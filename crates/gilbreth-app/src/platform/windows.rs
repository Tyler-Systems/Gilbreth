//! Windows host services: the pre-MAC-0 implementations moved verbatim from
//! `main.rs` / `config.rs` behind the platform facade. Behavior is
//! unchanged — same APIs, same flags, same log lines (zero-Windows-
//! behavior-change rule).

use std::{
    env,
    ffi::c_void,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    mem::size_of,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::Sender;
use gilbreth_capture_windows::CapturePump;
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use tracing::error;
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_NO_MORE_FILES,
            ERROR_SHARING_VIOLATION, HANDLE, LPARAM, WPARAM,
        },
        Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        Storage::FileSystem::{
            MoveFileExW, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
            MOVEFILE_WRITE_THROUGH,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{CreateMutexW, GetCurrentProcess, GetCurrentThreadId, OpenProcessToken},
        },
        UI::{
            Input::KeyboardAndMouse::{
                RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL,
                MOD_NOREPEAT, MOD_SHIFT, MOD_WIN,
            },
            Shell::ShellExecuteW,
            WindowsAndMessaging::{
                FindWindowW, FlashWindowEx, MessageBoxW, PostQuitMessage, PostThreadMessageW,
                SetForegroundWindow, SetWindowPos, FLASHWINFO, FLASHW_ALL, FLASHW_TIMERNOFG,
                HWND_TOPMOST, IDNO, IDOK, IDYES, MB_DEFBUTTON2, MB_ICONINFORMATION, MB_ICONWARNING,
                MB_OK, MB_OKCANCEL, MB_SETFOREGROUND, MB_SYSTEMMODAL, MB_YESNO, MB_YESNOCANCEL,
                SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_SHOWNORMAL, WM_APP, WM_HOTKEY,
            },
        },
    },
};

use super::{AlertKind, ConfirmAnswer, ConfirmButtons};
use crate::hotkey::{HotkeyKey, PauseHotkeyChord};

/// Content-free, per-user transaction sentinel shared by the packaged app,
/// repository-local development builds, and the Inno transaction. Keeping it
/// outside both the replaceable program directory and removable data root lets
/// one exclusive handle span rename, verification, rollback, and purge.
const LIFECYCLE_LOCK_NAME: &str = "Gilbreth.lifecycle.lock";
const PRODUCT_PROCESS_NAMES: [&str; 2] =
    ["gilbreth-app.exe", "gilbreth-elevated-record-helper.exe"];
const PAUSE_HOTKEY_ID: i32 = 0x4742;
static PAUSE_HOTKEY_PRESSED: AtomicBool = AtomicBool::new(false);

pub fn local_data_dir() -> Result<PathBuf> {
    let local_app_data =
        env::var_os("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA is not set"))?;
    Ok(PathBuf::from(local_app_data).join("Gilbreth"))
}

pub fn downloads_dir() -> Result<PathBuf, String> {
    let profile = env::var_os("USERPROFILE").ok_or_else(|| "USERPROFILE is not set".to_string())?;
    let downloads = PathBuf::from(profile).join("Downloads");
    if !downloads.is_dir() {
        return Err(format!(
            "Downloads folder not found at {}",
            downloads.display()
        ));
    }
    Ok(downloads)
}

pub fn local_host_name() -> Option<String> {
    env::var("COMPUTERNAME").ok()
}

/// Shared, cross-session package-lifecycle claim held for the lifetime of
/// every tray and dashboard process. Windows sharing rules are system-wide,
/// so an installer can deny all sharing on the same sentinel before replacing
/// program files, including when the viewer is in another logon session.
pub struct LifecycleGuard {
    _file: fs::File,
}

impl LifecycleGuard {
    pub fn acquire_shared() -> Result<Self> {
        let path = lifecycle_lock_path()?;
        let file = open_lifecycle_lock_shared_at(&path)?;
        Ok(Self { _file: file })
    }
}

/// Exclusive package-lifecycle probe. The handles remain held until Drop so
/// callers can perform an offline purge without another process from this
/// install root starting midway through it.
pub struct LifecycleExclusiveGuard {
    _files: Vec<fs::File>,
}

impl LifecycleExclusiveGuard {
    pub fn acquire(install_root: &Path) -> Result<Self> {
        if !install_root.is_absolute() {
            return Err(anyhow!("install root must be absolute"));
        }
        ensure_no_other_product_processes()?;
        let mut files = vec![open_lifecycle_lock_exclusive()?];
        files.extend(open_program_file_probes(install_root, true)?);
        Ok(Self { _files: files })
    }

    /// Destructive purge owns the cross-session sentinel but must not retain
    /// handles to the exact legacy binaries it is about to remove. A legacy
    /// process that wins the narrow post-enumeration race makes Windows refuse
    /// that delete and is reported as a deferred class instead of being raced.
    pub fn acquire_for_purge(install_root: &Path) -> Result<Self> {
        if !install_root.is_absolute() {
            return Err(anyhow!("install root must be absolute"));
        }
        ensure_no_other_product_processes()?;
        let mut files = vec![open_lifecycle_lock_exclusive()?];
        files.extend(open_program_file_probes(install_root, false)?);
        Ok(Self { _files: files })
    }

    /// The Inno transaction owns the exclusive sentinel while its purge child
    /// runs. Prove that owner exists, repeat the process scan, and retain every
    /// other known executable probe for the child's lifetime.
    pub fn acquire_under_installer_lock(install_root: &Path) -> Result<Self> {
        if !install_root.is_absolute() {
            return Err(anyhow!("install root must be absolute"));
        }
        ensure_no_other_product_processes()?;
        let path = lifecycle_lock_path()?;
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
            .open(&path)
        {
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.0 as i32) => {}
            Err(error) => {
                return Err(error).context("failed to verify the installer lifecycle lock")
            }
            Ok(_) => return Err(anyhow!("installer lifecycle lock is not held exclusively")),
        }
        Ok(Self {
            _files: open_program_file_probes(install_root, false)?,
        })
    }
}

fn lifecycle_lock_path() -> Result<PathBuf> {
    let local_app_data =
        env::var_os("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA is not set"))?;
    Ok(PathBuf::from(local_app_data).join(LIFECYCLE_LOCK_NAME))
}

fn open_lifecycle_lock_shared_at(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .open(path)
        .context("failed to acquire the shared package lifecycle guard")
}

fn open_lifecycle_lock_exclusive() -> Result<fs::File> {
    let path = lifecycle_lock_path()?;
    open_lifecycle_lock_exclusive_at(&path)
}

fn open_lifecycle_lock_exclusive_at(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .context("failed to acquire the exclusive package lifecycle guard")
}

fn open_program_file_probes(install_root: &Path, include_legacy: bool) -> Result<Vec<fs::File>> {
    if install_root.exists() && !install_root.is_dir() {
        return Err(anyhow!("install root is not a directory"));
    }
    let current = env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok());
    let local_app_data =
        env::var_os("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA is not set"))?;
    let legacy_root = PathBuf::from(local_app_data).join("Gilbreth").join("bin");
    let mut candidates = vec![
        install_root.join("gilbreth-app.exe"),
        install_root.join("gilbreth-elevated-record-helper.exe"),
    ];
    if include_legacy {
        candidates.push(legacy_root.join("gilbreth-app.exe"));
        candidates.push(legacy_root.join("gilbreth-elevated-record-helper.exe"));
    }
    let mut files = Vec::new();
    for path in candidates {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Gilbreth program file");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("could not inspect {name}")),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!(
                "program lifecycle path is not a regular file: {name}"
            ));
        }
        if current
            .as_ref()
            .is_some_and(|current| fs::canonicalize(&path).ok().as_ref() == Some(current))
        {
            continue;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .with_context(|| format!("program lifecycle file is locked: {name}"))?;
        files.push(file);
    }
    Ok(files)
}

fn ensure_no_other_product_processes() -> Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .context("failed to enumerate product processes")?;
    let _snapshot = HandleGuard(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Process32FirstW(snapshot, &mut entry) }
        .context("failed to read the product process snapshot")?;
    loop {
        if entry.th32ProcessID != std::process::id() {
            let len = entry
                .szExeFile
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if PRODUCT_PROCESS_NAMES
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
            {
                return Err(anyhow!("another Gilbreth product process is running"));
            }
        }
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(anyhow!("product process enumeration ended unexpectedly"));
        }
    }
    Ok(())
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Atomic config replace: `MoveFileExW` with replace + write-through, so a
/// crash mid-save can never leave a half-written config in place.
pub fn replace_file(from: &Path, to: &Path) -> Result<()> {
    let from_wide = wide_path(from);
    let to_wide = wide_path(to);
    unsafe {
        MoveFileExW(
            PCWSTR(from_wide.as_ptr()),
            PCWSTR(to_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }?;
    Ok(())
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[derive(Debug)]
struct OtherSessionInstance;

impl std::fmt::Display for OtherSessionInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("another Gilbreth instance is running in another Windows session")
    }
}

impl std::error::Error for OtherSessionInstance {}

pub fn is_other_session_instance_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<OtherSessionInstance>().is_some())
}

struct NamedMutexHandle(HANDLE);

impl Drop for NamedMutexHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            error!(%error, "failed to close single-instance mutex");
        }
    }
}

fn create_named_mutex(name: &str) -> Result<(NamedMutexHandle, bool)> {
    let name = wide(name);
    // Handle lifetime is the claim; no thread ownership is needed, which also
    // avoids abandoned-mutex state if the process exits unexpectedly.
    let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }?;
    // GetLastError must be sampled immediately after CreateMutexW: a valid
    // handle plus ERROR_ALREADY_EXISTS is the named-object collision signal.
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    Ok((NamedMutexHandle(handle), already_exists))
}

fn current_user_sid_suffix() -> Result<String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("failed to open the current process token for the writer guard")?;
    let token = NamedMutexHandle(token);

    let mut required_len = 0_u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required_len) };
    if required_len == 0 {
        return Err(windows::core::Error::from_thread())
            .context("failed to size the current-user SID for the writer guard");
    }
    let mut buffer = vec![0_u8; required_len as usize];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            required_len,
            &mut required_len,
        )
    }
    .context("failed to read the current-user SID for the writer guard")?;
    // TOKEN_USER is pointer-aligned, while Vec<u8> is not. Read the wrapper
    // unaligned; its SID pointer still targets `buffer`, which remains alive.
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid_len = unsafe { GetLengthSid(token_user.User.Sid) } as usize;
    if sid_len == 0 {
        return Err(anyhow!("current-user SID is empty"));
    }
    let sid_bytes =
        unsafe { std::slice::from_raw_parts(token_user.User.Sid.0.cast::<u8>(), sid_len) };
    // Encode every SID byte rather than hashing it: distinct Windows users
    // remain structurally distinct without relying on collision probability.
    let mut suffix = String::with_capacity(sid_bytes.len() * 2);
    for byte in sid_bytes {
        write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(suffix)
}

fn acquire_named_single_instance(local_name: &str, global_name: &str) -> Result<SingleInstance> {
    let (local, local_exists) = create_named_mutex(local_name)?;
    if local_exists {
        return Err(anyhow!("another Gilbreth instance is already running"));
    }

    let (global, global_exists) = create_named_mutex(global_name)?;
    if global_exists {
        return Err(OtherSessionInstance.into());
    }

    Ok(SingleInstance {
        _local: local,
        _global: global,
    })
}

pub struct SingleInstance {
    // Local first distinguishes an explicit same-session duplicate from a
    // quiet cross-session autostart collision. Both stay held for process life.
    _local: NamedMutexHandle,
    _global: NamedMutexHandle,
}

impl SingleInstance {
    pub fn acquire() -> Result<Self> {
        let suffix = current_user_sid_suffix()?;
        acquire_named_single_instance("Local\\GilbrethV2", &format!("Global\\GilbrethV2-{suffix}"))
    }
}

/// Exclusive writer claim for eframe's `dashboard-ui.ron` state.
///
/// Unlike the capture process's session-scoped named mutex, this uses an
/// exclusive handle on a lockfile inside the per-user data root. Windows file
/// sharing applies across logon sessions, so two dashboard viewers for the
/// same profile cannot both become persistence writers. The file itself is
/// deliberately retained; closing this handle releases the claim.
pub struct DashboardUiStateOwner {
    _file: fs::File,
}

impl DashboardUiStateOwner {
    /// Return `Some` for the first viewer and `None` when another viewer owns
    /// persistence. Errors are returned so the caller can log them and fail
    /// closed to a non-persisting viewer without refusing to open the window.
    pub fn try_acquire(local_data_dir: &Path) -> Result<Option<Self>> {
        fs::create_dir_all(local_data_dir)
            .context("failed to create the Gilbreth data directory for dashboard UI state")?;
        let path = local_data_dir.join("dashboard-ui.lock");
        match fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            // Zero sharing is the lock: any other process/session trying to
            // open this path receives ERROR_SHARING_VIOLATION until Drop.
            .share_mode(0)
            .open(&path)
        {
            Ok(file) => Ok(Some(Self { _file: file })),
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.0 as i32) => {
                Ok(None)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to open dashboard UI-state lockfile {}",
                    path.display()
                )
            }),
        }
    }
}

/// Cross-thread wake handle for the pump thread. Cheap to copy into worker
/// threads; `wake()` posts a benign `WM_APP` so a blocked `GetMessageW`
/// returns and the pump services its callback (stop checks, tray events).
#[derive(Clone, Copy, Debug)]
pub struct PumpWaker {
    thread_id: u32,
}

impl PumpWaker {
    /// Capture the calling thread as the wake target; call this on the
    /// thread that will run `run_capture_pump`.
    pub fn for_current_thread() -> Self {
        Self {
            thread_id: unsafe { GetCurrentThreadId() },
        }
    }

    /// A waker that wakes nobody, for tests exercising the command lanes
    /// without a pump thread.
    #[cfg(test)]
    pub fn disconnected() -> Self {
        Self { thread_id: 0 }
    }

    pub fn wake(&self) {
        let thread_id = self.thread_id;
        if let Err(error) = unsafe { PostThreadMessageW(thread_id, WM_APP, WPARAM(0), LPARAM(0)) } {
            error!(%error, thread_id, "failed to wake message pump");
        }
    }
}

#[cfg(not(test))]
pub fn reconcile_sensitive_context_before_resume(pump_waker: PumpWaker) -> Option<u64> {
    let reply = gilbreth_capture_windows::request_sensitive_context_reconcile();
    pump_waker.wake();
    reply.recv_timeout(Duration::from_secs(2)).unwrap_or(None)
}

#[cfg(test)]
pub fn reconcile_sensitive_context_before_resume(_pump_waker: PumpWaker) -> Option<u64> {
    Some(0)
}

/// Ask the pump's run loop to exit (tray Quit). The Win32 pump also exits
/// when the stop token cancels and a wake arrives; this accelerates the
/// user-initiated path exactly as before.
pub fn request_pump_quit() {
    unsafe {
        PostQuitMessage(0);
    }
}

/// Windows twin of the macOS `NSApplication` setup: a no-op — the tray's
/// hidden window and the pump's message loop need no separate application
/// object.
pub fn init_app_shell() {}

/// Windows twin of the macOS NSEvent drain: a no-op — the pump's
/// `GetMessage`/`DispatchMessage` loop already dispatches the tray
/// window's messages before each service pass.
pub fn pump_app_events() {}

/// Windows twins of the macOS SIGTERM latch: no-ops — session end arrives
/// as `WM_ENDSESSION` inside the capture pump, which already runs the
/// graceful shutdown; no POSIX signal path exists here.
pub fn init_termination_signal() {}

pub fn take_termination_signal() -> bool {
    false
}

/// Windows twins of the macOS TCC permission facade: no-ops / absent. The
/// permissions panel is a macOS-only Diagnostics section (Windows uses UAC
/// and its own manifest, no per-stream TCC grants), so the pump writes no
/// state sidecar here and the dashboard never renders the panel.
pub fn init_permission_baseline() {}

pub fn current_permission_state() -> Option<crate::permissions::PermissionState> {
    None
}

pub fn permission_state_changed(_state: &crate::permissions::PermissionState) -> bool {
    false
}

pub fn note_permission_state_written(_state: &crate::permissions::PermissionState) {}

pub fn perform_permission_action(_action: crate::permissions::PermissionAction) -> bool {
    // No macOS-style relaunch on Windows; the caller never quits on this.
    false
}

pub fn open_url(url: &str) -> bool {
    let wide = OsStr::new(url)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    result.0 as isize > 32
}

/// Lifetime guard for the pump-thread `RegisterHotKey` claim. Registration
/// and unregistration both happen on the pump/main thread, matching Win32's
/// thread-associated `hwnd = NULL` contract.
pub struct PauseHotkeyRegistration {
    id: i32,
}

impl Drop for PauseHotkeyRegistration {
    fn drop(&mut self) {
        if let Err(error) = unsafe { UnregisterHotKey(None, self.id) } {
            error!(%error, "failed to unregister the pause hotkey");
        }
    }
}

pub fn register_pause_hotkey(chord: PauseHotkeyChord) -> Result<PauseHotkeyRegistration> {
    let (modifiers, virtual_key) = windows_hotkey(chord);
    register_pause_hotkey_with(modifiers, virtual_key, |modifiers, virtual_key| unsafe {
        RegisterHotKey(None, PAUSE_HOTKEY_ID, modifiers, virtual_key)
            .context("RegisterHotKey rejected the configured pause chord")
    })?;
    PAUSE_HOTKEY_PRESSED.store(false, Ordering::SeqCst);
    Ok(PauseHotkeyRegistration {
        id: PAUSE_HOTKEY_ID,
    })
}

fn register_pause_hotkey_with<F>(
    modifiers: HOT_KEY_MODIFIERS,
    virtual_key: u32,
    register: F,
) -> Result<()>
where
    F: FnOnce(HOT_KEY_MODIFIERS, u32) -> Result<()>,
{
    register(modifiers, virtual_key)
}

fn windows_hotkey(chord: PauseHotkeyChord) -> (HOT_KEY_MODIFIERS, u32) {
    let mut modifiers = MOD_NOREPEAT;
    if chord.ctrl {
        modifiers |= MOD_CONTROL;
    }
    if chord.alt {
        modifiers |= MOD_ALT;
    }
    if chord.shift {
        modifiers |= MOD_SHIFT;
    }
    if chord.win {
        modifiers |= MOD_WIN;
    }
    (modifiers, windows_virtual_key(chord.key))
}

fn windows_virtual_key(key: HotkeyKey) -> u32 {
    match key {
        HotkeyKey::Letter(value) | HotkeyKey::Digit(value) => value as u32,
        HotkeyKey::Function(value) => 0x70 + u32::from(value - 1), // VK_F1 .. VK_F24
        HotkeyKey::Backspace => 0x08,
        HotkeyKey::Tab => 0x09,
        HotkeyKey::Enter => 0x0D,
        HotkeyKey::Pause => 0x13,
        HotkeyKey::Escape => 0x1B,
        HotkeyKey::Space => 0x20,
        HotkeyKey::PageUp => 0x21,
        HotkeyKey::PageDown => 0x22,
        HotkeyKey::End => 0x23,
        HotkeyKey::Home => 0x24,
        HotkeyKey::Left => 0x25,
        HotkeyKey::Up => 0x26,
        HotkeyKey::Right => 0x27,
        HotkeyKey::Down => 0x28,
        HotkeyKey::Insert => 0x2D,
        HotkeyKey::Delete => 0x2E,
    }
}

/// Consume the edge recorded by the existing message loop. Called once per
/// pump service pass, immediately before tray/menu handling.
pub fn take_pause_hotkey_press() -> bool {
    PAUSE_HOTKEY_PRESSED.swap(false, Ordering::SeqCst)
}

/// Run the platform capture pump on the current thread until stop/quit:
/// all sources, the message pump, and the periodic service callback.
pub fn run_capture_pump<F>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    let mut after_service = after_service;
    CapturePump::all().run_with_message_pump_controls_and_observer(
        tx,
        stop,
        controls,
        move |message, wparam, _| {
            if message == WM_HOTKEY && wparam == PAUSE_HOTKEY_ID as usize {
                PAUSE_HOTKEY_PRESSED.store(true, Ordering::SeqCst);
            }
            after_service();
        },
    )
}

pub fn alert(title: &str, message: &str, kind: AlertKind) {
    show_message(title, message, MB_OK | icon_style(kind));
}

/// Blocking confirm; returns `true` on the positive answer (OK / Yes).
/// `default_negative` puts the keyboard default on the second (negative)
/// button, the pre-MAC-0 `MB_DEFBUTTON2` posture of the record dialogs.
pub fn confirm(
    title: &str,
    message: &str,
    kind: AlertKind,
    buttons: ConfirmButtons,
    default_negative: bool,
) -> bool {
    let mut style = icon_style(kind)
        | match buttons {
            ConfirmButtons::OkCancel => MB_OKCANCEL,
            ConfirmButtons::YesNo => MB_YESNO,
        };
    if default_negative {
        style |= MB_DEFBUTTON2;
    }
    let result = show_message(title, message, style);
    match buttons {
        ConfirmButtons::OkCancel => result == IDOK,
        ConfirmButtons::YesNo => result == IDYES,
    }
}

/// Blocking three-way Yes / No / Cancel confirm (first-run consent dialog,
/// the first-run consent design). The keyboard default is always the negative
/// button (`MB_DEFBUTTON2`: plain Enter keeps the safe default), and Esc or
/// the close box return Cancel, which maps to `Dismissed` ("decide later").
pub fn confirm_three_way(title: &str, message: &str, kind: AlertKind) -> ConfirmAnswer {
    let style = icon_style(kind) | MB_YESNOCANCEL | MB_DEFBUTTON2;
    let result = show_message(title, message, style);
    if result == IDYES {
        ConfirmAnswer::Positive
    } else if result == IDNO {
        ConfirmAnswer::Negative
    } else {
        ConfirmAnswer::Dismissed
    }
}

fn icon_style(kind: AlertKind) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE {
    match kind {
        AlertKind::Info => MB_ICONINFORMATION,
        AlertKind::Warning => MB_ICONWARNING,
    }
}

fn show_message(
    title: &str,
    message: &str,
    style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    let title_text = title.to_string();
    let title = wide(title);
    let message = wide(message);
    // UX-02 diagnosis: this box is unowned (no HWND) and shown from a
    // background thread of a background tray process. MB_SETFOREGROUND is
    // denied by the foreground lock (no recent input in this process), and
    // the undocumented MB_TOPMOST was observed NOT taking effect on this
    // path — the Record Routine ask opened behind the dashboard with no
    // taskbar signal. MB_SYSTEMMODAL is the documented way to give a
    // message box WS_EX_TOPMOST; the watcher below additionally flashes
    // the box's taskbar button so a denied activation still announces the
    // pending ask instead of reading as a dead button.
    let style = style | MB_SETFOREGROUND | MB_SYSTEMMODAL;
    // Branch review (UX-02): the dismissed flag bounds the join — when the
    // box returns immediately (or never appears), the watcher exits at its
    // next 50 ms poll instead of running out the full two-second budget.
    let dismissed = Arc::new(AtomicBool::new(false));
    let watcher_dismissed = Arc::clone(&dismissed);
    let watcher = thread::spawn(move || nudge_message_box_visible(&title_text, &watcher_dismissed));
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            style,
        )
    };
    dismissed.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    result
}

/// Best-effort visibility nudge for an unowned tray message box: find it by
/// class + title, raise it topmost without stealing focus, request
/// foreground, and flash its taskbar button until the user brings it
/// forward. Bounded polling; gives up quietly if the box closed first or
/// never appeared.
fn nudge_message_box_visible(title: &str, dismissed: &AtomicBool) {
    const MESSAGE_BOX_CLASS: PCWSTR = w!("#32770");
    let title = wide(title);
    for _ in 0..40 {
        if dismissed.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
        if dismissed.load(Ordering::SeqCst) {
            return;
        }
        let Ok(hwnd) = (unsafe { FindWindowW(MESSAGE_BOX_CLASS, PCWSTR(title.as_ptr())) }) else {
            continue;
        };
        if hwnd.is_invalid() {
            continue;
        }
        unsafe {
            let _ = SetWindowPos(
                hwnd,
                Some(HWND_TOPMOST),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
            let _ = SetForegroundWindow(hwnd);
            let _ = FlashWindowEx(&FLASHWINFO {
                cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
                hwnd,
                dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
                uCount: 0,
                dwTimeout: 0,
            });
        }
        return;
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::atomic::{AtomicU64, AtomicUsize},
        time::Instant,
    };

    static MUTEX_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn mutex_test_names(label: &str) -> (String, String) {
        let id = MUTEX_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let suffix = format!("{}-{}-{id}", std::process::id(), label);
        (
            format!("Local\\GilbrethV2-test-{suffix}"),
            format!("Global\\GilbrethV2-test-{suffix}"),
        )
    }

    #[test]
    fn single_instance_acquires_local_then_global_and_classifies_collisions() {
        let (local_name, global_name) = mutex_test_names("same-session");
        let first = acquire_named_single_instance(&local_name, &global_name)
            .expect("first writer owns both mutexes");
        let duplicate = match acquire_named_single_instance(&local_name, &global_name) {
            Ok(_) => panic!("same-session duplicate must be refused"),
            Err(error) => error,
        };
        assert!(!is_other_session_instance_error(&duplicate));
        assert!(duplicate
            .to_string()
            .contains("another Gilbreth instance is already running"));
        drop(first);
        drop(
            acquire_named_single_instance(&local_name, &global_name)
                .expect("both mutex handles release on drop"),
        );

        let (local_name, global_name) = mutex_test_names("cross-session");
        let (global_blocker, already_exists) =
            create_named_mutex(&global_name).expect("simulated other-session global claim");
        assert!(!already_exists);
        let blocked = match acquire_named_single_instance(&local_name, &global_name) {
            Ok(_) => panic!("global collision must refuse this writer"),
            Err(error) => error,
        };
        assert!(is_other_session_instance_error(&blocked));
        drop(global_blocker);
        drop(
            acquire_named_single_instance(&local_name, &global_name)
                .expect("failed global claim released its temporary local mutex"),
        );
    }

    const BLOCKER_MUTEX_ENV: &str = "GILBRETH_TEST_GLOBAL_MUTEX";
    const BLOCKER_READY_ENV: &str = "GILBRETH_TEST_GLOBAL_MUTEX_READY";
    const BLOCKER_RELEASE_ENV: &str = "GILBRETH_TEST_GLOBAL_MUTEX_RELEASE";

    #[test]
    fn single_instance_global_mutex_blocker_child() {
        let Ok(global_name) = std::env::var(BLOCKER_MUTEX_ENV) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(BLOCKER_READY_ENV).expect("ready path"));
        let release = PathBuf::from(std::env::var_os(BLOCKER_RELEASE_ENV).expect("release path"));
        let (_blocker, already_exists) =
            create_named_mutex(&global_name).expect("child claims global mutex");
        assert!(!already_exists);
        fs::write(&ready, b"ready").expect("child publishes ready state");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(release.exists(), "parent released blocker before timeout");
    }

    #[test]
    fn single_instance_cross_process_global_block_exits_through_quiet_class() {
        let dir = tempfile::tempdir().expect("temp synchronization dir");
        let ready = dir.path().join("ready");
        let release = dir.path().join("release");
        let (local_name, global_name) = mutex_test_names("child-blocker");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("platform::imp::tests::single_instance_global_mutex_blocker_child")
            .arg("--nocapture")
            .env(BLOCKER_MUTEX_ENV, &global_name)
            .env(BLOCKER_READY_ENV, &ready)
            .env(BLOCKER_RELEASE_ENV, &release)
            .spawn()
            .expect("global-mutex blocker child starts");

        let ready_deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < ready_deadline {
            assert!(
                child.try_wait().expect("child state").is_none(),
                "global-mutex blocker exited before publishing ready state"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "global-mutex blocker became ready");

        let blocked = match acquire_named_single_instance(&local_name, &global_name) {
            Ok(_) => panic!("another process's global claim must refuse this writer"),
            Err(error) => error,
        };
        assert!(is_other_session_instance_error(&blocked));

        fs::write(&release, b"release").expect("release child blocker");
        assert!(child.wait().expect("blocker child joins").success());
        drop(
            acquire_named_single_instance(&local_name, &global_name)
                .expect("temporary local claim released after quiet cross-session block"),
        );
    }

    #[test]
    fn machine_global_writer_mutex_name_is_stable_and_per_user() {
        let first = current_user_sid_suffix().expect("current user SID suffix");
        let second = current_user_sid_suffix().expect("stable current user SID suffix");
        assert_eq!(first, second);
        assert!(first.len() >= 16);
        assert_eq!(first.len() % 2, 0);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn lifecycle_shared_claim_blocks_exclusive_replacement_until_drop() {
        let dir = tempfile::tempdir().expect("temp lifecycle dir");
        let path = dir.path().join(LIFECYCLE_LOCK_NAME);
        let shared = open_lifecycle_lock_shared_at(&path).expect("shared lifecycle claim");
        assert!(
            open_lifecycle_lock_exclusive_at(&path).is_err(),
            "exclusive replacement must fail while any product claim is live"
        );
        drop(shared);
        drop(open_lifecycle_lock_exclusive_at(&path).expect("exclusive claim after product exit"));
    }

    #[test]
    fn dashboard_ui_state_claim_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().expect("temp data dir");
        let first = DashboardUiStateOwner::try_acquire(dir.path())
            .expect("first claim")
            .expect("first viewer owns persistence");

        assert!(
            DashboardUiStateOwner::try_acquire(dir.path())
                .expect("second claim")
                .is_none(),
            "a simultaneous viewer must continue without persistence"
        );

        drop(first);
        assert!(
            DashboardUiStateOwner::try_acquire(dir.path())
                .expect("claim after owner closes")
                .is_some(),
            "a later viewer can own persistence once the first closes"
        );
        assert!(dir.path().join("dashboard-ui.lock").is_file());
    }

    #[test]
    fn injected_hotkey_registrar_is_called_once_and_propagates_failure() {
        let calls = AtomicUsize::new(0);
        let chord = PauseHotkeyChord {
            ctrl: true,
            alt: true,
            shift: true,
            win: false,
            key: HotkeyKey::Letter('P'),
        };
        let (modifiers, virtual_key) = windows_hotkey(chord);
        register_pause_hotkey_with(modifiers, virtual_key, |seen_modifiers, seen_key| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                seen_modifiers,
                MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT
            );
            assert_eq!(seen_key, u32::from(b'P'));
            Ok(())
        })
        .expect("registration succeeds");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let error =
            register_pause_hotkey_with(modifiers, virtual_key, |_, _| Err(anyhow!("owned")))
                .expect_err("failure propagates");
        assert_eq!(error.to_string(), "owned");
    }
}
