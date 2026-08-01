//! Linux host services (LIN-1, the X11 dogfood tier): real paths, the
//! lockfile single-instance guard, atomic config replace, the hostname, the
//! SIGTERM latch, `xdg-open`, and the live capture-pump surface —
//! `gilbreth-capture-linux`'s X11 pump, its self-pipe waker, and the
//! XGrabKey pause hotkey. The dialogs keep the LIN-0 stub posture: logged
//! alerts (echoed to stderr), fail-safe declined confirms — a recorded
//! LIN-1 gap, not an oversight; the confirm-gated privacy flows therefore
//! refuse rather than proceed unseen. The POSIX pieces are the macOS
//! shapes: `flock` guards, `rename(2)` replace, `gethostname(2)`, the
//! atomic-store SIGTERM handler.

use std::{
    env,
    ffi::OsStr,
    fs, io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::Sender;
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use tracing::warn;

use super::{AlertKind, ConfirmAnswer, ConfirmButtons};
use crate::hotkey::{HotkeyKey, PauseHotkeyChord};
use crate::permissions::{PermissionAction, PermissionState};

pub fn reconcile_sensitive_context_before_resume(_pump_waker: PumpWaker) -> Option<u64> {
    Some(0)
}

/// XDG base directory: `$XDG_DATA_HOME/gilbreth`, falling back to
/// `~/.local/share/gilbreth`. Lowercase to match the binary name and the
/// platform's convention, unlike the branded `Gilbreth` folder on Windows
/// and macOS — LIN-1 inherits whichever name ships here first.
pub fn local_data_dir() -> Result<PathBuf> {
    let xdg = env::var_os("XDG_DATA_HOME");
    let home = env::var_os("HOME");
    data_dir_from(xdg.as_deref(), home.as_deref())
}

fn data_dir_from(xdg_data_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    // The XDG spec treats a relative (or empty) XDG_DATA_HOME as unset.
    if let Some(dir) = xdg_data_home {
        let dir = Path::new(dir);
        if dir.is_absolute() {
            return Ok(dir.join("gilbreth"));
        }
    }
    let home = home.ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("gilbreth"))
}

pub fn downloads_dir() -> Result<PathBuf, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let downloads = PathBuf::from(home).join("Downloads");
    if !downloads.is_dir() {
        return Err(format!(
            "Downloads folder not found at {}",
            downloads.display()
        ));
    }
    Ok(downloads)
}

pub fn local_host_name() -> Option<String> {
    // gethostname(2); the session-identity host field only needs a stable
    // per-machine label.
    let mut buffer = [0u8; 256];
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return None;
    }
    let len = buffer.iter().position(|&byte| byte == 0)?;
    String::from_utf8(buffer[..len].to_vec()).ok()
}

/// Phase 5 package lifecycle locking is Windows-only. Keep the facade stable
/// for the shared app entry point.
pub struct LifecycleGuard;

impl LifecycleGuard {
    pub fn acquire_shared() -> Result<Self> {
        Ok(Self)
    }
}

pub struct LifecycleExclusiveGuard;

impl LifecycleExclusiveGuard {
    pub fn acquire(install_root: &Path) -> Result<Self> {
        if !install_root.is_absolute() {
            return Err(anyhow!("install root must be absolute"));
        }
        Ok(Self)
    }
}

/// Atomic config replace: POSIX `rename(2)` replaces atomically on the same
/// volume (the temp file is written beside its target).
pub fn replace_file(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)?;
    Ok(())
}

/// Single instance via a held `flock` on a data-dir lockfile (the macOS
/// shape). The kernel drops the lock when the process dies, so a crash never
/// leaves a stale guard; the lockfile itself is left in place deliberately
/// (removing it would race a second instance locking the same inode).
pub struct SingleInstance {
    _file: fs::File,
}

/// Exclusive writer claim for eframe's `dashboard-ui.ron` state.
///
/// The lockfile stays in the per-user data root so the inode is stable across
/// dashboard processes. The kernel releases `flock` when this retained file
/// closes or the process dies; secondary viewers keep running without owning
/// persistence.
pub struct DashboardUiStateOwner {
    _file: fs::File,
}

impl DashboardUiStateOwner {
    pub fn try_acquire(local_data_dir: &Path) -> Result<Option<Self>> {
        fs::create_dir_all(local_data_dir)
            .context("failed to create the Gilbreth data directory for dashboard UI state")?;
        let path = local_data_dir.join("dashboard-ui.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| {
                format!(
                    "failed to open dashboard UI-state lockfile {}",
                    path.display()
                )
            })?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(error).with_context(|| {
                format!(
                    "failed to lock dashboard UI-state lockfile {}",
                    path.display()
                )
            });
        }
        Ok(Some(Self { _file: file }))
    }
}

impl SingleInstance {
    pub fn acquire() -> Result<Self> {
        let dir = local_data_dir()?;
        Self::acquire_in(&dir)
    }

    fn acquire_in(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).context("failed to create the Gilbreth data directory")?;
        let path = dir.join("gilbreth.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            // Never truncate: the lock lives on the inode, not the contents,
            // and truncating a file another instance holds locked would be
            // needless churn on it.
            .truncate(false)
            .open(&path)
            .context("failed to open the single-instance lockfile")?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(anyhow!("another Gilbreth instance is already running"));
            }
            return Err(error).context("failed to lock the single-instance lockfile");
        }
        Ok(Self { _file: file })
    }
}

/// The per-user data-root flock already spans login sessions. A blocked
/// launch remains the existing explicit duplicate error; there is no Windows
/// cross-session autostart distinction to classify here.
pub fn is_other_session_instance_error(_error: &anyhow::Error) -> bool {
    false
}

/// Cross-thread wake handle for the pump thread: signals the capture
/// crate's self-pipe (the Linux analog of the Win32
/// `PostThreadMessageW(WM_APP)` wake and the macOS CFRunLoop wake source).
/// The pump registers its pipe when it starts, so the handle itself stays a
/// copyable token like the Windows thread id.
#[derive(Clone, Copy, Debug)]
pub struct PumpWaker {
    connected: bool,
}

impl PumpWaker {
    /// Call on the thread that will run `run_capture_pump`, before workers
    /// that wake it spawn — same contract as the Windows twin.
    pub fn for_current_thread() -> Self {
        Self { connected: true }
    }

    /// A waker that wakes nobody, for tests exercising the command lanes
    /// without a pump thread.
    #[cfg(test)]
    pub fn disconnected() -> Self {
        Self { connected: false }
    }

    pub fn wake(&self) {
        if self.connected {
            gilbreth_capture_linux::wake_pump();
        }
    }
}

/// SIGTERM latch, the macOS shape: the handler body is a single atomic
/// store (the only async-signal-safe thing it could do). Nothing polls it
/// in the viewer build — the capture service pass that consumes it is
/// Windows/macOS — but the facade contract stays real rather than lying.
static TERMINATION_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_sigterm(_signo: libc::c_int) {
    TERMINATION_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install the SIGTERM handler. Call once, early in `main`, on any thread.
pub fn init_termination_signal() {
    // SAFETY: installing a handler whose body is a single atomic store —
    // async-signal-safe per POSIX; the zeroed sigaction is fully
    // initialized before use.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigterm as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0 {
            warn!("failed to install the SIGTERM handler");
        }
    }
}

/// Consume a pending termination signal (edge-triggered).
pub fn take_termination_signal() -> bool {
    TERMINATION_REQUESTED.swap(false, std::sync::atomic::Ordering::SeqCst)
}

// Permission surface: Linux has no TCC analog, so this is the Windows
// posture — no permission panel, `None` state, no edges, no actions.

pub fn init_permission_baseline() {}

pub fn current_permission_state() -> Option<PermissionState> {
    None
}

pub fn permission_state_changed(_state: &PermissionState) -> bool {
    false
}

pub fn note_permission_state_written(_state: &PermissionState) {}

pub fn perform_permission_action(_action: PermissionAction) -> bool {
    // No macOS-style relaunch on Linux; the caller never quits on this.
    false
}

/// Open a URL via `xdg-open`. `false` if it could not be spawned.
pub fn open_url(url: &str) -> bool {
    match Command::new("xdg-open").arg(url).spawn() {
        Ok(_) => true,
        Err(error) => {
            warn!(%error, "failed to spawn xdg-open");
            false
        }
    }
}

/// Nothing to set up: the SNI tray lives on its own D-Bus service thread
/// (no AppKit/Win32 message-queue analog exists on this seam).
pub fn init_app_shell() {}

/// No shell event queue exists: tray activations arrive through the menu
/// channel the ksni service feeds, drained by the shared service pass.
pub fn pump_app_events() {}

/// Ask the pump to exit (the tray-quit path — the Linux analog of
/// `PostQuitMessage`): latch the capture crate's stop flag and wake its
/// self-pipe, so the request is never lost regardless of where the loop is
/// in its pass. Cross-thread safe; a quiet no-op once the pump has exited.
pub fn request_pump_quit() {
    gilbreth_capture_linux::stop_pump();
}

/// Run the platform capture pump on the current thread until stop/quit: the
/// X11 connection drained beside the self-pipe waker, with the periodic
/// service callback on the shared 50 ms cadence (LIN-1). A session without
/// an X server declines here honestly — Wayland is absent by design.
pub fn run_capture_pump<F>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    gilbreth_capture_linux::run_pump(tx, stop, controls, after_service)
}

/// Lifetime guard for the XGrabKey claim, mirroring the Windows/Carbon
/// twins: dropping it releases the grab and stops the reader thread.
pub struct PauseHotkeyRegistration {
    _grab: gilbreth_capture_linux::PauseHotkeyGrab,
}

pub fn register_pause_hotkey(chord: PauseHotkeyChord) -> Result<PauseHotkeyRegistration> {
    let keysym = x_keysym(chord.key).ok_or_else(|| {
        anyhow!(
            "X11 has no keysym for {}; choose a different pause chord",
            chord.key
        )
    })?;
    let grab = gilbreth_capture_linux::register_pause_hotkey_grab(
        keysym,
        gilbreth_capture_linux::PauseChordModifiers {
            ctrl: chord.ctrl,
            alt: chord.alt,
            shift: chord.shift,
            win: chord.win,
        },
    )
    .map_err(|error| anyhow!(error))?;
    Ok(PauseHotkeyRegistration { _grab: grab })
}

/// Consume the edge recorded by the grab reader. Called once per pump
/// service pass, immediately before tray/menu handling.
pub fn take_pause_hotkey_press() -> bool {
    gilbreth_capture_linux::take_pause_hotkey_press()
}

/// `HotkeyKey` to X keysym, the twin of `windows_virtual_key` and
/// `carbon_key_code`. Letters map to their lowercase keysym — the capture
/// crate's grab matches a keysym at any shift level of a keycode, so the
/// level-0 lowercase form is the canonical spelling. `None` never happens
/// today (X has a keysym for every `HotkeyKey`), but the shape stays the
/// twins' so a future key addition degrades to "off for this run" instead
/// of binding the wrong key.
fn x_keysym(key: HotkeyKey) -> Option<u32> {
    let keysym = match key {
        HotkeyKey::Letter(value) => u32::from(value.to_ascii_lowercase()),
        HotkeyKey::Digit(value) => u32::from(value),
        HotkeyKey::Function(value) => {
            // XK_F1 (0xffbe) through XK_F24; the parser already caps at 24.
            0xffbe + u32::from(value.checked_sub(1)?)
        }
        HotkeyKey::Backspace => u32::from(xkeysym::Keysym::BackSpace),
        HotkeyKey::Delete => u32::from(xkeysym::Keysym::Delete),
        HotkeyKey::Down => u32::from(xkeysym::Keysym::Down),
        HotkeyKey::End => u32::from(xkeysym::Keysym::End),
        HotkeyKey::Enter => u32::from(xkeysym::Keysym::Return),
        HotkeyKey::Escape => u32::from(xkeysym::Keysym::Escape),
        HotkeyKey::Home => u32::from(xkeysym::Keysym::Home),
        HotkeyKey::Insert => u32::from(xkeysym::Keysym::Insert),
        HotkeyKey::Left => u32::from(xkeysym::Keysym::Left),
        HotkeyKey::PageDown => u32::from(xkeysym::Keysym::Next),
        HotkeyKey::PageUp => u32::from(xkeysym::Keysym::Prior),
        HotkeyKey::Pause => u32::from(xkeysym::Keysym::Pause),
        HotkeyKey::Right => u32::from(xkeysym::Keysym::Right),
        HotkeyKey::Space => u32::from(xkeysym::Keysym::space),
        HotkeyKey::Tab => u32::from(xkeysym::Keysym::Tab),
        HotkeyKey::Up => u32::from(xkeysym::Keysym::Up),
    };
    Some(keysym)
}

/// Stub dialog (the MAC-0 posture): logged, echoed to stderr — a Linux
/// viewer is launched from a terminal, and the startup-failure alert must
/// reach the person who launched it — never silently swallowed.
pub fn alert(title: &str, message: &str, kind: AlertKind) {
    warn!(
        title,
        message,
        ?kind,
        "alert dialog logged only (no Linux dialog surface)"
    );
    eprintln!("{title}: {message}");
}

/// Stub confirm (the MAC-0 posture): every confirm answers negative — the
/// fail-safe refusal, so no destructive flow can proceed through a dialog
/// nobody saw.
pub fn confirm(
    title: &str,
    message: &str,
    kind: AlertKind,
    buttons: ConfirmButtons,
    default_negative: bool,
) -> bool {
    warn!(
        title,
        message,
        ?kind,
        ?buttons,
        default_negative,
        "confirm dialog auto-declined (no Linux dialog surface)"
    );
    false
}

/// Stub three-way confirm: `Dismissed` is the do-nothing outcome, matching
/// the first-run consent design's rule that the safe path is also the
/// deferral path.
pub fn confirm_three_way(title: &str, message: &str, kind: AlertKind) -> ConfirmAnswer {
    warn!(
        title,
        message,
        ?kind,
        "three-way confirm deferred (no Linux dialog surface)"
    );
    ConfirmAnswer::Dismissed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_honors_an_absolute_xdg_data_home_and_ignores_a_relative_one() {
        // Read through helper inputs, not the process environment: tests run
        // in parallel and env mutation would race the other cases.
        assert_eq!(
            data_dir_from(Some(OsStr::new("/xdg/data")), Some(OsStr::new("/home/u")))
                .expect("absolute XDG_DATA_HOME"),
            PathBuf::from("/xdg/data/gilbreth")
        );
        // Relative and empty both mean unset per the XDG spec.
        assert_eq!(
            data_dir_from(Some(OsStr::new("relative")), Some(OsStr::new("/home/u")))
                .expect("relative falls back to HOME"),
            PathBuf::from("/home/u/.local/share/gilbreth")
        );
        assert_eq!(
            data_dir_from(Some(OsStr::new("")), Some(OsStr::new("/home/u")))
                .expect("empty falls back to HOME"),
            PathBuf::from("/home/u/.local/share/gilbreth")
        );
        assert!(
            data_dir_from(Some(OsStr::new("relative")), None).is_err(),
            "no HOME and no usable XDG_DATA_HOME is an error"
        );
    }

    #[test]
    fn pause_chord_keys_all_resolve_to_keysyms() {
        // Every key the chord parser can produce must map, so a valid
        // config never silently loses its hotkey to a table gap. Spot the
        // families plus every named key.
        for key in [
            HotkeyKey::Letter('P'),
            HotkeyKey::Letter('a'),
            HotkeyKey::Digit('0'),
            HotkeyKey::Digit('9'),
            HotkeyKey::Function(1),
            HotkeyKey::Function(24),
            HotkeyKey::Backspace,
            HotkeyKey::Delete,
            HotkeyKey::Down,
            HotkeyKey::End,
            HotkeyKey::Enter,
            HotkeyKey::Escape,
            HotkeyKey::Home,
            HotkeyKey::Insert,
            HotkeyKey::Left,
            HotkeyKey::PageDown,
            HotkeyKey::PageUp,
            HotkeyKey::Pause,
            HotkeyKey::Right,
            HotkeyKey::Space,
            HotkeyKey::Tab,
            HotkeyKey::Up,
        ] {
            assert!(x_keysym(key).is_some(), "{key:?} must resolve");
        }
        // Letters resolve to the lowercase keysym (XK_p), the level-0 form
        // the capture crate's grab scan expects.
        assert_eq!(x_keysym(HotkeyKey::Letter('P')), Some(0x70));
        assert_eq!(x_keysym(HotkeyKey::Function(1)), Some(0xffbe));
    }

    #[test]
    fn dialogs_answer_fail_safe() {
        // No dialog surface exists, so a confirm nobody can see must refuse
        // and a three-way must defer — same contract as the off-main-thread
        // macOS stubs.
        alert("t", "m", AlertKind::Info);
        assert!(
            !confirm("t", "m", AlertKind::Warning, ConfirmButtons::YesNo, true),
            "an unseen confirm must refuse"
        );
        assert_eq!(
            confirm_three_way("t", "m", AlertKind::Info),
            ConfirmAnswer::Dismissed,
            "an unseen three-way confirm must defer"
        );
    }

    #[test]
    fn sigterm_sets_the_termination_latch_once() {
        init_termination_signal();
        assert!(!take_termination_signal(), "no signal yet");
        // SAFETY: raising a signal at our own process whose installed
        // handler is the atomic-store latch above.
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(take_termination_signal(), "the latch caught the signal");
        assert!(!take_termination_signal(), "edge-triggered: consumed once");
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
    fn single_instance_flock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().expect("temp data dir");
        let first = SingleInstance::acquire_in(dir.path()).expect("first writer claim");
        let error = match SingleInstance::acquire_in(dir.path()) {
            Ok(_) => panic!("duplicate writer must be refused"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("another Gilbreth instance is already running"));

        drop(first);
        drop(SingleInstance::acquire_in(dir.path()).expect("claim released on drop"));
    }
}
