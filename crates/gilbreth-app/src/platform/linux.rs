//! Linux host services (LIN-0, the viewer build): real paths, the lockfile
//! single-instance guard, atomic config replace, the hostname, the SIGTERM
//! latch, and `xdg-open`. There is no Linux capture backend — the capture
//! pump declines with `CaptureError::UnsupportedPlatform` and `run()`'s
//! Linux stub turns the capture process away before it gets here — and the
//! dialogs keep the MAC-0 stub posture: logged alerts (echoed to stderr,
//! since a viewer launched from a terminal has no other surface), fail-safe
//! declined confirms. The product platforms stay Windows and macOS; this
//! backend exists so `gilbreth-app --dashboard` builds and runs on a Linux
//! development machine (LIN-0). The POSIX pieces are the macOS shapes:
//! `flock` guards, `rename(2)` replace, `gethostname(2)`, the atomic-store
//! SIGTERM handler.

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

/// There is no Linux capture pump to wake (LIN-0); the token exists for
/// facade symmetry and wakes nobody.
#[derive(Clone, Copy, Debug)]
pub struct PumpWaker;

impl PumpWaker {
    pub fn for_current_thread() -> Self {
        Self
    }

    /// A waker that wakes nobody, for tests exercising the command lanes
    /// without a pump thread.
    #[cfg(test)]
    pub fn disconnected() -> Self {
        Self
    }

    pub fn wake(&self) {}
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

/// Nothing to set up: the viewer build has no tray shell and egui owns its
/// own event loop in the `--dashboard` process.
pub fn init_app_shell() {}

/// No shell event queue exists outside the dashboard's own loop.
pub fn pump_app_events() {}

/// No pump runs on Linux (LIN-0); there is nothing to stop.
pub fn request_pump_quit() {}

/// LIN-0: ambient capture has no Linux backend. `run()`'s Linux stub
/// declines before the pipeline is wired, so this is unreachable in
/// practice; it answers honestly anyway.
pub fn run_capture_pump<F>(
    _tx: Sender<Captured>,
    _stop: StopToken,
    _controls: CaptureControls,
    _after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    Err(CaptureError::UnsupportedPlatform)
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
    fn capture_pump_declines_as_unsupported() {
        let (tx, _rx) = crossbeam_channel::bounded(1);
        let result = run_capture_pump(tx, StopToken::new(), CaptureControls::default(), || {});
        assert!(
            matches!(result, Err(CaptureError::UnsupportedPlatform)),
            "the Linux pump must decline, not pretend"
        );
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
