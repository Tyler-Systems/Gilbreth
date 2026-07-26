//! macOS host services. Paths, the lockfile single-instance guard, atomic
//! config replace, the hostname, the CFRunLoop capture pump/waker, and the
//! blocking NSAlert dialogs (shell-remainders slice) are all real; off the
//! main thread the dialogs keep the earlier stub behavior — logged alerts,
//! auto-declined confirms — because AppKit UI is main-thread-only
//! (ROADMAP "macOS port" section, the macOS start-gate record).

use std::{
    env,
    ffi::c_void,
    fs, io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::Command,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    sync::Once,
};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::Sender;
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use objc2::{rc::autoreleasepool, MainThreadMarker};
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertStyle, NSApplication, NSApplicationActivationPolicy,
    NSEventMask,
};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSString};
use tracing::{info, warn};

use super::{AlertKind, ConfirmAnswer, ConfirmButtons};
use crate::hotkey::{HotkeyKey, PauseHotkeyChord};
use crate::permissions::{GrantState, PermissionAction, PermissionState, PERMISSION_STATE_VERSION};

pub fn reconcile_sensitive_context_before_resume(_pump_waker: PumpWaker) -> Option<u64> {
    Some(0)
}

pub fn local_data_dir() -> Result<PathBuf> {
    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Gilbreth"))
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
    // gethostname(2). MAC-1 may prefer the user-facing ComputerName from
    // SystemConfiguration; the session-identity host field only needs a
    // stable per-machine label.
    let mut buffer = [0u8; 256];
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return None;
    }
    let len = buffer.iter().position(|&byte| byte == 0)?;
    String::from_utf8(buffer[..len].to_vec()).ok()
}

/// Phase 5 package lifecycle locking is Windows-only. Keep the facade stable
/// for the shared app entry point without changing macOS process behavior.
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
/// stand-in for the Windows named mutex). The kernel drops the lock when
/// the process dies, so a crash never leaves a stale guard; the lockfile
/// itself is left in place deliberately (removing it would race a second
/// instance locking the same inode).
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

/// macOS's per-user data-root flock already spans login sessions. A blocked
/// launch remains the existing explicit duplicate error; there is no Windows
/// cross-session autostart distinction to classify here.
pub fn is_other_session_instance_error(_error: &anyhow::Error) -> bool {
    false
}

/// Cross-thread wake handle for the pump thread: signals the capture crate's
/// registered CFRunLoop wake source (the macOS analog of the Win32
/// `PostThreadMessageW(WM_APP)` wake). The pump registers its run loop when
/// it starts, so the handle itself stays a copyable token like the Windows
/// thread id.
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
            gilbreth_capture_macos::wake_pump();
        }
    }
}

/// SIGTERM latch (Shutdown rules, TCC record 2026-07-12): loginwindow and
/// `kill` deliver SIGTERM; the handler body is a single atomic store (the
/// only async-signal-safe thing it could do), and the app's service pass
/// consumes the flag through the normal quit path within one 50 ms tick —
/// SIGTERM is therefore exactly tray-Quit with a different trigger. The
/// pump has no NSApplication to receive loginwindow's quit AppleEvent, so
/// this latch plus the live logout probe (the log line at consumption
/// records what macOS actually delivered) is the recorded delivery story;
/// an AE quit handler is added only if the probe shows AppleEvents are the
/// real path. `NSSupportsSuddenTermination` stays off.
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
            warn!("failed to install the SIGTERM handler; logout delivery degrades to SIGKILL");
        }
    }
}

/// Consume a pending termination signal (edge-triggered; the service pass
/// polls this each tick and routes it through the tray-quit path).
pub fn take_termination_signal() -> bool {
    TERMINATION_REQUESTED.swap(false, std::sync::atomic::Ordering::SeqCst)
}

/// Input Monitoring's launch-time baseline (permissions panel): macOS
/// delivers Input Monitoring only at process launch, so a grant made while
/// the pump runs reads `preflight = true` while the tap still delivers
/// nothing until relaunch. The panel distinguishes active from
/// needs-relaunch by comparing the live preflight against this baseline —
/// preflight-true-now while it was false at launch means "granted, needs
/// relaunch". `0` = not captured, `1` = granted at launch, `2` = not
/// granted at launch. Accessibility needs no baseline (it activates live).
static INPUT_MONITORING_AT_LAUNCH: AtomicU8 = AtomicU8::new(0);

/// Capture the Input Monitoring launch baseline. Called once at pump
/// startup, before the panel can report state.
pub fn init_permission_baseline() {
    let granted = gilbreth_capture_macos::input_monitoring_trusted();
    INPUT_MONITORING_AT_LAUNCH.store(if granted { 1 } else { 2 }, Ordering::SeqCst);
}

/// The authoritative live permission state (pump process). Reads both
/// grants (non-prompting) and resolves Input Monitoring against the launch
/// baseline. If the baseline was never captured (defensive), a granted
/// Input Monitoring reports plain `Granted` rather than inventing a
/// relaunch prompt. `Option` for facade symmetry with the Windows no-op
/// (which returns `None` — no TCC panel there); the pump always gets
/// `Some` on macOS.
pub fn current_permission_state() -> Option<PermissionState> {
    let accessibility = if gilbreth_capture_macos::accessibility_trusted() {
        GrantState::Granted
    } else {
        GrantState::NotGranted
    };
    let input_monitoring = if gilbreth_capture_macos::input_monitoring_trusted() {
        match INPUT_MONITORING_AT_LAUNCH.load(Ordering::SeqCst) {
            2 => GrantState::GrantedNeedsRelaunch,
            _ => GrantState::Granted,
        }
    } else {
        GrantState::NotGranted
    };
    Some(PermissionState {
        version: PERMISSION_STATE_VERSION,
        accessibility,
        input_monitoring,
    })
}

/// Perform a permission action in the pump process (the only process
/// allowed to prompt, per the TCC record). The prompts register the bundle
/// and show the system flow; `Relaunch` re-launches via LaunchServices.
/// Returns whether the caller should quit the pump — **true only when a
/// `Relaunch` actually spawned its reopen waiter**, so a relaunch that
/// could not initiate (an unbundled dev binary with no `.app` to reopen)
/// never quits the pump into oblivion. Prompts return false (stay running).
#[must_use]
pub fn perform_permission_action(action: PermissionAction) -> bool {
    match action {
        PermissionAction::PromptAccessibility => {
            let trusted = gilbreth_capture_macos::prompt_accessibility();
            warn!(trusted, "Accessibility prompt fired from the pump process");
            false
        }
        PermissionAction::PromptInputMonitoring => {
            let granted = gilbreth_capture_macos::request_listen_access();
            warn!(
                granted,
                "Input Monitoring prompt fired from the pump process"
            );
            false
        }
        PermissionAction::Relaunch => relaunch_via_launch_services(),
    }
}

/// Relaunch through LaunchServices (the Input Monitoring activation step).
/// A raw self-exec would recreate the terminal-spawn TCC misattribution, so
/// this always goes through `open` on the resolved bundle. The relaunch
/// must not race the single-instance lock: a detached waiter polls until
/// this process exits, THEN opens the bundle, so the new instance never
/// hits `EWOULDBLOCK` on the still-held lockfile. Returns whether the
/// reopen waiter actually spawned — the caller quits only then, so an
/// unbundled binary (no `.app` to reopen) or a failed spawn leaves the pump
/// running rather than exiting with nothing to bring it back.
#[must_use]
pub fn relaunch_via_launch_services() -> bool {
    let Some(bundle) = bundle_path() else {
        warn!(
            "relaunch requested but the .app bundle path could not be resolved \
             (unbundled binary?); staying running rather than quitting with no reopen"
        );
        return false;
    };
    let pid = std::process::id();
    // Detached: wait for our pid to exit (LOCK released on the lockfile fd
    // close), then LaunchServices-open the bundle. `open` with no -n reuses
    // the (now-gone) instance slot cleanly.
    let script = format!(
        "while kill -0 {pid} 2>/dev/null; do sleep 0.2; done; \
         /usr/bin/open {}",
        shell_quote(&bundle.to_string_lossy())
    );
    match Command::new("/bin/sh").arg("-c").arg(&script).spawn() {
        Ok(_) => {
            info!("relaunch waiter spawned; the pump will quit and reopen via LaunchServices");
            true
        }
        Err(error) => {
            warn!(%error, "failed to spawn the relaunch waiter; staying running");
            false
        }
    }
}

/// Resolve the `.app` bundle path from the running executable
/// (`…/Gilbreth.app/Contents/MacOS/gilbreth-app` → `…/Gilbreth.app`). `None`
/// for an unbundled dev binary (no relaunch target).
fn bundle_path() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    // Contents/MacOS/<binary> → pop three components to the .app.
    let bundle = exe.parent()?.parent()?.parent()?;
    (bundle.extension().is_some_and(|ext| ext == "app")).then(|| bundle.to_path_buf())
}

/// Minimal single-quote shell escaping for the `open` argument.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Open a System Settings deep link (or any URL) via LaunchServices. Touches
/// no TCC, so the dashboard process calls this directly for the
/// Privacy-pane deep links. `false` if `open` could not be spawned.
pub fn open_url(url: &str) -> bool {
    match Command::new("/usr/bin/open").arg(url).spawn() {
        Ok(_) => true,
        Err(error) => {
            warn!(%error, "failed to open a System Settings deep link");
            false
        }
    }
}

/// Guard so a state-sidecar write only happens on an actual change (the
/// pump polls each pass; unchanged state must not churn the file).
static LAST_STATE_WRITTEN: AtomicU8 = AtomicU8::new(u8::MAX);
static STATE_EVER_WRITTEN: AtomicBool = AtomicBool::new(false);

fn state_fingerprint(state: &PermissionState) -> u8 {
    let g = |grant: GrantState| match grant {
        GrantState::NotGranted => 0u8,
        GrantState::Granted => 1,
        GrantState::GrantedNeedsRelaunch => 2,
    };
    g(state.accessibility) | (g(state.input_monitoring) << 2)
}

/// Whether the current state differs from the last one written (or nothing
/// has been written yet). The pump uses this to write the state sidecar
/// only on edges.
pub fn permission_state_changed(state: &PermissionState) -> bool {
    let fingerprint = state_fingerprint(state);
    !STATE_EVER_WRITTEN.load(Ordering::SeqCst)
        || LAST_STATE_WRITTEN.load(Ordering::SeqCst) != fingerprint
}

/// Record that the given state was written (called after a successful
/// sidecar write).
pub fn note_permission_state_written(state: &PermissionState) {
    LAST_STATE_WRITTEN.store(state_fingerprint(state), Ordering::SeqCst);
    STATE_EVER_WRITTEN.store(true, Ordering::SeqCst);
}

/// Ask the pump to exit (tray Quit): a latched stop flag plus
/// `CFRunLoopStop`, together the macOS analog of `PostQuitMessage`'s
/// never-lost WM_QUIT. The latch matters twice over. First, this is called
/// from inside the pump's service callback, where a bare `CFRunLoopStop`
/// is discarded (the loop is between runs); the flag guarantees exit
/// within one service pass. Second, the latch is the pump's SOLE quit
/// authority: once the shell dispatches NSEvents, AppKit stops the main
/// run loop for its own event-routing reasons (observed live 2026-07-12 —
/// hovering the status item quit the app), so the pump absorbs any stop
/// that arrives without this latch. The pump also exits when the stop
/// token cancels and a wake arrives, which is the path the shared tray
/// code takes first on both platforms.
pub fn request_pump_quit() {
    gilbreth_capture_macos::stop_pump();
}

/// Run the platform capture pump on the current thread until stop/quit: a
/// CFRunLoop with the wake source, the periodic service callback, and the
/// Foreground poller on the service cadence (the first mac ambient stream;
/// permission-free per the TCC record). The TCC-gated streams — event tap,
/// AX observers — arrive in later slices behind that record's cells.
pub fn run_capture_pump<F>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    gilbreth_capture_macos::run_pump(tx, stop, controls, after_service)
}

/// One-time AppKit application setup for the tray shell (Shell slice,
/// ROADMAP "macOS port" section): initialize the shared `NSApplication`,
/// pin the Accessory activation policy (no Dock icon, no app switcher —
/// the unbundled-dev-run twin of the bundle's `LSUIElement`), and
/// `finishLaunching` so the process is a launched app to AppKit. Without
/// this, status-item clicks queue as NSEvents that nothing dispatches and
/// the tray menu never opens (root cause recorded 2026-07-12 with the
/// Shell bullet).
///
/// Must run on the main thread (AppKit rule); `main` calls it before the
/// tray is built. Off the main thread it degrades honestly: one warning,
/// no AppKit touched, capture unaffected.
pub fn init_app_shell() {
    let Some(mtm) = MainThreadMarker::new() else {
        warn!("NSApplication setup skipped off the main thread; the tray menu will be inert");
        return;
    };
    autoreleasepool(|_pool| {
        let app = NSApplication::sharedApplication(mtm);
        // LSUIElement already implies Accessory for bundle launches;
        // setting it here covers unbundled dev runs too. The bool return
        // only reports whether the transition applied now — a refusal is
        // harmless (the bundle's plist policy stands).
        let _ = app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        app.finishLaunching();
    });
}

/// Dispatch pending AppKit events — the macOS half of what the Win32
/// pump's `GetMessage`/`DispatchMessage` loop does for the tray's hidden
/// window. The capture pump's `CFRunLoopRunInMode` services run-loop
/// sources and timers but never dequeues NSEvents, so the app drains the
/// queue here, once per service pass (≤ 50 ms latency; an arriving event
/// also wakes the run loop, so a click is normally dispatched at once).
/// `distantPast` expiration makes each call a non-blocking poll: drain
/// what is queued, never wait for new input.
///
/// A status-item click starts AppKit menu tracking *inside* `sendEvent`,
/// which runs a nested run loop until the menu closes. The capture tap
/// and pump wake source live in `kCFRunLoopCommonModes` so capture keeps
/// flowing during tracking; the rest of the service pass waits until the
/// menu closes (recorded parity nuance: Windows' modal menu loop keeps
/// its timers alive, ours pauses — the tap keeps queueing with true
/// event-time stamps, so nothing is lost, only derived late). Runs on the
/// pump/main thread with no capture-queue borrow held across it.
pub fn pump_app_events() {
    let Some(mtm) = MainThreadMarker::new() else {
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            warn!("NSEvent dispatch skipped off the main thread; the tray menu will be inert");
        });
        return;
    };
    // Pump-thread AppKit rule (Foreground-slice review blocker): every
    // AppKit access on this thread runs inside its own autorelease pool.
    autoreleasepool(|_pool| {
        let app = NSApplication::sharedApplication(mtm);
        // SAFETY: reading a framework-provided extern static; Foundation
        // initializes its run-loop mode constants before any code here runs.
        let mode = unsafe { NSDefaultRunLoopMode };
        let distant_past = NSDate::distantPast();
        while let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
            NSEventMask::Any,
            Some(&distant_past),
            mode,
            true,
        ) {
            app.sendEvent(&event);
        }
    });
}

/// Severity mapping (shell-remainders slice): `Info` →
/// `NSAlertStyle::Informational`; `Warning` → `NSAlertStyle::Critical`.
/// Meaning-parity over name-parity: modern macOS renders Warning and
/// Informational identically (the app icon), and the app reserves
/// `AlertKind::Warning` for destructive/failure surfaces (secure erase,
/// Record Routine failures) where the Windows UI shows a caution icon —
/// Critical's caution badge is the only macOS style that preserves that
/// visual severity distinction.
fn alert_style(kind: AlertKind) -> NSAlertStyle {
    match kind {
        AlertKind::Info => NSAlertStyle::Informational,
        AlertKind::Warning => NSAlertStyle::Critical,
    }
}

/// Build, activate, and run one modal NSAlert on the main thread. The
/// blocking `runModal` pauses the pump's service pass exactly as menu
/// tracking does (and as `MessageBoxW` blocks its thread on Windows); the
/// capture tap and wake source live in common modes, so capture keeps
/// queueing while the dialog is up. The explicit activation matters for an
/// Accessory-policy (menu-bar-only) app: without it the alert opens behind
/// the frontmost app's windows.
fn run_alert_modal(
    mtm: MainThreadMarker,
    title: &str,
    message: &str,
    kind: AlertKind,
    buttons: &[&str],
) -> isize {
    autoreleasepool(|_pool| {
        let alert = NSAlert::new(mtm);
        alert.setMessageText(&NSString::from_str(title));
        alert.setInformativeText(&NSString::from_str(message));
        alert.setAlertStyle(alert_style(kind));
        for label in buttons {
            let _ = alert.addButtonWithTitle(&NSString::from_str(label));
        }
        // activateIgnoringOtherApps is deprecated in favor of activate(),
        // but activate() is macOS 14+ and the MAC-1 floor is macOS 13
        // (start-gate item 3) — the deprecated call is the correct one for
        // the floor; it remains functional on current systems.
        #[allow(deprecated)]
        NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
        alert.runModal()
    })
}

/// Blocking NSAlert (shell-remainders slice). Off the main thread it keeps
/// the stub behavior — logged, never silently swallowed — because AppKit
/// UI is main-thread-only and every production caller (tray handlers, the
/// startup error path) runs there.
pub fn alert(title: &str, message: &str, kind: AlertKind) {
    let Some(mtm) = MainThreadMarker::new() else {
        warn!(
            title,
            message,
            ?kind,
            "alert dialog logged only (off the main thread)"
        );
        return;
    };
    let _ = run_alert_modal(mtm, title, message, kind, &["OK"]);
}

/// Blocking NSAlert confirm (shell-remainders slice). The first added
/// button is the default (Return key, rightmost): `default_negative`
/// decides whether the positive or the negative answer gets that slot,
/// mirroring `MB_DEFBUTTON2` on Windows. Returns true only for an explicit
/// positive click. Off the main thread every confirm answers negative —
/// the fail-safe refusal, so no destructive flow (erase, archive reset)
/// can proceed through a dialog nobody saw.
pub fn confirm(
    title: &str,
    message: &str,
    kind: AlertKind,
    buttons: ConfirmButtons,
    default_negative: bool,
) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        warn!(
            title,
            message,
            ?kind,
            ?buttons,
            default_negative,
            "confirm dialog auto-declined (off the main thread)"
        );
        return false;
    };
    let (positive, negative) = match buttons {
        ConfirmButtons::OkCancel => ("OK", "Cancel"),
        ConfirmButtons::YesNo => ("Yes", "No"),
    };
    let ordered = if default_negative {
        [negative, positive]
    } else {
        [positive, negative]
    };
    let response = run_alert_modal(mtm, title, message, kind, &ordered);
    let positive_slot = if default_negative {
        // Positive was added second.
        NSAlertFirstButtonReturn + 1
    } else {
        NSAlertFirstButtonReturn
    };
    response == positive_slot
}

/// Blocking three-way Yes / No / Cancel confirm (first-run consent dialog,
/// the first-run consent design). Button order encodes the design's keyboard
/// posture: "No" is added first (Return keeps the safe default, the
/// `MB_DEFBUTTON2` twin), and AppKit gives any button literally titled
/// "Cancel" the Escape key equivalent automatically (NSAlert
/// `addButtonWithTitle:` contract), so Esc lands on `Dismissed` ("decide
/// later") with no per-button wiring. Off the main thread the fail-safe is
/// `Dismissed` — the do-nothing outcome, matching the design's rule that
/// the safe path is also the deferral path.
pub fn confirm_three_way(title: &str, message: &str, kind: AlertKind) -> ConfirmAnswer {
    let Some(mtm) = MainThreadMarker::new() else {
        warn!(
            title,
            message,
            ?kind,
            "three-way confirm deferred (off the main thread)"
        );
        return ConfirmAnswer::Dismissed;
    };
    let response = run_alert_modal(mtm, title, message, kind, &["No", "Yes", "Cancel"]);
    if response == NSAlertFirstButtonReturn {
        ConfirmAnswer::Negative
    } else if response == NSAlertFirstButtonReturn + 1 {
        ConfirmAnswer::Positive
    } else {
        ConfirmAnswer::Dismissed
    }
}

// ---------------------------------------------------------------------------
// Pause hotkey — Carbon `RegisterEventHotKey`.
//
// The Windows twin uses `RegisterHotKey`; Carbon is its structural analogue and
// the mechanism the owner chose (2026-07-19) over matching inside the capture
// event tap. The tap's mask is gated on `input_trusted`, and an untrusted tap is
// torn down entirely, so a tap-matched chord would be dead for any user who has
// not granted Input Monitoring — Gilbreth's zero-grant tier is supported, so
// that would relocate the silently-dead surface rather than remove it. Carbon
// needs no TCC permission at all and, like `RegisterHotKey`, consumes the chord.
//
// Delivery was measured before this was written (`bin/gilbreth-hotkey-probe.rs`,
// 2026-07-19): the handler fires under the pump's manual `CFRunLoopRunInMode`
// pass plus hand `NSEvent` drain, with no `[NSApp run]`. That was not derivable
// from the code and is the assumption the whole mechanism rests on.
//
// Registration runs at the existing Windows call site, which sits after
// `init_app_shell()` and before `run_capture_pump` — NSApplication is up, we are
// on the main thread, and the run loop that delivers the events starts after. No
// deferred arming is needed.
// ---------------------------------------------------------------------------

type OSStatus = i32;
/// `MacTypes.h:291` — `typedef unsigned long ItemCount;`, so 64-bit here, not
/// the obvious `u32`.
type ItemCount = usize;

type EventTargetRef = *mut c_void;
type EventHandlerRef = *mut c_void;
type EventHandlerCallRef = *mut c_void;
type EventRef = *mut c_void;
type EventHotKeyRef = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHotKeyID {
    signature: u32,
    id: u32,
}

type EventHandlerProc = extern "C" fn(EventHandlerCallRef, EventRef, *mut c_void) -> OSStatus;

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetApplicationEventTarget() -> EventTargetRef;
    fn InstallEventHandler(
        target: EventTargetRef,
        handler: EventHandlerProc,
        num_types: ItemCount,
        list: *const EventTypeSpec,
        user_data: *mut c_void,
        out_ref: *mut EventHandlerRef,
    ) -> OSStatus;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyID,
        target: EventTargetRef,
        options: u32,
        out_ref: *mut EventHotKeyRef,
    ) -> OSStatus;
    fn UnregisterEventHotKey(hot_key: EventHotKeyRef) -> OSStatus;
}

/// `'keyb'` — `kEventClassKeyboard`.
const K_EVENT_CLASS_KEYBOARD: u32 = 0x6B65_7962;
/// `kEventHotKeyPressed`.
const K_EVENT_HOT_KEY_PRESSED: u32 = 5;

// Carbon modifier bits (`Events.h`). NOT the `CGEventFlags` bits used by the
// capture tap — same concepts, different values.
const CONTROL_KEY: u32 = 0x1000;
const OPTION_KEY: u32 = 0x0800;
const SHIFT_KEY: u32 = 0x0200;
const CMD_KEY: u32 = 0x0100;

/// Set by the Carbon handler, consumed once per pump service pass. Identical
/// edge semantics to the Windows `PAUSE_HOTKEY_PRESSED`.
static PAUSE_HOTKEY_PRESSED: AtomicBool = AtomicBool::new(false);
/// The Carbon event handler is installed once per process. Re-installing on a
/// re-registration would deliver each press N times.
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn pause_hotkey_handler(
    _call_ref: EventHandlerCallRef,
    _event: EventRef,
    _user_data: *mut c_void,
) -> OSStatus {
    // Minimal by design, like the capture tap callback: set a flag, return.
    // Everything else happens on the pump's service pass.
    PAUSE_HOTKEY_PRESSED.store(true, Ordering::SeqCst);
    // noErr claims the event, which is what makes the chord consumed.
    0
}

/// Lifetime guard for the Carbon claim, mirroring the Windows twin. Registration
/// and unregistration both happen on the pump/main thread.
pub struct PauseHotkeyRegistration {
    hot_key: EventHotKeyRef,
}

// SAFETY: the ref is only ever touched on the pump/main thread — created at
// launch there and unregistered by `Drop` on the same thread. The raw pointer
// alone is what makes the struct non-Send.
unsafe impl Send for PauseHotkeyRegistration {}

impl Drop for PauseHotkeyRegistration {
    fn drop(&mut self) {
        // SAFETY: `hot_key` is the live registration returned by
        // `RegisterEventHotKey` and is unregistered exactly once.
        let status = unsafe { UnregisterEventHotKey(self.hot_key) };
        if status != 0 {
            warn!(status, "failed to unregister the pause hotkey");
        }
    }
}

pub fn register_pause_hotkey(chord: PauseHotkeyChord) -> Result<PauseHotkeyRegistration> {
    let key_code = carbon_key_code(chord.key).ok_or_else(|| {
        anyhow!(
            "macOS has no key for {}; choose a different pause chord",
            chord.key
        )
    })?;

    if !HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        let spec = EventTypeSpec {
            event_class: K_EVENT_CLASS_KEYBOARD,
            event_kind: K_EVENT_HOT_KEY_PRESSED,
        };
        let mut handler_ref: EventHandlerRef = ptr::null_mut();
        // SAFETY: Carbon copies the type list, so `spec` need not outlive the
        // call; the handler matches `EventHandlerUPP`; the out-param is a valid
        // local. Never removed — the handler lives for the process.
        let status = unsafe {
            InstallEventHandler(
                GetApplicationEventTarget(),
                pause_hotkey_handler,
                1,
                &spec,
                ptr::null_mut(),
                &mut handler_ref,
            )
        };
        if status != 0 {
            HANDLER_INSTALLED.store(false, Ordering::SeqCst);
            return Err(anyhow!(
                "InstallEventHandler rejected the pause-hotkey handler (status {status})"
            ));
        }
    }

    let mut hot_key: EventHotKeyRef = ptr::null_mut();
    // SAFETY: documented signature; `id` is a by-value POD struct; the
    // out-param is a valid local.
    let status = unsafe {
        RegisterEventHotKey(
            key_code,
            carbon_modifiers(chord),
            EventHotKeyID {
                signature: u32::from_be_bytes(*b"glbr"),
                id: 1,
            },
            GetApplicationEventTarget(),
            0,
            &mut hot_key,
        )
    };
    if status != 0 {
        // The documented failure is `eventHotKeyExistsErr` (-9878): another app
        // already owns this chord. That is the same meaning as the Windows
        // `RegisterHotKey` failure, so `registration_failure_alert` and
        // `PauseHotkeyStatus::unregistered` apply verbatim.
        return Err(anyhow!(
            "RegisterEventHotKey rejected the configured pause chord (status {status})"
        ));
    }

    PAUSE_HOTKEY_PRESSED.store(false, Ordering::SeqCst);
    Ok(PauseHotkeyRegistration { hot_key })
}

fn carbon_modifiers(chord: PauseHotkeyChord) -> u32 {
    let mut modifiers = 0;
    if chord.ctrl {
        modifiers |= CONTROL_KEY;
    }
    if chord.alt {
        modifiers |= OPTION_KEY;
    }
    if chord.shift {
        modifiers |= SHIFT_KEY;
    }
    if chord.win {
        modifiers |= CMD_KEY;
    }
    modifiers
}

/// `HotkeyKey` to macOS virtual keycode, the twin of `windows_virtual_key`.
///
/// `None` means the key does not exist on a Mac keyboard. `Insert` and `Pause`
/// have no macOS keycode, and macOS function keys stop at F20 where Windows
/// goes to F24. Returning `None` produces the same "off for this run" path as a
/// contended chord rather than silently binding the wrong key.
fn carbon_key_code(key: HotkeyKey) -> Option<u32> {
    let code: u16 = match key {
        HotkeyKey::Letter(value) => match value.to_ascii_uppercase() {
            'A' => 0x00,
            'B' => 0x0B,
            'C' => 0x08,
            'D' => 0x02,
            'E' => 0x0E,
            'F' => 0x03,
            'G' => 0x05,
            'H' => 0x04,
            'I' => 0x22,
            'J' => 0x26,
            'K' => 0x28,
            'L' => 0x25,
            'M' => 0x2E,
            'N' => 0x2D,
            'O' => 0x1F,
            'P' => 0x23,
            'Q' => 0x0C,
            'R' => 0x0F,
            'S' => 0x01,
            'T' => 0x11,
            'U' => 0x20,
            'V' => 0x09,
            'W' => 0x0D,
            'X' => 0x07,
            'Y' => 0x10,
            'Z' => 0x06,
            _ => return None,
        },
        HotkeyKey::Digit(value) => match value {
            '0' => 0x1D,
            '1' => 0x12,
            '2' => 0x13,
            '3' => 0x14,
            '4' => 0x15,
            '5' => 0x17,
            '6' => 0x16,
            '7' => 0x1A,
            '8' => 0x1C,
            '9' => 0x19,
            _ => return None,
        },
        HotkeyKey::Function(value) => match value {
            1 => 0x7A,
            2 => 0x78,
            3 => 0x63,
            4 => 0x76,
            5 => 0x60,
            6 => 0x61,
            7 => 0x62,
            8 => 0x64,
            9 => 0x65,
            10 => 0x6D,
            11 => 0x67,
            12 => 0x6F,
            13 => 0x69,
            14 => 0x6B,
            15 => 0x71,
            16 => 0x6A,
            17 => 0x40,
            18 => 0x4F,
            19 => 0x50,
            20 => 0x5A,
            // F21-F24 exist as Windows virtual keys but have no macOS keycode.
            _ => return None,
        },
        HotkeyKey::Backspace => 0x33,
        HotkeyKey::Tab => 0x30,
        HotkeyKey::Enter => 0x24,
        HotkeyKey::Escape => 0x35,
        HotkeyKey::Space => 0x31,
        HotkeyKey::PageUp => 0x74,
        HotkeyKey::PageDown => 0x79,
        HotkeyKey::End => 0x77,
        HotkeyKey::Home => 0x73,
        HotkeyKey::Left => 0x7B,
        HotkeyKey::Up => 0x7E,
        HotkeyKey::Right => 0x7C,
        HotkeyKey::Down => 0x7D,
        HotkeyKey::Delete => 0x75,
        // No macOS keycode exists for either.
        HotkeyKey::Insert | HotkeyKey::Pause => return None,
    };
    Some(u32::from(code))
}

/// Consume the edge recorded by the Carbon handler. Called once per pump
/// service pass, immediately before tray/menu handling.
pub fn take_pause_hotkey_press() -> bool {
    PAUSE_HOTKEY_PRESSED.swap(false, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `carbon_key_code` is a second hand-written keycode table beside the one
    /// in `gilbreth-capture-macos`. Two such tables drift silently, so every
    /// key this one claims is checked against the capture vocabulary: register
    /// the wrong keycode and the chord binds a key the user did not ask for,
    /// with nothing else to catch it.
    ///
    /// Proven to bite by mutation: changing any single arm fails here.
    #[test]
    fn carbon_keycodes_agree_with_the_capture_key_vocabulary() {
        use gilbreth_capture_macos::key_name_for_keycode as name_of;

        // (HotkeyKey, the capture crate's name for that physical key).
        // The two vocabularies differ for the arrows, which is exactly the
        // kind of mismatch this test exists to keep honest.
        let cases: &[(HotkeyKey, &str)] = &[
            (HotkeyKey::Letter('p'), "P"),
            (HotkeyKey::Letter('a'), "A"),
            (HotkeyKey::Letter('z'), "Z"),
            (HotkeyKey::Digit('0'), "0"),
            (HotkeyKey::Digit('9'), "9"),
            (HotkeyKey::Function(1), "F1"),
            (HotkeyKey::Function(12), "F12"),
            (HotkeyKey::Function(20), "F20"),
            (HotkeyKey::Backspace, "Backspace"),
            (HotkeyKey::Tab, "Tab"),
            (HotkeyKey::Escape, "Escape"),
            (HotkeyKey::Space, "Space"),
            (HotkeyKey::PageUp, "PageUp"),
            (HotkeyKey::PageDown, "PageDown"),
            (HotkeyKey::End, "End"),
            (HotkeyKey::Home, "Home"),
            (HotkeyKey::Delete, "Delete"),
            (HotkeyKey::Left, "ArrowLeft"),
            (HotkeyKey::Right, "ArrowRight"),
            (HotkeyKey::Up, "ArrowUp"),
            (HotkeyKey::Down, "ArrowDown"),
        ];

        for (key, expected) in cases {
            let code =
                carbon_key_code(*key).unwrap_or_else(|| panic!("{key} must have a macOS keycode"));
            let code = u16::try_from(code).expect("keycode fits u16");
            assert_eq!(
                name_of(code),
                *expected,
                "{key} maps to keycode {code:#04x}, which the capture vocabulary calls {}",
                name_of(code)
            );
        }
    }

    /// Keys that exist as Windows virtual keys but have no macOS keycode must
    /// resolve to `None`, so registration fails loudly into the existing
    /// "off for this run" path. Silently binding a nearby key would be the
    /// same class of defect P3 exists to remove.
    #[test]
    fn keys_absent_from_mac_keyboards_have_no_keycode() {
        assert!(carbon_key_code(HotkeyKey::Insert).is_none());
        assert!(carbon_key_code(HotkeyKey::Pause).is_none());
        // macOS function keys stop at F20; Windows goes to F24.
        assert!(carbon_key_code(HotkeyKey::Function(20)).is_some());
        assert!(carbon_key_code(HotkeyKey::Function(21)).is_none());
        assert!(carbon_key_code(HotkeyKey::Function(24)).is_none());
    }

    /// Carbon modifier bits are a different numbering from the `CGEventFlags`
    /// the capture tap uses; mixing them up would register a chord nobody can
    /// press. `win` is the schema's name for the physical Command key.
    #[test]
    fn carbon_modifiers_map_each_flag_to_its_own_bit() {
        let chord = |ctrl, alt, shift, win| PauseHotkeyChord {
            ctrl,
            alt,
            shift,
            win,
            key: HotkeyKey::Letter('p'),
        };
        assert_eq!(carbon_modifiers(chord(true, false, false, false)), 0x1000);
        assert_eq!(carbon_modifiers(chord(false, true, false, false)), 0x0800);
        assert_eq!(carbon_modifiers(chord(false, false, true, false)), 0x0200);
        assert_eq!(carbon_modifiers(chord(false, false, false, true)), 0x0100);
        // The shipped default, Control-Option-Shift-P.
        assert_eq!(carbon_modifiers(chord(true, true, true, false)), 0x1A00);
    }

    /// The press edge is consume-once, like the Windows twin: the pump reads it
    /// on one service pass and must not see it again on the next.
    #[test]
    fn taking_the_press_edge_clears_it() {
        PAUSE_HOTKEY_PRESSED.store(false, Ordering::SeqCst);
        assert!(!take_pause_hotkey_press());
        PAUSE_HOTKEY_PRESSED.store(true, Ordering::SeqCst);
        assert!(take_pause_hotkey_press());
        assert!(!take_pause_hotkey_press(), "the edge must not repeat");
    }

    #[test]
    fn relaunch_without_a_bundle_declines_and_spawns_nothing() {
        // Tail-review pin for the fc90010 contract: "quit only when a
        // reopen actually spawned". The test binary lives under target/,
        // not inside an .app, so bundle resolution must fail and the call
        // must return false without spawning a waiter — pre-fix this path
        // quit the pump into oblivion. (If tests ever run from inside a
        // bundle this assert flips, which would itself be worth knowing.)
        assert!(
            !relaunch_via_launch_services(),
            "an unbundled binary must decline the relaunch"
        );
    }

    #[test]
    fn app_shell_calls_are_inert_off_the_main_thread() {
        // Tests never run on the AppKit main thread; every AppKit-touching
        // entry point must degrade to a logged no-op there rather than
        // touching AppKit — and a confirm nobody can see must answer
        // negative (the fail-safe refusal).
        std::thread::spawn(|| {
            init_app_shell();
            pump_app_events();
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
        })
        .join()
        .expect("off-main-thread app-shell calls must not panic");
    }

    #[test]
    fn state_fingerprint_distinguishes_every_grant_combination() {
        // The pump writes the sidecar on edges; the fingerprint must change
        // for any per-permission transition, or an edge would be missed.
        let grants = [
            GrantState::NotGranted,
            GrantState::Granted,
            GrantState::GrantedNeedsRelaunch,
        ];
        let mut seen = std::collections::HashSet::new();
        for accessibility in grants {
            for input_monitoring in grants {
                let state = PermissionState {
                    version: PERMISSION_STATE_VERSION,
                    accessibility,
                    input_monitoring,
                };
                assert!(
                    seen.insert(state_fingerprint(&state)),
                    "collision at {accessibility:?}/{input_monitoring:?}"
                );
            }
        }
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(
            shell_quote("/Applications/Gilbreth.app"),
            "'/Applications/Gilbreth.app'"
        );
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
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
