//! Host-services facade (MAC-0): the per-OS seam between the app and the
//! platform. Everything the app needs from the host — data/downloads
//! directories, hostname, the single-instance guard, atomic config replace,
//! blocking confirm dialogs, and the capture pump's run/wake/quit surface —
//! is consumed through this module, so `main.rs` and `config.rs` carry no
//! platform API calls of their own.
//!
//! The Windows backend is the pre-MAC-0 code moved here unchanged
//! (zero-Windows-behavior-change rule, ROADMAP "macOS port" section). The
//! macOS backend is the MAC-0 seam implementation: real paths, lockfile
//! single instance, and POSIX rename; dialogs and the capture pump are
//! honest stubs until MAC-1 (NSAlert, CFRunLoop + real event sources).
//! The Linux backend is the LIN-1 dogfood seam: the LIN-0 viewer pieces
//! (real paths and guards, stub dialogs — a recorded LIN-1 gap) plus the
//! live X11 capture pump, self-pipe waker, and XGrabKey pause hotkey from
//! `gilbreth-capture-linux`. X11 only; Wayland is absent by design.

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod imp;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;

pub use imp::{
    alert, confirm, confirm_three_way, current_permission_state, downloads_dir, init_app_shell,
    init_permission_baseline, init_termination_signal, is_other_session_instance_error,
    local_data_dir, local_host_name, note_permission_state_written, open_url,
    perform_permission_action, permission_state_changed, pump_app_events,
    reconcile_sensitive_context_before_resume, register_pause_hotkey, replace_file,
    request_pump_quit, run_capture_pump, take_pause_hotkey_press, take_termination_signal,
    DashboardUiStateOwner, LifecycleExclusiveGuard, LifecycleGuard, PauseHotkeyRegistration,
    PumpWaker, SingleInstance,
};

/// Icon/severity of a blocking dialog. On Windows this maps 1:1 onto
/// `MB_ICONINFORMATION` / `MB_ICONWARNING`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertKind {
    Info,
    Warning,
}

/// Button set of a blocking confirm dialog. On Windows this maps 1:1 onto
/// `MB_OKCANCEL` / `MB_YESNO`; the positive answer is OK / Yes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmButtons {
    OkCancel,
    YesNo,
}

/// Answer of a three-way Yes / No / Cancel confirm (`confirm_three_way`):
/// the explicit positive choice, the explicit negative choice, or a
/// dismissal (Cancel button, Esc, the close box) meaning "decide later".
/// Fail-safe paths that cannot render a dialog answer `Dismissed` — the
/// do-nothing outcome. The design record is
/// the first-run consent design; its "`ConfirmButtons` gains a
/// `YesNoCancel` variant" shape is realized as this dedicated entry point
/// instead, because a button set the bool-returning `confirm()` cannot
/// answer honestly would be dead API surface (amended there).
// On Linux the stub dialogs answer only `Dismissed` (the recorded LIN-1
// gap), so the other variants are matched but never constructed there.
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmAnswer {
    Positive,
    Negative,
    Dismissed,
}
