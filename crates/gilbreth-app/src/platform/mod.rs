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

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod imp;

pub use imp::{
    alert, confirm, confirm_three_way, current_permission_state, downloads_dir, init_app_shell,
    init_permission_baseline, init_termination_signal, is_other_session_instance_error,
    local_data_dir, local_host_name, note_permission_state_written, open_url,
    perform_permission_action, permission_state_changed, pump_app_events,
    reconcile_sensitive_context_before_resume, replace_file, request_pump_quit, run_capture_pump,
    take_termination_signal, DashboardUiStateOwner, LifecycleExclusiveGuard, LifecycleGuard,
    PumpWaker, SingleInstance,
};

#[cfg(any(windows, target_os = "macos"))]
pub use imp::{register_pause_hotkey, take_pause_hotkey_press, PauseHotkeyRegistration};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmAnswer {
    Positive,
    Negative,
    Dismissed,
}
