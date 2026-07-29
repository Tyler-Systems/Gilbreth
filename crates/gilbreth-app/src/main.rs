#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod authenticode;
// Launch-at-startup: HKCU Run key on Windows, SMAppService login item on
// macOS (shell-remainders slice); the stub declines on any other target.
#[cfg(windows)]
mod autostart;
#[cfg(target_os = "macos")]
#[path = "autostart_macos.rs"]
mod autostart;
#[cfg(not(any(windows, target_os = "macos")))]
#[path = "autostart_stub.rs"]
mod autostart;
mod config;
mod consent;
mod consent_copy;
#[cfg(test)]
mod copy_audit;
#[cfg(windows)]
mod elevated_record_helper;
mod health;
mod hotkey;
mod notification_consent;
// The macOS TCC permission subsystem (onboarding/Diagnostics panel). The
// module is cross-platform (types + sidecar IO); the mac-specific reads and
// prompt/relaunch actions live behind the platform facade.
mod permissions;
mod platform;
mod privacy_receipt;
mod uninstall;

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{Seek, SeekFrom, Write},
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use config::{AppConfig, ConfigStatus};
use crossbeam_channel::{bounded, select, Receiver, Sender};
#[cfg(windows)]
use gilbreth_capture_windows::record_routine::{
    start_record_routine_capture, RecordRoutineConfig, RecordRoutineHandle,
};
use gilbreth_core::RecordStopReason;
use gilbreth_core::{
    CaptureControls, CaptureStream, Captured, EventPayload, Sequencer, SessionTimebase, Source,
    StopToken, WriterInput,
};
use gilbreth_store::{
    run_writer_with_commands, ArchiveResetOutcome, ArchiveResetReport, CapPrompt, GilbrethStore,
    PanicActionCutoff, PendingRecordRequest, SecureEraseOutcome, SecureEraseReport,
    SessionIdentity, StoreError, WriterCommand, WriterReport,
};
use platform::{
    alert, confirm, downloads_dir, local_data_dir, local_host_name, AlertKind, ConfirmButtons,
    DashboardUiStateOwner, LifecycleGuard, PumpWaker, SingleInstance,
};
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu},
    Icon, TrayIcon, TrayIconBuilder,
};

const CHANNEL_CAPACITY: usize = 4096;
const WRITER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_FORWARDER_FLUSH_QUIET_PERIOD: Duration = Duration::from_millis(250);
const CAPTURE_FORWARDER_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const FOREGROUND_MENU_ID: &str = "capture_foreground";
const WINDOWS_MENU_ID: &str = "capture_windows";
const KEYBOARD_MENU_ID: &str = "capture_keyboard";
const MOUSE_MENU_ID: &str = "capture_mouse";
const SYSTEM_MENU_ID: &str = "capture_system";
const IDLE_MENU_ID: &str = "capture_idle";
const OPEN_DASHBOARD_MENU_ID: &str = "open_dashboard";
const OPEN_DASHBOARD_MENU_LABEL: &str = "Open Dashboard";
const PAUSE_CAPTURE_MENU_ID: &str = "pause_capture";
/// Second-process flag: the tray spawns the same exe with this argument to
/// open the egui dashboard (S4 process model — one binary, no socket).
const DASHBOARD_PROCESS_FLAG: &str = "--dashboard";
/// The scripted graceful stop: ask the running instance to exit through
/// the WM_CLOSE quit path (same flush as tray Quit). Exit code 0 when an
/// instance acknowledged, 1 when none was found.
#[cfg(windows)]
const QUIT_FLAG: &str = "--quit";
// Archive and reset is Windows-only until the mac key wrap is decided
// (owner decision 2026-07-19: no mac archive lane at MAC-2). `dpapi_protect`
// cannot succeed off Windows, so shipping the item would ship an action that
// always fails.
#[cfg(windows)]
const ARCHIVE_RESET_MENU_ID: &str = "archive_reset";
const ERASE_ALL_DATA_MENU_ID: &str = "erase_all_data";
// Record Routine is Windows-only by decision record; macOS has no tray
// surface for it, so the ids and labels do not exist there either.
#[cfg(windows)]
const RECORD_ROUTINE_MENU_ID: &str = "record_routine";
#[cfg(windows)]
const STOP_RECORDING_MENU_ID: &str = "stop_recording";
#[cfg(windows)]
const PAUSE_RECORDING_MENU_ID: &str = "pause_recording";
#[cfg(windows)]
const RESUME_RECORDING_MENU_ID: &str = "resume_recording";
const STORE_KEY_CONTENT_MENU_ID: &str = "store_key_content";
const NOTIFICATION_ACCESS_MENU_ID: &str = "notification_access";
const LAUNCH_AT_STARTUP_MENU_ID: &str = "launch_at_startup";
const QUIT_MENU_ID: &str = "quit";
const GILBRETH_LOG_ENV: &str = "GILBRETH_LOG";
const DEFAULT_LOG_FILTER: &str = "info";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_SHA: &str = env!("GILBRETH_GIT_SHA");

// ---- Tray + dialog copy (Lane B residual sweep, 2026-07-14) ----
//
// Every string a user reads in the tray menu, the tray tooltip, or a
// Gilbreth dialog is pinned here or produced by a small builder fn the
// copy audit exercises with fixtures (`copy_audit` module). The
// copy-style audit parses these constants straight out of this file, so
// a new dialog string added inline elsewhere is invisible to it — add
// the constant here instead. Rules: docs/MAINTAINING.md, Product-copy rules.
// Deliberate exceptions carry a `// copy-allow:` line beside the
// constant; the dialog-title and tooltip em dashes are name — context
// notation (the "Recording N — untitled" data-notation family), not
// prose punctuation.

const MENU_LABEL_CAPTURE: &str = "Capture";
const MENU_LABEL_FOREGROUND: &str = "Foreground";
const MENU_LABEL_WINDOWS: &str = "Windows";
const MENU_LABEL_KEYBOARD: &str = "Keyboard";
const MENU_LABEL_MOUSE: &str = "Mouse";
const MENU_LABEL_SYSTEM: &str = "System";
const MENU_LABEL_IDLE: &str = "Idle";
const MENU_LABEL_PAUSE_CAPTURE: &str = "Pause capture";
const MENU_LABEL_RESUME_CAPTURE: &str = "Resume capture";
const MENU_LABEL_PRIVACY: &str = "Privacy";
const MENU_LABEL_STORE_KEY_CONTENT: &str = "Store typed key content";
const MENU_LABEL_NOTIFICATION_ACCESS: &str = "Notification counts...";
#[cfg_attr(not(windows), allow(dead_code))]
const MENU_LABEL_NOTIFICATION_ACCESS_ON: &str = "Notification counts: On...";
#[cfg_attr(not(windows), allow(dead_code))]
const MENU_LABEL_NOTIFICATION_ACCESS_DENIED: &str = "Notification counts: Denied...";
#[cfg(windows)]
const MENU_LABEL_ARCHIVE_RESET: &str = "Archive and reset...";
const MENU_LABEL_ERASE_ALL_DATA: &str = "Erase all my data...";
#[cfg(windows)]
const MENU_LABEL_RECORD_ROUTINE: &str = "Record Routine...";
#[cfg(windows)]
const MENU_LABEL_STOP_RECORDING: &str = "Stop recording";
#[cfg(windows)]
const MENU_LABEL_PAUSE_RECORDING: &str = "Pause recording";
#[cfg(windows)]
const MENU_LABEL_RESUME_RECORDING: &str = "Resume recording";
const MENU_LABEL_LAUNCH_AT_STARTUP: &str = "Launch at startup";
const MENU_LABEL_QUIT: &str = "Quit";

const TOOLTIP_DEFAULT: &str = "Gilbreth";
// copy-allow: em-dash name — state tooltip notation, not prose (Lane B ruling, data-notation family)
const TOOLTIP_CAPTURE_PAUSED: &str = "Gilbreth — capture paused (Resume from tray or pause hotkey)";
// copy-allow: em-dash name — state tooltip notation, not prose (Lane B ruling, data-notation family)
const TOOLTIP_RECORDING_PAUSED: &str = "Gilbreth — recording paused (Resume / Stop)";
// copy-allow: em-dash name — state tooltip notation, not prose (Lane B ruling, data-notation family)
const TOOLTIP_RECORDING: &str = "Gilbreth — recording (Pause / Stop)";

const DIALOG_TITLE_DASHBOARD: &str = "Gilbreth Dashboard";
const DIALOG_TITLE_APP: &str = "Gilbreth";
// The copy-allow must sit directly above the constant it grants: the auditor
// binds it to the next string literal, and the cfg predicate below contains
// one ("macos").
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_PAUSE_HOTKEY: &str = "Gilbreth — Pause hotkey";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_SETTINGS_NOT_LOADED: &str = "Gilbreth — Settings not loaded";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_PRIVACY: &str = "Gilbreth — Privacy";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_LAUNCH_AT_STARTUP: &str = "Gilbreth — Launch at startup";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_RECORD_ROUTINE: &str = "Gilbreth — Record Routine";
#[cfg_attr(not(windows), allow(dead_code))]
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_ARCHIVE_RESET: &str = "Gilbreth — Archive and reset";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
const DIALOG_TITLE_SECURE_ERASE: &str = "Gilbreth — Secure erase";

const BODY_DASHBOARD_START_FAILED_PREFIX: &str =
    "The dashboard couldn't start.\n\nTechnical detail:\n";
const BODY_APP_START_FAILED_PREFIX: &str =
    "Gilbreth couldn't start or keep recording.\n\nTechnical detail:\n";
const BODY_CONFIG_MALFORMED_PREFIX: &str =
    "Your config file could not be read, so Gilbreth is running with default settings \
     for now. Any custom privacy capture exclusions, redaction rules, or storage paths \
     in it are NOT active until it is fixed.\n\nYour file was left unchanged: correct \
     it and restart Gilbreth to restore your settings.\n\nDetail: ";
const BODY_STORE_KEY_CONTENT_ON: &str =
    "Typed key content will be stored starting the next time Gilbreth runs. Until then \
     keystrokes stay counted without content.";
const BODY_STORE_KEY_CONTENT_OFF: &str =
    "Key content storage is off. The change takes effect the next time Gilbreth runs; \
     rows captured before the restart keep their content unless you prune or erase them.";
const BODY_LAUNCH_AT_STARTUP_FAILED_PREFIX: &str = "Couldn't change launch at startup.\n\n";
const BODY_PRIVACY_BLOCKED_DURING_RECORDING: &str =
    "Finish or stop the current Record Routine before archiving, resetting, or erasing \
     activity.";
#[cfg(windows)]
const BODY_RECORD_BLOCKED_DURING_PRIVACY: &str =
    "Finish the current privacy action before starting a Record Routine.";
#[cfg_attr(windows, allow(dead_code))]
const BODY_NOTIFICATIONS_UNSUPPORTED_PLATFORM: &str =
    "Notification capture is not available on this operating system.";
#[cfg_attr(not(windows), allow(dead_code))]
const BODY_NOTIFICATION_SETTINGS_QUESTION: &str = "Open Windows notification privacy settings?";
#[cfg_attr(not(windows), allow(dead_code))]
const BODY_NOTIFICATION_SETTINGS_OPEN_FAILED: &str =
    "Windows Settings could not be opened. Open Settings > Privacy & security > \
     Notifications manually.";
#[cfg_attr(not(windows), allow(dead_code))]
const BODY_ELEVATED_HELPER_FALLBACK: &str =
    "The elevated helper did not start, so this recording will continue with standard \
     Record Routine capture. Administrator windows may still be skipped.";
#[cfg_attr(not(windows), allow(dead_code))]
const BODY_UIA_START_FAILED_PREFIX: &str =
    "Recording could not start UI Automation capture, so Gilbreth will close this \
     recording as an error:\n\n";
#[cfg(windows)]
const BODY_RECORD_START_EXPLANATION: &str =
    "Gilbreth will record which UI elements you act on and the kind of action (click, \
     toggle, select, and so on) until you stop. It never records the text you type, \
     the values of fields, screenshots, or window contents. A recording indicator \
     stays in the system tray while it runs, and the recording is stored locally so \
     you can review or delete it from the dashboard. Choose OK to continue, or Cancel \
     to not record.";
#[cfg(windows)]
const BODY_ELEVATED_HELPER_CONSENT: &str =
    "This recording can ask Windows for a short-lived elevated helper so Gilbreth can \
     read administrator app windows during this recording. It still stores only which \
     controls you used and the kind of action, never the values you enter. It does \
     not capture the UAC prompt or Secure Desktop, and does not run automation. \
     Choose Yes to request the elevated helper, or No to record without \
     elevated-window capture.";
const BODY_ARCHIVE_RESET_FINAL_CONFIRM: &str =
    "Final confirmation: create the archive, delete your current activity, securely \
     wipe it, and start a fresh recording session?";
const BODY_ARCHIVE_PIPELINE_NOT_QUIET: &str =
    "Archive and reset could not start because the capture pipeline did not become \
     quiet. No archive was created and no activity was deleted; the current manual \
     capture state was restored.";
const BODY_ARCHIVE_WRITER_UNAVAILABLE: &str =
    "Archive and reset could not start because the writer is not available. No \
     activity was deleted; the current manual capture state was restored.";
const BODY_ARCHIVE_NO_REPORT: &str =
    "Archive and reset did not return a result. The current manual capture state was \
     restored; check the Gilbreth log before relying on the reset.";
const BODY_SECURE_ERASE_PIPELINE_NOT_QUIET: &str =
    "Secure erase could not start because the capture pipeline did not become quiet. \
     No activity was deleted; the current manual capture state was restored.";
const BODY_SECURE_ERASE_WRITER_UNAVAILABLE: &str =
    "Secure erase could not start because the writer is not available. No activity \
     was deleted; the current manual capture state was restored.";
const BODY_SECURE_ERASE_NO_REPORT: &str =
    "Secure erase did not return a result. The current manual capture state was \
     restored; check the Gilbreth log before relying on the wipe.";
const BODY_SECURE_ERASE_CLEAR_LOGS_QUESTION: &str =
    "Also delete Gilbreth's diagnostic logs? They never contain typed text or window \
     titles, but they can mention app names and counts.";
const SECURE_ERASE_SCOPE_WITH_LOGS: &str =
    "delete your live activity database, sealed and plaintext-era archives, privacy \
     sidecars, and diagnostic logs, then securely scrub the database";
const SECURE_ERASE_SCOPE_WITHOUT_LOGS: &str =
    "delete your live activity database, sealed and plaintext-era archives, and \
     privacy sidecars, then securely scrub the database";

const RECORD_FAIL_COMMAND_WRITER_UNAVAILABLE: &str =
    "Record command could not start because the writer is not available";
const RECORD_FAIL_COMMAND: &str = "Record command failed";
const RECORD_FAIL_COMMAND_NO_RESULT: &str = "Record command did not return a result";
#[cfg(windows)]
const RECORD_FAIL_START_WRITER_UNAVAILABLE: &str =
    "Recording could not start because the writer is not available";
#[cfg(windows)]
const RECORD_FAIL_START: &str = "Recording could not start";
#[cfg(windows)]
const RECORD_FAIL_START_NO_RESULT: &str = "Recording did not return a result";
const RECORD_FAIL_CAP_RESPONSE_UNSAVED: &str = "Recording cap response could not be saved";

const NO_FURTHER_DETAIL: &str = "No further detail was reported.";
const CAPTURE_STILL_PAUSED_NOTE: &str = "Capture remains paused by your manual setting.";
const CAPTURE_RESUMED_NOTE: &str = "Capture has resumed.";
const ARCHIVE_LOCATION_UNAVAILABLE: &str = "(archive location unavailable)";
const RECEIPT_NOTE_PREFIX: &str = "Content-free receipt: ";
const LOG_RETENTION_FILES: usize = 30;
const DAY_MS: i64 = 86_400_000;

fn session_identity(started_at: i64) -> SessionIdentity {
    SessionIdentity::new(APP_VERSION)
        .with_host(local_host_name())
        .with_git_sha(GIT_SHA)
        .with_run_label(Some(format!("session-{started_at}")))
}

fn replacement_session_identity() -> SessionIdentity {
    SessionIdentity::new(APP_VERSION)
        .with_host(local_host_name())
        .with_git_sha(GIT_SHA)
}

/// Startup retention consumes the raw wall clock before any in-session drift
/// machinery exists. If a previous run captured under a badly wrong clock
/// (dead CMOS battery, bad NTP source) and the clock has since been corrected
/// forward, `now - retention_days` can land above genuinely recent rows and a
/// startup prune would silently destroy them. Clamping the reference time to
/// the newest stored row guarantees a startup prune never deletes the newest
/// retention-window of the data's own timeline, while legitimately old rows
/// still age out relative to it (S14).
fn clamped_retention_now_ms(wall_now_ms: i64, newest_event_ts: Option<i64>) -> i64 {
    match newest_event_ts {
        Some(newest) => wall_now_ms.min(newest),
        None => wall_now_ms,
    }
}

fn retention_cutoff_ms(now_ms: i64, retention_days: u64) -> i64 {
    let days = retention_days.max(1);
    let retention_ms = i128::from(days) * i128::from(DAY_MS);
    let cutoff = i128::from(now_ms) - retention_ms;
    cutoff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn run_startup_title_retention(store: &mut GilbrethStore, title_retention_days: u64, now_ms: i64) {
    if title_retention_days == 0 {
        return;
    }
    let cutoff_ms = retention_cutoff_ms(now_ms, title_retention_days);
    match store.scrub_titles_before(cutoff_ms) {
        Ok(0) => info!(
            title_retention_days,
            cutoff_ms, "startup title retention found no titles to age out"
        ),
        Ok(scrubbed) => info!(
            title_retention_days,
            cutoff_ms, scrubbed, "startup title retention blanked old window titles"
        ),
        Err(error) => warn!(
            %error,
            title_retention_days,
            cutoff_ms,
            "startup title retention failed; continuing without scrubbing"
        ),
    }
}

fn run_startup_mouse_move_retention(
    store: &mut GilbrethStore,
    mouse_move_retention_days: u64,
    now_ms: i64,
) {
    if mouse_move_retention_days == 0 {
        return;
    }
    let cutoff_ms = retention_cutoff_ms(now_ms, mouse_move_retention_days);
    match store.prune_mouse_moves_before(cutoff_ms) {
        Ok(0) => info!(
            mouse_move_retention_days,
            cutoff_ms, "startup mouse-move tier found no movement rows to age out"
        ),
        Ok(pruned) => info!(
            mouse_move_retention_days,
            cutoff_ms, pruned, "startup mouse-move tier aged out old movement rows"
        ),
        Err(error) => warn!(
            %error,
            mouse_move_retention_days,
            cutoff_ms,
            "startup mouse-move tier failed; continuing without pruning"
        ),
    }
}

fn run_startup_retention(store: &mut GilbrethStore, retention_days: u64, now_ms: i64) {
    let cutoff_ms = retention_cutoff_ms(now_ms, retention_days);
    match store.prune_old_activity(cutoff_ms) {
        Ok(report) => {
            if report.events_deleted > 0 || report.sessions_deleted > 0 {
                info!(
                    retention_days,
                    cutoff_ms,
                    events_deleted = report.events_deleted,
                    sessions_deleted = report.sessions_deleted,
                    "startup retention pruned old activity"
                );
            } else {
                info!(
                    retention_days,
                    cutoff_ms, "startup retention found no old activity to prune"
                );
            }
        }
        Err(error) => warn!(
            %error,
            retention_days,
            cutoff_ms,
            "startup retention prune failed; continuing without pruning"
        ),
    }
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(command) = uninstall::parse_offline_command(arguments.iter().cloned())? {
        return uninstall::execute(command, APP_VERSION, GIT_SHA);
    }
    // `--quit` routes before the single-instance guard: it must talk to the
    // running instance, never become one.
    #[cfg(windows)]
    if arguments
        .iter()
        .any(|argument| argument.as_os_str() == QUIT_FLAG)
    {
        if gilbreth_capture_windows::request_running_instance_quit() {
            return Ok(());
        }
        std::process::exit(1);
    }
    // The dashboard runs as a second process of this same exe (S4 process
    // model). It is not a capture owner, so route it before the capture-scoped
    // single-instance guard and before any capture threads start. Explicit
    // delete/prune actions still use the dashboard's bounded store writer lane.
    if is_dashboard_process(&arguments) {
        return match run_native_dashboard() {
            Ok(()) => Ok(()),
            Err(error) => {
                alert(
                    DIALOG_TITLE_DASHBOARD,
                    &format!("{BODY_DASHBOARD_START_FAILED_PREFIX}{error:#}"),
                    AlertKind::Warning,
                );
                Err(error)
            }
        };
    }
    match run() {
        Ok(()) => Ok(()),
        Err(error) => {
            // In the windowed (console-less) release build a bare `Err` exits
            // with no console and no UI, so a failed store-open / migration /
            // single-instance / config load silently never starts capture —
            // fatal for unattended autostart. Surface it before exiting.
            alert(
                DIALOG_TITLE_APP,
                &format!("{BODY_APP_START_FAILED_PREFIX}{error:#}"),
                AlertKind::Warning,
            );
            Err(error)
        }
    }
}

fn is_dashboard_process(arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> bool {
    arguments
        .into_iter()
        .any(|argument| argument.as_ref() == OsStr::new(DASHBOARD_PROCESS_FLAG))
}

fn dashboard_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    command.arg(DASHBOARD_PROCESS_FLAG);
    command
}

/// Launch and reap one dashboard child off the tray/message-pump thread.
///
/// Dropping a finished [`std::process::Child`] without waiting is harmless on
/// Windows but can retain a zombie on Unix until the tray exits. Starting the
/// child inside this worker also means a thread-creation failure happens before
/// any process exists.
fn spawn_dashboard_worker(
    mut command: Command,
) -> std::io::Result<thread::JoinHandle<std::io::Result<ExitStatus>>> {
    thread::Builder::new()
        .name("gilbreth-dashboard-process".to_string())
        .spawn(move || {
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    error!(%error, "failed to launch the dashboard");
                    return Err(error);
                }
            };
            let pid = child.id();
            info!(pid, "dashboard launch started");
            match child.wait() {
                Ok(status) if status.success() => {
                    info!(pid, %status, "dashboard process exited");
                    Ok(status)
                }
                Ok(status) => {
                    warn!(pid, %status, "dashboard process exited unsuccessfully");
                    Ok(status)
                }
                Err(error) => {
                    error!(%error, pid, "failed to reap dashboard process");
                    Err(error)
                }
            }
        })
}

/// The `--dashboard` process: wire the host boundary (paths, cooperative
/// sidecar IO, icon) and hand control to `gilbreth-dashboard`. Logs go to
/// their own rolling file so the capture process's log writer is never
/// shared across processes.
fn run_native_dashboard() -> Result<()> {
    let _lifecycle = LifecycleGuard::acquire_shared()
        .context("failed to acquire shared package lifecycle guard")?;
    let local_data_dir = local_data_dir()?;
    let log_dir = local_data_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("gilbreth-dashboard.log")
        .max_log_files(LOG_RETENTION_FILES)
        .build(&log_dir)?;
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(DEFAULT_LOG_FILTER))
        .with_writer(writer)
        .with_ansi(false)
        .init();
    let _log_guard = guard;

    // eframe's file storage is not an inter-process writer: only the first
    // viewer holding this data-root claim may restore or save UI state. A
    // claim error fails closed to a non-persisting viewer, never to a missing
    // dashboard window.
    let ui_state_owner = match DashboardUiStateOwner::try_acquire(&local_data_dir) {
        Ok(Some(owner)) => {
            info!("dashboard owns persistent UI state");
            Some(owner)
        }
        Ok(None) => {
            info!("dashboard UI-state persistence disabled; another viewer owns it");
            None
        }
        Err(error) => {
            warn!(%error, "dashboard UI-state claim failed; persistence disabled");
            None
        }
    };
    let ui_state_persistence = if ui_state_owner.is_some() {
        gilbreth_dashboard::data::UiStatePersistence::Owner
    } else {
        gilbreth_dashboard::data::UiStatePersistence::Secondary
    };

    let config_path = config::config_path(&local_data_dir);
    let loaded_config = config::load_or_create(&config_path).context("failed to load config")?;
    log_config_status(&loaded_config.status);
    let db_path = loaded_config.config.db_path(&local_data_dir);
    info!(db = %db_path.display(), "native dashboard starting");

    let notice_state_path = config::discovery_notice_state_sidecar_path(&config_path);
    let spheres_sidecar = config::spheres_sidecar_path(&config_path);
    let privacy_config_path = config_path.clone();
    let welcome_read_path = config_path.clone();
    let welcome_write_path = config_path.clone();
    let read_state_path = notice_state_path.clone();
    let overlay_read_path = config_path.clone();
    let overlay_write_path = config_path.clone();
    let alias_read_path = spheres_sidecar.clone();
    let alias_write_path = spheres_sidecar.clone();
    let alias_prune_path = spheres_sidecar.clone();
    let request_db_path = db_path.clone();
    let status_db_path = db_path.clone();
    let verified_classes_path = config_path.clone();
    let export_db_path = db_path.clone();
    let export_config_path = config_path.clone();
    let delete_db_path = db_path.clone();
    let events_delete_db_path = db_path.clone();
    let privacy_read_path = config_path.clone();
    let privacy_write_path = config_path.clone();
    let retention_path = config_path.clone();
    let permission_state_path = permissions::state_sidecar_path(&config_path);
    let permission_request_path = permissions::request_sidecar_path(&config_path);
    let hotkey_status_path = hotkey::status_sidecar_path(&config_path);
    let notification_status_path = notification_consent::sidecar_path(&local_data_dir);
    let preview_db_path = db_path.clone();
    let prune_db_path = db_path.clone();
    let archives_dir = local_data_dir.join("archives");
    let archive_count_dir = archives_dir.clone();
    let archive_diagnostics_dir = archives_dir.clone();
    #[cfg(windows)]
    let portable_archive_list_dir = archives_dir.clone();
    #[cfg(windows)]
    let portable_archive_export_dir = archives_dir.clone();
    #[cfg(windows)]
    let portable_receipt_data_dir = local_data_dir.clone();
    let review_logs_dir = log_dir.clone();
    let host = gilbreth_dashboard::data::DashboardHost {
        config_path: config_path.clone(),
        db_path,
        ui_state_path: local_data_dir.join("dashboard-ui.ron"),
        ui_state_persistence,
        window_icon: Some((32, 32, favicon_rgba(32))),
        store_key_content: Box::new(move || {
            config::read_privacy_settings(&privacy_config_path)
                .settings
                .store_key_content
        }),
        read_first_run_welcome_dismissed: Box::new(move || {
            config::read_first_run_welcome_dismissed(&welcome_read_path)
        }),
        dismiss_first_run_welcome: Box::new(move || {
            config::dismiss_first_run_welcome(&welcome_write_path)
                .map_err(|error| format!("{error}"))
        }),
        read_notice_state: Box::new(move || {
            let state = config::read_discovery_notice_state(&read_state_path);
            gilbreth_read::DiscoveryNoticeState {
                dismissed: state.dismissed,
                muted: state.muted,
                watched: state.watched,
            }
        }),
        write_notice_state: Box::new(move |state| {
            let state = config::DiscoveryNoticeState {
                dismissed: state.dismissed.clone(),
                muted: state.muted.clone(),
                watched: state.watched.clone(),
            };
            config::write_discovery_notice_state(&notice_state_path, &state)
                // Display-only rendering: the sanitized outer message, never
                // the error chain (config error contract).
                .map_err(|error| format!("{error}"))
        }),
        read_sphere_overlay_enabled: Box::new(move || {
            config::read_sphere_overlay_enabled(&overlay_read_path)
        }),
        write_sphere_overlay_enabled: Box::new(move |enabled| {
            config::write_sphere_overlay_enabled(&overlay_write_path, enabled)
                .map_err(|error| format!("{error}"))
        }),
        read_sphere_aliases: Box::new(move || config::read_sphere_aliases(&alias_read_path)),
        write_sphere_aliases: Box::new(move |aliases| {
            config::write_sphere_aliases(&alias_write_path, aliases)
                .map_err(|error| format!("{error}"))
        }),
        prune_sphere_aliases: Box::new(move |live_tokens| {
            config::prune_stale_sphere_aliases(&alias_prune_path, live_tokens)
                .map_err(|error| format!("{error}"))
        }),
        request_recording: Box::new(move |kind, payload| {
            gilbreth_store::request_recording(
                &request_db_path,
                Some(kind),
                payload,
                gilbreth_dashboard::data::now_ms(),
            )
            .map_err(|error| format!("{error}"))
        }),
        record_request_status: Box::new(move |request_id| {
            gilbreth_read::open_readonly(&status_db_path)
                .ok()
                .and_then(|conn| {
                    gilbreth_read::record_request_status(&conn, request_id)
                        .ok()
                        .flatten()
                })
        }),
        spheres_sidecar_name: spheres_sidecar
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("spheres.json")
            .to_string(),
        casefold_token: Box::new(config::casefold_token),
        verified_framework_classes: Box::new(move || {
            config::read_verified_framework_classes(&verified_classes_path)
        }),
        save_replay_export: Box::new(move |record_session_id, mode, labels| {
            save_replay_export_to_downloads(
                &export_db_path,
                &export_config_path,
                record_session_id,
                mode,
                labels,
            )
        }),
        #[cfg(windows)]
        list_portable_archive_sources: Box::new(move || {
            gilbreth_store::inventory_archives(&portable_archive_list_dir)
                .map(|inventory| {
                    inventory
                        .encrypted
                        .into_iter()
                        .filter_map(|path| {
                            let name = path.file_name()?.to_str()?.to_string();
                            Some(gilbreth_dashboard::data::PortableArchiveSource {
                                id: name.clone(),
                                label: name,
                            })
                        })
                        .collect()
                })
                .map_err(|error| format!("{error}"))
        }),
        #[cfg(windows)]
        export_portable_archive: Box::new(move |source_id, mode| {
            save_portable_archive_to_downloads(
                &portable_archive_export_dir,
                &portable_receipt_data_dir,
                source_id,
                mode,
            )
        }),
        delete_recording: Box::new(move |record_session_id| {
            gilbreth_store::delete_recording(&delete_db_path, record_session_id)
                .map(|result| gilbreth_dashboard::data::RecordingDeleteOutcome {
                    deleted: result.deleted,
                    scrub_warning: result.scrub_warning,
                })
                .map_err(|error| format!("{error}"))
        }),
        delete_events: Box::new(move |event_ids| {
            gilbreth_store::delete_events(&events_delete_db_path, event_ids)
                .map(|result| gilbreth_dashboard::data::EventsDeleteOutcome {
                    deleted: result.deleted,
                    scrub_warning: result.scrub_warning,
                })
                .map_err(|error| format!("{error}"))
        }),
        read_privacy_settings: Box::new(move || {
            let read = config::read_privacy_settings(&privacy_read_path);
            gilbreth_dashboard::data::PrivacySettingsView {
                sensitive_context_suppression: read.settings.sensitive_context_suppression,
                redact_titles_containing: read.settings.redact_titles_containing,
                redact_keys_containing: read.settings.redact_keys_containing,
                excluded_apps: read.settings.excluded_apps,
                store_key_content: read.settings.store_key_content,
                title_retention_days: read.settings.title_retention_days,
                mouse_move_retention_days: read.settings.mouse_move_retention_days,
                error: read.error,
            }
        }),
        write_privacy_settings: Box::new(move |values| {
            // The writer only persists the dashboard-editable fields;
            // store_key_content stays whatever the tray last set.
            let current = config::read_privacy_settings(&privacy_write_path).settings;
            let settings = config::PrivacySettings {
                sensitive_context_suppression: values.sensitive_context_suppression,
                redact_titles_containing: values.redact_titles_containing.clone(),
                redact_keys_containing: values.redact_keys_containing.clone(),
                excluded_apps: values.excluded_apps.clone(),
                store_key_content: current.store_key_content,
                title_retention_days: values.title_retention_days,
                mouse_move_retention_days: values.mouse_move_retention_days,
            };
            config::write_privacy_settings(&privacy_write_path, &settings)
                .map_err(|error| format!("{error}"))
        }),
        read_retention_days: Box::new(move || config::read_retention_days(&retention_path)),
        prune_preview: Box::new(move |cutoff_ms| {
            gilbreth_store::prune_preview(&preview_db_path, cutoff_ms)
                .map(|preview| gilbreth_dashboard::data::PrunePreview {
                    cutoff_ms: preview.cutoff_ms,
                    events: preview.events,
                    ended_empty_sessions: preview.ended_empty_sessions,
                    action_events: preview.action_events,
                    ended_empty_record_sessions: preview.ended_empty_record_sessions,
                    record_requests: preview.record_requests,
                    selector_paths: preview.selector_paths,
                })
                .map_err(|error| format!("{error}"))
        }),
        prune_old_events: Box::new(move |cutoff_ms| {
            gilbreth_store::prune_old_events(&prune_db_path, cutoff_ms)
                .map(|result| gilbreth_dashboard::data::PruneOutcome {
                    events_deleted: result.events_deleted,
                    sessions_deleted: result.sessions_deleted,
                    action_events_deleted: result.action_events_deleted,
                    record_sessions_deleted: result.record_sessions_deleted,
                    record_requests_deleted: result.record_requests_deleted,
                    selector_paths_deleted: result.selector_paths_deleted,
                    compaction_completed: result.compaction_completed,
                    compact_error: result.compact_error,
                })
                .map_err(|error| format!("{error}"))
        }),
        autostart_command: Box::new(|| match autostart::read_command() {
            Ok(command) => (command, None),
            // Display-only rendering per the config error contract.
            Err(error) => (None, Some(format!("{error}"))),
        }),
        archive_count: Box::new(move || {
            gilbreth_store::inventory_archives(&archive_count_dir)
                .map(|inventory| inventory.encrypted.len() + inventory.plaintext_legacy.len())
                .unwrap_or(0)
        }),
        read_legacy_plaintext_archive_count: Box::new(move || {
            gilbreth_store::inventory_archives(&archive_diagnostics_dir)
                .map(|inventory| inventory.plaintext_legacy.len())
                .map_err(|_| "archive inventory unavailable".to_string())
        }),
        review_logs: Box::new(move |since_ms, until_ms| {
            let summary = health::review_logs(&review_logs_dir, since_ms, until_ms);
            gilbreth_dashboard::data::LogReview {
                files: summary.files,
                warning_lines: summary.warning_lines,
                error_panic_lines: summary.error_panic_lines,
                clipboard_locked_warning_lines: summary.clipboard_locked_warning_lines,
                orphan_session_repair_warning_lines: summary.orphan_session_repair_warning_lines,
                stale_pre_erase_drop_warning_lines: summary.stale_pre_erase_drop_warning_lines,
                recovered_focus_warning_lines: summary.recovered_focus_warning_lines,
                open_focus_discard_warning_lines: summary.open_focus_discard_warning_lines,
                max_events_skipped: summary.max_events_skipped,
            }
        }),
        clock: Box::new(gilbreth_dashboard::data::now_ms),
        read_permission_snapshot: Box::new(move || {
            permissions::read_state(&permission_state_path).map(permission_snapshot_for_dashboard)
        }),
        read_pause_hotkey_warning: Box::new(move || {
            hotkey::read_status(&hotkey_status_path).and_then(|status| status.diagnostics_warning())
        }),
        read_notification_access: Box::new(move || {
            notification_consent::read_snapshot(&notification_status_path)
                .map(notification_snapshot_for_dashboard)
        }),
        request_permission_action: Box::new(move |action| {
            dispatch_permission_action(&permission_request_path, action);
        }),
    };
    let result = gilbreth_dashboard::run_dashboard(host)
        .map_err(|error| anyhow::anyhow!("dashboard window failed: {error}"));
    // Make the claim lifetime explicit: eframe joins its persistence thread
    // before returning, then this handle closes and a later viewer may own it.
    drop(ui_state_owner);
    result
}

/// Map the app's authoritative `PermissionState` (from the pump-written
/// sidecar) to the dashboard's display mirror. Kept here so gilbreth-dashboard
/// stays free of a gilbreth-app dependency.
fn permission_snapshot_for_dashboard(
    state: permissions::PermissionState,
) -> gilbreth_dashboard::data::PermissionSnapshot {
    use gilbreth_dashboard::data::PermissionRowState;
    use permissions::GrantState;
    let row = |grant: GrantState| match grant {
        GrantState::NotGranted => PermissionRowState::NotGranted,
        GrantState::Granted => PermissionRowState::Granted,
        GrantState::GrantedNeedsRelaunch => PermissionRowState::GrantedNeedsRelaunch,
    };
    gilbreth_dashboard::data::PermissionSnapshot {
        accessibility: row(state.accessibility),
        input_monitoring: row(state.input_monitoring),
    }
}

fn notification_snapshot_for_dashboard(
    snapshot: notification_consent::NotificationAccessSnapshot,
) -> gilbreth_dashboard::data::NotificationAccessSnapshot {
    use gilbreth_dashboard::data::NotificationAccessRowState as Row;
    use notification_consent::NotificationAccessState as State;
    let state = match snapshot.state {
        State::Allowed => Row::Allowed,
        State::Unspecified => Row::Unspecified,
        State::Denied => Row::Denied,
        State::Unavailable => Row::Unavailable,
        State::Unsupported => Row::Unsupported,
    };
    gilbreth_dashboard::data::NotificationAccessSnapshot {
        state,
        privacy_copy: snapshot.state.privacy_copy().to_string(),
        diagnostics_copy: snapshot.state.diagnostics_copy().to_string(),
    }
}

#[cfg(windows)]
fn map_notification_access_state(
    state: gilbreth_capture_windows::notification_access::NotificationAccessStatus,
) -> notification_consent::NotificationAccessState {
    use gilbreth_capture_windows::notification_access::NotificationAccessStatus as Win;
    use notification_consent::NotificationAccessState as App;
    match state {
        Win::Allowed => App::Allowed,
        Win::Unspecified => App::Unspecified,
        Win::Denied => App::Denied,
        Win::Unavailable => App::Unavailable,
    }
}

#[cfg(windows)]
fn current_notification_access_state() -> notification_consent::NotificationAccessState {
    gilbreth_capture_windows::notification_access::current_notification_access()
        .map(map_notification_access_state)
        .unwrap_or_else(|error| {
            warn!(%error, "notification access state is unavailable");
            notification_consent::NotificationAccessState::Unavailable
        })
}

#[cfg(windows)]
fn request_notification_access_state() -> notification_consent::NotificationAccessState {
    gilbreth_capture_windows::notification_access::request_notification_access()
        .map(map_notification_access_state)
        .unwrap_or_else(|error| {
            warn!(%error, "notification access request failed");
            notification_consent::NotificationAccessState::Unavailable
        })
}

/// Route a permission-panel button (dashboard process). Deep-link opens
/// touch no TCC and go straight to System Settings from here; prompt and
/// relaunch actions are written to the request sidecar with a monotonic
/// generation (the reseed-flag precedent) for the pump to execute — the
/// only process the TCC record allows to prompt.
fn dispatch_permission_action(
    request_path: &Path,
    action: gilbreth_dashboard::data::PermissionActionRequest,
) {
    use gilbreth_dashboard::data::PermissionActionRequest as Req;
    let pump_action = match action {
        Req::OpenAccessibilityPane => {
            open_privacy_pane(permissions::ACCESSIBILITY_PANE_URL);
            return;
        }
        Req::OpenInputMonitoringPane => {
            open_privacy_pane(permissions::INPUT_MONITORING_PANE_URL);
            return;
        }
        Req::PromptAccessibility => permissions::PermissionAction::PromptAccessibility,
        Req::PromptInputMonitoring => permissions::PermissionAction::PromptInputMonitoring,
        Req::Relaunch => permissions::PermissionAction::Relaunch,
    };
    // The generation must advance past any request already on disk so the
    // pump sees a fresh edge (the file may hold a prior action).
    let generation = permissions::read_request(request_path)
        .map(|prior| prior.generation)
        .unwrap_or(0)
        + 1;
    let request = permissions::PermissionRequest {
        generation,
        action: pump_action,
    };
    if let Err(error) = permissions::write_request(request_path, &request) {
        warn!(%error, "failed to write the permission request for the pump");
    }
}

/// Open a System Settings deep link, falling back to the Privacy & Security
/// root if the pane URL is refused (the recorded fallback for a moved pane
/// id).
fn open_privacy_pane(url: &str) {
    if !platform::open_url(url) {
        platform::open_url(permissions::PRIVACY_ROOT_URL);
    }
}

/// Build a dashboard export, then write it into the user's Downloads folder
/// under the canonical filename with browser-style " (1)" collision suffixes.
fn save_replay_export_to_downloads(
    db_path: &Path,
    config_path: &Path,
    record_session_id: i64,
    mode: &str,
    labels: &std::collections::HashMap<i64, String>,
) -> Result<String, gilbreth_dashboard::data::ExportSaveError> {
    use gilbreth_dashboard::data::ExportSaveError;
    let serialized = (|| {
        let conn = gilbreth_read::open_readonly(db_path).map_err(|error| format!("{error}"))?;
        let verified = config::read_verified_framework_classes(config_path);
        let artifact = gilbreth_read::build_replay_export(
            &conn,
            record_session_id,
            mode,
            &verified,
            gilbreth_dashboard::data::now_ms(),
            labels,
        )
        .map_err(|error| format!("{error}"))?;
        gilbreth_read::serialize_replay_export(&artifact).map_err(|error| format!("{error}"))
    })()
    .map_err(ExportSaveError::Build)?;
    let downloads = downloads_dir().map_err(ExportSaveError::Write)?;
    let filename = gilbreth_read::replay_export_filename(record_session_id, mode);
    let path = collision_free_path(&downloads, &filename).map_err(ExportSaveError::Write)?;
    fs::write(&path, serialized.as_bytes())
        .map_err(|error| ExportSaveError::Write(format!("{error}")))?;
    Ok(path.display().to_string())
}

#[cfg(windows)]
fn save_portable_archive_to_downloads(
    archives_dir: &Path,
    data_dir: &Path,
    source_id: &str,
    mode: &gilbreth_dashboard::data::PortableArchiveExportMode,
) -> Result<String, String> {
    use gilbreth_dashboard::data::PortableArchiveExportMode;
    use privacy_receipt::{PrivacyOperation, PrivacyReceipt, ReceiptClass, ReceiptOutcome};

    let inventory = gilbreth_store::inventory_archives(archives_dir)
        .map_err(|error| format!("couldn't list encrypted archives: {error}"))?;
    let source = inventory
        .encrypted
        .into_iter()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(source_id))
        .ok_or_else(|| "the selected encrypted archive is no longer available".to_string())?;
    let downloads = downloads_dir()?;
    let source_stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("gilbreth-archive");
    let (filename, result) = match mode {
        PortableArchiveExportMode::Passphrase(passphrase) => {
            let filename = format!("{source_stem}-portable.gla");
            let destination = collision_free_path(&downloads, &filename)?;
            let result = gilbreth_store::export_passphrase_archive(
                &source,
                &destination,
                gilbreth_store::ArchiveCredential::DpapiUser,
                passphrase,
            )
            .map(|_| destination);
            (filename, result)
        }
        PortableArchiveExportMode::PlaintextAcknowledged => {
            let acknowledgement =
                gilbreth_store::PlaintextExportAcknowledgement::after_explicit_warning(true)
                    .expect("the UI supplied explicit plaintext acknowledgement");
            let filename = format!("{source_stem}-portable.db");
            let destination = collision_free_path(&downloads, &filename)?;
            let result = gilbreth_store::export_plaintext_archive(
                &source,
                &destination,
                gilbreth_store::ArchiveCredential::DpapiUser,
                acknowledgement,
            )
            .map(|_| destination);
            (filename, result)
        }
    };
    let destination = match result {
        Ok(destination) => destination,
        Err(error) => {
            let receipt = PrivacyReceipt::new(
                PrivacyOperation::PortableArchiveExport,
                vec![
                    ReceiptClass::new("source_archive", ReceiptOutcome::Retained).with_count(1),
                    ReceiptClass::new("portable_export", ReceiptOutcome::NeedsRetry).with_count(1),
                ],
            );
            let receipt_note = privacy_receipt::write_receipt(data_dir, &receipt)
                .map(|path| format!(" Receipt: {}.", path.display()))
                .unwrap_or_else(|receipt_error| {
                    format!(" The operation receipt also needs retry: {receipt_error}.")
                });
            return Err(format!("archive export failed: {error}.{receipt_note}"));
        }
    };
    let receipt = PrivacyReceipt::new(
        PrivacyOperation::PortableArchiveExport,
        vec![
            ReceiptClass::new("source_archive", ReceiptOutcome::Retained).with_count(1),
            ReceiptClass::new("portable_export", ReceiptOutcome::Copied).with_count(1),
        ],
    );
    if let Err(error) = privacy_receipt::write_receipt(data_dir, &receipt) {
        return Err(format!(
            "{} was copied, but the content-free operation receipt needs retry: {error}",
            destination.display()
        ));
    }
    debug!(export_file = filename, "portable archive export completed");
    Ok(destination.display().to_string())
}

/// "name.json" -> "name (1).json" -> "name (2).json", like a browser's
/// download collision handling.
fn collision_free_path(dir: &Path, filename: &str) -> Result<PathBuf, String> {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return Ok(candidate);
    }
    let (stem, extension) = match filename.rsplit_once('.') {
        Some((stem, extension)) => (stem, Some(extension)),
        None => (filename, None),
    };
    for counter in 1..=999 {
        let name = match extension {
            Some(extension) => format!("{stem} ({counter}).{extension}"),
            None => format!("{stem} ({counter})"),
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "no free export name for {filename} in {}",
        dir.display()
    ))
}

fn run() -> Result<()> {
    let _lifecycle = LifecycleGuard::acquire_shared()
        .context("failed to acquire shared package lifecycle guard")?;
    let _log_guard = init_tracing().context("failed to initialize logging")?;

    let _instance = match SingleInstance::acquire()
        .context("failed to acquire single instance guard")
    {
        Ok(instance) => instance,
        Err(error) if platform::is_other_session_instance_error(&error) => {
            info!(
                "another Gilbreth writer is active for this user in another Windows session; exiting quietly"
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let local_data_dir = local_data_dir()?;
    let config_path = config::config_path(&local_data_dir);
    let loaded_config = config::load_or_create(&config_path).context("failed to load config")?;
    log_config_status(&loaded_config.status);
    warn_user_if_config_malformed(&loaded_config.status);
    let mut app_config = loaded_config.config;
    #[cfg(any(windows, target_os = "macos"))]
    let resolved_pause_hotkey = {
        let resolved = hotkey::resolve_pause_hotkey(&app_config.hotkey.pause_resume);
        if let Some(message) = resolved.warning {
            warn!(message, "pause hotkey config fell back to its default");
        }
        resolved
    };
    #[cfg(any(windows, target_os = "macos"))]
    let hotkey_status_path = hotkey::status_sidecar_path(&config_path);
    // First-run consent (the first-run consent design, R1): blocking on the main
    // thread, before the tray exists and before any capture source starts.
    // Every outcome proceeds to capture; only the keystroke posture differs,
    // and a persisted opt-in is the only path to store_key_content = true.
    consent::run_first_run_consent(&config_path, &mut app_config);
    let controls = CaptureControls::new(app_config.capture.settings())
        .with_excluded_apps(app_config.privacy.excluded_apps.clone());
    let stop = StopToken::new();
    let (capture_tx, capture_rx) = bounded(CHANNEL_CAPACITY);
    let (capture_flush_tx, capture_flush_rx) = bounded(1);
    let (writer_tx, writer_rx) = bounded(CHANNEL_CAPACITY);
    let (command_tx, command_rx) = bounded(4);
    let (record_request_notify_tx, record_request_notify_rx) = bounded(1);
    let (cap_prompt_notify_tx, cap_prompt_notify_rx) = bounded(1);
    let (record_ui_tx, record_ui_rx) = bounded(16);
    let record_prompt_in_flight = Arc::new(AtomicBool::new(false));
    let panic_action_cutoff = PanicActionCutoff::default();

    let timebase = SessionTimebase::start_now();
    let session_identity = session_identity(timebase.base_utc_ms());
    let db_path = app_config.db_path(&local_data_dir);
    let mut store = GilbrethStore::open(&db_path).context("failed to open Gilbreth store")?;
    let retention_now_ms = match store.newest_event_ts() {
        Ok(newest) => {
            let clamped = clamped_retention_now_ms(timebase.base_utc_ms(), newest);
            let skew_ms = timebase.base_utc_ms().saturating_sub(clamped);
            if skew_ms > DAY_MS {
                info!(
                    skew_ms,
                    "startup retention ages relative to the newest stored row; the wall clock is far ahead of stored activity"
                );
            }
            clamped
        }
        Err(error) => {
            warn!(%error, "could not read the newest stored row; startup retention uses the wall clock");
            timebase.base_utc_ms()
        }
    };
    run_startup_retention(
        &mut store,
        app_config.privacy.retention_days,
        retention_now_ms,
    );
    run_startup_title_retention(
        &mut store,
        app_config.privacy.title_retention_days,
        retention_now_ms,
    );
    run_startup_mouse_move_retention(
        &mut store,
        app_config.privacy.mouse_move_retention_days,
        retention_now_ms,
    );
    let session_id = store
        .create_session_with_identity(timebase.base_utc_ms(), &session_identity)
        .context("failed to create session")?;
    let sequencer = Sequencer::new(session_id, timebase);
    let writer_config = app_config
        .writer_config()
        .with_record_notifications(
            record_request_notify_tx,
            cap_prompt_notify_tx,
            Arc::clone(&record_prompt_in_flight),
        )
        .with_diagnostics(controls.diagnostics())
        .with_panic_action_cutoff(panic_action_cutoff.clone());
    let policy = app_config.policy();

    let record_action_tx = writer_tx.clone();
    let capture_forwarder_tx = writer_tx.clone();
    drop(writer_tx);
    let capture_forwarder_handle = thread::spawn(move || {
        run_capture_forwarder(capture_rx, capture_forwarder_tx, capture_flush_rx);
    });

    let pump_waker = PumpWaker::for_current_thread();
    let writer_stop = stop.clone();
    let (writer_done_tx, writer_done_rx) = mpsc::channel();
    let writer_handle = thread::spawn(move || {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            run_writer_with_commands(
                store,
                writer_rx,
                command_rx,
                writer_stop.clone(),
                sequencer,
                policy,
                writer_config,
            )
        }));
        report_writer_thread_exit(result, writer_stop, || pump_waker.wake(), writer_done_tx);
    });

    // AppKit application setup precedes the tray (no-op on Windows): without
    // it, macOS queues status-item clicks as NSEvents nothing dispatches and
    // the tray menu never opens.
    platform::init_app_shell();
    let capture_paused_by_user = Arc::new(AtomicBool::new(false));
    let mut tray = Tray::new(
        stop.clone(),
        controls.clone(),
        app_config,
        config_path,
        PrivacyCommandContext {
            archive_dir: local_data_dir.join("archives"),
            writer_commands: command_tx.clone(),
            capture_flush: capture_flush_tx,
            pump_waker,
            writer_inputs: record_action_tx.clone(),
            capture_paused_by_user: Arc::clone(&capture_paused_by_user),
        },
        RecordCommandContext {
            writer_commands: command_tx,
            writer_inputs: record_action_tx,
            request_notifications: record_request_notify_rx,
            cap_notifications: cap_prompt_notify_rx,
            ui_events: record_ui_rx,
            ui_event_tx: record_ui_tx,
            prompt_in_flight: record_prompt_in_flight,
            panic_action_cutoff,
            pump_waker,
        },
    )
    .context("failed to create tray icon")?;
    #[cfg(any(windows, target_os = "macos"))]
    let _pause_hotkey_registration =
        initialize_pause_hotkey(resolved_pause_hotkey.setting, &hotkey_status_path);
    // File name only, and no host/run-label: paths, hostnames, and labels can
    // carry usernames or client names, and retained logs survive retention
    // and secure erase (S7). The sessions table keeps the erase-governed copy.
    info!(
        db_file = %log_file_name(&db_path),
        session_id,
        app_version = APP_VERSION,
        git_sha = GIT_SHA,
        "Gilbreth started"
    );

    platform::init_termination_signal();
    platform::init_permission_baseline();
    let capture_result = platform::run_capture_pump(capture_tx, stop.clone(), controls, || {
        // Dispatch queued AppKit events first (no-op on Windows) so a tray
        // click handled this pass reaches MenuEvent::receiver() before the
        // menu handler below reads it.
        platform::pump_app_events();
        #[cfg(any(windows, target_os = "macos"))]
        if platform::take_pause_hotkey_press() {
            tray.toggle_capture_pause(true);
        }
        tray.handle_termination_signal();
        tray.handle_permission_subsystem(Instant::now());
        tray.handle_notification_access_state(Instant::now());
        tray.handle_menu_events();
    });

    stop.cancel();
    if let Err(error) = capture_result {
        error!(%error, "foreground capture stopped with error");
    }
    tray.stop_record_worker();
    drop(tray);
    if capture_forwarder_handle.join().is_err() {
        warn!("capture forwarder thread panicked");
    }

    match wait_for_writer(writer_handle, writer_done_rx) {
        Ok(report) => {
            info!(
                events_written = report.events_written,
                events_skipped = report.events_skipped,
                actions_written = report.actions_written,
                actions_skipped = report.actions_skipped,
                "Gilbreth M3 stopped"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn initialize_pause_hotkey(
    setting: hotkey::PauseHotkeySetting,
    status_path: &Path,
) -> Option<platform::PauseHotkeyRegistration> {
    let (registration, status) = match setting {
        hotkey::PauseHotkeySetting::Disabled => {
            info!(
                config_key = "[hotkey].pause_resume",
                "pause hotkey disabled by config"
            );
            (None, hotkey::PauseHotkeyStatus::disabled())
        }
        hotkey::PauseHotkeySetting::Enabled(chord) => {
            match platform::register_pause_hotkey(chord) {
                Ok(registration) => {
                    info!(%chord, "pause hotkey registered");
                    (
                        Some(registration),
                        hotkey::PauseHotkeyStatus::registered(chord),
                    )
                }
                Err(error) => {
                    warn!(%error, %chord, "pause hotkey is off for this run");
                    alert(
                        DIALOG_TITLE_PAUSE_HOTKEY,
                        &hotkey::registration_failure_alert(chord),
                        AlertKind::Warning,
                    );
                    (None, hotkey::PauseHotkeyStatus::unregistered(chord))
                }
            }
        }
    };
    if let Err(error) = hotkey::write_status(status_path, &status) {
        warn!(%error, "failed to publish pause-hotkey Diagnostics state");
    }
    registration
}

fn log_config_status(status: &ConfigStatus) {
    match status {
        ConfigStatus::Loaded => info!("loaded config"),
        ConfigStatus::CreatedDefault => info!("created default config"),
        ConfigStatus::UpgradedDefaultFields => {
            info!("upgraded config with missing default fields")
        }
        ConfigStatus::Malformed { message } => {
            warn!(%message, "config is malformed; using defaults without overwriting it");
        }
    }
}

/// A malformed config silently falls back to defaults — which drops any custom
/// redaction rules and storage paths for the run. Defaults are permissive, so
/// this is a fail-open for privacy; make it visible with a startup dialog
/// instead of a log line only, mirroring the incompatible-DB message box. The
/// bad file is not overwritten, so fixing the typo and restarting restores the
/// settings.
fn warn_user_if_config_malformed(status: &ConfigStatus) {
    if let ConfigStatus::Malformed { message } = status {
        alert(
            DIALOG_TITLE_SETTINGS_NOT_LOADED,
            &format!("{BODY_CONFIG_MALFORMED_PREFIX}{message}"),
            AlertKind::Warning,
        );
    }
}

fn init_tracing() -> Result<WorkerGuard> {
    let mut log_filter = log_filter_config();
    let invalid_filter = match EnvFilter::try_new(&log_filter.directive) {
        Ok(_) => {
            log_filter.effective_directive = log_filter.directive.clone();
            None
        }
        Err(error) => {
            let invalid = log_filter.directive.clone();
            log_filter.effective_directive = DEFAULT_LOG_FILTER.to_string();
            Some((invalid, error.to_string()))
        }
    };
    let filter = EnvFilter::new(&log_filter.effective_directive);
    let log_dir = local_data_dir()?.join("logs");
    fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("gilbreth.log")
        .max_log_files(LOG_RETENTION_FILES)
        .build(&log_dir)
        .context("failed to create rolling log appender")?;
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer)
        .init();
    // No log_dir path here: it contains the user profile directory, and this
    // line lands in a retained log (S7).
    info!(
        filter = %log_filter.effective_directive,
        source = ?log_filter.source,
        timestamps = "utc",
        daily_rollover = "utc",
        max_log_files = LOG_RETENTION_FILES,
        "logging initialized"
    );
    if let Some((invalid, error)) = invalid_filter {
        warn!(
            env_var = GILBRETH_LOG_ENV,
            invalid_filter = %invalid,
            fallback = DEFAULT_LOG_FILTER,
            %error,
            "invalid log filter; using default"
        );
    }
    Ok(guard)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LogFilterSource {
    Default,
    Env,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogFilterConfig {
    directive: String,
    effective_directive: String,
    source: LogFilterSource,
}

fn log_filter_config() -> LogFilterConfig {
    match env::var(GILBRETH_LOG_ENV) {
        Ok(value) if !value.trim().is_empty() => LogFilterConfig {
            directive: value,
            effective_directive: String::new(),
            source: LogFilterSource::Env,
        },
        _ => LogFilterConfig {
            directive: DEFAULT_LOG_FILTER.to_string(),
            effective_directive: String::new(),
            source: LogFilterSource::Default,
        },
    }
}

type StoreWriterResult = std::result::Result<WriterReport, StoreError>;

fn report_writer_thread_exit<W>(
    result: thread::Result<StoreWriterResult>,
    stop: StopToken,
    wake: W,
    done_tx: mpsc::Sender<Result<WriterReport>>,
) where
    W: FnOnce(),
{
    let result = match result {
        Ok(result) => result.context("writer failed"),
        Err(payload) => {
            let panic_message = panic_payload_message(payload.as_ref());
            error!(panic = %panic_message, "writer thread panicked; stopping capture");
            Err(anyhow!("writer thread panicked: {panic_message}"))
        }
    };
    stop.cancel();
    wake();
    let _ = done_tx.send(result);
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn wait_for_writer(
    handle: thread::JoinHandle<()>,
    done_rx: mpsc::Receiver<Result<WriterReport>>,
) -> Result<WriterReport> {
    match done_rx.recv_timeout(WRITER_JOIN_TIMEOUT) {
        Ok(result) => {
            handle
                .join()
                .map_err(|_| anyhow!("writer thread panicked after reporting a result"))?;
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            error!(
                timeout_ms = WRITER_JOIN_TIMEOUT.as_millis(),
                "writer did not stop before timeout"
            );
            Err(anyhow!("writer did not stop before timeout"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match handle.join() {
            Ok(()) => Err(anyhow!("writer stopped without reporting a result")),
            Err(_) => Err(anyhow!("writer thread panicked")),
        },
    }
}

type CaptureFlushReply = Sender<()>;

fn forward_captured_to_writer(captured: Captured, writer_tx: &Sender<WriterInput>) -> bool {
    writer_tx.send(WriterInput::Motion(captured)).is_ok()
}

fn drain_capture_forwarder_until_quiet(
    capture_rx: &Receiver<Captured>,
    writer_tx: &Sender<WriterInput>,
) -> bool {
    let mut quiet_deadline = std::time::Instant::now() + CAPTURE_FORWARDER_FLUSH_QUIET_PERIOD;
    loop {
        let now = std::time::Instant::now();
        if now >= quiet_deadline {
            return true;
        }
        match capture_rx.recv_timeout(quiet_deadline.saturating_duration_since(now)) {
            Ok(captured) => {
                if !forward_captured_to_writer(captured, writer_tx) {
                    return false;
                }
                quiet_deadline = std::time::Instant::now() + CAPTURE_FORWARDER_FLUSH_QUIET_PERIOD;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => return true,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return true,
        }
    }
}

fn run_capture_forwarder(
    capture_rx: Receiver<Captured>,
    writer_tx: Sender<WriterInput>,
    flush_rx: Receiver<CaptureFlushReply>,
) {
    let mut flush_open = true;
    loop {
        if flush_open {
            select! {
                recv(capture_rx) -> msg => match msg {
                    Ok(captured) => {
                        if !forward_captured_to_writer(captured, &writer_tx) {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                recv(flush_rx) -> msg => match msg {
                    Ok(reply) => {
                        let writer_open = drain_capture_forwarder_until_quiet(&capture_rx, &writer_tx);
                        let _ = reply.send(());
                        if !writer_open {
                            break;
                        }
                    }
                    Err(_) => flush_open = false,
                },
            }
        } else {
            match capture_rx.recv() {
                Ok(captured) => {
                    if !forward_captured_to_writer(captured, &writer_tx) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn flush_capture_forwarder(flush_tx: &Sender<CaptureFlushReply>) -> Result<(), String> {
    let (reply_tx, reply_rx) = bounded(1);
    flush_tx
        .send(reply_tx)
        .map_err(|error| format!("capture forwarder is not available: {error}"))?;
    reply_rx
        .recv_timeout(CAPTURE_FORWARDER_FLUSH_TIMEOUT)
        .map_err(|error| format!("capture forwarder did not confirm a quiet pipeline: {error}"))
}

/// Turning the Foreground stream off must invalidate the writer policy's
/// focus latch (the exclusion fail-open fix): no FocusChanged can correct it
/// while the stream is off, so window-less rows would inherit the last
/// verdict for the whole off period. The caller closes the stream gate
/// FIRST; this then flushes the capture-forwarder hop and sends the forget,
/// whose writer-side handler drains its input channel before forgetting —
/// with no new FocusChanged producible, none can re-arm the latch after the
/// forget. A flush failure (writer wedged past the 2 s timeout) still sends
/// the forget, but the guarantee degrades: a pre-gate FocusChanged still
/// upstream of the writer when the drain runs applies after the forget and
/// re-arms the latch with its stale verdict — accepted as a double-failure
/// residue rather than handled. The forget is unconditional on the
/// exclusion list (simpler, and exclusions cannot change mid-run). No-op
/// for every other stream or direction.
fn forget_focus_attribution_on_stream_toggle(
    stream: CaptureStream,
    enabled: bool,
    capture_flush: &Sender<CaptureFlushReply>,
    commands: &Sender<WriterCommand>,
) {
    if stream != CaptureStream::Foreground || enabled {
        return;
    }
    if let Err(error) = flush_capture_forwarder(capture_flush) {
        error!(%error, "forwarder flush before focus-attribution forget failed");
    }
    let (ack, _) = bounded(1);
    if let Err(error) = commands.send(WriterCommand::ForgetFocusAttribution { ack }) {
        error!(%error, "failed to send focus-attribution forget");
    }
}

fn enqueue_capture_pause_row(
    writer_inputs: &Sender<WriterInput>,
    payload: EventPayload,
) -> Result<(), String> {
    writer_inputs
        .send(WriterInput::Motion(Captured::new(
            Source::System,
            Instant::now(),
            payload,
        )))
        .map_err(|error| format!("failed to write the capture pause boundary: {error}"))
}

#[cfg(not(test))]
fn prepare_capture_resume(
    capture_flush: &Sender<CaptureFlushReply>,
    pump_waker: PumpWaker,
) -> Result<u64, String> {
    let generation = platform::reconcile_sensitive_context_before_resume(pump_waker)
        .ok_or_else(|| "sensitive-context reconciliation did not complete".to_string())?;
    flush_capture_forwarder(capture_flush)?;
    Ok(generation)
}

#[cfg(test)]
fn prepare_capture_resume(
    _capture_flush: &Sender<CaptureFlushReply>,
    pump_waker: PumpWaker,
) -> Result<u64, String> {
    platform::reconcile_sensitive_context_before_resume(pump_waker)
        .ok_or_else(|| "sensitive-context reconciliation did not complete".to_string())
}

fn resume_capture_after_quiet(
    controls: &CaptureControls,
    capture_flush: &Sender<CaptureFlushReply>,
    writer_inputs: &Sender<WriterInput>,
    pump_waker: PumpWaker,
    boundary: Option<EventPayload>,
    redact_titles_on_reseed: bool,
) -> Result<(), String> {
    // The resume barrier gates ordinary traffic while reconciliation and the
    // forwarder drain run without holding the transition mutex. The final
    // generation check happens under that mutex. A transition that announces
    // itself after the check globally gates capture, waits, then queues its
    // boundary after reopen before releasing ordinary traffic.
    controls.set_sensitive_resume_barrier(true);
    let mut last_error = "sensitive context changed throughout resume".to_string();
    for _ in 0..3 {
        let generation = match prepare_capture_resume(capture_flush, pump_waker) {
            Ok(generation) => generation,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        let guard_owner = controls.clone();
        let _resume_guard = guard_owner.sensitive_resume_guard();
        if controls.sensitive_transition_active()
            || controls.sensitive_transition_generation() != generation
        {
            last_error = "sensitive context changed during the resume drain".to_string();
            continue;
        }
        if let Some(payload) = boundary.as_ref() {
            if let Err(error) = enqueue_capture_pause_row(writer_inputs, payload.clone()) {
                controls.set_sensitive_resume_barrier(false);
                return Err(error);
            }
        }
        controls.set_suspended(false);
        controls.set_sensitive_resume_barrier(false);
        if redact_titles_on_reseed {
            controls.request_title_redacted_reseed();
        } else {
            controls.request_reseed();
        }
        pump_waker.wake();
        return Ok(());
    }
    controls.set_sensitive_resume_barrier(false);
    Err(last_error)
}

struct Tray {
    _menu: Menu,
    _capture_menu: Submenu,
    foreground: CheckMenuItem,
    windows: CheckMenuItem,
    keyboard: CheckMenuItem,
    mouse: CheckMenuItem,
    system: CheckMenuItem,
    idle: CheckMenuItem,
    pause_capture: MenuItem,
    _separator: PredefinedMenuItem,
    _open_dashboard: MenuItem,
    _privacy_menu: Submenu,
    store_key_content: CheckMenuItem,
    // Appended on every platform so the tray anatomy stays identical; only
    // the Windows handler reads (and retitles) it today.
    #[cfg_attr(not(windows), allow(dead_code))]
    notification_access: MenuItem,
    // Gated rather than disabled, for the same reason as the record items:
    // `apply_recording_visual_state` re-applies the enabled flag on every
    // capture pause, so a disabled item comes back.
    #[cfg(windows)]
    archive_reset: MenuItem,
    erase_all_data: MenuItem,
    // Record Routine is Windows-only by decision record: AX has no
    // UIA-equivalent action event, so macOS never gets these surfaces at all
    // rather than getting a weaker version of them. Gating the fields (not
    // just their `enabled` flag) is deliberate — `apply_recording_visual_state`
    // re-enables the item on every state change, so an enabled-flag gate is
    // silently undone the first time capture pauses or resumes.
    #[cfg(windows)]
    record_routine: MenuItem,
    #[cfg(windows)]
    stop_recording: MenuItem,
    #[cfg(windows)]
    pause_recording: MenuItem,
    #[cfg(windows)]
    resume_recording: MenuItem,
    launch_at_startup: CheckMenuItem,
    _quit: MenuItem,
    _icon: TrayIcon,
    stop: StopToken,
    controls: CaptureControls,
    config: AppConfig,
    config_path: PathBuf,
    privacy_commands: PrivacyCommandContext,
    record_commands: RecordCommandContext,
    privacy_action_in_progress: Arc<AtomicBool>,
    privacy_suspension_owned: Arc<AtomicBool>,
    record_action_in_progress: Arc<AtomicBool>,
    active_record_session_id: Option<i64>,
    record_stop_pending_session_id: Option<i64>,
    recording_paused: bool,
    baseline_capture_suspended_for_recording: bool,
    /// Ambient capture pause is independent of Record Routine's temporary
    /// baseline suspension. It is manual-only and survives a recording stop.
    capture_paused_by_user: Arc<AtomicBool>,
    /// The last permission-request generation this pump acted on (the
    /// reseed-flag precedent: act only when the dashboard's generation
    /// advances, so a stale request file on disk is never replayed). `0`
    /// means nothing acted on yet.
    last_permission_request_generation: u64,
    /// Throttle for the permission state/request sidecar poll (the 1 s
    /// cadence the other pollers use); the pump services at ~20 Hz and this
    /// work has no reason to run every pass.
    last_permission_poll: Option<Instant>,
    // Read only by the Windows notification poll; kept on every platform so
    // the tray anatomy stays identical.
    #[cfg_attr(not(windows), allow(dead_code))]
    notification_access_state: Option<notification_consent::NotificationAccessState>,
    #[cfg_attr(not(windows), allow(dead_code))]
    last_notification_access_poll: Option<Instant>,
    #[cfg(windows)]
    record_worker: Option<RecordRoutineHandle>,
    #[cfg(windows)]
    elevated_record_worker: Option<elevated_record_helper::ElevatedRecordHelperHandle>,
}

struct PrivacyCommandContext {
    archive_dir: PathBuf,
    writer_commands: Sender<WriterCommand>,
    capture_flush: Sender<CaptureFlushReply>,
    pump_waker: PumpWaker,
    writer_inputs: Sender<WriterInput>,
    capture_paused_by_user: Arc<AtomicBool>,
}

struct RecordCommandContext {
    writer_commands: Sender<WriterCommand>,
    // Consumed only by the Windows-only record workers, but kept on every
    // platform so the writer channel's lifetime (open until the tray drops)
    // is identical cross-platform.
    #[cfg_attr(not(windows), allow(dead_code))]
    writer_inputs: Sender<WriterInput>,
    request_notifications: Receiver<PendingRecordRequest>,
    cap_notifications: Receiver<CapPrompt>,
    ui_events: Receiver<RecordUiEvent>,
    ui_event_tx: Sender<RecordUiEvent>,
    prompt_in_flight: Arc<AtomicBool>,
    panic_action_cutoff: PanicActionCutoff,
    pump_waker: PumpWaker,
}

/// Record Routine lifecycle events delivered back to the tray. Every
/// resolution event is stamped with the record session it belongs to so the
/// pump thread can drop stale confirmations: a Pause reply that lands after a
/// Stop, or a Stopped/Failed for a session that already resolved, must not
/// mutate state that now belongs to a newer recording (B2/S16).
#[derive(Debug)]
enum RecordUiEvent {
    #[cfg(windows)]
    Started {
        record_session_id: i64,
        elevated_helper_requested: bool,
        baseline_capture_suspended: bool,
    },
    StopForSafetyCap(i64),
    Stopped {
        record_session_id: i64,
    },
    Paused {
        record_session_id: i64,
    },
    Resumed {
        record_session_id: i64,
    },
    Failed {
        /// `None` when the failure precedes a session id (the start flow).
        record_session_id: Option<i64>,
        message: String,
    },
}

impl Tray {
    fn new(
        stop: StopToken,
        controls: CaptureControls,
        config: AppConfig,
        config_path: PathBuf,
        privacy_commands: PrivacyCommandContext,
        record_commands: RecordCommandContext,
    ) -> Result<Self> {
        let capture_paused_by_user = Arc::clone(&privacy_commands.capture_paused_by_user);
        let menu = Menu::new();
        let capture_menu = Submenu::new(MENU_LABEL_CAPTURE, true);
        let foreground = CheckMenuItem::with_id(
            MenuId::new(FOREGROUND_MENU_ID),
            MENU_LABEL_FOREGROUND,
            true,
            config.capture.foreground,
            None,
        );
        let windows = CheckMenuItem::with_id(
            MenuId::new(WINDOWS_MENU_ID),
            MENU_LABEL_WINDOWS,
            true,
            config.capture.windows,
            None,
        );
        let keyboard = CheckMenuItem::with_id(
            MenuId::new(KEYBOARD_MENU_ID),
            MENU_LABEL_KEYBOARD,
            true,
            config.capture.keyboard,
            None,
        );
        let mouse = CheckMenuItem::with_id(
            MenuId::new(MOUSE_MENU_ID),
            MENU_LABEL_MOUSE,
            true,
            config.capture.mouse,
            None,
        );
        let system = CheckMenuItem::with_id(
            MenuId::new(SYSTEM_MENU_ID),
            MENU_LABEL_SYSTEM,
            true,
            config.capture.system,
            None,
        );
        let idle = CheckMenuItem::with_id(
            MenuId::new(IDLE_MENU_ID),
            MENU_LABEL_IDLE,
            true,
            config.capture.idle,
            None,
        );
        capture_menu.append_items(&[&foreground, &windows, &keyboard, &mouse, &system, &idle])?;
        let pause_capture = MenuItem::with_id(
            MenuId::new(PAUSE_CAPTURE_MENU_ID),
            MENU_LABEL_PAUSE_CAPTURE,
            true,
            None,
        );
        let open_dashboard = MenuItem::with_id(
            MenuId::new(OPEN_DASHBOARD_MENU_ID),
            OPEN_DASHBOARD_MENU_LABEL,
            true,
            None,
        );
        let privacy_menu = Submenu::new(MENU_LABEL_PRIVACY, true);
        let store_key_content = CheckMenuItem::with_id(
            MenuId::new(STORE_KEY_CONTENT_MENU_ID),
            MENU_LABEL_STORE_KEY_CONTENT,
            true,
            config.privacy.store_key_content,
            None,
        );
        let notification_access = MenuItem::with_id(
            MenuId::new(NOTIFICATION_ACCESS_MENU_ID),
            MENU_LABEL_NOTIFICATION_ACCESS,
            cfg!(windows),
            None,
        );
        #[cfg(windows)]
        let archive_reset = MenuItem::with_id(
            MenuId::new(ARCHIVE_RESET_MENU_ID),
            MENU_LABEL_ARCHIVE_RESET,
            true,
            None,
        );
        let erase_all_data = MenuItem::with_id(
            MenuId::new(ERASE_ALL_DATA_MENU_ID),
            MENU_LABEL_ERASE_ALL_DATA,
            true,
            None,
        );
        privacy_menu.append(&store_key_content)?;
        privacy_menu.append(&notification_access)?;
        privacy_menu.append(&PredefinedMenuItem::separator())?;
        #[cfg(windows)]
        privacy_menu.append(&archive_reset)?;
        privacy_menu.append(&erase_all_data)?;
        #[cfg(windows)]
        let record_routine = MenuItem::with_id(
            MenuId::new(RECORD_ROUTINE_MENU_ID),
            MENU_LABEL_RECORD_ROUTINE,
            true,
            None,
        );
        #[cfg(windows)]
        let stop_recording = MenuItem::with_id(
            MenuId::new(STOP_RECORDING_MENU_ID),
            MENU_LABEL_STOP_RECORDING,
            false,
            None,
        );
        #[cfg(windows)]
        let pause_recording = MenuItem::with_id(
            MenuId::new(PAUSE_RECORDING_MENU_ID),
            MENU_LABEL_PAUSE_RECORDING,
            false,
            None,
        );
        #[cfg(windows)]
        let resume_recording = MenuItem::with_id(
            MenuId::new(RESUME_RECORDING_MENU_ID),
            MENU_LABEL_RESUME_RECORDING,
            false,
            None,
        );
        let launch_at_startup_enabled = match autostart::is_enabled() {
            Ok(enabled) => enabled,
            Err(error) => {
                warn!(%error, "failed to read launch-at-startup state; showing it off");
                false
            }
        };
        let launch_at_startup = CheckMenuItem::with_id(
            MenuId::new(LAUNCH_AT_STARTUP_MENU_ID),
            MENU_LABEL_LAUNCH_AT_STARTUP,
            true,
            launch_at_startup_enabled,
            None,
        );
        let separator = PredefinedMenuItem::separator();
        let quit = MenuItem::with_id(MenuId::new(QUIT_MENU_ID), MENU_LABEL_QUIT, true, None);

        menu.append(&capture_menu)?;
        menu.append(&pause_capture)?;
        menu.append(&open_dashboard)?;
        #[cfg(windows)]
        {
            menu.append(&record_routine)?;
            menu.append(&stop_recording)?;
            menu.append(&pause_recording)?;
            menu.append(&resume_recording)?;
        }
        menu.append(&privacy_menu)?;
        menu.append(&launch_at_startup)?;
        menu.append(&separator)?;
        menu.append(&quit)?;

        let icon = create_icon()?;
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip(TOOLTIP_DEFAULT)
            .with_icon(icon)
            // macOS renders the status item as a template image (shell-
            // remainders slice): the system tints the monochrome glyph for
            // light/dark menu bars and menu-open highlight. Windows keeps
            // the colored icon; the flag is ignored there by the crate.
            .with_icon_as_template(cfg!(target_os = "macos"))
            .build()?;

        Ok(Self {
            _menu: menu,
            _capture_menu: capture_menu,
            foreground,
            windows,
            keyboard,
            mouse,
            system,
            idle,
            pause_capture,
            _separator: separator,
            _open_dashboard: open_dashboard,
            _privacy_menu: privacy_menu,
            store_key_content,
            notification_access,
            #[cfg(windows)]
            archive_reset,
            erase_all_data,
            #[cfg(windows)]
            record_routine,
            #[cfg(windows)]
            stop_recording,
            #[cfg(windows)]
            pause_recording,
            #[cfg(windows)]
            resume_recording,
            launch_at_startup,
            _quit: quit,
            _icon: tray_icon,
            stop,
            controls,
            config,
            config_path,
            privacy_commands,
            record_commands,
            privacy_action_in_progress: Arc::new(AtomicBool::new(false)),
            privacy_suspension_owned: Arc::new(AtomicBool::new(false)),
            record_action_in_progress: Arc::new(AtomicBool::new(false)),
            active_record_session_id: None,
            record_stop_pending_session_id: None,
            recording_paused: false,
            baseline_capture_suspended_for_recording: false,
            capture_paused_by_user,
            last_permission_request_generation: 0,
            last_permission_poll: None,
            notification_access_state: None,
            last_notification_access_poll: None,
            #[cfg(windows)]
            record_worker: None,
            #[cfg(windows)]
            elevated_record_worker: None,
        })
    }

    /// SIGTERM (loginwindow logout/shutdown, `kill`) routes through the
    /// exact tray-Quit path (Shutdown rules, TCC record 2026-07-12). The
    /// log line doubles as the live logout-delivery probe: what macOS
    /// actually sent is recorded by whether this line appears at logout.
    fn handle_termination_signal(&mut self) {
        if platform::take_termination_signal() {
            info!("quit requested by SIGTERM (logout/shutdown or kill)");
            self.stop.cancel();
            platform::request_pump_quit();
        }
    }

    /// The macOS TCC permission subsystem's pump half (onboarding/Diagnostics
    /// panel; no-op on Windows via the platform facade). Once per second:
    /// (1) publish the authoritative grant state to the sidecar the
    /// dashboard reads, on edges only; (2) act on any dashboard-written
    /// prompt/relaunch request whose generation has advanced — prompts fire
    /// only here, in the pump process, per the TCC record. A `Relaunch`
    /// request routes through the exact tray-Quit path after spawning the
    /// LaunchServices waiter.
    fn handle_permission_subsystem(&mut self, now: Instant) {
        let first_poll = self.last_permission_poll.is_none();
        let due = self
            .last_permission_poll
            .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(1));
        if !due {
            return;
        }
        self.last_permission_poll = Some(now);

        // (0) First-poll silent baseline (the process/system-monitor
        // pattern): adopt whatever request generation is already on disk
        // WITHOUT acting on it. This is what stops a `Relaunch` request —
        // the one that triggered this very launch — from being replayed
        // into an infinite relaunch loop, and stops any other leftover
        // request from re-firing once per restart.
        if first_poll {
            let request_path = permissions::request_sidecar_path(&self.config_path);
            if let Some(request) = permissions::read_request(&request_path) {
                self.last_permission_request_generation = request.generation;
                debug!(
                    generation = request.generation,
                    "permission request baseline adopted at startup (not replayed)"
                );
            }
        }

        // (1) Publish state on edges.
        if let Some(state) = platform::current_permission_state() {
            if platform::permission_state_changed(&state) {
                let path = permissions::state_sidecar_path(&self.config_path);
                match permissions::write_state(&path, &state) {
                    Ok(()) => {
                        platform::note_permission_state_written(&state);
                        info!(
                            accessibility = ?state.accessibility,
                            input_monitoring = ?state.input_monitoring,
                            "permission state published to the Diagnostics panel"
                        );
                    }
                    Err(error) => warn!(%error, "failed to publish the permission state sidecar"),
                }
            }
        }

        // (2) Act on a fresh dashboard request.
        let request_path = permissions::request_sidecar_path(&self.config_path);
        if let Some(request) = permissions::read_request(&request_path) {
            if request.generation > self.last_permission_request_generation {
                self.last_permission_request_generation = request.generation;
                info!(?request.action, "acting on a permission request from the dashboard");
                // Quit ONLY when the action actually initiated a relaunch
                // (the reopen waiter spawned). A relaunch that could not
                // start — an unbundled dev binary with no `.app` to reopen,
                // or a failed spawn — returns false and leaves the pump
                // running rather than exiting with nothing to bring it back.
                // Prompts always return false. The quit then runs the exact
                // tray-Quit path so the graceful shutdown releases the
                // single-instance lock before the reopen.
                if platform::perform_permission_action(request.action) {
                    self.stop.cancel();
                    platform::request_pump_quit();
                }
            }
        }
    }

    /// Publish Windows notification access for the dashboard without ever
    /// requesting consent from this periodic/background path.
    fn handle_notification_access_state(&mut self, now: Instant) {
        #[cfg(not(windows))]
        let _ = now;
        #[cfg(windows)]
        {
            let due = self
                .last_notification_access_poll
                .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(1));
            if !due {
                return;
            }
            self.last_notification_access_poll = Some(now);
            let state = current_notification_access_state();
            if self.notification_access_state != Some(state) {
                self.publish_notification_access_state(state);
            }
        }
    }

    #[cfg(windows)]
    fn publish_notification_access_state(
        &mut self,
        state: notification_consent::NotificationAccessState,
    ) {
        let path = notification_consent::sidecar_path(
            self.config_path.parent().unwrap_or_else(|| Path::new(".")),
        );
        let snapshot = notification_consent::NotificationAccessSnapshot::new(state);
        match notification_consent::write_snapshot(&path, &snapshot) {
            Ok(()) => {
                self.notification_access_state = Some(state);
                self.notification_access.set_text(match state {
                    notification_consent::NotificationAccessState::Allowed => {
                        MENU_LABEL_NOTIFICATION_ACCESS_ON
                    }
                    notification_consent::NotificationAccessState::Denied => {
                        MENU_LABEL_NOTIFICATION_ACCESS_DENIED
                    }
                    _ => MENU_LABEL_NOTIFICATION_ACCESS,
                });
                info!(?state, "notification access state published");
            }
            Err(error) => warn!(%error, ?state, "failed to publish notification access state"),
        }
    }

    fn handle_notification_access_action(&mut self) {
        #[cfg(not(windows))]
        alert(
            notification_consent::REQUEST_TITLE,
            BODY_NOTIFICATIONS_UNSUPPORTED_PLATFORM,
            AlertKind::Info,
        );
        #[cfg(windows)]
        {
            use notification_consent::{ExplicitAction, NotificationAccessState};
            let state = current_notification_access_state();
            self.publish_notification_access_state(state);
            match notification_consent::explicit_action_for(state) {
                ExplicitAction::ReportAllowed => alert(
                    notification_consent::REQUEST_TITLE,
                    notification_consent::ALLOWED_EXPLANATION,
                    AlertKind::Info,
                ),
                ExplicitAction::ExplainAndRequest => {
                    if !confirm(
                        notification_consent::REQUEST_TITLE,
                        notification_consent::REQUEST_EXPLANATION,
                        AlertKind::Info,
                        ConfirmButtons::OkCancel,
                        false,
                    ) {
                        return;
                    }
                    let requested = request_notification_access_state();
                    self.publish_notification_access_state(requested);
                    if requested == NotificationAccessState::Allowed {
                        alert(
                            notification_consent::REQUEST_TITLE,
                            notification_consent::ALLOWED_EXPLANATION,
                            AlertKind::Info,
                        );
                    } else {
                        self.offer_notification_settings(requested.privacy_copy());
                    }
                }
                ExplicitAction::ExplainAndOpenSettings => {
                    self.offer_notification_settings(state.privacy_copy());
                }
                ExplicitAction::ReportUnsupported => alert(
                    notification_consent::REQUEST_TITLE,
                    state.privacy_copy(),
                    AlertKind::Info,
                ),
            }
        }
    }

    #[cfg(windows)]
    fn offer_notification_settings(&self, explanation: &str) {
        let message = format!("{explanation}\n\n{BODY_NOTIFICATION_SETTINGS_QUESTION}");
        if confirm(
            notification_consent::REQUEST_TITLE,
            &message,
            AlertKind::Info,
            ConfirmButtons::OkCancel,
            false,
        ) && !platform::open_url(notification_consent::NOTIFICATION_SETTINGS_URI)
        {
            alert(
                notification_consent::REQUEST_TITLE,
                BODY_NOTIFICATION_SETTINGS_OPEN_FAILED,
                AlertKind::Warning,
            );
        }
    }

    fn handle_menu_events(&mut self) {
        self.handle_record_ui_events();
        #[cfg(windows)]
        self.handle_elevated_record_worker_liveness();
        #[cfg(windows)]
        self.handle_record_worker_liveness();
        self.handle_record_notifications();
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            match event.id.0.as_str() {
                FOREGROUND_MENU_ID => self.toggle_stream(CaptureStream::Foreground),
                WINDOWS_MENU_ID => self.toggle_stream(CaptureStream::Windows),
                KEYBOARD_MENU_ID => self.toggle_stream(CaptureStream::Keyboard),
                MOUSE_MENU_ID => self.toggle_stream(CaptureStream::Mouse),
                SYSTEM_MENU_ID => self.toggle_stream(CaptureStream::System),
                IDLE_MENU_ID => self.toggle_stream(CaptureStream::Idle),
                PAUSE_CAPTURE_MENU_ID => self.toggle_capture_pause(false),
                OPEN_DASHBOARD_MENU_ID => self.open_dashboard(),
                #[cfg(windows)]
                ARCHIVE_RESET_MENU_ID => self.request_archive_reset(),
                ERASE_ALL_DATA_MENU_ID => self.request_secure_erase(),
                #[cfg(windows)]
                RECORD_ROUTINE_MENU_ID => self.request_manual_record_routine(),
                #[cfg(windows)]
                STOP_RECORDING_MENU_ID => self.stop_recording(),
                #[cfg(windows)]
                PAUSE_RECORDING_MENU_ID => self.pause_recording(),
                #[cfg(windows)]
                RESUME_RECORDING_MENU_ID => self.resume_recording(),
                STORE_KEY_CONTENT_MENU_ID => self.toggle_store_key_content(),
                NOTIFICATION_ACCESS_MENU_ID => self.handle_notification_access_action(),
                LAUNCH_AT_STARTUP_MENU_ID => self.toggle_launch_at_startup(),
                QUIT_MENU_ID => {
                    info!("quit requested from tray");
                    self.stop.cancel();
                    platform::request_pump_quit();
                }
                _ => {}
            }
        }
    }

    fn toggle_stream(&mut self, stream: CaptureStream) {
        let enabled = !self.config.capture.is_enabled(stream);
        self.config.capture.set_enabled(stream, enabled);
        self.controls.set_enabled(stream, enabled);
        // Runs after the gate change above: forgetting the focus latch is
        // only race-free once no new FocusChanged can be produced.
        forget_focus_attribution_on_stream_toggle(
            stream,
            enabled,
            &self.privacy_commands.capture_flush,
            &self.privacy_commands.writer_commands,
        );
        self.menu_item(stream).set_checked(enabled);

        if let Err(error) = config::save_capture_toggle(&self.config_path, stream, enabled) {
            error!(%error, ?stream, enabled, "failed to persist capture toggle");
        } else {
            info!(?stream, enabled, "capture toggle updated");
        }
    }

    /// Toggle the one ambient-capture pause state shared by the global
    /// hotkey and the always-present tray fallback. Resume is never timed.
    fn toggle_capture_pause(&mut self, from_hotkey: bool) {
        let privacy_operation_owns_suspension =
            self.privacy_suspension_owned.load(Ordering::SeqCst);
        if self.capture_paused_by_user.load(Ordering::SeqCst) {
            // Defensive edge: an explicit recording should not normally be
            // startable while ambient capture is paused. If one exists, the
            // panic control closes it and remains paused rather than briefly
            // running ambient + Record Routine together.
            if let Some(record_session_id) = self.active_record_session_id {
                self.stop_recording_with_reason(record_session_id, RecordStopReason::PanicHotkey);
                return;
            }
            self.capture_paused_by_user.store(false, Ordering::SeqCst);
            if !privacy_operation_owns_suspension {
                // Keep producers closed until the value-free resume boundary
                // is enqueued. That makes the boundary the first row of the
                // reopened interval instead of racing a capture callback.
                let resume_result = resume_capture_after_quiet(
                    &self.controls,
                    &self.privacy_commands.capture_flush,
                    &self.record_commands.writer_inputs,
                    self.record_commands.pump_waker,
                    Some(EventPayload::CaptureResumed),
                    true,
                );
                match resume_result {
                    Ok(()) => {}
                    Err(error) => {
                        self.capture_paused_by_user.store(true, Ordering::SeqCst);
                        error!(%error, "ambient capture remains paused because its resume boundary could not be written");
                    }
                }
            }
            info!(
                trigger = if from_hotkey { "hotkey" } else { "tray" },
                "ambient capture resumed"
            );
        } else {
            self.capture_paused_by_user.store(true, Ordering::SeqCst);
            self.controls.set_suspended(true);
            if let Some(record_session_id) = self.active_record_session_id {
                // Arm the Record Routine fence at the pause edge before the
                // ambient forwarder quiet barrier can wait.
                self.stop_recording_with_reason(record_session_id, RecordStopReason::PanicHotkey);
            }
            if !privacy_operation_owns_suspension {
                // Close producers, then drain their forwarder hop before the
                // pause row. A pre-pause event can therefore never land on
                // the paused side of the audit boundary.
                if let Err(error) = flush_capture_forwarder(&self.privacy_commands.capture_flush) {
                    error!(%error, "capture is paused but its audit boundary could not be serialized");
                } else {
                    if let Err(error) = enqueue_capture_pause_row(
                        &self.record_commands.writer_inputs,
                        EventPayload::CapturePaused,
                    ) {
                        error!(%error, "capture is paused but its audit boundary could not be written");
                    }
                }
            }
            info!(
                trigger = if from_hotkey { "hotkey" } else { "tray" },
                "ambient capture paused"
            );
        }
        if privacy_operation_owns_suspension {
            info!(
                desired_paused = self.capture_paused_by_user.load(Ordering::SeqCst),
                "privacy operation retains capture suspension until its worker completes"
            );
        }
        self.apply_recording_visual_state();
    }

    fn toggle_store_key_content(&mut self) {
        // muda auto-toggles the checkmark before this handler runs; the config
        // is the source of truth, so derive the new state from it and force the
        // checkmark to match the persisted result.
        let enabled = !self.config.privacy.store_key_content;
        match config::save_store_key_content(&self.config_path, enabled) {
            Ok(()) => {
                self.config.privacy.store_key_content = enabled;
                // Using the toggle is an explicit posture choice: the save
                // above persists posture_confirmed = true, so the first-run
                // consent dialog never returns (the first-run consent design).
                self.config.privacy.posture_confirmed = true;
                self.store_key_content.set_checked(enabled);
                info!(enabled, "store-key-content setting updated");
                let message = if enabled {
                    BODY_STORE_KEY_CONTENT_ON
                } else {
                    BODY_STORE_KEY_CONTENT_OFF
                };
                alert(DIALOG_TITLE_PRIVACY, message, AlertKind::Info);
            }
            Err(error) => {
                error!(%error, enabled, "failed to persist store-key-content setting");
                self.store_key_content
                    .set_checked(self.config.privacy.store_key_content);
            }
        }
    }

    fn toggle_launch_at_startup(&self) {
        // The registry is the source of truth — derive the new state from it, NOT
        // from `is_checked()`. muda auto-toggles a CheckMenuItem's checkmark on
        // click *before* this handler runs, so reading the checkmark here would
        // double-toggle and make every click a no-op. After acting, we force the
        // checkmark to match the actual result.
        let desired = !autostart::is_enabled().unwrap_or(false);
        match autostart::set_enabled(desired) {
            Ok(()) => {
                self.launch_at_startup.set_checked(desired);
                info!(enabled = desired, "launch-at-startup updated");
            }
            Err(error) => {
                error!(%error, enabled = desired, "failed to update launch-at-startup");
                let actual = autostart::is_enabled().unwrap_or(false);
                self.launch_at_startup.set_checked(actual);
                // Surface the failure the user just triggered instead of
                // silently flicking the checkbox back — the message carries
                // the actionable path (on macOS, System Settings > General >
                // Login Items when the item was switched off there). The
                // shell-remainders slice added this dialog for exactly this.
                platform::alert(
                    DIALOG_TITLE_LAUNCH_AT_STARTUP,
                    &format!("{BODY_LAUNCH_AT_STARTUP_FAILED_PREFIX}{error}"),
                    platform::AlertKind::Warning,
                );
            }
        }
    }

    fn menu_item(&self, stream: CaptureStream) -> &CheckMenuItem {
        match stream {
            CaptureStream::Foreground => &self.foreground,
            CaptureStream::Windows => &self.windows,
            CaptureStream::Keyboard => &self.keyboard,
            CaptureStream::Mouse => &self.mouse,
            CaptureStream::System => &self.system,
            CaptureStream::Idle => &self.idle,
        }
    }

    /// Spawn the egui dashboard as a second process of this exe.
    /// Concurrent dashboard windows are allowed. Read lanes are WAL-safe and
    /// explicit writes use the existing bounded store/config paths; a separate
    /// nonblocking claim merely limits eframe UI-state persistence to one
    /// viewer and never blocks another window from opening.
    fn open_dashboard(&self) {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(error) => {
                error!(%error, "could not resolve current exe for the dashboard");
                return;
            }
        };
        match spawn_dashboard_worker(dashboard_command(&exe)) {
            Ok(_) => info!("dashboard launch worker started"),
            Err(error) => error!(%error, "failed to start dashboard launch worker"),
        }
    }

    fn record_lifecycle_active(&self) -> bool {
        self.active_record_session_id.is_some()
            || self.record_stop_pending_session_id.is_some()
            || self.record_action_in_progress.load(Ordering::SeqCst)
            || self.record_commands.prompt_in_flight.load(Ordering::SeqCst)
    }

    fn block_privacy_action_during_recording(&self) -> bool {
        if !self.record_lifecycle_active() {
            return false;
        }
        alert(
            DIALOG_TITLE_PRIVACY,
            BODY_PRIVACY_BLOCKED_DURING_RECORDING,
            AlertKind::Warning,
        );
        true
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    fn request_archive_reset(&mut self) {
        if self.block_privacy_action_during_recording() {
            return;
        }
        if self
            .privacy_action_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!("privacy action already in progress");
            return;
        }

        let controls = self.controls.clone();
        let commands = self.privacy_commands.writer_commands.clone();
        let capture_flush = self.privacy_commands.capture_flush.clone();
        let archive_path = next_archive_path(&self.privacy_commands.archive_dir);
        let receipt_data_dir = self
            .privacy_commands
            .archive_dir
            .parent()
            .unwrap_or(&self.privacy_commands.archive_dir)
            .to_path_buf();
        let pump_waker = self.privacy_commands.pump_waker;
        let writer_inputs = self.privacy_commands.writer_inputs.clone();
        let capture_paused_by_user = Arc::clone(&self.privacy_commands.capture_paused_by_user);
        let privacy_action_in_progress = Arc::clone(&self.privacy_action_in_progress);
        let privacy_suspension_owned = Arc::clone(&self.privacy_suspension_owned);
        thread::spawn(move || {
            let _reset_guard = FlagGuard::new(privacy_action_in_progress);
            run_archive_reset_dialogs_and_command(
                archive_path,
                receipt_data_dir,
                PrivacyOperationRuntime {
                    controls,
                    commands,
                    capture_flush,
                    pump_waker,
                    writer_inputs,
                    capture_paused_by_user,
                    privacy_suspension_owned,
                },
            );
        });
    }

    fn request_secure_erase(&mut self) {
        if self.block_privacy_action_during_recording() {
            return;
        }
        if self
            .privacy_action_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!("privacy action already in progress");
            return;
        }

        let controls = self.controls.clone();
        let commands = self.privacy_commands.writer_commands.clone();
        let capture_flush = self.privacy_commands.capture_flush.clone();
        let pump_waker = self.privacy_commands.pump_waker;
        let config_path = self.config_path.clone();
        let writer_inputs = self.privacy_commands.writer_inputs.clone();
        let capture_paused_by_user = Arc::clone(&self.privacy_commands.capture_paused_by_user);
        let privacy_action_in_progress = Arc::clone(&self.privacy_action_in_progress);
        let privacy_suspension_owned = Arc::clone(&self.privacy_suspension_owned);
        thread::spawn(move || {
            let _reset_guard = FlagGuard::new(privacy_action_in_progress);
            run_secure_erase_dialogs_and_command(
                config_path,
                PrivacyOperationRuntime {
                    controls,
                    commands,
                    capture_flush,
                    pump_waker,
                    writer_inputs,
                    capture_paused_by_user,
                    privacy_suspension_owned,
                },
            );
        });
    }

    fn handle_record_notifications(&mut self) {
        while let Ok(request) = self.record_commands.request_notifications.try_recv() {
            #[cfg(not(windows))]
            decline_unsupported_record_request(&self.record_commands.writer_commands, &request);
            #[cfg(windows)]
            self.spawn_record_request_dialog(Some(request));
        }
        while let Ok(prompt) = self.record_commands.cap_notifications.try_recv() {
            if should_spawn_cap_prompt(
                self.active_record_session_id,
                self.record_stop_pending_session_id,
                prompt.record_session_id,
            ) {
                self.spawn_cap_prompt(prompt);
            } else {
                info!(
                    record_session_id = prompt.record_session_id,
                    active_record_session_id = ?self.active_record_session_id,
                    stop_pending_record_session_id = ?self.record_stop_pending_session_id,
                    "ignored stale record routine safety-cap prompt"
                );
            }
        }
    }

    fn handle_record_ui_events(&mut self) {
        while let Ok(event) = self.record_commands.ui_events.try_recv() {
            match event {
                #[cfg(windows)]
                RecordUiEvent::Started {
                    record_session_id,
                    elevated_helper_requested,
                    baseline_capture_suspended,
                } => {
                    self.active_record_session_id = Some(record_session_id);
                    self.record_stop_pending_session_id = None;
                    self.recording_paused = false;
                    self.baseline_capture_suspended_for_recording = baseline_capture_suspended;
                    self.apply_recording_visual_state();
                    if self.capture_paused_by_user.load(Ordering::SeqCst) {
                        // The panic control may have landed while the native
                        // start confirmation or writer round-trip was in
                        // flight. Never start a capture worker on the late
                        // success edge; close the just-created session with
                        // the auditable panic reason instead.
                        info!(
                            record_session_id,
                            "closing a late Record Routine start because ambient capture is paused"
                        );
                        self.stop_recording_with_reason(
                            record_session_id,
                            RecordStopReason::PanicHotkey,
                        );
                    } else {
                        self.start_record_worker(record_session_id, elevated_helper_requested);
                    }
                }
                RecordUiEvent::StopForSafetyCap(record_session_id) => {
                    self.stop_recording_with_reason(
                        record_session_id,
                        RecordStopReason::SafetyCapStop,
                    );
                }
                RecordUiEvent::Stopped { record_session_id } => {
                    if self.active_record_session_id != Some(record_session_id) {
                        info!(record_session_id, "ignored stale record stop confirmation");
                        continue;
                    }
                    self.record_commands
                        .panic_action_cutoff
                        .clear(record_session_id);
                    self.stop_record_worker();
                    self.active_record_session_id = None;
                    self.record_stop_pending_session_id = None;
                    self.recording_paused = false;
                    self.resume_baseline_capture_after_recording();
                    self.apply_recording_visual_state();
                }
                RecordUiEvent::Paused { record_session_id } => {
                    // A pause confirmation that lands after a Stop was
                    // dispatched must not flip the indicator to "paused" --
                    // the stop is already in flight and will resolve the
                    // session (B2's original wedge showed exactly this).
                    if self.active_record_session_id != Some(record_session_id)
                        || self.record_stop_pending_session_id == Some(record_session_id)
                    {
                        info!(record_session_id, "ignored stale record pause confirmation");
                        continue;
                    }
                    self.recording_paused = true;
                    self.apply_recording_visual_state();
                }
                RecordUiEvent::Resumed { record_session_id } => {
                    if self.active_record_session_id != Some(record_session_id)
                        || self.record_stop_pending_session_id == Some(record_session_id)
                    {
                        info!(
                            record_session_id,
                            "ignored stale record resume confirmation"
                        );
                        continue;
                    }
                    self.recording_paused = false;
                    self.apply_recording_visual_state();
                }
                RecordUiEvent::Failed {
                    record_session_id,
                    message,
                } => {
                    if let Some(failed_session) = record_session_id {
                        if self.active_record_session_id != Some(failed_session) {
                            warn!(
                                record_session_id = failed_session,
                                failure = %message,
                                "ignored stale record command failure"
                            );
                            continue;
                        }
                        // Converge the writer before clearing local state: a
                        // lost pause/resume reply leaves the writer holding
                        // the session open, and without this stop it would be
                        // closed at shutdown as `app_shutdown` instead of its
                        // real reason (S16). Stopping a session the writer
                        // already closed replies Err, which the stale filter
                        // above then drops -- so this cannot loop.
                        if self.record_stop_pending_session_id != Some(failed_session) {
                            self.spawn_stop_record_command(failed_session, RecordStopReason::Error);
                        }
                    }
                    self.stop_record_worker();
                    self.active_record_session_id = None;
                    self.record_stop_pending_session_id = None;
                    self.recording_paused = false;
                    self.resume_baseline_capture_after_recording();
                    self.apply_recording_visual_state();
                    alert(DIALOG_TITLE_RECORD_ROUTINE, &message, AlertKind::Warning);
                }
            }
        }
    }

    #[cfg(windows)]
    fn handle_elevated_record_worker_liveness(&mut self) {
        let helper_stop_reason = self
            .elevated_record_worker
            .as_mut()
            .and_then(|worker| worker.poll_unexpected_stop());
        let Some(stop_reason) = helper_stop_reason else {
            return;
        };
        let Some(record_session_id) = self.active_record_session_id else {
            return;
        };
        warn!(
            record_session_id,
            stop_reason = stop_reason.as_str(),
            "elevated record helper stopped unexpectedly; closing recording"
        );
        self.stop_recording_with_reason(record_session_id, stop_reason);
    }

    /// The standard (non-elevated) worker equivalent of the elevated liveness
    /// poll: a UIA worker thread that dies mid-recording must close the
    /// recording rather than leave the indicator showing "recording" with
    /// nothing captured and baseline capture suspended (S15).
    #[cfg(windows)]
    fn handle_record_worker_liveness(&mut self) {
        let worker_died = self
            .record_worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished());
        if !worker_died {
            return;
        }
        let Some(record_session_id) = self.active_record_session_id else {
            return;
        };
        if self.record_stop_pending_session_id == Some(record_session_id) {
            // A stop is already in flight; the Stopped handler joins the
            // worker when the writer confirms.
            return;
        }
        warn!(
            record_session_id,
            "record routine UIA worker exited unexpectedly; closing recording"
        );
        self.stop_recording_with_reason(record_session_id, RecordStopReason::Error);
    }

    #[cfg(windows)]
    fn request_manual_record_routine(&mut self) {
        self.spawn_record_request_dialog(None);
    }

    #[cfg(windows)]
    fn spawn_record_request_dialog(&mut self, request: Option<PendingRecordRequest>) {
        if self.privacy_action_in_progress.load(Ordering::SeqCst) {
            alert(
                DIALOG_TITLE_RECORD_ROUTINE,
                BODY_RECORD_BLOCKED_DURING_PRIVACY,
                AlertKind::Warning,
            );
            return;
        }
        if self
            .record_action_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!("record action already in progress");
            return;
        }
        if self
            .record_commands
            .prompt_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.record_action_in_progress
                .store(false, Ordering::SeqCst);
            info!("record prompt already in flight");
            return;
        }
        let commands = self.record_commands.writer_commands.clone();
        let ui_events = self.record_commands.ui_event_tx.clone();
        let pump_waker = self.record_commands.pump_waker;
        let record_action_in_progress = Arc::clone(&self.record_action_in_progress);
        let prompt_in_flight = Arc::clone(&self.record_commands.prompt_in_flight);
        let capture_paused_by_user = Arc::clone(&self.capture_paused_by_user);
        let config = self.config.clone();
        let controls = self.controls.clone();
        thread::spawn(move || {
            let _record_guard = FlagGuard::new(record_action_in_progress).and(prompt_in_flight);
            run_record_routine_dialogs_and_command(
                request,
                config,
                controls,
                commands,
                ui_events,
                pump_waker,
                capture_paused_by_user,
            );
        });
    }

    fn spawn_cap_prompt(&mut self, prompt: CapPrompt) {
        if self
            .record_commands
            .prompt_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!("record prompt already in flight");
            return;
        }
        let commands = self.record_commands.writer_commands.clone();
        let ui_events = self.record_commands.ui_event_tx.clone();
        let pump_waker = self.record_commands.pump_waker;
        let prompt_in_flight = Arc::clone(&self.record_commands.prompt_in_flight);
        thread::spawn(move || {
            let _prompt_guard = FlagGuard::new(prompt_in_flight);
            run_cap_prompt_and_command(prompt, commands, ui_events, pump_waker);
        });
    }

    #[cfg(windows)]
    fn stop_recording(&mut self) {
        let Some(record_session_id) = self.active_record_session_id else {
            return;
        };
        self.stop_recording_with_reason(record_session_id, RecordStopReason::UserStop);
    }

    fn stop_recording_with_reason(
        &mut self,
        record_session_id: i64,
        stop_reason: RecordStopReason,
    ) {
        if self.active_record_session_id != Some(record_session_id) {
            return;
        }
        if stop_reason == RecordStopReason::PanicHotkey {
            self.record_commands
                .panic_action_cutoff
                .arm(record_session_id, Instant::now());
            // Panic is a capture boundary, not a normal graceful stop. Freeze
            // both UIA lanes before asking the writer to drain/close so no
            // action observed after the keypress can enter that drain.
            self.stop_record_worker();
        }
        if self.record_stop_pending_session_id == Some(record_session_id) {
            return;
        }
        self.record_stop_pending_session_id = Some(record_session_id);
        // For ordinary stops, deliver before touching the worker: the worker
        // is killed by the Stopped/Failed handler once the writer confirms, so a stop can
        // never leave a dead worker behind with baseline capture suspended and
        // the tray still showing "recording" (B2). Actions the still-live
        // worker emits after the writer closes the session are dropped by the
        // writer's session-id stamp. PanicHotkey is the deliberate exception
        // above because its trust boundary requires an immediate freeze.
        self.spawn_stop_record_command(record_session_id, stop_reason);
    }

    #[cfg(windows)]
    fn start_record_worker(&mut self, record_session_id: i64, elevated_helper_requested: bool) {
        self.stop_record_worker();
        if elevated_helper_requested {
            let required_signer_sha256 = self
                .config
                .record
                .elevated_helper_required_signer_sha256
                .trim();
            let configured_helper_path = self.config.record.elevated_helper_path.trim();
            match elevated_record_helper::start(
                record_session_id,
                self.record_commands.writer_inputs.clone(),
                (!required_signer_sha256.is_empty()).then_some(required_signer_sha256),
                (!configured_helper_path.is_empty()).then_some(configured_helper_path),
                self.config.record.safety_cap_ms,
            ) {
                Ok(worker) => {
                    self.elevated_record_worker = Some(worker);
                    info!(record_session_id, "elevated record helper launched");
                    return;
                }
                Err(error) => {
                    warn!(
                        %error,
                        record_session_id,
                        "elevated record helper could not launch; falling back to standard capture"
                    );
                    alert(
                        DIALOG_TITLE_RECORD_ROUTINE,
                        BODY_ELEVATED_HELPER_FALLBACK,
                        AlertKind::Warning,
                    );
                }
            }
        }
        let config = RecordRoutineConfig::new(record_session_id);
        match start_record_routine_capture(config, self.record_commands.writer_inputs.clone()) {
            Ok(worker) => {
                self.record_worker = Some(worker);
                info!(record_session_id, "record routine UIA worker started");
            }
            Err(error) => {
                error!(%error, record_session_id, "record routine UIA worker failed to start");
                alert(
                    DIALOG_TITLE_RECORD_ROUTINE,
                    &format!("{BODY_UIA_START_FAILED_PREFIX}{error}"),
                    AlertKind::Warning,
                );
                // Must use the guaranteed stop lane: the start dialog thread
                // may still hold `record_action_in_progress` while this runs,
                // and a CAS-refused stop here would strand the open session
                // with no worker (the same wedge as B2).
                self.stop_recording_with_reason(record_session_id, RecordStopReason::Error);
            }
        }
    }

    #[cfg(windows)]
    fn stop_record_worker(&mut self) {
        if let Some(mut worker) = self.elevated_record_worker.take() {
            worker.stop();
            info!("elevated record helper stopped");
        }
        if let Some(mut worker) = self.record_worker.take() {
            worker.stop();
            info!("record routine UIA worker stopped");
        }
    }

    /// No workers exist off-Windows (Record Routine is Windows-only).
    #[cfg(not(windows))]
    fn stop_record_worker(&mut self) {}

    fn resume_baseline_capture_after_recording(&mut self) {
        if self.capture_paused_by_user.load(Ordering::SeqCst) {
            // Panic pause owns the suspension now. Consume Record Routine's
            // temporary ownership without re-enabling ambient capture.
            self.baseline_capture_suspended_for_recording = false;
            return;
        }
        if restore_baseline_capture_after_recording(
            &self.controls,
            self.baseline_capture_suspended_for_recording,
        ) {
            self.controls.request_title_redacted_reseed();
            self.record_commands.pump_waker.wake();
            info!("baseline capture resumed after Record Routine with title-redacted reseed");
        }
        self.baseline_capture_suspended_for_recording = false;
    }

    #[cfg(windows)]
    fn pause_recording(&mut self) {
        if self.recording_paused {
            return;
        }
        let Some(record_session_id) = self.active_record_session_id else {
            return;
        };
        if self.record_stop_pending_session_id == Some(record_session_id) {
            return;
        }
        self.spawn_simple_record_command(record_session_id, move |reply| {
            WriterCommand::PauseRecording {
                record_session_id,
                reply,
            }
        });
    }

    #[cfg(windows)]
    fn resume_recording(&mut self) {
        if !self.recording_paused {
            return;
        }
        let Some(record_session_id) = self.active_record_session_id else {
            return;
        };
        if self.record_stop_pending_session_id == Some(record_session_id) {
            return;
        }
        self.spawn_simple_record_command(record_session_id, move |reply| {
            WriterCommand::ResumeRecording {
                record_session_id,
                reply,
            }
        });
    }

    /// Pause/Resume lane: serialized by the shared `record_action_in_progress`
    /// CAS so at most one pause/resume round-trip is in flight. Stop must NOT
    /// go through here -- a Stop refused because a Pause reply is still in
    /// flight was silently dropped and wedged baseline capture off (B2); stops
    /// use `spawn_stop_record_command`.
    #[cfg(windows)]
    fn spawn_simple_record_command<F>(&mut self, record_session_id: i64, build: F)
    where
        F: FnOnce(Sender<Result<(), String>>) -> WriterCommand + Send + 'static,
    {
        if self
            .record_action_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!("record action already in progress");
            return;
        }
        let commands = self.record_commands.writer_commands.clone();
        let ui_events = self.record_commands.ui_event_tx.clone();
        let pump_waker = self.record_commands.pump_waker;
        let record_action_in_progress = Arc::clone(&self.record_action_in_progress);
        thread::spawn(move || {
            let _record_guard = FlagGuard::new(record_action_in_progress);
            deliver_record_command(&commands, &ui_events, pump_waker, record_session_id, build);
        });
    }

    /// Stop lane: no shared CAS, so delivery is guaranteed even while a
    /// Pause/Resume round-trip holds `record_action_in_progress`. Callers
    /// dedup per session via `record_stop_pending_session_id`, and the writer
    /// treats a stop for an already-closed session as an Err reply, which the
    /// stale-event filter drops.
    fn spawn_stop_record_command(&mut self, record_session_id: i64, stop_reason: RecordStopReason) {
        let commands = self.record_commands.writer_commands.clone();
        let ui_events = self.record_commands.ui_event_tx.clone();
        let pump_waker = self.record_commands.pump_waker;
        thread::spawn(move || {
            deliver_record_command(
                &commands,
                &ui_events,
                pump_waker,
                record_session_id,
                move |reply| WriterCommand::StopRecording {
                    record_session_id,
                    stop_reason,
                    reply,
                },
            );
        });
    }

    fn apply_recording_visual_state(&self) {
        let recording = self.active_record_session_id.is_some();
        let capture_paused_by_user = self.capture_paused_by_user.load(Ordering::SeqCst);
        #[cfg(windows)]
        self.archive_reset.set_enabled(!recording);
        self.erase_all_data.set_enabled(!recording);
        // The record items do not exist on macOS (Windows-only by decision
        // record); `recording` is permanently false there, so the icon and
        // tooltip below resolve to the plain capture states.
        #[cfg(windows)]
        {
            self.record_routine
                .set_enabled(!recording && !capture_paused_by_user);
            self.stop_recording.set_enabled(recording);
            self.pause_recording
                .set_enabled(recording && !self.recording_paused);
            self.resume_recording
                .set_enabled(recording && self.recording_paused);
        }

        self.pause_capture.set_text(if capture_paused_by_user {
            MENU_LABEL_RESUME_CAPTURE
        } else {
            MENU_LABEL_PAUSE_CAPTURE
        });

        let icon = if capture_paused_by_user {
            create_paused_recording_icon()
        } else if !recording {
            create_icon()
        } else if self.recording_paused {
            create_paused_recording_icon()
        } else {
            create_recording_icon()
        };
        match icon.and_then(|icon| self._icon.set_icon(Some(icon)).map_err(Into::into)) {
            Ok(()) => {
                // Re-assert template rendering after every icon swap on
                // macOS. Only the capture-paused and plain icons are
                // reachable here now that the record items are gone; the
                // recording icons stay unreachable on this platform.
                #[cfg(target_os = "macos")]
                self._icon.set_icon_as_template(true);
            }
            Err(error) => warn!(%error, "failed to update tray icon"),
        }
        let tooltip = if capture_paused_by_user {
            TOOLTIP_CAPTURE_PAUSED
        } else if !recording {
            TOOLTIP_DEFAULT
        } else if self.recording_paused {
            TOOLTIP_RECORDING_PAUSED
        } else {
            TOOLTIP_RECORDING
        };
        if let Err(error) = self._icon.set_tooltip(Some(tooltip)) {
            warn!(%error, "failed to update tray tooltip");
        }
    }
}

struct FlagGuard {
    flags: Vec<Arc<AtomicBool>>,
}

impl FlagGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flags: vec![flag] }
    }

    #[cfg(windows)]
    fn and(mut self, flag: Arc<AtomicBool>) -> Self {
        self.flags.push(flag);
        self
    }
}

impl Drop for FlagGuard {
    fn drop(&mut self) {
        for flag in &self.flags {
            flag.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn suspend_baseline_capture_for_recording(controls: &CaptureControls) -> bool {
    if controls.is_suspended() {
        false
    } else {
        controls.set_suspended(true);
        info!("baseline capture suspended for Record Routine");
        true
    }
}

fn restore_baseline_capture_after_recording(
    controls: &CaptureControls,
    suspended_for_recording: bool,
) -> bool {
    if suspended_for_recording {
        controls.set_suspended(false);
        true
    } else {
        false
    }
}

fn next_archive_path(archive_dir: &std::path::Path) -> PathBuf {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let git_sha = GIT_SHA.chars().take(12).collect::<String>();
    archive_dir.join(format!(
        "gilbreth-archive-{now_ms}-{git_sha}.{}",
        gilbreth_store::ARCHIVE_EXTENSION
    ))
}

/// Send one pause/resume/stop command to the writer and translate the reply
/// into the matching session-stamped `RecordUiEvent`. Shared by both command
/// lanes so the stamping cannot drift between them.
fn deliver_record_command<F>(
    commands: &Sender<WriterCommand>,
    ui_events: &Sender<RecordUiEvent>,
    pump_waker: PumpWaker,
    record_session_id: i64,
    build: F,
) where
    F: FnOnce(Sender<Result<(), String>>) -> WriterCommand,
{
    let (reply_tx, reply_rx) = bounded(1);
    let command = build(reply_tx);
    let event = match &command {
        WriterCommand::StopRecording { .. } => RecordUiEvent::Stopped { record_session_id },
        WriterCommand::PauseRecording { .. } => RecordUiEvent::Paused { record_session_id },
        WriterCommand::ResumeRecording { .. } => RecordUiEvent::Resumed { record_session_id },
        _ => unreachable!("simple record command"),
    };
    if let Err(error) = commands.send(command) {
        let _ = ui_events.send(RecordUiEvent::Failed {
            record_session_id: Some(record_session_id),
            message: format!("{RECORD_FAIL_COMMAND_WRITER_UNAVAILABLE}: {error}"),
        });
        pump_waker.wake();
        return;
    }
    match reply_rx.recv() {
        Ok(Ok(())) => {
            let _ = ui_events.send(event);
        }
        Ok(Err(error)) => {
            let _ = ui_events.send(RecordUiEvent::Failed {
                record_session_id: Some(record_session_id),
                message: format!("{RECORD_FAIL_COMMAND}: {error}"),
            });
        }
        Err(error) => {
            let _ = ui_events.send(RecordUiEvent::Failed {
                record_session_id: Some(record_session_id),
                message: format!("{RECORD_FAIL_COMMAND_NO_RESULT}: {error}"),
            });
        }
    }
    pump_waker.wake();
}

#[cfg(windows)]
fn run_record_routine_dialogs_and_command(
    request: Option<PendingRecordRequest>,
    config: AppConfig,
    controls: CaptureControls,
    commands: Sender<WriterCommand>,
    ui_events: Sender<RecordUiEvent>,
    pump_waker: PumpWaker,
    capture_paused_by_user: Arc<AtomicBool>,
) {
    let request_id = request.as_ref().map(|request| request.request_id);
    let candidate = request
        .as_ref()
        .map(candidate_label)
        .unwrap_or_else(|| "Manual recording".to_string());

    let Some(start_choice) =
        confirm_record_routine_start(&candidate, config.record.elevated_helper_enabled)
    else {
        if let Some(request_id) = request_id {
            let _ = commands.send(WriterCommand::DeclineRecordRequest { request_id });
        }
        pump_waker.wake();
        return;
    };

    // A panic pause may arrive while the native confirmation is open. Abort
    // before creating a writer session on that common edge; the Started-event
    // guard independently closes the narrower race after this check.
    if capture_paused_by_user.load(Ordering::SeqCst) {
        if let Some(request_id) = request_id {
            let _ = commands.send(WriterCommand::DeclineRecordRequest { request_id });
        }
        info!(
            "Record Routine start abandoned because ambient capture was paused during confirmation"
        );
        pump_waker.wake();
        return;
    }

    let (reply_tx, reply_rx) = bounded(1);
    let title = Some(candidate.clone());
    let safety_cap_ms = i64::try_from(config.record.safety_cap_ms.max(1)).unwrap_or(i64::MAX);
    let policy_snapshot_json =
        record_policy_snapshot_json(&config, start_choice.elevated_helper_requested);
    let baseline_capture_suspended = suspend_baseline_capture_for_recording(&controls);
    if let Err(error) = commands.send(WriterCommand::StartRecording {
        request_id,
        title,
        policy_snapshot_json,
        safety_cap_ms,
        // Always true: the recording indicator is unconditional (stealth mode is
        // never supported); the column remains for historical rows.
        visible_indicator: true,
        reply: reply_tx,
    }) {
        if restore_baseline_capture_after_recording(&controls, baseline_capture_suspended) {
            controls.request_reseed();
        }
        let _ = ui_events.send(RecordUiEvent::Failed {
            record_session_id: None,
            message: format!("{RECORD_FAIL_START_WRITER_UNAVAILABLE}: {error}"),
        });
        pump_waker.wake();
        return;
    }

    match reply_rx.recv() {
        Ok(Ok(record_session_id)) => {
            let _ = ui_events.send(RecordUiEvent::Started {
                record_session_id,
                elevated_helper_requested: start_choice.elevated_helper_requested,
                baseline_capture_suspended,
            });
        }
        Ok(Err(error)) => {
            if restore_baseline_capture_after_recording(&controls, baseline_capture_suspended) {
                controls.request_reseed();
            }
            let _ = ui_events.send(RecordUiEvent::Failed {
                record_session_id: None,
                message: format!("{RECORD_FAIL_START}: {error}"),
            });
        }
        Err(error) => {
            if restore_baseline_capture_after_recording(&controls, baseline_capture_suspended) {
                controls.request_reseed();
            }
            let _ = ui_events.send(RecordUiEvent::Failed {
                record_session_id: None,
                message: format!("{RECORD_FAIL_START_NO_RESULT}: {error}"),
            });
        }
    }
    pump_waker.wake();
}

fn run_cap_prompt_and_command(
    prompt: CapPrompt,
    commands: Sender<WriterCommand>,
    ui_events: Sender<RecordUiEvent>,
    pump_waker: PumpWaker,
) {
    if confirm_recording_cap_continue(prompt.safety_cap_ms) {
        if let Err(error) = commands.send(WriterCommand::ExtendCap {
            record_session_id: prompt.record_session_id,
        }) {
            let _ = ui_events.send(RecordUiEvent::Failed {
                record_session_id: Some(prompt.record_session_id),
                message: format!("{RECORD_FAIL_CAP_RESPONSE_UNSAVED}: {error}"),
            });
        }
        pump_waker.wake();
        return;
    }

    let _ = ui_events.send(RecordUiEvent::StopForSafetyCap(prompt.record_session_id));
    pump_waker.wake();
}

/// Record Routine does not exist off Windows, but a record request can still
/// arrive: `record_requests` rows survive in a database written by a Windows
/// build, and the writer surfaces them cross-platform.
///
/// Decline rather than drop. A dropped request keeps `status='requested'`, and
/// the writer clears `last_surfaced_request_id` whenever prompts go idle, so
/// silence re-surfaces the same request on every poll until its TTL expires.
/// `DeclineRecordRequest` is the same command the Windows dialog sends when
/// the user says no, so the row lands in the same terminal state.
#[cfg(not(windows))]
fn decline_unsupported_record_request(
    commands: &Sender<WriterCommand>,
    request: &PendingRecordRequest,
) {
    let request_id = request.request_id;
    debug!(
        request_id,
        "declining record request; Record Routine is Windows-only"
    );
    let _ = commands.send(WriterCommand::DeclineRecordRequest { request_id });
}

fn should_spawn_cap_prompt(
    active_record_session_id: Option<i64>,
    stop_pending_record_session_id: Option<i64>,
    prompt_record_session_id: i64,
) -> bool {
    active_record_session_id == Some(prompt_record_session_id)
        && stop_pending_record_session_id != Some(prompt_record_session_id)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordStartChoice {
    elevated_helper_requested: bool,
}

#[cfg(windows)]
fn confirm_record_routine_start(
    candidate: &str,
    elevated_helper_enabled: bool,
) -> Option<RecordStartChoice> {
    let first = confirm(
        DIALOG_TITLE_RECORD_ROUTINE,
        BODY_RECORD_START_EXPLANATION,
        AlertKind::Warning,
        ConfirmButtons::OkCancel,
        true,
    );
    if !first {
        return None;
    }

    let second = confirm(
        DIALOG_TITLE_RECORD_ROUTINE,
        &record_start_confirm_body(candidate),
        AlertKind::Warning,
        ConfirmButtons::YesNo,
        true,
    );
    if !second {
        return None;
    }

    let elevated_helper_requested = elevated_helper_enabled
        && confirm(
            DIALOG_TITLE_RECORD_ROUTINE,
            BODY_ELEVATED_HELPER_CONSENT,
            AlertKind::Warning,
            ConfirmButtons::YesNo,
            true,
        );

    Some(RecordStartChoice {
        elevated_helper_requested,
    })
}

/// The named-routine start confirmation (pure; the copy audit exercises
/// it with a fixture candidate).
#[cfg_attr(not(windows), allow(dead_code))]
fn record_start_confirm_body(candidate: &str) -> String {
    format!(
        "Start recording the routine \"{candidate}\" now? Choose Yes to begin recording, \
         or No to cancel. You can stop the recording at any time from the tray."
    )
}

/// The safety-cap keep-going prompt (pure; the copy audit exercises it
/// with fixture minutes).
fn recording_cap_body(minutes: i64) -> String {
    format!(
        "This recording has been running for about {minutes} minutes. Keep recording, \
         or stop and save it now? Choose Yes to keep recording for another {minutes} \
         minutes, or No to stop and save now."
    )
}

fn confirm_recording_cap_continue(safety_cap_ms: i64) -> bool {
    let minutes = (safety_cap_ms.max(1) as f64 / 60_000.0).round().max(1.0) as i64;
    confirm(
        DIALOG_TITLE_RECORD_ROUTINE,
        &recording_cap_body(minutes),
        AlertKind::Info,
        ConfirmButtons::YesNo,
        true,
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
fn candidate_label(request: &PendingRecordRequest) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(&request.candidate_json).ok();
    let raw = parsed
        .as_ref()
        .and_then(|value| value.get("title").and_then(serde_json::Value::as_str))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|value| value.get("category").and_then(serde_json::Value::as_str))
        })
        .or(request.candidate_kind.as_deref())
        .unwrap_or("Candidate routine");
    sanitize_candidate_label(raw)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sanitize_candidate_label(value: &str) -> String {
    const MAX_CHARS: usize = 256;
    let mut output = value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_CHARS)
        .collect::<String>();
    if output.trim().is_empty() {
        output = "Candidate routine".to_string();
    }
    output
}

#[cfg_attr(not(windows), allow(dead_code))]
fn record_policy_snapshot_json(config: &AppConfig, elevated_helper_requested: bool) -> String {
    serde_json::json!({
        "schema": "gilbreth.record_session.policy.v1",
        "value_free": true,
        "baseline_capture": {
            "suspended_during_recording": true,
            "reason": "record_routine_value_free"
        },
        "sensitive_suppression": config.privacy.sensitive_context_suppression,
        "redaction_posture": {
            "titles": !config.privacy.redact_titles_containing.is_empty(),
            "keys": !config.privacy.redact_keys_containing.is_empty()
        },
        "redactions_active_at_start": !config.privacy.redact_titles_containing.is_empty()
            || !config.privacy.redact_keys_containing.is_empty(),
        "excluded_apps": config::normalize_excluded_apps(&config.privacy.excluded_apps),
        "retention_days": config.privacy.retention_days,
        "trust_model": "os_anchored_v1",
        "iuiautomation6_available": false,
        "coalesce_events": false,
        "connection_recovery": true,
        "scroll_quiet_ms": 0,
        "include_selector_strings": false,
        "app_version": APP_VERSION,
        "schema_user_version": 6_i64,
        "storm_dropped_events": 0_i64,
        "paused_dropped_events": 0_i64,
        "capture_degraded": false,
        "elevated_helper": {
            "config_enabled": config.record.elevated_helper_enabled,
            "requested": elevated_helper_requested,
            "strategy": config.record.elevated_helper_strategy.as_str(),
            "value_free_ipc": true,
            "secure_desktop_capture": false,
            "automation_execution": false,
            "launch_result_recorded": false,
            "custom_helper_path_configured": !config
                .record
                .elevated_helper_path
                .trim()
                .is_empty(),
            "signer_sha256_required": !config
                .record
                .elevated_helper_required_signer_sha256
                .trim()
                .is_empty()
        },
        "windows_recorded": 0_i64,
        "framework_class_counts": {
            "native": 0_i64,
            "web_renderer": 0_i64,
            "virtualized": 0_i64
        }
    })
    .to_string()
}

fn restore_capture_after_privacy_operation(
    controls: &CaptureControls,
    capture_paused_by_user: &AtomicBool,
    manual_pause_at_start: bool,
    replacement_session_created: bool,
    capture_flush: &Sender<CaptureFlushReply>,
    writer_inputs: &Sender<WriterInput>,
    pump_waker: PumpWaker,
) {
    let paused = capture_paused_by_user.load(Ordering::SeqCst);
    if paused {
        controls.set_suspended(true);
        if !manual_pause_at_start || replacement_session_created {
            let captured =
                Captured::new(Source::System, Instant::now(), EventPayload::CapturePaused);
            if let Err(error) = writer_inputs.send(WriterInput::Motion(captured)) {
                error!(%error, "failed to re-emit capture pause after privacy operation");
            }
        }
    } else {
        let boundary = manual_pause_at_start.then_some(EventPayload::CaptureResumed);
        if let Err(error) = resume_capture_after_quiet(
            controls,
            capture_flush,
            writer_inputs,
            pump_waker,
            boundary,
            false,
        ) {
            error!(%error, "capture remains paused because the safe resume handshake did not complete");
            capture_paused_by_user.store(true, Ordering::SeqCst);
            controls.set_suspended(true);
            pump_waker.wake();
        }
    }
}

struct PrivacyOperationRuntime {
    controls: CaptureControls,
    commands: Sender<WriterCommand>,
    capture_flush: Sender<CaptureFlushReply>,
    pump_waker: PumpWaker,
    writer_inputs: Sender<WriterInput>,
    capture_paused_by_user: Arc<AtomicBool>,
    privacy_suspension_owned: Arc<AtomicBool>,
}

fn run_archive_reset_dialogs_and_command(
    archive_path: PathBuf,
    receipt_data_dir: PathBuf,
    runtime: PrivacyOperationRuntime,
) {
    let PrivacyOperationRuntime {
        controls,
        commands,
        capture_flush,
        pump_waker,
        writer_inputs,
        capture_paused_by_user,
        privacy_suspension_owned,
    } = runtime;
    if !confirm_archive_reset(&archive_path) {
        return;
    }

    let manual_pause_at_start = capture_paused_by_user.load(Ordering::SeqCst);
    privacy_suspension_owned.store(true, Ordering::SeqCst);
    let _suspension_guard = FlagGuard::new(privacy_suspension_owned);
    info!(archive_file = %log_file_name(&archive_path), "archive and reset confirmed; suspending capture");
    controls.set_suspended(true);
    if let Err(error) = flush_capture_forwarder(&capture_flush) {
        restore_capture_after_privacy_operation(
            &controls,
            &capture_paused_by_user,
            manual_pause_at_start,
            false,
            &capture_flush,
            &writer_inputs,
            pump_waker,
        );
        error!(%error, archive_file = %log_file_name(&archive_path), "archive and reset could not quiet the capture pipeline");
        let receipt_note = write_archive_reset_receipt(
            &receipt_data_dir,
            ArchiveResetOutcome::ArchiveFailed,
            "capture_pipeline",
        );
        alert(
            DIALOG_TITLE_ARCHIVE_RESET,
            &format!("{BODY_ARCHIVE_PIPELINE_NOT_QUIET}\n\n{receipt_note}"),
            AlertKind::Warning,
        );
        return;
    }
    let (reply_tx, reply_rx) = bounded(1);
    if let Err(error) = commands.send(WriterCommand::ArchiveAndReset {
        archive_path: archive_path.clone(),
        session_identity: replacement_session_identity(),
        reply: reply_tx,
    }) {
        restore_capture_after_privacy_operation(
            &controls,
            &capture_paused_by_user,
            manual_pause_at_start,
            false,
            &capture_flush,
            &writer_inputs,
            pump_waker,
        );
        error!(%error, archive_file = %log_file_name(&archive_path), "failed to send archive and reset command");
        let receipt_note = write_archive_reset_receipt(
            &receipt_data_dir,
            ArchiveResetOutcome::ArchiveFailed,
            "writer_unavailable",
        );
        alert(
            DIALOG_TITLE_ARCHIVE_RESET,
            &format!("{BODY_ARCHIVE_WRITER_UNAVAILABLE}\n\n{receipt_note}"),
            AlertKind::Warning,
        );
        return;
    }

    match reply_rx.recv() {
        Ok(report) => {
            let keep_suspended = report.outcome == ArchiveResetOutcome::ReplacementSessionFailed;
            if !keep_suspended {
                restore_capture_after_privacy_operation(
                    &controls,
                    &capture_paused_by_user,
                    manual_pause_at_start,
                    report.new_session_id.is_some(),
                    &capture_flush,
                    &writer_inputs,
                    pump_waker,
                );
            }
            let receipt_note =
                write_archive_reset_receipt(&receipt_data_dir, report.outcome, "operation_result");
            show_archive_reset_report(
                &report,
                keep_suspended,
                capture_paused_by_user.load(Ordering::SeqCst),
                &receipt_note,
            );
        }
        Err(error) => {
            restore_capture_after_privacy_operation(
                &controls,
                &capture_paused_by_user,
                manual_pause_at_start,
                false,
                &capture_flush,
                &writer_inputs,
                pump_waker,
            );
            error!(%error, archive_path = %archive_path.display(), "archive and reset command did not return a report");
            let receipt_note = write_archive_reset_receipt(
                &receipt_data_dir,
                ArchiveResetOutcome::ArchiveFailed,
                "missing_writer_reply",
            );
            alert(
                DIALOG_TITLE_ARCHIVE_RESET,
                &format!("{BODY_ARCHIVE_NO_REPORT}\n\n{receipt_note}"),
                AlertKind::Warning,
            );
        }
    }
}

/// The first archive-and-reset confirmation (pure; the copy audit
/// exercises it with a fixture path).
fn archive_reset_confirm_body(archive_path: &std::path::Path) -> String {
    format!(
        "Archive the current activity database, then reset the live database for a \
         fresh run?\n\nArchive target:\n{}\n\nThe archive is encrypted to this Windows \
         account. If this Windows profile is lost, the archive is not recoverable; \
         make a separate portable export for anything that must outlive it.",
        archive_path.display()
    )
}

fn confirm_archive_reset(archive_path: &std::path::Path) -> bool {
    let first = confirm(
        DIALOG_TITLE_ARCHIVE_RESET,
        &archive_reset_confirm_body(archive_path),
        AlertKind::Warning,
        ConfirmButtons::OkCancel,
        false,
    );
    if !first {
        return false;
    }

    confirm(
        DIALOG_TITLE_ARCHIVE_RESET,
        BODY_ARCHIVE_RESET_FINAL_CONFIRM,
        AlertKind::Warning,
        ConfirmButtons::YesNo,
        false,
    )
}

fn write_archive_reset_receipt(
    data_dir: &Path,
    outcome: ArchiveResetOutcome,
    error_category: &'static str,
) -> String {
    use privacy_receipt::{PrivacyOperation, PrivacyReceipt, ReceiptClass, ReceiptOutcome};

    let archive_outcome = if outcome == ArchiveResetOutcome::ArchiveFailed {
        ReceiptOutcome::NeedsRetry
    } else {
        ReceiptOutcome::Copied
    };
    let activity_outcome = match outcome {
        ArchiveResetOutcome::Completed
        | ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        | ArchiveResetOutcome::ReplacementSessionFailed => ReceiptOutcome::Removed,
        ArchiveResetOutcome::ArchiveFailed | ArchiveResetOutcome::DeleteFailed => {
            ReceiptOutcome::Retained
        }
    };
    let archive_inventory = gilbreth_store::inventory_archives(&data_dir.join("archives"));
    let config_path = config::config_path(data_dir);
    let sphere_sidecar = config::spheres_sidecar_path(&config_path);
    let sphere_alias_files = count_specific_files([
        sphere_sidecar.clone(),
        sphere_sidecar.with_extension("json.tmp"),
    ]);
    let control_state_sidecars = count_control_state_sidecars(data_dir);
    let diagnostic_logs = count_regular_files(&data_dir.join("logs"));
    let mut classes = vec![
        ReceiptClass::new("encrypted_archive", archive_outcome).with_count(1),
        ReceiptClass::new("live_activity", activity_outcome).with_count(1),
        ReceiptClass::new("configuration", ReceiptOutcome::Retained).with_count(1),
        retained_inventory_class("working_sphere_alias_files", sphere_alias_files),
        retained_inventory_class("control_state_sidecars", control_state_sidecars),
        retained_inventory_class("diagnostic_logs", diagnostic_logs),
        ReceiptClass::new("portable_exports", ReceiptOutcome::Retained),
    ];
    match archive_inventory {
        Ok(inventory) => {
            classes.push(
                ReceiptClass::new("other_sealed_archives", ReceiptOutcome::Retained).with_count(
                    inventory
                        .encrypted
                        .len()
                        .saturating_sub(usize::from(archive_outcome == ReceiptOutcome::Copied)),
                ),
            );
            classes.push(
                ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::Retained)
                    .with_count(inventory.plaintext_legacy.len()),
            );
        }
        Err(_) => classes.push(
            ReceiptClass::new("archive_inventory", ReceiptOutcome::NeedsRetry)
                .with_error_category("inventory_failed"),
        ),
    }
    if outcome == ArchiveResetOutcome::DeleteCommittedScrubIncomplete {
        classes.push(
            ReceiptClass::new("live_database_scrub", ReceiptOutcome::NeedsRetry)
                .with_count(1)
                .with_error_category(error_category),
        );
    }
    if outcome == ArchiveResetOutcome::ReplacementSessionFailed {
        classes.push(
            ReceiptClass::new("recording_resume", ReceiptOutcome::NeedsRetry)
                .with_count(1)
                .with_error_category(error_category),
        );
    }
    if outcome == ArchiveResetOutcome::ArchiveFailed {
        classes[0].error_category = Some(error_category.to_string());
    }
    let receipt = PrivacyReceipt::new(PrivacyOperation::ArchiveReset, classes);
    let summary = receipt.summary();
    receipt_note_for_dialog(privacy_receipt::write_receipt(data_dir, &receipt), &summary)
}

/// The dialog line pointing at the written content-free receipt, or
/// saying the receipt write itself needs retry. Shared by every
/// privacy-operation dialog; the receipt summary lines are class/outcome
/// data notation from `privacy_receipt`, not authored prose.
fn receipt_note_for_dialog(write_result: Result<PathBuf, String>, summary: &str) -> String {
    match write_result {
        Ok(path) => format!("{RECEIPT_NOTE_PREFIX}{}\n{summary}", path.display()),
        Err(error) => format!("{RECEIPT_NOTE_PREFIX}needs retry ({error})\n{summary}"),
    }
}

/// The archive-and-reset outcome dialog body (pure; the copy audit
/// exercises every outcome with fixture reports).
fn archive_reset_report_message(
    report: &ArchiveResetReport,
    keep_suspended: bool,
    capture_paused_by_user: bool,
    receipt_note: &str,
) -> String {
    let archive = report
        .archive_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ARCHIVE_LOCATION_UNAVAILABLE.to_string());
    let mut message = match report.outcome {
        ArchiveResetOutcome::Completed => format!(
            "Archive and reset completed.\n\nArchive:\n{}\n\nArchived {} events across \
             {} sessions. The replacement recording session is {}.",
            archive,
            report.events_archived,
            report.sessions_archived,
            report.new_session_id.unwrap_or_default()
        ),
        ArchiveResetOutcome::ArchiveFailed => format!(
            "Archive failed before any live data was deleted.\n\nTarget:\n{}\n\n{}",
            archive,
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
        ArchiveResetOutcome::DeleteFailed => format!(
            "Archive completed, but live reset failed before deleting data. The \
             original database is still active.\n\nArchive:\n{}\n\n{}",
            archive,
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
        ArchiveResetOutcome::DeleteCommittedScrubIncomplete => format!(
            "Archive completed and your activity was deleted. The replacement recording \
             session is {}, but the secure wipe couldn't fully finish after waiting for \
             the database.\n\nArchive:\n{}\n\nClose the dashboard and use Privacy > \
             Erase all my data... to retry the secure wipe if needed.\n\n{}",
            report.new_session_id.unwrap_or_default(),
            archive,
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
        ArchiveResetOutcome::ReplacementSessionFailed => format!(
            "Archive completed and your activity was deleted, but Gilbreth couldn't \
             create a fresh recording session. Capture remains suspended; restart \
             Gilbreth before recording resumes.\n\nArchive:\n{}\n\n{}",
            archive,
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
    };
    if !keep_suspended {
        message.push_str("\n\n");
        message.push_str(if capture_paused_by_user {
            CAPTURE_STILL_PAUSED_NOTE
        } else {
            CAPTURE_RESUMED_NOTE
        });
    }
    if let Some(encryption) = &report.archive_encryption {
        message.push_str("\n\n");
        message.push_str(encryption.summary);
        message.push('\n');
        message.push_str(encryption.durability_notice);
    }
    message.push_str("\n\n");
    message.push_str(receipt_note);
    message
}

fn show_archive_reset_report(
    report: &ArchiveResetReport,
    keep_suspended: bool,
    capture_paused_by_user: bool,
    receipt_note: &str,
) {
    let message =
        archive_reset_report_message(report, keep_suspended, capture_paused_by_user, receipt_note);
    let kind = if keep_suspended || report.outcome != ArchiveResetOutcome::Completed {
        AlertKind::Warning
    } else {
        AlertKind::Info
    };
    alert(DIALOG_TITLE_ARCHIVE_RESET, &message, kind);
}

/// Secure removal of the Working Spheres alias sidecar. It holds user-typed
/// sphere renames that can encode window-title content, so "Erase all my
/// data" must take it too — it lives beside config.toml, outside the
/// activity DB the writer wipes. Covers both the canonical `spheres.json`
/// and the dashboard's `spheres.json.tmp` staging file (a crash mid-write
/// can leave the same title-derived payload in the temp path). Overwrite
/// bytes are best-effort on modern journaling/SSD storage, but *removal* is
/// load-bearing: a file that survives (e.g. a dashboard reader still holds it
/// open, so Windows refuses the delete) is returned as an error the erase
/// dialog must surface — a silent warn! reads as a completed wipe (S4).
fn secure_erase_spheres_sidecar(config_path: &Path) -> Result<(), String> {
    let sidecar = config::spheres_sidecar_path(config_path);
    let staged = sidecar.with_extension("json.tmp");
    let mut failures = Vec::new();
    for path in [&sidecar, &staged] {
        let label = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("spheres.json");
        match scrub_and_remove_file(path) {
            Ok(true) => info!(
                file = label,
                "secure erase removed a Working Spheres alias file"
            ),
            Ok(false) => {}
            Err(error) => {
                warn!(%error, file = label, "secure erase could not remove a Working Spheres alias file");
                failures.push(format!("{label} ({error})"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "The Working Spheres name file could not be removed: {}. It can contain \
             window-title-derived names. Close the dashboard, then delete the file next \
             to config.toml to complete the wipe.",
            failures.join(", ")
        ))
    }
}

fn count_existing_spheres_sidecars(config_path: &Path) -> usize {
    let sidecar = config::spheres_sidecar_path(config_path);
    [sidecar.clone(), sidecar.with_extension("json.tmp")]
        .into_iter()
        .filter(|path| path.is_file())
        .count()
}

fn count_regular_files(directory: &Path) -> Result<usize, String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err("inventory_failed".to_string()),
    };
    let mut count = 0;
    for entry in entries {
        let entry = entry.map_err(|_| "inventory_failed".to_string())?;
        if entry
            .file_type()
            .map_err(|_| "inventory_failed".to_string())?
            .is_file()
        {
            count += 1;
        }
    }
    Ok(count)
}

fn count_control_state_sidecars(data_dir: &Path) -> Result<usize, String> {
    let config_path = config::config_path(data_dir);
    let base_paths = [
        config::discovery_notice_state_sidecar_path(&config_path),
        permissions::state_sidecar_path(&config_path),
        permissions::request_sidecar_path(&config_path),
        hotkey::status_sidecar_path(&config_path),
        notification_consent::sidecar_path(data_dir),
    ];
    let mut candidates = std::collections::BTreeSet::new();
    for path in base_paths {
        candidates.insert(path.clone());
        candidates.insert(path.with_extension("tmp"));
        candidates.insert(path.with_extension("json.tmp"));
    }
    count_specific_files(candidates)
}

fn count_specific_files(paths: impl IntoIterator<Item = PathBuf>) -> Result<usize, String> {
    let mut count = 0;
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => count += 1,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("inventory_failed".to_string()),
        }
    }
    Ok(count)
}

fn retained_inventory_class(
    class: &'static str,
    count: Result<usize, String>,
) -> privacy_receipt::ReceiptClass {
    match count {
        Ok(count) => {
            privacy_receipt::ReceiptClass::new(class, privacy_receipt::ReceiptOutcome::Retained)
                .with_count(count)
        }
        Err(category) => {
            privacy_receipt::ReceiptClass::new(class, privacy_receipt::ReceiptOutcome::NeedsRetry)
                .with_error_category(category)
        }
    }
}

fn remove_archives_for_secure_erase(
    data_dir: &Path,
) -> (Vec<privacy_receipt::ReceiptClass>, Vec<String>, bool) {
    use privacy_receipt::{ReceiptClass, ReceiptOutcome};

    let directory = data_dir.join("archives");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (
                vec![
                    ReceiptClass::new("sealed_archives", ReceiptOutcome::Removed),
                    ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::Removed),
                    ReceiptClass::new("archive_staging_artifacts", ReceiptOutcome::Removed),
                ],
                Vec::new(),
                false,
            )
        }
        Err(error) => {
            return (
                vec![
                    ReceiptClass::new("sealed_archives", ReceiptOutcome::NeedsRetry)
                        .with_error_category("archive_directory_unreadable"),
                    ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::NeedsRetry)
                        .with_error_category("archive_directory_unreadable"),
                    ReceiptClass::new("archive_staging_artifacts", ReceiptOutcome::NeedsRetry)
                        .with_error_category("archive_directory_unreadable"),
                ],
                vec![format!("Archive removal needs retry: {error}")],
                true,
            )
        }
    };
    let mut sealed_removed = 0;
    let mut sealed_retry = 0;
    let mut plaintext_removed = 0;
    let mut plaintext_retry = 0;
    let mut staging_removed = 0;
    let mut staging_retry = 0;
    let mut retained = 0;
    let mut inventory_retry = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory_retry += 1;
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(class) = archive_erase_class(&name) else {
            retained += 1;
            continue;
        };
        match scrub_and_remove_file(&path) {
            Ok(_) if class == ArchiveEraseClass::Sealed => sealed_removed += 1,
            Ok(_) if class == ArchiveEraseClass::PlaintextEra => plaintext_removed += 1,
            Ok(_) => staging_removed += 1,
            Err(_) if class == ArchiveEraseClass::Sealed => sealed_retry += 1,
            Err(_) if class == ArchiveEraseClass::PlaintextEra => plaintext_retry += 1,
            Err(_) => staging_retry += 1,
        }
    }
    let mut classes = vec![
        ReceiptClass::new("sealed_archives", ReceiptOutcome::Removed).with_count(sealed_removed),
        ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::Removed)
            .with_count(plaintext_removed),
        ReceiptClass::new("archive_staging_artifacts", ReceiptOutcome::Removed)
            .with_count(staging_removed),
        ReceiptClass::new(
            "unrecognized_archive_directory_entries",
            ReceiptOutcome::Retained,
        )
        .with_count(retained),
    ];
    if sealed_retry > 0 {
        classes.push(
            ReceiptClass::new("sealed_archives", ReceiptOutcome::NeedsRetry)
                .with_count(sealed_retry)
                .with_error_category("remove_failed"),
        );
    }
    if plaintext_retry > 0 {
        classes.push(
            ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::NeedsRetry)
                .with_count(plaintext_retry)
                .with_error_category("remove_failed"),
        );
    }
    if staging_retry > 0 {
        classes.push(
            ReceiptClass::new("archive_staging_artifacts", ReceiptOutcome::NeedsRetry)
                .with_count(staging_retry)
                .with_error_category("remove_failed"),
        );
    }
    if inventory_retry > 0 {
        classes.push(
            ReceiptClass::new("archive_directory_entries", ReceiptOutcome::NeedsRetry)
                .with_count(inventory_retry)
                .with_error_category("inventory_failed"),
        );
    }
    let retry = sealed_retry + plaintext_retry + staging_retry + inventory_retry > 0;
    let notes = if retry {
        vec![format!(
            "Archive removal needs retry: {} sealed, {} plaintext-era, {} staging, and {} unreadable archive-directory item(s) could not be completed.",
            sealed_retry, plaintext_retry, staging_retry, inventory_retry
        )]
    } else {
        Vec::new()
    };
    (classes, notes, retry)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveEraseClass {
    Sealed,
    PlaintextEra,
    Staging,
}

fn archive_erase_class(name: &str) -> Option<ArchiveEraseClass> {
    if name.starts_with("gilbreth-archive-")
        && name.ends_with(&format!(".{}", gilbreth_store::ARCHIVE_EXTENSION))
    {
        return Some(ArchiveEraseClass::Sealed);
    }
    if name.starts_with("gilbreth-archive-") && name.ends_with(".db") {
        return Some(ArchiveEraseClass::PlaintextEra);
    }
    if is_generated_archive_staging_name(name) {
        return Some(ArchiveEraseClass::Staging);
    }
    None
}

/// Match only the crash-leftover names emitted by `archive_activity_to`:
/// `.<final .gla name>.<UUID>.plaintext.db`, its SQLite WAL/SHM/journal
/// siblings, and the corresponding `.pending`.
/// Requiring the complete shape keeps unrelated hidden files in the archive
/// directory outside Secure Erase's ownership boundary.
fn is_generated_archive_staging_name(name: &str) -> bool {
    let stem = [
        ".plaintext.db",
        ".plaintext.db-wal",
        ".plaintext.db-shm",
        ".plaintext.db-journal",
        ".pending",
    ]
    .into_iter()
    .find_map(|suffix| name.strip_suffix(suffix));
    let Some((archive_name, unique)) = stem.and_then(|value| value.rsplit_once('.')) else {
        return false;
    };
    archive_name.starts_with(".gilbreth-archive-")
        && archive_name.ends_with(&format!(".{}", gilbreth_store::ARCHIVE_EXTENSION))
        && uuid::Uuid::parse_str(unique).is_ok()
}

/// File name only, for log lines: DB/archive paths carry user directories
/// (usernames, client folders), which retained logs must not (S7).
fn log_file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<none>".to_string())
}

/// Best-effort removal of the rotated log files after the user opts in
/// during secure erase (S7). Returns `(removed, kept)`: the active file is
/// held open by this process's appender, so Windows refuses its deletion —
/// callers surface the kept count so the wipe report stays honest.
fn clear_logs_best_effort() -> (usize, usize) {
    let Ok(local_data_dir) = local_data_dir() else {
        return (0, 0);
    };
    let Ok(entries) = std::fs::read_dir(local_data_dir.join("logs")) else {
        return (0, 0);
    };
    let mut removed = 0usize;
    let mut kept = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(_) => kept += 1,
        }
    }
    info!(removed, kept, "secure erase cleared diagnostic logs");
    (removed, kept)
}

/// Zero-fill then remove one file. `Ok(false)` means it was already absent.
fn scrub_and_remove_file(path: &Path) -> std::io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to scrub a link or non-file",
        ));
    }
    let mut remaining = metadata.len();
    if remaining > 0 {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let zeros = [0_u8; 64 * 1024];
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn write_secure_erase_receipt(
    data_dir: &Path,
    outcome: Option<SecureEraseOutcome>,
    mut archive_classes: Vec<privacy_receipt::ReceiptClass>,
    sidecars_before: usize,
    sidecars_after: usize,
    sidecar_failed: bool,
    clear_logs: bool,
    logs: (usize, usize),
) -> String {
    use privacy_receipt::{PrivacyOperation, PrivacyReceipt, ReceiptClass, ReceiptOutcome};

    let live_outcome = match outcome {
        Some(
            SecureEraseOutcome::Completed
            | SecureEraseOutcome::DeleteCommittedScrubIncomplete
            | SecureEraseOutcome::ReplacementSessionFailed,
        ) => ReceiptOutcome::Removed,
        Some(SecureEraseOutcome::DeleteFailed) => ReceiptOutcome::Retained,
        None => ReceiptOutcome::NeedsRetry,
    };
    let mut classes = vec![
        ReceiptClass::new("live_database_activity", live_outcome).with_count(1),
        ReceiptClass::new("configuration", ReceiptOutcome::Retained).with_count(1),
        ReceiptClass::new("working_sphere_alias_files", ReceiptOutcome::Removed)
            .with_count(sidecars_before.saturating_sub(sidecars_after)),
        retained_inventory_class(
            "control_state_sidecars",
            count_control_state_sidecars(data_dir),
        ),
    ];
    if sidecar_failed || sidecars_after > 0 {
        classes.push(
            ReceiptClass::new("working_sphere_alias_files", ReceiptOutcome::NeedsRetry)
                .with_count(sidecars_after)
                .with_error_category("remove_failed"),
        );
    }
    if clear_logs {
        classes
            .push(ReceiptClass::new("diagnostic_logs", ReceiptOutcome::Removed).with_count(logs.0));
        if logs.1 > 0 {
            classes.push(
                ReceiptClass::new("diagnostic_logs", ReceiptOutcome::NeedsRetry)
                    .with_count(logs.1)
                    .with_error_category("active_or_locked"),
            );
        }
    } else {
        classes.push(retained_inventory_class(
            "diagnostic_logs",
            count_regular_files(&data_dir.join("logs")),
        ));
    }
    if matches!(
        outcome,
        Some(SecureEraseOutcome::DeleteCommittedScrubIncomplete)
    ) {
        classes.push(
            ReceiptClass::new("sqlite_storage_scrub", ReceiptOutcome::NeedsRetry)
                .with_count(1)
                .with_error_category("scrub_incomplete"),
        );
    }
    if matches!(outcome, Some(SecureEraseOutcome::ReplacementSessionFailed)) {
        classes.push(
            ReceiptClass::new("recording_resume", ReceiptOutcome::NeedsRetry)
                .with_count(1)
                .with_error_category("replacement_session_failed"),
        );
    }
    classes.append(&mut archive_classes);
    classes.push(ReceiptClass::new(
        "portable_exports_outside_data_root",
        ReceiptOutcome::Retained,
    ));
    classes.push(retained_inventory_class(
        "prior_content_free_receipts",
        count_regular_files(&data_dir.join(privacy_receipt::RECEIPT_DIRECTORY)),
    ));
    let receipt = PrivacyReceipt::new(PrivacyOperation::SecureErase, classes);
    let summary = receipt.summary();
    receipt_note_for_dialog(privacy_receipt::write_receipt(data_dir, &receipt), &summary)
}

fn write_secure_erase_not_started_receipt(data_dir: &Path, error_category: &'static str) -> String {
    use privacy_receipt::{PrivacyOperation, PrivacyReceipt, ReceiptClass, ReceiptOutcome};

    let archives = gilbreth_store::inventory_archives(&data_dir.join("archives"));
    let config_path = config::config_path(data_dir);
    let sphere_sidecar = config::spheres_sidecar_path(&config_path);
    let sidecars = count_specific_files([
        sphere_sidecar.clone(),
        sphere_sidecar.with_extension("json.tmp"),
    ]);
    let logs = count_regular_files(&data_dir.join("logs"));
    let mut classes = vec![
        ReceiptClass::new("secure_erase_operation", ReceiptOutcome::NeedsRetry)
            .with_count(1)
            .with_error_category(error_category),
        ReceiptClass::new("live_database_activity", ReceiptOutcome::Retained).with_count(1),
        ReceiptClass::new("configuration", ReceiptOutcome::Retained).with_count(1),
        retained_inventory_class("working_sphere_alias_files", sidecars),
        retained_inventory_class(
            "control_state_sidecars",
            count_control_state_sidecars(data_dir),
        ),
        retained_inventory_class("diagnostic_logs", logs),
        ReceiptClass::new(
            "portable_exports_outside_data_root",
            ReceiptOutcome::Retained,
        ),
    ];
    match archives {
        Ok(inventory) => {
            classes.push(
                ReceiptClass::new("sealed_archives", ReceiptOutcome::Retained)
                    .with_count(inventory.encrypted.len()),
            );
            classes.push(
                ReceiptClass::new("plaintext_era_archives", ReceiptOutcome::Retained)
                    .with_count(inventory.plaintext_legacy.len()),
            );
        }
        Err(_) => classes.push(
            ReceiptClass::new("archive_inventory", ReceiptOutcome::NeedsRetry)
                .with_error_category("inventory_failed"),
        ),
    }
    let receipt = PrivacyReceipt::new(PrivacyOperation::SecureErase, classes);
    let summary = receipt.summary();
    receipt_note_for_dialog(privacy_receipt::write_receipt(data_dir, &receipt), &summary)
}

fn run_secure_erase_dialogs_and_command(config_path: PathBuf, runtime: PrivacyOperationRuntime) {
    let PrivacyOperationRuntime {
        controls,
        commands,
        capture_flush,
        pump_waker,
        writer_inputs,
        capture_paused_by_user,
        privacy_suspension_owned,
    } = runtime;
    let Some(choices) = confirm_secure_erase() else {
        return;
    };

    let manual_pause_at_start = capture_paused_by_user.load(Ordering::SeqCst);
    privacy_suspension_owned.store(true, Ordering::SeqCst);
    let _suspension_guard = FlagGuard::new(privacy_suspension_owned);
    info!("secure erase confirmed; suspending capture");
    controls.set_suspended(true);
    if let Err(error) = flush_capture_forwarder(&capture_flush) {
        restore_capture_after_privacy_operation(
            &controls,
            &capture_paused_by_user,
            manual_pause_at_start,
            false,
            &capture_flush,
            &writer_inputs,
            pump_waker,
        );
        error!(%error, "secure erase could not quiet the capture pipeline");
        let receipt_note = write_secure_erase_not_started_receipt(
            config_path.parent().unwrap_or(&config_path),
            "capture_pipeline",
        );
        alert(
            DIALOG_TITLE_SECURE_ERASE,
            &format!("{BODY_SECURE_ERASE_PIPELINE_NOT_QUIET}\n\n{receipt_note}"),
            AlertKind::Warning,
        );
        return;
    }
    let (reply_tx, reply_rx) = bounded(1);
    if let Err(error) = commands.send(WriterCommand::SecureErase {
        session_identity: replacement_session_identity(),
        reply: reply_tx,
    }) {
        restore_capture_after_privacy_operation(
            &controls,
            &capture_paused_by_user,
            manual_pause_at_start,
            false,
            &capture_flush,
            &writer_inputs,
            pump_waker,
        );
        error!(%error, "failed to send secure erase command");
        let receipt_note = write_secure_erase_not_started_receipt(
            config_path.parent().unwrap_or(&config_path),
            "writer_unavailable",
        );
        alert(
            DIALOG_TITLE_SECURE_ERASE,
            &format!("{BODY_SECURE_ERASE_WRITER_UNAVAILABLE}\n\n{receipt_note}"),
            AlertKind::Warning,
        );
        return;
    }

    match reply_rx.recv() {
        Ok(report) => {
            let mut extra_notes = Vec::new();
            let mut extra_warn = false;
            let data_dir = config_path.parent().unwrap_or(&config_path);
            let sidecars_before = count_existing_spheres_sidecars(&config_path);
            let sidecar_result = secure_erase_spheres_sidecar(&config_path);
            let sidecars_after = count_existing_spheres_sidecars(&config_path);
            if let Err(sidecar_error) = &sidecar_result {
                extra_warn = true;
                extra_notes.push(sidecar_error.clone());
            }
            let (archive_classes, archive_notes, archive_warn) =
                remove_archives_for_secure_erase(data_dir);
            extra_warn |= archive_warn;
            extra_notes.extend(archive_notes);
            let logs = if choices.clear_logs {
                let logs = clear_logs_best_effort();
                extra_notes.push(describe_log_clearing(logs));
                logs
            } else {
                (0, 0)
            };
            let receipt_note = write_secure_erase_receipt(
                data_dir,
                Some(report.outcome),
                archive_classes,
                sidecars_before,
                sidecars_after,
                sidecar_result.is_err(),
                choices.clear_logs,
                logs,
            );
            let keep_suspended = report.outcome == SecureEraseOutcome::ReplacementSessionFailed;
            if !keep_suspended {
                restore_capture_after_privacy_operation(
                    &controls,
                    &capture_paused_by_user,
                    manual_pause_at_start,
                    report.new_session_id.is_some(),
                    &capture_flush,
                    &writer_inputs,
                    pump_waker,
                );
            }
            show_secure_erase_report(
                &report,
                keep_suspended,
                capture_paused_by_user.load(Ordering::SeqCst),
                &extra_notes,
                extra_warn,
                &receipt_note,
            );
        }
        Err(error) => {
            // The writer wipes the DB before it replies, so a lost reply
            // almost certainly means the wipe happened; take the sidecar
            // (and opted-in logs) too rather than leave title-derived
            // aliases beside an erased DB.
            let data_dir = config_path.parent().unwrap_or(&config_path);
            let sidecars_before = count_existing_spheres_sidecars(&config_path);
            let sidecar_error = secure_erase_spheres_sidecar(&config_path).err();
            let sidecars_after = count_existing_spheres_sidecars(&config_path);
            let (archive_classes, archive_notes, _) = remove_archives_for_secure_erase(data_dir);
            let logs = if choices.clear_logs {
                clear_logs_best_effort()
            } else {
                (0, 0)
            };
            let log_note = choices.clear_logs.then(|| describe_log_clearing(logs));
            let receipt_note = write_secure_erase_receipt(
                data_dir,
                None,
                archive_classes,
                sidecars_before,
                sidecars_after,
                sidecar_error.is_some(),
                choices.clear_logs,
                logs,
            );
            restore_capture_after_privacy_operation(
                &controls,
                &capture_paused_by_user,
                manual_pause_at_start,
                false,
                &capture_flush,
                &writer_inputs,
                pump_waker,
            );
            error!(%error, "secure erase command did not return a report");
            let mut message = String::from(BODY_SECURE_ERASE_NO_REPORT);
            for note in sidecar_error
                .iter()
                .chain(log_note.iter())
                .chain(archive_notes.iter())
            {
                message.push_str("\n\n");
                message.push_str(note);
            }
            message.push_str("\n\n");
            message.push_str(&receipt_note);
            alert(DIALOG_TITLE_SECURE_ERASE, &message, AlertKind::Warning);
        }
    }
}

/// User-facing summary of the opt-in log wipe. The active log file stays
/// held open by the running appender, so a nonzero kept count is expected
/// and must be said plainly rather than implying a complete wipe.
fn describe_log_clearing((removed, kept): (usize, usize)) -> String {
    if kept == 0 {
        format!("Deleted {removed} diagnostic log file(s).")
    } else {
        format!(
            "Deleted {removed} diagnostic log file(s); {kept} could not be removed \
             (today's active log stays in use while Gilbreth is running). To finish, \
             quit Gilbreth and delete the logs folder next to the database."
        )
    }
}

/// What the user opted into alongside the activity wipe.
struct SecureEraseChoices {
    clear_logs: bool,
}

/// The secure-erase final confirmation (pure; the copy audit exercises
/// both scopes).
fn secure_erase_final_confirm_body(clear_logs: bool) -> String {
    let scope = if clear_logs {
        SECURE_ERASE_SCOPE_WITH_LOGS
    } else {
        SECURE_ERASE_SCOPE_WITHOUT_LOGS
    };
    format!("Final confirmation: {scope}, and start a fresh recording session?")
}

fn confirm_secure_erase() -> Option<SecureEraseChoices> {
    let first = confirm(
        DIALOG_TITLE_SECURE_ERASE,
        secure_erase_scope_confirmation(),
        AlertKind::Warning,
        ConfirmButtons::OkCancel,
        false,
    );
    if !first {
        return None;
    }

    let clear_logs = confirm(
        DIALOG_TITLE_SECURE_ERASE,
        BODY_SECURE_ERASE_CLEAR_LOGS_QUESTION,
        AlertKind::Warning,
        ConfirmButtons::YesNo,
        false,
    );

    let second = confirm(
        DIALOG_TITLE_SECURE_ERASE,
        &secure_erase_final_confirm_body(clear_logs),
        AlertKind::Warning,
        ConfirmButtons::YesNo,
        false,
    );
    second.then_some(SecureEraseChoices { clear_logs })
}

#[cfg(windows)]
fn secure_erase_scope_confirmation() -> &'static str {
    "Erases all Gilbreth activity data on this machine for this Windows user. This includes the live database, sealed and plaintext-era archives, and privacy sidecars. Capture in flight during the erase is discarded. Settings and portable exports outside Gilbreth's data folder are kept. This can't be undone."
}

#[cfg(target_os = "macos")]
fn secure_erase_scope_confirmation() -> &'static str {
    "Erases all Gilbreth activity data on this machine for this macOS user. This includes the live database, sealed and plaintext-era archives, and privacy sidecars. Capture in flight during the erase is discarded. Settings and portable exports outside Gilbreth's data folder are kept. Gilbreth cannot reach APFS local snapshots or Time Machine backups, so blocks written before the erase can survive there for up to about 24 hours; FileVault is the control that protects them. This can't be undone."
}

#[cfg(not(any(windows, target_os = "macos")))]
fn secure_erase_scope_confirmation() -> &'static str {
    "Erases all Gilbreth activity data on this machine for this user, including the live database, archives, and privacy sidecars. Capture in flight during the erase is discarded. Settings and portable exports outside Gilbreth's data folder are kept. This can't be undone."
}

/// The secure-erase outcome dialog body (pure; the copy audit exercises
/// every outcome with fixture reports).
fn secure_erase_report_message(
    report: &SecureEraseReport,
    keep_suspended: bool,
    capture_paused_by_user: bool,
    extra_notes: &[String],
    receipt_note: &str,
) -> String {
    let mut message = match report.outcome {
        SecureEraseOutcome::Completed => format!(
            "Secure erase completed. Deleted {} events and {} sessions. The replacement \
             recording session is {}.",
            report.events_deleted,
            report.sessions_deleted,
            report.new_session_id.unwrap_or_default()
        ),
        SecureEraseOutcome::DeleteFailed => format!(
            "Secure erase failed before deleting data.\n\n{}",
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
        SecureEraseOutcome::DeleteCommittedScrubIncomplete => format!(
            "Your activity was deleted and the replacement recording session is {}, but \
             the secure wipe couldn't fully finish after waiting for the database.\n\n\
             Close the dashboard and retry secure erase to finish the secure wipe.\n\n{}",
            report.new_session_id.unwrap_or_default(),
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
        SecureEraseOutcome::ReplacementSessionFailed => format!(
            "Your activity was deleted, but Gilbreth couldn't create a fresh recording \
             session. Capture remains suspended; restart Gilbreth before recording \
             resumes.\n\n{}",
            report.message.as_deref().unwrap_or(NO_FURTHER_DETAIL)
        ),
    };
    if !keep_suspended {
        message.push_str("\n\n");
        message.push_str(if capture_paused_by_user {
            CAPTURE_STILL_PAUSED_NOTE
        } else {
            CAPTURE_RESUMED_NOTE
        });
    }
    for note in extra_notes {
        message.push_str("\n\n");
        message.push_str(note);
    }
    message.push_str("\n\n");
    message.push_str(receipt_note);
    message
}

fn show_secure_erase_report(
    report: &SecureEraseReport,
    keep_suspended: bool,
    capture_paused_by_user: bool,
    extra_notes: &[String],
    extra_warn: bool,
    receipt_note: &str,
) {
    let message = secure_erase_report_message(
        report,
        keep_suspended,
        capture_paused_by_user,
        extra_notes,
        receipt_note,
    );
    let kind = if keep_suspended || report.outcome != SecureEraseOutcome::Completed || extra_warn {
        AlertKind::Warning
    } else {
        AlertKind::Info
    };
    alert(DIALOG_TITLE_SECURE_ERASE, &message, kind);
}

fn create_icon() -> Result<Icon> {
    const ICON_SIZE: usize = 32;
    // macOS status items are template images (shell-remainders slice): a
    // monochrome black+alpha glyph the system tints for light/dark menu
    // bars. Windows keeps the brand-colored icon unchanged.
    #[cfg(target_os = "macos")]
    let rgba = template_icon_rgba(ICON_SIZE);
    #[cfg(not(target_os = "macos"))]
    let rgba = favicon_rgba(ICON_SIZE);
    Icon::from_rgba(rgba, ICON_SIZE as u32, ICON_SIZE as u32).context("invalid tray icon")
}

/// The menu-bar template glyph: the brand mark reduced to black+alpha — a
/// rounded-square ring with the center dot. Only the alpha channel matters
/// to AppKit's template rendering (the system supplies the tint); black
/// keeps the raw RGBA legible in debugging tools.
#[cfg(target_os = "macos")]
fn template_icon_rgba(size: usize) -> Vec<u8> {
    const SAMPLES_PER_AXIS: usize = 4;
    const RING_INSET: f64 = 3.0;

    let mut rgba = Vec::with_capacity(size * size * 4);
    let scale = 32.0 / size as f64;
    let sample_count = (SAMPLES_PER_AXIS * SAMPLES_PER_AXIS) as f64;

    for y in 0..size {
        for x in 0..size {
            let mut alpha = 0.0;
            for sy in 0..SAMPLES_PER_AXIS {
                for sx in 0..SAMPLES_PER_AXIS {
                    let px = (x as f64 + (sx as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;
                    let py = (y as f64 + (sy as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;

                    let in_ring = inside_rounded_rect(px, py, 32.0, 32.0, 7.0)
                        && !inside_rounded_rect(
                            px - RING_INSET,
                            py - RING_INSET,
                            32.0 - 2.0 * RING_INSET,
                            32.0 - 2.0 * RING_INSET,
                            5.0,
                        );
                    if in_ring || inside_circle(px, py, 16.0, 16.0, 6.5) {
                        alpha += 255.0;
                    }
                }
            }
            rgba.push(0);
            rgba.push(0);
            rgba.push(0);
            rgba.push((alpha / sample_count).round() as u8);
        }
    }

    rgba
}

fn create_recording_icon() -> Result<Icon> {
    const ICON_SIZE: usize = 32;
    let rgba = record_icon_rgba(ICON_SIZE, RecordIconState::Recording);
    Icon::from_rgba(rgba, ICON_SIZE as u32, ICON_SIZE as u32).context("invalid recording tray icon")
}

fn create_paused_recording_icon() -> Result<Icon> {
    const ICON_SIZE: usize = 32;
    let rgba = record_icon_rgba(ICON_SIZE, RecordIconState::Paused);
    Icon::from_rgba(rgba, ICON_SIZE as u32, ICON_SIZE as u32)
        .context("invalid paused recording tray icon")
}

fn favicon_rgba(size: usize) -> Vec<u8> {
    const DARKROOM: [f64; 3] = [21.0, 23.0, 27.0]; // #15171B
    const AMBER: [f64; 3] = [242.0, 163.0, 60.0]; // #F2A33C
    const SAMPLES_PER_AXIS: usize = 4;

    let mut rgba = Vec::with_capacity(size * size * 4);
    let scale = 32.0 / size as f64;
    let sample_count = (SAMPLES_PER_AXIS * SAMPLES_PER_AXIS) as f64;

    for y in 0..size {
        for x in 0..size {
            let mut red = 0.0;
            let mut green = 0.0;
            let mut blue = 0.0;
            let mut alpha = 0.0;

            for sy in 0..SAMPLES_PER_AXIS {
                for sx in 0..SAMPLES_PER_AXIS {
                    let px = (x as f64 + (sx as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;
                    let py = (y as f64 + (sy as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;

                    let color = if inside_circle(px, py, 16.0, 16.0, 6.5) {
                        Some(AMBER)
                    } else if inside_rounded_rect(px, py, 32.0, 32.0, 7.0) {
                        Some(DARKROOM)
                    } else {
                        None
                    };

                    if let Some(color) = color {
                        red += color[0];
                        green += color[1];
                        blue += color[2];
                        alpha += 255.0;
                    }
                }
            }

            rgba.push((red / sample_count).round() as u8);
            rgba.push((green / sample_count).round() as u8);
            rgba.push((blue / sample_count).round() as u8);
            rgba.push((alpha / sample_count).round() as u8);
        }
    }

    rgba
}

#[derive(Clone, Copy)]
enum RecordIconState {
    Recording,
    Paused,
}

fn record_icon_rgba(size: usize, state: RecordIconState) -> Vec<u8> {
    const DARKROOM: [f64; 3] = [21.0, 23.0, 27.0]; // #15171B
    const RED: [f64; 3] = [225.0, 62.0, 62.0]; // #E13E3E
    const AMBER: [f64; 3] = [242.0, 163.0, 60.0]; // #F2A33C
    const SAMPLES_PER_AXIS: usize = 4;

    let mut rgba = Vec::with_capacity(size * size * 4);
    let scale = 32.0 / size as f64;
    let sample_count = (SAMPLES_PER_AXIS * SAMPLES_PER_AXIS) as f64;

    for y in 0..size {
        for x in 0..size {
            let mut red = 0.0;
            let mut green = 0.0;
            let mut blue = 0.0;
            let mut alpha = 0.0;

            for sy in 0..SAMPLES_PER_AXIS {
                for sx in 0..SAMPLES_PER_AXIS {
                    let px = (x as f64 + (sx as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;
                    let py = (y as f64 + (sy as f64 + 0.5) / SAMPLES_PER_AXIS as f64) * scale;

                    let color = if matches!(state, RecordIconState::Paused)
                        && ((10.0..=13.0).contains(&px) || (19.0..=22.0).contains(&px))
                        && (9.0..=23.0).contains(&py)
                    {
                        Some(AMBER)
                    } else if matches!(state, RecordIconState::Recording)
                        && inside_circle(px, py, 16.0, 16.0, 7.5)
                    {
                        Some(RED)
                    } else if inside_rounded_rect(px, py, 32.0, 32.0, 7.0) {
                        Some(DARKROOM)
                    } else {
                        None
                    };

                    if let Some(color) = color {
                        red += color[0];
                        green += color[1];
                        blue += color[2];
                        alpha += 255.0;
                    }
                }
            }

            rgba.push((red / sample_count).round() as u8);
            rgba.push((green / sample_count).round() as u8);
            rgba.push((blue / sample_count).round() as u8);
            rgba.push((alpha / sample_count).round() as u8);
        }
    }

    rgba
}

fn inside_circle(px: f64, py: f64, cx: f64, cy: f64, radius: f64) -> bool {
    let dx = px - cx;
    let dy = py - cy;
    dx.mul_add(dx, dy * dy) <= radius * radius
}

fn inside_rounded_rect(px: f64, py: f64, width: f64, height: f64, radius: f64) -> bool {
    let nearest_x = px.clamp(radius, width - radius);
    let nearest_y = py.clamp(radius, height - radius);
    let dx = px - nearest_x;
    let dy = py - nearest_y;
    dx.mul_add(dx, dy * dy) <= radius * radius
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn foreground_disable_flushes_forwarder_before_sending_forget() {
        let (flush_tx, flush_rx) = bounded::<CaptureFlushReply>(1);
        let (command_tx, command_rx) = bounded(4);
        // Stand-in forwarder: the flush must be requested and acked while
        // the command channel is still empty — the writer-side drain only
        // guarantees no FocusChanged survives the forget if the forwarder
        // hop was emptied first.
        let forwarder = thread::spawn(move || {
            let reply = flush_rx.recv().expect("flush requested");
            assert!(
                command_rx.try_recv().is_err(),
                "the forget must not be sent before the forwarder hop is flushed"
            );
            reply.send(()).expect("flush ack");
            command_rx
        });

        forget_focus_attribution_on_stream_toggle(
            CaptureStream::Foreground,
            false,
            &flush_tx,
            &command_tx,
        );

        let command_rx = forwarder.join().expect("forwarder thread");
        match command_rx.recv_timeout(Duration::from_secs(2)) {
            Ok(WriterCommand::ForgetFocusAttribution { .. }) => {}
            _ => panic!("expected the forget command after the flush"),
        }
    }

    #[test]
    fn only_the_foreground_off_toggle_forgets_focus_attribution() {
        let (flush_tx, flush_rx) = bounded::<CaptureFlushReply>(1);
        let (command_tx, command_rx) = bounded(4);

        forget_focus_attribution_on_stream_toggle(
            CaptureStream::Foreground,
            true,
            &flush_tx,
            &command_tx,
        );
        forget_focus_attribution_on_stream_toggle(
            CaptureStream::Keyboard,
            false,
            &flush_tx,
            &command_tx,
        );

        assert!(flush_rx.try_recv().is_err(), "no flush may be requested");
        assert!(command_rx.try_recv().is_err(), "no forget may be sent");
    }

    #[test]
    fn dashboard_process_routing_requires_the_exact_flag() {
        assert!(is_dashboard_process([DASHBOARD_PROCESS_FLAG]));
        assert!(is_dashboard_process([
            "--unrelated",
            DASHBOARD_PROCESS_FLAG
        ]));
        assert!(!is_dashboard_process(["--dashboard-preview"]));
        assert!(!is_dashboard_process(["--dashboard=true"]));
        assert!(!is_dashboard_process(std::iter::empty::<&str>()));
    }

    #[test]
    fn dashboard_command_spawns_current_executable_with_only_dashboard_flag() {
        let executable = Path::new(r"C:\Program Files\Gilbreth\gilbreth-app.exe");
        let command = dashboard_command(executable);

        assert_eq!(command.get_program(), executable.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![OsStr::new(DASHBOARD_PROCESS_FLAG)]
        );
    }

    #[test]
    fn dashboard_worker_waits_for_and_reaps_its_child() {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let worker = spawn_dashboard_worker(command).expect("dashboard worker starts");
        let status = worker
            .join()
            .expect("dashboard worker does not panic")
            .expect("child starts and is reaped");

        assert!(status.success());
    }

    #[test]
    fn dashboard_menu_uses_the_single_shipping_label() {
        assert_eq!(OPEN_DASHBOARD_MENU_LABEL, "Open Dashboard");
    }

    #[cfg(windows)]
    #[test]
    fn secure_erase_confirmation_pins_machine_user_scope_and_in_flight_boundary() {
        let copy = secure_erase_scope_confirmation();
        assert!(copy
            .contains("Erases all Gilbreth activity data on this machine for this Windows user."));
        assert!(copy.contains("Capture in flight during the erase is discarded."));
    }

    #[test]
    fn tray_icon_matches_site_favicon_shape_and_colors() {
        let rgba = favicon_rgba(32);

        assert_eq!(rgba.len(), 32 * 32 * 4);
        assert_eq!(pixel(&rgba, 16, 16), [242, 163, 60, 255]);
        assert_eq!(pixel(&rgba, 16, 4), [21, 23, 27, 255]);
        assert_eq!(pixel(&rgba, 0, 0)[3], 0);
        assert_eq!(
            ico_image_rgba(include_bytes!("../assets/windows/gilbreth.ico"), 32),
            rgba,
            "the embedded shell asset must stay pixel-identical to the runtime mark"
        );
    }

    fn test_captured() -> Captured {
        Captured::new(
            gilbreth_core::Source::System,
            std::time::Instant::now(),
            gilbreth_core::EventPayload::SensitiveContextEntered {
                reason: gilbreth_core::SensitiveContextReason::SessionLocked,
            },
        )
    }

    #[test]
    fn capture_forwarder_flush_drains_backlog_before_confirming() {
        let (capture_tx, capture_rx) = bounded(CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = bounded(CHANNEL_CAPACITY);
        let (flush_tx, flush_rx) = bounded(1);
        let forwarder =
            thread::spawn(move || run_capture_forwarder(capture_rx, writer_tx, flush_rx));

        for _ in 0..8 {
            capture_tx.send(test_captured()).expect("event queued");
        }
        flush_capture_forwarder(&flush_tx).expect("flush confirms a quiet pipeline");

        // Everything enqueued before the confirmation must already be on the
        // writer channel — that ordering is what lets erase/archive trust that
        // the writer's own quiet-drain sees every pre-suspension row.
        for _ in 0..8 {
            assert!(matches!(
                writer_rx
                    .try_recv()
                    .expect("backlog forwarded before the flush reply"),
                WriterInput::Motion(_)
            ));
        }
        assert!(writer_rx.try_recv().is_err(), "no extra events invented");

        // Normal forwarding resumes after a flush.
        capture_tx
            .send(test_captured())
            .expect("post-flush event queued");
        assert!(matches!(
            writer_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("post-flush event forwarded"),
            WriterInput::Motion(_)
        ));

        drop(capture_tx);
        drop(flush_tx);
        forwarder
            .join()
            .expect("forwarder exits when the capture channel closes");
    }

    #[test]
    fn manual_pause_boundary_follows_every_pre_pause_capture() {
        let (capture_tx, capture_rx) = bounded(CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = bounded(CHANNEL_CAPACITY);
        let boundary_tx = writer_tx.clone();
        let (flush_tx, flush_rx) = bounded(1);
        let forwarder =
            thread::spawn(move || run_capture_forwarder(capture_rx, writer_tx, flush_rx));

        capture_tx.send(test_captured()).expect("event queued");
        flush_capture_forwarder(&flush_tx).expect("pre-pause traffic drains");
        enqueue_capture_pause_row(&boundary_tx, EventPayload::CapturePaused)
            .expect("pause boundary queued");

        assert!(matches!(
            writer_rx.recv().expect("pre-pause row"),
            WriterInput::Motion(Captured {
                payload: EventPayload::SensitiveContextEntered { .. },
                ..
            })
        ));
        assert!(matches!(
            writer_rx.recv().expect("pause boundary"),
            WriterInput::Motion(Captured {
                payload: EventPayload::CapturePaused,
                ..
            })
        ));

        drop(capture_tx);
        drop(flush_tx);
        forwarder.join().expect("forwarder exits");
    }

    #[test]
    fn privacy_operation_restores_latest_manual_pause_state_with_boundaries() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);
        let paused = AtomicBool::new(false);
        let (writer_tx, writer_rx) = bounded(2);
        let (flush_tx, _flush_rx) = bounded(1);

        restore_capture_after_privacy_operation(
            &controls,
            &paused,
            true,
            true,
            &flush_tx,
            &writer_tx,
            PumpWaker::disconnected(),
        );

        assert!(!controls.is_suspended());
        assert!(matches!(
            writer_rx.recv().expect("resume boundary"),
            WriterInput::Motion(Captured {
                payload: EventPayload::CaptureResumed,
                ..
            })
        ));

        controls.set_suspended(true);
        paused.store(true, Ordering::SeqCst);
        restore_capture_after_privacy_operation(
            &controls,
            &paused,
            true,
            true,
            &flush_tx,
            &writer_tx,
            PumpWaker::disconnected(),
        );
        assert!(controls.is_suspended());
        assert!(matches!(
            writer_rx
                .recv()
                .expect("pause boundary in replacement session"),
            WriterInput::Motion(Captured {
                payload: EventPayload::CapturePaused,
                ..
            })
        ));
    }

    #[test]
    fn privacy_operation_resume_boundary_failure_stays_fail_closed() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);
        let paused = AtomicBool::new(false);
        let (writer_tx, writer_rx) = bounded(1);
        let (flush_tx, _flush_rx) = bounded(1);
        drop(writer_rx);

        restore_capture_after_privacy_operation(
            &controls,
            &paused,
            true,
            false,
            &flush_tx,
            &writer_tx,
            PumpWaker::disconnected(),
        );

        assert!(controls.is_suspended());
        assert!(paused.load(Ordering::SeqCst));
    }

    #[test]
    fn privacy_operation_resume_rejects_a_stale_sensitive_generation() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);
        drop(controls.begin_sensitive_transition());
        let paused = AtomicBool::new(false);
        let (writer_tx, writer_rx) = bounded(1);
        let (flush_tx, _flush_rx) = bounded(1);

        // The test platform acknowledges generation zero; the announced
        // transition above advanced the live generation to one. Resume must
        // not write its boundary or reopen on that stale acknowledgement.
        restore_capture_after_privacy_operation(
            &controls,
            &paused,
            true,
            false,
            &flush_tx,
            &writer_tx,
            PumpWaker::disconnected(),
        );

        assert!(controls.is_suspended());
        assert!(paused.load(Ordering::SeqCst));
        assert!(writer_rx.try_recv().is_err());
    }

    #[test]
    fn capture_forwarder_flush_confirms_quiet_even_when_writer_is_gone() {
        let (capture_tx, capture_rx) = bounded(CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = bounded(CHANNEL_CAPACITY);
        let (flush_tx, flush_rx) = bounded(1);
        let forwarder =
            thread::spawn(move || run_capture_forwarder(capture_rx, writer_tx, flush_rx));

        // The flush must still confirm (the privacy action then fails loud on
        // the writer command send instead of timing out here), and the
        // forwarder must exit once a forward hits the dead writer.
        drop(writer_rx);
        flush_capture_forwarder(&flush_tx).expect("flush confirms with the writer gone");
        capture_tx.send(test_captured()).expect("event queued");
        forwarder
            .join()
            .expect("forwarder exits after the writer disappears");
    }

    #[test]
    fn capture_forwarder_keeps_forwarding_after_flush_channel_closes() {
        let (capture_tx, capture_rx) = bounded(CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = bounded(CHANNEL_CAPACITY);
        let (flush_tx, flush_rx) = bounded(1);
        let forwarder =
            thread::spawn(move || run_capture_forwarder(capture_rx, writer_tx, flush_rx));

        drop(flush_tx);
        capture_tx.send(test_captured()).expect("event queued");
        assert!(matches!(
            writer_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("event still forwarded after the flush channel closed"),
            WriterInput::Motion(_)
        ));

        drop(capture_tx);
        forwarder
            .join()
            .expect("forwarder exits when the capture channel closes");
    }

    #[test]
    fn secure_erase_removes_the_spheres_sidecar_and_its_staging_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = config::config_path(dir.path());
        let sidecar = config::spheres_sidecar_path(&config_path);
        let staged = sidecar.with_extension("json.tmp");
        std::fs::write(&sidecar, r#"{"version":1,"aliases":{"x":"Secret"}}"#)
            .expect("sidecar written");
        // A dashboard crash mid-write leaves the same payload in the staging
        // path; the wipe must take it too (S4).
        std::fs::write(&staged, r#"{"version":1,"aliases":{"x":"Secret"}}"#)
            .expect("staging file written");

        assert_eq!(secure_erase_spheres_sidecar(&config_path), Ok(()));
        assert!(!sidecar.exists(), "secure erase must remove the sidecar");
        assert!(
            !staged.exists(),
            "secure erase must remove the staging file"
        );

        // Absent files are a no-op success (no panic, no error).
        assert_eq!(secure_erase_spheres_sidecar(&config_path), Ok(()));
    }

    #[test]
    fn secure_erase_removes_archives_and_exact_crash_staging_names_but_retains_unknown_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive_dir = dir.path().join("archives");
        fs::create_dir_all(&archive_dir).expect("archive directory");
        let sealed = archive_dir.join("gilbreth-archive-100-deadbeef.gla");
        let plaintext = archive_dir.join("gilbreth-archive-90-deadbeef.db");
        let plaintext_staging = archive_dir.join(
            ".gilbreth-archive-100-deadbeef.gla.550e8400-e29b-41d4-a716-446655440000.plaintext.db",
        );
        let plaintext_staging_sidecars = ["-wal", "-shm", "-journal"].map(|suffix| {
            archive_dir.join(format!(
                ".gilbreth-archive-100-deadbeef.gla.550e8400-e29b-41d4-a716-446655440000.plaintext.db{suffix}"
            ))
        });
        let sealed_pending = archive_dir.join(
            ".gilbreth-archive-100-deadbeef.gla.550e8400-e29b-41d4-a716-446655440001.pending",
        );
        let unknown = archive_dir.join("notes.txt");
        let staging_near_misses = [
            ".plaintext.db",
            ".plaintext.db-wal",
            ".plaintext.db-shm",
            ".plaintext.db-journal",
        ]
        .map(|suffix| {
            archive_dir.join(format!(
                ".gilbreth-archive-100-deadbeef.gla.not-a-uuid{suffix}"
            ))
        });
        fs::write(&sealed, b"sealed ciphertext fixture").expect("sealed fixture");
        fs::write(&plaintext, b"SQLite format 3\0private fixture").expect("legacy fixture");
        fs::write(
            &plaintext_staging,
            b"SQLite format 3\0crash-leftover private fixture",
        )
        .expect("plaintext staging fixture");
        for sidecar in &plaintext_staging_sidecars {
            fs::write(sidecar, b"SQLite crash-leftover private sidecar")
                .expect("plaintext staging sidecar fixture");
        }
        fs::write(&sealed_pending, b"pending ciphertext fixture").expect("pending fixture");
        fs::write(&unknown, b"user-owned").expect("unknown fixture");
        for near_miss in &staging_near_misses {
            fs::write(near_miss, b"user-owned near miss").expect("near-miss fixture");
        }

        let (classes, notes, warning) = remove_archives_for_secure_erase(dir.path());

        assert!(!warning, "all Gilbreth-owned archives were removable");
        assert!(notes.is_empty());
        assert!(!sealed.exists());
        assert!(!plaintext.exists());
        assert!(!plaintext_staging.exists());
        for sidecar in plaintext_staging_sidecars {
            assert!(
                !sidecar.exists(),
                "plaintext SQLite sidecar must be removed"
            );
        }
        assert!(!sealed_pending.exists());
        assert!(unknown.exists(), "unrecognized entries are retained");
        for near_miss in staging_near_misses {
            assert!(
                near_miss.exists(),
                "a staging-like name without Gilbreth's UUID shape is retained"
            );
        }
        assert!(classes.iter().any(|class| {
            class.class == "sealed_archives"
                && class.outcome == privacy_receipt::ReceiptOutcome::Removed
                && class.item_count == 1
        }));
        assert!(classes.iter().any(|class| {
            class.class == "plaintext_era_archives"
                && class.outcome == privacy_receipt::ReceiptOutcome::Removed
                && class.item_count == 1
        }));
        assert!(classes.iter().any(|class| {
            class.class == "archive_staging_artifacts"
                && class.outcome == privacy_receipt::ReceiptOutcome::Removed
                && class.item_count == 5
        }));
        assert!(classes.iter().any(|class| {
            class.class == "unrecognized_archive_directory_entries"
                && class.outcome == privacy_receipt::ReceiptOutcome::Retained
                && class.item_count == 5
        }));
    }

    #[test]
    fn archive_reset_receipt_uses_exact_content_free_outcomes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let note = write_archive_reset_receipt(
            dir.path(),
            ArchiveResetOutcome::DeleteCommittedScrubIncomplete,
            "test_scrub",
        );
        assert!(note.contains("encrypted_archive: copied"));
        assert!(note.contains("live_activity: removed"));
        assert!(note.contains("live_database_scrub: needs retry"));
        let receipt_dir = dir.path().join(privacy_receipt::RECEIPT_DIRECTORY);
        let receipt_path = fs::read_dir(receipt_dir)
            .expect("receipt directory")
            .next()
            .expect("receipt entry")
            .expect("read receipt")
            .path();
        let json = fs::read_to_string(receipt_path).expect("receipt JSON");
        assert!(json.contains("\"needs retry\""));
        assert!(!json.contains(dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn secure_erase_not_started_receipt_is_honest_and_incomplete() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::create_dir_all(dir.path().join("archives")).expect("archive directory");
        fs::write(
            dir.path().join("archives/gilbreth-archive-10-legacy.db"),
            b"SQLite format 3\0fixture",
        )
        .expect("legacy archive");

        let note = write_secure_erase_not_started_receipt(dir.path(), "writer_unavailable");

        assert!(note.contains("secure_erase_operation: needs retry"));
        assert!(note.contains("live_database_activity: retained"));
        assert!(note.contains("plaintext_era_archives: retained (1)"));
        let receipt_path = fs::read_dir(dir.path().join(privacy_receipt::RECEIPT_DIRECTORY))
            .expect("receipt directory")
            .next()
            .expect("receipt entry")
            .expect("receipt path")
            .path();
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(receipt_path).expect("receipt bytes"))
                .expect("receipt JSON");
        assert_eq!(value["status"], "incomplete");
        assert!(value.to_string().contains("writer_unavailable"));
        assert!(!value
            .to_string()
            .contains(dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn receipt_inventory_errors_are_needs_retry_not_zero_counts() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("archives"), b"not a directory").expect("archive blocker");

        let note = write_secure_erase_not_started_receipt(dir.path(), "writer_unavailable");

        assert!(note.contains("archive_inventory: needs retry"));
        assert!(count_regular_files(&dir.path().join("archives")).is_err());
        let receipt_path = fs::read_dir(dir.path().join(privacy_receipt::RECEIPT_DIRECTORY))
            .expect("receipt directory")
            .next()
            .expect("receipt entry")
            .expect("receipt path")
            .path();
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(receipt_path).expect("receipt bytes"))
                .expect("receipt JSON");
        assert_eq!(value["status"], "incomplete");
        assert!(value.to_string().contains("inventory_failed"));
    }

    /// Record Routine is Windows-only by decision record. The tray must not
    /// merely disable the items off Windows: `apply_recording_visual_state`
    /// runs on every capture pause/resume and re-enables them, so an
    /// enabled-flag gate is silently undone the first time capture pauses.
    ///
    /// Off Windows the guarantee is structural rather than asserted here —
    /// the ids, labels and dialog bodies are not compiled at all, so any
    /// attempt to append the items again fails to build. This test holds the
    /// Windows side of that contract.
    #[cfg(windows)]
    #[test]
    fn record_routine_menu_ids_exist_only_on_windows() {
        assert_eq!(RECORD_ROUTINE_MENU_ID, "record_routine");
        assert_eq!(STOP_RECORDING_MENU_ID, "stop_recording");
        assert_eq!(PAUSE_RECORDING_MENU_ID, "pause_recording");
        assert_eq!(RESUME_RECORDING_MENU_ID, "resume_recording");
    }

    /// A record request that arrives on a platform without Record Routine
    /// must be declined, not dropped: dropping leaves the row `requested` and
    /// the writer re-surfaces it every poll until the TTL.
    #[cfg(not(windows))]
    #[test]
    fn unsupported_record_request_is_declined_not_dropped() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let request = PendingRecordRequest {
            request_id: 77,
            candidate_kind: Some("automatable_routine".to_string()),
            candidate_json: "{}".to_string(),
            expires_at: 0,
        };

        decline_unsupported_record_request(&tx, &request);

        match rx.try_recv().expect("a decline command is sent") {
            WriterCommand::DeclineRecordRequest { request_id } => assert_eq!(request_id, 77),
            other => panic!("expected DeclineRecordRequest, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command per request");
    }

    #[test]
    fn recording_icons_have_distinct_center_states() {
        let recording = record_icon_rgba(32, RecordIconState::Recording);
        let paused = record_icon_rgba(32, RecordIconState::Paused);

        assert_eq!(pixel(&recording, 16, 16), [225, 62, 62, 255]);
        assert_eq!(pixel(&paused, 11, 16), [242, 163, 60, 255]);
        assert_eq!(pixel(&paused, 16, 16), [21, 23, 27, 255]);
    }

    #[test]
    fn deliver_record_command_stamps_replies_with_the_session_id() {
        let (command_tx, command_rx) = bounded(8);
        let (ui_tx, ui_rx) = bounded(8);

        let writer = thread::spawn(move || {
            for reply_with in [Ok(()), Err("already closed".to_string())] {
                match command_rx.recv().expect("command arrives") {
                    WriterCommand::StopRecording {
                        record_session_id,
                        reply,
                        ..
                    } => {
                        assert_eq!(record_session_id, 41);
                        reply.send(reply_with).expect("reply sent");
                    }
                    _ => panic!("unexpected writer command"),
                }
            }
        });

        for _ in 0..2 {
            deliver_record_command(
                &command_tx,
                &ui_tx,
                PumpWaker::disconnected(),
                41,
                |reply| WriterCommand::StopRecording {
                    record_session_id: 41,
                    stop_reason: RecordStopReason::UserStop,
                    reply,
                },
            );
        }
        writer.join().expect("writer thread");

        match ui_rx.try_recv().expect("first ui event") {
            RecordUiEvent::Stopped { record_session_id } => assert_eq!(record_session_id, 41),
            other => panic!("expected session-stamped Stopped, got {other:?}"),
        }
        match ui_rx.try_recv().expect("second ui event") {
            RecordUiEvent::Failed {
                record_session_id,
                message,
            } => {
                assert_eq!(record_session_id, Some(41));
                assert!(message.contains("already closed"));
            }
            other => panic!("expected session-stamped Failed, got {other:?}"),
        }
    }

    #[test]
    fn candidate_label_is_bounded_and_control_free() {
        let request = PendingRecordRequest {
            request_id: 1,
            candidate_kind: Some("automatable_routine".to_string()),
            candidate_json: serde_json::json!({
                "title": format!("{}{}\n", "A".repeat(300), "\u{0007}")
            })
            .to_string(),
            expires_at: 10,
        };

        let label = candidate_label(&request);

        assert_eq!(label.chars().count(), 256);
        assert!(!label.chars().any(char::is_control));
    }

    #[test]
    fn policy_snapshot_is_value_free_and_omits_redaction_fragments() {
        let mut config = AppConfig::default();
        config.privacy.redact_titles_containing = vec!["Secret Bank".to_string()];
        config.privacy.redact_keys_containing = vec!["Password".to_string()];
        config.privacy.excluded_apps = vec!["private.exe".to_string()];
        config.privacy.retention_days = 30;
        config.record.elevated_helper_enabled = true;
        config.record.elevated_helper_path =
            r"C:\Program Files\Gilbreth\gilbreth-elevated-record-helper.exe".to_string();
        config.record.elevated_helper_required_signer_sha256 =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        let snapshot = record_policy_snapshot_json(&config, true);
        let value: serde_json::Value = serde_json::from_str(&snapshot).expect("snapshot json");

        assert_eq!(value["schema"], "gilbreth.record_session.policy.v1");
        assert_eq!(value["value_free"], true);
        assert_eq!(
            value["baseline_capture"]["suspended_during_recording"],
            true
        );
        assert_eq!(
            value["baseline_capture"]["reason"],
            "record_routine_value_free"
        );
        assert_eq!(value["redaction_posture"]["titles"], true);
        assert_eq!(value["redaction_posture"]["keys"], true);
        assert_eq!(value["retention_days"], 30);
        assert_eq!(value["excluded_apps"], serde_json::json!(["private.exe"]));
        assert!(value.get("excluded_drop_count").is_none());
        assert_eq!(value["elevated_helper"]["config_enabled"], true);
        assert_eq!(value["elevated_helper"]["requested"], true);
        assert_eq!(value["elevated_helper"]["strategy"], "runas");
        assert_eq!(value["elevated_helper"]["value_free_ipc"], true);
        assert_eq!(value["elevated_helper"]["secure_desktop_capture"], false);
        assert_eq!(value["elevated_helper"]["automation_execution"], false);
        assert_eq!(value["elevated_helper"]["launch_result_recorded"], false);
        assert_eq!(
            value["elevated_helper"]["custom_helper_path_configured"],
            true
        );
        assert_eq!(value["elevated_helper"]["signer_sha256_required"], true);
        assert!(!snapshot.contains("Secret Bank"));
        assert!(!snapshot.contains("Password"));
        assert!(!snapshot.contains("0123456789abcdef"));
        assert!(!snapshot.contains("Program Files"));
        assert!(!snapshot.contains("gilbreth-elevated-record-helper"));
        assert!(!snapshot.contains("GILBRETH_TYPED_SENTINEL"));
    }

    #[test]
    fn record_routine_suspends_and_restores_baseline_capture() {
        let controls = CaptureControls::all_enabled();

        let suspended = suspend_baseline_capture_for_recording(&controls);
        assert!(suspended);
        assert!(controls.is_suspended());

        assert!(restore_baseline_capture_after_recording(
            &controls, suspended
        ));
        assert!(!controls.is_suspended());
    }

    #[test]
    fn record_routine_does_not_resume_preexisting_capture_suspension() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);

        let suspended = suspend_baseline_capture_for_recording(&controls);
        assert!(!suspended);
        assert!(controls.is_suspended());

        assert!(!restore_baseline_capture_after_recording(
            &controls, suspended
        ));
        assert!(controls.is_suspended());
    }

    #[test]
    fn cap_prompt_only_spawns_for_active_non_stopping_recording() {
        assert!(should_spawn_cap_prompt(Some(42), None, 42));
        assert!(!should_spawn_cap_prompt(None, None, 42));
        assert!(!should_spawn_cap_prompt(Some(41), None, 42));
        assert!(!should_spawn_cap_prompt(Some(42), Some(42), 42));
        assert!(should_spawn_cap_prompt(Some(42), Some(41), 42));
    }

    fn pixel(rgba: &[u8], x: usize, y: usize) -> [u8; 4] {
        let index = ((y * 32) + x) * 4;
        [
            rgba[index],
            rgba[index + 1],
            rgba[index + 2],
            rgba[index + 3],
        ]
    }

    fn ico_image_rgba(ico: &[u8], wanted_size: usize) -> Vec<u8> {
        let read_u16 =
            |offset: usize| u16::from_le_bytes(ico[offset..offset + 2].try_into().unwrap());
        let read_u32 =
            |offset: usize| u32::from_le_bytes(ico[offset..offset + 4].try_into().unwrap());
        assert_eq!(read_u16(0), 0);
        assert_eq!(read_u16(2), 1);

        let count = read_u16(4) as usize;
        let entry = (0..count)
            .map(|index| 6 + index * 16)
            .find(|offset| {
                let width = if ico[*offset] == 0 {
                    256
                } else {
                    ico[*offset] as usize
                };
                let height = if ico[*offset + 1] == 0 {
                    256
                } else {
                    ico[*offset + 1] as usize
                };
                width == wanted_size && height == wanted_size
            })
            .expect("requested icon size should exist");
        assert_eq!(read_u16(entry + 6), 32);
        let dib = read_u32(entry + 12) as usize;
        assert_eq!(read_u32(dib), 40);
        let pixels = dib + 40;
        let mut rgba = Vec::with_capacity(wanted_size * wanted_size * 4);
        for y in 0..wanted_size {
            let source_y = wanted_size - 1 - y;
            for x in 0..wanted_size {
                let source = pixels + (source_y * wanted_size + x) * 4;
                rgba.extend_from_slice(&[
                    ico[source + 2],
                    ico[source + 1],
                    ico[source],
                    ico[source + 3],
                ]);
            }
        }
        rgba
    }

    #[test]
    fn log_filter_ignores_generic_rust_log() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_env_var("RUST_LOG", Some("warn"), || {
            with_env_var(GILBRETH_LOG_ENV, None, || {
                assert_eq!(
                    log_filter_config(),
                    LogFilterConfig {
                        directive: DEFAULT_LOG_FILTER.to_string(),
                        effective_directive: String::new(),
                        source: LogFilterSource::Default
                    }
                );
            });
        });
    }

    #[test]
    fn log_filter_uses_gilbreth_specific_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        with_env_var(GILBRETH_LOG_ENV, Some("gilbreth_app=debug"), || {
            assert_eq!(
                log_filter_config(),
                LogFilterConfig {
                    directive: "gilbreth_app=debug".to_string(),
                    effective_directive: String::new(),
                    source: LogFilterSource::Env
                }
            );
        });
    }

    #[test]
    fn retention_now_clamps_to_newest_stored_row() {
        // Empty DB: the wall clock is the only reference.
        assert_eq!(clamped_retention_now_ms(1_000, None), 1_000);
        // Clock jumped ahead of stored activity (corrected dead-CMOS clock):
        // age relative to the data's own timeline instead.
        assert_eq!(
            clamped_retention_now_ms(100 * DAY_MS, Some(3 * DAY_MS)),
            3 * DAY_MS
        );
        // Clock behind the newest row: keep the (older) wall clock, which
        // only prunes less.
        assert_eq!(
            clamped_retention_now_ms(2 * DAY_MS, Some(3 * DAY_MS)),
            2 * DAY_MS
        );
    }

    #[test]
    fn retention_cutoff_uses_at_least_one_day_and_clamps() {
        assert_eq!(retention_cutoff_ms(10 * DAY_MS, 0), 9 * DAY_MS);
        assert_eq!(retention_cutoff_ms(10 * DAY_MS, 3), 7 * DAY_MS);
        assert_eq!(retention_cutoff_ms(i64::MIN + 1, u64::MAX), i64::MIN);
    }

    #[test]
    fn writer_panic_result_cancels_capture_and_wakes_pump() {
        let stop = StopToken::new();
        let woke = Arc::new(AtomicBool::new(false));
        let woke_clone = woke.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let panic_result: thread::Result<StoreWriterResult> =
            Err(Box::new("boom") as Box<dyn std::any::Any + Send>);

        report_writer_thread_exit(
            panic_result,
            stop.clone(),
            move || woke_clone.store(true, Ordering::SeqCst),
            done_tx,
        );

        assert!(stop.is_cancelled());
        assert!(woke.load(Ordering::SeqCst));
        let result = done_rx
            .recv_timeout(Duration::from_millis(10))
            .expect("writer result reported");
        assert!(result
            .expect_err("panic result is an error")
            .to_string()
            .contains("boom"));
    }

    fn with_env_var(key: &str, value: Option<&str>, action: impl FnOnce()) {
        let old_value = env::var_os(key);
        match value {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }
        action();
        match old_value {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }
    }
}
