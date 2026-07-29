//! Host boundary and the background reader.
//!
//! The UI never touches the database or config sidecars directly: a
//! [`DashboardHost`] supplied by `gilbreth-app` carries the paths and the
//! cooperative sidecar IO (config ownership stays in `gilbreth-app::config`
//! per the S2 crate boundary), and a worker thread runs every read so a slow
//! query can never block paint. The UI holds the latest [`TodaySnapshot`]
//! and repaints when a fresh one arrives.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use gilbreth_read::{
    active_focus_minutes_total, daily_active_minutes, database_health, day_strip,
    focus_minutes_total, focus_rollup, hourly_input_pulse, input_rollup, live_sphere_tokens,
    open_readonly, pattern_history_days, read_activity_events, read_database_counts,
    read_debug_log, read_event_counts, read_focus_summary, read_power_events, read_process_churn,
    read_recording_export_steps, read_recording_steps, read_recordings,
    read_session_active_focus_seconds_total, read_session_focus_seconds_total, read_sessions,
    read_system_events, recording_replay_verdict, session_analytics, session_story_totals,
    today_story, weekly_digest, window_lifecycle_rollup, working_spheres_overlay,
    working_spheres_skeleton, ActivityEventRow, DatabaseCounts, DatabaseHealth, DayActive,
    DayStrip, DebugLogSnapshot, DiscoveryNotice, DiscoveryNoticeState, EventCountRow,
    FocusRollupRow, FocusSummaryRow, FragmentationMetrics, HourPulse, InputExposureMetrics,
    InputRollupRow, InstallStateSnapshot, InterruptionCosts, PatternCandidate, PowerEventRow,
    ProcessChurnReport, RecordingRow, RecordingStep, ReplayExportVerdict, RhythmMetrics, Scope,
    SessionAnalyticsRow, SessionRow, SessionStoryTotals, SphereOverlay, SphereSkeleton,
    SystemEventRow, TodayStory, WeeklyDigest, WindowLifecycleRow,
};

/// Whether this viewer owns the one durable eframe UI-state writer claim.
/// Secondary viewers remain fully usable but start from defaults and never
/// read or write persistent window, egui-memory, or active-tab state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiStatePersistence {
    Owner,
    Secondary,
}

impl UiStatePersistence {
    pub const fn is_owner(self) -> bool {
        matches!(self, Self::Owner)
    }
}

/// Everything the dashboard needs from the owning app. Callbacks are used
/// (rather than a dependency on `gilbreth-app`) so config/sidecar ownership
/// stays in the app crate and tests can substitute an in-memory host.
pub struct DashboardHost {
    pub db_path: PathBuf,
    /// eframe persistence file, kept under `%LOCALAPPDATA%\Gilbreth` beside
    /// the other run artifacts — never eframe's default directory.
    pub ui_state_path: PathBuf,
    /// Only the first concurrent viewer may persist eframe UI state.
    pub ui_state_persistence: UiStatePersistence,
    /// Window icon RGBA (width, height, bytes) sharing the tray-icon
    /// geometry; `None` falls back to the default window icon.
    pub window_icon: Option<(u32, u32, Vec<u8>)>,
    /// Whether opt-in full key-content capture is currently enabled — the
    /// one privacy posture surfaced at a glance on Today.
    pub store_key_content: Box<dyn Fn() -> bool + Send + Sync>,
    /// Monotonic per-install onboarding flag. Existing installs default to
    /// dismissed; only a genuinely fresh config starts with the welcome
    /// visible.
    pub read_first_run_welcome_dismissed: Box<dyn Fn() -> bool + Send + Sync>,
    /// Document-preserving config write that can only move the welcome flag
    /// from visible to dismissed.
    pub dismiss_first_run_welcome: Box<dyn Fn() -> Result<(), String> + Send + Sync>,
    /// Tolerant notices.json read (never the strict parity twin).
    pub read_notice_state: Box<dyn Fn() -> DiscoveryNoticeState + Send + Sync>,
    /// Atomic notices.json write; errors come back as sanitized display
    /// strings per the config error contract.
    pub write_notice_state: WriteNoticeState,
    /// `analytics.sphere_labels_from_titles` from the cooperative config.
    pub read_sphere_overlay_enabled: Box<dyn Fn() -> bool + Send + Sync>,
    /// Document-preserving config write of the sphere-names toggle.
    pub write_sphere_overlay_enabled: WriteSphereOverlayEnabled,
    /// Tolerant spheres.json alias read.
    pub read_sphere_aliases: Box<dyn Fn() -> BTreeMap<String, String> + Send + Sync>,
    /// Atomic spheres.json alias write.
    pub write_sphere_aliases: WriteSphereAliases,
    /// Once-per-dashboard-session stale-alias prune against the live token
    /// set (S11: alias keys are title-derived and must not outlive titles).
    pub prune_sphere_aliases: PruneSphereAliases,
    /// Insert a record request (gilbreth-store) and return its id.
    pub request_recording: RequestRecording,
    /// Current status text of a record request, if the table and row exist.
    pub record_request_status: Box<dyn Fn(i64) -> Option<String> + Send + Sync>,
    /// Sidecar file name shown in the rename/merge caption ("spheres.json").
    pub spheres_sidecar_name: String,
    /// CPython-casefold alias-key normalization, single-sourced from the
    /// config crate so saved keys fold exactly like the sidecar reader.
    pub casefold_token: Box<dyn Fn(&str) -> String + Send + Sync>,
    /// Config file location, shown in the redaction-rules expander.
    pub config_path: PathBuf,
    /// Operator-verified framework classes for replay exports
    /// (`[export].verified_framework_classes`, read by the config crate).
    pub verified_framework_classes: Box<dyn Fn() -> HashSet<String> + Send + Sync>,
    /// Build, serialize, and write one replay export (record session id,
    /// mode, review labels) to the user's Downloads folder; returns the
    /// saved path for the notice.
    pub save_replay_export: SaveReplayExport,
    /// Encrypted archive copies eligible for an explicit portable export.
    /// The opaque id is passed back to `export_portable_archive`; the label
    /// is safe to render in the local dashboard.
    #[cfg(windows)]
    pub list_portable_archive_sources: ListPortableArchiveSources,
    /// Rewrap one encrypted archive for portability, or deliberately write
    /// a plaintext copy after the Privacy UI has collected acknowledgement.
    #[cfg(windows)]
    pub export_portable_archive: ExportPortableArchive,
    /// Dashboard-lane recording delete (gilbreth-store): secure-delete on,
    /// WAL checkpoint after, a deferred checkpoint surfaced as the warning.
    pub delete_recording: DeleteRecording,
    /// Dashboard-lane per-event delete (gilbreth-store) for the Session
    /// tab's Event list — same secure-delete + checkpoint semantics as the
    /// recording delete, proven equal to the Python `delete_events` by the
    /// DB-diff parity suite.
    pub delete_events: DeleteEvents,
    /// Tolerant `[privacy]` settings read (config crate; malformed config
    /// comes back as the error string with defaults).
    pub read_privacy_settings: Box<dyn Fn() -> PrivacySettingsView + Send + Sync>,
    /// Document-preserving write of the dashboard-editable privacy
    /// values (`store_key_content` stays tray-owned).
    pub write_privacy_settings: WritePrivacySettings,
    /// `[privacy].retention_days` with the 90-day tolerant default — seeds
    /// the prune-days input.
    pub read_retention_days: Box<dyn Fn() -> i64 + Send + Sync>,
    /// Row counts that a prune at the given cutoff would delete.
    pub prune_preview: PrunePreviewFn,
    /// The prune itself (gilbreth-store): secure-delete, then compaction,
    /// with a compaction failure surfaced on the outcome.
    pub prune_old_events: PruneOldEvents,
    /// The HKCU Run value for install state: (command, error).
    pub autostart_command: Box<dyn Fn() -> (Option<String>, Option<String>) + Send + Sync>,
    /// How many archive copies exist beside the live database (the DASH-05
    /// continuity line).
    pub archive_count: Box<dyn Fn() -> usize + Send + Sync>,
    /// Count legacy `gilbreth-archive-*.db` files without exposing their
    /// names or paths. Diagnostics renders this even when the live DB is
    /// absent so an old plaintext archive cannot disappear behind DB state.
    pub read_legacy_plaintext_archive_count: Box<dyn Fn() -> Result<usize, String> + Send + Sync>,
    /// Classify the rotated logs into review_run.py's categories, scoped
    /// to the given event window — counts only, no content (DASH-04).
    pub review_logs: Box<dyn Fn(Option<i64>, Option<i64>) -> LogReview + Send + Sync>,
    /// macOS TCC grant state, read from the sidecar the pump publishes.
    /// `None` off macOS or before the pump has published — the panel then
    /// does not render. The host reads the file; the dashboard only renders.
    pub read_permission_snapshot: Box<dyn Fn() -> Option<PermissionSnapshot> + Send + Sync>,
    /// Content-free Windows pause-hotkey registration warning, read from the
    /// pump-written sidecar. `None` means registered or deliberately off.
    pub read_pause_hotkey_warning: Box<dyn Fn() -> Option<String> + Send + Sync>,
    /// Windows notification-listener access published by the tray process.
    /// The dashboard is display-only and never requests access.
    pub read_notification_access: Box<dyn Fn() -> Option<NotificationAccessSnapshot> + Send + Sync>,
    /// Emit a permission-panel button action. The host routes it: deep-link
    /// opens go straight to System Settings from the dashboard process (no
    /// TCC); prompt/relaunch actions are written to the request sidecar for
    /// the pump to execute (the only process the TCC record lets prompt).
    pub request_permission_action: Box<dyn Fn(PermissionActionRequest) + Send + Sync>,
    /// The worker's batch clock: sampled once per drained batch and passed
    /// to every builder in it. Production wires `now_ms`; tests script it
    /// so a builder sampling its own fresh clock (at any call site) lands
    /// a later scripted tick and fails the one-clock test (r4-SF-4).
    pub clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

/// Sanitized-error notice-state writer supplied by the owning app.
pub type WriteNoticeState = Box<dyn Fn(&DiscoveryNoticeState) -> Result<(), String> + Send + Sync>;
pub type WriteSphereOverlayEnabled = Box<dyn Fn(bool) -> Result<(), String> + Send + Sync>;
pub type WriteSphereAliases =
    Box<dyn Fn(&BTreeMap<String, String>) -> Result<(), String> + Send + Sync>;
pub type PruneSphereAliases =
    Box<dyn Fn(&HashSet<String>) -> Result<BTreeMap<String, String>, String> + Send + Sync>;
pub type RequestRecording = Box<dyn Fn(&str, &str) -> Result<i64, String> + Send + Sync>;
pub type SaveReplayExport =
    Box<dyn Fn(i64, &str, &HashMap<i64, String>) -> Result<String, ExportSaveError> + Send + Sync>;
#[cfg(windows)]
pub type ListPortableArchiveSources =
    Box<dyn Fn() -> Result<Vec<PortableArchiveSource>, String> + Send + Sync>;
#[cfg(windows)]
pub type ExportPortableArchive =
    Box<dyn Fn(&str, &PortableArchiveExportMode) -> Result<String, String> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(windows)]
pub struct PortableArchiveSource {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(windows)]
pub enum PortableArchiveExportMode {
    Passphrase(String),
    PlaintextAcknowledged,
}
pub type DeleteRecording = Box<dyn Fn(i64) -> Result<RecordingDeleteOutcome, String> + Send + Sync>;
pub type DeleteEvents = Box<dyn Fn(&[i64]) -> Result<EventsDeleteOutcome, String> + Send + Sync>;

/// Which phase of a replay-export save failed: a build failure keeps the
/// Streamlit "database may be busy" framing, a write failure is the
/// native-only file step and names its own cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportSaveError {
    Build(String),
    Write(String),
}

/// `gilbreth_store::DeleteResult` across the host boundary (this crate
/// doesn't depend on the store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingDeleteOutcome {
    pub deleted: usize,
    pub scrub_warning: Option<String>,
}

/// `gilbreth_store::DeleteResult` for the Session tab's per-event delete —
/// the same store shape, named for its own flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventsDeleteOutcome {
    pub deleted: usize,
    pub scrub_warning: Option<String>,
}

pub type WritePrivacySettings =
    Box<dyn Fn(&PrivacySettingsValues) -> Result<(), String> + Send + Sync>;
pub type PrunePreviewFn = Box<dyn Fn(i64) -> Result<PrunePreview, String> + Send + Sync>;
pub type PruneOldEvents = Box<dyn Fn(i64) -> Result<PruneOutcome, String> + Send + Sync>;

/// `gilbreth-app::config::PrivacySettingsRead` across the host boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivacySettingsView {
    pub sensitive_context_suppression: bool,
    pub redact_titles_containing: Vec<String>,
    pub redact_keys_containing: Vec<String>,
    pub excluded_apps: Vec<String>,
    pub store_key_content: bool,
    pub title_retention_days: u64,
    pub mouse_move_retention_days: u64,
    /// Malformed-config detail; when set, the redaction editor is read-only.
    pub error: Option<String>,
}

/// The dashboard-editable privacy values, as saved by the redaction
/// editor (mirrors the Streamlit `PrivacySettings` construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacySettingsValues {
    pub sensitive_context_suppression: bool,
    pub redact_titles_containing: Vec<String>,
    pub redact_keys_containing: Vec<String>,
    pub excluded_apps: Vec<String>,
    pub title_retention_days: u64,
    pub mouse_move_retention_days: u64,
}

/// `gilbreth_store::DashboardPrunePreview` across the host boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePreview {
    pub cutoff_ms: i64,
    pub events: usize,
    pub ended_empty_sessions: usize,
    pub action_events: usize,
    pub ended_empty_record_sessions: usize,
    pub record_requests: usize,
    pub selector_paths: usize,
}

impl PrunePreview {
    pub fn total_rows(&self) -> usize {
        self.events
            + self.ended_empty_sessions
            + self.action_events
            + self.ended_empty_record_sessions
            + self.record_requests
            + self.selector_paths
    }
}

/// `gilbreth_store::DashboardPruneResult` across the host boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneOutcome {
    pub events_deleted: usize,
    pub sessions_deleted: usize,
    pub action_events_deleted: usize,
    pub record_sessions_deleted: usize,
    pub record_requests_deleted: usize,
    pub selector_paths_deleted: usize,
    pub compaction_completed: bool,
    pub compact_error: Option<String>,
}

impl PruneOutcome {
    pub fn total_deleted(&self) -> usize {
        self.events_deleted
            + self.sessions_deleted
            + self.action_events_deleted
            + self.record_sessions_deleted
            + self.record_requests_deleted
            + self.selector_paths_deleted
    }
}

const DAILY_WINDOW_DAYS: i64 = 7;
/// Mirrors `SEQUENCE_MIN_HISTORY_DAYS` for the patterns empty caption
/// (db.py pins 2 — O-3.2e hides sequence work below this many local dates).
pub const SEQUENCE_MIN_HISTORY_DAYS: i64 = 2;
const LAST_7D_MS: i64 = 7 * 86_400_000;
const DAY_MS: i64 = 86_400_000;

/// One coherent read of everything the Today tab renders.
pub struct TodaySnapshot {
    pub generated_at_ms: i64,
    pub today_key: String,
    pub db_missing: bool,
    pub counts: DatabaseCounts,
    pub strip: DayStrip,
    pub story: TodayStory,
    pub pulse: Vec<HourPulse>,
    pub daily: Vec<DayActive>,
    pub notices: Vec<DiscoveryNotice>,
    /// How many candidates the dismiss/mute filters removed, counted by
    /// the reader pre-cap over the same enumeration as `notices` (UX-30:
    /// the "N hidden" indicator and the all-hidden state). Zero when no
    /// filters are set.
    pub hidden_notice_count: usize,
    pub notice_state: DiscoveryNoticeState,
    pub pattern_history_days: i64,
    pub store_key_content: bool,
    /// Independent of activity population: a first-open dashboard can have
    /// already received events and must still show its welcome.
    pub first_run_welcome_dismissed: bool,
    pub error: Option<String>,
}

impl TodaySnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            today_key: gilbreth_read::local_date(now_ms),
            db_missing: true,
            counts: DatabaseCounts {
                sessions: 0,
                events: 0,
                active_sessions: 0,
            },
            strip: DayStrip {
                day_start_ms: now_ms,
                day_end_ms: now_ms,
                focus: Vec::new(),
                away: Vec::new(),
            },
            story: TodayStory {
                active_ms: 0,
                foreground_ms: 0,
                focus_switches: 0,
                keystrokes: 0,
                top_app: None,
                longest_run_app: None,
                longest_run_ms: 0,
                longest_run_start_ms: None,
            },
            pulse: Vec::new(),
            daily: Vec::new(),
            notices: Vec::new(),
            hidden_notice_count: 0,
            notice_state: DiscoveryNoticeState::default(),
            pattern_history_days: 0,
            store_key_content: false,
            // Fail closed if a panic prevents the host-backed read. A fresh
            // install's normal builder path replaces this with `false`.
            first_run_welcome_dismissed: true,
            error: None,
        }
    }
}

/// One coherent read of everything the Week tab renders.
pub struct WeekSnapshot {
    pub generated_at_ms: i64,
    pub db_missing: bool,
    pub digest: WeeklyDigest,
    pub error: Option<String>,
}

impl WeekSnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            db_missing: true,
            digest: WeeklyDigest {
                week_start_ms: now_ms - 7 * DAY_MS,
                now_ms,
                has_prior_week: false,
                active_ms: 0,
                prior_active_ms: 0,
                active_days: 0,
                top_apps: Vec::new(),
                switches_per_active_hour: None,
                prior_switches_per_active_hour: None,
                keystrokes: 0,
                prior_keystrokes: 0,
                friction: Vec::new(),
                morning_launch: Vec::new(),
                morning_launch_days: 0,
                first_after_idle: Vec::new(),
                heatmap: Vec::new(),
                changed_this_week: Vec::new(),
            },
            error: None,
        }
    }
}

/// One coherent read of everything the Session tab renders EXCEPT the
/// Event list, which is snapshot-backed on its own cadence (see
/// [`SessionEventsSnapshot`]).
pub struct SessionSnapshot {
    pub generated_at_ms: i64,
    pub db_missing: bool,
    pub error: Option<String>,
    /// Every session, newest first — the selector rows.
    pub sessions: Vec<SessionRow>,
    /// The selection actually honored: the requested session when it still
    /// exists, otherwise the first (open/latest) row, like the Streamlit
    /// selectbox default.
    pub selected_session_id: Option<i64>,
    pub counts: Vec<EventCountRow>,
    /// `include_titles=false` — the default Time-per-app table and the
    /// story-totals substrate.
    pub focus_apps: Vec<FocusSummaryRow>,
    /// `include_titles=true` — what the "Show window titles" toggle shows.
    /// Both variants ride one snapshot so the toggle flips locally, exactly
    /// the data the Streamlit toggle re-reads.
    pub focus_titles: Vec<FocusSummaryRow>,
    pub story: SessionStoryTotals,
    pub focus_seconds_total: f64,
    pub active_focus_seconds_total: f64,
    /// The `key`-kind rows of `counts`, summed across sources.
    pub key_events: i64,
    pub system_events: Vec<SystemEventRow>,
    pub power_events: Vec<PowerEventRow>,
}

impl SessionSnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            db_missing: true,
            error: None,
            sessions: Vec::new(),
            selected_session_id: None,
            counts: Vec::new(),
            focus_apps: Vec::new(),
            focus_titles: Vec::new(),
            story: SessionStoryTotals {
                top_app: None,
                top_app_active_seconds: 0.0,
                focus_switches: 0,
            },
            focus_seconds_total: 0.0,
            active_focus_seconds_total: 0.0,
            key_events: 0,
            system_events: Vec::new(),
            power_events: Vec::new(),
        }
    }
}

/// The Session tab's Event-list snapshot. Mirrors the Streamlit two-key
/// snapshot cache (`read_event_list_snapshot`): it is rebuilt only by the
/// explicit "Refresh event list" button, a session/database change, or a
/// completed delete — never by a plain tab refresh.
pub struct SessionEventsSnapshot {
    pub generated_at_ms: i64,
    /// The session this list was read for — the cache key.
    pub session_id: i64,
    pub events: Vec<ActivityEventRow>,
    pub error: Option<String>,
}

/// The review pane for one selected recording.
pub struct RecordingDetail {
    pub steps: Vec<RecordingStep>,
    /// Replay readiness from the value-free step metadata plus the operator
    /// allowlist — derived exactly like the native-export gate, so the
    /// banner and the export buttons can never disagree.
    pub verdict: ReplayExportVerdict,
}

/// One coherent read of everything the Recordings tab renders.
pub struct RecordingsSnapshot {
    pub generated_at_ms: i64,
    pub db_missing: bool,
    /// False when the Record Routine tables aren't in this database.
    pub tables_present: bool,
    pub rows: Vec<RecordingRow>,
    /// The selection actually honored — cleared when the requested
    /// recording no longer exists (e.g. it was just deleted).
    pub selected_id: Option<i64>,
    pub detail: Option<RecordingDetail>,
    pub detail_error: Option<String>,
    pub error: Option<String>,
}

impl RecordingsSnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            db_missing: true,
            tables_present: true,
            rows: Vec::new(),
            selected_id: None,
            detail: None,
            detail_error: None,
            error: None,
        }
    }
}

/// review_run.py's `LogSummary` across the host boundary (the classifier
/// lives in `gilbreth-app::health` beside the filesystem it reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogReview {
    pub files: usize,
    pub warning_lines: i64,
    pub error_panic_lines: i64,
    pub clipboard_locked_warning_lines: i64,
    pub orphan_session_repair_warning_lines: i64,
    pub stale_pre_erase_drop_warning_lines: i64,
    pub recovered_focus_warning_lines: i64,
    pub open_focus_discard_warning_lines: i64,
    pub max_events_skipped: i64,
}

impl LogReview {
    pub fn unknown_warning_lines(&self) -> i64 {
        (self.warning_lines
            - self.clipboard_locked_warning_lines
            - self.orphan_session_repair_warning_lines
            - self.stale_pre_erase_drop_warning_lines
            - self.recovered_focus_warning_lines
            - self.open_focus_discard_warning_lines)
            .max(0)
    }

    /// review_run's `LogSummary.healthy`.
    pub fn healthy(&self) -> bool {
        self.unknown_warning_lines() == 0
            && self.error_panic_lines == 0
            && self.max_events_skipped == 0
    }
}

/// One coherent read of everything the Diagnostics tab renders.
pub struct DiagnosticsSnapshot {
    pub generated_at_ms: i64,
    pub db_missing: bool,
    pub error: Option<String>,
    pub debug: Option<DebugLogSnapshot>,
    pub churn: Option<ProcessChurnReport>,
    pub install: Option<InstallStateSnapshot>,
    pub health: Option<DatabaseHealth>,
    /// Log categories scoped to the event span, like review_run.py.
    pub logs: Option<LogReview>,
    /// macOS TCC grant states (Accessibility, Input Monitoring), read from
    /// the sidecar the pump publishes. `None` off macOS (no TCC panel) or
    /// before the pump has published, so the section renders only when the
    /// host actually has grant state to show.
    pub permissions: Option<PermissionSnapshot>,
    /// Persistent warning when Windows could not claim the configured pause
    /// chord. This is independent of database health: the tray fallback
    /// remains available and the run is otherwise healthy.
    pub pause_hotkey_warning: Option<String>,
    /// Configured basenames only — never a usage timestamp or drop count.
    pub excluded_apps: Vec<String>,
    /// Content-free Windows notification access/capability state.
    pub notification_access: Option<NotificationAccessSnapshot>,
    /// Legacy archive count only; filenames and paths never enter the
    /// dashboard model.
    pub legacy_plaintext_archive_count: Option<usize>,
    /// Sanitized inventory failure, separate from database health.
    pub archive_inventory_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationAccessRowState {
    Allowed,
    Unspecified,
    Denied,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationAccessSnapshot {
    pub state: NotificationAccessRowState,
    pub privacy_copy: String,
    pub diagnostics_copy: String,
}

/// Per-permission grant state for the Diagnostics panel (the dashboard
/// mirror of the app's `GrantState`; kept here so gilbreth-dashboard does
/// not depend on gilbreth-app — the host maps between them).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionRowState {
    NotGranted,
    Granted,
    GrantedNeedsRelaunch,
}

/// The two macOS permissions the panel surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    pub accessibility: PermissionRowState,
    pub input_monitoring: PermissionRowState,
}

/// A button action the panel emits. The host decides local-vs-pump: the
/// deep-link opens touch no TCC and open System Settings directly from the
/// dashboard process; the prompt/relaunch actions are written to the
/// request sidecar and executed by the pump (the only process the TCC
/// record allows to prompt).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionActionRequest {
    OpenAccessibilityPane,
    OpenInputMonitoringPane,
    PromptAccessibility,
    PromptInputMonitoring,
    Relaunch,
}

impl DiagnosticsSnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            db_missing: true,
            error: None,
            debug: None,
            churn: None,
            install: None,
            health: None,
            logs: None,
            permissions: None,
            pause_hotkey_warning: None,
            excluded_apps: Vec::new(),
            notification_access: None,
            legacy_plaintext_archive_count: None,
            archive_inventory_error: None,
        }
    }
}

/// The DASH-05 continuity readout: how much detector history exists, from
/// local counts and dates only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityReport {
    /// Distinct local dates with focus activity (detector history).
    pub active_days: i64,
    /// Distinct local focus dates strictly before the digest's rolling
    /// week start (now - 7 days) — the actual numerator the
    /// changed-this-week "new" gate compares against its 14-day floor.
    pub pre_week_focus_days: i64,
    /// Today's weekday name, for the same-weekday line.
    pub weekday_label: String,
    /// Distinct local dates with focus activity on today's weekday.
    pub same_weekday_days: i64,
    /// Local dates of the oldest and newest events in the live database.
    pub first_date: Option<String>,
    pub last_date: Option<String>,
    pub archive_count: usize,
}

/// One coherent read of everything the Privacy tab renders.
pub struct PrivacySnapshot {
    pub generated_at_ms: i64,
    /// Echo of the request generation this read answered. The shell drops
    /// completions older than its latest request so a stale preview can
    /// never replace newer state or re-seed the redaction editor.
    pub generation: u64,
    pub db_missing: bool,
    pub error: Option<String>,
    pub counts: DatabaseCounts,
    pub install: Option<InstallStateSnapshot>,
    pub settings: PrivacySettingsView,
    /// The configured retention default that seeds the prune-days input.
    pub retention_days: i64,
    /// The days value this snapshot's preview was computed for.
    pub prune_days: i64,
    pub preview: Option<PrunePreview>,
    pub preview_error: Option<String>,
    pub continuity: Option<ContinuityReport>,
    #[cfg(windows)]
    pub portable_archive_sources: Vec<PortableArchiveSource>,
    #[cfg(windows)]
    pub portable_archive_error: Option<String>,
    /// Content-free Windows notification access state from the tray sidecar.
    pub notification_access: Option<NotificationAccessSnapshot>,
    /// Rows the suppression rules redacted in the open (or latest) session —
    /// the Settings group's inline suppression state. Count only.
    pub sensitive_rows_this_session: Option<i64>,
}

impl PrivacySnapshot {
    fn empty(now_ms: i64) -> Self {
        Self {
            generated_at_ms: now_ms,
            generation: 0,
            db_missing: true,
            error: None,
            counts: DatabaseCounts {
                sessions: 0,
                events: 0,
                active_sessions: 0,
            },
            install: None,
            settings: PrivacySettingsView::default(),
            retention_days: 90,
            prune_days: 90,
            preview: None,
            preview_error: None,
            continuity: None,
            #[cfg(windows)]
            portable_archive_sources: Vec::new(),
            #[cfg(windows)]
            portable_archive_error: None,
            notification_access: None,
            sensitive_rows_this_session: None,
        }
    }
}

/// The Analytics scope dropdown, mirroring `analytics_scope_options`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScopeKey {
    Last24h,
    Last7d,
    Last30d,
    All,
}

impl ScopeKey {
    pub const OPTIONS: [ScopeKey; 4] = [
        ScopeKey::Last24h,
        ScopeKey::Last7d,
        ScopeKey::Last30d,
        ScopeKey::All,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ScopeKey::Last24h => "Last 24 hours",
            ScopeKey::Last7d => "Last 7 days",
            ScopeKey::Last30d => "Last 30 days",
            ScopeKey::All => "All data",
        }
    }

    fn cutoff_ms(self, now_ms: i64) -> Option<i64> {
        match self {
            ScopeKey::Last24h => Some(now_ms - DAY_MS),
            ScopeKey::Last7d => Some(now_ms - 7 * DAY_MS),
            ScopeKey::Last30d => Some(now_ms - 30 * DAY_MS),
            ScopeKey::All => None,
        }
    }
}

/// What the Analytics tab currently asks for. `scope: None` means "resolve
/// the default" (last 7 days when it has events, otherwise all data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnalyticsSelection {
    pub scope: Option<ScopeKey>,
    pub session_id: Option<i64>,
}

/// One run-selector entry, labeled like `analytics_run_label`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOption {
    pub session_id: i64,
    pub label: String,
}

/// Everything the Analytics tab renders for one scope/run selection.
pub struct AnalyticsData {
    pub session_options: Vec<SessionOption>,
    pub focus: Vec<FocusRollupRow>,
    pub focus_minutes_total: f64,
    pub active_focus_minutes_total: f64,
    pub sessions: Vec<SessionAnalyticsRow>,
    pub inputs: Vec<InputRollupRow>,
    pub lifecycle: Vec<WindowLifecycleRow>,
    pub candidates: Vec<PatternCandidate>,
    pub pattern_history_days: i64,
    pub fragmentation: FragmentationMetrics,
    pub interruption: InterruptionCosts,
    pub input_exposure: InputExposureMetrics,
    pub spheres: SphereSkeleton,
    pub sphere_overlay: Option<SphereOverlay>,
    pub rhythm: RhythmMetrics,
    pub overlay_enabled: bool,
    pub aliases: BTreeMap<String, String>,
}

pub struct AnalyticsSnapshot {
    pub generated_at_ms: i64,
    pub db_missing: bool,
    pub error: Option<String>,
    /// The scope that was actually read (the resolved default on first
    /// open) and the label of the scope it fell back from, if any.
    pub scope: ScopeKey,
    pub fallback_from: Option<&'static str>,
    pub session_id: Option<i64>,
    pub data: Option<AnalyticsData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    RefreshToday,
    RefreshWeek,
    /// The payload is the selected session, if any (`None` resolves the
    /// open/latest default). Does NOT rebuild the Event-list snapshot.
    RefreshSession(Option<i64>),
    /// Rebuild the Event-list snapshot for one session — issued only by the
    /// explicit refresh button, a session change, or a completed delete.
    RefreshSessionEvents(i64),
    RefreshAnalytics(AnalyticsSelection),
    /// The payload is the selected record session, if any.
    RefreshRecordings(Option<i64>),
    /// `days` is the prune-days input; `None` means "the configured
    /// retention default". `generation` is echoed on the snapshot so the
    /// shell can reject completions of outdated requests.
    RefreshPrivacy {
        days: Option<i64>,
        generation: u64,
    },
    RefreshDiagnostics,
}

/// A completed read arriving from the worker thread.
pub enum Snapshot {
    Today(Box<TodaySnapshot>),
    Week(Box<WeekSnapshot>),
    Session(Box<SessionSnapshot>),
    SessionEvents(Box<SessionEventsSnapshot>),
    Analytics(Box<AnalyticsSnapshot>),
    Recordings(Box<RecordingsSnapshot>),
    Privacy(Box<PrivacySnapshot>),
    Diagnostics(Box<DiagnosticsSnapshot>),
}

pub struct DataWorker {
    request_tx: Sender<Request>,
    snapshot_rx: Receiver<Snapshot>,
}

impl DataWorker {
    pub fn spawn(host: Arc<DashboardHost>, ctx: egui::Context) -> Self {
        let (request_tx, request_rx) = std::sync::mpsc::channel::<Request>();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel::<Snapshot>();
        std::thread::Builder::new()
            .name("dashboard-reader".to_owned())
            .spawn(move || {
                let mut pending = PendingReads {
                    today: true,
                    week: false,
                    session: None,
                    session_events: None,
                    analytics: None,
                    recordings: None,
                    privacy: None,
                    diagnostics: false,
                };
                let mut sphere_prune_done = false;
                loop {
                    // One clock per drained batch: tabs built together see
                    // the same "now", so populations that share a rolling
                    // cutoff (Week's digest gate, Privacy's pre-week count)
                    // cannot straddle a floor on microscopic clock skew.
                    // Accepted residual (round-3 review SF-3): snapshots
                    // from DIFFERENT batches keep their own clocks, so a
                    // cached tab can straddle a rolling boundary against a
                    // newer tab until its queued refresh lands — the shell
                    // renders cached state immediately and nothing bounds
                    // that wait to one frame on a slow reader.
                    let batch_now = (host.clock)();
                    // UX-57 (branch review): every build runs under
                    // catch_unwind — a panicking reader becomes that tab's
                    // error snapshot instead of a dead worker thread that
                    // would leave Refresh disabled forever.
                    if pending.today {
                        let snapshot = catch_build(
                            || build_snapshot(&host, batch_now),
                            |error| {
                                let mut fallback = TodaySnapshot::empty(batch_now);
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Today(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if pending.week {
                        let snapshot = catch_build(
                            || build_week_snapshot(&host, batch_now),
                            |error| {
                                let mut fallback = WeekSnapshot::empty(batch_now);
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Week(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some(selection) = pending.session.take() {
                        let snapshot = catch_build(
                            || build_session_snapshot(&host, batch_now, selection),
                            |error| {
                                let mut fallback = SessionSnapshot::empty(batch_now);
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Session(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some(session_id) = pending.session_events.take() {
                        let snapshot = catch_build(
                            || build_session_events_snapshot(&host, batch_now, session_id),
                            |error| SessionEventsSnapshot {
                                generated_at_ms: batch_now,
                                session_id,
                                events: Vec::new(),
                                error: Some(error),
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::SessionEvents(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some(selection) = pending.analytics.take() {
                        let snapshot = catch_build(
                            || {
                                build_analytics_snapshot(
                                    &host,
                                    batch_now,
                                    selection,
                                    &mut sphere_prune_done,
                                )
                            },
                            |error| AnalyticsSnapshot {
                                generated_at_ms: batch_now,
                                db_missing: false,
                                error: Some(error),
                                scope: selection.scope.unwrap_or(ScopeKey::Last7d),
                                fallback_from: None,
                                session_id: selection.session_id,
                                data: None,
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Analytics(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some(selected) = pending.recordings.take() {
                        let snapshot = catch_build(
                            || build_recordings_snapshot(&host, batch_now, selected),
                            |error| {
                                let mut fallback = RecordingsSnapshot::empty(batch_now);
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Recordings(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Some((days, generation)) = pending.privacy.take() {
                        let snapshot = catch_build(
                            || build_privacy_snapshot(&host, batch_now, days, generation),
                            |error| {
                                let mut fallback = PrivacySnapshot::empty(batch_now);
                                fallback.generation = generation;
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Privacy(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    if pending.diagnostics {
                        let snapshot = catch_build(
                            || build_diagnostics_snapshot(&host, batch_now),
                            |error| {
                                let mut fallback = DiagnosticsSnapshot::empty(batch_now);
                                fallback.db_missing = false;
                                fallback.error = Some(error);
                                fallback
                            },
                        );
                        if snapshot_tx
                            .send(Snapshot::Diagnostics(Box::new(snapshot)))
                            .is_err()
                        {
                            return;
                        }
                    }
                    ctx.request_repaint();
                    pending.today = false;
                    pending.week = false;
                    pending.diagnostics = false;
                    // Wait for an explicit refresh or the periodic tick (the
                    // short timer belongs to Today only, per the S4 runtime
                    // conventions); drain any burst into one read per tab.
                    match request_rx.recv_timeout(Duration::from_secs(30)) {
                        Ok(request) => apply_request(request, &mut pending),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => pending.today = true,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                    while let Ok(request) = request_rx.try_recv() {
                        apply_request(request, &mut pending);
                    }
                }
            })
            .expect("dashboard reader thread spawns");
        Self {
            request_tx,
            snapshot_rx,
        }
    }

    /// Test double: the same channels the shell sends on and polls from,
    /// with no reader thread behind them. Tests drain the returned
    /// receiver to observe exactly what was delivered to the worker
    /// boundary, and push snapshots through the returned sender to
    /// exercise the real poll/adoption path.
    pub fn stub_for_tests() -> (Self, std::sync::mpsc::Receiver<Request>, Sender<Snapshot>) {
        let (request_tx, request_rx) = std::sync::mpsc::channel::<Request>();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel::<Snapshot>();
        (
            Self {
                request_tx,
                snapshot_rx,
            },
            request_rx,
            snapshot_tx,
        )
    }

    /// Returns whether the request reached the worker channel — a failed
    /// send must not mark the tab in flight (branch review, UX-57).
    pub fn request(&self, request: Request) -> bool {
        self.request_tx.send(request).is_ok()
    }

    /// Drain every snapshot the worker has finished since the last poll.
    pub fn poll(&self) -> Vec<Snapshot> {
        let mut arrived = Vec::new();
        while let Ok(snapshot) = self.snapshot_rx.try_recv() {
            arrived.push(snapshot);
        }
        arrived
    }
}

struct PendingReads {
    today: bool,
    week: bool,
    /// Last-wins; the inner value is the selected session.
    session: Option<Option<i64>>,
    /// Last-wins; the inner value is the session whose Event list rebuilds.
    session_events: Option<i64>,
    /// Last-wins across a drained burst: the newest selection is the truth.
    analytics: Option<AnalyticsSelection>,
    /// Last-wins like analytics; the inner value is the selected recording.
    recordings: Option<Option<i64>>,
    /// Last-wins; the inner value is (prune-days input, request generation).
    privacy: Option<(Option<i64>, u64)>,
    diagnostics: bool,
}

fn apply_request(request: Request, pending: &mut PendingReads) {
    match request {
        Request::RefreshToday => pending.today = true,
        Request::RefreshWeek => pending.week = true,
        Request::RefreshSession(selected) => pending.session = Some(selected),
        Request::RefreshSessionEvents(session_id) => pending.session_events = Some(session_id),
        Request::RefreshAnalytics(selection) => pending.analytics = Some(selection),
        Request::RefreshRecordings(selected) => pending.recordings = Some(selected),
        Request::RefreshPrivacy { days, generation } => pending.privacy = Some((days, generation)),
        Request::RefreshDiagnostics => pending.diagnostics = true,
    }
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// UX-57 (branch review): run one snapshot build, converting a panic into
/// the tab's error snapshot so the reader thread survives and the shell's
/// in-flight state always clears.
fn catch_build<T>(build: impl FnOnce() -> T, fallback: impl FnOnce(String) -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)) {
        Ok(snapshot) => snapshot,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            fallback(format!(
                "The dashboard reader hit an internal error and recovered. \
                 Technical detail: {detail}"
            ))
        }
    }
}

fn build_snapshot(host: &DashboardHost, now_ms: i64) -> TodaySnapshot {
    let mut snapshot = TodaySnapshot::empty(now_ms);
    snapshot.store_key_content = (host.store_key_content)();
    snapshot.first_run_welcome_dismissed = (host.read_first_run_welcome_dismissed)();
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        snapshot.counts = read_database_counts(&conn)?;
        snapshot.strip = day_strip(&conn, now_ms)?;
        snapshot.story = today_story(&conn, now_ms)?;
        snapshot.pulse = hourly_input_pulse(&conn, now_ms)?;
        snapshot.daily = daily_active_minutes(&conn, DAILY_WINDOW_DAYS, now_ms)?;

        let state = (host.read_notice_state)();
        // UX-30 (branch review): the hidden count comes from the reader,
        // pre-cap, over the same enumeration (and backfill population) the
        // visible list came from — never a difference of capped lengths.
        let (notices, hidden_count) =
            gilbreth_read::discovery_notices_with_hidden_count_default_limit(
                &conn,
                now_ms,
                Some(&state),
                None,
            )?;
        snapshot.notices = notices;
        snapshot.hidden_notice_count = hidden_count;
        snapshot.notice_state = state;

        // Mirrors `resolve_default_analytics_scope`: last-7-days when it has
        // events, otherwise all data.
        let last_7d = Scope {
            cutoff_ms: Some(now_ms - LAST_7D_MS),
            session_id: None,
        };
        let recent_events: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE ts >= ?1",
            [now_ms - LAST_7D_MS],
            |row| row.get(0),
        )?;
        let scope = if recent_events > 0 {
            last_7d
        } else {
            Scope {
                cutoff_ms: None,
                session_id: None,
            }
        };
        snapshot.pattern_history_days = pattern_history_days(&conn, &scope)?;
        Ok(())
    })();
    if let Err(error) = result {
        snapshot.error = Some(format!("Couldn't read today's activity: {error}"));
    }
    snapshot
}

fn short_sha(value: &str) -> Option<&str> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    Some(&text[..text.len().min(12)])
}

/// Mirrors `analytics_run_label` + `compact_datetime`: "Session {id}:
/// {YYYY-MM-DD HH:MM} [{sha12}]".
fn session_options(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<SessionOption>> {
    let mut stmt = conn.prepare(
        "SELECT s.session_id,
                datetime(s.started_at / 1000, 'unixepoch', 'localtime'),
                COALESCE(s.git_sha, '')
         FROM sessions s
         ORDER BY s.started_at DESC, s.session_id DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut options = Vec::new();
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let started_at: String = row.get(1)?;
        let git_sha: String = row.get(2)?;
        let compact: String = started_at.chars().take(16).collect();
        let mut label = format!("Session {session_id}: {compact}");
        if let Some(sha) = short_sha(&git_sha) {
            label = format!("{label} [{sha}]");
        }
        options.push(SessionOption { session_id, label });
    }
    Ok(options)
}

fn event_count_for_cutoff(
    conn: &rusqlite::Connection,
    cutoff_ms: Option<i64>,
) -> rusqlite::Result<i64> {
    match cutoff_ms {
        Some(cutoff) => conn.query_row(
            "SELECT COUNT(*) FROM events WHERE ts >= ?1",
            [cutoff],
            |row| row.get(0),
        ),
        None => conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)),
    }
}

fn build_analytics_snapshot(
    host: &DashboardHost,
    now_ms: i64,
    selection: AnalyticsSelection,
    sphere_prune_done: &mut bool,
) -> AnalyticsSnapshot {
    let mut snapshot = AnalyticsSnapshot {
        generated_at_ms: now_ms,
        db_missing: true,
        error: None,
        scope: selection.scope.unwrap_or(ScopeKey::Last7d),
        fallback_from: None,
        session_id: selection.session_id,
        data: None,
    };
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    let result: rusqlite::Result<AnalyticsData> = (|| {
        // Mirrors `resolve_default_analytics_scope` on the first read: last
        // 7 days when it has events, otherwise all data with the fallback
        // caption naming the empty scope.
        let (scope_key, fallback_from) = match selection.scope {
            Some(key) => (key, None),
            None => {
                let last_7d = ScopeKey::Last7d;
                if event_count_for_cutoff(&conn, last_7d.cutoff_ms(now_ms))? > 0 {
                    (last_7d, None)
                } else if event_count_for_cutoff(&conn, None)? > 0 {
                    (ScopeKey::All, Some(last_7d.label()))
                } else {
                    (last_7d, None)
                }
            }
        };
        snapshot.scope = scope_key;
        snapshot.fallback_from = fallback_from;
        let scope = Scope {
            cutoff_ms: scope_key.cutoff_ms(now_ms),
            session_id: selection.session_id,
        };

        let overlay_enabled = (host.read_sphere_overlay_enabled)();
        let mut aliases = BTreeMap::new();
        let mut sphere_overlay = None;
        if overlay_enabled {
            aliases = (host.read_sphere_aliases)();
            // Once per dashboard session: age out alias keys whose source
            // titles are gone; on failure keep the unpruned map (retried
            // next launch), mirroring the Streamlit handler.
            if !aliases.is_empty() && !*sphere_prune_done {
                *sphere_prune_done = true;
                let live = live_sphere_tokens(&conn)?;
                if let Ok(pruned) = (host.prune_sphere_aliases)(&live) {
                    aliases = pruned;
                }
            }
            let alias_map: HashMap<String, String> = aliases
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            sphere_overlay = Some(working_spheres_overlay(&conn, &scope, &alias_map)?);
        }

        // One input-run sweep for the whole snapshot: exposure, the
        // candidate detectors, and the friction windows all consume the
        // same result instead of each re-scanning the events table (the
        // 2026-07-28 timing finding: three sweeps per Analytics load).
        let (shared_runs, shared_counts) = gilbreth_read::input_runs_and_counts(&conn, &scope)?;
        let focus_context = gilbreth_read::focus_cost_context(&conn, &scope)?;
        Ok(AnalyticsData {
            session_options: session_options(&conn)?,
            focus: focus_rollup(&conn, &scope)?,
            focus_minutes_total: focus_minutes_total(&conn, &scope)?,
            active_focus_minutes_total: active_focus_minutes_total(&conn, &scope)?,
            sessions: session_analytics(&conn, &scope)?,
            inputs: input_rollup(&conn, &scope)?,
            lifecycle: window_lifecycle_rollup(&conn, &scope)?,
            candidates: gilbreth_read::patterns_worth_reviewing_with(&conn, &scope, &shared_runs)?,
            pattern_history_days: pattern_history_days(&conn, &scope)?,
            fragmentation: gilbreth_read::fragmentation_metrics_with(&focus_context),
            interruption: gilbreth_read::interruption_costs_with(&focus_context),
            input_exposure: gilbreth_read::input_exposure_metrics_with(
                &conn,
                &scope,
                &shared_runs,
                &shared_counts,
            )?,
            spheres: working_spheres_skeleton(&conn, &scope)?,
            sphere_overlay,
            rhythm: gilbreth_read::rhythm_metrics_with(
                &conn,
                &scope,
                now_ms,
                &shared_runs,
                &focus_context,
            )?,
            overlay_enabled,
            aliases,
        })
    })();
    match result {
        Ok(data) => snapshot.data = Some(data),
        Err(error) => {
            snapshot.error = Some(format!("Couldn't read your analytics: {error}"));
        }
    }
    snapshot
}

fn build_recordings_snapshot(
    host: &DashboardHost,
    now_ms: i64,
    selected: Option<i64>,
) -> RecordingsSnapshot {
    let mut snapshot = RecordingsSnapshot::empty(now_ms);
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    let list = match read_recordings(&conn, now_ms) {
        Ok(list) => list,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't read your recordings: {error}"));
            return snapshot;
        }
    };
    snapshot.tables_present = list.record_routine_tables_present;
    snapshot.rows = list.rows;
    snapshot.selected_id =
        selected.filter(|id| snapshot.rows.iter().any(|row| row.record_session_id == *id));
    if let Some(record_session_id) = snapshot.selected_id {
        let detail: rusqlite::Result<RecordingDetail> = (|| {
            let steps = read_recording_steps(&conn, record_session_id)?;
            // The verdict reads the same value-free step projection the
            // export builder re-derives internally.
            let verdict_steps = read_recording_export_steps(&conn, record_session_id, false)?;
            let verified = (host.verified_framework_classes)();
            Ok(RecordingDetail {
                verdict: recording_replay_verdict(&verdict_steps, &verified),
                steps,
            })
        })();
        match detail {
            Ok(detail) => snapshot.detail = Some(detail),
            Err(error) => {
                snapshot.detail_error = Some(format!("Couldn't read the recording steps: {error}"));
            }
        }
    }
    snapshot
}

/// Mirrors `cutoff_ms_for_days`: at least one day back from now.
fn cutoff_ms_for_days(days: i64, now_ms: i64) -> i64 {
    now_ms - days.max(1) * DAY_MS
}

/// Test seam: run the real Today reader stack over a fixture database, so
/// integration tests can assert copy and cards against reader-built
/// snapshots instead of hand-injected ones.
pub fn build_today_snapshot_for_tests(host: &DashboardHost, now_ms: i64) -> TodaySnapshot {
    build_snapshot(host, now_ms)
}

/// Test seam: the real Privacy reader stack (retention-default days,
/// generation 0).
pub fn build_privacy_snapshot_for_tests(host: &DashboardHost, now_ms: i64) -> PrivacySnapshot {
    build_privacy_snapshot(host, now_ms, None, 0)
}

/// Test seam: the real Diagnostics reader stack (UX-06 pins that one
/// failing section reader no longer drops the others).
pub fn build_diagnostics_snapshot_for_tests(
    host: &DashboardHost,
    now_ms: i64,
) -> DiagnosticsSnapshot {
    build_diagnostics_snapshot(host, now_ms)
}

fn continuity_report(
    host: &DashboardHost,
    conn: &rusqlite::Connection,
    now_ms: i64,
) -> rusqlite::Result<ContinuityReport> {
    use chrono::Datelike;
    let all_scope = Scope {
        cutoff_ms: None,
        session_id: None,
    };
    let active_days = pattern_history_days(conn, &all_scope)?;
    let local_now = chrono::DateTime::from_timestamp_millis(now_ms)
        .map(|utc| utc.with_timezone(&chrono::Local))
        .unwrap_or_else(chrono::Local::now);
    let weekday = local_now.weekday();
    // SQLite's %w and chrono's num_days_from_sunday share 0 = Sunday.
    let same_weekday_days: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT date(ts / 1000, 'unixepoch', 'localtime'))
         FROM events
         WHERE kind = 'focus_changed'
           AND CAST(strftime('%w', ts / 1000, 'unixepoch', 'localtime') AS INTEGER) = ?1",
        [weekday.num_days_from_sunday() as i64],
        |row| row.get(0),
    )?;
    let span: (Option<i64>, Option<i64>) =
        conn.query_row("SELECT MIN(ts), MAX(ts) FROM events", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    // The same population digest_changed_this_week gates "new" flags on:
    // distinct local focus dates strictly before the rolling week start
    // (weekly_digest_core pins week_start = now - 7 days).
    let pre_week_focus_days: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT date(ts / 1000, 'unixepoch', 'localtime'))
         FROM events WHERE kind = 'focus_changed' AND ts < ?1",
        [now_ms - 7 * DAY_MS],
        |row| row.get(0),
    )?;
    Ok(ContinuityReport {
        active_days,
        pre_week_focus_days,
        weekday_label: format!("{}", local_now.format("%A")),
        same_weekday_days,
        first_date: span.0.map(gilbreth_read::local_date),
        last_date: span.1.map(gilbreth_read::local_date),
        archive_count: (host.archive_count)(),
    })
}

fn build_privacy_snapshot(
    host: &DashboardHost,
    now_ms: i64,
    days: Option<i64>,
    generation: u64,
) -> PrivacySnapshot {
    let mut snapshot = PrivacySnapshot::empty(now_ms);
    snapshot.generation = generation;
    snapshot.settings = (host.read_privacy_settings)();
    snapshot.notification_access = (host.read_notification_access)();
    #[cfg(windows)]
    match (host.list_portable_archive_sources)() {
        Ok(sources) => snapshot.portable_archive_sources = sources,
        Err(error) => snapshot.portable_archive_error = Some(error),
    }
    snapshot.retention_days = (host.read_retention_days)();
    snapshot.prune_days = days.unwrap_or(snapshot.retention_days).clamp(1, 3650);
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        snapshot.counts = read_database_counts(&conn)?;
        let (command, command_error) = (host.autostart_command)();
        let mut install = gilbreth_read::read_install_state(
            &conn,
            &host.db_path,
            command,
            gilbreth_read::DB_SIZE_WARNING_BYTES,
            gilbreth_read::WAL_SIZE_WARNING_BYTES,
        )?;
        install.autostart_error = command_error;
        snapshot.install = Some(install);
        snapshot.continuity = Some(continuity_report(host, &conn, now_ms)?);
        // The suppression state line: redacted rows in the open (or latest)
        // session, matching the Diagnostics reader's session choice.
        let session_id: Option<i64> = conn
            .query_row(
                "SELECT session_id FROM sessions ORDER BY (ended_at IS NULL) DESC, session_id \
                 DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        if let Some(session_id) = session_id {
            snapshot.sensitive_rows_this_session = Some(conn.query_row(
                "SELECT COUNT(*) FROM events WHERE session_id = ? AND is_sensitive != 0",
                [session_id],
                |row| row.get(0),
            )?);
        }
        Ok(())
    })();
    if let Err(error) = result {
        snapshot.error = Some(format!("Couldn't read your data overview: {error}"));
    }
    match (host.prune_preview)(cutoff_ms_for_days(snapshot.prune_days, now_ms)) {
        Ok(preview) => snapshot.preview = Some(preview),
        Err(error) => snapshot.preview_error = Some(error),
    }
    snapshot
}

fn build_diagnostics_snapshot(host: &DashboardHost, now_ms: i64) -> DiagnosticsSnapshot {
    let mut snapshot = DiagnosticsSnapshot::empty(now_ms);
    snapshot.pause_hotkey_warning = (host.read_pause_hotkey_warning)();
    snapshot.excluded_apps = (host.read_privacy_settings)().excluded_apps;
    snapshot.notification_access = (host.read_notification_access)();
    match (host.read_legacy_plaintext_archive_count)() {
        Ok(count) => snapshot.legacy_plaintext_archive_count = Some(count),
        Err(error) => snapshot.archive_inventory_error = Some(error),
    }
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    // UX-06: each section reads independently, so one failing reader can
    // no longer drop the DASH-04 verdict (or any other section) with it.
    let mut errors: Vec<String> = Vec::new();
    match read_debug_log(&conn, &host.db_path, now_ms) {
        Ok(debug) => snapshot.debug = Some(debug),
        Err(error) => errors.push(format!("recorder status: {error}")),
    }
    match read_process_churn(&conn, 7, now_ms) {
        Ok(churn) => snapshot.churn = Some(churn),
        Err(error) => errors.push(format!("process churn: {error}")),
    }
    let (command, command_error) = (host.autostart_command)();
    match gilbreth_read::read_install_state(
        &conn,
        &host.db_path,
        command,
        gilbreth_read::DB_SIZE_WARNING_BYTES,
        gilbreth_read::WAL_SIZE_WARNING_BYTES,
    ) {
        Ok(mut install) => {
            install.autostart_error = command_error;
            snapshot.install = Some(install);
        }
        Err(error) => errors.push(format!("install state: {error}")),
    }
    match database_health(&conn) {
        Ok(health) => {
            // review_run.py scopes timestamped log lines to the event span.
            snapshot.logs = Some((host.review_logs)(health.min_ts, health.max_ts));
            snapshot.health = Some(health);
        }
        Err(error) => errors.push(format!("health check: {error}")),
    }
    // TCC grant state (macOS only; None off macOS, so the section is absent
    // on Windows). A file read, not a DB read — no error is surfaced, a
    // missing/unreadable sidecar simply hides the panel.
    snapshot.permissions = (host.read_permission_snapshot)();
    if !errors.is_empty() {
        snapshot.error = Some(format!(
            "{DIAGNOSTICS_PARTIAL_READ_PREFIX}{}",
            errors.join("; ")
        ));
    }
    snapshot
}

/// The Diagnostics partial-read banner prefix (the joined reader errors
/// follow it).
// copy-allow: em-dash prose em dash within the one-per-string cap (the one-per-string cap), recorded by the Lane B audit
const DIAGNOSTICS_PARTIAL_READ_PREFIX: &str = "Couldn't read part of the diagnostics — ";

fn build_week_snapshot(host: &DashboardHost, now_ms: i64) -> WeekSnapshot {
    let mut snapshot = WeekSnapshot::empty(now_ms);
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    match weekly_digest(&conn, now_ms) {
        Ok(digest) => snapshot.digest = digest,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't read this week's activity: {error}"));
        }
    }
    snapshot
}

fn build_session_snapshot(
    host: &DashboardHost,
    now_ms: i64,
    selection: Option<i64>,
) -> SessionSnapshot {
    let mut snapshot = SessionSnapshot::empty(now_ms);
    if !host.db_path.exists() {
        return snapshot;
    }
    snapshot.db_missing = false;
    let conn = match open_readonly(&host.db_path) {
        Ok(conn) => conn,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't open the activity database: {error}"));
            return snapshot;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        snapshot.sessions = read_sessions(&conn)?;
        // The stored selection when its session still exists, else the
        // first row — the open/latest session, like the Streamlit default.
        snapshot.selected_session_id = selection
            .filter(|id| snapshot.sessions.iter().any(|row| row.session_id == *id))
            .or_else(|| snapshot.sessions.first().map(|row| row.session_id));
        let Some(session_id) = snapshot.selected_session_id else {
            return Ok(());
        };
        snapshot.counts = read_event_counts(&conn, session_id)?;
        snapshot.key_events = snapshot
            .counts
            .iter()
            .filter(|row| row.kind == "key")
            .map(|row| row.events)
            .sum();
        snapshot.focus_apps = read_focus_summary(&conn, session_id, false)?;
        snapshot.focus_titles = read_focus_summary(&conn, session_id, true)?;
        snapshot.story = session_story_totals(&snapshot.focus_apps);
        snapshot.focus_seconds_total = read_session_focus_seconds_total(&conn, session_id)?;
        snapshot.active_focus_seconds_total =
            read_session_active_focus_seconds_total(&conn, session_id)?;
        snapshot.system_events = read_system_events(&conn, session_id)?;
        snapshot.power_events = read_power_events(&conn, session_id)?;
        Ok(())
    })();
    if let Err(error) = result {
        snapshot.error = Some(format!("Couldn't read your events: {error}"));
    }
    snapshot
}

fn build_session_events_snapshot(
    host: &DashboardHost,
    now_ms: i64,
    session_id: i64,
) -> SessionEventsSnapshot {
    let mut snapshot = SessionEventsSnapshot {
        generated_at_ms: now_ms,
        session_id,
        events: Vec::new(),
        error: None,
    };
    if !host.db_path.exists() {
        return snapshot;
    }
    let result: rusqlite::Result<Vec<ActivityEventRow>> =
        open_readonly(&host.db_path).and_then(|conn| read_activity_events(&conn, session_id));
    match result {
        Ok(events) => snapshot.events = events,
        Err(error) => {
            snapshot.error = Some(format!("Couldn't read your events: {error}"));
        }
    }
    snapshot
}

/// Test seam: the real Session reader stack over a fixture database.
pub fn build_session_snapshot_for_tests(
    host: &DashboardHost,
    now_ms: i64,
    selection: Option<i64>,
) -> SessionSnapshot {
    build_session_snapshot(host, now_ms, selection)
}

/// Test seam: the real Event-list reader stack over a fixture database.
pub fn build_session_events_snapshot_for_tests(
    host: &DashboardHost,
    now_ms: i64,
    session_id: i64,
) -> SessionEventsSnapshot {
    build_session_events_snapshot(host, now_ms, session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host whose callbacks all succeed over a nonexistent database.
    fn stub_host() -> DashboardHost {
        DashboardHost {
            db_path: PathBuf::from("Z:/nonexistent/gilbreth.db"),
            ui_state_path: std::env::temp_dir().join("gilbreth-data-test-ui.ron"),
            ui_state_persistence: UiStatePersistence::Owner,
            window_icon: None,
            store_key_content: Box::new(|| false),
            read_first_run_welcome_dismissed: Box::new(|| true),
            dismiss_first_run_welcome: Box::new(|| Ok(())),
            read_notice_state: Box::new(DiscoveryNoticeState::default),
            write_notice_state: Box::new(|_| Ok(())),
            read_sphere_overlay_enabled: Box::new(|| false),
            write_sphere_overlay_enabled: Box::new(|_| Ok(())),
            read_sphere_aliases: Box::new(BTreeMap::new),
            write_sphere_aliases: Box::new(|_| Ok(())),
            prune_sphere_aliases: Box::new(|_| Ok(BTreeMap::new())),
            request_recording: Box::new(|_, _| Ok(1)),
            record_request_status: Box::new(|_| None),
            spheres_sidecar_name: "spheres.json".to_string(),
            casefold_token: Box::new(|token| token.to_lowercase()),
            config_path: PathBuf::from("Z:/nonexistent/config.toml"),
            verified_framework_classes: Box::new(HashSet::new),
            save_replay_export: Box::new(|_, _, _| Err(ExportSaveError::Build("stub".into()))),
            #[cfg(windows)]
            list_portable_archive_sources: Box::new(|| Ok(Vec::new())),
            #[cfg(windows)]
            export_portable_archive: Box::new(|_, _| Err("stub".to_string())),
            delete_recording: Box::new(|_| {
                Ok(RecordingDeleteOutcome {
                    deleted: 0,
                    scrub_warning: None,
                })
            }),
            delete_events: Box::new(|_| {
                Ok(EventsDeleteOutcome {
                    deleted: 0,
                    scrub_warning: None,
                })
            }),
            read_privacy_settings: Box::new(PrivacySettingsView::default),
            write_privacy_settings: Box::new(|_| Ok(())),
            read_retention_days: Box::new(|| 90),
            prune_preview: Box::new(|cutoff_ms| {
                Ok(PrunePreview {
                    cutoff_ms,
                    events: 0,
                    ended_empty_sessions: 0,
                    action_events: 0,
                    ended_empty_record_sessions: 0,
                    record_requests: 0,
                    selector_paths: 0,
                })
            }),
            prune_old_events: Box::new(|_| {
                Ok(PruneOutcome {
                    events_deleted: 0,
                    sessions_deleted: 0,
                    action_events_deleted: 0,
                    record_sessions_deleted: 0,
                    record_requests_deleted: 0,
                    selector_paths_deleted: 0,
                    compaction_completed: true,
                    compact_error: None,
                })
            }),
            autostart_command: Box::new(|| (None, None)),
            archive_count: Box::new(|| 0),
            read_legacy_plaintext_archive_count: Box::new(|| Ok(0)),
            review_logs: Box::new(|_, _| LogReview::default()),
            read_permission_snapshot: Box::new(|| None),
            read_pause_hotkey_warning: Box::new(|| None),
            read_notification_access: Box::new(|| None),
            request_permission_action: Box::new(|_| {}),
            clock: Box::new(now_ms),
        }
    }

    #[test]
    fn today_reads_the_welcome_flag_independently_of_activity_storage() {
        let mut host = stub_host();
        host.read_first_run_welcome_dismissed = Box::new(|| false);

        let snapshot = build_snapshot(&host, 123);

        assert!(snapshot.db_missing);
        assert!(!snapshot.first_run_welcome_dismissed);
    }

    #[test]
    fn diagnostics_reads_legacy_archive_count_without_a_live_database() {
        let mut host = stub_host();
        host.read_legacy_plaintext_archive_count = Box::new(|| Ok(4));

        let snapshot = build_diagnostics_snapshot(&host, 123);

        assert!(snapshot.db_missing);
        assert_eq!(snapshot.legacy_plaintext_archive_count, Some(4));
        assert!(snapshot.archive_inventory_error.is_none());
    }

    /// r3-SF-3 / r4-SF-4: every builder in one drained batch receives the
    /// batch's single clock sample, so populations with rolling cutoffs
    /// (Week's digest gate, Privacy's pre-week count) cannot straddle a
    /// floor on clock skew. The host clock is scripted to step 100 s per
    /// sample, so ANY builder handed its own fresh sample — through the
    /// seam or the OS clock — lands a value 100 s (or epochs) away from
    /// its batchmates and fails deterministically, Today included; no
    /// sleep-based separation. The parked first Today build guarantees
    /// all eight requests land in a single drain, and arrival itself is
    /// asserted (r5-SF-1): a build arm that stops sending its snapshot
    /// fails the seven-snapshot count instead of deadline-spinning to a
    /// pass. UX-62 extended the batch with the Session tab's two arms
    /// (the tab snapshot and its separately-requested Event list).
    #[test]
    fn worker_builds_one_drained_batch_on_one_clock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("gilbreth.db");
        {
            // A real migrated (empty) database so every build runs its
            // reader stack and host callbacks instead of early-returning.
            let _store =
                gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
        }
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate_rx = std::sync::Mutex::new(gate_rx);
        let mut host = stub_host();
        host.db_path = db_path;
        host.store_key_content = Box::new(move || {
            let _ = gate_rx.lock().expect("gate lock").recv();
            false
        });
        // Sample N is BASE + N * 100_000: realistic epoch magnitude, and
        // two samplings inside one batch differ by 100 s.
        let ticks = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let clock_ticks = ticks.clone();
        host.clock = Box::new(move || {
            1_783_584_000_000
                + clock_ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) * 100_000
        });
        let worker = DataWorker::spawn(Arc::new(host), egui::Context::default());
        // Queue one request per tab (plus the Session tab's separate
        // Event-list read) while the first Today build is parked, so all
        // eight coalesce into the next drained batch.
        worker.request(Request::RefreshToday);
        worker.request(Request::RefreshWeek);
        worker.request(Request::RefreshSession(None));
        worker.request(Request::RefreshSessionEvents(1));
        worker.request(Request::RefreshAnalytics(AnalyticsSelection::default()));
        worker.request(Request::RefreshRecordings(None));
        worker.request(Request::RefreshPrivacy {
            days: None,
            generation: 1,
        });
        worker.request(Request::RefreshDiagnostics);
        // Two tokens: the parked initial Today build, then the batched one.
        gate_tx.send(()).expect("release the initial build");
        gate_tx.send(()).expect("release the batched build");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut today_clocks = Vec::new();
        let mut clocks = BTreeMap::new();
        while (today_clocks.len() < 2 || clocks.len() < 7) && std::time::Instant::now() < deadline {
            for snapshot in worker.poll() {
                match snapshot {
                    Snapshot::Today(today) => today_clocks.push(today.generated_at_ms),
                    Snapshot::Week(week) => {
                        clocks.insert("week", week.generated_at_ms);
                    }
                    Snapshot::Session(session) => {
                        clocks.insert("session", session.generated_at_ms);
                    }
                    Snapshot::SessionEvents(events) => {
                        clocks.insert("session-events", events.generated_at_ms);
                    }
                    Snapshot::Analytics(analytics) => {
                        clocks.insert("analytics", analytics.generated_at_ms);
                    }
                    Snapshot::Recordings(recordings) => {
                        clocks.insert("recordings", recordings.generated_at_ms);
                    }
                    Snapshot::Privacy(privacy) => {
                        clocks.insert("privacy", privacy.generated_at_ms);
                    }
                    Snapshot::Diagnostics(diagnostics) => {
                        clocks.insert("diagnostics", diagnostics.generated_at_ms);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(today_clocks.len(), 2, "both Today builds arrive");
        assert_eq!(
            clocks.len(),
            7,
            "all seven queued snapshots must arrive (six tabs beyond Today \
             plus the Session Event list) — a deleted build arm fails here \
             instead of deadline-spinning to a pass (r5-SF-1)"
        );
        let batch_clock = today_clocks[1];
        assert_ne!(
            today_clocks[0], batch_clock,
            "the two batches sample distinct scripted ticks"
        );
        for (tab, clock) in clocks {
            assert_eq!(
                clock, batch_clock,
                "the {tab} snapshot must carry the one drained batch's clock"
            );
        }
        assert_eq!(
            ticks.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "exactly one clock sample per drained batch"
        );
    }

    /// UX-57 (branch review): a panic inside a build becomes that tab's
    /// error snapshot and the worker thread survives to serve the next
    /// request — a dead reader thread would leave Refresh disabled
    /// forever with a perpetual "updating…" cue.
    #[test]
    fn worker_survives_a_panicking_build() {
        let mut host = stub_host();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_counter = calls.clone();
        host.store_key_content = Box::new(move || {
            if call_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                panic!("injected build panic");
            }
            false
        });
        let worker = DataWorker::spawn(Arc::new(host), egui::Context::default());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut first = None;
        while first.is_none() && std::time::Instant::now() < deadline {
            for snapshot in worker.poll() {
                if let Snapshot::Today(snapshot) = snapshot {
                    first = Some(*snapshot);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let first = first.expect("the panicking build still yields a snapshot");
        let error = first.error.expect("the panic surfaces as the tab error");
        assert!(
            error.contains("internal error") && error.contains("injected build panic"),
            "unexpected error text: {error}"
        );
        // The thread is alive: the next request is delivered and served.
        assert!(
            worker.request(Request::RefreshToday),
            "the worker channel must still be open after the panic"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut second = None;
        while second.is_none() && std::time::Instant::now() < deadline {
            for snapshot in worker.poll() {
                if let Snapshot::Today(snapshot) = snapshot {
                    second = Some(*snapshot);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let second = second.expect("the worker thread survives the panic");
        assert!(second.error.is_none(), "the recovered build reads cleanly");
    }

    /// r4-SF-3: the channel stub proves delivery; this proves consumption.
    /// A Privacy burst drained by the REAL worker coalesces last-wins, and
    /// the built snapshot carries the newest days and generation — a
    /// worker that discards the delivered days (falling back to the config
    /// default) or keeps the first request of a burst fails here.
    #[test]
    fn worker_coalesces_a_privacy_burst_to_the_newest_request() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("gilbreth.db");
        {
            let _store =
                gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
        }
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate_rx = std::sync::Mutex::new(gate_rx);
        let mut host = stub_host();
        host.db_path = db_path;
        host.store_key_content = Box::new(move || {
            let _ = gate_rx.lock().expect("gate lock").recv();
            false
        });
        let worker = DataWorker::spawn(Arc::new(host), egui::Context::default());
        // Both requests sit behind the parked initial Today build, so the
        // worker drains them as one burst.
        worker.request(Request::RefreshPrivacy {
            days: Some(90),
            generation: 16,
        });
        worker.request(Request::RefreshPrivacy {
            days: Some(3650),
            generation: 17,
        });
        gate_tx.send(()).expect("release the worker");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut privacy = None;
        while privacy.is_none() && std::time::Instant::now() < deadline {
            for snapshot in worker.poll() {
                if let Snapshot::Privacy(snapshot) = snapshot {
                    privacy = Some(snapshot);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let privacy = privacy.expect("the coalesced privacy snapshot arrives");
        assert_eq!(
            (privacy.prune_days, privacy.generation),
            (3650, 17),
            "the drained burst must build once, from the newest days and generation"
        );
    }
}
