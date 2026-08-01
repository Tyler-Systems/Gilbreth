pub mod copy_style;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt::Write as _,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossbeam_channel::{bounded, Sender};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

pub const SCHEMA_VERSION: u16 = 1;
pub const EXCLUDED_APP_GAP_PATTERN: &str = "excluded_app_gap";
pub const EXCLUDED_APP_GAP_LABEL: &str = "Steps in an excluded app were not recorded.";

#[derive(Clone, Debug)]
pub struct DiagnosticsCounters {
    power_boundary_catches: Arc<AtomicU64>,
    // Capture-side events dropped because the bounded channel to the writer
    // was full. This is distinct from the writer's `events_skipped` (dedup /
    // stream-off skips): a full channel means data the capture layer produced
    // never reached the writer at all, so `events_skipped = 0` alone does not
    // prove zero loss. Surfaced so the health story stays honest.
    capture_events_dropped: Arc<AtomicU64>,
    // Writer-side motion rows that arrived after secure erase completed but
    // whose capture timestamp predates the erase boundary. These are dropped
    // deliberately: privacy wins over retaining an in-flight stale row.
    stale_pre_erase_rows_dropped: Arc<AtomicU64>,
}

impl DiagnosticsCounters {
    pub fn new() -> Self {
        Self {
            power_boundary_catches: Arc::new(AtomicU64::new(0)),
            capture_events_dropped: Arc::new(AtomicU64::new(0)),
            stale_pre_erase_rows_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn increment_power_boundary_catches(&self) {
        self.power_boundary_catches.fetch_add(1, Ordering::SeqCst);
    }

    pub fn power_boundary_catches(&self) -> u64 {
        self.power_boundary_catches.load(Ordering::SeqCst)
    }

    pub fn increment_capture_events_dropped(&self) {
        self.capture_events_dropped.fetch_add(1, Ordering::SeqCst);
    }

    pub fn capture_events_dropped(&self) -> u64 {
        self.capture_events_dropped.load(Ordering::SeqCst)
    }

    pub fn increment_stale_pre_erase_rows_dropped(&self) -> u64 {
        self.stale_pre_erase_rows_dropped
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1)
    }

    pub fn stale_pre_erase_rows_dropped(&self) -> u64 {
        self.stale_pre_erase_rows_dropped.load(Ordering::SeqCst)
    }
}

impl Default for DiagnosticsCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("capture channel closed")]
    ChannelClosed,
    #[error("windows api error: {0}")]
    WindowsApi(String),
    #[error("source error: {0}")]
    Source(#[source] Box<dyn Error + Send + Sync>),
}

#[derive(Clone, Debug)]
pub struct StopToken {
    cancelled: Arc<AtomicBool>,
}

impl StopToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for StopToken {
    fn default() -> Self {
        Self::new()
    }
}

pub trait EventSource: Send {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError>;
}

// --- Capture control surface (moved verbatim from gilbreth-capture-windows
// at MAC-0). This is the portable per-stream toggle / suspension / reseed /
// sensitive-field-gate state every per-OS capture backend shares with the
// app; only the pump machinery behind it is platform code. The re-exports in
// gilbreth-capture-windows keep its public API unchanged.

pub const DEFAULT_IDLE_THRESHOLD_MS: u64 = 3 * 60 * 1000;

/// Cadence of the writer's `open_focus` heartbeat (the foreground-heartbeat
/// design, 2026-07-12 owner decision 4): a crash mid-segment loses at most
/// one beat of open-segment dwell (a crash inside the close path's
/// delete-then-flush window can still lose that whole segment — the
/// deliberate trade, since the reverse order would double-count), and
/// readers treat a row as live only while its high-water mark is within two
/// beats of the read. Shared here because the writer (gilbreth-store) beats
/// on it and the readers (gilbreth-read) apply the freshness rule against
/// it.
pub const OPEN_FOCUS_BEAT_MS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureStream {
    Foreground,
    Windows,
    Keyboard,
    Mouse,
    System,
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureSettings {
    pub foreground: bool,
    pub windows: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub system: bool,
    pub idle: bool,
    pub idle_threshold_ms: u64,
    /// Background-process churn filter (demote, don't discard): process
    /// start/exit rows are kept only for apps the user has actually focused;
    /// everything else is counted into periodic churn summaries instead of
    /// being written row-by-row.
    pub process_filter: bool,
}

impl CaptureSettings {
    pub fn all_enabled() -> Self {
        Self {
            foreground: true,
            windows: true,
            keyboard: true,
            mouse: true,
            system: true,
            idle: true,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        }
    }

    pub fn enabled(self, stream: CaptureStream) -> bool {
        match stream {
            CaptureStream::Foreground => self.foreground,
            CaptureStream::Windows => self.windows,
            CaptureStream::Keyboard => self.keyboard,
            CaptureStream::Mouse => self.mouse,
            CaptureStream::System => self.system,
            CaptureStream::Idle => self.idle,
        }
    }
}

impl Default for CaptureSettings {
    fn default() -> Self {
        Self::all_enabled()
    }
}

#[derive(Debug)]
pub struct SensitiveFieldProbeRequest {
    pub reply: Sender<Option<SensitiveFieldProbeResult>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensitiveFieldProbeResult {
    pub is_password: bool,
    pub focus_generation: u64,
}

const SENSITIVE_TRANSITION_GENERATION_STEP: u64 = 1 << 32;
const SENSITIVE_TRANSITION_ACTIVE_MASK: u64 = u32::MAX as u64;

pub struct SensitiveTransitionPending {
    state: Arc<AtomicU64>,
}

impl Drop for SensitiveTransitionPending {
    fn drop(&mut self) {
        self.state.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct CaptureControls {
    foreground: Arc<AtomicBool>,
    windows: Arc<AtomicBool>,
    keyboard: Arc<AtomicBool>,
    mouse: Arc<AtomicBool>,
    system: Arc<AtomicBool>,
    idle: Arc<AtomicBool>,
    suspended: Arc<AtomicBool>,
    reseed_generation: Arc<AtomicU64>,
    redact_titles_on_next_reseed: Arc<AtomicBool>,
    password_field_active: Arc<AtomicBool>,
    password_field_confirmed_active: Arc<AtomicBool>,
    sensitive_reconcile_pending: Arc<AtomicBool>,
    sensitive_resume_serialization: Arc<Mutex<()>>,
    sensitive_resume_barrier: Arc<AtomicBool>,
    sensitive_transition_state: Arc<AtomicU64>,
    password_focus_generation: Arc<AtomicU64>,
    sensitive_field_probe: Arc<Mutex<Option<Sender<SensitiveFieldProbeRequest>>>>,
    diagnostics: DiagnosticsCounters,
    idle_threshold_ms: u64,
    process_filter: Arc<AtomicBool>,
    foreground_seen: Arc<Mutex<HashSet<String>>>,
    excluded_apps: Arc<HashSet<String>>,
    excluded_notification_keys: Arc<HashSet<String>>,
}

impl CaptureControls {
    pub fn new(settings: CaptureSettings) -> Self {
        Self {
            foreground: Arc::new(AtomicBool::new(settings.foreground)),
            windows: Arc::new(AtomicBool::new(settings.windows)),
            keyboard: Arc::new(AtomicBool::new(settings.keyboard)),
            mouse: Arc::new(AtomicBool::new(settings.mouse)),
            system: Arc::new(AtomicBool::new(settings.system)),
            idle: Arc::new(AtomicBool::new(settings.idle)),
            suspended: Arc::new(AtomicBool::new(false)),
            reseed_generation: Arc::new(AtomicU64::new(0)),
            redact_titles_on_next_reseed: Arc::new(AtomicBool::new(false)),
            password_field_active: Arc::new(AtomicBool::new(false)),
            password_field_confirmed_active: Arc::new(AtomicBool::new(false)),
            sensitive_reconcile_pending: Arc::new(AtomicBool::new(false)),
            sensitive_resume_serialization: Arc::new(Mutex::new(())),
            sensitive_resume_barrier: Arc::new(AtomicBool::new(false)),
            sensitive_transition_state: Arc::new(AtomicU64::new(0)),
            password_focus_generation: Arc::new(AtomicU64::new(0)),
            sensitive_field_probe: Arc::new(Mutex::new(None)),
            diagnostics: DiagnosticsCounters::new(),
            idle_threshold_ms: settings.idle_threshold_ms.max(1),
            process_filter: Arc::new(AtomicBool::new(settings.process_filter)),
            foreground_seen: Arc::new(Mutex::new(HashSet::new())),
            excluded_apps: Arc::new(HashSet::new()),
            excluded_notification_keys: Arc::new(HashSet::new()),
        }
    }

    pub fn all_enabled() -> Self {
        Self::new(CaptureSettings::all_enabled())
    }

    pub fn set_enabled(&self, stream: CaptureStream, enabled: bool) {
        self.flag(stream).store(enabled, Ordering::SeqCst);
    }

    pub fn enabled(&self, stream: CaptureStream) -> bool {
        self.flag(stream).load(Ordering::SeqCst)
    }

    pub fn settings(&self) -> CaptureSettings {
        CaptureSettings {
            foreground: self.enabled(CaptureStream::Foreground),
            windows: self.enabled(CaptureStream::Windows),
            keyboard: self.enabled(CaptureStream::Keyboard),
            mouse: self.enabled(CaptureStream::Mouse),
            system: self.enabled(CaptureStream::System),
            idle: self.enabled(CaptureStream::Idle),
            idle_threshold_ms: self.idle_threshold_ms,
            process_filter: self.process_filter_enabled(),
        }
    }

    pub fn process_filter_enabled(&self) -> bool {
        self.process_filter.load(Ordering::SeqCst)
    }

    pub fn set_process_filter_enabled(&self, enabled: bool) {
        self.process_filter.store(enabled, Ordering::SeqCst);
    }

    /// Record that an exe has held foreground focus. The process-churn filter
    /// keeps lifecycle rows only for these apps (the crash-signature rescue:
    /// an app the user actually works in keeps its start/exit evidence).
    pub fn note_foreground_exe(&self, exe: &str) {
        let basename = exe_basename_lower(exe);
        if basename.is_empty() {
            return;
        }
        if let Ok(mut seen) = self.foreground_seen.lock() {
            seen.insert(basename);
        }
    }

    pub fn foreground_exe_seen(&self, basename: &str) -> bool {
        self.foreground_seen
            .lock()
            .map(|seen| seen.contains(basename))
            .unwrap_or(false)
    }

    pub fn with_excluded_apps<I, S>(mut self, apps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let excluded_apps: HashSet<_> = apps
            .into_iter()
            .map(|app| exe_basename_lower(app.as_ref()))
            .filter(|app| !app.is_empty())
            .collect();
        self.excluded_notification_keys = Arc::new(
            excluded_apps
                .iter()
                .map(|app| notification_match_key(app))
                .collect(),
        );
        self.excluded_apps = Arc::new(excluded_apps);
        self
    }

    pub fn app_excluded(&self, exe: &str) -> bool {
        self.excluded_apps.contains(&exe_basename_lower(exe))
    }

    pub fn has_app_exclusions(&self) -> bool {
        !self.excluded_apps.is_empty()
    }

    /// Notification source metadata is a display label, PFN, or AUMID rather
    /// than a verified executable identity. Match only when that label itself
    /// aligns with an exclusion after the documented extension-agnostic
    /// normalization; callers must not infer an exe mapping from it.
    pub fn notification_app_excluded(&self, label: &str) -> bool {
        self.excluded_notification_keys
            .contains(&notification_match_key(label))
    }

    pub fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Ordering::SeqCst);
    }

    pub fn is_suspended(&self) -> bool {
        self.sensitive_transition_should_defer() || self.sensitive_transition_active()
    }

    pub fn request_reseed(&self) -> u64 {
        self.reseed_generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn request_title_redacted_reseed(&self) -> u64 {
        self.redact_titles_on_next_reseed
            .store(true, Ordering::SeqCst);
        self.request_reseed()
    }

    pub fn reseed_generation(&self) -> u64 {
        self.reseed_generation.load(Ordering::SeqCst)
    }

    pub fn take_title_redaction_for_reseed(&self) -> bool {
        self.redact_titles_on_next_reseed
            .swap(false, Ordering::SeqCst)
    }

    pub fn password_field_active(&self) -> bool {
        self.password_field_active.load(Ordering::SeqCst)
    }

    pub fn password_field_confirmed_active(&self) -> bool {
        self.password_field_confirmed_active.load(Ordering::SeqCst)
    }

    pub fn set_password_field_gate(&self, active: bool) {
        self.password_field_active.store(active, Ordering::SeqCst);
    }

    /// The shared flag behind `password_field_active()`, for capture backends
    /// that wire it into their sensitive-field plumbing.
    pub fn password_field_active_flag(&self) -> Arc<AtomicBool> {
        self.password_field_active.clone()
    }

    /// The shared flag behind `password_field_confirmed_active()`.
    pub fn password_field_confirmed_active_flag(&self) -> Arc<AtomicBool> {
        self.password_field_confirmed_active.clone()
    }

    pub fn request_sensitive_context_reconcile(&self) {
        self.sensitive_reconcile_pending
            .store(true, Ordering::SeqCst);
    }

    pub fn take_sensitive_context_reconcile(&self) -> bool {
        self.sensitive_reconcile_pending
            .swap(false, Ordering::SeqCst)
    }

    /// Serialize a sensitive-context transition with the final resume drain
    /// and producer reopen. Only transition producers and the rare resume
    /// path take this guard; ordinary capture callbacks remain lock-free.
    pub fn sensitive_resume_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.sensitive_resume_serialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Gate ordinary capture while a sensitive-context producer updates its
    /// state and queues the corresponding writer-policy boundary. The active
    /// count is announced before the producer waits for resume serialization,
    /// so an already-waiting transition cannot be overtaken after reopen.
    pub fn begin_sensitive_transition(&self) -> SensitiveTransitionPending {
        self.sensitive_transition_state
            .fetch_add(SENSITIVE_TRANSITION_GENERATION_STEP + 1, Ordering::SeqCst);
        SensitiveTransitionPending {
            state: self.sensitive_transition_state.clone(),
        }
    }

    pub fn sensitive_transition_should_defer(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
            || self.sensitive_resume_barrier.load(Ordering::SeqCst)
    }

    pub fn set_sensitive_resume_barrier(&self, blocked: bool) {
        self.sensitive_resume_barrier
            .store(blocked, Ordering::SeqCst);
    }

    pub fn sensitive_transition_active(&self) -> bool {
        self.sensitive_transition_state.load(Ordering::SeqCst) & SENSITIVE_TRANSITION_ACTIVE_MASK
            != 0
    }

    pub fn sensitive_transition_generation(&self) -> u64 {
        self.sensitive_transition_state.load(Ordering::SeqCst)
            >> SENSITIVE_TRANSITION_GENERATION_STEP.trailing_zeros()
    }

    /// The shared focus-generation counter behind `password_focus_generation()`.
    pub fn password_focus_generation_counter(&self) -> Arc<AtomicU64> {
        self.password_focus_generation.clone()
    }

    #[doc(hidden)]
    pub fn mark_password_focus_changed(&self) -> u64 {
        self.password_focus_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    pub fn password_focus_generation(&self) -> u64 {
        self.password_focus_generation.load(Ordering::SeqCst)
    }

    pub fn set_sensitive_field_probe(&self, probe: Option<Sender<SensitiveFieldProbeRequest>>) {
        match self.sensitive_field_probe.lock() {
            Ok(mut current) => *current = probe,
            Err(error) => warn!(%error, "sensitive-field probe mutex poisoned"),
        }
    }

    pub fn probe_password_field_active(
        &self,
        timeout: Duration,
    ) -> Option<SensitiveFieldProbeResult> {
        let probe = match self.sensitive_field_probe.lock() {
            Ok(current) => current.clone(),
            Err(error) => {
                warn!(%error, "sensitive-field probe mutex poisoned");
                None
            }
        }?;
        let (reply_tx, reply_rx) = bounded(1);
        if probe
            .try_send(SensitiveFieldProbeRequest { reply: reply_tx })
            .is_err()
        {
            return None;
        }
        reply_rx.recv_timeout(timeout).ok().flatten()
    }

    pub fn diagnostics(&self) -> DiagnosticsCounters {
        self.diagnostics.clone()
    }

    pub fn idle_threshold(&self) -> Duration {
        Duration::from_millis(self.idle_threshold_ms)
    }

    pub fn enabled_for(&self, captured: &Captured) -> bool {
        !self.is_suspended() && self.enabled(stream_for(captured))
    }

    fn flag(&self, stream: CaptureStream) -> &AtomicBool {
        match stream {
            CaptureStream::Foreground => &self.foreground,
            CaptureStream::Windows => &self.windows,
            CaptureStream::Keyboard => &self.keyboard,
            CaptureStream::Mouse => &self.mouse,
            CaptureStream::System => &self.system,
            CaptureStream::Idle => &self.idle,
        }
    }
}

impl Default for CaptureControls {
    fn default() -> Self {
        Self::all_enabled()
    }
}

pub fn stream_for(captured: &Captured) -> CaptureStream {
    match captured.source {
        Source::Foreground => CaptureStream::Foreground,
        Source::Window => CaptureStream::Windows,
        Source::Keyboard => CaptureStream::Keyboard,
        Source::Mouse => CaptureStream::Mouse,
        Source::System => match &captured.payload {
            EventPayload::Idle { .. } | EventPayload::Active { .. } => CaptureStream::Idle,
            EventPayload::SystemInfo { .. }
            | EventPayload::VirtualScreen { .. }
            | EventPayload::ProcessStarted { .. }
            | EventPayload::ProcessExited { .. }
            | EventPayload::PowerSuspend { .. }
            | EventPayload::PowerResume { .. }
            | EventPayload::PowerBoundaryRecovered { .. }
            | EventPayload::SessionLock { .. }
            | EventPayload::SessionUnlock { .. }
            | EventPayload::SessionConnect { .. }
            | EventPayload::SessionDisconnect { .. }
            | EventPayload::ClipboardUsed { .. } => CaptureStream::System,
            EventPayload::SensitiveContextEntered { .. }
            | EventPayload::SensitiveContextExited { .. } => CaptureStream::System,
            _ => CaptureStream::System,
        },
    }
}

pub fn exe_basename_lower(exe: &str) -> String {
    exe.rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe)
        .trim()
        .to_lowercase()
}

/// Notification source metadata is not a verified executable identity. Keep
/// literal label matching extension-agnostic so `private` and `private.exe`
/// align, without claiming that a DisplayName, PFN, or AUMID maps to an exe.
fn notification_match_key(label: &str) -> String {
    let basename = exe_basename_lower(label);
    basename
        .strip_suffix(".exe")
        .unwrap_or(&basename)
        .to_string()
}

#[derive(Clone, Debug)]
pub struct Captured {
    pub source: Source,
    pub captured_at: Instant,
    pub payload: EventPayload,
}

impl Captured {
    pub fn new(source: Source, captured_at: Instant, payload: EventPayload) -> Self {
        Self {
            source,
            captured_at,
            payload,
        }
    }
}

#[derive(Clone, Debug)]
pub enum WriterInput {
    Motion(Captured),
    Action(ActionCapture),
    ActionDiag(ActionDiag),
    RejectedAction(RejectedAction),
}

impl From<Captured> for WriterInput {
    fn from(captured: Captured) -> Self {
        Self::Motion(captured)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditCommitSignal {
    CompositionFinalized,
    FocusLoss,
    Enter,
    Tab,
    Stop,
    Cap,
    Idle,
}

impl EditCommitSignal {
    pub const ALL: [Self; 7] = [
        Self::CompositionFinalized,
        Self::FocusLoss,
        Self::Enter,
        Self::Tab,
        Self::Stop,
        Self::Cap,
        Self::Idle,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompositionFinalized => "composition_finalized",
            Self::FocusLoss => "focus_loss",
            Self::Enter => "enter",
            Self::Tab => "tab",
            Self::Stop => "stop",
            Self::Cap => "cap",
            Self::Idle => "idle",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown edit commit signal: {value}")]
pub struct EditCommitSignalParseError {
    value: String,
}

impl FromStr for EditCommitSignal {
    type Err = EditCommitSignalParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "composition_finalized" => Ok(Self::CompositionFinalized),
            "focus_loss" => Ok(Self::FocusLoss),
            "enter" => Ok(Self::Enter),
            "tab" => Ok(Self::Tab),
            "stop" => Ok(Self::Stop),
            "cap" => Ok(Self::Cap),
            "idle" => Ok(Self::Idle),
            _ => Err(EditCommitSignalParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectedActionReason {
    NullElement,
    WindowMismatch,
    SelectorCaptureFailed,
    TrustRejected,
    ElevatedOrUipiDenied,
    NonActionableElement,
    BenignNoAction,
}

impl RejectedActionReason {
    pub const ALL: [Self; 7] = [
        Self::NullElement,
        Self::WindowMismatch,
        Self::SelectorCaptureFailed,
        Self::TrustRejected,
        Self::ElevatedOrUipiDenied,
        Self::NonActionableElement,
        Self::BenignNoAction,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullElement => "null_element",
            Self::WindowMismatch => "window_mismatch",
            Self::SelectorCaptureFailed => "selector_capture_failed",
            Self::TrustRejected => "trust_rejected",
            Self::ElevatedOrUipiDenied => "elevated_or_uipi_denied",
            Self::NonActionableElement => "non_actionable_element",
            Self::BenignNoAction => "benign_no_action",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown rejected action reason: {value}")]
pub struct RejectedActionReasonParseError {
    value: String,
}

impl FromStr for RejectedActionReason {
    type Err = RejectedActionReasonParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "null_element" => Ok(Self::NullElement),
            "window_mismatch" => Ok(Self::WindowMismatch),
            "selector_capture_failed" => Ok(Self::SelectorCaptureFailed),
            "trust_rejected" => Ok(Self::TrustRejected),
            "elevated_or_uipi_denied" => Ok(Self::ElevatedOrUipiDenied),
            "non_actionable_element" => Ok(Self::NonActionableElement),
            "benign_no_action" => Ok(Self::BenignNoAction),
            _ => Err(RejectedActionReasonParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDiag {
    pub record_session_id: i64,
    pub worker_ordinal: u64,
    pub event_kind: String,
    pub callback_latency_ns: u64,
    pub event_to_selector_complete_ns: u64,
    pub queue_depth_at_enqueue: usize,
    pub repeat_count: u32,
    pub edit_commit_signal: Option<EditCommitSignal>,
    pub trust_basis: Option<SelectorTrustBasis>,
    pub action_type: Option<ActionType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedAction {
    pub record_session_id: i64,
    pub worker_ordinal: u64,
    pub event_kind: String,
    pub captured_at: Instant,
    pub reason: RejectedActionReason,
    pub trust_basis: Option<SelectorTrustBasis>,
    pub callback_latency_ns: u64,
    pub event_to_selector_complete_ns: u64,
    pub queue_depth_at_enqueue: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Foreground,
    Window,
    Keyboard,
    Mouse,
    System,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Foreground => "foreground",
            Source::Window => "window",
            Source::Keyboard => "keyboard",
            Source::Mouse => "mouse",
            Source::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Invoke,
    Toggle,
    Select,
    ExpandCollapse,
    EditCommitted,
    Scroll,
    UiActionOther,
}

impl ActionType {
    pub const ALL: [Self; 7] = [
        Self::Invoke,
        Self::Toggle,
        Self::Select,
        Self::ExpandCollapse,
        Self::EditCommitted,
        Self::Scroll,
        Self::UiActionOther,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::Toggle => "toggle",
            Self::Select => "select",
            Self::ExpandCollapse => "expand_collapse",
            Self::EditCommitted => "edit_committed",
            Self::Scroll => "scroll",
            Self::UiActionOther => "ui_action_other",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown action type: {value}")]
pub struct ActionTypeParseError {
    value: String,
}

impl FromStr for ActionType {
    type Err = ActionTypeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "toggle" => Ok(Self::Toggle),
            "select" => Ok(Self::Select),
            "expand_collapse" => Ok(Self::ExpandCollapse),
            "edit_committed" => Ok(Self::EditCommitted),
            "scroll" => Ok(Self::Scroll),
            "ui_action_other" => Ok(Self::UiActionOther),
            _ => Err(ActionTypeParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordRequestStatus {
    Requested,
    Confirmed,
    Started,
    Expired,
    Cancelled,
    Failed,
}

impl RecordRequestStatus {
    pub const ALL: [Self; 6] = [
        Self::Requested,
        Self::Confirmed,
        Self::Started,
        Self::Expired,
        Self::Cancelled,
        Self::Failed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Confirmed => "confirmed",
            Self::Started => "started",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown record request status: {value}")]
pub struct RecordRequestStatusParseError {
    value: String,
}

impl FromStr for RecordRequestStatus {
    type Err = RecordRequestStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "requested" => Ok(Self::Requested),
            "confirmed" => Ok(Self::Confirmed),
            "started" => Ok(Self::Started),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            _ => Err(RecordRequestStatusParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStopReason {
    UserStop,
    PanicHotkey,
    SafetyCapStop,
    AppShutdown,
    Error,
}

impl RecordStopReason {
    pub const ALL: [Self; 5] = [
        Self::UserStop,
        Self::PanicHotkey,
        Self::SafetyCapStop,
        Self::AppShutdown,
        Self::Error,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserStop => "user_stop",
            Self::PanicHotkey => "panic_hotkey",
            Self::SafetyCapStop => "safety_cap_stop",
            Self::AppShutdown => "app_shutdown",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown record stop reason: {value}")]
pub struct RecordStopReasonParseError {
    value: String,
}

impl FromStr for RecordStopReason {
    type Err = RecordStopReasonParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user_stop" => Ok(Self::UserStop),
            "panic_hotkey" => Ok(Self::PanicHotkey),
            "safety_cap_stop" => Ok(Self::SafetyCapStop),
            "app_shutdown" => Ok(Self::AppShutdown),
            "error" => Ok(Self::Error),
            _ => Err(RecordStopReasonParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectorPath {
    pub backend: String,
    pub hops: Vec<SelectorPathHop>,
}

impl SelectorPath {
    pub fn serialize_v1(&self) -> String {
        serialize_selector_path_v1(self)
    }

    pub fn hash_v1(&self) -> String {
        selector_path_hash_v1(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectorPathHop {
    pub control_type: i32,
    pub automation_id: String,
    pub class_name: String,
    pub ordinal: u32,
}

pub fn serialize_selector_path_v1(path: &SelectorPath) -> String {
    let mut output = String::from("gilbreth.selector_path.v1\nbackend=");
    push_selector_escaped(&mut output, &path.backend);
    for (index, hop) in path.hops.iter().enumerate() {
        write!(
            output,
            "\nhop={index}|control_type={}|automation_id=",
            hop.control_type
        )
        .expect("write to string");
        push_selector_escaped(&mut output, &hop.automation_id);
        output.push_str("|class_name=");
        push_selector_escaped(&mut output, &hop.class_name.to_lowercase());
        write!(output, "|ordinal={}", hop.ordinal).expect("write to string");
    }
    output
}

pub fn selector_path_hash_v1(path: &SelectorPath) -> String {
    let digest = Sha256::digest(serialize_selector_path_v1(path).as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(output, "{byte:02x}").expect("write to string");
    }
    output
}

fn push_selector_escaped(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '|' => output.push_str("\\|"),
            _ => output.push(ch),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorTrustBasis {
    PidMatch,
    WindowOwnership,
    ScopedInvokeSender,
}

impl SelectorTrustBasis {
    pub const ALL: [Self; 3] = [
        Self::PidMatch,
        Self::WindowOwnership,
        Self::ScopedInvokeSender,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PidMatch => "pid_match",
            Self::WindowOwnership => "window_ownership",
            Self::ScopedInvokeSender => "scoped_invoke_sender",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown selector trust basis: {value}")]
pub struct SelectorTrustBasisParseError {
    value: String,
}

impl FromStr for SelectorTrustBasis {
    type Err = SelectorTrustBasisParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pid_match" => Ok(Self::PidMatch),
            "window_ownership" => Ok(Self::WindowOwnership),
            "scoped_invoke_sender" => Ok(Self::ScopedInvokeSender),
            _ => Err(SelectorTrustBasisParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AutomationAction {
    pub action_type: ActionType,
    pub selector_path: SelectorPath,
    pub trust_basis: SelectorTrustBasis,
}

#[derive(Clone, Debug)]
pub struct ActionCapture {
    pub action: AutomationAction,
    pub captured_at: Instant,
    pub record_session_id: i64,
    pub exe: Option<String>,
    pub is_sensitive: bool,
    pub has_name: bool,
    pub pattern_action: Option<String>,
    pub framework: String,
    pub framework_class: FrameworkClass,
    pub depth: u32,
    pub leaf_rect: Option<String>,
    pub payload: ActionPayload,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActionCaptureWire {
    pub action: AutomationAction,
    pub captured_unix_ms: i64,
    pub record_session_id: i64,
    pub exe: Option<String>,
    pub is_sensitive: bool,
    pub has_name: bool,
    pub pattern_action: Option<String>,
    pub framework: String,
    pub framework_class: FrameworkClass,
    pub depth: u32,
    pub leaf_rect: Option<String>,
    pub payload: ActionPayload,
}

impl ActionCaptureWire {
    pub fn from_capture(capture: &ActionCapture) -> Self {
        let now_instant = Instant::now();
        let now_unix_ms = unix_now_ms();
        Self::from_capture_at(
            capture,
            instant_to_unix_ms(capture.captured_at, now_instant, now_unix_ms),
        )
    }

    pub fn from_capture_at(capture: &ActionCapture, captured_unix_ms: i64) -> Self {
        Self {
            action: capture.action.clone(),
            captured_unix_ms,
            record_session_id: capture.record_session_id,
            exe: capture.exe.clone(),
            is_sensitive: capture.is_sensitive,
            has_name: capture.has_name,
            pattern_action: capture.pattern_action.clone(),
            framework: capture.framework.clone(),
            framework_class: capture.framework_class,
            depth: capture.depth,
            leaf_rect: capture.leaf_rect.clone(),
            payload: capture.payload.clone(),
        }
    }

    pub fn into_capture(self) -> ActionCapture {
        let now_instant = Instant::now();
        let now_unix_ms = unix_now_ms();
        self.into_capture_at(now_instant, now_unix_ms)
    }

    pub fn into_capture_at(self, now_instant: Instant, now_unix_ms: i64) -> ActionCapture {
        ActionCapture {
            action: self.action,
            captured_at: unix_ms_to_instant(self.captured_unix_ms, now_instant, now_unix_ms),
            record_session_id: self.record_session_id,
            exe: self.exe,
            is_sensitive: self.is_sensitive,
            has_name: self.has_name,
            pattern_action: self.pattern_action,
            framework: self.framework,
            framework_class: self.framework_class,
            depth: self.depth,
            leaf_rect: self.leaf_rect,
            payload: self.payload,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordRoutineIpcMessage {
    Ready {
        schema: String,
        record_session_id: i64,
        helper_pid: u32,
        transport: String,
    },
    Action {
        action: ActionCaptureWire,
    },
    RunSummary {
        record_session_id: i64,
        stopped: bool,
        stop_reason: RecordStopReason,
        actions_forwarded: u64,
    },
    Error {
        record_session_id: i64,
        message: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordRoutineIpcControl {
    Stop { record_session_id: i64 },
    KeepAlive { record_session_id: i64 },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StampedAction {
    pub session_id: i64,
    pub seq: u64,
    pub ts_unix_ms: i64,
    pub action: AutomationAction,
    pub record_session_id: i64,
    pub exe: Option<String>,
    pub is_sensitive: bool,
    pub has_name: bool,
    pub pattern_action: Option<String>,
    pub framework: String,
    pub framework_class: FrameworkClass,
    pub depth: u32,
    pub leaf_rect: Option<String>,
    pub payload: ActionPayload,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameworkClass {
    Native,
    NativeProvisional,
    WebRenderer,
    Virtualized,
    Unknown,
}

impl FrameworkClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::NativeProvisional => "native_provisional",
            Self::WebRenderer => "web_renderer",
            Self::Virtualized => "virtualized",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("unknown framework class: {value}")]
pub struct FrameworkClassParseError {
    value: String,
}

impl FromStr for FrameworkClass {
    type Err = FrameworkClassParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "native" => Ok(Self::Native),
            "native_provisional" => Ok(Self::NativeProvisional),
            "web_renderer" => Ok(Self::WebRenderer),
            "virtualized" => Ok(Self::Virtualized),
            "unknown" => Ok(Self::Unknown),
            _ => Err(FrameworkClassParseError {
                value: value.to_string(),
            }),
        }
    }
}

pub fn framework_class_from_id(framework_id: &str) -> FrameworkClass {
    let normalized = framework_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return FrameworkClass::Unknown;
    }
    match normalized.as_str() {
        "win32" | "wpf" | "windowsforms" | "xaml" | "uia" | "directui" => FrameworkClass::Native,
        "qt" | "qt5" | "qt6" => FrameworkClass::NativeProvisional,
        "chrome" | "chromium" | "cef" | "electron" | "webview2" | "mshtml" | "firefox" | "edge" => {
            FrameworkClass::WebRenderer
        }
        "citrix" | "rdp" | "remote" | "vnc" | "vmware" => FrameworkClass::Virtualized,
        _ => FrameworkClass::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Mouse,
    Keyboard,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToggleActionState {
    On,
    Off,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpandCollapseActionState {
    Expanded,
    Collapsed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Up,
    Down,
    Left,
    Right,
    Horizontal,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionPayload {
    Invoke {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    Toggle {
        to_state: ToggleActionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    Select {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selection_size: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        in_set_of: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    ExpandCollapse {
        to_state: ExpandCollapseActionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    EditCommitted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    Scroll {
        direction: ScrollDirection,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        amount_bucket: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
    UiActionOther {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw_pattern_id: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_modality: Option<Modality>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corroborates: Option<i64>,
    },
}

#[derive(Debug, Error)]
pub enum AutomationClientError {
    #[error("automation unavailable: {0}")]
    Unavailable(String),
    #[error("automation source error: {0}")]
    Source(#[source] Box<dyn Error + Send + Sync>),
}

pub trait AutomationClient: Send + Sync {
    fn next_action(&self) -> Result<Option<AutomationAction>, AutomationClientError>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub schema_version: u16,
    pub session_id: i64,
    pub seq: u64,
    pub ts_unix_ms: i64,
    pub source: Source,
    pub is_sensitive: bool,
    pub payload: EventPayload,
}

impl EventEnvelope {
    pub fn kind(&self) -> &'static str {
        self.payload.kind()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    FocusChanged {
        window: WindowRef,
        prev: Option<WindowRef>,
        previous_focused_for_ms: u64,
        window_unfocused_for_ms: u64,
        /// True only on a row synthesized by startup or archive repair from
        /// an orphaned `open_focus` heartbeat row: the dwell is reconstructed
        /// after a crash, not observed at a live focus switch. Additive so
        /// stored rows deserialize unchanged, absent unless set so ordinary
        /// rows serialize byte-identically.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        recovered: bool,
    },
    WindowOpened {
        window: WindowRef,
        origin: WindowLifecycleOrigin,
    },
    WindowClosed {
        window: WindowRef,
        open_for_ms: u64,
        origin: WindowLifecycleOrigin,
    },
    Key {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        key: String,
        mods: Modifiers,
        window: Option<WindowRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_class: Option<KeyClass>,
    },
    MouseClick {
        button: MouseButton,
        x: Option<i32>,
        y: Option<i32>,
        window: Option<WindowRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_origin: Option<InputOrigin>,
    },
    MouseDoubleClick {
        button: MouseButton,
        interval_ms: u64,
        x: Option<i32>,
        y: Option<i32>,
        window: Option<WindowRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_origin: Option<InputOrigin>,
    },
    MouseDrag {
        button: MouseButton,
        dx_total: i64,
        dy_total: i64,
        distance_px: u64,
        raw_event_count: u64,
        duration_ms: u64,
        start_x: Option<i32>,
        start_y: Option<i32>,
        end_x: Option<i32>,
        end_y: Option<i32>,
        window: Option<WindowRef>,
        /// Heuristic, value-free hint: a primary-button drag can be text/range
        /// selection, but Gilbreth does not inspect selected content.
        selection_candidate: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_origin: Option<InputOrigin>,
    },
    MouseWheel {
        axis: MouseWheelAxis,
        delta: i32,
        x: Option<i32>,
        y: Option<i32>,
        window: Option<WindowRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_origin: Option<InputOrigin>,
    },
    MouseMove {
        dx_total: i64,
        dy_total: i64,
        distance_px: u64,
        raw_event_count: u64,
        duration_ms: u64,
        x: Option<i32>,
        y: Option<i32>,
        window: Option<WindowRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_origin: Option<InputOrigin>,
    },
    SystemInfo {
        host: String,
        os_version: String,
        arch: String,
        processor_count: u32,
        memory_total_bytes: u64,
    },
    VirtualScreen {
        x0: i32,
        y0: i32,
        x1: i32,
        y1: i32,
        width: i32,
        height: i32,
    },
    ProcessStarted {
        pid: u32,
        exe: String,
        exe_source: ProcessExeSource,
    },
    ProcessExited {
        pid: u32,
        exe: String,
        exe_source: ProcessExeSource,
    },
    /// Periodic aggregate of process transitions the background-churn filter
    /// dropped (demote, don't discard): the churn *rate* stays queryable while
    /// the routine rows stay out of the database. `top` lists the largest
    /// dropped basenames; `sustained` marks same-name churn heavy enough to
    /// look like a restart loop rather than routine background activity.
    ProcessChurnSummary {
        window_ms: u64,
        dropped: u32,
        distinct_exes: u32,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        top: Vec<ProcessChurnEntry>,
    },
    PowerSuspend {
        tick_ms: Option<u64>,
    },
    PowerResume {
        tick_ms: Option<u64>,
        matched_suspend: bool,
    },
    PowerBoundaryRecovered {
        gap_ms: u64,
        capped_dwell_ms: u64,
    },
    /// Value-free marker that ambient capture was manually paused. The
    /// event timestamp is the complete payload.
    CapturePaused,
    /// Value-free marker that ambient capture was manually resumed. The
    /// event timestamp is the complete payload.
    CaptureResumed,
    /// AC/battery power-source change (value-free): plugged vs on-battery plus a
    /// coarse battery snapshot. Emitted on `PBT_APMPOWERSTATUSCHANGE`. `None` fields
    /// mean the value was unknown/unavailable (e.g. desktop with no battery).
    PowerStatusChanged {
        ac_online: Option<bool>,
        battery_percent: Option<u8>,
        battery_saver: Option<bool>,
    },
    SessionLock {
        session_id: u32,
    },
    SessionUnlock {
        session_id: u32,
    },
    SessionConnect {
        session_id: u32,
        connection: SessionConnectionKind,
    },
    SessionDisconnect {
        session_id: u32,
        connection: SessionConnectionKind,
    },
    ClipboardUsed {
        sequence_number: u32,
        format_kind: ClipboardFormatKind,
        format_count: u32,
        text_char_count: Option<u64>,
        byte_size: Option<u64>,
    },
    /// Metadata-only notification receipt signal. `app` is a sanitized source-app
    /// label from Windows app metadata; notification title/body/XML are never read.
    NotificationsReceived {
        app: Option<String>,
        count: u32,
    },
    SensitiveContextEntered {
        reason: SensitiveContextReason,
    },
    SensitiveContextExited {
        reason: SensitiveContextReason,
    },
    Idle {
        idle_ms: u64,
    },
    Active {
        idle_ms: u64,
    },
}

impl EventPayload {
    pub fn kind(&self) -> &'static str {
        match self {
            EventPayload::FocusChanged { .. } => "focus_changed",
            EventPayload::WindowOpened { .. } => "window_opened",
            EventPayload::WindowClosed { .. } => "window_closed",
            EventPayload::Key { .. } => "key",
            EventPayload::MouseClick { .. } => "mouse_click",
            EventPayload::MouseDoubleClick { .. } => "mouse_double_click",
            EventPayload::MouseDrag { .. } => "mouse_drag",
            EventPayload::MouseWheel { .. } => "mouse_wheel",
            EventPayload::MouseMove { .. } => "mouse_move",
            EventPayload::SystemInfo { .. } => "system_info",
            EventPayload::VirtualScreen { .. } => "virtual_screen",
            EventPayload::ProcessStarted { .. } => "process_started",
            EventPayload::ProcessExited { .. } => "process_exited",
            EventPayload::ProcessChurnSummary { .. } => "process_churn_summary",
            EventPayload::PowerSuspend { .. } => "power_suspend",
            EventPayload::PowerResume { .. } => "power_resume",
            EventPayload::PowerBoundaryRecovered { .. } => "power_boundary_recovered",
            EventPayload::CapturePaused => "capture_paused",
            EventPayload::CaptureResumed => "capture_resumed",
            EventPayload::PowerStatusChanged { .. } => "power_status",
            EventPayload::SessionLock { .. } => "session_lock",
            EventPayload::SessionUnlock { .. } => "session_unlock",
            EventPayload::SessionConnect { .. } => "session_connect",
            EventPayload::SessionDisconnect { .. } => "session_disconnect",
            EventPayload::ClipboardUsed { .. } => "clipboard_used",
            EventPayload::NotificationsReceived { .. } => "notifications_received",
            EventPayload::SensitiveContextEntered { .. } => "sensitive_context_entered",
            EventPayload::SensitiveContextExited { .. } => "sensitive_context_exited",
            EventPayload::Idle { .. } => "idle",
            EventPayload::Active { .. } => "active",
        }
    }

    fn redact_titles_containing(&mut self, fragments: &[String]) -> bool {
        match self {
            EventPayload::FocusChanged { window, prev, .. } => {
                let mut changed = window.redact_title_if_needed(fragments);
                if let Some(prev) = prev {
                    changed |= prev.redact_title_if_needed(fragments);
                }
                changed
            }
            EventPayload::WindowOpened { window, .. } => window.redact_title_if_needed(fragments),
            EventPayload::WindowClosed { window, .. } => window.redact_title_if_needed(fragments),
            EventPayload::Key { window, .. } => window
                .as_mut()
                .is_some_and(|window| window.redact_title_if_needed(fragments)),
            EventPayload::MouseClick { window, .. }
            | EventPayload::MouseDoubleClick { window, .. }
            | EventPayload::MouseDrag { window, .. }
            | EventPayload::MouseWheel { window, .. }
            | EventPayload::MouseMove { window, .. } => window
                .as_mut()
                .is_some_and(|window| window.redact_title_if_needed(fragments)),
            EventPayload::NotificationsReceived { app, .. } => {
                redact_optional_label_if_needed(app, fragments)
            }
            EventPayload::SystemInfo { .. }
            | EventPayload::VirtualScreen { .. }
            | EventPayload::ProcessStarted { .. }
            | EventPayload::ProcessExited { .. }
            | EventPayload::ProcessChurnSummary { .. }
            | EventPayload::PowerSuspend { .. }
            | EventPayload::PowerResume { .. }
            | EventPayload::PowerBoundaryRecovered { .. }
            | EventPayload::CapturePaused
            | EventPayload::CaptureResumed
            | EventPayload::PowerStatusChanged { .. }
            | EventPayload::SessionLock { .. }
            | EventPayload::SessionUnlock { .. }
            | EventPayload::SessionConnect { .. }
            | EventPayload::SessionDisconnect { .. }
            | EventPayload::ClipboardUsed { .. }
            | EventPayload::SensitiveContextEntered { .. }
            | EventPayload::SensitiveContextExited { .. }
            | EventPayload::Idle { .. }
            | EventPayload::Active { .. } => false,
        }
    }

    /// Lean-capture branch: drop the key name entirely (it disappears from
    /// both the typed column and the payload JSON) and record only the
    /// value-free key class, computed before the name is discarded. Keys a
    /// privacy rule already redacted stay unclassified: classifying them
    /// would leak a shape trace of exactly the content the rule protected.
    fn omit_key_content(&mut self) -> bool {
        match self {
            EventPayload::Key { key, key_class, .. } if !key.is_empty() => {
                if key != "<redacted>" {
                    *key_class = Some(key_class_for_name(key));
                }
                key.clear();
                true
            }
            _ => false,
        }
    }

    fn redact_keys_containing(&mut self, fragments: &[String]) -> bool {
        match self {
            EventPayload::Key { key, .. }
                if fragments
                    .iter()
                    .any(|fragment| !fragment.is_empty() && key.contains(fragment)) =>
            {
                *key = "<redacted>".to_string();
                true
            }
            _ => false,
        }
    }

    fn redact_for_sensitive_context(&mut self) -> bool {
        match self {
            EventPayload::FocusChanged { window, prev, .. } => {
                let mut changed = window.redact_title();
                if let Some(prev) = prev {
                    changed |= prev.redact_title();
                }
                changed
            }
            EventPayload::WindowOpened { window, .. }
            | EventPayload::WindowClosed { window, .. } => window.redact_title(),
            EventPayload::Key {
                key, mods, window, ..
            } => {
                let mut changed = if key == "<redacted>" {
                    false
                } else {
                    *key = "<redacted>".to_string();
                    true
                };
                if *mods != Modifiers::default() {
                    *mods = Modifiers::default();
                    changed = true;
                }
                if let Some(window) = window {
                    changed |= window.redact_title();
                }
                changed
            }
            EventPayload::MouseClick { window, .. }
            | EventPayload::MouseDoubleClick { window, .. }
            | EventPayload::MouseDrag { window, .. }
            | EventPayload::MouseWheel { window, .. }
            | EventPayload::MouseMove { window, .. } => {
                window.as_mut().is_some_and(WindowRef::redact_title)
            }
            EventPayload::NotificationsReceived { app, .. } => redact_optional_label(app),
            EventPayload::ClipboardUsed {
                text_char_count,
                byte_size,
                ..
            } => {
                let changed = text_char_count.is_some() || byte_size.is_some();
                *text_char_count = None;
                *byte_size = None;
                changed
            }
            EventPayload::SystemInfo { .. }
            | EventPayload::VirtualScreen { .. }
            | EventPayload::ProcessStarted { .. }
            | EventPayload::ProcessExited { .. }
            | EventPayload::ProcessChurnSummary { .. }
            | EventPayload::PowerSuspend { .. }
            | EventPayload::PowerResume { .. }
            | EventPayload::PowerBoundaryRecovered { .. }
            | EventPayload::CapturePaused
            | EventPayload::CaptureResumed
            | EventPayload::PowerStatusChanged { .. }
            | EventPayload::SessionLock { .. }
            | EventPayload::SessionUnlock { .. }
            | EventPayload::SessionConnect { .. }
            | EventPayload::SessionDisconnect { .. }
            | EventPayload::SensitiveContextEntered { .. }
            | EventPayload::SensitiveContextExited { .. }
            | EventPayload::Idle { .. }
            | EventPayload::Active { .. } => false,
        }
    }

    fn key_was_capture_redacted(&self) -> bool {
        matches!(
            self,
            EventPayload::Key { key, window, .. }
                if key == "<redacted>"
                    || window
                        .as_ref()
                        .is_some_and(|window| window.title == "<redacted>")
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowLifecycleOrigin {
    Observed,
    Seeded,
    Synthesized,
}

impl WindowLifecycleOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Seeded => "seeded",
            Self::Synthesized => "synthesized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExeSource {
    FullPath,
    SnapshotName,
}

impl ProcessExeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullPath => "full_path",
            Self::SnapshotName => "snapshot_name",
        }
    }
}

/// One basename's share of a `ProcessChurnSummary` window. `exe` is a
/// lowercased basename only (never a full path or arguments).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessChurnEntry {
    pub exe: String,
    pub dropped: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sustained: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardFormatKind {
    Text,
    Files,
    Image,
    Audio,
    Custom,
    Empty,
    Unavailable,
    /// A copy the source app marked concealed (`org.nspasteboard.ConcealedType`,
    /// the password-manager convention): the copy stays visible as activity,
    /// but the content class is deliberately not inspected — the marker
    /// overrides content-type classification. Additive, macOS-only (owner
    /// decision 2026-07-12, the `secure_input` precedent): Windows ignores
    /// its own equivalent exclusion marker today, and whether it should
    /// honor it is a recorded Windows follow-up, not taken in a mac slice.
    Concealed,
}

impl ClipboardFormatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Files => "files",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Custom => "custom",
            Self::Empty => "empty",
            Self::Unavailable => "unavailable",
            Self::Concealed => "concealed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveContextReason {
    SessionLocked,
    SessionDisconnected,
    SecureDesktop,
    PasswordField,
    /// macOS secure event input (`IsSecureEventInputEnabled`): the OS
    /// withholds keystrokes from listen-only taps system-wide during
    /// password entry, so capture receives nothing; this reason labels the
    /// quiet period truthfully. Additive, macOS-only — `SecureDesktop`
    /// stays Windows-only; neither platform writes the other's reason.
    SecureInput,
}

impl SensitiveContextReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionLocked => "session locked",
            Self::SessionDisconnected => "session disconnected",
            Self::SecureDesktop => "secure desktop",
            Self::PasswordField => "password field",
            Self::SecureInput => "secure input",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionConnectionKind {
    Console,
    Remote,
}

impl SessionConnectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::Remote => "remote",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

impl MouseButton {
    pub fn as_str(self) -> &'static str {
        match self {
            MouseButton::Left => "left",
            MouseButton::Right => "right",
            MouseButton::Middle => "middle",
            MouseButton::X1 => "x1",
            MouseButton::X2 => "x2",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseWheelAxis {
    Vertical,
    Horizontal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOrigin {
    Local,
    RemoteRelaySuspected,
}

impl InputOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            InputOrigin::Local => "local",
            InputOrigin::RemoteRelaySuspected => "remote_relay_suspected",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub win: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowRef {
    pub hwnd: u64,
    pub exe: String,
    pub title: String,
    pub pid: u32,
}

impl WindowRef {
    pub fn hwnd_hex(&self) -> String {
        format!("0x{:x}", self.hwnd)
    }

    fn redact_title_if_needed(&mut self, fragments: &[String]) -> bool {
        if fragments
            .iter()
            .any(|fragment| !fragment.is_empty() && self.title.contains(fragment))
        {
            self.redact_title()
        } else {
            false
        }
    }

    fn redact_title(&mut self) -> bool {
        if self.title == "<redacted>" {
            false
        } else {
            self.title = "<redacted>".to_string();
            true
        }
    }
}

fn redact_optional_label_if_needed(label: &mut Option<String>, fragments: &[String]) -> bool {
    if label.as_ref().is_some_and(|value| {
        fragments
            .iter()
            .any(|fragment| !fragment.is_empty() && value.contains(fragment))
    }) {
        redact_optional_label(label)
    } else {
        false
    }
}

fn redact_optional_label(label: &mut Option<String>) -> bool {
    match label {
        Some(value) if value == "<redacted>" => false,
        Some(value) => {
            *value = "<redacted>".to_string();
            true
        }
        None => false,
    }
}

#[derive(Clone, Debug)]
pub struct SessionTimebase {
    base_instant: Instant,
    base_utc_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriftCorrection {
    pub old_base_utc_ms: i64,
    pub new_base_utc_ms: i64,
    pub measured_drift_ms: i64,
    pub clamp_ms: i64,
    pub threshold_ms: i64,
}

impl SessionTimebase {
    pub fn new(base_instant: Instant, base_utc_ms: i64) -> Self {
        Self {
            base_instant,
            base_utc_ms,
        }
    }

    pub fn start_now() -> Self {
        Self::new(Instant::now(), unix_now_ms())
    }

    pub fn base_instant(&self) -> Instant {
        self.base_instant
    }

    pub fn base_utc_ms(&self) -> i64 {
        self.base_utc_ms
    }

    pub fn timestamp_for(&self, captured_at: Instant) -> i64 {
        match captured_at.checked_duration_since(self.base_instant) {
            Some(delta) => self.base_utc_ms.saturating_add(duration_ms_i64(delta)),
            None => self.base_utc_ms.saturating_sub(duration_ms_i64(
                self.base_instant.duration_since(captured_at),
            )),
        }
    }

    pub fn resync(
        &mut self,
        now_instant: Instant,
        now_utc_ms: i64,
        threshold_ms: i64,
        min_timestamp_ms: Option<i64>,
    ) -> Option<DriftCorrection> {
        let threshold_ms = threshold_ms.max(0);
        let old_base_utc_ms = self.base_utc_ms;
        let projected_utc_ms = self.timestamp_for(now_instant);
        let measured_drift_ms = now_utc_ms.saturating_sub(projected_utc_ms);
        if i128::from(measured_drift_ms).abs() <= i128::from(threshold_ms) {
            return None;
        }

        let new_base_utc_ms = min_timestamp_ms.map_or(now_utc_ms, |min| now_utc_ms.max(min));
        let clamp_ms = new_base_utc_ms.saturating_sub(now_utc_ms);
        self.base_instant = now_instant;
        self.base_utc_ms = new_base_utc_ms;
        Some(DriftCorrection {
            old_base_utc_ms,
            new_base_utc_ms,
            measured_drift_ms,
            clamp_ms,
            threshold_ms,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Sequencer {
    session_id: i64,
    next_seq: u64,
    timebase: SessionTimebase,
    last_ts_unix_ms: Option<i64>,
}

impl Sequencer {
    pub fn new(session_id: i64, timebase: SessionTimebase) -> Self {
        Self {
            session_id,
            next_seq: 1,
            timebase,
            last_ts_unix_ms: None,
        }
    }

    pub fn session_id(&self) -> i64 {
        self.session_id
    }

    pub fn started_at(&self) -> i64 {
        self.timebase.base_utc_ms()
    }

    pub fn timestamp_for(&self, instant: Instant) -> i64 {
        self.clamp_timestamp(self.timebase.timestamp_for(instant))
    }

    /// Project an instant onto this session's wall-clock timebase without the
    /// monotonic last-event clamp. Privacy boundaries use this form so a late
    /// pre-boundary capture cannot be made to look current merely because a
    /// newer row was stamped first.
    pub fn projected_timestamp_for(&self, instant: Instant) -> i64 {
        self.timebase.timestamp_for(instant)
    }

    pub fn last_ts_unix_ms(&self) -> Option<i64> {
        self.last_ts_unix_ms
    }

    pub fn resync(
        &mut self,
        now_instant: Instant,
        now_utc_ms: i64,
        threshold_ms: i64,
    ) -> Option<DriftCorrection> {
        self.timebase
            .resync(now_instant, now_utc_ms, threshold_ms, self.last_ts_unix_ms)
    }

    pub fn stamp(&mut self, captured: Captured) -> EventEnvelope {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let ts_unix_ms = self.clamp_timestamp(self.timebase.timestamp_for(captured.captured_at));
        self.last_ts_unix_ms = Some(ts_unix_ms);

        EventEnvelope {
            schema_version: SCHEMA_VERSION,
            session_id: self.session_id,
            seq,
            ts_unix_ms,
            source: captured.source,
            is_sensitive: false,
            payload: captured.payload,
        }
    }

    pub fn stamp_action(&mut self, capture: ActionCapture) -> StampedAction {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let ts_unix_ms = self.clamp_timestamp(self.timebase.timestamp_for(capture.captured_at));
        self.last_ts_unix_ms = Some(ts_unix_ms);

        StampedAction {
            session_id: self.session_id,
            seq,
            ts_unix_ms,
            action: capture.action,
            record_session_id: capture.record_session_id,
            exe: capture.exe,
            is_sensitive: capture.is_sensitive,
            has_name: capture.has_name,
            pattern_action: capture.pattern_action,
            framework: capture.framework,
            framework_class: capture.framework_class,
            depth: capture.depth,
            leaf_rect: capture.leaf_rect,
            payload: capture.payload,
        }
    }

    fn clamp_timestamp(&self, ts_unix_ms: i64) -> i64 {
        self.last_ts_unix_ms
            .map_or(ts_unix_ms, |last| ts_unix_ms.max(last))
    }
}

/// Coarse, value-free key families for lean-capture rows. The class
/// reconstructs no text but keeps typing-speed analytics honest once key
/// content is absent: burst-rate lenses can exclude navigation/editing and
/// modifier chords from printable-character runs (see the Rhythms roadmap
/// item). Backspace/Delete/Tab are classified as navigation because they
/// edit or move rather than emit text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    Printable,
    Navigation,
    Modifier,
    Function,
    Other,
}

pub fn key_class_for_name(name: &str) -> KeyClass {
    match name {
        // `Cmd`/`Option`/`Fn` are the macOS modifier-key names (schema
        // vocabulary record); additive here since Windows never emits them,
        // so no stored value changes. Without this arm they would classify
        // as `Other`.
        "Shift" | "Ctrl" | "Alt" | "Win" | "CapsLock" | "NumLock" | "ScrollLock" | "Cmd"
        | "Option" | "Fn" => KeyClass::Modifier,
        "Home" | "End" | "PageUp" | "PageDown" | "ArrowLeft" | "ArrowUp" | "ArrowRight"
        | "ArrowDown" | "Insert" | "Delete" | "Backspace" | "Tab" => KeyClass::Navigation,
        "Enter" | "Escape" | "Pause" | "Apps" | "PrintScreen" => KeyClass::Function,
        "Space" => KeyClass::Printable,
        _ if name.len() >= 2
            && name.starts_with('F')
            && name[1..].bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            KeyClass::Function
        }
        _ if name.starts_with("Numpad") => KeyClass::Printable,
        _ if name.chars().count() == 1 => KeyClass::Printable,
        _ => KeyClass::Other,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    title_redaction_fragments: Vec<String>,
    key_redaction_fragments: Vec<String>,
    sensitive_context_suppression: bool,
    // Lean capture: when set, key rows keep timing/modifiers/window but the
    // key name itself is never stored. False by default so Policy::identity()
    // remains a true identity; the app config default supplies lean mode.
    omit_key_content: bool,
    /// User-selected app basenames whose attributed events must never reach
    /// storage. Values are normalized once, not on every ordinary event.
    excluded_apps: HashSet<String>,
    excluded_notification_keys: HashSet<String>,
    /// Sensitive-context rows carry no WindowRef in schema v1. The immediately
    /// preceding focus attribution is therefore their only app attribution.
    /// `None` means no live attribution exists (never observed, or forgotten
    /// because the Foreground stream stopped): rows that depend on the latch
    /// must fail closed while any exclusion is configured.
    current_focus_excluded: RefCell<Option<bool>>,
    active_sensitive_reasons: RefCell<HashSet<SensitiveContextReason>>,
}

impl Policy {
    pub fn identity() -> Self {
        Self::default()
    }

    pub fn redact_titles_containing<I, S>(fragments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::identity().with_title_redactions(fragments)
    }

    pub fn redact_keys_containing<I, S>(fragments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::identity().with_key_redactions(fragments)
    }

    pub fn with_title_redactions<I, S>(mut self, fragments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.title_redaction_fragments
            .extend(fragments.into_iter().map(Into::into));
        self
    }

    pub fn with_key_redactions<I, S>(mut self, fragments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.key_redaction_fragments
            .extend(fragments.into_iter().map(Into::into));
        self
    }

    pub fn with_sensitive_context_suppression(mut self, enabled: bool) -> Self {
        self.sensitive_context_suppression = enabled;
        self
    }

    pub fn with_store_key_content(mut self, store: bool) -> Self {
        self.omit_key_content = !store;
        self
    }

    pub fn with_excluded_apps<I, S>(mut self, apps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for app in apps {
            let basename = exe_basename_lower(app.as_ref());
            if basename.is_empty() {
                continue;
            }
            self.excluded_notification_keys
                .insert(notification_match_key(&basename));
            self.excluded_apps.insert(basename);
        }
        self
    }

    pub fn excludes_exe(&self, exe: &str) -> bool {
        self.excluded_apps.contains(&exe_basename_lower(exe))
    }

    /// The exclusion verdict for rows whose only app attribution is the live
    /// focus latch. Without live attribution the row could belong to an
    /// excluded app, so it fails closed while any exclusion is configured.
    fn latched_focus_excluded(&self) -> bool {
        self.current_focus_excluded
            .borrow()
            .unwrap_or_else(|| !self.excluded_apps.is_empty())
    }

    /// Invalidate the live focus attribution. The app drives this when the
    /// Foreground stream stops: no `FocusChanged` can arrive to correct the
    /// latch while the stream is off, so keeping the last verdict would let
    /// unattributed rows inherit a stale not-excluded answer for the whole
    /// off period. The next `FocusChanged` re-arms the latch.
    pub fn forget_focus_attribution(&self) {
        *self.current_focus_excluded.borrow_mut() = None;
    }

    pub fn excludes_action(&self, action: &ActionCapture) -> bool {
        action
            .exe
            .as_deref()
            .is_some_and(|exe| self.excludes_exe(exe))
    }

    pub fn sensitive_context_active(&self) -> bool {
        self.sensitive_context_suppression && !self.active_sensitive_reasons.borrow().is_empty()
    }

    pub fn active_sensitive_reasons(&self) -> Vec<SensitiveContextReason> {
        if !self.sensitive_context_suppression {
            return Vec::new();
        }
        let active = self.active_sensitive_reasons.borrow();
        [
            SensitiveContextReason::SessionLocked,
            SensitiveContextReason::SessionDisconnected,
            SensitiveContextReason::SecureDesktop,
            SensitiveContextReason::PasswordField,
        ]
        .into_iter()
        .filter(|reason| active.contains(reason))
        .collect()
    }

    /// Apply only the exclusion boundary before a sequencer consumes a durable
    /// sequence number. A dropped app must leave neither a row nor a seq hole.
    pub fn apply_exclusions_to_captured(&self, mut captured: Captured) -> Option<Captured> {
        self.apply_exclusion_boundary(&mut captured.payload)
            .then_some(captured)
    }

    fn apply_exclusion_boundary(&self, payload: &mut EventPayload) -> bool {
        match payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => {
                let current_is_excluded = self.excludes_exe(&window.exe);
                *self.current_focus_excluded.borrow_mut() = Some(current_is_excluded);
                if current_is_excluded {
                    return false;
                }
                if prev
                    .as_ref()
                    .is_some_and(|previous| self.excludes_exe(&previous.exe))
                {
                    // The allowed outbound row reads like a first focus. None
                    // of the excluded app's identity or dwell/correlation may
                    // cross the boundary.
                    *prev = None;
                    *previous_focused_for_ms = 0;
                    *window_unfocused_for_ms = 0;
                }
            }
            EventPayload::WindowOpened { window, .. }
            | EventPayload::WindowClosed { window, .. }
                if self.excludes_exe(&window.exe) =>
            {
                return false;
            }
            EventPayload::Key { window, .. }
            | EventPayload::MouseClick { window, .. }
            | EventPayload::MouseDoubleClick { window, .. }
            | EventPayload::MouseDrag { window, .. }
            | EventPayload::MouseWheel { window, .. }
            | EventPayload::MouseMove { window, .. }
                if window.as_ref().map_or_else(
                    || self.latched_focus_excluded(),
                    |window| self.excludes_exe(&window.exe),
                ) =>
            {
                return false;
            }
            EventPayload::ProcessStarted { exe, .. } | EventPayload::ProcessExited { exe, .. }
                if self.excludes_exe(exe) =>
            {
                return false;
            }
            EventPayload::NotificationsReceived { app, .. }
                if !self.excluded_apps.is_empty()
                    || app.as_ref().is_some_and(|app| {
                        self.excluded_notification_keys
                            .contains(&notification_match_key(app))
                    }) =>
            {
                return false;
            }
            EventPayload::SensitiveContextEntered { .. }
            | EventPayload::SensitiveContextExited { .. }
                if self.latched_focus_excluded() =>
            {
                // Keep the state machine honest even though the attributed
                // boundary row itself is intentionally absent from storage.
                if self.sensitive_context_suppression {
                    match payload {
                        EventPayload::SensitiveContextEntered { reason } => {
                            self.active_sensitive_reasons.borrow_mut().insert(*reason);
                        }
                        EventPayload::SensitiveContextExited { reason } => {
                            self.active_sensitive_reasons.borrow_mut().remove(reason);
                        }
                        _ => unreachable!(),
                    }
                }
                return false;
            }
            _ => {}
        }
        true
    }

    /// Apply the remaining privacy policy after the exclusion boundary was
    /// already evaluated ahead of sequencing.
    pub fn apply_after_exclusions(&self, mut event: EventEnvelope) -> EventEnvelope {
        if self.sensitive_context_suppression {
            match &event.payload {
                EventPayload::SensitiveContextEntered { reason } => {
                    self.active_sensitive_reasons.borrow_mut().insert(*reason);
                    return event;
                }
                EventPayload::SensitiveContextExited { reason } => {
                    self.active_sensitive_reasons.borrow_mut().remove(reason);
                    return event;
                }
                _ => {}
            }
        }

        if self.sensitive_context_suppression
            && !self.active_sensitive_reasons.borrow().is_empty()
            && event.payload.redact_for_sensitive_context()
        {
            event.is_sensitive = true;
        }

        if event.payload.key_was_capture_redacted() {
            event.is_sensitive = true;
        }

        if event
            .payload
            .redact_titles_containing(&self.title_redaction_fragments)
            || event
                .payload
                .redact_keys_containing(&self.key_redaction_fragments)
        {
            event.is_sensitive = true;
        }

        // Lean capture runs last so redaction rules see the real key name
        // (and keep setting is_sensitive), while policy-omitted content is
        // deliberately NOT marked sensitive: that flag means "a privacy rule
        // fired", and stamping every key row would drown its diagnostic value.
        if self.omit_key_content {
            event.payload.omit_key_content();
        }
        event
    }

    pub fn apply(&self, mut event: EventEnvelope) -> Option<EventEnvelope> {
        if !self.apply_exclusion_boundary(&mut event.payload) {
            return None;
        }
        Some(self.apply_after_exclusions(event))
    }
}

pub fn unix_now_ms() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    duration_ms_i64(elapsed)
}

pub fn instant_to_unix_ms(captured_at: Instant, now_instant: Instant, now_unix_ms: i64) -> i64 {
    let elapsed_ms = duration_ms_i64(now_instant.saturating_duration_since(captured_at));
    now_unix_ms.saturating_sub(elapsed_ms)
}

pub fn unix_ms_to_instant(
    captured_unix_ms: i64,
    now_instant: Instant,
    now_unix_ms: i64,
) -> Instant {
    let lag_ms = now_unix_ms.saturating_sub(captured_unix_ms).max(0);
    let lag_ms = u64::try_from(lag_ms).unwrap_or(u64::MAX);
    now_instant
        .checked_sub(Duration::from_millis(lag_ms))
        .unwrap_or(now_instant)
}

pub fn duration_ms_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

pub fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

// ───────────────────── shared capture state machines ─────────────────────
// Hoisted from the platform capture crates 2026-07-12 (the recorded MAC-1
// core-hoist trigger: after the power, process, and clipboard slices land,
// before the beta). Both pumps drive these with platform-observed inputs;
// the emission rules ARE the cross-platform dwell/churn contract, so they
// live beside the vocabulary they emit. The bodies are the Windows
// semantics moved unchanged — no value Windows writes is altered by the
// move — and the public surface is the union of what the two pumps used
// (Windows: seed/switch/boundary/destroyed; macOS additionally: the
// current-window accessors and the privacy-pause correlation clear).

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn focus_changed(
    window: WindowRef,
    prev: Option<WindowRef>,
    previous_focused_for_ms: u64,
    window_unfocused_for_ms: u64,
    captured_at: Instant,
) -> Captured {
    Captured::new(
        Source::Foreground,
        captured_at,
        EventPayload::FocusChanged {
            window,
            prev,
            previous_focused_for_ms,
            window_unfocused_for_ms,
            recovered: false,
        },
    )
}

struct FocusedWindow {
    window: WindowRef,
    focused_at: Instant,
}

/// The foreground dwell/segment state machine: which window holds focus,
/// since when, and how long each window has been unfocused (the
/// `window_unfocused_for_ms` correlation). Emission rules — dwell attributed
/// to `prev_*`, boundary rows reusing the current window as both sides,
/// unfocused eviction on destroy — are identical on both platforms.
#[derive(Default)]
pub struct ForegroundState {
    current: Option<FocusedWindow>,
    last_unfocused_at: HashMap<u64, Instant>,
}

impl ForegroundState {
    /// Seed the initial window without attributing any prior dwell.
    pub fn seed_window_at(&mut self, window: WindowRef, now: Instant) -> Option<Captured> {
        self.current = Some(FocusedWindow {
            window: window.clone(),
            focused_at: now,
        });
        Some(focus_changed(window, None, 0, 0, now))
    }

    /// A focus switch: attributes the previous window's completed dwell and
    /// reports how long the newly-focused window had been unfocused. A
    /// same-window observation is a no-op.
    pub fn on_window_at(&mut self, window: WindowRef, now: Instant) -> Option<Captured> {
        if self
            .current
            .as_ref()
            .is_some_and(|current| current.window.hwnd == window.hwnd)
        {
            return None;
        }

        let window_unfocused_for_ms = self
            .last_unfocused_at
            .get(&window.hwnd)
            .map(|last| duration_ms(now.saturating_duration_since(*last)))
            .unwrap_or(0);

        let previous = self.current.replace(FocusedWindow {
            window: window.clone(),
            focused_at: now,
        });

        let (prev_window, previous_focused_for_ms) = match previous {
            Some(previous) => {
                self.last_unfocused_at.insert(previous.window.hwnd, now);
                let duration = duration_ms(now.saturating_duration_since(previous.focused_at));
                (Some(previous.window), duration)
            }
            None => (None, 0),
        };

        Some(focus_changed(
            window,
            prev_window,
            previous_focused_for_ms,
            window_unfocused_for_ms,
            now,
        ))
    }

    /// End the open segment at a boundary (lock, sleep, shutdown) with the
    /// full observed dwell.
    pub fn end_current_at(&mut self, now: Instant) -> Option<Captured> {
        self.end_current_at_with_duration_limit(now, None)
    }

    /// End the open segment attributing at most `max_duration` — the
    /// missed-boundary path, where only the capped dwell was truly observed.
    pub fn end_current_at_with_max_duration(
        &mut self,
        now: Instant,
        max_duration: Duration,
    ) -> Option<Captured> {
        self.end_current_at_with_duration_limit(now, Some(max_duration))
    }

    /// End the open segment, optionally capping the attributed dwell. A
    /// boundary has no replacement foreground window: the current window is
    /// reused as both sides, preserving the `FocusChanged` schema while
    /// attributing the completed dwell to `prev_*` for read-time rollups.
    pub fn end_current_at_with_duration_limit(
        &mut self,
        now: Instant,
        max_duration: Option<Duration>,
    ) -> Option<Captured> {
        let current = self.current.take()?;
        let elapsed = now.saturating_duration_since(current.focused_at);
        let elapsed = max_duration.map_or(elapsed, |max| elapsed.min(max));
        let focused_for_ms = duration_ms(elapsed);
        self.last_unfocused_at.insert(current.window.hwnd, now);

        Some(focus_changed(
            current.window.clone(),
            Some(current.window),
            focused_for_ms,
            0,
            now,
        ))
    }

    /// A destroyed window's unfocused timing is meaningless if its id is
    /// ever reused: evict it.
    pub fn on_window_destroyed(&mut self, hwnd: u64) {
        self.last_unfocused_at.remove(&hwnd);
    }

    /// When the currently-open segment began, if one is open.
    pub fn current_focused_at(&self) -> Option<Instant> {
        self.current.as_ref().map(|current| current.focused_at)
    }

    /// The currently-focused window, if a segment is open.
    pub fn current_window(&self) -> Option<&WindowRef> {
        self.current.as_ref().map(|current| &current.window)
    }

    /// Forget the unfocused-at correlations (the macOS privacy-pause rule:
    /// a user pause must leave no measurable trace, so
    /// `window_unfocused_for_ms` must not span the off period).
    pub fn clear_unfocused_correlations(&mut self) {
        self.last_unfocused_at.clear();
    }
}

// Background-process churn filter (demote, don't discard). Process
// start/exit rows are written only for apps the user has focused (the
// crash-signature rescue); everything else is counted and periodically
// flushed as one process_churn_summary row, so the churn *rate* stays
// visible in Diagnostics at near-zero storage. A basename whose drop count
// is heavy inside a short window is flagged `sustained` in the summary: at
// the 5 s snapshot cadence, exit-to-restart gaps are quantized to ~0 s or
// ~5 s, so a gap-width test cannot tell a crash-looping service from a busy
// spawn pipeline — volume over a sustained window is the honest signal
// available. Thresholds are part of the recorded contract (unchanged by the
// hoist).
pub const CHURN_SUMMARY_INTERVAL: Duration = Duration::from_secs(3600);
pub const CHURN_SUSTAINED_WINDOW: Duration = Duration::from_secs(600);
pub const CHURN_SUSTAINED_HITS: usize = 30;
pub const CHURN_SUMMARY_TOP_ENTRIES: usize = 3;

pub struct ProcessNoiseFilter {
    window_started: Instant,
    dropped_by_basename: HashMap<String, u32>,
    recent_hits: HashMap<String, VecDeque<Instant>>,
    sustained: HashSet<String>,
}

impl ProcessNoiseFilter {
    pub fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            dropped_by_basename: HashMap::new(),
            recent_hits: HashMap::new(),
            sustained: HashSet::new(),
        }
    }

    /// Count a transition that was not rescued by foreground focus. Always
    /// returns false (drop); the name says what the counting is for.
    pub fn keep_after_counting(&mut self, basename: &str, now: Instant) -> bool {
        *self
            .dropped_by_basename
            .entry(basename.to_string())
            .or_insert(0) += 1;
        let hits = self.recent_hits.entry(basename.to_string()).or_default();
        hits.push_back(now);
        while let Some(front) = hits.front() {
            if now.duration_since(*front) > CHURN_SUSTAINED_WINDOW {
                hits.pop_front();
            } else {
                break;
            }
        }
        if hits.len() >= CHURN_SUSTAINED_HITS && self.sustained.insert(basename.to_string()) {
            // debug, not warn: a client-named exe basename in a retained log
            // would survive retention and secure erase (S7). The durable,
            // erase-governed signal is the churn summary row in the DB.
            debug!(
                basename,
                hits = hits.len(),
                window_secs = CHURN_SUSTAINED_WINDOW.as_secs(),
                "sustained same-name process churn; flagged in the next churn summary"
            );
        }
        false
    }

    /// The hourly flush: `Some` only when the summary interval has elapsed
    /// AND there is something to report.
    pub fn summary_if_due(&mut self, now: Instant) -> Option<EventPayload> {
        if now.duration_since(self.window_started) < CHURN_SUMMARY_INTERVAL {
            return None;
        }
        self.take_summary(now)
    }

    /// Flush the partial window unconditionally (the shutdown path).
    pub fn take_summary(&mut self, now: Instant) -> Option<EventPayload> {
        let window_ms = now.duration_since(self.window_started).as_millis() as u64;
        let dropped: u32 = self.dropped_by_basename.values().sum();
        if dropped == 0 {
            self.window_started = now;
            return None;
        }
        let distinct_exes = self.dropped_by_basename.len() as u32;
        let mut entries: Vec<(String, u32)> = self.dropped_by_basename.drain().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top = entries
            .into_iter()
            .take(CHURN_SUMMARY_TOP_ENTRIES)
            .map(|(exe, count)| ProcessChurnEntry {
                sustained: self.sustained.contains(&exe),
                exe,
                dropped: count,
            })
            .collect();
        self.recent_hits.clear();
        self.sustained.clear();
        self.window_started = now;
        Some(EventPayload::ProcessChurnSummary {
            window_ms,
            dropped,
            distinct_exes,
            top,
        })
    }
}

// Process launch/exit tracking, hoisted from `gilbreth-capture-macos`
// (LIN-1's recorded trigger: the roadmap names "the shared core tracker"
// for the procfs sweep, and a third verbatim port would be the drift the
// MAC-1 hoists exist to prevent). The semantics are the Windows
// `ProcessTracker` as the macOS port carried them, unchanged by the move:
// the first snapshot seeds silently; a same-pid identity change (name or
// start token — PID reuse) emits Exited-then-Started; lifecycle rows are
// kept only for apps the user has focused, everything else counted into
// hourly `process_churn_summary` rows by [`ProcessNoiseFilter`]. The
// Windows backend keeps its own original under the
// zero-Windows-behavior-change rule.

/// The sweep cadence every backend shares (the Windows Toolhelp interval);
/// [`ProcessMonitor`] throttles to it internally, so a pump may call in on
/// its own faster service tick.
pub const PROCESS_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// One process from a platform sweep. `comm` is the kernel's short process
/// name (macOS `pbi_comm`, Linux `/proc/<pid>/comm`); `path` is the full
/// executable path when the platform exposes one; `start_time_id` is an
/// opaque per-boot start token compared only for equality (microseconds on
/// macOS, clock ticks on Linux) — the PID-reuse detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSnapshotEntry {
    pub pid: u32,
    pub comm: String,
    pub path: Option<String>,
    pub start_time_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    /// Lowercased comparison/filter name. Prefers the resolved path's
    /// basename — the untruncated name, matching Windows' snapshot name —
    /// and falls back to the kernel's short `comm`. Recorded nuance: a
    /// binary name longer than the kernel's comm limit whose path is
    /// unreadable compares by the truncated comm.
    compare_name: String,
    exe: String,
    exe_source: ProcessExeSource,
    start_time_id: Option<u64>,
}

impl ProcessIdentity {
    fn from_entry(entry: &ProcessSnapshotEntry) -> Self {
        let (exe, exe_source) = match &entry.path {
            Some(path) if !path.trim().is_empty() => (path.clone(), ProcessExeSource::FullPath),
            _ => (entry.comm.clone(), ProcessExeSource::SnapshotName),
        };
        let compare_name = match &entry.path {
            Some(path) if !path.trim().is_empty() => exe_basename_lower(path),
            _ => entry.comm.trim().to_lowercase(),
        };
        Self {
            pid: entry.pid,
            compare_name,
            exe,
            exe_source,
            start_time_id: entry.start_time_id,
        }
    }

    /// The Windows `is_same_process` semantics: same comparison name, and
    /// same start token when both sides know it (an unknown side never
    /// forces a false restart).
    fn is_same_process(&self, next: &Self) -> bool {
        self.compare_name == next.compare_name
            && match (self.start_time_id, next.start_time_id) {
                (Some(previous), Some(next)) => previous == next,
                _ => true,
            }
    }

    /// Keep a previously-known start token when a refresh lost it (the
    /// Windows `refreshed_with`).
    fn refreshed_with(&self, mut next: Self) -> Self {
        if next.start_time_id.is_none() {
            next.start_time_id = self.start_time_id;
        }
        next
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessTransition {
    Started(ProcessIdentity),
    Exited(ProcessIdentity),
}

impl ProcessTransition {
    /// Lowercased basename for churn filtering (the Windows `basename`).
    fn basename(&self) -> String {
        let identity = match self {
            ProcessTransition::Started(identity) | ProcessTransition::Exited(identity) => identity,
        };
        if identity.compare_name.is_empty() {
            exe_basename_lower(&identity.exe)
        } else {
            identity.compare_name.clone()
        }
    }

    fn into_captured(self, captured_at: Instant) -> Captured {
        let payload = match self {
            ProcessTransition::Started(identity) => EventPayload::ProcessStarted {
                pid: identity.pid,
                exe: identity.exe,
                exe_source: identity.exe_source,
            },
            ProcessTransition::Exited(identity) => EventPayload::ProcessExited {
                pid: identity.pid,
                exe: identity.exe,
                exe_source: identity.exe_source,
            },
        };
        Captured::new(Source::System, captured_at, payload)
    }
}

/// The Windows `ProcessTracker` ported: seed silently, then diff by pid
/// with identity comparison for PID-reuse honesty.
#[derive(Default)]
struct ProcessTracker {
    seeded: bool,
    live: HashMap<u32, ProcessIdentity>,
}

impl ProcessTracker {
    fn apply_snapshot(&mut self, snapshot: &[ProcessSnapshotEntry]) -> Vec<ProcessTransition> {
        let entries: HashMap<u32, ProcessIdentity> = snapshot
            .iter()
            .filter(|entry| {
                !entry.comm.trim().is_empty()
                    || entry.path.as_deref().is_some_and(|p| !p.trim().is_empty())
            })
            .map(|entry| (entry.pid, ProcessIdentity::from_entry(entry)))
            .collect();
        if entries.is_empty() {
            // A machine always runs processes; an empty sweep is a failed
            // sweep (the Windows empty-snapshot defense) — keep state.
            return Vec::new();
        }

        if !self.seeded {
            self.live = entries;
            self.seeded = true;
            return Vec::new();
        }

        let mut transitions = Vec::new();
        let mut next_live = HashMap::with_capacity(entries.len());
        let mut pids: Vec<u32> = entries.keys().chain(self.live.keys()).copied().collect();
        pids.sort_unstable();
        pids.dedup();

        for pid in pids {
            match (self.live.get(&pid), entries.get(&pid)) {
                (Some(previous), Some(next)) => {
                    if previous.is_same_process(next) {
                        next_live.insert(pid, previous.refreshed_with(next.clone()));
                    } else {
                        transitions.push(ProcessTransition::Exited(previous.clone()));
                        transitions.push(ProcessTransition::Started(next.clone()));
                        next_live.insert(pid, next.clone());
                    }
                }
                (Some(previous), None) => {
                    transitions.push(ProcessTransition::Exited(previous.clone()));
                }
                (None, Some(next)) => {
                    transitions.push(ProcessTransition::Started(next.clone()));
                    next_live.insert(pid, next.clone());
                }
                (None, None) => {}
            }
        }

        self.live = next_live;
        transitions
    }
}

/// The pump-facing monitor: the shared sweep throttle, tracker diff, focus
/// rescue, churn accounting, and hourly summaries. Rows gate at `send`
/// like every stream.
pub struct ProcessMonitor {
    tracker: ProcessTracker,
    noise: ProcessNoiseFilter,
    last_sweep: Option<Instant>,
}

impl ProcessMonitor {
    pub fn new(now: Instant) -> Self {
        Self {
            tracker: ProcessTracker::default(),
            noise: ProcessNoiseFilter::new(now),
            last_sweep: None,
        }
    }

    pub fn poll<S>(
        &mut self,
        now: Instant,
        controls: &CaptureControls,
        snapshot: &mut S,
        events: &mut Vec<Captured>,
    ) where
        S: FnMut() -> Option<Vec<ProcessSnapshotEntry>>,
    {
        let due = self
            .last_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= PROCESS_POLL_INTERVAL);
        if !due {
            return;
        }
        self.last_sweep = Some(now);
        match snapshot() {
            Some(entries) if !entries.is_empty() => {
                for transition in self.tracker.apply_snapshot(&entries) {
                    if controls.app_excluded(&transition.basename()) {
                        continue;
                    }
                    // Ported filter order: everything is kept with the
                    // filter off; with it on, focused apps are rescued and
                    // the rest is counted into the summary.
                    let keep = !controls.process_filter_enabled() || {
                        let basename = transition.basename();
                        controls.foreground_exe_seen(&basename)
                            || self.noise.keep_after_counting(&basename, now)
                    };
                    if keep {
                        events.push(transition.into_captured(now));
                    }
                }
            }
            _ => {
                warn!("process snapshot failed; keeping previous process state");
            }
        }
        if let Some(payload) = self.noise.summary_if_due(now) {
            events.push(Captured::new(Source::System, now, payload));
        }
    }

    /// Pump shutdown: flush the partial churn window (the Windows monitor's
    /// stop-path `take_summary`).
    pub fn flush(&mut self, now: Instant, events: &mut Vec<Captured>) {
        if let Some(payload) = self.noise.take_summary(now) {
            events.push(Captured::new(Source::System, now, payload));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{mpsc, Arc, Mutex},
    };

    fn focus_payload(title: &str) -> EventPayload {
        EventPayload::FocusChanged {
            window: window_ref(title),
            prev: None,
            previous_focused_for_ms: 0,
            window_unfocused_for_ms: 0,
            recovered: false,
        }
    }

    fn window_ref(title: &str) -> WindowRef {
        WindowRef {
            hwnd: 0x1234,
            exe: "C:\\Windows\\notepad.exe".to_string(),
            title: title.to_string(),
            pid: 42,
        }
    }

    fn sample_selector_path() -> SelectorPath {
        SelectorPath {
            backend: "uia".to_string(),
            hops: vec![
                SelectorPathHop {
                    control_type: 50032,
                    automation_id: "root".to_string(),
                    class_name: "Notepad".to_string(),
                    ordinal: 0,
                },
                SelectorPathHop {
                    control_type: 50004,
                    automation_id: "15".to_string(),
                    class_name: "Edit".to_string(),
                    ordinal: 1,
                },
            ],
        }
    }

    fn sample_action_capture(captured_at: Instant) -> ActionCapture {
        ActionCapture {
            action: AutomationAction {
                action_type: ActionType::Invoke,
                selector_path: sample_selector_path(),
                trust_basis: SelectorTrustBasis::PidMatch,
            },
            captured_at,
            record_session_id: 99,
            exe: Some("C:\\Windows\\notepad.exe".to_string()),
            is_sensitive: false,
            has_name: false,
            pattern_action: Some("invoke".to_string()),
            framework: "uia".to_string(),
            framework_class: FrameworkClass::Native,
            depth: 2,
            leaf_rect: None,
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
        }
    }

    fn envelope(payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            schema_version: SCHEMA_VERSION,
            session_id: 1,
            seq: 1,
            ts_unix_ms: 1,
            source: Source::System,
            is_sensitive: false,
            payload,
        }
    }

    fn attributed_window(exe: &str) -> WindowRef {
        WindowRef {
            hwnd: 7,
            exe: exe.to_string(),
            title: "private title".to_string(),
            pid: 8,
        }
    }

    #[test]
    fn exclusions_drop_each_attributed_kind_and_scrub_the_outbound_boundary() {
        let policy = Policy::identity().with_excluded_apps(["PRIVATE.exe"]);
        let excluded = attributed_window(r"C:\Apps\Private.EXE");
        let allowed = attributed_window("allowed.exe");

        let focus_in = envelope(EventPayload::FocusChanged {
            window: excluded.clone(),
            prev: Some(allowed.clone()),
            previous_focused_for_ms: 11,
            window_unfocused_for_ms: 12,
            recovered: false,
        });
        assert!(policy.apply(focus_in).is_none());
        assert!(policy
            .apply(envelope(EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField,
            }))
            .is_none());

        let focus_out = policy
            .apply(envelope(EventPayload::FocusChanged {
                window: allowed.clone(),
                prev: Some(excluded.clone()),
                previous_focused_for_ms: 9_999,
                window_unfocused_for_ms: 8_888,
                recovered: false,
            }))
            .expect("allowed outbound focus kept");
        let EventPayload::FocusChanged {
            prev,
            previous_focused_for_ms,
            window_unfocused_for_ms,
            ..
        } = focus_out.payload
        else {
            panic!("focus payload");
        };
        assert_eq!(prev, None);
        assert_eq!(previous_focused_for_ms, 0);
        assert_eq!(window_unfocused_for_ms, 0);

        let attributed = vec![
            EventPayload::WindowOpened {
                window: excluded.clone(),
                origin: WindowLifecycleOrigin::Observed,
            },
            EventPayload::WindowClosed {
                window: excluded.clone(),
                open_for_ms: 1,
                origin: WindowLifecycleOrigin::Observed,
            },
            EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: Some(excluded.clone()),
                key_class: None,
            },
            EventPayload::MouseClick {
                button: MouseButton::Left,
                x: None,
                y: None,
                window: Some(excluded.clone()),
                input_origin: None,
            },
            EventPayload::MouseDoubleClick {
                button: MouseButton::Left,
                interval_ms: 1,
                x: None,
                y: None,
                window: Some(excluded.clone()),
                input_origin: None,
            },
            EventPayload::MouseDrag {
                button: MouseButton::Left,
                dx_total: 1,
                dy_total: 1,
                distance_px: 1,
                raw_event_count: 1,
                duration_ms: 1,
                start_x: None,
                start_y: None,
                end_x: None,
                end_y: None,
                window: Some(excluded.clone()),
                selection_candidate: false,
                input_origin: None,
            },
            EventPayload::MouseWheel {
                axis: MouseWheelAxis::Vertical,
                delta: 1,
                x: None,
                y: None,
                window: Some(excluded.clone()),
                input_origin: None,
            },
            EventPayload::MouseMove {
                dx_total: 1,
                dy_total: 1,
                distance_px: 1,
                raw_event_count: 1,
                duration_ms: 1,
                x: None,
                y: None,
                window: Some(excluded.clone()),
                input_origin: None,
            },
            EventPayload::ProcessStarted {
                pid: 1,
                exe: excluded.exe.clone(),
                exe_source: ProcessExeSource::FullPath,
            },
            EventPayload::ProcessExited {
                pid: 1,
                exe: excluded.exe.clone(),
                exe_source: ProcessExeSource::FullPath,
            },
            EventPayload::NotificationsReceived {
                app: Some("PRIVATE".to_string()),
                count: 1,
            },
        ];
        for payload in attributed {
            assert!(policy.apply(envelope(payload)).is_none());
        }

        assert!(policy
            .apply(envelope(EventPayload::WindowOpened {
                window: allowed,
                origin: WindowLifecycleOrigin::Observed,
            }))
            .is_some());
        let mut action = sample_action_capture(Instant::now());
        action.exe = Some("/Applications/Private.EXE".to_string());
        assert!(policy.excludes_action(&action));

        let controls = CaptureControls::all_enabled().with_excluded_apps(["PRIVATE.exe"]);
        assert!(controls.app_excluded(r"C:\Apps\private.EXE"));
        assert!(!controls.app_excluded("allowed.exe"));
        assert!(controls.has_app_exclusions());
        assert!(controls.notification_app_excluded("PRIVATE"));
        assert!(!controls.notification_app_excluded("Private Workspace"));
    }

    #[test]
    fn exclusions_fail_closed_for_unattributed_input_and_all_notifications() {
        let policy = Policy::identity().with_excluded_apps(["private.exe"]);
        let excluded = attributed_window("private.exe");
        let allowed = attributed_window("allowed.exe");

        assert!(policy
            .apply(envelope(EventPayload::FocusChanged {
                window: excluded.clone(),
                prev: Some(allowed.clone()),
                previous_focused_for_ms: 1,
                window_unfocused_for_ms: 2,
                recovered: false,
            }))
            .is_none());

        let unattributed_input = vec![
            EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
            EventPayload::MouseClick {
                button: MouseButton::Left,
                x: None,
                y: None,
                window: None,
                input_origin: None,
            },
            EventPayload::MouseDoubleClick {
                button: MouseButton::Left,
                interval_ms: 1,
                x: None,
                y: None,
                window: None,
                input_origin: None,
            },
            EventPayload::MouseDrag {
                button: MouseButton::Left,
                dx_total: 1,
                dy_total: 1,
                distance_px: 1,
                raw_event_count: 1,
                duration_ms: 1,
                start_x: None,
                start_y: None,
                end_x: None,
                end_y: None,
                window: None,
                selection_candidate: false,
                input_origin: None,
            },
            EventPayload::MouseWheel {
                axis: MouseWheelAxis::Vertical,
                delta: 1,
                x: None,
                y: None,
                window: None,
                input_origin: None,
            },
            EventPayload::MouseMove {
                dx_total: 1,
                dy_total: 1,
                distance_px: 1,
                raw_event_count: 1,
                duration_ms: 1,
                x: None,
                y: None,
                window: None,
                input_origin: None,
            },
        ];
        for payload in unattributed_input {
            assert!(
                policy.apply(envelope(payload)).is_none(),
                "unattributed foreground-bound input must fail closed"
            );
        }

        // DisplayName/PFN/AUMID metadata cannot be treated as a reliable exe
        // mapping. With any exclusion configured, both an unrelated label and
        // a missing label therefore fail closed globally.
        assert!(policy
            .apply(envelope(EventPayload::NotificationsReceived {
                app: Some("Friendly Product Name".to_string()),
                count: 1,
            }))
            .is_none());
        assert!(policy
            .apply(envelope(EventPayload::NotificationsReceived {
                app: None,
                count: 1,
            }))
            .is_none());

        assert!(policy
            .apply(envelope(EventPayload::FocusChanged {
                window: allowed,
                prev: Some(excluded),
                previous_focused_for_ms: 3,
                window_unfocused_for_ms: 4,
                recovered: false,
            }))
            .is_some());
        assert!(policy
            .apply(envelope(EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            }))
            .is_some());
        assert!(policy
            .apply(envelope(EventPayload::NotificationsReceived {
                app: Some("Friendly Product Name".to_string()),
                count: 1,
            }))
            .is_none());
        assert!(Policy::identity()
            .apply(envelope(EventPayload::NotificationsReceived {
                app: Some("Friendly Product Name".to_string()),
                count: 1,
            }))
            .is_some());
    }

    fn unattributed_key() -> EventPayload {
        EventPayload::Key {
            key: "A".to_string(),
            mods: Modifiers::default(),
            window: None,
            key_class: None,
        }
    }

    fn unattributed_mouse_move() -> EventPayload {
        EventPayload::MouseMove {
            dx_total: 1,
            dy_total: 1,
            distance_px: 1,
            raw_event_count: 1,
            duration_ms: 1,
            x: None,
            y: None,
            window: None,
            input_origin: None,
        }
    }

    #[test]
    fn exclusion_never_observed_focus_fails_closed_for_unattributed_input() {
        // The first fail-open ordering: the Foreground stream was off from
        // process start, so no FocusChanged ever reached the latch. With an
        // exclusion configured, window-less input could belong to the
        // excluded app and must not store.
        let policy = Policy::identity().with_excluded_apps(["private.exe"]);
        assert!(policy.apply(envelope(unattributed_key())).is_none());
        assert!(policy.apply(envelope(unattributed_mouse_move())).is_none());

        // Attributed rows keep their per-row verdicts: the latch is not
        // consulted in either direction.
        assert!(policy
            .apply(envelope(EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: Some(attributed_window("allowed.exe")),
                key_class: None,
            }))
            .is_some());
        assert!(policy
            .apply(envelope(EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: Some(attributed_window("private.exe")),
                key_class: None,
            }))
            .is_none());

        // No exclusions configured: nothing to protect, capture proceeds.
        assert!(Policy::identity()
            .apply(envelope(unattributed_key()))
            .is_some());
    }

    #[test]
    fn exclusion_observed_then_stopped_focus_fails_closed_after_forget() {
        // The second fail-open ordering, the ordinary user path: focus was
        // observed on an allowed app, then the Foreground stream stopped.
        // The latched not-excluded verdict must not survive the stop.
        let policy = Policy::identity().with_excluded_apps(["private.exe"]);
        let allowed = attributed_window("allowed.exe");

        assert!(policy
            .apply(envelope(EventPayload::FocusChanged {
                window: allowed.clone(),
                prev: None,
                previous_focused_for_ms: 0,
                window_unfocused_for_ms: 0,
                recovered: false,
            }))
            .is_some());
        // While the stream runs, the latch attributes window-less input to
        // the allowed app.
        assert!(policy.apply(envelope(unattributed_key())).is_some());

        policy.forget_focus_attribution();
        assert!(policy.apply(envelope(unattributed_key())).is_none());
        assert!(policy.apply(envelope(unattributed_mouse_move())).is_none());
        // Attributed input is unaffected by the forgotten latch.
        assert!(policy
            .apply(envelope(EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: Some(allowed.clone()),
                key_class: None,
            }))
            .is_some());

        // A re-enabled stream re-arms the latch with its next focus row.
        assert!(policy
            .apply(envelope(EventPayload::FocusChanged {
                window: allowed,
                prev: None,
                previous_focused_for_ms: 0,
                window_unfocused_for_ms: 0,
                recovered: false,
            }))
            .is_some());
        assert!(policy.apply(envelope(unattributed_key())).is_some());

        // Forgetting an excluded-focus latch stays closed: forget never
        // fails open regardless of what the latch held.
        let excluded = attributed_window("private.exe");
        assert!(policy
            .apply(envelope(EventPayload::FocusChanged {
                window: excluded,
                prev: None,
                previous_focused_for_ms: 0,
                window_unfocused_for_ms: 0,
                recovered: false,
            }))
            .is_none());
        policy.forget_focus_attribution();
        assert!(policy.apply(envelope(unattributed_key())).is_none());
    }

    #[test]
    fn sensitive_rows_under_unknown_latch_drop_but_update_suppression() {
        // Sensitive-context rows carry no WindowRef, so the latch is their
        // only attribution. Under an unknown latch with exclusions they fail
        // closed like unattributed input, while the suppression state
        // machine keeps tracking so following keys still redact.
        let policy = Policy::identity()
            .with_excluded_apps(["private.exe"])
            .with_sensitive_context_suppression(true);

        assert!(policy
            .apply(envelope(EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField,
            }))
            .is_none());
        let key = policy
            .apply(envelope(EventPayload::Key {
                key: "P".to_string(),
                mods: Modifiers::default(),
                window: Some(attributed_window("allowed.exe")),
                key_class: None,
            }))
            .expect("attributed allowed key stores");
        assert!(key.is_sensitive);
        match key.payload {
            EventPayload::Key { key, .. } => assert_eq!(key, "<redacted>"),
            _ => panic!("expected key event"),
        }

        assert!(policy
            .apply(envelope(EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField,
            }))
            .is_none());
        let key_after = policy
            .apply(envelope(EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: Some(attributed_window("allowed.exe")),
                key_class: None,
            }))
            .expect("post-exit key stores");
        assert!(!key_after.is_sensitive);
    }

    #[test]
    fn action_capture_wire_round_trips_without_process_local_instant() {
        let now = Instant::now();
        let captured_at = now
            .checked_sub(Duration::from_millis(1_250))
            .expect("captured instant");
        let capture = sample_action_capture(captured_at);

        let wire = ActionCaptureWire::from_capture_at(&capture, 1_780_000_000_000);
        let json = serde_json::to_string(&wire).expect("serialize wire action");

        assert!(!json.contains("captured_at"));
        assert!(!json.contains("title"));
        assert_eq!(wire.record_session_id, 99);
        assert_eq!(wire.action, capture.action);
        assert_eq!(wire.payload, capture.payload);

        let round_trip = wire.into_capture_at(now, 1_780_000_001_250);

        assert_eq!(round_trip.captured_at, captured_at);
        assert_eq!(round_trip.record_session_id, capture.record_session_id);
        assert_eq!(round_trip.action, capture.action);
        assert_eq!(round_trip.exe, capture.exe);
        assert_eq!(round_trip.framework_class, FrameworkClass::Native);
        assert_eq!(round_trip.payload, capture.payload);
    }

    #[test]
    fn record_routine_ipc_messages_use_stable_snake_case_tags() {
        let ready = RecordRoutineIpcMessage::Ready {
            schema: "gilbreth.record_routine.ipc.v1".to_string(),
            record_session_id: 99,
            helper_pid: 1234,
            transport: "named_pipe".to_string(),
        };
        let ready_json = serde_json::to_string(&ready).expect("serialize ready message");

        assert!(ready_json.contains("\"type\":\"ready\""));
        assert!(ready_json.contains("\"schema\":\"gilbreth.record_routine.ipc.v1\""));

        let control = RecordRoutineIpcControl::Stop {
            record_session_id: 99,
        };
        let control_json = serde_json::to_string(&control).expect("serialize stop control");

        assert_eq!(control_json, "{\"type\":\"stop\",\"record_session_id\":99}");
        assert_eq!(
            serde_json::from_str::<RecordRoutineIpcControl>(&control_json)
                .expect("deserialize stop control"),
            control
        );

        let keep_alive = RecordRoutineIpcControl::KeepAlive {
            record_session_id: 99,
        };
        let keep_alive_json =
            serde_json::to_string(&keep_alive).expect("serialize keep-alive control");

        assert_eq!(
            keep_alive_json,
            "{\"type\":\"keep_alive\",\"record_session_id\":99}"
        );
        assert_eq!(
            serde_json::from_str::<RecordRoutineIpcControl>(&keep_alive_json)
                .expect("deserialize keep-alive control"),
            keep_alive
        );
    }

    #[test]
    fn action_type_round_trips_stored_strings() {
        for action_type in ActionType::ALL {
            assert_eq!(
                action_type.as_str().parse::<ActionType>().expect("parse"),
                action_type
            );
            assert_eq!(
                serde_json::from_str::<ActionType>(
                    &serde_json::to_string(&action_type).expect("serialize")
                )
                .expect("deserialize"),
                action_type
            );
        }

        assert!("none".parse::<ActionType>().is_err());
    }

    #[test]
    fn record_routine_diagnostic_enums_round_trip_strings() {
        for signal in EditCommitSignal::ALL {
            assert_eq!(
                signal.as_str().parse::<EditCommitSignal>().expect("parse"),
                signal
            );
            assert_eq!(
                serde_json::from_str::<EditCommitSignal>(
                    &serde_json::to_string(&signal).expect("serialize")
                )
                .expect("deserialize"),
                signal
            );
        }

        for reason in RejectedActionReason::ALL {
            assert_eq!(
                reason
                    .as_str()
                    .parse::<RejectedActionReason>()
                    .expect("parse"),
                reason
            );
            assert_eq!(
                serde_json::from_str::<RejectedActionReason>(
                    &serde_json::to_string(&reason).expect("serialize")
                )
                .expect("deserialize"),
                reason
            );
        }

        assert!("composition_done".parse::<EditCommitSignal>().is_err());
        assert!("provider_pid_only".parse::<RejectedActionReason>().is_err());
    }

    #[test]
    fn framework_class_round_trips_and_maps_framework_ids() {
        let classes = [
            FrameworkClass::Native,
            FrameworkClass::NativeProvisional,
            FrameworkClass::WebRenderer,
            FrameworkClass::Virtualized,
            FrameworkClass::Unknown,
        ];
        for framework_class in classes {
            assert_eq!(
                framework_class
                    .as_str()
                    .parse::<FrameworkClass>()
                    .expect("parse"),
                framework_class
            );
            assert_eq!(
                serde_json::from_str::<FrameworkClass>(
                    &serde_json::to_string(&framework_class).expect("serialize")
                )
                .expect("deserialize"),
                framework_class
            );
        }

        assert_eq!(framework_class_from_id("Win32"), FrameworkClass::Native);
        assert_eq!(
            framework_class_from_id("Chrome"),
            FrameworkClass::WebRenderer
        );
        assert_eq!(
            framework_class_from_id("Qt"),
            FrameworkClass::NativeProvisional
        );
        assert_eq!(
            framework_class_from_id("Citrix"),
            FrameworkClass::Virtualized
        );
        assert_eq!(framework_class_from_id(""), FrameworkClass::Unknown);
        assert!("native_like".parse::<FrameworkClass>().is_err());
    }

    #[test]
    fn record_request_status_round_trips_stored_strings() {
        for status in RecordRequestStatus::ALL {
            assert_eq!(
                status
                    .as_str()
                    .parse::<RecordRequestStatus>()
                    .expect("parse"),
                status
            );
            assert_eq!(
                serde_json::from_str::<RecordRequestStatus>(
                    &serde_json::to_string(&status).expect("serialize")
                )
                .expect("deserialize"),
                status
            );
        }

        assert!("pending".parse::<RecordRequestStatus>().is_err());
    }

    #[test]
    fn record_stop_reason_round_trips_stored_strings() {
        for reason in RecordStopReason::ALL {
            assert_eq!(
                reason.as_str().parse::<RecordStopReason>().expect("parse"),
                reason
            );
            assert_eq!(
                serde_json::from_str::<RecordStopReason>(
                    &serde_json::to_string(&reason).expect("serialize")
                )
                .expect("deserialize"),
                reason
            );
        }

        assert!("crash_recovered".parse::<RecordStopReason>().is_err());
    }

    #[test]
    fn capture_pause_boundaries_serialize_without_values() {
        assert_eq!(
            serde_json::to_value(EventPayload::CapturePaused).expect("pause serializes"),
            serde_json::json!({"kind": "capture_paused"})
        );
        assert_eq!(
            serde_json::to_value(EventPayload::CaptureResumed).expect("resume serializes"),
            serde_json::json!({"kind": "capture_resumed"})
        );
    }

    #[test]
    fn selector_path_v1_serialization_escapes_and_normalizes() {
        let path = SelectorPath {
            backend: "uia".to_string(),
            hops: vec![SelectorPathHop {
                control_type: 50004,
                automation_id: "Main\\Panel|Name\nLine\rEnd".to_string(),
                class_name: "RichEditD2DPT\rWidget".to_string(),
                ordinal: 3,
            }],
        };

        assert_eq!(
            path.serialize_v1(),
            "gilbreth.selector_path.v1\nbackend=uia\nhop=0|control_type=50004|automation_id=Main\\\\Panel\\|Name\\nLine\\rEnd|class_name=richeditd2dpt\\rwidget|ordinal=3"
        );
    }

    #[test]
    fn selector_path_hash_v1_matches_golden_value() {
        assert_eq!(
            sample_selector_path().serialize_v1(),
            "gilbreth.selector_path.v1\nbackend=uia\nhop=0|control_type=50032|automation_id=root|class_name=notepad|ordinal=0\nhop=1|control_type=50004|automation_id=15|class_name=edit|ordinal=1"
        );
        assert_eq!(
            sample_selector_path().hash_v1(),
            "58e709df2a08130f722a05b319cb285b93076e10c5b9861fdb95ceda4145befe"
        );
    }

    #[test]
    fn selector_trust_basis_round_trips_without_provider_pid_only() {
        for trust_basis in SelectorTrustBasis::ALL {
            assert_eq!(
                trust_basis
                    .as_str()
                    .parse::<SelectorTrustBasis>()
                    .expect("parse"),
                trust_basis
            );
        }

        assert!("provider_pid_only".parse::<SelectorTrustBasis>().is_err());
    }

    struct FakeAutomationClient {
        actions: Arc<Mutex<VecDeque<AutomationAction>>>,
    }

    impl FakeAutomationClient {
        fn new(actions: impl IntoIterator<Item = AutomationAction>) -> Self {
            Self {
                actions: Arc::new(Mutex::new(actions.into_iter().collect())),
            }
        }
    }

    impl AutomationClient for FakeAutomationClient {
        fn next_action(&self) -> Result<Option<AutomationAction>, AutomationClientError> {
            Ok(self.actions.lock().expect("lock").pop_front())
        }
    }

    #[test]
    fn automation_client_trait_is_object_safe_for_fake_capture() {
        let action = AutomationAction {
            action_type: ActionType::Toggle,
            selector_path: sample_selector_path(),
            trust_basis: SelectorTrustBasis::WindowOwnership,
        };
        let client = FakeAutomationClient::new([action.clone()]);
        let client: &dyn AutomationClient = &client;

        assert_eq!(client.next_action().expect("next action"), Some(action));
        assert_eq!(client.next_action().expect("drained"), None);
    }

    #[test]
    fn action_payload_omits_reserved_fields_until_populated() {
        let payload = ActionPayload::Invoke {
            from_modality: None,
            corroborates: None,
        };

        let json = serde_json::to_value(&payload).expect("serialize payload");

        assert_eq!(json, serde_json::json!({ "kind": "invoke" }));
    }

    #[test]
    fn action_payload_serializes_reserved_fields_when_present() {
        let payload = ActionPayload::Scroll {
            direction: ScrollDirection::Down,
            amount_bucket: Some(3),
            from_modality: Some(Modality::Mouse),
            corroborates: Some(42),
        };

        let json = serde_json::to_value(&payload).expect("serialize payload");

        assert_eq!(
            json,
            serde_json::json!({
                "kind": "scroll",
                "direction": "down",
                "amount_bucket": 3,
                "from_modality": "mouse",
                "corroborates": 42
            })
        );
    }

    #[test]
    fn action_payload_reserved_fields_are_uniform_across_variants() {
        let payloads = [
            (
                "invoke",
                ActionPayload::Invoke {
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "toggle",
                ActionPayload::Toggle {
                    to_state: ToggleActionState::On,
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "select",
                ActionPayload::Select {
                    selection_size: Some(2),
                    in_set_of: Some(5),
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "expand_collapse",
                ActionPayload::ExpandCollapse {
                    to_state: ExpandCollapseActionState::Expanded,
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "edit_committed",
                ActionPayload::EditCommitted {
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "scroll",
                ActionPayload::Scroll {
                    direction: ScrollDirection::Horizontal,
                    amount_bucket: Some(4),
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
            (
                "ui_action_other",
                ActionPayload::UiActionOther {
                    raw_pattern_id: Some(10_001),
                    from_modality: Some(Modality::Keyboard),
                    corroborates: Some(7),
                },
            ),
        ];

        for (kind, payload) in payloads {
            let json = serde_json::to_value(&payload).expect("serialize payload");
            assert_eq!(json["kind"], kind);
            assert_eq!(json["from_modality"], "keyboard");
            assert_eq!(json["corroborates"], 7);
        }
    }

    #[test]
    fn sequencer_assigns_monotonic_seq_and_session() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));

        let first = sequencer.stamp(Captured::new(
            Source::Foreground,
            base,
            focus_payload("First"),
        ));
        let second = sequencer.stamp(Captured::new(
            Source::Foreground,
            base + Duration::from_millis(1),
            focus_payload("Second"),
        ));

        assert_eq!(first.session_id, 10);
        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
    }

    #[test]
    fn sequencer_stamp_action_shares_seq_and_timestamp_clamp() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));

        let motion = sequencer.stamp(Captured::new(
            Source::Foreground,
            base + Duration::from_millis(100),
            focus_payload("Motion"),
        ));
        let action =
            sequencer.stamp_action(sample_action_capture(base + Duration::from_millis(50)));
        let next_motion = sequencer.stamp(Captured::new(
            Source::Foreground,
            base + Duration::from_millis(200),
            focus_payload("Next"),
        ));

        assert_eq!(motion.seq, 1);
        assert_eq!(action.seq, 2);
        assert_eq!(next_motion.seq, 3);
        assert_eq!(action.session_id, 10);
        assert_eq!(action.ts_unix_ms, motion.ts_unix_ms);
        assert_eq!(next_motion.ts_unix_ms, 1_200);
    }

    #[test]
    fn timebase_derives_wall_time_from_capture_instant() {
        let base = Instant::now();
        let timebase = SessionTimebase::new(base, 1_000);

        assert_eq!(
            timebase.timestamp_for(base + Duration::from_millis(250)),
            1_250
        );
    }

    #[test]
    fn timebase_resyncs_positive_drift() {
        let base = Instant::now();
        let mut timebase = SessionTimebase::new(base, 1_000);

        let correction = timebase
            .resync(base + Duration::from_secs(10), 12_500, 1_000, None)
            .expect("drift crosses threshold");

        assert_eq!(correction.old_base_utc_ms, 1_000);
        assert_eq!(correction.new_base_utc_ms, 12_500);
        assert_eq!(correction.measured_drift_ms, 1_500);
        assert_eq!(correction.clamp_ms, 0);
        assert_eq!(
            timebase.timestamp_for(base + Duration::from_millis(10_250)),
            12_750
        );
    }

    #[test]
    fn timebase_resyncs_negative_drift() {
        let base = Instant::now();
        let mut timebase = SessionTimebase::new(base, 1_000);

        let correction = timebase
            .resync(base + Duration::from_secs(10), 9_000, 1_000, None)
            .expect("drift crosses threshold");

        assert_eq!(correction.measured_drift_ms, -2_000);
        assert_eq!(correction.new_base_utc_ms, 9_000);
        assert_eq!(
            timebase.timestamp_for(base + Duration::from_millis(10_500)),
            9_500
        );
    }

    #[test]
    fn timebase_resync_ignores_below_threshold_drift() {
        let base = Instant::now();
        let mut timebase = SessionTimebase::new(base, 1_000);

        let correction = timebase.resync(base + Duration::from_secs(10), 11_400, 1_000, None);

        assert_eq!(correction, None);
        assert_eq!(
            timebase.timestamp_for(base + Duration::from_secs(10)),
            11_000
        );
    }

    #[test]
    fn sequencer_resync_never_moves_timestamps_backwards() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let stamped = sequencer.stamp(Captured::new(
            Source::Foreground,
            base + Duration::from_secs(10),
            focus_payload("Later"),
        ));

        let correction = sequencer
            .resync(base + Duration::from_secs(2), 5_000, 100)
            .expect("drift crosses threshold");
        let after_resync = sequencer.stamp(Captured::new(
            Source::Foreground,
            base + Duration::from_secs(2),
            focus_payload("Earlier instant"),
        ));

        assert_eq!(stamped.ts_unix_ms, 11_000);
        assert_eq!(correction.new_base_utc_ms, 11_000);
        assert_eq!(correction.clamp_ms, 6_000);
        assert_eq!(after_resync.ts_unix_ms, 11_000);
    }

    #[test]
    fn process_payload_kinds_are_stable() {
        assert_eq!(
            EventPayload::ProcessStarted {
                pid: 1,
                exe: "notepad.exe".to_string(),
                exe_source: ProcessExeSource::SnapshotName,
            }
            .kind(),
            "process_started"
        );
        assert_eq!(
            EventPayload::ProcessExited {
                pid: 1,
                exe: "notepad.exe".to_string(),
                exe_source: ProcessExeSource::SnapshotName,
            }
            .kind(),
            "process_exited"
        );
    }

    #[test]
    fn identity_policy_preserves_event() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Foreground,
            base,
            focus_payload("Plain"),
        ));

        let filtered = Policy::identity().apply(event.clone());

        assert_eq!(filtered, Some(event));
    }

    #[test]
    fn policy_reports_sensitive_context_only_when_suppression_is_enabled() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let enabled_policy = Policy::identity().with_sensitive_context_suppression(true);
        let disabled_policy = Policy::identity().with_sensitive_context_suppression(false);
        let entered = sequencer.stamp(Captured::new(
            Source::System,
            base,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked,
            },
        ));

        enabled_policy.apply(entered.clone());
        disabled_policy.apply(entered);

        assert!(enabled_policy.sensitive_context_active());
        assert!(!disabled_policy.sensitive_context_active());
    }

    #[test]
    fn policy_reports_active_sensitive_reasons_in_stable_order() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let policy = Policy::identity().with_sensitive_context_suppression(true);

        for reason in [
            SensitiveContextReason::PasswordField,
            SensitiveContextReason::SessionLocked,
        ] {
            policy.apply(sequencer.stamp(Captured::new(
                Source::System,
                base,
                EventPayload::SensitiveContextEntered { reason },
            )));
        }

        assert_eq!(
            policy.active_sensitive_reasons(),
            vec![
                SensitiveContextReason::SessionLocked,
                SensitiveContextReason::PasswordField
            ]
        );
    }

    #[test]
    fn policy_marks_capture_redacted_keys_sensitive_before_boundary_arrives() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let policy = Policy::identity().with_sensitive_context_suppression(true);
        let event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base,
            EventPayload::Key {
                key: "<redacted>".to_string(),
                mods: Modifiers::default(),
                window: Some(window_ref("<redacted>")),
                key_class: None,
            },
        ));

        let filtered = policy.apply(event).expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::Key { key, window, .. } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(window.expect("window").title, "<redacted>");
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn redaction_policy_marks_sensitive_and_removes_title() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Foreground,
            base,
            focus_payload("Secret Plan"),
        ));

        let filtered = Policy::redact_titles_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::FocusChanged { window, .. } => {
                assert_eq!(window.title, "<redacted>");
            }
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn redaction_policy_covers_window_lifecycle_titles() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Window,
            base,
            EventPayload::WindowClosed {
                window: WindowRef {
                    hwnd: 0x4567,
                    exe: "C:\\Apps\\editor.exe".to_string(),
                    title: "Secret Notes".to_string(),
                    pid: 77,
                },
                open_for_ms: 500,
                origin: WindowLifecycleOrigin::Observed,
            },
        ));

        let filtered = Policy::redact_titles_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::WindowClosed { window, .. } => {
                assert_eq!(window.title, "<redacted>");
            }
            _ => panic!("expected window closed event"),
        }
    }

    #[test]
    fn redaction_policy_covers_key_content() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base,
            EventPayload::Key {
                key: "Secret".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));

        let filtered = Policy::redact_keys_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::Key { key, .. } => {
                assert_eq!(key, "<redacted>");
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn key_class_for_name_covers_key_name_families() {
        assert_eq!(key_class_for_name("A"), KeyClass::Printable);
        assert_eq!(key_class_for_name("7"), KeyClass::Printable);
        assert_eq!(key_class_for_name(";"), KeyClass::Printable);
        assert_eq!(key_class_for_name("Space"), KeyClass::Printable);
        assert_eq!(key_class_for_name("Numpad4"), KeyClass::Printable);
        assert_eq!(key_class_for_name("NumpadAdd"), KeyClass::Printable);
        assert_eq!(key_class_for_name("Backspace"), KeyClass::Navigation);
        assert_eq!(key_class_for_name("Tab"), KeyClass::Navigation);
        assert_eq!(key_class_for_name("Delete"), KeyClass::Navigation);
        assert_eq!(key_class_for_name("ArrowLeft"), KeyClass::Navigation);
        assert_eq!(key_class_for_name("PageDown"), KeyClass::Navigation);
        assert_eq!(key_class_for_name("Shift"), KeyClass::Modifier);
        assert_eq!(key_class_for_name("Win"), KeyClass::Modifier);
        assert_eq!(key_class_for_name("CapsLock"), KeyClass::Modifier);
        // Additive macOS modifier-key names (Keyboard+Mouse slice): the mac
        // Cmd/Option/Fn keys' own names must classify with the shared ones.
        assert_eq!(key_class_for_name("Cmd"), KeyClass::Modifier);
        assert_eq!(key_class_for_name("Option"), KeyClass::Modifier);
        assert_eq!(key_class_for_name("Fn"), KeyClass::Modifier);
        assert_eq!(key_class_for_name("Enter"), KeyClass::Function);
        assert_eq!(key_class_for_name("Escape"), KeyClass::Function);
        assert_eq!(key_class_for_name("F1"), KeyClass::Function);
        assert_eq!(key_class_for_name("F24"), KeyClass::Function);
        // A bare "F" is the letter, not a function key.
        assert_eq!(key_class_for_name("F"), KeyClass::Printable);
        assert_eq!(key_class_for_name("VK_0xff"), KeyClass::Other);
    }

    #[test]
    fn lean_policy_omits_key_content_without_marking_sensitive() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base,
            EventPayload::Key {
                key: "S".to_string(),
                mods: Modifiers {
                    shift: true,
                    ctrl: false,
                    alt: false,
                    win: false,
                },
                window: None,
                key_class: None,
            },
        ));

        let filtered = Policy::identity()
            .with_store_key_content(false)
            .apply(event)
            .expect("policy keeps row");

        // Policy-omitted content is not a fired privacy rule.
        assert!(!filtered.is_sensitive);
        match filtered.payload {
            EventPayload::Key {
                key,
                mods,
                key_class,
                ..
            } => {
                assert_eq!(key, "");
                assert_eq!(key_class, Some(KeyClass::Printable));
                // Timing/modifier analytics stay intact.
                assert!(mods.shift);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn lean_policy_leaves_redacted_keys_unclassified() {
        // A key a redaction rule (or capture-side password redaction) already
        // hit must not gain a key class: classifying it would leak a shape
        // trace of the protected content. The sensitive flag survives.
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base,
            EventPayload::Key {
                key: "Secret".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));

        let filtered = Policy::redact_keys_containing(["Secret"])
            .with_store_key_content(false)
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::Key { key, key_class, .. } => {
                assert_eq!(key, "");
                assert_eq!(key_class, None);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn full_capture_policy_stores_key_content_without_class() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base,
            EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));

        let filtered = Policy::identity()
            .with_store_key_content(true)
            .apply(event)
            .expect("policy keeps row");

        assert!(!filtered.is_sensitive);
        match filtered.payload {
            EventPayload::Key { key, key_class, .. } => {
                assert_eq!(key, "A");
                assert_eq!(key_class, None);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn redaction_policy_can_combine_title_and_key_rules() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let title_event = sequencer.stamp(Captured::new(
            Source::Foreground,
            base,
            focus_payload("Secret Window"),
        ));
        let key_event = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base + Duration::from_millis(1),
            EventPayload::Key {
                key: "Password".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));
        let policy = Policy::identity()
            .with_title_redactions(["Secret"])
            .with_key_redactions(["Password"]);

        let filtered_title = policy.apply(title_event).expect("title row kept");
        let filtered_key = policy.apply(key_event).expect("key row kept");

        assert!(filtered_title.is_sensitive);
        assert!(filtered_key.is_sensitive);
        match filtered_title.payload {
            EventPayload::FocusChanged { window, .. } => {
                assert_eq!(window.title, "<redacted>");
            }
            _ => panic!("expected focus event"),
        }
        match filtered_key.payload {
            EventPayload::Key { key, .. } => {
                assert_eq!(key, "<redacted>");
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn redaction_policy_covers_mouse_window_titles() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Mouse,
            base,
            EventPayload::MouseClick {
                button: MouseButton::Left,
                x: Some(10),
                y: Some(20),
                window: Some(WindowRef {
                    hwnd: 0x7890,
                    exe: "C:\\Apps\\browser.exe".to_string(),
                    title: "Secret Browser".to_string(),
                    pid: 88,
                }),
                input_origin: None,
            },
        ));

        let filtered = Policy::redact_titles_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::MouseClick {
                window: Some(window),
                ..
            } => {
                assert_eq!(window.title, "<redacted>");
            }
            _ => panic!("expected mouse click event"),
        }
    }

    #[test]
    fn redaction_policy_covers_mouse_semantic_window_titles() {
        let window = || WindowRef {
            hwnd: 0x7890,
            exe: "C:\\Apps\\browser.exe".to_string(),
            title: "Secret Browser".to_string(),
            pid: 88,
        };
        let policy = Policy::redact_titles_containing(["Secret"]);

        let double_click = EventEnvelope {
            schema_version: 1,
            session_id: 10,
            seq: 1,
            ts_unix_ms: 1_000,
            source: Source::Mouse,
            is_sensitive: false,
            payload: EventPayload::MouseDoubleClick {
                button: MouseButton::Left,
                interval_ms: 120,
                x: Some(10),
                y: Some(20),
                window: Some(window()),
                input_origin: None,
            },
        };
        let filtered_double = policy
            .apply(double_click)
            .expect("policy keeps double-click row");
        assert!(filtered_double.is_sensitive);
        match filtered_double.payload {
            EventPayload::MouseDoubleClick {
                window: Some(window),
                ..
            } => assert_eq!(window.title, "<redacted>"),
            _ => panic!("expected mouse double-click event"),
        }

        let drag = EventEnvelope {
            schema_version: 1,
            session_id: 10,
            seq: 2,
            ts_unix_ms: 1_100,
            source: Source::Mouse,
            is_sensitive: false,
            payload: EventPayload::MouseDrag {
                button: MouseButton::Left,
                dx_total: 10,
                dy_total: 5,
                distance_px: 11,
                raw_event_count: 2,
                duration_ms: 200,
                start_x: Some(10),
                start_y: Some(20),
                end_x: Some(20),
                end_y: Some(25),
                window: Some(window()),
                selection_candidate: true,
                input_origin: None,
            },
        };
        let filtered_drag = policy.apply(drag).expect("policy keeps drag row");
        assert!(filtered_drag.is_sensitive);
        match filtered_drag.payload {
            EventPayload::MouseDrag {
                window: Some(window),
                ..
            } => assert_eq!(window.title, "<redacted>"),
            _ => panic!("expected mouse drag event"),
        }
    }

    #[test]
    fn redaction_policy_covers_notification_app_labels() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::System,
            base,
            EventPayload::NotificationsReceived {
                app: Some("Secret Calendar".to_string()),
                count: 1,
            },
        ));

        let filtered = Policy::redact_titles_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");

        assert!(filtered.is_sensitive);
        match filtered.payload {
            EventPayload::NotificationsReceived { app, count } => {
                assert_eq!(app.as_deref(), Some("<redacted>"));
                assert_eq!(count, 1);
            }
            _ => panic!("expected notification event"),
        }
    }

    #[test]
    fn sensitive_context_policy_redacts_until_exit() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let policy = Policy::identity().with_sensitive_context_suppression(true);
        let entered = sequencer.stamp(Captured::new(
            Source::System,
            base,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked,
            },
        ));
        let key_during = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base + Duration::from_millis(1),
            EventPayload::Key {
                key: "P".to_string(),
                mods: Modifiers {
                    shift: true,
                    ctrl: false,
                    alt: true,
                    win: false,
                },
                window: Some(WindowRef {
                    hwnd: 0x99,
                    exe: "C:\\Apps\\login.exe".to_string(),
                    title: "Login".to_string(),
                    pid: 99,
                }),
                key_class: None,
            },
        ));
        let clipboard_during = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(2),
            EventPayload::ClipboardUsed {
                sequence_number: 7,
                format_kind: ClipboardFormatKind::Text,
                format_count: 1,
                text_char_count: Some(12),
                byte_size: Some(26),
            },
        ));
        let notification_during = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(3),
            EventPayload::NotificationsReceived {
                app: Some("Calendar".to_string()),
                count: 1,
            },
        ));
        let exited = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(4),
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked,
            },
        ));
        let key_after = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base + Duration::from_millis(5),
            EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));

        assert!(!policy.apply(entered).expect("entered kept").is_sensitive);
        let filtered_key = policy.apply(key_during).expect("key kept");
        let filtered_clipboard = policy.apply(clipboard_during).expect("clipboard kept");
        let filtered_notification = policy
            .apply(notification_during)
            .expect("notification kept");
        assert!(!policy.apply(exited).expect("exited kept").is_sensitive);
        let filtered_after = policy.apply(key_after).expect("post-exit key kept");

        assert!(filtered_key.is_sensitive);
        match filtered_key.payload {
            EventPayload::Key {
                key,
                mods,
                window: Some(window),
                ..
            } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(mods, Modifiers::default());
                assert_eq!(window.title, "<redacted>");
            }
            _ => panic!("expected key event"),
        }
        assert!(filtered_clipboard.is_sensitive);
        match filtered_clipboard.payload {
            EventPayload::ClipboardUsed {
                text_char_count,
                byte_size,
                ..
            } => {
                assert_eq!(text_char_count, None);
                assert_eq!(byte_size, None);
            }
            _ => panic!("expected clipboard event"),
        }
        assert!(filtered_notification.is_sensitive);
        match filtered_notification.payload {
            EventPayload::NotificationsReceived { app, count } => {
                assert_eq!(app.as_deref(), Some("<redacted>"));
                assert_eq!(count, 1);
            }
            _ => panic!("expected notification event"),
        }
        assert!(!filtered_after.is_sensitive);
        match filtered_after.payload {
            EventPayload::Key { key, .. } => assert_eq!(key, "A"),
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn sensitive_context_policy_tracks_overlapping_reasons() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(10, SessionTimebase::new(base, 1_000));
        let policy = Policy::identity().with_sensitive_context_suppression(true);

        let entered_lock = sequencer.stamp(Captured::new(
            Source::System,
            base,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked,
            },
        ));
        let entered_password = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(1),
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField,
            },
        ));
        let exited_lock = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(2),
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked,
            },
        ));
        let key_during_password = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base + Duration::from_millis(3),
            EventPayload::Key {
                key: "S".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));
        let exited_password = sequencer.stamp(Captured::new(
            Source::System,
            base + Duration::from_millis(4),
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField,
            },
        ));
        let key_after = sequencer.stamp(Captured::new(
            Source::Keyboard,
            base + Duration::from_millis(5),
            EventPayload::Key {
                key: "A".to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        ));

        policy.apply(entered_lock).expect("lock entered kept");
        policy
            .apply(entered_password)
            .expect("password entered kept");
        policy.apply(exited_lock).expect("lock exited kept");
        let filtered_during = policy
            .apply(key_during_password)
            .expect("key during password kept");
        policy.apply(exited_password).expect("password exited kept");
        let filtered_after = policy.apply(key_after).expect("post-exit key kept");

        assert!(filtered_during.is_sensitive);
        assert!(!filtered_after.is_sensitive);
    }

    // The capture control surface moved here at MAC-0; these portable twins
    // of the capture-windows tests run on every platform's lane, so the
    // shared vocabulary stays guarded even where the Windows suite doesn't
    // run. Deeper behavior (probe plumbing, reseed generations) keeps its
    // original coverage in gilbreth-capture-windows.

    #[test]
    fn exe_basename_lower_handles_both_platforms_path_shapes() {
        assert_eq!(
            exe_basename_lower("C:\\Windows\\System32\\SVCHOST.EXE"),
            "svchost.exe"
        );
        assert_eq!(
            exe_basename_lower("/Applications/Safari.app/Contents/MacOS/Safari"),
            "safari"
        );
        assert_eq!(exe_basename_lower("Notepad.exe"), "notepad.exe");
        assert_eq!(exe_basename_lower("  "), "");
    }

    #[test]
    fn capture_controls_round_trip_settings_and_suspension() {
        let controls = CaptureControls::new(CaptureSettings {
            keyboard: false,
            ..CaptureSettings::all_enabled()
        });
        assert!(!controls.enabled(CaptureStream::Keyboard));
        assert!(controls.enabled(CaptureStream::Mouse));
        assert!(!controls.settings().keyboard);

        controls.set_enabled(CaptureStream::Keyboard, true);
        assert!(controls.settings().keyboard);

        assert!(!controls.is_suspended());
        controls.set_suspended(true);
        assert!(controls.is_suspended());

        let generation = controls.request_title_redacted_reseed();
        assert_eq!(controls.reseed_generation(), generation);
        assert!(controls.take_title_redaction_for_reseed());
        assert!(!controls.take_title_redaction_for_reseed());
    }

    #[test]
    fn sensitive_resume_guard_serializes_transition_producers() {
        let controls = CaptureControls::all_enabled();
        let guard = controls.sensitive_resume_guard();
        let worker_controls = controls.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _pending = worker_controls.begin_sensitive_transition();
            let _transition_guard = worker_controls.sensitive_resume_guard();
            entered_tx.send(()).expect("guard entry reported");
        });

        assert!(entered_rx.recv_timeout(Duration::from_millis(20)).is_err());
        assert!(controls.sensitive_transition_active());
        assert!(controls.is_suspended());
        assert_eq!(controls.sensitive_transition_generation(), 1);
        drop(guard);
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("transition proceeds after resume reopens");
        worker.join().expect("transition worker joins");
        assert!(!controls.sensitive_transition_active());
        assert!(!controls.is_suspended());
    }

    // ── hoisted state-machine tests (moved with the code, 2026-07-12) ──
    // These were gilbreth-capture-windows unit tests; they travel with the
    // hoisted ForegroundState/ProcessNoiseFilter so the shared contract is
    // gated natively on BOTH platforms (core tests run everywhere), not
    // only on the Windows box.

    fn state_window(hwnd: u64, title: &str) -> WindowRef {
        WindowRef {
            hwnd,
            exe: format!("C:\\Apps\\{title}.exe"),
            title: title.to_string(),
            pid: hwnd as u32,
        }
    }

    #[test]
    fn focus_sequence_attributes_completed_dwell_to_previous_window() {
        let mut state = ForegroundState::default();
        let base = Instant::now();
        let first = state_window(1, "A");
        let second = state_window(2, "B");

        let seed = state
            .seed_window_at(first.clone(), base)
            .expect("seed event");
        let first_switch = state
            .on_window_at(second.clone(), base + Duration::from_millis(10))
            .expect("first switch event");
        let second_switch = state
            .on_window_at(first, base + Duration::from_millis(30))
            .expect("second switch event");

        match &seed.payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(*previous_focused_for_ms, 0),
            _ => panic!("expected focus event"),
        }

        match &first_switch.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => {
                assert_eq!(window.title, "B");
                assert_eq!(prev.as_ref().expect("previous window").title, "A");
                assert_eq!(*previous_focused_for_ms, 10);
                assert_eq!(*window_unfocused_for_ms, 0);
            }
            _ => panic!("expected focus event"),
        }

        match &second_switch.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => {
                assert_eq!(window.title, "A");
                assert_eq!(prev.as_ref().expect("previous window").title, "B");
                assert_eq!(*previous_focused_for_ms, 20);
                assert_eq!(*window_unfocused_for_ms, 20);
            }
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn foreground_state_can_end_current_window_at_boundary() {
        let mut state = ForegroundState::default();
        let base = Instant::now();
        let current = state_window(1, "A");

        assert!(state.seed_window_at(current.clone(), base).is_some());
        let ended = state
            .end_current_at(base + Duration::from_millis(42))
            .expect("boundary should emit completed dwell");

        assert!(state.current.is_none());
        assert!(state.last_unfocused_at.contains_key(&current.hwnd));
        match &ended.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => {
                assert_eq!(window.title, "A");
                assert_eq!(prev.as_ref().expect("previous window").title, "A");
                assert_eq!(*previous_focused_for_ms, 42);
                assert_eq!(*window_unfocused_for_ms, 0);
            }
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn destroyed_window_evicts_unfocused_timing() {
        let mut state = ForegroundState::default();
        let base = Instant::now();
        let first = state_window(1, "A");
        let second = state_window(2, "B");

        assert!(state.seed_window_at(first.clone(), base).is_some());
        assert!(state
            .on_window_at(second, base + Duration::from_millis(10))
            .is_some());
        state.on_window_destroyed(first.hwnd);
        let refocus = state
            .on_window_at(first, base + Duration::from_millis(30))
            .expect("refocus event");

        match &refocus.payload {
            EventPayload::FocusChanged {
                window_unfocused_for_ms,
                ..
            } => assert_eq!(*window_unfocused_for_ms, 0),
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn foreground_boundary_can_cap_missed_sleep_dwell() {
        // 30 s is the platforms' missed-power-boundary max dwell; the cap
        // API takes it as a parameter, so the value here just mirrors the
        // production call sites.
        let max_dwell = Duration::from_secs(30);
        let mut state = ForegroundState::default();
        let base = Instant::now();
        let current = state_window(1, "A");

        assert!(state.seed_window_at(current, base).is_some());
        let ended = state
            .end_current_at_with_max_duration(base + Duration::from_secs(9 * 60 * 60), max_dwell)
            .expect("boundary should emit capped dwell");

        match &ended.payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(*previous_focused_for_ms, duration_ms(max_dwell)),
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn foreground_state_exposes_current_window_and_clears_correlations() {
        let mut state = ForegroundState::default();
        let base = Instant::now();
        assert!(state.current_window().is_none());
        assert!(state.current_focused_at().is_none());

        state.seed_window_at(state_window(1, "A"), base);
        assert_eq!(state.current_window().expect("current").title, "A");
        assert_eq!(state.current_focused_at(), Some(base));

        state.on_window_at(state_window(2, "B"), base + Duration::from_millis(10));
        state.clear_unfocused_correlations();
        // Window 1 was unfocused 10 ms ago, but the pause cleared the
        // correlation: the re-focus reports 0, disclosing nothing.
        let refocus = state
            .on_window_at(state_window(1, "A"), base + Duration::from_millis(30))
            .expect("refocus event");
        match &refocus.payload {
            EventPayload::FocusChanged {
                window_unfocused_for_ms,
                ..
            } => assert_eq!(*window_unfocused_for_ms, 0),
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn process_noise_filter_counts_drops_and_reports_summary() {
        let start = Instant::now();
        let mut filter = ProcessNoiseFilter::new(start);
        assert!(!filter.keep_after_counting("svchost.exe", start));
        assert!(!filter.keep_after_counting("svchost.exe", start));
        assert!(!filter.keep_after_counting("git.exe", start));

        // Not due before the summary interval elapses.
        assert!(filter.summary_if_due(start).is_none());

        let later = start + CHURN_SUMMARY_INTERVAL;
        let payload = filter.summary_if_due(later).expect("summary due");
        match payload {
            EventPayload::ProcessChurnSummary {
                window_ms,
                dropped,
                distinct_exes,
                top,
            } => {
                assert!(window_ms >= CHURN_SUMMARY_INTERVAL.as_millis() as u64);
                assert_eq!(dropped, 3);
                assert_eq!(distinct_exes, 2);
                assert_eq!(top.len(), 2);
                assert_eq!(top[0].exe, "svchost.exe");
                assert_eq!(top[0].dropped, 2);
                assert!(!top[0].sustained);
                assert_eq!(top[1].exe, "git.exe");
            }
            other => panic!("expected churn summary, got {other:?}"),
        }
        // Counters reset with the window: a quiet next window emits nothing.
        assert!(filter
            .summary_if_due(later + CHURN_SUMMARY_INTERVAL)
            .is_none());
    }

    #[test]
    fn process_noise_filter_flags_sustained_same_name_churn() {
        let start = Instant::now();
        let mut filter = ProcessNoiseFilter::new(start);
        for _ in 0..CHURN_SUSTAINED_HITS {
            filter.keep_after_counting("crashloop.exe", start);
        }
        filter.keep_after_counting("quiet.exe", start);

        let payload = filter
            .take_summary(start + Duration::from_secs(1))
            .expect("summary with drops");
        match payload {
            EventPayload::ProcessChurnSummary { top, .. } => {
                assert_eq!(top[0].exe, "crashloop.exe");
                assert!(top[0].sustained);
                assert_eq!(top[1].exe, "quiet.exe");
                assert!(!top[1].sustained);
            }
            other => panic!("expected churn summary, got {other:?}"),
        }
    }

    #[test]
    fn process_noise_filter_sustained_needs_hits_inside_window() {
        let start = Instant::now();
        let mut filter = ProcessNoiseFilter::new(start);
        // Same volume spread far wider than the sustained window: no flag.
        for index in 0..CHURN_SUSTAINED_HITS {
            let at = start + CHURN_SUSTAINED_WINDOW * (index as u32);
            filter.keep_after_counting("spread.exe", at);
        }
        let payload = filter
            .take_summary(start + CHURN_SUSTAINED_WINDOW * (CHURN_SUSTAINED_HITS as u32))
            .expect("summary with drops");
        match payload {
            EventPayload::ProcessChurnSummary { top, .. } => {
                assert_eq!(top[0].exe, "spread.exe");
                assert!(!top[0].sustained);
            }
            other => panic!("expected churn summary, got {other:?}"),
        }
    }

    // ProcessMonitor tests, moved with the LIN-1 hoist from
    // gilbreth-capture-macos (fixture paths kept so the moved behavior is
    // byte-comparable against the pre-hoist suite).

    fn process_entry(pid: u32, comm: &str, path: Option<&str>, start: u64) -> ProcessSnapshotEntry {
        ProcessSnapshotEntry {
            pid,
            comm: comm.to_string(),
            path: path.map(str::to_string),
            start_time_id: Some(start),
        }
    }

    fn unfiltered_controls() -> CaptureControls {
        let controls = CaptureControls::all_enabled();
        controls.set_process_filter_enabled(false);
        controls
    }

    #[test]
    fn process_first_snapshot_seeds_silently_then_diffs() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();

        let base = vec![
            process_entry(1, "launchd", Some("/sbin/launchd"), 10),
            process_entry(700, "A", Some("/Applications/A.app/Contents/MacOS/A"), 20),
        ];
        monitor.poll(t0, &controls, &mut || Some(base.clone()), &mut events);
        assert!(events.is_empty(), "the seed is silent");

        let mut next = base.clone();
        next.push(process_entry(
            800,
            "B",
            Some("/Applications/B.app/Contents/MacOS/B"),
            30,
        ));
        next.remove(1); // A exits
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || Some(next.clone()),
            &mut events,
        );
        let kinds: Vec<&str> = events.iter().map(|c| c.payload.kind()).collect();
        assert_eq!(kinds, ["process_exited", "process_started"]);
        assert!(matches!(
            &events[0].payload,
            EventPayload::ProcessExited { pid: 700, .. }
        ));
        match &events[1].payload {
            EventPayload::ProcessStarted {
                pid,
                exe,
                exe_source,
            } => {
                assert_eq!(*pid, 800);
                assert_eq!(exe, "/Applications/B.app/Contents/MacOS/B");
                assert_eq!(*exe_source, ProcessExeSource::FullPath);
            }
            other => panic!("expected started, got {other:?}"),
        }
        assert!(matches!(events[0].source, Source::System));
    }

    #[test]
    fn process_pid_reuse_emits_exit_then_start() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![process_entry(500, "old", Some("/usr/bin/old"), 100)]),
            &mut events,
        );
        // Same pid, new start token and name: the pid was reused.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || Some(vec![process_entry(500, "new", Some("/usr/bin/new"), 900)]),
            &mut events,
        );
        let kinds: Vec<&str> = events.iter().map(|c| c.payload.kind()).collect();
        assert_eq!(kinds, ["process_exited", "process_started"]);
    }

    #[test]
    fn process_comm_fallback_uses_snapshot_name_source() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![process_entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // A path-unreadable daemon appears: comm only.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || {
                Some(vec![
                    process_entry(1, "launchd", Some("/sbin/launchd"), 1),
                    process_entry(901, "secretd", None, 55),
                ])
            },
            &mut events,
        );
        match &events[0].payload {
            EventPayload::ProcessStarted {
                exe, exe_source, ..
            } => {
                assert_eq!(exe, "secretd");
                assert_eq!(*exe_source, ProcessExeSource::SnapshotName);
            }
            other => panic!("expected started, got {other:?}"),
        }
    }

    #[test]
    fn process_sweep_is_throttled_to_the_cadence() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        let calls = std::cell::Cell::new(0u32);
        let mut provider = || {
            calls.set(calls.get() + 1);
            Some(vec![process_entry(1, "launchd", Some("/sbin/launchd"), 1)])
        };
        monitor.poll(t0, &controls, &mut provider, &mut events);
        monitor.poll(
            t0 + Duration::from_secs(1),
            &controls,
            &mut provider,
            &mut events,
        );
        monitor.poll(
            t0 + Duration::from_secs(4),
            &controls,
            &mut provider,
            &mut events,
        );
        assert_eq!(calls.get(), 1, "sub-cadence passes must not sweep");
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut provider,
            &mut events,
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn process_filter_rescues_focused_apps_and_demotes_the_rest() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = CaptureControls::all_enabled();
        assert!(controls.process_filter_enabled(), "filter defaults on");
        controls.note_foreground_exe("/Applications/A.app/Contents/MacOS/A");
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![process_entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // One focused app and one background daemon start together.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || {
                Some(vec![
                    process_entry(1, "launchd", Some("/sbin/launchd"), 1),
                    process_entry(700, "A", Some("/Applications/A.app/Contents/MacOS/A"), 20),
                    process_entry(901, "noised", Some("/usr/libexec/noised"), 30),
                ])
            },
            &mut events,
        );
        assert_eq!(events.len(), 1, "only the focused app's row is kept");
        assert!(matches!(
            &events[0].payload,
            EventPayload::ProcessStarted { pid: 700, .. }
        ));

        // The demoted transition is not lost: the shutdown flush reports it.
        let mut summary = Vec::new();
        monitor.flush(t0 + Duration::from_secs(6), &mut summary);
        match &summary[0].payload {
            EventPayload::ProcessChurnSummary {
                dropped,
                distinct_exes,
                top,
                ..
            } => {
                assert_eq!(*dropped, 1);
                assert_eq!(*distinct_exes, 1);
                assert_eq!(top[0].exe, "noised");
                assert!(!top[0].sustained);
            }
            other => panic!("expected churn summary, got {other:?}"),
        }
    }

    #[test]
    fn process_sustained_churn_is_flagged_in_the_summary() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = CaptureControls::all_enabled();
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![process_entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // A crash-looping daemon: a fresh pid + start token every 5 s sweep,
        // well past the 30-hit sustained threshold (each restart is an
        // exit + start = 2 hits).
        for round in 0u64..20 {
            let now = t0 + Duration::from_secs(5 * (round + 1));
            let pid = 2000 + round as u32;
            monitor.poll(
                now,
                &controls,
                &mut || {
                    Some(vec![
                        process_entry(1, "launchd", Some("/sbin/launchd"), 1),
                        process_entry(pid, "loopd", Some("/usr/libexec/loopd"), 1000 + round),
                    ])
                },
                &mut events,
            );
        }
        assert!(events.is_empty(), "all loopd churn is demoted");
        let mut summary = Vec::new();
        monitor.flush(t0 + Duration::from_secs(200), &mut summary);
        match &summary[0].payload {
            EventPayload::ProcessChurnSummary { top, dropped, .. } => {
                assert!(*dropped >= 30);
                assert_eq!(top[0].exe, "loopd");
                assert!(top[0].sustained, "crash-loop volume flags sustained");
            }
            other => panic!("expected churn summary, got {other:?}"),
        }
    }

    #[test]
    fn process_failed_sweep_keeps_state_and_emits_nothing() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![process_entry(700, "A", Some("/a"), 1)]),
            &mut events,
        );
        // A failed sweep (None) and an empty sweep both keep prior state.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || None,
            &mut events,
        );
        monitor.poll(
            t0 + Duration::from_secs(10),
            &controls,
            &mut || Some(Vec::new()),
            &mut events,
        );
        assert!(events.is_empty(), "no exits fabricated from failed sweeps");
        // The process is still live afterwards: its real exit still emits.
        monitor.poll(
            t0 + Duration::from_secs(15),
            &controls,
            &mut || Some(vec![process_entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        let kinds: Vec<&str> = events.iter().map(|c| c.payload.kind()).collect();
        assert!(kinds.contains(&"process_exited"));
    }
}
