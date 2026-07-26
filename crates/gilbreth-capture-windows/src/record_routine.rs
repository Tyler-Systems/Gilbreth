use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    mem::size_of,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use gilbreth_core::{
    framework_class_from_id, ActionCapture, ActionDiag, ActionPayload, ActionType,
    AutomationAction, AutomationClient, AutomationClientError, CaptureError, EditCommitSignal,
    ExpandCollapseActionState, FrameworkClass, Modality, RejectedAction, RejectedActionReason,
    ScrollDirection, SelectorPath, SelectorPathHop, SelectorTrustBasis, StopToken,
    ToggleActionState, WriterInput,
};
use tracing::{debug, info, warn};
use windows::{
    core::{implement, Interface, Ref, BOOL, BSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, LPARAM, POINT, RECT, VARIANT_TRUE},
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED,
            },
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
            Variant::{VARIANT, VT_BOOL, VT_I4, VT_R4, VT_R8},
        },
        UI::{
            Accessibility::{
                AutomationElementMode_None, CUIAutomation, CUIAutomation8,
                CoalesceEventsOptions_Enabled, ConnectionRecoveryBehaviorOptions_Enabled,
                ExpandCollapseState, ExpandCollapseState_Collapsed, ExpandCollapseState_Expanded,
                ExpandCollapseState_PartiallyExpanded, IUIAutomation, IUIAutomation3,
                IUIAutomation6, IUIAutomationCacheRequest, IUIAutomationElement,
                IUIAutomationEventHandler, IUIAutomationEventHandlerGroup,
                IUIAutomationEventHandler_Impl, IUIAutomationFocusChangedEventHandler,
                IUIAutomationFocusChangedEventHandler_Impl,
                IUIAutomationPropertyChangedEventHandler,
                IUIAutomationPropertyChangedEventHandler_Impl,
                IUIAutomationTextEditTextChangedEventHandler,
                IUIAutomationTextEditTextChangedEventHandler_Impl,
                TextEditChangeType_CompositionFinalized, ToggleState, ToggleState_Indeterminate,
                ToggleState_Off, ToggleState_On, TreeScope_Children, TreeScope_Element,
                TreeScope_Subtree, UIA_AutomationIdPropertyId, UIA_BoundingRectanglePropertyId,
                UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
                UIA_ExpandCollapseExpandCollapseStatePropertyId, UIA_FrameworkIdPropertyId,
                UIA_HasKeyboardFocusPropertyId, UIA_Invoke_InvokedEventId,
                UIA_IsExpandCollapsePatternAvailablePropertyId,
                UIA_IsInvokePatternAvailablePropertyId, UIA_IsScrollPatternAvailablePropertyId,
                UIA_IsSelectionItemPatternAvailablePropertyId,
                UIA_IsTextEditPatternAvailablePropertyId, UIA_IsTogglePatternAvailablePropertyId,
                UIA_MenuOpenedEventId, UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId,
                UIA_ScrollHorizontalScrollPercentPropertyId,
                UIA_ScrollVerticalScrollPercentPropertyId,
                UIA_SelectionItem_ElementSelectedEventId, UIA_ToggleToggleStatePropertyId,
                UIA_EVENT_ID, UIA_PROPERTY_ID,
            },
            Input::KeyboardAndMouse::GetDoubleClickTime,
            WindowsAndMessaging::{
                EnumWindows, GetAncestor, GetForegroundWindow, GetWindow, GetWindowRect,
                GetWindowThreadProcessId, IsWindow, IsWindowVisible, WindowFromPoint, GA_ROOT,
                GA_ROOTOWNER, GW_OWNER,
            },
        },
    },
};

const BACKEND_UIA: &str = "uia";
const MAX_SELECTOR_DEPTH: usize = 8;
const DEFAULT_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_TARGET_WAIT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const TEARDOWN_DRAIN_CEILING: Duration = Duration::from_millis(500);
const RECT_CONTAINMENT_TOLERANCE_PX: i32 = 2;
const CHROME_FRAMEWORK_ID: &str = "chrome";
const CHROME_ROOT_WEB_AREA_ID: &str = "RootWebArea";
const UIA_DOCUMENT_CONTROL_TYPE: i32 = 50030;
const UIA_SCROLL_PATTERN_NO_SCROLL: f64 = -1.0;

const CACHE_PROPERTIES: &[UIA_PROPERTY_ID] = &[
    UIA_RuntimeIdPropertyId,
    UIA_ControlTypePropertyId,
    UIA_AutomationIdPropertyId,
    UIA_ClassNamePropertyId,
    UIA_FrameworkIdPropertyId,
    UIA_BoundingRectanglePropertyId,
    UIA_ProcessIdPropertyId,
    UIA_HasKeyboardFocusPropertyId,
    UIA_IsInvokePatternAvailablePropertyId,
    UIA_IsTogglePatternAvailablePropertyId,
    UIA_IsSelectionItemPatternAvailablePropertyId,
    UIA_IsExpandCollapsePatternAvailablePropertyId,
    UIA_IsScrollPatternAvailablePropertyId,
    UIA_IsTextEditPatternAvailablePropertyId,
    UIA_ToggleToggleStatePropertyId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId,
    UIA_ScrollHorizontalScrollPercentPropertyId,
    UIA_ScrollVerticalScrollPercentPropertyId,
];

const STATE_CHANGE_PROPERTIES: &[UIA_PROPERTY_ID] = &[
    UIA_ToggleToggleStatePropertyId,
    UIA_ExpandCollapseExpandCollapseStatePropertyId,
    UIA_ScrollHorizontalScrollPercentPropertyId,
    UIA_ScrollVerticalScrollPercentPropertyId,
    UIA_HasKeyboardFocusPropertyId,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoalescerTiming {
    pub scroll_quiet_ms: u64,
    pub dedup_window_ms: u64,
    pub idle_commit_ms: Option<u64>,
}

impl CoalescerTiming {
    pub fn from_os() -> Self {
        let double_click_ms = unsafe { GetDoubleClickTime() }.clamp(250, 800);
        Self {
            scroll_quiet_ms: u64::from(double_click_ms),
            dedup_window_ms: u64::from(double_click_ms),
            idle_commit_ms: None,
        }
    }
}

impl Default for CoalescerTiming {
    fn default() -> Self {
        Self {
            scroll_quiet_ms: 500,
            dedup_window_ms: 500,
            idle_commit_ms: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecordRoutineConfig {
    pub record_session_id: i64,
    pub queue_capacity: usize,
    pub coalescer_timing: CoalescerTiming,
    pub target_wait: Duration,
    pub emit_diagnostics: bool,
    pub target_pid: Option<u32>,
    pub extra_trusted_pids: Vec<u32>,
    pub follow_foreground: bool,
}

impl RecordRoutineConfig {
    pub fn new(record_session_id: i64) -> Self {
        Self {
            record_session_id,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            coalescer_timing: CoalescerTiming::from_os(),
            target_wait: DEFAULT_TARGET_WAIT,
            emit_diagnostics: false,
            target_pid: None,
            extra_trusted_pids: Vec::new(),
            follow_foreground: true,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LatencySummary {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub max_ns: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordRoutineRunStats {
    pub storm_dropped_events: u64,
    pub max_queue_depth: usize,
    pub callback_latency: LatencySummary,
    pub event_to_selector_complete: LatencySummary,
    pub trust_basis_counts: BTreeMap<String, u64>,
    pub action_type_counts: BTreeMap<String, u64>,
    pub failure_counts: BTreeMap<String, u64>,
    pub edit_commit_signal_counts: BTreeMap<String, u64>,
    pub windows_recorded: usize,
}

#[derive(Default)]
struct RecordRoutineStatsInner {
    max_queue_depth: usize,
    callback_latencies_ns: Vec<u64>,
    selector_latencies_ns: Vec<u64>,
    trust_basis_counts: BTreeMap<String, u64>,
    action_type_counts: BTreeMap<String, u64>,
    failure_counts: BTreeMap<String, u64>,
    edit_commit_signal_counts: BTreeMap<String, u64>,
    windows_recorded: HashSet<isize>,
}

#[derive(Clone, Default)]
struct RecordRoutineSharedStats {
    storm_dropped_events: Arc<AtomicU64>,
    inner: Arc<Mutex<RecordRoutineStatsInner>>,
}

impl RecordRoutineSharedStats {
    fn new() -> Self {
        Self::default()
    }

    fn record_window(&self, hwnd: HWND) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.windows_recorded.insert(hwnd.0 as isize);
        }
    }

    fn record_action_diag(&self, diag: &ActionDiag) {
        if let Ok(mut inner) = self.inner.lock() {
            record_common_diag(&mut inner, diag);
            if let Some(trust_basis) = diag.trust_basis {
                increment_count(&mut inner.trust_basis_counts, trust_basis.as_str());
            }
            if let Some(action_type) = diag.action_type {
                increment_count(&mut inner.action_type_counts, action_type.as_str());
            }
            if let Some(signal) = diag.edit_commit_signal {
                increment_count(&mut inner.edit_commit_signal_counts, signal.as_str());
            }
        }
    }

    fn record_rejected(&self, rejected: &RejectedAction) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.max_queue_depth = inner.max_queue_depth.max(rejected.queue_depth_at_enqueue);
            inner
                .callback_latencies_ns
                .push(rejected.callback_latency_ns);
            inner
                .selector_latencies_ns
                .push(rejected.event_to_selector_complete_ns);
            if let Some(trust_basis) = rejected.trust_basis {
                increment_count(&mut inner.trust_basis_counts, trust_basis.as_str());
            }
            increment_count(&mut inner.failure_counts, rejected.reason.as_str());
        }
    }

    fn snapshot(&self) -> RecordRoutineRunStats {
        let storm_dropped_events = self.storm_dropped_events.load(Ordering::SeqCst);
        let Ok(inner) = self.inner.lock() else {
            return RecordRoutineRunStats {
                storm_dropped_events,
                ..RecordRoutineRunStats::default()
            };
        };
        RecordRoutineRunStats {
            storm_dropped_events,
            max_queue_depth: inner.max_queue_depth,
            callback_latency: summarize_latencies(&inner.callback_latencies_ns),
            event_to_selector_complete: summarize_latencies(&inner.selector_latencies_ns),
            trust_basis_counts: inner.trust_basis_counts.clone(),
            action_type_counts: inner.action_type_counts.clone(),
            failure_counts: inner.failure_counts.clone(),
            edit_commit_signal_counts: inner.edit_commit_signal_counts.clone(),
            windows_recorded: inner.windows_recorded.len(),
        }
    }
}

fn record_common_diag(inner: &mut RecordRoutineStatsInner, diag: &ActionDiag) {
    inner.max_queue_depth = inner.max_queue_depth.max(diag.queue_depth_at_enqueue);
    inner.callback_latencies_ns.push(diag.callback_latency_ns);
    inner
        .selector_latencies_ns
        .push(diag.event_to_selector_complete_ns);
}

fn increment_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_string()).or_insert(0) += 1;
}

fn summarize_latencies(values: &[u64]) -> LatencySummary {
    if values.is_empty() {
        return LatencySummary::default();
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    LatencySummary {
        p50_ns: percentile_sorted(&sorted, 50),
        p95_ns: percentile_sorted(&sorted, 95),
        max_ns: *sorted.last().expect("nonempty latencies"),
    }
}

fn percentile_sorted(sorted: &[u64], percentile: u64) -> u64 {
    debug_assert!(!sorted.is_empty());
    let rank =
        ((sorted.len() as u64 * percentile).saturating_add(99) / 100).saturating_sub(1) as usize;
    sorted[rank.min(sorted.len() - 1)]
}

pub struct RecordRoutineHandle {
    stop: StopToken,
    join: Option<JoinHandle<()>>,
    stats: RecordRoutineSharedStats,
}

impl RecordRoutineHandle {
    /// True once the worker thread has exited, cleanly or by panic. The tray
    /// polls this so a dead worker cannot leave a recording open with the
    /// indicator still showing "recording" (S15).
    pub fn is_finished(&self) -> bool {
        self.join.as_ref().is_none_or(|join| join.is_finished())
    }

    pub fn stop(&mut self) -> RecordRoutineRunStats {
        self.stop.cancel();
        if let Some(join) = self.join.take() {
            if join.join().is_err() {
                warn!("record routine UIA worker panicked during stop");
            }
        }
        self.stats.snapshot()
    }
}

impl Drop for RecordRoutineHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn start_record_routine_capture(
    config: RecordRoutineConfig,
    writer_tx: Sender<WriterInput>,
) -> Result<RecordRoutineHandle, CaptureError> {
    let stop = StopToken::new();
    let worker_stop = stop.clone();
    let (ready_tx, ready_rx) = bounded(1);
    let ready_sent = Arc::new(AtomicBool::new(false));
    let worker_ready_sent = Arc::clone(&ready_sent);
    let stats = RecordRoutineSharedStats::new();
    let worker_stats = stats.clone();
    let join = thread::Builder::new()
        .name("gilbreth-record-routine-uia".to_string())
        .spawn(move || {
            if let Err(error) = run_record_routine_worker(
                config,
                writer_tx,
                worker_stop,
                ready_tx,
                worker_ready_sent,
                worker_stats,
            ) {
                warn!(%error, "record routine UIA worker stopped with an error");
            }
        })
        .map_err(|error| CaptureError::Source(Box::new(error)))?;
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            stop.cancel();
            let _ = join.join();
            return Err(CaptureError::WindowsApi(error));
        }
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
            stop.cancel();
            let _ = join.join();
            return Err(CaptureError::WindowsApi(
                "record routine UIA worker did not finish startup".to_string(),
            ));
        }
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
            stop.cancel();
            let _ = join.join();
            return Err(CaptureError::WindowsApi(
                "record routine UIA worker exited during startup".to_string(),
            ));
        }
    }
    Ok(RecordRoutineHandle {
        stop,
        join: Some(join),
        stats,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PatternAvailability {
    pub invoke: bool,
    pub toggle: bool,
    pub select: bool,
    pub expand_collapse: bool,
    pub scroll: bool,
    pub text_edit: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CachedActionState {
    pub toggle_state: Option<ToggleActionState>,
    pub expand_collapse_state: Option<ExpandCollapseActionState>,
    pub vertical_scroll_percent: Option<f64>,
    pub horizontal_scroll_percent: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScrollDelta {
    pub direction: ScrollDirection,
    pub amount_bucket: Option<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClassifiedAction {
    pub action_type: ActionType,
    pub payload: ActionPayload,
    pub pattern_action: Option<&'static str>,
}

pub fn classify_cached_action(
    availability: PatternAvailability,
    state: CachedActionState,
    scroll_delta: Option<ScrollDelta>,
) -> ClassifiedAction {
    if availability.expand_collapse {
        let to_state = state
            .expand_collapse_state
            .unwrap_or(ExpandCollapseActionState::Expanded);
        return ClassifiedAction {
            action_type: ActionType::ExpandCollapse,
            payload: ActionPayload::ExpandCollapse {
                to_state,
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("expand_collapse"),
        };
    }
    if availability.select {
        return ClassifiedAction {
            action_type: ActionType::Select,
            payload: ActionPayload::Select {
                selection_size: None,
                in_set_of: None,
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("select"),
        };
    }
    if availability.toggle {
        let to_state = state.toggle_state.unwrap_or(ToggleActionState::On);
        return ClassifiedAction {
            action_type: ActionType::Toggle,
            payload: ActionPayload::Toggle {
                to_state,
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("toggle"),
        };
    }
    if availability.scroll {
        if let Some(delta) = scroll_delta {
            return ClassifiedAction {
                action_type: ActionType::Scroll,
                payload: ActionPayload::Scroll {
                    direction: delta.direction,
                    amount_bucket: delta.amount_bucket,
                    from_modality: None,
                    corroborates: None,
                },
                pattern_action: Some("scroll"),
            };
        }
    }
    if availability.invoke {
        return ClassifiedAction {
            action_type: ActionType::Invoke,
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("invoke"),
        };
    }
    ClassifiedAction {
        action_type: ActionType::UiActionOther,
        payload: ActionPayload::UiActionOther {
            raw_pattern_id: None,
            from_modality: None,
            corroborates: None,
        },
        pattern_action: Some("ui_action_other"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustProbe {
    pub element_pid_in_target_tree: bool,
    pub owner_window_pid_in_target_tree: bool,
    pub rect_contained_by_owner_window: bool,
    pub scoped_invoke_sender: bool,
}

pub fn classify_trust(probe: TrustProbe) -> Option<SelectorTrustBasis> {
    if probe.element_pid_in_target_tree {
        return Some(SelectorTrustBasis::PidMatch);
    }
    if probe.owner_window_pid_in_target_tree && probe.rect_contained_by_owner_window {
        return Some(SelectorTrustBasis::WindowOwnership);
    }
    if probe.scoped_invoke_sender {
        return Some(SelectorTrustBasis::ScopedInvokeSender);
    }
    None
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoalescedAction {
    pub target: CapturedElement,
    pub action_type: ActionType,
    pub payload: ActionPayload,
    pub pattern_action: Option<String>,
    pub captured_at: Instant,
    pub diag: ActionDiag,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActionDraft {
    pub target: CapturedElement,
    pub action_type: ActionType,
    pub payload: ActionPayload,
    pub pattern_action: Option<String>,
    pub captured_at: Instant,
    pub diag: ActionDiag,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoalescerInput {
    Action(ActionDraft),
    EditMarker {
        target: CapturedElement,
        captured_at: Instant,
        from_modality: Option<Modality>,
        diag: ActionDiag,
    },
    CommitEdit {
        captured_at: Instant,
        signal: EditCommitSignal,
    },
    FocusChanged {
        captured_at: Instant,
        signal: EditCommitSignal,
    },
    Stop {
        captured_at: Instant,
        signal: EditCommitSignal,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct PendingEdit {
    target: CapturedElement,
    captured_at: Instant,
    from_modality: Option<Modality>,
    diag: ActionDiag,
}

#[derive(Clone, Debug, PartialEq)]
struct PendingScroll {
    draft: ActionDraft,
    last_seen: Instant,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActionCoalescer {
    timing: CoalescerTiming,
    last_by_target_action: HashMap<(String, ActionType), (ActionPayload, Instant)>,
    pending_scroll: Option<PendingScroll>,
    pending_edit: Option<PendingEdit>,
}

impl ActionCoalescer {
    pub fn new(timing: CoalescerTiming) -> Self {
        Self {
            timing,
            last_by_target_action: HashMap::new(),
            pending_scroll: None,
            pending_edit: None,
        }
    }

    pub fn handle(&mut self, input: CoalescerInput) -> Vec<CoalescedAction> {
        match input {
            CoalescerInput::Action(draft) if draft.action_type == ActionType::Scroll => {
                self.handle_scroll(draft)
            }
            CoalescerInput::Action(draft) => self.handle_non_scroll(draft),
            CoalescerInput::EditMarker {
                target,
                captured_at,
                from_modality,
                diag,
            } => {
                let mut output = self.flush_pending_scroll();
                if let Some(pending) = self.pending_edit.as_mut() {
                    if pending.target.target_key == target.target_key {
                        pending.captured_at = captured_at;
                        pending.from_modality = pending.from_modality.or(from_modality);
                        merge_action_diag(&mut pending.diag, &diag);
                        return output;
                    }
                }
                output.extend(self.flush_edit(captured_at, EditCommitSignal::FocusLoss));
                self.pending_edit = Some(PendingEdit {
                    target,
                    captured_at,
                    from_modality,
                    diag,
                });
                output
            }
            CoalescerInput::CommitEdit {
                captured_at,
                signal,
            }
            | CoalescerInput::FocusChanged {
                captured_at,
                signal,
            } => {
                let mut output = self.flush_pending_scroll();
                output.extend(self.flush_edit(captured_at, signal));
                output
            }
            CoalescerInput::Stop {
                captured_at,
                signal,
            } => self.flush_all_with_signal(captured_at, signal),
        }
    }

    pub fn flush_due(&mut self, now: Instant) -> Vec<CoalescedAction> {
        let quiet = Duration::from_millis(self.timing.scroll_quiet_ms);
        if self
            .pending_scroll
            .as_ref()
            .is_some_and(|pending| now.duration_since(pending.last_seen) >= quiet)
        {
            self.pending_scroll
                .take()
                .map(|pending| self.emit_draft(pending.draft))
                .into_iter()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn flush_all(&mut self, now: Instant) -> Vec<CoalescedAction> {
        self.flush_all_with_signal(now, EditCommitSignal::Stop)
    }

    fn flush_all_with_signal(
        &mut self,
        now: Instant,
        signal: EditCommitSignal,
    ) -> Vec<CoalescedAction> {
        let mut output = Vec::new();
        if let Some(pending) = self.pending_scroll.take() {
            output.push(self.emit_draft(pending.draft));
        }
        output.extend(self.flush_edit(now, signal));
        output
    }

    fn handle_non_scroll(&mut self, draft: ActionDraft) -> Vec<CoalescedAction> {
        let mut output = self.flush_pending_scroll();
        output.extend(self.flush_edit(draft.captured_at, EditCommitSignal::FocusLoss));
        if self.is_duplicate(&draft) {
            return output;
        }
        output.push(self.emit_draft(draft));
        output
    }

    fn handle_scroll(&mut self, draft: ActionDraft) -> Vec<CoalescedAction> {
        let mut output = self.flush_edit(draft.captured_at, EditCommitSignal::FocusLoss);
        if let Some(mut pending) = self.pending_scroll.take() {
            if pending.draft.target.target_key == draft.target.target_key
                && same_scroll_direction(&pending.draft.payload, &draft.payload)
            {
                pending.draft.captured_at = draft.captured_at;
                pending.draft.payload =
                    merge_scroll_payload(&pending.draft.payload, &draft.payload);
                merge_action_diag(&mut pending.draft.diag, &draft.diag);
                pending.last_seen = draft.captured_at;
                self.pending_scroll = Some(pending);
                return output;
            }
            output.push(self.emit_draft(pending.draft));
        }
        self.pending_scroll = Some(PendingScroll {
            last_seen: draft.captured_at,
            draft,
        });
        output
    }

    fn flush_pending_scroll(&mut self) -> Vec<CoalescedAction> {
        self.pending_scroll
            .take()
            .map(|pending| self.emit_draft(pending.draft))
            .into_iter()
            .collect()
    }

    fn flush_edit(
        &mut self,
        captured_at: Instant,
        signal: EditCommitSignal,
    ) -> Vec<CoalescedAction> {
        let Some(pending) = self.pending_edit.take() else {
            return Vec::new();
        };
        let mut diag = pending.diag;
        diag.action_type = Some(ActionType::EditCommitted);
        diag.edit_commit_signal = Some(signal);
        vec![CoalescedAction {
            target: pending.target,
            action_type: ActionType::EditCommitted,
            payload: ActionPayload::EditCommitted {
                from_modality: pending.from_modality,
                corroborates: None,
            },
            pattern_action: Some("edit_committed".to_string()),
            captured_at,
            diag,
        }]
    }

    fn is_duplicate(&self, draft: &ActionDraft) -> bool {
        let Some((payload, seen_at)) = self
            .last_by_target_action
            .get(&(draft.target.target_key.clone(), draft.action_type))
        else {
            return false;
        };
        payload == &draft.payload
            && draft.captured_at.duration_since(*seen_at)
                <= Duration::from_millis(self.timing.dedup_window_ms)
    }

    fn emit_draft(&mut self, draft: ActionDraft) -> CoalescedAction {
        self.last_by_target_action.insert(
            (draft.target.target_key.clone(), draft.action_type),
            (draft.payload.clone(), draft.captured_at),
        );
        CoalescedAction {
            target: draft.target,
            action_type: draft.action_type,
            payload: draft.payload,
            pattern_action: draft.pattern_action,
            captured_at: draft.captured_at,
            diag: draft.diag,
        }
    }
}

fn merge_action_diag(left: &mut ActionDiag, right: &ActionDiag) {
    left.repeat_count = left.repeat_count.saturating_add(right.repeat_count);
    left.callback_latency_ns = left.callback_latency_ns.max(right.callback_latency_ns);
    left.event_to_selector_complete_ns = left
        .event_to_selector_complete_ns
        .max(right.event_to_selector_complete_ns);
    left.queue_depth_at_enqueue = left
        .queue_depth_at_enqueue
        .max(right.queue_depth_at_enqueue);
}

fn same_scroll_direction(left: &ActionPayload, right: &ActionPayload) -> bool {
    matches!(
        (left, right),
        (
            ActionPayload::Scroll {
                direction: left, ..
            },
            ActionPayload::Scroll {
                direction: right, ..
            }
        ) if left == right
    )
}

fn merge_scroll_payload(left: &ActionPayload, right: &ActionPayload) -> ActionPayload {
    match (left, right) {
        (
            ActionPayload::Scroll {
                direction,
                amount_bucket: left_bucket,
                ..
            },
            ActionPayload::Scroll {
                amount_bucket: right_bucket,
                ..
            },
        ) => ActionPayload::Scroll {
            direction: *direction,
            amount_bucket: merge_amount_bucket(*left_bucket, *right_bucket),
            from_modality: None,
            corroborates: None,
        },
        _ => right.clone(),
    }
}

fn merge_amount_bucket(left: Option<u8>, right: Option<u8>) -> Option<u8> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.saturating_add(right).min(10)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CapturedElement {
    pub target_key: String,
    pub selector_path: SelectorPath,
    pub trust_basis: SelectorTrustBasis,
    pub exe: Option<String>,
    pub has_name: bool,
    pub framework: String,
    pub framework_class: FrameworkClass,
    pub framework_id: String,
    pub depth: u32,
    pub leaf_rect: Option<String>,
}

impl CoalescedAction {
    fn into_capture(self, record_session_id: i64) -> ActionCapture {
        ActionCapture {
            action: AutomationAction {
                action_type: self.action_type,
                selector_path: self.target.selector_path,
                trust_basis: self.target.trust_basis,
            },
            captured_at: self.captured_at,
            record_session_id,
            exe: self.target.exe,
            is_sensitive: false,
            has_name: self.target.has_name,
            pattern_action: self.pattern_action,
            framework: self.target.framework,
            framework_class: self.target.framework_class,
            depth: self.target.depth,
            leaf_rect: self.target.leaf_rect,
            payload: self.payload,
        }
    }
}

#[derive(Clone)]
pub struct RecordRoutineClient {
    rx: Receiver<AutomationAction>,
}

impl AutomationClient for RecordRoutineClient {
    fn next_action(&self) -> Result<Option<AutomationAction>, AutomationClientError> {
        match self.rx.try_recv() {
            Ok(action) => Ok(Some(action)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(AutomationClientError::Unavailable(
                "record routine worker disconnected".to_string(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawUiaEventKind {
    FocusChanged,
    Invoke,
    Selection,
    PropertyChanged(UIA_PROPERTY_ID),
    TextEditCompositionFinalized,
    MenuOpened,
}

impl RawUiaEventKind {
    fn diag_name(self) -> String {
        match self {
            Self::FocusChanged => "focus_changed".to_string(),
            Self::Invoke => "invoke".to_string(),
            Self::Selection => "selection".to_string(),
            Self::PropertyChanged(property) => format!("property_changed:{}", property.0),
            Self::TextEditCompositionFinalized => "text_edit_composition_finalized".to_string(),
            Self::MenuOpened => "menu_opened".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct RawUiaEvent {
    kind: RawUiaEventKind,
    captured_at: Instant,
    enqueued_at: Instant,
    queue_depth_at_enqueue: usize,
    element: Option<IUIAutomationElement>,
    scoped_sender: bool,
}

#[derive(Clone)]
#[implement(
    IUIAutomationFocusChangedEventHandler,
    IUIAutomationEventHandler,
    IUIAutomationPropertyChangedEventHandler,
    IUIAutomationTextEditTextChangedEventHandler
)]
struct RecordRoutineEventHandler {
    tx: Sender<RawUiaEvent>,
    storm_dropped_events: Arc<AtomicU64>,
}

impl RecordRoutineEventHandler {
    fn enqueue(
        &self,
        kind: RawUiaEventKind,
        element: Option<IUIAutomationElement>,
        scoped_sender: bool,
    ) {
        let now = Instant::now();
        let event = RawUiaEvent {
            kind,
            captured_at: now,
            enqueued_at: now,
            queue_depth_at_enqueue: self.tx.len().saturating_add(1),
            element,
            scoped_sender,
        };
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.storm_dropped_events.fetch_add(1, Ordering::SeqCst);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

#[allow(non_snake_case)]
impl IUIAutomationFocusChangedEventHandler_Impl for RecordRoutineEventHandler_Impl {
    fn HandleFocusChangedEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
    ) -> windows::core::Result<()> {
        self.enqueue(RawUiaEventKind::FocusChanged, sender.cloned(), false);
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IUIAutomationEventHandler_Impl for RecordRoutineEventHandler_Impl {
    fn HandleAutomationEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
        eventid: UIA_EVENT_ID,
    ) -> windows::core::Result<()> {
        let kind = if eventid == UIA_Invoke_InvokedEventId {
            Some(RawUiaEventKind::Invoke)
        } else if eventid == UIA_SelectionItem_ElementSelectedEventId {
            Some(RawUiaEventKind::Selection)
        } else if eventid == UIA_MenuOpenedEventId {
            Some(RawUiaEventKind::MenuOpened)
        } else {
            None
        };
        if let Some(kind) = kind {
            self.enqueue(kind, sender.cloned(), true);
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IUIAutomationPropertyChangedEventHandler_Impl for RecordRoutineEventHandler_Impl {
    fn HandlePropertyChangedEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
        propertyid: UIA_PROPERTY_ID,
        _newvalue: &VARIANT,
    ) -> windows::core::Result<()> {
        self.enqueue(
            RawUiaEventKind::PropertyChanged(propertyid),
            sender.cloned(),
            true,
        );
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IUIAutomationTextEditTextChangedEventHandler_Impl for RecordRoutineEventHandler_Impl {
    fn HandleTextEditTextChangedEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
        texteditchangetype: windows::Win32::UI::Accessibility::TextEditChangeType,
        _eventstrings: *const windows::Win32::System::Com::SAFEARRAY,
    ) -> windows::core::Result<()> {
        if texteditchangetype == TextEditChangeType_CompositionFinalized {
            self.enqueue(
                RawUiaEventKind::TextEditCompositionFinalized,
                sender.cloned(),
                true,
            );
        }
        Ok(())
    }
}

fn run_record_routine_worker(
    config: RecordRoutineConfig,
    writer_tx: Sender<WriterInput>,
    stop: StopToken,
    ready_tx: Sender<Result<(), String>>,
    ready_sent: Arc<AtomicBool>,
    stats: RecordRoutineSharedStats,
) -> Result<(), CaptureError> {
    let (raw_tx, raw_rx) = bounded(config.queue_capacity.max(1));
    let handler = RecordRoutineEventHandler {
        tx: raw_tx,
        storm_dropped_events: Arc::clone(&stats.storm_dropped_events),
    };
    let handler = HandlerInterfaces::new(handler).map_err(windows_error)?;
    let mut coalescer = ActionCoalescer::new(config.coalescer_timing);
    let mut runtime = match UiaRuntime::new(handler) {
        Ok(runtime) => runtime,
        Err(error) => {
            send_ready_error(&ready_tx, &ready_sent, &error);
            return Err(error);
        }
    };
    let mut target = match wait_for_target_window(
        config.target_wait,
        config.target_pid,
        &config.extra_trusted_pids,
    ) {
        Some(target) => target,
        None => {
            let message = match config.target_pid {
                Some(pid) => format!("no visible target window found for pid {pid}"),
                None => "no non-Gilbreth foreground window available".to_string(),
            };
            let error = CaptureError::WindowsApi(message);
            send_ready_error(&ready_tx, &ready_sent, &error);
            return Err(error);
        }
    };
    if let Err(error) = runtime.subscribe_to_window(target.hwnd) {
        send_ready_error(&ready_tx, &ready_sent, &error);
        return Err(error);
    }
    if config.emit_diagnostics {
        stats.record_window(target.hwnd);
    }
    send_ready_ok(&ready_tx, &ready_sent);
    // debug for the exe: a client-named recording target in a retained log
    // would survive retention and secure erase (S7); the session row carries
    // the durable, erase-governed copy.
    let target_exe_basename = target.exe.as_deref().and_then(exe_basename);
    info!(
        record_session_id = config.record_session_id,
        target_pid = target.pid,
        "record routine UIA worker started"
    );
    debug!(
        record_session_id = config.record_session_id,
        target_exe = ?target_exe_basename,
        "record routine target exe"
    );

    while !stop.is_cancelled() {
        match raw_rx.recv_timeout(POLL_INTERVAL) {
            Ok(raw) => {
                let dequeued_at = Instant::now();
                let worker_ordinal = runtime.next_worker_ordinal();
                if config.follow_foreground && matches!(raw.kind, RawUiaEventKind::FocusChanged) {
                    let Some(new_target) = foreground_non_self_target(&config.extra_trusted_pids)
                    else {
                        if !send_rejected_action(
                            &writer_tx,
                            &stats,
                            config.emit_diagnostics,
                            rejected_from_raw(
                                &config,
                                worker_ordinal,
                                &raw,
                                dequeued_at,
                                RejectedActionReason::WindowMismatch,
                                None,
                            ),
                        ) {
                            stop.cancel();
                        }
                        continue;
                    };
                    if new_target.hwnd != target.hwnd {
                        match runtime.replace_window_subscription(new_target.hwnd) {
                            Ok(()) => {
                                target = new_target;
                                if config.emit_diagnostics {
                                    stats.record_window(target.hwnd);
                                }
                                let target_exe_basename =
                                    target.exe.as_deref().and_then(exe_basename);
                                info!(
                                    record_session_id = config.record_session_id,
                                    target_pid = target.pid,
                                    "record routine target window changed"
                                );
                                debug!(
                                    record_session_id = config.record_session_id,
                                    target_exe = ?target_exe_basename,
                                    "record routine target exe"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    %error,
                                    "record routine target resubscribe failed; keeping current target"
                                );
                                continue;
                            }
                        }
                    }
                }

                match process_raw_event(
                    &mut runtime,
                    &target,
                    raw,
                    &config,
                    worker_ordinal,
                    dequeued_at,
                ) {
                    ProcessedRawEvent::Input(input) => {
                        for action in coalescer.handle(*input) {
                            if !send_coalesced_action(
                                &writer_tx,
                                &stats,
                                action,
                                config.record_session_id,
                                config.emit_diagnostics,
                            ) {
                                stop.cancel();
                                break;
                            }
                        }
                    }
                    ProcessedRawEvent::Rejected(rejected) => {
                        if !send_rejected_action(
                            &writer_tx,
                            &stats,
                            config.emit_diagnostics,
                            rejected,
                        ) {
                            stop.cancel();
                        }
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                for action in coalescer.flush_due(Instant::now()) {
                    if !send_coalesced_action(
                        &writer_tx,
                        &stats,
                        action,
                        config.record_session_id,
                        config.emit_diagnostics,
                    ) {
                        stop.cancel();
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    for action in coalescer.flush_all(Instant::now()) {
        if !send_coalesced_action(
            &writer_tx,
            &stats,
            action,
            config.record_session_id,
            config.emit_diagnostics,
        ) {
            break;
        }
    }
    runtime.unsubscribe();
    drain_for_teardown(&raw_rx, config.coalescer_timing);
    let dropped = stats.storm_dropped_events.load(Ordering::SeqCst);
    if dropped > 0 {
        warn!(
            storm_dropped_events = dropped,
            "record routine UIA worker dropped events during a storm"
        );
    }
    info!(
        record_session_id = config.record_session_id,
        storm_dropped_events = dropped,
        "record routine UIA worker stopped"
    );
    Ok(())
}

fn send_ready_ok(tx: &Sender<Result<(), String>>, sent: &AtomicBool) {
    if !sent.swap(true, Ordering::SeqCst) {
        let _ = tx.send(Ok(()));
    }
}

fn send_ready_error(tx: &Sender<Result<(), String>>, sent: &AtomicBool, error: &CaptureError) {
    if !sent.swap(true, Ordering::SeqCst) {
        let _ = tx.send(Err(error.to_string()));
    }
}

fn exe_basename(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

fn drain_for_teardown(rx: &Receiver<RawUiaEvent>, timing: CoalescerTiming) {
    let quiet = Duration::from_millis(timing.scroll_quiet_ms).min(TEARDOWN_DRAIN_CEILING);
    let deadline = Instant::now() + TEARDOWN_DRAIN_CEILING;
    let mut empty_since = None;
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(_) => {
                empty_since = None;
            }
            Err(TryRecvError::Empty) => {
                let now = Instant::now();
                let since = empty_since.get_or_insert(now);
                if now.duration_since(*since) >= quiet {
                    break;
                }
                thread::sleep(POLL_INTERVAL.min(quiet));
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
}

#[derive(Debug)]
enum ProcessedRawEvent {
    Input(Box<CoalescerInput>),
    Rejected(RejectedAction),
}

fn send_coalesced_action(
    writer_tx: &Sender<WriterInput>,
    stats: &RecordRoutineSharedStats,
    action: CoalescedAction,
    record_session_id: i64,
    emit_diagnostics: bool,
) -> bool {
    if emit_diagnostics {
        let diag = action.diag.clone();
        stats.record_action_diag(&diag);
        match writer_tx.try_send(WriterInput::ActionDiag(diag)) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
    writer_tx
        .send(WriterInput::Action(action.into_capture(record_session_id)))
        .is_ok()
}

fn send_rejected_action(
    writer_tx: &Sender<WriterInput>,
    stats: &RecordRoutineSharedStats,
    emit_diagnostics: bool,
    rejected: RejectedAction,
) -> bool {
    if !emit_diagnostics {
        return true;
    }
    stats.record_rejected(&rejected);
    match writer_tx.try_send(WriterInput::RejectedAction(rejected)) {
        Ok(()) | Err(TrySendError::Full(_)) => true,
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn base_action_diag(
    config: &RecordRoutineConfig,
    worker_ordinal: u64,
    raw: &RawUiaEvent,
    dequeued_at: Instant,
) -> ActionDiag {
    ActionDiag {
        record_session_id: config.record_session_id,
        worker_ordinal,
        event_kind: raw.kind.diag_name(),
        callback_latency_ns: duration_ns(dequeued_at.duration_since(raw.enqueued_at)),
        event_to_selector_complete_ns: 0,
        queue_depth_at_enqueue: raw.queue_depth_at_enqueue,
        repeat_count: 1,
        edit_commit_signal: None,
        trust_basis: None,
        action_type: None,
    }
}

fn finalize_action_diag(
    mut diag: ActionDiag,
    raw: &RawUiaEvent,
    snapshot: Option<&ElementSnapshot>,
) -> ActionDiag {
    diag.event_to_selector_complete_ns = duration_ns(raw.captured_at.elapsed());
    if let Some(snapshot) = snapshot {
        diag.trust_basis = Some(snapshot.element.trust_basis);
    }
    diag
}

fn rejected_from_raw(
    config: &RecordRoutineConfig,
    worker_ordinal: u64,
    raw: &RawUiaEvent,
    dequeued_at: Instant,
    reason: RejectedActionReason,
    trust_basis: Option<SelectorTrustBasis>,
) -> RejectedAction {
    let diag = base_action_diag(config, worker_ordinal, raw, dequeued_at);
    RejectedAction {
        record_session_id: config.record_session_id,
        worker_ordinal,
        event_kind: diag.event_kind,
        captured_at: raw.captured_at,
        reason,
        trust_basis,
        callback_latency_ns: diag.callback_latency_ns,
        event_to_selector_complete_ns: duration_ns(raw.captured_at.elapsed()),
        queue_depth_at_enqueue: raw.queue_depth_at_enqueue,
    }
}

fn rejected_reason_for_error(error: &CaptureError) -> RejectedActionReason {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("access denied")
        || message.contains("uipi")
        || message.contains("elevated")
        || message.contains("0x80070005")
    {
        RejectedActionReason::ElevatedOrUipiDenied
    } else if message.contains("trust classification") {
        RejectedActionReason::TrustRejected
    } else {
        RejectedActionReason::SelectorCaptureFailed
    }
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn process_raw_event(
    runtime: &mut UiaRuntime,
    target: &TargetWindow,
    raw: RawUiaEvent,
    config: &RecordRoutineConfig,
    worker_ordinal: u64,
    dequeued_at: Instant,
) -> ProcessedRawEvent {
    let diag = base_action_diag(config, worker_ordinal, &raw, dequeued_at);
    let Some(element) = raw.element.as_ref() else {
        return ProcessedRawEvent::Rejected(rejected_from_raw(
            config,
            worker_ordinal,
            &raw,
            dequeued_at,
            RejectedActionReason::NullElement,
            None,
        ));
    };
    let snapshot = match runtime.capture_element(element, target, raw.scoped_sender) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if matches!(raw.kind, RawUiaEventKind::FocusChanged) {
                if let Ok(focused) = runtime.focused_element() {
                    match runtime.capture_element(&focused, target, false) {
                        Ok(snapshot) => snapshot,
                        Err(fallback_error) => {
                            debug!(
                                %error,
                                %fallback_error,
                                "record routine UIA focus event skipped after focused-element fallback"
                            );
                            return ProcessedRawEvent::Rejected(rejected_from_raw(
                                config,
                                worker_ordinal,
                                &raw,
                                dequeued_at,
                                rejected_reason_for_error(&fallback_error),
                                None,
                            ));
                        }
                    }
                } else {
                    debug!(%error, "record routine UIA focus event skipped; focused-element fallback failed");
                    return ProcessedRawEvent::Rejected(rejected_from_raw(
                        config,
                        worker_ordinal,
                        &raw,
                        dequeued_at,
                        rejected_reason_for_error(&error),
                        None,
                    ));
                }
            } else {
                debug!(%error, "record routine UIA event skipped");
                return ProcessedRawEvent::Rejected(rejected_from_raw(
                    config,
                    worker_ordinal,
                    &raw,
                    dequeued_at,
                    rejected_reason_for_error(&error),
                    None,
                ));
            }
        }
    };
    if snapshot.is_non_actionable_chromium_root() {
        return ProcessedRawEvent::Rejected(rejected_from_raw(
            config,
            worker_ordinal,
            &raw,
            dequeued_at,
            RejectedActionReason::NonActionableElement,
            Some(snapshot.element.trust_basis),
        ));
    }
    if raw.kind == RawUiaEventKind::FocusChanged {
        if snapshot.availability.text_edit {
            let diag = finalize_action_diag(diag, &raw, Some(&snapshot));
            return ProcessedRawEvent::Input(Box::new(CoalescerInput::EditMarker {
                target: snapshot.element,
                captured_at: raw.captured_at,
                from_modality: None,
                diag,
            }));
        }
        return ProcessedRawEvent::Input(Box::new(CoalescerInput::FocusChanged {
            captured_at: raw.captured_at,
            signal: EditCommitSignal::FocusLoss,
        }));
    }
    if raw.kind == RawUiaEventKind::TextEditCompositionFinalized {
        return ProcessedRawEvent::Input(Box::new(CoalescerInput::CommitEdit {
            captured_at: raw.captured_at,
            signal: EditCommitSignal::CompositionFinalized,
        }));
    }

    let scroll_delta = match raw.kind {
        RawUiaEventKind::PropertyChanged(property)
            if property == UIA_ScrollVerticalScrollPercentPropertyId
                || property == UIA_ScrollHorizontalScrollPercentPropertyId =>
        {
            runtime.scroll_delta(&snapshot, property)
        }
        _ => None,
    };
    let classified = classify_cached_action(snapshot.availability, snapshot.state, scroll_delta);
    if classified.action_type == ActionType::UiActionOther
        && matches!(raw.kind, RawUiaEventKind::MenuOpened)
    {
        return ProcessedRawEvent::Rejected(rejected_from_raw(
            config,
            worker_ordinal,
            &raw,
            dequeued_at,
            RejectedActionReason::BenignNoAction,
            Some(snapshot.element.trust_basis),
        ));
    }
    let mut diag = finalize_action_diag(diag, &raw, Some(&snapshot));
    diag.action_type = Some(classified.action_type);
    ProcessedRawEvent::Input(Box::new(CoalescerInput::Action(ActionDraft {
        target: snapshot.element,
        action_type: classified.action_type,
        payload: classified.payload,
        pattern_action: classified.pattern_action.map(str::to_string),
        captured_at: raw.captured_at,
        diag,
    })))
}

struct HandlerInterfaces {
    focus: IUIAutomationFocusChangedEventHandler,
    event: IUIAutomationEventHandler,
    property: IUIAutomationPropertyChangedEventHandler,
    text_edit: IUIAutomationTextEditTextChangedEventHandler,
}

impl HandlerInterfaces {
    fn new(handler: RecordRoutineEventHandler) -> windows::core::Result<Self> {
        let unknown: windows::core::IUnknown = handler.into();
        Ok(Self {
            focus: unknown.cast()?,
            event: unknown.cast()?,
            property: unknown.cast()?,
            text_edit: unknown.cast()?,
        })
    }
}

struct UiaRuntime {
    _com: ComApartment,
    automation: IUIAutomation,
    automation6: Option<IUIAutomation6>,
    automation3: Option<IUIAutomation3>,
    cache_request: IUIAutomationCacheRequest,
    walker: windows::Win32::UI::Accessibility::IUIAutomationTreeWalker,
    handler: HandlerInterfaces,
    subscription: Option<Subscription>,
    last_scroll_state: HashMap<String, CachedActionState>,
    worker_ordinal: u64,
}

impl UiaRuntime {
    fn new(handler: HandlerInterfaces) -> Result<Self, CaptureError> {
        let com = ComApartment::initialize()?;
        let automation = create_automation()?;
        let automation6 = automation.cast::<IUIAutomation6>().ok();
        let automation3 = automation.cast::<IUIAutomation3>().ok();
        if let Some(automation6) = automation6.as_ref() {
            unsafe {
                automation6
                    .SetConnectionRecoveryBehavior(ConnectionRecoveryBehaviorOptions_Enabled)
                    .map_err(windows_context(
                        "IUIAutomation6::SetConnectionRecoveryBehavior",
                    ))?;
                automation6
                    .SetCoalesceEvents(CoalesceEventsOptions_Enabled)
                    .map_err(windows_context("IUIAutomation6::SetCoalesceEvents"))?;
            }
        }
        let cache_request = unsafe {
            automation
                .CreateCacheRequest()
                .map_err(windows_context("IUIAutomation::CreateCacheRequest"))?
        };
        unsafe {
            cache_request
                .SetAutomationElementMode(AutomationElementMode_None)
                .map_err(windows_context(
                    "IUIAutomationCacheRequest::SetAutomationElementMode",
                ))?;
            cache_request
                .SetTreeScope(windows::Win32::UI::Accessibility::TreeScope(
                    TreeScope_Element.0 | TreeScope_Children.0,
                ))
                .map_err(windows_context("IUIAutomationCacheRequest::SetTreeScope"))?;
            for property in CACHE_PROPERTIES {
                cache_request
                    .AddProperty(*property)
                    .map_err(windows_context("IUIAutomationCacheRequest::AddProperty"))?;
            }
        }
        let walker = unsafe {
            automation
                .ControlViewWalker()
                .map_err(windows_context("IUIAutomation::ControlViewWalker"))?
        };
        unsafe {
            automation
                .AddFocusChangedEventHandler(&cache_request, &handler.focus)
                .map_err(windows_context(
                    "IUIAutomation::AddFocusChangedEventHandler",
                ))?;
        }
        Ok(Self {
            _com: com,
            automation,
            automation6,
            automation3,
            cache_request,
            walker,
            handler,
            subscription: None,
            last_scroll_state: HashMap::new(),
            worker_ordinal: 0,
        })
    }

    fn next_worker_ordinal(&mut self) -> u64 {
        self.worker_ordinal = self.worker_ordinal.saturating_add(1);
        self.worker_ordinal
    }

    fn subscribe_to_window(&mut self, hwnd: HWND) -> Result<(), CaptureError> {
        self.unsubscribe_window();
        let element = unsafe {
            self.automation
                .ElementFromHandle(hwnd)
                .map_err(windows_context("IUIAutomation::ElementFromHandle"))?
        };
        let subscription = if let Some(automation6) = self.automation6.as_ref() {
            match self.subscribe_with_group(&element, automation6) {
                Ok(subscription) => subscription,
                Err(error) => {
                    warn!(
                        %error,
                        "record routine UIA event-handler group failed; falling back to individual handlers"
                    );
                    self.subscribe_individual(element)?
                }
            }
        } else {
            self.subscribe_individual(element)?
        };
        self.subscription = Some(subscription);
        Ok(())
    }

    fn subscribe_with_group(
        &self,
        element: &IUIAutomationElement,
        automation6: &IUIAutomation6,
    ) -> Result<Subscription, CaptureError> {
        let group = unsafe {
            automation6
                .CreateEventHandlerGroup()
                .map_err(windows_context("IUIAutomation6::CreateEventHandlerGroup"))?
        };
        unsafe {
            group
                .AddAutomationEventHandler(
                    UIA_Invoke_InvokedEventId,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context(
                    "IUIAutomationEventHandlerGroup::AddInvokeHandler",
                ))?;
            group
                .AddAutomationEventHandler(
                    UIA_SelectionItem_ElementSelectedEventId,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context(
                    "IUIAutomationEventHandlerGroup::AddSelectionHandler",
                ))?;
            group
                .AddAutomationEventHandler(
                    UIA_MenuOpenedEventId,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context(
                    "IUIAutomationEventHandlerGroup::AddMenuOpenedHandler",
                ))?;
            group
                .AddPropertyChangedEventHandler(
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.property,
                    STATE_CHANGE_PROPERTIES,
                )
                .map_err(windows_context(
                    "IUIAutomationEventHandlerGroup::AddPropertyChangedHandler",
                ))?;
            group
                .AddTextEditTextChangedEventHandler(
                    TreeScope_Subtree,
                    TextEditChangeType_CompositionFinalized,
                    &self.cache_request,
                    &self.handler.text_edit,
                )
                .map_err(windows_context(
                    "IUIAutomationEventHandlerGroup::AddTextEditHandler",
                ))?;
            automation6
                .AddEventHandlerGroup(element, &group)
                .map_err(windows_context("IUIAutomation6::AddEventHandlerGroup"))?;
        }
        Ok(Subscription {
            element: element.clone(),
            group: Some(group),
            individual: false,
        })
    }

    fn subscribe_individual(
        &self,
        element: IUIAutomationElement,
    ) -> Result<Subscription, CaptureError> {
        unsafe {
            self.automation
                .AddAutomationEventHandler(
                    UIA_Invoke_InvokedEventId,
                    &element,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context("IUIAutomation::AddInvokeHandler"))?;
            self.automation
                .AddAutomationEventHandler(
                    UIA_SelectionItem_ElementSelectedEventId,
                    &element,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context("IUIAutomation::AddSelectionHandler"))?;
            self.automation
                .AddAutomationEventHandler(
                    UIA_MenuOpenedEventId,
                    &element,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.event,
                )
                .map_err(windows_context("IUIAutomation::AddMenuOpenedHandler"))?;
            self.automation
                .AddPropertyChangedEventHandlerNativeArray(
                    &element,
                    TreeScope_Subtree,
                    &self.cache_request,
                    &self.handler.property,
                    STATE_CHANGE_PROPERTIES,
                )
                .map_err(windows_context("IUIAutomation::AddPropertyChangedHandler"))?;
            if let Some(automation3) = self.automation3.as_ref() {
                automation3
                    .AddTextEditTextChangedEventHandler(
                        &element,
                        TreeScope_Subtree,
                        TextEditChangeType_CompositionFinalized,
                        &self.cache_request,
                        &self.handler.text_edit,
                    )
                    .map_err(windows_context("IUIAutomation3::AddTextEditHandler"))?;
            }
        }
        Ok(Subscription {
            element,
            group: None,
            individual: true,
        })
    }

    fn replace_window_subscription(&mut self, hwnd: HWND) -> Result<(), CaptureError> {
        let previous = self.subscription.take();
        match self.subscribe_to_window(hwnd) {
            Ok(()) => {
                if let Some(subscription) = previous {
                    self.remove_subscription(&subscription);
                }
                Ok(())
            }
            Err(error) => {
                self.subscription = previous;
                Err(error)
            }
        }
    }

    fn unsubscribe(&mut self) {
        self.unsubscribe_window();
        unsafe {
            let _ = self
                .automation
                .RemoveFocusChangedEventHandler(&self.handler.focus);
        }
    }

    fn unsubscribe_window(&mut self) {
        let Some(subscription) = self.subscription.take() else {
            return;
        };
        self.remove_subscription(&subscription);
    }

    fn remove_subscription(&self, subscription: &Subscription) {
        unsafe {
            if let Some(group) = subscription.group.as_ref() {
                if let Some(automation6) = self.automation6.as_ref() {
                    let _ = automation6.RemoveEventHandlerGroup(&subscription.element, group);
                }
            } else if subscription.individual {
                let _ = self.automation.RemoveAutomationEventHandler(
                    UIA_Invoke_InvokedEventId,
                    &subscription.element,
                    &self.handler.event,
                );
                let _ = self.automation.RemoveAutomationEventHandler(
                    UIA_SelectionItem_ElementSelectedEventId,
                    &subscription.element,
                    &self.handler.event,
                );
                let _ = self.automation.RemoveAutomationEventHandler(
                    UIA_MenuOpenedEventId,
                    &subscription.element,
                    &self.handler.event,
                );
                let _ = self.automation.RemovePropertyChangedEventHandler(
                    &subscription.element,
                    &self.handler.property,
                );
                if let Some(automation3) = self.automation3.as_ref() {
                    let _ = automation3.RemoveTextEditTextChangedEventHandler(
                        &subscription.element,
                        &self.handler.text_edit,
                    );
                }
            }
        }
    }

    fn focused_element(&self) -> Result<IUIAutomationElement, CaptureError> {
        unsafe {
            self.automation
                .GetFocusedElementBuildCache(&self.cache_request)
                .map_err(windows_context(
                    "IUIAutomation::GetFocusedElementBuildCache",
                ))
        }
    }

    fn capture_element(
        &self,
        element: &IUIAutomationElement,
        target: &TargetWindow,
        scoped_sender: bool,
    ) -> Result<ElementSnapshot, CaptureError> {
        let leaf = CachedNode::from_element(element)?;
        let owner_probe = owner_window_probe(&leaf.rect);
        let probe = TrustProbe {
            element_pid_in_target_tree: target.processes.contains(&leaf.process_id),
            owner_window_pid_in_target_tree: owner_probe
                .as_ref()
                .is_some_and(|probe| target.processes.contains(&probe.pid)),
            rect_contained_by_owner_window: owner_probe.is_some_and(|probe| probe.contains_rect),
            scoped_invoke_sender: scoped_sender,
        };
        let Some(trust_basis) = classify_trust(probe) else {
            return Err(CaptureError::WindowsApi(
                "UIA element failed target trust classification".to_string(),
            ));
        };
        let selector_path = self.selector_path_for(element, &leaf)?;
        let target_key = selector_path.hash_v1();
        let depth = selector_path.hops.len() as u32;
        let framework_class = framework_class_from_id(&leaf.framework_id);
        let captured = CapturedElement {
            target_key,
            selector_path,
            trust_basis,
            exe: process_path(leaf.process_id).or_else(|| target.exe.clone()),
            has_name: false,
            framework: BACKEND_UIA.to_string(),
            framework_class,
            framework_id: leaf.framework_id.clone(),
            depth,
            leaf_rect: Some(rect_string(&leaf.rect)),
        };
        Ok(ElementSnapshot {
            element: captured,
            availability: PatternAvailability {
                invoke: cached_bool(element, UIA_IsInvokePatternAvailablePropertyId),
                toggle: cached_bool(element, UIA_IsTogglePatternAvailablePropertyId),
                select: cached_bool(element, UIA_IsSelectionItemPatternAvailablePropertyId),
                expand_collapse: cached_bool(
                    element,
                    UIA_IsExpandCollapsePatternAvailablePropertyId,
                ),
                scroll: cached_bool(element, UIA_IsScrollPatternAvailablePropertyId),
                text_edit: cached_bool(element, UIA_IsTextEditPatternAvailablePropertyId),
            },
            state: CachedActionState {
                toggle_state: cached_toggle_state(element),
                expand_collapse_state: cached_expand_collapse_state(element),
                vertical_scroll_percent: cached_scroll_percent(
                    element,
                    UIA_ScrollVerticalScrollPercentPropertyId,
                ),
                horizontal_scroll_percent: cached_scroll_percent(
                    element,
                    UIA_ScrollHorizontalScrollPercentPropertyId,
                ),
            },
            control_type: leaf.control_type,
            automation_id: leaf.automation_id,
            framework_id: leaf.framework_id,
        })
    }

    fn selector_path_for(
        &self,
        leaf_element: &IUIAutomationElement,
        leaf: &CachedNode,
    ) -> Result<SelectorPath, CaptureError> {
        let mut nodes = VecDeque::new();
        nodes.push_front(SelectorPathHop {
            control_type: leaf.control_type,
            automation_id: leaf.automation_id.clone(),
            class_name: leaf.class_name.clone(),
            ordinal: self.sibling_ordinal(leaf_element, leaf).unwrap_or(0),
        });
        let mut current = leaf_element.clone();
        for _ in 1..MAX_SELECTOR_DEPTH {
            let parent = unsafe {
                self.walker
                    .GetParentElementBuildCache(&current, &self.cache_request)
                    .ok()
            };
            let Some(parent) = parent else {
                break;
            };
            let attrs = CachedNode::from_element(&parent)?;
            nodes.push_front(SelectorPathHop {
                control_type: attrs.control_type,
                automation_id: attrs.automation_id.clone(),
                class_name: attrs.class_name.clone(),
                ordinal: self.sibling_ordinal(&parent, &attrs).unwrap_or(0),
            });
            if !attrs.native_window_handle.is_invalid() {
                break;
            }
            current = parent;
        }
        Ok(SelectorPath {
            backend: BACKEND_UIA.to_string(),
            hops: nodes.into(),
        })
    }

    fn sibling_ordinal(&self, element: &IUIAutomationElement, attrs: &CachedNode) -> Option<u32> {
        let parent = unsafe {
            self.walker
                .GetParentElementBuildCache(element, &self.cache_request)
                .ok()?
        };
        let condition = unsafe { self.automation.CreateTrueCondition().ok()? };
        let children = unsafe {
            parent
                .FindAllBuildCache(TreeScope_Children, &condition, &self.cache_request)
                .ok()?
        };
        let length = unsafe { children.Length().ok()? };
        let mut ordinal = 0_u32;
        for index in 0..length {
            let candidate = unsafe { children.GetElement(index).ok()? };
            if unsafe {
                self.automation
                    .CompareElements(&candidate, element)
                    .ok()?
                    .as_bool()
            } {
                return Some(ordinal);
            }
            if let Ok(candidate_attrs) = CachedNode::from_element(&candidate) {
                if candidate_attrs.same_selector_identity(attrs) {
                    ordinal = ordinal.saturating_add(1);
                }
            }
        }
        Some(ordinal)
    }

    fn scroll_delta(
        &mut self,
        snapshot: &ElementSnapshot,
        property: UIA_PROPERTY_ID,
    ) -> Option<ScrollDelta> {
        let key = snapshot.element.target_key.clone();
        let current = snapshot.state;
        let previous = self.last_scroll_state.insert(key, current);
        let previous = previous?;
        if property == UIA_ScrollHorizontalScrollPercentPropertyId {
            let delta = scroll_axis_delta(
                previous.horizontal_scroll_percent,
                current.horizontal_scroll_percent,
            )?;
            return Some(ScrollDelta {
                direction: ScrollDirection::Horizontal,
                amount_bucket: Some(scroll_amount_bucket(delta)),
            });
        }
        let delta = scroll_axis_delta(
            previous.vertical_scroll_percent,
            current.vertical_scroll_percent,
        )?;
        Some(ScrollDelta {
            direction: if delta < 0.0 {
                ScrollDirection::Up
            } else {
                ScrollDirection::Down
            },
            amount_bucket: Some(scroll_amount_bucket(delta)),
        })
    }
}

struct Subscription {
    element: IUIAutomationElement,
    group: Option<IUIAutomationEventHandlerGroup>,
    individual: bool,
}

struct ElementSnapshot {
    element: CapturedElement,
    availability: PatternAvailability,
    state: CachedActionState,
    control_type: i32,
    automation_id: String,
    framework_id: String,
}

impl ElementSnapshot {
    fn is_non_actionable_chromium_root(&self) -> bool {
        self.framework_id.eq_ignore_ascii_case(CHROME_FRAMEWORK_ID)
            && self.automation_id == CHROME_ROOT_WEB_AREA_ID
            && self.control_type == UIA_DOCUMENT_CONTROL_TYPE
    }
}

#[derive(Clone, Debug)]
struct CachedNode {
    process_id: u32,
    control_type: i32,
    automation_id: String,
    class_name: String,
    framework_id: String,
    native_window_handle: HWND,
    rect: RECT,
}

impl CachedNode {
    fn from_element(element: &IUIAutomationElement) -> Result<Self, CaptureError> {
        Ok(Self {
            process_id: unsafe { element.CachedProcessId().map_err(windows_error)? }
                .try_into()
                .unwrap_or(0),
            control_type: unsafe { element.CachedControlType().map_err(windows_error)? }.0,
            automation_id: bstr_string(unsafe {
                element.CachedAutomationId().map_err(windows_error)?
            }),
            class_name: bstr_string(unsafe { element.CachedClassName().map_err(windows_error)? }),
            framework_id: bstr_string(unsafe {
                element.CachedFrameworkId().map_err(windows_error)?
            }),
            native_window_handle: unsafe { element.CachedNativeWindowHandle().unwrap_or_default() },
            rect: unsafe { element.CachedBoundingRectangle().map_err(windows_error)? },
        })
    }

    fn same_selector_identity(&self, other: &Self) -> bool {
        self.control_type == other.control_type
            && self.automation_id == other.automation_id
            && self.class_name == other.class_name
    }
}

fn cached_bool(element: &IUIAutomationElement, property: UIA_PROPERTY_ID) -> bool {
    unsafe {
        element
            .GetCachedPropertyValue(property)
            .map(|value| variant_is_true(&value))
            .unwrap_or(false)
    }
}

fn variant_is_true(value: &VARIANT) -> bool {
    unsafe {
        value.Anonymous.Anonymous.vt == VT_BOOL
            && value.Anonymous.Anonymous.Anonymous.boolVal == VARIANT_TRUE
    }
}

fn cached_toggle_state(element: &IUIAutomationElement) -> Option<ToggleActionState> {
    let state = cached_i32(element, UIA_ToggleToggleStatePropertyId)?;
    map_toggle_state(ToggleState(state))
}

fn map_toggle_state(state: ToggleState) -> Option<ToggleActionState> {
    if state == ToggleState_On {
        Some(ToggleActionState::On)
    } else if state == ToggleState_Off {
        Some(ToggleActionState::Off)
    } else if state == ToggleState_Indeterminate {
        Some(ToggleActionState::Indeterminate)
    } else {
        None
    }
}

fn cached_expand_collapse_state(
    element: &IUIAutomationElement,
) -> Option<ExpandCollapseActionState> {
    let state = cached_i32(element, UIA_ExpandCollapseExpandCollapseStatePropertyId)?;
    map_expand_collapse_state(ExpandCollapseState(state))
}

fn map_expand_collapse_state(state: ExpandCollapseState) -> Option<ExpandCollapseActionState> {
    if state == ExpandCollapseState_Expanded || state == ExpandCollapseState_PartiallyExpanded {
        Some(ExpandCollapseActionState::Expanded)
    } else if state == ExpandCollapseState_Collapsed {
        Some(ExpandCollapseActionState::Collapsed)
    } else {
        None
    }
}

fn cached_scroll_percent(element: &IUIAutomationElement, property: UIA_PROPERTY_ID) -> Option<f64> {
    let value = unsafe { element.GetCachedPropertyValue(property).ok()? };
    variant_f64(&value).filter(|value| *value >= 0.0 && *value != UIA_SCROLL_PATTERN_NO_SCROLL)
}

fn cached_i32(element: &IUIAutomationElement, property: UIA_PROPERTY_ID) -> Option<i32> {
    let value = unsafe { element.GetCachedPropertyValue(property).ok()? };
    variant_i32(&value)
}

fn variant_i32(value: &VARIANT) -> Option<i32> {
    unsafe {
        let vt = value.Anonymous.Anonymous.vt;
        if vt == VT_I4 {
            Some(value.Anonymous.Anonymous.Anonymous.lVal)
        } else {
            None
        }
    }
}

fn variant_f64(value: &VARIANT) -> Option<f64> {
    unsafe {
        let vt = value.Anonymous.Anonymous.vt;
        if vt == VT_R8 {
            Some(value.Anonymous.Anonymous.Anonymous.dblVal)
        } else if vt == VT_R4 {
            Some(f64::from(value.Anonymous.Anonymous.Anonymous.fltVal))
        } else if vt == VT_I4 {
            Some(f64::from(value.Anonymous.Anonymous.Anonymous.lVal))
        } else {
            None
        }
    }
}

fn scroll_axis_delta(previous: Option<f64>, current: Option<f64>) -> Option<f64> {
    let previous = previous?;
    let current = current?;
    let delta = current - previous;
    (delta.abs() > f64::EPSILON).then_some(delta)
}

fn scroll_amount_bucket(delta: f64) -> u8 {
    let magnitude = delta.abs();
    if magnitude < 5.0 {
        1
    } else if magnitude < 15.0 {
        2
    } else if magnitude < 35.0 {
        3
    } else {
        4
    }
}

fn bstr_string(value: BSTR) -> String {
    value.to_string()
}

fn rect_string(rect: &RECT) -> String {
    format!("{},{},{},{}", rect.left, rect.top, rect.right, rect.bottom)
}

#[derive(Clone, Copy, Debug)]
struct OwnerWindowProbe {
    pid: u32,
    contains_rect: bool,
}

fn owner_window_probe(rect: &RECT) -> Option<OwnerWindowProbe> {
    let point = rect_center(rect)?;
    let hwnd = unsafe { WindowFromPoint(point) };
    if hwnd.is_invalid() {
        return None;
    }
    let owner = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
    if owner.is_invalid() || !unsafe { IsWindowVisible(owner).as_bool() } {
        return None;
    }
    let pid = hwnd_pid(owner)?;
    let mut owner_rect = RECT::default();
    let contains_rect = unsafe { GetWindowRect(owner, &mut owner_rect).is_ok() }
        && rect_contains_with_tolerance(&owner_rect, rect, RECT_CONTAINMENT_TOLERANCE_PX);
    Some(OwnerWindowProbe { pid, contains_rect })
}

fn rect_contains_with_tolerance(outer: &RECT, inner: &RECT, tolerance: i32) -> bool {
    inner.left >= outer.left - tolerance
        && inner.top >= outer.top - tolerance
        && inner.right <= outer.right + tolerance
        && inner.bottom <= outer.bottom + tolerance
}

fn rect_center(rect: &RECT) -> Option<POINT> {
    if rect.right <= rect.left || rect.bottom <= rect.top {
        return None;
    }
    Some(POINT {
        x: rect.left + (rect.right - rect.left) / 2,
        y: rect.top + (rect.bottom - rect.top) / 2,
    })
}

#[derive(Clone, Debug)]
struct TargetWindow {
    hwnd: HWND,
    pid: u32,
    processes: HashSet<u32>,
    exe: Option<String>,
}

fn wait_for_target_window(
    timeout: Duration,
    target_pid: Option<u32>,
    extra_trusted_pids: &[u32],
) -> Option<TargetWindow> {
    let deadline = Instant::now() + timeout;
    loop {
        let target = match target_pid {
            Some(pid) => target_window_for_pid(pid, extra_trusted_pids),
            None => foreground_non_self_target(extra_trusted_pids),
        };
        if target.is_some() {
            return target;
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn foreground_non_self_target(extra_trusted_pids: &[u32]) -> Option<TargetWindow> {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_invalid() || !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return None;
    }
    let root = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
    let pid = hwnd_pid(root)?;
    if pid == unsafe { GetCurrentProcessId() } {
        return None;
    }
    target_window_from_root(root, pid, extra_trusted_pids)
}

fn target_window_for_pid(pid: u32, extra_trusted_pids: &[u32]) -> Option<TargetWindow> {
    if pid == unsafe { GetCurrentProcessId() } {
        return None;
    }
    let hwnd = top_level_window_for_pid(pid)?;
    target_window_from_root(hwnd, pid, extra_trusted_pids)
}

fn target_window_from_root(
    root: HWND,
    pid: u32,
    extra_trusted_pids: &[u32],
) -> Option<TargetWindow> {
    let mut processes = ProcessSnapshot::capture()
        .map(|snapshot| snapshot.process_tree(pid))
        .unwrap_or_else(|_| HashSet::from([pid]));
    for trusted_pid in extra_trusted_pids {
        processes.insert(*trusted_pid);
    }
    Some(TargetWindow {
        hwnd: root,
        pid,
        processes,
        exe: process_path(pid),
    })
}

fn top_level_window_for_pid(pid: u32) -> Option<HWND> {
    let mut search = TargetPidWindowSearch {
        pid,
        windows: Vec::new(),
    };
    let result = unsafe {
        EnumWindows(
            Some(enum_target_pid_windows_callback),
            LPARAM((&mut search as *mut TargetPidWindowSearch) as isize),
        )
    };
    if let Err(error) = result {
        warn!(%error, pid, "failed to enumerate target windows");
    }
    search.windows.into_iter().next()
}

struct TargetPidWindowSearch {
    pid: u32,
    windows: Vec<HWND>,
}

unsafe extern "system" fn enum_target_pid_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let search = unsafe { &mut *(lparam.0 as *mut TargetPidWindowSearch) };
    if is_real_top_level_window(hwnd) {
        if let Some(pid) = hwnd_pid(hwnd) {
            if pid == search.pid && pid != unsafe { GetCurrentProcessId() } {
                search.windows.push(hwnd);
            }
        }
    }
    true.into()
}

fn is_real_top_level_window(hwnd: HWND) -> bool {
    if hwnd.is_invalid() {
        return false;
    }

    unsafe {
        if !IsWindow(Some(hwnd)).as_bool() || !IsWindowVisible(hwnd).as_bool() {
            return false;
        }

        if GetAncestor(hwnd, GA_ROOT).0 != hwnd.0 {
            return false;
        }

        GetWindow(hwnd, GW_OWNER).is_err()
    }
}

fn hwnd_pid(hwnd: HWND) -> Option<u32> {
    if hwnd.is_invalid() {
        return None;
    }
    let mut pid = 0_u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    (pid > 0).then_some(pid)
}

fn process_path(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let _guard = HandleGuard(handle);
    let mut buffer = vec![0_u16; 32_768];
    let mut len = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
        .ok()?;
    }
    buffer.truncate(len as usize);
    Some(String::from_utf16_lossy(&buffer))
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcessEntry {
    parent_pid: u32,
}

struct ProcessSnapshot {
    entries: HashMap<u32, ProcessEntry>,
}

impl ProcessSnapshot {
    fn capture() -> Result<Self, CaptureError> {
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(windows_error)? };
        let _guard = HandleGuard(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut entries = HashMap::new();
        let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
        while has_entry {
            entries.insert(
                entry.th32ProcessID,
                ProcessEntry {
                    parent_pid: entry.th32ParentProcessID,
                },
            );
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            has_entry = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
        }
        Ok(Self { entries })
    }

    fn process_tree(&self, root_pid: u32) -> HashSet<u32> {
        let mut result = HashSet::from([root_pid]);
        let mut queue = VecDeque::from([root_pid]);
        while let Some(parent) = queue.pop_front() {
            for (pid, entry) in &self.entries {
                if entry.parent_pid == parent && result.insert(*pid) {
                    queue.push_back(*pid);
                }
            }
        }
        result
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> Result<Self, CaptureError> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(windows_error)?;
        }
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

fn create_automation() -> Result<IUIAutomation, CaptureError> {
    unsafe {
        CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
            .or_else(|_| CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER))
            .map_err(windows_error)
    }
}

fn windows_error(error: windows::core::Error) -> CaptureError {
    CaptureError::WindowsApi(error.to_string())
}

fn windows_context(label: &'static str) -> impl FnOnce(windows::core::Error) -> CaptureError {
    move |error| CaptureError::WindowsApi(format!("{label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> CapturedElement {
        let selector_path = SelectorPath {
            backend: BACKEND_UIA.to_string(),
            hops: vec![SelectorPathHop {
                control_type: 50000,
                automation_id: name.to_string(),
                class_name: "Button".to_string(),
                ordinal: 0,
            }],
        };
        CapturedElement {
            target_key: selector_path.hash_v1(),
            selector_path,
            trust_basis: SelectorTrustBasis::PidMatch,
            exe: Some("app.exe".to_string()),
            has_name: false,
            framework: BACKEND_UIA.to_string(),
            framework_class: FrameworkClass::Native,
            framework_id: "Win32".to_string(),
            depth: 1,
            leaf_rect: None,
        }
    }

    fn diag(action_type: Option<ActionType>, worker_ordinal: u64) -> ActionDiag {
        ActionDiag {
            record_session_id: 7,
            worker_ordinal,
            event_kind: "test".to_string(),
            callback_latency_ns: 1,
            event_to_selector_complete_ns: 2,
            queue_depth_at_enqueue: 1,
            repeat_count: 1,
            edit_commit_signal: None,
            trust_basis: Some(SelectorTrustBasis::PidMatch),
            action_type,
        }
    }

    fn draft(
        name: &str,
        action_type: ActionType,
        payload: ActionPayload,
        captured_at: Instant,
    ) -> ActionDraft {
        ActionDraft {
            target: target(name),
            action_type,
            payload,
            pattern_action: Some(action_type.as_str().to_string()),
            captured_at,
            diag: diag(Some(action_type), 1),
        }
    }

    fn toggle_payload(state: ToggleActionState) -> ActionPayload {
        ActionPayload::Toggle {
            to_state: state,
            from_modality: None,
            corroborates: None,
        }
    }

    fn scroll_payload(direction: ScrollDirection, amount_bucket: Option<u8>) -> ActionPayload {
        ActionPayload::Scroll {
            direction,
            amount_bucket,
            from_modality: None,
            corroborates: None,
        }
    }

    #[test]
    fn cache_properties_are_limited_to_value_free_allowlist() {
        use windows::Win32::UI::Accessibility::{
            UIA_AutomationIdPropertyId, UIA_BoundingRectanglePropertyId, UIA_ClassNamePropertyId,
            UIA_ControlTypePropertyId, UIA_ExpandCollapseExpandCollapseStatePropertyId,
            UIA_FrameworkIdPropertyId, UIA_HasKeyboardFocusPropertyId,
            UIA_IsExpandCollapsePatternAvailablePropertyId, UIA_IsInvokePatternAvailablePropertyId,
            UIA_IsScrollPatternAvailablePropertyId, UIA_IsSelectionItemPatternAvailablePropertyId,
            UIA_IsTextEditPatternAvailablePropertyId, UIA_IsTogglePatternAvailablePropertyId,
            UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId,
            UIA_ScrollHorizontalScrollPercentPropertyId, UIA_ScrollVerticalScrollPercentPropertyId,
            UIA_ToggleToggleStatePropertyId,
        };

        let allowed_properties = [
            UIA_RuntimeIdPropertyId,
            UIA_ControlTypePropertyId,
            UIA_AutomationIdPropertyId,
            UIA_ClassNamePropertyId,
            UIA_FrameworkIdPropertyId,
            UIA_BoundingRectanglePropertyId,
            UIA_ProcessIdPropertyId,
            UIA_HasKeyboardFocusPropertyId,
            UIA_IsInvokePatternAvailablePropertyId,
            UIA_IsTogglePatternAvailablePropertyId,
            UIA_IsSelectionItemPatternAvailablePropertyId,
            UIA_IsExpandCollapsePatternAvailablePropertyId,
            UIA_IsScrollPatternAvailablePropertyId,
            UIA_IsTextEditPatternAvailablePropertyId,
            UIA_ToggleToggleStatePropertyId,
            UIA_ExpandCollapseExpandCollapseStatePropertyId,
            UIA_ScrollHorizontalScrollPercentPropertyId,
            UIA_ScrollVerticalScrollPercentPropertyId,
        ];

        for property in CACHE_PROPERTIES {
            assert!(
                allowed_properties.contains(property),
                "UIA cache property {} is not on the value-free allowlist",
                property.0
            );
        }
    }

    #[test]
    fn run_stats_aggregate_synthetic_diagnostics() {
        let stats = RecordRoutineSharedStats::new();
        stats.storm_dropped_events.store(2, Ordering::SeqCst);

        let mut first = diag(Some(ActionType::Invoke), 1);
        first.callback_latency_ns = 10;
        first.event_to_selector_complete_ns = 100;
        first.queue_depth_at_enqueue = 3;
        stats.record_action_diag(&first);

        let mut edit = diag(Some(ActionType::EditCommitted), 2);
        edit.callback_latency_ns = 20;
        edit.event_to_selector_complete_ns = 200;
        edit.queue_depth_at_enqueue = 5;
        edit.edit_commit_signal = Some(EditCommitSignal::FocusLoss);
        stats.record_action_diag(&edit);

        let mut scroll = diag(Some(ActionType::Scroll), 4);
        scroll.callback_latency_ns = 40;
        scroll.event_to_selector_complete_ns = 400;
        scroll.queue_depth_at_enqueue = 2;
        scroll.trust_basis = Some(SelectorTrustBasis::WindowOwnership);
        stats.record_action_diag(&scroll);

        stats.record_rejected(&RejectedAction {
            record_session_id: 7,
            worker_ordinal: 3,
            event_kind: "focus_changed".to_string(),
            captured_at: Instant::now(),
            reason: RejectedActionReason::WindowMismatch,
            trust_basis: None,
            callback_latency_ns: 30,
            event_to_selector_complete_ns: 300,
            queue_depth_at_enqueue: 4,
        });
        stats.record_window(HWND(0x100 as _));
        stats.record_window(HWND(0x100 as _));
        stats.record_window(HWND(0x200 as _));

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.storm_dropped_events, 2);
        assert_eq!(snapshot.max_queue_depth, 5);
        assert_eq!(snapshot.callback_latency.p50_ns, 20);
        assert_eq!(snapshot.callback_latency.p95_ns, 40);
        assert_eq!(snapshot.callback_latency.max_ns, 40);
        assert_eq!(snapshot.event_to_selector_complete.p50_ns, 200);
        assert_eq!(snapshot.action_type_counts["invoke"], 1);
        assert_eq!(snapshot.action_type_counts["edit_committed"], 1);
        assert_eq!(snapshot.action_type_counts["scroll"], 1);
        assert_eq!(snapshot.trust_basis_counts["pid_match"], 2);
        assert_eq!(snapshot.trust_basis_counts["window_ownership"], 1);
        assert_eq!(snapshot.failure_counts["window_mismatch"], 1);
        assert_eq!(snapshot.edit_commit_signal_counts["focus_loss"], 1);
        assert_eq!(snapshot.windows_recorded, 2);
    }

    #[test]
    fn send_helpers_gate_diagnostic_variants() {
        let stats = RecordRoutineSharedStats::new();
        let (tx, rx) = bounded(4);
        let captured_at = Instant::now();
        let action = CoalescedAction {
            target: target("save"),
            action_type: ActionType::Invoke,
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("invoke".to_string()),
            captured_at,
            diag: diag(Some(ActionType::Invoke), 1),
        };

        assert!(send_coalesced_action(&tx, &stats, action, 7, false));
        match rx.try_recv().expect("action row") {
            WriterInput::Action(action) => {
                assert_eq!(action.record_session_id, 7);
                assert_eq!(action.action.action_type, ActionType::Invoke);
            }
            other => panic!("unexpected writer input: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(stats.snapshot().action_type_counts.is_empty());

        assert!(send_rejected_action(
            &tx,
            &stats,
            false,
            RejectedAction {
                record_session_id: 7,
                worker_ordinal: 2,
                event_kind: "focus_changed".to_string(),
                captured_at,
                reason: RejectedActionReason::WindowMismatch,
                trust_basis: None,
                callback_latency_ns: 1,
                event_to_selector_complete_ns: 2,
                queue_depth_at_enqueue: 1,
            },
        ));
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(stats.snapshot().failure_counts.is_empty());

        let (full_tx, full_rx) = bounded(1);
        full_tx
            .send(WriterInput::ActionDiag(diag(Some(ActionType::Invoke), 9)))
            .expect("fill channel");
        assert!(send_rejected_action(
            &full_tx,
            &stats,
            true,
            RejectedAction {
                record_session_id: 7,
                worker_ordinal: 3,
                event_kind: "focus_changed".to_string(),
                captured_at,
                reason: RejectedActionReason::WindowMismatch,
                trust_basis: None,
                callback_latency_ns: 3,
                event_to_selector_complete_ns: 4,
                queue_depth_at_enqueue: 2,
            },
        ));
        assert!(matches!(
            full_rx.try_recv().expect("original row remains"),
            WriterInput::ActionDiag(_)
        ));
    }

    #[test]
    fn classifier_covers_all_action_kinds_and_priority() {
        let state = CachedActionState {
            toggle_state: Some(ToggleActionState::Off),
            expand_collapse_state: Some(ExpandCollapseActionState::Collapsed),
            vertical_scroll_percent: Some(10.0),
            horizontal_scroll_percent: None,
        };

        let all = classify_cached_action(
            PatternAvailability {
                invoke: true,
                toggle: true,
                select: true,
                expand_collapse: true,
                scroll: true,
                text_edit: false,
            },
            state,
            Some(ScrollDelta {
                direction: ScrollDirection::Down,
                amount_bucket: Some(1),
            }),
        );
        assert_eq!(all.action_type, ActionType::ExpandCollapse);

        let select_toggle = classify_cached_action(
            PatternAvailability {
                select: true,
                toggle: true,
                ..PatternAvailability::default()
            },
            state,
            None,
        );
        assert_eq!(select_toggle.action_type, ActionType::Select);

        assert_eq!(
            classify_cached_action(
                PatternAvailability {
                    toggle: true,
                    ..PatternAvailability::default()
                },
                state,
                None,
            )
            .action_type,
            ActionType::Toggle
        );
        assert_eq!(
            classify_cached_action(
                PatternAvailability {
                    scroll: true,
                    ..PatternAvailability::default()
                },
                state,
                Some(ScrollDelta {
                    direction: ScrollDirection::Horizontal,
                    amount_bucket: Some(2),
                }),
            )
            .action_type,
            ActionType::Scroll
        );
        assert_eq!(
            classify_cached_action(
                PatternAvailability {
                    invoke: true,
                    ..PatternAvailability::default()
                },
                state,
                None,
            )
            .action_type,
            ActionType::Invoke
        );
        assert_eq!(
            classify_cached_action(PatternAvailability::default(), state, None).action_type,
            ActionType::UiActionOther
        );

        let edit = CoalescedAction {
            target: target("edit"),
            action_type: ActionType::EditCommitted,
            payload: ActionPayload::EditCommitted {
                from_modality: None,
                corroborates: None,
            },
            pattern_action: Some("edit_committed".to_string()),
            captured_at: Instant::now(),
            diag: diag(Some(ActionType::EditCommitted), 1),
        };
        assert_eq!(edit.action_type, ActionType::EditCommitted);
    }

    #[test]
    fn trust_classifier_uses_ordered_os_anchored_bases() {
        assert_eq!(
            classify_trust(TrustProbe {
                element_pid_in_target_tree: true,
                owner_window_pid_in_target_tree: true,
                rect_contained_by_owner_window: true,
                scoped_invoke_sender: true,
            }),
            Some(SelectorTrustBasis::PidMatch)
        );
        assert_eq!(
            classify_trust(TrustProbe {
                element_pid_in_target_tree: false,
                owner_window_pid_in_target_tree: true,
                rect_contained_by_owner_window: true,
                scoped_invoke_sender: true,
            }),
            Some(SelectorTrustBasis::WindowOwnership)
        );
        assert_eq!(
            classify_trust(TrustProbe {
                element_pid_in_target_tree: false,
                owner_window_pid_in_target_tree: false,
                rect_contained_by_owner_window: false,
                scoped_invoke_sender: true,
            }),
            Some(SelectorTrustBasis::ScopedInvokeSender)
        );
        assert_eq!(
            classify_trust(TrustProbe {
                element_pid_in_target_tree: false,
                owner_window_pid_in_target_tree: false,
                rect_contained_by_owner_window: false,
                scoped_invoke_sender: false,
            }),
            None
        );
    }

    #[test]
    fn record_routine_config_defaults_to_foreground_following() {
        let config = RecordRoutineConfig::new(42);

        assert_eq!(config.record_session_id, 42);
        assert_eq!(config.target_pid, None);
        assert!(config.extra_trusted_pids.is_empty());
        assert!(config.follow_foreground);
        assert!(!config.emit_diagnostics);
    }

    #[test]
    fn exe_basename_drops_parent_directories_for_info_logs() {
        assert_eq!(
            exe_basename(r"C:\Users\operator\Apps\tool.exe").as_deref(),
            Some("tool.exe")
        );
        assert_eq!(exe_basename("notepad.exe").as_deref(), Some("notepad.exe"));
    }

    #[test]
    fn elevated_failures_are_classified_after_uia_attempt() {
        assert_eq!(
            rejected_reason_for_error(&CaptureError::WindowsApi(
                "IUIAutomation::AddInvokeHandler failed: access denied (0x80070005)".to_string()
            )),
            RejectedActionReason::ElevatedOrUipiDenied
        );
        assert_eq!(
            rejected_reason_for_error(&CaptureError::WindowsApi(
                "target UIA read blocked by UIPI".to_string()
            )),
            RejectedActionReason::ElevatedOrUipiDenied
        );
    }

    #[test]
    fn coalescer_suppresses_duplicate_state_and_splits_scroll_reversal() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming {
            dedup_window_ms: 500,
            scroll_quiet_ms: 500,
            idle_commit_ms: None,
        });
        let toggle = toggle_payload(ToggleActionState::On);
        assert_eq!(
            coalescer
                .handle(CoalescerInput::Action(draft(
                    "check",
                    ActionType::Toggle,
                    toggle.clone(),
                    base
                )))
                .len(),
            1
        );
        assert!(coalescer
            .handle(CoalescerInput::Action(draft(
                "check",
                ActionType::Toggle,
                toggle,
                base + Duration::from_millis(10)
            )))
            .is_empty());

        let after_dedup_window = coalescer.handle(CoalescerInput::Action(draft(
            "check",
            ActionType::Toggle,
            toggle_payload(ToggleActionState::On),
            base + Duration::from_millis(501),
        )));
        assert_eq!(after_dedup_window.len(), 1);

        let down = scroll_payload(ScrollDirection::Down, Some(1));
        let up = scroll_payload(ScrollDirection::Up, Some(1));
        let mut first_down = draft("pane", ActionType::Scroll, down.clone(), base);
        first_down.diag.callback_latency_ns = 10;
        first_down.diag.event_to_selector_complete_ns = 20;
        first_down.diag.queue_depth_at_enqueue = 1;
        assert!(coalescer
            .handle(CoalescerInput::Action(first_down))
            .is_empty());
        let mut second_down = draft(
            "pane",
            ActionType::Scroll,
            down,
            base + Duration::from_millis(20),
        );
        second_down.diag.callback_latency_ns = 30;
        second_down.diag.event_to_selector_complete_ns = 40;
        second_down.diag.queue_depth_at_enqueue = 3;
        assert!(coalescer
            .handle(CoalescerInput::Action(second_down))
            .is_empty());
        let flushed = coalescer.handle(CoalescerInput::Action(draft(
            "pane",
            ActionType::Scroll,
            up,
            base + Duration::from_millis(40),
        )));
        assert_eq!(flushed.len(), 1);
        assert!(matches!(
            flushed[0].payload,
            ActionPayload::Scroll {
                direction: ScrollDirection::Down,
                ..
            }
        ));
        assert_eq!(flushed[0].diag.repeat_count, 2);
        assert_eq!(flushed[0].diag.callback_latency_ns, 30);
        assert_eq!(flushed[0].diag.event_to_selector_complete_ns, 40);
        assert_eq!(flushed[0].diag.queue_depth_at_enqueue, 3);
        assert_eq!(
            coalescer.flush_all(base + Duration::from_millis(50)).len(),
            1
        );
    }

    #[test]
    fn coalescer_commits_edit_on_focus_loss_and_stop() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming::default());
        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("edit"),
                captured_at: base,
                from_modality: Some(Modality::Keyboard),
                diag: diag(None, 1),
            })
            .is_empty());
        let committed = coalescer.handle(CoalescerInput::FocusChanged {
            captured_at: base + Duration::from_millis(20),
            signal: EditCommitSignal::FocusLoss,
        });
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            committed[0].diag.edit_commit_signal,
            Some(EditCommitSignal::FocusLoss)
        );

        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("edit"),
                captured_at: base + Duration::from_millis(30),
                from_modality: None,
                diag: diag(None, 2),
            })
            .is_empty());
        let committed = coalescer.handle(CoalescerInput::Stop {
            captured_at: base + Duration::from_millis(40),
            signal: EditCommitSignal::Stop,
        });
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            committed[0].diag.edit_commit_signal,
            Some(EditCommitSignal::Stop)
        );
    }

    #[test]
    fn coalescer_merges_repeated_edit_markers_for_same_target() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming::default());
        let mut first_diag = diag(None, 1);
        first_diag.callback_latency_ns = 10;
        first_diag.event_to_selector_complete_ns = 20;
        first_diag.queue_depth_at_enqueue = 1;
        let mut second_diag = diag(None, 2);
        second_diag.callback_latency_ns = 30;
        second_diag.event_to_selector_complete_ns = 40;
        second_diag.queue_depth_at_enqueue = 3;

        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("edit"),
                captured_at: base,
                from_modality: None,
                diag: first_diag,
            })
            .is_empty());
        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("edit"),
                captured_at: base + Duration::from_millis(5),
                from_modality: Some(Modality::Keyboard),
                diag: second_diag,
            })
            .is_empty());

        let committed = coalescer.handle(CoalescerInput::Stop {
            captured_at: base + Duration::from_millis(20),
            signal: EditCommitSignal::Stop,
        });
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            committed[0].payload,
            ActionPayload::EditCommitted {
                from_modality: Some(Modality::Keyboard),
                corroborates: None,
            }
        );
        assert_eq!(committed[0].diag.repeat_count, 2);
        assert_eq!(committed[0].diag.callback_latency_ns, 30);
        assert_eq!(committed[0].diag.event_to_selector_complete_ns, 40);
        assert_eq!(committed[0].diag.queue_depth_at_enqueue, 3);
    }

    #[test]
    fn coalescer_flushes_edit_before_new_marker_and_superseding_action() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming::default());

        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("first_field"),
                captured_at: base,
                from_modality: Some(Modality::Keyboard),
                diag: diag(None, 1),
            })
            .is_empty());
        let first_flush = coalescer.handle(CoalescerInput::EditMarker {
            target: target("second_field"),
            captured_at: base + Duration::from_millis(10),
            from_modality: Some(Modality::Keyboard),
            diag: diag(None, 2),
        });
        assert_eq!(first_flush.len(), 1);
        assert_eq!(first_flush[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            first_flush[0].target.target_key,
            target("first_field").target_key
        );
        assert_eq!(first_flush[0].captured_at, base + Duration::from_millis(10));

        let second_flush = coalescer.handle(CoalescerInput::Action(draft(
            "save_button",
            ActionType::Invoke,
            ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
            base + Duration::from_millis(20),
        )));
        assert_eq!(second_flush.len(), 2);
        assert_eq!(second_flush[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            second_flush[0].target.target_key,
            target("second_field").target_key
        );
        assert_eq!(second_flush[1].action_type, ActionType::Invoke);
    }

    #[test]
    fn coalescer_flushes_scroll_on_target_change_quiet_window_and_stop() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming {
            dedup_window_ms: 500,
            scroll_quiet_ms: 25,
            idle_commit_ms: None,
        });

        assert!(coalescer
            .handle(CoalescerInput::Action(draft(
                "left_pane",
                ActionType::Scroll,
                scroll_payload(ScrollDirection::Down, Some(1)),
                base,
            )))
            .is_empty());
        let target_change = coalescer.handle(CoalescerInput::Action(draft(
            "right_pane",
            ActionType::Scroll,
            scroll_payload(ScrollDirection::Down, Some(1)),
            base + Duration::from_millis(5),
        )));
        assert_eq!(target_change.len(), 1);
        assert_eq!(
            target_change[0].target.target_key,
            target("left_pane").target_key
        );

        assert!(coalescer
            .flush_due(base + Duration::from_millis(20))
            .is_empty());
        let quiet_flush = coalescer.flush_due(base + Duration::from_millis(30));
        assert_eq!(quiet_flush.len(), 1);
        assert_eq!(
            quiet_flush[0].target.target_key,
            target("right_pane").target_key
        );

        assert!(coalescer
            .handle(CoalescerInput::Action(draft(
                "bottom_pane",
                ActionType::Scroll,
                scroll_payload(ScrollDirection::Down, Some(1)),
                base + Duration::from_millis(40),
            )))
            .is_empty());
        let stop_flush = coalescer.handle(CoalescerInput::Stop {
            captured_at: base + Duration::from_millis(45),
            signal: EditCommitSignal::Stop,
        });
        assert_eq!(stop_flush.len(), 1);
        assert_eq!(
            stop_flush[0].target.target_key,
            target("bottom_pane").target_key
        );
    }

    #[test]
    fn coalescer_commit_edit_input_flushes_marker() {
        let base = Instant::now();
        let mut coalescer = ActionCoalescer::new(CoalescerTiming::default());

        assert!(coalescer
            .handle(CoalescerInput::EditMarker {
                target: target("edit"),
                captured_at: base,
                from_modality: None,
                diag: diag(None, 1),
            })
            .is_empty());
        let committed = coalescer.handle(CoalescerInput::CommitEdit {
            captured_at: base + Duration::from_millis(15),
            signal: EditCommitSignal::CompositionFinalized,
        });
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].action_type, ActionType::EditCommitted);
        assert_eq!(
            committed[0].diag.edit_commit_signal,
            Some(EditCommitSignal::CompositionFinalized)
        );
    }

    #[test]
    fn rect_helpers_reject_empty_rects_and_allow_two_pixel_containment_tolerance() {
        let owner = RECT {
            left: 10,
            top: 10,
            right: 100,
            bottom: 100,
        };
        let within_tolerance = RECT {
            left: 8,
            top: 9,
            right: 102,
            bottom: 101,
        };
        let outside_tolerance = RECT {
            left: 7,
            top: 10,
            right: 100,
            bottom: 100,
        };

        assert!(rect_contains_with_tolerance(
            &owner,
            &within_tolerance,
            RECT_CONTAINMENT_TOLERANCE_PX
        ));
        assert!(!rect_contains_with_tolerance(
            &owner,
            &outside_tolerance,
            RECT_CONTAINMENT_TOLERANCE_PX
        ));
        assert!(rect_center(&RECT {
            left: 10,
            top: 10,
            right: 10,
            bottom: 20,
        })
        .is_none());
    }

    #[test]
    fn drain_for_teardown_returns_within_ceiling_on_open_empty_queue() {
        let (_tx, rx) = crossbeam_channel::bounded(1);
        let started = Instant::now();

        drain_for_teardown(
            &rx,
            CoalescerTiming {
                dedup_window_ms: 1,
                scroll_quiet_ms: 1,
                idle_commit_ms: None,
            },
        );

        assert!(started.elapsed() <= TEARDOWN_DRAIN_CEILING + Duration::from_millis(50));
    }
}
