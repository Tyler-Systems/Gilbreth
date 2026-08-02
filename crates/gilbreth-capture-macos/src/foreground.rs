//! Foreground stream at two observation granularities: app-granularity
//! from NSWorkspace alone (no TCC permission), upgraded to focused-window
//! granularity with titles when the AX-gated `Windows` stream is enabled
//! AND Accessibility is granted (the macOS TCC and stream rules,
//! Windows-titles amendment).
//!
//! Vocabulary per schema/README.md's macOS section: `hwnd` carries a
//! synthetic within-session correlator — keyed by pid at app granularity
//! (re-activating a running app correlates; a relaunch gets a fresh id
//! exactly as a new process's HWNDs would), keyed by AX window identity at
//! window granularity, both drawn from ONE shared counter so ids can never
//! collide across granularities. `exe` carries the bundle-executable path.
//! `title` is empty at app granularity and carries the focus-time window
//! title at window granularity — read once per focus transition, exactly
//! as Windows reads `GetWindowTextW` at emission and never re-reads (a
//! mid-segment title change produces no row on either platform). The
//! enriched rows stay `Source::Foreground`: on macOS the `windows` toggle
//! gates enrichment at capture time, the `foreground` toggle gates the
//! rows (recorded stream-gate interplay).
//!
//! The segment state machine is the shared `gilbreth_core::ForegroundState`
//! (hoisted 2026-07-12 per the recorded trigger — after the power, process,
//! and clipboard slices, before the beta; both platforms drive the same
//! emission rules).
//!
//! Reviewed divergences from the Windows calling policy (both adjudicated
//! in the independent slice review):
//!
//! 1. Mid-run user pause (stream toggle / suspension): this source closes
//!    the segment at the transition (the closing row is intentionally
//!    unpersisted — the send gate is already off, and the segment reads
//!    like a crash tail), clears the unfocused timestamps so nothing —
//!    dwell or `window_unfocused_for_ms` — spans or discloses the off
//!    period, and re-seeds fresh at re-enable. Windows keeps tracking
//!    while disabled and over-attributes across the off period after
//!    re-enable; mac is deliberately the more private of the two. A
//!    session block (lock / fast-user-switch, [`PollGate`]) closes the
//!    segment the same way — and its closing row DOES persist, since the
//!    stream setting is still on — but preserves the unfocused
//!    correlations, matching Windows across locks: the block's boundaries
//!    are already persisted session rows, so clearing would lose a metric
//!    without hiding anything. Consequently the post-unlock re-seed of a
//!    recently-focused app carries a `window_unfocused_for_ms` spanning
//!    the block, where Windows' unlock seed hardcodes 0 — mac reports the
//!    more truthful value, within the field's meaning.
//! 2. Missed-boundary cap: Windows caps a missed-boundary segment's dwell
//!    at a fixed 30s because its detection granularity is that coarse; this
//!    poller observes at the 50ms service cadence, so it caps at the
//!    last-observed tick — the same "attribute only what was observed"
//!    rule at finer granularity, yielding more truthful (not identical)
//!    values on this rare path.
//!
//! Within-session maps (`synthetic_ids`, `window_ids`, `last_unfocused_at`)
//! grow one small entry per distinct frontmost app / focused window per
//! run; pruning arrives with the NSWorkspace termination observers in a
//! later slice (recorded follow-up, which also covers the AX app-element
//! cache in `ax.rs`).

use std::{collections::HashMap, time::Duration, time::Instant};

use gilbreth_core::{Captured, ForegroundState, WindowRef};
use tracing::{info, warn};

/// Same boundary threshold the Windows pump uses for a missed power
/// boundary (`MISSED_POWER_BOUNDARY_THRESHOLD_MS`): a service-tick gap this
/// large means observation stopped, and dwell must cap at the last observed
/// tick rather than absorbing the gap. Clock reality on macOS (verified in
/// the Idle/System review): `Instant` is uptime-based and does not advance
/// during machine sleep, so sleeps self-exclude from dwell automatically
/// and this gap arises from process stalls/starvation — rarer than on
/// Windows, whose tick clock genuinely spans suspend. The cap is
/// conservative and correct in both clock worlds (including any future
/// std clock change).
const MISSED_BOUNDARY_THRESHOLD: Duration = Duration::from_secs(30);

/// The frontmost application as the provider reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrontmostApp {
    pub(crate) pid: i32,
    pub(crate) exe: String,
}

/// AX focused-window probes run on this cadence while the frontmost app is
/// unchanged (immediately on app change or re-seed) — the sub-second
/// aggregate cadence the TCC record already uses for moves/precise scroll.
/// Bounds the synchronous AX IPC to ~4 probes/s steady state (each probe
/// is up to two round-trips — focused window, then title — so ≤8
/// round-trips/s; review-corrected count).
pub(crate) const WINDOW_PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// One focused-window probe result from the AX provider.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum WindowProbe<K> {
    /// The app's focused window and its title (title read here is the
    /// focus-time read; the poller discards it unemitted when the window
    /// hasn't changed, keeping emitted rows Windows-identical).
    Window { key: K, title: String },
    /// The app legitimately has no focused window (or no AX support at
    /// all): attribute at app granularity — a stable state, not an error.
    NoFocusedWindow,
    /// Transient failure (messaging timeout, stale element): blackout
    /// within the same app, app-granular attribution across an app switch.
    Failed,
    /// `kAXErrorAPIDisabled`: Accessibility was revoked. Handled like
    /// [`WindowProbe::Failed`] for attribution, and surfaced in
    /// [`PollReport`] so the pump degrades the stream.
    ApiDisabled,
}

/// Out-of-band signals from a foreground pass (the events themselves go to
/// the `events` vec).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PollReport {
    /// An AX read returned `kAXErrorAPIDisabled` this pass.
    pub(crate) ax_api_disabled: bool,
}

/// While the Windows stream is wanted but Accessibility is not granted,
/// re-probe trust on this cadence so a grant made in System Settings is
/// noticed without any restart (the TCC record's "slow re-probe").
pub(crate) const TRUST_REPROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Pump-side trust state for the AX-gated Windows stream. Probing policy
/// (TCC record, Windows-titles amendment): probe on stream-enable edges;
/// while wanted-but-untrusted, re-probe every [`TRUST_REPROBE_INTERVAL`];
/// while trusted, never probe — revocation arrives as `kAXErrorAPIDisabled`
/// from the reads themselves via [`WindowsStreamTrust::on_api_disabled`].
/// Transitions are edge-logged and content-free; the pump never prompts.
pub(crate) struct WindowsStreamTrust {
    trusted: bool,
    wanted_last: bool,
    last_probe: Option<Instant>,
}

impl WindowsStreamTrust {
    pub(crate) fn new() -> Self {
        Self {
            trusted: false,
            wanted_last: false,
            last_probe: None,
        }
    }

    /// One pass: `wanted` is the caller's `settings().windows &&
    /// !is_suspended()` snapshot; returns whether the AX-gated stream is
    /// live this pass.
    pub(crate) fn refresh(
        &mut self,
        now: Instant,
        wanted: bool,
        probe: &mut impl FnMut() -> bool,
    ) -> bool {
        if !wanted {
            self.wanted_last = false;
            return false;
        }
        let enable_edge = !self.wanted_last;
        self.wanted_last = true;

        let reprobe_due = !self.trusted
            && self
                .last_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= TRUST_REPROBE_INTERVAL);
        if enable_edge || reprobe_due {
            self.last_probe = Some(now);
            let trusted = probe();
            // Log on every state change AND on every explicit enable edge:
            // a user action deserves an answer in the log even when the
            // answer is unchanged. Bounded by user actions + transitions.
            if trusted != self.trusted || enable_edge {
                log_trust_state(trusted);
            }
            self.trusted = trusted;
        }
        self.trusted
    }

    /// An AX read returned `kAXErrorAPIDisabled`: revoked mid-run. Degrade
    /// now; the re-probe cadence notices a re-grant.
    pub(crate) fn on_api_disabled(&mut self, now: Instant) {
        if self.trusted {
            warn!(
                "window titles degraded to app granularity: Accessibility was revoked mid-run \
                 (re-probing for a re-grant every {}s)",
                TRUST_REPROBE_INTERVAL.as_secs()
            );
        }
        self.trusted = false;
        self.last_probe = Some(now);
    }
}

fn log_trust_state(trusted: bool) {
    if trusted {
        info!("window-titles stream active: Accessibility is granted");
    } else {
        info!(
            "window titles off (declared): Accessibility is not granted — enable in \
             System Settings > Privacy & Security > Accessibility; capture continues at \
             app granularity and re-probes every {}s",
            TRUST_REPROBE_INTERVAL.as_secs()
        );
    }
}

/// How a foreground pass is gated. The two disabled variants close the
/// open segment identically but treat correlation state differently:
///
/// - [`PollGate::PausedByUser`] is a privacy pause (stream toggle off or
///   capture suspension): the unfocused timestamps are also forgotten so
///   the off period leaves no measurable trace.
/// - [`PollGate::BlockedBySession`] is a lock or fast-user-switch: dwell
///   must not accumulate, but correlations persist — the block's
///   boundaries are already persisted as `session_lock`/`session_unlock`
///   rows (nothing to hide), and Windows keeps unfocused tracking across
///   locks (Idle/System review, finding 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollGate {
    Enabled,
    PausedByUser,
    BlockedBySession,
}

/// Polls the frontmost application on the pump's service cadence and feeds
/// the segment state machine, upgrading to focused-window granularity when
/// the caller passes `windows: true` (Windows stream on + Accessibility
/// granted). Generic over both providers so tests inject app and window
/// sequences without touching AppKit or the AX API.
pub(crate) struct ForegroundPoller<P, W, K> {
    provider: P,
    window_provider: W,
    state: ForegroundState,
    synthetic_ids: HashMap<i32, u64>,
    /// `(pid, window key, synthetic id)` — window identity is provider
    /// equality (CFEqual in production), looked up by linear scan; probes
    /// resolve ids only on focus transitions and cadence ticks, and the
    /// entry count is "distinct focused windows this run".
    window_ids: Vec<(i32, K, u64)>,
    /// One counter feeds BOTH id maps (the recorded allocator-sharing
    /// follow-up): app-granular and window-granular ids can never collide.
    next_synthetic_id: u64,
    last_poll: Option<Instant>,
    last_window_probe: Option<Instant>,
    last_gate: PollGate,
}

impl<P, W, K> ForegroundPoller<P, W, K>
where
    P: FnMut() -> Option<FrontmostApp>,
    W: FnMut(i32) -> WindowProbe<K>,
    K: PartialEq + Clone,
{
    pub(crate) fn new(provider: P, window_provider: W) -> Self {
        Self {
            provider,
            window_provider,
            state: ForegroundState::default(),
            synthetic_ids: HashMap::new(),
            window_ids: Vec::new(),
            // Synthetic ids start at 1: 0 reads as "no window" in too many
            // debugging contexts to hand it to a real row.
            next_synthetic_id: 1,
            last_poll: None,
            last_window_probe: None,
            last_gate: PollGate::PausedByUser,
        }
    }

    /// One service-cadence pass. The gate composes the caller's snapshot of
    /// `settings().foreground && !is_suspended()` with the session-block
    /// state; `windows` is the caller's `settings().windows && trusted`
    /// snapshot (enrichment gate — see the module doc). The send path
    /// re-checks `enabled_for` as defense-in-depth, same as the Windows
    /// sources.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        gate: PollGate,
        windows: bool,
        events: &mut Vec<Captured>,
    ) -> PollReport {
        let mut report = PollReport::default();
        if gate != PollGate::Enabled {
            if self.last_gate == PollGate::Enabled {
                // A pass after a long observation gap can arrive already
                // gated (e.g. a stalled pump resuming into a locked
                // session), so the gap cap must apply on this close too —
                // an uncapped close here PERSISTS an over-attributed row
                // (verify-round blocker, demonstrated by execution; note
                // that on macOS `Instant` excludes sleep, so the everyday
                // trigger is a stall, not a lid-close — the cap holds in
                // both clock worlds).
                events.extend(self.end_current_gap_capped_at(now));
            }
            if gate == PollGate::PausedByUser && self.last_gate != PollGate::PausedByUser {
                // Privacy: the boundary close stamps last_unfocused_at, and
                // a re-seed after re-enable would read it back as
                // window_unfocused_for_ms spanning the whole off period —
                // disclosing exactly when capture was paused. Forget the
                // timestamps; the pause leaves no measurable trace. (A
                // session block deliberately does NOT clear — see PollGate.)
                self.state.clear_unfocused_correlations();
            }
            self.last_gate = gate;
            self.last_poll = Some(now);
            return report;
        }
        self.last_gate = PollGate::Enabled;

        // Sleep/stall boundary: cap the open segment's dwell at the last
        // observed tick, then fall through and re-seed from the current
        // frontmost app.
        if self.gap_exceeds_boundary(now) {
            events.extend(self.end_current_gap_capped_at(now));
        }

        if let Some(app) = (self.provider)() {
            if let Some(window) = self.resolve_window_ref(now, &app, windows, &mut report) {
                events.extend(self.state.on_window_at(window, now));
            }
        }

        self.last_poll = Some(now);
        report
    }

    /// Decide what this pass feeds the state machine: an app-granular ref,
    /// a window-granular ref, or nothing (probe not due / blackout).
    fn resolve_window_ref(
        &mut self,
        now: Instant,
        app: &FrontmostApp,
        windows: bool,
        report: &mut PollReport,
    ) -> Option<WindowRef> {
        if !windows {
            // Reset the probe cadence so a re-enabled stream probes
            // immediately instead of waiting out a stale interval.
            self.last_window_probe = None;
            return Some(self.app_granular_ref(app));
        }

        let app_pid = u32::try_from(app.pid).unwrap_or(0);
        let current_pid = self.state.current_window().map(|window| window.pid);
        // Probe immediately on an app switch or re-seed; otherwise on the
        // AX cadence (bounds the synchronous IPC — TCC record amendment).
        let probe_due = current_pid != Some(app_pid)
            || self
                .last_window_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= WINDOW_PROBE_INTERVAL);
        if !probe_due {
            return None;
        }
        self.last_window_probe = Some(now);

        match (self.window_provider)(app.pid) {
            WindowProbe::Window { key, title } => {
                let hwnd = self.window_id(app.pid, &key);
                Some(WindowRef {
                    hwnd,
                    exe: app.exe.clone(),
                    title,
                    pid: app_pid,
                })
            }
            WindowProbe::NoFocusedWindow => Some(self.app_granular_ref(app)),
            WindowProbe::Failed => self.degraded_ref(app, current_pid),
            WindowProbe::ApiDisabled => {
                report.ax_api_disabled = true;
                self.degraded_ref(app, current_pid)
            }
        }
    }

    /// A failed probe: within the same app, keep the open segment (the
    /// provider-blackout rule — fabricate nothing, retry on cadence);
    /// across an app switch or with no open segment, attribute at app
    /// granularity now — the switch itself was observed even if the window
    /// wasn't.
    fn degraded_ref(&mut self, app: &FrontmostApp, current_pid: Option<u32>) -> Option<WindowRef> {
        if current_pid == Some(u32::try_from(app.pid).unwrap_or(0)) {
            None
        } else {
            Some(self.app_granular_ref(app))
        }
    }

    fn app_granular_ref(&mut self, app: &FrontmostApp) -> WindowRef {
        let synthetic_id = *self.synthetic_ids.entry(app.pid).or_insert_with(|| {
            let id = self.next_synthetic_id;
            self.next_synthetic_id += 1;
            id
        });
        WindowRef {
            hwnd: synthetic_id,
            exe: app.exe.clone(),
            title: String::new(),
            pid: u32::try_from(app.pid).unwrap_or(0),
        }
    }

    fn window_id(&mut self, pid: i32, key: &K) -> u64 {
        if let Some((_, _, id)) = self
            .window_ids
            .iter()
            .find(|(cached_pid, cached_key, _)| *cached_pid == pid && cached_key == key)
        {
            return *id;
        }
        let id = self.next_synthetic_id;
        self.next_synthetic_id += 1;
        self.window_ids.push((pid, key.clone(), id));
        id
    }

    /// True when a service gap large enough to be a sleep/stall boundary
    /// separates `now` from the last poll while a segment is open.
    fn gap_exceeds_boundary(&self, now: Instant) -> bool {
        self.state.current_focused_at().is_some()
            && self.last_poll.is_some_and(|last_poll| {
                now.saturating_duration_since(last_poll) > MISSED_BOUNDARY_THRESHOLD
            })
    }

    /// Close the open segment; when a sleep/stall gap intervened, cap the
    /// attributed dwell at the last observed tick (attribute only what was
    /// observed — the rule must hold on EVERY close path that can follow a
    /// gap, not just the Enabled one).
    fn end_current_gap_capped_at(&mut self, now: Instant) -> Option<Captured> {
        let cap = match (self.last_poll, self.state.current_focused_at()) {
            (Some(last_poll), Some(focused_at))
                if now.saturating_duration_since(last_poll) > MISSED_BOUNDARY_THRESHOLD =>
            {
                Some(last_poll.saturating_duration_since(focused_at))
            }
            _ => None,
        };
        self.state.end_current_at_with_duration_limit(now, cap)
    }

    /// Pump shutdown AND power boundaries: close the open segment so the
    /// final dwell is attributed (the Windows pump ends the segment at
    /// suspend and at shutdown the same way). The gap cap applies here too
    /// — for a suspend that is what caps any process-stall gap, and sleep
    /// itself contributes no dwell on macOS (uptime clock); the next poll
    /// pass reseeds the fresh segment.
    pub(crate) fn flush_at(&mut self, now: Instant, events: &mut Vec<Captured>) {
        events.extend(self.end_current_gap_capped_at(now));
    }

    /// The currently-focused window, for attributing keyboard/mouse events
    /// this pass (the frontmost window, Windows parity — not the window
    /// under the cursor). `None` when no segment is open (unfocused / gated).
    pub(crate) fn current_window(&self) -> Option<WindowRef> {
        self.state.current_window().cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use gilbreth_core::{EventPayload, Source};

    use super::*;

    fn app(pid: i32, exe: &str) -> Option<FrontmostApp> {
        Some(FrontmostApp {
            pid,
            exe: exe.to_string(),
        })
    }

    struct Script {
        frontmost: Rc<RefCell<Option<FrontmostApp>>>,
    }

    fn scripted() -> (Script, impl FnMut() -> Option<FrontmostApp>) {
        let frontmost = Rc::new(RefCell::new(None));
        let provider_view = frontmost.clone();
        (Script { frontmost }, move || provider_view.borrow().clone())
    }

    /// Window provider for app-granularity tests (`windows: false`): the
    /// poller must never touch the AX provider while the gate is off — a
    /// call here IS the regression.
    fn no_windows() -> impl FnMut(i32) -> WindowProbe<u32> {
        |_| panic!("window provider must not be called with the windows gate off")
    }

    struct WindowScript {
        probe: Rc<RefCell<WindowProbe<u32>>>,
        calls: Rc<Cell<u32>>,
    }

    fn scripted_windows() -> (WindowScript, impl FnMut(i32) -> WindowProbe<u32>) {
        let probe = Rc::new(RefCell::new(WindowProbe::NoFocusedWindow));
        let calls = Rc::new(Cell::new(0));
        let probe_view = probe.clone();
        let calls_view = calls.clone();
        (WindowScript { probe, calls }, move |_pid| {
            calls_view.set(calls_view.get() + 1);
            probe_view.borrow().clone()
        })
    }

    fn window(key: u32, title: &str) -> WindowProbe<u32> {
        WindowProbe::Window {
            key,
            title: title.to_string(),
        }
    }

    fn expect_focus_changed(captured: &Captured) -> (&WindowRef, Option<&WindowRef>, u64, u64) {
        match &captured.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => (
                window,
                prev.as_ref(),
                *previous_focused_for_ms,
                *window_unfocused_for_ms,
            ),
            other => panic!("expected FocusChanged, got {other:?}"),
        }
    }

    #[test]
    fn first_poll_seeds_the_frontmost_app_with_a_synthetic_id_and_empty_title() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/Applications/Safari.app/Contents/MacOS/Safari");
        poller.poll(base, PollGate::Enabled, false, &mut events);

        assert_eq!(events.len(), 1);
        let (window, prev, prev_ms, unfocused_ms) = expect_focus_changed(&events[0]);
        assert_eq!(window.hwnd, 1, "synthetic ids start at 1");
        assert_eq!(window.exe, "/Applications/Safari.app/Contents/MacOS/Safari");
        assert_eq!(window.title, "", "titles are the AX stream's data");
        assert_eq!(window.pid, 400);
        assert!(prev.is_none());
        assert_eq!((prev_ms, unfocused_ms), (0, 0));
        assert!(matches!(events[0].source, Source::Foreground));
    }

    #[test]
    fn app_switch_attributes_dwell_and_return_correlates_by_pid() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        // Same app again: no event.
        poller.poll(
            base + Duration::from_millis(50),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 1);

        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        poller.poll(
            base + Duration::from_millis(2_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window.hwnd, 2);
        assert_eq!(prev.expect("previous window").hwnd, 1);
        assert_eq!(prev_ms, 2_000, "dwell on A attributed at the switch");

        // Back to A: the pid-keyed synthetic id correlates, and the
        // unfocused interval is tracked.
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(
            base + Duration::from_millis(3_500),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (window, prev, _, unfocused_ms) = expect_focus_changed(&events[2]);
        assert_eq!(window.hwnd, 1, "same running app keeps its correlator");
        assert_eq!(prev.expect("previous window").hwnd, 2);
        assert_eq!(unfocused_ms, 1_500);
    }

    #[test]
    fn disable_closes_the_segment_and_reenable_reseeds_without_off_time_dwell() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);

        // Disable transition: boundary row closes the segment with the same
        // window on both sides and the dwell so far.
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::PausedByUser,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window.hwnd, prev.expect("boundary reuses the window").hwnd);
        assert_eq!(prev_ms, 1_000);

        // Disabled passes emit nothing and accumulate nothing.
        poller.poll(
            base + Duration::from_millis(60_000),
            PollGate::PausedByUser,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 2);

        // Re-enable re-seeds from now: neither dwell nor the unfocused
        // interval may span (or disclose the length of) the disabled period.
        poller.poll(
            base + Duration::from_millis(61_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (window, prev, prev_ms, unfocused_ms) = expect_focus_changed(&events[2]);
        assert_eq!(window.hwnd, 1);
        assert!(prev.is_none(), "re-seed, not a switch");
        assert_eq!(prev_ms, 0);
        assert_eq!(
            unfocused_ms, 0,
            "the off period must leave no measurable trace"
        );
    }

    #[test]
    fn a_session_block_preserves_unfocused_correlations_unlike_a_pause() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        // A focused, then B (A gets its unfocused timestamp at 1s).
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            false,
            &mut events,
        );

        // Lock for four seconds: the block closes B's segment (row persists
        // via the still-on send gate) but must NOT forget A's timestamp.
        poller.poll(
            base + Duration::from_millis(2_000),
            PollGate::BlockedBySession,
            false,
            &mut events,
        );
        let after_block = events.len();

        // Unlock and return to A: window_unfocused_for_ms spans switch-away
        // through the lock to the refocus — Windows parity across locks.
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(
            base + Duration::from_millis(6_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), after_block + 1);
        let (window, prev, _, unfocused_ms) = expect_focus_changed(&events[after_block]);
        assert_eq!(window.hwnd, 1, "A keeps its correlator across the block");
        assert!(prev.is_none(), "post-block re-seed");
        assert_eq!(
            unfocused_ms, 5_000,
            "unfocused span survives the block (1s -> 6s)"
        );
    }

    #[test]
    fn wake_into_a_locked_session_caps_dwell_at_the_last_observed_tick() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        // Work in A for five observed seconds, then the lid closes;
        // "require password after sleep" means the wake pass arrives
        // already BlockedBySession, eight hours later.
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        poller.poll(
            base + Duration::from_secs(5),
            PollGate::Enabled,
            false,
            &mut events,
        );
        poller.poll(
            base + Duration::from_secs(8 * 3600 + 5),
            PollGate::BlockedBySession,
            false,
            &mut events,
        );

        assert_eq!(events.len(), 2);
        let (_, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert!(prev.is_some(), "boundary row closes the segment");
        assert_eq!(
            prev_ms, 5_000,
            "the persisted lock-boundary row attributes only the observed \
             five seconds, never the sleep (verify-round blocker)"
        );
    }

    #[test]
    fn a_service_gap_caps_dwell_at_the_last_observed_tick() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        poller.poll(
            base + Duration::from_millis(5_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 1);

        // The machine "slept" for two minutes: the boundary row must
        // attribute only the five observed seconds, then re-seed.
        poller.poll(
            base + Duration::from_millis(125_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (_, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert!(prev.is_some());
        assert_eq!(prev_ms, 5_000, "dwell capped at the last observed tick");
        let (window, prev, _, _) = expect_focus_changed(&events[2]);
        assert_eq!(window.hwnd, 1);
        assert!(prev.is_none(), "post-boundary re-seed");
    }

    #[test]
    fn an_app_relaunch_gets_a_fresh_synthetic_id() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        *script.frontmost.borrow_mut() = app(900, "/A.app/Contents/MacOS/A");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            false,
            &mut events,
        );

        assert_eq!(events.len(), 2);
        let (window, prev, _, _) = expect_focus_changed(&events[1]);
        assert_eq!(
            window.hwnd, 2,
            "new pid, new correlator — like a new process's HWNDs"
        );
        assert_eq!(window.pid, 900);
        assert_eq!(prev.expect("previous").hwnd, 1);
    }

    #[test]
    fn shutdown_flush_attributes_the_final_dwell() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        poller.flush_at(base + Duration::from_millis(4_000), &mut events);

        assert_eq!(events.len(), 2);
        let (window, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window.hwnd, prev.expect("boundary window").hwnd);
        assert_eq!(prev_ms, 4_000);
    }

    #[test]
    fn a_provider_blackout_keeps_the_segment_open() {
        let (script, provider) = scripted();
        let mut poller = ForegroundPoller::new(provider, no_windows());
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        *script.frontmost.borrow_mut() = None;
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 1, "transient None is not a focus change");

        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        poller.poll(
            base + Duration::from_millis(2_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        let (_, _, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(
            prev_ms, 2_000,
            "dwell spans the blackout to the real switch"
        );
    }

    // ---- Windows-titles enrichment (AX-gated `Windows` stream) ----

    #[test]
    fn windows_stream_seeds_window_granular_rows_with_titles() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Quarterly Plan");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        assert_eq!(events.len(), 1);
        let (window_ref, prev, _, _) = expect_focus_changed(&events[0]);
        assert_eq!(window_ref.hwnd, 1, "window id from the shared allocator");
        assert_eq!(window_ref.title, "Quarterly Plan");
        assert_eq!(window_ref.exe, "/A.app/Contents/MacOS/A");
        assert_eq!(window_ref.pid, 400);
        assert!(prev.is_none());
        assert!(matches!(events[0].source, Source::Foreground));
    }

    #[test]
    fn within_app_window_switch_attributes_dwell_and_correlates_on_return() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc A");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        // Same app, new focused window: a per-window segment boundary.
        *windows.probe.borrow_mut() = window(11, "Doc B");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window_ref, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window_ref.hwnd, 2);
        assert_eq!(window_ref.title, "Doc B");
        assert_eq!(prev.expect("previous window").hwnd, 1);
        assert_eq!(prev_ms, 1_000, "dwell attributed per window, not per app");

        // Back to the first window: identity correlates and the unfocused
        // interval is measured — tab/document-level continuity.
        *windows.probe.borrow_mut() = window(10, "Doc A");
        poller.poll(
            base + Duration::from_millis(3_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (window_ref, prev, _, unfocused_ms) = expect_focus_changed(&events[2]);
        assert_eq!(window_ref.hwnd, 1, "same window keeps its correlator");
        assert_eq!(prev.expect("previous window").hwnd, 2);
        assert_eq!(unfocused_ms, 2_000);
    }

    #[test]
    fn a_title_change_on_the_same_window_emits_nothing() {
        // Windows parity: GetWindowTextW is read at FocusChanged emission
        // and never re-read — a mid-segment retitle produces no row there,
        // so it must produce none here (TCC record amendment).
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Draft — v1");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        *windows.probe.borrow_mut() = window(10, "Draft — v2");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 1, "same window, new title: no row");

        // The stored title for the open segment remains the focus-time
        // read; the boundary row proves it.
        poller.flush_at(base + Duration::from_millis(2_000), &mut events);
        let (window_ref, _, _, _) = expect_focus_changed(&events[1]);
        assert_eq!(window_ref.title, "Draft — v1");
    }

    #[test]
    fn no_focused_window_attributes_at_app_granularity_and_upgrades_later() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        // App with no focused window (or no AX support): app-granular row,
        // empty title — the stable honest shape, not an error.
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, true, &mut events);
        assert_eq!(events.len(), 1);
        let (window_ref, _, _, _) = expect_focus_changed(&events[0]);
        assert_eq!(window_ref.hwnd, 1, "app-granular id");
        assert_eq!(window_ref.title, "");

        // A window appears: upgrade is an ordinary focus transition.
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window_ref, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window_ref.hwnd, 2, "window id from the same allocator");
        assert_eq!(window_ref.title, "Doc");
        assert_eq!(prev.expect("app-granular segment closed").hwnd, 1);
        assert_eq!(prev_ms, 1_000);
    }

    #[test]
    fn a_transient_ax_failure_within_the_same_app_keeps_the_segment_open() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        // Messaging timeouts on the cadence: blackout — fabricate nothing.
        *windows.probe.borrow_mut() = WindowProbe::Failed;
        for ms in [300u64, 600, 900] {
            poller.poll(
                base + Duration::from_millis(ms),
                PollGate::Enabled,
                true,
                &mut events,
            );
        }
        assert_eq!(events.len(), 1, "failures within the app emit nothing");

        // Recovery lands on the same window: still no fabricated row, and
        // dwell spans the blackout (it was the same window throughout).
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(
            base + Duration::from_millis(1_200),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 1);
        poller.flush_at(base + Duration::from_millis(2_000), &mut events);
        let (_, _, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(prev_ms, 2_000, "dwell continuous across the blackout");
    }

    #[test]
    fn an_ax_failure_across_an_app_switch_degrades_to_app_granularity() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc A");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        // The switch to B was observed even though B's window wasn't:
        // attribute at app granularity NOW rather than losing the switch.
        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        *windows.probe.borrow_mut() = WindowProbe::Failed;
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window_ref, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window_ref.pid, 500);
        assert_eq!(window_ref.title, "", "degraded shape: app-granular");
        assert_eq!(prev.expect("A's window segment closed").hwnd, 1);
        assert_eq!(prev_ms, 1_000);

        // The next cadence probe upgrades to window granularity.
        *windows.probe.borrow_mut() = window(20, "Doc B");
        poller.poll(
            base + Duration::from_millis(1_300),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (window_ref, _, _, _) = expect_focus_changed(&events[2]);
        assert_eq!(window_ref.title, "Doc B");
    }

    #[test]
    fn api_disabled_reports_to_the_pump_and_follows_the_failure_rules() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc");
        let report = poller.poll(base, PollGate::Enabled, true, &mut events);
        assert!(!report.ax_api_disabled);

        // Same app: the revocation is reported, attribution blacks out.
        *windows.probe.borrow_mut() = WindowProbe::ApiDisabled;
        let report = poller.poll(
            base + Duration::from_millis(300),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert!(report.ax_api_disabled, "revocation surfaces to the pump");
        assert_eq!(events.len(), 1, "no fabricated row on the same app");

        // Across a switch: reported AND the switch is still attributed.
        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        let report = poller.poll(
            base + Duration::from_millis(600),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert!(report.ax_api_disabled);
        assert_eq!(events.len(), 2);
        let (window_ref, _, _, _) = expect_focus_changed(&events[1]);
        assert_eq!((window_ref.pid, window_ref.title.as_str()), (500, ""));
    }

    #[test]
    fn toggling_windows_off_mid_segment_transitions_with_correlations_kept() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(base, PollGate::Enabled, true, &mut events);

        // Enrichment off (user toggle or trust loss): an honest
        // observation-granularity boundary — window segment closes,
        // app-granular segment opens.
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        let (window_ref, prev, prev_ms, _) = expect_focus_changed(&events[1]);
        assert_eq!(window_ref.title, "");
        assert_eq!(window_ref.hwnd, 2, "app id from the same allocator");
        assert_eq!(prev.expect("window segment closed").hwnd, 1);
        assert_eq!(prev_ms, 1_000);

        // Enrichment back on: the window's id correlates across the gap
        // (its unfocused span was stamped at the granularity boundary).
        poller.poll(
            base + Duration::from_millis(3_000),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 3);
        let (window_ref, prev, _, unfocused_ms) = expect_focus_changed(&events[2]);
        assert_eq!(window_ref.hwnd, 1, "window keeps its correlator");
        assert_eq!(prev.expect("app segment closed").hwnd, 2);
        assert_eq!(unfocused_ms, 2_000);
    }

    #[test]
    fn ax_probes_throttle_to_the_cadence_within_an_app() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(base, PollGate::Enabled, true, &mut events);
        assert_eq!(windows.calls.get(), 1, "seed probes immediately");

        // Service ticks inside the cadence window must not touch AX (the
        // IPC bound from the TCC record amendment).
        for ms in [50u64, 100, 150, 200] {
            poller.poll(
                base + Duration::from_millis(ms),
                PollGate::Enabled,
                true,
                &mut events,
            );
        }
        assert_eq!(windows.calls.get(), 1, "no probe inside 250ms");

        poller.poll(
            base + Duration::from_millis(250),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(windows.calls.get(), 2, "cadence probe at 250ms");
        assert_eq!(events.len(), 1, "same window: cadence probe emits nothing");

        // An app switch probes immediately regardless of cadence.
        *script.frontmost.borrow_mut() = app(500, "/B.app/Contents/MacOS/B");
        *windows.probe.borrow_mut() = window(20, "Other");
        poller.poll(
            base + Duration::from_millis(260),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(windows.calls.get(), 3, "app switch probes immediately");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn window_and_app_ids_share_one_allocator() {
        let (script, provider) = scripted();
        let (windows, window_provider) = scripted_windows();
        let mut poller = ForegroundPoller::new(provider, window_provider);
        let base = Instant::now();
        let mut events = Vec::new();

        // App-granular id first (enrichment off), then a window id: one
        // counter serves both — the recorded follow-up's collision
        // guarantee, asserted end to end.
        *script.frontmost.borrow_mut() = app(400, "/A.app/Contents/MacOS/A");
        poller.poll(base, PollGate::Enabled, false, &mut events);
        *windows.probe.borrow_mut() = window(10, "Doc");
        poller.poll(
            base + Duration::from_millis(1_000),
            PollGate::Enabled,
            true,
            &mut events,
        );

        assert_eq!(events.len(), 2);
        let (first, _, _, _) = expect_focus_changed(&events[0]);
        let (second, _, _, _) = expect_focus_changed(&events[1]);
        assert_eq!(first.hwnd, 1, "app id");
        assert_eq!(second.hwnd, 2, "window id continues the same sequence");
    }

    // ---- WindowsStreamTrust (pump-side trust lifecycle) ----

    struct TrustProbe {
        result: Rc<Cell<bool>>,
        calls: Rc<Cell<u32>>,
    }

    fn trust_probe(initial: bool) -> (TrustProbe, impl FnMut() -> bool) {
        let result = Rc::new(Cell::new(initial));
        let calls = Rc::new(Cell::new(0));
        let result_view = result.clone();
        let calls_view = calls.clone();
        (TrustProbe { result, calls }, move || {
            calls_view.set(calls_view.get() + 1);
            result_view.get()
        })
    }

    #[test]
    fn trust_probes_on_the_enable_edge_and_never_while_trusted() {
        let (probe, mut probe_fn) = trust_probe(true);
        let mut trust = WindowsStreamTrust::new();
        let base = Instant::now();

        assert!(trust.refresh(base, true, &mut probe_fn));
        assert_eq!(probe.calls.get(), 1, "enable edge probes");

        // Trusted steady state: revocation arrives as ApiDisabled from the
        // reads themselves, so no polling of the trust API.
        assert!(trust.refresh(base + Duration::from_secs(120), true, &mut probe_fn));
        assert_eq!(probe.calls.get(), 1, "no re-probe while trusted");
    }

    #[test]
    fn untrusted_reprobe_notices_a_grant_on_the_cadence() {
        let (probe, mut probe_fn) = trust_probe(false);
        let mut trust = WindowsStreamTrust::new();
        let base = Instant::now();

        assert!(!trust.refresh(base, true, &mut probe_fn));
        assert!(!trust.refresh(base + Duration::from_secs(10), true, &mut probe_fn));
        assert_eq!(probe.calls.get(), 1, "cadence not due at 10s");

        probe.result.set(true);
        assert!(
            !trust.refresh(base + Duration::from_secs(29), true, &mut probe_fn),
            "grant not yet noticed before the cadence"
        );
        assert!(
            trust.refresh(base + Duration::from_secs(30), true, &mut probe_fn),
            "grant noticed at the 30s re-probe"
        );
        assert_eq!(probe.calls.get(), 2);
    }

    #[test]
    fn api_disabled_degrades_and_the_reprobe_notices_a_regrant() {
        let (probe, mut probe_fn) = trust_probe(true);
        let mut trust = WindowsStreamTrust::new();
        let base = Instant::now();

        assert!(trust.refresh(base, true, &mut probe_fn));

        trust.on_api_disabled(base + Duration::from_secs(5));
        assert!(
            !trust.refresh(base + Duration::from_secs(6), true, &mut probe_fn),
            "degraded immediately after revocation"
        );
        assert_eq!(probe.calls.get(), 1, "revocation restarts the cadence");

        assert!(
            trust.refresh(base + Duration::from_secs(35), true, &mut probe_fn),
            "re-grant noticed on the next cadence probe"
        );
        assert_eq!(probe.calls.get(), 2);
    }

    #[test]
    fn a_reenable_edge_probes_again_even_inside_the_cadence() {
        let (probe, mut probe_fn) = trust_probe(false);
        let mut trust = WindowsStreamTrust::new();
        let base = Instant::now();

        assert!(!trust.refresh(base, true, &mut probe_fn));
        assert!(!trust.refresh(base + Duration::from_secs(1), false, &mut probe_fn));
        assert_eq!(probe.calls.get(), 1, "wanted-off never probes");

        // The user toggling the stream back on is an explicit action and
        // gets an immediate answer, cadence or not.
        probe.result.set(true);
        assert!(trust.refresh(base + Duration::from_secs(2), true, &mut probe_fn));
        assert_eq!(probe.calls.get(), 2, "re-enable edge probes immediately");
    }
}
