//! Foreground stream (LIN-1): window-granular focus segments with titles
//! from EWMH — `_NET_ACTIVE_WINDOW` on the root window, read through the
//! injected provider. Event-driven like the Windows WinEvent hook: the pump
//! marks the monitor dirty when a root `PropertyNotify` names the active
//! window, and a slow recheck cadence catches anything a window manager
//! forgets to announce. The segment state machine is the shared
//! `gilbreth_core::ForegroundState`, so the emission rules — dwell
//! attributed to `prev_*`, `window_unfocused_for_ms` correlation, boundary
//! closes — are the cross-platform contract verbatim.
//!
//! Vocabulary per the schema: `hwnd` carries the X window id (a real
//! server-issued identity token, compared by equality exactly like a Win32
//! HWND), `exe` the `/proc` executable path, `title` the focus-time
//! `_NET_WM_NAME` read — captured at the transition and never re-read, so a
//! mid-segment title change produces no row on any platform. Titles ride
//! the Foreground stream whenever it is on (the Windows posture: X11 gates
//! nothing behind a permission, so there is no grant for a `windows` toggle
//! to compose with; the capability matrix records the choice).
//!
//! The macOS calling-policy divergences are inherited deliberately:
//! a user pause closes the segment (unpersisted — the send gate is already
//! off), clears the unfocused correlations so the off period leaves no
//! measurable trace, and re-seeds fresh at re-enable; a service gap past
//! the missed-boundary threshold caps dwell at the last observed tick
//! (Linux `Instant` is `CLOCK_MONOTONIC`, which excludes suspend, so like
//! macOS the everyday trigger is a stall, not a lid-close).

use std::time::{Duration, Instant};

use gilbreth_core::{Captured, ForegroundState, WindowRef};

/// Same boundary threshold the Windows and macOS pumps use: a service-tick
/// gap this large means observation stopped, and dwell must cap at the last
/// observed tick rather than absorbing the gap.
const MISSED_BOUNDARY_THRESHOLD: Duration = Duration::from_secs(30);

/// Fallback provider-read cadence while no `PropertyNotify` marks the
/// monitor dirty: a safety net for a window manager that misses an update,
/// at one round-trip batch per second.
pub(crate) const ACTIVE_WINDOW_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// The active window as the provider reports it: identity, attribution,
/// and the focus-time title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveWindow {
    pub(crate) xid: u32,
    pub(crate) pid: u32,
    pub(crate) exe: String,
    pub(crate) title: String,
}

/// How a foreground pass is gated. LIN-1 has no session-block source (lock
/// boundaries are LIN-2's elogind slice), so the only disabled gate is the
/// privacy pause — which forgets the unfocused correlations, the macOS
/// rule: the off period leaves no measurable trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollGate {
    Enabled,
    PausedByUser,
}

/// Feeds the shared segment state machine from the EWMH provider. Generic
/// over the provider so tests inject window sequences without an X server.
pub(crate) struct ForegroundMonitor<P> {
    provider: P,
    state: ForegroundState,
    /// Last observed service tick (the gap-cap anchor) — advances every
    /// pass, read or not, because observation is the pump running.
    last_poll: Option<Instant>,
    /// Last provider read (the recheck throttle).
    last_read: Option<Instant>,
    gate_enabled_last: bool,
}

impl<P> ForegroundMonitor<P>
where
    P: FnMut() -> Option<ActiveWindow>,
{
    pub(crate) fn new(provider: P) -> Self {
        Self {
            provider,
            state: ForegroundState::default(),
            last_poll: None,
            last_read: None,
            gate_enabled_last: false,
        }
    }

    /// One service-cadence pass. `dirty` is the pump's `PropertyNotify`
    /// edge; the provider is read on that edge, on re-enable, and on the
    /// slow recheck cadence. A `None` provider answer is a blackout: keep
    /// the open segment and retry on cadence — fabricate nothing.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        gate: PollGate,
        dirty: bool,
        events: &mut Vec<Captured>,
    ) {
        if gate != PollGate::Enabled {
            if self.gate_enabled_last {
                // The closing row is intentionally unpersisted (the send
                // gate is already off); the correlation clear is the
                // privacy half — window_unfocused_for_ms must not span or
                // disclose the off period.
                events.extend(self.end_current_gap_capped_at(now));
                self.state.clear_unfocused_correlations();
            }
            self.gate_enabled_last = false;
            self.last_poll = Some(now);
            self.last_read = None;
            return;
        }
        let enable_edge = !self.gate_enabled_last;
        self.gate_enabled_last = true;

        // Stall boundary: cap the open segment's dwell at the last observed
        // tick, then fall through and re-seed from the current window.
        if self.gap_exceeds_boundary(now) {
            events.extend(self.end_current_gap_capped_at(now));
        }

        let read_due = dirty
            || enable_edge
            || self.last_read.is_none_or(|last| {
                now.saturating_duration_since(last) >= ACTIVE_WINDOW_RECHECK_INTERVAL
            });
        if read_due {
            self.last_read = Some(now);
            if let Some(active) = (self.provider)() {
                let window = WindowRef {
                    hwnd: u64::from(active.xid),
                    exe: active.exe,
                    title: active.title,
                    pid: active.pid,
                };
                events.extend(self.state.on_window_at(window, now));
            }
        }
        self.last_poll = Some(now);
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
    /// observed — on every close path that can follow a gap).
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

    /// Pump shutdown: close the open segment so the final dwell is
    /// attributed, exactly as the other pumps' shutdown flushes do.
    pub(crate) fn flush_at(&mut self, now: Instant, events: &mut Vec<Captured>) {
        events.extend(self.end_current_gap_capped_at(now));
    }

    /// The currently-focused window, for attributing keyboard/mouse events
    /// this pass (the active window, Windows parity — not the window under
    /// the cursor). `None` when no segment is open (unfocused / gated).
    pub(crate) fn current_window(&self) -> Option<WindowRef> {
        self.state.current_window().cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use gilbreth_core::EventPayload;

    use super::*;

    #[allow(clippy::type_complexity)]
    fn monitor() -> (
        Rc<RefCell<Option<ActiveWindow>>>,
        ForegroundMonitor<impl FnMut() -> Option<ActiveWindow>>,
    ) {
        let active = Rc::new(RefCell::new(None));
        let provider_view = Rc::clone(&active);
        (
            active,
            ForegroundMonitor::new(move || provider_view.borrow().clone()),
        )
    }

    fn window(xid: u32, title: &str) -> Option<ActiveWindow> {
        Some(ActiveWindow {
            xid,
            pid: 100 + xid,
            exe: format!("/usr/bin/app{xid}"),
            title: title.to_string(),
        })
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|event| event.payload.kind()).collect()
    }

    #[test]
    fn focus_transitions_attribute_dwell_and_carry_titles() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "README - editor");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        assert_eq!(kinds(&events), vec!["focus_changed"], "seed row");

        *active.borrow_mut() = window(9, "inbox - mail");
        monitor.poll(
            base + Duration::from_secs(3),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(kinds(&events), vec!["focus_changed", "focus_changed"]);
        match &events[1].payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert_eq!(window.hwnd, 9);
                assert_eq!(window.title, "inbox - mail");
                let prev = prev.as_ref().expect("previous window attributed");
                assert_eq!(prev.hwnd, 7);
                assert_eq!(prev.title, "README - editor", "focus-time title kept");
                assert_eq!(*previous_focused_for_ms, 3_000);
            }
            other => panic!("expected focus_changed, got {other:?}"),
        }
    }

    #[test]
    fn same_window_rereads_emit_nothing() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "one");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        // Title changed mid-segment; the re-read is discarded unemitted
        // (Windows/macOS parity: title is the focus-time read).
        *active.borrow_mut() = window(7, "two");
        monitor.poll(
            base + Duration::from_secs(2),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 1, "same window: no new row");
    }

    #[test]
    fn provider_blackout_keeps_the_segment_open() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "t");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        *active.borrow_mut() = None;
        monitor.poll(
            base + Duration::from_secs(2),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(events.len(), 1, "blackout fabricates nothing");
        assert_eq!(
            monitor.current_window().expect("segment stays open").hwnd,
            7
        );
    }

    #[test]
    fn reads_throttle_to_the_recheck_cadence_unless_dirty() {
        let calls = Rc::new(RefCell::new(0u32));
        let calls_view = Rc::clone(&calls);
        let mut monitor = ForegroundMonitor::new(move || {
            *calls_view.borrow_mut() += 1;
            window(7, "t")
        });
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, PollGate::Enabled, false, &mut events);
        assert_eq!(*calls.borrow(), 1, "enable edge reads");
        monitor.poll(
            base + Duration::from_millis(50),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(*calls.borrow(), 1, "not dirty, not due: no read");
        monitor.poll(
            base + Duration::from_millis(100),
            PollGate::Enabled,
            true,
            &mut events,
        );
        assert_eq!(*calls.borrow(), 2, "the PropertyNotify edge reads at once");
        monitor.poll(
            base + Duration::from_millis(1_150),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(*calls.borrow(), 3, "the recheck cadence reads");
    }

    #[test]
    fn user_pause_closes_the_segment_and_forgets_correlations() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "t");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        events.clear();

        // Pause: the close row exists (the caller's send gate drops it) and
        // correlations are forgotten.
        monitor.poll(
            base + Duration::from_secs(5),
            PollGate::PausedByUser,
            false,
            &mut events,
        );
        assert_eq!(kinds(&events), vec!["focus_changed"], "boundary close");
        events.clear();

        // Re-enable 60s later: the fresh seed must not disclose the off
        // period through window_unfocused_for_ms.
        monitor.poll(
            base + Duration::from_secs(65),
            PollGate::Enabled,
            false,
            &mut events,
        );
        match &events[0].payload {
            EventPayload::FocusChanged {
                window_unfocused_for_ms,
                prev,
                ..
            } => {
                assert_eq!(
                    *window_unfocused_for_ms, 0,
                    "the pause leaves no measurable trace"
                );
                assert!(prev.is_none(), "fresh seed, no prior attribution");
            }
            other => panic!("expected focus_changed, got {other:?}"),
        }
    }

    #[test]
    fn a_service_gap_caps_dwell_at_the_last_observed_tick() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "t");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        monitor.poll(
            base + Duration::from_secs(10),
            PollGate::Enabled,
            false,
            &mut events,
        );
        events.clear();

        // The pump stalls for 5 minutes, then resumes: the segment closes
        // capped at the 10s actually observed, and the same window re-seeds.
        monitor.poll(
            base + Duration::from_secs(310),
            PollGate::Enabled,
            false,
            &mut events,
        );
        assert_eq!(kinds(&events), vec!["focus_changed", "focus_changed"]);
        match &events[0].payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(*previous_focused_for_ms, 10_000, "gap-capped dwell"),
            other => panic!("expected focus_changed, got {other:?}"),
        }
    }

    #[test]
    fn shutdown_flush_attributes_the_final_dwell() {
        let (active, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *active.borrow_mut() = window(7, "t");
        monitor.poll(base, PollGate::Enabled, true, &mut events);
        events.clear();
        monitor.flush_at(base + Duration::from_secs(4), &mut events);
        match &events[0].payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                prev,
                ..
            } => {
                assert_eq!(*previous_focused_for_ms, 4_000);
                assert_eq!(prev.as_ref().expect("boundary reuses current").hwnd, 7);
            }
            other => panic!("expected focus_changed, got {other:?}"),
        }
    }
}
