//! Idle stream (LIN-1): the edge detector ported verbatim from the
//! Windows/macOS twins so all platforms cross the threshold identically;
//! the sample source is the X server's idle clock (the MIT-SCREEN-SAVER
//! extension's `ms_since_user_input`), read through the injected provider.
//!
//! Sampling cadence matches the shared 1 s rule (`SAMPLE_INTERVAL`), with
//! the monitor throttling internally below the pump's 50 ms tick. On a
//! mid-run stream disable the state resets to fresh, so re-enabling never
//! emits an `Active` row for an idle period that began while the stream
//! was off — the macOS rule, deliberately the cleaner of the two.

use std::time::{Duration, Instant};

use gilbreth_core::{Captured, EventPayload, Source};

/// The shared sample cadence (Windows `SYSTEM_POLL_INTERVAL_MS`, the macOS
/// `SAMPLE_INTERVAL`): at least as often as either platform ever samples.
pub(crate) const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Ported threshold edge rules: same payloads, same `Source::System`
/// labeling (the payloads gate under `CaptureStream::Idle` via
/// `stream_for`).
struct IdleState {
    threshold: Duration,
    is_idle: bool,
}

impl IdleState {
    fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            is_idle: false,
        }
    }

    fn on_sample_at(&mut self, idle_ms: u64, captured_at: Instant) -> Option<Captured> {
        let threshold_ms = u64::try_from(self.threshold.as_millis()).unwrap_or(u64::MAX);
        if !self.is_idle && idle_ms >= threshold_ms {
            self.is_idle = true;
            return Some(Captured::new(
                Source::System,
                captured_at,
                EventPayload::Idle { idle_ms },
            ));
        }

        if self.is_idle && idle_ms < threshold_ms {
            self.is_idle = false;
            return Some(Captured::new(
                Source::System,
                captured_at,
                EventPayload::Active { idle_ms },
            ));
        }

        None
    }
}

/// Samples the X idle clock on the shared cadence and feeds the edge
/// detector. Generic over the provider so tests inject idle sequences
/// without an X server.
pub(crate) struct IdleMonitor<P> {
    provider: P,
    state: IdleState,
    threshold: Duration,
    last_sample: Option<Instant>,
    enabled: bool,
}

impl<P> IdleMonitor<P>
where
    P: FnMut() -> Option<u64>,
{
    pub(crate) fn new(threshold: Duration, provider: P) -> Self {
        Self {
            provider,
            state: IdleState::new(threshold),
            threshold,
            last_sample: None,
            enabled: false,
        }
    }

    /// Post-erase reseed: fresh edge state, so an idle period straddling
    /// the wipe never yields an Active edge with no Idle row before it in
    /// the replacement session (the disable-path reset).
    pub(crate) fn reseed(&mut self) {
        self.state = IdleState::new(self.threshold);
        self.last_sample = None;
    }

    /// One service-cadence pass; internally throttled to [`SAMPLE_INTERVAL`].
    pub(crate) fn poll(&mut self, now: Instant, enabled: bool, events: &mut Vec<Captured>) {
        if !enabled {
            if self.enabled {
                // Fresh state on disable: an idle period that begins while
                // the stream is off never yields a later Active edge.
                self.state = IdleState::new(self.threshold);
                self.last_sample = None;
            }
            self.enabled = false;
            return;
        }
        self.enabled = true;

        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        if let Some(idle_ms) = (self.provider)() {
            events.extend(self.state.on_sample_at(idle_ms, now));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use super::*;

    #[allow(clippy::type_complexity)]
    fn monitor_with_idle(
        threshold_ms: u64,
    ) -> (
        Rc<Cell<Option<u64>>>,
        IdleMonitor<impl FnMut() -> Option<u64>>,
    ) {
        let idle = Rc::new(Cell::new(Some(0)));
        let provider_view = idle.clone();
        (
            idle,
            IdleMonitor::new(Duration::from_millis(threshold_ms), move || {
                provider_view.get()
            }),
        )
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|event| event.payload.kind()).collect()
    }

    #[test]
    fn idle_and_active_edges_fire_once_per_crossing() {
        let (idle, mut monitor) = monitor_with_idle(60_000);
        let base = Instant::now();
        let mut events = Vec::new();

        idle.set(Some(1_000));
        monitor.poll(base, true, &mut events);
        assert!(events.is_empty(), "below threshold: no edge");

        idle.set(Some(60_000));
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        idle.set(Some(75_000));
        monitor.poll(base + Duration::from_secs(4), true, &mut events);
        assert_eq!(kinds(&events), vec!["idle"], "one Idle edge, no repeats");

        idle.set(Some(200));
        monitor.poll(base + Duration::from_secs(6), true, &mut events);
        assert_eq!(kinds(&events), vec!["idle", "active"]);
    }

    #[test]
    fn sampling_is_throttled_to_the_shared_cadence() {
        let (idle, mut monitor) = monitor_with_idle(1_000);
        let base = Instant::now();
        let mut events = Vec::new();

        idle.set(Some(5_000));
        monitor.poll(base, true, &mut events);
        assert_eq!(events.len(), 1, "first sample crosses to idle");

        idle.set(Some(10));
        monitor.poll(base + Duration::from_millis(50), true, &mut events);
        assert_eq!(events.len(), 1, "throttled: no resample within 1s");

        monitor.poll(base + Duration::from_millis(1_050), true, &mut events);
        assert_eq!(kinds(&events), vec!["idle", "active"]);
    }

    #[test]
    fn disable_resets_state_so_reenable_never_reports_off_period_idleness() {
        let (idle, mut monitor) = monitor_with_idle(1_000);
        let base = Instant::now();
        let mut events = Vec::new();

        idle.set(Some(5_000));
        monitor.poll(base, true, &mut events);
        assert_eq!(events.len(), 1, "idle edge before disable");

        monitor.poll(base + Duration::from_secs(2), false, &mut events);
        assert_eq!(events.len(), 1, "disable emits nothing");

        idle.set(Some(100));
        monitor.poll(base + Duration::from_secs(10), true, &mut events);
        assert_eq!(events.len(), 1, "no Active edge from the off period");

        idle.set(Some(2_000));
        monitor.poll(base + Duration::from_secs(12), true, &mut events);
        assert_eq!(kinds(&events), vec!["idle", "idle"]);
    }

    #[test]
    fn provider_blackout_skips_the_sample_without_state_damage() {
        let (idle, mut monitor) = monitor_with_idle(1_000);
        let base = Instant::now();
        let mut events = Vec::new();

        idle.set(None);
        monitor.poll(base, true, &mut events);
        idle.set(Some(5_000));
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert_eq!(kinds(&events), vec!["idle"]);
    }
}
