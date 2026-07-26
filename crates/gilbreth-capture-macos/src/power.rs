//! Power-boundary state machine (TCC record, "Pre-implementation decisions
//! (2026-07-12)" power rules): sleep/wake edges from `IORegisterForSystemPower`
//! feed the same `PowerSuspend` / `PowerResume` vocabulary Windows writes on
//! `PBT_APMSUSPEND` / `PBT_APMRESUME*`, and a continuous-vs-uptime clock
//! divergence detector replaces the Windows tick-gap detector — mac `Instant`
//! (uptime clock) pauses during sleep, so an `Instant` gap can never see a
//! sleep; `mach_continuous_time` (the `GetTickCount64` parity twin) spans it,
//! and the divergence between the two across one pump pass IS the slept
//! interval.
//!
//! Everything here is provider-fed and pure (no IOKit, no AppKit), mirroring
//! the SystemMonitor/IdleMonitor pattern; the IOKit edge source and the IOPS
//! status snapshot live in `iokit.rs`.

use std::time::{Duration, Instant};

use gilbreth_core::{Captured, EventPayload, Source};
use tracing::{debug, info};

/// Ported Windows constants (capture-windows): a resume within this window of
/// the previous one, with no suspend between, is the same wake reported twice
/// (`PBT_APMRESUMEAUTOMATIC` + `PBT_APMRESUMESUSPEND` on Windows; a defensive
/// guard here).
const POWER_RESUME_DEBOUNCE: Duration = Duration::from_secs(2);
/// Ported Windows threshold: a slept interval this large with no observed
/// boundary is a missed boundary worth a `PowerBoundaryRecovered` row.
const MISSED_POWER_BOUNDARY_THRESHOLD_MS: u64 = 30_000;
/// Status snapshots poll on the Windows 1 s system cadence (the recorded
/// poll-with-edge-detection rule); rows emit on change only.
const STATUS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// A sleep/wake notification delivered by the IOKit callback. `continuous_ms`
/// is read in the callback (the true edge time on the spans-sleep clock);
/// `at` is the pump `Instant` stamped alongside it.
pub(crate) struct PowerEdgeSample {
    pub(crate) at: Instant,
    pub(crate) continuous_ms: Option<u64>,
    pub(crate) edge: PowerEdge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PowerEdge {
    /// `kIOMessageSystemWillSleep` — committed, already acknowledged in the
    /// callback (Gilbreth observes sleep, never delays it).
    WillSleep,
    /// `kIOMessageSystemHasPoweredOn` — wake complete. Emitted for every
    /// wake including dark wakes (owner decision: Windows
    /// `PBT_APMRESUMEAUTOMATIC` parity; user presence stays the job of
    /// idle/active and dwell, not power rows).
    DidWake,
}

/// AC/battery/Low-Power-Mode snapshot. `None` fields are honestly unknown —
/// a desktop Mac has no battery power source, mirroring the Windows
/// desktop's unknown battery fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PowerStatusSnapshot {
    pub(crate) ac_online: Option<bool>,
    pub(crate) battery_percent: Option<u8>,
    pub(crate) battery_saver: Option<bool>,
}

/// The pump's power seam: edges + the continuous clock + the status
/// snapshot. Production is `iokit::IoKitPowerSource`; tests inject scripts.
pub(crate) trait PowerSource {
    /// Everything the sleep/wake callback queued since the last pass.
    fn drain_edges(&mut self) -> Vec<PowerEdgeSample>;
    /// The spans-sleep clock (`mach_continuous_time` in ms). `None` disables
    /// the divergence detector for the pass (quiet test sources).
    fn continuous_ms(&mut self) -> Option<u64>;
    /// The AC/battery/Low-Power-Mode snapshot; `None` when unavailable.
    fn status(&mut self) -> Option<PowerStatusSnapshot>;
}

/// What the pump must do for a boundary this pass, in Windows order: input
/// state machines reset and the Foreground segment closes BEFORE the power
/// rows are pushed (`on_power_suspend_at` ordering, ported).
pub(crate) struct PowerBoundary {
    /// Close the open Foreground segment before pushing `rows` (false when a
    /// matched resume follows a suspend that already closed it).
    pub(crate) close_foreground: bool,
    pub(crate) rows: Vec<Captured>,
}

pub(crate) struct PowerMonitor {
    suspended: bool,
    last_resume_at: Option<Instant>,
    /// (uptime instant, continuous ms) of the last divergence sample; the
    /// two clocks tick together while awake and diverge by exactly the
    /// slept time across a sleep.
    divergence_sample: Option<(Instant, u64)>,
    /// Windows' `last_power_status` key: (ac, saver, percent/10) — only
    /// meaningful changes emit (plug/unplug, saver toggle, ~10% steps).
    status_key: Option<(Option<bool>, Option<bool>, Option<u8>)>,
    /// The first status sample baselines silently: Windows only samples on
    /// change messages, so its rows are actual changes — a poller that
    /// emitted its first sample would add a spurious row per launch
    /// (recorded implementation amendment).
    status_baselined: bool,
    last_status_at: Option<Instant>,
}

impl PowerMonitor {
    pub(crate) fn new() -> Self {
        Self {
            suspended: false,
            last_resume_at: None,
            divergence_sample: None,
            status_key: None,
            status_baselined: false,
            last_status_at: None,
        }
    }

    /// `kIOMessageSystemWillSleep`: the Windows `PBT_APMSUSPEND` twin.
    pub(crate) fn on_will_sleep(&mut self, sample: &PowerEdgeSample) -> Option<PowerBoundary> {
        if self.suspended {
            debug!("duplicate willSleep ignored (already suspended)");
            self.rebaseline(sample.at, sample.continuous_ms);
            return None;
        }
        self.suspended = true;
        self.last_resume_at = None;
        self.rebaseline(sample.at, sample.continuous_ms);
        info!(tick_ms = sample.continuous_ms, "power suspend boundary");
        Some(PowerBoundary {
            close_foreground: true,
            rows: vec![Captured::new(
                Source::System,
                sample.at,
                EventPayload::PowerSuspend {
                    tick_ms: sample.continuous_ms,
                },
            )],
        })
    }

    /// `kIOMessageSystemHasPoweredOn`: the Windows `PBT_APMRESUME*` twin,
    /// including the ported duplicate-resume debounce and the
    /// missed-boundary recovery for a wake whose suspend was never seen.
    pub(crate) fn on_did_wake(&mut self, sample: &PowerEdgeSample) -> Option<PowerBoundary> {
        if !self.suspended
            && self.last_resume_at.is_some_and(|previous| {
                sample.at.saturating_duration_since(previous) <= POWER_RESUME_DEBOUNCE
            })
        {
            self.last_resume_at = Some(sample.at);
            self.rebaseline(sample.at, sample.continuous_ms);
            info!(
                tick_ms = sample.continuous_ms,
                "duplicate power resume boundary ignored"
            );
            return None;
        }

        let matched_suspend = self.suspended;
        let mut rows = Vec::new();
        if !matched_suspend {
            // The suspend was never observed. If the clocks diverged past
            // the threshold, this wake also recovers a missed boundary —
            // Windows' resume-path recovery, rows in the same order
            // (Recovered, then Resume).
            if let Some(gap_ms) = self.divergence_ms(sample.at, sample.continuous_ms) {
                if gap_ms > MISSED_POWER_BOUNDARY_THRESHOLD_MS {
                    rows.push(recovered_row(sample.at, gap_ms));
                    info!(gap_ms, "missed power boundary caught at wake");
                }
            }
        }
        rows.push(Captured::new(
            Source::System,
            sample.at,
            EventPayload::PowerResume {
                tick_ms: sample.continuous_ms,
                matched_suspend,
            },
        ));
        self.suspended = false;
        self.last_resume_at = Some(sample.at);
        self.rebaseline(sample.at, sample.continuous_ms);
        info!(
            tick_ms = sample.continuous_ms,
            matched_suspend, "power resume boundary"
        );
        Some(PowerBoundary {
            // A matched resume follows a suspend that already closed the
            // segment; an unmatched one must close it now (capped by the
            // poller's own gap-capped close — on macOS sleep contributes no
            // dwell anyway, the uptime clock pauses).
            close_foreground: !matched_suspend,
            rows,
        })
    }

    /// Per-pass divergence detector — the mac replacement for the Windows
    /// tick-gap detector (recorded power rules): `Instant` pauses during
    /// sleep, `mach_continuous_time` spans it, so continuous-delta minus
    /// instant-delta across one pass is the slept time the notification
    /// path missed. Also the replacement for Windows' "timer tick while
    /// suspended acts as the resume": mac polls keep running in the 1–2 s
    /// pre-sleep window after willSleep, so mere polling proves nothing —
    /// the clock divergence is the wake evidence (recorded amendment).
    pub(crate) fn poll_divergence(
        &mut self,
        now: Instant,
        continuous_ms: Option<u64>,
    ) -> Option<PowerBoundary> {
        let gap_ms = self.divergence_ms(now, continuous_ms)?;
        self.rebaseline(now, continuous_ms);
        if gap_ms <= MISSED_POWER_BOUNDARY_THRESHOLD_MS {
            return None;
        }
        if self.suspended {
            // The suspend was observed but the wake notification never
            // arrived: the divergence is the wake evidence. Matched resume;
            // the segment was already closed at suspend.
            self.suspended = false;
            self.last_resume_at = Some(now);
            info!(gap_ms, "power resume recovered from clock divergence");
            return Some(PowerBoundary {
                close_foreground: false,
                rows: vec![Captured::new(
                    Source::System,
                    now,
                    EventPayload::PowerResume {
                        tick_ms: continuous_ms,
                        matched_suspend: true,
                    },
                )],
            });
        }
        // Neither boundary was observed: the Windows timer-path recovery —
        // a Recovered row only, no Resume row (ported semantics).
        self.last_resume_at = Some(now);
        info!(gap_ms, "missed power boundary caught");
        Some(PowerBoundary {
            close_foreground: true,
            rows: vec![recovered_row(now, gap_ms)],
        })
    }

    /// Throttled status sample with the ported Windows change key. `force`
    /// bypasses the throttle right after a boundary (Windows samples status
    /// at every real resume and recovery); the silent first baseline still
    /// applies — a boundary at launch must not fabricate a change row.
    pub(crate) fn poll_status<S>(
        &mut self,
        now: Instant,
        force: bool,
        snapshot: &mut S,
        events: &mut Vec<Captured>,
    ) where
        S: FnMut() -> Option<PowerStatusSnapshot>,
    {
        let due = self
            .last_status_at
            .is_none_or(|last| now.saturating_duration_since(last) >= STATUS_SAMPLE_INTERVAL);
        if !force && !due {
            return;
        }
        self.last_status_at = Some(now);
        let Some(snap) = snapshot() else {
            return;
        };
        let key = (
            snap.ac_online,
            snap.battery_saver,
            snap.battery_percent.map(|p| p / 10),
        );
        if !self.status_baselined {
            self.status_baselined = true;
            self.status_key = Some(key);
            return;
        }
        if self.status_key == Some(key) {
            return;
        }
        self.status_key = Some(key);
        events.push(Captured::new(
            Source::System,
            now,
            EventPayload::PowerStatusChanged {
                ac_online: snap.ac_online,
                battery_percent: snap.battery_percent,
                battery_saver: snap.battery_saver,
            },
        ));
    }

    /// Continuous-minus-instant delta since the last sample, in ms; `None`
    /// when either clock is unavailable or no baseline exists yet (the
    /// first call baselines).
    fn divergence_ms(&mut self, now: Instant, continuous_ms: Option<u64>) -> Option<u64> {
        let current = continuous_ms?;
        let Some((last_at, last_continuous)) = self.divergence_sample else {
            self.divergence_sample = Some((now, current));
            return None;
        };
        let instant_delta =
            u64::try_from(now.saturating_duration_since(last_at).as_millis()).unwrap_or(u64::MAX);
        let continuous_delta = current.saturating_sub(last_continuous);
        Some(continuous_delta.saturating_sub(instant_delta))
    }

    fn rebaseline(&mut self, at: Instant, continuous_ms: Option<u64>) {
        if let Some(continuous) = continuous_ms {
            self.divergence_sample = Some((at, continuous));
        }
    }
}

fn recovered_row(at: Instant, gap_ms: u64) -> Captured {
    Captured::new(
        Source::System,
        at,
        EventPayload::PowerBoundaryRecovered {
            gap_ms,
            // Windows reports the 30 s cap it enforces on dwell attributed
            // across the gap (its tick clock spans suspend). On macOS the
            // uptime clock pauses during sleep, so a gap can contribute NO
            // dwell — 0 is the cap actually in force (recorded amendment;
            // the field means "max dwell attributable across the recovered
            // gap").
            capped_dwell_ms: 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at: Instant, continuous_ms: u64, edge: PowerEdge) -> PowerEdgeSample {
        PowerEdgeSample {
            at,
            continuous_ms: Some(continuous_ms),
            edge,
        }
    }

    fn payloads(rows: &[Captured]) -> Vec<&EventPayload> {
        rows.iter().map(|c| &c.payload).collect()
    }

    #[test]
    fn will_sleep_emits_suspend_and_closes_foreground() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        let boundary = monitor
            .on_will_sleep(&sample(t0, 1_000, PowerEdge::WillSleep))
            .expect("first willSleep is a boundary");
        assert!(boundary.close_foreground);
        assert!(matches!(
            payloads(&boundary.rows)[..],
            [EventPayload::PowerSuspend {
                tick_ms: Some(1_000)
            }]
        ));

        // A duplicate willSleep while already suspended is silent.
        assert!(monitor
            .on_will_sleep(&sample(t0, 1_100, PowerEdge::WillSleep))
            .is_none());
    }

    #[test]
    fn matched_wake_emits_resume_without_reclosing_foreground() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        monitor.on_will_sleep(&sample(t0, 1_000, PowerEdge::WillSleep));
        let boundary = monitor
            .on_did_wake(&sample(
                t0 + Duration::from_millis(50),
                3_601_000,
                PowerEdge::DidWake,
            ))
            .expect("wake after suspend is a boundary");
        assert!(!boundary.close_foreground, "suspend already closed it");
        assert!(matches!(
            payloads(&boundary.rows)[..],
            [EventPayload::PowerResume {
                matched_suspend: true,
                ..
            }]
        ));
    }

    #[test]
    fn unmatched_wake_with_divergence_recovers_the_missed_boundary() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        // Baseline the divergence clocks, then wake with the continuous
        // clock 60 s ahead of the instant clock: the suspend was missed.
        assert!(monitor.poll_divergence(t0, Some(1_000)).is_none());
        let boundary = monitor
            .on_did_wake(&sample(
                t0 + Duration::from_millis(100),
                61_100,
                PowerEdge::DidWake,
            ))
            .expect("unmatched wake is a boundary");
        assert!(boundary.close_foreground);
        assert!(matches!(
            payloads(&boundary.rows)[..],
            [
                EventPayload::PowerBoundaryRecovered {
                    capped_dwell_ms: 0,
                    ..
                },
                EventPayload::PowerResume {
                    matched_suspend: false,
                    ..
                }
            ]
        ));
        let EventPayload::PowerBoundaryRecovered { gap_ms, .. } = boundary.rows[0].payload else {
            panic!("first row is the recovery");
        };
        assert!(
            (59_000..=60_100).contains(&gap_ms),
            "gap ≈ 60 s, got {gap_ms}"
        );
    }

    #[test]
    fn duplicate_wake_within_debounce_is_ignored() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        monitor.on_will_sleep(&sample(t0, 1_000, PowerEdge::WillSleep));
        monitor
            .on_did_wake(&sample(
                t0 + Duration::from_secs(10),
                11_000,
                PowerEdge::DidWake,
            ))
            .expect("real wake");
        assert!(
            monitor
                .on_did_wake(&sample(
                    t0 + Duration::from_secs(11),
                    12_000,
                    PowerEdge::DidWake,
                ))
                .is_none(),
            "second wake within the debounce is the same wake"
        );
        // Past the debounce, an unmatched wake is a boundary again.
        assert!(monitor
            .on_did_wake(&sample(
                t0 + Duration::from_secs(30),
                31_000,
                PowerEdge::DidWake
            ))
            .is_some());
    }

    #[test]
    fn divergence_while_suspended_is_the_recovered_matched_resume() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        monitor.on_will_sleep(&sample(t0, 1_000, PowerEdge::WillSleep));
        // The wake notification never arrives; the next pass sees the
        // continuous clock 45 s ahead of the instant clock.
        let boundary = monitor
            .poll_divergence(t0 + Duration::from_millis(100), Some(46_100))
            .expect("divergence while suspended resumes");
        assert!(!boundary.close_foreground);
        assert!(matches!(
            payloads(&boundary.rows)[..],
            [EventPayload::PowerResume {
                matched_suspend: true,
                ..
            }]
        ));
    }

    #[test]
    fn divergence_without_any_boundary_emits_recovered_only() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        assert!(
            monitor.poll_divergence(t0, Some(1_000)).is_none(),
            "baseline"
        );
        let boundary = monitor
            .poll_divergence(t0 + Duration::from_millis(50), Some(41_050))
            .expect("40 s divergence is a missed boundary");
        assert!(boundary.close_foreground);
        assert!(matches!(
            payloads(&boundary.rows)[..],
            [EventPayload::PowerBoundaryRecovered { .. }]
        ));

        // The detector rebaselined: the next pass is quiet.
        assert!(monitor
            .poll_divergence(t0 + Duration::from_millis(100), Some(41_100))
            .is_none());
    }

    #[test]
    fn small_divergence_stays_silent_and_rebaselines() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        assert!(monitor.poll_divergence(t0, Some(1_000)).is_none());
        // 10 s divergence: below the ported 30 s threshold.
        assert!(monitor
            .poll_divergence(t0 + Duration::from_millis(50), Some(11_050))
            .is_none());
        // The baseline moved: another 10 s step is still quiet (no
        // accumulation into a false 20 s gap).
        assert!(monitor
            .poll_divergence(t0 + Duration::from_millis(100), Some(21_100))
            .is_none());
    }

    #[test]
    fn status_baselines_silently_then_emits_meaningful_changes_only() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        let mut events = Vec::new();

        let mut snap = Some(PowerStatusSnapshot {
            ac_online: Some(true),
            battery_percent: Some(95),
            battery_saver: Some(false),
        });
        monitor.poll_status(t0, false, &mut || snap, &mut events);
        assert!(events.is_empty(), "first sample baselines silently");

        // Same bucket (95 → 91 is still the 9x bucket): no row, and the
        // throttle requires a second to pass.
        snap = Some(PowerStatusSnapshot {
            ac_online: Some(true),
            battery_percent: Some(91),
            battery_saver: Some(false),
        });
        monitor.poll_status(
            t0 + Duration::from_secs(1),
            false,
            &mut || snap,
            &mut events,
        );
        assert!(events.is_empty(), "same 10%-bucket is not a change");

        // Unplugging is a change.
        snap = Some(PowerStatusSnapshot {
            ac_online: Some(false),
            battery_percent: Some(91),
            battery_saver: Some(false),
        });
        monitor.poll_status(
            t0 + Duration::from_secs(2),
            false,
            &mut || snap,
            &mut events,
        );
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].payload,
            EventPayload::PowerStatusChanged {
                ac_online: Some(false),
                battery_percent: Some(91),
                battery_saver: Some(false),
            }
        ));

        // Low Power Mode flip is a change even inside the throttle window
        // when forced (the post-boundary sample).
        snap = Some(PowerStatusSnapshot {
            ac_online: Some(false),
            battery_percent: Some(91),
            battery_saver: Some(true),
        });
        monitor.poll_status(
            t0 + Duration::from_millis(2_100),
            true,
            &mut || snap,
            &mut events,
        );
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn status_throttles_to_the_sample_interval() {
        let mut monitor = PowerMonitor::new();
        let t0 = Instant::now();
        let mut events = Vec::new();
        let calls = std::cell::Cell::new(0u32);
        let mut provider = || {
            calls.set(calls.get() + 1);
            Some(PowerStatusSnapshot {
                ac_online: Some(true),
                battery_percent: Some(50),
                battery_saver: Some(false),
            })
        };
        monitor.poll_status(t0, false, &mut provider, &mut events);
        monitor.poll_status(
            t0 + Duration::from_millis(200),
            false,
            &mut provider,
            &mut events,
        );
        monitor.poll_status(
            t0 + Duration::from_millis(400),
            false,
            &mut provider,
            &mut events,
        );
        assert_eq!(calls.get(), 1, "sub-interval passes must not sample");
        monitor.poll_status(
            t0 + Duration::from_millis(1_100),
            false,
            &mut provider,
            &mut events,
        );
        assert_eq!(calls.get(), 2);
    }
}
