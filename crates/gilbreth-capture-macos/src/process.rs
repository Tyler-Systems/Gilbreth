//! Process launch/exit tracking (TCC record, "Pre-implementation decisions
//! (2026-07-12)" process rules): a libproc sweep at the ported Windows 5 s
//! cadence, throttled inside the pump's service tick — sweep-only, the
//! recorded decision; no NSWorkspace observers. The tracker is the Windows
//! semantics ported verbatim (`ProcessTracker` in capture-windows): the
//! first snapshot seeds silently; a same-pid identity change (name or
//! start time — PID reuse) emits Exited-then-Started; lifecycle rows are
//! kept only for apps the user has focused, everything else is counted into
//! hourly `process_churn_summary` rows with the sustained-churn flag by the
//! shared `gilbreth_core::ProcessNoiseFilter` (hoisted 2026-07-12 per the
//! recorded trigger, thresholds unchanged).
//!
//! Provider-fed and pure like the other monitors; the libproc snapshot
//! lives in `coregraphics.rs` (the crate's libc provider module).

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use gilbreth_core::{
    exe_basename_lower, CaptureControls, Captured, EventPayload, ProcessExeSource,
    ProcessNoiseFilter, Source,
};
use tracing::warn;

/// Ported Windows cadence: the Toolhelp sweep every 5 s; here the pump's
/// service tick calls in and this throttle enforces the cadence (no extra
/// thread — the recorded deviation from Windows' dedicated poll thread).
const PROCESS_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// One process from a libproc sweep. `comm` is the kernel's process name
/// (`pbi_comm`, truncated to 15 bytes); `path` is the full executable path
/// when `proc_pidpath` succeeds; `start_time_us` is the process start time
/// for PID-reuse detection (the Windows creation-time twin).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessSnapshotEntry {
    pub(crate) pid: u32,
    pub(crate) comm: String,
    pub(crate) path: Option<String>,
    pub(crate) start_time_us: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    /// Lowercased comparison/filter name. Prefers the resolved path's
    /// basename — the untruncated name, matching Windows' snapshot name —
    /// and falls back to the kernel's 15-byte `comm`. Recorded nuance: a
    /// binary name longer than 15 chars whose path is unreadable compares
    /// by the truncated comm.
    compare_name: String,
    exe: String,
    exe_source: ProcessExeSource,
    start_time_us: Option<u64>,
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
            start_time_us: entry.start_time_us,
        }
    }

    /// The Windows `is_same_process` semantics: same comparison name, and
    /// same start time when both sides know it (an unknown side never
    /// forces a false restart).
    fn is_same_process(&self, next: &Self) -> bool {
        self.compare_name == next.compare_name
            && match (self.start_time_us, next.start_time_us) {
                (Some(previous), Some(next)) => previous == next,
                _ => true,
            }
    }

    /// Keep a previously-known start time when a refresh lost it (the
    /// Windows `refreshed_with`).
    fn refreshed_with(&self, mut next: Self) -> Self {
        if next.start_time_us.is_none() {
            next.start_time_us = self.start_time_us;
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

/// The pump-facing monitor: 5 s throttle, tracker diff, focus rescue, churn
/// accounting, hourly summaries. Rows gate at `send` like every stream.
pub(crate) struct ProcessMonitor {
    tracker: ProcessTracker,
    noise: ProcessNoiseFilter,
    last_sweep: Option<Instant>,
}

impl ProcessMonitor {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            tracker: ProcessTracker::default(),
            noise: ProcessNoiseFilter::new(now),
            last_sweep: None,
        }
    }

    pub(crate) fn poll<S>(
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
    pub(crate) fn flush(&mut self, now: Instant, events: &mut Vec<Captured>) {
        if let Some(payload) = self.noise.take_summary(now) {
            events.push(Captured::new(Source::System, now, payload));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: u32, comm: &str, path: Option<&str>, start: u64) -> ProcessSnapshotEntry {
        ProcessSnapshotEntry {
            pid,
            comm: comm.to_string(),
            path: path.map(str::to_string),
            start_time_us: Some(start),
        }
    }

    fn unfiltered_controls() -> CaptureControls {
        let controls = CaptureControls::all_enabled();
        controls.set_process_filter_enabled(false);
        controls
    }

    #[test]
    fn first_snapshot_seeds_silently_then_diffs() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();

        let base = vec![
            entry(1, "launchd", Some("/sbin/launchd"), 10),
            entry(700, "A", Some("/Applications/A.app/Contents/MacOS/A"), 20),
        ];
        monitor.poll(t0, &controls, &mut || Some(base.clone()), &mut events);
        assert!(events.is_empty(), "the seed is silent");

        let mut next = base.clone();
        next.push(entry(
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
    fn pid_reuse_emits_exit_then_start() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![entry(500, "old", Some("/usr/bin/old"), 100)]),
            &mut events,
        );
        // Same pid, new start time and name: the pid was reused.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || Some(vec![entry(500, "new", Some("/usr/bin/new"), 900)]),
            &mut events,
        );
        let kinds: Vec<&str> = events.iter().map(|c| c.payload.kind()).collect();
        assert_eq!(kinds, ["process_exited", "process_started"]);
    }

    #[test]
    fn comm_fallback_uses_snapshot_name_source() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // A path-unreadable daemon appears: comm only.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || {
                Some(vec![
                    entry(1, "launchd", Some("/sbin/launchd"), 1),
                    entry(901, "secretd", None, 55),
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
    fn sweep_is_throttled_to_the_cadence() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        let calls = std::cell::Cell::new(0u32);
        let mut provider = || {
            calls.set(calls.get() + 1);
            Some(vec![entry(1, "launchd", Some("/sbin/launchd"), 1)])
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
    fn filter_rescues_focused_apps_and_demotes_the_rest() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = CaptureControls::all_enabled();
        assert!(controls.process_filter_enabled(), "filter defaults on");
        controls.note_foreground_exe("/Applications/A.app/Contents/MacOS/A");
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // One focused app and one background daemon start together.
        monitor.poll(
            t0 + Duration::from_secs(5),
            &controls,
            &mut || {
                Some(vec![
                    entry(1, "launchd", Some("/sbin/launchd"), 1),
                    entry(700, "A", Some("/Applications/A.app/Contents/MacOS/A"), 20),
                    entry(901, "noised", Some("/usr/libexec/noised"), 30),
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
    fn sustained_churn_is_flagged_in_the_summary() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = CaptureControls::all_enabled();
        let mut events = Vec::new();

        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        // A crash-looping daemon: a fresh pid + start time every 5 s sweep,
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
                        entry(1, "launchd", Some("/sbin/launchd"), 1),
                        entry(pid, "loopd", Some("/usr/libexec/loopd"), 1000 + round),
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
    fn failed_sweep_keeps_state_and_emits_nothing() {
        let t0 = Instant::now();
        let mut monitor = ProcessMonitor::new(t0);
        let controls = unfiltered_controls();
        let mut events = Vec::new();
        monitor.poll(
            t0,
            &controls,
            &mut || Some(vec![entry(700, "A", Some("/a"), 1)]),
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
            &mut || Some(vec![entry(1, "launchd", Some("/sbin/launchd"), 1)]),
            &mut events,
        );
        let kinds: Vec<&str> = events.iter().map(|c| c.payload.kind()).collect();
        assert!(kinds.contains(&"process_exited"));
    }
}
