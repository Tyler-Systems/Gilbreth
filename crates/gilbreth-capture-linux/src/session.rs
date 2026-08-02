//! Session stream (LIN-2): lock/unlock and console connect/disconnect
//! edges over the D-Bus snapshot the watcher thread maintains — the macOS
//! `SystemMonitor` session half ported whole, emission rules and the
//! mechanism/stream split included. The snapshot's `locked` bit composes
//! elogind's `LockedHint` with the session locker's own surface; the
//! composition rules and their live evidence live in `dbus.rs`.
//!
//! While the session is locked or off-console the pump blocks the
//! Foreground stream ([`SessionMonitor::session_blocked`]) — the Windows
//! pump ends the foreground segment at lock/disconnect for the same
//! reason: dwell must never accumulate while nobody is at the machine.
//! The pump also DROPS raw keyboard/mouse input for the duration of the
//! block (`lib.rs`): unlike the twins' OS-withheld input, X11 keeps
//! delivering raw events while the lock surface is up, and what those
//! events spell is the unlock password — parity with what Windows and
//! macOS observe during a lock is an empty stream, so the events are
//! discarded before any state machine or channel sees them (the recorded
//! fail-closed sensitive-context posture).
//!
//! Fast-user-switch/VT-switch maps to `session_connect` /
//! `session_disconnect` with kind `console` per the schema vocabulary
//! record; the `remote` kind stays Windows-only. Sensitive-context rows
//! around locks stay deferred exactly as macOS defers them (the input
//! drop above covers the X11-specific exposure they would have fenced).

use std::time::Instant;

use gilbreth_core::{Captured, EventPayload, SessionConnectionKind, Source};

use crate::idle::SAMPLE_INTERVAL;

/// Point-in-time session state from the D-Bus watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionSnapshot {
    pub(crate) session_id: u32,
    pub(crate) on_console: bool,
    pub(crate) locked: bool,
}

/// Edge-detects session state on the shared 1 s cadence. Generic over the
/// provider so tests inject scripted state without a bus.
pub(crate) struct SessionMonitor<S> {
    provider: S,
    last_session: Option<SessionSnapshot>,
    last_sample: Option<Instant>,
    mechanism_was_on: bool,
}

impl<S> SessionMonitor<S>
where
    S: FnMut() -> Option<SessionSnapshot>,
{
    pub(crate) fn new(provider: S) -> Self {
        Self {
            provider,
            last_session: None,
            last_sample: None,
            mechanism_was_on: false,
        }
    }

    /// Foreground must not accumulate dwell while the session is locked or
    /// off-console; the pump feeds this into the Foreground gate. Unknown
    /// state (never sampled) blocks nothing.
    pub(crate) fn session_blocked(&self) -> bool {
        self.last_session
            .is_some_and(|session| session.locked || !session.on_console)
    }

    /// One service-cadence pass; internally throttled to [`SAMPLE_INTERVAL`].
    ///
    /// `stream_enabled` gates ROW EMISSION (the System stream setting);
    /// `track_session` keeps the session-blocking MECHANISM alive for the
    /// Foreground stream's sake. The split is the macOS/Windows rule: with
    /// System off and Foreground on, locks must still block dwell — and
    /// disabling System mid-lock must not unblock a still-locked session.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        stream_enabled: bool,
        track_session: bool,
        events: &mut Vec<Captured>,
    ) {
        let mechanism_on = stream_enabled || track_session;
        if !mechanism_on {
            if self.mechanism_was_on {
                // Everything off: drop the baseline, exactly like the
                // macOS re-baseline — no phantom edges for state that
                // changed while everything was off. With Foreground also
                // off there is no dwell to protect, so dropping the
                // session baseline is safe here (and only here).
                self.last_session = None;
                self.last_sample = None;
            }
            self.mechanism_was_on = false;
            return;
        }
        self.mechanism_was_on = true;

        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        if let Some(session) = (self.provider)() {
            if let Some(previous) = self.last_session.filter(|_| stream_enabled) {
                // Lock edges first, then console edges — deterministic
                // ordering when one poll observes both transitions.
                if !previous.locked && session.locked {
                    events.push(Captured::new(
                        Source::System,
                        now,
                        EventPayload::SessionLock {
                            session_id: session.session_id,
                        },
                    ));
                }
                if previous.locked && !session.locked {
                    events.push(Captured::new(
                        Source::System,
                        now,
                        EventPayload::SessionUnlock {
                            session_id: session.session_id,
                        },
                    ));
                }
                if previous.on_console && !session.on_console {
                    events.push(Captured::new(
                        Source::System,
                        now,
                        EventPayload::SessionDisconnect {
                            session_id: session.session_id,
                            connection: SessionConnectionKind::Console,
                        },
                    ));
                }
                if !previous.on_console && session.on_console {
                    events.push(Captured::new(
                        Source::System,
                        now,
                        EventPayload::SessionConnect {
                            session_id: session.session_id,
                            connection: SessionConnectionKind::Console,
                        },
                    ));
                }
            }
            // First observation is a baseline, not an edge — no platform
            // emits a session event at startup.
            self.last_session = Some(session);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, time::Duration};

    use super::*;

    #[allow(clippy::type_complexity)]
    fn monitor() -> (
        Rc<RefCell<Option<SessionSnapshot>>>,
        SessionMonitor<impl FnMut() -> Option<SessionSnapshot>>,
    ) {
        let session = Rc::new(RefCell::new(Some(SessionSnapshot {
            session_id: 1,
            on_console: true,
            locked: false,
        })));
        let view = Rc::clone(&session);
        (session, SessionMonitor::new(move || *view.borrow()))
    }

    #[test]
    fn lock_and_unlock_edges_emit_once_and_block_foreground() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        assert!(events.is_empty(), "first observation is a baseline");
        assert!(!monitor.session_blocked());

        session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionLock { session_id: 1 }
        ));
        assert!(monitor.session_blocked(), "locked blocks foreground");

        // Steady locked state: no repeats.
        monitor.poll(base + Duration::from_secs(4), true, true, &mut events);
        assert_eq!(events.len(), 1);

        session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(6), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionUnlock { session_id: 1 }
        ));
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn console_switch_maps_to_connect_and_disconnect() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        session.borrow_mut().as_mut().unwrap().on_console = false;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionDisconnect {
                session_id: 1,
                connection: SessionConnectionKind::Console,
            }
        ));
        assert!(monitor.session_blocked(), "off-console blocks foreground");

        session.borrow_mut().as_mut().unwrap().on_console = true;
        monitor.poll(base + Duration::from_secs(4), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionConnect {
                session_id: 1,
                connection: SessionConnectionKind::Console,
            }
        ));
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn unknown_provider_state_blocks_nothing_and_edges_nothing() {
        let mut monitor = SessionMonitor::new(|| None);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert!(events.is_empty(), "no bus: no fabricated edges");
        assert!(!monitor.session_blocked(), "unknown state blocks nothing");
    }

    #[test]
    fn foreground_only_config_still_blocks_on_lock_without_emitting_rows() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        // System stream OFF, session tracking ON (Foreground enabled).
        monitor.poll(base, false, true, &mut events);
        session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), false, true, &mut events);
        assert!(events.is_empty(), "no session rows without the stream");
        assert!(
            monitor.session_blocked(),
            "the blocking mechanism works regardless of the stream toggle"
        );

        session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(events.is_empty());
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn disabling_the_system_stream_mid_lock_keeps_blocking_while_tracked() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert!(monitor.session_blocked());
        let rows_before = events.len();

        // User disables the System stream while locked; Foreground still
        // on, so tracking persists and the still-locked session keeps
        // blocking.
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(
            monitor.session_blocked(),
            "a still-locked session must not unblock on a stream toggle"
        );

        // Unlock is still observed (mechanism alive), just unemitted.
        session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(6), false, true, &mut events);
        assert!(!monitor.session_blocked());
        assert_eq!(events.len(), rows_before, "no rows while the stream is off");
    }

    #[test]
    fn stream_reenable_mid_lock_does_not_replay_the_lock_as_an_edge() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        // Stream goes off (mechanism stays on for Foreground); the lock
        // lands while rows are gated.
        monitor.poll(base + Duration::from_secs(2), false, true, &mut events);
        session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(monitor.session_blocked());
        assert!(events.is_empty());

        // Stream back on mid-lock: the already-current baseline must not
        // replay the off-period lock as a new edge (its unlock row will
        // land normally, matching Windows' orphan-unlock behavior after a
        // gated lock).
        monitor.poll(base + Duration::from_secs(6), true, true, &mut events);
        assert!(events.is_empty(), "no phantom lock edge on re-enable");
        assert!(monitor.session_blocked(), "still blocked while locked");
    }

    #[test]
    fn full_disable_drops_the_baseline_so_off_period_changes_never_edge() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        monitor.poll(base + Duration::from_secs(2), false, false, &mut events);
        assert!(!monitor.session_blocked(), "stale state cannot block");

        // While everything was off, a lock came and went. Re-enable:
        // fresh baseline, no lock/unlock pair.
        session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(10), true, true, &mut events);
        assert!(events.is_empty(), "re-enable re-baselines without edges");
    }

    #[test]
    fn sampling_is_throttled_to_the_shared_cadence() {
        let (session, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_millis(50), true, true, &mut events);
        assert!(events.is_empty(), "throttled: no resample within 1 s");

        monitor.poll(base + Duration::from_millis(1_050), true, true, &mut events);
        assert_eq!(events.len(), 1, "edge lands on the next sample");
    }
}
