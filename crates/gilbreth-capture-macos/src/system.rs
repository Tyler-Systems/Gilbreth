//! System stream (the macOS TCC and stream rules: no TCC
//! permission): the `SystemInfo` + `VirtualScreen` seed rows, display-shape
//! changes, and session lock/unlock + console connect/disconnect edges.
//!
//! Session state is *polled* from the CoreGraphics session dictionary and
//! edge-detected on the Windows 1s cadence (a recorded amendment to the TCC
//! record, which originally named distributed-notification observers: the
//! poll is provider-injectable and keeps this crate's no-observer
//! architecture; observers can replace it in a later slice without
//! vocabulary changes). Fast-user-switch maps to
//! `session_connect`/`session_disconnect` with kind `console` per the
//! schema vocabulary record; the `remote` kind stays Windows-only.
//!
//! While the session is locked or off-console the pump also blocks the
//! Foreground stream ([`SystemMonitor::session_blocked`]) — the Windows
//! pump ends the foreground segment at lock/disconnect for the same
//! reason: dwell must never accumulate while nobody is at the machine.
//!
//! Deferred to later slices, recorded in the TCC record's amendment note:
//! `sensitive_context_entered/exited` rows around locks (they matter when
//! content streams exist), power suspend/resume/boundary events, and
//! NSWorkspace sleep observers.

use std::time::Instant;

use gilbreth_core::{Captured, EventPayload, SessionConnectionKind, Source};

use crate::idle::SAMPLE_INTERVAL;

/// The union of all active display bounds, in global display points — the
/// macOS analog of the Win32 virtual-screen metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtualScreenRect {
    pub(crate) x0: i32,
    pub(crate) y0: i32,
    pub(crate) width: i32,
    pub(crate) height: i32,
}

/// Point-in-time session state from the CoreGraphics session dictionary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionSnapshot {
    pub(crate) session_id: u32,
    pub(crate) on_console: bool,
    pub(crate) locked: bool,
}

/// Seeds once, then edge-detects session and display changes on the 1s
/// cadence. Generic over the providers so tests inject scripted state
/// without touching CoreGraphics.
pub(crate) struct SystemMonitor<S, V, I> {
    session_provider: S,
    screen_provider: V,
    info_provider: I,
    last_session: Option<SessionSnapshot>,
    last_screen: Option<VirtualScreenRect>,
    last_sample: Option<Instant>,
    seeded: bool,
    mechanism_was_on: bool,
    stream_was_enabled: bool,
}

impl<S, V, I> SystemMonitor<S, V, I>
where
    S: FnMut() -> Option<SessionSnapshot>,
    V: FnMut() -> Option<VirtualScreenRect>,
    I: FnMut() -> EventPayload,
{
    pub(crate) fn new(session_provider: S, screen_provider: V, info_provider: I) -> Self {
        Self {
            session_provider,
            screen_provider,
            info_provider,
            last_session: None,
            last_screen: None,
            last_sample: None,
            seeded: false,
            mechanism_was_on: false,
            stream_was_enabled: false,
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
    /// Foreground stream's sake. The split mirrors Windows, where the
    /// WTS-driven segment-end machinery is message-driven and independent
    /// of stream toggles (independent-review finding: with System off and
    /// Foreground on, locks must still block dwell — and disabling System
    /// mid-lock must not unblock a still-locked session).
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
                // Everything off: full re-baseline, exactly like the
                // Windows reseed — fresh seeds and no phantom edges for
                // state that changed while everything was off. With
                // Foreground also off there is no dwell to protect, so
                // dropping the session baseline is safe here (and only
                // here).
                self.seeded = false;
                self.last_session = None;
                self.last_screen = None;
                self.last_sample = None;
            }
            self.mechanism_was_on = false;
            self.stream_was_enabled = false;
            return;
        }
        if !stream_enabled && self.stream_was_enabled {
            // Stream off, mechanism still on: re-baseline the ROW state so
            // a later re-enable seeds afresh, but keep the session baseline
            // — session_blocked() must keep protecting Foreground.
            self.seeded = false;
            self.last_screen = None;
        }
        self.mechanism_was_on = true;
        self.stream_was_enabled = stream_enabled;

        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        if stream_enabled {
            if !self.seeded {
                self.seeded = true;
                events.push(Captured::new(Source::System, now, (self.info_provider)()));
                if let Some(screen) = (self.screen_provider)() {
                    self.last_screen = Some(screen);
                    events.push(Self::virtual_screen_event(screen, now));
                }
            } else if let Some(screen) = (self.screen_provider)() {
                if self.last_screen != Some(screen) {
                    self.last_screen = Some(screen);
                    events.push(Self::virtual_screen_event(screen, now));
                }
            }
        }

        if let Some(session) = (self.session_provider)() {
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
            // First observation is a baseline, not an edge — the Windows
            // pump emits no session event at startup either.
            self.last_session = Some(session);
        }
    }

    fn virtual_screen_event(screen: VirtualScreenRect, captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::VirtualScreen {
                x0: screen.x0,
                y0: screen.y0,
                x1: screen.x0.saturating_add(screen.width),
                y1: screen.y0.saturating_add(screen.height),
                width: screen.width,
                height: screen.height,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, time::Duration};

    use super::*;

    struct Script {
        session: Rc<RefCell<Option<SessionSnapshot>>>,
        screen: Rc<RefCell<Option<VirtualScreenRect>>>,
    }

    #[allow(clippy::type_complexity)]
    fn monitor() -> (
        Script,
        SystemMonitor<
            impl FnMut() -> Option<SessionSnapshot>,
            impl FnMut() -> Option<VirtualScreenRect>,
            impl FnMut() -> EventPayload,
        >,
    ) {
        let session = Rc::new(RefCell::new(Some(SessionSnapshot {
            session_id: 257,
            on_console: true,
            locked: false,
        })));
        let screen = Rc::new(RefCell::new(Some(VirtualScreenRect {
            x0: 0,
            y0: 0,
            width: 3456,
            height: 2234,
        })));
        let session_view = session.clone();
        let screen_view = screen.clone();
        (
            Script { session, screen },
            SystemMonitor::new(
                move || *session_view.borrow(),
                move || *screen_view.borrow(),
                || EventPayload::SystemInfo {
                    host: "test-host".to_string(),
                    os_version: "26.5.2".to_string(),
                    arch: "aarch64".to_string(),
                    processor_count: 10,
                    memory_total_bytes: 34_359_738_368,
                },
            ),
        )
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|event| event.payload.kind()).collect()
    }

    #[test]
    fn first_enabled_poll_seeds_info_and_screen_without_session_edges() {
        let (_script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        assert_eq!(kinds(&events), vec!["system_info", "virtual_screen"]);
        match &events[1].payload {
            EventPayload::VirtualScreen {
                x0,
                y0,
                x1,
                y1,
                width,
                height,
            } => {
                assert_eq!(
                    (*x0, *y0, *x1, *y1, *width, *height),
                    (0, 0, 3456, 2234, 3456, 2234)
                );
            }
            other => panic!("expected VirtualScreen, got {other:?}"),
        }
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn lock_and_unlock_edges_emit_once_and_block_foreground() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        let seed_count = events.len();

        script.session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert_eq!(events.len(), seed_count + 1);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionLock { session_id: 257 }
        ));
        assert!(monitor.session_blocked(), "locked blocks foreground");

        // Steady locked state: no repeats.
        monitor.poll(base + Duration::from_secs(4), true, true, &mut events);
        assert_eq!(events.len(), seed_count + 1);

        script.session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(6), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionUnlock { session_id: 257 }
        ));
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn fast_user_switch_maps_to_console_connect_and_disconnect() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        script.session.borrow_mut().as_mut().unwrap().on_console = false;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionDisconnect {
                session_id: 257,
                connection: SessionConnectionKind::Console,
            }
        ));
        assert!(monitor.session_blocked(), "off-console blocks foreground");

        script.session.borrow_mut().as_mut().unwrap().on_console = true;
        monitor.poll(base + Duration::from_secs(4), true, true, &mut events);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::SessionConnect {
                session_id: 257,
                connection: SessionConnectionKind::Console,
            }
        ));
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn display_change_emits_a_fresh_virtual_screen_row_once() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        let seed_count = events.len();

        *script.screen.borrow_mut() = Some(VirtualScreenRect {
            x0: -1920,
            y0: 0,
            width: 5376,
            height: 2234,
        });
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert_eq!(events.len(), seed_count + 1);
        assert!(matches!(
            events.last().unwrap().payload,
            EventPayload::VirtualScreen { x0: -1920, .. }
        ));

        monitor.poll(base + Duration::from_secs(4), true, true, &mut events);
        assert_eq!(events.len(), seed_count + 1, "unchanged screen: no repeat");
    }

    #[test]
    fn disable_rebaselines_so_off_period_changes_emit_no_phantom_edges() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        let seed_count = events.len();

        monitor.poll(base + Duration::from_secs(2), false, false, &mut events);
        assert!(!monitor.session_blocked(), "stale state cannot block");

        // While off: a lock came and went, and the display changed twice
        // ending where it started. Re-enable: fresh seeds, no lock/unlock
        // pair, no screen row beyond the seed.
        script.session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(10), true, true, &mut events);
        assert_eq!(
            kinds(&events[seed_count..]),
            vec!["system_info", "virtual_screen"],
            "re-enable reseeds without phantom session edges"
        );
    }

    #[test]
    fn foreground_only_config_still_blocks_on_lock_without_emitting_rows() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        // System stream OFF, session tracking ON (Foreground enabled).
        monitor.poll(base, false, true, &mut events);
        assert!(events.is_empty(), "no seeds without the System stream");

        script.session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), false, true, &mut events);
        assert!(events.is_empty(), "no session rows without the stream");
        assert!(
            monitor.session_blocked(),
            "the blocking mechanism works regardless of the stream toggle"
        );

        script.session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(events.is_empty());
        assert!(!monitor.session_blocked());
    }

    #[test]
    fn disabling_the_system_stream_mid_lock_keeps_blocking_while_tracked() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        script.session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(2), true, true, &mut events);
        assert!(monitor.session_blocked());

        // User disables the System stream while the screen is locked; the
        // Foreground stream is still on, so tracking must persist and the
        // still-locked session must keep blocking.
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(
            monitor.session_blocked(),
            "a still-locked session must not unblock on a stream toggle"
        );

        // Unlock is still observed (mechanism alive), just unemitted.
        let rows_before = events.len();
        script.session.borrow_mut().as_mut().unwrap().locked = false;
        monitor.poll(base + Duration::from_secs(6), false, true, &mut events);
        assert!(!monitor.session_blocked());
        assert_eq!(events.len(), rows_before, "no rows while the stream is off");
    }

    #[test]
    fn stream_reenable_mid_lock_seeds_without_a_phantom_lock_edge() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        let seed_count = events.len();

        // Stream goes off (mechanism stays on for Foreground); the lock
        // lands while rows are gated.
        monitor.poll(base + Duration::from_secs(2), false, true, &mut events);
        script.session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_secs(4), false, true, &mut events);
        assert!(monitor.session_blocked());
        assert_eq!(events.len(), seed_count, "no rows while the stream is off");

        // Stream back on mid-lock: fresh seeds, and the already-current
        // baseline must not replay the off-period lock as a new edge.
        monitor.poll(base + Duration::from_secs(6), true, true, &mut events);
        assert_eq!(
            kinds(&events[seed_count..]),
            vec!["system_info", "virtual_screen"],
            "re-seed only — the off-period lock is not a phantom edge \
             (its unlock row will land normally, matching Windows' \
             orphan-unlock behavior after a gated lock)"
        );
        assert!(monitor.session_blocked(), "still blocked while locked");
    }

    #[test]
    fn sampling_is_throttled_to_the_windows_cadence() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, true, &mut events);
        let seed_count = events.len();

        script.session.borrow_mut().as_mut().unwrap().locked = true;
        monitor.poll(base + Duration::from_millis(50), true, true, &mut events);
        assert_eq!(events.len(), seed_count, "throttled: no resample within 1s");

        monitor.poll(base + Duration::from_millis(1_050), true, true, &mut events);
        assert_eq!(
            events.len(),
            seed_count + 1,
            "edge lands on the next sample"
        );
    }
}
