//! Window lifecycle stream (LIN-2): `window_opened`/`window_closed` from
//! EWMH's `_NET_CLIENT_LIST` on the root window — the set of windows the
//! window manager manages, which is X11's authoritative "real top-level
//! windows" answer (the Windows backend reconstructs the same set from
//! WinEvents plus style filters). Event-driven like the foreground
//! stream: a root `PropertyNotify` naming the client list marks the
//! monitor dirty, and the 1 s recheck cadence catches anything a window
//! manager forgets to announce.
//!
//! The Windows `WindowState` semantics carry over verbatim:
//!
//! - The startup read SEEDS silently (origin `seeded`, no rows) so
//!   already-open windows are known; their eventual close rows carry the
//!   seeded origin.
//! - A window appearing after that emits `window_opened` with origin
//!   `observed`; its close row reuses the OPEN-time `WindowRef` (title as
//!   of open, the focus-time-read rule's lifecycle twin) with
//!   `open_for_ms` attributed.
//! - Pump shutdown closes every tracked window with origin `synthesized`.
//!
//! Dock and desktop windows (`_NET_WM_WINDOW_TYPE_DOCK`/`_DESKTOP`: the
//! panel, the desktop itself) are excluded at first sight — the Windows
//! filter excludes the taskbar/desktop the same way — and remembered so
//! the exclusion costs one type read per window, not per diff. A failed
//! client-list read is a blackout: state holds, nothing is synthesized
//! (the foreground blackout rule).
//!
//! Rows gate at `send` (Source::Window rides the `windows` toggle, the
//! Windows posture); the tracker advances regardless, so a toggle-off
//! period never corrupts open/close pairing — a window opened while the
//! stream was off simply has no open row, exactly as on Windows.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use gilbreth_core::{Captured, EventPayload, Source, WindowLifecycleOrigin, WindowRef};

/// Fallback list-read cadence while no `PropertyNotify` marks the monitor
/// dirty — the foreground stream's safety-net shape.
const CLIENT_LIST_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// One managed window as the provider resolves it at first sight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowDetails {
    pub(crate) pid: u32,
    pub(crate) exe: String,
    pub(crate) title: String,
    /// True for dock/desktop windows, which the stream excludes.
    pub(crate) excluded: bool,
}

struct OpenWindow {
    window: WindowRef,
    opened_at: Instant,
    origin: WindowLifecycleOrigin,
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Diffs the client list and emits lifecycle rows. Generic over the
/// providers so tests inject scripted lists without an X server.
pub(crate) struct WindowMonitor<CL, WD> {
    list_provider: CL,
    details_provider: WD,
    windows: HashMap<u32, OpenWindow>,
    /// Dock/desktop ids currently in the client list, ignored until they
    /// vanish.
    excluded: HashSet<u32>,
    seeded: bool,
    last_read: Option<Instant>,
}

impl<CL, WD> WindowMonitor<CL, WD>
where
    CL: FnMut() -> Option<Vec<u32>>,
    WD: FnMut(u32) -> Option<WindowDetails>,
{
    pub(crate) fn new(list_provider: CL, details_provider: WD) -> Self {
        Self {
            list_provider,
            details_provider,
            windows: HashMap::new(),
            excluded: HashSet::new(),
            seeded: false,
            last_read: None,
        }
    }

    /// One service-cadence pass. `dirty` is the pump's `PropertyNotify`
    /// edge; the list is read on that edge and on the recheck cadence.
    pub(crate) fn poll(&mut self, now: Instant, dirty: bool, events: &mut Vec<Captured>) {
        let read_due = dirty
            || self.last_read.is_none_or(|last| {
                now.saturating_duration_since(last) >= CLIENT_LIST_RECHECK_INTERVAL
            });
        if !read_due {
            return;
        }
        self.last_read = Some(now);
        let Some(list) = (self.list_provider)() else {
            return;
        };
        let live: HashSet<u32> = list.into_iter().collect();

        // Vanished first (Windows emits DESTROY before the replacement's
        // CREATE lands in practice; either order is consistent, one is
        // picked deterministically).
        let gone: Vec<u32> = self
            .windows
            .keys()
            .filter(|xid| !live.contains(xid))
            .copied()
            .collect();
        for xid in gone {
            if let Some(open) = self.windows.remove(&xid) {
                events.push(Captured::new(
                    Source::Window,
                    now,
                    EventPayload::WindowClosed {
                        window: open.window,
                        open_for_ms: duration_ms(now.saturating_duration_since(open.opened_at)),
                        origin: open.origin,
                    },
                ));
            }
        }
        self.excluded.retain(|xid| live.contains(xid));

        let seeding = !self.seeded;
        for xid in live {
            if self.windows.contains_key(&xid) || self.excluded.contains(&xid) {
                continue;
            }
            // A window that vanishes between the list read and its detail
            // reads was open for less than one cadence tick; it is skipped
            // rather than fabricated (its close would race too).
            let Some(details) = (self.details_provider)(xid) else {
                continue;
            };
            if details.excluded {
                self.excluded.insert(xid);
                continue;
            }
            let window = WindowRef {
                hwnd: u64::from(xid),
                exe: details.exe,
                title: details.title,
                pid: details.pid,
            };
            let origin = if seeding {
                WindowLifecycleOrigin::Seeded
            } else {
                WindowLifecycleOrigin::Observed
            };
            self.windows.insert(
                xid,
                OpenWindow {
                    window: window.clone(),
                    opened_at: now,
                    origin,
                },
            );
            if !seeding {
                events.push(Captured::new(
                    Source::Window,
                    now,
                    EventPayload::WindowOpened { window, origin },
                ));
            }
        }
        self.seeded = true;
    }

    /// Pump shutdown: every tracked window closes with origin
    /// `synthesized`, exactly as the Windows shutdown flush does.
    pub(crate) fn flush_at(&mut self, now: Instant, events: &mut Vec<Captured>) {
        let windows = std::mem::take(&mut self.windows);
        for (_, open) in windows {
            events.push(Captured::new(
                Source::Window,
                now,
                EventPayload::WindowClosed {
                    window: open.window,
                    open_for_ms: duration_ms(now.saturating_duration_since(open.opened_at)),
                    origin: WindowLifecycleOrigin::Synthesized,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    struct Script {
        list: Rc<RefCell<Option<Vec<u32>>>>,
    }

    #[allow(clippy::type_complexity)]
    fn monitor(
        initial: Vec<u32>,
    ) -> (
        Script,
        WindowMonitor<impl FnMut() -> Option<Vec<u32>>, impl FnMut(u32) -> Option<WindowDetails>>,
    ) {
        let list = Rc::new(RefCell::new(Some(initial)));
        let view = Rc::clone(&list);
        (
            Script { list },
            WindowMonitor::new(
                move || view.borrow().clone(),
                |xid| {
                    Some(WindowDetails {
                        pid: 1000 + xid,
                        exe: format!("/usr/bin/app{xid}"),
                        title: format!("window {xid}"),
                        // 90s are docks/desktops in this script.
                        excluded: xid >= 90,
                    })
                },
            ),
        )
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|event| event.payload.kind()).collect()
    }

    #[test]
    fn startup_seeds_silently_and_seeded_closes_carry_the_origin() {
        let (script, mut monitor) = monitor(vec![7, 8]);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        assert!(events.is_empty(), "the startup read seeds without rows");

        // A seeded window closing later records the seeded origin.
        *script.list.borrow_mut() = Some(vec![8]);
        monitor.poll(base + Duration::from_secs(5), true, &mut events);
        assert_eq!(kinds(&events), vec!["window_closed"]);
        match &events[0].payload {
            EventPayload::WindowClosed {
                window,
                open_for_ms,
                origin,
            } => {
                assert_eq!(window.hwnd, 7);
                assert_eq!(window.title, "window 7");
                assert_eq!(*open_for_ms, 5_000);
                assert_eq!(*origin, WindowLifecycleOrigin::Seeded);
            }
            other => panic!("expected window_closed, got {other:?}"),
        }
    }

    #[test]
    fn observed_windows_open_and_close_with_open_time_identity() {
        let (script, mut monitor) = monitor(vec![7]);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.list.borrow_mut() = Some(vec![7, 9]);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert_eq!(kinds(&events), vec!["window_opened"]);
        match &events[0].payload {
            EventPayload::WindowOpened { window, origin } => {
                assert_eq!(window.hwnd, 9);
                assert_eq!(window.exe, "/usr/bin/app9");
                assert_eq!(*origin, WindowLifecycleOrigin::Observed);
            }
            other => panic!("expected window_opened, got {other:?}"),
        }
        events.clear();

        *script.list.borrow_mut() = Some(vec![7]);
        monitor.poll(base + Duration::from_secs(10), true, &mut events);
        match &events[0].payload {
            EventPayload::WindowClosed {
                window,
                open_for_ms,
                origin,
            } => {
                assert_eq!(window.hwnd, 9);
                assert_eq!(window.title, "window 9", "open-time title kept");
                assert_eq!(*open_for_ms, 8_000);
                assert_eq!(*origin, WindowLifecycleOrigin::Observed);
            }
            other => panic!("expected window_closed, got {other:?}"),
        }
    }

    #[test]
    fn docks_and_desktops_never_row_and_forget_on_vanish() {
        let (script, mut monitor) = monitor(vec![7, 90]);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        // The dock joining or leaving the list emits nothing.
        *script.list.borrow_mut() = Some(vec![7, 90, 91]);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        *script.list.borrow_mut() = Some(vec![7]);
        monitor.poll(base + Duration::from_secs(4), true, &mut events);
        assert!(events.is_empty(), "excluded types never produce rows");
    }

    #[test]
    fn a_blackout_keeps_state_and_synthesizes_nothing() {
        let (script, mut monitor) = monitor(vec![7]);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.list.borrow_mut() = None;
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert!(events.is_empty(), "a failed read fabricates nothing");

        // The list comes back without the window: a real close, timed
        // from open.
        *script.list.borrow_mut() = Some(vec![]);
        monitor.poll(base + Duration::from_secs(3), true, &mut events);
        assert_eq!(kinds(&events), vec!["window_closed"]);
    }

    #[test]
    fn reads_throttle_to_the_recheck_cadence_unless_dirty() {
        let calls = Rc::new(RefCell::new(0u32));
        let calls_view = Rc::clone(&calls);
        let mut monitor = WindowMonitor::new(
            move || {
                *calls_view.borrow_mut() += 1;
                Some(vec![7])
            },
            |_| None,
        );
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, false, &mut events);
        assert_eq!(*calls.borrow(), 1, "first pass reads");
        monitor.poll(base + Duration::from_millis(50), false, &mut events);
        assert_eq!(*calls.borrow(), 1, "not dirty, not due: no read");
        monitor.poll(base + Duration::from_millis(100), true, &mut events);
        assert_eq!(*calls.borrow(), 2, "the PropertyNotify edge reads at once");
        monitor.poll(base + Duration::from_millis(1_150), false, &mut events);
        assert_eq!(*calls.borrow(), 3, "the recheck cadence reads");
    }

    #[test]
    fn shutdown_flush_synthesizes_closes_for_everything_tracked() {
        let (script, mut monitor) = monitor(vec![7]);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.list.borrow_mut() = Some(vec![7, 9]);
        monitor.poll(base + Duration::from_secs(1), true, &mut events);
        events.clear();

        monitor.flush_at(base + Duration::from_secs(4), &mut events);
        assert_eq!(events.len(), 2, "every tracked window closes");
        let mut origins_and_ids: Vec<(u64, u64)> = events
            .iter()
            .map(|event| match &event.payload {
                EventPayload::WindowClosed {
                    window,
                    open_for_ms,
                    origin: WindowLifecycleOrigin::Synthesized,
                } => (window.hwnd, *open_for_ms),
                other => panic!("expected synthesized close, got {other:?}"),
            })
            .collect();
        origins_and_ids.sort();
        assert_eq!(origins_and_ids, vec![(7, 4_000), (9, 3_000)]);
    }

    #[test]
    fn a_window_vanishing_before_details_resolve_is_skipped_not_fabricated() {
        let list = Rc::new(RefCell::new(Some(vec![7u32])));
        let view = Rc::clone(&list);
        let mut monitor = WindowMonitor::new(
            move || view.borrow().clone(),
            |_| None, // every detail read races a closing window
        );
        let base = Instant::now();
        let mut events = Vec::new();
        monitor.poll(base, true, &mut events);
        *list.borrow_mut() = Some(vec![]);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert!(events.is_empty(), "nothing opened, so nothing closes");
    }
}
