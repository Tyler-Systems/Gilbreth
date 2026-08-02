//! Mouse stream derivation (LIN-1). The Windows `MouseState` machine as the
//! macOS port carries it, adapted to X11's input shape:
//!
//! - `MouseClick` on button-down; `MouseDoubleClick` on the second
//!   same-button down within the interval AND box (reconstructed, the
//!   Windows way); `interval_ms` is the *measured* elapsed.
//! - `MouseDrag` on button-up through a per-button accumulator; a gesture
//!   is a drag when it leaves the drag box OR its path length reaches the
//!   box's max dimension (catches a return-to-origin drag).
//! - `MouseMove` aggregated on the 250 ms flush. **In-drag motion counts
//!   into BOTH the move aggregate and the drag accumulator** — a drag
//!   emits `[MouseMove, MouseDrag]` sharing the deltas, exactly as Windows
//!   does. `distance_px` is path length; `dx/dy_total` are net.
//! - `MouseWheel`: X wheels are discrete buttons (4/5 vertical, 6/7
//!   horizontal), one row per tick at Windows ±120 units — including the
//!   server-emulated ticks a smooth-scrolling touchpad quantizes to, which
//!   is the same notch semantics, at notch granularity. The smooth-scroll
//!   valuators are deliberately never read, so no tick is double-counted.
//!
//! Positions are `Option`: XI2 raw events carry no pointer position, so
//! the pump samples `QueryPointer` once per pass that carries input, and a
//! failed sample stores absent rather than fabricated coordinates. The
//! click/drag metrics are the shared fallback constants (X11 has no
//! standard pointer-metrics API; recorded in the capability matrix). The
//! machine advances regardless of the stream toggle; gating is only at
//! `send` (Windows parity). No input-relay detector exists on this
//! platform, so `input_origin` stays absent.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use gilbreth_core::{Captured, EventPayload, MouseButton, MouseWheelAxis, Source, WindowRef};

/// Trailing-move flush cadence — Windows `MOUSE_MOVE_FLUSH_INTERVAL`.
pub(crate) const MOVE_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
/// Wheel tick → Windows wheel units (WHEEL_DELTA per notch).
const WHEEL_UNIT: i32 = 120;
/// The shared fallback pointer metrics (the macOS fallback values): X11
/// exposes no system double-click/drag metrics to read.
const DOUBLE_CLICK_MS: u64 = 500;
const DOUBLE_CLICK_HALF_PX: i32 = 4;
const DRAG_HALF_PX: i32 = 8;

/// One XI2 raw pointer event reduced to the fields the derivation needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RawMouseEvent {
    pub(crate) kind: RawMouseKind,
    /// The per-pass `QueryPointer` sample; `None` when the sample failed.
    pub(crate) pos: Option<(i32, i32)>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RawMouseKind {
    Down(MouseButton),
    Up(MouseButton),
    /// Raw motion; deltas are the x/y valuator changes.
    Moved {
        dx: i32,
        dy: i32,
    },
    /// One discrete wheel tick: +1 is up/right, -1 down/left.
    Wheel {
        axis: MouseWheelAxis,
        ticks: i32,
    },
}

fn distance_px(dx: i32, dy: i32) -> u64 {
    let d = ((f64::from(dx) * f64::from(dx)) + (f64::from(dy) * f64::from(dy))).sqrt();
    d.round() as u64
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct PendingMove {
    started_at: Instant,
    last_at: Instant,
    dx_total: i64,
    dy_total: i64,
    distance_px: u64,
    raw_event_count: u64,
    pos: Option<(i32, i32)>,
    window: Option<WindowRef>,
}

struct ActiveButton {
    started_at: Instant,
    start: Option<(i32, i32)>,
    end: Option<(i32, i32)>,
    dx_total: i64,
    dy_total: i64,
    distance_px: u64,
    raw_event_count: u64,
    window: Option<WindowRef>,
    /// True only if this button-down was NOT itself a double-click, so it
    /// can seed a future one (Windows' triple-click suppression).
    seed_completed_click: bool,
}

#[derive(Clone, Copy)]
struct CompletedClick {
    button: MouseButton,
    down_at: Instant,
    pos: Option<(i32, i32)>,
    hwnd: Option<u64>,
}

pub(crate) struct MouseState {
    pending_move: Option<PendingMove>,
    active: HashMap<MouseButton, ActiveButton>,
    last_completed_click: Option<CompletedClick>,
}

impl MouseState {
    pub(crate) fn new() -> Self {
        Self {
            pending_move: None,
            active: HashMap::new(),
            last_completed_click: None,
        }
    }

    /// Feed one raw mouse event; appends any emitted rows to `out`.
    pub(crate) fn on_event(
        &mut self,
        raw: RawMouseEvent,
        window: Option<WindowRef>,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        match raw.kind {
            RawMouseKind::Moved { dx, dy } => {
                self.record_move(dx, dy, raw.pos, window.clone(), now);
                for button in self.active.values_mut() {
                    button.add_movement(dx, dy, raw.pos, window.clone());
                }
            }
            RawMouseKind::Down(button) => {
                self.flush_move(out);
                self.on_button_down(button, raw.pos, window, now, out);
            }
            RawMouseKind::Up(button) => {
                self.flush_move(out);
                self.on_button_up(button, raw.pos, now, out);
            }
            RawMouseKind::Wheel { axis, ticks } => {
                if ticks == 0 {
                    return;
                }
                // Discrete input flushes the pending move first, so stored
                // order stays scroll-after-motion like the other platforms.
                self.flush_move(out);
                let (x, y) = split_pos(raw.pos);
                out.push(Captured::new(
                    Source::Mouse,
                    now,
                    EventPayload::MouseWheel {
                        axis,
                        delta: ticks.saturating_mul(WHEEL_UNIT),
                        x,
                        y,
                        window,
                        input_origin: None,
                    },
                ));
            }
        }
    }

    /// A session/power boundary drops active-button and double-click
    /// tracking so no drag or click pair spans the boundary (the macOS
    /// reset, ported; the trailing move aggregate still flushes normally —
    /// its content is pre-boundary motion).
    pub(crate) fn reset_after_boundary(&mut self) {
        self.active.clear();
        self.last_completed_click = None;
    }

    /// Called once per pump service pass: flush a trailing move aggregate
    /// whose window has elapsed (Windows' per-message `flush_due`).
    pub(crate) fn flush_due(&mut self, now: Instant, out: &mut Vec<Captured>) {
        if self
            .pending_move
            .as_ref()
            .is_some_and(|m| now.saturating_duration_since(m.started_at) >= MOVE_FLUSH_INTERVAL)
        {
            self.flush_move(out);
        }
    }

    fn record_move(
        &mut self,
        dx: i32,
        dy: i32,
        pos: Option<(i32, i32)>,
        window: Option<WindowRef>,
        now: Instant,
    ) {
        let dist = distance_px(dx, dy);
        match &mut self.pending_move {
            Some(m) => {
                m.last_at = now;
                m.dx_total = m.dx_total.saturating_add(i64::from(dx));
                m.dy_total = m.dy_total.saturating_add(i64::from(dy));
                m.distance_px = m.distance_px.saturating_add(dist);
                m.raw_event_count = m.raw_event_count.saturating_add(1);
                if pos.is_some() {
                    m.pos = pos;
                }
                if window.is_some() {
                    m.window = window;
                }
            }
            None => {
                self.pending_move = Some(PendingMove {
                    started_at: now,
                    last_at: now,
                    dx_total: i64::from(dx),
                    dy_total: i64::from(dy),
                    distance_px: dist,
                    raw_event_count: 1,
                    pos,
                    window,
                });
            }
        }
    }

    fn flush_move(&mut self, out: &mut Vec<Captured>) {
        let Some(m) = self.pending_move.take() else {
            return;
        };
        let (x, y) = split_pos(m.pos);
        out.push(Captured::new(
            Source::Mouse,
            m.last_at,
            EventPayload::MouseMove {
                dx_total: m.dx_total,
                dy_total: m.dy_total,
                distance_px: m.distance_px,
                raw_event_count: m.raw_event_count,
                duration_ms: duration_ms(m.last_at.saturating_duration_since(m.started_at)),
                x,
                y,
                window: m.window,
                input_origin: None,
            },
        ));
    }

    fn on_button_down(
        &mut self,
        button: MouseButton,
        pos: Option<(i32, i32)>,
        window: Option<WindowRef>,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        let interval_ms = self.double_click_interval_ms(button, pos, window.as_ref(), now);

        self.active.insert(
            button,
            ActiveButton {
                started_at: now,
                start: pos,
                end: pos,
                dx_total: 0,
                dy_total: 0,
                distance_px: 0,
                raw_event_count: 0,
                window: window.clone(),
                seed_completed_click: interval_ms.is_none(),
            },
        );

        let (x, y) = split_pos(pos);
        out.push(Captured::new(
            Source::Mouse,
            now,
            EventPayload::MouseClick {
                button,
                x,
                y,
                window: window.clone(),
                input_origin: None,
            },
        ));

        if let Some(interval_ms) = interval_ms {
            out.push(Captured::new(
                Source::Mouse,
                now,
                EventPayload::MouseDoubleClick {
                    button,
                    interval_ms,
                    x,
                    y,
                    window,
                    input_origin: None,
                },
            ));
            self.last_completed_click = None;
        }
    }

    fn on_button_up(
        &mut self,
        button: MouseButton,
        pos: Option<(i32, i32)>,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        let Some(mut active) = self.active.remove(&button) else {
            return;
        };
        if pos.is_some() {
            active.end = pos;
        }

        if active.is_drag() {
            out.push(active.into_drag(button, now));
            self.last_completed_click = None;
        } else if active.seed_completed_click {
            self.last_completed_click = Some(CompletedClick {
                button,
                down_at: active.started_at,
                pos: active.start,
                hwnd: active.window.as_ref().map(|w| w.hwnd),
            });
        } else {
            self.last_completed_click = None;
        }
    }

    /// `Some(measured_interval_ms)` when this down completes a double-click
    /// with the previous click (same button, within the interval, within
    /// the box, same known window — the Windows reconstruction; unknown
    /// positions decline rather than guess), else `None`.
    fn double_click_interval_ms(
        &self,
        button: MouseButton,
        pos: Option<(i32, i32)>,
        window: Option<&WindowRef>,
        now: Instant,
    ) -> Option<u64> {
        let prev = self.last_completed_click?;
        if prev.button != button {
            return None;
        }
        let elapsed = now.saturating_duration_since(prev.down_at);
        if elapsed > Duration::from_millis(DOUBLE_CLICK_MS) {
            return None;
        }
        let hwnd = window?.hwnd;
        if prev.hwnd? != hwnd {
            return None;
        }
        let (x, y) = pos?;
        let (px, py) = prev.pos?;
        if (x - px).abs() > DOUBLE_CLICK_HALF_PX || (y - py).abs() > DOUBLE_CLICK_HALF_PX {
            return None;
        }
        Some(duration_ms(elapsed))
    }
}

fn split_pos(pos: Option<(i32, i32)>) -> (Option<i32>, Option<i32>) {
    match pos {
        Some((x, y)) => (Some(x), Some(y)),
        None => (None, None),
    }
}

impl ActiveButton {
    fn add_movement(
        &mut self,
        dx: i32,
        dy: i32,
        end: Option<(i32, i32)>,
        window: Option<WindowRef>,
    ) {
        self.dx_total = self.dx_total.saturating_add(i64::from(dx));
        self.dy_total = self.dy_total.saturating_add(i64::from(dy));
        self.distance_px = self.distance_px.saturating_add(distance_px(dx, dy));
        self.raw_event_count = self.raw_event_count.saturating_add(1);
        if end.is_some() {
            self.end = end;
        }
        if window.is_some() {
            self.window = window;
        }
    }

    fn is_drag(&self) -> bool {
        let max_dim = u64::try_from(DRAG_HALF_PX).unwrap_or(1);
        let displaced = match (self.start, self.end) {
            (Some((sx, sy)), Some((ex, ey))) => {
                (ex - sx).abs() > DRAG_HALF_PX || (ey - sy).abs() > DRAG_HALF_PX
            }
            // Unknown positions: the path length below still decides.
            _ => false,
        };
        displaced || self.distance_px >= max_dim
    }

    fn into_drag(self, button: MouseButton, ended_at: Instant) -> Captured {
        let (start_x, start_y) = split_pos(self.start);
        let (end_x, end_y) = split_pos(self.end);
        Captured::new(
            Source::Mouse,
            ended_at,
            EventPayload::MouseDrag {
                button,
                dx_total: self.dx_total,
                dy_total: self.dy_total,
                distance_px: self.distance_px,
                raw_event_count: self.raw_event_count,
                duration_ms: duration_ms(ended_at.saturating_duration_since(self.started_at)),
                start_x,
                start_y,
                end_x,
                end_y,
                window: self.window,
                selection_candidate: button == MouseButton::Left,
                input_origin: None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(hwnd: u64) -> Option<WindowRef> {
        Some(WindowRef {
            hwnd,
            exe: "/usr/bin/app".to_string(),
            title: String::new(),
            pid: 400,
        })
    }

    fn down(button: MouseButton, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Down(button),
            pos: Some((x, y)),
        }
    }
    fn up(button: MouseButton, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Up(button),
            pos: Some((x, y)),
        }
    }
    fn moved(dx: i32, dy: i32, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Moved { dx, dy },
            pos: Some((x, y)),
        }
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|e| e.payload.kind()).collect()
    }

    #[test]
    fn a_single_click_emits_click_on_down_and_nothing_on_up() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();

        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        assert_eq!(kinds(&out), vec!["mouse_click"]);
        state.on_event(
            up(MouseButton::Left, 100, 100),
            win(1),
            base + Duration::from_millis(30),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            vec!["mouse_click"],
            "a still click emits no drag"
        );
    }

    #[test]
    fn a_second_fast_click_in_place_adds_a_double_click() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();

        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            up(MouseButton::Left, 100, 100),
            win(1),
            base + Duration::from_millis(20),
            &mut out,
        );
        state.on_event(
            down(MouseButton::Left, 101, 100),
            win(1),
            base + Duration::from_millis(120),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            vec!["mouse_click", "mouse_click", "mouse_double_click"]
        );
        match &out[2].payload {
            EventPayload::MouseDoubleClick { interval_ms, .. } => {
                assert_eq!(
                    *interval_ms, 120,
                    "measured interval, not the fixed setting"
                );
            }
            other => panic!("expected double click, got {other:?}"),
        }
    }

    #[test]
    fn three_fast_clicks_do_not_chain_a_second_double() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        for t in [0u64, 100, 200] {
            state.on_event(
                down(MouseButton::Left, 100, 100),
                win(1),
                base + Duration::from_millis(t),
                &mut out,
            );
            state.on_event(
                up(MouseButton::Left, 100, 100),
                win(1),
                base + Duration::from_millis(t + 10),
                &mut out,
            );
        }
        assert_eq!(
            kinds(&out),
            vec![
                "mouse_click",
                "mouse_click",
                "mouse_double_click",
                "mouse_click"
            ]
        );
    }

    #[test]
    fn unknown_positions_never_reconstruct_a_double_click() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        let blind_down = RawMouseEvent {
            kind: RawMouseKind::Down(MouseButton::Left),
            pos: None,
        };
        let blind_up = RawMouseEvent {
            kind: RawMouseKind::Up(MouseButton::Left),
            pos: None,
        };
        state.on_event(blind_down, win(1), base, &mut out);
        state.on_event(blind_up, win(1), base + Duration::from_millis(20), &mut out);
        state.on_event(
            blind_down,
            win(1),
            base + Duration::from_millis(120),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            vec!["mouse_click", "mouse_click"],
            "the box test declines rather than guesses"
        );
    }

    #[test]
    fn a_drag_emits_move_then_drag_sharing_the_deltas() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();

        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            moved(20, 10, 120, 110),
            win(1),
            base + Duration::from_millis(50),
            &mut out,
        );
        state.on_event(
            up(MouseButton::Left, 120, 110),
            win(1),
            base + Duration::from_millis(100),
            &mut out,
        );

        assert_eq!(kinds(&out), vec!["mouse_click", "mouse_move", "mouse_drag"]);
        match &out[2].payload {
            EventPayload::MouseDrag {
                dx_total,
                dy_total,
                distance_px,
                raw_event_count,
                duration_ms,
                start_x,
                start_y,
                end_x,
                end_y,
                selection_candidate,
                ..
            } => {
                assert_eq!((*dx_total, *dy_total), (20, 10));
                assert_eq!(*distance_px, 22, "path length round(sqrt(500))");
                assert_eq!(*raw_event_count, 1);
                assert_eq!(*duration_ms, 100);
                assert_eq!(
                    (*start_x, *start_y, *end_x, *end_y),
                    (Some(100), Some(100), Some(120), Some(110))
                );
                assert!(*selection_candidate, "left-button drag");
            }
            other => panic!("expected drag, got {other:?}"),
        }
        match &out[1].payload {
            EventPayload::MouseMove {
                dx_total, dy_total, ..
            } => {
                assert_eq!(
                    (*dx_total, *dy_total),
                    (20, 10),
                    "the move carries the SAME deltas (Windows parity)"
                );
            }
            other => panic!("expected move, got {other:?}"),
        }
    }

    #[test]
    fn a_return_to_origin_drag_is_still_a_drag_by_path_length() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            moved(50, 0, 150, 100),
            win(1),
            base + Duration::from_millis(20),
            &mut out,
        );
        state.on_event(
            moved(-50, 0, 100, 100),
            win(1),
            base + Duration::from_millis(40),
            &mut out,
        );
        state.on_event(
            up(MouseButton::Left, 100, 100),
            win(1),
            base + Duration::from_millis(60),
            &mut out,
        );
        let drag = out
            .iter()
            .find(|e| e.payload.kind() == "mouse_drag")
            .expect("path length forces a drag");
        match &drag.payload {
            EventPayload::MouseDrag {
                dx_total,
                distance_px,
                ..
            } => {
                assert_eq!(*dx_total, 0);
                assert_eq!(*distance_px, 100);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn trailing_move_flushes_on_the_cadence() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(moved(5, 5, 105, 105), win(1), base, &mut out);
        state.flush_due(base + Duration::from_millis(100), &mut out);
        assert!(out.is_empty(), "not due at 100ms");
        state.flush_due(base + Duration::from_millis(250), &mut out);
        assert_eq!(kinds(&out), vec!["mouse_move"]);
    }

    #[test]
    fn wheel_ticks_scale_to_windows_units_per_axis() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(
            RawMouseEvent {
                kind: RawMouseKind::Wheel {
                    axis: MouseWheelAxis::Vertical,
                    ticks: 1,
                },
                pos: Some((50, 60)),
            },
            win(1),
            base,
            &mut out,
        );
        state.on_event(
            RawMouseEvent {
                kind: RawMouseKind::Wheel {
                    axis: MouseWheelAxis::Horizontal,
                    ticks: -1,
                },
                pos: Some((50, 60)),
            },
            win(1),
            base,
            &mut out,
        );
        assert_eq!(kinds(&out), vec!["mouse_wheel", "mouse_wheel"]);
        match (&out[0].payload, &out[1].payload) {
            (
                EventPayload::MouseWheel {
                    axis: a0,
                    delta: d0,
                    ..
                },
                EventPayload::MouseWheel {
                    axis: a1,
                    delta: d1,
                    ..
                },
            ) => {
                assert_eq!((*a0, *d0), (MouseWheelAxis::Vertical, 120));
                assert_eq!((*a1, *d1), (MouseWheelAxis::Horizontal, -120));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn wheel_input_flushes_the_pending_move_first() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(moved(5, 5, 105, 105), win(1), base, &mut out);
        state.on_event(
            RawMouseEvent {
                kind: RawMouseKind::Wheel {
                    axis: MouseWheelAxis::Vertical,
                    ticks: 1,
                },
                pos: Some((105, 105)),
            },
            win(1),
            base + Duration::from_millis(10),
            &mut out,
        );
        assert_eq!(kinds(&out), vec!["mouse_move", "mouse_wheel"]);
    }

    #[test]
    fn non_left_button_drag_is_not_a_selection_candidate() {
        let mut state = MouseState::new();
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(down(MouseButton::Right, 100, 100), win(1), base, &mut out);
        state.on_event(
            moved(40, 40, 140, 140),
            win(1),
            base + Duration::from_millis(20),
            &mut out,
        );
        state.on_event(
            up(MouseButton::Right, 140, 140),
            win(1),
            base + Duration::from_millis(40),
            &mut out,
        );
        let drag = out
            .iter()
            .find(|e| e.payload.kind() == "mouse_drag")
            .expect("drag");
        match &drag.payload {
            EventPayload::MouseDrag {
                selection_candidate,
                ..
            } => assert!(!selection_candidate),
            _ => unreachable!(),
        }
    }
}
