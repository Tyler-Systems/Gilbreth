//! Mouse stream derivation (the macOS TCC and stream rules,
//! Keyboard+Mouse amendment). The Windows `MouseState` machine ported
//! wholesale, verified against that source:
//!
//! - `MouseClick` on button-down; `MouseDoubleClick` on the second same-button
//!   down within the system interval AND box (reconstructed like Windows, not
//!   read from the window-server `kCGMouseEventClickState` annotation, which
//!   is unreliable at the HID tap point); `interval_ms` is the *measured*
//!   elapsed.
//! - `MouseDrag` on button-up through a per-button accumulator; a gesture is a
//!   drag when it leaves the system drag box OR its path length reaches the
//!   box's max dimension (catches a return-to-origin drag).
//! - `MouseMove` aggregated on the 250 ms flush. **In-drag motion is counted
//!   into BOTH the move aggregate and the drag accumulator** — a drag gesture
//!   emits `[MouseMove, MouseDrag]` sharing the deltas, exactly as Windows
//!   does (the "exclude moves during a drag" idea is explicitly NOT
//!   replicated). `distance_px` is path length; `dx/dy_total` are net.
//! - `MouseWheel`: discrete line deltas scaled to Windows ±120 units, one row
//!   per event per axis; continuous/trackpad deltas accumulate and flush on
//!   the move cadence; momentum-phase events are dropped.
//!
//! Coordinates are global display points; the attributed `window` is supplied
//! by the caller (the frontmost window, shared with the Foreground segment),
//! not the window under the cursor. The machine advances regardless of the
//! stream toggle; gating is only at `send` (Windows parity).

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use gilbreth_core::{
    Captured, EventPayload, InputOrigin, MouseButton, MouseWheelAxis, Source, WindowRef,
};

/// Trailing-move flush cadence — Windows `MOUSE_MOVE_FLUSH_INTERVAL`.
pub(crate) const MOVE_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
/// Discrete scroll line delta → Windows wheel units (WHEEL_DELTA per notch).
const WHEEL_UNIT: i32 = 120;
const FALLBACK_DOUBLE_CLICK_MS: u64 = 500;
const FALLBACK_DOUBLE_CLICK_HALF_PX: i32 = 4;
const FALLBACK_DRAG_HALF_PX: i32 = 8;

/// System pointer metrics (injected so tests are deterministic and the
/// production reader stays a thin CoreGraphics/AppKit shim).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PointerMetrics {
    pub(crate) double_click_interval: Duration,
    pub(crate) double_click_half: i32,
    pub(crate) drag_half: i32,
}

impl Default for PointerMetrics {
    fn default() -> Self {
        Self {
            double_click_interval: Duration::from_millis(FALLBACK_DOUBLE_CLICK_MS),
            double_click_half: FALLBACK_DOUBLE_CLICK_HALF_PX,
            drag_half: FALLBACK_DRAG_HALF_PX,
        }
    }
}

/// One mouse CGEvent reduced to the fields the derivation needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RawMouseEvent {
    pub(crate) kind: RawMouseKind,
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) input_origin: Option<InputOrigin>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RawMouseKind {
    Down(MouseButton),
    Up(MouseButton),
    /// Movement (a `mouseMoved` or any `*MouseDragged`); deltas are the
    /// `kCGMouseEventDeltaX/Y` fields.
    Moved {
        dx: i32,
        dy: i32,
    },
    Wheel(RawWheel),
}

/// Raw scroll fields; the derivation applies the unit/coalesce/momentum rules.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RawWheel {
    pub(crate) continuous: bool,
    pub(crate) momentum: bool,
    /// Discrete line deltas (`kCGScrollWheelEventDeltaAxis1/2`): vertical,
    /// horizontal.
    pub(crate) line_v: i32,
    pub(crate) line_h: i32,
    /// Continuous fixed-point deltas (`kCGScrollWheelEventFixedPtDeltaAxis*`).
    pub(crate) fixed_v: f64,
    pub(crate) fixed_h: f64,
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
    x: i32,
    y: i32,
    input_origin: Option<InputOrigin>,
    window: Option<WindowRef>,
}

struct ActiveButton {
    started_at: Instant,
    start: (i32, i32),
    end: (i32, i32),
    dx_total: i64,
    dy_total: i64,
    distance_px: u64,
    raw_event_count: u64,
    input_origin: Option<InputOrigin>,
    window: Option<WindowRef>,
    /// True only if this button-down was NOT itself a double-click, so it can
    /// seed a future one (Windows' triple-click suppression).
    seed_completed_click: bool,
}

#[derive(Clone, Copy)]
struct CompletedClick {
    button: MouseButton,
    down_at: Instant,
    x: i32,
    y: i32,
    hwnd: Option<u64>,
}

/// Per-axis continuous-scroll accumulator (precise/trackpad scrolling).
struct WheelAccum {
    started_at: Instant,
    total: f64,
    x: i32,
    y: i32,
    input_origin: Option<InputOrigin>,
    window: Option<WindowRef>,
}

pub(crate) struct MouseState {
    metrics: PointerMetrics,
    pending_move: Option<PendingMove>,
    active: HashMap<MouseButton, ActiveButton>,
    last_completed_click: Option<CompletedClick>,
    wheel_v: Option<WheelAccum>,
    wheel_h: Option<WheelAccum>,
}

impl MouseState {
    pub(crate) fn new(metrics: PointerMetrics) -> Self {
        Self {
            metrics,
            pending_move: None,
            active: HashMap::new(),
            last_completed_click: None,
            wheel_v: None,
            wheel_h: None,
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
                self.record_move(dx, dy, raw, window.clone(), now);
                for button in self.active.values_mut() {
                    button.add_movement(dx, dy, (raw.x, raw.y), raw.input_origin, window.clone());
                }
            }
            RawMouseKind::Down(button) => {
                self.flush_move(now, out);
                self.flush_wheels(now, out);
                self.on_button_down(button, raw, window, now, out);
            }
            RawMouseKind::Up(button) => {
                self.flush_move(now, out);
                self.flush_wheels(now, out);
                self.on_button_up(button, raw, now, out);
            }
            RawMouseKind::Wheel(wheel) => {
                self.on_wheel(wheel, raw, window, now, out);
            }
        }
    }

    /// Called once per pump drain pass: flush trailing move/scroll aggregates
    /// whose window has elapsed (Windows' per-message `flush_due`).
    pub(crate) fn flush_due(&mut self, now: Instant, out: &mut Vec<Captured>) {
        if self
            .pending_move
            .as_ref()
            .is_some_and(|m| now.saturating_duration_since(m.started_at) >= MOVE_FLUSH_INTERVAL)
        {
            self.flush_move(now, out);
        }
        for axis in [MouseWheelAxis::Vertical, MouseWheelAxis::Horizontal] {
            let accum = self.wheel_slot(axis);
            if accum
                .as_ref()
                .is_some_and(|w| now.saturating_duration_since(w.started_at) >= MOVE_FLUSH_INTERVAL)
            {
                self.flush_wheel(axis, out);
            }
        }
    }

    /// Session/power boundary: drop active buttons and the last click so no
    /// drag is synthesized across the boundary and no double-click chains
    /// across it (Windows `reset_after_boundary`). Pending move and scroll
    /// accumulators are left to flush normally.
    pub(crate) fn reset_after_boundary(&mut self) {
        self.active.clear();
        self.last_completed_click = None;
    }

    fn record_move(
        &mut self,
        dx: i32,
        dy: i32,
        raw: RawMouseEvent,
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
                m.x = raw.x;
                m.y = raw.y;
                if raw.input_origin.is_some() {
                    m.input_origin = raw.input_origin;
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
                    x: raw.x,
                    y: raw.y,
                    input_origin: raw.input_origin,
                    window,
                });
            }
        }
    }

    fn flush_move(&mut self, _now: Instant, out: &mut Vec<Captured>) {
        let Some(m) = self.pending_move.take() else {
            return;
        };
        out.push(Captured::new(
            Source::Mouse,
            m.last_at,
            EventPayload::MouseMove {
                dx_total: m.dx_total,
                dy_total: m.dy_total,
                distance_px: m.distance_px,
                raw_event_count: m.raw_event_count,
                duration_ms: duration_ms(m.last_at.saturating_duration_since(m.started_at)),
                x: Some(m.x),
                y: Some(m.y),
                window: m.window,
                input_origin: m.input_origin,
            },
        ));
    }

    fn on_button_down(
        &mut self,
        button: MouseButton,
        raw: RawMouseEvent,
        window: Option<WindowRef>,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        let interval_ms = self.double_click_interval_ms(button, raw.x, raw.y, window.as_ref(), now);

        self.active.insert(
            button,
            ActiveButton {
                started_at: now,
                start: (raw.x, raw.y),
                end: (raw.x, raw.y),
                dx_total: 0,
                dy_total: 0,
                distance_px: 0,
                raw_event_count: 0,
                input_origin: raw.input_origin,
                window: window.clone(),
                seed_completed_click: interval_ms.is_none(),
            },
        );

        out.push(Captured::new(
            Source::Mouse,
            now,
            EventPayload::MouseClick {
                button,
                x: Some(raw.x),
                y: Some(raw.y),
                window: window.clone(),
                input_origin: raw.input_origin,
            },
        ));

        if let Some(interval_ms) = interval_ms {
            out.push(Captured::new(
                Source::Mouse,
                now,
                EventPayload::MouseDoubleClick {
                    button,
                    interval_ms,
                    x: Some(raw.x),
                    y: Some(raw.y),
                    window,
                    input_origin: raw.input_origin,
                },
            ));
            self.last_completed_click = None;
        }
    }

    fn on_button_up(
        &mut self,
        button: MouseButton,
        raw: RawMouseEvent,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        let Some(mut active) = self.active.remove(&button) else {
            return;
        };
        active.end = (raw.x, raw.y);
        if raw.input_origin.is_some() {
            active.input_origin = raw.input_origin;
        }

        if active.is_drag(self.metrics.drag_half) {
            out.push(active.into_drag(button, now));
            self.last_completed_click = None;
        } else if active.seed_completed_click {
            self.last_completed_click = Some(CompletedClick {
                button,
                down_at: active.started_at,
                x: active.start.0,
                y: active.start.1,
                hwnd: active.window.as_ref().map(|w| w.hwnd),
            });
        } else {
            self.last_completed_click = None;
        }
    }

    /// Returns `Some(measured_interval_ms)` when this down completes a
    /// double-click with the previous click (Windows reconstruction: same
    /// button, within the system interval, within the box, same known
    /// window), else `None`.
    fn double_click_interval_ms(
        &self,
        button: MouseButton,
        x: i32,
        y: i32,
        window: Option<&WindowRef>,
        now: Instant,
    ) -> Option<u64> {
        let prev = self.last_completed_click?;
        if prev.button != button {
            return None;
        }
        let elapsed = now.saturating_duration_since(prev.down_at);
        if elapsed > self.metrics.double_click_interval {
            return None;
        }
        let hwnd = window?.hwnd;
        if prev.hwnd? != hwnd {
            return None;
        }
        let half = self.metrics.double_click_half.max(1);
        if (x - prev.x).abs() > half || (y - prev.y).abs() > half {
            return None;
        }
        Some(duration_ms(elapsed))
    }

    fn on_wheel(
        &mut self,
        wheel: RawWheel,
        raw: RawMouseEvent,
        window: Option<WindowRef>,
        now: Instant,
        out: &mut Vec<Captured>,
    ) {
        // Momentum coast is machine-generated after the finger lifts; dropping
        // it keeps every wheel row user-driven (Windows parity).
        if wheel.momentum {
            return;
        }

        if wheel.continuous {
            self.accumulate_continuous(
                MouseWheelAxis::Vertical,
                wheel.fixed_v,
                raw,
                window.clone(),
                now,
            );
            self.accumulate_continuous(MouseWheelAxis::Horizontal, wheel.fixed_h, raw, window, now);
            return;
        }

        // Discrete wheel: force-flush a pending move and any continuous
        // accumulation, then one row per non-zero axis at ±120 units.
        self.flush_move(now, out);
        self.flush_wheels(now, out);
        for (axis, line) in [
            (MouseWheelAxis::Vertical, wheel.line_v),
            (MouseWheelAxis::Horizontal, wheel.line_h),
        ] {
            if line != 0 {
                out.push(Captured::new(
                    Source::Mouse,
                    now,
                    EventPayload::MouseWheel {
                        axis,
                        delta: line.saturating_mul(WHEEL_UNIT),
                        x: Some(raw.x),
                        y: Some(raw.y),
                        window: window_for_axis(&window),
                        input_origin: raw.input_origin,
                    },
                ));
            }
        }
    }

    fn accumulate_continuous(
        &mut self,
        axis: MouseWheelAxis,
        fixed: f64,
        raw: RawMouseEvent,
        window: Option<WindowRef>,
        now: Instant,
    ) {
        if fixed == 0.0 {
            return;
        }
        let slot = self.wheel_slot(axis);
        match slot {
            Some(w) => {
                w.total += fixed;
                w.x = raw.x;
                w.y = raw.y;
                if raw.input_origin.is_some() {
                    w.input_origin = raw.input_origin;
                }
                if window.is_some() {
                    w.window = window;
                }
            }
            None => {
                *slot = Some(WheelAccum {
                    started_at: now,
                    total: fixed,
                    x: raw.x,
                    y: raw.y,
                    input_origin: raw.input_origin,
                    window,
                });
            }
        }
    }

    fn wheel_slot(&mut self, axis: MouseWheelAxis) -> &mut Option<WheelAccum> {
        match axis {
            MouseWheelAxis::Vertical => &mut self.wheel_v,
            MouseWheelAxis::Horizontal => &mut self.wheel_h,
        }
    }

    fn flush_wheels(&mut self, _now: Instant, out: &mut Vec<Captured>) {
        self.flush_wheel(MouseWheelAxis::Vertical, out);
        self.flush_wheel(MouseWheelAxis::Horizontal, out);
    }

    fn flush_wheel(&mut self, axis: MouseWheelAxis, out: &mut Vec<Captured>) {
        let Some(w) = self.wheel_slot(axis).take() else {
            return;
        };
        let delta = (w.total * f64::from(WHEEL_UNIT)).round() as i32;
        if delta == 0 {
            return;
        }
        out.push(Captured::new(
            Source::Mouse,
            w.started_at,
            EventPayload::MouseWheel {
                axis,
                delta,
                x: Some(w.x),
                y: Some(w.y),
                window: w.window,
                input_origin: w.input_origin,
            },
        ));
    }
}

fn window_for_axis(window: &Option<WindowRef>) -> Option<WindowRef> {
    window.clone()
}

impl ActiveButton {
    fn add_movement(
        &mut self,
        dx: i32,
        dy: i32,
        end: (i32, i32),
        input_origin: Option<InputOrigin>,
        window: Option<WindowRef>,
    ) {
        self.dx_total = self.dx_total.saturating_add(i64::from(dx));
        self.dy_total = self.dy_total.saturating_add(i64::from(dy));
        self.distance_px = self.distance_px.saturating_add(distance_px(dx, dy));
        self.raw_event_count = self.raw_event_count.saturating_add(1);
        self.end = end;
        if input_origin.is_some() {
            self.input_origin = input_origin;
        }
        if window.is_some() {
            self.window = window;
        }
    }

    fn is_drag(&self, drag_half: i32) -> bool {
        let half = drag_half.max(1);
        let max_dim = u64::try_from(half).unwrap_or(1);
        let (sx, sy) = self.start;
        let (ex, ey) = self.end;
        (ex - sx).abs() > half || (ey - sy).abs() > half || self.distance_px >= max_dim
    }

    fn into_drag(self, button: MouseButton, ended_at: Instant) -> Captured {
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
                start_x: Some(self.start.0),
                start_y: Some(self.start.1),
                end_x: Some(self.end.0),
                end_y: Some(self.end.1),
                window: self.window,
                selection_candidate: button == MouseButton::Left,
                input_origin: self.input_origin,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> PointerMetrics {
        PointerMetrics::default()
    }

    fn win(hwnd: u64) -> Option<WindowRef> {
        Some(WindowRef {
            hwnd,
            exe: "/A.app/Contents/MacOS/A".to_string(),
            title: String::new(),
            pid: 400,
        })
    }

    fn down(button: MouseButton, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Down(button),
            x,
            y,
            input_origin: None,
        }
    }
    fn up(button: MouseButton, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Up(button),
            x,
            y,
            input_origin: None,
        }
    }
    fn moved(dx: i32, dy: i32, x: i32, y: i32) -> RawMouseEvent {
        RawMouseEvent {
            kind: RawMouseKind::Moved { dx, dy },
            x,
            y,
            input_origin: None,
        }
    }

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|e| e.payload.kind()).collect()
    }

    #[test]
    fn a_single_click_emits_click_on_down_and_nothing_on_up() {
        let mut state = MouseState::new(metrics());
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
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();

        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            up(MouseButton::Left, 100, 100),
            win(1),
            base + Duration::from_millis(20),
            &mut out,
        );
        // Second down 100ms later, same spot & window: click + double_click.
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
                    "measured interval, not the system setting"
                );
            }
            other => panic!("expected double click, got {other:?}"),
        }
    }

    #[test]
    fn three_fast_clicks_do_not_chain_a_second_double() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        for (i, t) in [0u64, 100, 200].into_iter().enumerate() {
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
            let _ = i;
        }
        // click, (click, double), click — no second double on the third.
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
    fn far_second_click_is_not_a_double_click() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            up(MouseButton::Left, 100, 100),
            win(1),
            base + Duration::from_millis(10),
            &mut out,
        );
        state.on_event(
            down(MouseButton::Left, 200, 200),
            win(1),
            base + Duration::from_millis(80),
            &mut out,
        );
        assert_eq!(
            kinds(&out),
            vec!["mouse_click", "mouse_click"],
            "outside the box"
        );
    }

    #[test]
    fn a_drag_emits_move_then_drag_sharing_the_deltas() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();

        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        // Move 20,10 while held (one raw movement event).
        state.on_event(
            moved(20, 10, 120, 110),
            win(1),
            base + Duration::from_millis(50),
            &mut out,
        );
        // Button up 100ms after down: discrete input flushes the move first.
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
        // The move carries the SAME deltas (double-counted, Windows parity).
        match &out[1].payload {
            EventPayload::MouseMove {
                dx_total, dy_total, ..
            } => {
                assert_eq!((*dx_total, *dy_total), (20, 10));
            }
            other => panic!("expected move, got {other:?}"),
        }
    }

    #[test]
    fn a_return_to_origin_drag_is_still_a_drag_by_path_length() {
        let mut state = MouseState::new(metrics());
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
        // Net displacement zero, but path length 100 >> drag box.
        assert!(kinds(&out).contains(&"mouse_drag"));
        match out
            .iter()
            .find(|e| e.payload.kind() == "mouse_drag")
            .unwrap()
            .payload
        {
            EventPayload::MouseDrag {
                dx_total,
                distance_px,
                ..
            } => {
                assert_eq!(dx_total, 0);
                assert_eq!(distance_px, 100);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn trailing_move_flushes_on_the_cadence() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(moved(5, 5, 105, 105), win(1), base, &mut out);
        state.flush_due(base + Duration::from_millis(100), &mut out);
        assert!(out.is_empty(), "not due at 100ms");
        state.flush_due(base + Duration::from_millis(250), &mut out);
        assert_eq!(kinds(&out), vec!["mouse_move"]);
    }

    #[test]
    fn discrete_wheel_scales_to_windows_units_per_axis() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        let wheel = RawWheel {
            continuous: false,
            momentum: false,
            line_v: -2,
            line_h: 1,
            fixed_v: 0.0,
            fixed_h: 0.0,
        };
        state.on_event(
            RawMouseEvent {
                kind: RawMouseKind::Wheel(wheel),
                x: 50,
                y: 60,
                input_origin: None,
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
                assert_eq!((*a0, *d0), (MouseWheelAxis::Vertical, -240));
                assert_eq!((*a1, *d1), (MouseWheelAxis::Horizontal, 120));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn continuous_scroll_accumulates_and_flushes_on_cadence() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        for t in [0u64, 50, 100] {
            let wheel = RawWheel {
                continuous: true,
                momentum: false,
                line_v: 0,
                line_h: 0,
                fixed_v: 0.5,
                fixed_h: 0.0,
            };
            state.on_event(
                RawMouseEvent {
                    kind: RawMouseKind::Wheel(wheel),
                    x: 10,
                    y: 20,
                    input_origin: None,
                },
                win(1),
                base + Duration::from_millis(t),
                &mut out,
            );
        }
        assert!(
            out.is_empty(),
            "continuous scroll accumulates, no per-event rows"
        );
        state.flush_due(base + Duration::from_millis(260), &mut out);
        // 1.5 accumulated * 120 = 180.
        assert_eq!(kinds(&out), vec!["mouse_wheel"]);
        match &out[0].payload {
            EventPayload::MouseWheel { axis, delta, .. } => {
                assert_eq!((*axis, *delta), (MouseWheelAxis::Vertical, 180));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn momentum_scroll_is_dropped() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        let wheel = RawWheel {
            continuous: true,
            momentum: true,
            line_v: 0,
            line_h: 0,
            fixed_v: 3.0,
            fixed_h: 0.0,
        };
        state.on_event(
            RawMouseEvent {
                kind: RawMouseKind::Wheel(wheel),
                x: 10,
                y: 20,
                input_origin: None,
            },
            win(1),
            base,
            &mut out,
        );
        state.flush_due(base + Duration::from_millis(300), &mut out);
        assert!(out.is_empty(), "momentum coast is not user-driven");
    }

    #[test]
    fn a_boundary_drops_a_held_button_without_synthesizing_a_drag() {
        let mut state = MouseState::new(metrics());
        let base = Instant::now();
        let mut out = Vec::new();
        state.on_event(down(MouseButton::Left, 100, 100), win(1), base, &mut out);
        state.on_event(
            moved(40, 0, 140, 100),
            win(1),
            base + Duration::from_millis(20),
            &mut out,
        );
        out.clear();
        state.reset_after_boundary();
        // The (missed) button-up after the boundary finds no active button.
        state.on_event(
            up(MouseButton::Left, 140, 100),
            win(1),
            base + Duration::from_millis(40),
            &mut out,
        );
        assert!(
            !kinds(&out).contains(&"mouse_drag"),
            "no drag across the boundary"
        );
    }

    #[test]
    fn non_left_button_drag_is_not_a_selection_candidate() {
        let mut state = MouseState::new(metrics());
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
        match out
            .iter()
            .find(|e| e.payload.kind() == "mouse_drag")
            .unwrap()
            .payload
        {
            EventPayload::MouseDrag {
                selection_candidate,
                ..
            } => assert!(!selection_candidate),
            _ => unreachable!(),
        }
    }
}
