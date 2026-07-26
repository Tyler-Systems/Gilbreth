//! The shared listen-only `CGEventTap` feeding the Keyboard and Mouse
//! streams (the macOS TCC and stream rules...: Keyboard+Mouse amendment).
//! Unlike every other macOS source this is not a poller: the tap's mach-port
//! source runs on the pump's CFRunLoop, and its C callback fires on the pump
//! thread inside `run_in_mode`. The callback is deliberately minimal — it
//! reduces the CGEvent to a plain `RawInput`, stamps `Instant::now()` (same
//! thread, so the true event time at per-event resolution), and pushes to a
//! pump-owned queue; all derivation runs when the pump drains that queue
//! after `run_in_mode` returns, off the event-delivery path (a slow callback
//! risks the OS disabling the tap by timeout). Callback and drain never
//! overlap (one thread; callback only during `run_in_mode`, drain only
//! after), so the queue needs no lock.
//!
//! The tap is `kCGEventTapOptionListenOnly` — Gilbreth observes, never
//! rewrites or swallows input, and a passive tap cannot inject. One Input
//! Monitoring grant (`CGPreflightListenEventAccess`, never prompting) gates
//! both streams; the tap exists only while at least one is wanted AND
//! granted, and its event mask covers only the wanted stream's types (a
//! mouse-only grant-holder never even receives keystrokes).

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ffi::c_void,
    ptr::NonNull,
    time::{Duration, Instant},
};

use objc2_core_foundation::{
    kCFRunLoopCommonModes, CFMachPort, CFRetained, CFRunLoop, CFRunLoopSource,
};
use objc2_core_graphics::{
    CGEvent, CGEventField, CGEventFlags, CGEventMask, CGEventTapLocation, CGEventTapOptions,
    CGEventTapPlacement, CGEventType,
};
use tracing::{info, warn};

use gilbreth_core::{InputOrigin, MouseButton};

use crate::{keyboard, mouse};

/// One raw input event the callback extracted, tagged for dispatch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RawInput {
    Key(keyboard::RawKeyEvent),
    Mouse(mouse::RawMouseEvent),
}

/// Slow re-probe cadence while wanted-but-untrusted (matrix cadence, shared
/// with the AX trust).
pub(crate) const TRUST_REPROBE_INTERVAL: Duration = Duration::from_secs(30);

// CGEventType raw values → event-mask bits (`1 << type`).
const fn bit(ty: u32) -> u64 {
    1u64 << ty
}
const KEYBOARD_MASK: CGEventMask = bit(10) | bit(11) | bit(12); // keyDown/keyUp/flagsChanged
const MOUSE_MASK: CGEventMask = bit(1)
    | bit(2)
    | bit(3)
    | bit(4)
    | bit(5)
    | bit(6)
    | bit(7)
    | bit(22)
    | bit(25)
    | bit(26)
    | bit(27);

/// Preflight the Input Monitoring grant — never prompts.
pub(crate) fn preflight_listen_access() -> bool {
    objc2_core_graphics::CGPreflightListenEventAccess()
}

/// Ask macOS to show the Input Monitoring approval flow — fired ONLY
/// behind an explicit user action (the Diagnostics panel's Request-access
/// button via the permission-request sidecar; the app layer's
/// `perform_permission_action`, pump process only, is the one caller),
/// mirroring `ax::prompt_accessibility`. Never called autonomously.
pub fn request_listen_access() -> bool {
    objc2_core_graphics::CGRequestListenEventAccess()
}

/// Pump-side Input Monitoring trust state, identical in shape to the AX
/// `WindowsStreamTrust`: probe on wanted-enable edges and every
/// [`TRUST_REPROBE_INTERVAL`] while wanted-but-untrusted; never probe while
/// trusted (revocation arrives as `TapDisabledByUserInput` from the tap).
pub(crate) struct InputTrust {
    trusted: bool,
    wanted_last: bool,
    last_probe: Option<Instant>,
}

impl InputTrust {
    pub(crate) fn new() -> Self {
        Self {
            trusted: false,
            wanted_last: false,
            last_probe: None,
        }
    }

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
            if trusted != self.trusted || enable_edge {
                log_trust_state(trusted);
            }
            self.trusted = trusted;
        }
        self.trusted
    }

    /// The tap reported `TapDisabledByUserInput` (or the preflight flipped):
    /// treat as revocation and re-probe on the cadence for a re-grant.
    pub(crate) fn on_revoked(&mut self, now: Instant) {
        if self.trusted {
            warn!(
                "keyboard/mouse capture degraded: Input Monitoring was revoked mid-run \
                 (re-probing every {}s)",
                TRUST_REPROBE_INTERVAL.as_secs()
            );
        }
        self.trusted = false;
        self.last_probe = Some(now);
    }
}

fn log_trust_state(trusted: bool) {
    if trusted {
        info!("keyboard/mouse streams active: Input Monitoring is granted");
    } else {
        info!(
            "keyboard/mouse off (declared): Input Monitoring is not granted — enable in \
             System Settings > Privacy & Security > Input Monitoring; re-probing every {}s",
            TRUST_REPROBE_INTERVAL.as_secs()
        );
    }
}

/// Shared state the C callback writes and the pump drains. Single-threaded
/// (callback and drain both on the pump/run-loop thread, never concurrent),
/// so `Cell`/`RefCell` are sufficient and correct.
struct TapShared {
    queue: RefCell<VecDeque<(Instant, RawInput)>>,
    /// Count of `TapDisabledByTimeout` events (Diagnostics surfaces a
    /// recurring count; each is re-enabled by the pump).
    timeout_disables: Cell<u64>,
    /// Set on `TapDisabledByUserInput` — revocation.
    user_disabled: Cell<bool>,
}

/// A live tap: the mach port, its run-loop source, the wanted mask, and the
/// heap-stable shared state the callback points at. Dropping it removes the
/// source and invalidates the port.
pub(crate) struct EventTap {
    port: CFRetained<CFMachPort>,
    source: CFRetained<CFRunLoopSource>,
    run_loop: CFRetained<CFRunLoop>,
    shared: Box<TapShared>,
    mask: CGEventMask,
}

impl EventTap {
    /// Create and enable a listen-only tap for the given mask on `run_loop`.
    /// Returns None if the OS refuses (not granted / creation failed).
    fn create(run_loop: &CFRetained<CFRunLoop>, mask: CGEventMask) -> Option<Self> {
        let shared = Box::new(TapShared {
            queue: RefCell::new(VecDeque::new()),
            timeout_disables: Cell::new(0),
            user_disabled: Cell::new(false),
        });
        let user_info = (&*shared as *const TapShared as *mut c_void).cast();
        // SAFETY: `tap_callback` matches the CGEventTapCallBack ABI; user_info
        // points at `shared`, which this struct owns and keeps alive for the
        // tap's lifetime (the callback only fires while the source is on the
        // run loop, i.e. before Drop removes it).
        let port = unsafe {
            CGEvent::tap_create(
                CGEventTapLocation::HIDEventTap,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                mask,
                Some(tap_callback),
                user_info,
            )
        }?;
        let source = CFMachPort::new_run_loop_source(None, Some(&port), 0)?;
        // SAFETY: framework-provided mode constant, initialized before any
        // code here runs.
        let common_modes = unsafe { kCFRunLoopCommonModes };
        // Common modes, not default (Shell slice, 2026-07-12): an open tray
        // menu runs AppKit's nested tracking loop in the event-tracking
        // mode, where a default-mode-only tap source would stall — events
        // buffer undelivered and the OS may disable the tap by timeout
        // while the user browses the menu. In common modes the callback
        // keeps firing there (same thread, still only while a run loop
        // runs); it only pushes to the queue, so it can never overlap the
        // pump's drain borrow.
        run_loop.add_source(Some(&source), common_modes);
        CGEvent::tap_enable(&port, true);
        info!("input event tap created and enabled (listen-only)");
        Some(Self {
            port,
            source,
            run_loop: run_loop.clone(),
            shared,
            mask,
        })
    }

    /// Drain everything the callback queued since the last pass, in order.
    fn drain(&self) -> Vec<(Instant, RawInput)> {
        self.shared.queue.borrow_mut().drain(..).collect()
    }

    /// Reconcile a `TapDisabledByTimeout`: re-enable immediately and report
    /// the running count for Diagnostics (returns the new count if it grew).
    fn handle_timeouts(&self) -> Option<u64> {
        // The callback cannot re-enable (it is inside delivery); the pump
        // does. A single flag would suffice, but the count is the Diagnostics
        // signal. We re-enable whenever the tap is not currently enabled.
        let count = self.shared.timeout_disables.get();
        if !CGEvent::tap_is_enabled(&self.port) {
            CGEvent::tap_enable(&self.port, true);
            return Some(count);
        }
        None
    }

    fn user_revoked(&self) -> bool {
        self.shared.user_disabled.get()
    }
}

impl Drop for EventTap {
    fn drop(&mut self) {
        // SAFETY: mode constant as above. Removal mode must match the add
        // (common modes) or the source would stay registered.
        let common_modes = unsafe { kCFRunLoopCommonModes };
        self.run_loop
            .remove_source(Some(&self.source), common_modes);
        self.port.invalidate();
    }
}

/// The mask wanted this pass given the two stream flags; 0 means "no tap".
pub(crate) fn wanted_mask(keyboard: bool, mouse: bool) -> CGEventMask {
    let mut mask = 0;
    if keyboard {
        mask |= KEYBOARD_MASK;
    }
    if mouse {
        mask |= MOUSE_MASK;
    }
    mask
}

/// Owns the current tap (if any) and reconciles it against the wanted mask
/// each pump pass. Keeps the unsafe tap handling in one place.
pub(crate) struct EventTapController {
    tap: Option<EventTap>,
}

impl EventTapController {
    pub(crate) fn new() -> Self {
        Self { tap: None }
    }

    /// Reconcile the tap to `mask` (0 tears it down). Returns any drained raw
    /// events plus lifecycle signals for the pump to act on.
    pub(crate) fn reconcile(
        &mut self,
        run_loop: &CFRetained<CFRunLoop>,
        mask: CGEventMask,
    ) -> TapPass {
        // Rebuild when the wanted mask changes (e.g. keyboard toggled while
        // mouse stays on) so we tap only the wanted event types.
        if self.tap.as_ref().map(|t| t.mask) != Some(mask) {
            self.tap = None;
            if mask != 0 {
                self.tap = EventTap::create(run_loop, mask);
            }
        }

        let Some(tap) = self.tap.as_ref() else {
            return TapPass::default();
        };

        if tap.user_revoked() {
            self.tap = None;
            return TapPass {
                revoked: true,
                ..TapPass::default()
            };
        }
        let timeout_reenabled = tap.handle_timeouts();
        let events = tap.drain();
        TapPass {
            events,
            revoked: false,
            timeout_reenabled,
        }
    }

    /// Tear the tap down (neither stream wanted, or shutdown).
    pub(crate) fn teardown(&mut self) {
        self.tap = None;
    }
}

/// The outcome of one tap reconciliation pass.
#[derive(Default)]
pub(crate) struct TapPass {
    pub(crate) events: Vec<(Instant, RawInput)>,
    pub(crate) revoked: bool,
    pub(crate) timeout_reenabled: Option<u64>,
}

/// The pump's seam onto the event tap: the real `EventTapController` in
/// production, a scripted mock in tests (so pump tests never call the real
/// `CGEventTapCreate`, which would need a grant and could add the test binary
/// to the Input Monitoring list). `run_loop` is passed per pass because it is
/// created inside the pump, after the sources are assembled.
pub(crate) trait InputTap {
    /// The Input Monitoring preflight (never prompts).
    fn preflight(&mut self) -> bool;
    /// Reconcile the tap to `mask` (0 tears it down) and return the pass.
    fn reconcile(&mut self, run_loop: &CFRetained<CFRunLoop>, mask: CGEventMask) -> TapPass;
    /// Drop any live tap (pump shutdown / neither stream wanted).
    fn teardown(&mut self);
}

impl InputTap for EventTapController {
    fn preflight(&mut self) -> bool {
        preflight_listen_access()
    }
    fn reconcile(&mut self, run_loop: &CFRetained<CFRunLoop>, mask: CGEventMask) -> TapPass {
        EventTapController::reconcile(self, run_loop, mask)
    }
    fn teardown(&mut self) {
        EventTapController::teardown(self)
    }
}

/// No-op tap for pump tests that assert about the pump rather than input:
/// never granted, never any events, so the real tap code is never reached.
#[cfg(test)]
pub(crate) struct NullInputTap;

#[cfg(test)]
impl InputTap for NullInputTap {
    fn preflight(&mut self) -> bool {
        false
    }
    fn reconcile(&mut self, _run_loop: &CFRetained<CFRunLoop>, _mask: CGEventMask) -> TapPass {
        TapPass::default()
    }
    fn teardown(&mut self) {}
}

/// The tap callback: minimal, on the pump thread, inside `run_in_mode`.
/// Extracts fields, stamps the event time, queues, and returns the event
/// unmodified (listen-only).
unsafe extern "C-unwind" fn tap_callback(
    _proxy: objc2_core_graphics::CGEventTapProxy,
    ty: CGEventType,
    event: NonNull<CGEvent>,
    user_info: *mut c_void,
) -> *mut CGEvent {
    // SAFETY: user_info is the `&TapShared` set at tap creation, alive for the
    // tap's lifetime; the callback only fires while the tap's source is on the
    // run loop.
    let shared = unsafe { &*(user_info as *const TapShared) };
    match ty {
        CGEventType::TapDisabledByTimeout => {
            shared
                .timeout_disables
                .set(shared.timeout_disables.get().saturating_add(1));
        }
        CGEventType::TapDisabledByUserInput => {
            shared.user_disabled.set(true);
        }
        _ => {
            // SAFETY: within the callback the event pointer is valid.
            let event_ref = unsafe { event.as_ref() };
            if let Some(raw) = extract(ty, event_ref) {
                shared.queue.borrow_mut().push_back((Instant::now(), raw));
            }
        }
    }
    event.as_ptr()
}

fn extract(ty: CGEventType, event: &CGEvent) -> Option<RawInput> {
    match ty {
        CGEventType::KeyDown | CGEventType::KeyUp | CGEventType::FlagsChanged => {
            let keycode =
                CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode)
                    as u16;
            let flags = CGEvent::flags(Some(event)).0;
            let kind = match ty {
                CGEventType::KeyDown => {
                    let autorepeat = CGEvent::integer_value_field(
                        Some(event),
                        CGEventField::KeyboardEventAutorepeat,
                    ) != 0;
                    keyboard::RawKeyKind::KeyDown { autorepeat }
                }
                CGEventType::KeyUp => keyboard::RawKeyKind::KeyUp,
                _ => keyboard::RawKeyKind::FlagsChanged,
            };
            Some(RawInput::Key(keyboard::RawKeyEvent {
                keycode,
                kind,
                flags,
            }))
        }
        _ => extract_mouse(ty, event).map(RawInput::Mouse),
    }
}

fn extract_mouse(ty: CGEventType, event: &CGEvent) -> Option<mouse::RawMouseEvent> {
    let location = CGEvent::location(Some(event));
    let x = location.x.round() as i32;
    let y = location.y.round() as i32;
    let input_origin = input_origin(event);

    let kind = match ty {
        CGEventType::LeftMouseDown => mouse::RawMouseKind::Down(MouseButton::Left),
        CGEventType::LeftMouseUp => mouse::RawMouseKind::Up(MouseButton::Left),
        CGEventType::RightMouseDown => mouse::RawMouseKind::Down(MouseButton::Right),
        CGEventType::RightMouseUp => mouse::RawMouseKind::Up(MouseButton::Right),
        CGEventType::OtherMouseDown => mouse::RawMouseKind::Down(other_button(event)),
        CGEventType::OtherMouseUp => mouse::RawMouseKind::Up(other_button(event)),
        CGEventType::MouseMoved
        | CGEventType::LeftMouseDragged
        | CGEventType::RightMouseDragged
        | CGEventType::OtherMouseDragged => {
            let dx =
                CGEvent::integer_value_field(Some(event), CGEventField::MouseEventDeltaX) as i32;
            let dy =
                CGEvent::integer_value_field(Some(event), CGEventField::MouseEventDeltaY) as i32;
            mouse::RawMouseKind::Moved { dx, dy }
        }
        CGEventType::ScrollWheel => mouse::RawMouseKind::Wheel(extract_wheel(event)),
        _ => return None,
    };
    Some(mouse::RawMouseEvent {
        kind,
        x,
        y,
        input_origin,
    })
}

fn other_button(event: &CGEvent) -> MouseButton {
    match CGEvent::integer_value_field(Some(event), CGEventField::MouseEventButtonNumber) {
        2 => MouseButton::Middle,
        3 => MouseButton::X1,
        4 => MouseButton::X2,
        // Buttons beyond X2 have no vocabulary; fold onto X2 rather than
        // dropping the event (rare hardware). Documented parity gap.
        _ => MouseButton::X2,
    }
}

fn extract_wheel(event: &CGEvent) -> mouse::RawWheel {
    mouse::RawWheel {
        continuous: CGEvent::integer_value_field(
            Some(event),
            CGEventField::ScrollWheelEventIsContinuous,
        ) != 0,
        momentum: CGEvent::integer_value_field(
            Some(event),
            CGEventField::ScrollWheelEventMomentumPhase,
        ) != 0,
        line_v: CGEvent::integer_value_field(Some(event), CGEventField::ScrollWheelEventDeltaAxis1)
            as i32,
        line_h: CGEvent::integer_value_field(Some(event), CGEventField::ScrollWheelEventDeltaAxis2)
            as i32,
        fixed_v: CGEvent::double_value_field(
            Some(event),
            CGEventField::ScrollWheelEventFixedPtDeltaAxis1,
        ),
        fixed_h: CGEvent::double_value_field(
            Some(event),
            CGEventField::ScrollWheelEventFixedPtDeltaAxis2,
        ),
    }
}

/// Local hardware input vs. an event posted by another process (relay
/// suspicion). macOS exposes real source info Windows lacks: a HID-originated
/// event has the HID system state (1) and no source process id; anything else
/// (a private/session source, or a non-zero posting pid) is suspect.
fn input_origin(event: &CGEvent) -> Option<InputOrigin> {
    const HID_SYSTEM_STATE: i64 = 1;
    let source_state = CGEvent::integer_value_field(Some(event), CGEventField::EventSourceStateID);
    let source_pid =
        CGEvent::integer_value_field(Some(event), CGEventField::EventSourceUnixProcessID);
    if source_state == HID_SYSTEM_STATE && source_pid == 0 {
        None
    } else {
        Some(InputOrigin::RemoteRelaySuspected)
    }
}

// SAFETY: `CGEventFlags` is a plain `u64` newtype; the `.0` access above is
// the documented field. (This use exists only to keep the import honest if
// the flags newtype changes shape.)
const _: fn(CGEventFlags) -> u64 = |f| f.0;

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc, time::Duration};

    use super::*;

    fn probe(initial: bool) -> (Rc<Cell<bool>>, Rc<Cell<u32>>, impl FnMut() -> bool) {
        let result = Rc::new(Cell::new(initial));
        let calls = Rc::new(Cell::new(0));
        let r = result.clone();
        let c = calls.clone();
        (result, calls, move || {
            c.set(c.get() + 1);
            r.get()
        })
    }

    #[test]
    fn wanted_mask_reflects_the_two_toggles() {
        assert_eq!(wanted_mask(false, false), 0);
        assert_eq!(wanted_mask(true, false), KEYBOARD_MASK);
        assert_eq!(wanted_mask(false, true), MOUSE_MASK);
        assert_eq!(wanted_mask(true, true), KEYBOARD_MASK | MOUSE_MASK);
        // Masks are disjoint (no shared type bits).
        assert_eq!(KEYBOARD_MASK & MOUSE_MASK, 0);
    }

    #[test]
    fn trust_probes_on_enable_edge_and_never_while_trusted() {
        let (_r, calls, mut probe) = probe(true);
        let mut trust = InputTrust::new();
        let base = Instant::now();

        assert!(trust.refresh(base, true, &mut probe));
        assert_eq!(calls.get(), 1);
        assert!(trust.refresh(base + Duration::from_secs(120), true, &mut probe));
        assert_eq!(calls.get(), 1, "no re-probe while trusted");
    }

    #[test]
    fn untrusted_reprobes_on_the_cadence_and_notices_a_grant() {
        let (result, calls, mut probe) = probe(false);
        let mut trust = InputTrust::new();
        let base = Instant::now();

        assert!(!trust.refresh(base, true, &mut probe));
        assert!(!trust.refresh(base + Duration::from_secs(10), true, &mut probe));
        assert_eq!(calls.get(), 1, "not due at 10s");
        result.set(true);
        assert!(trust.refresh(base + Duration::from_secs(30), true, &mut probe));
        assert_eq!(calls.get(), 2, "cadence probe noticed the grant");
    }

    #[test]
    fn revocation_degrades_and_the_reprobe_notices_a_regrant() {
        let (_r, calls, mut probe) = probe(true);
        let mut trust = InputTrust::new();
        let base = Instant::now();

        assert!(trust.refresh(base, true, &mut probe));
        trust.on_revoked(base + Duration::from_secs(5));
        assert!(!trust.refresh(base + Duration::from_secs(6), true, &mut probe));
        assert_eq!(calls.get(), 1, "revocation restarts the cadence");
        assert!(trust.refresh(base + Duration::from_secs(36), true, &mut probe));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn wanted_off_never_probes() {
        let (_r, calls, mut probe) = probe(true);
        let mut trust = InputTrust::new();
        let base = Instant::now();
        assert!(!trust.refresh(base, false, &mut probe));
        assert_eq!(calls.get(), 0);
    }
}
