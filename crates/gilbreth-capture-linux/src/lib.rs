#![cfg(target_os = "linux")]

//! Linux ambient-capture backend (LIN-1, X11 only): the pump — an X
//! connection drained beside a self-pipe waker on the Windows/macOS service
//! cadence — plus the capture shell seams the app consumes (the pause-hotkey
//! grab). Capture streams arrive in the recorded LIN-1 order: foreground
//! focus with titles (EWMH), idle/active (the X idle clock), keyboard and
//! mouse rows (XInput2 raw events), display shape, and the procfs process
//! sweep through the shared core tracker.
//!
//! Wayland is absent by design (README roadmap): every stream here reads
//! X11 state that a Wayland compositor deliberately does not expose, and a
//! session without an X server declines capture honestly rather than
//! approximating. Mirrors `gilbreth-capture-windows`'s crate-level target
//! gate, so non-Linux workspace builds see an empty shell here.

mod dbus;
mod foreground;
mod hotkey;
mod idle;
mod keyboard;
mod mouse;
mod process;
mod session;
mod system;
mod xserver;

pub use hotkey::{
    register_pause_hotkey_grab, take_pause_hotkey_press, PauseChordModifiers, PauseHotkeyGrab,
};

use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};

use crossbeam_channel::{Sender, TrySendError};
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use tracing::{debug, info, warn};
use x11rb::{connection::Connection, protocol::Event, rust_connection::RustConnection};

/// Longest the loop sleeps between service ticks when nothing fires — the
/// macOS pump's cadence (its MAC-0 heritage), so tray responsiveness is
/// identical. A wake or any X event returns control sooner.
const SERVICE_INTERVAL_MS: i32 = 50;

/// The live pump's waker half: the write end of the self-pipe and the
/// latched stop request, registered for the duration of [`run_pump`] and
/// cleared on every exit path so a wake after shutdown is a logged no-op
/// and a later pump (tests run several per process) registers afresh.
struct PumpHandle {
    wake_write: OwnedFd,
    stop_requested: Arc<AtomicBool>,
}

static PUMP: RwLock<Option<PumpHandle>> = RwLock::new(None);

fn pump_read() -> std::sync::RwLockReadGuard<'static, Option<PumpHandle>> {
    match PUMP.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn pump_write() -> std::sync::RwLockWriteGuard<'static, Option<PumpHandle>> {
    match PUMP.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Clears the pump registration on every exit path, including panics, so no
/// waker can write to a pipe whose pump has returned.
struct RegistrationGuard;

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        *pump_write() = None;
    }
}

fn write_wake_byte(fd: BorrowedFd<'_>) {
    // A full pipe already guarantees a pending wake; EAGAIN is success.
    let byte = [1u8];
    // SAFETY: writing one byte from a valid stack buffer to an owned,
    // non-blocking pipe fd.
    let rc = unsafe { libc::write(fd.as_raw_fd(), byte.as_ptr().cast(), 1) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock {
            debug!(%error, "pump wake write failed");
        }
    }
}

/// Wake the pump so it re-checks its stop token and services the tray.
/// Cross-thread safe. After the pump exits this is a quiet no-op: the writer
/// exit reporter legitimately wakes an already-gone pump during an orderly
/// quit, so a routine shutdown must not add warning lines to the log.
pub fn wake_pump() {
    if let Some(pump) = pump_read().as_ref() {
        write_wake_byte(pump.wake_write.as_fd());
    } else {
        debug!("pump wake requested but no capture pump is registered");
    }
}

/// Ask the pump to exit (the tray-quit path — the Linux analog of
/// `PostQuitMessage`). Latches the stop flag, then wakes, so the request is
/// as unlosable as a posted WM_QUIT regardless of where the loop is in its
/// pass. Cross-thread safe; a quiet no-op once the pump has exited.
pub fn stop_pump() {
    if let Some(pump) = pump_read().as_ref() {
        pump.stop_requested.store(true, Ordering::SeqCst);
        write_wake_byte(pump.wake_write.as_fd());
    } else {
        debug!("pump stop requested but no capture pump is registered");
    }
}

/// The Windows sources' send discipline on the load-bearing parts:
/// `enabled_for` as the defense-in-depth stream gate, `try_send` so capture
/// never blocks the pump, and the shared dropped counter under backpressure
/// — with the macOS quietenings (no per-event warn on a full channel, one
/// bounded end-of-run warning instead).
fn send_captured(tx: &Sender<Captured>, controls: &CaptureControls, captured: Captured) {
    if !controls.enabled_for(&captured) {
        debug!("capture stream disabled; dropping event before enqueue");
        return;
    }
    match tx.try_send(captured) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            controls.diagnostics().increment_capture_events_dropped();
        }
        Err(TrySendError::Disconnected(_)) => {
            debug!("capture channel disconnected; dropping event");
        }
    }
}

/// Open the self-pipe waker (read, write). Non-blocking on both ends: the
/// pump drains without stalling and wakers never block behind a full pipe.
fn wake_pipe() -> Result<(OwnedFd, OwnedFd), CaptureError> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 fills the two-element array; O_CLOEXEC keeps the fds
    // out of spawned dashboards, O_NONBLOCK keeps both ends non-blocking.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if rc != 0 {
        return Err(CaptureError::Source(
            format!("pump wake pipe failed: {}", io::Error::last_os_error()).into(),
        ));
    }
    // SAFETY: pipe2 succeeded, so both fds are freshly owned by this process.
    let read = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
    // SAFETY: same pipe2 success; the write end is distinct and owned.
    let write = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
    Ok((read, write))
}

fn drain_wake_pipe(fd: BorrowedFd<'_>) {
    let mut buffer = [0u8; 64];
    loop {
        // SAFETY: reading into a valid stack buffer from our non-blocking
        // pipe read end.
        let rc = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if rc <= 0 {
            return;
        }
    }
}

/// Block until the X stream or the wake pipe is readable, or the service
/// interval elapses. EINTR counts as a wake (the pass re-checks stop).
fn wait_for_activity(x_fd: RawFd, wake_fd: RawFd) {
    let mut fds = [
        libc::pollfd {
            fd: x_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: polling two valid fds owned by the pump; the array outlives
    // the call.
    let rc = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            fds.len() as libc::nfds_t,
            SERVICE_INTERVAL_MS,
        )
    };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            warn!(%error, "pump poll failed; continuing on the service cadence");
        }
    }
}

/// One raw input event translated by the io seam; position and window
/// attribution are joined by the pump loop.
#[derive(Clone, Copy, Debug, PartialEq)]
enum RawInput {
    Key(keyboard::RawKeyEvent),
    Mouse(mouse::RawMouseKind),
}

/// One pass's translated X-event yield, produced by the io seam.
#[derive(Clone, Debug, Default)]
struct PumpSignals {
    /// A root `PropertyNotify` named `_NET_ACTIVE_WINDOW` this pass.
    focus_dirty: bool,
    /// A `MappingNotify` arrived: the keymap must be rebuilt.
    keymap_dirty: bool,
    /// The X connection died; the pump must exit rather than spin.
    connection_lost: bool,
    /// Raw input in arrival order.
    raw_inputs: Vec<RawInput>,
}

/// The pump's io seam: the production implementation is the X connection
/// beside the self-pipe; tests script it so the full loop runs without an
/// X server.
trait PumpIo {
    /// Drain everything queued and translate it, so a burst is handled in
    /// one pass rather than one event per tick.
    fn drain(&mut self) -> PumpSignals;
    /// Block until activity or the service interval elapses, consuming any
    /// pending wake.
    fn wait(&mut self);
}

struct XIo {
    conn: Arc<RustConnection>,
    atoms: xserver::Atoms,
    wake_read: OwnedFd,
    /// Slave devices whose x/y valuators are absolute positions (touch
    /// screens): excluded from motion deltas, refreshed on hierarchy
    /// changes.
    absolute_sources: std::collections::HashSet<u16>,
}

/// A raw pointer axis value: `Fp3232` fixed point (integral + frac/2^32).
fn fp3232(value: x11rb::protocol::xinput::Fp3232) -> f64 {
    f64::from(value.integral) + f64::from(value.frac) / 4_294_967_296.0
}

/// Pull one axis's value out of a raw event's packed valuators.
fn axis_value(mask: &[u32], values: &[x11rb::protocol::xinput::Fp3232], axis: u32) -> Option<f64> {
    let word = (axis / 32) as usize;
    let bit = axis % 32;
    if mask.get(word).is_none_or(|w| w & (1 << bit) == 0) {
        return None;
    }
    let mut index = 0usize;
    for earlier in 0..axis {
        let word = (earlier / 32) as usize;
        let bit = earlier % 32;
        if mask.get(word).is_some_and(|w| w & (1 << bit) != 0) {
            index += 1;
        }
    }
    values.get(index).copied().map(fp3232)
}

/// X wheel buttons are discrete ticks: 4/5 vertical (up positive, the
/// Windows sign), 6/7 horizontal (right positive).
fn wheel_for_button(button: u32) -> Option<mouse::RawMouseKind> {
    let (axis, ticks) = match button {
        4 => (gilbreth_core::MouseWheelAxis::Vertical, 1),
        5 => (gilbreth_core::MouseWheelAxis::Vertical, -1),
        6 => (gilbreth_core::MouseWheelAxis::Horizontal, -1),
        7 => (gilbreth_core::MouseWheelAxis::Horizontal, 1),
        _ => return None,
    };
    Some(mouse::RawMouseKind::Wheel { axis, ticks })
}

fn button_for_detail(detail: u32) -> Option<gilbreth_core::MouseButton> {
    Some(match detail {
        1 => gilbreth_core::MouseButton::Left,
        2 => gilbreth_core::MouseButton::Middle,
        3 => gilbreth_core::MouseButton::Right,
        8 => gilbreth_core::MouseButton::X1,
        9 => gilbreth_core::MouseButton::X2,
        _ => return None,
    })
}

fn raw_key(event: &x11rb::protocol::xinput::RawKeyPressEvent, press: bool) -> RawInput {
    RawInput::Key(keyboard::RawKeyEvent {
        keycode: event.detail as u8,
        press,
        flagged_repeat: u32::from(event.flags)
            & u32::from(x11rb::protocol::xinput::KeyEventFlags::KEY_REPEAT)
            != 0,
        time: event.time,
    })
}

impl XIo {
    fn translate(&mut self, event: Event, signals: &mut PumpSignals) {
        match event {
            Event::PropertyNotify(notify) if notify.atom == self.atoms._NET_ACTIVE_WINDOW => {
                signals.focus_dirty = true;
            }
            Event::MappingNotify(_) => signals.keymap_dirty = true,
            Event::XinputRawKeyPress(event) => signals.raw_inputs.push(raw_key(&event, true)),
            Event::XinputRawKeyRelease(event) => signals.raw_inputs.push(raw_key(&event, false)),
            Event::XinputRawButtonPress(event) => {
                if let Some(wheel) = wheel_for_button(event.detail) {
                    signals.raw_inputs.push(RawInput::Mouse(wheel));
                } else if let Some(button) = button_for_detail(event.detail) {
                    signals
                        .raw_inputs
                        .push(RawInput::Mouse(mouse::RawMouseKind::Down(button)));
                }
            }
            Event::XinputRawButtonRelease(event) => {
                // Wheel ticks are press-only; 4-7 releases carry nothing.
                if wheel_for_button(event.detail).is_none() {
                    if let Some(button) = button_for_detail(event.detail) {
                        signals
                            .raw_inputs
                            .push(RawInput::Mouse(mouse::RawMouseKind::Up(button)));
                    }
                }
            }
            Event::XinputRawMotion(event) => {
                if self.absolute_sources.contains(&event.sourceid) {
                    return;
                }
                let dx = axis_value(&event.valuator_mask, &event.axisvalues, 0).unwrap_or(0.0);
                let dy = axis_value(&event.valuator_mask, &event.axisvalues, 1).unwrap_or(0.0);
                let dx = dx.round() as i32;
                let dy = dy.round() as i32;
                if dx != 0 || dy != 0 {
                    signals
                        .raw_inputs
                        .push(RawInput::Mouse(mouse::RawMouseKind::Moved { dx, dy }));
                }
            }
            Event::XinputHierarchy(_) | Event::XinputDeviceChanged(_) => {
                self.absolute_sources = xserver::absolute_pointer_sources(&self.conn);
            }
            _ => {}
        }
    }
}

impl PumpIo for XIo {
    fn drain(&mut self) -> PumpSignals {
        let mut signals = PumpSignals::default();
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(event)) => self.translate(event, &mut signals),
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "X connection failed; capture pump exiting");
                    signals.connection_lost = true;
                    return signals;
                }
            }
        }
        if let Err(error) = self.conn.flush() {
            warn!(%error, "X connection flush failed; capture pump exiting");
            signals.connection_lost = true;
        }
        signals
    }

    fn wait(&mut self) {
        wait_for_activity(
            self.conn.stream().as_fd().as_raw_fd(),
            self.wake_read.as_raw_fd(),
        );
        drain_wake_pipe(self.wake_read.as_fd());
    }
}

/// The pump's capture providers, injected so tests drive scripted state
/// through the real pump loop without an X server (the macOS `Sources`
/// pattern).
struct Sources<AW, ID, KM, PP, VS, SI, PR, SE> {
    active_window: AW,
    idle: ID,
    /// The keymap read, called at start and on `keymap_dirty`.
    keymap: KM,
    /// The per-pass pointer-position sample (raw events carry none).
    pointer_position: PP,
    /// The virtual-screen shape (root geometry), on the 1 s cadence.
    screen: VS,
    /// The one-shot host identity payload.
    info: SI,
    /// The procfs sweep; the shared core monitor throttles the cadence.
    processes: PR,
    /// The D-Bus session snapshot (elogind + the locker surface).
    session: SE,
}

/// Run the capture pump on the current thread until the stop token cancels
/// or [`stop_pump`] is called. Services `after_service` after every wake,
/// X event batch, or timeout, mirroring the Windows pump's per-message
/// servicing. The capture channel is held open for the duration so the
/// forwarder/writer pipeline sees the same channel lifetime it does under
/// the other pumps.
pub fn run_pump<F>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    let (conn, screen_num) = x11rb::connect(None).map_err(|error| {
        CaptureError::Source(format!("cannot connect to the X server: {error}").into())
    })?;
    let conn = Arc::new(conn);
    let root = conn.setup().roots[screen_num].root;
    let atoms = xserver::Atoms::new(&*conn)
        .map_err(|error| CaptureError::Source(format!("atom interning failed: {error}").into()))?
        .reply()
        .map_err(|error| CaptureError::Source(format!("atom interning failed: {error}").into()))?;
    xserver::select_root_property_events(&conn, root)
        .map_err(|error| CaptureError::Source(error.into()))?;
    xserver::select_raw_input_events(&conn, root)
        .map_err(|error| CaptureError::Source(error.into()))?;
    let absolute_sources = xserver::absolute_pointer_sources(&conn);

    let (wake_read, wake_write) = wake_pipe()?;
    let stop_requested = Arc::new(AtomicBool::new(false));
    {
        let mut slot = pump_write();
        if slot.is_some() {
            return Err(CaptureError::Source(
                "a capture pump is already registered in this process".into(),
            ));
        }
        *slot = Some(PumpHandle {
            wake_write,
            stop_requested: stop_requested.clone(),
        });
    }
    let _registration = RegistrationGuard;

    info!(
        "Linux capture pump running: X11 connection + self-pipe waker + \
         EWMH foreground, X idle clock, XI2 raw keyboard/mouse, display \
         shape, procfs process, and D-Bus session streams"
    );

    let session_watch = dbus::spawn_session_watch();
    let reader = xserver::XReader::new(Arc::clone(&conn), root, atoms);
    let idle_reader = reader.clone();
    let keymap_reader = reader.clone();
    let pointer_reader = reader.clone();
    let screen_reader = reader.clone();
    let session_reader = session_watch.clone();
    let result = run_pump_loop(
        tx,
        stop,
        stop_requested,
        controls,
        after_service,
        XIo {
            conn,
            atoms,
            wake_read,
            absolute_sources,
        },
        Sources {
            active_window: move || reader.active_window(),
            idle: move || idle_reader.idle_ms(),
            keymap: move || keymap_reader.keymap(),
            pointer_position: move || pointer_reader.pointer_position(),
            screen: move || screen_reader.virtual_screen(),
            info: system::system_info,
            processes: process::process_snapshot,
            session: move || session_reader.snapshot(),
        },
    );
    session_watch.stop();
    result
}

fn run_pump_loop<F, IO, AW, ID, KM, PP, VS, SI, PR, SE>(
    tx: Sender<Captured>,
    stop: StopToken,
    stop_requested: Arc<AtomicBool>,
    controls: CaptureControls,
    mut after_service: F,
    mut io: IO,
    mut sources: Sources<AW, ID, KM, PP, VS, SI, PR, SE>,
) -> Result<(), CaptureError>
where
    F: FnMut(),
    IO: PumpIo,
    AW: FnMut() -> Option<foreground::ActiveWindow>,
    ID: FnMut() -> Option<u64>,
    KM: FnMut() -> Option<keyboard::Keymap>,
    PP: FnMut() -> Option<(i32, i32)>,
    VS: FnMut() -> Option<system::VirtualScreenRect>,
    SI: FnMut() -> gilbreth_core::EventPayload,
    PR: FnMut() -> Option<Vec<gilbreth_core::ProcessSnapshotEntry>>,
    SE: FnMut() -> Option<session::SessionSnapshot>,
{
    let mut foreground_monitor = foreground::ForegroundMonitor::new(sources.active_window);
    let mut idle_monitor = idle::IdleMonitor::new(controls.idle_threshold(), sources.idle);
    let mut system_monitor = system::SystemMonitor::new(sources.screen, sources.info);
    let mut session_monitor = session::SessionMonitor::new(sources.session);
    let mut process_monitor = gilbreth_core::ProcessMonitor::new(Instant::now());
    let mut keyboard_state = keyboard::KeyboardState::new();
    let mut mouse_state = mouse::MouseState::new();
    let mut keymap: Option<keyboard::Keymap> = None;
    let mut pending_events = Vec::new();
    let mut last_noted_pid: Option<u32> = None;
    let mut session_blocked_last = false;

    let result = loop {
        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        let mut signals = io.drain();
        if signals.connection_lost {
            break Err(CaptureError::Source("X connection lost".into()));
        }

        after_service();

        let now = Instant::now();
        let settings = controls.settings();
        let suspended = controls.is_suspended();
        // System first (the macOS ordering): its session tracking decides
        // whether Foreground may accumulate dwell this pass. The session
        // MECHANISM runs whenever Foreground needs it, independent of the
        // System stream toggle; rows gate at `send` while state advances
        // regardless.
        let system_stream = settings.system && !suspended;
        let foreground_stream = settings.foreground && !suspended;
        system_monitor.poll(now, system_stream, &mut pending_events);
        session_monitor.poll(now, system_stream, foreground_stream, &mut pending_events);
        process_monitor.poll(now, &controls, &mut sources.processes, &mut pending_events);
        let fg_gate = if !foreground_stream {
            foreground::PollGate::PausedByUser
        } else if session_monitor.session_blocked() {
            foreground::PollGate::BlockedBySession
        } else {
            foreground::PollGate::Enabled
        };
        foreground_monitor.poll(now, fg_gate, signals.focus_dirty, &mut pending_events);
        // The churn filter's focus rescue (Windows `note_focused_app`,
        // ported): record the active exe once per process change so the
        // process stream keeps this app's start/exit rows.
        if let Some(window) = foreground_monitor.current_window() {
            if last_noted_pid != Some(window.pid) {
                last_noted_pid = Some(window.pid);
                if !window.exe.is_empty() {
                    controls.note_foreground_exe(&window.exe);
                }
            }
        }
        idle_monitor.poll(now, settings.idle && !suspended, &mut pending_events);

        // A session boundary (lock / console switch) resets the input
        // state machines so no chord, drag, or click pair spans the
        // boundary (the twins' reset_after_boundary), and raw input is
        // DROPPED for the duration of the block: X11 keeps delivering raw
        // events while the lock surface is up — what they spell is the
        // unlock password — where Windows and macOS observe an empty
        // stream during a lock. Parity is discarding them before any
        // state machine or channel sees them (the recorded fail-closed
        // posture; see session.rs).
        let session_blocked = session_monitor.session_blocked();
        if session_blocked && !session_blocked_last {
            keyboard_state.reset_after_boundary();
            mouse_state.reset_after_boundary();
        }
        session_blocked_last = session_blocked;
        if session_blocked {
            signals.raw_inputs.clear();
        }

        // Keyboard + mouse: raw input drained this pass runs through the
        // derivation state machines, attributed to the active window just
        // polled (Windows parity; ~one service tick of skew is within the
        // pump's granularity). The machines advance regardless of stream
        // toggles; rows gate at `send`.
        if keymap.is_none() || signals.keymap_dirty {
            keymap = (sources.keymap)();
        }
        let input_window = foreground_monitor.current_window();
        // One position sample serves the whole pass's pointer events (raw
        // events carry no coordinates; sub-tick moves share a position).
        let pass_position = if signals
            .raw_inputs
            .iter()
            .any(|input| matches!(input, RawInput::Mouse(_)))
        {
            (sources.pointer_position)()
        } else {
            None
        };
        for raw in signals.raw_inputs.drain(..) {
            match raw {
                RawInput::Key(event) => {
                    if let Some(keymap) = keymap.as_ref() {
                        pending_events.extend(keyboard_state.on_event(
                            event,
                            keymap,
                            input_window.clone(),
                            now,
                        ));
                    }
                }
                RawInput::Mouse(kind) => {
                    mouse_state.on_event(
                        mouse::RawMouseEvent {
                            kind,
                            pos: pass_position,
                        },
                        input_window.clone(),
                        now,
                        &mut pending_events,
                    );
                }
            }
        }
        mouse_state.flush_due(now, &mut pending_events);

        for captured in pending_events.drain(..) {
            send_captured(&tx, &controls, captured);
        }

        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        io.wait();
    };

    // Shutdown flush: attribute the final foreground dwell and the partial
    // churn window, exactly as the other pumps' shutdown flushes do.
    let mut shutdown_events = Vec::new();
    foreground_monitor.flush_at(Instant::now(), &mut shutdown_events);
    process_monitor.flush(Instant::now(), &mut shutdown_events);
    for captured in shutdown_events {
        send_captured(&tx, &controls, captured);
    }

    let dropped = controls.diagnostics().capture_events_dropped();
    if dropped > 0 {
        warn!(
            dropped,
            "capture dropped events under channel backpressure during this run; \
             writer events_skipped does not include these"
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, thread, time::Duration};

    use crossbeam_channel::bounded;

    use super::*;

    /// Pump tests share the process-global registration slot; serialize them.
    static PUMP_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn x_available() -> bool {
        std::env::var_os("DISPLAY").is_some()
    }

    #[test]
    fn pump_registers_wakes_and_stops() {
        let _serial = PUMP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if !x_available() {
            eprintln!("skipping: no DISPLAY (the pump needs a live X server)");
            return;
        }
        let (tx, _rx) = bounded(8);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let serviced = Arc::new(AtomicBool::new(false));
        let serviced_in_pump = serviced.clone();

        let pump = thread::spawn(move || {
            run_pump(tx, stop, controls, move || {
                serviced_in_pump.store(true, Ordering::SeqCst);
            })
        });

        // The pump registers within its first pass; then a stop must end it.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while pump_read().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "pump never registered"
            );
            thread::sleep(Duration::from_millis(5));
        }
        wake_pump();
        stop_pump();
        pump.join()
            .expect("pump thread must not panic")
            .expect("pump exits cleanly on stop");
        assert!(serviced.load(Ordering::SeqCst), "after_service ran");
        assert!(pump_read().is_none(), "registration cleared on exit");
    }

    #[test]
    fn stop_token_cancellation_plus_wake_ends_the_pump() {
        let _serial = PUMP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if !x_available() {
            eprintln!("skipping: no DISPLAY (the pump needs a live X server)");
            return;
        }
        let (tx, _rx) = bounded(8);
        let stop = StopToken::new();
        let stop_for_pump = stop.clone();
        let controls = CaptureControls::all_enabled();
        let pump = thread::spawn(move || run_pump(tx, stop_for_pump, controls, || {}));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while pump_read().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "pump never registered"
            );
            thread::sleep(Duration::from_millis(5));
        }
        stop.cancel();
        wake_pump();
        pump.join()
            .expect("pump thread must not panic")
            .expect("pump exits cleanly when the stop token cancels");
    }

    #[test]
    fn wake_and_stop_after_exit_are_quiet_no_ops() {
        let _serial = PUMP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert!(pump_read().is_none());
        wake_pump();
        stop_pump();
    }

    /// A scripted io seam: each pass pops the next scripted yield, and an
    /// exhausted script cancels the stop token — the whole loop runs
    /// without an X server. A non-zero `wait` sleeps between passes so a
    /// script can straddle the monitors' real-clock 1 s cadences.
    struct ScriptedIo {
        script: std::collections::VecDeque<PumpSignals>,
        stop: StopToken,
        wait: Duration,
    }

    impl PumpIo for ScriptedIo {
        fn drain(&mut self) -> PumpSignals {
            match self.script.pop_front() {
                Some(signals) => signals,
                None => {
                    self.stop.cancel();
                    PumpSignals::default()
                }
            }
        }

        fn wait(&mut self) {
            if !self.wait.is_zero() {
                thread::sleep(self.wait);
            }
        }
    }

    fn scripted_window() -> Option<foreground::ActiveWindow> {
        Some(foreground::ActiveWindow {
            xid: 42,
            pid: 4242,
            exe: "/usr/bin/editor".to_string(),
            title: "notes".to_string(),
        })
    }

    /// Keycode 8 = 'p' in the scripted keymap.
    fn scripted_keymap() -> Option<keyboard::Keymap> {
        Some(keyboard::Keymap::new(8, 1, vec![0x70]))
    }

    #[test]
    fn scripted_loop_emits_focus_rows_notes_the_exe_and_flushes_on_shutdown() {
        let (tx, rx) = bounded(16);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let io = ScriptedIo {
            script: std::collections::VecDeque::from([
                PumpSignals {
                    focus_dirty: true,
                    ..Default::default()
                },
                PumpSignals::default(),
            ]),
            stop: stop.clone(),
            wait: Duration::ZERO,
        };
        run_pump_loop(
            tx,
            stop,
            Arc::new(AtomicBool::new(false)),
            controls.clone(),
            || {},
            io,
            Sources {
                active_window: scripted_window,
                idle: || Some(0),
                keymap: scripted_keymap,
                pointer_position: || Some((10, 20)),
                screen: || None,
                info: system::system_info,
                processes: || None,
                session: || None,
            },
        )
        .expect("scripted pump exits cleanly");

        let mut kinds = Vec::new();
        while let Ok(captured) = rx.try_recv() {
            kinds.push(captured.payload.kind());
        }
        assert_eq!(
            kinds,
            vec!["system_info", "focus_changed", "focus_changed"],
            "the system seed and dirty-pass focus seed, then the shutdown close"
        );
        assert!(
            controls.foreground_exe_seen("editor"),
            "the churn-filter focus rescue noted the active exe"
        );
    }

    #[test]
    fn scripted_raw_input_becomes_attributed_key_and_mouse_rows() {
        let (tx, rx) = bounded(32);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let io = ScriptedIo {
            script: std::collections::VecDeque::from([PumpSignals {
                focus_dirty: true,
                raw_inputs: vec![
                    RawInput::Key(keyboard::RawKeyEvent {
                        keycode: 8,
                        press: true,
                        flagged_repeat: false,
                        time: 100,
                    }),
                    RawInput::Mouse(mouse::RawMouseKind::Down(gilbreth_core::MouseButton::Left)),
                    RawInput::Mouse(mouse::RawMouseKind::Up(gilbreth_core::MouseButton::Left)),
                    RawInput::Mouse(mouse::RawMouseKind::Wheel {
                        axis: gilbreth_core::MouseWheelAxis::Vertical,
                        ticks: 1,
                    }),
                ],
                ..Default::default()
            }]),
            stop: stop.clone(),
            wait: Duration::ZERO,
        };
        run_pump_loop(
            tx,
            stop,
            Arc::new(AtomicBool::new(false)),
            controls,
            || {},
            io,
            Sources {
                active_window: scripted_window,
                idle: || Some(0),
                keymap: scripted_keymap,
                pointer_position: || Some((10, 20)),
                screen: || None,
                info: system::system_info,
                processes: || None,
                session: || None,
            },
        )
        .expect("scripted pump exits cleanly");

        let mut rows = Vec::new();
        while let Ok(captured) = rx.try_recv() {
            rows.push(captured);
        }
        let kinds: Vec<&str> = rows.iter().map(|row| row.payload.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "system_info",
                "focus_changed",
                "key",
                "mouse_click",
                "mouse_wheel",
                "focus_changed"
            ]
        );
        match &rows[2].payload {
            gilbreth_core::EventPayload::Key { key, window, .. } => {
                assert_eq!(key, "P");
                let window = window.as_ref().expect("attributed to the active window");
                assert_eq!(window.hwnd, 42);
                assert_eq!(window.title, "notes");
            }
            other => panic!("expected key, got {other:?}"),
        }
        match &rows[3].payload {
            gilbreth_core::EventPayload::MouseClick { x, y, window, .. } => {
                assert_eq!((*x, *y), (Some(10), Some(20)), "per-pass position sample");
                assert_eq!(window.as_ref().expect("attributed").hwnd, 42);
            }
            other => panic!("expected click, got {other:?}"),
        }
    }

    #[test]
    fn a_blocked_session_gates_focus_and_discards_raw_input() {
        let (tx, rx) = bounded(32);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let io = ScriptedIo {
            script: std::collections::VecDeque::from([PumpSignals {
                focus_dirty: true,
                raw_inputs: vec![
                    RawInput::Key(keyboard::RawKeyEvent {
                        keycode: 8,
                        press: true,
                        flagged_repeat: false,
                        time: 100,
                    }),
                    RawInput::Mouse(mouse::RawMouseKind::Down(gilbreth_core::MouseButton::Left)),
                ],
                ..Default::default()
            }]),
            stop: stop.clone(),
            wait: Duration::ZERO,
        };
        run_pump_loop(
            tx,
            stop,
            Arc::new(AtomicBool::new(false)),
            controls,
            || {},
            io,
            Sources {
                active_window: scripted_window,
                idle: || Some(0),
                keymap: scripted_keymap,
                pointer_position: || Some((10, 20)),
                screen: || None,
                info: system::system_info,
                processes: || None,
                // Locked from the very first pass: the unlock-password
                // shape — raw events keep arriving while the lock surface
                // is up.
                session: || {
                    Some(session::SessionSnapshot {
                        session_id: 1,
                        on_console: true,
                        locked: true,
                    })
                },
            },
        )
        .expect("scripted pump exits cleanly");

        let mut kinds = Vec::new();
        while let Ok(captured) = rx.try_recv() {
            kinds.push(captured.payload.kind());
        }
        assert_eq!(
            kinds,
            vec!["system_info"],
            "no focus seed (gate blocked), no key or click rows (raw input \
             discarded while the session is blocked), and the first session \
             observation is a baseline, not an edge"
        );
    }

    /// The definition-of-done arc at loop level: lock closes the segment
    /// and writes both rows, unlock reseeds. Real 1.05 s waits straddle
    /// the session monitor's real-clock cadence — the one deliberately
    /// slow test in this module.
    #[test]
    fn scripted_lock_unlock_arc_closes_dwell_and_writes_session_rows() {
        let (tx, rx) = bounded(32);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let locked = Arc::new(AtomicBool::new(false));
        let locked_provider = locked.clone();
        let io = ScriptedIo {
            script: std::collections::VecDeque::from([
                PumpSignals {
                    focus_dirty: true,
                    ..Default::default()
                },
                PumpSignals::default(),
                PumpSignals::default(),
            ]),
            stop: stop.clone(),
            wait: Duration::from_millis(1_050),
        };
        // after_service runs before each pass's polls: pass 1 seeds
        // unlocked, pass 2 samples the lock, pass 3 samples the unlock.
        let lock_sequencer = {
            let locked = locked.clone();
            let mut pass = 0u32;
            move || {
                pass += 1;
                locked.store(pass == 2, Ordering::SeqCst);
            }
        };
        run_pump_loop(
            tx,
            stop,
            Arc::new(AtomicBool::new(false)),
            controls,
            lock_sequencer,
            io,
            Sources {
                active_window: scripted_window,
                idle: || Some(0),
                keymap: scripted_keymap,
                pointer_position: || None,
                screen: || None,
                info: system::system_info,
                processes: || None,
                session: move || {
                    Some(session::SessionSnapshot {
                        session_id: 1,
                        on_console: true,
                        locked: locked_provider.load(Ordering::SeqCst),
                    })
                },
            },
        )
        .expect("scripted pump exits cleanly");

        let mut rows = Vec::new();
        while let Ok(captured) = rx.try_recv() {
            rows.push(captured);
        }
        let kinds: Vec<&str> = rows.iter().map(|row| row.payload.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "system_info",
                "focus_changed", // seed while unlocked
                "session_lock",
                "focus_changed", // the lock closes the segment — dwell stops
                "session_unlock",
                "focus_changed", // the unlock reseeds
                "focus_changed", // shutdown close
            ]
        );
        match &rows[3].payload {
            gilbreth_core::EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert_eq!(prev.as_ref().expect("closing row").hwnd, 42);
                assert!(
                    (900..=1_400).contains(previous_focused_for_ms),
                    "dwell capped at the lock boundary, got {previous_focused_for_ms}"
                );
            }
            other => panic!("expected the boundary close, got {other:?}"),
        }
    }
}
