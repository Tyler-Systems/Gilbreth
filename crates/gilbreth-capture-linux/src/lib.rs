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

mod foreground;
mod hotkey;
mod idle;
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

/// One pass's translated X-event yield, produced by the io seam.
#[derive(Clone, Copy, Debug, Default)]
struct PumpSignals {
    /// A root `PropertyNotify` named `_NET_ACTIVE_WINDOW` this pass.
    focus_dirty: bool,
    /// The X connection died; the pump must exit rather than spin.
    connection_lost: bool,
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
}

impl PumpIo for XIo {
    fn drain(&mut self) -> PumpSignals {
        let mut signals = PumpSignals::default();
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(Event::PropertyNotify(notify)))
                    if notify.atom == self.atoms._NET_ACTIVE_WINDOW =>
                {
                    signals.focus_dirty = true;
                }
                Ok(Some(_)) => {}
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
struct Sources<AW, ID> {
    active_window: AW,
    idle: ID,
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
         EWMH foreground and X idle clock streams"
    );

    let reader = xserver::XReader::new(Arc::clone(&conn), root, atoms);
    let idle_reader = reader.clone();
    run_pump_loop(
        tx,
        stop,
        stop_requested,
        controls,
        after_service,
        XIo {
            conn,
            atoms,
            wake_read,
        },
        Sources {
            active_window: move || reader.active_window(),
            idle: move || idle_reader.idle_ms(),
        },
    )
}

fn run_pump_loop<F, IO, AW, ID>(
    tx: Sender<Captured>,
    stop: StopToken,
    stop_requested: Arc<AtomicBool>,
    controls: CaptureControls,
    mut after_service: F,
    mut io: IO,
    sources: Sources<AW, ID>,
) -> Result<(), CaptureError>
where
    F: FnMut(),
    IO: PumpIo,
    AW: FnMut() -> Option<foreground::ActiveWindow>,
    ID: FnMut() -> Option<u64>,
{
    let mut foreground_monitor = foreground::ForegroundMonitor::new(sources.active_window);
    let mut idle_monitor = idle::IdleMonitor::new(controls.idle_threshold(), sources.idle);
    let mut pending_events = Vec::new();
    let mut last_noted_pid: Option<u32> = None;

    let result = loop {
        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        let signals = io.drain();
        if signals.connection_lost {
            break Err(CaptureError::Source("X connection lost".into()));
        }

        after_service();

        let now = Instant::now();
        let settings = controls.settings();
        let suspended = controls.is_suspended();
        let fg_gate = if settings.foreground && !suspended {
            foreground::PollGate::Enabled
        } else {
            foreground::PollGate::PausedByUser
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

        for captured in pending_events.drain(..) {
            send_captured(&tx, &controls, captured);
        }

        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        io.wait();
    };

    // Shutdown flush: attribute the final foreground dwell, exactly as the
    // Windows and macOS pumps' shutdown flushes do.
    let mut shutdown_events = Vec::new();
    foreground_monitor.flush_at(Instant::now(), &mut shutdown_events);
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

    /// A scripted io seam: pass 1 reports the focus-dirty edge, and the
    /// stop token cancels after a fixed pass count — the whole loop runs
    /// without an X server.
    struct ScriptedIo {
        passes: u32,
        dirty_on_pass: u32,
        stop_after: u32,
        stop: StopToken,
    }

    impl PumpIo for ScriptedIo {
        fn drain(&mut self) -> PumpSignals {
            self.passes += 1;
            let mut signals = PumpSignals::default();
            if self.passes == self.dirty_on_pass {
                signals.focus_dirty = true;
            }
            if self.passes >= self.stop_after {
                self.stop.cancel();
            }
            signals
        }

        fn wait(&mut self) {}
    }

    #[test]
    fn scripted_loop_emits_focus_rows_notes_the_exe_and_flushes_on_shutdown() {
        let (tx, rx) = bounded(16);
        let stop = StopToken::new();
        let controls = CaptureControls::all_enabled();
        let io = ScriptedIo {
            passes: 0,
            dirty_on_pass: 1,
            stop_after: 3,
            stop: stop.clone(),
        };
        run_pump_loop(
            tx,
            stop,
            Arc::new(AtomicBool::new(false)),
            controls.clone(),
            || {},
            io,
            Sources {
                active_window: || {
                    Some(foreground::ActiveWindow {
                        xid: 42,
                        pid: 4242,
                        exe: "/usr/bin/editor".to_string(),
                        title: "notes".to_string(),
                    })
                },
                idle: || Some(0),
            },
        )
        .expect("scripted pump exits cleanly");

        let mut kinds = Vec::new();
        while let Ok(captured) = rx.try_recv() {
            kinds.push(captured.payload.kind());
        }
        assert_eq!(
            kinds,
            vec!["focus_changed", "focus_changed"],
            "the dirty pass seeds the segment; the shutdown flush closes it"
        );
        assert!(
            controls.foreground_exe_seen("editor"),
            "the churn-filter focus rescue noted the active exe"
        );
    }
}
