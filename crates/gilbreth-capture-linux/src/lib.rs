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

mod hotkey;

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
};

use crossbeam_channel::{Sender, TrySendError};
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use tracing::{debug, info, warn};
use x11rb::connection::Connection;

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
#[allow(dead_code)] // consumed by the stream slices
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
    mut after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    // Suppress the unused warnings until the stream slices consume these.
    let _ = (&tx, &controls);

    let (conn, _screen) = x11rb::connect(None).map_err(|error| {
        CaptureError::Source(format!("cannot connect to the X server: {error}").into())
    })?;

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

    info!("Linux capture pump running: X11 connection + self-pipe waker (LIN-1 shell)");

    let x_fd = conn.stream().as_fd().as_raw_fd();
    let result = loop {
        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }

        // Drain everything the X server has queued before servicing, so a
        // burst is handled in one pass rather than one event per tick.
        loop {
            match conn.poll_for_event() {
                Ok(Some(_event)) => {
                    // Stream slices route events here.
                }
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "X connection failed; capture pump exiting");
                    break;
                }
            }
        }
        if let Err(error) = conn.flush() {
            break Err(CaptureError::Source(
                format!("X connection flush failed: {error}").into(),
            ));
        }

        after_service();

        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        wait_for_activity(x_fd, wake_read.as_raw_fd());
        drain_wake_pipe(wake_read.as_fd());
    };

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
}
