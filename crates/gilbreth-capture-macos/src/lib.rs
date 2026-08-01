#![cfg(target_os = "macos")]

//! macOS capture backend: the CFRunLoop pump/waker, the complete
//! no-permission capture tier of
//! `the macOS TCC and stream rules` — app-granularity
//! `Foreground` (NSWorkspace), `Idle` (the HID idle clock), and `System`
//! (SystemInfo/VirtualScreen seeds, session lock/unlock and console
//! connect/disconnect edges, power boundaries/status, the libproc process
//! sweep, and pasteboard-metadata clipboard rows) — plus the first
//! TCC-gated stream: `Windows` (focused-window granularity + titles via
//! the AX API, Accessibility), which enriches the Foreground rows when
//! granted and degrades to app granularity otherwise, per that record's
//! Windows-titles amendment; plus the `Keyboard` and `Mouse` streams
//! behind one Input Monitoring grant — a single listen-only `CGEventTap`
//! on the pump run loop feeding the ported keyboard/mouse derivation, with
//! `secure_input` sensitive-context labeling. **macOS 13 is the MAC-1
//! floor** (start-gate item 3); every API this crate touches predates it.
//! Mirrors `gilbreth-capture-windows`'s crate-level target gate, so
//! Windows workspace builds see an empty shell here.

mod appkit;
mod ax;
mod clipboard;
mod coregraphics;
mod eventtap;
mod foreground;
mod idle;
mod iokit;
mod keyboard;
mod mouse;
mod password_field;
mod power;
mod process;
mod secure_input;
mod system;

/// The explicit-user-action Accessibility prompt (TCC record: onboarding /
/// Diagnostics only — the pump never prompts). Called by the onboarding
/// permissions panel through the app layer, never by the pump loop.
pub use ax::prompt_accessibility;
/// The explicit-user-action Input Monitoring prompt (same policy as
/// `prompt_accessibility`). Called by the onboarding permissions panel
/// through the app layer, never by the pump loop.
pub use eventtap::request_listen_access;
pub use keyboard::key_name_for_keycode;

/// Non-prompting Accessibility trust read (`AXIsProcessTrusted`) — the
/// grant-state read the Diagnostics permissions panel displays. Trust binds
/// to bundle id + signing identity, so this reads the same for the pump and
/// the dashboard subprocess (same signed bundle); the panel reads it in the
/// pump process, the authority per the TCC record.
pub fn accessibility_trusted() -> bool {
    ax::process_trusted()
}

/// Non-prompting Input Monitoring trust read (`CGPreflightListenEventAccess`)
/// — the grant-state read the panel displays. Caveat the panel relies on
/// (recorded live 2026-07-12): this returns true immediately after a grant,
/// but macOS does not begin delivering events to an already-running process
/// until it relaunches — so "preflight true" alone cannot distinguish
/// active from granted-but-needs-relaunch. The panel resolves that with a
/// launch-time baseline (see the app's permission facade).
pub fn input_monitoring_trusted() -> bool {
    eventtap::preflight_listen_access()
}

use std::{
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};

use crossbeam_channel::{Sender, TrySendError};
use gilbreth_core::{CaptureControls, CaptureError, Captured, StopToken};
use objc2_core_foundation::{
    kCFRunLoopCommonModes, kCFRunLoopDefaultMode, CFRetained, CFRunLoop, CFRunLoopRunResult,
    CFRunLoopSource, CFRunLoopSourceContext,
};
use tracing::{debug, info, warn};

/// Longest the loop sleeps between service ticks when nothing fires — the
/// same cadence the MAC-0 stub polled at, so tray responsiveness is
/// unchanged. A wake or any handled source returns control sooner.
const SERVICE_INTERVAL_SECONDS: f64 = 0.05;

/// The live pump's run loop and wake source, registered for the duration of
/// [`run_pump`] and cleared on every exit path so a wake after shutdown is a
/// logged no-op and a later pump (tests run several per process) registers
/// afresh.
struct PumpLoop {
    run_loop: CFRetained<CFRunLoop>,
    wake_source: CFRetained<CFRunLoopSource>,
    /// Latched stop request — the never-lost half of the WM_QUIT analog,
    /// and the pump's SOLE quit authority. `CFRunLoopStop` is only honored
    /// while the loop is inside a run; a stop landing between runs
    /// (notably during the service callback, which is exactly where the
    /// tray-quit path executes) is silently discarded by CoreFoundation —
    /// the flag makes our stop unlosable. The converse matters too (Shell
    /// slice, 2026-07-12): AppKit stops the main run loop for its own
    /// event-routing reasons once NSEvents are dispatched, so a raw
    /// `Stopped` result proves nothing about quitting — the pump absorbs
    /// it and only this flag (or the stop token) ends the loop.
    stop_requested: Arc<AtomicBool>,
}

// SAFETY: the waker surface only calls CFRunLoopSourceSignal, CFRunLoopWakeUp,
// and CFRunLoopStop, which Apple's Threading Programming Guide documents as
// safe to call from any thread ("Core Foundation framework functions that are
// explicitly thread safe" — the run-loop wake/stop/signal set).
unsafe impl Send for PumpLoop {}
unsafe impl Sync for PumpLoop {}

static PUMP_LOOP: RwLock<Option<PumpLoop>> = RwLock::new(None);

fn pump_loop_read() -> std::sync::RwLockReadGuard<'static, Option<PumpLoop>> {
    match PUMP_LOOP.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn pump_loop_write() -> std::sync::RwLockWriteGuard<'static, Option<PumpLoop>> {
    match PUMP_LOOP.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Clears the pump registration and invalidates the wake source on every
/// exit path, including panics, so no waker can signal a run loop whose pump
/// has returned and no source outlives its pump.
struct RegistrationGuard {
    wake_source: CFRetained<CFRunLoopSource>,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        self.wake_source.invalidate();
        *pump_loop_write() = None;
    }
}

/// Wake the pump so it re-checks its stop token and services the tray.
/// Cross-thread safe. After the pump exits this is a quiet no-op: the writer
/// exit reporter legitimately wakes an already-gone pump during an orderly
/// quit, so a routine shutdown must not add warning lines to the log.
pub fn wake_pump() {
    if let Some(pump) = pump_loop_read().as_ref() {
        pump.wake_source.signal();
        pump.run_loop.wake_up();
    } else {
        debug!("pump wake requested but no capture pump is registered");
    }
}

/// Ask the pump to exit (the tray-quit path — the macOS analog of
/// `PostQuitMessage`). Latches the stop flag first, because `CFRunLoopStop`
/// alone is discarded whenever the loop is between runs (including during
/// the service callback this is called from); the latch plus the wake makes
/// the stop as unlosable as a posted WM_QUIT. Cross-thread safe; a quiet
/// no-op once the pump has exited.
pub fn stop_pump() {
    if let Some(pump) = pump_loop_read().as_ref() {
        pump.stop_requested.store(true, Ordering::SeqCst);
        pump.wake_source.signal();
        pump.run_loop.wake_up();
        pump.run_loop.stop();
    } else {
        debug!("pump stop requested but no capture pump is registered");
    }
}

/// The wake source's only job is returning control to [`run_pump`]'s
/// stop-check/service point; handling the signal IS the work.
unsafe extern "C-unwind" fn wake_source_perform(_info: *mut c_void) {}

/// The Windows sources' send discipline on the load-bearing parts:
/// `enabled_for` as the defense-in-depth stream gate, `try_send` so capture
/// never blocks the pump, and the shared dropped counter under
/// backpressure. Two deliberate quietenings versus the Windows twin: no
/// per-event warn on a full channel and `debug!` (not `warn!`) on
/// disconnect — sustained backpressure stays one bounded end-of-run warn
/// instead of a log flood, which the soak gates prefer.
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

/// Run the capture pump on the current thread's CFRunLoop until the stop
/// token cancels or [`stop_pump`] is called. Services `after_service` after
/// every handled source or timeout, mirroring the Windows pump's
/// per-message servicing, then polls the Foreground source on the same
/// cadence. The capture channel is held open for the duration so the
/// forwarder/writer pipeline sees the same channel lifetime it does under
/// the Windows pump.
pub fn run_pump<F>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    after_service: F,
) -> Result<(), CaptureError>
where
    F: FnMut(),
{
    let mut window_reader = ax::FocusedWindowReader::new();
    run_pump_with_sources(
        tx,
        stop,
        controls,
        after_service,
        Sources {
            frontmost: appkit::frontmost_app,
            window: move |pid| window_reader.probe(pid),
            ax_trusted: ax::process_trusted,
            idle: coregraphics::hid_idle_ms,
            session: coregraphics::session_snapshot,
            screen: coregraphics::virtual_screen,
            info: coregraphics::system_info,
            input: Box::new(eventtap::EventTapController::new()),
            secure_input: secure_input::secure_input_active,
            pointer_metrics: appkit::pointer_metrics(),
            power: Box::new(iokit::IoKitPowerSource::new()),
            activity: {
                let mut activity = appkit::PumpActivity::new();
                move |wanted| activity.set(wanted)
            },
            processes: coregraphics::process_snapshot,
            pasteboard_count: appkit::pasteboard_change_count,
            pasteboard_types: appkit::pasteboard_types,
            secure_field: ax::SecureFieldReader::new(),
        },
    )
}

/// The pump's capture providers, injected so tests drive scripted state
/// through the real pump loop without touching AppKit, CoreGraphics, the AX
/// API, or a real event tap.
struct Sources<FM, WP, AT, ID, SS, VS, SI, SC, AC, PR, CC, CT, SF> {
    frontmost: FM,
    window: WP,
    ax_trusted: AT,
    idle: ID,
    session: SS,
    screen: VS,
    info: SI,
    /// The event-tap seam (real `EventTapController` in production, a
    /// scripted mock in tests).
    input: Box<dyn eventtap::InputTap>,
    secure_input: SC,
    pointer_metrics: mouse::PointerMetrics,
    /// The power seam (real `IoKitPowerSource` in production, a scripted
    /// mock in tests): sleep/wake edges, the continuous clock, and the
    /// AC/battery/Low-Power-Mode snapshot.
    power: Box<dyn power::PowerSource>,
    /// The App Nap activity seam, edge-called with "any stream enabled and
    /// not suspended" (real `PumpActivity` in production).
    activity: AC,
    /// The libproc sweep (real `process_snapshot` in production, scripted
    /// in tests); the monitor throttles it to the 5 s cadence.
    processes: PR,
    /// The pasteboard seam (TCC record clipboard rules, 2026-07-12): the
    /// cheap changeCount scalar sampled on the 1 s cadence, and the
    /// declared-types list read only when a change will emit.
    pasteboard_count: CC,
    pasteboard_types: CT,
    /// The AX secure-field seam (password-field slice + the O3 pair):
    /// probes are consulted only on emitting key-downs, cache-bounded,
    /// while Accessibility is trusted; the seam also carries the
    /// assistive-activation announce/retract operations (real
    /// `SecureFieldReader` in production, scripted sources — or bare
    /// probe closures via the blanket impl — in tests).
    secure_field: SF,
}

#[allow(clippy::type_complexity)]
fn run_pump_with_sources<F, FM, WP, AT, WK, ID, SS, VS, SI, SC, AC, PR, CC, CT, SF>(
    tx: Sender<Captured>,
    stop: StopToken,
    controls: CaptureControls,
    mut after_service: F,
    sources: Sources<FM, WP, AT, ID, SS, VS, SI, SC, AC, PR, CC, CT, SF>,
) -> Result<(), CaptureError>
where
    F: FnMut(),
    FM: FnMut() -> Option<foreground::FrontmostApp>,
    WP: FnMut(i32) -> foreground::WindowProbe<WK>,
    AT: FnMut() -> bool,
    WK: PartialEq + Clone,
    ID: FnMut() -> Option<u64>,
    SS: FnMut() -> Option<system::SessionSnapshot>,
    VS: FnMut() -> Option<system::VirtualScreenRect>,
    SI: FnMut() -> gilbreth_core::EventPayload,
    SC: FnMut() -> bool,
    AC: FnMut(bool),
    PR: FnMut() -> Option<Vec<process::ProcessSnapshotEntry>>,
    CC: FnMut() -> Option<i64>,
    CT: FnMut() -> Option<Vec<String>>,
    SF: ax::SecureFieldSource,
{
    let run_loop = CFRunLoop::current()
        .ok_or_else(|| CaptureError::Source("no CFRunLoop for the pump thread".into()))?;

    let mut wake_context = CFRunLoopSourceContext {
        version: 0,
        info: ptr::null_mut(),
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: Some(wake_source_perform),
    };
    // SAFETY: the context is a valid version-0 source description whose only
    // callback is a no-op `perform`; CFRunLoopSourceCreate copies the struct,
    // so its stack lifetime ends safely with this call.
    let wake_source = unsafe { CFRunLoopSource::new(None, 0, &mut wake_context) }
        .ok_or_else(|| CaptureError::Source("CFRunLoopSourceCreate failed".into()))?;

    let stop_requested = Arc::new(AtomicBool::new(false));
    {
        let mut slot = pump_loop_write();
        if slot.is_some() {
            return Err(CaptureError::Source(
                "a capture pump is already registered in this process".into(),
            ));
        }
        *slot = Some(PumpLoop {
            run_loop: run_loop.clone(),
            wake_source: wake_source.clone(),
            stop_requested: stop_requested.clone(),
        });
    }
    let _registration = RegistrationGuard {
        wake_source: wake_source.clone(),
    };

    // SAFETY: reading framework-provided extern statics; CoreFoundation
    // initializes its mode constants before any code here can run.
    let default_mode = unsafe { kCFRunLoopDefaultMode };
    let common_modes = unsafe { kCFRunLoopCommonModes };
    // Common modes, not default (Shell slice, 2026-07-12): while a tray menu
    // is open, AppKit tracks it in a nested run loop in the event-tracking
    // mode, and a default-mode-only wake source would sit unserviced until
    // the menu closed. Default mode is a member of the common set, so the
    // pump's own `run_in_mode(default_mode, ...)` passes see it unchanged.
    run_loop.add_source(Some(&wake_source), common_modes);

    info!(
        "macOS capture pump running: CFRunLoop + wake source + \
         Foreground/Idle/System pollers (no-permission tier) + AX \
         window-titles enrichment + keyboard/mouse event tap when granted"
    );

    let mut poller = foreground::ForegroundPoller::new(sources.frontmost, sources.window);
    let mut ax_trusted = sources.ax_trusted;
    let mut windows_trust = foreground::WindowsStreamTrust::new();
    let mut idle_monitor = idle::IdleMonitor::new(controls.idle_threshold(), sources.idle);
    let mut system_monitor =
        system::SystemMonitor::new(sources.session, sources.screen, sources.info);
    let mut clipboard_monitor =
        clipboard::ClipboardMonitor::new(sources.pasteboard_count, sources.pasteboard_types);
    let mut input_tap = sources.input;
    let mut input_trust = eventtap::InputTrust::new();
    let mut keyboard_state = keyboard::KeyboardState::new();
    let mut mouse_state = mouse::MouseState::new(sources.pointer_metrics);
    let mut secure_input_monitor = secure_input::SecureInputMonitor::new(sources.secure_input);
    let mut secure_field = sources.secure_field;
    let mut password_monitor = password_field::PasswordFieldMonitor::new();
    let mut probe_trust = password_field::ProbeTrust::new();
    let mut power_source = sources.power;
    let mut power_monitor = power::PowerMonitor::new();
    let mut activity = sources.activity;
    let mut activity_held = false;
    let mut processes = sources.processes;
    let mut process_monitor = process::ProcessMonitor::new(Instant::now());
    let mut last_noted_pid: Option<u32> = None;
    let mut session_blocked_last = false;
    let mut pending_events = Vec::new();

    let result = loop {
        if stop.is_cancelled() || stop_requested.load(Ordering::SeqCst) {
            break Ok(());
        }
        let run_result = CFRunLoop::run_in_mode(default_mode, SERVICE_INTERVAL_SECONDS, true);
        after_service();
        let now = Instant::now();
        let settings = controls.settings();
        let suspended = controls.is_suspended();
        let system_stream = settings.system && !suspended;
        let foreground_stream = settings.foreground && !suspended;
        // The AX-gated enrichment composes the user's toggle with live
        // Accessibility trust (probed on enable edges and the slow
        // re-probe cadence — never prompting).
        let windows_stream =
            windows_trust.refresh(now, settings.windows && !suspended, &mut ax_trusted);
        // System first: its session tracking decides whether Foreground may
        // accumulate dwell this pass (locked/off-console sessions must not
        // count as focus time — the Windows pump ends the segment at
        // lock/disconnect for the same reason). The mechanism runs whenever
        // Foreground needs it, independent of the System stream toggle.
        system_monitor.poll(now, system_stream, foreground_stream, &mut pending_events);
        // Clipboard metadata on the same 1 s cadence (TCC record clipboard
        // rules, 2026-07-12): the baseline advances even while the stream is
        // off so off-period copies never replay; rows also gate at send.
        clipboard_monitor.poll(now, system_stream, &mut pending_events);

        // App Nap activity assertion (owner decision, 2026-07-12 rules):
        // held while any stream is enabled, released when capture is
        // paused — never a system/display sleep assertion.
        let activity_wanted = !suspended
            && (settings.foreground
                || settings.windows
                || settings.keyboard
                || settings.mouse
                || settings.system
                || settings.idle);
        if activity_wanted != activity_held {
            activity(activity_wanted);
            activity_held = activity_wanted;
        }

        // Power boundaries (TCC record power rules, 2026-07-12): observed
        // sleep/wake edges first, then the divergence detector for anything
        // the notification path missed. Each boundary does the Windows
        // state work in the ported order — input state machines reset and
        // the open Foreground segment closes BEFORE the power rows — and
        // the next poller pass reseeds the fresh segment. Rows gate at
        // `send` like every stream, so the state work runs even with the
        // System stream off.
        let mut power_boundary = false;
        for sample in power_source.drain_edges() {
            let boundary = match sample.edge {
                power::PowerEdge::WillSleep => power_monitor.on_will_sleep(&sample),
                power::PowerEdge::DidWake => power_monitor.on_did_wake(&sample),
            };
            if let Some(boundary) = boundary {
                mouse_state.reset_after_boundary();
                keyboard_state.reset_after_boundary();
                if boundary.close_foreground {
                    poller.flush_at(sample.at, &mut pending_events);
                }
                pending_events.extend(boundary.rows);
                power_boundary = true;
            }
        }
        if let Some(boundary) = power_monitor.poll_divergence(now, power_source.continuous_ms()) {
            mouse_state.reset_after_boundary();
            keyboard_state.reset_after_boundary();
            if boundary.close_foreground {
                poller.flush_at(now, &mut pending_events);
            }
            pending_events.extend(boundary.rows);
            power_boundary = true;
        }
        // Status sample on the 1 s edge-detect cadence; a boundary forces
        // the sample (Windows samples status at every real resume and
        // recovery).
        power_monitor.poll_status(
            now,
            power_boundary,
            &mut || power_source.status(),
            &mut pending_events,
        );

        // Process launch/exit (TCC record process rules, 2026-07-12): the
        // libproc sweep at the ported Windows 5 s cadence, throttled inside
        // the monitor — sweep-only, no observers. Rows gate at send.
        process_monitor.poll(now, &controls, &mut processes, &mut pending_events);

        let fg_gate = if !foreground_stream {
            foreground::PollGate::PausedByUser
        } else if system_monitor.session_blocked() {
            foreground::PollGate::BlockedBySession
        } else {
            foreground::PollGate::Enabled
        };
        let report = poller.poll(now, fg_gate, windows_stream, &mut pending_events);
        if report.ax_api_disabled {
            windows_trust.on_api_disabled(now);
        }
        // The churn filter's focus rescue (Windows `note_focused_app`,
        // ported): record the frontmost exe once per app change so the
        // process stream keeps this app's start/exit rows. When the window
        // exe is empty (no executableURL — rare), pay for a pid-path
        // resolution so the rescue still works (the Windows review-finding-7
        // fallback); live-only, since scripted tests always carry an exe.
        if let Some(window) = poller.current_window() {
            if last_noted_pid != Some(window.pid) {
                last_noted_pid = Some(window.pid);
                if !window.exe.is_empty() {
                    controls.note_foreground_exe(&window.exe);
                } else if let Some(exe) = coregraphics::exe_path_for_pid(window.pid as i32) {
                    controls.note_foreground_exe(&exe);
                }
            }
        }
        idle_monitor.poll(now, settings.idle && !suspended, &mut pending_events);

        // Keyboard + Mouse: one shared listen-only event tap, gated by the
        // Input Monitoring grant. The tap's callback queued events during the
        // run_in_mode above (and, while a tray menu is open, during AppKit's
        // nested event-tracking run loop — the tap source lives in common
        // modes, and the callback only ever pushes, so no queue borrow can
        // overlap the swap below); here we reconcile the tap to the wanted
        // mask and drain those events into the derivation state machines.
        // Events are attributed to the frontmost window just polled (Windows
        // parity; ~one service tick of skew is within the pump's
        // granularity).
        let keyboard_stream = settings.keyboard && !suspended;
        let mouse_stream = settings.mouse && !suspended;
        let input_wanted = keyboard_stream || mouse_stream;
        let input_trusted = input_trust.refresh(now, input_wanted, &mut || input_tap.preflight());
        let mask = if input_trusted {
            eventtap::wanted_mask(keyboard_stream, mouse_stream)
        } else {
            0
        };
        let pass = input_tap.reconcile(&run_loop, mask);
        if pass.revoked {
            input_trust.on_revoked(now);
        }
        if let Some(count) = pass.timeout_reenabled {
            debug!(
                timeout_disables = count,
                "input tap re-enabled after a timeout"
            );
        }
        // A session boundary (lock / fast-user-switch) resets the input state
        // machines so no keystroke or drag spans the boundary (Windows'
        // reset_after_boundary). Edge-triggered on entering the blocked state.
        let session_blocked = system_monitor.session_blocked();
        if session_blocked && !session_blocked_last {
            keyboard_state.reset_after_boundary();
            mouse_state.reset_after_boundary();
        }
        session_blocked_last = session_blocked;
        let input_window = poller.current_window();
        // AX password-field probe (TCC record, password-field rules): a
        // separate Accessibility trust track from the titles stream — the
        // owner-decided interplay cell keeps keyboard ON while the probe is
        // off-declared. Focus changes bump the generation and set the
        // provisional gate; emitting key-downs consult the cache/probe.
        let probe_live = probe_trust.refresh(now, keyboard_stream, &mut ax_trusted);
        password_monitor.on_probe_liveness(
            probe_live,
            now,
            &controls,
            &mut secure_field,
            &mut pending_events,
        );
        if password_monitor.note_focus(
            input_window.as_ref().map(|window| window.hwnd),
            input_window.as_ref().map(|window| window.pid as i32),
            probe_live,
            now,
            &controls,
            &mut secure_field,
            &mut pending_events,
        ) {
            probe_trust.on_api_disabled(now);
        }
        for (instant, raw) in pass.events {
            match raw {
                eventtap::RawInput::Key(key) => {
                    // Redaction is decided only for a key event that can
                    // actually EMIT a row: a fresh (non-autorepeat) key-down
                    // or a modifier flag edge. Key-ups never emit, and
                    // autorepeat downs are dropped by the derivation — so
                    // probing on them is wasted work, and against a hung app
                    // (a ~0.75 s AX round-trip) a held key would otherwise
                    // re-probe every autorepeat tick on the single-threaded
                    // pump (review finding). Flag *release* edges are probed
                    // too though they never emit — a cache-bounded extra
                    // read, kept for gate simplicity. The Windows per-key
                    // ordering stays; the cache still bounds steady typing
                    // to at most one probe per TTL.
                    let emits_row = !matches!(
                        key.kind,
                        keyboard::RawKeyKind::KeyUp
                            | keyboard::RawKeyKind::KeyDown { autorepeat: true }
                    );
                    let redact = if probe_live && emits_row {
                        let decision = password_monitor.redact_key_at(
                            input_window.as_ref().map(|window| window.hwnd),
                            input_window.as_ref().map(|window| window.pid as i32),
                            instant,
                            &controls,
                            &mut secure_field,
                            &mut pending_events,
                        );
                        if decision.api_disabled {
                            probe_trust.on_api_disabled(now);
                        }
                        decision.redact
                    } else {
                        false
                    };
                    pending_events.extend(keyboard_state.on_event(
                        key,
                        input_window.clone(),
                        instant,
                        redact,
                    ));
                }
                eventtap::RawInput::Mouse(mouse) => {
                    mouse_state.on_event(mouse, input_window.clone(), instant, &mut pending_events);
                }
            }
        }
        mouse_state.flush_due(now, &mut pending_events);
        // secure_input labeling: OS-enforced fail-closed suppression means we
        // receive no keystrokes while active; this labels the quiet period.
        secure_input_monitor.poll(now, keyboard_stream, &mut pending_events);

        for captured in pending_events.drain(..) {
            send_captured(&tx, &controls, captured);
        }
        match run_result {
            CFRunLoopRunResult::Stopped => {
                // ABSORBED, not an exit (Shell slice, 2026-07-12): once the
                // app shell dispatches NSEvents, AppKit — which assumes it
                // owns the main loop — calls CFRunLoopStop for its own
                // event-routing reasons. Observed live: merely hovering the
                // status item ended the pump and cleanly quit the app
                // before any click. The latched stop flag is the sole quit
                // authority (checked at the top of every pass); our own
                // quit path sets it BEFORE stopping the loop, so a Stopped
                // without the latch is AppKit's, not ours.
                debug!("run loop stop absorbed; quit is decided by the stop latch");
            }
            CFRunLoopRunResult::Finished => {
                // Defensive: the wake source stays attached for the pump's
                // lifetime, so "no sources left" means it was invalidated
                // out from under us; exiting beats spinning on a dead loop.
                warn!("capture pump run loop reported no sources; exiting");
                break Ok(());
            }
            _ => {} // TimedOut | HandledSource: service and re-check stop.
        }
    };

    // Drop the event tap first so no callback fires during shutdown.
    input_tap.teardown();
    // Posture restore (O3 pair): clear any assistive-activation
    // announcements on the way out — the liveness-off edge covers stream
    // toggles and revocation, this covers quitting while the probe is
    // live. Idempotent with that edge; a crash skips it (recorded
    // residual: the attribute dies with the target app's next relaunch).
    secure_field.retract_all();
    // Shutdown flush: attribute the final foreground dwell and the partial
    // churn window, exactly as the Windows pump's shutdown flushes do, then
    // account for backpressure drops the same way it does.
    let mut shutdown_events = Vec::new();
    poller.flush_at(Instant::now(), &mut shutdown_events);
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
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex, MutexGuard,
        },
        thread,
        time::Duration,
    };

    use crossbeam_channel::bounded;

    use gilbreth_core::{EventPayload, Source};

    use super::*;

    /// Providers that observe nothing, for pump tests that assert about the
    /// pump rather than the streams. `ax_trusted` is false, so the window
    /// provider must never be called — the panic makes every pump test
    /// enforce the trust-gate composition, not just the foreground.rs
    /// unit tests (review should-fix).
    /// A power seam that observes nothing: no edges, no continuous clock
    /// (the divergence detector stays dormant), no status snapshot — so
    /// lifecycle tests keep their channel-emptiness asserts.
    struct NullPowerSource;

    impl power::PowerSource for NullPowerSource {
        fn drain_edges(&mut self) -> Vec<power::PowerEdgeSample> {
            Vec::new()
        }
        fn continuous_ms(&mut self) -> Option<u64> {
            None
        }
        fn status(&mut self) -> Option<power::PowerStatusSnapshot> {
            None
        }
    }

    /// A one-process snapshot that never changes: the monitor seeds it
    /// silently on the first sweep and stays quiet forever after — no rows,
    /// no failed-sweep warnings.
    fn quiet_process_snapshot() -> Option<Vec<process::ProcessSnapshotEntry>> {
        Some(vec![process::ProcessSnapshotEntry {
            pid: 1,
            comm: "launchd".to_string(),
            path: Some("/sbin/launchd".to_string()),
            start_time_id: Some(1),
        }])
    }

    #[allow(clippy::type_complexity)]
    fn quiet_sources() -> Sources<
        fn() -> Option<foreground::FrontmostApp>,
        fn(i32) -> foreground::WindowProbe<u32>,
        fn() -> bool,
        fn() -> Option<u64>,
        fn() -> Option<system::SessionSnapshot>,
        fn() -> Option<system::VirtualScreenRect>,
        fn() -> EventPayload,
        fn() -> bool,
        fn(bool),
        fn() -> Option<Vec<process::ProcessSnapshotEntry>>,
        fn() -> Option<i64>,
        fn() -> Option<Vec<String>>,
        fn() -> ax::SecureFieldProbe,
    > {
        Sources {
            frontmost: || None,
            window: |_| panic!("window provider called while the AX gate is off"),
            ax_trusted: || false,
            idle: || None,
            session: || None,
            screen: || None,
            info: || EventPayload::SystemInfo {
                host: String::new(),
                os_version: String::new(),
                arch: String::new(),
                processor_count: 0,
                memory_total_bytes: 0,
            },
            // NullInputTap never grants, so the derivation is never reached
            // and no real CGEventTap is created off the main thread.
            input: Box::new(eventtap::NullInputTap),
            secure_input: || false,
            pointer_metrics: mouse::PointerMetrics::default(),
            power: Box::new(NullPowerSource),
            activity: |_| {},
            processes: quiet_process_snapshot,
            // An unreadable pasteboard: the clipboard monitor never
            // baselines, so lifecycle tests keep channel-emptiness asserts.
            pasteboard_count: || None,
            pasteboard_types: || None,
            // ax_trusted is false in quiet tests, so the probe is never
            // live and this provider is never called.
            secure_field: || ax::SecureFieldProbe::CannotAnswer,
        }
    }

    /// A scripted event-tap mock: grants on demand and replays a fixed queue
    /// of raw events across pump passes, so the pump's keyboard/mouse
    /// integration is exercised end-to-end without a real tap or grant.
    struct ScriptedTap {
        granted: bool,
        events: std::sync::Arc<
            std::sync::Mutex<std::collections::VecDeque<(Instant, eventtap::RawInput)>>,
        >,
    }

    impl eventtap::InputTap for ScriptedTap {
        fn preflight(&mut self) -> bool {
            self.granted
        }
        fn reconcile(
            &mut self,
            _run_loop: &CFRetained<CFRunLoop>,
            mask: objc2_core_graphics::CGEventMask,
        ) -> eventtap::TapPass {
            if mask == 0 {
                return eventtap::TapPass::default();
            }
            let drained = self.events.lock().expect("script").drain(..).collect();
            eventtap::TapPass {
                events: drained,
                revoked: false,
                timeout_reenabled: None,
            }
        }
        fn teardown(&mut self) {}
    }

    /// The pump registration is deliberately process-global (one tray app,
    /// one pump), so pump tests must not overlap.
    static PUMP_TEST_SERIAL: Mutex<()> = Mutex::new(());

    fn serialize_pump_test() -> MutexGuard<'static, ()> {
        match PUMP_TEST_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    struct RunningPump {
        capture_rx: crossbeam_channel::Receiver<Captured>,
        exit_rx: crossbeam_channel::Receiver<Result<(), CaptureError>>,
        ticks: Arc<AtomicU64>,
        stop: StopToken,
    }

    /// A failed assert must not leak a live registered pump into the next
    /// test (the registration is process-global): on drop, stop the pump
    /// and wait for its exit so every test leaves a clean slate.
    impl Drop for RunningPump {
        fn drop(&mut self) {
            self.stop.cancel();
            wake_pump();
            let _ = self.exit_rx.recv_timeout(Duration::from_secs(5));
        }
    }

    fn spawn_pump(stop: &StopToken) -> RunningPump {
        let (capture_tx, capture_rx) = bounded::<Captured>(4);
        let (exit_tx, exit_rx) = bounded(1);
        let ticks = Arc::new(AtomicU64::new(0));
        let pump_stop = stop.clone();
        let pump_ticks = ticks.clone();
        thread::spawn(move || {
            // Lifecycle tests run the pump off the main thread, so they
            // inject quiet providers (no AppKit/CoreGraphics off-main-
            // thread) and disable the seeding streams, keeping the
            // channel-emptiness asserts about the pump itself.
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::System, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                move || {
                    pump_ticks.fetch_add(1, Ordering::SeqCst);
                },
                quiet_sources(),
            );
            let _ = exit_tx.send(result);
        });
        RunningPump {
            capture_rx,
            exit_rx,
            ticks,
            stop: stop.clone(),
        }
    }

    /// Deadline-poll until the tick counter passes `from`. Fixed sleeps are
    /// load-flaky on an oversubscribed box (the CI runner shares this dev
    /// machine); polling asserts liveness without betting on the scheduler.
    fn wait_for_tick_past(pump: &RunningPump, from: u64) {
        for _ in 0..1000 {
            if pump.ticks.load(Ordering::SeqCst) > from {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("pump stopped servicing (no tick past {from} within the deadline)");
    }

    fn wait_for_first_tick(pump: &RunningPump) {
        wait_for_tick_past(pump, 0);
    }

    #[test]
    fn pump_exits_on_stop_token_with_wake_and_keeps_the_channel_open() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let pump = spawn_pump(&stop);
        wait_for_first_tick(&pump);

        // The channel must stay open while the pump runs (no premature
        // disconnect for the forwarder), and close when it exits.
        assert!(matches!(
            pump.capture_rx.try_recv(),
            Err(crossbeam_channel::TryRecvError::Empty)
        ));

        stop.cancel();
        wake_pump();
        pump.exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits promptly after cancel + wake")
            .expect("pump result");
        assert!(matches!(
            pump.capture_rx.try_recv(),
            Err(crossbeam_channel::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn pump_exits_on_stop_pump_without_token_cancel() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let pump = spawn_pump(&stop);
        wait_for_first_tick(&pump);

        // The stop token is deliberately left uncancelled to pin the latched
        // half of the contract: stop_pump alone must suffice, however it
        // races the loop (CFRunLoopStop between runs is discarded by CF; the
        // latch makes it as unlosable as a posted WM_QUIT). Production
        // cancels the token first on both platforms — this test enforces
        // the stronger guarantee so that ordering is a courtesy, not a
        // load-bearing requirement.
        stop_pump();
        pump.exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits promptly after stop_pump")
            .expect("pump result");
    }

    #[test]
    fn foreign_run_loop_stop_is_absorbed_without_the_latch() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let pump = spawn_pump(&stop);
        wait_for_first_tick(&pump);

        // Once the app shell dispatches NSEvents, AppKit stops the main run
        // loop for its own event-routing reasons (observed live 2026-07-12:
        // hovering the status item cleanly quit the app before any click).
        // A stop that arrives WITHOUT the latch must be absorbed: the pump
        // keeps servicing. Each stop lands either mid-run (absorbed
        // `Stopped` result) or between runs (discarded by CF) — several
        // attempts across ticks make at least one mid-run landing all but
        // certain, and the assertion holds for both landings.
        for _ in 0..3 {
            {
                let guard = pump_loop_read();
                guard
                    .as_ref()
                    .expect("pump registered while running")
                    .run_loop
                    .stop();
            }
            let before = pump.ticks.load(Ordering::SeqCst);
            wait_for_tick_past(&pump, before);
        }
        assert!(
            matches!(
                pump.exit_rx.try_recv(),
                Err(crossbeam_channel::TryRecvError::Empty)
            ),
            "a foreign run-loop stop must not exit the pump"
        );

        // The real quit path still works after the absorbed stops.
        stop_pump();
        pump.exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits promptly after stop_pump")
            .expect("pump result");
    }

    #[test]
    fn pump_registration_clears_on_exit_and_a_second_run_registers_afresh() {
        let _serial = serialize_pump_test();

        let first_stop = StopToken::new();
        let first = spawn_pump(&first_stop);
        wait_for_first_tick(&first);
        first_stop.cancel();
        wake_pump();
        first
            .exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first pump exits")
            .expect("first pump result");

        // With no pump registered, wake/stop must be quiet no-ops.
        wake_pump();
        stop_pump();

        let second_stop = StopToken::new();
        let second = spawn_pump(&second_stop);
        wait_for_first_tick(&second);
        second_stop.cancel();
        wake_pump();
        second
            .exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second pump exits — registration was reclaimed")
            .expect("second pump result");
    }

    #[test]
    fn pump_delivers_foreground_events_from_the_injected_provider() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(16);
        let (exit_tx, exit_rx) = bounded(1);
        let frontmost = Arc::new(std::sync::Mutex::new(None::<foreground::FrontmostApp>));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::System, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        *frontmost.lock().expect("provider lock") = Some(foreground::FrontmostApp {
            pid: 700,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        });
        let seeded = capture_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("seed FocusChanged arrives through the real pump");
        assert!(matches!(seeded.source, Source::Foreground));
        match &seeded.payload {
            EventPayload::FocusChanged { window, prev, .. } => {
                assert_eq!(window.exe, "/Applications/A.app/Contents/MacOS/A");
                assert_eq!(window.title, "");
                assert!(prev.is_none());
            }
            other => panic!("expected FocusChanged, got {other:?}"),
        }

        *frontmost.lock().expect("provider lock") = Some(foreground::FrontmostApp {
            pid: 701,
            exe: "/Applications/B.app/Contents/MacOS/B".to_string(),
        });
        let switched = capture_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("switch FocusChanged arrives");
        match &switched.payload {
            EventPayload::FocusChanged { window, prev, .. } => {
                assert_eq!(window.exe, "/Applications/B.app/Contents/MacOS/B");
                assert_eq!(
                    prev.as_ref().expect("previous window").exe,
                    "/Applications/A.app/Contents/MacOS/A"
                );
            }
            other => panic!("expected FocusChanged, got {other:?}"),
        }

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
        // The shutdown flush attributes B's final dwell.
        let flushed = capture_rx.try_recv().expect("shutdown boundary row");
        match &flushed.payload {
            EventPayload::FocusChanged { window, prev, .. } => {
                assert_eq!(window.exe, "/Applications/B.app/Contents/MacOS/B");
                assert_eq!(prev.as_ref().expect("boundary prev").exe, window.exe);
            }
            other => panic!("expected FocusChanged, got {other:?}"),
        }
    }

    #[test]
    fn pump_enriches_titles_when_trusted_and_degrades_on_revocation() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(16);
        let (exit_tx, exit_rx) = bounded(1);
        let frontmost = Arc::new(std::sync::Mutex::new(Some(foreground::FrontmostApp {
            pid: 700,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        })));
        let probe = Arc::new(std::sync::Mutex::new(foreground::WindowProbe::Window {
            key: 1u32,
            title: "Report — Q3".to_string(),
        }));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        let pump_probe = probe.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::System, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: move |_pid| pump_probe.lock().expect("probe lock").clone(),
                    ax_trusted: || true,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        // Trusted + enabled: the seed row carries the window title through
        // the real pump, trust refresh, and send gate.
        let seeded = capture_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("window-granular seed arrives");
        match &seeded.payload {
            EventPayload::FocusChanged { window, prev, .. } => {
                assert_eq!(window.title, "Report — Q3");
                assert_eq!(window.hwnd, 1, "window id from the shared allocator");
                assert!(prev.is_none());
            }
            other => panic!("expected FocusChanged, got {other:?}"),
        }
        assert!(matches!(seeded.source, Source::Foreground));

        // Revocation mid-run: reads fail ApiDisabled, the pump degrades the
        // stream, and the observed app switch is still attributed — at app
        // granularity with an empty title.
        *probe.lock().expect("probe lock") = foreground::WindowProbe::ApiDisabled;
        *frontmost.lock().expect("provider lock") = Some(foreground::FrontmostApp {
            pid: 701,
            exe: "/Applications/B.app/Contents/MacOS/B".to_string(),
        });
        let degraded = capture_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("degraded switch row arrives");
        match &degraded.payload {
            EventPayload::FocusChanged { window, .. } => {
                assert_eq!(window.exe, "/Applications/B.app/Contents/MacOS/B");
                assert_eq!(window.title, "", "degraded to app granularity");
                assert_eq!(window.hwnd, 2, "app id continues the shared sequence");
            }
            other => panic!("expected FocusChanged, got {other:?}"),
        }

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_delivers_keyboard_and_mouse_rows_through_the_tap_when_granted() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        // A frontmost app so keyboard/mouse rows have a window to attribute to.
        let frontmost = Arc::new(std::sync::Mutex::new(Some(foreground::FrontmostApp {
            pid: 700,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        })));
        // Scripted raw input: 'A' key-down and a left click.
        let base = Instant::now();
        let script: std::collections::VecDeque<(Instant, eventtap::RawInput)> = [
            (
                base,
                eventtap::RawInput::Key(keyboard::RawKeyEvent {
                    keycode: 0x00,
                    kind: keyboard::RawKeyKind::KeyDown { autorepeat: false },
                    flags: 0,
                }),
            ),
            (
                base,
                eventtap::RawInput::Mouse(mouse::RawMouseEvent {
                    kind: mouse::RawMouseKind::Down(gilbreth_core::MouseButton::Left),
                    x: 40,
                    y: 50,
                    input_origin: None,
                }),
            ),
        ]
        .into_iter()
        .collect();
        let events = Arc::new(std::sync::Mutex::new(script));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        let pump_events = events.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            // Keep the pass quiet apart from Foreground + Keyboard + Mouse.
            controls.set_enabled(gilbreth_core::CaptureStream::System, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: Box::new(ScriptedTap {
                        granted: true,
                        events: pump_events,
                    }),
                    secure_input: || false,
                    pointer_metrics: mouse::PointerMetrics::default(),
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        // Assert a keyboard row and a mouse click arrive, both attributed to
        // the frontmost window, through the real pump drain path.
        let mut saw_key = false;
        let mut saw_click = false;
        for _ in 0..8 {
            match capture_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(captured) => match &captured.payload {
                    EventPayload::Key { key, window, .. } => {
                        assert_eq!(key, "A");
                        assert_eq!(
                            window.as_ref().map(|w| w.exe.as_str()),
                            Some("/Applications/A.app/Contents/MacOS/A")
                        );
                        assert!(matches!(captured.source, Source::Keyboard));
                        saw_key = true;
                    }
                    EventPayload::MouseClick { button, window, .. } => {
                        assert_eq!(*button, gilbreth_core::MouseButton::Left);
                        assert!(window.is_some(), "click attributed to the frontmost window");
                        assert!(matches!(captured.source, Source::Mouse));
                        saw_click = true;
                    }
                    _ => {}
                },
                Err(_) => break,
            }
            if saw_key && saw_click {
                break;
            }
        }
        assert!(saw_key, "keyboard row delivered through the tap");
        assert!(saw_click, "mouse click delivered through the tap");

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_redacts_keys_in_a_secure_field_and_labels_the_context() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        let frontmost = Arc::new(std::sync::Mutex::new(Some(foreground::FrontmostApp {
            pid: 700,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        })));
        let base = Instant::now();
        let script: std::collections::VecDeque<(Instant, eventtap::RawInput)> = [(
            base,
            eventtap::RawInput::Key(keyboard::RawKeyEvent {
                keycode: 0x00,
                kind: keyboard::RawKeyKind::KeyDown { autorepeat: false },
                flags: 0,
            }),
        )]
        .into_iter()
        .collect();
        let events = Arc::new(std::sync::Mutex::new(script));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        let pump_events = events.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: quiet.window,
                    // Accessibility trusted: the probe track is live even
                    // though the Windows titles stream is toggled off.
                    ax_trusted: || true,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: Box::new(ScriptedTap {
                        granted: true,
                        events: pump_events,
                    }),
                    secure_input: || false,
                    pointer_metrics: mouse::PointerMetrics::default(),
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: || ax::SecureFieldProbe::Answered { is_secure: true },
                },
            );
            let _ = exit_tx.send(result);
        });

        // The focused element is a secure text field: the key row must
        // arrive content-redacted, and the quiet period must be labeled by
        // the PasswordField sensitive-context row.
        let mut saw_redacted_key = false;
        let mut saw_entered = false;
        for _ in 0..12 {
            match capture_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(captured) => match &captured.payload {
                    EventPayload::Key { key, window, .. } => {
                        assert_eq!(key, "<redacted>", "key content must not leak");
                        assert_eq!(
                            window.as_ref().map(|w| w.title.as_str()),
                            Some("<redacted>"),
                            "window title must not leak"
                        );
                        saw_redacted_key = true;
                    }
                    EventPayload::SensitiveContextEntered {
                        reason: gilbreth_core::SensitiveContextReason::PasswordField,
                    } => {
                        saw_entered = true;
                    }
                    _ => {}
                },
                Err(_) => break,
            }
            if saw_redacted_key && saw_entered {
                break;
            }
        }
        assert!(saw_redacted_key, "redacted key row delivered");
        assert!(saw_entered, "password-field context labeled");

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    /// Records the O3-pair calls the pump routes through the seam; probes
    /// always fail, so the announce threshold is reachable from scripted
    /// keystrokes alone.
    struct RecordingSecureField {
        announced: Arc<Mutex<Vec<i32>>>,
        retract_alls: Arc<AtomicU64>,
    }

    impl ax::SecureFieldSource for RecordingSecureField {
        fn probe(&mut self, _pid: Option<i32>) -> ax::SecureFieldProbe {
            ax::SecureFieldProbe::CannotAnswer
        }
        fn announce(&mut self, pid: i32) {
            self.announced.lock().expect("record lock").push(pid);
        }
        fn retract_all(&mut self) {
            self.retract_alls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn pump_announces_the_frontmost_apps_pid_and_retracts_on_shutdown() {
        // O3-pair plumbing pin: the pid that reaches announce() is the
        // frontmost app's (through input_window), and the pump's exit path
        // restores the passive posture exactly once. 25 scripted emitting
        // key-downs against an always-failing probe cross the announce
        // threshold within the first drained pass.
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, _capture_rx) = bounded::<Captured>(256);
        let (exit_tx, exit_rx) = bounded(1);

        let frontmost = Arc::new(std::sync::Mutex::new(Some(foreground::FrontmostApp {
            pid: 700,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        })));
        let base = Instant::now();
        let script: std::collections::VecDeque<(Instant, eventtap::RawInput)> = (0..25)
            .map(|i| {
                (
                    base + Duration::from_millis(i),
                    eventtap::RawInput::Key(keyboard::RawKeyEvent {
                        keycode: 0x00,
                        kind: keyboard::RawKeyKind::KeyDown { autorepeat: false },
                        flags: 0,
                    }),
                )
            })
            .collect();
        let events = Arc::new(std::sync::Mutex::new(script));
        let announced = Arc::new(Mutex::new(Vec::new()));
        let retract_alls = Arc::new(AtomicU64::new(0));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        let pump_events = events.clone();
        let pump_announced = announced.clone();
        let pump_retracts = retract_alls.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: quiet.window,
                    ax_trusted: || true,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: Box::new(ScriptedTap {
                        granted: true,
                        events: pump_events,
                    }),
                    secure_input: || false,
                    pointer_metrics: mouse::PointerMetrics::default(),
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: RecordingSecureField {
                        announced: pump_announced,
                        retract_alls: pump_retracts,
                    },
                },
            );
            let _ = exit_tx.send(result);
        });

        // Deadline-poll for the announce (the threshold crossing happens in
        // the pass that drains the scripted tap).
        let mut announced_pids = Vec::new();
        for _ in 0..1000 {
            announced_pids = announced.lock().expect("record lock").clone();
            if !announced_pids.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            announced_pids,
            vec![700],
            "the announce carries the frontmost app's pid, exactly once"
        );
        assert_eq!(
            retract_alls.load(Ordering::SeqCst),
            0,
            "no retraction while the pump runs live"
        );

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
        assert_eq!(
            retract_alls.load(Ordering::SeqCst),
            1,
            "the exit path restores the passive posture exactly once"
        );
    }

    #[test]
    fn pump_probes_once_per_emitting_key_never_per_autorepeat_tick() {
        // Tail-review pin: the autorepeat fix's safety rests on a
        // cross-module invariant — the probed-key set contains every
        // row-emitting kind and excludes autorepeat downs (which the
        // derivation drops). Script one fresh down, then a held-key burst
        // of autorepeat downs each spaced PAST the not-secure TTL: the
        // fresh down re-probes the expired cache once; the autorepeats
        // must not probe at all. Pre-fix each expired autorepeat re-probed
        // (and refreshed) the cache: this test counts 5 there, 2 post-fix
        // (the focus-transition probe + the fresh down's re-probe).
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        let frontmost = Arc::new(std::sync::Mutex::new(Some(foreground::FrontmostApp {
            pid: 701,
            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
        })));
        // Scripted instants sit far past any real pump-pass time so the
        // fresh down definitely finds the focus-transition cache expired,
        // and each autorepeat sits past the 250 ms not-secure TTL of its
        // predecessor — the exact shape that re-probed pre-fix.
        let base = Instant::now() + Duration::from_secs(10);
        let held = |offset_ms: u64| {
            (
                base + Duration::from_millis(offset_ms),
                eventtap::RawInput::Key(keyboard::RawKeyEvent {
                    keycode: 0x00,
                    kind: keyboard::RawKeyKind::KeyDown { autorepeat: true },
                    flags: 0,
                }),
            )
        };
        let script: std::collections::VecDeque<(Instant, eventtap::RawInput)> = [
            (
                base,
                eventtap::RawInput::Key(keyboard::RawKeyEvent {
                    keycode: 0x00,
                    kind: keyboard::RawKeyKind::KeyDown { autorepeat: false },
                    flags: 0,
                }),
            ),
            held(300),
            held(600),
            held(900),
        ]
        .into_iter()
        .collect();
        let events = Arc::new(std::sync::Mutex::new(script));
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let pump_stop = stop.clone();
        let pump_frontmost = frontmost.clone();
        let pump_events = events.clone();
        let pump_probes = probes.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: move || pump_frontmost.lock().expect("provider lock").clone(),
                    window: quiet.window,
                    ax_trusted: || true,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: Box::new(ScriptedTap {
                        granted: true,
                        events: pump_events,
                    }),
                    secure_input: || false,
                    pointer_metrics: mouse::PointerMetrics::default(),
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: move || {
                        pump_probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        ax::SecureFieldProbe::Answered { is_secure: false }
                    },
                },
            );
            let _ = exit_tx.send(result);
        });

        // Exactly one Key row arrives (the derivation drops autorepeats);
        // by the time it is delivered, its pass has made every gate
        // decision for the whole scripted burst.
        let mut key_rows = 0;
        for _ in 0..12 {
            match capture_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(captured) => {
                    if matches!(captured.payload, EventPayload::Key { .. }) {
                        key_rows += 1;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(key_rows, 1, "the fresh down emits; autorepeats do not");

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");

        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "autorepeat ticks must never probe (pre-fix this counts 5)"
        );
    }

    /// A scripted power seam: replays queued sleep/wake edges and a queued
    /// continuous-clock script (repeating the last reading once drained),
    /// so the pump's boundary integration runs without IOKit.
    struct ScriptedPowerSource {
        edges: Arc<std::sync::Mutex<std::collections::VecDeque<power::PowerEdgeSample>>>,
        continuous: Arc<std::sync::Mutex<std::collections::VecDeque<u64>>>,
        last_continuous: Option<u64>,
    }

    impl power::PowerSource for ScriptedPowerSource {
        fn drain_edges(&mut self) -> Vec<power::PowerEdgeSample> {
            self.edges.lock().expect("script").drain(..).collect()
        }
        fn continuous_ms(&mut self) -> Option<u64> {
            if let Some(next) = self.continuous.lock().expect("script").pop_front() {
                self.last_continuous = Some(next);
            }
            self.last_continuous
        }
        fn status(&mut self) -> Option<power::PowerStatusSnapshot> {
            None
        }
    }

    #[test]
    fn pump_delivers_power_boundaries_from_the_injected_source() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        let base = Instant::now();
        let edges: std::collections::VecDeque<power::PowerEdgeSample> = [
            power::PowerEdgeSample {
                at: base,
                continuous_ms: Some(1_000),
                edge: power::PowerEdge::WillSleep,
            },
            power::PowerEdgeSample {
                at: base + Duration::from_millis(50),
                continuous_ms: Some(2_000),
                edge: power::PowerEdge::DidWake,
            },
        ]
        .into_iter()
        .collect();
        let edges = Arc::new(std::sync::Mutex::new(edges));

        let pump_stop = stop.clone();
        let pump_edges = edges.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: quiet.frontmost,
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: Box::new(ScriptedPowerSource {
                        edges: pump_edges,
                        continuous: Arc::new(std::sync::Mutex::new(
                            std::collections::VecDeque::new(),
                        )),
                        last_continuous: None,
                    }),
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        // Both edges drain in one pass: suspend row first, then the matched
        // resume, both System-sourced.
        let mut saw_suspend = false;
        let mut saw_resume = false;
        for _ in 0..8 {
            match capture_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(captured) => match &captured.payload {
                    EventPayload::PowerSuspend { tick_ms } => {
                        assert_eq!(*tick_ms, Some(1_000));
                        assert!(matches!(captured.source, Source::System));
                        assert!(!saw_resume, "suspend row precedes the resume row");
                        saw_suspend = true;
                    }
                    EventPayload::PowerResume {
                        tick_ms,
                        matched_suspend,
                    } => {
                        assert_eq!(*tick_ms, Some(2_000));
                        assert!(matched_suspend, "the suspend edge was observed");
                        saw_resume = true;
                    }
                    _ => {}
                },
                Err(_) => break,
            }
            if saw_suspend && saw_resume {
                break;
            }
        }
        assert!(saw_suspend, "power suspend row delivered");
        assert!(saw_resume, "power resume row delivered");

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_recovers_a_missed_power_boundary_from_clock_divergence() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        // The continuous clock jumps 100 s between the baseline pass and the
        // next while the pump's Instant advances ~one service pass: the
        // divergence IS a slept interval neither notification reported.
        let continuous: std::collections::VecDeque<u64> = [0, 100_000].into_iter().collect();
        let continuous = Arc::new(std::sync::Mutex::new(continuous));

        let pump_stop = stop.clone();
        let pump_continuous = continuous.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: quiet.frontmost,
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: Box::new(ScriptedPowerSource {
                        edges: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
                        continuous: pump_continuous,
                        last_continuous: None,
                    }),
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        let mut recovered = None;
        for _ in 0..8 {
            match capture_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(captured) => {
                    if let EventPayload::PowerBoundaryRecovered {
                        gap_ms,
                        capped_dwell_ms,
                    } = captured.payload
                    {
                        recovered = Some((gap_ms, capped_dwell_ms));
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let (gap_ms, capped_dwell_ms) = recovered.expect("missed boundary recovered");
        assert!(
            (60_000..=100_000).contains(&gap_ms),
            "gap is the clock divergence, got {gap_ms}"
        );
        assert_eq!(
            capped_dwell_ms, 0,
            "macOS attributes no dwell across a slept gap (uptime clock)"
        );

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_delivers_process_rows_with_the_focus_rescue() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);

        // Sweep 1 seeds silently; sweep 2 (one 5 s cadence later) starts the
        // focused app AND a background daemon — the rescue keeps only the
        // focused app's row, exercising the pump's note_foreground_exe
        // wiring end to end (process_filter stays default-on).
        let focused_exe = "/Applications/A.app/Contents/MacOS/A";
        let launchd = process::ProcessSnapshotEntry {
            pid: 1,
            comm: "launchd".to_string(),
            path: Some("/sbin/launchd".to_string()),
            start_time_id: Some(1),
        };
        let sweeps: std::collections::VecDeque<Vec<process::ProcessSnapshotEntry>> = [
            vec![launchd.clone()],
            vec![
                launchd.clone(),
                process::ProcessSnapshotEntry {
                    pid: 700,
                    comm: "A".to_string(),
                    path: Some(focused_exe.to_string()),
                    start_time_id: Some(50),
                },
                process::ProcessSnapshotEntry {
                    pid: 901,
                    comm: "noised".to_string(),
                    path: Some("/usr/libexec/noised".to_string()),
                    start_time_id: Some(60),
                },
            ],
        ]
        .into_iter()
        .collect();
        let sweeps = Arc::new(std::sync::Mutex::new(sweeps));
        let mut last_sweep: Option<Vec<process::ProcessSnapshotEntry>> = None;

        let pump_stop = stop.clone();
        let pump_sweeps = sweeps.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                || {},
                Sources {
                    frontmost: || {
                        Some(foreground::FrontmostApp {
                            pid: 700,
                            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
                        })
                    },
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: move || {
                        if let Some(next) = pump_sweeps.lock().expect("sweeps").pop_front() {
                            last_sweep = Some(next);
                        }
                        last_sweep.clone()
                    },
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        // The focused app's start arrives (one 5 s cadence after the seed);
        // the daemon's start was demoted to the churn summary.
        let mut saw_focused_start = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match capture_rx.recv_timeout(Duration::from_secs(15)) {
                Ok(captured) => {
                    if let EventPayload::ProcessStarted { pid, exe, .. } = &captured.payload {
                        assert_eq!(*pid, 700, "only the focused app's row is kept");
                        assert_eq!(exe, focused_exe);
                        assert!(matches!(captured.source, Source::System));
                        saw_focused_start = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert!(saw_focused_start, "focused app's process row delivered");
        // Same-sweep emissions arrive together: anything already queued
        // must not include the demoted daemon.
        while let Ok(captured) = capture_rx.try_recv() {
            if let EventPayload::ProcessStarted { pid, .. } = &captured.payload {
                assert_ne!(*pid, 901, "background churn must be demoted");
            }
        }

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_delivers_clipboard_rows_from_the_injected_provider() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);
        let change_count = Arc::new(AtomicU64::new(100));
        let ticks = Arc::new(AtomicU64::new(0));

        let pump_stop = stop.clone();
        let pump_count = change_count.clone();
        let pump_ticks = ticks.clone();
        thread::spawn(move || {
            let controls = CaptureControls::all_enabled();
            controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Windows, false);
            controls.set_enabled(gilbreth_core::CaptureStream::Foreground, false);
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                controls,
                move || {
                    pump_ticks.fetch_add(1, Ordering::SeqCst);
                },
                Sources {
                    frontmost: quiet.frontmost,
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: move || Some(pump_count.load(Ordering::SeqCst) as i64),
                    pasteboard_types: || {
                        Some(vec![
                            "public.utf8-plain-text".to_string(),
                            "public.rtf".to_string(),
                        ])
                    },
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        // The launch baseline is silent, and it lands on the first service
        // pass — deadline-poll past pass 1 (tick 2 means pass 1's polls have
        // completed) so the bump below is unambiguously a post-baseline
        // copy, not launch state. Then one 1 s sample later the metadata
        // row lands, System-sourced, sizes None by construction.
        for _ in 0..1000 {
            if ticks.load(Ordering::SeqCst) >= 2 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ticks.load(Ordering::SeqCst) >= 2, "pump never serviced");
        change_count.store(101, Ordering::SeqCst);
        let mut clipboard_row = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match capture_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(captured) => {
                    if matches!(captured.payload, EventPayload::ClipboardUsed { .. }) {
                        clipboard_row = Some(captured);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let captured = clipboard_row.expect("clipboard row delivered through the pump");
        assert!(matches!(captured.source, Source::System));
        match &captured.payload {
            EventPayload::ClipboardUsed {
                sequence_number,
                format_kind,
                format_count,
                text_char_count,
                byte_size,
            } => {
                assert_eq!(*sequence_number, 101);
                assert_eq!(*format_kind, gilbreth_core::ClipboardFormatKind::Text);
                assert_eq!(*format_count, 2);
                assert_eq!(*text_char_count, None);
                assert_eq!(*byte_size, None);
            }
            other => panic!("expected ClipboardUsed, got {other:?}"),
        }

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_holds_and_releases_the_activity_assertion_with_suspension() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(8);
        let (exit_tx, exit_rx) = bounded(1);
        let transitions: Arc<std::sync::Mutex<Vec<bool>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let pump_stop = stop.clone();
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(gilbreth_core::CaptureStream::System, false);
        controls.set_enabled(gilbreth_core::CaptureStream::Idle, false);
        let pump_controls = controls.clone();
        let pump_transitions = transitions.clone();
        thread::spawn(move || {
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                pump_controls,
                || {},
                Sources {
                    frontmost: quiet.frontmost,
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: quiet.session,
                    screen: quiet.screen,
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: move |wanted| {
                        pump_transitions
                            .lock()
                            .expect("transitions lock")
                            .push(wanted);
                    },
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });
        let _keep_channel_open = capture_rx;

        // Deadline-poll (the repo's anti-flake idiom) for each edge.
        let wait_for = |expected: &[bool]| {
            for _ in 0..1000 {
                if transitions.lock().expect("transitions lock").as_slice() == expected {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
            panic!(
                "activity transitions never reached {expected:?}, got {:?}",
                transitions.lock().expect("transitions lock")
            );
        };

        // Streams enabled and not suspended: held once, no repeats.
        wait_for(&[true]);

        // Pausing capture releases the assertion; resuming re-holds it.
        controls.set_suspended(true);
        wake_pump();
        wait_for(&[true, false]);
        controls.set_suspended(false);
        wake_pump();
        wait_for(&[true, false, true]);

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn pump_lock_edge_blocks_foreground_and_unlock_reseeds() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let (capture_tx, capture_rx) = bounded::<Captured>(32);
        let (exit_tx, exit_rx) = bounded(1);
        let session = Arc::new(std::sync::Mutex::new(Some(system::SessionSnapshot {
            session_id: 257,
            on_console: true,
            locked: false,
        })));

        let pump_stop = stop.clone();
        let pump_session = session.clone();
        thread::spawn(move || {
            let quiet = quiet_sources();
            let result = run_pump_with_sources(
                capture_tx,
                pump_stop,
                CaptureControls::all_enabled(),
                || {},
                Sources {
                    frontmost: || {
                        Some(foreground::FrontmostApp {
                            pid: 800,
                            exe: "/Applications/A.app/Contents/MacOS/A".to_string(),
                        })
                    },
                    window: quiet.window,
                    ax_trusted: quiet.ax_trusted,
                    idle: quiet.idle,
                    session: move || *pump_session.lock().expect("session lock"),
                    screen: || {
                        Some(system::VirtualScreenRect {
                            x0: 0,
                            y0: 0,
                            width: 1000,
                            height: 800,
                        })
                    },
                    info: quiet.info,
                    input: quiet.input,
                    secure_input: quiet.secure_input,
                    pointer_metrics: quiet.pointer_metrics,
                    power: quiet.power,
                    activity: quiet.activity,
                    processes: quiet.processes,
                    pasteboard_count: quiet.pasteboard_count,
                    pasteboard_types: quiet.pasteboard_types,
                    secure_field: quiet.secure_field,
                },
            );
            let _ = exit_tx.send(result);
        });

        let recv_kind = || {
            capture_rx
                .recv_timeout(Duration::from_secs(5))
                .map(|captured| captured.payload.kind())
        };
        // Startup: SystemInfo + VirtualScreen seeds, then the focus seed.
        assert_eq!(recv_kind().expect("system info seed"), "system_info");
        assert_eq!(recv_kind().expect("screen seed"), "virtual_screen");
        assert_eq!(recv_kind().expect("focus seed"), "focus_changed");

        // Lock: the SessionLock edge lands, and the foreground segment
        // closes with a persisted boundary row (the stream is still
        // enabled — a lock is not a user pause, so unlike the disable path
        // the closing row passes the send gate).
        session
            .lock()
            .expect("session lock")
            .as_mut()
            .unwrap()
            .locked = true;
        assert_eq!(recv_kind().expect("lock edge"), "session_lock");
        assert_eq!(recv_kind().expect("lock boundary row"), "focus_changed");

        // Locked steady state: nothing flows (foreground is blocked).
        assert!(
            capture_rx.recv_timeout(Duration::from_millis(400)).is_err(),
            "no rows accumulate while locked"
        );

        // Unlock: the SessionUnlock edge lands and foreground re-seeds.
        session
            .lock()
            .expect("session lock")
            .as_mut()
            .unwrap()
            .locked = false;
        assert_eq!(recv_kind().expect("unlock edge"), "session_unlock");
        assert_eq!(recv_kind().expect("post-unlock reseed"), "focus_changed");

        stop.cancel();
        wake_pump();
        exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits")
            .expect("pump result");
    }

    #[test]
    fn waker_stays_effective_across_repeated_signals() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let pump = spawn_pump(&stop);
        wait_for_first_tick(&pump);

        // Wake twice while running: a waker that goes dead after its first
        // signal would leave the final cancel+wake relying on the timeout
        // cadence alone; the deadline-polled tick advances show servicing
        // continued after each signal.
        let after_first_tick = pump.ticks.load(Ordering::SeqCst);
        wake_pump();
        wait_for_tick_past(&pump, after_first_tick);
        let after_second_wake = pump.ticks.load(Ordering::SeqCst);
        wake_pump();
        wait_for_tick_past(&pump, after_second_wake);

        stop.cancel();
        wake_pump();
        pump.exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump exits promptly after the third wake")
            .expect("pump result");
    }

    #[test]
    fn second_concurrent_pump_is_refused_without_disturbing_the_first() {
        let _serial = serialize_pump_test();
        let stop = StopToken::new();
        let pump = spawn_pump(&stop);
        wait_for_first_tick(&pump);

        // A second pump in the same process must be refused outright and
        // must not clobber the live registration.
        let (orphan_tx, _orphan_rx) = bounded::<Captured>(1);
        let refused = run_pump(
            orphan_tx,
            StopToken::new(),
            CaptureControls::all_enabled(),
            || {},
        );
        assert!(refused.is_err(), "a concurrent second pump must be refused");

        // The first pump is still live and still stoppable through the
        // registered surface.
        let ticks_before = pump.ticks.load(Ordering::SeqCst);
        wait_for_tick_past(&pump, ticks_before);
        stop_pump();
        pump.exit_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first pump still stops cleanly")
            .expect("first pump result");
    }
}
