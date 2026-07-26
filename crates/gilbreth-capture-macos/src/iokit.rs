//! IOKit providers for the power slice (TCC record, 2026-07-12 power rules):
//! sleep/wake notifications from the root power domain, the spans-sleep
//! continuous clock, and the AC/battery snapshot from IOPowerSources. All CF
//! returns here are owned (`CFRetained`) or plain scalars — nothing
//! autoreleased, like `coregraphics.rs`.
//!
//! The sleep/wake source follows the event-tap shape exactly: a minimal C
//! callback on the pump's CFRunLoop pushes edges into a pump-owned queue and
//! the pump drains it per pass. The one extra duty is the acknowledgement —
//! `kIOMessageCanSystemSleep` and `kIOMessageSystemWillSleep` must be
//! answered with `IOAllowPowerChange` IMMEDIATELY (in the callback), or the
//! OS waits up to 30 s on us: Gilbreth observes sleep, never delays it.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ffi::c_void,
    ptr,
    time::Instant,
};

use objc2_core_foundation::{
    kCFRunLoopCommonModes, CFRetained, CFRunLoop, CFRunLoopSource, CFType,
};
use objc2_io_kit::{
    io_connect_t, io_object_t, io_service_t, kIOMessageCanSystemSleep,
    kIOMessageSystemHasPoweredOn, kIOMessageSystemWillSleep, IOAllowPowerChange,
    IODeregisterForSystemPower, IONotificationPort, IONotificationPortRef,
    IOPSCopyPowerSourcesInfo, IOPSCopyPowerSourcesList, IOPSGetPowerSourceDescription,
    IORegisterForSystemPower, IOServiceClose,
};
use tracing::{info, warn};

use crate::{
    appkit, coregraphics,
    power::{PowerEdge, PowerEdgeSample, PowerSource, PowerStatusSnapshot},
};

/// The spans-sleep monotonic clock in milliseconds — the parity twin of
/// Windows' `GetTickCount64` (the recorded `tick_ms` vocabulary). Darwin's
/// `CLOCK_MONOTONIC` is documented (clock_gettime(3)) to "continue to
/// increment while the system is asleep" — the `mach_continuous_time`
/// clock, already exposed through libc without raw mach FFI or timebase
/// math. Rust's `Instant` is `CLOCK_UPTIME_RAW` (review-verified,
/// Idle/System slice), which pauses during sleep; the divergence between
/// the two is the divergence detector's entire signal. `None` only if the
/// clock read fails (cannot happen for a valid clock id; honesty beats a
/// fabricated 0 that would poison the divergence baseline).
pub(crate) fn continuous_ms() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain out-param read of a documented clock id.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).saturating_mul(1_000) + (ts.tv_nsec as u64) / 1_000_000)
}

/// IOPSKeys.h dictionary keys/values. Local `&str` twins of the vendored
/// `&CStr` constants so the shared CFDictionary readers can take them
/// directly; `iops_keys_match_the_vendored_constants` pins them to the
/// binding's values.
const POWER_SOURCE_STATE_KEY: &str = "Power Source State"; // kIOPSPowerSourceStateKey
const AC_POWER_VALUE: &str = "AC Power"; // kIOPSACPowerValue
const CURRENT_CAPACITY_KEY: &str = "Current Capacity"; // kIOPSCurrentCapacityKey
const MAX_CAPACITY_KEY: &str = "Max Capacity"; // kIOPSMaxCapacityKey
const IS_PRESENT_KEY: &str = "Is Present"; // kIOPSIsPresentKey

/// AC + battery from the first present power source. A Mac with no battery
/// power source (desktop) yields `(None, None)` — honestly unknown, the
/// recorded rule — rather than a fabricated "AC".
fn power_source_sample() -> (Option<bool>, Option<u8>) {
    let Some(blob) = IOPSCopyPowerSourcesInfo() else {
        return (None, None);
    };
    // SAFETY: `blob` is exactly the value IOPSCopyPowerSourcesInfo returned.
    let Some(list) = (unsafe { IOPSCopyPowerSourcesList(Some(&blob)) }) else {
        return (None, None);
    };
    for index in 0..list.count() {
        // SAFETY: index is in bounds; the array holds CFTypeRefs owned by
        // the list, valid for the list's lifetime.
        let source = unsafe { list.value_at_index(index) };
        if source.is_null() {
            continue;
        }
        // SAFETY: non-null power-source handles are valid CFType objects.
        let source = unsafe { &*source.cast::<CFType>() };
        // SAFETY: blob and source come from the two calls above; the
        // binding retains the returned description (no borrow hazard).
        let Some(description) =
            (unsafe { IOPSGetPowerSourceDescription(Some(&blob), Some(source)) })
        else {
            continue;
        };
        if !coregraphics::dictionary_bool(&description, IS_PRESENT_KEY).unwrap_or(true) {
            continue;
        }
        let ac_online = coregraphics::dictionary_string(&description, POWER_SOURCE_STATE_KEY)
            .map(|state| state == AC_POWER_VALUE);
        let battery_percent = match (
            coregraphics::dictionary_number(&description, CURRENT_CAPACITY_KEY),
            coregraphics::dictionary_number(&description, MAX_CAPACITY_KEY),
        ) {
            (Some(current), Some(max)) if max > 0 => {
                Some((current * 100 / max).clamp(0, 100) as u8)
            }
            _ => None,
        };
        return (ac_online, battery_percent);
    }
    (None, None)
}

/// Shared state the sleep/wake callback points at — heap-stable behind a
/// `Box` for the registration's lifetime, the `TapShared` pattern. Callback
/// and drain run on the one pump thread and never overlap a borrow: the
/// callback only fires while a run loop runs (`run_in_mode` or a nested
/// tracking loop) and only pushes; the drain swaps outside both.
struct SleepWakeShared {
    queue: RefCell<VecDeque<PowerEdgeSample>>,
    /// The root-power-domain session for `IOAllowPowerChange`, written once
    /// between registration and source scheduling (the callback cannot fire
    /// before the source is on the loop).
    root_port: Cell<io_connect_t>,
}

/// SAFETY: `sleep_wake_callback` matches `IOServiceInterestCallback`;
/// `refcon` points at the `SleepWakeShared` its `SleepWakeSource` owns and
/// keeps alive until `Drop` removes the run-loop source first.
unsafe extern "C-unwind" fn sleep_wake_callback(
    refcon: *mut c_void,
    _service: io_service_t,
    message_type: u32,
    argument: *mut c_void,
) {
    let shared = unsafe { &*refcon.cast::<SleepWakeShared>() };
    // If/else rather than match: the vendored constants keep Apple's
    // lowerCamel names, which pattern positions would lint on.
    if message_type == kIOMessageCanSystemSleep || message_type == kIOMessageSystemWillSleep {
        // Acknowledge FIRST — observe, never delay (recorded rule). The Can
        // message is idle-sleep's veto phase: allowing it silently is the
        // no-veto posture; only the committed WillSleep is a boundary.
        let _ = IOAllowPowerChange(shared.root_port.get(), argument as isize);
        if message_type == kIOMessageSystemWillSleep {
            shared.queue.borrow_mut().push_back(PowerEdgeSample {
                at: Instant::now(),
                continuous_ms: continuous_ms(),
                edge: PowerEdge::WillSleep,
            });
        }
    } else if message_type == kIOMessageSystemHasPoweredOn {
        // No acknowledgement is expected for HasPoweredOn (SDK doc).
        shared.queue.borrow_mut().push_back(PowerEdgeSample {
            at: Instant::now(),
            continuous_ms: continuous_ms(),
            edge: PowerEdge::DidWake,
        });
    }
    // WillNotSleep and friends: nothing pending to cancel — the Can phase
    // never emitted.
}

/// The registered root-power-domain notification: port + notifier + the
/// run-loop source on the pump's loop (common modes — the shell precedent:
/// an open tray menu must not delay the sleep acknowledgement).
struct SleepWakeSource {
    shared: Box<SleepWakeShared>,
    root_port: io_connect_t,
    notifier: io_object_t,
    notify_port: IONotificationPortRef,
    source: CFRetained<CFRunLoopSource>,
    run_loop: CFRetained<CFRunLoop>,
}

impl SleepWakeSource {
    fn register_on_current_loop() -> Option<Self> {
        let run_loop = CFRunLoop::current()?;
        let shared = Box::new(SleepWakeShared {
            queue: RefCell::new(VecDeque::new()),
            root_port: Cell::new(0),
        });
        let refcon = (&*shared as *const SleepWakeShared as *mut SleepWakeShared).cast::<c_void>();
        let mut notify_port: IONotificationPortRef = ptr::null_mut();
        let mut notifier: io_object_t = 0;
        // SAFETY: refcon points at the boxed shared state this struct owns;
        // the out-params are live stack slots; the callback matches the
        // required ABI.
        let root_port = unsafe {
            IORegisterForSystemPower(
                refcon,
                &mut notify_port,
                Some(sleep_wake_callback),
                &mut notifier,
            )
        };
        if root_port == 0 || notify_port.is_null() {
            warn!("IORegisterForSystemPower failed; sleep/wake boundaries fall back to the divergence detector");
            return None;
        }
        shared.root_port.set(root_port);
        // SAFETY: notify_port is the valid port the registration returned.
        let Some(source) = (unsafe { IONotificationPort::run_loop_source(notify_port) }) else {
            // SAFETY: tearing down exactly what was created above.
            unsafe {
                IODeregisterForSystemPower(&mut notifier);
                IONotificationPort::destroy(notify_port);
            }
            IOServiceClose(root_port);
            warn!("IONotificationPort run-loop source unavailable; sleep/wake boundaries fall back to the divergence detector");
            return None;
        };
        // SAFETY: framework-provided mode constant, initialized before any
        // code here runs.
        let common_modes = unsafe { kCFRunLoopCommonModes };
        run_loop.add_source(Some(&source), common_modes);
        info!("sleep/wake notifications registered on the pump run loop");
        Some(Self {
            shared,
            root_port,
            notifier,
            notify_port,
            source,
            run_loop,
        })
    }

    fn drain(&self) -> Vec<PowerEdgeSample> {
        self.shared.queue.borrow_mut().drain(..).collect()
    }
}

impl Drop for SleepWakeSource {
    fn drop(&mut self) {
        // Remove the source before anything is torn down so the callback
        // can never fire against freed state (the event-tap Drop rule),
        // then unwind the registration in the SDK-documented order:
        // deregister the notifier, destroy the port, close the root-domain
        // session.
        // SAFETY: mode constant as above; the handles are the live ones
        // this struct owns.
        let common_modes = unsafe { kCFRunLoopCommonModes };
        self.run_loop
            .remove_source(Some(&self.source), common_modes);
        unsafe {
            IODeregisterForSystemPower(&mut self.notifier);
            IONotificationPort::destroy(self.notify_port);
        }
        IOServiceClose(self.root_port);
    }
}

/// Production [`PowerSource`]: lazy sleep/wake registration on first drain
/// (the pump thread owns the loop by then — the event-tap lazy pattern), the
/// continuous clock, and IOPS + Low Power Mode as the status snapshot.
pub(crate) struct IoKitPowerSource {
    sleep_wake: SleepWakeState,
}

enum SleepWakeState {
    Unregistered,
    Failed,
    Live(SleepWakeSource),
}

impl IoKitPowerSource {
    pub(crate) fn new() -> Self {
        Self {
            sleep_wake: SleepWakeState::Unregistered,
        }
    }
}

impl PowerSource for IoKitPowerSource {
    fn drain_edges(&mut self) -> Vec<PowerEdgeSample> {
        if matches!(self.sleep_wake, SleepWakeState::Unregistered) {
            self.sleep_wake = match SleepWakeSource::register_on_current_loop() {
                Some(source) => SleepWakeState::Live(source),
                None => SleepWakeState::Failed,
            };
        }
        match &self.sleep_wake {
            SleepWakeState::Live(source) => source.drain(),
            _ => Vec::new(),
        }
    }

    fn continuous_ms(&mut self) -> Option<u64> {
        continuous_ms()
    }

    fn status(&mut self) -> Option<PowerStatusSnapshot> {
        let (ac_online, battery_percent) = power_source_sample();
        Some(PowerStatusSnapshot {
            ac_online,
            battery_percent,
            // Low Power Mode is the recorded `battery_saver` mapping; the
            // API exists on every supported system, so this is always
            // known (false on desktops that never toggle it).
            battery_saver: Some(appkit::low_power_mode_enabled()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iops_keys_match_the_vendored_constants() {
        use objc2_io_kit::{
            kIOPSACPowerValue, kIOPSCurrentCapacityKey, kIOPSIsPresentKey, kIOPSMaxCapacityKey,
            kIOPSPowerSourceStateKey,
        };
        assert_eq!(
            kIOPSPowerSourceStateKey.to_str().unwrap(),
            POWER_SOURCE_STATE_KEY
        );
        assert_eq!(kIOPSACPowerValue.to_str().unwrap(), AC_POWER_VALUE);
        assert_eq!(
            kIOPSCurrentCapacityKey.to_str().unwrap(),
            CURRENT_CAPACITY_KEY
        );
        assert_eq!(kIOPSMaxCapacityKey.to_str().unwrap(), MAX_CAPACITY_KEY);
        assert_eq!(kIOPSIsPresentKey.to_str().unwrap(), IS_PRESENT_KEY);
    }

    #[test]
    fn continuous_clock_is_monotonic_and_plausible() {
        let first = continuous_ms().expect("CLOCK_MONOTONIC reads");
        let second = continuous_ms().expect("CLOCK_MONOTONIC reads");
        assert!(second >= first);
        // Milliseconds since boot: a machine up for even a year stays far
        // under 10^12 ms — a raw-nanosecond mistake would blow this.
        assert!(first < 1_000_000_000_000, "not milliseconds: {first}");
    }

    #[test]
    fn power_source_sample_is_well_formed() {
        // Hardware-dependent values, shape-checked only: a percent, when
        // present, is 0..=100 (this is the live IOPS read on the dev mac;
        // a desktop yields (None, None) and that is the recorded honest
        // answer).
        let (_ac_online, battery_percent) = power_source_sample();
        if let Some(percent) = battery_percent {
            assert!(percent <= 100);
        }
    }
}
