//! Real providers for the Idle and System streams, all CoreGraphics/libc —
//! no TCC permission (per the amended TCC record) and no AppKit objects, so
//! unlike `appkit.rs` there is nothing autoreleased here: every CF value is
//! either returned by value or owned (`CFRetained` from a Copy-rule
//! function). Keep it that way — anything autoreleased on the pump thread
//! must go inside `objc2::rc::autoreleasepool` (the Foreground review
//! blocker).

use std::{ffi::CString, ptr};

use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_core_graphics::{
    CGDirectDisplayID, CGError, CGEventSource, CGEventSourceStateID, CGEventType,
    CGGetActiveDisplayList, CGSessionCopyCurrentDictionary,
};

use crate::system::{SessionSnapshot, VirtualScreenRect};

/// `kCGAnyInputEventType` — CoreGraphics defines it as `(CGEventType)(~0)`;
/// the vendored bindings expose the type (a `u32` newtype) but not this
/// constant.
const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);

/// System-wide HID idle time in milliseconds: the seconds-since-last-input
/// counter of the HID event system — the same clock the recorded IOKit
/// `HIDIdleTime` property exposes, read through the already-vendored
/// CoreGraphics binding. Reading the *timer* needs no Input Monitoring;
/// only event *content* is TCC-gated.
pub(crate) fn hid_idle_ms() -> Option<u64> {
    let seconds = CGEventSource::seconds_since_last_event_type(
        CGEventSourceStateID::HIDSystemState,
        ANY_INPUT_EVENT_TYPE,
    );
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some((seconds * 1000.0) as u64)
}

/// Current session state from the CoreGraphics session dictionary.
/// `CGSessionCopyCurrentDictionary` follows the Copy rule (owned return);
/// key semantics: `kCGSSessionOnConsoleKey` is a CFBoolean;
/// `CGSSessionScreenIsLocked` is only present while the screen is locked;
/// the session id is `kCGSSessionAuditIDKey` (the audit session id, a
/// CFNumber — independent-review finding: the older `kCGSSessionIDKey`
/// name is simply absent from the dictionary on modern macOS, verified
/// empirically on 26.5.2, and would have fabricated a constant 0). Returns
/// None outside a login session (the dictionary itself is NULL there).
pub(crate) fn session_snapshot() -> Option<SessionSnapshot> {
    let dictionary = CGSessionCopyCurrentDictionary()?;
    let session_id = dictionary_number(&dictionary, "kCGSSessionAuditIDKey")
        .and_then(|id| u32::try_from(id).ok())
        .unwrap_or(0);
    let on_console = dictionary_bool(&dictionary, "kCGSSessionOnConsoleKey").unwrap_or(false);
    let locked = dictionary_bool(&dictionary, "CGSSessionScreenIsLocked").unwrap_or(false);
    Some(SessionSnapshot {
        session_id,
        on_console,
        locked,
    })
}

// Shared CFDictionary readers — also used by the power slice's IOPS
// dictionary parsing in iokit.rs.
pub(crate) fn dictionary_value<'a>(dictionary: &'a CFDictionary, key: &str) -> Option<&'a CFType> {
    let key = CFString::from_str(key);
    // SAFETY: the key CFString outlives the call; the returned pointer, when
    // non-null, is a CF object owned by the dictionary and valid for the
    // dictionary's lifetime, which the 'a bound ties it to.
    let value = unsafe { dictionary.value(CFRetained::<CFString>::as_ptr(&key).as_ptr().cast()) };
    if value.is_null() {
        return None;
    }
    // SAFETY: non-null values in a CFDictionary are valid CFType objects.
    Some(unsafe { &*(value as *const CFType) })
}

pub(crate) fn dictionary_bool(dictionary: &CFDictionary, key: &str) -> Option<bool> {
    dictionary_value(dictionary, key)?
        .downcast_ref::<CFBoolean>()
        .map(CFBoolean::as_bool)
}

pub(crate) fn dictionary_number(dictionary: &CFDictionary, key: &str) -> Option<i64> {
    dictionary_value(dictionary, key)?
        .downcast_ref::<CFNumber>()
        .and_then(CFNumber::as_i64)
}

pub(crate) fn dictionary_string(dictionary: &CFDictionary, key: &str) -> Option<String> {
    dictionary_value(dictionary, key)?
        .downcast_ref::<CFString>()
        .map(|value| value.to_string())
}

/// Full executable path for a pid via `proc_pidpath` (the mac analog of
/// `QueryFullProcessImageNameW`). None when the path is unreadable — some
/// other-user/system processes deny it to an unprivileged caller.
pub(crate) fn exe_path_for_pid(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is live and sized per the API's documented maximum.
    let len = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            libc::PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    if len <= 0 {
        return None;
    }
    buffer.truncate(len as usize);
    let path = String::from_utf8_lossy(&buffer).into_owned();
    (!path.trim().is_empty()).then_some(path)
}

/// One libproc sweep — the mac analog of the Toolhelp snapshot (TCC record
/// process rules: sweep-only at the ported 5 s cadence). Per pid:
/// `proc_pidinfo(PROC_PIDTBSDINFO)` for the kernel name (`pbi_comm`,
/// 15 bytes) and the start time (the PID-reuse identity), then
/// `proc_pidpath` for the untruncated full path. A process denying every
/// unprivileged read (no name by any route) is skipped — unlike Windows,
/// whose snapshot always carries a name; recorded nuance. `None` when the
/// pid list itself cannot be read (treated as a failed sweep, state kept).
pub(crate) fn process_snapshot() -> Option<Vec<crate::process::ProcessSnapshotEntry>> {
    // SAFETY: a null-buffer call returns the space needed (documented).
    let needed = unsafe { libc::proc_listallpids(ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }
    // Headroom for processes spawned between the size call and the fill.
    let capacity = (needed as usize).saturating_add(64);
    let mut pids = vec![0 as libc::pid_t; capacity];
    // SAFETY: the buffer is live; the size is its true byte length.
    let filled = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            (capacity * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
        )
    };
    if filled <= 0 {
        return None;
    }
    pids.truncate(filled as usize);

    let mut entries = Vec::with_capacity(pids.len());
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: out-param struct is live and correctly sized.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
            )
        };
        let (comm, start_time_id) = if got == std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
            let comm_bytes: Vec<u8> = info
                .pbi_comm
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            (
                String::from_utf8_lossy(&comm_bytes).into_owned(),
                Some(info.pbi_start_tvsec.saturating_mul(1_000_000) + info.pbi_start_tvusec),
            )
        } else {
            (String::new(), None)
        };
        let path = exe_path_for_pid(pid);
        if comm.trim().is_empty() && path.is_none() {
            // Unnameable by every unprivileged route (or it died mid-sweep):
            // skip rather than fabricate an empty identity.
            continue;
        }
        entries.push(crate::process::ProcessSnapshotEntry {
            pid: pid as u32,
            comm,
            path,
            start_time_id,
        });
    }
    (!entries.is_empty()).then_some(entries)
}

/// Union of all active display bounds in global display points — the macOS
/// analog of the Win32 virtual-screen metrics. None when the display list
/// is unavailable (headless session).
pub(crate) fn virtual_screen() -> Option<VirtualScreenRect> {
    const MAX_DISPLAYS: u32 = 16;
    let mut displays: [CGDirectDisplayID; MAX_DISPLAYS as usize] = [0; MAX_DISPLAYS as usize];
    let mut count: u32 = 0;
    // SAFETY: both pointers reference live stack storage sized to
    // MAX_DISPLAYS, per the binding's documented requirements.
    let result = unsafe { CGGetActiveDisplayList(MAX_DISPLAYS, displays.as_mut_ptr(), &mut count) };
    if result != CGError::Success || count == 0 {
        return None;
    }

    let mut x0 = f64::MAX;
    let mut y0 = f64::MAX;
    let mut x1 = f64::MIN;
    let mut y1 = f64::MIN;
    for display in displays.iter().take(count as usize) {
        // A display unplugged between the list call and this bounds call
        // can yield a null rect (infinities saturating to i32 extremes) for
        // one sample; the next 1s poll self-corrects and the change row
        // dedupes thereafter — same mid-change race Windows' metrics have.
        let bounds = objc2_core_graphics::CGDisplayBounds(*display);
        x0 = x0.min(bounds.origin.x);
        y0 = y0.min(bounds.origin.y);
        x1 = x1.max(bounds.origin.x + bounds.size.width);
        y1 = y1.max(bounds.origin.y + bounds.size.height);
    }
    Some(VirtualScreenRect {
        x0: x0 as i32,
        y0: y0 as i32,
        width: (x1 - x0) as i32,
        height: (y1 - y0) as i32,
    })
}

/// SystemInfo seed values, field-for-field parallel to the Windows
/// implementation (`current_system_info`): DNS-ish host name, OS product
/// version, native arch, logical processor count, physical memory bytes.
pub(crate) fn system_info() -> gilbreth_core::EventPayload {
    gilbreth_core::EventPayload::SystemInfo {
        host: host_name(),
        os_version: sysctl_string("kern.osproductversion")
            .map(|version| format!("macOS {version}"))
            .unwrap_or_else(|| "macOS".to_string()),
        arch: std::env::consts::ARCH.to_string(),
        processor_count: std::thread::available_parallelism()
            .map(|count| u32::try_from(count.get()).unwrap_or(u32::MAX))
            .unwrap_or(0),
        memory_total_bytes: sysctl_u64("hw.memsize").unwrap_or(0),
    }
}

fn host_name() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: buffer is live for the call and the length is its real size.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return String::new();
    }
    let len = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..len]).into_owned()
}

fn sysctl_string(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: querying the required length with a null buffer per sysctl(3).
    let rc =
        unsafe { libc::sysctlbyname(name.as_ptr(), ptr::null_mut(), &mut len, ptr::null_mut(), 0) };
    if rc != 0 || len == 0 {
        return None;
    }
    let mut buffer = vec![0u8; len];
    // SAFETY: buffer is sized to the reported length.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buffer.truncate(len.saturating_sub(1)); // drop the trailing NUL
    Some(String::from_utf8_lossy(&buffer).into_owned())
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let name = CString::new(name).ok()?;
    let mut value: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::size_t;
    // SAFETY: value is a live u64 and len is its exact size.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut u64).cast(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(value)
}

#[cfg(test)]
mod probe {
    /// Manual diagnostic, never run in CI: prints the live session snapshot
    /// so session-dictionary assumptions can be re-verified by hand on new
    /// macOS versions: run with `--ignored --nocapture`, lock the screen,
    /// run again from a second shell, compare `locked`.
    ///
    /// Run 2026-07-11 on macOS 26.5.2 (closing the Idle/System review's one
    /// unverified cell): unlocked → `locked: false` (key absent); within 4s
    /// of display sleep → CFBoolean `true`, held across 12 samples over 48s
    /// including a display-relit lock-screen sample; `on_console` stayed
    /// `true` throughout (a lock is not an off-console transition) and the
    /// audit session id stayed stable. Full transcript in the TCC record
    /// (the macOS TCC and stream rules).
    #[test]
    #[ignore = "manual probe: verify live session state by hand"]
    fn probe_session_snapshot() {
        println!("{:?}", super::session_snapshot());
    }
}
