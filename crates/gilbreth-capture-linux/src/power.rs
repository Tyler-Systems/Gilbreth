//! Power seam (LIN-2): the platform halves of the shared power-boundary
//! machine, which lives in `gilbreth_core::power` (hoisted 2026-08-01
//! when this port became the macOS machine's byte-for-byte twin — the
//! ForegroundState/ProcessMonitor precedent). Sleep/wake edges come from
//! elogind's `PrepareForSleep` signal (queued by the D-Bus watcher
//! thread, drained by the pump), the spans-sleep clock is
//! `CLOCK_BOOTTIME` (Linux `Instant` is `CLOCK_MONOTONIC`, which stops
//! during suspend exactly as the mac uptime clock does), and the
//! AC/battery status snapshot reads `/sys/class/power_supply` directly:
//! AC online is the OR across Mains-class supplies, the percentage is the
//! first system-scope battery's capacity, and `battery_saver` stays
//! honestly `None` — this tier has no power-saver signal with the
//! Windows/macOS meaning.

pub(crate) use gilbreth_core::power::{
    PowerEdge, PowerEdgeSample, PowerMonitor, PowerSource, PowerStatusSnapshot,
};

/// The spans-sleep clock: `CLOCK_BOOTTIME` in milliseconds.
pub(crate) fn boottime_ms() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: passing a valid pointer to the stack timespec above.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc != 0 {
        return None;
    }
    let seconds = u64::try_from(ts.tv_sec).ok()?;
    let millis = u64::try_from(ts.tv_nsec).ok()? / 1_000_000;
    seconds.checked_mul(1000).map(|base| base + millis)
}

/// One `/sys/class/power_supply` sweep: AC online is the OR across
/// Mains-class supplies, the percentage is the first system-scope
/// battery's capacity (sorted by name for determinism; `scope = Device`
/// supplies — wireless mice and the like — are excluded). A machine
/// without any readable supply reports all-unknown rather than absent, so
/// the silent first baseline still forms.
pub(crate) fn power_status_snapshot() -> Option<PowerStatusSnapshot> {
    let entries = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let mut names: Vec<std::path::PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    names.sort();

    let read = |path: &std::path::Path, file: &str| -> Option<String> {
        std::fs::read_to_string(path.join(file))
            .ok()
            .map(|value| value.trim().to_string())
    };

    let mut ac_online: Option<bool> = None;
    let mut battery_percent: Option<u8> = None;
    for path in &names {
        let Some(kind) = read(path, "type") else {
            continue;
        };
        match kind.as_str() {
            "Mains" => {
                if let Some(online) = read(path, "online") {
                    let online = online == "1";
                    ac_online = Some(ac_online.unwrap_or(false) || online);
                }
            }
            "Battery" => {
                if read(path, "scope").as_deref() == Some("Device") {
                    continue;
                }
                if battery_percent.is_none() {
                    battery_percent = read(path, "capacity")
                        .and_then(|value| value.parse::<u8>().ok())
                        .map(|value| value.min(100));
                }
            }
            _ => {}
        }
    }
    Some(PowerStatusSnapshot {
        ac_online,
        battery_percent,
        battery_saver: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_boottime_clock_reads_and_advances_monotonically() {
        let first = boottime_ms().expect("CLOCK_BOOTTIME is readable");
        let second = boottime_ms().expect("CLOCK_BOOTTIME is readable");
        assert!(second >= first, "boottime never goes backwards");
        assert!(first > 0, "a running machine has non-zero uptime");
    }

    #[test]
    fn live_status_snapshot_is_well_formed_when_present() {
        // Hosted runners may expose no power supplies at all; the read
        // itself must stay well-formed either way.
        if let Some(snapshot) = power_status_snapshot() {
            if let Some(percent) = snapshot.battery_percent {
                assert!(percent <= 100);
            }
            assert_eq!(snapshot.battery_saver, None, "no Linux analog");
        }
    }
}
