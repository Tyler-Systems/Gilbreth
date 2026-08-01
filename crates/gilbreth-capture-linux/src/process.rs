//! The procfs process sweep (LIN-1): the snapshot provider feeding the
//! shared `gilbreth_core::ProcessMonitor` — the same tracker, cadence,
//! churn filter, and focus rescue the macOS backend runs, per the
//! roadmap's "shared core tracker". Identity per entry: `comm` from
//! `/proc/<pid>/comm` (a name every process exposes, the Windows-like
//! guarantee), the executable path from the `exe` link when readable, and
//! the kernel's per-boot `starttime` (clock ticks, field 22 of
//! `/proc/<pid>/stat`) as the opaque PID-reuse token. Always-on capture
//! reads nothing else — no cmdline, no environ, no uid — matching the
//! recorded process-privacy posture.

use gilbreth_core::ProcessSnapshotEntry;

/// `PF_KTHREAD` in the stat flags field: the kernel's own kernel-thread
/// marker, stable ABI. Kernel threads are excluded from the sweep —
/// Toolhelp and libproc do not report them, and meaning-constant rows mean
/// the Linux sweep must not either (a first live run showed kworker churn
/// drowning the summary's top entries). The exe link cannot make this
/// call: for an unprivileged reader a kernel thread's link answers EACCES
/// exactly like another user's process (observed live before this landed).
const PF_KTHREAD: u64 = 0x0020_0000;

/// One full procfs sweep. `None` when `/proc` itself is unreadable (the
/// failed-sweep defense keeps prior state); a process that vanishes
/// mid-sweep is skipped, never fabricated.
pub(crate) fn process_snapshot() -> Option<Vec<ProcessSnapshotEntry>> {
    let entries = std::fs::read_dir("/proc").ok()?;
    let mut snapshot = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        // Died mid-sweep (no stat): skip; its exit still emits when the
        // tracker notices the pid gone.
        let Some(stat) = stat_identity(pid) else {
            continue;
        };
        if stat.flags & PF_KTHREAD != 0 {
            continue;
        }
        let path = exe_link(pid);
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|comm| comm.trim().to_string())
            .unwrap_or_default();
        if comm.is_empty() && path.is_none() {
            continue;
        }
        snapshot.push(ProcessSnapshotEntry {
            pid,
            comm,
            path,
            start_time_id: Some(stat.start_time_ticks),
        });
    }
    (!snapshot.is_empty()).then_some(snapshot)
}

/// The `exe` link only — no comm fallback here, because the monitor's
/// `SnapshotName` lane carries comm separately and a duplicated name would
/// misreport `exe_source`. Unreadable (another user's process) is `None`.
/// The kernel's " (deleted)" suffix is stripped so an updated-on-disk
/// binary keeps a stable identity.
fn exe_link(pid: u32) -> Option<String> {
    let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let mut path = link.to_string_lossy().into_owned();
    if let Some(stripped) = path.strip_suffix(" (deleted)") {
        path.truncate(stripped.len());
    }
    (!path.is_empty()).then_some(path)
}

struct StatIdentity {
    flags: u64,
    start_time_ticks: u64,
}

/// Fields 9 (`flags`) and 22 (`starttime`, clock ticks since boot) of
/// `/proc/<pid>/stat`. The comm field can carry spaces and parentheses, so
/// the scan anchors after the LAST `)` — the kernel's own recommended
/// parse; the remainder starts at field 3.
fn stat_identity(pid: u32) -> Option<StatIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_comm.split_whitespace();
    let flags = fields.clone().nth(6)?.parse().ok()?;
    let start_time_ticks = fields.nth(19)?.parse().ok()?;
    Some(StatIdentity {
        flags,
        start_time_ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_sweep_contains_this_process_with_full_identity() {
        let pid = std::process::id();
        let snapshot = process_snapshot().expect("/proc is readable");
        let me = snapshot
            .iter()
            .find(|entry| entry.pid == pid)
            .expect("own process present");
        assert!(!me.comm.is_empty(), "comm always resolves");
        assert!(
            me.path.as_deref().is_some_and(|p| p.starts_with('/')),
            "own exe link resolves to a full path"
        );
        assert!(me.start_time_id.is_some(), "starttime parses");
        assert!(snapshot.len() > 10, "a live machine runs many processes");
        // Kernel threads are excluded (kthreadd is pid 2 on Linux).
        assert!(
            !snapshot.iter().any(|entry| entry.pid == 2),
            "kthreadd must not appear in the sweep"
        );
    }

    #[test]
    fn stat_identity_parses_own_stat_and_flags_kthreadd() {
        let me = stat_identity(std::process::id()).expect("own stat parses");
        assert!(me.start_time_ticks > 0);
        assert_eq!(me.flags & PF_KTHREAD, 0, "a userspace process");
        // kthreadd is pid 2 on Linux; its stat is world-readable.
        let kthreadd = stat_identity(2).expect("kthreadd stat readable");
        assert_ne!(kthreadd.flags & PF_KTHREAD, 0, "kernel thread flagged");
        assert!(stat_identity(0).is_none(), "pid 0 has no stat");
    }
}
