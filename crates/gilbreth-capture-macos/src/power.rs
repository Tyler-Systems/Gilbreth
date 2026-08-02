//! Power seam (MAC-1): the shared power-boundary machine lives in
//! `gilbreth_core::power`, hoisted 2026-08-01 when the LIN-2 port became
//! this file's byte-for-byte twin (the ForegroundState/ProcessMonitor
//! precedent; bodies moved unchanged, unit tests moved with them, the two
//! platform-named log strings neutralized). The macOS platform halves
//! stay where they were: sleep/wake edges from `IORegisterForSystemPower`
//! and the IOPS status snapshot live in `iokit.rs`, and
//! `mach_continuous_time` is the spans-sleep clock (`Instant` is the
//! uptime clock, which pauses during sleep — the divergence between the
//! two across one pump pass IS the slept interval).

pub(crate) use gilbreth_core::power::{
    PowerEdge, PowerEdgeSample, PowerMonitor, PowerSource, PowerStatusSnapshot,
};
