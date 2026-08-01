//! Process launch/exit tracking (TCC record, "Pre-implementation decisions
//! (2026-07-12)" process rules): a libproc sweep at the shared cadence,
//! sweep-only, the recorded decision — no NSWorkspace observers.
//!
//! The tracker/monitor pair lived here as a verbatim Windows port until
//! LIN-1 hoisted it to `gilbreth-core` (the roadmap's "shared core
//! tracker"; a third port would be the drift the MAC-1 hoists exist to
//! prevent). This module is now the crate-local name for the shared
//! machinery; the libproc snapshot provider stays in `coregraphics.rs`
//! (the crate's libc provider module), and behavior is unchanged by the
//! move — the pre-hoist unit suite moved to core with it.

pub(crate) use gilbreth_core::{ProcessMonitor, ProcessSnapshotEntry};
