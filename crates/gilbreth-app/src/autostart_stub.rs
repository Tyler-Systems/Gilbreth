//! Launch-at-startup stub for targets with no implementation. Windows uses
//! the HKCU `Run` registry key (`autostart.rs`); macOS uses `SMAppService`
//! (`autostart_macos.rs`, shell-remainders slice). Anywhere else this
//! reports autostart as off and declines to change it, so the tray
//! checkbox stays honest instead of pretending a setting persisted.

use anyhow::{bail, Result};

/// No autostart registration exists on this target, so the install-state
/// read reports none.
pub fn read_command() -> Result<Option<String>> {
    Ok(None)
}

pub fn is_enabled() -> Result<bool> {
    Ok(false)
}

pub fn set_enabled(_enabled: bool) -> Result<()> {
    bail!("launch at startup is not available on this platform")
}
