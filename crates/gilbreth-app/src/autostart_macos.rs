//! Per-user "launch at startup" on macOS via `SMAppService` login-item
//! registration (shell-remainders slice; minimum system macOS 13, which is
//! already the MAC-1 floor). The registration binds to the app bundle —
//! the canonical `/Applications/Gilbreth.app` install per the 2026-07-12
//! owner decision — and, like the Windows `Run`-key twin, the system's
//! registration state *is* the persisted setting: the tray reflects
//! `SMAppService.status` on every read, so nothing can drift.
//!
//! Honesty rules: `is_enabled` is true only for `Enabled` — a registration
//! the user switched off in System Settings (`RequiresApproval`) will not
//! launch, so it reads as disabled; enabling in that state fails with the
//! System Settings › General › Login Items path in the message rather than
//! pretending success. The user visibility surface is the standard system
//! one (Login Items lists the app; macOS notifies on registration).

use anyhow::{bail, Context, Result};
use objc2::rc::Retained;
use objc2_foundation::NSError;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

fn main_app_service() -> Retained<SMAppService> {
    // SAFETY: mainAppService is a class-method constructor with no
    // preconditions; the returned service describes this process's bundle.
    unsafe { SMAppService::mainAppService() }
}

fn describe(error: &NSError) -> String {
    error.localizedDescription().to_string()
}

/// The install-state read the dashboard surfaces. macOS has no stored
/// command string (the registration is the bundle itself), so an enabled
/// registration reports the current executable path — the closest honest
/// analog of the Windows `Run` value.
pub fn read_command() -> Result<Option<String>> {
    if !is_enabled()? {
        return Ok(None);
    }
    let exe = std::env::current_exe().context("resolve current executable path")?;
    Ok(Some(exe.display().to_string()))
}

pub fn is_enabled() -> Result<bool> {
    // SAFETY: status() reads registration state; no preconditions.
    Ok(unsafe { main_app_service().status() } == SMAppServiceStatus::Enabled)
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    let service = main_app_service();
    // SAFETY (all calls below): register/unregister/status on the main-app
    // service; the API is documented for exactly this use and carries no
    // threading precondition. Errors come back as NSError values.
    if enabled {
        if let Err(error) = unsafe { service.registerAndReturnError() } {
            bail!("failed to register the login item: {}", describe(&error));
        }
        match unsafe { service.status() } {
            SMAppServiceStatus::Enabled => Ok(()),
            // copy-allow: em-dash one prose em dash within the per-string cap (Lane B ruling)
            SMAppServiceStatus::RequiresApproval => bail!(
                "registered, but launch at login is switched off for Gilbreth in \
                 System Settings — enable it under General > Login Items"
            ),
            other => bail!(
                "login-item registration did not take effect (status {:?}); \
                 launch-at-startup needs the installed /Applications/Gilbreth.app bundle",
                other.0
            ),
        }
    } else {
        if unsafe { service.status() } == SMAppServiceStatus::NotRegistered {
            return Ok(());
        }
        if let Err(error) = unsafe { service.unregisterAndReturnError() } {
            bail!("failed to unregister the login item: {}", describe(&error));
        }
        Ok(())
    }
}

#[cfg(test)]
mod probe {
    /// Manual diagnostic, never run in CI (the `probe_session_snapshot`
    /// pattern): prints the live SMAppService status for this process so
    /// the registration cells can be evidenced by hand — meaningful only
    /// when run from the installed bundle; an unbundled test binary reads
    /// as not-registered/not-found.
    #[test]
    #[ignore = "manual probe: verify live SMAppService status by hand"]
    fn probe_login_item_status() {
        // SAFETY: status() reads registration state; no preconditions.
        println!("SMAppService status: {:?}", unsafe {
            super::main_app_service().status()
        });
        println!("is_enabled: {:?}", super::is_enabled());
    }
}
