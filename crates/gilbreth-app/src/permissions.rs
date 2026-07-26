//! The macOS TCC permission subsystem (onboarding / Diagnostics panel; TCC
//! record "TCC permission subsystem" + the 2026-07-12 onboarding rules).
//!
//! Two file channels between the dashboard subprocess and the pump/tray
//! process, since they are separate processes of one signed bundle (S4
//! model, file IPC — no socket):
//!
//! - **State (pump → dashboard):** the pump is the authority on grant state
//!   and writes `permissions.json` on grant-state edges. The dashboard reads
//!   it for display. The pump is authoritative because only it can tell the
//!   granted-but-needs-relaunch case apart (Input Monitoring is delivered at
//!   launch — a grant made mid-run reads `preflight = true` while the tap
//!   still delivers nothing until relaunch; the pump knows because it
//!   captured a launch-time baseline).
//! - **Request (dashboard → pump):** the dashboard writes `permission-
//!   request.json` (a monotonic generation + one action) and the pump polls
//!   it on its service cadence and acts. **Prompts fire only here, in the
//!   pump process** (the terminal-spawn evidence proved TCC attribution is
//!   subtle; the pump is the process whose grants actually gate capture).
//!   Deep links open System Settings and touch no TCC, so the dashboard
//!   opens those itself — they are not in this channel.
//!
//! Everything here is a no-op stub off macOS (the app is cross-compiled for
//! the Windows cross-check); the dashboard only renders the panel when the
//! state read returns `Some`, which is macOS-only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The per-permission grant state the panel renders.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Not granted (or not yet asked): the stream is OFF-declared.
    NotGranted,
    /// Granted and active.
    Granted,
    /// Granted, but a relaunch is needed before it takes effect — the
    /// Input Monitoring case where the grant landed after this process
    /// launched (macOS delivers the permission only at launch).
    GrantedNeedsRelaunch,
}

/// The authoritative permission snapshot the pump writes and the dashboard
/// reads. Versioned like the other sidecars so a future field is additive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionState {
    pub version: u64,
    pub accessibility: GrantState,
    pub input_monitoring: GrantState,
}

pub const PERMISSION_STATE_VERSION: u64 = 1;
pub const PERMISSION_STATE_SIDECAR_NAME: &str = "permissions.json";
pub const PERMISSION_REQUEST_SIDECAR_NAME: &str = "permission-request.json";

/// An action the dashboard asks the pump to perform. Deep-link opens are
/// deliberately absent: they touch no TCC and the dashboard does them
/// directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    /// Run `AXIsProcessTrustedWithOptions(prompt)` in the pump process:
    /// registers the bundle in the Accessibility list and shows the system
    /// prompt.
    PromptAccessibility,
    /// Run `CGRequestListenEventAccess()` in the pump process (the Input
    /// Monitoring twin).
    PromptInputMonitoring,
    /// Relaunch via LaunchServices (`open` on the bundle) after a graceful
    /// quit — the Input Monitoring activation step. A raw self-exec would
    /// recreate the terminal-spawn misattribution, so this always goes
    /// through `open`.
    Relaunch,
}

/// The dashboard-written request: a monotonic generation (the reseed-flag
/// precedent — the pump acts only when the generation advances, so a stale
/// file on disk is never replayed) plus the action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub generation: u64,
    pub action: PermissionAction,
}

pub fn state_sidecar_path(config_path: &Path) -> PathBuf {
    sidecar_beside(config_path, PERMISSION_STATE_SIDECAR_NAME)
}

pub fn request_sidecar_path(config_path: &Path) -> PathBuf {
    sidecar_beside(config_path, PERMISSION_REQUEST_SIDECAR_NAME)
}

fn sidecar_beside(config_path: &Path, name: &str) -> PathBuf {
    config_path
        .parent()
        .map(|dir| dir.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Read the pump-written state sidecar. `None` when it is absent or
/// unreadable — the dashboard treats that as "no panel" (Windows, or a
/// pump that has not written yet), never as an error banner.
pub fn read_state(path: &Path) -> Option<PermissionState> {
    let contents = std::fs::read_to_string(path).ok()?;
    let state: PermissionState = serde_json::from_str(&contents).ok()?;
    (state.version == PERMISSION_STATE_VERSION).then_some(state)
}

/// Atomically write the state sidecar (write-temp-then-rename, the config
/// crate's pattern). Errors are returned for the caller to log; a failed
/// state write only degrades the panel's freshness, never capture.
pub fn write_state(path: &Path, state: &PermissionState) -> std::io::Result<()> {
    let contents = serde_json::to_string_pretty(state)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &contents)
}

/// Read the dashboard-written request (pump side). `None` when absent or
/// unreadable.
pub fn read_request(path: &Path) -> Option<PermissionRequest> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Atomically write a request (dashboard side).
pub fn write_request(path: &Path, request: &PermissionRequest) -> std::io::Result<()> {
    let contents = serde_json::to_string_pretty(request)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &contents)
}

fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let result = (|| {
        std::fs::write(&tmp, contents)?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The System Settings deep-link URLs — verified live on macOS 26.5
/// (2026-07-12): both open their pane. The dashboard opens these directly;
/// if a pane id ever moves, the caller falls back to the Privacy & Security
/// root (`PRIVACY_ROOT_URL`).
pub const ACCESSIBILITY_PANE_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";
pub const INPUT_MONITORING_PANE_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent";
pub const PRIVACY_ROOT_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_the_sidecar() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("config.toml");
        let path = state_sidecar_path(&config);
        assert_eq!(path.file_name().unwrap(), PERMISSION_STATE_SIDECAR_NAME);

        let state = PermissionState {
            version: PERMISSION_STATE_VERSION,
            accessibility: GrantState::Granted,
            input_monitoring: GrantState::GrantedNeedsRelaunch,
        };
        write_state(&path, &state).expect("write");
        assert_eq!(read_state(&path), Some(state));
    }

    #[test]
    fn a_version_mismatch_reads_as_no_panel() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("permissions.json");
        std::fs::write(
            &path,
            r#"{"version":999,"accessibility":"granted","input_monitoring":"granted"}"#,
        )
        .expect("seed");
        assert_eq!(read_state(&path), None, "an unknown version is ignored");
    }

    #[test]
    fn a_missing_or_garbage_sidecar_reads_none_not_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(read_state(&dir.path().join("absent.json")), None);
        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, "not json").expect("seed");
        assert_eq!(read_state(&garbage), None);
        assert_eq!(read_request(&garbage), None);
    }

    #[test]
    fn request_round_trips_and_the_generation_carries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = request_sidecar_path(&dir.path().join("config.toml"));
        let request = PermissionRequest {
            generation: 7,
            action: PermissionAction::Relaunch,
        };
        write_request(&path, &request).expect("write");
        assert_eq!(read_request(&path), Some(request));
    }

    /// The generation is the pump's edge signal (and the loop guard): the
    /// dashboard always writes strictly above whatever is on disk, so a
    /// stale request (notably the `Relaunch` that triggered a restart) is
    /// distinguishable from a fresh one by a pump that baselined the
    /// on-disk generation at startup.
    #[test]
    fn a_dashboard_write_always_advances_the_generation_past_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = request_sidecar_path(&dir.path().join("config.toml"));

        // Simulate the dispatch helper's generation rule directly.
        let next = |path: &std::path::Path, action: PermissionAction| {
            let generation = read_request(path)
                .map(|prior| prior.generation)
                .unwrap_or(0)
                + 1;
            let request = PermissionRequest { generation, action };
            write_request(path, &request).expect("write");
            generation
        };

        assert_eq!(next(&path, PermissionAction::Relaunch), 1);
        assert_eq!(next(&path, PermissionAction::PromptAccessibility), 2);

        // A pump that baselines the on-disk generation (2) at startup treats
        // that exact request as already-seen and only acts on a strictly
        // greater one — no replay of the leftover request.
        let baseline = read_request(&path).expect("request on disk").generation;
        assert_eq!(baseline, 2);
        assert_eq!(next(&path, PermissionAction::Relaunch), 3);
        assert!(
            3 > baseline,
            "the next dashboard click outranks the baseline"
        );
    }
}
