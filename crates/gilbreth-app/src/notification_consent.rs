//! Product-owned notification consent state and content-free dashboard sidecar.
//!
//! The WinRT calls stay behind the Windows platform/capture facade. This module
//! owns the cross-process vocabulary, copy, and explicit-action state machine so
//! the dashboard can report access without ever prompting from its reader
//! process.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

// The explicit-request half (settings URI, request copy, action state machine,
// snapshot writes) is invoked only by the Windows tray handler today; it stays
// compiled (and unit-tested) on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
pub const NOTIFICATION_SETTINGS_URI: &str = "ms-settings:privacy-notifications";
// copy-allow: em-dash name — context title notation, not prose (Lane B ruling, data-notation family)
pub const REQUEST_TITLE: &str = "Gilbreth — Notification counts";
#[cfg_attr(not(windows), allow(dead_code))]
pub const REQUEST_EXPLANATION: &str = "Gilbreth can count new Windows notifications by source app. It stores the source app and count, never notification title, body, actions, or other content. While any app exclusion is configured, notification rows stay off because Windows does not provide a reliable executable identity. Choose OK to ask Windows for access.";
pub const DENIED_EXPLANATION: &str = "Windows notification access is denied. Other capture continues. Open Windows Settings if you want to allow source-app and count metadata.";
pub const UNAVAILABLE_EXPLANATION: &str = "Notification access is unavailable on this installation. Other capture continues. Open Windows Settings to inspect the notification privacy setting.";
pub const ALLOWED_EXPLANATION: &str = "Windows notification access is on. Gilbreth normally records the source app and count, never notification title, body, actions, or other content. While any app exclusion is configured, notification rows stay off because Windows does not provide a reliable executable identity.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAccessState {
    Allowed,
    Unspecified,
    Denied,
    Unavailable,
    Unsupported,
}

impl NotificationAccessState {
    pub fn privacy_copy(self) -> &'static str {
        match self {
            Self::Allowed => ALLOWED_EXPLANATION,
            Self::Unspecified => {
                "Windows has not been asked for notification access. Use Privacy > Notification counts... from the tray to choose. Gilbreth stores source app and count only, never notification content. While any app exclusion is configured, notification rows stay off."
            }
            Self::Denied => DENIED_EXPLANATION,
            Self::Unavailable => UNAVAILABLE_EXPLANATION,
            Self::Unsupported => {
                "Notification capture is not available on this operating system. Other capture continues."
            }
        }
    }

    pub fn diagnostics_copy(self) -> &'static str {
        match self {
            Self::Allowed => {
                "allowed; source-app and count metadata only; app exclusions suppress all rows"
            }
            Self::Unspecified => "not requested; use the tray Privacy action",
            Self::Denied => "denied by Windows; other capture continues",
            Self::Unavailable => "unavailable on this installation; other capture continues",
            Self::Unsupported => "unsupported on this operating system",
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplicitAction {
    ReportAllowed,
    ExplainAndRequest,
    ExplainAndOpenSettings,
    ReportUnsupported,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn explicit_action_for(state: NotificationAccessState) -> ExplicitAction {
    match state {
        NotificationAccessState::Allowed => ExplicitAction::ReportAllowed,
        NotificationAccessState::Unspecified => ExplicitAction::ExplainAndRequest,
        NotificationAccessState::Denied | NotificationAccessState::Unavailable => {
            ExplicitAction::ExplainAndOpenSettings
        }
        NotificationAccessState::Unsupported => ExplicitAction::ReportUnsupported,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationAccessSnapshot {
    pub schema_version: u32,
    pub state: NotificationAccessState,
    pub observed_at_ms: i64,
}

impl NotificationAccessSnapshot {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn new(state: NotificationAccessState) -> Self {
        Self {
            schema_version: 1,
            state,
            observed_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(i64::MAX as u128) as i64,
        }
    }
}

pub const NOTIFICATION_ACCESS_SIDECAR_NAME: &str = "notification-access.json";

pub fn sidecar_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NOTIFICATION_ACCESS_SIDECAR_NAME)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn write_snapshot(path: &Path, snapshot: &NotificationAccessSnapshot) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "notification state path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staged = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    fs::write(&staged, bytes).map_err(|error| error.to_string())?;
    let result = crate::platform::replace_file(&staged, path).map_err(|error| error.to_string());
    if result.is_err() {
        let _ = fs::remove_file(staged);
    }
    result
}

pub fn read_snapshot(path: &Path) -> Option<NotificationAccessSnapshot> {
    let bytes = fs::read(path).ok()?;
    let snapshot: NotificationAccessSnapshot = serde_json::from_slice(&bytes).ok()?;
    (snapshot.schema_version == 1).then_some(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unspecified_requests_access() {
        assert_eq!(
            explicit_action_for(NotificationAccessState::Unspecified),
            ExplicitAction::ExplainAndRequest
        );
        for state in [
            NotificationAccessState::Allowed,
            NotificationAccessState::Denied,
            NotificationAccessState::Unavailable,
            NotificationAccessState::Unsupported,
        ] {
            assert_ne!(
                explicit_action_for(state),
                ExplicitAction::ExplainAndRequest
            );
        }
    }

    #[test]
    fn copy_pins_metadata_only_boundary() {
        assert!(REQUEST_EXPLANATION.contains("source app and count"));
        assert!(REQUEST_EXPLANATION.contains("never notification title, body"));
        assert!(ALLOWED_EXPLANATION.contains("never notification title, body"));
        assert!(REQUEST_EXPLANATION.contains("any app exclusion"));
        assert!(ALLOWED_EXPLANATION.contains("notification rows stay off"));
        assert!(!REQUEST_EXPLANATION.contains("toast XML"));
    }

    #[test]
    fn snapshot_round_trips_without_content_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sidecar_path(dir.path());
        let snapshot = NotificationAccessSnapshot {
            schema_version: 1,
            state: NotificationAccessState::Denied,
            observed_at_ms: 42,
        };
        write_snapshot(&path, &snapshot).expect("write snapshot");
        assert_eq!(read_snapshot(&path), Some(snapshot));
        let raw = fs::read_to_string(&path).expect("read raw snapshot");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw)
                .expect("json")
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["observed_at_ms", "schema_version", "state"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );

        let allowed = NotificationAccessSnapshot {
            schema_version: 1,
            state: NotificationAccessState::Allowed,
            observed_at_ms: 43,
        };
        write_snapshot(&path, &allowed).expect("replace existing snapshot");
        assert_eq!(read_snapshot(&path), Some(allowed));
    }
}
