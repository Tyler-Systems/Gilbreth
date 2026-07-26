//! Foreground-only Windows notification access facade.
//!
//! The background notification worker deliberately does not import this
//! request function. The tray/pump calls it only after an explicit user action.

use windows::{
    Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
    UI::Notifications::Management::{
        UserNotificationListener, UserNotificationListenerAccessStatus as WinStatus,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationAccessStatus {
    Allowed,
    Unspecified,
    Denied,
    Unavailable,
}

impl NotificationAccessStatus {
    fn from_windows(status: WinStatus) -> Self {
        match status {
            WinStatus::Allowed => Self::Allowed,
            WinStatus::Unspecified => Self::Unspecified,
            WinStatus::Denied => Self::Denied,
            _ => Self::Unavailable,
        }
    }
}

struct WinRtGuard;

impl WinRtGuard {
    fn initialize() -> Result<Self, String> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map_err(|error| format!("WinRT initialization failed: {error}"))?;
        Ok(Self)
    }
}

impl Drop for WinRtGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

pub fn current_notification_access() -> Result<NotificationAccessStatus, String> {
    let _winrt = WinRtGuard::initialize()?;
    let listener = UserNotificationListener::Current()
        .map_err(|error| format!("notification listener is unavailable: {error}"))?;
    listener
        .GetAccessStatus()
        .map(NotificationAccessStatus::from_windows)
        .map_err(|error| format!("notification access status failed: {error}"))
}

/// Request access from the foreground pump/UI thread. Callers must put an
/// explicit, user-confirmed action in front of this function.
pub fn request_notification_access() -> Result<NotificationAccessStatus, String> {
    let _winrt = WinRtGuard::initialize()?;
    let listener = UserNotificationListener::Current()
        .map_err(|error| format!("notification listener is unavailable: {error}"))?;
    listener
        .RequestAccessAsync()
        .map_err(|error| format!("notification access request could not start: {error}"))?
        .join()
        .map(NotificationAccessStatus::from_windows)
        .map_err(|error| format!("notification access request failed: {error}"))
}
