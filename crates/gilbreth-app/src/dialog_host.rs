//! The Linux modal-dialog host: the wire contract between the app and the
//! short-lived `--dialog` child that renders it (see `DIALOG_PROCESS_FLAG`).
//!
//! Windows blocks in `MessageBox` and macOS in `NSAlert`; here the calling
//! thread blocks on a child process instead, which gives the same synchronous
//! contract from any thread — the privacy flows confirm from workers, not the
//! pump. The request travels on stdin, never argv, so a message never appears
//! in `/proc/<pid>/cmdline`; the answer comes back as the exit status, the
//! one channel a crashed or killed child cannot forge.

use serde::{Deserialize, Serialize};

use crate::platform::{AlertKind, ConfirmAnswer, ConfirmButtons};

/// Exit statuses. Anything else — a panic, a kill, a missing display — is
/// read by the parent as "no answer", which every caller treats as its own
/// fail-safe.
pub const EXIT_POSITIVE: i32 = 0;
pub const EXIT_NEGATIVE: i32 = 1;
pub const EXIT_DISMISSED: i32 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireKind {
    Info,
    Warning,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireButtons {
    Ok,
    OkCancel,
    YesNo,
    YesNoCancel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DialogWireRequest {
    pub version: u32,
    pub title: String,
    pub message: String,
    pub kind: WireKind,
    pub buttons: WireButtons,
    pub default_negative: bool,
}

/// Bumped only if the shape changes incompatibly. Parent and child are the
/// same binary, so a mismatch means something else launched us.
pub const DIALOG_WIRE_VERSION: u32 = 1;

impl DialogWireRequest {
    pub fn new(
        title: &str,
        message: &str,
        kind: AlertKind,
        buttons: WireButtons,
        default_negative: bool,
    ) -> Self {
        Self {
            version: DIALOG_WIRE_VERSION,
            title: title.to_string(),
            message: message.to_string(),
            kind: match kind {
                AlertKind::Info => WireKind::Info,
                AlertKind::Warning => WireKind::Warning,
            },
            buttons,
            default_negative,
        }
    }
}

impl From<ConfirmButtons> for WireButtons {
    fn from(buttons: ConfirmButtons) -> Self {
        match buttons {
            ConfirmButtons::OkCancel => WireButtons::OkCancel,
            ConfirmButtons::YesNo => WireButtons::YesNo,
        }
    }
}

/// Map a child's exit status back to an answer. `None` means the child never
/// reported one.
pub fn answer_from_status(code: Option<i32>) -> Option<ConfirmAnswer> {
    match code {
        Some(EXIT_POSITIVE) => Some(ConfirmAnswer::Positive),
        Some(EXIT_NEGATIVE) => Some(ConfirmAnswer::Negative),
        Some(EXIT_DISMISSED) => Some(ConfirmAnswer::Dismissed),
        _ => None,
    }
}

pub fn status_for_answer(answer: gilbreth_dashboard::dialog::DialogAnswer) -> i32 {
    use gilbreth_dashboard::dialog::DialogAnswer;
    match answer {
        DialogAnswer::Positive => EXIT_POSITIVE,
        DialogAnswer::Negative => EXIT_NEGATIVE,
        DialogAnswer::Dismissed => EXIT_DISMISSED,
    }
}

impl DialogWireRequest {
    /// Convert to the renderer's own request type.
    pub fn into_render_request(
        self,
        window_icon: Option<(u32, u32, Vec<u8>)>,
    ) -> gilbreth_dashboard::dialog::DialogRequest {
        use gilbreth_dashboard::dialog::{DialogButtons, DialogKind, DialogRequest};
        DialogRequest {
            title: self.title,
            message: self.message,
            kind: match self.kind {
                WireKind::Info => DialogKind::Info,
                WireKind::Warning => DialogKind::Warning,
            },
            buttons: match self.buttons {
                WireButtons::Ok => DialogButtons::Ok,
                WireButtons::OkCancel => DialogButtons::OkCancel,
                WireButtons::YesNo => DialogButtons::YesNo,
                WireButtons::YesNoCancel => DialogButtons::YesNoCancel,
            },
            default_negative: self.default_negative,
            window_icon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_round_trips_through_the_wire() {
        let request = DialogWireRequest::new(
            "Gilbreth — Privacy",
            "Erase everything?",
            AlertKind::Warning,
            ConfirmButtons::YesNo.into(),
            true,
        );
        let encoded = serde_json::to_string(&request).expect("encodes");
        let decoded: DialogWireRequest = serde_json::from_str(&encoded).expect("decodes");
        assert_eq!(decoded, request);
        assert_eq!(decoded.version, DIALOG_WIRE_VERSION);
        assert_eq!(decoded.buttons, WireButtons::YesNo);
        assert_eq!(decoded.kind, WireKind::Warning);
        assert!(decoded.default_negative);
    }

    #[test]
    fn every_exit_status_maps_and_anything_else_is_no_answer() {
        assert_eq!(
            answer_from_status(Some(EXIT_POSITIVE)),
            Some(ConfirmAnswer::Positive)
        );
        assert_eq!(
            answer_from_status(Some(EXIT_NEGATIVE)),
            Some(ConfirmAnswer::Negative)
        );
        assert_eq!(
            answer_from_status(Some(EXIT_DISMISSED)),
            Some(ConfirmAnswer::Dismissed)
        );
        // A panic, a signal, or a child that could not open a display: the
        // caller must fall back to its own safe answer, never guess.
        assert_eq!(answer_from_status(Some(101)), None);
        assert_eq!(answer_from_status(None), None);
    }

    #[test]
    fn answers_and_statuses_are_inverse() {
        use gilbreth_dashboard::dialog::DialogAnswer;
        for (answer, expected) in [
            (DialogAnswer::Positive, ConfirmAnswer::Positive),
            (DialogAnswer::Negative, ConfirmAnswer::Negative),
            (DialogAnswer::Dismissed, ConfirmAnswer::Dismissed),
        ] {
            assert_eq!(
                answer_from_status(Some(status_for_answer(answer))),
                Some(expected),
                "the child's answer must survive the exit status"
            );
        }
    }
}
