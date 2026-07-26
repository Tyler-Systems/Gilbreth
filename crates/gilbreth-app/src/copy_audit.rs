//! Lane B enforcement: the app crate's copy-style audit
//! (docs/MAINTAINING.md, Product-copy rules).
//!
//! Two halves, one law (`gilbreth_core::copy_style`):
//! - the source scan walks the whole `src/` tree at test time and audits
//!   production literals in const/static declarations, arrays, inline
//!   expressions, and reconstructed `concat!`/`format!` copy, honoring
//!   strict `// copy-allow:` annotations beside the source string;
//! - the produced-string audit exercises the pure dialog builders with
//!   fixtures, so copy whose words come from nonliteral runtime values
//!   obeys the same rules. The store crate's receipt strings are audited
//!   as rendered through the report-message builders below.

use gilbreth_core::copy_style::{self, AllowEntry};
use gilbreth_store::{
    ArchiveEncryptionReceipt, ArchiveResetOutcome, ArchiveResetReport, SecureEraseOutcome,
    SecureEraseReport,
};

use crate::hotkey;
use crate::notification_consent::NotificationAccessState;

fn em_dash_allow(reason: &str) -> Vec<AllowEntry> {
    vec![AllowEntry {
        rule_id: "em-dash".to_string(),
        reason: reason.to_string(),
        line: 0,
    }]
}

#[test]
fn production_copy_source_passes_the_copy_style_law() {
    let violations = copy_style::audit_crate_src("gilbreth-app", env!("CARGO_MANIFEST_DIR"));
    copy_style::assert_no_violations(&violations);
}

#[test]
fn produced_dialog_strings_pass_the_copy_style_law() {
    let chord = match hotkey::resolve_pause_hotkey(hotkey::DEFAULT_PAUSE_RESUME_HOTKEY).setting {
        hotkey::PauseHotkeySetting::Enabled(chord) => chord,
        other => panic!("default pause hotkey resolves enabled, got {other:?}"),
    };

    let mut produced: Vec<(String, String, Vec<AllowEntry>)> = vec![
        (
            "record_start_confirm_body".to_string(),
            crate::record_start_confirm_body("Invoice sweep"),
            Vec::new(),
        ),
        (
            "recording_cap_body".to_string(),
            crate::recording_cap_body(30),
            Vec::new(),
        ),
        (
            "archive_reset_confirm_body".to_string(),
            crate::archive_reset_confirm_body(std::path::Path::new("C:/data/archives/a.gla")),
            Vec::new(),
        ),
        (
            "secure_erase_final_confirm_body(with logs)".to_string(),
            crate::secure_erase_final_confirm_body(true),
            Vec::new(),
        ),
        (
            "secure_erase_final_confirm_body(without logs)".to_string(),
            crate::secure_erase_final_confirm_body(false),
            Vec::new(),
        ),
        (
            "secure_erase_scope_confirmation".to_string(),
            crate::secure_erase_scope_confirmation().to_string(),
            Vec::new(),
        ),
        (
            "describe_log_clearing(all removed)".to_string(),
            crate::describe_log_clearing((3, 0)),
            Vec::new(),
        ),
        (
            "describe_log_clearing(active log kept)".to_string(),
            crate::describe_log_clearing((3, 1)),
            Vec::new(),
        ),
        (
            "receipt_note_for_dialog(written)".to_string(),
            crate::receipt_note_for_dialog(
                Ok(std::path::PathBuf::from("C:/data/receipts/r.json")),
                "encrypted_archive: copied (1)",
            ),
            Vec::new(),
        ),
        (
            "receipt_note_for_dialog(needs retry)".to_string(),
            crate::receipt_note_for_dialog(
                Err("disk full".to_string()),
                "encrypted_archive: needs retry (1)",
            ),
            Vec::new(),
        ),
        (
            "hotkey::registration_failure_alert".to_string(),
            hotkey::registration_failure_alert(chord),
            em_dash_allow(
                "prose em dash within the one-per-string cap (the one-per-string cap), \
                 recorded by the Lane B audit",
            ),
        ),
    ];

    for state in [
        NotificationAccessState::Allowed,
        NotificationAccessState::Unspecified,
        NotificationAccessState::Denied,
        NotificationAccessState::Unavailable,
        NotificationAccessState::Unsupported,
    ] {
        produced.push((
            format!("notification privacy_copy({state:?})"),
            state.privacy_copy().to_string(),
            Vec::new(),
        ));
        produced.push((
            format!("notification diagnostics_copy({state:?})"),
            state.diagnostics_copy().to_string(),
            Vec::new(),
        ));
    }

    // Every archive-and-reset outcome, as rendered; the Completed arm
    // also carries the store crate's encryption receipt strings.
    let archive_report = |outcome| ArchiveResetReport {
        outcome,
        archive_path: Some(std::path::PathBuf::from("C:/data/archives/a.gla")),
        events_archived: 120,
        sessions_archived: 3,
        events_deleted: 120,
        sessions_deleted: 3,
        new_session_id: Some(7),
        message: None,
        archive_encryption: Some(ArchiveEncryptionReceipt::dpapi_user()),
    };
    for outcome in [
        ArchiveResetOutcome::Completed,
        ArchiveResetOutcome::ArchiveFailed,
        ArchiveResetOutcome::DeleteFailed,
        ArchiveResetOutcome::DeleteCommittedScrubIncomplete,
        ArchiveResetOutcome::ReplacementSessionFailed,
    ] {
        produced.push((
            format!("archive_reset_report_message({outcome:?})"),
            crate::archive_reset_report_message(
                &archive_report(outcome),
                outcome == ArchiveResetOutcome::ReplacementSessionFailed,
                false,
                "Content-free receipt: C:/data/receipts/r.json",
            ),
            Vec::new(),
        ));
    }
    // The no-archive-path fallback label renders too.
    produced.push((
        "archive_reset_report_message(no archive path)".to_string(),
        crate::archive_reset_report_message(
            &ArchiveResetReport {
                archive_path: None,
                ..archive_report(ArchiveResetOutcome::ArchiveFailed)
            },
            false,
            true,
            "Content-free receipt: needs retry (disk full)",
        ),
        Vec::new(),
    ));

    let erase_report = |outcome| SecureEraseReport {
        outcome,
        events_deleted: 120,
        sessions_deleted: 3,
        new_session_id: Some(7),
        message: None,
    };
    for outcome in [
        SecureEraseOutcome::Completed,
        SecureEraseOutcome::DeleteFailed,
        SecureEraseOutcome::DeleteCommittedScrubIncomplete,
        SecureEraseOutcome::ReplacementSessionFailed,
    ] {
        produced.push((
            format!("secure_erase_report_message({outcome:?})"),
            crate::secure_erase_report_message(
                &erase_report(outcome),
                outcome == SecureEraseOutcome::ReplacementSessionFailed,
                false,
                &[
                    "Archive removal needs retry: 1 sealed item could not be completed."
                        .to_string(),
                ],
                "Content-free receipt: C:/data/receipts/r.json",
            ),
            Vec::new(),
        ));
    }

    let mut violations = Vec::new();
    for (name, text, allows) in &produced {
        violations.extend(copy_style::audit_text(
            "gilbreth-app produced dialog strings",
            name,
            0,
            text,
            allows,
        ));
    }
    copy_style::assert_no_violations(&violations);
}

#[test]
fn consent_dialog_copy_passes_the_copy_style_law() {
    // The consent dialog's tone rules live in consent.rs; this adds the
    // shared style law over the same pinned constants (they are also
    // source-scanned, so this mostly documents that both apply).
    let violations = [
        copy_style::audit_text(
            "consent copy",
            "CONSENT_DIALOG_TITLE",
            0,
            crate::consent_copy::CONSENT_DIALOG_TITLE,
            &[],
        ),
        copy_style::audit_text(
            "consent copy",
            "CONSENT_DIALOG_BODY",
            0,
            crate::consent_copy::CONSENT_DIALOG_BODY,
            &[],
        ),
    ]
    .concat();
    copy_style::assert_no_violations(&violations);
}
