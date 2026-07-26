//! First-run consent dialog (R1; design record
//! the first-run consent design, all seven decisions owner-made
//! 2026-07-12).
//!
//! Fires in the pump process only, on the main thread, after config
//! load/create and before the tray exists or any capture source starts.
//! Gated by `privacy.posture_confirmed`: fresh installs are written `false`
//! and asked each launch until they choose; existing configs are
//! grandfathered `true` and never see it. All three outcomes start capture.
//! The dialog chooses between two capture postures — it is not
//! consent-to-run; the always-visible tray icon stays the run-consent
//! mechanism (stealth-mode Never, 2026-07-02).

use std::path::Path;

use tracing::{info, warn};

use crate::config::{self, AppConfig};
pub use crate::consent_copy::{CONSENT_DIALOG_BODY, CONSENT_DIALOG_TITLE};
use crate::platform::{self, AlertKind, ConfirmAnswer};

/// Show the first-run posture dialog if the posture is unconfirmed, and
/// apply the answer. Blocking; the caller runs it on the main thread before
/// the tray is created and before any capture source starts, so nothing is
/// recorded while the dialog is up and the chosen posture governs this
/// run's writer policy from the first event.
pub fn run_first_run_consent(config_path: &Path, config: &mut AppConfig) {
    if config.privacy.posture_confirmed {
        return;
    }
    info!("first-run capture posture unconfirmed; showing the consent dialog");
    let answer =
        platform::confirm_three_way(CONSENT_DIALOG_TITLE, CONSENT_DIALOG_BODY, AlertKind::Info);
    apply_consent_answer(config_path, config, answer);
}

/// Outcome application, separated for tests. The load-bearing rule: full
/// capture only ever runs with a persisted opt-in — the config write comes
/// first, and a failed write leaves this run lean and unconfirmed (the
/// dialog returns next launch; mirrors the tray toggle's
/// log-and-revert-on-save-failure posture). Dismissal changes nothing on
/// disk, so the on-disk `posture_confirmed = false` re-arms the next
/// launch by construction.
fn apply_consent_answer(config_path: &Path, config: &mut AppConfig, answer: ConfirmAnswer) {
    let store_key_content = match answer {
        ConfirmAnswer::Positive => true,
        ConfirmAnswer::Negative => false,
        ConfirmAnswer::Dismissed => {
            info!("first-run capture posture deferred; running lean and asking again next launch");
            return;
        }
    };
    match config::save_store_key_content(config_path, store_key_content) {
        Ok(()) => {
            config.privacy.store_key_content = store_key_content;
            config.privacy.posture_confirmed = true;
            info!(
                store_key_content,
                "first-run capture posture chosen and persisted"
            );
        }
        Err(error) => {
            warn!(
                %error,
                "could not persist the first-run posture choice; running lean and asking again next launch"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn fresh_config(dir: &Path) -> (PathBuf, AppConfig) {
        let path = dir.join("config.toml");
        let loaded = config::load_or_create(&path).expect("config created");
        assert!(!loaded.config.privacy.posture_confirmed);
        (path, loaded.config)
    }

    #[test]
    fn positive_persists_full_capture_and_confirms() {
        let dir = tempdir().expect("temp dir");
        let (path, mut app_config) = fresh_config(dir.path());

        apply_consent_answer(&path, &mut app_config, ConfirmAnswer::Positive);

        assert!(app_config.privacy.store_key_content);
        assert!(app_config.privacy.posture_confirmed);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("store_key_content = true"));
        assert!(written.contains("posture_confirmed = true"));
    }

    #[test]
    fn negative_persists_lean_and_confirms() {
        let dir = tempdir().expect("temp dir");
        let (path, mut app_config) = fresh_config(dir.path());

        apply_consent_answer(&path, &mut app_config, ConfirmAnswer::Negative);

        assert!(!app_config.privacy.store_key_content);
        assert!(app_config.privacy.posture_confirmed);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("store_key_content = false"));
        assert!(written.contains("posture_confirmed = true"));
    }

    #[test]
    fn dismissed_changes_nothing_and_rearms_next_launch() {
        let dir = tempdir().expect("temp dir");
        let (path, mut app_config) = fresh_config(dir.path());

        apply_consent_answer(&path, &mut app_config, ConfirmAnswer::Dismissed);

        assert!(!app_config.privacy.store_key_content);
        assert!(!app_config.privacy.posture_confirmed);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("posture_confirmed = false"));
        let reloaded = config::load_or_create(&path).expect("config reloads");
        assert!(!reloaded.config.privacy.posture_confirmed);
    }

    #[test]
    fn failed_write_after_positive_stays_lean_and_unconfirmed() {
        // Full capture only ever runs with a persisted opt-in: when the
        // config write fails, the in-memory posture must stay lean and
        // unconfirmed so this run records no key content and the dialog
        // returns next launch. A regular file where the parent directory
        // should be makes the save's create_dir_all fail deterministically
        // (write_atomic creates missing parents, so a merely-absent
        // directory would not fail).
        let dir = tempdir().expect("temp dir");
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, "not a directory").expect("blocker written");
        let unwritable = blocker.join("config.toml");
        let mut app_config = AppConfig::default();
        app_config.privacy.posture_confirmed = false;

        apply_consent_answer(&unwritable, &mut app_config, ConfirmAnswer::Positive);

        assert!(!app_config.privacy.store_key_content);
        assert!(!app_config.privacy.posture_confirmed);
    }

    #[test]
    fn confirmed_posture_never_shows_the_dialog() {
        // Safe to call in tests: with the posture confirmed the function
        // returns before any platform dialog call, and the config file is
        // never touched (it does not even need to exist).
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut app_config = AppConfig::default();
        assert!(app_config.privacy.posture_confirmed);

        run_first_run_consent(&path, &mut app_config);

        assert!(!path.exists());
        assert!(!app_config.privacy.store_key_content);
    }

    #[test]
    fn copy_pins_hold() {
        // The design's pinned facts (the first-run consent design "Canonical
        // copy"): both honesty sentences, the retention window, the
        // tray-toggle phrase, and the three-outcome button legend.
        assert!(CONSENT_DIALOG_BODY.contains("Gilbreth sees this machine only"));
        assert!(CONSENT_DIALOG_BODY.contains("Observing your own work changes it at first"));
        assert!(CONSENT_DIALOG_BODY.contains("Window titles are kept 30 days by default"));
        assert!(CONSENT_DIALOG_BODY
            .to_lowercase()
            .contains("store typed key content"));
        assert!(CONSENT_DIALOG_BODY.contains("whoever is using this session"));
        assert!(CONSENT_DIALOG_BODY.contains("\nYes: "));
        assert!(CONSENT_DIALOG_BODY.contains("\nNo: "));
        assert!(CONSENT_DIALOG_BODY.contains("\nCancel: "));
        assert!(CONSENT_DIALOG_BODY.contains("asks again next launch"));
    }

    #[test]
    fn copy_style_and_tone_guards_hold() {
        // Copy-sweep style rules pinned for this dialog (zero em dashes,
        // zero arrows) plus the tone rules: state the posture, no safety
        // promises, no fear copy.
        let all = format!("{CONSENT_DIALOG_TITLE}\n{CONSENT_DIALOG_BODY}");
        assert!(!all.contains('\u{2014}'), "no em dashes in dialog copy");
        assert!(!all.contains('\u{2192}'), "no arrows in dialog copy");
        let lower = all.to_lowercase();
        for banned in [
            "safe",
            "protect",
            "guarantee",
            "secure",
            "private",
            "worry",
            "trust us",
        ] {
            assert!(
                !lower.contains(banned),
                "banned tone word present: {banned}"
            );
        }
    }
}
