//! The Privacy tab in the instrument register (slice 2 of the dashboard
//! register program, charter: the recorded redesign,
//! direction D "Plain controls").
//!
//! Three sections: Your data (the opening facts and gauges), Settings (one
//! group — every control colocated with its state chip and helper line),
//! and Delete data and archive handling (the prune with confirmations, the
//! DASH-05 continuity note, the erase facts at the point of action, and the
//! portable archive export). No narrative frames: the tab states facts and
//! offers controls. All write paths go through the cooperative config
//! writer; the serialized save flow (tail-review SF-3) is preserved and
//! test-pinned, not reimplemented.

use egui::{CornerRadius, FontId, Margin, RichText, Stroke};

use super::widgets::{
    self as widgets, caption, opening_section_kicker, secnote, section_kicker, state_chip,
    summary_section,
};
#[cfg(windows)]
use crate::data::PortableArchiveExportMode;
use crate::data::{
    NotificationAccessRowState, PrivacySettingsValues, PrivacySnapshot, PrunePreview,
};
use crate::format::{split_unit, thousands, MISSING_VALUE_CELL};
use crate::theme;

pub const LOCAL_ONLY_CAPTION: &str = "Everything Gilbreth captures stays in a local database on \
     this PC. The app makes no outbound network calls, and nothing is uploaded, ever.";
pub const KEYSTROKES_ON_LINE: &str = "full key content capture is enabled (opt-in). Turn it off \
     under tray > Privacy > Store typed key content; the change applies after Gilbreth restarts.";
pub const KEYSTROKES_OFF_LINE: &str = "counted with timing, modifiers, and a coarse key class; \
     typed content is not stored (storing it is an explicit tray opt-in).";
pub const TITLES_LIFE_LINE: &str = "stored for context for the life of the row; the title \
     setting under Settings below ages them out.";

pub const PRUNE_ROW_TITLE: &str = "Prune old data";
pub const PRUNE_CAPTION: &str =
    "Removes entries older than the cutoff from the local database. Not a secure erase.";
pub const PRUNE_DAYS_LABEL: &str = "Delete data older than";
/// UX-29: the DragValue reads as editable, and changing it visibly
/// re-runs the preview.
pub const PRUNE_DAYS_HELP: &str = "Drag or click to type a number of days. Changing it \
     re-runs the preview below.";
pub const CONFIRM_PRUNE_LABEL: &str = "Confirm deletion";
pub const PRUNE_BUTTON_LABEL: &str = "Delete old data";
/// Shown while the previewed counts still belong to a different days value;
/// deletion stays disabled until the preview catches up.
pub const UPDATING_PREVIEW_LABEL: &str = "Updating preview…";
/// UX-32: an armed confirmation never disappears silently.
// copy-allow: em-dash prose em dash within the one-per-string cap (the one-per-string cap), recorded by the Lane B audit
pub const CONFIRM_CLEARED_LABEL: &str = "Confirmation cleared — the preview changed.";
pub const CONFIRM_DISABLED_REASON: &str =
    "Nothing to confirm yet: the preview above must show entries ready to delete.";
pub const DELETE_DISABLED_REASON: &str =
    "Tick Confirm deletion once the preview shows entries ready to delete.";
pub const SAVE_DISABLED_REASON: &str = "Tick \"I understand this disables protected-context \
     redaction\" above to save with suppression off.";

/// The erase facts, structured at the point of action (charter §3). The
/// stronger tools live in the tray; the dashboard states what each does.
#[cfg(windows)]
pub const ERASE_BLOCK_TITLE: &str = "Stronger tools live in the tray";
// One tool, not two: macOS has no archive lane (owner decision 2026-07-19),
// so the block below describes secure erase alone.
#[cfg(not(windows))]
pub const ERASE_BLOCK_TITLE: &str = "The stronger tool lives in the tray";
#[cfg(windows)]
pub const ARCHIVE_RESET_LINE: &str = "Archive and reset creates an account-bound encrypted .gla \
     archive before clearing the live data. Moving an archive elsewhere requires an explicit \
     passphrase-protected or acknowledged-plaintext portable export (below).";
pub const LEGACY_ARCHIVES_LINE: &str =
    "Legacy .db archives remain plaintext and are never silently converted.";
pub const ERASE_ALL_LINE: &str = "Erase all my data wipes without preserving an archive. This is \
     the strong path: dashboard deletes never zero the underlying storage with forensic \
     certainty.";
/// UX-35: the per-event delete lives on the native Session tab since the
/// UX-62 port; the capability pointer stays truthful.
pub const SINGLE_ENTRIES_HINT: &str =
    "Single entries: select them in the Event list on the Session tab.";

pub const CONTINUITY_TITLE: &str = "What deleting changes for discovery";
/// Mirrors `SEQUENCE_MIN_HISTORY_DAYS` (db.py pins 2).
const PATTERNS_HISTORY_FLOOR_DAYS: i64 = crate::data::SEQUENCE_MIN_HISTORY_DAYS;
/// Mirrors `DIGEST_CHANGE_MIN_HISTORY_DAYS` (db.py pins 14).
const CHANGED_THIS_WEEK_HISTORY_FLOOR_DAYS: i64 = 14;

pub const SETTINGS_ERROR_PREFIX: &str =
    "config.toml is malformed, so privacy settings cannot be saved from the dashboard";
pub const SUPPRESSION_ROW_TITLE: &str = "Suppress sensitive content";
pub const SUPPRESSION_LABEL: &str = "Suppress sensitive content during protected contexts";
/// The scope sentence in platform tokens (the pre-beta fast-follow's
/// privacy item, merged here per the charter): each platform names its own
/// protected contexts.
#[cfg(windows)]
pub const SUPPRESSION_CAPTION: &str = "When enabled, Gilbreth keeps timing rows but redacts key \
     values, window titles, and clipboard size/count metadata while the Windows session is \
     locked or disconnected, Secure Desktop is active, or a password field is focused.";
#[cfg(not(windows))]
pub const SUPPRESSION_CAPTION: &str = "When enabled, Gilbreth keeps timing rows but redacts key \
     values, window titles, and clipboard size/count metadata while the login session is locked \
     or disconnected, macOS secure input is active, or a password field is focused.";
#[cfg(windows)]
pub const SUPPRESSION_OFF_WARNING: &str = "Disabling this can store more sensitive content \
     during protected lock, disconnect, Secure Desktop, and password-field contexts.";
#[cfg(not(windows))]
pub const SUPPRESSION_OFF_WARNING: &str = "Disabling this can store more sensitive content \
     during protected lock, disconnect, secure-input, and password-field contexts.";
pub const DISABLE_CONFIRM_LABEL: &str = "I understand this disables protected-context redaction";
pub const SETTINGS_EDIT_CAPTION: &str = "Use the three list fields below to add or edit entries. \
     Put one entry on each line, then choose Save privacy settings at the end of this section. \
     Saved changes apply after Gilbreth restarts.";
pub const TITLE_RETENTION_ROW_TITLE: &str = "Blank window titles older than";
pub const TITLE_RETENTION_HINT: &str = "0 keeps titles for the life of the row. Applies at the \
     next Gilbreth start and clears the live database.";
pub const TITLE_PATTERNS_LABEL: &str = "Redact window titles containing";
pub const TITLE_PATTERNS_PLACEHOLDER: &str = "One case-sensitive phrase per line\nExample: Bank";
pub const TITLE_PATTERNS_CAPTION: &str = "Add or edit one case-sensitive phrase per line; delete \
     a line to remove it. A match redacts the whole window title and marks the row sensitive.";
pub const KEY_PATTERNS_LABEL: &str = "Redact key names containing";
pub const KEY_PATTERNS_PLACEHOLDER: &str = "One case-sensitive key name per line\nExample: Enter";
/// UX-44: egui labels aren't markdown (no backticks), and the safety half
/// stands alone without the hedge tail.
pub const KEY_PATTERNS_CAPTION: &str =
    "Add or edit one case-sensitive key name per line; delete a line to remove it. A match \
     redacts that key value. Use sensitive-context suppression above to protect typed content.";
pub const EXCLUDED_APPS_LABEL: &str = "Exclude apps from capture";
pub const EXCLUDED_APPS_PLACEHOLDER: &str =
    "One executable filename per line\nExample: private.exe";
pub const EXCLUDED_APPS_CAPTION: &str = "Add or edit one executable filename per line; delete a \
     line to remove it. Matching ignores capitalization. After saving, restart Gilbreth to apply \
     exclusions; existing rows are unchanged. While this list is non-empty, notification counts \
     are also paused because Windows does not provide a reliable executable identity.";
/// The macOS half of the exclusion fail-closed rule (owner decision,
/// 2026-07-28): without the Foreground stream there is no app identity to
/// match exclusions against, so input capture pauses rather than storing
/// rows that could belong to an excluded app.
#[cfg(target_os = "macos")]
pub const EXCLUDED_APPS_MACOS_FOREGROUND_CAPTION: &str = "While this list is non-empty and the \
     Foreground stream is off, keyboard and mouse capture is also paused because macOS provides \
     no app identity without Foreground.";
pub const NOTIFICATION_ROW_TITLE: &str = "Notification counts";
pub const MOUSE_RETENTION_ROW_TITLE: &str = "Keep raw mouse movement for";
pub const MOUSE_RETENTION_CAPTION: &str = "Housekeeping for the mouse-speed lenses. Older \
     motion rows are pruned so the database stays small. 0 keeps everything.";
pub const SAVE_SETTINGS_LABEL: &str = "Save privacy settings";
pub const SAVE_SETTINGS_HINT: &str =
    "Saves all editable settings above. Changes take effect after Gilbreth restarts.";
#[cfg(windows)]
pub const PORTABLE_EXPORT_TITLE: &str = "Portable archive export";
#[cfg(windows)]
pub const PORTABLE_EXPORT_CAPTION: &str = "Make an explicit copy of an encrypted archive for use outside this Windows profile. The source archive stays in Gilbreth. Legacy .db archives remain plaintext and are not silently converted.";
#[cfg(windows)]
pub const PLAINTEXT_EXPORT_WARNING: &str = "Plaintext exports contain the full activity database and are not protected by Gilbreth encryption. Store and transfer the file accordingly.";

/// What the Privacy tab asks the shell to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyAction {
    /// The prune-days input changed; queue a fresh preview.
    SetPruneDays(i64),
    /// Run the prune at the cutoff the previewed counts were computed for.
    PruneOldEvents { cutoff_ms: i64 },
    /// Save the editor values; `revisions` snapshots every field's edit
    /// counter at the click, so the later acknowledgement can tell which
    /// buffers were edited after this save and must survive it.
    SaveSettings {
        values: PrivacySettingsValues,
        revisions: [u64; ADVANCED_BUFFER_FIELDS.len()],
    },
    #[cfg(windows)]
    ExportPortableArchive {
        source_id: String,
        mode: PortableArchiveExportMode,
    },
}

/// Cross-frame state the shell owns for this tab.
pub struct PrivacyView<'a> {
    pub snapshot: &'a PrivacySnapshot,
    /// One-shot prune notice: (is_error, message).
    pub prune_notice: Option<&'a (bool, String)>,
    /// One-shot settings notice: (is_error, message).
    pub advanced_notice: Option<&'a (bool, String)>,
    /// One-shot portable archive export notice: (is_error, message).
    #[cfg(windows)]
    pub portable_export_notice: Option<&'a (bool, String)>,
}

pub fn prune_confirm_id() -> egui::Id {
    egui::Id::new("privacy-prune-confirm")
}

pub fn prune_days_id() -> egui::Id {
    egui::Id::new("privacy-prune-days")
}

/// The settings-editor buffers, so the shell can clear them after a
/// successful save (they re-seed from the refreshed snapshot). The ids keep
/// their historical "advanced" names: they are persisted egui state keys,
/// and renaming them buys nothing.
pub const ADVANCED_BUFFER_FIELDS: [&str; 7] = [
    "suppression",
    "disable-confirm",
    "titles",
    "keys",
    "excluded-apps",
    "title-retention",
    "mouse-retention",
];

pub fn advanced_buffer_id(field: &str) -> egui::Id {
    egui::Id::new(("privacy-advanced", field))
}

/// Monotonic per-field edit counter, bumped on every widget change and
/// never cleared. A save captures all six; the acknowledgement uses them
/// to tell "unchanged since that save" from "edited afterwards".
fn advanced_buffer_revision_id(field: &str) -> egui::Id {
    egui::Id::new(("privacy-advanced-revision", field))
}

/// Record one edit to a field. Public so tests can simulate typing the
/// same way the widgets report it.
pub fn bump_advanced_buffer_revision(ctx: &egui::Context, field: &str) {
    let id = advanced_buffer_revision_id(field);
    ctx.data_mut(|data| {
        let revision: u64 = data.get_temp(id).unwrap_or(0);
        data.insert_temp(id, revision + 1);
    });
}

/// The edit revisions of all six editor fields, in
/// [`ADVANCED_BUFFER_FIELDS`] order — captured at the moment of a save.
pub fn advanced_buffer_revisions(ctx: &egui::Context) -> [u64; ADVANCED_BUFFER_FIELDS.len()] {
    let mut revisions = [0u64; ADVANCED_BUFFER_FIELDS.len()];
    ctx.data_mut(|data| {
        for (slot, field) in revisions.iter_mut().zip(ADVANCED_BUFFER_FIELDS) {
            *slot = data
                .get_temp(advanced_buffer_revision_id(field))
                .unwrap_or(0);
        }
    });
    revisions
}

/// Drop the editor buffers that have NOT been edited since the save the
/// acknowledging snapshot reflects, so they re-seed from it next frame.
/// Fields whose revision moved past the captured one carry newer input —
/// clearing those would discard an edit the acknowledged save never saw.
pub fn clear_unedited_buffers(
    ctx: &egui::Context,
    saved_revisions: &[u64; ADVANCED_BUFFER_FIELDS.len()],
) {
    ctx.data_mut(|data| {
        for (field, saved) in ADVANCED_BUFFER_FIELDS.iter().zip(saved_revisions) {
            let current: u64 = data
                .get_temp(advanced_buffer_revision_id(field))
                .unwrap_or(0);
            if current != *saved {
                continue;
            }
            let id = advanced_buffer_id(field);
            data.remove::<bool>(id);
            data.remove::<String>(id);
            data.remove::<i64>(id);
        }
    });
}

fn notice_line(ui: &mut egui::Ui, notice: Option<&(bool, String)>) {
    if let Some((is_error, message)) = notice {
        // UX-34: glyph beside the color, never hue alone.
        super::widgets::outcome_notice(ui, *is_error, message);
        ui.add_space(2.0);
    }
}

pub fn show(ui: &mut egui::Ui, view: &PrivacyView<'_>) -> Vec<PrivacyAction> {
    let mut actions = Vec::new();
    let snapshot = view.snapshot;
    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
    }

    your_data_section(ui, snapshot);
    settings_section(ui, view, &mut actions);
    delete_and_archive_section(ui, view, &mut actions);
    actions
}

#[cfg(windows)]
pub fn clear_portable_export_secrets(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.remove::<String>(egui::Id::new("privacy-portable-export-passphrase"));
        data.remove::<String>(egui::Id::new("privacy-portable-export-passphrase-confirm"));
        data.remove::<bool>(egui::Id::new("privacy-portable-export-plaintext-ack"));
    });
}

// ---------------------------------------------------------------- widgets

/// One framed control row: name and state chip on the header line, the
/// control and its helper text underneath. The settings group's anatomy.
fn control_row(
    ui: &mut egui::Ui,
    name: &str,
    chip: Option<(&str, bool)>,
    body: impl FnOnce(&mut egui::Ui, egui::Id),
) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let label_id = ui
                .horizontal(|ui| {
                    let label = ui.label(
                        RichText::new(name)
                            .color(theme::SILVER)
                            .font(FontId::new(13.0, theme::family_medium())),
                    );
                    if let Some((text, on)) = chip {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            state_chip(ui, text, on);
                        });
                    }
                    label.id
                })
                .inner;
            body(ui, label_id);
        });
}

fn hint_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::GRAY).size(11.5));
}

fn list_count_chip(count: usize, singular: &str, plural: &str) -> (String, bool) {
    let noun = if count == 1 { singular } else { plural };
    (format!("{count} {noun}"), count > 0)
}

/// The three line-list editors share one explicit editable treatment:
/// visible at rest, brass on hover, amber on focus, with examples inside
/// empty fields and the row heading as their accessible label.
fn settings_list_editor(
    ui: &mut egui::Ui,
    value: &mut String,
    label_id: egui::Id,
    placeholder: &'static str,
) -> egui::Response {
    let width = 520.0_f32.min(ui.available_width().max(120.0));
    ui.scope(|ui| {
        ui.visuals_mut().widgets.inactive.bg_stroke =
            Stroke::new(1.0, theme::GRAY.gamma_multiply(0.68));
        ui.add(
            egui::TextEdit::multiline(value)
                .desired_rows(3)
                .desired_width(width)
                .margin(Margin::symmetric(9, 7))
                .hint_text(RichText::new(placeholder).color(theme::GRAY)),
        )
    })
    .inner
    .labelled_by(label_id)
}

// --------------------------------------------------------------- sections

fn your_data_section(ui: &mut egui::Ui, snapshot: &PrivacySnapshot) {
    // The tab's first section opens directly under the tab bar (§3).
    opening_section_kicker(ui, "YOUR DATA");
    // Amendment §6: the opening facts are reading text — secnotes, plain
    // labels, uniform 6px inter-line gaps.
    ui.spacing_mut().item_spacing.y = 6.0;
    secnote(ui, LOCAL_ONLY_CAPTION);
    if snapshot.settings.error.is_none() {
        let keystroke_line = if snapshot.settings.store_key_content {
            KEYSTROKES_ON_LINE.to_string()
        } else {
            KEYSTROKES_OFF_LINE.to_string()
        };
        let titles_line = if snapshot.settings.title_retention_days > 0 {
            format!(
                "stored for context, blanked once rows are older than {} days (the title \
                 setting under Settings below).",
                snapshot.settings.title_retention_days
            )
        } else {
            TITLES_LIFE_LINE.to_string()
        };
        for (term, line) in [
            ("Keystrokes", keystroke_line),
            ("Window titles", titles_line),
        ] {
            secnote(ui, &format!("{term}: {line}"));
        }
    }
    ui.spacing_mut().item_spacing.y = 7.0;
    ui.add_space(4.0);
    let (db_value, db_suffix) = snapshot
        .install
        .as_ref()
        .map(|install| split_unit(&gilbreth_read::format_bytes(install.db_size_bytes)))
        .unwrap_or_else(|| (MISSING_VALUE_CELL.to_string(), None));
    let gauges: [(&str, String, Option<String>); 3] = [
        ("Events stored", thousands(snapshot.counts.events), None),
        ("Sessions", snapshot.counts.sessions.to_string(), None),
        ("Database", db_value, db_suffix),
    ];
    widgets::gauge_tiles_suffixed(ui, &gauges, 4);
    if let Some(install) = &snapshot.install {
        // The storage path as a quiet mono line (charter §1).
        ui.label(
            RichText::new(&install.db_path)
                .color(theme::GRAY)
                .font(FontId::new(11.5, egui::FontFamily::Monospace)),
        );
        for warning in &install.storage_warnings {
            super::widgets::flagged_line(ui, warning);
        }
    }
}

/// The one settings group (charter §2): every control with its state chip
/// and helper line, one save button, the serialized save flow unchanged.
fn settings_section(ui: &mut egui::Ui, view: &PrivacyView<'_>, actions: &mut Vec<PrivacyAction>) {
    let snapshot = view.snapshot;
    section_kicker(ui, "SETTINGS");
    notice_line(ui, view.advanced_notice);
    if let Some(error) = &snapshot.settings.error {
        ui.label(
            RichText::new(format!("{SETTINGS_ERROR_PREFIX}: {error}"))
                .color(theme::RED)
                .size(12.5),
        );
        return;
    }

    let settings = &snapshot.settings;
    secnote(ui, SETTINGS_EDIT_CAPTION);
    ui.add_space(2.0);

    // Suppression: toggle, platform-token scope sentence, inline state.
    let suppression_id = advanced_buffer_id("suppression");
    let mut suppression: bool = ui.ctx().data_mut(|data| {
        *data.get_temp_mut_or_insert_with(suppression_id, || settings.sensitive_context_suppression)
    });
    let mut disable_confirmed = true;
    control_row(
        ui,
        SUPPRESSION_ROW_TITLE,
        Some(if suppression {
            ("ON", true)
        } else {
            ("OFF", false)
        }),
        |ui, _label_id| {
            if ui.checkbox(&mut suppression, SUPPRESSION_LABEL).changed() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(suppression_id, suppression));
                bump_advanced_buffer_revision(ui.ctx(), "suppression");
            }
            hint_line(ui, SUPPRESSION_CAPTION);
            if let Some(rows) = snapshot.sensitive_rows_this_session {
                let row_word = if rows == 1 { "row" } else { "rows" };
                caption(ui, &format!("{rows} {row_word} redacted this session."));
            }
            if !suppression {
                super::widgets::flagged_line(ui, SUPPRESSION_OFF_WARNING);
                let confirm_id = advanced_buffer_id("disable-confirm");
                let mut confirmed: bool = ui
                    .ctx()
                    .data_mut(|data| data.get_temp(confirm_id).unwrap_or(false));
                if ui.checkbox(&mut confirmed, DISABLE_CONFIRM_LABEL).changed() {
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(confirm_id, confirmed));
                    bump_advanced_buffer_revision(ui.ctx(), "disable-confirm");
                }
                disable_confirmed = confirmed;
            }
        },
    );

    // Title retention: the sentinel meaning as helper text, not a label.
    let title_retention_id = advanced_buffer_id("title-retention");
    let mut title_retention: i64 = ui.ctx().data_mut(|data| {
        *data.get_temp_mut_or_insert_with(title_retention_id, || {
            settings.title_retention_days as i64
        })
    });
    let title_chip = if title_retention == 0 {
        ("KEEP ALL".to_string(), false)
    } else {
        (format!("{title_retention} DAYS"), true)
    };
    control_row(
        ui,
        TITLE_RETENTION_ROW_TITLE,
        Some((title_chip.0.as_str(), title_chip.1)),
        |ui, _label_id| {
            ui.horizontal(|ui| {
                let response = ui.add(
                    egui::DragValue::new(&mut title_retention)
                        .range(0..=3650)
                        .speed(1),
                );
                ui.label(RichText::new("days").color(theme::SILVER_DIM).size(12.5));
                if response.changed() {
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(title_retention_id, title_retention));
                    bump_advanced_buffer_revision(ui.ctx(), "title-retention");
                }
            });
            hint_line(ui, TITLE_RETENTION_HINT);
        },
    );

    // Title patterns.
    let titles_id = advanced_buffer_id("titles");
    let mut titles: String = ui.ctx().data_mut(|data| {
        data.get_temp_mut_or_insert_with(titles_id, || settings.redact_titles_containing.join("\n"))
            .clone()
    });
    let title_count = titles
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let titles_chip = list_count_chip(title_count, "RULE", "RULES");
    control_row(
        ui,
        TITLE_PATTERNS_LABEL,
        Some((titles_chip.0.as_str(), titles_chip.1)),
        |ui, label_id| {
            if settings_list_editor(ui, &mut titles, label_id, TITLE_PATTERNS_PLACEHOLDER).changed()
            {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(titles_id, titles.clone()));
                bump_advanced_buffer_revision(ui.ctx(), "titles");
            }
            hint_line(ui, TITLE_PATTERNS_CAPTION);
        },
    );

    // Key patterns.
    let keys_id = advanced_buffer_id("keys");
    let mut keys: String = ui.ctx().data_mut(|data| {
        data.get_temp_mut_or_insert_with(keys_id, || settings.redact_keys_containing.join("\n"))
            .clone()
    });
    let key_count = keys.lines().filter(|line| !line.trim().is_empty()).count();
    let keys_chip = list_count_chip(key_count, "RULE", "RULES");
    control_row(
        ui,
        KEY_PATTERNS_LABEL,
        Some((keys_chip.0.as_str(), keys_chip.1)),
        |ui, label_id| {
            if settings_list_editor(ui, &mut keys, label_id, KEY_PATTERNS_PLACEHOLDER).changed() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(keys_id, keys.clone()));
                bump_advanced_buffer_revision(ui.ctx(), "keys");
            }
            hint_line(ui, KEY_PATTERNS_CAPTION);
        },
    );

    // Per-app exclusions (the foundation's editor, truthful next-start copy).
    let excluded_id = advanced_buffer_id("excluded-apps");
    let mut excluded_apps: String = ui.ctx().data_mut(|data| {
        data.get_temp_mut_or_insert_with(excluded_id, || settings.excluded_apps.join("\n"))
            .clone()
    });
    let excluded_count = excluded_apps
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let excluded_chip = list_count_chip(excluded_count, "APP", "APPS");
    control_row(
        ui,
        EXCLUDED_APPS_LABEL,
        Some((excluded_chip.0.as_str(), excluded_chip.1)),
        |ui, label_id| {
            if settings_list_editor(ui, &mut excluded_apps, label_id, EXCLUDED_APPS_PLACEHOLDER)
                .changed()
            {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(excluded_id, excluded_apps.clone()));
                bump_advanced_buffer_revision(ui.ctx(), "excluded-apps");
            }
            hint_line(ui, EXCLUDED_APPS_CAPTION);
            #[cfg(target_os = "macos")]
            hint_line(ui, EXCLUDED_APPS_MACOS_FOREGROUND_CAPTION);
        },
    );

    // Notification access: tray-owned state, stated here (read-only).
    if let Some(notification) = &snapshot.notification_access {
        let (chip_text, chip_on) = match notification.state {
            NotificationAccessRowState::Allowed => ("ON", true),
            NotificationAccessRowState::Unspecified => ("NOT REQUESTED", false),
            NotificationAccessRowState::Denied => ("DENIED", false),
            NotificationAccessRowState::Unavailable => ("UNAVAILABLE", false),
            NotificationAccessRowState::Unsupported => ("UNSUPPORTED", false),
        };
        control_row(
            ui,
            NOTIFICATION_ROW_TITLE,
            Some((chip_text, chip_on)),
            |ui, _label_id| {
                hint_line(ui, &notification.privacy_copy);
            },
        );
    }

    // Mouse retention.
    let mouse_retention_id = advanced_buffer_id("mouse-retention");
    let mut mouse_retention: i64 = ui.ctx().data_mut(|data| {
        *data.get_temp_mut_or_insert_with(mouse_retention_id, || {
            settings.mouse_move_retention_days as i64
        })
    });
    let mouse_chip = if mouse_retention == 0 {
        ("KEEP ALL".to_string(), false)
    } else {
        (format!("{mouse_retention} DAYS"), true)
    };
    control_row(
        ui,
        MOUSE_RETENTION_ROW_TITLE,
        Some((mouse_chip.0.as_str(), mouse_chip.1)),
        |ui, _label_id| {
            ui.horizontal(|ui| {
                let response = ui.add(
                    egui::DragValue::new(&mut mouse_retention)
                        .range(0..=3650)
                        .speed(1),
                );
                ui.label(RichText::new("days").color(theme::SILVER_DIM).size(12.5));
                if response.changed() {
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(mouse_retention_id, mouse_retention));
                    bump_advanced_buffer_revision(ui.ctx(), "mouse-retention");
                }
            });
            hint_line(ui, MOUSE_RETENTION_CAPTION);
        },
    );

    ui.add_space(4.0);
    let save_text = RichText::new(SAVE_SETTINGS_LABEL).size(11.5);
    let save_response = ui
        .add_enabled(disable_confirmed, egui::Button::new(save_text))
        .on_disabled_hover_text(SAVE_DISABLED_REASON);
    hint_line(ui, SAVE_SETTINGS_HINT);
    if save_response.clicked() {
        actions.push(PrivacyAction::SaveSettings {
            values: PrivacySettingsValues {
                sensitive_context_suppression: suppression,
                redact_titles_containing: titles.lines().map(str::to_string).collect(),
                redact_keys_containing: keys.lines().map(str::to_string).collect(),
                excluded_apps: excluded_apps.lines().map(str::to_string).collect(),
                title_retention_days: title_retention.max(0) as u64,
                mouse_move_retention_days: mouse_retention.max(0) as u64,
            },
            revisions: advanced_buffer_revisions(ui.ctx()),
        });
    }
}

fn delete_and_archive_section(
    ui: &mut egui::Ui,
    view: &PrivacyView<'_>,
    actions: &mut Vec<PrivacyAction>,
) {
    let snapshot = view.snapshot;
    section_kicker(ui, "DELETE DATA AND ARCHIVE HANDLING");
    notice_line(ui, view.prune_notice);

    // The days input owns its buffer after the first seed, like a Streamlit
    // widget holding session state.
    let days_id = prune_days_id();
    let mut days: i64 = ui
        .ctx()
        .data_mut(|data| *data.get_temp_mut_or_insert_with(days_id, || snapshot.prune_days));
    let preview_stale = days != snapshot.prune_days;
    let preview = snapshot.preview.filter(|_| !preview_stale);
    let total_rows = preview.map(|preview| preview.total_rows()).unwrap_or(0);
    let prune_chip = if preview_stale || preview.is_none() {
        ("…".to_string(), false)
    } else if total_rows == 0 {
        ("NONE".to_string(), false)
    } else {
        (format!("{} READY", thousands(total_rows as i64)), true)
    };
    control_row(
        ui,
        PRUNE_ROW_TITLE,
        Some((prune_chip.0.as_str(), prune_chip.1)),
        |ui, _label_id| {
            hint_line(ui, PRUNE_CAPTION);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(PRUNE_DAYS_LABEL)
                        .color(theme::SILVER_DIM)
                        .size(12.5),
                );
                let response = ui
                    .add(egui::DragValue::new(&mut days).range(1..=3650).speed(1))
                    .on_hover_text(PRUNE_DAYS_HELP);
                ui.label(RichText::new("days").color(theme::SILVER_DIM).size(12.5));
                if response.changed() {
                    ui.ctx().data_mut(|data| data.insert_temp(days_id, days));
                    actions.push(PrivacyAction::SetPruneDays(days));
                }
            });

            if let Some(error) = &snapshot.preview_error {
                ui.label(
                    RichText::new(format!(
                        "Gilbreth couldn't preview the delete right now. The database may be \
                         busy. Technical detail: {error}"
                    ))
                    .color(theme::RED)
                    .size(12.5),
                );
            }
            // The preview (counts and destructive cutoff) belongs to
            // `snapshot.prune_days`. While the live input disagrees, the
            // preview is stale: hide its counts, drop any armed
            // confirmation, and keep the delete inert so the visible days
            // and the executed cutoff can never split.
            let confirm_id = prune_confirm_id();
            let confirm_cleared_id = egui::Id::new("privacy-prune-confirm-cleared");
            if preview_stale {
                // UX-32: dropping an armed confirmation is announced, not
                // silent.
                let was_armed: bool = ui
                    .ctx()
                    .data_mut(|data| data.get_temp(confirm_id).unwrap_or(false));
                if was_armed {
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(confirm_cleared_id, true));
                }
                ui.ctx().data_mut(|data| data.remove::<bool>(confirm_id));
                caption(ui, UPDATING_PREVIEW_LABEL);
                let cleared: bool = ui
                    .ctx()
                    .data_mut(|data| data.get_temp(confirm_cleared_id).unwrap_or(false));
                if cleared {
                    caption(ui, CONFIRM_CLEARED_LABEL);
                }
            } else if preview.is_some() {
                ui.ctx()
                    .data_mut(|data| data.remove::<bool>(confirm_cleared_id));
                if total_rows == 0 {
                    caption(
                        ui,
                        &format!(
                            "Nothing to delete. Nothing stored is older than {} days.",
                            snapshot.prune_days
                        ),
                    );
                } else if let Some(preview) = &preview {
                    caption(ui, &prune_breakdown_caption(preview));
                }
            }

            // UXR-07: the shared confirm-then-act gate.
            if super::widgets::confirm_gate(
                ui,
                confirm_id,
                CONFIRM_PRUNE_LABEL,
                total_rows > 0,
                CONFIRM_DISABLED_REASON,
                PRUNE_BUTTON_LABEL,
                DELETE_DISABLED_REASON,
            ) {
                if let Some(preview) = &preview {
                    actions.push(PrivacyAction::PruneOldEvents {
                        cutoff_ms: preview.cutoff_ms,
                    });
                }
            }
        },
    );

    continuity_section(ui, snapshot);
    erase_block(ui);
    #[cfg(windows)]
    portable_archive_export_row(ui, view, actions);
}

/// Mirrors the Streamlit preview breakdown caption.
fn prune_breakdown_caption(preview: &PrunePreview) -> String {
    format!(
        "Activity events: {}; empty sessions: {}; recording steps: {}; empty recordings: {}; \
         expired record requests: {}; leftover recording data: {}.",
        preview.events,
        preview.ended_empty_sessions,
        preview.action_events,
        preview.ended_empty_record_sessions,
        preview.record_requests,
        preview.selector_paths
    )
}

/// DASH-05 in the register (charter §3): the discovery essay collapsed to
/// one paragraph behind a summary-carrying header — local counts and dates
/// only, stating the analysis consequence without discouraging a reset.
fn continuity_section(ui: &mut egui::Ui, snapshot: &PrivacySnapshot) {
    let Some(report) = &snapshot.continuity else {
        return;
    };
    let day_word = if report.active_days == 1 {
        "day"
    } else {
        "days"
    };
    let summary = format!(
        "{} active {day_word} retained • never blocks a delete",
        report.active_days
    );
    summary_section(
        ui,
        "privacy-continuity",
        CONTINUITY_TITLE,
        &summary,
        false,
        false,
        |ui| {
            caption(ui, &continuity_paragraph(report));
        },
    );
}

/// The one-paragraph advisor: rewind semantics, the two detector floors,
/// and this database's own counts.
fn continuity_paragraph(report: &crate::data::ContinuityReport) -> String {
    let span = match (&report.first_date, &report.last_date) {
        (Some(first), Some(last)) => format!(" ({first} to {last})"),
        _ => String::new(),
    };
    let archives = match report.archive_count {
        0 => "no archives".to_string(),
        1 => "1 archive".to_string(),
        count => format!("{count} archives"),
    };
    let day_word = if report.active_days == 1 {
        "day"
    } else {
        "days"
    };
    format!(
        "Deleting rewinds the history the pattern detectors draw on. It never breaks Gilbreth. \
         The floors: sequence and return patterns want {PATTERNS_HISTORY_FLOOR_DAYS} or more \
         active days, new-this-week flags want {CHANGED_THIS_WEEK_HISTORY_FLOOR_DAYS}. You have \
         {} active {day_word} recorded{span} and {archives} beside the live database.",
        report.active_days
    )
}

/// The erase facts at the point of action (charter §3): what each tray tool
/// does, stated plainly inside one red-hairline block.
fn erase_block(ui: &mut egui::Ui) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::RED_HAIRLINE))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(ERASE_BLOCK_TITLE)
                    .color(theme::RED)
                    .font(FontId::new(13.0, theme::family_medium())),
            );
            #[cfg(windows)]
            caption(ui, ARCHIVE_RESET_LINE);
            caption(ui, LEGACY_ARCHIVES_LINE);
            caption(ui, ERASE_ALL_LINE);
            hint_line(ui, SINGLE_ENTRIES_HINT);
        });
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(windows)]
enum PortableExportChoice {
    #[default]
    Passphrase,
    Plaintext,
}

#[cfg(windows)]
fn portable_archive_export_row(
    ui: &mut egui::Ui,
    view: &PrivacyView<'_>,
    actions: &mut Vec<PrivacyAction>,
) {
    let source_count = view.snapshot.portable_archive_sources.len();
    let chip = if source_count == 0 {
        ("NONE".to_string(), false)
    } else {
        let noun = if source_count == 1 {
            "ARCHIVE"
        } else {
            "ARCHIVES"
        };
        (format!("{source_count} {noun}"), true)
    };
    control_row(
        ui,
        PORTABLE_EXPORT_TITLE,
        Some((chip.0.as_str(), chip.1)),
        |ui, _label_id| {
            hint_line(ui, PORTABLE_EXPORT_CAPTION);
            notice_line(ui, view.portable_export_notice);
            if let Some(error) = &view.snapshot.portable_archive_error {
                super::widgets::flagged_line(
                    ui,
                    &format!("Couldn't list encrypted archives: {error}"),
                );
                return;
            }
            if view.snapshot.portable_archive_sources.is_empty() {
                caption(
                    ui,
                    "No encrypted archive is available yet. Use tray > Privacy > Archive and reset... first.",
                );
                return;
            }

            let source_id = egui::Id::new("privacy-portable-export-source");
            let mut selected: String = ui.ctx().data_mut(|data| {
                data.get_temp_mut_or_insert_with(source_id, || {
                    view.snapshot.portable_archive_sources[0].id.clone()
                })
                .clone()
            });
            if !view
                .snapshot
                .portable_archive_sources
                .iter()
                .any(|source| source.id == selected)
            {
                selected = view.snapshot.portable_archive_sources[0].id.clone();
            }
            let selected_label = view
                .snapshot
                .portable_archive_sources
                .iter()
                .find(|source| source.id == selected)
                .map(|source| source.label.as_str())
                .unwrap_or("Encrypted archive");
            egui::ComboBox::from_label("Archive to export")
                .selected_text(selected_label)
                .show_ui(ui, |ui| {
                    for source in &view.snapshot.portable_archive_sources {
                        ui.selectable_value(&mut selected, source.id.clone(), &source.label);
                    }
                });
            ui.ctx()
                .data_mut(|data| data.insert_temp(source_id, selected.clone()));

            let choice_id = egui::Id::new("privacy-portable-export-choice");
            let mut choice: PortableExportChoice = ui
                .ctx()
                .data_mut(|data| *data.get_temp_mut_or_default(choice_id));
            ui.radio_value(
                &mut choice,
                PortableExportChoice::Passphrase,
                "Passphrase-protected copy",
            );
            ui.radio_value(
                &mut choice,
                PortableExportChoice::Plaintext,
                "Plaintext copy (explicit choice)",
            );
            ui.ctx()
                .data_mut(|data| data.insert_temp(choice_id, choice));

            let mode = match choice {
                PortableExportChoice::Passphrase => {
                    let passphrase_id = egui::Id::new("privacy-portable-export-passphrase");
                    let confirm_id = egui::Id::new("privacy-portable-export-passphrase-confirm");
                    let mut passphrase: String = ui.ctx().data_mut(|data| {
                        data.get_temp_mut_or_default::<String>(passphrase_id)
                            .clone()
                    });
                    let mut confirmation: String = ui.ctx().data_mut(|data| {
                        data.get_temp_mut_or_default::<String>(confirm_id).clone()
                    });
                    ui.label("Passphrase");
                    ui.add(egui::TextEdit::singleline(&mut passphrase).password(true));
                    ui.label("Confirm passphrase");
                    ui.add(egui::TextEdit::singleline(&mut confirmation).password(true));
                    ui.ctx().data_mut(|data| {
                        data.insert_temp(passphrase_id, passphrase.clone());
                        data.insert_temp(confirm_id, confirmation.clone());
                    });
                    if passphrase.is_empty() || passphrase != confirmation {
                        None
                    } else {
                        Some(PortableArchiveExportMode::Passphrase(passphrase))
                    }
                }
                PortableExportChoice::Plaintext => {
                    super::widgets::flagged_line(ui, PLAINTEXT_EXPORT_WARNING);
                    let acknowledge_id = egui::Id::new("privacy-portable-export-plaintext-ack");
                    let mut acknowledged: bool = ui
                        .ctx()
                        .data_mut(|data| *data.get_temp_mut_or_default::<bool>(acknowledge_id));
                    ui.checkbox(
                        &mut acknowledged,
                        "I understand this copy is a full plaintext activity database",
                    );
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(acknowledge_id, acknowledged));
                    acknowledged.then_some(PortableArchiveExportMode::PlaintextAcknowledged)
                }
            };

            let button = ui.add_enabled(
                mode.is_some(),
                egui::Button::new("Export archive to Downloads"),
            );
            if button.clicked() {
                actions.push(PrivacyAction::ExportPortableArchive {
                    source_id: selected,
                    mode: mode.expect("enabled export has a validated mode"),
                });
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::ContinuityReport;

    #[test]
    fn continuity_paragraph_states_floors_counts_and_archives() {
        let report = ContinuityReport {
            active_days: 34,
            pre_week_focus_days: 27,
            weekday_label: "Wednesday".to_string(),
            same_weekday_days: 5,
            first_date: Some("2026-06-05".to_string()),
            last_date: Some("2026-07-09".to_string()),
            archive_count: 2,
        };
        assert_eq!(
            continuity_paragraph(&report),
            "Deleting rewinds the history the pattern detectors draw on. It never breaks \
             Gilbreth. The floors: sequence and return patterns want 2 or more active days, \
             new-this-week flags want 14. You have 34 active days recorded (2026-06-05 to \
             2026-07-09) and 2 archives beside the live database."
        );
        let sparse = ContinuityReport {
            active_days: 1,
            pre_week_focus_days: 0,
            weekday_label: "Monday".to_string(),
            same_weekday_days: 1,
            first_date: None,
            last_date: None,
            archive_count: 0,
        };
        assert_eq!(
            continuity_paragraph(&sparse),
            "Deleting rewinds the history the pattern detectors draw on. It never breaks \
             Gilbreth. The floors: sequence and return patterns want 2 or more active days, \
             new-this-week flags want 14. You have 1 active day recorded and no archives \
             beside the live database."
        );
    }

    #[test]
    fn suppression_copy_names_this_platforms_tokens() {
        #[cfg(windows)]
        {
            assert!(SUPPRESSION_CAPTION.contains("Windows session"));
            assert!(SUPPRESSION_CAPTION.contains("Secure Desktop"));
        }
        #[cfg(not(windows))]
        {
            assert!(SUPPRESSION_CAPTION.contains("login session"));
            assert!(SUPPRESSION_CAPTION.contains("macOS secure input"));
            assert!(!SUPPRESSION_CAPTION.contains("Windows"));
            assert!(!SUPPRESSION_OFF_WARNING.contains("Secure Desktop"));
        }
    }
}
