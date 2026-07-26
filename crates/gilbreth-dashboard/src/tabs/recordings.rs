//! The Recordings tab in the instrument register (slice 3 of the dashboard
//! register program, charter: the recorded redesign,
//! direction A "Lead with the job").
//!
//! The tab opens with why-you'd-bother (the three-leg journey: record it by
//! hand once, read the step map, ask your own AI), lists routines with
//! readiness dots, rewrites the replay verdict in product voice, and
//! promotes the already-shipping Agent handoff export to the primary action
//! zone with the copyable analysis prompt. Engineering internals live in
//! one expander; delete is a quiet footer. Exports stay local files
//! (M5b Phase 3, DECIDED-3.6: zero network).

use std::collections::HashMap;

use egui::{Color32, CornerRadius, FontId, Margin, RichText, Sense, Stroke, Vec2};
use gilbreth_read::{
    RecordingRow, RecordingStep, ReplayExportVerdict, REPLAY_EXPORT_REVIEW_LABEL_MAX_CHARS,
};

use super::widgets::{caption, confirm_gate, explainer, gauge_tiles, info_box, section_kicker};
use crate::data::RecordingsSnapshot;
use crate::format::format_duration_ms;
use crate::format::MISSING_VALUE_CELL;
use crate::theme;

pub const TABLES_MISSING_INFO: &str = "Record Routine recordings are not present in this database.";

// The three-leg journey (charter §1): why you'd record a routine, in
// product voice. The privacy line is demoted to a supporting line, meaning
// kept verbatim (a factual enumeration, per the recorded exception).
pub const JOURNEY_RECORD_KICKER: &str = "1 • RECORD";
pub const JOURNEY_RECORD_TITLE: &str = "Do it by hand, once";
pub const JOURNEY_RECORD_BODY: &str = "From the tray: Record this routine. Gilbreth writes down \
     every step: element structure and action types, never your content.";
pub const JOURNEY_REVIEW_KICKER: &str = "2 • REVIEW";
pub const JOURNEY_REVIEW_TITLE: &str = "Read the step map";
pub const JOURNEY_REVIEW_BODY: &str = "See what the routine actually is: the controls it \
     touches and where the time goes. Name it, keep it.";
pub const JOURNEY_ANALYZE_KICKER: &str = "3 • ANALYZE";
pub const JOURNEY_ANALYZE_TITLE: &str = "Ask your own AI";
pub const JOURNEY_ANALYZE_BODY: &str = "Export the value-free trace and hand it to the \
     assistant you already use. Gilbreth emits a file and stops. Nothing leaves this machine \
     unless you move it.";
pub const PRIVACY_LINE: &str = "Recordings store structural action metadata only: no typed \
     text, field values, or window titles.";

pub const SELECT_RECORDING_CAPTION: &str =
    "Select a recording to review its steps and delete controls.";
pub const REPLAY_READINESS_CAPTION: &str = "Replay readiness uses only value-free framework \
     class, trust basis, action type, pattern action, and selector presence. Agent handoff \
     export is always available; native automation blueprints require verified \
     replay-readiness.";
pub const HOW_JUDGED_TITLE: &str = "How replay readiness is judged";
pub const STEPS_VALUE_FREE_CAPTION: &str = "Steps show element structure and action type only. \
     No typed text, field values, or element names are stored.";
pub const NO_STEPS_INFO: &str = "No action steps were stored for this recording.";
pub const ENGINEERING_DETAIL_TITLE: &str = "Engineering details";
pub const ENGINEERING_DETAIL_SUMMARY: &str = "selectors • frameworks • trust basis • pattern \
     actions • coverage";
pub const LABELS_EXPANDER_TITLE: &str = "Optional export labels";
pub const LABELS_CAPTION: &str = "Add human review labels only if you want them in downloaded \
     exports. Gilbreth does not infer these from captured content and does not store them in \
     the database.";
pub const LABEL_PLACEHOLDER: &str = "Optional human label for this export";
pub const CAPTURE_CONTEXT_TITLE: &str = "Capture context";
pub const NO_POLICY_SNAPSHOT_CAPTION: &str = "No policy snapshot stored.";
pub const OPEN_RECORDING_INFO: &str =
    "This recording is still open. Stop it from the Gilbreth tray.";

// The export kit (charter §4): the tab's purpose, promoted to the primary
// action zone directly under the verdict.
pub const KIT_TITLE: &str = "Take it to your assistant";
pub const KIT_BODY: &str = "The trace is a value-free JSON file. Your AI can read the shape of \
     the routine without ever seeing what you typed. Ask it what's worth automating.";
pub const EXPORT_AGENT_BUTTON: &str = "Export trace for AI analysis";
pub const EXPORT_AGENT_HELP: &str = "Local JSON download only.";
pub const EXPORT_CAPTION: &str = "Agent handoff traces are value-free step guides an agent can \
     follow. They contain apps, action types, order, relative timing, value-free selector \
     hints, blank input slots, and any labels you typed above; native replay remains gated \
     separately.";
pub const EXPORT_CONTENTS_TITLE: &str = "What an agent handoff trace contains";
pub const COPY_PROMPT_BUTTON: &str = "Copy analysis prompt";
pub const PROMPT_COPIED_CAPTION: &str = "Prompt copied to the clipboard.";
pub const PROMPT_PREVIEW_KICKER: &str = "THE PROMPT THAT SHIPS WITH IT";
/// The canonical analysis prompt (charter, owner-decided with direction A):
/// static copy, zero network, DECIDED-3.6 compatible. Copy-pinned like the
/// consent copy.
pub const ANALYSIS_PROMPT: &str = "This file is a value-free trace of a routine I did by hand. \
     It holds element structure and action types, no content. Find the automation \
     opportunities: repeated sequences, predictable navigation, waits between steps. Suggest \
     the top three automations. For each, say what it replaces and what a safe first attempt \
     looks like.";
pub const NATIVE_EXPORT_GATE_CAPTION: &str = "Native automation blueprint export appears only \
     after this recording passes verified native replay-readiness.";
// copy-allow: em-dash prose em dash within the one-per-string cap (the one-per-string cap), recorded by the Lane B audit
pub const NATIVE_EXPORT_CAPTION: &str = "Native automation blueprints add selector-backed \
     native UI steps for verified recordings — scaffolding for a future replay/export tool.";
pub const EXPORT_NATIVE_BUTTON: &str = "Export native automation blueprint";
pub const EXPORT_NATIVE_HELP: &str = "Local JSON download only. Selector blocks are included \
     only for D5-eligible native steps.";

/// Charter §6: delete demoted to a quiet footer; the honest
/// not-a-secure-erase sentence kept verbatim.
pub const DELETE_SECTION_CAPTION: &str = "Deletes this recording and its steps from the local \
     database, but is not a secure erase. Use the Gilbreth tray Privacy menu for archive/reset \
     or secure erase.";
pub const CONFIRM_DELETE_LABEL: &str = "Confirm deletion";
pub const DELETE_BUTTON_LABEL: &str = "Delete recording";
pub const DELETE_DISABLED_REASON: &str = "Tick Confirm deletion to enable.";

// The empty state as the pitch (charter §7): the first encounter is where
// the why matters most.
pub const EMPTY_PITCH_TITLE: &str = "Turn a chore into a checklist for your AI";
pub const EMPTY_PITCH_BODY: &str = "Some part of your day is a routine you could describe in \
     your sleep. Record it once. Gilbreth writes down the steps (structure only, never your \
     content), and you get a file your own AI can read to tell you what's worth automating.";
pub const HOW_TO_RECORD_LEAD: &str = "To record a routine:";
pub const HOW_TO_RECORD_BULLETS: [&str; 2] = [
    "Right-click the Gilbreth tray icon and choose Record Routine..., or",
    "Use Ask tray to record this routine on a routine candidate in the Analytics tab.",
];
pub const HOW_RECORDING_STARTS: &str = "The tray always asks before recording starts, and a \
     visible indicator stays on while it runs. Finished recordings appear here for review, \
     export, or deletion.";

/// What the Recordings tab asks the shell to do. Selection changes queue a
/// fresh read; exports and deletes go through the host callbacks. The
/// analysis-prompt copy is clipboard-local and never leaves the tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordingsAction {
    Select(i64),
    ExportAgentHandoff {
        record_session_id: i64,
        labels: HashMap<i64, String>,
    },
    ExportNativeBlueprint {
        record_session_id: i64,
        labels: HashMap<i64, String>,
    },
    Delete(i64),
}

/// Cross-frame state the shell owns for this tab.
pub struct RecordingsView<'a> {
    pub snapshot: &'a RecordingsSnapshot,
    /// One-shot export/delete notice: (is_error, message).
    pub notice: Option<&'a (bool, String)>,
}

/// The delete-confirm checkbox state for one recording, so the shell can
/// reset it after a successful delete (Streamlit's `reset_confirmation`).
pub fn delete_confirm_id(record_session_id: i64) -> egui::Id {
    egui::Id::new(("recording-delete-confirm", record_session_id))
}

fn label_buffer_id(record_session_id: i64, seq: i64) -> egui::Id {
    egui::Id::new(("recording-export-label", record_session_id, seq))
}

fn prompt_copied_id() -> egui::Id {
    egui::Id::new("recording-prompt-copied")
}

/// Mirrors `optional_text`: trimmed text or None.
fn optional_text(value: Option<&str>) -> Option<&str> {
    let text = value?.trim();
    (!text.is_empty()).then_some(text)
}

fn dash_cell(value: Option<&str>) -> String {
    optional_text(value)
        .unwrap_or(MISSING_VALUE_CELL)
        .to_string()
}

pub fn show(ui: &mut egui::Ui, view: &RecordingsView<'_>) -> Vec<RecordingsAction> {
    let mut actions = Vec::new();
    let snapshot = view.snapshot;
    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
        return actions;
    }
    if !snapshot.tables_present {
        info_box(ui, TABLES_MISSING_INFO);
        return actions;
    }
    if snapshot.rows.is_empty() {
        empty_pitch(ui);
        return actions;
    }

    journey_strip(ui);
    caption(ui, PRIVACY_LINE);
    section_kicker(ui, "ROUTINES");
    routine_list(ui, snapshot, &mut actions);

    // UX-15: with a recording selected, the export/delete outcome renders
    // beside its triggers in the detail pane instead of far above them.
    let Some(selected_id) = snapshot.selected_id else {
        if let Some((is_error, message)) = view.notice {
            ui.add_space(4.0);
            super::widgets::outcome_notice(ui, *is_error, message);
        }
        ui.add_space(4.0);
        caption(ui, SELECT_RECORDING_CAPTION);
        return actions;
    };
    if let Some(recording) = snapshot
        .rows
        .iter()
        .find(|row| row.record_session_id == selected_id)
    {
        detail_section(ui, view, snapshot, recording, &mut actions);
    }
    actions
}

/// The first-encounter pitch (charter §7).
fn empty_pitch(ui: &mut egui::Ui) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x3A, 0x3F, 0x47)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(EMPTY_PITCH_TITLE)
                    .color(theme::SILVER)
                    .font(theme::heading_card()),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(EMPTY_PITCH_BODY)
                    .color(theme::SILVER_DIM)
                    .size(13.0),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(HOW_TO_RECORD_LEAD)
                    .color(theme::SILVER_DIM)
                    .size(13.0),
            );
            super::widgets::bullet_list(ui, &HOW_TO_RECORD_BULLETS);
            ui.add_space(4.0);
            ui.label(
                RichText::new(HOW_RECORDING_STARTS)
                    .color(theme::SILVER_DIM)
                    .size(13.0),
            );
        });
}

/// The three-leg journey strip (charter §1).
fn journey_strip(ui: &mut egui::Ui) {
    let legs: [(&str, &str, &str); 3] = [
        (
            JOURNEY_RECORD_KICKER,
            JOURNEY_RECORD_TITLE,
            JOURNEY_RECORD_BODY,
        ),
        (
            JOURNEY_REVIEW_KICKER,
            JOURNEY_REVIEW_TITLE,
            JOURNEY_REVIEW_BODY,
        ),
        (
            JOURNEY_ANALYZE_KICKER,
            JOURNEY_ANALYZE_TITLE,
            JOURNEY_ANALYZE_BODY,
        ),
    ];
    ui.columns(3, |columns| {
        for (column, (kicker, title, body)) in columns.iter_mut().zip(legs) {
            egui::Frame::default()
                .fill(theme::WELL)
                .stroke(Stroke::new(1.0, theme::BELLOWS))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::symmetric(14, 12))
                .show(column, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(kicker)
                            .color(theme::BRASS)
                            .font(FontId::new(11.0, egui::FontFamily::Monospace)),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(title)
                            .color(theme::SILVER)
                            .font(FontId::new(13.0, theme::family_medium())),
                    );
                    ui.label(RichText::new(body).color(theme::GRAY).size(12.0));
                });
        }
    });
}

/// One routine row's story line: steps and duration, or the live marker.
fn routine_meta(row: &RecordingRow) -> String {
    if row.ended_ts.is_none() {
        format!("recording now • {}", format_duration_ms(row.duration_ms))
    } else {
        let noun = if row.action_count == 1 {
            "step"
        } else {
            "steps"
        };
        format!(
            "{} {noun} • {}",
            row.action_count,
            format_duration_ms(row.duration_ms)
        )
    }
}

/// The routine's display name; an untitled recording keeps its id (the em
/// dash is the null marker, data notation rather than prose).
fn routine_name(row: &RecordingRow) -> String {
    routine_display_name(row.title.as_deref(), row.record_session_id)
}

/// The untitled fallback (pure; the copy audit exercises it). The em
/// dash is the null marker, data notation rather than prose.
fn routine_display_name(title: Option<&str>, record_session_id: i64) -> String {
    match optional_text(title) {
        Some(title) => title.to_string(),
        // copy-allow: em-dash null-title data notation (Lane B seeded exception)
        None => format!("Recording {record_session_id} — untitled"),
    }
}

/// The routine list with readiness dots (charter §2): brass = ended and
/// reviewable; the single amber dot = recording now, the tray indicator's
/// own semantic and the one amber moment this view is allowed.
fn routine_list(
    ui: &mut egui::Ui,
    snapshot: &RecordingsSnapshot,
    actions: &mut Vec<RecordingsAction>,
) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(4, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for row in &snapshot.rows {
                let selected = snapshot.selected_id == Some(row.record_session_id);
                let response = ui
                    .scope(|ui| {
                        ui.style_mut().interaction.selectable_labels = false;
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            let (dot_rect, _) =
                                ui.allocate_exact_size(egui::vec2(10.0, 16.0), Sense::hover());
                            let color = if row.ended_ts.is_none() {
                                theme::AMBER
                            } else {
                                theme::BRASS
                            };
                            ui.painter().circle_filled(dot_rect.center(), 3.5, color);
                            ui.label(
                                RichText::new(routine_name(row))
                                    .color(theme::SILVER)
                                    .size(12.5),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(dash_cell(
                                            row.started_at
                                                .as_deref()
                                                .and_then(|at| at.split_whitespace().next()),
                                        ))
                                        .color(theme::GRAY)
                                        .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                                    );
                                    ui.label(
                                        RichText::new(routine_meta(row))
                                            .color(theme::GRAY)
                                            .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                                    );
                                },
                            );
                        });
                    })
                    .response;
                let row_rect = response.rect.expand2(Vec2::new(6.0, 3.0));
                let row_response = ui.interact(
                    row_rect,
                    ui.id().with(("recording-row", row.record_session_id)),
                    Sense::click(),
                );
                if row_response.clicked() {
                    actions.push(RecordingsAction::Select(row.record_session_id));
                }
                if selected {
                    ui.painter()
                        .rect_filled(row_rect, 3.0, theme::BRASS.gamma_multiply(0.12));
                } else if row_response.hovered() {
                    ui.painter()
                        .rect_filled(row_rect, 3.0, Color32::from_white_alpha(5));
                }
            }
        });
}

/// The recording's operational facts in one quiet line: timestamps, stop
/// reason, and request lineage, dashes for the parts a row lacks.
fn recording_meta_line(recording: &RecordingRow) -> String {
    let mut parts = vec![format!(
        "{} to {}",
        dash_cell(recording.started_at.as_deref()),
        dash_cell(recording.ended_at.as_deref())
    )];
    parts.push(recording.stop_reason_label.clone());
    if let Some(status) = optional_text(recording.request_status.as_deref()) {
        parts.push(format!("request {status}"));
    }
    parts.join(" • ")
}

fn detail_section(
    ui: &mut egui::Ui,
    view: &RecordingsView<'_>,
    snapshot: &RecordingsSnapshot,
    recording: &RecordingRow,
    actions: &mut Vec<RecordingsAction>,
) {
    ui.add_space(10.0);
    let heading = match optional_text(recording.title.as_deref()) {
        Some(title) => format!("Recording {}: {}", recording.record_session_id, title),
        None => format!("Recording {}", recording.record_session_id),
    };
    ui.label(
        RichText::new(heading)
            .color(theme::SILVER)
            // UX-19: card-level headings share one size.
            .font(theme::heading_card()),
    );
    caption(ui, &recording_meta_line(recording));

    if let Some(error) = &snapshot.detail_error {
        // Branch review (UX-15): an export/delete outcome must not be
        // swallowed by an unrelated detail-read error.
        if let Some((is_error, message)) = view.notice {
            ui.add_space(4.0);
            super::widgets::outcome_notice(ui, *is_error, message);
        }
        ui.label(RichText::new(error).color(theme::RED));
        return;
    }
    let Some(detail) = &snapshot.detail else {
        return;
    };

    ui.add_space(6.0);
    verdict_banner(ui, &detail.verdict);
    explainer(ui, HOW_JUDGED_TITLE, |ui| {
        caption(ui, REPLAY_READINESS_CAPTION);
    });
    ui.add_space(4.0);
    detail_gauges(ui, recording, &detail.steps);

    if recording.ended_ts.is_none() {
        ui.add_space(4.0);
        info_box(ui, OPEN_RECORDING_INFO);
        if detail.steps.is_empty() {
            info_box(ui, NO_STEPS_INFO);
        } else {
            steps_story_table(ui, &detail.steps);
            caption(ui, STEPS_VALUE_FREE_CAPTION);
        }
        return;
    }

    // UX-15: the outcome lands where the user is looking — beside the
    // export controls that produced it.
    if let Some((is_error, message)) = view.notice {
        ui.add_space(4.0);
        super::widgets::outcome_notice(ui, *is_error, message);
    }
    if !detail.steps.is_empty() {
        export_labels_expander(ui, recording.record_session_id, &detail.steps);
    }
    export_kit(
        ui,
        recording,
        &detail.steps,
        detail.verdict.export_available,
        actions,
    );

    ui.add_space(4.0);
    if detail.steps.is_empty() {
        info_box(ui, NO_STEPS_INFO);
    } else {
        steps_story_table(ui, &detail.steps);
        caption(ui, STEPS_VALUE_FREE_CAPTION);
        engineering_detail_expander(ui, &detail.steps);
    }
    capture_context_expander(ui, recording);
    delete_footer(ui, recording.record_session_id, actions);
}

/// The verdict in product voice, composed from the verdict's own counts
/// (UXR-06: one match on the state). Two-level language: brass tick for the
/// verified pass, brass ⚠ for attention, quiet info otherwise.
fn verdict_banner(ui: &mut egui::Ui, verdict: &ReplayExportVerdict) {
    let replay_eligible = verdict.native_eligible_steps + verdict.provisional_steps;
    let gaps_phrase = match verdict.native_gap_steps {
        0 => "no unknown or missing-selector gaps".to_string(),
        1 => "1 unknown or missing-selector gap".to_string(),
        count => format!("{count} unknown or missing-selector gaps"),
    };
    let (glyph, lead, subline): (Option<&str>, String, String) = match verdict.state.as_str() {
        "verified_replay_eligible" => (
            Some("✓"),
            // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
            "Replayable — every actionable step maps to a named control.".to_string(),
            format!(
                "{replay_eligible} of {} actionable steps native-eligible • {gaps_phrase}",
                verdict.actionable_steps
            ),
        ),
        "replay_eligible_unverified" => (
            Some("⚠"),
            "Replay-eligible, not yet verified on this install.".to_string(),
            format!(
                "{replay_eligible} of {} actionable steps native-eligible • {gaps_phrase} • \
                 native replay stays off until this install verifies its allowlist",
                verdict.actionable_steps
            ),
        ),
        "replay_eligible_provisional" => (
            Some("⚠"),
            "Replay-eligible in principle, not yet volume-validated.".to_string(),
            format!(
                "{replay_eligible} of {} actionable steps native-eligible or provisional • \
                 {gaps_phrase}",
                verdict.actionable_steps
            ),
        ),
        _ => (
            None,
            "Agent-grounded: captured for an agent to follow, not for native replay.".to_string(),
            if verdict.actionable_steps == 0 {
                "no actionable steps classified".to_string()
            } else if verdict.hard_veto_steps > 0 {
                format!(
                    "{} web or virtualized steps among {} actionable",
                    verdict.hard_veto_steps, verdict.actionable_steps
                )
            } else {
                format!(
                    "{replay_eligible} of {} actionable steps native-eligible • {gaps_phrase}",
                    verdict.actionable_steps
                )
            },
        ),
    };
    egui::Frame::default()
        .fill(theme::WELL)
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                if let Some(glyph) = glyph {
                    ui.label(
                        RichText::new(glyph)
                            .color(theme::BRASS)
                            .font(FontId::new(14.0, egui::FontFamily::Monospace)),
                    );
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new(lead).color(theme::SILVER).size(13.5));
                    ui.label(RichText::new(subline).color(theme::GRAY).size(11.5));
                });
            });
        });
}

/// One gauge row for the selected routine: steps, duration, distinct
/// controls, and free-input steps (charter's card set).
fn detail_gauges(ui: &mut egui::Ui, recording: &RecordingRow, steps: &[RecordingStep]) {
    let distinct_elements = steps
        .iter()
        .filter_map(|step| step.selector_id)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let free_input = steps
        .iter()
        .filter(|step| step.coverage == "free input (value-free)")
        .count();
    let gauges: [(&str, String); 4] = [
        ("Steps", recording.action_count.to_string()),
        ("Duration", format_duration_ms(recording.duration_ms)),
        ("Controls touched", distinct_elements.to_string()),
        ("Free-input steps", free_input.to_string()),
    ];
    gauge_tiles(ui, &gauges);
}

/// The primary action zone (charter §4): a brass-framed kit with the trace
/// export, the copyable analysis prompt, and the blueprint as a quiet
/// third. The prompt preview keeps the shipped copy visible.
fn export_kit(
    ui: &mut egui::Ui,
    recording: &RecordingRow,
    steps: &[RecordingStep],
    export_available: bool,
    actions: &mut Vec<RecordingsAction>,
) {
    let record_session_id = recording.record_session_id;
    egui::Frame::default()
        .fill(theme::BRASS_WELL)
        .stroke(Stroke::new(1.0, theme::BRASS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(16, 13))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(KIT_TITLE)
                    .color(theme::SILVER)
                    .font(theme::heading_card()),
            );
            ui.label(RichText::new(KIT_BODY).color(theme::GRAY).size(12.5));
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add(egui::Button::new(
                        RichText::new(EXPORT_AGENT_BUTTON)
                            .color(theme::BRASS_ON_CARD)
                            .size(12.0),
                    ))
                    .on_hover_text(EXPORT_AGENT_HELP)
                    .clicked()
                {
                    actions.push(RecordingsAction::ExportAgentHandoff {
                        record_session_id,
                        labels: collect_export_labels(ui, record_session_id, steps),
                    });
                }
                if ui
                    .add(egui::Button::new(
                        RichText::new(COPY_PROMPT_BUTTON).size(12.0),
                    ))
                    .clicked()
                {
                    ui.ctx().copy_text(ANALYSIS_PROMPT.to_string());
                    ui.ctx()
                        .data_mut(|data| data.insert_temp(prompt_copied_id(), true));
                }
                if export_available
                    && ui
                        .add(egui::Button::new(
                            RichText::new(EXPORT_NATIVE_BUTTON).size(12.0),
                        ))
                        .on_hover_text(EXPORT_NATIVE_HELP)
                        .clicked()
                {
                    actions.push(RecordingsAction::ExportNativeBlueprint {
                        record_session_id,
                        labels: collect_export_labels(ui, record_session_id, steps),
                    });
                }
            });
            let copied: bool = ui
                .ctx()
                .data_mut(|data| data.get_temp(prompt_copied_id()).unwrap_or(false));
            if copied {
                caption(ui, PROMPT_COPIED_CAPTION);
            }
            ui.add_space(6.0);
            egui::Frame::default()
                .fill(theme::DARKROOM)
                .stroke(Stroke::new(1.0, theme::BELLOWS))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(PROMPT_PREVIEW_KICKER)
                            .color(theme::BRASS)
                            .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                    );
                    ui.add_space(2.0);
                    // The shipped prompt renders in the body face: mono is
                    // punctuation, not paragraphs.
                    ui.label(RichText::new(ANALYSIS_PROMPT).color(theme::GRAY).size(12.0));
                });
            explainer(ui, EXPORT_CONTENTS_TITLE, |ui| {
                caption(ui, EXPORT_CAPTION);
            });
            if !export_available {
                caption(ui, NATIVE_EXPORT_GATE_CAPTION);
            } else {
                caption(ui, NATIVE_EXPORT_CAPTION);
            }
        });
}

/// The step's story in product voice: what happened, from the value-free
/// action and pattern metadata.
fn step_story(step: &RecordingStep) -> String {
    match (step.action_type.as_str(), step.pattern_action.as_deref()) {
        ("ui_action", Some("invoke")) => "Pressed a button".to_string(),
        ("ui_action", Some("toggle")) => "Toggled a control".to_string(),
        ("ui_action", Some("expand_collapse")) => "Expanded or collapsed a control".to_string(),
        ("ui_action", Some("select")) => "Selected an item".to_string(),
        ("ui_action", Some(other)) => format!("Used a control ({other})"),
        ("ui_action", None) => "Used a control".to_string(),
        ("edit_committed", _) => "Typed into a field (content not stored)".to_string(),
        ("ui_action_other", _) => "Interacted with an unmapped element".to_string(),
        (other, _) => other.to_string(),
    }
}

/// Where the step happened: the app, plus whether the control is named.
fn step_where(step: &RecordingStep) -> String {
    let app = dash_cell(step.exe.as_deref());
    if step.selector_id.is_some() {
        format!("{app} • named control")
    } else {
        app
    }
}

/// The step's confidence chip: facts about a step, not failures.
fn step_confidence(step: &RecordingStep) -> (&'static str, bool) {
    match step.coverage.as_str() {
        "structurally observed" => ("REPLAYABLE", true),
        "free input (value-free)" => ("FREE INPUT", false),
        _ => ("UNMAPPED", false),
    }
}

/// UX-26: a several-hundred-step recording scrolls inside a bounded
/// region; UXR-15: rows are virtualized, so only the visible slice builds.
const STEPS_MAX_HEIGHT: f32 = 360.0;
const STEP_ROW_HEIGHT: f32 = 26.0;

/// The humanized steps table (charter §5): # • When • What happened •
/// Where • Confidence.
fn steps_story_table(ui: &mut egui::Ui, steps: &[RecordingStep]) {
    ui.add_space(2.0);
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new("recording-steps-header")
                .spacing(egui::vec2(18.0, 4.0))
                .min_col_width(40.0)
                .show(ui, |ui| {
                    for header in ["#", "When", "What happened", "Where", "Confidence"] {
                        ui.label(
                            RichText::new(header)
                                .color(theme::GRAY)
                                .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                        );
                    }
                    ui.end_row();
                });
            egui::ScrollArea::vertical()
                .id_salt("recording-steps-scroll")
                .max_height(STEPS_MAX_HEIGHT)
                .auto_shrink([false, true])
                .show_rows(ui, STEP_ROW_HEIGHT, steps.len(), |ui, range| {
                    egui::Grid::new("recording-steps")
                        .spacing(egui::vec2(18.0, 4.0))
                        .min_col_width(40.0)
                        .start_row(range.start)
                        .show(ui, |ui| {
                            for step in &steps[range] {
                                ui.label(
                                    RichText::new(step.seq.to_string())
                                        .color(theme::SILVER_DIM)
                                        .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                                );
                                let when = step
                                    .captured_at
                                    .as_deref()
                                    .and_then(|at| at.split_whitespace().nth(1))
                                    .map(str::to_string)
                                    .unwrap_or_else(|| MISSING_VALUE_CELL.to_string());
                                ui.label(
                                    RichText::new(when)
                                        .color(theme::SILVER_DIM)
                                        .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                                );
                                ui.label(
                                    RichText::new(step_story(step))
                                        .color(theme::SILVER)
                                        .size(12.5),
                                );
                                ui.label(
                                    RichText::new(step_where(step))
                                        .color(theme::SILVER_DIM)
                                        .size(12.0),
                                );
                                let (chip, on) = step_confidence(step);
                                super::widgets::state_chip(ui, chip, on);
                                ui.end_row();
                            }
                        });
                });
        });
}

/// All engineering columns in one expander (charter §5): the full
/// value-free metadata table, unchanged vocabulary.
fn engineering_detail_expander(ui: &mut egui::Ui, steps: &[RecordingStep]) {
    explainer(ui, ENGINEERING_DETAIL_TITLE, |ui| {
        caption(ui, ENGINEERING_DETAIL_SUMMARY);
        let rows: Vec<Vec<String>> = steps
            .iter()
            .map(|step| {
                vec![
                    step.seq.to_string(),
                    dash_cell(step.captured_at.as_deref()),
                    step.action_type.clone(),
                    dash_cell(step.pattern_action.as_deref()),
                    step.selector.clone(),
                    step.framework_class.clone(),
                    step.trust_basis.clone(),
                    dash_cell(step.exe.as_deref()),
                    step.is_sensitive.to_string(),
                    step.coverage.clone(),
                ]
            })
            .collect();
        egui::ScrollArea::vertical()
            .id_salt("recording-steps-engineering")
            .max_height(STEPS_MAX_HEIGHT)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                super::widgets::data_table(
                    ui,
                    "recording-steps-detail",
                    &[
                        "Step",
                        "Captured",
                        "Action",
                        "Pattern action",
                        "Selector",
                        "Framework",
                        "Trust basis",
                        "App",
                        "Sensitive",
                        "Coverage",
                    ],
                    &rows,
                );
            });
    });
}

/// Mirrors `render_recording_export_label_inputs`; buffers live in egui
/// temp memory so typed labels survive expander collapse, like Streamlit
/// session state.
fn export_labels_expander(ui: &mut egui::Ui, record_session_id: i64, steps: &[RecordingStep]) {
    explainer(ui, LABELS_EXPANDER_TITLE, |ui| {
        caption(ui, LABELS_CAPTION);
        // UX-26: bounded like the step list.
        egui::ScrollArea::vertical()
            .id_salt("recording-labels-scroll")
            .max_height(STEPS_MAX_HEIGHT)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for step in steps {
                    let id = label_buffer_id(record_session_id, step.seq);
                    let mut value: String = ui
                        .ctx()
                        .data_mut(|data| data.get_temp(id).unwrap_or_default());
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Step {} label", step.seq))
                                .color(theme::GRAY)
                                .size(11.5),
                        );
                        // UX-23: egui does not clamp desired_width, so cap it to
                        // what the row actually has.
                        let edit = egui::TextEdit::singleline(&mut value)
                            .char_limit(REPLAY_EXPORT_REVIEW_LABEL_MAX_CHARS)
                            .hint_text(LABEL_PLACEHOLDER)
                            .desired_width(340.0_f32.min(ui.available_width().max(120.0)));
                        if ui.add(edit).changed() {
                            ui.ctx()
                                .data_mut(|data| data.insert_temp(id, value.clone()));
                        }
                    });
                }
            });
    });
}

/// The labels typed for this recording's steps, whether or not the expander
/// is currently open (Streamlit keeps collapsed inputs in session state).
fn collect_export_labels(
    ui: &egui::Ui,
    record_session_id: i64,
    steps: &[RecordingStep],
) -> HashMap<i64, String> {
    let mut labels = HashMap::new();
    ui.ctx().data_mut(|data| {
        for step in steps {
            let value: String = data
                .get_temp(label_buffer_id(record_session_id, step.seq))
                .unwrap_or_default();
            if !value.trim().is_empty() {
                labels.insert(step.seq, value);
            }
        }
    });
    labels
}

fn capture_context_expander(ui: &mut egui::Ui, recording: &RecordingRow) {
    explainer(ui, CAPTURE_CONTEXT_TITLE, |ui| {
        let raw = recording.policy_snapshot_json.trim();
        if raw.is_empty() {
            caption(ui, NO_POLICY_SNAPSHOT_CAPTION);
            return;
        }
        let pretty = serde_json::from_str::<serde_json::Value>(raw)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .unwrap_or_else(|_| raw.to_string());
        ui.label(
            RichText::new(pretty)
                .color(theme::SILVER_DIM)
                .font(FontId::new(11.0, egui::FontFamily::Monospace)),
        );
    });
}

/// Charter §6: delete demoted to a quiet footer; UX-11 grammar and the
/// UXR-07 shared confirm gate.
fn delete_footer(ui: &mut egui::Ui, record_session_id: i64, actions: &mut Vec<RecordingsAction>) {
    ui.add_space(10.0);
    caption(ui, DELETE_SECTION_CAPTION);
    if confirm_gate(
        ui,
        delete_confirm_id(record_session_id),
        CONFIRM_DELETE_LABEL,
        true,
        "",
        DELETE_BUTTON_LABEL,
        DELETE_DISABLED_REASON,
    ) {
        actions.push(RecordingsAction::Delete(record_session_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_prompt_is_value_free_and_local() {
        // The shipped prompt makes no content claims and asks for nothing
        // beyond the file: pinned like the consent copy.
        assert!(ANALYSIS_PROMPT.contains("value-free trace"));
        assert!(ANALYSIS_PROMPT.contains("no content"));
        assert!(ANALYSIS_PROMPT.contains("top three automations"));
        assert!(!ANALYSIS_PROMPT.contains("upload"));
        assert!(!ANALYSIS_PROMPT.contains('—'));
    }

    #[test]
    fn step_stories_read_as_product_voice() {
        let mut step = RecordingStep {
            seq: 1,
            captured_at: Some("2026-07-09 09:01:00".to_string()),
            action_type: "ui_action".to_string(),
            pattern_action: Some("invoke".to_string()),
            selector: "uia:4-deep (named)".to_string(),
            selector_id: Some(10),
            framework_class: "native".to_string(),
            trust_basis: "pid_match".to_string(),
            exe: Some("studio.exe".to_string()),
            is_sensitive: 0,
            coverage: "structurally observed".to_string(),
        };
        assert_eq!(step_story(&step), "Pressed a button");
        assert_eq!(step_where(&step), "studio.exe • named control");
        assert_eq!(step_confidence(&step), ("REPLAYABLE", true));
        step.action_type = "edit_committed".to_string();
        step.selector_id = None;
        step.coverage = "free input (value-free)".to_string();
        assert_eq!(step_story(&step), "Typed into a field (content not stored)");
        assert_eq!(step_where(&step), "studio.exe");
        assert_eq!(step_confidence(&step), ("FREE INPUT", false));
        step.action_type = "ui_action_other".to_string();
        step.coverage = "unmapped".to_string();
        assert_eq!(step_story(&step), "Interacted with an unmapped element");
        assert_eq!(step_confidence(&step), ("UNMAPPED", false));
    }

    #[test]
    fn produced_recording_labels_pass_the_copy_style_law() {
        use gilbreth_core::copy_style::{self, AllowEntry};

        assert_eq!(
            routine_display_name(Some("Invoice sweep"), 4),
            "Invoice sweep"
        );
        let untitled = routine_display_name(None, 4);
        assert_eq!(untitled, "Recording 4 — untitled");
        let violations = copy_style::audit_text(
            "recordings produced labels",
            "routine_display_name(untitled)",
            0,
            &untitled,
            &[AllowEntry {
                rule_id: "em-dash".to_string(),
                reason: "untitled-recording null marker, data notation not prose \
                         (Lane B seeded exception)"
                    .to_string(),
                line: 0,
            }],
        );
        copy_style::assert_no_violations(&violations);
    }
}
