//! The Diagnostics tab in the instrument register (slice 1 of the dashboard
//! register program, charter: the recorded redesign).
//!
//! One verdict band answers the page's only real question, findings render
//! as red-pencil flag rows directly under it, one uniform gauge grid carries
//! the live figures, and every detail section is a summary-carrying
//! collapsing header. The health verdict keeps DASH-04 byte-parity with
//! `scripts/review_run.py` (same categories, same reason wording) and the
//! UX-47 acknowledged log baseline layers over it unchanged. Read-only; log
//! figures are counts scoped to the event span — content never leaves the
//! machine.

use egui::{CornerRadius, FontId, Margin, RichText, Sense, Stroke};
use gilbreth_read::{DatabaseHealth, DebugLogSnapshot, InstallStateSnapshot, ProcessChurnReport};

use super::widgets::{
    self as widgets, caption, check_table, flagged_line, info_box, section_kicker, state_chip,
    summary_section, CheckRow,
};
use crate::data::{
    DiagnosticsSnapshot, LogReview, NotificationAccessRowState, PermissionActionRequest,
    PermissionRowState, PermissionSnapshot,
};
use crate::format::{
    format_age_seconds, format_duration_ms, split_unit, thousands, MISSING_VALUE_CELL,
};
use crate::theme;

pub const PERMISSIONS_CAPTION: &str = "Gilbreth captures with zero permissions; these two \
     unlock the fuller streams. Grants are made in System Settings and take effect for this \
     app only. Nothing here sends a prompt without your click.";
pub const ACCESSIBILITY_EXPLAINER: &str = "Accessibility lets Gilbreth read the focused \
     window's title and check whether the focused field is a password field (so it can \
     redact it). Without it, focus rows stay at app granularity and titles are not captured.";
pub const INPUT_MONITORING_EXPLAINER: &str = "Input Monitoring lets Gilbreth count keyboard \
     and mouse activity through one listen-only tap. Without it, those two streams stay off; \
     everything else keeps working.";
// copy-allow: em-dash prose em dash within the one-per-string cap (the one-per-string cap), recorded by the Lane B audit
pub const INPUT_MONITORING_RELAUNCH_CAPTION: &str = "Granted — but macOS delivers this \
     permission only when the app starts, so keyboard and mouse capture stays off until \
     Gilbreth relaunches.";

pub const DROPPED_BEFORE_WRITE_CAPTION: &str = "Dropped before write counts capture-side events \
     that never reached the database because the recorder was briefly saturated. It is \
     cumulative across runs and survives crashes; together with the writer-side skip count, \
     zero here means no known loss.";
pub const EXCLUDED_APPS_DIAGNOSTIC_SUFFIX: &str = "Saved list changes apply at the next \
     Gilbreth start. From that start onward, excluded app activity is absent from all analytics \
     and exports, and notification counts are off while the list is non-empty.";
pub const NO_LEGACY_PLAINTEXT_ARCHIVES: &str = "Plaintext-era archives: none.";
pub const LEGACY_PLAINTEXT_ARCHIVES_EXPLAINER: &str = "Legacy .db archives predate encryption. \
     They remain plaintext and are never silently converted; protect or remove them explicitly.";
pub const ARCHIVE_INVENTORY_UNAVAILABLE: &str =
    "The archive protection inventory couldn't be read right now.";
pub const NO_EVENTS_INFO: &str = "No events to summarize yet.";
pub const LOG_WINDOW_CAPTION: &str = "(timestamped log lines are scoped to the event time \
     span; unparseable log lines are counted)";
/// UX-06: the verdict slot always says something, even when the health
/// read itself failed.
pub const HEALTH_UNAVAILABLE: &str =
    "The health verdict couldn't be computed right now. The error above has the detail.";
/// The verdict band's method sub-line: the retired "How health is judged"
/// explainer compressed to one visible line (hover retirement).
pub const VERDICT_METHOD_CAPTION: &str = "Same layered check as the repo's review gate • log \
     figures are counts only • content never leaves this machine";
/// The zero-findings verdict sentence: with it, no red exists on the page.
pub const ALL_CHECKS_HEALTHY: &str = "All checks healthy.";
/// The background-process filter, explained once where its counts render.
pub const FILTER_EXPLAINER_CAPTION: &str = "Routine process start/exit transitions are counted \
     instead of stored. Apps you actually focus keep their start/exit rows, so crash evidence \
     survives.";
/// UX-47 (owner decision 2026-07-10, one-sided): a locally acknowledged
/// log-count baseline. The review_run.py verdict stays computed unchanged
/// underneath; the headline gates on log-count growth instead of absolutes,
/// and REVIEW fires only on deltas above the acknowledged counts.
/// review_run.py itself is untouched.
pub const ACKNOWLEDGE_LOGS_LABEL: &str = "Acknowledge these log counts as baseline";
pub const CLEAR_BASELINE_LABEL: &str = "Clear acknowledged baseline";
pub const ACKNOWLEDGE_LOGS_HELP: &str = "Treat today's unknown-warning and error/panic counts \
     as known history on this machine. The headline alarms again only when the counts grow \
     past them. Stored locally; the repo's review gate is unaffected.";

/// The acknowledged log-count baseline, persisted in the dashboard's local
/// UI state (never the database, never the repo gate).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct LogBaseline {
    pub unknown_warnings: i64,
    pub error_panics: i64,
    pub acknowledged_on: String,
}

pub fn log_baseline_id() -> egui::Id {
    egui::Id::new("diagnostics-log-baseline")
}

/// Branch review (UX-47): the gate is a count comparison, so the caption
/// states exactly that — counts at or below the baseline, never a
/// "no new lines" claim the span-scoped counts cannot support.
fn baseline_pass_caption(baseline: &LogBaseline) -> String {
    format!(
        "Unknown/error log counts at or below the baseline acknowledged {}.",
        baseline.acknowledged_on
    )
}

fn baseline_detail_caption(baseline: &LogBaseline, log_reasons: &str) -> String {
    format!(
        "Acknowledged baseline ({}): {}. The absolute check reads REVIEW until these counts \
         are zero.",
        baseline.acknowledged_on, log_reasons
    )
}

fn baseline_exceeded_caption(baseline: &LogBaseline) -> String {
    format!(
        "Counts rose past the baseline acknowledged {} (unknown log warnings={}, log \
         errors/panics={}).",
        baseline.acknowledged_on, baseline.unknown_warnings, baseline.error_panics
    )
}

/// The reasons the acknowledged baseline may absorb: the two absolute
/// log-count categories. Everything else always fires.
fn is_log_count_reason(reason: &str) -> bool {
    reason.starts_with("unknown log warnings=") || reason.starts_with("log errors/panics=")
}

/// The named reasons behind a REVIEW verdict — byte-for-byte the strings
/// `review_run.review_reasons` builds, so the script and this tab tell the
/// same story (DASH-04).
pub fn health_reasons(health: &DatabaseHealth, logs: &LogReview) -> Vec<String> {
    let mut reasons = Vec::new();
    if health.integrity_check != "ok" {
        reasons.push(format!("integrity={}", health.integrity_check));
    }
    if health.foreign_key_issues != 0 {
        reasons.push(format!("foreign_key_issues={}", health.foreign_key_issues));
    }
    if !health.seq_gap_sessions.is_empty() {
        let joined = health
            .seq_gap_sessions
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        reasons.push(format!("sequence gaps in sessions {joined}"));
    }
    if health.capture_events_dropped < 0 {
        reasons.push("capture drop counter unparseable".to_string());
    } else if health.capture_events_dropped > 0 {
        reasons.push(format!("capture drops={}", health.capture_events_dropped));
    }
    if health.stale_pre_erase_rows_dropped < 0 {
        reasons.push("stale pre-erase drop counter unparseable".to_string());
    } else if health.stale_pre_erase_rows_dropped > 0 {
        reasons.push(format!(
            "stale pre-erase drops={}",
            health.stale_pre_erase_rows_dropped
        ));
    }
    if logs.unknown_warning_lines() != 0 {
        reasons.push(format!(
            "unknown log warnings={}",
            logs.unknown_warning_lines()
        ));
    }
    if logs.error_panic_lines != 0 {
        reasons.push(format!("log errors/panics={}", logs.error_panic_lines));
    }
    if logs.max_events_skipped != 0 {
        reasons.push(format!("max events skipped={}", logs.max_events_skipped));
    }
    reasons
}

/// One red-pencil flag row: the bold finding, the plain-language read, and
/// the evidence sentence in muted text.
struct Finding {
    lead: String,
    body: Option<String>,
    evidence: Option<String>,
}

/// The findings the verdict counts: capture warnings and sustained process
/// churn. Section-level states (permissions, archives, autostart) carry
/// their own summaries instead — severity lives here, calm lives there.
fn collect_findings(snapshot: &DiagnosticsSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(debug) = &snapshot.debug {
        for warning in &debug.warnings {
            findings.push(Finding {
                lead: warning.clone(),
                body: None,
                evidence: None,
            });
        }
    }
    if let Some(churn) = &snapshot.churn {
        if churn.dropped > 0 && !churn.sustained_exes.is_empty() {
            let churners = churn
                .top
                .iter()
                .map(|row| format!("{} ({})", row.exe, thousands(row.dropped)))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding {
                lead: format!(
                    "Sustained process churn: {}.",
                    churn.sustained_exes.join(", ")
                ),
                body: Some(
                    "A program restarting this often can point at a crash loop or a runaway \
                     updater."
                        .to_string(),
                ),
                evidence: Some(format!(
                    "The filter kept the evidence: {} routine transitions in 7 days counted \
                     instead of stored ({} summary rows); biggest churners: {churners}.",
                    thousands(churn.dropped),
                    churn.summaries
                )),
            });
        }
    }
    findings
}

pub fn show(
    ui: &mut egui::Ui,
    snapshot: &DiagnosticsSnapshot,
    config_path: &str,
) -> Vec<PermissionActionRequest> {
    let mut actions = Vec::new();
    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
    }
    let findings = collect_findings(snapshot);
    verdict_area(ui, snapshot, findings.len());
    for finding in &findings {
        flag_row(ui, finding);
    }
    if let Some(debug) = &snapshot.debug {
        section_kicker(ui, "INSTRUMENTS");
        gauge_grid(ui, debug);
    }
    section_kicker(ui, "DETAILS");
    if let (Some(health), Some(logs)) = (&snapshot.health, &snapshot.logs) {
        health_check_section(ui, health, logs);
    }
    // The macOS permissions panel renders only when the host publishes grant
    // state (macOS only); Windows never sets it, so the section is absent.
    if let Some(permissions) = &snapshot.permissions {
        permissions_section(ui, permissions, &mut actions);
    }
    if let Some(debug) = &snapshot.debug {
        capture_mix_section(ui, debug);
        capture_detail_section(ui, debug, snapshot.churn.as_ref());
    }
    privacy_controls_section(ui, snapshot);
    if let Some(install) = &snapshot.install {
        install_section(ui, install, config_path);
    }
    actions
}

// ---------------------------------------------------------------- verdict

/// The verdict band: a quiet framed chip plus one sentence, with the method
/// sub-line underneath. Quiet metal (brass outline) = OK; red pencil =
/// flagged; nothing else.
fn verdict_band(ui: &mut egui::Ui, chip: Option<(&str, bool)>, line: &str, subline: bool) {
    egui::Frame::default()
        .fill(theme::WELL)
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 14.0;
                if let Some((text, flagged)) = chip {
                    let color = if flagged { theme::RED } else { theme::BRASS };
                    egui::Frame::default()
                        .stroke(Stroke::new(1.0, color))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(text)
                                    .color(color)
                                    .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                            );
                        });
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(RichText::new(line).color(theme::SILVER).size(13.5));
                    if subline {
                        ui.label(
                            RichText::new(VERDICT_METHOD_CAPTION)
                                .color(theme::GRAY)
                                .size(11.5),
                        );
                    }
                });
            });
        });
}

/// The verdict sentence for a passing check: owner-worded product voice.
/// The em dash is the page's one (per-string cap, spent here).
fn healthy_verdict_line(finding_count: usize) -> String {
    match finding_count {
        0 => ALL_CHECKS_HEALTHY.to_string(),
        // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
        1 => "All checks healthy — one thing worth a look below.".to_string(),
        // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
        n => format!("All checks healthy — {n} things worth a look below."),
    }
}

/// DASH-04 + UX-47: the verdict band plus the acknowledged-baseline
/// captions and actions, exactly the machinery the old headline carried.
fn verdict_area(ui: &mut egui::Ui, snapshot: &DiagnosticsSnapshot, finding_count: usize) {
    let (Some(health), Some(logs)) = (&snapshot.health, &snapshot.logs) else {
        if snapshot.error.is_some() {
            // UX-06: a partial read keeps the verdict slot visible instead
            // of silently dropping the tab's main story.
            verdict_band(ui, None, HEALTH_UNAVAILABLE, false);
        }
        return;
    };
    let reasons = health_reasons(health, logs);
    let baseline: Option<LogBaseline> = ui
        .ctx()
        .data_mut(|data| data.get_persisted(log_baseline_id()));
    // UXR-12: the halves borrow from the one built list instead of cloning
    // it twice over.
    let (log_reasons, hard_reasons): (Vec<&String>, Vec<&String>) = reasons
        .iter()
        .partition(|reason| is_log_count_reason(reason));
    let within_baseline = baseline.as_ref().is_some_and(|b| {
        logs.unknown_warning_lines() <= b.unknown_warnings
            && logs.error_panic_lines <= b.error_panics
    });
    let logs_alarm = !log_reasons.is_empty() && !within_baseline;
    let joined_log_reasons = log_reasons
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if hard_reasons.is_empty() && !logs_alarm {
        verdict_band(
            ui,
            Some(("PASS", false)),
            &healthy_verdict_line(finding_count),
            true,
        );
        if !log_reasons.is_empty() {
            if let Some(baseline) = &baseline {
                caption(ui, &baseline_pass_caption(baseline));
                caption(ui, &baseline_detail_caption(baseline, &joined_log_reasons));
            }
        }
    } else {
        // The reason strings stay byte-parity with review_run.py; absorbed
        // log counts move into the baseline caption below, and the prefix
        // says so when they do (branch review, UX-47 coherence).
        let (prefix, shown): (&str, Vec<&String>) = if within_baseline {
            ("Reasons above the acknowledged baseline", hard_reasons)
        } else {
            ("Reasons", reasons.iter().collect())
        };
        let joined = shown
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        verdict_band(
            ui,
            Some(("REVIEW", true)),
            &format!("{prefix}: {joined}"),
            true,
        );
        if within_baseline && !log_reasons.is_empty() {
            if let Some(baseline) = &baseline {
                caption(ui, &baseline_detail_caption(baseline, &joined_log_reasons));
            }
        }
        if logs_alarm {
            if let Some(baseline) = &baseline {
                caption(ui, &baseline_exceeded_caption(baseline));
            }
            if super::widgets::small_button_help(ui, ACKNOWLEDGE_LOGS_LABEL, ACKNOWLEDGE_LOGS_HELP)
            {
                let acknowledged = LogBaseline {
                    unknown_warnings: logs.unknown_warning_lines(),
                    error_panics: logs.error_panic_lines,
                    acknowledged_on: gilbreth_read::local_date(snapshot.generated_at_ms),
                };
                ui.ctx()
                    .data_mut(|data| data.insert_persisted(log_baseline_id(), acknowledged));
            }
        }
    }
    if baseline.is_some() && super::widgets::small_button(ui, CLEAR_BASELINE_LABEL) {
        ui.ctx()
            .data_mut(|data| data.remove::<LogBaseline>(log_baseline_id()));
    }
}

/// A red-pencil flag row: flag glyph, bold finding sentence, plain read,
/// evidence in muted text. The only loud construct on the page.
fn flag_row(ui: &mut egui::Ui, finding: &Finding) {
    egui::Frame::default()
        .fill(theme::RED_WELL)
        .stroke(Stroke::new(1.0, theme::RED_HAIRLINE))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                ui.label(
                    RichText::new("⚑")
                        .color(theme::RED)
                        .font(FontId::new(13.0, egui::FontFamily::Monospace)),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(
                        RichText::new(&finding.lead)
                            .color(theme::RED)
                            .font(FontId::new(12.5, theme::family_medium())),
                    );
                    if let Some(body) = &finding.body {
                        ui.label(RichText::new(body).color(theme::SILVER_DIM).size(12.5));
                    }
                    if let Some(evidence) = &finding.evidence {
                        ui.label(RichText::new(evidence).color(theme::GRAY).size(12.5));
                    }
                });
            });
        });
}

// --------------------------------------------------------------- gauges

/// The gauge value for the capture status: the reader's "Recording" reads
/// "Active" in the instrument register; other statuses pass through.
fn capture_status_display(status: &str) -> String {
    if status == "Recording" {
        "Active".to_string()
    } else {
        status.to_string()
    }
}

/// One uniform gauge grid replacing the two mismatched tile rows and the
/// duplicate details box: uniform size, one label style, no hover help.
fn gauge_grid(ui: &mut egui::Ui, debug: &DebugLogSnapshot) {
    let (session_value, session_suffix) = match debug.session_id {
        Some(id) => (
            id.to_string(),
            Some(format!("• {} events", thousands(debug.event_count))),
        ),
        None => (MISSING_VALUE_CELL.to_string(), None),
    };
    let (sleeps_value, sleeps_suffix) = if debug.power_boundary_catches > 0 {
        (
            debug.power_sleeps.to_string(),
            Some(format!("• {} recovered", debug.power_boundary_catches)),
        )
    } else {
        (debug.power_sleeps.to_string(), None)
    };
    let (focus_value, focus_suffix) = match (
        debug.longest_foreground_ms,
        debug.longest_active_foreground_ms,
    ) {
        (Some(raw), Some(active)) => (
            format_duration_ms(raw),
            Some(format!("raw • {} active", format_duration_ms(active))),
        ),
        (Some(raw), None) => (format_duration_ms(raw), Some("raw".to_string())),
        (None, Some(active)) => (format_duration_ms(active), Some("active".to_string())),
        (None, None) => (MISSING_VALUE_CELL.to_string(), None),
    };
    // The age reads "14s" big with a quiet "ago" (amendment §7).
    let (age_value, age_suffix) = match format_age_seconds(debug.latest_event_age_seconds) {
        value if value == MISSING_VALUE_CELL => (value, None),
        value => (
            value.trim_end_matches(" ago").to_string(),
            Some("ago".to_string()),
        ),
    };
    let (db_value, db_suffix) = split_unit(&gilbreth_read::format_bytes(debug.db_size_bytes));
    let gauges: [(&str, String, Option<String>); 8] = [
        (
            "Capture",
            capture_status_display(&debug.recording_status),
            None,
        ),
        ("Latest event", age_value, age_suffix),
        ("Events last 5 min", thousands(debug.events_last_5m), None),
        ("Database", db_value, db_suffix),
        ("Session", session_value, session_suffix),
        (
            "Dropped before write",
            debug.capture_events_dropped.to_string(),
            None,
        ),
        ("Sleeps", sleeps_value, sleeps_suffix),
        ("Longest focus", focus_value, focus_suffix),
    ];
    widgets::gauge_tiles_suffixed(ui, &gauges, 4);
}

// -------------------------------------------------------------- sections

/// The composed known-category warning counts (non-gating): only the
/// categories that actually fired, bullet-joined.
fn known_categories_value(logs: &LogReview) -> Option<String> {
    let mut parts = Vec::new();
    if logs.clipboard_locked_warning_lines > 0 {
        parts.push(format!(
            "clipboard-locked {}",
            logs.clipboard_locked_warning_lines
        ));
    }
    if logs.orphan_session_repair_warning_lines > 0 {
        parts.push(format!(
            "orphan-repair {}",
            logs.orphan_session_repair_warning_lines
        ));
    }
    if logs.stale_pre_erase_drop_warning_lines > 0 {
        parts.push(format!(
            "stale-pre-erase-drop {}",
            logs.stale_pre_erase_drop_warning_lines
        ));
    }
    if logs.recovered_focus_warning_lines > 0 {
        parts.push(format!(
            "recovered-focus {}",
            logs.recovered_focus_warning_lines
        ));
    }
    if logs.open_focus_discard_warning_lines > 0 {
        parts.push(format!(
            "open-focus-discard {}",
            logs.open_focus_discard_warning_lines
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" • "))
    }
}

fn health_check_section(ui: &mut egui::Ui, health: &DatabaseHealth, logs: &LogReview) {
    let reasons = health_reasons(health, logs);
    let known = known_categories_value(logs);
    let known_count = logs.clipboard_locked_warning_lines
        + logs.orphan_session_repair_warning_lines
        + logs.stale_pre_erase_drop_warning_lines
        + logs.recovered_focus_warning_lines
        + logs.open_focus_discard_warning_lines;
    let mut summary = if reasons.is_empty() {
        "all clean".to_string()
    } else {
        let noun = if reasons.len() == 1 {
            "reason"
        } else {
            "reasons"
        };
        format!("{} {noun}", reasons.len())
    };
    if known_count > 0 {
        let noun = if known_count == 1 {
            "known warning"
        } else {
            "known warnings"
        };
        summary.push_str(&format!(" • {known_count} {noun}"));
    }
    let flagged = !reasons.is_empty();
    summary_section(
        ui,
        "diag-health",
        "Health check",
        &summary,
        flagged,
        true,
        |ui| {
            let integrity_ok = health.integrity_check == "ok";
            let fk_seq_ok = health.foreign_key_issues == 0 && health.seq_gap_sessions.is_empty();
            // The three-arm wording review_run's Seq continuity line uses:
            // unexplained gaps flag, gaps covered by recorded deletions
            // (migration 008) read as known.
            let explained_note = format!(
                "gaps in sessions {} explained by recorded deletions",
                health
                    .explained_gap_sessions
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let seq_status = if !health.seq_gap_sessions.is_empty() {
                let mut status = format!(
                    "gaps in sessions {}",
                    health
                        .seq_gap_sessions
                        .iter()
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if !health.explained_gap_sessions.is_empty() {
                    status.push_str(&format!("; {explained_note}"));
                }
                status
            } else if !health.explained_gap_sessions.is_empty() {
                format!("ok ({explained_note})")
            } else {
                "ok".to_string()
            };
            let drops_value = if health.capture_events_dropped < 0 {
                "unparseable".to_string()
            } else {
                health.capture_events_dropped.to_string()
            };
            let drops_ok = health.capture_events_dropped == 0 && logs.max_events_skipped == 0;
            let stale_value = if health.stale_pre_erase_rows_dropped < 0 {
                "unparseable".to_string()
            } else {
                health.stale_pre_erase_rows_dropped.to_string()
            };
            let stale_ok = health.stale_pre_erase_rows_dropped == 0;
            let errors_ok = logs.error_panic_lines == 0;
            let unknown_ok = logs.unknown_warning_lines() == 0;
            let mut rows = vec![
                CheckRow {
                    label: "Database integrity".to_string(),
                    value: health.integrity_check.clone(),
                    flagged: !integrity_ok,
                    tick: integrity_ok,
                    ..Default::default()
                },
                CheckRow {
                    label: "Foreign keys • sequence continuity".to_string(),
                    value: format!("{} issues • {seq_status}", health.foreign_key_issues),
                    flagged: !fk_seq_ok,
                    tick: fk_seq_ok,
                    ..Default::default()
                },
                CheckRow {
                    label: "Capture drops • skipped events".to_string(),
                    value: format!("{drops_value} • {}", logs.max_events_skipped),
                    flagged: !drops_ok,
                    tick: drops_ok,
                    ..Default::default()
                },
                CheckRow {
                    label: "Stale pre-erase rows dropped".to_string(),
                    value: stale_value,
                    flagged: !stale_ok,
                    tick: stale_ok,
                    ..Default::default()
                },
                CheckRow {
                    label: "Recovered focus rows".to_string(),
                    value: health.recovered_focus_rows.to_string(),
                    tick: health.recovered_focus_rows == 0,
                    dim: health.recovered_focus_rows > 0,
                    ..Default::default()
                },
                CheckRow {
                    label: "Errors or panics in logs".to_string(),
                    value: logs.error_panic_lines.to_string(),
                    flagged: !errors_ok,
                    tick: errors_ok,
                    ..Default::default()
                },
                CheckRow {
                    label: "Unknown warnings".to_string(),
                    value: logs.unknown_warning_lines().to_string(),
                    flagged: !unknown_ok,
                    tick: unknown_ok,
                    ..Default::default()
                },
            ];
            // Same placement as review_run's "Recorded deletions: N rows"
            // line; the row is absent on a pre-008 database, matching the
            // script's skip-the-line behavior.
            if let Some(rows_deleted) = health.deletion_audit_rows_deleted {
                rows.push(CheckRow {
                    label: "Recorded deletions".to_string(),
                    value: format!("{rows_deleted} rows"),
                    tick: rows_deleted == 0,
                    dim: rows_deleted > 0,
                    ..Default::default()
                });
            }
            if let Some(known) = known {
                rows.push(CheckRow {
                    label: "Known categories (non-gating)".to_string(),
                    value: known,
                    dim: true,
                    ..Default::default()
                });
            }
            rows.push(CheckRow {
                label: "Schema version".to_string(),
                value: health.user_version.to_string(),
                dim: true,
                ..Default::default()
            });
            rows.push(CheckRow {
                label: "Log files scanned".to_string(),
                value: logs.files.to_string(),
                dim: true,
                ..Default::default()
            });
            check_table(ui, "diag-health-checks", &rows);
            if logs.files > 1 {
                caption(ui, LOG_WINDOW_CAPTION);
            }
        },
    );
}

/// The TCC permissions panel (macOS onboarding/Diagnostics): each grant's
/// live state as a framed chip, a one-line explanation, and the appropriate
/// action button. Explain-then-prompt, individually declineable — a decline
/// just leaves the stream OFF-declared here, never a nag loop.
fn permissions_section(
    ui: &mut egui::Ui,
    permissions: &PermissionSnapshot,
    actions: &mut Vec<PermissionActionRequest>,
) {
    let granted = [permissions.accessibility, permissions.input_monitoring]
        .iter()
        .filter(|state| {
            matches!(
                state,
                PermissionRowState::Granted | PermissionRowState::GrantedNeedsRelaunch
            )
        })
        .count();
    let needs_relaunch = matches!(
        permissions.input_monitoring,
        PermissionRowState::GrantedNeedsRelaunch
    ) || matches!(
        permissions.accessibility,
        PermissionRowState::GrantedNeedsRelaunch
    );
    let mut summary = match granted {
        2 => "both granted".to_string(),
        count => format!("{count} of 2 granted"),
    };
    if needs_relaunch {
        summary.push_str(" • relaunch needed");
    }
    let default_open = granted < 2 || needs_relaunch;
    summary_section(
        ui,
        "diag-permissions",
        "Permissions",
        &summary,
        false,
        default_open,
        |ui| {
            caption(ui, PERMISSIONS_CAPTION);
            permission_row(
                ui,
                "Accessibility",
                permissions.accessibility,
                ACCESSIBILITY_EXPLAINER,
                PermissionActionRequest::OpenAccessibilityPane,
                PermissionActionRequest::PromptAccessibility,
                None,
                actions,
            );
            permission_row(
                ui,
                "Input Monitoring",
                permissions.input_monitoring,
                INPUT_MONITORING_EXPLAINER,
                PermissionActionRequest::OpenInputMonitoringPane,
                PermissionActionRequest::PromptInputMonitoring,
                Some(PermissionActionRequest::Relaunch),
                actions,
            );
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn permission_row(
    ui: &mut egui::Ui,
    name: &str,
    state: PermissionRowState,
    explainer_text: &str,
    open_pane: PermissionActionRequest,
    prompt: PermissionActionRequest,
    relaunch: Option<PermissionActionRequest>,
    actions: &mut Vec<PermissionActionRequest>,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(name).color(theme::SILVER).size(13.5).strong());
        match state {
            PermissionRowState::Granted | PermissionRowState::GrantedNeedsRelaunch => {
                state_chip(ui, "GRANTED", true);
            }
            PermissionRowState::NotGranted => {
                state_chip(ui, "OFF", false);
            }
        }
    });
    match state {
        PermissionRowState::NotGranted => {
            body_line(ui, explainer_text);
            ui.horizontal(|ui| {
                if ui.button("Request access").clicked() {
                    actions.push(prompt);
                }
                if ui.button("Open System Settings").clicked() {
                    actions.push(open_pane);
                }
            });
        }
        PermissionRowState::GrantedNeedsRelaunch => {
            body_line(ui, INPUT_MONITORING_RELAUNCH_CAPTION);
            if ui.button("Relaunch to activate").clicked() {
                if let Some(relaunch) = relaunch {
                    actions.push(relaunch);
                }
            }
        }
        PermissionRowState::Granted => {}
    }
}

fn capture_mix_section(ui: &mut egui::Ui, debug: &DebugLogSnapshot) {
    let total_events: i64 = debug.source_counts.iter().map(|row| row.events).sum();
    let summary = if debug.source_counts.is_empty() {
        "no events yet".to_string()
    } else {
        let leader = debug
            .source_counts
            .iter()
            .max_by_key(|row| row.events)
            .map(|row| row.source.as_str())
            .unwrap_or("");
        let noun = if debug.source_counts.len() == 1 {
            "source"
        } else {
            "sources"
        };
        format!("{} {noun} • {leader} leads", debug.source_counts.len())
    };
    summary_section(
        ui,
        "diag-mix",
        "Capture mix",
        &summary,
        false,
        false,
        |ui| {
            if debug.source_counts.is_empty() {
                info_box(ui, NO_EVENTS_INFO);
                return;
            }
            for row in &debug.source_counts {
                let share = if total_events > 0 {
                    row.events as f64 / total_events as f64
                } else {
                    0.0
                };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    ui.allocate_ui_with_layout(
                        egui::vec2(90.0, 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.label(RichText::new(&row.source).color(theme::SILVER).size(12.5));
                        },
                    );
                    ui.allocate_ui_with_layout(
                        egui::vec2(70.0, 18.0),
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            ui.label(
                                RichText::new(thousands(row.events))
                                    .color(theme::SILVER_DIM)
                                    .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                            );
                        },
                    );
                    ui.allocate_ui_with_layout(
                        egui::vec2(46.0, 18.0),
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            ui.label(
                                RichText::new(format!("{:.0}%", share * 100.0))
                                    .color(theme::GRAY)
                                    .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                            );
                        },
                    );
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width().max(40.0), 6.0),
                        Sense::hover(),
                    );
                    let painter = ui.painter();
                    painter.rect_filled(rect, 3.0, theme::WELL);
                    let mut fill = rect;
                    fill.set_width(rect.width() * share as f32);
                    painter.rect_filled(fill, 3.0, theme::BLUE);
                });
            }
        },
    );
}

fn capture_detail_section(
    ui: &mut egui::Ui,
    debug: &DebugLogSnapshot,
    churn: Option<&ProcessChurnReport>,
) {
    let mut summary_parts = Vec::new();
    if debug.wal_size_bytes != 0 {
        summary_parts.push(format!(
            "WAL {}",
            gilbreth_read::format_bytes(debug.wal_size_bytes)
        ));
    }
    if let Some(boundary) = &debug.last_boundary_at {
        let date = boundary.split_whitespace().next().unwrap_or(boundary);
        summary_parts.push(format!("last backstop {date}"));
    }
    let summary = if summary_parts.is_empty() {
        "quiet".to_string()
    } else {
        summary_parts.join(" • ")
    };
    summary_section(
        ui,
        "diag-detail",
        "Capture details",
        &summary,
        false,
        false,
        |ui| {
            let mut rows = Vec::new();
            if let Some(latest) = &debug.latest_event_at {
                rows.push(CheckRow {
                    label: "Latest event".to_string(),
                    value: latest.clone(),
                    ..Default::default()
                });
            }
            if debug.wal_size_bytes != 0 {
                rows.push(CheckRow {
                    label: "WAL size".to_string(),
                    value: gilbreth_read::format_bytes(debug.wal_size_bytes),
                    ..Default::default()
                });
            }
            if let Some(boundary) = &debug.last_boundary_at {
                rows.push(CheckRow {
                    label: "Last backstop recovery".to_string(),
                    value: boundary.clone(),
                    ..Default::default()
                });
            }
            match (
                &debug.longest_foreground_app,
                &debug.longest_active_foreground_app,
            ) {
                (Some(raw), Some(active)) => rows.push(CheckRow {
                    label: "Longest focus app (raw • active)".to_string(),
                    value: format!("{raw} • {active}"),
                    ..Default::default()
                }),
                (Some(raw), None) => rows.push(CheckRow {
                    label: "Longest raw foreground app".to_string(),
                    value: raw.clone(),
                    ..Default::default()
                }),
                (None, Some(active)) => rows.push(CheckRow {
                    label: "Longest active foreground app".to_string(),
                    value: active.clone(),
                    ..Default::default()
                }),
                (None, None) => {}
            }
            if debug.sensitive_rows > 0 {
                let row_word = if debug.sensitive_rows == 1 {
                    "row"
                } else {
                    "rows"
                };
                rows.push(CheckRow {
                    label: "Privacy redactions this session".to_string(),
                    value: format!(
                        "{} {row_word} (your settings working)",
                        debug.sensitive_rows
                    ),
                    ..Default::default()
                });
            }
            if rows.is_empty() {
                body_line(ui, "No additional capture details this session.");
            } else {
                check_table(ui, "diag-capture-detail", &rows);
            }
            if debug.capture_events_dropped != 0 {
                caption(ui, DROPPED_BEFORE_WRITE_CAPTION);
            }
            if let Some(churn) = churn {
                // The sustained-churn flag row carries these figures when it is
                // up; this section carries them when the filter worked quietly.
                if churn.dropped > 0 && churn.sustained_exes.is_empty() {
                    caption(
                        ui,
                        &format!(
                            "Background-process filter: {} routine transitions in the last 7 days \
                         counted instead of stored ({} summary rows).",
                            thousands(churn.dropped),
                            churn.summaries
                        ),
                    );
                    if !churn.top.is_empty() {
                        let top_text = churn
                            .top
                            .iter()
                            .map(|row| format!("{} ({})", row.exe, thousands(row.dropped)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        caption(ui, &format!("Biggest background churners: {top_text}."));
                    }
                }
                if churn.dropped > 0 {
                    caption(ui, FILTER_EXPLAINER_CAPTION);
                }
            }
        },
    );
}

/// The notification-access fragment for the Privacy & controls summary.
fn notification_summary_fragment(state: NotificationAccessRowState) -> &'static str {
    match state {
        NotificationAccessRowState::Allowed => "notifications on",
        NotificationAccessRowState::Unspecified => "notifications not requested",
        NotificationAccessRowState::Denied => "notifications denied",
        NotificationAccessRowState::Unavailable => "notifications unavailable",
        NotificationAccessRowState::Unsupported => "notifications unsupported",
    }
}

fn legacy_plaintext_archive_count_copy(count: usize) -> String {
    match count {
        0 => NO_LEGACY_PLAINTEXT_ARCHIVES.to_string(),
        // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
        1 => "1 archive predates encryption — plaintext.".to_string(),
        // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
        count => format!("{count} archives predate encryption — plaintext."),
    }
}

/// The Phase 6 controls in one section: pause-hotkey registration failures,
/// configured exclusions, count-only archive protection, and notification
/// access. Facts stay visible; the summary carries the collapsed story.
fn privacy_controls_section(ui: &mut egui::Ui, snapshot: &DiagnosticsSnapshot) {
    let has_content = snapshot.pause_hotkey_warning.is_some()
        || !snapshot.excluded_apps.is_empty()
        || snapshot.legacy_plaintext_archive_count.is_some()
        || snapshot.archive_inventory_error.is_some()
        || snapshot.notification_access.is_some();
    if !has_content {
        return;
    }
    let mut parts = Vec::new();
    let mut flagged = false;
    if snapshot.pause_hotkey_warning.is_some() {
        parts.push("pause hotkey unregistered".to_string());
        flagged = true;
    }
    if !snapshot.excluded_apps.is_empty() {
        let noun = if snapshot.excluded_apps.len() == 1 {
            "app"
        } else {
            "apps"
        };
        parts.push(format!("{} {noun} excluded", snapshot.excluded_apps.len()));
    }
    if let Some(count) = snapshot.legacy_plaintext_archive_count {
        if count > 0 {
            let noun = if count == 1 { "archive" } else { "archives" };
            parts.push(format!("{count} plaintext {noun}"));
        }
    }
    if snapshot.archive_inventory_error.is_some() {
        parts.push("archive inventory unreadable".to_string());
        flagged = true;
    }
    if let Some(notification) = &snapshot.notification_access {
        parts.push(notification_summary_fragment(notification.state).to_string());
    }
    let summary = if parts.is_empty() {
        "quiet".to_string()
    } else {
        parts.join(" • ")
    };
    let default_open =
        snapshot.pause_hotkey_warning.is_some() || snapshot.archive_inventory_error.is_some();
    summary_section(
        ui,
        "diag-privacy-controls",
        "Privacy & controls",
        &summary,
        flagged,
        default_open,
        |ui| {
            if let Some(warning) = &snapshot.pause_hotkey_warning {
                flagged_line(ui, warning);
            }
            if !snapshot.excluded_apps.is_empty() {
                let excluded_count = snapshot.excluded_apps.len();
                let excluded_noun = if excluded_count == 1 { "app" } else { "apps" };
                caption(
                    ui,
                    &format!(
                        "{excluded_count} {excluded_noun} configured for exclusion. {}",
                        EXCLUDED_APPS_DIAGNOSTIC_SUFFIX
                    ),
                );
                body_line(
                    ui,
                    &format!("Configured apps: {}", snapshot.excluded_apps.join(", ")),
                );
            }
            if let Some(count) = snapshot.legacy_plaintext_archive_count {
                body_line(ui, &legacy_plaintext_archive_count_copy(count));
                if count > 0 {
                    caption(ui, LEGACY_PLAINTEXT_ARCHIVES_EXPLAINER);
                }
            }
            if snapshot.archive_inventory_error.is_some() {
                flagged_line(ui, ARCHIVE_INVENTORY_UNAVAILABLE);
            }
            if let Some(notification) = &snapshot.notification_access {
                body_line(ui, &notification.diagnostics_copy);
            }
        },
    );
}

/// UX-49: "Build source: open session" read as a raw token; say it in a
/// sentence.
fn build_source_caption(source: &str) -> String {
    match source {
        "open session" => "The build SHA comes from the currently open session.".to_string(),
        "latest session" => "The build SHA comes from the most recent session.".to_string(),
        "unavailable" => "No build SHA is recorded in this database.".to_string(),
        other => format!("Build source: {other}"),
    }
}

fn install_section(ui: &mut egui::Ui, install: &InstallStateSnapshot, config_path: &str) {
    let build_label: String = install
        .build_sha
        .as_deref()
        .unwrap_or("Unknown")
        .chars()
        .take(12)
        .collect();
    let autostart_status = if install.autostart_error.is_some() {
        // UX-49: an unreadable Run entry is not the same "Unknown" as a
        // missing SHA.
        "Unreadable"
    } else if install.autostart_path.is_some() {
        if install.autostart_path_exists {
            "Configured"
        } else {
            "Missing target"
        }
    } else {
        "Off"
    };
    let autostart_problem = install.autostart_error.is_some()
        || (install.autostart_path.is_some() && !install.autostart_path_exists);
    let summary = format!(
        "{build_label} • autostart {}",
        autostart_status.to_lowercase()
    );
    summary_section(
        ui,
        "diag-install",
        "Install & autostart",
        &summary,
        autostart_problem,
        autostart_problem,
        |ui| {
            // UX-49: the truncated SHA gets its full value on hover.
            let sha_help = match install.build_sha.as_deref() {
                Some(sha) if !sha.trim().is_empty() => format!("Full SHA: {}", sha.trim()),
                _ => "No build SHA is recorded in this database.".to_string(),
            };
            let rows = vec![
                CheckRow {
                    label: "Build".to_string(),
                    value: build_label.clone(),
                    hover: Some(sha_help),
                    ..Default::default()
                },
                CheckRow {
                    label: "Open sessions".to_string(),
                    value: install.open_sessions.to_string(),
                    ..Default::default()
                },
                CheckRow {
                    label: "Autostart".to_string(),
                    value: autostart_status.to_string(),
                    flagged: autostart_problem,
                    ..Default::default()
                },
                // The config file location: an ops fact, moved here from the
                // Privacy tab (decided with the Privacy redesign, D §4).
                CheckRow {
                    label: "Config".to_string(),
                    value: config_path.to_string(),
                    dim: true,
                    ..Default::default()
                },
            ];
            check_table(ui, "diag-install-rows", &rows);
            caption(ui, &build_source_caption(&install.build_source));
            if let Some(path) = &install.autostart_path {
                body_line(ui, &format!("Autostart target: {path}"));
            }
            if let Some(error) = &install.autostart_error {
                flagged_line(ui, &format!("Could not read autostart target: {error}"));
            } else if install.autostart_path.is_some() && !install.autostart_path_exists {
                flagged_line(ui, "Autostart target does not exist.");
            }
        },
    );
}

/// UX-59: the tab's primary data reads as body text, not fine print.
fn body_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::SILVER_DIM).size(13.0));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_fixture() -> (DatabaseHealth, LogReview) {
        (
            DatabaseHealth {
                integrity_check: "ok".to_string(),
                foreign_key_issues: 0,
                user_version: 9,
                seq_gap_sessions: Vec::new(),
                explained_gap_sessions: Vec::new(),
                deletion_audit_rows_deleted: Some(0),
                capture_events_dropped: 0,
                stale_pre_erase_rows_dropped: 0,
                recovered_focus_rows: 0,
                min_ts: Some(1_000),
                max_ts: Some(2_000),
            },
            LogReview::default(),
        )
    }

    #[test]
    fn health_reasons_match_review_run_vocabulary() {
        let (health, logs) = healthy_fixture();
        assert!(health_reasons(&health, &logs).is_empty());

        let mut health = health;
        health.seq_gap_sessions = vec![4, 7];
        // Explained gaps are a known category, never a REVIEW reason.
        health.explained_gap_sessions = vec![2];
        health.capture_events_dropped = -1;
        health.stale_pre_erase_rows_dropped = 3;
        let mut logs = logs;
        logs.warning_lines = 3;
        logs.clipboard_locked_warning_lines = 1;
        logs.error_panic_lines = 2;
        logs.max_events_skipped = 5;
        assert_eq!(
            health_reasons(&health, &logs),
            vec![
                "sequence gaps in sessions 4, 7".to_string(),
                "capture drop counter unparseable".to_string(),
                "stale pre-erase drops=3".to_string(),
                "unknown log warnings=2".to_string(),
                "log errors/panics=2".to_string(),
                "max events skipped=5".to_string(),
            ]
        );
    }

    #[test]
    fn legacy_plaintext_archive_copy_is_count_only() {
        assert_eq!(
            legacy_plaintext_archive_count_copy(0),
            NO_LEGACY_PLAINTEXT_ARCHIVES
        );
        assert_eq!(
            legacy_plaintext_archive_count_copy(1),
            "1 archive predates encryption — plaintext."
        );
        assert_eq!(
            legacy_plaintext_archive_count_copy(7),
            "7 archives predate encryption — plaintext."
        );
    }

    #[test]
    fn verdict_line_counts_findings_in_product_voice() {
        assert_eq!(healthy_verdict_line(0), ALL_CHECKS_HEALTHY);
        assert_eq!(
            healthy_verdict_line(1),
            "All checks healthy — one thing worth a look below."
        );
        assert_eq!(
            healthy_verdict_line(3),
            "All checks healthy — 3 things worth a look below."
        );
    }

    #[test]
    fn capture_status_reads_active_in_the_register() {
        assert_eq!(capture_status_display("Recording"), "Active");
        assert_eq!(capture_status_display("No open session"), "No open session");
        assert_eq!(capture_status_display("No sessions"), "No sessions");
    }

    #[test]
    fn produced_diagnostics_copy_passes_the_copy_style_law() {
        use gilbreth_core::copy_style::{self, AllowEntry};

        let verdict_allow = [AllowEntry {
            rule_id: "em-dash".to_string(),
            reason: "the Diagnostics verdict spends the per-string cap \
                     (Lane B seeded exception)"
                .to_string(),
            line: 0,
        }];
        let plaintext_allow = [AllowEntry {
            rule_id: "em-dash".to_string(),
            reason: "prose em dash within the one-per-string cap \
                     (the one-per-string cap), recorded by the Lane B audit"
                .to_string(),
            line: 0,
        }];
        let mut violations = Vec::new();
        for (name, text, allows) in [
            ("healthy_verdict_line(0)", healthy_verdict_line(0), &[][..]),
            (
                "healthy_verdict_line(1)",
                healthy_verdict_line(1),
                &verdict_allow[..],
            ),
            (
                "healthy_verdict_line(3)",
                healthy_verdict_line(3),
                &verdict_allow[..],
            ),
            (
                "legacy_plaintext_archive_count_copy(0)",
                legacy_plaintext_archive_count_copy(0),
                &[][..],
            ),
            (
                "legacy_plaintext_archive_count_copy(1)",
                legacy_plaintext_archive_count_copy(1),
                &plaintext_allow[..],
            ),
            (
                "legacy_plaintext_archive_count_copy(7)",
                legacy_plaintext_archive_count_copy(7),
                &plaintext_allow[..],
            ),
        ] {
            violations.extend(copy_style::audit_text(
                "diagnostics produced copy",
                name,
                0,
                &text,
                allows,
            ));
        }
        copy_style::assert_no_violations(&violations);
    }
}
