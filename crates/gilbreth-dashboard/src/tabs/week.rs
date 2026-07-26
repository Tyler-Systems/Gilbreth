//! The Week tab in the instrument register (slice 6 of the dashboard
//! register program, charter: the recorded redesign,
//! direction A "Same anatomy, the glance pair").
//!
//! The figure leads: the heatmap opens the tab (extending the Analytics
//! Rhythms-first amendment to the whole glance family), then the trend
//! gauges with the one-"last week" delta takeaway, top apps as share bars
//! (the leader in instrument gray — amber stays the heatmap's), the two-up
//! morning-launch and pulls-you-back pair with bullet-joined counts,
//! changed-this-week as New/Quieter takeaway lines with the thresholds in
//! Details, and the week-scoped friction candidates in the shared
//! observation anatomy with the hedge stated once. Registers per the
//! type-ramp amendment.

use egui::{FontId, RichText};
use gilbreth_read::{PatternCandidate, WeeklyDigest};

use super::widgets::{
    self, accent_card, caption, card_frame, family_chip, opening_section_kicker,
    patterns_empty_caption, secnote, section_kicker, summary_section, takeaway, ShareBarRow,
};
use crate::charts;
use crate::data::WeekSnapshot;
use crate::format::{format_duration_ms, local_month_day, thousands, MISSING_VALUE_CELL};
use crate::theme;

pub const NOTHING_RECORDED_WEEK: &str = "Nothing recorded in the last 7 days yet.";
pub const NO_PRIOR_WEEK_CAPTION: &str =
    "No prior week to compare against yet. Trends appear once Gilbreth has two weeks of history.";
pub const MORNING_LAUNCH_EMPTY: &str = "Not enough mornings recorded to see a launch pattern yet.";
pub const PULLS_BACK_CAPTION: &str = "The app you return to right after a break.";
pub const PULLS_BACK_EMPTY: &str = "No breaks-and-returns recorded this week yet.";
pub const NO_CHANGES_CAPTION: &str = "No pattern changes to report this week.";
/// UX-13: sections keep their kicker plus a one-line empty state instead
/// of vanishing.
pub const NO_HEATMAP_CAPTION: &str = "No recorded activity to chart yet this week.";
pub const NO_TOP_APPS_CAPTION: &str = "No app time recorded this week yet.";
/// The what-counts-as-changed thresholds, verbatim, as two labeled lines
/// with the archive note last (C-ledger).
pub const CHANGED_NEW_LINE: &str = "New: a pattern with 8+ occurrences across 2+ days this week \
     and none in the prior three weeks, shown once Gilbreth has 14 days of history.";
pub const CHANGED_QUIETER_LINE: &str = "Quieter: a pattern active on 3+ days in the prior three \
     weeks with no occurrences this week.";
pub const CHANGED_ARCHIVE_LINE: &str =
    "Archiving and resetting the database restarts this history.";

/// Mirrors `_delta_caption` reshaped by the C-ledger: the sentence says
/// "last week" once (the prefix carries it), each part reads
/// "{pct}% {direction} {unit}", and rates move "higher/lower" while
/// quantities move "more/less". UX-42 (owner decision 2026-07-10,
/// two-sided): an unchanged metric reads "about the same", not "0% more".
fn delta_part(current: f64, prior: f64, unit: &str, directions: (&str, &str)) -> Option<String> {
    if prior <= 0.0 {
        return None;
    }
    let pct = ((current - prior) / prior * 100.0).round_ties_even() as i64;
    if pct == 0 {
        return Some(format!("about the same {unit}"));
    }
    let direction = if pct > 0 { directions.0 } else { directions.1 };
    Some(format!("{}% {direction} {unit}", pct.abs()))
}

pub fn show(ui: &mut egui::Ui, snapshot: &WeekSnapshot) {
    let digest = &snapshot.digest;

    // The story title retired with the tool-not-story ruling; the caption
    // states the window and the method.
    caption(
        ui,
        &format!(
            "The last 7 days, {} to {}, compared to the 7 before. Durations and counts only, \
             subtracting idle and sleep.",
            local_month_day(digest.week_start_ms),
            local_month_day(digest.now_ms)
        ),
    );
    ui.add_space(4.0);

    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
        ui.add_space(4.0);
    }

    if digest.active_ms <= 0 {
        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(NOTHING_RECORDED_WEEK).color(theme::SILVER));
        });
        return;
    }

    // The figure leads (charter §1): the heatmap opens the tab, the one
    // amber moment on this view. The kicker pulls up under the page
    // opener (amendment §3).
    opening_section_kicker(ui, "WHEN YOU WERE ACTIVE");
    let heat_total: f64 = digest
        .heatmap
        .iter()
        .map(|bucket| bucket.active_minutes)
        .sum();
    if !digest.heatmap.is_empty() && heat_total > 0.0 {
        takeaway(
            ui,
            "Your active hours across the week. Brighter is more active.",
        );
        charts::weekday_hour_heatmap(ui, &digest.heatmap);
    } else {
        caption(ui, NO_HEATMAP_CAPTION);
    }

    trend_gauges(ui, digest);
    if digest.has_prior_week {
        let parts: Vec<String> = [
            delta_part(
                digest.active_ms as f64,
                digest.prior_active_ms as f64,
                "active time",
                ("more", "less"),
            ),
            delta_part(
                digest.keystrokes as f64,
                digest.prior_keystrokes as f64,
                "keystrokes",
                ("more", "less"),
            ),
            match (
                digest.switches_per_active_hour,
                digest.prior_switches_per_active_hour,
            ) {
                (Some(current), Some(prior)) => {
                    delta_part(current, prior, "switch rate", ("higher", "lower"))
                }
                _ => None,
            },
        ]
        .into_iter()
        .flatten()
        .collect();
        if !parts.is_empty() {
            // The sentence says "last week" once (C-ledger). The founding
            // bug of the amendment (§2): this is the week's finding, so it
            // renders as a takeaway, never a caption.
            takeaway(ui, &format!("Vs. last week: {}.", parts.join("; ")));
        }
    } else {
        caption(ui, NO_PRIOR_WEEK_CAPTION);
    }
    summary_section(
        ui,
        "week-trends-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            caption(
                ui,
                "Active time is time you were actually working this week, idle and sleep \
                 removed; active days count how many of the last 7 days had any recorded \
                 activity.",
            );
            caption(
                ui,
                "App switches per active hour is how often you moved between apps, per hour \
                 of active time. Keystrokes are counted key presses.",
            );
            caption(
                ui,
                "Vs. last week compares each number to the previous 7 days.",
            );
        },
    );

    section_kicker(ui, "WHERE THE TIME WENT");
    if !digest.top_apps.is_empty() {
        top_app_bars(ui, digest);
    } else {
        caption(ui, NO_TOP_APPS_CAPTION);
    }

    // UX-25: plain top-down layouts inside the columns — cross-justify
    // letter-spreads wrapped label lines (the metric_tile gotcha).
    ui.columns(2, |columns| {
        columns[0].with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            morning_launch(ui, digest);
        });
        columns[1].with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            pulls_you_back(ui, digest);
        });
    });

    section_kicker(ui, "CHANGED THIS WEEK");
    if !digest.changed_this_week.is_empty() {
        // Amendment §11: separate takeaway lines with uniform rhythm; the
        // kicker carries "this week", so the labels read New: / Quieter:.
        for change in &digest.changed_this_week {
            let label = if change.direction == "new" {
                "New:"
            } else {
                "Quieter:"
            };
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(
                    RichText::new(label)
                        .color(theme::SILVER)
                        .font(FontId::new(theme::TAKEAWAY_SIZE, theme::family_medium())),
                );
                ui.label(
                    RichText::new(format!("{}.", change.evidence))
                        .color(theme::SILVER)
                        .size(theme::TAKEAWAY_SIZE),
                );
            });
        }
        ui.add_space(2.0);
    } else {
        caption(ui, NO_CHANGES_CAPTION);
    }
    // UX-46: the thresholds render in both states — the empty week is
    // exactly when a user wonders what would count.
    summary_section(
        ui,
        "week-changed-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            caption(ui, CHANGED_NEW_LINE);
            caption(ui, CHANGED_QUIETER_LINE);
            caption(ui, CHANGED_ARCHIVE_LINE);
        },
    );

    section_kicker(ui, "NEW FRICTION THIS WEEK");
    if !digest.friction.is_empty() {
        // UX-37: the hedge lives here once, not on every card — in the
        // secnote register (amendment §6).
        secnote(ui, widgets::PATTERNS_DESCRIPTIVE_CAPTION);
        for candidate in &digest.friction {
            friction_card(ui, candidate);
            ui.add_space(8.0);
        }
    } else {
        // Streamlit passes the digest's distinct-active-day count here — the
        // same floor the pattern miner applies to this week's scope.
        // UX-12: the shared info-box treatment for the empty state.
        widgets::info_box(ui, &patterns_empty_caption(digest.active_days));
    }
}

fn trend_gauges(ui: &mut egui::Ui, digest: &WeeklyDigest) {
    let gauges: [(&str, String); 4] = [
        ("Active time", format_duration_ms(digest.active_ms)),
        ("Active days", format!("{} of 7", digest.active_days)),
        (
            "App switches / active hour",
            digest.switches_per_active_hour.map_or_else(
                || MISSING_VALUE_CELL.to_string(),
                |rate| format!("{rate:.0}"),
            ),
        ),
        ("Keystrokes", thousands(digest.keystrokes)),
    ];
    widgets::gauge_tiles(ui, &gauges);
}

/// Top apps as share bars with mono figures (charter §5): the leader in
/// instrument gray — amber stays the heatmap's. One measure across rows
/// through the shared widget (amendment §10).
fn top_app_bars(ui: &mut egui::Ui, digest: &WeeklyDigest) {
    let total: i64 = digest
        .top_apps
        .iter()
        .map(|row| row.active_ms)
        .sum::<i64>()
        .max(1);
    let rows: Vec<ShareBarRow> = digest
        .top_apps
        .iter()
        .enumerate()
        .map(|(rank, row)| ShareBarRow {
            name: row.app.clone(),
            share: row.active_ms as f32 / total as f32,
            // The leader reads instrument gray; lower ranks step quieter.
            color: theme::series_color(rank + 2),
            figures: format_duration_ms(row.active_ms),
        })
        .collect();
    widgets::share_bars(ui, &rows);
}

fn morning_launch(ui: &mut egui::Ui, digest: &WeeklyDigest) {
    section_kicker(ui, "MORNING LAUNCH");
    if !digest.morning_launch.is_empty() {
        // Glance subsections read kicker → secnote → figure (the owner's
        // round-2 fix, matching the section anatomy elsewhere).
        // UX-41: real pluralization, like the tab's other counts.
        let day_word = if digest.morning_launch_days == 1 {
            "day"
        } else {
            "days"
        };
        secnote(
            ui,
            &format!(
                "The apps you open first, across {} {day_word} this week.",
                digest.morning_launch_days
            ),
        );
        ui.label(
            // copy-allow: arrow ordered app-path data notation (Lane B ruling)
            RichText::new(digest.morning_launch.join(" → "))
                .color(theme::SILVER)
                .font(FontId::new(12.5, egui::FontFamily::Monospace)),
        );
    } else {
        caption(ui, MORNING_LAUNCH_EMPTY);
    }
}

fn pulls_you_back(ui: &mut egui::Ui, digest: &WeeklyDigest) {
    section_kicker(ui, "WHAT PULLS YOU BACK");
    if !digest.first_after_idle.is_empty() {
        // Kicker → secnote → figure (the owner's round-2 fix).
        secnote(ui, PULLS_BACK_CAPTION);
        for row in &digest.first_after_idle {
            let times = if row.count == 1 { "time" } else { "times" };
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(&row.app)
                        .color(theme::SILVER)
                        .font(FontId::new(12.5, egui::FontFamily::Monospace)),
                );
                // Bullet-joined counts (amendment §4): the dot keeps its
                // semantics at legible weight.
                ui.label(
                    RichText::new(format!("• {} {times}", row.count))
                        .color(theme::SILVER_DIM)
                        .size(12.5),
                );
            });
        }
    } else {
        caption(ui, PULLS_BACK_EMPTY);
    }
}

/// One week-scoped friction candidate in the shared observation anatomy
/// (charter §4, amendment §9/§10): title, engraved brass family chip,
/// the signal line, the candidate's own evidence, behind the 2px brass
/// edge. Read-only: the record flow stays Analytics-only.
fn friction_card(ui: &mut egui::Ui, candidate: &PatternCandidate) {
    accent_card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(
                RichText::new(&candidate.title)
                    .color(theme::SILVER)
                    .font(theme::heading_card()),
            );
            family_chip(
                ui,
                &widgets::candidate_kind_label(&candidate.kind).to_uppercase(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!(
                        "signal {} • events {} • recurs {}",
                        candidate.band,
                        thousands(candidate.support_count),
                        thousands(candidate.support_sessions.max(candidate.support_days))
                    ))
                    .color(theme::GRAY)
                    .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                );
            });
        });
        ui.label(
            RichText::new(&candidate.evidence)
                .color(theme::SILVER_DIM)
                .size(13.0),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_parts_match_python_rounding_and_the_one_last_week_shape() {
        assert_eq!(
            delta_part(100.0, 0.0, "active time", ("more", "less")),
            None
        );
        assert_eq!(
            delta_part(150.0, 100.0, "active time", ("more", "less")).as_deref(),
            Some("50% more active time")
        );
        assert_eq!(
            delta_part(50.0, 100.0, "keystrokes", ("more", "less")).as_deref(),
            Some("50% less keystrokes")
        );
        // Rates move higher/lower, not more/less (C-ledger).
        assert_eq!(
            delta_part(14.2, 16.0, "switch rate", ("higher", "lower")).as_deref(),
            Some("11% lower switch rate")
        );
        // UX-42 (owner decision 2026-07-10): the unchanged case reads as
        // unchanged on both readers, never "0% more".
        assert_eq!(
            delta_part(100.0, 100.0, "switch rate", ("higher", "lower")).as_deref(),
            Some("about the same switch rate")
        );
        // A sub-half-percent change rounds to the same-as case too.
        assert_eq!(
            delta_part(100.4, 100.0, "keystrokes", ("more", "less")).as_deref(),
            Some("about the same keystrokes")
        );
        // Python round() is banker's: 12.5% rounds down to the even 12.
        assert_eq!(
            delta_part(112.5, 100.0, "keystrokes", ("more", "less")).as_deref(),
            Some("12% more keystrokes")
        );
        assert_eq!(
            delta_part(113.5, 100.0, "keystrokes", ("more", "less")).as_deref(),
            Some("14% more keystrokes")
        );
    }
}
