//! The Analytics tab in the instrument register (slice 4 of the dashboard
//! register program, charter: the recorded redesign,
//! direction A "One anatomy, signal first" with the Rhythms-first
//! amendment).
//!
//! Rhythms opens the page (the always-populated personal baseline; its
//! heatmap is the page's one amber moment), then Patterns, Focus,
//! Interruption cost, Input load, and Work episodes — every section the
//! same shape: a takeaway sentence, one gauge row, and one plain Details
//! expander carrying the how-measured notes, the research citations
//! verbatim, and a real jump to the section's dense table on the Tables
//! view (registers per the type-ramp amendment). The
//! Analysis/Tables switch is a segmented control on the scope row; what the
//! detectors compute is untouched (NOTICE_V2 / merge-round territory).

use std::collections::{BTreeSet, HashMap};

use egui::{FontId, RichText};
use gilbreth_read::{select_pattern_display_default, PatternCandidate, WorkEpisode};

use super::widgets::{
    self, accent_card, bullet_list, caption, data_table, family_chip, gauge_tiles, info_box,
    patterns_empty_caption, secnote, section_kicker, summary_section, takeaway,
};
use crate::data::{AnalyticsData, AnalyticsSnapshot, ScopeKey};
use crate::format::{
    float_cell, format_duration_minutes, format_duration_ms, format_minutes_metric,
    format_rate_metric, format_seconds_metric, local_clock, opt_float_cell, thousands,
    MISSING_VALUE_CELL, RANGE_SEPARATOR,
};
use crate::theme;

pub const FOREGROUND_MINUTES_CAVEAT: &str = "Active time is time you were actually working, \
     with idle and sleep removed. Time in front counts the app being frontmost even while \
     idle, so it is always larger.";
pub const NO_FRAGMENTATION_INFO: &str =
    "Not enough active focus changes for fragmentation metrics yet.";
pub const NO_ROUNDTRIPS_INFO: &str = "Not enough return round trips to price interruptions yet.";
pub const NO_INPUT_INFO: &str = "No input events in scope yet.";
pub const NO_SUSTAINED_INPUT_INFO: &str =
    "Not enough sustained input for break/exposure metrics yet.";
pub const NO_EPISODES_INFO: &str = "Not enough activity to group into work episodes yet.";
pub const NO_RHYTHM_INFO: &str = "Not enough active history for time-of-day rhythms yet.";
/// UX-05: a snapshot with neither data nor an error still says something.
pub const NO_ANALYTICS_DATA_INFO: &str =
    "Nothing to analyze yet. Analytics fills in once Gilbreth captures activity.";
pub const EMPTY_SPHERE_NAME_ERROR: &str = "A sphere name can't be empty.";
/// UX-31: the merge-by-same-name behavior surfaces at the moment of need.
// copy-allow: em-dash prose em dash within the one-per-string cap (the one-per-string cap), recorded by the Lane B audit
pub const SPHERE_NAME_HINT: &str = "New name — reuse an existing name to merge";
pub const SPHERE_FILTER_HINT: &str = "Filter labels";
/// The sphere combo grows a filter box once its list gets long (UX-31).
const SPHERE_FILTER_MIN_TOKENS: usize = 9;
pub const OVERLAY_ON_NOTICE: &str = "Sphere names are on. Names come from window titles stored \
     on this device and stay here.";
pub const OVERLAY_OFF_NOTICE: &str = "Sphere names are off. Episodes are grouped by app only.";
pub use super::widgets::VIEW_MICRO_LABEL;

/// What the Analytics tab asks the shell to do. Selection changes queue a
/// fresh read; sphere and record actions go through the host callbacks.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalyticsAction {
    SelectScope(ScopeKey),
    SelectSession(Option<i64>),
    SetOverlayEnabled(bool),
    SaveAlias { token: String, name: String },
    RemoveAlias(String),
    RequestRecording(Box<PatternCandidate>),
    EmptyAliasRejected,
}

/// Mirrors the Streamlit `request_key` so one candidate keeps one request.
pub fn record_request_key(candidate: &PatternCandidate) -> String {
    format!(
        "record_request_{}_{}_{}_{}",
        candidate.category, candidate.support_count, candidate.support_days, candidate.title
    )
}

/// Cross-frame state the shell owns for this tab.
pub struct AnalyticsView<'a> {
    pub snapshot: &'a AnalyticsSnapshot,
    /// request_key -> (request_id, last status read).
    pub record_statuses: &'a HashMap<String, (i64, Option<String>)>,
    /// One-shot sphere notice: (is_error, message).
    pub sphere_notice: Option<&'a (bool, String)>,
    /// Record-request failure line, if the last send failed.
    pub record_error: Option<&'a str>,
    pub sidecar_name: &'a str,
    /// The host's CPython-casefold for alias-key lookups.
    pub casefold: &'a (dyn Fn(&str) -> String + Send + Sync),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SubTab {
    #[default]
    Analysis,
    Tables,
}

fn subtab_id(ui: &egui::Ui) -> egui::Id {
    ui.id().with("analytics-subtab")
}

fn jump_target_id() -> egui::Id {
    egui::Id::new("analytics-tables-jump")
}

pub fn show(ui: &mut egui::Ui, view: &AnalyticsView<'_>) -> Vec<AnalyticsAction> {
    let mut actions = Vec::new();
    let snapshot = view.snapshot;
    let Some(data) = &snapshot.data else {
        if let Some(error) = &snapshot.error {
            ui.label(RichText::new(error).color(theme::RED));
        } else {
            // UX-05: data=None + error=None must never render a blank tab.
            info_box(ui, NO_ANALYTICS_DATA_INFO);
        }
        return actions;
    };

    let subtab_id = subtab_id(ui);
    let mut subtab: SubTab = ui
        .ctx()
        .data_mut(|data| *data.get_temp_mut_or_default(subtab_id));
    selectors(ui, snapshot, data, &mut subtab, &mut actions);
    ui.ctx()
        .data_mut(|data| data.insert_temp(subtab_id, subtab));
    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
    }
    ui.add_space(6.0);
    header_gauges(ui, data);
    caption(ui, FOREGROUND_MINUTES_CAVEAT);
    ui.add_space(4.0);

    match subtab {
        SubTab::Analysis => analysis_half(ui, view, data, &mut actions),
        SubTab::Tables => tables_half(ui, data),
    }
    actions
}

/// Queue a jump to a named table: flips the view to Tables and scrolls to
/// that table's kicker on the next frame (the Detail pointers are real
/// jumps, not text).
fn queue_tables_jump(ui: &egui::Ui, anchor: &'static str) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(jump_target_id(), anchor.to_string());
    });
}

/// A table kicker that answers jumps aimed at it.
fn anchored_kicker(ui: &mut egui::Ui, text: &str, anchor: &str) {
    section_kicker(ui, text);
    let pending: Option<String> = ui.ctx().data_mut(|data| data.get_temp(jump_target_id()));
    if pending.as_deref() == Some(anchor) {
        let rect = ui.min_rect();
        ui.scroll_to_rect(
            egui::Rect::from_min_max(egui::pos2(rect.left(), rect.bottom() - 24.0), rect.max),
            Some(egui::Align::Min),
        );
        ui.ctx()
            .data_mut(|data| data.remove::<String>(jump_target_id()));
    }
}

/// One "open the named table" jump button inside a Detail expander.
fn tables_jump_button(ui: &mut egui::Ui, label: &str, anchor: &'static str) {
    if widgets::small_button(ui, label) {
        let id = subtab_id(ui);
        ui.ctx()
            .data_mut(|data| data.insert_temp(id, SubTab::Tables));
        queue_tables_jump(ui, anchor);
    }
}

fn selectors(
    ui: &mut egui::Ui,
    snapshot: &AnalyticsSnapshot,
    data: &AnalyticsData,
    subtab: &mut SubTab,
    actions: &mut Vec<AnalyticsAction>,
) {
    // UX-23: a wrapped row plus an available-width clamp, so the 300 px
    // run selector folds under the scope selector instead of overflowing
    // a narrow window.
    // Reserve the tallest control's height up front. A wrapped horizontal
    // row otherwise grows as controls are added, leaving earlier combo boxes
    // stranded above the final centerline.
    const SELECTOR_ROW_HEIGHT: f32 = 30.0;
    const SWITCHER_CONTENT_HEIGHT: f32 = SELECTOR_ROW_HEIGHT - 2.0;
    let default_interact_height = ui.spacing().interact_size.y;
    ui.spacing_mut().interact_size.y = SELECTOR_ROW_HEIGHT;
    ui.horizontal_wrapped(|ui| {
        let mut scope = snapshot.scope;
        egui::ComboBox::from_id_salt("analytics-scope")
            .selected_text(scope.label())
            .show_ui(ui, |ui| {
                // Keep menu rows at the dashboard's normal interaction
                // height; only the closed toolbar controls are 30 px tall.
                ui.spacing_mut().interact_size.y = default_interact_height;
                for option in ScopeKey::OPTIONS {
                    ui.selectable_value(&mut scope, option, option.label());
                }
            });
        if scope != snapshot.scope {
            actions.push(AnalyticsAction::SelectScope(scope));
        }

        let mut session = snapshot.session_id;
        let selected_label = match session {
            None => "All sessions".to_string(),
            Some(id) => data
                .session_options
                .iter()
                .find(|option| option.session_id == id)
                .map(|option| option.label.clone())
                .unwrap_or_else(|| format!("Session {id}")),
        };
        egui::ComboBox::from_id_salt("analytics-run")
            .selected_text(selected_label)
            .width(300.0_f32.min(ui.available_width().max(120.0)))
            .show_ui(ui, |ui| {
                ui.spacing_mut().interact_size.y = default_interact_height;
                ui.selectable_value(&mut session, None, "All sessions");
                for option in &data.session_options {
                    ui.selectable_value(&mut session, Some(option.session_id), &option.label);
                }
            });
        if session != snapshot.session_id {
            actions.push(AnalyticsAction::SelectSession(session));
        }

        if let Some(fallback_from) = snapshot.fallback_from {
            caption(
                ui,
                &format!(
                    "Showing {}: {} had no data.",
                    snapshot.scope.label(),
                    fallback_from
                ),
            );
        }

        // The Analysis/Tables segmented control at the right end of the
        // scope row (a flip-labeled swap button was considered and
        // rejected: one visible name at a time never teaches that two
        // views exist).
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // The switcher's one-pixel frame adds two pixels around its
            // content. Keep its painted height equal to the combo buttons.
            ui.spacing_mut().interact_size.y = SWITCHER_CONTENT_HEIGHT;
            let mut selected = match *subtab {
                SubTab::Analysis => 0,
                SubTab::Tables => 1,
            };
            widgets::view_switcher(
                ui,
                "analytics-view-segment",
                ["Analysis", "Tables"],
                &mut selected,
            );
            *subtab = if selected == 0 {
                SubTab::Analysis
            } else {
                SubTab::Tables
            };
        });
    });
    ui.spacing_mut().interact_size.y = default_interact_height;
}

fn header_gauges(ui: &mut egui::Ui, data: &AnalyticsData) {
    let top_app = data
        .focus
        .iter()
        .max_by(|left, right| {
            left.active_foreground_minutes
                .partial_cmp(&right.active_foreground_minutes)
                .expect("finite minutes")
        })
        .filter(|row| row.active_foreground_minutes > 0.0)
        .map_or_else(|| MISSING_VALUE_CELL.to_string(), |row| row.app.clone());
    let keystrokes: i64 = data.inputs.iter().map(|row| row.key_events).sum();
    let gauges: [(&str, String); 5] = [
        (
            "Active time",
            format_duration_minutes(data.active_focus_minutes_total),
        ),
        (
            "In front (idle incl.)",
            format_duration_minutes(data.focus_minutes_total),
        ),
        ("Top app (active)", top_app),
        ("Sessions", thousands(data.sessions.len() as i64)),
        ("Keystrokes", thousands(keystrokes)),
    ];
    widgets::gauge_tiles_capped(ui, &gauges, 5);
}

fn analysis_half(
    ui: &mut egui::Ui,
    view: &AnalyticsView<'_>,
    data: &AnalyticsData,
    actions: &mut Vec<AnalyticsAction>,
) {
    // Owner amendment: Rhythms leads — the personal baseline opens the
    // page and its heatmap is the one amber moment.
    rhythms_section(ui, data);
    patterns_section(ui, view, data, actions);
    focus_section(ui, data);
    interruption_section(ui, data);
    input_load_section(ui, data);
    episodes_section(ui, view, data, actions);
}

fn rhythms_section(ui: &mut egui::Ui, data: &AnalyticsData) {
    let rhythm = &data.rhythm;
    section_kicker(ui, "RHYTHMS");
    let heat_total: f64 = rhythm
        .heatmap
        .iter()
        .map(|bucket| bucket.active_minutes)
        .sum();
    if rhythm.heatmap.is_empty() || heat_total <= 0.0 {
        info_box(ui, NO_RHYTHM_INFO);
    } else {
        takeaway(
            ui,
            "Your active hours, from your own history. Brighter is more active.",
        );
        crate::charts::weekday_hour_heatmap(ui, &rhythm.heatmap);
    }

    let mut gauges: Vec<(&str, String, Option<String>)> = Vec::new();
    match rhythm.typing_burst_wpm_median {
        Some(median) => {
            gauges.push((
                "Typing burst, median",
                format!("{median:.0}"),
                Some("wpm".to_string()),
            ));
            if let Some(p90) = rhythm.typing_burst_wpm_p90 {
                gauges.push((
                    "Typing burst, top 10%",
                    format!("{p90:.0}"),
                    Some("wpm".to_string()),
                ));
            }
        }
        None => gauges.push(("Typing burst, median", "not enough data".to_string(), None)),
    }
    if let Some(speed) = rhythm.mouse_velocity_median_px_s {
        gauges.push((
            "Mouse speed, median",
            format!("{speed:.0}"),
            Some("px/s".to_string()),
        ));
    }
    widgets::gauge_tiles_suffixed(ui, &gauges, 4);
    widgets::insight_lines(
        ui,
        &[
            "The top-10% burst pace is quick for you, not a typing norm.",
            "Input rate and speed carry only weak signal about attention or focus \
             (Fogarty et al., TOCHI 2005), so there is no single activity score here.",
            "Friction windows compare each hour to your own recent history: descriptive \
             clusters, not a quality rating.",
        ],
    );

    summary_section(
        ui,
        "analytics-rhythms-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            if let Some(classified) = rhythm.typing_classified_fraction {
                bullet_list(
                    ui,
                    &[&format!(
                        "{:.0}% of key rows had a known key class (printable / navigation / \
                         modifier); older rows are classified from the key name, lean-capture \
                         rows from the stored class.",
                        classified * 100.0
                    )],
                );
            }
            bullet_list(
                ui,
                &[
                    "The heatmap sums active foreground time (idle, sleep, and recovered-power \
                     gaps removed) into hour-of-day x weekday cells. Higher active-time hours \
                     glow brighter, like a long exposure.",
                    "Typing burst rate clusters key presses with gaps of 2 seconds or less, \
                     counts only printable keys (so backspacing and arrow keys don't inflate \
                     it), and reports words per minute by the chars-divided-by-5 convention.",
                    "Mouse speed is distance over duration per movement sample, with \
                     software-KVM / relayed input excluded. Pixel speeds are DPI- and \
                     monitor-relative, so they are within-user only.",
                    "Raw movement rows are kept for a bounded window (default 30 days; \
                     `privacy.mouse_move_retention_days`), so mouse-speed and moves-per-hour \
                     lenses see at most that far back. Keys, clicks, and scrolls keep the full \
                     retention window.",
                ],
            );
            if rhythm.typing_burst_count > 0 {
                caption(
                    ui,
                    &format!(
                        "Based on {} typing bursts and {} mouse-movement samples in scope.",
                        rhythm.typing_burst_count, rhythm.mouse_move_samples
                    ),
                );
            }
            if !rhythm.friction_windows.is_empty() {
                tables_jump_button(ui, "Open in Tables: friction windows", "friction");
            }
        },
    );
}

fn patterns_section(
    ui: &mut egui::Ui,
    view: &AnalyticsView<'_>,
    data: &AnalyticsData,
    actions: &mut Vec<AnalyticsAction>,
) {
    section_kicker(ui, "PATTERNS WORTH REVIEWING");
    if let Some(error) = view.record_error {
        // UXR-20: the failure carries the UX-34 glyph convention, not a
        // bare red label.
        widgets::outcome_notice(ui, true, error);
    }
    if data.candidates.is_empty() {
        // UX-12: one empty-patterns treatment and copy across the tabs —
        // the floor-aware caption inside the info box.
        info_box(ui, &patterns_empty_caption(data.pattern_history_days));
        return;
    }
    // Branch review (UX-12): the Streamlit oracle still renders the
    // below-floor history caption ABOVE candidate cards (churn/clipboard
    // candidates exist below the sequence floor); keep that behavior with
    // the unified copy. The empty state above carries it in the info box.
    if data.pattern_history_days < crate::data::SEQUENCE_MIN_HISTORY_DAYS {
        caption(ui, &patterns_empty_caption(data.pattern_history_days));
    }
    let display = select_pattern_display_default(&data.candidates);
    // UX-37: the hedge lives here once, not on every card; the shared
    // family explainer states once with it (pattern dedupe, charter §2).
    secnote(ui, widgets::PATTERNS_DESCRIPTIVE_CAPTION);
    secnote(
        ui,
        "The strongest card from each pattern family. Repeated tight sequences can point to a \
         manual routine; a shortcut or macro may remove the shuffle.",
    );
    let mut family_counts: HashMap<&str, usize> = HashMap::new();
    for candidate in &data.candidates {
        *family_counts.entry(candidate.kind.as_str()).or_default() += 1;
    }
    // The family dedupe (charter §2): one card per family in the reader's
    // ranking order; every variant waits in the expander below.
    let mut winners: Vec<&PatternCandidate> = Vec::new();
    let mut variants: Vec<&PatternCandidate> = Vec::new();
    let mut seen_families: BTreeSet<&str> = BTreeSet::new();
    for candidate in display.strip.iter().chain(display.remainder.iter()) {
        if seen_families.insert(candidate.kind.as_str()) {
            winners.push(candidate);
        } else {
            variants.push(candidate);
        }
    }
    for candidate in &winners {
        family_card(ui, view, candidate, &family_counts, actions);
        ui.add_space(8.0);
    }
    if !variants.is_empty() {
        let families = seen_families.len();
        let family_noun = if families == 1 { "family" } else { "families" };
        summary_section(
            ui,
            "analytics-all-patterns",
            "All patterns in scope",
            &format!(
                "{} patterns • {families} {family_noun}",
                data.candidates.len()
            ),
            false,
            false,
            |ui| {
                for candidate in &variants {
                    family_card(ui, view, candidate, &family_counts, actions);
                    ui.add_space(8.0);
                }
            },
        );
    }
}

/// One deduplicated family card (charter §2): title, family chip with the
/// variant count, the signal/events/recurrence line, the candidate's own
/// evidence sentence, and the record affordance where applicable. The
/// shared boilerplate lives in the section note, stated once.
/// `view` and `actions` are read only by the Windows-only Record Routine
/// action below; the signature stays identical on every platform so the
/// caller and the card's other sections do not fork.
#[cfg_attr(not(windows), allow(unused_variables, clippy::ptr_arg))]
fn family_card(
    ui: &mut egui::Ui,
    view: &AnalyticsView<'_>,
    candidate: &PatternCandidate,
    family_counts: &HashMap<&str, usize>,
    actions: &mut Vec<AnalyticsAction>,
) {
    accent_card(ui, |ui| {
        let family = widgets::candidate_kind_label(&candidate.kind).to_uppercase();
        let variants = family_counts
            .get(candidate.kind.as_str())
            .copied()
            .unwrap_or(1);
        let chip = if variants > 1 {
            format!("{family} • {variants} VARIANTS")
        } else {
            family
        };
        widgets::card_title_row(ui, &candidate.title, &chip, |ui| {
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
        // Record Routine is Windows-only by decision record, so macOS offers
        // no way to ask for a recording and shows no request status. The
        // candidate and its evidence still render — the pattern is real on
        // every platform; only the action that cannot be honoured is absent.
        #[cfg(windows)]
        if candidate.kind == "automatable_routine" {
            ui.add_space(2.0);
            if widgets::notice_action_button(ui, widgets::RECORD_BUTTON_LABEL, "") {
                actions.push(AnalyticsAction::RequestRecording(Box::new(
                    candidate.clone(),
                )));
            }
            let status = view
                .record_statuses
                .get(&record_request_key(candidate))
                .and_then(|(_, status)| status.as_deref());
            if let Some(status) = status {
                // UX-45: one sentence, one meaning — never the sent
                // caption plus a raw status token.
                caption(ui, &widgets::record_status_line(status));
            }
        }
    });
}

fn focus_section(ui: &mut egui::Ui, data: &AnalyticsData) {
    let fragmentation = &data.fragmentation;
    section_kicker(ui, "FOCUS");
    if fragmentation.breakdown.is_empty()
        && fragmentation.median_sustained_focus_run_minutes.is_none()
    {
        info_box(ui, NO_FRAGMENTATION_INFO);
        return;
    }
    if let Some(median) = fragmentation.median_sustained_focus_run_minutes {
        takeaway(
            ui,
            &format!(
                "Focus runs {} before something pulls you away.",
                format_duration_minutes(median)
            ),
        );
    }
    let gauges: [(&str, String); 5] = [
        (
            "Median focus run",
            format_minutes_metric(fragmentation.median_sustained_focus_run_minutes),
        ),
        (
            "Switches per hour",
            format_rate_metric(fragmentation.sustained_switches_per_active_hour),
        ),
        (
            "Median time away",
            if fragmentation.anchor_returns > 0 {
                format_minutes_metric(fragmentation.median_active_diversion_minutes)
            } else {
                MISSING_VALUE_CELL.to_string()
            },
        ),
        (
            "Returns to anchor app",
            if fragmentation.anchor_returns > 0 {
                thousands(fragmentation.anchor_returns)
            } else {
                MISSING_VALUE_CELL.to_string()
            },
        ),
        (
            "Lag before typing resumes",
            format_seconds_metric(fragmentation.median_resumption_lag_seconds),
        ),
    ];
    widgets::gauge_tiles_capped(ui, &gauges, 5);
    widgets::insight_lines(
        ui,
        &[
            "Mark et al.'s famous ~25m resume figure measures wall-clock working spheres; \
             Gilbreth reports active app-focus time, so the numbers are not directly \
             comparable.",
        ],
    );
    summary_section(
        ui,
        "analytics-focus-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            bullet_list(
                ui,
                &[
                    "App-focus metrics are estimated from foreground app changes. Active time \
                     subtracts idle, sleep, and recovered power gaps.",
                    "The focus-run headline and switch rate use app-focus runs of at least 15 \
                     seconds to reduce tab-through noise, following the Iqbal & Horvitz \
                     desktop-log filtering heuristic. Raw per-app median runs remain in the \
                     table.",
                    "Returns to anchor app count first returns on merged active-focus runs \
                     (active time), a different measurement than the 'You keep leaving and \
                     returning to ...' cards above, which count round trips on wall-clock \
                     episodes. The two numbers can differ for the same app. Median time away \
                     shows a dash until the same diversions recur enough to measure.",
                    "Lag before typing resumes is the time from refocusing an app (after a \
                     diversion) to your first key/click/scroll there. It is a seconds-scale \
                     proxy for getting back into a task (Altmann & Trafton), distinct from the \
                     minutes-scale time-away above. It counts all returns, not only gated \
                     anchors.",
                    // copy-allow: em-dash missing-value cell notation, not prose (UX-10 ruling)
                    "In the by-app table, per-app switch rate is hidden (—) for apps with under \
                     5 active minutes, where the rate is too sample-poor to be reliable.",
                ],
            );
            if !fragmentation.breakdown.is_empty() {
                tables_jump_button(ui, "Open in Tables: focus by app", "focus-by-app");
            }
        },
    );
}

fn interruption_section(ui: &mut egui::Ui, data: &AnalyticsData) {
    let costs = &data.interruption;
    section_kicker(ui, "INTERRUPTION COST");
    if costs.total_roundtrips == 0 {
        info_box(ui, NO_ROUNDTRIPS_INFO);
        return;
    }
    if let Some(median) = costs.median_restart_seconds {
        takeaway(
            ui,
            &format!(
                "Getting back after a pull-away costs {} before input resumes.",
                format_seconds_metric(Some(median))
            ),
        );
    }
    let gauges: [(&str, String); 4] = [
        ("Round trips", thousands(costs.total_roundtrips)),
        (
            "Median restart",
            format_seconds_metric(costs.median_restart_seconds),
        ),
        (
            "Restart toll, est.",
            format_minutes_metric(costs.estimated_restart_minutes),
        ),
        (
            "Time away in diversions",
            format_minutes_metric(Some(costs.total_away_minutes)),
        ),
    ];
    gauge_tiles(ui, &gauges);
    widgets::insight_lines(
        ui,
        &[
            "In a field study of information workers, people averaged about three minutes \
             on a task before switching (González & Mark, CHI 2004).",
            "Trips overlap and nest, so time away in diversions can exceed the period's \
             active time.",
        ],
    );
    summary_section(
        ui,
        "analytics-interruption-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            bullet_list(
                ui,
                &[
                    "Each round trip leaves an app, spends active time elsewhere, and pays a \
                     restart toll on return: the gap between refocusing and your first key, \
                     click, or scroll there.",
                    "Median restart shows once at least 3 restarts were measurable. Restart \
                     toll is round trips times the median restart; the median keeps long \
                     passive returns (reading, watching) from dominating the estimate.",
                    "Time away in diversions adds up active time spent elsewhere during these \
                     round trips.",
                ],
            );
            if costs.estimated_restart_minutes.is_some() {
                caption(
                    ui,
                    &format!(
                        "Restart toll is estimated from {} of {} round trips where a restart \
                         was measurable (the rest returned with no recorded input), scaled by \
                         the median.",
                        costs.measured_restarts, costs.total_roundtrips
                    ),
                );
            }
            if !costs.pairs.is_empty() {
                tables_jump_button(ui, "Open in Tables: where pull-aways go", "pull-aways");
            }
        },
    );
}

fn input_load_section(ui: &mut egui::Ui, data: &AnalyticsData) {
    let exposure = &data.input_exposure;
    section_kicker(ui, "INPUT LOAD");
    // The 2026-07-28 walk: the face caption was redundant with the
    // methodology bullets; the medical boundary stays as the lead bullet
    // in Details (the disclaimers-stay rule), just not in the headline.
    if exposure.total_input_events == 0 {
        info_box(ui, NO_INPUT_INFO);
        return;
    }
    if !exposure.has_sustained_input {
        info_box(ui, NO_SUSTAINED_INPUT_INFO);
        return;
    }
    if let Some(per_day) = exposure.active_input_minutes_per_day {
        let band_phrase = match exposure.day_band.as_deref() {
            Some("high") => ", in the high population band (over 6h per day)",
            Some("elevated") => ", in the elevated population band (over 4h per day)",
            Some("normal") => ", below the 4h per day population band",
            _ => "",
        };
        takeaway(
            ui,
            &format!(
                "Input runs {} per day{band_phrase}.",
                format_duration_minutes(per_day)
            ),
        );
    }
    let gauges: [(&str, String); 4] = [
        (
            "Active input, per day",
            format_minutes_metric(exposure.active_input_minutes_per_day),
        ),
        (
            "Longest unbroken run",
            format_minutes_metric(exposure.longest_run_minutes),
        ),
        (
            "Runs over 20 min",
            thousands(exposure.runs_over_break_target),
        ),
        (
            "Input events per active hour",
            format_rate_metric(exposure.input_events_per_active_hour),
        ),
    ];
    gauge_tiles(ui, &gauges);
    widgets::insight_lines(
        ui,
        &[
            "Microbreak research found the greatest benefit at about every 20 minutes \
             (McLean et al., 2001); we suggest short breaks roughly every 20-30 min.",
            "Treat the population bands as soft context, not a personal risk score.",
        ],
    );
    summary_section(
        ui,
        "analytics-input-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            bullet_list(
                ui,
                &[
                    "This is an exposure proxy from input-activity logs; it is not a medical \
                     or RSI assessment.",
                    "Active input time = key/mouse activity intersected with foreground focus, \
                     after idle, sleep, and recovered-power gaps are removed.",
                    "Breaks are only pauses of 3 minutes or more, so brief micro-pauses are \
                     invisible and recovery is undercounted.",
                    "No posture, force, grip, or muscle load is captured. The strongest \
                     musculoskeletal factors are not visible to Gilbreth.",
                    "Software-KVM / relayed mouse input is excluded.",
                    "Exposure associations are strongest for self-reported time; measured time \
                     like this shows weaker links.",
                    "Population bands: over 4h per day is the elevated band, over 6h the high \
                     band (Health Council of the Netherlands, 2012).",
                ],
            );
            if !exposure.breakdown.is_empty() {
                tables_jump_button(ui, "Open in Tables: input load by app", "input-by-app");
            }
        },
    );
}

fn episode_composition_text(apps: &[gilbreth_read::AppDwell]) -> String {
    let mut parts: Vec<String> = apps
        .iter()
        .take(4)
        .map(|dwell| format!("{} {}", dwell.app, format_duration_ms(dwell.active_ms)))
        .collect();
    if apps.len() > 4 {
        parts.push(format!("+{} more", apps.len() - 4));
    }
    parts.join(", ")
}

/// UX-17 / UXR-19: one range separator constant across every sibling table;
/// the date joins with the bullet (amendment §4 — the en dash stays the
/// range's).
fn episode_when(episode: &WorkEpisode) -> String {
    format!(
        "{}{RANGE_SEPARATOR}{} • {}",
        local_clock(episode.start_ms),
        local_clock(episode.end_ms),
        episode.local_date
    )
}

fn fragmented_episodes(episodes: &[WorkEpisode]) -> Vec<&WorkEpisode> {
    let mut fragmented: Vec<&WorkEpisode> = episodes
        .iter()
        .filter(|episode| episode.active_ms >= 10 * 60_000 && episode.switch_count >= 8)
        .collect();
    fragmented.sort_by(|left, right| {
        let rate = |episode: &WorkEpisode| {
            episode.switch_count as f64 / (episode.active_ms as f64 / 3_600_000.0).max(1e-9)
        };
        (rate(right), right.switch_count)
            .partial_cmp(&(rate(left), left.switch_count))
            .expect("finite rates")
    });
    fragmented
}

fn switch_rate_cell(episode: &WorkEpisode) -> String {
    let rate = episode.switch_count as f64 / (episode.active_ms as f64 / 3_600_000.0).max(1e-9);
    float_cell((rate * 10.0).round() / 10.0)
}

const SPHERE_DISPLAY_LIMIT: usize = 15;

fn episodes_section(
    ui: &mut egui::Ui,
    view: &AnalyticsView<'_>,
    data: &AnalyticsData,
    actions: &mut Vec<AnalyticsAction>,
) {
    section_kicker(ui, "WORK EPISODES");
    if let Some((is_error, message)) = view.sphere_notice {
        // UX-34: glyph beside the color, never hue alone.
        widgets::outcome_notice(ui, *is_error, message);
        ui.add_space(2.0);
    }
    let (episode_count, total_active_ms, median_ms, named_share) = match &data.sphere_overlay {
        Some(overlay) => (
            overlay.episodes.len(),
            overlay.total_active_ms,
            None,
            overlay.labeled_fraction,
        ),
        None => (
            data.spheres.episodes.len(),
            data.spheres.total_active_ms,
            data.spheres.median_episode_ms,
            None,
        ),
    };
    if episode_count == 0 {
        info_box(ui, NO_EPISODES_INFO);
        if data.sphere_overlay.is_some() && widgets::small_button(ui, "Turn off names from titles")
        {
            actions.push(AnalyticsAction::SetOverlayEnabled(false));
        }
        return;
    }
    let grouping = if data.sphere_overlay.is_some() {
        "named from the window titles stored on this device"
    } else {
        "grouped by app, no titles read"
    };
    match median_ms {
        Some(median) => takeaway(
            ui,
            &format!(
                "Active time groups into {episode_count} episodes; the median runs {}.",
                format_duration_ms(median)
            ),
        ),
        None => takeaway(
            ui,
            &format!("Active time groups into {episode_count} episodes."),
        ),
    }
    caption(
        ui,
        &format!(
            "A work episode is a continuous spell of activity, split where you were away for \
             more than 5 minutes; {grouping}.",
        ),
    );
    let mut gauges: Vec<(&str, String)> = vec![
        ("Episodes", thousands(episode_count as i64)),
        ("Active time", format_duration_ms(total_active_ms)),
    ];
    if let Some(median) = median_ms {
        gauges.push(("Median episode", format_duration_ms(median)));
    }
    if data.sphere_overlay.is_some() {
        let named = named_share.map_or_else(
            || MISSING_VALUE_CELL.to_string(),
            |value| format!("{:.0}%", value * 100.0),
        );
        gauges.push(("Time with a name", named));
    }
    gauge_tiles(ui, &gauges);
    // The 2026-07-28 UI/UX pass: the section shows its five longest
    // episodes instead of hiding everything behind Tables, and the
    // sphere-naming tooling moves out of the methodology expander into
    // its own section below.
    let episodes = match &data.sphere_overlay {
        Some(overlay) => &overlay.episodes,
        None => &data.spheres.episodes,
    };
    let mut longest: Vec<&gilbreth_read::WorkEpisode> = episodes.iter().collect();
    longest.sort_by(|left, right| right.active_ms.cmp(&left.active_ms));
    longest.truncate(5);
    if !longest.is_empty() {
        ui.add_space(4.0);
        ui.label(
            RichText::new("Longest episodes")
                .color(theme::SILVER)
                .font(FontId::new(12.5, theme::family_medium())),
        );
        // An in-section summary, not a Tables-view export surface: body
        // typography and no scroll area — the name column is clamped so
        // the grid always fits the card (the 2026-07-28 walk).
        egui::Grid::new("analytics-episodes-longest")
            .spacing(egui::vec2(18.0, 3.0))
            .show(ui, |ui| {
                for header in ["When", "Name", "Active", "Switches"] {
                    ui.label(RichText::new(header).color(theme::GRAY).size(11.5));
                }
                ui.end_row();
                for episode in &longest {
                    let name = episode
                        .sphere
                        .clone()
                        .unwrap_or_else(|| episode.dominant_app.clone());
                    ui.label(
                        RichText::new(format!(
                            "{} {}",
                            episode.local_date,
                            local_clock(episode.start_ms)
                        ))
                        .color(theme::SILVER_DIM)
                        .size(12.5),
                    );
                    ui.label(
                        RichText::new(ellipsize(&name, 40))
                            .color(theme::SILVER)
                            .size(12.5),
                    );
                    ui.label(
                        RichText::new(format_duration_ms(episode.active_ms))
                            .color(theme::SILVER_DIM)
                            .size(12.5),
                    );
                    ui.label(
                        RichText::new(thousands(episode.switch_count))
                            .color(theme::SILVER_DIM)
                            .size(12.5),
                    );
                    ui.end_row();
                }
            });
    }
    summary_section(
        ui,
        "analytics-episodes-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            // The split rule lives in the caption above; these carry only
            // what the caption does not.
            bullet_list(
                ui,
                &[
                    "Switches count app changes within an episode; switch density is \
                     switches per active hour.",
                    "Time with a name is the share of active time where a window title \
                     named the episode; untitled episodes stay grouped by app.",
                ],
            );
            tables_jump_button(ui, "Open in Tables: work episodes", "episodes");
        },
    );
    summary_section(
        ui,
        "analytics-episode-names",
        "Episode names",
        "",
        false,
        false,
        |ui| match &data.sphere_overlay {
            Some(overlay) => {
                rename_merge_controls(ui, view, data, overlay, actions);
                ui.add_space(6.0);
                if widgets::small_button(ui, "Turn off names from titles") {
                    actions.push(AnalyticsAction::SetOverlayEnabled(false));
                }
            }
            None => naming_opt_in(ui, actions),
        },
    );
}

/// Char-boundary-safe display truncation for title-derived labels; the
/// full text stays available where it matters (the combo popup, Tables).
fn ellipsize(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let mut shortened: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        shortened.push('…');
        shortened
    }
}

fn naming_opt_in(ui: &mut egui::Ui, actions: &mut Vec<AnalyticsAction>) {
    ui.label(
        RichText::new("Name these episodes from window titles (optional)")
            .color(theme::SILVER)
            .font(FontId::new(12.5, theme::family_medium())),
    );
    ui.label(
        RichText::new(
            "Gilbreth can name each episode after what you were working on, using the \
             window titles it already stores on this device.",
        )
        .color(theme::SILVER_DIM)
        .size(12.5),
    );
    bullet_list(
        ui,
        &[
            "Names are read at view time, on this machine only. Nothing new is captured, and \
             names are never part of exports or archives.",
            "Titles can include document and page names. If you'd rather not read them at \
             all, leave this off; the app-level view keeps working.",
            "You can rename or merge the suggested names, and turn this off again any time.",
            "App-level grouping is coarse: a project boundary often lives inside the browser, \
             invisible to app-level signal. Names from titles recover it.",
        ],
    );
    if widgets::small_button(ui, "Turn on names from titles") {
        actions.push(AnalyticsAction::SetOverlayEnabled(true));
    }
}

fn rename_merge_controls(
    ui: &mut egui::Ui,
    view: &AnalyticsView<'_>,
    data: &AnalyticsData,
    overlay: &gilbreth_read::SphereOverlay,
    actions: &mut Vec<AnalyticsAction>,
) {
    ui.label(
        RichText::new("Rename or merge spheres")
            .color(theme::SILVER)
            .font(FontId::new(12.5, theme::family_medium())),
    );
    caption(
        ui,
        &format!(
            "Pick a label and give it the name you actually use. Two labels with the same \
             name merge into one sphere. Saved on this device only, in {}.",
            view.sidecar_name
        ),
    );
    // UXR-16: the lowered forms are computed once per frame beside the
    // tokens, not per token inside the open popup.
    let tokens: Vec<(String, String)> = overlay
        .spheres
        .iter()
        .flat_map(|row| row.tokens.iter().cloned())
        .chain(data.aliases.keys().cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .map(|token| {
            let lowered = token.to_lowercase();
            (token, lowered)
        })
        .collect();
    if tokens.is_empty() {
        caption(ui, "No labels to rename yet.");
    } else {
        let selected_id = ui.id().with("sphere-alias-token");
        let mut selected: String = ui.ctx().data_mut(|store| {
            store
                .get_temp(selected_id)
                .unwrap_or_else(|| tokens[0].0.clone())
        });
        if !tokens.iter().any(|(token, _)| *token == selected) {
            selected = tokens[0].0.clone();
        }
        // UX-23: wrapped row + clamps so the combo and name field fold
        // instead of overflowing a narrow window.
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let filter_id = ui.id().with("sphere-token-filter");
            egui::ComboBox::from_id_salt("sphere-alias-token")
                // Title-derived labels can be sentence-long; the button
                // shows a clamped preview, the popup shows full labels.
                .selected_text(ellipsize(&selected, 34))
                .width(240.0_f32.min(ui.available_width().max(120.0)))
                .show_ui(ui, |ui| {
                    // UX-31: dozens of title-derived labels need a
                    // filter box, not a scroll hunt.
                    let mut filter: String = ui
                        .ctx()
                        .data_mut(|store| store.get_temp(filter_id).unwrap_or_default());
                    // Branch review (UX-31): visibility and application
                    // share one condition — a stored needle always
                    // renders the box, so it can never keep filtering
                    // invisibly after the token count drops.
                    let show_filter =
                        tokens.len() >= SPHERE_FILTER_MIN_TOKENS || !filter.is_empty();
                    if show_filter
                        && ui
                            .add(
                                egui::TextEdit::singleline(&mut filter)
                                    .hint_text(SPHERE_FILTER_HINT),
                            )
                            .changed()
                    {
                        ui.ctx()
                            .data_mut(|store| store.insert_temp(filter_id, filter.clone()));
                    }
                    let needle = filter.to_lowercase();
                    for (token, lowered) in tokens
                        .iter()
                        .filter(|(_, lowered)| needle.is_empty() || lowered.contains(&needle))
                    {
                        ui.selectable_value(&mut selected, token.clone(), token);
                        let _ = lowered;
                    }
                });
            // Keyed per label so switching labels shows that label's
            // current name instead of carrying over the previous edit.
            let buffer_id = ui.id().with(("sphere-alias-name", selected.as_str()));
            let current = data
                .aliases
                .get(&(view.casefold)(&selected))
                .cloned()
                .unwrap_or_else(|| selected.clone());
            let mut name: String = ui
                .ctx()
                .data_mut(|store| store.get_temp(buffer_id).unwrap_or(current));
            // A resting TextEdit inherits no border from the dark theme
            // and read as plain text beside the combo; a visible stroke
            // makes it an obvious input (the 2026-07-28 walk).
            ui.scope(|ui| {
                ui.style_mut().visuals.widgets.inactive.bg_stroke =
                    egui::Stroke::new(1.0, theme::GRAY);
                ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .hint_text(SPHERE_NAME_HINT)
                        .desired_width(260.0_f32.min(ui.available_width().max(120.0))),
                );
            });
            ui.ctx()
                .data_mut(|store| store.insert_temp(buffer_id, name.clone()));
            if widgets::small_button(ui, "Save name") {
                let cleaned = name.trim().to_string();
                if cleaned.is_empty() {
                    actions.push(AnalyticsAction::EmptyAliasRejected);
                } else {
                    actions.push(AnalyticsAction::SaveAlias {
                        token: selected.clone(),
                        name: cleaned,
                    });
                }
            }
        });
        ui.ctx()
            .data_mut(|store| store.insert_temp(selected_id, selected));
    }

    if !data.aliases.is_empty() {
        caption(ui, "Names you've set:");
        for (alias_key, alias_value) in &data.aliases {
            ui.horizontal(|ui| {
                ui.label(RichText::new(alias_key).color(theme::SILVER).size(12.5));
                ui.label(
                    RichText::new(format!("shows as {alias_value}"))
                        .color(theme::SILVER_DIM)
                        .size(12.5),
                );
                if widgets::small_button(ui, "Remove") {
                    actions.push(AnalyticsAction::RemoveAlias(alias_key.clone()));
                }
            });
        }
    }
}

// ------------------------------------------------------------- tables view

fn tables_half(ui: &mut egui::Ui, data: &AnalyticsData) {
    anchored_kicker(ui, "APP FOCUS", "app-focus");
    let rows: Vec<Vec<String>> = data
        .focus
        .iter()
        .map(|row| {
            vec![
                row.app.clone(),
                format_duration_minutes(row.focus_minutes),
                format_duration_minutes(row.active_foreground_minutes),
                thousands(row.focus_switches),
                format_duration_minutes(row.avg_dwell_seconds / 60.0),
                thousands(row.support_sessions),
                thousands(row.support_days),
            ]
        })
        .collect();
    data_table(
        ui,
        "table-focus",
        &[
            "App",
            "Time in front",
            "Active time",
            "Focus switches",
            "Avg dwell",
            "Sessions seen",
            "Days seen",
        ],
        &rows,
    );

    anchored_kicker(ui, "FOCUS BY APP", "focus-by-app");
    if data.fragmentation.breakdown.is_empty() {
        caption(ui, "No fragmentation rows in this scope.");
    } else {
        caption(ui, "Fragmentation by app (top 25 by active minutes).");
        let rows: Vec<Vec<String>> = data
            .fragmentation
            .breakdown
            .iter()
            .map(|row| {
                vec![
                    row.app.clone(),
                    format_duration_minutes(row.active_minutes),
                    thousands(row.same_app_focus_runs),
                    row.median_run_minutes
                        .map_or_else(|| MISSING_VALUE_CELL.to_string(), format_duration_minutes),
                    opt_float_cell(row.sustained_switches_per_active_hour),
                    thousands(row.anchor_returns),
                    row.median_active_diversion_minutes
                        .map_or_else(|| MISSING_VALUE_CELL.to_string(), format_duration_minutes),
                    opt_float_cell(row.median_intervening_app_focus_segments),
                    opt_float_cell(row.median_resumption_lag_seconds),
                ]
            })
            .collect();
        data_table(
            ui,
            "fragmentation-breakdown",
            &[
                "App",
                "Active time",
                "Focus runs",
                "Median run",
                "Switches/hour",
                "Anchor returns",
                "Median diversion",
                "Apps between (median)",
                "Resumption lag (s)",
            ],
            &rows,
        );
    }

    anchored_kicker(ui, "WHERE PULL-AWAYS GO", "pull-aways");
    if data.interruption.pairs.is_empty() {
        caption(ui, "No round-trip pairs in this scope.");
    } else {
        caption(
            ui,
            "The first app you switched into, the app you left, and the price of coming \
             back. Pairs shown after 3 or more round trips.",
        );
        let rows: Vec<Vec<String>> = data
            .interruption
            .pairs
            .iter()
            .map(|pair| {
                vec![
                    pair.diverter.clone(),
                    pair.anchor.clone(),
                    thousands(pair.count),
                    thousands(pair.days),
                    pair.median_away_minutes
                        .map_or_else(|| MISSING_VALUE_CELL.to_string(), format_duration_minutes),
                    opt_float_cell(pair.median_restart_seconds),
                    pair.estimated_restart_minutes
                        .map_or_else(|| MISSING_VALUE_CELL.to_string(), format_duration_minutes),
                ]
            })
            .collect();
        data_table(
            ui,
            "interruption-pairs",
            &[
                "Pulled into",
                "While in",
                "Round trips",
                "Days seen",
                "Median away",
                "Median restart (s)",
                "Restart toll (est.)",
            ],
            &rows,
        );
    }

    anchored_kicker(ui, "INPUT LOAD BY APP", "input-by-app");
    if data.input_exposure.breakdown.is_empty() {
        caption(ui, "No input rows in this scope.");
    } else {
        caption(ui, "Input load by app (top 25 by active input time).");
        let rows: Vec<Vec<String>> = data
            .input_exposure
            .breakdown
            .iter()
            .map(|row| {
                vec![
                    row.app.clone(),
                    format_duration_minutes(row.active_input_minutes),
                    opt_float_cell(row.keystrokes_per_hour),
                    opt_float_cell(row.clicks_per_hour),
                    opt_float_cell(row.moves_per_hour),
                    opt_float_cell(row.scrolls_per_hour),
                    thousands(row.total_input_events),
                ]
            })
            .collect();
        data_table(
            ui,
            "exposure-breakdown",
            &[
                "App",
                "Active input time",
                "Keys/hour",
                "Clicks/hour",
                "Moves/hour",
                "Scrolls/hour",
                "Input events",
            ],
            &rows,
        );
    }

    episodes_tables(ui, data);
    friction_table(ui, data);

    anchored_kicker(ui, "SESSIONS", "sessions");
    let no_idle_data = !data.sessions.is_empty()
        && data
            .sessions
            .iter()
            .all(|row| row.idle_events == 0 && row.active_events == 0);
    if no_idle_data {
        caption(ui, "No idle/active data in this scope.");
    }
    // UX-48: full timestamps, seconds included — no silent truncation.
    let rows: Vec<Vec<String>> = data
        .sessions
        .iter()
        .map(|row| {
            let mut cells = vec![
                thousands(row.session_id),
                row.started_at.clone(),
                row.ended_at
                    .clone()
                    .unwrap_or_else(|| "ongoing".to_string()),
                format_duration_minutes(row.active_foreground_minutes),
                format_duration_minutes(row.active_span_minutes),
            ];
            if !no_idle_data {
                cells.push(format_duration_minutes(row.idle_minutes));
            }
            cells.push(thousands(row.event_count));
            if !no_idle_data {
                cells.push(thousands(row.idle_events));
                cells.push(thousands(row.active_events));
            }
            cells
        })
        .collect();
    let headers: Vec<&str> = if no_idle_data {
        vec![
            "Session",
            "Started",
            "Ended",
            "Active time",
            "Session span",
            "Events",
        ]
    } else {
        vec![
            "Session",
            "Started",
            "Ended",
            "Active time",
            "Session span",
            "Idle time",
            "Events",
            "Idle events",
            "Active events",
        ]
    };
    data_table(ui, "table-sessions", &headers, &rows);

    anchored_kicker(ui, "INPUT SUMMARY", "input-summary");
    caption(
        ui,
        "Keystrokes are press-event counts with held-key auto-repeat suppressed; raw key \
         values are not shown here. Suspected software-KVM mouse rows are separated from \
         local mouse counts.",
    );
    let rows: Vec<Vec<String>> = data
        .inputs
        .iter()
        .map(|row| {
            vec![
                row.app.clone(),
                thousands(row.key_events),
                float_cell(row.ctrl_rate),
                float_cell(row.alt_rate),
                float_cell(row.shift_rate),
                float_cell(row.win_rate),
                thousands(row.mouse_clicks),
                thousands(row.mouse_moves),
                thousands(row.mouse_wheels),
                thousands(row.remote_relay_suspected_events),
                thousands(row.total_input_events),
            ]
        })
        .collect();
    data_table(
        ui,
        "table-inputs",
        &[
            "App",
            "Key events",
            "Ctrl rate",
            "Alt rate",
            "Shift rate",
            "Win rate",
            "Clicks",
            "Moves",
            "Wheels",
            "Suspected relay",
            "Total inputs",
        ],
        &rows,
    );

    anchored_kicker(ui, "WINDOW LIFECYCLE", "window-lifecycle");
    caption(
        ui,
        "Open duration uses observed window closes only; startup-seeded and \
         shutdown-synthesized closes are excluded.",
    );
    let rows: Vec<Vec<String>> = data
        .lifecycle
        .iter()
        .map(|row| {
            vec![
                row.app.clone(),
                thousands(row.opened_windows),
                thousands(row.closed_windows),
                format_duration_minutes(row.median_open_seconds / 60.0),
                format_duration_minutes(row.avg_open_seconds / 60.0),
                thousands(row.support_sessions),
                thousands(row.support_days),
            ]
        })
        .collect();
    data_table(
        ui,
        "table-lifecycle",
        &[
            "App",
            "Opened",
            "Closed",
            "Median open",
            "Avg open",
            "Sessions seen",
            "Days seen",
        ],
        &rows,
    );
}

/// The episode tables (skeleton or overlay mode) on the Tables view: the
/// dense register the Analysis section's Detail points at.
fn episodes_tables(ui: &mut egui::Ui, data: &AnalyticsData) {
    anchored_kicker(ui, "WORK EPISODES", "episodes");
    match &data.sphere_overlay {
        None => {
            let skeleton = &data.spheres;
            if skeleton.episodes.is_empty() {
                caption(ui, "No work episodes in this scope.");
                return;
            }
            let fragmented = fragmented_episodes(&skeleton.episodes);
            if !fragmented.is_empty() {
                caption(
                    ui,
                    "Most fragmented app-only episodes. Switch density is switches per active \
                     hour inside the episode.",
                );
                let rows: Vec<Vec<String>> = fragmented
                    .iter()
                    .take(SPHERE_DISPLAY_LIMIT)
                    .map(|episode| {
                        vec![
                            episode_when(episode),
                            episode.dominant_app.clone(),
                            format_duration_ms(episode.active_ms),
                            thousands(episode.switch_count),
                            switch_rate_cell(episode),
                            episode_composition_text(&episode.apps),
                        ]
                    })
                    .collect();
                data_table(
                    ui,
                    "sphere-fragmented",
                    &[
                        "When",
                        "Dominant app",
                        "Active",
                        "Switches",
                        "Switches/hour",
                        "Apps",
                    ],
                    &rows,
                );
            }

            caption(
                ui,
                "Longest episodes (by active time). Switches count app changes within the \
                 episode.",
            );
            let mut longest: Vec<&WorkEpisode> = skeleton.episodes.iter().collect();
            longest.sort_by_key(|episode| -episode.active_ms);
            let rows: Vec<Vec<String>> = longest
                .iter()
                .take(SPHERE_DISPLAY_LIMIT)
                .map(|episode| {
                    vec![
                        episode_when(episode),
                        format_duration_ms(episode.active_ms),
                        episode_composition_text(&episode.apps),
                        thousands(episode.switch_count),
                    ]
                })
                .collect();
            data_table(
                ui,
                "sphere-longest",
                &["When", "Active", "Apps (by active time)", "Switches"],
                &rows,
            );

            if !skeleton.app_rollup.is_empty() {
                caption(
                    ui,
                    "Recurring contexts: episodes grouped by their busiest app. Turn on names \
                     (Analysis, Work episodes, Detail) to see project-level spheres.",
                );
                let rows: Vec<Vec<String>> = skeleton
                    .app_rollup
                    .iter()
                    .map(|row| {
                        vec![
                            row.app.clone(),
                            thousands(row.episode_count),
                            format_duration_ms(row.active_ms),
                            thousands(row.days),
                        ]
                    })
                    .collect();
                data_table(
                    ui,
                    "sphere-rollup",
                    &["App", "Episodes", "Active time", "Days seen"],
                    &rows,
                );
            }
        }
        Some(overlay) => {
            if overlay.episodes.is_empty() {
                caption(ui, "No work episodes in this scope.");
                return;
            }
            let fragmented = fragmented_episodes(&overlay.episodes);
            if !fragmented.is_empty() {
                caption(
                    ui,
                    "Most fragmented app-only episodes. Names are supporting context; the \
                     switch-density signal is app-only.",
                );
                let rows: Vec<Vec<String>> = fragmented
                    .iter()
                    .take(SPHERE_DISPLAY_LIMIT)
                    .map(|episode| {
                        vec![
                            episode
                                .sphere
                                .clone()
                                .unwrap_or_else(|| "(no title signal)".to_string()),
                            episode_when(episode),
                            episode.dominant_app.clone(),
                            format_duration_ms(episode.active_ms),
                            thousands(episode.switch_count),
                            switch_rate_cell(episode),
                            episode_composition_text(&episode.apps),
                        ]
                    })
                    .collect();
                data_table(
                    ui,
                    "overlay-fragmented",
                    &[
                        "Sphere",
                        "When",
                        "Dominant app",
                        "Active",
                        "Switches",
                        "Switches/hour",
                        "Apps",
                    ],
                    &rows,
                );
            }

            if !overlay.spheres.is_empty() {
                let rows: Vec<Vec<String>> = overlay
                    .spheres
                    .iter()
                    .map(|row| {
                        vec![
                            row.sphere.clone(),
                            thousands(row.episode_count),
                            format_duration_ms(row.active_ms),
                            thousands(row.days),
                        ]
                    })
                    .collect();
                data_table(
                    ui,
                    "overlay-spheres",
                    &["Sphere", "Episodes", "Active time", "Days seen"],
                    &rows,
                );
            }

            caption(
                ui,
                "Longest episodes (by active time). Switches count app changes within the \
                 episode.",
            );
            let mut longest: Vec<&WorkEpisode> = overlay.episodes.iter().collect();
            longest.sort_by_key(|episode| -episode.active_ms);
            let rows: Vec<Vec<String>> = longest
                .iter()
                .take(SPHERE_DISPLAY_LIMIT)
                .map(|episode| {
                    vec![
                        episode
                            .sphere
                            .clone()
                            .unwrap_or_else(|| "(no title signal)".to_string()),
                        episode_when(episode),
                        format_duration_ms(episode.active_ms),
                        episode_composition_text(&episode.apps),
                        thousands(episode.switch_count),
                    ]
                })
                .collect();
            data_table(
                ui,
                "overlay-longest",
                &[
                    "Sphere",
                    "When",
                    "Active",
                    "Apps (by active time)",
                    "Switches",
                ],
                &rows,
            );
        }
    }
}

fn friction_table(ui: &mut egui::Ui, data: &AnalyticsData) {
    if data.rhythm.friction_windows.is_empty() {
        return;
    }
    anchored_kicker(ui, "FRICTION WINDOWS", "friction");
    caption(
        ui,
        "Self-relative friction windows: hours where switch rate, return toll, return ramp, \
         or input-dense spans clustered in this scope.",
    );
    let rows: Vec<Vec<String>> = data
        .rhythm
        .friction_windows
        .iter()
        .take(8)
        .map(|window| {
            vec![
                window.signal.clone(),
                window.hour_label.clone(),
                thousands(window.days),
                thousands(window.count),
                thousands(window.today_count),
                float_cell(window.value),
                float_cell(window.baseline),
                window.unit.clone(),
            ]
        })
        .collect();
    data_table(
        ui,
        "friction-windows",
        &[
            "Signal",
            "Hour",
            "Days",
            "Count",
            "Today",
            "Value",
            "Recent p75",
            "Unit",
        ],
        &rows,
    );
}
