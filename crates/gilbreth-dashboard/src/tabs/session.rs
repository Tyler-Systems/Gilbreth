//! The Session tab in the instrument register (slice 5 of the dashboard
//! register program, charter: the recorded redesign,
//! direction A "Same anatomy, session scope").
//!
//! The scope row answers what data (the session selector) and which lens
//! (the segmented VIEW control: Overview | Records). Overview is the
//! Analytics anatomy applied to one session — takeaway sentence, one quiet
//! figure, one Detail expander per section — with the recorded anatomy
//! bend: machine events are enumerable records, so they render as
//! timestamped rows, not gauges. The Records lens holds the verify
//! register wholesale: the four tables, the event list, and the product's
//! only per-event delete, unchanged in semantics (UX-11/UX-32, the
//! ERASE_SCOPE-recorded flow).

use std::collections::HashSet;

use egui::{Color32, CornerRadius, FontId, Margin, RichText, Stroke, Vec2};
use gilbreth_read::{
    display_app, ActivityEventRow, EventCountRow, FocusSummaryRow, PowerEventRow, SessionRow,
    SystemEventRow,
};

use super::widgets::{
    self, caption, confirm_gate, data_table, gauge_tiles, info_box, section_kicker,
    summary_section, takeaway, ShareBarRow,
};
use crate::data::{SessionEventsSnapshot, SessionSnapshot};
use crate::format::{
    format_duration_ms, format_duration_seconds, thousands, MISSING_VALUE_CELL, RANGE_SEPARATOR,
};
use crate::theme;

pub const NO_SESSIONS_INFO: &str = "No Gilbreth sessions found yet.";
pub const NO_EVENTS_INFO: &str = "No events in this session.";
pub const READING_EVENTS_LABEL: &str = "Reading the event list…";
pub const REFRESH_EVENTS_LABEL: &str = "Refresh event list";
pub const REFRESH_EVENTS_HELP: &str =
    "The event list holds still while you review it; this re-reads it from the database.";
pub const KINDS_LABEL: &str = "Show kinds";
pub const SHOW_TITLES_LABEL: &str = "Show window titles";
pub const SHOW_TITLES_HELP: &str = "Window titles can contain document names, subjects, and \
     other content. The default view aggregates time by app.";
pub const POWER_EMPTY_CAPTION: &str = "No power suspend/resume events recorded in this session.";
pub const POWER_CONTEXT_CAPTION: &str = "Standby events, listed separately so they always surface.";
/// The two-clock method, stated once (the C-ledger line).
pub const POWER_METHOD_CAPTION: &str =
    "Gaps are measured on two clocks; the backstop takes the larger.";
pub const EVENT_COUNTS_CAPTION: &str =
    "Everything captured this session, counted by source and kind.";
/// The keystroke posture as visible copy (charter §2), scoped to the
/// default rather than claiming this install's live setting.
pub const KEY_POSTURE_LINE: &str = "Keys are counted; what you typed is not stored (default).";
/// UX-11: the delete flow reads like Privacy's prune — one line of
/// permanence copy, confirm-then-act with disabled-hover reasons.
#[cfg(windows)]
pub const DELETE_SECTION_CAPTION: &str = "Deletes the selected entries from the local database, \
     but is not a secure erase. Use the Gilbreth tray Privacy menu for archive/reset or secure \
     erase.";
// macOS has no archive/reset to point at (owner decision 2026-07-19).
#[cfg(not(windows))]
pub const DELETE_SECTION_CAPTION: &str = "Deletes the selected entries from the local database, \
     but is not a secure erase. Use the Gilbreth tray Privacy menu for secure erase.";
pub const CONFIRM_DELETE_LABEL: &str = "Confirm deletion";
pub const DELETE_BUTTON_LABEL: &str = "Delete selected";
pub const CONFIRM_DISABLED_REASON: &str =
    "Nothing to confirm yet: select entries in the list above first.";
pub const DELETE_DISABLED_REASON: &str = "Tick Confirm deletion once entries are selected above.";

/// What the Session tab asks the shell to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    /// The selector changed; queue a fresh session read (the Event-list
    /// snapshot follows once the new session resolves, mirroring the
    /// Streamlit two-key cache).
    Select(i64),
    /// The explicit "Refresh event list" button.
    RefreshEvents,
    /// The confirm-gated per-event delete.
    DeleteEvents(Vec<i64>),
}

/// Cross-frame state the shell owns for this tab.
pub struct SessionView<'a> {
    pub snapshot: &'a SessionSnapshot,
    /// The separately-cadenced Event-list snapshot, if one has been read.
    pub events: Option<&'a SessionEventsSnapshot>,
    /// Whether an Event-list read is in flight (drives the reading label).
    pub events_pending: bool,
    /// Shown in the header Detail.
    pub db_path: &'a str,
    /// One-shot delete notice: (is_error, message).
    pub notice: Option<&'a (bool, String)>,
}

/// The delete-confirm checkbox state, so the shell can reset it after a
/// successful delete (Streamlit's `reset_confirmation`).
pub fn delete_confirm_id() -> egui::Id {
    egui::Id::new("session-delete-confirm")
}

fn subtab_id() -> egui::Id {
    egui::Id::new("session-subtab")
}

fn show_titles_id() -> egui::Id {
    egui::Id::new("session-show-titles")
}

fn jump_target_id() -> egui::Id {
    egui::Id::new("session-records-jump")
}

/// Selected event ids, keyed by the Event-list snapshot identity so a
/// rebuilt list starts unselected (Streamlit's table-generation reset).
fn selection_id(events: &SessionEventsSnapshot) -> egui::Id {
    egui::Id::new((
        "session-event-selection",
        events.session_id,
        events.generated_at_ms,
    ))
}

/// Deselected kinds, keyed by the session and the option set so the filter
/// resets when the kind options change (Streamlit widget identity).
fn kind_filter_id(session_id: i64, kind_options: &[String]) -> egui::Id {
    egui::Id::new(("session-kind-filter", session_id, kind_options.join("\n")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SubTab {
    #[default]
    Overview,
    Records,
}

/// Mirrors `compact_datetime`: the first 16 chars ("YYYY-MM-DD HH:MM").
fn compact_datetime(value: Option<&str>) -> String {
    match value {
        Some(text) if !text.is_empty() => text.chars().take(16).collect(),
        _ => "unknown".to_string(),
    }
}

/// The time-of-day part of a compact timestamp ("06:30"), for takeaways.
fn compact_clock(value: Option<&str>) -> Option<String> {
    let text = compact_datetime(value);
    text.split_whitespace().nth(1).map(str::to_string)
}

/// The selector label (C-ledger shape): sentence case, one parenthesized
/// shape for open and ended sessions.
pub fn session_label(session: &SessionRow) -> String {
    let started_at = compact_datetime(session.started_at.as_deref());
    let event_word = if session.event_count == 1 {
        "event"
    } else {
        "events"
    };
    match session.ended_at.as_deref() {
        None => format!(
            "Current session (since {started_at}, {} {event_word})",
            session.event_count
        ),
        Some(ended_at) => format!(
            "{started_at}{RANGE_SEPARATOR}{} ({} {event_word})",
            compact_datetime(Some(ended_at)),
            session.event_count
        ),
    }
}

/// Mirrors `optional_text`: trimmed text or None.
fn optional_text(value: Option<&str>) -> Option<&str> {
    let text = value?.trim();
    (!text.is_empty()).then_some(text)
}

/// Mirrors `short_sha`: the first 12 chars of a non-empty sha.
fn short_sha(value: Option<&str>) -> Option<String> {
    optional_text(value).map(|text| text.chars().take(12).collect())
}

/// The identity caption: bullet-joined facts (amendment §4).
pub fn session_identity_caption(session: &SessionRow) -> String {
    let mut parts = Vec::new();
    if let Some(run_label) = optional_text(session.run_label.as_deref()) {
        parts.push(format!("Run label {run_label}"));
    }
    if let Some(host) = optional_text(session.host.as_deref()) {
        parts.push(format!("Host {host}"));
    }
    if let Some(app_version) = optional_text(session.app_version.as_deref()) {
        parts.push(format!("Version {app_version}"));
    }
    if let Some(git_sha) = short_sha(session.git_sha.as_deref()) {
        parts.push(format!("Build {git_sha}"));
    }
    parts.join(" • ")
}

/// Mirrors `humanized_value`: underscores to spaces, Python `capitalize()`
/// (first char upper, the rest lower).
fn humanized_value(value: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        return String::new();
    }
    let replaced = text.replace('_', " ");
    let mut chars = replaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => String::new(),
    }
}

/// The app-wide missing-value spelling (UX-10).
fn dash_cell(value: Option<&str>) -> String {
    optional_text(value)
        .unwrap_or(MISSING_VALUE_CELL)
        .to_string()
}

fn dash_int(value: Option<i64>) -> String {
    value.map_or_else(|| MISSING_VALUE_CELL.to_string(), |value| value.to_string())
}

fn dash_thousands(value: Option<i64>) -> String {
    value.map_or_else(|| MISSING_VALUE_CELL.to_string(), thousands)
}

fn dash_duration(value: Option<i64>) -> String {
    value.map_or_else(|| MISSING_VALUE_CELL.to_string(), format_duration_ms)
}

pub fn show(ui: &mut egui::Ui, view: &SessionView<'_>) -> Vec<SessionAction> {
    let mut actions = Vec::new();
    let snapshot = view.snapshot;
    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
        ui.add_space(4.0);
    }
    if snapshot.sessions.is_empty() {
        info_box(ui, NO_SESSIONS_INFO);
        return actions;
    }

    let id = subtab_id();
    let mut subtab: SubTab = ui.ctx().data_mut(|data| *data.get_temp_mut_or_default(id));
    scope_row(ui, snapshot, &mut subtab, &mut actions);
    ui.ctx().data_mut(|data| data.insert_temp(id, subtab));
    ui.add_space(6.0);

    match subtab {
        SubTab::Overview => overview(ui, view),
        SubTab::Records => records(ui, view, &mut actions),
    }
    actions
}

fn selected_session(snapshot: &SessionSnapshot) -> Option<&SessionRow> {
    let selected_id = snapshot.selected_session_id?;
    snapshot
        .sessions
        .iter()
        .find(|row| row.session_id == selected_id)
}

/// The scope row in the Analytics grammar: the selector answers what data;
/// the segmented control answers which lens.
fn scope_row(
    ui: &mut egui::Ui,
    snapshot: &SessionSnapshot,
    subtab: &mut SubTab,
    actions: &mut Vec<SessionAction>,
) {
    ui.horizontal_wrapped(|ui| {
        let mut selection = snapshot.selected_session_id;
        let selected_label = selected_session(snapshot)
            .map(session_label)
            .unwrap_or_else(|| MISSING_VALUE_CELL.to_string());
        // The Streamlit selectbox width (520), clamped to the window (UX-23).
        egui::ComboBox::from_id_salt("session-selector")
            .selected_text(selected_label)
            .width(520.0_f32.min(ui.available_width().max(120.0)))
            .show_ui(ui, |ui| {
                for row in &snapshot.sessions {
                    ui.selectable_value(&mut selection, Some(row.session_id), session_label(row));
                }
            });
        if selection != snapshot.selected_session_id {
            if let Some(session_id) = selection {
                actions.push(SessionAction::Select(session_id));
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let mut selected = match *subtab {
                SubTab::Overview => 0,
                SubTab::Records => 1,
            };
            widgets::view_switcher(
                ui,
                "session-view-segment",
                ["Overview", "Records"],
                &mut selected,
            );
            *subtab = if selected == 0 {
                SubTab::Overview
            } else {
                SubTab::Records
            };
        });
    });
}

/// One "open the named table" jump inside a Detail expander (the Analytics
/// decision, inherited: the pointer switches the lens AND scrolls there).
fn records_jump_button(ui: &mut egui::Ui, label: &str, anchor: &'static str) {
    if widgets::small_button(ui, label) {
        ui.ctx().data_mut(|data| {
            data.insert_temp(subtab_id(), SubTab::Records);
            data.insert_temp(jump_target_id(), anchor.to_string());
        });
    }
}

/// A Records-lens kicker that answers jumps aimed at it.
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

// -------------------------------------------------------------- overview

fn overview(ui: &mut egui::Ui, view: &SessionView<'_>) {
    let snapshot = view.snapshot;
    header_section(ui, view);
    time_section(ui, snapshot);
    machine_events_section(ui, snapshot);
    captured_section(ui, snapshot);
}

/// The header takeaway: active of in-front, since when, and who carried it.
fn header_takeaway(snapshot: &SessionSnapshot) -> String {
    let active = format_duration_seconds(snapshot.active_focus_seconds_total);
    let front = format_duration_seconds(snapshot.focus_seconds_total);
    let session = selected_session(snapshot);
    let since = session
        .filter(|row| row.ended_at.is_none())
        .and_then(|row| compact_clock(row.started_at.as_deref()));
    let mut text = match since {
        Some(since) => format!("{active} active since {since}, of {front} in front."),
        None => format!("{active} active, of {front} in front."),
    };
    if let Some(top_app) = &snapshot.story.top_app {
        text.push_str(&format!(
            " {top_app} carried {} of it.",
            format_duration_seconds(snapshot.story.top_app_active_seconds)
        ));
    }
    text
}

fn header_section(ui: &mut egui::Ui, view: &SessionView<'_>) {
    let snapshot = view.snapshot;
    takeaway(ui, &header_takeaway(snapshot));
    let gauges: [(&str, String); 5] = [
        (
            "Active time",
            format_duration_seconds(snapshot.active_focus_seconds_total),
        ),
        (
            "In front (idle incl.)",
            format_duration_seconds(snapshot.focus_seconds_total),
        ),
        (
            "Top app (active)",
            snapshot
                .story
                .top_app
                .clone()
                .unwrap_or_else(|| MISSING_VALUE_CELL.to_string()),
        ),
        ("Focus switches", thousands(snapshot.story.focus_switches)),
        ("Keystrokes", thousands(snapshot.key_events)),
    ];
    widgets::gauge_tiles_capped(ui, &gauges, 5);
    summary_section(
        ui,
        "session-header-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            caption(ui, super::analytics::FOREGROUND_MINUTES_CAVEAT);
            if let Some(selected) = selected_session(snapshot) {
                let identity = session_identity_caption(selected);
                if !identity.is_empty() {
                    caption(ui, &identity);
                }
            }
            ui.label(
                RichText::new(view.db_path)
                    .color(theme::GRAY)
                    .font(FontId::new(11.5, egui::FontFamily::Monospace)),
            );
        },
    );
}

/// Where the time went: per-app share bars in the Today day-strip
/// convention — amber is the session's top app by active time, the rest
/// stay quiet series colors.
fn time_section(ui: &mut egui::Ui, snapshot: &SessionSnapshot) {
    section_kicker(ui, "WHERE THE TIME WENT");
    let rows = &snapshot.focus_apps;
    if rows.is_empty() {
        info_box(ui, NO_EVENTS_INFO);
        return;
    }
    let total_active: f64 = rows
        .iter()
        .map(|row| row.active_foreground_seconds)
        .sum::<f64>()
        .max(1e-9);
    let mut sorted: Vec<&FocusSummaryRow> = rows.iter().collect();
    sorted.sort_by(|left, right| {
        right
            .active_foreground_seconds
            .partial_cmp(&left.active_foreground_seconds)
            .expect("finite seconds")
    });
    let top = sorted[0];
    let top_share = top.active_foreground_seconds / total_active * 100.0;
    let app_word = if sorted.len() == 1 { "app" } else { "apps" };
    takeaway(
        ui,
        &format!(
            "{} {app_word} held focus. {} took {top_share:.0}% of active time.",
            sorted.len(),
            display_app(Some(&top.completed_exe)),
        ),
    );
    let bars: Vec<ShareBarRow> = sorted
        .iter()
        .enumerate()
        .map(|(rank, row)| ShareBarRow {
            name: display_app(Some(&row.completed_exe)),
            share: (row.active_foreground_seconds / total_active) as f32,
            color: theme::series_color(rank),
            figures: format!(
                "active {} • in front {} • switches {}",
                format_duration_seconds(row.active_foreground_seconds),
                format_duration_seconds(row.focus_seconds),
                thousands(row.switches)
            ),
        })
        .collect();
    widgets::share_bars(ui, &bars);
    summary_section(
        ui,
        "session-time-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            caption(ui, SHOW_TITLES_HELP);
            records_jump_button(ui, "Open in Records: time per app", "time-per-app");
        },
    );
}

/// One machine-event row: when, what, and the detail, as a record rather
/// than a gauge (the recorded anatomy bend).
struct MachineEvent {
    at: String,
    what: String,
    amount: String,
}

/// The machine-events story: sign-ins, display changes, and standby gaps,
/// merged chronologically from the system and power streams.
fn machine_events(snapshot: &SessionSnapshot) -> Vec<MachineEvent> {
    let mut events: Vec<MachineEvent> = Vec::new();
    for row in &snapshot.system_events {
        let what = match row.kind.as_str() {
            "session_start" => "Signed in".to_string(),
            "session_end" => "Signed out".to_string(),
            "display_change" => "Display changed".to_string(),
            other => humanized_value(other),
        };
        let amount = if row.pos_x.is_some() || row.pos_y.is_some() {
            format!(
                "{} × {}",
                row.pos_x.map(|x| x.to_string()).unwrap_or_default(),
                row.pos_y.map(|y| y.to_string()).unwrap_or_default()
            )
        } else {
            row.title.clone().unwrap_or_default()
        };
        events.push(MachineEvent {
            at: dash_cell(row.captured_at.as_deref()),
            what,
            amount,
        });
    }
    // Standby spans: each suspend row, with its matched resume's gap.
    let resumes: Vec<&PowerEventRow> = snapshot
        .power_events
        .iter()
        .filter(|row| row.kind == "power_resume")
        .collect();
    for row in &snapshot.power_events {
        if row.kind != "power_suspend" {
            continue;
        }
        let resume = resumes
            .iter()
            .find(|resume| resume.captured_at > row.captured_at);
        let amount = match resume {
            Some(resume) => {
                let resumed = compact_clock(resume.captured_at.as_deref())
                    .unwrap_or_else(|| MISSING_VALUE_CELL.to_string());
                match resume.gap_ms {
                    Some(gap) => format!("resumed {resumed} • gap {}", format_duration_ms(gap)),
                    None => format!("resumed {resumed}"),
                }
            }
            None => "no resume recorded".to_string(),
        };
        events.push(MachineEvent {
            at: dash_cell(row.captured_at.as_deref()),
            what: "Standby".to_string(),
            amount,
        });
    }
    events.sort_by(|left, right| left.at.cmp(&right.at));
    events
}

/// The machine-events takeaway: the standby story first, then sign-in and
/// display facts.
fn machine_takeaway(snapshot: &SessionSnapshot) -> String {
    let gaps: Vec<i64> = snapshot
        .power_events
        .iter()
        .filter(|row| row.kind == "power_resume")
        .filter_map(|row| row.gap_ms)
        .collect();
    let mut parts: Vec<String> = Vec::new();
    match gaps.len() {
        0 => parts.push("No standby gaps.".to_string()),
        1 => {
            let from = snapshot
                .power_events
                .iter()
                .find(|row| row.kind == "power_suspend")
                .and_then(|row| compact_clock(row.captured_at.as_deref()));
            match from {
                Some(from) => parts.push(format!(
                    "One standby gap: {} from {from}.",
                    format_duration_ms(gaps[0])
                )),
                None => parts.push(format!("One standby gap: {}.", format_duration_ms(gaps[0]))),
            }
        }
        count => {
            let longest = gaps.iter().copied().max().unwrap_or(0);
            parts.push(format!(
                "{count} standby gaps; the longest {}.",
                format_duration_ms(longest)
            ));
        }
    }
    let signed_in = snapshot
        .system_events
        .iter()
        .find(|row| row.kind == "session_start")
        .and_then(|row| compact_clock(row.captured_at.as_deref()));
    let displays = snapshot
        .system_events
        .iter()
        .filter(|row| row.kind == "display_change")
        .count();
    match (signed_in, displays) {
        (Some(at), 0) => parts.push(format!("Signed in at {at}.")),
        (Some(at), 1) => parts.push(format!("Signed in at {at}; the display changed once.")),
        (Some(at), n) => parts.push(format!("Signed in at {at}; the display changed {n} times.")),
        (None, 0) => {}
        (None, 1) => parts.push("The display changed once.".to_string()),
        (None, n) => parts.push(format!("The display changed {n} times.")),
    }
    parts.join(" ")
}

fn machine_events_section(ui: &mut egui::Ui, snapshot: &SessionSnapshot) {
    section_kicker(ui, "MACHINE EVENTS");
    let events = machine_events(snapshot);
    if events.is_empty() {
        caption(ui, POWER_EMPTY_CAPTION);
        return;
    }
    takeaway(ui, &machine_takeaway(snapshot));
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new("session-machine-events")
                .spacing(egui::vec2(18.0, 5.0))
                .show(ui, |ui| {
                    for event in &events {
                        ui.label(
                            RichText::new(&event.at)
                                .color(theme::GRAY)
                                .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                        );
                        ui.label(RichText::new(&event.what).color(theme::SILVER).size(12.5));
                        ui.label(
                            RichText::new(&event.amount)
                                .color(theme::GRAY)
                                .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                        );
                        ui.end_row();
                    }
                });
        });
    summary_section(
        ui,
        "session-machine-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            caption(ui, POWER_METHOD_CAPTION);
            caption(ui, POWER_CONTEXT_CAPTION);
            records_jump_button(ui, "Open in Records: machine events", "machine-events");
            records_jump_button(ui, "Open in Records: power timeline", "power-timeline");
        },
    );
}

/// What was captured: the counts takeaway with the keystroke posture as
/// visible copy, one gauge per source.
fn captured_section(ui: &mut egui::Ui, snapshot: &SessionSnapshot) {
    section_kicker(ui, "WHAT WAS CAPTURED");
    if snapshot.counts.is_empty() {
        info_box(ui, NO_EVENTS_INFO);
        return;
    }
    let mut source_totals: Vec<(String, i64)> = Vec::new();
    for row in &snapshot.counts {
        match source_totals
            .iter_mut()
            .find(|(source, _)| *source == row.source)
        {
            Some((_, total)) => *total += row.events,
            None => source_totals.push((row.source.clone(), row.events)),
        }
    }
    source_totals.sort_by_key(|(_, total)| -*total);
    let lead = &source_totals[0];
    let rest = source_totals[1..]
        .iter()
        .map(|(source, total)| format!("{} {source}", thousands(*total)))
        .collect::<Vec<_>>()
        .join(" and ");
    let mut text = format!("Mostly {}: {} events", lead.0, thousands(lead.1));
    if !rest.is_empty() {
        text.push_str(&format!(", with {rest}"));
    }
    text.push('.');
    text.push_str(&format!(" {KEY_POSTURE_LINE}"));
    takeaway(ui, &text);
    let gauges: Vec<(&str, String)> = source_totals
        .iter()
        .map(|(source, total)| {
            let label: &str = match source.as_str() {
                "keyboard" => "Keyboard",
                "mouse" => "Mouse",
                "foreground" => "Foreground",
                "system" => "System",
                other => other,
            };
            (label, thousands(*total))
        })
        .collect();
    gauge_tiles(ui, &gauges);
    summary_section(
        ui,
        "session-captured-detail",
        "Details",
        "",
        false,
        false,
        |ui| {
            records_jump_button(ui, "Open in Records: event counts", "event-counts");
        },
    );
}

// --------------------------------------------------------------- records

/// The Records lens: the four tables, the event list, and the delete flow,
/// unchanged in semantics.
fn records(ui: &mut egui::Ui, view: &SessionView<'_>, actions: &mut Vec<SessionAction>) {
    let snapshot = view.snapshot;

    anchored_kicker(ui, "TIME PER APP", "time-per-app");
    let titles_id = show_titles_id();
    let mut show_titles: bool = ui
        .ctx()
        .data_mut(|data| data.get_temp(titles_id).unwrap_or(false));
    if ui
        .checkbox(&mut show_titles, SHOW_TITLES_LABEL)
        .on_hover_text(SHOW_TITLES_HELP)
        .changed()
    {
        ui.ctx()
            .data_mut(|data| data.insert_temp(titles_id, show_titles));
    }
    ui.add_space(2.0);
    focus_table(
        ui,
        if show_titles {
            &snapshot.focus_titles
        } else {
            &snapshot.focus_apps
        },
        show_titles,
    );

    anchored_kicker(ui, "MACHINE EVENTS", "machine-events");
    context_table(ui, &snapshot.system_events);

    anchored_kicker(ui, "POWER TIMELINE", "power-timeline");
    if snapshot.power_events.is_empty() {
        caption(ui, POWER_EMPTY_CAPTION);
    } else {
        caption(ui, POWER_CONTEXT_CAPTION);
        caption(ui, POWER_METHOD_CAPTION);
        power_table(ui, &snapshot.power_events);
    }

    anchored_kicker(ui, "EVENT COUNTS", "event-counts");
    caption(ui, EVENT_COUNTS_CAPTION);
    counts_table(ui, &snapshot.counts);

    anchored_kicker(ui, "EVENT LIST", "event-list");
    event_list(ui, view, actions);
}

/// Mirrors `foreground_time_display` with sentence-case column labels.
fn focus_table(ui: &mut egui::Ui, rows: &[FocusSummaryRow], include_titles: bool) {
    let headers: Vec<&str> = if include_titles {
        vec![
            "App name",
            "App title",
            "Active time",
            "In front (idle incl.)",
            "Switches",
        ]
    } else {
        vec![
            "App name",
            "Active time",
            "In front (idle incl.)",
            "Switches",
        ]
    };
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let mut cells = vec![display_app(Some(&row.completed_exe))];
            if include_titles {
                cells.push(row.completed_title.clone().unwrap_or_default());
            }
            cells.push(format_duration_seconds(row.active_foreground_seconds));
            cells.push(format_duration_seconds(row.focus_seconds));
            cells.push(thousands(row.switches));
            cells
        })
        .collect();
    data_table(ui, "session-focus-table", &headers, &cells);
}

/// Mirrors `session_context_display`: title context unless the row carries a
/// screen position.
fn context_table(ui: &mut egui::Ui, rows: &[SystemEventRow]) {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let context = if row.pos_x.is_some() || row.pos_y.is_some() {
                format!(
                    "Screen position {}, {}",
                    row.pos_x.map(|x| x.to_string()).unwrap_or_default(),
                    row.pos_y.map(|y| y.to_string()).unwrap_or_default()
                )
            } else {
                row.title.clone().unwrap_or_default()
            };
            vec![
                dash_cell(row.captured_at.as_deref()),
                humanized_value(&row.kind),
                context,
                dash_duration(row.duration_ms),
            ]
        })
        .collect();
    data_table(
        ui,
        "session-context-table",
        &["Captured at", "Kind", "Context", "Duration"],
        &cells,
    );
}

/// Mirrors `format_optional_bool`, with the em dash for missing (UX-10).
fn optional_bool_cell(value: Option<i64>) -> String {
    match value {
        None => MISSING_VALUE_CELL.to_string(),
        Some(0) => "No".to_string(),
        Some(_) => "Yes".to_string(),
    }
}

/// The power table with the C-ledger column names: engine vocabulary out
/// of headline positions, the two-clock method stated in the caption.
fn power_table(ui: &mut egui::Ui, rows: &[PowerEventRow]) {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                dash_cell(row.captured_at.as_deref()),
                humanized_value(&row.kind),
                optional_bool_cell(row.matched_suspend),
                dash_duration(row.tick_gap_ms),
                dash_duration(row.wall_gap_ms),
                dash_duration(row.gap_ms),
                dash_duration(row.capped_dwell_ms),
                dash_int(row.tick_ms),
            ]
        })
        .collect();
    data_table(
        ui,
        "session-power-table",
        &[
            "Captured at",
            "Kind",
            "Resume matched",
            "App-clock gap",
            "Wall-clock gap",
            "Gap, backstop",
            "Dwell cap",
            "Heartbeat (ms)",
        ],
        &cells,
    );
}

fn counts_table(ui: &mut egui::Ui, rows: &[EventCountRow]) {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                humanized_value(&row.source),
                humanized_value(&row.kind),
                thousands(row.events),
            ]
        })
        .collect();
    data_table(
        ui,
        "session-counts-table",
        &["Source", "Kind", "Events total"],
        &cells,
    );
}

/// UX-26: a 500-row event list scrolls inside a bounded region.
const EVENTS_MAX_HEIGHT: f32 = 360.0;

fn event_list(ui: &mut egui::Ui, view: &SessionView<'_>, actions: &mut Vec<SessionAction>) {
    if widgets::small_button_help(ui, REFRESH_EVENTS_LABEL, REFRESH_EVENTS_HELP) {
        actions.push(SessionAction::RefreshEvents);
    }
    // UX-15/UX-20: the one-shot delete outcome renders here — adjacent to
    // the controls that produced it, and still visible while the list
    // rebuilds after a delete (the Streamlit success message was wiped by
    // its own rerun; the warning branch deliberately held the rerun).
    if let Some((is_error, message)) = view.notice {
        widgets::outcome_notice(ui, *is_error, message);
    }
    ui.add_space(2.0);

    let current_events = view
        .events
        .filter(|events| view.snapshot.selected_session_id == Some(events.session_id));
    let Some(events) = current_events else {
        // The shell has queued (or is about to queue) the read for the
        // resolved session; the list holds still meanwhile.
        caption(ui, READING_EVENTS_LABEL);
        return;
    };
    if let Some(error) = &events.error {
        ui.label(RichText::new(error).color(theme::RED).size(12.5));
        return;
    }
    if events.events.is_empty() {
        info_box(ui, NO_EVENTS_INFO);
        return;
    }

    // Mirrors the Streamlit kind multiselect: options are the sorted unique
    // kinds, all selected by default; the deselected set resets when the
    // options change.
    let mut kind_options: Vec<String> = events
        .events
        .iter()
        .map(|row| row.kind.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    kind_options.sort();
    let filter_id = kind_filter_id(events.session_id, &kind_options);
    let mut deselected: HashSet<String> = ui
        .ctx()
        .data_mut(|data| data.get_temp(filter_id).unwrap_or_default());
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(KINDS_LABEL).color(theme::GRAY).size(11.5));
        for kind in &kind_options {
            let mut selected = !deselected.contains(kind);
            if ui.checkbox(&mut selected, kind).changed() {
                if selected {
                    deselected.remove(kind);
                } else {
                    deselected.insert(kind.clone());
                }
            }
        }
    });
    ui.ctx()
        .data_mut(|data| data.insert_temp(filter_id, deselected.clone()));

    let filtered: Vec<&ActivityEventRow> = events
        .events
        .iter()
        .filter(|row| !deselected.contains(&row.kind))
        .collect();

    ui.add_space(4.0);
    let sel_id = selection_id(events);
    let mut selected_ids: HashSet<i64> = ui
        .ctx()
        .data_mut(|data| data.get_temp(sel_id).unwrap_or_default());
    egui::ScrollArea::vertical()
        .id_salt("session-events-scroll")
        .max_height(EVENTS_MAX_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            events_table(ui, &filtered, &mut selected_ids);
        });
    // Selection lives in the displayed (filtered) table, like the
    // Streamlit multi-row selection.
    let visible_selected: Vec<i64> = filtered
        .iter()
        .map(|row| row.id)
        .filter(|id| selected_ids.contains(id))
        .collect();
    ui.ctx()
        .data_mut(|data| data.insert_temp(sel_id, selected_ids));

    delete_controls(ui, &visible_selected, actions);
}

/// The full stored column set, sentence-cased where multiword.
const EVENT_HEADERS: [&str; 22] = [
    "ID",
    "Session ID",
    "Sequence",
    "Changed at",
    "Source",
    "Kind",
    "App name",
    "App title",
    "Duration (ms)",
    "App",
    "Title",
    "Window handle",
    "Key",
    "Shift",
    "Ctrl",
    "Alt",
    "Win",
    "Button",
    "X",
    "Y",
    "Sensitive",
    "Payload",
];

fn event_cells(row: &ActivityEventRow) -> [String; 22] {
    [
        row.id.to_string(),
        row.session_id.to_string(),
        row.seq.to_string(),
        dash_cell(row.changed_at.as_deref()),
        humanized_value(&row.source),
        humanized_value(&row.kind),
        display_app(row.completed_exe.as_deref()),
        dash_cell(row.completed_title.as_deref()),
        dash_thousands(row.duration_ms),
        display_app(row.exe.as_deref()),
        dash_cell(row.title.as_deref()),
        dash_cell(row.hwnd.as_deref()),
        dash_cell(row.key.as_deref()),
        dash_int(row.mod_shift),
        dash_int(row.mod_ctrl),
        dash_int(row.mod_alt),
        dash_int(row.mod_win),
        dash_cell(row.button.as_deref()),
        dash_int(row.pos_x),
        dash_int(row.pos_y),
        row.is_sensitive.to_string(),
        dash_cell(row.payload.as_deref()),
    ]
}

/// The multi-row-selectable event table: the id cell and the whole row are
/// click targets that TOGGLE membership (Streamlit's multi-row selection),
/// with the UX-33 row-fill highlight on selected rows.
fn events_table(ui: &mut egui::Ui, rows: &[&ActivityEventRow], selected_ids: &mut HashSet<i64>) {
    egui::ScrollArea::horizontal()
        .id_salt("session-events-table")
        .auto_shrink([false, true])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .show(ui, |ui| {
            egui::Grid::new("session-events-grid")
                .spacing(egui::vec2(20.0, 4.0))
                .show(ui, |ui| {
                    for header in EVENT_HEADERS {
                        ui.label(
                            RichText::new(header)
                                .color(theme::GRAY)
                                .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                        );
                    }
                    ui.end_row();
                    for row in rows {
                        let selected = selected_ids.contains(&row.id);
                        let cells = event_cells(row);
                        let (first, rest) = cells.split_first().expect("22 cells");
                        let id_text = RichText::new(first)
                            .color(if selected { theme::SILVER } else { theme::BLUE })
                            .font(FontId::new(11.5, egui::FontFamily::Monospace));
                        // UX-28: the id keeps its hover fill...
                        let response = widgets::quiet_tab_button(ui, id_text);
                        let mut toggle = response.clicked();
                        let mut last_rect = response.rect;
                        for cell in rest {
                            last_rect = ui
                                .label(
                                    RichText::new(cell)
                                        .color(theme::SILVER_DIM)
                                        .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                                )
                                .rect;
                        }
                        // ...and the whole row is a click target (UX-28).
                        let row_rect = response.rect.union(last_rect).expand2(Vec2::new(4.0, 1.0));
                        let row_response = ui.interact(
                            row_rect,
                            ui.id().with(("session-event-row", row.id)),
                            egui::Sense::click(),
                        );
                        toggle |= row_response.clicked();
                        if toggle && !selected_ids.remove(&row.id) {
                            selected_ids.insert(row.id);
                        }
                        if selected_ids.contains(&row.id) {
                            ui.painter().rect_filled(
                                row_rect,
                                3.0,
                                theme::BRASS.gamma_multiply(0.12),
                            );
                        } else if row_response.hovered() {
                            ui.painter()
                                .rect_filled(row_rect, 3.0, Color32::from_white_alpha(5));
                        }
                        ui.end_row();
                    }
                });
        });
}

fn delete_controls(ui: &mut egui::Ui, selected: &[i64], actions: &mut Vec<SessionAction>) {
    ui.add_space(8.0);
    // UX-11: the destructive flow reads like Privacy's prune — kicker,
    // permanence line, confirm-then-act with disabled reasons (UX-32),
    // through the shared confirm gate (UXR-07).
    section_kicker(ui, "DELETE SELECTED");
    caption(ui, DELETE_SECTION_CAPTION);
    if !selected.is_empty() {
        caption(ui, &format!("{} selected", selected.len()));
    }
    if confirm_gate(
        ui,
        delete_confirm_id(),
        CONFIRM_DELETE_LABEL,
        !selected.is_empty(),
        CONFIRM_DISABLED_REASON,
        DELETE_BUTTON_LABEL,
        DELETE_DISABLED_REASON,
    ) {
        actions.push(SessionAction::DeleteEvents(selected.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_row(ended: Option<&str>, count: i64) -> SessionRow {
        SessionRow {
            session_id: 7,
            started_at: Some("2026-07-09 06:30:12".to_string()),
            ended_at: ended.map(str::to_string),
            host: None,
            app_version: None,
            git_sha: None,
            run_label: None,
            event_count: count,
        }
    }

    #[test]
    fn session_label_uses_the_one_parenthesized_shape() {
        // Open session: sentence case, the count inside the parenthetical
        // (C-ledger).
        assert_eq!(
            session_label(&session_row(None, 128)),
            "Current session (since 2026-07-09 06:30, 128 events)"
        );
        assert_eq!(
            session_label(&session_row(None, 1)),
            "Current session (since 2026-07-09 06:30, 1 event)"
        );
        // Ended session: the range form with the UX-17 en dash.
        assert_eq!(
            session_label(&session_row(Some("2026-07-09 18:02:44"), 2)),
            "2026-07-09 06:30–2026-07-09 18:02 (2 events)"
        );
        // Missing start reads "unknown" like `compact_datetime`.
        let mut unknown = session_row(None, 0);
        unknown.started_at = None;
        assert_eq!(
            session_label(&unknown),
            "Current session (since unknown, 0 events)"
        );
    }

    #[test]
    fn identity_caption_joins_present_parts_with_bullets() {
        let mut row = session_row(Some("2026-07-09 18:02:44"), 2);
        row.run_label = Some("soak".to_string());
        row.host = Some("DESK".to_string());
        row.app_version = Some("0.9.0".to_string());
        row.git_sha = Some("abcdef1234567890".to_string());
        assert_eq!(
            session_identity_caption(&row),
            "Run label soak • Host DESK • Version 0.9.0 • Build abcdef123456"
        );
        // Blank / missing parts drop out entirely.
        row.run_label = Some("   ".to_string());
        row.host = None;
        assert_eq!(
            session_identity_caption(&row),
            "Version 0.9.0 • Build abcdef123456"
        );
        assert_eq!(session_identity_caption(&session_row(None, 0)), "");
    }

    #[test]
    fn humanized_value_matches_python_capitalize() {
        assert_eq!(humanized_value("focus_changed"), "Focus changed");
        assert_eq!(
            humanized_value("power_boundary_recovered"),
            "Power boundary recovered"
        );
        assert_eq!(humanized_value("KEY"), "Key");
        assert_eq!(humanized_value("  key  "), "Key");
        assert_eq!(humanized_value(""), "");
    }

    #[test]
    fn optional_bool_cell_reads_yes_no_dash() {
        assert_eq!(optional_bool_cell(Some(1)), "Yes");
        assert_eq!(optional_bool_cell(Some(0)), "No");
        assert_eq!(optional_bool_cell(None), "—");
    }
}
