//! The Today tab in the instrument register (slice 6 of the dashboard
//! register program, charter: the recorded redesign,
//! direction A "Same anatomy, the glance pair").
//!
//! The figure leads: the day strip opens the tab, the labeled input pulse
//! follows (charts carry their numbers, the 2026-07-13 owner ruling), then
//! the story gauges with their Detail, the Worth Noticing cards in the
//! shared observation anatomy (curation semantics unchanged: dismiss,
//! mute, watch, reset through the sidecar writer), and the last-7-days
//! bars with per-day minutes. One definition per term: the glossary
//! retired into per-section Details, and the capture posture line is
//! visible copy.

use std::path::Path;

use egui::{Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Stroke};
use gilbreth_read::{DiscoveryNotice, DiscoveryNoticeEvidence};

pub use super::widgets::patterns_empty_caption;
use super::widgets::{
    self, accent_card, caption, opening_section_kicker, secnote, section_kicker, summary_section,
    takeaway,
};
use crate::charts;
use crate::data::TodaySnapshot;
use crate::format::{
    format_duration_ms, local_clock, local_day_heading, thousands, MISSING_VALUE_CELL,
};
use crate::theme;

/// A curation intent raised by the notice cards; the app shell applies it
/// through the host's cooperative sidecar writer and refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurationAction {
    DismissToday(String),
    ToggleMute(String),
    ToggleWatch(String),
    ResetControls,
}

/// Intents raised by the Today view. Notice curation still travels through
/// its existing sidecar writer; the first-run welcome has separate,
/// install-level persistence in the app shell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TodayActions {
    pub curation: Vec<CurationAction>,
    pub dismiss_welcome: bool,
    pub open_privacy_controls: bool,
}

impl TodayActions {
    pub fn is_empty(&self) -> bool {
        self.curation.is_empty() && !self.dismiss_welcome && !self.open_privacy_controls
    }
}

pub const NO_ACTIVITY_HEADING: &str = "No activity yet";
pub const NO_ACTIVITY_LEDE: &str = "There's no activity to show for this device yet.";
pub const NO_ACTIVITY_START: &str = "When Gilbreth captures an app switch or input activity, this \
     page begins to fill in.";
pub const NO_ACTIVITY_DAY: &str = "Once a session is behind you, this page shows your day: a \
     timeline of which app was in front, an hourly input pulse, and evidence-backed things worth \
     noticing.";
pub const NO_ACTIVITY_LOCAL: &str = "Everything Gilbreth captures stays on this device.";
pub const EMPTY_LEAN_CAPTURE_LINE: &str =
    "Configured key-content setting: off. Changes take effect the next time \
     Gilbreth starts; off counts keys without storing typed key names.";
pub const EMPTY_FULL_CAPTURE_LINE: &str = "Configured key-content setting: on (opt-in). Changes \
     take effect the next time Gilbreth starts; on stores typed key names.";
pub const DATABASE_LABEL: &str = "DATABASE";
// Narrowed per heartbeat decision 7 (live-verified 2026-07-28): the open
// interval feeds Today within one 30 s beat, so the old "once you first
// switch away" claim is obsolete — this caption now covers only the
// genuinely-empty moments (capture just started, the Foreground stream
// off, a gated session).
pub const FRESH_START_CAPTION: &str =
    "Active time and top app appear within about half a minute of capture seeing a focus.";
pub const CONTENT_CAPTURE_WARNING: &str = "Typed key content is stored. Full capture is enabled \
     (opt-in). Turn it off under tray > Privacy > Store typed key content.";
/// The capture posture as visible copy (C-ledger, matching Session).
pub const LEAN_CAPTURE_LINE: &str =
    "Lean capture is on: keys are counted; what you type is not stored.";
/// The pulse caption (C-ledger).
pub const PULSE_CAPTION: &str = "Keys and mouse, per hour.";
pub const ALL_NOTICES_HIDDEN: &str =
    "All current notices are dismissed for today or muted locally.";
pub const DISMISS_HELP: &str = "Hide this notice for the rest of today. It can return tomorrow.";
pub const MUTE_HELP: &str = "Hide this notice on this device until you unmute it.";
pub const UNMUTE_HELP: &str = "Show this notice again.";
pub const WATCH_HELP: &str = "Mark this notice so you can track it day to day.";
pub const UNWATCH_HELP: &str = "Remove the watched mark.";
pub const RESET_CONTROLS_HELP: &str = "Clears dismissed and muted notices. Watched marks are kept.";

const WELCOME_KICKER: &str = "GETTING STARTED";
const WELCOME_HEADLINE: &str = "This dashboard reads what's captured on this machine.";
const WELCOME_LEDE_ONE: &str = "Gilbreth captures activity on this device and nothing leaves it. \
     The dashboard only reads what's stored. Capture is managed from the Gilbreth tray.";
const WELCOME_LEDE_TWO: &str = "As activity is captured, this page fills in: a timeline of which \
     app was in front, an hourly input pulse, and things worth noticing.";
const DISMISS_WELCOME_LABEL: &str = "Dismiss welcome banner";
const WELCOME_HAIRLINE: Color32 = Color32::from_rgb(0x4A, 0x3F, 0x26);
const WELCOME_QUIET_STROKE: Color32 = Color32::from_rgb(0x3A, 0x3F, 0x47);
const EMPTY_STATE_WELL: Color32 = Color32::from_rgb(0x20, 0x24, 0x2B);
const WELCOME_READING_MAX_WIDTH: f32 = 570.0;
const EMPTY_READING_MAX_WIDTH: f32 = 620.0;
const WELCOME_LEGS_STACK_AT: f32 = 660.0;

struct WelcomeLeg {
    number: &'static str,
    label: &'static str,
    title: &'static str,
    body: &'static str,
}

const WELCOME_LEGS: [WelcomeLeg; 3] = [
    WelcomeLeg {
        number: "01",
        label: "FROM THE TRAY",
        title: "Capture is locally controlled",
        body: "Pause or resume capture anytime from the tray. The dashboard only reads what is \
               stored.",
    },
    WelcomeLeg {
        number: "02",
        label: "YOUR PRIVACY",
        title: "Choose what is stored",
        body: "Review key-content capture, redaction, app exclusions, and retention under Privacy.",
    },
    WelcomeLeg {
        number: "03",
        label: "FIND THE ONE THING",
        title: "Worth Noticing surfaces patterns",
        body: "After a few days, findings appear here with the evidence behind them, never before.",
    },
];

/// The partial-curation indicator: some notices are hidden while others
/// still show (UX-30).
pub fn hidden_notices_caption(hidden: usize) -> String {
    let word = if hidden == 1 { "notice" } else { "notices" };
    format!("{hidden} {word} hidden (dismissed or muted).")
}

pub fn notice_type_label(notice_type: &str) -> &str {
    match notice_type {
        "clipboard_bridge" => "Clipboard bridge",
        "episode_fragmentation" => "Episode fragmentation",
        "input_dense_span" => "Input-dense span",
        "notification_adjacent" => "Notification-adjacent",
        "recurring_sequence" => "Recurring sequence",
        "return_ramp" => "Return ramp",
        "return_toll" => "Return toll",
        "time_anchor" => "Time-of-day anchor",
        other => other,
    }
}

/// The first-open orientation plate. It stays in normal page flow and
/// reports only a dismiss intent; persistence belongs to the app shell.
fn welcome_banner(ui: &mut egui::Ui) -> (bool, bool) {
    let mut dismiss = false;
    let mut open_privacy_controls = false;

    egui::Frame::default()
        .fill(theme::BRASS_WELL)
        .stroke(Stroke::new(1.0, theme::BRASS))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin {
            left: 20,
            right: 20,
            top: 18,
            bottom: 17,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(welcome_micro_label_job(WELCOME_KICKER));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let response = ui.add_sized(
                        [26.0, 26.0],
                        egui::Button::new(
                            RichText::new("×")
                                .color(theme::BRASS)
                                .font(FontId::new(15.0, theme::family_medium())),
                        )
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::new(1.0, WELCOME_HAIRLINE))
                        .corner_radius(CornerRadius::same(6)),
                    );
                    response.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::WidgetType::Button,
                            true,
                            DISMISS_WELCOME_LABEL,
                        )
                    });
                    if response.on_hover_text(DISMISS_WELCOME_LABEL).clicked() {
                        dismiss = true;
                    }
                });
            });

            ui.add_space(1.0);
            ui.label(
                RichText::new(WELCOME_HEADLINE)
                    .color(theme::SILVER)
                    .font(FontId::new(18.0, theme::family_semibold())),
            );
            ui.add_space(2.0);
            ui.scope(|ui| {
                ui.set_max_width(ui.available_width().min(WELCOME_READING_MAX_WIDTH));
                ui.label(
                    RichText::new(WELCOME_LEDE_ONE)
                        .color(theme::SILVER_DIM)
                        .size(13.5),
                );
                ui.add_space(5.0);
                ui.label(
                    RichText::new(WELCOME_LEDE_TWO)
                        .color(theme::SILVER_DIM)
                        .size(13.5),
                );
            });

            ui.add_space(13.0);
            welcome_journey(ui);
            ui.add_space(12.0);

            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.spacing_mut().button_padding = egui::vec2(14.0, 9.0);
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Open privacy controls")
                                .color(theme::BRASS)
                                .font(FontId::new(12.0, theme::family_medium())),
                        )
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::new(1.0, theme::BRASS))
                        .corner_radius(CornerRadius::same(6)),
                    )
                    .clicked()
                {
                    open_privacy_controls = true;
                }

                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Dismiss")
                                .color(theme::SILVER_DIM)
                                .font(FontId::new(12.0, theme::family_medium())),
                        )
                        .fill(theme::BELLOWS)
                        .stroke(Stroke::new(1.0, WELCOME_QUIET_STROKE))
                        .corner_radius(CornerRadius::same(6)),
                    )
                    .on_hover_text(DISMISS_WELCOME_LABEL)
                    .clicked()
                {
                    dismiss = true;
                }
            });
            ui.add_space(3.0);
            ui.label(
                RichText::new("Banner stays open until you dismiss it")
                    .color(theme::GRAY)
                    .size(11.5),
            );
        });

    (dismiss, open_privacy_controls)
}

fn welcome_micro_label_job(text: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        text,
        0.0,
        egui::text::TextFormat {
            font_id: FontId::new(11.0, FontFamily::Monospace),
            color: theme::BRASS,
            extra_letter_spacing: 1.35,
            ..Default::default()
        },
    );
    job
}

fn welcome_journey(ui: &mut egui::Ui) {
    if ui.available_width() < WELCOME_LEGS_STACK_AT {
        for (index, leg) in WELCOME_LEGS.iter().enumerate() {
            welcome_leg(ui, leg);
            if index + 1 < WELCOME_LEGS.len() {
                ui.add_space(13.0);
            }
        }
    } else {
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 22.0;
            ui.columns(WELCOME_LEGS.len(), |columns| {
                for (column, leg) in columns.iter_mut().zip(WELCOME_LEGS.iter()) {
                    welcome_leg(column, leg);
                }
            });
        });
    }
}

fn welcome_leg(ui: &mut egui::Ui, leg: &WelcomeLeg) {
    let width = ui.available_width();
    let (line, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
    ui.painter().line_segment(
        [line.left_center(), line.right_center()],
        Stroke::new(1.0, WELCOME_HAIRLINE),
    );
    ui.add_space(4.0);
    // copy-allow: middot-separator approved first-run journey compound-fact separator
    ui.label(welcome_micro_label_job(&format!(
        "{} · {}",
        leg.number, leg.label
    )));
    ui.add_space(1.0);
    ui.label(
        RichText::new(leg.title)
            .color(theme::SILVER)
            .font(FontId::new(13.0, theme::family_medium())),
    );
    ui.add_space(1.0);
    ui.label(RichText::new(leg.body).color(theme::GRAY).size(12.0));
}

pub fn show(ui: &mut egui::Ui, snapshot: &TodaySnapshot, db_path: &Path) -> TodayActions {
    let mut actions = TodayActions::default();

    if !snapshot.first_run_welcome_dismissed {
        (actions.dismiss_welcome, actions.open_privacy_controls) = welcome_banner(ui);
        ui.add_space(16.0);
    }

    caption(
        ui,
        &format!(
            "{}, midnight to now. The app you are in right now appears once you switch away.",
            local_day_heading(snapshot.strip.day_end_ms)
        ),
    );
    ui.add_space(4.0);

    if let Some(error) = &snapshot.error {
        ui.label(RichText::new(error).color(theme::RED));
        ui.add_space(4.0);
    }

    let no_activity = snapshot.strip.focus.is_empty() && snapshot.pulse.is_empty();
    if no_activity {
        // An empty successful read is evidence of no activity. A failed
        // read is not, so leave the explicit error above as the only state
        // claim instead of falling through to the blank-state receipt.
        if snapshot.error.is_none() {
            capture_receipt(ui, snapshot, db_path);
        }
    } else {
        // The figure leads (charter §1): the day strip opens the tab, the
        // labeled pulse under it. Match Week's glance-page opener so the
        // figure reads as a deliberate section rather than a continuation
        // of the page caption.
        opening_section_kicker(ui, "WHEN YOU WERE ACTIVE");
        let palette = charts::AppPalette::from_strip(&snapshot.strip);
        let has_day_strip = !snapshot.strip.focus.is_empty();
        if has_day_strip {
            charts::day_strip(ui, &snapshot.strip, &palette);
            charts::day_strip_legend(ui, &palette);
        }
        if !snapshot.pulse.is_empty() {
            // Separate the two related figures without giving the pulse a
            // competing top-level section heading.
            if has_day_strip {
                ui.add_space(16.0);
            }
            secnote(ui, PULSE_CAPTION);
            charts::hourly_pulse(ui, &snapshot.pulse, &snapshot.strip);
            // UX-51: name which color is which without hovering.
            charts::pulse_legend(ui);
        }
        summary_section(
            ui,
            "today-figure-detail",
            "Details",
            "",
            false,
            false,
            |ui| {
                caption(
                    ui,
                    "The day strip is a timeline of which app was in front through the day; \
                     the gaps are time you were away.",
                );
                caption(
                    ui,
                    "The input pulse counts key and mouse events each hour: a measure of \
                     motion. Each hour's keys count is labeled; mouse reads against the same \
                     scale.",
                );
            },
        );

        // Analytics' successful section anatomy: kicker, takeaway, gauges,
        // quiet posture copy, then the methodology expander. The full
        // section rhythm is intentional even in a short window; Today
        // scrolls instead of compressing unrelated groups together.
        section_kicker(ui, "TODAY SO FAR");
        let story = &snapshot.story;
        if let (Some(run_app), Some(run_start)) =
            (&story.longest_run_app, story.longest_run_start_ms)
        {
            // The buried-insight defect that started the amendment (§2):
            // the day's finding renders as a takeaway, never a caption.
            takeaway(
                ui,
                &format!(
                    "Longest run: {} on {}, starting at {}.",
                    format_duration_ms(story.longest_run_ms),
                    run_app,
                    local_clock(run_start)
                ),
            );
        } else if story.active_ms == 0 && story.keystrokes > 0 {
            caption(ui, FRESH_START_CAPTION);
        }
        story_gauges(ui, snapshot);
        // The capture posture as visible copy (charter §3).
        if snapshot.store_key_content {
            caption(ui, CONTENT_CAPTURE_WARNING);
        } else {
            caption(ui, LEAN_CAPTURE_LINE);
        }
        summary_section(
            ui,
            "today-numbers-detail",
            "Details",
            "",
            false,
            false,
            |ui| {
                caption(
                    ui,
                    "Active time is time you were actually working today, with idle and sleep \
                     gaps removed.",
                );
                caption(
                    ui,
                    "In front (idle incl.) is total time an app was frontmost, idle counted \
                     too, so it is always larger than active time.",
                );
                caption(
                    ui,
                    "Longest focus run is the longest unbroken stretch you stayed in one app; \
                     focus switches count how many times you moved between apps.",
                );
                caption(
                    ui,
                    "Keystrokes are counted key presses; by default what you typed is not \
                     stored.",
                );
            },
        );
    }

    // UX-04: on an empty day the capture receipt above already carries the
    // pattern-floor caption, so the section renders only when it has
    // something of its own to say — the caption never appears twice.
    let show_notice_section =
        !snapshot.notices.is_empty() || snapshot.hidden_notice_count > 0 || !no_activity;
    if show_notice_section {
        section_kicker(ui, "WORTH NOTICING");
        if !snapshot.notices.is_empty() {
            // UX-37, extended (charter §4): the shared hedge states once at
            // section level, never per card — in the secnote register (§6).
            secnote(ui, widgets::PATTERNS_DESCRIPTIVE_CAPTION);
            for notice in &snapshot.notices {
                notice_card(ui, notice, snapshot, &mut actions.curation);
                ui.add_space(8.0);
            }
            // UX-30: hidden notices are named even while others still show,
            // and recovery does not wait for the all-hidden state.
            if snapshot.hidden_notice_count > 0 {
                caption(ui, &hidden_notices_caption(snapshot.hidden_notice_count));
                if reset_controls_button(ui) {
                    actions.curation.push(CurationAction::ResetControls);
                }
            }
        } else if snapshot.hidden_notice_count > 0 {
            caption(ui, ALL_NOTICES_HIDDEN);
            if reset_controls_button(ui) {
                actions.curation.push(CurationAction::ResetControls);
            }
        } else {
            // UX-12: the shared info-box treatment for the empty state.
            widgets::info_box(ui, &patterns_empty_caption(snapshot.pattern_history_days));
        }
    }

    // UX-13: the section keeps its kicker with a one-line empty state on
    // active days; the pure receipt state stays minimal.
    let daily_total: f64 = snapshot.daily.iter().map(|day| day.active_minutes).sum();
    let has_daily = !snapshot.daily.is_empty() && daily_total > 0.0;
    if has_daily || !no_activity {
        section_kicker(ui, "LAST 7 DAYS");
    }
    if !has_daily && !no_activity {
        caption(ui, "No active minutes in the last 7 days yet.");
    }
    if has_daily {
        secnote(ui, "Minutes active per day.");
        // Full width (amendment: supersedes the slice-6 46×84px compact
        // bars ruling), so the UX-56 centering wrapper retires with it.
        charts::daily_bars(ui, &snapshot.daily, &snapshot.today_key);
    }

    actions
}

/// The one recovery control for hidden notices; UX-30 pins that it spares
/// watched marks (see `apply_curation`), and the tooltip says so.
fn reset_controls_button(ui: &mut egui::Ui) -> bool {
    // UX-18: the 11.5 px small-button register, like every other action.
    widgets::small_button_help(ui, "Reset notice controls", RESET_CONTROLS_HELP)
}

/// The richer blank Today state below the one-time welcome. It describes
/// what will arrive, the configured key-content setting, and the actual
/// database location without claiming capture is currently running or
/// that a pending configuration change is already active.
fn capture_receipt(ui: &mut egui::Ui, snapshot: &TodaySnapshot, db_path: &Path) {
    egui::Frame::default()
        .fill(EMPTY_STATE_WELL)
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x34, 0x39, 0x42)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin {
            left: 24,
            right: 24,
            top: 22,
            bottom: 22,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(NO_ACTIVITY_HEADING)
                    .color(theme::SILVER)
                    .font(theme::heading_page()),
            );
            ui.add_space(6.0);
            ui.scope(|ui| {
                ui.set_max_width(ui.available_width().min(EMPTY_READING_MAX_WIDTH));
                for paragraph in [NO_ACTIVITY_LEDE, NO_ACTIVITY_START, NO_ACTIVITY_DAY] {
                    ui.label(RichText::new(paragraph).color(theme::SILVER_DIM).size(13.5));
                    ui.add_space(4.0);
                }
                ui.add_space(2.0);
                ui.label(
                    RichText::new(NO_ACTIVITY_LOCAL)
                        .color(theme::SILVER)
                        .size(12.5),
                );
                ui.label(
                    RichText::new(if snapshot.store_key_content {
                        EMPTY_FULL_CAPTURE_LINE
                    } else {
                        EMPTY_LEAN_CAPTURE_LINE
                    })
                    .color(theme::GRAY)
                    .size(12.0),
                );
            });

            ui.add_space(13.0);
            let width = ui.available_width();
            let (line, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
            ui.painter().line_segment(
                [line.left_center(), line.right_center()],
                Stroke::new(1.0, WELCOME_HAIRLINE),
            );
            ui.add_space(5.0);
            ui.label(welcome_micro_label_job(DATABASE_LABEL));
            ui.label(
                RichText::new(db_path.display().to_string())
                    .color(theme::SILVER_DIM)
                    .font(FontId::new(11.5, FontFamily::Monospace)),
            );
            let database_status = if snapshot.counts.events > 0 {
                let event_word = if snapshot.counts.events == 1 {
                    "event"
                } else {
                    "events"
                };
                let session_word = if snapshot.counts.sessions == 1 {
                    "session"
                } else {
                    "sessions"
                };
                format!(
                    "{} {event_word} stored across {} {session_word}; no Today readings yet.",
                    thousands(snapshot.counts.events),
                    thousands(snapshot.counts.sessions)
                )
            } else {
                "No Today readings yet.".to_string()
            };
            caption(ui, &database_status);
            caption(ui, &patterns_empty_caption(snapshot.pattern_history_days));
        });
}

fn story_gauges(ui: &mut egui::Ui, snapshot: &TodaySnapshot) {
    let story = &snapshot.story;
    let gauges: [(&str, String); 5] = [
        ("Active time", format_duration_ms(story.active_ms)),
        (
            "In front (idle incl.)",
            format_duration_ms(story.foreground_ms),
        ),
        (
            "Longest focus run",
            if story.longest_run_ms > 0 {
                format_duration_ms(story.longest_run_ms)
            } else {
                MISSING_VALUE_CELL.to_string()
            },
        ),
        ("Focus switches", thousands(story.focus_switches)),
        ("Keystrokes", thousands(story.keystrokes)),
    ];
    widgets::gauge_tiles_capped(ui, &gauges, 5);
}

/// One observation card in the shared anatomy (charter §4): title, mono
/// family chip, the facts line, quiet actions, evidence behind one
/// expander. Curation semantics unchanged.
fn notice_card(
    ui: &mut egui::Ui,
    notice: &DiscoveryNotice,
    snapshot: &TodaySnapshot,
    actions: &mut Vec<CurationAction>,
) {
    let state = &snapshot.notice_state;
    accent_card(ui, |ui| {
        let mut chip = notice_type_label(&notice.notice_type).to_uppercase();
        if state.watched.contains(&notice.notice_key) {
            chip.push_str(" • WATCHED");
        }
        widgets::card_title_row(ui, &notice.title, &chip, |_| {});
        ui.add_space(3.0);
        ui.label(
            RichText::new(&notice.summary)
                .color(theme::SILVER_DIM)
                .size(13.0),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            // Amendment §10: 12px actions with 10px gaps.
            ui.spacing_mut().item_spacing.x = 10.0;
            if widgets::notice_action_button(ui, "Dismiss today", DISMISS_HELP) {
                actions.push(CurationAction::DismissToday(notice.notice_key.clone()));
            }
            let muted = state.muted.contains(&notice.notice_key);
            let (mute_label, mute_help) = if muted {
                ("Unmute", UNMUTE_HELP)
            } else {
                ("Mute", MUTE_HELP)
            };
            if widgets::notice_action_button(ui, mute_label, mute_help) {
                actions.push(CurationAction::ToggleMute(notice.notice_key.clone()));
            }
            let watched = state.watched.contains(&notice.notice_key);
            let (watch_label, watch_help) = if watched {
                ("Stop watching", UNWATCH_HELP)
            } else {
                ("Watch", WATCH_HELP)
            };
            if widgets::notice_action_button(ui, watch_label, watch_help) {
                actions.push(CurationAction::ToggleWatch(notice.notice_key.clone()));
            }
        });
        if !notice.evidence.is_empty() || !notice.detail.is_empty() {
            ui.add_space(4.0);
            let evidence_title = if notice.evidence.is_empty() {
                "Evidence".to_string()
            } else {
                {
                    let count = notice.evidence.len();
                    let noun = if count == 1 { "entry" } else { "entries" };
                    format!("Evidence ({count} {noun})")
                }
            };
            egui::CollapsingHeader::new(
                RichText::new(evidence_title).color(theme::BLUE).size(12.0),
            )
            .id_salt(&notice.notice_key)
            .default_open(false)
            .show(ui, |ui| {
                if !notice.detail.is_empty() {
                    caption(ui, &notice.detail);
                }
                if !notice.evidence.is_empty() {
                    evidence_grid(ui, &notice.notice_key, &notice.evidence)
                }
            });
        }
    });
}

/// Mirrors `_discovery_evidence_row`: value-free columns only, shown for a
/// column when any row carries it, in the Streamlit column order.
/// UX-16: rendered through the shared data_table so free-length path
/// chains scroll instead of stretching the page.
fn evidence_grid(ui: &mut egui::Ui, notice_key: &str, evidence: &[DiscoveryNoticeEvidence]) {
    struct Column {
        header: &'static str,
        value: fn(&DiscoveryNoticeEvidence) -> Option<String>,
    }
    let columns: [Column; 9] = [
        Column {
            header: "Seen at",
            value: |row| Some(local_clock(row.occurred_at_ms)),
        },
        Column {
            header: "Path",
            value: |row| (!row.path.is_empty()).then(|| row.path.join(" -> ")),
        },
        Column {
            header: "Duration",
            value: |row| row.duration_ms.map(format_duration_ms),
        },
        Column {
            header: "Away",
            value: |row| row.away_ms.map(format_duration_ms),
        },
        Column {
            header: "Restart",
            value: |row| row.restart_ms.map(format_duration_ms),
        },
        Column {
            header: "Inputs",
            value: |row| row.input_events.map(thousands),
        },
        Column {
            header: "Switches",
            value: |row| row.switch_count.map(thousands),
        },
        Column {
            header: "Rate",
            value: |row| row.rate.map(|rate| format!("{rate:.1}")),
        },
        Column {
            header: "Note",
            value: |row| (!row.note.is_empty()).then(|| row.note.clone()),
        },
    ];
    let active: Vec<&Column> = columns
        .iter()
        .filter(|column| evidence.iter().any(|row| (column.value)(row).is_some()))
        .collect();
    let headers: Vec<&str> = active.iter().map(|column| column.header).collect();
    let rows: Vec<Vec<String>> = evidence
        .iter()
        .map(|row| {
            active
                .iter()
                .map(|column| (column.value)(row).unwrap_or_default())
                .collect()
        })
        .collect();
    widgets::data_table(ui, &format!("evidence-{notice_key}"), &headers, &rows);
}
