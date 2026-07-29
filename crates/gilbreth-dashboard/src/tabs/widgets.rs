//! Shared building blocks the tabs compose: captions, section kickers,
//! bellows cards, metric tiles, the metric glossary, and the pattern
//! candidate card (Week renders it read-only; Analytics adds the record
//! button when it lands). Copy stays verbatim with the Streamlit dashboard.

use egui::{Color32, CornerRadius, FontId, RichText, Stroke};

use crate::data::SEQUENCE_MIN_HISTORY_DAYS;
use crate::theme;

pub fn caption(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::GRAY).size(11.5));
}

/// A section kicker in the amendment register: 18px tracked mono caps
/// in brass, full pre-space (§3). Sections that open directly under the
/// tab/page opener use [`opening_section_kicker`] instead.
pub fn section_kicker(ui: &mut egui::Ui, text: &str) {
    kicker_with_prespace(ui, text, theme::SECTION_PRESPACE);
}

/// The pulled-up kicker for a section directly under a tab/page opener
/// (amendment §3: ~20px, never a 64px hole at the top of a tab).
pub fn opening_section_kicker(ui: &mut egui::Ui, text: &str) {
    kicker_with_prespace(ui, text, theme::SECTION_PRESPACE_OPENER);
}

fn kicker_with_prespace(ui: &mut egui::Ui, text: &str, prespace: f32) {
    ui.add_space(prespace);
    ui.label(theme::kicker_job(text));
    ui.add_space(theme::SECTION_GAP_BELOW);
}

/// The takeaway register (amendment §2): one finding-class sentence per
/// section, 15px full silver. The standing rule: findings never render
/// in `caption()` — captions carry provenance, method, and asides.
pub fn takeaway(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(theme::SILVER)
            .size(theme::TAKEAWAY_SIZE),
    );
}

/// The secnote register (amendment §6): a one-line section note as
/// reading text — 14px full silver, wrapping only at the gutter.
pub fn secnote(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(theme::SILVER)
            .size(theme::SECNOTE_SIZE),
    );
}

pub fn card_frame() -> egui::Frame {
    egui::Frame::default()
        .fill(theme::BELLOWS)
        .corner_radius(CornerRadius::same(8))
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x34, 0x39, 0x42)))
        .inner_margin(14.0)
}

pub fn small_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(label).size(11.5)))
        .clicked()
}

/// UX-28: a quiet chip/tab button — transparent at rest, but egui's
/// hovered/active fills stay alive so it still looks clickable.
pub fn quiet_tab_button(ui: &mut egui::Ui, text: RichText) -> egui::Response {
    ui.scope(|ui| {
        let widgets = &mut ui.style_mut().visuals.widgets;
        widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
        widgets.inactive.bg_fill = Color32::TRANSPARENT;
        widgets.inactive.bg_stroke = Stroke::NONE;
        ui.add(egui::Button::new(text))
    })
    .inner
}

/// UX-34: one-shot outcome notices carry a glyph beside the color, so
/// success and error never differ by hue alone.
pub fn outcome_notice(ui: &mut egui::Ui, is_error: bool, message: &str) {
    let (glyph, color) = if is_error {
        ("⚠", theme::RED)
    } else {
        ("✔", theme::BLUE)
    };
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(RichText::new(glyph).color(color).size(12.5));
        ui.label(RichText::new(message).color(color).size(12.5));
    });
}

/// A small button with hover help, so terse action labels like "Mute" say
/// what they actually do (UX-30).
pub fn small_button_help(ui: &mut egui::Ui, label: &str, help: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(label).size(11.5)))
        .on_hover_text(help)
        .clicked()
}

/// One raised stat tile (the Streamlit `render_session_total` look).
pub fn metric_tile(ui: &mut egui::Ui, label: &str, value: &str) {
    metric_tile_help(ui, label, value, None);
}

/// Minimum width one metric tile needs before its row wraps (UX-21). At
/// the 1040 pt content cap this keeps Diagnostics' seven-tile row on one
/// line; below ~660 px rows fold to 4-then-N instead of crushing labels.
const TILE_MIN_WIDTH: f32 = 132.0;

/// One row's worth of metric tiles, wrapping into extra rows when the
/// window is too narrow for one tile per column (UX-21). Each tile is
/// (label, value, optional hover help).
pub fn metric_tile_flow(ui: &mut egui::Ui, tiles: &[(&str, String, Option<&str>)]) {
    if tiles.is_empty() {
        return;
    }
    let spacing = ui.spacing().item_spacing.x;
    let fit = ((ui.available_width() + spacing) / (TILE_MIN_WIDTH + spacing)).floor() as usize;
    let per_row = fit.clamp(1, tiles.len());
    for chunk in tiles.chunks(per_row) {
        ui.columns(per_row, |columns| {
            for (column, (label, value, help)) in columns.iter_mut().zip(chunk) {
                metric_tile_help(column, label, value, *help);
            }
        });
    }
}

/// The visible cue that a tile or label carries hover help (UX-27).
pub const HELP_GLYPH: &str = "ℹ";

/// The tile/metric label row, with the info glyph appended when hover help
/// exists so the affordance is discoverable without hovering (UX-27).
fn help_label_row(ui: &mut egui::Ui, label: &str, size: f32, has_help: bool) {
    if has_help {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(RichText::new(label).color(theme::GRAY).size(size));
            ui.label(RichText::new(HELP_GLYPH).color(theme::BLUE).size(size));
        });
    } else {
        ui.label(RichText::new(label).color(theme::GRAY).size(size));
    }
}

/// A stat tile with the `st.metric(help=...)` hover explainer.
pub fn metric_tile_help(ui: &mut egui::Ui, label: &str, value: &str, help: Option<&str>) {
    let response = card_frame()
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Plain top-down layout: `ui.columns` cross-justifies, which
            // letter-spreads any wrapped label line.
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                help_label_row(ui, label, 10.5, help.is_some());
                ui.label(
                    RichText::new(value)
                        .color(theme::SILVER)
                        .font(FontId::new(19.0, theme::family_medium())),
                );
            });
        })
        .response;
    if let Some(help) = help {
        response
            .on_hover_cursor(egui::CursorIcon::Help)
            .on_hover_text(help);
    }
}

/// Mirrors `patterns_empty_caption`: distinguish "not enough history yet"
/// from "enough history, nothing recurred".
pub fn patterns_empty_caption(pattern_history_days: i64) -> String {
    if pattern_history_days < SEQUENCE_MIN_HISTORY_DAYS {
        let day_word = if pattern_history_days == 1 {
            "day"
        } else {
            "days"
        };
        format!(
            "Patterns need at least {SEQUENCE_MIN_HISTORY_DAYS} days of history to appear. \
             Gilbreth has {pattern_history_days} {day_word} so far. They'll show up here after \
             enough activity has been captured."
        )
    } else {
        "Nothing has repeated often enough yet to flag. Patterns appear here when something \
         recurs across your history."
            .to_string()
    }
}

/// Mirrors `st.info`: a quiet bellows card for empty-state explanations.
pub fn info_box(ui: &mut egui::Ui, text: &str) {
    card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(text).color(theme::SILVER).size(13.0));
    });
}

pub fn bullet_list(ui: &mut egui::Ui, bullets: &[&str]) {
    for bullet in bullets {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("•").color(theme::GRAY).size(12.5));
            ui.label(RichText::new(*bullet).color(theme::GRAY).size(12.5));
        });
    }
}

pub fn explainer(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).color(theme::GRAY).size(12.0))
        .default_open(false)
        .show(ui, body);
}

/// A monospace data table with the Streamlit column headers, horizontally
/// scrollable so wide breakdowns never stretch the page.
pub fn data_table(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<String>]) {
    egui::ScrollArea::horizontal()
        .id_salt(id)
        .auto_shrink([false, true])
        // UX-16: a clipped right edge gets a visible affordance instead of
        // a scrollbar that only appears on hover.
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .show(ui, |ui| {
            egui::Grid::new(id)
                .spacing(egui::vec2(20.0, 4.0))
                .show(ui, |ui| {
                    for header in headers {
                        ui.label(
                            RichText::new(*header)
                                .color(theme::GRAY)
                                .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                        );
                    }
                    ui.end_row();
                    for row in rows {
                        for cell in row {
                            ui.label(
                                RichText::new(cell)
                                    .color(theme::SILVER_DIM)
                                    .font(FontId::new(11.5, egui::FontFamily::Monospace)),
                            );
                        }
                        ui.end_row();
                    }
                });
        });
}

/// Mirrors `_CANDIDATE_KIND_LABELS`.
pub fn candidate_kind_label(kind: &str) -> &str {
    match kind {
        "automatable_routine" => "Routine",
        "fragmentation" => "Fragmentation",
        "input_exposure" => "Input exposure",
        other => other,
    }
}

/// UX-37 (owner decision 2026-07-10): the "may be normal workflow" hedge
/// is stated once under each pattern section's kicker, never per card.
pub const PATTERNS_DESCRIPTIVE_CAPTION: &str = "Any pattern here can simply be normal workflow.";

pub const RECORD_BUTTON_LABEL: &str = "Ask tray to record this routine";
pub const RECORD_SENT_CAPTION: &str =
    "Request sent. The Gilbreth tray will ask before recording starts.";

/// UX-45: one sentence per request state instead of the sent caption plus
/// a raw "Record request status: requested" token line.
pub fn record_status_line(status: &str) -> String {
    match status {
        "requested" => RECORD_SENT_CAPTION.to_string(),
        "confirmed" => "The tray confirmed the request; recording is starting.".to_string(),
        "started" => {
            // copy-allow: em-dash one prose em dash within the per-string cap (the one-per-string cap)
            "Recording now — the tray indicator is on.".to_string()
        }
        "expired" => "The request expired before the tray answered.".to_string(),
        "cancelled" => "The recording request was cancelled at the tray.".to_string(),
        "failed" => "The recording request failed. Check the Gilbreth tray.".to_string(),
        other => format!("Record request status: {other}"),
    }
}

// ------------------------------------------------------------------------
// The instrument-register anatomy (dashboard register program): shared by
// the redesigned tabs from slice 2 on. Summary-carrying sections, aligned
// check tables, framed state chips, flagged lines, and uniform gauges.

use egui::{Margin, Sense};

/// A summary-carrying collapsing section: the header states the section's
/// one-line story so nothing needs opening to know its state.
pub fn summary_section(
    ui: &mut egui::Ui,
    id_salt: &str,
    name: &str,
    summary: &str,
    summary_flagged: bool,
    default_open: bool,
    body: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let id = ui.make_persistent_id(id_salt);
            let mut state = egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                id,
                default_open,
            );
            let header = ui
                .horizontal(|ui| {
                    // Text selection would swallow the header's whole-row
                    // click sense; the header is a control, not copy.
                    ui.style_mut().interaction.selectable_labels = false;
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let (icon_rect, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                    let icon_response = ui.interact(icon_rect, id.with("icon"), Sense::hover());
                    let openness = if state.is_open() { 1.0 } else { 0.0 };
                    egui::collapsing_header::paint_default_icon(ui, openness, &icon_response);
                    ui.label(
                        RichText::new(name)
                            .color(theme::SILVER)
                            .font(FontId::new(13.0, theme::family_medium())),
                    );
                    // Amendment §1: the plain-"Details" variant carries no
                    // subtext; state-carrying summaries keep their slot.
                    if !summary.is_empty() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let color = if summary_flagged {
                                theme::RED
                            } else {
                                theme::GRAY
                            };
                            ui.label(RichText::new(summary).color(color).size(12.0));
                        });
                    }
                })
                .response;
            if ui
                .interact(header.rect, id.with("header"), Sense::click())
                .clicked()
            {
                state.toggle(ui);
            }
            state.show_body_unindented(ui, |ui| {
                ui.add_space(2.0);
                body(ui);
            });
        });
}

/// One aligned check-table row: label, mono value, and a brass tick when
/// the check is settled-good. Red pencil on the value marks a flagged read.
#[derive(Default)]
pub struct CheckRow {
    pub label: String,
    pub value: String,
    pub dim: bool,
    pub flagged: bool,
    pub tick: bool,
    pub hover: Option<String>,
}

pub fn check_table(ui: &mut egui::Ui, id: &str, rows: &[CheckRow]) {
    egui::Grid::new(id)
        .spacing(egui::vec2(18.0, 5.0))
        .show(ui, |ui| {
            for row in rows {
                ui.label(RichText::new(&row.label).color(theme::GRAY).size(12.5));
                let value_color = if row.flagged {
                    theme::RED
                } else if row.dim {
                    theme::GRAY
                } else {
                    theme::SILVER_DIM
                };
                let value_response = ui.label(
                    RichText::new(&row.value)
                        .color(value_color)
                        .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                );
                if let Some(hover) = &row.hover {
                    value_response
                        .on_hover_cursor(egui::CursorIcon::Help)
                        .on_hover_text(hover);
                }
                if row.tick {
                    ui.label(
                        RichText::new("✓")
                            .color(theme::BRASS)
                            .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                    );
                } else {
                    ui.label("");
                }
                ui.end_row();
            }
        });
}

/// A small framed state chip in the two-level language: brass outline for a
/// settled-good state, quiet gray for off/neutral.
pub fn state_chip(ui: &mut egui::Ui, text: &str, on: bool) {
    let color = if on { theme::BRASS } else { theme::GRAY };
    egui::Frame::default()
        .stroke(Stroke::new(1.0, color))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .color(color)
                    .font(FontId::new(11.0, egui::FontFamily::Monospace)),
            );
        });
}

/// A flagged state inside a section: red pencil, small — the two-level
/// language's loud level, spent only when something is actually flagged.
pub fn flagged_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::RED).size(12.5));
}

/// The engraved brass family chip (amendment §9): the discovery-card
/// mark — notices, pattern cards, the week's friction card. 11.5px
/// tracked mono caps, lifted-brass text over the brass well inside a
/// brass hairline. Plain sections stay unaccented so the mark keeps
/// meaning; amber is never spent on chips.
/// A card's fixed header-row height: the family chip's frame (11.5 mono
/// line + 8 vertical margin + 2 stroke) is taller than the 14.5 title
/// line, and egui's wrapped rows size to the tallest item seen SO FAR —
/// so a chip placed after the title hangs below the title's centerline
/// unless the row height is fixed up front (2026-07-28 UI/UX pass).
const CARD_TITLE_ROW_HEIGHT: f32 = 24.0;

/// Card header row: title and family chip centered on one shared line,
/// plus whatever the caller appends (e.g. right-aligned meta).
pub fn card_title_row(
    ui: &mut egui::Ui,
    title: &str,
    chip: &str,
    extra: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.set_row_height(CARD_TITLE_ROW_HEIGHT);
        ui.label(
            RichText::new(title)
                .color(theme::SILVER)
                .font(theme::heading_card()),
        );
        family_chip(ui, chip);
        extra(ui);
    });
}

pub fn family_chip(ui: &mut egui::Ui, text: &str) {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        text,
        0.0,
        egui::text::TextFormat {
            font_id: FontId::new(11.5, egui::FontFamily::Monospace),
            color: theme::BRASS_CHIP_TEXT,
            extra_letter_spacing: 0.9,
            ..Default::default()
        },
    );
    egui::Frame::default()
        .fill(theme::BRASS_WELL)
        .stroke(Stroke::new(1.0, theme::BRASS))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(job);
        });
}

/// The accented discovery-card frame (amendment §9): quiet hairline,
/// 14×16 padding (§8), and a 2px brass left edge painted over the frame
/// so the cornerstone cards read as one family.
pub fn accent_card(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    let response = egui::Frame::default()
        .stroke(Stroke::new(1.0, theme::BELLOWS))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui);
        })
        .response;
    let rect = response.rect;
    let edge = egui::Rect::from_min_max(
        rect.left_top(),
        egui::Pos2::new(rect.left() + 2.0, rect.bottom()),
    );
    ui.painter().rect_filled(
        edge,
        CornerRadius {
            nw: 2,
            sw: 2,
            ne: 0,
            se: 0,
        },
        theme::BRASS,
    );
}

/// A discovery-card action (amendment §10): 12px quiet buttons with
/// hover help, one step up from the 11.5px small-button register so the
/// cornerstone cards' actions read beside their 13px facts line.
pub fn notice_action_button(ui: &mut egui::Ui, label: &str, help: &str) -> bool {
    let response = ui.add(egui::Button::new(RichText::new(label).size(12.0)));
    let response = if help.is_empty() {
        response
    } else {
        response.on_hover_text(help)
    };
    response.clicked()
}

/// One share-bar block (amendment §10): app names in 12px mono (process
/// names are machine identifiers), and every row on ONE measure — fixed
/// name column, the figures column sized to the widest row — so no app's
/// track renders longer than another's.
pub struct ShareBarRow {
    pub name: String,
    /// 0..=1 of the leader's/total measure, the fill fraction.
    pub share: f32,
    pub color: egui::Color32,
    /// The mono figures after the track ("6h 12m", "active 1h 23m • …").
    pub figures: String,
}

pub fn share_bars(ui: &mut egui::Ui, rows: &[ShareBarRow]) {
    if rows.is_empty() {
        return;
    }
    let figure_font = FontId::new(11.5, egui::FontFamily::Monospace);
    let figures_width = rows
        .iter()
        .map(|row| {
            ui.painter()
                .layout_no_wrap(row.figures.clone(), figure_font.clone(), theme::SILVER_DIM)
                .rect
                .width()
        })
        .fold(0.0_f32, f32::max);
    for row in rows {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            ui.allocate_ui_with_layout(
                egui::vec2(110.0, 18.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&row.name)
                                .color(theme::SILVER)
                                .font(FontId::new(12.0, egui::FontFamily::Monospace)),
                        )
                        .truncate(),
                    );
                },
            );
            let track_width = (ui.available_width() - figures_width - 12.0).max(60.0);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(track_width, 6.0), Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(rect, 3.0, theme::WELL);
            let mut fill = rect;
            fill.set_width(rect.width() * row.share.clamp(0.01, 1.0));
            painter.rect_filled(fill, 3.0, row.color);
            ui.label(
                RichText::new(&row.figures)
                    .color(theme::SILVER_DIM)
                    .font(figure_font.clone()),
            );
        });
    }
}

/// UXR-07: the shared confirm-then-act destructive gate (the Privacy prune
/// and the Recordings delete): a gated confirm checkbox, then a button that
/// reads red pencil only while armed. Returns true when the armed button
/// was clicked this frame.
#[allow(clippy::too_many_arguments)]
pub fn confirm_gate(
    ui: &mut egui::Ui,
    confirm_id: egui::Id,
    confirm_label: &str,
    confirm_enabled: bool,
    confirm_disabled_reason: &str,
    button_label: &str,
    button_disabled_reason: &str,
) -> bool {
    let mut confirm: bool = ui
        .ctx()
        .data_mut(|data| data.get_temp(confirm_id).unwrap_or(false));
    let mut response = ui.add_enabled(
        confirm_enabled,
        egui::Checkbox::new(&mut confirm, confirm_label),
    );
    if !confirm_disabled_reason.is_empty() {
        response = response.on_disabled_hover_text(confirm_disabled_reason);
    }
    if response.changed() {
        ui.ctx()
            .data_mut(|data| data.insert_temp(confirm_id, confirm));
    }
    let armed = confirm && confirm_enabled;
    let button_text =
        RichText::new(button_label)
            .size(11.5)
            .color(if armed { theme::RED } else { theme::GRAY });
    ui.add_enabled(armed, egui::Button::new(button_text))
        .on_disabled_hover_text(button_disabled_reason)
        .clicked()
}

/// The quiet mono micro-label ahead of the view switcher (Analytics round,
/// owner 2026-07-13): left of the scope row answers what data, right
/// answers which lens.
pub const VIEW_MICRO_LABEL: &str = "VIEW";

/// The two-lens segmented view switcher at the right end of a scope row:
/// both options always visible, the selected segment filled Bellows +
/// silver, the unselected quiet gray, behind the VIEW micro-label. Call it
/// inside a right-to-left layout; egui's `horizontal` keeps that parent
/// preference, so the tuple iteration is reversed and the control reads
/// left-to-right.
pub fn view_switcher(ui: &mut egui::Ui, id_salt: &str, labels: [&str; 2], selected: &mut usize) {
    egui::Frame::default()
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x3A, 0x3F, 0x47)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::same(0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.style_mut().interaction.selectable_labels = false;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (index, label) in labels.iter().enumerate().rev() {
                    let is_selected = *selected == index;
                    let (fill, color) = if is_selected {
                        (theme::BELLOWS, theme::SILVER)
                    } else {
                        (Color32::TRANSPARENT, theme::GRAY)
                    };
                    let response = egui::Frame::default()
                        .fill(fill)
                        .inner_margin(egui::Margin::symmetric(14, 6))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(*label)
                                    .color(color)
                                    .font(FontId::new(12.0, theme::family_medium())),
                            );
                        })
                        .response;
                    let response = ui.interact(
                        response.rect,
                        ui.id().with((id_salt, *label)),
                        egui::Sense::click(),
                    );
                    if response.clicked() {
                        *selected = index;
                    }
                }
            });
        });
    ui.label(
        RichText::new(VIEW_MICRO_LABEL)
            .color(theme::GRAY)
            .font(FontId::new(10.0, egui::FontFamily::Monospace)),
    );
}

/// A uniform gauge row set: one size, one label style, no hover help.
/// Four per row (the card proportion), fewer only when the window is
/// genuinely too narrow.
pub fn gauge_tiles(ui: &mut egui::Ui, gauges: &[(&str, String)]) {
    gauge_tiles_capped(ui, gauges, 4);
}

/// The gauge row with an explicit per-row cap, for the sections whose
/// decided card runs wider than four.
pub fn gauge_tiles_capped(ui: &mut egui::Ui, gauges: &[(&str, String)], cap: usize) {
    let rows: Vec<(&str, String, Option<String>)> = gauges
        .iter()
        .map(|(label, value)| (*label, value.clone(), None))
        .collect();
    gauge_tiles_suffixed(ui, &rows, cap);
}

/// The gauge row with per-gauge value suffixes (amendment §7): values
/// 19px, suffixes 12.5px quiet on the same line — "75.0 MB",
/// "2 • 1 recovered" — labels 11.5px.
pub fn gauge_tiles_suffixed(
    ui: &mut egui::Ui,
    gauges: &[(&str, String, Option<String>)],
    cap: usize,
) {
    if gauges.is_empty() {
        return;
    }
    let spacing = ui.spacing().item_spacing.x;
    let fit = ((ui.available_width() + spacing) / (132.0 + spacing)).floor() as usize;
    let per_row = fit.clamp(1, cap.max(1)).min(gauges.len());
    for chunk in gauges.chunks(per_row) {
        ui.columns(per_row, |columns| {
            for (column, (label, value, suffix)) in columns.iter_mut().zip(chunk) {
                card_frame().inner_margin(10.0).show(column, |ui| {
                    ui.set_width(ui.available_width());
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.label(RichText::new(*label).color(theme::GRAY).size(11.5));
                        // One LayoutJob so the 12.5px suffix shares the
                        // 19px value's baseline (and the reader hears one
                        // value, "75.0 MB", not two fragments).
                        let mut job = egui::text::LayoutJob::default();
                        job.append(
                            value,
                            0.0,
                            egui::text::TextFormat {
                                font_id: FontId::new(19.0, theme::family_medium()),
                                color: theme::SILVER,
                                valign: egui::Align::BOTTOM,
                                ..Default::default()
                            },
                        );
                        if let Some(suffix) = suffix {
                            job.append(
                                &format!(" {suffix}"),
                                0.0,
                                egui::text::TextFormat {
                                    font_id: FontId::new(12.5, egui::FontFamily::Proportional),
                                    color: theme::GRAY,
                                    valign: egui::Align::BOTTOM,
                                    ..Default::default()
                                },
                            );
                        }
                        ui.label(job);
                    });
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_empty_caption_pins_the_python_floor_of_two_days() {
        // db.py SEQUENCE_MIN_HISTORY_DAYS == 2; the caption must not drift.
        assert!(patterns_empty_caption(0).contains("at least 2 days of history"));
        assert!(patterns_empty_caption(1).contains("Gilbreth has 1 day so far"));
        assert!(patterns_empty_caption(2).starts_with("Nothing has repeated often enough"));
    }
}
