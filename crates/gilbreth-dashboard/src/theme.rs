//! The brand tokens and the egui style for the darkroom register.
//!
//! The dashboard's data views hold the dark register: darkroom background,
//! bellows surfaces, silver-print text. Color is punctuation — light trail
//! amber gets ONE loud moment per view, brass draws hairlines and labels,
//! process blue carries links and secondary chart series, red pencil appears
//! only when something is being flagged.

use egui::style::Selection;
use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub const DARKROOM: Color32 = Color32::from_rgb(0x15, 0x17, 0x1B);
pub const BELLOWS: Color32 = Color32::from_rgb(0x2A, 0x2E, 0x35);
pub const SILVER: Color32 = Color32::from_rgb(0xF2, 0xEF, 0xE8);
pub const GRAY: Color32 = Color32::from_rgb(0x9A, 0xA3, 0xAE);
pub const AMBER: Color32 = Color32::from_rgb(0xF2, 0xA3, 0x3C);
pub const BRASS: Color32 = Color32::from_rgb(0xB0, 0x8D, 0x3E);
/// Process blue, on-dark text stop (5.76:1 on darkroom).
pub const BLUE: Color32 = Color32::from_rgb(0x5E, 0x97, 0xC9);
/// Red pencil, on-dark text stop (5.18:1 on darkroom). Flags only.
pub const RED: Color32 = Color32::from_rgb(0xE2, 0x61, 0x4F);

/// A step below bellows for wells and chart tracks.
pub const WELL: Color32 = Color32::from_rgb(0x1C, 0x1F, 0x25);
/// Red pencil sunk into darkroom: the flag-row ground. Loud only next to
/// its hairline; reads as a marked page, not an alarm panel.
pub const RED_WELL: Color32 = Color32::from_rgb(0x22, 0x1A, 0x19);
/// The flag-row hairline (red analog of HAIRLINE).
pub const RED_HAIRLINE: Color32 = Color32::from_rgb(0x4A, 0x2A, 0x26);
/// Hairline stroke between regions — brass at low alpha reads as instrument
/// hardware without paint.
pub const HAIRLINE: Color32 = Color32::from_rgba_premultiplied(0x4A, 0x42, 0x2A, 0xFF);
/// Muted silver for de-emphasized values that still need to read as data.
pub const SILVER_DIM: Color32 = Color32::from_rgb(0xC6, 0xC2, 0xB8);
/// Brass, one step lighter for small text on BELLOWS cards (UX-54): plain
/// BRASS lands ~4.3:1 there, under the 4.5:1 small-text threshold; this
/// stop reads ~5.0:1 on cards while staying recognizably brass.
pub const BRASS_ON_CARD: Color32 = Color32::from_rgb(0xBD, 0x97, 0x42);
/// The engraved brass family chip's text stop (type-ramp amendment §9):
/// lifted brass that reads over the brass-tinted well below.
pub const BRASS_CHIP_TEXT: Color32 = Color32::from_rgb(0xC9, 0xA9, 0x61);
/// The brass-tinted well: family-chip fill and the export kit's ground.
pub const BRASS_WELL: Color32 = Color32::from_rgb(0x1E, 0x1B, 0x14);

/// Ranked series colors for app bands: the top app gets the light trail; the
/// rest stay quiet so the amber reads as "your motion", not decoration.
/// Brass is deliberately absent — beside amber it reads as a second, wrong
/// amber ("two competing ambers means one is wrong").
/// UX-53: the low ranks stay deliberately quiet but hold >= 3:1 on the
/// WELL track (WCAG 1.4.11 non-text guidance), so rank-3+ apps stay
/// visible in the day strip without hovering.
pub const SERIES: [Color32; 6] = [
    AMBER,
    BLUE,
    Color32::from_rgb(0x8A, 0x94, 0xA6), // instrument gray, lifted (5.4:1)
    Color32::from_rgb(0x6E, 0x76, 0x83), // 3.6:1
    Color32::from_rgb(0x66, 0x6E, 0x7A), // 3.2:1
    Color32::from_rgb(0x62, 0x6A, 0x76), // 3.0:1
];

pub fn series_color(rank: usize) -> Color32 {
    SERIES[rank.min(SERIES.len() - 1)]
}

/// Named font families registered in [`crate::fonts::install`].
pub fn family_medium() -> FontFamily {
    FontFamily::Name("inter-medium".into())
}

pub fn family_semibold() -> FontFamily {
    FontFamily::Name("inter-semibold".into())
}

/// UX-19: the two heading levels every hand-rolled semibold size maps to.
/// Page-level (the no-DB card) and card/section-level (card titles, the
/// health status line, the recording detail heading).
pub fn heading_page() -> FontId {
    FontId::new(17.0, family_semibold())
}

pub fn heading_card() -> FontId {
    FontId::new(14.5, family_semibold())
}

// ------------------------------------------------------------------------
// Type-ramp & register amendment (2026-07-13): section rhythm, the tracked
// kicker, and the takeaway/secnote registers.

/// Pre-space before a section kicker. The visual target is the card
/// figure (~64 px at the 1240 pt baseline width); egui's 7 px item
/// spacing rides on top of this value.
pub const SECTION_PRESPACE: f32 = 57.0;
/// The pulled-up variant for a section that opens directly under the
/// tab/page opener (amendment §3: ~20 px, no 64 px hole).
pub const SECTION_PRESPACE_OPENER: f32 = 13.0;
/// The gap under a kicker (~14 px rendered, item spacing included).
pub const SECTION_GAP_BELOW: f32 = 7.0;

/// The takeaway register (amendment §2): finding-class sentences,
/// 15 px full silver, every tab. Findings never render in `caption()`.
pub const TAKEAWAY_SIZE: f32 = 15.0;
/// The secnote register (amendment §6): one-line section notes as
/// reading text — 14 px full silver, full panel width (no measure).
pub const SECNOTE_SIZE: f32 = 14.0;

/// Dashboard section kickers: 18 px tracked mono caps in brass — the
/// committed BRAND type-rule-3 exception (6836097), scoped to dashboard
/// section headers; the 13 px tracked-caps cap holds everywhere else.
/// `RichText` cannot letter-space, so kickers render via a `LayoutJob`
/// with `extra_letter_spacing` (~.14em at 18 px).
pub fn kicker_job(text: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        text,
        0.0,
        egui::text::TextFormat {
            font_id: FontId::new(18.0, FontFamily::Monospace),
            color: BRASS,
            extra_letter_spacing: 2.5,
            ..Default::default()
        },
    );
    job
}

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();

    style.text_styles = [
        (
            TextStyle::Small,
            FontId::new(11.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.0, family_medium())),
        (TextStyle::Heading, FontId::new(17.0, family_semibold())),
        (
            TextStyle::Monospace,
            FontId::new(12.0, FontFamily::Monospace),
        ),
    ]
    .into();

    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(11.0, 5.0);
    style.spacing.menu_margin = egui::Margin::same(8);
    style.spacing.indent = 18.0;

    let mut visuals = Visuals::dark();
    visuals.panel_fill = DARKROOM;
    visuals.window_fill = BELLOWS;
    visuals.extreme_bg_color = WELL;
    visuals.faint_bg_color = BELLOWS;
    visuals.override_text_color = Some(SILVER);
    visuals.hyperlink_color = BLUE;
    visuals.selection = Selection {
        bg_fill: AMBER.gamma_multiply(0.35),
        stroke: Stroke::new(1.0, AMBER),
    };
    visuals.widgets.noninteractive.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(0x33, 0x38, 0x40));
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, SILVER);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(0x33, 0x38, 0x40);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(0x33, 0x38, 0x40);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, SILVER);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x3D, 0x43, 0x4D);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x3D, 0x43, 0x4D);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BRASS);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, SILVER);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0x46, 0x4D, 0x59);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, SILVER);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(4);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(4);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(4);
    visuals.widgets.active.corner_radius = CornerRadius::same(4);
    visuals.popup_shadow.color = Color32::from_black_alpha(96);
    visuals.window_shadow.color = Color32::from_black_alpha(96);
    style.visuals = visuals;

    ctx.set_style_of(egui::Theme::Dark, style);
}
