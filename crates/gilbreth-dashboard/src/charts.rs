//! The shared charts module: day strip, hourly input pulse, 7-day bars.
//! One place owns band layout, hour ticks, and hover hit-testing so every
//! tab's timeline reads the same. Colors follow the brand tokens in
//! `theme.rs`: the top app by active time carries the light trail;
//! everything else stays quiet.

use std::collections::HashMap;

use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use gilbreth_read::{DayActive, DayStrip, HeatmapBucket, HourPulse};

use crate::format::{format_duration_ms, local_clock, thousands, RANGE_SEPARATOR};
use crate::theme;

const HOUR_MS: i64 = 3_600_000;

/// Dwell-ranked app colors for one day of bands. Rank 0 (most active time)
/// gets light trail amber — the view's one loud moment.
pub struct AppPalette {
    colors: HashMap<String, Color32>,
    /// Apps with their total band time, most first.
    pub ranked: Vec<(String, i64)>,
}

impl AppPalette {
    pub fn from_strip(strip: &DayStrip) -> Self {
        let mut dwell: HashMap<String, i64> = HashMap::new();
        for band in &strip.focus {
            *dwell.entry(band.app.clone()).or_insert(0) += band.end_ts - band.start_ts;
        }
        let mut ranked: Vec<(String, i64)> = dwell.into_iter().collect();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        let colors = ranked
            .iter()
            .enumerate()
            .map(|(rank, (app, _))| (app.clone(), theme::series_color(rank)))
            .collect();
        Self { colors, ranked }
    }

    pub fn color(&self, app: &str) -> Color32 {
        self.colors
            .get(app)
            .copied()
            .unwrap_or_else(|| theme::series_color(theme::SERIES.len()))
    }
}

/// The shared x-axis: a UTC-ms window aligned to the local-day hour grid
/// (`day_start + n hours`, the same DST-day approximation the readers pin).
#[derive(Clone, Copy)]
pub struct TimeAxis {
    pub start_ms: i64,
    pub end_ms: i64,
    day_start_ms: i64,
}

impl TimeAxis {
    /// Window from the first to the last activity, expanded to hour
    /// boundaries, spanning at least six hours, always reaching `now`.
    pub fn for_day(strip: &DayStrip) -> Self {
        let day_start = strip.day_start_ms;
        let mut first = strip.day_end_ms;
        let mut last = strip.day_end_ms;
        for band in &strip.focus {
            first = first.min(band.start_ts);
            last = last.max(band.end_ts);
        }
        for (away_start, away_end) in &strip.away {
            first = first.min(*away_start);
            last = last.max(*away_end);
        }
        let floor_hour = |ts: i64| day_start + ((ts - day_start).max(0) / HOUR_MS) * HOUR_MS;
        let ceil_hour = |ts: i64| {
            let offset = (ts - day_start).max(0);
            day_start + ((offset + HOUR_MS - 1) / HOUR_MS).max(1) * HOUR_MS
        };
        let mut start = floor_hour(first);
        let mut end = ceil_hour(last.max(strip.day_end_ms));
        const MIN_SPAN_MS: i64 = 6 * HOUR_MS;
        if end - start < MIN_SPAN_MS {
            end = start + MIN_SPAN_MS;
        }
        // Never scroll past midnight into hour labels that don't exist today.
        start = start.max(day_start);
        Self {
            start_ms: start,
            end_ms: end,
            day_start_ms: day_start,
        }
    }

    pub fn x_of(&self, rect: &Rect, ts: i64) -> f32 {
        let span = (self.end_ms - self.start_ms).max(1) as f32;
        rect.left() + rect.width() * ((ts - self.start_ms) as f32 / span)
    }

    fn ts_of(&self, rect: &Rect, x: f32) -> i64 {
        let fraction = ((x - rect.left()) / rect.width().max(1.0)).clamp(0.0, 1.0);
        self.start_ms + ((self.end_ms - self.start_ms) as f32 * fraction) as i64
    }

    /// Hour tick positions with their local labels, thinned to keep at
    /// least ~48 px between labeled ticks.
    fn ticks(&self, rect: &Rect) -> Vec<(f32, i64, bool)> {
        let px_per_hour =
            rect.width() / (((self.end_ms - self.start_ms) as f32 / HOUR_MS as f32).max(1.0));
        let label_every = if px_per_hour >= 48.0 {
            1
        } else if px_per_hour >= 24.0 {
            2
        } else if px_per_hour >= 16.0 {
            3
        } else {
            6
        };
        let mut ticks = Vec::new();
        let mut ts = self.start_ms;
        while ts <= self.end_ms {
            let hour = ((ts - self.day_start_ms) / HOUR_MS).rem_euclid(24);
            let labeled = hour % label_every == 0;
            ticks.push((self.x_of(rect, ts), hour, labeled));
            ts += HOUR_MS;
        }
        ticks
    }
}

fn paint_hour_ticks(painter: &egui::Painter, axis: &TimeAxis, rect: &Rect, baseline: f32) {
    for (x, hour, labeled) in axis.ticks(rect) {
        painter.line_segment(
            [Pos2::new(x, baseline), Pos2::new(x, baseline + 4.0)],
            Stroke::new(1.0, theme::GRAY.gamma_multiply(0.7)),
        );
        if !labeled {
            continue;
        }
        // UX-55: edge labels anchor inward instead of being dropped, so the
        // axis start and end are never guesswork.
        let (anchor_x, align) = if x < rect.left() + 16.0 {
            (x.max(rect.left()), Align2::LEFT_TOP)
        } else if x > rect.right() - 16.0 {
            (x.min(rect.right()), Align2::RIGHT_TOP)
        } else {
            (x, Align2::CENTER_TOP)
        };
        painter.text(
            Pos2::new(anchor_x, baseline + 6.0),
            align,
            format!("{hour:02}:00"),
            FontId::new(11.0, egui::FontFamily::Monospace),
            theme::GRAY,
        );
    }
}

fn hover_panel(ui: &mut egui::Ui, lines: &[(String, Color32)]) {
    for (text, color) in lines {
        ui.label(
            egui::RichText::new(text)
                .color(*color)
                .font(FontId::new(11.5, egui::FontFamily::Monospace)),
        );
    }
}

/// The Today timeline: app bands over a well track, away as a thin center
/// line, hour ticks below, hover resolving the band under the pointer.
pub fn day_strip(ui: &mut egui::Ui, strip: &DayStrip, palette: &AppPalette) {
    let axis = TimeAxis::for_day(strip);
    let desired = Vec2::new(ui.available_width(), 66.0);
    let (response, painter) = ui.allocate_painter(desired, Sense::hover());
    let rect = response.rect;
    let track = Rect::from_min_max(
        Pos2::new(rect.left(), rect.top() + 2.0),
        Pos2::new(rect.right(), rect.top() + 40.0),
    );
    painter.rect_filled(track, 5.0, theme::WELL);

    // Away spans: a thin instrument-gray line at track center.
    let center_y = track.center().y;
    for (away_start, away_end) in &strip.away {
        let left = axis.x_of(&track, *away_start);
        let right = axis.x_of(&track, *away_end);
        if right - left < 1.0 {
            continue;
        }
        painter.line_segment(
            [Pos2::new(left, center_y), Pos2::new(right, center_y)],
            Stroke::new(2.0, theme::GRAY.gamma_multiply(0.8)),
        );
    }

    // Focus bands.
    for band in &strip.focus {
        let left = axis.x_of(&track, band.start_ts);
        let right = axis.x_of(&track, band.end_ts).max(left + 1.0);
        let band_rect = Rect::from_min_max(
            Pos2::new(left, track.top() + 5.0),
            Pos2::new(right, track.bottom() - 5.0),
        );
        painter.rect_filled(
            band_rect.shrink2(Vec2::new(0.4, 0.0)),
            3.0,
            palette.color(&band.app),
        );
    }

    // "Now" marker: a quiet silver tick at the right edge of recorded time.
    let now_x = axis.x_of(&track, strip.day_end_ms);
    painter.line_segment(
        [
            Pos2::new(now_x, track.top() - 2.0),
            Pos2::new(now_x, track.bottom() + 2.0),
        ],
        Stroke::new(1.0, theme::SILVER_DIM.gamma_multiply(0.85)),
    );

    paint_hour_ticks(&painter, &axis, &track, track.bottom() + 3.0);

    if let Some(pointer) = response.hover_pos() {
        if track.contains(pointer) {
            let ts = axis.ts_of(&track, pointer.x);
            let band = strip
                .focus
                .iter()
                .find(|band| ts >= band.start_ts && ts < band.end_ts);
            let away = strip
                .away
                .iter()
                .find(|(start, end)| ts >= *start && ts < *end);
            let lines: Vec<(String, Color32)> = if let Some(band) = band {
                vec![
                    (band.app.clone(), palette.color(&band.app)),
                    (
                        format!(
                            "{} {RANGE_SEPARATOR} {}  ({})",
                            local_clock(band.start_ts),
                            local_clock(band.end_ts),
                            format_duration_ms(band.end_ts - band.start_ts),
                        ),
                        theme::SILVER,
                    ),
                ]
            } else if let Some((away_start, away_end)) = away {
                vec![
                    ("away".to_string(), theme::GRAY),
                    (
                        format!(
                            "{} {RANGE_SEPARATOR} {}  ({})",
                            local_clock(*away_start),
                            local_clock(*away_end),
                            format_duration_ms(away_end - away_start),
                        ),
                        theme::SILVER,
                    ),
                ]
            } else {
                vec![("no focus recorded".to_string(), theme::GRAY)]
            };
            response
                .clone()
                .on_hover_ui_at_pointer(|ui| hover_panel(ui, &lines));
        }
    }
}

/// Legend chips for the day strip: the top apps with their band time, plus
/// the away marker, so the colors need no guessing.
pub fn day_strip_legend(ui: &mut egui::Ui, palette: &AppPalette) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(14.0, 4.0);
        for (app, dwell) in palette.ranked.iter().take(5) {
            let color = palette.color(app);
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::empty());
            ui.painter().rect_filled(rect.shrink(0.5), 2.0, color);
            ui.label(
                egui::RichText::new(format!("{app}  {}", format_duration_ms(*dwell)))
                    .color(theme::SILVER_DIM)
                    .size(11.5),
            );
        }
        if palette.ranked.len() > 5 {
            ui.label(
                egui::RichText::new(format!("+{} more", palette.ranked.len() - 5))
                    .color(theme::GRAY)
                    .size(11.5),
            );
        }
        let (rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 9.0), Sense::empty());
        ui.painter().line_segment(
            [
                Pos2::new(rect.left(), rect.center().y),
                Pos2::new(rect.right(), rect.center().y),
            ],
            Stroke::new(2.0, theme::GRAY.gamma_multiply(0.8)),
        );
        ui.label(egui::RichText::new("away").color(theme::GRAY).size(11.5));
    });
}

/// UX-51: legend chips naming the pulse's two series, so the colors need
/// no hover to decode.
pub fn pulse_legend(ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(14.0, 4.0);
        for (label, color) in [("keys (labeled)", theme::BLUE), ("mouse", theme::GRAY)] {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::empty());
            ui.painter().rect_filled(rect.shrink(0.5), 2.0, color);
            ui.label(
                egui::RichText::new(label)
                    .color(theme::SILVER_DIM)
                    .size(11.5),
            );
        }
    });
}

/// Hourly input pulse: key and mouse events per hour as paired columns on
/// the same axis as the day strip. The two modalities stay separate by
/// design — keys in process blue, mouse in instrument gray.
pub fn hourly_pulse(ui: &mut egui::Ui, pulse: &[HourPulse], strip: &DayStrip) {
    let axis = TimeAxis::for_day(strip);
    let desired = Vec2::new(ui.available_width(), 92.0);
    let (response, painter) = ui.allocate_painter(desired, Sense::hover());
    let rect = response.rect;
    let plot = Rect::from_min_max(
        Pos2::new(rect.left(), rect.top() + 2.0),
        Pos2::new(rect.right(), rect.top() + 68.0),
    );
    painter.rect_filled(plot, 5.0, theme::WELL);

    let max_events = pulse
        .iter()
        .flat_map(|hour| [hour.key_events, hour.mouse_events])
        .max()
        .unwrap_or(0)
        .max(1) as f32;
    let by_start: HashMap<i64, &HourPulse> = pulse
        .iter()
        .map(|hour| (hour.hour_start_ms, hour))
        .collect();

    let hour_width = axis.x_of(&plot, axis.start_ms + HOUR_MS) - axis.x_of(&plot, axis.start_ms);
    let column_width = ((hour_width - 6.0) / 2.0).clamp(1.5, 13.0);
    let floor_y = plot.bottom() - 4.0;
    // The keys count labels each column (the hover-retirement ruling:
    // charts carry their numbers); the label zone sits above the columns.
    let label_zone = 13.0;
    let max_height = plot.height() - 10.0 - label_zone;
    let label_hours = hour_width >= 30.0;

    let mut ts = axis.start_ms;
    while ts < axis.end_ms {
        if let Some(hour) = by_start.get(&ts) {
            let center = axis.x_of(&plot, ts + HOUR_MS / 2);
            let mut tallest = 0.0_f32;
            for (offset, events, color) in [
                (-column_width - 0.75, hour.key_events, theme::BLUE),
                (0.75, hour.mouse_events, theme::GRAY),
            ] {
                if events <= 0 {
                    continue;
                }
                let height = (events as f32 / max_events * max_height).max(2.0);
                tallest = tallest.max(height);
                let column = Rect::from_min_max(
                    Pos2::new(center + offset, floor_y - height),
                    Pos2::new(center + offset + column_width, floor_y),
                );
                painter.rect_filled(column, 1.5, color.gamma_multiply(0.92));
            }
            // The keys count, quiet mono above the pair; mouse reads
            // against the labeled scale.
            if label_hours && hour.key_events > 0 {
                painter.text(
                    Pos2::new(center, floor_y - tallest - 2.0),
                    Align2::CENTER_BOTTOM,
                    thousands(hour.key_events),
                    FontId::new(10.0, egui::FontFamily::Monospace),
                    Color32::from_rgb(0x5C, 0x64, 0x70),
                );
            }
        }
        ts += HOUR_MS;
    }

    paint_hour_ticks(&painter, &axis, &plot, plot.bottom() + 3.0);

    if let Some(pointer) = response.hover_pos() {
        if plot.contains(pointer) {
            let ts = axis.ts_of(&plot, pointer.x);
            let hour_start = axis.start_ms + ((ts - axis.start_ms) / HOUR_MS) * HOUR_MS;
            if let Some(hour) = by_start.get(&hour_start) {
                let lines = vec![
                    (
                        format!(
                            "{} {RANGE_SEPARATOR} {}",
                            local_clock(hour.hour_start_ms),
                            { local_clock(hour.hour_start_ms + HOUR_MS) }
                        ),
                        theme::SILVER,
                    ),
                    (
                        format!("{} key events", thousands(hour.key_events)),
                        theme::BLUE,
                    ),
                    (
                        format!("{} mouse events", thousands(hour.mouse_events)),
                        theme::GRAY,
                    ),
                ];
                response
                    .clone()
                    .on_hover_ui_at_pointer(|ui| hover_panel(ui, &lines));
            }
        }
    }
}

/// Last-7-days active minutes: one quiet column per day, today carrying the
/// light trail (the "you are here" moment when the strip has no bands yet).
pub fn daily_bars(ui: &mut egui::Ui, daily: &[DayActive], today_key: &str) {
    if daily.is_empty() {
        return;
    }
    // Full width (type-ramp amendment, supersedes the slice-6 46×84px
    // compact-bars ruling): broad columns on the card's 7×1fr grid, each
    // day's minutes labeled so the chart carries its numbers without hover.
    let desired = Vec2::new(ui.available_width(), 124.0);
    let (response, painter) = ui.allocate_painter(desired, Sense::hover());
    let rect = response.rect;
    let plot = Rect::from_min_max(
        Pos2::new(rect.left(), rect.top() + 2.0),
        Pos2::new(rect.right(), rect.bottom() - 18.0),
    );
    painter.rect_filled(plot, 5.0, theme::WELL);

    let max_minutes = daily
        .iter()
        .map(|day| day.active_minutes)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let slot = plot.width() / daily.len() as f32;
    let column_width = (slot - 12.0).max(8.0);
    let label_zone = 14.0;
    let mut hovered: Option<(usize, Rect)> = None;

    for (index, day) in daily.iter().enumerate() {
        let center_x = plot.left() + slot * (index as f32 + 0.5);
        let height = ((day.active_minutes / max_minutes) as f32
            * (plot.height() - 12.0 - label_zone))
            .max(2.0);
        let column = Rect::from_min_max(
            Pos2::new(center_x - column_width / 2.0, plot.bottom() - 5.0 - height),
            Pos2::new(center_x + column_width / 2.0, plot.bottom() - 5.0),
        );
        let is_today = day.local_date == today_key;
        // Today reads as a lighter gray, not amber: the light trail stays
        // the day strip's (one amber moment per view).
        let color = if is_today {
            Color32::from_rgb(0x8A, 0x94, 0xA6)
        } else {
            theme::BLUE.gamma_multiply(0.75)
        };
        painter.rect_filled(column, 2.5, color);
        painter.text(
            Pos2::new(center_x, column.top() - 2.0),
            Align2::CENTER_BOTTOM,
            format!("{:.0}", day.active_minutes),
            FontId::new(10.0, egui::FontFamily::Monospace),
            Color32::from_rgb(0x5C, 0x64, 0x70),
        );
        painter.text(
            Pos2::new(center_x, plot.bottom() + 4.0),
            Align2::CENTER_TOP,
            &day.day_label,
            FontId::new(11.0, egui::FontFamily::Monospace),
            if is_today { theme::SILVER } else { theme::GRAY },
        );
        if response.hover_pos().is_some_and(|pointer| {
            pointer.x >= center_x - slot / 2.0 && pointer.x < center_x + slot / 2.0
        }) {
            hovered = Some((index, column));
        }
    }

    if let Some((index, _)) = hovered {
        let day = &daily[index];
        let lines = vec![
            (day.local_date.clone(), theme::GRAY),
            (
                format!("{:.0} min active", day.active_minutes),
                theme::SILVER,
            ),
        ];
        response.on_hover_ui_at_pointer(|ui| hover_panel(ui, &lines));
    }
}

/// The Streamlit `HEATMAP_RAMP` stops: away/bellows through a dim amber to
/// the light trail, interpolated in RGB (the default hue path detours
/// through purple).
const HEATMAP_STOPS: [(u8, u8, u8); 3] =
    [(0x2A, 0x2E, 0x35), (0x8E, 0x69, 0x38), (0xF2, 0xA3, 0x3C)];

fn heatmap_ramp(t: f32) -> Color32 {
    let lerp = |from: u8, to: u8, local: f32| {
        (f32::from(from) + (f32::from(to) - f32::from(from)) * local).round() as u8
    };
    let t = t.clamp(0.0, 1.0) * 2.0;
    let (from, to, local) = if t <= 1.0 {
        (HEATMAP_STOPS[0], HEATMAP_STOPS[1], t)
    } else {
        (HEATMAP_STOPS[1], HEATMAP_STOPS[2], t - 1.0)
    };
    Color32::from_rgb(
        lerp(from.0, to.0, local),
        lerp(from.1, to.1, local),
        lerp(from.2, to.2, local),
    )
}

const HEATMAP_WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// The Week/Rhythms day×hour heatmap, mirroring `rhythm_heatmap_chart`:
/// fixed 24-hour columns so sparse data keeps its true position, Mon–Sun
/// rows that never drop their labels, the brand ramp from zero to the
/// busiest cell, and a hover naming day, hour, and active time.
pub const HEATMAP_TOO_NARROW: &str = "Not enough room to draw the heatmap.";

/// UX-07: below this width the gutters would invert the grid rect and the
/// axis labels collide; a message replaces negative-width cells.
const HEATMAP_MIN_WIDTH: f32 = 220.0;

pub fn weekday_hour_heatmap(ui: &mut egui::Ui, heatmap: &[HeatmapBucket]) {
    let max_minutes = heatmap
        .iter()
        .map(|bucket| bucket.active_minutes)
        .fold(0.0_f64, f64::max);
    if heatmap.is_empty() || max_minutes <= 0.0 {
        return;
    }
    if ui.available_width() < HEATMAP_MIN_WIDTH {
        ui.label(
            egui::RichText::new(HEATMAP_TOO_NARROW)
                .color(theme::GRAY)
                .size(11.5),
        );
        return;
    }
    let by_cell: HashMap<(i64, i64), &HeatmapBucket> = heatmap
        .iter()
        .map(|bucket| ((bucket.weekday, bucket.hour), bucket))
        .collect();

    // Real size (type-ramp amendment): the grid takes the full measure —
    // the card anatomy carries no side ramp legend, so the 60px gutter
    // retires; exact per-cell minutes stay on hover.
    let desired = Vec2::new(ui.available_width(), 182.0);
    let (response, painter) = ui.allocate_painter(desired, Sense::hover());
    let rect = response.rect;
    let grid = Rect::from_min_max(
        Pos2::new(rect.left() + 34.0, rect.top() + 2.0),
        Pos2::new(rect.right(), rect.bottom() - 28.0),
    );
    let cell_width = grid.width() / 24.0;
    let cell_height = grid.height() / 7.0;

    for row in 0..7_i64 {
        let top = grid.top() + row as f32 * cell_height;
        painter.text(
            Pos2::new(grid.left() - 6.0, top + cell_height / 2.0),
            Align2::RIGHT_CENTER,
            HEATMAP_WEEKDAYS[row as usize],
            FontId::new(11.0, egui::FontFamily::Monospace),
            theme::GRAY,
        );
        for column in 0..24_i64 {
            let cell = Rect::from_min_size(
                Pos2::new(grid.left() + column as f32 * cell_width, top),
                Vec2::new(cell_width, cell_height),
            )
            .shrink2(Vec2::new(1.0, 3.0));
            // UX-52: hours with no recorded span at all stay transparent
            // (the darkroom shows through), clearly distinct from the
            // ramp's zero stop.
            if let Some(bucket) = by_cell.get(&(row, column)) {
                painter.rect_filled(
                    cell,
                    2.0,
                    heatmap_ramp((bucket.active_minutes / max_minutes) as f32),
                );
            }
        }
    }

    for hour in (0..24_i64).step_by(3) {
        painter.text(
            Pos2::new(
                grid.left() + (hour as f32 + 0.5) * cell_width,
                grid.bottom() + 4.0,
            ),
            Align2::CENTER_TOP,
            hour.to_string(),
            FontId::new(11.0, egui::FontFamily::Monospace),
            theme::GRAY,
        );
    }
    painter.text(
        Pos2::new(grid.center().x, grid.bottom() + 17.0),
        Align2::CENTER_TOP,
        "hour of day",
        FontId::new(9.5, egui::FontFamily::Monospace),
        theme::GRAY.gamma_multiply(0.85),
    );

    if let Some(pointer) = response.hover_pos() {
        if grid.contains(pointer) {
            let column = (((pointer.x - grid.left()) / cell_width) as i64).clamp(0, 23);
            let row = (((pointer.y - grid.top()) / cell_height) as i64).clamp(0, 6);
            // UX-52: empty cells answer the hover too instead of being
            // silent dead space.
            let lines = match by_cell.get(&(row, column)) {
                Some(bucket) => vec![
                    (
                        format!("{} {:02}:00", bucket.weekday_label, bucket.hour),
                        theme::SILVER,
                    ),
                    (
                        format!(
                            "{} active",
                            format_duration_ms((bucket.active_minutes * 60_000.0).round() as i64)
                        ),
                        theme::SILVER_DIM,
                    ),
                ],
                None => vec![
                    (
                        format!("{} {column:02}:00", HEATMAP_WEEKDAYS[row as usize]),
                        theme::SILVER,
                    ),
                    ("no recorded span".to_string(), theme::GRAY),
                ],
            };
            response
                .clone()
                .on_hover_ui_at_pointer(|ui| hover_panel(ui, &lines));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gilbreth_read::DayStripBand;

    fn strip(day_start: i64, now: i64, bands: &[(i64, i64)]) -> DayStrip {
        DayStrip {
            day_start_ms: day_start,
            day_end_ms: now,
            focus: bands
                .iter()
                .map(|(start, end)| DayStripBand {
                    app: "studio.exe".to_string(),
                    start_ts: *start,
                    end_ts: *end,
                })
                .collect(),
            away: Vec::new(),
        }
    }

    #[test]
    fn axis_floors_and_ceils_to_hour_boundaries() {
        let day = 1_000_000_000;
        let axis = TimeAxis::for_day(&strip(
            day,
            day + 10 * HOUR_MS + 30 * 60_000,
            &[(day + 2 * HOUR_MS + 15 * 60_000, day + 3 * HOUR_MS)],
        ));
        assert_eq!(axis.start_ms, day + 2 * HOUR_MS);
        assert_eq!(axis.end_ms, day + 11 * HOUR_MS);
    }

    #[test]
    fn axis_enforces_minimum_span_and_day_floor() {
        let day = 5_000_000;
        let axis = TimeAxis::for_day(&strip(day, day + 30 * 60_000, &[]));
        assert_eq!(axis.start_ms, day);
        assert_eq!(axis.end_ms, day + 6 * HOUR_MS);
    }

    #[test]
    fn heatmap_ramp_pins_the_brand_stops() {
        assert_eq!(heatmap_ramp(0.0), Color32::from_rgb(0x2A, 0x2E, 0x35));
        assert_eq!(heatmap_ramp(0.5), Color32::from_rgb(0x8E, 0x69, 0x38));
        assert_eq!(heatmap_ramp(1.0), theme::AMBER);
        // Clamped outside the domain, monotone within it.
        assert_eq!(heatmap_ramp(-1.0), heatmap_ramp(0.0));
        assert_eq!(heatmap_ramp(2.0), heatmap_ramp(1.0));
        assert!(heatmap_ramp(0.25).r() > heatmap_ramp(0.0).r());
        assert!(heatmap_ramp(0.75).r() > heatmap_ramp(0.5).r());
    }

    #[test]
    fn palette_gives_amber_to_the_top_app_only() {
        let day = 0;
        let mut strip = strip(day, day + 8 * HOUR_MS, &[]);
        strip.focus = vec![
            DayStripBand {
                app: "studio.exe".into(),
                start_ts: 0,
                end_ts: 3 * HOUR_MS,
            },
            DayStripBand {
                app: "mail.exe".into(),
                start_ts: 3 * HOUR_MS,
                end_ts: 4 * HOUR_MS,
            },
        ];
        let palette = AppPalette::from_strip(&strip);
        assert_eq!(palette.color("studio.exe"), theme::AMBER);
        assert_ne!(palette.color("mail.exe"), theme::AMBER);
        assert_eq!(palette.ranked[0].0, "studio.exe");
    }
}
