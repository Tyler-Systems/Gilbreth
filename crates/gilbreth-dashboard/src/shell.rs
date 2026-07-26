//! The dashboard shell: brand bar, tab strip, and the DASH-03 states that
//! render before there is anything to draw. All six S4 milestone tabs plus
//! the UX-62 Session port are native — every Streamlit surface now has a
//! native equivalent, and S6 routes the sole dashboard tray action here.

use egui::{Color32, CornerRadius, FontId, Pos2, RichText, Sense, Stroke, Vec2};

use crate::format::local_clock;
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Tab {
    Today,
    Week,
    /// UX-62: the native Session tab, slotted after Week like the Streamlit
    /// strip; home of the Event list and the product's only per-event delete.
    Session,
    Analytics,
    Recordings,
    Privacy,
    Diagnostics,
}

impl Tab {
    #[cfg(windows)]
    pub const ALL: [Tab; 7] = [
        Tab::Today,
        Tab::Week,
        Tab::Session,
        Tab::Analytics,
        Tab::Recordings,
        Tab::Privacy,
        Tab::Diagnostics,
    ];

    /// Record Routine is Windows-only by decision record, so a macOS install
    /// can never write a `record_sessions` row and the Recordings tab could
    /// only ever show its empty state. The variant itself stays so a database
    /// or persisted UI state written on Windows still parses; it is simply
    /// never offered. `is_available` is what keeps a restored tab honest.
    #[cfg(not(windows))]
    pub const ALL: [Tab; 6] = [
        Tab::Today,
        Tab::Week,
        Tab::Session,
        Tab::Analytics,
        Tab::Privacy,
        Tab::Diagnostics,
    ];

    /// Whether this tab is offered on the current platform. Guards restored
    /// UI state: a state file written on Windows can name a tab this build
    /// does not put in the strip.
    pub fn is_available(self) -> bool {
        Self::ALL.contains(&self)
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Today => "Today",
            Tab::Week => "Week",
            Tab::Session => "Session",
            Tab::Analytics => "Analytics",
            Tab::Recordings => "Recordings",
            Tab::Privacy => "Privacy",
            Tab::Diagnostics => "Diagnostics",
        }
    }
}

/// UX-57: shown beside the timestamp while this tab's read is in flight.
pub const UPDATING_LABEL: &str = "updating…";
pub const REFRESH_BUSY_REASON: &str = "A refresh is already running for this tab.";
/// Prefix for dashboard read recency. This timestamp describes when the
/// dashboard last read stored data; it never asserts that capture is live.
pub const DASHBOARD_READ_LABEL: &str = "updated";

/// The brand row: pulse mark, name, and the refresh affordance. Returns
/// true when the user asked for a refresh. `in_flight` disables Refresh
/// and shows the updating cue; `stale` marks an old dashboard-read timestamp
/// (UX-57). `last_updated_ms` is deliberately not a capture-status signal.
pub fn top_bar(
    ui: &mut egui::Ui,
    last_updated_ms: Option<i64>,
    in_flight: bool,
    stale: bool,
) -> bool {
    let mut refresh_clicked = false;
    ui.horizontal(|ui| {
        // The tray icon's pulse mark: darkroom tile, light-trail center dot.
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::empty());
        ui.painter()
            .rect_filled(rect, CornerRadius::same(5), theme::WELL);
        ui.painter().circle_filled(rect.center(), 4.0, theme::AMBER);
        ui.label(
            RichText::new("Gilbreth")
                .color(theme::SILVER)
                .font(FontId::new(15.0, theme::family_semibold())),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add_enabled(
                    !in_flight,
                    egui::Button::new(RichText::new("Refresh").size(11.5)),
                )
                .on_disabled_hover_text(REFRESH_BUSY_REASON)
                .clicked()
            {
                refresh_clicked = true;
            }
            if in_flight {
                ui.label(
                    RichText::new(UPDATING_LABEL)
                        .color(theme::GRAY)
                        .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                );
            }
            if let Some(updated_ms) = last_updated_ms {
                let (text, color) = if stale {
                    (
                        format!("{DASHBOARD_READ_LABEL} {} (stale)", local_clock(updated_ms)),
                        theme::BRASS,
                    )
                } else {
                    (
                        format!("{DASHBOARD_READ_LABEL} {}", local_clock(updated_ms)),
                        theme::GRAY,
                    )
                };
                ui.label(
                    RichText::new(text)
                        .color(color)
                        .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                );
            }
        });
    });
    refresh_clicked
}

/// The tab strip: silver labels, brass underline on the active tab (amber
/// stays reserved for the data itself). Wrapped (UX-21): at widths where the
/// strip no longer fits on one line it folds to a second row instead of
/// overflowing — an unwrapped overflow would silently widen every sibling
/// below it (egui expands the parent to include children). The strip is built
/// from `Tab::ALL`, which is one tab narrower off Windows.
pub fn tab_strip(ui: &mut egui::Ui, active: &mut Tab) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for tab in Tab::ALL {
            let selected = *active == tab;
            let text = RichText::new(tab.label())
                .color(if selected { theme::SILVER } else { theme::GRAY })
                .font(FontId::new(13.0, theme::family_medium()));
            // UX-28: hover fill stays alive so the strip looks clickable.
            let response = crate::tabs::widgets::quiet_tab_button(ui, text);
            if selected {
                let rect = response.rect;
                ui.painter().line_segment(
                    [
                        Pos2::new(rect.left() + 6.0, rect.bottom() + 1.0),
                        Pos2::new(rect.right() - 6.0, rect.bottom() + 1.0),
                    ],
                    Stroke::new(2.0, theme::BRASS),
                );
            }
            if response.clicked() {
                *active = tab;
            }
        }
    });
}

pub fn hairline(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::empty());
    ui.painter().line_segment(
        [
            Pos2::new(rect.left(), rect.center().y),
            Pos2::new(rect.right(), rect.center().y),
        ],
        Stroke::new(1.0, theme::HAIRLINE.gamma_multiply(0.6)),
    );
}

pub const NO_DB_HEADING: &str = "No activity yet";
pub const NO_DB_BODY: &str = "Gilbreth has no captured activity to show because this device's \
     activity database does not exist yet. Capture is managed from the Gilbreth tray; this \
     dashboard only reads what is stored on this machine.";
pub const NO_DB_WHAT_APPEARS: &str = "When captured activity becomes available, this page fills \
     in with your day: \
     a timeline of which app was in front, an hourly input pulse, and evidence-backed things \
     worth noticing.";
pub const NO_DB_PRIVACY: &str = "Gilbreth stores captured activity on this device. Capture and \
     key-content controls remain available from the tray.";

/// DASH-03 no-DB shell: explains what will appear and where capture settings
/// live without simulating metrics or asserting capture state or posture.
pub fn no_database(ui: &mut egui::Ui, db_path: &std::path::Path) {
    ui.add_space(48.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(560.0);
        egui::Frame::default()
            .fill(theme::BELLOWS)
            .corner_radius(CornerRadius::same(10))
            .stroke(Stroke::new(1.0, Color32::from_rgb(0x34, 0x39, 0x42)))
            .inner_margin(24.0)
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.label(
                        RichText::new(NO_DB_HEADING)
                            .color(theme::SILVER)
                            .font(theme::heading_page()),
                    );
                    ui.add_space(8.0);
                    for body in [NO_DB_BODY, NO_DB_WHAT_APPEARS, NO_DB_PRIVACY] {
                        ui.label(RichText::new(body).color(theme::SILVER_DIM).size(13.0));
                        ui.add_space(6.0);
                    }
                    ui.label(
                        RichText::new(format!("Looking for: {}", db_path.display()))
                            .color(theme::GRAY)
                            .font(FontId::new(10.5, egui::FontFamily::Monospace)),
                    );
                });
            });
    });
}

#[cfg(test)]
mod tests {
    use super::Tab;

    /// Record Routine is Windows-only by decision record, so a macOS install
    /// can never write a `record_sessions` row. The tab strip is built from
    /// `Tab::ALL`, so excluding it there is what actually removes the surface.
    #[test]
    fn recordings_tab_is_offered_only_on_windows() {
        assert_eq!(Tab::ALL.contains(&Tab::Recordings), cfg!(windows));
        assert_eq!(Tab::Recordings.is_available(), cfg!(windows));
    }

    /// Every other tab stays on both platforms; this is a Record Routine
    /// removal, not a general trim of the strip.
    #[test]
    fn every_non_recordings_tab_stays_available() {
        for tab in [
            Tab::Today,
            Tab::Week,
            Tab::Session,
            Tab::Analytics,
            Tab::Privacy,
            Tab::Diagnostics,
        ] {
            assert!(tab.is_available(), "{tab:?} must stay in the strip");
        }
    }
}
