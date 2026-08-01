//! Modal confirm/alert dialogs, rendered with the product's own egui shell.
//!
//! Windows has `MessageBox` and macOS has `NSAlert`; a Linux desktop has no
//! equivalent every session is guaranteed to provide, and shelling out to
//! `zenity`/`kdialog` would make a privacy control depend on a binary that
//! may not be installed. So the shell that already owns egui, the theme, and
//! the fonts renders the dialog too, and the app hosts it in a short-lived
//! child process (the `--dashboard` precedent) — which also means a dialog
//! can be raised from any thread, not just the one holding a UI toolkit's
//! main-thread claim. That matters here: the privacy flows confirm from
//! worker threads.
//!
//! The dialog never renders captured data. Its callers pass product copy
//! plus values the app already treats as loggable (paths, counts).

use std::sync::Arc;

use crate::{fonts, theme};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogKind {
    Info,
    Warning,
}

/// Button sets, matching the platform facade's own vocabulary. The positive
/// answer is OK / Yes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogButtons {
    Ok,
    OkCancel,
    YesNo,
    YesNoCancel,
}

/// The three-way answer, the same shape the platform facade returns. A
/// two-button dialog never answers `Dismissed`: its close box and Esc map to
/// the negative choice, matching `MessageBox`'s Cancel/No behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogAnswer {
    Positive,
    Negative,
    Dismissed,
}

#[derive(Clone, Debug)]
pub struct DialogRequest {
    pub title: String,
    pub message: String,
    pub kind: DialogKind,
    pub buttons: DialogButtons,
    /// Return activates the negative choice (the `MB_DEFBUTTON2` twin): the
    /// destructive flows keep the safe answer under the default key.
    pub default_negative: bool,
    /// Window icon, as `(width, height, rgba)`.
    pub window_icon: Option<(u32, u32, Vec<u8>)>,
}

/// Run one modal dialog to completion on this thread. Returns the user's
/// answer; a window that cannot be created at all surfaces as an eframe
/// error, and the caller decides the fail-safe.
pub fn run_dialog(request: DialogRequest) -> eframe::Result<DialogAnswer> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(request.title.clone())
        .with_inner_size([520.0, 250.0])
        .with_min_inner_size([380.0, 180.0])
        // Resizable so an unusually long body can always be read in full;
        // the message scrolls inside the content area regardless.
        .with_resizable(true)
        // A confirm the user must answer before the flow proceeds should not
        // be lost behind the window that raised it.
        .with_always_on_top();
    if let Some((width, height, rgba)) = request.window_icon.clone() {
        viewport = viewport.with_icon(Arc::new(egui::IconData {
            rgba,
            width,
            height,
        }));
    }
    let options = eframe::NativeOptions {
        viewport,
        // A dialog has no state worth restoring, and it must never contend
        // for the viewer's eframe persistence claim.
        persist_window: false,
        persistence_path: None,
        ..Default::default()
    };

    let answer = Arc::new(std::sync::Mutex::new(default_answer(request.buttons)));
    let reported = Arc::clone(&answer);
    eframe::run_native(
        "gilbreth-dialog",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(DialogApp {
                request,
                answer: reported,
                decided: false,
            }))
        }),
    )?;
    let answer = match answer.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    };
    Ok(answer)
}

/// What a closed-without-choosing window means. Two-button dialogs answer
/// negative (the `MessageBox` contract); the three-way defers.
fn default_answer(buttons: DialogButtons) -> DialogAnswer {
    match buttons {
        DialogButtons::YesNoCancel => DialogAnswer::Dismissed,
        DialogButtons::Ok => DialogAnswer::Positive,
        DialogButtons::OkCancel | DialogButtons::YesNo => DialogAnswer::Negative,
    }
}

/// Button labels, positive first, matching each platform twin's wording.
fn button_labels(buttons: DialogButtons) -> Vec<(&'static str, DialogAnswer)> {
    match buttons {
        DialogButtons::Ok => vec![("OK", DialogAnswer::Positive)],
        DialogButtons::OkCancel => vec![
            ("OK", DialogAnswer::Positive),
            ("Cancel", DialogAnswer::Negative),
        ],
        DialogButtons::YesNo => vec![
            ("Yes", DialogAnswer::Positive),
            ("No", DialogAnswer::Negative),
        ],
        DialogButtons::YesNoCancel => vec![
            ("Yes", DialogAnswer::Positive),
            ("No", DialogAnswer::Negative),
            ("Cancel", DialogAnswer::Dismissed),
        ],
    }
}

struct DialogApp {
    request: DialogRequest,
    answer: Arc<std::sync::Mutex<DialogAnswer>>,
    /// Latches on the first answer. `finish` asks the viewport to close, but
    /// the close is processed on a later frame, and this method runs again
    /// meanwhile with `close_requested()` already true — so without the
    /// latch the close-box branch would overwrite a real choice with the
    /// default. Caught live: clicking Yes reported No.
    decided: bool,
}

impl DialogApp {
    fn finish(&mut self, ctx: &egui::Context, answer: DialogAnswer) {
        if self.decided {
            return;
        }
        self.decided = true;
        match self.answer.lock() {
            Ok(mut guard) => *guard = answer,
            Err(poisoned) => *poisoned.into_inner() = answer,
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

impl eframe::App for DialogApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Frames still paint while the viewport works through the close it
        // was asked for; the answer is already recorded, so do nothing.
        if self.decided {
            return;
        }
        let labels = button_labels(self.request.buttons);
        // Esc is the close box: the same answer a dismissed window gives.
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.finish(&ctx, default_answer(self.request.buttons));
            return;
        }
        // Return takes the default choice — the negative one on the
        // destructive flows, so a held key cannot confirm a wipe.
        if ctx.input(|input| input.key_pressed(egui::Key::Enter)) {
            let default = if self.request.default_negative {
                labels
                    .iter()
                    .find(|(_, answer)| *answer == DialogAnswer::Negative)
                    .map(|(_, answer)| *answer)
                    .unwrap_or(DialogAnswer::Positive)
            } else {
                DialogAnswer::Positive
            };
            self.finish(&ctx, default);
            return;
        }

        // The button row is reserved out of the available height first, so a
        // long message scrolls inside what is left instead of pushing the
        // buttons off the bottom edge of a fixed-size window.
        const MARGIN: f32 = 14.0;
        const BUTTON_ROW: f32 = 34.0;
        let mut chosen = None;
        let available = ui.available_size();
        let content_height = (available.y - BUTTON_ROW - MARGIN).max(0.0);

        egui::Frame::NONE
            .inner_margin(egui::Margin::symmetric(MARGIN as i8, MARGIN as i8))
            .show(ui, |ui| {
                ui.allocate_ui(
                    egui::vec2(ui.available_width(), content_height - MARGIN * 2.0),
                    |ui| {
                        ui.horizontal(|ui| {
                            let (glyph, color) = match self.request.kind {
                                DialogKind::Info => ("\u{2022}", theme::series_color(0)),
                                DialogKind::Warning => ("!", egui::Color32::from_rgb(225, 62, 62)),
                            };
                            ui.label(egui::RichText::new(glyph).color(color).size(20.0));
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(&self.request.title)
                                    .font(theme::heading_card()),
                            );
                        });
                        ui.add_space(10.0);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.label(&self.request.message);
                            });
                    },
                );
            });

        // Buttons bottom-right, positive rightmost — the platform
        // convention on this desktop.
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width() - MARGIN, BUTTON_ROW),
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                for (label, answer) in labels.iter() {
                    if ui.button(*label).clicked() {
                        chosen = Some(*answer);
                    }
                    ui.add_space(6.0);
                }
            },
        );
        if let Some(answer) = chosen {
            self.finish(&ctx, answer);
            return;
        }

        // The window manager's close box.
        if ctx.input(|input| input.viewport().close_requested()) {
            self.finish(&ctx, default_answer(self.request.buttons));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_window_answers_the_safe_choice_for_every_button_set() {
        // The fail-safe contract the platform facade documents: a dialog the
        // user closed without choosing must never read as consent.
        assert_eq!(
            default_answer(DialogButtons::OkCancel),
            DialogAnswer::Negative
        );
        assert_eq!(default_answer(DialogButtons::YesNo), DialogAnswer::Negative);
        assert_eq!(
            default_answer(DialogButtons::YesNoCancel),
            DialogAnswer::Dismissed,
            "the three-way defers rather than refusing"
        );
        // A one-button acknowledgement has no negative answer to fall to.
        assert_eq!(default_answer(DialogButtons::Ok), DialogAnswer::Positive);
    }

    #[test]
    fn button_sets_carry_the_platform_wording_positive_first() {
        assert_eq!(
            button_labels(DialogButtons::YesNoCancel)
                .iter()
                .map(|(label, _)| *label)
                .collect::<Vec<_>>(),
            vec!["Yes", "No", "Cancel"]
        );
        assert_eq!(
            button_labels(DialogButtons::OkCancel)
                .iter()
                .map(|(label, _)| *label)
                .collect::<Vec<_>>(),
            vec!["OK", "Cancel"]
        );
        for buttons in [
            DialogButtons::Ok,
            DialogButtons::OkCancel,
            DialogButtons::YesNo,
            DialogButtons::YesNoCancel,
        ] {
            let labels = button_labels(buttons);
            assert_eq!(
                labels.first().map(|(_, answer)| *answer),
                Some(DialogAnswer::Positive),
                "the positive answer is always listed first"
            );
        }
    }
}
