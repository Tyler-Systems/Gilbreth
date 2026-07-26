//! Embedded, self-hosted faces: Inter for body/UI, IBM Plex Mono for data.
//! No system-font or network dependence; Jost is a marketing-surface face
//! and never ships in the app. License files sit beside the font binaries
//! in `assets/fonts/` (both SIL OFL).

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily};

const INTER_REGULAR: &[u8] = include_bytes!("../assets/fonts/Inter-Regular.otf");
const INTER_MEDIUM: &[u8] = include_bytes!("../assets/fonts/Inter-Medium.otf");
const INTER_SEMIBOLD: &[u8] = include_bytes!("../assets/fonts/Inter-SemiBold.otf");
const PLEX_MONO: &[u8] = include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf");

pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "inter".to_owned(),
        Arc::new(FontData::from_static(INTER_REGULAR)),
    );
    fonts.font_data.insert(
        "inter-medium".to_owned(),
        Arc::new(FontData::from_static(INTER_MEDIUM)),
    );
    fonts.font_data.insert(
        "inter-semibold".to_owned(),
        Arc::new(FontData::from_static(INTER_SEMIBOLD)),
    );
    fonts.font_data.insert(
        "plex-mono".to_owned(),
        Arc::new(FontData::from_static(PLEX_MONO)),
    );

    // Inter leads both stock families; egui's bundled faces stay as glyph
    // fallback so box-drawing and symbol glyphs keep rendering.
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "inter".to_owned());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "plex-mono".to_owned());

    let proportional_fallback: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut medium = proportional_fallback.clone();
    medium[0] = "inter-medium".to_owned();
    fonts
        .families
        .insert(FontFamily::Name("inter-medium".into()), medium);
    let mut semibold = proportional_fallback;
    semibold[0] = "inter-semibold".to_owned();
    fonts
        .families
        .insert(FontFamily::Name("inter-semibold".into()), semibold);

    ctx.set_fonts(fonts);
}
