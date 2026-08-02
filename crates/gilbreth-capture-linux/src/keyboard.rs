//! Keyboard stream derivation (LIN-1). Fed `RawKeyEvent`s translated from
//! XInput2 raw key events; produces `EventPayload::Key` rows with Windows
//! parity:
//!
//! - **key-down edges only**; auto-repeat is filtered twice over — the
//!   server marks repeats with `XIKeyRepeat` when it can, and a press whose
//!   same-keycode release carried the identical server timestamp is the
//!   release/press pair a non-detectable-autorepeat server synthesizes, so
//!   both spellings of a repeat drop to one row per physical press.
//! - **names come from the current keymap's keysyms** mapped into the SAME
//!   vocabulary as the Windows `key_to_string` table (and the macOS table),
//!   so a database reads identically across platforms and core's
//!   `key_class_for_name` matches for free. A physical numpad key prefers
//!   its `KP_*` digit spelling at any shift level, so `Numpad7` stays
//!   `Numpad7` whatever NumLock says — the positional-name rule.
//! - **modifiers are the four collapsed bools** derived from the tracked
//!   pressed set (the Windows `pressed_keys` approach — XI2 raw events
//!   carry no modifier state): Super → `win` (the schema's `mod_win`
//!   mapping on this platform), Alt/Meta/AltGr → `alt`. Tracking runs
//!   before the send gate, so modifier state stays correct while the
//!   stream is toggled off (Windows parity).
//!
//! There is no password-field probe on X11 (recorded in the capability
//! matrix): no accessibility bus is consulted, and the keyboard stream's
//! privacy posture rests on the lean-capture default (`store_key_content =
//! false`), which omits every key name at the writer.

use std::collections::HashSet;

use gilbreth_core::{Captured, EventPayload, Modifiers, Source, WindowRef};
use xkeysym::Keysym;

/// What the io seam saw for one XI2 raw key event, reduced to the fields
/// the derivation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawKeyEvent {
    pub(crate) keycode: u8,
    pub(crate) press: bool,
    /// The server's `XIKeyRepeat` flag, when it marks repeats.
    pub(crate) flagged_repeat: bool,
    /// Server event time (ms), for the release/press repeat heuristic.
    pub(crate) time: u32,
}

/// Which collapsed modifier a key contributes to, resolved per-keycode
/// from the keymap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModifierKind {
    Shift,
    Ctrl,
    Alt,
    Win,
}

/// The current keycode-to-keysym table, rebuilt on `MappingNotify` so a
/// layout switch renames keys live. Pure and provider-fed: built from the
/// raw `GetKeyboardMapping` shape so tests construct it directly.
#[derive(Clone, Debug)]
pub(crate) struct Keymap {
    min_keycode: u8,
    keysyms_per_keycode: usize,
    keysyms: Vec<u32>,
}

impl Keymap {
    pub(crate) fn new(min_keycode: u8, keysyms_per_keycode: u8, keysyms: Vec<u32>) -> Self {
        Self {
            min_keycode,
            keysyms_per_keycode: usize::from(keysyms_per_keycode).max(1),
            keysyms,
        }
    }

    fn keysyms_for(&self, keycode: u8) -> &[u32] {
        if keycode < self.min_keycode {
            return &[];
        }
        let start = usize::from(keycode - self.min_keycode) * self.keysyms_per_keycode;
        let end = (start + self.keysyms_per_keycode).min(self.keysyms.len());
        self.keysyms.get(start..end).unwrap_or(&[])
    }

    /// The shared key vocabulary for one keycode. Numpad spellings win at
    /// any shift level (positional identity); otherwise the first bound
    /// keysym names the key; an unbound keycode gets an honest `Xkc` label.
    pub(crate) fn name_for_keycode(&self, keycode: u8) -> String {
        let keysyms = self.keysyms_for(keycode);
        if let Some(numpad) = keysyms.iter().find_map(|&keysym| numpad_name(keysym)) {
            return numpad.to_string();
        }
        match keysyms.iter().find(|&&keysym| keysym != 0) {
            Some(&keysym) => key_name_for_keysym(keysym),
            // No keysym bound: an honest platform label (the Mac0x..
            // precedent), classifying as Other.
            None => format!("Xkc{keycode}"),
        }
    }

    fn modifier_for_keycode(&self, keycode: u8) -> Option<ModifierKind> {
        self.keysyms_for(keycode)
            .iter()
            .find_map(|&keysym| modifier_kind(keysym))
    }
}

fn numpad_name(keysym: u32) -> Option<&'static str> {
    let keysym = Keysym::from(keysym);
    Some(match keysym {
        Keysym::KP_0 => "Numpad0",
        Keysym::KP_1 => "Numpad1",
        Keysym::KP_2 => "Numpad2",
        Keysym::KP_3 => "Numpad3",
        Keysym::KP_4 => "Numpad4",
        Keysym::KP_5 => "Numpad5",
        Keysym::KP_6 => "Numpad6",
        Keysym::KP_7 => "Numpad7",
        Keysym::KP_8 => "Numpad8",
        Keysym::KP_9 => "Numpad9",
        Keysym::KP_Decimal => "NumpadDecimal",
        Keysym::KP_Separator => "NumpadSeparator",
        _ => return None,
    })
}

fn modifier_kind(keysym: u32) -> Option<ModifierKind> {
    let keysym = Keysym::from(keysym);
    Some(match keysym {
        Keysym::Shift_L | Keysym::Shift_R => ModifierKind::Shift,
        Keysym::Control_L | Keysym::Control_R => ModifierKind::Ctrl,
        // AltGr (ISO_Level3_Shift) and Meta are the right-alt spellings;
        // Windows raw input reports that physical key as Alt too.
        Keysym::Alt_L
        | Keysym::Alt_R
        | Keysym::Meta_L
        | Keysym::Meta_R
        | Keysym::ISO_Level3_Shift => ModifierKind::Alt,
        Keysym::Super_L | Keysym::Super_R => ModifierKind::Win,
        _ => return None,
    })
}

/// Keysym to the cross-platform key vocabulary — the Windows
/// `key_to_string` names byte-for-byte for every shared key, the same
/// contract the macOS table keeps.
fn key_name_for_keysym(keysym: u32) -> String {
    let sym = Keysym::from(keysym);
    // Letters: the level-0 keysym is the lowercase form; store uppercase
    // like the Windows VK letters.
    if let Some(character) = char::from_u32(keysym) {
        if (0x20..0x7f).contains(&keysym) {
            if character.is_ascii_alphabetic() {
                return character.to_ascii_uppercase().to_string();
            }
            if character.is_ascii_digit()
                || matches!(
                    character,
                    ';' | '=' | ',' | '-' | '.' | '/' | '`' | '[' | '\\' | ']' | '\''
                )
            {
                return character.to_string();
            }
        }
    }
    if let Some(number) = function_key_number(sym) {
        return format!("F{number}");
    }
    let named = match sym {
        Keysym::BackSpace => "Backspace",
        Keysym::Tab | Keysym::ISO_Left_Tab => "Tab",
        Keysym::Return | Keysym::KP_Enter => "Enter",
        Keysym::Pause => "Pause",
        Keysym::Caps_Lock => "CapsLock",
        Keysym::Escape => "Escape",
        Keysym::space => "Space",
        Keysym::Prior | Keysym::KP_Prior => "PageUp",
        Keysym::Next | Keysym::KP_Next => "PageDown",
        Keysym::End | Keysym::KP_End => "End",
        Keysym::Home | Keysym::KP_Home => "Home",
        Keysym::Left | Keysym::KP_Left => "ArrowLeft",
        Keysym::Up | Keysym::KP_Up => "ArrowUp",
        Keysym::Right | Keysym::KP_Right => "ArrowRight",
        Keysym::Down | Keysym::KP_Down => "ArrowDown",
        Keysym::Insert | Keysym::KP_Insert => "Insert",
        Keysym::Delete | Keysym::KP_Delete => "Delete",
        Keysym::Super_L | Keysym::Super_R => "Win",
        Keysym::Menu => "Apps",
        Keysym::KP_Multiply => "NumpadMultiply",
        Keysym::KP_Add => "NumpadAdd",
        Keysym::KP_Subtract => "NumpadSubtract",
        Keysym::KP_Divide => "NumpadDivide",
        Keysym::Num_Lock => "NumLock",
        Keysym::Scroll_Lock => "ScrollLock",
        Keysym::Shift_L | Keysym::Shift_R => "Shift",
        Keysym::Control_L | Keysym::Control_R => "Ctrl",
        Keysym::Alt_L | Keysym::Alt_R | Keysym::Meta_L | Keysym::Meta_R => "Alt",
        Keysym::ISO_Level3_Shift => "Alt",
        _ => "",
    };
    if !named.is_empty() {
        return named.to_string();
    }
    // Unmapped: an honest, platform-labeled keysym (NOT the Windows
    // "VK_0x.." form — these are X keysyms). Classifies as Other.
    format!("X0x{keysym:04x}")
}

fn function_key_number(sym: Keysym) -> Option<u8> {
    let value = u32::from(sym);
    let f1 = u32::from(Keysym::F1);
    let f24 = u32::from(Keysym::F24);
    if (f1..=f24).contains(&value) {
        return Some((value - f1 + 1) as u8);
    }
    None
}

/// The keyboard segment state: the physically-down keycode set (the
/// Windows `pressed_keys` mirror) from which the four modifier bools are
/// derived, plus the release/press repeat heuristic's memory.
pub(crate) struct KeyboardState {
    pressed: HashSet<u8>,
    last_release: Option<(u8, u32)>,
}

impl KeyboardState {
    pub(crate) fn new() -> Self {
        Self {
            pressed: HashSet::new(),
            last_release: None,
        }
    }

    /// A session/power boundary resets pressed-key tracking so no chord or
    /// repeat heuristic spans the boundary (the Windows/macOS rule; a
    /// release swallowed by the boundary must not suppress future presses).
    pub(crate) fn reset_after_boundary(&mut self) {
        self.pressed.clear();
        self.last_release = None;
    }

    fn modifiers(&self, keymap: &Keymap) -> Modifiers {
        let mut mods = Modifiers::default();
        for &keycode in &self.pressed {
            match keymap.modifier_for_keycode(keycode) {
                Some(ModifierKind::Shift) => mods.shift = true,
                Some(ModifierKind::Ctrl) => mods.ctrl = true,
                Some(ModifierKind::Alt) => mods.alt = true,
                Some(ModifierKind::Win) => mods.win = true,
                None => {}
            }
        }
        mods
    }

    /// Feed one raw keyboard event; returns a `Key` row on a fresh key-down
    /// edge (including a modifier key's own press), `None` otherwise.
    /// Tracking happens unconditionally and first, so modifier state is
    /// correct even when the caller drops the returned row (stream
    /// disabled).
    pub(crate) fn on_event(
        &mut self,
        event: RawKeyEvent,
        keymap: &Keymap,
        window: Option<WindowRef>,
        captured_at: std::time::Instant,
    ) -> Option<Captured> {
        if !event.press {
            self.pressed.remove(&event.keycode);
            self.last_release = Some((event.keycode, event.time));
            return None;
        }

        // A server without detectable autorepeat spells a repeat as a
        // release+press pair with the same timestamp; with the XIKeyRepeat
        // flag both spellings are covered.
        let paired_repeat = self.last_release == Some((event.keycode, event.time));
        self.pressed.insert(event.keycode);
        if event.flagged_repeat || paired_repeat {
            return None;
        }

        Some(Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: keymap.name_for_keycode(event.keycode),
                mods: self.modifiers(keymap),
                window,
                // Filled downstream in core from the name, exactly as the
                // other platforms leave it.
                key_class: None,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use gilbreth_core::key_class_for_name;

    use super::*;

    /// A tiny two-level keymap over keycodes 8..: 8 = 'p', 9 = Shift_L,
    /// 10 = Return, 11 = KP_Home/KP_7 (numpad 7), 12 = Super_L, 13 = F5,
    /// 14 = unbound.
    fn keymap() -> Keymap {
        let p = 0x70;
        let shift_l = u32::from(Keysym::Shift_L);
        let ret = u32::from(Keysym::Return);
        let kp_home = u32::from(Keysym::KP_Home);
        let kp_7 = u32::from(Keysym::KP_7);
        let super_l = u32::from(Keysym::Super_L);
        let f5 = u32::from(Keysym::F5);
        Keymap::new(
            8,
            2,
            vec![
                p, 0x50, // 8: p/P
                shift_l, 0, // 9
                ret, 0, // 10
                kp_home, kp_7, // 11: numpad 7
                super_l, 0, // 12
                f5, 0, // 13
                0, 0, // 14: unbound
            ],
        )
    }

    fn press(keycode: u8, time: u32) -> RawKeyEvent {
        RawKeyEvent {
            keycode,
            press: true,
            flagged_repeat: false,
            time,
        }
    }

    fn release(keycode: u8, time: u32) -> RawKeyEvent {
        RawKeyEvent {
            keycode,
            press: false,
            flagged_repeat: false,
            time,
        }
    }

    fn expect_key(captured: &Captured) -> (&str, &Modifiers) {
        match &captured.payload {
            EventPayload::Key { key, mods, .. } => (key.as_str(), mods),
            other => panic!("expected Key, got {other:?}"),
        }
    }

    #[test]
    fn key_names_match_the_cross_platform_vocabulary() {
        let keymap = keymap();
        assert_eq!(keymap.name_for_keycode(8), "P");
        assert_eq!(keymap.name_for_keycode(9), "Shift");
        assert_eq!(keymap.name_for_keycode(10), "Enter");
        assert_eq!(
            keymap.name_for_keycode(11),
            "Numpad7",
            "the KP digit wins at any level: positional identity"
        );
        assert_eq!(keymap.name_for_keycode(12), "Win");
        assert_eq!(keymap.name_for_keycode(13), "F5");
        assert_eq!(keymap.name_for_keycode(14), "Xkc14", "unbound stays honest");
    }

    #[test]
    fn keysym_names_cover_the_families_and_classify_in_core() {
        for (keysym, name) in [
            (0x61u32, "A"),
            (0x7a, "Z"),
            (0x30, "0"),
            (0x3b, ";"),
            (u32::from(Keysym::BackSpace), "Backspace"),
            (u32::from(Keysym::Escape), "Escape"),
            (u32::from(Keysym::Left), "ArrowLeft"),
            (u32::from(Keysym::Prior), "PageUp"),
            (u32::from(Keysym::F24), "F24"),
            (u32::from(Keysym::Menu), "Apps"),
            (u32::from(Keysym::Num_Lock), "NumLock"),
            (u32::from(Keysym::ISO_Level3_Shift), "Alt"),
        ] {
            assert_eq!(key_name_for_keysym(keysym), name, "keysym {keysym:#x}");
        }
        // The shared modifier names classify as Modifier in core.
        for name in ["Shift", "Ctrl", "Alt", "Win"] {
            assert_eq!(
                key_class_for_name(name),
                gilbreth_core::KeyClass::Modifier,
                "{name} must be a Modifier"
            );
        }
        // The honest fallback labels classify as Other.
        assert_eq!(
            key_class_for_name(&key_name_for_keysym(0x1008ff13)),
            gilbreth_core::KeyClass::Other,
            "multimedia keys fall back honestly"
        );
    }

    #[test]
    fn only_fresh_key_down_edges_emit_rows() {
        let keymap = keymap();
        let mut state = KeyboardState::new();
        let base = Instant::now();

        assert!(
            state.on_event(press(8, 100), &keymap, None, base).is_some(),
            "down emits"
        );
        assert!(
            state
                .on_event(release(8, 150), &keymap, None, base)
                .is_none(),
            "up emits nothing"
        );
    }

    #[test]
    fn flagged_repeats_are_filtered() {
        let keymap = keymap();
        let mut state = KeyboardState::new();
        let base = Instant::now();

        assert!(state.on_event(press(8, 100), &keymap, None, base).is_some());
        let repeat = RawKeyEvent {
            keycode: 8,
            press: true,
            flagged_repeat: true,
            time: 600,
        };
        assert!(
            state.on_event(repeat, &keymap, None, base).is_none(),
            "server-flagged repeat is dropped"
        );
    }

    #[test]
    fn same_time_release_press_pairs_are_repeats() {
        let keymap = keymap();
        let mut state = KeyboardState::new();
        let base = Instant::now();

        assert!(state.on_event(press(8, 100), &keymap, None, base).is_some());
        // Non-detectable autorepeat: release+press at the identical server
        // time is the synthesized pair, not a fresh press.
        assert!(state
            .on_event(release(8, 600), &keymap, None, base)
            .is_none());
        assert!(
            state.on_event(press(8, 600), &keymap, None, base).is_none(),
            "the synthesized pair is one held key, not a new press"
        );
        // A real re-press arrives at a later time and emits.
        assert!(state
            .on_event(release(8, 700), &keymap, None, base)
            .is_none());
        assert!(state.on_event(press(8, 900), &keymap, None, base).is_some());
    }

    #[test]
    fn modifiers_derive_from_the_pressed_set() {
        let keymap = keymap();
        let mut state = KeyboardState::new();
        let base = Instant::now();

        // Shift's own press emits a named row carrying shift already set.
        let shift_row = state
            .on_event(press(9, 100), &keymap, None, base)
            .expect("modifier press row");
        let (name, mods) = expect_key(&shift_row);
        assert_eq!(name, "Shift");
        assert!(mods.shift && !mods.ctrl && !mods.alt && !mods.win);

        // 'p' while Shift and Super are held: both bools set.
        state.on_event(press(12, 150), &keymap, None, base);
        let row = state
            .on_event(press(8, 200), &keymap, None, base)
            .expect("row");
        let (name, mods) = expect_key(&row);
        assert_eq!(name, "P");
        assert!(mods.shift && mods.win && !mods.ctrl && !mods.alt);

        // After releases the next key carries defaults.
        state.on_event(release(9, 300), &keymap, None, base);
        state.on_event(release(12, 310), &keymap, None, base);
        let row = state
            .on_event(press(10, 400), &keymap, None, base)
            .expect("row");
        assert_eq!(*expect_key(&row).1, Modifiers::default());
    }
}
