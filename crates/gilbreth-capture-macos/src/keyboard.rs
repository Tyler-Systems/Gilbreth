//! Keyboard stream derivation (the macOS TCC and stream rules,
//! Keyboard+Mouse amendment). Fed `RawKeyEvent`s the event-tap callback
//! extracted from CGEvents; produces `EventPayload::Key` rows with Windows
//! parity:
//!
//! - **key-down edges only** (there is no KeyUp/KeyPress variant); auto-repeat
//!   is filtered — macOS marks synthetic repeats in the event itself
//!   (`kCGKeyboardEventAutorepeat`), cleaner than Windows' pressed-keys set
//!   but the same "one row per physical press" result. A modifier key's own
//!   press (delivered as `flagsChanged`) also emits a row, tracked by a
//!   toggle set so left/right variants and re-presses are correct.
//! - **names are positional and layout-independent** — a static
//!   `CGKeyCode → name` table over the hardware-independent `kVK_*` codes,
//!   producing the SAME vocabulary as the Windows `key_to_string` table so a
//!   database reads identically on both platforms and core's
//!   `key_class_for_name` (which classifies the name) matches for free. No
//!   `UCKeyTranslate`/layout API is used — that would make the stored name
//!   layout-dependent. The three macOS modifier keys map to the additive
//!   names `Cmd`/`Option`/`Fn` (the additive core `key_class_for_name` arm).
//! - **modifiers are the four collapsed bools** read from the event's
//!   `CGEventFlags` on every event: Command → `win` (schema `mod_win ←
//!   Command`), Option → `alt`, Control → `ctrl`, Shift → `shift`. Tracking
//!   runs before the send gate, so modifier state stays correct while the
//!   stream is toggled off (Windows parity).

use std::collections::HashSet;

use gilbreth_core::{Captured, EventPayload, Modifiers, Source, WindowRef};

// CGEventFlags bit values (objc2-core-graphics `CGEventFlags`), inlined as
// plain masks so the derivation stays free of CG types and unit-testable.
const MASK_SHIFT: u64 = 131_072;
const MASK_CONTROL: u64 = 262_144;
const MASK_ALTERNATE: u64 = 524_288; // Option
const MASK_COMMAND: u64 = 1_048_576;

/// What the tap saw for one keyboard CGEvent, reduced to the fields the
/// derivation needs (keeps CG types out of the testable state machine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawKeyEvent {
    pub(crate) keycode: u16,
    pub(crate) kind: RawKeyKind,
    /// The event's `CGEventFlags`, verbatim — the authoritative modifier
    /// state at event time.
    pub(crate) flags: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawKeyKind {
    /// A `keyDown`; `autorepeat` is the `kCGKeyboardEventAutorepeat` field.
    KeyDown {
        autorepeat: bool,
    },
    KeyUp,
    /// A modifier transition (`flagsChanged`); press vs release is derived
    /// from the toggle set, not the mask (left/right share a mask bit).
    FlagsChanged,
}

fn modifiers_from_flags(flags: u64) -> Modifiers {
    Modifiers {
        shift: flags & MASK_SHIFT != 0,
        ctrl: flags & MASK_CONTROL != 0,
        alt: flags & MASK_ALTERNATE != 0,
        win: flags & MASK_COMMAND != 0,
    }
}

/// The keyboard segment state: current modifier bools plus the set of
/// physically-down keycodes (mirrors the Windows `pressed_keys` set — used
/// for modifier press/release edges from `flagsChanged`, and as a
/// belt-and-suspenders repeat guard alongside the autorepeat flag).
pub(crate) struct KeyboardState {
    mods: Modifiers,
    pressed: HashSet<u16>,
}

impl KeyboardState {
    pub(crate) fn new() -> Self {
        Self {
            mods: Modifiers::default(),
            pressed: HashSet::new(),
        }
    }

    /// Feed one raw keyboard event; returns a `Key` row on a fresh key-down
    /// edge (including a modifier key's own press), `None` otherwise.
    /// Modifier tracking happens unconditionally and first, so it is correct
    /// even when the caller drops the returned row (stream disabled).
    ///
    /// `redact_key` is the password-field capture redaction (Windows'
    /// `on_raw_key_with_capture_redaction` shape): the row still exists —
    /// typing cadence stays honest — but the key name, modifiers, and
    /// window title are replaced, so no password content or context leaks.
    pub(crate) fn on_event(
        &mut self,
        event: RawKeyEvent,
        mut window: Option<WindowRef>,
        captured_at: std::time::Instant,
        redact_key: bool,
    ) -> Option<Captured> {
        // Authoritative modifier state from the event flags, every event.
        self.mods = modifiers_from_flags(event.flags);

        let is_fresh_down = match event.kind {
            RawKeyKind::KeyUp => {
                self.pressed.remove(&event.keycode);
                false
            }
            RawKeyKind::KeyDown { autorepeat } => {
                // OS-marked repeats are dropped; the set also guards against
                // a missed key-up leaving a stuck key (a second real down
                // with the key still "pressed" would else be swallowed — so
                // only the autorepeat flag suppresses, the set just tracks).
                self.pressed.insert(event.keycode);
                !autorepeat
            }
            RawKeyKind::FlagsChanged => {
                // Toggle: presence flips per keycode, so left/right variants
                // and re-presses each register once; only the press edge
                // (0 → down) emits a row (key-down-only, Windows parity).
                if self.pressed.remove(&event.keycode) {
                    false
                } else {
                    self.pressed.insert(event.keycode);
                    true
                }
            }
        };

        if !is_fresh_down {
            return None;
        }

        if redact_key {
            if let Some(window) = window.as_mut() {
                window.title = "<redacted>".to_string();
            }
        }

        Some(Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: if redact_key {
                    "<redacted>".to_string()
                } else {
                    key_name(event.keycode)
                },
                mods: if redact_key {
                    Modifiers::default()
                } else {
                    self.mods.clone()
                },
                window,
                // Filled downstream in core from the name, exactly as the
                // Windows capture leaves it.
                key_class: None,
            },
        ))
    }

    /// Clear tracked key state at a session/power boundary (Windows'
    /// `reset_after_boundary`), so a key held across a lock does not leave a
    /// phantom "pressed" entry or stale modifier.
    pub(crate) fn reset_after_boundary(&mut self) {
        self.pressed.clear();
        self.mods = Modifiers::default();
    }
}

/// Positional `CGKeyCode → name`, matching the Windows `key_to_string`
/// vocabulary byte-for-byte for every shared key. Codes are the
/// hardware-independent `kVK_*` virtual key codes (Carbon `Events.h`), stable
/// since 10.0; the mapping is by physical position on an ANSI layout, so the
/// stored name never depends on the active keyboard layout — the same
/// cross-platform contract Windows' VK table provides.
/// The shared key vocabulary for one macOS keycode.
///
/// Exposed so the pause-hotkey facade in `gilbreth-app` can prove its
/// `HotkeyKey` to keycode mapping agrees with the capture vocabulary. Two
/// independently hand-written keycode tables would drift silently; the test
/// that consumes this is the guard.
pub fn key_name_for_keycode(keycode: u16) -> String {
    key_name(keycode)
}

fn key_name(keycode: u16) -> String {
    // Letters (kVK_ANSI_* are scattered, so an explicit arm each).
    let named = match keycode {
        0x00 => "A",
        0x0B => "B",
        0x08 => "C",
        0x02 => "D",
        0x0E => "E",
        0x03 => "F",
        0x05 => "G",
        0x04 => "H",
        0x22 => "I",
        0x26 => "J",
        0x28 => "K",
        0x25 => "L",
        0x2E => "M",
        0x2D => "N",
        0x1F => "O",
        0x23 => "P",
        0x0C => "Q",
        0x0F => "R",
        0x01 => "S",
        0x11 => "T",
        0x20 => "U",
        0x09 => "V",
        0x0D => "W",
        0x07 => "X",
        0x10 => "Y",
        0x06 => "Z",
        // Digit row.
        0x1D => "0",
        0x12 => "1",
        0x13 => "2",
        0x14 => "3",
        0x15 => "4",
        0x17 => "5",
        0x16 => "6",
        0x1A => "7",
        0x1C => "8",
        0x19 => "9",
        // Whitespace / editing / control (Windows names).
        0x31 => "Space",
        0x24 => "Enter",
        0x4C => "Enter", // keypad enter → Enter, as Windows numpad-Enter
        0x30 => "Tab",
        0x33 => "Backspace",
        0x75 => "Delete", // forward delete
        0x35 => "Escape",
        0x39 => "CapsLock",
        // The Menu/Application key (external PC keyboards); Windows' VK_APPS
        // twin, shared name "Apps" (keycode-audit parity addition).
        0x6E => "Apps",
        // Navigation cluster.
        0x73 => "Home",
        0x77 => "End",
        0x74 => "PageUp",
        0x79 => "PageDown",
        0x7B => "ArrowLeft",
        0x7C => "ArrowRight",
        0x7D => "ArrowDown",
        0x7E => "ArrowUp",
        // Modifiers → additive macOS names (Cmd/Option/Fn) + shared Shift/Ctrl.
        0x38 | 0x3C => "Shift",
        0x3B | 0x3E => "Ctrl",
        0x3A | 0x3D => "Option",
        0x37 | 0x36 => "Cmd",
        0x3F => "Fn",
        // US-layout OEM punctuation, matching the Windows OEM arm.
        0x29 => ";",
        0x18 => "=",
        0x2B => ",",
        0x1B => "-",
        0x2F => ".",
        0x2C => "/",
        0x32 => "`",
        0x21 => "[",
        0x2A => "\\",
        0x1E => "]",
        0x27 => "'",
        // Numpad (Windows "Numpad*" vocabulary).
        0x52 => "Numpad0",
        0x53 => "Numpad1",
        0x54 => "Numpad2",
        0x55 => "Numpad3",
        0x56 => "Numpad4",
        0x57 => "Numpad5",
        0x58 => "Numpad6",
        0x59 => "Numpad7",
        0x5B => "Numpad8",
        0x5C => "Numpad9",
        0x43 => "NumpadMultiply",
        0x45 => "NumpadAdd",
        0x4E => "NumpadSubtract",
        0x41 => "NumpadDecimal",
        0x4B => "NumpadDivide",
        _ => "",
    };
    if !named.is_empty() {
        return named.to_string();
    }
    // Function keys are numerically scattered on macOS; map by value.
    if let Some(n) = function_key_number(keycode) {
        return format!("F{n}");
    }
    // Unmapped: a mac-specific, honest label (NOT the Windows "VK_0x.."
    // form — these are macOS keycodes, and reusing that prefix would
    // misattribute them to Windows virtual keys). Classifies as `Other`.
    format!("Mac0x{keycode:02x}")
}

fn function_key_number(keycode: u16) -> Option<u8> {
    Some(match keycode {
        0x7A => 1,
        0x78 => 2,
        0x63 => 3,
        0x76 => 4,
        0x60 => 5,
        0x61 => 6,
        0x62 => 7,
        0x64 => 8,
        0x65 => 9,
        0x6D => 10,
        0x67 => 11,
        0x6F => 12,
        0x69 => 13,
        0x6B => 14,
        0x71 => 15,
        0x6A => 16,
        0x40 => 17,
        0x4F => 18,
        0x50 => 19,
        0x5A => 20,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use gilbreth_core::key_class_for_name;

    use super::*;

    fn down(keycode: u16, flags: u64) -> RawKeyEvent {
        RawKeyEvent {
            keycode,
            kind: RawKeyKind::KeyDown { autorepeat: false },
            flags,
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
        // Spot-check every family against the Windows names.
        for (code, name) in [
            (0x00u16, "A"),
            (0x06, "Z"),
            (0x12, "1"),
            (0x1D, "0"),
            (0x31, "Space"),
            (0x24, "Enter"),
            (0x35, "Escape"),
            (0x33, "Backspace"),
            (0x7B, "ArrowLeft"),
            (0x7E, "ArrowUp"),
            (0x7A, "F1"),
            (0x5A, "F20"),
            (0x52, "Numpad0"),
            (0x29, ";"),
            (0x2A, "\\"),
            (0x38, "Shift"),
            (0x37, "Cmd"),
            (0x3A, "Option"),
            (0x3F, "Fn"),
            (0x6E, "Apps"),
        ] {
            assert_eq!(key_name(code), name, "keycode {code:#x}");
        }
    }

    #[test]
    fn modifier_key_names_classify_as_modifier_in_core() {
        // The additive core arm: the three mac names must classify with the
        // shared ones (this is the whole point of the core change).
        for name in ["Cmd", "Option", "Fn", "Shift", "Ctrl"] {
            assert_eq!(
                key_class_for_name(name),
                gilbreth_core::KeyClass::Modifier,
                "{name} must be a Modifier"
            );
        }
    }

    #[test]
    fn only_key_down_edges_emit_rows() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        assert!(
            state.on_event(down(0x00, 0), None, base, false).is_some(),
            "down emits"
        );
        assert!(
            state
                .on_event(
                    RawKeyEvent {
                        keycode: 0x00,
                        kind: RawKeyKind::KeyUp,
                        flags: 0
                    },
                    None,
                    base,
                    false
                )
                .is_none(),
            "up emits nothing"
        );
    }

    #[test]
    fn autorepeat_downs_are_filtered() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        assert!(state.on_event(down(0x00, 0), None, base, false).is_some());
        let repeat = RawKeyEvent {
            keycode: 0x00,
            kind: RawKeyKind::KeyDown { autorepeat: true },
            flags: 0,
        };
        assert!(
            state.on_event(repeat, None, base, false).is_none(),
            "OS-marked repeat is dropped"
        );
    }

    #[test]
    fn modifiers_are_read_from_flags_on_every_event() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        // 'C' pressed with Command held: win must be set (Command → mod_win).
        let event = state
            .on_event(down(0x08, MASK_COMMAND), None, base, false)
            .expect("row");
        let (name, mods) = expect_key(&event);
        assert_eq!(name, "C");
        assert!(mods.win, "Command sets mod_win");
        assert!(!mods.alt && !mods.ctrl && !mods.shift);

        // Command + Shift + Option: all three map correctly.
        let event = state
            .on_event(
                down(0x09, MASK_COMMAND | MASK_SHIFT | MASK_ALTERNATE),
                None,
                base,
                false,
            )
            .expect("row");
        let (_, mods) = expect_key(&event);
        assert!(mods.win && mods.shift && mods.alt && !mods.ctrl);
    }

    #[test]
    fn a_modifier_press_emits_a_named_row_and_release_does_not() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        // Shift key down (flagsChanged, mask now set): a "Shift" row.
        let press = state
            .on_event(
                RawKeyEvent {
                    keycode: 0x38,
                    kind: RawKeyKind::FlagsChanged,
                    flags: MASK_SHIFT,
                },
                None,
                base,
                false,
            )
            .expect("modifier press row");
        assert_eq!(expect_key(&press).0, "Shift");

        // Shift key up (flagsChanged, mask cleared): no row.
        assert!(
            state
                .on_event(
                    RawKeyEvent {
                        keycode: 0x38,
                        kind: RawKeyKind::FlagsChanged,
                        flags: 0
                    },
                    None,
                    base,
                    false
                )
                .is_none(),
            "modifier release emits nothing"
        );
    }

    #[test]
    fn left_and_right_modifiers_each_register_once() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        // Left shift down, then right shift down while left held: two presses
        // (distinct keycodes), mask stays set throughout.
        assert!(state
            .on_event(
                RawKeyEvent {
                    keycode: 0x38,
                    kind: RawKeyKind::FlagsChanged,
                    flags: MASK_SHIFT
                },
                None,
                base,
                false
            )
            .is_some());
        assert!(
            state
                .on_event(
                    RawKeyEvent {
                        keycode: 0x3C,
                        kind: RawKeyKind::FlagsChanged,
                        flags: MASK_SHIFT
                    },
                    None,
                    base,
                    false
                )
                .is_some(),
            "right shift is a distinct press even with the mask already set"
        );
        // Releasing left shift (mask still set because right is down): no row,
        // and the left keycode is cleared from the set.
        assert!(state
            .on_event(
                RawKeyEvent {
                    keycode: 0x38,
                    kind: RawKeyKind::FlagsChanged,
                    flags: MASK_SHIFT
                },
                None,
                base,
                false
            )
            .is_none());
    }

    #[test]
    fn boundary_reset_clears_pressed_and_modifiers() {
        let mut state = KeyboardState::new();
        let base = Instant::now();

        // Hold a modifier, then a boundary (lock) resets.
        state.on_event(
            RawKeyEvent {
                keycode: 0x38,
                kind: RawKeyKind::FlagsChanged,
                flags: MASK_SHIFT,
            },
            None,
            base,
            false,
        );
        state.reset_after_boundary();

        // The same modifier keycode after reset is a fresh press, not a
        // release — the set was cleared.
        assert!(state
            .on_event(
                RawKeyEvent {
                    keycode: 0x38,
                    kind: RawKeyKind::FlagsChanged,
                    flags: MASK_SHIFT
                },
                None,
                base,
                false
            )
            .is_some());
        // And a plain key carries default modifiers again.
        let event = state
            .on_event(down(0x00, 0), None, base, false)
            .expect("row");
        assert_eq!(*expect_key(&event).1, Modifiers::default());
    }

    #[test]
    fn capture_redaction_scrubs_key_mods_and_window_title() {
        let mut state = KeyboardState::new();
        let base = Instant::now();
        let window = gilbreth_core::WindowRef {
            hwnd: 7,
            exe: "/Applications/Browser.app/Contents/MacOS/Browser".to_string(),
            title: "Login — Bank".to_string(),
            pid: 7,
        };

        let event = state
            .on_event(down(0x08, MASK_COMMAND), Some(window), base, true)
            .expect("redacted row still exists (typing cadence stays honest)");
        match &event.payload {
            gilbreth_core::EventPayload::Key {
                key, mods, window, ..
            } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(*mods, Modifiers::default(), "modifiers scrubbed");
                let window = window.as_ref().expect("window kept");
                assert_eq!(window.title, "<redacted>", "title scrubbed");
                assert!(!window.exe.is_empty(), "exe attribution kept");
            }
            other => panic!("expected Key, got {other:?}"),
        }
    }

    #[test]
    fn unmapped_keycode_gets_an_honest_mac_label_classing_as_other() {
        // 0x48 is Volume Up — not in the table; must not masquerade as a
        // Windows VK.
        let name = key_name(0x48);
        assert_eq!(name, "Mac0x48");
        assert_eq!(key_class_for_name(&name), gilbreth_core::KeyClass::Other);
    }
}
