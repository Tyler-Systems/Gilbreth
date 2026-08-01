//! Global ambient-capture pause hotkey: tolerant config parsing plus the
//! content-free status sidecar consumed by the native Diagnostics process.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PAUSE_RESUME_HOTKEY: &str = "ctrl+alt+shift+p";
pub const HOTKEY_STATUS_SIDECAR_NAME: &str = "hotkey-status.json";
pub const HOTKEY_STATUS_VERSION: u64 = 1;
pub const DIAGNOSTICS_UNREGISTERED_WARNING: &str =
    "pause hotkey unregistered (chord owned by another app); tray Pause remains available.";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct HotkeyConfig {
    pub pause_resume: String,
}

impl Default for HotkeyConfig {
    fn default() -> Self {
        Self {
            pause_resume: DEFAULT_PAUSE_RESUME_HOTKEY.to_string(),
        }
    }
}

// Everything from here through `registration_failure_alert` is shared by
// the three per-platform registration paths (RegisterHotKey, Carbon,
// XGrabKey); the parsing and status logic is portable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotkeyKey {
    Letter(char),
    Digit(char),
    Function(u8),
    Backspace,
    Delete,
    Down,
    End,
    Enter,
    Escape,
    Home,
    Insert,
    Left,
    PageDown,
    PageUp,
    Pause,
    Right,
    Space,
    Tab,
    Up,
}

impl fmt::Display for HotkeyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Letter(value) | Self::Digit(value) => {
                write!(formatter, "{}", value.to_ascii_uppercase())
            }
            Self::Function(value) => write!(formatter, "F{value}"),
            Self::Backspace => formatter.write_str("Backspace"),
            Self::Delete => formatter.write_str("Delete"),
            Self::Down => formatter.write_str("Down"),
            Self::End => formatter.write_str("End"),
            Self::Enter => formatter.write_str("Enter"),
            Self::Escape => formatter.write_str("Escape"),
            Self::Home => formatter.write_str("Home"),
            Self::Insert => formatter.write_str("Insert"),
            Self::Left => formatter.write_str("Left"),
            Self::PageDown => formatter.write_str("PageDown"),
            Self::PageUp => formatter.write_str("PageUp"),
            Self::Pause => formatter.write_str("Pause"),
            Self::Right => formatter.write_str("Right"),
            Self::Space => formatter.write_str("Space"),
            Self::Tab => formatter.write_str("Tab"),
            Self::Up => formatter.write_str("Up"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PauseHotkeyChord {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub win: bool,
    pub key: HotkeyKey,
}

impl fmt::Display for PauseHotkeyChord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::with_capacity(5);
        if self.ctrl {
            parts.push("Ctrl".to_string());
        }
        if self.alt {
            parts.push("Alt".to_string());
        }
        if self.shift {
            parts.push("Shift".to_string());
        }
        if self.win {
            // Same modifier, platform's own name. This string is user-visible
            // in Diagnostics, the status sidecar and the failure alert.
            parts.push(
                if cfg!(target_os = "macos") {
                    "Cmd"
                } else {
                    "Win"
                }
                .to_string(),
            );
        }
        parts.push(self.key.to_string());
        formatter.write_str(&parts.join("+"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseHotkeySetting {
    Disabled,
    Enabled(PauseHotkeyChord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPauseHotkey {
    pub setting: PauseHotkeySetting,
    /// Present only when a non-empty malformed value fell back to the
    /// documented default. Safe to log: it never repeats the malformed
    /// source text.
    pub warning: Option<&'static str>,
}

pub fn resolve_pause_hotkey(value: &str) -> ResolvedPauseHotkey {
    if value.trim().is_empty() {
        return ResolvedPauseHotkey {
            setting: PauseHotkeySetting::Disabled,
            warning: None,
        };
    }
    match parse_pause_hotkey(value) {
        Ok(chord) => ResolvedPauseHotkey {
            setting: PauseHotkeySetting::Enabled(chord),
            warning: None,
        },
        Err(()) => ResolvedPauseHotkey {
            setting: PauseHotkeySetting::Enabled(default_pause_hotkey()),
            warning: Some(
                "[hotkey].pause_resume is malformed; using Ctrl+Alt+Shift+P for this run",
            ),
        },
    }
}

fn default_pause_hotkey() -> PauseHotkeyChord {
    parse_pause_hotkey(DEFAULT_PAUSE_RESUME_HOTKEY).expect("built-in pause hotkey is valid")
}

fn parse_pause_hotkey(value: &str) -> Result<PauseHotkeyChord, ()> {
    let parts = value.split('+').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 2 || parts.iter().any(|part| part.is_empty()) {
        return Err(());
    }

    let mut seen = HashSet::new();
    let mut ctrl = false;
    let mut alt = false;
    let mut shift = false;
    let mut win = false;
    let mut key = None;
    for part in parts {
        let normalized = part.to_ascii_lowercase();
        if !seen.insert(normalized.clone()) {
            return Err(());
        }
        match normalized.as_str() {
            "ctrl" | "control" if !ctrl => ctrl = true,
            "alt" if !alt => alt = true,
            "shift" if !shift => shift = true,
            // `cmd`/`command` are macOS spellings of the same physical
            // modifier the schema calls `win` (the recorded mod_win <- Command
            // mapping). Accepted on every platform so a config written on one
            // parses on the other.
            "win" | "windows" | "cmd" | "command" if !win => win = true,
            "ctrl" | "control" | "alt" | "shift" | "win" | "windows" | "cmd" | "command" => {
                return Err(())
            }
            _ if key.is_none() => key = parse_key(&normalized),
            _ => return Err(()),
        }
        if !matches!(
            normalized.as_str(),
            "ctrl" | "control" | "alt" | "shift" | "win" | "windows" | "cmd" | "command"
        ) && key.is_none()
        {
            return Err(());
        }
    }
    if !(ctrl || alt || shift || win) {
        return Err(());
    }
    Ok(PauseHotkeyChord {
        ctrl,
        alt,
        shift,
        win,
        key: key.ok_or(())?,
    })
}

fn parse_key(value: &str) -> Option<HotkeyKey> {
    let mut chars = value.chars();
    if let (Some(single), None) = (chars.next(), chars.next()) {
        if single.is_ascii_alphabetic() {
            return Some(HotkeyKey::Letter(single.to_ascii_uppercase()));
        }
        if single.is_ascii_digit() {
            return Some(HotkeyKey::Digit(single));
        }
    }
    if let Some(number) = value
        .strip_prefix('f')
        .and_then(|raw| raw.parse::<u8>().ok())
    {
        if (1..=24).contains(&number) {
            return Some(HotkeyKey::Function(number));
        }
    }
    Some(match value {
        "backspace" => HotkeyKey::Backspace,
        "delete" | "del" => HotkeyKey::Delete,
        "down" => HotkeyKey::Down,
        "end" => HotkeyKey::End,
        "enter" | "return" => HotkeyKey::Enter,
        "escape" | "esc" => HotkeyKey::Escape,
        "home" => HotkeyKey::Home,
        "insert" | "ins" => HotkeyKey::Insert,
        "left" => HotkeyKey::Left,
        "pagedown" | "pgdn" => HotkeyKey::PageDown,
        "pageup" | "pgup" => HotkeyKey::PageUp,
        "pause" => HotkeyKey::Pause,
        "right" => HotkeyKey::Right,
        "space" => HotkeyKey::Space,
        "tab" => HotkeyKey::Tab,
        "up" => HotkeyKey::Up,
        _ => return None,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseHotkeyStatusKind {
    Registered,
    Disabled,
    Unregistered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PauseHotkeyStatus {
    pub version: u64,
    pub state: PauseHotkeyStatusKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chord: Option<String>,
}

impl PauseHotkeyStatus {
    pub fn registered(chord: PauseHotkeyChord) -> Self {
        Self {
            version: HOTKEY_STATUS_VERSION,
            state: PauseHotkeyStatusKind::Registered,
            chord: Some(chord.to_string()),
        }
    }

    pub fn disabled() -> Self {
        Self {
            version: HOTKEY_STATUS_VERSION,
            state: PauseHotkeyStatusKind::Disabled,
            chord: None,
        }
    }

    pub fn unregistered(chord: PauseHotkeyChord) -> Self {
        Self {
            version: HOTKEY_STATUS_VERSION,
            state: PauseHotkeyStatusKind::Unregistered,
            chord: Some(chord.to_string()),
        }
    }

    pub fn diagnostics_warning(&self) -> Option<String> {
        matches!(self.state, PauseHotkeyStatusKind::Unregistered)
            .then(|| DIAGNOSTICS_UNREGISTERED_WARNING.to_string())
    }
}

pub fn status_sidecar_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|dir| dir.join(HOTKEY_STATUS_SIDECAR_NAME))
        .unwrap_or_else(|| PathBuf::from(HOTKEY_STATUS_SIDECAR_NAME))
}

pub fn read_status(path: &Path) -> Option<PauseHotkeyStatus> {
    let contents = std::fs::read_to_string(path).ok()?;
    let status: PauseHotkeyStatus = serde_json::from_str(&contents).ok()?;
    (status.version == HOTKEY_STATUS_VERSION).then_some(status)
}

pub fn write_status(path: &Path, status: &PauseHotkeyStatus) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_string_pretty(status)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let temporary = path.with_extension("tmp");
    let result = (|| {
        std::fs::write(&temporary, contents)?;
        crate::platform::replace_file(&temporary, path)
            .map_err(|error| std::io::Error::other(error.to_string()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

pub fn registration_failure_alert(chord: PauseHotkeyChord) -> String {
    // copy-allow: em-dash one prose em dash within the per-string cap (Lane B ruling)
    format!(
        "The pause hotkey ({chord}) could not be registered — another app owns it. The hotkey is off this run; the tray Pause item still works. Change the chord under [hotkey] in config.toml."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_custom_malformed_and_empty_settings_resolve_as_decided() {
        let default = resolve_pause_hotkey(DEFAULT_PAUSE_RESUME_HOTKEY);
        assert_eq!(
            default.setting,
            PauseHotkeySetting::Enabled(default_pause_hotkey())
        );
        assert_eq!(default.warning, None);

        let custom = resolve_pause_hotkey("WIN + Shift + F12");
        let PauseHotkeySetting::Enabled(custom) = custom.setting else {
            panic!("custom chord must be enabled");
        };
        // One modifier, two platform names. The rendered string is user-visible
        // (Diagnostics, the status sidecar, the registration-failure alert), so
        // a Mac must not be shown "Win+".
        let expected = if cfg!(target_os = "macos") {
            "Shift+Cmd+F12"
        } else {
            "Shift+Win+F12"
        };
        assert_eq!(custom.to_string(), expected);

        // `cmd` and `command` are macOS spellings of the same modifier and
        // parse on every platform, so a config moved between machines keeps
        // working. Before this, a mac user writing the natural spelling got a
        // parse error and a silent fallback to the default.
        for spelling in ["cmd+shift+f12", "command+shift+f12", "win+shift+f12"] {
            let parsed = resolve_pause_hotkey(spelling);
            assert_eq!(
                parsed.setting,
                PauseHotkeySetting::Enabled(custom),
                "{spelling} must resolve to the same chord"
            );
            assert_eq!(parsed.warning, None, "{spelling} must not warn");
        }
        // Still rejected: the same modifier named twice.
        assert!(resolve_pause_hotkey("cmd+win+f12").warning.is_some());

        let malformed = resolve_pause_hotkey("ctrl+banana+p");
        assert_eq!(
            malformed.setting,
            PauseHotkeySetting::Enabled(default_pause_hotkey())
        );
        assert!(malformed.warning.is_some());

        assert_eq!(
            resolve_pause_hotkey("  ").setting,
            PauseHotkeySetting::Disabled
        );
    }

    #[test]
    fn parser_rejects_missing_modifiers_duplicate_parts_and_multiple_keys() {
        assert!(parse_pause_hotkey("p").is_err());
        assert!(parse_pause_hotkey("ctrl+ctrl+p").is_err());
        assert!(parse_pause_hotkey("ctrl+p+q").is_err());
        assert!(parse_pause_hotkey("ctrl+").is_err());
    }

    #[test]
    fn status_sidecar_round_trips_and_only_failure_has_a_warning() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = status_sidecar_path(&dir.path().join("config.toml"));
        let chord = default_pause_hotkey();
        let failed = PauseHotkeyStatus::unregistered(chord);
        write_status(&path, &failed).expect("status writes");
        assert_eq!(read_status(&path), Some(failed.clone()));
        assert_eq!(
            failed.diagnostics_warning().as_deref(),
            Some(DIAGNOSTICS_UNREGISTERED_WARNING)
        );
        assert!(PauseHotkeyStatus::registered(chord)
            .diagnostics_warning()
            .is_none());
        assert!(PauseHotkeyStatus::disabled()
            .diagnostics_warning()
            .is_none());
    }
}
