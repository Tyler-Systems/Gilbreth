//! Per-user "launch at startup" backed by XDG autostart (LIN-1 shell): a
//! `gilbreth.desktop` entry under `$XDG_CONFIG_HOME/autostart` (falling back
//! to `~/.config/autostart`), the freedesktop analog of the HKCU `Run`
//! value. The desktop file itself *is* the persisted setting — the tray
//! reflects the live file state on each launch, exactly like the registry
//! and `SMAppService` backends — and disabling removes the file.

use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

const DESKTOP_FILE_NAME: &str = "gilbreth.desktop";

/// XDG base directory: an absolute `$XDG_CONFIG_HOME`, else `~/.config`
/// (the spec treats a relative or empty value as unset — the same rule the
/// platform data root applies to `XDG_DATA_HOME`).
fn autostart_dir_from(xdg_config_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(dir) = xdg_config_home {
        let dir = Path::new(dir);
        if dir.is_absolute() {
            return Ok(dir.join("autostart"));
        }
    }
    let home = home.ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config").join("autostart"))
}

fn autostart_path() -> Result<PathBuf> {
    let xdg = env::var_os("XDG_CONFIG_HOME");
    let home = env::var_os("HOME");
    Ok(autostart_dir_from(xdg.as_deref(), home.as_deref())?.join(DESKTOP_FILE_NAME))
}

/// Exec value per the Desktop Entry spec's quoting rules: quote when the
/// path carries a character the field-splitting rules reserve, escaping the
/// characters that stay special inside quotes.
fn exec_value(exe: &Path) -> String {
    let raw = exe.display().to_string();
    let needs_quoting = raw
        .chars()
        .any(|c| c.is_whitespace() || "\"'\\><~|&;$*?#()`".contains(c));
    if !needs_quoting {
        return raw;
    }
    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('"');
    for c in raw.chars() {
        if "\"`$\\".contains(c) {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

fn desktop_entry(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Gilbreth\n\
         Comment=Ambient time-and-motion capture\n\
         Exec={}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exec_value(exe)
    )
}

/// The Exec command in the current desktop entry, if the entry exists — the
/// dashboard's install-state read, mirroring the registry backend (missing
/// file reads as `None`, failures surface as the error).
pub fn read_command() -> Result<Option<String>> {
    let path = autostart_path()?;
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read autostart entry {}", path.display()))
        }
    };
    Ok(contents
        .lines()
        .find_map(|line| line.strip_prefix("Exec="))
        .map(str::to_string))
}

pub fn is_enabled() -> Result<bool> {
    Ok(read_command()?.is_some())
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    let path = autostart_path()?;
    if !enabled {
        return match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("remove autostart entry {}", path.display()))
            }
        };
    }
    let exe = std::env::current_exe().context("resolve current executable path")?;
    let dir = path
        .parent()
        .expect("autostart path always has a directory");
    fs::create_dir_all(dir)
        .with_context(|| format!("create autostart directory {}", dir.display()))?;
    fs::write(&path, desktop_entry(&exe))
        .with_context(|| format!("write autostart entry {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_dir_honors_an_absolute_xdg_config_home_and_ignores_a_relative_one() {
        assert_eq!(
            autostart_dir_from(Some(OsStr::new("/xdg/cfg")), Some(OsStr::new("/home/u")))
                .expect("absolute XDG_CONFIG_HOME"),
            PathBuf::from("/xdg/cfg/autostart")
        );
        assert_eq!(
            autostart_dir_from(Some(OsStr::new("relative")), Some(OsStr::new("/home/u")))
                .expect("relative falls back to HOME"),
            PathBuf::from("/home/u/.config/autostart")
        );
        assert!(autostart_dir_from(None, None).is_err());
    }

    #[test]
    fn exec_values_quote_only_when_the_path_needs_it() {
        assert_eq!(
            exec_value(Path::new("/home/u/.local/bin/gilbreth-app")),
            "/home/u/.local/bin/gilbreth-app"
        );
        assert_eq!(
            exec_value(Path::new("/home/u/My Apps/gilbreth-app")),
            "\"/home/u/My Apps/gilbreth-app\""
        );
        assert_eq!(
            exec_value(Path::new("/opt/a\"b/gilbreth-app")),
            "\"/opt/a\\\"b/gilbreth-app\""
        );
    }

    #[test]
    fn desktop_entry_round_trips_through_the_exec_reader() {
        let entry = desktop_entry(Path::new("/usr/local/bin/gilbreth-app"));
        let exec = entry
            .lines()
            .find_map(|line| line.strip_prefix("Exec="))
            .expect("entry carries Exec");
        assert_eq!(exec, "/usr/local/bin/gilbreth-app");
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains("Type=Application\n"));
    }
}
