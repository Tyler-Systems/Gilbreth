//! Per-user "launch at startup" backed by the HKCU `Run` registry key.
//!
//! Enabling writes the current executable's (quoted) path to
//! `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` under the
//! value name `Gilbreth`; disabling deletes that value. This is **per-user** (no
//! admin rights), and the registry value itself *is* the persisted setting — the
//! tray reflects the live registry state on each launch, so there is no separate
//! config field that could drift out of sync.

use std::iter::once;
use std::path::Path;

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "Gilbreth";

/// UTF-16, NUL-terminated — the form Win32 wide-string APIs expect.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(once(0)).collect()
}

/// The command stored in the `Run` value: the executable path wrapped in quotes
/// so a path containing spaces (e.g. under `C:\Program Files\`) is parsed as a
/// single argument by the shell at logon.
fn quote_command(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

fn startup_command() -> Result<String> {
    let exe = std::env::current_exe().context("resolve current executable path")?;
    Ok(quote_command(&exe))
}

/// The command currently stored in the `Gilbreth` Run value, if any — the
/// dashboard's install-state read mirrors db.py's `_read_autostart_command`
/// (missing value reads as `None`, failures surface as the error string).
pub fn read_command() -> Result<Option<String>> {
    let key = RunKey::open()?;
    let name = wide(VALUE_NAME);
    let mut value_type = REG_VALUE_TYPE(0);
    let mut byte_len = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut byte_len),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        bail!("query Run value failed: {status:?}");
    }
    if value_type != REG_SZ {
        bail!("Run value has unexpected registry type: {value_type:?}");
    }

    let mut bytes = vec![0u8; byte_len as usize];
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut value_type),
            Some(bytes.as_mut_ptr()),
            Some(&mut byte_len),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("read Run value failed: {status:?}");
    }

    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    Ok(Some(
        String::from_utf16(&units).context("decode Run value")?,
    ))
}

fn write_command(command: &str) -> Result<()> {
    let key = RunKey::open()?;
    let name = wide(VALUE_NAME);
    let data = wide(command);
    // REG_SZ wants the NUL-terminated UTF-16 string as a byte buffer.
    let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len() * 2) };
    let status = unsafe { RegSetValueExW(key.0, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes)) };
    if status != ERROR_SUCCESS {
        bail!("set Run value failed: {status:?}");
    }
    Ok(())
}

/// RAII handle to the opened `Run` key; closes on drop.
struct RunKey(HKEY);

impl RunKey {
    /// Open the per-user `Run` key (creating it if absent) with query+set rights.
    fn open() -> Result<Self> {
        let subkey = wide(RUN_KEY);
        let mut hkey = HKEY::default();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            bail!("open HKCU Run key failed: {status:?}");
        }
        Ok(Self(hkey))
    }
}

impl Drop for RunKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Whether autostart is currently enabled (the `Gilbreth` Run value exists).
pub fn is_enabled() -> Result<bool> {
    let key = RunKey::open()?;
    let name = wide(VALUE_NAME);
    // lpData/lpcbData NULL: just probe for existence (and type), not the value.
    let status = unsafe { RegQueryValueExW(key.0, PCWSTR(name.as_ptr()), None, None, None, None) };
    if status == ERROR_SUCCESS {
        Ok(true)
    } else if status == ERROR_FILE_NOT_FOUND {
        Ok(false)
    } else {
        bail!("query Run value failed: {status:?}");
    }
}

/// Enable autostart: write the current executable's quoted path to the `Run` key.
pub fn enable() -> Result<()> {
    let command = startup_command()?;
    write_command(&command)
}

/// Disable autostart: delete the `Run` value. Idempotent — absent is success.
pub fn disable() -> Result<()> {
    let key = RunKey::open()?;
    let name = wide(VALUE_NAME);
    let status = unsafe { RegDeleteValueW(key.0, PCWSTR(name.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        bail!("delete Run value failed: {status:?}");
    }
}

/// Set autostart to `enabled`.
pub fn set_enabled(enabled: bool) -> Result<()> {
    if enabled {
        enable()
    } else {
        disable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RunValueRestore(Option<String>);

    impl Drop for RunValueRestore {
        fn drop(&mut self) {
            match self.0.as_deref() {
                Some(command) => {
                    let _ = write_command(command);
                }
                None => {
                    let _ = disable();
                }
            }
        }
    }

    #[test]
    fn quote_command_wraps_path_in_quotes() {
        let cmd = quote_command(Path::new(r"C:\Program Files\Gilbreth\gilbreth-app.exe"));
        assert_eq!(cmd, "\"C:\\Program Files\\Gilbreth\\gilbreth-app.exe\"");
        // A consumer splitting on whitespace must see one token.
        assert!(cmd.starts_with('"') && cmd.ends_with('"'));
    }

    #[test]
    fn enable_then_disable_round_trips_in_hkcu() {
        // Touches the real per-user Run key (HKCU is always writable by the
        // current user, so this is self-contained). Snapshot and restore the
        // exact command, not just enabled/disabled, so a test run cannot replace
        // the installed app path with the test harness executable.
        let prior = read_command().expect("query initial autostart command");
        let restore = RunValueRestore(prior.clone());

        enable().expect("enable autostart");
        let after_enable = read_command().expect("query after enable");
        let expected_enable_command = startup_command().expect("expected startup command");

        disable().expect("disable autostart");
        let after_disable = read_command().expect("query after disable");

        drop(restore);

        assert_eq!(
            read_command().expect("query restored autostart command"),
            prior,
            "test should restore the exact prior Run value"
        );
        assert_eq!(
            after_enable.as_deref(),
            Some(expected_enable_command.as_str()),
            "enable() should register the current executable"
        );
        assert!(
            after_disable.is_none(),
            "disable() should remove the Run value"
        );
    }
}
