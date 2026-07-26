#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("gilbreth-token-diagnostics is only available on Windows");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    windows_impl::run()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::{
        env,
        ffi::c_void,
        io,
        mem::{size_of, MaybeUninit},
        path::PathBuf,
        ptr,
    };

    use anyhow::{anyhow, bail, Context, Result};
    use serde_json::{json, Value};
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{
                GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
                TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
                TokenElevationTypeLimited, TokenIntegrityLevel, TokenUIAccess, TOKEN_ELEVATION,
                TOKEN_ELEVATION_TYPE, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
            },
            System::Threading::{
                GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
                QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    pub fn run() -> Result<()> {
        let targets = parse_targets(env::args())?;
        let processes = targets.into_iter().map(diagnose_target).collect::<Vec<_>>();
        let report = json!({
            "schema": "gilbreth.2ce.token_diagnostics.v1",
            "processes": processes,
        });

        serde_json::to_writer_pretty(io::stdout(), &report)?;
        println!();
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Target {
        Current,
        Pid(u32),
    }

    #[derive(Debug)]
    struct ProcessDiagnostics {
        pid: u32,
        image_path: PathBuf,
        token: TokenDiagnostics,
    }

    #[derive(Debug)]
    struct TokenDiagnostics {
        elevation_type_raw: i32,
        elevation_type: &'static str,
        elevated: bool,
        ui_access: bool,
        integrity_rid: u32,
        integrity_label: &'static str,
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn parse_targets(args: impl IntoIterator<Item = String>) -> Result<Vec<Target>> {
        let mut args = args.into_iter();
        let _exe = args.next();
        let mut targets = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--current" => targets.push(Target::Current),
                "--pid" => {
                    let pid = args
                        .next()
                        .ok_or_else(|| anyhow!("--pid requires a process id"))?
                        .parse::<u32>()
                        .with_context(|| "parse --pid value")?;
                    targets.push(Target::Pid(pid));
                }
                "-h" | "--help" => {
                    println!(
                        "Usage: gilbreth-token-diagnostics [--current] [--pid <pid> ...]\n\
                         Prints JSON with elevation type, integrity level, and TokenUIAccess."
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        if targets.is_empty() {
            targets.push(Target::Current);
        }
        Ok(targets)
    }

    fn diagnose_target(target: Target) -> Value {
        let target_name = target_name(target);
        let requested_pid = requested_pid(target);
        match diagnose_target_inner(target) {
            Ok(diagnostics) => json!({
                "target": target_name,
                "requested_pid": requested_pid,
                "ok": true,
                "pid": diagnostics.pid,
                "image_path": diagnostics.image_path,
                "token": {
                    "elevation_type_raw": diagnostics.token.elevation_type_raw,
                    "elevation_type": diagnostics.token.elevation_type,
                    "elevated": diagnostics.token.elevated,
                    "ui_access": diagnostics.token.ui_access,
                    "integrity": {
                        "rid": diagnostics.token.integrity_rid,
                        "label": diagnostics.token.integrity_label,
                    },
                },
            }),
            Err(error) => json!({
                "target": target_name,
                "requested_pid": requested_pid,
                "ok": false,
                "error": error.to_string(),
            }),
        }
    }

    fn target_name(target: Target) -> &'static str {
        match target {
            Target::Current => "current",
            Target::Pid(_) => "pid",
        }
    }

    fn requested_pid(target: Target) -> Option<u32> {
        match target {
            Target::Current => None,
            Target::Pid(pid) => Some(pid),
        }
    }

    fn diagnose_target_inner(target: Target) -> Result<ProcessDiagnostics> {
        match target {
            Target::Current => {
                let process = unsafe { GetCurrentProcess() };
                let token = open_process_token(process)?;
                Ok(ProcessDiagnostics {
                    pid: unsafe { GetCurrentProcessId() },
                    image_path: process_image_path(process)?,
                    token: read_token(token.0)?,
                })
            }
            Target::Pid(pid) => {
                let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                    .with_context(|| format!("open process {pid}"))?;
                let process = OwnedHandle(process);
                let token = open_process_token(process.0)
                    .with_context(|| format!("open process token for pid {pid}"))?;
                Ok(ProcessDiagnostics {
                    pid,
                    image_path: process_image_path(process.0)
                        .with_context(|| format!("read process image for pid {pid}"))?,
                    token: read_token(token.0)?,
                })
            }
        }
    }

    fn open_process_token(process: HANDLE) -> Result<OwnedHandle> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .with_context(|| "OpenProcessToken")?;
        Ok(OwnedHandle(token))
    }

    fn process_image_path(process: HANDLE) -> Result<PathBuf> {
        let mut buffer = vec![0_u16; 32_768];
        let mut size = buffer.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        }
        .with_context(|| "QueryFullProcessImageNameW")?;
        buffer.truncate(size as usize);
        Ok(PathBuf::from(String::from_utf16_lossy(&buffer)))
    }

    fn read_token(token: HANDLE) -> Result<TokenDiagnostics> {
        let elevation_type = query_token_struct::<TOKEN_ELEVATION_TYPE>(
            token,
            TokenElevationType,
            "TokenElevationType",
        )?;
        let elevation =
            query_token_struct::<TOKEN_ELEVATION>(token, TokenElevation, "TokenElevation")?;
        let ui_access = query_token_struct::<u32>(token, TokenUIAccess, "TokenUIAccess")?;
        let integrity_rid = query_integrity_rid(token)?;

        Ok(TokenDiagnostics {
            elevation_type_raw: elevation_type.0,
            elevation_type: elevation_type_label(elevation_type),
            elevated: elevation.TokenIsElevated != 0,
            ui_access: ui_access != 0,
            integrity_rid,
            integrity_label: integrity_label(integrity_rid),
        })
    }

    fn query_token_struct<T>(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        name: &str,
    ) -> Result<T> {
        let mut value = MaybeUninit::<T>::zeroed();
        let mut return_len = 0_u32;
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(value.as_mut_ptr().cast::<c_void>()),
                size_of::<T>() as u32,
                &mut return_len,
            )
        }
        .with_context(|| format!("read {name}"))?;
        Ok(unsafe { value.assume_init() })
    }

    fn query_token_bytes(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        name: &str,
    ) -> Result<Vec<u8>> {
        let mut required_len = 0_u32;
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut required_len) };
        if required_len == 0 {
            bail!("probe {name} size: {}", windows::core::Error::from_thread());
        }

        let mut buffer = vec![0_u8; required_len as usize];
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                required_len,
                &mut required_len,
            )
        }
        .with_context(|| format!("read {name}"))?;
        Ok(buffer)
    }

    fn query_integrity_rid(token: HANDLE) -> Result<u32> {
        let buffer = query_token_bytes(token, TokenIntegrityLevel, "TokenIntegrityLevel")?;
        if buffer.len() < size_of::<TOKEN_MANDATORY_LABEL>() {
            bail!("TokenIntegrityLevel returned a short buffer");
        }

        let label = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
        if label.Label.Sid.is_invalid() {
            bail!("TokenIntegrityLevel returned a null SID");
        }

        let sub_authority_count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
        if sub_authority_count.is_null() {
            bail!("GetSidSubAuthorityCount returned null");
        }
        let sub_authority_count = unsafe { *sub_authority_count as u32 };
        if sub_authority_count == 0 {
            bail!("integrity SID has no sub authorities");
        }

        let rid = unsafe { GetSidSubAuthority(label.Label.Sid, sub_authority_count - 1) };
        if rid.is_null() {
            bail!("GetSidSubAuthority returned null");
        }
        Ok(unsafe { *rid })
    }

    fn elevation_type_label(value: TOKEN_ELEVATION_TYPE) -> &'static str {
        if value == TokenElevationTypeDefault {
            "default"
        } else if value == TokenElevationTypeFull {
            "full"
        } else if value == TokenElevationTypeLimited {
            "limited"
        } else {
            "unknown"
        }
    }

    fn integrity_label(rid: u32) -> &'static str {
        match rid {
            0x0000 => "untrusted",
            0x1000 => "low",
            0x2000 => "medium",
            0x2100 => "medium_plus",
            0x3000 => "high",
            0x4000 => "system",
            0x5000 => "protected",
            0x2001..=0x2fff => "medium_family",
            0x3001..=0x3fff => "high_family",
            _ => "unknown",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn integrity_label_names_known_rids() {
            assert_eq!(integrity_label(0x0000), "untrusted");
            assert_eq!(integrity_label(0x1000), "low");
            assert_eq!(integrity_label(0x2000), "medium");
            assert_eq!(integrity_label(0x2100), "medium_plus");
            assert_eq!(integrity_label(0x3000), "high");
            assert_eq!(integrity_label(0x4000), "system");
        }

        #[test]
        fn elevation_type_label_names_known_values() {
            assert_eq!(elevation_type_label(TokenElevationTypeDefault), "default");
            assert_eq!(elevation_type_label(TokenElevationTypeFull), "full");
            assert_eq!(elevation_type_label(TokenElevationTypeLimited), "limited");
            assert_eq!(elevation_type_label(TOKEN_ELEVATION_TYPE(99)), "unknown");
        }

        #[test]
        fn default_target_is_current_process() {
            let targets = parse_targets(["gilbreth-token-diagnostics".to_string()]).unwrap();
            assert_eq!(targets, vec![Target::Current]);
        }

        #[test]
        fn current_process_token_diagnostics_reads() {
            let process = unsafe { GetCurrentProcess() };
            let token = open_process_token(process).unwrap();
            let diagnostics = read_token(token.0).unwrap();
            assert!(!diagnostics.elevation_type.is_empty());
            assert!(diagnostics.integrity_rid >= 0x1000);
            assert_ne!(diagnostics.integrity_label, "unknown");
        }
    }
}
