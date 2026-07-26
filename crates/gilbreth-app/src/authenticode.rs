use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, path::Path, ptr};

use anyhow::{anyhow, bail, Context, Result};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND},
        Security::{
            Cryptography::{
                CertGetCertificateContextProperty, CertGetNameStringW,
                CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA256_HASH_PROP_ID,
            },
            WinTrust::{
                WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
                WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
                WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
            },
        },
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticodeIdentity {
    pub signer_subject: String,
    pub signer_sha256: String,
}

#[derive(Debug)]
pub struct AuthenticodeLaunchLock {
    handle: HANDLE,
}

impl Drop for AuthenticodeLaunchLock {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
fn verify_file_signed_by_sha256(
    path: &Path,
    expected_signer_sha256: &str,
) -> Result<AuthenticodeIdentity> {
    let identity = verify_file_signature(path, HANDLE::default())?;
    require_expected_signer(identity, expected_signer_sha256)
}

pub fn verify_file_signed_by_sha256_for_launch(
    path: &Path,
    expected_signer_sha256: &str,
) -> Result<(AuthenticodeIdentity, AuthenticodeLaunchLock)> {
    let lock = AuthenticodeLaunchLock {
        handle: open_launch_lock(path)?,
    };
    let identity = verify_file_signature(path, lock.handle)?;
    Ok((
        require_expected_signer(identity, expected_signer_sha256)?,
        lock,
    ))
}

pub fn verify_file_signed_by_subject_for_launch(
    path: &Path,
    expected_signer_subject: &str,
) -> Result<(AuthenticodeIdentity, AuthenticodeLaunchLock)> {
    let (identity, lock) = verify_file_for_launch(path)?;
    Ok((
        require_expected_subject(identity, expected_signer_subject)?,
        lock,
    ))
}

pub fn verify_file_for_launch(
    path: &Path,
) -> Result<(AuthenticodeIdentity, AuthenticodeLaunchLock)> {
    let lock = AuthenticodeLaunchLock {
        handle: open_launch_lock(path)?,
    };
    let identity = verify_file_signature(path, lock.handle)?;
    Ok((identity, lock))
}

fn require_expected_signer(
    identity: AuthenticodeIdentity,
    expected_signer_sha256: &str,
) -> Result<AuthenticodeIdentity> {
    let expected = normalize_sha256_hex(expected_signer_sha256)?;
    if identity.signer_sha256 != expected {
        bail!("signer certificate SHA-256 did not match configured publisher");
    }
    Ok(identity)
}

fn require_expected_subject(
    identity: AuthenticodeIdentity,
    expected_signer_subject: &str,
) -> Result<AuthenticodeIdentity> {
    if expected_signer_subject.is_empty()
        || expected_signer_subject.len() > 200
        || expected_signer_subject.chars().any(char::is_control)
    {
        bail!("expected signer subject is invalid");
    }
    if identity.signer_subject != expected_signer_subject {
        bail!("signer subject did not match configured publisher");
    }
    Ok(identity)
}

fn verify_file_signature(path: &Path, handle: HANDLE) -> Result<AuthenticodeIdentity> {
    let path_wide = wide_path(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: handle,
        pgKnownSubject: ptr::null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let result = if status == 0 {
        signer_identity_from_state(trust_data.hWVTStateData)
            .with_context(|| format!("read Authenticode signer for {}", path.display()))
    } else {
        Err(anyhow!(
            "file is not Authenticode trusted by Windows policy: {}",
            wintrust_status_hex(status)
        ))
    };

    close_wintrust_state(&mut trust_data, &mut action);
    result
}

fn open_launch_lock(path: &Path) -> Result<HANDLE> {
    let path_wide = wide_path(path);
    unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| {
        format!(
            "open elevated helper with deny-write launch lock: {}",
            path.display()
        )
    })
}

fn signer_identity_from_state(state: HANDLE) -> Result<AuthenticodeIdentity> {
    if state.is_invalid() {
        bail!("WinVerifyTrust did not return provider state");
    }
    let provider_data = unsafe { WTHelperProvDataFromStateData(state) };
    if provider_data.is_null() {
        bail!("WinVerifyTrust provider data was not available");
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider_data, 0, false, 0) };
    if signer.is_null() {
        bail!("WinVerifyTrust signer chain was not available");
    }
    let signer = unsafe { &*signer };
    if signer.csCertChain == 0 || signer.pasCertChain.is_null() {
        bail!("WinVerifyTrust signer certificate chain was empty");
    }
    let provider_cert = unsafe { &*signer.pasCertChain };
    if provider_cert.pCert.is_null() {
        bail!("WinVerifyTrust signer certificate was not available");
    }

    Ok(AuthenticodeIdentity {
        signer_subject: cert_simple_subject(provider_cert.pCert),
        signer_sha256: cert_sha256(provider_cert.pCert)?,
    })
}

fn close_wintrust_state(trust_data: &mut WINTRUST_DATA, action: &mut windows::core::GUID) {
    if trust_data.hWVTStateData.is_invalid() {
        return;
    }
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            action,
            (trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
    }
}

fn cert_sha256(
    cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Result<String> {
    let mut len = 0_u32;
    let _ = unsafe {
        CertGetCertificateContextProperty(cert, CERT_SHA256_HASH_PROP_ID, None, &mut len)
    };
    if len == 0 {
        bail!("signer certificate SHA-256 property was not available");
    }

    let mut bytes = vec![0_u8; len as usize];
    unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA256_HASH_PROP_ID,
            Some(bytes.as_mut_ptr().cast::<c_void>()),
            &mut len,
        )
    }
    .context("read signer certificate SHA-256")?;
    bytes.truncate(len as usize);
    Ok(hex_lower(&bytes))
}

fn cert_simple_subject(
    cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> String {
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if len <= 1 {
        return String::new();
    }

    let mut buffer = vec![0_u16; len as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        )
    };
    if written == 0 {
        return String::new();
    }
    let len = written.saturating_sub(1) as usize;
    buffer.truncate(len);
    String::from_utf16_lossy(&buffer)
}

fn normalize_sha256_hex(value: &str) -> Result<String> {
    let normalized = value
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | ' ' | '\t' | '\r' | '\n'))
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("expected a 64-hex-character signer certificate SHA-256");
    }
    Ok(normalized)
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn wintrust_status_hex(status: i32) -> String {
    format!("0x{:08X}", status as u32)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn normalizes_sha256_fingerprint_spelling() {
        let spaced = "AA:BB-CC DD\tEE\nFF00112233445566778899AABBCCDDEEFF00112233445566778899";

        assert_eq!(
            normalize_sha256_hex(spaced).unwrap(),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn rejects_invalid_sha256_fingerprint() {
        assert!(normalize_sha256_hex("abcd").is_err());
        assert!(normalize_sha256_hex(&"0".repeat(63)).is_err());
        assert!(normalize_sha256_hex(&format!("{}z", "0".repeat(63))).is_err());
    }

    #[test]
    fn hex_lower_formats_bytes() {
        assert_eq!(hex_lower(&[0, 1, 10, 15, 16, 255]), "00010a0f10ff");
    }

    #[test]
    fn accepts_matching_signer_fingerprint() {
        let signer_sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let identity = AuthenticodeIdentity {
            signer_subject: "Gilbreth Test Publisher".to_string(),
            signer_sha256: signer_sha256.to_string(),
        };

        let accepted = require_expected_signer(
            identity.clone(),
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        )
        .expect("matching signer accepted");

        assert_eq!(accepted, identity);
    }

    #[test]
    fn rejects_wrong_signer_fingerprint() {
        let identity = AuthenticodeIdentity {
            signer_subject: "Gilbreth Test Publisher".to_string(),
            signer_sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .to_string(),
        };

        let error = require_expected_signer(identity, &"00".repeat(32)).unwrap_err();

        assert!(error
            .to_string()
            .contains("did not match configured publisher"));
    }

    #[test]
    fn subject_requirement_is_exact_and_bounded() {
        let identity = AuthenticodeIdentity {
            signer_subject: "Tyler Systems LLC".to_string(),
            signer_sha256: "00".repeat(32),
        };
        assert_eq!(
            require_expected_subject(identity.clone(), "Tyler Systems LLC").unwrap(),
            identity
        );
        assert!(require_expected_subject(identity.clone(), "Tyler Systems").is_err());
        assert!(require_expected_subject(identity, "bad\nsubject").is_err());
    }

    #[test]
    fn unsigned_temp_file_is_not_trusted() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("unsigned-helper.exe");
        std::fs::write(&path, b"unsigned").expect("write unsigned file");

        let error = verify_file_signed_by_sha256(&path, &"00".repeat(32)).unwrap_err();

        assert!(error.to_string().contains("not Authenticode trusted"));
    }
}
