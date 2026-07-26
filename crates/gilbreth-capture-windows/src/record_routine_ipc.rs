use std::{
    ffi::{c_void, OsStr},
    mem::size_of,
    os::windows::ffi::OsStrExt,
    sync::Arc,
    time::Duration,
};

use gilbreth_core::CaptureError;
use serde::{de::DeserializeOwned, Serialize};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GENERIC_READ,
            GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
            FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
            SYNCHRONIZE,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
            PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const MAX_JSON_LINE_BYTES: usize = 1024 * 1024;
const ELEVATED_HELPER_PIPE_CLIENT_ACCESS: u32 = SYNCHRONIZE.0
    | READ_CONTROL.0
    | FILE_READ_DATA.0
    | FILE_WRITE_DATA.0
    | FILE_READ_ATTRIBUTES.0
    | FILE_WRITE_ATTRIBUTES.0
    | FILE_READ_EA.0
    | FILE_WRITE_EA.0;
const ELEVATED_HELPER_PIPE_CLIENT_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAGS_AND_ATTRIBUTES(
    FILE_ATTRIBUTE_NORMAL.0 | SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0,
);
const ELEVATED_HELPER_PIPE_ACCESS_MASK_SDDL: &str = "0x0012019B";

#[derive(Clone)]
pub struct PipeHandle {
    inner: Arc<PipeInner>,
}

struct PipeInner {
    handle: HANDLE,
}

unsafe impl Send for PipeInner {}
unsafe impl Sync for PipeInner {}

impl Drop for PipeInner {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl PipeHandle {
    pub fn create_server(pipe_name: &str) -> Result<Self, CaptureError> {
        Self::create_server_with_security(pipe_name, None)
    }

    pub fn create_elevated_helper_server(pipe_name: &str) -> Result<Self, CaptureError> {
        let sddl = elevated_helper_pipe_sddl()?;
        Self::create_server_with_security(pipe_name, Some(&sddl))
    }

    fn create_server_with_security(
        pipe_name: &str,
        sddl: Option<&str>,
    ) -> Result<Self, CaptureError> {
        let name = wide_null(pipe_name);
        let security_descriptor = match sddl {
            Some(sddl) => Some(SecurityDescriptor::from_sddl(sddl)?),
            None => None,
        };
        let security_attributes = security_descriptor
            .as_ref()
            .map(|descriptor| descriptor.security_attributes());
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                security_attributes
                    .as_ref()
                    .map(|attributes| attributes as *const _),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateNamedPipeW"));
        }
        Ok(Self::from_handle(handle))
    }

    pub fn connect_server(&self) -> Result<(), CaptureError> {
        match unsafe { ConnectNamedPipe(self.inner.handle, None) } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(()),
            Err(error) => Err(CaptureError::WindowsApi(format!(
                "ConnectNamedPipe failed: {error}"
            ))),
        }
    }

    pub fn connected_client_process_id(&self) -> Result<u32, CaptureError> {
        let mut client_pid = 0_u32;
        unsafe { GetNamedPipeClientProcessId(self.inner.handle, &mut client_pid) }.map_err(
            |error| {
                CaptureError::WindowsApi(format!("GetNamedPipeClientProcessId failed: {error}"))
            },
        )?;
        if client_pid == 0 {
            return Err(CaptureError::WindowsApi(
                "GetNamedPipeClientProcessId returned PID 0".to_string(),
            ));
        }
        Ok(client_pid)
    }

    pub fn open_client(pipe_name: &str, wait: Duration) -> Result<Self, CaptureError> {
        Self::open_client_with_access(
            pipe_name,
            wait,
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_ATTRIBUTE_NORMAL,
        )
    }

    pub fn open_elevated_helper_client(
        pipe_name: &str,
        wait: Duration,
    ) -> Result<Self, CaptureError> {
        Self::open_client_with_access(
            pipe_name,
            wait,
            ELEVATED_HELPER_PIPE_CLIENT_ACCESS,
            ELEVATED_HELPER_PIPE_CLIENT_FLAGS,
        )
    }

    fn open_client_with_access(
        pipe_name: &str,
        wait: Duration,
        access: u32,
        flags: FILE_FLAGS_AND_ATTRIBUTES,
    ) -> Result<Self, CaptureError> {
        let name = wide_null(pipe_name);
        let wait_ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
        if !unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), wait_ms).as_bool() } {
            return Err(last_error("WaitNamedPipeW"));
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                access,
                Default::default(),
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
        .map_err(|error| CaptureError::WindowsApi(format!("CreateFileW failed: {error}")))?;
        Ok(Self::from_handle(handle))
    }

    fn from_handle(handle: HANDLE) -> Self {
        Self {
            inner: Arc::new(PipeInner { handle }),
        }
    }

    fn read_chunk(&self, buffer: &mut [u8]) -> Result<Option<usize>, CaptureError> {
        let mut read = 0_u32;
        match unsafe { ReadFile(self.inner.handle, Some(buffer), Some(&mut read), None) } {
            Ok(()) => {
                if read == 0 {
                    Ok(None)
                } else {
                    Ok(Some(read as usize))
                }
            }
            Err(error) if error.code() == ERROR_BROKEN_PIPE.to_hresult() => Ok(None),
            Err(error) => Err(CaptureError::WindowsApi(format!(
                "ReadFile failed: {error}"
            ))),
        }
    }

    pub fn write_all(&self, bytes: &[u8]) -> Result<(), CaptureError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let mut written = 0_u32;
            match unsafe {
                WriteFile(
                    self.inner.handle,
                    Some(&bytes[offset..]),
                    Some(&mut written),
                    None,
                )
            } {
                Ok(()) if written > 0 => offset = offset.saturating_add(written as usize),
                Ok(()) => {
                    return Err(CaptureError::WindowsApi(
                        "WriteFile wrote zero bytes".to_string(),
                    ));
                }
                Err(error) if error.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                    return Err(CaptureError::ChannelClosed);
                }
                Err(error) => {
                    return Err(CaptureError::WindowsApi(format!(
                        "WriteFile failed: {error}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn write_json_line<T: Serialize>(&self, value: &T) -> Result<(), CaptureError> {
        let mut bytes = serde_json::to_vec(value)
            .map_err(|error| CaptureError::WindowsApi(format!("serialize IPC JSON: {error}")))?;
        bytes.push(b'\n');
        self.write_all(&bytes)
    }
}

struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, CaptureError> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let sddl = wide_null(sddl);
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            CaptureError::WindowsApi(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {error}"
            ))
        })?;
        Ok(Self { descriptor })
    }

    fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0.cast::<c_void>(),
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

pub struct JsonLineReader {
    buffer: Vec<u8>,
}

impl JsonLineReader {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn read_next<T: DeserializeOwned>(
        &mut self,
        pipe: &PipeHandle,
    ) -> Result<Option<T>, CaptureError> {
        loop {
            if let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = self.buffer.drain(..=newline).collect::<Vec<_>>();
                let line = &line[..line.len().saturating_sub(1)];
                if line.is_empty() {
                    continue;
                }
                let value = serde_json::from_slice::<T>(line).map_err(|error| {
                    CaptureError::WindowsApi(format!("deserialize IPC JSON: {error}"))
                })?;
                return Ok(Some(value));
            }

            if self.buffer.len() > MAX_JSON_LINE_BYTES {
                return Err(CaptureError::WindowsApi(
                    "IPC JSON line exceeded maximum size".to_string(),
                ));
            }

            let mut chunk = [0_u8; 8192];
            match pipe.read_chunk(&mut chunk)? {
                Some(read) => self.buffer.extend_from_slice(&chunk[..read]),
                None if self.buffer.is_empty() => return Ok(None),
                None => {
                    let value = serde_json::from_slice::<T>(&self.buffer).map_err(|error| {
                        CaptureError::WindowsApi(format!("deserialize IPC JSON: {error}"))
                    })?;
                    self.buffer.clear();
                    return Ok(Some(value));
                }
            }
        }
    }
}

impl Default for JsonLineReader {
    fn default() -> Self {
        Self::new()
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn last_error(context: &str) -> CaptureError {
    let error = windows::core::Error::from_thread();
    CaptureError::WindowsApi(format!("{context} failed: {error}"))
}

fn elevated_helper_pipe_sddl() -> Result<String, CaptureError> {
    let user_sid = current_user_sid_string()?;
    // A12 (ipc-01): append a mandatory-integrity-label SACL so processes below the
    // pipe's integrity level cannot write to it (`NW` = NO_WRITE_UP). The pipe
    // server is created by the unelevated (Medium-IL) tray, which cannot raise an
    // object's label above its own token, so the label is Medium (`ME`): this
    // blocks Low-IL / AppContainer writers as defense-in-depth. The primary control
    // against a same-user Medium-IL impersonator remains the connected-client-PID
    // check (`validate_connected_helper_client`, now on both the action and control
    // pipes — A13). Both legitimate flows are same-or-down-level writes (Medium tray
    // -> Medium pipe on control; High helper -> Medium pipe on actions), so neither
    // is blocked by NO_WRITE_UP.
    Ok(format!(
        "D:P(A;;{mask};;;SY)(A;;{mask};;;BA)(A;;{mask};;;{user_sid})S:(ML;;NW;;;ME)",
        mask = ELEVATED_HELPER_PIPE_ACCESS_MASK_SDDL
    ))
}

fn current_user_sid_string() -> Result<String, CaptureError> {
    let token = ProcessToken::current()?;
    let mut required_len = 0_u32;
    let _ = unsafe { GetTokenInformation(token.handle, TokenUser, None, 0, &mut required_len) };
    if required_len == 0 {
        return Err(last_error("GetTokenInformation"));
    }

    let mut buffer = vec![0_u8; required_len as usize];
    unsafe {
        GetTokenInformation(
            token.handle,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            required_len,
            &mut required_len,
        )
    }
    .map_err(|error| CaptureError::WindowsApi(format!("GetTokenInformation failed: {error}")))?;

    // SAFETY: `buffer` is a 1-byte-aligned `Vec<u8>` filled by GetTokenInformation
    // with a TOKEN_USER, whose `User.Sid` field requires pointer alignment. Read the
    // struct out unaligned instead of forming a reference into the under-aligned
    // buffer (matches the TOKEN_MANDATORY_LABEL read in gilbreth-token-diagnostics).
    // The copied `User.Sid` still points into `buffer`, which outlives this read.
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid) }.map_err(|error| {
        CaptureError::WindowsApi(format!("ConvertSidToStringSidW failed: {error}"))
    })?;
    if sid.is_null() {
        return Err(CaptureError::WindowsApi(
            "ConvertSidToStringSidW returned a null SID string".to_string(),
        ));
    }

    let sid_string = unsafe { sid.to_string() }
        .map_err(|error| CaptureError::WindowsApi(format!("read SID string: {error}")))?;
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid.0.cast::<c_void>())));
    }
    Ok(sid_string)
}

struct ProcessToken {
    handle: HANDLE,
}

impl ProcessToken {
    fn current() -> Result<Self, CaptureError> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(
            |error| CaptureError::WindowsApi(format!("OpenProcessToken failed: {error}")),
        )?;
        Ok(Self { handle: token })
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process, thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE;

    const SECURITY_IMPERSONATION_LEVEL_MASK: u32 = 0x0003_0000;

    #[test]
    fn elevated_helper_pipe_access_does_not_grant_instance_creation() {
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_ACCESS & FILE_READ_DATA.0,
            FILE_READ_DATA.0
        );
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_ACCESS & FILE_WRITE_DATA.0,
            FILE_WRITE_DATA.0
        );
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_ACCESS & SYNCHRONIZE.0,
            SYNCHRONIZE.0
        );
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE.0,
            0
        );
    }

    #[test]
    fn elevated_helper_pipe_client_flags_limit_server_impersonation() {
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_FLAGS.0 & SECURITY_SQOS_PRESENT.0,
            SECURITY_SQOS_PRESENT.0
        );
        assert_eq!(
            ELEVATED_HELPER_PIPE_CLIENT_FLAGS.0 & SECURITY_IMPERSONATION_LEVEL_MASK,
            SECURITY_IDENTIFICATION.0
        );
    }

    #[test]
    fn elevated_helper_pipe_sddl_is_parseable() {
        let sddl = elevated_helper_pipe_sddl().expect("elevated helper SDDL builds");
        let user_sid = current_user_sid_string().expect("current user SID string");

        assert!(sddl.contains("(A;;0x0012019B;;;SY)"));
        assert!(sddl.contains("(A;;0x0012019B;;;BA)"));
        assert!(sddl.contains(&format!("(A;;0x0012019B;;;{user_sid})")));
        // A12 (ipc-01): mandatory-integrity SACL (NO_WRITE_UP at Medium IL) present.
        assert!(sddl.contains("S:(ML;;NW;;;ME)"));
        let descriptor = SecurityDescriptor::from_sddl(&sddl).expect("elevated helper SDDL parses");
        assert!(!descriptor.descriptor.0.is_null());
    }

    #[test]
    fn elevated_helper_pipe_allows_current_user_client() {
        let pipe_name = test_pipe_name();
        let server = PipeHandle::create_elevated_helper_server(&pipe_name).expect("server pipe");
        let server_for_connect = server.clone();
        let connect = thread::spawn(move || server_for_connect.connect_server());

        let client = PipeHandle::open_elevated_helper_client(&pipe_name, Duration::from_secs(2))
            .expect("client pipe");

        connect
            .join()
            .expect("connect thread joined")
            .expect("server connected");
        client.write_all(b"ping").expect("write through pipe");
    }

    #[test]
    fn connected_client_process_id_reports_current_process_client() {
        let pipe_name = test_pipe_name();
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let server_for_connect = server.clone();
        let connect = thread::spawn(move || server_for_connect.connect_server());

        let _client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        connect
            .join()
            .expect("connect thread joined")
            .expect("server connected");

        assert_eq!(
            server
                .connected_client_process_id()
                .expect("connected client process id"),
            process::id()
        );
    }

    fn test_pipe_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        format!(
            r"\\.\pipe\gilbreth-elevated-helper-dacl-test-{}-{nanos}",
            process::id()
        )
    }
}
