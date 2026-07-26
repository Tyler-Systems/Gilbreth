use std::{
    env,
    ffi::OsStr,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
    path::PathBuf,
    process, thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use gilbreth_capture_windows::record_routine_ipc::{JsonLineReader, PipeHandle};
use gilbreth_core::{
    unix_now_ms, RecordRoutineIpcControl, RecordRoutineIpcMessage, RecordStopReason, WriterInput,
};
use tracing::{info, warn};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT},
        System::Threading::{
            GetProcessId, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
            PROCESS_NAME_FORMAT,
        },
        UI::{
            Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    },
};

use crate::authenticode;

const HELPER_EXE_NAME: &str = "gilbreth-elevated-record-helper.exe";
const IPC_SCHEMA: &str = "gilbreth.record_routine.ipc.v1";
const HELPER_STOP_WAIT_MS: u32 = 5_000;
const HELPER_STOP_CONTROL_WAIT_MS: u64 = 1_000;
const HELPER_BRIDGE_DRAIN_WAIT_MS: u64 = 1_000;
const HELPER_SELF_STOP_MARGIN_MS: u64 = 5 * 60 * 1_000;

pub struct ElevatedRecordHelperHandle {
    record_session_id: i64,
    control_pipe: PipeHandle,
    control_ready: Option<Receiver<Result<(), String>>>,
    process: ProcessHandle,
    bridge_done: Receiver<RecordStopReason>,
    stopped: bool,
    bridge_finished: bool,
    /// A13 (ipc-02): set when the control-pipe connection or its client-PID
    /// validation fails, so the recording is terminated rather than silently
    /// continuing without a validated control channel.
    control_connect_failed: bool,
    keepalive_interval: Duration,
    last_keepalive: Instant,
}

impl ElevatedRecordHelperHandle {
    pub fn poll_unexpected_stop(&mut self) -> Option<RecordStopReason> {
        if self.stopped || self.bridge_finished {
            return None;
        }

        if let Some(reason) = self.poll_bridge_done() {
            return Some(reason);
        }
        // A13 (ipc-02): a failed control-pipe connection or client-PID validation
        // is terminal — terminate the helper instead of degrading to no control.
        self.poll_control_connection();
        if self.control_connect_failed {
            self.bridge_finished = true;
            return Some(RecordStopReason::Error);
        }
        self.write_keepalive_if_due();
        self.poll_bridge_done()
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.write_stop_control_bounded();
        self.process.wait_or_terminate();
        if !self.bridge_finished {
            match self
                .bridge_done
                .recv_timeout(Duration::from_millis(HELPER_BRIDGE_DRAIN_WAIT_MS))
            {
                Ok(_) => {
                    self.bridge_finished = true;
                }
                Err(_) => {
                    warn!(
                        record_session_id = self.record_session_id,
                        timeout_ms = HELPER_BRIDGE_DRAIN_WAIT_MS,
                        "elevated record helper bridge did not drain before timeout"
                    );
                }
            }
        }
    }

    fn write_stop_control_bounded(&mut self) {
        if !self.wait_for_control_connection() {
            return;
        }

        let (reply_tx, reply_rx) = bounded(1);
        let pipe = self.control_pipe.clone();
        let record_session_id = self.record_session_id;
        let spawn_result = thread::Builder::new()
            .name("gilbreth-elevated-helper-stop-control".to_string())
            .spawn(move || {
                let result = pipe
                    .write_json_line(&RecordRoutineIpcControl::Stop { record_session_id })
                    .map_err(|error| error.to_string());
                let _ = reply_tx.send(result);
            });
        if let Err(error) = spawn_result {
            warn!(
                %error,
                record_session_id = self.record_session_id,
                "could not start elevated helper stop-control thread"
            );
            return;
        }

        match reply_rx.recv_timeout(Duration::from_millis(HELPER_STOP_CONTROL_WAIT_MS)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(
                %error,
                record_session_id = self.record_session_id,
                "could not send stop to elevated record helper"
            ),
            Err(_) => warn!(
                record_session_id = self.record_session_id,
                timeout_ms = HELPER_STOP_CONTROL_WAIT_MS,
                "timed out sending stop to elevated record helper"
            ),
        }
    }

    fn poll_bridge_done(&mut self) -> Option<RecordStopReason> {
        match self.bridge_done.try_recv() {
            Ok(reason) => {
                self.bridge_finished = true;
                Some(reason)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.bridge_finished = true;
                Some(RecordStopReason::Error)
            }
        }
    }

    fn write_keepalive_if_due(&mut self) {
        if self.last_keepalive.elapsed() < self.keepalive_interval {
            return;
        }
        if !self.poll_control_connection() {
            return;
        }

        match self
            .control_pipe
            .write_json_line(&RecordRoutineIpcControl::KeepAlive {
                record_session_id: self.record_session_id,
            }) {
            Ok(()) => {
                self.last_keepalive = Instant::now();
            }
            Err(error) => warn!(
                %error,
                record_session_id = self.record_session_id,
                "could not send keep-alive to elevated record helper"
            ),
        }
    }

    fn wait_for_control_connection(&mut self) -> bool {
        if let Some(control_ready) = self.control_ready.take() {
            match control_ready.recv_timeout(Duration::from_millis(HELPER_STOP_CONTROL_WAIT_MS)) {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    warn!(
                        %error,
                        record_session_id = self.record_session_id,
                        "elevated helper control pipe did not connect"
                    );
                    false
                }
                Err(_) => {
                    warn!(
                        record_session_id = self.record_session_id,
                        timeout_ms = HELPER_STOP_CONTROL_WAIT_MS,
                        "timed out waiting for elevated helper control pipe"
                    );
                    false
                }
            }
        } else {
            true
        }
    }

    fn poll_control_connection(&mut self) -> bool {
        let Some(control_ready) = self.control_ready.as_ref() else {
            return true;
        };
        match control_ready.try_recv() {
            Ok(Ok(())) => {
                self.control_ready = None;
                true
            }
            Ok(Err(error)) => {
                warn!(
                    %error,
                    record_session_id = self.record_session_id,
                    "elevated helper control pipe did not connect or failed client validation"
                );
                self.control_ready = None;
                self.control_connect_failed = true;
                false
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                warn!(
                    record_session_id = self.record_session_id,
                    "elevated helper control pipe connect thread ended before reporting readiness"
                );
                self.control_ready = None;
                self.control_connect_failed = true;
                false
            }
        }
    }
}

impl Drop for ElevatedRecordHelperHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ProcessHandle {
    handle: HANDLE,
    pid: u32,
}

impl ProcessHandle {
    fn wait_or_terminate(&self) {
        if self.handle.is_invalid() {
            return;
        }
        let wait = unsafe { WaitForSingleObject(self.handle, HELPER_STOP_WAIT_MS) };
        if wait == WAIT_TIMEOUT {
            warn!("elevated record helper did not exit after stop; terminating helper process");
            let _ = unsafe { TerminateProcess(self.handle, 1) };
            let _ = unsafe { WaitForSingleObject(self.handle, HELPER_STOP_WAIT_MS) };
        }
    }

    fn terminate_after_launch_validation_failure(&self) {
        if self.handle.is_invalid() {
            return;
        }
        warn!("terminating elevated record helper after launch validation failed");
        let _ = unsafe { TerminateProcess(self.handle, 1) };
        let _ = unsafe { WaitForSingleObject(self.handle, HELPER_STOP_WAIT_MS) };
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

pub fn start(
    record_session_id: i64,
    writer_tx: Sender<WriterInput>,
    required_signer_sha256: Option<&str>,
    configured_helper_path: Option<&str>,
    safety_cap_ms: u64,
) -> Result<ElevatedRecordHelperHandle> {
    let action_pipe_name = elevated_helper_pipe_name(record_session_id, "actions");
    let control_pipe_name = elevated_helper_pipe_name(record_session_id, "control");
    let action_pipe = PipeHandle::create_elevated_helper_server(&action_pipe_name)
        .map_err(|error| anyhow!("create elevated helper pipe: {error}"))?;
    let control_pipe = PipeHandle::create_elevated_helper_server(&control_pipe_name)
        .map_err(|error| anyhow!("create elevated helper control pipe: {error}"))?;
    let process = launch_helper_runas(
        record_session_id,
        &action_pipe_name,
        &control_pipe_name,
        required_signer_sha256,
        configured_helper_path,
        helper_parent_liveness_timeout_ms(safety_cap_ms),
    )?;
    // A13 (ipc-02): validate the control-pipe client PID too (parity with the
    // action pipe), so only the launched high-integrity helper is trusted for
    // control (keep-alive / stop) traffic. Spawned after launch so the helper
    // PID is known; the control pipe server already exists and is listening.
    let control_ready =
        spawn_control_pipe_connect(record_session_id, process.pid, control_pipe.clone())?;
    let bridge_done = spawn_bridge_thread(record_session_id, process.pid, action_pipe, writer_tx)?;
    let parent_liveness_timeout_ms = helper_parent_liveness_timeout_ms(safety_cap_ms);

    Ok(ElevatedRecordHelperHandle {
        record_session_id,
        control_pipe,
        control_ready: Some(control_ready),
        process,
        bridge_done,
        stopped: false,
        bridge_finished: false,
        control_connect_failed: false,
        keepalive_interval: helper_keepalive_interval(parent_liveness_timeout_ms),
        last_keepalive: Instant::now(),
    })
}

fn spawn_control_pipe_connect(
    record_session_id: i64,
    expected_helper_pid: u32,
    pipe: PipeHandle,
) -> Result<Receiver<Result<(), String>>> {
    let (ready_tx, ready_rx) = bounded(1);
    thread::Builder::new()
        .name("gilbreth-elevated-record-helper-control".to_string())
        .spawn(move || {
            let result = pipe
                .connect_server()
                .map_err(|error| error.to_string())
                .and_then(|()| {
                    validate_connected_helper_client(&pipe, record_session_id, expected_helper_pid)
                        .map_err(|error| error.to_string())
                });
            if let Err(error) = &result {
                warn!(
                    %error,
                    record_session_id, "elevated helper control pipe connect failed"
                );
            }
            let _ = ready_tx.send(result);
        })
        .context("start elevated helper control pipe thread")?;
    Ok(ready_rx)
}

fn spawn_bridge_thread(
    record_session_id: i64,
    expected_helper_pid: u32,
    pipe: PipeHandle,
    writer_tx: Sender<WriterInput>,
) -> Result<Receiver<RecordStopReason>> {
    let (done_tx, done_rx) = bounded(1);
    thread::Builder::new()
        .name("gilbreth-elevated-record-helper-bridge".to_string())
        .spawn(move || {
            let reason = match bridge_helper_actions(
                record_session_id,
                expected_helper_pid,
                pipe,
                writer_tx,
            ) {
                Ok(reason) => reason,
                Err(error) => {
                    warn!(%error, record_session_id, "elevated record helper bridge stopped");
                    RecordStopReason::Error
                }
            };
            let _ = done_tx.send(reason);
        })
        .context("start elevated helper bridge thread")?;
    Ok(done_rx)
}

fn bridge_helper_actions(
    record_session_id: i64,
    expected_helper_pid: u32,
    pipe: PipeHandle,
    writer_tx: Sender<WriterInput>,
) -> Result<RecordStopReason> {
    pipe.connect_server()
        .map_err(|error| anyhow!("connect elevated helper pipe: {error}"))?;
    validate_connected_helper_client(&pipe, record_session_id, expected_helper_pid)?;
    let mut reader = JsonLineReader::new();
    let mut ready = false;
    loop {
        let Some(message) = reader
            .read_next::<RecordRoutineIpcMessage>(&pipe)
            .map_err(|error| anyhow!("read elevated helper IPC: {error}"))?
        else {
            break;
        };
        match message {
            RecordRoutineIpcMessage::Ready {
                schema,
                record_session_id: message_session_id,
                helper_pid,
                transport,
            } if schema == IPC_SCHEMA
                && message_session_id == record_session_id
                && helper_pid == expected_helper_pid =>
            {
                ready = true;
                info!(
                    record_session_id,
                    helper_pid, transport, "elevated record helper ready"
                );
            }
            RecordRoutineIpcMessage::Ready { .. } => {
                return Err(anyhow!(
                    "elevated helper ready message did not match session/schema/process"
                ));
            }
            RecordRoutineIpcMessage::Action { action }
                if ready && action.record_session_id == record_session_id =>
            {
                writer_tx
                    .send(WriterInput::Action(action.into_capture()))
                    .map_err(|error| anyhow!("forward elevated helper action: {error}"))?;
            }
            RecordRoutineIpcMessage::Action { .. } => {
                warn!(
                    record_session_id,
                    "dropped elevated helper action before ready or for a different session"
                );
            }
            RecordRoutineIpcMessage::RunSummary {
                record_session_id: message_session_id,
                stopped,
                stop_reason,
                actions_forwarded,
            } if message_session_id == record_session_id => {
                info!(
                    record_session_id,
                    stopped,
                    stop_reason = stop_reason.as_str(),
                    actions_forwarded,
                    "elevated record helper run summary"
                );
                return Ok(stop_reason);
            }
            RecordRoutineIpcMessage::RunSummary { .. } => {}
            RecordRoutineIpcMessage::Error {
                record_session_id: message_session_id,
                message,
            } if message_session_id == record_session_id => {
                return Err(anyhow!("elevated helper error: {message}"));
            }
            RecordRoutineIpcMessage::Error { .. } => {}
        }
    }
    Ok(RecordStopReason::Error)
}

fn validate_connected_helper_client(
    pipe: &PipeHandle,
    record_session_id: i64,
    expected_helper_pid: u32,
) -> Result<()> {
    let connected_client_pid = pipe
        .connected_client_process_id()
        .map_err(|error| anyhow!("read elevated helper pipe client process id: {error}"))?;
    if connected_client_pid != expected_helper_pid {
        return Err(anyhow!(
            "elevated helper pipe client process id {connected_client_pid} did not match launched helper process id {expected_helper_pid}"
        ));
    }
    info!(
        record_session_id,
        connected_client_pid, "elevated record helper pipe client validated"
    );
    Ok(())
}

/// A11 (toctou-02): best-effort test of whether the helper's directory is writable
/// by this (unelevated) process, by attempting to create a probe file in it. An
/// effective-access probe is more reliable than walking the DACL (which can miss
/// inherited / effective rights). A user-writable directory means a non-admin
/// process could pre-position or swap the helper binary before it is elevated.
/// Returns `None` when inconclusive (directory missing / other IO error). The
/// deny-write launch lock (A1 / toctou-01) still guards the binary across
/// verification and launch; this surfaces the directory-level risk that lock
/// cannot cover.
fn helper_dir_is_user_writable(helper: &std::path::Path) -> Option<bool> {
    let dir = helper.parent()?;
    let probe = dir.join(format!(
        ".gilbreth-helper-write-probe-{}",
        uuid::Uuid::new_v4()
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Some(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Some(false),
        Err(_) => None,
    }
}

/// A11 (toctou-02): a signed-lane config (a required signer is set) that points at
/// a user-writable helper directory is a misconfiguration, not the expected dev
/// lane — elevating from there defeats the signed install's admin-only-directory
/// guarantee, so treat it as fatal. The unsigned dev lane is user-writable by
/// design and only warns.
fn signed_helper_in_writable_dir_is_fatal(
    user_writable: Option<bool>,
    required_signer_sha256: Option<&str>,
) -> bool {
    user_writable == Some(true) && required_signer_sha256.is_some()
}

fn launch_helper_runas(
    record_session_id: i64,
    action_pipe_name: &str,
    control_pipe_name: &str,
    required_signer_sha256: Option<&str>,
    configured_helper_path: Option<&str>,
    parent_liveness_timeout_ms: u64,
) -> Result<ProcessHandle> {
    let helper = helper_exe_path(configured_helper_path)?;
    let _signature_lock = validate_helper_signature_requirement(&helper, required_signer_sha256)?;
    let helper_dir_user_writable = helper_dir_is_user_writable(&helper);
    if signed_helper_in_writable_dir_is_fatal(helper_dir_user_writable, required_signer_sha256) {
        // copy-allow: glow-vocabulary "elevate" names the Windows security action; it is not rhetorical glow
        return Err(anyhow!(
            "refusing to elevate the signed helper {} from a user-writable directory (toctou-02): \
             a non-admin process could pre-position or replace the binary. Install the signed \
             helper into an admin-only directory.",
            helper.display()
        ));
    }
    if helper_dir_user_writable == Some(true) {
        warn!(
            record_session_id,
            helper = %helper.display(),
            "elevating a helper from a user-writable directory: a non-admin process could \
             pre-position or replace the binary (toctou-02). Expected for the unsigned local dev \
             lane; the signed release lane installs the helper to an admin-only directory, where \
             this warning should not appear."
        );
    }
    let params = format!(
        "--pipe-name {} --control-pipe-name {} --record-session-id {record_session_id} --parent-liveness-timeout-ms {parent_liveness_timeout_ms}",
        quote_windows_arg(action_pipe_name),
        quote_windows_arg(control_pipe_name)
    );
    let verb = wide_null("runas");
    let file = wide_os(helper.as_os_str());
    let directory = helper
        .parent()
        .map(|path| wide_os(path.as_os_str()))
        .unwrap_or_else(|| vec![0]);
    let parameters = wide_null(&params);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(directory.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info) }
        .with_context(|| format!("launch elevated helper {}", helper.display()))?;
    if info.hProcess.is_invalid() {
        return Err(anyhow!(
            "ShellExecuteExW did not return a helper process handle"
        ));
    }
    let mut process = ProcessHandle {
        handle: info.hProcess,
        pid: 0,
    };
    match validate_launched_helper_process(&mut process, &helper) {
        Ok(()) => Ok(process),
        Err(error) => {
            process.terminate_after_launch_validation_failure();
            Err(error)
        }
    }
}

fn validate_helper_signature_requirement(
    helper: &Path,
    required_signer_sha256: Option<&str>,
) -> Result<Option<authenticode::AuthenticodeLaunchLock>> {
    let Some(required_signer_sha256) =
        required_signer_sha256.filter(|value| !value.trim().is_empty())
    else {
        let helper_name = helper
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(HELPER_EXE_NAME);
        warn!(
            helper = helper_name,
            "elevated helper signer requirement is not configured; allowing unsigned local/dev helper"
        );
        return Ok(None);
    };
    let (identity, lock) =
        authenticode::verify_file_signed_by_sha256_for_launch(helper, required_signer_sha256)
            .with_context(|| {
                "elevated helper did not satisfy configured Authenticode signer requirement"
            })?;
    info!(
        signer_subject = %identity.signer_subject,
        signer_sha256 = %identity.signer_sha256,
        "elevated helper Authenticode signer validated"
    );
    Ok(Some(lock))
}

fn validate_launched_helper_process(
    process: &mut ProcessHandle,
    expected_helper: &Path,
) -> Result<()> {
    let pid = unsafe { GetProcessId(process.handle) };
    if pid == 0 {
        return Err(anyhow!(
            "could not read elevated helper process id: {}",
            windows::core::Error::from_thread()
        ));
    }
    process.pid = pid;
    let launched_path = process_image_path_from_handle(process.handle)?;
    if !same_executable_path(&launched_path, expected_helper)? {
        return Err(anyhow!(
            "launched elevated helper image did not match requested helper executable"
        ));
    }
    Ok(())
}

fn process_image_path_from_handle(handle: HANDLE) -> Result<PathBuf> {
    let mut buffer = vec![0_u16; 32_768];
    let mut size = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    }
    .map_err(|error| anyhow!("read elevated helper process image: {error}"))?;
    buffer.truncate(size as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

fn same_executable_path(actual: &Path, expected: &Path) -> Result<bool> {
    Ok(path_compare_key(actual)? == path_compare_key(expected)?)
}

fn path_compare_key(path: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .with_context(|| "canonicalize elevated helper executable path")?;
    Ok(canonical
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase())
}

fn helper_exe_path(configured_helper_path: Option<&str>) -> Result<PathBuf> {
    if let Some(configured_helper_path) =
        configured_helper_path.filter(|value| !value.trim().is_empty())
    {
        return configured_helper_exe_path(configured_helper_path.trim());
    }
    default_helper_exe_path()
}

fn helper_parent_liveness_timeout_ms(safety_cap_ms: u64) -> u64 {
    safety_cap_ms
        .max(1)
        .saturating_add(HELPER_SELF_STOP_MARGIN_MS)
}

fn helper_keepalive_interval(parent_liveness_timeout_ms: u64) -> Duration {
    let interval_ms = (parent_liveness_timeout_ms / 3).clamp(1_000, 15_000);
    Duration::from_millis(interval_ms)
}

fn default_helper_exe_path() -> Result<PathBuf> {
    let mut path = env::current_exe().context("read current executable path")?;
    path.set_file_name(HELPER_EXE_NAME);
    if !path.exists() {
        return Err(anyhow!(
            "elevated helper executable not found beside app: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn configured_helper_exe_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(anyhow!(
            "configured elevated helper path must be absolute: {}",
            path.display()
        ));
    }
    if path.file_name() != Some(OsStr::new(HELPER_EXE_NAME)) {
        return Err(anyhow!(
            "configured elevated helper path must end with {HELPER_EXE_NAME}: {}",
            path.display()
        ));
    }
    if !path.exists() {
        return Err(anyhow!(
            "configured elevated helper executable not found: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn elevated_helper_pipe_name(record_session_id: i64, purpose: &str) -> String {
    format!(
        r"\\.\pipe\gilbreth-record-routine-{}-{}-{}-{}",
        process::id(),
        record_session_id,
        purpose,
        unix_now_ms()
    )
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn quote_windows_arg(value: &str) -> String {
    let mut quoted = String::from("\"");
    let mut backslashes = 0_usize;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes = backslashes.saturating_add(1),
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes.saturating_mul(2) + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes.saturating_mul(2)));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, fs, time::Duration};

    use crossbeam_channel::bounded;
    use gilbreth_core::{
        ActionCaptureWire, ActionPayload, ActionType, AutomationAction, FrameworkClass,
        SelectorPath, SelectorPathHop, SelectorTrustBasis,
    };
    use tempfile::tempdir;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn bridge_forwards_matching_value_free_action() {
        let record_session_id = 70_001;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let expected_helper_pid = test_helper_pid();
        let bridge = thread::spawn(move || {
            bridge_helper_actions(record_session_id, expected_helper_pid, server, writer_tx)
                .expect("bridge");
        });
        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        client
            .write_json_line(&ready_message(record_session_id, expected_helper_pid))
            .expect("ready sent");
        client
            .write_json_line(&RecordRoutineIpcMessage::Action {
                action: sample_wire_action(record_session_id),
            })
            .expect("action sent");

        let forwarded = writer_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("forwarded action");
        match forwarded {
            WriterInput::Action(action) => {
                assert_eq!(action.record_session_id, record_session_id);
                assert_eq!(action.action.action_type, ActionType::Invoke);
                assert_eq!(action.framework_class, FrameworkClass::Native);
            }
            _ => panic!("expected forwarded action"),
        }

        drop(client);
        bridge.join().expect("bridge thread joined");
    }

    #[test]
    fn bridge_drops_mismatched_session_actions() {
        let record_session_id = 70_002;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let expected_helper_pid = test_helper_pid();
        let bridge = thread::spawn(move || {
            bridge_helper_actions(record_session_id, expected_helper_pid, server, writer_tx)
                .expect("bridge");
        });
        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        client
            .write_json_line(&ready_message(record_session_id, expected_helper_pid))
            .expect("ready sent");
        client
            .write_json_line(&RecordRoutineIpcMessage::Action {
                action: sample_wire_action(record_session_id + 1),
            })
            .expect("action sent");

        assert!(writer_rx.recv_timeout(Duration::from_millis(100)).is_err());

        drop(client);
        bridge.join().expect("bridge thread joined");
    }

    #[test]
    fn bridge_thread_signals_done_after_run_summary() {
        let record_session_id = 70_004;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let expected_helper_pid = test_helper_pid();
        let bridge_done =
            spawn_bridge_thread(record_session_id, expected_helper_pid, server, writer_tx)
                .expect("bridge thread");
        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        client
            .write_json_line(&ready_message(record_session_id, expected_helper_pid))
            .expect("ready sent");
        client
            .write_json_line(&RecordRoutineIpcMessage::RunSummary {
                record_session_id,
                stopped: true,
                stop_reason: RecordStopReason::SafetyCapStop,
                actions_forwarded: 0,
            })
            .expect("summary sent");

        let reason = bridge_done
            .recv_timeout(Duration::from_secs(2))
            .expect("bridge done");
        assert_eq!(reason, RecordStopReason::SafetyCapStop);
        assert!(writer_rx.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn bridge_rejects_wrong_ipc_schema() {
        let record_session_id = 70_003;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let expected_helper_pid = test_helper_pid();
        let bridge = thread::spawn(move || {
            bridge_helper_actions(record_session_id, expected_helper_pid, server, writer_tx)
        });
        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        client
            .write_json_line(&RecordRoutineIpcMessage::Ready {
                schema: "wrong.schema".to_string(),
                record_session_id,
                helper_pid: expected_helper_pid,
                transport: "named_pipe".to_string(),
            })
            .expect("ready sent");

        assert!(writer_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(client);
        assert!(bridge.join().expect("bridge thread joined").is_err());
    }

    #[test]
    fn bridge_rejects_unexpected_helper_pid() {
        let record_session_id = 70_005;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let expected_helper_pid = test_helper_pid();
        let wrong_helper_pid = mismatched_test_helper_pid();
        let bridge = thread::spawn(move || {
            bridge_helper_actions(record_session_id, expected_helper_pid, server, writer_tx)
        });
        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        client
            .write_json_line(&ready_message(record_session_id, wrong_helper_pid))
            .expect("ready sent");

        assert!(writer_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(client);
        assert!(bridge.join().expect("bridge thread joined").is_err());
    }

    #[test]
    fn bridge_rejects_unexpected_pipe_client_pid() {
        let record_session_id = 70_006;
        let pipe_name = test_pipe_name(record_session_id);
        let server = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let (writer_tx, writer_rx) = bounded(1);
        let wrong_helper_pid = mismatched_test_helper_pid();
        let bridge = thread::spawn(move || {
            bridge_helper_actions(record_session_id, wrong_helper_pid, server, writer_tx)
        });

        let client =
            PipeHandle::open_client(&pipe_name, Duration::from_secs(2)).expect("client pipe");

        assert!(writer_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(client);
        assert!(bridge.join().expect("bridge thread joined").is_err());
    }

    #[test]
    fn quote_windows_arg_wraps_pipe_names_and_escapes_quotes() {
        assert_eq!(
            quote_windows_arg(r#"\\.\pipe\gilbreth "quoted""#),
            r#""\\.\pipe\gilbreth \"quoted\"""#
        );
    }

    #[test]
    fn elevated_helper_pipe_name_is_session_scoped() {
        let pipe_name = elevated_helper_pipe_name(42, "actions");

        assert!(pipe_name.starts_with(r"\\.\pipe\gilbreth-record-routine-"));
        assert!(pipe_name.contains("-42-actions-"));
        assert!(!pipe_name.contains(' '));
    }

    #[test]
    fn helper_exe_name_is_distinct_from_tray_binary() {
        assert_eq!(HELPER_EXE_NAME, "gilbreth-elevated-record-helper.exe");
    }

    #[test]
    fn helper_dir_is_user_writable_detects_writable_dir() {
        // A11 (toctou-02): the per-user temp directory is user-writable, so a
        // helper resolved inside it reports the user-writable condition.
        let helper = std::env::temp_dir().join("gilbreth-fake-helper.exe");
        assert_eq!(helper_dir_is_user_writable(&helper), Some(true));
    }

    #[test]
    fn signed_helper_in_writable_dir_is_fatal_only_for_signed_lane() {
        // A11 (toctou-02): signed config + user-writable dir is fatal; the unsigned
        // dev lane only warns; non-writable dirs are fine either way.
        assert!(signed_helper_in_writable_dir_is_fatal(
            Some(true),
            Some("ABCD")
        ));
        assert!(!signed_helper_in_writable_dir_is_fatal(Some(true), None));
        assert!(!signed_helper_in_writable_dir_is_fatal(
            Some(false),
            Some("ABCD")
        ));
        assert!(!signed_helper_in_writable_dir_is_fatal(None, Some("ABCD")));
    }

    #[test]
    fn helper_parent_liveness_timeout_adds_grace_margin() {
        assert_eq!(
            helper_parent_liveness_timeout_ms(60_000),
            60_000 + HELPER_SELF_STOP_MARGIN_MS
        );
        assert_eq!(
            helper_parent_liveness_timeout_ms(0),
            1 + HELPER_SELF_STOP_MARGIN_MS
        );
    }

    #[test]
    fn helper_keepalive_interval_is_bounded() {
        assert_eq!(
            helper_keepalive_interval(1).as_millis(),
            u128::from(1_000_u16)
        );
        assert_eq!(
            helper_keepalive_interval(90_000).as_millis(),
            u128::from(15_000_u16)
        );
    }

    #[test]
    fn helper_handle_reports_unexpected_bridge_stop_once() {
        let (_control_ready_tx, control_ready_rx) = bounded(1);
        let (bridge_done_tx, bridge_done_rx) = bounded(1);
        let pipe_name = test_pipe_name(70_007);
        let control_pipe = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let mut handle = ElevatedRecordHelperHandle {
            record_session_id: 70_007,
            control_pipe,
            control_ready: Some(control_ready_rx),
            process: ProcessHandle {
                handle: HANDLE::default(),
                pid: 0,
            },
            bridge_done: bridge_done_rx,
            stopped: false,
            bridge_finished: false,
            control_connect_failed: false,
            keepalive_interval: Duration::from_secs(60),
            last_keepalive: Instant::now(),
        };

        assert_eq!(handle.poll_unexpected_stop(), None);
        bridge_done_tx
            .send(RecordStopReason::SafetyCapStop)
            .expect("bridge done sent");
        assert_eq!(
            handle.poll_unexpected_stop(),
            Some(RecordStopReason::SafetyCapStop)
        );
        assert_eq!(handle.poll_unexpected_stop(), None);
        handle.stopped = true;
    }

    #[test]
    fn control_pipe_validation_failure_is_terminal() {
        // A13 (ipc-02): a failed control-pipe connection / client-PID validation
        // terminates the recording rather than silently degrading to no control.
        let (control_ready_tx, control_ready_rx) = bounded(1);
        let (_bridge_done_tx, bridge_done_rx) = bounded(1);
        let pipe_name = test_pipe_name(70_013);
        let control_pipe = PipeHandle::create_server(&pipe_name).expect("server pipe");
        let mut handle = ElevatedRecordHelperHandle {
            record_session_id: 70_013,
            control_pipe,
            control_ready: Some(control_ready_rx),
            process: ProcessHandle {
                handle: HANDLE::default(),
                pid: 0,
            },
            bridge_done: bridge_done_rx,
            stopped: false,
            bridge_finished: false,
            control_connect_failed: false,
            keepalive_interval: Duration::from_secs(60),
            last_keepalive: Instant::now(),
        };

        control_ready_tx
            .send(Err(
                "control pipe client pid 999 did not match launched helper pid 123".to_string(),
            ))
            .expect("control failure sent");
        assert_eq!(handle.poll_unexpected_stop(), Some(RecordStopReason::Error));
        // Terminal: subsequent polls report nothing further.
        assert_eq!(handle.poll_unexpected_stop(), None);
        handle.stopped = true;
    }

    #[test]
    fn configured_helper_path_accepts_absolute_existing_helper_name() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");
        fs::write(&helper, b"helper").expect("helper file");

        let resolved =
            helper_exe_path(Some(helper.to_str().expect("utf8 path"))).expect("helper path");

        assert_eq!(resolved, helper);
    }

    #[test]
    fn configured_helper_path_rejects_relative_paths() {
        let error = helper_exe_path(Some(r".\gilbreth-elevated-record-helper.exe")).unwrap_err();

        assert!(error
            .to_string()
            .contains("configured elevated helper path must be absolute"));
    }

    #[test]
    fn configured_helper_path_rejects_wrong_file_name() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("not-the-helper.exe");
        fs::write(&helper, b"helper").expect("helper file");

        let error = helper_exe_path(Some(helper.to_str().expect("utf8 path"))).unwrap_err();

        assert!(error
            .to_string()
            .contains("configured elevated helper path must end with"));
    }

    #[test]
    fn configured_helper_path_rejects_missing_file() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");

        let error = helper_exe_path(Some(helper.to_str().expect("utf8 path"))).unwrap_err();

        assert!(error
            .to_string()
            .contains("configured elevated helper executable not found"));
    }

    #[test]
    fn process_image_path_from_handle_reads_current_process() {
        let path =
            process_image_path_from_handle(unsafe { GetCurrentProcess() }).expect("process path");

        assert!(path.file_name().is_some());
    }

    #[test]
    fn same_executable_path_accepts_same_existing_file() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");
        fs::write(&helper, b"helper").expect("helper file");

        assert!(same_executable_path(&helper, &helper).expect("path compare"));
    }

    #[test]
    fn same_executable_path_rejects_different_existing_files() {
        let dir = tempdir().expect("tempdir");
        let expected = dir.path().join("gilbreth-elevated-record-helper.exe");
        let actual = dir.path().join("other-helper.exe");
        fs::write(&expected, b"expected").expect("expected helper file");
        fs::write(&actual, b"actual").expect("actual helper file");

        assert!(!same_executable_path(&actual, &expected).expect("path compare"));
    }

    #[test]
    fn helper_signature_requirement_skips_empty_config() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");
        fs::write(&helper, b"unsigned helper").expect("helper file");

        validate_helper_signature_requirement(&helper, None).expect("none skips");
        validate_helper_signature_requirement(&helper, Some("")).expect("empty skips");
        validate_helper_signature_requirement(&helper, Some("   ")).expect("blank skips");
    }

    #[test]
    fn helper_signature_requirement_rejects_invalid_hash_config() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");
        fs::write(&helper, b"unsigned helper").expect("helper file");

        let error =
            validate_helper_signature_requirement(&helper, Some("not-a-sha256")).unwrap_err();

        assert!(error
            .to_string()
            .contains("configured Authenticode signer requirement"));
    }

    #[test]
    fn helper_signature_requirement_rejects_unsigned_file() {
        let dir = tempdir().expect("tempdir");
        let helper = dir.path().join("gilbreth-elevated-record-helper.exe");
        fs::write(&helper, b"unsigned helper").expect("helper file");
        let expected = "00".repeat(32);

        let error = validate_helper_signature_requirement(&helper, Some(&expected)).unwrap_err();

        assert!(error
            .to_string()
            .contains("configured Authenticode signer requirement"));
    }

    #[test]
    fn wide_os_terminates_with_nul() {
        let wide = wide_os(OsString::from("gilbreth").as_os_str());

        assert_eq!(wide.last(), Some(&0));
    }

    fn ready_message(record_session_id: i64, helper_pid: u32) -> RecordRoutineIpcMessage {
        RecordRoutineIpcMessage::Ready {
            schema: IPC_SCHEMA.to_string(),
            record_session_id,
            helper_pid,
            transport: "named_pipe".to_string(),
        }
    }

    fn test_helper_pid() -> u32 {
        process::id()
    }

    fn mismatched_test_helper_pid() -> u32 {
        let pid = test_helper_pid();
        if pid == u32::MAX {
            pid - 1
        } else {
            pid + 1
        }
    }

    fn sample_wire_action(record_session_id: i64) -> ActionCaptureWire {
        ActionCaptureWire {
            action: AutomationAction {
                action_type: ActionType::Invoke,
                selector_path: SelectorPath {
                    backend: "uia".to_string(),
                    hops: vec![SelectorPathHop {
                        control_type: 50000,
                        automation_id: "ok".to_string(),
                        class_name: "Button".to_string(),
                        ordinal: 0,
                    }],
                },
                trust_basis: SelectorTrustBasis::PidMatch,
            },
            captured_unix_ms: 1_780_000_000_000,
            record_session_id,
            exe: Some("C:\\Windows\\notepad.exe".to_string()),
            is_sensitive: false,
            has_name: false,
            pattern_action: Some("invoke".to_string()),
            framework: "uia".to_string(),
            framework_class: FrameworkClass::Native,
            depth: 1,
            leaf_rect: None,
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
        }
    }

    fn test_pipe_name(record_session_id: i64) -> String {
        format!(
            r"\\.\pipe\gilbreth-elevated-helper-test-{}-{}-{}",
            process::id(),
            record_session_id,
            unix_now_ms()
        )
    }
}
