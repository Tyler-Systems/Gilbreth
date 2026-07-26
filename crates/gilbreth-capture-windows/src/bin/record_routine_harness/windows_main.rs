use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossbeam_channel::{bounded, Receiver, RecvTimeoutError};
use gilbreth_capture_windows::record_routine::{
    start_record_routine_capture, LatencySummary, RecordRoutineConfig, RecordRoutineRunStats,
};
use gilbreth_core::{
    ActionCapture, ActionDiag, EditCommitSignal, RejectedAction, RejectedActionReason,
    SelectorPath, SelectorPathHop, SelectorTrustBasis, WriterInput,
};
use serde::Serialize;
use serde_json::Value;

pub type HarnessResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const DEFAULT_OUTPUT: &str = "record_routine_harness.ndjson";
const DEFAULT_RECORD_SESSION_ID: i64 = 1;
const DEFAULT_DURATION_MS: u64 = 30_000;
const DEFAULT_QUEUE_CAPACITY: usize = 1_024;

const DISALLOWED_CONTENT_KEYS: &[&str] = &[
    "name",
    "value",
    "text",
    "document",
    "description",
    "help_text",
    "localized_control_type",
    "legacyiaccessible",
    "legacyiaccessible_name",
    "legacyiaccessible_value",
    "legacyiaccessible_description",
];

pub fn main() -> HarnessResult<()> {
    match parse_args(env::args().skip(1))? {
        Command::Capture(args) => capture_to_file(args),
        Command::Redact { input, output } => redact_file(&input, &output),
        Command::ExtractSelectors { input, output } => extract_selectors_file(&input, &output),
        Command::Help => {
            print_help();
            Ok(())
        }
    }
}

enum Command {
    Capture(CaptureArgs),
    Redact { input: PathBuf, output: PathBuf },
    ExtractSelectors { input: PathBuf, output: PathBuf },
    Help,
}

struct CaptureArgs {
    output: PathBuf,
    duration: Duration,
    record_session_id: i64,
    queue_capacity: usize,
    include_selector_strings: bool,
    target_pid: Option<u32>,
    extra_trusted_pids: Vec<u32>,
    lock_target: bool,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> HarnessResult<Command> {
    let mut args = args.into_iter().peekable();
    match args.peek().map(String::as_str) {
        Some("--help") | Some("-h") => return Ok(Command::Help),
        Some("redact") => {
            args.next();
            let mut input = None;
            let mut output = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--input" => input = Some(PathBuf::from(next_arg(&mut args, "--input")?)),
                    "--output" => output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                    "--help" | "-h" => return Ok(Command::Help),
                    other => {
                        return Err(harness_error(format!("unknown redact argument: {other}")))
                    }
                }
            }
            return Ok(Command::Redact {
                input: input.ok_or_else(|| harness_error("redact requires --input"))?,
                output: output.ok_or_else(|| harness_error("redact requires --output"))?,
            });
        }
        Some("extract-selectors") => {
            args.next();
            let mut input = None;
            let mut output = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--input" => input = Some(PathBuf::from(next_arg(&mut args, "--input")?)),
                    "--output" => output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                    "--help" | "-h" => return Ok(Command::Help),
                    other => {
                        return Err(harness_error(format!(
                            "unknown extract-selectors argument: {other}"
                        )))
                    }
                }
            }
            return Ok(Command::ExtractSelectors {
                input: input.ok_or_else(|| harness_error("extract-selectors requires --input"))?,
                output: output
                    .ok_or_else(|| harness_error("extract-selectors requires --output"))?,
            });
        }
        Some("capture") => {
            args.next();
        }
        _ => {}
    }

    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut duration_ms = DEFAULT_DURATION_MS;
    let mut record_session_id = DEFAULT_RECORD_SESSION_ID;
    let mut queue_capacity = DEFAULT_QUEUE_CAPACITY;
    let mut include_selector_strings = false;
    let mut redact_selector_strings = false;
    let mut target_pid = None;
    let mut extra_trusted_pids = Vec::new();
    let mut lock_target = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => output = PathBuf::from(next_arg(&mut args, "--output")?),
            "--duration-ms" => {
                duration_ms = next_arg(&mut args, "--duration-ms")?.parse()?;
            }
            "--record-session-id" => {
                record_session_id = next_arg(&mut args, "--record-session-id")?.parse()?;
            }
            "--queue-capacity" => {
                queue_capacity = next_arg(&mut args, "--queue-capacity")?.parse()?;
            }
            "--include-selector-strings" => include_selector_strings = true,
            "--redact-selector-strings" => redact_selector_strings = true,
            "--target-pid" => {
                target_pid = Some(next_arg(&mut args, "--target-pid")?.parse()?);
            }
            "--extra-trusted-pid" => {
                extra_trusted_pids.push(next_arg(&mut args, "--extra-trusted-pid")?.parse()?);
            }
            "--lock-target" => lock_target = true,
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(harness_error(format!("unknown capture argument: {other}"))),
        }
    }

    Ok(Command::Capture(CaptureArgs {
        output,
        duration: Duration::from_millis(duration_ms),
        record_session_id,
        queue_capacity,
        include_selector_strings: include_selector_strings && !redact_selector_strings,
        target_pid,
        extra_trusted_pids,
        lock_target,
    }))
}

fn next_arg(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> HarnessResult<String> {
    args.next()
        .ok_or_else(|| harness_error(format!("{flag} requires a value")))
}

fn harness_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

fn print_help() {
    eprintln!(
        "Usage:\n  record_routine_harness capture --output out.ndjson [--duration-ms 30000] [--include-selector-strings] [--target-pid PID] [--extra-trusted-pid PID] [--lock-target]\n  record_routine_harness redact --input raw.ndjson --output redacted.ndjson\n  record_routine_harness extract-selectors --input strings-on.ndjson --output selectors.json"
    );
}

fn capture_to_file(args: CaptureArgs) -> HarnessResult<()> {
    let (writer_tx, writer_rx) = bounded(args.queue_capacity.max(1));
    let mut config = RecordRoutineConfig::new(args.record_session_id);
    config.queue_capacity = args.queue_capacity.max(1);
    config.emit_diagnostics = true;
    config.target_pid = args.target_pid;
    config.extra_trusted_pids = args.extra_trusted_pids.clone();
    config.follow_foreground = !args.lock_target;
    let mut writer = BufWriter::new(File::create(&args.output)?);
    let clock = RunClock::new();
    let mut handle = match start_record_routine_capture(config, writer_tx) {
        Ok(handle) => handle,
        Err(error) => {
            write_startup_failure(&mut writer, &clock, args.record_session_id, &error)?;
            writer.flush()?;
            return Ok(());
        }
    };
    let mut state = StreamState::default();
    let deadline = Instant::now() + args.duration;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = remaining.min(Duration::from_millis(100));
        match writer_rx.recv_timeout(timeout) {
            Ok(input) => write_input(&mut writer, &clock, &mut state, input, &args)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    let stats = handle.stop();
    drain_inputs(&writer_rx, &mut writer, &clock, &mut state, &args)?;
    write_row(&mut writer, &NdjsonRow::RunSummary(run_summary_row(stats)))?;
    writer.flush()?;
    Ok(())
}

fn write_startup_failure(
    writer: &mut impl Write,
    clock: &RunClock,
    record_session_id: i64,
    error: &(dyn Error + Send + Sync + 'static),
) -> HarnessResult<()> {
    let reason = rejected_reason_for_startup_error(error);
    let rejected = RejectedAction {
        record_session_id,
        worker_ordinal: 0,
        event_kind: "startup".to_string(),
        captured_at: clock.started_at,
        reason,
        trust_basis: None,
        callback_latency_ns: 0,
        event_to_selector_complete_ns: 0,
        queue_depth_at_enqueue: 0,
    };
    write_row(writer, &NdjsonRow::Rejected(rejected_row(rejected, clock)))?;

    let mut stats = RecordRoutineRunStats::default();
    stats.failure_counts.insert(reason.as_str().to_string(), 1);
    write_row(writer, &NdjsonRow::RunSummary(run_summary_row(stats)))?;
    Ok(())
}

fn rejected_reason_for_startup_error(
    error: &(dyn Error + Send + Sync + 'static),
) -> RejectedActionReason {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("access denied")
        || message.contains("uipi")
        || message.contains("elevated")
        || message.contains("0x80070005")
    {
        RejectedActionReason::ElevatedOrUipiDenied
    } else if message.contains("trust classification") {
        RejectedActionReason::TrustRejected
    } else {
        RejectedActionReason::SelectorCaptureFailed
    }
}

fn drain_inputs(
    rx: &Receiver<WriterInput>,
    writer: &mut impl Write,
    clock: &RunClock,
    state: &mut StreamState,
    args: &CaptureArgs,
) -> HarnessResult<()> {
    while let Ok(input) = rx.try_recv() {
        write_input(writer, clock, state, input, args)?;
    }
    Ok(())
}

#[derive(Default)]
struct StreamState {
    pending_diag: Option<ActionDiag>,
}

fn write_input(
    writer: &mut impl Write,
    clock: &RunClock,
    state: &mut StreamState,
    input: WriterInput,
    args: &CaptureArgs,
) -> HarnessResult<()> {
    match input {
        WriterInput::ActionDiag(diag) => state.pending_diag = Some(diag),
        WriterInput::Action(action) => {
            let row = action_row(
                action,
                state.pending_diag.take(),
                clock,
                args.include_selector_strings,
            );
            write_row(writer, &NdjsonRow::Action(row))?;
        }
        WriterInput::RejectedAction(rejected) => {
            write_row(writer, &NdjsonRow::Rejected(rejected_row(rejected, clock)))?;
        }
        WriterInput::Motion(_) => {}
    }
    Ok(())
}

fn write_row(writer: &mut impl Write, row: &NdjsonRow) -> HarnessResult<()> {
    let value = serde_json::to_value(row)?;
    assert_value_free_keys(&value)?;
    serde_json::to_writer(&mut *writer, &value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[derive(Clone, Copy)]
struct RunClock {
    started_at: Instant,
    started_unix_ms: i64,
}

impl RunClock {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            started_unix_ms: unix_now_ms(),
        }
    }

    fn unix_ms(self, instant: Instant) -> i64 {
        let delta = if instant >= self.started_at {
            instant.duration_since(self.started_at)
        } else {
            Duration::ZERO
        };
        self.started_unix_ms
            .saturating_add(delta.as_millis().min(i64::MAX as u128) as i64)
    }
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[derive(Serialize)]
#[serde(tag = "row_type", rename_all = "snake_case")]
enum NdjsonRow {
    Action(ActionRow),
    Rejected(RejectedRow),
    RunSummary(RunSummaryRow),
}

#[derive(Serialize)]
struct ActionRow {
    schema_version: u32,
    record_session_id: i64,
    captured_ts_unix_ms: i64,
    action_type: &'static str,
    trust_basis: &'static str,
    exe_basename: Option<String>,
    framework: String,
    framework_class: &'static str,
    depth: u32,
    has_name: bool,
    leaf_rect_present: bool,
    pattern_action: Option<String>,
    selector_path: SelectorPathRow,
    payload: Value,
    diagnostics: Option<ActionDiagRow>,
}

#[derive(Serialize)]
struct SelectorPathRow {
    backend: String,
    path_hash: String,
    hop_count: usize,
    selector_strings_included: bool,
    hops: Vec<SelectorHopRow>,
}

#[derive(Serialize)]
struct SelectorHopRow {
    control_type: i32,
    ordinal: u32,
    has_automation_id: bool,
    has_class_name: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    automation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    class_name: Option<String>,
}

#[derive(Serialize)]
struct ActionDiagRow {
    worker_ordinal: u64,
    event_kind: String,
    callback_latency_ns: u64,
    event_to_selector_complete_ns: u64,
    queue_depth_at_enqueue: usize,
    repeat_count: u32,
    edit_commit_signal: Option<&'static str>,
}

#[derive(Serialize)]
struct RejectedRow {
    schema_version: u32,
    record_session_id: i64,
    worker_ordinal: u64,
    event_kind: String,
    captured_ts_unix_ms: i64,
    reason: &'static str,
    trust_basis: Option<&'static str>,
    callback_latency_ns: u64,
    event_to_selector_complete_ns: u64,
    queue_depth_at_enqueue: usize,
}

#[derive(Serialize)]
struct RunSummaryRow {
    schema_version: u32,
    storm_dropped_events: u64,
    max_queue_depth: usize,
    callback_latency: LatencySummaryRow,
    event_to_selector_complete: LatencySummaryRow,
    trust_basis_counts: BTreeMap<String, u64>,
    action_type_counts: BTreeMap<String, u64>,
    failure_counts: BTreeMap<String, u64>,
    edit_commit_signal_counts: BTreeMap<String, u64>,
    windows_recorded: usize,
}

#[derive(Serialize)]
struct LatencySummaryRow {
    p50_ns: u64,
    p95_ns: u64,
    max_ns: u64,
}

fn action_row(
    capture: ActionCapture,
    diag: Option<ActionDiag>,
    clock: &RunClock,
    include_selector_strings: bool,
) -> ActionRow {
    let payload = serde_json::to_value(&capture.payload).expect("action payload serializes");
    ActionRow {
        schema_version: 1,
        record_session_id: capture.record_session_id,
        captured_ts_unix_ms: clock.unix_ms(capture.captured_at),
        action_type: capture.action.action_type.as_str(),
        trust_basis: capture.action.trust_basis.as_str(),
        exe_basename: capture.exe.as_deref().and_then(path_basename),
        framework: capture.framework,
        framework_class: capture.framework_class.as_str(),
        depth: capture.depth,
        has_name: capture.has_name,
        leaf_rect_present: capture.leaf_rect.is_some(),
        pattern_action: capture.pattern_action,
        selector_path: selector_path_row(&capture.action.selector_path, include_selector_strings),
        payload,
        diagnostics: diag.map(action_diag_row),
    }
}

fn selector_path_row(path: &SelectorPath, include_selector_strings: bool) -> SelectorPathRow {
    SelectorPathRow {
        backend: path.backend.clone(),
        path_hash: path.hash_v1(),
        hop_count: path.hops.len(),
        selector_strings_included: include_selector_strings,
        hops: path
            .hops
            .iter()
            .map(|hop| selector_hop_row(hop, include_selector_strings))
            .collect(),
    }
}

fn selector_hop_row(hop: &SelectorPathHop, include_selector_strings: bool) -> SelectorHopRow {
    SelectorHopRow {
        control_type: hop.control_type,
        ordinal: hop.ordinal,
        has_automation_id: !hop.automation_id.is_empty(),
        has_class_name: !hop.class_name.is_empty(),
        automation_id: include_selector_strings.then(|| hop.automation_id.clone()),
        class_name: include_selector_strings.then(|| hop.class_name.clone()),
    }
}

fn action_diag_row(diag: ActionDiag) -> ActionDiagRow {
    ActionDiagRow {
        worker_ordinal: diag.worker_ordinal,
        event_kind: diag.event_kind,
        callback_latency_ns: diag.callback_latency_ns,
        event_to_selector_complete_ns: diag.event_to_selector_complete_ns,
        queue_depth_at_enqueue: diag.queue_depth_at_enqueue,
        repeat_count: diag.repeat_count,
        edit_commit_signal: diag.edit_commit_signal.map(EditCommitSignal::as_str),
    }
}

fn rejected_row(rejected: RejectedAction, clock: &RunClock) -> RejectedRow {
    RejectedRow {
        schema_version: 1,
        record_session_id: rejected.record_session_id,
        worker_ordinal: rejected.worker_ordinal,
        event_kind: rejected.event_kind,
        captured_ts_unix_ms: clock.unix_ms(rejected.captured_at),
        reason: rejected.reason.as_str(),
        trust_basis: rejected.trust_basis.map(SelectorTrustBasis::as_str),
        callback_latency_ns: rejected.callback_latency_ns,
        event_to_selector_complete_ns: rejected.event_to_selector_complete_ns,
        queue_depth_at_enqueue: rejected.queue_depth_at_enqueue,
    }
}

fn run_summary_row(stats: RecordRoutineRunStats) -> RunSummaryRow {
    RunSummaryRow {
        schema_version: 1,
        storm_dropped_events: stats.storm_dropped_events,
        max_queue_depth: stats.max_queue_depth,
        callback_latency: latency_summary_row(stats.callback_latency),
        event_to_selector_complete: latency_summary_row(stats.event_to_selector_complete),
        trust_basis_counts: stats.trust_basis_counts,
        action_type_counts: stats.action_type_counts,
        failure_counts: stats.failure_counts,
        edit_commit_signal_counts: stats.edit_commit_signal_counts,
        windows_recorded: stats.windows_recorded,
    }
}

fn latency_summary_row(summary: LatencySummary) -> LatencySummaryRow {
    LatencySummaryRow {
        p50_ns: summary.p50_ns,
        p95_ns: summary.p95_ns,
        max_ns: summary.max_ns,
    }
}

fn path_basename(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    (!name.is_empty()).then(|| name.to_string())
}

fn redact_file(input: &PathBuf, output: &PathBuf) -> HarnessResult<()> {
    let reader = BufReader::new(File::open(input)?);
    let mut writer = BufWriter::new(File::create(output)?);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut value: Value = serde_json::from_str(&line)?;
        redact_selector_strings(&mut value);
        assert_value_free_keys(&value)?;
        serde_json::to_writer(&mut writer, &value)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn extract_selectors_file(input: &PathBuf, output: &PathBuf) -> HarnessResult<()> {
    let selectors = read_selector_paths(input)?;
    let mut writer = BufWriter::new(File::create(output)?);
    serde_json::to_writer_pretty(&mut writer, &selectors)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_selector_paths(input: &PathBuf) -> HarnessResult<Vec<SelectorPath>> {
    let reader = BufReader::new(File::open(input)?);
    let mut selectors = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)?;
        if let Some(selector) = selector_path_from_row(&value)? {
            selectors.push(selector);
        }
    }
    Ok(selectors)
}

fn selector_path_from_row(row: &Value) -> HarnessResult<Option<SelectorPath>> {
    let Some(object) = row.as_object() else {
        return Ok(None);
    };
    if object.get("row_type").and_then(Value::as_str) != Some("action") {
        return Ok(None);
    }
    let selector = object
        .get("selector_path")
        .and_then(Value::as_object)
        .ok_or_else(|| harness_error("action row missing selector_path"))?;
    if selector
        .get("selector_strings_included")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(harness_error(
            "selector extraction requires an artifact captured with --include-selector-strings",
        ));
    }
    let backend = selector
        .get("backend")
        .and_then(Value::as_str)
        .ok_or_else(|| harness_error("selector_path.backend missing"))?
        .to_string();
    let hops = selector
        .get("hops")
        .and_then(Value::as_array)
        .ok_or_else(|| harness_error("selector_path.hops missing"))?
        .iter()
        .map(selector_hop_from_value)
        .collect::<HarnessResult<Vec<_>>>()?;
    Ok(Some(SelectorPath { backend, hops }))
}

fn selector_hop_from_value(value: &Value) -> HarnessResult<SelectorPathHop> {
    let object = value
        .as_object()
        .ok_or_else(|| harness_error("selector hop must be an object"))?;
    let control_type = object
        .get("control_type")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| harness_error("selector hop control_type missing or out of range"))?;
    let ordinal = object
        .get("ordinal")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| harness_error("selector hop ordinal missing or out of range"))?;
    let automation_id = object
        .get("automation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| harness_error("selector hop automation_id missing"))?
        .to_string();
    let class_name = object
        .get("class_name")
        .and_then(Value::as_str)
        .ok_or_else(|| harness_error("selector hop class_name missing"))?
        .to_string();
    Ok(SelectorPathHop {
        control_type,
        automation_id,
        class_name,
        ordinal,
    })
}

fn redact_selector_strings(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("automation_id");
            object.remove("class_name");
            if let Some(selector_strings_included) = object.get_mut("selector_strings_included") {
                *selector_strings_included = Value::Bool(false);
            }
            for nested in object.values_mut() {
                redact_selector_strings(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                redact_selector_strings(nested);
            }
        }
        _ => {}
    }
}

fn assert_value_free_keys(value: &Value) -> HarnessResult<()> {
    let mut path = Vec::new();
    assert_value_free_keys_at(value, &mut path)
}

fn assert_value_free_keys_at(value: &Value, path: &mut Vec<String>) -> HarnessResult<()> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if DISALLOWED_CONTENT_KEYS
                    .iter()
                    .any(|blocked| key.eq_ignore_ascii_case(blocked))
                {
                    let mut location = path.join(".");
                    if !location.is_empty() {
                        location.push('.');
                    }
                    location.push_str(key);
                    return Err(format!(
                        "value-bearing key is not allowed in harness output: {location}"
                    )
                    .into());
                }
                path.push(key.clone());
                assert_value_free_keys_at(nested, path)?;
                path.pop();
            }
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                path.push(index.to_string());
                assert_value_free_keys_at(nested, path)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gilbreth_core::{
        ActionPayload, ActionType, AutomationAction, FrameworkClass, RejectedActionReason,
    };

    fn sample_capture(captured_at: Instant) -> ActionCapture {
        ActionCapture {
            action: AutomationAction {
                action_type: ActionType::Invoke,
                selector_path: SelectorPath {
                    backend: "uia".to_string(),
                    hops: vec![SelectorPathHop {
                        control_type: 50000,
                        automation_id: "secret_save_button".to_string(),
                        class_name: "SecretButtonClass".to_string(),
                        ordinal: 2,
                    }],
                },
                trust_basis: SelectorTrustBasis::PidMatch,
            },
            captured_at,
            record_session_id: 42,
            exe: Some(r"C:\Program Files\TestApp\app.exe".to_string()),
            is_sensitive: false,
            has_name: true,
            pattern_action: Some("invoke".to_string()),
            framework: "uia".to_string(),
            framework_class: FrameworkClass::Native,
            depth: 1,
            leaf_rect: Some("1,2,3,4".to_string()),
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
        }
    }

    fn sample_diag() -> ActionDiag {
        ActionDiag {
            record_session_id: 42,
            worker_ordinal: 9,
            event_kind: "invoke".to_string(),
            callback_latency_ns: 10,
            event_to_selector_complete_ns: 20,
            queue_depth_at_enqueue: 2,
            repeat_count: 1,
            edit_commit_signal: None,
            trust_basis: Some(SelectorTrustBasis::PidMatch),
            action_type: Some(ActionType::Invoke),
        }
    }

    #[test]
    fn capture_args_parse_explicit_target_controls() {
        let args = [
            "capture",
            "--output",
            "out.ndjson",
            "--duration-ms",
            "1234",
            "--record-session-id",
            "77",
            "--queue-capacity",
            "9",
            "--target-pid",
            "4242",
            "--extra-trusted-pid",
            "5151",
            "--extra-trusted-pid",
            "6161",
            "--lock-target",
        ]
        .into_iter()
        .map(str::to_string);

        let Command::Capture(args) = parse_args(args).expect("parse capture args") else {
            panic!("expected capture command");
        };

        assert_eq!(args.output, PathBuf::from("out.ndjson"));
        assert_eq!(args.duration, Duration::from_millis(1234));
        assert_eq!(args.record_session_id, 77);
        assert_eq!(args.queue_capacity, 9);
        assert_eq!(args.target_pid, Some(4242));
        assert_eq!(args.extra_trusted_pids, vec![5151, 6161]);
        assert!(args.lock_target);
    }

    #[test]
    fn default_action_row_uses_selector_booleans_not_strings() {
        let clock = RunClock::new();
        let row = action_row(
            sample_capture(clock.started_at),
            Some(sample_diag()),
            &clock,
            false,
        );
        let value = serde_json::to_value(NdjsonRow::Action(row)).expect("serialize");
        let text = serde_json::to_string(&value).expect("json");

        assert!(text.contains("\"has_automation_id\":true"));
        assert!(text.contains("\"has_class_name\":true"));
        assert!(text.contains("\"selector_strings_included\":false"));
        assert!(!text.contains("secret_save_button"));
        assert!(!text.contains("SecretButtonClass"));
        assert_value_free_keys(&value).expect("value-free keys");
    }

    #[test]
    fn include_selector_strings_is_explicit_and_redactable() {
        let clock = RunClock::new();
        let row = action_row(
            sample_capture(clock.started_at),
            Some(sample_diag()),
            &clock,
            true,
        );
        let mut value = serde_json::to_value(NdjsonRow::Action(row)).expect("serialize");
        let text = serde_json::to_string(&value).expect("json");

        assert!(text.contains("\"selector_strings_included\":true"));
        assert!(text.contains("secret_save_button"));
        assert!(text.contains("SecretButtonClass"));

        redact_selector_strings(&mut value);
        let redacted = serde_json::to_string(&value).expect("json");
        assert!(redacted.contains("\"selector_strings_included\":false"));
        assert!(!redacted.contains("secret_save_button"));
        assert!(!redacted.contains("SecretButtonClass"));
        assert_value_free_keys(&value).expect("value-free keys");
    }

    #[test]
    fn selector_reader_reconstructs_paths_only_from_strings_on_rows() {
        let clock = RunClock::new();
        let row = action_row(
            sample_capture(clock.started_at),
            Some(sample_diag()),
            &clock,
            true,
        );
        let value = serde_json::to_value(NdjsonRow::Action(row)).expect("serialize");
        let selector = selector_path_from_row(&value)
            .expect("parse selector")
            .expect("selector present");
        assert_eq!(selector.backend, "uia");
        assert_eq!(selector.hops.len(), 1);
        assert_eq!(selector.hops[0].automation_id, "secret_save_button");
        assert_eq!(selector.hops[0].class_name, "SecretButtonClass");

        let row = action_row(
            sample_capture(clock.started_at),
            Some(sample_diag()),
            &clock,
            false,
        );
        let value = serde_json::to_value(NdjsonRow::Action(row)).expect("serialize");
        let error = selector_path_from_row(&value).expect_err("booleans-only rejected");
        assert!(
            error.to_string().contains("--include-selector-strings"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejected_and_summary_rows_serialize_without_content_keys() {
        let clock = RunClock::new();
        let rejected = RejectedAction {
            record_session_id: 42,
            worker_ordinal: 10,
            event_kind: "focus_changed".to_string(),
            captured_at: clock.started_at,
            reason: RejectedActionReason::WindowMismatch,
            trust_basis: None,
            callback_latency_ns: 1,
            event_to_selector_complete_ns: 2,
            queue_depth_at_enqueue: 3,
        };
        let rejected_value =
            serde_json::to_value(NdjsonRow::Rejected(rejected_row(rejected, &clock)))
                .expect("serialize");
        assert_value_free_keys(&rejected_value).expect("value-free keys");

        let mut stats = RecordRoutineRunStats {
            storm_dropped_events: 1,
            max_queue_depth: 4,
            windows_recorded: 2,
            ..RecordRoutineRunStats::default()
        };
        stats
            .failure_counts
            .insert("window_mismatch".to_string(), 1);
        let summary_value =
            serde_json::to_value(NdjsonRow::RunSummary(run_summary_row(stats))).expect("serialize");
        assert_value_free_keys(&summary_value).expect("value-free keys");
    }

    #[test]
    fn startup_elevation_failure_writes_rejected_row_and_summary() {
        let clock = RunClock::new();
        let error = harness_error(
            "target window is running elevated or its elevation could not be verified",
        );
        let mut output = Vec::new();

        write_startup_failure(&mut output, &clock, 99, error.as_ref())
            .expect("startup failure row");

        let rows = String::from_utf8(output).expect("utf8");
        let values = rows
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("json row"))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["row_type"], "rejected");
        assert_eq!(values[0]["record_session_id"], 99);
        assert_eq!(values[0]["event_kind"], "startup");
        assert_eq!(values[0]["reason"], "elevated_or_uipi_denied");
        assert_eq!(values[1]["row_type"], "run_summary");
        assert_eq!(values[1]["failure_counts"]["elevated_or_uipi_denied"], 1);
        assert_value_free_keys(&values[0]).expect("rejected value-free");
        assert_value_free_keys(&values[1]).expect("summary value-free");
    }

    #[test]
    fn value_free_guard_rejects_content_key_contract() {
        for key in [
            "Name",
            "Document",
            "Description",
            "LegacyIAccessible",
            "LegacyIAccessible_Value",
        ] {
            let mut object = serde_json::Map::new();
            object.insert(key.to_string(), Value::String("secret".to_string()));
            let value = Value::Object(object);
            let error = assert_value_free_keys(&value).expect_err("content key rejected");
            assert!(
                error.to_string().contains("value-bearing key"),
                "unexpected error for {key}: {error}"
            );
        }
    }
}
