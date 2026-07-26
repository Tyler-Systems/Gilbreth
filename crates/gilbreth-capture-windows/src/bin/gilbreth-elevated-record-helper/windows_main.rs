use std::{env, process, thread, time::Duration};

use crossbeam_channel::{after, bounded, select, unbounded};
use gilbreth_capture_windows::{
    record_routine::{start_record_routine_capture, RecordRoutineConfig},
    record_routine_ipc::{JsonLineReader, PipeHandle},
};
use gilbreth_core::{
    ActionCaptureWire, RecordRoutineIpcControl, RecordRoutineIpcMessage, RecordStopReason,
    WriterInput,
};

const IPC_SCHEMA: &str = "gilbreth.record_routine.ipc.v1";

pub fn main() {
    if let Err(error) = run() {
        eprintln!("gilbreth elevated record helper failed: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = HelperArgs::parse(env::args().skip(1))?;
    let pipe = PipeHandle::open_elevated_helper_client(&args.pipe_name, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let control_pipe =
        PipeHandle::open_elevated_helper_client(&args.control_pipe_name, Duration::from_secs(30))
            .map_err(|error| error.to_string())?;

    let (writer_tx, writer_rx) = bounded(4096);
    let mut capture = match start_record_routine_capture(
        RecordRoutineConfig::new(args.record_session_id),
        writer_tx,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            let _ = pipe.write_json_line(&RecordRoutineIpcMessage::Error {
                record_session_id: args.record_session_id,
                message: error.to_string(),
            });
            return Err(error.to_string());
        }
    };
    pipe.write_json_line(&RecordRoutineIpcMessage::Ready {
        schema: IPC_SCHEMA.to_string(),
        record_session_id: args.record_session_id,
        helper_pid: process::id(),
        transport: "named_pipe".to_string(),
    })
    .map_err(|error| error.to_string())?;

    let (control_tx, control_rx) = unbounded();
    let record_session_id = args.record_session_id;
    thread::Builder::new()
        .name("gilbreth-elevated-helper-control".to_string())
        .spawn(move || {
            let mut reader = JsonLineReader::new();
            loop {
                match reader.read_next::<RecordRoutineIpcControl>(&control_pipe) {
                    Ok(Some(message)) => {
                        if let Some(event) = control_event_for_message(message, record_session_id) {
                            let should_stop = event.should_stop();
                            let _ = control_tx.send(event);
                            if should_stop {
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        let _ = control_tx.send(ControlEvent::ParentDisconnected);
                        break;
                    }
                    Err(_) => {
                        let _ = control_tx.send(ControlEvent::ParentDisconnected);
                        break;
                    }
                }
            }
        })
        .map_err(|error| format!("start helper control thread: {error}"))?;

    let mut actions_forwarded = 0_u64;
    let parent_liveness_timeout = Duration::from_millis(args.parent_liveness_timeout_ms.max(1));
    let mut parent_deadline = after(parent_liveness_timeout);
    let stop_reason = loop {
        select! {
            recv(parent_deadline) -> _ => {
                let _ = capture.stop();
                break RecordStopReason::SafetyCapStop;
            }
            recv(control_rx) -> message => match message {
                Ok(ControlEvent::KeepAlive) => {
                    parent_deadline = after(parent_liveness_timeout);
                }
                Ok(event) => {
                    let _ = capture.stop();
                    break event.stop_reason();
                }
                Err(_) => {
                    let _ = capture.stop();
                    break RecordStopReason::Error;
                }
            },
            recv(writer_rx) -> message => match message {
                Ok(WriterInput::Action(action)) => {
                    let wire = ActionCaptureWire::from_capture(&action);
                    pipe.write_json_line(&RecordRoutineIpcMessage::Action { action: wire })
                        .map_err(|error| error.to_string())?;
                    actions_forwarded = actions_forwarded.saturating_add(1);
                }
                Ok(WriterInput::ActionDiag(_)) | Ok(WriterInput::RejectedAction(_)) | Ok(WriterInput::Motion(_)) => {}
                Err(_) => {
                    let _ = capture.stop();
                    break RecordStopReason::Error;
                }
            }
        }
    };

    let _ = pipe.write_json_line(&RecordRoutineIpcMessage::RunSummary {
        record_session_id: args.record_session_id,
        stopped: true,
        stop_reason,
        actions_forwarded,
    });
    Ok(())
}

#[derive(Debug)]
struct HelperArgs {
    pipe_name: String,
    control_pipe_name: String,
    record_session_id: i64,
    parent_liveness_timeout_ms: u64,
}

impl HelperArgs {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut pipe_name = None;
        let mut control_pipe_name = None;
        let mut record_session_id = None;
        let mut parent_liveness_timeout_ms = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--pipe-name" => pipe_name = args.next(),
                "--control-pipe-name" => control_pipe_name = args.next(),
                "--record-session-id" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--record-session-id requires a value".to_string())?;
                    record_session_id = Some(
                        value
                            .parse::<i64>()
                            .map_err(|error| format!("invalid --record-session-id: {error}"))?,
                    );
                }
                "--parent-liveness-timeout-ms" => {
                    let value = args.next().ok_or_else(|| {
                        "--parent-liveness-timeout-ms requires a value".to_string()
                    })?;
                    parent_liveness_timeout_ms = Some(value.parse::<u64>().map_err(|error| {
                        format!("invalid --parent-liveness-timeout-ms: {error}")
                    })?);
                }
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument: {other}\n{}", usage())),
            }
        }
        let pipe_name = pipe_name.ok_or_else(|| "--pipe-name is required".to_string())?;
        let control_pipe_name =
            control_pipe_name.ok_or_else(|| "--control-pipe-name is required".to_string())?;
        let record_session_id =
            record_session_id.ok_or_else(|| "--record-session-id is required".to_string())?;
        if record_session_id <= 0 {
            return Err("--record-session-id must be positive".to_string());
        }
        let parent_liveness_timeout_ms = parent_liveness_timeout_ms
            .ok_or_else(|| "--parent-liveness-timeout-ms is required".to_string())?;
        if parent_liveness_timeout_ms == 0 {
            return Err("--parent-liveness-timeout-ms must be positive".to_string());
        }
        Ok(Self {
            pipe_name,
            control_pipe_name,
            record_session_id,
            parent_liveness_timeout_ms,
        })
    }
}

fn usage() -> String {
    "usage: gilbreth-elevated-record-helper --pipe-name <name> --control-pipe-name <name> --record-session-id <id> --parent-liveness-timeout-ms <ms>".to_string()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlEvent {
    Stop,
    KeepAlive,
    ParentDisconnected,
}

impl ControlEvent {
    fn should_stop(self) -> bool {
        !matches!(self, Self::KeepAlive)
    }

    fn stop_reason(self) -> RecordStopReason {
        match self {
            Self::Stop => RecordStopReason::UserStop,
            Self::KeepAlive => RecordStopReason::Error,
            Self::ParentDisconnected => RecordStopReason::Error,
        }
    }
}

fn control_event_for_message(
    message: RecordRoutineIpcControl,
    record_session_id: i64,
) -> Option<ControlEvent> {
    match message {
        RecordRoutineIpcControl::Stop {
            record_session_id: stopped_id,
        } if stopped_id == record_session_id => Some(ControlEvent::Stop),
        RecordRoutineIpcControl::KeepAlive {
            record_session_id: keepalive_id,
        } if keepalive_id == record_session_id => Some(ControlEvent::KeepAlive),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_args_parse_parent_liveness_timeout() {
        let args = HelperArgs::parse([
            "--pipe-name".to_string(),
            r"\\.\pipe\actions".to_string(),
            "--control-pipe-name".to_string(),
            r"\\.\pipe\control".to_string(),
            "--record-session-id".to_string(),
            "42".to_string(),
            "--parent-liveness-timeout-ms".to_string(),
            "12345".to_string(),
        ])
        .expect("parse args");

        assert_eq!(args.pipe_name, r"\\.\pipe\actions");
        assert_eq!(args.control_pipe_name, r"\\.\pipe\control");
        assert_eq!(args.record_session_id, 42);
        assert_eq!(args.parent_liveness_timeout_ms, 12_345);
    }

    #[test]
    fn helper_args_require_positive_parent_liveness_timeout() {
        let error = HelperArgs::parse([
            "--pipe-name".to_string(),
            r"\\.\pipe\actions".to_string(),
            "--control-pipe-name".to_string(),
            r"\\.\pipe\control".to_string(),
            "--record-session-id".to_string(),
            "42".to_string(),
            "--parent-liveness-timeout-ms".to_string(),
            "0".to_string(),
        ])
        .expect_err("parent liveness timeout must be positive");

        assert!(error.contains("--parent-liveness-timeout-ms must be positive"));
    }

    #[test]
    fn control_event_ignores_wrong_session_stop() {
        assert_eq!(
            control_event_for_message(
                RecordRoutineIpcControl::Stop {
                    record_session_id: 99
                },
                42
            ),
            None
        );
        assert_eq!(
            control_event_for_message(
                RecordRoutineIpcControl::Stop {
                    record_session_id: 42
                },
                42
            ),
            Some(ControlEvent::Stop)
        );
    }

    #[test]
    fn control_event_keeps_alive_only_for_matching_session() {
        assert_eq!(
            control_event_for_message(
                RecordRoutineIpcControl::KeepAlive {
                    record_session_id: 99
                },
                42
            ),
            None
        );
        assert_eq!(
            control_event_for_message(
                RecordRoutineIpcControl::KeepAlive {
                    record_session_id: 42
                },
                42
            ),
            Some(ControlEvent::KeepAlive)
        );
        assert!(!ControlEvent::KeepAlive.should_stop());
    }

    #[test]
    fn parent_disconnect_is_error_self_stop() {
        assert!(ControlEvent::ParentDisconnected.should_stop());
        assert_eq!(
            ControlEvent::ParentDisconnected.stop_reason(),
            RecordStopReason::Error
        );
    }
}
