//! The log half of the DASH-04 unified health story: classify Gilbreth's
//! rotated logs into the same categories `scripts/review_run.py` prints
//! (known warnings, unknown warnings, errors/panics, writer skips), scoped
//! to the same event time window, so the native Diagnostics tab and the
//! script can never disagree about a REVIEW. Counts only — no log content
//! leaves this function.

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

/// review_run.py's `LogSummary` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogReviewSummary {
    pub files: usize,
    pub warning_lines: i64,
    pub error_panic_lines: i64,
    pub clipboard_locked_warning_lines: i64,
    pub orphan_session_repair_warning_lines: i64,
    pub stale_pre_erase_drop_warning_lines: i64,
    pub recovered_focus_warning_lines: i64,
    pub max_events_skipped: i64,
}

// The verdict methods mirror review_run.py for the tests here; the
// dashboard consumes the raw counts through its own boundary twin.
#[allow(dead_code)]
impl LogReviewSummary {
    pub fn unknown_warning_lines(&self) -> i64 {
        (self.warning_lines
            - self.clipboard_locked_warning_lines
            - self.orphan_session_repair_warning_lines
            - self.stale_pre_erase_drop_warning_lines
            - self.recovered_focus_warning_lines)
            .max(0)
    }

    pub fn healthy(&self) -> bool {
        self.unknown_warning_lines() == 0
            && self.error_panic_lines == 0
            && self.max_events_skipped == 0
    }
}

fn warning_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bWARN\b").expect("warning pattern compiles"))
}

fn error_or_panic_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bERROR\b|panic").expect("error pattern compiles"))
}

fn clipboard_locked_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)clipboard changed but metadata was unavailable; clipboard is locked")
            .expect("clipboard pattern compiles")
    })
}

fn orphan_repair_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)previous session\(s\) ended without graceful stop")
            .expect("orphan pattern compiles")
    })
}

fn stale_pre_erase_drop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)dropped stale pre-erase capture row")
            .expect("stale pre-erase drop pattern compiles")
    })
}

fn recovered_focus_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)recovered an open focus segment from an ungraceful shutdown")
            .expect("recovered focus pattern compiles")
    })
}

fn events_skipped_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)events_skipped[=:\s]+(\d+)").expect("skip pattern compiles"))
}

fn timestamp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\b",
        )
        .expect("timestamp pattern compiles")
    })
}

/// review_run.py's `_log_line_in_window`: untimestamped (or unparseable)
/// lines always count; timestamped lines are scoped to the event span.
fn line_in_window(line: &str, since_ms: Option<i64>, until_ms: Option<i64>) -> bool {
    if since_ms.is_none() && until_ms.is_none() {
        return true;
    }
    let Some(timestamp_ms) = leading_rfc3339_ms(line) else {
        return true;
    };
    if let Some(since) = since_ms {
        if timestamp_ms < since {
            return false;
        }
    }
    if let Some(until) = until_ms {
        if timestamp_ms > until {
            return false;
        }
    }
    true
}

fn leading_rfc3339_ms(line: &str) -> Option<i64> {
    let captures = timestamp_re().captures(line)?;
    let timestamp = captures.name("timestamp")?.as_str();
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|parsed| parsed.timestamp_millis())
}

pub fn classify_line(line: &str, summary: &mut LogReviewSummary) {
    if warning_re().is_match(line) {
        summary.warning_lines += 1;
        if clipboard_locked_re().is_match(line) {
            summary.clipboard_locked_warning_lines += 1;
        }
        if orphan_repair_re().is_match(line) {
            summary.orphan_session_repair_warning_lines += 1;
        }
        if stale_pre_erase_drop_re().is_match(line) {
            summary.stale_pre_erase_drop_warning_lines += 1;
        }
        if recovered_focus_re().is_match(line) {
            summary.recovered_focus_warning_lines += 1;
        }
    }
    if error_or_panic_re().is_match(line) {
        summary.error_panic_lines += 1;
    }
    for captures in events_skipped_re().captures_iter(line) {
        if let Some(skipped) = captures.get(1).and_then(|m| m.as_str().parse::<i64>().ok()) {
            summary.max_events_skipped = summary.max_events_skipped.max(skipped);
        }
    }
}

/// The rotated-log prefix, matched ASCII-case-insensitively:
/// review_run.py's `Path.glob("gilbreth.log*")` is case-insensitive on
/// Windows, so a renamed `GILBRETH.LOG.OLD` still carries its errors into
/// the verdict on both sides.
///
/// Documented bound (2026-07-10 re-review SF-1): the contract is an ASCII
/// filename grammar. Python's glob additionally folds non-ASCII case pairs
/// (e.g. U+0130/U+0131 over the `i`) and accepts ill-formed UTF-16 names
/// that `to_str()` rejects here; producing such a name takes a deliberate
/// noncanonical rename — the logger's rotation and ordinary Windows
/// renames never leave ASCII.
const LOG_NAME_PREFIX: &[u8] = b"gilbreth.log";

fn is_log_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= LOG_NAME_PREFIX.len()
        && bytes[..LOG_NAME_PREFIX.len()].eq_ignore_ascii_case(LOG_NAME_PREFIX)
}

/// review_run.py's `review_logs`: every `gilbreth.log*` file in the logs
/// directory, classified line by line; an unreadable file counts as an
/// error line rather than silently vanishing from the verdict.
pub fn review_logs(
    logs_dir: &Path,
    since_ms: Option<i64>,
    until_ms: Option<i64>,
) -> LogReviewSummary {
    let mut summary = LogReviewSummary::default();
    let Ok(entries) = std::fs::read_dir(logs_dir) else {
        return summary;
    };
    let mut files: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_log_file_name)
        })
        .collect();
    files.sort();
    summary.files = files.len();
    for path in files {
        match std::fs::read(&path) {
            Ok(bytes) => {
                // errors="replace" semantics: undecodable bytes never stop
                // the review.
                let text = String::from_utf8_lossy(&bytes);
                for line in text.lines() {
                    if !line_in_window(line, since_ms, until_ms) {
                        continue;
                    }
                    classify_line(line, &mut summary);
                }
            }
            Err(_) => summary.error_panic_lines += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_mirrors_review_run_patterns() {
        let mut summary = LogReviewSummary::default();
        // Word boundaries: WARN counts, WARNING does not double-classify a
        // non-WARN token; "panicked" matches (no boundary on panic).
        classify_line(
            "2026-07-09T10:00:00Z  WARN gilbreth_app: something odd",
            &mut summary,
        );
        classify_line("this line has UNWARNED text only", &mut summary);
        classify_line("thread 'main' panicked at src/main.rs:1", &mut summary);
        classify_line(
            "2026-07-09T10:01:00Z ERROR gilbreth_store: broke",
            &mut summary,
        );
        classify_line(
            "2026-07-09T10:02:00Z  WARN clipboard changed but metadata was unavailable; \
             clipboard is locked",
            &mut summary,
        );
        classify_line(
            "2026-07-09T10:03:00Z  WARN gilbreth_store: previous session(s) ended without \
             graceful stop orphan_sessions_finalized=1",
            &mut summary,
        );
        classify_line("writer report events_skipped=3 batches=2", &mut summary);
        classify_line("writer report events_skipped=9", &mut summary);
        classify_line(
            "2026-07-09T10:04:00Z WARN gilbreth_store: dropped stale pre-erase capture row",
            &mut summary,
        );
        classify_line(
            "2026-07-28T10:05:00Z WARN gilbreth_store: recovered an open focus segment \
             from an ungraceful shutdown session_id=1 recovered_ms=30000",
            &mut summary,
        );

        assert_eq!(summary.warning_lines, 5);
        assert_eq!(summary.clipboard_locked_warning_lines, 1);
        assert_eq!(summary.orphan_session_repair_warning_lines, 1);
        assert_eq!(summary.stale_pre_erase_drop_warning_lines, 1);
        assert_eq!(summary.recovered_focus_warning_lines, 1);
        assert_eq!(summary.unknown_warning_lines(), 1);
        assert_eq!(summary.error_panic_lines, 2);
        assert_eq!(summary.max_events_skipped, 9);
        assert!(!summary.healthy());
    }

    #[test]
    fn known_warnings_alone_stay_healthy() {
        let mut summary = LogReviewSummary::default();
        classify_line(
            "2026-07-09T10:03:00Z  WARN gilbreth_store: previous session(s) ended without \
             graceful stop orphan_sessions_finalized=1",
            &mut summary,
        );
        assert_eq!(summary.unknown_warning_lines(), 0);
        assert!(summary.healthy());
    }

    #[test]
    fn window_scoping_keeps_untimestamped_lines() {
        // Timestamped lines outside the event span are skipped; lines with
        // no leading timestamp always count (review_run parity).
        assert!(line_in_window("no timestamp WARN here", Some(0), Some(1)));
        let early = "2026-07-09T10:00:00Z  WARN early";
        let ms = leading_rfc3339_ms(early).expect("parses");
        assert!(!line_in_window(early, Some(ms + 1), None));
        assert!(line_in_window(early, Some(ms), Some(ms)));
        assert!(!line_in_window(early, None, Some(ms - 1)));
        // Fractional seconds and explicit offsets both parse.
        assert!(leading_rfc3339_ms("2026-07-09T10:00:00.123456Z rest").is_some());
        assert!(leading_rfc3339_ms("2026-07-09T10:00:00+02:00 rest").is_some());
        assert!(leading_rfc3339_ms("not a timestamp").is_none());
    }

    #[test]
    fn log_name_matching_is_case_insensitive_like_windows_glob() {
        // B2 (2026-07-09 S4 review): a rotated GILBRETH.LOG.OLD is a valid
        // Windows rename and must not fall out of the verdict.
        assert!(is_log_file_name("gilbreth.log"));
        assert!(is_log_file_name("gilbreth.log.2026-07-08"));
        assert!(is_log_file_name("GILBRETH.LOG.OLD"));
        assert!(is_log_file_name("Gilbreth.Log.1"));
        assert!(!is_log_file_name("gilbreth.lo"));
        assert!(!is_log_file_name("other.log"));
        assert!(!is_log_file_name("agilbreth.log"));
    }

    #[test]
    fn review_logs_reads_rotated_files_from_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join("gilbreth.log.2026-07-08"),
            "2026-07-08T10:00:00Z  WARN old unknown warning\n",
        )
        .expect("old log");
        std::fs::write(dir.path().join("GILBRETH.LOG.OLD"), "ERROR renamed log\n")
            .expect("renamed log");
        std::fs::write(
            dir.path().join("gilbreth.log.2026-07-09"),
            "2026-07-09T10:00:00Z  INFO fine\nevents_skipped=2 in report\n",
        )
        .expect("new log");
        std::fs::write(dir.path().join("unrelated.txt"), "ERROR ignored\n").expect("other file");

        let all = review_logs(dir.path(), None, None);
        assert_eq!(all.files, 3);
        assert_eq!(all.warning_lines, 1);
        assert_eq!(all.error_panic_lines, 1);
        assert_eq!(all.max_events_skipped, 2);

        // Scoping to a window after the old file's line drops that warning
        // but keeps the untimestamped skip and renamed-log error lines.
        let since = leading_rfc3339_ms("2026-07-09T00:00:00Z x").expect("parses");
        let scoped = review_logs(dir.path(), Some(since), None);
        assert_eq!(scoped.warning_lines, 0);
        assert_eq!(scoped.error_panic_lines, 1);
        assert_eq!(scoped.max_events_skipped, 2);

        let missing = review_logs(&dir.path().join("nope"), None, None);
        assert_eq!(missing, LogReviewSummary::default());
    }
}
