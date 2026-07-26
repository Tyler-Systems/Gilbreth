//! Dev-only probe for the DASH-04 log classifier: print `review_logs`
//! counts and the derived verdict as JSON so the pytest gate can compare
//! them with `scripts/review_run.py` over the same corpus. Never shipped
//! or launched by the app; it exists for the cross-language differential
//! test (B2, 2026-07-09 S4 review).

// The classifier is a module of the gilbreth-app binary, not a library;
// compile the same source into this probe so both targets share one
// implementation.
#[path = "../health.rs"]
mod health;

use std::path::Path;

fn parse_window_arg(value: &str) -> Option<i64> {
    if value == "-" {
        None
    } else {
        Some(
            value
                .parse::<i64>()
                .expect("window bound is milliseconds or '-'"),
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [logs_dir, since, until] = args.as_slice() else {
        eprintln!("usage: gilbreth-health-dump <logs_dir> <since_ms|-> <until_ms|->");
        std::process::exit(2);
    };
    let summary = health::review_logs(
        Path::new(logs_dir),
        parse_window_arg(since),
        parse_window_arg(until),
    );
    println!(
        "{}",
        serde_json::json!({
            "files": summary.files,
            "warning_lines": summary.warning_lines,
            "error_panic_lines": summary.error_panic_lines,
            "clipboard_locked_warning_lines": summary.clipboard_locked_warning_lines,
            "orphan_session_repair_warning_lines": summary.orphan_session_repair_warning_lines,
            "stale_pre_erase_drop_warning_lines": summary.stale_pre_erase_drop_warning_lines,
            "max_events_skipped": summary.max_events_skipped,
            "unknown_warning_lines": summary.unknown_warning_lines(),
            "healthy": summary.healthy(),
        })
    );
}
