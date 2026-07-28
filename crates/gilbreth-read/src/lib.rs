//! Read-time analytics over the Gilbreth SQLite contract.
//!
//! This crate owns the shipping reader implementation used by the native
//! Rust/egui dashboard. It originated as the S2 function-by-function port of
//! the former Python reader, with field-identical parity used to bind rounding,
//! tie-breaking, and edge-case behavior before retirement. That Python oracle
//! and its parity harness have since been retired and are not part of this
//! repository; current behavior and deliberate changes are specified and
//! tested in Rust here.

mod python_3_12;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use icu_casemap::CaseMapper;
use python_3_12::is_python_3_12_alpha;
use regex::Regex;
use rusqlite::types::{Type, Value};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Mirrors `EPISODE_GAP_MS`: a >5 min gap between focus events starts a new
/// episode (O-3.2b).
pub const EPISODE_GAP_MS: i64 = 300_000;

/// Mirrors `TODAY_RUN_MERGE_GAP_MS`: today-story runs merge across gaps of
/// up to two seconds.
pub const TODAY_RUN_MERGE_GAP_MS: i64 = 2_000;

const DAY_MS: i64 = 86_400_000;
const TOP_N_ANALYTICS: usize = 25;
const WINDOW_ORIGIN_OBSERVED: &str = "observed";
const MIN_SWITCH_DWELL_MS: i64 = 15_000;
const SWITCH_RATE_MIN_ACTIVE_MS: i64 = 300_000;
const DIGEST_TOP_APPS: usize = 5;
const DIGEST_FRICTION_LIMIT: usize = 3;
const DIGEST_CHANGE_MIN_OCCURRENCES: i64 = 8;
const DIGEST_CHANGE_MIN_DAYS_NEW: usize = 2;
const DIGEST_CHANGE_MIN_DAYS_FADED: usize = 3;
const DIGEST_CHANGE_MIN_HISTORY_DAYS: i64 = 14;
const DIGEST_CHANGE_BASELINE_DAYS: i64 = 21;
const DIGEST_CHANGE_LIMIT: usize = 3;
const MORNING_WINDOW_MS: i64 = 10 * 60 * 1000;
const FIRST_AFTER_IDLE_TOP: usize = 3;
const RHYTHM_WEEKDAY_LABELS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const DISCOVERY_BASELINE_MIN_SAMPLES: usize = 3;
const DISCOVERY_BASELINE_DAYS: i64 = 14;
const DISCOVERY_NOTICE_LIMIT: usize = 3;
const DISCOVERY_NOTICE_EVIDENCE_LIMIT: usize = 5;
const RETURN_TOLL_EVIDENCE_LIMIT: usize = 5;
const RETURN_TOLL_NOTICE_MIN_MEASURED_RETURNS: usize = RESUMPTION_LAG_MIN_SAMPLES;
const DISCOVERY_NOTICE_TYPE_RETURN_TOLL: &str = "return_toll";
const DISCOVERY_NOTICE_TYPE_INPUT_DENSE: &str = "input_dense_span";
const DISCOVERY_NOTICE_TYPE_SEQUENCE: &str = "recurring_sequence";
const DISCOVERY_NOTICE_TYPE_CLIPBOARD: &str = "clipboard_bridge";
const DISCOVERY_NOTICE_TYPE_EPISODE_FRAGMENTATION: &str = "episode_fragmentation";
const DISCOVERY_NOTICE_TYPE_RAMP: &str = "return_ramp";
const DISCOVERY_NOTICE_TYPE_TIME_ANCHOR: &str = "time_anchor";
const DISCOVERY_NOTICE_TYPE_NOTIFICATION_ADJACENT: &str = "notification_adjacent";

// Discovery-notice and pattern-card static copy, pinned as constants so
// the copy-style audit sees it (Lane B final enforcement audit,
// docs/MAINTAINING.md). Interpolated titles/summaries
// stay inline beside their data; the kittest scenes freeze their
// rendered forms.
const NOTICE_DETAIL_RETURN_TOLL: &str =
    "Evidence rows show timing, app basenames, and durations only.";
const NOTICE_DETAIL_NOTIFICATION_ADJACENT: &str = "Evidence rows show notification receipt \
     timing, source app, switch timing, away duration, and restart duration only.";
const NOTICE_DETAIL_INPUT_DENSE: &str =
    "Evidence rows show timing, app basenames, durations, and input-event counts only.";
const NOTICE_DETAIL_EPISODE_FRAGMENTATION: &str = "Evidence rows show episode timing, app \
     composition, active duration, switches, and switch density only.";
const NOTICE_DETAIL_SEQUENCE: &str =
    "Evidence rows show timing, app basenames, and sequence duration only.";
const NOTICE_DETAIL_CLIPBOARD: &str =
    "Evidence rows show timing, app basenames, handoff duration, and size class only.";
const NOTICE_DETAIL_RAMP: &str = "Evidence rows show the return point, app basenames, ramp \
     duration, and switch count only.";
const NOTICE_DETAIL_TIME_ANCHOR: &str =
    "Evidence rows show the hour window, signal name, timing, and rate/count only.";
const CARD_TITLE_INPUT_STRETCHES: &str = "You often work in long stretches without a break";
const CARD_WHY_SWITCHING: &str = "Frequent short focus transitions can indicate context switching.";
const CARD_NEXT_SWITCHING: &str = "Consider whether this handoff is intentional or could be \
     simplified with layout, shortcuts, or a consolidated workflow.";
const CARD_WHY_SHORT_LIVED: &str = "Repeated short-lived windows can point to lookup, launch, \
     or setup friction, but closed-window data is left-censored.";
const CARD_NEXT_SHORT_LIVED: &str = "Consider whether these windows are part of a deliberate \
     task or could be reduced with pinned views, templates, or shortcuts.";
const CARD_WHY_SEQUENCE: &str =
    "A recurring multi-step app sequence often marks a routine worth streamlining.";
// Record Routine is Windows-only by decision record, so the macOS cards must
// not point at a tray action that does not exist there. The observation and
// the suggestion are identical; only the recording sentence is Windows-only.
#[cfg(windows)]
const CARD_NEXT_SEQUENCE: &str = "Review whether this sequence could be shortened or batched. \
     Use \"Ask tray to record this routine\" to capture the exact steps for deeper analysis.";
#[cfg(not(windows))]
const CARD_NEXT_SEQUENCE: &str = "Review whether this sequence could be shortened or batched.";
const CARD_WHY_RETURNS: &str = "Frequently switching away from a primary app and back can mark \
     app-focus context-switching cost, not necessarily something to automate.";
const CARD_NEXT_RETURNS: &str = "Consider whether these interruptions are necessary, or could \
     be batched, pinned, or consolidated to protect focus.";
const CARD_WHY_INPUT_STRETCHES: &str = "Long unbroken input stretches are an exposure pattern \
     that ergonomics research links to more discomfort across groups -- an observation, not a \
     medical assessment. Short recovery breaks are commonly suggested.";
const CARD_NEXT_INPUT_STRETCHES: &str =
    "Consider short breaks roughly every 20-30 min during long input stretches.";
const CARD_WHY_CLIPBOARD: &str =
    "Repeated cross-app copying often marks a transfer routine worth streamlining.";
#[cfg(windows)]
const CARD_NEXT_CLIPBOARD: &str = "Review whether this transfer could be batched or shortened. \
     Use \"Ask tray to record this routine\" to capture the exact steps.";
#[cfg(not(windows))]
const CARD_NEXT_CLIPBOARD: &str = "Review whether this transfer could be batched or shortened.";
const SEQUENCE_MOTIF_MAX_LEN: usize = 5;
const SEQUENCE_MIN_SUPPORT: i64 = 8;
const SEQUENCE_MIN_DAYS: usize = 2;
const SEQUENCE_MIN_HISTORY_DAYS: usize = 2;
const SEQUENCE_TIGHTNESS_MAX_MS: f64 = 120_000.0;
const MOTIF_TRACKING_CAP: usize = 50_000;
const FRAGMENTATION_MIN_ROUNDTRIPS: i64 = 8;
const CANDIDATE_KIND_ROUTINE: &str = "automatable_routine";
const CANDIDATE_KIND_FRAGMENTATION: &str = "fragmentation";
const CANDIDATE_KIND_INPUT_EXPOSURE: &str = "input_exposure";
const CANDIDATE_CATEGORY_CLIPBOARD: &str = "clipboard_transfer";
const CLIPBOARD_BRACKET_MS: i64 = 60_000;
const CLIPBOARD_TRANSFER_MIN_SUPPORT: usize = 6;
const CLIPBOARD_TOP_DAY_SHARE_MAX: f64 = 0.6;
const CATEGORY_SLOT_CAP: usize = 6;
const HIGH_BAND_DAYS_FRACTION: f64 = 0.25;
const PATTERN_DISPLAY_LIMIT: usize = 6;
const TIME_ANCHOR_MIN_DAYS: usize = 3;
const INPUT_EXPOSURE_BREAK_TARGET_MS: i64 = 1_200_000;
const INPUT_DENSE_NOTICE_MIN_MS: i64 = INPUT_EXPOSURE_BREAK_TARGET_MS;
const INPUT_EXPOSURE_LONG_RUN_MS: i64 = 2_700_000;
const INPUT_EXPOSURE_MIN_LONG_RUNS: usize = 4;
const INPUT_EXPOSURE_RATE_MIN_ACTIVE_MS: i64 = 300_000;
const INPUT_EXPOSURE_DAY_ELEVATED_MS: f64 = 14_400_000.0;
const INPUT_EXPOSURE_DAY_HIGH_MS: f64 = 21_600_000.0;
const EPISODE_FRAGMENTATION_MIN_ACTIVE_MS: i64 = 10 * 60_000;
const EPISODE_FRAGMENTATION_MIN_SWITCHES: i64 = 8;
const EPISODE_FRAGMENTATION_MIN_SWITCHES_PER_HOUR: f64 = 20.0;
const RESUMPTION_LAG_MIN_SAMPLES: usize = 3;
const INTERRUPTION_PAIR_MIN_ROUNDTRIPS: i64 = 3;
const INTERRUPTION_PAIR_LIMIT: usize = 10;
const RAMP_SUSTAINED_FOCUS_MS: i64 = 5 * 60_000;
const RAMP_NOTICE_MIN_MS: i64 = 5 * 60_000;
const RAMP_NOTICE_MIN_SWITCHES: i64 = 3;
const NOTIFICATION_ADJACENT_MAX_SWITCH_MS: i64 = 5 * 60_000;
const NOTIFICATION_ADJACENT_MIN_MATCHES: i64 = 3;
const NOTIFICATION_ADJACENT_MIN_DAYS: usize = 7;
const TYPING_BURST_GAP_MS: i64 = 2_000;
const TYPING_BURST_MIN_CHARS: i64 = 5;
const WPM_CHARS_PER_WORD: f64 = 5.0;
const SPHERE_ROLLUP_MIN_EPISODES: i64 = 2;
const SPHERE_ONE_OFF_LABEL: &str = "(one-off spheres)";
const RECORDING_EXPORT_SCHEMA: &str = "gilbreth.replay_export.v1";
const RECORDING_EXPORT_SCHEMA_VERSION: &str = "1.1";
pub const REPLAY_EXPORT_MODE_AGENT_GROUNDED: &str = "agent_grounded";
pub const REPLAY_EXPORT_MODE_NATIVE_SKELETON: &str = "native_skeleton";
const ACTIONABLE_NATIVE_THRESHOLD: f64 = 0.9;
const ACTIONABLE_MIN_FLOOR: i64 = 2;
const REPLAY_CLASS_ELIGIBLE: &str = "eligible";
const REPLAY_CLASS_PROVISIONAL: &str = "provisional_eligible";
const REPLAY_CLASS_NATIVE_GAP: &str = "native_gap";
const EXCLUDED_APP_GAP_PATTERN: &str = "excluded_app_gap";
pub const EXCLUDED_APP_GAP_LABEL: &str = "Steps in an excluded app were not recorded.";
const REPLAY_CLASS_HARD_VETO: &str = "agent_grounded_hard_veto";
const REPLAY_CLASS_FREE_INPUT: &str = "free_input";
const REPLAY_CLASS_NOISE: &str = "noise";
const REPLAY_VERDICT_VERIFIED: &str = "verified_replay_eligible";
const REPLAY_VERDICT_UNVERIFIED: &str = "unverified_replay_eligible";
const REPLAY_VERDICT_PROVISIONAL: &str = "provisional_replay_eligible";
const REPLAY_VERDICT_AGENT_ONLY: &str = "agent_grounded_only";
pub const REPLAY_EXPORT_REVIEW_LABEL_MAX_CHARS: usize = 120;
const MAX_REPLAY_EXPORT_SELECTOR_IDENTIFIER_CHARS: usize = 256;
const REPLAY_EXPORT_SELECTOR_BACKENDS: [&str; 23] = [
    "cef",
    "chrome",
    "chromium",
    "citrix",
    "directui",
    "edge",
    "electron",
    "firefox",
    "mshtml",
    "qt",
    "qt5",
    "qt6",
    "rdp",
    "remote",
    "uia",
    "unknown",
    "vnc",
    "vmware",
    "webview2",
    "windowsforms",
    "win32",
    "wpf",
    "xaml",
];

/// The analytics scope filter. Mirrors the filtering fields of Python's
/// `AnalyticsScope` (`key`/`label` are presentation-only and stay UI-side).
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub cutoff_ms: Option<i64>,
    pub session_id: Option<i64>,
}

/// Mirrors `_scope_predicate`: a WHERE fragment plus its positional params.
pub fn scope_predicate(alias: &str, scope: &Scope) -> (String, Vec<i64>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<i64> = Vec::new();
    if let Some(cutoff) = scope.cutoff_ms {
        clauses.push(format!("{alias}.ts >= ?"));
        params.push(cutoff);
    }
    if let Some(session_id) = scope.session_id {
        clauses.push(format!("{alias}.session_id = ?"));
        params.push(session_id);
    }
    if clauses.is_empty() {
        return ("1 = 1".to_string(), params);
    }
    (clauses.join(" AND "), params)
}

pub fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    Ok(conn)
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    let mut stmt =
        conn.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1")?;
    let mut rows = stmt.query([table])?;
    Ok(rows.next()?.is_some())
}

fn table_columns(conn: &Connection, table: &str) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    let mut columns = HashSet::new();
    while let Some(row) = rows.next()? {
        columns.insert(row.get::<_, String>(1)?);
    }
    Ok(columns)
}

/// Mirrors `INPUT_KINDS`.
const INPUT_KINDS: [&str; 4] = ["key", "mouse_click", "mouse_move", "mouse_wheel"];

/// Mirrors `_input_sweep_predicate`: all key rows; non-relay mouse rows
/// (relay/software-KVM is not local exposure).
fn input_sweep_predicate(alias: &str) -> String {
    let origin = format!("COALESCE(json_extract({alias}.payload, '$.input_origin'), 'local')");
    let kinds = INPUT_KINDS
        .iter()
        .map(|kind| format!("'{kind}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{alias}.kind IN ({kinds}) AND ({alias}.kind = 'key' OR {origin} != 'remote_relay_suspected')"
    )
}

/// One completed foreground dwell, exactly as `_read_focus_intervals`
/// reports it (a `focus_changed` row carries the *previous* app's dwell).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FocusInterval {
    pub exe: String,
    pub title: String,
    pub session_id: i64,
    pub seq: i64,
    pub local_date: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub duration_ms: i64,
}

/// Mirrors `_read_focus_intervals`, including the post-query cutoff clip:
/// under a cutoff scope every row's start is clamped to the cutoff, every
/// duration is recomputed from the clamped bounds, and non-positive
/// durations are dropped.
pub fn focus_intervals(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<FocusInterval>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT
            COALESCE(NULLIF(e.prev_exe, ''), '(unknown)') AS exe,
            COALESCE(e.prev_title, '') AS title,
            e.session_id,
            e.seq,
            date(e.ts / 1000, 'unixepoch', 'localtime') AS local_date,
            MAX(e.ts - COALESCE(e.duration_ms, 0), 0) AS start_ts,
            e.ts AS end_ts,
            COALESCE(e.duration_ms, 0) AS duration_ms
        FROM events e
        WHERE e.kind = 'focus_changed'
          AND e.prev_exe IS NOT NULL
          AND e.duration_ms IS NOT NULL
          AND {where_clause}
        ORDER BY e.session_id, e.seq"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut out: Vec<FocusInterval> = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(FocusInterval {
            exe: row.get(0)?,
            title: row.get(1)?,
            session_id: row.get(2)?,
            seq: row.get(3)?,
            local_date: row.get(4)?,
            start_ts: row.get(5)?,
            end_ts: row.get(6)?,
            duration_ms: row.get(7)?,
        });
    }
    if let Some(cutoff) = scope.cutoff_ms {
        out.retain_mut(|interval| {
            if interval.start_ts < cutoff {
                interval.start_ts = cutoff;
            }
            interval.duration_ms = interval.end_ts - interval.start_ts;
            interval.duration_ms > 0
        });
    }
    Ok(out)
}

/// Mirrors `display_app`: basename an executable path for display.
pub fn display_app(exe: Option<&str>) -> String {
    let Some(exe) = exe else {
        return "(unknown)".to_string();
    };
    let value = exe.trim();
    if value.is_empty() || value == "(unknown)" {
        return "(unknown)".to_string();
    }
    let normalized = value.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    if last.is_empty() {
        value.to_string()
    } else {
        last.to_string()
    }
}

/// Mirrors `_percentile`: nearest-rank on a copy-sorted list, 0.0 when empty.
/// The arithmetic (`pct / 100 * len`, then ceil) is kept in the Python
/// operation order so float edge cases resolve identically.
pub fn percentile_nearest_rank(values: &[f64], pct: f64) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.total_cmp(b));
    if ordered.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0 * ordered.len() as f64).ceil() as usize).max(1);
    ordered[rank.min(ordered.len()) - 1]
}

/// Mirrors `_coalesce_spans`: merge overlapping/touching `[start, end]`
/// spans after a plain tuple sort.
pub fn coalesce_spans(mut spans: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    spans.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// The local date of a timestamp, resolving DST-ambiguous instants with
/// `fold=0` exactly as Python's `datetime.fromtimestamp` does.
fn local_date_of(ts_ms: i64) -> chrono::NaiveDate {
    use chrono::{Local, LocalResult, TimeZone};
    match Local.timestamp_millis_opt(ts_ms) {
        LocalResult::Single(dt) => dt.date_naive(),
        LocalResult::Ambiguous(first, _) => first.date_naive(),
        LocalResult::None => unreachable!("a UTC instant always maps to local time"),
    }
}

/// Local midnight of a calendar date. Python resolves DST-ambiguous and
/// DST-nonexistent midnights with `fold=0` (the pre-transition UTC offset);
/// both branches below reproduce that choice.
fn local_midnight_ms(date: chrono::NaiveDate) -> i64 {
    use chrono::NaiveTime;

    local_naive_datetime_ms(date.and_time(NaiveTime::MIN))
}

fn local_naive_datetime_ms(naive: chrono::NaiveDateTime) -> i64 {
    use chrono::{Local, LocalResult, TimeZone};

    match Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => dt.timestamp_millis(),
        LocalResult::Ambiguous(first, _) => first.timestamp_millis(),
        LocalResult::None => {
            // `fold=0` interprets a nonexistent wall time with the offset in
            // force immediately before the gap. Derive that offset instead of
            // assuming every transition skips exactly one hour (some zones
            // use half-hour or whole-day gaps).
            let pre_gap_offset_seconds = pre_gap_offset_seconds_with(naive, |probe| {
                match Local.from_local_datetime(&probe) {
                    LocalResult::Single(dt) => Some(dt.offset().local_minus_utc()),
                    LocalResult::Ambiguous(_, latest) => Some(latest.offset().local_minus_utc()),
                    LocalResult::None => None,
                }
            });
            let offset_ms = i64::from(
                pre_gap_offset_seconds.expect("a valid local time exists before a DST gap"),
            ) * 1_000;
            naive.and_utc().timestamp_millis() - offset_ms
        }
    }
}

fn pre_gap_offset_seconds_with<F>(naive: chrono::NaiveDateTime, mut offset_at: F) -> Option<i32>
where
    F: FnMut(chrono::NaiveDateTime) -> Option<i32>,
{
    let mut probe = naive;
    for _ in 0..=(2 * 24 * 60) {
        probe -= chrono::Duration::minutes(1);
        if let Some(offset) = offset_at(probe) {
            return Some(offset);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalBoundaryCandidates {
    Single(i64),
    Ambiguous(i64, i64),
}

fn local_boundary_candidates(naive: chrono::NaiveDateTime) -> LocalBoundaryCandidates {
    use chrono::{Local, LocalResult, TimeZone};

    match Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => LocalBoundaryCandidates::Single(dt.timestamp_millis()),
        LocalResult::Ambiguous(first, second) => {
            LocalBoundaryCandidates::Ambiguous(first.timestamp_millis(), second.timestamp_millis())
        }
        LocalResult::None => LocalBoundaryCandidates::Single(local_naive_datetime_ms(naive)),
    }
}

fn ambiguous_candidate_after(first_ms: i64, second_ms: i64, cursor_ms: i64) -> i64 {
    let (earlier_ms, later_ms) = if first_ms <= second_ms {
        (first_ms, second_ms)
    } else {
        (second_ms, first_ms)
    };
    if earlier_ms > cursor_ms {
        earlier_ms
    } else {
        later_ms
    }
}

/// Mirrors `local_day_start_ms`: local midnight of the timestamp's local
/// date, with `fold=0` DST resolution on both the date and the midnight.
pub fn local_day_start_ms(now_ms: i64) -> i64 {
    local_midnight_ms(local_date_of(now_ms))
}

/// Mirrors `_local_date`: the local calendar date of a timestamp.
pub fn local_date(ts_ms: i64) -> String {
    local_date_of(ts_ms).format("%Y-%m-%d").to_string()
}

fn local_hour(ts_ms: i64) -> i64 {
    use chrono::{Local, LocalResult, TimeZone, Timelike};

    match Local.timestamp_millis_opt(ts_ms) {
        LocalResult::Single(dt) => dt.hour() as i64,
        LocalResult::Ambiguous(first, _) => first.hour() as i64,
        LocalResult::None => unreachable!("a UTC instant always maps to local time"),
    }
}

/// Mirrors `_notice_duration_text`: humanize a millisecond duration the way
/// notice copy does. Python's `round()` is banker's rounding, hence
/// `round_ties_even`.
pub fn notice_duration_text(value_ms: i64) -> String {
    let rounded = (value_ms as f64 / 1000.0).round_ties_even() as i64;
    let total_seconds = rounded.max(0);
    if total_seconds < 60 {
        return format!("{total_seconds}s");
    }
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    if seconds != 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{minutes}m")
    }
}

/// Mirrors `_payload_int`: an integer payload field, tolerating integral
/// floats and rejecting bools, missing keys, and malformed JSON.
pub fn payload_int(payload: Option<&str>, key: &str) -> Option<i64> {
    let payload = payload?;
    if payload.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    match value.get(key)? {
        serde_json::Value::Bool(_) => None,
        serde_json::Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Some(int)
            } else {
                let float = number.as_f64()?;
                (float.fract() == 0.0).then_some(float as i64)
            }
        }
        _ => None,
    }
}

/// Mirrors `_merge_intervals`: coalesce sorted-by-tuple intervals, merging
/// overlapping or touching spans.
pub fn merge_intervals(mut intervals: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    intervals.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in intervals {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Mirrors `_subtract_intervals`: remove every subtraction span from every
/// interval, preserving the interval iteration order.
pub fn subtract_intervals(
    intervals: Vec<(i64, i64)>,
    subtractions: &[(i64, i64)],
) -> Vec<(i64, i64)> {
    let mut segments = intervals;
    for &(subtract_start, subtract_end) in subtractions {
        let mut next_segments: Vec<(i64, i64)> = Vec::new();
        for (start, end) in segments {
            if subtract_end <= start || subtract_start >= end {
                next_segments.push((start, end));
                continue;
            }
            if subtract_start > start {
                next_segments.push((start, subtract_start.min(end)));
            }
            if subtract_end < end {
                next_segments.push((subtract_end.max(start), end));
            }
        }
        segments = next_segments;
        if segments.is_empty() {
            break;
        }
    }
    segments
}

/// Mirrors `_subtract_spans`: pieces of `[start, end)` not covered by
/// sorted, coalesced blocker spans.
pub fn subtract_spans(start: i64, end: i64, blockers: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut pieces: Vec<(i64, i64)> = Vec::new();
    let mut cursor = start;
    for &(blocker_start, blocker_end) in blockers {
        if blocker_end <= cursor {
            continue;
        }
        if blocker_start >= end {
            break;
        }
        if blocker_start > cursor {
            pieces.push((cursor, blocker_start.min(end)));
        }
        cursor = cursor.max(blocker_end);
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        pieces.push((cursor, end));
    }
    pieces
}

/// One per-session `[start_ts, end_ts]` span (idle or sleep).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionInterval {
    pub session_id: i64,
    pub start_ts: i64,
    pub end_ts: i64,
}

fn normalized_session_ids(session_ids: &[i64]) -> Vec<i64> {
    session_ids
        .iter()
        .copied()
        .collect::<BTreeSet<i64>>()
        .into_iter()
        .collect()
}

fn ended_at_by_session(
    conn: &Connection,
    ids: &[i64],
) -> rusqlite::Result<HashMap<i64, Option<i64>>> {
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql =
        format!("SELECT session_id, ended_at FROM sessions WHERE session_id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(ids.iter()))?;
    let mut ended: HashMap<i64, Option<i64>> = HashMap::new();
    while let Some(row) = rows.next()? {
        ended.insert(row.get(0)?, row.get(1)?);
    }
    Ok(ended)
}

/// Mirrors `_idle_intervals_by_session`: per-session merged `(start, end)`
/// spans, dropping non-positive rows. `BTreeMap` mirrors pandas' groupby key
/// sort.
pub fn intervals_by_session(rows: &[SessionInterval]) -> BTreeMap<i64, Vec<(i64, i64)>> {
    let mut collected: BTreeMap<i64, Vec<(i64, i64)>> = BTreeMap::new();
    for row in rows {
        if row.end_ts > row.start_ts {
            collected
                .entry(row.session_id)
                .or_default()
                .push((row.start_ts, row.end_ts));
        }
    }
    // Sessions whose every row was non-positive still appear (with an empty
    // merged list), exactly as the Python groupby does.
    let mut merged: BTreeMap<i64, Vec<(i64, i64)>> = BTreeMap::new();
    for row in rows {
        merged.entry(row.session_id).or_default();
    }
    for (session_id, spans) in collected {
        merged.insert(session_id, merge_intervals(spans));
    }
    merged
}

/// Mirrors `_subtract_interval_frame`: subtract per-session merged
/// subtraction spans from each interval row, preserving row order.
pub fn subtract_interval_frame(
    intervals: Vec<SessionInterval>,
    subtractions: &[SessionInterval],
) -> Vec<SessionInterval> {
    if intervals.is_empty() || subtractions.is_empty() {
        return intervals;
    }
    let by_session = intervals_by_session(subtractions);
    let mut rows: Vec<SessionInterval> = Vec::new();
    for row in &intervals {
        if row.end_ts <= row.start_ts {
            continue;
        }
        let subs = by_session
            .get(&row.session_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for (start_ts, end_ts) in subtract_intervals(vec![(row.start_ts, row.end_ts)], subs) {
            rows.push(SessionInterval {
                session_id: row.session_id,
                start_ts,
                end_ts,
            });
        }
    }
    rows
}

/// Capture-off intervals used by active/away accounting: power
/// suspend->resume and user `capture_paused`->`capture_resumed` spans both
/// fall back to the session end, then `power_boundary_recovered` gap spans
/// are clamped to the prior suspend. A pause is intentional absence, so it
/// must be subtracted like sleep rather than read as unexplained inactivity.
pub fn sleep_intervals(
    conn: &Connection,
    session_ids: &[i64],
) -> rusqlite::Result<Vec<SessionInterval>> {
    let ids = normalized_session_ids(session_ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ended = ended_at_by_session(conn, &ids)?;
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT session_id, kind, ts, payload FROM events
         WHERE session_id IN ({placeholders})
           AND kind IN (
               'power_suspend', 'power_resume', 'power_boundary_recovered',
               'capture_paused', 'capture_resumed'
           )
         ORDER BY session_id, ts, id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut query = stmt.query(rusqlite::params_from_iter(ids.iter()))?;
    let mut events: Vec<(i64, String, i64, Option<String>)> = Vec::new();
    while let Some(row) = query.next()? {
        events.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
    }
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let mut rows: Vec<SessionInterval> = Vec::new();
    let mut index = 0;
    while index < events.len() {
        let session_id = events[index].0;
        let mut group_end = index;
        while group_end < events.len() && events[group_end].0 == session_id {
            group_end += 1;
        }
        let group = &events[index..group_end];
        index = group_end;

        let suspend_ts: Vec<i64> = group
            .iter()
            .filter(|(_, kind, _, _)| kind == "power_suspend")
            .map(|(_, _, ts, _)| *ts)
            .collect();
        let resume_ts: Vec<i64> = group
            .iter()
            .filter(|(_, kind, _, _)| kind == "power_resume")
            .map(|(_, _, ts, _)| *ts)
            .collect();

        let mut resume_index = 0;
        for &suspend in &suspend_ts {
            while resume_index < resume_ts.len() && resume_ts[resume_index] <= suspend {
                resume_index += 1;
            }
            let end_ts = if resume_index < resume_ts.len() {
                Some(resume_ts[resume_index])
            } else {
                ended.get(&session_id).copied().flatten()
            };
            let Some(end_ts) = end_ts else { continue };
            if end_ts <= suspend {
                continue;
            }
            rows.push(SessionInterval {
                session_id,
                start_ts: suspend,
                end_ts,
            });
        }

        let pause_ts: Vec<i64> = group
            .iter()
            .filter(|(_, kind, _, _)| kind == "capture_paused")
            .map(|(_, _, ts, _)| *ts)
            .collect();
        let capture_resume_ts: Vec<i64> = group
            .iter()
            .filter(|(_, kind, _, _)| kind == "capture_resumed")
            .map(|(_, _, ts, _)| *ts)
            .collect();
        let mut capture_resume_index = 0;
        for &pause in &pause_ts {
            while capture_resume_index < capture_resume_ts.len()
                && capture_resume_ts[capture_resume_index] <= pause
            {
                capture_resume_index += 1;
            }
            let end_ts = if capture_resume_index < capture_resume_ts.len() {
                Some(capture_resume_ts[capture_resume_index])
            } else {
                ended.get(&session_id).copied().flatten()
            };
            let Some(end_ts) = end_ts else { continue };
            if end_ts <= pause {
                continue;
            }
            rows.push(SessionInterval {
                session_id,
                start_ts: pause,
                end_ts,
            });
        }

        let mut prior_suspend_index = 0;
        for (_, kind, recovered_ts, payload) in group {
            if kind != "power_boundary_recovered" {
                continue;
            }
            let recovered_ts = *recovered_ts;
            while prior_suspend_index < suspend_ts.len()
                && suspend_ts[prior_suspend_index] <= recovered_ts
            {
                prior_suspend_index += 1;
            }
            let prior_suspend = if prior_suspend_index > 0 {
                suspend_ts[prior_suspend_index - 1]
            } else {
                0
            };
            let gap_ms = payload_int(payload.as_deref(), "gap_ms").unwrap_or(0);
            let raw_start = if gap_ms > recovered_ts {
                0
            } else {
                // Python's unbounded subtraction can exceed i64 for a
                // hand-edited negative gap. Keep the Rust reader panic-free
                // and saturate at its documented scalar boundary; the
                // resulting inverted sleep span remains a downstream no-op.
                recovered_ts.saturating_sub(gap_ms)
            };
            rows.push(SessionInterval {
                session_id,
                start_ts: raw_start.max(prior_suspend),
                end_ts: recovered_ts,
            });
        }
    }
    Ok(rows)
}

/// Mirrors `_read_idle_intervals`: each `idle` event paired with the next
/// strictly-later `active` event (falling back to the session end), the
/// start reconstructed from the idle duration, scope-filtered and
/// cutoff-clamped, then sleep spans subtracted.
pub fn idle_intervals(
    conn: &Connection,
    session_ids: &[i64],
    scope: Option<&Scope>,
) -> rusqlite::Result<Vec<SessionInterval>> {
    let ids = normalized_session_ids(session_ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ended = ended_at_by_session(conn, &ids)?;
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT session_id, kind, ts, COALESCE(duration_ms, 0) FROM events
         WHERE session_id IN ({placeholders})
           AND kind IN ('idle', 'active')
         ORDER BY session_id, ts, id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut query = stmt.query(rusqlite::params_from_iter(ids.iter()))?;
    let mut events: Vec<(i64, String, i64, i64)> = Vec::new();
    while let Some(row) = query.next()? {
        events.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
    }
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let scope_session_id = scope.and_then(|scope| scope.session_id);
    let scope_cutoff_ms = scope.and_then(|scope| scope.cutoff_ms);
    let mut intervals: Vec<SessionInterval> = Vec::new();
    let mut index = 0;
    while index < events.len() {
        let session_id = events[index].0;
        let mut group_end = index;
        while group_end < events.len() && events[group_end].0 == session_id {
            group_end += 1;
        }
        let group = &events[index..group_end];
        index = group_end;

        let active_ts: Vec<i64> = group
            .iter()
            .filter(|(_, kind, _, _)| kind == "active")
            .map(|(_, _, ts, _)| *ts)
            .collect();
        let mut active_index = 0;
        for (_, kind, idle_ts, duration_ms) in group {
            if kind != "idle" {
                continue;
            }
            let idle_ts = *idle_ts;
            if let Some(scope_session) = scope_session_id {
                if session_id != scope_session {
                    continue;
                }
            }
            while active_index < active_ts.len() && active_ts[active_index] <= idle_ts {
                active_index += 1;
            }
            let end_ts = if active_index < active_ts.len() {
                Some(active_ts[active_index])
            } else {
                ended.get(&session_id).copied().flatten()
            };
            let Some(end_ts) = end_ts else { continue };
            if end_ts <= idle_ts {
                continue;
            }
            let mut start_ts = (idle_ts - duration_ms).max(0);
            if let Some(cutoff) = scope_cutoff_ms {
                start_ts = start_ts.max(cutoff);
            }
            if end_ts <= start_ts {
                continue;
            }
            intervals.push(SessionInterval {
                session_id,
                start_ts,
                end_ts,
            });
        }
    }

    let sleep = sleep_intervals(conn, &ids)?;
    Ok(subtract_interval_frame(intervals, &sleep))
}

/// Mirrors `_away_spans_by_session`: coalesced idle+sleep spans per
/// session, each clipped to `[lo, hi]`. Sessions whose every span clips to
/// nothing are absent, exactly as in Python.
pub fn away_spans_by_session(
    idle: &[SessionInterval],
    sleep: &[SessionInterval],
    lo: i64,
    hi: i64,
) -> BTreeMap<i64, Vec<(i64, i64)>> {
    let mut by_session: BTreeMap<i64, Vec<(i64, i64)>> = BTreeMap::new();
    for frame in [idle, sleep] {
        for row in frame {
            let span_start = row.start_ts.max(lo);
            let span_end = row.end_ts.min(hi);
            if span_end > span_start {
                by_session
                    .entry(row.session_id)
                    .or_default()
                    .push((span_start, span_end));
            }
        }
    }
    by_session
        .into_iter()
        .map(|(session_id, spans)| (session_id, coalesce_spans(spans)))
        .collect()
}

/// A focus interval with its idle/sleep-subtracted active time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveFocusInterval {
    pub exe: String,
    pub title: String,
    pub session_id: i64,
    pub seq: i64,
    pub local_date: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub duration_ms: i64,
    pub active_foreground_ms: i64,
}

/// Mirrors `_add_active_foreground_ms`: subtract per-session merged inactive
/// spans from each focus dwell with a non-rewinding cursor sweep in
/// (session, start) order, writing results back in the original row order.
pub fn add_active_foreground_ms(
    focus: &[FocusInterval],
    inactive: &[SessionInterval],
) -> Vec<ActiveFocusInterval> {
    let mut out: Vec<ActiveFocusInterval> = focus
        .iter()
        .map(|row| ActiveFocusInterval {
            exe: row.exe.clone(),
            title: row.title.clone(),
            session_id: row.session_id,
            seq: row.seq,
            local_date: row.local_date.clone(),
            start_ts: row.start_ts,
            end_ts: row.end_ts,
            duration_ms: row.duration_ms,
            active_foreground_ms: (row.end_ts - row.start_ts).max(0),
        })
        .collect();
    if inactive.is_empty() {
        return out;
    }
    let merged = intervals_by_session(inactive);
    let mut order: Vec<usize> = (0..out.len()).collect();
    order.sort_by_key(|&index| (out[index].session_id, out[index].start_ts));
    let mut cursor: HashMap<i64, usize> = HashMap::new();
    for &index in &order {
        let session_id = out[index].session_id;
        let focus_start = out[index].start_ts;
        let focus_end = out[index].end_ts;
        let focus_ms = (focus_end - focus_start).max(0);
        let intervals = merged.get(&session_id).map(Vec::as_slice).unwrap_or(&[]);
        let mut position = cursor.get(&session_id).copied().unwrap_or(0);
        while position < intervals.len() && intervals[position].1 <= focus_start {
            position += 1;
        }
        cursor.insert(session_id, position);
        let mut idle_overlap = 0i64;
        let mut scan = position;
        while scan < intervals.len() && intervals[scan].0 < focus_end {
            let (idle_start, idle_end) = intervals[scan];
            idle_overlap += (focus_end.min(idle_end) - focus_start.max(idle_start)).max(0);
            scan += 1;
        }
        out[index].active_foreground_ms = (focus_ms - idle_overlap).max(0);
    }
    out
}

/// Mirrors `_read_focus_intervals_with_active`.
pub fn focus_intervals_with_active(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<ActiveFocusInterval>> {
    let focus = focus_intervals(conn, scope)?;
    if focus.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = focus.iter().map(|row| row.session_id).collect();
    let mut inactive = idle_intervals(conn, &ids, None)?;
    inactive.extend(sleep_intervals(conn, &ids)?);
    Ok(add_active_foreground_ms(&focus, &inactive))
}

/// Beat cadence of the writer's `open_focus` heartbeat. Kept equal to
/// `gilbreth_core::OPEN_FOCUS_BEAT_MS` (pinned by a test; this crate's
/// runtime dependency surface deliberately excludes gilbreth-core) and
/// documented as the contract in schema/README.md.
const OPEN_FOCUS_BEAT_MS: i64 = 30_000;

/// The writer's live open foreground segment, read under the freshness rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveOpenFocus {
    session_id: i64,
    exe: String,
    start_ts: i64,
    end_ts: i64,
}

/// Read the single `open_focus` row and accept it only while live: the
/// high-water mark must be within two beats of `now_ms`. A staler row means
/// a crashed pump whose startup repair has not run yet — that dwell belongs
/// to repair, and consuming it here would double-count once the synthesized
/// row lands. Readers never synthesize incomplete intervals from it; the
/// span is exactly `[started_ts, high_water_ts]`, with the end clamped to
/// `now_ms` so a writer clock a hair ahead cannot claim future time. Older
/// databases without the table contribute nothing.
fn live_open_focus(conn: &Connection, now_ms: i64) -> rusqlite::Result<Option<LiveOpenFocus>> {
    if !table_exists(conn, "open_focus")? {
        return Ok(None);
    }
    let Some((session_id, exe, started_ts, high_water_ts)) = conn
        .query_row(
            "SELECT session_id, exe, started_ts, high_water_ts FROM open_focus WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    if now_ms.saturating_sub(high_water_ts) > 2 * OPEN_FOCUS_BEAT_MS {
        return Ok(None);
    }
    let end_ts = high_water_ts.min(now_ms);
    if end_ts <= started_ts {
        return Ok(None);
    }
    let exe = match exe {
        Some(exe) if !exe.is_empty() => exe,
        _ => "(unknown)".to_string(),
    };
    Ok(Some(LiveOpenFocus {
        session_id,
        exe,
        start_ts: started_ts,
        end_ts,
    }))
}

/// An idle span that is still open at the read: the session's last
/// idle/active row is an `idle` with no `active` after it. Completed-row
/// readers drop such spans (their fallback terminator, `sessions.ended_at`,
/// is NULL for the live session), which is honest for intervals that ended
/// before the idleness began — but the live open interval extends to now,
/// so the in-progress idleness must subtract or empty-desk time reads as
/// active on the Today tile until the user returns.
fn open_trailing_idle_span(
    conn: &Connection,
    session_id: i64,
    end_ts: i64,
) -> rusqlite::Result<Option<(i64, i64)>> {
    let last: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT kind, ts, COALESCE(duration_ms, 0) FROM events
             WHERE session_id = ?1 AND kind IN ('idle', 'active')
             ORDER BY ts DESC, id DESC LIMIT 1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(match last {
        Some((kind, ts, elapsed_ms)) if kind == "idle" => {
            // The idle row carries the already-elapsed idle when the
            // threshold crossed, so the span starts before the row's ts —
            // the same reconstruction idle_intervals uses.
            let start = (ts - elapsed_ms).max(0);
            (start < end_ts).then_some((start, end_ts))
        }
        _ => None,
    })
}

/// The open segment's contribution under a scope cutoff: raw dwell and the
/// idle/sleep-subtracted active portion, using the same per-session
/// subtraction completed rows get plus the still-open trailing idle span.
fn open_focus_contribution(
    conn: &Connection,
    open: &LiveOpenFocus,
    cutoff_ms: i64,
) -> rusqlite::Result<Option<(i64, i64)>> {
    let start_ts = open.start_ts.max(cutoff_ms);
    if open.end_ts <= start_ts {
        return Ok(None);
    }
    let interval = FocusInterval {
        exe: open.exe.clone(),
        title: String::new(),
        session_id: open.session_id,
        seq: i64::MAX,
        local_date: local_date(open.end_ts),
        start_ts,
        end_ts: open.end_ts,
        duration_ms: open.end_ts - start_ts,
    };
    let ids = [open.session_id];
    let mut inactive = idle_intervals(conn, &ids, None)?;
    inactive.extend(sleep_intervals(conn, &ids)?);
    if let Some((idle_start, idle_end)) =
        open_trailing_idle_span(conn, open.session_id, open.end_ts)?
    {
        inactive.push(SessionInterval {
            session_id: open.session_id,
            start_ts: idle_start,
            end_ts: idle_end,
        });
    }
    let active = add_active_foreground_ms(std::slice::from_ref(&interval), &inactive)
        .pop()
        .map(|row| row.active_foreground_ms)
        .unwrap_or(0);
    Ok(Some((interval.duration_ms, active)))
}

/// One ordered foreground dwell with display app and active time — the
/// segment substrate episodes, runs, and spheres all build on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppSegment {
    pub order: i64,
    pub app: String,
    pub session_id: i64,
    pub seq: i64,
    pub local_date: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub active_ms: i64,
}

/// Mirrors `_read_active_app_focus_segments`.
pub fn active_app_focus_segments(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<AppSegment>> {
    let mut focus = focus_intervals_with_active(conn, scope)?;
    if focus.is_empty() {
        return Ok(Vec::new());
    }
    focus.sort_by_key(|row| (row.session_id, row.seq));
    Ok(focus
        .iter()
        .enumerate()
        .map(|(order, row)| AppSegment {
            order: order as i64,
            app: display_app(Some(&row.exe)),
            session_id: row.session_id,
            seq: row.seq,
            local_date: row.local_date.clone(),
            start_ts: row.start_ts,
            end_ts: row.end_ts,
            active_ms: row.active_foreground_ms.max(0),
        })
        .collect())
}

/// A merged same-app focus run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FocusRun {
    pub app: String,
    pub session_id: i64,
    pub local_date: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub active_ms: i64,
    pub first_order: i64,
    pub last_order: i64,
    pub first_seq: i64,
    pub last_seq: i64,
}

fn is_known_active_segment(segment: &AppSegment) -> bool {
    segment.app != "(unknown)" && segment.active_ms > 0
}

fn can_merge_focus_run(current: &FocusRun, segment: &AppSegment) -> bool {
    current.app == segment.app
        && current.session_id == segment.session_id
        && segment.order == current.last_order + 1
        && segment.start_ts - current.end_ts <= EPISODE_GAP_MS
}

/// Mirrors `_same_app_focus_runs`: merge consecutive known-active segments
/// of the same app within the episode gap; unknown or zero-active segments
/// break the current run.
pub fn same_app_focus_runs(segments: &[AppSegment]) -> Vec<FocusRun> {
    let mut runs: Vec<FocusRun> = Vec::new();
    let mut current: Option<FocusRun> = None;
    for segment in segments {
        if !is_known_active_segment(segment) {
            if let Some(run) = current.take() {
                runs.push(run);
            }
            continue;
        }
        if let Some(run) = current.as_mut() {
            if can_merge_focus_run(run, segment) {
                run.active_ms += segment.active_ms;
                run.end_ts = segment.end_ts;
                run.last_order = segment.order;
                run.last_seq = segment.seq;
                continue;
            }
        }
        if let Some(run) = current.take() {
            runs.push(run);
        }
        current = Some(FocusRun {
            app: segment.app.clone(),
            session_id: segment.session_id,
            local_date: segment.local_date.clone(),
            start_ts: segment.start_ts,
            end_ts: segment.end_ts,
            active_ms: segment.active_ms,
            first_order: segment.order,
            last_order: segment.order,
            first_seq: segment.seq,
            last_seq: segment.seq,
        });
    }
    if let Some(run) = current.take() {
        runs.push(run);
    }
    runs
}

/// Productive input timestamps for one (session, app) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductiveInput {
    pub session_id: i64,
    pub app: String,
    pub ts: Vec<i64>,
}

/// Mirrors `_productive_input_ts_by_app` (key/click/wheel, relay mouse
/// excluded, timestamps ascending), emitted sorted by (session, app) — the
/// parity harness sorts the Python dict the same way.
pub fn productive_input_by_app(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<ProductiveInput>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT e.session_id, COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe, e.ts
         FROM events e
         WHERE e.kind IN ('key', 'mouse_click', 'mouse_wheel')
           AND (e.kind = 'key'
                OR COALESCE(json_extract(e.payload, '$.input_origin'), 'local')
                   != 'remote_relay_suspected')
           AND {where_clause}
         ORDER BY e.ts"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut by_key: BTreeMap<(i64, String), Vec<i64>> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let exe: String = row.get(1)?;
        let ts: i64 = row.get(2)?;
        by_key
            .entry((session_id, display_app(Some(&exe))))
            .or_default()
            .push(ts);
    }
    Ok(by_key
        .into_iter()
        .map(|((session_id, app), ts)| ProductiveInput {
            session_id,
            app,
            ts,
        })
        .collect())
}

type ProductiveInputMap = HashMap<(i64, String), Vec<i64>>;

fn productive_input_map(conn: &Connection, scope: &Scope) -> rusqlite::Result<ProductiveInputMap> {
    Ok(productive_input_by_app(conn, scope)?
        .into_iter()
        .map(|row| ((row.session_id, row.app), row.ts))
        .collect())
}

fn median_i64_as_f64(values: &mut [i64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[mid] as f64)
    } else {
        Some((values[mid - 1] as f64 + values[mid] as f64) / 2.0)
    }
}

fn median_minutes(values_ms: &[i64]) -> Option<f64> {
    let mut values = values_ms.to_vec();
    median_i64_as_f64(&mut values).map(|value| round_2dp(value / 60_000.0))
}

fn median_seconds(values_ms: &[i64]) -> Option<f64> {
    let mut values = values_ms.to_vec();
    median_i64_as_f64(&mut values).map(|value| round_1dp(value / 1000.0))
}

/// One maximal continuous input run from `_read_input_runs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputRun {
    pub session_id: i64,
    pub min_ts: i64,
    pub max_ts: i64,
    pub event_count: i64,
    pub exe_counts: BTreeMap<String, i64>,
    #[serde(skip_serializing)]
    exe_order: Vec<String>,
    pub run_ms: i64,
    pub start_local_date: String,
}

#[derive(Debug, Clone)]
struct InputEvent {
    session_id: i64,
    seq: i64,
    ts: i64,
    exe: String,
}

/// Mirrors `_read_input_runs`: input rows ordered by `(session_id, seq)`,
/// split only by session boundaries or reconstructed idle/sleep spans.
pub fn input_runs(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<InputRun>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let input_predicate = input_sweep_predicate("e");
    let sql = format!(
        "SELECT e.session_id, e.seq, e.ts,
                COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe
         FROM events e
         WHERE {input_predicate}
           AND {where_clause}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut events: Vec<InputEvent> = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(InputEvent {
            session_id: row.get(0)?,
            seq: row.get(1)?,
            ts: row.get(2)?,
            exe: row.get(3)?,
        });
    }
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let session_ids: Vec<i64> = normalized_session_ids(
        &events
            .iter()
            .map(|event| event.session_id)
            .collect::<Vec<_>>(),
    );
    let mut inactive = idle_intervals(conn, &session_ids, None)?;
    inactive.extend(sleep_intervals(conn, &session_ids)?);
    let mut inactive_by_session: HashMap<i64, (Vec<i64>, Vec<i64>)> = HashMap::new();
    let mut raw_inactive_by_session: BTreeMap<i64, Vec<(i64, i64)>> = BTreeMap::new();
    for row in inactive {
        raw_inactive_by_session
            .entry(row.session_id)
            .or_default()
            .push((row.start_ts, row.end_ts));
    }
    for (session_id, spans) in raw_inactive_by_session {
        let spans = merge_intervals(spans);
        inactive_by_session.insert(
            session_id,
            (
                spans.iter().map(|(start, _)| *start).collect(),
                spans.iter().map(|(_, end)| *end).collect(),
            ),
        );
    }

    events.sort_by_key(|event| (event.session_id, event.seq));
    let mut runs: Vec<InputRun> = Vec::new();
    let mut current: Option<InputRun> = None;
    let mut prev_session: Option<i64> = None;
    let mut prev_ts: Option<i64> = None;

    for event in events {
        let mut broke = true;
        if current.is_some() && Some(event.session_id) == prev_session {
            let (lo, hi) = if let Some(prev) = prev_ts {
                (prev.min(event.ts), prev.max(event.ts))
            } else {
                (event.ts, event.ts)
            };
            let (starts, ends) = inactive_by_session
                .get(&event.session_id)
                .map(|(starts, ends)| (starts.as_slice(), ends.as_slice()))
                .unwrap_or((&[], &[]));
            let pos = starts.partition_point(|&start| start < hi);
            broke = pos > 0 && ends[pos - 1] > lo;
        }

        if let Some(run) = current.as_mut() {
            if !broke {
                run.min_ts = run.min_ts.min(event.ts);
                run.max_ts = run.max_ts.max(event.ts);
                run.event_count += 1;
                if !run.exe_counts.contains_key(&event.exe) {
                    run.exe_order.push(event.exe.clone());
                }
                *run.exe_counts.entry(event.exe.clone()).or_insert(0) += 1;
                run.run_ms = (run.max_ts - run.min_ts).max(0);
                run.start_local_date = local_date(run.min_ts);
                prev_session = Some(event.session_id);
                prev_ts = Some(event.ts);
                continue;
            }
        }

        if let Some(run) = current.take() {
            runs.push(run);
        }
        let mut exe_counts = BTreeMap::new();
        exe_counts.insert(event.exe.clone(), 1);
        current = Some(InputRun {
            session_id: event.session_id,
            min_ts: event.ts,
            max_ts: event.ts,
            event_count: 1,
            exe_counts,
            exe_order: vec![event.exe.clone()],
            run_ms: 0,
            start_local_date: local_date(event.ts),
        });
        prev_session = Some(event.session_id);
        prev_ts = Some(event.ts);
    }
    if let Some(run) = current {
        runs.push(run);
    }
    Ok(runs)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputExposureBreakdown {
    pub app: String,
    pub active_input_minutes: f64,
    pub keystrokes_per_hour: Option<f64>,
    pub clicks_per_hour: Option<f64>,
    pub moves_per_hour: Option<f64>,
    pub scrolls_per_hour: Option<f64>,
    pub total_input_events: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputExposureMetrics {
    pub active_input_minutes_total: f64,
    pub active_input_minutes_per_day: Option<f64>,
    pub day_band: Option<String>,
    pub longest_run_minutes: Option<f64>,
    pub runs_over_break_target: i64,
    pub input_events_per_active_hour: Option<f64>,
    pub total_input_events: i64,
    pub has_sustained_input: bool,
    pub breakdown: Vec<InputExposureBreakdown>,
}

fn empty_input_exposure_metrics() -> InputExposureMetrics {
    InputExposureMetrics {
        active_input_minutes_total: 0.0,
        active_input_minutes_per_day: None,
        day_band: None,
        longest_run_minutes: None,
        runs_over_break_target: 0,
        input_events_per_active_hour: None,
        total_input_events: 0,
        has_sustained_input: false,
        breakdown: Vec::new(),
    }
}

fn split_ms_interval_by_local_day(start_ms: i64, end_ms: i64) -> Vec<(String, i64)> {
    if end_ms <= start_ms {
        return Vec::new();
    }
    let mut pieces = Vec::new();
    let mut cursor = start_ms;
    while cursor < end_ms {
        let date = local_date_of(cursor);
        let next_midnight = local_midnight_ms(date + chrono::Duration::days(1));
        let mut boundary = end_ms.min(next_midnight);
        if boundary <= cursor {
            boundary = end_ms;
        }
        pieces.push((date.format("%Y-%m-%d").to_string(), boundary - cursor));
        cursor = boundary;
    }
    pieces
}

fn input_active_by_app_and_day(
    runs: &[InputRun],
    focus: &[FocusInterval],
) -> (HashMap<String, i64>, HashMap<String, i64>, i64) {
    let mut per_app: HashMap<String, i64> = HashMap::new();
    let mut per_day: HashMap<String, i64> = HashMap::new();
    let mut total = 0;
    if runs.is_empty() || focus.is_empty() {
        return (per_app, per_day, total);
    }

    let mut focus_by_session: HashMap<i64, Vec<(i64, i64, String)>> = HashMap::new();
    for row in focus {
        focus_by_session.entry(row.session_id).or_default().push((
            row.start_ts,
            row.end_ts,
            display_app(Some(&row.exe)),
        ));
    }
    for values in focus_by_session.values_mut() {
        values.sort_by_key(|row| (row.0, row.1));
    }

    let mut runs_by_session: HashMap<i64, Vec<(i64, i64)>> = HashMap::new();
    for run in runs {
        runs_by_session
            .entry(run.session_id)
            .or_default()
            .push((run.min_ts, run.max_ts));
    }

    for (session_id, mut run_list) in runs_by_session {
        let Some(focus_list) = focus_by_session.get(&session_id) else {
            continue;
        };
        run_list.sort_unstable();
        let mut cursor = 0usize;
        for (run_start, run_end) in run_list {
            if run_end <= run_start {
                continue;
            }
            while cursor < focus_list.len() && focus_list[cursor].1 <= run_start {
                cursor += 1;
            }
            let mut index = cursor;
            while index < focus_list.len() && focus_list[index].0 < run_end {
                let (focus_start, focus_end, app) = &focus_list[index];
                let lo = run_start.max(*focus_start);
                let hi = run_end.min(*focus_end);
                if hi > lo {
                    for (date, duration) in split_ms_interval_by_local_day(lo, hi) {
                        *per_app.entry(app.clone()).or_insert(0) += duration;
                        *per_day.entry(date).or_insert(0) += duration;
                        total += duration;
                    }
                }
                index += 1;
            }
        }
    }
    (per_app, per_day, total)
}

fn input_counts_by_app(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<(String, HashMap<String, i64>)>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let input_predicate = input_sweep_predicate("e");
    let sql = format!(
        "SELECT COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe, e.kind, COUNT(*) AS n
         FROM events e
         WHERE {input_predicate}
           AND {where_clause}
         GROUP BY COALESCE(NULLIF(e.exe, ''), '(unknown)'), e.kind"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut counts: Vec<(String, HashMap<String, i64>)> = Vec::new();
    let mut index_by_app: HashMap<String, usize> = HashMap::new();
    while let Some(row) = rows.next()? {
        let exe: String = row.get(0)?;
        let kind: String = row.get(1)?;
        let n: i64 = row.get(2)?;
        let app = display_app(Some(&exe));
        let index = if let Some(index) = index_by_app.get(&app) {
            *index
        } else {
            let index = counts.len();
            index_by_app.insert(app.clone(), index);
            counts.push((app, HashMap::new()));
            index
        };
        *counts[index].1.entry(kind).or_insert(0) += n;
    }
    Ok(counts)
}

fn input_day_band(per_day_avg_ms: Option<f64>) -> Option<String> {
    let value = per_day_avg_ms?;
    if value >= INPUT_EXPOSURE_DAY_HIGH_MS {
        Some("high".to_string())
    } else if value >= INPUT_EXPOSURE_DAY_ELEVATED_MS {
        Some("elevated".to_string())
    } else {
        Some("normal".to_string())
    }
}

/// Mirrors `read_input_exposure_metrics`.
pub fn input_exposure_metrics(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<InputExposureMetrics> {
    let runs = input_runs(conn, scope)?;
    if runs.is_empty() {
        return Ok(empty_input_exposure_metrics());
    }
    let focus = focus_intervals(conn, scope)?;
    let counts = input_counts_by_app(conn, scope)?;
    let total_events: i64 = counts
        .iter()
        .map(|(_, bucket)| bucket.values().sum::<i64>())
        .sum();
    if total_events == 0 {
        return Ok(empty_input_exposure_metrics());
    }

    let longest_ms = runs.iter().map(|run| run.run_ms).max().unwrap_or(0);
    let runs_over = runs
        .iter()
        .filter(|run| run.run_ms >= INPUT_EXPOSURE_BREAK_TARGET_MS)
        .count() as i64;
    let (per_app, per_day, total_ms) = input_active_by_app_and_day(&runs, &focus);
    let active_days = per_day.len() as f64;
    let per_day_avg_ms = (active_days > 0.0).then_some(total_ms as f64 / active_days);
    let total_active_hours = total_ms as f64 / 3_600_000.0;
    let events_per_hour =
        (total_active_hours > 0.0).then_some(round_1dp(total_events as f64 / total_active_hours));

    let mut breakdown: Vec<InputExposureBreakdown> = Vec::new();
    for (app, bucket) in counts {
        let app_ms = per_app.get(&app).copied().unwrap_or(0);
        let app_hours = app_ms as f64 / 3_600_000.0;
        let show_rate = app_ms >= INPUT_EXPOSURE_RATE_MIN_ACTIVE_MS && app_hours > 0.0;
        let rate = |kind: &str| {
            show_rate.then_some(round_1dp(
                bucket.get(kind).copied().unwrap_or(0) as f64 / app_hours,
            ))
        };
        breakdown.push(InputExposureBreakdown {
            app,
            active_input_minutes: round_2dp(app_ms as f64 / 60_000.0),
            keystrokes_per_hour: rate("key"),
            clicks_per_hour: rate("mouse_click"),
            moves_per_hour: rate("mouse_move"),
            scrolls_per_hour: rate("mouse_wheel"),
            total_input_events: bucket.values().sum(),
        });
    }
    breakdown.sort_by(|left, right| {
        right
            .active_input_minutes
            .total_cmp(&left.active_input_minutes)
            .then_with(|| right.total_input_events.cmp(&left.total_input_events))
    });
    breakdown.truncate(TOP_N_ANALYTICS);

    Ok(InputExposureMetrics {
        active_input_minutes_total: round_2dp(total_ms as f64 / 60_000.0),
        active_input_minutes_per_day: per_day_avg_ms.map(|value| round_2dp(value / 60_000.0)),
        day_band: input_day_band(per_day_avg_ms),
        longest_run_minutes: Some(round_2dp(longest_ms as f64 / 60_000.0)),
        runs_over_break_target: runs_over,
        input_events_per_active_hour: events_per_hour,
        total_input_events: total_events,
        has_sustained_input: longest_ms > 0,
        breakdown,
    })
}

fn runs_are_adjacent(left: &FocusRun, right: &FocusRun) -> bool {
    left.session_id == right.session_id
        && right.first_order == left.last_order + 1
        && right.start_ts - left.end_ts <= EPISODE_GAP_MS
}

fn next_anchor_returns(runs: &[FocusRun]) -> Vec<(usize, usize)> {
    if runs.is_empty() {
        return Vec::new();
    }
    let mut chain_end = vec![0usize; runs.len()];
    chain_end[runs.len() - 1] = runs.len() - 1;
    for index in (0..runs.len() - 1).rev() {
        chain_end[index] = if runs_are_adjacent(&runs[index], &runs[index + 1]) {
            chain_end[index + 1]
        } else {
            index
        };
    }
    let mut indices_by_app: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, run) in runs.iter().enumerate() {
        indices_by_app
            .entry(run.app.as_str())
            .or_default()
            .push(index);
    }
    let mut pairs = Vec::new();
    for (index, run) in runs.iter().enumerate() {
        let Some(occurrences) = indices_by_app.get(run.app.as_str()) else {
            continue;
        };
        let position = occurrences.partition_point(|&value| value <= index);
        if position >= occurrences.len() {
            continue;
        }
        let return_index = occurrences[position];
        if return_index <= chain_end[index] && return_index > index + 1 {
            pairs.push((index, return_index));
        }
    }
    pairs
}

fn active_ms_prefix(runs: &[FocusRun]) -> Vec<i64> {
    let mut prefix = Vec::with_capacity(runs.len() + 1);
    prefix.push(0);
    for run in runs {
        prefix.push(prefix.last().copied().unwrap_or(0) + run.active_ms);
    }
    prefix
}

fn first_input_lag(
    session_id: i64,
    app: &str,
    start_ts: i64,
    end_ts: i64,
    productive_ts_by_app: &ProductiveInputMap,
) -> Option<i64> {
    let ts_list = productive_ts_by_app.get(&(session_id, app.to_string()))?;
    let index = ts_list.partition_point(|&ts| ts < start_ts);
    if index < ts_list.len() && ts_list[index] < end_ts {
        Some((ts_list[index] - start_ts).max(0))
    } else {
        None
    }
}

/// One round-trip interruption-cost substrate record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiversionCostRecord {
    pub session_id: i64,
    pub anchor: String,
    pub diverter: String,
    pub path: Vec<String>,
    pub anchor_start_ts: i64,
    pub diverter_start_ts: i64,
    pub return_start_ts: i64,
    pub return_end_ts: i64,
    pub away_ms: i64,
    pub restart_ms: Option<i64>,
    pub local_date: String,
}

fn diversion_cost_records(
    runs: &[FocusRun],
    productive_ts_by_app: &ProductiveInputMap,
) -> Vec<DiversionCostRecord> {
    let active_prefix = active_ms_prefix(runs);
    let mut records = Vec::new();
    for (index, return_index) in next_anchor_returns(runs) {
        let run = &runs[index];
        let candidate = &runs[return_index];
        let anchor = run.app.clone();
        records.push(DiversionCostRecord {
            session_id: run.session_id,
            anchor: anchor.clone(),
            diverter: runs[index + 1].app.clone(),
            path: runs[index..=return_index]
                .iter()
                .map(|row| row.app.clone())
                .collect(),
            anchor_start_ts: run.start_ts,
            diverter_start_ts: runs[index + 1].start_ts,
            return_start_ts: candidate.start_ts,
            return_end_ts: candidate.end_ts,
            away_ms: active_prefix[return_index] - active_prefix[index + 1],
            restart_ms: first_input_lag(
                candidate.session_id,
                &anchor,
                candidate.start_ts,
                candidate.end_ts,
                productive_ts_by_app,
            ),
            local_date: run.local_date.clone(),
        });
    }
    records
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterruptionPair {
    pub diverter: String,
    pub anchor: String,
    pub count: i64,
    pub days: i64,
    pub median_away_minutes: Option<f64>,
    pub median_restart_seconds: Option<f64>,
    pub estimated_restart_minutes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterruptionCosts {
    pub total_roundtrips: i64,
    pub measured_restarts: i64,
    pub median_restart_seconds: Option<f64>,
    pub estimated_restart_minutes: Option<f64>,
    pub total_away_minutes: f64,
    pub pairs: Vec<InterruptionPair>,
}

type PairAccum = (i64, HashSet<String>, Vec<i64>, Vec<i64>);
type HourGroups<T> = Vec<(i64, Vec<T>)>;
type SwitchRateHourSample = (String, f64, i64);
type DateValueSample = (String, i64);
type ReturnTollNoticeGroup = (i64, Vec<i64>, Vec<DiversionCostRecord>);
type SessionSeqItems = HashMap<i64, (Vec<i64>, Vec<(i64, String)>)>;

/// Mirrors `read_interruption_costs`.
pub fn interruption_costs(conn: &Connection, scope: &Scope) -> rusqlite::Result<InterruptionCosts> {
    let segments = active_app_focus_segments(conn, scope)?;
    if segments.is_empty() {
        return Ok(InterruptionCosts {
            total_roundtrips: 0,
            measured_restarts: 0,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
            total_away_minutes: 0.0,
            pairs: Vec::new(),
        });
    }
    let productive_ts = productive_input_map(conn, scope)?;
    let runs = same_app_focus_runs(&segments);
    let records = diversion_cost_records(&runs, &productive_ts);
    if records.is_empty() {
        return Ok(InterruptionCosts {
            total_roundtrips: 0,
            measured_restarts: 0,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
            total_away_minutes: 0.0,
            pairs: Vec::new(),
        });
    }

    let restarts: Vec<i64> = records
        .iter()
        .filter_map(|record| record.restart_ms)
        .collect();
    let total_away_ms: i64 = records.iter().map(|record| record.away_ms).sum();
    let mut grouped: HashMap<(String, String), PairAccum> = HashMap::new();
    for record in &records {
        let entry = grouped
            .entry((record.diverter.clone(), record.anchor.clone()))
            .or_insert_with(|| (0, HashSet::new(), Vec::new(), Vec::new()));
        entry.0 += 1;
        entry.1.insert(record.local_date.clone());
        entry.2.push(record.away_ms);
        if let Some(restart) = record.restart_ms {
            entry.3.push(restart);
        }
    }

    let mut pairs: Vec<InterruptionPair> = grouped
        .into_iter()
        .filter_map(|((diverter, anchor), (count, days, away_ms, restart_ms))| {
            if count < INTERRUPTION_PAIR_MIN_ROUNDTRIPS {
                return None;
            }
            let pair_median = (restart_ms.len() >= RESUMPTION_LAG_MIN_SAMPLES)
                .then(|| median_seconds(&restart_ms))
                .flatten();
            Some(InterruptionPair {
                diverter,
                anchor,
                count,
                days: days.len() as i64,
                median_away_minutes: median_minutes(&away_ms),
                median_restart_seconds: pair_median,
                estimated_restart_minutes: pair_median
                    .map(|seconds| round_2dp(seconds * count as f64 / 60.0)),
            })
        })
        .collect();
    pairs.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| {
                let right_estimate = right.estimated_restart_minutes.unwrap_or(0.0);
                let left_estimate = left.estimated_restart_minutes.unwrap_or(0.0);
                right_estimate.total_cmp(&left_estimate)
            })
            .then_with(|| left.diverter.cmp(&right.diverter))
            .then_with(|| left.anchor.cmp(&right.anchor))
    });
    pairs.truncate(INTERRUPTION_PAIR_LIMIT);

    let overall_median = (restarts.len() >= RESUMPTION_LAG_MIN_SAMPLES)
        .then(|| median_seconds(&restarts))
        .flatten();
    Ok(InterruptionCosts {
        total_roundtrips: records.len() as i64,
        measured_restarts: restarts.len() as i64,
        median_restart_seconds: overall_median,
        estimated_restart_minutes: overall_median
            .map(|seconds| round_2dp(seconds * records.len() as f64 / 60.0)),
        total_away_minutes: round_2dp(total_away_ms as f64 / 60_000.0),
        pairs,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RampRecord {
    pub session_id: i64,
    pub anchor_ts: i64,
    pub first_input_ts: i64,
    pub sustained_start_ts: i64,
    pub sustained_end_ts: i64,
    pub duration_ms: i64,
    pub switch_count: i64,
    pub sustained_app: String,
    pub anchor_label: String,
    pub path: Vec<String>,
    pub local_date: String,
}

fn session_starts(conn: &Connection, session_ids: &[i64]) -> rusqlite::Result<Vec<(i64, i64)>> {
    let ids = normalized_session_ids(session_ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT session_id, started_at
         FROM sessions
         WHERE session_id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(ids.iter()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push((row.get(0)?, row.get(1)?));
    }
    Ok(out)
}

fn power_resume_events(
    conn: &Connection,
    session_ids: &[i64],
) -> rusqlite::Result<Vec<(i64, i64)>> {
    let ids = normalized_session_ids(session_ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT session_id, ts
         FROM events
         WHERE session_id IN ({placeholders})
           AND kind = 'power_resume'
         ORDER BY session_id, ts"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(ids.iter()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push((row.get(0)?, row.get(1)?));
    }
    Ok(out)
}

fn ramp_anchor_priority(record: &RampRecord) -> (i64, i64) {
    let label_rank = match record.anchor_label.as_str() {
        "power resume" => 3,
        "session start" => 2,
        "long idle return" => 1,
        _ => 0,
    };
    (label_rank, -record.anchor_ts)
}

fn ramp_path_and_switches(
    segments: &[AppSegment],
    start_ts: i64,
    end_ts: i64,
    sustained_app: &str,
) -> (Vec<String>, i64) {
    let mut apps: Vec<String> = Vec::new();
    let mut previous: Option<&str> = None;
    let mut switches = 0;
    for segment in segments {
        if segment.end_ts <= start_ts || segment.start_ts >= end_ts {
            continue;
        }
        if segment.app == "(unknown)" {
            continue;
        }
        if apps.last().map(String::as_str) != Some(segment.app.as_str()) {
            apps.push(segment.app.clone());
        }
        if previous.is_some_and(|prev| prev != segment.app) {
            switches += 1;
        }
        previous = Some(segment.app.as_str());
    }
    if apps.last().map(String::as_str) != Some(sustained_app) {
        apps.push(sustained_app.to_string());
        if previous.is_some_and(|prev| prev != sustained_app) {
            switches += 1;
        }
    }
    apps.truncate(5);
    (apps, switches)
}

pub fn ramp_records(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<RampRecord>> {
    let segments = active_app_focus_segments(conn, scope)?;
    if segments.is_empty() {
        return Ok(Vec::new());
    }
    let productive_ts = productive_input_map(conn, scope)?;
    let session_ids: Vec<i64> = normalized_session_ids(
        &segments
            .iter()
            .map(|segment| segment.session_id)
            .collect::<Vec<_>>(),
    );

    let mut anchors: Vec<(i64, i64, String)> = Vec::new();
    for (session_id, started_at) in session_starts(conn, &session_ids)? {
        if scope.cutoff_ms.is_none_or(|cutoff| started_at >= cutoff) {
            anchors.push((session_id, started_at, "session start".to_string()));
        }
    }
    for (session_id, ts) in power_resume_events(conn, &session_ids)? {
        if scope.cutoff_ms.is_none_or(|cutoff| ts >= cutoff) {
            anchors.push((session_id, ts, "power resume".to_string()));
        }
    }
    for row in idle_intervals(conn, &session_ids, Some(scope))? {
        let idle_ms = row.end_ts - row.start_ts;
        if idle_ms >= EPISODE_GAP_MS {
            anchors.push((row.session_id, row.end_ts, "long idle return".to_string()));
        }
    }

    let mut input_by_session: HashMap<i64, Vec<i64>> = HashMap::new();
    for ((session_id, _app), values) in productive_ts.iter() {
        input_by_session
            .entry(*session_id)
            .or_default()
            .extend(values.iter().copied());
    }
    for values in input_by_session.values_mut() {
        values.sort_unstable();
    }

    let runs = same_app_focus_runs(&segments);
    let mut runs_by_session: HashMap<i64, Vec<&FocusRun>> = HashMap::new();
    let mut segments_by_session: HashMap<i64, Vec<AppSegment>> = HashMap::new();
    for run in &runs {
        runs_by_session.entry(run.session_id).or_default().push(run);
    }
    for segment in &segments {
        segments_by_session
            .entry(segment.session_id)
            .or_default()
            .push(segment.clone());
    }

    anchors.sort_by_key(|(session_id, ts, _)| (*session_id, *ts));
    let mut deduped_records: HashMap<(i64, i64, i64, i64, String), RampRecord> = HashMap::new();
    for (session_id, anchor_ts, label) in anchors {
        let ts_list = input_by_session
            .get(&session_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let input_index = ts_list.partition_point(|&ts| ts < anchor_ts);
        if input_index >= ts_list.len() {
            continue;
        }
        let first_input = ts_list[input_index];
        let sustained = runs_by_session
            .get(&session_id)
            .into_iter()
            .flat_map(|runs| runs.iter().copied())
            .find(|run| run.end_ts >= first_input && run.active_ms >= RAMP_SUSTAINED_FOCUS_MS);
        let Some(sustained) = sustained else {
            continue;
        };
        let ramp_end = sustained.start_ts;
        let ramp_ms = (ramp_end - first_input).max(0);
        if ramp_ms <= 0 {
            continue;
        }
        let (path, switches) = ramp_path_and_switches(
            segments_by_session
                .get(&session_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            first_input,
            ramp_end,
            &sustained.app,
        );
        let record = RampRecord {
            session_id,
            anchor_ts,
            first_input_ts: first_input,
            sustained_start_ts: sustained.start_ts,
            sustained_end_ts: sustained.end_ts,
            duration_ms: ramp_ms,
            switch_count: switches,
            sustained_app: sustained.app.clone(),
            anchor_label: label,
            path,
            local_date: local_date(anchor_ts),
        };
        let dedupe_key = (
            session_id,
            first_input,
            sustained.start_ts,
            sustained.end_ts,
            sustained.app.clone(),
        );
        let replace = deduped_records
            .get(&dedupe_key)
            .is_none_or(|existing| ramp_anchor_priority(&record) > ramp_anchor_priority(existing));
        if replace {
            deduped_records.insert(dedupe_key, record);
        }
    }
    let mut records: Vec<RampRecord> = deduped_records.into_values().collect();
    records.sort_by_key(|record| (record.session_id, record.anchor_ts));
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FrictionWindow {
    pub signal: String,
    pub hour: i64,
    pub hour_label: String,
    pub days: i64,
    pub count: i64,
    pub today_count: i64,
    pub value: f64,
    pub baseline: f64,
    pub unit: String,
    pub summary: String,
}

struct TimeWindowInput<'a> {
    signal: &'a str,
    hour: i64,
    days: usize,
    count: i64,
    today_count: i64,
    value: f64,
    baseline: f64,
    unit: &'a str,
}

fn time_window_row(input: TimeWindowInput<'_>) -> FrictionWindow {
    let signal = input.signal;
    let hour = input.hour;
    let days = input.days;
    let hour_label = format!("{hour:02}:00");
    FrictionWindow {
        signal: signal.to_string(),
        hour,
        hour_label: hour_label.clone(),
        days: days as i64,
        count: input.count,
        today_count: input.today_count,
        value: round_2dp(input.value),
        baseline: round_2dp(input.baseline),
        unit: input.unit.to_string(),
        summary: format!("{signal} clustered around {hour_label} on {days} recent local dates."),
    }
}

fn push_hour_value<T>(
    rows: &mut Vec<(i64, Vec<T>)>,
    index: &mut HashMap<i64, usize>,
    hour: i64,
    value: T,
) {
    if let Some(&position) = index.get(&hour) {
        rows[position].1.push(value);
    } else {
        index.insert(hour, rows.len());
        rows.push((hour, vec![value]));
    }
}

fn add_switch_rate_windows(
    rows: &mut Vec<FrictionWindow>,
    segments: &[AppSegment],
    today_key: &str,
) {
    if segments.is_empty() {
        return;
    }
    let mut active_by_key: HashMap<(String, i64), i64> = HashMap::new();
    let mut switches_by_key: Vec<((String, i64), i64)> = Vec::new();
    let mut switches_index: HashMap<(String, i64), usize> = HashMap::new();
    let mut previous: Option<&AppSegment> = None;
    for segment in segments {
        let key = (segment.local_date.clone(), local_hour(segment.start_ts));
        *active_by_key.entry(key.clone()).or_insert(0) += segment.active_ms;
        if let Some(prev) = previous {
            if prev.session_id == segment.session_id
                && segment.order == prev.order + 1
                && segment.start_ts - prev.end_ts <= EPISODE_GAP_MS
                && prev.app != segment.app
                && segment.active_ms >= MIN_SWITCH_DWELL_MS
            {
                bump_ordered(&mut switches_by_key, &mut switches_index, key, 1);
            }
        }
        previous = Some(segment);
    }
    let mut rates_by_hour: HourGroups<SwitchRateHourSample> = Vec::new();
    let mut rates_index: HashMap<i64, usize> = HashMap::new();
    for (key, switches) in switches_by_key {
        let active_ms = active_by_key.get(&key).copied().unwrap_or(0);
        if active_ms < SWITCH_RATE_MIN_ACTIVE_MS {
            continue;
        }
        let (date, hour) = key;
        let rate = switches as f64 / (active_ms as f64 / 3_600_000.0);
        push_hour_value(
            &mut rates_by_hour,
            &mut rates_index,
            hour,
            (date, rate, switches),
        );
    }
    let all_rates: Vec<f64> = rates_by_hour
        .iter()
        .flat_map(|(_, values)| values.iter().map(|(_, rate, _)| *rate))
        .collect();
    if all_rates.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return;
    }
    let baseline = percentile_nearest_rank(&all_rates, 75.0);
    for (hour, values) in rates_by_hour {
        let days: HashSet<String> = values.iter().map(|(date, _, _)| date.clone()).collect();
        if days.len() < TIME_ANCHOR_MIN_DAYS {
            continue;
        }
        let mut rates: Vec<f64> = values.iter().map(|(_, rate, _)| *rate).collect();
        let median_rate = median_f64(&mut rates).unwrap_or(0.0);
        if median_rate < baseline {
            continue;
        }
        rows.push(time_window_row(TimeWindowInput {
            signal: "switch rate",
            hour,
            days: days.len(),
            count: values.iter().map(|(_, _, switches)| *switches).sum(),
            today_count: values
                .iter()
                .filter(|(date, _, _)| date == today_key)
                .map(|(_, _, switches)| *switches)
                .sum(),
            value: median_rate,
            baseline,
            unit: "switches/hr",
        }));
    }
}

fn add_return_toll_windows(
    rows: &mut Vec<FrictionWindow>,
    records: &[DiversionCostRecord],
    today_key: &str,
) {
    let measured: Vec<&DiversionCostRecord> = records
        .iter()
        .filter(|record| record.restart_ms.is_some())
        .collect();
    if measured.is_empty() {
        return;
    }
    let mut by_hour: HourGroups<DateValueSample> = Vec::new();
    let mut by_hour_index: HashMap<i64, usize> = HashMap::new();
    for record in measured {
        push_hour_value(
            &mut by_hour,
            &mut by_hour_index,
            local_hour(record.return_start_ts),
            (record.local_date.clone(), record.restart_ms.unwrap_or(0)),
        );
    }
    let hour_medians: Vec<f64> = by_hour
        .iter()
        .filter_map(|(_, values)| {
            let mut restarts: Vec<i64> = values.iter().map(|(_, value)| *value).collect();
            median_i64_as_f64(&mut restarts).map(|value| value / 1000.0)
        })
        .collect();
    if hour_medians.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return;
    }
    let baseline = percentile_nearest_rank(&hour_medians, 75.0);
    for (hour, values) in by_hour {
        let days: HashSet<String> = values.iter().map(|(date, _)| date.clone()).collect();
        if days.len() < TIME_ANCHOR_MIN_DAYS {
            continue;
        }
        let mut restarts: Vec<i64> = values.iter().map(|(_, value)| *value).collect();
        let median_seconds = median_i64_as_f64(&mut restarts).unwrap_or(0.0) / 1000.0;
        if median_seconds < baseline {
            continue;
        }
        rows.push(time_window_row(TimeWindowInput {
            signal: "return toll",
            hour,
            days: days.len(),
            count: values.len() as i64,
            today_count: values.iter().filter(|(date, _)| date == today_key).count() as i64,
            value: median_seconds,
            baseline,
            unit: "s median restart",
        }));
    }
}

fn add_input_dense_windows(rows: &mut Vec<FrictionWindow>, runs: &[InputRun], today_key: &str) {
    let dense: Vec<&InputRun> = runs
        .iter()
        .filter(|run| run.run_ms >= INPUT_DENSE_NOTICE_MIN_MS)
        .collect();
    if dense.is_empty() {
        return;
    }
    let mut by_hour: HourGroups<DateValueSample> = Vec::new();
    let mut by_hour_index: HashMap<i64, usize> = HashMap::new();
    for run in dense {
        push_hour_value(
            &mut by_hour,
            &mut by_hour_index,
            local_hour(run.min_ts),
            (run.start_local_date.clone(), 1),
        );
    }
    let counts: Vec<f64> = by_hour
        .iter()
        .map(|(_, values)| values.len() as f64)
        .collect();
    if counts.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return;
    }
    let baseline = percentile_nearest_rank(&counts, 75.0);
    for (hour, values) in by_hour {
        let days: HashSet<String> = values.iter().map(|(date, _)| date.clone()).collect();
        if days.len() < TIME_ANCHOR_MIN_DAYS || (values.len() as f64) < baseline {
            continue;
        }
        rows.push(time_window_row(TimeWindowInput {
            signal: "input-dense spans",
            hour,
            days: days.len(),
            count: values.len() as i64,
            today_count: values.iter().filter(|(date, _)| date == today_key).count() as i64,
            value: values.len() as f64,
            baseline,
            unit: "spans",
        }));
    }
}

fn add_ramp_windows(rows: &mut Vec<FrictionWindow>, records: &[RampRecord], today_key: &str) {
    if records.is_empty() {
        return;
    }
    let mut by_hour: HourGroups<DateValueSample> = Vec::new();
    let mut by_hour_index: HashMap<i64, usize> = HashMap::new();
    for record in records {
        push_hour_value(
            &mut by_hour,
            &mut by_hour_index,
            local_hour(record.anchor_ts),
            (record.local_date.clone(), record.duration_ms),
        );
    }
    let hour_medians: Vec<f64> = by_hour
        .iter()
        .filter_map(|(_, values)| {
            let mut durations: Vec<i64> = values.iter().map(|(_, value)| *value).collect();
            median_i64_as_f64(&mut durations).map(|value| value / 60_000.0)
        })
        .collect();
    if hour_medians.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return;
    }
    let baseline = percentile_nearest_rank(&hour_medians, 75.0);
    for (hour, values) in by_hour {
        let days: HashSet<String> = values.iter().map(|(date, _)| date.clone()).collect();
        if days.len() < TIME_ANCHOR_MIN_DAYS {
            continue;
        }
        let mut durations: Vec<i64> = values.iter().map(|(_, value)| *value).collect();
        let median_minutes = median_i64_as_f64(&mut durations).unwrap_or(0.0) / 60_000.0;
        if median_minutes < baseline {
            continue;
        }
        rows.push(time_window_row(TimeWindowInput {
            signal: "return ramp",
            hour,
            days: days.len(),
            count: values.len() as i64,
            today_count: values.iter().filter(|(date, _)| date == today_key).count() as i64,
            value: median_minutes,
            baseline,
            unit: "min median ramp",
        }));
    }
}

/// Mirrors `_time_of_day_friction_windows`.
pub fn time_of_day_friction_windows(
    conn: &Connection,
    scope: &Scope,
    now_ms: i64,
) -> rusqlite::Result<Vec<FrictionWindow>> {
    let today_key = local_date(local_day_start_ms(now_ms));
    let segments = active_app_focus_segments(conn, scope)?;
    let productive_ts = if segments.is_empty() {
        HashMap::new()
    } else {
        productive_input_map(conn, scope)?
    };
    let runs = if segments.is_empty() {
        Vec::new()
    } else {
        same_app_focus_runs(&segments)
    };
    let records = if runs.is_empty() {
        Vec::new()
    } else {
        diversion_cost_records(&runs, &productive_ts)
    };
    let input_runs = input_runs(conn, scope)?;
    let ramp = ramp_records(conn, scope)?;

    let mut rows = Vec::new();
    add_switch_rate_windows(&mut rows, &segments, &today_key);
    add_return_toll_windows(&mut rows, &records, &today_key);
    add_input_dense_windows(&mut rows, &input_runs, &today_key);
    add_ramp_windows(&mut rows, &ramp, &today_key);
    rows.sort_by(|left, right| {
        right
            .days
            .cmp(&left.days)
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| right.value.total_cmp(&left.value))
    });
    Ok(rows)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryNoticeEvidence {
    pub occurred_at_ms: i64,
    pub path: Vec<String>,
    pub duration_ms: Option<i64>,
    pub away_ms: Option<i64>,
    pub restart_ms: Option<i64>,
    pub input_events: Option<i64>,
    pub switch_count: Option<i64>,
    pub rate: Option<f64>,
    pub note: String,
}

impl DiscoveryNoticeEvidence {
    fn at(occurred_at_ms: i64) -> Self {
        Self {
            occurred_at_ms,
            path: Vec::new(),
            duration_ms: None,
            away_ms: None,
            restart_ms: None,
            input_events: None,
            switch_count: None,
            rate: None,
            note: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryNotice {
    pub notice_key: String,
    pub notice_type: String,
    pub title: String,
    pub summary: String,
    pub support_count: i128,
    pub sort_score: f64,
    pub evidence: Vec<DiscoveryNoticeEvidence>,
    pub detail: String,
    pub baseline: String,
    pub total_count: i128,
    pub median_restart_seconds: Option<f64>,
    pub estimated_restart_minutes: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DiscoveryNoticeState {
    pub dismissed: BTreeMap<String, String>,
    pub muted: BTreeSet<String>,
    pub watched: BTreeSet<String>,
}

fn discovery_today_key(now_ms: i64) -> String {
    local_date(local_day_start_ms(now_ms))
}

fn effective_discovery_today_key(today_key: Option<&str>, now_ms: i64) -> String {
    today_key
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| discovery_today_key(now_ms))
}

fn today_scope(now_ms: i64) -> Scope {
    Scope {
        cutoff_ms: Some(local_day_start_ms(now_ms)),
        session_id: None,
    }
}

fn discovery_baseline_scope(now_ms: i64) -> Scope {
    let today = local_day_start_ms(now_ms);
    Scope {
        cutoff_ms: Some(today - (DISCOVERY_BASELINE_DAYS * DAY_MS)),
        session_id: None,
    }
}

fn discovery_notice_key(notice_type: &str, parts: &[String]) -> String {
    let mut cleaned = vec![notice_type.to_string()];
    for part in parts {
        let trimmed = part.replace('|', "/").trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        cleaned.push(trimmed.chars().take(120).collect());
    }
    cleaned.join("|")
}

fn duration_baseline_text(values_ms: &[i64]) -> (Option<i64>, String) {
    let samples: Vec<f64> = values_ms
        .iter()
        .filter(|value| **value > 0)
        .map(|value| *value as f64)
        .collect();
    if samples.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return (None, "Recent baseline is still forming.".to_string());
    }
    let p75 = percentile_nearest_rank(&samples, 75.0) as i64;
    (
        Some(p75),
        format!("recent p75 {}.", notice_duration_text(p75)),
    )
}

fn rate_baseline_text(values: &[f64], unit: &str) -> (Option<f64>, String) {
    let samples: Vec<f64> = values
        .iter()
        .copied()
        .filter(|value| *value > 0.0)
        .collect();
    if samples.len() < DISCOVERY_BASELINE_MIN_SAMPLES {
        return (None, "Recent baseline is still forming.".to_string());
    }
    let p75 = percentile_nearest_rank(&samples, 75.0);
    (Some(p75), format!("recent p75 {p75:.1} {unit}."))
}

fn dominant_input_app(run: &InputRun) -> String {
    run.exe_counts
        .iter()
        .max_by_key(|(exe, count)| (**count, (*exe).clone()))
        .map(|(exe, _)| display_app(Some(exe)))
        .unwrap_or_else(|| "(unknown)".to_string())
}

fn discovery_notice_hidden(
    notice: &DiscoveryNotice,
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
    include_muted: bool,
) -> bool {
    let Some(state) = state else {
        return false;
    };
    let dismissed_today = today_key.is_some_and(|key| {
        state
            .dismissed
            .get(&notice.notice_key)
            .is_some_and(|day| day == key)
    });
    let muted = state.muted.contains(&notice.notice_key);
    dismissed_today || (muted && !include_muted)
}

fn sort_discovery_notices(notices: &mut [DiscoveryNotice], state: Option<&DiscoveryNoticeState>) {
    notices.sort_by(|left, right| {
        let left_watched = if state.is_some_and(|s| s.watched.contains(&left.notice_key)) {
            -1
        } else {
            0
        };
        let right_watched = if state.is_some_and(|s| s.watched.contains(&right.notice_key)) {
            -1
        } else {
            0
        };
        left_watched
            .cmp(&right_watched)
            .then_with(|| right.sort_score.total_cmp(&left.sort_score))
            .then_with(|| right.support_count.cmp(&left.support_count))
            .then_with(|| right.total_count.cmp(&left.total_count))
            .then_with(|| left.title.cmp(&right.title))
    });
}

pub fn visible_discovery_notices(
    notices: &[DiscoveryNotice],
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
    limit: usize,
    include_muted: bool,
    allow_same_type_backfill: bool,
) -> Vec<DiscoveryNotice> {
    let cap = limit;
    if cap == 0 {
        return Vec::new();
    }
    let mut ranked: Vec<DiscoveryNotice> = notices
        .iter()
        .filter(|notice| !discovery_notice_hidden(notice, state, today_key, include_muted))
        .cloned()
        .collect();
    sort_discovery_notices(&mut ranked, state);

    let mut selected: Vec<DiscoveryNotice> = Vec::new();
    let mut selected_ids: HashSet<String> = HashSet::new();
    let mut seen_types: HashSet<String> = HashSet::new();
    for notice in &ranked {
        if seen_types.contains(&notice.notice_type) {
            continue;
        }
        selected_ids.insert(notice.notice_key.clone());
        seen_types.insert(notice.notice_type.clone());
        selected.push(notice.clone());
        if selected.len() >= cap {
            return selected;
        }
    }
    if !allow_same_type_backfill {
        return selected;
    }
    for notice in ranked {
        if selected_ids.contains(&notice.notice_key) {
            continue;
        }
        selected_ids.insert(notice.notice_key.clone());
        selected.push(notice);
        if selected.len() >= cap {
            break;
        }
    }
    selected
}

fn needs_discovery_backfill(
    notices: &[DiscoveryNotice],
    limit: usize,
    state: Option<&DiscoveryNoticeState>,
    today_key: &str,
    notice_type: &str,
) -> bool {
    if limit == 0 {
        return false;
    }
    if let Some(state) = state {
        let prefix = format!("{notice_type}|");
        if state
            .watched
            .iter()
            .any(|key| key == notice_type || key.starts_with(&prefix))
        {
            return true;
        }
    }
    visible_discovery_notices(notices, state, Some(today_key), limit, false, false).len() < limit
}

fn return_toll_notices(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let scope = today_scope(now_ms);
    let segments = active_app_focus_segments(conn, &scope)?;
    if segments.is_empty() {
        return Ok(Vec::new());
    }
    let productive_ts = productive_input_map(conn, &scope)?;
    let runs = same_app_focus_runs(&segments);
    let records = diversion_cost_records(&runs, &productive_ts);
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let mut grouped: Vec<((String, String), ReturnTollNoticeGroup)> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for record in records {
        let key = (record.anchor.clone(), record.diverter.clone());
        let position = if let Some(position) = index.get(&key) {
            *position
        } else {
            index.insert(key.clone(), grouped.len());
            grouped.push((key.clone(), (0, Vec::new(), Vec::new())));
            grouped.len() - 1
        };
        let entry = &mut grouped[position].1;
        entry.0 += 1;
        if let Some(restart_ms) = record.restart_ms {
            entry.1.push(restart_ms);
            entry.2.push(record);
        }
    }

    let mut notices = Vec::new();
    for ((anchor, diverter), (total_count, measured, records)) in grouped {
        if measured.len() < RETURN_TOLL_NOTICE_MIN_MEASURED_RETURNS {
            continue;
        }
        let median_restart_seconds = median_seconds(&measured);
        let Some(median_restart_seconds) = median_restart_seconds else {
            continue;
        };
        let estimated_restart_ms =
            (median_restart_seconds * 1000.0 * total_count as f64).round_ties_even() as i64;
        let mut evidence_records = records;
        evidence_records.sort_by_key(|record| std::cmp::Reverse(record.return_start_ts));
        let evidence = evidence_records
            .into_iter()
            .take(RETURN_TOLL_EVIDENCE_LIMIT)
            .map(|record| {
                let mut row = DiscoveryNoticeEvidence::at(record.return_start_ts);
                row.path = record.path;
                row.away_ms = Some(record.away_ms);
                row.restart_ms = record.restart_ms;
                row
            })
            .collect();
        let measured_count = measured.len() as i64;
        // UX-43 (owner decision 2026-07-10, two-sided): when every return
        // was measured, the leading "N measured returns today" already
        // states the count once — no trailing clause repeats it.
        let total_clause = if total_count != measured_count {
            format!(" Returned after this path {total_count} times today.")
        } else {
            String::new()
        };
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(
                DISCOVERY_NOTICE_TYPE_RETURN_TOLL,
                &[anchor.clone(), diverter.clone()],
            ),
            notice_type: DISCOVERY_NOTICE_TYPE_RETURN_TOLL.to_string(),
            title: format!("{anchor} -> {diverter} -> {anchor}"),
            summary: format!(
                "{measured_count} measured returns today; median restart {median_restart_seconds:.1}s; estimated restart toll {}.{}",
                notice_duration_text(estimated_restart_ms),
                total_clause,
            ),
            detail: NOTICE_DETAIL_RETURN_TOLL.to_string(),
            baseline: String::new(),
            support_count: measured_count.into(),
            total_count: total_count.into(),
            sort_score: estimated_restart_ms as f64,
            median_restart_seconds: Some(median_restart_seconds),
            estimated_restart_minutes: Some(round_2dp(estimated_restart_ms as f64 / 60_000.0)),
            evidence,
        });
    }
    Ok(notices)
}

#[derive(Debug, Clone)]
struct NotificationReceipt {
    session_id: i64,
    ts: i64,
    local_date: String,
    app: String,
    count: Value,
}

#[derive(Debug, Clone)]
struct PreparedNotificationReceipt {
    ts: i64,
    local_date: String,
    app: String,
    count: i64,
}

// These two readers get their payload scalars from SQLite, just like the
// pandas oracle. Python then calls `int()` on count metadata: reals truncate,
// integer strings parse, and non-numeric strings fail the read. The Rust API's
// persisted scalar contract is intentionally i64-bounded: a hand-edited REAL
// outside that range fails closed instead of materializing Python's unbounded
// integer. This accepted S2 narrowing is documented in the final review packet.
fn python_int_from_sql_value(value: Value, column: usize) -> rusqlite::Result<Option<i64>> {
    match value {
        Value::Null => Ok(None),
        Value::Integer(value) => Ok(Some(value)),
        Value::Real(value) if value.is_finite() => {
            let truncated = value.trunc();
            if truncated < i64::MIN as f64 || truncated >= -(i64::MIN as f64) {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    column,
                    Type::Real,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SQLite real is outside the reader's i64 range",
                    )),
                ));
            }
            Ok(Some(truncated as i64))
        }
        Value::Real(_) => Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Real,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SQLite real is not finite",
            )),
        )),
        Value::Text(value) => value.trim().parse::<i64>().map(Some).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
        }),
        Value::Blob(_) => Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SQLite blob cannot be converted with Python int() semantics",
            )),
        )),
    }
}

// `_read_notification_receipts` applies `str()` before `display_app`.
fn python_string_from_sql_value(value: Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Integer(value) => value.to_string(),
        Value::Real(value) => format!("{value:?}"),
        Value::Text(value) => value,
        Value::Blob(value) => format!("{value:?}"),
    }
}

fn python_count_from_sql_value(value: Value, column: usize) -> rusqlite::Result<i64> {
    let count = match &value {
        Value::Null | Value::Integer(0) => 1,
        Value::Real(value) if *value == 0.0 => 1,
        Value::Text(value) if value.is_empty() => 1,
        Value::Blob(value) if value.is_empty() => 1,
        _ => python_int_from_sql_value(value, column)?.unwrap_or(1),
    };
    Ok(count.max(1))
}

fn read_notification_receipts(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<NotificationReceipt>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT e.session_id, e.ts,
                COALESCE(
                    NULLIF(e.title, ''),
                    NULLIF(json_extract(e.payload, '$.app'), ''),
                    '(unknown)'
                ) AS app,
                COALESCE(json_extract(e.payload, '$.count'), 1) AS count
         FROM events e
         WHERE e.kind = 'notifications_received'
           AND {where_clause}
         ORDER BY e.session_id, e.ts, e.id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let ts: i64 = row.get(1)?;
        let app = python_string_from_sql_value(row.get(2)?);
        out.push(NotificationReceipt {
            session_id: row.get(0)?,
            ts,
            local_date: local_date(ts),
            app,
            count: row.get(3)?,
        });
    }
    Ok(out)
}

fn notification_app_match_key(app: &str) -> String {
    let mut text = display_app(Some(app)).to_lowercase().trim().to_string();
    if text.is_empty() || text == "(unknown)" || text == "<redacted>" {
        return String::new();
    }
    if let Some(stripped) = text.strip_suffix(".exe") {
        text = stripped.to_string();
    }
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

#[derive(Debug, Clone)]
struct NotificationAdjacentRecord {
    source_app: String,
    anchor: String,
    notification_ts: i64,
    notification_count: i64,
    switch_latency_ms: i64,
    away_ms: i64,
    restart_ms: i64,
    local_date: String,
}

fn notification_adjacent_records(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<NotificationAdjacentRecord>> {
    let segments = active_app_focus_segments(conn, scope)?;
    if segments.is_empty() {
        return Ok(Vec::new());
    }
    let productive_ts = productive_input_map(conn, scope)?;
    let notifications = read_notification_receipts(conn, scope)?;
    if notifications.is_empty() {
        return Ok(Vec::new());
    }
    let runs = same_app_focus_runs(&segments);
    let mut diversion_records: Vec<DiversionCostRecord> =
        diversion_cost_records(&runs, &productive_ts)
            .into_iter()
            .filter(|record| record.restart_ms.is_some())
            .collect();
    if diversion_records.is_empty() {
        return Ok(Vec::new());
    }

    let mut notifications_by_key: HashMap<
        (i64, String),
        (Vec<i64>, Vec<PreparedNotificationReceipt>),
    > = HashMap::new();
    for receipt in notifications {
        let source_app = display_app(Some(&receipt.app));
        let match_key = notification_app_match_key(&source_app);
        if match_key.is_empty() {
            continue;
        }
        let count = python_count_from_sql_value(receipt.count, 3)?;
        let key = (receipt.session_id, match_key);
        let entry = notifications_by_key
            .entry(key)
            .or_insert_with(|| (Vec::new(), Vec::new()));
        entry.0.push(receipt.ts);
        entry.1.push(PreparedNotificationReceipt {
            ts: receipt.ts,
            local_date: receipt.local_date,
            app: source_app,
            count,
        });
    }

    diversion_records.sort_by_key(|record| (record.session_id, record.diverter_start_ts));
    let mut matched = Vec::new();
    let mut used_notifications: HashSet<(i64, String, usize)> = HashSet::new();
    for record in diversion_records {
        let session_id = record.session_id;
        let source_key = notification_app_match_key(&record.diverter);
        let Some((ts_list, rows)) = notifications_by_key.get(&(session_id, source_key.clone()))
        else {
            continue;
        };
        if ts_list.is_empty() {
            continue;
        }
        let switch_ts = record.diverter_start_ts;
        let mut index = ts_list.partition_point(|ts| *ts <= switch_ts);
        if index == 0 {
            continue;
        }
        index -= 1;
        let mut chosen_index = None;
        loop {
            let notification_ts = ts_list[index];
            if switch_ts - notification_ts > NOTIFICATION_ADJACENT_MAX_SWITCH_MS {
                break;
            }
            let use_key = (session_id, source_key.clone(), index);
            if !used_notifications.contains(&use_key) {
                used_notifications.insert(use_key);
                chosen_index = Some(index);
                break;
            }
            if index == 0 {
                break;
            }
            index -= 1;
        }
        let Some(chosen_index) = chosen_index else {
            continue;
        };
        let notification = &rows[chosen_index];
        matched.push(NotificationAdjacentRecord {
            source_app: notification.app.clone(),
            anchor: record.anchor,
            notification_ts: notification.ts,
            notification_count: notification.count,
            switch_latency_ms: (switch_ts - notification.ts).max(0),
            away_ms: record.away_ms,
            restart_ms: record.restart_ms.unwrap_or(0),
            local_date: notification.local_date.clone(),
        });
    }
    Ok(matched)
}

fn notification_receipt_note(count: i64) -> String {
    format!(
        "{} receipt{} in poll pass",
        count,
        if count == 1 { "" } else { "s" }
    )
}

fn notification_adjacent_notices(
    conn: &Connection,
    now_ms: i64,
) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let records = notification_adjacent_records(conn, &discovery_baseline_scope(now_ms))?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    type NotificationGroup = (
        Vec<NotificationAdjacentRecord>,
        HashSet<String>,
        i128,
        Vec<i64>,
    );
    let mut grouped: Vec<((String, String), NotificationGroup)> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for record in records {
        let key = (record.source_app.clone(), record.anchor.clone());
        let position = if let Some(position) = index.get(&key) {
            *position
        } else {
            index.insert(key.clone(), grouped.len());
            grouped.push((key.clone(), (Vec::new(), HashSet::new(), 0, Vec::new())));
            grouped.len() - 1
        };
        let entry = &mut grouped[position].1;
        entry.1.insert(record.local_date.clone());
        entry.2 += i128::from(record.notification_count);
        entry.3.push(record.restart_ms);
        entry.0.push(record);
    }

    let mut notices = Vec::new();
    for ((source_app, anchor), (records, dates, receipt_count, _restart_ms)) in grouped {
        let support_days = dates.len();
        if receipt_count < i128::from(NOTIFICATION_ADJACENT_MIN_MATCHES)
            || support_days < NOTIFICATION_ADJACENT_MIN_DAYS
        {
            continue;
        }
        let mut today_records: Vec<NotificationAdjacentRecord> = records
            .into_iter()
            .filter(|record| record.notification_ts >= today_start)
            .collect();
        if today_records.is_empty() {
            continue;
        }
        today_records.sort_by_key(|record| std::cmp::Reverse(record.notification_ts));
        let today_receipts: i128 = today_records
            .iter()
            .map(|record| i128::from(record.notification_count))
            .sum();
        let today_restarts: Vec<i64> = today_records
            .iter()
            .map(|record| record.restart_ms)
            .collect();
        let Some(median_restart_seconds) = median_seconds(&today_restarts) else {
            continue;
        };
        let estimated_restart_ms =
            (median_restart_seconds * 1000.0 * today_records.len() as f64).round_ties_even() as i64;
        let evidence = today_records
            .iter()
            .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
            .map(|record| {
                let mut row = DiscoveryNoticeEvidence::at(record.notification_ts);
                row.path = vec![anchor.clone(), source_app.clone(), anchor.clone()];
                row.duration_ms = Some(record.switch_latency_ms);
                row.away_ms = Some(record.away_ms);
                row.restart_ms = Some(record.restart_ms);
                row.note = notification_receipt_note(record.notification_count);
                row
            })
            .collect();
        let today_returns = today_records.len() as i64;
        let baseline = format!(
            "Recent support: {receipt_count} notification-adjacent receipts across {support_days} local dates."
        );
        // Python first evaluates the complete integer expression with its
        // unbounded integers and only then converts the score to float. Keep
        // every persisted i64 count exact through both aggregates and the
        // multiplication, then make the same single integer-to-f64 cast.
        let sort_score = i128::from(estimated_restart_ms)
            + today_receipts * i128::from(NOTIFICATION_ADJACENT_MAX_SWITCH_MS);
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(
                DISCOVERY_NOTICE_TYPE_NOTIFICATION_ADJACENT,
                &[source_app.clone(), anchor.clone()],
            ),
            notice_type: DISCOVERY_NOTICE_TYPE_NOTIFICATION_ADJACENT.to_string(),
            title: format!("Notification-adjacent returns: {source_app} -> {anchor}"),
            summary: format!(
                "{today_receipts} {source_app} notification-adjacent receipt{} today preceded switches into {source_app} before returning to {anchor}; {today_returns} measured return{}, median restart {median_restart_seconds:.1}s. {baseline}",
                if today_receipts == 1 { "" } else { "s" },
                if today_returns == 1 { "" } else { "s" },
            ),
            detail: NOTICE_DETAIL_NOTIFICATION_ADJACENT.to_string(),
            baseline,
            support_count: today_receipts,
            total_count: receipt_count,
            sort_score: sort_score as f64,
            median_restart_seconds: Some(median_restart_seconds),
            estimated_restart_minutes: Some(round_2dp(estimated_restart_ms as f64 / 60_000.0)),
            evidence,
        });
    }
    Ok(notices)
}

fn input_dense_notices(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let scope = discovery_baseline_scope(now_ms);
    let runs = input_runs(conn, &scope)?;
    if runs.is_empty() {
        return Ok(Vec::new());
    }
    let prior_ms: Vec<i64> = runs
        .iter()
        .filter(|run| run.max_ts < today_start && run.run_ms >= SWITCH_RATE_MIN_ACTIVE_MS)
        .map(|run| run.run_ms)
        .collect();
    let (p75_ms, baseline) = duration_baseline_text(&prior_ms);
    let threshold = INPUT_DENSE_NOTICE_MIN_MS.max(p75_ms.unwrap_or(INPUT_EXPOSURE_LONG_RUN_MS));
    let today_runs: Vec<InputRun> = runs
        .into_iter()
        .filter(|run| {
            run.max_ts >= today_start
                && run.run_ms >= INPUT_DENSE_NOTICE_MIN_MS
                && run.run_ms >= threshold
        })
        .collect();
    if today_runs.is_empty() {
        return Ok(Vec::new());
    }
    let mut grouped: Vec<(String, Vec<InputRun>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for run in today_runs {
        let app = dominant_input_app(&run);
        let position = if let Some(position) = index.get(&app) {
            *position
        } else {
            index.insert(app.clone(), grouped.len());
            grouped.push((app, Vec::new()));
            grouped.len() - 1
        };
        grouped[position].1.push(run);
    }
    let mut notices = Vec::new();
    for (app, mut app_runs) in grouped {
        app_runs.sort_by_key(|run| std::cmp::Reverse(run.run_ms));
        let Some(longest) = app_runs.first() else {
            continue;
        };
        let mut evidence_runs = app_runs.clone();
        evidence_runs.sort_by_key(|run| std::cmp::Reverse(run.min_ts));
        let evidence = evidence_runs
            .into_iter()
            .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
            .map(|run| {
                let mut row = DiscoveryNoticeEvidence::at(run.min_ts);
                row.path = vec![app.clone()];
                row.duration_ms = Some(run.run_ms);
                row.input_events = Some(run.event_count);
                row
            })
            .collect();
        let count = app_runs.len() as i64;
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(
                DISCOVERY_NOTICE_TYPE_INPUT_DENSE,
                std::slice::from_ref(&app),
            ),
            notice_type: DISCOVERY_NOTICE_TYPE_INPUT_DENSE.to_string(),
            title: if count == 1 {
                format!("Input-dense span in {app}")
            } else {
                format!("Input-dense spans in {app}")
            },
            summary: format!(
                "{count} input-dense span{} today; longest {} with {} input events. {baseline}",
                if count == 1 { "" } else { "s" },
                notice_duration_text(longest.run_ms),
                longest.event_count,
            ),
            detail: NOTICE_DETAIL_INPUT_DENSE.to_string(),
            baseline: baseline.clone(),
            support_count: count.into(),
            total_count: count.into(),
            sort_score: app_runs.iter().map(|run| run.run_ms).sum::<i64>() as f64,
            evidence,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
        });
    }
    Ok(notices)
}

fn episode_switch_rate(episode: &WorkEpisode) -> Option<f64> {
    (episode.active_ms > 0)
        .then_some(episode.switch_count as f64 / (episode.active_ms as f64 / 3_600_000.0))
}

fn episode_fragmentation_notices(
    conn: &Connection,
    now_ms: i64,
) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let collected = collect_work_episodes(conn, &discovery_baseline_scope(now_ms), false)?;
    if collected.is_empty() {
        return Ok(Vec::new());
    }
    let episodes: Vec<WorkEpisode> = collected.into_iter().map(|(episode, _)| episode).collect();
    let prior_rates: Vec<f64> = episodes
        .iter()
        .filter(|episode| {
            episode.end_ms < today_start && episode.active_ms >= EPISODE_FRAGMENTATION_MIN_ACTIVE_MS
        })
        .filter_map(episode_switch_rate)
        .collect();
    let (p75_rate, baseline) = rate_baseline_text(&prior_rates, "switches/hr");
    let threshold = EPISODE_FRAGMENTATION_MIN_SWITCHES_PER_HOUR
        .max(p75_rate.unwrap_or(EPISODE_FRAGMENTATION_MIN_SWITCHES_PER_HOUR));
    let mut today_episodes: Vec<(WorkEpisode, f64)> = Vec::new();
    for episode in episodes {
        let Some(rate) = episode_switch_rate(&episode) else {
            continue;
        };
        if episode.end_ms >= today_start
            && episode.active_ms >= EPISODE_FRAGMENTATION_MIN_ACTIVE_MS
            && episode.switch_count >= EPISODE_FRAGMENTATION_MIN_SWITCHES
            && rate >= threshold
        {
            today_episodes.push((episode, rate));
        }
    }
    if today_episodes.is_empty() {
        return Ok(Vec::new());
    }
    today_episodes.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| right.0.switch_count.cmp(&left.0.switch_count))
    });
    let (top, top_rate) = today_episodes[0].clone();
    let mut evidence_rows = today_episodes.clone();
    evidence_rows.sort_by_key(|(episode, _)| std::cmp::Reverse(episode.end_ms));
    let evidence = evidence_rows
        .into_iter()
        .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
        .map(|(episode, rate)| {
            let mut row = DiscoveryNoticeEvidence::at(episode.end_ms);
            row.path = episode
                .apps
                .iter()
                .take(4)
                .map(|app| app.app.clone())
                .collect();
            row.duration_ms = Some(episode.active_ms);
            row.switch_count = Some(episode.switch_count);
            row.rate = Some(round_1dp(rate));
            row
        })
        .collect();
    let app_text = top
        .apps
        .iter()
        .take(3)
        .map(|app| app.app.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let count = today_episodes.len() as i64;
    Ok(vec![DiscoveryNotice {
        notice_key: discovery_notice_key(
            DISCOVERY_NOTICE_TYPE_EPISODE_FRAGMENTATION,
            &[top.dominant_app.clone(), local_date(top.start_ms)],
        ),
        notice_type: DISCOVERY_NOTICE_TYPE_EPISODE_FRAGMENTATION.to_string(),
        title: if count == 1 {
            "Fragmented app-only episode".to_string()
        } else {
            "Fragmented app-only episodes".to_string()
        },
        summary: format!(
            "{count} app-only episode{} ended today above the recent switch-density floor. The largest had {} switches over {} ({top_rate:.1}/hr). Dominant apps: {app_text}. {baseline}",
            if count == 1 { "" } else { "s" },
            top.switch_count,
            notice_duration_text(top.active_ms),
        ),
        detail: NOTICE_DETAIL_EPISODE_FRAGMENTATION.to_string(),
        baseline,
        support_count: count.into(),
        total_count: count.into(),
        sort_score: today_episodes
            .iter()
            .map(|(episode, rate)| rate * episode.switch_count as f64)
            .sum(),
        evidence,
        median_restart_seconds: None,
        estimated_restart_minutes: None,
    }])
}

#[derive(Debug, Clone)]
struct SequenceStep {
    app: String,
    ts: i64,
    session_id: i64,
    local_date: String,
}

fn focus_sequence_episodes(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<Vec<SequenceStep>>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT e.session_id, e.ts, e.exe
         FROM events e
         WHERE e.kind = 'focus_changed'
           AND e.exe IS NOT NULL
           AND {where_clause}
         ORDER BY e.session_id, e.seq"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut episodes: Vec<Vec<SequenceStep>> = Vec::new();
    let mut current: Vec<SequenceStep> = Vec::new();
    let mut prev_session: Option<i64> = None;
    let mut prev_ts: Option<i64> = None;
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let exe: String = row.get(2)?;
        let broke = prev_session.is_some_and(|prev| prev != session_id)
            || prev_ts.is_some_and(|prev| ts - prev > EPISODE_GAP_MS);
        if broke && !current.is_empty() {
            episodes.push(std::mem::take(&mut current));
        }
        let app = display_app(Some(&exe));
        if app != "(unknown)" && current.last().map(|step| step.app.as_str()) != Some(app.as_str())
        {
            current.push(SequenceStep {
                app,
                ts,
                session_id,
                local_date: local_date(ts),
            });
        }
        prev_session = Some(session_id);
        prev_ts = Some(ts);
    }
    if !current.is_empty() {
        episodes.push(current);
    }
    Ok(episodes)
}

fn has_enough_history(episodes: &[Vec<SequenceStep>]) -> bool {
    let dates: HashSet<String> = episodes
        .iter()
        .flat_map(|episode| episode.iter().map(|step| step.local_date.clone()))
        .collect();
    dates.len() >= SEQUENCE_MIN_HISTORY_DAYS
}

#[derive(Debug, Clone)]
struct SequenceExample {
    start_ts: i64,
    duration_ms: i64,
    local_date: String,
}

#[derive(Debug, Clone)]
struct SequenceMotif {
    window: Vec<String>,
    count: i64,
    dates: HashSet<String>,
    step_ms: Vec<i64>,
    examples: Vec<SequenceExample>,
}

fn sequence_motif_records(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<SequenceMotif>> {
    let episodes = focus_sequence_episodes(conn, scope)?;
    if episodes.is_empty() || !has_enough_history(&episodes) {
        return Ok(Vec::new());
    }
    let mut motifs: Vec<SequenceMotif> = Vec::new();
    let mut index: HashMap<Vec<String>, usize> = HashMap::new();
    for episode in episodes {
        let apps: Vec<String> = episode.iter().map(|step| step.app.clone()).collect();
        let times: Vec<i64> = episode.iter().map(|step| step.ts).collect();
        let count = apps.len();
        for length in 3..=SEQUENCE_MOTIF_MAX_LEN {
            if length > count {
                continue;
            }
            for start in 0..=(count - length) {
                let window: Vec<String> = apps[start..start + length].to_vec();
                let unique: HashSet<&String> = window.iter().collect();
                if unique.len() < 2 {
                    continue;
                }
                let position = if let Some(position) = index.get(&window) {
                    *position
                } else {
                    if motifs.len() >= MOTIF_TRACKING_CAP {
                        continue;
                    }
                    index.insert(window.clone(), motifs.len());
                    motifs.push(SequenceMotif {
                        window: window.clone(),
                        count: 0,
                        dates: HashSet::new(),
                        step_ms: Vec::new(),
                        examples: Vec::new(),
                    });
                    motifs.len() - 1
                };
                let motif = &mut motifs[position];
                motif.count += 1;
                motif.dates.insert(episode[start].local_date.clone());
                for idx in start..start + length - 1 {
                    motif.step_ms.push((times[idx + 1] - times[idx]).max(0));
                }
                motif.examples.push(SequenceExample {
                    start_ts: times[start],
                    duration_ms: (times[start + length - 1] - times[start]).max(0),
                    local_date: episode[start].local_date.clone(),
                });
                let _ = episode[start].session_id;
            }
        }
    }
    Ok(motifs)
}

fn sequence_notices(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_key = discovery_today_key(now_ms);
    let motifs = sequence_motif_records(conn, &discovery_baseline_scope(now_ms))?;
    let mut notices = Vec::new();
    for motif in motifs {
        let support_count = motif.count;
        let support_days = motif.dates.len();
        if support_count < SEQUENCE_MIN_SUPPORT || support_days < SEQUENCE_MIN_DAYS {
            continue;
        }
        let median_step_ms = median_i64_as_f64(&mut motif.step_ms.clone()).unwrap_or(0.0);
        if median_step_ms > SEQUENCE_TIGHTNESS_MAX_MS {
            continue;
        }
        let mut today_examples: Vec<SequenceExample> = motif
            .examples
            .into_iter()
            .filter(|example| example.local_date == today_key)
            .collect();
        if today_examples.is_empty() {
            continue;
        }
        today_examples.sort_by_key(|example| std::cmp::Reverse(example.start_ts));
        let evidence = today_examples
            .iter()
            .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
            .map(|example| {
                let mut row = DiscoveryNoticeEvidence::at(example.start_ts);
                row.path = motif.window.clone();
                row.duration_ms = Some(example.duration_ms);
                row
            })
            .collect();
        let today_count = today_examples.len() as i64;
        let baseline = format!(
            "Seen {support_count} times across {support_days} local dates in the recent window."
        );
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(DISCOVERY_NOTICE_TYPE_SEQUENCE, &motif.window),
            notice_type: DISCOVERY_NOTICE_TYPE_SEQUENCE.to_string(),
            title: format!("Recurring sequence: {}", motif.window.join(" -> ")),
            summary: format!(
                "This sequence appeared {today_count} time{} today; median step {:.1}s. {baseline}",
                if today_count == 1 { "" } else { "s" },
                median_step_ms / 1000.0,
            ),
            detail: NOTICE_DETAIL_SEQUENCE.to_string(),
            baseline,
            support_count: today_count.into(),
            total_count: support_count.into(),
            sort_score: support_count as f64
                * motif.window.len() as f64
                * (1.0 / (1.0 + median_step_ms / 1000.0)),
            evidence,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
        });
    }
    Ok(notices)
}

#[derive(Debug, Clone)]
struct ClipboardBridgeRecord {
    session_id: i64,
    ts: i64,
    source: String,
    destination: String,
    handoff_ms: i64,
    text_char_count: Option<i64>,
    local_date: String,
}

fn clipboard_bridge_records(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<ClipboardBridgeRecord>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let clip_sql = format!(
        "SELECT e.session_id, e.seq, e.ts,
                json_extract(e.payload, '$.text_char_count') AS text_char_count
         FROM events e
         WHERE e.kind = 'clipboard_used' AND {where_clause}
         ORDER BY e.session_id, e.seq"
    );
    let mut stmt = conn.prepare(&clip_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.clone()))?;
    let mut clips: Vec<(i64, i64, i64, Value)> = Vec::new();
    while let Some(row) = rows.next()? {
        clips.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
    }
    if clips.is_empty() {
        return Ok(Vec::new());
    }

    let focus_sql = format!(
        "SELECT e.session_id, e.seq, e.ts, e.exe
         FROM events e
         WHERE e.kind = 'focus_changed' AND e.exe IS NOT NULL AND {where_clause}
         ORDER BY e.session_id, e.seq"
    );
    let mut stmt = conn.prepare(&focus_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.clone()))?;
    let mut focus_by_session: SessionSeqItems = HashMap::new();
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let seq: i64 = row.get(1)?;
        let ts: i64 = row.get(2)?;
        let exe: String = row.get(3)?;
        let entry = focus_by_session
            .entry(session_id)
            .or_insert_with(|| (Vec::new(), Vec::new()));
        entry.0.push(seq);
        entry.1.push((ts, display_app(Some(&exe))));
    }

    let chord_sql = format!(
        "SELECT e.session_id, e.seq, e.ts, e.exe
         FROM events e
         WHERE e.kind = 'key'
           AND e.mod_ctrl = 1
           AND e.exe IS NOT NULL
           AND {where_clause}
         ORDER BY e.session_id, e.seq"
    );
    let mut stmt = conn.prepare(&chord_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut chords_by_session: SessionSeqItems = HashMap::new();
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let seq: i64 = row.get(1)?;
        let ts: i64 = row.get(2)?;
        let exe: String = row.get(3)?;
        let entry = chords_by_session
            .entry(session_id)
            .or_insert_with(|| (Vec::new(), Vec::new()));
        entry.0.push(seq);
        entry.1.push((ts, display_app(Some(&exe))));
    }
    if focus_by_session.is_empty() || chords_by_session.is_empty() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for (session_id, seq, ts, text_char_count) in clips {
        let Some((focus_seqs, focus_items)) = focus_by_session.get(&session_id) else {
            continue;
        };
        let index = focus_seqs.partition_point(|focus_seq| *focus_seq < seq);
        if index == 0 {
            continue;
        }
        let source = focus_items[index - 1].1.clone();
        if source == "(unknown)" {
            continue;
        }
        let mut destination: Option<String> = None;
        let mut switch_ts: Option<i64> = None;
        for (later_ts, later_app) in focus_items.iter().skip(index) {
            if *later_ts - ts > CLIPBOARD_BRACKET_MS {
                break;
            }
            if later_app != &source && later_app != "(unknown)" {
                destination = Some(later_app.clone());
                switch_ts = Some(*later_ts);
                break;
            }
        }
        let (Some(destination), Some(switch_ts)) = (destination, switch_ts) else {
            continue;
        };
        let Some((chord_seqs, chord_items)) = chords_by_session.get(&session_id) else {
            continue;
        };
        let mut has_chord = false;
        for (chord_ts, chord_app) in chord_items
            .iter()
            .skip(chord_seqs.partition_point(|chord_seq| *chord_seq <= seq))
        {
            if *chord_ts - ts > CLIPBOARD_BRACKET_MS {
                break;
            }
            if *chord_ts >= switch_ts && chord_app == &destination {
                has_chord = true;
                break;
            }
        }
        if !has_chord {
            continue;
        }
        let text_char_count = python_int_from_sql_value(text_char_count, 3)?;
        records.push(ClipboardBridgeRecord {
            session_id,
            ts,
            source,
            destination,
            handoff_ms: (switch_ts - ts).max(0),
            text_char_count,
            local_date: local_date(ts),
        });
    }
    Ok(records)
}

fn clipboard_size_note(value: Option<i64>) -> String {
    let Some(count) = value else {
        return String::new();
    };
    if count < 100 {
        "small text metadata".to_string()
    } else if count < 1_000 {
        "medium text metadata".to_string()
    } else {
        "large text metadata".to_string()
    }
}

fn clipboard_bridge_notices(
    conn: &Connection,
    now_ms: i64,
) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let records = clipboard_bridge_records(conn, &discovery_baseline_scope(now_ms))?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    type ClipboardGroup = (
        Vec<ClipboardBridgeRecord>,
        HashSet<String>,
        HashMap<String, i64>,
        Vec<i64>,
        Vec<i64>,
    );
    let mut grouped: Vec<((String, String), ClipboardGroup)> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for record in records {
        let key = (record.source.clone(), record.destination.clone());
        let position = if let Some(position) = index.get(&key) {
            *position
        } else {
            index.insert(key.clone(), grouped.len());
            grouped.push((
                key.clone(),
                (
                    Vec::new(),
                    HashSet::new(),
                    HashMap::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ));
            grouped.len() - 1
        };
        let entry = &mut grouped[position].1;
        entry.1.insert(record.local_date.clone());
        *entry.2.entry(record.local_date.clone()).or_insert(0) += 1;
        entry.3.push(record.handoff_ms);
        if let Some(count) = record.text_char_count {
            entry.4.push(count);
        }
        entry.0.push(record);
    }

    let mut notices = Vec::new();
    for ((source, destination), (records, dates, per_date, handoff_ms, char_counts)) in grouped {
        let support_count = records.len();
        let support_days = dates.len();
        if support_count < CLIPBOARD_TRANSFER_MIN_SUPPORT || support_days < SEQUENCE_MIN_DAYS {
            continue;
        }
        let max_per_date = per_date.values().copied().max().unwrap_or(0);
        if max_per_date as f64 / support_count as f64 > CLIPBOARD_TOP_DAY_SHARE_MAX {
            continue;
        }
        let mut today_records: Vec<ClipboardBridgeRecord> = records
            .into_iter()
            .filter(|record| record.ts >= today_start)
            .collect();
        if today_records.is_empty() {
            continue;
        }
        today_records.sort_by_key(|record| std::cmp::Reverse(record.ts));
        let median_handoff = median_i64_as_f64(&mut handoff_ms.clone()).unwrap_or(0.0) as i64;
        let text_clause = if char_counts.is_empty() {
            String::new()
        } else {
            let median_chars = median_i64_as_f64(&mut char_counts.clone()).unwrap_or(0.0) as i64;
            format!(" Median text metadata {median_chars} characters when present.")
        };
        let evidence = today_records
            .iter()
            .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
            .map(|record| {
                let mut row = DiscoveryNoticeEvidence::at(record.ts);
                row.path = vec![source.clone(), destination.clone()];
                row.duration_ms = Some(record.handoff_ms);
                row.note = clipboard_size_note(record.text_char_count);
                row
            })
            .collect();
        let today_count = today_records.len() as i64;
        let baseline =
            format!("Recent support: {support_count} bridges across {support_days} local dates.");
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(
                DISCOVERY_NOTICE_TYPE_CLIPBOARD,
                &[source.clone(), destination.clone()],
            ),
            notice_type: DISCOVERY_NOTICE_TYPE_CLIPBOARD.to_string(),
            title: format!("Clipboard bridge: {source} -> {destination}"),
            summary: format!(
                "{today_count} clipboard bridge{} today from {source} into {destination}; median handoff {}. {baseline}{text_clause}",
                if today_count == 1 { "" } else { "s" },
                notice_duration_text(median_handoff),
            ),
            detail: NOTICE_DETAIL_CLIPBOARD.to_string(),
            baseline,
            support_count: today_count.into(),
            total_count: support_count as i128,
            sort_score: (today_count * support_days.max(1) as i64 * 60_000 + median_handoff)
                as f64,
            evidence,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
        });
    }
    Ok(notices)
}

fn ramp_notices(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let records = ramp_records(conn, &discovery_baseline_scope(now_ms))?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let prior_ms: Vec<i64> = records
        .iter()
        .filter(|record| record.anchor_ts < today_start)
        .map(|record| record.duration_ms)
        .collect();
    let (p75_ms, baseline) = duration_baseline_text(&prior_ms);
    let threshold = RAMP_NOTICE_MIN_MS.max(p75_ms.unwrap_or(0));
    let mut today_records: Vec<RampRecord> = records
        .into_iter()
        .filter(|record| {
            record.anchor_ts >= today_start
                && record.duration_ms >= threshold
                && record.switch_count >= RAMP_NOTICE_MIN_SWITCHES
        })
        .collect();
    if today_records.is_empty() {
        return Ok(Vec::new());
    }
    today_records.sort_by_key(|record| {
        (
            std::cmp::Reverse(record.duration_ms),
            std::cmp::Reverse(record.switch_count),
        )
    });
    let top = today_records[0].clone();
    let mut evidence_records = today_records.clone();
    evidence_records.sort_by_key(|record| std::cmp::Reverse(record.anchor_ts));
    let evidence = evidence_records
        .into_iter()
        .take(DISCOVERY_NOTICE_EVIDENCE_LIMIT)
        .map(|record| {
            let mut row = DiscoveryNoticeEvidence::at(record.anchor_ts);
            row.path = record.path;
            row.duration_ms = Some(record.duration_ms);
            row.switch_count = Some(record.switch_count);
            row.note = record.anchor_label;
            row
        })
        .collect();
    let count = today_records.len() as i64;
    Ok(vec![DiscoveryNotice {
        notice_key: discovery_notice_key(
            DISCOVERY_NOTICE_TYPE_RAMP,
            &[top.anchor_label.clone(), top.sustained_app.clone()],
        ),
        notice_type: DISCOVERY_NOTICE_TYPE_RAMP.to_string(),
        title: format!("Return ramp before {}", top.sustained_app),
        summary: format!(
            "{count} return ramp{} today before a first sustained focus run. The longest was after {}: {} and {} app switches before {}. {baseline}",
            if count == 1 { "" } else { "s" },
            top.anchor_label,
            notice_duration_text(top.duration_ms),
            top.switch_count,
            top.sustained_app,
        ),
        detail: NOTICE_DETAIL_RAMP.to_string(),
        baseline,
        support_count: count.into(),
        total_count: count.into(),
        sort_score: today_records
            .iter()
            .map(|record| record.duration_ms)
            .sum::<i64>() as f64,
        evidence,
        median_restart_seconds: None,
        estimated_restart_minutes: None,
    }])
}

fn time_anchor_notices(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    let today_start = local_day_start_ms(now_ms);
    let mut windows =
        time_of_day_friction_windows(conn, &discovery_baseline_scope(now_ms), now_ms)?;
    windows.retain(|row| row.today_count > 0);
    if windows.is_empty() {
        return Ok(Vec::new());
    }
    windows.sort_by(|left, right| {
        right
            .days
            .cmp(&left.days)
            .then_with(|| right.today_count.cmp(&left.today_count))
            .then_with(|| right.value.total_cmp(&left.value))
    });
    let mut notices = Vec::new();
    for row in windows {
        let baseline = format!("Recent p75: {:.1} {}.", row.baseline, row.unit);
        let mut evidence = DiscoveryNoticeEvidence::at(today_start + (row.hour * 3_600_000));
        evidence.duration_ms = Some(3_600_000);
        evidence.rate = Some(row.value);
        evidence.note = format!("{}; {} today", row.signal, row.today_count);
        notices.push(DiscoveryNotice {
            notice_key: discovery_notice_key(
                DISCOVERY_NOTICE_TYPE_TIME_ANCHOR,
                &[row.signal.clone(), row.hour.to_string()],
            ),
            notice_type: DISCOVERY_NOTICE_TYPE_TIME_ANCHOR.to_string(),
            title: format!("Time-of-day anchor around {}", row.hour_label),
            summary: format!(
                "{} clustered around {} on {} recent local dates; today has {} supporting event{} in that hour. {baseline}",
                row.signal,
                row.hour_label,
                row.days,
                row.today_count,
                if row.today_count == 1 { "" } else { "s" },
            ),
            detail: NOTICE_DETAIL_TIME_ANCHOR.to_string(),
            baseline,
            support_count: row.today_count.into(),
            total_count: row.count.into(),
            sort_score: row.days as f64 * 1.0_f64.max(row.value) * 60_000.0,
            evidence: vec![evidence],
            median_restart_seconds: None,
            estimated_restart_minutes: None,
        });
    }
    Ok(notices)
}

/// Mirrors `read_discovery_notices`.
pub fn discovery_notices(
    conn: &Connection,
    now_ms: i64,
    limit: usize,
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    Ok(discovery_notices_with_hidden_count(conn, now_ms, limit, state, today_key)?.0)
}

/// The visible notices plus how many enumerated candidates the state's
/// dismiss/mute filters removed (UX-30). The hidden count is taken
/// pre-cap, over the SAME enumeration (including any state-driven
/// backfill) the visible list came from, so the display cap can never
/// erase it and the two figures can never come from different candidate
/// populations. Native-dashboard helper — the Streamlit oracle has no
/// hidden-count surface, and the shared `discovery_notices` output is
/// byte-identical to before.
pub fn discovery_notices_with_hidden_count(
    conn: &Connection,
    now_ms: i64,
    limit: usize,
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
) -> rusqlite::Result<(Vec<DiscoveryNotice>, usize)> {
    let state_today_key = effective_discovery_today_key(today_key, now_ms);
    let cap = limit;
    let mut notices = Vec::new();
    notices.extend(return_toll_notices(conn, now_ms)?);
    notices.extend(notification_adjacent_notices(conn, now_ms)?);
    notices.extend(input_dense_notices(conn, now_ms)?);
    notices.extend(episode_fragmentation_notices(conn, now_ms)?);
    notices.extend(clipboard_bridge_notices(conn, now_ms)?);
    notices.extend(sequence_notices(conn, now_ms)?);
    if needs_discovery_backfill(
        &notices,
        cap,
        state,
        &state_today_key,
        DISCOVERY_NOTICE_TYPE_RAMP,
    ) {
        notices.extend(ramp_notices(conn, now_ms)?);
    }
    if needs_discovery_backfill(
        &notices,
        cap,
        state,
        &state_today_key,
        DISCOVERY_NOTICE_TYPE_TIME_ANCHOR,
    ) {
        notices.extend(time_anchor_notices(conn, now_ms)?);
    }
    let hidden: HashSet<&str> = notices
        .iter()
        .filter(|notice| discovery_notice_hidden(notice, state, Some(&state_today_key), false))
        .map(|notice| notice.notice_key.as_str())
        .collect();
    let hidden_count = hidden.len();
    Ok((
        visible_discovery_notices(&notices, state, Some(&state_today_key), cap, false, true),
        hidden_count,
    ))
}

pub fn discovery_notices_default_limit(
    conn: &Connection,
    now_ms: i64,
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
) -> rusqlite::Result<Vec<DiscoveryNotice>> {
    discovery_notices(conn, now_ms, DISCOVERY_NOTICE_LIMIT, state, today_key)
}

/// [`discovery_notices_with_hidden_count`] at the default display cap.
pub fn discovery_notices_with_hidden_count_default_limit(
    conn: &Connection,
    now_ms: i64,
    state: Option<&DiscoveryNoticeState>,
    today_key: Option<&str>,
) -> rusqlite::Result<(Vec<DiscoveryNotice>, usize)> {
    discovery_notices_with_hidden_count(conn, now_ms, DISCOVERY_NOTICE_LIMIT, state, today_key)
}

/// One idle/sleep-punched app-focus band on the Today timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DayStripBand {
    pub app: String,
    pub start_ts: i64,
    pub end_ts: i64,
}

/// Mirrors `DayStripData`: one local day of app-focus bands plus the
/// coalesced away spans, all clipped to `[day_start, now]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DayStrip {
    pub day_start_ms: i64,
    pub day_end_ms: i64,
    pub focus: Vec<DayStripBand>,
    pub away: Vec<(i64, i64)>,
}

/// Mirrors `read_day_strip`: focus intervals scoped to the local day, each
/// session's own away spans punched out of its own bands only, and the away
/// marker line as the coalesced union across sessions.
pub fn day_strip(conn: &Connection, now_ms: i64) -> rusqlite::Result<DayStrip> {
    let day_start = local_day_start_ms(now_ms);
    let scope = Scope {
        cutoff_ms: Some(day_start),
        session_id: None,
    };
    let focus = focus_intervals(conn, &scope)?;
    if focus.is_empty() {
        return Ok(DayStrip {
            day_start_ms: day_start,
            day_end_ms: now_ms,
            focus: Vec::new(),
            away: Vec::new(),
        });
    }
    let ids: Vec<i64> = focus.iter().map(|row| row.session_id).collect();
    let idle = idle_intervals(conn, &ids, None)?;
    let sleep = sleep_intervals(conn, &ids)?;
    let away_by_session = away_spans_by_session(&idle, &sleep, day_start, now_ms);

    let empty: Vec<(i64, i64)> = Vec::new();
    let mut bands: Vec<DayStripBand> = Vec::new();
    for row in &focus {
        let band_start = row.start_ts.max(day_start);
        let band_end = row.end_ts.min(now_ms);
        if band_end <= band_start {
            continue;
        }
        // Punch out only this session's own idle/sleep — an idle span belongs
        // to one session's timeline and must not clip another session's band.
        let session_away = away_by_session.get(&row.session_id).unwrap_or(&empty);
        for (piece_start, piece_end) in subtract_spans(band_start, band_end, session_away) {
            bands.push(DayStripBand {
                app: display_app(Some(&row.exe)),
                start_ts: piece_start,
                end_ts: piece_end,
            });
        }
    }

    // The away marker line is the union of every session's away spans (they
    // do not normally overlap in wall-clock time).
    let away = coalesce_spans(away_by_session.into_values().flatten().collect());
    Ok(DayStrip {
        day_start_ms: day_start,
        day_end_ms: now_ms,
        focus: bands,
        away,
    })
}

/// One local-day hour of key and mouse event counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HourPulse {
    pub hour: i64,
    pub hour_start_ms: i64,
    pub key_events: i64,
    pub mouse_events: i64,
}

/// Mirrors `read_hourly_input_pulse`: per-hour key and mouse event counts
/// for the local day; the two modalities stay separate by design. Hours are
/// bucketed by SQLite `strftime('%H', ..., 'localtime')` and
/// `hour_start_ms` is `day_start + hour * 3_600_000`, exactly as in Python
/// (both sides share the same DST-day approximation).
pub fn hourly_input_pulse(conn: &Connection, now_ms: i64) -> rusqlite::Result<Vec<HourPulse>> {
    let day_start = local_day_start_ms(now_ms);
    let predicate = input_sweep_predicate("e");
    let sql = format!(
        "SELECT
            CAST(strftime('%H', e.ts / 1000, 'unixepoch', 'localtime') AS INTEGER)
                AS hour,
            SUM(CASE WHEN e.kind = 'key' THEN 1 ELSE 0 END) AS key_events,
            SUM(CASE WHEN e.kind != 'key' THEN 1 ELSE 0 END) AS mouse_events
        FROM events e
        WHERE e.ts >= ? AND e.ts <= ? AND {predicate}
        GROUP BY hour
        ORDER BY hour"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params![day_start, now_ms])?;
    let mut out: Vec<HourPulse> = Vec::new();
    while let Some(row) = rows.next()? {
        let hour: i64 = row.get(0)?;
        out.push(HourPulse {
            hour,
            hour_start_ms: day_start + hour * 3_600_000,
            key_events: row.get(1)?,
            mouse_events: row.get(2)?,
        });
    }
    Ok(out)
}

/// One trailing-window local day of active foreground minutes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DayActive {
    pub local_date: String,
    pub day_label: String,
    pub active_minutes: f64,
}

/// Python's `round(value, 2)`: correctly-rounded 2-decimal rounding of the
/// exact binary value, ties to even. Rust's fixed-precision float formatting
/// is the same correctly-rounded conversion; unit tests pin the tie cases.
fn round_2dp(value: f64) -> f64 {
    format!("{value:.2}")
        .parse()
        .expect("fixed-precision float always reparses")
}

/// pandas/NumPy `Series.round(2)` (`np.around`): scale by 100, IEEE
/// round-half-even on the scaled binary value, unscale. This disagrees with
/// Python's built-in `round` at ordinary binary boundaries (216535/1000 is
/// 216.53 built-in but 216.54 here, 25/1000 is 0.03 built-in but 0.02 here),
/// so every ported reader must use whichever helper its oracle call site
/// actually uses: `.round(2)` on a Series/column is this one.
///
/// Documented bound (2026-07-10 re-review SF-2): the helper itself is
/// exact against NumPy, but the average callers build the pre-rounding
/// value from an exact i64 sum where pandas accumulates a float group
/// mean. The two constructions part only once a single duration reaches
/// the 2^53 ms float-precision edge (285,000+ years) — outside what
/// monotonic-elapsed canonical capture can emit.
fn pandas_round_2dp(value: f64) -> f64 {
    (value * 100.0).round_ties_even() / 100.0
}

fn round_1dp(value: f64) -> f64 {
    format!("{value:.1}")
        .parse()
        .expect("fixed-precision float always reparses")
}

fn median_f64(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|left, right| left.total_cmp(right));
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[mid])
    } else {
        Some((values[mid - 1] + values[mid]) / 2.0)
    }
}

fn median_i64(values: &mut [i64]) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[mid])
    } else {
        Some(((values[mid - 1] + values[mid]) as f64 / 2.0) as i64)
    }
}

fn overlap_ms(a_lo: i64, a_hi: i64, b_lo: i64, b_hi: i64) -> i64 {
    0.max(a_hi.min(b_hi) - a_lo.max(b_lo))
}

/// Mirrors `read_daily_active_minutes`: active foreground minutes per local
/// day for the trailing `days` days, zero-filled so the strip always shows
/// the full window. Intervals are attributed to the local date they end on.
/// Day labels are chrono's fixed English `%a`, matching Python's C-locale
/// `strftime`.
pub fn daily_active_minutes(
    conn: &Connection,
    days: i64,
    now_ms: i64,
) -> rusqlite::Result<Vec<DayActive>> {
    use chrono::Duration;

    let day_count = days.max(1);
    let today_local = local_date_of(now_ms);
    let first_day = today_local - Duration::days(day_count - 1);
    let scope = Scope {
        cutoff_ms: Some(local_midnight_ms(first_day)),
        session_id: None,
    };
    let focus = focus_intervals_with_active(conn, &scope)?;
    let mut by_date: BTreeMap<String, i64> = BTreeMap::new();
    for row in &focus {
        *by_date.entry(row.local_date.clone()).or_insert(0) += row.active_foreground_ms;
    }
    let mut out: Vec<DayActive> = Vec::new();
    for offset in 0..day_count {
        let day = first_day + Duration::days(offset);
        let key = day.format("%Y-%m-%d").to_string();
        let active_ms = by_date.get(&key).copied().unwrap_or(0);
        out.push(DayActive {
            local_date: key,
            day_label: day.format("%a").to_string(),
            active_minutes: round_2dp(active_ms as f64 / 60_000.0),
        });
    }
    Ok(out)
}

/// Mirrors `TodayStory`: the Today tab's tile numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TodayStory {
    pub active_ms: i64,
    pub foreground_ms: i64,
    pub focus_switches: i64,
    pub keystrokes: i64,
    pub top_app: Option<String>,
    pub longest_run_app: Option<String>,
    pub longest_run_ms: i64,
    pub longest_run_start_ms: Option<i64>,
}

/// Mirrors `read_today_story`. Two pinned tie-breaks: `top_app` resolves a
/// tie at the maximum active time to the lexicographically-smallest raw exe
/// (pandas keeps the ascending groupby order among tied values), and equal
/// longest runs keep the first (strict `>`). The run sweep deliberately has
/// no session guard, exactly like Python: a same-exe run can merge across a
/// session boundary when the wall-clock gap is small enough.
pub fn today_story(conn: &Connection, now_ms: i64) -> rusqlite::Result<TodayStory> {
    let day_start = local_day_start_ms(now_ms);
    let scope = Scope {
        cutoff_ms: Some(day_start),
        session_id: None,
    };
    let focus = focus_intervals_with_active(conn, &scope)?;
    // The open-focus heartbeat (reader scope v1: active time and top app
    // only). This runs before the empty early-return because a first
    // unbroken stretch is exactly the case with zero completed rows.
    let open = live_open_focus(conn, now_ms)?;
    let open_contribution = match &open {
        Some(open) => open_focus_contribution(conn, open, day_start)?,
        None => None,
    };
    let keystrokes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE kind = 'key' AND ts >= ? AND ts <= ?",
        rusqlite::params![day_start, now_ms],
        |row| row.get(0),
    )?;
    if focus.is_empty() && open_contribution.is_none() {
        return Ok(TodayStory {
            active_ms: 0,
            foreground_ms: 0,
            focus_switches: 0,
            keystrokes,
            top_app: None,
            longest_run_app: None,
            longest_run_ms: 0,
            longest_run_start_ms: None,
        });
    }
    let (open_raw_ms, open_active_ms) = open_contribution.unwrap_or((0, 0));

    let mut active_by_app: BTreeMap<&str, i64> = BTreeMap::new();
    for row in &focus {
        *active_by_app.entry(row.exe.as_str()).or_insert(0) += row.active_foreground_ms;
    }
    if open_active_ms > 0 {
        if let Some(open) = &open {
            *active_by_app.entry(open.exe.as_str()).or_insert(0) += open_active_ms;
        }
    }
    let mut top: Option<(&str, i64)> = None;
    for (&exe, &total) in &active_by_app {
        if top.is_none_or(|(_, best)| total > best) {
            top = Some((exe, total));
        }
    }
    let top_app = top.and_then(|(exe, total)| (total > 0).then(|| display_app(Some(exe))));

    let mut ordered: Vec<&ActiveFocusInterval> = focus.iter().collect();
    ordered.sort_by_key(|row| (row.session_id, row.seq));
    let mut longest_app: Option<&str> = None;
    let mut longest_ms: i64 = 0;
    let mut longest_start: Option<i64> = None;
    let mut run_app: Option<&str> = None;
    let mut run_active: i64 = 0;
    let mut run_start: Option<i64> = None;
    let mut run_end: Option<i64> = None;
    for row in ordered {
        let same_run = run_app == Some(row.exe.as_str())
            && run_end.is_some_and(|end| row.start_ts - end <= TODAY_RUN_MERGE_GAP_MS);
        if same_run {
            run_active += row.active_foreground_ms;
            run_end = Some(row.end_ts);
        } else {
            run_app = Some(row.exe.as_str());
            run_active = row.active_foreground_ms;
            run_start = Some(row.start_ts);
            run_end = Some(row.end_ts);
        }
        if run_active > longest_ms {
            longest_ms = run_active;
            longest_app = run_app;
            longest_start = run_start;
        }
    }

    Ok(TodayStory {
        // The open interval counts toward both totals (it is real in-front
        // time) but is not a completed switch and joins no run.
        active_ms: focus
            .iter()
            .map(|row| row.active_foreground_ms)
            .sum::<i64>()
            + open_active_ms,
        foreground_ms: focus.iter().map(|row| row.duration_ms).sum::<i64>() + open_raw_ms,
        focus_switches: focus.len() as i64,
        keystrokes,
        top_app,
        longest_run_app: longest_app.map(|exe| display_app(Some(exe))),
        longest_run_ms: longest_ms,
        longest_run_start_ms: longest_start,
    })
}

/// One week-digest top-app row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DigestTopApp {
    pub app: String,
    pub active_ms: i64,
}

/// One first-after-idle row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstAfterIdle {
    pub app: String,
    pub count: i64,
}

/// One Rhythm/Week heatmap bucket.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HeatmapBucket {
    pub weekday: i64,
    pub weekday_label: String,
    pub hour: i64,
    pub active_minutes: f64,
}

/// The S2 stage-3 core of `WeeklyDigest`: the Week-tab reader fields whose
/// dependencies are in the reader-port substrate. The `friction` and
/// `changed_this_week` fields depend on later Discovery/pattern candidates and
/// stay out of this stage's Rust surface until those readers move.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WeeklyDigestCore {
    pub week_start_ms: i64,
    pub now_ms: i64,
    pub has_prior_week: bool,
    pub active_ms: i64,
    pub prior_active_ms: i64,
    pub active_days: i64,
    pub top_apps: Vec<DigestTopApp>,
    pub switches_per_active_hour: Option<f64>,
    pub prior_switches_per_active_hour: Option<f64>,
    pub keystrokes: i64,
    pub prior_keystrokes: i64,
    pub morning_launch: Vec<String>,
    pub morning_launch_days: i64,
    pub first_after_idle: Vec<FirstAfterIdle>,
    pub heatmap: Vec<HeatmapBucket>,
}

fn switch_rate(switches: i64, active_ms: i64) -> Option<f64> {
    (active_ms >= SWITCH_RATE_MIN_ACTIVE_MS)
        .then(|| round_2dp(switches as f64 / (active_ms as f64 / 3_600_000.0)))
}

fn bump_ordered<K: Eq + std::hash::Hash + Clone>(
    rows: &mut Vec<(K, i64)>,
    index: &mut HashMap<K, usize>,
    key: K,
    amount: i64,
) {
    if let Some(&position) = index.get(&key) {
        rows[position].1 += amount;
    } else {
        index.insert(key.clone(), rows.len());
        rows.push((key, amount));
    }
}

fn split_ms_by_weekday_hour_with<L, B>(
    start_ms: i64,
    end_ms: i64,
    mut local_hour_at: L,
    mut boundary_candidates: B,
) -> Vec<(i64, i64, i64)>
where
    L: FnMut(i64) -> Option<(chrono::NaiveDate, u32)>,
    B: FnMut(chrono::NaiveDateTime) -> LocalBoundaryCandidates,
{
    use chrono::Datelike;

    if end_ms <= start_ms {
        return Vec::new();
    }
    let mut pieces: Vec<(i64, i64, i64)> = Vec::new();
    let mut cursor = start_ms;
    while cursor < end_ms {
        let Some((local_date, local_hour)) = local_hour_at(cursor) else {
            return Vec::new();
        };
        let next_hour = local_date
            .and_hms_opt(local_hour, 0, 0)
            .expect("current local hour is valid")
            + chrono::Duration::hours(1);
        let candidate = match boundary_candidates(next_hour) {
            LocalBoundaryCandidates::Single(candidate) => candidate,
            // Advance through whichever ambiguous candidate is still ahead of
            // the cursor so both occurrences of a repeated hour are retained.
            LocalBoundaryCandidates::Ambiguous(first, second) => {
                ambiguous_candidate_after(first, second, cursor)
            }
        };
        let mut boundary = end_ms.min(candidate);
        if boundary <= cursor {
            boundary = end_ms;
        }
        pieces.push((
            local_date.weekday().num_days_from_monday() as i64,
            i64::from(local_hour),
            boundary - cursor,
        ));
        cursor = boundary;
    }
    pieces
}

fn split_ms_by_weekday_hour(start_ms: i64, end_ms: i64) -> Vec<(i64, i64, i64)> {
    use chrono::{Local, LocalResult, TimeZone, Timelike};

    split_ms_by_weekday_hour_with(
        start_ms,
        end_ms,
        |cursor| match Local.timestamp_millis_opt(cursor) {
            LocalResult::Single(dt) => Some((dt.date_naive(), dt.hour())),
            LocalResult::Ambiguous(first, _) => Some((first.date_naive(), first.hour())),
            LocalResult::None => None,
        },
        local_boundary_candidates,
    )
}

fn active_focus_spans(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<(i64, i64)>> {
    let focus = focus_intervals(conn, scope)?;
    if focus.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = focus.iter().map(|row| row.session_id).collect();
    let span_lo = focus.iter().map(|row| row.start_ts).min().unwrap_or(0);
    let span_hi = focus.iter().map(|row| row.end_ts).max().unwrap_or(0);
    let idle = idle_intervals(conn, &ids, None)?;
    let sleep = sleep_intervals(conn, &ids)?;
    let away_by_session = away_spans_by_session(&idle, &sleep, span_lo, span_hi);
    let empty: Vec<(i64, i64)> = Vec::new();
    let mut active: Vec<(i64, i64)> = Vec::new();
    for row in &focus {
        if row.end_ts <= row.start_ts {
            continue;
        }
        let session_away = away_by_session.get(&row.session_id).unwrap_or(&empty);
        active.extend(subtract_spans(row.start_ts, row.end_ts, session_away));
    }
    Ok(active)
}

/// Mirrors `_rhythm_heatmap`: active foreground spans split across local
/// weekday/hour buckets, preserving Python dict insertion order for rows.
pub fn rhythm_heatmap(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<HeatmapBucket>> {
    let mut buckets: Vec<((i64, i64), i64)> = Vec::new();
    let mut index: HashMap<(i64, i64), usize> = HashMap::new();
    for (start_ms, end_ms) in active_focus_spans(conn, scope)? {
        for (weekday, hour, duration_ms) in split_ms_by_weekday_hour(start_ms, end_ms) {
            bump_ordered(&mut buckets, &mut index, (weekday, hour), duration_ms);
        }
    }
    Ok(buckets
        .into_iter()
        .map(|((weekday, hour), ms)| HeatmapBucket {
            weekday,
            weekday_label: RHYTHM_WEEKDAY_LABELS[weekday as usize].to_string(),
            hour,
            active_minutes: round_2dp(ms as f64 / 60_000.0),
        })
        .collect())
}

/// The 7 local calendar dates ending today — the digest's active-day
/// window. The rolling 168-hour focus window can touch 8 local dates;
/// the Active-days tile and the morning-launch day count credit only
/// these 7, so "8 of 7" can never render (UX-01, decided 2026-07-10).
fn digest_week_dates(now_ms: i64) -> HashSet<String> {
    let today = local_date_of(now_ms);
    (0..7)
        .filter_map(|offset| today.checked_sub_days(chrono::Days::new(offset)))
        .map(|date| date.format("%Y-%m-%d").to_string())
        .collect()
}

fn digest_morning_launch(
    focus: &[FocusInterval],
    week_lo: i64,
    week_hi: i64,
    week_dates: &HashSet<String>,
) -> (Vec<String>, i64) {
    let mut by_date: BTreeMap<String, Vec<&FocusInterval>> = BTreeMap::new();
    for row in focus {
        if row.end_ts >= week_lo && row.end_ts < week_hi && week_dates.contains(&row.local_date) {
            by_date.entry(row.local_date.clone()).or_default().push(row);
        }
    }
    if by_date.is_empty() {
        return (Vec::new(), 0);
    }

    let mut sequences: Vec<Vec<String>> = Vec::new();
    for rows in by_date.values_mut() {
        rows.sort_by_key(|row| (row.session_id, row.seq));
        let Some(day_start) = rows.iter().map(|row| row.start_ts).min() else {
            continue;
        };
        let mut apps: Vec<String> = Vec::new();
        for row in rows
            .iter()
            .filter(|row| row.start_ts <= day_start + MORNING_WINDOW_MS)
        {
            let app = display_app(Some(&row.exe));
            if apps.last() != Some(&app) {
                apps.push(app);
            }
        }
        if !apps.is_empty() {
            sequences.push(apps);
        }
    }
    if sequences.is_empty() {
        return (Vec::new(), 0);
    }

    let mut launch: Vec<String> = Vec::new();
    for position in 0..3 {
        let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
        for sequence in &sequences {
            if let Some(app) = sequence.get(position) {
                *counts.entry(app.as_str()).or_insert(0) += 1;
            }
        }
        if counts.is_empty() {
            break;
        }
        let modal = counts
            .into_iter()
            .max_by_key(|(app, count)| (*count, std::cmp::Reverse(*app)))
            .map(|(app, _)| app.to_string())
            .expect("counts is not empty");
        if launch.last() == Some(&modal) {
            continue;
        }
        launch.push(modal);
    }
    (launch, sequences.len() as i64)
}

fn digest_first_after_idle(
    focus: &[FocusInterval],
    idle: &[SessionInterval],
    week_lo: i64,
    week_hi: i64,
) -> Vec<FirstAfterIdle> {
    let resumes: Vec<(i64, i64)> = idle
        .iter()
        .filter(|row| row.end_ts >= week_lo && row.end_ts < week_hi)
        .map(|row| (row.session_id, row.end_ts))
        .collect();
    if resumes.is_empty() || focus.is_empty() {
        return Vec::new();
    }

    let mut by_session: BTreeMap<i64, Vec<(i64, i64, String)>> = BTreeMap::new();
    for row in focus {
        by_session.entry(row.session_id).or_default().push((
            row.start_ts,
            row.end_ts,
            display_app(Some(&row.exe)),
        ));
    }
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for (session_id, resume_ts) in resumes {
        let intervals = by_session
            .get(&session_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut chosen: Option<&str> = None;
        let mut best_after: Option<(i64, &str)> = None;
        for (start_ts, end_ts, app) in intervals {
            if *start_ts <= resume_ts && resume_ts < *end_ts {
                chosen = Some(app);
                break;
            }
            if *start_ts >= resume_ts
                && best_after.is_none_or(|(best_start, _)| *start_ts < best_start)
            {
                best_after = Some((*start_ts, app));
            }
        }
        if chosen.is_none() {
            chosen = best_after.map(|(_, app)| app);
        }
        if let Some(app) = chosen {
            *counts.entry(app.to_string()).or_insert(0) += 1;
        }
    }
    let mut ranked: Vec<(String, i64)> = counts.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked
        .into_iter()
        .take(FIRST_AFTER_IDLE_TOP)
        .map(|(app, count)| FirstAfterIdle { app, count })
        .collect()
}

/// Mirrors the S2 stage-3 fields of `read_weekly_digest`: 7v7 active/input
/// trends, top apps, week-scoped heatmap, morning launch, first-after-idle,
/// and empty/prior-week honesty. Later Discovery/pattern fields stay out of
/// this core reader until their own stage ports.
pub fn weekly_digest_core(conn: &Connection, now_ms: i64) -> rusqlite::Result<WeeklyDigestCore> {
    let week_start = now_ms - 7 * DAY_MS;
    let prior_start = now_ms - 14 * DAY_MS;
    let two_week_scope = Scope {
        cutoff_ms: Some(prior_start),
        session_id: None,
    };
    let this_week_scope = Scope {
        cutoff_ms: Some(week_start),
        session_id: None,
    };

    let focus = focus_intervals(conn, &two_week_scope)?;
    // The open-focus heartbeat contributes to active time, top apps, and
    // active days below — never to switches. Its session joins the id set
    // so the away-span subtraction covers it even when it has no completed
    // rows yet (the first-session case).
    let open = live_open_focus(conn, now_ms)?;
    let mut ids: Vec<i64> = focus.iter().map(|row| row.session_id).collect();
    if let Some(open) = &open {
        ids.push(open.session_id);
    }
    let idle = idle_intervals(conn, &ids, None)?;
    let sleep = sleep_intervals(conn, &ids)?;
    let keystrokes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE kind='key' AND ts>=? AND ts<?",
        rusqlite::params![week_start, now_ms],
        |row| row.get(0),
    )?;
    let prior_keystrokes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE kind='key' AND ts>=? AND ts<?",
        rusqlite::params![prior_start, week_start],
        |row| row.get(0),
    )?;
    let heatmap = rhythm_heatmap(conn, &this_week_scope)?;

    let away_by_session = away_spans_by_session(&idle, &sleep, prior_start, now_ms);
    let empty: Vec<(i64, i64)> = Vec::new();
    let week_dates = digest_week_dates(now_ms);
    let mut this_active = 0i64;
    let mut prior_active = 0i64;
    let mut this_switches = 0i64;
    let mut prior_switches = 0i64;
    let mut this_by_app: Vec<(String, i64)> = Vec::new();
    let mut this_by_app_index: HashMap<String, usize> = HashMap::new();
    let mut active_dates: HashSet<String> = HashSet::new();
    for row in &focus {
        let band_start = row.start_ts.max(prior_start);
        let band_end = row.end_ts.min(now_ms);
        if band_end > band_start {
            let session_away = away_by_session.get(&row.session_id).unwrap_or(&empty);
            let app = display_app(Some(&row.exe));
            for (span_start, span_end) in subtract_spans(band_start, band_end, session_away) {
                let this_part = overlap_ms(span_start, span_end, week_start, now_ms);
                let prior_part = overlap_ms(span_start, span_end, prior_start, week_start);
                this_active += this_part;
                prior_active += prior_part;
                if this_part != 0 {
                    bump_ordered(
                        &mut this_by_app,
                        &mut this_by_app_index,
                        app.clone(),
                        this_part,
                    );
                    if week_dates.contains(&row.local_date) {
                        active_dates.insert(row.local_date.clone());
                    }
                }
            }
        }
        if row.end_ts >= week_start && row.end_ts < now_ms {
            this_switches += 1;
        } else if row.end_ts >= prior_start && row.end_ts < week_start {
            prior_switches += 1;
        }
    }

    if let Some(open) = &open {
        let band_start = open.start_ts.max(prior_start);
        let band_end = open.end_ts.min(now_ms);
        if band_end > band_start {
            let session_away = away_by_session.get(&open.session_id).unwrap_or(&empty);
            // The still-open trailing idle span is invisible to the
            // completed-row away spans (its terminator has not landed yet)
            // but must subtract from an interval that extends to now.
            let trailing_idle: Vec<(i64, i64)> =
                open_trailing_idle_span(conn, open.session_id, open.end_ts)?
                    .into_iter()
                    .collect();
            let app = display_app(Some(&open.exe));
            let open_date = local_date(open.end_ts);
            for (away_start, away_end) in subtract_spans(band_start, band_end, session_away) {
                for (span_start, span_end) in subtract_spans(away_start, away_end, &trailing_idle) {
                    let this_part = overlap_ms(span_start, span_end, week_start, now_ms);
                    prior_active += overlap_ms(span_start, span_end, prior_start, week_start);
                    this_active += this_part;
                    if this_part != 0 {
                        bump_ordered(
                            &mut this_by_app,
                            &mut this_by_app_index,
                            app.clone(),
                            this_part,
                        );
                        if week_dates.contains(&open_date) {
                            active_dates.insert(open_date.clone());
                        }
                    }
                }
            }
        }
    }

    this_by_app.sort_by_key(|row| std::cmp::Reverse(row.1));
    let top_apps = this_by_app
        .into_iter()
        .take(DIGEST_TOP_APPS)
        .map(|(app, active_ms)| DigestTopApp { app, active_ms })
        .collect();
    let (morning_launch, morning_launch_days) =
        digest_morning_launch(&focus, week_start, now_ms, &week_dates);
    let first_after_idle = digest_first_after_idle(&focus, &idle, week_start, now_ms);

    Ok(WeeklyDigestCore {
        week_start_ms: week_start,
        now_ms,
        has_prior_week: prior_active > 0 || prior_keystrokes > 0,
        active_ms: this_active,
        prior_active_ms: prior_active,
        active_days: active_dates.len() as i64,
        top_apps,
        switches_per_active_hour: switch_rate(this_switches, this_active),
        prior_switches_per_active_hour: switch_rate(prior_switches, prior_active),
        keystrokes,
        prior_keystrokes,
        morning_launch,
        morning_launch_days,
        first_after_idle,
        heatmap,
    })
}

/// One changed-this-week line: a pattern that appeared ("new") or went
/// quiet ("quieter") relative to the prior three weeks. Value-free — app
/// identities and counts only; describes a state change, not a judgment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DigestChange {
    pub direction: String,
    pub app: String,
    pub evidence: String,
    pub support: i64,
    pub days: i64,
}

/// Pattern key granularity mirrored from `_digest_changed_this_week`:
/// round-trip anchors and unordered app clusters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ChangeKey {
    Anchor(String),
    Cluster(BTreeSet<String>),
}

#[derive(Debug, Default)]
struct ChangeStat {
    week: i64,
    week_dates: HashSet<String>,
    base: i64,
    base_dates: HashSet<String>,
}

/// Python-dict semantics: first-bump insertion order is observable through
/// the equal-support tie-break below, so stats live in an ordered vec.
fn bump_change(
    stats: &mut Vec<(ChangeKey, ChangeStat)>,
    index: &mut HashMap<ChangeKey, usize>,
    key: ChangeKey,
    ts: i64,
    local_date: &str,
    week_start_ms: i64,
    now_ms: i64,
) {
    if ts >= now_ms {
        return;
    }
    let position = if let Some(&position) = index.get(&key) {
        position
    } else {
        index.insert(key.clone(), stats.len());
        stats.push((key, ChangeStat::default()));
        stats.len() - 1
    };
    let entry = &mut stats[position].1;
    if ts >= week_start_ms {
        entry.week += 1;
        entry.week_dates.insert(local_date.to_string());
    } else {
        entry.base += 1;
        entry.base_dates.insert(local_date.to_string());
    }
}

fn change_flag_direction(entry: &ChangeStat, history_days: i64) -> Option<&'static str> {
    if entry.week >= DIGEST_CHANGE_MIN_OCCURRENCES
        && entry.week_dates.len() >= DIGEST_CHANGE_MIN_DAYS_NEW
        && entry.base == 0
        && history_days >= DIGEST_CHANGE_MIN_HISTORY_DAYS
    {
        return Some("new");
    }
    if entry.base >= DIGEST_CHANGE_MIN_OCCURRENCES
        && entry.base_dates.len() >= DIGEST_CHANGE_MIN_DAYS_FADED
        && entry.week == 0
    {
        return Some("quieter");
    }
    None
}

/// Cluster flags attribute to their most distinctive member: fewest distinct
/// focus dates overall, ties broken lexicographically (Python `min` key).
fn change_distinctive_app(key: &ChangeKey, app_dates: &HashMap<String, HashSet<String>>) -> String {
    match key {
        ChangeKey::Anchor(app) => app.clone(),
        ChangeKey::Cluster(members) => members
            .iter()
            .min_by(|left, right| {
                let left_days = app_dates.get(*left).map_or(0, HashSet::len);
                let right_days = app_dates.get(*right).map_or(0, HashSet::len);
                left_days.cmp(&right_days).then_with(|| left.cmp(right))
            })
            .cloned()
            .expect("cluster keys are non-empty"),
    }
}

fn change_describe(key: &ChangeKey) -> String {
    match key {
        ChangeKey::Anchor(app) => format!("a {app} round-trip pattern"),
        ChangeKey::Cluster(members) => {
            // copy-allow: arrow bidirectional cluster data notation (Lane B ruling)
            let joined = members.iter().cloned().collect::<Vec<_>>().join(" ↔ ");
            format!("a {joined} pattern")
        }
    }
}

/// The pure core of `_digest_changed_this_week`, seamed on the episode list
/// and pre-week history-day count so the flag/attribution/dedup semantics
/// unit-test without a database (the `split_ms_by_weekday_hour_with`
/// convention).
fn digest_changed_from_episodes(
    episodes: &[Vec<SequenceStep>],
    history_days: i64,
    week_start_ms: i64,
    now_ms: i64,
) -> Vec<DigestChange> {
    let mut stats: Vec<(ChangeKey, ChangeStat)> = Vec::new();
    let mut stats_index: HashMap<ChangeKey, usize> = HashMap::new();
    let mut app_dates: HashMap<String, HashSet<String>> = HashMap::new();

    for episode in episodes {
        for step in episode {
            app_dates
                .entry(step.app.clone())
                .or_default()
                .insert(step.local_date.clone());
        }
        let apps: Vec<&str> = episode.iter().map(|step| step.app.as_str()).collect();
        for index in 0..apps.len().saturating_sub(2) {
            if apps[index] == apps[index + 2] && apps[index] != apps[index + 1] {
                bump_change(
                    &mut stats,
                    &mut stats_index,
                    ChangeKey::Anchor(apps[index].to_string()),
                    episode[index].ts,
                    &episode[index].local_date,
                    week_start_ms,
                    now_ms,
                );
            }
        }
        for length in 3..=SEQUENCE_MOTIF_MAX_LEN {
            if length > apps.len() {
                continue;
            }
            for start in 0..=(apps.len() - length) {
                let members: BTreeSet<String> = apps[start..start + length]
                    .iter()
                    .map(|app| (*app).to_string())
                    .collect();
                if members.len() < 2 {
                    continue;
                }
                bump_change(
                    &mut stats,
                    &mut stats_index,
                    ChangeKey::Cluster(members),
                    episode[start].ts,
                    &episode[start].local_date,
                    week_start_ms,
                    now_ms,
                );
            }
        }
    }

    let flagged: Vec<(&ChangeKey, &ChangeStat, &'static str)> = stats
        .iter()
        .filter_map(|(key, entry)| {
            change_flag_direction(entry, history_days).map(|direction| (key, entry, direction))
        })
        .collect();

    // One phenomenon, one line: when a flagged cluster covers an app, that
    // app's own anchor flag in the same direction is the same change seen
    // through a narrower key — keep only the distinctive-app attribution.
    let mut covered: HashSet<(&'static str, String)> = HashSet::new();
    for (key, _entry, direction) in &flagged {
        if let ChangeKey::Cluster(members) = key {
            let distinctive = change_distinctive_app(key, &app_dates);
            for member in members.iter() {
                if member != &distinctive {
                    covered.insert((direction, member.clone()));
                }
            }
        }
    }

    let mut best: HashMap<(String, String), DigestChange> = HashMap::new();
    for (key, entry, direction) in &flagged {
        let app = change_distinctive_app(key, &app_dates);
        if matches!(key, ChangeKey::Anchor(_)) && covered.contains(&(*direction, app.clone())) {
            continue;
        }
        let change = if *direction == "new" {
            DigestChange {
                direction: "new".to_string(),
                app: app.clone(),
                evidence: format!(
                    "{} ({} occurrences across {} days)",
                    change_describe(key),
                    entry.week,
                    entry.week_dates.len()
                ),
                support: entry.week,
                days: entry.week_dates.len() as i64,
            }
        } else {
            DigestChange {
                direction: "quieter".to_string(),
                app: app.clone(),
                evidence: format!(
                    "{app} patterns ({} active days in the prior three weeks, none this week)",
                    entry.base_dates.len()
                ),
                support: entry.base,
                days: entry.base_dates.len() as i64,
            }
        };
        let slot = (change.direction.clone(), change.app.clone());
        // Equal support keeps the earlier-bumped key (Python `>` guard).
        let replace = best
            .get(&slot)
            .is_none_or(|current| change.support > current.support);
        if replace {
            best.insert(slot, change);
        }
    }

    // Apps are unique per direction (the slot key), so (-support, app) is a
    // total order within each direction and map iteration order can't leak
    // into the output.
    let mut ordered: Vec<DigestChange> = best.into_values().collect();
    ordered.sort_by(|left, right| {
        right
            .support
            .cmp(&left.support)
            .then_with(|| left.app.cmp(&right.app))
    });
    let mut changes: Vec<DigestChange> = ordered
        .iter()
        .filter(|change| change.direction == "new")
        .take(DIGEST_CHANGE_LIMIT)
        .cloned()
        .collect();
    changes.extend(
        ordered
            .iter()
            .filter(|change| change.direction == "quieter")
            .take(DIGEST_CHANGE_LIMIT)
            .cloned(),
    );
    changes
}

/// Mirrors `_digest_changed_this_week`: stateless pattern emergence/decay
/// lines for the Week digest — the trailing week vs the prior three-week
/// baseline, recomputable at any time within the same week. "New" flags are
/// gated on pre-week history so week one doesn't flag everything as new.
pub fn digest_changed_this_week(
    conn: &Connection,
    week_start_ms: i64,
    now_ms: i64,
) -> rusqlite::Result<Vec<DigestChange>> {
    let baseline_start = week_start_ms - DIGEST_CHANGE_BASELINE_DAYS * DAY_MS;
    let scope = Scope {
        cutoff_ms: Some(baseline_start),
        session_id: None,
    };
    let episodes = focus_sequence_episodes(conn, &scope)?;
    if episodes.is_empty() {
        return Ok(Vec::new());
    }
    let history_days: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT date(ts / 1000, 'unixepoch', 'localtime')) \
         FROM events WHERE kind = 'focus_changed' AND ts < ?",
        [week_start_ms],
        |row| row.get(0),
    )?;
    Ok(digest_changed_from_episodes(
        &episodes,
        history_days,
        week_start_ms,
        now_ms,
    ))
}

/// Mirrors `read_weekly_digest` end to end: the stage-3 core plus the
/// Discovery-dependent tail — week-scoped friction candidates and the
/// changed-this-week emergence/decay lines. This is the Week tab's reader.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WeeklyDigest {
    pub week_start_ms: i64,
    pub now_ms: i64,
    pub has_prior_week: bool,
    pub active_ms: i64,
    pub prior_active_ms: i64,
    pub active_days: i64,
    pub top_apps: Vec<DigestTopApp>,
    pub switches_per_active_hour: Option<f64>,
    pub prior_switches_per_active_hour: Option<f64>,
    pub keystrokes: i64,
    pub prior_keystrokes: i64,
    pub friction: Vec<PatternCandidate>,
    pub morning_launch: Vec<String>,
    pub morning_launch_days: i64,
    pub first_after_idle: Vec<FirstAfterIdle>,
    pub heatmap: Vec<HeatmapBucket>,
    pub changed_this_week: Vec<DigestChange>,
}

pub fn weekly_digest(conn: &Connection, now_ms: i64) -> rusqlite::Result<WeeklyDigest> {
    let core = weekly_digest_core(conn, now_ms)?;
    let week_start = now_ms - 7 * DAY_MS;
    let this_week_scope = Scope {
        cutoff_ms: Some(week_start),
        session_id: None,
    };
    let mut friction = patterns_worth_reviewing(conn, &this_week_scope)?;
    friction.truncate(DIGEST_FRICTION_LIMIT);
    let changed_this_week = digest_changed_this_week(conn, week_start, now_ms)?;
    Ok(WeeklyDigest {
        week_start_ms: core.week_start_ms,
        now_ms: core.now_ms,
        has_prior_week: core.has_prior_week,
        active_ms: core.active_ms,
        prior_active_ms: core.prior_active_ms,
        active_days: core.active_days,
        top_apps: core.top_apps,
        switches_per_active_hour: core.switches_per_active_hour,
        prior_switches_per_active_hour: core.prior_switches_per_active_hour,
        keystrokes: core.keystrokes,
        prior_keystrokes: core.prior_keystrokes,
        friction,
        morning_launch: core.morning_launch,
        morning_launch_days: core.morning_launch_days,
        first_after_idle: core.first_after_idle,
        heatmap: core.heatmap,
        changed_this_week,
    })
}

/// One Analytics "App Focus" rollup row. `exe` mirrors the Python frame,
/// which overwrites it with the display app after grouping.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FocusRollupRow {
    pub app: String,
    pub exe: String,
    pub focus_minutes: f64,
    pub active_foreground_minutes: f64,
    pub focus_switches: i64,
    pub avg_dwell_seconds: f64,
    pub support_sessions: i64,
    pub support_days: i64,
}

/// Mirrors `read_focus_rollup`: per-display-app dwell totals over the
/// active-focus substrate, aggregated in pandas' alphabetical group order,
/// stably sorted by (focus time, switches) descending, top 25.
pub fn focus_rollup(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<FocusRollupRow>> {
    #[derive(Default)]
    struct Accum {
        switches: i64,
        focus_ms: i64,
        active_ms: i64,
        sessions: HashSet<i64>,
        days: HashSet<String>,
    }
    let mut groups: BTreeMap<String, Accum> = BTreeMap::new();
    for row in focus_intervals_with_active(conn, scope)? {
        let entry = groups.entry(display_app(Some(&row.exe))).or_default();
        entry.switches += 1;
        entry.focus_ms += row.duration_ms;
        entry.active_ms += row.active_foreground_ms;
        entry.sessions.insert(row.session_id);
        entry.days.insert(row.local_date);
    }
    let mut rollup: Vec<(String, Accum)> = groups.into_iter().collect();
    rollup.sort_by(|left, right| {
        (right.1.focus_ms, right.1.switches).cmp(&(left.1.focus_ms, left.1.switches))
    });
    rollup.truncate(TOP_N_ANALYTICS);
    Ok(rollup
        .into_iter()
        .map(|(app, accum)| FocusRollupRow {
            exe: app.clone(),
            app,
            focus_minutes: pandas_round_2dp(accum.focus_ms as f64 / 60_000.0),
            active_foreground_minutes: pandas_round_2dp(accum.active_ms as f64 / 60_000.0),
            focus_switches: accum.switches,
            avg_dwell_seconds: pandas_round_2dp(
                accum.focus_ms as f64 / accum.switches as f64 / 1000.0,
            ),
            support_sessions: accum.sessions.len() as i64,
            support_days: accum.days.len() as i64,
        })
        .collect())
}

/// Mirrors `read_focus_minutes_total` (unrounded).
pub fn focus_minutes_total(conn: &Connection, scope: &Scope) -> rusqlite::Result<f64> {
    let total: i64 = focus_intervals(conn, scope)?
        .iter()
        .map(|row| row.duration_ms)
        .sum();
    Ok(total as f64 / 60_000.0)
}

/// Mirrors `read_active_focus_minutes_total` (unrounded).
pub fn active_focus_minutes_total(conn: &Connection, scope: &Scope) -> rusqlite::Result<f64> {
    let total: i64 = focus_intervals_with_active(conn, scope)?
        .iter()
        .map(|row| row.active_foreground_ms)
        .sum();
    Ok(total as f64 / 60_000.0)
}

/// One Analytics "Input Summary" rollup row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputRollupRow {
    pub app: String,
    pub exe: String,
    pub key_events: i64,
    pub ctrl_rate: f64,
    pub alt_rate: f64,
    pub shift_rate: f64,
    pub win_rate: f64,
    pub mouse_clicks: i64,
    pub mouse_moves: i64,
    pub mouse_wheels: i64,
    pub remote_relay_suspected_events: i64,
    pub total_input_events: i64,
}

/// Sum SQL-grouped per-exe counts by display-app identity, alphabetically —
/// mirrors `_sum_by_app_identity` (a sorted pandas groupby).
fn sum_by_app_identity<const N: usize>(rows: Vec<(String, [i64; N])>) -> Vec<(String, [i64; N])> {
    let mut groups: BTreeMap<String, [i64; N]> = BTreeMap::new();
    for (exe, counts) in rows {
        let entry = groups.entry(display_app(Some(&exe))).or_insert([0; N]);
        for (slot, value) in entry.iter_mut().zip(counts) {
            *slot += value;
        }
    }
    groups.into_iter().collect()
}

/// Mirrors `read_input_rollup`: keyboard and mouse counts per display app,
/// outer-merged in pandas order (keyboard apps first, then mouse-only apps),
/// modifier rates over a floor-of-1 key denominator, stably sorted by the
/// four-count key descending, top 25.
pub fn input_rollup(conn: &Connection, scope: &Scope) -> rusqlite::Result<Vec<InputRollupRow>> {
    let (where_clause, params) = scope_predicate("e", scope);

    let keyboard_sql = format!(
        "SELECT COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe,
                COUNT(*),
                SUM(COALESCE(e.mod_shift, 0)),
                SUM(COALESCE(e.mod_ctrl, 0)),
                SUM(COALESCE(e.mod_alt, 0)),
                SUM(COALESCE(e.mod_win, 0))
         FROM events e
         WHERE e.kind = 'key' AND {where_clause}
         GROUP BY COALESCE(NULLIF(e.exe, ''), '(unknown)')"
    );
    let mut stmt = conn.prepare(&keyboard_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.clone()))?;
    let mut keyboard_raw: Vec<(String, [i64; 5])> = Vec::new();
    while let Some(row) = rows.next()? {
        keyboard_raw.push((
            row.get(0)?,
            [
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ],
        ));
    }
    let keyboard = sum_by_app_identity(keyboard_raw);

    let mouse_sql = format!(
        "WITH mouse_events AS (
            SELECT e.*,
                   COALESCE(json_extract(e.payload, '$.input_origin'), 'local') AS input_origin
            FROM events e
            WHERE e.source = 'mouse' AND {where_clause}
        )
        SELECT COALESCE(NULLIF(exe, ''), '(unknown)') AS exe,
               SUM(CASE WHEN kind = 'mouse_click' AND input_origin != 'remote_relay_suspected' THEN 1 ELSE 0 END),
               SUM(CASE WHEN kind = 'mouse_move' AND input_origin != 'remote_relay_suspected' THEN 1 ELSE 0 END),
               SUM(CASE WHEN kind = 'mouse_wheel' AND input_origin != 'remote_relay_suspected' THEN 1 ELSE 0 END),
               SUM(CASE WHEN input_origin = 'remote_relay_suspected' THEN 1 ELSE 0 END)
        FROM mouse_events
        GROUP BY COALESCE(NULLIF(exe, ''), '(unknown)')"
    );
    let mut stmt = conn.prepare(&mouse_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut mouse_raw: Vec<(String, [i64; 4])> = Vec::new();
    while let Some(row) = rows.next()? {
        mouse_raw.push((
            row.get(0)?,
            [row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?],
        ));
    }
    let mouse = sum_by_app_identity(mouse_raw);

    // pandas outer merge: left-frame keys in order, then right-only keys.
    struct Merged {
        keyboard: [i64; 5],
        mouse: [i64; 4],
    }
    let mut order: Vec<String> = Vec::new();
    let mut merged: HashMap<String, Merged> = HashMap::new();
    for (app, counts) in keyboard {
        order.push(app.clone());
        merged.insert(
            app,
            Merged {
                keyboard: counts,
                mouse: [0; 4],
            },
        );
    }
    for (app, counts) in mouse {
        match merged.get_mut(&app) {
            Some(entry) => entry.mouse = counts,
            None => {
                order.push(app.clone());
                merged.insert(
                    app,
                    Merged {
                        keyboard: [0; 5],
                        mouse: counts,
                    },
                );
            }
        }
    }

    let mut result: Vec<InputRollupRow> = order
        .into_iter()
        .map(|app| {
            let entry = &merged[&app];
            let [key_events, shift, ctrl, alt, win] = entry.keyboard;
            let [clicks, moves, wheels, relay] = entry.mouse;
            let denominator = if key_events > 0 { key_events } else { 1 } as f64;
            InputRollupRow {
                exe: app.clone(),
                app,
                key_events,
                ctrl_rate: pandas_round_2dp(ctrl as f64 / denominator),
                alt_rate: pandas_round_2dp(alt as f64 / denominator),
                shift_rate: pandas_round_2dp(shift as f64 / denominator),
                win_rate: pandas_round_2dp(win as f64 / denominator),
                mouse_clicks: clicks,
                mouse_moves: moves,
                mouse_wheels: wheels,
                remote_relay_suspected_events: relay,
                total_input_events: key_events + clicks + moves + wheels,
            }
        })
        .collect();
    result.sort_by(|left, right| {
        (
            right.total_input_events,
            right.remote_relay_suspected_events,
            right.key_events,
            right.mouse_clicks,
        )
            .cmp(&(
                left.total_input_events,
                left.remote_relay_suspected_events,
                left.key_events,
                left.mouse_clicks,
            ))
    });
    result.truncate(TOP_N_ANALYTICS);
    Ok(result)
}

/// One Analytics "Sessions" rollup row. Timestamp strings come from SQLite's
/// own localtime rendering, exactly as the Python frame receives them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionAnalyticsRow {
    pub session_id: i64,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub event_count: i64,
    pub active_foreground_minutes: f64,
    pub active_span_minutes: f64,
    pub idle_events: i64,
    pub active_events: i64,
    pub idle_minutes: f64,
}

/// Mirrors `read_session_analytics`: newest 25 sessions with in-scope
/// events, joined with idle spans and active-focus sums.
pub fn session_analytics(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<SessionAnalyticsRow>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT s.session_id,
                datetime(s.started_at / 1000, 'unixepoch', 'localtime'),
                datetime(s.ended_at / 1000, 'unixepoch', 'localtime'),
                COUNT(e.id),
                MIN(e.ts),
                MAX(e.ts),
                SUM(CASE WHEN e.kind = 'idle' THEN 1 ELSE 0 END),
                SUM(CASE WHEN e.kind = 'active' THEN 1 ELSE 0 END)
         FROM sessions s
         LEFT JOIN events e
           ON e.session_id = s.session_id
          AND {where_clause}
         GROUP BY s.session_id, s.started_at, s.ended_at
         HAVING COUNT(e.id) > 0
         ORDER BY s.started_at DESC, s.session_id DESC
         LIMIT ?"
    );
    struct BaseRow {
        session_id: i64,
        started_at: String,
        ended_at: Option<String>,
        event_count: i64,
        first_event_ts: i64,
        last_event_ts: i64,
        idle_events: i64,
        active_events: i64,
    }
    let mut stmt = conn.prepare(&sql)?;
    let mut query_params = params;
    query_params.push(TOP_N_ANALYTICS as i64);
    let mut rows = stmt.query(rusqlite::params_from_iter(query_params))?;
    let mut base: Vec<BaseRow> = Vec::new();
    while let Some(row) = rows.next()? {
        base.push(BaseRow {
            session_id: row.get(0)?,
            started_at: row.get(1)?,
            ended_at: row.get(2)?,
            event_count: row.get(3)?,
            first_event_ts: row.get(4)?,
            last_event_ts: row.get(5)?,
            idle_events: row.get(6)?,
            active_events: row.get(7)?,
        });
    }
    if base.is_empty() {
        return Ok(Vec::new());
    }

    let session_ids: Vec<i64> = base.iter().map(|row| row.session_id).collect();
    let mut idle_by_session: HashMap<i64, i64> = HashMap::new();
    for interval in idle_intervals(conn, &session_ids, Some(scope))? {
        *idle_by_session.entry(interval.session_id).or_insert(0) +=
            (interval.end_ts - interval.start_ts).max(0);
    }
    let mut active_by_session: HashMap<i64, i64> = HashMap::new();
    for row in focus_intervals_with_active(conn, scope)? {
        *active_by_session.entry(row.session_id).or_insert(0) += row.active_foreground_ms;
    }

    Ok(base
        .into_iter()
        .map(|row| SessionAnalyticsRow {
            active_foreground_minutes: pandas_round_2dp(
                active_by_session.get(&row.session_id).copied().unwrap_or(0) as f64 / 60_000.0,
            ),
            active_span_minutes: pandas_round_2dp(
                (row.last_event_ts - row.first_event_ts).max(0) as f64 / 60_000.0,
            ),
            idle_minutes: pandas_round_2dp(
                idle_by_session.get(&row.session_id).copied().unwrap_or(0) as f64 / 60_000.0,
            ),
            session_id: row.session_id,
            started_at: row.started_at,
            ended_at: row.ended_at,
            event_count: row.event_count,
            idle_events: row.idle_events,
            active_events: row.active_events,
        })
        .collect())
}

/// One Analytics "Window Lifecycle" rollup row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WindowLifecycleRow {
    pub app: String,
    pub exe: String,
    pub opened_windows: i64,
    pub closed_windows: i64,
    pub median_open_seconds: f64,
    pub avg_open_seconds: f64,
    pub support_sessions: i64,
    pub support_days: i64,
}

/// Mirrors `read_window_lifecycle_rollup`: observed-origin closes only,
/// outer-merged with open counts in pandas order, top 25.
pub fn window_lifecycle_rollup(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<WindowLifecycleRow>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let origin_expr = "COALESCE(json_extract(e.payload, '$.origin'), 'observed')";

    let opened_sql = format!(
        "SELECT COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe, COUNT(*)
         FROM events e
         WHERE e.kind = 'window_opened' AND {where_clause}
         GROUP BY COALESCE(NULLIF(e.exe, ''), '(unknown)')"
    );
    let mut stmt = conn.prepare(&opened_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.clone()))?;
    let mut opened_raw: Vec<(String, [i64; 1])> = Vec::new();
    while let Some(row) = rows.next()? {
        opened_raw.push((row.get(0)?, [row.get(1)?]));
    }
    let opened = sum_by_app_identity(opened_raw);

    let closed_sql = format!(
        "SELECT COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe,
                e.session_id,
                date(e.ts / 1000, 'unixepoch', 'localtime') AS local_date,
                COALESCE(e.duration_ms, 0) AS duration_ms
         FROM events e
         WHERE e.kind = 'window_closed'
           AND e.duration_ms IS NOT NULL
           AND {origin_expr} = ?
           AND {where_clause}"
    );
    let mut stmt = conn.prepare(&closed_sql)?;
    let origin = WINDOW_ORIGIN_OBSERVED;
    let mut closed_params: Vec<&dyn rusqlite::types::ToSql> = vec![&origin];
    for param in &params {
        closed_params.push(param);
    }
    let mut rows = stmt.query(&closed_params[..])?;
    #[derive(Default)]
    struct ClosedAccum {
        durations: Vec<i64>,
        sessions: HashSet<i64>,
        days: HashSet<String>,
    }
    let mut closed_groups: BTreeMap<String, ClosedAccum> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let exe: String = row.get(0)?;
        let entry = closed_groups.entry(display_app(Some(&exe))).or_default();
        entry.sessions.insert(row.get(1)?);
        entry.days.insert(row.get(2)?);
        entry.durations.push(row.get(3)?);
    }
    struct ClosedRow {
        closed_windows: i64,
        median_open_ms: f64,
        avg_open_ms: f64,
        support_sessions: i64,
        support_days: i64,
    }
    let mut closed_rollup: Vec<(String, ClosedRow)> = closed_groups
        .into_iter()
        .map(|(app, mut accum)| {
            let count = accum.durations.len() as i64;
            let total: i64 = accum.durations.iter().sum();
            let median = median_i64_as_f64(&mut accum.durations).unwrap_or(0.0);
            (
                app,
                ClosedRow {
                    closed_windows: count,
                    median_open_ms: median,
                    avg_open_ms: total as f64 / count as f64,
                    support_sessions: accum.sessions.len() as i64,
                    support_days: accum.days.len() as i64,
                },
            )
        })
        .collect();
    closed_rollup.sort_by(|left, right| {
        right
            .1
            .closed_windows
            .cmp(&left.1.closed_windows)
            .then_with(|| {
                left.1
                    .median_open_ms
                    .partial_cmp(&right.1.median_open_ms)
                    .expect("finite medians")
            })
    });

    // pandas outer merge: opened keys in order, then closed-only keys.
    let mut order: Vec<String> = Vec::new();
    let mut opened_by_app: HashMap<String, i64> = HashMap::new();
    for (app, [count]) in opened {
        order.push(app.clone());
        opened_by_app.insert(app, count);
    }
    let mut closed_by_app: HashMap<String, ClosedRow> = HashMap::new();
    for (app, row) in closed_rollup {
        if !opened_by_app.contains_key(&app) {
            order.push(app.clone());
        }
        closed_by_app.insert(app, row);
    }

    let mut result: Vec<WindowLifecycleRow> = order
        .into_iter()
        .map(|app| {
            let opened_windows = opened_by_app.get(&app).copied().unwrap_or(0);
            let closed = closed_by_app.get(&app);
            WindowLifecycleRow {
                exe: app.clone(),
                app,
                opened_windows,
                closed_windows: closed.map_or(0, |row| row.closed_windows),
                median_open_seconds: pandas_round_2dp(
                    closed.map_or(0.0, |row| row.median_open_ms) / 1000.0,
                ),
                avg_open_seconds: pandas_round_2dp(
                    closed.map_or(0.0, |row| row.avg_open_ms) / 1000.0,
                ),
                support_sessions: closed.map_or(0, |row| row.support_sessions),
                support_days: closed.map_or(0, |row| row.support_days),
            }
        })
        .collect();
    result.sort_by(|left, right| {
        (right.closed_windows, right.opened_windows)
            .cmp(&(left.closed_windows, left.opened_windows))
    });
    result.truncate(TOP_N_ANALYTICS);
    Ok(result)
}

/// Mirrors `_sustained_app_switches`: switches between adjacent known
/// segments where the destination dwell is sustained (>= 15 s).
fn sustained_app_switches(segments: &[AppSegment]) -> (i64, HashMap<String, i64>) {
    let mut total = 0i64;
    let mut by_destination: HashMap<String, i64> = HashMap::new();
    let mut previous: Option<&AppSegment> = None;
    for segment in segments {
        if !is_known_active_segment(segment) {
            previous = None;
            continue;
        }
        if let Some(prev) = previous {
            if prev.session_id == segment.session_id
                && segment.order == prev.order + 1
                && segment.start_ts - prev.end_ts <= EPISODE_GAP_MS
                && prev.app != segment.app
                && segment.active_ms >= MIN_SWITCH_DWELL_MS
            {
                total += 1;
                *by_destination.entry(segment.app.clone()).or_insert(0) += 1;
            }
        }
        previous = Some(segment);
    }
    (total, by_destination)
}

/// Per-anchor diversion evidence from the shared anchor-return pairs.
#[derive(Debug, Default)]
struct AnchorDiversions {
    count: i64,
    dates: HashSet<String>,
    active_diversion_ms: Vec<i64>,
    intervening_segments: Vec<i64>,
}

/// Mirrors `_active_diversion_records`. Ordering never leaks: consumers
/// look up by app or feed medians/sums.
fn active_diversion_records(runs: &[FocusRun]) -> HashMap<String, AnchorDiversions> {
    let mut anchors: HashMap<String, AnchorDiversions> = HashMap::new();
    let prefix = active_ms_prefix(runs);
    for (index, return_index) in next_anchor_returns(runs) {
        let run = &runs[index];
        let record = anchors.entry(run.app.clone()).or_default();
        record.count += 1;
        record.dates.insert(run.local_date.clone());
        record
            .active_diversion_ms
            .push(prefix[return_index] - prefix[index + 1]);
        record
            .intervening_segments
            .push((return_index - index - 1) as i64);
    }
    anchors
}

/// Mirrors `_resumption_lags`.
fn resumption_lags(
    runs: &[FocusRun],
    productive_ts_by_app: &ProductiveInputMap,
) -> (Vec<i64>, HashMap<String, Vec<i64>>) {
    let mut overall: Vec<i64> = Vec::new();
    let mut by_app: HashMap<String, Vec<i64>> = HashMap::new();
    for (index, return_index) in next_anchor_returns(runs) {
        let anchor = runs[index].app.as_str();
        let candidate = &runs[return_index];
        if let Some(lag) = first_input_lag(
            candidate.session_id,
            anchor,
            candidate.start_ts,
            candidate.end_ts,
            productive_ts_by_app,
        ) {
            overall.push(lag);
            by_app.entry(anchor.to_string()).or_default().push(lag);
        }
    }
    (overall, by_app)
}

/// One Focus Fragmentation per-app breakdown row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FragmentationBreakdownRow {
    pub app: String,
    pub active_minutes: f64,
    pub same_app_focus_runs: i64,
    pub median_run_minutes: Option<f64>,
    pub sustained_switches_per_active_hour: Option<f64>,
    pub anchor_returns: i64,
    pub median_active_diversion_minutes: Option<f64>,
    pub median_intervening_app_focus_segments: Option<f64>,
    pub median_resumption_lag_seconds: Option<f64>,
}

/// Mirrors `FragmentationMetrics`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FragmentationMetrics {
    pub active_minutes: f64,
    pub same_app_focus_runs: i64,
    pub median_same_app_run_minutes: Option<f64>,
    pub median_sustained_focus_run_minutes: Option<f64>,
    pub sustained_switches: i64,
    pub sustained_switches_per_active_hour: Option<f64>,
    pub anchor_returns: i64,
    pub median_active_diversion_minutes: Option<f64>,
    pub median_resumption_lag_seconds: Option<f64>,
    pub breakdown: Vec<FragmentationBreakdownRow>,
}

fn empty_fragmentation_metrics() -> FragmentationMetrics {
    FragmentationMetrics {
        active_minutes: 0.0,
        same_app_focus_runs: 0,
        median_same_app_run_minutes: None,
        median_sustained_focus_run_minutes: None,
        sustained_switches: 0,
        sustained_switches_per_active_hour: None,
        anchor_returns: 0,
        median_active_diversion_minutes: None,
        median_resumption_lag_seconds: None,
        breakdown: Vec::new(),
    }
}

/// Descending with `None` last per key — pandas `sort_values(ascending=False,
/// na_position="last")`.
fn option_desc_none_last(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => right.partial_cmp(&left).expect("finite sort keys"),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// Mirrors `read_fragmentation_metrics`: the Focus Fragmentation headline
/// and the per-app breakdown, per-app rows in Python's first-seen dict
/// order before the stable three-key descending sort, top 25.
pub fn fragmentation_metrics(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<FragmentationMetrics> {
    let segments = active_app_focus_segments(conn, scope)?;
    if segments.is_empty() {
        return Ok(empty_fragmentation_metrics());
    }
    let productive_ts = productive_input_map(conn, scope)?;

    let known_active_ms: i64 = segments
        .iter()
        .filter(|segment| is_known_active_segment(segment))
        .map(|segment| segment.active_ms)
        .sum();
    if known_active_ms <= 0 {
        return Ok(empty_fragmentation_metrics());
    }

    let runs = same_app_focus_runs(&segments);
    let (sustained_switches, switches_by_app) = sustained_app_switches(&segments);
    let anchor_records = active_diversion_records(&runs);
    let (resumption_overall, resumption_by_app) = resumption_lags(&runs, &productive_ts);

    let gated_anchors: HashMap<&String, &AnchorDiversions> = anchor_records
        .iter()
        .filter(|(_, record)| {
            record.count >= FRAGMENTATION_MIN_ROUNDTRIPS && record.dates.len() >= SEQUENCE_MIN_DAYS
        })
        .collect();

    // Python's active_by_app dict: first-seen order over known segments.
    let mut active_order: Vec<(String, i64)> = Vec::new();
    let mut active_index: HashMap<String, usize> = HashMap::new();
    for segment in &segments {
        if is_known_active_segment(segment) {
            bump_ordered(
                &mut active_order,
                &mut active_index,
                segment.app.clone(),
                segment.active_ms,
            );
        }
    }

    let mut runs_by_app: HashMap<&str, Vec<i64>> = HashMap::new();
    for run in &runs {
        runs_by_app
            .entry(run.app.as_str())
            .or_default()
            .push(run.active_ms);
    }

    let mut breakdown: Vec<FragmentationBreakdownRow> = active_order
        .iter()
        .map(|(app, active_ms)| {
            let run_ms = runs_by_app.get(app.as_str()).cloned().unwrap_or_default();
            let app_lags = resumption_by_app.get(app).cloned().unwrap_or_default();
            let anchor = gated_anchors.get(app);
            let app_active_hours = *active_ms as f64 / 3_600_000.0;
            let mut intervening = anchor
                .map(|record| record.intervening_segments.clone())
                .unwrap_or_default();
            FragmentationBreakdownRow {
                app: app.clone(),
                active_minutes: round_2dp(*active_ms as f64 / 60_000.0),
                same_app_focus_runs: run_ms.len() as i64,
                median_run_minutes: median_minutes(&run_ms),
                sustained_switches_per_active_hour: (app_active_hours > 0.0
                    && *active_ms >= SWITCH_RATE_MIN_ACTIVE_MS)
                    .then(|| {
                        round_2dp(
                            switches_by_app.get(app).copied().unwrap_or(0) as f64
                                / app_active_hours,
                        )
                    }),
                anchor_returns: anchor.map_or(0, |record| record.count),
                median_active_diversion_minutes: median_minutes(
                    anchor.map_or(&[][..], |record| &record.active_diversion_ms),
                ),
                median_intervening_app_focus_segments: median_i64_as_f64(&mut intervening)
                    .map(round_2dp),
                median_resumption_lag_seconds: (app_lags.len() >= RESUMPTION_LAG_MIN_SAMPLES)
                    .then(|| median_seconds(&app_lags))
                    .flatten(),
            }
        })
        .collect();
    breakdown.sort_by(|left, right| {
        right
            .active_minutes
            .partial_cmp(&left.active_minutes)
            .expect("finite sort keys")
            .then_with(|| right.anchor_returns.cmp(&left.anchor_returns))
            .then_with(|| {
                option_desc_none_last(
                    left.sustained_switches_per_active_hour,
                    right.sustained_switches_per_active_hour,
                )
            })
    });
    breakdown.truncate(TOP_N_ANALYTICS);

    let all_run_ms: Vec<i64> = runs.iter().map(|run| run.active_ms).collect();
    let sustained_run_ms: Vec<i64> = runs
        .iter()
        .map(|run| run.active_ms)
        .filter(|&active_ms| active_ms >= MIN_SWITCH_DWELL_MS)
        .collect();
    let gated_diversions: Vec<i64> = gated_anchors
        .values()
        .flat_map(|record| record.active_diversion_ms.iter().copied())
        .collect();
    let active_hours = known_active_ms as f64 / 3_600_000.0;
    Ok(FragmentationMetrics {
        active_minutes: round_2dp(known_active_ms as f64 / 60_000.0),
        same_app_focus_runs: runs.len() as i64,
        median_same_app_run_minutes: median_minutes(&all_run_ms),
        median_sustained_focus_run_minutes: median_minutes(&sustained_run_ms),
        sustained_switches,
        sustained_switches_per_active_hour: (active_hours > 0.0)
            .then(|| round_2dp(sustained_switches as f64 / active_hours)),
        anchor_returns: gated_anchors.values().map(|record| record.count).sum(),
        median_active_diversion_minutes: median_minutes(&gated_diversions),
        median_resumption_lag_seconds: median_seconds(&resumption_overall),
        breakdown,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RhythmMetricsCore {
    pub heatmap: Vec<HeatmapBucket>,
    pub typing_burst_wpm_median: Option<f64>,
    pub typing_burst_wpm_p90: Option<f64>,
    pub typing_burst_count: i64,
    pub typing_classified_fraction: Option<f64>,
    pub mouse_velocity_median_px_s: Option<f64>,
    pub mouse_velocity_p90_px_s: Option<f64>,
    pub mouse_move_samples: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RhythmMetrics {
    pub heatmap: Vec<HeatmapBucket>,
    pub typing_burst_wpm_median: Option<f64>,
    pub typing_burst_wpm_p90: Option<f64>,
    pub typing_burst_count: i64,
    pub typing_classified_fraction: Option<f64>,
    pub mouse_velocity_median_px_s: Option<f64>,
    pub mouse_velocity_p90_px_s: Option<f64>,
    pub mouse_move_samples: i64,
    pub friction_windows: Vec<FrictionWindow>,
}

fn key_class_for_name(name: &str) -> &'static str {
    match name {
        "Shift" | "Ctrl" | "Alt" | "Win" | "CapsLock" | "NumLock" | "ScrollLock" => "modifier",
        "Home" | "End" | "PageUp" | "PageDown" | "ArrowLeft" | "ArrowUp" | "ArrowRight"
        | "ArrowDown" | "Insert" | "Delete" | "Backspace" | "Tab" => "navigation",
        "Enter" | "Escape" | "Pause" | "Apps" | "PrintScreen" => "function",
        "Space" => "printable",
        _ if name.len() >= 2
            && name.as_bytes()[0] == b'F'
            && name[1..].chars().all(|ch| ch.is_ascii_digit()) =>
        {
            "function"
        }
        _ if name.starts_with("Numpad") => "printable",
        _ if name.chars().count() == 1 => "printable",
        _ => "other",
    }
}

fn key_row_class(key: Option<&str>, payload: Option<&str>) -> Option<String> {
    let parsed: serde_json::Value = payload
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(serde_json::Value::Null);
    if let Some(stored) = parsed.get("key_class").and_then(serde_json::Value::as_str) {
        if !stored.is_empty() {
            return Some(stored.to_string());
        }
    }
    let name = key
        .filter(|value| !value.is_empty())
        .or_else(|| parsed.get("key").and_then(serde_json::Value::as_str));
    name.filter(|value| !value.is_empty())
        .map(key_class_for_name)
        .map(str::to_string)
}

type TypingBurstStats = (Option<f64>, Option<f64>, i64, Option<f64>);

fn typing_burst_rates(conn: &Connection, scope: &Scope) -> rusqlite::Result<TypingBurstStats> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT e.session_id, e.ts, e.key, e.payload
         FROM events e
         WHERE e.kind = 'key' AND {where_clause}
         ORDER BY e.session_id, e.ts, e.id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut events: Vec<(i64, i64, Option<String>, Option<String>)> = Vec::new();
    while let Some(row) = rows.next()? {
        events.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
    }
    if events.is_empty() {
        return Ok((None, None, 0, None));
    }

    let classes: Vec<Option<String>> = events
        .iter()
        .map(|(_, _, key, payload)| key_row_class(key.as_deref(), payload.as_deref()))
        .collect();
    let known = classes.iter().filter(|value| value.is_some()).count();
    let classified_fraction = Some(known as f64 / classes.len() as f64);
    let mut rates: Vec<f64> = Vec::new();

    let close_burst = |lo: usize, hi: usize, rates: &mut Vec<f64>| {
        let printable = (lo..=hi)
            .filter(|&idx| classes[idx].as_deref() == Some("printable"))
            .count() as i64;
        let duration_ms = events[hi].1 - events[lo].1;
        if printable >= TYPING_BURST_MIN_CHARS && duration_ms > 0 {
            let words = printable as f64 / WPM_CHARS_PER_WORD;
            rates.push(words / (duration_ms as f64 / 60_000.0));
        }
    };

    let mut burst_start = 0usize;
    for idx in 1..events.len() {
        let same_session = events[idx].0 == events[idx - 1].0;
        let gap = events[idx].1 - events[idx - 1].1;
        if !same_session || gap > TYPING_BURST_GAP_MS {
            close_burst(burst_start, idx - 1, &mut rates);
            burst_start = idx;
        }
    }
    close_burst(burst_start, events.len() - 1, &mut rates);

    if rates.is_empty() {
        return Ok((None, None, 0, classified_fraction));
    }
    let mut median_values = rates.clone();
    let median = median_f64(&mut median_values).map(round_1dp);
    let p90 = Some(round_1dp(percentile_nearest_rank(&rates, 90.0)));
    Ok((median, p90, rates.len() as i64, classified_fraction))
}

fn mouse_velocities(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<(Option<f64>, Option<f64>, i64)> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT
             CAST(json_extract(e.payload, '$.distance_px') AS REAL) AS distance_px,
             CAST(json_extract(e.payload, '$.duration_ms') AS REAL) AS duration_ms
         FROM events e
         WHERE e.kind = 'mouse_move'
           AND COALESCE(json_extract(e.payload, '$.input_origin'), 'local')
               != 'remote_relay_suspected'
           AND {where_clause}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut velocities: Vec<f64> = Vec::new();
    while let Some(row) = rows.next()? {
        let distance_px: Option<f64> = row.get(0)?;
        let duration_ms: Option<f64> = row.get(1)?;
        let (Some(distance_px), Some(duration_ms)) = (distance_px, duration_ms) else {
            continue;
        };
        if duration_ms > 0.0 && distance_px > 0.0 {
            velocities.push(distance_px / (duration_ms / 1000.0));
        }
    }
    if velocities.is_empty() {
        return Ok((None, None, 0));
    }
    let mut median_values = velocities.clone();
    let median = median_f64(&mut median_values).map(round_1dp);
    let p90 = Some(round_1dp(percentile_nearest_rank(&velocities, 90.0)));
    Ok((median, p90, velocities.len() as i64))
}

/// Mirrors the stage-4 core fields of `read_rhythm_metrics`: heatmap,
/// printable-only typing bursts, and relay-excluded mouse velocity.
pub fn rhythm_metrics_core(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<RhythmMetricsCore> {
    let heatmap = rhythm_heatmap(conn, scope)?;
    let (typing_median, typing_p90, typing_count, classified_fraction) =
        typing_burst_rates(conn, scope)?;
    let (mouse_median, mouse_p90, mouse_samples) = mouse_velocities(conn, scope)?;
    Ok(RhythmMetricsCore {
        heatmap,
        typing_burst_wpm_median: typing_median,
        typing_burst_wpm_p90: typing_p90,
        typing_burst_count: typing_count,
        typing_classified_fraction: classified_fraction,
        mouse_velocity_median_px_s: mouse_median,
        mouse_velocity_p90_px_s: mouse_p90,
        mouse_move_samples: mouse_samples,
    })
}

/// Mirrors `read_rhythm_metrics`, with `now_ms` injected for deterministic
/// `friction_windows.today_count` parity.
pub fn rhythm_metrics(
    conn: &Connection,
    scope: &Scope,
    now_ms: i64,
) -> rusqlite::Result<RhythmMetrics> {
    let core = rhythm_metrics_core(conn, scope)?;
    let friction_windows = time_of_day_friction_windows(conn, scope, now_ms)?;
    Ok(RhythmMetrics {
        heatmap: core.heatmap,
        typing_burst_wpm_median: core.typing_burst_wpm_median,
        typing_burst_wpm_p90: core.typing_burst_wpm_p90,
        typing_burst_count: core.typing_burst_count,
        typing_classified_fraction: core.typing_classified_fraction,
        mouse_velocity_median_px_s: core.mouse_velocity_median_px_s,
        mouse_velocity_p90_px_s: core.mouse_velocity_p90_px_s,
        mouse_move_samples: core.mouse_move_samples,
        friction_windows,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppDwell {
    pub app: String,
    pub active_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkEpisode {
    pub start_ms: i64,
    pub end_ms: i64,
    pub active_ms: i64,
    pub apps: Vec<AppDwell>,
    pub dominant_app: String,
    pub switch_count: i64,
    pub local_date: String,
    pub sphere: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SphereAppRollup {
    pub app: String,
    pub episode_count: i64,
    pub active_ms: i64,
    pub days: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SphereSkeleton {
    pub episodes: Vec<WorkEpisode>,
    pub app_rollup: Vec<SphereAppRollup>,
    pub total_active_ms: i64,
    pub median_episode_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SphereRollup {
    pub sphere: String,
    pub active_ms: i64,
    pub episode_count: i64,
    pub days: i64,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SphereOverlay {
    pub episodes: Vec<WorkEpisode>,
    pub spheres: Vec<SphereRollup>,
    pub total_active_ms: i64,
    pub labeled_active_ms: i64,
    pub labeled_fraction: Option<f64>,
}

// Python 3.12's Unicode regex character classes (UCD 15.0). Spell these out
// so future regex crate table upgrades cannot silently move the frozen oracle.
const PYTHON_REGEX_WHITESPACE: &str = r"[\x{9}-\x{D}\x{1C}-\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}-\x{2029}\x{202F}\x{205F}\x{3000}]";
const PYTHON_REGEX_DECIMAL: &str = concat!(
    r"[\x{30}-\x{39}\x{660}-\x{669}\x{6F0}-\x{6F9}\x{7C0}-\x{7C9}",
    r"\x{966}-\x{96F}\x{9E6}-\x{9EF}\x{A66}-\x{A6F}\x{AE6}-\x{AEF}",
    r"\x{B66}-\x{B6F}\x{BE6}-\x{BEF}\x{C66}-\x{C6F}\x{CE6}-\x{CEF}",
    r"\x{D66}-\x{D6F}\x{DE6}-\x{DEF}\x{E50}-\x{E59}\x{ED0}-\x{ED9}",
    r"\x{F20}-\x{F29}\x{1040}-\x{1049}\x{1090}-\x{1099}\x{17E0}-\x{17E9}",
    r"\x{1810}-\x{1819}\x{1946}-\x{194F}\x{19D0}-\x{19D9}\x{1A80}-\x{1A89}",
    r"\x{1A90}-\x{1A99}\x{1B50}-\x{1B59}\x{1BB0}-\x{1BB9}\x{1C40}-\x{1C49}",
    r"\x{1C50}-\x{1C59}\x{A620}-\x{A629}\x{A8D0}-\x{A8D9}\x{A900}-\x{A909}",
    r"\x{A9D0}-\x{A9D9}\x{A9F0}-\x{A9F9}\x{AA50}-\x{AA59}\x{ABF0}-\x{ABF9}",
    r"\x{FF10}-\x{FF19}\x{104A0}-\x{104A9}\x{10D30}-\x{10D39}",
    r"\x{11066}-\x{1106F}\x{110F0}-\x{110F9}\x{11136}-\x{1113F}",
    r"\x{111D0}-\x{111D9}\x{112F0}-\x{112F9}\x{11450}-\x{11459}",
    r"\x{114D0}-\x{114D9}\x{11650}-\x{11659}\x{116C0}-\x{116C9}",
    r"\x{11730}-\x{11739}\x{118E0}-\x{118E9}\x{11950}-\x{11959}",
    r"\x{11C50}-\x{11C59}\x{11D50}-\x{11D59}\x{11DA0}-\x{11DA9}",
    r"\x{11F50}-\x{11F59}\x{16A60}-\x{16A69}\x{16AC0}-\x{16AC9}",
    r"\x{16B50}-\x{16B59}\x{1D7CE}-\x{1D7FF}\x{1E140}-\x{1E149}",
    r"\x{1E2F0}-\x{1E2F9}\x{1E4F0}-\x{1E4F9}\x{1E950}-\x{1E959}",
    r"\x{1FBF0}-\x{1FBF9}]",
);

fn is_python_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'..='\u{000d}'
            | '\u{001c}'..='\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_trim(text: &str) -> &str {
    text.trim_matches(is_python_whitespace)
}

fn unread_count_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(&format!(
            r"^\({PYTHON_REGEX_DECIMAL}+\){PYTHON_REGEX_WHITESPACE}*|{PYTHON_REGEX_WHITESPACE}*\({PYTHON_REGEX_DECIMAL}+\)$"
        ))
        .expect("unread-count regex is valid")
    })
}

fn remove_unread_count(text: String) -> String {
    let without_count = unread_count_regex().replace_all(&text, "");
    python_trim(&without_count).to_string()
}

fn more_pages_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(&format!(
            concat!(
                r"{PYTHON_REGEX_WHITESPACE}+[aA][nN][dD]{PYTHON_REGEX_WHITESPACE}+",
                r"{PYTHON_REGEX_DECIMAL}+{PYTHON_REGEX_WHITESPACE}+[mM][oO][rR][eE]",
                r"{PYTHON_REGEX_WHITESPACE}+[pP][aA][gG][eE][sS\x{{17F}}]?$",
            ),
            PYTHON_REGEX_WHITESPACE = PYTHON_REGEX_WHITESPACE,
            PYTHON_REGEX_DECIMAL = PYTHON_REGEX_DECIMAL,
        ))
        .expect("more-pages regex is valid")
    })
}

fn remove_more_pages(text: &str) -> String {
    let without_suffix = more_pages_regex().replace(text, "");
    python_trim(&without_suffix).to_string()
}

fn browser_chrome_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(&format!(
            concat!(
                r"(?i){PYTHON_REGEX_WHITESPACE}+[-–—]{PYTHON_REGEX_WHITESPACE}+",
                r"(?:[^-–—|]{{1,40}}{PYTHON_REGEX_WHITESPACE}+[-–—]",
                r"{PYTHON_REGEX_WHITESPACE}+)?",
                // Python re.IGNORECASE additionally equates ASCII I with
                // dotted/dotless I. Rust regex handles long-s simple-folding
                // but needs these two Python-specific members spelled out.
                r"(?:M[iİı]crosoft Edge|Google Chrome|Mozilla F[iİı]refox|",
                r"F[iİı]refox|Brave|Opera|V[iİı]vald[iİı])$",
            ),
            PYTHON_REGEX_WHITESPACE = PYTHON_REGEX_WHITESPACE,
        ))
        .expect("browser-chrome regex is valid")
    })
}

fn remove_browser_chrome(text: &str) -> String {
    browser_chrome_regex().replace(text, "").to_string()
}

fn split_sphere_first(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    for idx in 0..chars.len() {
        let ch = chars[idx];
        let is_separator = matches!(ch, '-' | '–' | '—' | '|' | '·');
        if !is_separator
            || idx == 0
            || idx + 1 >= chars.len()
            || !is_python_whitespace(chars[idx - 1])
            || !is_python_whitespace(chars[idx + 1])
        {
            continue;
        }
        let first = chars[..idx].iter().collect::<String>();
        return python_trim(&first).to_string();
    }
    python_trim(text).to_string()
}

/// Mirrors `sphere_token`: normalize a stored window title into the opt-in
/// Working Spheres token. Empty/redacted/no-letter titles return `None`.
pub fn sphere_token(title: Option<&str>) -> Option<String> {
    let mut text = title?
        .replace(['\u{200b}', '\u{200c}'], "")
        .trim_matches(is_python_whitespace)
        .to_string();
    if text.is_empty() || text == "<redacted>" {
        return None;
    }
    text = remove_browser_chrome(&text);
    text = remove_more_pages(&text);
    text = remove_unread_count(text);
    if text.is_empty() {
        return None;
    }
    let mut first = split_sphere_first(&text);
    first = remove_more_pages(&first);
    first = remove_unread_count(first);
    let candidate = if first.chars().count() >= 2 {
        first
    } else {
        text
    };
    if candidate.chars().count() < 2 || !candidate.chars().any(is_python_3_12_alpha) {
        None
    } else {
        Some(candidate)
    }
}

pub fn sphere_label(title: Option<&str>, aliases: &HashMap<String, String>) -> Option<String> {
    let token = sphere_token(title)?;
    Some(
        aliases
            .get(&sphere_casefold(&token))
            .cloned()
            .unwrap_or(token),
    )
}

pub fn live_sphere_tokens(conn: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare(
        "
        SELECT DISTINCT title FROM (
            SELECT prev_title AS title FROM events WHERE prev_title IS NOT NULL
            UNION
            SELECT title FROM events WHERE title IS NOT NULL
        )
        ",
    )?;
    let mut rows = stmt.query([])?;
    let mut tokens = HashSet::new();
    while let Some(row) = rows.next()? {
        let title: Option<String> = row.get(0)?;
        if let Some(token) = sphere_token(title.as_deref()) {
            tokens.insert(sphere_casefold(&token));
        }
    }
    Ok(tokens)
}

type TokenDwell = HashMap<String, (String, i64)>;
type AppRollupAccum = (String, (i64, i64, HashSet<String>));
type SphereRollupAccum = (String, (i64, i64, HashSet<String>, HashSet<String>));

fn build_work_episode(subs: &[(i64, i64, String, Option<String>)]) -> (WorkEpisode, TokenDwell) {
    let mut by_app: Vec<(String, i64)> = Vec::new();
    let mut by_app_index: HashMap<String, usize> = HashMap::new();
    let mut seq_apps: Vec<String> = Vec::new();
    let mut token_dwell: TokenDwell = HashMap::new();
    for (start, end, app, title) in subs {
        let dwell = end - start;
        bump_ordered(&mut by_app, &mut by_app_index, app.clone(), dwell);
        if seq_apps.last() != Some(app) {
            seq_apps.push(app.clone());
        }
        if let Some(token) = sphere_token(title.as_deref()) {
            let key = sphere_casefold(&token);
            let entry = token_dwell.entry(key).or_insert((token, 0));
            entry.1 += dwell;
        }
    }
    by_app.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let start_ms = subs.first().map(|row| row.0).unwrap_or(0);
    let end_ms = subs.last().map(|row| row.1).unwrap_or(start_ms);
    let active_ms: i64 = subs.iter().map(|(start, end, _, _)| end - start).sum();
    let apps: Vec<AppDwell> = by_app
        .iter()
        .map(|(app, active_ms)| AppDwell {
            app: app.clone(),
            active_ms: *active_ms,
        })
        .collect();
    let dominant_app = apps.first().map(|row| row.app.clone()).unwrap_or_default();
    (
        WorkEpisode {
            start_ms,
            end_ms,
            active_ms,
            apps,
            dominant_app,
            switch_count: 0.max(seq_apps.len() as i64 - 1),
            local_date: local_date(start_ms),
            sphere: None,
        },
        token_dwell,
    )
}

fn sphere_casefold(value: &str) -> String {
    CaseMapper::new().fold_string(value.trim())
}

fn collect_work_episodes(
    conn: &Connection,
    scope: &Scope,
    read_titles: bool,
) -> rusqlite::Result<Vec<(WorkEpisode, TokenDwell)>> {
    let mut focus = focus_intervals(conn, scope)?;
    if focus.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = focus.iter().map(|row| row.session_id).collect();
    let idle = idle_intervals(conn, &ids, None)?;
    let sleep = sleep_intervals(conn, &ids)?;
    let lo = focus.iter().map(|row| row.start_ts).min().unwrap_or(0);
    let hi = focus.iter().map(|row| row.end_ts).max().unwrap_or(0);
    let away_by_session = away_spans_by_session(&idle, &sleep, lo, hi);
    focus.sort_by_key(|row| (row.session_id, row.seq));

    let empty: Vec<(i64, i64)> = Vec::new();
    let mut subs: Vec<(i64, i64, i64, String, Option<String>)> = Vec::new();
    for row in &focus {
        if row.end_ts <= row.start_ts {
            continue;
        }
        let session_away = away_by_session.get(&row.session_id).unwrap_or(&empty);
        let app = display_app(Some(&row.exe));
        let title = read_titles.then(|| row.title.clone());
        for (piece_start, piece_end) in subtract_spans(row.start_ts, row.end_ts, session_away) {
            subs.push((
                row.session_id,
                piece_start,
                piece_end,
                app.clone(),
                title.clone(),
            ));
        }
    }
    if subs.is_empty() {
        return Ok(Vec::new());
    }
    subs.sort_by_key(|row| (row.0, row.1));

    let mut collected: Vec<(WorkEpisode, TokenDwell)> = Vec::new();
    let mut current: Vec<(i64, i64, String, Option<String>)> = Vec::new();
    let mut prev_session: Option<i64> = None;
    let mut prev_end: Option<i64> = None;
    for (session_id, start, end, app, title) in subs {
        let broke = prev_session.is_some_and(|prev| prev != session_id)
            || prev_end.is_some_and(|prev| start - prev > EPISODE_GAP_MS);
        if broke && !current.is_empty() {
            collected.push(build_work_episode(&current));
            current.clear();
        }
        current.push((start, end, app, title));
        prev_session = Some(session_id);
        prev_end = Some(end);
    }
    if !current.is_empty() {
        collected.push(build_work_episode(&current));
    }
    Ok(collected)
}

pub fn working_spheres_skeleton(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<SphereSkeleton> {
    let collected = collect_work_episodes(conn, scope, false)?;
    if collected.is_empty() {
        return Ok(SphereSkeleton {
            episodes: Vec::new(),
            app_rollup: Vec::new(),
            total_active_ms: 0,
            median_episode_ms: None,
        });
    }
    let episodes: Vec<WorkEpisode> = collected.into_iter().map(|(episode, _)| episode).collect();
    let mut rollup: Vec<AppRollupAccum> = Vec::new();
    let mut rollup_index: HashMap<String, usize> = HashMap::new();
    for episode in &episodes {
        if let Some(&position) = rollup_index.get(&episode.dominant_app) {
            rollup[position].1 .0 += 1;
            rollup[position].1 .1 += episode.active_ms;
            rollup[position].1 .2.insert(episode.local_date.clone());
        } else {
            let mut days = HashSet::new();
            days.insert(episode.local_date.clone());
            rollup_index.insert(episode.dominant_app.clone(), rollup.len());
            rollup.push((episode.dominant_app.clone(), (1, episode.active_ms, days)));
        }
    }
    rollup.sort_by_key(|row| std::cmp::Reverse(row.1 .1));
    let app_rollup = rollup
        .into_iter()
        .map(|(app, (episode_count, active_ms, days))| SphereAppRollup {
            app,
            episode_count,
            active_ms,
            days: days.len() as i64,
        })
        .collect();
    let total_active_ms = episodes.iter().map(|episode| episode.active_ms).sum();
    let mut durations: Vec<i64> = episodes.iter().map(|episode| episode.active_ms).collect();
    Ok(SphereSkeleton {
        episodes,
        app_rollup,
        total_active_ms,
        median_episode_ms: median_i64(&mut durations),
    })
}

pub fn working_spheres_overlay(
    conn: &Connection,
    scope: &Scope,
    aliases: &HashMap<String, String>,
) -> rusqlite::Result<SphereOverlay> {
    let collected = collect_work_episodes(conn, scope, true)?;
    if collected.is_empty() {
        return Ok(SphereOverlay {
            episodes: Vec::new(),
            spheres: Vec::new(),
            total_active_ms: 0,
            labeled_active_ms: 0,
            labeled_fraction: None,
        });
    }

    let mut episodes: Vec<WorkEpisode> = Vec::new();
    let mut spheres: Vec<SphereRollupAccum> = Vec::new();
    let mut sphere_index: HashMap<String, usize> = HashMap::new();
    let mut labeled_active_ms = 0i64;
    let mut total_active_ms = 0i64;
    for (mut episode, token_dwell) in collected {
        total_active_ms += episode.active_ms;
        let winner = token_dwell
            .iter()
            .max_by(|left, right| left.1 .1.cmp(&right.1 .1).then_with(|| left.0.cmp(right.0)))
            .map(|(key, (display, _))| (key.clone(), display.clone()));
        if let Some((key, display)) = winner {
            let label = aliases.get(&key).cloned().unwrap_or(display.clone());
            episode.sphere = Some(label.clone());
            labeled_active_ms += episode.active_ms;
            if let Some(&position) = sphere_index.get(&label) {
                spheres[position].1 .0 += episode.active_ms;
                spheres[position].1 .1 += 1;
                spheres[position].1 .2.insert(episode.local_date.clone());
                spheres[position].1 .3.insert(display);
            } else {
                let mut days = HashSet::new();
                days.insert(episode.local_date.clone());
                let mut tokens = HashSet::new();
                tokens.insert(display);
                sphere_index.insert(label.clone(), spheres.len());
                spheres.push((label, (episode.active_ms, 1, days, tokens)));
            }
        }
        episodes.push(episode);
    }

    let mut recurring: Vec<SphereRollupAccum> = Vec::new();
    let mut one_offs: Vec<SphereRollupAccum> = Vec::new();
    for row in spheres {
        if row.1 .1 >= SPHERE_ROLLUP_MIN_EPISODES {
            recurring.push(row);
        } else {
            one_offs.push(row);
        }
    }
    recurring.sort_by(|left, right| {
        right
            .1
             .0
            .cmp(&left.1 .0)
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut sphere_rows: Vec<SphereRollup> = recurring
        .into_iter()
        .map(|(sphere, (active_ms, episode_count, days, tokens))| {
            let mut tokens: Vec<String> = tokens.into_iter().collect();
            tokens.sort();
            SphereRollup {
                sphere,
                active_ms,
                episode_count,
                days: days.len() as i64,
                tokens,
            }
        })
        .collect();
    if !one_offs.is_empty() {
        let active_ms = one_offs.iter().map(|(_, entry)| entry.0).sum();
        let episode_count = one_offs.iter().map(|(_, entry)| entry.1).sum();
        let mut days: HashSet<String> = HashSet::new();
        let mut tokens: HashSet<String> = HashSet::new();
        for (_, (_, _, row_days, row_tokens)) in one_offs {
            days.extend(row_days);
            tokens.extend(row_tokens);
        }
        let mut tokens: Vec<String> = tokens.into_iter().collect();
        tokens.sort();
        sphere_rows.push(SphereRollup {
            sphere: SPHERE_ONE_OFF_LABEL.to_string(),
            active_ms,
            episode_count,
            days: days.len() as i64,
            tokens,
        });
    }
    Ok(SphereOverlay {
        episodes,
        spheres: sphere_rows,
        total_active_ms,
        labeled_active_ms,
        labeled_fraction: (total_active_ms > 0)
            .then(|| labeled_active_ms as f64 / total_active_ms as f64),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternCandidate {
    pub category: String,
    pub band: String,
    pub title: String,
    pub evidence: String,
    pub why: String,
    pub suggested_next_step: String,
    pub support_count: i64,
    pub support_sessions: i64,
    pub support_days: i64,
    pub kind: String,
    pub dedup_apps: Vec<String>,
    pub sort_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PatternDisplay {
    pub strip: Vec<PatternCandidate>,
    pub remainder: Vec<PatternCandidate>,
}

fn sorted_app_set<I>(apps: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    apps.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn high_band_days(history_days: i64) -> i64 {
    (HIGH_BAND_DAYS_FRACTION * history_days as f64)
        .ceil()
        .max(3.0) as i64
}

fn sequence_band(
    support_count: i64,
    recurrence: i64,
    median_step_ms: f64,
    support_days: i64,
    history_days: i64,
) -> &'static str {
    if support_count >= 24
        && support_days >= high_band_days(history_days)
        && median_step_ms <= 30_000.0
    {
        "High"
    } else if support_count >= 12 && recurrence >= 2 && median_step_ms <= 60_000.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn fragmentation_band(
    support_count: i64,
    recurrence: i64,
    support_days: i64,
    history_days: i64,
) -> &'static str {
    if support_count >= 24 && support_days >= high_band_days(history_days) {
        "High"
    } else if support_count >= 12 && recurrence >= 2 {
        "Medium"
    } else {
        "Low"
    }
}

fn focus_churn_band(
    support_count: i64,
    recurrence: i64,
    median_ms: f64,
    support_days: i64,
    history_days: i64,
) -> &'static str {
    if support_count >= 24 && support_days >= high_band_days(history_days) && median_ms <= 15_000.0
    {
        "High"
    } else if support_count >= 12 && recurrence >= 2 && median_ms <= 30_000.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn window_churn_band(
    support_count: i64,
    recurrence: i64,
    median_ms: f64,
    support_days: i64,
    history_days: i64,
) -> &'static str {
    if support_count >= 18 && support_days >= high_band_days(history_days) && median_ms <= 90_000.0
    {
        "High"
    } else if support_count >= 9 && recurrence >= 2 && median_ms <= 180_000.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn input_exposure_band(long_runs: i64, support_days: i64, longest_ms: i64) -> &'static str {
    if (long_runs >= 8 && support_days >= 3) || longest_ms >= 7_200_000 {
        "High"
    } else if long_runs >= 6 || longest_ms >= 4_500_000 {
        "Medium"
    } else {
        "Low"
    }
}

fn clipboard_transfer_band(support_count: i64, support_days: i64) -> &'static str {
    if support_count >= 24 && support_days >= 4 {
        "High"
    } else if support_count >= 12 && support_days >= 3 {
        "Medium"
    } else {
        "Low"
    }
}

fn band_rank(band: &str) -> i64 {
    match band {
        "Low" => 1,
        "Medium" => 2,
        "High" => 3,
        _ => 0,
    }
}

fn category_priority(category: &str) -> i64 {
    match category {
        "input_exposure" => 5,
        "focus_churn" | "repeated_window_churn" | CANDIDATE_CATEGORY_CLIPBOARD => 4,
        "fragmentation" => 3,
        "sequence_routine" => 2,
        _ => 1,
    }
}

pub fn pattern_history_days(conn: &Connection, scope: &Scope) -> rusqlite::Result<i64> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql =
        format!("SELECT e.ts FROM events e WHERE e.kind = 'focus_changed' AND {where_clause}");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut dates = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let ts: i64 = row.get(0)?;
        dates.insert(local_date(ts));
    }
    Ok(dates.len() as i64)
}

#[derive(Default)]
struct PairDurationAccum {
    durations: Vec<i64>,
    sessions: HashSet<i64>,
    dates: HashSet<String>,
}

fn focus_churn_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let sql = format!(
        "SELECT e.session_id, e.ts,
                COALESCE(NULLIF(e.prev_exe, ''), '(unknown)') AS prev_exe,
                COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe,
                COALESCE(e.duration_ms, 0) AS duration_ms
         FROM events e
         WHERE e.kind = 'focus_changed'
           AND e.prev_exe IS NOT NULL
           AND e.exe IS NOT NULL
           AND e.duration_ms IS NOT NULL
           AND {where_clause}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut grouped: BTreeMap<(String, String), PairDurationAccum> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let session_id: i64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let prev_exe: String = row.get(2)?;
        let exe: String = row.get(3)?;
        let duration_ms: i64 = row.get(4)?;
        let prev_app = display_app(Some(&prev_exe));
        let app = display_app(Some(&exe));
        if prev_app == "(unknown)" || app == "(unknown)" || prev_app == app {
            continue;
        }
        let (app_a, app_b) = if prev_app <= app {
            (prev_app, app)
        } else {
            (app, prev_app)
        };
        let entry = grouped.entry((app_a, app_b)).or_default();
        entry.durations.push(duration_ms);
        entry.sessions.insert(session_id);
        entry.dates.insert(local_date(ts));
    }

    let history_days = pattern_history_days(conn, scope)?;
    let mut out = Vec::new();
    for ((app_a, app_b), entry) in grouped {
        let support_count = entry.durations.len() as i64;
        let support_sessions = entry.sessions.len() as i64;
        let support_days = entry.dates.len() as i64;
        let recurrence = support_sessions.max(support_days);
        let median_ms = median_i64_as_f64(&mut entry.durations.clone()).unwrap_or(0.0);
        if support_count < 8 || recurrence < 2 || median_ms > 30_000.0 {
            continue;
        }
        let band = focus_churn_band(
            support_count,
            recurrence,
            median_ms,
            support_days,
            history_days,
        );
        out.push(PatternCandidate {
            category: "focus_churn".to_string(),
            kind: CANDIDATE_KIND_FRAGMENTATION.to_string(),
            dedup_apps: sorted_app_set([app_a.clone(), app_b.clone()]),
            band: band.to_string(),
            title: format!("Review switching between {app_a} and {app_b}"),
            evidence: format!(
                "{support_count} short focus transitions; median dwell {:.1}s; seen across {support_sessions} sessions and {support_days} local dates.",
                median_ms / 1000.0
            ),
            // UX-37 (owner decision 2026-07-10): the per-card hedge is stated
            // once under the section kicker on both dashboards.
            why: CARD_WHY_SWITCHING.to_string(),
            suggested_next_step: CARD_NEXT_SWITCHING.to_string(),
            support_count,
            support_sessions,
            support_days,
            sort_score: 0.0,
        });
    }
    Ok(out)
}

fn window_churn_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let (where_clause, params) = scope_predicate("e", scope);
    let origin_expr =
        format!("COALESCE(json_extract(e.payload, '$.origin'), '{WINDOW_ORIGIN_OBSERVED}')");
    let sql = format!(
        "SELECT e.session_id, e.ts,
                COALESCE(NULLIF(e.exe, ''), '(unknown)') AS exe,
                COALESCE(e.duration_ms, 0) AS duration_ms
         FROM events e
         WHERE e.kind = 'window_closed'
           AND e.duration_ms IS NOT NULL
           AND {origin_expr} = '{WINDOW_ORIGIN_OBSERVED}'
           AND {where_clause}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
    let mut grouped: BTreeMap<String, PairDurationAccum> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let exe: String = row.get(2)?;
        let app = display_app(Some(&exe));
        if app == "(unknown)" {
            continue;
        }
        let session_id: i64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let duration_ms: i64 = row.get(3)?;
        let entry = grouped.entry(app).or_default();
        entry.durations.push(duration_ms);
        entry.sessions.insert(session_id);
        entry.dates.insert(local_date(ts));
    }

    let history_days = pattern_history_days(conn, scope)?;
    let mut out = Vec::new();
    for (app, entry) in grouped {
        let support_count = entry.durations.len() as i64;
        let support_sessions = entry.sessions.len() as i64;
        let support_days = entry.dates.len() as i64;
        let recurrence = support_sessions.max(support_days);
        let median_ms = median_i64_as_f64(&mut entry.durations.clone()).unwrap_or(0.0);
        if support_count < 6 || recurrence < 2 || median_ms > 180_000.0 {
            continue;
        }
        let band = window_churn_band(
            support_count,
            recurrence,
            median_ms,
            support_days,
            history_days,
        );
        out.push(PatternCandidate {
            category: "repeated_window_churn".to_string(),
            kind: CANDIDATE_KIND_ROUTINE.to_string(),
            dedup_apps: vec![format!("window:{app}")],
            band: band.to_string(),
            title: format!("Review short-lived {app} windows"),
            evidence: format!(
                "{support_count} observed window closes; median open time {:.1}s; seen across {support_sessions} sessions and {support_days} local dates.",
                median_ms / 1000.0
            ),
            why: CARD_WHY_SHORT_LIVED.to_string(),
            suggested_next_step: CARD_NEXT_SHORT_LIVED.to_string(),
            support_count,
            support_sessions,
            support_days,
            sort_score: 0.0,
        });
    }
    Ok(out)
}

#[derive(Default)]
struct PatternMotif {
    count: i64,
    sessions: HashSet<i64>,
    dates: HashSet<String>,
    step_ms: Vec<i64>,
    covered: HashSet<(usize, usize)>,
}

fn sequence_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let episodes = focus_sequence_episodes(conn, scope)?;
    if episodes.is_empty() || !has_enough_history(&episodes) {
        return Ok(Vec::new());
    }

    let total_steps: usize = episodes.iter().map(Vec::len).sum();
    let mut motifs: Vec<(Vec<String>, PatternMotif)> = Vec::new();
    let mut motif_index: HashMap<Vec<String>, usize> = HashMap::new();
    for (episode_index, episode) in episodes.iter().enumerate() {
        let apps: Vec<String> = episode.iter().map(|step| step.app.clone()).collect();
        let times: Vec<i64> = episode.iter().map(|step| step.ts).collect();
        let count = apps.len();
        for length in 3..=SEQUENCE_MOTIF_MAX_LEN {
            if length > count {
                continue;
            }
            for start in 0..=(count - length) {
                let window = apps[start..start + length].to_vec();
                if window.iter().collect::<HashSet<_>>().len() < 2 {
                    continue;
                }
                let position = if let Some(position) = motif_index.get(&window) {
                    *position
                } else {
                    if motifs.len() >= MOTIF_TRACKING_CAP {
                        continue;
                    }
                    motif_index.insert(window.clone(), motifs.len());
                    motifs.push((window.clone(), PatternMotif::default()));
                    motifs.len() - 1
                };
                let motif = &mut motifs[position].1;
                motif.count += 1;
                motif.sessions.insert(episode[start].session_id);
                motif.dates.insert(episode[start].local_date.clone());
                for idx in start..start + length - 1 {
                    motif.step_ms.push((times[idx + 1] - times[idx]).max(0));
                }
                for idx in start..start + length {
                    motif.covered.insert((episode_index, idx));
                }
            }
        }
    }

    let history_days = pattern_history_days(conn, scope)?;
    let mut out = Vec::new();
    for (window, motif) in motifs {
        let support_count = motif.count;
        let support_sessions = motif.sessions.len() as i64;
        let support_days = motif.dates.len() as i64;
        let recurrence = support_sessions.max(support_days);
        if support_count < SEQUENCE_MIN_SUPPORT || support_days < SEQUENCE_MIN_DAYS as i64 {
            continue;
        }
        let median_step_ms = median_i64_as_f64(&mut motif.step_ms.clone()).unwrap_or(0.0);
        if median_step_ms > SEQUENCE_TIGHTNESS_MAX_MS {
            continue;
        }
        let shape = if window.len() == 3 && window.first() == window.get(2) {
            "round trip"
        } else {
            "sequence"
        };
        let band = sequence_band(
            support_count,
            recurrence,
            median_step_ms,
            support_days,
            history_days,
        );
        let coverage = if total_steps > 0 {
            motif.covered.len() as f64 / total_steps as f64
        } else {
            0.0
        };
        let cohesion = 1.0 / (1.0 + median_step_ms / 1000.0);
        let sort_score = support_count as f64 * window.len() as f64 * coverage * cohesion;
        // copy-allow: arrow ordered routine-path data notation (Lane B ruling)
        let path = window.join(" → ");
        out.push(PatternCandidate {
            category: "sequence_routine".to_string(),
            kind: CANDIDATE_KIND_ROUTINE.to_string(),
            dedup_apps: sorted_app_set(window.clone()),
            sort_score,
            band: band.to_string(),
            title: format!("Review the {shape}: {path}"),
            evidence: format!(
                "{support_count} occurrences; median step {:.1}s; seen across {support_sessions} sessions and {support_days} local dates.",
                median_step_ms / 1000.0
            ),
            why: CARD_WHY_SEQUENCE.to_string(),
            suggested_next_step: CARD_NEXT_SEQUENCE.to_string(),
            support_count,
            support_sessions,
            support_days,
        });
    }
    Ok(out)
}

#[derive(Default)]
struct FragmentationAccum {
    count: i64,
    sessions: HashSet<i64>,
    dates: HashSet<String>,
    away_ms: Vec<i64>,
    others: HashSet<String>,
}

fn fragmentation_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let episodes = focus_sequence_episodes(conn, scope)?;
    if episodes.is_empty() || !has_enough_history(&episodes) {
        return Ok(Vec::new());
    }

    let mut anchors: Vec<(String, FragmentationAccum)> = Vec::new();
    let mut anchor_index: HashMap<String, usize> = HashMap::new();
    for episode in &episodes {
        let apps: Vec<String> = episode.iter().map(|step| step.app.clone()).collect();
        let times: Vec<i64> = episode.iter().map(|step| step.ts).collect();
        for index in 0..apps.len().saturating_sub(2) {
            let anchor = &apps[index];
            let away = &apps[index + 1];
            let back = &apps[index + 2];
            if anchor == back && anchor != away {
                let position = if let Some(position) = anchor_index.get(anchor) {
                    *position
                } else {
                    anchor_index.insert(anchor.clone(), anchors.len());
                    anchors.push((anchor.clone(), FragmentationAccum::default()));
                    anchors.len() - 1
                };
                let record = &mut anchors[position].1;
                record.count += 1;
                record.sessions.insert(episode[index].session_id);
                record.dates.insert(episode[index].local_date.clone());
                record
                    .away_ms
                    .push((times[index + 2] - times[index + 1]).max(0));
                record.others.insert(away.clone());
            }
        }
    }

    let history_days = pattern_history_days(conn, scope)?;
    let mut out = Vec::new();
    for (app, record) in anchors {
        let support_count = record.count;
        let support_sessions = record.sessions.len() as i64;
        let support_days = record.dates.len() as i64;
        let recurrence = support_sessions.max(support_days);
        if support_count < FRAGMENTATION_MIN_ROUNDTRIPS || support_days < SEQUENCE_MIN_DAYS as i64 {
            continue;
        }
        let median_away_ms = median_i64_as_f64(&mut record.away_ms.clone()).unwrap_or(0.0);
        let mut others: Vec<String> = record.others.into_iter().collect();
        others.sort();
        let others_text = others
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let mut dedup = others.clone();
        dedup.push(app.clone());
        let band = fragmentation_band(support_count, recurrence, support_days, history_days);
        out.push(PatternCandidate {
            category: "fragmentation".to_string(),
            kind: CANDIDATE_KIND_FRAGMENTATION.to_string(),
            dedup_apps: sorted_app_set(dedup),
            band: band.to_string(),
            title: format!("You keep leaving and returning to {app}"),
            evidence: format!(
                "{support_count} round trips away from {app} (to {others_text}); median elapsed away {:.1}s; across {support_sessions} sessions and {support_days} local dates.",
                median_away_ms / 1000.0
            ),
            why: CARD_WHY_RETURNS.to_string(),
            suggested_next_step: CARD_NEXT_RETURNS.to_string(),
            support_count,
            support_sessions,
            support_days,
            sort_score: 0.0,
        });
    }
    Ok(out)
}

fn input_exposure_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let runs = input_runs(conn, scope)?;
    let long_runs: Vec<InputRun> = runs
        .into_iter()
        .filter(|run| run.run_ms >= INPUT_EXPOSURE_LONG_RUN_MS)
        .collect();
    if long_runs.len() < INPUT_EXPOSURE_MIN_LONG_RUNS {
        return Ok(Vec::new());
    }
    let dates: HashSet<String> = long_runs
        .iter()
        .map(|run| run.start_local_date.clone())
        .collect();
    if dates.len() < SEQUENCE_MIN_DAYS {
        return Ok(Vec::new());
    }
    let sessions: HashSet<i64> = long_runs.iter().map(|run| run.session_id).collect();
    let longest_ms = long_runs.iter().map(|run| run.run_ms).max().unwrap_or(0);
    let mut app_totals: Vec<(String, i64)> = Vec::new();
    let mut app_index: HashMap<String, usize> = HashMap::new();
    for run in &long_runs {
        let mut ordered = run.exe_order.clone();
        for exe in run.exe_counts.keys() {
            if !ordered.iter().any(|existing| existing == exe) {
                ordered.push(exe.clone());
            }
        }
        for exe in ordered {
            let count = run.exe_counts.get(&exe).copied().unwrap_or(0);
            let app = display_app(Some(&exe));
            if let Some(position) = app_index.get(&app).copied() {
                app_totals[position].1 += count;
            } else {
                app_index.insert(app.clone(), app_totals.len());
                app_totals.push((app, count));
            }
        }
    }
    app_totals.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let top_apps = app_totals
        .iter()
        .take(3)
        .map(|(app, _)| app.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let band = input_exposure_band(long_runs.len() as i64, dates.len() as i64, longest_ms);
    Ok(vec![PatternCandidate {
        category: "input_exposure".to_string(),
        kind: CANDIDATE_KIND_INPUT_EXPOSURE.to_string(),
        dedup_apps: Vec::new(),
        band: band.to_string(),
        title: CARD_TITLE_INPUT_STRETCHES.to_string(),
        evidence: format!(
            "{} input stretches over {} min with no pause over 3 min (longest {} min; mostly {top_apps}); across {} local dates.",
            long_runs.len(),
            INPUT_EXPOSURE_LONG_RUN_MS / 60_000,
            longest_ms / 60_000,
            dates.len()
        ),
        why: CARD_WHY_INPUT_STRETCHES.to_string(),
        suggested_next_step: CARD_NEXT_INPUT_STRETCHES.to_string(),
        support_count: long_runs.len() as i64,
        support_sessions: sessions.len() as i64,
        support_days: dates.len() as i64,
        sort_score: 0.0,
    }])
}

#[derive(Default)]
struct ClipboardTransferAccum {
    directions: Vec<((String, String), i64)>,
    dates: HashSet<String>,
    sessions: HashSet<i64>,
    per_date: HashMap<String, i64>,
    char_counts: Vec<i64>,
}

fn clipboard_transfer_candidates(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let records = clipboard_bridge_records(conn, scope)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let mut pairs: Vec<(Vec<String>, ClipboardTransferAccum)> = Vec::new();
    let mut pair_index: HashMap<Vec<String>, usize> = HashMap::new();
    for record in records {
        let key = sorted_app_set([record.source.clone(), record.destination.clone()]);
        let position = if let Some(position) = pair_index.get(&key) {
            *position
        } else {
            pair_index.insert(key.clone(), pairs.len());
            pairs.push((key.clone(), ClipboardTransferAccum::default()));
            pairs.len() - 1
        };
        let entry = &mut pairs[position].1;
        let direction = (record.source.clone(), record.destination.clone());
        if let Some((_, count)) = entry
            .directions
            .iter_mut()
            .find(|(existing, _)| existing == &direction)
        {
            *count += 1;
        } else {
            entry.directions.push((direction, 1));
        }
        entry.dates.insert(record.local_date.clone());
        entry.sessions.insert(record.session_id);
        *entry.per_date.entry(record.local_date.clone()).or_insert(0) += 1;
        if let Some(count) = record.text_char_count {
            entry.char_counts.push(count);
        }
    }

    let mut out = Vec::new();
    for (apps, entry) in pairs {
        let support_count: i64 = entry.directions.iter().map(|(_, count)| *count).sum();
        let support_days = entry.dates.len() as i64;
        if support_count < CLIPBOARD_TRANSFER_MIN_SUPPORT as i64
            || support_days < SEQUENCE_MIN_DAYS as i64
        {
            continue;
        }
        let top_day = entry.per_date.values().copied().max().unwrap_or(0);
        if top_day as f64 / support_count as f64 > CLIPBOARD_TOP_DAY_SHARE_MAX {
            continue;
        }
        let mut dominant_direction = entry.directions[0].0.clone();
        let mut dominant = entry.directions[0].1;
        for (direction, count) in entry.directions.iter().skip(1) {
            if *count > dominant {
                dominant = *count;
                dominant_direction = direction.clone();
            }
        }
        let (source, destination) = dominant_direction;
        let reverse = support_count - dominant;
        let direction_text = if reverse != 0 {
            format!("{dominant} into {destination}, {reverse} back")
        } else {
            format!("all {dominant} into {destination}")
        };
        let mut evidence = format!(
            "{support_count} copy hand-offs ({direction_text}); across {support_days} local dates"
        );
        if !entry.char_counts.is_empty() {
            let median_chars =
                median_i64_as_f64(&mut entry.char_counts.clone()).unwrap_or(0.0) as i64;
            evidence.push_str(&format!("; median {median_chars} characters when text"));
        }
        evidence.push('.');
        out.push(PatternCandidate {
            category: CANDIDATE_CATEGORY_CLIPBOARD.to_string(),
            kind: CANDIDATE_KIND_ROUTINE.to_string(),
            dedup_apps: apps,
            band: clipboard_transfer_band(support_count, support_days).to_string(),
            title: format!("You often copy from {source} into {destination}"),
            evidence,
            why: CARD_WHY_CLIPBOARD.to_string(),
            suggested_next_step: CARD_NEXT_CLIPBOARD.to_string(),
            support_count,
            support_sessions: entry.sessions.len() as i64,
            support_days,
            sort_score: 0.0,
        });
    }
    Ok(out)
}

fn dedupe_candidates(ranked: Vec<PatternCandidate>) -> Vec<PatternCandidate> {
    let pair_collapse = ["focus_churn", "sequence_routine", "fragmentation"];
    let mut seen_category_cluster: HashSet<(String, Vec<String>)> = HashSet::new();
    let mut seen_pair: HashSet<Vec<String>> = HashSet::new();
    let mut out = Vec::new();
    for candidate in ranked {
        if candidate.dedup_apps.is_empty() {
            out.push(candidate);
            continue;
        }
        if candidate.dedup_apps.len() == 2 && pair_collapse.contains(&candidate.category.as_str()) {
            if seen_pair.contains(&candidate.dedup_apps) {
                continue;
            }
            seen_pair.insert(candidate.dedup_apps.clone());
        }
        let category_key = (candidate.category.clone(), candidate.dedup_apps.clone());
        if seen_category_cluster.contains(&category_key) {
            continue;
        }
        seen_category_cluster.insert(category_key);
        out.push(candidate);
    }
    out
}

fn cap_category_slots(deduped: Vec<PatternCandidate>) -> Vec<PatternCandidate> {
    let mut selected: Vec<usize> = Vec::new();
    let mut overflow: Vec<usize> = Vec::new();
    let mut per_category: HashMap<String, usize> = HashMap::new();
    for (index, candidate) in deduped.iter().enumerate() {
        let count = *per_category.get(&candidate.category).unwrap_or(&0);
        if selected.len() < TOP_N_ANALYTICS && count < CATEGORY_SLOT_CAP {
            per_category.insert(candidate.category.clone(), count + 1);
            selected.push(index);
        } else {
            overflow.push(index);
        }
    }
    let backfill = TOP_N_ANALYTICS.saturating_sub(selected.len());
    if backfill > 0 && !overflow.is_empty() {
        let mut chosen: BTreeSet<usize> = selected.into_iter().collect();
        for index in overflow.into_iter().take(backfill) {
            chosen.insert(index);
        }
        return deduped
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate)| chosen.contains(&index).then_some(candidate))
            .collect();
    }
    selected
        .into_iter()
        .filter_map(|index| deduped.get(index).cloned())
        .collect()
}

fn rank_candidates(candidates: &mut [PatternCandidate]) {
    candidates.sort_by(|left, right| {
        band_rank(&right.band)
            .cmp(&band_rank(&left.band))
            .then_with(|| {
                category_priority(&right.category).cmp(&category_priority(&left.category))
            })
            .then_with(|| {
                right
                    .sort_score
                    .partial_cmp(&left.sort_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| right.support_count.cmp(&left.support_count))
            .then_with(|| right.support_sessions.cmp(&left.support_sessions))
            .then_with(|| right.support_days.cmp(&left.support_days))
    });
}

pub fn patterns_worth_reviewing(
    conn: &Connection,
    scope: &Scope,
) -> rusqlite::Result<Vec<PatternCandidate>> {
    let mut candidates = Vec::new();
    candidates.extend(focus_churn_candidates(conn, scope)?);
    candidates.extend(window_churn_candidates(conn, scope)?);
    candidates.extend(sequence_candidates(conn, scope)?);
    candidates.extend(fragmentation_candidates(conn, scope)?);
    candidates.extend(input_exposure_candidates(conn, scope)?);
    candidates.extend(clipboard_transfer_candidates(conn, scope)?);
    rank_candidates(&mut candidates);
    Ok(cap_category_slots(dedupe_candidates(candidates)))
}

pub fn select_pattern_display(candidates: &[PatternCandidate], limit: usize) -> PatternDisplay {
    if candidates.is_empty() {
        return PatternDisplay {
            strip: Vec::new(),
            remainder: Vec::new(),
        };
    }
    let mut seen_categories: HashSet<String> = HashSet::new();
    let mut strip_indices: BTreeSet<usize> = BTreeSet::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if seen_categories.insert(candidate.category.clone()) && strip_indices.len() < limit {
            strip_indices.insert(index);
        }
    }
    for index in 0..candidates.len() {
        if strip_indices.len() >= limit {
            break;
        }
        strip_indices.insert(index);
    }
    let mut strip = Vec::new();
    let mut remainder = Vec::new();
    for (index, candidate) in candidates.iter().cloned().enumerate() {
        if strip_indices.contains(&index) {
            strip.push(candidate);
        } else {
            remainder.push(candidate);
        }
    }
    PatternDisplay { strip, remainder }
}

pub fn select_pattern_display_default(candidates: &[PatternCandidate]) -> PatternDisplay {
    select_pattern_display(candidates, PATTERN_DISPLAY_LIMIT)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordingList {
    pub record_routine_tables_present: bool,
    pub rows: Vec<RecordingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordingRow {
    pub record_session_id: i64,
    pub title: Option<String>,
    pub started_ts: i64,
    pub ended_ts: Option<i64>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub duration_ms: i64,
    pub recording_status: String,
    pub stop_reason: Option<String>,
    pub stop_reason_label: String,
    pub action_count: i64,
    pub session_id: i64,
    pub request_id: Option<i64>,
    pub request_status: Option<String>,
    pub request_requested_at: Option<i64>,
    pub request_expires_at: Option<i64>,
    pub policy_snapshot_json: String,
    pub pause_intervals_json: String,
    pub safety_cap_ms: i64,
    pub visible_indicator: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordingStep {
    pub seq: i64,
    pub captured_at: Option<String>,
    pub action_type: String,
    pub pattern_action: Option<String>,
    pub selector_id: Option<i64>,
    pub selector: String,
    pub framework_class: String,
    pub trust_basis: String,
    pub exe: Option<String>,
    pub is_sensitive: i64,
    pub coverage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecordingExportStep {
    pub seq: i64,
    pub ts: i64,
    pub action_type: String,
    #[serde(default)]
    pub pattern_action: Option<String>,
    #[serde(default)]
    pub selector_id: Option<i64>,
    pub framework_class: String,
    pub trust_basis: String,
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub path_hash: Option<String>,
    #[serde(default)]
    pub selector_backend: Option<String>,
    #[serde(default)]
    pub path_json: Option<String>,
    #[serde(default)]
    pub leaf_rect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordingExportStepBasic {
    pub seq: i64,
    pub ts: i64,
    pub action_type: String,
    pub pattern_action: Option<String>,
    pub selector_id: Option<i64>,
    pub framework_class: String,
    pub trust_basis: String,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordingExportStepWithSelector {
    pub seq: i64,
    pub ts: i64,
    pub action_type: String,
    pub pattern_action: Option<String>,
    pub selector_id: Option<i64>,
    pub framework_class: String,
    pub trust_basis: String,
    pub exe: Option<String>,
    pub path_hash: Option<String>,
    pub selector_backend: Option<String>,
    pub path_json: Option<String>,
    pub leaf_rect: Option<String>,
}

impl From<&RecordingExportStep> for RecordingExportStepBasic {
    fn from(step: &RecordingExportStep) -> Self {
        Self {
            seq: step.seq,
            ts: step.ts,
            action_type: step.action_type.clone(),
            pattern_action: step.pattern_action.clone(),
            selector_id: step.selector_id,
            framework_class: step.framework_class.clone(),
            trust_basis: step.trust_basis.clone(),
            exe: step.exe.clone(),
        }
    }
}

impl From<&RecordingExportStep> for RecordingExportStepWithSelector {
    fn from(step: &RecordingExportStep) -> Self {
        Self {
            seq: step.seq,
            ts: step.ts,
            action_type: step.action_type.clone(),
            pattern_action: step.pattern_action.clone(),
            selector_id: step.selector_id,
            framework_class: step.framework_class.clone(),
            trust_basis: step.trust_basis.clone(),
            exe: step.exe.clone(),
            path_hash: step.path_hash.clone(),
            selector_backend: step.selector_backend.clone(),
            path_json: step.path_json.clone(),
            leaf_rect: step.leaf_rect.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReplayExportVerdict {
    pub state: String,
    pub label: String,
    pub detail: String,
    pub coverage_line: String,
    pub severity: String,
    pub actionable_steps: i64,
    pub native_eligible_steps: i64,
    pub provisional_steps: i64,
    pub native_gap_steps: i64,
    pub hard_veto_steps: i64,
    pub free_input_steps: i64,
    pub noise_steps: i64,
    pub native_eligible_fraction: Option<f64>,
    pub export_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExport {
    pub metadata: ReplayExportMetadata,
    pub steps: Vec<ReplayExportStepItem>,
    pub input_slots: Vec<ReplayInputSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExportMetadata {
    pub schema: String,
    pub schema_version: String,
    pub value_free: bool,
    pub generated_ts: String,
    pub record_session_id: i64,
    pub title: Option<String>,
    pub app_allowlist: Vec<String>,
    pub mode: String,
    pub verdict: ReplayExportVerdictSummary,
    pub source: ReplayExportSource,
    pub review_labels: ReplayExportReviewLabels,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExportVerdictSummary {
    pub state: String,
    pub export_available: bool,
    pub coverage_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExportSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExportReviewLabels {
    pub included: bool,
    pub source: String,
    pub max_chars: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayExportStepItem {
    pub seq: i64,
    pub offset_ms_from_recording_start: i64,
    pub action_type: String,
    pub pattern_action: Option<String>,
    pub intent: String,
    pub framework_class: String,
    pub trust_basis: String,
    pub exe: String,
    pub replay_class: String,
    pub native_replayable: bool,
    pub selector: Option<ReplaySelectorExport>,
    pub input_slot_ref: Option<String>,
    pub review_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayInputSlot {
    pub slot_id: String,
    pub at_step_seq: i64,
    pub role: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub target_selector_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplaySelectorExport {
    pub backend: String,
    pub hops: Vec<ReplaySelectorHopExport>,
    pub path_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_rect: Option<ReplayLeafRect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplaySelectorHopExport {
    pub control_type: i64,
    pub control_type_label: String,
    pub automation_id: String,
    pub class_name: String,
    pub ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayLeafRect {
    pub left: i64,
    pub top: i64,
    pub right: i64,
    pub bottom: i64,
}

#[derive(Debug, Clone)]
struct RecordingExportMetadata {
    started_ts: i64,
    ended_ts: Option<i64>,
    app_version: Option<String>,
    git_sha: Option<String>,
}

pub fn record_request_status(
    conn: &Connection,
    request_id: i64,
) -> rusqlite::Result<Option<String>> {
    if !table_exists(conn, "record_requests")? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT status FROM record_requests WHERE request_id = ?",
        [request_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

pub fn record_routine_tables_present(conn: &Connection) -> rusqlite::Result<bool> {
    for table in [
        "record_requests",
        "record_sessions",
        "selector_paths",
        "action_events",
    ] {
        if !table_exists(conn, table)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn decode_pause_intervals(value: &str) -> Vec<(i64, Option<i64>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };
    let Some(items) = parsed.as_array() else {
        return Vec::new();
    };
    let mut intervals = Vec::new();
    for item in items {
        let Some(pair) = item.as_array() else {
            continue;
        };
        if pair.len() != 2 {
            continue;
        }
        let Some(start) = json_value_int_like(pair.first()) else {
            continue;
        };
        let end = if pair[1].is_null() {
            None
        } else {
            let Some(value) = json_value_int_like(pair.get(1)) else {
                continue;
            };
            Some(value)
        };
        intervals.push((start, end));
    }
    intervals
}

fn json_value_int_like(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Bool(value) => Some(i64::from(*value)),
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64)),
        serde_json::Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    }
}

fn paused_duration_ms(
    intervals: &[(i64, Option<i64>)],
    started_ts: i64,
    ended_ts_or_now: i64,
) -> i64 {
    let mut total = 0;
    for &(start, end) in intervals {
        let pause_start = start.max(started_ts);
        let pause_end = end.unwrap_or(ended_ts_or_now).min(ended_ts_or_now);
        if pause_end > pause_start {
            total += pause_end - pause_start;
        }
    }
    total
}

fn recording_duration_ms(
    started_ts: i64,
    ended_ts: Option<i64>,
    pause_intervals_json: &str,
    now_ms: i64,
) -> i64 {
    let ended_or_now = ended_ts.unwrap_or(now_ms);
    let elapsed = (ended_or_now - started_ts).max(0);
    let paused = paused_duration_ms(
        &decode_pause_intervals(pause_intervals_json),
        started_ts,
        ended_or_now,
    );
    (elapsed - paused).max(0)
}

fn record_stop_reason_label(value: Option<&str>) -> String {
    let Some(raw) = value else {
        return "Recording...".to_string();
    };
    let text = raw.trim();
    if text.is_empty() {
        return "Ended".to_string();
    }
    text.replace('_', " ")
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    let mut out = first.to_uppercase().collect::<String>();
                    out.push_str(&chars.as_str().to_lowercase());
                    out
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn read_recordings(conn: &Connection, now_ms: i64) -> rusqlite::Result<RecordingList> {
    if !table_exists(conn, "record_sessions")? {
        return Ok(RecordingList {
            record_routine_tables_present: false,
            rows: Vec::new(),
        });
    }
    let record_session_columns = table_columns(conn, "record_sessions")?;
    let has_session_request_id = record_session_columns.contains("request_id");
    let request_id_expr = if has_session_request_id {
        "rs.request_id"
    } else {
        "NULL AS request_id"
    };
    let mut request_status_expr = "NULL AS request_status".to_string();
    let mut request_requested_expr = "NULL AS request_requested_at".to_string();
    let mut request_expires_expr = "NULL AS request_expires_at".to_string();
    if table_exists(conn, "record_requests")? {
        let fulfilled_status_expr = "(
            SELECT rr.status
            FROM record_requests rr
            WHERE rr.fulfilled_record_session_id = rs.record_session_id
            ORDER BY rr.request_id
            LIMIT 1
        )";
        let fulfilled_requested_expr = "(
            SELECT rr.requested_at
            FROM record_requests rr
            WHERE rr.fulfilled_record_session_id = rs.record_session_id
            ORDER BY rr.request_id
            LIMIT 1
        )";
        let fulfilled_expires_expr = "(
            SELECT rr.expires_at
            FROM record_requests rr
            WHERE rr.fulfilled_record_session_id = rs.record_session_id
            ORDER BY rr.request_id
            LIMIT 1
        )";
        if has_session_request_id {
            request_status_expr = format!(
                "COALESCE((SELECT rr.status FROM record_requests rr WHERE rr.request_id = rs.request_id LIMIT 1), {fulfilled_status_expr}) AS request_status"
            );
            request_requested_expr = format!(
                "COALESCE((SELECT rr.requested_at FROM record_requests rr WHERE rr.request_id = rs.request_id LIMIT 1), {fulfilled_requested_expr}) AS request_requested_at"
            );
            request_expires_expr = format!(
                "COALESCE((SELECT rr.expires_at FROM record_requests rr WHERE rr.request_id = rs.request_id LIMIT 1), {fulfilled_expires_expr}) AS request_expires_at"
            );
        } else {
            request_status_expr = format!("{fulfilled_status_expr} AS request_status");
            request_requested_expr = format!("{fulfilled_requested_expr} AS request_requested_at");
            request_expires_expr = format!("{fulfilled_expires_expr} AS request_expires_at");
        }
    }
    let sql = format!(
        "SELECT
            rs.record_session_id,
            rs.title,
            rs.started_ts,
            rs.ended_ts,
            datetime(rs.started_ts / 1000, 'unixepoch', 'localtime') AS started_at,
            datetime(rs.ended_ts / 1000, 'unixepoch', 'localtime') AS ended_at,
            rs.stop_reason,
            rs.action_count,
            rs.session_id,
            {request_id_expr},
            {request_status_expr},
            {request_requested_expr},
            {request_expires_expr},
            rs.policy_snapshot_json,
            rs.pause_intervals_json,
            rs.safety_cap_ms,
            rs.visible_indicator
        FROM record_sessions rs
        ORDER BY rs.started_ts DESC, rs.record_session_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let started_ts: i64 = row.get(2)?;
        let ended_ts: Option<i64> = row.get(3)?;
        let pause_intervals_json: String = row.get(14)?;
        let stop_reason: Option<String> = row.get(6)?;
        out.push(RecordingRow {
            record_session_id: row.get(0)?,
            title: row.get(1)?,
            started_ts,
            ended_ts,
            started_at: row.get(4)?,
            ended_at: row.get(5)?,
            duration_ms: recording_duration_ms(started_ts, ended_ts, &pause_intervals_json, now_ms),
            recording_status: if ended_ts.is_none() {
                "Recording...".to_string()
            } else {
                "Ended".to_string()
            },
            stop_reason_label: record_stop_reason_label(stop_reason.as_deref()),
            stop_reason,
            action_count: row.get(7)?,
            session_id: row.get(8)?,
            request_id: row.get(9)?,
            request_status: row.get(10)?,
            request_requested_at: row.get(11)?,
            request_expires_at: row.get(12)?,
            policy_snapshot_json: row.get(13)?,
            pause_intervals_json,
            safety_cap_ms: row.get(15)?,
            visible_indicator: row.get(16)?,
        });
    }
    Ok(RecordingList {
        record_routine_tables_present: true,
        rows: out,
    })
}

fn recording_step_coverage(
    action_type: &str,
    selector_id: Option<i64>,
    pattern_action: Option<&str>,
    trust_basis: &str,
) -> String {
    if action_type == "edit_committed" {
        return "free input (value-free)".to_string();
    }
    if action_type == "ui_action_other" {
        return "unmapped".to_string();
    }
    if selector_id.is_some()
        && pattern_action.is_some_and(|value| {
            matches!(
                value,
                "invoke" | "toggle" | "select" | "expand_collapse" | "scroll"
            )
        })
        && matches!(
            trust_basis,
            "pid_match" | "window_ownership" | "scoped_invoke_sender"
        )
    {
        return "structurally observed".to_string();
    }
    "unmapped".to_string()
}

pub fn read_recording_steps(
    conn: &Connection,
    record_session_id: i64,
) -> rusqlite::Result<Vec<RecordingStep>> {
    if !table_exists(conn, "action_events")? {
        return Ok(Vec::new());
    }
    let action_columns = table_columns(conn, "action_events")?;
    let framework_class_expr = if action_columns.contains("framework_class") {
        "ae.framework_class AS framework_class"
    } else {
        "'unknown' AS framework_class"
    };
    let (selector_join, selector_id_expr, selector_expr) = if table_exists(conn, "selector_paths")?
    {
        (
            "LEFT JOIN selector_paths sp ON sp.selector_id = ae.selector_id",
            "sp.selector_id AS selector_id",
            "CASE
                WHEN sp.selector_id IS NULL THEN 'no selector'
                ELSE sp.framework || ':' || sp.depth || '-deep' ||
                     CASE WHEN sp.has_name != 0 THEN ' (named)' ELSE '' END
             END AS selector",
        )
    } else {
        ("", "NULL AS selector_id", "'no selector' AS selector")
    };
    let sql = format!(
        "SELECT
            ae.seq,
            datetime(ae.ts / 1000, 'unixepoch', 'localtime') AS captured_at,
            ae.action_type,
            ae.pattern_action,
            {selector_id_expr},
            {selector_expr},
            {framework_class_expr},
            ae.trust_basis,
            ae.exe,
            ae.is_sensitive
        FROM action_events ae
        {selector_join}
        WHERE ae.record_session_id = ?
        ORDER BY ae.seq"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([record_session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut action_type: String = row.get(2)?;
        let mut pattern_action: Option<String> = row.get(3)?;
        let selector_id: Option<i64> = row.get(4)?;
        let trust_basis: String = row.get(7)?;
        let is_excluded_gap = pattern_action.as_deref() == Some(EXCLUDED_APP_GAP_PATTERN);
        let coverage = recording_step_coverage(
            &action_type,
            selector_id,
            pattern_action.as_deref(),
            &trust_basis,
        );
        if is_excluded_gap {
            action_type = EXCLUDED_APP_GAP_LABEL.to_string();
            pattern_action = None;
        }
        out.push(RecordingStep {
            seq: row.get(0)?,
            captured_at: row.get(1)?,
            action_type,
            pattern_action,
            selector_id,
            selector: if is_excluded_gap {
                "not recorded".to_string()
            } else {
                row.get(5)?
            },
            framework_class: if is_excluded_gap {
                "not recorded".to_string()
            } else {
                row.get(6)?
            },
            trust_basis: if is_excluded_gap {
                "not recorded".to_string()
            } else {
                trust_basis
            },
            exe: if is_excluded_gap { None } else { row.get(8)? },
            is_sensitive: row.get(9)?,
            coverage: if is_excluded_gap {
                "excluded gap".to_string()
            } else {
                coverage
            },
        });
    }
    Ok(out)
}

pub fn read_recording_export_steps(
    conn: &Connection,
    record_session_id: i64,
    include_selector_paths: bool,
) -> rusqlite::Result<Vec<RecordingExportStep>> {
    if !table_exists(conn, "action_events")? {
        return Ok(Vec::new());
    }
    let action_columns = table_columns(conn, "action_events")?;
    let framework_class_expr = if action_columns.contains("framework_class") {
        "ae.framework_class AS framework_class"
    } else {
        "'unknown' AS framework_class"
    };
    let selector_paths_present = table_exists(conn, "selector_paths")?;
    let selector_id_expr = if selector_paths_present {
        "sp.selector_id AS selector_id"
    } else if include_selector_paths {
        "NULL AS selector_id"
    } else {
        "ae.selector_id AS selector_id"
    };
    let selector_join = if selector_paths_present {
        "LEFT JOIN selector_paths sp ON sp.selector_id = ae.selector_id"
    } else {
        ""
    };
    let selector_select = if include_selector_paths {
        if selector_paths_present {
            ", sp.path_hash, sp.framework AS selector_backend, sp.path_json, sp.leaf_rect"
        } else {
            ", NULL AS path_hash, NULL AS selector_backend, NULL AS path_json, NULL AS leaf_rect"
        }
    } else {
        ", NULL AS path_hash, NULL AS selector_backend, NULL AS path_json, NULL AS leaf_rect"
    };
    let sql = format!(
        "SELECT
            ae.seq,
            ae.ts,
            ae.action_type,
            ae.pattern_action,
            {selector_id_expr},
            {framework_class_expr},
            ae.trust_basis,
            ae.exe
            {selector_select}
        FROM action_events ae
        {selector_join}
        WHERE ae.record_session_id = ?
        ORDER BY ae.seq"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([record_session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(RecordingExportStep {
            seq: row.get(0)?,
            ts: row.get(1)?,
            action_type: row.get(2)?,
            pattern_action: row.get(3)?,
            selector_id: row.get(4)?,
            framework_class: row.get(5)?,
            trust_basis: row.get(6)?,
            exe: row.get(7)?,
            path_hash: row.get(8)?,
            selector_backend: row.get(9)?,
            path_json: row.get(10)?,
            leaf_rect: row.get(11)?,
        });
    }
    Ok(out)
}

fn clean_text(value: Option<&str>) -> String {
    value.unwrap_or("").trim().to_string()
}

pub fn step_replay_class(
    framework_class: Option<&str>,
    trust_basis: Option<&str>,
    action_type: Option<&str>,
    pattern_action: Option<&str>,
    selector_id: Option<i64>,
) -> String {
    let action = clean_text(action_type);
    if action == "edit_committed" {
        return REPLAY_CLASS_FREE_INPUT.to_string();
    }
    if action == "ui_action_other" {
        return REPLAY_CLASS_NOISE.to_string();
    }
    let pattern = clean_text(pattern_action);
    if !matches!(
        pattern.as_str(),
        "invoke" | "toggle" | "select" | "expand_collapse" | "scroll"
    ) {
        return REPLAY_CLASS_NOISE.to_string();
    }
    let framework = clean_text(framework_class);
    let trust = clean_text(trust_basis);
    if matches!(framework.as_str(), "web_renderer" | "virtualized") {
        return REPLAY_CLASS_HARD_VETO.to_string();
    }
    if selector_id.is_none() {
        return REPLAY_CLASS_NATIVE_GAP.to_string();
    }
    if framework == "native" && matches!(trust.as_str(), "pid_match" | "window_ownership") {
        return REPLAY_CLASS_ELIGIBLE.to_string();
    }
    if framework == "native_provisional"
        && matches!(trust.as_str(), "pid_match" | "window_ownership")
    {
        return REPLAY_CLASS_PROVISIONAL.to_string();
    }
    REPLAY_CLASS_NATIVE_GAP.to_string()
}

pub fn recording_replay_verdict(
    steps: &[RecordingExportStep],
    verified_classes: &HashSet<String>,
) -> ReplayExportVerdict {
    let mut native_eligible = 0;
    let mut provisional = 0;
    let mut native_gap = 0;
    let mut hard_veto = 0;
    let mut free_input = 0;
    let mut noise = 0;
    for row in steps {
        match step_replay_class(
            Some(&row.framework_class),
            Some(&row.trust_basis),
            Some(&row.action_type),
            row.pattern_action.as_deref(),
            row.selector_id,
        )
        .as_str()
        {
            REPLAY_CLASS_ELIGIBLE => native_eligible += 1,
            REPLAY_CLASS_PROVISIONAL => provisional += 1,
            REPLAY_CLASS_NATIVE_GAP => native_gap += 1,
            REPLAY_CLASS_HARD_VETO => hard_veto += 1,
            REPLAY_CLASS_FREE_INPUT => free_input += 1,
            _ => noise += 1,
        }
    }
    let actionable = native_eligible + provisional + native_gap + hard_veto;
    let replay_eligible = native_eligible + provisional;
    let native_fraction = (actionable > 0).then_some(replay_eligible as f64 / actionable as f64);
    let build = |state: &str,
                 label: &str,
                 detail: &str,
                 coverage_line: String,
                 severity: &str,
                 export_available: bool| {
        ReplayExportVerdict {
            state: state.to_string(),
            label: label.to_string(),
            detail: detail.to_string(),
            coverage_line,
            severity: severity.to_string(),
            actionable_steps: actionable,
            native_eligible_steps: native_eligible,
            provisional_steps: provisional,
            native_gap_steps: native_gap,
            hard_veto_steps: hard_veto,
            free_input_steps: free_input,
            noise_steps: noise,
            native_eligible_fraction: native_fraction,
            export_available,
        }
    };
    if actionable == 0 {
        return build(
            REPLAY_VERDICT_AGENT_ONLY,
            "Agent-grounded only",
            "No native-eligible control actions were observed, so replay cannot be demonstrated.",
            "Agent-grounded only -- no actionable steps classified.".to_string(),
            "info",
            false,
        );
    }
    let pct = ((native_fraction.unwrap_or(0.0) * 100.0).round_ties_even()) as i64;
    if hard_veto > 0 {
        return build(
            REPLAY_VERDICT_AGENT_ONLY,
            "Agent-grounded only",
            "Contains web or virtualized steps. Captured for an agent to follow, not for native replay.",
            format!(
                "Agent-grounded only -- {hard_veto} web/virtualized actionable steps among {actionable} actionable steps."
            ),
            "info",
            false,
        );
    }
    let threshold_met = actionable >= ACTIONABLE_MIN_FLOOR
        && native_fraction.unwrap_or(0.0) >= ACTIONABLE_NATIVE_THRESHOLD;
    if provisional > 0 {
        if threshold_met {
            return build(
                REPLAY_VERDICT_PROVISIONAL,
                "Replay-eligible (provisional)",
                "Native-provisional UI -- eligible in principle but not yet volume-validated. Native automation blueprint remains hidden.",
                format!(
                    "Replay-eligible (provisional) -- native/provisional-eligible for {pct}% of {actionable} actionable steps; {native_gap} unknown/untrusted/missing-selector gaps."
                ),
                "warning",
                false,
            );
        }
        return build(
            REPLAY_VERDICT_AGENT_ONLY,
            "Agent-grounded only",
            "Too many unknown, untrusted, or missing-selector gaps, or too few actionable native steps. Captured for an agent to follow.",
            format!(
                "Agent-grounded only -- native/provisional-eligible for {pct}% of {actionable} actionable steps; {native_gap} unknown/untrusted/missing-selector gaps."
            ),
            "info",
            false,
        );
    }
    if threshold_met {
        if verified_classes.contains("native") {
            return build(
                REPLAY_VERDICT_VERIFIED,
                "Verified replay-eligible",
                "Native UI elements, and an operator recorded that the restart-resolution test passed for this framework class.",
                format!(
                    "Verified replay-eligible -- native-eligible for {pct}% of {actionable} actionable steps; {native_gap} unknown/untrusted/missing-selector gaps."
                ),
                "success",
                true,
            );
        }
        return build(
            REPLAY_VERDICT_UNVERIFIED,
            "Replay-eligible (unverified) -- native replay not enabled",
            "Native UI elements meet the structural bar, but this install has no verified replay allowlist configured, so replay is not yet validated here. Use agent-grounded steps for now.",
            format!(
                "Replay-eligible (unverified) -- native-eligible for {pct}% of {actionable} actionable steps; {native_gap} unknown/untrusted/missing-selector gaps."
            ),
            "warning",
            false,
        );
    }
    build(
        REPLAY_VERDICT_AGENT_ONLY,
        "Agent-grounded only",
        "Too many unknown, untrusted, or missing-selector gaps, or too few actionable native steps. Captured for an agent to follow.",
        format!(
            "Agent-grounded only -- native-eligible for {pct}% of {actionable} actionable steps; {native_gap} unknown/untrusted/missing-selector gaps."
        ),
        "info",
        false,
    )
}

fn read_recording_export_metadata(
    conn: &Connection,
    record_session_id: i64,
) -> rusqlite::Result<Option<RecordingExportMetadata>> {
    if !table_exists(conn, "record_sessions")? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT rs.started_ts, rs.ended_ts, s.app_version, s.git_sha
         FROM record_sessions rs
         LEFT JOIN sessions s ON s.session_id = rs.session_id
         WHERE rs.record_session_id = ?
         LIMIT 1",
        [record_session_id],
        |row| {
            Ok(RecordingExportMetadata {
                started_ts: row.get(0)?,
                ended_ts: row.get(1)?,
                app_version: row.get(2)?,
                git_sha: row.get(3)?,
            })
        },
    )
    .optional()
}

fn export_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

pub fn build_replay_export(
    conn: &Connection,
    record_session_id: i64,
    mode: &str,
    verified_classes: &HashSet<String>,
    generated_ts_ms: i64,
    step_labels: &HashMap<i64, String>,
) -> Result<ReplayExport, Box<dyn Error>> {
    if !matches!(
        mode,
        REPLAY_EXPORT_MODE_AGENT_GROUNDED | REPLAY_EXPORT_MODE_NATIVE_SKELETON
    ) {
        return Err(export_error(format!(
            "unsupported replay export mode: {mode}"
        )));
    }
    let include_native_blueprint = mode == REPLAY_EXPORT_MODE_NATIVE_SKELETON;
    let cleaned_step_labels = clean_export_review_labels(step_labels);
    let Some(recording) = read_recording_export_metadata(conn, record_session_id)? else {
        return Err(export_error(format!(
            "recording not found: {record_session_id}"
        )));
    };
    if recording.ended_ts.is_none() {
        return Err(export_error("cannot export an open recording"));
    }
    let verdict_steps = read_recording_export_steps(conn, record_session_id, false)?;
    let verdict = recording_replay_verdict(&verdict_steps, verified_classes);
    if include_native_blueprint && !verdict.export_available {
        return Err(export_error(
            "native automation blueprint requires verified replay-readiness",
        ));
    }
    let steps = read_recording_export_steps(conn, record_session_id, true)?;
    let mut app_allowlist = steps
        .iter()
        .filter_map(|step| {
            let text = clean_text(step.exe.as_deref());
            (!text.is_empty()).then(|| display_app(Some(&text)))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    app_allowlist.sort();

    let mut step_items = Vec::new();
    let mut input_slots = Vec::new();
    let mut includes_review_labels = false;
    for row in &steps {
        let is_excluded_gap = row.pattern_action.as_deref() == Some(EXCLUDED_APP_GAP_PATTERN);
        let mut replay_class = step_replay_class(
            Some(&row.framework_class),
            Some(&row.trust_basis),
            Some(&row.action_type),
            row.pattern_action.as_deref(),
            row.selector_id,
        );
        let mut selector = None;
        let mut native_replayable = false;
        if is_excluded_gap {
            // The marker is deliberately value-free: never export the
            // internal placeholder selector used to persist its position.
        } else if include_native_blueprint && replay_class == REPLAY_CLASS_ELIGIBLE {
            selector = selector_export_block(row)?;
            native_replayable = selector.is_some();
            if selector.is_none() {
                replay_class = REPLAY_CLASS_NATIVE_GAP.to_string();
            }
        } else if mode == REPLAY_EXPORT_MODE_AGENT_GROUNDED {
            selector = selector_export_hint(row);
        }

        let mut input_slot_ref = None;
        if clean_text(Some(&row.action_type)) == "edit_committed" {
            let slot_id = format!("input_{}", input_slots.len() + 1);
            input_slot_ref = Some(slot_id.clone());
            let target_selector_ref = if clean_text(row.path_hash.as_deref()).is_empty() {
                None
            } else if selector_ref_is_export_safe(row) {
                Some(clean_text(row.path_hash.as_deref()))
            } else {
                None
            };
            input_slots.push(ReplayInputSlot {
                slot_id,
                at_step_seq: row.seq,
                role: "input".to_string(),
                kind: "string".to_string(),
                target_selector_ref,
            });
        }

        let review_label = cleaned_step_labels.get(&row.seq).cloned();
        if review_label.is_some() {
            includes_review_labels = true;
        }
        let framework_class = {
            let text = clean_text(Some(&row.framework_class));
            if text.is_empty() {
                "unknown".to_string()
            } else {
                text
            }
        };
        let trust_basis = {
            let text = clean_text(Some(&row.trust_basis));
            if text.is_empty() {
                "unknown".to_string()
            } else {
                text
            }
        };
        let exe = {
            let text = clean_text(row.exe.as_deref());
            if text.is_empty() {
                display_app(None)
            } else {
                display_app(Some(&text))
            }
        };
        step_items.push(ReplayExportStepItem {
            seq: row.seq,
            offset_ms_from_recording_start: (row.ts - recording.started_ts).max(0),
            action_type: clean_text(Some(&row.action_type)),
            pattern_action: row
                .pattern_action
                .as_deref()
                .map(|value| clean_text(Some(value)))
                .filter(|value| !value.is_empty()),
            intent: export_intent(row, selector.as_ref()),
            framework_class,
            trust_basis,
            exe,
            replay_class,
            native_replayable,
            selector,
            input_slot_ref,
            review_label,
        });
    }
    let source = ReplayExportSource {
        app_version: recording
            .app_version
            .as_deref()
            .map(|value| clean_text(Some(value)))
            .filter(|value| !value.is_empty()),
        git_sha: recording
            .git_sha
            .as_deref()
            .map(|value| clean_text(Some(value)))
            .filter(|value| !value.is_empty()),
    };
    let artifact = ReplayExport {
        metadata: ReplayExportMetadata {
            schema: RECORDING_EXPORT_SCHEMA.to_string(),
            schema_version: RECORDING_EXPORT_SCHEMA_VERSION.to_string(),
            value_free: true,
            generated_ts: export_generated_ts(generated_ts_ms),
            record_session_id,
            title: None,
            app_allowlist,
            mode: mode.to_string(),
            verdict: ReplayExportVerdictSummary {
                state: verdict.state.clone(),
                export_available: verdict.export_available,
                coverage_line: verdict.coverage_line.clone(),
            },
            source,
            review_labels: ReplayExportReviewLabels {
                included: includes_review_labels,
                source: "human_entered_at_export_time".to_string(),
                max_chars: REPLAY_EXPORT_REVIEW_LABEL_MAX_CHARS,
            },
        },
        steps: step_items,
        input_slots,
    };
    assert_replay_export_value_free(&artifact)?;
    Ok(artifact)
}

pub fn serialize_replay_export(artifact: &ReplayExport) -> Result<String, Box<dyn Error>> {
    assert_replay_export_value_free(artifact)?;
    Ok(format!("{}\n", serde_json::to_string_pretty(artifact)?))
}

/// Mirrors `replay_export_filename`: the download name for each export mode.
pub fn replay_export_filename(record_session_id: i64, mode: &str) -> String {
    if mode == REPLAY_EXPORT_MODE_NATIVE_SKELETON {
        return format!("gilbreth_native_blueprint_{record_session_id}.json");
    }
    format!("gilbreth_agent_handoff_{record_session_id}.json")
}

fn clean_export_review_labels(labels: &HashMap<i64, String>) -> HashMap<i64, String> {
    let mut cleaned = HashMap::new();
    for (&seq, label) in labels {
        let value = clean_export_review_label(label);
        if !value.is_empty() {
            cleaned.insert(seq, value);
        }
    }
    cleaned
}

fn clean_export_review_label(value: &str) -> String {
    let text = clean_text(Some(value));
    if text.is_empty() {
        return String::new();
    }
    let replaced = text
        .chars()
        .map(|ch| {
            if ch.is_control() || is_unicode_format_char(ch) {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    replaced
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(REPLAY_EXPORT_REVIEW_LABEL_MAX_CHARS)
        .collect()
}

fn is_unicode_format_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x08E2
            | 0x180E
            | 0xFEFF
            | 0x110BD
            | 0x110CD
            | 0xE0001
            | 0x0600..=0x0605
            | 0x0890..=0x0891
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFFF9..=0xFFFB
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0020..=0xE007F
    )
}

fn selector_export_hint(row: &RecordingExportStep) -> Option<ReplaySelectorExport> {
    selector_export_block(row).ok().flatten()
}

fn selector_export_block(
    row: &RecordingExportStep,
) -> Result<Option<ReplaySelectorExport>, Box<dyn Error>> {
    let path_json = clean_text(row.path_json.as_deref());
    let path_hash = clean_text(row.path_hash.as_deref());
    if path_json.is_empty() || path_hash.is_empty() {
        return Ok(None);
    }
    let parsed: serde_json::Value = serde_json::from_str(&path_json)
        .map_err(|_| export_error("selector path_json is not valid JSON"))?;
    assert_export_forbidden_keys_free(&parsed, "$.selector_path_json")?;
    let hops = expect_selector_hops(&parsed)?;
    let mut exported_hops = Vec::new();
    for hop in hops {
        let Some(exported) = selector_hop_export(hop)? else {
            return Ok(None);
        };
        exported_hops.push(exported);
    }
    let Some(backend) = selector_backend_export_value(row.selector_backend.as_deref()) else {
        return Ok(None);
    };
    Ok(Some(ReplaySelectorExport {
        backend,
        hops: exported_hops,
        path_hash,
        leaf_rect: parse_leaf_rect(row.leaf_rect.as_deref()),
    }))
}

fn expect_selector_hops(
    value: &serde_json::Value,
) -> Result<Vec<&serde_json::Map<String, serde_json::Value>>, Box<dyn Error>> {
    let Some(items) = value.as_array() else {
        return Err(export_error("selector path_json must be a list of hops"));
    };
    let mut hops = Vec::new();
    for item in items {
        let Some(hop) = item.as_object() else {
            return Err(export_error("selector hop must be an object"));
        };
        hops.push(hop);
    }
    Ok(hops)
}

fn selector_hop_export(
    hop: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<ReplaySelectorHopExport>, Box<dyn Error>> {
    if !selector_hop_identifiers_are_export_safe(hop) {
        return Ok(None);
    }
    let control_type = json_value_int_or_default(hop.get("control_type"), 0)?;
    Ok(Some(ReplaySelectorHopExport {
        control_type,
        control_type_label: control_type_label(control_type).to_string(),
        automation_id: clean_value_text(hop.get("automation_id")),
        class_name: clean_value_text(hop.get("class_name")),
        ordinal: json_value_int_or_default(hop.get("ordinal"), 0)?,
    }))
}

fn json_value_int_or_default(
    value: Option<&serde_json::Value>,
    default: i64,
) -> Result<i64, Box<dyn Error>> {
    match value {
        None => Ok(default),
        Some(serde_json::Value::Bool(value)) => Ok(i64::from(*value)),
        Some(serde_json::Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64))
            .ok_or_else(|| export_error("selector integer is not representable")),
        Some(serde_json::Value::String(value)) => value
            .parse::<i64>()
            .map_err(|_| export_error("selector integer is not valid")),
        _ => Err(export_error("selector integer is not valid")),
    }
}

fn selector_hop_identifiers_are_export_safe(
    hop: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    selector_identifier_is_export_safe_value(hop.get("automation_id"))
        && selector_identifier_is_export_safe_value(hop.get("class_name"))
}

fn selector_backend_export_value(value: Option<&str>) -> Option<String> {
    let backend = {
        let text = clean_text(value);
        if text.is_empty() {
            "unknown".to_string()
        } else {
            text.to_lowercase()
        }
    };
    REPLAY_EXPORT_SELECTOR_BACKENDS
        .contains(&backend.as_str())
        .then_some(backend)
}

fn selector_ref_is_export_safe(row: &RecordingExportStep) -> bool {
    if selector_backend_export_value(row.selector_backend.as_deref()).is_none() {
        return false;
    }
    let path_json = clean_text(row.path_json.as_deref());
    if path_json.is_empty() {
        return false;
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&path_json) else {
        return false;
    };
    let Ok(hops) = expect_selector_hops(&parsed) else {
        return false;
    };
    hops.iter()
        .all(|hop| selector_hop_identifiers_are_export_safe(hop))
}

fn selector_identifier_is_export_safe_value(value: Option<&serde_json::Value>) -> bool {
    selector_identifier_is_export_safe(&clean_value_text(value))
}

fn selector_identifier_is_export_safe(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return true;
    }
    if text.chars().count() > MAX_REPLAY_EXPORT_SELECTOR_IDENTIFIER_CHARS {
        return false;
    }
    if !text.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '_' | '.' | ':' | '#' | '{' | '}' | '$' | '+' | '-')
    }) {
        return false;
    }
    let mut run = 0;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            run += 1;
            if run >= 6 {
                return false;
            }
        } else {
            run = 0;
        }
    }
    true
}

fn parse_leaf_rect(value: Option<&str>) -> Option<ReplayLeafRect> {
    let text = clean_text(value);
    if text.is_empty() {
        return None;
    }
    let parts = text
        .split(',')
        .map(str::trim)
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parts.len() != 4 {
        return None;
    }
    Some(ReplayLeafRect {
        left: parts[0],
        top: parts[1],
        right: parts[2],
        bottom: parts[3],
    })
}

fn export_intent(row: &RecordingExportStep, selector: Option<&ReplaySelectorExport>) -> String {
    let action = clean_text(Some(&row.action_type));
    let pattern = clean_text(row.pattern_action.as_deref());
    let target = selector_target_phrase(selector);
    if pattern == EXCLUDED_APP_GAP_PATTERN {
        return EXCLUDED_APP_GAP_LABEL.to_string();
    }
    if action == "edit_committed" {
        return "Provide the runtime input for this step.".to_string();
    }
    match pattern.as_str() {
        "invoke" => format!("Invoke {target}."),
        "toggle" => format!("Toggle {target}."),
        "select" => format!("Select {target}."),
        "expand_collapse" => format!("Expand or collapse {target}."),
        "scroll" => format!("Scroll {target}."),
        "" => {
            if action == "ui_action_other" {
                "Review this observed UI step.".to_string()
            } else if action.is_empty() {
                "Follow this observed step.".to_string()
            } else {
                format!("Perform the {} step on {target}.", action.replace('_', " "))
            }
        }
        other => format!(
            "Perform the {} action on {target}.",
            other.replace('_', " ")
        ),
    }
}

fn selector_target_phrase(selector: Option<&ReplaySelectorExport>) -> String {
    let mut label = "target control";
    if let Some(selector) = selector {
        if let Some(last) = selector.hops.last() {
            if !last.control_type_label.trim().is_empty() {
                label = &last.control_type_label;
            }
        }
    }
    format!("the {label}")
}

fn control_type_label(value: i64) -> &'static str {
    match value {
        50000 => "button",
        50001 => "calendar",
        50002 => "check box",
        50003 => "combo box",
        50004 => "edit field",
        50005 => "link",
        50006 => "image",
        50007 => "list item",
        50008 => "list",
        50009 => "menu",
        50010 => "menu bar",
        50011 => "menu item",
        50012 => "progress bar",
        50013 => "radio button",
        50014 => "scroll bar",
        50015 => "slider",
        50016 => "spinner",
        50017 => "status bar",
        50018 => "tab",
        50019 => "tab item",
        50020 => "text element",
        50021 => "tool bar",
        50022 => "tool tip",
        50023 => "tree",
        50024 => "tree item",
        50025 => "custom control",
        50026 => "group",
        50027 => "thumb",
        50028 => "data grid",
        50029 => "data item",
        50030 => "document",
        50031 => "split button",
        50032 => "window",
        50033 => "pane",
        50034 => "header",
        50035 => "header item",
        50036 => "table",
        50037 => "title bar",
        50038 => "separator",
        50039 => "semantic zoom",
        50040 => "app bar",
        _ => "target control",
    }
}

fn export_generated_ts(generated_ts_ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    let dt = Utc
        .timestamp_millis_opt(generated_ts_ms)
        .single()
        .unwrap_or_else(|| Utc.timestamp_millis_opt(0).single().unwrap());
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn assert_export_forbidden_keys_free(
    value: &serde_json::Value,
    path: &str,
) -> Result<(), Box<dyn Error>> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_replay_export_forbidden_key(key) {
                    return Err(export_error(format!(
                        "export contains forbidden key {key:?} at {path}"
                    )));
                }
                assert_export_forbidden_keys_free(child, &format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                assert_export_forbidden_keys_free(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn assert_replay_export_value_free(artifact: &ReplayExport) -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_value(artifact)?;
    assert_export_value_free_value(&value, "$")
}

fn assert_export_value_free_value(
    value: &serde_json::Value,
    path: &str,
) -> Result<(), Box<dyn Error>> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_replay_export_forbidden_key(key) {
                    return Err(export_error(format!(
                        "export contains forbidden key {key:?} at {path}"
                    )));
                }
                if is_replay_export_selector_identifier_key(key)
                    && !selector_identifier_is_export_safe_value(Some(child))
                {
                    return Err(export_error(format!(
                        "export contains unsafe selector identifier {key:?} at {path}"
                    )));
                }
                assert_export_value_free_value(child, &format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                assert_export_value_free_value(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_replay_export_forbidden_key(key: &str) -> bool {
    matches!(
        sphere_casefold(key).as_str(),
        "name"
            | "value"
            | "text"
            | "document"
            | "description"
            | "help_text"
            | "localized_control_type"
            | "legacyiaccessible"
            | "legacyiaccessible_name"
            | "legacyiaccessible_value"
            | "legacyiaccessible_description"
            | "sphere"
            | "spheres"
    )
}

fn is_replay_export_selector_identifier_key(key: &str) -> bool {
    matches!(key.to_lowercase().as_str(), "automation_id" | "class_name")
}

fn clean_value_text(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(value)) => value.trim().to_string(),
        Some(serde_json::Value::Bool(value)) => {
            if *value {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(value) => value.to_string().trim().to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabaseCounts {
    pub sessions: i64,
    pub events: i64,
    pub active_sessions: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallStateSnapshot {
    pub db_path: String,
    pub db_size_bytes: i64,
    pub wal_size_bytes: i64,
    pub open_sessions: i64,
    pub build_sha: Option<String>,
    pub build_source: String,
    pub autostart_command: Option<String>,
    pub autostart_path: Option<String>,
    pub autostart_path_exists: bool,
    pub storage_warnings: Vec<String>,
    pub autostart_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessChurnReport {
    pub summaries: i64,
    pub dropped: i64,
    pub top: Vec<ProcessChurnTopRow>,
    pub sustained_exes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessChurnTopRow {
    pub exe: String,
    pub dropped: i64,
    pub sustained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugLogSnapshot {
    pub session_id: Option<i64>,
    pub recording_status: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub latest_event_at: Option<String>,
    pub latest_event_age_seconds: Option<i64>,
    pub event_count: i64,
    pub events_last_5m: i64,
    pub events_last_30m: i64,
    pub events_last_60m: i64,
    pub db_size_bytes: i64,
    pub wal_size_bytes: i64,
    pub longest_foreground_ms: Option<i64>,
    pub longest_foreground_app: Option<String>,
    pub longest_active_foreground_ms: Option<i64>,
    pub longest_active_foreground_app: Option<String>,
    pub power_sleeps: i64,
    pub power_boundary_catches: i64,
    pub capture_events_dropped: i64,
    pub stale_pre_erase_rows_dropped: i64,
    pub last_boundary_at: Option<String>,
    pub max_modifier_run: i64,
    pub max_modifier_name: Option<String>,
    pub sensitive_rows: i64,
    pub source_counts: Vec<DebugSourceCount>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugSourceCount {
    pub source: String,
    pub events: i64,
}

pub const DB_SIZE_WARNING_BYTES: i64 = 1_073_741_824;
/// The remedy the database-growth warning names. macOS has no archive lane
/// (owner decision 2026-07-19), so naming archive/reset there would point a
/// Mac user at a tray item that does not exist.
#[cfg(windows)]
const DB_SIZE_WARNING_REMEDY: &str = "consider archive/reset or a manual retention prune";
#[cfg(not(windows))]
const DB_SIZE_WARNING_REMEDY: &str = "consider a manual retention prune";
pub const WAL_SIZE_WARNING_BYTES: i64 = 67_108_864;
const PROCESS_CHURN_TOP_LIMIT: usize = 5;
const DEBUG_KEY_SCAN_LIMIT: i64 = 10_000;
const DEBUG_STALE_EVENT_SECONDS: i64 = 5 * 60;
const DEBUG_LONG_FOREGROUND_MS: i64 = 60 * 60 * 1000;
const DEBUG_STUCK_MODIFIER_RUN: i64 = 25;

/// The DB-side health checks `scripts/review_run.py` runs, so the native
/// Diagnostics tab and the script explain a REVIEW with the same layered
/// categories (DASH-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabaseHealth {
    /// First row of `PRAGMA integrity_check` ("ok" when clean).
    pub integrity_check: String,
    /// Row count from `PRAGMA foreign_key_check`.
    pub foreign_key_issues: i64,
    pub user_version: i64,
    /// Sessions whose event and action-event rows don't form a dense,
    /// duplicate-free shared seq span.
    pub seq_gap_sessions: Vec<i64>,
    /// `meta['capture_events_dropped']`: a missing key is a pre-counter DB
    /// and reads as 0 (healthy); an unparseable value reads as -1 so the
    /// verdict fails REVIEW instead of silently passing (review_run's
    /// `_meta_int` rule).
    pub capture_events_dropped: i64,
    /// `meta['stale_pre_erase_rows_dropped']`: motion rows captured before a
    /// secure-erase completion boundary and discarded when they arrived late.
    pub stale_pre_erase_rows_dropped: i64,
    /// Focus rows synthesized by open-focus crash repair (payload flag
    /// `recovered`): reconstructed dwell, reported explicitly but healthy —
    /// repair working as designed after an ungraceful end (review_run's
    /// recovered-focus category).
    pub recovered_focus_rows: i64,
    /// Event time span, which also scopes the log review window.
    pub min_ts: Option<i64>,
    pub max_ts: Option<i64>,
}

impl DatabaseHealth {
    /// review_run's `DatabaseReview.healthy`.
    pub fn healthy(&self) -> bool {
        self.integrity_check == "ok"
            && self.foreign_key_issues == 0
            && self.seq_gap_sessions.is_empty()
            && self.capture_events_dropped == 0
            && self.stale_pre_erase_rows_dropped == 0
    }
}

fn health_meta_int(conn: &Connection, key: &str) -> rusqlite::Result<i64> {
    if !table_exists(conn, "meta")? {
        return Ok(0);
    }
    let value: Option<rusqlite::types::Value> = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(match value {
        None => 0,
        // Match review_run.py's int coercion and -1 REVIEW sentinel.
        Some(rusqlite::types::Value::Integer(value)) => value,
        Some(rusqlite::types::Value::Real(value)) => value as i64,
        Some(rusqlite::types::Value::Text(raw)) => raw.trim().parse::<i64>().unwrap_or(-1),
        Some(_) => -1,
    })
}

pub fn database_health(conn: &Connection) -> rusqlite::Result<DatabaseHealth> {
    let integrity_check: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_key_issues = {
        let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
        let mut rows = stmt.query([])?;
        let mut count = 0i64;
        while rows.next()?.is_some() {
            count += 1;
        }
        count
    };
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let mut seq_gap_sessions = Vec::new();
    {
        let seq_gap_sql = if table_exists(conn, "action_events")? {
            "WITH sequenced_rows AS (
                 SELECT session_id, seq
                 FROM events
                 UNION ALL
                 SELECT session_id, seq
                 FROM action_events
             )
             SELECT session_id
             FROM sequenced_rows
             GROUP BY session_id
             HAVING COUNT(*) != MAX(seq) - MIN(seq) + 1
                 OR COUNT(*) != COUNT(DISTINCT seq)
             ORDER BY session_id"
        } else {
            "SELECT session_id
             FROM events
             GROUP BY session_id
             HAVING COUNT(*) != MAX(seq) - MIN(seq) + 1
                 OR COUNT(*) != COUNT(DISTINCT seq)
             ORDER BY session_id"
        };
        let mut stmt = conn.prepare(seq_gap_sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            seq_gap_sessions.push(row.get(0)?);
        }
    }
    let capture_events_dropped = health_meta_int(conn, "capture_events_dropped")?;
    let stale_pre_erase_rows_dropped = health_meta_int(conn, "stale_pre_erase_rows_dropped")?;
    let recovered_focus_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events
         WHERE kind = 'focus_changed'
           AND json_extract(payload, '$.recovered') = 1",
        [],
        |row| row.get(0),
    )?;
    let (min_ts, max_ts): (Option<i64>, Option<i64>) =
        conn.query_row("SELECT MIN(ts), MAX(ts) FROM events", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    Ok(DatabaseHealth {
        integrity_check,
        foreign_key_issues,
        user_version,
        seq_gap_sessions,
        capture_events_dropped,
        stale_pre_erase_rows_dropped,
        recovered_focus_rows,
        min_ts,
        max_ts,
    })
}

/// One row of the Session tab's selector, exactly as `read_sessions`
/// reports it. Identity columns landed in migration 002, so a pre-identity
/// database reads them as NULL, like the Python `_optional_session_column`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRow {
    pub session_id: i64,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub host: Option<String>,
    pub app_version: Option<String>,
    pub git_sha: Option<String>,
    pub run_label: Option<String>,
    pub event_count: i64,
}

fn optional_session_column(columns: &HashSet<String>, column: &str) -> String {
    if columns.contains(column) {
        format!("s.{column} AS {column}")
    } else {
        format!("NULL AS {column}")
    }
}

/// Mirrors `read_sessions`: every session with its identity columns and
/// event count, newest first — so the first row is the open/latest session
/// the Session tab selects by default.
pub fn read_sessions(conn: &Connection) -> rusqlite::Result<Vec<SessionRow>> {
    let columns = table_columns(conn, "sessions")?;
    let host_expr = optional_session_column(&columns, "host");
    let app_version_expr = optional_session_column(&columns, "app_version");
    let git_sha_expr = optional_session_column(&columns, "git_sha");
    let run_label_expr = optional_session_column(&columns, "run_label");
    let sql = format!(
        "SELECT
            s.session_id,
            datetime(s.started_at / 1000, 'unixepoch', 'localtime') AS started_at,
            datetime(s.ended_at / 1000, 'unixepoch', 'localtime') AS ended_at,
            {host_expr},
            {app_version_expr},
            {git_sha_expr},
            {run_label_expr},
            COUNT(e.id) AS event_count
        FROM sessions s
        LEFT JOIN events e ON e.session_id = s.session_id
        GROUP BY
            s.session_id,
            s.started_at,
            s.ended_at,
            host,
            app_version,
            git_sha,
            run_label
        ORDER BY s.started_at DESC, s.session_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(SessionRow {
            session_id: row.get(0)?,
            started_at: row.get(1)?,
            ended_at: row.get(2)?,
            host: row.get(3)?,
            app_version: row.get(4)?,
            git_sha: row.get(5)?,
            run_label: row.get(6)?,
            event_count: row.get(7)?,
        });
    }
    Ok(out)
}

/// One Session Event-list row, exactly as `read_activity_events` reports it
/// (a `focus_changed` row's `prev_*` columns surface as the completed app).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivityEventRow {
    pub id: i64,
    pub session_id: i64,
    pub seq: i64,
    pub changed_at: Option<String>,
    pub source: String,
    pub kind: String,
    pub completed_exe: Option<String>,
    pub completed_title: Option<String>,
    pub duration_ms: Option<i64>,
    pub exe: Option<String>,
    pub title: Option<String>,
    pub hwnd: Option<String>,
    pub key: Option<String>,
    pub mod_shift: Option<i64>,
    pub mod_ctrl: Option<i64>,
    pub mod_alt: Option<i64>,
    pub mod_win: Option<i64>,
    pub button: Option<String>,
    pub pos_x: Option<i64>,
    pub pos_y: Option<i64>,
    pub is_sensitive: i64,
    pub payload: Option<String>,
}

/// Mirrors `read_activity_events`: the newest 500 events of one session,
/// every stored column, for the Event list and its per-event delete.
pub fn read_activity_events(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<ActivityEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT
            id,
            session_id,
            seq,
            datetime(ts / 1000, 'unixepoch', 'localtime') AS changed_at,
            source,
            kind,
            prev_exe AS completed_exe,
            prev_title AS completed_title,
            duration_ms,
            exe,
            title,
            hwnd,
            key,
            mod_shift,
            mod_ctrl,
            mod_alt,
            mod_win,
            button,
            pos_x,
            pos_y,
            is_sensitive,
            payload
        FROM events
        WHERE session_id = ?
        ORDER BY ts DESC
        LIMIT 500",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(ActivityEventRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            seq: row.get(2)?,
            changed_at: row.get(3)?,
            source: row.get(4)?,
            kind: row.get(5)?,
            completed_exe: row.get(6)?,
            completed_title: row.get(7)?,
            duration_ms: row.get(8)?,
            exe: row.get(9)?,
            title: row.get(10)?,
            hwnd: row.get(11)?,
            key: row.get(12)?,
            mod_shift: row.get(13)?,
            mod_ctrl: row.get(14)?,
            mod_alt: row.get(15)?,
            mod_win: row.get(16)?,
            button: row.get(17)?,
            pos_x: row.get(18)?,
            pos_y: row.get(19)?,
            is_sensitive: row.get(20)?,
            payload: row.get(21)?,
        });
    }
    Ok(out)
}

/// One Session "Event Counts" row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventCountRow {
    pub source: String,
    pub kind: String,
    pub events: i64,
}

/// Mirrors `read_event_counts`: per-(source, kind) totals for one session.
pub fn read_event_counts(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<EventCountRow>> {
    let mut stmt = conn.prepare(
        "SELECT source, kind, COUNT(*) AS events
         FROM events
         WHERE session_id = ?
         GROUP BY source, kind
         ORDER BY events DESC, source, kind",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(EventCountRow {
            source: row.get(0)?,
            kind: row.get(1)?,
            events: row.get(2)?,
        });
    }
    Ok(out)
}

/// One Session "Time per app" row. `completed_title` is present only for the
/// `include_titles` read, mirroring the Python frame's column set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FocusSummaryRow {
    pub completed_exe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_title: Option<String>,
    pub focus_seconds: f64,
    pub active_foreground_seconds: f64,
    pub switches: i64,
}

/// Mirrors `read_focus_summary`: per-(exe[, title]) dwell totals over the
/// active-focus substrate of one session, aggregated in pandas' sorted
/// group order, stably sorted by (focus time, switches) descending, top 25.
/// Unlike `focus_rollup` this groups by the raw stored exe, not the display
/// app — the view maps `display_app` per row like the Streamlit frame.
pub fn read_focus_summary(
    conn: &Connection,
    session_id: i64,
    include_titles: bool,
) -> rusqlite::Result<Vec<FocusSummaryRow>> {
    #[derive(Default)]
    struct Accum {
        switches: i64,
        focus_ms: i64,
        active_ms: i64,
    }
    let scope = Scope {
        cutoff_ms: None,
        session_id: Some(session_id),
    };
    let mut groups: BTreeMap<(String, String), Accum> = BTreeMap::new();
    for row in focus_intervals_with_active(conn, &scope)? {
        let title = if include_titles {
            row.title.clone()
        } else {
            String::new()
        };
        let entry = groups.entry((row.exe.clone(), title)).or_default();
        entry.switches += 1;
        entry.focus_ms += row.duration_ms;
        entry.active_ms += row.active_foreground_ms;
    }
    let mut summary: Vec<((String, String), Accum)> = groups.into_iter().collect();
    summary.sort_by(|left, right| {
        (right.1.focus_ms, right.1.switches).cmp(&(left.1.focus_ms, left.1.switches))
    });
    summary.truncate(TOP_N_ANALYTICS);
    Ok(summary
        .into_iter()
        .map(|((exe, title), accum)| FocusSummaryRow {
            completed_exe: exe,
            completed_title: include_titles.then_some(title),
            focus_seconds: pandas_round_2dp(accum.focus_ms as f64 / 1000.0),
            active_foreground_seconds: pandas_round_2dp(accum.active_ms as f64 / 1000.0),
            switches: accum.switches,
        })
        .collect())
}

/// Headline Session values from the app-level focus summary — mirrors
/// `session_story_totals` over the `include_titles=false` shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionStoryTotals {
    pub top_app: Option<String>,
    pub top_app_active_seconds: f64,
    pub focus_switches: i64,
}

pub fn session_story_totals(app_focus_summary: &[FocusSummaryRow]) -> SessionStoryTotals {
    // pandas idxmax: the FIRST row holding the maximum wins ties, so only a
    // strictly greater value replaces the running top.
    let mut top: Option<&FocusSummaryRow> = None;
    for row in app_focus_summary {
        let replace = top.is_none_or(|current| {
            row.active_foreground_seconds > current.active_foreground_seconds
        });
        if replace {
            top = Some(row);
        }
    }
    let Some(top) = top else {
        return SessionStoryTotals {
            top_app: None,
            top_app_active_seconds: 0.0,
            focus_switches: 0,
        };
    };
    SessionStoryTotals {
        top_app: Some(display_app(Some(&top.completed_exe))),
        top_app_active_seconds: top.active_foreground_seconds,
        focus_switches: app_focus_summary.iter().map(|row| row.switches).sum(),
    }
}

/// Mirrors `read_session_focus_seconds_total`: summed completed dwells of
/// one session, in seconds (no cutoff clipping — the session is the scope).
pub fn read_session_focus_seconds_total(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<f64> {
    conn.query_row(
        "SELECT COALESCE(SUM(COALESCE(duration_ms, 0)), 0) / 1000.0
         FROM events
         WHERE session_id = ?
           AND kind = 'focus_changed'
           AND prev_exe IS NOT NULL
           AND duration_ms IS NOT NULL",
        [session_id],
        |row| row.get(0),
    )
}

/// Mirrors `read_session_active_focus_seconds_total` (seconds; the existing
/// `active_focus_minutes_total` differs only in unit, but the division is
/// kept Python-shaped here so floats match bit-for-bit).
pub fn read_session_active_focus_seconds_total(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<f64> {
    let scope = Scope {
        cutoff_ms: None,
        session_id: Some(session_id),
    };
    let total: i64 = focus_intervals_with_active(conn, &scope)?
        .iter()
        .map(|row| row.active_foreground_ms)
        .sum();
    Ok(total as f64 / 1000.0)
}

/// One Session Context row (non-process system events).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemEventRow {
    pub captured_at: Option<String>,
    pub kind: String,
    pub title: Option<String>,
    pub pos_x: Option<i64>,
    pub pos_y: Option<i64>,
    pub duration_ms: Option<i64>,
    pub payload: Option<String>,
}

/// Mirrors `read_system_events`: the newest 50 system events of one session,
/// with process starts/exits excluded (those live in the churn report).
pub fn read_system_events(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<SystemEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT
            datetime(ts / 1000, 'unixepoch', 'localtime') AS captured_at,
            kind,
            title,
            pos_x,
            pos_y,
            duration_ms,
            payload
        FROM events
        WHERE session_id = ?
          AND source = 'system'
          AND kind NOT IN ('process_started', 'process_exited')
        ORDER BY ts DESC
        LIMIT 50",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(SystemEventRow {
            captured_at: row.get(0)?,
            kind: row.get(1)?,
            title: row.get(2)?,
            pos_x: row.get(3)?,
            pos_y: row.get(4)?,
            duration_ms: row.get(5)?,
            payload: row.get(6)?,
        });
    }
    Ok(out)
}

/// One Power Timeline row, including the pandas-diff gap columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PowerEventRow {
    pub captured_at: Option<String>,
    pub kind: String,
    pub matched_suspend: Option<i64>,
    pub tick_ms: Option<i64>,
    pub wall_gap_ms: Option<i64>,
    pub tick_gap_ms: Option<i64>,
    pub gap_ms: Option<i64>,
    pub capped_dwell_ms: Option<i64>,
}

/// Mirrors `read_power_events`: suspend/resume/boundary events of one
/// session in capture order, with `wall_gap_ms` / `tick_gap_ms` computed as
/// row-over-row diffs exactly like the pandas `.diff()` (a missing operand
/// on either side of a diff yields no value).
pub fn read_power_events(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<PowerEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT
            ts,
            datetime(ts / 1000, 'unixepoch', 'localtime') AS captured_at,
            kind,
            json_extract(payload, '$.matched_suspend') AS matched_suspend,
            json_extract(payload, '$.tick_ms') AS tick_ms,
            json_extract(payload, '$.gap_ms') AS gap_ms,
            json_extract(payload, '$.capped_dwell_ms') AS capped_dwell_ms
        FROM events
        WHERE session_id = ?
          AND source = 'system'
          AND kind IN (
              'power_suspend',
              'power_resume',
              'power_boundary_recovered'
          )
        ORDER BY ts ASC, id ASC",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut out: Vec<PowerEventRow> = Vec::new();
    let mut prev_ts: Option<i64> = None;
    let mut prev_tick: Option<i64> = None;
    while let Some(row) = rows.next()? {
        let ts: i64 = row.get(0)?;
        let tick_ms: Option<i64> = row.get(4)?;
        out.push(PowerEventRow {
            captured_at: row.get(1)?,
            kind: row.get(2)?,
            matched_suspend: row.get(3)?,
            tick_ms,
            wall_gap_ms: prev_ts.map(|prev| ts - prev),
            tick_gap_ms: prev_tick.zip(tick_ms).map(|(prev, tick)| tick - prev),
            gap_ms: row.get(5)?,
            capped_dwell_ms: row.get(6)?,
        });
        prev_ts = Some(ts);
        prev_tick = tick_ms;
    }
    Ok(out)
}

pub fn read_database_counts(conn: &Connection) -> rusqlite::Result<DatabaseCounts> {
    Ok(DatabaseCounts {
        sessions: conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?,
        events: conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?,
        active_sessions: conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
            [],
            |row| row.get(0),
        )?,
    })
}

pub fn read_install_state(
    conn: &Connection,
    db_path: &Path,
    autostart_command: Option<String>,
    db_size_warning_bytes: i64,
    wal_size_warning_bytes: i64,
) -> rusqlite::Result<InstallStateSnapshot> {
    let command = autostart_command;
    let autostart_path = command_path(command.as_deref());
    let autostart_path_exists = autostart_path
        .as_deref()
        .map(|path| Path::new(path).exists())
        .unwrap_or(false);
    let open_sessions = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let (build_sha, build_source) = current_build_sha(conn)?;
    let db_size_bytes = path_size(db_path);
    let wal_size_bytes = path_size(&wal_path(db_path));
    Ok(InstallStateSnapshot {
        db_path: db_path.to_string_lossy().to_string(),
        db_size_bytes,
        wal_size_bytes,
        open_sessions,
        build_sha,
        build_source,
        autostart_command: command,
        autostart_path,
        autostart_path_exists,
        storage_warnings: install_state_storage_warnings(
            db_size_bytes,
            wal_size_bytes,
            db_size_warning_bytes,
            wal_size_warning_bytes,
        ),
        autostart_error: None,
    })
}

fn install_state_storage_warnings(
    db_size_bytes: i64,
    wal_size_bytes: i64,
    db_size_warning_bytes: i64,
    wal_size_warning_bytes: i64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if db_size_warning_bytes > 0 && db_size_bytes >= db_size_warning_bytes {
        warnings.push(format!(
            "Live database is {}; {DB_SIZE_WARNING_REMEDY} before a long unattended run.",
            format_bytes(db_size_bytes)
        ));
    }
    if wal_size_warning_bytes > 0 && wal_size_bytes >= wal_size_warning_bytes {
        warnings.push(format!(
            "WAL sidecar is {}; close dashboard readers so heartbeat checkpoints can truncate it. If it stays high after readers close, restart Gilbreth.",
            format_bytes(wal_size_bytes)
        ));
    }
    warnings
}

fn current_build_sha(conn: &Connection) -> rusqlite::Result<(Option<String>, String)> {
    if !table_columns(conn, "sessions")?.contains("git_sha") {
        return Ok((None, "unavailable".to_string()));
    }
    let row = conn
        .query_row(
            "SELECT git_sha,
                    CASE WHEN ended_at IS NULL THEN 'open session' ELSE 'latest session' END
             FROM sessions
             WHERE git_sha IS NOT NULL
               AND TRIM(git_sha) <> ''
             ORDER BY
                   CASE WHEN ended_at IS NULL THEN 0 ELSE 1 END,
                   started_at DESC,
                   session_id DESC
             LIMIT 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    Ok(row
        .map(|(sha, source)| (Some(sha), source))
        .unwrap_or((None, "unavailable".to_string())))
}

fn command_path(command: Option<&str>) -> Option<String> {
    let command = command?.trim();
    if command.is_empty() {
        return None;
    }
    if let Some(stripped) = command.strip_prefix('"') {
        let end_quote = stripped.find('"')? + 1;
        if end_quote > 1 {
            return Some(command[1..end_quote].to_string());
        }
        return None;
    }
    command
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn wal_path(path: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}-wal", path.to_string_lossy()))
}

fn path_size(path: &Path) -> i64 {
    std::fs::metadata(path)
        .map(|metadata| metadata.len() as i64)
        .unwrap_or(0)
}

/// Mirrors app.py's `format_bytes` (whole bytes, then one-decimal KB/MB/GB).
pub fn format_bytes(size: i64) -> String {
    let units = ["B", "KB", "MB", "GB"];
    let mut value = size as f64;
    for (index, unit) in units.iter().enumerate() {
        if value < 1024.0 || index == units.len() - 1 {
            if *unit == "B" {
                return format!("{} {unit}", value as i64);
            }
            return format!("{value:.1} {unit}");
        }
        value /= 1024.0;
    }
    format!("{size} B")
}

pub fn read_process_churn(
    conn: &Connection,
    days: i64,
    now_ms: i64,
) -> rusqlite::Result<ProcessChurnReport> {
    let cutoff = now_ms - days * DAY_MS;
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind = 'process_churn_summary' AND ts >= ?")?;
    let mut rows = stmt.query([cutoff])?;
    let mut summaries = 0;
    let mut dropped = 0;
    let mut by_exe: HashMap<String, (i64, bool)> = HashMap::new();
    while let Some(row) = rows.next()? {
        summaries += 1;
        let payload_text: Option<String> = row.get(0)?;
        let Some(payload_text) = payload_text else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_text) else {
            continue;
        };
        let Some(payload_map) = payload.as_object() else {
            continue;
        };
        dropped += json_value_int_like(payload_map.get("dropped")).unwrap_or(0);
        let Some(entries) = payload_map.get("top").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for entry in entries {
            let Some(entry_map) = entry.as_object() else {
                continue;
            };
            let exe = python_json_str(entry_map.get("exe")).trim().to_string();
            if exe.is_empty() {
                continue;
            }
            let entry_dropped = json_value_int_like(entry_map.get("dropped")).unwrap_or(0);
            let sustained = json_truthy(entry_map.get("sustained"));
            let slot = by_exe.entry(exe).or_insert((0, false));
            slot.0 += entry_dropped;
            slot.1 |= sustained;
        }
    }
    let mut top = by_exe
        .iter()
        .map(|(exe, (dropped, sustained))| ProcessChurnTopRow {
            exe: exe.clone(),
            dropped: *dropped,
            sustained: *sustained,
        })
        .collect::<Vec<_>>();
    top.sort_by(|a, b| b.dropped.cmp(&a.dropped).then_with(|| a.exe.cmp(&b.exe)));
    top.truncate(PROCESS_CHURN_TOP_LIMIT);
    let mut sustained_exes = by_exe
        .into_iter()
        .filter_map(|(exe, (_, sustained))| sustained.then_some(exe))
        .collect::<Vec<_>>();
    sustained_exes.sort();
    Ok(ProcessChurnReport {
        summaries,
        dropped,
        top,
        sustained_exes,
    })
}

fn python_json_str(value: Option<&serde_json::Value>) -> String {
    match value {
        None => String::new(),
        Some(serde_json::Value::Null) => "None".to_string(),
        Some(serde_json::Value::Bool(true)) => "True".to_string(),
        Some(serde_json::Value::Bool(false)) => "False".to_string(),
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(value) => value.to_string(),
    }
}

fn json_truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::Number(number)) => number.as_f64().unwrap_or(0.0) != 0.0,
        Some(serde_json::Value::String(value)) => !value.is_empty(),
        Some(serde_json::Value::Array(value)) => !value.is_empty(),
        Some(serde_json::Value::Object(value)) => !value.is_empty(),
    }
}

fn read_meta_int(conn: &Connection, key: &str) -> i64 {
    let Ok(value) = conn
        .query_row("SELECT value FROM meta WHERE key = ?", [key], |row| {
            row.get::<_, String>(0)
        })
        .optional()
    else {
        return 0;
    };
    value
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
}

pub fn read_debug_log(
    conn: &Connection,
    db_path: &Path,
    now_ms: i64,
) -> rusqlite::Result<DebugLogSnapshot> {
    let open_sessions = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let session = conn
        .query_row(
            "SELECT
                session_id,
                started_at,
                ended_at,
                datetime(started_at / 1000, 'unixepoch', 'localtime') AS started_at_text,
                datetime(ended_at / 1000, 'unixepoch', 'localtime') AS ended_at_text
            FROM sessions s
            ORDER BY (ended_at IS NULL) DESC, started_at DESC, session_id DESC
            LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((session_id, ended_at_raw, started_at, ended_at)) = session else {
        return Ok(DebugLogSnapshot {
            session_id: None,
            recording_status: "No sessions".to_string(),
            started_at: None,
            ended_at: None,
            latest_event_at: None,
            latest_event_age_seconds: None,
            event_count: 0,
            events_last_5m: 0,
            events_last_30m: 0,
            events_last_60m: 0,
            db_size_bytes: path_size(db_path),
            wal_size_bytes: path_size(&wal_path(db_path)),
            longest_foreground_ms: None,
            longest_foreground_app: None,
            longest_active_foreground_ms: None,
            longest_active_foreground_app: None,
            power_sleeps: 0,
            power_boundary_catches: 0,
            capture_events_dropped: read_meta_int(conn, "capture_events_dropped"),
            stale_pre_erase_rows_dropped: read_meta_int(conn, "stale_pre_erase_rows_dropped"),
            last_boundary_at: None,
            max_modifier_run: 0,
            max_modifier_name: None,
            sensitive_rows: 0,
            source_counts: Vec::new(),
            warnings: vec!["No Gilbreth sessions found yet.".to_string()],
        });
    };
    let recording = ended_at_raw.is_none();
    let (event_count, latest_ts, latest_event_at): (i64, Option<i64>, Option<String>) = conn
        .query_row(
            "SELECT
                COUNT(*) AS event_count,
                MAX(ts) AS latest_ts,
                datetime(MAX(ts) / 1000, 'unixepoch', 'localtime') AS latest_event_at
             FROM events
             WHERE session_id = ?",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let latest_event_age_seconds = latest_ts.map(|ts| ((now_ms - ts) / 1000).max(0));
    let (events_last_5m, events_last_30m, events_last_60m): (i64, i64, i64) = conn.query_row(
        "SELECT
                SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS events_last_5m,
                SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS events_last_30m,
                SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS events_last_60m
             FROM events
             WHERE session_id = ?",
        [
            now_ms - 5 * 60 * 1000,
            now_ms - 30 * 60 * 1000,
            now_ms - 60 * 60 * 1000,
            session_id,
        ],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        },
    )?;
    let raw_longest = conn
        .query_row(
            "SELECT duration_ms, COALESCE(NULLIF(prev_exe, ''), '(unknown)') AS app
             FROM events
             WHERE session_id = ?
               AND kind = 'focus_changed'
               AND prev_exe IS NOT NULL
               AND duration_ms IS NOT NULL
             ORDER BY duration_ms DESC, id DESC
             LIMIT 1",
            [session_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let active_focus = focus_intervals_with_active(
        conn,
        &Scope {
            cutoff_ms: None,
            session_id: Some(session_id),
        },
    )?;
    let mut longest_active_foreground_ms = None;
    let mut longest_active_foreground_app = None;
    for row in &active_focus {
        if longest_active_foreground_ms.is_none_or(|current| row.active_foreground_ms > current) {
            longest_active_foreground_ms = Some(row.active_foreground_ms);
            longest_active_foreground_app = Some(display_app(Some(&row.exe)));
        }
    }
    let (power_boundary_catches, last_boundary_at): (i64, Option<String>) = conn.query_row(
        "SELECT
            COUNT(*) AS recovered_count,
            datetime(MAX(ts) / 1000, 'unixepoch', 'localtime') AS last_boundary_at
         FROM events
         WHERE session_id = ?
           AND kind = 'power_boundary_recovered'",
        [session_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let power_sleeps = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE session_id = ? AND kind = 'power_suspend'",
        [session_id],
        |row| row.get(0),
    )?;
    let source_counts = read_debug_source_counts(conn, session_id)?;
    let (max_modifier_name, max_modifier_run) = max_modifier_run(conn, session_id)?;
    let sensitive_rows = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE session_id = ? AND is_sensitive != 0",
        [session_id],
        |row| row.get(0),
    )?;
    let capture_events_dropped = read_meta_int(conn, "capture_events_dropped");
    let stale_pre_erase_rows_dropped = read_meta_int(conn, "stale_pre_erase_rows_dropped");
    let warnings = debug_log_warnings(DebugWarningInputs {
        recording,
        latest_event_age_seconds,
        longest_active_foreground_ms,
        power_boundary_catches,
        max_modifier_run,
        max_modifier_name: max_modifier_name.as_deref(),
        open_sessions,
        event_count,
    });
    Ok(DebugLogSnapshot {
        session_id: Some(session_id),
        recording_status: if recording {
            "Recording".to_string()
        } else {
            "No open session".to_string()
        },
        started_at,
        ended_at,
        latest_event_at,
        latest_event_age_seconds,
        event_count,
        events_last_5m,
        events_last_30m,
        events_last_60m,
        db_size_bytes: path_size(db_path),
        wal_size_bytes: path_size(&wal_path(db_path)),
        longest_foreground_ms: raw_longest.as_ref().map(|row| row.0),
        longest_foreground_app: raw_longest.as_ref().map(|row| display_app(Some(&row.1))),
        longest_active_foreground_ms,
        longest_active_foreground_app,
        power_sleeps,
        power_boundary_catches,
        capture_events_dropped,
        stale_pre_erase_rows_dropped,
        last_boundary_at,
        max_modifier_run,
        max_modifier_name,
        sensitive_rows,
        source_counts,
        warnings,
    })
}

fn read_debug_source_counts(
    conn: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<DebugSourceCount>> {
    let mut stmt = conn.prepare(
        "SELECT source, COUNT(*) AS events
         FROM events
         WHERE session_id = ?
         GROUP BY source
         ORDER BY events DESC, source",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(DebugSourceCount {
            source: row.get(0)?,
            events: row.get(1)?,
        });
    }
    Ok(out)
}

fn max_modifier_run(conn: &Connection, session_id: i64) -> rusqlite::Result<(Option<String>, i64)> {
    let mut stmt = conn.prepare(
        "SELECT mod_shift, mod_ctrl, mod_alt, mod_win
         FROM (
             SELECT id, ts, mod_shift, mod_ctrl, mod_alt, mod_win
             FROM events
             WHERE session_id = ?
               AND kind = 'key'
             ORDER BY ts DESC, id DESC
             LIMIT ?
         )
         ORDER BY ts ASC, id ASC",
    )?;
    let mut rows = stmt.query([session_id, DEBUG_KEY_SCAN_LIMIT])?;
    let mut current = [0_i64; 4];
    let mut maximum = [0_i64; 4];
    while let Some(row) = rows.next()? {
        for index in 0..4 {
            let active = row.get::<_, Option<i64>>(index)?.unwrap_or(0) != 0;
            if active {
                current[index] += 1;
                maximum[index] = maximum[index].max(current[index]);
            } else {
                current[index] = 0;
            }
        }
    }
    let names = ["Shift", "Ctrl", "Alt", "Win"];
    let mut best_index = 0;
    for index in 1..4 {
        if maximum[index] > maximum[best_index] {
            best_index = index;
        }
    }
    if maximum[best_index] == 0 {
        Ok((None, 0))
    } else {
        Ok((Some(names[best_index].to_string()), maximum[best_index]))
    }
}

struct DebugWarningInputs<'a> {
    recording: bool,
    latest_event_age_seconds: Option<i64>,
    longest_active_foreground_ms: Option<i64>,
    power_boundary_catches: i64,
    max_modifier_run: i64,
    max_modifier_name: Option<&'a str>,
    open_sessions: i64,
    event_count: i64,
}

fn debug_log_warnings(inputs: DebugWarningInputs<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    if inputs.event_count == 0 {
        warnings.push("Selected session has no recorded events.".to_string());
    }
    if inputs.recording && inputs.latest_event_age_seconds.is_none() {
        warnings.push("Recording session is open but has no latest event yet.".to_string());
    }
    if inputs.recording
        && inputs
            .latest_event_age_seconds
            .is_some_and(|age| age > DEBUG_STALE_EVENT_SECONDS)
    {
        let age = inputs.latest_event_age_seconds.unwrap_or(0);
        warnings.push(format!(
            "Recording session is open, but the latest event is {} minutes old.",
            age / 60
        ));
    }
    if inputs
        .longest_active_foreground_ms
        .is_some_and(|ms| ms > DEBUG_LONG_FOREGROUND_MS)
    {
        let minutes = (inputs.longest_active_foreground_ms.unwrap_or(0) as f64 / 60_000.0)
            .round_ties_even() as i64;
        warnings.push(format!(
            "Longest active foreground dwell is {minutes} minutes."
        ));
    }
    if inputs.power_boundary_catches > 0 {
        warnings.push(format!(
            "Power-boundary backstop recovered {} missed boundaries.",
            inputs.power_boundary_catches
        ));
    }
    if inputs.max_modifier_run >= DEBUG_STUCK_MODIFIER_RUN {
        if let Some(name) = inputs.max_modifier_name {
            warnings.push(format!(
                "Possible stuck {name} modifier: {} consecutive key events carried it.",
                inputs.max_modifier_run
            ));
        }
    }
    if inputs.open_sessions > 1 {
        warnings.push(format!(
            "{} sessions are open at once.",
            inputs.open_sessions
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lane B final enforcement audit (docs/MAINTAINING.md, Product-copy rules):
    /// production literals in const/static declarations, arrays, inline
    /// expressions, and reconstructed `concat!`/`format!` copy obey the
    /// shared law, with the whole `src/` tree walked at test time so a new
    /// file joins the scan. Comments, char/byte literals, regex grammar,
    /// and inline test-module fixtures are intentionally not product copy.
    /// Produced-output tests cover copy whose words come from runtime data.
    #[test]
    fn production_copy_source_passes_the_copy_style_law() {
        use gilbreth_core::copy_style;

        let violations = copy_style::audit_crate_src("gilbreth-read", env!("CARGO_MANIFEST_DIR"));
        copy_style::assert_no_violations(&violations);
    }

    fn health_fixture_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE sessions (session_id INTEGER PRIMARY KEY, started_at INTEGER, ended_at INTEGER);
             CREATE TABLE events (id INTEGER PRIMARY KEY, session_id INTEGER, seq INTEGER, ts INTEGER, kind TEXT, payload TEXT NOT NULL DEFAULT '{}');
             CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO events (session_id, seq, ts, kind) VALUES
                 (1, 1, 1000, 'focus_changed'),
                 (1, 2, 2000, 'focus_changed'),
                 (1, 3, 3000, 'focus_changed');",
        )
        .expect("fixture schema");
        conn
    }

    #[test]
    fn database_health_mirrors_review_run_semantics() {
        let conn = health_fixture_db();
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.integrity_check, "ok");
        assert_eq!(health.foreign_key_issues, 0);
        assert!(health.seq_gap_sessions.is_empty());
        assert_eq!(health.capture_events_dropped, 0, "missing key reads 0");
        assert_eq!(
            health.stale_pre_erase_rows_dropped, 0,
            "missing named category reads 0"
        );
        assert_eq!((health.min_ts, health.max_ts), (Some(1000), Some(3000)));
        assert!(health.healthy());

        // A seq gap flags the session and fails the verdict.
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind) VALUES (2, 5, 4000, 'focus_changed'), (2, 9, 5000, 'focus_changed')",
            [],
        )
        .expect("gap rows");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.seq_gap_sessions, vec![2]);
        assert!(!health.healthy());
    }

    #[test]
    fn database_health_counts_record_routine_actions_in_sequence_continuity() {
        let conn = health_fixture_db();
        conn.execute_batch(
            "CREATE TABLE action_events (
                 id INTEGER PRIMARY KEY,
                 session_id INTEGER NOT NULL,
                 seq INTEGER NOT NULL
             );
             INSERT INTO events (session_id, seq, ts, kind) VALUES
                 (2, 10, 4000, 'focus_changed'),
                 (2, 14, 8000, 'focus_changed');
             INSERT INTO action_events (session_id, seq) VALUES
                 (2, 11),
                 (2, 12),
                 (2, 13);",
        )
        .expect("record routine sequence rows");

        let health = database_health(&conn).expect("health reads");
        assert!(health.seq_gap_sessions.is_empty());
        assert!(health.healthy());

        conn.execute(
            "DELETE FROM action_events WHERE session_id = 2 AND seq = 12",
            [],
        )
        .expect("remove one sequence row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.seq_gap_sessions, vec![2]);
        assert!(!health.healthy());

        // This cross-table duplicate compensates for the missing seq in
        // COUNT(*) but does not make the shared sequence continuous.
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind) VALUES
                 (2, 11, 5000, 'focus_changed')",
            [],
        )
        .expect("compensating duplicate sequence row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.seq_gap_sessions, vec![2]);
        assert!(!health.healthy());
    }

    #[test]
    fn database_health_checks_action_only_surviving_sessions() {
        let conn = health_fixture_db();
        conn.execute_batch(
            "CREATE TABLE action_events (
                 id INTEGER PRIMARY KEY,
                 session_id INTEGER NOT NULL,
                 seq INTEGER NOT NULL
             );
             INSERT INTO action_events (session_id, seq) VALUES
                 (2, 7),
                 (2, 8),
                 (2, 9);",
        )
        .expect("action-only sequence rows");

        let health = database_health(&conn).expect("health reads");
        assert!(health.seq_gap_sessions.is_empty());
        assert!(health.healthy());

        conn.execute(
            "DELETE FROM action_events WHERE session_id = 2 AND seq = 8",
            [],
        )
        .expect("remove one action-only sequence row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.seq_gap_sessions, vec![2]);
        assert!(!health.healthy());
    }

    #[test]
    fn database_health_counts_recovered_focus_rows_without_failing_the_verdict() {
        let conn = health_fixture_db();
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.recovered_focus_rows, 0);

        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind, payload) VALUES
                 (1, 4, 4000, 'focus_changed', '{\"recovered\":true}')",
            [],
        )
        .expect("recovered row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.recovered_focus_rows, 1);
        assert!(
            health.healthy(),
            "a repaired dwell is reported, not a failure"
        );
    }

    #[test]
    fn database_health_drop_counter_uses_the_unparseable_sentinel() {
        let conn = health_fixture_db();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_events_dropped', '7')",
            [],
        )
        .expect("counter row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.capture_events_dropped, 7);
        assert!(!health.healthy(), "non-zero drops fail the verdict");

        conn.execute(
            "UPDATE meta SET value = 'not-a-number' WHERE key = 'capture_events_dropped'",
            [],
        )
        .expect("corrupt counter");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(
            health.capture_events_dropped, -1,
            "unparseable counter is the REVIEW sentinel, not a silent pass"
        );
        assert!(!health.healthy());
    }

    #[test]
    fn database_health_reads_named_stale_pre_erase_drop_category() {
        let conn = health_fixture_db();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('stale_pre_erase_rows_dropped', '4')",
            [],
        )
        .expect("counter row");
        let health = database_health(&conn).expect("health reads");
        assert_eq!(health.stale_pre_erase_rows_dropped, 4);
        assert!(!health.healthy(), "non-zero stale drops fail the verdict");
    }

    #[test]
    fn replay_export_filename_pins_both_mode_names() {
        assert_eq!(
            replay_export_filename(7, REPLAY_EXPORT_MODE_AGENT_GROUNDED),
            "gilbreth_agent_handoff_7.json"
        );
        assert_eq!(
            replay_export_filename(7, REPLAY_EXPORT_MODE_NATIVE_SKELETON),
            "gilbreth_native_blueprint_7.json"
        );
    }

    fn replay_export_fixture_db(
        app_version: &str,
        git_sha: Option<&str>,
        ended_ts: Option<i64>,
    ) -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory replay export db");
        conn.execute_batch(
            r#"
            CREATE TABLE sessions (
                session_id INTEGER PRIMARY KEY,
                app_version TEXT,
                git_sha TEXT
            );
            CREATE TABLE record_sessions (
                record_session_id INTEGER PRIMARY KEY,
                session_id INTEGER NOT NULL,
                started_ts INTEGER NOT NULL,
                ended_ts INTEGER,
                title TEXT
            );
            CREATE TABLE selector_paths (
                selector_id INTEGER PRIMARY KEY,
                path_hash TEXT,
                framework TEXT,
                depth INTEGER NOT NULL DEFAULT 0,
                has_name INTEGER NOT NULL DEFAULT 0,
                path_json TEXT,
                leaf_rect TEXT
            );
            CREATE TABLE action_events (
                id INTEGER PRIMARY KEY,
                record_session_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                pattern_action TEXT,
                selector_id INTEGER,
                framework_class TEXT NOT NULL,
                trust_basis TEXT NOT NULL,
                exe TEXT,
                is_sensitive INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )
        .expect("replay export fixture schema");
        conn.execute(
            "INSERT INTO sessions (session_id, app_version, git_sha) VALUES (1, ?, ?)",
            rusqlite::params![app_version, git_sha],
        )
        .expect("replay export session");
        conn.execute(
            "INSERT INTO record_sessions (
                record_session_id, session_id, started_ts, ended_ts, title
             ) VALUES (20, 1, 2000, ?, 'User supplied words must stay local')",
            [ended_ts],
        )
        .expect("replay export recording");
        conn
    }

    fn insert_replay_selector(
        conn: &Connection,
        selector_id: i64,
        suffix: &str,
        path_hash: &str,
        leaf_rect: &str,
    ) {
        let path_json = serde_json::json!([
            {
                "control_type": 50032,
                "automation_id": "root",
                "class_name": "Notepad",
                "ordinal": 0
            },
            {
                "control_type": 50000,
                "automation_id": format!("safe_{suffix}"),
                "class_name": "Button",
                "ordinal": 1
            }
        ])
        .to_string();
        conn.execute(
            "INSERT INTO selector_paths (
                selector_id, path_hash, framework, path_json, leaf_rect
             ) VALUES (?, ?, 'uia', ?, ?)",
            rusqlite::params![selector_id, path_hash, path_json, leaf_rect],
        )
        .expect("replay selector");
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_replay_action(
        conn: &Connection,
        id: i64,
        seq: i64,
        ts: i64,
        selector_id: Option<i64>,
        action_type: &str,
        pattern_action: Option<&str>,
        framework_class: &str,
        trust_basis: &str,
    ) {
        conn.execute(
            "INSERT INTO action_events (
                id, record_session_id, seq, ts, action_type, pattern_action,
                selector_id, framework_class, trust_basis, exe
             ) VALUES (?, 20, ?, ?, ?, ?, ?, ?, ?, 'C:/Apps/msedge.exe')",
            rusqlite::params![
                id,
                seq,
                ts,
                action_type,
                pattern_action,
                selector_id,
                framework_class,
                trust_basis
            ],
        )
        .expect("replay action");
    }

    #[test]
    fn agent_replay_export_builder_and_serialization_match_contract_fixture() {
        let conn = replay_export_fixture_db("0.1.0", Some("abc123"), Some(5_000));
        insert_replay_selector(&conn, 30, "web", "web-safe", "10,20,30,40");
        insert_replay_action(
            &conn,
            40,
            1,
            2_500,
            Some(30),
            "invoke",
            Some("invoke"),
            "web_renderer",
            "pid_match",
        );
        insert_replay_action(
            &conn,
            41,
            2,
            3_000,
            None,
            "edit_committed",
            None,
            "web_renderer",
            "pid_match",
        );

        let artifact = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_AGENT_GROUNDED,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect("agent replay export");
        assert_eq!(artifact.metadata.schema, RECORDING_EXPORT_SCHEMA);
        assert_eq!(artifact.metadata.mode, REPLAY_EXPORT_MODE_AGENT_GROUNDED);
        assert_eq!(artifact.metadata.title, None);
        assert_eq!(artifact.metadata.app_allowlist, ["msedge.exe"]);
        assert_eq!(artifact.metadata.verdict.state, REPLAY_VERDICT_AGENT_ONLY);
        assert_eq!(artifact.steps[0].replay_class, REPLAY_CLASS_HARD_VETO);
        assert!(artifact.steps[0].selector.is_some());
        assert_eq!(artifact.steps[1].replay_class, REPLAY_CLASS_FREE_INPUT);
        assert_eq!(artifact.input_slots[0].at_step_seq, 2);

        let serialized = serialize_replay_export(&artifact).expect("agent export serializes");
        assert!(!serialized.contains("User supplied words"));
        let expected = include_str!("../../../scripts/tests/fixtures/agent_handoff_export.json")
            .replace("\r\n", "\n");
        assert_eq!(serialized, expected);
    }

    #[test]
    fn excluded_routine_gap_is_labeled_in_steps_and_export_without_app_metadata() {
        let conn = replay_export_fixture_db("test", None, Some(5_000));
        insert_replay_selector(&conn, 30, "must-not-export", "gap-hash", "1,2,3,4");
        conn.execute(
            "INSERT INTO action_events (
                id, record_session_id, seq, ts, action_type, pattern_action,
                selector_id, framework_class, trust_basis, exe
             ) VALUES (40, 20, 1, 2500, 'ui_action_other', ?, 30, 'unknown',
                       'scoped_invoke_sender', NULL)",
            [EXCLUDED_APP_GAP_PATTERN],
        )
        .expect("gap action");

        let steps = read_recording_steps(&conn, 20).expect("steps");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action_type, EXCLUDED_APP_GAP_LABEL);
        assert_eq!(steps[0].exe, None);
        assert_eq!(steps[0].selector, "not recorded");

        let artifact = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_AGENT_GROUNDED,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect("agent export");
        assert!(artifact.metadata.app_allowlist.is_empty());
        assert_eq!(artifact.steps[0].intent, EXCLUDED_APP_GAP_LABEL);
        assert_eq!(artifact.steps[0].selector, None);
        let serialized = serialize_replay_export(&artifact).expect("serialized export");
        assert!(serialized.contains(EXCLUDED_APP_GAP_LABEL));
        assert!(!serialized.contains("must-not-export"));
        assert!(!serialized.contains("gap-hash"));
    }

    #[test]
    fn native_replay_export_requires_verification_and_matches_contract_fixture() {
        let conn = replay_export_fixture_db("test", None, Some(18_000));
        for index in 1..=10 {
            insert_replay_selector(
                &conn,
                100 + index,
                &index.to_string(),
                &format!("native-{index}"),
                &format!("{index},{},{},{}", index + 1, index + 2, index + 3),
            );
        }
        for index in 1..=9 {
            insert_replay_action(
                &conn,
                200 + index,
                index,
                2_000 + index * 100,
                Some(100 + index),
                "invoke",
                Some("invoke"),
                "native",
                "pid_match",
            );
        }
        insert_replay_action(
            &conn,
            220,
            10,
            3_200,
            Some(110),
            "invoke",
            Some("invoke"),
            "native",
            "scoped_invoke_sender",
        );
        insert_replay_action(
            &conn,
            221,
            11,
            3_400,
            Some(101),
            "edit_committed",
            None,
            "native",
            "pid_match",
        );

        let error = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_NATIVE_SKELETON,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect_err("unverified native export must fail");
        assert!(error.to_string().contains("verified replay-readiness"));

        let verified_classes = HashSet::from(["native".to_string()]);
        let artifact = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_NATIVE_SKELETON,
            &verified_classes,
            10_000,
            &HashMap::new(),
        )
        .expect("verified native replay export");
        assert_eq!(artifact.metadata.verdict.state, REPLAY_VERDICT_VERIFIED);
        assert!(artifact.metadata.verdict.export_available);
        assert!(artifact.steps[0].native_replayable);
        assert_eq!(artifact.steps[9].replay_class, REPLAY_CLASS_NATIVE_GAP);
        assert_eq!(artifact.steps[9].selector, None);
        assert_eq!(artifact.steps[10].replay_class, REPLAY_CLASS_FREE_INPUT);
        assert_eq!(
            artifact.input_slots[0].target_selector_ref.as_deref(),
            Some("native-1")
        );

        let serialized = serialize_replay_export(&artifact).expect("native export serializes");
        let expected = include_str!("../../../scripts/tests/fixtures/native_blueprint_export.json")
            .replace("\r\n", "\n");
        assert_eq!(serialized, expected);
    }

    #[test]
    fn replay_export_builder_and_serializer_fail_closed_on_invalid_inputs() {
        let conn = replay_export_fixture_db("test", None, Some(5_000));
        let error = build_replay_export(
            &conn,
            20,
            "unsupported",
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect_err("unsupported mode must fail");
        assert!(error.to_string().contains("unsupported replay export mode"));

        let error = build_replay_export(
            &conn,
            404,
            REPLAY_EXPORT_MODE_AGENT_GROUNDED,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect_err("missing recording must fail");
        assert!(error.to_string().contains("recording not found: 404"));

        conn.execute(
            "UPDATE record_sessions SET ended_ts = NULL WHERE record_session_id = 20",
            [],
        )
        .expect("recording made open");
        let error = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_AGENT_GROUNDED,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect_err("open recording must fail");
        assert!(error
            .to_string()
            .contains("cannot export an open recording"));

        conn.execute(
            "UPDATE record_sessions SET ended_ts = 5000 WHERE record_session_id = 20",
            [],
        )
        .expect("recording closed");
        insert_replay_selector(&conn, 30, "safe", "safe-ref", "1,2,3,4");
        insert_replay_action(
            &conn,
            40,
            1,
            2_500,
            Some(30),
            "invoke",
            Some("invoke"),
            "web_renderer",
            "pid_match",
        );
        let mut artifact = build_replay_export(
            &conn,
            20,
            REPLAY_EXPORT_MODE_AGENT_GROUNDED,
            &HashSet::new(),
            10_000,
            &HashMap::new(),
        )
        .expect("valid artifact");
        artifact.steps[0]
            .selector
            .as_mut()
            .expect("selector hint")
            .hops[1]
            .automation_id = "Customer Email jane.doe@example.com".to_string();
        let error = serialize_replay_export(&artifact)
            .expect_err("unsafe selector identifier must fail serialization");
        assert!(error
            .to_string()
            .contains("unsafe selector identifier \"automation_id\""));
    }

    #[test]
    fn subtract_spans_matches_python_semantics() {
        assert_eq!(
            subtract_spans(0, 100, &[(10, 20), (30, 40)]),
            vec![(0, 10), (20, 30), (40, 100)]
        );
        assert_eq!(
            subtract_spans(15, 35, &[(10, 20), (30, 40)]),
            vec![(20, 30)]
        );
        assert_eq!(
            subtract_spans(10, 20, &[(0, 100)]),
            Vec::<(i64, i64)>::new()
        );
        assert_eq!(subtract_spans(10, 20, &[]), vec![(10, 20)]);
    }

    #[test]
    fn subtract_intervals_splits_and_preserves_order() {
        assert_eq!(
            subtract_intervals(vec![(0, 100)], &[(40, 60)]),
            vec![(0, 40), (60, 100)]
        );
        assert_eq!(
            subtract_intervals(vec![(0, 50), (60, 90)], &[(45, 70)]),
            vec![(0, 45), (70, 90)]
        );
        assert_eq!(
            subtract_intervals(vec![(10, 20)], &[(0, 30)]),
            Vec::<(i64, i64)>::new()
        );
    }

    #[test]
    fn notice_duration_text_uses_bankers_rounding() {
        assert_eq!(notice_duration_text(0), "0s");
        assert_eq!(notice_duration_text(-1_500), "0s");
        assert_eq!(notice_duration_text(1_500), "2s"); // 1.5 rounds to even 2
        assert_eq!(notice_duration_text(2_500), "2s"); // 2.5 rounds to even 2
        assert_eq!(notice_duration_text(59_499), "59s");
        assert_eq!(notice_duration_text(59_500), "1m"); // 59.5 -> 60
        assert_eq!(notice_duration_text(61_000), "1m 1s");
        assert_eq!(notice_duration_text(3_600_000), "60m");
        assert_eq!(notice_duration_text(3_661_000), "61m 1s");
    }

    #[test]
    fn payload_int_matches_python_tolerances() {
        assert_eq!(
            payload_int(Some(r#"{"gap_ms": 30000}"#), "gap_ms"),
            Some(30_000)
        );
        assert_eq!(
            payload_int(Some(r#"{"gap_ms": 30000.0}"#), "gap_ms"),
            Some(30_000)
        );
        assert_eq!(payload_int(Some(r#"{"gap_ms": 1.5}"#), "gap_ms"), None);
        assert_eq!(payload_int(Some(r#"{"gap_ms": true}"#), "gap_ms"), None);
        assert_eq!(payload_int(Some(r#"{"other": 1}"#), "gap_ms"), None);
        assert_eq!(payload_int(Some("not json"), "gap_ms"), None);
        assert_eq!(payload_int(Some(""), "gap_ms"), None);
        assert_eq!(payload_int(None, "gap_ms"), None);
    }

    #[test]
    fn round_2dp_matches_python_bankers_rounding() {
        // Python oracle (verified live): round(0.125, 2) == 0.12,
        // round(0.375, 2) == 0.38, round(0.625, 2) == 0.62,
        // round(90500 / 60000, 2) == 1.51, round(5.125, 2) == 5.12.
        assert_eq!(round_2dp(0.125), 0.12);
        assert_eq!(round_2dp(0.375), 0.38);
        assert_eq!(round_2dp(0.625), 0.62);
        assert_eq!(round_2dp(90_500.0 / 60_000.0), 1.51);
        assert_eq!(round_2dp(5.125), 5.12);
        assert_eq!(round_2dp(0.0), 0.0);
    }

    #[test]
    fn pandas_round_2dp_matches_numpy_on_boundary_vectors() {
        // NumPy oracle (verified live against the repo venv, both
        // directions on the real ms grids). The review's B1 vector first:
        // np.round(216535 / 1000, 2) == 216.54 where built-in round gives
        // 216.53.
        assert_eq!(pandas_round_2dp(216_535.0 / 1000.0), 216.54);
        assert_eq!(round_2dp(216_535.0 / 1000.0), 216.53);
        // NumPy above built-in: /1000 and /60000 grids.
        assert_eq!(pandas_round_2dp(15.0 / 1000.0), 0.02);
        assert_eq!(pandas_round_2dp(175.0 / 1000.0), 0.18);
        assert_eq!(pandas_round_2dp(900.0 / 60_000.0), 0.02);
        assert_eq!(pandas_round_2dp(10_500.0 / 60_000.0), 0.18);
        // NumPy below built-in: the same grids in the other direction.
        assert_eq!(pandas_round_2dp(25.0 / 1000.0), 0.02);
        assert_eq!(pandas_round_2dp(225.0 / 1000.0), 0.22);
        assert_eq!(pandas_round_2dp(1_500.0 / 60_000.0), 0.02);
        assert_eq!(pandas_round_2dp(13_500.0 / 60_000.0), 0.22);
        // Modifier-rate ratios (input rollup denominators).
        assert_eq!(pandas_round_2dp(3.0 / 40.0), 0.08);
        assert_eq!(pandas_round_2dp(9.0 / 40.0), 0.22);
        // Agreement away from boundaries, and at zero.
        assert_eq!(pandas_round_2dp(90_500.0 / 60_000.0), 1.51);
        assert_eq!(pandas_round_2dp(0.0), 0.0);
    }

    fn segment(order: i64, app: &str, start_ts: i64, end_ts: i64, active_ms: i64) -> AppSegment {
        AppSegment {
            order,
            app: app.to_string(),
            session_id: 1,
            seq: order + 100,
            local_date: "2026-07-08".to_string(),
            start_ts,
            end_ts,
            active_ms,
        }
    }

    #[test]
    fn away_spans_clip_coalesce_and_drop_empty_sessions() {
        let idle = vec![
            SessionInterval {
                session_id: 1,
                start_ts: 0,
                end_ts: 50,
            },
            SessionInterval {
                session_id: 1,
                start_ts: 45,
                end_ts: 70,
            },
            SessionInterval {
                session_id: 2,
                start_ts: 500,
                end_ts: 600,
            }, // clips away
        ];
        let sleep = vec![SessionInterval {
            session_id: 1,
            start_ts: 70,
            end_ts: 90,
        }];
        let spans = away_spans_by_session(&idle, &sleep, 10, 100);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans.get(&1).unwrap(), &vec![(10, 90)]);
    }

    #[test]
    fn same_app_focus_runs_merges_and_breaks() {
        let segments = vec![
            segment(0, "a.exe", 0, 100, 100),
            segment(1, "a.exe", 150, 300, 150), // merges: consecutive, small gap
            segment(2, "(unknown)", 300, 320, 20), // breaks the run
            segment(3, "a.exe", 320, 400, 80),
            segment(
                4,
                "a.exe",
                400 + EPISODE_GAP_MS + 1,
                400 + EPISODE_GAP_MS + 50,
                49,
            ),
        ];
        let runs = same_app_focus_runs(&segments);
        assert_eq!(runs.len(), 3);
        assert_eq!(
            (
                runs[0].start_ts,
                runs[0].end_ts,
                runs[0].active_ms,
                runs[0].last_order
            ),
            (0, 300, 250, 1)
        );
        assert_eq!((runs[1].first_order, runs[1].last_order), (3, 3));
        // The gap beyond EPISODE_GAP_MS starts a new run despite same app.
        assert_eq!(runs[2].first_order, 4);
    }

    #[test]
    fn display_app_matches_python_semantics() {
        assert_eq!(display_app(None), "(unknown)");
        assert_eq!(display_app(Some("")), "(unknown)");
        assert_eq!(display_app(Some("  ")), "(unknown)");
        assert_eq!(display_app(Some("(unknown)")), "(unknown)");
        assert_eq!(display_app(Some(r"C:\Apps\Tool.exe")), "Tool.exe");
        assert_eq!(display_app(Some("tool.exe")), "tool.exe");
        assert_eq!(display_app(Some("a/b/")), "b");
        assert_eq!(display_app(Some("  padded.exe  ")), "padded.exe");
        // All-separator inputs fall back to the stripped original value.
        assert_eq!(display_app(Some("///")), "///");
        assert_eq!(display_app(Some(r"C:\")), "C:");
    }

    /// MAC-0 read-side audit: the `exe` column's macOS form is the bundle
    /// executable path (schema/README.md vocabulary record). It must
    /// basename through the shared display helper with no `.exe`-shaped or
    /// backslash-shaped assumptions — and either platform's dashboard must
    /// render the other platform's DB (one cross-platform schema).
    #[test]
    fn display_app_handles_macos_bundle_paths() {
        assert_eq!(
            display_app(Some("/Applications/Safari.app/Contents/MacOS/Safari")),
            "Safari"
        );
        assert_eq!(
            display_app(Some(
                "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
            )),
            "Electron"
        );
        // Helper binaries nested under an outer bundle keep their own name.
        assert_eq!(
            display_app(Some(
                "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container"
            )),
            "plugin-container"
        );
        assert_eq!(display_app(Some(r"C:\Apps\Tool.exe")), "Tool.exe");
    }

    /// The notification diverter key must reduce the same product on either
    /// platform to the same token: `.exe` stripping is a no-op on mac
    /// basenames, never a requirement.
    #[test]
    fn notification_app_match_key_is_extension_agnostic_across_platforms() {
        assert_eq!(
            notification_app_match_key(r"C:\Program Files\Slack\slack.exe"),
            "slack"
        );
        assert_eq!(
            notification_app_match_key("/Applications/Slack.app/Contents/MacOS/Slack"),
            "slack"
        );
    }

    /// r4-SF-1: pin the exact discovery cutoff the Privacy advisor copy
    /// names. The real-reader fixtures alone only prove "more than nine
    /// days"; narrowing or widening `DISCOVERY_BASELINE_DAYS` must fail
    /// here (its frozen-oracle twin lives in test_db.py).
    #[test]
    fn discovery_baseline_scope_is_exactly_fourteen_days_before_local_midnight() {
        for now_ms in [1_752_000_000_000_i64, 1_783_645_200_000] {
            let scope = discovery_baseline_scope(now_ms);
            assert_eq!(
                scope.cutoff_ms,
                Some(local_day_start_ms(now_ms) - 14 * DAY_MS)
            );
            assert_eq!(scope.session_id, None);
            // The same instant's today scope starts at that local midnight.
            assert_eq!(
                today_scope(now_ms).cutoff_ms,
                Some(local_day_start_ms(now_ms))
            );
        }
    }

    #[test]
    fn sphere_label_uses_sidecar_casefold_keys() {
        let aliases = HashMap::from([("strasse".to_string(), "Comms".to_string())]);

        assert_eq!(
            sphere_label(Some("Straße - Google Chrome"), &aliases),
            Some("Comms".to_string())
        );
    }

    #[test]
    fn sphere_token_matches_python_suffix_regexes() {
        // These prefixes exercise lowercase expansions and byte-length changes;
        // suffix removal must always use offsets from the original string.
        assert_eq!(sphere_token(Some("ẞ and 2 more pages")), None);
        assert_eq!(sphere_token(Some("K and 2 more pages")), None);
        assert_eq!(sphere_token(Some("İ and 2 more pages")), None);

        assert_eq!(
            sphere_token(Some("Title\tAND\u{2003}12 more\nPAGES")),
            Some("Title".to_string())
        );
        assert_eq!(
            sphere_token(Some("Title\u{1c}AND\u{1c}12\u{1c}more\u{1c}pageſ")),
            Some("Title".to_string())
        );
        assert_eq!(
            sphere_token(Some("Title and  more pages")),
            Some("Title and  more pages".to_string())
        );
        assert_eq!(sphere_token(Some("Inbox(3)")), Some("Inbox".to_string()));
        assert_eq!(
            sphere_token(Some("Inbox\u{1c}(3)")),
            Some("Inbox".to_string())
        );
        assert_eq!(sphere_token(Some("Inbox (٣)")), Some("Inbox".to_string()));
        assert_eq!(sphere_token(Some("(٣) Inbox")), Some("Inbox".to_string()));
        assert_eq!(
            sphere_token(Some("Ა Project")),
            Some("Ა Project".to_string())
        );
    }

    #[test]
    fn sphere_token_matches_python_3_12_string_semantics() {
        let python_whitespace = [
            '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{001c}', '\u{001d}',
            '\u{001e}', '\u{001f}', '\u{0020}', '\u{0085}', '\u{00a0}', '\u{1680}', '\u{2000}',
            '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}',
            '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}',
            '\u{3000}',
        ];
        for whitespace in python_whitespace {
            assert!(is_python_whitespace(whitespace));
            assert_eq!(
                sphere_token(Some(&format!("{whitespace}Notes{whitespace}"))),
                Some("Notes".to_string())
            );
            assert_eq!(
                sphere_token(Some(&format!("Left{whitespace}-{whitespace}Right"))),
                Some("Left".to_string())
            );
        }
        assert!(!is_python_whitespace('\u{200b}'));
        assert_eq!(
            sphere_token(Some("\u{001c}and 2 more pages")),
            Some("and 2 more pages".to_string())
        );
        assert_eq!(sphere_token(Some("\u{001c}\u{001f}")), None);

        // Python's str.isalpha() admits only L* general categories, unlike
        // Rust's broader Alphabetic property.
        assert_eq!(sphere_token(Some("Ⅻ 12")), None); // Nl
        assert_eq!(sphere_token(Some("ⓐ②")), None); // Other_Alphabetic
        assert_eq!(sphere_token(Some("3ͅ4")), None); // Other_Alphabetic

        // The suffix substitution preserves every delimiter and space in the
        // unmatched prefix, and Unicode IGNORECASE folds long s to ASCII s.
        assert_eq!(
            sphere_token(Some("π – B7 – C – Microsoft Edge")),
            Some("π – B7".to_string())
        );
        assert_eq!(
            sphere_token(Some("π  –  B7  —  Work – Google Chrome")),
            Some("π  –  B7".to_string())
        );
        assert_eq!(sphere_token(Some("X - Microſoft Edge")), None);
        assert_eq!(sphere_token(Some("X - Mıcrosoft Edge")), None);
        assert_eq!(sphere_token(Some("X - Mİcrosoft Edge")), None);
    }

    #[test]
    fn live_sphere_tokens_reads_title_and_prev_title_with_full_casefold() {
        let conn = Connection::open_in_memory().expect("db opens");
        conn.execute_batch(
            "
            CREATE TABLE events (title TEXT, prev_title TEXT);
            INSERT INTO events (title, prev_title)
            VALUES
                ('Straße - Google Chrome', NULL),
                (NULL, 'ﬁle Notes - Editor'),
                ('Ა Project - Google Chrome', NULL),
                ('<redacted>', '123 - 456');
            ",
        )
        .expect("fixture inserted");

        let tokens = live_sphere_tokens(&conn).expect("tokens read");

        assert_eq!(
            tokens,
            HashSet::from([
                "strasse".to_string(),
                "file notes".to_string(),
                "ა project".to_string(),
            ])
        );
    }

    #[test]
    fn percentile_nearest_rank_goldens() {
        assert_eq!(percentile_nearest_rank(&[], 75.0), 0.0);
        assert_eq!(percentile_nearest_rank(&[7.0], 75.0), 7.0);
        assert_eq!(percentile_nearest_rank(&[1.0, 2.0, 3.0, 4.0], 75.0), 3.0);
        assert_eq!(
            percentile_nearest_rank(&[5.0, 1.0, 4.0, 2.0, 3.0], 50.0),
            3.0
        );
        // 90/100 * 10 rounds to exactly 9.0 in IEEE double (the excess is
        // under half an ulp), so ceil stays at rank 9 — in both languages.
        // Cross-language agreement is pinned by test_percentile_parity.
        let ten: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(percentile_nearest_rank(&ten, 90.0), 9.0);
        assert_eq!(percentile_nearest_rank(&ten, 0.0), 1.0);
    }

    #[test]
    fn coalesce_spans_merges_touching_and_overlapping() {
        assert_eq!(
            coalesce_spans(vec![(10, 20), (30, 40), (15, 25), (25, 30)]),
            vec![(10, 40)]
        );
        assert_eq!(coalesce_spans(vec![(5, 6), (1, 2)]), vec![(1, 2), (5, 6)]);
        assert!(coalesce_spans(Vec::new()).is_empty());
    }

    #[test]
    fn local_day_start_is_a_fixed_point_at_most_a_day_back() {
        for now_ms in [86_400_123_i64, 1_600_000_000_000, 1_751_900_000_000] {
            let start = local_day_start_ms(now_ms);
            assert!(start <= now_ms);
            // Within one day plus a DST hour of the input.
            assert!(now_ms - start < 86_400_000 + 3_600_000);
            assert_eq!(local_day_start_ms(start), start);
        }
    }

    #[test]
    fn ambiguous_boundary_advances_to_the_second_candidate_after_the_first() {
        assert_eq!(ambiguous_candidate_after(1_000, 2_000, 999), 1_000);
        assert_eq!(ambiguous_candidate_after(1_000, 2_000, 1_000), 2_000);
        assert_eq!(ambiguous_candidate_after(2_000, 1_000, 1_500), 2_000);
    }

    #[test]
    fn heatmap_splitter_advances_through_injected_ambiguous_window() {
        use chrono::{NaiveDate, Timelike};

        let date = NaiveDate::from_ymd_opt(2026, 11, 1).expect("valid date");
        let pieces = split_ms_by_weekday_hour_with(
            1_000,
            2_500,
            |cursor| Some((date, if cursor < 2_000 { 0 } else { 1 })),
            |next_hour| match next_hour.hour() {
                1 => LocalBoundaryCandidates::Ambiguous(1_500, 2_000),
                2 => LocalBoundaryCandidates::Single(2_500),
                hour => panic!("unexpected synthetic boundary hour {hour}"),
            },
        );

        // Choosing fold 0 unconditionally collapses the second and third
        // pieces and loses the final hour bucket. This test is independent of
        // the host timezone and exercises the splitter call site itself.
        assert_eq!(pieces, vec![(6, 0, 500), (6, 0, 500), (6, 1, 500)]);
    }

    const CHANGE_WEEK_START: i64 = 1_000_000;
    const CHANGE_NOW: i64 = 2_000_000;

    fn change_episode(date: &str, start_ts: i64, apps: &[&str]) -> Vec<SequenceStep> {
        apps.iter()
            .enumerate()
            .map(|(index, app)| SequenceStep {
                app: (*app).to_string(),
                ts: start_ts + index as i64,
                session_id: 1,
                local_date: date.to_string(),
            })
            .collect()
    }

    #[test]
    fn digest_changes_flag_new_and_quieter_with_python_evidence_strings() {
        let mut episodes = Vec::new();
        // A "new" cluster: 8 in-week occurrences across 2 dates, no baseline.
        for index in 0..8 {
            let date = if index < 4 { "w1" } else { "w2" };
            episodes.push(change_episode(
                date,
                CHANGE_WEEK_START + 100 + index * 10,
                &["alpha", "beta", "gamma"],
            ));
        }
        // A "quieter" anchor: baseline-only round-trips across 3 dates.
        for index in 0..8 {
            let date = ["b1", "b2", "b3"][(index % 3) as usize];
            episodes.push(change_episode(
                date,
                100 + index * 10,
                &["xray", "yankee", "xray"],
            ));
        }

        let changes = digest_changed_from_episodes(&episodes, 14, CHANGE_WEEK_START, CHANGE_NOW);

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].direction, "new");
        assert_eq!(changes[0].app, "alpha");
        assert_eq!(
            changes[0].evidence,
            "a alpha ↔ beta ↔ gamma pattern (8 occurrences across 2 days)"
        );
        assert_eq!((changes[0].support, changes[0].days), (8, 2));
        assert_eq!(changes[1].direction, "quieter");
        assert_eq!(changes[1].app, "xray");
        assert_eq!(
            changes[1].evidence,
            "xray patterns (3 active days in the prior three weeks, none this week)"
        );
        assert_eq!((changes[1].support, changes[1].days), (8, 3));
    }

    #[test]
    fn digest_changes_history_floor_gates_new_flags() {
        let mut episodes = Vec::new();
        for index in 0..8 {
            let date = if index < 4 { "w1" } else { "w2" };
            episodes.push(change_episode(
                date,
                CHANGE_WEEK_START + 100 + index * 10,
                &["alpha", "beta", "gamma"],
            ));
        }
        // 13 pre-week history days sits below DIGEST_CHANGE_MIN_HISTORY_DAYS.
        let changes = digest_changed_from_episodes(&episodes, 13, CHANGE_WEEK_START, CHANGE_NOW);
        assert!(changes.is_empty());
    }

    #[test]
    fn digest_changes_cluster_coverage_suppresses_member_anchor_lines() {
        // [alpha, beta, gamma, beta] flags the {alpha,beta,gamma} cluster
        // (bumped by its len-3 and len-4 windows), the {beta,gamma} cluster,
        // and the beta round-trip anchor. The anchor line is the same change
        // seen through a narrower key and must be dropped.
        let mut episodes = Vec::new();
        for index in 0..8 {
            let date = if index < 4 { "w1" } else { "w2" };
            episodes.push(change_episode(
                date,
                CHANGE_WEEK_START + 100 + index * 10,
                &["alpha", "beta", "gamma", "beta"],
            ));
        }

        let changes = digest_changed_from_episodes(&episodes, 14, CHANGE_WEEK_START, CHANGE_NOW);

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].app, "alpha");
        assert_eq!(
            changes[0].evidence,
            "a alpha ↔ beta ↔ gamma pattern (16 occurrences across 2 days)"
        );
        assert_eq!(changes[1].app, "beta");
        // beta's line is the {beta,gamma} cluster, never its own anchor.
        assert_eq!(
            changes[1].evidence,
            "a beta ↔ gamma pattern (8 occurrences across 2 days)"
        );
    }

    #[test]
    fn digest_changes_equal_support_keeps_first_bumped_key() {
        // Two clusters attribute to the same slot ("new", alpha) with equal
        // support; Python's dict pass keeps the first-inserted key, which is
        // observable through the evidence text.
        let mut episodes = Vec::new();
        for index in 0..8 {
            let date = if index < 4 { "w1" } else { "w2" };
            episodes.push(change_episode(
                date,
                CHANGE_WEEK_START + 100 + index * 10,
                &["alpha", "beta", "gamma"],
            ));
        }
        for index in 0..8 {
            let date = if index < 4 { "w1" } else { "w2" };
            episodes.push(change_episode(
                date,
                CHANGE_WEEK_START + 500 + index * 10,
                &["alpha", "beta", "delta"],
            ));
        }

        let changes = digest_changed_from_episodes(&episodes, 14, CHANGE_WEEK_START, CHANGE_NOW);

        let alpha: Vec<&DigestChange> = changes
            .iter()
            .filter(|change| change.app == "alpha")
            .collect();
        assert_eq!(alpha.len(), 1);
        assert_eq!(
            alpha[0].evidence,
            "a alpha ↔ beta ↔ gamma pattern (8 occurrences across 2 days)"
        );
    }

    #[test]
    fn nonexistent_boundary_probe_finds_non_hour_pre_gap_offset() {
        let naive = chrono::NaiveDate::from_ymd_opt(2026, 10, 4)
            .expect("valid date")
            .and_hms_opt(2, 0, 0)
            .expect("valid time");
        let valid_before = naive - chrono::Duration::minutes(90);
        let mut probes = 0;

        let offset = pre_gap_offset_seconds_with(naive, |probe| {
            probes += 1;
            (probe <= valid_before).then_some(20_700)
        });

        assert_eq!(offset, Some(20_700));
        assert_eq!(probes, 90);
    }

    #[test]
    fn sleep_recovery_with_minimum_gap_saturates_without_panicking() {
        let conn = Connection::open_in_memory().expect("db opens");
        conn.execute_batch(
            r#"
            CREATE TABLE sessions (session_id INTEGER PRIMARY KEY, ended_at INTEGER);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                session_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                ts INTEGER NOT NULL,
                payload TEXT
            );
            INSERT INTO sessions (session_id, ended_at) VALUES (1, 5000);
            INSERT INTO events (id, session_id, kind, ts, payload)
            VALUES (
                1,
                1,
                'power_boundary_recovered',
                1000,
                '{"gap_ms": -9223372036854775808}'
            );
            "#,
        )
        .expect("fixture inserted");

        assert_eq!(
            sleep_intervals(&conn, &[1]).expect("sleep intervals read"),
            vec![SessionInterval {
                session_id: 1,
                start_ts: i64::MAX,
                end_ts: 1_000,
            }]
        );
    }

    #[test]
    fn pause_spans_are_capture_off_and_an_orphan_closes_at_session_end() {
        let conn = Connection::open_in_memory().expect("db opens");
        conn.execute_batch(
            r#"
            CREATE TABLE sessions (session_id INTEGER PRIMARY KEY, ended_at INTEGER);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                session_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                ts INTEGER NOT NULL,
                payload TEXT
            );
            INSERT INTO sessions (session_id, ended_at) VALUES (1, 9000), (2, 8000);
            INSERT INTO events (id, session_id, kind, ts, payload) VALUES
                (1, 1, 'capture_paused', 2000, '{"kind":"capture_paused"}'),
                (2, 1, 'capture_resumed', 5000, '{"kind":"capture_resumed"}'),
                (3, 2, 'capture_paused', 6000, '{"kind":"capture_paused"}');
            "#,
        )
        .expect("fixture inserted");

        assert_eq!(
            sleep_intervals(&conn, &[1, 2]).expect("capture-off intervals read"),
            vec![
                SessionInterval {
                    session_id: 1,
                    start_ts: 2_000,
                    end_ts: 5_000,
                },
                SessionInterval {
                    session_id: 2,
                    start_ts: 6_000,
                    end_ts: 8_000,
                },
            ]
        );
    }

    /// Minimal schema for the open-focus reader tests: the columns the
    /// focus/idle/sleep readers touch plus the migration-007 table.
    fn open_focus_fixture_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            r#"
            CREATE TABLE sessions (session_id INTEGER PRIMARY KEY, ended_at INTEGER);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                session_id INTEGER NOT NULL,
                seq INTEGER,
                ts INTEGER NOT NULL,
                kind TEXT NOT NULL,
                exe TEXT,
                prev_exe TEXT,
                prev_title TEXT,
                duration_ms INTEGER,
                payload TEXT
            );
            CREATE TABLE open_focus (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                session_id INTEGER NOT NULL,
                exe TEXT,
                started_ts INTEGER NOT NULL,
                high_water_ts INTEGER NOT NULL
            );
            INSERT INTO sessions (session_id, ended_at) VALUES (1, NULL);
            "#,
        )
        .expect("fixture schema");
        conn
    }

    /// Noon of a fixed local day: day math stays deterministic in any
    /// timezone because the derived now sits far from both midnights.
    fn open_focus_noon_now() -> i64 {
        local_day_start_ms(1_783_590_000_000) + 12 * 3_600_000
    }

    #[test]
    fn open_focus_beat_matches_the_core_constant() {
        assert_eq!(OPEN_FOCUS_BEAT_MS, gilbreth_core::OPEN_FOCUS_BEAT_MS);
    }

    #[test]
    fn today_story_counts_a_fresh_open_interval_without_completed_rows() {
        let conn = open_focus_fixture_db();
        let now_ms = open_focus_noon_now();
        let started = now_ms - 20 * 60_000;
        let high_water = now_ms - 10_000;
        conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, 1, 'editor.exe', ?1, ?2)",
            rusqlite::params![started, high_water],
        )
        .expect("open row");

        let story = today_story(&conn, now_ms).expect("story reads");
        assert_eq!(story.active_ms, high_water - started);
        assert_eq!(story.foreground_ms, high_water - started);
        assert_eq!(story.focus_switches, 0, "an open segment is not a switch");
        assert_eq!(story.top_app.as_deref(), Some("editor.exe"));
        assert_eq!(story.longest_run_app, None, "the open segment joins no run");
    }

    #[test]
    fn today_story_subtracts_idle_and_clips_the_open_interval_to_day_start() {
        let conn = open_focus_fixture_db();
        let now_ms = open_focus_noon_now();
        let day_start = local_day_start_ms(now_ms);
        let high_water = now_ms - 5_000;
        // Started before local midnight: only the today part counts.
        conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, 1, 'editor.exe', ?1, ?2)",
            rusqlite::params![day_start - 60_000, high_water],
        )
        .expect("open row");
        // A closed idle span inside the open interval: idle rows carry the
        // already-elapsed idle in duration_ms and pair with the next active.
        let idle_start = now_ms - 10 * 60_000;
        let idle_end = now_ms - 4 * 60_000;
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind, duration_ms, payload) \
             VALUES (1, 1, ?1, 'idle', 0, '{}'), (1, 2, ?2, 'active', NULL, '{}')",
            rusqlite::params![idle_start, idle_end],
        )
        .expect("idle pair");

        let story = today_story(&conn, now_ms).expect("story reads");
        let raw = high_water - day_start;
        assert_eq!(story.foreground_ms, raw);
        assert_eq!(story.active_ms, raw - (idle_end - idle_start));
    }

    #[test]
    fn today_story_subtracts_a_still_open_idle_span_from_the_open_interval() {
        let conn = open_focus_fixture_db();
        let now_ms = open_focus_noon_now();
        let started = now_ms - 30 * 60_000;
        let high_water = now_ms - 5_000;
        conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, 1, 'editor.exe', ?1, ?2)",
            rusqlite::params![started, high_water],
        )
        .expect("open row");
        // An idle row with no active row after it: the user is idle RIGHT
        // NOW. The span reconstructs backwards by the already-elapsed idle
        // and must subtract through the interval's end.
        let idle_ts = now_ms - 10 * 60_000;
        let elapsed_ms = 3 * 60_000;
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind, duration_ms, payload) \
             VALUES (1, 1, ?1, 'idle', ?2, '{}')",
            rusqlite::params![idle_ts, elapsed_ms],
        )
        .expect("open idle row");

        let story = today_story(&conn, now_ms).expect("story reads");
        let raw = high_water - started;
        assert_eq!(story.foreground_ms, raw, "in-front time keeps idle");
        assert_eq!(
            story.active_ms,
            raw - (high_water - (idle_ts - elapsed_ms)),
            "active time excludes the idleness happening right now"
        );
    }

    #[test]
    fn today_story_ignores_a_stale_open_focus_row() {
        let conn = open_focus_fixture_db();
        let now_ms = open_focus_noon_now();
        // One tick past two beats: a crashed pump whose repair has not run
        // yet — the dwell belongs to repair, not the live reader.
        conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, 1, 'editor.exe', ?1, ?2)",
            rusqlite::params![
                now_ms - 30 * 60_000,
                now_ms - 2 * OPEN_FOCUS_BEAT_MS - 1_000
            ],
        )
        .expect("stale row");

        let story = today_story(&conn, now_ms).expect("story reads");
        assert_eq!(story.active_ms, 0);
        assert_eq!(story.foreground_ms, 0);
        assert_eq!(story.top_app, None);
    }

    #[test]
    fn today_story_reads_unchanged_without_the_open_focus_table() {
        let conn = open_focus_fixture_db();
        conn.execute_batch("DROP TABLE open_focus")
            .expect("older database shape");
        let story = today_story(&conn, open_focus_noon_now()).expect("story reads");
        assert_eq!(story.active_ms, 0);
        assert_eq!(story.top_app, None);
    }

    #[test]
    fn weekly_digest_counts_the_open_interval_but_never_as_a_switch() {
        let conn = open_focus_fixture_db();
        let now_ms = open_focus_noon_now();
        let started = now_ms - 20 * 60_000;
        let high_water = now_ms - 10_000;
        conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, 1, 'editor.exe', ?1, ?2)",
            rusqlite::params![started, high_water],
        )
        .expect("open row");
        // A still-open idle span (no active row after it) subtracts from
        // the weekly open interval too, through the second span pass.
        let idle_ts = now_ms - 5 * 60_000;
        let elapsed_ms = 60_000;
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, kind, duration_ms, payload) \
             VALUES (1, 1, ?1, 'idle', ?2, '{}')",
            rusqlite::params![idle_ts, elapsed_ms],
        )
        .expect("open idle row");

        let digest = weekly_digest_core(&conn, now_ms).expect("digest reads");
        let expected_active = (high_water - started) - (high_water - (idle_ts - elapsed_ms));
        assert_eq!(digest.active_ms, expected_active);
        assert_eq!(digest.top_apps.len(), 1);
        assert_eq!(digest.top_apps[0].app, "editor.exe");
        assert_eq!(digest.top_apps[0].active_ms, expected_active);
        assert_eq!(digest.active_days, 1);
        assert_eq!(
            digest.switches_per_active_hour,
            Some(0.0),
            "the open segment is not a switch"
        );
    }

    #[test]
    fn empty_discovery_today_key_uses_computed_default() {
        let now_ms = 1_783_590_000_000;
        assert_eq!(
            effective_discovery_today_key(Some(""), now_ms),
            effective_discovery_today_key(None, now_ms)
        );
        assert_eq!(
            effective_discovery_today_key(Some("2026-07-06"), now_ms),
            "2026-07-06"
        );
    }

    #[test]
    fn replay_export_forbidden_keys_use_python_casefold() {
        assert!(is_replay_export_forbidden_key("ſphere"));
        assert!(is_replay_export_forbidden_key("SPHERE"));
        assert!(!is_replay_export_forbidden_key("safe_key"));
    }

    #[test]
    fn out_of_i64_python_integer_coercion_fails_closed() {
        let error = python_int_from_sql_value(Value::Real(1e26), 7)
            .expect_err("out-of-contract scalar must fail closed");
        assert!(error.to_string().contains("outside the reader's i64 range"));
    }

    /// The Session-tab reader fixture: an ended identity-bearing session, an
    /// open (ended_at NULL) session, and an empty ended session.
    fn session_fixture_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            r#"
            CREATE TABLE sessions (
                session_id INTEGER PRIMARY KEY,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                host TEXT,
                app_version TEXT,
                git_sha TEXT,
                run_label TEXT
            );
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                session_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                is_sensitive INTEGER NOT NULL DEFAULT 0,
                hwnd TEXT,
                exe TEXT,
                title TEXT,
                prev_exe TEXT,
                prev_title TEXT,
                key TEXT,
                mod_shift INTEGER,
                mod_ctrl INTEGER,
                mod_alt INTEGER,
                mod_win INTEGER,
                button TEXT,
                pos_x INTEGER,
                pos_y INTEGER,
                duration_ms INTEGER,
                payload TEXT NOT NULL DEFAULT '{}'
            );
            INSERT INTO sessions (session_id, started_at, ended_at, host, app_version, git_sha, run_label)
            VALUES
                (1, 1000000, 2000000, 'DESK', '0.9.0', 'abcdef1234567890abcdef', 'soak'),
                (2, 3000000, NULL, NULL, NULL, NULL, NULL),
                (3, 500000, 600000, NULL, NULL, NULL, NULL);
            -- Session 1: two apps, one shared basename under different paths,
            -- an idle span overlapping the second dwell, keys, and system rows.
            INSERT INTO events (id, session_id, seq, ts, source, kind, prev_exe, prev_title, duration_ms, payload)
            VALUES
                (1, 1, 1, 1060000, 'foreground', 'focus_changed', 'C:\Apps\studio.exe', 'Doc A', 60000, '{}'),
                (2, 1, 2, 1090000, 'foreground', 'focus_changed', 'chat.exe', 'Chat', 30000, '{}'),
                (3, 1, 3, 1150000, 'foreground', 'focus_changed', 'D:\Other\studio.exe', 'Doc B', 60000, '{}');
            INSERT INTO events (id, session_id, seq, ts, source, kind, duration_ms, payload)
            VALUES
                (4, 1, 4, 1100000, 'system', 'idle', NULL, '{}'),
                (5, 1, 5, 1120000, 'system', 'active', NULL, '{}');
            INSERT INTO events (id, session_id, seq, ts, source, kind, key, payload)
            VALUES
                (6, 1, 6, 1130000, 'keyboard', 'key', 'a', '{}'),
                (7, 1, 7, 1130500, 'keyboard', 'key', 'b', '{}');
            INSERT INTO events (id, session_id, seq, ts, source, kind, title, pos_x, pos_y, payload)
            VALUES
                (8, 1, 8, 1140000, 'system', 'session_start', 'logon', NULL, NULL, '{}'),
                (9, 1, 9, 1141000, 'system', 'process_started', 'x.exe', NULL, NULL, '{}');
            INSERT INTO events (id, session_id, seq, ts, source, kind, payload)
            VALUES
                (10, 1, 10, 1160000, 'system', 'power_suspend', '{"tick_ms": 5000}'),
                (11, 1, 11, 1190000, 'system', 'power_resume', '{"matched_suspend": true, "tick_ms": 6000, "gap_ms": 30000}'),
                (12, 1, 12, 1195000, 'system', 'power_boundary_recovered', '{"gap_ms": 4000, "capped_dwell_ms": 2000}');
            -- Session 2 (open): a single dwell, no idle rows.
            INSERT INTO events (id, session_id, seq, ts, source, kind, prev_exe, prev_title, duration_ms, payload)
            VALUES (13, 2, 1, 3040000, 'foreground', 'focus_changed', 'mail.exe', 'Inbox', 40000, '{}');
            "#,
        )
        .expect("fixture schema");
        conn
    }

    #[test]
    fn read_sessions_orders_newest_first_with_identity_and_counts() {
        let conn = session_fixture_db();
        let sessions = read_sessions(&conn).expect("sessions read");
        assert_eq!(
            sessions
                .iter()
                .map(|row| (row.session_id, row.event_count))
                .collect::<Vec<_>>(),
            vec![(2, 1), (1, 12), (3, 0)],
            "newest first — the open session leads; the empty session still lists"
        );
        let open = &sessions[0];
        assert!(open.started_at.is_some());
        assert_eq!(open.ended_at, None, "open session has no end");
        assert_eq!(open.host, None);
        let identity = &sessions[1];
        assert_eq!(identity.host.as_deref(), Some("DESK"));
        assert_eq!(identity.app_version.as_deref(), Some("0.9.0"));
        assert_eq!(identity.run_label.as_deref(), Some("soak"));
    }

    #[test]
    fn read_sessions_tolerates_a_pre_identity_schema() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE sessions (session_id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL, ended_at INTEGER);
             CREATE TABLE events (id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, ts INTEGER);
             INSERT INTO sessions (session_id, started_at, ended_at) VALUES (1, 1000000, NULL);",
        )
        .expect("legacy schema");
        let sessions = read_sessions(&conn).expect("sessions read");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].host, None, "missing identity columns read NULL");
        assert_eq!(sessions[0].git_sha, None);
    }

    #[test]
    fn read_event_counts_groups_and_orders_by_volume() {
        let conn = session_fixture_db();
        let counts = read_event_counts(&conn, 1).expect("counts read");
        assert_eq!(counts[0].kind, "focus_changed");
        assert_eq!(counts[0].events, 3);
        let key_row = counts
            .iter()
            .find(|row| row.kind == "key")
            .expect("key row");
        assert_eq!((key_row.source.as_str(), key_row.events), ("keyboard", 2));
        // Ties on events sort by (source, kind); every count is in-session.
        let total: i64 = counts.iter().map(|row| row.events).sum();
        assert_eq!(total, 12);
        assert!(read_event_counts(&conn, 3).expect("empty read").is_empty());
    }

    #[test]
    fn read_focus_summary_groups_raw_exe_and_subtracts_idle() {
        let conn = session_fixture_db();
        let summary = read_focus_summary(&conn, 1, false).expect("summary reads");
        // Grouped by the raw stored exe: the two studio paths stay separate
        // rows (display_app is applied by the view, like the pandas frame).
        assert_eq!(summary.len(), 3);
        assert!(summary.iter().all(|row| row.completed_title.is_none()));
        let second_studio = summary
            .iter()
            .find(|row| row.completed_exe == "D:\\Other\\studio.exe")
            .expect("second studio row");
        // 60 s dwell (1090000..1150000) minus the 20 s idle overlap.
        assert_eq!(second_studio.focus_seconds, 60.0);
        assert_eq!(second_studio.active_foreground_seconds, 40.0);

        let titled = read_focus_summary(&conn, 1, true).expect("titled summary");
        assert!(
            titled.iter().all(|row| row.completed_title.is_some()),
            "titles column present"
        );
        assert!(read_focus_summary(&conn, 3, false)
            .expect("empty summary")
            .is_empty());
    }

    #[test]
    fn session_story_totals_first_max_wins_and_switches_sum() {
        let conn = session_fixture_db();
        let summary = read_focus_summary(&conn, 1, false).expect("summary reads");
        let story = session_story_totals(&summary);
        assert_eq!(story.top_app.as_deref(), Some("studio.exe"));
        assert_eq!(story.top_app_active_seconds, 60.0);
        assert_eq!(story.focus_switches, 3);

        let empty = session_story_totals(&[]);
        assert_eq!(
            (
                empty.top_app,
                empty.top_app_active_seconds,
                empty.focus_switches
            ),
            (None, 0.0, 0)
        );

        // A tie on active seconds keeps the FIRST row, like pandas idxmax.
        let tied = vec![
            FocusSummaryRow {
                completed_exe: "first.exe".to_string(),
                completed_title: None,
                focus_seconds: 10.0,
                active_foreground_seconds: 5.0,
                switches: 1,
            },
            FocusSummaryRow {
                completed_exe: "second.exe".to_string(),
                completed_title: None,
                focus_seconds: 10.0,
                active_foreground_seconds: 5.0,
                switches: 1,
            },
        ];
        assert_eq!(
            session_story_totals(&tied).top_app.as_deref(),
            Some("first.exe")
        );
    }

    #[test]
    fn session_totals_cover_open_and_empty_sessions() {
        let conn = session_fixture_db();
        assert_eq!(
            read_session_focus_seconds_total(&conn, 1).expect("focus total"),
            150.0
        );
        // Idle (20 s) and the suspend..resume sleep span (30 s) both land
        // inside no dwell for session 1's third interval only partially; the
        // exact value is pinned by the parity suite — here the invariant:
        // active <= focus, and the open session's single dwell counts fully.
        let active = read_session_active_focus_seconds_total(&conn, 1).expect("active total");
        assert!(active > 0.0 && active < 150.0, "idle subtracts: {active}");
        assert_eq!(
            read_session_focus_seconds_total(&conn, 2).expect("open focus"),
            40.0
        );
        assert_eq!(
            read_session_active_focus_seconds_total(&conn, 2).expect("open active"),
            40.0
        );
        assert_eq!(
            read_session_focus_seconds_total(&conn, 3).expect("empty focus"),
            0.0
        );
        assert_eq!(
            read_session_active_focus_seconds_total(&conn, 3).expect("empty active"),
            0.0
        );
    }

    #[test]
    fn read_system_events_excludes_process_churn_rows() {
        let conn = session_fixture_db();
        let rows = read_system_events(&conn, 1).expect("system events");
        assert!(rows.iter().all(|row| row.kind != "process_started"));
        assert!(rows.iter().any(|row| row.kind == "session_start"));
        assert!(rows.iter().any(|row| row.kind == "power_suspend"));
        // Newest first.
        assert_eq!(
            rows.first().map(|row| row.kind.as_str()),
            Some("power_boundary_recovered")
        );
        assert!(read_system_events(&conn, 3).expect("empty").is_empty());
    }

    #[test]
    fn read_power_events_diff_columns_mirror_pandas() {
        let conn = session_fixture_db();
        let rows = read_power_events(&conn, 1).expect("power events");
        assert_eq!(
            rows.iter().map(|row| row.kind.as_str()).collect::<Vec<_>>(),
            vec!["power_suspend", "power_resume", "power_boundary_recovered"]
        );
        // First row: no prior row, both diffs empty.
        assert_eq!((rows[0].wall_gap_ms, rows[0].tick_gap_ms), (None, None));
        assert_eq!(rows[0].tick_ms, Some(5000));
        // Second row: 30 s wall gap, 1 s tick gap, matched_suspend true -> 1.
        assert_eq!(rows[1].wall_gap_ms, Some(30_000));
        assert_eq!(rows[1].tick_gap_ms, Some(1_000));
        assert_eq!(rows[1].matched_suspend, Some(1));
        assert_eq!(rows[1].gap_ms, Some(30_000));
        // Third row: no tick_ms on it, so the tick diff is empty on this row
        // (and would be on the next), like pandas NaN propagation.
        assert_eq!(rows[2].wall_gap_ms, Some(5_000));
        assert_eq!(rows[2].tick_gap_ms, None);
        assert_eq!(rows[2].capped_dwell_ms, Some(2_000));
        assert!(read_power_events(&conn, 2)
            .expect("no power rows")
            .is_empty());
    }

    #[test]
    fn read_activity_events_returns_newest_full_rows() {
        let conn = session_fixture_db();
        let rows = read_activity_events(&conn, 1).expect("events read");
        assert_eq!(rows.len(), 12);
        assert_eq!(rows[0].id, 12, "newest first");
        let focus = rows
            .iter()
            .find(|row| row.id == 1)
            .expect("first focus row");
        assert_eq!(focus.completed_exe.as_deref(), Some("C:\\Apps\\studio.exe"));
        assert_eq!(focus.completed_title.as_deref(), Some("Doc A"));
        assert_eq!(focus.duration_ms, Some(60_000));
        assert_eq!(focus.kind, "focus_changed");
        let key = rows.iter().find(|row| row.id == 6).expect("key row");
        assert_eq!(key.key.as_deref(), Some("a"));
        assert!(read_activity_events(&conn, 3).expect("empty").is_empty());
    }
}
