//! Display formatting carried over from the Streamlit dashboard so the two
//! dashboards read identically during strangler mode.

use chrono::{Local, LocalResult, TimeZone};

/// Mirrors `format_duration_ms`: "2h 5m 3s" style, "0s" for zero/negative,
/// empty string only for unrepresentable input (which Rust callers don't
/// produce). Python rounds float seconds with banker's rounding.
pub fn format_duration_ms(value_ms: i64) -> String {
    format_duration_seconds_total((value_ms as f64 / 1000.0).round_ties_even() as i64)
}

/// Mirrors `format_duration_minutes`: minutes-valued floats through the
/// same duration shape (Python calls `format_duration_ms(value * 60_000)`).
pub fn format_duration_minutes(minutes: f64) -> String {
    format_duration_seconds_total((minutes * 60.0).round_ties_even() as i64)
}

/// Mirrors `format_duration_seconds`: seconds-valued floats through the
/// same duration shape (Python calls `format_duration_ms(value * 1000)`).
pub fn format_duration_seconds(seconds: f64) -> String {
    format_duration_seconds_total(seconds.round_ties_even() as i64)
}

fn format_duration_seconds_total(total_seconds: i64) -> String {
    if total_seconds <= 0 {
        return "0s".to_string();
    }
    let (minutes, seconds) = (total_seconds / 60, total_seconds % 60);
    let (hours, minutes) = (minutes / 60, minutes % 60);
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

/// Mirrors `format_minutes_metric`.
pub fn format_minutes_metric(value: Option<f64>) -> String {
    match value {
        Some(minutes) => format_duration_minutes(minutes),
        None => "Not enough data".to_string(),
    }
}

/// Mirrors `format_seconds_metric`, minus the space before the unit: raw
/// seconds stay only where sub-second precision matters, and they read
/// "2.3s" beside "1m 23s", not "2.3 s" (UX-09).
pub fn format_seconds_metric(value: Option<f64>) -> String {
    match value {
        Some(seconds) => format!("{seconds:.1}s"),
        None => "Not enough data".to_string(),
    }
}

/// Mirrors `format_rate_metric`: thousands-grouped whole numbers from 100
/// up, one decimal below.
pub fn format_rate_metric(value: Option<f64>) -> String {
    match value {
        Some(rate) if rate >= 100.0 => thousands(rate.round_ties_even() as i64),
        Some(rate) => format!("{rate:.1}"),
        None => "Not enough data".to_string(),
    }
}

/// Shortest float rendering for table cells ("48", "53.33").
pub fn float_cell(value: f64) -> String {
    if value == value.trunc() {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

/// UX-10: the one missing-value spelling every table and gauge uses. The
/// bare em dash is data notation, not prose (Lane B seeded exception).
// copy-allow: em-dash UX-10 missing-value cell, data notation not prose (Lane B seeded exception)
pub const MISSING_VALUE_CELL: &str = "—";

/// `None` renders as the em dash the Streamlit tables substitute.
pub fn opt_float_cell(value: Option<f64>) -> String {
    value.map_or_else(|| MISSING_VALUE_CELL.to_string(), float_cell)
}

/// Splits a unit-carrying figure ("75.0 MB", "512 bytes") into the value
/// and its unit, for the gauge value/suffix registers (type-ramp
/// amendment §7: values 19px, suffixes 12.5px).
pub fn split_unit(value: &str) -> (String, Option<String>) {
    match value.rsplit_once(' ') {
        Some((figure, unit)) => (figure.to_string(), Some(unit.to_string())),
        None => (value.to_string(), None),
    }
}

/// Mirrors app.py's `format_age_seconds` ("14s ago", "3m 2s ago",
/// "1h 4m ago"), except `None` renders the app-wide em dash instead of
/// Streamlit's "none" (UX-10: one missing-value spelling).
pub fn format_age_seconds(value: Option<i64>) -> String {
    let Some(value) = value else {
        return MISSING_VALUE_CELL.to_string();
    };
    if value < 60 {
        return format!("{value}s ago");
    }
    let (minutes, seconds) = (value / 60, value % 60);
    if minutes < 60 {
        return format!("{minutes}m {seconds}s ago");
    }
    let (hours, minutes) = (minutes / 60, minutes % 60);
    format!("{hours}h {minutes}m ago")
}

/// Mirrors `_local_clock`: local wall-clock HH:MM for a UTC millisecond
/// timestamp, resolving DST-ambiguous instants with fold=0 like Python.
pub fn local_clock(ts_ms: i64) -> String {
    local_datetime(ts_ms)
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_default()
}

/// "Thursday, July 9" — Python renders f"{dt:%A, %B} {dt.day}".
pub fn local_day_heading(ts_ms: i64) -> String {
    local_datetime(ts_ms)
        .map(|dt| {
            use chrono::Datelike;
            format!("{} {}", dt.format("%A, %B"), dt.day())
        })
        .unwrap_or_default()
}

/// "Jul 2" — Python renders f"{dt:%b} {dt.day}" in the Week caption.
pub fn local_month_day(ts_ms: i64) -> String {
    local_datetime(ts_ms)
        .map(|dt| {
            use chrono::Datelike;
            format!("{} {}", dt.format("%b"), dt.day())
        })
        .unwrap_or_default()
}

fn local_datetime(ts_ms: i64) -> Option<chrono::DateTime<Local>> {
    match Local.timestamp_millis_opt(ts_ms) {
        LocalResult::Single(dt) => Some(dt),
        LocalResult::Ambiguous(first, _) => Some(first),
        LocalResult::None => None,
    }
}

/// Mirrors Python's `f"{value:,}"` thousands grouping.
/// UX-17 / UXR-19: the one range separator every sibling range label uses
/// (an en dash; em dashes stay out of data notation).
// copy-allow: en-dash the range separator itself (the range separator ruleAMENDMENT decision 4: the en dash is reserved for ranges; Lane B seeded exception)
pub const RANGE_SEPARATOR: &str = "\u{2013}";

pub fn thousands(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if negative {
        format!("-{grouped}")
    } else {
        grouped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_matches_streamlit_shapes() {
        assert_eq!(format_duration_ms(0), "0s");
        assert_eq!(format_duration_ms(-100), "0s");
        assert_eq!(format_duration_ms(999), "1s");
        assert_eq!(format_duration_ms(59_000), "59s");
        assert_eq!(format_duration_ms(60_000), "1m");
        assert_eq!(format_duration_ms(61_000), "1m 1s");
        assert_eq!(format_duration_ms(3_600_000), "1h");
        assert_eq!(format_duration_ms(3_661_000), "1h 1m 1s");
        assert_eq!(format_duration_ms(7_205_000), "2h 5s");
        // Python round() is banker's: 500 ms rounds to the even second.
        assert_eq!(format_duration_ms(500), "0s");
        assert_eq!(format_duration_ms(1_500), "2s");
        assert_eq!(format_duration_ms(2_500), "2s");
    }

    #[test]
    fn thousands_groups_like_python() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-1_234), "-1,234");
    }
}
