from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# The level token sits right after the timestamp, so both patterns anchor
# there case-sensitively: message text must not classify the line (the
# 2026-07-28 finding: 94 of a dev machine's 95 counted "errors" were WARN
# lines carrying a structured `error=` field). Panic lines have no level
# prefix at all, so that arm stays an unanchored, case-insensitive
# substring. Byte-parity twin: gilbreth-app/src/health.rs.
LOG_WARNING_RE = re.compile(r"^\S+\s+WARN\b")
LOG_ERROR_OR_PANIC_RE = re.compile(r"^\S+\s+ERROR\b|(?i:panic)")
CLIPBOARD_LOCKED_RE = re.compile(
    r"clipboard changed but metadata was unavailable; clipboard is locked",
    re.IGNORECASE,
)
ORPHAN_SESSION_REPAIR_RE = re.compile(
    r"previous session\(s\) ended without graceful stop",
    re.IGNORECASE,
)
STALE_PRE_ERASE_DROP_RE = re.compile(
    r"dropped stale pre-erase capture row",
    re.IGNORECASE,
)
RECOVERED_FOCUS_RE = re.compile(
    r"recovered an open focus segment from an ungraceful shutdown",
    re.IGNORECASE,
)
OPEN_FOCUS_DISCARD_RE = re.compile(
    r"discarded an open-focus row whose session already ended",
    re.IGNORECASE,
)
EVENTS_SKIPPED_RE = re.compile(r"events_skipped[=:\s]+(\d+)", re.IGNORECASE)
LOG_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\b"
)
SEQ_GAP_SQL = """
WITH sequenced_rows AS (
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
ORDER BY session_id
"""
EVENTS_ONLY_SEQ_GAP_SQL = """
SELECT session_id
FROM events
GROUP BY session_id
HAVING COUNT(*) != MAX(seq) - MIN(seq) + 1
    OR COUNT(*) != COUNT(DISTINCT seq)
ORDER BY session_id
"""
POWER_COUNTS_SQL = """
SELECT kind, COUNT(*)
FROM events
WHERE kind IN (
    'power_suspend',
    'power_resume',
    'power_boundary_recovered'
)
GROUP BY kind
"""
PROCESS_COUNTS_SQL = """
SELECT kind, COUNT(*)
FROM events
WHERE kind IN ('process_started', 'process_exited')
GROUP BY kind
"""
PAUSE_COUNTS_SQL = """
SELECT kind, COUNT(*)
FROM events
WHERE kind IN ('capture_paused', 'capture_resumed')
GROUP BY kind
"""
RECOVERED_FOCUS_SQL = """
SELECT COUNT(*)
FROM events
WHERE kind = 'focus_changed'
  AND json_extract(payload, '$.recovered') = 1
"""
DELETION_AUDIT_SPANS_SQL = """
SELECT session_id, seq_min, seq_max, performed_at, rows_deleted
FROM deletion_audit
"""
DELETION_AUDIT_TOTAL_SQL = "SELECT COALESCE(SUM(rows_deleted), 0) FROM deletion_audit"
SESSION_SEQS_SQL = """
SELECT seq FROM events WHERE session_id = ?1
UNION ALL
SELECT seq FROM action_events WHERE session_id = ?1
"""
EVENTS_ONLY_SESSION_SEQS_SQL = "SELECT seq FROM events WHERE session_id = ?1"
CAPTURE_EVENTS_DROPPED_META_KEY = "capture_events_dropped"
STALE_PRE_ERASE_ROWS_DROPPED_META_KEY = "stale_pre_erase_rows_dropped"


@dataclass(frozen=True)
class LogSummary:
    files: int
    warning_lines: int
    error_panic_lines: int
    clipboard_locked_warning_lines: int
    orphan_session_repair_warning_lines: int
    stale_pre_erase_drop_warning_lines: int
    recovered_focus_warning_lines: int
    open_focus_discard_warning_lines: int
    max_events_skipped: int

    @property
    def issue_lines(self) -> int:
        return self.warning_lines + self.error_panic_lines

    @property
    def unknown_warning_lines(self) -> int:
        known_warnings = (
            self.clipboard_locked_warning_lines
            + self.orphan_session_repair_warning_lines
            + self.stale_pre_erase_drop_warning_lines
            + self.recovered_focus_warning_lines
            + self.open_focus_discard_warning_lines
        )
        return max(0, self.warning_lines - known_warnings)

    @property
    def healthy(self) -> bool:
        return (
            self.unknown_warning_lines == 0
            and self.error_panic_lines == 0
            and self.max_events_skipped == 0
        )


@dataclass(frozen=True)
class DatabaseReview:
    db_path: Path
    sha256: str
    size_bytes: int
    wal_size_bytes: int
    shm_size_bytes: int
    integrity_check: str
    foreign_key_issues: int
    user_version: int
    sessions: int
    open_sessions: int
    events: int
    sensitive_rows: int
    # Sessions whose seq holes are NOT covered by recorded deletions — the
    # REVIEW-driving set. Explained sessions land in explained_gap_sessions.
    seq_gap_sessions: tuple[int, ...]
    explained_gap_sessions: tuple[int, ...]
    # Total rows_deleted recorded in deletion_audit; None when the table
    # does not exist yet (pre-008 database or old archive).
    deletion_audit_rows_deleted: int | None
    power_counts: dict[str, int]
    process_counts: dict[str, int]
    pause_counts: dict[str, int]
    recovered_focus_rows: int
    clipboard_rows: int
    clipboard_unavailable_rows: int
    capture_events_dropped: int
    stale_pre_erase_rows_dropped: int
    min_ts: int | None
    max_ts: int | None

    @property
    def healthy(self) -> bool:
        return (
            self.integrity_check == "ok"
            and self.foreign_key_issues == 0
            and not self.seq_gap_sessions
            and self.capture_events_dropped == 0
            and self.stale_pre_erase_rows_dropped == 0
        )


def default_db_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "Gilbreth" / "gilbreth.db"
    return Path("gilbreth.db")


def default_logs_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "Gilbreth" / "logs"
    return Path("logs")


def review_database(db_path: Path) -> DatabaseReview:
    resolved = db_path.resolve()
    with closing(sqlite3.connect(f"{resolved.as_uri()}?mode=ro", uri=True)) as conn:
        conn.execute("PRAGMA busy_timeout = 5000")
        integrity_check = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_issues = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        sessions = _count(conn, "sessions")
        events = _count(conn, "events")
        open_sessions = int(
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL"
            ).fetchone()[0]
        )
        sensitive_rows = int(
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE is_sensitive != 0"
            ).fetchone()[0]
        )
        has_action_events = _table_exists(conn, "action_events")
        seq_gap_sql = SEQ_GAP_SQL if has_action_events else EVENTS_ONLY_SEQ_GAP_SQL
        seq_gap_rows = conn.execute(seq_gap_sql).fetchall()
        flagged_gap_sessions = tuple(int(row[0]) for row in seq_gap_rows)
        if _table_exists(conn, "deletion_audit"):
            deletion_audit_rows_deleted = int(
                conn.execute(DELETION_AUDIT_TOTAL_SQL).fetchone()[0]
            )
            audit_spans: dict[int, list[tuple[int, int, int, int]]] = {}
            for (
                span_session,
                seq_min,
                seq_max,
                performed_at,
                rows_deleted,
            ) in conn.execute(DELETION_AUDIT_SPANS_SQL).fetchall():
                audit_spans.setdefault(int(span_session), []).append(
                    (int(seq_min), int(seq_max), int(performed_at), int(rows_deleted))
                )
        else:
            deletion_audit_rows_deleted = None
            audit_spans = {}
        unexplained: list[int] = []
        explained: list[int] = []
        for flagged_session in flagged_gap_sessions:
            session_spans = audit_spans.get(flagged_session, [])
            if session_spans:
                started_row = conn.execute(
                    "SELECT started_at FROM sessions WHERE session_id = ?1",
                    (flagged_session,),
                ).fetchone()
                started_at = started_row[0] if started_row is not None else None
                if started_at is not None:
                    # A deletion inside a session can only happen after the
                    # session began. Spans stamped earlier are residue from a
                    # pre-008 binary's erase (it does not know this table, and
                    # session ids restart after erase), and residue must never
                    # explain a fresh session's gaps — discarding fails toward
                    # REVIEW, the honest direction.
                    session_spans = [
                        span for span in session_spans if span[2] >= int(started_at)
                    ]
            if _session_gap_is_explained(
                conn,
                flagged_session,
                has_action_events,
                session_spans,
            ):
                explained.append(flagged_session)
            else:
                unexplained.append(flagged_session)
        seq_gap_sessions = tuple(unexplained)
        explained_gap_sessions = tuple(explained)
        power_rows = conn.execute(POWER_COUNTS_SQL).fetchall()
        power_counts = {str(kind): int(count) for kind, count in power_rows}
        process_rows = conn.execute(PROCESS_COUNTS_SQL).fetchall()
        process_counts = {str(kind): int(count) for kind, count in process_rows}
        pause_rows = conn.execute(PAUSE_COUNTS_SQL).fetchall()
        pause_counts = {str(kind): int(count) for kind, count in pause_rows}
        recovered_focus_rows = int(conn.execute(RECOVERED_FOCUS_SQL).fetchone()[0])
        clipboard_rows = int(
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE kind = 'clipboard_used'"
            ).fetchone()[0]
        )
        clipboard_unavailable_rows = int(conn.execute("""
                SELECT COUNT(*)
                FROM events
                WHERE kind = 'clipboard_used'
                  AND json_extract(payload, '$.format_kind') = 'unavailable'
                """).fetchone()[0])
        capture_events_dropped = _meta_int(conn, CAPTURE_EVENTS_DROPPED_META_KEY)
        stale_pre_erase_rows_dropped = _meta_int(
            conn, STALE_PRE_ERASE_ROWS_DROPPED_META_KEY
        )
        min_ts, max_ts = conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()

    return DatabaseReview(
        db_path=resolved,
        sha256=sha256_file(resolved),
        size_bytes=_path_size(resolved),
        wal_size_bytes=_path_size(Path(f"{resolved}-wal")),
        shm_size_bytes=_path_size(Path(f"{resolved}-shm")),
        integrity_check=integrity_check,
        foreign_key_issues=foreign_key_issues,
        user_version=user_version,
        sessions=sessions,
        open_sessions=open_sessions,
        events=events,
        sensitive_rows=sensitive_rows,
        seq_gap_sessions=seq_gap_sessions,
        explained_gap_sessions=explained_gap_sessions,
        deletion_audit_rows_deleted=deletion_audit_rows_deleted,
        power_counts=power_counts,
        process_counts=process_counts,
        pause_counts=pause_counts,
        recovered_focus_rows=recovered_focus_rows,
        clipboard_rows=clipboard_rows,
        clipboard_unavailable_rows=clipboard_unavailable_rows,
        capture_events_dropped=capture_events_dropped,
        stale_pre_erase_rows_dropped=stale_pre_erase_rows_dropped,
        min_ts=int(min_ts) if min_ts is not None else None,
        max_ts=int(max_ts) if max_ts is not None else None,
    )


def review_logs(
    logs_dir: Path,
    *,
    since_ms: int | None = None,
    until_ms: int | None = None,
) -> LogSummary:
    if not logs_dir.exists():
        return LogSummary(
            files=0,
            warning_lines=0,
            error_panic_lines=0,
            clipboard_locked_warning_lines=0,
            orphan_session_repair_warning_lines=0,
            stale_pre_erase_drop_warning_lines=0,
            recovered_focus_warning_lines=0,
            open_focus_discard_warning_lines=0,
            max_events_skipped=0,
        )

    files = sorted(path for path in logs_dir.glob("gilbreth.log*") if path.is_file())
    warning_lines = 0
    error_panic_lines = 0
    clipboard_locked_warning_lines = 0
    orphan_session_repair_warning_lines = 0
    stale_pre_erase_drop_warning_lines = 0
    recovered_focus_warning_lines = 0
    open_focus_discard_warning_lines = 0
    max_events_skipped = 0
    for path in files:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    if not _log_line_in_window(line, since_ms, until_ms):
                        continue
                    if LOG_WARNING_RE.search(line):
                        warning_lines += 1
                        if CLIPBOARD_LOCKED_RE.search(line):
                            clipboard_locked_warning_lines += 1
                        if ORPHAN_SESSION_REPAIR_RE.search(line):
                            orphan_session_repair_warning_lines += 1
                        if STALE_PRE_ERASE_DROP_RE.search(line):
                            stale_pre_erase_drop_warning_lines += 1
                        if RECOVERED_FOCUS_RE.search(line):
                            recovered_focus_warning_lines += 1
                        if OPEN_FOCUS_DISCARD_RE.search(line):
                            open_focus_discard_warning_lines += 1
                    if LOG_ERROR_OR_PANIC_RE.search(line):
                        error_panic_lines += 1
                    for match in EVENTS_SKIPPED_RE.finditer(line):
                        max_events_skipped = max(
                            max_events_skipped, int(match.group(1))
                        )
        except OSError:
            error_panic_lines += 1
    return LogSummary(
        files=len(files),
        warning_lines=warning_lines,
        error_panic_lines=error_panic_lines,
        clipboard_locked_warning_lines=clipboard_locked_warning_lines,
        orphan_session_repair_warning_lines=orphan_session_repair_warning_lines,
        stale_pre_erase_drop_warning_lines=stale_pre_erase_drop_warning_lines,
        recovered_focus_warning_lines=recovered_focus_warning_lines,
        open_focus_discard_warning_lines=open_focus_discard_warning_lines,
        max_events_skipped=max_events_skipped,
    )


def _merged_audit_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1] + 1:
            last_start, last_end = merged[-1]
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _session_gap_is_explained(
    conn: sqlite3.Connection,
    session_id: int,
    has_action_events: bool,
    spans: list[tuple[int, int, int, int]],
) -> bool:
    """True when every missing seq in the session's shared span falls inside
    a recorded-deletion span (migration 008) AND the total missing count
    fits inside the audited rows_deleted sum (<=, because prefix/suffix
    deletions shrink the observed span instead of leaving holes). The count
    arm keeps a wide span honest: a 2-row audit must not excuse a
    10,000-row loss inside its span. Duplicate seqs are never a recorded
    deletion, and a missing run outside the audited spans still reads as
    possible data loss — all three keep the session in REVIEW. Spans are
    tuples of (seq_min, seq_max, performed_at, rows_deleted), already
    filtered to this session's lifetime by the caller."""
    if not spans:
        return False
    if has_action_events:
        rows = conn.execute(SESSION_SEQS_SQL, (session_id,)).fetchall()
    else:
        rows = conn.execute(EVENTS_ONLY_SESSION_SEQS_SQL, (session_id,)).fetchall()
    seqs = sorted(int(row[0]) for row in rows)
    merged = _merged_audit_spans([(start, end) for start, end, _, _ in spans])
    audited_total = sum(count for _, _, _, count in spans)
    missing_total = 0
    previous: int | None = None
    for seq in seqs:
        if seq == previous:
            return False
        if previous is not None and seq > previous + 1:
            run_start, run_end = previous + 1, seq - 1
            if not any(start <= run_start and run_end <= end for start, end in merged):
                return False
            missing_total += run_end - run_start + 1
        previous = seq
    return missing_total <= audited_total


def review_reasons(review: DatabaseReview, logs: LogSummary | None) -> list[str]:
    """The named reasons behind a REVIEW verdict — the same layered
    categories the dashboard Diagnostics tab shows (DASH-04), so the two
    surfaces can never disagree about why a run needs review."""
    reasons: list[str] = []
    if review.integrity_check != "ok":
        reasons.append(f"integrity={review.integrity_check}")
    if review.foreign_key_issues:
        reasons.append(f"foreign_key_issues={review.foreign_key_issues}")
    if review.seq_gap_sessions:
        joined = ", ".join(str(value) for value in review.seq_gap_sessions)
        reasons.append(f"sequence gaps in sessions {joined}")
    if review.capture_events_dropped < 0:
        reasons.append("capture drop counter unparseable")
    elif review.capture_events_dropped > 0:
        reasons.append(f"capture drops={review.capture_events_dropped}")
    if review.stale_pre_erase_rows_dropped < 0:
        reasons.append("stale pre-erase drop counter unparseable")
    elif review.stale_pre_erase_rows_dropped > 0:
        reasons.append(f"stale pre-erase drops={review.stale_pre_erase_rows_dropped}")
    if logs is not None:
        if logs.unknown_warning_lines:
            reasons.append(f"unknown log warnings={logs.unknown_warning_lines}")
        if logs.error_panic_lines:
            reasons.append(f"log errors/panics={logs.error_panic_lines}")
        if logs.max_events_skipped:
            reasons.append(f"max events skipped={logs.max_events_skipped}")
    return reasons


def format_report(review: DatabaseReview, logs: LogSummary | None) -> str:
    power_suspend = review.power_counts.get("power_suspend", 0)
    power_resume = review.power_counts.get("power_resume", 0)
    power_recovered = review.power_counts.get("power_boundary_recovered", 0)
    process_started = review.process_counts.get("process_started", 0)
    process_exited = review.process_counts.get("process_exited", 0)
    capture_paused = review.pause_counts.get("capture_paused", 0)
    capture_resumed = review.pause_counts.get("capture_resumed", 0)
    open_pauses = max(0, capture_paused - capture_resumed)
    explained_note = (
        "gaps in sessions "
        + ", ".join(str(value) for value in review.explained_gap_sessions)
        + " explained by recorded deletions"
    )
    if review.seq_gap_sessions:
        seq_status = "gaps in sessions " + ", ".join(
            str(value) for value in review.seq_gap_sessions
        )
        if review.explained_gap_sessions:
            seq_status += f"; {explained_note}"
    elif review.explained_gap_sessions:
        seq_status = f"ok ({explained_note})"
    else:
        seq_status = "ok"
    reasons = review_reasons(review, logs)
    status = "PASS" if not reasons else "REVIEW"
    lines = [
        "Gilbreth Run Review",
        f"Status: {status}",
    ]
    if reasons:
        lines.append(f"Reasons: {'; '.join(reasons)}")
    lines += [
        f"DB: {review.db_path}",
        f"SHA256: {review.sha256}",
        (
            f"Size: {_format_bytes(review.size_bytes)} "
            f"(wal {_format_bytes(review.wal_size_bytes)}, "
            f"shm {_format_bytes(review.shm_size_bytes)})"
        ),
        f"SQLite: integrity={review.integrity_check}, foreign_key_issues={review.foreign_key_issues}, user_version={review.user_version}",
        f"Rows: sessions={review.sessions}, open_sessions={review.open_sessions}, events={review.events}, sensitive_rows={review.sensitive_rows}",
        f"Seq continuity: {seq_status}",
        f"Power rows: suspend={power_suspend}, resume={power_resume}, recovered={power_recovered}",
        f"Process rows: started={process_started}, exited={process_exited}",
        (
            "Capture pause rows: "
            f"paused={capture_paused}, resumed={capture_resumed}, open={open_pauses}"
        ),
        f"Recovered focus rows: {review.recovered_focus_rows}",
    ]
    if review.deletion_audit_rows_deleted is not None:
        lines.append(f"Recorded deletions: {review.deletion_audit_rows_deleted} rows")
    lines += [
        f"Clipboard rows: total={review.clipboard_rows}, unavailable={review.clipboard_unavailable_rows}",
        (
            "Capture drops before write: unparseable"
            if review.capture_events_dropped < 0
            else f"Capture drops before write: {review.capture_events_dropped}"
        ),
        (
            "Stale pre-erase rows dropped: unparseable"
            if review.stale_pre_erase_rows_dropped < 0
            else (
                "Stale pre-erase rows dropped: "
                f"{review.stale_pre_erase_rows_dropped}"
            )
        ),
    ]
    if review.min_ts is not None and review.max_ts is not None:
        lines.append(f"Event time span: {review.min_ts} -> {review.max_ts}")
    if logs is not None:
        lines.append(
            f"Logs: files={logs.files}, warnings={logs.warning_lines}, "
            f"unknown_warnings={logs.unknown_warning_lines}, "
            f"errors_or_panics={logs.error_panic_lines}, "
            f"clipboard_locked_warnings={logs.clipboard_locked_warning_lines}, "
            f"orphan_session_repair_warnings={logs.orphan_session_repair_warning_lines}, "
            f"stale_pre_erase_drop_warnings={logs.stale_pre_erase_drop_warning_lines}, "
            f"recovered_focus_warnings={logs.recovered_focus_warning_lines}, "
            f"open_focus_discard_warnings={logs.open_focus_discard_warning_lines}, "
            f"max_events_skipped={logs.max_events_skipped}"
        )
        if logs.files > 1:
            lines.append(
                "  (timestamped log lines are scoped to the event time span; "
                "unparseable log lines are counted)"
            )
    return "\n".join(lines)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is not None
    )


def _meta_int(conn: sqlite3.Connection, key: str) -> int:
    """A missing key is a pre-counter DB and reads as 0 (healthy); an
    unparseable value is a corrupt counter and reads as -1 so the health
    check fails REVIEW instead of silently passing the gate it feeds."""
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row is None:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return -1


def _path_size(path: Path) -> int:
    try:
        return int(path.stat().st_size)
    except FileNotFoundError:
        return 0


def _format_bytes(size: int) -> str:
    units = ("B", "KB", "MB", "GB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _log_line_in_window(
    line: str,
    since_ms: int | None,
    until_ms: int | None,
) -> bool:
    if since_ms is None and until_ms is None:
        return True
    timestamp_ms = _leading_rfc3339_ms(line)
    if timestamp_ms is None:
        return True
    if since_ms is not None and timestamp_ms < since_ms:
        return False
    if until_ms is not None and timestamp_ms > until_ms:
        return False
    return True


def _leading_rfc3339_ms(line: str) -> int | None:
    match = LOG_TIMESTAMP_RE.match(line)
    if match is None:
        return None
    timestamp = match.group("timestamp")
    if timestamp.endswith("Z"):
        timestamp = f"{timestamp[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review a Gilbreth SQLite run/archive without printing captured content.",
    )
    parser.add_argument(
        "db",
        nargs="?",
        type=Path,
        default=default_db_path(),
        help="Path to gilbreth.db or an archive DB.",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=default_logs_dir(),
        help="Gilbreth logs directory to summarize.",
    )
    parser.add_argument(
        "--no-logs",
        action="store_true",
        help="Skip log summary.",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    review = review_database(args.db)
    logs = (
        None
        if args.no_logs
        else review_logs(
            args.logs_dir,
            since_ms=review.min_ts,
            until_ms=review.max_ts,
        )
    )
    print(format_report(review, logs))
    log_health = logs is None or logs.healthy
    return 0 if review.healthy and log_health else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
