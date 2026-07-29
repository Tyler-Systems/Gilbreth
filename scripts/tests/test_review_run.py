from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from scripts.review_run import format_report, review_database, review_logs
from scripts.tests.db_fixtures import (
    create_db,
    insert_deletion_audit,
    insert_event,
    insert_session,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_review_run_reports_core_database_health(tmp_path: Path) -> None:
    path = tmp_path / "archive.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(
            conn,
            2,
            session_id=1,
            seq=2,
            ts=3_000,
            source="system",
            kind="power_suspend",
        )
        insert_event(
            conn,
            3,
            session_id=1,
            seq=3,
            ts=4_000,
            source="system",
            kind="power_resume",
        )
        insert_event(
            conn,
            4,
            session_id=1,
            seq=4,
            ts=5_000,
            source="system",
            kind="process_started",
            pid=4242,
            exe="C:\\Windows\\System32\\notepad.exe",
            payload='{"kind":"process_started","pid":4242,"exe_source":"full_path"}',
        )
        insert_event(
            conn,
            5,
            session_id=1,
            seq=5,
            ts=6_000,
            source="system",
            kind="capture_paused",
            payload='{"kind":"capture_paused"}',
        )
        insert_event(
            conn,
            6,
            session_id=1,
            seq=6,
            ts=7_000,
            source="system",
            kind="capture_resumed",
            payload='{"kind":"capture_resumed"}',
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is True
    assert len(review.sha256) == 64
    assert review.sessions == 1
    assert review.open_sessions == 0
    assert review.events == 6
    assert review.power_counts == {"power_resume": 1, "power_suspend": 1}
    assert review.process_counts == {"process_started": 1}
    assert review.pause_counts == {"capture_paused": 1, "capture_resumed": 1}
    assert review.clipboard_rows == 0
    assert review.clipboard_unavailable_rows == 0
    assert review.capture_events_dropped == 0
    assert review.stale_pre_erase_rows_dropped == 0
    assert "Status: PASS" in report
    assert "Power rows: suspend=1, resume=1, recovered=0" in report
    assert "Process rows: started=1, exited=0" in report
    assert "Capture pause rows: paused=1, resumed=1, open=0" in report
    assert "Capture drops before write: 0" in report
    assert "Stale pre-erase rows dropped: 0" in report
    assert "notepad" not in report.lower()


def test_review_verdict_names_its_reasons(tmp_path: Path) -> None:
    """DASH-04: a REVIEW must say why, in the same category vocabulary the
    dashboard Diagnostics tab uses — and a PASS carries no Reasons line."""
    path = tmp_path / "reasons.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=3, ts=3_000)
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_events_dropped', '5')"
        )
        conn.commit()
    finally:
        conn.close()

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-07-09").write_text(
        "2026-07-09T10:00:00Z  WARN something unrecognized\n",
        encoding="utf-8",
    )

    review = review_database(path)
    report = format_report(review, review_logs(logs_dir))

    assert "Status: REVIEW" in report
    assert (
        "Reasons: sequence gaps in sessions 1; capture drops=5; "
        "unknown log warnings=1" in report
    )

    healthy_path = tmp_path / "healthy.db"
    create_db(healthy_path)
    conn = sqlite3.connect(healthy_path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        conn.commit()
    finally:
        conn.close()
    healthy_report = format_report(review_database(healthy_path), logs=None)
    assert "Status: PASS" in healthy_report
    assert "Reasons:" not in healthy_report


def test_review_run_flags_sequence_gaps(tmp_path: Path) -> None:
    path = tmp_path / "gap.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=3, ts=3_000)
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)

    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)
    assert "Seq continuity: gaps in sessions 1" in format_report(review, logs=None)


def test_review_run_counts_record_routine_actions_in_sequence_continuity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "record-routine-sequence.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=5, ts=6_000)
        conn.execute("""
            INSERT INTO record_sessions (
                record_session_id, session_id, started_ts, ended_ts,
                stop_reason, policy_snapshot_json, action_count
            )
            VALUES (1, 1, 2500, 5500, 'user_stop', '{}', 3)
            """)
        conn.executemany(
            """
            INSERT INTO action_events (
                session_id, seq, ts, action_type, trust_basis,
                record_session_id, payload
            )
            VALUES (1, ?, ?, 'invoke', 'pid_match', 1, '{}')
            """,
            ((2, 3_000), (3, 4_000), (4, 5_000)),
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is True
    assert review.seq_gap_sessions == ()

    conn = sqlite3.connect(path)
    try:
        conn.execute("DELETE FROM action_events WHERE session_id = 1 AND seq = 3")
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)

    conn = sqlite3.connect(path)
    try:
        # A cross-table duplicate restores COUNT(*) to the seq span while the
        # real gap at seq 3 remains. Continuity must still fail.
        insert_event(conn, 3, session_id=1, seq=2, ts=3_500)
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)


def test_review_run_checks_action_only_surviving_sessions(tmp_path: Path) -> None:
    path = tmp_path / "action-only-sequence.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        conn.execute("""
            INSERT INTO record_sessions (
                record_session_id, session_id, started_ts, ended_ts,
                stop_reason, policy_snapshot_json, action_count
            )
            VALUES (1, 1, 2000, 6000, 'user_stop', '{}', 3)
            """)
        conn.executemany(
            """
            INSERT INTO action_events (
                session_id, seq, ts, action_type, trust_basis,
                record_session_id, payload
            )
            VALUES (1, ?, ?, 'invoke', 'pid_match', 1, '{}')
            """,
            ((7, 3_000), (8, 4_000), (9, 5_000)),
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is True
    assert review.seq_gap_sessions == ()

    conn = sqlite3.connect(path)
    try:
        conn.execute("DELETE FROM action_events WHERE session_id = 1 AND seq = 8")
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)


def test_review_run_uses_events_only_for_pre_record_routine_databases(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-sequence.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute("DROP TABLE action_events")
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=3, ts=3_000)
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)


def test_review_run_classifies_audited_gaps_as_explained(tmp_path: Path) -> None:
    """A seq hole fully covered by recorded deletions (migration 008) is a
    known deletion, not data loss: the DB passes and the report says why."""
    path = tmp_path / "explained-gap.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=5, ts=6_000)
        insert_deletion_audit(
            conn,
            kind="mouse_move_retention",
            performed_at=20_000,
            session_id=1,
            rows_deleted=3,
            seq_min=2,
            seq_max=4,
            cutoff_ms=15_000,
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is True
    assert review.seq_gap_sessions == ()
    assert review.explained_gap_sessions == (1,)
    assert review.deletion_audit_rows_deleted == 3
    assert "Status: PASS" in report
    assert (
        "Seq continuity: ok (gaps in sessions 1 explained by recorded deletions)"
        in report
    )
    assert "Recorded deletions: 3 rows" in report


def test_review_run_keeps_unaudited_and_partially_audited_gaps_in_review(
    tmp_path: Path,
) -> None:
    """One session's hole is audited, the other session's is not — and a
    hole reaching past the audited span stays REVIEW too."""
    path = tmp_path / "mixed-gaps.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=5, ts=6_000)
        insert_deletion_audit(
            conn,
            kind="event_delete",
            performed_at=20_000,
            session_id=1,
            rows_deleted=3,
            seq_min=2,
            seq_max=4,
        )
        insert_session(conn, 2, started_at=1_000, ended_at=10_000)
        insert_event(conn, 3, session_id=2, seq=1, ts=2_000)
        insert_event(conn, 4, session_id=2, seq=3, ts=3_000)
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is False
    assert review.seq_gap_sessions == (2,)
    assert review.explained_gap_sessions == (1,)
    assert "Status: REVIEW" in report
    assert "Reasons: sequence gaps in sessions 2" in report
    assert (
        "Seq continuity: gaps in sessions 2; "
        "gaps in sessions 1 explained by recorded deletions" in report
    )

    conn = sqlite3.connect(path)
    try:
        # Session 1's hole now reaches seq 6, past the audited [2, 4] span:
        # partially explained is still possible data loss.
        conn.execute("UPDATE events SET seq = 7 WHERE id = 2")
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.seq_gap_sessions == (1, 2)
    assert review.explained_gap_sessions == ()


def test_review_run_never_explains_duplicate_seqs_by_deletion_audit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate-seq.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=2, ts=3_000)
        # A cross-table duplicate: an action_events row reusing seq 2 (the
        # same shape the record-routine continuity test pins).
        conn.execute("""
            INSERT INTO record_sessions (
                record_session_id, session_id, started_ts, ended_ts,
                stop_reason, policy_snapshot_json, action_count
            )
            VALUES (1, 1, 2500, 5500, 'user_stop', '{}', 1)
            """)
        conn.execute("""
            INSERT INTO action_events (
                session_id, seq, ts, action_type, trust_basis,
                record_session_id, payload
            )
            VALUES (1, 2, 3500, 'invoke', 'pid_match', 1, '{}')
            """)
        # Even a blanket audit span cannot explain a duplicate: deletions
        # remove rows, they never mint two rows with one seq.
        insert_deletion_audit(
            conn,
            kind="dashboard_prune",
            performed_at=20_000,
            session_id=1,
            rows_deleted=10,
            seq_min=0,
            seq_max=100,
            cutoff_ms=15_000,
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.healthy is False
    assert review.seq_gap_sessions == (1,)
    assert review.explained_gap_sessions == ()


def test_review_run_merges_adjacent_audit_spans_across_batches(
    tmp_path: Path,
) -> None:
    """A multi-batch prune audits one operation as adjacent per-batch spans;
    a missing run crossing the batch boundary is still explained. Spans that
    leave uncovered seqs between them are not a union."""
    path = tmp_path / "batch-spans.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=8, ts=6_000)
        for seq_min, seq_max in ((2, 4), (5, 7)):
            insert_deletion_audit(
                conn,
                kind="mouse_move_retention",
                performed_at=20_000,
                session_id=1,
                rows_deleted=3,
                seq_min=seq_min,
                seq_max=seq_max,
                cutoff_ms=15_000,
            )
        insert_session(conn, 2, started_at=1_000, ended_at=10_000)
        insert_event(conn, 3, session_id=2, seq=1, ts=2_000)
        insert_event(conn, 4, session_id=2, seq=8, ts=6_000)
        for seq_min, seq_max in ((2, 3), (6, 7)):
            insert_deletion_audit(
                conn,
                kind="mouse_move_retention",
                performed_at=20_000,
                session_id=2,
                rows_deleted=3,
                seq_min=seq_min,
                seq_max=seq_max,
                cutoff_ms=15_000,
            )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)

    assert review.explained_gap_sessions == (1,)
    # Session 2's seqs 4 and 5 are covered by neither span: not a union.
    assert review.seq_gap_sessions == (2,)


def test_review_run_count_arm_keeps_wide_audit_spans_honest(
    tmp_path: Path,
) -> None:
    """Containment alone would let a 2-row audit excuse a 100-row loss
    inside its span; the missing count must also fit the audited sum.
    Prefix-trim slack (audited > missing) stays explained."""
    path = tmp_path / "count-arm.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=102, ts=6_000)
        insert_deletion_audit(
            conn,
            kind="event_delete",
            performed_at=20_000,
            session_id=1,
            rows_deleted=2,
            seq_min=2,
            seq_max=101,
        )
        insert_session(conn, 2, started_at=1_000, ended_at=10_000)
        insert_event(conn, 3, session_id=2, seq=5, ts=2_000)
        insert_event(conn, 4, session_id=2, seq=7, ts=6_000)
        # A dashboard prune trimmed seqs 0-4 (a prefix, invisible to the
        # gap check) plus seq 6: audited 50 covers the 1 observed missing.
        insert_deletion_audit(
            conn,
            kind="dashboard_prune",
            performed_at=20_000,
            session_id=2,
            rows_deleted=50,
            seq_min=0,
            seq_max=6,
            cutoff_ms=15_000,
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)

    assert review.seq_gap_sessions == (1,)
    assert review.explained_gap_sessions == (2,)


def test_review_run_discards_audit_spans_from_before_the_session_began(
    tmp_path: Path,
) -> None:
    """Pre-erase residue: a v0.1.1 rollback erases without knowing
    deletion_audit, and session ids restart — a span stamped before this
    session began must not explain its gaps."""
    path = tmp_path / "stale-span.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=5, ts=6_000)
        insert_deletion_audit(
            conn,
            kind="mouse_move_retention",
            performed_at=500,
            session_id=1,
            rows_deleted=3,
            seq_min=2,
            seq_max=4,
            cutoff_ms=400,
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.seq_gap_sessions == (1,)
    assert review.explained_gap_sessions == ()

    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE deletion_audit SET performed_at = 2000")
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    assert review.seq_gap_sessions == ()
    assert review.explained_gap_sessions == (1,)


def test_review_run_treats_a_pre_audit_database_as_unexplained(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pre-audit.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute("DROP TABLE deletion_audit")
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        insert_event(conn, 2, session_id=1, seq=3, ts=3_000)
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.deletion_audit_rows_deleted is None
    assert review.seq_gap_sessions == (1,)
    assert review.explained_gap_sessions == ()
    assert "Recorded deletions:" not in report


def test_review_run_explains_an_orphan_pause_without_marking_it_unhealthy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-pause.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(
            conn,
            1,
            session_id=1,
            seq=1,
            ts=2_000,
            source="system",
            kind="capture_paused",
            payload='{"kind":"capture_paused"}',
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is True
    assert "Status: PASS" in report
    assert "Capture pause rows: paused=1, resumed=0, open=1" in report


def test_review_run_reports_recovered_focus_rows_without_marking_them_unhealthy(
    tmp_path: Path,
) -> None:
    """A crash-repaired focus row is a reconstructed dwell, reported
    explicitly (foreground-heartbeat design, decision 5) but healthy: the
    repair is the system working as designed after an ungraceful end."""
    path = tmp_path / "recovered.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=40_000)
        insert_event(
            conn,
            1,
            session_id=1,
            seq=1,
            ts=40_000,
            source="foreground",
            kind="focus_changed",
            payload=(
                '{"kind":"focus_changed","window":{"hwnd":0,"exe":"","title":"","pid":0},'
                '"prev":{"hwnd":0,"exe":"","title":"","pid":0},'
                '"previous_focused_for_ms":30000,"window_unfocused_for_ms":0,'
                '"recovered":true}'
            ),
        )
        insert_event(
            conn,
            2,
            session_id=1,
            seq=2,
            ts=41_000,
            source="foreground",
            kind="focus_changed",
            payload=(
                '{"kind":"focus_changed","window":{"hwnd":1,"exe":"","title":"","pid":1},'
                '"prev":null,"previous_focused_for_ms":0,"window_unfocused_for_ms":0}'
            ),
        )
        conn.commit()
    finally:
        conn.close()

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log").write_text(
        "2026-07-28T09:00:00Z  WARN recovered an open focus segment from an "
        "ungraceful shutdown session_id=1 recovered_ms=30000\n",
        encoding="utf-8",
    )

    review = review_database(path)
    logs = review_logs(logs_dir)
    report = format_report(review, logs)

    assert review.recovered_focus_rows == 1
    assert review.healthy is True
    assert logs.recovered_focus_warning_lines == 1
    assert logs.unknown_warning_lines == 0
    assert logs.healthy is True
    assert "Status: PASS" in report
    assert "Recovered focus rows: 1" in report
    assert "recovered_focus_warnings=1" in report


def test_review_run_classifies_an_open_focus_discard_as_known(tmp_path: Path) -> None:
    """The discard fires on the ordinary rollback-return path (an older
    build stamped the crashed session's end while leaving the heartbeat row
    behind), so it must read as a known category, not an unknown-warning
    REVIEW."""
    path = tmp_path / "discard.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        conn.commit()
    finally:
        conn.close()

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log").write_text(
        "2026-07-28T09:00:00Z  WARN discarded an open-focus row whose session "
        "already ended; no dwell synthesized session_id=1\n",
        encoding="utf-8",
    )

    review = review_database(path)
    logs = review_logs(logs_dir)
    report = format_report(review, logs)

    assert logs.open_focus_discard_warning_lines == 1
    assert logs.unknown_warning_lines == 0
    assert logs.healthy is True
    assert "Status: PASS" in report
    assert "open_focus_discard_warnings=1" in report


def test_review_run_flags_capture_events_dropped(tmp_path: Path) -> None:
    path = tmp_path / "capture-drops.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_events_dropped', '5')"
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is False
    assert review.capture_events_dropped == 5
    assert "Status: REVIEW" in report
    assert "Capture drops before write: 5" in report


def test_review_run_flags_unparseable_capture_drop_counter(tmp_path: Path) -> None:
    path = tmp_path / "capture-drops-corrupt.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('capture_events_dropped', 'not-a-count')"
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is False
    assert "Status: REVIEW" in report
    assert "Capture drops before write: unparseable" in report


def test_review_run_flags_named_stale_pre_erase_drop_counter(tmp_path: Path) -> None:
    path = tmp_path / "stale-pre-erase-drops.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=10_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=2_000)
        conn.execute(
            "INSERT INTO meta (key, value) "
            "VALUES ('stale_pre_erase_rows_dropped', '2')"
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.healthy is False
    assert review.stale_pre_erase_rows_dropped == 2
    assert "Status: REVIEW" in report
    assert "Reasons: stale pre-erase drops=2" in report
    assert "Stale pre-erase rows dropped: 2" in report


def test_review_logs_summarizes_issues_without_printing_content(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-06-07").write_text(
        "\n".join(
            [
                "INFO writer heartbeat events_skipped=0",
                "WARN something happened",
                "ERROR writer failed events_skipped=2",
                "writer thread panicked",
            ]
        ),
        encoding="utf-8",
    )

    summary = review_logs(logs_dir)

    assert summary.files == 1
    assert summary.issue_lines == 3
    assert summary.warning_lines == 1
    assert summary.unknown_warning_lines == 1
    assert summary.error_panic_lines == 2
    assert summary.clipboard_locked_warning_lines == 0
    assert summary.orphan_session_repair_warning_lines == 0
    assert summary.stale_pre_erase_drop_warning_lines == 0
    assert summary.max_events_skipped == 2
    assert summary.healthy is False


def test_review_logs_classifies_clipboard_locked_warning_noise(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-06-15").write_text(
        "\n".join(
            [
                "WARN gilbreth_capture_windows: clipboard changed but metadata was unavailable; clipboard is locked",
                "WARN gilbreth_capture_windows: clipboard changed but metadata was unavailable; clipboard is locked",
                "INFO writer heartbeat events_skipped=0",
            ]
        ),
        encoding="utf-8",
    )

    summary = review_logs(logs_dir)
    report = format_report(review_database(_healthy_db(tmp_path)), summary)

    assert summary.issue_lines == 2
    assert summary.warning_lines == 2
    assert summary.unknown_warning_lines == 0
    assert summary.error_panic_lines == 0
    assert summary.clipboard_locked_warning_lines == 2
    assert summary.orphan_session_repair_warning_lines == 0
    assert summary.max_events_skipped == 0
    assert summary.healthy is True
    assert "Status: PASS" in report
    assert "unknown_warnings=0" in report
    assert "clipboard_locked_warnings=2" in report
    assert "orphan_session_repair_warnings=0" in report


def test_review_logs_classifies_orphan_repair_warning_as_known(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-06-19").write_text(
        "\n".join(
            [
                "WARN gilbreth_store: previous session(s) ended without graceful stop orphan_sessions_finalized=1",
                "INFO writer heartbeat events_skipped=0",
            ]
        ),
        encoding="utf-8",
    )

    summary = review_logs(logs_dir)
    report = format_report(review_database(_healthy_db(tmp_path)), summary)

    assert summary.issue_lines == 1
    assert summary.warning_lines == 1
    assert summary.unknown_warning_lines == 0
    assert summary.error_panic_lines == 0
    assert summary.clipboard_locked_warning_lines == 0
    assert summary.orphan_session_repair_warning_lines == 1
    assert summary.max_events_skipped == 0
    assert summary.healthy is True
    assert "Status: PASS" in report
    assert "unknown_warnings=0" in report
    assert "orphan_session_repair_warnings=1" in report


def test_review_logs_unknown_warning_marks_report_for_review(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-06-15").write_text(
        "\n".join(
            [
                "WARN gilbreth_store: unexpected long-run condition",
                "INFO writer heartbeat events_skipped=0",
            ]
        ),
        encoding="utf-8",
    )

    summary = review_logs(logs_dir)
    report = format_report(review_database(_healthy_db(tmp_path)), summary)

    assert summary.warning_lines == 1
    assert summary.unknown_warning_lines == 1
    assert summary.orphan_session_repair_warning_lines == 0
    assert summary.healthy is False
    assert "Status: REVIEW" in report
    assert "unknown_warnings=1" in report


def test_review_logs_classifies_stale_pre_erase_drop_under_named_counter(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-07-12").write_text(
        "WARN gilbreth_store: dropped stale pre-erase capture row ",
        encoding="utf-8",
    )

    summary = review_logs(logs_dir)

    assert summary.warning_lines == 1
    assert summary.stale_pre_erase_drop_warning_lines == 1
    assert summary.unknown_warning_lines == 0
    assert summary.healthy is True


def test_review_logs_scopes_timestamped_lines_to_event_window(
    tmp_path: Path,
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "gilbreth.log.2026-06-15").write_text(
        "\n".join(
            [
                "1970-01-01T00:00:00.999Z WARN previous run warning",
                "1970-01-01T00:00:01.500Z WARN in-window warning",
                "1970-01-01T00:00:01.700+00:00 INFO writer heartbeat events_skipped=3",
                "1970-01-01T00:00:02.001Z ERROR next run failure",
                "WARN unparseable timestamp stays in scope",
            ]
        ),
        encoding="utf-8",
    )

    summary = review_logs(logs_dir, since_ms=1_000, until_ms=2_000)

    assert summary.warning_lines == 2
    assert summary.unknown_warning_lines == 2
    assert summary.error_panic_lines == 0
    assert summary.max_events_skipped == 3


def test_review_database_counts_unavailable_clipboard_rows(tmp_path: Path) -> None:
    path = _healthy_db(tmp_path)
    conn = sqlite3.connect(path)
    try:
        insert_event(
            conn,
            2,
            session_id=1,
            seq=2,
            ts=1_600,
            source="system",
            kind="clipboard_used",
            payload='{"kind":"clipboard_used","format_kind":"unavailable"}',
        )
        insert_event(
            conn,
            3,
            session_id=1,
            seq=3,
            ts=1_700,
            source="system",
            kind="clipboard_used",
            payload='{"kind":"clipboard_used","format_kind":"text"}',
        )
        conn.commit()
    finally:
        conn.close()

    review = review_database(path)
    report = format_report(review, logs=None)

    assert review.clipboard_rows == 2
    assert review.clipboard_unavailable_rows == 1
    assert "Clipboard rows: total=2, unavailable=1" in report


def _healthy_db(tmp_path: Path) -> Path:
    path = tmp_path / "healthy.db"
    create_db(path)
    conn = sqlite3.connect(path)
    try:
        insert_session(conn, 1, started_at=1_000, ended_at=2_000)
        insert_event(conn, 1, session_id=1, seq=1, ts=1_500)
        conn.commit()
    finally:
        conn.close()
    return path


def _health_dump(logs_dir: Path, since_ms: int | None, until_ms: int | None) -> dict:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "gilbreth-app",
            "--features",
            "dev-health-dump",
            "--bin",
            "gilbreth-health-dump",
            "--",
            str(logs_dir),
            str(since_ms) if since_ms is not None else "-",
            str(until_ms) if until_ms is not None else "-",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _utc_ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="pins Windows glob case semantics against the native classifier",
)
def test_review_logs_matches_the_native_health_classifier(tmp_path: Path) -> None:
    """B2 (2026-07-09 S4 review): scripts/review_run.py and the native
    DASH-04 log classifier must agree over the same corpus — including a
    case-varied Windows rename, which only reaches both verdicts through
    case-insensitive filename matching."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "gilbreth.log").write_text(
        "2026-07-09T10:00:00Z  WARN gilbreth_app: unknown warning\n"
        "2026-07-09T10:00:01Z  WARN clipboard changed but metadata was "
        "unavailable; clipboard is locked\n"
        "2026-07-09T10:00:02Z  WARN gilbreth_store: previous session(s) "
        "ended without graceful stop orphan_sessions_finalized=2\n"
        "2026-07-09T10:00:03Z ERROR gilbreth_store: write failed\n"
        "thread 'main' panicked at src/main.rs:10\n"
        "writer report events_skipped=4 batches=1\n"
        "2026-07-01T09:00:00Z  WARN before the event window\n",
        encoding="utf-8",
    )
    # The B2 corpus: a valid Windows rename differing only in case still
    # carries its error into the verdict.
    (logs / "GILBRETH.LOG.OLD").write_text("ERROR renamed log\n", encoding="utf-8")
    # Undecodable bytes never stop the review on either side.
    (logs / "gilbreth.log.1").write_bytes(
        b"2026-07-09T11:00:00Z  WARN bad \xff\xfe bytes\nevents_skipped=2\n"
    )
    (logs / "unrelated.txt").write_text("ERROR ignored\n", encoding="utf-8")

    windows = (
        (None, None),
        (_utc_ms("2026-07-09T00:00:00Z"), _utc_ms("2026-07-10T00:00:00Z")),
    )
    for since_ms, until_ms in windows:
        expected = review_logs(logs, since_ms=since_ms, until_ms=until_ms)
        native = _health_dump(logs, since_ms, until_ms)
        assert native == {
            "files": expected.files,
            "warning_lines": expected.warning_lines,
            "error_panic_lines": expected.error_panic_lines,
            "clipboard_locked_warning_lines": expected.clipboard_locked_warning_lines,
            "orphan_session_repair_warning_lines": (
                expected.orphan_session_repair_warning_lines
            ),
            "stale_pre_erase_drop_warning_lines": (
                expected.stale_pre_erase_drop_warning_lines
            ),
            "max_events_skipped": expected.max_events_skipped,
            "unknown_warning_lines": expected.unknown_warning_lines,
            "healthy": expected.unknown_warning_lines == 0
            and expected.error_panic_lines == 0
            and expected.max_events_skipped == 0,
        }, (since_ms, until_ms)

    # The mixed-case rename is inside the corpus on both sides: three files,
    # and its error keeps the verdict at REVIEW even in the scoped window.
    full = review_logs(logs)
    assert full.files == 3
    assert full.error_panic_lines == 3
