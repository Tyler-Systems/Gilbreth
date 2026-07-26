"""Value-free SQLite fixtures shared by operational-tool tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"


def create_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        for schema in (
            "001_initial.sql",
            "002_session_identity.sql",
            "003_analytics_indexes.sql",
            "004_drop_redundant_session_index.sql",
            "005_record_routine.sql",
            "006_action_framework_class.sql",
        ):
            conn.executescript((SCHEMA_DIR / schema).read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()


def insert_session(
    conn: sqlite3.Connection,
    session_id: int,
    *,
    started_at: int,
    ended_at: int | None,
    host: str | None = None,
    app_version: str = "test",
    git_sha: str | None = None,
    run_label: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO sessions (
            session_id, started_at, ended_at, host, app_version, git_sha, run_label
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, started_at, ended_at, host, app_version, git_sha, run_label),
    )


def insert_event(
    conn: sqlite3.Connection,
    event_id: int,
    *,
    session_id: int,
    seq: int,
    ts: int,
    kind: str = "key",
    source: str = "keyboard",
    exe: str | None = None,
    prev_exe: str | None = None,
    title: str | None = None,
    prev_title: str | None = None,
    pid: int | None = None,
    key: str | None = None,
    duration_ms: int | None = None,
    mod_shift: int = 0,
    mod_ctrl: int = 0,
    mod_alt: int = 0,
    mod_win: int = 0,
    button: str | None = None,
    payload: str = "{}",
    is_sensitive: int = 0,
) -> None:
    conn.execute(
        """
        INSERT INTO events (
            id, session_id, seq, ts, source, kind, exe, prev_exe,
            title, prev_title, pid, key, duration_ms, mod_shift, mod_ctrl,
            mod_alt, mod_win, button, payload, is_sensitive
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            session_id,
            seq,
            ts,
            source,
            kind,
            exe,
            prev_exe,
            title,
            prev_title,
            pid,
            key,
            duration_ms,
            mod_shift,
            mod_ctrl,
            mod_alt,
            mod_win,
            button,
            payload,
            is_sensitive,
        ),
    )
