CREATE TABLE record_requests (
    request_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    status        TEXT    NOT NULL,
    candidate_kind TEXT,
    candidate_json TEXT NOT NULL,
    fulfilled_record_session_id INTEGER,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE record_sessions (
    record_session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id     INTEGER,
    session_id     INTEGER NOT NULL REFERENCES sessions(session_id),
    started_ts     INTEGER NOT NULL,
    ended_ts       INTEGER,
    stop_reason    TEXT,
    title          TEXT,
    policy_snapshot_json TEXT NOT NULL,
    pause_intervals_json TEXT NOT NULL DEFAULT '[]',
    action_count   INTEGER NOT NULL DEFAULT 0,
    safety_cap_ms  INTEGER NOT NULL DEFAULT 1800000,
    visible_indicator INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE selector_paths (
    selector_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    path_hash     TEXT    NOT NULL UNIQUE,
    framework     TEXT    NOT NULL,
    depth         INTEGER NOT NULL,
    path_json     TEXT    NOT NULL,
    leaf_rect     TEXT,
    has_name      INTEGER NOT NULL DEFAULT 0,
    created_ts    INTEGER NOT NULL
);

CREATE TABLE action_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES sessions(session_id),
    seq           INTEGER NOT NULL,
    ts            INTEGER NOT NULL,
    action_type   TEXT    NOT NULL,
    pattern_action TEXT,
    selector_id   INTEGER REFERENCES selector_paths(selector_id),
    trust_basis   TEXT    NOT NULL,
    exe           TEXT,
    is_sensitive  INTEGER NOT NULL DEFAULT 0,
    record_session_id INTEGER NOT NULL REFERENCES record_sessions(record_session_id),
    payload       TEXT NOT NULL,
    UNIQUE(session_id, seq)
);

CREATE INDEX idx_action_events_record_session_seq
    ON action_events(record_session_id, seq);

CREATE INDEX idx_record_requests_status_expires
    ON record_requests(status, expires_at);
