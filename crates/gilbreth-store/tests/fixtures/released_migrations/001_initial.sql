CREATE TABLE sessions (
    session_id   INTEGER PRIMARY KEY,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    host         TEXT,
    app_version  TEXT
);

CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL REFERENCES sessions(session_id),
    seq          INTEGER NOT NULL,
    ts           INTEGER NOT NULL,
    source       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    is_sensitive INTEGER NOT NULL DEFAULT 0,
    hwnd         TEXT,
    exe          TEXT,
    title        TEXT,
    pid          INTEGER,
    prev_exe     TEXT,
    prev_title   TEXT,
    key          TEXT,
    mod_shift    INTEGER,
    mod_ctrl     INTEGER,
    mod_alt      INTEGER,
    mod_win      INTEGER,
    button       TEXT,
    pos_x        INTEGER,
    pos_y        INTEGER,
    duration_ms  INTEGER,
    payload      TEXT NOT NULL,
    UNIQUE(session_id, seq)
);

CREATE INDEX idx_events_ts      ON events(ts);
CREATE INDEX idx_events_kind    ON events(kind);
CREATE INDEX idx_events_exe     ON events(exe);
CREATE INDEX idx_events_session ON events(session_id);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
