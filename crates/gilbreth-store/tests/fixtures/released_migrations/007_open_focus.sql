CREATE TABLE open_focus (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    session_id    INTEGER NOT NULL REFERENCES sessions(session_id),
    exe           TEXT,
    started_ts    INTEGER NOT NULL,
    high_water_ts INTEGER NOT NULL
);
