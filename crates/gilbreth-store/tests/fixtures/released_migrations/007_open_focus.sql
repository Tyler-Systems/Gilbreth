-- Deliberately no sessions FK: a rolled-back binary that predates this
-- table deletes sessions without knowing to delete open_focus first, and a
-- foreign key would fail its secure-erase, archive-reset, and retention
-- transactions. Repair and the writer enforce the session linkage in code.
CREATE TABLE open_focus (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    session_id    INTEGER NOT NULL,
    exe           TEXT,
    started_ts    INTEGER NOT NULL,
    high_water_ts INTEGER NOT NULL
);
