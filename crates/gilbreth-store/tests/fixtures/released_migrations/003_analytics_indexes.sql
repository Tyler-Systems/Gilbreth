CREATE INDEX IF NOT EXISTS idx_events_session_kind_ts_id ON events(session_id, kind, ts, id);
