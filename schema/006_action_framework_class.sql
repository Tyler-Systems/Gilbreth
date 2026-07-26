ALTER TABLE action_events
    ADD COLUMN framework_class TEXT NOT NULL DEFAULT 'unknown';
