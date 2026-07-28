-- Value-free accounting for every seq-bearing row Gilbreth deletes outside
-- secure erase (dashboard prune, recording delete, per-event delete, startup
-- retention, mouse-move retention): one row per affected session per
-- operation, counts and seq spans only. No content and no event timestamps —
-- the audit must not preserve what the delete removed. The seq-continuity
-- health check uses these spans to tell a recorded deletion from data loss.
-- Deliberately no sessions FK, twice over: audit rows must outlive the
-- sessions they explain (a fully pruned session keeps its accounting), and a
-- rolled-back binary predating this table must keep its secure-erase,
-- archive-reset, and retention transactions working (the 007 open_focus
-- rule). Secure erase deletes this table with everything else.
CREATE TABLE deletion_audit (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,
    performed_at INTEGER NOT NULL,
    session_id   INTEGER NOT NULL,
    rows_deleted INTEGER NOT NULL,
    seq_min      INTEGER NOT NULL,
    seq_max      INTEGER NOT NULL,
    cutoff_ms    INTEGER
);

CREATE INDEX idx_deletion_audit_session ON deletion_audit(session_id);
