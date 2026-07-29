use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crossbeam_channel::{never, select, tick, Receiver, Sender};
use gilbreth_core::{
    u64_to_i64, unix_now_ms, ActionCapture, ActionPayload, ActionType, AutomationAction, Captured,
    DiagnosticsCounters, DriftCorrection, EventEnvelope, EventPayload, FrameworkClass, Policy,
    RecordRequestStatus, RecordStopReason, SelectorPath, SelectorTrustBasis, Sequencer,
    SessionTimebase, Source, StampedAction, StopToken, WindowRef, WriterInput,
    EXCLUDED_APP_GAP_PATTERN, SCHEMA_VERSION,
};
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension};
use rusqlite_migration::{Migrations, M};
use thiserror::Error;
use tracing::{debug, error, info, warn};

mod archive;

pub use archive::{
    export_passphrase_archive, export_plaintext_archive, inventory_archives, read_archive_header,
    unseal_archive_to, verify_archive, ArchiveCredential, ArchiveEncryptionReceipt, ArchiveError,
    ArchiveHeader, ArchiveInventory, ArchiveKeyWrap, ArchiveProtection, ArchiveProvenance,
    PlaintextExportAcknowledgement, ARCHIVE_EXTENSION, ARCHIVE_FORMAT_VERSION, ARCHIVE_MAGIC,
    DPAPI_ARCHIVE_RECEIPT, DPAPI_DURABILITY_NOTICE,
};

const SCHEMA_SQL: &str = include_str!("../../../schema/001_initial.sql");
const SESSION_IDENTITY_SQL: &str = include_str!("../../../schema/002_session_identity.sql");
const ANALYTICS_INDEXES_SQL: &str = include_str!("../../../schema/003_analytics_indexes.sql");
const DROP_REDUNDANT_SESSION_INDEX_SQL: &str =
    include_str!("../../../schema/004_drop_redundant_session_index.sql");
const RECORD_ROUTINE_SQL: &str = include_str!("../../../schema/005_record_routine.sql");
const ACTION_FRAMEWORK_CLASS_SQL: &str =
    include_str!("../../../schema/006_action_framework_class.sql");
const OPEN_FOCUS_SQL: &str = include_str!("../../../schema/007_open_focus.sql");
const DELETION_AUDIT_SQL: &str = include_str!("../../../schema/008_deletion_audit.sql");
/// Shared by the writer's batched insert and open-focus crash repair so a
/// synthesized row can never drift from the live column mapping.
const INSERT_EVENT_SQL: &str = "INSERT INTO events (
    session_id, seq, ts, source, kind, is_sensitive,
    hwnd, exe, title, pid, prev_exe, prev_title,
    key, mod_shift, mod_ctrl, mod_alt, mod_win,
    button, pos_x, pos_y, duration_ms, payload
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6,
    ?7, ?8, ?9, ?10, ?11, ?12,
    ?13, ?14, ?15, ?16, ?17,
    ?18, ?19, ?20, ?21, ?22
)";
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10 * 60);
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);
const DAY_MS: i64 = 86_400_000;
const SHUTDOWN_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const WRITER_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WRITER_SHUTDOWN_DRAIN_QUIET_PERIOD: Duration = Duration::from_millis(250);
const DEFAULT_TIMEBASE_DRIFT_THRESHOLD_MS: i64 = 1_000;
const DEFAULT_STALE_EVENT_WARN_AFTER: Duration = Duration::from_secs(30 * 60);
const SQLITE_BUSY_RETRY_ATTEMPTS: usize = 12;
#[cfg(not(test))]
const SQLITE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(250);
#[cfg(test)]
const SQLITE_BUSY_RETRY_DELAY: Duration = Duration::ZERO;

#[cfg(test)]
static INJECTED_ARCHIVE_VERIFICATION_FAILURES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("archive failed verification; nothing was reset: {0}")]
    ArchiveVerification(String),
    #[error("archive plaintext staging cleanup failed; nothing was reset: {0}")]
    ArchiveStagingCleanup(String),
    #[cfg(windows)]
    #[error("LOCALAPPDATA is not set")]
    MissingLocalAppData,
    #[cfg(target_os = "macos")]
    #[error("HOME is not set")]
    MissingHome,
    #[error("record routine error: {0}")]
    RecordRoutine(String),
    #[error("writer thread disconnected")]
    Disconnected,
}

pub struct GilbrethStore {
    conn: Connection,
    path: PathBuf,
}

struct SqliteStopInterrupt {
    done: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SqliteStopInterrupt {
    fn new(conn: &Connection, stop: StopToken) -> Self {
        let interrupt = conn.get_interrupt_handle();
        let done = Arc::new(AtomicBool::new(false));
        let thread_done = done.clone();
        let handle = thread::spawn(move || {
            while !thread_done.load(Ordering::SeqCst) {
                if stop.is_cancelled() {
                    interrupt.interrupt();
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            done,
            handle: Some(handle),
        }
    }
}

impl Drop for SqliteStopInterrupt {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                warn!("sqlite stop interrupt watcher panicked");
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub app_version: String,
    pub host: Option<String>,
    pub git_sha: Option<String>,
    pub run_label: Option<String>,
}

impl SessionIdentity {
    pub fn new(app_version: impl Into<String>) -> Self {
        Self {
            app_version: app_version.into(),
            host: None,
            git_sha: None,
            run_label: None,
        }
    }

    pub fn with_host(mut self, host: Option<String>) -> Self {
        self.host = non_empty(host);
        self
    }

    pub fn with_git_sha(mut self, git_sha: impl Into<String>) -> Self {
        self.git_sha = non_empty(Some(git_sha.into()));
        self
    }

    pub fn with_run_label(mut self, run_label: Option<String>) -> Self {
        self.run_label = non_empty(run_label);
        self
    }
}

impl GilbrethStore {
    #[cfg(any(windows, target_os = "macos"))]
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(default_db_path()?)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut conn = Connection::open(path)?;
        apply_pragmas(&conn)?;
        migrate(&mut conn)?;
        ensure_meta_identity(&conn, unix_now_ms())?;
        // Before the orphan stamp: the synthesized row's high-water
        // timestamp becomes the crashed session's MAX(events.ts). A repair
        // failure must not brick startup — discard the row best-effort and
        // continue; losing the crashed dwell is the safe direction.
        if let Err(error) = repair_open_focus(&conn) {
            warn!(%error, "open-focus repair failed; discarding the row");
            let _ = conn.execute("DELETE FROM open_focus", []);
        }
        finalize_orphan_sessions(&conn)?;
        finalize_orphan_record_sessions(&conn)?;
        reconcile_confirmed_record_requests(&conn, unix_now_ms())?;

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn create_session(&self, started_at: i64, app_version: &str) -> Result<i64, StoreError> {
        self.create_session_with_identity(started_at, &SessionIdentity::new(app_version))
    }

    pub fn create_session_with_identity(
        &self,
        started_at: i64,
        identity: &SessionIdentity,
    ) -> Result<i64, StoreError> {
        self.conn.execute(
            "
            INSERT INTO sessions (started_at, host, app_version, git_sha, run_label)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ",
            params![
                started_at,
                identity.host.as_deref(),
                identity.app_version.as_str(),
                identity.git_sha.as_deref(),
                identity.run_label.as_deref(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn end_session(&self, session_id: i64, ended_at: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE sessions SET ended_at = ?1 WHERE session_id = ?2",
            params![ended_at, session_id],
        )?;
        Ok(())
    }

    /// Write or advance the single `open_focus` row (`CHECK (id = 1)` keeps
    /// it single by construction). Only the writer's beat calls this.
    fn upsert_open_focus(
        &self,
        session_id: i64,
        exe: &str,
        started_ts: i64,
        high_water_ts: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO open_focus (id, session_id, exe, started_ts, high_water_ts) \
             VALUES (1, ?1, ?2, ?3, ?4) \
             ON CONFLICT(id) DO UPDATE SET \
                 session_id = excluded.session_id, \
                 exe = excluded.exe, \
                 started_ts = excluded.started_ts, \
                 high_water_ts = excluded.high_water_ts",
            params![session_id, exe, started_ts, high_water_ts],
        )?;
        Ok(())
    }

    fn delete_open_focus(&self) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM open_focus", [])?;
        Ok(())
    }

    pub fn create_record_request(
        &self,
        requested_at: i64,
        expires_at: i64,
        candidate_kind: Option<&str>,
        candidate_json: &str,
    ) -> Result<i64, StoreError> {
        ensure_value_free_json(candidate_json, "candidate_json")?;
        self.conn.execute(
            "
            INSERT INTO record_requests (
                requested_at, expires_at, status, candidate_kind, candidate_json, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?1)
            ",
            params![
                requested_at,
                expires_at,
                RecordRequestStatus::Requested.as_str(),
                candidate_kind,
                candidate_json,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn confirm_record_request(
        &self,
        request_id: i64,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "
            UPDATE record_requests
               SET status = ?1, updated_at = ?2
             WHERE request_id = ?3
               AND status = ?4
            ",
            params![
                RecordRequestStatus::Confirmed.as_str(),
                updated_at,
                request_id,
                RecordRequestStatus::Requested.as_str(),
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::RecordRoutine(format!(
                "record request {request_id} is not requestable"
            )));
        }
        Ok(())
    }

    pub fn cancel_record_request(
        &self,
        request_id: i64,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "
            UPDATE record_requests
               SET status = ?1, updated_at = ?2
             WHERE request_id = ?3
               AND status IN (?4, ?5)
            ",
            params![
                RecordRequestStatus::Cancelled.as_str(),
                updated_at,
                request_id,
                RecordRequestStatus::Requested.as_str(),
                RecordRequestStatus::Confirmed.as_str(),
            ],
        )?;
        Ok(())
    }

    pub fn fail_record_request(&self, request_id: i64, updated_at: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "
            UPDATE record_requests
               SET status = ?1, updated_at = ?2
             WHERE request_id = ?3
               AND status IN (?4, ?5)
            ",
            params![
                RecordRequestStatus::Failed.as_str(),
                updated_at,
                request_id,
                RecordRequestStatus::Requested.as_str(),
                RecordRequestStatus::Confirmed.as_str(),
            ],
        )?;
        Ok(())
    }

    pub fn expire_record_requests(&self, now_ms: i64) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "
            UPDATE record_requests
               SET status = ?1, updated_at = ?2
             WHERE status = ?3
               AND expires_at < ?2
            ",
            params![
                RecordRequestStatus::Expired.as_str(),
                now_ms,
                RecordRequestStatus::Requested.as_str(),
            ],
        )?)
    }

    pub fn oldest_pending_record_request(
        &self,
        now_ms: i64,
    ) -> Result<Option<PendingRecordRequest>, StoreError> {
        match self.conn.query_row(
            "
            SELECT request_id, candidate_kind, candidate_json, expires_at
              FROM record_requests
             WHERE status = ?1
               AND expires_at >= ?2
             ORDER BY requested_at ASC, request_id ASC
             LIMIT 1
            ",
            params![RecordRequestStatus::Requested.as_str(), now_ms],
            |row| {
                Ok(PendingRecordRequest {
                    request_id: row.get(0)?,
                    candidate_kind: row.get(1)?,
                    candidate_json: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        ) {
            Ok(request) => Ok(Some(request)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(StoreError::Sqlite(error)),
        }
    }

    pub fn open_record_session(
        &mut self,
        params: OpenRecordSessionParams<'_>,
    ) -> Result<i64, StoreError> {
        ensure_value_free_json(params.policy_snapshot_json, "policy_snapshot_json")?;
        if params.safety_cap_ms <= 0 {
            return Err(StoreError::RecordRoutine(
                "safety_cap_ms must be positive".to_string(),
            ));
        }

        let tx = self.conn.transaction()?;
        tx.execute(
            "
            INSERT INTO record_sessions (
                request_id, session_id, started_ts, title, policy_snapshot_json,
                safety_cap_ms, visible_indicator
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                params.request_id,
                params.session_id,
                params.started_ts,
                params.title,
                params.policy_snapshot_json,
                params.safety_cap_ms,
                bool_i64(params.visible_indicator),
            ],
        )?;
        let record_session_id = tx.last_insert_rowid();
        if let Some(request_id) = params.request_id {
            let changed = tx.execute(
                "
                UPDATE record_requests
                   SET status = ?1,
                       fulfilled_record_session_id = ?2,
                       updated_at = ?3
                 WHERE request_id = ?4
                   AND status = ?5
                ",
                params![
                    RecordRequestStatus::Started.as_str(),
                    record_session_id,
                    params.started_ts,
                    request_id,
                    RecordRequestStatus::Confirmed.as_str(),
                ],
            )?;
            if changed == 0 {
                return Err(StoreError::RecordRoutine(format!(
                    "record request {request_id} was not confirmed"
                )));
            }
        }
        tx.commit()?;
        Ok(record_session_id)
    }

    pub fn close_record_session(
        &self,
        record_session_id: i64,
        ended_ts: i64,
        stop_reason: RecordStopReason,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "
            UPDATE record_sessions
               SET ended_ts = max(started_ts, ?1), stop_reason = ?2
             WHERE record_session_id = ?3
               AND ended_ts IS NULL
            ",
            params![ended_ts, stop_reason.as_str(), record_session_id],
        )?;
        Ok(())
    }

    pub fn pause_record_session(
        &self,
        record_session_id: i64,
        paused_ts: i64,
    ) -> Result<(), StoreError> {
        let intervals = self.pause_intervals(record_session_id)?;
        if intervals
            .last()
            .is_some_and(|interval| interval.1.is_none())
        {
            return Ok(());
        }
        let mut intervals = intervals;
        intervals.push((paused_ts, None));
        self.write_pause_intervals(record_session_id, &intervals)
    }

    pub fn resume_record_session(
        &self,
        record_session_id: i64,
        resumed_ts: i64,
    ) -> Result<(), StoreError> {
        let mut intervals = self.pause_intervals(record_session_id)?;
        if let Some((start, end)) = intervals.last_mut() {
            if end.is_none() {
                *end = Some(resumed_ts.max(*start));
            }
        }
        self.write_pause_intervals(record_session_id, &intervals)
    }

    pub fn finalize_open_record_sessions(
        &self,
        stop_reason: RecordStopReason,
        ended_ts: i64,
    ) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "
            UPDATE record_sessions
               SET ended_ts = max(started_ts, ?1), stop_reason = ?2
             WHERE ended_ts IS NULL
            ",
            params![ended_ts, stop_reason.as_str()],
        )?)
    }

    pub fn open_record_sessions(&self) -> Result<Vec<OpenRecordSession>, StoreError> {
        let mut stmt = self.conn.prepare(
            "
            SELECT record_session_id, started_ts, safety_cap_ms, pause_intervals_json
              FROM record_sessions
             WHERE ended_ts IS NULL
             ORDER BY started_ts ASC, record_session_id ASC
            ",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(OpenRecordSession {
                    record_session_id: row.get(0)?,
                    started_ts: row.get(1)?,
                    safety_cap_ms: row.get(2)?,
                    pause_intervals_json: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn insert_events(&mut self, events: &[EventEnvelope]) -> Result<InsertReport, StoreError> {
        let mut report = InsertReport::default();
        if events.is_empty() {
            return Ok(report);
        }

        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(INSERT_EVENT_SQL)?;

            for event in events {
                let row = match EventRow::from_envelope(event) {
                    Ok(row) => row,
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = event.seq, "skipping unserializable event");
                        continue;
                    }
                };

                match stmt.execute(params![
                    row.session_id,
                    row.seq,
                    row.ts,
                    row.source,
                    row.kind,
                    row.is_sensitive,
                    row.hwnd,
                    row.exe,
                    row.title,
                    row.pid,
                    row.prev_exe,
                    row.prev_title,
                    row.key,
                    row.mod_shift,
                    row.mod_ctrl,
                    row.mod_alt,
                    row.mod_win,
                    row.button,
                    row.pos_x,
                    row.pos_y,
                    row.duration_ms,
                    row.payload,
                ]) {
                    Ok(_) => report.inserted += 1,
                    Err(error)
                        if is_rusqlite_busy_or_locked(&error)
                            || is_rusqlite_interrupted(&error) =>
                    {
                        return Err(StoreError::Sqlite(error));
                    }
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = event.seq, "skipping event that failed to insert");
                    }
                }
            }
        }

        tx.commit()?;
        Ok(report)
    }

    pub fn insert_actions(
        &mut self,
        actions: &[StampedAction],
    ) -> Result<InsertReport, StoreError> {
        let mut report = InsertReport::default();
        if actions.is_empty() {
            return Ok(report);
        }

        let tx = self.conn.transaction()?;
        {
            let mut intern_selector = tx.prepare_cached(
                "
                INSERT OR IGNORE INTO selector_paths (
                    path_hash, framework, depth, path_json, leaf_rect, has_name, created_ts
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7
                )
                ",
            )?;
            let mut select_selector =
                tx.prepare_cached("SELECT selector_id FROM selector_paths WHERE path_hash = ?1")?;
            let mut mark_selector_has_name =
                tx.prepare_cached("UPDATE selector_paths SET has_name = 1 WHERE path_hash = ?1")?;
            let mut select_open_recording = tx.prepare_cached(
                "SELECT ended_ts IS NULL FROM record_sessions WHERE record_session_id = ?1",
            )?;
            let mut insert_action = tx.prepare_cached(
                "
                INSERT INTO action_events (
                    session_id, seq, ts, action_type, pattern_action, selector_id,
                    trust_basis, exe, is_sensitive, record_session_id, framework_class, payload
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6,
                    ?7, ?8, ?9, ?10, ?11, ?12
                )
                ",
            )?;
            let mut bump_action_count = tx.prepare_cached(
                "
                UPDATE record_sessions
                   SET action_count = action_count + 1
                 WHERE record_session_id = ?1
                ",
            )?;

            for action in actions {
                debug_assert!(matches!(
                    action.action.trust_basis,
                    SelectorTrustBasis::PidMatch
                        | SelectorTrustBasis::WindowOwnership
                        | SelectorTrustBasis::ScopedInvokeSender
                ));

                let recording_is_open = match select_open_recording
                    .query_row([action.record_session_id], |row| row.get::<_, i64>(0))
                {
                    Ok(1) => true,
                    Ok(_) => false,
                    Err(rusqlite::Error::QueryReturnedNoRows) => false,
                    Err(error) => return Err(StoreError::Sqlite(error)),
                };
                if !recording_is_open {
                    report.skipped += 1;
                    warn!(
                        seq = action.seq,
                        record_session_id = action.record_session_id,
                        "skipping action for closed or missing record routine session"
                    );
                    continue;
                }

                let path_hash = action.action.selector_path.hash_v1();
                let path_json = match serde_json::to_string(&action.action.selector_path.hops) {
                    Ok(json) => json,
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = action.seq, "skipping action with unserializable selector path");
                        continue;
                    }
                };
                let payload = match serde_json::to_string(&action.payload) {
                    Ok(json) => json,
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = action.seq, "skipping action with unserializable payload");
                        continue;
                    }
                };
                if let Err(error) = ensure_value_free_json(&path_json, "selector_path") {
                    report.skipped += 1;
                    warn!(%error, seq = action.seq, "skipping action after value-free selector guard");
                    continue;
                }
                if let Err(error) = ensure_value_free_json(&payload, "action_payload") {
                    report.skipped += 1;
                    warn!(%error, seq = action.seq, "skipping action after value-free payload guard");
                    continue;
                }

                if let Err(error) = intern_selector.execute(params![
                    path_hash.as_str(),
                    action.framework.as_str(),
                    i64::from(action.depth),
                    path_json.as_str(),
                    action.leaf_rect.as_deref(),
                    bool_i64(action.has_name),
                    action.ts_unix_ms,
                ]) {
                    if is_rusqlite_busy_or_locked(&error) || is_rusqlite_interrupted(&error) {
                        return Err(StoreError::Sqlite(error));
                    }
                    report.skipped += 1;
                    warn!(%error, seq = action.seq, "skipping action after selector intern failed");
                    continue;
                }

                if action.has_name {
                    mark_selector_has_name.execute([path_hash.as_str()])?;
                }

                let selector_id = match select_selector
                    .query_row([path_hash.as_str()], |row| row.get::<_, i64>(0))
                {
                    Ok(selector_id) => selector_id,
                    Err(error)
                        if is_rusqlite_busy_or_locked(&error)
                            || is_rusqlite_interrupted(&error) =>
                    {
                        return Err(StoreError::Sqlite(error));
                    }
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = action.seq, "skipping action after selector lookup failed");
                        continue;
                    }
                };

                let action_exe = action.exe.as_deref().map(exe_basename);
                match insert_action.execute(params![
                    action.session_id,
                    u64_to_i64(action.seq),
                    action.ts_unix_ms,
                    action.action.action_type.as_str(),
                    action.pattern_action.as_deref(),
                    selector_id,
                    action.action.trust_basis.as_str(),
                    action_exe.as_deref(),
                    bool_i64(action.is_sensitive),
                    action.record_session_id,
                    action.framework_class.as_str(),
                    payload.as_str(),
                ]) {
                    Ok(_) => {
                        bump_action_count.execute([action.record_session_id])?;
                        report.inserted += 1;
                    }
                    Err(error)
                        if is_rusqlite_busy_or_locked(&error)
                            || is_rusqlite_interrupted(&error) =>
                    {
                        return Err(StoreError::Sqlite(error));
                    }
                    Err(error) => {
                        report.skipped += 1;
                        warn!(%error, seq = action.seq, "skipping action that failed to insert");
                    }
                }
            }
        }

        tx.commit()?;
        Ok(report)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn db_path(&self) -> &Path {
        &self.path
    }

    pub fn wal_file_size(&self) -> u64 {
        fs::metadata(wal_path(&self.path))
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    /// Size of the main `.db` file (STORE-01). Distinct from the WAL: the main DB
    /// grows with retained capture and only shrinks via compaction.
    pub fn main_db_file_size(&self) -> u64 {
        fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    /// Newest stored event timestamp, if any rows exist. Startup retention
    /// clamps its wall-clock reference against this so a corrected clock
    /// (dead CMOS battery, bad NTP source) can never make genuinely recent
    /// rows look expired and silently prune them (S14).
    pub fn newest_event_ts(&self) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT MAX(ts) FROM events", [], |row| row.get(0))?)
    }

    pub fn secure_delete_activity(&mut self) -> Result<SecureDeleteReport, StoreError> {
        self.conn.execute_batch("PRAGMA secure_delete = ON;")?;
        let events_deleted = self.count_rows("events")?;
        let sessions_deleted = self.count_rows("sessions")?;

        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM action_events", [])?;
        tx.execute("DELETE FROM record_sessions", [])?;
        tx.execute("DELETE FROM record_requests", [])?;
        tx.execute("DELETE FROM selector_paths", [])?;
        tx.execute("DELETE FROM open_focus", [])?;
        tx.execute("DELETE FROM deletion_audit", [])?;
        tx.execute("DELETE FROM events", [])?;
        tx.execute("DELETE FROM sessions", [])?;
        tx.execute("DELETE FROM meta", [])?;
        tx.execute(
            "DELETE FROM sqlite_sequence
             WHERE name IN (
                'action_events',
                'record_sessions',
                'record_requests',
                'selector_paths',
                'deletion_audit',
                'events',
                'sessions',
                'meta'
             )",
            [],
        )?;
        tx.commit()?;

        let mut scrub_errors = Vec::new();
        if let Err(error) = checkpoint_truncate_verified(&self.conn) {
            scrub_errors.push(format!("checkpoint before vacuum failed: {error}"));
        }
        if let Err(error) = self.conn.execute_batch("VACUUM;") {
            scrub_errors.push(format!("vacuum failed: {error}"));
        }
        if let Err(error) = checkpoint_truncate_verified(&self.conn) {
            scrub_errors.push(format!("checkpoint after vacuum failed: {error}"));
        }

        Ok(SecureDeleteReport {
            events_deleted,
            sessions_deleted,
            scrub_error: (!scrub_errors.is_empty()).then(|| scrub_errors.join("; ")),
        })
    }

    pub fn prune_old_activity(&mut self, cutoff_ms: i64) -> Result<PruneReport, StoreError> {
        let secure_delete = secure_delete_setting(&self.conn)?;
        self.conn.execute_batch("PRAGMA secure_delete = ON;")?;

        let prune_result = (|| {
            let performed_at = unix_now_ms();
            let tx = self.conn.transaction()?;
            let mut audit = DeletionAuditAggregate::default();
            delete_returning_audit_batched(
                &tx,
                &format!(
                    "DELETE FROM action_events WHERE rowid IN (
                         SELECT rowid FROM action_events WHERE ts < ?1
                         LIMIT {PRUNE_RETURNING_BATCH}
                     ) RETURNING session_id, seq"
                ),
                [cutoff_ms],
                &mut audit,
            )?;
            let events_deleted = delete_returning_audit_batched(
                &tx,
                &format!(
                    "DELETE FROM events WHERE rowid IN (
                         SELECT rowid FROM events WHERE ts < ?1
                         LIMIT {PRUNE_RETURNING_BATCH}
                     ) RETURNING session_id, seq"
                ),
                [cutoff_ms],
                &mut audit,
            )?;
            tx.execute(
                "
                DELETE FROM record_sessions
                WHERE ended_ts IS NOT NULL
                  AND ended_ts < ?1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM action_events
                      WHERE action_events.record_session_id = record_sessions.record_session_id
                  )
                ",
                [cutoff_ms],
            )?;
            // Orphan sweep deletes regardless of ts, so it must feed the
            // audit too — a mirrored ts predicate would under-count it.
            delete_returning_audit_batched(
                &tx,
                &format!(
                    "DELETE FROM action_events WHERE rowid IN (
                         SELECT rowid FROM action_events
                         WHERE NOT EXISTS (
                             SELECT 1
                             FROM record_sessions
                             WHERE record_sessions.record_session_id =
                                 action_events.record_session_id
                         )
                         LIMIT {PRUNE_RETURNING_BATCH}
                     ) RETURNING session_id, seq"
                ),
                [],
                &mut audit,
            )?;
            let sessions_deleted = tx.execute(
                "
                DELETE FROM sessions
                WHERE ended_at IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM events
                      WHERE events.session_id = sessions.session_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM action_events
                      WHERE action_events.session_id = sessions.session_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM record_sessions
                      WHERE record_sessions.session_id = sessions.session_id
                  )
                ",
                [],
            )?;
            tx.execute(
                "
                DELETE FROM record_requests
                WHERE expires_at < ?1
                  AND (
                      fulfilled_record_session_id IS NULL
                      OR NOT EXISTS (
                          SELECT 1
                          FROM record_sessions
                          WHERE record_sessions.record_session_id =
                              record_requests.fulfilled_record_session_id
                      )
                  )
                ",
                [cutoff_ms],
            )?;
            tx.execute(
                "
                DELETE FROM selector_paths
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM action_events
                    WHERE action_events.selector_id = selector_paths.selector_id
                )
                ",
                [],
            )?;
            record_deletion_audit(
                &tx,
                DELETION_AUDIT_KIND_STARTUP_RETENTION,
                performed_at,
                Some(cutoff_ms),
                &audit,
            )?;
            tx.commit()?;

            Ok(PruneReport {
                events_deleted,
                sessions_deleted,
            })
        })();

        let restore_result = restore_secure_delete_setting(&self.conn, secure_delete);
        match (prune_result, restore_result) {
            (Ok(report), Ok(())) => {
                // Checkpoint so the prune's secure-delete page rewrites leave
                // the WAL. Best-effort like the title scrub: a checkpoint held
                // off by a live dashboard reader must not turn a committed
                // prune into a reported failure — the startup log would then
                // claim "continuing without pruning" after rows were already
                // irreversibly deleted.
                if let Err(error) = checkpoint_truncate_verified(&self.conn) {
                    warn!(
                        %error,
                        events_deleted = report.events_deleted,
                        sessions_deleted = report.sessions_deleted,
                        "checkpoint after retention prune incomplete; pre-prune page bytes may persist in the WAL until the next checkpoint"
                    );
                }
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(restore_error)) => {
                warn!(
                    %restore_error,
                    "failed to restore secure_delete after failed retention prune"
                );
                Err(error)
            }
        }
    }

    /// Blank window titles on rows older than `cutoff_ms` while keeping the
    /// rows (`privacy.title_retention_days`). The title disappears from both
    /// the typed columns and the payload JSON (the same both-copies rule as
    /// redaction), and rows are NOT marked `is_sensitive` -- aging content out
    /// by policy is not a fired privacy rule. Bounded batches keep a large
    /// backlog from stalling startup; `secure_delete` is enabled for the
    /// duration so overwritten pages do not retain the old title bytes.
    pub fn scrub_titles_before(&mut self, cutoff_ms: i64) -> Result<u64, StoreError> {
        const SCRUB_BATCH: i64 = 20_000;
        let secure_delete = secure_delete_setting(&self.conn)?;
        self.conn.execute_batch("PRAGMA secure_delete = ON;")?;

        let scrub_result = (|| {
            let mut total: u64 = 0;
            loop {
                let tx = self.conn.transaction()?;
                let changed = tx.execute(
                    "
                    UPDATE events SET
                        title = NULL,
                        prev_title = NULL,
                        payload = json_remove(payload, '$.window.title', '$.prev.title')
                    WHERE id IN (
                        SELECT id FROM events
                        WHERE ts < ?1
                          AND (title IS NOT NULL
                               OR prev_title IS NOT NULL
                               OR payload LIKE '%\"title\"%')
                        LIMIT ?2
                    )
                    ",
                    params![cutoff_ms, SCRUB_BATCH],
                )?;
                tx.commit()?;
                total += changed as u64;
                if (changed as i64) < SCRUB_BATCH {
                    break;
                }
            }
            Ok(total)
        })();

        let restore_result = restore_secure_delete_setting(&self.conn, secure_delete);
        // Checkpoint so the scrub's overwrites land in the main DB and the WAL
        // (which still holds the pre-scrub title bytes) is truncated. Without
        // this a "blanked" title can linger in the -wal file until the next
        // checkpoint. Best-effort: a deferred or failed checkpoint does not
        // undo the logical scrub, so log rather than fail the whole operation
        // -- but it must be the verified form, or a checkpoint held off by a
        // live dashboard reader reports success while the bytes remain.
        if scrub_result.is_ok() {
            if let Err(error) = checkpoint_truncate_verified(&self.conn) {
                warn!(%error, "checkpoint after title scrub incomplete; pre-scrub title bytes may persist in the WAL until the next checkpoint");
            }
        }
        match (scrub_result, restore_result) {
            (Ok(total), Ok(())) => Ok(total),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(restore_error)) => {
                warn!(
                    %restore_error,
                    "failed to restore secure_delete after failed title scrub"
                );
                Err(error)
            }
        }
    }

    /// Mouse-move tier: delete raw `mouse_move` rows older than the cutoff in
    /// bounded batches. Noise reduction, not redaction: movement rows are
    /// ~half of a long-run DB and only feed motion metrics that read a
    /// bounded window, so aging them out is a plain prune (no secure_delete,
    /// no `is_sensitive` semantics). Other input rows are untouched.
    pub fn prune_mouse_moves_before(&mut self, cutoff_ms: i64) -> Result<u64, StoreError> {
        const PRUNE_BATCH: i64 = 20_000;
        // One operation timestamp across every batch: a multi-batch prune
        // still audits per batch transaction (a crash between batches keeps
        // committed batches explained), but the shared performed_at groups
        // the rows as one operation.
        let performed_at = unix_now_ms();
        let mut total: u64 = 0;
        loop {
            let tx = self.conn.transaction()?;
            let mut audit = DeletionAuditAggregate::default();
            let changed = delete_returning_audit(
                &tx,
                "
                DELETE FROM events
                WHERE id IN (
                    SELECT id FROM events
                    WHERE kind = 'mouse_move' AND ts < ?1
                    LIMIT ?2
                )
                RETURNING session_id, seq
                ",
                params![cutoff_ms, PRUNE_BATCH],
                &mut audit,
            )?;
            record_deletion_audit(
                &tx,
                DELETION_AUDIT_KIND_MOUSE_MOVE_RETENTION,
                performed_at,
                Some(cutoff_ms),
                &audit,
            )?;
            tx.commit()?;
            total += changed as u64;
            if (changed as i64) < PRUNE_BATCH {
                break;
            }
        }
        Ok(total)
    }

    pub fn archive_activity_to(
        &self,
        archive_path: &Path,
        archive_ended_at: i64,
    ) -> Result<ArchiveReport, StoreError> {
        #[cfg(test)]
        if take_injected_archive_verification_failure(archive_path) {
            return self.archive_activity_to_with_verifier(archive_path, archive_ended_at, |_| {
                Err(StoreError::RecordRoutine(
                    "injected full-read verification failure".to_string(),
                ))
            });
        }
        self.archive_activity_to_with_verifier(archive_path, archive_ended_at, |sealed_path| {
            verify_archive(sealed_path, ArchiveCredential::DpapiUser)?;
            Ok(())
        })
    }

    fn archive_activity_to_with_verifier<F>(
        &self,
        archive_path: &Path,
        archive_ended_at: i64,
        verify: F,
    ) -> Result<ArchiveReport, StoreError>
    where
        F: FnOnce(&Path) -> Result<(), StoreError>,
    {
        // First statement in the function, before any filesystem effect.
        // Sealing is what discovers an unavailable key, and it runs after
        // `VACUUM main INTO` has written a complete plaintext copy of the
        // activity database; from there only a best-effort scrub removes it,
        // and a scrub failure leaves an unencrypted database that no inventory
        // surface reports (the staging name is dot-prefixed;
        // `inventory_archives` matches `gilbreth-archive-*`). Off Windows
        // `DpapiUser` can never succeed, so that was every attempt. Refusing
        // here means a rejected archive does not even create its directory.
        archive::ensure_seal_key_available(archive::ArchiveSealKey::DpapiUser)?;
        if let Some(parent) = archive_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if archive_path.extension().and_then(|value| value.to_str()) != Some(ARCHIVE_EXTENSION) {
            return Err(ArchiveError::InvalidFormat(format!(
                "encrypted archive path must use the .{ARCHIVE_EXTENSION} extension"
            ))
            .into());
        }
        if archive_path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("archive already exists: {}", archive_path.display()),
            )));
        }
        let unique = uuid::Uuid::new_v4();
        let archive_name = archive_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("gilbreth-archive");
        let parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
        let plaintext_path = parent.join(format!(".{archive_name}.{unique}.plaintext.db"));
        let sealed_pending_path = parent.join(format!(".{archive_name}.{unique}.pending"));
        let plaintext_path_text = plaintext_path.to_str().ok_or_else(|| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "archive temporary path is not valid UTF-8: {}",
                    plaintext_path.display()
                ),
            ))
        })?;
        let events_archived = self.count_rows("events")?;
        let sessions_archived = self.count_rows("sessions")?;
        let provenance = self.archive_provenance(archive_ended_at)?;
        let prepared = (|| {
            self.conn
                .execute("VACUUM main INTO ?1", params![plaintext_path_text])?;
            stamp_archive_open_sessions(&plaintext_path, archive_ended_at)?;
            archive::seal_archive_file(
                &plaintext_path,
                &sealed_pending_path,
                provenance,
                archive::ArchiveSealKey::DpapiUser,
            )?;
            if let Err(error) = verify(&sealed_pending_path) {
                return Err(StoreError::ArchiveVerification(error.to_string()));
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            let plaintext_cleanup = scrub_archive_plaintext_staging(&plaintext_path);
            remove_archive_temporary_file(&sealed_pending_path, "unverified sealed archive");
            if let Err(cleanup_error) = plaintext_cleanup {
                return Err(StoreError::ArchiveStagingCleanup(format!(
                    "{cleanup_error}; archive preparation also failed: {error}"
                )));
            }
            return Err(error);
        }
        if let Err(error) = scrub_archive_plaintext_staging(&plaintext_path) {
            remove_archive_temporary_file(&sealed_pending_path, "verified pending archive");
            return Err(StoreError::ArchiveStagingCleanup(error.to_string()));
        }
        if let Err(error) = fs::rename(&sealed_pending_path, archive_path) {
            remove_archive_temporary_file(&sealed_pending_path, "verified pending archive");
            return Err(error.into());
        }
        Ok(ArchiveReport {
            archive_path: archive_path.to_path_buf(),
            events_archived,
            sessions_archived,
            encryption: ArchiveEncryptionReceipt::dpapi_user(),
        })
    }

    fn archive_provenance(&self, created_at: i64) -> Result<ArchiveProvenance, StoreError> {
        let db_uuid: String =
            self.conn
                .query_row("SELECT value FROM meta WHERE key = 'db_uuid'", [], |row| {
                    row.get(0)
                })?;
        let host = self
            .conn
            .query_row(
                "SELECT host FROM sessions WHERE host IS NOT NULL AND trim(host) <> '' ORDER BY session_id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .or_else(|| env::var("COMPUTERNAME").ok())
            .or_else(|| env::var("HOSTNAME").ok());
        let schema_version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let (first_ts, last_ts): (Option<i64>, Option<i64>) = self.conn.query_row(
            "SELECT MIN(ts), MAX(ts) FROM (SELECT ts FROM events UNION ALL SELECT ts FROM action_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(ArchiveProvenance {
            db_uuid,
            host,
            schema_version,
            first_ts,
            last_ts,
            created_at,
        })
    }

    pub fn mint_meta_identity(&self, created_at: i64) -> Result<(), StoreError> {
        let db_uuid = uuid::Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params!["db_uuid", db_uuid],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params!["created_at", created_at.to_string()],
        )?;
        Ok(())
    }

    fn count_rows(&self, table: &str) -> Result<usize, StoreError> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = self.conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    fn pause_intervals(
        &self,
        record_session_id: i64,
    ) -> Result<Vec<(i64, Option<i64>)>, StoreError> {
        let json: String = self.conn.query_row(
            "SELECT pause_intervals_json FROM record_sessions WHERE record_session_id = ?1",
            [record_session_id],
            |row| row.get(0),
        )?;
        parse_pause_intervals(&json)
    }

    fn write_pause_intervals(
        &self,
        record_session_id: i64,
        intervals: &[(i64, Option<i64>)],
    ) -> Result<(), StoreError> {
        let value = serde_json::Value::Array(
            intervals
                .iter()
                .map(|(start, end)| {
                    serde_json::Value::Array(vec![
                        serde_json::Value::from(*start),
                        end.map_or(serde_json::Value::Null, serde_json::Value::from),
                    ])
                })
                .collect(),
        );
        self.conn.execute(
            "
            UPDATE record_sessions
               SET pause_intervals_json = ?1
             WHERE record_session_id = ?2
               AND ended_ts IS NULL
            ",
            params![value.to_string(), record_session_id],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WriterConfig {
    pub flush_interval: Duration,
    pub batch_size: usize,
    pub heartbeat_interval: Option<Duration>,
    /// Cadence of the `open_focus` single-row beat (foreground-heartbeat
    /// design, decision 4). Production keeps the shared 30 s default from
    /// gilbreth-core; tests shorten it to drive beats deterministically.
    pub open_focus_beat_interval: Duration,
    pub record_request_poll_interval: Option<Duration>,
    pub record_request_notify: Option<Sender<PendingRecordRequest>>,
    pub cap_prompt_notify: Option<Sender<CapPrompt>>,
    pub record_prompt_in_flight: Option<Arc<AtomicBool>>,
    pub timebase_drift_threshold_ms: i64,
    pub stale_event_warn_after: Option<Duration>,
    pub diagnostics: DiagnosticsCounters,
    pub panic_action_cutoff: PanicActionCutoff,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            flush_interval: Duration::from_millis(250),
            batch_size: 100,
            heartbeat_interval: Some(DEFAULT_HEARTBEAT_INTERVAL),
            open_focus_beat_interval: Duration::from_millis(
                gilbreth_core::OPEN_FOCUS_BEAT_MS as u64,
            ),
            record_request_poll_interval: Some(Duration::from_secs(3)),
            record_request_notify: None,
            cap_prompt_notify: None,
            record_prompt_in_flight: None,
            timebase_drift_threshold_ms: DEFAULT_TIMEBASE_DRIFT_THRESHOLD_MS,
            stale_event_warn_after: Some(DEFAULT_STALE_EVENT_WARN_AFTER),
            diagnostics: DiagnosticsCounters::new(),
            panic_action_cutoff: PanicActionCutoff::default(),
        }
    }
}

impl WriterConfig {
    pub fn with_diagnostics(mut self, diagnostics: DiagnosticsCounters) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn with_panic_action_cutoff(mut self, cutoff: PanicActionCutoff) -> Self {
        self.panic_action_cutoff = cutoff;
        self
    }

    pub fn with_record_notifications(
        mut self,
        record_request_notify: Sender<PendingRecordRequest>,
        cap_prompt_notify: Sender<CapPrompt>,
        record_prompt_in_flight: Arc<AtomicBool>,
    ) -> Self {
        self.record_request_notify = Some(record_request_notify);
        self.cap_prompt_notify = Some(cap_prompt_notify);
        self.record_prompt_in_flight = Some(record_prompt_in_flight);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct WriterReport {
    pub events_written: usize,
    pub events_skipped: usize,
    pub actions_written: usize,
    pub actions_skipped: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRecordRequest {
    pub request_id: i64,
    pub candidate_kind: Option<String>,
    pub candidate_json: String,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenRecordSessionParams<'a> {
    pub request_id: Option<i64>,
    pub session_id: i64,
    pub started_ts: i64,
    pub title: Option<&'a str>,
    pub policy_snapshot_json: &'a str,
    pub safety_cap_ms: i64,
    pub visible_indicator: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapPrompt {
    pub record_session_id: i64,
    pub window_index: i64,
    pub elapsed_active_ms: i64,
    pub safety_cap_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRecordSession {
    pub record_session_id: i64,
    pub started_ts: i64,
    pub safety_cap_ms: i64,
    pub pause_intervals_json: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InsertReport {
    pub inserted: usize,
    pub skipped: usize,
}

/// Shared, process-local Record Routine panic fence. The tray arms it at the
/// keypress boundary before stopping workers or waiting on the writer command;
/// the writer consults it on every action input, including inputs it selects
/// before the StopRecording command arrives.
#[derive(Clone, Debug, Default)]
pub struct PanicActionCutoff {
    inner: Arc<Mutex<Option<(i64, Instant)>>>,
}

impl PanicActionCutoff {
    pub fn arm(&self, record_session_id: i64, captured_at: Instant) {
        if let Ok(mut current) = self.inner.lock() {
            *current = Some((record_session_id, captured_at));
        }
    }

    pub fn clear(&self, record_session_id: i64) {
        if let Ok(mut current) = self.inner.lock() {
            if current.is_some_and(|(current_id, _)| current_id == record_session_id) {
                *current = None;
            }
        }
    }

    fn rejects(&self, action: &ActionCapture) -> bool {
        self.inner.lock().is_ok_and(|current| {
            current.is_some_and(|(record_session_id, cutoff)| {
                record_session_id == action.record_session_id && action.captured_at >= cutoff
            })
        })
    }
}

#[derive(Clone, Debug)]
pub enum WriterCommand {
    /// Invalidate the writer policy's live focus attribution (exclusion
    /// fail-open fix). The app sends this when the user turns the Foreground
    /// stream off, AFTER closing the stream gate and flushing the capture
    /// forwarder: the writer then drains its own input channel before
    /// forgetting, so no in-flight FocusChanged can re-arm the latch with a
    /// stale verdict once the forget lands (a timed-out flush degrades this
    /// to an accepted low-probability residue — see the sender's doc). Rows
    /// without attribution fail closed from the forget on. The ack exists so
    /// tests can order the command against later inputs; the tray drops its
    /// receiver without waiting.
    ForgetFocusAttribution {
        ack: Sender<()>,
    },
    StartRecording {
        request_id: Option<i64>,
        title: Option<String>,
        policy_snapshot_json: String,
        safety_cap_ms: i64,
        visible_indicator: bool,
        reply: Sender<Result<i64, String>>,
    },
    StopRecording {
        record_session_id: i64,
        stop_reason: RecordStopReason,
        reply: Sender<Result<(), String>>,
    },
    PauseRecording {
        record_session_id: i64,
        reply: Sender<Result<(), String>>,
    },
    ResumeRecording {
        record_session_id: i64,
        reply: Sender<Result<(), String>>,
    },
    ExtendCap {
        record_session_id: i64,
    },
    DeclineRecordRequest {
        request_id: i64,
    },
    /// Caller must set capture suspension before sending this command and keep
    /// it set until the reply is handled. The app flushes the capture-forwarder
    /// hop first; the writer then quiet-drains its own input channel before
    /// crossing the delete boundary.
    SecureErase {
        session_identity: SessionIdentity,
        reply: Sender<SecureEraseReport>,
    },
    /// Same suspension contract as secure erase, but first archives the live DB
    /// with SQLite's VACUUM INTO path, then resets live activity into a fresh
    /// session.
    ArchiveAndReset {
        archive_path: PathBuf,
        session_identity: SessionIdentity,
        reply: Sender<ArchiveResetReport>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureDeleteReport {
    pub events_deleted: usize,
    pub sessions_deleted: usize,
    pub scrub_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruneReport {
    pub events_deleted: usize,
    pub sessions_deleted: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteResult {
    pub deleted: usize,
    pub scrub_warning: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DashboardPrunePreview {
    pub cutoff_ms: i64,
    pub events: usize,
    pub ended_empty_sessions: usize,
    pub action_events: usize,
    pub ended_empty_record_sessions: usize,
    pub record_requests: usize,
    pub selector_paths: usize,
}

impl DashboardPrunePreview {
    pub fn total_rows(&self) -> usize {
        self.events
            + self.ended_empty_sessions
            + self.action_events
            + self.ended_empty_record_sessions
            + self.record_requests
            + self.selector_paths
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardPruneResult {
    pub events_deleted: usize,
    pub sessions_deleted: usize,
    pub compaction_completed: bool,
    pub compact_error: Option<String>,
    pub action_events_deleted: usize,
    pub record_sessions_deleted: usize,
    pub record_requests_deleted: usize,
    pub selector_paths_deleted: usize,
}

impl DashboardPruneResult {
    pub fn total_deleted(&self) -> usize {
        self.events_deleted
            + self.sessions_deleted
            + self.action_events_deleted
            + self.record_sessions_deleted
            + self.record_requests_deleted
            + self.selector_paths_deleted
    }
}

pub fn cutoff_ms_for_days(retention_days: i64, now_ms: i64) -> i64 {
    now_ms.saturating_sub(retention_days.max(1).saturating_mul(DAY_MS))
}

/// Create a dashboard-originated Record Routine request.
///
/// Unlike the legacy Python dashboard writer, the Rust path validates the
/// candidate blob with the same value-free JSON guard the tray/writer already
/// uses before any request can reach the recorder.
pub fn request_recording(
    db_path: impl AsRef<Path>,
    candidate_kind: Option<&str>,
    candidate_json: &str,
    now_ms: i64,
) -> Result<i64, StoreError> {
    ensure_value_free_json(candidate_json, "candidate_json")?;
    let conn = dashboard_writable_connection(db_path.as_ref())?;
    if !sqlite_table_exists(&conn, "record_requests")? {
        return Err(StoreError::RecordRoutine(
            "record_requests table is not present in this database".to_string(),
        ));
    }
    let expires_at = now_ms.saturating_add(DAY_MS);
    conn.execute(
        "
        INSERT INTO record_requests (
            requested_at,
            expires_at,
            status,
            candidate_kind,
            candidate_json,
            updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?1)
        ",
        params![
            now_ms,
            expires_at,
            RecordRequestStatus::Requested.as_str(),
            candidate_kind,
            candidate_json
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_events(
    db_path: impl AsRef<Path>,
    event_ids: &[i64],
) -> Result<DeleteResult, StoreError> {
    let mut ids = event_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(DeleteResult {
            deleted: 0,
            scrub_warning: None,
        });
    }

    let mut conn = dashboard_writable_connection(db_path.as_ref())?;
    let performed_at = unix_now_ms();
    let deleted = with_temporary_secure_delete(&mut conn, |conn| {
        let tx = conn.transaction()?;
        let mut audit = DeletionAuditAggregate::default();
        let mut deleted = 0;
        {
            let mut stmt =
                tx.prepare("DELETE FROM events WHERE id = ?1 RETURNING session_id, seq")?;
            for id in &ids {
                let mut rows = stmt.query([*id])?;
                while let Some(row) = rows.next()? {
                    audit.note(row.get(0)?, row.get(1)?);
                    deleted += 1;
                }
            }
        }
        record_deletion_audit(
            &tx,
            DELETION_AUDIT_KIND_EVENT_DELETE,
            performed_at,
            None,
            &audit,
        )?;
        tx.commit()?;
        Ok(deleted)
    })?;
    let scrub_warning = checkpoint_after_secure_delete(&conn);
    Ok(DeleteResult {
        deleted,
        scrub_warning,
    })
}

pub fn delete_recording(
    db_path: impl AsRef<Path>,
    record_session_id: i64,
) -> Result<DeleteResult, StoreError> {
    let mut conn = dashboard_writable_connection(db_path.as_ref())?;
    if !record_routine_tables_present_conn(&conn)? {
        return Ok(DeleteResult {
            deleted: 0,
            scrub_warning: None,
        });
    }
    let deleted = with_temporary_secure_delete(&mut conn, |conn| {
        let tx = conn.transaction()?;
        let deleted = delete_recording_rows(&tx, record_session_id)?;
        tx.commit()?;
        Ok(deleted)
    })?;
    let scrub_warning = checkpoint_after_secure_delete(&conn);
    Ok(DeleteResult {
        deleted,
        scrub_warning,
    })
}

pub fn prune_preview(
    db_path: impl AsRef<Path>,
    cutoff_ms: i64,
) -> Result<DashboardPrunePreview, StoreError> {
    let conn = dashboard_readonly_connection(db_path.as_ref())?;
    let has_record_routine = record_routine_tables_present_conn(&conn)?;
    let events = query_count(
        &conn,
        "SELECT COUNT(*) FROM events WHERE ts < ?1",
        [cutoff_ms],
    )?;
    let sessions = if has_record_routine {
        query_count(
            &conn,
            "
            WITH pruned_record_sessions AS (
                SELECT rs.record_session_id
                FROM record_sessions rs
                WHERE rs.ended_ts IS NOT NULL
                  AND rs.ended_ts < ?1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM action_events ae
                      WHERE ae.record_session_id = rs.record_session_id
                        AND ae.ts >= ?1
                  )
            )
            SELECT COUNT(*)
            FROM sessions s
            WHERE s.ended_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM events e
                  WHERE e.session_id = s.session_id
                    AND e.ts >= ?1
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM action_events ae
                  WHERE ae.session_id = s.session_id
                    AND ae.ts >= ?1
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM record_sessions rs
                  WHERE rs.session_id = s.session_id
                    AND rs.record_session_id NOT IN (
                        SELECT record_session_id
                        FROM pruned_record_sessions
                    )
              )
            ",
            [cutoff_ms],
        )?
    } else {
        query_count(
            &conn,
            "
            SELECT COUNT(*)
            FROM sessions s
            WHERE s.ended_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM events e
                  WHERE e.session_id = s.session_id
                    AND e.ts >= ?1
              )
            ",
            [cutoff_ms],
        )?
    };

    let mut action_events = 0;
    let mut record_sessions = 0;
    let mut record_requests = 0;
    let mut selector_paths = 0;
    if has_record_routine {
        action_events = query_count(
            &conn,
            "SELECT COUNT(*) FROM action_events WHERE ts < ?1",
            [cutoff_ms],
        )?;
        record_sessions = query_count(
            &conn,
            "
            SELECT COUNT(*)
            FROM record_sessions rs
            WHERE rs.ended_ts IS NOT NULL
              AND rs.ended_ts < ?1
              AND NOT EXISTS (
                  SELECT 1
                  FROM action_events ae
                  WHERE ae.record_session_id = rs.record_session_id
                    AND ae.ts >= ?1
              )
            ",
            [cutoff_ms],
        )?;
        record_requests = query_count(
            &conn,
            "
            WITH pruned_record_sessions AS (
                SELECT rs.record_session_id
                FROM record_sessions rs
                WHERE rs.ended_ts IS NOT NULL
                  AND rs.ended_ts < ?1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM action_events ae
                      WHERE ae.record_session_id = rs.record_session_id
                        AND ae.ts >= ?1
                  )
            )
            SELECT COUNT(*)
            FROM record_requests rr
            WHERE rr.expires_at < ?1
              AND (
                  rr.fulfilled_record_session_id IS NULL
                  OR NOT EXISTS (
                      SELECT 1
                      FROM record_sessions rs
                      WHERE rs.record_session_id =
                            rr.fulfilled_record_session_id
                        AND rs.record_session_id NOT IN (
                            SELECT record_session_id
                            FROM pruned_record_sessions
                        )
                  )
              )
            ",
            [cutoff_ms],
        )?;
        selector_paths = query_count(
            &conn,
            "
            SELECT COUNT(*)
            FROM selector_paths sp
            WHERE NOT EXISTS (
                SELECT 1
                FROM action_events ae
                WHERE ae.selector_id = sp.selector_id
                  AND ae.ts >= ?1
            )
            ",
            [cutoff_ms],
        )?;
    }

    Ok(DashboardPrunePreview {
        cutoff_ms,
        events,
        ended_empty_sessions: sessions,
        action_events,
        ended_empty_record_sessions: record_sessions,
        record_requests,
        selector_paths,
    })
}

pub fn prune_old_events(
    db_path: impl AsRef<Path>,
    cutoff_ms: i64,
) -> Result<DashboardPruneResult, StoreError> {
    prune_old_events_with_compactor(db_path.as_ref(), cutoff_ms, compact_database)
}

fn prune_old_events_with_compactor(
    db_path: &Path,
    cutoff_ms: i64,
    compactor: impl FnOnce(&Connection) -> Option<String>,
) -> Result<DashboardPruneResult, StoreError> {
    let mut conn = dashboard_writable_connection(db_path)?;
    let result = with_temporary_secure_delete(&mut conn, |conn| {
        let tx = conn.transaction()?;
        let result = prune_old_event_rows(&tx, cutoff_ms)?;
        tx.commit()?;
        Ok(result)
    })?;
    let compact_error = compactor(&conn);
    Ok(DashboardPruneResult {
        compaction_completed: compact_error.is_none(),
        compact_error,
        ..result
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReport {
    pub archive_path: PathBuf,
    pub events_archived: usize,
    pub sessions_archived: usize,
    pub encryption: ArchiveEncryptionReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureEraseOutcome {
    Completed,
    DeleteFailed,
    DeleteCommittedScrubIncomplete,
    ReplacementSessionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveResetOutcome {
    Completed,
    ArchiveFailed,
    DeleteFailed,
    DeleteCommittedScrubIncomplete,
    ReplacementSessionFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveResetReport {
    pub outcome: ArchiveResetOutcome,
    pub archive_path: Option<PathBuf>,
    pub events_archived: usize,
    pub sessions_archived: usize,
    pub events_deleted: usize,
    pub sessions_deleted: usize,
    pub new_session_id: Option<i64>,
    pub message: Option<String>,
    pub archive_encryption: Option<ArchiveEncryptionReceipt>,
}

impl ArchiveResetReport {
    fn archive_failed(archive_path: &Path, error: impl ToString) -> Self {
        Self {
            outcome: ArchiveResetOutcome::ArchiveFailed,
            archive_path: Some(archive_path.to_path_buf()),
            events_archived: 0,
            sessions_archived: 0,
            events_deleted: 0,
            sessions_deleted: 0,
            new_session_id: None,
            message: Some(error.to_string()),
            archive_encryption: None,
        }
    }

    fn delete_failed(archive: ArchiveReport, error: impl ToString) -> Self {
        Self {
            outcome: ArchiveResetOutcome::DeleteFailed,
            archive_path: Some(archive.archive_path),
            events_archived: archive.events_archived,
            sessions_archived: archive.sessions_archived,
            events_deleted: 0,
            sessions_deleted: 0,
            new_session_id: None,
            message: Some(error.to_string()),
            archive_encryption: Some(archive.encryption),
        }
    }

    fn replacement_session_failed(
        archive: ArchiveReport,
        delete_report: SecureDeleteReport,
        error: impl ToString,
    ) -> Self {
        Self {
            outcome: ArchiveResetOutcome::ReplacementSessionFailed,
            archive_path: Some(archive.archive_path),
            events_archived: archive.events_archived,
            sessions_archived: archive.sessions_archived,
            events_deleted: delete_report.events_deleted,
            sessions_deleted: delete_report.sessions_deleted,
            new_session_id: None,
            message: Some(error.to_string()),
            archive_encryption: Some(archive.encryption),
        }
    }

    fn reset_committed(
        archive: ArchiveReport,
        delete_report: SecureDeleteReport,
        new_session_id: i64,
    ) -> Self {
        let outcome = if delete_report.scrub_error.is_some() {
            ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        } else {
            ArchiveResetOutcome::Completed
        };
        Self {
            outcome,
            archive_path: Some(archive.archive_path),
            events_archived: archive.events_archived,
            sessions_archived: archive.sessions_archived,
            events_deleted: delete_report.events_deleted,
            sessions_deleted: delete_report.sessions_deleted,
            new_session_id: Some(new_session_id),
            message: delete_report.scrub_error,
            archive_encryption: Some(archive.encryption),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEraseReport {
    pub outcome: SecureEraseOutcome,
    pub events_deleted: usize,
    pub sessions_deleted: usize,
    pub new_session_id: Option<i64>,
    pub message: Option<String>,
}

impl SecureEraseReport {
    fn delete_failed(error: impl ToString) -> Self {
        Self {
            outcome: SecureEraseOutcome::DeleteFailed,
            events_deleted: 0,
            sessions_deleted: 0,
            new_session_id: None,
            message: Some(error.to_string()),
        }
    }

    fn replacement_session_failed(report: SecureDeleteReport, error: impl ToString) -> Self {
        Self {
            outcome: SecureEraseOutcome::ReplacementSessionFailed,
            events_deleted: report.events_deleted,
            sessions_deleted: report.sessions_deleted,
            new_session_id: None,
            message: Some(error.to_string()),
        }
    }

    fn delete_committed(report: SecureDeleteReport, new_session_id: i64) -> Self {
        let outcome = if report.scrub_error.is_some() {
            SecureEraseOutcome::DeleteCommittedScrubIncomplete
        } else {
            SecureEraseOutcome::Completed
        };
        Self {
            outcome,
            events_deleted: report.events_deleted,
            sessions_deleted: report.sessions_deleted,
            new_session_id: Some(new_session_id),
            message: report.scrub_error,
        }
    }
}

fn apply_shutdown_busy_timeout_if_cancelled(store: &GilbrethStore, stop: &StopToken) {
    if !stop.is_cancelled() {
        return;
    }
    if let Err(error) = store.connection().busy_timeout(SHUTDOWN_BUSY_TIMEOUT) {
        warn!(%error, "failed to shorten sqlite busy timeout for writer shutdown");
    }
}

pub fn run_writer(
    store: GilbrethStore,
    rx: Receiver<WriterInput>,
    stop: StopToken,
    sequencer: Sequencer,
    policy: Policy,
    config: WriterConfig,
) -> Result<WriterReport, StoreError> {
    run_writer_with_commands(store, rx, never(), stop, sequencer, policy, config)
}

pub fn run_writer_with_commands(
    mut store: GilbrethStore,
    rx: Receiver<WriterInput>,
    command_rx: Receiver<WriterCommand>,
    stop: StopToken,
    mut sequencer: Sequencer,
    policy: Policy,
    config: WriterConfig,
) -> Result<WriterReport, StoreError> {
    let sqlite_interrupt = SqliteStopInterrupt::new(store.connection(), stop.clone());
    let mut batch = Vec::with_capacity(config.batch_size);
    let mut action_batch = Vec::with_capacity(config.batch_size);
    let mut report = WriterReport::default();
    let ticker = tick(config.flush_interval);
    let heartbeat_ticker = config.heartbeat_interval.map(tick).unwrap_or_else(never);
    let poll_ticker = config
        .record_request_poll_interval
        .map(tick)
        .unwrap_or_else(never);
    let stop_ticker = tick(WRITER_STOP_POLL_INTERVAL);
    let open_focus_ticker = tick(config.open_focus_beat_interval);
    let mut heartbeat = WriterHeartbeat::default();
    let mut record_state = WriterRecordState::default();
    let mut open_focus = OpenFocusState::default();
    // Set only after a secure-erase replacement session is successfully
    // created. It remains active for that replacement session and is cleared
    // if archive/reset later creates a different replacement session.
    let mut erase_completion_boundary_ms = None;
    let mut commands_open = true;

    loop {
        if commands_open {
            select! {
                recv(rx) -> msg => match msg {
                    Ok(input) => queue_writer_input(
                        input,
                        &mut WriterRuntime {
                            store: &mut store,
                            sequencer: &mut sequencer,
                            policy: &policy,
                            batch: &mut batch,
                            action_batch: &mut action_batch,
                            report: &mut report,
                            heartbeat: &mut heartbeat,
                            record_state: &mut record_state,
                            open_focus: &mut open_focus,
                            stop: &stop,
                            diagnostics: &config.diagnostics,
                            panic_action_cutoff: &config.panic_action_cutoff,
                            erase_completion_boundary_ms: &mut erase_completion_boundary_ms,
                            batch_size: config.batch_size,
                            timebase_drift_threshold_ms: config.timebase_drift_threshold_ms,
                        },
                    ),
                    Err(_) => break,
                },
                recv(command_rx) -> msg => match msg {
                    Ok(command) => handle_writer_command(
                        command,
                        &rx,
                        &mut WriterRuntime {
                            store: &mut store,
                            sequencer: &mut sequencer,
                            policy: &policy,
                            batch: &mut batch,
                            action_batch: &mut action_batch,
                            report: &mut report,
                            heartbeat: &mut heartbeat,
                            record_state: &mut record_state,
                            open_focus: &mut open_focus,
                            stop: &stop,
                            diagnostics: &config.diagnostics,
                            panic_action_cutoff: &config.panic_action_cutoff,
                            erase_completion_boundary_ms: &mut erase_completion_boundary_ms,
                            batch_size: config.batch_size,
                            timebase_drift_threshold_ms: config.timebase_drift_threshold_ms,
                        },
                    ),
                    Err(_) => commands_open = false,
                },
                recv(ticker) -> _ => flush_all_batches(&mut store, &mut batch, &mut action_batch, &mut report, &stop),
                recv(poll_ticker) -> _ => poll_recording_control(&store, &mut record_state, &config),
                recv(heartbeat_ticker) -> _ => log_writer_heartbeat(&store, &mut sequencer, &batch, &action_batch, &report, &mut heartbeat, &config),
                recv(open_focus_ticker) -> _ => beat_open_focus(&mut store, &mut sequencer, &mut open_focus),
                recv(stop_ticker) -> _ => {
                    if stop.is_cancelled() {
                        break;
                    }
                },
            }
        } else {
            select! {
                recv(rx) -> msg => match msg {
                    Ok(input) => queue_writer_input(
                        input,
                        &mut WriterRuntime {
                            store: &mut store,
                            sequencer: &mut sequencer,
                            policy: &policy,
                            batch: &mut batch,
                            action_batch: &mut action_batch,
                            report: &mut report,
                            heartbeat: &mut heartbeat,
                            record_state: &mut record_state,
                            open_focus: &mut open_focus,
                            stop: &stop,
                            diagnostics: &config.diagnostics,
                            panic_action_cutoff: &config.panic_action_cutoff,
                            erase_completion_boundary_ms: &mut erase_completion_boundary_ms,
                            batch_size: config.batch_size,
                            timebase_drift_threshold_ms: config.timebase_drift_threshold_ms,
                        },
                    ),
                    Err(_) => break,
                },
                recv(ticker) -> _ => flush_all_batches(&mut store, &mut batch, &mut action_batch, &mut report, &stop),
                recv(poll_ticker) -> _ => poll_recording_control(&store, &mut record_state, &config),
                recv(heartbeat_ticker) -> _ => log_writer_heartbeat(&store, &mut sequencer, &batch, &action_batch, &report, &mut heartbeat, &config),
                recv(open_focus_ticker) -> _ => beat_open_focus(&mut store, &mut sequencer, &mut open_focus),
                recv(stop_ticker) -> _ => {
                    if stop.is_cancelled() {
                        break;
                    }
                },
            }
        }
    }

    drop(sqlite_interrupt);
    drain_writer_inputs_until_quiet(
        &rx,
        &mut WriterRuntime {
            store: &mut store,
            sequencer: &mut sequencer,
            policy: &policy,
            batch: &mut batch,
            action_batch: &mut action_batch,
            report: &mut report,
            heartbeat: &mut heartbeat,
            record_state: &mut record_state,
            open_focus: &mut open_focus,
            stop: &stop,
            diagnostics: &config.diagnostics,
            panic_action_cutoff: &config.panic_action_cutoff,
            erase_completion_boundary_ms: &mut erase_completion_boundary_ms,
            batch_size: config.batch_size,
            timebase_drift_threshold_ms: config.timebase_drift_threshold_ms,
        },
    );
    apply_shutdown_busy_timeout_if_cancelled(&store, &stop);
    flush_all_batches(
        &mut store,
        &mut batch,
        &mut action_batch,
        &mut report,
        &stop,
    );
    // A clean stop leaves no open-focus row: the final focus rows are
    // flushed above, so a row present at the next open means an ungraceful
    // end — the invariant crash repair keys on.
    clear_open_focus(&mut open_focus, &mut store);
    let ended_at = sequencer.timestamp_for(std::time::Instant::now());
    if let Err(error) = store.finalize_open_record_sessions(RecordStopReason::AppShutdown, ended_at)
    {
        error!(%error, session_id = sequencer.session_id(), "failed to close open record sessions");
        return Err(error);
    }
    if let Err(error) = store.end_session(sequencer.session_id(), ended_at) {
        error!(%error, session_id = sequencer.session_id(), "failed to mark session ended");
        return Err(error);
    }
    // Persist the capture drop counter one last time: runs shorter than the
    // heartbeat interval would otherwise never write it.
    persist_diagnostics_counters(&store, &mut heartbeat, &config.diagnostics);
    info!(
        events_written = report.events_written,
        events_skipped = report.events_skipped,
        actions_written = report.actions_written,
        actions_skipped = report.actions_skipped,
        capture_events_dropped = config.diagnostics.capture_events_dropped(),
        stale_pre_erase_rows_dropped = config.diagnostics.stale_pre_erase_rows_dropped(),
        "writer stopped"
    );

    Ok(report)
}

fn queue_writer_input(input: WriterInput, runtime: &mut WriterRuntime<'_>) {
    match input {
        WriterInput::Motion(captured) => queue_captured(captured, runtime),
        WriterInput::Action(action) => queue_action(action, runtime),
        WriterInput::ActionDiag(_) | WriterInput::RejectedAction(_) => {}
    }
}

fn capture_predates_erase_boundary(capture_ts: i64, erase_completion_boundary_ms: i64) -> bool {
    capture_ts < erase_completion_boundary_ms
}

fn queue_captured(captured: Captured, runtime: &mut WriterRuntime<'_>) {
    if let Some(erase_completion_boundary_ms) = *runtime.erase_completion_boundary_ms {
        let capture_ts = runtime
            .sequencer
            .projected_timestamp_for(captured.captured_at);
        if capture_predates_erase_boundary(capture_ts, erase_completion_boundary_ms) {
            let stale_pre_erase_rows_dropped =
                runtime.diagnostics.increment_stale_pre_erase_rows_dropped();
            warn!(
                capture_ts,
                erase_completion_boundary_ms,
                stale_pre_erase_rows_dropped,
                event_kind = captured.payload.kind(),
                "dropped stale pre-erase capture row"
            );
            return;
        }
    }
    if let EventPayload::FocusChanged { window, .. } = &captured.payload {
        if !runtime.policy.excludes_exe(&window.exe) {
            runtime.record_state.excluded_gap_open = false;
        }
    }
    let resync_instant = Instant::now();
    let resync_utc_ms = unix_now_ms();
    resync_for_event_if_needed(
        runtime.sequencer,
        &captured.payload,
        resync_instant,
        resync_utc_ms,
        runtime.timebase_drift_threshold_ms,
    );
    let was_focus_change = matches!(&captured.payload, EventPayload::FocusChanged { .. });
    let Some(captured) = runtime.policy.apply_exclusions_to_captured(captured) else {
        if was_focus_change {
            // An excluded app took focus: its dropped row carried the open
            // segment's final dwell, so nothing may keep accruing to it —
            // the model mirrors the stored stream, which just went dark.
            clear_open_focus(runtime.open_focus, runtime.store);
        }
        return;
    };
    runtime.heartbeat.mark_event(captured.payload.kind());
    let event = runtime.sequencer.stamp(captured);
    let event = runtime.policy.apply_after_exclusions(event);
    note_open_focus_event(runtime.open_focus, runtime.store, &event);
    runtime.batch.push(event);
    if runtime.batch.len() >= runtime.batch_size {
        flush_batch(runtime.store, runtime.batch, runtime.report, runtime.stop);
    }
}

fn queue_action(mut action: ActionCapture, runtime: &mut WriterRuntime<'_>) {
    if runtime.record_state.active_record_session_id != Some(action.record_session_id) {
        runtime.report.actions_skipped += 1;
        debug!(
            record_session_id = action.record_session_id,
            active_record_session_id = runtime.record_state.active_record_session_id,
            action_type = action.action.action_type.as_str(),
            "dropping action capture for inactive record routine session"
        );
        return;
    }

    if runtime.panic_action_cutoff.rejects(&action) {
        runtime.report.actions_skipped += 1;
        debug!(
            record_session_id = action.record_session_id,
            action_type = action.action.action_type.as_str(),
            "dropping action captured at or after the panic boundary"
        );
        return;
    }

    if runtime
        .record_state
        .paused_record_session_id
        .is_some_and(|paused| paused == action.record_session_id)
    {
        runtime.report.actions_skipped += 1;
        debug!(
            record_session_id = action.record_session_id,
            action_type = action.action.action_type.as_str(),
            "dropping action capture while record routine is paused"
        );
        return;
    }

    if runtime.policy.sensitive_context_active() && !runtime.policy.excludes_action(&action) {
        runtime.report.actions_skipped += 1;
        debug!(
            record_session_id = action.record_session_id,
            action_type = action.action.action_type.as_str(),
            "dropping action capture during sensitive context"
        );
        return;
    }

    if runtime.policy.excludes_action(&action) {
        if !runtime.record_state.excluded_gap_open {
            // Store one value-free marker per contiguous excluded action run.
            // The source ActionCapture is discarded wholesale: no selector,
            // executable, framework, or payload from the excluded app crosses
            // the privacy boundary.
            let gap = ActionCapture {
                action: AutomationAction {
                    action_type: ActionType::UiActionOther,
                    selector_path: SelectorPath {
                        backend: "privacy_gap".to_string(),
                        hops: Vec::new(),
                    },
                    trust_basis: SelectorTrustBasis::ScopedInvokeSender,
                },
                captured_at: action.captured_at,
                record_session_id: action.record_session_id,
                exe: None,
                is_sensitive: false,
                has_name: false,
                pattern_action: Some(EXCLUDED_APP_GAP_PATTERN.to_string()),
                framework: "privacy_gap".to_string(),
                framework_class: FrameworkClass::Unknown,
                depth: 0,
                leaf_rect: None,
                payload: ActionPayload::UiActionOther {
                    raw_pattern_id: None,
                    from_modality: None,
                    corroborates: None,
                },
            };
            runtime.heartbeat.mark_event("ui_action_gap");
            runtime
                .action_batch
                .push(runtime.sequencer.stamp_action(gap));
            if runtime.action_batch.len() >= runtime.batch_size {
                flush_action_batch(
                    runtime.store,
                    runtime.action_batch,
                    runtime.report,
                    runtime.stop,
                );
            }
        }
        runtime.record_state.excluded_gap_open = true;
        return;
    }
    runtime.record_state.excluded_gap_open = false;

    debug_assert!(matches!(
        action.action.trust_basis,
        SelectorTrustBasis::PidMatch
            | SelectorTrustBasis::WindowOwnership
            | SelectorTrustBasis::ScopedInvokeSender
    ));
    action.is_sensitive = false;
    runtime.heartbeat.mark_event("ui_action");
    let action = runtime.sequencer.stamp_action(action);
    runtime.action_batch.push(action);
    if runtime.action_batch.len() >= runtime.batch_size {
        flush_action_batch(
            runtime.store,
            runtime.action_batch,
            runtime.report,
            runtime.stop,
        );
    }
}

struct WriterRuntime<'a> {
    store: &'a mut GilbrethStore,
    sequencer: &'a mut Sequencer,
    policy: &'a Policy,
    batch: &'a mut Vec<EventEnvelope>,
    action_batch: &'a mut Vec<StampedAction>,
    report: &'a mut WriterReport,
    heartbeat: &'a mut WriterHeartbeat,
    record_state: &'a mut WriterRecordState,
    open_focus: &'a mut OpenFocusState,
    stop: &'a StopToken,
    diagnostics: &'a DiagnosticsCounters,
    panic_action_cutoff: &'a PanicActionCutoff,
    erase_completion_boundary_ms: &'a mut Option<i64>,
    batch_size: usize,
    timebase_drift_threshold_ms: i64,
}

/// The writer's open foreground segment, mirrored from the stored row stream
/// (foreground-heartbeat design, decisions 1-2). A stored `FocusChanged`
/// names the newly open window unless it is a self-close row (`prev` equals
/// `window` — the shape every capture close path emits for a segment that
/// ended with no successor); boundary rows and exclusion-dropped focus rows
/// end the segment outright. The single `open_focus` DB row is written only
/// by the beat, and `row_written` remembers whether one exists so clears and
/// replacements delete it exactly when a stale row could otherwise survive
/// into crash repair and double-count a dwell the stream already recorded.
#[derive(Default)]
struct OpenFocusState {
    segment: Option<OpenSegment>,
    row_written: bool,
}

struct OpenSegment {
    session_id: i64,
    exe: String,
    started_ts: i64,
}

/// End the open segment and remove its DB row if one was beaten out.
fn clear_open_focus(state: &mut OpenFocusState, store: &mut GilbrethStore) {
    state.segment = None;
    if state.row_written {
        if let Err(error) = store.delete_open_focus() {
            warn!(%error, "failed to clear the open-focus row");
        } else {
            state.row_written = false;
        }
    }
}

/// Track the open segment from the stored stream. Runs on every event the
/// writer actually queues, after stamping, so the segment carries the same
/// session and timestamp the row does.
fn note_open_focus_event(
    state: &mut OpenFocusState,
    store: &mut GilbrethStore,
    event: &EventEnvelope,
) {
    match &event.payload {
        EventPayload::FocusChanged { window, prev, .. } => {
            if prev.as_ref() == Some(window) {
                clear_open_focus(state, store);
            } else {
                // Replacing a segment whose row was already beaten out must
                // drop that row now: the replacing row just recorded the old
                // segment's dwell, and a crash before the next beat would
                // otherwise synthesize it a second time.
                if state.row_written {
                    clear_open_focus(state, store);
                }
                state.segment = Some(OpenSegment {
                    session_id: event.session_id,
                    exe: exe_basename(&window.exe),
                    started_ts: event.ts_unix_ms,
                });
            }
        }
        EventPayload::PowerSuspend { .. }
        | EventPayload::SessionLock { .. }
        | EventPayload::SessionDisconnect { .. }
        | EventPayload::CapturePaused => {
            clear_open_focus(state, store);
        }
        _ => {}
    }
}

/// One open-focus beat: re-stamp the single row's high-water mark while a
/// segment is open. The row is the crash evidence — a crash mid-segment
/// loses at most one beat of dwell (a crash inside a close path's
/// delete-then-flush window loses that segment instead: the deliberate
/// trade, since the reverse order would double-count), and a clean shutdown
/// deletes it, so a row present at the next open means an ungraceful end.
fn beat_open_focus(
    store: &mut GilbrethStore,
    sequencer: &mut Sequencer,
    state: &mut OpenFocusState,
) {
    let Some(segment) = &state.segment else {
        return;
    };
    let high_water = sequencer
        .timestamp_for(Instant::now())
        .max(segment.started_ts);
    match store.upsert_open_focus(
        segment.session_id,
        &segment.exe,
        segment.started_ts,
        high_water,
    ) {
        Ok(()) => state.row_written = true,
        Err(error) => warn!(%error, "open-focus beat failed"),
    }
}

#[derive(Default)]
struct WriterRecordState {
    active_record_session_id: Option<i64>,
    paused_record_session_id: Option<i64>,
    last_surfaced_request_id: Option<i64>,
    cap_prompted_windows: HashMap<i64, i64>,
    excluded_gap_open: bool,
}

fn handle_writer_command(
    command: WriterCommand,
    rx: &Receiver<WriterInput>,
    runtime: &mut WriterRuntime<'_>,
) {
    match command {
        WriterCommand::ForgetFocusAttribution { ack } => {
            // Drain queued rows before forgetting: a FocusChanged applied
            // after the forget would re-arm the latch with a stale verdict
            // for the entire off period. The sender closes the Foreground
            // gate and flushes the capture forwarder before sending, so on
            // the ordinary path every in-flight FocusChanged already sits in
            // `rx` here and a try_recv sweep suffices without a quiet-period
            // stall. If that flush timed out, a straggler FocusChanged can
            // still apply after this sweep and re-arm the latch — the
            // sender's doc records that accepted double-failure residue.
            drain_writer_inputs(rx, runtime);
            runtime.policy.forget_focus_attribution();
            // The Foreground gate is the one segment-closing path that emits
            // no stored row on either platform (Windows keeps its state
            // machine running silently; macOS drops the close row at the
            // send gate), so this command doubles as the open-focus clear
            // signal (foreground-heartbeat design, decision 2 close set).
            clear_open_focus(runtime.open_focus, runtime.store);
            let _ = ack.send(());
        }
        WriterCommand::StartRecording {
            request_id,
            title,
            policy_snapshot_json,
            safety_cap_ms,
            visible_indicator,
            reply,
        } => {
            let result = start_recording(
                runtime,
                request_id,
                title.as_deref(),
                policy_snapshot_json.as_str(),
                safety_cap_ms,
                visible_indicator,
            )
            .map_err(|error| error.to_string());
            let _ = reply.send(result);
        }
        WriterCommand::StopRecording {
            record_session_id,
            stop_reason,
            reply,
        } => {
            let result = stop_recording(rx, runtime, record_session_id, stop_reason)
                .map_err(|error| error.to_string());
            let _ = reply.send(result);
        }
        WriterCommand::PauseRecording {
            record_session_id,
            reply,
        } => {
            let result =
                pause_recording(runtime, record_session_id).map_err(|error| error.to_string());
            let _ = reply.send(result);
        }
        WriterCommand::ResumeRecording {
            record_session_id,
            reply,
        } => {
            let result =
                resume_recording(runtime, record_session_id).map_err(|error| error.to_string());
            let _ = reply.send(result);
        }
        WriterCommand::ExtendCap { record_session_id } => {
            debug!(record_session_id, "record routine safety cap extended");
        }
        WriterCommand::DeclineRecordRequest { request_id } => {
            if let Err(error) = runtime
                .store
                .cancel_record_request(request_id, runtime.sequencer.timestamp_for(Instant::now()))
            {
                warn!(%error, request_id, "failed to cancel declined record request");
            }
            if runtime.record_state.last_surfaced_request_id == Some(request_id) {
                runtime.record_state.last_surfaced_request_id = None;
            }
        }
        WriterCommand::SecureErase {
            session_identity,
            reply,
        } => {
            let erase_report = secure_erase(rx, runtime, &session_identity);
            let _ = reply.send(erase_report);
        }
        WriterCommand::ArchiveAndReset {
            archive_path,
            session_identity,
            reply,
        } => {
            let archive_report = archive_and_reset(rx, runtime, &archive_path, &session_identity);
            let _ = reply.send(archive_report);
        }
    }
}

fn start_recording(
    runtime: &mut WriterRuntime<'_>,
    request_id: Option<i64>,
    title: Option<&str>,
    policy_snapshot_json: &str,
    safety_cap_ms: i64,
    visible_indicator: bool,
) -> Result<i64, StoreError> {
    let started_ts = runtime.sequencer.timestamp_for(Instant::now());
    if let Some(request_id) = request_id {
        runtime
            .store
            .confirm_record_request(request_id, started_ts)
            .inspect_err(|error| {
                warn!(%error, request_id, "failed to confirm record request before start");
            })?;
    }

    let result = runtime.store.open_record_session(OpenRecordSessionParams {
        request_id,
        session_id: runtime.sequencer.session_id(),
        started_ts,
        title,
        policy_snapshot_json,
        safety_cap_ms,
        visible_indicator,
    });
    match result {
        Ok(record_session_id) => {
            runtime.record_state.active_record_session_id = Some(record_session_id);
            runtime.record_state.paused_record_session_id = None;
            runtime
                .record_state
                .cap_prompted_windows
                .remove(&record_session_id);
            if runtime.record_state.last_surfaced_request_id == request_id {
                runtime.record_state.last_surfaced_request_id = None;
            }
            info!(record_session_id, request_id, "record routine started");
            Ok(record_session_id)
        }
        Err(error) => {
            if let Some(request_id) = request_id {
                if let Err(mark_error) = runtime.store.fail_record_request(request_id, started_ts) {
                    warn!(%mark_error, request_id, "failed to mark record request failed");
                }
            }
            Err(error)
        }
    }
}

fn stop_recording(
    rx: &Receiver<WriterInput>,
    runtime: &mut WriterRuntime<'_>,
    record_session_id: i64,
    stop_reason: RecordStopReason,
) -> Result<(), StoreError> {
    drain_writer_inputs(rx, runtime);
    flush_all_batches(
        runtime.store,
        runtime.batch,
        runtime.action_batch,
        runtime.report,
        runtime.stop,
    );
    let ended_ts = runtime.sequencer.timestamp_for(Instant::now());
    runtime
        .store
        .close_record_session(record_session_id, ended_ts, stop_reason)?;
    if runtime.record_state.active_record_session_id == Some(record_session_id) {
        runtime.record_state.active_record_session_id = None;
    }
    if runtime.record_state.paused_record_session_id == Some(record_session_id) {
        runtime.record_state.paused_record_session_id = None;
    }
    runtime
        .record_state
        .cap_prompted_windows
        .remove(&record_session_id);
    info!(
        record_session_id,
        stop_reason = stop_reason.as_str(),
        "record routine stopped"
    );
    Ok(())
}

fn drain_writer_inputs(rx: &Receiver<WriterInput>, runtime: &mut WriterRuntime<'_>) {
    while let Ok(input) = rx.try_recv() {
        queue_writer_input(input, runtime);
    }
}

fn drain_writer_inputs_until_quiet(rx: &Receiver<WriterInput>, runtime: &mut WriterRuntime<'_>) {
    let mut quiet_deadline = Instant::now() + WRITER_SHUTDOWN_DRAIN_QUIET_PERIOD;
    loop {
        let now = Instant::now();
        if now >= quiet_deadline {
            break;
        }
        match rx.recv_timeout(quiet_deadline.saturating_duration_since(now)) {
            Ok(input) => {
                queue_writer_input(input, runtime);
                quiet_deadline = Instant::now() + WRITER_SHUTDOWN_DRAIN_QUIET_PERIOD;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => break,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn pause_recording(
    runtime: &mut WriterRuntime<'_>,
    record_session_id: i64,
) -> Result<(), StoreError> {
    let paused_ts = runtime.sequencer.timestamp_for(Instant::now());
    runtime
        .store
        .pause_record_session(record_session_id, paused_ts)?;
    runtime.record_state.paused_record_session_id = Some(record_session_id);
    info!(record_session_id, "record routine paused");
    Ok(())
}

fn resume_recording(
    runtime: &mut WriterRuntime<'_>,
    record_session_id: i64,
) -> Result<(), StoreError> {
    let resumed_ts = runtime.sequencer.timestamp_for(Instant::now());
    runtime
        .store
        .resume_record_session(record_session_id, resumed_ts)?;
    if runtime.record_state.paused_record_session_id == Some(record_session_id) {
        runtime.record_state.paused_record_session_id = None;
    }
    info!(record_session_id, "record routine resumed");
    Ok(())
}

fn poll_recording_control(
    store: &GilbrethStore,
    state: &mut WriterRecordState,
    config: &WriterConfig,
) {
    let now_ms = unix_now_ms();
    if let Err(error) = store.expire_record_requests(now_ms) {
        warn!(%error, "failed to expire old record requests");
    }
    if let Some(request_id) = state.last_surfaced_request_id {
        match record_request_status(store.connection(), request_id) {
            Ok(Some(status)) if status == RecordRequestStatus::Requested.as_str() => {
                if state.active_record_session_id.is_none() && !prompt_in_flight(config) {
                    // A tray-side race can drain and drop a notification while a manual
                    // recording dialog grabs the prompt flag. Re-arm the still-requested
                    // row once prompts are idle so the mailbox cannot wedge for its TTL.
                    // A duplicate re-send is benign: request confirmation is CAS-guarded
                    // on `status='requested'`, so only one dialog can ever start it.
                    state.last_surfaced_request_id = None;
                }
            }
            Ok(_) => state.last_surfaced_request_id = None,
            Err(error) => {
                warn!(%error, request_id, "failed to read surfaced record request status")
            }
        }
    }

    poll_record_request_prompt(store, state, config, now_ms);
    poll_cap_prompt(store, state, config, now_ms);
}

fn poll_record_request_prompt(
    store: &GilbrethStore,
    state: &mut WriterRecordState,
    config: &WriterConfig,
    now_ms: i64,
) {
    if state.active_record_session_id.is_some() || prompt_in_flight(config) {
        return;
    }
    let Some(notify) = &config.record_request_notify else {
        return;
    };
    let request = match store.oldest_pending_record_request(now_ms) {
        Ok(Some(request)) => request,
        Ok(None) => return,
        Err(error) => {
            warn!(%error, "failed to poll record requests");
            return;
        }
    };
    if state.last_surfaced_request_id == Some(request.request_id) {
        return;
    }
    if let Err(error) = ensure_value_free_json(&request.candidate_json, "candidate_json") {
        warn!(%error, request_id = request.request_id, "record request failed value-free guard");
        if let Err(mark_error) = store.fail_record_request(request.request_id, now_ms) {
            warn!(%mark_error, request_id = request.request_id, "failed to mark invalid record request failed");
        }
        return;
    }
    if notify.try_send(request.clone()).is_ok() {
        state.last_surfaced_request_id = Some(request.request_id);
    }
}

fn poll_cap_prompt(
    store: &GilbrethStore,
    state: &mut WriterRecordState,
    config: &WriterConfig,
    now_ms: i64,
) {
    if prompt_in_flight(config) {
        return;
    }
    let Some(notify) = &config.cap_prompt_notify else {
        return;
    };
    let sessions = match store.open_record_sessions() {
        Ok(sessions) => sessions,
        Err(error) => {
            warn!(%error, "failed to poll open record sessions for cap prompt");
            return;
        }
    };
    for session in sessions {
        if session.safety_cap_ms <= 0 {
            continue;
        }
        let paused_total_ms =
            paused_total_ms_at(&session.pause_intervals_json, now_ms).unwrap_or_else(|error| {
                warn!(%error, record_session_id = session.record_session_id, "failed to parse pause intervals for cap prompt");
                0
            });
        let elapsed_active_ms = now_ms
            .saturating_sub(session.started_ts)
            .saturating_sub(paused_total_ms)
            .max(0);
        let window_index = elapsed_active_ms / session.safety_cap_ms;
        if window_index <= 0 {
            continue;
        }
        if state
            .cap_prompted_windows
            .get(&session.record_session_id)
            .is_some_and(|prompted| *prompted >= window_index)
        {
            continue;
        }
        let prompt = CapPrompt {
            record_session_id: session.record_session_id,
            window_index,
            elapsed_active_ms,
            safety_cap_ms: session.safety_cap_ms,
        };
        if notify.try_send(prompt).is_ok() {
            state
                .cap_prompted_windows
                .insert(session.record_session_id, window_index);
            return;
        }
    }
}

fn prompt_in_flight(config: &WriterConfig) -> bool {
    config
        .record_prompt_in_flight
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::SeqCst))
}

fn secure_erase(
    rx: &Receiver<WriterInput>,
    runtime: &mut WriterRuntime<'_>,
    session_identity: &SessionIdentity,
) -> SecureEraseReport {
    // The tray refuses privacy actions while a recording is live, but that
    // guard is UI-thread state; the writer's record state is authoritative,
    // so refuse here too rather than silently closing a live recording at the
    // delete boundary. (Stale open record sessions from a crashed prior run
    // have no in-memory state and are still finalized below.)
    if let Some(record_session_id) = runtime.record_state.active_record_session_id {
        warn!(
            record_session_id,
            "secure erase refused: a record routine session is still open"
        );
        return SecureEraseReport::delete_failed(
            "a Record Routine is still active; stop the recording and retry",
        );
    }
    // The app has suspended capture and flushed the capture-forwarder hop.
    // Quiet-drain the writer channel as well so pre-suspension rows are flushed
    // into the old session before deletion, not stamped into the replacement.
    drain_writer_inputs_until_quiet(rx, runtime);
    flush_all_batches(
        runtime.store,
        runtime.batch,
        runtime.action_batch,
        runtime.report,
        runtime.stop,
    );
    let reset_ended_at = runtime.sequencer.timestamp_for(Instant::now());
    if let Err(error) = runtime
        .store
        .finalize_open_record_sessions(RecordStopReason::AppShutdown, reset_ended_at)
    {
        error!(%error, "secure erase could not finalize open record sessions");
        return SecureEraseReport::delete_failed(error);
    }
    runtime.record_state.active_record_session_id = None;
    runtime.record_state.paused_record_session_id = None;
    runtime.record_state.cap_prompted_windows.clear();

    let delete_report = match runtime.store.secure_delete_activity() {
        Ok(report) => report,
        Err(error) => {
            error!(%error, "secure erase delete failed");
            return SecureEraseReport::delete_failed(error);
        }
    };
    // The delete removed every `meta` row, including the persisted capture
    // drop counter. Rebase at the next persist so the pre-erase total is not
    // resurrected from the in-memory cache.
    // Rebase immediately at the delete boundary. Delaying the offset until
    // the next heartbeat could misclassify a post-erase drop as pre-erase and
    // hide the very residual this gate is meant to report.
    runtime.heartbeat.capture_dropped_offset = runtime.diagnostics.capture_events_dropped();
    runtime.heartbeat.capture_dropped_base = Some(0);
    runtime.heartbeat.capture_dropped_persisted = None;
    runtime.heartbeat.capture_dropped_reset_pending = false;
    runtime.heartbeat.stale_pre_erase_dropped_offset =
        runtime.diagnostics.stale_pre_erase_rows_dropped();
    runtime.heartbeat.stale_pre_erase_dropped_base = Some(0);
    runtime.heartbeat.stale_pre_erase_dropped_persisted = None;
    runtime.heartbeat.stale_pre_erase_dropped_reset_pending = false;

    match create_replacement_session(runtime, session_identity) {
        Ok(new_session_id) => {
            let erase_completed_at = Instant::now();
            let erase_completion_boundary_ms = runtime
                .sequencer
                .projected_timestamp_for(erase_completed_at);
            *runtime.erase_completion_boundary_ms = Some(erase_completion_boundary_ms);
            // The wipe removed the open_focus row with everything else, and
            // the tracked segment belonged to the erased session.
            runtime.open_focus.segment = None;
            runtime.open_focus.row_written = false;
            reemit_active_sensitive_contexts(runtime, erase_completed_at);
            let report = SecureEraseReport::delete_committed(delete_report, new_session_id);
            match report.outcome {
                SecureEraseOutcome::Completed => {
                    info!(
                        events_deleted = report.events_deleted,
                        sessions_deleted = report.sessions_deleted,
                        new_session_id,
                        erase_completion_boundary_ms,
                        "secure erase completed"
                    );
                }
                SecureEraseOutcome::DeleteCommittedScrubIncomplete => {
                    warn!(
                        events_deleted = report.events_deleted,
                        sessions_deleted = report.sessions_deleted,
                        new_session_id,
                        erase_completion_boundary_ms,
                        message = ?report.message,
                        "secure erase deleted rows but scrub was incomplete"
                    );
                }
                SecureEraseOutcome::DeleteFailed | SecureEraseOutcome::ReplacementSessionFailed => {
                }
            };
            report
        }
        Err(error) => {
            error!(%error, "secure erase replacement session failed");
            SecureEraseReport::replacement_session_failed(delete_report, error)
        }
    }
}

fn archive_and_reset(
    rx: &Receiver<WriterInput>,
    runtime: &mut WriterRuntime<'_>,
    archive_path: &Path,
    session_identity: &SessionIdentity,
) -> ArchiveResetReport {
    // Same authoritative refusal as secure erase: never archive-and-delete
    // across a live recording, whatever the tray-side guard believed.
    if let Some(record_session_id) = runtime.record_state.active_record_session_id {
        warn!(
            record_session_id,
            "archive and reset refused: a record routine session is still open"
        );
        return ArchiveResetReport::archive_failed(
            archive_path,
            "a Record Routine is still active; stop the recording and retry",
        );
    }
    // Same ordering as secure erase: archive only after the capture-forwarder
    // hop has been flushed and the writer channel is quiet.
    drain_writer_inputs_until_quiet(rx, runtime);
    flush_all_batches(
        runtime.store,
        runtime.batch,
        runtime.action_batch,
        runtime.report,
        runtime.stop,
    );

    let archive_ended_at = runtime.sequencer.timestamp_for(Instant::now());
    if let Err(error) = runtime
        .store
        .finalize_open_record_sessions(RecordStopReason::AppShutdown, archive_ended_at)
    {
        error!(%error, "archive and reset could not finalize open record sessions");
        return ArchiveResetReport::archive_failed(archive_path, error);
    }
    runtime.record_state.active_record_session_id = None;
    runtime.record_state.paused_record_session_id = None;
    runtime.record_state.cap_prompted_windows.clear();
    let archive = match runtime
        .store
        .archive_activity_to(archive_path, archive_ended_at)
    {
        Ok(report) => report,
        Err(error) => {
            error!(%error, archive_file = %log_file_name(archive_path), "activity archive failed");
            return ArchiveResetReport::archive_failed(archive_path, error);
        }
    };

    let delete_report = match runtime.store.secure_delete_activity() {
        Ok(report) => report,
        Err(error) => {
            error!(%error, archive_file = %log_file_name(&archive.archive_path), "archive completed but reset delete failed");
            return ArchiveResetReport::delete_failed(archive, error);
        }
    };

    match create_replacement_session(runtime, session_identity) {
        Ok(new_session_id) => {
            // Archive/reset preserves capture rather than destroying it. A
            // delayed row that missed the archive belongs in the fresh live
            // DB, so an earlier secure-erase gate must not cross this reset.
            *runtime.erase_completion_boundary_ms = None;
            // The archive copy carried the open_focus row into stamping and
            // the live reset wiped it; the tracked segment belonged to the
            // archived session.
            runtime.open_focus.segment = None;
            runtime.open_focus.row_written = false;
            reemit_active_sensitive_contexts(runtime, Instant::now());
            let report =
                ArchiveResetReport::reset_committed(archive, delete_report, new_session_id);
            match report.outcome {
                ArchiveResetOutcome::Completed => {
                    info!(
                        archive_file = ?report.archive_path.as_deref().map(log_file_name),
                        events_archived = report.events_archived,
                        sessions_archived = report.sessions_archived,
                        events_deleted = report.events_deleted,
                        sessions_deleted = report.sessions_deleted,
                        new_session_id,
                        "archive and reset completed"
                    );
                }
                ArchiveResetOutcome::DeleteCommittedScrubIncomplete => {
                    warn!(
                        archive_file = ?report.archive_path.as_deref().map(log_file_name),
                        events_archived = report.events_archived,
                        sessions_archived = report.sessions_archived,
                        events_deleted = report.events_deleted,
                        sessions_deleted = report.sessions_deleted,
                        new_session_id,
                        message = ?report.message,
                        "archive and reset deleted rows but scrub was incomplete"
                    );
                }
                ArchiveResetOutcome::ArchiveFailed
                | ArchiveResetOutcome::DeleteFailed
                | ArchiveResetOutcome::ReplacementSessionFailed => {}
            };
            report
        }
        Err(error) => {
            error!(%error, "archive and reset replacement session failed");
            ArchiveResetReport::replacement_session_failed(archive, delete_report, error)
        }
    }
}

fn create_replacement_session(
    runtime: &mut WriterRuntime<'_>,
    session_identity: &SessionIdentity,
) -> Result<i64, StoreError> {
    let timebase = SessionTimebase::start_now();
    let replacement_identity =
        identity_with_default_run_label(session_identity.clone(), timebase.base_utc_ms());
    runtime.store.mint_meta_identity(timebase.base_utc_ms())?;
    let new_session_id = runtime
        .store
        .create_session_with_identity(timebase.base_utc_ms(), &replacement_identity)?;
    *runtime.sequencer = Sequencer::new(new_session_id, timebase);
    Ok(new_session_id)
}

fn reemit_active_sensitive_contexts(runtime: &mut WriterRuntime<'_>, now: Instant) {
    for reason in runtime.policy.active_sensitive_reasons() {
        queue_captured(
            Captured::new(
                Source::System,
                now,
                EventPayload::SensitiveContextEntered { reason },
            ),
            runtime,
        );
    }
}

/// File name only, for log lines: archive/db paths carry user directories
/// (usernames, client folders), which retained logs must not (S7).
fn log_file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<none>".to_string())
}

fn stamp_archive_open_sessions(archive_path: &Path, ended_at: i64) -> Result<(), StoreError> {
    let archive = Connection::open(archive_path)?;
    // VACUUM INTO copied the open_focus row as-is; the archive must be
    // self-contained, so it gets the same synthesize-and-clear treatment as
    // crash repair, before the session stamp below can land on the
    // synthesized timestamp. Usually a no-op: the suspension that precedes
    // a privacy operation already closed the segment and cleared the row.
    repair_open_focus(&archive)?;
    archive.execute(
        "UPDATE sessions SET ended_at = ?1 WHERE ended_at IS NULL",
        params![ended_at],
    )?;
    archive.execute(
        "
        UPDATE record_sessions
           SET ended_ts = max(started_ts, ?1), stop_reason = ?2
         WHERE ended_ts IS NULL
        ",
        params![ended_at, RecordStopReason::AppShutdown.as_str()],
    )?;
    checkpoint_truncate_verified(&archive)?;
    Ok(())
}

fn remove_archive_temporary_file(path: &Path, label: &'static str) {
    if let Err(remove_error) = fs::remove_file(path) {
        if remove_error.kind() != std::io::ErrorKind::NotFound {
            warn!(
                %remove_error,
                archive_file = %log_file_name(path),
                %label,
                "failed to remove archive temporary file"
            );
        }
    }
}

/// Overwrite and remove the complete plaintext SQLite staging set.
///
/// `stamp_archive_open_sessions` can cause SQLite to create transient WAL,
/// shared-memory, or rollback-journal siblings. Even though a clean close
/// normally removes those files, every archive exit path treats them as part
/// of the plaintext staging database and scrubs any that remain.
fn scrub_archive_plaintext_staging(path: &Path) -> std::io::Result<()> {
    let mut candidates = Vec::with_capacity(4);
    candidates.push(path.to_path_buf());
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sibling = path.as_os_str().to_os_string();
        sibling.push(suffix);
        candidates.push(PathBuf::from(sibling));
    }

    let mut first_error = None;
    for candidate in candidates {
        if let Err(error) = scrub_and_remove_archive_plaintext_file(&candidate) {
            warn!(
                %error,
                archive_file = %log_file_name(&candidate),
                "failed to scrub archive plaintext staging file"
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Zero-fill then remove one regular file. If removal itself fails, the file
/// is left containing zeros rather than archive plaintext.
fn scrub_and_remove_archive_plaintext_file(path: &Path) -> std::io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to scrub an archive staging link or non-file",
        ));
    }

    let mut remaining = metadata.len();
    if remaining > 0 {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let zeros = [0_u8; 64 * 1024];
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(true)
}

#[cfg(all(test, windows))]
fn inject_archive_verification_failure(path: &Path) {
    INJECTED_ARCHIVE_VERIFICATION_FAILURES
        .lock()
        .expect("archive verification injection mutex")
        .insert(path.to_path_buf());
}

#[cfg(test)]
fn take_injected_archive_verification_failure(path: &Path) -> bool {
    INJECTED_ARCHIVE_VERIFICATION_FAILURES
        .lock()
        .expect("archive verification injection mutex")
        .remove(path)
}

#[cfg(windows)]
pub fn default_db_path() -> Result<PathBuf, StoreError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(StoreError::MissingLocalAppData)?;
    Ok(PathBuf::from(local_app_data)
        .join("Gilbreth")
        .join("gilbreth.db"))
}

/// macOS twin of the Windows `%LOCALAPPDATA%\Gilbreth` default (MAC-0 seam;
/// the schema vocabulary record in `schema/README.md` keeps the two homes in
/// one place).
#[cfg(target_os = "macos")]
pub fn default_db_path() -> Result<PathBuf, StoreError> {
    let home = env::var_os("HOME").ok_or(StoreError::MissingHome)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Gilbreth")
        .join("gilbreth.db"))
}

fn identity_with_default_run_label(
    mut identity: SessionIdentity,
    started_at: i64,
) -> SessionIdentity {
    if identity.run_label.is_none() {
        identity.run_label = Some(format!("session-{started_at}"));
    }
    identity
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn ensure_value_free_json(json: &str, label: &str) -> Result<(), StoreError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(key) = first_forbidden_json_key(&value) {
        return Err(StoreError::RecordRoutine(format!(
            "{label} contains forbidden value-bearing key {key}"
        )));
    }
    if let Some(key) = first_unbounded_identifier(&value) {
        return Err(StoreError::RecordRoutine(format!(
            "{label} identifier {key} is over-long or carries control characters \
             (likely value-bearing content, not a stable identifier)"
        )));
    }
    Ok(())
}

fn first_forbidden_json_key(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.to_ascii_lowercase().as_str(), "name" | "value" | "text") {
                    return Some(key.as_str());
                }
                if let Some(found) = first_forbidden_json_key(value) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(values) => values.iter().find_map(first_forbidden_json_key),
        _ => None,
    }
}

/// Maximum length for a value-free selector identifier (`automation_id` /
/// `class_name`). Real identifiers are short and stable; a longer one is a sign
/// the app echoed user-visible content into the field.
const MAX_SELECTOR_IDENT_LEN: usize = 256;

/// A15 (priv-03): bound the developer-assigned, value-free selector identifiers.
/// `automation_id` / `class_name` are normally short, single-line, and stable, so
/// reject any selector whose identifier is over-long or carries control characters
/// (newlines/tabs) — both are tells that user-visible content leaked into the
/// field. (Comparing against the element Name to catch `AutomationId == Name` is
/// intentionally NOT done: it would require reading the Name string, which
/// value-free capture deliberately never reads — only `has_name` is recorded.)
fn first_unbounded_identifier(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "automation_id" | "class_name"
                ) {
                    if let serde_json::Value::String(text) = value {
                        if text.chars().count() > MAX_SELECTOR_IDENT_LEN
                            || text.chars().any(char::is_control)
                        {
                            return Some(key.as_str());
                        }
                    }
                }
                if let Some(found) = first_unbounded_identifier(value) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(values) => values.iter().find_map(first_unbounded_identifier),
        _ => None,
    }
}

/// Reduce an executable path to its file name. The value-free `exe`/`prev_exe`
/// columns (and the Record Routine action `exe`) must never store a full path,
/// which can embed the user-profile directory / username and an installed-app
/// inventory. The deliberate always-on process stream is the exception: both its
/// typed `exe` column and payload keep the full path when Windows exposes one.
fn exe_basename(path: &str) -> String {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    if name.is_empty() {
        path.to_string()
    } else {
        name.to_string()
    }
}

fn record_request_status(conn: &Connection, request_id: i64) -> Result<Option<String>, StoreError> {
    match conn.query_row(
        "SELECT status FROM record_requests WHERE request_id = ?1",
        [request_id],
        |row| row.get(0),
    ) {
        Ok(status) => Ok(Some(status)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(StoreError::Sqlite(error)),
    }
}

fn parse_pause_intervals(json: &str) -> Result<Vec<(i64, Option<i64>)>, StoreError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let Some(intervals) = value.as_array() else {
        return Err(StoreError::RecordRoutine(
            "pause_intervals_json must be an array".to_string(),
        ));
    };
    intervals
        .iter()
        .map(|interval| {
            let Some(items) = interval.as_array() else {
                return Err(StoreError::RecordRoutine(
                    "pause interval must be an array".to_string(),
                ));
            };
            if items.len() != 2 {
                return Err(StoreError::RecordRoutine(
                    "pause interval must have start and end".to_string(),
                ));
            }
            let start = items[0].as_i64().ok_or_else(|| {
                StoreError::RecordRoutine("pause interval start must be integer".to_string())
            })?;
            let end = if items[1].is_null() {
                None
            } else {
                Some(items[1].as_i64().ok_or_else(|| {
                    StoreError::RecordRoutine("pause interval end must be integer".to_string())
                })?)
            };
            Ok((start, end))
        })
        .collect()
}

fn paused_total_ms_at(json: &str, now_ms: i64) -> Result<i64, StoreError> {
    let intervals = parse_pause_intervals(json)?;
    Ok(intervals.into_iter().fold(0_i64, |total, (start, end)| {
        let end = end.unwrap_or(now_ms).max(start);
        total.saturating_add(end.saturating_sub(start))
    }))
}

fn flush_all_batches(
    store: &mut GilbrethStore,
    batch: &mut Vec<EventEnvelope>,
    action_batch: &mut Vec<StampedAction>,
    report: &mut WriterReport,
    stop: &StopToken,
) {
    apply_shutdown_busy_timeout_if_cancelled(store, stop);
    flush_batch(store, batch, report, stop);
    flush_action_batch(store, action_batch, report, stop);
}

fn flush_batch(
    store: &mut GilbrethStore,
    batch: &mut Vec<EventEnvelope>,
    report: &mut WriterReport,
    stop: &StopToken,
) {
    apply_shutdown_busy_timeout_if_cancelled(store, stop);
    flush_batch_with_insert_and_stop(batch, report, stop, |events| store.insert_events(events));
}

#[cfg(test)]
fn flush_batch_with_insert<F>(
    batch: &mut Vec<EventEnvelope>,
    report: &mut WriterReport,
    mut insert_events: F,
) where
    F: FnMut(&[EventEnvelope]) -> Result<InsertReport, StoreError>,
{
    let stop = StopToken::new();
    flush_batch_with_insert_and_stop(batch, report, &stop, &mut insert_events);
}

fn flush_batch_with_insert_and_stop<F>(
    batch: &mut Vec<EventEnvelope>,
    report: &mut WriterReport,
    stop: &StopToken,
    mut insert_events: F,
) where
    F: FnMut(&[EventEnvelope]) -> Result<InsertReport, StoreError>,
{
    if batch.is_empty() {
        return;
    }

    match insert_batch_with_retry(batch, &mut insert_events, stop) {
        Ok(insert_report) => {
            report.events_written += insert_report.inserted;
            report.events_skipped += insert_report.skipped;
            debug!(
                inserted = insert_report.inserted,
                skipped = insert_report.skipped,
                "flushed event batch"
            );
        }
        Err(error) => {
            report.events_skipped += batch.len();
            let (first_seq, last_seq) = batch_seq_range(batch).unwrap_or((0, 0));
            let retry_budget_exhausted = is_sqlite_busy_or_locked(&error);
            error!(
                %error,
                count = batch.len(),
                first_seq,
                last_seq,
                retry_budget_exhausted,
                "failed to commit event batch; dropping batch and continuing"
            );
        }
    }
    batch.clear();
}

fn flush_action_batch(
    store: &mut GilbrethStore,
    batch: &mut Vec<StampedAction>,
    report: &mut WriterReport,
    stop: &StopToken,
) {
    apply_shutdown_busy_timeout_if_cancelled(store, stop);
    flush_action_batch_with_insert_and_stop(batch, report, stop, |actions| {
        store.insert_actions(actions)
    });
}

#[cfg(test)]
fn flush_action_batch_with_insert<F>(
    batch: &mut Vec<StampedAction>,
    report: &mut WriterReport,
    mut insert_actions: F,
) where
    F: FnMut(&[StampedAction]) -> Result<InsertReport, StoreError>,
{
    let stop = StopToken::new();
    flush_action_batch_with_insert_and_stop(batch, report, &stop, &mut insert_actions);
}

fn flush_action_batch_with_insert_and_stop<F>(
    batch: &mut Vec<StampedAction>,
    report: &mut WriterReport,
    stop: &StopToken,
    mut insert_actions: F,
) where
    F: FnMut(&[StampedAction]) -> Result<InsertReport, StoreError>,
{
    if batch.is_empty() {
        return;
    }

    match insert_action_batch_with_retry(batch, &mut insert_actions, stop) {
        Ok(insert_report) => {
            report.actions_written += insert_report.inserted;
            report.actions_skipped += insert_report.skipped;
            debug!(
                inserted = insert_report.inserted,
                skipped = insert_report.skipped,
                "flushed action batch"
            );
        }
        Err(error) => {
            report.actions_skipped += batch.len();
            let (first_seq, last_seq) = action_batch_seq_range(batch).unwrap_or((0, 0));
            let retry_budget_exhausted = is_sqlite_busy_or_locked(&error);
            error!(
                %error,
                count = batch.len(),
                first_seq,
                last_seq,
                retry_budget_exhausted,
                "failed to commit action batch; dropping batch and continuing"
            );
        }
    }
    batch.clear();
}

fn insert_batch_with_retry<F>(
    batch: &[EventEnvelope],
    insert_events: &mut F,
    stop: &StopToken,
) -> Result<InsertReport, StoreError>
where
    F: FnMut(&[EventEnvelope]) -> Result<InsertReport, StoreError>,
{
    let mut busy_attempts = 0;
    loop {
        match insert_events(batch) {
            Ok(report) => return Ok(report),
            Err(error) if is_sqlite_busy_or_locked(&error) => {
                if busy_attempts >= SQLITE_BUSY_RETRY_ATTEMPTS {
                    return Err(error);
                }
                busy_attempts += 1;
                let (first_seq, last_seq) = batch_seq_range(batch).unwrap_or((0, 0));
                warn!(
                    %error,
                    count = batch.len(),
                    first_seq,
                    last_seq,
                    attempt = busy_attempts,
                    max_attempts = SQLITE_BUSY_RETRY_ATTEMPTS,
                    "event batch commit hit sqlite busy/locked; retrying with bounded backoff"
                );
                if SQLITE_BUSY_RETRY_DELAY > Duration::ZERO
                    && !sleep_before_busy_retry(SQLITE_BUSY_RETRY_DELAY, stop)
                {
                    return Err(error);
                }
            }
            Err(error) if stop.is_cancelled() && is_sqlite_interrupted(&error) => {
                if busy_attempts >= SQLITE_BUSY_RETRY_ATTEMPTS {
                    return Err(error);
                }
                busy_attempts += 1;
                let (first_seq, last_seq) = batch_seq_range(batch).unwrap_or((0, 0));
                warn!(
                    %error,
                    count = batch.len(),
                    first_seq,
                    last_seq,
                    attempt = busy_attempts,
                    max_attempts = SQLITE_BUSY_RETRY_ATTEMPTS,
                    "event batch commit was interrupted during shutdown; retrying final flush"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn insert_action_batch_with_retry<F>(
    batch: &[StampedAction],
    insert_actions: &mut F,
    stop: &StopToken,
) -> Result<InsertReport, StoreError>
where
    F: FnMut(&[StampedAction]) -> Result<InsertReport, StoreError>,
{
    let mut busy_attempts = 0;
    loop {
        match insert_actions(batch) {
            Ok(report) => return Ok(report),
            Err(error) if is_sqlite_busy_or_locked(&error) => {
                if busy_attempts >= SQLITE_BUSY_RETRY_ATTEMPTS {
                    return Err(error);
                }
                busy_attempts += 1;
                let (first_seq, last_seq) = action_batch_seq_range(batch).unwrap_or((0, 0));
                warn!(
                    %error,
                    count = batch.len(),
                    first_seq,
                    last_seq,
                    attempt = busy_attempts,
                    max_attempts = SQLITE_BUSY_RETRY_ATTEMPTS,
                    "action batch commit hit sqlite busy/locked; retrying with bounded backoff"
                );
                if SQLITE_BUSY_RETRY_DELAY > Duration::ZERO
                    && !sleep_before_busy_retry(SQLITE_BUSY_RETRY_DELAY, stop)
                {
                    return Err(error);
                }
            }
            Err(error) if stop.is_cancelled() && is_sqlite_interrupted(&error) => {
                if busy_attempts >= SQLITE_BUSY_RETRY_ATTEMPTS {
                    return Err(error);
                }
                busy_attempts += 1;
                let (first_seq, last_seq) = action_batch_seq_range(batch).unwrap_or((0, 0));
                warn!(
                    %error,
                    count = batch.len(),
                    first_seq,
                    last_seq,
                    attempt = busy_attempts,
                    max_attempts = SQLITE_BUSY_RETRY_ATTEMPTS,
                    "action batch commit was interrupted during shutdown; retrying final flush"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn sleep_before_busy_retry(duration: Duration, stop: &StopToken) -> bool {
    if stop.is_cancelled() {
        thread::sleep(duration);
        true
    } else {
        sleep_unless_stopped(duration, stop)
    }
}

fn sleep_unless_stopped(duration: Duration, stop: &StopToken) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if stop.is_cancelled() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
    !stop.is_cancelled()
}

fn is_sqlite_busy_or_locked(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Sqlite(sqlite) if is_rusqlite_busy_or_locked(sqlite)
    )
}

fn is_sqlite_interrupted(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Sqlite(sqlite) if is_rusqlite_interrupted(sqlite)
    )
}

fn is_rusqlite_busy_or_locked(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn is_rusqlite_interrupted(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::OperationInterrupted)
    )
}

fn batch_seq_range(batch: &[EventEnvelope]) -> Option<(u64, u64)> {
    Some((batch.first()?.seq, batch.last()?.seq))
}

fn action_batch_seq_range(batch: &[StampedAction]) -> Option<(u64, u64)> {
    Some((batch.first()?.seq, batch.last()?.seq))
}

fn resync_for_event_if_needed(
    sequencer: &mut Sequencer,
    payload: &EventPayload,
    now_instant: Instant,
    now_utc_ms: i64,
    threshold_ms: i64,
) -> Option<DriftCorrection> {
    if matches!(
        payload,
        EventPayload::PowerResume { .. } | EventPayload::PowerBoundaryRecovered { .. }
    ) {
        resync_sequencer_at(
            sequencer,
            now_instant,
            now_utc_ms,
            threshold_ms,
            "power boundary",
        )
    } else {
        None
    }
}

fn resync_sequencer_at(
    sequencer: &mut Sequencer,
    now_instant: Instant,
    now_utc_ms: i64,
    threshold_ms: i64,
    trigger: &'static str,
) -> Option<DriftCorrection> {
    let correction = sequencer.resync(now_instant, now_utc_ms, threshold_ms)?;
    info!(
        session_id = sequencer.session_id(),
        trigger,
        old_base_utc_ms = correction.old_base_utc_ms,
        new_base_utc_ms = correction.new_base_utc_ms,
        measured_drift_ms = correction.measured_drift_ms,
        clamp_ms = correction.clamp_ms,
        threshold_ms = correction.threshold_ms,
        "session timebase drift corrected"
    );
    Some(correction)
}

#[derive(Default)]
struct WriterHeartbeat {
    last_event_at: Option<Instant>,
    last_event_kind: Option<&'static str>,
    last_gap_explainer_at: Option<Instant>,
    last_gap_explainer_kind: Option<&'static str>,
    /// STORE-01: set once the main-DB-large warning has fired, so it warns once
    /// per threshold crossing rather than every heartbeat; cleared when the DB
    /// drops back below the threshold (e.g. after an archive/reset).
    main_db_size_warned: bool,
    /// Cross-run cumulative base for the capture drop counter, loaded from
    /// `meta` on first persist; `None` until then.
    capture_dropped_base: Option<u64>,
    /// Last cumulative total written to `meta`, to skip no-change writes.
    capture_dropped_persisted: Option<u64>,
    /// In-run drops already accounted before a secure erase reset the
    /// persisted counter; subtracted so post-erase totals restart cleanly.
    capture_dropped_offset: u64,
    /// Set by secure erase (which deletes `meta`); the next persist rebases
    /// instead of resurrecting the pre-erase total.
    capture_dropped_reset_pending: bool,
    /// The stale-pre-erase category mirrors the capture-side counter's
    /// durable/rebase lifecycle but remains separately named in Diagnostics.
    stale_pre_erase_dropped_base: Option<u64>,
    stale_pre_erase_dropped_persisted: Option<u64>,
    stale_pre_erase_dropped_offset: u64,
    stale_pre_erase_dropped_reset_pending: bool,
}

impl WriterHeartbeat {
    fn mark_event(&mut self, kind: &'static str) {
        self.mark_event_at(kind, Instant::now());
    }

    fn last_event_age_ms(&self) -> i64 {
        self.last_event_age_ms_at(Instant::now())
    }

    fn mark_event_at(&mut self, kind: &'static str, now: Instant) {
        self.last_event_at = Some(now);
        self.last_event_kind = Some(kind);
        if event_kind_explains_heartbeat_gap(kind) {
            self.last_gap_explainer_at = Some(now);
            self.last_gap_explainer_kind = Some(kind);
        }
    }

    fn last_event_age_ms_at(&self, now: Instant) -> i64 {
        self.last_event_at.map_or(-1, |last_event_at| {
            i64::try_from(now.saturating_duration_since(last_event_at).as_millis())
                .unwrap_or(i64::MAX)
        })
    }

    fn stale_warning_at(
        &self,
        now: Instant,
        warn_after: Option<Duration>,
    ) -> Option<HeartbeatStaleWarning> {
        let warn_after = warn_after?;
        let last_event_at = self.last_event_at?;
        if now.saturating_duration_since(last_event_at) <= warn_after {
            return None;
        }
        if self
            .last_gap_explainer_at
            .is_some_and(|explainer_at| explainer_at >= last_event_at)
        {
            return None;
        }

        Some(HeartbeatStaleWarning {
            last_event_age_ms: self.last_event_age_ms_at(now),
            last_event_kind: self.last_event_kind,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeartbeatStaleWarning {
    last_event_age_ms: i64,
    last_event_kind: Option<&'static str>,
}

fn event_kind_explains_heartbeat_gap(kind: &'static str) -> bool {
    matches!(
        kind,
        "power_suspend"
            | "power_resume"
            | "power_boundary_recovered"
            | "session_lock"
            | "session_unlock"
            | "session_connect"
            | "session_disconnect"
            | "sensitive_context_entered"
            | "sensitive_context_exited"
    )
}

/// `meta` key holding the cumulative (cross-run) capture-side drop count.
/// The in-memory atomic previously surfaced only in a clean-shutdown log
/// line, so a crash erased the evidence of loss; persisting it durably is
/// what lets `events_skipped=0` plus this key tell the whole zero-loss story
/// on the Diagnostics tab (S2).
const CAPTURE_EVENTS_DROPPED_META_KEY: &str = "capture_events_dropped";
const STALE_PRE_ERASE_ROWS_DROPPED_META_KEY: &str = "stale_pre_erase_rows_dropped";

fn read_meta_u64(conn: &Connection, key: &str) -> u64 {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    })
    .ok()
    .and_then(|value| value.parse().ok())
    .unwrap_or(0)
}

fn persist_capture_events_dropped(
    store: &GilbrethStore,
    heartbeat: &mut WriterHeartbeat,
    diagnostics: &DiagnosticsCounters,
) {
    if heartbeat.capture_dropped_reset_pending {
        heartbeat.capture_dropped_reset_pending = false;
        heartbeat.capture_dropped_offset = diagnostics.capture_events_dropped();
        heartbeat.capture_dropped_base = Some(0);
        heartbeat.capture_dropped_persisted = None;
    }
    let base = match heartbeat.capture_dropped_base {
        Some(base) => base,
        None => {
            let base = read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY);
            heartbeat.capture_dropped_base = Some(base);
            base
        }
    };
    let run_dropped = diagnostics
        .capture_events_dropped()
        .saturating_sub(heartbeat.capture_dropped_offset);
    let total = base.saturating_add(run_dropped);
    if heartbeat.capture_dropped_persisted == Some(total) {
        return;
    }
    match store.connection().execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![CAPTURE_EVENTS_DROPPED_META_KEY, total.to_string()],
    ) {
        Ok(_) => heartbeat.capture_dropped_persisted = Some(total),
        Err(error) => warn!(%error, "failed to persist capture_events_dropped counter"),
    }
}

fn persist_stale_pre_erase_rows_dropped(
    store: &GilbrethStore,
    heartbeat: &mut WriterHeartbeat,
    diagnostics: &DiagnosticsCounters,
) {
    if heartbeat.stale_pre_erase_dropped_reset_pending {
        heartbeat.stale_pre_erase_dropped_reset_pending = false;
        heartbeat.stale_pre_erase_dropped_offset = diagnostics.stale_pre_erase_rows_dropped();
        heartbeat.stale_pre_erase_dropped_base = Some(0);
        heartbeat.stale_pre_erase_dropped_persisted = None;
    }
    let base = match heartbeat.stale_pre_erase_dropped_base {
        Some(base) => base,
        None => {
            let base = read_meta_u64(store.connection(), STALE_PRE_ERASE_ROWS_DROPPED_META_KEY);
            heartbeat.stale_pre_erase_dropped_base = Some(base);
            base
        }
    };
    let run_dropped = diagnostics
        .stale_pre_erase_rows_dropped()
        .saturating_sub(heartbeat.stale_pre_erase_dropped_offset);
    let total = base.saturating_add(run_dropped);
    if heartbeat.stale_pre_erase_dropped_persisted == Some(total) {
        return;
    }
    match store.connection().execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![STALE_PRE_ERASE_ROWS_DROPPED_META_KEY, total.to_string()],
    ) {
        Ok(_) => heartbeat.stale_pre_erase_dropped_persisted = Some(total),
        Err(error) => warn!(%error, "failed to persist stale_pre_erase_rows_dropped counter"),
    }
}

fn persist_diagnostics_counters(
    store: &GilbrethStore,
    heartbeat: &mut WriterHeartbeat,
    diagnostics: &DiagnosticsCounters,
) {
    persist_capture_events_dropped(store, heartbeat, diagnostics);
    persist_stale_pre_erase_rows_dropped(store, heartbeat, diagnostics);
}

fn log_writer_heartbeat(
    store: &GilbrethStore,
    sequencer: &mut Sequencer,
    batch: &[EventEnvelope],
    action_batch: &[StampedAction],
    report: &WriterReport,
    heartbeat: &mut WriterHeartbeat,
    config: &WriterConfig,
) {
    let now = Instant::now();
    resync_sequencer_at(
        sequencer,
        now,
        unix_now_ms(),
        config.timebase_drift_threshold_ms,
        "writer heartbeat",
    );
    if let Some(warning) = heartbeat.stale_warning_at(now, config.stale_event_warn_after) {
        warn!(
            session_id = sequencer.session_id(),
            last_event_age_ms = warning.last_event_age_ms,
            last_event_kind = warning.last_event_kind,
            "writer heartbeat has not seen recent capture events"
        );
    }
    let db_bytes = store.main_db_file_size();
    info!(
        session_id = sequencer.session_id(),
        events_written = report.events_written,
        events_skipped = report.events_skipped,
        actions_written = report.actions_written,
        actions_skipped = report.actions_skipped,
        pending_batch = batch.len(),
        pending_action_batch = action_batch.len(),
        last_event_age_ms = heartbeat.last_event_age_ms(),
        wal_bytes = store.wal_file_size(),
        db_bytes,
        power_boundary_catches = config.diagnostics.power_boundary_catches(),
        capture_events_dropped = config.diagnostics.capture_events_dropped(),
        stale_pre_erase_rows_dropped = config.diagnostics.stale_pre_erase_rows_dropped(),
        "writer heartbeat"
    );
    persist_diagnostics_counters(store, heartbeat, &config.diagnostics);
    if db_bytes > MAIN_DB_SIZE_WARN_BYTES {
        if !heartbeat.main_db_size_warned {
            heartbeat.main_db_size_warned = true;
            warn!(
                session_id = sequencer.session_id(),
                db_bytes,
                warn_threshold_bytes = MAIN_DB_SIZE_WARN_BYTES,
                "main capture database is large (STORE-01); consider tightening \
                 privacy.retention_days or archiving/resetting the live DB"
            );
        }
    } else {
        heartbeat.main_db_size_warned = false;
    }

    // Reclaim freed pages (after prunes / erases) and then the WAL high-water
    // mark, both opportunistically, so a transient reader can't ratchet the
    // .db-wal up and freed space is returned to the OS during long runs.
    incremental_vacuum_opportunistic(store.connection());
    checkpoint_truncate_opportunistic(store.connection());
}

fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
    // auto_vacuum=INCREMENTAL takes effect only on a fresh DB (it must be set
    // before the first table is created); pre-existing auto_vacuum=NONE databases
    // keep their mode and adopt INCREMENTAL on the next archive/reset. It lets
    // incremental_vacuum (STORE-01) reclaim freed pages from prunes/erases without
    // a blocking full VACUUM.
    conn.execute_batch(
        "
        PRAGMA auto_vacuum = INCREMENTAL;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        ",
    )?;
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    Ok(())
}

/// Warn (STORE-01) when the main `.db` grows past this size during a run; a large
/// main DB slows queries and signals retention may need tightening. WAL reclaim is
/// handled separately by the opportunistic truncate checkpoint.
const MAIN_DB_SIZE_WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Reclaim a bounded number of freed pages (after prunes / secure erases) without
/// blocking the sole writer. A no-op on `auto_vacuum = NONE` databases. Bounded so
/// a single heartbeat never runs a long vacuum (256 pages ~= 1 MiB at 4 KiB pages).
fn incremental_vacuum_opportunistic(conn: &Connection) {
    // Like the WAL truncate, drop the busy timeout to zero first so a transient
    // reader can never stall the sole writer for the default 5 s; under contention
    // we simply reclaim at the next heartbeat. No-op on auto_vacuum=NONE databases.
    if conn.busy_timeout(Duration::ZERO).is_err() {
        return;
    }
    if let Err(error) = conn.execute_batch("PRAGMA incremental_vacuum(256);") {
        debug!(%error, "opportunistic incremental vacuum skipped");
    }
    if let Err(error) = conn.busy_timeout(DEFAULT_BUSY_TIMEOUT) {
        warn!(%error, "failed to restore SQLite busy timeout after incremental vacuum");
    }
}

/// TRUNCATE checkpoint that verifies completion by reading the result row.
///
/// A TRUNCATE checkpoint held off by a concurrent reader reports `busy=1` in
/// its result row without raising a SQLite error, so a fire-and-forget
/// `execute_batch` form would return `Ok` while the pre-delete page bytes stay
/// recoverable in the `-wal` file. Privacy-critical callers (secure erase, the
/// title scrub) must surface that deferral, so `busy != 0` becomes a
/// `SQLITE_BUSY` error here.
fn checkpoint_truncate_verified(conn: &Connection) -> Result<(), rusqlite::Error> {
    let (busy, log_frames, checkpointed_frames) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
    if busy != 0 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some(format!(
                "WAL truncate checkpoint deferred by a concurrent reader \
                 (busy={busy}, log={log_frames}, checkpointed={checkpointed_frames}); \
                 prior page bytes remain recoverable in the -wal file"
            )),
        ));
    }
    Ok(())
}

/// Reclaim the WAL high-water mark without ever blocking the sole writer.
///
/// In steady state SQLite's passive autocheckpoint recycles the WAL but never
/// shrinks the file, so a transient reader (e.g. the dashboard opening a
/// snapshot mid-checkpoint) ratchets the high-water mark up and it then stays
/// there for the rest of the run — the 2026-06-10..15 long run showed the
/// `.db-wal` jump from ~4.0 MB to ~6.8 MB the moment the dashboard launched and
/// never fall back. A `TRUNCATE` checkpoint reclaims it, but it needs a brief
/// exclusive moment a reader can hold off, so we drop `busy_timeout` to 0
/// first: if a reader is mid-read the checkpoint simply reports busy and we
/// reclaim at the next heartbeat instead of stalling capture for up to 5 s.
fn checkpoint_truncate_opportunistic(conn: &Connection) {
    if let Err(error) = conn.busy_timeout(Duration::ZERO) {
        debug!(%error, "opportunistic WAL truncate checkpoint skipped");
        return;
    }

    let checkpoint = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    });

    let restore = conn.busy_timeout(DEFAULT_BUSY_TIMEOUT);
    if let Err(error) = restore {
        warn!(%error, "failed to restore SQLite busy timeout after WAL checkpoint");
    }

    match checkpoint {
        Ok((0, log_frames, checkpointed_frames)) => {
            debug!(
                log_frames,
                checkpointed_frames, "opportunistic WAL truncate checkpoint completed"
            );
        }
        Ok((busy, log_frames, checkpointed_frames)) => {
            debug!(
                busy,
                log_frames, checkpointed_frames, "opportunistic WAL truncate checkpoint deferred"
            );
        }
        Err(error) => {
            debug!(%error, "opportunistic WAL truncate checkpoint skipped");
        }
    }
}

fn wal_path(path: &Path) -> PathBuf {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    PathBuf::from(wal)
}

fn secure_delete_setting(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA secure_delete", [], |row| row.get(0))?)
}

fn restore_secure_delete_setting(conn: &Connection, setting: i64) -> Result<(), StoreError> {
    match setting {
        0 => conn.execute_batch("PRAGMA secure_delete = OFF;")?,
        1 => conn.execute_batch("PRAGMA secure_delete = ON;")?,
        2 => conn.execute_batch("PRAGMA secure_delete = FAST;")?,
        _ => conn.pragma_update(None, "secure_delete", setting)?,
    }
    Ok(())
}

fn dashboard_readonly_connection(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    Ok(conn)
}

fn dashboard_writable_connection(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool, StoreError> {
    match conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |_| Ok(()),
    ) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(error) => Err(StoreError::Sqlite(error)),
    }
}

fn record_routine_tables_present_conn(conn: &Connection) -> Result<bool, StoreError> {
    for table in [
        "record_requests",
        "record_sessions",
        "selector_paths",
        "action_events",
    ] {
        if !sqlite_table_exists(conn, table)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn query_count<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<usize, StoreError> {
    let count: i64 = conn.query_row(sql, params, |row| row.get(0))?;
    Ok(count.max(0) as usize)
}

fn with_temporary_secure_delete<T>(
    conn: &mut Connection,
    operation: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let setting = secure_delete_setting(conn)?;
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    let result = operation(conn);
    let restore = restore_secure_delete_setting(conn, setting);
    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restore_error)) => {
            warn!(
                %restore_error,
                "failed to restore secure_delete after dashboard-owned write"
            );
            Err(error)
        }
    }
}

fn checkpoint_after_secure_delete(conn: &Connection) -> Option<String> {
    match checkpoint_truncate_verified(conn) {
        Ok(()) => None,
        Err(error) if is_rusqlite_busy_or_locked(&error) => Some(
            "the rows are gone from every view, but their bytes can remain in \
             the database file until a later idle moment because the database \
             was busy"
                .to_string(),
        ),
        Err(error) => Some(format!("the secure wipe could not run ({error})")),
    }
}

/// deletion_audit kinds — one per production deletion path. Secure erase is
/// exempt: it deletes the audit table with everything else.
const DELETION_AUDIT_KIND_STARTUP_RETENTION: &str = "startup_retention";
const DELETION_AUDIT_KIND_MOUSE_MOVE_RETENTION: &str = "mouse_move_retention";
const DELETION_AUDIT_KIND_DASHBOARD_PRUNE: &str = "dashboard_prune";
const DELETION_AUDIT_KIND_EVENT_DELETE: &str = "event_delete";
const DELETION_AUDIT_KIND_RECORDING_DELETE: &str = "recording_delete";

/// Per-session aggregate of one deletion operation's seq-bearing rows,
/// fed from `DELETE ... RETURNING session_id, seq` so the audit records
/// exactly what each statement removed — no mirrored predicate to drift.
/// BTreeMap keeps the audit rows in session order.
#[derive(Debug, Default)]
struct DeletionAuditAggregate {
    per_session: BTreeMap<i64, DeletionAuditSpan>,
}

#[derive(Debug, Clone, Copy)]
struct DeletionAuditSpan {
    rows_deleted: i64,
    seq_min: i64,
    seq_max: i64,
}

impl DeletionAuditAggregate {
    fn note(&mut self, session_id: i64, seq: i64) {
        self.per_session
            .entry(session_id)
            .and_modify(|span| {
                span.rows_deleted += 1;
                span.seq_min = span.seq_min.min(seq);
                span.seq_max = span.seq_max.max(seq);
            })
            .or_insert(DeletionAuditSpan {
                rows_deleted: 1,
                seq_min: seq,
                seq_max: seq,
            });
    }
}

/// Run a `DELETE ... RETURNING session_id, seq` statement, folding every
/// deleted row into the aggregate. Returns the deleted-row count.
fn delete_returning_audit<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
    aggregate: &mut DeletionAuditAggregate,
) -> Result<usize, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    let mut deleted = 0;
    while let Some(row) = rows.next()? {
        aggregate.note(row.get(0)?, row.get(1)?);
        deleted += 1;
    }
    Ok(deleted)
}

/// SQLite materializes a statement's entire RETURNING result set before the
/// first row is read, so one unbounded prune DELETE would buffer every
/// deleted (session_id, seq) pair at once. Callers embed this LIMIT in a
/// `rowid IN (SELECT rowid ... LIMIT N)` shape and loop via
/// `delete_returning_audit_batched`: same single-transaction atomicity,
/// bounded accumulation per statement.
const PRUNE_RETURNING_BATCH: i64 = 20_000;

/// Repeat a LIMIT-bounded `DELETE ... RETURNING session_id, seq` until it
/// deletes fewer rows than [`PRUNE_RETURNING_BATCH`], inside the caller's
/// transaction. The SQL must carry the LIMIT; see the const above.
fn delete_returning_audit_batched<P>(
    conn: &Connection,
    sql: &str,
    params: P,
    aggregate: &mut DeletionAuditAggregate,
) -> Result<usize, StoreError>
where
    P: rusqlite::Params + Clone,
{
    let mut total = 0;
    loop {
        let deleted = delete_returning_audit(conn, sql, params.clone(), aggregate)?;
        total += deleted;
        if deleted < PRUNE_RETURNING_BATCH as usize {
            return Ok(total);
        }
    }
}

/// Write the operation's audit rows in the same transaction as its deletes:
/// one row per affected session, counts and seq span only (value-free; see
/// migration 008). A database without the table yet — a dashboard opened
/// against a store the app has not migrated past 007 — skips the audit and
/// keeps today's unaudited delete rather than failing it.
fn record_deletion_audit(
    conn: &Connection,
    kind: &str,
    performed_at: i64,
    cutoff_ms: Option<i64>,
    aggregate: &DeletionAuditAggregate,
) -> Result<(), StoreError> {
    if aggregate.per_session.is_empty() || !sqlite_table_exists(conn, "deletion_audit")? {
        return Ok(());
    }
    let mut stmt = conn.prepare(
        "
        INSERT INTO deletion_audit
            (kind, performed_at, session_id, rows_deleted, seq_min, seq_max, cutoff_ms)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ",
    )?;
    for (session_id, span) in &aggregate.per_session {
        stmt.execute(params![
            kind,
            performed_at,
            session_id,
            span.rows_deleted,
            span.seq_min,
            span.seq_max,
            cutoff_ms
        ])?;
    }
    Ok(())
}

fn delete_recording_rows(conn: &Connection, record_session_id: i64) -> Result<usize, StoreError> {
    let row = match conn.query_row(
        "
        SELECT request_id, ended_ts
        FROM record_sessions
        WHERE record_session_id = ?1
        ",
        [record_session_id],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    ) {
        Ok(row) => row,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(0),
        Err(error) => return Err(StoreError::Sqlite(error)),
    };
    let (request_id, ended_ts) = row;
    if ended_ts.is_none() {
        return Err(StoreError::RecordRoutine(
            "cannot delete an open recording".to_string(),
        ));
    }

    let performed_at = unix_now_ms();
    let mut audit = DeletionAuditAggregate::default();
    delete_returning_audit_batched(
        conn,
        &format!(
            "DELETE FROM action_events WHERE rowid IN (
                 SELECT rowid FROM action_events WHERE record_session_id = ?1
                 LIMIT {PRUNE_RETURNING_BATCH}
             ) RETURNING session_id, seq"
        ),
        [record_session_id],
        &mut audit,
    )?;
    record_deletion_audit(
        conn,
        DELETION_AUDIT_KIND_RECORDING_DELETE,
        performed_at,
        None,
        &audit,
    )?;
    let deleted = conn.execute(
        "DELETE FROM record_sessions WHERE record_session_id = ?1",
        [record_session_id],
    )?;
    if let Some(request_id) = request_id {
        conn.execute(
            "
            DELETE FROM record_requests
            WHERE fulfilled_record_session_id = ?1
               OR request_id = ?2
            ",
            params![record_session_id, request_id],
        )?;
    } else {
        conn.execute(
            "DELETE FROM record_requests WHERE fulfilled_record_session_id = ?1",
            [record_session_id],
        )?;
    }
    sweep_orphan_selector_paths(conn)?;
    Ok(deleted)
}

fn prune_old_event_rows(
    conn: &Connection,
    cutoff_ms: i64,
) -> Result<DashboardPruneResult, StoreError> {
    let has_record_routine = record_routine_tables_present_conn(conn)?;
    let performed_at = unix_now_ms();
    let mut audit = DeletionAuditAggregate::default();
    let mut action_events_deleted = 0;
    let mut record_sessions_deleted = 0;
    let mut record_requests_deleted = 0;
    let mut selector_paths_deleted = 0;

    if has_record_routine {
        action_events_deleted += delete_returning_audit_batched(
            conn,
            &format!(
                "DELETE FROM action_events WHERE rowid IN (
                     SELECT rowid FROM action_events WHERE ts < ?1
                     LIMIT {PRUNE_RETURNING_BATCH}
                 ) RETURNING session_id, seq"
            ),
            [cutoff_ms],
            &mut audit,
        )?;
    }

    let events_deleted = delete_returning_audit_batched(
        conn,
        &format!(
            "DELETE FROM events WHERE rowid IN (
                 SELECT rowid FROM events WHERE ts < ?1
                 LIMIT {PRUNE_RETURNING_BATCH}
             ) RETURNING session_id, seq"
        ),
        [cutoff_ms],
        &mut audit,
    )?;

    if has_record_routine {
        record_sessions_deleted = conn.execute(
            "
            DELETE FROM record_sessions
            WHERE ended_ts IS NOT NULL
              AND ended_ts < ?1
              AND NOT EXISTS (
                  SELECT 1
                  FROM action_events
                  WHERE action_events.record_session_id =
                        record_sessions.record_session_id
              )
            ",
            [cutoff_ms],
        )?;
        // Orphan sweep deletes regardless of ts — it must feed the audit.
        action_events_deleted += delete_returning_audit_batched(
            conn,
            &format!(
                "DELETE FROM action_events WHERE rowid IN (
                     SELECT rowid FROM action_events
                     WHERE NOT EXISTS (
                         SELECT 1
                         FROM record_sessions
                         WHERE record_sessions.record_session_id =
                             action_events.record_session_id
                     )
                     LIMIT {PRUNE_RETURNING_BATCH}
                 ) RETURNING session_id, seq"
            ),
            [],
            &mut audit,
        )?;
    }

    let sessions_deleted = if has_record_routine {
        conn.execute(
            "
            DELETE FROM sessions
            WHERE ended_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM events
                  WHERE events.session_id = sessions.session_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM action_events
                  WHERE action_events.session_id = sessions.session_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM record_sessions
                  WHERE record_sessions.session_id = sessions.session_id
              )
            ",
            [],
        )?
    } else {
        conn.execute(
            "
            DELETE FROM sessions
            WHERE ended_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM events
                  WHERE events.session_id = sessions.session_id
              )
            ",
            [],
        )?
    };

    if has_record_routine {
        record_requests_deleted = conn.execute(
            "
            DELETE FROM record_requests
            WHERE expires_at < ?1
              AND (
                  fulfilled_record_session_id IS NULL
                  OR NOT EXISTS (
                      SELECT 1
                      FROM record_sessions
                      WHERE record_sessions.record_session_id =
                            record_requests.fulfilled_record_session_id
                  )
              )
            ",
            [cutoff_ms],
        )?;
        selector_paths_deleted = sweep_orphan_selector_paths(conn)?;
    }

    record_deletion_audit(
        conn,
        DELETION_AUDIT_KIND_DASHBOARD_PRUNE,
        performed_at,
        Some(cutoff_ms),
        &audit,
    )?;

    Ok(DashboardPruneResult {
        events_deleted,
        sessions_deleted,
        compaction_completed: true,
        compact_error: None,
        action_events_deleted,
        record_sessions_deleted,
        record_requests_deleted,
        selector_paths_deleted,
    })
}

fn sweep_orphan_selector_paths(conn: &Connection) -> Result<usize, StoreError> {
    Ok(conn.execute(
        "
        DELETE FROM selector_paths
        WHERE NOT EXISTS (
            SELECT 1
            FROM action_events
            WHERE action_events.selector_id = selector_paths.selector_id
        )
        ",
        [],
    )?)
}

fn compact_database(conn: &Connection) -> Option<String> {
    let mut errors = Vec::new();
    for (label, checkpoint) in [
        ("checkpoint before vacuum", true),
        ("vacuum", false),
        ("checkpoint after vacuum", true),
    ] {
        if checkpoint {
            match checkpoint_truncate_verified(conn) {
                Ok(()) => {}
                Err(error) if is_rusqlite_busy_or_locked(&error) => errors.push(format!(
                    "{label} could not finish because the database was busy"
                )),
                Err(error) => errors.push(format!("{label} failed: {error}")),
            }
        } else if let Err(error) = conn.execute_batch("VACUUM;") {
            errors.push(format!("{label} failed: {error}"));
        }
    }
    (!errors.is_empty()).then(|| errors.join("; "))
}

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(SCHEMA_SQL),
        M::up(SESSION_IDENTITY_SQL),
        M::up(ANALYTICS_INDEXES_SQL),
        M::up(DROP_REDUNDANT_SESSION_INDEX_SQL),
        M::up(RECORD_ROUTINE_SQL),
        M::up(ACTION_FRAMEWORK_CLASS_SQL),
        M::up(OPEN_FOCUS_SQL),
        M::up(DELETION_AUDIT_SQL),
    ])
}

/// Give a database its durable source identity as part of first open/create.
/// `INSERT OR IGNORE` also repairs pre-encryption databases that never passed
/// through the old reset-only minting path without changing an existing ID.
fn ensure_meta_identity(conn: &Connection, created_at: i64) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('db_uuid', ?1)",
        [uuid::Uuid::new_v4().to_string()],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('created_at', ?1)",
        [created_at.to_string()],
    )?;
    Ok(())
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let migrations = migrations();
    // Time the migration: on the first launch after a build that adds a schema
    // migration, `to_latest` may build an index over the whole existing DB
    // before the tray/message pump start, so a large DB shows a multi-second
    // no-window startup. The elapsed_ms line makes that hang diagnosable.
    let started = Instant::now();
    match migrations.to_latest(conn) {
        Ok(()) => {
            info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "schema migration complete"
            );
            Ok(())
        }
        // A DB written by a newer build carries a higher `user_version` than this
        // binary knows, which rusqlite_migration reports as `DatabaseTooFarAhead`.
        // Every post-initial migration to date is rollback-compatible with older
        // binaries (ADD COLUMN / CREATE TABLE / CREATE INDEX / DROP INDEX only), so continue
        // instead of refusing to start; otherwise rolling a build back would
        // brick startup. Tests enforce that shape. A future migration that
        // changes table shape or stored semantics must add a real version gate
        // here before it ships.
        Err(rusqlite_migration::Error::MigrationDefinition(
            rusqlite_migration::MigrationDefinitionError::DatabaseTooFarAhead,
        )) => {
            warn!(
                "database schema is newer than this build; continuing \
                 (additive migrations are forward-compatible)"
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Convert an orphaned `open_focus` row into one synthesized `focus_changed`
/// row in its session, flagged `recovered` in the payload, then delete the
/// row (foreground-heartbeat design, decision 5). A clean shutdown deletes
/// the row after the final flush, so reaching one here means the previous
/// run ended ungracefully and the open segment's dwell would otherwise die
/// with it. Runs at store open after migration and BEFORE
/// `finalize_orphan_sessions`, so the orphan session stamp lands on the
/// synthesized row's high-water timestamp; also run against the archive
/// copy by `stamp_archive_open_sessions` so an archive is self-contained.
/// The insert and the delete commit as one transaction: a crash between
/// them would otherwise synthesize the same dwell again on the next open.
fn repair_open_focus(conn: &Connection) -> Result<usize, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let row = tx
        .query_row(
            "SELECT session_id, exe, started_ts, high_water_ts FROM open_focus WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((session_id, exe, started_ts, high_water_ts)) = row else {
        return Ok(0);
    };
    // A row whose session already ended gracefully means the final
    // row-delete failed on a clean stop: the dwell is already recorded, so
    // synthesizing it again would double-count. Consume the row silently.
    let session_ended: Option<bool> = tx
        .query_row(
            "SELECT ended_at IS NOT NULL FROM sessions WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?;
    if session_ended != Some(false) {
        tx.execute("DELETE FROM open_focus", [])?;
        tx.commit()?;
        warn!(
            session_id,
            "discarded an open-focus row whose session already ended; no dwell synthesized"
        );
        return Ok(0);
    }
    let high_water_ts = high_water_ts.max(started_ts);
    let recovered_ms = high_water_ts - started_ts;
    // events and action_events share one per-session seq universe, so the
    // union keeps the synthesized seq both unique and contiguous.
    let next_seq: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM (
             SELECT seq FROM events WHERE session_id = ?1
             UNION ALL
             SELECT seq FROM action_events WHERE session_id = ?1
         )",
        [session_id],
        |row| row.get(0),
    )?;
    // The dwell reader takes the app from `prev_exe` and the span from
    // `duration_ms` ending at `ts`; the self-close shape (window == prev)
    // matches what every capture close path emits for a segment that ended
    // with no successor. hwnd 0 / pid 0 make no live-window claim, and no
    // title is stored because the heartbeat row never carried one.
    let window = WindowRef {
        hwnd: 0,
        exe: exe.unwrap_or_default(),
        title: String::new(),
        pid: 0,
    };
    let envelope = EventEnvelope {
        schema_version: SCHEMA_VERSION,
        session_id,
        seq: u64::try_from(next_seq).unwrap_or(u64::MAX),
        ts_unix_ms: high_water_ts,
        source: Source::Foreground,
        is_sensitive: false,
        payload: EventPayload::FocusChanged {
            window: window.clone(),
            prev: Some(window),
            previous_focused_for_ms: u64::try_from(recovered_ms).unwrap_or(0),
            window_unfocused_for_ms: 0,
            recovered: true,
        },
    };
    let event_row = EventRow::from_envelope(&envelope)?;
    tx.execute(
        INSERT_EVENT_SQL,
        params![
            event_row.session_id,
            event_row.seq,
            event_row.ts,
            event_row.source,
            event_row.kind,
            event_row.is_sensitive,
            event_row.hwnd,
            event_row.exe,
            event_row.title,
            event_row.pid,
            event_row.prev_exe,
            event_row.prev_title,
            event_row.key,
            event_row.mod_shift,
            event_row.mod_ctrl,
            event_row.mod_alt,
            event_row.mod_win,
            event_row.button,
            event_row.pos_x,
            event_row.pos_y,
            event_row.duration_ms,
            event_row.payload,
        ],
    )?;
    tx.execute("DELETE FROM open_focus", [])?;
    tx.commit()?;
    warn!(
        session_id,
        recovered_ms, "recovered an open focus segment from an ungraceful shutdown"
    );
    Ok(1)
}

fn finalize_orphan_sessions(conn: &Connection) -> Result<usize, StoreError> {
    let orphan_sessions_finalized = conn.execute(
        "
        UPDATE sessions
           SET ended_at = max(
               started_at,
               COALESCE(
                   (
                       SELECT MAX(events.ts)
                         FROM events
                        WHERE events.session_id = sessions.session_id
                   ),
                   started_at
               )
           )
         WHERE ended_at IS NULL
        ",
        [],
    )?;
    if orphan_sessions_finalized > 0 {
        warn!(
            orphan_sessions_finalized,
            "previous session(s) ended without graceful stop"
        );
    }
    Ok(orphan_sessions_finalized)
}

fn finalize_orphan_record_sessions(conn: &Connection) -> Result<usize, StoreError> {
    let orphan_record_sessions_finalized = conn.execute(
        "
        UPDATE record_sessions
           SET ended_ts = max(
               started_ts,
               COALESCE(
                   (
                       SELECT MAX(action_events.ts)
                         FROM action_events
                        WHERE action_events.record_session_id =
                              record_sessions.record_session_id
                   ),
                   started_ts
               )
           ),
               stop_reason = ?1
         WHERE ended_ts IS NULL
        ",
        [RecordStopReason::Error.as_str()],
    )?;
    if orphan_record_sessions_finalized > 0 {
        warn!(
            orphan_record_sessions_finalized,
            "previous record routine session(s) ended without graceful stop"
        );
    }
    Ok(orphan_record_sessions_finalized)
}

fn reconcile_confirmed_record_requests(
    conn: &Connection,
    updated_at: i64,
) -> Result<usize, StoreError> {
    Ok(conn.execute(
        "
        UPDATE record_requests
           SET status = ?1, updated_at = ?2
         WHERE status = ?3
           AND fulfilled_record_session_id IS NULL
        ",
        params![
            RecordRequestStatus::Expired.as_str(),
            updated_at,
            RecordRequestStatus::Confirmed.as_str(),
        ],
    )?)
}

struct EventRow {
    session_id: i64,
    seq: i64,
    ts: i64,
    source: &'static str,
    kind: &'static str,
    is_sensitive: i64,
    hwnd: Option<String>,
    exe: Option<String>,
    title: Option<String>,
    pid: Option<i64>,
    prev_exe: Option<String>,
    prev_title: Option<String>,
    key: Option<String>,
    mod_shift: Option<i64>,
    mod_ctrl: Option<i64>,
    mod_alt: Option<i64>,
    mod_win: Option<i64>,
    button: Option<String>,
    pos_x: Option<i64>,
    pos_y: Option<i64>,
    duration_ms: Option<i64>,
    payload: String,
}

impl EventRow {
    fn from_envelope(event: &EventEnvelope) -> Result<Self, StoreError> {
        let payload = payload_json(event)?;

        match &event.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: Some(window.hwnd_hex()),
                exe: Some(exe_basename(&window.exe)),
                title: Some(window.title.clone()),
                pid: Some(i64::from(window.pid)),
                prev_exe: prev.as_ref().map(|window| exe_basename(&window.exe)),
                prev_title: prev.as_ref().map(|window| window.title.clone()),
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: Some(u64_to_i64(*previous_focused_for_ms)),
                payload,
            }),
            EventPayload::WindowOpened { window, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: Some(window.hwnd_hex()),
                exe: Some(exe_basename(&window.exe)),
                title: Some(window.title.clone()),
                pid: Some(i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::WindowClosed {
                window,
                open_for_ms,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: Some(window.hwnd_hex()),
                exe: Some(exe_basename(&window.exe)),
                title: Some(window.title.clone()),
                pid: Some(i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: Some(u64_to_i64(*open_for_ms)),
                payload,
            }),
            EventPayload::Key {
                key, mods, window, ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: window.as_ref().map(|window| window.title.clone()),
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: (!key.is_empty()).then(|| key.clone()),
                mod_shift: Some(bool_i64(mods.shift)),
                mod_ctrl: Some(bool_i64(mods.ctrl)),
                mod_alt: Some(bool_i64(mods.alt)),
                mod_win: Some(bool_i64(mods.win)),
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::MouseClick {
                button,
                x,
                y,
                window,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: window.as_ref().map(|window| window.title.clone()),
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: Some(button.as_str().to_string()),
                pos_x: x.map(i64::from),
                pos_y: y.map(i64::from),
                duration_ms: None,
                payload,
            }),
            EventPayload::MouseDoubleClick {
                button,
                interval_ms,
                x,
                y,
                window,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: window.as_ref().map(|window| window.title.clone()),
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: Some(button.as_str().to_string()),
                pos_x: x.map(i64::from),
                pos_y: y.map(i64::from),
                duration_ms: Some(u64_to_i64(*interval_ms)),
                payload,
            }),
            EventPayload::MouseDrag {
                button,
                duration_ms,
                end_x,
                end_y,
                window,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: window.as_ref().map(|window| window.title.clone()),
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: Some(button.as_str().to_string()),
                pos_x: end_x.map(i64::from),
                pos_y: end_y.map(i64::from),
                duration_ms: Some(u64_to_i64(*duration_ms)),
                payload,
            }),
            EventPayload::MouseWheel {
                axis,
                delta,
                x,
                y,
                window,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: window.as_ref().map(|window| window.title.clone()),
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: Some(wheel_button_name(*axis, *delta).to_string()),
                pos_x: x.map(i64::from),
                pos_y: y.map(i64::from),
                duration_ms: None,
                payload,
            }),
            EventPayload::MouseMove {
                duration_ms,
                x,
                y,
                window,
                ..
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: window.as_ref().map(|window| window.hwnd_hex()),
                exe: window.as_ref().map(|window| exe_basename(&window.exe)),
                title: None,
                pid: window.as_ref().map(|window| i64::from(window.pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: x.map(i64::from),
                pos_y: y.map(i64::from),
                duration_ms: Some(u64_to_i64(*duration_ms)),
                payload,
            }),
            EventPayload::SystemInfo { host, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: Some(host.clone()),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::VirtualScreen { x0, y0, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: None,
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: Some(i64::from(*x0)),
                pos_y: Some(i64::from(*y0)),
                duration_ms: None,
                payload,
            }),
            EventPayload::ProcessStarted { pid, exe, .. }
            | EventPayload::ProcessExited { pid, exe, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: Some(exe.clone()),
                title: None,
                pid: Some(i64::from(*pid)),
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::ProcessChurnSummary { window_ms, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: None,
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: Some(u64_to_i64(*window_ms)),
                payload,
            }),
            EventPayload::PowerSuspend { .. }
            | EventPayload::PowerResume { .. }
            | EventPayload::CapturePaused
            | EventPayload::CaptureResumed
            | EventPayload::PowerStatusChanged { .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: None,
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::PowerBoundaryRecovered { gap_ms, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: None,
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: Some(u64_to_i64(*gap_ms)),
                payload,
            }),
            EventPayload::SessionLock { session_id }
            | EventPayload::SessionUnlock { session_id } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: Some(format!("Session {session_id}")),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::SessionConnect {
                session_id,
                connection,
            }
            | EventPayload::SessionDisconnect {
                session_id,
                connection,
            } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: Some(format!("{} session {session_id}", connection.as_str())),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::ClipboardUsed { format_kind, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: Some(format!("Clipboard {}", format_kind.as_str())),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::NotificationsReceived { app, .. } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: app.clone(),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::SensitiveContextEntered { reason }
            | EventPayload::SensitiveContextExited { reason } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: Some(reason.as_str().to_string()),
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload,
            }),
            EventPayload::Idle { idle_ms } | EventPayload::Active { idle_ms } => Ok(Self {
                session_id: event.session_id,
                seq: u64_to_i64(event.seq),
                ts: event.ts_unix_ms,
                source: event.source.as_str(),
                kind: event.kind(),
                is_sensitive: i64::from(event.is_sensitive),
                hwnd: None,
                exe: None,
                title: None,
                pid: None,
                prev_exe: None,
                prev_title: None,
                key: None,
                mod_shift: None,
                mod_ctrl: None,
                mod_alt: None,
                mod_win: None,
                button: None,
                pos_x: None,
                pos_y: None,
                duration_ms: Some(u64_to_i64(*idle_ms)),
                payload,
            }),
        }
    }
}

/// A14 (priv-02): the typed `exe`/`prev_exe` columns are basenamed at insert, but
/// payload JSON serializes whole `EventPayload`s, so a `WindowRef` nested in a
/// payload (focus / window / key / click / wheel) still carries the full path.
/// Basename the `exe` of any JSON object that also has an `hwnd` key (i.e. a
/// serialized `WindowRef`). The deliberate process full path lives in a payload
/// object WITHOUT `hwnd` (it carries `exe_source` instead), so it is left intact.
fn basename_window_exe_in_payload(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("hwnd") {
                if let Some(serde_json::Value::String(exe)) = map.get_mut("exe") {
                    *exe = exe_basename(exe.as_str());
                }
            }
            for entry in map.values_mut() {
                basename_window_exe_in_payload(entry);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                basename_window_exe_in_payload(item);
            }
        }
        _ => {}
    }
}

fn payload_json(event: &EventEnvelope) -> Result<String, StoreError> {
    match &event.payload {
        EventPayload::MouseMove {
            dx_total,
            dy_total,
            distance_px,
            raw_event_count,
            duration_ms,
            x,
            y,
            input_origin,
            ..
        } => {
            let mut payload = serde_json::json!({
                "kind": event.kind(),
                "dx_total": dx_total,
                "dy_total": dy_total,
                "distance_px": distance_px,
                "raw_event_count": raw_event_count,
                "duration_ms": duration_ms,
                "x": x,
                "y": y,
            });
            if let Some(input_origin) = input_origin {
                payload["input_origin"] = serde_json::json!(input_origin.as_str());
            }
            Ok(serde_json::to_string(&payload)?)
        }
        _ => {
            let mut payload = serde_json::to_value(&event.payload)?;
            basename_window_exe_in_payload(&mut payload);
            Ok(serde_json::to_string(&payload)?)
        }
    }
}

fn wheel_button_name(axis: gilbreth_core::MouseWheelAxis, delta: i32) -> &'static str {
    match (axis, delta.signum()) {
        (gilbreth_core::MouseWheelAxis::Vertical, 1) => "wheel_up",
        (gilbreth_core::MouseWheelAxis::Vertical, -1) => "wheel_down",
        (gilbreth_core::MouseWheelAxis::Horizontal, 1) => "wheel_right",
        (gilbreth_core::MouseWheelAxis::Horizontal, -1) => "wheel_left",
        (gilbreth_core::MouseWheelAxis::Vertical, _) => "wheel",
        (gilbreth_core::MouseWheelAxis::Horizontal, _) => "wheel_horizontal",
    }
}

fn bool_i64(value: bool) -> i64 {
    i64::from(value)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::AtomicBool, mpsc, Arc, Mutex},
        time::{Duration, Instant},
    };

    use crossbeam_channel::bounded;
    use gilbreth_core::{
        ActionCapture, ActionDiag, ActionPayload, ActionType, AutomationAction, Captured,
        ClipboardFormatKind, EventPayload, FrameworkClass, InputOrigin, Modifiers, MouseButton,
        MouseWheelAxis, Policy, ProcessExeSource, RejectedAction, RejectedActionReason,
        SelectorPath, SelectorPathHop, SelectorTrustBasis, SensitiveContextReason, Sequencer,
        SessionConnectionKind, SessionTimebase, Source, WindowLifecycleOrigin, WindowRef,
    };
    use tempfile::tempdir;

    use super::*;

    fn temp_store() -> (tempfile::TempDir, GilbrethStore) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(path).expect("store opens");
        (dir, store)
    }

    #[test]
    fn database_identity_is_minted_on_first_create_and_stable_on_reopen() {
        let (_dir, store) = temp_store();
        let path = store.db_path().to_path_buf();
        let db_uuid: String = store
            .connection()
            .query_row("SELECT value FROM meta WHERE key = 'db_uuid'", [], |row| {
                row.get(0)
            })
            .expect("db_uuid minted at create");
        uuid::Uuid::parse_str(&db_uuid).expect("db_uuid is a UUID");
        let created_at: String = store
            .connection()
            .query_row(
                "SELECT value FROM meta WHERE key = 'created_at'",
                [],
                |row| row.get(0),
            )
            .expect("created_at minted at create");
        created_at
            .parse::<i64>()
            .expect("created_at is an epoch timestamp");
        drop(store);

        let reopened = GilbrethStore::open(&path).expect("store reopens");
        let reopened_uuid: String = reopened
            .connection()
            .query_row("SELECT value FROM meta WHERE key = 'db_uuid'", [], |row| {
                row.get(0)
            })
            .expect("db_uuid remains");
        assert_eq!(reopened_uuid, db_uuid);
    }

    #[cfg(windows)]
    fn open_dpapi_archive(path: &Path) -> Connection {
        let restored = path.with_extension("opened.db");
        unseal_archive_to(path, &restored, ArchiveCredential::DpapiUser)
            .expect("archive decrypts and authenticates");
        Connection::open(restored).expect("decrypted archive opens")
    }

    fn wait_for_event_count(path: &std::path::Path, expected: i64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let count = Connection::open(path)
                .and_then(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                })
                .unwrap_or(-1);
            if count == expected {
                return;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for {expected} events; saw {count}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_action_count(path: &std::path::Path, expected: i64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let count = Connection::open(path)
                .and_then(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM action_events", [], |row| row.get(0))
                })
                .unwrap_or(-1);
            if count == expected {
                return;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for {expected} actions; saw {count}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn sqlite_storage_contains(db_path: &std::path::Path, needle: &[u8]) -> bool {
        let mut shm = db_path.as_os_str().to_os_string();
        shm.push("-shm");
        [db_path.to_path_buf(), wal_path(db_path), PathBuf::from(shm)]
            .iter()
            .filter_map(|path| std::fs::read(path).ok())
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    }

    fn captured_focus(title: &str, captured_at: Instant) -> Captured {
        Captured::new(
            Source::Foreground,
            captured_at,
            EventPayload::FocusChanged {
                window: WindowRef {
                    hwnd: 0x1a2b3c,
                    exe: "C:\\Windows\\System32\\notepad.exe".to_string(),
                    title: title.to_string(),
                    pid: 1234,
                },
                prev: None,
                previous_focused_for_ms: 25,
                window_unfocused_for_ms: 0,
                recovered: false,
            },
        )
    }

    struct RecordRoutineFixture<'a> {
        request_id: i64,
        record_session_id: i64,
        selector_id: i64,
        session_id: i64,
        seq: i64,
        action_ts: i64,
        record_ended_ts: Option<i64>,
        request_expires_at: i64,
        selector_hash: &'a str,
    }

    struct RecordRoutineParentFixture {
        request_id: i64,
        record_session_id: i64,
        session_id: i64,
        started_ts: i64,
        ended_ts: Option<i64>,
        request_expires_at: i64,
        action_count: i64,
    }

    fn insert_record_routine_parent(conn: &Connection, fixture: RecordRoutineParentFixture) {
        conn.execute(
            "
            INSERT INTO record_requests (
                request_id,
                requested_at,
                expires_at,
                status,
                candidate_kind,
                candidate_json,
                fulfilled_record_session_id,
                updated_at
            )
            VALUES (?1, ?2, ?3, 'started', 'fragmentation_candidate', '{}', ?4, ?2)
            ",
            params![
                fixture.request_id,
                fixture.started_ts.saturating_sub(50),
                fixture.request_expires_at,
                fixture.record_session_id
            ],
        )
        .expect("record request inserted");
        conn.execute(
            "
            INSERT INTO record_sessions (
                record_session_id,
                request_id,
                session_id,
                started_ts,
                ended_ts,
                stop_reason,
                title,
                policy_snapshot_json,
                action_count
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'user_stop', 'Routine', '{}', ?6)
            ",
            params![
                fixture.record_session_id,
                fixture.request_id,
                fixture.session_id,
                fixture.started_ts,
                fixture.ended_ts,
                fixture.action_count
            ],
        )
        .expect("record session inserted");
    }

    fn insert_record_routine_rows(conn: &Connection, fixture: RecordRoutineFixture<'_>) {
        insert_record_routine_parent(
            conn,
            RecordRoutineParentFixture {
                request_id: fixture.request_id,
                record_session_id: fixture.record_session_id,
                session_id: fixture.session_id,
                started_ts: fixture.action_ts.saturating_sub(50),
                ended_ts: fixture.record_ended_ts,
                request_expires_at: fixture.request_expires_at,
                action_count: 1,
            },
        );
        conn.execute(
            "
            INSERT INTO selector_paths (
                selector_id,
                path_hash,
                framework,
                depth,
                path_json,
                created_ts
            )
            VALUES (?1, ?2, 'uia', 1, '[]', ?3)
            ",
            params![
                fixture.selector_id,
                fixture.selector_hash,
                fixture.action_ts
            ],
        )
        .expect("selector path inserted");
        conn.execute(
            "
            INSERT INTO action_events (
                session_id,
                seq,
                ts,
                action_type,
                pattern_action,
                selector_id,
                trust_basis,
                exe,
                record_session_id,
                payload
            )
            VALUES (?1, ?2, ?3, 'invoke', 'invoke', ?4, 'pid_match', 'app.exe', ?5, '{}')
            ",
            params![
                fixture.session_id,
                fixture.seq,
                fixture.action_ts,
                fixture.selector_id,
                fixture.record_session_id
            ],
        )
        .expect("action event inserted");
    }

    fn record_routine_counts(conn: &Connection) -> (i64, i64, i64, i64) {
        (
            row_count(conn, "record_requests"),
            row_count(conn, "record_sessions"),
            row_count(conn, "selector_paths"),
            row_count(conn, "action_events"),
        )
    }

    fn stamped_focus_batch(count: usize) -> Vec<EventEnvelope> {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(1, SessionTimebase::new(base, 1_000));
        (0..count)
            .map(|index| {
                sequencer.stamp(captured_focus(
                    &format!("Window {index}"),
                    base + Duration::from_millis(index as u64),
                ))
            })
            .collect()
    }

    fn stamped_action_batch(count: usize) -> Vec<StampedAction> {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(1, SessionTimebase::new(base, 1_000));
        (0..count)
            .map(|index| {
                sequencer.stamp_action(sample_action_capture(
                    10,
                    base + Duration::from_millis(index as u64),
                    &format!("action-{index}"),
                ))
            })
            .collect()
    }

    fn sqlite_failure(code: i32) -> StoreError {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("forced sqlite failure".to_string()),
        ))
    }

    fn insert_minimal_event(conn: &Connection, session_id: i64, seq: i64, ts: i64) {
        conn.execute(
            "
            INSERT INTO events (session_id, seq, ts, source, kind, payload)
            VALUES (?1, ?2, ?3, 'system', 'test_event', '{}')
            ",
            rusqlite::params![session_id, seq, ts],
        )
        .expect("minimal event inserted");
    }

    fn session_ended_at(conn: &Connection, session_id: i64) -> Option<i64> {
        conn.query_row(
            "SELECT ended_at FROM sessions WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .expect("session ended_at")
    }

    fn normalize_migration_sql(sql: &str) -> String {
        sql.replace("\r\n", "\n")
            .replace('\r', "\n")
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }

    fn migration_statements(sql: &str) -> Vec<String> {
        normalize_migration_sql(sql)
            .lines()
            .map(|line| line.split_once("--").map_or(line, |(sql, _comment)| sql))
            .collect::<Vec<_>>()
            .join("\n")
            .split(';')
            .filter_map(|statement| {
                let normalized = statement
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_uppercase();
                (!normalized.is_empty()).then_some(normalized)
            })
            .collect()
    }

    fn is_rollback_compatible_statement(statement: &str) -> bool {
        let tokens = statement.split_whitespace().collect::<Vec<_>>();
        matches!(
            tokens.as_slice(),
            ["ALTER", "TABLE", _, "ADD", "COLUMN", ..]
                | ["CREATE", "TABLE", ..]
                | ["CREATE", "INDEX", ..]
                | ["CREATE", "UNIQUE", "INDEX", ..]
                | ["DROP", "INDEX", ..]
        )
    }

    #[test]
    fn rollback_compatible_statements_allow_create_table_shapes() {
        assert!(is_rollback_compatible_statement(
            "CREATE TABLE action_events (id INTEGER PRIMARY KEY)"
        ));
        assert!(is_rollback_compatible_statement(
            "CREATE TABLE IF NOT EXISTS action_events (id INTEGER PRIMARY KEY)"
        ));

        assert!(!is_rollback_compatible_statement(
            "DROP TABLE action_events"
        ));
        assert!(!is_rollback_compatible_statement(
            "ALTER TABLE action_events DROP COLUMN action_type"
        ));
    }

    #[derive(Clone)]
    struct OrphanRepairWarnSubscriber {
        orphan_counts: Arc<Mutex<Vec<u64>>>,
    }

    impl tracing::Subscriber for OrphanRepairWarnSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            let mut visitor = OrphanRepairWarnVisitor { count: None };
            event.record(&mut visitor);
            if let Some(count) = visitor.count {
                self.orphan_counts
                    .lock()
                    .expect("orphan count lock")
                    .push(count);
            }
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    struct OrphanRepairWarnVisitor {
        count: Option<u64>,
    }

    impl tracing::field::Visit for OrphanRepairWarnVisitor {
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            if field.name() == "orphan_sessions_finalized" && value >= 0 {
                self.count = Some(value as u64);
            }
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if field.name() == "orphan_sessions_finalized" {
                self.count = Some(value);
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "orphan_sessions_finalized" {
                self.count = format!("{value:?}").parse().ok();
            }
        }
    }

    fn window_ref(hwnd: u64, title: &str) -> WindowRef {
        WindowRef {
            hwnd,
            exe: format!("C:\\Apps\\{title}.exe"),
            title: title.to_string(),
            pid: 1234,
        }
    }

    fn captured_window_closed(title: &str, captured_at: Instant) -> Captured {
        Captured::new(
            Source::Window,
            captured_at,
            EventPayload::WindowClosed {
                window: window_ref(0x4567, title),
                open_for_ms: 750,
                origin: WindowLifecycleOrigin::Observed,
            },
        )
    }

    fn captured_key(key: &str, captured_at: Instant) -> Captured {
        Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: key.to_string(),
                mods: Modifiers {
                    shift: true,
                    ctrl: false,
                    alt: true,
                    win: false,
                },
                window: Some(window_ref(0x789a, "Editor")),
                key_class: None,
            },
        )
    }

    fn captured_capture_redacted_key(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: "<redacted>".to_string(),
                key_class: None,
                mods: Modifiers {
                    shift: true,
                    ctrl: false,
                    alt: false,
                    win: false,
                },
                window: Some(WindowRef {
                    title: "<redacted>".to_string(),
                    ..window_ref(0x789a, "Password Dialog")
                }),
            },
        )
    }

    fn captured_mouse_click(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            captured_at,
            EventPayload::MouseClick {
                button: MouseButton::Left,
                x: Some(100),
                y: Some(200),
                window: Some(window_ref(0x8888, "Editor")),
                input_origin: None,
            },
        )
    }

    fn captured_mouse_double_click(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            captured_at,
            EventPayload::MouseDoubleClick {
                button: MouseButton::Left,
                interval_ms: 175,
                x: Some(102),
                y: Some(202),
                window: Some(window_ref(0x8888, "Editor")),
                input_origin: None,
            },
        )
    }

    fn captured_mouse_drag(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            captured_at,
            EventPayload::MouseDrag {
                button: MouseButton::Left,
                dx_total: 25,
                dy_total: 12,
                distance_px: 28,
                raw_event_count: 3,
                duration_ms: 420,
                start_x: Some(100),
                start_y: Some(200),
                end_x: Some(125),
                end_y: Some(212),
                window: Some(window_ref(0x8888, "Editor")),
                selection_candidate: true,
                input_origin: None,
            },
        )
    }

    fn captured_mouse_wheel(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            captured_at,
            EventPayload::MouseWheel {
                axis: MouseWheelAxis::Vertical,
                delta: -120,
                x: Some(300),
                y: Some(400),
                window: Some(window_ref(0x9999, "Browser")),
                input_origin: None,
            },
        )
    }

    fn captured_mouse_move(captured_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            captured_at,
            EventPayload::MouseMove {
                dx_total: 12,
                dy_total: -5,
                distance_px: 18,
                raw_event_count: 3,
                duration_ms: 250,
                x: Some(500),
                y: Some(600),
                window: Some(window_ref(0xaaaa, "Canvas")),
                input_origin: None,
            },
        )
    }

    fn captured_system_info(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::SystemInfo {
                host: "workstation".to_string(),
                os_version: "10.0.26100".to_string(),
                arch: "x86_64".to_string(),
                processor_count: 16,
                memory_total_bytes: 68_719_476_736,
            },
        )
    }

    fn captured_virtual_screen(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::VirtualScreen {
                x0: -1920,
                y0: 0,
                x1: 2560,
                y1: 1440,
                width: 4480,
                height: 1440,
            },
        )
    }

    fn captured_process_started(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::ProcessStarted {
                pid: 4242,
                exe: "C:\\Windows\\System32\\notepad.exe".to_string(),
                exe_source: ProcessExeSource::FullPath,
            },
        )
    }

    fn captured_power_boundary_recovered(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::PowerBoundaryRecovered {
                gap_ms: 30_001,
                capped_dwell_ms: 30_000,
            },
        )
    }

    fn captured_power_suspend(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::PowerSuspend {
                tick_ms: Some(1_000),
            },
        )
    }

    fn captured_power_resume(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::PowerResume {
                tick_ms: Some(2_000),
                matched_suspend: true,
            },
        )
    }

    fn captured_session_connect(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::SessionConnect {
                session_id: 42,
                connection: SessionConnectionKind::Remote,
            },
        )
    }

    fn captured_clipboard_used(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::ClipboardUsed {
                sequence_number: 77,
                format_kind: ClipboardFormatKind::Text,
                format_count: 3,
                text_char_count: Some(12),
                byte_size: Some(26),
            },
        )
    }

    fn captured_sensitive_context_entered(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked,
            },
        )
    }

    fn captured_notifications_received(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::NotificationsReceived {
                app: Some("Calendar".to_string()),
                count: 1,
            },
        )
    }

    fn captured_idle(captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::Idle { idle_ms: 300_000 },
        )
    }

    fn sample_selector_path(automation_id: &str) -> SelectorPath {
        SelectorPath {
            backend: "uia".to_string(),
            hops: vec![
                SelectorPathHop {
                    control_type: 50032,
                    automation_id: "root".to_string(),
                    class_name: "Notepad".to_string(),
                    ordinal: 0,
                },
                SelectorPathHop {
                    control_type: 50004,
                    automation_id: automation_id.to_string(),
                    class_name: "Edit".to_string(),
                    ordinal: 1,
                },
            ],
        }
    }

    fn sample_action_capture(
        record_session_id: i64,
        captured_at: Instant,
        automation_id: &str,
    ) -> ActionCapture {
        let selector_path = sample_selector_path(automation_id);
        let depth = selector_path.hops.len() as u32;
        ActionCapture {
            action: AutomationAction {
                action_type: ActionType::Invoke,
                selector_path,
                trust_basis: SelectorTrustBasis::PidMatch,
            },
            captured_at,
            record_session_id,
            exe: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
            is_sensitive: false,
            has_name: false,
            pattern_action: Some("invoke".to_string()),
            framework: "uia".to_string(),
            framework_class: FrameworkClass::Native,
            depth,
            leaf_rect: None,
            payload: ActionPayload::Invoke {
                from_modality: None,
                corroborates: None,
            },
        }
    }

    fn sample_action_diag(record_session_id: i64) -> ActionDiag {
        ActionDiag {
            record_session_id,
            worker_ordinal: 1,
            event_kind: "invoke".to_string(),
            callback_latency_ns: 10,
            event_to_selector_complete_ns: 20,
            queue_depth_at_enqueue: 1,
            repeat_count: 1,
            edit_commit_signal: None,
            trust_basis: Some(SelectorTrustBasis::PidMatch),
            action_type: Some(ActionType::Invoke),
        }
    }

    fn sample_rejected_action(record_session_id: i64, captured_at: Instant) -> RejectedAction {
        RejectedAction {
            record_session_id,
            worker_ordinal: 2,
            event_kind: "focus_changed".to_string(),
            captured_at,
            reason: RejectedActionReason::WindowMismatch,
            trust_basis: None,
            callback_latency_ns: 30,
            event_to_selector_complete_ns: 40,
            queue_depth_at_enqueue: 2,
        }
    }

    fn insert_recording_parent_for_session(
        conn: &Connection,
        session_id: i64,
        record_session_id: i64,
    ) {
        insert_record_routine_parent(
            conn,
            RecordRoutineParentFixture {
                request_id: record_session_id,
                record_session_id,
                session_id,
                started_ts: 1_050,
                ended_ts: None,
                request_expires_at: 10_000,
                action_count: 0,
            },
        );
    }

    fn start_recording_for_writer(command_tx: &crossbeam_channel::Sender<WriterCommand>) -> i64 {
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StartRecording {
                request_id: None,
                title: Some("Routine".to_string()),
                policy_snapshot_json:
                    r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#
                        .to_string(),
                safety_cap_ms: 1_800_000,
                visible_indicator: true,
                reply: reply_tx,
            })
            .expect("start recording command");
        reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("start recording reply")
            .expect("recording starts")
    }

    fn stop_recording_for_writer(
        command_tx: &crossbeam_channel::Sender<WriterCommand>,
        record_session_id: i64,
    ) {
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StopRecording {
                record_session_id,
                stop_reason: RecordStopReason::UserStop,
                reply: reply_tx,
            })
            .expect("stop recording command");
        reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("stop recording reply")
            .expect("recording stops");
    }

    #[test]
    fn heartbeat_resync_changes_future_timestamps_without_renumbering_seq() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(42, SessionTimebase::new(base, 1_000));
        let first = sequencer.stamp(captured_focus("Before drift", base));

        let correction = resync_sequencer_at(
            &mut sequencer,
            base + Duration::from_secs(10),
            50_000,
            1_000,
            "test heartbeat",
        )
        .expect("heartbeat drift crosses threshold");
        let second = sequencer.stamp(captured_focus(
            "After drift",
            base + Duration::from_secs(11),
        ));

        assert_eq!(first.seq, 1);
        assert_eq!(first.ts_unix_ms, 1_000);
        assert_eq!(correction.measured_drift_ms, 39_000);
        assert_eq!(second.seq, 2);
        assert_eq!(second.ts_unix_ms, 51_000);
    }

    #[test]
    fn power_resume_requests_timebase_resync_before_stamp() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(42, SessionTimebase::new(base, 1_000));
        let captured = captured_power_resume(base + Duration::from_secs(10));

        let correction = resync_for_event_if_needed(
            &mut sequencer,
            &captured.payload,
            captured.captured_at,
            20_000,
            1_000,
        )
        .expect("power resume triggers resync");
        let event = sequencer.stamp(captured);

        assert_eq!(correction.measured_drift_ms, 9_000);
        assert_eq!(event.seq, 1);
        assert_eq!(event.ts_unix_ms, 20_000);
    }

    #[test]
    fn non_power_events_do_not_request_timebase_resync() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(42, SessionTimebase::new(base, 1_000));
        let captured = captured_focus("Plain", base + Duration::from_secs(10));

        let correction = resync_for_event_if_needed(
            &mut sequencer,
            &captured.payload,
            captured.captured_at,
            20_000,
            1_000,
        );
        let event = sequencer.stamp(captured);

        assert_eq!(correction, None);
        assert_eq!(event.ts_unix_ms, 11_000);
    }

    #[test]
    fn heartbeat_warns_when_last_event_is_stale_and_unexplained() {
        let now = Instant::now();
        let mut heartbeat = WriterHeartbeat::default();
        heartbeat.mark_event_at("key", now - Duration::from_secs(60));

        let warning = heartbeat
            .stale_warning_at(now, Some(Duration::from_secs(30)))
            .expect("unexplained stale event warns");

        assert_eq!(warning.last_event_age_ms, 60_000);
        assert_eq!(warning.last_event_kind, Some("key"));
    }

    #[test]
    fn heartbeat_suppresses_warn_when_gap_is_explained() {
        let now = Instant::now();
        let mut heartbeat = WriterHeartbeat::default();
        heartbeat.mark_event_at("power_suspend", now - Duration::from_secs(60));

        assert_eq!(
            heartbeat.stale_warning_at(now, Some(Duration::from_secs(30))),
            None
        );
    }

    #[test]
    fn mouse_move_payload_preserves_remote_relay_origin_when_present() {
        let base = Instant::now();
        let mut sequencer = Sequencer::new(1, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::Mouse,
            base,
            EventPayload::MouseMove {
                dx_total: 12,
                dy_total: -5,
                distance_px: 18,
                raw_event_count: 3,
                duration_ms: 250,
                x: Some(500),
                y: Some(600),
                window: Some(window_ref(0xaaaa, "Canvas")),
                input_origin: Some(InputOrigin::RemoteRelaySuspected),
            },
        ));

        let payload: serde_json::Value =
            serde_json::from_str(&payload_json(&event).expect("payload json"))
                .expect("payload parses");

        assert_eq!(payload["input_origin"], "remote_relay_suspected");
        assert!(payload.get("window").is_none());
    }

    #[test]
    fn insert_actions_interns_selector_and_updates_action_count() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_recording_parent_for_session(store.connection(), session_id, 10);
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let action = sequencer.stamp_action(sample_action_capture(10, base, "edit"));

        let report = store.insert_actions(&[action]).expect("action inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );
        assert_eq!(row_count(store.connection(), "selector_paths"), 1);
        assert_eq!(row_count(store.connection(), "action_events"), 1);
        struct ActionRow {
            session_id: i64,
            seq: i64,
            action_type: String,
            pattern_action: String,
            trust_basis: String,
            exe: Option<String>,
            is_sensitive: i64,
            action_count: i64,
            framework_class: String,
            path_hash: String,
            payload: String,
        }

        let row: ActionRow = store
            .connection()
            .query_row(
                "
                    SELECT action_events.session_id, action_events.seq,
                           action_events.action_type, action_events.pattern_action,
                           action_events.trust_basis, action_events.exe,
                           action_events.is_sensitive, record_sessions.action_count,
                           action_events.framework_class, selector_paths.path_hash,
                           action_events.payload
                      FROM action_events
                      JOIN selector_paths USING (selector_id)
                      JOIN record_sessions USING (record_session_id)
                    ",
                [],
                |row| {
                    Ok(ActionRow {
                        session_id: row.get(0)?,
                        seq: row.get(1)?,
                        action_type: row.get(2)?,
                        pattern_action: row.get(3)?,
                        trust_basis: row.get(4)?,
                        exe: row.get(5)?,
                        is_sensitive: row.get(6)?,
                        action_count: row.get(7)?,
                        framework_class: row.get(8)?,
                        path_hash: row.get(9)?,
                        payload: row.get(10)?,
                    })
                },
            )
            .expect("action row");
        assert_eq!(row.session_id, session_id);
        assert_eq!(row.seq, 1);
        assert_eq!(row.action_type, "invoke");
        assert_eq!(row.pattern_action, "invoke");
        assert_eq!(row.trust_basis, "pid_match");
        // A14 (priv-02): the value-free action `exe` is stored basename-only; the
        // full path "C:\\Windows\\System32\\notepad.exe" must not be persisted.
        assert_eq!(row.exe.as_deref(), Some("notepad.exe"));
        assert_eq!(row.is_sensitive, 0);
        assert_eq!(row.action_count, 1);
        assert_eq!(row.framework_class, "native");
        assert_eq!(row.path_hash, sample_selector_path("edit").hash_v1());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&row.payload).expect("payload json"),
            serde_json::json!({ "kind": "invoke" })
        );
    }

    #[test]
    fn insert_actions_skips_closed_record_session_without_selector_side_effects() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_record_routine_parent(
            store.connection(),
            RecordRoutineParentFixture {
                request_id: 13,
                record_session_id: 13,
                session_id,
                started_ts: 1_050,
                ended_ts: Some(1_500),
                request_expires_at: 10_000,
                action_count: 0,
            },
        );
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let action = sequencer.stamp_action(sample_action_capture(13, base, "closed"));

        let report = store.insert_actions(&[action]).expect("action skipped");

        assert_eq!(
            report,
            InsertReport {
                inserted: 0,
                skipped: 1
            }
        );
        assert_eq!(row_count(store.connection(), "selector_paths"), 0);
        assert_eq!(row_count(store.connection(), "action_events"), 0);
        let action_count: i64 = store
            .connection()
            .query_row(
                "SELECT action_count FROM record_sessions WHERE record_session_id = 13",
                [],
                |row| row.get(0),
            )
            .expect("action count");
        assert_eq!(action_count, 0);
    }

    #[test]
    fn insert_actions_reuses_selector_across_recordings_by_hash() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_recording_parent_for_session(store.connection(), session_id, 11);
        insert_recording_parent_for_session(store.connection(), session_id, 12);
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let first = sequencer.stamp_action(sample_action_capture(11, base, "edit"));
        let mut second_capture = sample_action_capture(12, base + Duration::from_millis(1), "edit");
        second_capture.has_name = true;
        let second = sequencer.stamp_action(second_capture);

        let report = store
            .insert_actions(&[first, second])
            .expect("actions inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 2,
                skipped: 0
            }
        );
        assert_eq!(row_count(store.connection(), "selector_paths"), 1);
        let has_name: i64 = store
            .connection()
            .query_row("SELECT has_name FROM selector_paths", [], |row| row.get(0))
            .expect("selector has_name");
        assert_eq!(has_name, 1);
        let action_counts: Vec<(i64, i64)> = store
            .connection()
            .prepare(
                "SELECT record_session_id, action_count FROM record_sessions ORDER BY record_session_id",
            )
            .expect("prepare record sessions")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query record sessions")
            .collect::<Result<Vec<_>, _>>()
            .expect("record session rows");
        assert_eq!(action_counts, vec![(11, 1), (12, 1)]);
    }

    #[test]
    fn record_request_and_session_lifecycle_round_trip() {
        let (_dir, mut store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        let request_id = store
            .create_record_request(
                1_010,
                10_000,
                Some("automatable_routine"),
                r#"{"schema":"test","title":"Routine"}"#,
            )
            .expect("request");

        store
            .confirm_record_request(request_id, 1_020)
            .expect("confirm");
        let record_session_id = store
            .open_record_session(OpenRecordSessionParams {
                request_id: Some(request_id),
                session_id,
                started_ts: 1_030,
                title: Some("Routine"),
                policy_snapshot_json:
                    r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#,
                safety_cap_ms: 1_800_000,
                visible_indicator: true,
            })
            .expect("open recording");

        let request_row: (String, i64) = store
            .connection()
            .query_row(
                "SELECT status, fulfilled_record_session_id FROM record_requests WHERE request_id = ?1",
                [request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("request status");
        assert_eq!(
            request_row,
            (
                RecordRequestStatus::Started.as_str().to_string(),
                record_session_id
            )
        );

        store
            .pause_record_session(record_session_id, 1_100)
            .expect("pause");
        let open_pause: String = store
            .connection()
            .query_row(
                "SELECT pause_intervals_json FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| row.get(0),
            )
            .expect("open pause json");
        assert_eq!(open_pause, "[[1100,null]]");

        store
            .resume_record_session(record_session_id, 1_250)
            .expect("resume");
        store
            .close_record_session(record_session_id, 1_400, RecordStopReason::UserStop)
            .expect("close");
        let session_row: (String, Option<i64>, String, i64, i64) = store
            .connection()
            .query_row(
                "SELECT pause_intervals_json, ended_ts, stop_reason, safety_cap_ms, visible_indicator \
                 FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("record session row");
        assert_eq!(
            session_row,
            (
                "[[1100,1250]]".to_string(),
                Some(1_400),
                RecordStopReason::UserStop.as_str().to_string(),
                1_800_000,
                1,
            )
        );
    }

    #[test]
    fn open_finalizes_orphan_record_sessions_and_reconciles_confirmed_requests() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        {
            let mut store = GilbrethStore::open(&path).expect("store opens");
            let session_id = store.create_session(1_000, "test").expect("session");
            store
                .open_record_session(OpenRecordSessionParams {
                    request_id: None,
                    session_id,
                    started_ts: 1_100,
                    title: Some("empty"),
                    policy_snapshot_json:
                        r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#,
                    safety_cap_ms: 1_800_000,
                    visible_indicator: true,
                })
                .expect("empty recording");
            insert_recording_parent_for_session(store.connection(), session_id, 99);
            let base = Instant::now();
            let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
            let action = sequencer.stamp_action(sample_action_capture(
                99,
                base + Duration::from_millis(750),
                "orphan",
            ));
            store.insert_actions(&[action]).expect("action inserted");
            store
                .connection()
                .execute(
                    "INSERT INTO record_requests (request_id, requested_at, expires_at, status, candidate_json, updated_at) \
                     VALUES (200, 1_000, 10_000, 'confirmed', '{}', 1_000)",
                    [],
                )
                .expect("confirmed request");
        }

        let store = GilbrethStore::open(&path).expect("reopen repairs");
        let rows: Vec<(i64, Option<i64>, String)> = store
            .connection()
            .prepare(
                "SELECT record_session_id, ended_ts, stop_reason FROM record_sessions ORDER BY record_session_id",
            )
            .expect("prepare rows")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![
                (1, Some(1_100), RecordStopReason::Error.as_str().to_string()),
                (
                    99,
                    Some(1_750),
                    RecordStopReason::Error.as_str().to_string()
                ),
            ]
        );
        let status: String = store
            .connection()
            .query_row(
                "SELECT status FROM record_requests WHERE request_id = 200",
                [],
                |row| row.get(0),
            )
            .expect("request status");
        assert_eq!(status, RecordRequestStatus::Expired.as_str());
    }

    #[test]
    fn writer_ignores_record_routine_diagnostic_inputs() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);

        let handle = std::thread::spawn(move || {
            run_writer(
                store,
                rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::ActionDiag(sample_action_diag(77)))
            .expect("diag sent");
        tx.send(WriterInput::RejectedAction(sample_rejected_action(
            77,
            base + Duration::from_millis(1),
        )))
        .expect("rejected sent");
        drop(tx);

        let report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 0);
        assert_eq!(report.actions_written, 0);
        assert_eq!(report.actions_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(row_count(&conn, "events"), 0);
        assert_eq!(row_count(&conn, "action_events"), 0);
        assert_eq!(row_count(&conn, "selector_paths"), 0);
    }

    #[test]
    fn writer_record_commands_pause_drop_and_close_recordings() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(8);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    record_request_poll_interval: None,
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        let (start_reply_tx, start_reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StartRecording {
                request_id: None,
                title: Some("Routine".to_string()),
                policy_snapshot_json:
                    r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#
                        .to_string(),
                safety_cap_ms: 1_800_000,
                visible_indicator: true,
                reply: start_reply_tx,
            })
            .expect("start command");
        let record_session_id = start_reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("start reply")
            .expect("start ok");

        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(10),
            "before-pause",
        )))
        .expect("first action");
        wait_for_action_count(&path, 1);
        let (pause_reply_tx, pause_reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::PauseRecording {
                record_session_id,
                reply: pause_reply_tx,
            })
            .expect("pause command");
        pause_reply_rx
            .recv()
            .expect("pause reply")
            .expect("pause ok");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(20),
            "during-pause",
        )))
        .expect("paused action");
        std::thread::sleep(Duration::from_millis(50));
        let (resume_reply_tx, resume_reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ResumeRecording {
                record_session_id,
                reply: resume_reply_tx,
            })
            .expect("resume command");
        resume_reply_rx
            .recv()
            .expect("resume reply")
            .expect("resume ok");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(30),
            "after-resume",
        )))
        .expect("after resume action");
        wait_for_action_count(&path, 2);
        let (stop_reply_tx, stop_reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StopRecording {
                record_session_id,
                stop_reason: RecordStopReason::UserStop,
                reply: stop_reply_tx,
            })
            .expect("stop command");
        stop_reply_rx.recv().expect("stop reply").expect("stop ok");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(40),
            "after-stop",
        )))
        .expect("after stop action");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(report.actions_written, 2);
        assert_eq!(report.actions_skipped, 2);

        let conn = Connection::open(&path).expect("reader opens");
        let row: (i64, String, i64) = conn
            .query_row(
                "SELECT COUNT(*), stop_reason, action_count FROM record_sessions \
                 JOIN action_events USING (record_session_id) \
                 WHERE record_session_id = ?1",
                [record_session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("recording row");
        assert_eq!(
            row,
            (2, RecordStopReason::UserStop.as_str().to_string(), 2,)
        );
    }

    #[test]
    fn panic_action_cutoff_rejects_in_flight_actions_before_stop_command_arrives() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(8);
        let cutoff = PanicActionCutoff::default();
        let writer_cutoff = cutoff.clone();
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    record_request_poll_interval: None,
                    batch_size: 1,
                    panic_action_cutoff: writer_cutoff,
                    ..WriterConfig::default()
                },
            )
        });

        let (start_tx, start_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StartRecording {
                request_id: None,
                title: Some("Routine".to_string()),
                policy_snapshot_json:
                    r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#
                        .to_string(),
                safety_cap_ms: 1_800_000,
                visible_indicator: true,
                reply: start_tx,
            })
            .expect("start command");
        let record_session_id = start_rx.recv().expect("start reply").expect("start ok");
        let boundary = base + Duration::from_millis(20);
        cutoff.arm(record_session_id, boundary);

        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            boundary - Duration::from_millis(1),
            "before-panic",
        )))
        .expect("pre-boundary action");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            boundary,
            "in-flight-after-panic",
        )))
        .expect("post-boundary action races the command");

        let (stop_tx, stop_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StopRecording {
                record_session_id,
                stop_reason: RecordStopReason::PanicHotkey,
                reply: stop_tx,
            })
            .expect("panic stop command");
        stop_rx.recv().expect("stop reply").expect("stop ok");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(report.actions_written, 1);
        assert_eq!(report.actions_skipped, 1);
        let conn = Connection::open(&path).expect("reader opens");
        let row: (i64, String) = conn
            .query_row(
                "SELECT action_count, stop_reason FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("recording row");
        assert_eq!(row, (1, RecordStopReason::PanicHotkey.as_str().to_string()));
        assert!(cutoff.rejects(&sample_action_capture(
            record_session_id,
            boundary + Duration::from_millis(1),
            "late-old-session",
        )));
        cutoff.clear(record_session_id);
        assert!(!cutoff.rejects(&sample_action_capture(
            record_session_id,
            boundary + Duration::from_millis(2),
            "reused-session-id",
        )));
    }

    #[test]
    fn writer_replaces_contiguous_excluded_routine_actions_with_value_free_gaps() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(4);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_excluded_apps(["NOTEPAD.exe"]),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    record_request_poll_interval: None,
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StartRecording {
                request_id: None,
                title: Some("Routine".to_string()),
                policy_snapshot_json: "{}".to_string(),
                safety_cap_ms: 1_800_000,
                visible_indicator: true,
                reply: reply_tx,
            })
            .expect("start");
        let record_session_id = reply_rx.recv().expect("reply").expect("started");

        for offset in [10, 20] {
            tx.send(WriterInput::Action(sample_action_capture(
                record_session_id,
                base + Duration::from_millis(offset),
                "private-selector-must-not-survive",
            )))
            .expect("excluded action");
        }
        let mut allowed = sample_action_capture(
            record_session_id,
            base + Duration::from_millis(30),
            "allowed",
        );
        allowed.exe = Some("calc.exe".to_string());
        tx.send(WriterInput::Action(allowed))
            .expect("allowed action");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(40),
            "second-private-selector",
        )))
        .expect("second gap");
        wait_for_action_count(&path, 3);
        drop(tx);
        drop(command_tx);
        let report = handle.join().expect("join").expect("writer");
        assert_eq!(report.actions_written, 3);
        assert_eq!(
            report.actions_skipped, 0,
            "privacy exclusions are not a drop counter"
        );

        let conn = Connection::open(&path).expect("reader");
        let rows: Vec<(String, Option<String>, Option<String>, String)> = conn
            .prepare(
                "SELECT action_type, pattern_action, exe, sp.path_json
                 FROM action_events ae JOIN selector_paths sp USING (selector_id)
                 ORDER BY ae.seq",
            )
            .expect("prepare")
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].1.as_deref(), Some(EXCLUDED_APP_GAP_PATTERN));
        assert_eq!(rows[0].2, None);
        assert_eq!(rows[1].2.as_deref(), Some("calc.exe"));
        assert_eq!(rows[2].1.as_deref(), Some(EXCLUDED_APP_GAP_PATTERN));
        for gap in [&rows[0], &rows[2]] {
            let serialized = serde_json::to_string(gap).expect("serialize gap");
            assert!(!serialized.to_ascii_lowercase().contains("notepad"));
            assert!(!serialized.contains("private-selector"));
        }
    }

    #[test]
    fn excluded_motion_rows_leave_no_rows_seq_holes_or_identity_bytes() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_excluded_apps(["notepad.exe"]),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "excluded-private-title",
            base + Duration::from_millis(10),
        )))
        .expect("first excluded row");
        let mut allowed = captured_focus("allowed", base + Duration::from_millis(20));
        if let EventPayload::FocusChanged { window, .. } = &mut allowed.payload {
            window.exe = r"C:\Windows\System32\calc.exe".to_string();
        }
        tx.send(WriterInput::Motion(allowed.clone()))
            .expect("first allowed row");
        tx.send(WriterInput::Motion(captured_focus(
            "excluded-private-title-2",
            base + Duration::from_millis(30),
        )))
        .expect("second excluded row");
        if let EventPayload::FocusChanged { window, .. } = &mut allowed.payload {
            window.hwnd += 1;
            window.title = "allowed-2".to_string();
        }
        allowed.captured_at = base + Duration::from_millis(40);
        tx.send(WriterInput::Motion(allowed))
            .expect("second allowed row");
        drop(tx);
        drop(command_tx);
        let report = handle.join().expect("join").expect("writer");
        assert_eq!(report.events_written, 2);
        assert_eq!(
            report.events_skipped, 0,
            "privacy exclusion is not a drop counter"
        );

        let conn = Connection::open(&path).expect("reader");
        let rows: Vec<(i64, Option<String>, Option<String>)> = conn
            .prepare("SELECT seq, exe, title FROM events ORDER BY seq")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().map(|row| row.0).collect::<Vec<_>>(), vec![1, 2]);
        let bytes = serde_json::to_vec(&rows).expect("serialize rows");
        let text = String::from_utf8(bytes).expect("utf8").to_ascii_lowercase();
        assert!(!text.contains("notepad"));
        assert!(!text.contains("excluded-private-title"));
    }

    #[test]
    fn forget_focus_attribution_command_fails_closed_for_unattributed_input() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(4);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_excluded_apps(["private.exe"]),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        let windowless_key = |key: &str, captured_at: Instant| {
            Captured::new(
                Source::Keyboard,
                captured_at,
                EventPayload::Key {
                    key: key.to_string(),
                    mods: Modifiers::default(),
                    window: None,
                    key_class: None,
                },
            )
        };
        let mut allowed_focus = captured_focus("allowed", base + Duration::from_millis(10));
        if let EventPayload::FocusChanged { window, .. } = &mut allowed_focus.payload {
            window.exe = r"C:\Windows\System32\calc.exe".to_string();
        }
        tx.send(WriterInput::Motion(allowed_focus.clone()))
            .expect("allowed focus row");
        tx.send(WriterInput::Motion(windowless_key(
            "A",
            base + Duration::from_millis(20),
        )))
        .expect("latched window-less key");

        // Wait until both rows are durably written before sending the
        // command: the select loop draws from the event and command channels
        // in no particular order, so the ack below only sequences inputs
        // sent AFTER it was received.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let count: i64 = Connection::open(&path)
                .and_then(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                })
                .unwrap_or(0);
            if count >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "latched rows never reached the store"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let (ack_tx, ack_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ForgetFocusAttribution { ack: ack_tx })
            .expect("forget command");
        ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("forget acked");

        // Unattributed input after the forget fails closed; a later focus
        // row re-arms the latch end to end.
        tx.send(WriterInput::Motion(windowless_key(
            "B",
            base + Duration::from_millis(30),
        )))
        .expect("post-forget key");
        allowed_focus.captured_at = base + Duration::from_millis(40);
        tx.send(WriterInput::Motion(allowed_focus))
            .expect("re-arming focus row");
        tx.send(WriterInput::Motion(windowless_key(
            "C",
            base + Duration::from_millis(50),
        )))
        .expect("re-armed key");
        drop(tx);
        drop(command_tx);
        let report = handle.join().expect("join").expect("writer");
        assert_eq!(report.events_written, 4);

        let conn = Connection::open(&path).expect("reader");
        let rows: Vec<(i64, String, Option<String>)> = conn
            .prepare("SELECT seq, kind, key FROM events ORDER BY seq")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(
            rows.iter().map(|row| row.0).collect::<Vec<_>>(),
            vec![1, 2, 3, 4],
            "the dropped key must leave neither a row nor a seq hole"
        );
        let keys: Vec<&str> = rows
            .iter()
            .filter(|row| row.1 == "key")
            .filter_map(|row| row.2.as_deref())
            .collect();
        assert_eq!(keys, vec!["A", "C"], "the post-forget key must not store");
    }

    #[test]
    fn forget_drains_in_flight_focus_rows_so_none_can_re_arm_the_latch() {
        // The re-arm race (review finding F1): a FocusChanged already queued
        // when the forget command is processed must be applied BEFORE the
        // forget, not after — applied after, it would hold a stale
        // not-excluded verdict for the entire off period. The select loop
        // draws from both channels in random order, so each iteration is a
        // coin flip without the handler's drain; twenty iterations make a
        // regression effectively certain to trip the post-ack assert.
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(32);
        let (command_tx, command_rx) = bounded(4);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_excluded_apps(["private.exe"]),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        const ROUNDS: u64 = 20;
        for round in 0..ROUNDS {
            let at = base + Duration::from_millis(10 * round + 10);
            let mut allowed_focus = captured_focus("allowed", at);
            if let EventPayload::FocusChanged { window, .. } = &mut allowed_focus.payload {
                window.exe = r"C:\Windows\System32\calc.exe".to_string();
            }
            tx.send(WriterInput::Motion(allowed_focus))
                .expect("in-flight focus row");
            // Sent immediately, racing the focus row for the select loop.
            let (ack_tx, ack_rx) = bounded(1);
            command_tx
                .send(WriterCommand::ForgetFocusAttribution { ack: ack_tx })
                .expect("forget command");
            ack_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("forget acked");
            tx.send(WriterInput::Motion(Captured::new(
                Source::Keyboard,
                at + Duration::from_millis(1),
                EventPayload::Key {
                    key: "X".to_string(),
                    mods: Modifiers::default(),
                    window: None,
                    key_class: None,
                },
            )))
            .expect("post-ack window-less key");
        }
        drop(tx);
        drop(command_tx);
        let report = handle.join().expect("join").expect("writer");

        // Every focus row survives the drain (the drain applies rows, it
        // does not discard them); every post-ack window-less key fails
        // closed because the drained latch is forgotten.
        assert_eq!(report.events_written, ROUNDS as usize);
        let conn = Connection::open(&path).expect("reader");
        let (focus_rows, key_rows): (i64, i64) = conn
            .query_row(
                "SELECT \
                     SUM(CASE WHEN kind = 'focus_changed' THEN 1 ELSE 0 END), \
                     SUM(CASE WHEN kind = 'key' THEN 1 ELSE 0 END) \
                 FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("counts");
        assert_eq!(
            focus_rows, ROUNDS as i64,
            "no drained focus row may be lost"
        );
        assert_eq!(key_rows, 0, "a re-armed latch stored a post-forget key");
    }

    fn read_open_focus(path: &std::path::Path) -> Option<(i64, Option<String>, i64, i64)> {
        Connection::open(path)
            .ok()?
            .query_row(
                "SELECT session_id, exe, started_ts, high_water_ts FROM open_focus WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .ok()?
    }

    fn wait_for_open_focus_exe(path: &std::path::Path, expected: Option<&str>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let row = read_open_focus(path);
            let exe = row.as_ref().and_then(|row| row.1.as_deref());
            if exe == expected {
                return;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for open_focus exe {expected:?}; saw {row:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    type OpenFocusWriterHarness = (
        Sender<WriterInput>,
        Sender<WriterCommand>,
        std::thread::JoinHandle<Result<WriterReport, StoreError>>,
        i64,
    );

    fn open_focus_writer(path: &std::path::Path, policy: Policy) -> OpenFocusWriterHarness {
        let store = GilbrethStore::open(path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(32);
        let (command_tx, command_rx) = bounded(4);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                policy,
                WriterConfig {
                    flush_interval: Duration::from_millis(25),
                    batch_size: 1,
                    open_focus_beat_interval: Duration::from_millis(25),
                    ..WriterConfig::default()
                },
            )
        });
        (tx, command_tx, handle, session_id)
    }

    fn focus_to(exe: &str, at: Instant) -> Captured {
        Captured::new(
            Source::Foreground,
            at,
            EventPayload::FocusChanged {
                window: WindowRef {
                    hwnd: 0x11,
                    exe: exe.to_string(),
                    title: "t".to_string(),
                    pid: 7,
                },
                prev: None,
                previous_focused_for_ms: 0,
                window_unfocused_for_ms: 0,
                recovered: false,
            },
        )
    }

    #[test]
    fn open_focus_beat_tracks_replaces_and_clean_stop_clears() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let (tx, command_tx, handle, session_id) = open_focus_writer(&path, Policy::identity());
        let base = Instant::now();

        tx.send(WriterInput::Motion(focus_to("first.exe", base)))
            .expect("first focus");
        wait_for_open_focus_exe(&path, Some("first.exe"));
        let (row_session, _, started_first, high_first) =
            read_open_focus(&path).expect("row present");
        assert_eq!(row_session, session_id);
        assert!(high_first >= started_first);

        // A replacing focus row moves the segment; the beat keeps exactly
        // one row (CHECK id = 1) and re-points it.
        tx.send(WriterInput::Motion(focus_to(
            "second.exe",
            base + Duration::from_millis(10),
        )))
        .expect("second focus");
        wait_for_open_focus_exe(&path, Some("second.exe"));
        let count: i64 = Connection::open(&path)
            .and_then(|conn| {
                conn.query_row("SELECT COUNT(*) FROM open_focus", [], |row| row.get(0))
            })
            .expect("count");
        assert_eq!(count, 1);

        // A clean stop deletes the row after the final flush: row present at
        // the next open means an ungraceful end, and this stop is graceful.
        drop(tx);
        drop(command_tx);
        handle.join().expect("join").expect("writer");
        assert_eq!(read_open_focus(&path), None);
    }

    #[test]
    fn open_focus_clears_on_every_stored_close_path_row_kind() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let (tx, command_tx, handle, _) = open_focus_writer(
            &path,
            Policy::identity().with_excluded_apps(["private.exe"]),
        );
        let base = Instant::now();
        let mut at = base;
        let mut next_at = || {
            at += Duration::from_millis(5);
            at
        };

        let self_close = |at: Instant| {
            let window = WindowRef {
                hwnd: 0x11,
                exe: "self.exe".to_string(),
                title: "t".to_string(),
                pid: 7,
            };
            Captured::new(
                Source::Foreground,
                at,
                EventPayload::FocusChanged {
                    window: window.clone(),
                    prev: Some(window),
                    previous_focused_for_ms: 40,
                    window_unfocused_for_ms: 0,
                    recovered: false,
                },
            )
        };
        let closers: Vec<(&str, Captured)> = vec![
            ("self-close focus row", self_close(next_at())),
            (
                "power_suspend",
                Captured::new(
                    Source::System,
                    next_at(),
                    EventPayload::PowerSuspend { tick_ms: None },
                ),
            ),
            (
                "session_lock",
                Captured::new(
                    Source::System,
                    next_at(),
                    EventPayload::SessionLock { session_id: 1 },
                ),
            ),
            (
                "session_disconnect",
                Captured::new(
                    Source::System,
                    next_at(),
                    EventPayload::SessionDisconnect {
                        session_id: 1,
                        connection: SessionConnectionKind::Console,
                    },
                ),
            ),
            (
                "capture_paused",
                Captured::new(Source::System, next_at(), EventPayload::CapturePaused),
            ),
            ("excluded focus row", focus_to("private.exe", next_at())),
        ];

        for (label, closer) in closers {
            tx.send(WriterInput::Motion(focus_to("open.exe", next_at())))
                .expect("segment opens");
            wait_for_open_focus_exe(&path, Some("open.exe"));
            tx.send(WriterInput::Motion(closer)).expect(label);
            wait_for_open_focus_exe(&path, None);
        }

        // The stream-gate path stores no row at all; the forget command is
        // its clear signal (design decision 2 close set).
        tx.send(WriterInput::Motion(focus_to("open.exe", next_at())))
            .expect("segment opens");
        wait_for_open_focus_exe(&path, Some("open.exe"));
        let (ack_tx, ack_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ForgetFocusAttribution { ack: ack_tx })
            .expect("forget command");
        ack_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("forget acked");
        wait_for_open_focus_exe(&path, None);

        drop(tx);
        drop(command_tx);
        handle.join().expect("join").expect("writer");
    }

    #[test]
    fn open_focus_repair_synthesizes_recovered_row_and_is_idempotent() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let session_id;
        {
            let store = GilbrethStore::open(&path).expect("store opens");
            session_id = store.create_session(1_000, "test").expect("session");
            insert_minimal_event(store.connection(), session_id, 7, 2_000);
            store
                .upsert_open_focus(session_id, "crashed.exe", 10_000, 40_000)
                .expect("orphan row simulating a crash");
        }

        // Reopen: repair must synthesize before the orphan stamp so the
        // session ends on the recovered high-water mark.
        let store = GilbrethStore::open(&path).expect("reopen repairs");
        let conn = store.connection();
        let (seq, ts, exe, prev_exe, duration_ms, payload): (
            i64,
            i64,
            Option<String>,
            Option<String>,
            Option<i64>,
            String,
        ) = conn
            .query_row(
                "SELECT seq, ts, exe, prev_exe, duration_ms, payload FROM events \
                 WHERE kind = 'focus_changed' AND session_id = ?1",
                [session_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("synthesized row present");
        assert_eq!(seq, 8, "seq continues the session's shared universe");
        assert_eq!(ts, 40_000, "row lands on the high-water mark");
        assert_eq!(exe.as_deref(), Some("crashed.exe"));
        assert_eq!(
            prev_exe.as_deref(),
            Some("crashed.exe"),
            "the dwell reader takes the app from prev_exe"
        );
        assert_eq!(duration_ms, Some(30_000));
        assert!(
            payload.contains("\"recovered\":true"),
            "the payload carries the additive recovery flag: {payload}"
        );
        assert_eq!(
            session_ended_at(conn, session_id),
            Some(40_000),
            "the orphan stamp lands on the synthesized timestamp"
        );
        assert_eq!(read_open_focus(&path), None, "repair consumes the row");
        drop(store);

        // Idempotent: a second open finds no row and synthesizes nothing.
        let store = GilbrethStore::open(&path).expect("second open");
        let focus_rows: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'focus_changed'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(focus_rows, 1);
    }

    #[test]
    fn repair_discards_an_open_focus_row_whose_session_already_ended() {
        // The failed-final-DELETE shape: the close row flushed and the
        // session ended cleanly, but the open_focus delete did not land.
        // Synthesizing would double-count the dwell the close row already
        // recorded, so repair consumes the row without a synthesized row.
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        {
            let store = GilbrethStore::open(&path).expect("store opens");
            let session_id = store.create_session(1_000, "test").expect("session");
            insert_minimal_event(store.connection(), session_id, 1, 2_000);
            store.end_session(session_id, 3_000).expect("clean end");
            store
                .upsert_open_focus(session_id, "survivor.exe", 10_000, 40_000)
                .expect("row surviving a clean stop");
        }

        let store = GilbrethStore::open(&path).expect("reopen");
        let focus_rows: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'focus_changed'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(focus_rows, 0, "no dwell may be synthesized");
        assert_eq!(read_open_focus(&path), None, "the survivor row is consumed");
        assert_eq!(
            session_ended_at(store.connection(), 1),
            Some(3_000),
            "the clean end stamp is untouched"
        );
    }

    #[cfg(windows)]
    #[test]
    fn archive_stamps_open_focus_into_the_archive_copy_and_repair_matches() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 1, 2_000);
        store
            .upsert_open_focus(session_id, "open.exe", 10_000, 40_000)
            .expect("open segment row");

        let archive_path = dir.path().join("activity.gla");
        store
            .archive_activity_to(&archive_path, 50_000)
            .expect("archive");

        let archive = open_dpapi_archive(&archive_path);
        let open_focus_rows: i64 = archive
            .query_row("SELECT COUNT(*) FROM open_focus", [], |row| row.get(0))
            .expect("open_focus queryable in archive");
        assert_eq!(open_focus_rows, 0, "the archive carries no open segment");
        let (ts, duration_ms, payload): (i64, Option<i64>, String) = archive
            .query_row(
                "SELECT ts, duration_ms, payload FROM events WHERE kind = 'focus_changed'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("synthesized row in archive");
        assert_eq!(ts, 40_000);
        assert_eq!(duration_ms, Some(30_000));
        assert!(payload.contains("\"recovered\":true"));
        let ended_at: Option<i64> = archive
            .query_row(
                "SELECT ended_at FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .expect("archived session");
        assert_eq!(ended_at, Some(50_000), "the archive stamp still lands");

        // The live DB keeps its row: only the erase that follows in the
        // archive/reset command wipes it.
        assert!(read_open_focus(&path).is_some());
    }

    #[test]
    fn stop_recording_flushes_queued_actions_before_closing_session() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(8);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    record_request_poll_interval: None,
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let record_session_id = start_recording_for_writer(&command_tx);
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(10),
            "final-edit",
        )))
        .expect("action queued before stop");
        let (stop_reply_tx, stop_reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StopRecording {
                record_session_id,
                stop_reason: RecordStopReason::UserStop,
                reply: stop_reply_tx,
            })
            .expect("stop command");
        stop_reply_rx.recv().expect("stop reply").expect("stop ok");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(report.actions_written, 1);
        assert_eq!(report.actions_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(row_count(&conn, "action_events"), 1);
        let row: (String, i64) = conn
            .query_row(
                "SELECT stop_reason, action_count FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("record session row");
        assert_eq!(row, (RecordStopReason::UserStop.as_str().to_string(), 1));
    }

    #[test]
    fn writer_shutdown_closes_open_recording_with_app_shutdown() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded::<WriterInput>(1);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    record_request_poll_interval: None,
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });
        let record_session_id = start_recording_for_writer(&command_tx);

        drop(command_tx);
        drop(tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let conn = Connection::open(&path).expect("reader opens");
        let row: (Option<i64>, String) = conn
            .query_row(
                "SELECT ended_ts, stop_reason FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("recording row");
        assert!(row.0.is_some());
        assert_eq!(row.1, RecordStopReason::AppShutdown.as_str());
    }

    #[test]
    fn writer_polls_record_requests_once_without_auto_confirming() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let session_id = store.create_session(1_000, "test").expect("session");
        let request_id = store
            .create_record_request(1_000, i64::MAX, Some("automatable_routine"), "{}")
            .expect("request");
        let base = Instant::now();
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded::<WriterInput>(1);
        let (command_tx, command_rx) = bounded(2);
        let (notify_tx, notify_rx) = bounded(1);
        let (cap_tx, _cap_rx) = bounded(1);
        let prompt_flag = Arc::new(AtomicBool::new(false));

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    heartbeat_interval: None,
                    record_request_poll_interval: Some(Duration::from_millis(20)),
                    record_request_notify: Some(notify_tx),
                    cap_prompt_notify: Some(cap_tx),
                    record_prompt_in_flight: Some(prompt_flag),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let surfaced = notify_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("request surfaced");
        assert_eq!(surfaced.request_id, request_id);

        drop(command_tx);
        drop(tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let conn = Connection::open(&path).expect("reader opens");
        let status: String = conn
            .query_row(
                "SELECT status FROM record_requests WHERE request_id = ?1",
                [request_id],
                |row| row.get(0),
            )
            .expect("status");
        assert_eq!(status, RecordRequestStatus::Requested.as_str());
    }

    #[test]
    fn poll_record_request_resurfaces_after_dropped_tray_notification() {
        let (_dir, store) = temp_store();
        let request_id = store
            .create_record_request(1_000, i64::MAX, Some("automatable_routine"), "{}")
            .expect("request");
        let (notify_tx, notify_rx) = bounded(1);
        let prompt_flag = Arc::new(AtomicBool::new(false));
        let config = WriterConfig {
            record_request_notify: Some(notify_tx),
            record_prompt_in_flight: Some(Arc::clone(&prompt_flag)),
            ..WriterConfig::default()
        };
        let mut state = WriterRecordState::default();

        poll_recording_control(&store, &mut state, &config);
        let first = notify_rx.try_recv().expect("first request surfaced");
        assert_eq!(first.request_id, request_id);
        assert_eq!(state.last_surfaced_request_id, Some(request_id));

        prompt_flag.store(true, Ordering::SeqCst);
        poll_recording_control(&store, &mut state, &config);
        assert!(notify_rx.try_recv().is_err());
        assert_eq!(state.last_surfaced_request_id, Some(request_id));

        prompt_flag.store(false, Ordering::SeqCst);
        poll_recording_control(&store, &mut state, &config);
        let second = notify_rx.try_recv().expect("request re-surfaced");
        assert_eq!(second.request_id, request_id);
        assert_eq!(state.last_surfaced_request_id, Some(request_id));
    }

    #[test]
    fn poll_record_request_marks_invalid_candidate_json_failed() {
        let (_dir, store) = temp_store();
        store
            .connection()
            .execute(
                "
                INSERT INTO record_requests (
                    requested_at, expires_at, status, candidate_kind, candidate_json, updated_at
                )
                VALUES (1000, 9223372036854775807, ?1, 'automatable_routine', '{\"Name\":\"secret\"}', 1000)
                ",
                [RecordRequestStatus::Requested.as_str()],
            )
            .expect("invalid request inserted");
        let request_id = store.connection().last_insert_rowid();
        let (notify_tx, notify_rx) = bounded(1);
        let config = WriterConfig {
            record_request_notify: Some(notify_tx),
            ..WriterConfig::default()
        };
        let mut state = WriterRecordState::default();

        poll_recording_control(&store, &mut state, &config);

        assert!(notify_rx.try_recv().is_err());
        let status: String = store
            .connection()
            .query_row(
                "SELECT status FROM record_requests WHERE request_id = ?1",
                [request_id],
                |row| row.get(0),
            )
            .expect("status");
        assert_eq!(status, RecordRequestStatus::Failed.as_str());
    }

    #[test]
    fn expire_record_requests_marks_only_past_requested_rows() {
        let (_dir, store) = temp_store();
        let expired = store
            .create_record_request(1_000, 1_500, Some("automatable_routine"), "{}")
            .expect("expired request");
        let still_pending = store
            .create_record_request(1_000, 3_000, Some("automatable_routine"), "{}")
            .expect("pending request");

        assert_eq!(store.expire_record_requests(2_000).expect("expire"), 1);

        let rows: Vec<(i64, String)> = store
            .connection()
            .prepare("SELECT request_id, status FROM record_requests ORDER BY request_id")
            .expect("prepare requests")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query requests")
            .collect::<Result<Vec<_>, _>>()
            .expect("request rows");
        assert_eq!(
            rows,
            vec![
                (expired, RecordRequestStatus::Expired.as_str().to_string()),
                (
                    still_pending,
                    RecordRequestStatus::Requested.as_str().to_string()
                )
            ]
        );
    }

    #[test]
    fn paused_total_counts_closed_and_open_pause_intervals() {
        let pause_json = "[[1000,1500],[1800,null]]";

        assert_eq!(
            paused_total_ms_at(pause_json, 2_200).expect("paused total"),
            900
        );
    }

    #[test]
    fn writer_sends_cap_prompt_once_per_window() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let mut store = GilbrethStore::open(&path).expect("store opens");
        let session_id = store.create_session(1_000, "test").expect("session");
        let safety_cap_ms = 10_000;
        let started_ts = unix_now_ms().saturating_sub(safety_cap_ms + 50);
        let record_session_id = store
            .open_record_session(OpenRecordSessionParams {
                request_id: None,
                session_id,
                started_ts,
                title: Some("Routine"),
                policy_snapshot_json:
                    r#"{"schema":"gilbreth.record_session.policy.v1","value_free":true}"#,
                safety_cap_ms,
                visible_indicator: true,
            })
            .expect("record session");
        let base = Instant::now();
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded::<WriterInput>(1);
        let (command_tx, command_rx) = bounded(2);
        let (request_tx, _request_rx) = bounded(1);
        let (cap_tx, cap_rx) = bounded(1);
        let prompt_flag = Arc::new(AtomicBool::new(false));

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    heartbeat_interval: None,
                    record_request_poll_interval: Some(Duration::from_millis(20)),
                    record_request_notify: Some(request_tx),
                    cap_prompt_notify: Some(cap_tx),
                    record_prompt_in_flight: Some(prompt_flag),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let prompt = cap_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cap prompt");
        assert_eq!(prompt.record_session_id, record_session_id);
        assert!(prompt.window_index > 0);
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            cap_rx.try_recv().is_err(),
            "cap prompt should not repeat in same window"
        );

        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::StopRecording {
                record_session_id,
                stop_reason: RecordStopReason::SafetyCapStop,
                reply: reply_tx,
            })
            .expect("stop command");
        reply_rx.recv().expect("stop reply").expect("stop ok");
        drop(command_tx);
        drop(tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
    }

    #[test]
    fn run_writer_flushes_batches_timeouts_and_shutdown_end_session() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let writer_stop = stop.clone();
        let (tx, rx) = bounded(4);

        let handle = std::thread::spawn(move || {
            run_writer(
                store,
                rx,
                writer_stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_millis(25),
                    batch_size: 2,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus("Batch one", base)))
            .expect("first send");
        tx.send(WriterInput::Motion(captured_focus(
            "Batch two",
            base + Duration::from_millis(1),
        )))
        .expect("second send");
        wait_for_event_count(&path, 2);

        tx.send(WriterInput::Motion(captured_focus(
            "Timeout flush",
            base + Duration::from_millis(2),
        )))
        .expect("third send");
        wait_for_event_count(&path, 3);

        stop.cancel();
        drop(tx);
        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 3);
        assert_eq!(report.events_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        let (ended_at, seq_count): (Option<i64>, i64) = conn
            .query_row(
                "SELECT ended_at, (SELECT COUNT(DISTINCT seq) FROM events WHERE session_id = ?1) \
                 FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("session row");

        assert!(ended_at.is_some());
        assert_eq!(seq_count, 3);
    }

    #[test]
    fn run_writer_stop_token_exits_even_when_senders_remain_open() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let writer_stop = stop.clone();
        let (tx, rx) = bounded(4);
        let (command_tx, command_rx) = bounded(4);
        let (done_tx, done_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let result = run_writer_with_commands(
                store,
                rx,
                command_rx,
                writer_stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            );
            let _ = done_tx.send(result);
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Queued before stop",
            base,
        )))
        .expect("send pending event");
        stop.cancel();

        let report = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("writer exits on stop despite held senders")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 1);
        assert_eq!(report.events_skipped, 0);
        drop(command_tx);
        drop(tx);

        let conn = Connection::open(&path).expect("reader opens");
        let (ended_at, event_count): (Option<i64>, i64) = conn
            .query_row(
                "SELECT ended_at, (SELECT COUNT(*) FROM events WHERE session_id = ?1) \
                 FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("session row");
        assert!(ended_at.is_some());
        assert_eq!(event_count, 1);
    }

    #[test]
    fn run_writer_shutdown_drain_catches_forwarded_event_after_stop() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let writer_stop = stop.clone();
        let (tx, rx) = bounded(4);
        let (command_tx, command_rx) = bounded(4);
        let (done_tx, done_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let result = run_writer_with_commands(
                store,
                rx,
                command_rx,
                writer_stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            );
            let _ = done_tx.send(result);
        });

        stop.cancel();
        let delayed_event = WriterInput::Motion(captured_focus(
            "Forwarded after stop",
            base + Duration::from_millis(1),
        ));
        let delayed_tx = tx.clone();
        let delayed = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            delayed_tx
                .send(delayed_event)
                .expect("delayed forwarder send");
        });

        let report = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("writer drains delayed event after stop")
            .expect("writer succeeds");
        delayed.join().expect("delayed sender joins");
        assert_eq!(report.events_written, 1);
        assert_eq!(report.events_skipped, 0);
        drop(command_tx);
        drop(tx);

        let conn = Connection::open(&path).expect("reader opens");
        let (ended_at, event_count): (Option<i64>, i64) = conn
            .query_row(
                "SELECT ended_at, (SELECT COUNT(*) FROM events WHERE session_id = ?1) \
                 FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("session row");
        assert!(ended_at.is_some());
        assert_eq!(event_count, 1);
    }

    #[test]
    fn run_writer_flushes_pending_batch_after_disconnect() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);

        let handle = std::thread::spawn(move || {
            run_writer(
                store,
                rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Pending shutdown",
            base,
        )))
        .expect("send pending event");
        drop(tx);

        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 1);
        assert_eq!(report.events_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        let (events, ended_at): (i64, Option<i64>) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM events WHERE session_id = ?1), ended_at \
                 FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("session row");

        assert_eq!(events, 1);
        assert!(ended_at.is_some());
    }

    #[test]
    fn writer_interleaves_motion_and_action_inputs_in_shared_seq_order() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });
        let record_session_id = start_recording_for_writer(&command_tx);

        tx.send(WriterInput::Motion(captured_focus(
            "Before action",
            base + Duration::from_millis(100),
        )))
        .expect("motion sent");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(50),
            "edit",
        )))
        .expect("action sent");
        tx.send(WriterInput::Motion(captured_focus(
            "After action",
            base + Duration::from_millis(200),
        )))
        .expect("second motion sent");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 2);
        assert_eq!(report.actions_written, 1);
        assert_eq!(report.events_skipped, 0);
        assert_eq!(report.actions_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        let rows: Vec<(String, i64, i64)> = conn
            .prepare(
                "
                SELECT stream, seq, ts FROM (
                    SELECT 'event' AS stream, seq, ts FROM events
                    UNION ALL
                    SELECT 'action' AS stream, seq, ts FROM action_events
                )
                ORDER BY seq
                ",
            )
            .expect("prepare interleave")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query interleave")
            .collect::<Result<Vec<_>, _>>()
            .expect("interleave rows");
        assert_eq!(
            rows,
            vec![
                ("event".to_string(), 1, 1_100),
                ("action".to_string(), 2, 1_100),
                ("event".to_string(), 3, 1_200)
            ]
        );
    }

    #[test]
    fn writer_drops_actions_during_sensitive_context_without_seq_gap() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_sensitive_context_suppression(true),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });
        let record_session_id = start_recording_for_writer(&command_tx);

        tx.send(WriterInput::Motion(captured_sensitive_context_entered(
            base,
        )))
        .expect("sensitive enter sent");
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base + Duration::from_millis(1),
            "edit",
        )))
        .expect("action sent");
        tx.send(WriterInput::Motion(captured_focus(
            "Sensitive focus",
            base + Duration::from_millis(2),
        )))
        .expect("focus sent");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 2);
        assert_eq!(report.actions_written, 0);
        assert_eq!(report.actions_skipped, 1);

        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(row_count(&conn, "action_events"), 0);
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT seq, kind FROM events ORDER BY seq")
            .expect("prepare events")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query events")
            .collect::<Result<Vec<_>, _>>()
            .expect("event rows");
        assert_eq!(
            rows,
            vec![
                (1, "sensitive_context_entered".to_string()),
                (2, "focus_changed".to_string())
            ]
        );
    }

    #[test]
    fn writer_marks_capture_redacted_key_sensitive_before_password_boundary() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_sensitive_context_suppression(true),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_capture_redacted_key(base)))
            .expect("capture-redacted key sent");
        tx.send(WriterInput::Motion(captured_sensitive_context_entered(
            base + Duration::from_millis(1),
        )))
        .expect("sensitive enter sent");
        drop(command_tx);
        drop(tx);

        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 2);
        assert_eq!(report.events_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        let key_row: (String, String, i64, String) = conn
            .query_row(
                "SELECT key, title, is_sensitive, payload FROM events WHERE kind = 'key'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("key row");
        assert_eq!(key_row.0, "<redacted>");
        assert_eq!(key_row.1, "<redacted>");
        assert_eq!(key_row.2, 1);
        assert!(!key_row.3.contains("\"A\""));
        assert!(key_row.3.contains("<redacted>"));
    }

    #[test]
    fn writer_counts_failed_batch_as_skipped_and_continues() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        store
            .connection()
            .execute_batch(
                "
                CREATE TEMP TRIGGER fail_key_events
                BEFORE INSERT ON events
                WHEN NEW.kind = 'key'
                BEGIN
                    SELECT RAISE(ABORT, 'forced key insert failure');
                END;
                ",
            )
            .expect("failure trigger installed");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(4);

        let handle = std::thread::spawn(move || {
            run_writer(
                store,
                rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 1,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_key("A", base)))
            .expect("failed event sent");
        tx.send(WriterInput::Motion(captured_focus(
            "After failure",
            base + Duration::from_millis(1),
        )))
        .expect("successful event sent");
        drop(tx);

        let report = handle
            .join()
            .expect("writer thread joins")
            .expect("writer succeeds");
        assert_eq!(report.events_written, 1);
        assert_eq!(report.events_skipped, 1);

        let conn = Connection::open(&path).expect("reader opens");
        let (events, key_rows, focus_rows, ended_at): (i64, i64, i64, Option<i64>) = conn
            .query_row(
                "SELECT \
                    (SELECT COUNT(*) FROM events WHERE session_id = ?1), \
                    (SELECT COUNT(*) FROM events WHERE session_id = ?1 AND kind = 'key'), \
                    (SELECT COUNT(*) FROM events WHERE session_id = ?1 AND kind = 'focus_changed'), \
                    ended_at \
                 FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("session summary");

        assert_eq!(events, 1);
        assert_eq!(key_rows, 0);
        assert_eq!(focus_rows, 1);
        assert!(ended_at.is_some());
    }

    #[test]
    fn insert_events_returns_busy_for_retry_when_write_lock_blocks_row_insert() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let mut store = GilbrethStore::open(&path).expect("store opens");
        store
            .connection()
            .busy_timeout(Duration::ZERO)
            .expect("busy timeout set to zero");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let events = vec![sequencer.stamp(captured_focus("Retry me", base))];

        let lock = Connection::open(&path).expect("lock connection opens");
        lock.execute_batch("BEGIN IMMEDIATE")
            .expect("write lock held");
        let error = store
            .insert_events(&events)
            .expect_err("busy row insert should bubble for retry");
        assert!(is_sqlite_busy_or_locked(&error));
        lock.execute_batch("ROLLBACK").expect("write lock released");

        let report = store.insert_events(&events).expect("retry succeeds");
        assert_eq!(report.inserted, 1);
        assert_eq!(report.skipped, 0);
    }

    #[test]
    fn flush_batch_retries_sqlite_busy_until_success_and_keeps_events() {
        let mut batch = stamped_focus_batch(2);
        let mut report = WriterReport::default();
        let mut attempts = 0;

        flush_batch_with_insert(&mut batch, &mut report, |events| {
            attempts += 1;
            assert_eq!(batch_seq_range(events), Some((1, 2)));
            if attempts <= 3 {
                Err(sqlite_failure(rusqlite::ffi::SQLITE_BUSY))
            } else {
                Ok(InsertReport {
                    inserted: events.len(),
                    skipped: 0,
                })
            }
        });

        assert_eq!(attempts, 4);
        assert!(batch.is_empty());
        assert_eq!(report.events_written, 2);
        assert_eq!(report.events_skipped, 0);
    }

    #[test]
    fn flush_action_batch_retries_sqlite_busy_until_success_and_keeps_actions() {
        let mut batch = stamped_action_batch(2);
        let mut report = WriterReport::default();
        let mut attempts = 0;

        flush_action_batch_with_insert(&mut batch, &mut report, |actions| {
            attempts += 1;
            assert_eq!(action_batch_seq_range(actions), Some((1, 2)));
            if attempts <= 3 {
                Err(sqlite_failure(rusqlite::ffi::SQLITE_BUSY))
            } else {
                Ok(InsertReport {
                    inserted: actions.len(),
                    skipped: 0,
                })
            }
        });

        assert_eq!(attempts, 4);
        assert!(batch.is_empty());
        assert_eq!(report.actions_written, 2);
        assert_eq!(report.actions_skipped, 0);
    }

    #[test]
    fn flush_batch_retries_sqlite_busy_during_shutdown_until_success() {
        let mut batch = stamped_focus_batch(2);
        let mut report = WriterReport::default();
        let stop = StopToken::new();
        let mut attempts = 0;

        flush_batch_with_insert_and_stop(&mut batch, &mut report, &stop, |events| {
            attempts += 1;
            stop.cancel();
            if attempts <= 3 {
                Err(sqlite_failure(rusqlite::ffi::SQLITE_BUSY))
            } else {
                Ok(InsertReport {
                    inserted: events.len(),
                    skipped: 0,
                })
            }
        });

        assert_eq!(attempts, 4);
        assert!(batch.is_empty());
        assert_eq!(report.events_written, 2);
        assert_eq!(report.events_skipped, 0);
    }

    #[test]
    fn flush_batch_retries_sqlite_interrupt_once_during_shutdown() {
        let mut batch = stamped_focus_batch(2);
        let mut report = WriterReport::default();
        let stop = StopToken::new();
        stop.cancel();
        let mut attempts = 0;

        flush_batch_with_insert_and_stop(&mut batch, &mut report, &stop, |events| {
            attempts += 1;
            if attempts == 1 {
                Err(sqlite_failure(rusqlite::ffi::SQLITE_INTERRUPT))
            } else {
                Ok(InsertReport {
                    inserted: events.len(),
                    skipped: 0,
                })
            }
        });

        assert_eq!(attempts, 2);
        assert!(batch.is_empty());
        assert_eq!(report.events_written, 2);
        assert_eq!(report.events_skipped, 0);
    }

    #[test]
    fn flush_action_batch_retries_sqlite_busy_during_shutdown_until_success() {
        let mut batch = stamped_action_batch(2);
        let mut report = WriterReport::default();
        let stop = StopToken::new();
        let mut attempts = 0;

        flush_action_batch_with_insert_and_stop(&mut batch, &mut report, &stop, |actions| {
            attempts += 1;
            stop.cancel();
            if attempts <= 3 {
                Err(sqlite_failure(rusqlite::ffi::SQLITE_LOCKED))
            } else {
                Ok(InsertReport {
                    inserted: actions.len(),
                    skipped: 0,
                })
            }
        });

        assert_eq!(attempts, 4);
        assert!(batch.is_empty());
        assert_eq!(report.actions_written, 2);
        assert_eq!(report.actions_skipped, 0);
    }

    #[test]
    fn flush_batch_drops_after_busy_retry_budget_fails() {
        let mut batch = stamped_focus_batch(2);
        let mut report = WriterReport::default();
        let mut attempts = 0;

        flush_batch_with_insert(&mut batch, &mut report, |_| {
            attempts += 1;
            Err(sqlite_failure(rusqlite::ffi::SQLITE_BUSY))
        });

        assert_eq!(attempts, SQLITE_BUSY_RETRY_ATTEMPTS + 1);
        assert!(batch.is_empty());
        assert_eq!(report.events_written, 0);
        assert_eq!(report.events_skipped, 2);
    }

    #[test]
    fn flush_action_batch_drops_after_busy_retry_budget_fails() {
        let mut batch = stamped_action_batch(2);
        let mut report = WriterReport::default();
        let mut attempts = 0;

        flush_action_batch_with_insert(&mut batch, &mut report, |_| {
            attempts += 1;
            Err(sqlite_failure(rusqlite::ffi::SQLITE_BUSY))
        });

        assert_eq!(attempts, SQLITE_BUSY_RETRY_ATTEMPTS + 1);
        assert!(batch.is_empty());
        assert_eq!(report.actions_written, 0);
        assert_eq!(report.actions_skipped, 2);
    }

    #[test]
    fn flush_batch_does_not_retry_non_busy_errors() {
        let mut batch = stamped_focus_batch(2);
        let mut report = WriterReport::default();
        let mut attempts = 0;

        flush_batch_with_insert(&mut batch, &mut report, |_| {
            attempts += 1;
            Err(StoreError::Sqlite(rusqlite::Error::ExecuteReturnedResults))
        });

        assert_eq!(attempts, 1);
        assert!(batch.is_empty());
        assert_eq!(report.events_written, 0);
        assert_eq!(report.events_skipped, 2);
    }

    #[test]
    fn cutoff_ms_for_days_clamps_to_at_least_one_day() {
        assert_eq!(cutoff_ms_for_days(7, 10 * DAY_MS), 3 * DAY_MS);
        assert_eq!(cutoff_ms_for_days(0, 10 * DAY_MS), 9 * DAY_MS);
        assert_eq!(cutoff_ms_for_days(-4, 10 * DAY_MS), 9 * DAY_MS);
    }

    #[test]
    fn dashboard_request_recording_inserts_requested_row() {
        let (_dir, store) = temp_store();
        let request_id = request_recording(
            store.db_path(),
            Some("fragmentation_candidate"),
            r#"{"kind":"fragmentation","apps":["editor.exe"]}"#,
            42_000,
        )
        .expect("recording requested");

        let row: (i64, i64, String, Option<String>, String, i64) = store
            .connection()
            .query_row(
                "
                SELECT requested_at, expires_at, status, candidate_kind, candidate_json, updated_at
                FROM record_requests
                WHERE request_id = ?1
                ",
                [request_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("request row");

        assert_eq!(
            row,
            (
                42_000,
                42_000 + DAY_MS,
                "requested".to_string(),
                Some("fragmentation_candidate".to_string()),
                r#"{"kind":"fragmentation","apps":["editor.exe"]}"#.to_string(),
                42_000,
            )
        );
    }

    #[test]
    fn dashboard_request_recording_rejects_value_bearing_candidate_json() {
        let (_dir, store) = temp_store();

        let error = request_recording(
            store.db_path(),
            Some("fragmentation_candidate"),
            r#"{"kind":"fragmentation","evidence":{"text":"secret"}}"#,
            42_000,
        )
        .expect_err("value-bearing candidate must be rejected");

        assert!(
            error
                .to_string()
                .contains("candidate_json contains forbidden value-bearing key text"),
            "unexpected error: {error}"
        );
        assert_eq!(row_count(store.connection(), "record_requests"), 0);
    }

    #[test]
    fn dashboard_request_recording_reports_missing_record_requests_table() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        Connection::open(&path)
            .expect("db opens")
            .execute_batch(SCHEMA_SQL)
            .expect("pre-record-routine schema created");

        let error = request_recording(
            &path,
            Some("fragmentation_candidate"),
            r#"{"kind":"fragmentation"}"#,
            42_000,
        )
        .expect_err("old schema must report the missing request table");

        assert!(
            error
                .to_string()
                .contains("record_requests table is not present"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn dashboard_delete_events_deletes_only_requested_ids_and_deduplicates_selection() {
        let (_dir, store) = temp_store();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_minimal_event(store.connection(), session_id, 1, 1_100);
        insert_minimal_event(store.connection(), session_id, 2, 1_200);
        insert_minimal_event(store.connection(), session_id, 3, 1_300);
        let result = delete_events(store.db_path(), &[3, 1, 1, 404]).expect("events deleted");

        assert_eq!(
            result,
            DeleteResult {
                deleted: 2,
                scrub_warning: None
            }
        );
        let remaining: Vec<i64> = store
            .connection()
            .prepare("SELECT seq FROM events ORDER BY seq")
            .expect("prepare remaining events")
            .query_map([], |row| row.get(0))
            .expect("query remaining events")
            .collect::<Result<Vec<_>, _>>()
            .expect("remaining events");
        assert_eq!(remaining, vec![2]);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AuditRow {
        kind: String,
        session_id: i64,
        rows_deleted: i64,
        seq_min: i64,
        seq_max: i64,
        cutoff_ms: Option<i64>,
    }

    fn deletion_audit_rows(conn: &Connection) -> Vec<AuditRow> {
        conn.prepare(
            "
            SELECT kind, session_id, rows_deleted, seq_min, seq_max, cutoff_ms
            FROM deletion_audit
            ORDER BY id
            ",
        )
        .expect("prepare audit rows")
        .query_map([], |row| {
            Ok(AuditRow {
                kind: row.get(0)?,
                session_id: row.get(1)?,
                rows_deleted: row.get(2)?,
                seq_min: row.get(3)?,
                seq_max: row.get(4)?,
                cutoff_ms: row.get(5)?,
            })
        })
        .expect("query audit rows")
        .collect::<Result<_, _>>()
        .expect("audit rows")
    }

    #[test]
    fn dashboard_delete_events_audits_count_and_seq_span_per_session() {
        let (_dir, store) = temp_store();
        let first = store.create_session(1_000, "test").expect("first session");
        let second = store.create_session(2_000, "test").expect("second session");
        insert_minimal_event(store.connection(), first, 0, 1_100);
        insert_minimal_event(store.connection(), first, 1, 1_200);
        insert_minimal_event(store.connection(), first, 2, 1_300);
        insert_minimal_event(store.connection(), second, 0, 2_100);
        let ids: Vec<i64> = store
            .connection()
            .prepare("SELECT id FROM events ORDER BY session_id, seq")
            .expect("prepare ids")
            .query_map([], |row| row.get(0))
            .expect("query ids")
            .collect::<Result<_, _>>()
            .expect("ids");

        // Delete seqs 0 and 2 of the first session and the second session's
        // only row; the unknown id must not audit anything.
        let result = delete_events(store.db_path(), &[ids[0], ids[2], ids[3], 404_404])
            .expect("events deleted");

        assert_eq!(result.deleted, 3);
        assert_eq!(
            deletion_audit_rows(store.connection()),
            vec![
                AuditRow {
                    kind: DELETION_AUDIT_KIND_EVENT_DELETE.to_string(),
                    session_id: first,
                    rows_deleted: 2,
                    seq_min: 0,
                    seq_max: 2,
                    cutoff_ms: None,
                },
                AuditRow {
                    kind: DELETION_AUDIT_KIND_EVENT_DELETE.to_string(),
                    session_id: second,
                    rows_deleted: 1,
                    seq_min: 0,
                    seq_max: 0,
                    cutoff_ms: None,
                },
            ]
        );
    }

    #[test]
    fn dashboard_prune_audits_deleted_rows_with_the_cutoff() {
        let (_dir, store) = temp_store();
        let first = store.create_session(1_000, "test").expect("first session");
        let second = store.create_session(2_000, "test").expect("second session");
        insert_minimal_event(store.connection(), first, 0, 1_100);
        insert_minimal_event(store.connection(), first, 1, 1_200);
        insert_minimal_event(store.connection(), second, 0, 1_500);
        insert_minimal_event(store.connection(), second, 1, 9_000);

        let result = prune_old_events(store.db_path(), 5_000).expect("pruned");

        assert_eq!(result.events_deleted, 3);
        assert_eq!(
            deletion_audit_rows(store.connection()),
            vec![
                AuditRow {
                    kind: DELETION_AUDIT_KIND_DASHBOARD_PRUNE.to_string(),
                    session_id: first,
                    rows_deleted: 2,
                    seq_min: 0,
                    seq_max: 1,
                    cutoff_ms: Some(5_000),
                },
                AuditRow {
                    kind: DELETION_AUDIT_KIND_DASHBOARD_PRUNE.to_string(),
                    session_id: second,
                    rows_deleted: 1,
                    seq_min: 0,
                    seq_max: 0,
                    cutoff_ms: Some(5_000),
                },
            ]
        );
    }

    #[test]
    fn dashboard_delete_recording_audits_its_action_event_rows() {
        let (_dir, store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 10,
                record_session_id: 20,
                selector_id: 30,
                session_id,
                seq: 7,
                action_ts: 1_500,
                record_ended_ts: Some(2_000),
                request_expires_at: 90_000,
                selector_hash: "hash-a",
            },
        );

        let result = delete_recording(store.db_path(), 20).expect("recording deleted");

        assert_eq!(result.deleted, 1);
        assert_eq!(
            deletion_audit_rows(store.connection()),
            vec![AuditRow {
                kind: DELETION_AUDIT_KIND_RECORDING_DELETE.to_string(),
                session_id,
                rows_deleted: 1,
                seq_min: 7,
                seq_max: 7,
                cutoff_ms: None,
            }]
        );
    }

    #[test]
    fn startup_retention_prune_audits_deleted_rows_with_the_cutoff() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let old_session = store.create_session(1_000, "test").expect("old session");
        store.end_session(old_session, 4_000).expect("old ended");
        let mut sequencer = Sequencer::new(old_session, SessionTimebase::new(base, 1_000));
        let first = sequencer.stamp(captured_focus("Old one", base));
        let second = sequencer.stamp(captured_focus("Old two", base + Duration::from_millis(10)));
        store
            .insert_events(&[first.clone(), second.clone()])
            .expect("events inserted");
        // Both action_events passes must feed the audit: seq 10 goes in the
        // ts-pass (its still-open recording keeps record_sessions row 20
        // alive), seq 11 goes in the orphan sweep (record_session 999 does
        // not exist; its ts is inside the window, so only the sweep takes it).
        store
            .connection()
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("allow the orphan fixture row");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 10,
                record_session_id: 20,
                selector_id: 30,
                session_id: old_session,
                seq: 10,
                action_ts: 2_000,
                record_ended_ts: None,
                request_expires_at: 90_000,
                selector_hash: "hash-retention",
            },
        );
        store
            .connection()
            .execute(
                "
                INSERT INTO action_events (
                    session_id, seq, ts, action_type, pattern_action, selector_id,
                    trust_basis, exe, record_session_id, payload
                )
                VALUES (?1, 11, 9000, 'invoke', 'invoke', 30, 'pid_match', 'app.exe', 999, '{}')
                ",
                [old_session],
            )
            .expect("orphan action row inserted");

        let report = store.prune_old_activity(5_000).expect("retention prune");

        assert_eq!(report.events_deleted, 2);
        assert_eq!(
            deletion_audit_rows(store.connection()),
            vec![AuditRow {
                kind: DELETION_AUDIT_KIND_STARTUP_RETENTION.to_string(),
                session_id: old_session,
                rows_deleted: 4,
                seq_min: u64_to_i64(first.seq),
                seq_max: 11,
                cutoff_ms: Some(5_000),
            }]
        );
        assert_eq!(
            row_count(store.connection(), "action_events"),
            0,
            "the ts-pass and the orphan sweep both ran"
        );
    }

    #[test]
    fn mouse_move_retention_audits_batches_as_one_operation() {
        let (_dir, mut store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        // One row past the batch size forces a second batch. Bulk-insert
        // inside one transaction so the fixture stays fast.
        let total_rows: i64 = 20_001;
        {
            let conn = store.connection();
            conn.execute_batch("BEGIN").expect("begin fixture tx");
            let mut stmt = conn
                .prepare(
                    "
                    INSERT INTO events (session_id, seq, ts, source, kind, payload)
                    VALUES (?1, ?2, ?3, 'mouse', 'mouse_move', '{}')
                    ",
                )
                .expect("prepare fixture insert");
            for seq in 0..total_rows {
                stmt.execute(params![session_id, seq, 1_000 + seq])
                    .expect("fixture row inserted");
            }
            drop(stmt);
            conn.execute_batch("COMMIT").expect("commit fixture tx");
        }

        let pruned = store
            .prune_mouse_moves_before(1_000 + total_rows)
            .expect("prune runs");

        assert_eq!(pruned, total_rows as u64);
        let audit = deletion_audit_rows(store.connection());
        assert_eq!(audit.len(), 2, "one audit row per batch: {audit:?}");
        assert!(audit
            .iter()
            .all(|row| row.kind == DELETION_AUDIT_KIND_MOUSE_MOVE_RETENTION
                && row.session_id == session_id
                && row.cutoff_ms == Some(1_000 + total_rows)));
        assert_eq!(
            audit.iter().map(|row| row.rows_deleted).sum::<i64>(),
            total_rows
        );
        assert_eq!(audit.iter().map(|row| row.seq_min).min(), Some(0));
        assert_eq!(
            audit.iter().map(|row| row.seq_max).max(),
            Some(total_rows - 1)
        );
        // Batches share one operation timestamp.
        let distinct_performed_at: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(DISTINCT performed_at) FROM deletion_audit",
                [],
                |row| row.get(0),
            )
            .expect("performed_at count");
        assert_eq!(distinct_performed_at, 1);
    }

    #[test]
    fn secure_erase_deletes_deletion_audit_rows() {
        let (_dir, mut store) = temp_store();
        store
            .connection()
            .execute(
                "
                INSERT INTO deletion_audit
                    (kind, performed_at, session_id, rows_deleted, seq_min, seq_max, cutoff_ms)
                VALUES ('event_delete', 1, 1, 1, 0, 0, NULL)
                ",
                [],
            )
            .expect("audit row inserted");

        store.secure_delete_activity().expect("erase runs");

        assert_eq!(row_count(store.connection(), "deletion_audit"), 0);
    }

    #[test]
    fn dashboard_delete_still_works_without_the_deletion_audit_table() {
        let (_dir, store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 0, 1_100);
        store
            .connection()
            .execute("DROP TABLE deletion_audit", [])
            .expect("simulate a pre-008 database");

        let result = delete_events(store.db_path(), &[1]).expect("delete still works");

        assert_eq!(result.deleted, 1);
        assert!(
            !sqlite_table_exists(store.connection(), "deletion_audit").expect("table probe"),
            "the guard must skip the audit, not recreate the table"
        );
    }

    #[test]
    fn temporary_secure_delete_restores_original_setting_on_same_connection() {
        let (_dir, store) = temp_store();
        let mut conn =
            dashboard_writable_connection(store.db_path()).expect("dashboard connection");
        conn.execute_batch("PRAGMA secure_delete = FAST;")
            .expect("set secure_delete");

        with_temporary_secure_delete(&mut conn, |active| {
            assert_eq!(secure_delete_setting(active)?, 1);
            Ok(())
        })
        .expect("temporary secure delete");

        assert_eq!(secure_delete_setting(&conn).expect("restored setting"), 2);
    }

    #[test]
    fn dashboard_delete_events_scrubs_deleted_bytes_from_sqlite_storage() {
        let (_dir, mut store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let sentinel = "GILBRETH_DASH_DELETE_SENTINEL_d8c3923b";
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus(sentinel, base));
        store.insert_events(&[event]).expect("sentinel inserted");
        let event_id = store
            .connection()
            .query_row(
                "SELECT id FROM events WHERE title = ?1",
                [sentinel],
                |row| row.get(0),
            )
            .expect("event id");
        assert!(
            sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "sentinel should be present before selected delete"
        );

        let result = delete_events(&db_path, &[event_id]).expect("event deleted");

        assert_eq!(result.deleted, 1);
        assert_eq!(result.scrub_warning, None);
        assert!(
            !sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "selected delete should flush secure-deleted pages out of db/wal/shm"
        );
    }

    #[test]
    fn dashboard_delete_recording_collects_exclusive_and_preserves_shared_selector() {
        let (_dir, store) = temp_store();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 10,
                record_session_id: 20,
                selector_id: 30,
                session_id,
                seq: 1,
                action_ts: 1_200,
                record_ended_ts: Some(1_500),
                request_expires_at: 2_000,
                selector_hash: "shared-selector",
            },
        );
        insert_record_routine_parent(
            store.connection(),
            RecordRoutineParentFixture {
                request_id: 11,
                record_session_id: 21,
                session_id,
                started_ts: 1_600,
                ended_ts: Some(1_900),
                request_expires_at: 2_200,
                action_count: 1,
            },
        );
        store
            .connection()
            .execute(
                "
                INSERT INTO action_events (
                    session_id, seq, ts, action_type, pattern_action, selector_id,
                    trust_basis, exe, record_session_id, payload
                )
                VALUES (?1, 2, 1700, 'invoke', 'invoke', 30, 'pid_match', 'app.exe', 21, '{}')
                ",
                [session_id],
            )
            .expect("shared selector action inserted");
        store
            .connection()
            .execute_batch(
                "
                INSERT INTO selector_paths (
                    selector_id, path_hash, framework, depth, path_json, created_ts
                )
                VALUES (31, 'exclusive-selector', 'uia', 1, '[]', 1750);
                ",
            )
            .expect("exclusive selector inserted");
        store
            .connection()
            .execute(
                "
                INSERT INTO action_events (
                    session_id, seq, ts, action_type, pattern_action, selector_id,
                    trust_basis, exe, record_session_id, payload
                )
                VALUES (
                    ?1, 3, 1750, 'invoke', 'invoke', 31,
                    'pid_match', 'app.exe', 20, '{}'
                )
                ",
                [session_id],
            )
            .expect("exclusive selector action inserted");

        let result = delete_recording(store.db_path(), 20).expect("recording deleted");

        assert_eq!(result.deleted, 1);
        assert_eq!(result.scrub_warning, None);
        assert_eq!(record_routine_counts(store.connection()), (1, 1, 1, 1));
        let remaining_request: i64 = store
            .connection()
            .query_row("SELECT request_id FROM record_requests", [], |row| {
                row.get(0)
            })
            .expect("remaining request");
        assert_eq!(remaining_request, 11);
        let remaining_selector: String = store
            .connection()
            .query_row("SELECT path_hash FROM selector_paths", [], |row| row.get(0))
            .expect("remaining selector");
        assert_eq!(remaining_selector, "shared-selector");
    }

    #[test]
    fn dashboard_delete_recording_refuses_open_recording() {
        let (_dir, store) = temp_store();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_record_routine_parent(
            store.connection(),
            RecordRoutineParentFixture {
                request_id: 12,
                record_session_id: 22,
                session_id,
                started_ts: 1_100,
                ended_ts: None,
                request_expires_at: 2_000,
                action_count: 0,
            },
        );

        let error = delete_recording(store.db_path(), 22).expect_err("open recording rejected");

        assert!(error.to_string().contains("open recording"));
        assert_eq!(record_routine_counts(store.connection()), (1, 1, 0, 0));
    }

    #[test]
    fn dashboard_prune_preview_and_result_cover_record_routine_rows() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        {
            let store = GilbrethStore::open(&path).expect("store opens");
            let old_session = store
                .create_session(0, "test")
                .expect("old session created");
            store
                .end_session(old_session, 2_000)
                .expect("old session ended");
            insert_minimal_event(store.connection(), old_session, 1, 1_000);

            let recent_session = store
                .create_session(0, "test")
                .expect("recent session created");
            store
                .end_session(recent_session, 8_000)
                .expect("recent session ended");
            insert_minimal_event(store.connection(), recent_session, 1, 6_000);

            let routine_session = store
                .create_session(0, "test")
                .expect("routine session created");
            store
                .end_session(routine_session, 3_000)
                .expect("routine session ended");
            insert_record_routine_rows(
                store.connection(),
                RecordRoutineFixture {
                    request_id: 40,
                    record_session_id: 50,
                    selector_id: 60,
                    session_id: routine_session,
                    seq: 1,
                    action_ts: 1_500,
                    record_ended_ts: Some(2_500),
                    request_expires_at: 2_000,
                    selector_hash: "old-selector",
                },
            );

            let open_routine_session = store
                .create_session(0, "test")
                .expect("open routine session created");
            store
                .end_session(open_routine_session, 3_500)
                .expect("open routine parent session ended");
            insert_record_routine_parent(
                store.connection(),
                RecordRoutineParentFixture {
                    request_id: 41,
                    record_session_id: 51,
                    session_id: open_routine_session,
                    started_ts: 1_800,
                    ended_ts: None,
                    request_expires_at: 2_200,
                    action_count: 0,
                },
            );
        }

        let preview = prune_preview(&path, 5_000).expect("preview");
        assert_eq!(
            preview,
            DashboardPrunePreview {
                cutoff_ms: 5_000,
                events: 1,
                ended_empty_sessions: 2,
                action_events: 1,
                ended_empty_record_sessions: 1,
                record_requests: 1,
                selector_paths: 1,
            }
        );
        assert_eq!(preview.total_rows(), 7);

        let result = prune_old_events(&path, 5_000).expect("pruned");

        assert_eq!(result.events_deleted, 1);
        assert_eq!(result.sessions_deleted, 2);
        assert_eq!(result.action_events_deleted, 1);
        assert_eq!(result.record_sessions_deleted, 1);
        assert_eq!(result.record_requests_deleted, 1);
        assert_eq!(result.selector_paths_deleted, 1);
        assert_eq!(result.total_deleted(), 7);
        assert!(result.compaction_completed, "{:?}", result.compact_error);

        let conn = Connection::open(&path).expect("db opens");
        assert_eq!(row_count(&conn, "events"), 1);
        assert_eq!(row_count(&conn, "sessions"), 2);
        assert_eq!(record_routine_counts(&conn), (1, 1, 0, 0));
    }

    #[test]
    fn dashboard_prune_preserves_recording_rows_with_recent_actions() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        {
            let store = GilbrethStore::open(&path).expect("store opens");
            let session_id = store.create_session(0, "test").expect("session created");
            store.end_session(session_id, 7_000).expect("session ended");
            insert_minimal_event(store.connection(), session_id, 1, 1_000);
            insert_record_routine_rows(
                store.connection(),
                RecordRoutineFixture {
                    request_id: 70,
                    record_session_id: 80,
                    selector_id: 90,
                    session_id,
                    seq: 2,
                    action_ts: 6_000,
                    record_ended_ts: Some(2_000),
                    request_expires_at: 2_000,
                    selector_hash: "recent-action-selector",
                },
            );
        }

        let preview = prune_preview(&path, 5_000).expect("preview");
        assert_eq!(preview.events, 1);
        assert_eq!(preview.ended_empty_sessions, 0);
        assert_eq!(preview.action_events, 0);
        assert_eq!(preview.ended_empty_record_sessions, 0);
        assert_eq!(preview.record_requests, 0);
        assert_eq!(preview.selector_paths, 0);

        let result = prune_old_events(&path, 5_000).expect("pruned");

        assert_eq!(result.events_deleted, 1);
        assert_eq!(result.sessions_deleted, 0);
        assert_eq!(result.action_events_deleted, 0);
        assert_eq!(result.record_sessions_deleted, 0);
        assert_eq!(result.record_requests_deleted, 0);
        assert_eq!(result.selector_paths_deleted, 0);
        let conn = Connection::open(&path).expect("db opens");
        assert_eq!(row_count(&conn, "sessions"), 1);
        assert_eq!(record_routine_counts(&conn), (1, 1, 1, 1));
    }

    #[test]
    fn dashboard_prune_sweeps_recent_action_with_missing_recording_parent() {
        let (_dir, store) = temp_store();
        let session_id = store.create_session(0, "test").expect("session created");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 100,
                record_session_id: 101,
                selector_id: 102,
                session_id,
                seq: 1,
                action_ts: 6_000,
                record_ended_ts: Some(7_000),
                request_expires_at: 10_000,
                selector_hash: "orphan-action-selector",
            },
        );
        store
            .connection()
            .execute_batch(
                "
                PRAGMA foreign_keys = OFF;
                DELETE FROM record_sessions WHERE record_session_id = 101;
                PRAGMA foreign_keys = ON;
                ",
            )
            .expect("orphan action fixture created");
        assert_eq!(record_routine_counts(store.connection()), (1, 0, 1, 1));

        let result = prune_old_events(store.db_path(), 5_000).expect("pruned");

        assert_eq!(result.events_deleted, 0);
        assert_eq!(result.sessions_deleted, 0);
        assert_eq!(result.action_events_deleted, 1);
        assert_eq!(result.record_sessions_deleted, 0);
        assert_eq!(result.record_requests_deleted, 0);
        assert_eq!(result.selector_paths_deleted, 1);
        assert_eq!(result.total_deleted(), 2);
        assert_eq!(record_routine_counts(store.connection()), (1, 0, 0, 0));
    }

    #[test]
    fn dashboard_prune_propagates_compaction_warning() {
        let (_dir, store) = temp_store();

        let result = prune_old_events_with_compactor(store.db_path(), i64::MIN, |_| {
            Some("forced compaction warning".to_string())
        })
        .expect("prune result");

        assert!(!result.compaction_completed);
        assert_eq!(
            result.compact_error.as_deref(),
            Some("forced compaction warning")
        );
    }

    #[test]
    fn dashboard_prune_tolerates_pre_record_routine_schema() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        {
            let conn = Connection::open(&path).expect("db opens");
            conn.execute_batch(SCHEMA_SQL).expect("schema created");
            conn.execute(
                "INSERT INTO sessions (session_id, started_at, ended_at, app_version)
                 VALUES (1, 0, 2000, 'test')",
                [],
            )
            .expect("session inserted");
            conn.execute(
                "INSERT INTO events (session_id, seq, ts, source, kind, payload)
                 VALUES (1, 1, 1000, 'system', 'test_event', '{}')",
                [],
            )
            .expect("event inserted");
        }

        let preview = prune_preview(&path, 5_000).expect("preview");
        assert_eq!(preview.events, 1);
        assert_eq!(preview.ended_empty_sessions, 1);
        assert_eq!(preview.action_events, 0);
        assert_eq!(preview.record_requests, 0);

        let result = prune_old_events(&path, 5_000).expect("pruned");

        assert_eq!(result.events_deleted, 1);
        assert_eq!(result.sessions_deleted, 1);
        assert_eq!(result.action_events_deleted, 0);
        assert_eq!(result.record_sessions_deleted, 0);
        let conn = Connection::open(&path).expect("db opens");
        assert_eq!(row_count(&conn, "events"), 0);
        assert_eq!(row_count(&conn, "sessions"), 0);
    }

    #[test]
    fn secure_delete_activity_removes_rows_meta_and_allows_fresh_session() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus("Before erase", base));
        store.insert_events(&[event]).expect("event inserted");
        store
            .connection()
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('db_uuid', 'old')",
                [],
            )
            .expect("meta inserted");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 1,
                record_session_id: 1,
                selector_id: 1,
                session_id,
                seq: 2,
                action_ts: 1_200,
                record_ended_ts: Some(1_500),
                request_expires_at: 2_000,
                selector_hash: "erase-hash",
            },
        );
        store
            .connection()
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("disable foreign_keys before secure erase");
        assert!(
            erased_table_sequence_count(store.connection()) > 0,
            "test setup should populate sqlite_sequence"
        );

        let report = store
            .secure_delete_activity()
            .expect("secure delete completes");

        assert_eq!(report.events_deleted, 1);
        assert_eq!(report.sessions_deleted, 1);
        assert_eq!(row_count(store.connection(), "events"), 0);
        assert_eq!(row_count(store.connection(), "sessions"), 0);
        assert_eq!(row_count(store.connection(), "meta"), 0);
        assert_eq!(record_routine_counts(store.connection()), (0, 0, 0, 0));
        assert_eq!(erased_table_sequence_count(store.connection()), 0);

        store.mint_meta_identity(2_000).expect("meta identity");
        let new_session_id = store.create_session(2_000, "test").expect("new session");
        let mut sequencer = Sequencer::new(new_session_id, SessionTimebase::new(base, 2_000));
        let event = sequencer.stamp(captured_focus("After erase", base));
        store.insert_events(&[event]).expect("post erase insert");

        assert_eq!(row_count(store.connection(), "events"), 1);
        assert_eq!(row_count(store.connection(), "sessions"), 1);
        assert_eq!(row_count(store.connection(), "meta"), 2);
    }

    #[test]
    fn secure_delete_activity_removes_record_routine_rows_with_foreign_keys_on() {
        let (_dir, mut store) = temp_store();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 2,
                record_session_id: 2,
                selector_id: 2,
                session_id,
                seq: 1,
                action_ts: 1_200,
                record_ended_ts: Some(1_500),
                request_expires_at: 2_000,
                selector_hash: "erase-fk-on-hash",
            },
        );
        let foreign_keys: i64 = store
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("foreign_keys pragma");
        assert_eq!(foreign_keys, 1);

        store
            .secure_delete_activity()
            .expect("secure delete completes");

        assert_eq!(record_routine_counts(store.connection()), (0, 0, 0, 0));
    }

    #[test]
    fn secure_delete_activity_scrubs_sentinel_from_sqlite_storage() {
        let (_dir, mut store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let sentinel = "GILBRETH_SECURE_ERASE_SENTINEL_7f40c2f8";
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus(sentinel, base));

        store
            .insert_events(&[event])
            .expect("sentinel event inserted");
        assert!(
            sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "sentinel should be present before secure erase so the test is meaningful"
        );

        store
            .secure_delete_activity()
            .expect("secure delete completes");

        assert_eq!(row_count(store.connection(), "events"), 0);
        assert!(
            !sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "sentinel bytes should not remain in the main DB or SQLite sidecars"
        );
    }

    #[test]
    fn secure_delete_activity_reports_scrub_error_when_reader_defers_checkpoint() {
        let (_dir, mut store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let sentinel = "GILBRETH_SECURE_ERASE_SENTINEL_HELD_READER_1b6de9aa";
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus(sentinel, base));
        store
            .insert_events(&[event])
            .expect("sentinel event inserted");

        // Hold a read transaction across the erase, like a dashboard query
        // that outlasts the writer's busy timeout. Shrink the timeout so the
        // test does not wait 5 s on each of the three blocked statements.
        store
            .connection()
            .busy_timeout(Duration::from_millis(25))
            .expect("busy timeout lowered");
        let reader = Connection::open(&db_path).expect("reader opens");
        let mut stmt = reader
            .prepare("SELECT id FROM events ORDER BY id")
            .expect("reader statement");
        let mut rows = stmt.query([]).expect("reader query");
        assert!(rows.next().expect("first row").is_some());

        let report = store
            .secure_delete_activity()
            .expect("erase returns a report");

        assert!(
            report.scrub_error.is_some(),
            "a checkpoint deferred by a live reader must surface as a scrub error, got: {report:?}"
        );
        assert!(
            sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "test premise: the deferred checkpoint leaves sentinel bytes recoverable"
        );

        // Retry once the reader is gone -- the UI's "retry secure erase" path.
        drop(rows);
        drop(stmt);
        drop(reader);
        let report = store
            .secure_delete_activity()
            .expect("retry returns a report");
        assert_eq!(
            report.scrub_error, None,
            "uncontended retry completes the scrub"
        );
        assert!(
            !sqlite_storage_contains(&db_path, sentinel.as_bytes()),
            "sentinel bytes should be gone after the uncontended retry"
        );
    }

    #[test]
    fn prune_old_activity_succeeds_when_reader_defers_checkpoint() {
        let (_dir, mut store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let events: Vec<_> = (0..4)
            .map(|_| sequencer.stamp(captured_focus("Old activity", base)))
            .collect();
        store.insert_events(&events).expect("events inserted");

        // Hold a read transaction across the prune, like a dashboard open
        // while the app restarts. The prune transaction must still commit and
        // report success; only the post-prune WAL truncate defers. Shrink the
        // busy timeout so the deferred checkpoint does not stall the test 5 s.
        store
            .connection()
            .busy_timeout(Duration::from_millis(25))
            .expect("busy timeout lowered");
        let reader = Connection::open(&db_path).expect("reader opens");
        let mut stmt = reader
            .prepare("SELECT id FROM events ORDER BY id")
            .expect("reader statement");
        let mut rows = stmt.query([]).expect("reader query");
        assert!(rows.next().expect("first row").is_some());

        let report = store
            .prune_old_activity(i64::MAX)
            .expect("a committed prune must not report failure on a deferred checkpoint");

        assert_eq!(report.events_deleted, 4);
        assert_eq!(row_count(store.connection(), "events"), 0);

        drop(rows);
        drop(stmt);
        drop(reader);
    }

    #[test]
    fn dashboard_checkpoint_reports_busy_privacy_warning() {
        let (_dir, store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_minimal_event(store.connection(), session_id, 1, 1_100);
        store
            .connection()
            .busy_timeout(Duration::from_millis(25))
            .expect("busy timeout lowered");

        let reader = Connection::open(&db_path).expect("reader opens");
        let mut stmt = reader
            .prepare("SELECT id FROM events ORDER BY id")
            .expect("reader statement");
        let mut rows = stmt.query([]).expect("reader query");
        assert!(rows.next().expect("first row").is_some());
        store
            .connection()
            .execute("DELETE FROM events", [])
            .expect("event deleted while reader holds prior snapshot");

        let warning = checkpoint_after_secure_delete(store.connection())
            .expect("held reader must defer the truncate checkpoint");
        assert!(warning.contains("database was busy"), "warning: {warning}");
        assert!(warning.contains("bytes can remain"), "warning: {warning}");

        drop(rows);
        drop(stmt);
        drop(reader);
        assert_eq!(checkpoint_after_secure_delete(store.connection()), None);
    }

    #[test]
    fn dashboard_prune_public_path_runs_compactor_and_reports_busy_reader() {
        let (_dir, store) = temp_store();
        let db_path = store.db_path().to_path_buf();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_minimal_event(store.connection(), session_id, 1, 1_100);

        let reader = Connection::open(&db_path).expect("reader opens");
        let mut stmt = reader
            .prepare("SELECT id FROM events ORDER BY id")
            .expect("reader statement");
        let mut rows = stmt.query([]).expect("reader query");
        assert!(rows.next().expect("first row").is_some());

        let result = prune_old_events(&db_path, 2_000).expect("prune commits");

        assert_eq!(result.events_deleted, 1);
        assert!(!result.compaction_completed);
        assert!(
            result
                .compact_error
                .as_deref()
                .is_some_and(|warning| warning.contains("database was busy")),
            "warning: {:?}",
            result.compact_error
        );

        drop(rows);
        drop(stmt);
        drop(reader);
    }

    #[test]
    fn compact_database_reports_vacuum_warning() {
        let (_dir, store) = temp_store();
        store
            .connection()
            .execute_batch("BEGIN;")
            .expect("transaction started");

        let warning = compact_database(store.connection())
            .expect("vacuum inside a transaction must produce a warning");

        assert!(warning.contains("vacuum failed"), "warning: {warning}");
        store
            .connection()
            .execute_batch("ROLLBACK;")
            .expect("transaction rolled back");
    }

    #[test]
    fn capture_drop_counter_persists_cumulatively_in_meta() {
        let (_dir, store) = temp_store();
        let mut heartbeat = WriterHeartbeat::default();
        let diagnostics = DiagnosticsCounters::new();

        persist_capture_events_dropped(&store, &mut heartbeat, &diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY),
            0,
            "fresh DB persists an explicit zero"
        );

        diagnostics.increment_capture_events_dropped();
        diagnostics.increment_capture_events_dropped();
        persist_capture_events_dropped(&store, &mut heartbeat, &diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY),
            2
        );

        // A later run (fresh cache, fresh atomic) accumulates on the stored
        // base -- the counter survives a crash of the earlier run.
        let mut next_run = WriterHeartbeat::default();
        let next_diagnostics = DiagnosticsCounters::new();
        next_diagnostics.increment_capture_events_dropped();
        persist_capture_events_dropped(&store, &mut next_run, &next_diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY),
            3
        );

        // Secure erase deletes meta and flags a rebase: the pre-erase total
        // must not resurrect from the in-memory cache.
        store
            .connection()
            .execute("DELETE FROM meta", [])
            .expect("meta cleared");
        next_run.capture_dropped_reset_pending = true;
        persist_capture_events_dropped(&store, &mut next_run, &next_diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY),
            0,
            "post-erase totals restart"
        );
        next_diagnostics.increment_capture_events_dropped();
        persist_capture_events_dropped(&store, &mut next_run, &next_diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), CAPTURE_EVENTS_DROPPED_META_KEY),
            1,
            "only drops after the erase count"
        );
    }

    #[test]
    fn erase_boundary_drops_only_strictly_older_capture_timestamps() {
        assert!(capture_predates_erase_boundary(999, 1_000));
        assert!(
            !capture_predates_erase_boundary(1_000, 1_000),
            "a row captured exactly at the completion boundary is kept"
        );
        assert!(!capture_predates_erase_boundary(1_001, 1_000));
    }

    #[test]
    fn stale_pre_erase_drop_counter_is_durable_cumulative_and_erase_rebased() {
        let (_dir, store) = temp_store();
        let mut heartbeat = WriterHeartbeat::default();
        let diagnostics = DiagnosticsCounters::new();

        persist_stale_pre_erase_rows_dropped(&store, &mut heartbeat, &diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            0
        );
        diagnostics.increment_stale_pre_erase_rows_dropped();
        diagnostics.increment_stale_pre_erase_rows_dropped();
        persist_stale_pre_erase_rows_dropped(&store, &mut heartbeat, &diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            2
        );

        let mut next_run = WriterHeartbeat::default();
        let next_diagnostics = DiagnosticsCounters::new();
        next_diagnostics.increment_stale_pre_erase_rows_dropped();
        persist_stale_pre_erase_rows_dropped(&store, &mut next_run, &next_diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            3,
            "a new process accumulates on the durable base"
        );

        store
            .connection()
            .execute("DELETE FROM meta", [])
            .expect("secure erase clears meta");
        next_run.stale_pre_erase_dropped_offset = next_diagnostics.stale_pre_erase_rows_dropped();
        next_run.stale_pre_erase_dropped_base = Some(0);
        next_run.stale_pre_erase_dropped_persisted = None;
        next_diagnostics.increment_stale_pre_erase_rows_dropped();
        persist_stale_pre_erase_rows_dropped(&store, &mut next_run, &next_diagnostics);
        assert_eq!(
            read_meta_u64(store.connection(), STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            1,
            "only drops after the erase completion boundary survive the rebase"
        );
    }

    #[test]
    fn opportunistic_truncate_reclaims_wal_high_water_mark() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let events: Vec<_> = (0..16)
            .map(|_| sequencer.stamp(captured_focus("wal frames", base)))
            .collect();
        store.insert_events(&events).expect("events inserted");

        assert!(
            store.wal_file_size() > 0,
            "committed events should leave WAL frames before truncation"
        );

        checkpoint_truncate_opportunistic(store.connection());

        assert_eq!(
            store.wal_file_size(),
            0,
            "an uncontended TRUNCATE checkpoint should reclaim the WAL file"
        );
        // Data survives the checkpoint (frames moved into the main DB).
        assert_eq!(row_count(store.connection(), "events"), 16);
    }

    #[test]
    fn native_readonly_snapshot_defers_then_releases_wal_checkpoint() {
        let (_dir, mut store) = temp_store();
        let path = store.db_path().to_path_buf();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let seed = sequencer.stamp(captured_focus("wal seed", base));
        store.insert_events(&[seed]).expect("seed event inserted");
        checkpoint_truncate_opportunistic(store.connection());
        assert_eq!(store.wal_file_size(), 0);

        let reader = gilbreth_read::open_readonly(&path).expect("native reader opens");
        let reader_busy_timeout_ms: i64 = reader
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("native reader busy timeout");
        assert_eq!(reader_busy_timeout_ms, 5_000);
        reader
            .execute("DELETE FROM events", [])
            .expect_err("native dashboard connection must reject writes");
        reader
            .execute_batch("BEGIN")
            .expect("native reader snapshot begins");
        let snapshot_count: i64 = reader
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("seed snapshot count");
        assert_eq!(snapshot_count, 1);

        let events: Vec<_> = (0..16)
            .map(|_| sequencer.stamp(captured_focus("wal frames", base)))
            .collect();
        store.insert_events(&events).expect("events inserted");
        let wal_before = store.wal_file_size();
        assert!(wal_before > 0);
        let stable_snapshot_count: i64 = reader
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("stable snapshot count");
        assert_eq!(
            stable_snapshot_count, 1,
            "the native read-only transaction must keep its pre-write snapshot"
        );

        checkpoint_truncate_opportunistic(store.connection());

        let busy_timeout_ms: i64 = store
            .connection()
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("busy timeout");
        assert_eq!(busy_timeout_ms, 5_000);
        assert_eq!(
            store.wal_file_size(),
            wal_before,
            "held reader should defer the nonblocking truncate checkpoint"
        );

        reader
            .execute_batch("ROLLBACK")
            .expect("native reader snapshot closes");
        drop(reader);
        checkpoint_truncate_opportunistic(store.connection());
        assert_eq!(store.wal_file_size(), 0);

        let reader = gilbreth_read::open_readonly(&path).expect("native reader reopens");
        let event_count: i64 = reader
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("event count after checkpoint");
        assert_eq!(
            event_count, 17,
            "checkpointing must not lose committed rows"
        );
    }

    #[test]
    fn open_finalizes_orphan_session_to_last_event_timestamp() {
        let (_dir, store) = temp_store();
        let path = store.db_path().to_path_buf();
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 1, 1_500);
        insert_minimal_event(store.connection(), session_id, 2, 2_500);
        drop(store);

        let store = GilbrethStore::open(&path).expect("store reopens");

        assert_eq!(
            session_ended_at(store.connection(), session_id),
            Some(2_500)
        );
    }

    #[test]
    fn open_finalizes_empty_orphan_session_to_started_at() {
        let (_dir, store) = temp_store();
        let path = store.db_path().to_path_buf();
        let session_id = store.create_session(4_000, "test").expect("session");
        drop(store);

        let store = GilbrethStore::open(&path).expect("store reopens");

        assert_eq!(
            session_ended_at(store.connection(), session_id),
            Some(4_000)
        );
    }

    #[test]
    fn open_clamps_orphan_session_end_to_started_at() {
        let (_dir, store) = temp_store();
        let path = store.db_path().to_path_buf();
        let session_id = store.create_session(4_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 1, 3_000);
        drop(store);

        let store = GilbrethStore::open(&path).expect("store reopens");

        assert_eq!(
            session_ended_at(store.connection(), session_id),
            Some(4_000)
        );
    }

    #[test]
    fn finalize_orphan_sessions_reports_count_and_is_idempotent() {
        let (_dir, store) = temp_store();
        let first_orphan = store.create_session(1_000, "test").expect("first orphan");
        let second_orphan = store.create_session(2_000, "test").expect("second orphan");
        let ended = store.create_session(3_000, "test").expect("ended");
        store.end_session(ended, 4_000).expect("mark ended");

        let orphan_counts = Arc::new(Mutex::new(Vec::new()));
        let subscriber = OrphanRepairWarnSubscriber {
            orphan_counts: Arc::clone(&orphan_counts),
        };
        let (first_finalize_count, second_finalize_count) =
            tracing::subscriber::with_default(subscriber, || {
                (
                    finalize_orphan_sessions(store.connection()).expect("finalize orphans"),
                    finalize_orphan_sessions(store.connection()).expect("finalize idempotently"),
                )
            });

        assert_eq!(first_finalize_count, 2);
        assert_eq!(second_finalize_count, 0);
        assert_eq!(*orphan_counts.lock().expect("orphan count lock"), vec![2]);
        assert_eq!(
            session_ended_at(store.connection(), first_orphan),
            Some(1_000)
        );
        assert_eq!(
            session_ended_at(store.connection(), second_orphan),
            Some(2_000)
        );
        assert_eq!(session_ended_at(store.connection(), ended), Some(4_000));
    }

    #[test]
    fn open_tolerates_database_written_by_a_newer_build() {
        // A DB whose user_version exceeds this binary's known migration count
        // (e.g. after a build is rolled back) must still open and record, not
        // fail startup — index-only migrations are forward-compatible.
        let (_dir, store) = temp_store();
        let path = store.db_path().to_path_buf();
        drop(store);
        {
            let conn = Connection::open(&path).expect("reopen for version bump");
            conn.pragma_update(None, "user_version", 99)
                .expect("bump user_version past the known migrations");
        }

        let store = GilbrethStore::open(&path).expect("open tolerates a newer schema");
        store
            .create_session(2_000, "test")
            .expect("store remains usable after opening a newer-schema DB");
        assert_eq!(row_count(store.connection(), "sessions"), 1);
    }

    #[test]
    fn prune_old_activity_removes_old_events_and_only_ended_empty_sessions() {
        let (_dir, mut store) = temp_store();
        store
            .connection()
            .execute_batch("PRAGMA secure_delete = OFF;")
            .expect("disable secure_delete before prune");
        let base = Instant::now();
        let old_session = store
            .create_session(1_000, "test")
            .expect("old session created");
        let active_session = store
            .create_session(2_000, "test")
            .expect("active session created");
        let kept_session = store
            .create_session(3_000, "test")
            .expect("kept session created");
        store
            .end_session(old_session, 10_000)
            .expect("old session ended");
        store
            .end_session(kept_session, 10_000)
            .expect("kept session ended");

        let mut old_seq = Sequencer::new(old_session, SessionTimebase::new(base, 1_000));
        let mut active_seq = Sequencer::new(active_session, SessionTimebase::new(base, 2_000));
        let mut kept_seq = Sequencer::new(kept_session, SessionTimebase::new(base, 3_000));
        let old_event = old_seq.stamp(captured_focus("Old event", base));
        let active_old_event = active_seq.stamp(captured_focus("Active old event", base));
        let kept_event = kept_seq.stamp(captured_focus(
            "Kept event",
            base + Duration::from_millis(10_000),
        ));
        store
            .insert_events(&[old_event, active_old_event, kept_event])
            .expect("events inserted");

        let report = store
            .prune_old_activity(5_000)
            .expect("retention prune succeeds");
        let secure_delete_after_prune: i64 = store
            .connection()
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .expect("secure_delete after prune");

        assert_eq!(
            report,
            PruneReport {
                events_deleted: 2,
                sessions_deleted: 1,
            }
        );
        assert_eq!(secure_delete_after_prune, 0);
        let session_ids: Vec<i64> = store
            .connection()
            .prepare("SELECT session_id FROM sessions ORDER BY session_id")
            .expect("prepare sessions")
            .query_map([], |row| row.get(0))
            .expect("query sessions")
            .collect::<Result<Vec<_>, _>>()
            .expect("session ids");
        let event_sessions: Vec<i64> = store
            .connection()
            .prepare("SELECT session_id FROM events ORDER BY id")
            .expect("prepare events")
            .query_map([], |row| row.get(0))
            .expect("query events")
            .collect::<Result<Vec<_>, _>>()
            .expect("event session ids");

        assert_eq!(session_ids, vec![active_session, kept_session]);
        assert_eq!(event_sessions, vec![kept_session]);
    }

    #[test]
    fn prune_old_activity_covers_record_routine_tables() {
        let (_dir, mut store) = temp_store();
        let old_session = store
            .create_session(1_000, "test")
            .expect("old session created");
        let kept_session = store
            .create_session(2_000, "test")
            .expect("kept session created");
        store
            .end_session(old_session, 3_000)
            .expect("old session ended");
        store
            .end_session(kept_session, 9_000)
            .expect("kept session ended");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 10,
                record_session_id: 10,
                selector_id: 10,
                session_id: old_session,
                seq: 1,
                action_ts: 1_500,
                record_ended_ts: Some(2_000),
                request_expires_at: 2_500,
                selector_hash: "old-hash",
            },
        );
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 20,
                record_session_id: 20,
                selector_id: 20,
                session_id: kept_session,
                seq: 1,
                action_ts: 8_000,
                record_ended_ts: Some(9_000),
                request_expires_at: 9_500,
                selector_hash: "kept-hash",
            },
        );

        let report = store
            .prune_old_activity(5_000)
            .expect("retention prune succeeds");

        assert_eq!(
            report,
            PruneReport {
                events_deleted: 0,
                sessions_deleted: 1,
            }
        );
        let action_rows: Vec<(i64, i64)> = store
            .connection()
            .prepare("SELECT session_id, selector_id FROM action_events ORDER BY id")
            .expect("prepare action rows")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query action rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("action rows");
        let selector_hashes: Vec<String> = store
            .connection()
            .prepare("SELECT path_hash FROM selector_paths ORDER BY selector_id")
            .expect("prepare selectors")
            .query_map([], |row| row.get(0))
            .expect("query selectors")
            .collect::<Result<Vec<_>, _>>()
            .expect("selector hashes");
        let record_session_ids: Vec<i64> = store
            .connection()
            .prepare("SELECT record_session_id FROM record_sessions ORDER BY record_session_id")
            .expect("prepare record sessions")
            .query_map([], |row| row.get(0))
            .expect("query record sessions")
            .collect::<Result<Vec<_>, _>>()
            .expect("record session ids");
        let request_ids: Vec<i64> = store
            .connection()
            .prepare("SELECT request_id FROM record_requests ORDER BY request_id")
            .expect("prepare record requests")
            .query_map([], |row| row.get(0))
            .expect("query record requests")
            .collect::<Result<Vec<_>, _>>()
            .expect("request ids");
        let session_ids: Vec<i64> = store
            .connection()
            .prepare("SELECT session_id FROM sessions ORDER BY session_id")
            .expect("prepare sessions")
            .query_map([], |row| row.get(0))
            .expect("query sessions")
            .collect::<Result<Vec<_>, _>>()
            .expect("session ids");

        assert_eq!(action_rows, vec![(kept_session, 20)]);
        assert_eq!(selector_hashes, vec!["kept-hash"]);
        assert_eq!(record_session_ids, vec![20]);
        assert_eq!(request_ids, vec![20]);
        assert_eq!(session_ids, vec![kept_session]);
    }

    #[test]
    fn prune_old_activity_keeps_session_referenced_by_recent_record_session() {
        let (_dir, mut store) = temp_store();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        store.end_session(session_id, 3_000).expect("session ended");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 30,
                record_session_id: 30,
                selector_id: 30,
                session_id,
                seq: 1,
                action_ts: 1_500,
                record_ended_ts: Some(6_000),
                request_expires_at: 9_500,
                selector_hash: "recent-record-session-hash",
            },
        );

        let report = store
            .prune_old_activity(5_000)
            .expect("retention prune succeeds");

        assert_eq!(
            report,
            PruneReport {
                events_deleted: 0,
                sessions_deleted: 0,
            }
        );
        assert_eq!(row_count(store.connection(), "sessions"), 1);
        assert_eq!(record_routine_counts(store.connection()), (1, 1, 0, 0));
    }

    #[test]
    fn prune_old_activity_covers_record_routine_tables_with_foreign_keys_off() {
        let (_dir, mut store) = temp_store();
        store
            .connection()
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("disable foreign_keys before prune");
        let old_session = store
            .create_session(1_000, "test")
            .expect("old session created");
        store
            .end_session(old_session, 3_000)
            .expect("old session ended");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 70,
                record_session_id: 70,
                selector_id: 70,
                session_id: old_session,
                seq: 1,
                action_ts: 1_500,
                record_ended_ts: Some(2_000),
                request_expires_at: 2_500,
                selector_hash: "fk-off-old-hash",
            },
        );

        let report = store
            .prune_old_activity(5_000)
            .expect("retention prune succeeds without FK cascades");

        assert_eq!(
            report,
            PruneReport {
                events_deleted: 0,
                sessions_deleted: 1,
            }
        );
        assert_eq!(row_count(store.connection(), "sessions"), 0);
        assert_eq!(record_routine_counts(store.connection()), (0, 0, 0, 0));
    }

    #[test]
    fn startup_orphan_repair_allows_retention_to_prune_old_session() {
        let (_dir, mut store) = temp_store();
        let path = store.db_path().to_path_buf();
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 1, 1_500);
        drop(store);

        store = GilbrethStore::open(&path).expect("store reopens and repairs orphan");
        assert_eq!(
            session_ended_at(store.connection(), session_id),
            Some(1_500)
        );

        let report = store
            .prune_old_activity(2_000)
            .expect("retention prune succeeds");

        assert_eq!(
            report,
            PruneReport {
                events_deleted: 1,
                sessions_deleted: 1,
            }
        );
        assert_eq!(row_count(store.connection(), "events"), 0);
        assert_eq!(row_count(store.connection(), "sessions"), 0);
    }

    #[cfg(windows)]
    #[test]
    fn archive_activity_to_creates_consistent_copy() {
        let (dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus("Archived", base));
        store.insert_events(&[event]).expect("event inserted");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 30,
                record_session_id: 30,
                selector_id: 30,
                session_id,
                seq: 2,
                action_ts: 1_200,
                record_ended_ts: Some(1_500),
                request_expires_at: 4_000,
                selector_hash: "archive-hash",
            },
        );
        let db_uuid: String = store
            .connection()
            .query_row("SELECT value FROM meta WHERE key = 'db_uuid'", [], |row| {
                row.get(0)
            })
            .expect("database identity");
        let archive_path = dir.path().join("archives").join("gilbreth-archive.gla");

        let report = store
            .archive_activity_to(&archive_path, 2_000)
            .expect("archive created");

        assert_eq!(
            report,
            ArchiveReport {
                archive_path: archive_path.clone(),
                events_archived: 1,
                sessions_archived: 1,
                encryption: ArchiveEncryptionReceipt::dpapi_user(),
            }
        );
        assert_eq!(row_count(store.connection(), "events"), 1);
        assert_eq!(record_routine_counts(store.connection()), (1, 1, 1, 1));
        let live_ended_at: Option<i64> = store
            .connection()
            .query_row("SELECT ended_at FROM sessions", [], |row| row.get(0))
            .expect("live ended_at");
        assert_eq!(live_ended_at, None);
        assert_ne!(
            &fs::read(&archive_path).expect("sealed bytes")[..16],
            b"SQLite format 3\0",
            "the final archive must not be plaintext SQLite"
        );
        let header = read_archive_header(&archive_path).expect("sealed header");
        assert_eq!(header.provenance.db_uuid, db_uuid);
        assert_eq!(header.provenance.first_ts, Some(1_000));
        assert_eq!(header.provenance.last_ts, Some(1_200));
        assert_eq!(header.provenance.created_at, 2_000);
        assert_eq!(header.key_wrap.method_name(), "dpapi-user");
        let remaining_names = fs::read_dir(archive_path.parent().expect("archive parent"))
            .expect("archive directory")
            .map(|entry| entry.expect("archive entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            remaining_names,
            vec![archive_path
                .file_name()
                .expect("archive name")
                .to_os_string()],
            "successful archive creation must leave only the sealed final artifact"
        );
        let archive = open_dpapi_archive(&archive_path);
        assert_eq!(row_count(&archive, "events"), 1);
        assert_eq!(row_count(&archive, "sessions"), 1);
        assert_eq!(record_routine_counts(&archive), (1, 1, 1, 1));
        let archived_ended_at: Option<i64> = archive
            .query_row("SELECT ended_at FROM sessions", [], |row| row.get(0))
            .expect("archived ended_at");
        assert_eq!(archived_ended_at, Some(2_000));
        let title: String = archive
            .query_row("SELECT title FROM events", [], |row| row.get(0))
            .expect("archived title");
        assert_eq!(title, "Archived");
        let (action_seq, action_type, trust_basis, path_hash): (i64, String, String, String) =
            archive
                .query_row(
                    "
                    SELECT action_events.seq, action_events.action_type,
                           action_events.trust_basis, selector_paths.path_hash
                    FROM action_events
                    JOIN selector_paths USING (selector_id)
                    ",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("archived action row");
        assert_eq!(action_seq, 2);
        assert_eq!(action_type, "invoke");
        assert_eq!(trust_basis, "pid_match");
        assert_eq!(path_hash, "archive-hash");
    }

    #[cfg(windows)]
    #[test]
    fn archive_stamps_only_live_session_after_startup_orphan_repair() {
        let (dir, mut store) = temp_store();
        let path = store.db_path().to_path_buf();
        let stale_session = store.create_session(1_000, "test").expect("stale session");
        insert_minimal_event(store.connection(), stale_session, 1, 1_500);
        drop(store);

        store = GilbrethStore::open(&path).expect("store reopens and repairs orphan");
        let live_session = store.create_session(2_000, "test").expect("live session");
        insert_minimal_event(store.connection(), live_session, 1, 2_500);
        let archive_path = dir.path().join("archives").join("repaired-archive.gla");

        store
            .archive_activity_to(&archive_path, 3_000)
            .expect("archive created");

        let archive = open_dpapi_archive(&archive_path);
        assert_eq!(session_ended_at(&archive, stale_session), Some(1_500));
        assert_eq!(session_ended_at(&archive, live_session), Some(3_000));
        assert_eq!(session_ended_at(store.connection(), live_session), None);
    }

    #[cfg(windows)]
    #[test]
    fn archive_verification_failure_removes_artifact_and_leaves_live_data_intact() {
        let (dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_focus("Must survive failed verification", base));
        store.insert_events(&[event]).expect("event inserted");
        let archive_dir = dir.path().join("archives");
        let archive_path = archive_dir.join("gilbreth-archive-injected.gla");

        let error = store
            .archive_activity_to_with_verifier(&archive_path, 2_000, |_| {
                Err(StoreError::RecordRoutine(
                    "injected full-read verification failure".to_string(),
                ))
            })
            .expect_err("verification failure aborts archive completion");
        assert!(matches!(error, StoreError::ArchiveVerification(_)));
        assert!(error.to_string().contains("nothing was reset"));
        assert_eq!(row_count(store.connection(), "events"), 1);
        assert_eq!(session_ended_at(store.connection(), session_id), None);
        assert!(!archive_path.exists());
        assert_eq!(
            fs::read_dir(&archive_dir)
                .expect("archive directory")
                .count(),
            0,
            "plaintext staging and unverified sealed files must both be removed"
        );
    }

    #[test]
    fn archive_plaintext_staging_scrub_overwrites_main_and_sqlite_sidecars() {
        let dir = tempfile::tempdir().expect("temp dir");
        let staging = dir.path().join(
            ".gilbreth-archive-100-deadbeef.gla.550e8400-e29b-41d4-a716-446655440000.plaintext.db",
        );
        let mut staged_paths = vec![staging.clone()];
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut path = staging.as_os_str().to_os_string();
            path.push(suffix);
            staged_paths.push(PathBuf::from(path));
        }

        let mut witnesses = Vec::new();
        for (index, path) in staged_paths.iter().enumerate() {
            let sensitive = format!("SQLite plaintext staging secret {index}").into_bytes();
            fs::write(path, &sensitive).expect("staging fixture");
            let witness = dir.path().join(format!("witness-{index}"));
            fs::hard_link(path, &witness).expect("hard-link overwrite witness");
            witnesses.push((witness, sensitive.len()));
        }

        scrub_archive_plaintext_staging(&staging).expect("staging set scrubbed");

        for path in staged_paths {
            assert!(!path.exists(), "staging artifact must be removed");
        }
        for (witness, expected_len) in witnesses {
            assert_eq!(
                fs::read(witness).expect("overwrite witness"),
                vec![0; expected_len],
                "the bytes behind every plaintext staging file must be overwritten before unlink"
            );
        }
    }

    #[test]
    fn process_events_persist_pid_exe_and_payload_without_command_line() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_process_started(base));

        store.insert_events(&[event]).expect("event inserted");

        let (source, kind, pid, exe, payload): (String, String, i64, String, String) = store
            .connection()
            .query_row(
                "SELECT source, kind, pid, exe, payload FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("process event row");

        assert_eq!(source, "system");
        assert_eq!(kind, "process_started");
        assert_eq!(pid, 4242);
        assert_eq!(exe, "C:\\Windows\\System32\\notepad.exe");
        assert!(payload.contains("\"exe_source\":\"full_path\""));
        assert!(!payload.contains("command"));
        assert!(!payload.contains("parent"));
    }

    #[test]
    fn value_free_exe_columns_store_basename_not_full_path() {
        // A14 (priv-02): the value-free window/focus `exe` column must never
        // persist a full path (which can embed the user-profile dir / username
        // and an installed-app inventory). The deliberate process stream keeps
        // its full path (column + `exe_source = full_path` payload) intact.
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let focus = sequencer.stamp(captured_focus("notepad", base));
        store.insert_events(&[focus]).expect("focus inserted");
        let focus_exe: String = store
            .connection()
            .query_row(
                "SELECT exe FROM events WHERE kind = 'focus_changed'",
                [],
                |row| row.get(0),
            )
            .expect("focus row");
        assert_eq!(focus_exe, "notepad.exe");
        // The full path must not leak through the payload JSON either (A14 review
        // finding): the serialized WindowRef nested in the payload carries `exe`.
        let focus_payload: String = store
            .connection()
            .query_row(
                "SELECT payload FROM events WHERE kind = 'focus_changed'",
                [],
                |row| row.get(0),
            )
            .expect("focus payload");
        assert!(
            !focus_payload.contains("System32"),
            "payload leaked full path: {focus_payload}"
        );
        assert!(focus_payload.contains("notepad.exe"));

        let proc = sequencer.stamp(captured_process_started(base));
        store.insert_events(&[proc]).expect("process inserted");
        let (proc_exe, proc_payload): (String, String) = store
            .connection()
            .query_row(
                "SELECT exe, payload FROM events WHERE kind = 'process_started'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("process row");
        assert_eq!(proc_exe, "C:\\Windows\\System32\\notepad.exe");
        // The deliberate process full path is preserved in the column AND payload.
        assert!(proc_payload.contains("System32"));

        assert_eq!(
            exe_basename(r"C:\Users\alice\AppData\Local\app\app.exe"),
            "app.exe"
        );
        assert_eq!(exe_basename("/opt/tools/foo"), "foo");
        assert_eq!(exe_basename("already.exe"), "already.exe");
    }

    #[test]
    fn value_free_guard_bounds_selector_identifiers() {
        // A15 (priv-03): over-long or control-character automation_id / class_name
        // values are rejected as likely value-bearing content; a normal short,
        // single-line identifier passes.
        let long = "a".repeat(MAX_SELECTOR_IDENT_LEN + 1);
        let oversize = format!(r#"[{{"automation_id":"{long}","class_name":"Edit"}}]"#);
        assert!(ensure_value_free_json(&oversize, "selector_path").is_err());

        let multiline = r#"[{"automation_id":"line1\nline2","class_name":"Edit"}]"#;
        assert!(ensure_value_free_json(multiline, "selector_path").is_err());

        let ok = r#"[{"automation_id":"num1Button","class_name":"Button"}]"#;
        assert!(ensure_value_free_json(ok, "selector_path").is_ok());
    }

    #[test]
    fn power_status_event_persists_value_free_fields() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(Captured::new(
            Source::System,
            base,
            EventPayload::PowerStatusChanged {
                ac_online: Some(false),
                battery_percent: Some(42),
                battery_saver: Some(true),
            },
        ));
        store
            .insert_events(&[event])
            .expect("power status inserted");

        let (kind, exe, payload): (String, Option<String>, String) = store
            .connection()
            .query_row("SELECT kind, exe, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("power status row");
        assert_eq!(kind, "power_status");
        assert_eq!(exe, None);
        assert!(payload.contains("ac_online"));
        assert!(payload.contains("battery_percent"));
        assert!(payload.contains("42"));
        assert!(payload.contains("battery_saver"));
    }

    #[test]
    fn fresh_db_uses_incremental_auto_vacuum_and_reports_size() {
        // STORE-01: fresh DBs get auto_vacuum=INCREMENTAL and the main-DB size is
        // observable (distinct from the WAL).
        let (_dir, mut store) = temp_store();
        let auto_vacuum: i64 = store
            .connection()
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .expect("auto_vacuum");
        assert_eq!(auto_vacuum, 2, "2 == INCREMENTAL");

        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(Instant::now(), 1_000));
        for _ in 0..50 {
            let event = sequencer.stamp(captured_focus("notepad", Instant::now()));
            store.insert_events(&[event]).expect("inserted");
        }
        assert!(store.main_db_file_size() > 0);
    }

    #[test]
    fn incremental_vacuum_after_prune_keeps_db_valid() {
        // STORE-01: reclaiming freed pages after a prune must leave a consistent,
        // still-usable database.
        let (_dir, mut store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(Instant::now(), 1_000));
        for _ in 0..200 {
            let event = sequencer.stamp(captured_focus("notepad", Instant::now()));
            store.insert_events(&[event]).expect("inserted");
        }
        store.prune_old_activity(i64::MAX).expect("pruned");
        incremental_vacuum_opportunistic(store.connection());

        let integrity: String = store
            .connection()
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity check");
        assert_eq!(integrity, "ok");
        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn writer_secure_erase_drops_stale_post_boundary_rows_and_resets_sequence() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let diagnostics = DiagnosticsCounters::new();
        let writer_diagnostics = diagnostics.clone();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    diagnostics: writer_diagnostics,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Stale before erase",
            base,
        )))
        .expect("stale event sent");
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::SecureErase {
                session_identity: SessionIdentity::new("test")
                    .with_host(Some("test-host".to_string()))
                    .with_git_sha("test-sha"),
                reply: reply_tx,
            })
            .expect("erase command sent");
        let erase_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("erase report");
        assert!(matches!(
            erase_report.outcome,
            SecureEraseOutcome::Completed | SecureEraseOutcome::DeleteCommittedScrubIncomplete
        ));
        let new_session_id = erase_report.new_session_id.expect("new session");
        assert_eq!(erase_report.events_deleted, 1);

        // This row arrives after the reply but carries a pre-boundary capture
        // timestamp. The quiet drain cannot help now; the lifetime gate must.
        tx.send(WriterInput::Motion(captured_focus(
            "Late stale after erase",
            base,
        )))
        .expect("late stale row sent");
        tx.send(WriterInput::Motion(captured_focus(
            "After erase",
            Instant::now(),
        )))
        .expect("boundary-later event sent");
        drop(tx);
        drop(command_tx);
        let writer_report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(writer_report.events_written, 2);
        assert_eq!(
            writer_report.events_skipped, 0,
            "privacy-boundary drops stay in their named category"
        );
        assert_eq!(diagnostics.stale_pre_erase_rows_dropped(), 1);

        let conn = Connection::open(&path).expect("reader opens");
        let rows: Vec<(i64, i64, String)> = conn
            .prepare("SELECT session_id, seq, title FROM events ORDER BY id")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");

        assert_eq!(rows, vec![(new_session_id, 1, "After erase".to_string())]);
        assert_eq!(row_count(&conn, "sessions"), 1);
        // Identity keys plus the two durable named drop counters.
        assert_eq!(row_count(&conn, "meta"), 4);
        assert_eq!(
            read_meta_u64(&conn, CAPTURE_EVENTS_DROPPED_META_KEY),
            0,
            "post-erase drop counter restarts at zero"
        );
        assert_eq!(
            read_meta_u64(&conn, STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            1,
            "late pre-boundary motion row is durably counted"
        );
        let identity: (String, String, String, String) = conn
            .query_row(
                "SELECT app_version, host, git_sha, run_label FROM sessions WHERE session_id = ?",
                [new_session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("replacement identity");
        assert_eq!(identity.0, "test");
        assert_eq!(identity.1, "test-host");
        assert_eq!(identity.2, "test-sha");
        assert!(identity.3.starts_with("session-"));
    }

    #[test]
    fn writer_secure_erase_quiet_drains_delayed_forwarded_event() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::SecureErase {
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("erase command sent");
        let delayed_tx = tx.clone();
        let delayed = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            delayed_tx
                .send(WriterInput::Motion(captured_focus(
                    "Delayed stale before erase",
                    base + Duration::from_millis(1),
                )))
                .expect("delayed stale event sent");
        });
        let erase_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("erase report");
        delayed.join().expect("delayed sender joins");
        assert!(matches!(
            erase_report.outcome,
            SecureEraseOutcome::Completed | SecureEraseOutcome::DeleteCommittedScrubIncomplete
        ));
        let new_session_id = erase_report.new_session_id.expect("new session");
        assert_eq!(erase_report.events_deleted, 1);

        tx.send(WriterInput::Motion(captured_focus(
            "After erase",
            Instant::now(),
        )))
        .expect("post erase event sent");
        drop(tx);
        drop(command_tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let conn = Connection::open(&path).expect("reader opens");
        let rows: Vec<(i64, i64, String)> = conn
            .prepare("SELECT session_id, seq, title FROM events ORDER BY id")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");

        assert_eq!(rows, vec![(new_session_id, 1, "After erase".to_string())]);
    }

    #[test]
    fn writer_secure_erase_refuses_while_recording_is_active() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Survives refused erase",
            base,
        )))
        .expect("event sent");
        let record_session_id = start_recording_for_writer(&command_tx);

        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::SecureErase {
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("erase command sent");
        let report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("erase report");

        assert!(matches!(report.outcome, SecureEraseOutcome::DeleteFailed));
        assert_eq!(report.events_deleted, 0);
        assert!(report
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Record Routine"));

        drop(tx);
        drop(command_tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let conn = Connection::open(&path).expect("reader opens");
        let events: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("event count");
        assert_eq!(events, 1, "the refused erase must not delete activity");
        let record_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| row.get(0),
            )
            .expect("record session count");
        assert_eq!(
            record_rows, 1,
            "the live recording must survive the refusal"
        );
    }

    #[test]
    fn writer_secure_erase_drains_queued_actions_and_erases_them() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let record_session_id = start_recording_for_writer(&command_tx);
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base,
            "edit",
        )))
        .expect("queued action sent");
        // The writer refuses erase while a recording is live, so stop first.
        // stop_recording drains the input channel before closing the session,
        // so the queued action is written while the session is still open —
        // the drained-into-the-erase premise this test guards is preserved.
        stop_recording_for_writer(&command_tx, record_session_id);
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::SecureErase {
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("erase command sent");
        let erase_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("erase report");
        assert!(matches!(
            erase_report.outcome,
            SecureEraseOutcome::Completed | SecureEraseOutcome::DeleteCommittedScrubIncomplete
        ));
        let new_session_id = erase_report.new_session_id.expect("new session");

        drop(tx);
        drop(command_tx);
        let writer_report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(writer_report.actions_written, 1);
        assert_eq!(writer_report.actions_skipped, 0);

        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(record_routine_counts(&conn), (0, 0, 0, 0));
        let sessions: Vec<i64> = conn
            .prepare("SELECT session_id FROM sessions ORDER BY session_id")
            .expect("prepare sessions")
            .query_map([], |row| row.get(0))
            .expect("query sessions")
            .collect::<Result<Vec<_>, _>>()
            .expect("session ids");
        assert_eq!(sessions, vec![new_session_id]);
    }

    #[cfg(windows)]
    #[test]
    fn writer_archive_and_reset_archives_then_replaces_live_session() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("baseline.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 40,
                record_session_id: 40,
                selector_id: 40,
                session_id,
                seq: 2,
                action_ts: 1_200,
                record_ended_ts: Some(1_500),
                request_expires_at: 4_000,
                selector_hash: "archive-reset-hash",
            },
        );
        store
            .connection()
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("disable foreign_keys before archive/reset");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Before archive reset",
            base,
        )))
        .expect("stale event sent");
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test")
                    .with_host(Some("test-host".to_string()))
                    .with_git_sha("test-sha"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let archive_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive reset report");
        assert!(matches!(
            archive_report.outcome,
            ArchiveResetOutcome::Completed | ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        ));
        assert_eq!(archive_report.archive_path.as_ref(), Some(&archive_path));
        assert_eq!(archive_report.events_archived, 1);
        assert_eq!(archive_report.sessions_archived, 1);
        assert_eq!(archive_report.events_deleted, 1);
        let new_session_id = archive_report.new_session_id.expect("new session");

        tx.send(WriterInput::Motion(captured_focus(
            "Stale row kept after archive reset",
            base,
        )))
        .expect("post reset event sent");
        drop(tx);
        drop(command_tx);
        let writer_report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(writer_report.events_written, 2);

        let archive = open_dpapi_archive(&archive_path);
        assert_eq!(row_count(&archive, "events"), 1);
        assert_eq!(record_routine_counts(&archive), (1, 1, 1, 1));
        let open_sessions: i64 = archive
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
                [],
                |row| row.get(0),
            )
            .expect("open sessions");
        assert_eq!(open_sessions, 0);
        let archived_title: String = archive
            .query_row("SELECT title FROM events", [], |row| row.get(0))
            .expect("archive row");
        assert_eq!(archived_title, "Before archive reset");
        let archived_action_hash: String = archive
            .query_row(
                "
                SELECT selector_paths.path_hash
                FROM action_events
                JOIN selector_paths USING (selector_id)
                ",
                [],
                |row| row.get(0),
            )
            .expect("archived selector hash");
        assert_eq!(archived_action_hash, "archive-reset-hash");

        let conn = Connection::open(&path).expect("reader opens");
        let rows: Vec<(i64, i64, String)> = conn
            .prepare("SELECT session_id, seq, title FROM events ORDER BY id")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![(
                new_session_id,
                1,
                "Stale row kept after archive reset".to_string()
            )]
        );
        assert_eq!(row_count(&conn, "sessions"), 1);
        // Archive/reset is deliberately not timestamp-gated; both named
        // counters remain zero in the fresh DB.
        assert_eq!(row_count(&conn, "meta"), 4);
        assert_eq!(
            read_meta_u64(&conn, STALE_PRE_ERASE_ROWS_DROPPED_META_KEY),
            0
        );
        assert_eq!(record_routine_counts(&conn), (0, 0, 0, 0));
    }

    #[cfg(windows)]
    #[test]
    fn writer_archive_and_reset_verification_failure_aborts_before_delete() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("verification-failure.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);
        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Survives failed archive verification",
            base,
        )))
        .expect("event sent");
        inject_archive_verification_failure(&archive_path);
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive failure receipt");
        assert_eq!(report.outcome, ArchiveResetOutcome::ArchiveFailed);
        assert_eq!(report.events_deleted, 0);
        assert_eq!(report.sessions_deleted, 0);
        assert_eq!(report.new_session_id, None);
        assert!(report
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("archive failed verification; nothing was reset"));
        assert!(!archive_path.exists());

        // Inspect the live store before shutting the writer down. A normal
        // writer shutdown closes its current session, so checking ended_at
        // after join would conflate that expected lifecycle transition with
        // the archive/reset failure boundary this test is meant to prove.
        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(row_count(&conn, "events"), 1);
        assert_eq!(row_count(&conn, "sessions"), 1);
        assert_eq!(session_ended_at(&conn, session_id), None);
        let title: String = conn
            .query_row("SELECT title FROM events", [], |row| row.get(0))
            .expect("surviving event");
        assert_eq!(title, "Survives failed archive verification");
        drop(conn);

        drop(tx);
        drop(command_tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        let conn = Connection::open(&path).expect("reader opens");
        assert_eq!(row_count(&conn, "events"), 1);
        assert_eq!(row_count(&conn, "sessions"), 1);
        assert!(session_ended_at(&conn, session_id).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn writer_archive_and_reset_quiet_drains_delayed_forwarded_event() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("baseline.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let delayed_tx = tx.clone();
        let delayed = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            delayed_tx
                .send(WriterInput::Motion(captured_focus(
                    "Delayed stale before archive",
                    base + Duration::from_millis(1),
                )))
                .expect("delayed stale event sent");
        });
        let archive_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive reset report");
        delayed.join().expect("delayed sender joins");
        assert!(matches!(
            archive_report.outcome,
            ArchiveResetOutcome::Completed | ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        ));
        assert_eq!(archive_report.events_archived, 1);
        assert_eq!(archive_report.events_deleted, 1);
        let new_session_id = archive_report.new_session_id.expect("new session");

        tx.send(WriterInput::Motion(captured_focus(
            "After archive reset",
            base + Duration::from_millis(500),
        )))
        .expect("post reset event sent");
        drop(tx);
        drop(command_tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let archive = open_dpapi_archive(&archive_path);
        let archived_title: String = archive
            .query_row("SELECT title FROM events", [], |row| row.get(0))
            .expect("archive row");
        assert_eq!(archived_title, "Delayed stale before archive");

        let conn = Connection::open(&path).expect("reader opens");
        let rows: Vec<(i64, i64, String)> = conn
            .prepare("SELECT session_id, seq, title FROM events ORDER BY id")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![(new_session_id, 1, "After archive reset".to_string())]
        );
    }

    /// Off Windows, `DpapiUser` can never wrap a content key. The refusal has
    /// to land *before* `VACUUM main INTO` writes a complete plaintext copy of
    /// the activity database, because the only thing that would remove that
    /// copy afterwards is a best-effort scrub, and a scrub failure leaves an
    /// unencrypted database that no inventory surface reports — the staging
    /// name is dot-prefixed, and `inventory_archives` matches
    /// `gilbreth-archive-*`.
    ///
    /// Proven to bite by mutation: with the `ensure_seal_key_available` call
    /// removed, the archive directory is created and this fails. Asserting
    /// "no residue" instead would NOT bite — the scrub succeeds in a clean
    /// temp dir, so a late refusal leaves the directory looking identical.
    #[cfg(not(windows))]
    #[test]
    fn archiving_off_windows_refuses_before_writing_any_plaintext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = GilbrethStore::open(dir.path().join("gilbreth.db")).expect("store opens");
        let archive_dir = dir.path().join("archives");
        let archive_path = archive_dir.join("gilbreth-archive.gla");

        let error = store
            .archive_activity_to(&archive_path, 2_000)
            .expect_err("sealing cannot succeed without DPAPI");
        assert!(
            matches!(
                error,
                StoreError::Archive(archive::ArchiveError::DpapiUnsupported)
            ),
            "expected a named refusal, got {error:?}"
        );

        // The observable proof that nothing was staged. Asserting "no residue"
        // would NOT catch a late refusal: the scrub succeeds in a clean temp
        // dir, so the plaintext copy is written and removed and the directory
        // looks identical afterwards. The directory never being created is the
        // difference a late refusal cannot fake.
        assert!(
            !archive_dir.exists(),
            "a refused archive must not touch the filesystem at all"
        );
        assert!(!archive_path.exists());
    }

    #[test]
    fn writer_archive_and_reset_refuses_while_recording_is_active() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("refused.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_focus(
            "Survives refused archive",
            base,
        )))
        .expect("event sent");
        let record_session_id = start_recording_for_writer(&command_tx);

        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive reset report");

        assert!(matches!(report.outcome, ArchiveResetOutcome::ArchiveFailed));
        assert_eq!(report.events_archived, 0);
        assert_eq!(report.events_deleted, 0);
        assert!(report
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Record Routine"));
        assert!(
            !archive_path.exists(),
            "no archive artifact may exist after a refusal"
        );

        drop(tx);
        drop(command_tx);
        handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");

        let conn = Connection::open(&path).expect("reader opens");
        let events: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("event count");
        assert_eq!(events, 1, "the refused reset must not delete activity");
        let record_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM record_sessions WHERE record_session_id = ?1",
                [record_session_id],
                |row| row.get(0),
            )
            .expect("record session count");
        assert_eq!(
            record_rows, 1,
            "the live recording must survive the refusal"
        );
    }

    #[cfg(windows)]
    #[test]
    fn writer_archive_and_reset_drains_queued_actions_into_archive() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("queued-action.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity(),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        let record_session_id = start_recording_for_writer(&command_tx);
        tx.send(WriterInput::Action(sample_action_capture(
            record_session_id,
            base,
            "edit",
        )))
        .expect("queued action sent");
        // The writer refuses archive/reset while a recording is live, so stop
        // first; stop_recording drains the queued action before closing, so it
        // still lands in the archive as this test requires.
        stop_recording_for_writer(&command_tx, record_session_id);
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let archive_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive reset report");
        assert!(matches!(
            archive_report.outcome,
            ArchiveResetOutcome::Completed | ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        ));

        drop(tx);
        drop(command_tx);
        let writer_report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(writer_report.actions_written, 1);
        assert_eq!(writer_report.actions_skipped, 0);

        let archive = open_dpapi_archive(&archive_path);
        assert_eq!(row_count(&archive, "action_events"), 1);
        let archived: (i64, String, i64, Option<i64>, String) = archive
            .query_row(
                "
                SELECT action_events.seq, selector_paths.path_hash,
                       record_sessions.action_count, record_sessions.ended_ts,
                       record_sessions.stop_reason
                  FROM action_events
                  JOIN selector_paths USING (selector_id)
                  JOIN record_sessions USING (record_session_id)
                ",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("archived queued action");
        assert_eq!(archived.0, 1);
        assert_eq!(archived.1, sample_selector_path("edit").hash_v1());
        assert_eq!(archived.2, 1);
        assert!(archived.3.is_some());
        assert_eq!(archived.4, RecordStopReason::UserStop.as_str());

        let live = Connection::open(&path).expect("live opens");
        assert_eq!(record_routine_counts(&live), (0, 0, 0, 0));
    }

    #[cfg(windows)]
    #[test]
    fn writer_archive_and_reset_reemits_active_sensitive_context_in_replacement_session() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("gilbreth.db");
        let archive_path = dir.path().join("archives").join("sensitive-context.gla");
        let store = GilbrethStore::open(&path).expect("store opens");
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let stop = StopToken::new();
        let (tx, rx) = bounded(8);
        let (command_tx, command_rx) = bounded(1);

        let handle = std::thread::spawn(move || {
            run_writer_with_commands(
                store,
                rx,
                command_rx,
                stop,
                sequencer,
                Policy::identity().with_sensitive_context_suppression(true),
                WriterConfig {
                    flush_interval: Duration::from_secs(60),
                    batch_size: 100,
                    ..WriterConfig::default()
                },
            )
        });

        tx.send(WriterInput::Motion(captured_sensitive_context_entered(
            base,
        )))
        .expect("sensitive enter sent");
        let (reply_tx, reply_rx) = bounded(1);
        command_tx
            .send(WriterCommand::ArchiveAndReset {
                archive_path: archive_path.clone(),
                session_identity: SessionIdentity::new("test"),
                reply: reply_tx,
            })
            .expect("archive reset command sent");
        let archive_report = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("archive reset report");
        assert!(matches!(
            archive_report.outcome,
            ArchiveResetOutcome::Completed | ArchiveResetOutcome::DeleteCommittedScrubIncomplete
        ));
        let new_session_id = archive_report.new_session_id.expect("new session");

        tx.send(WriterInput::Motion(captured_focus(
            "After archive reset while locked",
            base + Duration::from_millis(100),
        )))
        .expect("post reset event sent");
        drop(tx);
        drop(command_tx);
        let writer_report = handle
            .join()
            .expect("writer joins")
            .expect("writer succeeds");
        assert_eq!(writer_report.events_written, 3);

        let archive = open_dpapi_archive(&archive_path);
        let archived_rows: Vec<(String, String)> = archive
            .prepare("SELECT kind, title FROM events ORDER BY seq")
            .expect("prepare archive rows")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query archive rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("archive rows");
        assert_eq!(
            archived_rows,
            vec![(
                "sensitive_context_entered".to_string(),
                "session locked".to_string()
            )]
        );

        let live = Connection::open(&path).expect("live opens");
        let live_rows: Vec<(i64, i64, String, Option<String>, i64)> = live
            .prepare("SELECT session_id, seq, kind, title, is_sensitive FROM events ORDER BY seq")
            .expect("prepare live rows")
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .expect("query live rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("live rows");
        assert_eq!(
            live_rows,
            vec![
                (
                    new_session_id,
                    1,
                    "sensitive_context_entered".to_string(),
                    Some("session locked".to_string()),
                    0
                ),
                (
                    new_session_id,
                    2,
                    "focus_changed".to_string(),
                    Some("<redacted>".to_string()),
                    1
                )
            ]
        );
    }

    #[test]
    fn migrations_are_well_formed() {
        migrations().validate().expect("migrations validate");
    }

    #[test]
    fn post_initial_migrations_stay_rollback_compatible() {
        let post_initial_migrations = [
            ("002_session_identity.sql", SESSION_IDENTITY_SQL),
            ("003_analytics_indexes.sql", ANALYTICS_INDEXES_SQL),
            (
                "004_drop_redundant_session_index.sql",
                DROP_REDUNDANT_SESSION_INDEX_SQL,
            ),
            ("005_record_routine.sql", RECORD_ROUTINE_SQL),
            ("006_action_framework_class.sql", ACTION_FRAMEWORK_CLASS_SQL),
            ("007_open_focus.sql", OPEN_FOCUS_SQL),
            ("008_deletion_audit.sql", DELETION_AUDIT_SQL),
        ];

        for (name, sql) in post_initial_migrations {
            let statements = migration_statements(sql);
            assert!(
                !statements.is_empty(),
                "migration {name} should contain at least one SQL statement"
            );
            // Migrations already shipped in a public release are
            // grandfathered: every released binary knows their children and
            // deletes them before the referenced tables, so their FKs never
            // meet an ignorant binary. Only sessions references existed at
            // the v0.1.1 frontier.
            let grandfathered = name == "005_record_routine.sql";
            // Tables this migration itself creates: FKs among them are
            // rollback-safe because an older binary never touches them.
            let created_here: Vec<String> = statements
                .iter()
                .filter_map(|statement| {
                    let lowered = statement.to_ascii_lowercase();
                    let rest = lowered.trim_start().strip_prefix("create table")?;
                    Some(
                        rest.trim_start()
                            .split(|c: char| c.is_whitespace() || c == '(')
                            .next()?
                            .to_string(),
                    )
                })
                .collect();
            for statement in statements {
                // A REFERENCES clause pointing at a pre-existing table is a
                // rollback trap even though the CREATE TABLE shape passes:
                // an older binary deletes the referenced table's rows
                // without knowing about this child, and foreign_keys = ON
                // fails its erase/prune/archive transactions (the 007 FK
                // finding). References must stay within the migration that
                // created the target.
                let lowered = statement.to_ascii_lowercase();
                let mut rest = lowered.as_str();
                while let Some(position) = rest.find("references") {
                    let after = &rest[position + "references".len()..];
                    let target = after
                        .trim_start()
                        .split(|c: char| c.is_whitespace() || c == '(')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    assert!(
                        grandfathered || created_here.contains(&target),
                        "migration {name} declares a foreign key to pre-existing table                          {target}: an older binary deletes from {target} without knowing                          this child exists, so its erase/prune/archive transactions fail                          under foreign_keys = ON. Enforce the linkage in code instead                          (the 007 open_focus finding)."
                    );
                    rest = after;
                }
                assert!(
                    is_rollback_compatible_statement(&statement),
                    "migration {name} contains a non-additive/non-index statement: {statement}. \
                     The DatabaseTooFarAhead rollback path assumes new migrations are limited \
                     to ALTER TABLE ... ADD COLUMN, CREATE TABLE, CREATE INDEX, or DROP INDEX statements; \
                     add an explicit version gate before shipping table rewrites, column drops, \
                     column renames, retypes, or data rewrites."
                );
            }
        }
    }

    #[test]
    fn released_migration_sql_matches_golden_fixtures() {
        let released_migrations = [
            (
                "001_initial.sql",
                SCHEMA_SQL,
                include_str!("../tests/fixtures/released_migrations/001_initial.sql"),
            ),
            (
                "002_session_identity.sql",
                SESSION_IDENTITY_SQL,
                include_str!("../tests/fixtures/released_migrations/002_session_identity.sql"),
            ),
            (
                "003_analytics_indexes.sql",
                ANALYTICS_INDEXES_SQL,
                include_str!("../tests/fixtures/released_migrations/003_analytics_indexes.sql"),
            ),
            (
                "004_drop_redundant_session_index.sql",
                DROP_REDUNDANT_SESSION_INDEX_SQL,
                include_str!(
                    "../tests/fixtures/released_migrations/004_drop_redundant_session_index.sql"
                ),
            ),
            (
                "005_record_routine.sql",
                RECORD_ROUTINE_SQL,
                include_str!("../tests/fixtures/released_migrations/005_record_routine.sql"),
            ),
            (
                "006_action_framework_class.sql",
                ACTION_FRAMEWORK_CLASS_SQL,
                include_str!(
                    "../tests/fixtures/released_migrations/006_action_framework_class.sql"
                ),
            ),
            (
                "007_open_focus.sql",
                OPEN_FOCUS_SQL,
                include_str!("../tests/fixtures/released_migrations/007_open_focus.sql"),
            ),
            (
                "008_deletion_audit.sql",
                DELETION_AUDIT_SQL,
                include_str!("../tests/fixtures/released_migrations/008_deletion_audit.sql"),
            ),
        ];

        for (name, actual, golden) in released_migrations {
            assert_eq!(
                normalize_migration_sql(actual),
                normalize_migration_sql(golden),
                "released migration {name} changed; if intentional, add a NEW migration and update the golden fixture, do not edit a shipped migration in place"
            );
        }
    }

    #[test]
    fn fresh_db_schema_keeps_session_primary_key_without_autoincrement() {
        let (_dir, store) = temp_store();
        let session_sql: String = store
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sessions'",
                [],
                |row| row.get(0),
            )
            .expect("sessions table sql");
        let event_sql: String = store
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'events'",
                [],
                |row| row.get(0),
            )
            .expect("events table sql");

        let session_sql_normalized = session_sql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();
        let event_sql_normalized = event_sql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();

        assert!(
            session_sql_normalized.contains("SESSION_ID INTEGER PRIMARY KEY"),
            "sessions schema should keep session_id as a plain integer primary key: {session_sql}"
        );
        assert!(
            !session_sql_normalized.contains("AUTOINCREMENT"),
            "sessions.session_id should not use AUTOINCREMENT: {session_sql}"
        );
        assert!(
            event_sql_normalized.contains("ID INTEGER PRIMARY KEY AUTOINCREMENT"),
            "events.id should keep AUTOINCREMENT: {event_sql}"
        );
    }

    #[test]
    fn fresh_db_schema_creates_record_routine_tables_with_shared_seq_contract() {
        let (_dir, store) = temp_store();
        let tables: Vec<String> = store
            .connection()
            .prepare(
                "
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                    'record_requests',
                    'record_sessions',
                    'selector_paths',
                    'action_events'
                  )
                ORDER BY name
                ",
            )
            .expect("prepare tables")
            .query_map([], |row| row.get(0))
            .expect("query tables")
            .collect::<Result<Vec<_>, _>>()
            .expect("tables");
        let action_sql: String = store
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'action_events'",
                [],
                |row| row.get(0),
            )
            .expect("action_events table sql");
        let action_sql_compact = action_sql
            .split_whitespace()
            .collect::<String>()
            .to_ascii_uppercase();
        let record_session_index_count: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_action_events_record_session_seq'",
                [],
                |row| row.get(0),
            )
            .expect("record session index count");
        let request_index_count: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_record_requests_status_expires'",
                [],
                |row| row.get(0),
            )
            .expect("request expiry index count");

        assert_eq!(
            tables,
            vec![
                "action_events",
                "record_requests",
                "record_sessions",
                "selector_paths"
            ]
        );
        assert!(
            action_sql_compact.contains("UNIQUE(SESSION_ID,SEQ)"),
            "action_events should share the app-session seq space: {action_sql}"
        );
        assert!(
            action_sql_compact.contains("FRAMEWORK_CLASSTEXTNOTNULLDEFAULT'UNKNOWN'"),
            "action_events should carry a value-free framework_class default: {action_sql}"
        );
        assert!(
            !action_sql_compact.contains("UNIQUE(RECORD_SESSION_ID,SEQ)"),
            "action_events must not create a per-recording seq universe: {action_sql}"
        );
        assert_eq!(record_session_index_count, 1);
        assert_eq!(request_index_count, 1);
    }

    #[test]
    fn shared_seq_union_query_interleaves_motion_and_action_rows() {
        let (_dir, store) = temp_store();
        let session_id = store.create_session(1_000, "test").expect("session");
        insert_minimal_event(store.connection(), session_id, 1, 1_100);
        insert_record_routine_rows(
            store.connection(),
            RecordRoutineFixture {
                request_id: 1,
                record_session_id: 1,
                selector_id: 1,
                session_id,
                seq: 2,
                action_ts: 1_200,
                record_ended_ts: Some(1_300),
                request_expires_at: 2_000,
                selector_hash: "interleave-hash",
            },
        );
        insert_minimal_event(store.connection(), session_id, 3, 1_300);

        let interleaved: Vec<(String, i64)> = store
            .connection()
            .prepare(
                "
                SELECT stream, seq
                FROM (
                    SELECT 'event' AS stream, session_id, seq FROM events
                    UNION ALL
                    SELECT 'action' AS stream, session_id, seq FROM action_events
                )
                ORDER BY session_id, seq
                ",
            )
            .expect("prepare interleave")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query interleave")
            .collect::<Result<Vec<_>, _>>()
            .expect("interleaved rows");

        assert_eq!(
            interleaved,
            vec![
                ("event".to_string(), 1),
                ("action".to_string(), 2),
                ("event".to_string(), 3)
            ]
        );
    }

    #[test]
    fn migration_session_and_focus_insert_work() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let mut sequencer = Sequencer::new(1_000, SessionTimebase::new(base, 1_000));
        let session_id = store
            .create_session(sequencer.started_at(), "test")
            .expect("session created");
        sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_focus("Plain Window", base));
        let report = store.insert_events(&[event]).expect("event inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count");
        let hwnd: String = store
            .connection()
            .query_row("SELECT hwnd FROM events", [], |row| row.get(0))
            .expect("hwnd");
        let seq: i64 = store
            .connection()
            .query_row("SELECT seq FROM events", [], |row| row.get(0))
            .expect("seq");

        assert_eq!(count, 1);
        assert_eq!(hwnd, "0x1a2b3c");
        assert_eq!(seq, 1);
        let index_count: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_events_session_kind_ts_id'",
                [],
                |row| row.get(0),
            )
            .expect("analytics index count");
        assert_eq!(index_count, 1);
        let redundant_index_count: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_events_session'",
                [],
                |row| row.get(0),
            )
            .expect("redundant index count");
        assert_eq!(redundant_index_count, 0);
    }

    #[test]
    fn session_boundary_insert_persists_kind_context_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_session_connect(base));

        let report = store.insert_events(&[event]).expect("event inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let row: (String, String, String) = store
            .connection()
            .query_row("SELECT kind, title, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("event row");

        assert_eq!(row.0, "session_connect");
        assert_eq!(row.1, "remote session 42");
        assert!(row.2.contains("\"connection\":\"remote\""));
    }

    #[test]
    fn clipboard_insert_persists_metadata_without_content_fields() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_clipboard_used(base));

        let report = store.insert_events(&[event]).expect("event inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let row: (String, String, String, Option<String>, Option<String>) = store
            .connection()
            .query_row(
                "SELECT kind, title, payload, key, exe FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("event row");

        assert_eq!(row.0, "clipboard_used");
        assert_eq!(row.1, "Clipboard text");
        assert!(row.2.contains("\"format_kind\":\"text\""));
        assert!(row.2.contains("\"text_char_count\":12"));
        assert!(row.2.contains("\"byte_size\":26"));
        assert_eq!(row.3, None);
        assert_eq!(row.4, None);
    }

    #[test]
    fn notifications_received_insert_persists_source_app_and_count() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_notifications_received(base));

        let report = store.insert_events(&[event]).expect("event inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let row: (String, String, String, Option<String>, Option<String>) = store
            .connection()
            .query_row(
                "SELECT kind, title, payload, key, exe FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("notification row");

        assert_eq!(row.0, "notifications_received");
        assert_eq!(row.1, "Calendar");
        assert!(row.2.contains("\"app\":\"Calendar\""));
        assert!(row.2.contains("\"count\":1"));
        assert!(!row.2.contains("title"));
        assert!(!row.2.contains("body"));
        assert_eq!(row.3, None);
        assert_eq!(row.4, None);
    }

    #[test]
    fn sensitive_context_insert_persists_audit_context() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let event = sequencer.stamp(captured_sensitive_context_entered(base));

        let report = store.insert_events(&[event]).expect("event inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let row: (String, String, String) = store
            .connection()
            .query_row("SELECT kind, title, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("event row");

        assert_eq!(row.0, "sensitive_context_entered");
        assert_eq!(row.1, "session locked");
        assert!(row.2.contains("\"reason\":\"session_locked\""));
    }

    #[test]
    fn create_session_persists_run_identity() {
        let (_dir, store) = temp_store();
        let identity = SessionIdentity::new("1.2.3")
            .with_host(Some("workstation".to_string()))
            .with_git_sha("abcdef123456")
            .with_run_label(Some("24h baseline".to_string()));

        let session_id = store
            .create_session_with_identity(10_000, &identity)
            .expect("session created");

        let row: (String, String, String, String) = store
            .connection()
            .query_row(
                "SELECT app_version, host, git_sha, run_label FROM sessions WHERE session_id = ?",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("identity row");

        assert_eq!(
            row,
            (
                "1.2.3".to_string(),
                "workstation".to_string(),
                "abcdef123456".to_string(),
                "24h baseline".to_string(),
            )
        );
    }

    #[test]
    fn unique_session_seq_is_enforced() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_focus("Plain Window", base));
        assert_eq!(
            store
                .insert_events(std::slice::from_ref(&event))
                .expect("first insert"),
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        assert_eq!(
            store.insert_events(&[event]).expect("duplicate skipped"),
            InsertReport {
                inserted: 0,
                skipped: 1
            }
        );
    }

    #[test]
    fn unique_action_session_seq_is_enforced() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        insert_recording_parent_for_session(store.connection(), session_id, 60);
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let action = sequencer.stamp_action(sample_action_capture(60, base, "edit"));

        assert_eq!(
            store
                .insert_actions(std::slice::from_ref(&action))
                .expect("first action insert"),
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );
        assert_eq!(
            store.insert_actions(&[action]).expect("duplicate skipped"),
            InsertReport {
                inserted: 0,
                skipped: 1
            }
        );
        let action_count: i64 = store
            .connection()
            .query_row(
                "SELECT action_count FROM record_sessions WHERE record_session_id = 60",
                [],
                |row| row.get(0),
            )
            .expect("record session action_count");
        assert_eq!(action_count, 1);
    }

    #[test]
    fn scrub_titles_before_blanks_old_titles_in_columns_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        // Two focus rows with titles; we will scrub with a cutoff between them.
        let old_event = sequencer.stamp(captured_focus("Old Secret Doc", base));
        let new_event = sequencer.stamp(captured_focus(
            "Fresh Title",
            base + Duration::from_millis(10),
        ));
        let cutoff = (old_event.ts_unix_ms + new_event.ts_unix_ms) / 2;
        store
            .insert_events(&[old_event, new_event])
            .expect("events inserted");

        let scrubbed = store.scrub_titles_before(cutoff).expect("scrub runs");
        assert_eq!(scrubbed, 1);

        let rows: Vec<(Option<String>, i64, String)> = store
            .connection()
            .prepare("SELECT title, is_sensitive, payload FROM events ORDER BY ts")
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        let (old_title, old_sensitive, old_payload) = &rows[0];
        let (new_title, _, new_payload) = &rows[1];

        // Old row: title gone from BOTH the typed column and the payload JSON,
        // and the row is not marked sensitive (policy omission, not a rule).
        assert_eq!(old_title.as_deref(), None);
        assert_eq!(*old_sensitive, 0);
        assert!(!old_payload.contains("Old Secret Doc"));
        assert!(!old_payload.contains("\"title\""));
        // New row untouched in both copies.
        assert_eq!(new_title.as_deref(), Some("Fresh Title"));
        assert!(new_payload.contains("Fresh Title"));

        // Idempotent: nothing left to scrub at the same cutoff.
        assert_eq!(store.scrub_titles_before(cutoff).expect("rerun"), 0);
    }

    #[test]
    fn prune_mouse_moves_before_deletes_only_old_movement_rows() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        // Old mouse_move + old key before the cutoff; fresh mouse_move after.
        let old_move = sequencer.stamp(captured_mouse_move(base));
        let old_key = sequencer.stamp(captured_key("A", base + Duration::from_millis(1)));
        let new_move = sequencer.stamp(captured_mouse_move(base + Duration::from_millis(10)));
        let cutoff = (old_key.ts_unix_ms + new_move.ts_unix_ms) / 2;
        store
            .insert_events(&[old_move, old_key, new_move])
            .expect("events inserted");

        let pruned = store.prune_mouse_moves_before(cutoff).expect("prune runs");
        assert_eq!(pruned, 1);

        let kinds: Vec<String> = store
            .connection()
            .prepare("SELECT kind FROM events ORDER BY ts")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        // The old key row survives (the tier touches mouse_move only), and
        // the fresh mouse_move survives (it is inside the window).
        assert_eq!(kinds, vec!["key".to_string(), "mouse_move".to_string()]);

        // Idempotent at the same cutoff.
        assert_eq!(store.prune_mouse_moves_before(cutoff).expect("rerun"), 0);
    }

    #[test]
    fn redaction_is_applied_before_typed_columns_and_payload_are_serialized() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let mut sequencer = Sequencer::new(1_000, SessionTimebase::new(base, 1_000));
        let session_id = store
            .create_session(sequencer.started_at(), "test")
            .expect("session created");
        sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_focus(
            "Secret Window",
            base + Duration::from_millis(1),
        ));
        let redacted = Policy::redact_titles_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");
        store.insert_events(&[redacted]).expect("event inserted");

        let (title, payload): (String, String) = store
            .connection()
            .query_row("SELECT title, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("redacted row");

        assert_eq!(title, "<redacted>");
        assert!(!title.contains("Secret"));
        assert!(!payload.contains("Secret"));
        assert!(payload.contains("<redacted>"));
    }

    #[test]
    fn sensitive_context_redaction_is_applied_before_storage() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store.create_session(1_000, "test").expect("session");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));
        let policy = Policy::identity().with_sensitive_context_suppression(true);

        let events = [
            sequencer.stamp(captured_sensitive_context_entered(base)),
            sequencer.stamp(captured_key("P", base + Duration::from_millis(1))),
            sequencer.stamp(captured_clipboard_used(base + Duration::from_millis(2))),
        ]
        .into_iter()
        .map(|event| policy.apply(event).expect("policy keeps row"))
        .collect::<Vec<_>>();

        let report = store.insert_events(&events).expect("events inserted");
        assert_eq!(
            report,
            InsertReport {
                inserted: 3,
                skipped: 0
            }
        );

        let key_row: (String, String, String, i64) = store
            .connection()
            .query_row(
                "SELECT key, title, payload, is_sensitive FROM events WHERE kind = 'key'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("key row");
        assert_eq!(key_row.0, "<redacted>");
        assert_eq!(key_row.1, "<redacted>");
        assert!(!key_row.2.contains("\"P\""));
        assert!(!key_row.2.contains("\"title\":\"Editor\""));
        assert!(key_row.2.contains("\"title\":\"<redacted>\""));
        assert_eq!(key_row.3, 1);

        let clipboard_payload: String = store
            .connection()
            .query_row(
                "SELECT payload FROM events WHERE kind = 'clipboard_used'",
                [],
                |row| row.get(0),
            )
            .expect("clipboard row");
        assert!(clipboard_payload.contains("\"text_char_count\":null"));
        assert!(clipboard_payload.contains("\"byte_size\":null"));
    }

    #[test]
    fn window_closed_insert_persists_duration_and_kind() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_window_closed("Editor", base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (source, kind, hwnd, duration_ms, payload): (String, String, String, i64, String) =
            store
                .connection()
                .query_row(
                    "SELECT source, kind, hwnd, duration_ms, payload FROM events",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .expect("window row");

        assert_eq!(source, "window");
        assert_eq!(kind, "window_closed");
        assert_eq!(hwnd, "0x4567");
        assert_eq!(duration_ms, 750);
        assert!(payload.contains("\"origin\":\"observed\""));
    }

    #[test]
    fn key_insert_persists_key_modifiers_and_window() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_key("A", base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (source, kind, key, shift, ctrl, alt, win, hwnd): (
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            String,
        ) = store
            .connection()
            .query_row(
                "SELECT source, kind, key, mod_shift, mod_ctrl, mod_alt, mod_win, hwnd FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("key row");

        assert_eq!(source, "keyboard");
        assert_eq!(kind, "key");
        assert_eq!(key, "A");
        assert_eq!(shift, 1);
        assert_eq!(ctrl, 0);
        assert_eq!(alt, 1);
        assert_eq!(win, 0);
        assert_eq!(hwnd, "0x789a");
    }

    #[test]
    fn key_redaction_is_applied_before_typed_columns_and_payload_are_serialized() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_key("Secret", base));
        let redacted = Policy::redact_keys_containing(["Secret"])
            .apply(event)
            .expect("policy keeps row");
        store.insert_events(&[redacted]).expect("event inserted");

        let (key, payload): (String, String) = store
            .connection()
            .query_row("SELECT key, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("redacted key row");

        assert_eq!(key, "<redacted>");
        assert!(!key.contains("Secret"));
        assert!(!payload.contains("Secret"));
        assert!(payload.contains("<redacted>"));
    }

    #[test]
    fn lean_policy_stores_key_class_but_no_content_and_no_sensitive_flag() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_key("S", base));
        let lean = Policy::identity()
            .with_store_key_content(false)
            .apply(event)
            .expect("policy keeps row");
        store.insert_events(&[lean]).expect("event inserted");

        let (key, is_sensitive, mod_shift, payload): (Option<String>, i64, i64, String) = store
            .connection()
            .query_row(
                "SELECT key, is_sensitive, mod_shift, payload FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("lean key row");

        // Content is absent from the typed column and the payload JSON;
        // the value-free class and timing/modifier facts remain, and the
        // row is NOT marked sensitive (no privacy rule fired).
        assert_eq!(key, None);
        assert_eq!(is_sensitive, 0);
        // "kind":"key" still names the row kind; the key *field* is gone.
        assert!(!payload.contains("\"key\":"));
        assert!(payload.contains("\"key_class\":\"printable\""));
        assert_eq!(mod_shift, 1);
    }

    #[test]
    fn mouse_click_insert_persists_button_position_and_window() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_mouse_click(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (source, kind, button, x, y, hwnd): (String, String, String, i64, i64, String) = store
            .connection()
            .query_row(
                "SELECT source, kind, button, pos_x, pos_y, hwnd FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("mouse row");

        assert_eq!(source, "mouse");
        assert_eq!(kind, "mouse_click");
        assert_eq!(button, "left");
        assert_eq!(x, 100);
        assert_eq!(y, 200);
        assert_eq!(hwnd, "0x8888");
    }

    #[test]
    fn mouse_double_click_insert_persists_interval_position_and_window() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_mouse_double_click(base));
        store.insert_events(&[event]).expect("event inserted");

        let (kind, button, x, y, duration_ms, payload): (String, String, i64, i64, i64, String) =
            store
                .connection()
                .query_row(
                    "SELECT kind, button, pos_x, pos_y, duration_ms, payload FROM events",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .expect("double-click row");

        assert_eq!(kind, "mouse_double_click");
        assert_eq!(button, "left");
        assert_eq!(x, 102);
        assert_eq!(y, 202);
        assert_eq!(duration_ms, 175);
        assert!(payload.contains("\"interval_ms\":175"));
    }

    #[test]
    fn mouse_drag_insert_persists_end_position_duration_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_mouse_drag(base));
        store.insert_events(&[event]).expect("event inserted");

        let (kind, button, x, y, duration_ms, payload): (String, String, i64, i64, i64, String) =
            store
                .connection()
                .query_row(
                    "SELECT kind, button, pos_x, pos_y, duration_ms, payload FROM events",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .expect("drag row");

        assert_eq!(kind, "mouse_drag");
        assert_eq!(button, "left");
        assert_eq!(x, 125);
        assert_eq!(y, 212);
        assert_eq!(duration_ms, 420);
        assert!(payload.contains("\"start_x\":100"));
        assert!(payload.contains("\"end_x\":125"));
        assert!(payload.contains("\"selection_candidate\":true"));
        assert!(payload.contains("\"distance_px\":28"));
    }

    #[test]
    fn mouse_wheel_insert_persists_direction_and_full_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_mouse_wheel(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (kind, button, x, y, payload): (String, String, i64, i64, String) = store
            .connection()
            .query_row(
                "SELECT kind, button, pos_x, pos_y, payload FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("wheel row");

        assert_eq!(kind, "mouse_wheel");
        assert_eq!(button, "wheel_down");
        assert_eq!(x, 300);
        assert_eq!(y, 400);
        assert!(payload.contains("\"delta\":-120"));
        assert!(payload.contains("\"axis\":\"vertical\""));
    }

    #[test]
    fn mouse_move_insert_persists_position_duration_and_slim_motion_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_mouse_move(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (kind, title, x, y, duration_ms, payload): (
            String,
            Option<String>,
            i64,
            i64,
            i64,
            String,
        ) = store
            .connection()
            .query_row(
                "SELECT kind, title, pos_x, pos_y, duration_ms, payload FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("move row");

        assert_eq!(kind, "mouse_move");
        assert_eq!(title, None);
        assert_eq!(x, 500);
        assert_eq!(y, 600);
        assert_eq!(duration_ms, 250);
        assert!(payload.contains("\"dx_total\":12"));
        assert!(payload.contains("\"dy_total\":-5"));
        assert!(payload.contains("\"distance_px\":18"));
        assert!(payload.contains("\"raw_event_count\":3"));
        assert!(!payload.contains("\"window\""));
        assert!(!payload.contains("Canvas"));
    }

    #[test]
    fn system_info_insert_persists_host_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_system_info(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (source, kind, title, payload): (String, String, String, String) = store
            .connection()
            .query_row(
                "SELECT source, kind, title, payload FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("system row");

        assert_eq!(source, "system");
        assert_eq!(kind, "system_info");
        assert_eq!(title, "workstation");
        assert!(payload.contains("\"memory_total_bytes\":68719476736"));
        assert!(payload.contains("\"processor_count\":16"));
    }

    #[test]
    fn virtual_screen_insert_persists_origin_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_virtual_screen(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (kind, x, y, payload): (String, i64, i64, String) = store
            .connection()
            .query_row(
                "SELECT kind, pos_x, pos_y, payload FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("virtual screen row");

        assert_eq!(kind, "virtual_screen");
        assert_eq!(x, -1920);
        assert_eq!(y, 0);
        assert!(payload.contains("\"width\":4480"));
        assert!(payload.contains("\"height\":1440"));
    }

    #[test]
    fn power_boundary_recovered_insert_persists_audit_marker() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_power_boundary_recovered(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (source, kind, duration_ms, payload): (String, String, i64, String) = store
            .connection()
            .query_row(
                "SELECT source, kind, duration_ms, payload FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("power row");

        assert_eq!(source, "system");
        assert_eq!(kind, "power_boundary_recovered");
        assert_eq!(duration_ms, 30_001);
        assert!(payload.contains("\"gap_ms\":30001"));
        assert!(payload.contains("\"capped_dwell_ms\":30000"));
    }

    #[test]
    fn power_suspend_and_resume_insert_persist_audit_markers() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let suspend = sequencer.stamp(captured_power_suspend(base));
        let resume = sequencer.stamp(captured_power_resume(base + Duration::from_millis(1)));
        let report = store
            .insert_events(&[suspend, resume])
            .expect("events inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 2,
                skipped: 0
            }
        );

        let rows: Vec<(String, Option<i64>, String)> = store
            .connection()
            .prepare("SELECT kind, duration_ms, payload FROM events ORDER BY seq")
            .expect("prepare power rows")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query power rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("power rows");

        assert_eq!(rows[0].0, "power_suspend");
        assert_eq!(rows[0].1, None);
        assert!(rows[0].2.contains("\"tick_ms\":1000"));
        assert_eq!(rows[1].0, "power_resume");
        assert_eq!(rows[1].1, None);
        assert!(rows[1].2.contains("\"tick_ms\":2000"));
        assert!(rows[1].2.contains("\"matched_suspend\":true"));
    }

    #[test]
    fn idle_insert_persists_duration_and_payload() {
        let (_dir, mut store) = temp_store();
        let base = Instant::now();
        let session_id = store
            .create_session(1_000, "test")
            .expect("session created");
        let mut sequencer = Sequencer::new(session_id, SessionTimebase::new(base, 1_000));

        let event = sequencer.stamp(captured_idle(base));
        let report = store.insert_events(&[event]).expect("event inserted");

        assert_eq!(
            report,
            InsertReport {
                inserted: 1,
                skipped: 0
            }
        );

        let (kind, duration_ms, payload): (String, i64, String) = store
            .connection()
            .query_row("SELECT kind, duration_ms, payload FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("idle row");

        assert_eq!(kind, "idle");
        assert_eq!(duration_ms, 300_000);
        assert!(payload.contains("\"idle_ms\":300000"));
    }

    fn row_count(conn: &Connection, table: &str) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        conn.query_row(&sql, [], |row| row.get(0)).expect("count")
    }

    fn erased_table_sequence_count(conn: &Connection) -> i64 {
        conn.query_row(
            "
            SELECT COUNT(*)
            FROM sqlite_sequence
            WHERE name IN (
                'action_events',
                'record_sessions',
                'record_requests',
                'selector_paths',
                'events',
                'sessions',
                'meta'
            )
            ",
            [],
            |row| row.get(0),
        )
        .expect("sqlite_sequence count")
    }
}
