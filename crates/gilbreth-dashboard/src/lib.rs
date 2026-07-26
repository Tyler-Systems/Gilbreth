//! Gilbreth's native dashboard (S4): an egui/eframe shell over the
//! parity-proven `gilbreth-read` surface. The owning app supplies a
//! [`DashboardHost`]; this crate owns the window, theme, charts, and tabs.
//!
//! Runtime contract (ROADMAP S4 kickoff): reads happen on a background
//! thread and never block paint; one concurrent viewer persists UI state under
//! the host-supplied path inside `%LOCALAPPDATA%\Gilbreth`; errors surface as
//! sanitized display strings only.

pub mod charts;
#[cfg(test)]
mod copy_audit;
pub mod data;
pub mod fonts;
pub mod format;
pub mod shell;
pub mod tabs;
pub mod theme;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use data::{
    AnalyticsSelection, AnalyticsSnapshot, DashboardHost, DataWorker, DiagnosticsSnapshot,
    ExportSaveError, PrivacySnapshot, RecordingsSnapshot, Request, SessionEventsSnapshot,
    SessionSnapshot, Snapshot, TodaySnapshot, UiStatePersistence, WeekSnapshot,
};
use gilbreth_read::{DiscoveryNoticeState, PatternCandidate};
use shell::Tab;

/// UX-57: an "updated HH:MM" older than this renders as stale.
const STALE_AFTER_MS: i64 = 10 * 60_000;
const ACTIVE_TAB_STORAGE_KEY: &str = "active-tab";
use tabs::analytics::{record_request_key, AnalyticsAction, AnalyticsView};
use tabs::privacy::{PrivacyAction, PrivacyView};
use tabs::recordings::{RecordingsAction, RecordingsView};
use tabs::session::{SessionAction, SessionView};
use tabs::today::CurationAction;

pub struct DashboardApp {
    host: Arc<DashboardHost>,
    ui_state_persistence: UiStatePersistence,
    worker: Option<DataWorker>,
    today: Option<TodaySnapshot>,
    week: Option<Box<WeekSnapshot>>,
    session: Option<Box<SessionSnapshot>>,
    /// The Session selector's sticky selection; `None` resolves the
    /// open/latest default, like the Streamlit selectbox.
    session_selection: Option<i64>,
    /// The Event-list snapshot, on its own cadence (UX-62): a plain tab
    /// refresh never replaces it — only the explicit refresh button, a
    /// session change, or a completed delete queues a rebuild.
    session_events: Option<Box<SessionEventsSnapshot>>,
    /// Whether an Event-list read is in flight (its own flag — the list is
    /// separately-requested state, not part of the tab's pending read).
    session_events_pending: bool,
    /// One-shot delete notice: (is_error, message).
    session_notice: Option<(bool, String)>,
    analytics: Option<Box<AnalyticsSnapshot>>,
    analytics_selection: AnalyticsSelection,
    recordings: Option<Box<RecordingsSnapshot>>,
    recordings_selection: Option<i64>,
    /// One-shot export/delete notice: (is_error, message).
    recordings_notice: Option<(bool, String)>,
    privacy: Option<Box<PrivacySnapshot>>,
    diagnostics: Option<Box<DiagnosticsSnapshot>>,
    /// The prune-days input; `None` until the user edits it.
    privacy_days: Option<i64>,
    /// Generation of the newest privacy read issued; completions carrying
    /// an older generation are dropped (a stale preview must never replace
    /// newer state or re-seed the redaction editor).
    privacy_generation: u64,
    /// After a successful settings save: once a snapshot of at least this
    /// generation confirms the write landed, clear the editor buffers —
    /// but only the fields whose edit revision still matches the captured
    /// array, so input typed after the save is never discarded.
    privacy_buffers_clear_after: Option<(u64, [u64; tabs::privacy::ADVANCED_BUFFER_FIELDS.len()])>,
    /// One-shot prune notice: (is_error, message).
    privacy_notice: Option<(bool, String)>,
    /// One-shot advanced-settings notice: (is_error, message).
    advanced_privacy_notice: Option<(bool, String)>,
    /// One-shot portable archive export notice: (is_error, message).
    #[cfg(windows)]
    portable_archive_export_notice: Option<(bool, String)>,
    /// request_key -> (request_id, last status read from the DB).
    record_statuses: HashMap<String, (i64, Option<String>)>,
    record_error: Option<String>,
    sphere_notice: Option<(bool, String)>,
    tab: Tab,
    curation_error: Option<String>,
    /// Monotonic session latch for a successful welcome dismissal. A Today
    /// read that started before the config write completed must never make
    /// the banner reappear when that stale snapshot lands.
    first_run_welcome_dismissed_latch: bool,
    was_focused: bool,
    /// UX-57: tabs with a read in flight — set when a refresh is queued,
    /// cleared when that tab's snapshot arrives. Drives the disabled
    /// Refresh button and the updating cue.
    pending_reads: HashSet<Tab>,
    /// Test-only receiver end of the stub worker's request channel, so
    /// tests observe exactly what was DELIVERED to the worker boundary
    /// (payload and order) rather than inferring it from side effects.
    /// `None` in production.
    request_rx_for_tests: Option<std::sync::mpsc::Receiver<Request>>,
}

impl DashboardApp {
    pub fn new(host: Arc<DashboardHost>, ctx: egui::Context, restored_tab: Option<Tab>) -> Self {
        fonts::install(&ctx);
        theme::apply(&ctx);
        let worker = DataWorker::spawn(host.clone(), ctx);
        let ui_state_persistence = host.ui_state_persistence;
        let mut app = Self {
            host,
            ui_state_persistence,
            worker: Some(worker),
            today: None,
            week: None,
            session: None,
            session_selection: None,
            session_events: None,
            session_events_pending: false,
            session_notice: None,
            analytics: None,
            analytics_selection: AnalyticsSelection::default(),
            recordings: None,
            recordings_selection: None,
            recordings_notice: None,
            privacy: None,
            diagnostics: None,
            privacy_days: None,
            privacy_generation: 0,
            privacy_buffers_clear_after: None,
            privacy_notice: None,
            advanced_privacy_notice: None,
            #[cfg(windows)]
            portable_archive_export_notice: None,
            record_statuses: HashMap::new(),
            record_error: None,
            sphere_notice: None,
            tab: restored_tab.unwrap_or(Tab::Today),
            curation_error: None,
            first_run_welcome_dismissed_latch: false,
            was_focused: true,
            pending_reads: HashSet::new(),
            request_rx_for_tests: None,
        };
        // A restored non-Today tab needs its first read queued up front (the
        // worker only reads Today unprompted).
        app.request_refresh_for(app.tab);
        app
    }

    /// Test constructor: a channel-backed stub worker (no reader thread,
    /// no database) — snapshots are injected and curation writes go
    /// through the stub host, while issued requests stay observable on
    /// the real channel.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_tests(
        host: Arc<DashboardHost>,
        today: Option<TodaySnapshot>,
        week: Option<WeekSnapshot>,
        session: Option<SessionSnapshot>,
        session_events: Option<SessionEventsSnapshot>,
        analytics: Option<AnalyticsSnapshot>,
        recordings: Option<RecordingsSnapshot>,
        privacy: Option<PrivacySnapshot>,
        diagnostics: Option<DiagnosticsSnapshot>,
    ) -> Self {
        let ui_state_persistence = host.ui_state_persistence;
        let recordings_selection = recordings
            .as_ref()
            .and_then(|snapshot| snapshot.selected_id);
        let session_selection = session
            .as_ref()
            .and_then(|snapshot| snapshot.selected_session_id);
        let privacy_days = privacy.as_ref().map(|snapshot| snapshot.prune_days);
        let first_run_welcome_dismissed_latch = today
            .as_ref()
            .is_some_and(|snapshot| snapshot.first_run_welcome_dismissed);
        let (worker, request_rx, _snapshot_tx) = DataWorker::stub_for_tests();
        Self {
            host,
            ui_state_persistence,
            worker: Some(worker),
            today,
            week: week.map(Box::new),
            session: session.map(Box::new),
            session_selection,
            session_events: session_events.map(Box::new),
            session_events_pending: false,
            session_notice: None,
            analytics: analytics.map(Box::new),
            analytics_selection: AnalyticsSelection::default(),
            recordings: recordings.map(Box::new),
            recordings_selection,
            recordings_notice: None,
            privacy: privacy.map(Box::new),
            diagnostics: diagnostics.map(Box::new),
            privacy_days,
            privacy_generation: 0,
            privacy_buffers_clear_after: None,
            privacy_notice: None,
            advanced_privacy_notice: None,
            #[cfg(windows)]
            portable_archive_export_notice: None,
            record_statuses: HashMap::new(),
            record_error: None,
            sphere_notice: None,
            tab: Tab::Today,
            curation_error: None,
            first_run_welcome_dismissed_latch,
            was_focused: true,
            pending_reads: HashSet::new(),
            request_rx_for_tests: Some(request_rx),
        }
    }

    pub fn active_tab(&self) -> Tab {
        self.tab
    }

    /// Queue a background read for whatever the given tab renders (every
    /// tab is native as of the UX-62 Session port). Privacy reads take
    /// a fresh generation even without a worker so tests exercise the same
    /// staleness arithmetic.
    fn request_refresh_for(&mut self, tab: Tab) {
        let request = match tab {
            Tab::Today => Request::RefreshToday,
            Tab::Week => Request::RefreshWeek,
            // A plain Session refresh deliberately leaves the Event-list
            // snapshot untouched (UX-62 mirrors the Streamlit two-key
            // cache); the list rebuilds only via request_session_events.
            Tab::Session => Request::RefreshSession(self.session_selection),
            Tab::Analytics => Request::RefreshAnalytics(self.analytics_selection),
            Tab::Recordings => Request::RefreshRecordings(self.recordings_selection),
            Tab::Privacy => {
                self.privacy_generation += 1;
                Request::RefreshPrivacy {
                    days: self.privacy_days,
                    generation: self.privacy_generation,
                }
            }
            Tab::Diagnostics => Request::RefreshDiagnostics,
        };
        // UX-57: mark the read in flight until its snapshot arrives —
        // but only when the request actually reached the worker, so a
        // failed send can never wedge Refresh (branch review).
        let delivered = self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.request(request));
        if delivered {
            self.pending_reads.insert(tab);
        }
    }

    /// Queue an Event-list rebuild for one session. Separately-requested
    /// state: never issued by a plain tab refresh.
    fn request_session_events(&mut self, session_id: i64) {
        let delivered = self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.request(Request::RefreshSessionEvents(session_id)));
        if delivered {
            self.session_events_pending = true;
        }
    }

    /// The Event list follows the resolved session like the Streamlit
    /// two-key snapshot cache: whenever the held list is missing or keyed
    /// to a different session than the current resolution, queue one
    /// rebuild (at most one in flight).
    fn sync_session_events(&mut self) {
        if self.session_events_pending {
            return;
        }
        let Some(resolved) = self
            .session
            .as_ref()
            .and_then(|snapshot| snapshot.selected_session_id)
        else {
            return;
        };
        let current = self.session_events.as_ref().map(|events| events.session_id);
        if current != Some(resolved) {
            self.request_session_events(resolved);
        }
    }

    /// Test seam: drain the requests actually delivered to the stub
    /// worker's channel (exact payload, in send order). Empty in
    /// production mode.
    pub fn take_issued_requests_for_tests(&mut self) -> Vec<Request> {
        self.request_rx_for_tests
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default()
    }

    /// The whole viewport. Public so kittest harnesses can drive it without
    /// an eframe window.
    pub fn show_root(&mut self, ui: &mut egui::Ui) {
        let arrived = self
            .worker
            .as_ref()
            .map(|worker| worker.poll())
            .unwrap_or_default();
        if !arrived.is_empty() {
            let ctx = ui.ctx().clone();
            for snapshot in arrived {
                self.adopt_snapshot(&ctx, snapshot);
            }
        }
        let focused = ui.ctx().input(|input| input.focused);
        if focused && !self.was_focused {
            self.request_refresh_for(self.tab);
        }
        self.was_focused = focused;

        // UX-58: Ctrl+scroll (or pinch) scales the whole UI; egui's
        // built-in Ctrl+/Ctrl- zoom keys stay available too.
        let zoom = ui.ctx().input(|input| input.zoom_delta());
        if zoom != 1.0 {
            let factor = (ui.ctx().zoom_factor() * zoom).clamp(0.75, 2.0);
            ui.ctx().set_zoom_factor(factor);
        }

        egui::Frame::default()
            .fill(theme::DARKROOM)
            .inner_margin(egui::Margin {
                left: 18,
                right: 18,
                top: 12,
                bottom: 0,
            })
            .show(ui, |ui| {
                let updated = match self.tab {
                    Tab::Week => self.week.as_ref().map(|snapshot| snapshot.generated_at_ms),
                    Tab::Session => self
                        .session
                        .as_ref()
                        .map(|snapshot| snapshot.generated_at_ms),
                    Tab::Analytics => self
                        .analytics
                        .as_ref()
                        .map(|snapshot| snapshot.generated_at_ms),
                    Tab::Recordings => self
                        .recordings
                        .as_ref()
                        .map(|snapshot| snapshot.generated_at_ms),
                    Tab::Privacy => self
                        .privacy
                        .as_ref()
                        .map(|snapshot| snapshot.generated_at_ms),
                    Tab::Diagnostics => self
                        .diagnostics
                        .as_ref()
                        .map(|snapshot| snapshot.generated_at_ms),
                    _ => self.today.as_ref().map(|snapshot| snapshot.generated_at_ms),
                };
                // UX-57: in-flight and staleness cues on the brand row.
                let in_flight = self.pending_reads.contains(&self.tab);
                let stale = updated.is_some_and(|updated_ms| {
                    (self.host.clock)().saturating_sub(updated_ms) > STALE_AFTER_MS
                });
                if shell::top_bar(ui, updated, in_flight, stale) {
                    self.request_refresh_for(self.tab);
                }
                ui.add_space(6.0);
                let before = self.tab;
                shell::tab_strip(ui, &mut self.tab);
                if self.tab != before {
                    // Per-tab staleness: every switch queues a fresh read;
                    // the cached snapshot renders in the meantime.
                    self.request_refresh_for(self.tab);
                    // UX-20: one-shot outcome notices don't outlive the
                    // tab they answered; an hour-old "Deleted N entries"
                    // must not read as current status later.
                    self.privacy_notice = None;
                    self.advanced_privacy_notice = None;
                    self.recordings_notice = None;
                    self.session_notice = None;
                    self.sphere_notice = None;
                    self.record_error = None;
                    self.curation_error = None;
                }
                ui.add_space(2.0);
                shell::hairline(ui);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(10.0);
                        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                            ui.set_max_width(1040.0_f32.min(ui.available_width()));
                            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                                self.tab_body(ui)
                            });
                        });
                        ui.add_space(24.0);
                    });
            });
    }

    /// Adopt a completed read from the worker. Privacy snapshots carry the
    /// generation of the request they answered; anything older than the
    /// newest issued request is dropped, so a slow read can never rewind
    /// the days selection, re-arm a superseded prune preview, or re-seed
    /// the redaction editor from pre-save state.
    fn adopt_snapshot(&mut self, ctx: &egui::Context, snapshot: Snapshot) {
        // UX-57: an ADOPTED snapshot ends its tab's in-flight state. The
        // removal lives per-arm so a dropped stale Privacy completion
        // cannot clear the cue while the newer read is still running
        // (branch review).
        match snapshot {
            Snapshot::Today(mut snapshot) => {
                self.pending_reads.remove(&Tab::Today);
                snapshot.first_run_welcome_dismissed |= self.first_run_welcome_dismissed_latch;
                self.today = Some(*snapshot);
            }
            Snapshot::Week(snapshot) => {
                self.pending_reads.remove(&Tab::Week);
                self.week = Some(snapshot);
            }
            Snapshot::Session(snapshot) => {
                self.pending_reads.remove(&Tab::Session);
                // The worker clears a selection whose session no longer
                // exists (falling back to the open/latest default); adopt
                // whatever it honored, like Recordings.
                self.session_selection = snapshot.selected_session_id;
                self.session = Some(snapshot);
                // Session resolved: if the held Event list is keyed to a
                // different session (or absent), queue its rebuild — the
                // Streamlit cache's key-mismatch refresh.
                self.sync_session_events();
            }
            Snapshot::SessionEvents(snapshot) => {
                self.session_events_pending = false;
                self.session_events = Some(snapshot);
                // A slow read for a superseded session converges: the
                // key-mismatch check queues the current session's list.
                self.sync_session_events();
            }
            Snapshot::Analytics(snapshot) => {
                self.pending_reads.remove(&Tab::Analytics);
                // The resolved default becomes the sticky selection,
                // like the Streamlit selectbox.
                self.analytics_selection.scope = Some(snapshot.scope);
                self.analytics = Some(snapshot);
                for (request_id, status) in self.record_statuses.values_mut() {
                    *status = (self.host.record_request_status)(*request_id);
                }
            }
            Snapshot::Recordings(snapshot) => {
                self.pending_reads.remove(&Tab::Recordings);
                // The worker clears a selection whose recording no
                // longer exists; adopt whatever it honored.
                self.recordings_selection = snapshot.selected_id;
                self.recordings = Some(snapshot);
            }
            Snapshot::Privacy(snapshot) => {
                if snapshot.generation < self.privacy_generation {
                    return;
                }
                self.pending_reads.remove(&Tab::Privacy);
                if let Some((after, saved_revisions)) = self.privacy_buffers_clear_after {
                    if snapshot.generation >= after {
                        // The refreshed config is now in hand; the fields
                        // untouched since the acknowledged save re-seed
                        // from it, like the Streamlit rerun. Fields edited
                        // after that save keep their newer input.
                        tabs::privacy::clear_unedited_buffers(ctx, &saved_revisions);
                        self.privacy_buffers_clear_after = None;
                    }
                }
                self.privacy_days = Some(snapshot.prune_days);
                self.privacy = Some(snapshot);
            }
            Snapshot::Diagnostics(snapshot) => {
                self.pending_reads.remove(&Tab::Diagnostics);
                self.diagnostics = Some(snapshot);
            }
        }
    }

    /// Test seam: feed a snapshot through the same adoption path the
    /// worker poll uses.
    pub fn adopt_snapshot_for_tests(&mut self, ctx: &egui::Context, snapshot: Snapshot) {
        self.adopt_snapshot(ctx, snapshot);
    }

    /// Test seam: the newest issued privacy request generation, so tests
    /// can craft completions that count as current vs. stale.
    pub fn privacy_generation_for_tests(&self) -> u64 {
        self.privacy_generation
    }

    fn tab_body(&mut self, ui: &mut egui::Ui) {
        match self.tab {
            Tab::Today => self.today_body(ui),
            Tab::Week => self.week_body(ui),
            Tab::Session => self.session_body(ui),
            Tab::Analytics => self.analytics_body(ui),
            Tab::Recordings => self.recordings_body(ui),
            Tab::Privacy => self.privacy_body(ui),
            Tab::Diagnostics => self.diagnostics_body(ui),
        }
    }

    fn session_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.session else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading this session…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        let db_path = self.host.db_path.display().to_string();
        let actions = {
            let view = SessionView {
                snapshot,
                events: self.session_events.as_deref(),
                events_pending: self.session_events_pending,
                db_path: &db_path,
                notice: self.session_notice.as_ref(),
            };
            tabs::session::show(ui, &view)
        };
        if !actions.is_empty() {
            let ctx = ui.ctx().clone();
            self.apply_session_actions(&ctx, actions);
        }
    }

    fn apply_session_actions(&mut self, ctx: &egui::Context, actions: Vec<SessionAction>) {
        for action in actions {
            match action {
                SessionAction::Select(session_id) => {
                    self.session_selection = Some(session_id);
                    self.session_notice = None;
                    // The per-session reads re-run for the new selection;
                    // its snapshot adoption then queues the Event-list
                    // rebuild through the key-mismatch check.
                    self.request_refresh_for(Tab::Session);
                }
                SessionAction::RefreshEvents => {
                    let resolved = self
                        .session
                        .as_ref()
                        .and_then(|snapshot| snapshot.selected_session_id);
                    if let Some(session_id) = resolved {
                        self.request_session_events(session_id);
                    }
                }
                SessionAction::DeleteEvents(event_ids) => {
                    match (self.host.delete_events)(&event_ids) {
                        Ok(outcome) => {
                            self.session_notice = Some(match &outcome.scrub_warning {
                                Some(warning) => (
                                    true,
                                    format!(
                                        "Deleted {} entries, but {}.",
                                        outcome.deleted, warning
                                    ),
                                ),
                                None => (false, format!("Deleted {} entries.", outcome.deleted)),
                            });
                            // Mirrors reset_confirmation + the snapshot
                            // clear + rerun: the confirm disarms, the list
                            // and the per-session totals both re-read.
                            ctx.data_mut(|data| {
                                data.remove::<bool>(tabs::session::delete_confirm_id());
                            });
                            self.session_events = None;
                            self.request_refresh_for(Tab::Session);
                            self.sync_session_events();
                        }
                        Err(error) => {
                            self.session_notice = Some((
                                true,
                                format!(
                                    "Couldn't delete the selected entries. The database may be \
                                     busy. Technical detail: {error}"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn diagnostics_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.diagnostics else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading the diagnostics…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        let config_path = self.host.config_path.display().to_string();
        let actions = tabs::diagnostics::show(ui, snapshot, &config_path);
        for action in actions {
            (self.host.request_permission_action)(action);
        }
    }

    fn privacy_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.privacy else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading your data overview…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        let actions = {
            let view = PrivacyView {
                snapshot,
                prune_notice: self.privacy_notice.as_ref(),
                advanced_notice: self.advanced_privacy_notice.as_ref(),
                #[cfg(windows)]
                portable_export_notice: self.portable_archive_export_notice.as_ref(),
            };
            tabs::privacy::show(ui, &view)
        };
        if !actions.is_empty() {
            let ctx = ui.ctx().clone();
            self.apply_privacy_actions(&ctx, actions);
        }
    }

    fn apply_privacy_actions(&mut self, ctx: &egui::Context, actions: Vec<PrivacyAction>) {
        for action in actions {
            match action {
                PrivacyAction::SetPruneDays(days) => {
                    self.privacy_days = Some(days);
                    self.request_refresh_for(Tab::Privacy);
                }
                PrivacyAction::PruneOldEvents { cutoff_ms } => {
                    match (self.host.prune_old_events)(cutoff_ms) {
                        Ok(outcome) => {
                            let message = format!(
                                "Deleted {} entries ({} activity events, {} sessions, {} \
                                 recording steps, {} recordings, {} record requests, {} \
                                 recording-data entries). ",
                                outcome.total_deleted(),
                                outcome.events_deleted,
                                outcome.sessions_deleted,
                                outcome.action_events_deleted,
                                outcome.record_sessions_deleted,
                                outcome.record_requests_deleted,
                                outcome.selector_paths_deleted
                            );
                            self.privacy_notice = Some(if outcome.compaction_completed {
                                (
                                    false,
                                    format!(
                                        "{message}The database was compacted to reclaim the \
                                         space."
                                    ),
                                )
                            } else {
                                (
                                    true,
                                    format!(
                                        "{message}The data was deleted, but the database \
                                         couldn't be compacted to reclaim space right now. \
                                         Technical detail: {}",
                                        outcome
                                            .compact_error
                                            .as_deref()
                                            .unwrap_or("unknown compaction error")
                                    ),
                                )
                            });
                            // Mirrors `reset_confirmation` + the cache clear.
                            ctx.data_mut(|data| {
                                data.remove::<bool>(tabs::privacy::prune_confirm_id());
                            });
                            self.request_refresh_for(Tab::Privacy);
                        }
                        Err(error) => {
                            self.privacy_notice = Some((
                                true,
                                format!(
                                    "Couldn't delete the old data. The database may be busy. \
                                     Technical detail: {error}"
                                ),
                            ));
                        }
                    }
                }
                PrivacyAction::SaveSettings { values, revisions } => {
                    match (self.host.write_privacy_settings)(&values) {
                        Ok(()) => {
                            self.advanced_privacy_notice = Some((
                                false,
                                "Privacy settings saved. Redaction and capture-exclusion \
                                 changes apply to future rows after Gilbreth restarts; a \
                                 title-retention setting also blanks titles on existing rows \
                                 older than the window at the next start."
                                    .to_string(),
                            ));
                            // The held snapshot predates the write; fold the
                            // saved values in so nothing re-seeds from
                            // pre-save state. The buffers themselves stay
                            // put until a refresh at least as new as the
                            // save acknowledges it (adopt_snapshot clears
                            // them then) — clearing into the current
                            // snapshot could resurrect the old rules.
                            if let Some(snapshot) = &mut self.privacy {
                                let settings = &mut snapshot.settings;
                                settings.sensitive_context_suppression =
                                    values.sensitive_context_suppression;
                                settings.redact_titles_containing = values.redact_titles_containing;
                                settings.redact_keys_containing = values.redact_keys_containing;
                                settings.excluded_apps = values.excluded_apps;
                                settings.title_retention_days = values.title_retention_days;
                                settings.mouse_move_retention_days =
                                    values.mouse_move_retention_days;
                            }
                            self.request_refresh_for(Tab::Privacy);
                            self.privacy_buffers_clear_after =
                                Some((self.privacy_generation, revisions));
                        }
                        Err(error) => {
                            self.advanced_privacy_notice = Some((
                                true,
                                format!(
                                    "Couldn't save your privacy settings. Technical detail: \
                                     {error}"
                                ),
                            ));
                        }
                    }
                }
                #[cfg(windows)]
                PrivacyAction::ExportPortableArchive { source_id, mode } => {
                    let result = (self.host.export_portable_archive)(&source_id, &mode);
                    tabs::privacy::clear_portable_export_secrets(ctx);
                    self.portable_archive_export_notice = Some(match result {
                        Ok(path) => (
                            false,
                            format!(
                                "Portable archive copied to {path}. The source archive was retained."
                            ),
                        ),
                        Err(error) => (
                            true,
                            format!("Portable archive needs retry. Technical detail: {error}"),
                        ),
                    });
                }
            }
        }
    }

    fn recordings_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.recordings else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading your recordings…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        let actions = {
            let view = RecordingsView {
                snapshot,
                notice: self.recordings_notice.as_ref(),
            };
            tabs::recordings::show(ui, &view)
        };
        if !actions.is_empty() {
            let ctx = ui.ctx().clone();
            self.apply_recordings_actions(&ctx, actions);
        }
    }

    fn apply_recordings_actions(&mut self, ctx: &egui::Context, actions: Vec<RecordingsAction>) {
        for action in actions {
            match action {
                RecordingsAction::Select(record_session_id) => {
                    self.recordings_selection = Some(record_session_id);
                    self.recordings_notice = None;
                    self.request_refresh_for(Tab::Recordings);
                }
                RecordingsAction::ExportAgentHandoff {
                    record_session_id,
                    labels,
                } => {
                    self.save_export(
                        record_session_id,
                        gilbreth_read::REPLAY_EXPORT_MODE_AGENT_GROUNDED,
                        &labels,
                    );
                }
                RecordingsAction::ExportNativeBlueprint {
                    record_session_id,
                    labels,
                } => {
                    self.save_export(
                        record_session_id,
                        gilbreth_read::REPLAY_EXPORT_MODE_NATIVE_SKELETON,
                        &labels,
                    );
                }
                RecordingsAction::Delete(record_session_id) => {
                    match (self.host.delete_recording)(record_session_id) {
                        Ok(outcome) => {
                            self.recordings_notice = Some(match &outcome.scrub_warning {
                                Some(warning) => (
                                    true,
                                    format!(
                                        "Deleted {} recording, but {}.",
                                        outcome.deleted, warning
                                    ),
                                ),
                                None => (false, format!("Deleted {} recording.", outcome.deleted)),
                            });
                            // Mirrors `reset_confirmation` + the list rerun.
                            ctx.data_mut(|data| {
                                data.remove::<bool>(tabs::recordings::delete_confirm_id(
                                    record_session_id,
                                ));
                            });
                            self.recordings_selection = None;
                            self.request_refresh_for(Tab::Recordings);
                        }
                        Err(error) => {
                            self.recordings_notice = Some((
                                true,
                                format!(
                                    "Gilbreth couldn't delete that recording right now. The \
                                     database may be busy. Technical detail: {error}"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn save_export(&mut self, record_session_id: i64, mode: &str, labels: &HashMap<i64, String>) {
        let what = if mode == gilbreth_read::REPLAY_EXPORT_MODE_NATIVE_SKELETON {
            "native automation blueprint"
        } else {
            "agent handoff trace"
        };
        self.recordings_notice = Some(
            match (self.host.save_replay_export)(record_session_id, mode, labels) {
                Ok(path) => (false, format!("Saved the {what} to {path}.")),
                Err(ExportSaveError::Build(error)) => (
                    true,
                    format!(
                        "Gilbreth couldn't build the {what} right now. The database may be \
                         busy. Technical detail: {error}"
                    ),
                ),
                Err(ExportSaveError::Write(error)) => (
                    true,
                    format!("Gilbreth couldn't save the export file. Technical detail: {error}"),
                ),
            },
        );
    }

    fn analytics_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.analytics else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading your analytics…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        let actions = {
            let view = AnalyticsView {
                snapshot,
                record_statuses: &self.record_statuses,
                sphere_notice: self.sphere_notice.as_ref(),
                record_error: self.record_error.as_deref(),
                sidecar_name: &self.host.spheres_sidecar_name,
                casefold: self.host.casefold_token.as_ref(),
            };
            tabs::analytics::show(ui, &view)
        };
        if !actions.is_empty() {
            self.apply_analytics_actions(actions);
        }
    }

    fn current_aliases(&self) -> std::collections::BTreeMap<String, String> {
        self.analytics
            .as_ref()
            .and_then(|snapshot| snapshot.data.as_ref())
            .map(|data| data.aliases.clone())
            .unwrap_or_default()
    }

    fn apply_analytics_actions(&mut self, actions: Vec<AnalyticsAction>) {
        for action in actions {
            match action {
                AnalyticsAction::SelectScope(scope) => {
                    self.analytics_selection.scope = Some(scope);
                    self.request_refresh_for(Tab::Analytics);
                }
                AnalyticsAction::SelectSession(session_id) => {
                    self.analytics_selection.session_id = session_id;
                    self.request_refresh_for(Tab::Analytics);
                }
                AnalyticsAction::SetOverlayEnabled(enabled) => {
                    self.sphere_notice =
                        Some(match (self.host.write_sphere_overlay_enabled)(enabled) {
                            Ok(()) => (
                                false,
                                if enabled {
                                    tabs::analytics::OVERLAY_ON_NOTICE
                                } else {
                                    tabs::analytics::OVERLAY_OFF_NOTICE
                                }
                                .to_string(),
                            ),
                            Err(error) => (
                                true,
                                format!(
                                    "Couldn't change the sphere-names setting. Technical \
                                     detail: {error}"
                                ),
                            ),
                        });
                    self.request_refresh_for(Tab::Analytics);
                }
                AnalyticsAction::SaveAlias { token, name } => {
                    let mut updated = self.current_aliases();
                    updated.insert((self.host.casefold_token)(&token), name.clone());
                    self.sphere_notice = Some(match (self.host.write_sphere_aliases)(&updated) {
                        Ok(()) => (
                            false,
                            format!("Saved. \"{token}\" now shows as \"{name}\"."),
                        ),
                        Err(error) => (
                            true,
                            format!("Couldn't save the name. Technical detail: {error}"),
                        ),
                    });
                    self.request_refresh_for(Tab::Analytics);
                }
                AnalyticsAction::RemoveAlias(alias_key) => {
                    let mut updated = self.current_aliases();
                    updated.remove(&alias_key);
                    if let Err(error) = (self.host.write_sphere_aliases)(&updated) {
                        self.sphere_notice = Some((
                            true,
                            format!("Couldn't remove the name. Technical detail: {error}"),
                        ));
                    }
                    self.request_refresh_for(Tab::Analytics);
                }
                AnalyticsAction::EmptyAliasRejected => {
                    self.sphere_notice =
                        Some((true, tabs::analytics::EMPTY_SPHERE_NAME_ERROR.to_string()));
                }
                AnalyticsAction::RequestRecording(candidate) => {
                    self.request_recording(&candidate);
                }
            }
        }
    }

    fn request_recording(&mut self, candidate: &PatternCandidate) {
        #[derive(serde::Serialize)]
        struct CandidatePayload<'a> {
            schema: &'a str,
            kind: &'a str,
            category: &'a str,
            title: &'a str,
            band: &'a str,
            evidence: &'a str,
            support_count: i64,
            support_sessions: i64,
            support_days: i64,
        }
        let payload = serde_json::to_string(&CandidatePayload {
            schema: "gilbreth.record_request.candidate.v1",
            kind: &candidate.kind,
            category: &candidate.category,
            title: &candidate.title,
            band: &candidate.band,
            evidence: &candidate.evidence,
            support_count: candidate.support_count,
            support_sessions: candidate.support_sessions,
            support_days: candidate.support_days,
        })
        .expect("candidate payload serializes");
        match (self.host.request_recording)(&candidate.kind, &payload) {
            Ok(request_id) => {
                let status = (self.host.record_request_status)(request_id)
                    .or_else(|| Some("requested".to_string()));
                self.record_statuses
                    .insert(record_request_key(candidate), (request_id, status));
                self.record_error = None;
            }
            Err(error) => {
                self.record_error = Some(format!(
                    "Gilbreth couldn't send that request to the tray right now. The database \
                     may be busy. Technical detail: {error}"
                ));
            }
        }
    }

    fn week_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.week else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading this week's activity…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        tabs::week::show(ui, snapshot);
    }

    fn today_body(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = &self.today else {
            ui.add_space(48.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Reading today's activity…")
                        .color(theme::GRAY)
                        .size(12.5),
                );
            });
            return;
        };
        if snapshot.db_missing {
            shell::no_database(ui, &self.host.db_path);
            return;
        }
        if let Some(error) = &self.curation_error {
            ui.label(egui::RichText::new(error).color(theme::RED).size(12.0));
        }
        let actions = tabs::today::show(ui, snapshot, &self.host.db_path);
        if actions.dismiss_welcome {
            self.dismiss_first_run_welcome();
        }
        if actions.open_privacy_controls {
            self.tab = Tab::Privacy;
            self.privacy_notice = None;
            self.advanced_privacy_notice = None;
            self.request_refresh_for(Tab::Privacy);
        }
        if !actions.curation.is_empty() {
            self.apply_curation(&actions.curation);
        }
    }

    fn dismiss_first_run_welcome(&mut self) {
        match (self.host.dismiss_first_run_welcome)() {
            Ok(()) => {
                self.first_run_welcome_dismissed_latch = true;
                if let Some(snapshot) = &mut self.today {
                    snapshot.first_run_welcome_dismissed = true;
                }
                self.curation_error = None;
                // Re-read so this viewer confirms the durable state. Other
                // concurrent viewers converge on their normal Today refresh.
                self.request_refresh_for(Tab::Today);
            }
            Err(error) => {
                self.curation_error = Some(format!(
                    "Gilbreth couldn't dismiss the welcome right now. Try again. Technical \
                     detail: {error}"
                ));
            }
        }
    }

    fn apply_curation(&mut self, actions: &[CurationAction]) {
        let Some(snapshot) = &self.today else {
            return;
        };
        let mut state = snapshot.notice_state.clone();
        for action in actions {
            match action {
                CurationAction::DismissToday(key) => {
                    state
                        .dismissed
                        .insert(key.clone(), snapshot.today_key.clone());
                }
                CurationAction::ToggleMute(key) => {
                    if !state.muted.remove(key) {
                        state.muted.insert(key.clone());
                    }
                }
                CurationAction::ToggleWatch(key) => {
                    if !state.watched.remove(key) {
                        state.watched.insert(key.clone());
                    }
                }
                CurationAction::ResetControls => {
                    // UX-30: reset clears dismissals and mutes but spares
                    // watched marks — the one intentional, sticky curation.
                    let watched = std::mem::take(&mut state.watched);
                    state = DiscoveryNoticeState {
                        watched,
                        ..DiscoveryNoticeState::default()
                    };
                }
            }
        }
        match (self.host.write_notice_state)(&state) {
            Ok(()) => {
                self.curation_error = None;
                // Reflect the new state immediately; the worker refresh
                // re-filters notices against it.
                if let Some(snapshot) = &mut self.today {
                    snapshot.notice_state = state;
                }
                self.request_refresh_for(Tab::Today);
            }
            Err(error) => self.curation_error = Some(error),
        }
    }
}

impl eframe::App for DashboardApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show_root(ui);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        save_active_tab(self.ui_state_persistence, storage, self.tab);
    }

    fn persist_egui_memory(&self) -> bool {
        self.ui_state_persistence.is_owner()
    }
}

fn save_active_tab(persistence: UiStatePersistence, storage: &mut dyn eframe::Storage, tab: Tab) {
    if persistence.is_owner() {
        eframe::set_value(storage, ACTIVE_TAB_STORAGE_KEY, &tab);
    }
}

fn restore_active_tab(
    persistence: UiStatePersistence,
    storage: Option<&dyn eframe::Storage>,
) -> Option<Tab> {
    if !persistence.is_owner() {
        return None;
    }
    storage
        .and_then(|storage| eframe::get_value::<Tab>(storage, ACTIVE_TAB_STORAGE_KEY))
        // A state file written on Windows can name a tab this platform does
        // not offer (Recordings). Fall back to the default rather than
        // opening on a tab the strip cannot show or return to.
        .filter(|tab| tab.is_available())
}

fn persistence_path(persistence: UiStatePersistence, owner_path: &Path) -> PathBuf {
    match persistence {
        UiStatePersistence::Owner => owner_path.to_path_buf(),
        // eframe 0.35 treats `None` as its default app-data path. An explicit
        // empty path instead loads no state and cannot name a durable file;
        // all three eframe save lanes are disabled for this mode as well.
        UiStatePersistence::Secondary => PathBuf::new(),
    }
}

/// Open the dashboard window and run until it closes.
pub fn run_dashboard(host: DashboardHost) -> eframe::Result {
    let ui_state_persistence = host.ui_state_persistence;
    let host = Arc::new(host);
    // UX-24: the floor must fit a 1366x768 panel at 125% scaling
    // (1092x614 logical); the reflow pass (UX-21/22/23) keeps layouts
    // usable down to this size.
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Gilbreth")
        .with_inner_size([1180.0, 960.0])
        .with_min_inner_size([720.0, 560.0]);
    if let Some((width, height, rgba)) = host.window_icon.clone() {
        viewport = viewport.with_icon(Arc::new(egui::IconData {
            rgba,
            width,
            height,
        }));
    }
    let options = eframe::NativeOptions {
        viewport,
        persist_window: ui_state_persistence.is_owner(),
        persistence_path: Some(persistence_path(ui_state_persistence, &host.ui_state_path)),
        ..Default::default()
    };
    eframe::run_native(
        "gilbreth-dashboard",
        options,
        Box::new(move |cc| {
            let restored_tab = restore_active_tab(ui_state_persistence, cc.storage);
            Ok(Box::new(DashboardApp::new(
                host,
                cc.egui_ctx.clone(),
                restored_tab,
            )))
        }),
    )
}

#[cfg(test)]
mod persistence_tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct MemoryStorage {
        values: HashMap<String, String>,
        reads: Cell<usize>,
        writes: usize,
    }

    impl eframe::Storage for MemoryStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.reads.set(self.reads.get() + 1);
            self.values.get(key).cloned()
        }

        fn set_string(&mut self, key: &str, value: String) {
            self.writes += 1;
            self.values.insert(key.to_string(), value);
        }

        fn remove_string(&mut self, key: &str) {
            self.values.remove(key);
        }

        fn flush(&mut self) {}
    }

    #[test]
    fn owner_restores_and_saves_active_tab_at_the_durable_path() {
        let durable_path = Path::new("dashboard-ui.ron");
        let mut storage = MemoryStorage::default();
        eframe::set_value(&mut storage, ACTIVE_TAB_STORAGE_KEY, &Tab::Week);
        storage.writes = 0;

        assert_eq!(
            persistence_path(UiStatePersistence::Owner, durable_path),
            durable_path
        );
        assert_eq!(
            restore_active_tab(UiStatePersistence::Owner, Some(&storage)),
            Some(Tab::Week)
        );
        save_active_tab(UiStatePersistence::Owner, &mut storage, Tab::Privacy);
        assert_eq!(storage.writes, 1);
        assert_eq!(
            eframe::get_value::<Tab>(&storage, ACTIVE_TAB_STORAGE_KEY),
            Some(Tab::Privacy)
        );
    }

    #[test]
    fn secondary_neither_restores_nor_saves_and_uses_no_path() {
        let mut storage = MemoryStorage::default();
        eframe::set_value(&mut storage, ACTIVE_TAB_STORAGE_KEY, &Tab::Week);
        storage.reads.set(0);
        storage.writes = 0;

        assert_eq!(
            persistence_path(UiStatePersistence::Secondary, Path::new("dashboard-ui.ron")),
            PathBuf::new()
        );
        assert_eq!(
            restore_active_tab(UiStatePersistence::Secondary, Some(&storage)),
            None
        );
        save_active_tab(UiStatePersistence::Secondary, &mut storage, Tab::Privacy);
        assert_eq!(storage.reads.get(), 0);
        assert_eq!(storage.writes, 0);
        assert!(!UiStatePersistence::Secondary.is_owner());
    }
}
