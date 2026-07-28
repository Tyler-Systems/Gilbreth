//! kittest coverage for the S4 shell: DASH-03 states, tab strip, Today
//! content, and notice curation through the host boundary. Queries run
//! against the AccessKit tree, so every assertion here also proves the
//! element is exposed to assistive tech.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use egui_kittest::kittest::{By, Queryable};
use egui_kittest::Harness;
// Portable archive export is Windows-only (owner decision 2026-07-19).
use gilbreth_dashboard::data::{
    AnalyticsData, AnalyticsSnapshot, ContinuityReport, DashboardHost, DiagnosticsSnapshot,
    EventsDeleteOutcome, LogReview, PrivacySettingsValues, PrivacySettingsView, PrivacySnapshot,
    PruneOutcome, PrunePreview, RecordingDeleteOutcome, RecordingsSnapshot, ScopeKey,
    SessionEventsSnapshot, SessionOption, SessionSnapshot, TodaySnapshot, UiStatePersistence,
    WeekSnapshot,
};
#[cfg(windows)]
use gilbreth_dashboard::data::{PortableArchiveExportMode, PortableArchiveSource};
// Record Routine is Windows-only by decision record, so the fixtures that
// build recording detail rows only compile there.
#[cfg(windows)]
use gilbreth_dashboard::data::RecordingDetail;
use gilbreth_dashboard::shell;
use gilbreth_dashboard::DashboardApp;
#[cfg(windows)]
use gilbreth_read::{recording_replay_verdict, RecordingExportStep, RecordingRow, RecordingStep};
use gilbreth_read::{
    AppDwell, DatabaseCounts, DatabaseHealth, DayActive, DayStrip, DayStripBand, DebugLogSnapshot,
    DebugSourceCount, DigestChange, DigestTopApp, DiscoveryNotice, DiscoveryNoticeEvidence,
    DiscoveryNoticeState, FirstAfterIdle, FocusRollupRow, FragmentationBreakdownRow,
    FragmentationMetrics, HeatmapBucket, HourPulse, InputExposureBreakdown, InputExposureMetrics,
    InputRollupRow, InterruptionCosts, InterruptionPair, PatternCandidate, ProcessChurnReport,
    ProcessChurnTopRow, RhythmMetrics, SessionAnalyticsRow, SphereAppRollup, SphereOverlay,
    SphereRollup, SphereSkeleton, TodayStory, WeeklyDigest, WindowLifecycleRow, WorkEpisode,
};

const HOUR_MS: i64 = 3_600_000;
/// 2026-07-09 00:00 in this project's home timezone (AKDT, UTC-8), so the
/// visual snapshots show wall-clock-aligned hours on the dev machine.
const DAY_START: i64 = 1_783_584_000_000;

type WrittenStates = Arc<Mutex<Vec<DiscoveryNoticeState>>>;

/// (record_session_id, mode, sorted labels).
type ExportSaveRecord = (i64, String, Vec<(i64, String)>);

/// Everything the stub host records for assertions.
#[derive(Default)]
struct HostWrites {
    welcome_dismissals: usize,
    notice_states: Vec<DiscoveryNoticeState>,
    overlay_toggles: Vec<bool>,
    alias_writes: Vec<BTreeMap<String, String>>,
    record_requests: Vec<(String, String)>,
    export_saves: Vec<ExportSaveRecord>,
    #[cfg(windows)]
    portable_archive_exports: Vec<(String, PortableArchiveExportMode)>,
    recording_deletes: Vec<i64>,
    event_deletes: Vec<Vec<i64>>,
    prune_calls: Vec<i64>,
    settings_writes: Vec<PrivacySettingsValues>,
    permission_actions: Vec<gilbreth_dashboard::data::PermissionActionRequest>,
}

type SharedWrites = Arc<Mutex<HostWrites>>;

#[derive(Default)]
struct MemoryStorage(HashMap<String, String>);

impl eframe::Storage for MemoryStorage {
    fn get_string(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }

    fn set_string(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }

    fn remove_string(&mut self, key: &str) {
        self.0.remove(key);
    }

    fn flush(&mut self) {}
}

fn stub_host_recording(writes: SharedWrites) -> DashboardHost {
    let welcome_writes = writes.clone();
    let notice_writes = writes.clone();
    let overlay_writes = writes.clone();
    let alias_writes = writes.clone();
    let record_writes = writes.clone();
    let export_writes = writes.clone();
    #[cfg(windows)]
    let portable_export_writes = writes.clone();
    let delete_writes = writes.clone();
    let event_delete_writes = writes.clone();
    let prune_writes = writes.clone();
    let settings_writes = writes.clone();
    DashboardHost {
        config_path: std::path::PathBuf::from("Z:/nonexistent/config.toml"),
        db_path: std::path::PathBuf::from("Z:/nonexistent/gilbreth.db"),
        ui_state_path: std::env::temp_dir().join("gilbreth-dashboard-test-ui.ron"),
        ui_state_persistence: UiStatePersistence::Owner,
        window_icon: None,
        store_key_content: Box::new(|| false),
        read_first_run_welcome_dismissed: Box::new(|| true),
        dismiss_first_run_welcome: Box::new(move || {
            welcome_writes.lock().unwrap().welcome_dismissals += 1;
            Ok(())
        }),
        read_notice_state: Box::new(DiscoveryNoticeState::default),
        write_notice_state: Box::new(move |state| {
            notice_writes
                .lock()
                .unwrap()
                .notice_states
                .push(state.clone());
            Ok(())
        }),
        read_sphere_overlay_enabled: Box::new(|| false),
        write_sphere_overlay_enabled: Box::new(move |enabled| {
            overlay_writes.lock().unwrap().overlay_toggles.push(enabled);
            Ok(())
        }),
        read_sphere_aliases: Box::new(BTreeMap::new),
        write_sphere_aliases: Box::new(move |aliases| {
            alias_writes
                .lock()
                .unwrap()
                .alias_writes
                .push(aliases.clone());
            Ok(())
        }),
        prune_sphere_aliases: Box::new(|_| Ok(BTreeMap::new())),
        request_recording: Box::new(move |kind, payload| {
            record_writes
                .lock()
                .unwrap()
                .record_requests
                .push((kind.to_string(), payload.to_string()));
            Ok(41)
        }),
        record_request_status: Box::new(|_| Some("requested".to_string())),
        spheres_sidecar_name: "spheres.json".to_string(),
        casefold_token: Box::new(|token| token.trim().to_lowercase()),
        verified_framework_classes: Box::new(|| HashSet::from(["native".to_string()])),
        save_replay_export: Box::new(move |record_session_id, mode, labels| {
            let mut sorted: Vec<(i64, String)> = labels
                .iter()
                .map(|(seq, label)| (*seq, label.clone()))
                .collect();
            sorted.sort();
            export_writes.lock().unwrap().export_saves.push((
                record_session_id,
                mode.to_string(),
                sorted,
            ));
            Ok(format!(
                "C:\\stub\\Downloads\\{}",
                gilbreth_read::replay_export_filename(record_session_id, mode)
            ))
        }),
        #[cfg(windows)]
        list_portable_archive_sources: Box::new(|| Ok(Vec::new())),
        #[cfg(windows)]
        export_portable_archive: Box::new(move |source, mode| {
            portable_export_writes
                .lock()
                .unwrap()
                .portable_archive_exports
                .push((source.to_string(), mode.clone()));
            Ok("C:\\stub\\Downloads\\portable.gla".to_string())
        }),
        delete_recording: Box::new(move |record_session_id| {
            delete_writes
                .lock()
                .unwrap()
                .recording_deletes
                .push(record_session_id);
            Ok(RecordingDeleteOutcome {
                deleted: 1,
                scrub_warning: None,
            })
        }),
        delete_events: Box::new(move |event_ids| {
            event_delete_writes
                .lock()
                .unwrap()
                .event_deletes
                .push(event_ids.to_vec());
            Ok(EventsDeleteOutcome {
                deleted: event_ids.len(),
                scrub_warning: None,
            })
        }),
        read_privacy_settings: Box::new(PrivacySettingsView::default),
        write_privacy_settings: Box::new(move |values| {
            settings_writes
                .lock()
                .unwrap()
                .settings_writes
                .push(values.clone());
            Ok(())
        }),
        read_retention_days: Box::new(|| 90),
        prune_preview: Box::new(|cutoff_ms| {
            Ok(PrunePreview {
                cutoff_ms,
                events: 0,
                ended_empty_sessions: 0,
                action_events: 0,
                ended_empty_record_sessions: 0,
                record_requests: 0,
                selector_paths: 0,
            })
        }),
        prune_old_events: Box::new(move |cutoff_ms| {
            prune_writes.lock().unwrap().prune_calls.push(cutoff_ms);
            Ok(PruneOutcome {
                events_deleted: 4200,
                sessions_deleted: 3,
                action_events_deleted: 12,
                record_sessions_deleted: 1,
                record_requests_deleted: 2,
                selector_paths_deleted: 5,
                compaction_completed: true,
                compact_error: None,
            })
        }),
        autostart_command: Box::new(|| (None, None)),
        archive_count: Box::new(|| 2),
        read_legacy_plaintext_archive_count: Box::new(|| Ok(3)),
        review_logs: Box::new(|_, _| LogReview::default()),
        read_permission_snapshot: Box::new(|| None),
        read_pause_hotkey_warning: Box::new(|| None),
        read_notification_access: Box::new(|| None),
        request_permission_action: {
            let action_writes = writes.clone();
            Box::new(move |action| {
                action_writes
                    .lock()
                    .expect("writes lock")
                    .permission_actions
                    .push(action);
            })
        },
        clock: Box::new(gilbreth_dashboard::data::now_ms),
    }
}

fn stub_host(written: WrittenStates) -> DashboardHost {
    let writes: SharedWrites = Arc::default();
    let mut host = stub_host_recording(writes);
    host.write_notice_state = Box::new(move |state| {
        written.lock().unwrap().push(state.clone());
        Ok(())
    });
    host
}

fn app_with_ui_state_persistence(persistence: UiStatePersistence) -> DashboardApp {
    let mut host = stub_host_recording(Arc::default());
    host.ui_state_persistence = persistence;
    DashboardApp::new_for_tests(
        Arc::new(host),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

#[test]
fn secondary_viewer_disables_app_and_egui_memory_persistence() {
    let mut owner = app_with_ui_state_persistence(UiStatePersistence::Owner);
    let mut owner_storage = MemoryStorage::default();
    eframe::App::save(&mut owner, &mut owner_storage);
    assert!(eframe::App::persist_egui_memory(&owner));
    assert!(owner_storage.0.contains_key("active-tab"));

    let mut secondary = app_with_ui_state_persistence(UiStatePersistence::Secondary);
    let mut secondary_storage = MemoryStorage::default();
    eframe::App::save(&mut secondary, &mut secondary_storage);
    assert!(!eframe::App::persist_egui_memory(&secondary));
    assert!(secondary_storage.0.is_empty());
}

fn empty_snapshot() -> TodaySnapshot {
    let mut snapshot = rich_snapshot();
    snapshot.db_missing = true;
    snapshot.strip.focus.clear();
    snapshot.strip.away.clear();
    snapshot.pulse.clear();
    snapshot.daily.clear();
    snapshot.notices.clear();
    snapshot
}

fn band(app: &str, start_hour_ms: i64, end_hour_ms: i64) -> DayStripBand {
    DayStripBand {
        app: app.to_string(),
        start_ts: DAY_START + start_hour_ms,
        end_ts: DAY_START + end_hour_ms,
    }
}

fn rich_snapshot() -> TodaySnapshot {
    let now_ms = DAY_START + 17 * HOUR_MS + 24 * 60_000;
    let focus = vec![
        band("mail.exe", (65 * HOUR_MS) / 10, 8 * HOUR_MS),
        band(
            "studio.exe",
            8 * HOUR_MS + 12 * 60_000,
            (107 * HOUR_MS) / 10,
        ),
        band("chat.exe", (107 * HOUR_MS) / 10, 11 * HOUR_MS),
        band("studio.exe", 11 * HOUR_MS, (125 * HOUR_MS) / 10),
        band("browser.exe", (132 * HOUR_MS) / 10, (155 * HOUR_MS) / 10),
        band(
            "studio.exe",
            (156 * HOUR_MS) / 10,
            17 * HOUR_MS + 24 * 60_000,
        ),
    ];
    let away = vec![
        (
            DAY_START + 8 * HOUR_MS,
            DAY_START + 8 * HOUR_MS + 12 * 60_000,
        ),
        (
            DAY_START + (125 * HOUR_MS) / 10,
            DAY_START + (132 * HOUR_MS) / 10,
        ),
    ];
    let pulse = (6..18)
        .map(|hour| HourPulse {
            hour,
            hour_start_ms: DAY_START + hour * HOUR_MS,
            key_events: 320 + (hour % 5) * 410,
            mouse_events: 150 + (hour % 3) * 260,
        })
        .collect();
    let daily = (0..7)
        .map(|day| DayActive {
            local_date: format!("2026-07-{:02}", 3 + day),
            day_label: ["Fri", "Sat", "Sun", "Mon", "Tue", "Wed", "Thu"][day as usize].to_string(),
            active_minutes: [312.0, 44.0, 12.0, 388.0, 402.0, 351.0, 294.0][day as usize],
        })
        .collect();
    let notices = vec![
        DiscoveryNotice {
            notice_key: "return_toll:studio.exe".to_string(),
            notice_type: "return_toll".to_string(),
            title: "Returning to studio.exe has a toll".to_string(),
            summary: "7 returns to studio.exe today; the median restart took 4m 10s before \
                      sustained input resumed."
                .to_string(),
            support_count: 7,
            sort_score: 1740.0,
            evidence: vec![
                DiscoveryNoticeEvidence {
                    occurred_at_ms: DAY_START + 9 * HOUR_MS + 41 * 60_000,
                    path: vec!["chat.exe".to_string(), "studio.exe".to_string()],
                    duration_ms: Some(460_000),
                    away_ms: Some(1_260_000),
                    restart_ms: Some(250_000),
                    input_events: None,
                    switch_count: Some(4),
                    rate: None,
                    note: String::new(),
                },
                DiscoveryNoticeEvidence {
                    occurred_at_ms: DAY_START + 14 * HOUR_MS + 3 * 60_000,
                    path: vec!["browser.exe".to_string(), "studio.exe".to_string()],
                    duration_ms: Some(380_000),
                    away_ms: Some(2_520_000),
                    restart_ms: Some(310_000),
                    input_events: None,
                    switch_count: Some(3),
                    rate: None,
                    note: String::new(),
                },
            ],
            detail: "Estimated 29m of restart toll across today's returns.".to_string(),
            baseline: "Recent p75 restart: 3m 40s.".to_string(),
            total_count: 7,
            median_restart_seconds: Some(250.0),
            estimated_restart_minutes: Some(29.0),
        },
        DiscoveryNotice {
            notice_key: "clipboard_bridge:browser.exe->studio.exe".to_string(),
            notice_type: "clipboard_bridge".to_string(),
            title: "Clipboard bridge: browser.exe to studio.exe".to_string(),
            summary: "12 copy-then-switch handoffs from browser.exe into studio.exe today."
                .to_string(),
            support_count: 12,
            sort_score: 1320.0,
            evidence: vec![DiscoveryNoticeEvidence {
                occurred_at_ms: DAY_START + 15 * HOUR_MS,
                path: vec!["browser.exe".to_string(), "studio.exe".to_string()],
                duration_ms: None,
                away_ms: None,
                restart_ms: None,
                input_events: Some(12),
                switch_count: None,
                rate: None,
                note: "medium handoffs".to_string(),
            }],
            detail: String::new(),
            baseline: String::new(),
            total_count: 12,
            median_restart_seconds: None,
            estimated_restart_minutes: None,
        },
    ];
    TodaySnapshot {
        generated_at_ms: now_ms,
        today_key: "2026-07-09".to_string(),
        db_missing: false,
        counts: DatabaseCounts {
            sessions: 14,
            events: 128_411,
            active_sessions: 1,
        },
        strip: DayStrip {
            day_start_ms: DAY_START,
            day_end_ms: now_ms,
            focus,
            away,
        },
        story: TodayStory {
            active_ms: 6 * HOUR_MS + 42 * 60_000,
            foreground_ms: 9 * HOUR_MS + 5 * 60_000,
            focus_switches: 214,
            keystrokes: 18_402,
            top_app: Some("studio.exe".to_string()),
            longest_run_app: Some("studio.exe".to_string()),
            longest_run_ms: HOUR_MS + 34 * 60_000,
            longest_run_start_ms: Some(DAY_START + 11 * HOUR_MS),
        },
        pulse,
        daily,
        notices,
        hidden_notice_count: 0,
        notice_state: DiscoveryNoticeState::default(),
        pattern_history_days: 9,
        store_key_content: false,
        first_run_welcome_dismissed: true,
        error: None,
    }
}

fn first_run_snapshot() -> TodaySnapshot {
    let mut snapshot = rich_snapshot();
    snapshot.counts = DatabaseCounts {
        sessions: 0,
        events: 0,
        active_sessions: 0,
    };
    snapshot.strip.focus.clear();
    snapshot.strip.away.clear();
    snapshot.story = TodayStory {
        active_ms: 0,
        foreground_ms: 0,
        focus_switches: 0,
        keystrokes: 0,
        top_app: None,
        longest_run_app: None,
        longest_run_ms: 0,
        longest_run_start_ms: None,
    };
    snapshot.pulse.clear();
    snapshot.daily.clear();
    snapshot.notices.clear();
    snapshot.hidden_notice_count = 0;
    snapshot.pattern_history_days = 0;
    snapshot.first_run_welcome_dismissed = false;
    snapshot
}

const DAY_MS: i64 = 24 * HOUR_MS;

fn heat_bucket(weekday: i64, hour: i64, active_minutes: f64) -> HeatmapBucket {
    HeatmapBucket {
        weekday,
        weekday_label: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][weekday as usize]
            .to_string(),
        hour,
        active_minutes,
    }
}

fn rich_week_snapshot() -> WeekSnapshot {
    let now_ms = DAY_START + 17 * HOUR_MS + 24 * 60_000;
    let mut heatmap = Vec::new();
    for weekday in 0..6_i64 {
        for hour in 7..19_i64 {
            let minutes = ((weekday * 7 + hour * 3) % 47) as f64
                + if hour == 10 || hour == 14 { 13.0 } else { 0.0 };
            heatmap.push(heat_bucket(weekday, hour, minutes));
        }
    }
    WeekSnapshot {
        generated_at_ms: now_ms,
        db_missing: false,
        digest: WeeklyDigest {
            week_start_ms: now_ms - 7 * DAY_MS,
            now_ms,
            has_prior_week: true,
            active_ms: 15 * HOUR_MS,
            prior_active_ms: 10 * HOUR_MS,
            active_days: 6,
            top_apps: vec![
                DigestTopApp {
                    app: "studio.exe".to_string(),
                    active_ms: 6 * HOUR_MS + 12 * 60_000,
                },
                DigestTopApp {
                    app: "browser.exe".to_string(),
                    active_ms: 3 * HOUR_MS + 40 * 60_000,
                },
                DigestTopApp {
                    app: "mail.exe".to_string(),
                    active_ms: 2 * HOUR_MS + 5 * 60_000,
                },
                DigestTopApp {
                    app: "chat.exe".to_string(),
                    active_ms: HOUR_MS + 21 * 60_000,
                },
            ],
            switches_per_active_hour: Some(14.2),
            prior_switches_per_active_hour: Some(16.0),
            keystrokes: 84_312,
            prior_keystrokes: 70_260,
            friction: vec![PatternCandidate {
                category: "sequence".to_string(),
                band: "Medium".to_string(),
                title: "browser.exe → studio.exe → chat.exe".to_string(),
                evidence: "18 occurrences across 3 days; median step 42s.".to_string(),
                why: "Repeated tight sequences can point to a manual routine.".to_string(),
                suggested_next_step: "If this is one task, a shortcut or macro may remove the \
                                      shuffle."
                    .to_string(),
                support_count: 18,
                support_sessions: 3,
                support_days: 3,
                kind: "automatable_routine".to_string(),
                dedup_apps: vec![
                    "browser.exe".to_string(),
                    "chat.exe".to_string(),
                    "studio.exe".to_string(),
                ],
                sort_score: 120.0,
            }],
            morning_launch: vec![
                "mail.exe".to_string(),
                "studio.exe".to_string(),
                "browser.exe".to_string(),
            ],
            morning_launch_days: 5,
            first_after_idle: vec![
                FirstAfterIdle {
                    app: "studio.exe".to_string(),
                    count: 4,
                },
                FirstAfterIdle {
                    app: "chat.exe".to_string(),
                    count: 2,
                },
            ],
            heatmap,
            changed_this_week: vec![
                DigestChange {
                    direction: "new".to_string(),
                    app: "mail.exe".to_string(),
                    evidence: "a mail.exe ↔ studio.exe pattern (9 occurrences across 3 days)"
                        .to_string(),
                    support: 9,
                    days: 3,
                },
                DigestChange {
                    direction: "quieter".to_string(),
                    app: "ledger.exe".to_string(),
                    evidence: "ledger.exe patterns (4 active days in the prior three weeks, \
                               none this week)"
                        .to_string(),
                    support: 11,
                    days: 4,
                },
            ],
        },
        error: None,
    }
}

/// One active day, no prior week, nothing mined yet.
fn sparse_week_snapshot() -> WeekSnapshot {
    let mut snapshot = rich_week_snapshot();
    snapshot.digest.has_prior_week = false;
    snapshot.digest.prior_active_ms = 0;
    snapshot.digest.prior_keystrokes = 0;
    snapshot.digest.prior_switches_per_active_hour = None;
    snapshot.digest.friction.clear();
    snapshot.digest.changed_this_week.clear();
    snapshot.digest.active_days = 1;
    snapshot
}

fn routine_candidate() -> PatternCandidate {
    PatternCandidate {
        category: "sequence".to_string(),
        band: "High".to_string(),
        title: "browser.exe → studio.exe → chat.exe".to_string(),
        evidence: "24 occurrences across 4 days; median step 38s.".to_string(),
        why: "Repeated tight sequences can point to a manual routine.".to_string(),
        suggested_next_step: "If this is one task, a shortcut or macro may remove the shuffle."
            .to_string(),
        support_count: 24,
        support_sessions: 5,
        support_days: 4,
        kind: "automatable_routine".to_string(),
        dedup_apps: vec![
            "browser.exe".to_string(),
            "chat.exe".to_string(),
            "studio.exe".to_string(),
        ],
        sort_score: 210.0,
    }
}

fn work_episode(start_hour: i64, active_minutes: i64, switches: i64) -> WorkEpisode {
    WorkEpisode {
        start_ms: DAY_START + start_hour * HOUR_MS,
        end_ms: DAY_START + start_hour * HOUR_MS + active_minutes * 60_000,
        active_ms: active_minutes * 60_000,
        apps: vec![
            AppDwell {
                app: "studio.exe".to_string(),
                active_ms: active_minutes * 40_000,
            },
            AppDwell {
                app: "browser.exe".to_string(),
                active_ms: active_minutes * 20_000,
            },
        ],
        dominant_app: "studio.exe".to_string(),
        switch_count: switches,
        local_date: "2026-07-09".to_string(),
        sphere: Some("gilbreth".to_string()),
    }
}

fn rich_analytics_snapshot() -> AnalyticsSnapshot {
    let now_ms = DAY_START + 17 * HOUR_MS;
    let heatmap = (0..5_i64)
        .flat_map(|weekday| {
            (8..18_i64).map(move |hour| HeatmapBucket {
                weekday,
                weekday_label: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][weekday as usize]
                    .to_string(),
                hour,
                active_minutes: ((weekday * 11 + hour * 5) % 43) as f64,
            })
        })
        .collect();
    let mut fragmentation_candidate = routine_candidate();
    fragmentation_candidate.category = "fragmentation_anchor".to_string();
    fragmentation_candidate.band = "Medium".to_string();
    fragmentation_candidate.title = "You keep leaving and returning to studio.exe".to_string();
    fragmentation_candidate.kind = "fragmentation".to_string();
    fragmentation_candidate.sort_score = 0.0;
    // Five weaker sequence variants: the strip fills to its 6-card limit and
    // the last variant lands in the "All patterns in scope" remainder.
    let runner_ups: Vec<PatternCandidate> = (0..5)
        .map(|index| {
            let mut runner_up = routine_candidate();
            runner_up.band = "Medium".to_string();
            runner_up.title = format!("mail.exe → studio.exe (variant {index})");
            runner_up.support_count = 9 - index;
            runner_up.sort_score = 40.0 - index as f64;
            runner_up.dedup_apps = vec!["mail.exe".to_string(), "studio.exe".to_string()];
            runner_up
        })
        .collect();
    AnalyticsSnapshot {
        generated_at_ms: now_ms,
        db_missing: false,
        error: None,
        scope: ScopeKey::Last7d,
        fallback_from: None,
        session_id: None,
        data: Some(AnalyticsData {
            session_options: vec![
                SessionOption {
                    session_id: 16,
                    label: "Session 16: 2026-07-09 08:01 [5edc2cb4eb2d]".to_string(),
                },
                SessionOption {
                    session_id: 15,
                    label: "Session 15: 2026-07-08 09:12 [f2aaab7d91c0]".to_string(),
                },
            ],
            focus: vec![
                FocusRollupRow {
                    app: "studio.exe".to_string(),
                    exe: "studio.exe".to_string(),
                    focus_minutes: 312.4,
                    active_foreground_minutes: 268.9,
                    focus_switches: 141,
                    avg_dwell_seconds: 132.94,
                    support_sessions: 5,
                    support_days: 4,
                },
                FocusRollupRow {
                    app: "browser.exe".to_string(),
                    exe: "browser.exe".to_string(),
                    focus_minutes: 187.2,
                    active_foreground_minutes: 121.0,
                    focus_switches: 168,
                    avg_dwell_seconds: 66.86,
                    support_sessions: 5,
                    support_days: 4,
                },
            ],
            focus_minutes_total: 566.3,
            active_focus_minutes_total: 447.6,
            sessions: vec![
                SessionAnalyticsRow {
                    session_id: 16,
                    started_at: "2026-07-09 08:01:12".to_string(),
                    ended_at: None,
                    event_count: 48_211,
                    active_foreground_minutes: 240.5,
                    active_span_minutes: 545.0,
                    idle_events: 14,
                    active_events: 14,
                    idle_minutes: 88.2,
                },
                SessionAnalyticsRow {
                    session_id: 15,
                    started_at: "2026-07-08 09:12:44".to_string(),
                    ended_at: Some("2026-07-08 18:20:03".to_string()),
                    event_count: 80_144,
                    active_foreground_minutes: 207.1,
                    active_span_minutes: 547.3,
                    idle_events: 21,
                    active_events: 21,
                    idle_minutes: 130.6,
                },
            ],
            inputs: vec![InputRollupRow {
                app: "studio.exe".to_string(),
                exe: "studio.exe".to_string(),
                key_events: 61_420,
                ctrl_rate: 0.09,
                alt_rate: 0.02,
                shift_rate: 0.11,
                win_rate: 0.0,
                mouse_clicks: 8_204,
                mouse_moves: 141_202,
                mouse_wheels: 4_180,
                remote_relay_suspected_events: 12,
                total_input_events: 215_006,
            }],
            lifecycle: vec![WindowLifecycleRow {
                app: "browser.exe".to_string(),
                exe: "browser.exe".to_string(),
                opened_windows: 44,
                closed_windows: 39,
                median_open_seconds: 418.2,
                avg_open_seconds: 1_202.9,
                support_sessions: 5,
                support_days: 4,
            }],
            candidates: [routine_candidate(), fragmentation_candidate]
                .into_iter()
                .chain(runner_ups)
                .collect(),
            pattern_history_days: 9,
            fragmentation: FragmentationMetrics {
                active_minutes: 447.6,
                same_app_focus_runs: 220,
                median_same_app_run_minutes: Some(1.4),
                median_sustained_focus_run_minutes: Some(2.9),
                sustained_switches: 96,
                sustained_switches_per_active_hour: Some(12.87),
                anchor_returns: 18,
                median_active_diversion_minutes: Some(3.2),
                median_resumption_lag_seconds: Some(6.4),
                breakdown: vec![FragmentationBreakdownRow {
                    app: "studio.exe".to_string(),
                    active_minutes: 268.9,
                    same_app_focus_runs: 88,
                    median_run_minutes: Some(2.1),
                    sustained_switches_per_active_hour: Some(9.6),
                    anchor_returns: 18,
                    median_active_diversion_minutes: Some(3.2),
                    median_intervening_app_focus_segments: Some(1.0),
                    median_resumption_lag_seconds: Some(6.4),
                }],
            },
            interruption: InterruptionCosts {
                total_roundtrips: 42,
                measured_restarts: 31,
                median_restart_seconds: Some(7.2),
                estimated_restart_minutes: Some(5.0),
                total_away_minutes: 96.4,
                pairs: vec![InterruptionPair {
                    diverter: "chat.exe".to_string(),
                    anchor: "studio.exe".to_string(),
                    count: 12,
                    days: 4,
                    median_away_minutes: Some(2.4),
                    median_restart_seconds: Some(6.8),
                    estimated_restart_minutes: Some(1.4),
                }],
            },
            input_exposure: InputExposureMetrics {
                active_input_minutes_total: 402.4,
                active_input_minutes_per_day: Some(100.6),
                day_band: Some("normal".to_string()),
                longest_run_minutes: Some(48.2),
                runs_over_break_target: 3,
                input_events_per_active_hour: Some(9_412.0),
                total_input_events: 215_006,
                has_sustained_input: true,
                breakdown: vec![InputExposureBreakdown {
                    app: "studio.exe".to_string(),
                    active_input_minutes: 311.0,
                    keystrokes_per_hour: Some(8_204.2),
                    clicks_per_hour: Some(911.4),
                    moves_per_hour: Some(18_211.0),
                    scrolls_per_hour: Some(402.1),
                    total_input_events: 215_006,
                }],
            },
            spheres: SphereSkeleton {
                episodes: vec![work_episode(8, 92, 24), work_episode(13, 45, 9)],
                app_rollup: vec![SphereAppRollup {
                    app: "studio.exe".to_string(),
                    episode_count: 2,
                    active_ms: 137 * 60_000,
                    days: 1,
                }],
                total_active_ms: 137 * 60_000,
                median_episode_ms: Some(68 * 60_000 + 30_000),
            },
            sphere_overlay: None,
            rhythm: RhythmMetrics {
                heatmap,
                typing_burst_wpm_median: Some(64.0),
                typing_burst_wpm_p90: Some(92.0),
                typing_burst_count: 812,
                typing_classified_fraction: Some(0.97),
                mouse_velocity_median_px_s: Some(1_240.0),
                mouse_velocity_p90_px_s: Some(3_212.0),
                mouse_move_samples: 141_202,
                friction_windows: Vec::new(),
            },
            overlay_enabled: false,
            aliases: BTreeMap::new(),
        }),
    }
}

/// Overlay mode with an alias set, for the rename/merge and opt-out flows.
fn overlay_analytics_snapshot() -> AnalyticsSnapshot {
    let mut snapshot = rich_analytics_snapshot();
    let data = snapshot.data.as_mut().unwrap();
    data.overlay_enabled = true;
    data.aliases = BTreeMap::from([("gilbreth".to_string(), "Gilbreth build".to_string())]);
    data.sphere_overlay = Some(SphereOverlay {
        episodes: vec![work_episode(8, 92, 24), work_episode(13, 45, 9)],
        spheres: vec![SphereRollup {
            sphere: "Gilbreth build".to_string(),
            active_ms: 137 * 60_000,
            episode_count: 2,
            days: 1,
            tokens: vec!["gilbreth".to_string()],
        }],
        total_active_ms: 137 * 60_000,
        labeled_active_ms: 137 * 60_000,
        labeled_fraction: Some(1.0),
    });
    snapshot
}

#[cfg(windows)]
fn recording_export_step(
    seq: i64,
    action_type: &str,
    pattern_action: Option<&str>,
    selector_id: Option<i64>,
    framework_class: &str,
    trust_basis: &str,
) -> RecordingExportStep {
    RecordingExportStep {
        seq,
        ts: DAY_START + 9 * HOUR_MS + seq * 30_000,
        action_type: action_type.to_string(),
        pattern_action: pattern_action.map(str::to_string),
        selector_id,
        framework_class: framework_class.to_string(),
        trust_basis: trust_basis.to_string(),
        exe: Some("studio.exe".to_string()),
        path_hash: None,
        selector_backend: None,
        path_json: None,
        leaf_rect: None,
    }
}

#[cfg(windows)]
/// The display twin of an export step (what `read_recording_steps` yields).
fn display_step(export: &RecordingExportStep, selector: &str, coverage: &str) -> RecordingStep {
    RecordingStep {
        seq: export.seq,
        captured_at: Some(format!("2026-07-09 09:{:02}:00", export.seq)),
        action_type: export.action_type.clone(),
        pattern_action: export.pattern_action.clone(),
        selector_id: export.selector_id,
        selector: selector.to_string(),
        framework_class: export.framework_class.clone(),
        trust_basis: export.trust_basis.clone(),
        exe: export.exe.clone(),
        is_sensitive: 0,
        coverage: coverage.to_string(),
    }
}

#[cfg(windows)]
/// An ended, request-fulfilled recording with four steps.
fn ended_recording_row() -> RecordingRow {
    RecordingRow {
        record_session_id: 7,
        title: Some("Invoice sweep".to_string()),
        started_ts: DAY_START + 9 * HOUR_MS,
        ended_ts: Some(DAY_START + 9 * HOUR_MS + 30 * 60_000),
        started_at: Some("2026-07-09 09:00:00".to_string()),
        ended_at: Some("2026-07-09 09:30:00".to_string()),
        duration_ms: 30 * 60_000,
        recording_status: "Ended".to_string(),
        stop_reason: Some("user_stop".to_string()),
        stop_reason_label: "User Stop".to_string(),
        action_count: 4,
        session_id: 18,
        request_id: Some(41),
        request_status: Some("fulfilled".to_string()),
        request_requested_at: Some(DAY_START + 8 * HOUR_MS),
        request_expires_at: Some(DAY_START + 32 * HOUR_MS),
        policy_snapshot_json: r#"{"lean_capture": true, "store_key_content": false}"#.to_string(),
        pause_intervals_json: "[]".to_string(),
        safety_cap_ms: 600_000,
        visible_indicator: 1,
    }
}

#[cfg(windows)]
/// A still-open, untitled recording (stop it from the tray).
fn open_recording_row() -> RecordingRow {
    RecordingRow {
        record_session_id: 9,
        title: None,
        started_ts: DAY_START + 16 * HOUR_MS,
        ended_ts: None,
        started_at: Some("2026-07-09 16:00:00".to_string()),
        ended_at: None,
        duration_ms: 4 * 60_000,
        recording_status: "Recording...".to_string(),
        stop_reason: None,
        stop_reason_label: "Recording...".to_string(),
        action_count: 0,
        session_id: 18,
        request_id: None,
        request_status: None,
        request_requested_at: None,
        request_expires_at: None,
        policy_snapshot_json: String::new(),
        pause_intervals_json: "[]".to_string(),
        safety_cap_ms: 600_000,
        visible_indicator: 1,
    }
}

#[cfg(windows)]
/// Two recordings with the ended one selected: two native-eligible steps
/// (verified verdict, native export available), one free-input, one noise.
fn recordings_snapshot_rich() -> RecordingsSnapshot {
    let export_steps = vec![
        recording_export_step(
            1,
            "ui_action",
            Some("invoke"),
            Some(10),
            "native",
            "pid_match",
        ),
        recording_export_step(
            2,
            "ui_action",
            Some("toggle"),
            Some(11),
            "native",
            "window_ownership",
        ),
        recording_export_step(3, "edit_committed", None, None, "native", "pid_match"),
        recording_export_step(4, "ui_action_other", None, None, "unknown", "unknown"),
    ];
    let verified = HashSet::from(["native".to_string()]);
    let verdict = recording_replay_verdict(&export_steps, &verified);
    let steps = vec![
        display_step(
            &export_steps[0],
            "uia:4-deep (named)",
            "structurally observed",
        ),
        display_step(&export_steps[1], "uia:3-deep", "structurally observed"),
        display_step(&export_steps[2], "no selector", "free input (value-free)"),
        display_step(&export_steps[3], "no selector", "unmapped"),
    ];
    RecordingsSnapshot {
        generated_at_ms: DAY_START + 17 * HOUR_MS,
        db_missing: false,
        tables_present: true,
        rows: vec![open_recording_row(), ended_recording_row()],
        selected_id: Some(7),
        detail: Some(RecordingDetail { steps, verdict }),
        detail_error: None,
        error: None,
    }
}

/// A live database with prunable history: clean settings, two redaction
/// patterns, a non-empty preview, and a continuity report.
fn privacy_snapshot_rich() -> PrivacySnapshot {
    PrivacySnapshot {
        generated_at_ms: DAY_START + 17 * HOUR_MS,
        generation: 0,
        db_missing: false,
        error: None,
        counts: DatabaseCounts {
            sessions: 19,
            events: 215_006,
            active_sessions: 1,
        },
        install: Some(gilbreth_read::InstallStateSnapshot {
            db_path: "C:\\Users\\dev\\AppData\\Local\\Gilbreth\\gilbreth.db".to_string(),
            db_size_bytes: 78_643_200,
            wal_size_bytes: 1_048_576,
            open_sessions: 1,
            build_sha: Some("e2edd8ff3a9b".to_string()),
            build_source: "sessions.git_sha".to_string(),
            autostart_command: Some(
                "\"C:\\Users\\dev\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe\"".to_string(),
            ),
            autostart_path: Some(
                "C:\\Users\\dev\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe".to_string(),
            ),
            autostart_path_exists: true,
            storage_warnings: Vec::new(),
            autostart_error: None,
        }),
        settings: PrivacySettingsView {
            sensitive_context_suppression: true,
            redact_titles_containing: vec!["Bank".to_string(), "Therapy".to_string()],
            redact_keys_containing: Vec::new(),
            excluded_apps: vec!["private.exe".to_string()],
            store_key_content: false,
            title_retention_days: 0,
            mouse_move_retention_days: 30,
            error: None,
        },
        retention_days: 90,
        prune_days: 90,
        preview: Some(PrunePreview {
            cutoff_ms: DAY_START - 90 * 24 * HOUR_MS,
            events: 4200,
            ended_empty_sessions: 3,
            action_events: 12,
            ended_empty_record_sessions: 1,
            record_requests: 2,
            selector_paths: 5,
        }),
        preview_error: None,
        continuity: Some(ContinuityReport {
            active_days: 34,
            pre_week_focus_days: 27,
            weekday_label: "Wednesday".to_string(),
            same_weekday_days: 5,
            first_date: Some("2026-06-05".to_string()),
            last_date: Some("2026-07-09".to_string()),
            archive_count: 2,
        }),
        #[cfg(windows)]
        portable_archive_sources: Vec::new(),
        #[cfg(windows)]
        portable_archive_error: None,
        notification_access: None,
        sensitive_rows_this_session: Some(12),
    }
}

/// A live recorder with clean health: known log warnings only, churn with
/// one sustained exe, autostart configured.
fn diagnostics_snapshot_rich() -> DiagnosticsSnapshot {
    DiagnosticsSnapshot {
        generated_at_ms: DAY_START + 17 * HOUR_MS,
        db_missing: false,
        error: None,
        debug: Some(DebugLogSnapshot {
            session_id: Some(20),
            recording_status: "Recording".to_string(),
            started_at: Some("2026-07-09 16:00:00".to_string()),
            ended_at: None,
            latest_event_at: Some("2026-07-09 17:02:41".to_string()),
            latest_event_age_seconds: Some(14),
            event_count: 12_408,
            events_last_5m: 231,
            events_last_30m: 1_876,
            events_last_60m: 3_512,
            db_size_bytes: 78_643_200,
            wal_size_bytes: 1_048_576,
            longest_foreground_ms: Some(2_712_000),
            longest_foreground_app: Some("studio.exe".to_string()),
            longest_active_foreground_ms: Some(1_950_000),
            longest_active_foreground_app: Some("studio.exe".to_string()),
            power_sleeps: 2,
            power_boundary_catches: 1,
            capture_events_dropped: 0,
            stale_pre_erase_rows_dropped: 0,
            last_boundary_at: Some("2026-07-09 06:12:03".to_string()),
            max_modifier_run: 4,
            max_modifier_name: Some("Shift".to_string()),
            sensitive_rows: 12,
            source_counts: vec![
                DebugSourceCount {
                    source: "keyboard".to_string(),
                    events: 84_312,
                },
                DebugSourceCount {
                    source: "mouse".to_string(),
                    events: 121_004,
                },
                DebugSourceCount {
                    source: "system".to_string(),
                    events: 9_690,
                },
            ],
            warnings: Vec::new(),
        }),
        churn: Some(ProcessChurnReport {
            summaries: 61,
            dropped: 8_432,
            top: vec![
                ProcessChurnTopRow {
                    exe: "updater.exe".to_string(),
                    dropped: 5_120,
                    sustained: true,
                },
                ProcessChurnTopRow {
                    exe: "helper.exe".to_string(),
                    dropped: 3_312,
                    sustained: false,
                },
            ],
            sustained_exes: vec!["updater.exe".to_string()],
        }),
        install: Some(gilbreth_read::InstallStateSnapshot {
            db_path: "C:\\Users\\dev\\AppData\\Local\\Gilbreth\\gilbreth.db".to_string(),
            db_size_bytes: 78_643_200,
            wal_size_bytes: 1_048_576,
            open_sessions: 1,
            build_sha: Some("f763c76d0569".to_string()),
            build_source: "sessions.git_sha".to_string(),
            autostart_command: Some(
                "\"C:\\Users\\dev\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe\"".to_string(),
            ),
            autostart_path: Some(
                "C:\\Users\\dev\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe".to_string(),
            ),
            autostart_path_exists: true,
            storage_warnings: Vec::new(),
            autostart_error: None,
        }),
        health: Some(DatabaseHealth {
            integrity_check: "ok".to_string(),
            foreign_key_issues: 0,
            user_version: 9,
            seq_gap_sessions: Vec::new(),
            explained_gap_sessions: Vec::new(),
            deletion_audit_rows_deleted: Some(0),
            capture_events_dropped: 0,
            stale_pre_erase_rows_dropped: 0,
            recovered_focus_rows: 0,
            min_ts: Some(DAY_START),
            max_ts: Some(DAY_START + 17 * HOUR_MS),
        }),
        logs: Some(LogReview {
            files: 3,
            warning_lines: 2,
            error_panic_lines: 0,
            clipboard_locked_warning_lines: 1,
            orphan_session_repair_warning_lines: 1,
            stale_pre_erase_drop_warning_lines: 0,
            recovered_focus_warning_lines: 0,
            open_focus_discard_warning_lines: 0,
            max_events_skipped: 0,
        }),
        permissions: None,
        pause_hotkey_warning: None,
        excluded_apps: vec!["private.exe".to_string()],
        notification_access: None,
        legacy_plaintext_archive_count: Some(3),
        archive_inventory_error: None,
    }
}

fn session_row_fixture(
    session_id: i64,
    started_at: &str,
    ended_at: Option<&str>,
    event_count: i64,
) -> gilbreth_read::SessionRow {
    gilbreth_read::SessionRow {
        session_id,
        started_at: Some(started_at.to_string()),
        ended_at: ended_at.map(str::to_string),
        host: None,
        app_version: None,
        git_sha: None,
        run_label: None,
        event_count,
    }
}

fn focus_summary_row(
    exe: &str,
    title: Option<&str>,
    focus_seconds: f64,
    active_seconds: f64,
    switches: i64,
) -> gilbreth_read::FocusSummaryRow {
    gilbreth_read::FocusSummaryRow {
        completed_exe: exe.to_string(),
        completed_title: title.map(str::to_string),
        focus_seconds,
        active_foreground_seconds: active_seconds,
        switches,
    }
}

/// An open (selected) session with the full Overview mix, an ended
/// identity-bearing session, and an ended empty one.
fn rich_session_snapshot() -> SessionSnapshot {
    let mut identity =
        session_row_fixture(1, "2026-07-08 09:00:00", Some("2026-07-08 17:45:10"), 3401);
    identity.host = Some("DESK".to_string());
    identity.app_version = Some("0.9.0".to_string());
    identity.git_sha = Some("abcdef1234567890abcd".to_string());
    identity.run_label = Some("soak".to_string());
    SessionSnapshot {
        generated_at_ms: DAY_START + 17 * HOUR_MS,
        db_missing: false,
        error: None,
        sessions: vec![
            session_row_fixture(2, "2026-07-09 06:30:12", None, 128),
            identity,
            session_row_fixture(3, "2026-07-07 08:00:00", Some("2026-07-07 08:05:00"), 0),
        ],
        selected_session_id: Some(2),
        counts: vec![
            gilbreth_read::EventCountRow {
                source: "foreground".to_string(),
                kind: "focus_changed".to_string(),
                events: 64,
            },
            gilbreth_read::EventCountRow {
                source: "keyboard".to_string(),
                kind: "key".to_string(),
                events: 1_234,
            },
            gilbreth_read::EventCountRow {
                source: "mouse".to_string(),
                kind: "mouse_click".to_string(),
                events: 25,
            },
        ],
        focus_apps: vec![
            focus_summary_row("C:\\Apps\\studio.exe", None, 5_400.0, 4_980.5, 40),
            focus_summary_row("chat.exe", None, 1_200.0, 800.0, 24),
        ],
        focus_titles: vec![
            focus_summary_row(
                "C:\\Apps\\studio.exe",
                Some("Doc A — Studio"),
                5_400.0,
                4_980.5,
                40,
            ),
            focus_summary_row("chat.exe", Some("Team chat"), 1_200.0, 800.0, 24),
        ],
        story: gilbreth_read::SessionStoryTotals {
            top_app: Some("studio.exe".to_string()),
            top_app_active_seconds: 4_980.5,
            focus_switches: 64,
        },
        focus_seconds_total: 6_600.0,
        active_focus_seconds_total: 5_780.0,
        key_events: 1_234,
        system_events: vec![
            gilbreth_read::SystemEventRow {
                captured_at: Some("2026-07-09 07:00:00".to_string()),
                kind: "display_change".to_string(),
                title: None,
                pos_x: Some(2_560),
                pos_y: Some(1_440),
                duration_ms: Some(1_500),
                payload: Some("{}".to_string()),
            },
            gilbreth_read::SystemEventRow {
                captured_at: Some("2026-07-09 06:30:12".to_string()),
                kind: "session_start".to_string(),
                title: Some("logon".to_string()),
                pos_x: None,
                pos_y: None,
                duration_ms: None,
                payload: Some("{}".to_string()),
            },
        ],
        power_events: vec![
            gilbreth_read::PowerEventRow {
                captured_at: Some("2026-07-09 08:00:00".to_string()),
                kind: "power_suspend".to_string(),
                matched_suspend: None,
                tick_ms: Some(5_000),
                wall_gap_ms: None,
                tick_gap_ms: None,
                gap_ms: None,
                capped_dwell_ms: None,
            },
            gilbreth_read::PowerEventRow {
                captured_at: Some("2026-07-09 08:30:00".to_string()),
                kind: "power_resume".to_string(),
                matched_suspend: Some(1),
                tick_ms: Some(6_000),
                wall_gap_ms: Some(1_800_000),
                tick_gap_ms: Some(1_000),
                gap_ms: Some(1_800_000),
                capped_dwell_ms: None,
            },
        ],
    }
}

fn session_event_row(
    id: i64,
    seq: i64,
    source: &str,
    kind: &str,
) -> gilbreth_read::ActivityEventRow {
    gilbreth_read::ActivityEventRow {
        id,
        session_id: 2,
        seq,
        changed_at: Some("2026-07-09 10:15:00".to_string()),
        source: source.to_string(),
        kind: kind.to_string(),
        completed_exe: None,
        completed_title: None,
        duration_ms: None,
        exe: None,
        title: None,
        hwnd: None,
        key: None,
        mod_shift: None,
        mod_ctrl: None,
        mod_alt: None,
        mod_win: None,
        button: None,
        pos_x: None,
        pos_y: None,
        is_sensitive: 0,
        payload: Some("{}".to_string()),
    }
}

/// Three Event-list rows for the open session: a key press, a completed
/// focus dwell, and a sensitive mouse click with position data.
fn session_events_fixture() -> SessionEventsSnapshot {
    let mut key = session_event_row(101, 11, "keyboard", "key");
    key.key = Some("a".to_string());
    key.mod_shift = Some(0);
    key.mod_ctrl = Some(0);
    key.mod_alt = Some(0);
    key.mod_win = Some(0);
    let mut focus = session_event_row(102, 12, "foreground", "focus_changed");
    focus.completed_exe = Some("C:\\Apps\\studio.exe".to_string());
    focus.completed_title = Some("Doc A".to_string());
    focus.duration_ms = Some(60_000);
    focus.exe = Some("next.exe".to_string());
    let mut click = session_event_row(103, 13, "mouse", "mouse_click");
    click.exe = Some("studio.exe".to_string());
    click.button = Some("left".to_string());
    click.pos_x = Some(640);
    click.pos_y = Some(480);
    click.hwnd = Some("0x00AA12".to_string());
    click.is_sensitive = 1;
    SessionEventsSnapshot {
        generated_at_ms: DAY_START + 17 * HOUR_MS,
        session_id: 2,
        events: vec![click, focus, key],
        error: None,
    }
}

// One optional snapshot per tab — the tab set is complete, so the width
// is final.
#[allow(clippy::too_many_arguments)]
fn harness_with_host(
    host: DashboardHost,
    snapshot: Option<TodaySnapshot>,
    week: Option<WeekSnapshot>,
    session: Option<SessionSnapshot>,
    session_events: Option<SessionEventsSnapshot>,
    analytics: Option<AnalyticsSnapshot>,
    recordings: Option<RecordingsSnapshot>,
    privacy: Option<PrivacySnapshot>,
    diagnostics: Option<DiagnosticsSnapshot>,
    height: f32,
) -> Harness<'static> {
    let mut app = DashboardApp::new_for_tests(
        Arc::new(host),
        snapshot,
        week,
        session,
        session_events,
        analytics,
        recordings,
        privacy,
        diagnostics,
    );
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, height))
        .build_ui(move |ui| {
            if !styled.get() {
                // Fonts/style land at the next pass; render nothing until
                // the named Inter families are bound.
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app.show_root(ui);
        });
    harness.run();
    harness
}

fn harness_for(
    snapshot: Option<TodaySnapshot>,
    week: Option<WeekSnapshot>,
    written: WrittenStates,
) -> Harness<'static> {
    harness_for_sized(snapshot, week, written, 1600.0)
}

/// The glance harness at an explicit height: visual scenes hug their
/// content so the pinned PNG carries no dead tail.
fn harness_for_sized(
    snapshot: Option<TodaySnapshot>,
    week: Option<WeekSnapshot>,
    written: WrittenStates,
    height: f32,
) -> Harness<'static> {
    harness_with_host(
        stub_host(written),
        snapshot,
        week,
        None,
        None,
        None,
        None,
        None,
        None,
        height,
    )
}

/// Analytics content is much taller than the other tabs; give it room so
/// every AccessKit node stays inside the laid-out area.
fn analytics_harness(analytics: AnalyticsSnapshot, writes: SharedWrites) -> Harness<'static> {
    analytics_harness_sized(analytics, writes, 4200.0)
}

fn analytics_harness_sized(
    analytics: AnalyticsSnapshot,
    writes: SharedWrites,
    height: f32,
) -> Harness<'static> {
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(rich_snapshot()),
        None,
        None,
        None,
        Some(analytics),
        None,
        None,
        None,
        height,
    );
    harness.get_by_label("Analytics").click();
    harness.run();
    harness
}

/// Like `privacy_harness`, but the test keeps a handle on the app so it can
/// feed worker completions through the real adoption path (staleness races).
fn shared_privacy_harness(
    privacy: PrivacySnapshot,
    writes: SharedWrites,
) -> (Harness<'static>, Rc<RefCell<DashboardApp>>) {
    shared_privacy_harness_with_host(stub_host_recording(writes), privacy)
}

fn shared_privacy_harness_with_host(
    host: DashboardHost,
    privacy: PrivacySnapshot,
) -> (Harness<'static>, Rc<RefCell<DashboardApp>>) {
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(host),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        None,
        Some(privacy),
        None,
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, 2400.0))
        .build_ui(move |ui| {
            if !styled.get() {
                // Fonts/style land at the next pass; render nothing until
                // the named Inter families are bound.
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    harness.get_by_label("Privacy").click();
    harness.run();
    (harness, app)
}

fn privacy_harness(privacy: PrivacySnapshot, writes: SharedWrites) -> Harness<'static> {
    privacy_harness_sized(privacy, writes, 2400.0)
}

fn privacy_harness_sized(
    privacy: PrivacySnapshot,
    writes: SharedWrites,
    height: f32,
) -> Harness<'static> {
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        None,
        Some(privacy),
        None,
        height,
    );
    harness.get_by_label("Privacy").click();
    harness.run();
    harness
}

fn diagnostics_harness(diagnostics: DiagnosticsSnapshot, writes: SharedWrites) -> Harness<'static> {
    diagnostics_harness_sized(diagnostics, writes, 2400.0)
}

fn diagnostics_harness_sized(
    diagnostics: DiagnosticsSnapshot,
    writes: SharedWrites,
    height: f32,
) -> Harness<'static> {
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(diagnostics),
        height,
    );
    harness.get_by_label("Diagnostics").click();
    harness.run();
    harness
}

#[cfg(windows)]
/// The Recordings tab with a selected detail pane needs vertical room like
/// Analytics does.
fn recordings_harness(recordings: RecordingsSnapshot, writes: SharedWrites) -> Harness<'static> {
    recordings_harness_sized(recordings, writes, 3400.0)
}

#[cfg(windows)]
fn recordings_harness_sized(
    recordings: RecordingsSnapshot,
    writes: SharedWrites,
    height: f32,
) -> Harness<'static> {
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        Some(recordings),
        None,
        None,
        height,
    );
    harness.get_by_label("Recordings").click();
    harness.run();
    harness
}

/// The Session tab with a handle on the app, so tests can drain issued
/// requests (the snapshot-cadence assertions) and feed adoptions.
fn session_harness_shared(
    host: DashboardHost,
    session: Option<SessionSnapshot>,
    events: Option<SessionEventsSnapshot>,
) -> (Harness<'static>, Rc<RefCell<DashboardApp>>) {
    session_harness_shared_sized(host, session, events, 2800.0)
}

fn session_harness_shared_sized(
    host: DashboardHost,
    session: Option<SessionSnapshot>,
    events: Option<SessionEventsSnapshot>,
    height: f32,
) -> (Harness<'static>, Rc<RefCell<DashboardApp>>) {
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(host),
        Some(rich_snapshot()),
        None,
        session,
        events,
        None,
        None,
        None,
        None,
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, height))
        .build_ui(move |ui| {
            if !styled.get() {
                // Fonts/style land at the next pass; render nothing until
                // the named Inter families are bound.
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    harness.get_by_label("Session").click();
    harness.run();
    (harness, app)
}

fn session_harness(
    session: Option<SessionSnapshot>,
    events: Option<SessionEventsSnapshot>,
    writes: SharedWrites,
) -> Harness<'static> {
    session_harness_shared(stub_host_recording(writes), session, events).0
}

fn session_harness_sized(
    session: Option<SessionSnapshot>,
    events: Option<SessionEventsSnapshot>,
    writes: SharedWrites,
    height: f32,
) -> Harness<'static> {
    session_harness_shared_sized(stub_host_recording(writes), session, events, height).0
}

/// Switch a session harness to the Records lens.
fn open_event_list(harness: &mut Harness<'static>) {
    harness.get_by_label("Records").click();
    harness.run();
}

#[test]
fn no_database_state_shows_dash03_shell() {
    let written: WrittenStates = Arc::default();
    let mut snapshot = empty_snapshot();
    snapshot.first_run_welcome_dismissed = false;
    let mut harness = harness_for(Some(snapshot), None, written);
    harness.run();
    harness.get_by_label(shell::NO_DB_HEADING);
    harness.get_by_label(shell::NO_DB_BODY);
    harness.get_by_label(shell::NO_DB_WHAT_APPEARS);
    harness.get_by_label(shell::NO_DB_PRIVACY);
    assert!(harness
        .query_by_label("This dashboard reads what's captured on this machine.")
        .is_none());
    // The shell explains capture without offering to start it.
    assert!(harness.query_by_label("Start capture").is_none());
    for copy in [
        shell::NO_DB_BODY,
        shell::NO_DB_WHAT_APPEARS,
        shell::NO_DB_PRIVACY,
    ] {
        assert!(!copy.contains('—'));
        assert!(!copy.to_lowercase().contains("record"));
        assert!(!copy.to_lowercase().contains("capture is live"));
        assert!(!copy.to_lowercase().contains("capture is on"));
        assert!(!copy.to_lowercase().contains("lean capture"));
    }
}

#[test]
fn loading_state_reads_quietly_before_first_snapshot() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(None, None, written);
    harness.run();
    harness.get_by_label("Reading today's activity…");
}

#[test]
fn first_run_welcome_is_visible_for_blank_and_already_populated_today() {
    let writes: SharedWrites = Arc::default();
    let blank = harness_with_host(
        stub_host_recording(writes.clone()),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1600.0,
    );
    blank.get_by_label("This dashboard reads what's captured on this machine.");
    blank.get_by_label("Open privacy controls");
    blank.get_by_label("Dismiss");
    blank.get_by_label("Banner stays open until you dismiss it");
    blank.get_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_HEADING);
    blank.get_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_LEDE);
    blank.get_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_START);
    blank.get_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_DAY);
    blank.get_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_LOCAL);
    blank.get_by_label(gilbreth_dashboard::tabs::today::EMPTY_LEAN_CAPTURE_LINE);
    blank.get_by_label(gilbreth_dashboard::tabs::today::DATABASE_LABEL);
    blank.get_by_label("Z:/nonexistent/gilbreth.db");
    blank.get_by_label("No Today readings yet.");
    blank.get_by_label_contains("updated ");
    assert!(blank.query_by_label_contains(" · live").is_none());
    for retired in [
        "It's already on: lean capture started when you installed.",
        "Capture is running",
        "Lean capture is the default",
        "Keys are counted; what you type is never stored.",
    ] {
        assert!(
            blank.query_by_label_contains(retired).is_none(),
            "the posture-neutral welcome must not render retired state copy: {retired}"
        );
    }

    let mut populated = rich_snapshot();
    populated.first_run_welcome_dismissed = false;
    let rich = harness_with_host(
        stub_host_recording(writes),
        Some(populated),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1800.0,
    );
    rich.get_by_label("This dashboard reads what's captured on this machine.");
    rich.get_by_label("WHEN YOU WERE ACTIVE");
}

#[test]
fn blank_today_reports_full_key_content_without_changing_the_welcome() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = first_run_snapshot();
    snapshot.store_key_content = true;
    let harness = harness_with_host(
        stub_host_recording(writes),
        Some(snapshot),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1600.0,
    );

    harness.get_by_label("This dashboard reads what's captured on this machine.");
    harness.get_by_label("Capture is locally controlled");
    harness.get_by_label("Choose what is stored");
    harness.get_by_label(gilbreth_dashboard::tabs::today::EMPTY_FULL_CAPTURE_LINE);
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::today::EMPTY_LEAN_CAPTURE_LINE)
        .is_none());
}

#[test]
fn blank_today_does_not_claim_no_activity_when_the_read_failed() {
    let written: WrittenStates = Arc::default();
    let mut snapshot = first_run_snapshot();
    snapshot.first_run_welcome_dismissed = true;
    snapshot.error = Some("Today's activity could not be read.".to_string());
    let mut harness = harness_for(Some(snapshot), None, written);
    harness.run();

    harness.get_by_label("Today's activity could not be read.");
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::today::NO_ACTIVITY_HEADING)
        .is_none());
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::today::DATABASE_LABEL)
        .is_none());
}

#[test]
fn blank_today_database_receipt_pluralizes_singular_counts() {
    let written: WrittenStates = Arc::default();
    let mut snapshot = first_run_snapshot();
    snapshot.first_run_welcome_dismissed = true;
    snapshot.counts = DatabaseCounts {
        sessions: 1,
        events: 1,
        active_sessions: 1,
    };
    let mut harness = harness_for(Some(snapshot), None, written);
    harness.run();

    harness.get_by_label("1 event stored across 1 session; no Today readings yet.");
}

#[test]
fn welcome_privacy_cta_navigates_without_dismissing() {
    let writes: SharedWrites = Arc::default();
    let mut harness = harness_with_host(
        stub_host_recording(writes.clone()),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1600.0,
    );

    harness.get_by_label("Open privacy controls").click();
    harness.run();

    harness.get_by_label("Reading your data overview…");
    assert_eq!(writes.lock().unwrap().welcome_dismissals, 0);

    harness.get_by_label("Today").click();
    harness.run();
    harness.get_by_label("This dashboard reads what's captured on this machine.");
}

#[test]
fn both_welcome_dismiss_controls_persist_once_and_hide_immediately() {
    for label in ["Dismiss", "Dismiss welcome banner"] {
        let writes: SharedWrites = Arc::default();
        let mut harness = harness_with_host(
            stub_host_recording(writes.clone()),
            Some(first_run_snapshot()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            1600.0,
        );

        harness.get_by_label(label).click();
        harness.run();

        assert!(harness
            .query_by_label("This dashboard reads what's captured on this machine.")
            .is_none());
        assert_eq!(writes.lock().unwrap().welcome_dismissals, 1);
    }
}

#[test]
fn failed_welcome_dismissal_stays_visible_and_can_be_retried() {
    let mut host = stub_host_recording(Arc::default());
    host.dismiss_first_run_welcome = Box::new(|| Err("config file is busy".to_string()));
    let mut harness = harness_with_host(
        host,
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1600.0,
    );

    harness.get_by_label("Dismiss").click();
    harness.run();

    harness.get_by_label("This dashboard reads what's captured on this machine.");
    harness.get_by_label_contains("couldn't dismiss the welcome right now");
}

#[test]
fn stale_today_snapshot_cannot_rearm_a_dismissed_welcome() {
    use gilbreth_dashboard::data::Snapshot;

    let writes: SharedWrites = Arc::default();
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(stub_host_recording(writes.clone())),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, 1600.0))
        .build_ui(move |ui| {
            if !styled.get() {
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    harness.get_by_label("Dismiss").click();
    harness.run();

    let stale = first_run_snapshot();
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Today(Box::new(stale)));
    harness.run();

    assert!(harness
        .query_by_label("This dashboard reads what's captured on this machine.")
        .is_none());
    assert_eq!(writes.lock().unwrap().welcome_dismissals, 1);
}

#[test]
fn welcome_journey_stacks_at_the_supported_narrow_width() {
    let writes: SharedWrites = Arc::default();
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1400.0,
    );
    harness.set_size(egui::vec2(720.0, 1400.0));
    harness.run();

    let first = harness.get_by_label("01 · FROM THE TRAY").rect().top();
    let second = harness.get_by_label("02 · YOUR PRIVACY").rect().top();
    let third = harness.get_by_label("03 · FIND THE ONE THING").rect().top();
    assert!(first < second && second < third);
}

#[test]
fn first_run_actions_remain_reachable_at_the_minimum_viewport() {
    let writes: SharedWrites = Arc::default();
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        560.0,
    );
    harness.set_size(egui::vec2(720.0, 560.0));
    harness.run();

    harness.get_by_label("Dismiss").scroll_to_me();
    harness.run();
    let dismiss = harness.get_by_label("Dismiss").rect();
    assert!(
        dismiss.top() >= 0.0 && dismiss.bottom() <= 560.0,
        "the dismiss action must scroll into the minimum-height viewport: {dismiss:?}"
    );
}

#[test]
fn today_renders_story_notices_and_seven_days() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    let active_heading_top = harness.get_by_label("WHEN YOU WERE ACTIVE").rect().top();
    let pulse_top = harness
        .get_by_label(gilbreth_dashboard::tabs::today::PULSE_CAPTION)
        .rect()
        .top();
    let today_heading_top = harness.get_by_label("TODAY SO FAR").rect().top();
    let takeaway_top = harness
        .get_by_label_contains("Longest run: 1h 34m on studio.exe")
        .rect()
        .top();
    let gauge_top = harness.get_by_label("Active time").rect().top();
    assert!(active_heading_top < pulse_top);
    assert!(pulse_top < today_heading_top);
    assert!(today_heading_top < takeaway_top);
    assert!(
        takeaway_top < gauge_top,
        "the day's takeaway must precede the Today-so-far gauges"
    );
    for label in [
        "Active time",
        "In front (idle incl.)",
        "Longest focus run",
        "Focus switches",
        "Keystrokes",
    ] {
        harness.get_by_label(label);
    }
    // The labeled pulse and the visible capture posture (charter rulings).
    harness.get_by_label(gilbreth_dashboard::tabs::today::PULSE_CAPTION);
    harness.get_by_label(gilbreth_dashboard::tabs::today::LEAN_CAPTURE_LINE);
    // The observation cards in the shared anatomy: hedge once at section
    // level, uppercase family chips.
    harness.get_by_label(gilbreth_dashboard::tabs::widgets::PATTERNS_DESCRIPTIVE_CAPTION);
    harness.get_by_label("Returning to studio.exe has a toll");
    harness.get_by_label_contains("RETURN TOLL");
    harness.get_by_label("Clipboard bridge: browser.exe to studio.exe");
    harness.get_by_label("CLIPBOARD BRIDGE");
    harness.get_by_label("Minutes active per day.");
    // The glossary retired into per-section Details; the amendment (§1)
    // retired the content-describing subtexts too — two plain expanders.
    assert!(harness.query_by_label("What these numbers mean").is_none());
    assert!(harness
        .query_by_label("what active, in front, runs, and switches mean")
        .is_none());
    assert_eq!(harness.get_all_by_label("Details").count(), 2);
}

#[test]
fn today_pulse_only_fresh_start_keeps_the_opener_compact() {
    let written: WrittenStates = Arc::default();
    let mut snapshot = rich_snapshot();
    snapshot.strip.focus.clear();
    snapshot.strip.away.clear();
    let mut harness = harness_for(Some(snapshot), None, written);
    harness.run();

    let heading_bottom = harness.get_by_label("WHEN YOU WERE ACTIVE").rect().bottom();
    let pulse_top = harness
        .get_by_label(gilbreth_dashboard::tabs::today::PULSE_CAPTION)
        .rect()
        .top();
    let gap = pulse_top - heading_bottom;
    assert!(
        gap <= 24.0,
        "a pulse-only day must not reserve inter-figure space ({gap}px)"
    );
}

#[test]
fn tab_switching_round_trips_between_native_tabs() {
    // Every tab is native now — the last placeholder retired with the
    // Diagnostics milestone.
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    harness.get_by_label("Diagnostics").click();
    harness.run();
    harness.get_by_label("Reading the diagnostics…");
    harness.get_by_label("Today").click();
    harness.run();
    harness.get_by_label("Keystrokes");
}

#[test]
fn dismiss_today_writes_notice_state_through_the_host() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written.clone());
    harness.run();
    harness
        .get_all_by_label("Dismiss today")
        .next()
        .unwrap()
        .click();
    harness.run();
    let states = written.lock().unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(
        states[0].dismissed.get("return_toll:studio.exe"),
        Some(&"2026-07-09".to_string())
    );
    assert!(states[0].muted.is_empty());
}

#[test]
fn mute_and_watch_toggle_through_the_host() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written.clone());
    harness.run();
    harness.get_all_by_label("Mute").next().unwrap().click();
    harness.run();
    harness.get_all_by_label("Watch").next().unwrap().click();
    harness.run();
    let states = written.lock().unwrap();
    assert_eq!(states.len(), 2);
    assert!(states[0].muted.contains("return_toll:studio.exe"));
    // The second write starts from the updated in-memory state, so the mute
    // survives the watch toggle.
    assert!(states[1].muted.contains("return_toll:studio.exe"));
    assert!(!states[1].watched.is_empty());
}

#[test]
fn week_tab_renders_digest_trends_and_cards() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), Some(rich_week_snapshot()), written);
    harness.run();
    harness.get_by_label("Week").click();
    harness.run();
    harness.get_by_label("App switches / active hour");
    harness.get_by_label("84,312");
    // The heatmap leads with its takeaway; the story title retired.
    harness.get_by_label("Your active hours across the week. Brighter is more active.");
    assert!(harness
        .query_by_label_contains("Your week in motion")
        .is_none());
    // The delta line says "last week" once (C-ledger), rates move lower.
    harness.get_by_label(
        "Vs. last week: 50% more active time; 20% more keystrokes; 11% lower switch rate.",
    );
    // Top apps as share bars with mono figures.
    harness.get_by_label("6h 12m");
    harness.get_by_label("mail.exe → studio.exe → browser.exe");
    harness.get_by_label("The apps you open first, across 5 days this week.");
    // Pulls-you-back counts join with middots, not dashes.
    harness.get_by_label("• 4 times");
    harness.get_by_label("New:");
    harness.get_by_label("a mail.exe ↔ studio.exe pattern (9 occurrences across 3 days).");
    harness.get_by_label("Quieter:");
    // The thresholds live in the changed section's plain Details (the
    // tab's second), two labeled lines with the archive note last.
    harness
        .get_all_by_label("Details")
        .nth(1)
        .expect("the changed-this-week Details")
        .click();
    harness.run();
    harness.get_by_label(gilbreth_dashboard::tabs::week::CHANGED_NEW_LINE);
    harness.get_by_label(gilbreth_dashboard::tabs::week::CHANGED_QUIETER_LINE);
    harness.get_by_label(gilbreth_dashboard::tabs::week::CHANGED_ARCHIVE_LINE);
    harness.get_by_label("browser.exe → studio.exe → chat.exe");
    // UX-37: the shared hedge caption renders once above the week cards,
    // which carry uppercase family chips and the mono facts line.
    harness.get_by_label(gilbreth_dashboard::tabs::widgets::PATTERNS_DESCRIPTIVE_CAPTION);
    harness.get_by_label("ROUTINE");
    harness.get_by_label_contains("signal Medium");
    // The record button is Analytics-only; the Week digest stays read-only.
    assert!(harness
        .query_by_label("Ask tray to record this routine")
        .is_none());
}

#[test]
fn week_tab_empty_week_states_the_floor() {
    let written: WrittenStates = Arc::default();
    let mut empty = rich_week_snapshot();
    empty.digest.active_ms = 0;
    let mut harness = harness_for(Some(rich_snapshot()), Some(empty), written);
    harness.run();
    harness.get_by_label("Week").click();
    harness.run();
    harness.get_by_label(gilbreth_dashboard::tabs::week::NOTHING_RECORDED_WEEK);
    // Below the floor the digest stops: no tiles, no glossary.
    assert!(harness.query_by_label("Active days").is_none());
}

#[test]
fn week_tab_sparse_history_uses_the_two_day_floor_caption() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), Some(sparse_week_snapshot()), written);
    harness.run();
    harness.get_by_label("Week").click();
    harness.run();
    harness.get_by_label(gilbreth_dashboard::tabs::week::NO_PRIOR_WEEK_CAPTION);
    harness.get_by_label(gilbreth_dashboard::tabs::week::NO_CHANGES_CAPTION);
    // db.py pins the sequence floor at 2 days; 1 active day sits below it.
    harness.get_by_label(&gilbreth_dashboard::tabs::widgets::patterns_empty_caption(
        1,
    ));
}

#[test]
fn week_tab_loading_state_before_first_read() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    harness.get_by_label("Week").click();
    harness.run();
    harness.get_by_label("Reading this week's activity…");
}

#[test]
fn analytics_renders_selectors_header_and_analysis_sections() {
    use gilbreth_dashboard::tabs::analytics as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness(rich_analytics_snapshot(), writes);
    // The scope and run selectors expose their selection as the combo value;
    // the view switcher shows both lenses with its quiet micro-label.
    let scope_center_y = harness
        .get_by(|node| node.value().as_deref() == Some("Last 7 days"))
        .rect()
        .center()
        .y;
    let session_center_y = harness
        .get_by(|node| node.value().as_deref() == Some("All sessions"))
        .rect()
        .center()
        .y;
    let view_center_y = harness
        .get_by_label(tab::VIEW_MICRO_LABEL)
        .rect()
        .center()
        .y;
    let analysis_center_y = harness.get_by_label("Analysis").rect().center().y;
    let tables_center_y = harness.get_by_label("Tables").rect().center().y;
    let centers = [
        scope_center_y,
        session_center_y,
        view_center_y,
        analysis_center_y,
        tables_center_y,
    ];
    let min_center = centers.iter().copied().fold(f32::INFINITY, f32::min);
    let max_center = centers.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    assert!(
        max_center - min_center <= 0.5,
        "the Analytics toolbar must share one vertical center: scope={scope_center_y}, \
         session={session_center_y}, View={view_center_y}, Analysis={analysis_center_y}, \
         Tables={tables_center_y}"
    );
    harness.get_by_label("Top app (active)");
    harness.get_by_label(tab::FOREGROUND_MINUTES_CAVEAT);
    assert!(
        harness
            .query_by_label(gilbreth_dashboard::tabs::widgets::HELP_GLYPH)
            .is_none(),
        "the redesigned tab retires every ⓘ affordance"
    );
    // Rhythms leads the page (owner amendment) with its takeaway.
    harness.get_by_label("Your active hours, from your own history. Brighter is more active.");
    harness.get_by_label("Typing burst, median");
    // Gauge suffixes render beside the 19px value (amendment §7).
    harness.get_by_label("64 wpm");
    harness.get_by_label("1240 px/s");
    // UX-37: the hedge is stated once under the kicker, never per card;
    // the family boilerplate states once with it (charter §2).
    harness.get_by_label(gilbreth_dashboard::tabs::widgets::PATTERNS_DESCRIPTIVE_CAPTION);
    harness.get_by_label(
        "The strongest card from each pattern family. Repeated tight sequences can point to a \
         manual routine; a shortcut or macro may remove the shuffle.",
    );
    harness.get_by_label("browser.exe → studio.exe → chat.exe");
    harness.get_by_label("ROUTINE • 6 VARIANTS");
    harness.get_by_label("FRAGMENTATION");
    harness.get_by_label("signal High • events 24 • recurs 5");
    harness.get_by_label("All patterns in scope");
    harness.get_by_label("7 patterns • 2 families");
    // Every section: a takeaway sentence and renamed plain-word gauges.
    harness.get_by_label("Focus runs 2m 54s before something pulls you away.");
    harness.get_by_label("Median focus run");
    harness.get_by_label("Lag before typing resumes");
    harness.get_by_label("Getting back after a pull-away costs 7.2s before input resumes.");
    harness.get_by_label("Restart toll, est.");
    harness.get_by_label("Time away in diversions");
    harness.get_by_label("Input runs 1h 40m 36s per day, below the 4h per day population band.");
    harness.get_by_label("Active input, per day");
    harness.get_by_label("Active time groups into 2 episodes; the median runs 1h 8m 30s.");
    harness.get_by_label("Episodes");
    // Skeleton mode offers the opt-in inside the episodes Details (the
    // page's fifth plain expander), not the opt-out.
    harness
        .get_all_by_label("Details")
        .nth(4)
        .expect("the episodes Details")
        .click();
    harness.run();
    harness.get_by_label("Name these episodes from window titles (optional)");
    assert!(harness
        .query_by_label("Turn off names from titles")
        .is_none());
}

#[test]
fn analytics_tables_subtab_shows_rollups_and_ongoing_session() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness(rich_analytics_snapshot(), writes);
    harness.get_by_label("Tables").click();
    harness.run();
    harness.get_by_label("ongoing");
    harness.get_by_label("2026-07-08 09:12:44");
    // The total appears in both the input summary and the relocated
    // input-load table.
    assert!(harness.get_all_by_label("215,006").count() >= 2);
    harness.get_by_label(
        "Open duration uses observed window closes only; startup-seeded and \
         shutdown-synthesized closes are excluded.",
    );
    // The relocated dense tables live here now (charter §4): each named by
    // its kicker so the Detail jumps have a target.
    harness.get_by_label("FOCUS BY APP");
    harness.get_by_label("Resumption lag (s)");
    harness.get_by_label("WHERE PULL-AWAYS GO");
    harness.get_by_label("Pulled into");
    harness.get_by_label("INPUT LOAD BY APP");
    harness.get_by_label("Keys/hour");
    harness.get_by_label("WORK EPISODES");
    harness.get_by_label("Dominant app");
}

#[cfg(windows)]
#[test]
fn analytics_record_button_writes_candidate_payload_through_host() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness(rich_analytics_snapshot(), writes.clone());
    // Several routine cards carry the button; the first is the strip winner.
    harness
        .get_all_by_label("Ask tray to record this routine")
        .next()
        .unwrap()
        .click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.record_requests.len(), 1);
    let (kind, payload) = &recorded.record_requests[0];
    assert_eq!(kind, "automatable_routine");
    assert_eq!(
        payload,
        "{\"schema\":\"gilbreth.record_request.candidate.v1\",\
         \"kind\":\"automatable_routine\",\"category\":\"sequence\",\
         \"title\":\"browser.exe → studio.exe → chat.exe\",\"band\":\"High\",\
         \"evidence\":\"24 occurrences across 4 days; median step 38s.\",\
         \"support_count\":24,\"support_sessions\":5,\"support_days\":4}"
    );
    drop(recorded);
    // UX-45: one sentence for the request state, never the raw token.
    harness.run();
    harness.get_by_label(gilbreth_dashboard::tabs::widgets::RECORD_SENT_CAPTION);
    assert!(harness
        .query_by_label("Record request status: requested")
        .is_none());
}

#[test]
fn analytics_overlay_alias_remove_and_opt_out_write_through_host() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness(overlay_analytics_snapshot(), writes.clone());
    harness.get_by_label("Time with a name");
    // The naming controls live inside the episodes Details now.
    harness
        .get_all_by_label("Details")
        .nth(4)
        .expect("the episodes Details")
        .click();
    harness.run();
    harness.get_by_label("Rename or merge spheres");
    harness.get_by_label("Remove").click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.alias_writes.len(), 1);
        assert!(recorded.alias_writes[0].is_empty());
    }
    harness.get_by_label("Turn off names from titles").click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.overlay_toggles, vec![false]);
}

#[test]
fn analytics_empty_candidates_state_says_so() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_analytics_snapshot();
    snapshot.data.as_mut().unwrap().candidates.clear();
    let harness = analytics_harness(snapshot, writes);
    // UX-12: the shared floor-aware copy in the shared info-box treatment.
    harness.get_by_label(&gilbreth_dashboard::tabs::widgets::patterns_empty_caption(
        9,
    ));
}

#[test]
fn analytics_loading_state_before_first_read() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    harness.get_by_label("Analytics").click();
    harness.run();
    harness.get_by_label("Reading your analytics…");
}

#[cfg(windows)]
#[test]
fn recordings_render_table_verdict_and_controls() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = recordings_harness(recordings_snapshot_rich(), writes);
    // The journey strip leads, with the privacy line demoted beneath it.
    harness.get_by_label(tab::JOURNEY_RECORD_KICKER);
    harness.get_by_label(tab::JOURNEY_RECORD_TITLE);
    harness.get_by_label(tab::JOURNEY_REVIEW_TITLE);
    harness.get_by_label(tab::JOURNEY_ANALYZE_TITLE);
    harness.get_by_label(tab::JOURNEY_ANALYZE_BODY);
    harness.get_by_label(tab::PRIVACY_LINE);
    // The routine list: readiness dots, names, story meta, dates.
    harness.get_by_label("Invoice sweep");
    harness.get_by_label("Recording 9 — untitled");
    harness.get_by_label("4 steps • 30m");
    harness.get_by_label("recording now • 4m");
    assert!(
        harness.query_by_label("record_session_id").is_none(),
        "snake_case headers must not come back (UX-08)"
    );
    // Detail pane: heading, the operational meta line, the product-voice
    // verdict composed from the verdict counts, no hover-help glyphs.
    harness.get_by_label("Recording 7: Invoice sweep");
    harness
        .get_by_label("2026-07-09 09:00:00 to 2026-07-09 09:30:00 • User Stop • request fulfilled");
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::widgets::HELP_GLYPH)
        .is_none());
    harness.get_by_label("Replayable — every actionable step maps to a named control.");
    harness.get_by_label(
        "2 of 2 actionable steps native-eligible • no unknown or missing-selector gaps",
    );
    harness.get_by_label(tab::HOW_JUDGED_TITLE);
    // The gauge row: steps, duration, distinct controls, free input.
    harness.get_by_label("Controls touched");
    harness.get_by_label("Free-input steps");
    harness.get_by_label("30m");
    // The export kit is the primary action zone: trace export, the
    // copyable prompt (with its shipped copy visible), the quiet blueprint.
    harness.get_by_label(tab::KIT_TITLE);
    harness.get_by_label(tab::KIT_BODY);
    harness.get_by_label(tab::EXPORT_AGENT_BUTTON);
    harness.get_by_label(tab::EXPORT_NATIVE_BUTTON);
    harness.get_by_label(tab::PROMPT_PREVIEW_KICKER);
    harness.get_by_label(tab::ANALYSIS_PROMPT);
    harness.get_by_label(tab::EXPORT_CONTENTS_TITLE);
    harness.get_by_label(tab::NATIVE_EXPORT_CAPTION);
    harness.get_by_label(tab::COPY_PROMPT_BUTTON).click();
    harness.run();
    harness.get_by_label(tab::PROMPT_COPIED_CAPTION);
    // The humanized steps table with neutral confidence chips.
    harness.get_by_label("What happened");
    harness.get_by_label("Pressed a button");
    harness.get_by_label("Toggled a control");
    harness.get_by_label("Typed into a field (content not stored)");
    harness.get_by_label("Interacted with an unmapped element");
    assert!(harness.get_all_by_label("REPLAYABLE").count() >= 2);
    harness.get_by_label("FREE INPUT");
    harness.get_by_label("UNMAPPED");
    assert!(harness
        .get_all_by_label("studio.exe • named control")
        .next()
        .is_some());
    harness.get_by_label(tab::STEPS_VALUE_FREE_CAPTION);
    // Engineering internals live behind the one expander.
    harness.get_by_label(tab::ENGINEERING_DETAIL_TITLE).click();
    harness.run();
    harness.get_by_label("uia:4-deep (named)");
    harness.get_by_label("edit_committed");
    assert!(harness
        .get_all_by_label("structurally observed")
        .next()
        .is_some());
    // Labels, capture context, and the quiet delete footer.
    harness.get_by_label(tab::LABELS_EXPANDER_TITLE);
    harness.get_by_label(tab::CAPTURE_CONTEXT_TITLE);
    harness.get_by_label(tab::DELETE_SECTION_CAPTION);
    harness.get_by_label(tab::CONFIRM_DELETE_LABEL);
    harness.get_by_label(tab::DELETE_BUTTON_LABEL);
}

#[cfg(windows)]
#[test]
fn recordings_export_clicks_save_through_host() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = recordings_harness(recordings_snapshot_rich(), writes.clone());
    harness.get_by_label(tab::EXPORT_AGENT_BUTTON).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(
            recorded.export_saves,
            vec![(7, "agent_grounded".to_string(), Vec::new())]
        );
    }
    // UX-15: the outcome renders in the detail pane, below the detail
    // heading, beside the buttons that produced it.
    let notice_top = harness
        .get_by_label(
            "Saved the agent handoff trace to C:\\stub\\Downloads\\gilbreth_agent_handoff_7.json.",
        )
        .rect()
        .top();
    let heading_top = harness
        .get_by_label("Recording 7: Invoice sweep")
        .rect()
        .top();
    assert!(
        notice_top > heading_top,
        "the export outcome must land in the detail pane (UX-15): notice {notice_top}, heading {heading_top}"
    );
    harness.get_by_label(tab::EXPORT_NATIVE_BUTTON).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.export_saves.len(), 2);
        assert_eq!(recorded.export_saves[1].1, "native_skeleton");
    }
    harness.get_by_label(
        "Saved the native automation blueprint to \
         C:\\stub\\Downloads\\gilbreth_native_blueprint_7.json.",
    );
}

#[cfg(windows)]
#[test]
fn recordings_delete_needs_confirm_and_writes_through_host() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = recordings_harness(recordings_snapshot_rich(), writes.clone());
    // Unconfirmed: the button is disabled and nothing reaches the host.
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().recording_deletes.is_empty());
    harness.get_by_label(tab::CONFIRM_DELETE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    assert_eq!(writes.lock().unwrap().recording_deletes, vec![7]);
    harness.get_by_label("Deleted 1 recording.");
}

#[cfg(windows)]
#[test]
fn recordings_open_recording_gates_export_and_delete() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    snapshot.selected_id = Some(9);
    snapshot.detail = Some(RecordingDetail {
        steps: Vec::new(),
        verdict: recording_replay_verdict(&[], &HashSet::from(["native".to_string()])),
    });
    let harness = recordings_harness(snapshot, writes);
    harness.get_by_label("Recording 9");
    harness.get_by_label(tab::NO_STEPS_INFO);
    harness.get_by_label(tab::OPEN_RECORDING_INFO);
    assert!(harness.query_by_label(tab::EXPORT_AGENT_BUTTON).is_none());
    assert!(harness.query_by_label(tab::KIT_TITLE).is_none());
    assert!(harness.query_by_label(tab::DELETE_BUTTON_LABEL).is_none());
    assert!(harness.query_by_label(tab::LABELS_EXPANDER_TITLE).is_none());
}

#[cfg(windows)]
#[test]
fn recordings_empty_state_explains_record_routine() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    snapshot.rows.clear();
    snapshot.selected_id = None;
    snapshot.detail = None;
    let harness = recordings_harness(snapshot, writes);
    // The first encounter is the pitch (charter §7): why you'd record,
    // then exactly how to start.
    harness.get_by_label(tab::EMPTY_PITCH_TITLE);
    harness.get_by_label(tab::EMPTY_PITCH_BODY);
    harness.get_by_label(tab::HOW_TO_RECORD_LEAD);
    harness.get_by_label(tab::HOW_RECORDING_STARTS);
}

#[cfg(windows)]
#[test]
fn recordings_tables_missing_state_says_so() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    snapshot.tables_present = false;
    snapshot.rows.clear();
    snapshot.selected_id = None;
    snapshot.detail = None;
    let harness = recordings_harness(snapshot, writes);
    harness.get_by_label(tab::TABLES_MISSING_INFO);
}

#[cfg(windows)]
#[test]
fn recordings_no_selection_prompts_for_one() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    snapshot.selected_id = None;
    snapshot.detail = None;
    let harness = recordings_harness(snapshot, writes);
    harness.get_by_label(tab::SELECT_RECORDING_CAPTION);
}

#[cfg(windows)]
#[test]
fn recordings_loading_state_before_first_read() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    harness.get_by_label("Recordings").click();
    harness.run();
    harness.get_by_label("Reading your recordings…");
}

#[test]
fn session_renders_selector_tiles_details_and_overview() {
    use gilbreth_dashboard::tabs::session as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = session_harness(
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
        writes,
    );
    // Selector: the open/latest session leads with the C-ledger label
    // shape (the selection is the combo's value); the view switcher shows
    // both lenses behind its quiet micro-label.
    harness.get_by(|node| {
        node.value().as_deref() == Some("Current session (since 2026-07-09 06:30, 128 events)")
    });
    harness.get_by_label(gilbreth_dashboard::tabs::widgets::VIEW_MICRO_LABEL);
    harness.get_by_label("Overview");
    harness.get_by_label("Records");
    // The header: takeaway, five gauges (no hover-help glyphs anywhere),
    // and the Detail carrying the caveat, identity, and storage path.
    harness.get_by_label(
        "1h 36m 20s active since 06:30, of 1h 50m in front. studio.exe carried 1h 23m of it.",
    );
    for label in [
        "Active time",
        "In front (idle incl.)",
        "Top app (active)",
        "Focus switches",
        "Keystrokes",
    ] {
        harness.get_by_label(label);
    }
    harness.get_by_label("1h 36m 20s"); // 5780 active seconds
    harness.get_by_label("1h 50m"); // 6600 foreground seconds
    assert!(harness.get_all_by_label("studio.exe").count() >= 2);
    harness
        .get_all_by_label("1,234")
        .next()
        .expect("keystrokes");
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::widgets::HELP_GLYPH)
        .is_none());
    harness
        .get_all_by_label("Details")
        .next()
        .expect("the header Details")
        .click();
    harness.run();
    harness.get_by_label(gilbreth_dashboard::tabs::analytics::FOREGROUND_MINUTES_CAVEAT);
    harness.get_by_label("Z:/nonexistent/gilbreth.db");
    // Where the time went: takeaway + share-bar rows with mono figures.
    harness.get_by_label("WHERE THE TIME WENT");
    harness.get_by_label("2 apps held focus. studio.exe took 86% of active time.");
    harness.get_by_label("active 1h 23m • in front 1h 30m • switches 40");
    // Machine events: the takeaway and the timestamped rows (the recorded
    // anatomy bend: records render as rows, not gauges).
    harness.get_by_label("MACHINE EVENTS");
    harness.get_by_label(
        "One standby gap: 30m from 08:00. Signed in at 06:30; the display changed once.",
    );
    harness.get_by_label("Signed in");
    harness.get_by_label("Display changed");
    harness.get_by_label("2560 × 1440");
    harness.get_by_label("Standby");
    harness.get_by_label("resumed 08:30 • gap 30m");
    // What was captured: the counts takeaway with the visible keystroke
    // posture line, one gauge per source.
    harness.get_by_label("WHAT WAS CAPTURED");
    harness.get_by_label(
        "Mostly keyboard: 1,234 events, with 64 foreground and 25 mouse. Keys are counted; \
         what you typed is not stored (default).",
    );
    harness.get_by_label("Keyboard");
    harness.get_by_label("Foreground");
    harness.get_by_label("Mouse");
    // The Records lens holds the verify register: the four tables under
    // their kickers, sentence-case headers, the C-ledger power columns.
    harness.get_by_label("Records").click();
    harness.run();
    harness.get_by_label("TIME PER APP");
    harness.get_by_label(tab::SHOW_TITLES_LABEL);
    // "App name" heads both the focus table and the event list here.
    assert!(harness.get_all_by_label("App name").count() >= 2);
    harness.get_by_label("Screen position 2560, 1440");
    harness.get_by_label("Session start"); // humanized kind
    harness.get_by_label("POWER TIMELINE");
    harness.get_by_label(tab::POWER_CONTEXT_CAPTION);
    harness.get_by_label(tab::POWER_METHOD_CAPTION);
    harness.get_by_label("Power resume");
    harness.get_by_label("Resume matched");
    harness.get_by_label("App-clock gap");
    harness.get_by_label("Heartbeat (ms)");
    harness.get_by_label("Yes"); // matched_suspend
    harness.get_by_label("EVENT COUNTS");
    harness.get_by_label(tab::EVENT_COUNTS_CAPTION);
    harness.get_by_label("Events total");
    // "Focus changed" renders in both the counts table and the event list.
    assert!(harness.get_all_by_label("Focus changed").count() >= 1);
}

#[test]
fn session_identity_caption_renders_for_an_identity_bearing_session() {
    // The identity caption is the ended session's; select it through the
    // combo and open the details expander.
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_session_snapshot();
    snapshot.selected_session_id = Some(1);
    let mut harness = session_harness(Some(snapshot), None, writes);
    harness
        .get_all_by_label("Details")
        .next()
        .expect("the header Details")
        .click();
    harness.run();
    harness.get_by_label("Run label soak • Host DESK • Version 0.9.0 • Build abcdef123456");
}

#[test]
fn session_titles_toggle_reveals_the_title_column() {
    use gilbreth_dashboard::tabs::session as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = session_harness(Some(rich_session_snapshot()), None, writes);
    open_event_list(&mut harness);
    // Default off: apps only, no title column (the privacy default).
    assert!(harness.query_by_label("App title").is_none());
    assert!(harness.query_by_label("Doc A — Studio").is_none());
    harness.get_by_label(tab::SHOW_TITLES_LABEL).click();
    harness.run();
    harness.get_by_label("App title");
    harness.get_by_label("Doc A — Studio");
}

#[test]
fn session_power_timeline_empty_state_says_so() {
    use gilbreth_dashboard::tabs::session as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_session_snapshot();
    snapshot.power_events.clear();
    let mut harness = session_harness(Some(snapshot), None, writes);
    open_event_list(&mut harness);
    harness.get_by_label(tab::POWER_EMPTY_CAPTION);
    assert!(harness.query_by_label(tab::POWER_CONTEXT_CAPTION).is_none());
}

#[test]
fn session_event_list_filters_selects_and_gates_the_delete() {
    use gilbreth_dashboard::data::Request;
    use gilbreth_dashboard::tabs::session as tab;
    let writes: SharedWrites = Arc::default();
    let (mut harness, app) = session_harness_shared(
        stub_host_recording(writes.clone()),
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
    );
    open_event_list(&mut harness);
    let _ = app.borrow_mut().take_issued_requests_for_tests();
    harness.get_by_label(tab::REFRESH_EVENTS_LABEL);
    // The kind filter defaults to every kind; rows carry humanized cells.
    harness.get_by_label("key");
    harness.get_by_label("focus_changed");
    harness.get_by_label("mouse_click");
    harness.get_by_label("101");
    harness.get_by_label("0x00AA12");
    // Privacy-grammar delete: kicker + permanence line, confirm disabled
    // until a selection exists, delete disabled until armed.
    harness.get_by_label("DELETE SELECTED");
    harness.get_by_label(tab::DELETE_SECTION_CAPTION);
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().event_deletes.is_empty());
    // Select one row, arm, delete.
    harness.get_by_label("101").click();
    harness.run();
    harness.get_by_label("1 selected");
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    assert!(
        writes.lock().unwrap().event_deletes.is_empty(),
        "unconfirmed delete must stay inert"
    );
    harness.get_by_label(tab::CONFIRM_DELETE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    assert_eq!(writes.lock().unwrap().event_deletes, vec![vec![101]]);
    // One-shot success notice with the oracle copy; the list snapshot
    // cleared and both rebuild requests were queued.
    harness.get_by_label("Deleted 1 entries.");
    harness.get_by_label(tab::READING_EVENTS_LABEL);
    let issued = app.borrow_mut().take_issued_requests_for_tests();
    assert!(issued.contains(&Request::RefreshSession(Some(2))));
    assert!(issued.contains(&Request::RefreshSessionEvents(2)));
}

#[test]
fn session_kind_filter_hides_filtered_rows() {
    let writes: SharedWrites = Arc::default();
    let mut harness = session_harness(
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
        writes,
    );
    open_event_list(&mut harness);
    harness.get_by_label("101");
    // Deselect "key": the key row leaves the table; the others stay.
    harness.get_by_label("key").click();
    harness.run();
    assert!(harness.query_by_label("101").is_none());
    harness.get_by_label("102");
    harness.get_by_label("103");
}

#[test]
fn session_delete_error_keeps_the_busy_copy() {
    use gilbreth_dashboard::tabs::session as tab;
    let mut host = stub_host_recording(Arc::default());
    host.delete_events = Box::new(|_| Err("database is locked".to_string()));
    let (mut harness, _app) = session_harness_shared(
        host,
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
    );
    open_event_list(&mut harness);
    harness.get_by_label("101").click();
    harness.run();
    harness.get_by_label(tab::CONFIRM_DELETE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::DELETE_BUTTON_LABEL).click();
    harness.run();
    harness
        .get_by_label_contains("Couldn't delete the selected entries. The database may be busy.");
    // The failed delete keeps the list (no rebuild happened).
    harness.get_by_label("101");
}

/// UX-62's core semantics: the Event list is snapshot-backed. A plain tab
/// refresh re-reads the session but leaves the list untouched; only the
/// explicit button rebuilds it.
#[test]
fn session_event_list_snapshot_survives_a_tab_refresh() {
    use gilbreth_dashboard::data::Request;
    use gilbreth_dashboard::tabs::session as tab;
    let (mut harness, app) = session_harness_shared(
        stub_host_recording(Arc::default()),
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
    );
    open_event_list(&mut harness);
    // Clear the tab-switch read's in-flight state so the Refresh button is
    // live again (UX-57 disables it while a read runs).
    let ctx = harness.ctx.clone();
    app.borrow_mut().adopt_snapshot_for_tests(
        &ctx,
        gilbreth_dashboard::data::Snapshot::Session(Box::new(rich_session_snapshot())),
    );
    harness.run();
    let _ = app.borrow_mut().take_issued_requests_for_tests();
    // A plain tab refresh: the session re-reads, the event list does NOT.
    harness.get_by_label("Refresh").click();
    harness.run();
    assert_eq!(
        app.borrow_mut().take_issued_requests_for_tests(),
        vec![Request::RefreshSession(Some(2))],
        "a plain refresh must not rebuild the event-list snapshot"
    );
    // The held list still renders (not a reading state).
    harness.get_by_label("101");
    // The explicit button is the rebuild path.
    harness.get_by_label(tab::REFRESH_EVENTS_LABEL).click();
    harness.run();
    assert_eq!(
        app.borrow_mut().take_issued_requests_for_tests(),
        vec![Request::RefreshSessionEvents(2)]
    );
}

/// Selecting another session queues its read; the arriving session
/// snapshot then queues the event-list rebuild through the key-mismatch
/// check (the Streamlit two-key cache), and a matching list settles it.
#[test]
fn session_selection_change_rebuilds_the_event_list_via_adoption() {
    use gilbreth_dashboard::data::{Request, Snapshot};
    let (mut harness, app) = session_harness_shared(
        stub_host_recording(Arc::default()),
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
    );
    let _ = app.borrow_mut().take_issued_requests_for_tests();
    // Pick the ended identity session in the combo.
    harness
        .get_by(|node| {
            node.role() == egui::accesskit::Role::ComboBox
                && node.value().as_deref()
                    == Some("Current session (since 2026-07-09 06:30, 128 events)")
        })
        .click();
    harness.run();
    harness
        .get_by_label("2026-07-08 09:00–2026-07-08 17:45 (3401 events)")
        .click();
    harness.run();
    assert_eq!(
        app.borrow_mut().take_issued_requests_for_tests(),
        vec![Request::RefreshSession(Some(1))]
    );
    // The resolved snapshot arrives: the held list is keyed to session 2,
    // so the rebuild for session 1 queues automatically.
    let mut resolved = rich_session_snapshot();
    resolved.selected_session_id = Some(1);
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Session(Box::new(resolved)));
    harness.run();
    assert_eq!(
        app.borrow_mut().take_issued_requests_for_tests(),
        vec![Request::RefreshSessionEvents(1)]
    );
    // The matching list lands; nothing further is requested.
    let mut events = session_events_fixture();
    events.session_id = 1;
    events.events = vec![session_event_row(201, 1, "keyboard", "key")];
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::SessionEvents(Box::new(events)));
    harness.run();
    open_event_list(&mut harness);
    harness.get_by_label("201");
    assert_eq!(
        app.borrow_mut().take_issued_requests_for_tests(),
        Vec::<Request>::new()
    );
}

#[test]
fn session_no_sessions_states_itself() {
    use gilbreth_dashboard::tabs::session as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_session_snapshot();
    snapshot.sessions.clear();
    snapshot.selected_session_id = None;
    let harness = session_harness(Some(snapshot), None, writes);
    harness.get_by_label(tab::NO_SESSIONS_INFO);
}

#[test]
fn session_loading_state_before_first_read() {
    let writes: SharedWrites = Arc::default();
    let harness = session_harness(None, None, writes);
    harness.get_by_label("Reading this session…");
}

#[test]
fn privacy_renders_your_data_delete_data_and_continuity() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = privacy_harness(privacy_snapshot_rich(), writes);
    harness.get_by_label(tab::LOCAL_ONLY_CAPTION);
    // Lean-capture keystroke line + life-of-row titles line (retention 0).
    // The Your-data facts read as plain-label secnotes (amendment §6).
    harness.get_by_label(&format!("Keystrokes: {}", tab::KEYSTROKES_OFF_LINE));
    harness.get_by_label(&format!("Window titles: {}", tab::TITLES_LIFE_LINE));
    for label in ["Events stored", "Sessions", "Database"] {
        harness.get_by_label(label);
    }
    harness.get_by_label("215,006");
    harness.get_by_label("75.0 MB");
    // The storage path as a quiet mono line; every ⓘ retired with the
    // redesign.
    harness.get_by_label("C:\\Users\\dev\\AppData\\Local\\Gilbreth\\gilbreth.db");
    assert!(harness
        .query_by_label(gilbreth_dashboard::tabs::widgets::HELP_GLYPH)
        .is_none());
    // Settings: one group, every control with its state chip and helper.
    harness.get_by_label(tab::SUPPRESSION_ROW_TITLE);
    harness.get_by_label("ON");
    harness.get_by_label(tab::SUPPRESSION_CAPTION);
    harness.get_by_label("12 rows redacted this session.");
    harness.get_by_label(tab::TITLE_RETENTION_ROW_TITLE);
    harness.get_by_label("KEEP ALL");
    harness.get_by_label(tab::TITLE_RETENTION_HINT);
    harness.get_by_label(tab::TITLE_PATTERNS_LABEL);
    harness.get_by_label(tab::KEY_PATTERNS_LABEL);
    harness.get_by_label(tab::EXCLUDED_APPS_LABEL);
    harness.get_by_label(tab::MOUSE_RETENTION_ROW_TITLE);
    harness.get_by_label("30 DAYS");
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL);
    // Delete data and archive handling: the prune row with its readiness
    // chip and breakdown, the erase facts at the point of action, and the
    // portable export row.
    harness.get_by_label(tab::PRUNE_ROW_TITLE);
    harness.get_by_label(tab::PRUNE_CAPTION);
    harness.get_by_label("4,223 READY");
    harness.get_by_label(
        "Activity events: 4200; empty sessions: 3; recording steps: 12; empty recordings: 1; \
         expired record requests: 2; leftover recording data: 5.",
    );
    harness.get_by_label(tab::ERASE_BLOCK_TITLE);
    // Archive and reset is Windows-only; the rest of this block renders on
    // both platforms and stays asserted on both.
    #[cfg(windows)]
    harness.get_by_label(tab::ARCHIVE_RESET_LINE);
    harness.get_by_label(tab::LEGACY_ARCHIVES_LINE);
    harness.get_by_label(tab::ERASE_ALL_LINE);
    harness.get_by_label(tab::SINGLE_ENTRIES_HINT);
    #[cfg(windows)]
    harness.get_by_label(tab::PORTABLE_EXPORT_TITLE);
    // The DASH-05 advisor: one paragraph behind a summary-carrying header.
    harness.get_by_label("34 active days retained • never blocks a delete");
    harness.get_by_label(tab::CONTINUITY_TITLE).click();
    harness.run();
    harness.get_by_label(
        "Deleting rewinds the history the pattern detectors draw on. It never breaks Gilbreth. \
         The floors: sequence and return patterns want 2 or more active days, new-this-week \
         flags want 14. You have 34 active days recorded (2026-06-05 to 2026-07-09) and 2 \
         archives beside the live database.",
    );
}

#[test]
fn privacy_exclusion_copy_names_the_next_start_boundary() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let harness = privacy_harness(privacy_snapshot_rich(), writes);

    // The exclusion editor's chip counts the configured apps; the helper
    // names the next-start boundary truthfully.
    harness.get_by_label(tab::EXCLUDED_APPS_LABEL);
    harness.get_by_label("1 APP");
    harness.get_by_label(tab::EXCLUDED_APPS_CAPTION);

    assert!(tab::EXCLUDED_APPS_CAPTION.contains("restart Gilbreth"));
    assert!(!tab::EXCLUDED_APPS_CAPTION.contains("stops future capture"));
}

#[cfg(windows)]
#[test]
fn privacy_plaintext_archive_export_requires_explicit_acknowledgement() {
    use gilbreth_dashboard::tabs::privacy as tab;

    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.portable_archive_sources = vec![PortableArchiveSource {
        id: "gilbreth-archive-100-deadbeef.gla".to_string(),
        label: "gilbreth-archive-100-deadbeef.gla".to_string(),
    }];
    let mut harness = privacy_harness(snapshot, writes.clone());
    harness.get_by_label(tab::PORTABLE_EXPORT_CAPTION);
    harness.get_by_label("Archive to export");
    harness
        .get_by_label("Plaintext copy (explicit choice)")
        .click();
    harness.run();
    harness.get_by_label(tab::PLAINTEXT_EXPORT_WARNING);

    harness.get_by_label("Export archive to Downloads").click();
    harness.run();
    #[cfg(windows)]
    assert!(writes.lock().unwrap().portable_archive_exports.is_empty());

    harness
        .get_by_label("I understand this copy is a full plaintext activity database")
        .click();
    harness.run();
    harness.get_by_label("Export archive to Downloads").click();
    harness.run();
    assert_eq!(
        writes.lock().unwrap().portable_archive_exports,
        vec![(
            "gilbreth-archive-100-deadbeef.gla".to_string(),
            PortableArchiveExportMode::PlaintextAcknowledged,
        )]
    );
    harness.get_by_label(
        "Portable archive copied to C:\\stub\\Downloads\\portable.gla. The source archive was retained.",
    );
}

#[cfg(windows)]
#[test]
fn privacy_passphrase_archive_export_requires_matching_nonempty_inputs() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.portable_archive_sources = vec![PortableArchiveSource {
        id: "gilbreth-archive-200-cafebabe.gla".to_string(),
        label: "gilbreth-archive-200-cafebabe.gla".to_string(),
    }];
    let mut harness = privacy_harness(snapshot, writes.clone());
    harness
        .get_all_by(|node| node.role() == egui::accesskit::Role::PasswordInput)
        .next()
        .expect("passphrase input")
        .focus();
    harness.run();
    harness
        .get_by(|node| node.role() == egui::accesskit::Role::PasswordInput && node.is_focused())
        .type_text("portable test passphrase");
    harness.run();
    harness
        .get(
            By::new()
                .role(egui::accesskit::Role::PasswordInput)
                .value(""),
        )
        .focus();
    harness.run();
    harness
        .get_by(|node| node.role() == egui::accesskit::Role::PasswordInput && node.is_focused())
        .type_text("portable test passphrase");
    harness.run();
    harness.get_by_label("Export archive to Downloads").click();
    harness.run();

    assert_eq!(
        writes.lock().unwrap().portable_archive_exports,
        vec![(
            "gilbreth-archive-200-cafebabe.gla".to_string(),
            PortableArchiveExportMode::Passphrase("portable test passphrase".to_string()),
        )]
    );
    assert_eq!(
        harness
            .get_all_by(|node| node.role() == egui::accesskit::Role::PasswordInput)
            .filter(|node| node.value().unwrap_or_default().is_empty())
            .count(),
        2,
        "passphrase buffers are cleared after the export attempt"
    );
}

/// B3: below the floors, the lines report the family-specific numerators
/// (one active day can already carry churn candidates; three pre-week days
/// can already carry quieter flags — the advisor no longer claims
/// otherwise).
#[test]
fn privacy_continuity_readiness_uses_family_specific_populations() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    if let Some(report) = snapshot.continuity.as_mut() {
        report.active_days = 1;
        report.pre_week_focus_days = 3;
    }
    let mut harness = privacy_harness(snapshot, writes);
    // Below the floors, the paragraph still makes no "enough history"
    // claim — it states the floors and this database's own counts.
    harness.get_by_label("1 active day retained • never blocks a delete");
    harness.get_by_label(tab::CONTINUITY_TITLE).click();
    harness.run();
    harness.get_by_label(
        "Deleting rewinds the history the pattern detectors draw on. It never breaks Gilbreth. \
         The floors: sequence and return patterns want 2 or more active days, new-this-week \
         flags want 14. You have 1 active day recorded (2026-06-05 to 2026-07-09) and 2 \
         archives beside the live database.",
    );
}

/// rB1 (2026-07-10 re-review): with one old and one recent active date,
/// the all-data Privacy line and a scoped Analytics below-floor caption
/// are simultaneously true statements — the advisor names its population
/// and points at the scoped windows instead of contradicting them.
#[test]
fn privacy_readiness_and_scoped_analytics_copy_coexist() {
    use gilbreth_dashboard::tabs::privacy as tab;
    use gilbreth_dashboard::tabs::widgets::patterns_empty_caption;
    let writes: SharedWrites = Arc::default();
    // Two active dates all-time; the default Last-7-days scope sees one.
    let mut analytics = rich_analytics_snapshot();
    if let Some(data) = analytics.data.as_mut() {
        data.pattern_history_days = 1;
        data.candidates = Vec::new();
    }
    let mut privacy = privacy_snapshot_rich();
    if let Some(report) = privacy.continuity.as_mut() {
        report.active_days = 2;
    }
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(rich_snapshot()),
        None,
        None,
        None,
        Some(analytics),
        None,
        Some(privacy),
        None,
        4200.0,
    );
    harness.get_by_label("Analytics").click();
    harness.run();
    harness.get_by_label(&patterns_empty_caption(1));
    harness.get_by_label("Privacy").click();
    harness.run();
    harness.get_by_label(tab::CONTINUITY_TITLE).click();
    harness.run();
    // The paragraph states the all-data count while the scoped Analytics
    // caption reports its own window — both literally true at once because
    // the advisor claims counts and floors, never readiness.
    harness.get_by_label(
        "Deleting rewinds the history the pattern detectors draw on. It never breaks Gilbreth. \
         The floors: sequence and return patterns want 2 or more active days, new-this-week \
         flags want 14. You have 2 active days recorded (2026-06-05 to 2026-07-09) and 2 \
         archives beside the live database.",
    );
}

/// r3-B1: one ten-day-old and one today active date, built through the
/// REAL snapshot readers over a canonical migrated database. Today's Worth
/// Noticing detectors (rolling 14-day baseline) render recurring-sequence
/// cards while the Last-7 caption population holds one day — and every
/// Privacy advisor sentence stays literally true beside them.
#[test]
fn privacy_advisor_copy_is_true_beside_todays_real_detectors() {
    use gilbreth_dashboard::data::{
        build_privacy_snapshot_for_tests, build_today_snapshot_for_tests,
    };
    use gilbreth_dashboard::tabs::privacy as tab;
    use gilbreth_dashboard::tabs::widgets::patterns_empty_caption;

    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("gilbreth.db");
    {
        // The store's migrations produce the canonical schema; drop the
        // writer before the readers open the file.
        let _store =
            gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
    }
    // r4-SF-1: "today" comes from the runner's own local calendar (the
    // readers' `local_day_start_ms` over a fixed instant), never the AKDT
    // `DAY_START` constant — the rows below must be today/ten-days-ago in
    // every timezone this suite runs in.
    let today_start = gilbreth_read::local_day_start_ms(DAY_START + 17 * HOUR_MS);
    let now_ms = today_start + 17 * HOUR_MS;
    let day_ms = 24 * HOUR_MS;
    let conn = rusqlite::Connection::open(&db_path).expect("open fixture");
    // Seventeen alternating a.exe/b.exe focus steps ten days ago and again
    // today: the sequence detector's two-date recurrence gate opens on the
    // 14-day discovery baseline (with today's examples rendering cards)
    // while Last 7 days holds one date.
    for (session_id, day_start) in [(1, today_start - 10 * day_ms), (2, today_start)] {
        conn.execute(
            "INSERT INTO sessions (session_id, started_at, ended_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![session_id, day_start, day_start + 2 * HOUR_MS],
        )
        .expect("insert session");
        for step in 0..17_i64 {
            let (prev_exe, next_exe) = if step % 2 == 0 {
                ("a.exe", "b.exe")
            } else {
                ("b.exe", "a.exe")
            };
            conn.execute(
                "INSERT INTO events (session_id, seq, ts, source, kind, exe, prev_exe, \
                 duration_ms, payload) VALUES (?1, ?2, ?3, 'foreground', 'focus_changed', ?4, \
                 ?5, 60000, '{}')",
                rusqlite::params![
                    session_id,
                    step + 1,
                    day_start + HOUR_MS + step * 61_000,
                    next_exe,
                    prev_exe
                ],
            )
            .expect("insert focus step");
        }
    }
    drop(conn);

    let mut host = stub_host_recording(Arc::default());
    host.db_path = db_path;
    let today = build_today_snapshot_for_tests(&host, now_ms);
    assert_eq!(
        today.pattern_history_days, 1,
        "the Last-7 caption population must see exactly one active date"
    );
    let sequence_title = today
        .notices
        .iter()
        .find(|notice| notice.notice_type == "recurring_sequence")
        .map(|notice| notice.title.clone())
        .expect("the 14-day baseline must already carry a recurring sequence");
    let privacy = build_privacy_snapshot_for_tests(&host, now_ms);
    let report = privacy.continuity.as_ref().expect("continuity report");
    assert_eq!(report.active_days, 2);
    assert_eq!(report.pre_week_focus_days, 1);
    let first_date = report.first_date.clone().expect("first date");
    let last_date = report.last_date.clone().expect("last date");
    let archives = match report.archive_count {
        0 => "no archives".to_string(),
        1 => "1 archive".to_string(),
        count => format!("{count} archives"),
    };

    // Render both tabs from the reader-built snapshots: the real card is
    // on Today (not the below-floor caption), and the advisor's sentences
    // are all literally true beside it.
    let mut harness = harness_with_host(
        stub_host_recording(Arc::default()),
        Some(today),
        None,
        None,
        None,
        None,
        None,
        Some(privacy),
        None,
        4200.0,
    );
    harness.get_by_label_contains(&sequence_title);
    assert!(harness.query_by_label(&patterns_empty_caption(1)).is_none());
    harness.get_by_label("Privacy").click();
    harness.run();
    harness.get_by_label(tab::CONTINUITY_TITLE).click();
    harness.run();
    // The advisor paragraph over the REAL reader's report: the all-data
    // count beside Today's real card, both literally true.
    harness.get_by_label_contains("Deleting rewinds the history");
    let expected = format!(
        "Deleting rewinds the history the pattern detectors draw on. It never breaks Gilbreth. \
         The floors: sequence and return patterns want 2 or more active days, new-this-week \
         flags want 14. You have 2 active days recorded ({first_date} to {last_date}) and \
         {archives} beside the live database.",
    );
    harness.get_by_label(&expected);
}

/// r4-B1: return tolls are the one Worth Noticing family computed from
/// today alone, proven in both directions through the real readers — a
/// database whose ONLY rows are today's produces a real return-toll
/// card, and matching returns ten days back change none of its numbers.
/// The advisor sentence rendered beside the card is pinned as a string
/// literal (not `TODAY_BASELINE_LINE`), so copy that re-assigns this
/// family a multi-day baseline fails here.
#[test]
fn privacy_advisor_names_return_tolls_today_only_scope() {
    use gilbreth_dashboard::data::{
        build_privacy_snapshot_for_tests, build_today_snapshot_for_tests,
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("gilbreth.db");
    {
        // The store's migrations produce the canonical schema; drop the
        // writer before the readers open the file.
        let _store =
            gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
    }
    let today_start = gilbreth_read::local_day_start_ms(DAY_START + 17 * HOUR_MS);
    let now_ms = today_start + 17 * HOUR_MS;
    let conn = rusqlite::Connection::open(&db_path).expect("open fixture");
    conn.execute(
        "INSERT INTO sessions (session_id, started_at, ended_at) VALUES (1, ?1, ?2)",
        rusqlite::params![today_start, today_start + 2 * HOUR_MS],
    )
    .expect("insert session");
    // Seven contiguous one-minute dwells a/b/a/b/a/b/a from an hour into
    // today; each focus_changed row closes the dwell named by `prev_exe`.
    // The three a.exe return dwells (runs 2, 4, 6) each get one key event
    // five seconds in, so all three A->B->A round trips carry a measured
    // restart — exactly the notice floor — while the B->A trips stay
    // unmeasured and emit nothing.
    let base = today_start + HOUR_MS;
    let minute = 60_000_i64;
    for step in 0..7_i64 {
        let (dwell_exe, next_exe) = if step % 2 == 0 {
            ("a.exe", "b.exe")
        } else {
            ("b.exe", "a.exe")
        };
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, source, kind, exe, prev_exe, duration_ms, \
             payload) VALUES (1, ?1, ?2, 'foreground', 'focus_changed', ?3, ?4, ?5, '{}')",
            rusqlite::params![
                step + 1,
                base + (step + 1) * minute,
                next_exe,
                dwell_exe,
                minute
            ],
        )
        .expect("insert focus dwell");
        if step % 2 == 0 && step > 0 {
            conn.execute(
                "INSERT INTO events (session_id, seq, ts, source, kind, exe, duration_ms, \
                 payload) VALUES (1, ?1, ?2, 'keyboard', 'key', 'a.exe', 0, '{}')",
                rusqlite::params![100 + step, base + step * minute + 5_000],
            )
            .expect("insert productive key");
        }
    }
    drop(conn);

    let mut host = stub_host_recording(Arc::default());
    host.db_path = db_path;
    let today = build_today_snapshot_for_tests(&host, now_ms);
    let toll = today
        .notices
        .iter()
        .find(|notice| notice.notice_type == "return_toll")
        .expect("today-only data must already produce a return-toll notice");
    assert_eq!(
        (toll.support_count, toll.total_count),
        (3, 3),
        "all three of today's measured returns feed the card"
    );
    let toll_title = toll.title.clone();
    assert_eq!(toll_title, "a.exe -> b.exe -> a.exe");
    let privacy = build_privacy_snapshot_for_tests(&host, now_ms);

    let harness = harness_with_host(
        stub_host_recording(Arc::default()),
        Some(today),
        None,
        None,
        None,
        None,
        None,
        Some(privacy),
        None,
        2400.0,
    );
    // The real card is on Today under its Return toll family label. (The
    // advisor's per-family scope sentence retired with the D compression;
    // the scope guarantee itself is pinned below by the detector numbers.)
    harness.get_by_label_contains(&toll_title);
    harness.get_by_label_contains("RETURN TOLL");

    // The review's falsification probe, inverted: six slower matching
    // returns ten days earlier change nothing — a return-toll scope
    // widened to the discovery baseline lifts support to 9 and the
    // median to 30s, and fails here.
    let day_ms = 24 * HOUR_MS;
    let old_base = today_start - 10 * day_ms + HOUR_MS;
    let conn = rusqlite::Connection::open(&host.db_path).expect("reopen fixture");
    conn.execute(
        "INSERT INTO sessions (session_id, started_at, ended_at) VALUES (2, ?1, ?2)",
        rusqlite::params![old_base - HOUR_MS, old_base + HOUR_MS],
    )
    .expect("insert old session");
    for step in 0..13_i64 {
        let (dwell_exe, next_exe) = if step % 2 == 0 {
            ("a.exe", "b.exe")
        } else {
            ("b.exe", "a.exe")
        };
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, source, kind, exe, prev_exe, duration_ms, \
             payload) VALUES (2, ?1, ?2, 'foreground', 'focus_changed', ?3, ?4, ?5, '{}')",
            rusqlite::params![
                step + 1,
                old_base + (step + 1) * minute,
                next_exe,
                dwell_exe,
                minute
            ],
        )
        .expect("insert old focus dwell");
        if step % 2 == 0 && step > 0 {
            conn.execute(
                "INSERT INTO events (session_id, seq, ts, source, kind, exe, duration_ms, \
                 payload) VALUES (2, ?1, ?2, 'keyboard', 'key', 'a.exe', 0, '{}')",
                rusqlite::params![100 + step, old_base + step * minute + 30_000],
            )
            .expect("insert old productive key");
        }
    }
    drop(conn);
    let after = build_today_snapshot_for_tests(&host, now_ms);
    let toll_after = after
        .notices
        .iter()
        .find(|notice| notice.notice_type == "return_toll")
        .expect("the return-toll notice survives unrelated history");
    assert_eq!(
        (
            toll_after.support_count,
            toll_after.total_count,
            toll_after.median_restart_seconds,
        ),
        (3, 3, Some(5.0)),
        "ten-day-old matching returns must not add support or shift the median"
    );
}

#[test]
fn privacy_prune_needs_confirm_and_writes_through_host() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = privacy_harness(privacy_snapshot_rich(), writes.clone());
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().prune_calls.is_empty());
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(
            recorded.prune_calls,
            vec![DAY_START - 90 * 24 * HOUR_MS],
            "the prune must run at the previewed cutoff"
        );
    }
    harness.get_by_label(
        "Deleted 4223 entries (4200 activity events, 3 sessions, 12 recording steps, 1 \
         recordings, 2 record requests, 5 recording-data entries). The database was compacted \
         to reclaim the space.",
    );
}

#[test]
fn privacy_zero_preview_disables_the_prune() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.preview = Some(PrunePreview {
        cutoff_ms: DAY_START - 90 * 24 * HOUR_MS,
        events: 0,
        ended_empty_sessions: 0,
        action_events: 0,
        ended_empty_record_sessions: 0,
        record_requests: 0,
        selector_paths: 0,
    });
    let mut harness = privacy_harness(snapshot, writes.clone());
    harness.get_by_label("Nothing to delete. Nothing stored is older than 90 days.");
    // Both the confirmation and the delete stay inert at zero rows.
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().prune_calls.is_empty());
}

/// B4: while the live days input disagrees with the previewed cutoff, the
/// confirmation is dropped and deletion stays inert; the refreshed preview
/// re-arms it at the new cutoff. The edit drives the real prune-days
/// widget so the whole `SetPruneDays -> request_refresh_for` wiring is
/// under test (rSF-4: a removed refresh request must fail here).
#[test]
fn privacy_editing_days_disarms_the_stale_preview_until_it_catches_up() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let (mut harness, app) = shared_privacy_harness(privacy_snapshot_rich(), writes.clone());
    // Arm the confirmation against the 90-day preview.
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    // Type 3650 into the real days widget; the shown counts and the
    // destructive cutoff still belong to 90 days.
    let generation_before = app.borrow().privacy_generation_for_tests();
    let _ = app.borrow_mut().take_issued_requests_for_tests();
    harness
        .get_by(|node| node.value().as_deref() == Some("90"))
        .click();
    harness.run();
    // The click puts the DragValue into keyboard edit; type into the
    // focused editor and commit.
    harness.get_by(|node| node.is_focused()).type_text("3650");
    harness.run();
    harness.key_press(egui::Key::Enter);
    harness.run();
    assert_eq!(
        harness
            .ctx
            .data_mut(|data| data.get_temp::<i64>(tab::prune_days_id())),
        Some(3650),
        "the widget edit must land in the days buffer"
    );
    assert!(
        app.borrow().privacy_generation_for_tests() > generation_before,
        "the days edit must issue a fresh privacy read (SetPruneDays wiring)"
    );
    // The request must reach the worker boundary carrying the new days
    // value and the fresh generation; the completion injected below is
    // derived from the observed request, never invented.
    let issued = app.borrow_mut().take_issued_requests_for_tests();
    let (request_days, request_generation) = issued
        .iter()
        .rev()
        .find_map(|request| match request {
            gilbreth_dashboard::data::Request::RefreshPrivacy { days, generation } => {
                Some((*days, *generation))
            }
            _ => None,
        })
        .expect("the days edit must deliver a privacy request to the worker");
    assert_eq!(
        request_days,
        Some(3650),
        "the delivered request must carry the newly stored days value"
    );
    assert_eq!(
        request_generation,
        app.borrow().privacy_generation_for_tests()
    );
    harness.get_by_label(tab::UPDATING_PREVIEW_LABEL);
    // UX-32: the armed confirmation was dropped, and the drop is announced.
    harness.get_by_label(tab::CONFIRM_CLEARED_LABEL);
    // Branch review (UX-57): a dropped STALE completion must not clear the
    // in-flight cue while the newer read is still running.
    harness.get_by_label(shell::UPDATING_LABEL);
    {
        let stale = privacy_snapshot_rich(); // generation 0 < current
        let ctx = harness.ctx.clone();
        app.borrow_mut()
            .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(stale)));
    }
    harness.run();
    harness.get_by_label(shell::UPDATING_LABEL);
    assert!(harness.query_by_label("4,223 READY").is_none());
    // Clicking delete before the new preview returns must not delete at
    // the old cutoff.
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().prune_calls.is_empty());
    // Re-arming while stale stays inert too.
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().prune_calls.is_empty());

    // The refreshed preview arrives, answering exactly the observed
    // request; deletion re-arms at the cutoff those counts were computed
    // for.
    let new_cutoff = DAY_START - 3650 * 24 * HOUR_MS;
    let mut refreshed = privacy_snapshot_rich();
    refreshed.generation = request_generation;
    refreshed.prune_days = request_days.expect("asserted Some above");
    refreshed.preview = Some(PrunePreview {
        cutoff_ms: new_cutoff,
        events: 7,
        ended_empty_sessions: 0,
        action_events: 0,
        ended_empty_record_sessions: 0,
        record_requests: 0,
        selector_paths: 0,
    });
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(refreshed)));
    harness.run();
    harness.get_by_label("7 READY");
    // The caught-up preview clears the announcement.
    assert!(harness.query_by_label(tab::CONFIRM_CLEARED_LABEL).is_none());
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    assert_eq!(
        writes.lock().unwrap().prune_calls,
        vec![new_cutoff],
        "the prune must run at the refreshed cutoff, never the superseded one"
    );
}

/// B5: a successful save keeps the new rules in the editor while the held
/// snapshot still predates the write; stale completions are dropped and the
/// acknowledging refresh re-seeds from the saved config.
#[test]
fn privacy_save_never_reseeds_the_editor_from_the_stale_snapshot() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let (mut harness, app) = shared_privacy_harness(privacy_snapshot_rich(), writes.clone());
    // Replace the seeded "Bank"/"Therapy" rules with a new one and save.
    let titles_id = tab::advanced_buffer_id("titles");
    harness
        .ctx
        .data_mut(|data| data.insert_temp(titles_id, "New".to_string()));
    harness.run();
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.settings_writes.len(), 1);
        assert_eq!(
            recorded.settings_writes[0].redact_titles_containing,
            vec!["New".to_string()]
        );
    }
    // Frames later, the pre-save snapshot must not have resurrected the
    // old rules into the editor buffer.
    harness.run();
    harness.run();
    let buffer: Option<String> = harness.ctx.data_mut(|data| data.get_temp(titles_id));
    assert_eq!(buffer.as_deref(), Some("New"));

    // A completion from before the save (older generation) is dropped
    // outright rather than adopted.
    assert!(app.borrow().privacy_generation_for_tests() > 0);
    let mut stale = privacy_snapshot_rich();
    stale.counts.events = 999_999;
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(stale)));
    harness.run();
    assert!(harness.query_by_label("999,999").is_none());
    let buffer: Option<String> = harness.ctx.data_mut(|data| data.get_temp(titles_id));
    assert_eq!(buffer.as_deref(), Some("New"));

    // The post-save refresh acknowledges the write; the editor re-seeds
    // from the saved config and a later save writes the new rules again.
    let mut refreshed = privacy_snapshot_rich();
    refreshed.generation = app.borrow().privacy_generation_for_tests();
    refreshed.settings.redact_titles_containing = vec!["New".to_string()];
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(refreshed)));
    harness.run();
    harness.run();
    let buffer: Option<String> = harness.ctx.data_mut(|data| data.get_temp(titles_id));
    assert_eq!(buffer.as_deref(), Some("New"));
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 2);
    assert_eq!(
        recorded.settings_writes[1].redact_titles_containing,
        vec!["New".to_string()],
        "a later save must never write the pre-save rules back"
    );
}

/// Replace the content of the editor currently showing `current` with
/// `lines`, through real focus/select-all/text events — the same
/// `response.changed()` path a user's typing takes, so the revision
/// protection is armed by the production widgets (round-3 SF-1).
fn retype_text_edit(harness: &mut Harness<'static>, current: &str, lines: &[&str]) {
    harness
        .get(
            By::new()
                .role(egui::accesskit::Role::MultilineTextInput)
                .value(current),
        )
        .focus();
    harness.run();
    harness.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    harness.run();
    // Text events land in the focused editor; re-finding the input node by
    // its evolving value each step also asserts every keystroke arrived.
    let mut value = current.to_string();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            harness.key_press(egui::Key::Enter);
            harness.run();
            value.push('\n');
        }
        harness
            .get(
                By::new()
                    .role(egui::accesskit::Role::MultilineTextInput)
                    .value(value.as_str()),
            )
            .type_text(line);
        harness.run();
        if index == 0 {
            value = (*line).to_string();
        } else {
            value.push_str(line);
        }
    }
    // The editor ends up showing exactly the retyped content.
    harness.get(
        By::new()
            .role(egui::accesskit::Role::MultilineTextInput)
            .value(value.as_str()),
    );
}

/// Type a new line-list through the named empty Privacy editor. The
/// accessible row label is part of the discoverability contract: it lets a
/// user and assistive tech distinguish three otherwise-empty text areas.
fn type_empty_privacy_list(harness: &mut Harness<'static>, label: &str, lines: &[&str]) {
    assert!(!lines.is_empty());
    harness
        .get_by_role_and_label(egui::accesskit::Role::MultilineTextInput, label)
        .focus();
    harness.run();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            harness.key_press(egui::Key::Enter);
            harness.run();
        }
        harness.get_by(|node| node.is_focused()).type_text(line);
        harness.run();
    }
}

/// rB2 (2026-07-10 re-review): an acknowledgement for an earlier save must
/// not clear a buffer edited after that save — the queued second Save
/// writes the newer rules, never the acknowledged older ones. The edits
/// go through the real title editor.
#[test]
fn privacy_save_ack_preserves_edits_made_after_the_save() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let (mut harness, app) = shared_privacy_harness(privacy_snapshot_rich(), writes.clone());
    // Retype the title rules through the real editor and save (#1).
    retype_text_edit(&mut harness, "Bank\nTherapy", &["Saved"]);
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.settings_writes.len(), 1);
        assert_eq!(
            recorded.settings_writes[0].redact_titles_containing,
            vec!["Saved".to_string()]
        );
    }
    // Before the acknowledgement arrives, add the rule that matters —
    // again through the real editor.
    retype_text_edit(&mut harness, "Saved", &["Saved", "Secret Project"]);
    // Save #1's current-generation acknowledgement lands before the next
    // click frame; it reflects only the already-saved rule.
    let mut ack = privacy_snapshot_rich();
    ack.generation = app.borrow().privacy_generation_for_tests();
    ack.settings.redact_titles_containing = vec!["Saved".to_string()];
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(ack)));
    harness.run();
    // The newer edit survives the acknowledgement...
    let titles_id = tab::advanced_buffer_id("titles");
    let buffer: Option<String> = harness.ctx.data_mut(|data| data.get_temp(titles_id));
    assert_eq!(buffer.as_deref(), Some("Saved\nSecret Project"));
    // ...and the queued save writes it.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 2);
    assert_eq!(
        recorded.settings_writes[1].redact_titles_containing,
        vec!["Saved".to_string(), "Secret Project".to_string()],
        "the queued save must carry the edit made after the acknowledged save"
    );
}

/// rB2/SF-1: the suppression and confirmation checkboxes arm the same
/// revision protection — toggles made after a save survive that save's
/// acknowledgement, and the next save writes the toggled value.
#[test]
fn privacy_suppression_toggle_survives_the_earlier_ack() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let (mut harness, app) = shared_privacy_harness(privacy_snapshot_rich(), writes.clone());
    // Save #1 with suppression on.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    // Toggle suppression off and confirm — both through the real widgets.
    harness.get_by_label(tab::SUPPRESSION_LABEL).click();
    harness.run();
    harness.get_by_label(tab::DISABLE_CONFIRM_LABEL).click();
    harness.run();
    // Save #1's acknowledgement reflects suppression still on; the newer
    // toggles must survive it.
    let mut ack = privacy_snapshot_rich();
    ack.generation = app.borrow().privacy_generation_for_tests();
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(ack)));
    harness.run();
    harness.get_by_label(tab::SUPPRESSION_OFF_WARNING);
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 2);
    assert!(
        !recorded.settings_writes[1].sensitive_context_suppression,
        "the post-ack save must carry the suppression toggle made after save #1"
    );
}

/// r4-SF-2: the two retention `DragValue`s arm the same revision
/// protection as the editors and checkboxes — edits made through the
/// real widgets after a save survive that save's acknowledgement, and
/// the next save writes the edited values. Both retention IDs run the
/// same interleaving, so a removed revision bump on either widget resets
/// its buffer to the acknowledged value and fails here.
#[test]
fn privacy_retention_edits_survive_the_earlier_ack_on_both_widgets() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    // Distinct seeded values so each SpinButton is addressable by value.
    let mut fixture = privacy_snapshot_rich();
    fixture.settings.title_retention_days = 21;
    let (mut harness, app) = shared_privacy_harness(fixture, writes.clone());
    // Save #1 with the seeded retentions; arms its acknowledgement.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    {
        let recorded = writes.lock().unwrap();
        assert_eq!(recorded.settings_writes.len(), 1);
        assert_eq!(recorded.settings_writes[0].title_retention_days, 21);
        assert_eq!(recorded.settings_writes[0].mouse_move_retention_days, 30);
    }
    // Edit BOTH retention widgets through real click-and-type after the
    // save: title 21 -> 45, mouse 30 -> 60. The click puts the DragValue
    // into keyboard edit; typing replaces the selected value.
    for (seeded, edited) in [("21", "45"), ("30", "60")] {
        harness
            .get_by(|node| node.value().as_deref() == Some(seeded))
            .click();
        harness.run();
        harness.get_by(|node| node.is_focused()).type_text(edited);
        harness.run();
        harness.key_press(egui::Key::Enter);
        harness.run();
    }
    // Save #1's acknowledgement reflects the seeded retentions; the
    // newer widget edits must survive it.
    let mut ack = privacy_snapshot_rich();
    ack.settings.title_retention_days = 21;
    ack.generation = app.borrow().privacy_generation_for_tests();
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(ack)));
    harness.run();
    // The buffers hold the edits (a bump-less widget resets to 21/30)...
    let title_buffer: Option<i64> = harness
        .ctx
        .data_mut(|data| data.get_temp(tab::advanced_buffer_id("title-retention")));
    assert_eq!(
        title_buffer,
        Some(45),
        "the title-retention edit must survive the earlier save's ack"
    );
    let mouse_buffer: Option<i64> = harness
        .ctx
        .data_mut(|data| data.get_temp(tab::advanced_buffer_id("mouse-retention")));
    assert_eq!(
        mouse_buffer,
        Some(60),
        "the mouse-retention edit must survive the earlier save's ack"
    );
    // ...the real widgets still show them...
    harness.get_by(|node| node.value().as_deref() == Some("45"));
    harness.get_by(|node| node.value().as_deref() == Some("60"));
    // ...and the queued save writes them both.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 2);
    assert_eq!(
        (
            recorded.settings_writes[1].title_retention_days,
            recorded.settings_writes[1].mouse_move_retention_days,
        ),
        (45, 60),
        "the post-ack save must carry both retention edits"
    );
}

/// rB2: a success-then-fail sequence — input typed into a different field
/// after the successful save survives both the failed save and the earlier
/// save's acknowledgement (the failed-save retry contract).
#[test]
fn privacy_failed_save_keeps_newer_input_through_the_earlier_ack() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut host = stub_host_recording(writes.clone());
    let failing_writes = writes.clone();
    let calls = Arc::new(Mutex::new(0usize));
    host.write_privacy_settings = Box::new(move |values| {
        let mut count = calls.lock().unwrap();
        *count += 1;
        failing_writes
            .lock()
            .unwrap()
            .settings_writes
            .push(values.clone());
        if *count >= 2 {
            Err("disk unavailable".to_string())
        } else {
            Ok(())
        }
    });
    // Seed the key editor with a visible rule so the real widget can be
    // addressed by value.
    let mut fixture = privacy_snapshot_rich();
    fixture.settings.redact_keys_containing = vec!["OldKey".to_string()];
    let (mut harness, app) = shared_privacy_harness_with_host(host, fixture);
    // Save #1 succeeds with the seeded values and arms its acknowledgement.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    // Edit a different field through the real key editor, then a save
    // that fails.
    retype_text_edit(&mut harness, "OldKey", &["Password"]);
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    harness.get_by_label("Couldn't save your privacy settings. Technical detail: disk unavailable");
    // Save #1's acknowledgement arrives after the failure; the input the
    // failed save should have preserved must not be wiped by it.
    let mut ack = privacy_snapshot_rich();
    ack.settings.redact_keys_containing = vec!["OldKey".to_string()];
    ack.generation = app.borrow().privacy_generation_for_tests();
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Privacy(Box::new(ack)));
    harness.run();
    let keys_id = tab::advanced_buffer_id("keys");
    let buffer: Option<String> = harness.ctx.data_mut(|data| data.get_temp(keys_id));
    assert_eq!(
        buffer.as_deref(),
        Some("Password"),
        "failed-save input must survive the earlier save's acknowledgement"
    );
}

#[test]
fn privacy_settings_save_writes_seeded_values_through_host() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = privacy_harness(privacy_snapshot_rich(), writes.clone());
    harness.get_by_label(tab::SUPPRESSION_LABEL);
    harness.get_by_label(tab::TITLE_PATTERNS_LABEL);
    harness.get_by_label(tab::EXCLUDED_APPS_LABEL);
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(
        recorded.settings_writes,
        vec![PrivacySettingsValues {
            sensitive_context_suppression: true,
            redact_titles_containing: vec!["Bank".to_string(), "Therapy".to_string()],
            redact_keys_containing: Vec::new(),
            excluded_apps: vec!["private.exe".to_string()],
            title_retention_days: 0,
            mouse_move_retention_days: 30,
        }]
    );
}

#[test]
fn privacy_empty_list_editors_explain_and_save_direct_edits() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.settings.redact_titles_containing.clear();
    snapshot.settings.redact_keys_containing.clear();
    snapshot.settings.excluded_apps.clear();
    let mut harness = privacy_harness(snapshot, writes.clone());

    harness.get_by_label(tab::SETTINGS_EDIT_CAPTION);
    harness.get_by_label(tab::SAVE_SETTINGS_HINT);
    assert_eq!(harness.get_all_by_label("0 RULES").count(), 2);
    harness.get_by_label("0 APPS");

    for (label, placeholder) in [
        (tab::TITLE_PATTERNS_LABEL, tab::TITLE_PATTERNS_PLACEHOLDER),
        (tab::KEY_PATTERNS_LABEL, tab::KEY_PATTERNS_PLACEHOLDER),
        (tab::EXCLUDED_APPS_LABEL, tab::EXCLUDED_APPS_PLACEHOLDER),
    ] {
        harness.get_by(|node| {
            node.role() == egui::accesskit::Role::MultilineTextInput
                && node.label().as_deref() == Some(label)
                && node.placeholder() == Some(placeholder)
        });
    }

    type_empty_privacy_list(
        &mut harness,
        tab::TITLE_PATTERNS_LABEL,
        &["Bank", "Therapy"],
    );
    type_empty_privacy_list(&mut harness, tab::KEY_PATTERNS_LABEL, &["Enter"]);
    type_empty_privacy_list(&mut harness, tab::EXCLUDED_APPS_LABEL, &["private.exe"]);

    harness.get_by_label("2 RULES");
    harness.get_by_label("1 RULE");
    harness.get_by_label("1 APP");
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();

    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 1);
    assert_eq!(
        recorded.settings_writes[0].redact_titles_containing,
        vec!["Bank".to_string(), "Therapy".to_string()]
    );
    assert_eq!(
        recorded.settings_writes[0].redact_keys_containing,
        vec!["Enter".to_string()]
    );
    assert_eq!(
        recorded.settings_writes[0].excluded_apps,
        vec!["private.exe".to_string()]
    );
}

#[test]
fn privacy_suppression_off_requires_the_extra_confirm() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.settings.sensitive_context_suppression = false;
    let mut harness = privacy_harness(snapshot, writes.clone());
    harness.get_by_label(tab::SUPPRESSION_OFF_WARNING);
    // Unconfirmed: the save button is disabled.
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    assert!(writes.lock().unwrap().settings_writes.is_empty());
    harness.get_by_label(tab::DISABLE_CONFIRM_LABEL).click();
    harness.run();
    harness.get_by_label(tab::SAVE_SETTINGS_LABEL).click();
    harness.run();
    let recorded = writes.lock().unwrap();
    assert_eq!(recorded.settings_writes.len(), 1);
    assert!(!recorded.settings_writes[0].sensitive_context_suppression);
}

#[test]
fn privacy_malformed_config_blocks_the_editor() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = privacy_snapshot_rich();
    snapshot.settings.error = Some("TOML parse error; source text omitted".to_string());
    let harness = privacy_harness(snapshot, writes);
    harness.get_by_label(
        "config.toml is malformed, so privacy settings cannot be saved from the dashboard: \
         TOML parse error; source text omitted",
    );
    assert!(harness.query_by_label(tab::SAVE_SETTINGS_LABEL).is_none());
    // The malformed read also hides the keystroke/titles posture lines.
    assert!(harness
        .query_by_label(&format!("Keystrokes: {}", tab::KEYSTROKES_OFF_LINE))
        .is_none());
}

#[test]
fn privacy_loading_state_before_first_read() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for(Some(rich_snapshot()), None, written);
    harness.run();
    harness.get_by_label("Privacy").click();
    harness.run();
    harness.get_by_label("Reading your data overview…");
}

#[test]
fn diagnostics_renders_health_recorder_mix_and_install() {
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = diagnostics_harness(diagnostics_snapshot_rich(), writes);
    // The verdict band: PASS chip, owner-worded product voice counting the
    // one finding (the churn flag), and the method sub-line.
    harness.get_by_label("PASS");
    harness.get_by_label("All checks healthy — one thing worth a look below.");
    harness.get_by_label(tab::VERDICT_METHOD_CAPTION);
    // The finding renders as a red-pencil flag row with its evidence.
    harness.get_by_label("⚑");
    harness.get_by_label("Sustained process churn: updater.exe.");
    harness.get_by_label(
        "A program restarting this often can point at a crash loop or a runaway updater.",
    );
    harness.get_by_label(
        "The filter kept the evidence: 8,432 routine transitions in 7 days counted instead \
         of stored (61 summary rows); biggest churners: updater.exe (5,120), helper.exe \
         (3,312).",
    );
    // One gauge grid, Capture vocabulary, no hover-help glyphs anywhere
    // (ⓘ retired with the redesign).
    harness.get_by_label("Capture");
    harness.get_by_label("Active");
    harness.get_by_label("14s ago");
    harness.get_by_label("Events last 5 min");
    harness.get_by_label("231");
    harness.get_by_label("75.0 MB");
    // Merged gauge values read value-then-quiet-suffix (amendment §7).
    harness.get_by_label("20 • 12,408 events");
    harness.get_by_label("2 • 1 recovered");
    harness.get_by_label("45m 12s raw • 32m 30s active");
    assert!(
        harness
            .query_by_label(gilbreth_dashboard::tabs::widgets::HELP_GLYPH)
            .is_none(),
        "the redesigned tab retires every ⓘ affordance"
    );
    assert!(
        harness.query_by_label("Recorder").is_none(),
        "the Recorder vocabulary is fully renamed to Capture"
    );
    // Health check: open by default, aligned check table in review_run.py's
    // vocabulary, the log-window caption, and the summary-carrying header.
    harness.get_by_label("Health check");
    harness.get_by_label("all clean • 2 known warnings");
    harness.get_by_label("Database integrity");
    harness.get_by_label("Foreign keys • sequence continuity");
    harness.get_by_label("0 issues • ok");
    harness.get_by_label("clipboard-locked 1 • orphan-repair 1");
    harness.get_by_label(tab::LOG_WINDOW_CAPTION);
    // Capture mix: summary on the header, share rows behind it.
    harness.get_by_label("3 sources • mouse leads").click();
    harness.run();
    harness.get_by_label("keyboard");
    harness.get_by_label("121,004");
    harness.get_by_label("56%");
    // Capture details: the old details box as an aligned table.
    harness.get_by_label("Capture details").click();
    harness.run();
    harness.get_by_label("2026-07-09 17:02:41");
    harness.get_by_label("1.0 MB");
    harness.get_by_label("2026-07-09 06:12:03");
    harness.get_by_label("studio.exe • studio.exe");
    harness.get_by_label("12 rows (your settings working)");
    // Privacy & controls: the Phase 6 facts stay visible and pinned.
    harness.get_by_label("Privacy & controls");
    harness
        .get_by_label("1 app excluded • 3 plaintext archives")
        .click();
    harness.run();
    let exclusion_copy = format!(
        "1 app configured for exclusion. {}",
        tab::EXCLUDED_APPS_DIAGNOSTIC_SUFFIX
    );
    harness.get_by_label(&exclusion_copy);
    assert!(tab::EXCLUDED_APPS_DIAGNOSTIC_SUFFIX.contains("next Gilbreth start"));
    assert!(!tab::EXCLUDED_APPS_DIAGNOSTIC_SUFFIX.contains("apps excluded"));
    harness.get_by_label("Configured apps: private.exe");
    harness.get_by_label("3 archives predate encryption — plaintext.");
    harness.get_by_label(tab::LEGACY_PLAINTEXT_ARCHIVES_EXPLAINER);
    // Install & autostart: summary + rows + the UX-49 sentence.
    harness.get_by_label("Install & autostart");
    harness
        .get_by_label("f763c76d0569 • autostart configured")
        .click();
    harness.run();
    harness.get_by_label("f763c76d0569");
    harness.get_by_label("Configured");
    // The config file location moved here from the Privacy tab (D §4).
    harness.get_by_label("Config");
    harness.get_by_label("Z:/nonexistent/config.toml");
    harness.get_by_label("Build source: sessions.git_sha");
    harness.get_by_label(
        "Autostart target: C:\\Users\\dev\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe",
    );
}

/// The empty-findings state renders zero red pencil: no flag glyph, no
/// flag rows, and the verdict reads the plain healthy sentence.
#[test]
fn diagnostics_zero_findings_renders_no_red() {
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.churn.as_mut().unwrap().sustained_exes.clear();
    let harness = diagnostics_harness(snapshot, writes);
    harness.get_by_label("PASS");
    harness.get_by_label(tab::ALL_CHECKS_HEALTHY);
    assert!(
        harness.query_by_label("⚑").is_none(),
        "no findings means no flag rows and no red on the page"
    );
    assert!(
        harness
            .query_by_label("All checks healthy — one thing worth a look below.")
            .is_none(),
        "the worth-a-look sentence appears only with findings"
    );
}

#[test]
fn diagnostics_review_verdict_names_its_reasons() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    {
        let health = snapshot.health.as_mut().unwrap();
        health.seq_gap_sessions = vec![4, 7];
        health.capture_events_dropped = -1;
    }
    {
        let logs = snapshot.logs.as_mut().unwrap();
        logs.warning_lines = 4;
    }
    let harness = diagnostics_harness(snapshot, writes);
    harness.get_by_label("REVIEW");
    harness.get_by_label(
        "Reasons: sequence gaps in sessions 4, 7; capture drop counter unparseable; unknown \
         log warnings=2",
    );
    // The check table carries the same story in its aligned rows, red where
    // flagged.
    harness.get_by_label("0 issues • gaps in sessions 4, 7");
    harness.get_by_label("unparseable • 0");
    harness.get_by_label("3 reasons • 2 known warnings");
}

/// UX-47 (owner decision 2026-07-10, one-sided): the acknowledged log
/// baseline flips the headline to PASS while counts stay at the
/// acknowledged levels, keeps the byte-parity reason wording in the
/// baseline caption, and re-alarms only on deltas above it.
#[test]
fn diagnostics_acknowledged_baseline_gates_the_review_headline() {
    use gilbreth_dashboard::data::Snapshot;
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let mut snapshot = diagnostics_snapshot_rich();
    {
        // The standing dev-log noise: 138 unknown warnings, 15 errors.
        let logs = snapshot.logs.as_mut().unwrap();
        logs.warning_lines = 140;
        logs.error_panic_lines = 15;
    }
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(stub_host_recording(Arc::default())),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(snapshot),
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, 2400.0))
        .build_ui(move |ui| {
            if !styled.get() {
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    harness.get_by_label("Diagnostics").click();
    harness.run();
    // The absolute verdict, byte-parity wording.
    harness.get_by_label("REVIEW");
    harness.get_by_label("Reasons: unknown log warnings=138; log errors/panics=15");
    harness.get_by_label(tab::ACKNOWLEDGE_LOGS_LABEL).click();
    harness.run();
    // Acknowledged: the headline reads PASS with the dated baseline.
    harness.get_by_label("PASS");
    let date = gilbreth_read::local_date(DAY_START + 17 * HOUR_MS);
    // Branch review (UX-47): the caption states the measured count
    // comparison, not a "no new lines" claim.
    harness.get_by_label(&format!(
        "Unknown/error log counts at or below the baseline acknowledged {date}."
    ));
    harness.get_by_label(&format!(
        "Acknowledged baseline ({date}): unknown log warnings=138; log errors/panics=15. The absolute check reads REVIEW until these counts are zero."
    ));
    harness.get_by_label(tab::CLEAR_BASELINE_LABEL);
    // Counts rising past the baseline re-alarm the headline with the raw
    // reasons and the exceeded note.
    let mut worse = diagnostics_snapshot_rich();
    {
        let logs = worse.logs.as_mut().unwrap();
        logs.warning_lines = 143;
        logs.error_panic_lines = 15;
    }
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Diagnostics(Box::new(worse)));
    harness.run();
    harness.get_by_label("REVIEW");
    harness.get_by_label("Reasons: unknown log warnings=141; log errors/panics=15");
    harness.get_by_label(&format!(
        "Counts rose past the baseline acknowledged {date} (unknown log warnings=138, log errors/panics=15)."
    ));
}

#[test]
fn diagnostics_autostart_warnings_surface() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    {
        let install = snapshot.install.as_mut().unwrap();
        install.autostart_path_exists = false;
    }
    let harness = diagnostics_harness(snapshot, writes);
    harness.get_by_label("Missing target");
    harness.get_by_label("Autostart target does not exist.");
}

#[test]
fn diagnostics_pause_hotkey_registration_warning_surfaces() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.pause_hotkey_warning = Some(
        "pause hotkey unregistered (chord owned by another app); tray Pause remains available."
            .to_string(),
    );
    let harness = diagnostics_harness(snapshot, writes);

    // The warning lives in the Privacy & controls section, which opens by
    // default while it is up and carries it in the header summary.
    harness.get_by_label("Privacy & controls");
    harness.get_by_label("pause hotkey unregistered • 1 app excluded • 3 plaintext archives");
    harness.get_by_label(
        "pause hotkey unregistered (chord owned by another app); tray Pause remains available.",
    );
}

#[test]
fn diagnostics_empty_capture_mix_says_so() {
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.debug.as_mut().unwrap().source_counts.clear();
    let mut harness = diagnostics_harness(snapshot, writes);
    harness.get_by_label("no events yet").click();
    harness.run();
    harness.get_by_label(tab::NO_EVENTS_INFO);
}

/// UX-04: on an empty day the pattern-floor caption appears exactly once
/// inside the state-neutral receipt, and the notice section stays out
/// rather than repeating it.
#[test]
fn today_empty_day_shows_the_pattern_floor_caption_once() {
    use gilbreth_dashboard::tabs::widgets::patterns_empty_caption;
    let written: WrittenStates = Arc::default();
    let mut snapshot = rich_snapshot();
    snapshot.db_missing = false;
    snapshot.strip.focus.clear();
    snapshot.strip.away.clear();
    snapshot.pulse.clear();
    snapshot.daily.clear();
    snapshot.notices.clear();
    snapshot.pattern_history_days = 1;
    let mut harness = harness_for(Some(snapshot), None, written);
    harness.run();
    assert_eq!(
        harness.get_all_by_label(&patterns_empty_caption(1)).count(),
        1,
        "the pattern-floor caption must render exactly once on an empty day (UX-04)"
    );
    assert!(harness.query_by_label("WORTH NOTICING").is_none());
    assert!(harness.query_by_label("WHEN YOU WERE ACTIVE").is_none());
    assert!(harness.query_by_label("TODAY SO FAR").is_none());
}

/// UX-05: a snapshot carrying neither data nor an error renders an
/// explanatory box, never a completely blank tab.
#[test]
fn analytics_empty_snapshot_states_itself_instead_of_blank() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_analytics_snapshot();
    snapshot.data = None;
    snapshot.error = None;
    snapshot.db_missing = false;
    let harness = analytics_harness(snapshot, writes);
    harness.get_by_label(gilbreth_dashboard::tabs::analytics::NO_ANALYTICS_DATA_INFO);
}

/// UX-06 (UI half): when the health read failed, the verdict slot renders
/// a placeholder beside the surviving sections instead of vanishing.
#[test]
fn diagnostics_partial_failure_keeps_the_verdict_slot() {
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.health = None;
    snapshot.logs = None;
    snapshot.error =
        Some("Couldn't read part of the diagnostics — health check: disk I/O error".to_string());
    let harness = diagnostics_harness(snapshot, writes);
    harness.get_by_label(tab::HEALTH_UNAVAILABLE);
    // The surviving sections still render around the placeholder band.
    harness.get_by_label("Capture");
    harness.get_by_label("Active");
}

/// The macOS permissions panel renders each grant's state, its explainer,
/// and the right action button; a click emits the action to the host. The
/// panel is present only when the host publishes grant state (macOS), so a
/// Some(..) snapshot stands in for that here.
#[test]
fn diagnostics_permissions_panel_renders_states_and_emits_actions() {
    use gilbreth_dashboard::data::{PermissionRowState, PermissionSnapshot};
    use gilbreth_dashboard::tabs::diagnostics as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.permissions = Some(PermissionSnapshot {
        accessibility: PermissionRowState::NotGranted,
        input_monitoring: PermissionRowState::GrantedNeedsRelaunch,
    });
    let mut harness = diagnostics_harness(snapshot, writes.clone());

    // The section opens by default while anything needs action; the header
    // summary states the panel's story, and the chips carry the states.
    harness.get_by_label("Permissions");
    harness.get_by_label("1 of 2 granted • relaunch needed");
    harness.get_by_label("Accessibility");
    harness.get_by_label("OFF");
    harness.get_by_label(tab::ACCESSIBILITY_EXPLAINER);
    harness.get_by_label("Input Monitoring");
    harness.get_by_label("GRANTED");
    harness.get_by_label(tab::INPUT_MONITORING_RELAUNCH_CAPTION);

    // The not-granted row offers request + deep-link; clicking Request
    // access emits the prompt action (the pump, not the dashboard, prompts).
    harness.get_by_label("Request access").click();
    harness.run();
    assert_eq!(
        writes.lock().unwrap().permission_actions,
        vec![gilbreth_dashboard::data::PermissionActionRequest::PromptAccessibility]
    );

    // The needs-relaunch row offers Relaunch to activate.
    harness.get_by_label("Relaunch to activate").click();
    harness.run();
    assert_eq!(
        writes.lock().unwrap().permission_actions,
        vec![
            gilbreth_dashboard::data::PermissionActionRequest::PromptAccessibility,
            gilbreth_dashboard::data::PermissionActionRequest::Relaunch,
        ]
    );
}

/// A granted permission shows no action button — nothing to do, no nag.
#[test]
fn diagnostics_permissions_panel_is_quiet_when_granted() {
    use gilbreth_dashboard::data::{PermissionRowState, PermissionSnapshot};
    let writes: SharedWrites = Arc::default();
    let mut snapshot = diagnostics_snapshot_rich();
    snapshot.permissions = Some(PermissionSnapshot {
        accessibility: PermissionRowState::Granted,
        input_monitoring: PermissionRowState::Granted,
    });
    let mut harness = diagnostics_harness(snapshot, writes);
    // Fully granted: the section rests collapsed, its summary carrying the
    // whole story; opening it shows two quiet chips and no action buttons.
    harness.get_by_label("Permissions");
    harness.get_by_label("both granted").click();
    harness.run();
    assert_eq!(
        harness.get_all_by_label("GRANTED").count(),
        2,
        "both rows show the granted chip"
    );
    assert!(
        harness.query_by_label("Request access").is_none(),
        "a granted permission offers no action button"
    );
    assert!(
        harness.query_by_label("Relaunch to activate").is_none(),
        "a fully-granted panel needs no relaunch"
    );
}

/// UX-06 (reader half): one failing section reader no longer aborts the
/// sections after it — a database whose `sessions` table is gone still
/// yields the health verdict (and churn), with the failure named on the
/// snapshot error.
#[test]
fn diagnostics_reader_survives_a_failing_section() {
    use gilbreth_dashboard::data::build_diagnostics_snapshot_for_tests;
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("gilbreth.db");
    {
        let _store =
            gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
    }
    let conn = rusqlite::Connection::open(&db_path).expect("open fixture");
    conn.execute_batch("DROP TABLE sessions;")
        .expect("drop sessions");
    drop(conn);
    let mut host = stub_host_recording(Arc::default());
    host.db_path = db_path;
    let snapshot = build_diagnostics_snapshot_for_tests(&host, DAY_START + 17 * HOUR_MS);
    assert!(
        snapshot.debug.is_none(),
        "the recorder read is expected to fail without a sessions table"
    );
    assert!(
        snapshot.health.is_some() && snapshot.logs.is_some(),
        "the health verdict must survive an earlier section's failure (UX-06)"
    );
    let error = snapshot.error.expect("the partial failure is surfaced");
    assert!(error.contains("Couldn't read part of the diagnostics"));
}

/// UX-07: at widths where the heatmap's fixed gutters would invert the
/// grid rect, a message renders instead of negative-width cells.
#[test]
fn heatmap_narrow_width_falls_back_to_a_message() {
    let buckets = vec![heat_bucket(0, 9, 30.0)];
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(140.0, 260.0))
        .build_ui(move |ui| {
            gilbreth_dashboard::charts::weekday_hour_heatmap(ui, &buckets);
        });
    harness.run();
    harness.get_by_label(gilbreth_dashboard::charts::HEATMAP_TOO_NARROW);
}

/// UX-20: one-shot outcome notices don't outlive their tab — switching
/// away and back must not re-show an old "Deleted N entries" line as if
/// it were current status.
#[test]
fn one_shot_notices_clear_on_tab_switch() {
    use gilbreth_dashboard::tabs::privacy as tab;
    let writes: SharedWrites = Arc::default();
    let mut harness = privacy_harness(privacy_snapshot_rich(), writes);
    harness.get_by_label(tab::CONFIRM_PRUNE_LABEL).click();
    harness.run();
    harness.get_by_label(tab::PRUNE_BUTTON_LABEL).click();
    harness.run();
    harness.get_by_label_contains("Deleted 4223 entries");
    harness.get_by_label("Today").click();
    harness.run();
    harness.get_by_label("Privacy").click();
    harness.run();
    assert!(
        harness
            .query_by_label_contains("Deleted 4223 entries")
            .is_none(),
        "the prune notice must not survive a tab switch (UX-20)"
    );
}

#[cfg(windows)]
/// UX-26: a several-hundred-step recording renders inside a bounded
/// scroll region, so the export/delete controls stay reachable instead
/// of landing thousands of pixels down the page.
#[test]
fn recordings_long_step_list_stays_bounded() {
    use gilbreth_dashboard::tabs::recordings as tab;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    {
        let detail = snapshot.detail.as_mut().unwrap();
        let template = detail.steps[0].clone();
        detail.steps = (1..=400)
            .map(|seq| {
                let mut step = template.clone();
                step.seq = seq;
                step
            })
            .collect();
    }
    let harness = recordings_harness(snapshot, writes);
    let delete_top = harness.get_by_label(tab::DELETE_BUTTON_LABEL).rect().top();
    assert!(
        delete_top < 2600.0,
        "the delete controls must stay within the page when 400 steps render (UX-26); found them at y={delete_top}"
    );
}

/// One a->b->a return-toll pair with three measured returns (the r4-B1
/// fixture shape): seven one-minute dwells alternating anchor/diverter,
/// a key event five seconds into each anchor return.
fn insert_return_toll_pair(
    conn: &rusqlite::Connection,
    session_id: i64,
    seq_base: i64,
    base_ts: i64,
    anchor: &str,
    diverter: &str,
) {
    let minute = 60_000_i64;
    for step in 0..7_i64 {
        let (dwell_exe, next_exe) = if step % 2 == 0 {
            (anchor, diverter)
        } else {
            (diverter, anchor)
        };
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, source, kind, exe, prev_exe, duration_ms, \
             payload) VALUES (?1, ?2, ?3, 'foreground', 'focus_changed', ?4, ?5, ?6, '{}')",
            rusqlite::params![
                session_id,
                seq_base + step,
                base_ts + (step + 1) * minute,
                next_exe,
                dwell_exe,
                minute
            ],
        )
        .expect("insert focus dwell");
        if step % 2 == 0 && step > 0 {
            conn.execute(
                "INSERT INTO events (session_id, seq, ts, source, kind, exe, duration_ms, \
                 payload) VALUES (?1, ?2, ?3, 'keyboard', 'key', ?4, 0, '{}')",
                rusqlite::params![
                    session_id,
                    seq_base + 100 + step,
                    base_ts + step * minute + 5_000,
                    anchor
                ],
            )
            .expect("insert productive key");
        }
    }
}

/// Build a today snapshot over a fixture with `pairs` return-toll
/// candidates and the given curation state, through the real readers.
fn today_snapshot_with_toll_pairs(
    pairs: &[(&str, &str)],
    state: DiscoveryNoticeState,
) -> gilbreth_dashboard::data::TodaySnapshot {
    use gilbreth_dashboard::data::build_today_snapshot_for_tests;
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("gilbreth.db");
    {
        let _store =
            gilbreth_store::GilbrethStore::open(&db_path).expect("store migrates the schema");
    }
    let today_start = gilbreth_read::local_day_start_ms(DAY_START + 17 * HOUR_MS);
    let now_ms = today_start + 17 * HOUR_MS;
    let conn = rusqlite::Connection::open(&db_path).expect("open fixture");
    conn.execute(
        "INSERT INTO sessions (session_id, started_at, ended_at) VALUES (1, ?1, ?2)",
        rusqlite::params![today_start, today_start + 16 * HOUR_MS],
    )
    .expect("insert session");
    for (index, (anchor, diverter)) in pairs.iter().enumerate() {
        insert_return_toll_pair(
            &conn,
            1,
            (index as i64) * 200 + 1,
            today_start + HOUR_MS + (index as i64) * 2 * HOUR_MS,
            anchor,
            diverter,
        );
    }
    drop(conn);
    let mut host = stub_host_recording(Arc::default());
    host.db_path = db_path;
    host.read_notice_state = Box::new(move || state.clone());
    build_today_snapshot_for_tests(&host, now_ms)
}

/// UX-30 (branch review): the hidden count is the number of candidates
/// the dismiss/mute filters removed, counted PRE-CAP by the reader — it
/// must survive the 3-notice display cap instead of reading 0 whenever
/// three candidates still fill the visible list.
#[test]
fn hidden_notice_count_survives_the_display_cap() {
    let pairs = [
        ("alpha.exe", "n1.exe"),
        ("beta.exe", "n2.exe"),
        ("gamma.exe", "n3.exe"),
        ("delta.exe", "n4.exe"),
        ("epsilon.exe", "n5.exe"),
    ];
    let today_key =
        gilbreth_read::local_date(gilbreth_read::local_day_start_ms(DAY_START + 17 * HOUR_MS));
    let mut state = DiscoveryNoticeState::default();
    state.dismissed.insert(
        "return_toll|alpha.exe|n1.exe".to_string(),
        today_key.clone(),
    );
    state
        .dismissed
        .insert("return_toll|beta.exe|n2.exe".to_string(), today_key);
    let snapshot = today_snapshot_with_toll_pairs(&pairs, state);
    assert_eq!(
        snapshot.notices.len(),
        3,
        "three of the five candidates still fill the capped visible list"
    );
    assert_eq!(
        snapshot.hidden_notice_count, 2,
        "the two dismissed candidates must be counted even though the \
         visible list is full (pre-fix this read 3 - 3 = 0)"
    );
}

/// UX-30 (branch review): the hidden count and the visible list come from
/// ONE enumeration — the same candidate population, backfill included —
/// so an all-but-one dismissal reads as exactly the filtered candidates.
#[test]
fn hidden_notice_count_names_filters_over_one_population() {
    let pairs = [
        ("alpha.exe", "n1.exe"),
        ("beta.exe", "n2.exe"),
        ("gamma.exe", "n3.exe"),
    ];
    let today_key =
        gilbreth_read::local_date(gilbreth_read::local_day_start_ms(DAY_START + 17 * HOUR_MS));
    let mut state = DiscoveryNoticeState::default();
    state.dismissed.insert(
        "return_toll|alpha.exe|n1.exe".to_string(),
        today_key.clone(),
    );
    state
        .dismissed
        .insert("return_toll|beta.exe|n2.exe".to_string(), today_key);
    let snapshot = today_snapshot_with_toll_pairs(&pairs, state);
    assert_eq!(
        snapshot
            .notices
            .iter()
            .filter(|notice| notice.notice_type == "return_toll")
            .count(),
        1,
        "one return-toll candidate survives the filters"
    );
    assert_eq!(
        snapshot.hidden_notice_count, 2,
        "the count reflects the filtered candidates of the same enumeration"
    );
}

#[cfg(windows)]
/// Branch review (UX-15): an export/delete outcome survives a detail-read
/// error instead of being silently replaced by it.
#[test]
fn recordings_notice_survives_a_detail_error() {
    use gilbreth_dashboard::data::Snapshot;
    let writes: SharedWrites = Arc::default();
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(stub_host_recording(writes)),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        Some(recordings_snapshot_rich()),
        None,
        None,
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, 3400.0))
        .build_ui(move |ui| {
            if !styled.get() {
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    harness.get_by_label("Recordings").click();
    harness.run();
    use gilbreth_dashboard::tabs::recordings as tab;
    harness.get_by_label(tab::EXPORT_AGENT_BUTTON).click();
    harness.run();
    // The next refresh fails its detail read; the outcome must survive.
    let mut broken = recordings_snapshot_rich();
    broken.detail = None;
    broken.detail_error = Some("Couldn't read the recording steps: disk I/O error".to_string());
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Recordings(Box::new(broken)));
    harness.run();
    harness.get_by_label("Couldn't read the recording steps: disk I/O error");
    harness.get_by_label_contains("Saved the agent handoff trace");
}

/// Branch review (UX-12): below the history floor the caption renders
/// ABOVE candidate cards, like the Streamlit oracle (churn/clipboard
/// candidates exist below the sequence floor).
#[test]
fn analytics_below_floor_caption_renders_above_cards() {
    use gilbreth_dashboard::tabs::widgets::patterns_empty_caption;
    let writes: SharedWrites = Arc::default();
    let mut snapshot = rich_analytics_snapshot();
    snapshot.data.as_mut().unwrap().pattern_history_days = 1;
    let harness = analytics_harness(snapshot, writes);
    harness.get_by_label(&patterns_empty_caption(1));
    harness.get_by_label("browser.exe → studio.exe → chat.exe");
}

/// UX-57: while a tab's read is in flight the Refresh button is disabled
/// (and shows the updating cue); the arriving snapshot re-enables it.
#[test]
fn refresh_disabled_while_a_read_is_in_flight() {
    use gilbreth_dashboard::data::Snapshot;
    let app = Rc::new(RefCell::new(DashboardApp::new_for_tests(
        Arc::new(stub_host(Arc::default())),
        Some(rich_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )));
    let app_in_ui = app.clone();
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(1240.0, 1600.0))
        .build_ui(move |ui| {
            if !styled.get() {
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app_in_ui.borrow_mut().show_root(ui);
        });
    harness.run();
    let _ = app.borrow_mut().take_issued_requests_for_tests();
    // First click issues the read and marks it in flight.
    harness.get_by_label("Refresh").click();
    harness.run();
    assert_eq!(app.borrow_mut().take_issued_requests_for_tests().len(), 1);
    harness.get_by_label(shell::UPDATING_LABEL);
    // A second click while in flight must issue nothing (disabled).
    harness.get_by_label("Refresh").click();
    harness.run();
    assert!(
        app.borrow_mut().take_issued_requests_for_tests().is_empty(),
        "Refresh must stay inert while the read is in flight (UX-57)"
    );
    // The arriving snapshot ends the in-flight state; Refresh works again.
    let ctx = harness.ctx.clone();
    app.borrow_mut()
        .adopt_snapshot_for_tests(&ctx, Snapshot::Today(Box::new(rich_snapshot())));
    harness.run();
    assert!(harness.query_by_label(shell::UPDATING_LABEL).is_none());
    harness.get_by_label("Refresh").click();
    harness.run();
    assert_eq!(app.borrow_mut().take_issued_requests_for_tests().len(), 1);
}

/// UX-30: the partial hidden-notice state is named with a recovery control,
/// and "Reset notice controls" clears dismissals and mutes while sparing
/// watched marks.
#[test]
fn today_partial_hidden_state_names_count_and_reset_spares_watches() {
    use gilbreth_dashboard::tabs::today;
    let written: WrittenStates = Arc::default();
    let mut snapshot = rich_snapshot();
    // One notice filtered out locally; one watched notice still visible.
    snapshot.notices.truncate(1);
    snapshot.hidden_notice_count = 1;
    snapshot
        .notice_state
        .watched
        .insert("return_toll:studio.exe".to_string());
    snapshot
        .notice_state
        .muted
        .insert("clipboard_bridge:browser.exe->studio.exe".to_string());
    snapshot
        .notice_state
        .dismissed
        .insert("time_anchor:mail.exe".to_string(), "2026-07-09".to_string());
    let mut harness = harness_for(Some(snapshot), None, written.clone());
    harness.run();
    harness.get_by_label(&today::hidden_notices_caption(1));
    harness.get_by_label("Reset notice controls").click();
    harness.run();
    let states = written.lock().unwrap();
    assert_eq!(states.len(), 1);
    assert!(
        states[0].dismissed.is_empty() && states[0].muted.is_empty(),
        "reset clears dismissals and mutes"
    );
    assert!(
        states[0].watched.contains("return_toll:studio.exe"),
        "reset must spare watched marks (UX-30)"
    );
}

/// UX-21/UX-22: at narrow widths the fixed tile rows wrap into extra rows
/// instead of crushing labels, and the pattern card stacks its metrics
/// under the title instead of overflowing the card frame.
#[test]
fn narrow_window_wraps_tiles_and_stacks_pattern_metrics() {
    let written: WrittenStates = Arc::default();
    let mut app = DashboardApp::new_for_tests(
        Arc::new(stub_host(written)),
        Some(rich_snapshot()),
        Some(rich_week_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let styled = Cell::new(false);
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(520.0, 1800.0))
        .build_ui(move |ui| {
            if !styled.get() {
                gilbreth_dashboard::fonts::install(ui.ctx());
                gilbreth_dashboard::theme::apply(ui.ctx());
                styled.set(true);
                ui.ctx().request_repaint();
                return;
            }
            app.show_root(ui);
        });
    harness.run();
    // Today's five story tiles wrap: the last tile sits on a lower row
    // than the first instead of sharing one crushed 5-column row.
    let first_tile_top = harness.get_by_label("Active time").rect().top();
    let last_tile_top = harness.get_by_label("Keystrokes").rect().top();
    assert!(
        last_tile_top > first_tile_top + 10.0,
        "story tiles must wrap at 520 px (first {first_tile_top}, last {last_tile_top})"
    );
    // The Week friction card wraps its facts line under the title.
    harness.get_by_label("Week").click();
    harness.run();
    let title_top = harness
        .get_by_label("browser.exe → studio.exe → chat.exe")
        .rect()
        .top();
    let facts_top = harness.get_by_label_contains("signal Medium").rect().top();
    assert!(
        facts_top >= title_top,
        "the friction card's facts line stays inside the card at 520 px \
         (title {title_top}, facts {facts_top})"
    );
}

/// UX-03 repro attempt (2026-07-10): the live walkthrough saw the
/// sphere-rename combo popup survive an outside click and an Escape press.
/// This drives the same popup through kittest and pins the dismissal
/// behavior either way.
#[test]
fn analytics_sphere_combo_popup_dismisses_on_escape_and_outside_click() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness(overlay_analytics_snapshot(), writes);
    // The naming controls live inside the episodes Details now.
    harness
        .get_all_by_label("Details")
        .nth(4)
        .expect("the episodes Details")
        .click();
    harness.run();
    // Closed: the token label appears only on the combo header.
    let closed_count = harness.get_all_by_label("gilbreth").count();
    let open_combo = |harness: &mut Harness<'static>| {
        harness
            .get_by(|node| {
                node.role() == egui::accesskit::Role::ComboBox
                    && node.value().as_deref() == Some("gilbreth")
            })
            .click();
        harness.run();
    };
    open_combo(&mut harness);
    let open_count = harness.get_all_by_label("gilbreth").count();
    assert!(
        open_count > closed_count,
        "opening the combo must add the popup item ({closed_count} -> {open_count})"
    );
    // Escape closes the popup.
    harness.key_press(egui::Key::Escape);
    harness.run();
    assert_eq!(
        harness.get_all_by_label("gilbreth").count(),
        closed_count,
        "Escape must dismiss the sphere combo popup"
    );
    // An outside click closes it too.
    open_combo(&mut harness);
    assert!(harness.get_all_by_label("gilbreth").count() > closed_count);
    let outside = egui::Pos2::new(900.0, 80.0);
    harness.event(egui::Event::PointerMoved(outside));
    harness.event(egui::Event::PointerButton {
        pos: outside,
        button: egui::PointerButton::Primary,
        pressed: true,
        modifiers: egui::Modifiers::default(),
    });
    harness.event(egui::Event::PointerButton {
        pos: outside,
        button: egui::PointerButton::Primary,
        pressed: false,
        modifiers: egui::Modifiers::default(),
    });
    harness.run();
    assert_eq!(
        harness.get_all_by_label("gilbreth").count(),
        closed_count,
        "an outside click must dismiss the sphere combo popup"
    );
}

/// Per-platform visual-snapshot storage (MAC-1). GPU rasterization differs
/// by backend — Metal on macOS renders text and edges a hair differently
/// from the Windows backend — so a single shared baseline can't pass on
/// both. Baselines live under a per-OS subdir (`tests/snapshots/{os}/…`,
/// where `{os}` is `std::env::consts::OS` = `"macos"` / `"windows"`), and
/// each platform compares against its own set, generated on that platform.
///
/// Generation procedure (recorded in the crate's tests/snapshots/README):
/// macOS runs the un-ignored `visual_snapshot` filter as one GPU-backed
/// batch. Windows keeps the tests ignored and runs each named scene in its
/// own Cargo process with `--ignored --exact`; sharing one wgpu test process
/// can terminate with `STATUS_ACCESS_VIOLATION`. The README records the exact
/// 12-scene PowerShell loops for regeneration and comparison. A real GPU is
/// required on either platform.
///
/// Under `CI` the render still runs but the baseline comparison is skipped;
/// see `platform_snapshot` for why hosted runners cannot match a dev
/// machine's rasterization.
fn platform_snapshot(harness: &mut Harness<'_>, name: &str) {
    let name = format!("{}/{}", std::env::consts::OS, name);
    // Hosted CI runners render through a paravirtualized GPU that rasterizes
    // text and edges differently from the dev machines that generated these
    // baselines: on `macos-15` every scene fails on the same 31 shared-chrome
    // pixels before any content differs. Baselines are therefore machine-
    // specific, not merely OS-specific, and the comparison only means
    // something where it was generated.
    //
    // Render anyway, so wgpu initialization, layout and paint failures still
    // fail the lane, and skip only the pixel comparison. The gate that
    // actually guards the baselines is the pre-push hook on a dev machine.
    if std::env::var_os("CI").is_some() {
        harness
            .render()
            .unwrap_or_else(|err| panic!("render {name} under CI: {err}"));
        eprintln!(
            "skipped baseline comparison for {name}: hosted CI GPU \
             (see tests/snapshots/README.md)"
        );
        return;
    }
    harness.snapshot(name);
}

/// Local-only design review utility: render Today's first fold at the two
/// product viewport sizes without comparing or accepting a visual baseline.
#[test]
#[ignore = "writes local viewport previews under target/ui-previews"]
fn preview_today_default_viewports() {
    let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-previews");
    std::fs::create_dir_all(&output).expect("create viewport preview directory");
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for_sized(Some(rich_snapshot()), None, written, 960.0);

    for (name, width, height) in [
        ("today-1180x960.png", 1180_u32, 960_u32),
        ("today-1092x614.png", 1092_u32, 614_u32),
    ] {
        harness.set_size(egui::vec2(width as f32, height as f32));
        harness.run();
        let image = harness.render().expect("render Today viewport preview");
        assert_eq!(image.dimensions(), (width, height));
        image
            .save(output.join(name))
            .expect("save Today viewport preview");
    }
}

/// Local-only design review utility for the one-time first-run plate and
/// true blank Today state, including the supported narrow-width reflow.
#[test]
#[ignore = "writes local first-run previews under target/ui-previews"]
fn preview_today_first_run_viewports() {
    let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-previews");
    std::fs::create_dir_all(&output).expect("create viewport preview directory");
    let writes: SharedWrites = Arc::default();
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        960.0,
    );

    for (name, width, height) in [
        ("today-first-run-1180x960.png", 1180_u32, 960_u32),
        ("today-first-run-1092x614.png", 1092_u32, 614_u32),
        ("today-first-run-720x560.png", 720_u32, 560_u32),
    ] {
        harness.set_size(egui::vec2(width as f32, height as f32));
        harness.run();
        let image = harness.render().expect("render first-run viewport preview");
        assert_eq!(image.dimensions(), (width, height));
        image
            .save(output.join(name))
            .expect("save first-run viewport preview");
    }
}

/// Local-only design review utility: render the Analytics scope row at the
/// primary product width without comparing or accepting a visual baseline.
#[test]
#[ignore = "writes a local Analytics toolbar preview under target/ui-previews"]
fn preview_analytics_toolbar() {
    let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-previews");
    std::fs::create_dir_all(&output).expect("create viewport preview directory");
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness_sized(rich_analytics_snapshot(), writes, 180.0);
    harness.set_size(egui::vec2(1180.0, 180.0));
    harness.run();

    let image = harness.render().expect("render Analytics toolbar preview");
    assert_eq!(image.dimensions(), (1180, 180));
    image
        .save(output.join("analytics-toolbar-1180x180.png"))
        .expect("save Analytics toolbar preview");
}

/// The wgpu visual suite is ignored everywhere EXCEPT macOS: macOS has the
/// self-hosted GPU CI lane and generated Metal baselines, so the suite is a
/// live gate under a normal `cargo test`; other platforms lack the
/// lane/baselines and run it explicitly with `--ignored`. The first-run scene
/// is the temporary macOS exception until its genuine Metal baseline exists.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_today_rich() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for_sized(Some(rich_snapshot()), None, written, 1580.0);
    harness.run();
    // Open the first evidence drawer so the grid is part of the visual
    // record.
    harness.get_by_label("Evidence (2 rows)").click();
    harness.run();
    platform_snapshot(&mut harness, "today_rich");
}

/// Canonical first-run + true blank-state scene at the product's default
/// viewport. Phase 7 accepts the Windows render only; a normal macOS test run
/// skips this one scene until a genuine Metal render is generated and reviewed.
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "awaits a genuine Metal baseline generated on macOS"
)]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_today_first_run() {
    let writes: SharedWrites = Arc::default();
    let mut harness = harness_with_host(
        stub_host_recording(writes),
        Some(first_run_snapshot()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        960.0,
    );
    harness.set_size(egui::vec2(1180.0, 960.0));
    harness.run();
    platform_snapshot(&mut harness, "today_first_run");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_no_database() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for_sized(Some(empty_snapshot()), None, written, 460.0);
    harness.run();
    platform_snapshot(&mut harness, "no_database");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_week_rich() {
    let written: WrittenStates = Arc::default();
    let mut harness = harness_for_sized(
        Some(rich_snapshot()),
        Some(rich_week_snapshot()),
        written,
        1330.0,
    );
    harness.run();
    harness.get_by_label("Week").click();
    harness.run();
    platform_snapshot(&mut harness, "week_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_analytics_rich() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness_sized(rich_analytics_snapshot(), writes, 2110.0);
    platform_snapshot(&mut harness, "analytics_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_analytics_tables() {
    let writes: SharedWrites = Arc::default();
    let mut harness = analytics_harness_sized(rich_analytics_snapshot(), writes, 1760.0);
    harness.get_by_label("Tables").click();
    harness.run();
    platform_snapshot(&mut harness, "analytics_tables");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
#[cfg(windows)]
fn visual_snapshot_recordings_rich() {
    let writes: SharedWrites = Arc::default();
    let mut harness = recordings_harness_sized(recordings_snapshot_rich(), writes, 1310.0);
    platform_snapshot(&mut harness, "recordings_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_diagnostics_rich() {
    let writes: SharedWrites = Arc::default();
    let mut harness = diagnostics_harness_sized(diagnostics_snapshot_rich(), writes, 1060.0);
    // The resting state IS the design: verdict band, flag row, gauges, and
    // summary-carrying headers (Health check open by default, the rest
    // collapsed onto their summaries).
    platform_snapshot(&mut harness, "diagnostics_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_privacy_rich() {
    let writes: SharedWrites = Arc::default();
    let mut harness = privacy_harness_sized(privacy_snapshot_rich(), writes, 1940.0);
    // The resting state IS the design: the facts, the settings group with
    // its chips, and the delete/archive block with the advisor collapsed
    // onto its summary.
    platform_snapshot(&mut harness, "privacy_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_session_rich() {
    let writes: SharedWrites = Arc::default();
    let mut harness = session_harness_sized(
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
        writes,
        1030.0,
    );
    // The resting Overview IS the design: takeaways, gauges, share bars,
    // machine-event rows, and the collapsed Details.
    platform_snapshot(&mut harness, "session_rich");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
fn visual_snapshot_session_records() {
    let writes: SharedWrites = Arc::default();
    let mut harness = session_harness_sized(
        Some(rich_session_snapshot()),
        Some(session_events_fixture()),
        writes,
        1400.0,
    );
    // The Records lens joins the visual record (the analytics_tables
    // precedent): the four tables, the event list, and the delete flow.
    harness.get_by_label("Records").click();
    harness.run();
    platform_snapshot(&mut harness, "session_records");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "renders via wgpu; run explicitly (--ignored) off macOS"
)]
#[cfg(windows)]
fn visual_snapshot_recordings_empty() {
    let writes: SharedWrites = Arc::default();
    let mut snapshot = recordings_snapshot_rich();
    snapshot.rows.clear();
    snapshot.selected_id = None;
    snapshot.detail = None;
    // Sized to the short content: a taller canvas leaves post-click frame
    // remnants below the painted region in the wgpu capture.
    let mut harness = recordings_harness_sized(snapshot, writes, 340.0);
    platform_snapshot(&mut harness, "recordings_empty");
}
