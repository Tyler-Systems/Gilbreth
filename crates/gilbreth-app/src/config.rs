use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use gilbreth_core::{CaptureSettings, CaptureStream, Policy, DEFAULT_IDLE_THRESHOLD_MS};
use gilbreth_store::WriterConfig;
use icu_casemap::CaseMapper;
use serde::{ser::SerializeMap, Deserialize, Serialize};
use toml_edit::{value, DocumentMut, Item, Table, TableLike};

use crate::{hotkey::HotkeyConfig, platform::replace_file};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct AppConfig {
    pub capture: CaptureConfig,
    pub hotkey: HotkeyConfig,
    pub storage: StorageConfig,
    pub writer: WriterSection,
    pub record: RecordConfig,
    pub privacy: PrivacyConfig,
    pub onboarding: OnboardingConfig,
}

impl AppConfig {
    pub fn writer_config(&self) -> WriterConfig {
        WriterConfig {
            flush_interval: Duration::from_millis(self.writer.flush_interval_ms.max(1)),
            batch_size: self.writer.batch_size.max(1),
            record_request_poll_interval: Some(Duration::from_millis(
                self.record.request_poll_interval_ms.max(1),
            )),
            ..WriterConfig::default()
        }
    }

    pub fn policy(&self) -> Policy {
        Policy::identity()
            .with_title_redactions(self.privacy.redact_titles_containing.clone())
            .with_key_redactions(self.privacy.redact_keys_containing.clone())
            .with_excluded_apps(self.privacy.excluded_apps.clone())
            .with_sensitive_context_suppression(self.privacy.sensitive_context_suppression)
            .with_store_key_content(self.privacy.store_key_content)
    }

    pub fn db_path(&self, local_data_dir: &Path) -> PathBuf {
        self.storage
            .db_path
            .clone()
            .unwrap_or_else(|| local_data_dir.join("gilbreth.db"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub foreground: bool,
    pub windows: bool,
    pub keyboard: bool,
    pub mouse: bool,
    pub system: bool,
    pub idle: bool,
    pub idle_threshold_ms: u64,
    /// Background-process churn filter (default on). Process start/exit rows
    /// are kept only for apps that have held foreground focus; the rest are
    /// counted into periodic `process_churn_summary` rows instead of being
    /// written row-by-row. Set to `false` to store every process transition.
    pub process_filter: bool,
}

impl CaptureConfig {
    pub fn settings(&self) -> CaptureSettings {
        CaptureSettings {
            foreground: self.foreground,
            windows: self.windows,
            keyboard: self.keyboard,
            mouse: self.mouse,
            system: self.system,
            idle: self.idle,
            idle_threshold_ms: self.idle_threshold_ms.max(1),
            process_filter: self.process_filter,
        }
    }

    pub fn is_enabled(&self, stream: CaptureStream) -> bool {
        match stream {
            CaptureStream::Foreground => self.foreground,
            CaptureStream::Windows => self.windows,
            CaptureStream::Keyboard => self.keyboard,
            CaptureStream::Mouse => self.mouse,
            CaptureStream::System => self.system,
            CaptureStream::Idle => self.idle,
        }
    }

    pub fn set_enabled(&mut self, stream: CaptureStream, enabled: bool) {
        match stream {
            CaptureStream::Foreground => self.foreground = enabled,
            CaptureStream::Windows => self.windows = enabled,
            CaptureStream::Keyboard => self.keyboard = enabled,
            CaptureStream::Mouse => self.mouse = enabled,
            CaptureStream::System => self.system = enabled,
            CaptureStream::Idle => self.idle = enabled,
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            foreground: true,
            windows: true,
            keyboard: true,
            mouse: true,
            system: true,
            idle: true,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    pub db_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct WriterSection {
    pub flush_interval_ms: u64,
    pub batch_size: usize,
}

impl Default for WriterSection {
    fn default() -> Self {
        Self {
            flush_interval_ms: 250,
            batch_size: 100,
        }
    }
}

/// Record Routine is Windows-only by decision record, so the record-only keys
/// are not written off Windows. Gating only the upgrade path
/// (`insert_visible_defaults`) is not enough: a fresh install serializes this
/// whole struct, so the keys must be skipped here too or a new macOS
/// `config.toml` still names a `runas` strategy.
///
/// Only serialization is gated. `#[serde(default)]` means a config written by
/// an earlier build — every existing macOS install — still deserializes its
/// keys without error; they are simply never read off Windows.
/// `request_poll_interval_ms` stays on both platforms: the writer polls
/// `record_requests` everywhere, and off Windows that poll is what surfaces a
/// request so it can be declined.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct RecordConfig {
    #[cfg_attr(not(windows), serde(skip_serializing))]
    pub safety_cap_ms: u64,
    pub request_poll_interval_ms: u64,
    #[cfg_attr(not(windows), serde(skip_serializing))]
    pub elevated_helper_enabled: bool,
    #[cfg_attr(not(windows), serde(skip_serializing))]
    pub elevated_helper_strategy: ElevatedHelperStrategy,
    #[cfg_attr(not(windows), serde(skip_serializing))]
    pub elevated_helper_path: String,
    #[cfg_attr(not(windows), serde(skip_serializing))]
    pub elevated_helper_required_signer_sha256: String,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            safety_cap_ms: 1_800_000,
            request_poll_interval_ms: 3_000,
            elevated_helper_enabled: false,
            elevated_helper_strategy: ElevatedHelperStrategy::Runas,
            elevated_helper_path: String::new(),
            elevated_helper_required_signer_sha256: String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevatedHelperStrategy {
    #[default]
    Runas,
}

impl ElevatedHelperStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Runas => "runas",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct OnboardingConfig {
    /// Monotonic, per-install acknowledgement for the Today welcome plate.
    ///
    /// The default is true so an existing config that predates this setting
    /// is grandfathered and never receives a surprise first-run banner. Only
    /// `fresh_install_config` arms the welcome plate by writing false.
    pub first_run_welcome_dismissed: bool,
}

impl Default for OnboardingConfig {
    fn default() -> Self {
        Self {
            first_run_welcome_dismissed: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct PrivacyConfig {
    pub redact_titles_containing: Vec<String>,
    pub redact_keys_containing: Vec<String>,
    /// Case-insensitive executable basenames absent from future capture.
    pub excluded_apps: Vec<String>,
    pub sensitive_context_suppression: bool,
    // Lean capture default (DECIDED 2026-07-02): keystroke *content* is an
    // explicit opt-in. False keeps key rows (timing, modifiers, window, and a
    // value-free key class) while the key name itself is never stored.
    pub store_key_content: bool,
    // First-run consent (DESIGN DECIDED 2026-07-12, the first-run consent design):
    // false arms the pump's first-run posture dialog; any explicit choice
    // (dialog Yes/No, tray toggle) sets it true and it never reverts. The
    // default is TRUE — the grandfather rule: a config that merely lacks the
    // key predates the dialog and must never be re-prompted. Only
    // fresh_install_config() writes false.
    pub posture_confirmed: bool,
    pub retention_days: u64,
    // Title retention (DECIDED 2026-07-03): rows older than this many days
    // have their window titles blanked (columns + payload) while the row's
    // timing/app data is kept. 0 = keep titles for the life of the row.
    // Default 0 for existing installs; fresh installs move to 30 at R1.
    pub title_retention_days: u64,
    // Mouse-move tier (DECIDED 2026-07-04): raw mouse_move rows older than
    // this many days are deleted at startup; they are ~half of a long-run DB
    // and only feed motion metrics that read a bounded window anyway.
    // 0 = keep for the full retention_days. Clicks/keys/wheel are unaffected.
    pub mouse_move_retention_days: u64,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            redact_titles_containing: Vec::new(),
            redact_keys_containing: Vec::new(),
            excluded_apps: Vec::new(),
            sensitive_context_suppression: true,
            store_key_content: false,
            posture_confirmed: true,
            retention_days: 90,
            title_retention_days: 0,
            mouse_move_retention_days: 30,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigStatus {
    Loaded,
    CreatedDefault,
    UpgradedDefaultFields,
    Malformed { message: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedConfig {
    pub config: AppConfig,
    pub status: ConfigStatus,
}

pub fn config_path(local_data_dir: &Path) -> PathBuf {
    local_data_dir.join("config.toml")
}

/// The Working Spheres alias sidecar the native dashboard writes beside
/// config.toml. The spelling is a persisted-data contract inherited from the
/// retired Python implementation that originated it, so it stays as written
/// even though nothing else uses that spelling. It holds user-typed sphere
/// renames that can be derived from window titles, so secure erase must remove
/// it (it lives outside the activity DB by design).
pub const SPHERES_SIDECAR_NAME: &str = "spheres.json";
/// Stable, content-free sibling used to serialize every `config.toml`
/// read-modify-write transaction across tray and dashboard processes. The
/// config itself cannot be the lock target because each successful write
/// atomically replaces it, changing the file identity while a lock is held.
pub const CONFIG_LOCK_NAME: &str = "config.toml.lock";
// These versions are live contracts used by the native dashboard host and
// secure-erase paths. Keep them stable across document-preserving updates.
pub const SPHERE_ALIASES_VERSION: u64 = 1;
pub const DISCOVERY_STATE_SIDECAR_NAME: &str = "notices.json";
pub const DISCOVERY_STATE_VERSION: u64 = 1;

pub fn spheres_sidecar_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|dir| dir.join(SPHERES_SIDECAR_NAME))
        .unwrap_or_else(|| PathBuf::from(SPHERES_SIDECAR_NAME))
}

#[allow(dead_code)]
pub fn discovery_notice_state_sidecar_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|dir| dir.join(DISCOVERY_STATE_SIDECAR_NAME))
        .unwrap_or_else(|| PathBuf::from(DISCOVERY_STATE_SIDECAR_NAME))
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacySettings {
    pub sensitive_context_suppression: bool,
    pub redact_titles_containing: Vec<String>,
    pub redact_keys_containing: Vec<String>,
    pub excluded_apps: Vec<String>,
    pub store_key_content: bool,
    pub title_retention_days: u64,
    pub mouse_move_retention_days: u64,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        let privacy = PrivacyConfig::default();
        Self {
            sensitive_context_suppression: privacy.sensitive_context_suppression,
            redact_titles_containing: Vec::new(),
            redact_keys_containing: Vec::new(),
            excluded_apps: Vec::new(),
            store_key_content: privacy.store_key_content,
            title_retention_days: privacy.title_retention_days,
            mouse_move_retention_days: privacy.mouse_move_retention_days,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacySettingsRead {
    pub settings: PrivacySettings,
    pub error: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryNoticeState {
    pub dismissed: BTreeMap<String, String>,
    pub muted: BTreeSet<String>,
    pub watched: BTreeSet<String>,
}

pub fn load_or_create(path: &Path) -> Result<LoadedConfig> {
    with_config_write_lock(path, || load_or_create_locked(path))
}

fn load_or_create_locked(path: &Path) -> Result<LoadedConfig> {
    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<AppConfig>(&contents) {
            Ok(mut config) => {
                // The public contract is basename-only. Normalize even manual
                // config edits before any durable policy snapshot or UI can
                // repeat a user-bearing full path.
                config.privacy.excluded_apps =
                    normalize_excluded_apps(&config.privacy.excluded_apps);
                let status =
                    if let Some(upgraded_contents) = upgrade_config_contents(&contents, &config)? {
                        write_atomic(path, &upgraded_contents, "upgrade.tmp")?;
                        ConfigStatus::UpgradedDefaultFields
                    } else {
                        ConfigStatus::Loaded
                    };
                Ok(LoadedConfig { config, status })
            }
            Err(error) => Ok(LoadedConfig {
                config: AppConfig::default(),
                status: ConfigStatus::Malformed {
                    message: sanitized_toml_error(&contents, &error),
                },
            }),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let config = fresh_install_config();
            save_atomic_locked(path, &config)?;
            Ok(LoadedConfig {
                config,
                status: ConfigStatus::CreatedDefault,
            })
        }
        Err(error) => Err(anyhow::anyhow!(
            "{}",
            sanitized_config_io_error("read", &error)
        )),
    }
}

/// Defaults for a genuinely fresh install (no config.toml existed). The
/// fresh-install-only decisions live here and nowhere else — an existing
/// config that is merely missing these keys gets the grandfathered values
/// from `Default` instead: the first-run consent dialog arms
/// (`posture_confirmed = false`, DESIGN DECIDED 2026-07-12) and titles age
/// out at 30 days (`title_retention_days = 30`, DECIDED 2026-07-03: "fresh
/// installs move to 30 at R1, without retroactively changing existing
/// users"). The Today welcome plate is also armed only here; configs that
/// predate it remain dismissed by default.
fn fresh_install_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.privacy.posture_confirmed = false;
    config.privacy.title_retention_days = 30;
    config.onboarding.first_run_welcome_dismissed = false;
    config
}

fn sanitized_toml_error(contents: &str, error: &toml::de::Error) -> String {
    if let Some(span) = error.span() {
        let (line, column) = line_column_for_offset(contents, span.start);
        format!("TOML parse error at line {line}, column {column}; source text omitted")
    } else {
        "TOML parse error; source text omitted".to_string()
    }
}

fn line_column_for_offset(contents: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for (index, ch) in contents.char_indices() {
        if index >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

#[allow(dead_code)]
pub fn save_atomic(path: &Path, config: &AppConfig) -> Result<()> {
    with_config_write_lock(path, || save_atomic_locked(path, config))
}

fn save_atomic_locked(path: &Path, config: &AppConfig) -> Result<()> {
    let contents = toml::to_string_pretty(config).context("failed to serialize config")?;
    write_atomic(path, &contents, "tmp")
}

/// Persist the keystroke-content posture. Every caller is an explicit
/// posture choice (the tray toggle or the first-run dialog's Yes/No), so
/// this also confirms the posture in the same atomic write — once a choice
/// is persisted, the first-run dialog never returns.
pub fn save_store_key_content(path: &Path, enabled: bool) -> Result<()> {
    with_config_write_lock(path, || {
        let (mut document, _) = load_document_or_default(path)?;
        #[cfg(test)]
        pause_config_writer_after_read_for_test()?;
        let privacy = ensure_table(&mut document, "privacy");
        privacy.insert("store_key_content", value(enabled));
        privacy.insert("posture_confirmed", value(true));
        write_atomic(path, &document.to_string(), "tray.tmp")
    })
}

pub fn save_capture_toggle(path: &Path, stream: CaptureStream, enabled: bool) -> Result<()> {
    with_config_write_lock(path, || {
        let (mut document, _) = load_document_or_default(path)?;
        let capture = ensure_table(&mut document, "capture");
        capture.insert(capture_key(stream), value(enabled));
        write_atomic(path, &document.to_string(), "tray.tmp")
    })
}

/// Read the per-install Today welcome acknowledgement without making config
/// availability a reason to show onboarding. A missing file, missing key,
/// malformed document, wrong value type, or read failure all fail closed to
/// dismissed. A genuinely fresh install is the sole path that persists false.
#[allow(dead_code)]
pub fn read_first_run_welcome_dismissed(path: &Path) -> bool {
    let Ok(Some(value)) = read_config_value(path) else {
        return true;
    };
    value
        .get("onboarding")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("first_run_welcome_dismissed"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
}

/// Permanently acknowledge the Today welcome plate. This operation is
/// intentionally monotonic: callers can only move the flag to true. The
/// shared config lock serializes this read-modify-write with tray and other
/// dashboard writers, while `toml_edit` preserves unrelated keys/comments.
#[allow(dead_code)]
pub fn dismiss_first_run_welcome(path: &Path) -> Result<()> {
    with_config_write_lock(path, || {
        let (mut document, loaded_from_file) = load_document_or_default(path)?;
        let already_dismissed = document
            .as_table()
            .get("onboarding")
            .and_then(Item::as_table_like)
            .and_then(|table| table.get("first_run_welcome_dismissed"))
            .and_then(Item::as_bool)
            == Some(true);
        if already_dismissed && loaded_from_file {
            return Ok(());
        }

        let onboarding = ensure_table(&mut document, "onboarding");
        onboarding.insert("first_run_welcome_dismissed", value(true));
        write_atomic(path, &document.to_string(), "dashboard.tmp")
    })
}

#[allow(dead_code)]
pub fn read_privacy_settings(path: &Path) -> PrivacySettingsRead {
    let value = match read_config_value(path) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return PrivacySettingsRead {
                settings: PrivacySettings::default(),
                error: None,
            }
        }
        Err(error) => {
            return PrivacySettingsRead {
                settings: PrivacySettings::default(),
                error: Some(error),
            }
        }
    };
    let privacy = value.get("privacy").and_then(toml::Value::as_table);
    let default = PrivacySettings::default();
    let settings = PrivacySettings {
        sensitive_context_suppression: privacy
            .and_then(|table| table.get("sensitive_context_suppression"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(default.sensitive_context_suppression),
        redact_titles_containing: privacy
            .and_then(|table| table.get("redact_titles_containing"))
            .map(string_vec_from_toml)
            .unwrap_or_default(),
        redact_keys_containing: privacy
            .and_then(|table| table.get("redact_keys_containing"))
            .map(string_vec_from_toml)
            .unwrap_or_default(),
        excluded_apps: privacy
            .and_then(|table| table.get("excluded_apps"))
            .map(string_vec_from_toml)
            .map(|apps| normalize_excluded_apps(&apps))
            .unwrap_or_default(),
        store_key_content: privacy
            .and_then(|table| table.get("store_key_content"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(default.store_key_content),
        title_retention_days: privacy
            .and_then(|table| table.get("title_retention_days"))
            .and_then(nonnegative_toml_int)
            .unwrap_or(default.title_retention_days),
        mouse_move_retention_days: privacy
            .and_then(|table| table.get("mouse_move_retention_days"))
            .and_then(nonnegative_toml_int)
            .unwrap_or(default.mouse_move_retention_days),
    };
    PrivacySettingsRead {
        settings,
        error: None,
    }
}

#[allow(dead_code)]
pub fn write_privacy_settings(path: &Path, settings: &PrivacySettings) -> Result<()> {
    with_config_write_lock(path, || {
        let mut document = load_dashboard_document_or_empty(path)?;
        let privacy = ensure_table(&mut document, "privacy");
        privacy.insert(
            "sensitive_context_suppression",
            value(settings.sensitive_context_suppression),
        );
        privacy.insert(
            "redact_titles_containing",
            string_array_item(&normalize_privacy_patterns(
                &settings.redact_titles_containing,
            )),
        );
        privacy.insert(
            "redact_keys_containing",
            string_array_item(&normalize_privacy_patterns(
                &settings.redact_keys_containing,
            )),
        );
        privacy.insert(
            "excluded_apps",
            string_array_item(&normalize_excluded_apps(&settings.excluded_apps)),
        );
        privacy.insert(
            "title_retention_days",
            value(i64::try_from(settings.title_retention_days).unwrap_or(i64::MAX)),
        );
        privacy.insert(
            "mouse_move_retention_days",
            value(i64::try_from(settings.mouse_move_retention_days).unwrap_or(i64::MAX)),
        );
        write_atomic(path, &document.to_string(), "dashboard.tmp")
    })
}

#[allow(dead_code)]
pub fn read_sphere_overlay_enabled(path: &Path) -> bool {
    let Ok(Some(value)) = read_config_value(path) else {
        return false;
    };
    value
        .get("analytics")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("sphere_labels_from_titles"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

/// `[privacy].retention_days` with db.py's tolerant read: a missing or
/// malformed config, a non-integer, or a non-positive value all fall back
/// to the 90-day default.
#[allow(dead_code)]
pub fn read_retention_days(path: &Path) -> i64 {
    const DEFAULT_RETENTION_DAYS: i64 = 90;
    let Ok(Some(value)) = read_config_value(path) else {
        return DEFAULT_RETENTION_DAYS;
    };
    value
        .get("privacy")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("retention_days"))
        .and_then(toml::Value::as_integer)
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// Framework classes an operator has marked replay-verified for exports
/// (`[export].verified_framework_classes`). Mirrors db.py's tolerant read: a
/// missing or malformed config yields the empty set, and only classes on
/// both allowlists (known ∩ verified-exportable) survive.
#[allow(dead_code)]
pub fn read_verified_framework_classes(path: &Path) -> HashSet<String> {
    const KNOWN_FRAMEWORK_CLASSES: [&str; 5] = [
        "native",
        "native_provisional",
        "web_renderer",
        "virtualized",
        "unknown",
    ];
    const VERIFIED_EXPORT_FRAMEWORK_CLASSES: [&str; 1] = ["native"];
    let Ok(Some(value)) = read_config_value(path) else {
        return HashSet::new();
    };
    let Some(values) = value
        .get("export")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("verified_framework_classes"))
        .and_then(toml::Value::as_array)
    else {
        return HashSet::new();
    };
    values
        .iter()
        .filter_map(toml::Value::as_str)
        .filter(|class| {
            KNOWN_FRAMEWORK_CLASSES.contains(class)
                && VERIFIED_EXPORT_FRAMEWORK_CLASSES.contains(class)
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[allow(dead_code)]
pub fn save_sphere_overlay_enabled(path: &Path, enabled: bool) -> Result<()> {
    with_config_write_lock(path, || {
        let mut document = load_dashboard_document_or_empty(path)?;
        let analytics = ensure_table(&mut document, "analytics");
        analytics.insert("sphere_labels_from_titles", value(enabled));
        write_atomic(path, &document.to_string(), "dashboard.tmp")
    })
}

#[allow(dead_code)]
pub fn write_sphere_overlay_enabled(path: &Path, enabled: bool) -> Result<()> {
    save_sphere_overlay_enabled(path, enabled)
}

#[allow(dead_code)]
pub fn read_discovery_notice_state(path: &Path) -> DiscoveryNoticeState {
    let Ok(contents) = fs::read_to_string(path) else {
        return DiscoveryNoticeState::default();
    };
    let Ok(raw) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return DiscoveryNoticeState::default();
    };
    let Some(object) = raw.as_object() else {
        return DiscoveryNoticeState::default();
    };

    let dismissed = object
        .get("dismissed")
        .and_then(serde_json::Value::as_object)
        .map(|dismissed| {
            dismissed
                .iter()
                .filter_map(|(key, value)| {
                    let key = key.to_string();
                    let value = json_value_to_text(value);
                    (!python_strip(&key).is_empty() && !python_strip(&value).is_empty())
                        .then_some((key, value))
                })
                .collect()
        })
        .unwrap_or_default();
    let muted = json_list_to_set(object.get("muted"));
    let watched = json_list_to_set(object.get("watched"));
    DiscoveryNoticeState {
        dismissed,
        muted,
        watched,
    }
}

#[allow(dead_code)]
pub fn write_discovery_notice_state(path: &Path, state: &DiscoveryNoticeState) -> Result<()> {
    #[derive(Serialize)]
    struct Payload<'a> {
        version: u64,
        dismissed: &'a BTreeMap<String, String>,
        muted: &'a BTreeSet<String>,
        watched: &'a BTreeSet<String>,
    }

    let payload = Payload {
        version: DISCOVERY_STATE_VERSION,
        dismissed: &state.dismissed,
        muted: &state.muted,
        watched: &state.watched,
    };
    let contents = format!("{}\n", serde_json::to_string_pretty(&payload)?);
    write_atomic(path, &contents, "tmp")
}

#[allow(dead_code)]
pub fn read_sphere_aliases(path: &Path) -> BTreeMap<String, String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(raw) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return BTreeMap::new();
    };
    raw.get("aliases")
        .and_then(serde_json::Value::as_object)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|(key, value)| {
                    let value = python_strip(value.as_str()?).to_string();
                    let key = casefold_token(key);
                    (!key.is_empty() && !value.is_empty()).then_some((key, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[allow(dead_code)]
pub fn write_sphere_aliases(path: &Path, aliases: &BTreeMap<String, String>) -> Result<()> {
    struct OrderedAliases<'a>(&'a [(String, String)]);

    impl Serialize for OrderedAliases<'_> {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for (key, value) in self.0 {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }

    #[derive(Serialize)]
    struct Payload<'a> {
        version: u64,
        aliases: OrderedAliases<'a>,
    }

    // Python sorts the original keys, then inserts their normalized forms into
    // an ordered dict. A fold collision replaces the value without moving the
    // first insertion, so preserve that behavior instead of collecting into a
    // BTreeMap ordered by the normalized key.
    let mut positions = BTreeMap::<String, usize>::new();
    let mut cleaned = Vec::<(String, String)>::new();
    for (key, value) in aliases {
        let key = casefold_token(key);
        let value = python_strip(value).to_string();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if let Some(index) = positions.get(&key).copied() {
            cleaned[index].1 = value;
        } else {
            positions.insert(key.clone(), cleaned.len());
            cleaned.push((key, value));
        }
    }
    let payload = Payload {
        version: SPHERE_ALIASES_VERSION,
        aliases: OrderedAliases(&cleaned),
    };
    let contents = format!("{}\n", serde_json::to_string_pretty(&payload)?);
    write_atomic(path, &contents, "tmp")
}

#[allow(dead_code)]
pub fn prune_stale_sphere_aliases<I, S>(
    path: &Path,
    live_tokens: I,
) -> Result<BTreeMap<String, String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let aliases = read_sphere_aliases(path);
    if aliases.is_empty() {
        return Ok(aliases);
    }
    let live = live_tokens
        .into_iter()
        .map(|token| casefold_token(token.as_ref()))
        .filter(|token| !token.is_empty())
        .collect::<HashSet<_>>();
    let kept = aliases
        .iter()
        .filter(|(key, _)| live.contains(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if kept != aliases {
        write_sphere_aliases(path, &kept)?;
    }
    Ok(kept)
}

fn with_config_write_lock<T>(path: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let _lock = acquire_config_write_lock(path)?;
    operation()
}

fn acquire_config_write_lock(path: &Path) -> Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("{}", sanitized_config_io_error("write", &error)))?;
    }

    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config_lock_path(path))
        .map_err(|error| anyhow::anyhow!("{}", sanitized_config_io_error("write", &error)))?;
    lock_config_file(&lock_file)
        .map_err(|error| anyhow::anyhow!("{}", sanitized_config_io_error("write", &error)))?;
    Ok(lock_file)
}

fn config_lock_path(path: &Path) -> PathBuf {
    if path.file_name() == Some(OsStr::new("config.toml")) {
        return path.with_file_name(CONFIG_LOCK_NAME);
    }

    let mut name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("config.toml"))
        .to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

fn lock_config_file(lock_file: &File) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(marker) = std::env::var_os(TEST_EXPECT_LOCK_CONTENTION_MARKER) {
        match lock_file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) => {
                fs::write(marker, b"blocked")?;
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
            Ok(()) => {
                return Err(std::io::Error::other(
                    "test writer acquired a lock that should be contended",
                ));
            }
        }
    }

    lock_file.lock()
}

#[cfg(test)]
const TEST_WRITER_PAUSED_MARKER: &str = "GILBRETH_TEST_CONFIG_WRITER_PAUSED_MARKER";
#[cfg(test)]
const TEST_WRITER_RELEASE_MARKER: &str = "GILBRETH_TEST_CONFIG_WRITER_RELEASE_MARKER";
#[cfg(test)]
const TEST_EXPECT_LOCK_CONTENTION_MARKER: &str =
    "GILBRETH_TEST_EXPECT_CONFIG_LOCK_CONTENTION_MARKER";

#[cfg(test)]
fn pause_config_writer_after_read_for_test() -> Result<()> {
    let Some(paused_marker) = std::env::var_os(TEST_WRITER_PAUSED_MARKER) else {
        return Ok(());
    };
    let release_marker = std::env::var_os(TEST_WRITER_RELEASE_MARKER)
        .ok_or_else(|| anyhow::anyhow!("test writer release marker is missing"))?;
    fs::write(paused_marker, b"paused")?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !Path::new(&release_marker).exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting to release the paused test config writer");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &str, suffix: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            return Err(anyhow::anyhow!(
                "{}",
                sanitized_config_io_error("write", &error)
            ));
        }
    }

    let tmp_path = path.with_file_name(format!(
        "{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml"),
        suffix
    ));
    let result = (|| {
        fs::write(&tmp_path, contents)?;
        replace_file(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result.map_err(|error: anyhow::Error| sanitize_write_atomic_error(error))
}

fn upgrade_config_contents(contents: &str, config: &AppConfig) -> Result<Option<String>> {
    let mut document = contents.parse::<DocumentMut>().map_err(|error| {
        anyhow::anyhow!(
            "failed to parse loaded config for upgrade: {}",
            sanitized_toml_edit_error(contents, &error)
        )
    })?;
    let changed = insert_visible_defaults(&mut document, config);

    if changed {
        Ok(Some(document.to_string()))
    } else {
        Ok(None)
    }
}

/// Returns the editable document and whether it came from an existing file.
/// Callers that can skip an idempotent write still need the second value:
/// a default-valued in-memory document must be persisted when the file was
/// absent.
fn load_document_or_default(path: &Path) -> Result<(DocumentMut, bool)> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str::<AppConfig>(&contents).map_err(|error| {
                anyhow::anyhow!(
                    "config is malformed; refusing document-preserving update: {}",
                    sanitized_toml_error(&contents, &error)
                )
            })?;
            let document = contents.parse::<DocumentMut>().map_err(|error| {
                anyhow::anyhow!(
                    "failed to parse config document: {}",
                    sanitized_toml_edit_error(&contents, &error)
                )
            })?;
            Ok((document, true))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let contents = toml::to_string_pretty(&AppConfig::default())
                .context("failed to serialize config")?;
            let document = contents
                .parse::<DocumentMut>()
                .context("failed to parse default config document")?;
            Ok((document, false))
        }
        Err(error) => Err(anyhow::anyhow!(
            "{}",
            sanitized_config_io_error("read", &error)
        )),
    }
}

fn load_dashboard_document_or_empty(path: &Path) -> Result<DocumentMut> {
    match fs::read_to_string(path) {
        Ok(contents) => contents.parse::<DocumentMut>().map_err(|error| {
            anyhow::anyhow!(
                "config is malformed; refusing document-preserving update: {}",
                sanitized_toml_edit_error(&contents, &error)
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(error) => Err(anyhow::anyhow!(
            "{}",
            sanitized_config_io_error("read", &error)
        )),
    }
}

fn sanitized_toml_edit_error(contents: &str, error: &toml_edit::TomlError) -> String {
    if let Some(span) = error.span() {
        let (line, column) = line_column_for_offset(contents, span.start);
        format!("TOML parse error at line {line}, column {column}; source text omitted")
    } else {
        "TOML parse error; source text omitted".to_string()
    }
}

fn read_config_value(path: &Path) -> std::result::Result<Option<toml::Value>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(sanitized_config_io_error("read", &error)),
    };
    toml::from_str::<toml::Value>(&contents)
        .map(Some)
        .map_err(|error| sanitized_toml_error(&contents, &error))
}

fn sanitized_config_io_error(operation: &str, error: &std::io::Error) -> String {
    format!("Could not {operation} config file: {error}")
}

fn sanitize_write_atomic_error(error: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!("Could not write config file: {}", root_error_text(&error))
}

fn root_error_text(error: &anyhow::Error) -> String {
    error
        .chain()
        .last()
        .map(ToString::to_string)
        .unwrap_or_else(|| error.to_string())
}

fn string_vec_from_toml(value: &toml::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn nonnegative_toml_int(value: &toml::Value) -> Option<u64> {
    value
        .as_integer()
        .map(|value| u64::try_from(value.max(0)).unwrap_or(u64::MAX))
}

fn normalize_privacy_patterns(patterns: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for pattern in patterns {
        let trimmed = python_strip(pattern);
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

pub(crate) fn normalize_excluded_apps(apps: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for app in apps {
        let trimmed = python_strip(app);
        let basename = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).trim();
        if basename.is_empty() {
            continue;
        }
        let key = basename.to_lowercase();
        if seen.insert(key) {
            normalized.push(basename.to_string());
        }
    }
    normalized
}

fn string_array_item(values: &[String]) -> Item {
    let mut array = toml_edit::Array::default();
    for value in values {
        array.push(value.as_str());
    }
    Item::Value(toml_edit::Value::Array(array))
}

fn json_list_to_set(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    let value = json_value_to_text(value);
                    (!python_strip(&value).is_empty()).then_some(value)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn json_value_to_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(true) => "True".to_string(),
        serde_json::Value::Bool(false) => "False".to_string(),
        serde_json::Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// CPython-`str.casefold` alias-key normalization (icu casemap, pinned).
/// Public for the dashboard host: alias saves must fold exactly like the
/// sidecar reader.
pub fn casefold_token(value: &str) -> String {
    CaseMapper::new().fold_string(python_strip(value))
}

fn python_strip(value: &str) -> &str {
    value.trim_matches(is_python_whitespace)
}

fn is_python_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000d}'
            | '\u{001c}'..='\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn insert_visible_defaults(document: &mut DocumentMut, config: &AppConfig) -> bool {
    let mut changed = false;
    changed |= insert_missing_value(
        document,
        "capture",
        "idle_threshold_ms",
        value(i64::try_from(config.capture.idle_threshold_ms).unwrap_or(i64::MAX)),
    );
    changed |= insert_missing_value(
        document,
        "capture",
        "process_filter",
        value(config.capture.process_filter),
    );
    changed |= insert_missing_value(
        document,
        "hotkey",
        "pause_resume",
        value(config.hotkey.pause_resume.clone()),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "excluded_apps",
        string_array_item(&config.privacy.excluded_apps),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "sensitive_context_suppression",
        value(config.privacy.sensitive_context_suppression),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "mouse_move_retention_days",
        value(i64::try_from(config.privacy.mouse_move_retention_days).unwrap_or(i64::MAX)),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "store_key_content",
        value(config.privacy.store_key_content),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "posture_confirmed",
        value(config.privacy.posture_confirmed),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "title_retention_days",
        value(i64::try_from(config.privacy.title_retention_days).unwrap_or(i64::MAX)),
    );
    changed |= insert_missing_value(
        document,
        "privacy",
        "retention_days",
        value(i64::try_from(config.privacy.retention_days).unwrap_or(i64::MAX)),
    );
    changed |= insert_missing_value(
        document,
        "onboarding",
        "first_run_welcome_dismissed",
        value(config.onboarding.first_run_welcome_dismissed),
    );
    // `safety_cap_ms` bounds the length of a recording, so it only means
    // something where a recording can start. Gated in place rather than moved
    // into the block below so a fresh Windows config.toml keeps its key order.
    #[cfg(windows)]
    {
        changed |= insert_missing_value(
            document,
            "record",
            "safety_cap_ms",
            value(i64::try_from(config.record.safety_cap_ms).unwrap_or(i64::MAX)),
        );
    }
    // `request_poll_interval_ms` stays on every platform: the writer polls
    // `record_requests` cross-platform, and off Windows that poll is what
    // surfaces a request so it can be declined.
    changed |= insert_missing_value(
        document,
        "record",
        "request_poll_interval_ms",
        value(i64::try_from(config.record.request_poll_interval_ms).unwrap_or(i64::MAX)),
    );
    // The elevated helper belongs to Record Routine, which is Windows-only by
    // decision record. Seeding these into a macOS config.toml would offer
    // settings — including a `runas` strategy naming a Windows mechanism —
    // that nothing on that platform reads. Existing keys are left alone; only
    // seeding stops.
    #[cfg(windows)]
    {
        changed |= insert_missing_value(
            document,
            "record",
            "elevated_helper_enabled",
            value(config.record.elevated_helper_enabled),
        );
        changed |= insert_missing_value(
            document,
            "record",
            "elevated_helper_strategy",
            value(config.record.elevated_helper_strategy.as_str()),
        );
        changed |= insert_missing_value(
            document,
            "record",
            "elevated_helper_path",
            value(config.record.elevated_helper_path.clone()),
        );
        changed |= insert_missing_value(
            document,
            "record",
            "elevated_helper_required_signer_sha256",
            value(config.record.elevated_helper_required_signer_sha256.clone()),
        );
    }
    changed
}

fn insert_missing_value(
    document: &mut DocumentMut,
    section_name: &str,
    key: &str,
    default_value: Item,
) -> bool {
    let section = ensure_table(document, section_name);
    if section.contains_key(key) {
        false
    } else {
        section.insert(key, default_value);
        true
    }
}

fn ensure_table<'a>(document: &'a mut DocumentMut, section_name: &str) -> &'a mut dyn TableLike {
    if !document.as_table().contains_key(section_name)
        || document[section_name].as_table_like().is_none()
    {
        document[section_name] = Item::Table(Table::new());
    }
    document[section_name]
        .as_table_like_mut()
        .expect("section is table-like")
}

fn capture_key(stream: CaptureStream) -> &'static str {
    match stream {
        CaptureStream::Foreground => "foreground",
        CaptureStream::Windows => "windows",
        CaptureStream::Keyboard => "keyboard",
        CaptureStream::Mouse => "mouse",
        CaptureStream::System => "system",
        CaptureStream::Idle => "idle",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        time::{Duration, Instant},
    };

    use gilbreth_core::CaptureStream;
    use tempfile::tempdir;

    use super::*;

    const TEST_WRITER_ACTION: &str = "GILBRETH_TEST_CONFIG_WRITER_ACTION";
    const TEST_WRITER_CONFIG_PATH: &str = "GILBRETH_TEST_CONFIG_WRITER_PATH";
    const CONFIG_WRITER_HELPER_TEST: &str = "config::tests::config_writer_process_helper";

    fn assert_error_chain_omits(error: &anyhow::Error, sensitive: &[&str]) {
        let mut renderings = vec![
            error.to_string(),
            format!("{error:#}"),
            format!("{error:?}"),
            format!("{error:#?}"),
        ];
        renderings.extend(error.chain().map(ToString::to_string));
        for rendered in renderings {
            for value in sensitive {
                assert!(
                    !rendered.contains(value),
                    "error rendering leaked sensitive value {value:?}: {rendered}"
                );
            }
        }
        assert_eq!(
            error.chain().count(),
            1,
            "sanitized refusal must not retain a parser source"
        );
    }

    fn config_writer_command(path: &Path, action: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg(CONFIG_WRITER_HELPER_TEST)
            .arg("--nocapture")
            .env(TEST_WRITER_ACTION, action)
            .env(TEST_WRITER_CONFIG_PATH, path);
        command
    }

    fn wait_for_marker(path: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !path.exists() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    #[test]
    fn config_writer_process_helper() {
        let Some(action) = std::env::var_os(TEST_WRITER_ACTION) else {
            return;
        };
        let path = PathBuf::from(
            std::env::var_os(TEST_WRITER_CONFIG_PATH).expect("helper config path is set"),
        );
        match action.to_str().expect("helper action is Unicode") {
            "tray" => save_store_key_content(&path, true).expect("tray setting is saved"),
            "dashboard" => write_privacy_settings(
                &path,
                &PrivacySettings {
                    sensitive_context_suppression: false,
                    ..PrivacySettings::default()
                },
            )
            .expect("dashboard settings are saved"),
            other => panic!("unknown config writer helper action: {other}"),
        }
    }

    #[test]
    fn concurrent_tray_and_dashboard_processes_preserve_both_changes() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let paused = dir.path().join("tray-paused");
        let release = dir.path().join("release-tray");
        let contended = dir.path().join("dashboard-contended");
        let mut initial = AppConfig::default();
        initial.privacy.store_key_content = false;
        initial.privacy.posture_confirmed = false;
        initial.privacy.sensitive_context_suppression = true;
        save_atomic(&path, &initial).expect("initial config is saved");

        let lock_path = config_lock_path(&path);
        assert_eq!(
            lock_path.file_name().and_then(OsStr::to_str),
            Some(CONFIG_LOCK_NAME)
        );
        assert_eq!(
            config_lock_path(&dir.path().join("alternate.toml"))
                .file_name()
                .and_then(OsStr::to_str),
            Some("alternate.toml.lock")
        );
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("lock artifact exists")
                .len(),
            0,
            "the persistent synchronization artifact must remain content-free"
        );

        let mut tray = config_writer_command(&path, "tray")
            .env(TEST_WRITER_PAUSED_MARKER, &paused)
            .env(TEST_WRITER_RELEASE_MARKER, &release)
            .spawn()
            .expect("tray writer process starts");
        if !wait_for_marker(&paused) {
            let _ = fs::write(&release, b"release");
            let status = tray.wait().expect("tray writer exits");
            panic!("tray writer did not pause after reading config; status: {status}");
        }

        let mut dashboard = config_writer_command(&path, "dashboard")
            .env(TEST_EXPECT_LOCK_CONTENTION_MARKER, &contended)
            .spawn()
            .expect("dashboard writer process starts");
        let saw_contention = wait_for_marker(&contended);
        fs::write(&release, b"release").expect("paused tray writer is released");

        let tray_status = tray.wait().expect("tray writer exits");
        let dashboard_status = dashboard.wait().expect("dashboard writer exits");
        assert!(
            saw_contention,
            "dashboard writer never observed the tray writer's cross-process lock"
        );
        assert!(tray_status.success(), "tray writer failed: {tray_status}");
        assert!(
            dashboard_status.success(),
            "dashboard writer failed: {dashboard_status}"
        );

        let final_config: AppConfig =
            toml::from_str(&fs::read_to_string(&path).expect("final config remains readable"))
                .expect("final config remains valid");
        assert!(
            final_config.privacy.store_key_content,
            "the tray's keystroke-content choice must survive"
        );
        assert!(
            final_config.privacy.posture_confirmed,
            "the tray's consent confirmation must survive"
        );
        assert!(
            !final_config.privacy.sensitive_context_suppression,
            "the dashboard's privacy change must survive"
        );
        assert_eq!(
            fs::metadata(lock_path)
                .expect("lock artifact remains")
                .len(),
            0
        );
    }

    #[test]
    fn missing_config_creates_defaults() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        let loaded = load_or_create(&path).expect("config loads");

        // Fresh installs differ from `Default` only in the three
        // fresh-install-only decisions: consent arming, 30-day titles, and
        // an undismissed Today welcome. Everything else matches the
        // grandfathered defaults.
        let mut expected = AppConfig::default();
        expected.privacy.posture_confirmed = false;
        expected.privacy.title_retention_days = 30;
        expected.onboarding.first_run_welcome_dismissed = false;
        assert_eq!(loaded.status, ConfigStatus::CreatedDefault);
        assert_eq!(loaded.config, expected);
        assert!(path.exists());
        let contents = fs::read_to_string(path).expect("config file");
        let written: AppConfig = toml::from_str(&contents).expect("valid toml");
        assert_eq!(written, expected);
        assert!(contents.contains("[onboarding]"));
        assert!(contents.contains("first_run_welcome_dismissed = false"));
        // A fresh install serializes the whole struct rather than going
        // through `insert_visible_defaults`, so the record-only keys have to
        // be gated at both layers. This is the path that actually creates a
        // new user's config.
        assert_record_only_seeding(&contents);
        for retired in [
            "dashboard",
            "python",
            "port",
            "address",
            "auto_open_browser",
        ] {
            assert!(
                !contents.contains(retired),
                "fresh config emitted retired dashboard text: {retired}"
            );
        }
    }

    #[test]
    fn existing_config_is_grandfathered_past_the_first_run_welcome() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[privacy]\nretention_days = 30\n").expect("legacy config written");

        let loaded = load_or_create(&path).expect("legacy config loads");

        assert_eq!(loaded.status, ConfigStatus::UpgradedDefaultFields);
        assert!(loaded.config.onboarding.first_run_welcome_dismissed);
        assert!(read_first_run_welcome_dismissed(&path));
        let upgraded = fs::read_to_string(&path).expect("upgraded config readable");
        assert!(upgraded.contains("[onboarding]"));
        assert!(upgraded.contains("first_run_welcome_dismissed = true"));
    }

    #[test]
    fn dismiss_first_run_welcome_is_monotonic_and_document_preserving() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            concat!(
                "# keep this operator note\n",
                "[privacy]\n",
                "retention_days = 45\n",
                "future_setting = 'keep-me' # and this note\n\n",
                "[onboarding]\n",
                "first_run_welcome_dismissed = false\n",
            ),
        )
        .expect("config written");
        assert!(!read_first_run_welcome_dismissed(&path));

        dismiss_first_run_welcome(&path).expect("welcome dismissed");

        assert!(read_first_run_welcome_dismissed(&path));
        let once = fs::read_to_string(&path).expect("updated config readable");
        assert!(once.contains("# keep this operator note"));
        assert!(once.contains("future_setting = 'keep-me' # and this note"));
        assert!(once.contains("retention_days = 45"));
        assert!(once.contains("first_run_welcome_dismissed = true"));

        dismiss_first_run_welcome(&path).expect("second dismissal is harmless");
        assert_eq!(
            fs::read_to_string(&path).expect("config remains readable"),
            once,
            "an already-dismissed flag must not rewrite the document"
        );
    }

    #[test]
    fn dismiss_first_run_welcome_persists_when_config_is_missing() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        assert!(!path.exists());

        dismiss_first_run_welcome(&path).expect("welcome dismissal persisted");

        assert!(path.exists(), "dismissal must create durable config state");
        let contents = fs::read_to_string(&path).expect("created config readable");
        assert!(contents.contains("[onboarding]"));
        assert!(contents.contains("first_run_welcome_dismissed = true"));
    }

    #[test]
    fn welcome_reader_fails_closed_when_config_cannot_be_trusted() {
        let dir = tempdir().expect("temp dir");
        let missing = dir.path().join("missing.toml");
        assert!(read_first_run_welcome_dismissed(&missing));

        let malformed = dir.path().join("malformed.toml");
        fs::write(
            &malformed,
            "[onboarding]\nfirst_run_welcome_dismissed = definitely\n",
        )
        .expect("malformed config written");
        assert!(read_first_run_welcome_dismissed(&malformed));

        let wrong_type = dir.path().join("wrong-type.toml");
        fs::write(
            &wrong_type,
            "[onboarding]\nfirst_run_welcome_dismissed = 'no'\n",
        )
        .expect("wrong-type config written");
        assert!(read_first_run_welcome_dismissed(&wrong_type));
    }

    #[test]
    fn complete_config_with_legacy_dashboard_loads_without_rewrite() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut contents = toml::to_string_pretty(&AppConfig::default()).expect("default config");
        contents.push_str(concat!(
            "\n# rollback-only Streamlit settings\n",
            "[dashboard]\n",
            "# preserve this block byte-for-byte\n",
            "python = 'C:\\Legacy Python\\python.exe'\n",
            "port = 8502\n",
            "address = \"127.0.0.2\"\n",
            "auto_open_browser = false\n",
        ));
        fs::write(&path, &contents).expect("legacy config written");

        let loaded = load_or_create(&path).expect("legacy config loads");

        assert_eq!(loaded.status, ConfigStatus::Loaded);
        assert_eq!(loaded.config, AppConfig::default());
        assert_eq!(
            fs::read_to_string(&path).expect("legacy config remains readable"),
            contents,
            "loading a complete config must not rewrite retired dashboard text"
        );
    }

    #[test]
    fn malformed_config_uses_defaults_without_overwriting() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let contents =
            "[privacy]\nredact_titles_containing = [\"Falcon-Acquisition\" \"Jane-Doe-Therapy\"]\n";
        fs::write(&path, contents).expect("bad config written");

        let loaded = load_or_create(&path).expect("config loads");

        let ConfigStatus::Malformed { message } = &loaded.status else {
            panic!("expected malformed status");
        };
        assert!(message.contains("TOML parse error"));
        assert!(message.contains("source text omitted"));
        assert!(!message.contains("Falcon-Acquisition"));
        assert!(!message.contains("Jane-Doe-Therapy"));
        assert_eq!(loaded.config, AppConfig::default());
        assert_eq!(
            fs::read_to_string(path).expect("bad file remains"),
            contents
        );
    }

    #[test]
    fn partial_config_uses_field_defaults() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[capture]\nkeyboard = false\n").expect("partial config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.status, ConfigStatus::UpgradedDefaultFields);
        assert!(!loaded.config.capture.keyboard);
        assert!(loaded.config.capture.foreground);
        assert_eq!(loaded.config.writer.batch_size, 100);
        assert_eq!(loaded.config.record.safety_cap_ms, 1_800_000);
        assert_eq!(loaded.config.record.request_poll_interval_ms, 3_000);
        assert!(!loaded.config.record.elevated_helper_enabled);
        assert_eq!(
            loaded.config.record.elevated_helper_strategy,
            ElevatedHelperStrategy::Runas
        );
        assert_eq!(loaded.config.record.elevated_helper_path, "");
        assert_eq!(
            loaded.config.record.elevated_helper_required_signer_sha256,
            ""
        );
        assert_eq!(loaded.config.privacy.retention_days, 90);
        assert_eq!(
            loaded.config.capture.idle_threshold_ms,
            DEFAULT_IDLE_THRESHOLD_MS
        );
        assert!(loaded.config.privacy.sensitive_context_suppression);
        assert!(loaded.config.capture.process_filter);
        assert_eq!(
            loaded.config.hotkey.pause_resume,
            crate::hotkey::DEFAULT_PAUSE_RESUME_HOTKEY
        );
        assert_eq!(loaded.config.privacy.mouse_move_retention_days, 30);

        let upgraded = fs::read_to_string(&path).expect("upgraded config remains readable");
        assert!(upgraded.contains("keyboard = false"));
        assert!(upgraded.contains("idle_threshold_ms = 180000"));
        assert!(upgraded.contains("process_filter = true"));
        assert!(upgraded.contains("[hotkey]"));
        assert!(upgraded.contains("pause_resume = \"ctrl+alt+shift+p\""));
        assert!(upgraded.contains("sensitive_context_suppression = true"));
        assert!(upgraded.contains("mouse_move_retention_days = 30"));
        assert!(upgraded.contains("retention_days = 90"));
        assert!(upgraded.contains("request_poll_interval_ms = 3000"));
        assert!(!upgraded.contains("visible_indicator"));
        assert_record_only_seeding(&upgraded);
    }

    /// Record Routine is Windows-only, so only a Windows upgrade seeds the
    /// record-only keys. Asserting the absence on other platforms is the pin:
    /// a macOS `config.toml` must not offer a `runas` strategy naming a
    /// mechanism that platform does not have, nor a cap on the length of a
    /// recording that platform cannot start.
    ///
    /// `request_poll_interval_ms` is deliberately NOT in this set — the writer
    /// polls `record_requests` on every platform, and off Windows that poll is
    /// what surfaces a request so it can be declined.
    #[track_caller]
    fn assert_record_only_seeding(upgraded: &str) {
        assert!(upgraded.contains("request_poll_interval_ms"));
        #[cfg(windows)]
        {
            assert!(upgraded.contains("safety_cap_ms = 1800000"));
            assert!(upgraded.contains("elevated_helper_enabled = false"));
            assert!(upgraded.contains("elevated_helper_strategy = \"runas\""));
            assert!(upgraded.contains("elevated_helper_path = \"\""));
            assert!(upgraded.contains("elevated_helper_required_signer_sha256 = \"\""));
        }
        #[cfg(not(windows))]
        {
            assert!(!upgraded.contains("safety_cap_ms"));
            assert!(!upgraded.contains("elevated_helper"));
            assert!(!upgraded.contains("runas"));
        }
    }

    #[test]
    fn record_config_loads_and_feeds_writer_poll_interval() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        // visible_indicator is a retired key (stealth-mode-never, 2026-07-02);
        // keeping it in the fixture proves old configs still parse cleanly.
        fs::write(
            &path,
            "[record]\nsafety_cap_ms = 60000\nrequest_poll_interval_ms = 2000\nvisible_indicator = false\nelevated_helper_enabled = true\nelevated_helper_strategy = \"runas\"\nelevated_helper_path = 'C:\\Program Files\\Gilbreth\\gilbreth-elevated-record-helper.exe'\nelevated_helper_required_signer_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        )
        .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.config.record.safety_cap_ms, 60_000);
        assert_eq!(loaded.config.record.request_poll_interval_ms, 2_000);
        assert!(loaded.config.record.elevated_helper_enabled);
        assert_eq!(
            loaded.config.record.elevated_helper_strategy,
            ElevatedHelperStrategy::Runas
        );
        assert_eq!(
            loaded.config.record.elevated_helper_path,
            r"C:\Program Files\Gilbreth\gilbreth-elevated-record-helper.exe"
        );
        assert_eq!(
            loaded.config.record.elevated_helper_required_signer_sha256,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            loaded.config.writer_config().record_request_poll_interval,
            Some(Duration::from_millis(2_000))
        );
    }

    #[test]
    fn privacy_retention_days_loads_from_config() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[privacy]\nretention_days = 30\n").expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.config.privacy.retention_days, 30);
        assert!(loaded.config.privacy.sensitive_context_suppression);
        assert!(loaded.config.privacy.redact_titles_containing.is_empty());
        assert!(loaded.config.privacy.redact_keys_containing.is_empty());
    }

    #[test]
    fn store_key_content_defaults_to_lean_and_loads_opt_in() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        // Fresh config: lean by default, and the key is written visibly so
        // the posture is discoverable in the file.
        let created = load_or_create(&path).expect("config created");
        assert!(!created.config.privacy.store_key_content);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("store_key_content = false"));

        // Explicit opt-in round-trips.
        fs::write(
            &path,
            "[privacy]
store_key_content = true
",
        )
        .expect("config written");
        let loaded = load_or_create(&path).expect("config loads");
        assert!(loaded.config.privacy.store_key_content);
    }

    #[test]
    fn title_retention_fresh_install_is_thirty_days_and_round_trips() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        // Fresh install (R1 flip, DECIDED 2026-07-03): 30 days, written
        // visibly. Existing installs are covered by the grandfather test
        // below — absent key stays 0.
        let created = load_or_create(&path).expect("config created");
        assert_eq!(created.config.privacy.title_retention_days, 30);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("title_retention_days = 30"));

        // Explicit values round-trip, including turning it back off.
        fs::write(
            &path,
            "[privacy]
title_retention_days = 0
",
        )
        .expect("written");
        let loaded = load_or_create(&path).expect("config loads");
        assert_eq!(loaded.config.privacy.title_retention_days, 0);
    }

    #[test]
    fn existing_config_keeps_zero_title_retention_and_confirmed_posture() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[privacy]
retention_days = 30
",
        )
        .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        // The grandfather rule: an existing config missing the new keys is
        // never re-prompted and never gains title aging retroactively; the
        // upgrade writes both keys visibly at their grandfathered values.
        assert!(loaded.config.privacy.posture_confirmed);
        assert_eq!(loaded.config.privacy.title_retention_days, 0);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("posture_confirmed = true"));
        assert!(written.contains("title_retention_days = 0"));
    }

    #[test]
    fn fresh_config_arms_the_first_run_consent_dialog() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        let created = load_or_create(&path).expect("config created");

        assert_eq!(created.status, ConfigStatus::CreatedDefault);
        assert!(!created.config.privacy.posture_confirmed);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("posture_confirmed = false"));

        // A later load of the untouched fresh config still arms the dialog
        // (dismissal re-asks next launch), and a hand-edited false re-arms.
        let reloaded = load_or_create(&path).expect("config reloads");
        assert!(!reloaded.config.privacy.posture_confirmed);
    }

    #[test]
    fn save_store_key_content_confirms_the_posture() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let created = load_or_create(&path).expect("config created");
        assert!(!created.config.privacy.posture_confirmed);

        // Any explicit posture write (tray toggle or dialog Yes/No) confirms
        // in the same atomic write; the dialog never returns after it.
        save_store_key_content(&path, false).expect("posture saved");

        let loaded = load_or_create(&path).expect("config loads");
        assert!(!loaded.config.privacy.store_key_content);
        assert!(loaded.config.privacy.posture_confirmed);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("posture_confirmed = true"));
    }

    #[test]
    fn older_config_upgrade_adds_visible_lean_capture_key() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[privacy]
retention_days = 30
",
        )
        .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        // Absent key means lean mode, and the upgrade writes it visibly
        // without touching existing values.
        assert!(!loaded.config.privacy.store_key_content);
        let written = fs::read_to_string(&path).expect("config readable");
        assert!(written.contains("store_key_content = false"));
        assert!(written.contains("retention_days = 30"));
    }

    #[test]
    fn capture_idle_threshold_loads_from_config() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[capture]\nidle_threshold_ms = 120000\n").expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.config.capture.idle_threshold_ms, 120_000);
        assert_eq!(loaded.config.capture.settings().idle_threshold_ms, 120_000);
    }

    #[test]
    fn privacy_sensitive_context_suppression_can_be_disabled() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[privacy]\nsensitive_context_suppression = false\n")
            .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert!(!loaded.config.privacy.sensitive_context_suppression);
    }

    #[test]
    fn config_upgrade_preserves_existing_sensitive_suppression_choice() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[privacy]\nsensitive_context_suppression = false\nredact_keys_containing = [\"secret\"]\n",
        )
        .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.status, ConfigStatus::UpgradedDefaultFields);
        assert!(!loaded.config.privacy.sensitive_context_suppression);
        assert_eq!(
            loaded.config.privacy.redact_keys_containing,
            vec!["secret".to_string()]
        );
        let upgraded = fs::read_to_string(&path).expect("upgraded config remains readable");
        assert!(upgraded.contains("sensitive_context_suppression = false"));
        assert!(upgraded.contains("retention_days = 90"));
        assert!(upgraded.contains("idle_threshold_ms = 180000"));
        assert_record_only_seeding(&upgraded);
    }

    #[test]
    fn config_upgrade_preserves_unknown_fields() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "# keep me\n[privacy]\nfuture_setting = true # and me\n",
        )
        .expect("config written");

        let loaded = load_or_create(&path).expect("config loads");

        assert_eq!(loaded.status, ConfigStatus::UpgradedDefaultFields);
        let upgraded = fs::read_to_string(&path).expect("upgraded config remains readable");
        assert!(upgraded.contains("# keep me"));
        assert!(upgraded.contains("# and me"));
        assert!(upgraded.contains("future_setting = true"));
        assert!(upgraded.contains("sensitive_context_suppression = true"));
    }

    #[test]
    fn toggle_persistence_updates_only_intended_flag() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut config = AppConfig::default();

        config.capture.set_enabled(CaptureStream::Keyboard, false);
        save_atomic(&path, &config).expect("config saved");

        let loaded = load_or_create(&path).expect("config reloads");
        assert!(!loaded.config.capture.keyboard);
        assert!(loaded.config.capture.mouse);
        assert!(loaded.config.capture.foreground);
    }

    #[test]
    fn capture_toggle_preserves_privacy_settings_and_unknown_fields() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let legacy_dashboard = concat!(
            "# rollback-only Streamlit settings\n",
            "[dashboard]\n",
            "# keep this operator choice\n",
            "python = 'C:\\Legacy Python\\python.exe'\n",
            "port = 8502\n",
            "address = \"127.0.0.2\"\n",
            "auto_open_browser = false\n",
        );
        fs::write(
            &path,
            format!(
                "# hand edit\n{legacy_dashboard}\n[privacy]\nsensitive_context_suppression = false\nredact_titles_containing = [\"Bank\"]\nfuture_setting = true\n\n[capture]\nkeyboard = true\n"
            ),
        )
        .expect("config written");

        save_capture_toggle(&path, CaptureStream::Keyboard, false).expect("toggle persisted");

        let contents = fs::read_to_string(&path).expect("config remains readable");
        assert!(contents.contains("# hand edit"));
        assert!(contents.contains(legacy_dashboard));
        assert!(contents.contains("sensitive_context_suppression = false"));
        assert!(contents.contains("redact_titles_containing = [\"Bank\"]"));
        assert!(contents.contains("future_setting = true"));
        assert!(contents.contains("keyboard = false"));
        let loaded: AppConfig = toml::from_str(&contents).expect("typed config still parses");
        assert!(!loaded.capture.keyboard);
        assert!(!loaded.privacy.sensitive_context_suppression);
        assert_eq!(
            loaded.privacy.redact_titles_containing,
            vec!["Bank".to_string()]
        );
    }

    #[test]
    fn capture_toggle_refuses_malformed_config_without_overwriting() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "not = [valid").expect("bad config written");

        let error = save_capture_toggle(&path, CaptureStream::Mouse, false).expect_err("fails");

        assert!(error.to_string().contains("config is malformed"));
        assert_eq!(
            fs::read_to_string(&path).expect("bad file remains"),
            "not = [valid"
        );
    }

    #[test]
    fn malformed_write_refusals_sanitize_every_error_rendering_and_source() {
        let dir = tempdir().expect("temp dir");
        let contents =
            "[privacy]\nredact_titles_containing = [\"Falcon-Acquisition\" \"Jane-Doe-Therapy\"]\n";

        let tray_path = dir.path().join("Private-Profile-Name.toml");
        fs::write(&tray_path, contents).expect("bad tray config written");
        let tray_error = save_capture_toggle(&tray_path, CaptureStream::Mouse, false)
            .expect_err("tray write refuses malformed config");
        assert!(tray_error.to_string().contains("source text omitted"));
        assert_error_chain_omits(
            &tray_error,
            &[
                "Falcon-Acquisition",
                "Jane-Doe-Therapy",
                "Private-Profile-Name",
                tray_path.to_string_lossy().as_ref(),
            ],
        );

        let dashboard_path = dir.path().join("Private-Dashboard-Profile.toml");
        fs::write(&dashboard_path, contents).expect("bad dashboard config written");
        let dashboard_error = write_privacy_settings(&dashboard_path, &PrivacySettings::default())
            .expect_err("dashboard write refuses malformed config");
        assert!(dashboard_error.to_string().contains("source text omitted"));
        assert_error_chain_omits(
            &dashboard_error,
            &[
                "Falcon-Acquisition",
                "Jane-Doe-Therapy",
                "Private-Dashboard-Profile",
                dashboard_path.to_string_lossy().as_ref(),
            ],
        );
    }

    #[test]
    fn tray_load_read_error_omits_profile_path_from_entire_chain() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("Private-Profile-Name.toml");
        fs::create_dir(&path).expect("directory-shaped config fixture created");

        let error = load_or_create(&path).expect_err("reading a directory must fail");

        assert!(error.to_string().contains("Could not read config file"));
        assert_error_chain_omits(
            &error,
            &["Private-Profile-Name", path.to_string_lossy().as_ref()],
        );
    }

    #[test]
    fn capture_toggle_creates_capture_table_when_absent() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[privacy]\nsensitive_context_suppression = true\n")
            .expect("config written");

        save_capture_toggle(&path, CaptureStream::Mouse, false).expect("toggle persisted");

        let contents = fs::read_to_string(&path).expect("config remains readable");
        assert!(contents.contains("[capture]"));
        assert!(contents.contains("mouse = false"));
        let loaded: AppConfig = toml::from_str(&contents).expect("typed config still parses");
        assert!(!loaded.capture.mouse);
        assert!(loaded.capture.keyboard);
    }

    #[test]
    fn atomic_config_write_produces_valid_toml() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut config = AppConfig::default();
        config.writer.batch_size = 101;

        save_atomic(&path, &config).expect("config saved");

        let contents = fs::read_to_string(path).expect("config exists");
        let parsed: AppConfig = toml::from_str(&contents).expect("valid toml");
        assert_eq!(parsed.writer.batch_size, 101);
        assert!(!contents.contains("[dashboard]"));
    }

    #[test]
    fn atomic_write_cleans_temp_file_and_sanitizes_replace_errors() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::create_dir(&path).expect("destination directory created");

        let error = write_atomic(&path, "secret", "dashboard.tmp").expect_err("replace fails");

        let message = error.to_string();
        assert!(message.contains("Could not write config file"));
        assert!(!message.contains("dashboard.tmp"));
        assert!(!message.contains(&dir.path().display().to_string()));
        assert!(!dir.path().join("config.toml.dashboard.tmp").exists());
    }

    #[test]
    fn spheres_sidecar_sits_beside_config() {
        let dir = tempdir().expect("temp dir");
        let config = config_path(dir.path());
        let sidecar = spheres_sidecar_path(&config);
        assert_eq!(sidecar.parent(), config.parent());
        assert_eq!(
            sidecar.file_name().and_then(|n| n.to_str()),
            Some("spheres.json")
        );
    }

    #[test]
    fn discovery_notice_sidecar_sits_beside_config() {
        let dir = tempdir().expect("temp dir");
        let config = config_path(dir.path());
        let sidecar = discovery_notice_state_sidecar_path(&config);
        assert_eq!(sidecar.parent(), config.parent());
        assert_eq!(
            sidecar.file_name().and_then(|n| n.to_str()),
            Some("notices.json")
        );
    }

    #[test]
    fn privacy_settings_round_trip_preserves_comments_and_unknown_keys() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let legacy_dashboard = concat!(
            "# rollback-only Streamlit settings\n",
            "[dashboard]\n",
            "# keep this operator choice\n",
            "python = 'C:\\Legacy Python\\python.exe'\n",
            "port = 8502\n",
            "address = \"127.0.0.2\"\n",
            "auto_open_browser = false\n",
        );
        fs::write(
            &path,
            format!(
                "# root\n{legacy_dashboard}\n[privacy]\n# keep\nretention_days = 30\nfuture_setting = true\nstore_key_content = true\n"
            ),
        )
        .expect("config written");

        write_privacy_settings(
            &path,
            &PrivacySettings {
                sensitive_context_suppression: false,
                redact_titles_containing: vec![
                    " Bank ".to_string(),
                    "Bank".to_string(),
                    "Secret".to_string(),
                    String::new(),
                ],
                redact_keys_containing: vec![" Enter ".to_string(), "A".to_string()],
                excluded_apps: vec![" Secret.EXE ".to_string(), "secret.exe".to_string()],
                store_key_content: false,
                title_retention_days: 30,
                mouse_move_retention_days: 14,
            },
        )
        .expect("privacy settings written");

        let contents = fs::read_to_string(&path).expect("config readable");
        assert!(contents.contains("# root"));
        assert!(contents.contains(legacy_dashboard));
        assert!(contents.contains("# keep"));
        assert!(contents.contains("future_setting = true"));
        assert!(contents.contains("store_key_content = true"));
        assert!(contents.contains("title_retention_days = 30"));
        assert!(contents.contains("mouse_move_retention_days = 14"));

        let read = read_privacy_settings(&path);
        assert_eq!(read.error, None);
        assert_eq!(
            read.settings,
            PrivacySettings {
                sensitive_context_suppression: false,
                redact_titles_containing: vec!["Bank".to_string(), "Secret".to_string()],
                redact_keys_containing: vec!["Enter".to_string(), "A".to_string()],
                excluded_apps: vec!["Secret.EXE".to_string()],
                store_key_content: true,
                title_retention_days: 30,
                mouse_move_retention_days: 14,
            }
        );
    }

    #[test]
    fn manual_exclusion_paths_are_basename_normalized_on_every_read_boundary() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut config = AppConfig::default();
        config.privacy.excluded_apps = vec![
            r"C:\Users\Alice\Private.exe".to_string(),
            "/Applications/Private.exe".to_string(),
        ];
        fs::write(&path, toml::to_string(&config).expect("serialize config"))
            .expect("write config");

        let loaded = load_or_create(&path).expect("load config");
        assert_eq!(loaded.config.privacy.excluded_apps, vec!["Private.exe"]);
        let dashboard = read_privacy_settings(&path);
        assert_eq!(dashboard.settings.excluded_apps, vec!["Private.exe"]);
        let serialized = serde_json::to_string(&loaded.config.privacy.excluded_apps)
            .expect("serialize normalized apps");
        assert!(!serialized.contains("Alice"));
        assert!(!serialized.contains("Applications"));
    }

    #[test]
    fn privacy_settings_preserve_inline_table_siblings() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "privacy = { retention_days = 5, store_key_content = true, future_setting = \"keep\" }\n",
        )
        .expect("config written");

        write_privacy_settings(
            &path,
            &PrivacySettings {
                sensitive_context_suppression: false,
                redact_titles_containing: vec!["Bank".to_string()],
                redact_keys_containing: vec!["Enter".to_string()],
                excluded_apps: vec![r"C:\Tools\Private.exe".to_string()],
                store_key_content: false,
                title_retention_days: 30,
                mouse_move_retention_days: 14,
            },
        )
        .expect("privacy settings written");

        let contents = fs::read_to_string(&path).expect("config readable");
        let parsed: toml::Value = toml::from_str(&contents).expect("valid TOML");
        let privacy = parsed
            .get("privacy")
            .and_then(toml::Value::as_table)
            .expect("privacy table");
        assert_eq!(
            privacy
                .get("retention_days")
                .and_then(toml::Value::as_integer),
            Some(5)
        );
        assert_eq!(
            privacy
                .get("store_key_content")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            privacy.get("future_setting").and_then(toml::Value::as_str),
            Some("keep")
        );
        assert_eq!(
            privacy
                .get("title_retention_days")
                .and_then(toml::Value::as_integer),
            Some(30)
        );
    }

    #[test]
    fn privacy_settings_missing_config_writes_dashboard_owned_keys_only() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        write_privacy_settings(&path, &PrivacySettings::default())
            .expect("privacy settings written");

        let parsed: toml::Value =
            toml::from_str(&fs::read_to_string(&path).expect("config readable"))
                .expect("valid toml");
        let privacy = parsed
            .get("privacy")
            .and_then(toml::Value::as_table)
            .expect("privacy table");
        let keys = privacy.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "sensitive_context_suppression".to_string(),
                "redact_titles_containing".to_string(),
                "redact_keys_containing".to_string(),
                "excluded_apps".to_string(),
                "title_retention_days".to_string(),
                "mouse_move_retention_days".to_string(),
            ])
        );
    }

    #[test]
    fn privacy_settings_defaults_and_malformed_config_are_safe() {
        let dir = tempdir().expect("temp dir");
        let missing = dir.path().join("missing.toml");
        let malformed = dir.path().join("bad.toml");
        fs::write(&malformed, "secret = [not valid").expect("bad config written");

        let missing_read = read_privacy_settings(&missing);
        assert_eq!(missing_read.error, None);
        assert_eq!(missing_read.settings, PrivacySettings::default());

        let malformed_read = read_privacy_settings(&malformed);
        assert!(malformed_read
            .error
            .as_deref()
            .unwrap_or("")
            .contains("line"));
        assert!(!malformed_read
            .error
            .as_deref()
            .unwrap_or("")
            .contains("secret"));
        assert_eq!(malformed_read.settings, PrivacySettings::default());

        fs::write(
            &malformed,
            "[privacy]\ntitle_retention_days = -5\nmouse_move_retention_days = -2\n",
        )
        .expect("negative config written");
        let read = read_privacy_settings(&malformed);
        assert_eq!(read.settings.title_retention_days, 0);
        assert_eq!(read.settings.mouse_move_retention_days, 0);
    }

    #[test]
    fn privacy_settings_write_recovers_bad_owned_values() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[dashboard]\nport = 8502\n[privacy]\ntitle_retention_days = \"soon\"\n",
        )
        .expect("config written");

        let settings = PrivacySettings {
            title_retention_days: 30,
            ..PrivacySettings::default()
        };
        write_privacy_settings(&path, &settings).expect("privacy settings repaired");

        let read = read_privacy_settings(&path);
        assert_eq!(read.settings.title_retention_days, 30);
        let contents = fs::read_to_string(&path).expect("config readable");
        assert!(contents.contains("port = 8502"));
    }

    #[test]
    fn sphere_overlay_enabled_round_trips_and_fails_closed() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        assert!(!read_sphere_overlay_enabled(&path));
        fs::write(&path, "[privacy]\nretention_days = 30\n").expect("config written");
        assert!(!read_sphere_overlay_enabled(&path));

        write_sphere_overlay_enabled(&path, true).expect("overlay enabled");
        assert!(read_sphere_overlay_enabled(&path));
        let contents = fs::read_to_string(&path).expect("config readable");
        assert!(contents.contains("retention_days = 30"));
        assert!(contents.contains("sphere_labels_from_titles = true"));

        write_sphere_overlay_enabled(&path, false).expect("overlay disabled");
        assert!(!read_sphere_overlay_enabled(&path));

        fs::write(&path, "[analytics]\nsphere_labels_from_titles = \"yes\"\n")
            .expect("non-bool config written");
        assert!(!read_sphere_overlay_enabled(&path));
        fs::write(&path, "not toml [").expect("bad config written");
        assert!(!read_sphere_overlay_enabled(&path));
        assert!(write_sphere_overlay_enabled(&path, true).is_err());
        assert_eq!(
            fs::read_to_string(&path).expect("bad config remains"),
            "not toml ["
        );

        let missing = dir.path().join("missing.toml");
        write_sphere_overlay_enabled(&missing, true).expect("missing overlay config written");
        let missing_bytes = fs::read(&missing).expect("missing config readable");
        assert_eq!(
            missing_bytes,
            b"[analytics]\nsphere_labels_from_titles = true\n"
        );
        let missing_contents = String::from_utf8(missing_bytes).expect("missing config is UTF-8");
        assert!(missing_contents.contains("[analytics]"));
        assert!(missing_contents.contains("sphere_labels_from_titles = true"));
        assert!(!missing_contents.contains("[privacy]"));
    }

    #[test]
    fn discovery_notice_state_sidecar_round_trips_sorted_and_cleans_temp() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("notices.json");
        let state = DiscoveryNoticeState {
            dismissed: BTreeMap::from([
                ("notice-b".to_string(), "2026-07-08".to_string()),
                ("notice-a".to_string(), "2026-07-07".to_string()),
            ]),
            muted: BTreeSet::from(["muted-b".to_string(), "muted-a".to_string()]),
            watched: BTreeSet::from(["watched".to_string()]),
        };

        write_discovery_notice_state(&path, &state).expect("state written");

        let raw = fs::read(&path).expect("state readable");
        assert_eq!(
            raw,
            concat!(
                "{\n",
                "  \"version\": 1,\n",
                "  \"dismissed\": {\n",
                "    \"notice-a\": \"2026-07-07\",\n",
                "    \"notice-b\": \"2026-07-08\"\n",
                "  },\n",
                "  \"muted\": [\n",
                "    \"muted-a\",\n",
                "    \"muted-b\"\n",
                "  ],\n",
                "  \"watched\": [\n",
                "    \"watched\"\n",
                "  ]\n",
                "}\n"
            )
            .as_bytes()
        );
        assert_eq!(read_discovery_notice_state(&path), state);
        assert!(!dir.path().join("notices.json.tmp").exists());

        fs::write(
            &path,
            r#"{"dismissed":{" ":"today","kept":"2026-07-09"},"muted":["","x"],"watched":"bad"}"#,
        )
        .expect("messy state written");
        assert_eq!(
            read_discovery_notice_state(&path),
            DiscoveryNoticeState {
                dismissed: BTreeMap::from([("kept".to_string(), "2026-07-09".to_string())]),
                muted: BTreeSet::from(["x".to_string()]),
                watched: BTreeSet::new(),
            }
        );

        fs::write(&path, "not json{").expect("bad state written");
        assert_eq!(
            read_discovery_notice_state(&path),
            DiscoveryNoticeState::default()
        );

        fs::remove_file(&path).expect("remove state file");
        fs::create_dir(&path).expect("replace destination directory created");
        let error = write_discovery_notice_state(&path, &state).expect_err("replace fails");
        assert!(error.to_string().contains("Could not write config file"));
        assert!(!dir.path().join("notices.json.tmp").exists());
    }

    #[test]
    fn retention_days_read_is_tolerant_and_positive_only() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        assert_eq!(read_retention_days(&path), 90);
        fs::write(&path, "not = [valid").expect("bad config written");
        assert_eq!(read_retention_days(&path), 90);
        fs::write(&path, "[privacy]\nretention_days = 0\n").expect("config written");
        assert_eq!(read_retention_days(&path), 90);
        fs::write(&path, "[privacy]\nretention_days = \"30\"\n").expect("config written");
        assert_eq!(read_retention_days(&path), 90);
        fs::write(&path, "[privacy]\nretention_days = 30\n").expect("config written");
        assert_eq!(read_retention_days(&path), 30);
    }

    #[test]
    fn verified_framework_classes_read_is_tolerant_and_double_filtered() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        // Missing file, malformed TOML, non-table export, and non-array
        // values all read as the empty set (db.py parity).
        assert!(read_verified_framework_classes(&path).is_empty());
        fs::write(&path, "not = [valid").expect("bad config written");
        assert!(read_verified_framework_classes(&path).is_empty());
        fs::write(&path, "export = 3\n").expect("config written");
        assert!(read_verified_framework_classes(&path).is_empty());
        fs::write(&path, "[export]\nverified_framework_classes = \"native\"\n")
            .expect("config written");
        assert!(read_verified_framework_classes(&path).is_empty());

        // Only classes on BOTH allowlists survive: known-but-unverifiable
        // classes, unknown strings, and non-string items are dropped.
        fs::write(
            &path,
            "[export]\nverified_framework_classes = [\"native\", \"web_renderer\", \
             \"native_provisional\", \"bogus\", 7]\n",
        )
        .expect("config written");
        assert_eq!(
            read_verified_framework_classes(&path),
            HashSet::from(["native".to_string()])
        );
    }

    #[test]
    fn sphere_alias_sidecar_round_trips_casefolds_and_prunes() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("spheres.json");
        let aliases = BTreeMap::from([
            ("Straße".to_string(), "Comms".to_string()),
            ("Ა Project".to_string(), "Georgian".to_string()),
            ("  Inbox  ".to_string(), "Mail".to_string()),
            ("".to_string(), "dropped".to_string()),
            ("blank".to_string(), " ".to_string()),
        ]);

        write_sphere_aliases(&path, &aliases).expect("aliases written");

        let raw = fs::read_to_string(&path).expect("aliases readable");
        assert!(raw.contains("\"version\": 1"));
        assert_eq!(
            read_sphere_aliases(&path),
            BTreeMap::from([
                ("inbox".to_string(), "Mail".to_string()),
                ("strasse".to_string(), "Comms".to_string()),
                ("ა project".to_string(), "Georgian".to_string()),
            ])
        );
        assert!(!dir.path().join("spheres.json.tmp").exists());

        let kept = prune_stale_sphere_aliases(&path, ["STRASSE"]).expect("aliases pruned");
        assert_eq!(
            kept,
            BTreeMap::from([("strasse".to_string(), "Comms".to_string())])
        );
        assert_eq!(read_sphere_aliases(&path), kept);

        fs::write(&path, r#"{"version":1,"aliases":"nope"}"#).expect("bad aliases written");
        assert!(read_sphere_aliases(&path).is_empty());
        fs::write(
            &path,
            r#"{"version":1,"aliases":{"ok":"Kept","bad":3,"other":["x"]}}"#,
        )
        .expect("mixed aliases written");
        assert_eq!(
            read_sphere_aliases(&path),
            BTreeMap::from([("ok".to_string(), "Kept".to_string())])
        );

        fs::remove_file(&path).expect("remove alias file");
        fs::create_dir(&path).expect("replace destination directory created");
        let error = write_sphere_aliases(&path, &aliases).expect_err("replace fails");
        assert!(error.to_string().contains("Could not write config file"));
        assert!(!dir.path().join("spheres.json.tmp").exists());
    }

    #[test]
    fn sphere_alias_sidecar_matches_python_byte_order_and_utf8() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("spheres.json");
        let aliases = BTreeMap::from([
            ("B".to_string(), "old".to_string()),
            ("a".to_string(), "Álpha".to_string()),
            ("b".to_string(), "Béta".to_string()),
        ]);

        write_sphere_aliases(&path, &aliases).expect("aliases written");

        assert_eq!(
            fs::read(path).expect("aliases readable"),
            concat!(
                "{\n",
                "  \"version\": 1,\n",
                "  \"aliases\": {\n",
                "    \"b\": \"Béta\",\n",
                "    \"a\": \"Álpha\"\n",
                "  }\n",
                "}\n"
            )
            .as_bytes()
        );
    }

    #[test]
    fn python_only_whitespace_is_stripped_from_aliases_and_patterns() {
        assert_eq!(python_strip("\u{1c}\u{1f}"), "");
        assert_eq!(casefold_token("\u{1c}Straße\u{1f}"), "strasse");
        assert_eq!(
            normalize_privacy_patterns(&["\u{1c}".to_string(), "\u{1c}Falcon\u{1f}".to_string(),]),
            vec!["Falcon".to_string()]
        );

        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("spheres.json");
        fs::write(
            &path,
            r#"{"version":1,"aliases":{"\u001cNotes\u001f":"\u001cFocus\u001f"}}"#,
        )
        .expect("aliases written");

        assert_eq!(
            read_sphere_aliases(&path),
            BTreeMap::from([("notes".to_string(), "Focus".to_string())])
        );
        assert_eq!(
            prune_stale_sphere_aliases(&path, ["\u{1c}NOTES\u{1f}"]).expect("alias retained"),
            BTreeMap::from([("notes".to_string(), "Focus".to_string())])
        );
    }

    #[test]
    fn no_op_alias_prune_does_not_rewrite_sidecar() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("spheres.json");
        write_sphere_aliases(
            &path,
            &BTreeMap::from([("Notes".to_string(), "Focus".to_string())]),
        )
        .expect("aliases written");
        let before = fs::metadata(&path)
            .expect("metadata before prune")
            .modified()
            .expect("mtime before prune");
        std::thread::sleep(std::time::Duration::from_millis(20));

        assert_eq!(
            prune_stale_sphere_aliases(&path, ["NOTES"]).expect("no-op prune"),
            BTreeMap::from([("notes".to_string(), "Focus".to_string())])
        );

        let after = fs::metadata(&path)
            .expect("metadata after prune")
            .modified()
            .expect("mtime after prune");
        assert_eq!(after, before, "no-op prune must not replace the sidecar");
    }

    #[test]
    fn python_only_whitespace_is_empty_in_notice_state() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("notices.json");
        fs::write(
            &path,
            r#"{
                "dismissed": {"\u001c": "2026-07-09", "notice": "\u001f"},
                "muted": ["\u001c", "kept"],
                "watched": ["\u001f", "also-kept"]
            }"#,
        )
        .expect("notice state written");

        assert_eq!(
            read_discovery_notice_state(&path),
            DiscoveryNoticeState {
                dismissed: BTreeMap::new(),
                muted: BTreeSet::from(["kept".to_string()]),
                watched: BTreeSet::from(["also-kept".to_string()]),
            }
        );
    }
}
