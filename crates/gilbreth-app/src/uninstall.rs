//! Offline package lifecycle and destructive-uninstall entry points.
//!
//! These routes run before tracing, config loading, dashboard startup, or any
//! capture thread. Receipts intentionally contain only fixed class names,
//! outcomes, counts, and coarse error categories.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

#[cfg(any(windows, test))]
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
};

#[cfg(windows)]
use crate::authenticode;
use crate::platform::LifecycleExclusiveGuard;
#[cfg(windows)]
use crate::platform::{local_data_dir, SingleInstance};
#[cfg(any(windows, test))]
use crate::privacy_receipt::{
    PrivacyOperation, PrivacyReceipt, ReceiptClass, ReceiptOutcome, ReceiptStatus,
};
use anyhow::{anyhow, bail, Context, Result};

#[cfg(windows)]
const TEST_ROOT_ENV: &str = "GILBRETH_ALLOW_TEST_DATA_ROOT";
#[cfg(any(windows, test))]
const TEST_ROOT_MARKER: &str = ".gilbreth-purge-test-root";
#[cfg(windows)]
const TEST_ROOT_MARKER_CONTENT: &[u8] = b"GILBRETH-PURGE-TEST-ROOT-V1\n";
#[cfg(windows)]
const PACKAGE_TRUST_MODE: &str = env!("GILBRETH_PACKAGE_TRUST_MODE");
#[cfg(windows)]
const PACKAGE_SIGNER_SUBJECT: &str = env!("GILBRETH_PACKAGE_SIGNER_SUBJECT");

#[derive(Debug, Eq, PartialEq)]
pub enum OfflineCommand {
    LifecyclePreflight {
        install_root: PathBuf,
    },
    PackageSelfCheck {
        expected_version: String,
        expected_git_sha: Option<String>,
    },
    UninstallLifecyclePreflight {
        install_root: PathBuf,
        allow_unsigned_package: bool,
        installer_lock_held: bool,
    },
    UninstallPurge {
        receipt: PathBuf,
        data_root: Option<PathBuf>,
        installer_lock_held: bool,
        allow_unsigned_package: bool,
    },
}

pub fn parse_offline_command(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Option<OfflineCommand>> {
    let mut args = arguments.into_iter();
    let Some(route) = args.next() else {
        return Ok(None);
    };
    if route == OsStr::new("--lifecycle-preflight") {
        let flag = args
            .next()
            .ok_or_else(|| anyhow!("missing --install-root"))?;
        if flag != OsStr::new("--install-root") {
            bail!("lifecycle preflight requires --install-root");
        }
        let install_root = PathBuf::from(
            args.next()
                .ok_or_else(|| anyhow!("missing install root value"))?,
        );
        if args.next().is_some() {
            bail!("unexpected lifecycle preflight argument");
        }
        return Ok(Some(OfflineCommand::LifecyclePreflight { install_root }));
    }
    if route == OsStr::new("--package-self-check") {
        let flag = args
            .next()
            .ok_or_else(|| anyhow!("missing --expect-version"))?;
        if flag != OsStr::new("--expect-version") {
            bail!("package self-check requires --expect-version");
        }
        let expected_version = os_string(args.next(), "missing expected version")?;
        let expected_git_sha = match args.next() {
            None => None,
            Some(flag) if flag == OsStr::new("--expect-git-sha") => {
                Some(os_string(args.next(), "missing expected git SHA")?)
            }
            Some(_) => bail!("unexpected package self-check argument"),
        };
        if args.next().is_some() {
            bail!("unexpected package self-check argument");
        }
        return Ok(Some(OfflineCommand::PackageSelfCheck {
            expected_version,
            expected_git_sha,
        }));
    }
    if route == OsStr::new("--uninstall-lifecycle-preflight") {
        let flag = args
            .next()
            .ok_or_else(|| anyhow!("missing --install-root"))?;
        if flag != OsStr::new("--install-root") {
            bail!("uninstall lifecycle preflight requires --install-root");
        }
        let install_root = PathBuf::from(
            args.next()
                .ok_or_else(|| anyhow!("missing install root value"))?,
        );
        let mut allow_unsigned_package = false;
        let mut installer_lock_held = false;
        for flag in args.by_ref() {
            if flag == OsStr::new("--allow-unsigned-package") && !allow_unsigned_package {
                allow_unsigned_package = true;
            } else if flag == OsStr::new("--installer-lock-held") && !installer_lock_held {
                installer_lock_held = true;
            } else {
                bail!("unexpected uninstall lifecycle preflight argument");
            }
        }
        return Ok(Some(OfflineCommand::UninstallLifecyclePreflight {
            install_root,
            allow_unsigned_package,
            installer_lock_held,
        }));
    }
    if route == OsStr::new("--uninstall-purge") {
        let flag = args.next().ok_or_else(|| anyhow!("missing --receipt"))?;
        if flag != OsStr::new("--receipt") {
            bail!("uninstall purge requires --receipt");
        }
        let receipt = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing receipt path"))?);
        let mut data_root = None;
        let mut installer_lock_held = false;
        let mut allow_unsigned_package = false;
        while let Some(flag) = args.next() {
            if flag == OsStr::new("--data-root") && data_root.is_none() {
                data_root = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("missing data root value"))?,
                ));
            } else if flag == OsStr::new("--installer-lock-held") && !installer_lock_held {
                installer_lock_held = true;
            } else if flag == OsStr::new("--allow-unsigned-package") && !allow_unsigned_package {
                allow_unsigned_package = true;
            } else {
                bail!("unexpected uninstall purge argument");
            }
        }
        return Ok(Some(OfflineCommand::UninstallPurge {
            receipt,
            data_root,
            installer_lock_held,
            allow_unsigned_package,
        }));
    }
    Ok(None)
}

fn os_string(value: Option<OsString>, missing: &str) -> Result<String> {
    value
        .ok_or_else(|| anyhow!(missing.to_string()))?
        .into_string()
        .map_err(|_| anyhow!("argument must be valid Unicode"))
}

pub fn execute(command: OfflineCommand, app_version: &str, git_sha: &str) -> Result<()> {
    match command {
        OfflineCommand::LifecyclePreflight { install_root } => {
            let _guard = LifecycleExclusiveGuard::acquire(&install_root)
                .context("package lifecycle preflight failed")?;
            Ok(())
        }
        OfflineCommand::PackageSelfCheck {
            expected_version,
            expected_git_sha,
        } => package_self_check(
            app_version,
            git_sha,
            &expected_version,
            expected_git_sha.as_deref(),
        ),
        OfflineCommand::UninstallLifecyclePreflight {
            install_root,
            allow_unsigned_package,
            installer_lock_held,
        } => run_uninstall_lifecycle_preflight(
            &install_root,
            allow_unsigned_package,
            installer_lock_held,
        ),
        OfflineCommand::UninstallPurge {
            receipt,
            data_root,
            installer_lock_held,
            allow_unsigned_package,
        } => run_uninstall_purge(
            &receipt,
            data_root.as_deref(),
            installer_lock_held,
            allow_unsigned_package,
        ),
    }
}

fn package_self_check(
    app_version: &str,
    git_sha: &str,
    expected_version: &str,
    expected_git_sha: Option<&str>,
) -> Result<()> {
    if app_version != expected_version {
        bail!("package version does not match the expected version");
    }
    if let Some(expected) = expected_git_sha {
        let embedded = git_sha.trim().to_ascii_lowercase();
        let expected = expected.trim().to_ascii_lowercase();
        if embedded == "unknown"
            || embedded.len() < 7
            || !embedded.bytes().all(|byte| byte.is_ascii_hexdigit())
            || expected.len() < embedded.len()
            || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !expected.starts_with(&embedded)
        {
            bail!("package git SHA does not match the expected source");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_package_authority(
    executable: &Path,
    allow_unsigned_package: bool,
) -> Result<Option<authenticode::AuthenticodeLaunchLock>> {
    match (PACKAGE_TRUST_MODE, allow_unsigned_package) {
        ("release-package", false) => {
            let (_, lock) = authenticode::verify_file_signed_by_subject_for_launch(
                executable,
                PACKAGE_SIGNER_SUBJECT,
            )
            .context("installed package signer verification failed")?;
            Ok(Some(lock))
        }
        ("release-package", true) => {
            if authenticode::verify_file_for_launch(executable).is_ok() {
                bail!("signed package refused unsigned-package authority override");
            }
            Ok(None)
        }
        _ => bail!("development builds cannot authorize installed-package lifecycle actions"),
    }
}

#[cfg(windows)]
fn run_uninstall_lifecycle_preflight(
    install_root: &Path,
    allow_unsigned_package: bool,
    installer_lock_held: bool,
) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate lifecycle guard")?;
    let _authority = require_package_authority(&executable, allow_unsigned_package)?;
    let _guard = if installer_lock_held {
        LifecycleExclusiveGuard::acquire_under_installer_lock(install_root)
            .context("failed to verify installer-owned uninstall lifecycle guard")?
    } else {
        LifecycleExclusiveGuard::acquire(install_root)
            .context("uninstall package lifecycle preflight failed")?
    };
    Ok(())
}

#[cfg(not(windows))]
fn run_uninstall_lifecycle_preflight(
    _install_root: &Path,
    _allow_unsigned_package: bool,
    _installer_lock_held: bool,
) -> Result<()> {
    bail!("uninstall lifecycle preflight is Windows-only")
}

#[cfg(windows)]
fn run_uninstall_purge(
    receipt: &Path,
    explicit_data_root: Option<&Path>,
    installer_lock_held: bool,
    allow_unsigned_package: bool,
) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate uninstall executable")?;
    let _authority = require_package_authority(&executable, allow_unsigned_package)?;
    let install_root = executable
        .parent()
        .ok_or_else(|| anyhow!("uninstall executable has no parent"))?;
    let _lifecycle = if installer_lock_held {
        LifecycleExclusiveGuard::acquire_under_installer_lock(install_root)
            .context("failed to verify the installer-owned lifecycle guard")?
    } else {
        LifecycleExclusiveGuard::acquire_for_purge(install_root)
            .context("failed to acquire exclusive package lifecycle guard")?
    };
    let _writer = SingleInstance::acquire().context("failed to acquire writer mutex")?;

    let data_root = match explicit_data_root {
        Some(root) => validate_test_data_root(root)?,
        None => local_data_dir()?,
    };
    if data_root.exists() {
        let metadata = fs::symlink_metadata(&data_root)
            .context("failed to inspect the data root before purge")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("data root must be a real directory, not a link or file");
        }
    }
    validate_receipt_path(receipt, &data_root, explicit_data_root.is_some())?;
    let prepared = PreparedReceipt::create(receipt)?;
    let report = purge_data_root(&data_root, explicit_data_root.is_some());
    prepared.commit(&report)?;
    if report.status == ReceiptStatus::Incomplete {
        bail!("destructive uninstall was incomplete; inspect the content-free receipt");
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_uninstall_purge(
    _receipt: &Path,
    _explicit_data_root: Option<&Path>,
    _installer_lock_held: bool,
    _allow_unsigned_package: bool,
) -> Result<()> {
    bail!("offline uninstall purge is Windows-only")
}

#[cfg(windows)]
fn validate_test_data_root(root: &Path) -> Result<PathBuf> {
    if std::env::var(TEST_ROOT_ENV).as_deref() != Ok("1") {
        bail!("explicit data root requires the test-purge environment guard");
    }
    if !root.is_absolute() || !root.is_dir() {
        bail!("explicit data root must be an absolute existing directory");
    }
    let root = fs::canonicalize(root).context("failed to canonicalize explicit data root")?;
    let temp = fs::canonicalize(std::env::temp_dir())
        .context("failed to canonicalize the temporary directory")?;
    if root == temp || !root.starts_with(&temp) {
        bail!("explicit data root must be strictly beneath the temporary directory");
    }
    let marker = root.join(TEST_ROOT_MARKER);
    if fs::symlink_metadata(&marker)
        .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        .unwrap_or(true)
        || !fs::read(&marker)
            .map(|contents| contents == TEST_ROOT_MARKER_CONTENT)
            .unwrap_or(false)
    {
        bail!("explicit data root is missing the exact test-purge safety marker");
    }
    Ok(root)
}

#[cfg(windows)]
fn validate_receipt_path(receipt: &Path, data_root: &Path, test_mode: bool) -> Result<()> {
    if !receipt.is_absolute() {
        bail!("receipt path must be absolute");
    }
    let parent = receipt
        .parent()
        .ok_or_else(|| anyhow!("receipt path has no parent"))?;
    let parent = fs::canonicalize(parent).context("receipt parent must already exist")?;
    let data_root = if data_root.exists() {
        fs::canonicalize(data_root).context("failed to canonicalize data root")?
    } else {
        data_root.to_path_buf()
    };
    if parent == data_root || parent.starts_with(&data_root) {
        bail!("receipt must be outside the data root");
    }
    if test_mode {
        let temp = fs::canonicalize(std::env::temp_dir())
            .context("failed to canonicalize the temporary directory")?;
        if parent == temp || !parent.starts_with(&temp) {
            bail!("test receipt parent must be strictly beneath the temporary directory");
        }
    } else {
        let local_parent = local_data_dir()?
            .parent()
            .ok_or_else(|| anyhow!("local data directory has no parent"))?
            .to_path_buf();
        let expected = fs::canonicalize(local_parent.join("Gilbreth-uninstall-receipts"))
            .context("production receipt directory must already exist")?;
        if parent != expected {
            bail!("production receipt must use the dedicated Gilbreth receipt directory");
        }
    }
    if receipt.extension() != Some(OsStr::new("json")) {
        bail!("receipt path must use the .json extension");
    }
    if receipt.exists() {
        bail!("receipt path already exists");
    }
    Ok(())
}

#[cfg(any(windows, test))]
type PurgeReceipt = PrivacyReceipt;

#[cfg(any(windows, test))]
type ClassReceipt = ReceiptClass;

#[cfg(any(windows, test))]
fn class_receipt(
    class: &'static str,
    outcome: ReceiptOutcome,
    item_count: usize,
    error_category: Option<&'static str>,
) -> ClassReceipt {
    let receipt = ClassReceipt::new(class, outcome).with_count(item_count);
    match error_category {
        Some(category) => receipt.with_error_category(category),
        None => receipt,
    }
}

#[cfg(any(windows, test))]
fn removed(class: &'static str, item_count: usize) -> ClassReceipt {
    class_receipt(class, ReceiptOutcome::Removed, item_count, None)
}

#[cfg(any(windows, test))]
fn purge_data_root(data_root: &Path, has_test_marker: bool) -> PurgeReceipt {
    match fs::symlink_metadata(data_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return root_failure_receipt(io_error_category(&error)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return root_failure_receipt("unsafe_path")
        }
        Ok(_) => {}
    }

    let known = [
        "gilbreth.db",
        "gilbreth.db-wal",
        "gilbreth.db-shm",
        "config.toml",
        "config.toml.tmp",
        "config.toml.upgrade.tmp",
        "config.toml.tray.tmp",
        "config.toml.dashboard.tmp",
        crate::config::CONFIG_LOCK_NAME,
        TEST_ROOT_MARKER,
        "spheres.json",
        "spheres.json.tmp",
        "notices.json",
        "notices.json.tmp",
        crate::hotkey::HOTKEY_STATUS_SIDECAR_NAME,
        crate::notification_consent::NOTIFICATION_ACCESS_SIDECAR_NAME,
        "dashboard-ui.ron",
        "dashboard-ui.lock",
        "logs",
        "archives",
        crate::privacy_receipt::RECEIPT_DIRECTORY,
        "rollback",
        "bin",
    ];
    let mut classes = Vec::new();
    classes.push(purge_files(
        data_root,
        "database",
        &["gilbreth.db", "gilbreth.db-wal", "gilbreth.db-shm"],
    ));
    let configured_database = purge_configured_database(data_root);
    let preserve_configuration = matches!(
        configured_database.outcome,
        ReceiptOutcome::Deferred | ReceiptOutcome::NeedsRetry
    );
    classes.push(configured_database);
    let mut configuration = vec![
        "config.toml",
        "config.toml.tmp",
        "config.toml.upgrade.tmp",
        "config.toml.tray.tmp",
        "config.toml.dashboard.tmp",
        crate::config::CONFIG_LOCK_NAME,
    ];
    if has_test_marker {
        configuration.push(TEST_ROOT_MARKER);
    }
    classes.push(if preserve_configuration {
        defer_files(
            data_root,
            "configuration_and_staging",
            &configuration,
            "class_incomplete",
        )
    } else {
        purge_files(data_root, "configuration_and_staging", &configuration)
    });
    classes.push(purge_files(
        data_root,
        "sidecars_and_staging",
        &[
            "spheres.json",
            "spheres.json.tmp",
            "notices.json",
            "notices.json.tmp",
            crate::hotkey::HOTKEY_STATUS_SIDECAR_NAME,
            crate::notification_consent::NOTIFICATION_ACCESS_SIDECAR_NAME,
        ],
    ));
    classes.push(purge_files(
        data_root,
        "ui_state",
        &["dashboard-ui.ron", "dashboard-ui.lock"],
    ));
    classes.push(purge_directory(data_root, "logs", "logs"));
    classes.push(purge_directory(data_root, "archives", "archives"));
    classes.push(purge_directory(
        data_root,
        "privacy_operation_receipts",
        crate::privacy_receipt::RECEIPT_DIRECTORY,
    ));
    classes.push(purge_directory(data_root, "rollback_sensitive", "rollback"));
    let (legacy, bin_unknown) = purge_legacy_program_files(data_root);
    classes.push(legacy);
    classes.push(class_receipt(
        "external_exports",
        ReceiptOutcome::Retained,
        0,
        None,
    ));
    let root_unknown = count_unknown_directory_entries(data_root, &known);
    classes.push(match (root_unknown, bin_unknown) {
        (Ok(root_count), Ok(bin_count)) if root_count + bin_count == 0 => {
            removed("unknown_entries", 0)
        }
        (Ok(root_count), Ok(bin_count)) => class_receipt(
            "unknown_entries",
            ReceiptOutcome::Deferred,
            root_count + bin_count,
            Some("unknown_entries"),
        ),
        (Err(category), _) | (_, Err(category)) => class_receipt(
            "unknown_entries",
            ReceiptOutcome::NeedsRetry,
            0,
            Some(category),
        ),
    });

    let mut incomplete = classes.iter().any(|class| {
        matches!(
            class.outcome,
            ReceiptOutcome::Deferred | ReceiptOutcome::NeedsRetry
        )
    });
    if incomplete {
        classes.push(class_receipt(
            "data_root",
            ReceiptOutcome::Deferred,
            usize::from(data_root.exists()),
            Some("class_incomplete"),
        ));
    } else {
        let root_result = match fs::remove_dir(data_root) {
            Ok(()) => removed("data_root", 1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => removed("data_root", 0),
            Err(error) => class_receipt(
                "data_root",
                ReceiptOutcome::NeedsRetry,
                1,
                Some(io_error_category(&error)),
            ),
        };
        incomplete = root_result.outcome == ReceiptOutcome::NeedsRetry;
        classes.push(root_result);
    }
    let mut receipt = PurgeReceipt::new(PrivacyOperation::UninstallPurge, classes);
    receipt.status = if incomplete {
        ReceiptStatus::Incomplete
    } else {
        ReceiptStatus::Completed
    };
    receipt
}

#[cfg(any(windows, test))]
fn root_failure_receipt(category: &'static str) -> PurgeReceipt {
    PurgeReceipt::new(
        PrivacyOperation::UninstallPurge,
        vec![class_receipt(
            "data_root",
            ReceiptOutcome::NeedsRetry,
            1,
            Some(category),
        )],
    )
}

#[cfg(any(windows, test))]
fn purge_configured_database(data_root: &Path) -> ClassReceipt {
    let config_path = data_root.join("config.toml");
    let contents = match fs::read_to_string(&config_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return removed("configured_database", 0)
        }
        Err(_) => {
            return class_receipt(
                "configured_database",
                ReceiptOutcome::Deferred,
                0,
                Some("unresolved_config"),
            )
        }
    };
    let config = match toml::from_str::<crate::config::AppConfig>(&contents) {
        Ok(config) => config,
        Err(_) => {
            return class_receipt(
                "configured_database",
                ReceiptOutcome::Deferred,
                0,
                Some("unresolved_config"),
            )
        }
    };
    let configured = config.db_path(data_root);
    if !configured.is_absolute() {
        return class_receipt(
            "configured_database",
            ReceiptOutcome::Deferred,
            0,
            Some("unresolved_external_path"),
        );
    }
    let default = data_root.join("gilbreth.db");
    if configured == default {
        return removed("configured_database", 0);
    }
    let mut count = 0;
    let mut category = None;
    for path in &sqlite_file_family(&configured) {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                count += 1;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    category.get_or_insert("unsafe_path");
                } else if let Err(error) = fs::remove_file(path) {
                    category.get_or_insert(io_error_category(&error));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                category.get_or_insert(io_error_category(&error));
            }
        }
    }
    match category {
        None => removed("configured_database", count),
        Some(category) => class_receipt(
            "configured_database",
            if category == "locked" {
                ReceiptOutcome::Deferred
            } else {
                ReceiptOutcome::NeedsRetry
            },
            count,
            Some(category),
        ),
    }
}

#[cfg(any(windows, test))]
fn sqlite_file_family(database: &Path) -> [PathBuf; 3] {
    let mut wal = database.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = database.as_os_str().to_os_string();
    shm.push("-shm");
    [
        database.to_path_buf(),
        PathBuf::from(wal),
        PathBuf::from(shm),
    ]
}

#[cfg(any(windows, test))]
fn purge_files(root: &Path, class: &'static str, names: &[&str]) -> ClassReceipt {
    let mut count = 0;
    let mut category = None;
    for name in names {
        let path = root.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                category.get_or_insert(io_error_category(&error));
                continue;
            }
        };
        count += 1;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            category.get_or_insert("unsafe_path");
            continue;
        }
        if let Err(error) = fs::remove_file(&path) {
            category.get_or_insert(io_error_category(&error));
        }
    }
    match category {
        None => removed(class, count),
        Some(category) => class_receipt(
            class,
            if category == "locked" {
                ReceiptOutcome::Deferred
            } else {
                ReceiptOutcome::NeedsRetry
            },
            count,
            Some(category),
        ),
    }
}

#[cfg(any(windows, test))]
fn defer_files(
    root: &Path,
    class: &'static str,
    names: &[&str],
    category: &'static str,
) -> ClassReceipt {
    let mut count = 0;
    for name in names {
        match fs::symlink_metadata(root.join(name)) {
            Ok(_) => count += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return class_receipt(class, ReceiptOutcome::NeedsRetry, count, Some("io")),
        }
    }
    class_receipt(class, ReceiptOutcome::Deferred, count, Some(category))
}

#[cfg(any(windows, test))]
fn purge_directory(root: &Path, class: &'static str, name: &str) -> ClassReceipt {
    let path = root.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return removed(class, 0),
        Err(error) => {
            return class_receipt(
                class,
                ReceiptOutcome::NeedsRetry,
                0,
                Some(io_error_category(&error)),
            )
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return class_receipt(class, ReceiptOutcome::NeedsRetry, 1, Some("unsafe_path"));
    }
    let count = match count_tree_entries(&path) {
        Ok(count) => count,
        Err(_) => {
            return class_receipt(
                class,
                ReceiptOutcome::NeedsRetry,
                1,
                Some("unsafe_or_unreadable_tree"),
            )
        }
    };
    match fs::remove_dir_all(&path) {
        Ok(()) => removed(class, count),
        Err(error) => class_receipt(
            class,
            if io_error_category(&error) == "locked" {
                ReceiptOutcome::Deferred
            } else {
                ReceiptOutcome::NeedsRetry
            },
            count,
            Some(io_error_category(&error)),
        ),
    }
}

#[cfg(any(windows, test))]
fn purge_legacy_program_files(
    data_root: &Path,
) -> (ClassReceipt, std::result::Result<usize, &'static str>) {
    let bin = data_root.join("bin");
    let metadata = match fs::symlink_metadata(&bin) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (removed("legacy_program_files", 0), Ok(0))
        }
        Err(error) => {
            return (
                class_receipt(
                    "legacy_program_files",
                    ReceiptOutcome::NeedsRetry,
                    0,
                    Some(io_error_category(&error)),
                ),
                Err(io_error_category(&error)),
            )
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return (
            class_receipt(
                "legacy_program_files",
                ReceiptOutcome::NeedsRetry,
                1,
                Some("unsafe_path"),
            ),
            Err("unsafe_path"),
        );
    }
    let allowed = ["gilbreth-app.exe", "gilbreth-elevated-record-helper.exe"];
    let unknown = count_unknown_directory_entries(&bin, &allowed);
    let mut receipt = purge_files(&bin, "legacy_program_files", &allowed);
    if matches!(unknown, Ok(0)) && receipt.outcome == ReceiptOutcome::Removed {
        if let Err(error) = fs::remove_dir(&bin) {
            if error.kind() != std::io::ErrorKind::NotFound {
                receipt.outcome = ReceiptOutcome::NeedsRetry;
                receipt.error_category = Some(io_error_category(&error).to_string());
            }
        }
    }
    (receipt, unknown)
}

#[cfg(any(windows, test))]
fn count_unknown_directory_entries(
    root: &Path,
    known: &[&str],
) -> std::result::Result<usize, &'static str> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(io_error_category(&error)),
    };
    let mut count = 0;
    for entry in entries {
        let entry = entry.map_err(|error| io_error_category(&error))?;
        let name = entry.file_name();
        if !known.iter().any(|known| name == OsStr::new(known)) {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(any(windows, test))]
fn count_tree_entries(path: &Path) -> Result<usize> {
    let mut count = 1;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            bail!("unsafe path in purge tree");
        }
        count += if metadata.is_dir() {
            count_tree_entries(&entry.path())?
        } else {
            1
        };
    }
    Ok(count)
}

#[cfg(any(windows, test))]
fn io_error_category(error: &std::io::Error) -> &'static str {
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        "locked"
    } else if error.kind() == std::io::ErrorKind::PermissionDenied {
        "access_denied"
    } else {
        "io"
    }
}

#[cfg(any(windows, test))]
struct PreparedReceipt {
    temporary: PathBuf,
    reserved: Option<fs::File>,
    temporary_file: Option<fs::File>,
    preserve_temporary: bool,
}

#[cfg(any(windows, test))]
impl PreparedReceipt {
    fn create(destination: &Path) -> Result<Self> {
        let file_name = destination
            .file_name()
            .ok_or_else(|| anyhow!("receipt path must name a file"))?
            .to_string_lossy();
        let mut reserved = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .context("failed to reserve unique content-free receipt")?;
        serde_json::to_writer_pretty(&mut reserved, &root_failure_receipt("receipt_pending"))?;
        reserved.write_all(b"\n")?;
        reserved.sync_all()?;
        let temporary = destination.with_file_name(format!(
            ".{file_name}.{}.{}.recovery.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let temporary_file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)
            .context("failed to prepare content-free receipt")?;
        Ok(Self {
            temporary,
            reserved: Some(reserved),
            temporary_file: Some(temporary_file),
            preserve_temporary: false,
        })
    }

    fn commit(mut self, receipt: &PurgeReceipt) -> Result<()> {
        let mut contents = serde_json::to_vec_pretty(receipt)?;
        contents.push(b'\n');

        let temporary = self
            .temporary_file
            .as_mut()
            .expect("prepared receipt recovery file");
        temporary.set_len(0)?;
        temporary.seek(SeekFrom::Start(0))?;
        temporary.write_all(&contents)?;
        temporary.sync_all()?;
        self.preserve_temporary = true;

        let reserved = self.reserved.as_mut().expect("reserved receipt file");
        reserved.set_len(0)?;
        reserved.seek(SeekFrom::Start(0))?;
        reserved.write_all(&contents)?;
        reserved.sync_all()?;
        drop(self.reserved.take());
        drop(self.temporary_file.take());
        if fs::remove_file(&self.temporary).is_ok() {
            self.preserve_temporary = false;
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
impl Drop for PreparedReceipt {
    fn drop(&mut self) {
        if !self.preserve_temporary {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_self_check_accepts_full_expected_sha_for_embedded_prefix() {
        package_self_check(
            "0.1.0",
            "0123456789ab",
            "0.1.0",
            Some("0123456789abcdef0123456789abcdef01234567"),
        )
        .expect("matching identity");
        assert!(package_self_check("0.1.0", "0123456789ab", "0.2.0", None).is_err());
        assert!(package_self_check("0.1.0", "0123456789ab", "0.1.0", Some("abcdef0")).is_err());
    }

    #[test]
    fn parser_rejects_trailing_offline_arguments() {
        let error = parse_offline_command([
            OsString::from("--lifecycle-preflight"),
            OsString::from("--install-root"),
            OsString::from(r"C:\Program Files\Gilbreth"),
            OsString::from("--unexpected"),
        ])
        .expect_err("trailing input must fail closed");
        assert!(error.to_string().contains("unexpected"));

        let command = parse_offline_command([
            OsString::from("--uninstall-purge"),
            OsString::from("--receipt"),
            OsString::from(r"C:\receipts\purge.json"),
            OsString::from("--installer-lock-held"),
        ])
        .expect("installer purge parses")
        .expect("offline command");
        assert!(matches!(
            command,
            OfflineCommand::UninstallPurge {
                installer_lock_held: true,
                ..
            }
        ));

        let command = parse_offline_command([
            OsString::from("--uninstall-lifecycle-preflight"),
            OsString::from("--install-root"),
            OsString::from(r"C:\Program Files\Gilbreth"),
            OsString::from("--allow-unsigned-package"),
            OsString::from("--installer-lock-held"),
        ])
        .expect("uninstall preflight parses")
        .expect("offline command");
        assert!(matches!(
            command,
            OfflineCommand::UninstallLifecyclePreflight {
                allow_unsigned_package: true,
                installer_lock_held: true,
                ..
            }
        ));
    }

    #[test]
    fn prepared_receipt_reserves_a_unique_destination() {
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("receipt.json");
        let prepared = PreparedReceipt::create(&destination).expect("receipt reserved");
        let pending: serde_json::Value =
            serde_json::from_slice(&fs::read(&destination).expect("reserved receipt is readable"))
                .expect("reserved receipt is valid JSON");
        assert_eq!(pending["status"], "incomplete");
        assert!(PreparedReceipt::create(&destination).is_err());
        drop(prepared);
    }

    #[test]
    fn prepared_receipt_commits_canonical_receipt_and_retires_recovery() {
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("receipt.json");
        let prepared = PreparedReceipt::create(&destination).expect("receipt reserved");
        let recovery = prepared.temporary.clone();
        let receipt = root_failure_receipt("locked");
        let expected = serde_json::to_value(&receipt).expect("receipt serializes");

        prepared
            .commit(&receipt)
            .expect("synced canonical receipt commits");

        let canonical: serde_json::Value = serde_json::from_slice(
            &fs::read(&destination).expect("canonical receipt remains readable"),
        )
        .expect("canonical receipt is valid JSON");
        assert_eq!(canonical, expected);
        assert!(!recovery.exists(), "retired recovery receipt is removed");
    }

    #[cfg(windows)]
    #[test]
    fn prepared_receipt_preserves_exact_recovery_when_retirement_is_blocked() {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;

        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("receipt.json");
        let prepared = PreparedReceipt::create(&destination).expect("receipt reserved");
        let recovery = prepared.temporary.clone();
        let deletion_guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&recovery)
            .expect("recovery receipt opened without delete sharing");
        let receipt = root_failure_receipt("locked");
        let expected = serde_json::to_value(&receipt).expect("receipt serializes");

        prepared
            .commit(&receipt)
            .expect("synced canonical receipt makes the commit successful");

        let canonical: serde_json::Value = serde_json::from_slice(
            &fs::read(&destination).expect("canonical receipt remains readable"),
        )
        .expect("canonical receipt is valid JSON");
        let fallback: serde_json::Value =
            serde_json::from_slice(&fs::read(&recovery).expect("recovery receipt is preserved"))
                .expect("recovery receipt is valid JSON");
        assert_eq!(canonical, expected);
        assert_eq!(fallback, expected);

        drop(deletion_guard);
    }

    #[test]
    fn purge_removes_known_classes_and_reports_external_exports_retained() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(root.join("logs")).expect("logs");
        fs::create_dir_all(root.join("archives")).expect("archives");
        fs::create_dir_all(root.join("rollback")).expect("rollback");
        fs::create_dir_all(root.join("bin")).expect("bin");
        for path in [
            root.join("gilbreth.db"),
            root.join("gilbreth.db-wal"),
            root.join(crate::config::CONFIG_LOCK_NAME),
            root.join("spheres.json.tmp"),
            root.join("dashboard-ui.ron"),
            root.join("logs/gilbreth.log"),
            root.join("archives/archive.db"),
            root.join("rollback/sensitive.db"),
            root.join("bin/gilbreth-app.exe"),
        ] {
            fs::write(path, b"fixture").expect("fixture");
        }
        fs::write(
            root.join("config.toml"),
            toml::to_string(&crate::config::AppConfig::default()).expect("config serializes"),
        )
        .expect("config fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Completed);
        assert!(!root.exists());
        let external = receipt
            .classes
            .iter()
            .find(|class| class.class == "external_exports")
            .expect("external export class");
        assert_eq!(external.outcome, ReceiptOutcome::Retained);
        let serialized = serde_json::to_string(&receipt).expect("receipt serializes");
        assert!(!serialized.contains(&root.display().to_string()));
        assert!(!serialized.contains("sensitive.db"));
    }

    /// Every file the app writes into its own data root must be claimed by a
    /// purge class. One that is not lands in `unknown_entries`, which defers
    /// the data root and stops the program uninstall outright, so a single
    /// unclassified sidecar breaks destructive uninstall on every machine
    /// where that sidecar exists. Shipped v0.1.1 that way: `hotkey-status.json`
    /// and `notification-access.json` were written by the app but claimed by
    /// no class.
    #[test]
    fn purge_claims_every_sidecar_the_app_writes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        // Named via the writers' own constants so a rename cannot silently
        // drift out of the purge classes.
        for name in [
            crate::hotkey::HOTKEY_STATUS_SIDECAR_NAME,
            crate::notification_consent::NOTIFICATION_ACCESS_SIDECAR_NAME,
            "spheres.json",
            "notices.json",
            "dashboard-ui.ron",
        ] {
            fs::write(root.join(name), b"fixture").expect("sidecar fixture");
        }

        let receipt = purge_data_root(&root, false);

        let unknown = receipt
            .classes
            .iter()
            .find(|class| class.class == "unknown_entries")
            .expect("unknown class");
        assert_eq!(
            unknown.item_count, 0,
            "a sidecar the app writes is claimed by no purge class"
        );
        assert_eq!(unknown.outcome, ReceiptOutcome::Removed);
        assert_eq!(receipt.status, ReceiptStatus::Completed);
        assert!(!root.exists(), "purge must remove the emptied data root");
    }

    #[test]
    fn purge_leaves_unknown_entries_and_fails_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        fs::write(root.join("user-created.bin"), b"keep").expect("unknown fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Incomplete);
        assert!(root.join("user-created.bin").exists());
        let unknown = receipt
            .classes
            .iter()
            .find(|class| class.class == "unknown_entries")
            .expect("unknown class");
        assert_eq!(unknown.outcome, ReceiptOutcome::Deferred);
        assert_eq!(unknown.item_count, 1);
    }

    #[test]
    fn purge_removes_a_configured_database_outside_the_data_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        let external = dir.path().join("external.db");
        fs::write(&external, b"external fixture").expect("external database fixture");
        let mut config = crate::config::AppConfig::default();
        config.storage.db_path = Some(external.clone());
        fs::write(
            root.join("config.toml"),
            toml::to_string(&config).expect("config serializes"),
        )
        .expect("config fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Completed);
        assert!(!external.exists(), "configured DB family must be purged");
        let configured = receipt
            .classes
            .iter()
            .find(|class| class.class == "configured_database")
            .expect("configured database class");
        assert_eq!(configured.outcome, ReceiptOutcome::Removed);
        assert_eq!(configured.item_count, 1);
    }

    #[test]
    fn unresolved_config_preserves_the_pointer_and_fails_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        fs::write(root.join("config.toml"), b"not valid toml = [").expect("config fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Incomplete);
        assert!(root.join("config.toml").exists());
        let configured = receipt
            .classes
            .iter()
            .find(|class| class.class == "configured_database")
            .expect("configured database class");
        assert_eq!(configured.outcome, ReceiptOutcome::Deferred);
        assert_eq!(
            configured.error_category.as_deref(),
            Some("unresolved_config")
        );
    }

    #[test]
    fn relative_configured_database_is_never_resolved_against_process_cwd() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        let mut config = crate::config::AppConfig::default();
        config.storage.db_path = Some(PathBuf::from("ambiguous.db"));
        fs::write(
            root.join("config.toml"),
            toml::to_string(&config).expect("config serializes"),
        )
        .expect("config fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Incomplete);
        assert!(root.join("config.toml").exists());
        let configured = receipt
            .classes
            .iter()
            .find(|class| class.class == "configured_database")
            .expect("configured database class");
        assert_eq!(configured.outcome, ReceiptOutcome::Deferred);
        assert_eq!(
            configured.error_category.as_deref(),
            Some("unresolved_external_path")
        );
    }

    #[test]
    fn purge_refuses_a_directory_class_that_is_not_a_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        fs::create_dir_all(&root).expect("data root");
        fs::write(root.join("logs"), b"not a directory").expect("unsafe fixture");

        let receipt = purge_data_root(&root, false);
        assert_eq!(receipt.status, ReceiptStatus::Incomplete);
        assert!(root.join("logs").exists());
        let logs = receipt
            .classes
            .iter()
            .find(|class| class.class == "logs")
            .expect("logs class");
        assert_eq!(logs.outcome, ReceiptOutcome::NeedsRetry);
        assert_eq!(logs.error_category.as_deref(), Some("unsafe_path"));
    }
}
