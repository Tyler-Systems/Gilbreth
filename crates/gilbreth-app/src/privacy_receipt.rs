//! Content-free receipts for user-initiated privacy operations.
//!
//! Receipts enumerate artifact classes and exact outcomes without paths,
//! filenames, titles, app labels, hostnames, or other captured/user content.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const RECEIPT_DIRECTORY: &str = "operation-receipts";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyOperation {
    ArchiveReset,
    SecureErase,
    PortableArchiveExport,
    UninstallPurge,
}

impl PrivacyOperation {
    fn file_stem(self) -> &'static str {
        match self {
            Self::ArchiveReset => "archive-reset",
            Self::SecureErase => "secure-erase",
            Self::PortableArchiveExport => "portable-archive-export",
            Self::UninstallPurge => "uninstall-purge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReceiptOutcome {
    #[serde(rename = "copied")]
    Copied,
    #[serde(rename = "removed")]
    Removed,
    #[serde(rename = "retained")]
    Retained,
    #[serde(rename = "deferred")]
    Deferred,
    #[serde(rename = "needs retry")]
    NeedsRetry,
}

impl ReceiptOutcome {
    pub fn as_copy(self) -> &'static str {
        match self {
            Self::Copied => "copied",
            Self::Removed => "removed",
            Self::Retained => "retained",
            Self::Deferred => "deferred",
            Self::NeedsRetry => "needs retry",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptClass {
    pub class: String,
    pub outcome: ReceiptOutcome,
    pub item_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
}

impl ReceiptClass {
    pub fn new(class: impl Into<String>, outcome: ReceiptOutcome) -> Self {
        Self {
            class: class.into(),
            outcome,
            item_count: 0,
            error_category: None,
        }
    }

    pub fn with_count(mut self, count: usize) -> Self {
        self.item_count = count;
        self
    }

    pub fn with_error_category(mut self, category: impl Into<String>) -> Self {
        self.error_category = Some(category.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Completed,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyReceipt {
    pub schema_version: u32,
    pub operation: PrivacyOperation,
    pub status: ReceiptStatus,
    pub created_at_ms: i64,
    pub classes: Vec<ReceiptClass>,
}

impl PrivacyReceipt {
    pub fn new(operation: PrivacyOperation, classes: Vec<ReceiptClass>) -> Self {
        let status = if classes.iter().any(|class| {
            matches!(
                class.outcome,
                ReceiptOutcome::Deferred | ReceiptOutcome::NeedsRetry
            )
        }) {
            ReceiptStatus::Incomplete
        } else {
            ReceiptStatus::Completed
        };
        Self {
            schema_version: 1,
            operation,
            status,
            created_at_ms: now_ms(),
            classes,
        }
    }

    pub fn summary(&self) -> String {
        self.classes
            .iter()
            .map(|class| {
                format!(
                    "{}: {} ({})",
                    class.class,
                    class.outcome.as_copy(),
                    class.item_count
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub fn write_receipt(data_dir: &Path, receipt: &PrivacyReceipt) -> Result<PathBuf, String> {
    let directory = data_dir.join(RECEIPT_DIRECTORY);
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|error| error.to_string())?;
    for suffix in 0..=999_u32 {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let path = directory.join(format!(
            "{}-{}{}.json",
            receipt.operation.file_stem(),
            receipt.created_at_ms,
            suffix
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(&bytes).map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("could not reserve a unique privacy receipt name".to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_and_status_are_exact() {
        let completed = PrivacyReceipt::new(
            PrivacyOperation::ArchiveReset,
            vec![
                ReceiptClass::new("archive", ReceiptOutcome::Copied),
                ReceiptClass::new("live_database", ReceiptOutcome::Removed),
                ReceiptClass::new("configuration", ReceiptOutcome::Retained),
            ],
        );
        assert_eq!(completed.status, ReceiptStatus::Completed);
        let incomplete = PrivacyReceipt::new(
            PrivacyOperation::SecureErase,
            vec![ReceiptClass::new("active_log", ReceiptOutcome::NeedsRetry)],
        );
        assert_eq!(incomplete.status, ReceiptStatus::Incomplete);
        assert!(incomplete.summary().contains("needs retry"));
    }

    #[test]
    fn persisted_shape_is_content_free_and_never_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut receipt = PrivacyReceipt::new(
            PrivacyOperation::PortableArchiveExport,
            vec![ReceiptClass::new("portable_export", ReceiptOutcome::Copied)],
        );
        receipt.created_at_ms = 42;
        let first = write_receipt(dir.path(), &receipt).expect("first receipt");
        let second = write_receipt(dir.path(), &receipt).expect("second receipt");
        assert_ne!(first, second);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(first).expect("receipt bytes")).expect("json");
        let raw = value.to_string();
        assert!(!raw.contains(dir.path().to_string_lossy().as_ref()));
        assert_eq!(value["classes"][0]["class"], "portable_export");
        assert_eq!(value["classes"][0]["outcome"], "copied");
        assert_eq!(
            serde_json::to_value(ReceiptOutcome::NeedsRetry).expect("outcome"),
            "needs retry"
        );
    }
}
