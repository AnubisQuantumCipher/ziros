mod archiver;
mod classifier;
mod config;
mod health;
mod policy;
pub mod platform;
mod purger;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use archiver::{
    ArchiveCategory, ArchiveReport, ArchiveTargetKind, ICloudArchiveHealth,
    ResolvedArchiveTarget, archive_file, archive_to_icloud, current_icloud_archive_bytes,
    current_utc_timestamp, icloud_archive_health, icloud_archive_root,
    local_archive_fallback_root, resolve_archive_target,
};
pub use classifier::{FileClass, classify_path, collect_archivable_paths, collect_showcase_roots};
pub use config::StorageGuardianConfig;
pub use health::{HealthStatus, SsdHealth, directory_size_bytes, get_ssd_health};
pub use policy::{
    RetentionPolicy, StorageProfile, auto_profile, default_policy, default_policy_for_profile,
};
pub use purger::{PurgeReport, collect_ephemeral_paths, purge_ephemeral};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepReport {
    pub files_archived: usize,
    pub bytes_archived: u64,
    pub files_purged: usize,
    pub bytes_freed: u64,
    pub icloud_archive_path: Option<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("{0}")]
    Message(String),
    #[error("{command} failed: {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("{0} is not supported on this platform")]
    UnsupportedPlatform(&'static str),
    #[error("iCloud Drive is not available at the writable Mobile Documents root")]
    ICloudUnavailable,
    #[error("invalid file path: {0}")]
    InvalidPath(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn normalize_path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(crate) fn file_size_bytes(path: &Path) -> u64 {
    path.metadata().map(|metadata| metadata.len()).unwrap_or_default()
}
