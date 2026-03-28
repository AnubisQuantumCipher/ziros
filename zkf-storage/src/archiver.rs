use crate::classifier::FileClass;
use crate::{StorageError, directory_size_bytes, file_size_bytes, home_dir};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveCategory {
    Proof,
    Trace,
    Verifier,
    Report,
    Audit,
    Telemetry,
    Other,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReport {
    pub files_archived: usize,
    pub bytes_archived: u64,
    pub archived_paths: Vec<PathBuf>,
    pub archive_root: PathBuf,
    pub dry_run: bool,
}

pub fn current_utc_timestamp() -> String {
    Utc::now().format("%Y%m%d_%H%M%S").to_string()
}

pub fn icloud_archive_root() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let root = home_dir()
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs");
        if root.is_dir() {
            Some(root.join("ZirOS_Archive"))
        } else {
            None
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

pub fn current_icloud_archive_bytes() -> Option<u64> {
    icloud_archive_root()
        .filter(|path| path.exists())
        .and_then(|path| directory_size_bytes(&path).ok())
}

pub fn archive_to_icloud(
    files: &[PathBuf],
    run_name: &str,
    archive_root: &Path,
    dry_run: bool,
) -> Result<ArchiveReport, StorageError> {
    let mut report = ArchiveReport {
        archive_root: archive_root.to_path_buf(),
        dry_run,
        ..ArchiveReport::default()
    };
    for source in files {
        let dest = archive_file(source, FileClass::Archivable, run_name, archive_root, dry_run)?;
        report.files_archived += 1;
        report.bytes_archived += file_size_bytes(source);
        report.archived_paths.push(dest);
    }
    Ok(report)
}

pub fn archive_file(
    source: &Path,
    class: FileClass,
    run_name: &str,
    archive_root: &Path,
    dry_run: bool,
) -> Result<PathBuf, StorageError> {
    if class != FileClass::Archivable {
        return Err(StorageError::Message(format!(
            "{} is not archivable",
            source.display()
        )));
    }
    let file_name = source.file_name().ok_or_else(|| {
        StorageError::InvalidPath(format!("{} is missing a file name", source.display()))
    })?;
    let subdir = match classify_archive_category(source) {
        ArchiveCategory::Proof => "proofs",
        ArchiveCategory::Trace => "traces",
        ArchiveCategory::Verifier => "verifiers",
        ArchiveCategory::Report => "reports",
        ArchiveCategory::Audit => "audits",
        ArchiveCategory::Telemetry => "telemetry",
        ArchiveCategory::Other => "misc",
    };
    let dest_dir = archive_root.join(subdir).join(run_name);
    let dest_file = dest_dir.join(file_name);
    if dry_run {
        return Ok(dest_file);
    }
    fs::create_dir_all(&dest_dir)?;
    move_file(source, &dest_file)?;
    Ok(dest_file)
}

pub(crate) fn classify_archive_category(path: &Path) -> ArchiveCategory {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if file_name.ends_with(".proof.json") {
        return ArchiveCategory::Proof;
    }
    if file_name.ends_with(".execution_trace.json") || file_name.ends_with(".runtime_trace.json") {
        return ArchiveCategory::Trace;
    }
    if file_name.ends_with("Verifier.sol") {
        return ArchiveCategory::Verifier;
    }
    if file_name.ends_with(".report.md") {
        return ArchiveCategory::Report;
    }
    if file_name.ends_with(".audit.json") {
        return ArchiveCategory::Audit;
    }
    if path.to_string_lossy().contains("/.zkf/telemetry/") {
        return ArchiveCategory::Telemetry;
    }
    ArchiveCategory::Other
}

fn move_file(source: &Path, dest: &Path) -> Result<(), StorageError> {
    match fs::rename(source, dest) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            fs::copy(source, dest)?;
            fs::remove_file(source)?;
            Ok(())
        }
        Err(error) => Err(StorageError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{ArchiveCategory, archive_file, classify_archive_category};
    use crate::classifier::FileClass;
    use std::fs;

    #[test]
    fn archive_category_routes_known_artifacts() {
        assert_eq!(
            classify_archive_category(std::path::Path::new("/tmp/example.proof.json")),
            ArchiveCategory::Proof
        );
        assert_eq!(
            classify_archive_category(std::path::Path::new("/tmp/example.runtime_trace.json")),
            ArchiveCategory::Trace
        );
        assert_eq!(
            classify_archive_category(std::path::Path::new("/tmp/MyVerifier.sol")),
            ArchiveCategory::Verifier
        );
    }

    #[test]
    fn archive_file_creates_expected_destination_in_dry_run_mode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("example.proof.json");
        fs::write(&source, "{}").expect("write");
        let dest = archive_file(
            &source,
            FileClass::Archivable,
            "demo",
            temp.path(),
            true,
        )
        .expect("archive");
        assert!(dest.ends_with("proofs/demo/example.proof.json"));
        assert!(source.exists());
    }
}
