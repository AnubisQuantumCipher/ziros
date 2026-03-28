use crate::classifier::{FileClass, classify_path, collect_showcase_roots};
use crate::{StorageError, file_size_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeReport {
    pub files_purged: usize,
    pub bytes_freed: u64,
    pub purged_paths: Vec<PathBuf>,
    pub dry_run: bool,
}

pub fn collect_ephemeral_paths(
    repo_root: &Path,
    home: &Path,
    include_release: bool,
) -> Result<Vec<PathBuf>, StorageError> {
    let mut matches = BTreeSet::new();
    add_if_exists(repo_root.join("target-local").join("debug"), &mut matches);
    add_if_exists(repo_root.join("target-local").join("kani"), &mut matches);
    add_if_exists(repo_root.join("target").join("debug"), &mut matches);
    if include_release {
        add_if_exists(repo_root.join("target-local").join("release"), &mut matches);
    }

    for root in collect_showcase_roots(home) {
        collect_ephemeral_from_dir(&root, &mut matches)?;
    }
    Ok(matches.into_iter().collect())
}

pub fn purge_ephemeral(paths: &[PathBuf], dry_run: bool) -> Result<PurgeReport, StorageError> {
    let mut report = PurgeReport {
        dry_run,
        ..PurgeReport::default()
    };
    for path in paths {
        let freed = file_size_bytes(path)
            + if path.is_dir() {
                crate::directory_size_bytes(path).unwrap_or_default()
            } else {
                0
            };
        if !dry_run {
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else if path.exists() {
                fs::remove_file(path)?;
            }
        }
        report.files_purged += 1;
        report.bytes_freed += freed;
        report.purged_paths.push(path.clone());
    }
    Ok(report)
}

fn collect_ephemeral_from_dir(root: &Path, matches: &mut BTreeSet<PathBuf>) -> Result<(), StorageError> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let class = classify_path(&path);
        if class == FileClass::Ephemeral {
            matches.insert(path.clone());
            if path.is_dir() {
                continue;
            }
        }
        if path.is_dir() {
            collect_ephemeral_from_dir(&path, matches)?;
        }
    }
    Ok(())
}

fn add_if_exists(path: PathBuf, matches: &mut BTreeSet<PathBuf>) {
    if path.exists() {
        matches.insert(path);
    }
}

#[cfg(test)]
mod tests {
    use super::{collect_ephemeral_paths, purge_ephemeral};
    use std::fs;

    #[test]
    fn collect_ephemeral_paths_finds_build_cache_and_foundry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let home = temp.path().join("home");
        fs::create_dir_all(repo_root.join("target-local/debug")).expect("debug dir");
        fs::create_dir_all(home.join("Desktop/ZirOS_Test/foundry/src")).expect("foundry dir");
        let paths = collect_ephemeral_paths(&repo_root, &home, false).expect("collect");
        assert!(paths.iter().any(|path| path.ends_with("target-local/debug")));
        assert!(paths.iter().any(|path| path.ends_with("foundry")));
    }

    #[test]
    fn purge_ephemeral_respects_dry_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("artifact.compiled.json");
        fs::write(&path, "{}").expect("write");
        let report = purge_ephemeral(std::slice::from_ref(&path), true).expect("purge");
        assert_eq!(report.files_purged, 1);
        assert!(path.exists());
    }
}
