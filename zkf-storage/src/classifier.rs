use crate::{StorageError, normalize_path_string};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileClass {
    LocalCritical,
    Archivable,
    Ephemeral,
    Operational,
}

pub fn classify_path(path: &Path) -> FileClass {
    let normalized = normalize_path_string(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    if in_named_tree(&normalized, ".zkf/swarm")
        || in_named_tree(&normalized, ".zkf/keystore")
        || in_named_tree(&normalized, ".zkf/tuning")
        || in_named_tree(&normalized, ".zkf/security")
        || in_named_tree(&normalized, ".zkf/state")
    {
        return FileClass::LocalCritical;
    }

    if file_name.ends_with(".proof.json")
        || file_name.ends_with(".execution_trace.json")
        || file_name.ends_with(".runtime_trace.json")
        || file_name.ends_with(".calldata.json")
        || file_name.ends_with(".report.md")
        || file_name.ends_with(".summary.json")
        || file_name.ends_with(".audit.json")
        || file_name.ends_with("Verifier.sol")
        || file_name == "metal_doctor.json"
        || file_name == "machine_info.txt"
        || in_named_tree(&normalized, ".zkf/telemetry")
    {
        return FileClass::Archivable;
    }

    if in_named_tree(&normalized, "target-local/debug")
        || in_named_tree(&normalized, "target-local/kani")
        || in_named_tree(&normalized, "target/debug")
        || file_name.ends_with(".compiled.json")
        || is_witness_file(file_name)
        || file_name.ends_with(".original.program.json")
        || file_name.ends_with(".optimized.program.json")
        || file_name.ends_with(".inputs.json")
        || file_name.ends_with(".request.json")
        || ends_with_component(path, "foundry")
        || normalized.contains("/foundry/")
    {
        return FileClass::Ephemeral;
    }

    if in_named_tree(&normalized, "target-local/release")
        || (normalized.contains("/.zkf/models/") && file_name.ends_with(".mlpackage"))
    {
        return FileClass::Operational;
    }

    FileClass::Operational
}

pub fn collect_showcase_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let desktop = home.join("Desktop");
    if let Ok(entries) = fs::read_dir(&desktop) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("ZirOS_") || name.starts_with("ziros-") {
                roots.push(path);
            }
        }
    }

    let temp_root = std::env::temp_dir();
    if let Ok(entries) = fs::read_dir(&temp_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("swarm_") || name.starts_with("reentry_") {
                roots.push(path);
            }
        }
    }
    roots.sort();
    roots
}

pub fn collect_archivable_paths(repo_root: &Path, home: &Path) -> Result<Vec<PathBuf>, StorageError> {
    let mut matches = BTreeSet::new();
    let telemetry_dir = home.join(".zkf").join("telemetry");
    collect_archivable_from_dir(&telemetry_dir, &mut matches)?;
    for root in collect_showcase_roots(home) {
        let _ = repo_root;
        collect_archivable_from_dir(&root, &mut matches)?;
    }
    Ok(matches.into_iter().collect())
}

fn collect_archivable_from_dir(root: &Path, matches: &mut BTreeSet<PathBuf>) -> Result<(), StorageError> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_archivable_from_dir(&path, matches)?;
            continue;
        }
        if classify_path(&path) == FileClass::Archivable {
            matches.insert(path);
        }
    }
    Ok(())
}

fn is_witness_file(file_name: &str) -> bool {
    file_name.contains(".witness.") && file_name.ends_with(".json")
}

fn ends_with_component(path: &Path, component: &str) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == component)
}

fn in_named_tree(normalized: &str, needle: &str) -> bool {
    normalized.ends_with(needle)
        || normalized.contains(&format!("/{needle}/"))
        || normalized.contains(&format!("/{needle}"))
}

#[cfg(test)]
mod tests {
    use super::{FileClass, classify_path};
    use std::path::Path;

    #[test]
    fn classifier_uses_blueprint_precedence() {
        assert_eq!(
            classify_path(Path::new("/tmp/.zkf/swarm/rules.json")),
            FileClass::LocalCritical
        );
        assert_eq!(
            classify_path(Path::new("/tmp/example.proof.json")),
            FileClass::Archivable
        );
        assert_eq!(
            classify_path(Path::new("/tmp/target-local/debug/build")),
            FileClass::Ephemeral
        );
        assert_eq!(
            classify_path(Path::new("/tmp/target-local/release/zkf-cli")),
            FileClass::Operational
        );
    }

    #[test]
    fn classifier_marks_state_directory_as_local_critical() {
        assert_eq!(
            classify_path(Path::new("/Users/test/.zkf/state/ziros-first-run-v1")),
            FileClass::LocalCritical
        );
    }
}
