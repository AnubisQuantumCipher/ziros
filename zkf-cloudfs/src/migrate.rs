// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use crate::cloudfs::{CloudFS, default_local_root};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationConflict {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub cloud_root: String,
    pub cache_root: String,
    pub moved: Vec<MigrationPlan>,
    pub deduplicated: Vec<MigrationPlan>,
    pub conflicts: Vec<MigrationConflict>,
    pub pointer_file: String,
}

pub fn migrate_to_icloud(cloudfs: &CloudFS) -> io::Result<MigrationReport> {
    if !cloudfs.is_icloud_native() {
        return Err(io::Error::other(
            "iCloud Drive is unavailable; cannot migrate to iCloud-native mode",
        ));
    }

    let legacy_root = default_local_root();
    let cache_root = cloudfs.cache_root().to_path_buf();
    let cloud_root = cloudfs.persistent_root().to_path_buf();
    fs::create_dir_all(&cloud_root)?;
    fs::create_dir_all(&cache_root)?;

    let mut plans = Vec::new();
    collect_migration_plans(&legacy_root, &cloud_root, &mut plans)?;

    let mut conflicts = Vec::new();
    let mut deduplicated = Vec::new();
    for plan in &plans {
        let destination = PathBuf::from(&plan.destination);
        if destination.exists() {
            if same_bytes(Path::new(&plan.source), &destination)? {
                deduplicated.push(plan.clone());
                continue;
            }
            conflicts.push(MigrationConflict {
                source: plan.source.clone(),
                destination: plan.destination.clone(),
            });
        }
    }

    if !conflicts.is_empty() {
        return Ok(MigrationReport {
            cloud_root: cloud_root.display().to_string(),
            cache_root: cache_root.display().to_string(),
            moved: Vec::new(),
            deduplicated,
            conflicts,
            pointer_file: legacy_root.join("icloud-mode.json").display().to_string(),
        });
    }

    let mut moved = Vec::new();
    for plan in plans {
        let source = PathBuf::from(&plan.source);
        let destination = PathBuf::from(&plan.destination);
        if destination.exists() {
            let _ = fs::remove_file(&source);
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&source, &destination).or_else(|_| copy_then_remove(&source, &destination))?;
        moved.push(plan);
    }

    fs::create_dir_all(&cache_root)?;
    let pointer_file = legacy_root.join("icloud-mode.json");
    let pointer_payload = serde_json::json!({
        "mode": "icloud-native",
        "root": cloud_root.display().to_string(),
        "cache_root": cache_root.display().to_string(),
    });
    fs::create_dir_all(&legacy_root)?;
    fs::write(
        &pointer_file,
        serde_json::to_vec_pretty(&pointer_payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
    )?;

    Ok(MigrationReport {
        cloud_root: cloud_root.display().to_string(),
        cache_root: cache_root.display().to_string(),
        moved,
        deduplicated,
        conflicts,
        pointer_file: pointer_file.display().to_string(),
    })
}

fn collect_migration_plans(
    legacy_root: &Path,
    cloud_root: &Path,
    plans: &mut Vec<MigrationPlan>,
) -> io::Result<()> {
    let mappings = [
        ("proofs", "proofs"),
        ("traces", "traces"),
        ("verifiers", "verifiers"),
        ("reports", "reports"),
        ("audits", "audits"),
        ("telemetry", "telemetry"),
        ("models", "models"),
        ("swarm", "swarm"),
        ("registry", "registry"),
    ];

    for (source_dir, destination_dir) in mappings {
        let source = legacy_root.join(source_dir);
        let destination = cloud_root.join(destination_dir);
        collect_path_plans(&source, &destination, plans)?;
    }

    let config = legacy_root.join("config.json");
    if config.exists() {
        plans.push(MigrationPlan {
            source: config.display().to_string(),
            destination: cloud_root.join("config.json").display().to_string(),
        });
    }

    Ok(())
}

fn collect_path_plans(source: &Path, destination: &Path, plans: &mut Vec<MigrationPlan>) -> io::Result<()> {
    if !source.exists() {
        return Ok(());
    }
    if source.is_file() {
        plans.push(MigrationPlan {
            source: source.display().to_string(),
            destination: destination.display().to_string(),
        });
        return Ok(());
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().and_then(|value| value.to_str()) == Some("cache") {
            continue;
        }
        if path.file_name().and_then(|value| value.to_str()) == Some("swarm_memory.sqlite3") {
            continue;
        }
        let relative = path.strip_prefix(source).map_err(io::Error::other)?;
        collect_path_plans(&path, &destination.join(relative), plans)?;
    }
    Ok(())
}

fn copy_then_remove(source: &Path, destination: &Path) -> io::Result<()> {
    if source.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let child = entry.path();
            copy_then_remove(&child, &destination.join(entry.file_name()))?;
        }
        fs::remove_dir(source)?;
        return Ok(());
    }
    fs::copy(source, destination)?;
    fs::remove_file(source)?;
    Ok(())
}

fn same_bytes(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(hash_path(left)? == hash_path(right)?)
}

fn hash_path(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudfs::CloudFS;

    #[test]
    fn conflict_detection_returns_without_mutating() {
        let temp = tempfile::tempdir().expect("tempdir");
        let legacy = temp.path().join(".zkf");
        let cloud = temp.path().join("icloud");
        let cache = legacy.join("cache");
        fs::create_dir_all(legacy.join("proofs")).expect("legacy proofs dir");
        fs::create_dir_all(cloud.join("proofs")).expect("cloud proofs dir");
        fs::write(legacy.join("proofs/a.json"), b"legacy").expect("write legacy");
        fs::write(cloud.join("proofs/a.json"), b"cloud").expect("write cloud");
        let old_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", temp.path());
        }
        let cloudfs = CloudFS::from_roots(cloud.clone(), cache, true);
        let report = migrate_to_icloud(&cloudfs).expect("migrate");
        match old_home {
            Some(value) => unsafe {
                std::env::set_var("HOME", value);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        assert_eq!(report.moved.len(), 0);
        assert_eq!(report.conflicts.len(), 1);
    }
}
