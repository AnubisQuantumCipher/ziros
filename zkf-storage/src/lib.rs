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

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zkf_cloudfs::{
    CloudFS, CloudFSConfig, MigrationReport, default_local_root, migrate_to_icloud,
};
use zkf_keymanager::KeyManager;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatusReport {
    pub mode: String,
    pub persistent_root: String,
    pub cache_root: String,
    pub icloud_available: bool,
    pub ziros_directory_present: bool,
    pub local_cache_usage_bytes: u64,
    pub key_count: usize,
    pub sync_state: String,
    pub local_cache_max_gb: u64,
    pub auto_evict_after_hours: u64,
    pub swarm_sqlite_live_path: String,
    pub swarm_sqlite_snapshot_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmReport {
    pub prefetched: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictReport {
    pub evicted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub plist_path: String,
    pub cli_path: String,
}

pub fn status() -> io::Result<StorageStatusReport> {
    let cloudfs = CloudFS::new()?;
    let config = CloudFSConfig::load(&cloudfs)?;
    let key_count = KeyManager::new()?.list_all()?.len();
    Ok(StorageStatusReport {
        mode: cloudfs.sync_root_state().to_string(),
        persistent_root: cloudfs.persistent_root().display().to_string(),
        cache_root: cloudfs.cache_root().display().to_string(),
        icloud_available: cloudfs.is_icloud_native(),
        ziros_directory_present: cloudfs.persistent_root().exists(),
        local_cache_usage_bytes: directory_size(cloudfs.cache_root())?,
        key_count,
        sync_state: if cloudfs.is_icloud_native() {
            "icloud-native".to_string()
        } else {
            "local-only".to_string()
        },
        local_cache_max_gb: config.local_cache_max_gb,
        auto_evict_after_hours: config.auto_evict_after_hours,
        swarm_sqlite_live_path: cloudfs
            .cache_root()
            .join("swarm_memory.sqlite3")
            .display()
            .to_string(),
        swarm_sqlite_snapshot_path: cloudfs
            .persistent_root()
            .join("swarm")
            .join("swarm_memory.snapshot.sqlite3")
            .display()
            .to_string(),
    })
}

pub fn warm() -> io::Result<WarmReport> {
    let cloudfs = CloudFS::new()?;
    let config = CloudFSConfig::load(&cloudfs)?;
    let mut prefetched = Vec::new();
    for path in config.prefetch_on_startup {
        if cloudfs.prefetch(&path).is_ok() {
            prefetched.push(path);
        }
    }
    Ok(WarmReport { prefetched })
}

pub fn evict() -> io::Result<EvictReport> {
    let cloudfs = CloudFS::new()?;
    let config = CloudFSConfig::load(&cloudfs)?;
    let threshold = Utc::now() - Duration::hours(config.auto_evict_after_hours as i64);
    let mut evicted = Vec::new();
    for relative in cloudfs.list("")? {
        let path = cloudfs.persistent_root().join(&relative);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let modified = chrono::DateTime::<Utc>::from(modified);
        if modified < threshold && cloudfs.is_local(&relative) && cloudfs.evict_local(&relative).is_ok()
        {
            evicted.push(relative);
        }
    }
    Ok(EvictReport { evicted })
}

pub fn migrate() -> io::Result<MigrationReport> {
    let cloudfs = CloudFS::new()?;
    let report = migrate_to_icloud(&cloudfs)?;
    if !report.conflicts.is_empty() {
        return Ok(report);
    }
    migrate_swarm_memory_snapshot(&cloudfs)?;
    migrate_private_keys(&cloudfs)?;
    Ok(report)
}

pub fn install(cli_path: &Path) -> io::Result<InstallReport> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = cli_path;
        return Err(io::Error::other(
            "storage install is only supported on macOS",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        const TEMPLATE: &str = include_str!("../../scripts/launchd/com.ziros.storage-guardian.plist");
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let plist = TEMPLATE
            .replace("__ZKF_CLI_PATH__", &cli_path.display().to_string())
            .replace("__HOME__", &home);
        let path = PathBuf::from(&home)
            .join("Library")
            .join("LaunchAgents")
            .join("com.ziros.storage-guardian.plist");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, plist)?;
        Ok(InstallReport {
            plist_path: path.display().to_string(),
            cli_path: cli_path.display().to_string(),
        })
    }
}

fn directory_size(path: &Path) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        total = total.saturating_add(directory_size(&entry.path())?);
    }
    Ok(total)
}

fn migrate_private_keys(_cloudfs: &CloudFS) -> io::Result<()> {
    let legacy_root = default_local_root();
    let manager = KeyManager::new()?;

    let keystore_dir = legacy_root.join("keystore");
    if keystore_dir.exists() {
        for entry in fs::read_dir(&keystore_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("key") {
                continue;
            }
            let Some(label) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            let bytes = fs::read(&path)?;
            manager.store_key(label, &format!("com.ziros.proving.{label}"), &bytes)?;
            delete_secure(&path)?;
        }
    }

    let identity_dir = legacy_root.join("swarm").join("identity");
    if identity_dir.exists() {
        for entry in fs::read_dir(&identity_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.ends_with(".ed25519") {
                let label = name.trim_end_matches(".ed25519");
                let bytes = fs::read(&path)?;
                manager.store_key(label, "com.ziros.swarm.ed25519", &bytes)?;
                delete_secure(&path)?;
            } else if name.ends_with(".mldsa87") {
                let label = name.trim_end_matches(".mldsa87");
                let bytes = fs::read(&path)?;
                manager.store_key(label, "com.ziros.swarm.mldsa87", &bytes)?;
                delete_secure(&path)?;
            }
        }
    }

    Ok(())
}

fn migrate_swarm_memory_snapshot(cloudfs: &CloudFS) -> io::Result<()> {
    let legacy = default_local_root().join("swarm").join("swarm_memory.sqlite3");
    if !legacy.exists() {
        return Ok(());
    }
    let local_cache = cloudfs.cache_root().join("swarm_memory.sqlite3");
    let snapshot = cloudfs
        .persistent_root()
        .join("swarm")
        .join("swarm_memory.snapshot.sqlite3");
    if let Some(parent) = local_cache.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = snapshot.parent() {
        fs::create_dir_all(parent)?;
    }
    if snapshot.exists() && !same_bytes(&legacy, &snapshot)? {
        return Err(io::Error::other(format!(
            "swarm memory snapshot conflict at {}",
            snapshot.display()
        )));
    }
    fs::copy(&legacy, &local_cache)?;
    fs::copy(&legacy, &snapshot)?;
    delete_secure(&legacy)
}

fn delete_secure(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let length = fs::metadata(path)?.len();
    fs::write(path, vec![0u8; length as usize])?;
    fs::remove_file(path)
}

fn same_bytes(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(fs::read(left)? == fs::read(right)?)
}
