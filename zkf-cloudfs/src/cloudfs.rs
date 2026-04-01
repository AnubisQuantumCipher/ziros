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

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactType {
    Proofs,
    Traces,
    Verifiers,
    Reports,
    Audits,
    Telemetry,
}

impl ArtifactType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proofs => "proofs",
            Self::Traces => "traces",
            Self::Verifiers => "verifiers",
            Self::Reports => "reports",
            Self::Audits => "audits",
            Self::Telemetry => "telemetry",
        }
    }

    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "proofs" => Ok(Self::Proofs),
            "traces" => Ok(Self::Traces),
            "verifiers" => Ok(Self::Verifiers),
            "reports" => Ok(Self::Reports),
            "audits" => Ok(Self::Audits),
            "telemetry" => Ok(Self::Telemetry),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported artifact type '{other}'"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudFS {
    icloud_root: PathBuf,
    cache_root: PathBuf,
    icloud_native: bool,
}

impl CloudFS {
    pub fn new() -> io::Result<Self> {
        let cache_root = default_cache_root();
        let cloud_docs = default_cloud_docs_root();
        let icloud_root = default_icloud_root();
        let icloud_native = cfg!(target_os = "macos")
            && cloud_docs.exists()
            && cloud_docs.is_dir()
            && directory_is_writable(&cloud_docs);
        Ok(Self {
            icloud_root: if icloud_native {
                icloud_root
            } else {
                default_local_root()
            },
            cache_root,
            icloud_native,
        })
    }

    pub fn from_roots(icloud_root: PathBuf, cache_root: PathBuf, icloud_native: bool) -> Self {
        Self {
            icloud_root,
            cache_root,
            icloud_native,
        }
    }

    pub fn icloud_root(&self) -> &Path {
        &self.icloud_root
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    pub fn persistent_root(&self) -> &Path {
        &self.icloud_root
    }

    pub fn is_icloud_native(&self) -> bool {
        self.icloud_native
    }

    pub fn read(&self, relative_path: &str) -> io::Result<Vec<u8>> {
        fs::read(self.resolve_persistent(relative_path)?)
    }

    pub fn write(&self, relative_path: &str, data: &[u8]) -> io::Result<()> {
        let path = self.resolve_persistent(relative_path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(target_os = "macos")]
        if self.icloud_native {
            // Use NSFileCoordinator to notify the bird daemon synchronously.
            // Without coordination: bird discovers the change through FSEvents
            // polling (up to 30-second delay before upload is queued).
            // With coordination: bird is notified as part of the write operation
            // and queues the upload within 1-2 seconds.
            coordinated_write(&path, data)?;
            return Ok(());
        }
        fs::write(path, data)
    }

    pub fn write_local_only(&self, relative_path: &str, data: &[u8]) -> io::Result<()> {
        let path = self.resolve_cache(relative_path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)
    }

    pub fn delete_local(&self, relative_path: &str, zeroize: bool) -> io::Result<()> {
        let path = self.resolve_cache(relative_path)?;
        if !path.exists() {
            return Ok(());
        }
        if zeroize {
            zeroize_path(&path)?;
        }
        if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        }
    }

    pub fn prefetch(&self, relative_path: &str) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            if !self.icloud_native {
                return Ok(());
            }
            let path = self.resolve_persistent(relative_path)?;
            run_brctl("download", &path)?;
        }
        Ok(())
    }

    pub fn evict_local(&self, relative_path: &str) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            if !self.icloud_native {
                return Ok(());
            }
            let path = self.resolve_persistent(relative_path)?;
            run_brctl("evict", &path)?;
        }
        Ok(())
    }

    pub fn is_local(&self, relative_path: &str) -> bool {
        let Ok(path) = self.resolve_persistent(relative_path) else {
            return false;
        };
        if !path.exists() {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            if self.icloud_native {
                if let Ok(output) = Command::new("xattr")
                    .args(["-p", "com.apple.ubiquity.isDownloaded"])
                    .arg(&path)
                    .output()
                    && output.status.success()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    return stdout.trim() == "1";
                }
            }
        }
        true
    }

    pub fn list(&self, relative_dir: &str) -> io::Result<Vec<String>> {
        let dir = self.resolve_persistent(relative_dir)?;
        let mut entries = Vec::new();
        if !dir.exists() {
            return Ok(entries);
        }
        collect_files(&dir, &dir, &mut entries)?;
        entries.sort();
        Ok(entries)
    }

    pub fn store_artifact(
        &self,
        app_name: &str,
        artifact_type: &str,
        filename: &str,
        data: &[u8],
    ) -> io::Result<PathBuf> {
        let artifact_type = ArtifactType::parse(artifact_type)?;
        let app_name = sanitize_component(app_name);
        let file_name = sanitize_component(filename);
        let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
        let relative = format!(
            "{}/{}/{}/{}",
            artifact_type.as_str(),
            app_name,
            timestamp,
            file_name
        );
        self.write(&relative, data)?;
        Ok(self.resolve_persistent(&relative)?)
    }

    pub fn read_json<T>(&self, relative_path: &str) -> io::Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.resolve_persistent(relative_path)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Some(value))
    }

    pub fn write_json<T>(&self, relative_path: &str, value: &T) -> io::Result<()>
    where
        T: Serialize,
    {
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        self.write(relative_path, &payload)
    }

    pub fn sync_root_state(&self) -> &'static str {
        if self.icloud_native {
            "icloud-native"
        } else {
            "local-only"
        }
    }

    fn resolve_persistent(&self, relative_path: &str) -> io::Result<PathBuf> {
        Ok(self.icloud_root.join(safe_relative_path(relative_path)?))
    }

    fn resolve_cache(&self, relative_path: &str) -> io::Result<PathBuf> {
        Ok(self.cache_root.join(safe_cache_relative_path(relative_path)?))
    }
}

pub fn default_cloud_docs_root() -> PathBuf {
    home_dir()
        .join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs")
}

pub fn default_icloud_root() -> PathBuf {
    default_cloud_docs_root().join("ZirOS")
}

pub fn default_local_root() -> PathBuf {
    home_dir().join(".zkf")
}

pub fn default_cache_root() -> PathBuf {
    default_local_root().join("cache")
}

fn collect_files(root: &Path, current: &Path, entries: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, entries)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        entries.push(relative);
    }
    Ok(())
}

fn safe_relative_path(relative_path: &str) -> io::Result<PathBuf> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute paths are not allowed",
        ));
    }
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => sanitized.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "parent-directory traversal is not allowed",
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "absolute paths are not allowed",
                ));
            }
        }
    }
    Ok(sanitized)
}

fn safe_cache_relative_path(relative_path: &str) -> io::Result<PathBuf> {
    let mut normalized = relative_path.trim_start_matches('/');
    if let Some(stripped) = normalized.strip_prefix("cache/") {
        normalized = stripped;
    }
    safe_relative_path(normalized)
}

fn sanitize_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            sanitized.push(ch);
        } else {
            sanitized.push('-');
        }
    }
    if sanitized.is_empty() {
        "artifact".to_string()
    } else {
        sanitized
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn directory_is_writable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| !metadata.permissions().readonly())
        .unwrap_or(false)
}

fn zeroize_path(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            zeroize_path(&entry.path())?;
        }
        return Ok(());
    }
    let length = fs::metadata(path)?.len();
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; length as usize];
    file.write_all(&zeros)?;
    file.flush()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_brctl(action: &str, path: &Path) -> io::Result<()> {
    let output = Command::new("brctl").arg(action).arg(path).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "brctl {action} {} failed: {}",
        path.display(),
        stderr.trim()
    )))
}

/// Write to an iCloud-managed path using NSFileCoordinator for priority upload.
///
/// When a file is written through NSFileCoordinator, the macOS `bird` daemon
/// (iCloud sync) is notified synchronously as part of the write operation.
/// This triggers an upload queue entry within 1-2 seconds, compared to up to
/// 30 seconds when writing directly through `std::fs::write` (which relies on
/// FSEvents polling for the `bird` daemon to discover the change).
///
/// This is the same mechanism Apple's own applications (Pages, Numbers,
/// Keynote, Notes) use when saving documents to iCloud Drive.
#[cfg(target_os = "macos")]
fn coordinated_write(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::process::Command;

    // Write a small Swift helper inline that uses NSFileCoordinator.
    // This avoids adding objc2-foundation as a build dependency for a
    // single API call. The Swift invocation is ~30ms overhead, which is
    // negligible against proving times of seconds to minutes.
    let swift_src = format!(
        r#"
import Foundation
let url = URL(fileURLWithPath: "{path}")
let dir = url.deletingLastPathComponent()
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
let data = FileManager.default.contents(atPath: "/dev/stdin")!
let coordinator = NSFileCoordinator(filePresenter: nil)
var error: NSError?
var writeError: Error?
coordinator.coordinate(writingItemAt: url, options: .forReplacing, error: &error) {{ writeURL in
    do {{ try data.write(to: writeURL) }} catch {{ writeError = $0 }}
}}
if let e = error ?? writeError {{ fputs("error: \(e)\n", stderr); exit(1) }}
"#,
        path = path.display()
    );

    let child = Command::new("swift")
        .args(["-e", &swift_src])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(data);
            }
            let output = child.wait_with_output()?;
            if output.status.success() {
                Ok(())
            } else {
                // Fallback to direct write if Swift coordination fails
                fs::write(path, data)
            }
        }
        Err(_) => {
            // Swift not available — fall back to direct write
            fs::write(path, data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn store_artifact_organizes_under_timestamped_app_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("icloud");
        let cache = temp.path().join("cache");
        let cloudfs = CloudFS::from_roots(root.clone(), cache, true);
        let path = cloudfs
            .store_artifact("reentry-arc", "proofs", "proof.json", br#"{"ok":true}"#)
            .expect("store artifact");
        assert!(path.starts_with(root.join("proofs").join("reentry-arc")));
        assert_eq!(fs::read(path).expect("read"), br#"{"ok":true}"#);
    }

    #[test]
    fn cache_writer_strips_cache_prefix() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("icloud");
        let cache = temp.path().join("cache");
        let cloudfs = CloudFS::from_roots(root, cache.clone(), false);
        cloudfs
            .write_local_only("cache/witness.json", br#"{"secret":1}"#)
            .expect("write local");
        assert_eq!(
            fs::read(cache.join("witness.json")).expect("read"),
            br#"{"secret":1}"#
        );
    }

    #[test]
    fn list_returns_relative_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("icloud");
        let cache = temp.path().join("cache");
        let cloudfs = CloudFS::from_roots(root.clone(), cache, true);
        cloudfs
            .write("telemetry/2026-03-29/a.json", b"{}")
            .expect("write a");
        cloudfs
            .write("telemetry/2026-03-29/b.json", b"{}")
            .expect("write b");
        let entries = cloudfs.list("telemetry").expect("list");
        assert_eq!(
            entries,
            vec![
                "2026-03-29/a.json".to_string(),
                "2026-03-29/b.json".to_string()
            ]
        );
    }

    #[test]
    fn reject_parent_directory_traversal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(temp.path().join("icloud"), temp.path().join("cache"), false);
        let error = cloudfs.write("../escape", b"x").expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
