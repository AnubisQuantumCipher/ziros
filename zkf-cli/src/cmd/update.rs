use crate::cli::UpdateCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkf_agent::{ensure_ziros_layout, ziros_install_root, ziros_managed_bin_root};

const DEFAULT_INSTALLER_MANIFEST_URL: &str =
    "https://github.com/anubisquantumcipher/ziros/releases/latest/download/installer-manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryChannelV1 {
    pub platform: String,
    pub archive_url: String,
    pub sha256: String,
    pub binaries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerManifestV1 {
    pub schema: String,
    pub version: String,
    pub release_tag: String,
    pub channel: String,
    pub generated_at: String,
    pub platforms: Vec<BinaryChannelV1>,
}

#[derive(Debug, Clone, Serialize)]
struct UpdateStatusReportV1 {
    schema: String,
    current_version: String,
    manifest_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_tag: Option<String>,
    update_available: bool,
    install_mode: String,
}

pub(crate) fn handle_update(command: Option<UpdateCommands>) -> Result<(), String> {
    match command.unwrap_or(UpdateCommands::Apply {
        json: false,
        manifest_url: None,
    }) {
        UpdateCommands::Status { json, manifest_url } => handle_update_status(json, manifest_url),
        UpdateCommands::Apply { json, manifest_url } => handle_update_apply(json, manifest_url),
    }
}

pub(crate) fn handle_version(json: bool) -> Result<(), String> {
    let payload = serde_json::json!({
        "schema": "ziros-version-v1",
        "version": env!("CARGO_PKG_VERSION"),
        "pkg_name": env!("CARGO_PKG_NAME"),
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
    });
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
        );
    } else {
        println!("ziros {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}

fn handle_update_status(json_output: bool, manifest_url: Option<String>) -> Result<(), String> {
    let manifest_url = manifest_url.unwrap_or_else(resolve_manifest_url);
    let manifest = fetch_manifest(&manifest_url).ok();
    let report = UpdateStatusReportV1 {
        schema: "ziros-update-status-v1".to_string(),
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        manifest_url,
        remote_version: manifest.as_ref().map(|value| value.version.clone()),
        release_tag: manifest.as_ref().map(|value| value.release_tag.clone()),
        update_available: manifest
            .as_ref()
            .is_some_and(|value| value.version != env!("CARGO_PKG_VERSION")),
        install_mode: "managed-binary-or-source".to_string(),
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!("current: {}", report.current_version);
        if let Some(remote) = report.remote_version.as_deref() {
            println!("remote: {remote}");
        } else {
            println!("remote: unavailable");
        }
        println!(
            "update: {}",
            if report.update_available {
                "available"
            } else {
                "current"
            }
        );
        println!("manifest: {}", report.manifest_url);
    }
    Ok(())
}

fn handle_update_apply(json_output: bool, manifest_url: Option<String>) -> Result<(), String> {
    let _ = ensure_ziros_layout()?;
    let manifest_url = manifest_url.unwrap_or_else(resolve_manifest_url);
    let manifest = fetch_manifest(&manifest_url)?;
    let channel = manifest
        .platforms
        .into_iter()
        .find(|platform| platform.platform == current_platform_id())
        .ok_or_else(|| format!("no installer channel for {}", current_platform_id()))?;

    let archive_bytes = fetch_bytes(&channel.archive_url)?;
    let archive_sha = format!("{:x}", Sha256::digest(&archive_bytes));
    if archive_sha != channel.sha256 {
        return Err(format!(
            "installer archive checksum mismatch: expected {}, got {}",
            channel.sha256, archive_sha
        ));
    }

    fs::create_dir_all(ziros_install_root())
        .map_err(|error| format!("failed to create {}: {error}", ziros_install_root().display()))?;
    let archive_path = ziros_install_root().join("ziros-update.tar.gz");
    fs::write(&archive_path, &archive_bytes)
        .map_err(|error| format!("failed to write {}: {error}", archive_path.display()))?;

    let unpack_root = ziros_install_root().join("update-unpack");
    if unpack_root.exists() {
        fs::remove_dir_all(&unpack_root)
            .map_err(|error| format!("failed to remove {}: {error}", unpack_root.display()))?;
    }
    fs::create_dir_all(&unpack_root)
        .map_err(|error| format!("failed to create {}: {error}", unpack_root.display()))?;

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&unpack_root)
        .status()
        .map_err(|error| format!("failed to extract {}: {error}", archive_path.display()))?;
    if !status.success() {
        return Err(format!("tar failed while extracting {}", archive_path.display()));
    }

    fs::create_dir_all(ziros_managed_bin_root()).map_err(|error| {
        format!(
            "failed to create {}: {error}",
            ziros_managed_bin_root().display()
        )
    })?;

    for binary in &channel.binaries {
        let source = find_binary_in_tree(&unpack_root, binary)
            .ok_or_else(|| format!("archive does not contain '{binary}'"))?;
        let destination = ziros_managed_bin_root().join(binary);
        fs::copy(&source, &destination).map_err(|error| {
            format!(
                "failed to install {} -> {}: {error}",
                source.display(),
                destination.display()
            )
        })?;
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&destination)
                .map_err(|error| error.to_string())?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&destination, permissions).map_err(|error| error.to_string())?;
        }
    }

    let payload = serde_json::json!({
        "schema": "ziros-update-apply-v1",
        "installed_version": manifest.version,
        "release_tag": manifest.release_tag,
        "managed_bin_root": ziros_managed_bin_root().display().to_string(),
    });
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "installed {} into {}",
            payload["installed_version"].as_str().unwrap_or_default(),
            payload["managed_bin_root"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}

fn resolve_manifest_url() -> String {
    std::env::var("ZIROS_INSTALLER_MANIFEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_INSTALLER_MANIFEST_URL.to_string())
}

fn fetch_manifest(manifest_url: &str) -> Result<InstallerManifestV1, String> {
    let bytes = fetch_bytes(manifest_url)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid installer manifest: {error}"))
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return fs::read(path).map_err(|error| error.to_string());
    }
    let response = ureq::get(url)
        .call()
        .map_err(|error| format!("failed to fetch {url}: {error}"))?;
    let mut reader = response.into_reader();
    let mut bytes = Vec::new();
    use std::io::Read;
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {url}: {error}"))?;
    Ok(bytes)
}

fn current_platform_id() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn find_binary_in_tree(root: &Path, name: &str) -> Option<PathBuf> {
    if root.is_file() {
        return (root.file_name().and_then(|value| value.to_str()) == Some(name))
            .then(|| root.to_path_buf());
    }
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(found) = find_binary_in_tree(&path, name) {
            return Some(found);
        }
    }
    None
}
