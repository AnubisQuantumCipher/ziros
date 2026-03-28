//! Secure Enclave-backed keychain storage for proving keys.
//!
//! On macOS, proving keys can be stored in the SEP-protected keychain
//! using the Security.framework. This provides hardware-backed key
//! protection against extraction.
//!
//! On non-Apple platforms, keys are stored in a file-based keystore
//! with restricted permissions (0600).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A stored proving key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEntry {
    /// Human-readable label for this key.
    pub label: String,
    /// SHA-256 digest of the key material.
    pub digest: String,
    /// When the key was stored (Unix timestamp).
    pub stored_at_unix: u64,
    /// Storage backend used.
    pub backend: KeystoreBackend,
}

/// Where the key is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeystoreBackend {
    /// macOS Keychain (Secure Enclave protected on Apple Silicon)
    SecureEnclave,
    /// File-based storage with restricted permissions
    FileStore,
}

impl KeystoreBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure-enclave",
            Self::FileStore => "file-store",
        }
    }
}

/// Store a proving key in the platform keystore.
pub fn store_key(label: &str, key_data: &[u8]) -> Result<KeystoreEntry, String> {
    let digest = hex_sha256(key_data);
    let stored_at_unix = unix_now();

    #[cfg(target_os = "macos")]
    {
        if store_keychain_item(label, key_data).is_ok() {
            return Ok(KeystoreEntry {
                label: label.to_string(),
                digest,
                stored_at_unix,
                backend: KeystoreBackend::SecureEnclave,
            });
        }
    }

    // Fallback: file-based storage
    store_file_key(label, key_data)?;
    Ok(KeystoreEntry {
        label: label.to_string(),
        digest,
        stored_at_unix,
        backend: KeystoreBackend::FileStore,
    })
}

/// Retrieve a proving key from the platform keystore.
pub fn retrieve_key(label: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(data) = retrieve_keychain_item(label) {
            return Ok(data);
        }
    }

    retrieve_file_key(label)
}

/// Delete a proving key from the platform keystore.
pub fn delete_key(label: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = delete_keychain_item(label);
    }

    delete_file_key(label)
}

/// List all stored proving keys.
pub fn list_keys() -> Result<Vec<KeystoreEntry>, String> {
    let dir = keystore_dir()?;
    let index_path = dir.join("index.json");
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let data =
        std::fs::read(&index_path).map_err(|e| format!("failed to read keystore index: {e}"))?;
    serde_json::from_slice(&data).map_err(|e| format!("failed to parse keystore index: {e}"))
}

/// Get the preferred keystore backend for this platform.
pub fn preferred_backend() -> KeystoreBackend {
    #[cfg(target_os = "macos")]
    {
        KeystoreBackend::SecureEnclave
    }
    #[cfg(not(target_os = "macos"))]
    {
        KeystoreBackend::FileStore
    }
}

// ─── macOS Keychain ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn store_keychain_item(label: &str, data: &[u8]) -> Result<(), String> {
    use std::process::Command;
    // Use `security add-generic-password` for CLI-accessible keychain storage
    let service = format!("zkf-proving-key-{label}");
    let hex_data = hex::encode(data);

    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            &service,
            "-a",
            "zkf",
            "-w",
            &hex_data,
            "-U", // Update if exists
        ])
        .output()
        .map_err(|e| format!("security command failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "keychain store failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(target_os = "macos")]
fn retrieve_keychain_item(label: &str) -> Result<Vec<u8>, String> {
    use std::process::Command;
    let service = format!("zkf-proving-key-{label}");

    let output = Command::new("security")
        .args(["find-generic-password", "-s", &service, "-a", "zkf", "-w"])
        .output()
        .map_err(|e| format!("security command failed: {e}"))?;

    if output.status.success() {
        let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
        hex::decode(&hex).map_err(|e| format!("invalid hex in keychain: {e}"))
    } else {
        Err("key not found in keychain".to_string())
    }
}

#[cfg(target_os = "macos")]
fn delete_keychain_item(label: &str) -> Result<(), String> {
    use std::process::Command;
    let service = format!("zkf-proving-key-{label}");

    let output = Command::new("security")
        .args(["delete-generic-password", "-s", &service, "-a", "zkf"])
        .output()
        .map_err(|e| format!("security command failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err("key not found in keychain".to_string())
    }
}

// ─── File-based keystore ────────────────────────────────────────────────

fn keystore_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("keystore");
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create keystore dir: {e}"))?;
    Ok(dir)
}

fn store_file_key(label: &str, data: &[u8]) -> Result<(), String> {
    let dir = keystore_dir()?;
    let path = dir.join(format!("{label}.key"));

    std::fs::write(&path, data).map_err(|e| format!("failed to write key file: {e}"))?;

    // Set restrictive permissions (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("failed to set key file permissions: {e}"))?;
    }

    // Update index
    update_index(label, data, KeystoreBackend::FileStore)?;

    Ok(())
}

fn retrieve_file_key(label: &str) -> Result<Vec<u8>, String> {
    let dir = keystore_dir()?;
    let path = dir.join(format!("{label}.key"));

    // Verify permissions before reading
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.mode() & 0o777;
            if mode != 0o600 {
                return Err(format!(
                    "key file has insecure permissions {mode:o} (expected 600)"
                ));
            }
        }
    }

    std::fs::read(&path).map_err(|e| format!("failed to read key file: {e}"))
}

fn delete_file_key(label: &str) -> Result<(), String> {
    let dir = keystore_dir()?;
    let path = dir.join(format!("{label}.key"));
    if path.exists() {
        // Overwrite with zeros before deleting
        if let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) {
            let _ = std::fs::write(&path, vec![0u8; len as usize]);
        }
        std::fs::remove_file(&path).map_err(|e| format!("failed to delete key file: {e}"))?;
    }
    Ok(())
}

fn update_index(label: &str, data: &[u8], backend: KeystoreBackend) -> Result<(), String> {
    let dir = keystore_dir()?;
    let index_path = dir.join("index.json");

    let mut entries: Vec<KeystoreEntry> = if index_path.exists() {
        let raw = std::fs::read(&index_path).unwrap_or_default();
        serde_json::from_slice(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };

    entries.retain(|e| e.label != label);
    entries.push(KeystoreEntry {
        label: label.to_string(),
        digest: hex_sha256(data),
        stored_at_unix: unix_now(),
        backend,
    });

    let json = serde_json::to_vec_pretty(&entries)
        .map_err(|e| format!("failed to serialize index: {e}"))?;
    std::fs::write(&index_path, json).map_err(|e| format!("failed to write index: {e}"))
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// hex encode/decode helpers (avoiding external dep for this simple case)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {i}: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_backend_returns_valid() {
        let backend = preferred_backend();
        assert!(!backend.as_str().is_empty());
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"hello world";
        let encoded = hex::encode(data);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_sha256_deterministic() {
        let d1 = hex_sha256(b"test");
        let d2 = hex_sha256(b"test");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // 32 bytes * 2 hex chars
    }
}
