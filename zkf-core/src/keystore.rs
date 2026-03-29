//! Service-based proving and swarm key storage.
//!
//! On macOS, private material is stored in iCloud Keychain-compatible generic
//! password items. Public metadata lives in the ZirOS iCloud root under
//! `ZirOS/keys/index.json`. On non-macOS hosts, key bytes fall back to
//! restricted local files.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEntry {
    pub label: String,
    pub digest: String,
    pub stored_at_unix: u64,
    pub backend: KeystoreBackend,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeystoreBackend {
    SecureEnclave,
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

pub fn store_key(label: &str, key_data: &[u8]) -> Result<KeystoreEntry, String> {
    let service = proving_service(label);
    let account = label.to_string();
    store_service_key(&service, &account, key_data).map(|mut entry| {
        entry.label = label.to_string();
        entry
    })
}

pub fn retrieve_key(label: &str) -> Result<Vec<u8>, String> {
    retrieve_service_key(&proving_service(label), label)
}

pub fn delete_key(label: &str) -> Result<(), String> {
    delete_service_key(&proving_service(label), label)
}

pub fn list_keys() -> Result<Vec<KeystoreEntry>, String> {
    let index_path = key_index_path();
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let bytes =
        std::fs::read(&index_path).map_err(|e| format!("failed to read keystore index: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse keystore index: {e}"))
}

pub fn preferred_backend() -> KeystoreBackend {
    #[cfg(target_os = "macos")]
    {
        if synchronizable_keychain_supported() {
            KeystoreBackend::SecureEnclave
        } else {
            KeystoreBackend::FileStore
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        KeystoreBackend::FileStore
    }
}

pub fn synchronizable_keychain_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        keychain_write_probe().is_ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

pub fn store_service_key(
    service: &str,
    account: &str,
    key_data: &[u8],
) -> Result<KeystoreEntry, String> {
    let digest = hex_sha256(key_data);
    let stored_at_unix = unix_now();

    #[cfg(target_os = "macos")]
    {
        if store_keychain_item(service, account, key_data).is_ok() {
            let entry = KeystoreEntry {
                label: account.to_string(),
                digest,
                stored_at_unix,
                backend: KeystoreBackend::SecureEnclave,
                service: service.to_string(),
                account: account.to_string(),
            };
            update_index(&entry)?;
            return Ok(entry);
        }
    }

    store_file_key(service, account, key_data)?;
    let entry = KeystoreEntry {
        label: account.to_string(),
        digest,
        stored_at_unix,
        backend: KeystoreBackend::FileStore,
        service: service.to_string(),
        account: account.to_string(),
    };
    update_index(&entry)?;
    Ok(entry)
}

pub fn retrieve_service_key(service: &str, account: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(data) = retrieve_keychain_item(service, account) {
            return Ok(data);
        }
    }
    retrieve_file_key(service, account)
}

pub fn delete_service_key(service: &str, account: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = delete_keychain_item(service, account);
    }
    let _ = delete_file_key(service, account);
    remove_index(service, account)
}

fn proving_service(label: &str) -> String {
    format!("com.ziros.proving.{label}")
}

#[cfg(target_os = "macos")]
fn store_keychain_item(service: &str, account: &str, data: &[u8]) -> Result<(), String> {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlock;
    use security_framework_sys::base::errSecDuplicateItem;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};

    unsafe extern "C" {
        static kSecAttrAccessible: *const core_foundation::string::__CFString;
    }

    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(true).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible.cast()) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlock) }
                .into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(data).into_CFType(),
        ),
    ];
    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == errSecDuplicateItem {
        let selector = CFDictionary::from_CFType_pairs(&query[..4]);
        let updates = CFDictionary::from_CFType_pairs(&query[4..]);
        cvt_status(unsafe {
            SecItemUpdate(
                selector.as_concrete_TypeRef(),
                updates.as_concrete_TypeRef(),
            )
        })
    } else {
        cvt_status(status)
    }
}

#[cfg(target_os = "macos")]
fn retrieve_keychain_item(service: &str, account: &str) -> Result<Vec<u8>, String> {
    use core_foundation::base::{CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(true).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ),
    ];
    let params = CFDictionary::from_CFType_pairs(&query);
    let mut result: CFTypeRef = std::ptr::null();
    cvt_status(unsafe { SecItemCopyMatching(params.as_concrete_TypeRef(), &mut result) })?;
    if result.is_null() {
        return Err(format!("missing keychain item {service}/{account}"));
    }
    let data = unsafe { CFData::wrap_under_create_rule(result as _) };
    Ok(data.bytes().to_vec())
}

#[cfg(target_os = "macos")]
fn delete_keychain_item(service: &str, account: &str) -> Result<(), String> {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword,
    };
    use security_framework_sys::keychain_item::SecItemDelete;

    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(true).into_CFType(),
        ),
    ];
    let params = CFDictionary::from_CFType_pairs(&query);
    cvt_status(unsafe { SecItemDelete(params.as_concrete_TypeRef()) })
}

#[cfg(target_os = "macos")]
fn keychain_write_probe() -> Result<(), String> {
    let account = format!("probe-{}", unix_now());
    store_keychain_item("com.ziros.keychain.probe", &account, b"probe")?;
    delete_keychain_item("com.ziros.keychain.probe", &account)
}

#[cfg(target_os = "macos")]
fn cvt_status(status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Security.framework error {}",
            security_framework::base::Error::from_code(status)
        ))
    }
}

fn local_keystore_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("keys");
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create keystore dir: {e}"))?;
    Ok(dir)
}

fn key_index_path() -> PathBuf {
    persistent_root().join("keys").join("index.json")
}

fn store_file_key(service: &str, account: &str, data: &[u8]) -> Result<(), String> {
    let path = local_keystore_dir()?.join(file_name_for(service, account));
    std::fs::write(&path, data).map_err(|e| format!("failed to write key file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set key permissions: {e}"))?;
    }
    Ok(())
}

fn retrieve_file_key(service: &str, account: &str) -> Result<Vec<u8>, String> {
    let path = local_keystore_dir()?.join(file_name_for(service, account));
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
    std::fs::read(path).map_err(|e| format!("failed to read key file: {e}"))
}

fn delete_file_key(service: &str, account: &str) -> Result<(), String> {
    let path = local_keystore_dir()?.join(file_name_for(service, account));
    if path.exists() {
        if let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) {
            let _ = std::fs::write(&path, vec![0u8; len as usize]);
        }
        std::fs::remove_file(path).map_err(|e| format!("failed to delete key file: {e}"))?;
    }
    Ok(())
}

fn file_name_for(service: &str, account: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(service.as_bytes());
    hasher.update([0u8]);
    hasher.update(account.as_bytes());
    format!("{:x}.key", hasher.finalize())
}

fn update_index(entry: &KeystoreEntry) -> Result<(), String> {
    let index_path = key_index_path();
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create index dir: {e}"))?;
    }
    let mut entries = list_keys().unwrap_or_default();
    entries.retain(|candidate| {
        !(candidate.service == entry.service && candidate.account == entry.account)
    });
    entries.push(entry.clone());
    let json = serde_json::to_vec_pretty(&entries)
        .map_err(|e| format!("failed to serialize index: {e}"))?;
    std::fs::write(index_path, json).map_err(|e| format!("failed to write index: {e}"))
}

fn remove_index(service: &str, account: &str) -> Result<(), String> {
    let index_path = key_index_path();
    if !index_path.exists() {
        return Ok(());
    }
    let mut entries = list_keys().unwrap_or_default();
    entries.retain(|entry| !(entry.service == service && entry.account == account));
    let json = serde_json::to_vec_pretty(&entries)
        .map_err(|e| format!("failed to serialize index: {e}"))?;
    std::fs::write(index_path, json).map_err(|e| format!("failed to write index: {e}"))
}

fn persistent_root() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let cloud_docs = home
        .join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    let zir_root = cloud_docs.join("ZirOS");
    if cfg!(target_os = "macos") && cloud_docs.exists() && directory_is_writable(&cloud_docs) {
        zir_root
    } else {
        home.join(".zkf")
    }
}

fn directory_is_writable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| !metadata.permissions().readonly())
        .unwrap_or(false)
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    fn service_roundtrip_helpers_are_stable() {
        let service = proving_service("digest-123");
        assert_eq!(service, "com.ziros.proving.digest-123");
        assert!(file_name_for(&service, "digest-123").ends_with(".key"));
    }

    #[test]
    fn hex_sha256_deterministic() {
        let d1 = hex_sha256(b"test");
        let d2 = hex_sha256(b"test");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }
}
