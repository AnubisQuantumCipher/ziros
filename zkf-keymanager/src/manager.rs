use crate::zeroize_types::{Ed25519Seed, SymmetricKey};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::Utc;
use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
use libcrux_ml_dsa::ml_dsa_87::generate_key_pair as generate_ml_dsa_key_pair;
use libcrux_ml_kem::KEY_GENERATION_SEED_SIZE as ML_KEM_KEY_GENERATION_SEED_SIZE;
use libcrux_ml_kem::mlkem1024::generate_key_pair as generate_ml_kem_key_pair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
use zkf_cloudfs::CloudFS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    Ed25519Seed,
    MlDsa87Private,
    Groth16ProvingKey,
    ApiKey,
    CredentialIssuerKey,
    MlKem1024Decapsulation,
    X25519Secret,
    Symmetric,
    Unknown,
}

impl KeyType {
    pub fn from_service(service: &str) -> Self {
        if service.contains(".swarm.ed25519") {
            Self::Ed25519Seed
        } else if service.contains(".swarm.mldsa87") {
            Self::MlDsa87Private
        } else if service.contains(".proving.") {
            Self::Groth16ProvingKey
        } else if service.contains(".api.") {
            Self::ApiKey
        } else if service.contains(".credential.") {
            Self::CredentialIssuerKey
        } else if service.contains(".mlkem1024") {
            Self::MlKem1024Decapsulation
        } else if service.contains(".x25519") {
            Self::X25519Secret
        } else if service.contains(".symmetric") {
            Self::Symmetric
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBackend {
    IcloudKeychain,
    EncryptedFile,
}

impl KeyBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IcloudKeychain => "icloud-keychain",
            Self::EncryptedFile => "encrypted-file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub service: String,
    pub key_type: KeyType,
    pub backend: KeyBackend,
    pub digest: String,
    pub stored_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAuditItem {
    pub entry: KeyEntry,
    pub present: bool,
    pub synchronizable: bool,
    pub age_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAuditReport {
    pub backend: KeyBackend,
    pub healthy: bool,
    pub key_count: usize,
    pub items: Vec<KeyAuditItem>,
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    cloudfs: CloudFS,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct KeyIndex {
    version: String,
    entries: Vec<KeyEntry>,
}

impl KeyManager {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            cloudfs: CloudFS::new()?,
        })
    }

    pub fn with_cloudfs(cloudfs: CloudFS) -> Self {
        Self { cloudfs }
    }

    pub fn backend(&self) -> KeyBackend {
        #[cfg(target_os = "macos")]
        {
            if zkf_core::keystore::synchronizable_keychain_supported()
                && keychain_storage_supported()
            {
                KeyBackend::IcloudKeychain
            } else {
                KeyBackend::EncryptedFile
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            KeyBackend::EncryptedFile
        }
    }

    pub fn cloudfs(&self) -> &CloudFS {
        &self.cloudfs
    }

    pub fn keychain_probe(&self) -> io::Result<bool> {
        #[cfg(target_os = "macos")]
        {
            return keychain_probe();
        }

        #[cfg(not(target_os = "macos"))]
        {
            Ok(false)
        }
    }

    pub fn store_key(&self, id: &str, service: &str, bytes: &[u8]) -> io::Result<()> {
        let backend = self.backend();
        let entry = KeyEntry {
            id: id.to_string(),
            service: service.to_string(),
            key_type: KeyType::from_service(service),
            backend,
            digest: hex_sha256(bytes),
            stored_at_unix: Utc::now().timestamp(),
        };

        match backend {
            KeyBackend::IcloudKeychain => {
                #[cfg(target_os = "macos")]
                {
                    store_keychain_item(service, id, bytes)?;
                }
                #[cfg(not(target_os = "macos"))]
                {
                    return Err(io::Error::other(
                        "icloud-keychain backend is unavailable on this platform",
                    ));
                }
            }
            KeyBackend::EncryptedFile => {
                store_encrypted_file(&self.file_key_path(id, service), bytes)?;
            }
        }

        self.upsert_index_entry(entry)
    }

    pub fn retrieve_key(&self, id: &str, service: &str) -> io::Result<Vec<u8>> {
        match self.backend() {
            KeyBackend::IcloudKeychain => {
                #[cfg(target_os = "macos")]
                {
                    match retrieve_keychain_item(service, id) {
                        Ok(bytes) => Ok(bytes),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            let fallback_path = self.file_key_path(id, service);
                            match retrieve_encrypted_file(&fallback_path) {
                                Ok(bytes) => {
                                    // Migrate old fallback-backed material into the now-available
                                    // synchronizable keychain so subsequent unlocks stay on the
                                    // primary secure storage path.
                                    store_keychain_item(service, id, bytes.as_slice())?;
                                    let _ = delete_encrypted_file(&fallback_path);
                                    Ok(bytes)
                                }
                                Err(file_error) if file_error.kind() == io::ErrorKind::NotFound => {
                                    Err(error)
                                }
                                Err(file_error) => Err(file_error),
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Err(io::Error::other(
                        "icloud-keychain backend is unavailable on this platform",
                    ))
                }
            }
            KeyBackend::EncryptedFile => retrieve_encrypted_file(&self.file_key_path(id, service)),
        }
    }

    pub fn delete_key(&self, id: &str, service: &str) -> io::Result<()> {
        match self.backend() {
            KeyBackend::IcloudKeychain => {
                #[cfg(target_os = "macos")]
                {
                    let _ = delete_keychain_item(service, id);
                }
            }
            KeyBackend::EncryptedFile => {
                let _ = delete_encrypted_file(&self.file_key_path(id, service));
            }
        }

        self.remove_index_entry(id, service)
    }

    pub fn list_all(&self) -> io::Result<Vec<KeyEntry>> {
        let index = self.read_index()?;
        let prefix = "com.ziros.";
        Ok(index
            .entries
            .into_iter()
            .filter(|entry| entry.service.starts_with(prefix))
            .collect())
    }

    pub fn inspect(&self, id: &str) -> io::Result<KeyEntry> {
        self.list_all()?
            .into_iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("key '{id}' not found")))
    }

    pub fn rotate(&self, id: &str) -> io::Result<KeyEntry> {
        let entry = self.inspect(id)?;
        let new_bytes = generate_key_material(entry.key_type)?;
        self.store_key(id, &entry.service, &new_bytes)?;
        self.inspect(id)
    }

    pub fn audit(&self) -> io::Result<KeyAuditReport> {
        let entries = self.list_all()?;
        let now = Utc::now().timestamp();
        let mut items = Vec::new();
        let mut healthy = true;
        for entry in entries {
            let present = self.retrieve_key(&entry.id, &entry.service).is_ok();
            if !present {
                healthy = false;
            }
            items.push(KeyAuditItem {
                age_seconds: now.saturating_sub(entry.stored_at_unix),
                present,
                synchronizable: matches!(entry.backend, KeyBackend::IcloudKeychain),
                note: if present {
                    None
                } else {
                    Some("missing private key material".to_string())
                },
                entry,
            });
        }
        Ok(KeyAuditReport {
            backend: self.backend(),
            healthy,
            key_count: items.len(),
            items,
        })
    }

    pub fn revoke(&self, id: &str) -> io::Result<()> {
        let entry = self.inspect(id)?;
        self.delete_key(id, &entry.service)
    }

    pub fn write_public_metadata<T>(&self, relative_path: &str, value: &T) -> io::Result<()>
    where
        T: Serialize,
    {
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        self.cloudfs.write(relative_path, &payload)
    }

    fn file_key_path(&self, id: &str, service: &str) -> PathBuf {
        let mut digest = Sha256::new();
        digest.update(service.as_bytes());
        digest.update([0u8]);
        digest.update(id.as_bytes());
        let name = format!("{:x}.sealed", digest.finalize());
        self.cloudfs
            .cache_root()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("keys")
            .join(name)
    }

    fn read_index(&self) -> io::Result<KeyIndex> {
        Ok(self
            .cloudfs
            .read_json::<KeyIndex>("keys/index.json")?
            .unwrap_or(KeyIndex {
                version: "ziros-key-index-v1".to_string(),
                entries: Vec::new(),
            }))
    }

    fn upsert_index_entry(&self, entry: KeyEntry) -> io::Result<()> {
        let mut index = self.read_index()?;
        index.entries.retain(|candidate| {
            !(candidate.id == entry.id && candidate.service == entry.service)
        });
        index.entries.push(entry);
        index.entries.sort_by(|left, right| {
            left.service
                .cmp(&right.service)
                .then_with(|| left.id.cmp(&right.id))
        });
        self.cloudfs.write_json("keys/index.json", &index)
    }

    fn remove_index_entry(&self, id: &str, service: &str) -> io::Result<()> {
        let mut index = self.read_index()?;
        index.entries
            .retain(|entry| !(entry.id == id && entry.service == service));
        self.cloudfs.write_json("keys/index.json", &index)
    }
}

fn generate_key_material(key_type: KeyType) -> io::Result<Vec<u8>> {
    match key_type {
        KeyType::Ed25519Seed => Ok(Ed25519Seed(random_array::<32>()?).0.to_vec()),
        KeyType::MlDsa87Private => {
            let pair = generate_ml_dsa_key_pair(
                random_array::<{ KEY_GENERATION_RANDOMNESS_SIZE }>()?,
            );
            Ok(pair.signing_key.as_slice().to_vec())
        }
        KeyType::MlKem1024Decapsulation => {
            let pair = generate_ml_kem_key_pair(
                random_array::<{ ML_KEM_KEY_GENERATION_SEED_SIZE }>()?,
            );
            Ok(pair.sk().to_vec())
        }
        KeyType::ApiKey | KeyType::CredentialIssuerKey | KeyType::Symmetric => {
            Ok(SymmetricKey(random_array::<32>()?).0.to_vec())
        }
        KeyType::Groth16ProvingKey | KeyType::X25519Secret | KeyType::Unknown => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic rotation is unsupported for this key type",
        )),
    }
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes)
        .map_err(io::Error::other)?;
    Ok(bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn store_encrypted_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let salt = random_array::<16>()?;
    let nonce_bytes = random_array::<12>()?;
    let key = derive_file_key(&salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), bytes)
        .map_err(|err| io::Error::other(err.to_string()))?;
    let payload = SealedFile {
        salt: salt.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn retrieve_encrypted_file(path: &Path) -> io::Result<Vec<u8>> {
    let payload: SealedFile = serde_json::from_slice(&fs::read(path)?)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let key = derive_file_key(&payload.salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(&payload.nonce), payload.ciphertext.as_ref())
        .map_err(|err| io::Error::other(err.to_string()))
}

fn delete_encrypted_file(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let length = fs::metadata(path)?.len();
    fs::write(path, vec![0u8; length as usize])?;
    fs::remove_file(path)
}

fn derive_file_key(salt: &[u8]) -> io::Result<[u8; 32]> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut output = [0u8; 32];
    Argon2::default()
        .hash_password_into(home.as_bytes(), salt, &mut output)
        .map_err(|err| io::Error::other(err.to_string()))?;
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealedFile {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn store_keychain_item(service: &str, account: &str, bytes: &[u8]) -> io::Result<()> {
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
            CFData::from_buffer(bytes).into_CFType(),
        ),
    ];
    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == errSecDuplicateItem {
        let selector = CFDictionary::from_CFType_pairs(&query[..4]);
        let updates = CFDictionary::from_CFType_pairs(&query[4..]);
        cvt_status(unsafe {
            SecItemUpdate(selector.as_concrete_TypeRef(), updates.as_concrete_TypeRef())
        })
    } else {
        cvt_status(status)
    }
}

#[cfg(target_os = "macos")]
fn retrieve_keychain_item(service: &str, account: &str) -> io::Result<Vec<u8>> {
    use core_foundation::base::TCFType;
    use core_foundation::base::CFTypeRef;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::base::errSecItemNotFound;
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
    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut value: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut value) };
    if status == errSecItemNotFound {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing keychain item {service}/{account}"),
        ));
    }
    cvt_status(status)?;
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing keychain item {service}/{account}"),
        ));
    }
    let data = unsafe { CFData::wrap_under_create_rule(value as _) };
    Ok(data.bytes().to_vec())
}

#[cfg(target_os = "macos")]
fn delete_keychain_item(service: &str, account: &str) -> io::Result<()> {
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
    let dict = CFDictionary::from_CFType_pairs(&query);
    cvt_status(unsafe { SecItemDelete(dict.as_concrete_TypeRef()) })
}

#[cfg(target_os = "macos")]
fn keychain_probe() -> io::Result<bool> {
    use core_foundation::base::TCFType;
    use core_foundation::base::CFTypeRef;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::base::errSecItemNotFound;
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
            CFString::from("com.ziros.doctor.probe").into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from("probe").into_CFType(),
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
    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut value: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut value) };
    if status == 0 || status == errSecItemNotFound {
        Ok(true)
    } else {
        cvt_status(status).map(|_| true)
    }
}

#[cfg(target_os = "macos")]
fn keychain_storage_supported() -> bool {
    static SUPPORT: OnceLock<bool> = OnceLock::new();
    *SUPPORT.get_or_init(|| match keychain_storage_probe() {
        Ok(()) => true,
        Err(error) if error.to_string().contains("required entitlement") => false,
        Err(_) => false,
    })
}

#[cfg(target_os = "macos")]
fn keychain_storage_probe() -> io::Result<()> {
    let service = "com.ziros.keymanager.probe.write";
    let account = "probe-write";
    let probe = b"ziros-keymanager-probe";
    store_keychain_item(service, account, probe)?;
    let stored = retrieve_keychain_item(service, account)?;
    let _ = delete_keychain_item(service, account);
    if stored == probe {
        Ok(())
    } else {
        Err(io::Error::other(
            "keychain storage probe returned mismatched bytes",
        ))
    }
}

#[cfg(target_os = "macos")]
fn cvt_status(status: i32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Security.framework error {}",
            security_framework::base::Error::from_code(status)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store_or_skip(
        manager: &KeyManager,
        id: &str,
        service: &str,
        bytes: &[u8],
    ) -> Option<()> {
        match manager.store_key(id, service, bytes) {
            Ok(()) => Some(()),
            Err(error)
                if cfg!(target_os = "macos")
                    && error.to_string().contains("required entitlement") =>
            {
                None
            }
            Err(error) => panic!("store key: {error}"),
        }
    }

    #[test]
    fn list_reads_index_from_cloudfs() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(temp.path().join("icloud"), temp.path().join("cache"), false);
        let manager = KeyManager::with_cloudfs(cloudfs.clone());
        if store_or_skip(&manager, "peer-a", "com.ziros.swarm.ed25519", &[7u8; 32]).is_none() {
            return;
        }
        let entries = manager.list_all().expect("list keys");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_type, KeyType::Ed25519Seed);
    }

    #[test]
    fn rotate_rewrites_supported_key_material() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(temp.path().join("icloud"), temp.path().join("cache"), false);
        let manager = KeyManager::with_cloudfs(cloudfs);
        if store_or_skip(&manager, "peer-a", "com.ziros.swarm.ed25519", &[9u8; 32]).is_none() {
            return;
        }
        let before = manager
            .retrieve_key("peer-a", "com.ziros.swarm.ed25519")
            .expect("before");
        let rotated = manager.rotate("peer-a").expect("rotate");
        let after = manager
            .retrieve_key("peer-a", &rotated.service)
            .expect("after");
        assert_ne!(before, after);
    }

    #[test]
    fn revoke_removes_entry() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(temp.path().join("icloud"), temp.path().join("cache"), false);
        let manager = KeyManager::with_cloudfs(cloudfs);
        if store_or_skip(&manager, "peer-a", "com.ziros.swarm.ed25519", &[5u8; 32]).is_none() {
            return;
        }
        manager.revoke("peer-a").expect("revoke");
        assert!(manager.list_all().expect("list").is_empty());
    }
}
