use crate::manifest::GadgetManifest;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Local gadget registry backed by a JSON index file.
pub struct LocalRegistry {
    root: PathBuf,
    index: RegistryIndex,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct RegistryIndex {
    gadgets: BTreeMap<String, GadgetEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GadgetEntry {
    manifest: GadgetManifest,
    content_sha256: String,
}

impl LocalRegistry {
    /// Open or create a local registry at the given root directory.
    pub fn open(root: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(root)?;
        let index_path = root.join("registry.json");
        let index = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            RegistryIndex::default()
        };
        Ok(Self {
            root: root.to_path_buf(),
            index,
        })
    }

    /// Publish a gadget to the local registry.
    pub fn publish(&mut self, mut manifest: GadgetManifest, content: &[u8]) -> std::io::Result<()> {
        if manifest.content_sha256.is_none() {
            manifest.set_content_digest(content);
        } else if !manifest.verify_content_digest(content) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "content digest mismatch for gadget '{}' while publishing to local registry",
                    manifest.name
                ),
            ));
        }
        let hash = manifest
            .content_sha256
            .clone()
            .unwrap_or_else(|| format!("{:x}", Sha256::digest(content)));
        let gadget_dir = self.root.join(&manifest.name);
        fs::create_dir_all(&gadget_dir)?;
        fs::write(gadget_dir.join("content.zkf"), content)?;
        fs::write(
            gadget_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?,
        )?;

        self.index.gadgets.insert(
            manifest.name.clone(),
            GadgetEntry {
                manifest,
                content_sha256: hash,
            },
        );
        self.save_index()
    }

    /// Get a gadget manifest by name.
    pub fn get(&self, name: &str) -> Option<&GadgetManifest> {
        self.index.gadgets.get(name).map(|entry| &entry.manifest)
    }

    /// Read installed gadget content by name.
    pub fn read_content(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.root.join(name).join("content.zkf");
        if !path.exists() {
            return Ok(None);
        }
        fs::read(path).map(Some)
    }

    /// List all gadgets in the registry.
    pub fn list(&self) -> Vec<&GadgetManifest> {
        self.index
            .gadgets
            .values()
            .map(|entry| &entry.manifest)
            .collect()
    }

    /// Search gadgets by name substring or tag.
    pub fn search(&self, query: &str) -> Vec<&GadgetManifest> {
        let q = query.to_lowercase();
        self.index
            .gadgets
            .values()
            .filter(|entry| {
                entry.manifest.name.to_lowercase().contains(&q)
                    || entry.manifest.description.to_lowercase().contains(&q)
                    || entry
                        .manifest
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&q))
            })
            .map(|entry| &entry.manifest)
            .collect()
    }

    /// Update an existing gadget in the registry, replacing its manifest and content.
    /// Returns `Ok(true)` if the gadget existed and was updated, `Ok(false)` if it did not exist.
    pub fn update(&mut self, manifest: GadgetManifest, content: &[u8]) -> std::io::Result<bool> {
        if !self.index.gadgets.contains_key(&manifest.name) {
            return Ok(false);
        }
        self.publish(manifest, content)?;
        Ok(true)
    }

    /// Remove a gadget from the registry.
    pub fn remove(&mut self, name: &str) -> std::io::Result<bool> {
        if self.index.gadgets.remove(name).is_some() {
            let gadget_dir = self.root.join(name);
            if gadget_dir.exists() {
                fs::remove_dir_all(gadget_dir)?;
            }
            self.save_index()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn save_index(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.index).map_err(std::io::Error::other)?;
        fs::write(self.root.join("registry.json"), json)
    }
}

// ---------------------------------------------------------------------------
// RemoteRegistry — fetches gadget manifests from a remote HTTP endpoint
// using curl as transport (no reqwest/ureq dependency needed).
// ---------------------------------------------------------------------------

/// Error type for remote registry operations.
#[derive(Debug)]
pub enum RemoteError {
    /// curl command failed or was not found.
    CurlFailed(String),
    /// Response could not be parsed as JSON.
    InvalidJson(String),
    /// I/O error when interacting with the local cache.
    Io(std::io::Error),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::CurlFailed(msg) => write!(f, "curl failed: {}", msg),
            RemoteError::InvalidJson(msg) => write!(f, "invalid JSON response: {}", msg),
            RemoteError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for RemoteError {}

impl From<std::io::Error> for RemoteError {
    fn from(e: std::io::Error) -> Self {
        RemoteError::Io(e)
    }
}

/// A remote gadget registry that fetches manifests over HTTP using curl.
pub struct RemoteRegistry {
    /// Base URL of the remote registry API (e.g. `https://registry.zkf.dev/api/v1`).
    base_url: String,
    /// Local directory for caching fetched packages.
    cache_dir: PathBuf,
}

impl RemoteRegistry {
    /// Create a new `RemoteRegistry`.
    /// - If `url` is `None`, reads `ZKF_REGISTRY_URL` from the environment,
    ///   defaulting to `https://registry.zkf.dev/api/v1`.
    /// - If `cache_dir` is `None`, uses `~/.zkf/cache/`.
    pub fn new(url: Option<String>, cache_dir: Option<PathBuf>) -> Self {
        let base_url = url
            .or_else(|| std::env::var("ZKF_REGISTRY_URL").ok())
            .unwrap_or_else(|| "https://registry.zkf.dev/api/v1".to_string());

        let cache_dir = cache_dir.unwrap_or_else(|| dirs_or_home().join(".zkf").join("cache"));

        Self {
            base_url,
            cache_dir,
        }
    }

    /// Fetch a single gadget manifest by name from the remote registry.
    /// Returns `None` if the remote is unreachable or the gadget does not exist.
    pub fn get(&self, name: &str) -> Option<GadgetManifest> {
        let url = format!("{}/gadgets/{}", self.base_url, name);
        match self.curl_get(&url) {
            Ok(body) => match serde_json::from_str::<GadgetManifest>(&body) {
                Ok(manifest) => {
                    let _ = self.cache_manifest(&manifest);
                    Some(manifest)
                }
                Err(_) => self.get_cached(name),
            },
            Err(_) => self.get_cached(name),
        }
    }

    /// List all gadgets available on the remote registry.
    /// Falls back to cached manifests if the remote is unavailable.
    pub fn list(&self) -> Vec<GadgetManifest> {
        let url = format!("{}/gadgets", self.base_url);
        match self.curl_get(&url) {
            Ok(body) => match serde_json::from_str::<Vec<GadgetManifest>>(&body) {
                Ok(manifests) => {
                    for m in &manifests {
                        let _ = self.cache_manifest(m);
                    }
                    manifests
                }
                Err(_) => self.list_cached(),
            },
            Err(_) => self.list_cached(),
        }
    }

    /// Search for gadgets by query string on the remote registry.
    /// Falls back to searching cached manifests if the remote is unavailable.
    pub fn search(&self, query: &str) -> Vec<GadgetManifest> {
        let url = format!("{}/gadgets?search={}", self.base_url, query);
        match self.curl_get(&url) {
            Ok(body) => serde_json::from_str::<Vec<GadgetManifest>>(&body)
                .unwrap_or_else(|_| self.search_cached(query)),
            Err(_) => self.search_cached(query),
        }
    }

    /// Fetch a gadget manifest and package bytes, falling back to the local cache.
    pub fn fetch_package(&self, name: &str) -> Option<(GadgetManifest, Vec<u8>)> {
        let manifest = self.get(name)?;
        let url = format!("{}/gadgets/{}/content", self.base_url, name);
        match self.curl_get_bytes(&url) {
            Ok(content) => {
                if !manifest.verify_content_digest(&content) {
                    return self
                        .get_cached_content(name)
                        .filter(|cached| manifest.verify_content_digest(cached))
                        .map(|cached| (manifest, cached));
                }
                let _ = self.cache_content(name, &content);
                Some((manifest, content))
            }
            Err(_) => self
                .get_cached_content(name)
                .filter(|cached| manifest.verify_content_digest(cached))
                .map(|cached| (manifest, cached)),
        }
    }

    /// Execute an HTTP GET request using curl via `std::process::Command`.
    fn curl_get(&self, url: &str) -> Result<String, RemoteError> {
        let bytes = self.curl_get_bytes(url)?;
        String::from_utf8(bytes)
            .map_err(|e| RemoteError::InvalidJson(format!("non-UTF8 response: {}", e)))
    }

    fn curl_get_bytes(&self, url: &str) -> Result<Vec<u8>, RemoteError> {
        let output = std::process::Command::new("curl")
            .args([
                "--silent",
                "--fail",
                "--show-error",
                "--max-time",
                "10",
                "--location",
                url,
            ])
            .output()
            .map_err(|e| RemoteError::CurlFailed(format!("failed to execute curl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RemoteError::CurlFailed(format!(
                "curl exited with {}: {}",
                output.status, stderr
            )));
        }

        Ok(output.stdout)
    }

    /// Cache a manifest locally on disk.
    fn cache_manifest(&self, manifest: &GadgetManifest) -> Result<(), RemoteError> {
        let dir = self.cache_dir.join(&manifest.name);
        fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| RemoteError::InvalidJson(e.to_string()))?;
        fs::write(dir.join("manifest.json"), json)?;
        Ok(())
    }

    fn cache_content(&self, name: &str, content: &[u8]) -> Result<(), RemoteError> {
        let dir = self.cache_dir.join(name);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("content.zkf"), content)?;
        Ok(())
    }

    /// Read a cached manifest from disk.
    fn get_cached(&self, name: &str) -> Option<GadgetManifest> {
        let path = self.cache_dir.join(name).join("manifest.json");
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn get_cached_content(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.cache_dir.join(name).join("content.zkf");
        fs::read(path).ok()
    }

    /// List all manifests in the local cache.
    fn list_cached(&self) -> Vec<GadgetManifest> {
        let mut result = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let manifest_path = entry.path().join("manifest.json");
                    if let Ok(data) = fs::read_to_string(&manifest_path)
                        && let Ok(m) = serde_json::from_str::<GadgetManifest>(&data)
                    {
                        result.push(m);
                    }
                }
            }
        }
        result
    }

    /// Search cached manifests by query string.
    fn search_cached(&self, query: &str) -> Vec<GadgetManifest> {
        let q = query.to_lowercase();
        self.list_cached()
            .into_iter()
            .filter(|m| {
                m.name.to_lowercase().contains(&q)
                    || m.description.to_lowercase().contains(&q)
                    || m.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }
}

/// Helper to get the user's home directory.
fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// CombinedRegistry — wraps both Local and Remote registries.
// ---------------------------------------------------------------------------

/// A registry that queries a local registry first, then falls back to a remote.
pub struct CombinedRegistry {
    pub local: LocalRegistry,
    pub remote: Option<RemoteRegistry>,
}

impl CombinedRegistry {
    /// Create a new combined registry.
    pub fn new(local: LocalRegistry, remote: Option<RemoteRegistry>) -> Self {
        Self { local, remote }
    }

    /// Get a gadget manifest by name. Local takes priority.
    pub fn get(&self, name: &str) -> Option<GadgetManifest> {
        if let Some(m) = self.local.get(name) {
            return Some(m.clone());
        }
        self.remote.as_ref().and_then(|r| r.get(name))
    }

    /// List all gadgets across both registries. Local entries override remote
    /// entries with the same name.
    pub fn list(&self) -> Vec<GadgetManifest> {
        let mut map: BTreeMap<String, GadgetManifest> = BTreeMap::new();

        // Remote first so local overrides.
        if let Some(remote) = &self.remote {
            for m in remote.list() {
                map.insert(m.name.clone(), m);
            }
        }
        for m in self.local.list() {
            map.insert(m.name.clone(), m.clone());
        }

        map.into_values().collect()
    }

    /// Search gadgets across both registries. Deduplicates by name (local wins).
    pub fn search(&self, query: &str) -> Vec<GadgetManifest> {
        let mut map: BTreeMap<String, GadgetManifest> = BTreeMap::new();

        if let Some(remote) = &self.remote {
            for m in remote.search(query) {
                map.insert(m.name.clone(), m);
            }
        }
        for m in self.local.search(query) {
            map.insert(m.name.clone(), m.clone());
        }

        map.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zkf-{}-test-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn publish_and_retrieve_gadget() {
        let dir = temp_dir("registry");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        let manifest = GadgetManifest::new("test_gadget", "0.1.0", "A test gadget");
        registry.publish(manifest, b"gadget content").unwrap();

        assert!(registry.get("test_gadget").is_some());
        assert_eq!(registry.list().len(), 1);

        registry.remove("test_gadget").unwrap();
        assert!(registry.get("test_gadget").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_by_name_and_tag() {
        let dir = temp_dir("search");
        let mut registry = LocalRegistry::open(&dir).unwrap();

        let mut m1 = GadgetManifest::new("poseidon_hash", "1.0.0", "Poseidon hash function");
        m1.tags = vec!["hash".to_string(), "zk".to_string()];
        registry.publish(m1, b"content1").unwrap();

        let m2 = GadgetManifest::new("merkle_tree", "0.1.0", "Merkle tree gadget");
        registry.publish(m2, b"content2").unwrap();

        assert_eq!(registry.search("poseidon").len(), 1);
        assert_eq!(registry.search("hash").len(), 1); // matches tag on poseidon
        assert_eq!(registry.search("gadget").len(), 1); // matches description on merkle
        assert_eq!(registry.search("nonexistent").len(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_registry_falls_back_to_cache() {
        let cache = temp_dir("remote-cache");
        fs::create_dir_all(&cache).unwrap();

        // Pre-populate the cache.
        let gadget_dir = cache.join("cached_gadget");
        fs::create_dir_all(&gadget_dir).unwrap();
        let manifest = GadgetManifest::new("cached_gadget", "0.1.0", "A cached gadget");
        fs::write(
            gadget_dir.join("manifest.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        // Point at a URL that will fail.
        let remote =
            RemoteRegistry::new(Some("http://127.0.0.1:1".to_string()), Some(cache.clone()));

        // Should fall back to cache.
        let result = remote.get("cached_gadget");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "cached_gadget");

        let listed = remote.list();
        assert_eq!(listed.len(), 1);

        // Non-existent gadget returns None.
        assert!(remote.get("nonexistent").is_none());

        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn remote_registry_fetch_package_uses_cached_content() {
        let cache = temp_dir("remote-package-cache");
        let remote =
            RemoteRegistry::new(Some("http://127.0.0.1:1".to_string()), Some(cache.clone()));
        let mut manifest = GadgetManifest::new("cached_pkg", "1.0.0", "cached package");
        let content = b"cached gadget bytes".to_vec();
        manifest.set_content_digest(&content);
        remote.cache_manifest(&manifest).unwrap();
        remote.cache_content(&manifest.name, &content).unwrap();

        let fetched = remote.fetch_package("cached_pkg").expect("cached package");
        assert_eq!(fetched.0.name, "cached_pkg");
        assert_eq!(fetched.1, content);

        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn publish_populates_manifest_digest_when_missing() {
        let dir = temp_dir("publish-digest");
        let mut registry = LocalRegistry::open(&dir).unwrap();
        registry
            .publish(
                GadgetManifest::new("digest-me", "0.1.0", "digest me"),
                b"content bytes",
            )
            .unwrap();

        let stored = registry.get("digest-me").expect("stored manifest");
        assert!(stored.content_sha256.is_some());
        assert!(stored.verify_content_digest(b"content bytes"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn combined_registry_local_overrides_remote_cache() {
        let local_dir = temp_dir("combined-local");
        let cache_dir = temp_dir("combined-cache");

        let mut local = LocalRegistry::open(&local_dir).unwrap();
        let local_manifest = GadgetManifest::new("shared", "2.0.0", "Local version");
        local.publish(local_manifest, b"local").unwrap();

        // Put a different version in remote cache.
        fs::create_dir_all(cache_dir.join("shared")).unwrap();
        let remote_manifest = GadgetManifest::new("shared", "1.0.0", "Remote version");
        fs::write(
            cache_dir.join("shared").join("manifest.json"),
            serde_json::to_string(&remote_manifest).unwrap(),
        )
        .unwrap();

        let remote = RemoteRegistry::new(
            Some("http://127.0.0.1:1".to_string()),
            Some(cache_dir.clone()),
        );
        let combined = CombinedRegistry::new(local, Some(remote));

        // get() should return local version.
        let got = combined.get("shared").unwrap();
        assert_eq!(got.version, "2.0.0");

        // list() should also have the local version win.
        let all = combined.list();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].version, "2.0.0");

        let _ = fs::remove_dir_all(&local_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }
}
