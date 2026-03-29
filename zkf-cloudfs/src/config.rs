use crate::cloudfs::CloudFS;
use serde::{Deserialize, Serialize};
use std::io;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudFSConfig {
    pub icloud_enabled: bool,
    pub local_cache_max_gb: u64,
    #[serde(default)]
    pub prefetch_on_startup: Vec<String>,
    pub auto_evict_after_hours: u64,
}

impl Default for CloudFSConfig {
    fn default() -> Self {
        Self {
            icloud_enabled: cfg!(target_os = "macos"),
            local_cache_max_gb: default_cache_budget_gb(None),
            prefetch_on_startup: Vec::new(),
            auto_evict_after_hours: 24,
        }
    }
}

impl CloudFSConfig {
    pub fn load(cloudfs: &CloudFS) -> io::Result<Self> {
        let default = Self {
            icloud_enabled: cfg!(target_os = "macos"),
            local_cache_max_gb: default_cache_budget_gb(device_model().as_deref()),
            prefetch_on_startup: Vec::new(),
            auto_evict_after_hours: 24,
        };
        let path = cloudfs.persistent_root().join("config.json");
        if !path.exists() {
            return Ok(default);
        }
        let bytes = std::fs::read(path)?;
        let mut config: Self = serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if config.local_cache_max_gb == 0 {
            config.local_cache_max_gb = default.local_cache_max_gb;
        }
        if config.auto_evict_after_hours == 0 {
            config.auto_evict_after_hours = default.auto_evict_after_hours;
        }
        Ok(config)
    }
}

pub fn default_cache_budget_gb(model: Option<&str>) -> u64 {
    let lower = model.unwrap_or_default().to_ascii_lowercase();
    if lower.contains("air") {
        10
    } else if lower.contains("studio") {
        200
    } else {
        50
    }
}

fn device_model() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.model"]).output()
            && output.status.success()
        {
            let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !model.is_empty() {
                return Some(model);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudfs::CloudFS;

    #[test]
    fn default_cache_budget_matches_device_profiles() {
        assert_eq!(default_cache_budget_gb(Some("MacBookAir10,1")), 10);
        assert_eq!(default_cache_budget_gb(Some("MacBookPro18,3")), 50);
        assert_eq!(default_cache_budget_gb(Some("MacStudio1,1")), 200);
    }

    #[test]
    fn config_loads_defaults_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(temp.path().join("icloud"), temp.path().join("cache"), false);
        let config = CloudFSConfig::load(&cloudfs).expect("load");
        assert_eq!(config.auto_evict_after_hours, 24);
        assert!(config.local_cache_max_gb > 0);
    }
}
