use crate::policy::{StorageProfile, default_policy, default_policy_for_profile};
use crate::{home_dir, normalize_path_string};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageGuardianConfig {
    pub enabled: bool,
    pub icloud_archive_enabled: bool,
    pub auto_purge_debug_cache: bool,
    pub auto_archive_proofs: bool,
    pub auto_archive_telemetry: bool,
    pub monitor_interval_secs: u64,
    pub warn_free_space_gb: u64,
    pub critical_free_space_gb: u64,
    pub purge_witness_after_prove: bool,
    pub profile: StorageProfile,
    pub storage_root: PathBuf,
    pub log_path: PathBuf,
    pub dry_run: bool,
}

impl Default for StorageGuardianConfig {
    fn default() -> Self {
        let home = home_dir();
        let policy = default_policy();
        Self {
            enabled: true,
            icloud_archive_enabled: true,
            auto_purge_debug_cache: policy.auto_purge_debug_cache,
            auto_archive_proofs: policy.auto_archive_proofs,
            auto_archive_telemetry: policy.auto_archive_telemetry,
            monitor_interval_secs: policy.monitor_interval_secs,
            warn_free_space_gb: policy.warn_free_space_gb,
            critical_free_space_gb: policy.critical_free_space_gb,
            purge_witness_after_prove: true,
            profile: policy.profile,
            storage_root: home.join(".zkf").join("storage"),
            log_path: home.join(".zkf").join("logs").join("storage-guardian.log"),
            dry_run: false,
        }
    }
}

impl StorageGuardianConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(value) = std::env::var("ZKF_STORAGE_PROFILE")
            && let Some(profile) = StorageProfile::parse(&value)
        {
            let policy = default_policy_for_profile(profile);
            config.profile = profile;
            config.auto_purge_debug_cache = policy.auto_purge_debug_cache;
            config.auto_archive_proofs = policy.auto_archive_proofs;
            config.auto_archive_telemetry = policy.auto_archive_telemetry;
            config.monitor_interval_secs = policy.monitor_interval_secs;
            config.warn_free_space_gb = policy.warn_free_space_gb;
            config.critical_free_space_gb = policy.critical_free_space_gb;
        }

        if let Ok(value) = std::env::var("ZKF_STORAGE_ENABLED") {
            config.enabled = parse_boolish(&value, config.enabled);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_ICLOUD") {
            config.icloud_archive_enabled = parse_boolish(&value, config.icloud_archive_enabled);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_ARCHIVE_PROOFS") {
            config.auto_archive_proofs = parse_boolish(&value, config.auto_archive_proofs);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_ARCHIVE_TELEMETRY") {
            config.auto_archive_telemetry =
                parse_boolish(&value, config.auto_archive_telemetry);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_PURGE_WITNESS") {
            config.purge_witness_after_prove =
                parse_boolish(&value, config.purge_witness_after_prove);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_WARN_GB")
            && let Ok(parsed) = value.parse::<u64>()
        {
            config.warn_free_space_gb = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_CRIT_GB")
            && let Ok(parsed) = value.parse::<u64>()
        {
            config.critical_free_space_gb = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_INTERVAL")
            && let Ok(parsed) = value.parse::<u64>()
        {
            config.monitor_interval_secs = parsed.max(1);
        }
        if let Ok(value) = std::env::var("ZKF_STORAGE_DRY_RUN") {
            config.dry_run = parse_boolish(&value, config.dry_run);
        } else if let Ok(value) = std::env::var("ZIROS_DRY_RUN") {
            config.dry_run = parse_boolish(&value, config.dry_run);
        }
        config
    }

    pub fn repo_display_root(&self) -> String {
        normalize_path_string(&self.storage_root)
    }
}

fn parse_boolish(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::StorageGuardianConfig;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_env<T>(pairs: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_values = pairs
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
            .collect::<Vec<_>>();
        unsafe {
            for (key, value) in pairs {
                std::env::set_var(key, value);
            }
        }
        let result = f();
        unsafe {
            for (key, old_value) in old_values {
                match old_value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        result
    }

    #[test]
    fn from_env_respects_profile_and_threshold_overrides() {
        with_env(
            &[
                ("ZKF_STORAGE_PROFILE", "generous"),
                ("ZKF_STORAGE_WARN_GB", "123"),
                ("ZKF_STORAGE_CRIT_GB", "45"),
                ("ZKF_STORAGE_INTERVAL", "99"),
            ],
            || {
                let config = StorageGuardianConfig::from_env();
                assert_eq!(config.warn_free_space_gb, 123);
                assert_eq!(config.critical_free_space_gb, 45);
                assert_eq!(config.monitor_interval_secs, 99);
            },
        );
    }

    #[test]
    fn from_env_accepts_ziros_dry_run_alias() {
        with_env(&[("ZIROS_DRY_RUN", "1")], || {
            let config = StorageGuardianConfig::from_env();
            assert!(config.dry_run);
        });
    }
}
