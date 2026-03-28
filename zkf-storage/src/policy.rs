use crate::health::detected_capacity_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProfile {
    Constrained,
    Standard,
    Comfortable,
    Generous,
}

impl StorageProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constrained => "constrained",
            Self::Standard => "standard",
            Self::Comfortable => "comfortable",
            Self::Generous => "generous",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "constrained" => Some(Self::Constrained),
            "standard" => Some(Self::Standard),
            "comfortable" => Some(Self::Comfortable),
            "generous" => Some(Self::Generous),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub profile: StorageProfile,
    pub warn_free_space_gb: u64,
    pub critical_free_space_gb: u64,
    pub monitor_interval_secs: u64,
    pub telemetry_retention_days: u64,
    pub keep_release_binaries: bool,
    pub auto_archive_proofs: bool,
    pub auto_archive_telemetry: bool,
    pub auto_purge_debug_cache: bool,
}

pub fn auto_profile(capacity_gb: u64) -> StorageProfile {
    match capacity_gb {
        0..=300 => StorageProfile::Constrained,
        301..=600 => StorageProfile::Standard,
        601..=1200 => StorageProfile::Comfortable,
        _ => StorageProfile::Generous,
    }
}

pub fn default_policy() -> RetentionPolicy {
    let capacity_bytes = detected_capacity_bytes().unwrap_or_default();
    let capacity_gb = if capacity_bytes == 0 {
        0
    } else {
        capacity_bytes / 1_000_000_000
    };
    default_policy_for_profile(auto_profile(capacity_gb))
}

pub fn default_policy_for_profile(profile: StorageProfile) -> RetentionPolicy {
    match profile {
        StorageProfile::Constrained => RetentionPolicy {
            profile,
            warn_free_space_gb: 30,
            critical_free_space_gb: 15,
            monitor_interval_secs: 1_800,
            telemetry_retention_days: 0,
            keep_release_binaries: true,
            auto_archive_proofs: true,
            auto_archive_telemetry: true,
            auto_purge_debug_cache: true,
        },
        StorageProfile::Standard => RetentionPolicy {
            profile,
            warn_free_space_gb: 50,
            critical_free_space_gb: 25,
            monitor_interval_secs: 3_600,
            telemetry_retention_days: 7,
            keep_release_binaries: true,
            auto_archive_proofs: true,
            auto_archive_telemetry: true,
            auto_purge_debug_cache: true,
        },
        StorageProfile::Comfortable => RetentionPolicy {
            profile,
            warn_free_space_gb: 100,
            critical_free_space_gb: 50,
            monitor_interval_secs: 3_600,
            telemetry_retention_days: 30,
            keep_release_binaries: true,
            auto_archive_proofs: true,
            auto_archive_telemetry: true,
            auto_purge_debug_cache: true,
        },
        StorageProfile::Generous => RetentionPolicy {
            profile,
            warn_free_space_gb: 200,
            critical_free_space_gb: 100,
            monitor_interval_secs: 86_400,
            telemetry_retention_days: 90,
            keep_release_binaries: true,
            auto_archive_proofs: true,
            auto_archive_telemetry: true,
            auto_purge_debug_cache: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{StorageProfile, auto_profile, default_policy_for_profile};

    #[test]
    fn auto_profile_uses_exact_thresholds() {
        assert_eq!(auto_profile(300), StorageProfile::Constrained);
        assert_eq!(auto_profile(301), StorageProfile::Standard);
        assert_eq!(auto_profile(600), StorageProfile::Standard);
        assert_eq!(auto_profile(601), StorageProfile::Comfortable);
        assert_eq!(auto_profile(1_200), StorageProfile::Comfortable);
        assert_eq!(auto_profile(1_201), StorageProfile::Generous);
    }

    #[test]
    fn default_policy_matches_blueprint_thresholds() {
        let constrained = default_policy_for_profile(StorageProfile::Constrained);
        assert_eq!(constrained.warn_free_space_gb, 30);
        assert_eq!(constrained.critical_free_space_gb, 15);
        assert_eq!(constrained.monitor_interval_secs, 1_800);

        let standard = default_policy_for_profile(StorageProfile::Standard);
        assert_eq!(standard.warn_free_space_gb, 50);
        assert_eq!(standard.critical_free_space_gb, 25);
        assert_eq!(standard.monitor_interval_secs, 3_600);

        let comfortable = default_policy_for_profile(StorageProfile::Comfortable);
        assert_eq!(comfortable.warn_free_space_gb, 100);
        assert_eq!(comfortable.critical_free_space_gb, 50);
        assert_eq!(comfortable.monitor_interval_secs, 3_600);

        let generous = default_policy_for_profile(StorageProfile::Generous);
        assert_eq!(generous.warn_free_space_gb, 200);
        assert_eq!(generous.critical_free_space_gb, 100);
        assert_eq!(generous.monitor_interval_secs, 86_400);
    }
}
