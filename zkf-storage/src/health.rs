use crate::platform::platform_drive_info;
use crate::policy::{auto_profile, default_policy_for_profile};
use crate::{StorageError, file_size_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthStatus {
    Healthy,
    Warning { reason: String },
    Critical { reason: String },
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning { .. } => "warning",
            Self::Critical { .. } => "critical",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Healthy => None,
            Self::Warning { reason } | Self::Critical { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsdHealth {
    pub device_name: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f64,
    pub wear_level_percent: Option<f64>,
    pub temperature_celsius: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub health_status: HealthStatus,
    pub smart_available: bool,
}

pub fn get_ssd_health() -> Result<SsdHealth, StorageError> {
    let info = platform_drive_info()?;
    let capacity_bytes = info
        .capacity_bytes
        .max(info.used_bytes.saturating_add(info.available_bytes));
    let capacity_gb = if capacity_bytes == 0 {
        0
    } else {
        capacity_bytes / 1_000_000_000
    };
    let policy = default_policy_for_profile(auto_profile(capacity_gb));
    let used_percent = if capacity_bytes == 0 {
        0.0
    } else {
        (info.used_bytes as f64 / capacity_bytes as f64) * 100.0
    };
    let health_status = evaluate_health_status(
        info.available_bytes,
        policy.warn_free_space_gb,
        policy.critical_free_space_gb,
        info.wear_level_percent,
    );

    Ok(SsdHealth {
        device_name: info.device_name,
        model: info.model.unwrap_or_else(|| "unknown".to_string()),
        serial: info.serial.unwrap_or_else(|| "unknown".to_string()),
        firmware: info.firmware.unwrap_or_else(|| "unknown".to_string()),
        capacity_bytes,
        used_bytes: info.used_bytes,
        available_bytes: info.available_bytes,
        used_percent,
        wear_level_percent: info.wear_level_percent,
        temperature_celsius: info.temperature_celsius,
        power_on_hours: info.power_on_hours,
        health_status,
        smart_available: info.smart_available,
    })
}

pub fn directory_size_bytes(path: &Path) -> Result<u64, StorageError> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        return Ok(file_size_bytes(path));
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        if child.is_dir() {
            total = total.saturating_add(directory_size_bytes(&child)?);
        } else {
            total = total.saturating_add(file_size_bytes(&child));
        }
    }
    Ok(total)
}

pub(crate) fn detected_capacity_bytes() -> Result<u64, StorageError> {
    Ok(platform_drive_info()?.capacity_bytes)
}

fn evaluate_health_status(
    available_bytes: u64,
    warn_free_space_gb: u64,
    critical_free_space_gb: u64,
    wear_level_percent: Option<f64>,
) -> HealthStatus {
    let available_gb = available_bytes / 1_000_000_000;
    if available_gb < critical_free_space_gb {
        return HealthStatus::Critical {
            reason: format!(
                "only {available_gb} GB free (critical threshold: {critical_free_space_gb} GB)"
            ),
        };
    }
    if available_gb < warn_free_space_gb {
        return HealthStatus::Warning {
            reason: format!("only {available_gb} GB free (warning threshold: {warn_free_space_gb} GB)"),
        };
    }
    if let Some(wear) = wear_level_percent
        && wear >= 95.0
    {
        return HealthStatus::Critical {
            reason: format!("wear level is {wear:.1}%"),
        };
    }
    if let Some(wear) = wear_level_percent
        && wear >= 85.0
    {
        return HealthStatus::Warning {
            reason: format!("wear level is {wear:.1}%"),
        };
    }
    HealthStatus::Healthy
}

#[cfg(test)]
mod tests {
    use super::directory_size_bytes;
    use std::fs;

    #[test]
    fn directory_size_bytes_counts_nested_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("nested")).expect("nested");
        fs::write(temp.path().join("a.txt"), [0u8; 4]).expect("write");
        fs::write(temp.path().join("nested/b.txt"), [0u8; 6]).expect("write");
        let size = directory_size_bytes(temp.path()).expect("size");
        assert_eq!(size, 10);
    }
}
