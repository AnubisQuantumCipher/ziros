use crate::StorageError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PlatformDriveInfo {
    pub device_name: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub wear_level_percent: Option<f64>,
    pub temperature_celsius: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub smart_available: bool,
}

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;

pub(crate) fn platform_drive_info() -> Result<PlatformDriveInfo, StorageError> {
    #[cfg(target_os = "macos")]
    {
        macos::platform_drive_info()
    }
    #[cfg(target_os = "linux")]
    {
        linux::platform_drive_info()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(StorageError::UnsupportedPlatform("storage health"))
    }
}
