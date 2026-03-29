//! Metal 4 integration — experimental, feature-gated support for Apple's next-generation GPU API.
//!
//! Metal 4 features (WWDC 2025):
//! - MTL4ComputeCommandEncoder: unified encoder with improved parallel dispatch
//! - Native tensor support in MSL for MSM/NTT acceleration
//! - Parallel command encoding across threads
//! - Explicit MTL4CommandAllocator for memory control
//! - Residency sets for explicit memory management
//! - Barrier API for fine-grained synchronization
//! - Shared Metal IR for compilation reuse
//!
//! Requires: M1+ / A14+, macOS 26+ / iOS 19+.
//!
//! This module is explicitly experimental and is not counted in production
//! readiness claims. When the `metal4` feature is not enabled, the exported
//! helpers report Metal 4 as unavailable and the runtime stays on the
//! production Metal 3 path.

#[cfg(all(target_os = "macos", feature = "metal4"))]
pub mod barrier;
#[cfg(all(target_os = "macos", feature = "metal4"))]
pub mod residency;
#[cfg(all(target_os = "macos", feature = "metal4"))]
pub mod tensor_msm;
#[cfg(all(target_os = "macos", feature = "metal4"))]
pub mod unified_encoder;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::process::Command;

/// Metal capabilities detected at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetalCapabilities {
    /// Detected Metal version (3 or 4).
    pub metal_version: u32,
    /// Whether Metal 4 tensor operations are available.
    pub supports_tensors: bool,
    /// Whether parallel command encoding is available.
    pub supports_parallel_encoding: bool,
    /// Number of GPU compute cores.
    pub gpu_cores: Option<u32>,
    /// Unified memory size in bytes.
    pub unified_memory_bytes: Option<u64>,
    /// Maximum buffer allocation size.
    pub max_buffer_length: Option<u64>,
}

impl Default for MetalCapabilities {
    fn default() -> Self {
        Self {
            metal_version: 3,
            supports_tensors: false,
            supports_parallel_encoding: false,
            gpu_cores: None,
            unified_memory_bytes: None,
            max_buffer_length: None,
        }
    }
}

/// Detect Metal capabilities at runtime.
#[cfg(target_os = "macos")]
pub fn detect_capabilities() -> MetalCapabilities {
    let mut caps = MetalCapabilities::default();

    if let Some(ctx) = crate::global_context() {
        let os_major = host_macos_major_version().unwrap_or_default();
        let device_name = ctx.device_name();
        let metal4_runtime = os_major >= 26;
        let tensor_capable = device_name.contains("M4")
            || device_name.contains("M5")
            || device_name.contains("Ultra");

        caps.metal_version = if metal4_runtime { 4 } else { 3 };
        caps.supports_parallel_encoding = metal4_runtime;
        caps.supports_tensors = metal4_runtime && tensor_capable;
        caps.max_buffer_length = Some(ctx.max_buffer_length() as u64);
        caps.unified_memory_bytes = host_memory_bytes()
            .or_else(|| ctx.recommended_working_set_size().map(|bytes| bytes as u64));
    }

    caps
}

#[cfg(not(target_os = "macos"))]
pub fn detect_capabilities() -> MetalCapabilities {
    MetalCapabilities::default()
}

/// Check if Metal 4 features are available at runtime.
pub fn is_metal4_available() -> bool {
    #[cfg(all(target_os = "macos", feature = "metal4"))]
    {
        let caps = detect_capabilities();
        caps.metal_version >= 4 && caps.supports_parallel_encoding
    }
    #[cfg(not(all(target_os = "macos", feature = "metal4")))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn host_macos_major_version() -> Option<u32> {
    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_major_version(std::str::from_utf8(&output.stdout).ok()?.trim())
}

#[cfg(target_os = "macos")]
fn host_memory_bytes() -> Option<u64> {
    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn parse_major_version(value: &str) -> Option<u32> {
    value.split('.').next()?.parse().ok()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_major_version_accepts_standard_strings() {
        assert_eq!(parse_major_version("26.0"), Some(26));
        assert_eq!(parse_major_version("15.4.1"), Some(15));
        assert_eq!(parse_major_version("bogus"), None);
    }
}
