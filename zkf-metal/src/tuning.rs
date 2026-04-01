// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Runtime threshold selection based on GPU device capabilities.
//!
//! M4 Max (40 GPU cores, ~2us dispatch overhead) can profitably handle smaller
//! batch sizes than older chips. This module queries the device name at init
//! and returns appropriate thresholds.

use std::sync::{OnceLock, RwLock};
use zkf_core::{AppleChipFamily, DeviceFormFactor, PlatformCapability};

/// GPU dispatch thresholds for each operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ThresholdConfig {
    pub msm: usize,
    pub ntt: usize,
    pub poseidon2: usize,
    pub field_ops: usize,
    pub merkle: usize,
}

/// Thresholds for dispatching between GPU, CpuCrypto, CpuSme, and scalar CPU.
/// Below `gpu_*` threshold → use CpuCrypto/CpuSme instead of GPU.
/// Below `cpu_accel_*` threshold → use scalar CPU instead of CpuCrypto/CpuSme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MultiDeviceThresholdConfig {
    /// Below this, SHA/Keccak batches go to CpuCrypto instead of GPU.
    pub crypto_hash_gpu_threshold: usize,
    /// Below this, hash batches go to scalar CPU instead of CpuCrypto.
    pub crypto_hash_min_threshold: usize,
    /// Below this, field ops go to CpuSme instead of GPU.
    pub sme_field_gpu_threshold: usize,
    /// Below this, field ops go to scalar CPU instead of CpuSme.
    pub sme_field_min_threshold: usize,
}

impl MultiDeviceThresholdConfig {
    pub const DEFAULT: Self = Self {
        crypto_hash_gpu_threshold: 256,
        crypto_hash_min_threshold: 1,
        sme_field_gpu_threshold: 4096,
        sme_field_min_threshold: 16,
    };

    pub const AGGRESSIVE: Self = Self {
        crypto_hash_gpu_threshold: 512,
        crypto_hash_min_threshold: 1,
        sme_field_gpu_threshold: 8192,
        sme_field_min_threshold: 4,
    };
}

/// Throughput-oriented scheduling knobs for a Metal device profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ThroughputConfig {
    pub primary_queue_depth: usize,
    pub secondary_queue_depth: usize,
    pub pipeline_max_in_flight: usize,
    pub batch_profile_cap: usize,
    /// Desired fraction of available working-set headroom to use for GPU job scheduling.
    pub working_set_headroom_target_pct: u8,
}

/// Full Metal tuning profile for a device class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct DeviceTuning {
    pub thresholds: ThresholdConfig,
    pub throughput: ThroughputConfig,
}

impl ThresholdConfig {
    /// Conservative defaults (original values, safe for any Apple Silicon).
    pub const CONSERVATIVE: Self = Self {
        msm: 1 << 14, // 16,384
        ntt: 1 << 12, // 4,096
        poseidon2: 1_000,
        field_ops: 10_000,
        merkle: 2_048,
    };

    /// Moderate thresholds for M3 Max / M4 Pro class chips.
    pub const MODERATE: Self = Self {
        msm: 1 << 13, // 8,192
        ntt: 1 << 11, // 2,048
        poseidon2: 750,
        field_ops: 6_000,
        merkle: 1_536,
    };

    /// Aggressive thresholds for M4 Max (40 GPU cores, ~2us dispatch).
    pub const AGGRESSIVE: Self = Self {
        msm: 1 << 9, // 512
        ntt: 1 << 9, // 512
        poseidon2: 256,
        field_ops: 2_048,
        merkle: 512,
    };
}

impl ThroughputConfig {
    pub const CONSERVATIVE: Self = Self {
        primary_queue_depth: 8,
        secondary_queue_depth: 4,
        pipeline_max_in_flight: 3,
        batch_profile_cap: 4,
        working_set_headroom_target_pct: 70,
    };

    pub const MODERATE: Self = Self {
        primary_queue_depth: 12,
        secondary_queue_depth: 6,
        pipeline_max_in_flight: 4,
        batch_profile_cap: 8,
        working_set_headroom_target_pct: 80,
    };

    pub const AGGRESSIVE: Self = Self {
        primary_queue_depth: 24,
        secondary_queue_depth: 12,
        pipeline_max_in_flight: 8,
        batch_profile_cap: 16,
        working_set_headroom_target_pct: 85,
    };
}

impl DeviceTuning {
    pub const CONSERVATIVE: Self = Self {
        thresholds: ThresholdConfig::CONSERVATIVE,
        throughput: ThroughputConfig::CONSERVATIVE,
    };

    pub const MODERATE: Self = Self {
        thresholds: ThresholdConfig::MODERATE,
        throughput: ThroughputConfig::MODERATE,
    };

    pub const AGGRESSIVE: Self = Self {
        thresholds: ThresholdConfig::AGGRESSIVE,
        throughput: ThroughputConfig::AGGRESSIVE,
    };
}

/// Select thresholds based on GPU device name.
pub fn thresholds_for_device(name: &str) -> ThresholdConfig {
    tuning_for_device(name).thresholds
}

/// Select throughput knobs based on GPU device name.
pub fn throughput_for_device(name: &str) -> ThroughputConfig {
    tuning_for_device(name).throughput
}

/// Select the full tuning profile based on GPU device name.
pub fn tuning_for_device(name: &str) -> DeviceTuning {
    let platform = PlatformCapability {
        identity: zkf_core::PlatformIdentity {
            chip_family: if name.contains("M4") {
                AppleChipFamily::M4
            } else if name.contains("M3") {
                AppleChipFamily::M3
            } else if name.contains("M2") {
                AppleChipFamily::M2
            } else if name.contains("M1") {
                AppleChipFamily::M1
            } else {
                AppleChipFamily::UnknownApple
            },
            form_factor: DeviceFormFactor::Unknown,
            neural_engine: zkf_core::NeuralEngineCapability {
                available: true,
                tops: None,
                core_count: None,
            },
            gpu: zkf_core::GpuCapability {
                core_count: Some(infer_gpu_cores_from_device_name(name)),
                family: None,
            },
            crypto_extensions: zkf_core::CryptoExtensions::default(),
            unified_memory: true,
            total_ram_bytes: 0,
            model_identifier: None,
            machine_name: None,
            raw_chip_name: Some(name.to_string()),
        },
        thermal_envelope: zkf_core::ThermalEnvelope::default(),
    };
    tuning_for_platform(&platform)
}

/// Return a human-readable threshold profile name for a Metal device.
pub fn threshold_profile_for_device(name: &str) -> &'static str {
    match tuning_for_device(name) {
        DeviceTuning::AGGRESSIVE => "aggressive",
        DeviceTuning::MODERATE => "moderate",
        DeviceTuning::CONSERVATIVE => "conservative",
        _ => "conservative",
    }
}

/// Infer approximate GPU core count from a Metal device name string.
/// Used as fallback when we only have the device name, not full platform detection.
fn infer_gpu_cores_from_device_name(name: &str) -> u32 {
    if name.contains("Ultra") {
        64
    } else if name.contains("Max") {
        40
    } else if name.contains("Pro") {
        18
    } else {
        10
    }
}

pub fn tuning_for_platform(platform: &PlatformCapability) -> DeviceTuning {
    let gpu_cores = platform.identity.gpu.core_count.unwrap_or_default();
    match platform.identity.chip_family {
        AppleChipFamily::M4 if gpu_cores >= 32 => DeviceTuning::AGGRESSIVE,
        AppleChipFamily::M4 => DeviceTuning::MODERATE,
        AppleChipFamily::M3 if gpu_cores >= 18 => DeviceTuning::MODERATE,
        AppleChipFamily::M2 if gpu_cores >= 16 => DeviceTuning::MODERATE,
        AppleChipFamily::M1 if gpu_cores >= 16 => DeviceTuning::MODERATE,
        AppleChipFamily::A17Pro
        | AppleChipFamily::A18
        | AppleChipFamily::A18Pro
        | AppleChipFamily::VisionPro
            if matches!(
                platform.identity.form_factor,
                DeviceFormFactor::Mobile | DeviceFormFactor::Headset
            ) =>
        {
            DeviceTuning::CONSERVATIVE
        }
        _ => DeviceTuning::CONSERVATIVE,
    }
}

pub fn threshold_profile_for_platform(platform: &PlatformCapability) -> &'static str {
    match tuning_for_platform(platform) {
        DeviceTuning::AGGRESSIVE => "aggressive",
        DeviceTuning::MODERATE => "moderate",
        DeviceTuning::CONSERVATIVE => "conservative",
        _ => "conservative",
    }
}

/// Cached global tuning profile, initialized from the Metal device name.
static TUNING: std::sync::OnceLock<DeviceTuning> = std::sync::OnceLock::new();
static RUNTIME_THRESHOLD_OVERRIDE: OnceLock<RwLock<Option<ThresholdConfig>>> = OnceLock::new();
static LEARNED_THRESHOLDS: OnceLock<RwLock<Option<ThresholdConfig>>> = OnceLock::new();

fn runtime_override_store() -> &'static RwLock<Option<ThresholdConfig>> {
    RUNTIME_THRESHOLD_OVERRIDE.get_or_init(|| RwLock::new(None))
}

fn learned_threshold_store() -> &'static RwLock<Option<ThresholdConfig>> {
    LEARNED_THRESHOLDS.get_or_init(|| RwLock::new(None))
}

pub fn set_runtime_threshold_override(config: ThresholdConfig) {
    if let Ok(mut guard) = runtime_override_store().write() {
        *guard = Some(config);
    }
}

pub fn clear_runtime_threshold_override() {
    if let Ok(mut guard) = runtime_override_store().write() {
        *guard = None;
    }
}

pub fn set_learned_thresholds(config: ThresholdConfig) {
    if let Ok(mut guard) = learned_threshold_store().write() {
        *guard = Some(config);
    }
}

pub fn clear_learned_thresholds() {
    if let Ok(mut guard) = learned_threshold_store().write() {
        *guard = None;
    }
}

fn static_thresholds_disabled() -> bool {
    matches!(
        std::env::var("ZKF_STATIC_THRESHOLDS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Get the cached tuning profile for the current device.
pub fn current_device_tuning() -> &'static DeviceTuning {
    TUNING.get_or_init(|| {
        let platform = PlatformCapability::detect();
        let tuning = tuning_for_platform(&platform);
        if let Some(ctx) = crate::device::global_context() {
            let name = ctx.device_name();
            log::info!(
                "[zkf-metal] Tuning for '{}' ({}, gpu_cores={}): msm={}, ntt={}, poseidon2={}, field_ops={}, merkle={}, queues={}/{}, pipeline={}, batch_cap={}, headroom_target={}%",
                name,
                platform.identity.chip_family.as_str(),
                platform.identity.gpu.core_count.unwrap_or_default(),
                tuning.thresholds.msm,
                tuning.thresholds.ntt,
                tuning.thresholds.poseidon2,
                tuning.thresholds.field_ops,
                tuning.thresholds.merkle,
                tuning.throughput.primary_queue_depth,
                tuning.throughput.secondary_queue_depth,
                tuning.throughput.pipeline_max_in_flight,
                tuning.throughput.batch_profile_cap,
                tuning.throughput.working_set_headroom_target_pct
            );
            tuning
        } else {
            tuning
        }
    })
}

/// Get the cached threshold config for the current device.
/// Falls back to conservative if no Metal device is available.
pub fn current_thresholds() -> ThresholdConfig {
    let base = current_device_tuning().thresholds;
    if static_thresholds_disabled() {
        return base;
    }
    if let Ok(guard) = runtime_override_store().read()
        && let Some(config) = *guard
    {
        return config;
    }
    if let Ok(guard) = learned_threshold_store().read()
        && let Some(config) = *guard
    {
        return config;
    }
    base
}

/// Get the cached throughput config for the current device.
pub fn current_throughput_config() -> &'static ThroughputConfig {
    &current_device_tuning().throughput
}

/// Get the threshold profile name for the current Metal device.
pub fn current_threshold_profile_name() -> &'static str {
    threshold_profile_for_platform(&PlatformCapability::detect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m4_max_gets_aggressive() {
        let cfg = tuning_for_platform(&PlatformCapability {
            identity: zkf_core::PlatformIdentity {
                chip_family: AppleChipFamily::M4,
                form_factor: DeviceFormFactor::Laptop,
                neural_engine: zkf_core::NeuralEngineCapability {
                    available: true,
                    tops: Some(38.0),
                    core_count: Some(16),
                },
                gpu: zkf_core::GpuCapability {
                    core_count: Some(40),
                    family: None,
                },
                crypto_extensions: zkf_core::CryptoExtensions::default(),
                unified_memory: true,
                total_ram_bytes: 48 * 1024 * 1024 * 1024,
                model_identifier: None,
                machine_name: None,
                raw_chip_name: Some("Apple M4 Max".to_string()),
            },
            thermal_envelope: zkf_core::ThermalEnvelope::default(),
        })
        .thresholds;
        assert_eq!(cfg.msm, 1 << 9);
        assert_eq!(cfg.ntt, 1 << 9);
        assert_eq!(cfg.poseidon2, 256);
        assert_eq!(cfg.field_ops, 2_048);
        assert_eq!(cfg.merkle, 512);
    }

    #[test]
    fn m3_pro_gets_moderate() {
        let cfg = tuning_for_platform(&PlatformCapability {
            identity: zkf_core::PlatformIdentity {
                chip_family: AppleChipFamily::M3,
                form_factor: DeviceFormFactor::Laptop,
                neural_engine: zkf_core::NeuralEngineCapability {
                    available: true,
                    tops: Some(18.0),
                    core_count: Some(16),
                },
                gpu: zkf_core::GpuCapability {
                    core_count: Some(20),
                    family: None,
                },
                crypto_extensions: zkf_core::CryptoExtensions::default(),
                unified_memory: true,
                total_ram_bytes: 36 * 1024 * 1024 * 1024,
                model_identifier: None,
                machine_name: None,
                raw_chip_name: Some("Apple M3 Pro".to_string()),
            },
            thermal_envelope: zkf_core::ThermalEnvelope::default(),
        })
        .thresholds;
        assert_eq!(cfg.msm, 1 << 13);
        assert_eq!(cfg.ntt, 1 << 11);
    }

    #[test]
    fn unknown_gets_conservative() {
        let cfg = thresholds_for_device("Apple M1");
        assert_eq!(cfg.msm, 1 << 14);
        assert_eq!(cfg.ntt, 1 << 12);
        assert_eq!(cfg.poseidon2, 1_000);
    }

    #[test]
    fn current_thresholds_returns_valid() {
        let cfg = current_thresholds();
        assert!(cfg.msm > 0);
        assert!(cfg.ntt > 0);
    }

    #[test]
    fn runtime_override_beats_learned_and_static() {
        set_learned_thresholds(ThresholdConfig {
            msm: 100,
            ntt: 200,
            poseidon2: 300,
            field_ops: 400,
            merkle: 500,
        });
        set_runtime_threshold_override(ThresholdConfig {
            msm: 11,
            ntt: 22,
            poseidon2: 33,
            field_ops: 44,
            merkle: 55,
        });

        let cfg = current_thresholds();
        assert_eq!(cfg.msm, 11);
        assert_eq!(cfg.ntt, 22);

        clear_runtime_threshold_override();
        clear_learned_thresholds();
    }

    #[test]
    fn m4_max_gets_throughput_profile() {
        let cfg = tuning_for_platform(&PlatformCapability {
            identity: zkf_core::PlatformIdentity {
                chip_family: AppleChipFamily::M4,
                form_factor: DeviceFormFactor::Laptop,
                neural_engine: zkf_core::NeuralEngineCapability {
                    available: true,
                    tops: Some(38.0),
                    core_count: Some(16),
                },
                gpu: zkf_core::GpuCapability {
                    core_count: Some(40),
                    family: None,
                },
                crypto_extensions: zkf_core::CryptoExtensions::default(),
                unified_memory: true,
                total_ram_bytes: 48 * 1024 * 1024 * 1024,
                model_identifier: None,
                machine_name: None,
                raw_chip_name: Some("Apple M4 Max".to_string()),
            },
            thermal_envelope: zkf_core::ThermalEnvelope::default(),
        })
        .throughput;
        assert_eq!(cfg.primary_queue_depth, 24);
        assert_eq!(cfg.secondary_queue_depth, 12);
        assert_eq!(cfg.pipeline_max_in_flight, 8);
        assert_eq!(cfg.batch_profile_cap, 16);
        assert_eq!(cfg.working_set_headroom_target_pct, 85);
    }
}
