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

#![allow(unexpected_cfgs)]

//! Metal GPU acceleration for ZK proving operations.
//!
//! This crate provides Metal-accelerated implementations of the core
//! ZK proving bottlenecks: MSM, NTT, and Poseidon2 hashing.
//!
//! # Feature gating
//!
//! All Metal code is gated behind `cfg(target_os = "macos")`. On non-macOS
//! platforms, this crate compiles but provides no functionality.
//!
//! # Architecture
//!
//! Uses Apple's Metal API via `objc2-metal` bindings. Key advantages on M4 Max:
//! - **Unified memory**: Zero-copy buffer sharing between CPU and GPU
//! - **40 GPU cores**: Massive parallelism for bucket sort, butterflies, and hashing
//! - **Native u64**: M4 Max GPU supports 64-bit integer operations
//!
//! # Usage
//!
//! ```rust,ignore
//! use zkf_metal::MetalContext;
//!
//! if let Some(ctx) = zkf_metal::global_context() {
//!     println!("Metal GPU: {}", ctx.device_name());
//! }
//! ```

#[cfg(target_os = "macos")]
pub mod async_dispatch;
#[cfg(target_os = "macos")]
pub mod batch_prover;
#[cfg(target_os = "macos")]
pub mod constraint_eval;
#[cfg(target_os = "macos")]
pub mod device;
#[cfg(target_os = "macos")]
pub mod field_ops;
#[cfg(target_os = "macos")]
pub mod fri;
#[cfg(target_os = "macos")]
pub mod hash;
#[cfg(target_os = "macos")]
pub mod launch_contracts;
#[cfg(target_os = "macos")]
pub mod merkle;
#[cfg(target_os = "macos")]
pub mod metal4;
#[cfg(target_os = "macos")]
pub mod msm;
#[cfg(target_os = "macos")]
pub mod ntt;
#[cfg(target_os = "macos")]
pub mod pipeline;
#[cfg(target_os = "macos")]
pub mod poly;
#[cfg(target_os = "macos")]
pub mod poseidon2;
#[cfg(target_os = "macos")]
pub mod proof_ir;
#[cfg(target_os = "macos")]
pub mod registry;
#[cfg(target_os = "macos")]
pub mod shader_library;
#[cfg(target_os = "macos")]
pub mod tuning;
#[cfg(kani)]
#[cfg(target_os = "macos")]
mod verification_kani;
#[cfg(target_os = "macos")]
pub mod verified_artifacts;

// Re-export key types for convenience
#[cfg(target_os = "macos")]
pub use batch_prover::{BatchProver, GpuSchedulerHint, recommend_job_count};
#[cfg(target_os = "macos")]
pub use constraint_eval::MetalConstraintEval;
#[cfg(target_os = "macos")]
pub use device::{MetalContext, MetalDiagnostics, global_context, is_disabled_by_env};
#[cfg(target_os = "macos")]
pub use field_ops::MetalFieldOps;
#[cfg(target_os = "macos")]
pub use fri::MetalFri;
#[cfg(target_os = "macos")]
pub use hash::MetalHasher;
#[cfg(target_os = "macos")]
pub use merkle::MetalMerkleBuilder;
#[cfg(target_os = "macos")]
pub use metal4::{
    MetalCapabilities, detect_capabilities as detect_metal4_capabilities, is_metal4_available,
};
#[cfg(target_os = "macos")]
pub use msm::MetalMsmAccelerator;
#[cfg(target_os = "macos")]
pub use msm::try_metal_pallas_msm;
#[cfg(target_os = "macos")]
pub use msm::try_metal_vesta_msm;
#[cfg(target_os = "macos")]
pub use ntt::MetalNttAccelerator;
#[cfg(target_os = "macos")]
pub use ntt::bn254::MetalBn254Ntt;
#[cfg(target_os = "macos")]
pub use ntt::p3_adapter::MetalDft;
#[cfg(target_os = "macos")]
pub use pipeline::GpuPipeline;
#[cfg(target_os = "macos")]
pub use poly::MetalPolyOps;
#[cfg(target_os = "macos")]
pub use poseidon2::MetalPoseidon2;
#[cfg(target_os = "macos")]
pub use registry::register_metal_accelerators;
#[cfg(target_os = "macos")]
pub use tuning::{
    DeviceTuning, ThresholdConfig, ThroughputConfig, clear_learned_thresholds,
    clear_runtime_threshold_override, current_device_tuning, current_threshold_profile_name,
    current_thresholds, current_throughput_config, set_learned_thresholds,
    set_runtime_threshold_override, threshold_profile_for_platform, throughput_for_device,
    tuning_for_device, tuning_for_platform,
};
#[cfg(target_os = "macos")]
pub use verified_artifacts::{ExpectedKernelAttestation, ToolchainIdentity};

/// Check if Metal GPU acceleration is available on this system.
#[cfg(target_os = "macos")]
pub fn is_available() -> bool {
    global_context().is_some()
}

#[cfg(not(target_os = "macos"))]
pub fn is_available() -> bool {
    false
}

/// Get the Metal GPU device name, if available.
#[cfg(target_os = "macos")]
pub fn device_name() -> Option<String> {
    global_context().map(|ctx| ctx.device_name())
}

#[cfg(not(target_os = "macos"))]
pub fn device_name() -> Option<String> {
    None
}

/// Returns how this build loads Metal shader libraries.
#[cfg(target_os = "macos")]
pub fn metallib_mode() -> Option<&'static str> {
    if !is_available() {
        return None;
    }
    Some(if cfg!(metal_aot) { "aot" } else { "runtime" })
}

#[cfg(not(target_os = "macos"))]
pub fn metallib_mode() -> Option<&'static str> {
    None
}

/// Warm the common pipeline cache entries up front so the first proof avoids
/// per-kernel pipeline creation on the critical path.
#[cfg(target_os = "macos")]
pub fn prewarm_default_pipelines() -> usize {
    use std::sync::OnceLock;

    static WARMED: OnceLock<usize> = OnceLock::new();

    *WARMED.get_or_init(|| {
        let Some(ctx) = global_context() else {
            return 0;
        };

        let mut warmed = 0usize;
        let main_kernels = [
            shader_library::kernels::NTT_BUTTERFLY_GOLDILOCKS,
            shader_library::kernels::NTT_BUTTERFLY_BABYBEAR,
            shader_library::kernels::NTT_BUTTERFLY_BN254,
            shader_library::kernels::NTT_HYBRID_BN254,
            shader_library::kernels::POSEIDON2_GOLDILOCKS,
            shader_library::kernels::POSEIDON2_BABYBEAR,
            shader_library::kernels::POLY_BATCH_EVAL_GOLDILOCKS,
            shader_library::kernels::FRI_FOLD_GOLDILOCKS,
            shader_library::kernels::CONSTRAINT_EVAL_GOLDILOCKS,
        ];

        for kernel in main_kernels {
            if ctx.pipeline(kernel).is_some() {
                warmed += 1;
            }
        }

        if let Some(msm_library) = ctx.msm_library() {
            for kernel in [
                shader_library::msm_kernels::BUCKET_ASSIGN,
                shader_library::msm_kernels::BUCKET_ACC,
                shader_library::msm_kernels::WINDOW_COMBINE,
            ] {
                if ctx.pipeline_from_library(msm_library, kernel).is_some() {
                    warmed += 1;
                }
            }
        }

        if let Some(hash_library) = ctx.hash_library() {
            for kernel in [
                shader_library::kernels::BATCH_SHA256,
                shader_library::kernels::BATCH_KECCAK256,
            ] {
                if ctx.pipeline_from_library(hash_library, kernel).is_some() {
                    warmed += 1;
                }
            }
        }

        warmed
    })
}

#[cfg(not(target_os = "macos"))]
pub fn prewarm_default_pipelines() -> usize {
    0
}
