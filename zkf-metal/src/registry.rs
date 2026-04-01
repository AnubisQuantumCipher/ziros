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

//! Registration of Metal GPU accelerators into the global AcceleratorRegistry.
//!
//! Call `register_metal_accelerators()` once at initialization to make Metal
//! GPU implementations discoverable via `zkf_core::acceleration::accelerator_registry()`.

use zkf_core::acceleration::{
    ConstraintEvalAccelerator, FieldOpsAccelerator, FriAccelerator, HashAccelerator,
    PolyOpsAccelerator, Poseidon2Accelerator, accelerator_registry,
};
use zkf_core::{ZkfError, ZkfResult};

use crate::constraint_eval::MetalConstraintEval;
use crate::device;
use crate::field_ops::MetalFieldOps;
use crate::fri::MetalFri;
use crate::hash::MetalHasher;
use crate::msm::MetalMsmAccelerator;
use crate::ntt::MetalNttAccelerator;
use crate::poly::MetalPolyOps;
use crate::poseidon2::MetalPoseidon2;

/// Metal GPU hash accelerator wrapping `MetalHasher`.
pub struct MetalHashAccelerator {
    hasher: MetalHasher,
}

impl HashAccelerator for MetalHashAccelerator {
    fn name(&self) -> &str {
        "metal-hash"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn batch_sha256(&self, inputs: &[u8], input_len: usize) -> ZkfResult<Vec<u8>> {
        self.hasher
            .batch_sha256(inputs, input_len)
            .ok_or_else(|| ZkfError::Backend("Metal SHA-256 dispatch failed".to_string()))
    }

    fn batch_keccak256(&self, inputs: &[u8], input_len: usize) -> ZkfResult<Vec<u8>> {
        self.hasher
            .batch_keccak256(inputs, input_len)
            .ok_or_else(|| ZkfError::Backend("Metal Keccak-256 dispatch failed".to_string()))
    }
}

/// Metal GPU Poseidon2 accelerator wrapping `MetalPoseidon2`.
pub struct MetalPoseidon2Accelerator {
    poseidon2: MetalPoseidon2,
}

impl Poseidon2Accelerator for MetalPoseidon2Accelerator {
    fn name(&self) -> &str {
        "metal-poseidon2"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn batch_permute_goldilocks(
        &self,
        states: &mut [u64],
        round_constants: &[u64],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> ZkfResult<()> {
        if self.poseidon2.batch_permute_goldilocks(
            states,
            round_constants,
            n_external_rounds,
            n_internal_rounds,
        ) {
            Ok(())
        } else {
            Err(ZkfError::Backend(
                "Metal Poseidon2 Goldilocks dispatch failed".to_string(),
            ))
        }
    }

    fn batch_permute_babybear(
        &self,
        states: &mut [u32],
        round_constants: &[u32],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> ZkfResult<()> {
        if self.poseidon2.batch_permute_babybear(
            states,
            round_constants,
            n_external_rounds,
            n_internal_rounds,
        ) {
            Ok(())
        } else {
            Err(ZkfError::Backend(
                "Metal Poseidon2 BabyBear dispatch failed".to_string(),
            ))
        }
    }
}

/// Metal GPU field ops accelerator wrapping `MetalFieldOps`.
pub struct MetalFieldOpsAccelerator {
    field_ops: MetalFieldOps,
}

impl FieldOpsAccelerator for MetalFieldOpsAccelerator {
    fn name(&self) -> &str {
        "metal-field-ops"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn batch_add_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()> {
        if self.field_ops.batch_add_goldilocks(a, b) {
            Ok(())
        } else {
            Err(ZkfError::Backend(
                "Metal batch add Goldilocks dispatch failed".to_string(),
            ))
        }
    }

    fn batch_mul_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()> {
        if self.field_ops.batch_mul_goldilocks(a, b) {
            Ok(())
        } else {
            Err(ZkfError::Backend(
                "Metal batch mul Goldilocks dispatch failed".to_string(),
            ))
        }
    }

    fn batch_sub_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()> {
        if self.field_ops.batch_sub_goldilocks(a, b) {
            Ok(())
        } else {
            Err(ZkfError::Backend(
                "Metal batch sub Goldilocks dispatch failed".to_string(),
            ))
        }
    }
}

/// Metal GPU poly ops accelerator wrapping `MetalPolyOps`.
pub struct MetalPolyOpsAccelerator {
    poly_ops: MetalPolyOps,
}

impl PolyOpsAccelerator for MetalPolyOpsAccelerator {
    fn name(&self) -> &str {
        "metal-poly-ops"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn batch_eval_goldilocks(&self, coeffs: &[u64], points: &[u64]) -> ZkfResult<Vec<u64>> {
        self.poly_ops
            .batch_eval_goldilocks(coeffs, points)
            .ok_or_else(|| ZkfError::Backend("Metal poly eval dispatch failed".to_string()))
    }

    fn coset_eval_goldilocks(&self, coeffs: &[u64], shift: u64, log_n: u32) -> ZkfResult<Vec<u64>> {
        self.poly_ops
            .coset_eval_goldilocks(coeffs, shift, log_n)
            .ok_or_else(|| {
                ZkfError::Backend("Metal coset eval Goldilocks dispatch failed".to_string())
            })
    }

    fn quotient_goldilocks(&self, evals: &[u64], z: u64, f_z: u64) -> ZkfResult<Vec<u64>> {
        self.poly_ops
            .quotient_goldilocks(evals, z, f_z)
            .ok_or_else(|| ZkfError::Backend("Metal quotient dispatch failed".to_string()))
    }
}

/// Metal GPU FRI accelerator wrapping `MetalFri`.
pub struct MetalFriAccelerator {
    fri: MetalFri,
}

impl FriAccelerator for MetalFriAccelerator {
    fn name(&self) -> &str {
        "metal-fri"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn fold_goldilocks(
        &self,
        evals: &[u64],
        alpha: u64,
        inv_twiddles: &[u64],
    ) -> ZkfResult<Vec<u64>> {
        self.fri
            .fold_goldilocks(evals, alpha, inv_twiddles)
            .ok_or_else(|| ZkfError::Backend("Metal FRI fold dispatch failed".to_string()))
    }
}

/// Metal GPU constraint eval accelerator wrapping `MetalConstraintEval`.
pub struct MetalConstraintEvalAccelerator {
    constraint_eval: MetalConstraintEval,
}

impl ConstraintEvalAccelerator for MetalConstraintEvalAccelerator {
    fn name(&self) -> &str {
        "metal-constraint-eval"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn eval_trace_goldilocks(
        &self,
        trace: &[u64],
        width: usize,
        bytecode: &[u32],
        constants: &[u64],
        n_constraints: usize,
    ) -> ZkfResult<Vec<u64>> {
        self.constraint_eval
            .eval_trace_goldilocks(trace, width, bytecode, constants, n_constraints)
            .ok_or_else(|| ZkfError::Backend("Metal constraint eval dispatch failed".to_string()))
    }
}

/// Register all available Metal GPU accelerators in the global registry at priority 0.
///
/// This should be called once during application initialization. If Metal GPU
/// is unavailable (no GPU, disabled via `ZKF_METAL=0`, or non-macOS), this
/// is a no-op.
pub fn register_metal_accelerators() {
    if device::is_disabled_by_env() {
        return;
    }

    let ctx = match device::global_context() {
        Some(c) => c,
        None => return,
    };
    let warmed = crate::prewarm_default_pipelines();

    let mut reg = match accelerator_registry().lock() {
        Ok(r) => r,
        Err(_) => return,
    };

    // Register MSM at priority 0 (highest)
    if let Some(msm) = MetalMsmAccelerator::new() {
        reg.register_msm(0, Box::new(msm));
        log::info!("[zkf-metal] Registered metal-msm-bn254 in AcceleratorRegistry");
    }

    // Register NTT at priority 0
    if let Some(ntt) = MetalNttAccelerator::new() {
        reg.register_ntt(0, Box::new(ntt));
        log::info!("[zkf-metal] Registered metal-ntt in AcceleratorRegistry");
    }

    // Register Hash accelerator at priority 0
    if let Some(hasher) = MetalHasher::new() {
        reg.register_hash(0, Box::new(MetalHashAccelerator { hasher }));
        log::info!("[zkf-metal] Registered metal-hash in AcceleratorRegistry");
    }

    // Register Poseidon2 accelerator at priority 0
    if let Some(poseidon2) = MetalPoseidon2::new() {
        reg.register_poseidon2(0, Box::new(MetalPoseidon2Accelerator { poseidon2 }));
        log::info!("[zkf-metal] Registered metal-poseidon2 in AcceleratorRegistry");
    }

    // Register Field Ops accelerator at priority 0
    if let Some(field_ops) = MetalFieldOps::new() {
        reg.register_field_ops(0, Box::new(MetalFieldOpsAccelerator { field_ops }));
        log::info!("[zkf-metal] Registered metal-field-ops in AcceleratorRegistry");
    }

    // Register Poly Ops accelerator at priority 0
    if let Some(poly_ops) = MetalPolyOps::new() {
        reg.register_poly_ops(0, Box::new(MetalPolyOpsAccelerator { poly_ops }));
        log::info!("[zkf-metal] Registered metal-poly-ops in AcceleratorRegistry");
    }

    // Register FRI accelerator at priority 0
    if let Some(fri) = MetalFri::new() {
        reg.register_fri(0, Box::new(MetalFriAccelerator { fri }));
        log::info!("[zkf-metal] Registered metal-fri in AcceleratorRegistry");
    }

    // Register Constraint Eval accelerator at priority 0
    if let Some(constraint_eval) = MetalConstraintEval::new() {
        reg.register_constraint_eval(
            0,
            Box::new(MetalConstraintEvalAccelerator { constraint_eval }),
        );
        log::info!("[zkf-metal] Registered metal-constraint-eval in AcceleratorRegistry");
    }

    log::info!("[zkf-metal] Prewarmed {warmed} Metal pipelines");
    let _ = ctx; // used to ensure context is alive
}
