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

//! Metal-accelerated batch Poseidon2 hashing.

pub mod babybear;
pub mod goldilocks;

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::launch_contracts::{self, FieldFamily, Poseidon2ContractInput};
use crate::shader_library::kernels;
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Get the current Poseidon2 GPU threshold (device-adaptive).
fn gpu_poseidon2_threshold() -> usize {
    crate::tuning::current_thresholds().poseidon2
}

/// Metal batch Poseidon2 hasher.
pub struct MetalPoseidon2 {
    ctx: &'static MetalContext,
}

impl MetalPoseidon2 {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Batch-hash `n_perms` independent Poseidon2 permutations on GPU (Goldilocks).
    ///
    /// `states` is a flat array of `n_perms * 16` u64 field elements.
    /// Results are written back in-place.
    /// Returns `true` if GPU dispatch succeeded, `false` for CPU fallback.
    pub fn batch_permute_goldilocks(
        &self,
        states: &mut [u64],
        round_constants: &[u64],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> bool {
        let n_perms = states.len() / 16;
        if n_perms < gpu_poseidon2_threshold() || !states.len().is_multiple_of(16) {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernels::POSEIDON2_GOLDILOCKS) {
            Some(p) => p,
            None => return false,
        };
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let zero_copy_eligible = launch_contracts::page_aligned_for_zero_copy(states);
        if launch_contracts::poseidon2_contract(Poseidon2ContractInput {
            kernel: kernels::POSEIDON2_GOLDILOCKS,
            field: FieldFamily::Goldilocks,
            simd: false,
            state_elements: states.len(),
            round_constants: round_constants.len(),
            n_external_rounds,
            n_internal_rounds,
            element_bytes: std::mem::size_of::<u64>(),
            max_threads_per_group: max_tpg,
            requested_zero_copy: zero_copy_eligible,
            zero_copy_eligible,
        })
        .is_err()
        {
            return false;
        }

        // Try zero-copy first (requires page-aligned memory), fall back to copy
        let used_zero_copy;
        let states_buf = if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(states) } {
            used_zero_copy = true;
            b
        } else if let Some(b) = self.ctx.new_buffer_from_slice(states) {
            used_zero_copy = false;
            b
        } else {
            return false;
        };
        let rc_buf = match self.ctx.new_buffer_from_slice(round_constants) {
            Some(b) => b,
            None => return false,
        };
        let diag_buf = match self
            .ctx
            .new_buffer_from_slice(&goldilocks::MATRIX_DIAG_16_GOLDILOCKS)
        {
            Some(b) => b,
            None => return false,
        };

        let n_perms_u32 = n_perms as u32;

        let cmd = match self.ctx.command_buffer() {
            Some(c) => c,
            None => return false,
        };
        let enc = match cmd.computeCommandEncoder() {
            Some(e) => e,
            None => return false,
        };

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*states_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*rc_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_perms_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&n_external_rounds).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_internal_rounds).cast(), 4, 4);
            enc.setBuffer_offset_atIndex(Some(&*diag_buf), 0, 5);

            let num_groups = n_perms.div_ceil(max_tpg);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_tpg,
                    height: 1,
                    depth: 1,
                },
            );
        }

        enc.endEncoding();
        if async_dispatch::commit_and_wait(cmd, "poseidon2").is_err() {
            return false;
        }

        // Zero-copy: results already in states slice. Copy path: read back.
        if !used_zero_copy {
            let result: Vec<u64> = self.ctx.read_buffer(&states_buf, states.len());
            states.copy_from_slice(&result);
        }

        true
    }

    /// Batch-hash `n_perms` independent Poseidon2 permutations on GPU (BabyBear).
    ///
    /// `states` is a flat array of `n_perms * 16` u32 field elements.
    /// Results are written back in-place.
    /// Returns `true` if GPU dispatch succeeded, `false` for CPU fallback.
    pub fn batch_permute_babybear(
        &self,
        states: &mut [u32],
        round_constants: &[u32],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> bool {
        let n_perms = states.len() / 16;
        if n_perms < gpu_poseidon2_threshold() || !states.len().is_multiple_of(16) {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernels::POSEIDON2_BABYBEAR) {
            Some(p) => p,
            None => return false,
        };
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let zero_copy_eligible = launch_contracts::page_aligned_for_zero_copy(states);
        if launch_contracts::poseidon2_contract(Poseidon2ContractInput {
            kernel: kernels::POSEIDON2_BABYBEAR,
            field: FieldFamily::BabyBear,
            simd: false,
            state_elements: states.len(),
            round_constants: round_constants.len(),
            n_external_rounds,
            n_internal_rounds,
            element_bytes: std::mem::size_of::<u32>(),
            max_threads_per_group: max_tpg,
            requested_zero_copy: zero_copy_eligible,
            zero_copy_eligible,
        })
        .is_err()
        {
            return false;
        }

        // Try zero-copy first (requires page-aligned memory), fall back to copy
        let used_zero_copy;
        let states_buf = if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(states) } {
            used_zero_copy = true;
            b
        } else if let Some(b) = self.ctx.new_buffer_from_slice(states) {
            used_zero_copy = false;
            b
        } else {
            return false;
        };
        let rc_buf = match self.ctx.new_buffer_from_slice(round_constants) {
            Some(b) => b,
            None => return false,
        };
        let diag_buf = match self.ctx.new_buffer_from_slice(babybear::diagonal()) {
            Some(b) => b,
            None => return false,
        };

        let n_perms_u32 = n_perms as u32;

        let cmd = match self.ctx.command_buffer() {
            Some(c) => c,
            None => return false,
        };
        let enc = match cmd.computeCommandEncoder() {
            Some(e) => e,
            None => return false,
        };

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*states_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*rc_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_perms_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&n_external_rounds).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_internal_rounds).cast(), 4, 4);
            enc.setBuffer_offset_atIndex(Some(&*diag_buf), 0, 5);

            let num_groups = n_perms.div_ceil(max_tpg);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_tpg,
                    height: 1,
                    depth: 1,
                },
            );
        }

        enc.endEncoding();
        if async_dispatch::commit_and_wait(cmd, "poseidon2").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u32> = self.ctx.read_buffer(&states_buf, states.len());
            states.copy_from_slice(&result);
        }

        true
    }
    /// Batch-hash using the SIMD-cooperative Goldilocks Poseidon2 kernel.
    ///
    /// Uses 16 threads per permutation (one per state element) with SIMD
    /// shuffle-based reduction for the internal layer sum. Falls back to
    /// the scalar kernel if the SIMD pipeline is unavailable.
    pub fn batch_permute_goldilocks_simd(
        &self,
        states: &mut [u64],
        round_constants: &[u64],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> bool {
        let n_perms = states.len() / 16;
        if n_perms < gpu_poseidon2_threshold() || !states.len().is_multiple_of(16) {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernels::POSEIDON2_GOLDILOCKS_SIMD) {
            Some(p) => p,
            None => {
                return self.batch_permute_goldilocks(
                    states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
            }
        };
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let zero_copy_eligible = launch_contracts::page_aligned_for_zero_copy(states);
        if launch_contracts::poseidon2_contract(Poseidon2ContractInput {
            kernel: kernels::POSEIDON2_GOLDILOCKS_SIMD,
            field: FieldFamily::Goldilocks,
            simd: true,
            state_elements: states.len(),
            round_constants: round_constants.len(),
            n_external_rounds,
            n_internal_rounds,
            element_bytes: std::mem::size_of::<u64>(),
            max_threads_per_group: max_tpg,
            requested_zero_copy: zero_copy_eligible,
            zero_copy_eligible,
        })
        .is_err()
        {
            return false;
        }

        let used_zero_copy;
        let states_buf = if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(states) } {
            used_zero_copy = true;
            b
        } else if let Some(b) = self.ctx.new_buffer_from_slice(states) {
            used_zero_copy = false;
            b
        } else {
            return false;
        };
        let rc_buf = match self.ctx.new_buffer_from_slice(round_constants) {
            Some(b) => b,
            None => return false,
        };
        let diag_buf = match self
            .ctx
            .new_buffer_from_slice(&goldilocks::MATRIX_DIAG_16_GOLDILOCKS)
        {
            Some(b) => b,
            None => return false,
        };

        let n_perms_u32 = n_perms as u32;

        let cmd = match self.ctx.command_buffer() {
            Some(c) => c,
            None => return false,
        };
        let enc = match cmd.computeCommandEncoder() {
            Some(e) => e,
            None => return false,
        };

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*states_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*rc_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_perms_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&n_external_rounds).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_internal_rounds).cast(), 4, 4);
            enc.setBuffer_offset_atIndex(Some(&*diag_buf), 0, 5);

            // 16 threads per permutation
            let total_threads = n_perms * 16;
            let tpg = (max_tpg / 16) * 16;
            let num_groups = total_threads.div_ceil(tpg);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: tpg,
                    height: 1,
                    depth: 1,
                },
            );
        }

        enc.endEncoding();
        if async_dispatch::commit_and_wait(cmd, "poseidon2").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u64> = self.ctx.read_buffer(&states_buf, states.len());
            states.copy_from_slice(&result);
        }

        true
    }

    /// Batch-hash using the SIMD-cooperative BabyBear Poseidon2 kernel.
    ///
    /// Uses 16 threads per permutation (one per state element) with SIMD
    /// shuffle-based reduction for the internal layer sum. Falls back to
    /// the scalar kernel if the SIMD pipeline is unavailable.
    pub fn batch_permute_babybear_simd(
        &self,
        states: &mut [u32],
        round_constants: &[u32],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> bool {
        let n_perms = states.len() / 16;
        if n_perms < gpu_poseidon2_threshold() || !states.len().is_multiple_of(16) {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernels::POSEIDON2_BABYBEAR_SIMD) {
            Some(p) => p,
            None => {
                // Fall back to scalar kernel
                return self.batch_permute_babybear(
                    states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
            }
        };
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let zero_copy_eligible = launch_contracts::page_aligned_for_zero_copy(states);
        if launch_contracts::poseidon2_contract(Poseidon2ContractInput {
            kernel: kernels::POSEIDON2_BABYBEAR_SIMD,
            field: FieldFamily::BabyBear,
            simd: true,
            state_elements: states.len(),
            round_constants: round_constants.len(),
            n_external_rounds,
            n_internal_rounds,
            element_bytes: std::mem::size_of::<u32>(),
            max_threads_per_group: max_tpg,
            requested_zero_copy: zero_copy_eligible,
            zero_copy_eligible,
        })
        .is_err()
        {
            return false;
        }

        let used_zero_copy;
        let states_buf = if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(states) } {
            used_zero_copy = true;
            b
        } else if let Some(b) = self.ctx.new_buffer_from_slice(states) {
            used_zero_copy = false;
            b
        } else {
            return false;
        };
        let rc_buf = match self.ctx.new_buffer_from_slice(round_constants) {
            Some(b) => b,
            None => return false,
        };
        let diag_buf = match self.ctx.new_buffer_from_slice(babybear::diagonal()) {
            Some(b) => b,
            None => return false,
        };

        let n_perms_u32 = n_perms as u32;

        let cmd = match self.ctx.command_buffer() {
            Some(c) => c,
            None => return false,
        };
        let enc = match cmd.computeCommandEncoder() {
            Some(e) => e,
            None => return false,
        };

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*states_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*rc_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_perms_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&n_external_rounds).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_internal_rounds).cast(), 4, 4);
            enc.setBuffer_offset_atIndex(Some(&*diag_buf), 0, 5);

            // 16 threads per permutation
            let total_threads = n_perms * 16;
            // Round up to multiple of 16
            let tpg = (max_tpg / 16) * 16;
            let num_groups = total_threads.div_ceil(tpg);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: tpg,
                    height: 1,
                    depth: 1,
                },
            );
        }

        enc.endEncoding();
        if async_dispatch::commit_and_wait(cmd, "poseidon2").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u32> = self.ctx.read_buffer(&states_buf, states.len());
            states.copy_from_slice(&result);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::Goldilocks;
    use p3_symmetric::Permutation;

    #[test]
    fn poseidon2_babybear_gpu_matches_cpu() {
        let metal = match MetalPoseidon2::new() {
            Some(m) => m,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        use p3_baby_bear::BabyBear;

        let seed = 42u64;
        let (round_constants, n_ext, n_int) = babybear::flatten_round_constants(seed);

        use rand09::SeedableRng;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
        use p3_baby_bear::Poseidon2BabyBear;
        let cpu_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);

        let n_perms = 2000;
        let mut gpu_states: Vec<u32> = (0..n_perms * 16)
            .map(|i| (i as u32) % 2013265920) // keep in BabyBear range
            .collect();

        let mut cpu_states = gpu_states.clone();
        for perm_idx in 0..n_perms {
            let offset = perm_idx * 16;
            let mut state: [BabyBear; 16] =
                std::array::from_fn(|i| BabyBear::from_u64(cpu_states[offset + i] as u64));
            cpu_perm.permute_mut(&mut state);
            for i in 0..16 {
                cpu_states[offset + i] = state[i].as_canonical_u64() as u32;
            }
        }

        let success = metal.batch_permute_babybear(&mut gpu_states, &round_constants, n_ext, n_int);
        assert!(success, "GPU dispatch should succeed");

        for i in 0..n_perms * 16 {
            assert_eq!(
                gpu_states[i],
                cpu_states[i],
                "Mismatch at index {} (perm {}, element {})",
                i,
                i / 16,
                i % 16
            );
        }
    }

    #[test]
    fn poseidon2_babybear_simd_matches_cpu() {
        let metal = match MetalPoseidon2::new() {
            Some(m) => m,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        use p3_baby_bear::BabyBear;

        let seed = 42u64;
        let (round_constants, n_ext, n_int) = babybear::flatten_round_constants(seed);

        use rand09::SeedableRng;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
        use p3_baby_bear::Poseidon2BabyBear;
        let cpu_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);

        let n_perms = 2000;
        let mut gpu_states: Vec<u32> = (0..n_perms * 16).map(|i| (i as u32) % 2013265920).collect();

        let mut cpu_states = gpu_states.clone();
        for perm_idx in 0..n_perms {
            let offset = perm_idx * 16;
            let mut state: [BabyBear; 16] =
                std::array::from_fn(|i| BabyBear::from_u64(cpu_states[offset + i] as u64));
            cpu_perm.permute_mut(&mut state);
            for i in 0..16 {
                cpu_states[offset + i] = state[i].as_canonical_u64() as u32;
            }
        }

        let success =
            metal.batch_permute_babybear_simd(&mut gpu_states, &round_constants, n_ext, n_int);
        assert!(success, "SIMD GPU dispatch should succeed");

        for i in 0..n_perms * 16 {
            assert_eq!(
                gpu_states[i],
                cpu_states[i],
                "SIMD mismatch at index {} (perm {}, element {})",
                i,
                i / 16,
                i % 16
            );
        }
    }

    #[test]
    fn poseidon2_gpu_matches_cpu() {
        let metal = match MetalPoseidon2::new() {
            Some(m) => m,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        // Use fixed seed for deterministic constants
        let seed = 42u64;
        let (round_constants, n_ext, n_int) = goldilocks::flatten_round_constants(seed);

        // Create p3 permutation with same seed for CPU reference
        use rand09::SeedableRng;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
        use p3_goldilocks::Poseidon2Goldilocks;
        let cpu_perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);

        let n_perms = 2000; // above threshold
        let mut gpu_states: Vec<u64> = (0..n_perms * 16)
            .map(|i| (i as u64) % (u64::MAX - (1u64 << 32) + 2)) // keep in Goldilocks range
            .collect();

        // CPU reference: process each permutation
        let mut cpu_states = gpu_states.clone();
        for perm_idx in 0..n_perms {
            let offset = perm_idx * 16;
            let mut state: [Goldilocks; 16] =
                std::array::from_fn(|i| Goldilocks::from_u64(cpu_states[offset + i]));
            cpu_perm.permute_mut(&mut state);
            for i in 0..16 {
                cpu_states[offset + i] = state[i].as_canonical_u64();
            }
        }

        let success =
            metal.batch_permute_goldilocks(&mut gpu_states, &round_constants, n_ext, n_int);
        assert!(success, "GPU dispatch should succeed");

        // Compare
        for i in 0..n_perms * 16 {
            assert_eq!(
                gpu_states[i],
                cpu_states[i],
                "Mismatch at index {} (perm {}, element {})",
                i,
                i / 16,
                i % 16
            );
        }
    }

    fn patterned_goldilocks_states(seed: u64, n_perms: usize) -> Vec<u64> {
        (0..n_perms * 16)
            .map(|i| {
                let value = seed
                    .wrapping_mul(0x94d0_49bb_1331_11eb)
                    .wrapping_add((i as u64).wrapping_mul(0xda94_2042_e4dd_58b5));
                value % (u64::MAX - (1u64 << 32) + 2)
            })
            .collect()
    }

    fn patterned_babybear_states(seed: u64, n_perms: usize) -> Vec<u32> {
        (0..n_perms * 16)
            .map(|i| {
                let value = seed
                    .wrapping_mul(0xbf58_476d_1ce4_e5b9)
                    .wrapping_add((i as u64).wrapping_mul(0x94d0_49bb_1331_11eb));
                (value % 2_013_265_920) as u32
            })
            .collect()
    }

    #[test]
    fn poseidon2_randomized_batches_match_cpu() {
        let metal = match MetalPoseidon2::new() {
            Some(m) => m,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n_perms = gpu_poseidon2_threshold().max(1024);

        for seed in [7u64, 19u64] {
            let (gold_rc, gold_ext, gold_int) = goldilocks::flatten_round_constants(seed);
            use rand09::SeedableRng;
            let mut gold_rng = rand09::rngs::SmallRng::seed_from_u64(seed);
            use p3_goldilocks::Poseidon2Goldilocks;
            let gold_cpu_perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut gold_rng);

            let mut gold_gpu_states = patterned_goldilocks_states(seed, n_perms);
            let mut gold_cpu_states = gold_gpu_states.clone();
            for perm_idx in 0..n_perms {
                let offset = perm_idx * 16;
                let mut state: [Goldilocks; 16] =
                    std::array::from_fn(|i| Goldilocks::from_u64(gold_cpu_states[offset + i]));
                gold_cpu_perm.permute_mut(&mut state);
                for i in 0..16 {
                    gold_cpu_states[offset + i] = state[i].as_canonical_u64();
                }
            }

            assert!(
                metal.batch_permute_goldilocks(&mut gold_gpu_states, &gold_rc, gold_ext, gold_int),
                "Goldilocks GPU dispatch should succeed for seed {seed}"
            );
            assert_eq!(
                gold_gpu_states, gold_cpu_states,
                "Goldilocks randomized Poseidon2 mismatch for seed {seed}"
            );

            let (baby_rc, baby_ext, baby_int) = babybear::flatten_round_constants(seed);
            let mut baby_rng = rand09::rngs::SmallRng::seed_from_u64(seed);
            use p3_baby_bear::Poseidon2BabyBear;
            let baby_cpu_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut baby_rng);

            let mut baby_gpu_states = patterned_babybear_states(seed, n_perms);
            let mut baby_cpu_states = baby_gpu_states.clone();
            for perm_idx in 0..n_perms {
                let offset = perm_idx * 16;
                let mut state: [BabyBear; 16] =
                    std::array::from_fn(|i| BabyBear::from_u64(baby_cpu_states[offset + i] as u64));
                baby_cpu_perm.permute_mut(&mut state);
                for i in 0..16 {
                    baby_cpu_states[offset + i] = state[i].as_canonical_u64() as u32;
                }
            }

            assert!(
                metal.batch_permute_babybear(&mut baby_gpu_states, &baby_rc, baby_ext, baby_int),
                "BabyBear GPU dispatch should succeed for seed {seed}"
            );
            assert_eq!(
                baby_gpu_states, baby_cpu_states,
                "BabyBear randomized Poseidon2 mismatch for seed {seed}"
            );
        }
    }
}
