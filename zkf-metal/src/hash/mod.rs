//! Metal-accelerated batch SHA-256 and Keccak-256 hashing.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::launch_contracts;
use crate::shader_library::kernels;
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Minimum batch size to justify GPU dispatch for hash operations.
const GPU_HASH_THRESHOLD: usize = 1_000;

/// Metal batch hasher for SHA-256 and Keccak-256.
pub struct MetalHasher {
    ctx: &'static MetalContext,
}

impl MetalHasher {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Batch SHA-256: hash `n` inputs of `input_len` bytes each.
    ///
    /// `inputs` must be exactly `n * input_len` bytes (all inputs contiguous).
    /// Returns `n * 32` bytes of SHA-256 digests, or `None` if GPU dispatch fails.
    pub fn batch_sha256(&self, inputs: &[u8], input_len: usize) -> Option<Vec<u8>> {
        if input_len == 0 || !inputs.len().is_multiple_of(input_len) {
            return None;
        }
        let n = inputs.len() / input_len;
        if n < GPU_HASH_THRESHOLD {
            return None;
        }

        let hash_lib = self.ctx.hash_library()?;
        let pipeline = self
            .ctx
            .pipeline_from_library(hash_lib, kernels::BATCH_SHA256)?;
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        launch_contracts::hash_contract(
            kernels::BATCH_SHA256,
            n,
            input_len,
            inputs.len(),
            n * 32,
            max_tpg,
        )
        .ok()?;

        let input_buf = self.ctx.new_buffer_with_bytes(inputs)?;
        let output_buf = self.ctx.new_buffer(n * 32)?;
        let n_u32 = n as u32;
        let len_u32 = input_len as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*input_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&len_u32).cast(), 4, 3);

            let num_groups = n.div_ceil(max_tpg);

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
        async_dispatch::commit_and_wait(cmd, "hash").ok()?;

        let result: Vec<u8> = self.ctx.read_buffer(&output_buf, n * 32);
        Some(result)
    }

    /// Batch Keccak-256: hash `n` inputs of `input_len` bytes each.
    ///
    /// `inputs` must be exactly `n * input_len` bytes (all inputs contiguous).
    /// Returns `n * 32` bytes of Keccak-256 digests, or `None` if GPU dispatch fails.
    pub fn batch_keccak256(&self, inputs: &[u8], input_len: usize) -> Option<Vec<u8>> {
        if input_len == 0 || !inputs.len().is_multiple_of(input_len) {
            return None;
        }
        let n = inputs.len() / input_len;
        if n < GPU_HASH_THRESHOLD {
            return None;
        }

        let hash_lib = self.ctx.hash_library()?;
        let pipeline = self
            .ctx
            .pipeline_from_library(hash_lib, kernels::BATCH_KECCAK256)?;
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        launch_contracts::hash_contract(
            kernels::BATCH_KECCAK256,
            n,
            input_len,
            inputs.len(),
            n * 32,
            max_tpg,
        )
        .ok()?;

        let input_buf = self.ctx.new_buffer_with_bytes(inputs)?;
        let output_buf = self.ctx.new_buffer(n * 32)?;
        let n_u32 = n as u32;
        let len_u32 = input_len as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*input_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&len_u32).cast(), 4, 3);

            let num_groups = n.div_ceil(max_tpg);

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
        async_dispatch::commit_and_wait(cmd, "hash").ok()?;

        let result: Vec<u8> = self.ctx.read_buffer(&output_buf, n * 32);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn patterned_inputs(seed: u64, n: usize, input_len: usize) -> Vec<u8> {
        (0..n * input_len)
            .map(|i| {
                let x = seed
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add((i as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9));
                (x ^ (x >> 17) ^ (x >> 41)) as u8
            })
            .collect()
    }

    #[test]
    fn batch_sha256_matches_cpu() {
        let hasher = match MetalHasher::new() {
            Some(h) => h,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 2000;
        let input_len = 64;
        let inputs: Vec<u8> = (0..n * input_len).map(|i| (i % 256) as u8).collect();

        // CPU reference
        let mut expected = Vec::with_capacity(n * 32);
        for i in 0..n {
            let mut h = Sha256::new();
            h.update(&inputs[i * input_len..(i + 1) * input_len]);
            expected.extend_from_slice(&h.finalize());
        }

        let gpu_result = hasher.batch_sha256(&inputs, input_len);
        match gpu_result {
            Some(result) => {
                assert_eq!(result.len(), n * 32);
                for i in 0..n {
                    assert_eq!(
                        &result[i * 32..(i + 1) * 32],
                        &expected[i * 32..(i + 1) * 32],
                        "SHA-256 mismatch at index {}",
                        i
                    );
                }
            }
            None => {
                eprintln!("GPU SHA-256 dispatch failed, skipping");
            }
        }
    }

    #[test]
    fn batch_keccak256_matches_cpu() {
        let hasher = match MetalHasher::new() {
            Some(h) => h,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 2000;
        let input_len = 64;
        let inputs: Vec<u8> = (0..n * input_len).map(|i| (i % 256) as u8).collect();

        // CPU reference using tiny-keccak
        use tiny_keccak::{Hasher, Keccak};
        let mut expected = Vec::with_capacity(n * 32);
        for i in 0..n {
            let mut h = Keccak::v256();
            h.update(&inputs[i * input_len..(i + 1) * input_len]);
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            expected.extend_from_slice(&out);
        }

        let gpu_result = hasher.batch_keccak256(&inputs, input_len);
        match gpu_result {
            Some(result) => {
                assert_eq!(result.len(), n * 32);
                for i in 0..n {
                    assert_eq!(
                        &result[i * 32..(i + 1) * 32],
                        &expected[i * 32..(i + 1) * 32],
                        "Keccak-256 mismatch at index {}",
                        i
                    );
                }
            }
            None => {
                eprintln!("GPU Keccak-256 dispatch failed, skipping");
            }
        }
    }

    #[test]
    fn randomized_hash_batches_match_cpu() {
        let hasher = match MetalHasher::new() {
            Some(h) => h,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        use tiny_keccak::{Hasher, Keccak};

        for (seed, input_len) in [(3u64, 32usize), (17u64, 64usize), (29u64, 136usize)] {
            let n = GPU_HASH_THRESHOLD;
            let inputs = patterned_inputs(seed, n, input_len);

            let mut expected_sha = Vec::with_capacity(n * 32);
            let mut expected_keccak = Vec::with_capacity(n * 32);
            for i in 0..n {
                let chunk = &inputs[i * input_len..(i + 1) * input_len];

                let mut sha = Sha256::new();
                sha.update(chunk);
                expected_sha.extend_from_slice(&sha.finalize());

                let mut keccak = Keccak::v256();
                keccak.update(chunk);
                let mut out = [0u8; 32];
                keccak.finalize(&mut out);
                expected_keccak.extend_from_slice(&out);
            }

            let gpu_sha = hasher
                .batch_sha256(&inputs, input_len)
                .expect("GPU SHA-256 dispatch should succeed for threshold-sized randomized batch");
            let gpu_keccak = hasher.batch_keccak256(&inputs, input_len).expect(
                "GPU Keccak-256 dispatch should succeed for threshold-sized randomized batch",
            );

            assert_eq!(
                gpu_sha, expected_sha,
                "randomized SHA-256 mismatch for seed {seed}"
            );
            assert_eq!(
                gpu_keccak, expected_keccak,
                "randomized Keccak-256 mismatch for seed {seed}"
            );
        }
    }
}
