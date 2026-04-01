//! GPU-accelerated FRI folding operations.
//!
//! FRI (Fast Reed-Solomon Interactive Oracle Proof) folding is the core of
//! STARK proof compression. Each fold halves the polynomial degree by combining
//! pairs of evaluations with a random challenge.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::shader_library::kernels;
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

const MIN_FRI_FOLD_SIZE: usize = 1_024;

/// Metal FRI accelerator.
pub struct MetalFri {
    ctx: &'static MetalContext,
}

impl MetalFri {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// FRI fold evaluations using random challenge alpha (Goldilocks).
    ///
    /// g[i] = (f[2i] + f[2i+1]) / 2 + alpha * (f[2i] - f[2i+1]) * inv_twiddles[i]
    ///
    /// `evals`: 2n evaluations of the polynomial
    /// `alpha`: random folding challenge
    /// `inv_twiddles`: n precomputed inverse twiddle factors
    /// Returns: n folded evaluations
    pub fn fold_goldilocks(
        &self,
        evals: &[u64],
        alpha: u64,
        inv_twiddles: &[u64],
    ) -> Option<Vec<u64>> {
        let n_output = evals.len() / 2;
        if n_output < MIN_FRI_FOLD_SIZE
            || !evals.len().is_multiple_of(2)
            || inv_twiddles.len() != n_output
        {
            return None;
        }

        let pipeline = self.ctx.pipeline(kernels::FRI_FOLD_GOLDILOCKS)?;

        let evals_buf = self.ctx.new_buffer_from_slice(evals)?;
        let output_buf = self.ctx.new_buffer(n_output * std::mem::size_of::<u64>())?;
        let twiddles_buf = self.ctx.new_buffer_from_slice(inv_twiddles)?;

        let n_out = n_output as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*evals_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&alpha).cast(), 8, 2);
            enc.setBuffer_offset_atIndex(Some(&*twiddles_buf), 0, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_out).cast(), 4, 4);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = n_output.div_ceil(max_tpg);

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
        async_dispatch::commit_and_wait(cmd, "fri").ok()?;

        Some(self.ctx.read_buffer(&output_buf, n_output))
    }

    /// FRI fold evaluations using random challenge alpha (BabyBear).
    pub fn fold_babybear(
        &self,
        evals: &[u32],
        alpha: u32,
        inv_twiddles: &[u32],
    ) -> Option<Vec<u32>> {
        let n_output = evals.len() / 2;
        if n_output < MIN_FRI_FOLD_SIZE
            || !evals.len().is_multiple_of(2)
            || inv_twiddles.len() != n_output
        {
            return None;
        }

        let pipeline = self.ctx.pipeline(kernels::FRI_FOLD_BABYBEAR)?;

        let evals_buf = self.ctx.new_buffer_from_slice(evals)?;
        let output_buf = self.ctx.new_buffer(n_output * std::mem::size_of::<u32>())?;
        let twiddles_buf = self.ctx.new_buffer_from_slice(inv_twiddles)?;

        let n_out = n_output as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*evals_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&alpha).cast(), 4, 2);
            enc.setBuffer_offset_atIndex(Some(&*twiddles_buf), 0, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_out).cast(), 4, 4);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = n_output.div_ceil(max_tpg);

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
        async_dispatch::commit_and_wait(cmd, "fri").ok()?;

        Some(self.ctx.read_buffer(&output_buf, n_output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GL_P: u64 = 0xFFFFFFFF00000001;
    const GL_INV_TWO: u64 = 0x7FFFFFFF80000001;

    fn gl_add(a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        if sum >= GL_P as u128 {
            (sum - GL_P as u128) as u64
        } else {
            sum as u64
        }
    }

    fn gl_sub(a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { GL_P - (b - a) }
    }

    fn gl_mul(a: u64, b: u64) -> u64 {
        let prod = a as u128 * b as u128;
        let lo = prod as u64;
        let hi = (prod >> 64) as u64;
        let hi_shifted = (hi as u128) * ((1u128 << 32) - 1);
        let sum = lo as u128 + hi_shifted;
        let lo2 = sum as u64;
        let hi2 = (sum >> 64) as u64;
        if hi2 == 0 {
            if lo2 >= GL_P { lo2 - GL_P } else { lo2 }
        } else {
            let hi2_shifted = (hi2 as u128) * ((1u128 << 32) - 1);
            let final_sum = lo2 as u128 + hi2_shifted;
            (final_sum % GL_P as u128) as u64
        }
    }

    fn cpu_fri_fold(evals: &[u64], alpha: u64, inv_twiddles: &[u64]) -> Vec<u64> {
        let n = evals.len() / 2;
        (0..n)
            .map(|i| {
                let f_even = evals[2 * i];
                let f_odd = evals[2 * i + 1];
                let sum = gl_mul(gl_add(f_even, f_odd), GL_INV_TWO);
                let diff = gl_mul(gl_mul(gl_sub(f_even, f_odd), inv_twiddles[i]), alpha);
                gl_add(sum, diff)
            })
            .collect()
    }

    #[test]
    fn fri_fold_goldilocks_matches_cpu() {
        let fri = match MetalFri::new() {
            Some(f) => f,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n_output = 2048;
        let n_input = n_output * 2;
        let evals: Vec<u64> = (0..n_input).map(|i| (i as u64 * 7 + 1) % GL_P).collect();
        let alpha = 42u64;
        let inv_twiddles: Vec<u64> = (0..n_output).map(|i| (i as u64 * 13 + 3) % GL_P).collect();

        let expected = cpu_fri_fold(&evals, alpha, &inv_twiddles);
        let result = fri.fold_goldilocks(&evals, alpha, &inv_twiddles);
        assert!(result.is_some(), "GPU FRI fold should succeed");
        let result = result.unwrap();

        for i in 0..n_output {
            assert_eq!(result[i], expected[i], "FRI fold mismatch at index {}", i);
        }
    }
}
