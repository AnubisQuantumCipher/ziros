//! GPU-accelerated polynomial operations.
//!
//! Provides batch polynomial evaluation, coset evaluation, and quotient
//! computation on the Metal GPU.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::ntt::p3_adapter::MetalDft;
use crate::shader_library::kernels;
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use std::ptr::NonNull;

const MIN_POLY_EVAL_SIZE: usize = 1_024;

/// Metal polynomial operations accelerator.
pub struct MetalPolyOps {
    ctx: &'static MetalContext,
}

impl MetalPolyOps {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Evaluate polynomial at multiple points using Horner's method on GPU.
    ///
    /// `coeffs`: polynomial coefficients [c0, c1, ..., c_{d-1}] (Goldilocks)
    /// `points`: evaluation points
    /// Returns: f(x_i) for each point
    pub fn batch_eval_goldilocks(&self, coeffs: &[u64], points: &[u64]) -> Option<Vec<u64>> {
        let n_points = points.len();
        if n_points < MIN_POLY_EVAL_SIZE || coeffs.is_empty() {
            return None;
        }

        let pipeline = self.ctx.pipeline(kernels::POLY_EVAL_GOLDILOCKS)?;

        let coeffs_buf = self.ctx.new_buffer_from_slice(coeffs)?;
        let points_buf = self.ctx.new_buffer_from_slice(points)?;
        let output_buf = self.ctx.new_buffer(std::mem::size_of_val(points))?;

        let degree = coeffs.len() as u32;
        let n_pts = n_points as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*coeffs_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*points_buf), 0, 1);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 2);
            enc.setBytes_length_atIndex(NonNull::from(&degree).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_pts).cast(), 4, 4);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = n_points.div_ceil(max_tpg);

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
        async_dispatch::commit_and_wait(cmd, "poly").ok()?;

        Some(self.ctx.read_buffer(&output_buf, n_points))
    }

    /// Evaluate polynomial on coset `shift * omega^i` using GPU.
    ///
    /// Multiplies coefficients by shift powers, then uses NTT.
    /// Returns coset evaluations.
    pub fn coset_shift_goldilocks(&self, coeffs: &mut [u64], shift: u64) -> bool {
        let n = coeffs.len();
        if n < MIN_POLY_EVAL_SIZE {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernels::POLY_COSET_SHIFT_GOLDILOCKS) {
            Some(p) => p,
            None => return false,
        };

        let used_zero_copy;
        let coeffs_buf = if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(coeffs) } {
            used_zero_copy = true;
            b
        } else if let Some(b) = self.ctx.new_buffer_from_slice(coeffs) {
            used_zero_copy = false;
            b
        } else {
            return false;
        };

        let n_u32 = n as u32;

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
            enc.setBuffer_offset_atIndex(Some(&*coeffs_buf), 0, 0);
            enc.setBytes_length_atIndex(NonNull::from(&shift).cast(), 8, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
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
        if async_dispatch::commit_and_wait(cmd, "poly").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u64> = self.ctx.read_buffer(&coeffs_buf, n);
            coeffs.copy_from_slice(&result);
        }

        true
    }

    /// Evaluate polynomial on the Goldilocks coset `shift * omega^i`.
    pub fn coset_eval_goldilocks(
        &self,
        coeffs: &[u64],
        shift: u64,
        log_n: u32,
    ) -> Option<Vec<u64>> {
        let n = coeffs.len();
        if n == 0 || !n.is_power_of_two() || n.trailing_zeros() != log_n {
            return None;
        }

        let mut shifted = coeffs.to_vec();
        if !self.coset_shift_goldilocks(&mut shifted, shift) {
            return None;
        }

        let dft = MetalDft::<Goldilocks>::new()?;
        let values = shifted
            .into_iter()
            .map(Goldilocks::from_u64)
            .collect::<Vec<_>>();
        let result = dft.dft_batch(RowMajorMatrix::new(values, 1));
        Some(
            result
                .values
                .into_iter()
                .map(|value| value.as_canonical_u64())
                .collect(),
        )
    }

    /// Compute quotient values `(f(x_i) - f(z)) / (x_i - z)` on the canonical Goldilocks subgroup.
    pub fn quotient_goldilocks(&self, evals: &[u64], z: u64, f_z: u64) -> Option<Vec<u64>> {
        let n = evals.len();
        if n < MIN_POLY_EVAL_SIZE || n == 0 || !n.is_power_of_two() {
            return None;
        }

        let log_n = n.trailing_zeros() as usize;
        let generator = Goldilocks::two_adic_generator(log_n).as_canonical_u64();
        let pipeline = self.ctx.pipeline(kernels::POLY_QUOTIENT_GOLDILOCKS)?;

        let evals_buf = self.ctx.new_buffer_from_slice(evals)?;
        let output_buf = self.ctx.new_buffer(std::mem::size_of_val(evals))?;
        let n_u32 = n as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*evals_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&z).cast(), 8, 2);
            enc.setBytes_length_atIndex(NonNull::from(&f_z).cast(), 8, 3);
            enc.setBytes_length_atIndex(NonNull::from(&generator).cast(), 8, 4);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 5);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
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
        async_dispatch::commit_and_wait(cmd, "poly").ok()?;

        Some(self.ctx.read_buffer(&output_buf, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GL_P: u64 = 0xFFFFFFFF00000001;

    fn gl_mul_cpu(a: u64, b: u64) -> u64 {
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

    fn gl_add_cpu(a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        if sum >= GL_P as u128 {
            (sum - GL_P as u128) as u64
        } else {
            sum as u64
        }
    }

    fn gl_sub_cpu(a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { GL_P - (b - a) }
    }

    fn horner_eval(coeffs: &[u64], x: u64) -> u64 {
        let mut result = 0u64;
        for i in (0..coeffs.len()).rev() {
            result = gl_add_cpu(gl_mul_cpu(result, x), coeffs[i]);
        }
        result
    }

    #[test]
    fn poly_eval_matches_cpu() {
        let ops = match MetalPolyOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let degree = 64;
        let coeffs: Vec<u64> = (0..degree).map(|i| (i as u64 * 7 + 1) % GL_P).collect();
        let n_points = 2048;
        let points: Vec<u64> = (0..n_points).map(|i| (i as u64 * 13 + 3) % GL_P).collect();

        let expected: Vec<u64> = points.iter().map(|&x| horner_eval(&coeffs, x)).collect();

        let result = ops.batch_eval_goldilocks(&coeffs, &points);
        assert!(result.is_some(), "GPU dispatch should succeed");
        let result = result.unwrap();

        for i in 0..n_points {
            assert_eq!(result[i], expected[i], "Mismatch at point {}", i);
        }
    }

    fn subgroup_generator(log_n: usize) -> u64 {
        Goldilocks::two_adic_generator(log_n).as_canonical_u64()
    }

    fn subgroup_eval_point(index: usize, log_n: usize) -> u64 {
        gl_pow_cpu(subgroup_generator(log_n), index as u64)
    }

    fn gl_pow_cpu(mut base: u64, mut exp: u64) -> u64 {
        let mut result = 1u64;
        while exp > 0 {
            if exp & 1 == 1 {
                result = gl_mul_cpu(result, base);
            }
            exp >>= 1;
            base = gl_mul_cpu(base, base);
        }
        result
    }

    fn gl_inv_cpu(value: u64) -> u64 {
        gl_pow_cpu(value, GL_P - 2)
    }

    #[test]
    fn coset_eval_matches_cpu() {
        let ops = match MetalPolyOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let log_n = 11u32;
        let n = 1usize << log_n;
        let coeffs: Vec<u64> = (0..n).map(|i| (i as u64 * 5 + 9) % GL_P).collect();
        let shift = 7u64;
        let expected: Vec<u64> = (0..n)
            .map(|i| {
                horner_eval(
                    &coeffs,
                    gl_mul_cpu(shift, subgroup_eval_point(i, log_n as usize)),
                )
            })
            .collect();

        let result = ops
            .coset_eval_goldilocks(&coeffs, shift, log_n)
            .expect("GPU coset eval should succeed");
        assert_eq!(result, expected);
    }

    #[test]
    fn quotient_eval_matches_cpu() {
        let ops = match MetalPolyOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let log_n = 11usize;
        let n = 1usize << log_n;
        let coeffs: Vec<u64> = (0..64).map(|i| (i as u64 * 17 + 4) % GL_P).collect();
        let evals: Vec<u64> = (0..n)
            .map(|i| horner_eval(&coeffs, subgroup_eval_point(i, log_n)))
            .collect();
        let z = 9u64;
        let f_z = horner_eval(&coeffs, z);
        let expected: Vec<u64> = (0..n)
            .map(|i| {
                let x = subgroup_eval_point(i, log_n);
                let numerator = gl_sub_cpu(evals[i], f_z);
                let denominator = gl_sub_cpu(x, z);
                if denominator == 0 {
                    0
                } else {
                    gl_mul_cpu(numerator, gl_inv_cpu(denominator))
                }
            })
            .collect();

        let result = ops
            .quotient_goldilocks(&evals, z, f_z)
            .expect("GPU quotient eval should succeed");
        assert_eq!(result, expected);
    }
}
