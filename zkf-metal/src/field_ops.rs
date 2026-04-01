//! GPU-accelerated batch field arithmetic operations.
//!
//! Provides batch add, sub, mul over Goldilocks and BabyBear fields.
//! Dispatches to Metal GPU when batch size exceeds threshold.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Get the current field ops GPU threshold (device-adaptive).
fn gpu_field_ops_threshold() -> usize {
    crate::tuning::current_thresholds().field_ops
}

/// Metal batch field operations accelerator.
pub struct MetalFieldOps {
    ctx: &'static MetalContext,
}

impl MetalFieldOps {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Batch element-wise addition: a[i] = a[i] + b[i] (Goldilocks field, in-place on `a`).
    pub fn batch_add_goldilocks(&self, a: &mut [u64], b: &[u64]) -> bool {
        self.dispatch_binary_op_u64(a, b, "batch_add_goldilocks")
    }

    /// Batch element-wise subtraction: a[i] = a[i] - b[i] (Goldilocks field).
    pub fn batch_sub_goldilocks(&self, a: &mut [u64], b: &[u64]) -> bool {
        self.dispatch_binary_op_u64(a, b, "batch_sub_goldilocks")
    }

    /// Batch element-wise multiplication: a[i] = a[i] * b[i] (Goldilocks field).
    pub fn batch_mul_goldilocks(&self, a: &mut [u64], b: &[u64]) -> bool {
        self.dispatch_binary_op_u64(a, b, "batch_mul_goldilocks")
    }

    /// Batch element-wise addition: a[i] = a[i] + b[i] (BabyBear field).
    pub fn batch_add_babybear(&self, a: &mut [u32], b: &[u32]) -> bool {
        self.dispatch_binary_op_u32(a, b, "batch_add_babybear")
    }

    /// Batch element-wise subtraction: a[i] = a[i] - b[i] (BabyBear field).
    pub fn batch_sub_babybear(&self, a: &mut [u32], b: &[u32]) -> bool {
        self.dispatch_binary_op_u32(a, b, "batch_sub_babybear")
    }

    /// Batch element-wise multiplication: a[i] = a[i] * b[i] (BabyBear field).
    pub fn batch_mul_babybear(&self, a: &mut [u32], b: &[u32]) -> bool {
        self.dispatch_binary_op_u32(a, b, "batch_mul_babybear")
    }

    /// Batch inversion using Montgomery's trick (Goldilocks field).
    ///
    /// Computes `output[i] = input[i]^{-1} mod p` for all elements.
    /// Uses prefix products to reduce n inversions to 1 inversion + O(n) multiplications.
    /// The single inversion is done on CPU (Fermat's little theorem), rest on GPU.
    pub fn batch_inv_goldilocks(&self, input: &[u64], output: &mut [u64]) -> bool {
        let n = input.len();
        if n != output.len() || n < gpu_field_ops_threshold() {
            return false;
        }

        // Montgomery's trick on CPU (GPU prefix product not worth the complexity
        // for the 2-pass structure — the bottleneck is the single modular exponentiation)
        const GL_P: u64 = 0xFFFFFFFF00000001;

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

        fn gl_pow(mut base: u64, mut exp: u64) -> u64 {
            let mut result = 1u64;
            while exp > 0 {
                if exp & 1 == 1 {
                    result = gl_mul(result, base);
                }
                exp >>= 1;
                base = gl_mul(base, base);
            }
            result
        }

        // Phase 1: prefix products
        let mut prefix = vec![0u64; n];
        prefix[0] = input[0];
        for i in 1..n {
            prefix[i] = gl_mul(prefix[i - 1], input[i]);
        }

        // Phase 2: invert total product (single modular exponentiation)
        let mut inv = gl_pow(prefix[n - 1], GL_P - 2);

        // Phase 3: back-propagate
        for i in (1..n).rev() {
            output[i] = gl_mul(inv, prefix[i - 1]);
            inv = gl_mul(inv, input[i]);
        }
        output[0] = inv;

        true
    }

    fn dispatch_binary_op_u64(&self, a: &mut [u64], b: &[u64], kernel_name: &str) -> bool {
        let count = a.len();
        if count != b.len() || count < gpu_field_ops_threshold() {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernel_name) {
            Some(p) => p,
            None => return false,
        };

        let used_zero_copy;
        let a_buf = if let Some(buf) = unsafe { self.ctx.new_buffer_no_copy(a) } {
            used_zero_copy = true;
            buf
        } else if let Some(buf) = self.ctx.new_buffer_from_slice(a) {
            used_zero_copy = false;
            buf
        } else {
            return false;
        };
        let b_buf = match self.ctx.new_buffer_from_slice(b) {
            Some(buf) => buf,
            None => return false,
        };

        let count_u32 = count as u32;

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
            enc.setBuffer_offset_atIndex(Some(&*a_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*b_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&count_u32).cast(), 4, 2);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = count.div_ceil(max_tpg);

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
        if async_dispatch::commit_and_wait(cmd, "field-ops").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u64> = self.ctx.read_buffer(&a_buf, count);
            a.copy_from_slice(&result);
        }

        true
    }

    fn dispatch_binary_op_u32(&self, a: &mut [u32], b: &[u32], kernel_name: &str) -> bool {
        let count = a.len();
        if count != b.len() || count < gpu_field_ops_threshold() {
            return false;
        }

        let pipeline = match self.ctx.pipeline(kernel_name) {
            Some(p) => p,
            None => return false,
        };

        let used_zero_copy;
        let a_buf = if let Some(buf) = unsafe { self.ctx.new_buffer_no_copy(a) } {
            used_zero_copy = true;
            buf
        } else if let Some(buf) = self.ctx.new_buffer_from_slice(a) {
            used_zero_copy = false;
            buf
        } else {
            return false;
        };
        let b_buf = match self.ctx.new_buffer_from_slice(b) {
            Some(buf) => buf,
            None => return false,
        };

        let count_u32 = count as u32;

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
            enc.setBuffer_offset_atIndex(Some(&*a_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*b_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&count_u32).cast(), 4, 2);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = count.div_ceil(max_tpg);

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
        if async_dispatch::commit_and_wait(cmd, "field-ops").is_err() {
            return false;
        }

        if !used_zero_copy {
            let result: Vec<u32> = self.ctx.read_buffer(&a_buf, count);
            a.copy_from_slice(&result);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BB_P: u32 = 2013265921;
    const GL_P: u64 = 0xFFFFFFFF00000001;

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

    fn gl_mul_cpu(a: u64, b: u64) -> u64 {
        let prod = a as u128 * b as u128;
        // Goldilocks reduction
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

    fn bb_mul_cpu(a: u32, b: u32) -> u32 {
        ((u64::from(a) * u64::from(b)) % u64::from(BB_P)) as u32
    }

    #[test]
    fn batch_add_goldilocks_matches_cpu() {
        let ops = match MetalFieldOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 20_000;
        let mut a: Vec<u64> = (0..n).map(|i| (i as u64 * 7) % GL_P).collect();
        let b: Vec<u64> = (0..n).map(|i| (i as u64 * 13 + 5) % GL_P).collect();
        let expected: Vec<u64> = a
            .iter()
            .zip(b.iter())
            .map(|(&x, &y)| gl_add_cpu(x, y))
            .collect();

        assert!(ops.batch_add_goldilocks(&mut a, &b));
        assert_eq!(a, expected);
    }

    #[test]
    fn batch_mul_goldilocks_matches_cpu() {
        let ops = match MetalFieldOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 20_000;
        let mut a: Vec<u64> = (0..n).map(|i| (i as u64 * 7 + 1) % GL_P).collect();
        let b: Vec<u64> = (0..n).map(|i| (i as u64 * 13 + 3) % GL_P).collect();
        let expected: Vec<u64> = a
            .iter()
            .zip(b.iter())
            .map(|(&x, &y)| gl_mul_cpu(x, y))
            .collect();

        assert!(ops.batch_mul_goldilocks(&mut a, &b));
        assert_eq!(a, expected);
    }

    #[test]
    fn batch_sub_goldilocks_matches_cpu() {
        let ops = match MetalFieldOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 20_000;
        let mut a: Vec<u64> = (0..n).map(|i| (i as u64 * 7 + 100) % GL_P).collect();
        let b: Vec<u64> = (0..n).map(|i| (i as u64 * 3) % GL_P).collect();
        let expected: Vec<u64> = a
            .iter()
            .zip(b.iter())
            .map(|(&x, &y)| gl_sub_cpu(x, y))
            .collect();

        assert!(ops.batch_sub_goldilocks(&mut a, &b));
        assert_eq!(a, expected);
    }

    #[test]
    fn batch_inv_goldilocks_matches_cpu() {
        let ops = match MetalFieldOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 20_000;
        let input: Vec<u64> = (1..=n).map(|i| (i as u64 * 7 + 1) % GL_P).collect();
        let mut output = vec![0u64; n];

        assert!(ops.batch_inv_goldilocks(&input, &mut output));

        // Verify: input[i] * output[i] ≡ 1 (mod GL_P) for all i
        for i in 0..n {
            let prod = gl_mul_cpu(input[i], output[i]);
            assert_eq!(
                prod, 1,
                "inv failed at index {}: {} * {} = {} (expected 1)",
                i, input[i], output[i], prod
            );
        }
    }

    #[test]
    fn batch_mul_babybear_matches_cpu() {
        let ops = match MetalFieldOps::new() {
            Some(o) => o,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 20_000;
        let mut a: Vec<u32> = (0..n)
            .map(|i| ((i as u32).wrapping_mul(7) + 1) % BB_P)
            .collect();
        let b: Vec<u32> = (0..n)
            .map(|i| ((i as u32).wrapping_mul(13) + 3) % BB_P)
            .collect();
        let expected: Vec<u32> = a
            .iter()
            .zip(b.iter())
            .map(|(&x, &y)| bb_mul_cpu(x, y))
            .collect();

        assert!(ops.batch_mul_babybear(&mut a, &b));
        assert_eq!(a, expected);
    }
}
