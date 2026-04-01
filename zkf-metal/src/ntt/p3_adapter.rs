//! Plonky3 `TwoAdicSubgroupDft` adapter for Metal GPU NTT.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::launch_contracts::{self, FieldFamily, NttContractInput};
use crate::ntt::fields;
use crate::shader_library::kernels;
use objc2::runtime::ProtocolObject;
use objc2_metal::{
    MTLBarrierScope, MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder,
    MTLComputePipelineState, MTLSize,
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// Get the current NTT GPU threshold (device-adaptive).
fn gpu_ntt_threshold_val() -> usize {
    crate::tuning::current_thresholds().ntt
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DftDispatch {
    Metal,
    BelowThreshold,
    DispatchFailed,
}

pub fn gpu_ntt_threshold() -> usize {
    gpu_ntt_threshold_val()
}

/// Metal-accelerated DFT implementation for Plonky3.
pub struct MetalDft<F> {
    ctx: &'static MetalContext,
    _phantom: PhantomData<F>,
}

impl<F> Default for MetalDft<F> {
    fn default() -> Self {
        Self {
            ctx: device::global_context().expect("Metal GPU required for MetalDft"),
            _phantom: PhantomData,
        }
    }
}

impl<F> Clone for MetalDft<F> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx,
            _phantom: PhantomData,
        }
    }
}

impl<F> MetalDft<F> {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self {
            ctx,
            _phantom: PhantomData,
        })
    }
}

impl<F: TwoAdicField + PrimeField64> TwoAdicSubgroupDft<F> for MetalDft<F> {
    type Evaluations = RowMajorMatrix<F>;

    fn dft_batch(&self, mat: RowMajorMatrix<F>) -> Self::Evaluations {
        self.dft_batch_with_dispatch(mat).0
    }
}

impl<F: TwoAdicField + PrimeField64> MetalDft<F> {
    pub fn dft_batch_with_dispatch(
        &self,
        mat: RowMajorMatrix<F>,
    ) -> (RowMajorMatrix<F>, DftDispatch) {
        let n = mat.values.len();
        let width = mat.width;

        if width == 0 || n == 0 {
            return (mat, DftDispatch::BelowThreshold);
        }

        let height = n / width;
        if !height.is_power_of_two() || height < 2 {
            return (mat, DftDispatch::BelowThreshold);
        }

        if height >= gpu_ntt_threshold_val() {
            let values = mat.values;
            if let Some(result) = self.metal_dft_columns(&values, height, width, false) {
                return (RowMajorMatrix::new(result, width), DftDispatch::Metal);
            }
            return (
                cpu_dft_batch(RowMajorMatrix::new(values, width)),
                DftDispatch::DispatchFailed,
            );
        }

        (cpu_dft_batch(mat), DftDispatch::BelowThreshold)
    }

    /// Dispatch NTT on Metal GPU for one or more columns.
    ///
    /// For width > 1, uses batch 2D dispatch to process all columns in a single
    /// GPU invocation. For width == 1, uses the single-column kernel.
    fn metal_dft_columns(
        &self,
        values: &[F],
        height: usize,
        width: usize,
        inverse: bool,
    ) -> Option<Vec<F>> {
        let log_n = height.trailing_zeros() as usize;
        let is_32bit = std::mem::size_of::<F>() == 4;

        // Precompute twiddle factors (always u64 internally)
        let twiddles_u64 = if inverse {
            fields::precompute_inverse_twiddles::<F>(log_n)
        } else {
            fields::precompute_twiddles::<F>(log_n)
        };

        let twiddle_buf = if is_32bit {
            let twiddles_u32: Vec<u32> = twiddles_u64.iter().map(|&v| v as u32).collect();
            self.ctx.new_buffer_from_slice(&twiddles_u32)?
        } else {
            self.ctx.new_buffer_from_slice(&twiddles_u64)?
        };

        if width > 1 {
            self.metal_dft_batch(
                values,
                height,
                width,
                inverse,
                log_n,
                is_32bit,
                &twiddle_buf,
            )
        } else {
            self.metal_dft_single_column(values, height, inverse, log_n, is_32bit, &twiddle_buf)
        }
    }

    /// Batch NTT: process ALL columns in a single GPU dispatch using 2D grids.
    /// Data stays in row-major layout (stride = width).
    #[allow(clippy::too_many_arguments)]
    fn metal_dft_batch(
        &self,
        values: &[F],
        height: usize,
        width: usize,
        inverse: bool,
        log_n: usize,
        is_32bit: bool,
        twiddle_buf: &ProtocolObject<dyn MTLBuffer>,
    ) -> Option<Vec<F>> {
        let batch_kernel = if is_32bit {
            kernels::NTT_BUTTERFLY_BABYBEAR_BATCH
        } else {
            kernels::NTT_BUTTERFLY_GOLDILOCKS_BATCH
        };
        let pipeline = self.ctx.pipeline(batch_kernel)?;
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let field = if is_32bit {
            FieldFamily::BabyBear
        } else {
            FieldFamily::Goldilocks
        };
        launch_contracts::ntt_contract(NttContractInput {
            kernel: batch_kernel,
            field,
            height,
            width,
            twiddle_elements: height,
            element_bytes: if is_32bit { 4 } else { 8 },
            max_threads_per_group: max_tpg,
            inverse,
            batched: true,
        })
        .ok()?;

        // Bit-reverse each column's data in row-major layout
        // First, extract canonical values into a flat row-major buffer
        let total = height * width;

        let data_buf = if is_32bit {
            let mut data_u32: Vec<u32> = vec![0u32; total];
            for col in 0..width {
                let mut column: Vec<u32> = (0..height)
                    .map(|row| values[row * width + col].as_canonical_u64() as u32)
                    .collect();
                bit_reverse_permute(&mut column);
                for row in 0..height {
                    data_u32[row * width + col] = column[row];
                }
            }
            self.ctx.new_buffer_from_slice(&data_u32)?
        } else {
            let mut data_u64: Vec<u64> = vec![0u64; total];
            for col in 0..width {
                let mut column: Vec<u64> = (0..height)
                    .map(|row| values[row * width + col].as_canonical_u64())
                    .collect();
                bit_reverse_permute(&mut column);
                for row in 0..height {
                    data_u64[row * width + col] = column[row];
                }
            }
            self.ctx.new_buffer_from_slice(&data_u64)?
        };

        let n_u32 = height as u32;
        let stride_u32 = width as u32;
        let num_butterflies = height / 2;

        // 2D dispatch: X = butterfly index, Y = column index
        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        let groups_x = num_butterflies.div_ceil(max_tpg);

        for stage in 0..log_n as u32 {
            unsafe {
                enc.setComputePipelineState(&pipeline);
                enc.setBuffer_offset_atIndex(Some(&*data_buf), 0, 0);
                enc.setBuffer_offset_atIndex(Some(twiddle_buf), 0, 1);
                enc.setBytes_length_atIndex(NonNull::from(&stage).cast(), 4, 2);
                enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 3);
                enc.setBytes_length_atIndex(NonNull::from(&stride_u32).cast(), 4, 4);

                enc.dispatchThreadgroups_threadsPerThreadgroup(
                    MTLSize {
                        width: groups_x,
                        height: width,
                        depth: 1,
                    },
                    MTLSize {
                        width: max_tpg,
                        height: 1,
                        depth: 1,
                    },
                );

                if stage + 1 < log_n as u32 {
                    enc.memoryBarrierWithScope(MTLBarrierScope::Buffers);
                }
            }
        }

        enc.endEncoding();
        async_dispatch::commit_and_wait(cmd, "ntt").ok()?;

        // Read results back
        let n_inv = if inverse {
            let n_f = F::from_u64(height as u64);
            Some(n_f.exp_u64(F::ORDER_U64 - 2))
        } else {
            None
        };

        let mut result_values = values.to_vec();
        if is_32bit {
            let result_u32: Vec<u32> = self.ctx.read_buffer(&data_buf, total);
            for col in 0..width {
                for row in 0..height {
                    let val = F::from_u64(result_u32[row * width + col] as u64);
                    result_values[row * width + col] = match n_inv {
                        Some(inv) => val * inv,
                        None => val,
                    };
                }
            }
        } else {
            let result_u64: Vec<u64> = self.ctx.read_buffer(&data_buf, total);
            for col in 0..width {
                for row in 0..height {
                    let val = F::from_u64(result_u64[row * width + col]);
                    result_values[row * width + col] = match n_inv {
                        Some(inv) => val * inv,
                        None => val,
                    };
                }
            }
        }

        Some(result_values)
    }

    /// Single-column NTT dispatch (original path).
    fn metal_dft_single_column(
        &self,
        values: &[F],
        height: usize,
        inverse: bool,
        log_n: usize,
        is_32bit: bool,
        twiddle_buf: &ProtocolObject<dyn MTLBuffer>,
    ) -> Option<Vec<F>> {
        let kernel_name = if !is_32bit {
            kernels::NTT_BUTTERFLY_GOLDILOCKS
        } else {
            kernels::NTT_BUTTERFLY_BABYBEAR
        };
        let pipeline = self.ctx.pipeline(kernel_name)?;
        let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
        let field = if is_32bit {
            FieldFamily::BabyBear
        } else {
            FieldFamily::Goldilocks
        };
        launch_contracts::ntt_contract(NttContractInput {
            kernel: kernel_name,
            field,
            height,
            width: 1,
            twiddle_elements: height,
            element_bytes: if is_32bit { 4 } else { 8 },
            max_threads_per_group: max_tpg,
            inverse,
            batched: false,
        })
        .ok()?;

        let mut result_values = values.to_vec();

        let mut column_canonical: Vec<u64> = (0..height)
            .map(|row| result_values[row].as_canonical_u64())
            .collect();
        bit_reverse_permute(&mut column_canonical);

        let mut column_u32_storage: Option<Vec<u32>> = None;
        let data_buf = if is_32bit {
            let u32_data = column_canonical
                .iter()
                .map(|&v| v as u32)
                .collect::<Vec<u32>>();
            column_u32_storage = Some(u32_data);
            let u32_ref = column_u32_storage.as_mut().unwrap();
            if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(u32_ref.as_mut_slice()) } {
                b
            } else {
                self.ctx.new_buffer_from_slice(u32_ref)?
            }
        } else if let Some(b) = unsafe { self.ctx.new_buffer_no_copy(&mut column_canonical) } {
            b
        } else {
            self.ctx.new_buffer_from_slice(&column_canonical)?
        };
        let _ = &column_u32_storage;
        let n_u32 = height as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        let num_butterflies = height / 2;
        let num_groups = num_butterflies.div_ceil(max_tpg);

        for stage in 0..log_n as u32 {
            unsafe {
                enc.setComputePipelineState(&pipeline);
                enc.setBuffer_offset_atIndex(Some(&*data_buf), 0, 0);
                enc.setBuffer_offset_atIndex(Some(twiddle_buf), 0, 1);
                enc.setBytes_length_atIndex(NonNull::from(&stage).cast(), 4, 2);
                enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 3);

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

                if stage + 1 < log_n as u32 {
                    enc.memoryBarrierWithScope(MTLBarrierScope::Buffers);
                }
            }
        }

        enc.endEncoding();
        async_dispatch::commit_and_wait(cmd, "ntt").ok()?;

        let n_inv = if inverse {
            let n_f = F::from_u64(height as u64);
            Some(n_f.exp_u64(F::ORDER_U64 - 2))
        } else {
            None
        };

        if is_32bit {
            let result_u32: Vec<u32> = self.ctx.read_buffer(&data_buf, height);
            for row in 0..height {
                let val = F::from_u64(result_u32[row] as u64);
                result_values[row] = match n_inv {
                    Some(inv) => val * inv,
                    None => val,
                };
            }
        } else {
            let result_u64: Vec<u64> = self.ctx.read_buffer(&data_buf, height);
            for row in 0..height {
                let val = F::from_u64(result_u64[row]);
                result_values[row] = match n_inv {
                    Some(inv) => val * inv,
                    None => val,
                };
            }
        }

        Some(result_values)
    }

    /// Perform inverse DFT on Metal GPU.
    pub fn idft_batch(&self, mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
        self.idft_batch_with_dispatch(mat).0
    }

    pub fn idft_batch_with_dispatch(
        &self,
        mat: RowMajorMatrix<F>,
    ) -> (RowMajorMatrix<F>, DftDispatch) {
        let n = mat.values.len();
        let width = mat.width;

        if width == 0 || n == 0 {
            return (mat, DftDispatch::BelowThreshold);
        }

        let height = n / width;
        if !height.is_power_of_two() || height < 2 {
            return (mat, DftDispatch::BelowThreshold);
        }

        if height >= gpu_ntt_threshold_val() {
            let values = mat.values;
            if let Some(result) = self.metal_dft_columns(&values, height, width, true) {
                return (RowMajorMatrix::new(result, width), DftDispatch::Metal);
            }
            return (
                cpu_idft_batch(RowMajorMatrix::new(values, width)),
                DftDispatch::DispatchFailed,
            );
        }

        (cpu_idft_batch(mat), DftDispatch::BelowThreshold)
    }
}

/// CPU reference DFT (column-wise radix-2 DIT).
fn cpu_dft_batch<F: TwoAdicField + PrimeField64>(mut mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
    let width = mat.width;
    let n = mat.values.len();
    if width == 0 || n == 0 {
        return mat;
    }
    let height = n / width;
    let log_n = height.trailing_zeros() as usize;

    let g = F::two_adic_generator(log_n);

    for col in 0..width {
        let mut column: Vec<F> = (0..height)
            .map(|row| mat.values[row * width + col])
            .collect();

        bit_reverse_permute(&mut column);

        for stage in 0..log_n {
            let half = 1usize << stage;
            let group_size = half << 1;
            let step = height >> (stage + 1);

            for group in 0..(height / group_size) {
                for j in 0..half {
                    let idx0 = group * group_size + j;
                    let idx1 = idx0 + half;

                    let exp = j * step;
                    let w = g.exp_u64(exp as u64);

                    let a = column[idx0];
                    let b = column[idx1];
                    let wb = w * b;
                    column[idx0] = a + wb;
                    column[idx1] = a - wb;
                }
            }
        }

        for (row, value) in column.iter().enumerate().take(height) {
            mat.values[row * width + col] = *value;
        }
    }

    mat
}

/// CPU reference inverse DFT.
fn cpu_idft_batch<F: TwoAdicField + PrimeField64>(mut mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
    let width = mat.width;
    let n = mat.values.len();
    if width == 0 || n == 0 {
        return mat;
    }
    let height = n / width;
    let log_n = height.trailing_zeros() as usize;

    let g = F::two_adic_generator(log_n);
    let g_inv = g.exp_u64((height - 1) as u64); // g^(-1) = g^(N-1)
    let n_inv = F::from_u64(height as u64).exp_u64(F::ORDER_U64 - 2);

    for col in 0..width {
        let mut column: Vec<F> = (0..height)
            .map(|row| mat.values[row * width + col])
            .collect();

        bit_reverse_permute(&mut column);

        for stage in 0..log_n {
            let half = 1usize << stage;
            let group_size = half << 1;
            let step = height >> (stage + 1);

            for group in 0..(height / group_size) {
                for j in 0..half {
                    let idx0 = group * group_size + j;
                    let idx1 = idx0 + half;

                    let exp = j * step;
                    let w = g_inv.exp_u64(exp as u64);

                    let a = column[idx0];
                    let b = column[idx1];
                    let wb = w * b;
                    column[idx0] = a + wb;
                    column[idx1] = a - wb;
                }
            }
        }

        // Scale by 1/N
        for (row, value) in column.iter().enumerate().take(height) {
            mat.values[row * width + col] = *value * n_inv;
        }
    }

    mat
}

fn bit_reverse_permute<T: Copy>(data: &mut [T]) {
    let n = data.len();
    let log_n = n.trailing_zeros();

    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - log_n);
        if i < j {
            data.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    fn patterned_goldilocks_values(height: usize, width: usize, seed: u64) -> Vec<Goldilocks> {
        (0..height * width)
            .map(|i| {
                let value = seed
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add((i as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9));
                Goldilocks::from_u64(value)
            })
            .collect()
    }

    fn patterned_babybear_values(height: usize, width: usize, seed: u64) -> Vec<BabyBear> {
        (0..height * width)
            .map(|i| {
                let value = seed
                    .wrapping_mul(0xda94_2042_e4dd_58b5)
                    .wrapping_add((i as u64).wrapping_mul(0x94d0_49bb_1331_11eb))
                    % 2_013_265_921;
                BabyBear::from_u64(value)
            })
            .collect()
    }

    #[test]
    fn dft_basic_goldilocks() {
        let values = vec![
            Goldilocks::from_u64(1),
            Goldilocks::from_u64(2),
            Goldilocks::from_u64(3),
            Goldilocks::from_u64(4),
        ];
        let mat = RowMajorMatrix::new(values, 1);

        if let Some(metal_dft) = MetalDft::<Goldilocks>::new() {
            let result = metal_dft.dft_batch(mat);
            assert_eq!(result.values.len(), 4);
            assert_eq!(result.values[0], Goldilocks::from_u64(10));
        }
    }

    #[test]
    fn metal_ntt_matches_cpu_goldilocks() {
        if MetalDft::<Goldilocks>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let n = 1 << 13; // 8192
        let values: Vec<Goldilocks> = (0..n as u64).map(|i| Goldilocks::from_u64(i + 1)).collect();

        let cpu_mat = RowMajorMatrix::new(values.clone(), 1);
        let gpu_mat = RowMajorMatrix::new(values, 1);

        let cpu_result = cpu_dft_batch(cpu_mat);

        let metal = MetalDft::<Goldilocks>::new().unwrap();
        let gpu_result = metal.dft_batch(gpu_mat);

        assert_eq!(
            cpu_result.values, gpu_result.values,
            "Metal NTT output differs from CPU reference"
        );
    }

    #[test]
    fn metal_ntt_multi_column() {
        if MetalDft::<Goldilocks>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let height = 1 << 13;
        let width = 4;
        let values: Vec<Goldilocks> = (0..(height * width) as u64)
            .map(|i| Goldilocks::from_u64(i + 1))
            .collect();

        let cpu_result = cpu_dft_batch(RowMajorMatrix::new(values.clone(), width));
        let metal = MetalDft::<Goldilocks>::new().unwrap();
        let gpu_result = metal.dft_batch(RowMajorMatrix::new(values, width));

        assert_eq!(
            cpu_result.values, gpu_result.values,
            "Multi-column Metal NTT differs from CPU"
        );
    }

    #[test]
    fn metal_inverse_ntt_roundtrip() {
        if MetalDft::<Goldilocks>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let n = 1 << 13;
        let original: Vec<Goldilocks> =
            (0..n as u64).map(|i| Goldilocks::from_u64(i + 1)).collect();

        let metal = MetalDft::<Goldilocks>::new().unwrap();

        // Forward DFT
        let forward = metal.dft_batch(RowMajorMatrix::new(original.clone(), 1));
        // Inverse DFT
        let roundtrip = metal.idft_batch(forward);

        assert_eq!(
            original, roundtrip.values,
            "DFT -> IDFT roundtrip should recover original"
        );
    }

    #[test]
    fn metal_ntt_matches_cpu_babybear() {
        if MetalDft::<BabyBear>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let n = 1 << 13;
        let values: Vec<BabyBear> = (0..n as u64)
            .map(|i| BabyBear::from_u64((i + 1) % 2013265921))
            .collect();

        let cpu_mat = RowMajorMatrix::new(values.clone(), 1);
        let gpu_mat = RowMajorMatrix::new(values, 1);

        let cpu_result = cpu_dft_batch(cpu_mat);

        let metal = MetalDft::<BabyBear>::new().unwrap();
        let gpu_result = metal.dft_batch(gpu_mat);

        assert_eq!(
            cpu_result.values, gpu_result.values,
            "BabyBear Metal NTT output differs from CPU reference"
        );
    }

    #[test]
    fn metal_inverse_ntt_roundtrip_babybear() {
        if MetalDft::<BabyBear>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let n = 1 << 13;
        let original: Vec<BabyBear> = (0..n as u64)
            .map(|i| BabyBear::from_u64((i + 1) % 2013265921))
            .collect();

        let metal = MetalDft::<BabyBear>::new().unwrap();
        let forward = metal.dft_batch(RowMajorMatrix::new(original.clone(), 1));
        let roundtrip = metal.idft_batch(forward);

        assert_eq!(
            original, roundtrip.values,
            "BabyBear DFT -> IDFT roundtrip should recover original"
        );
    }

    #[test]
    fn metal_ntt_randomized_batches_match_cpu() {
        if MetalDft::<Goldilocks>::new().is_none() || MetalDft::<BabyBear>::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let height = 1 << 13;
        for (seed, width) in [(5u64, 1usize), (23u64, 4usize)] {
            let gold_values = patterned_goldilocks_values(height, width, seed);
            let gold_cpu = cpu_dft_batch(RowMajorMatrix::new(gold_values.clone(), width));
            let gold_gpu = MetalDft::<Goldilocks>::new()
                .unwrap()
                .dft_batch(RowMajorMatrix::new(gold_values, width));
            assert_eq!(
                gold_cpu.values, gold_gpu.values,
                "Goldilocks randomized Metal NTT mismatch for seed {seed}, width {width}"
            );

            let baby_values = patterned_babybear_values(height, width, seed);
            let baby_cpu = cpu_dft_batch(RowMajorMatrix::new(baby_values.clone(), width));
            let baby_gpu = MetalDft::<BabyBear>::new()
                .unwrap()
                .dft_batch(RowMajorMatrix::new(baby_values, width));
            assert_eq!(
                baby_cpu.values, baby_gpu.values,
                "BabyBear randomized Metal NTT mismatch for seed {seed}, width {width}"
            );
        }
    }
}
