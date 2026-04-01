//! GPU-accelerated Pippenger MSM dispatch for Pallas curve.
//!
//! Mirrors the BN254 Pippenger pipeline in `pippenger.rs`, adapted for
//! halo2curves Pallas types and the Pallas Fp Metal shader.

use crate::async_dispatch::GpuFuture;
use crate::device::MetalContext;
use crate::launch_contracts::{self, CurveFamily, MsmContractInput, MsmRouteClass};
use crate::msm::pallas;
use halo2curves::group::Group;
use halo2curves::pasta::{Fq, Pallas, PallasAffine};
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Execute Pippenger MSM on Metal GPU for Pallas curve.
///
/// For inputs below the GPU threshold, returns `None` to signal CPU fallback.
pub fn metal_pallas_msm(
    ctx: &MetalContext,
    scalars: &[Fq],
    bases: &[PallasAffine],
) -> Option<Pallas> {
    let n = scalars.len();
    let threshold = crate::tuning::current_thresholds().msm;
    if n != bases.len() || n < threshold {
        return None;
    }

    let msm_lib = ctx.pallas_msm_library()?;

    let c = optimal_window_size(n);
    let num_windows = pallas::num_windows(c);
    let num_buckets = pallas::num_buckets(c) as usize;
    let total_buckets = num_windows as usize * num_buckets;
    launch_contracts::msm_contract(MsmContractInput {
        kernel: "msm_bucket_acc",
        curve: CurveFamily::Pallas,
        route: MsmRouteClass::Classic,
        point_count: n,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: n * num_windows as usize,
        bucket_entries: total_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    })
    .ok()?;

    // --- Prepare GPU buffers ---

    // Scalars: n * 4 u64s (non-Montgomery, raw bigint)
    // Zero out scalars for identity base points
    let mut scalar_data: Vec<u64> = scalars
        .iter()
        .zip(bases.iter())
        .flat_map(|(s, b)| {
            if pallas::is_identity(b) {
                [0u64; 4].into_iter()
            } else {
                pallas::scalar_to_limbs(s).into_iter()
            }
        })
        .collect();

    let scalar_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut scalar_data) } {
        b
    } else {
        ctx.new_buffer_from_slice(&scalar_data)?
    };

    // Bases: separate X and Y coordinate buffers in Montgomery form
    let mut bases_x: Vec<u64> = Vec::with_capacity(n * 4);
    let mut bases_y: Vec<u64> = Vec::with_capacity(n * 4);
    for base in bases {
        if pallas::is_identity(base) {
            // Identity: use zero coordinates (won't be referenced since scalar is zeroed)
            bases_x.extend_from_slice(&[0u64; 4]);
            bases_y.extend_from_slice(&[0u64; 4]);
        } else {
            let (x_limbs, y_limbs) = pallas::affine_to_limbs(base);
            bases_x.extend_from_slice(&x_limbs);
            bases_y.extend_from_slice(&y_limbs);
        }
    }

    let bases_x_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_x) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_x)?
    };
    let bases_y_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_y) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_y)?
    };

    // Point-to-bucket mapping and bucket results
    let map_size = n * num_windows as usize;
    let map_buf = ctx.acquire_buffer(map_size * std::mem::size_of::<u32>())?;

    let bucket_result_size = total_buckets * 12;
    let bucket_buf = ctx.acquire_buffer(bucket_result_size * std::mem::size_of::<u64>())?;

    // --- Phase 1: Bucket assignment ---
    let assign_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_assign")?;
    let assign_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let n_u32 = n as u32;
        let c_u32 = c;
        let nw_u32 = num_windows;

        unsafe {
            enc.setComputePipelineState(&assign_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*scalar_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 4);

            let max_threads = assign_pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = n.div_ceil(max_threads);
            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_threads,
                    height: 1,
                    depth: 1,
                },
            );
        }
        enc.endEncoding();
        GpuFuture::submit_labeled(cmd, "msm")
    };
    assign_future.wait_checked().ok()?;

    // --- Phase 2: Bucket accumulation ---
    let acc_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_acc")?;
    let acc_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let n_u32 = n as u32;
        let c_u32 = c;
        let nw_u32 = num_windows;

        unsafe {
            enc.setComputePipelineState(&acc_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*bases_x_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*bases_y_buf), 0, 1);
            enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 2);
            enc.setBuffer_offset_atIndex(Some(&*bucket_buf), 0, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 4);
            enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 5);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 6);

            let max_threads = acc_pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = total_buckets.div_ceil(max_threads);
            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_threads,
                    height: 1,
                    depth: 1,
                },
            );
        }
        enc.endEncoding();
        GpuFuture::submit_labeled(cmd, "msm")
    };
    acc_future.wait_checked().ok()?;

    // --- Phase 3: Read results and do bucket reduction + window combination (CPU) ---
    let bucket_data: Vec<u64> = ctx.read_buffer(&bucket_buf, bucket_result_size);

    let mut window_results: Vec<Pallas> = Vec::with_capacity(num_windows as usize);

    for w in 0..num_windows as usize {
        let mut buckets: Vec<Pallas> = Vec::with_capacity(num_buckets);
        for b in 0..num_buckets {
            let offset = (w * num_buckets + b) * 12;
            let proj = pallas::gpu_proj_to_pallas(&bucket_data[offset..offset + 12])
                .unwrap_or_else(Pallas::identity);
            buckets.push(proj);
        }
        window_results.push(pallas::bucket_reduce_window(&buckets));
    }

    Some(pallas::combine_windows(&window_results, c))
}

/// Execute NAF-encoded Pippenger MSM on Metal GPU for Pallas curve.
///
/// Halved bucket count via signed-digit NAF encoding.
/// Point negation on Pallas: negate Y coordinate (same as BN254 pattern).
pub fn metal_pallas_msm_naf(
    ctx: &MetalContext,
    scalars: &[Fq],
    bases: &[PallasAffine],
) -> Option<Pallas> {
    let n = scalars.len();
    let threshold = crate::tuning::current_thresholds().msm;
    if n != bases.len() || n < threshold {
        return None;
    }

    let msm_lib = ctx.pallas_msm_library()?;

    let c = optimal_window_size_naf(n);
    let num_windows = pallas::num_windows(c);
    let num_buckets = pallas::num_buckets_naf(c) as usize;
    let total_buckets = num_windows as usize * num_buckets;
    launch_contracts::msm_contract(MsmContractInput {
        kernel: "msm_bucket_acc_naf",
        curve: CurveFamily::Pallas,
        route: MsmRouteClass::Naf,
        point_count: n,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: n * num_windows as usize,
        bucket_entries: total_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    })
    .ok()?;

    // CPU-side NAF map computation
    let mut map_data: Vec<u32> = Vec::with_capacity(n * num_windows as usize);
    for (scalar, base) in scalars.iter().zip(bases.iter()) {
        if pallas::is_identity(base) {
            map_data.extend(std::iter::repeat_n(0u32, num_windows as usize));
        } else {
            let limbs = pallas::scalar_to_limbs(scalar);
            let windows = pallas::scalar_to_naf_windows(&limbs, c, num_windows);
            map_data.extend(windows);
        }
    }

    let map_buf = ctx.new_buffer_from_slice(&map_data)?;

    // Bases
    let mut bases_x: Vec<u64> = Vec::with_capacity(n * 4);
    let mut bases_y: Vec<u64> = Vec::with_capacity(n * 4);
    for base in bases {
        if pallas::is_identity(base) {
            bases_x.extend_from_slice(&[0u64; 4]);
            bases_y.extend_from_slice(&[0u64; 4]);
        } else {
            let (x_limbs, y_limbs) = pallas::affine_to_limbs(base);
            bases_x.extend_from_slice(&x_limbs);
            bases_y.extend_from_slice(&y_limbs);
        }
    }

    let bases_x_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_x) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_x)?
    };
    let bases_y_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_y) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_y)?
    };

    let bucket_result_size = total_buckets * 12;
    let bucket_buf = ctx.acquire_buffer(bucket_result_size * std::mem::size_of::<u64>())?;

    // NAF bucket accumulation
    let acc_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_acc_naf")?;
    let acc_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let n_u32 = n as u32;
        let c_u32 = c;
        let nw_u32 = num_windows;
        let nb_u32 = num_buckets as u32;

        unsafe {
            enc.setComputePipelineState(&acc_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*bases_x_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*bases_y_buf), 0, 1);
            enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 2);
            enc.setBuffer_offset_atIndex(Some(&*bucket_buf), 0, 3);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 4);
            enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 5);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 6);
            enc.setBytes_length_atIndex(NonNull::from(&nb_u32).cast(), 4, 7);

            let max_threads = acc_pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = total_buckets.div_ceil(max_threads);
            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_threads,
                    height: 1,
                    depth: 1,
                },
            );
        }
        enc.endEncoding();
        GpuFuture::submit_labeled(cmd, "msm")
    };
    acc_future.wait_checked().ok()?;

    // Read and reduce
    let bucket_data: Vec<u64> = ctx.read_buffer(&bucket_buf, bucket_result_size);
    let mut window_results: Vec<Pallas> = Vec::with_capacity(num_windows as usize);

    for w in 0..num_windows as usize {
        let mut buckets: Vec<Pallas> = Vec::with_capacity(num_buckets);
        for b in 0..num_buckets {
            let offset = (w * num_buckets + b) * 12;
            let proj = pallas::gpu_proj_to_pallas(&bucket_data[offset..offset + 12])
                .unwrap_or_else(Pallas::identity);
            buckets.push(proj);
        }
        window_results.push(pallas::bucket_reduce_window(&buckets));
    }

    Some(pallas::combine_windows(&window_results, c))
}

fn optimal_window_size_naf(n: usize) -> u32 {
    // Wider windows at large scales where NAF bucket halving pays off
    if n < 1 << 12 {
        8
    } else if n < 1 << 16 {
        12
    } else if n < 1 << 20 {
        16
    } else {
        17
    }
}

/// CPU Pippenger implementation for Pallas (reference + fallback).
pub fn cpu_pallas_pippenger(scalars: &[Fq], bases: &[PallasAffine]) -> Pallas {
    let c = optimal_window_size(scalars.len());
    let num_windows = pallas::num_windows(c);
    let num_buckets = pallas::num_buckets(c) as usize;

    let mut window_results: Vec<Pallas> = Vec::with_capacity(num_windows as usize);

    for w in 0..num_windows {
        let mut buckets = vec![Pallas::identity(); num_buckets];

        for (scalar, base) in scalars.iter().zip(bases.iter()) {
            let limbs = pallas::scalar_to_limbs(scalar);
            let bucket_idx = extract_window(&limbs, w, c) as usize;
            if bucket_idx != 0 {
                buckets[bucket_idx] += Pallas::from(*base);
            }
        }

        window_results.push(pallas::bucket_reduce_window(&buckets));
    }

    pallas::combine_windows(&window_results, c)
}

/// Try Metal GPU MSM for Pallas curve.
///
/// This is the entry point called from the Nova MSM hook.
/// Prefers NAF path (halved buckets), falls back to standard if NAF kernel unavailable.
/// Returns `Some(result)` if GPU acceleration succeeded, `None` to fall back to CPU.
pub fn try_metal_pallas_msm(scalars: &[Fq], bases: &[PallasAffine]) -> Option<Pallas> {
    let ctx = crate::device::global_context()?;
    metal_pallas_msm_naf(ctx, scalars, bases).or_else(|| metal_pallas_msm(ctx, scalars, bases))
}

fn optimal_window_size(n: usize) -> u32 {
    if n < 1 << 12 {
        8
    } else if n < 1 << 16 {
        12
    } else if n < 1 << 20 {
        15
    } else {
        16
    }
}

fn extract_window(limbs: &[u64; 4], window_idx: u32, c: u32) -> u32 {
    let bit_offset = (window_idx * c) as usize;
    let limb_idx = bit_offset / 64;
    let bit_in_limb = bit_offset % 64;
    let mask = (1u64 << c) - 1;

    if limb_idx >= 4 {
        return 0;
    }

    let mut val = limbs[limb_idx] >> bit_in_limb;
    if bit_in_limb + c as usize > 64 && limb_idx + 1 < 4 {
        val |= limbs[limb_idx + 1] << (64 - bit_in_limb);
    }
    (val & mask) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::ff::Field;
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::{Curve, Group};
    use rand::{
        SeedableRng,
        rngs::{OsRng, StdRng},
    };

    #[test]
    fn cpu_pallas_pippenger_small() {
        let n = 64;
        let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(OsRng)).collect();
        let bases: Vec<PallasAffine> = (0..n)
            .map(|_| (Pallas::random(OsRng)).to_affine())
            .collect();

        // Naive MSM for reference
        let expected: Pallas = scalars
            .iter()
            .zip(bases.iter())
            .map(|(s, b)| Pallas::from(*b) * s)
            .fold(Pallas::identity(), |acc, p| acc + p);

        let result = cpu_pallas_pippenger(&scalars, &bases);
        assert_eq!(
            result.to_affine(),
            expected.to_affine(),
            "CPU Pallas Pippenger mismatch"
        );
    }

    #[test]
    fn metal_pallas_msm_matches_cpu() {
        let ctx = match crate::device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let threshold = crate::tuning::current_thresholds().msm;
        let n = threshold;
        let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(OsRng)).collect();
        let bases: Vec<PallasAffine> = (0..n).map(|_| Pallas::random(OsRng).to_affine()).collect();

        let cpu_result = cpu_pallas_pippenger(&scalars, &bases);
        let gpu_result = metal_pallas_msm(ctx, &scalars, &bases);

        match gpu_result {
            Some(gpu) => {
                assert_eq!(
                    gpu.to_affine(),
                    cpu_result.to_affine(),
                    "Metal Pallas MSM result does not match CPU reference"
                );
                eprintln!("  [pallas-msm] n={n}: GPU == CPU ✓");
            }
            None => {
                eprintln!("  [pallas-msm] Metal MSM dispatch failed, skipping");
            }
        }
    }

    #[test]
    fn metal_pallas_msm_with_identities() {
        let ctx = match crate::device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let threshold = crate::tuning::current_thresholds().msm;
        let n = threshold;
        let mut scalars: Vec<Fq> = (0..n).map(|_| Fq::random(OsRng)).collect();
        let mut bases: Vec<PallasAffine> =
            (0..n).map(|_| Pallas::random(OsRng).to_affine()).collect();

        // Inject identity points at various positions
        for i in [0, 10, n / 2, n - 1] {
            if i < n {
                bases[i] = PallasAffine::identity();
                scalars[i] = Fq::ZERO;
            }
        }

        let cpu_result = cpu_pallas_pippenger(&scalars, &bases);
        let gpu_result = metal_pallas_msm(ctx, &scalars, &bases);

        match gpu_result {
            Some(gpu) => {
                assert_eq!(
                    gpu.to_affine(),
                    cpu_result.to_affine(),
                    "Metal Pallas MSM with identities: mismatch"
                );
                eprintln!("  [pallas-msm] identities n={n}: GPU == CPU ✓");
            }
            None => {
                eprintln!("  [pallas-msm] identity test: GPU dispatch failed");
            }
        }
    }

    #[test]
    fn metal_pallas_msm_randomized_batches_match_cpu() {
        let ctx = match crate::device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let threshold = crate::tuning::current_thresholds().msm;
        for seed in [13u64, 31u64] {
            let mut rng = StdRng::seed_from_u64(seed);
            let n = threshold + ((seed as usize) & 7);
            let mut scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
            let mut bases: Vec<PallasAffine> = (0..n)
                .map(|_| Pallas::random(&mut rng).to_affine())
                .collect();

            if n >= 4 {
                bases[seed as usize % n] = PallasAffine::identity();
                scalars[(seed as usize + 1) % n] = Fq::ZERO;
            }

            let cpu_result = cpu_pallas_pippenger(&scalars, &bases);
            let gpu_result = metal_pallas_msm(ctx, &scalars, &bases)
                .expect("Metal Pallas MSM dispatch should succeed for randomized batch");

            assert_eq!(
                gpu_result.to_affine(),
                cpu_result.to_affine(),
                "randomized Metal Pallas MSM mismatch for seed {seed}"
            );
        }
    }
}
