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

//! GPU-accelerated Pippenger MSM dispatch.

use crate::async_dispatch::GpuFuture;
use crate::device::MetalContext;
use crate::launch_contracts::{self, CurveFamily, MsmContractInput, MsmRouteClass};
use crate::msm::bn254;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ff::{AdditiveGroup, BigInt};
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Get the current MSM GPU threshold (device-adaptive).
fn gpu_threshold_val() -> usize {
    crate::tuning::current_thresholds().msm
}

// Batch a few classic windows per dispatch to keep the certified route while
// avoiding pathological command-buffer overhead on larger circuits.
const MAX_MSM_WINDOWS_PER_DISPATCH: u32 = 16;
const BN254_STRICT_MAX_WINDOW_BITS: u32 = 15;

pub fn gpu_threshold() -> usize {
    gpu_threshold_val()
}

#[derive(Debug)]
pub enum Bn254MsmDispatch {
    Metal(G1Projective),
    BelowThreshold,
    Unavailable,
    DispatchFailed(String),
}

fn dispatch_failure_reason(ctx: &MetalContext, fallback: &str) -> String {
    ctx.last_dispatch_failure()
        .unwrap_or_else(|| fallback.to_string())
}

/// Execute the certified classic BN254 MSM route and report whether Metal was
/// actually used, skipped below threshold, unavailable, or failed mid-dispatch.
pub fn metal_msm_dispatch(
    ctx: &MetalContext,
    scalars: &[Fr],
    bases: &[G1Affine],
) -> Bn254MsmDispatch {
    let n = scalars.len();
    if n != bases.len() {
        return Bn254MsmDispatch::DispatchFailed(format!(
            "MSM size mismatch: {} scalars vs {} bases",
            n,
            bases.len()
        ));
    }
    if n < gpu_threshold_val() {
        return Bn254MsmDispatch::BelowThreshold;
    }
    if !ctx.dispatch_allowed() {
        return Bn254MsmDispatch::Unavailable;
    }

    let c = optimal_window_size(n);
    let num_windows = bn254::num_windows(c);
    let num_buckets = bn254::num_buckets(c) as usize;
    if launch_contracts::msm_contract(MsmContractInput {
        kernel: "msm_bucket_acc",
        curve: CurveFamily::Bn254,
        route: MsmRouteClass::Classic,
        point_count: n,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: n * num_windows as usize,
        bucket_entries: num_windows as usize * num_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    })
    .is_err()
    {
        return Bn254MsmDispatch::DispatchFailed(dispatch_failure_reason(
            ctx,
            "metal MSM launch contract rejected the classic BN254 route",
        ));
    }

    match metal_msm_partial(ctx, scalars, bases, c, 0, num_windows) {
        Some(window_results) => Bn254MsmDispatch::Metal(bn254::combine_windows(&window_results, c)),
        None => Bn254MsmDispatch::DispatchFailed(dispatch_failure_reason(
            ctx,
            "metal MSM classic route returned no result",
        )),
    }
}

/// Execute Pippenger MSM on Metal GPU.
///
/// Returns `None` for non-Metal outcomes so existing callers can continue to
/// fall back to CPU without handling the structured dispatch enum directly.
pub fn metal_msm(ctx: &MetalContext, scalars: &[Fr], bases: &[G1Affine]) -> Option<G1Projective> {
    match metal_msm_dispatch(ctx, scalars, bases) {
        Bn254MsmDispatch::Metal(projective) => Some(projective),
        Bn254MsmDispatch::BelowThreshold
        | Bn254MsmDispatch::Unavailable
        | Bn254MsmDispatch::DispatchFailed(_) => None,
    }
}

fn encode_scalar_data(scalars: &[Fr], bases: &[G1Affine]) -> Vec<u64> {
    scalars
        .iter()
        .zip(bases.iter())
        .flat_map(|(scalar, base)| {
            if bn254::is_identity(base) {
                [0u64; 4].into_iter()
            } else {
                bn254::scalar_to_limbs(scalar).into_iter()
            }
        })
        .collect()
}

fn encode_base_coordinates(bases: &[G1Affine]) -> (Vec<u64>, Vec<u64>) {
    let mut bases_x: Vec<u64> = Vec::with_capacity(bases.len() * 4);
    let mut bases_y: Vec<u64> = Vec::with_capacity(bases.len() * 4);
    for base in bases {
        if bn254::is_identity(base) {
            // Identity points are masked out by zeroed scalars, so zero coords are safe.
            bases_x.extend_from_slice(&[0u64; 4]);
            bases_y.extend_from_slice(&[0u64; 4]);
        } else {
            let (x_limbs, y_limbs) = bn254::affine_to_limbs(&base.x, &base.y);
            bases_x.extend_from_slice(&x_limbs);
            bases_y.extend_from_slice(&y_limbs);
        }
    }
    (bases_x, bases_y)
}

/// Convert 12 u64s (GPU projective point) to arkworks G1Projective.
/// Layout: [X(4 limbs), Y(4 limbs), Z(4 limbs)] in Montgomery form.
fn gpu_proj_to_arkworks(data: &[u64]) -> G1Projective {
    // GPU returns Montgomery form — use new_unchecked() which stores directly
    // new() would multiply by R² (double-Montgomerizing), from_bigint() also converts
    let x = Fq::new_unchecked(BigInt::new([data[0], data[1], data[2], data[3]]));
    let y = Fq::new_unchecked(BigInt::new([data[4], data[5], data[6], data[7]]));
    let z = Fq::new_unchecked(BigInt::new([data[8], data[9], data[10], data[11]]));

    if z == Fq::ZERO {
        G1Projective::default() // identity
    } else {
        G1Projective::new_unchecked(x, y, z)
    }
}

/// Execute full Pippenger MSM on Metal GPU, including bucket reduction and window combination.
///
/// Unlike `metal_msm`, this performs ALL phases on GPU — the final readback is just
/// 96 bytes (one G1Projective) instead of ~52MB of bucket data.
pub fn metal_msm_full_gpu(
    ctx: &MetalContext,
    scalars: &[Fr],
    bases: &[G1Affine],
) -> Option<G1Projective> {
    let n = scalars.len();
    if n != bases.len() || n < gpu_threshold_val() {
        return None;
    }

    let msm_lib = ctx.msm_library()?;

    let c = optimal_window_size(n);
    let num_windows = bn254::num_windows(c);
    let num_buckets = bn254::num_buckets(c) as usize;
    let total_buckets = num_windows as usize * num_buckets;
    launch_contracts::msm_contract(MsmContractInput {
        kernel: "msm_window_combine",
        curve: CurveFamily::Bn254,
        route: MsmRouteClass::FullGpu,
        point_count: n,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: n * num_windows as usize,
        bucket_entries: total_buckets * 12,
        window_entries: num_windows as usize * 12,
        final_entries: 12,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: false,
    })
    .ok()?;

    // Prepare GPU buffers (same as metal_msm)
    let mut scalar_data = encode_scalar_data(scalars, bases);
    let scalar_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut scalar_data) } {
        b
    } else {
        ctx.new_buffer_from_slice(&scalar_data)?
    };

    let (mut bases_x, mut bases_y) = encode_base_coordinates(bases);
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

    let map_size = n * num_windows as usize;
    let map_buf = ctx.acquire_buffer(map_size * std::mem::size_of::<u32>())?;
    let bucket_result_size = total_buckets * 12;
    let bucket_buf = ctx.acquire_buffer(bucket_result_size * std::mem::size_of::<u64>())?;

    // Window results buffer (num_windows * 12 u64s)
    let window_buf = ctx.new_buffer(num_windows as usize * 12 * std::mem::size_of::<u64>())?;
    // Final result buffer (12 u64s = one G1Projective)
    let final_buf = ctx.new_buffer(12 * std::mem::size_of::<u64>())?;

    // Phase 1: Bucket assignment
    let assign_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_assign")?;
    let assign_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let n_u32 = n as u32;
        let c_u32 = c;
        let nw_u32 = num_windows;
        let window_offset_u32 = 0u32;

        unsafe {
            enc.setComputePipelineState(&assign_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*scalar_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 3);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 4);
            enc.setBytes_length_atIndex(NonNull::from(&window_offset_u32).cast(), 4, 5);

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

    // Phase 2: Bucket accumulation
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

    // Phase 3: GPU bucket reduction (all windows in parallel)
    let reduce_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_reduce")?;
    let reduce_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let nb_u32 = num_buckets as u32;
        let nw_u32 = num_windows;

        unsafe {
            enc.setComputePipelineState(&reduce_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*bucket_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*window_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&nb_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 3);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_windows as usize,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: 1,
                    height: 1,
                    depth: 1,
                },
            );
        }
        enc.endEncoding();
        GpuFuture::submit_labeled(cmd, "msm")
    };
    reduce_future.wait_checked().ok()?;

    // Phase 4: GPU window combination (single thread, Horner's method)
    let combine_pipeline = ctx.pipeline_from_library(msm_lib, "msm_window_combine")?;
    let combine_future = {
        let cmd = ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;
        let nw_u32 = num_windows;
        let c_u32 = c;

        unsafe {
            enc.setComputePipelineState(&combine_pipeline);
            enc.setBuffer_offset_atIndex(Some(&*window_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*final_buf), 0, 1);
            enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 2);
            enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 3);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: 1,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: 1,
                    height: 1,
                    depth: 1,
                },
            );
        }
        enc.endEncoding();
        GpuFuture::submit_labeled(cmd, "msm")
    };
    combine_future.wait_checked().ok()?;

    // Read back just 96 bytes (12 u64s = one G1Projective)
    let final_data: Vec<u64> = ctx.read_buffer(&final_buf, 12);
    Some(gpu_proj_to_arkworks(&final_data))
}

/// CPU Pippenger implementation (reference + fallback).
pub fn cpu_pippenger(scalars: &[Fr], bases: &[G1Affine]) -> G1Projective {
    let c = optimal_window_size(scalars.len());
    let num_windows = bn254::num_windows(c);
    let num_buckets = bn254::num_buckets(c) as usize;

    let mut window_results: Vec<G1Projective> = Vec::with_capacity(num_windows as usize);

    for w in 0..num_windows {
        let mut buckets = vec![G1Projective::default(); num_buckets];

        for (scalar, base) in scalars.iter().zip(bases.iter()) {
            let limbs = bn254::scalar_to_limbs(scalar);
            let bucket_idx = extract_window(&limbs, w, c) as usize;
            if bucket_idx != 0 {
                buckets[bucket_idx] += G1Projective::from(*base);
            }
        }

        window_results.push(bn254::bucket_reduce_window(&buckets));
    }

    bn254::combine_windows(&window_results, c)
}

/// Hybrid CPU+GPU MSM: GPU handles bucket assignment and accumulation,
/// CPU works on the highest windows in parallel.
///
/// Splits MSM windows — GPU handles windows 0 to split-1,
/// CPU handles split to num_windows-1 via std::thread::spawn.
/// Combines results after both complete.
pub fn metal_msm_hybrid(
    ctx: &MetalContext,
    scalars: &[Fr],
    bases: &[G1Affine],
) -> Option<G1Projective> {
    let n = scalars.len();
    if n != bases.len() || n < gpu_threshold_val() {
        return None;
    }

    let c = optimal_window_size(n);
    let num_windows = bn254::num_windows(c) as usize;

    // Split: GPU takes lower 2/3 of windows, CPU takes upper 1/3
    let gpu_windows = (num_windows * 2 / 3).max(1);
    let cpu_windows = num_windows - gpu_windows;

    if cpu_windows == 0 {
        return metal_msm(ctx, scalars, bases);
    }
    let num_buckets = bn254::num_buckets(c) as usize;
    launch_contracts::msm_contract(MsmContractInput {
        kernel: "msm_bucket_acc",
        curve: CurveFamily::Bn254,
        route: MsmRouteClass::Hybrid,
        point_count: n,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: n * gpu_windows,
        bucket_entries: gpu_windows * num_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows: gpu_windows as u32,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: false,
    })
    .ok()?;
    std::thread::scope(|scope| {
        // Borrow the live slices instead of cloning the full proving inputs.
        let cpu_handle = scope.spawn(|| {
            let mut window_results: Vec<G1Projective> = Vec::with_capacity(cpu_windows);
            for w in gpu_windows..num_windows {
                let mut buckets = vec![G1Projective::default(); num_buckets];
                for (scalar, base) in scalars.iter().zip(bases.iter()) {
                    let limbs = bn254::scalar_to_limbs(scalar);
                    let bucket_idx = extract_window(&limbs, w as u32, c) as usize;
                    if bucket_idx != 0 {
                        buckets[bucket_idx] += G1Projective::from(*base);
                    }
                }
                window_results.push(bn254::bucket_reduce_window(&buckets));
            }
            window_results
        });

        // GPU handles lower windows via the standard pipeline.
        let gpu_result = metal_msm_partial(ctx, scalars, bases, c, 0, gpu_windows as u32);
        let cpu_result = cpu_handle.join().ok()?;

        let mut all_windows = gpu_result?;
        all_windows.extend(cpu_result);

        Some(bn254::combine_windows(&all_windows, c))
    })
}

/// Run GPU MSM for only the first `max_windows` windows.
fn metal_msm_partial(
    ctx: &MetalContext,
    scalars: &[Fr],
    bases: &[G1Affine],
    c: u32,
    window_offset: u32,
    max_windows: u32,
) -> Option<Vec<G1Projective>> {
    let n = scalars.len();
    let msm_lib = ctx.msm_library()?;

    let num_windows = max_windows;
    let num_buckets = bn254::num_buckets(c) as usize;

    let mut scalar_data = encode_scalar_data(scalars, bases);
    let scalar_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut scalar_data) } {
        b
    } else {
        ctx.new_buffer_from_slice(&scalar_data)?
    };

    let (mut bases_x, mut bases_y) = encode_base_coordinates(bases);
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

    let assign_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_assign")?;
    let acc_pipeline = ctx.pipeline_from_library(msm_lib, "msm_bucket_acc")?;
    let mut window_results: Vec<G1Projective> = Vec::with_capacity(num_windows as usize);
    let batch_windows = MAX_MSM_WINDOWS_PER_DISPATCH.max(1);

    for batch_start in (0..num_windows).step_by(batch_windows as usize) {
        let batch_windows = (num_windows - batch_start).min(batch_windows);
        let batch_total_buckets = batch_windows as usize * num_buckets;
        let map_buf =
            ctx.acquire_buffer(n * batch_windows as usize * std::mem::size_of::<u32>())?;
        let bucket_buf =
            ctx.acquire_buffer(batch_total_buckets * 12 * std::mem::size_of::<u64>())?;

        let assign_future = {
            let cmd = ctx.command_buffer()?;
            let enc = cmd.computeCommandEncoder()?;
            let n_u32 = n as u32;
            let c_u32 = c;
            let nw_u32 = batch_windows;
            let window_offset_u32 = window_offset + batch_start;

            unsafe {
                enc.setComputePipelineState(&assign_pipeline);
                enc.setBuffer_offset_atIndex(Some(&*scalar_buf), 0, 0);
                enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 1);
                enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 2);
                enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 3);
                enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 4);
                enc.setBytes_length_atIndex(NonNull::from(&window_offset_u32).cast(), 4, 5);

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

        let acc_future = {
            let cmd = ctx.command_buffer()?;
            let enc = cmd.computeCommandEncoder()?;
            let n_u32 = n as u32;
            let c_u32 = c;
            let nw_u32 = batch_windows;

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
                let num_groups = batch_total_buckets.div_ceil(max_threads);
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

        let bucket_data: Vec<u64> = ctx.read_buffer(&bucket_buf, batch_total_buckets * 12);
        for w in 0..batch_windows as usize {
            let mut buckets: Vec<G1Projective> = Vec::with_capacity(num_buckets);
            for b in 0..num_buckets {
                let offset = (w * num_buckets + b) * 12;
                let proj = gpu_proj_to_arkworks(&bucket_data[offset..offset + 12]);
                buckets.push(proj);
            }
            window_results.push(bn254::bucket_reduce_window(&buckets));
        }
    }

    Some(window_results)
}

pub(crate) fn optimal_window_size(n: usize) -> u32 {
    if n < 1 << 12 {
        8
    } else if n < 1 << 16 {
        12
    } else {
        // The certified BN254 strict lane explicitly excludes c=16. Large-window
        // variants remain outside the admitted surface until their auxiliary
        // kernels are promoted from attested-only to theorem-backed.
        BN254_STRICT_MAX_WINDOW_BITS
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
    use ark_bn254::G1Projective;
    use ark_ec::CurveGroup;

    #[test]
    fn test_extract_window() {
        let limbs = [0xDEADBEEFCAFEBABEu64, 0x1234567890ABCDEFu64, 0, 0];
        assert_eq!(extract_window(&limbs, 0, 8), 0xBE);
        assert_eq!(extract_window(&limbs, 1, 8), 0xBA);
    }

    #[test]
    fn test_optimal_window_size() {
        assert_eq!(optimal_window_size(100), 8);
        assert_eq!(optimal_window_size(1 << 18), BN254_STRICT_MAX_WINDOW_BITS);
        assert_eq!(optimal_window_size(1 << 22), BN254_STRICT_MAX_WINDOW_BITS);
    }

    #[test]
    fn strict_lane_window_schedule_excludes_c16() {
        for n in [1usize, 1 << 12, 1 << 16, 1 << 20, 1 << 24] {
            assert!(optimal_window_size(n) <= BN254_STRICT_MAX_WINDOW_BITS);
        }
    }

    #[test]
    fn cpu_pippenger_small() {
        // Test CPU pippenger with known values
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();

        let n = 64;
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        // Naive MSM for reference
        let expected: G1Projective = scalars
            .iter()
            .zip(bases.iter())
            .map(|(s, b)| G1Projective::from(*b) * s)
            .sum();

        let result = cpu_pippenger(&scalars, &bases);
        assert_eq!(result.into_affine(), expected.into_affine());
    }

    /// Test GPU by reading raw bucket data for trivial MSM
    #[test]
    fn metal_msm_dispatch_reports_below_threshold() {
        use crate::device;
        use ark_ec::AffineRepr;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let n = gpu_threshold_val().saturating_sub(1).max(1);
        let scalars = vec![Fr::from(1u64); n];
        let bases = vec![G1Affine::generator(); n];

        assert!(matches!(
            metal_msm_dispatch(ctx, &scalars, &bases),
            Bn254MsmDispatch::BelowThreshold
        ));
    }

    #[test]
    fn metal_msm_dispatch_reports_metal_success() {
        use crate::device;
        use ark_ff::UniformRand;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };
        if !ctx.dispatch_allowed() {
            eprintln!("Metal dispatch circuit is open, skipping");
            return;
        }

        let mut rng = ark_std::test_rng();
        let n = gpu_threshold_val();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let cpu_result = cpu_pippenger(&scalars, &bases);

        match metal_msm_dispatch(ctx, &scalars, &bases) {
            Bn254MsmDispatch::Metal(gpu_result) => {
                assert_eq!(gpu_result.into_affine(), cpu_result.into_affine());
            }
            other => panic!("expected Metal dispatch result, got {other:?}"),
        }
    }

    #[test]
    fn metal_msm_trivial() {
        use crate::device;
        use ark_ec::{AffineRepr, CurveGroup};

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        // Use the generator point with scalar = 1
        let generator = G1Affine::generator();
        let one = Fr::from(1u64);

        // Create enough points to hit threshold
        let n = gpu_threshold_val();
        let mut scalars = vec![Fr::from(0u64); n];
        let bases = vec![generator; n];
        scalars[0] = one;

        let gpu_result = metal_msm(ctx, &scalars, &bases);
        match gpu_result {
            Some(gpu) => {
                assert_eq!(gpu.into_affine(), generator, "1*G should equal G");
            }
            None => {
                eprintln!("Metal MSM dispatch failed");
            }
        }
    }

    #[test]
    fn metal_msm_hybrid_matches_cpu() {
        use crate::device;
        use ark_ec::CurveGroup;
        use ark_ff::UniformRand;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let mut rng = ark_std::test_rng();
        let n = gpu_threshold_val();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        let cpu_result = cpu_pippenger(&scalars, &bases);
        let hybrid_result = metal_msm_hybrid(ctx, &scalars, &bases);

        match hybrid_result {
            Some(hybrid) => {
                assert_eq!(
                    hybrid.into_affine(),
                    cpu_result.into_affine(),
                    "Hybrid Metal MSM result does not match CPU reference"
                );
            }
            None => {
                eprintln!("Hybrid MSM dispatch failed, skipping");
            }
        }
    }

    #[test]
    fn metal_msm_matches_cpu() {
        use crate::device;
        use ark_ec::CurveGroup;
        use ark_ff::UniformRand;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let mut rng = ark_std::test_rng();
        // Use gpu_threshold_val() to force GPU path
        let n = gpu_threshold_val();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        let cpu_result = cpu_pippenger(&scalars, &bases);
        let gpu_result = metal_msm(ctx, &scalars, &bases);

        match gpu_result {
            Some(gpu) => {
                assert_eq!(
                    gpu.into_affine(),
                    cpu_result.into_affine(),
                    "Metal MSM result does not match CPU reference"
                );
            }
            None => {
                eprintln!("Metal MSM dispatch failed, skipping comparison");
            }
        }
    }

    #[test]
    fn metal_msm_with_identities() {
        use crate::device;
        use ark_ec::CurveGroup;
        use ark_ff::UniformRand;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let mut rng = ark_std::test_rng();
        let n = gpu_threshold_val();
        let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let mut bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        for i in [0, 10, n / 2, n - 1] {
            if i < n {
                bases[i] = G1Affine::identity();
                scalars[i] = Fr::ZERO;
            }
        }

        let cpu_result = cpu_pippenger(&scalars, &bases);
        let gpu_result = metal_msm(ctx, &scalars, &bases);

        match gpu_result {
            Some(gpu) => {
                assert_eq!(
                    gpu.into_affine(),
                    cpu_result.into_affine(),
                    "Metal MSM with identities does not match CPU reference"
                );
            }
            None => {
                eprintln!("Metal MSM identity dispatch failed, skipping comparison");
            }
        }
    }

    #[test]
    #[ignore = "full-GPU BN254 reduction path remains experimental; certified production uses metal_msm"]
    fn metal_msm_full_gpu_with_identities() {
        use crate::device;
        use ark_ec::CurveGroup;
        use ark_ff::UniformRand;

        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU available, skipping");
                return;
            }
        };

        let mut rng = ark_std::test_rng();
        let n = gpu_threshold_val();
        let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let mut bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        for i in [0, 10, n / 2, n - 1] {
            if i < n {
                bases[i] = G1Affine::identity();
                scalars[i] = Fr::ZERO;
            }
        }

        let cpu_result = cpu_pippenger(&scalars, &bases);
        let gpu_result = metal_msm_full_gpu(ctx, &scalars, &bases);

        match gpu_result {
            Some(gpu) => {
                assert_eq!(
                    gpu.into_affine(),
                    cpu_result.into_affine(),
                    "Full-GPU Metal MSM with identities does not match CPU reference"
                );
            }
            None => {
                eprintln!("Full-GPU Metal MSM identity dispatch failed, skipping comparison");
            }
        }
    }
}
