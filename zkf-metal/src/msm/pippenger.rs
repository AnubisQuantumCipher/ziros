//! GPU-accelerated Pippenger MSM dispatch.

use crate::async_dispatch::GpuFuture;
use crate::device::MetalContext;
use crate::launch_contracts::{
    self, CurveFamily, MsmContractInput, MsmRouteClass, MsmSegmentReduceContractInput,
    MsmSegmentedAccumulateContractInput,
};
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

const BN254_STRICT_MAX_WINDOW_BITS: u32 = 15;
const BN254_SEGMENT_MERGE_BUFFER_CAP_BYTES: usize = 1 << 30;

pub fn gpu_threshold() -> usize {
    gpu_threshold_val()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bn254MsmTelemetry {
    pub batch_windows_per_dispatch: u32,
    pub segment_count: usize,
    pub points_per_segment: usize,
    pub segment_bucket_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClassicSegmentPlan {
    segment_count: usize,
    points_per_segment: usize,
    segment_bucket_bytes: usize,
}

#[derive(Debug)]
pub enum Bn254MsmDispatch {
    Metal {
        projective: G1Projective,
        telemetry: Bn254MsmTelemetry,
    },
    BelowThreshold,
    Unavailable,
    DispatchFailed {
        detail: String,
        telemetry: Option<Bn254MsmTelemetry>,
    },
}

fn dispatch_failure_reason(ctx: &MetalContext, fallback: &str) -> String {
    ctx.last_dispatch_failure()
        .unwrap_or_else(|| fallback.to_string())
}

fn parse_env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|value| *value > 0)
}

fn parse_env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
}

fn parse_env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn configured_max_windows_per_dispatch() -> u32 {
    parse_env_u32("ZKF_METAL_MSM_MAX_WINDOWS_PER_DISPATCH")
        .unwrap_or_else(|| crate::tuning::current_throughput_config().msm_max_windows_per_dispatch)
        .max(1)
}

fn configured_point_bucket_work_budget() -> u64 {
    parse_env_u64("ZKF_METAL_MSM_POINT_BUCKET_WORK_BUDGET")
        .unwrap_or(crate::tuning::current_throughput_config().msm_point_bucket_work_budget)
        .max(1)
}

fn configured_segment_point_bucket_work_budget() -> u64 {
    parse_env_u64("ZKF_METAL_MSM_SEGMENT_POINT_BUCKET_WORK_BUDGET")
        .unwrap_or(crate::tuning::current_throughput_config().msm_segment_point_bucket_work_budget)
        .max(1)
}

fn configured_max_points_per_segment() -> usize {
    parse_env_usize("ZKF_METAL_MSM_MAX_POINTS_PER_SEGMENT")
        .unwrap_or(crate::tuning::current_throughput_config().msm_max_points_per_segment)
        .max(1)
}

fn classic_msm_resident_bytes(point_count: usize) -> usize {
    point_count
        .saturating_mul(12)
        .saturating_mul(std::mem::size_of::<u64>())
}

fn classic_msm_per_window_bytes(point_count: usize, num_buckets: usize) -> usize {
    point_count
        .saturating_mul(std::mem::size_of::<u32>())
        .saturating_add(
            num_buckets
                .saturating_mul(12)
                .saturating_mul(std::mem::size_of::<u64>()),
        )
}

fn classic_msm_point_bucket_work(point_count: usize, num_buckets: usize, windows: u32) -> u64 {
    (point_count as u64)
        .saturating_mul(num_buckets as u64)
        .saturating_mul(windows as u64)
}

fn classic_segment_bucket_bytes(
    segment_count: usize,
    batch_windows: u32,
    num_buckets: usize,
) -> usize {
    segment_count
        .saturating_mul(batch_windows as usize)
        .saturating_mul(num_buckets)
        .saturating_mul(12)
        .saturating_mul(std::mem::size_of::<u64>())
}

fn usable_msm_encoder_budget_bytes(ctx: &MetalContext) -> Option<usize> {
    let pct = crate::tuning::current_throughput_config().working_set_headroom_target_pct as usize;
    ctx.working_set_headroom()
        .or_else(|| ctx.recommended_working_set_size())
        .map(|budget| budget.saturating_mul(pct) / 100)
}

fn usable_msm_merge_buffer_cap_bytes(ctx: &MetalContext) -> usize {
    usable_msm_encoder_budget_bytes(ctx)
        .map(|budget| {
            budget
                .saturating_div(8)
                .min(BN254_SEGMENT_MERGE_BUFFER_CAP_BYTES)
        })
        .unwrap_or(BN254_SEGMENT_MERGE_BUFFER_CAP_BYTES)
        .max(12 * std::mem::size_of::<u64>())
}

fn plan_classic_dispatch_batch_windows(
    point_count: usize,
    num_buckets: usize,
    total_windows: u32,
    max_windows_per_dispatch: u32,
    point_bucket_work_budget: u64,
    encoder_budget_bytes: Option<usize>,
) -> Result<u32, String> {
    let capped_total_windows = total_windows.max(1);
    let capped_max_windows = max_windows_per_dispatch.max(1).min(capped_total_windows);
    let resident_bytes = classic_msm_resident_bytes(point_count);
    let per_window_bytes = classic_msm_per_window_bytes(point_count, num_buckets).max(1);
    let single_window_work = classic_msm_point_bucket_work(point_count, num_buckets, 1);

    if let Some(budget) = encoder_budget_bytes {
        let single_window_bytes = resident_bytes.saturating_add(per_window_bytes);
        if single_window_bytes > budget {
            return Err(format!(
                "metal MSM pre-admission rejected the classic BN254 route: one-window encoder footprint {} bytes exceeds working-set budget {} bytes (point_count={}, num_buckets={})",
                single_window_bytes, budget, point_count, num_buckets
            ));
        }
    }

    let work_limited = if single_window_work > point_bucket_work_budget {
        1
    } else {
        ((point_bucket_work_budget / single_window_work.max(1)).clamp(1, capped_max_windows as u64))
            as u32
    };
    let memory_limited = encoder_budget_bytes
        .map(|budget| {
            if budget <= resident_bytes {
                1
            } else {
                ((budget.saturating_sub(resident_bytes) / per_window_bytes)
                    .clamp(1, capped_max_windows as usize)) as u32
            }
        })
        .unwrap_or(capped_max_windows);

    Ok(capped_max_windows
        .min(work_limited)
        .min(memory_limited)
        .max(1))
}

fn plan_classic_point_segments(
    point_count: usize,
    num_buckets: usize,
    batch_windows: u32,
    segment_point_bucket_work_budget: u64,
    max_points_per_segment: usize,
    merge_buffer_cap_bytes: usize,
) -> Result<ClassicSegmentPlan, String> {
    let points_from_budget =
        (segment_point_bucket_work_budget / (num_buckets as u64).max(1)).max(1) as usize;
    let points_per_segment = point_count
        .min(max_points_per_segment.max(1))
        .min(points_from_budget.max(1))
        .max(1);
    let segment_count = point_count.div_ceil(points_per_segment);
    let segment_bucket_bytes =
        classic_segment_bucket_bytes(segment_count, batch_windows.max(1), num_buckets);

    if segment_bucket_bytes > merge_buffer_cap_bytes {
        return Err(format!(
            "metal MSM pre-admission rejected the segmented classic BN254 route: segment bucket buffer {} bytes exceeds merge cap {} bytes (segment_count={}, points_per_segment={}, batch_windows={}, num_buckets={})",
            segment_bucket_bytes,
            merge_buffer_cap_bytes,
            segment_count,
            points_per_segment,
            batch_windows,
            num_buckets,
        ));
    }

    Ok(ClassicSegmentPlan {
        segment_count,
        points_per_segment,
        segment_bucket_bytes,
    })
}

fn telemetry_for_batch(
    batch_windows_per_dispatch: u32,
    plan: ClassicSegmentPlan,
) -> Bn254MsmTelemetry {
    Bn254MsmTelemetry {
        batch_windows_per_dispatch,
        segment_count: plan.segment_count,
        points_per_segment: plan.points_per_segment,
        segment_bucket_bytes: plan.segment_bucket_bytes,
    }
}

fn classic_dispatch_batch_windows_for_context(
    ctx: &MetalContext,
    point_count: usize,
    c: u32,
    total_windows: u32,
) -> Result<u32, String> {
    let num_buckets = bn254::num_buckets(c) as usize;
    plan_classic_dispatch_batch_windows(
        point_count,
        num_buckets,
        total_windows,
        configured_max_windows_per_dispatch(),
        configured_point_bucket_work_budget(),
        usable_msm_encoder_budget_bytes(ctx),
    )
}

fn classic_segment_plan_for_context(
    ctx: &MetalContext,
    point_count: usize,
    num_buckets: usize,
    batch_windows: u32,
) -> Result<ClassicSegmentPlan, String> {
    plan_classic_point_segments(
        point_count,
        num_buckets,
        batch_windows,
        configured_segment_point_bucket_work_budget(),
        configured_max_points_per_segment(),
        usable_msm_merge_buffer_cap_bytes(ctx),
    )
}

fn wait_checked_or_dispatch_failure(
    future: &GpuFuture,
    ctx: &MetalContext,
    fallback: &str,
) -> Result<(), String> {
    future
        .wait_checked()
        .map(|_| ())
        .map_err(|_| dispatch_failure_reason(ctx, fallback))
}

fn decode_bucket_results(
    ctx: &MetalContext,
    bucket_buf: &objc2::runtime::ProtocolObject<dyn objc2_metal::MTLBuffer>,
    batch_windows: u32,
    num_buckets: usize,
) -> Vec<G1Projective> {
    let bucket_data: Vec<u64> =
        ctx.read_buffer(bucket_buf, batch_windows as usize * num_buckets * 12);
    let mut window_results = Vec::with_capacity(batch_windows as usize);
    for w in 0..batch_windows as usize {
        let mut buckets: Vec<G1Projective> = Vec::with_capacity(num_buckets);
        for b in 0..num_buckets {
            let offset = (w * num_buckets + b) * 12;
            buckets.push(gpu_proj_to_arkworks(&bucket_data[offset..offset + 12]));
        }
        window_results.push(bn254::bucket_reduce_window(&buckets));
    }
    window_results
}

fn decode_segmented_bucket_results(
    ctx: &MetalContext,
    segment_bucket_buf: &objc2::runtime::ProtocolObject<dyn objc2_metal::MTLBuffer>,
    segment_count: usize,
    batch_windows: u32,
    num_buckets: usize,
) -> Vec<G1Projective> {
    let batch_total_buckets = batch_windows as usize * num_buckets;
    let segment_bucket_data: Vec<u64> =
        ctx.read_buffer(segment_bucket_buf, segment_count * batch_total_buckets * 12);
    let mut window_results = Vec::with_capacity(batch_windows as usize);
    for w in 0..batch_windows as usize {
        let mut buckets: Vec<G1Projective> = vec![G1Projective::default(); num_buckets];
        for segment_index in 0..segment_count {
            let segment_base = segment_index * batch_total_buckets * 12;
            for b in 0..num_buckets {
                let offset = segment_base + (w * num_buckets + b) * 12;
                buckets[b] += gpu_proj_to_arkworks(&segment_bucket_data[offset..offset + 12]);
            }
        }
        window_results.push(bn254::bucket_reduce_window(&buckets));
    }
    window_results
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
        return Bn254MsmDispatch::DispatchFailed {
            detail: format!("MSM size mismatch: {} scalars vs {} bases", n, bases.len()),
            telemetry: None,
        };
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
    let batch_windows_per_dispatch =
        match classic_dispatch_batch_windows_for_context(ctx, n, c, num_windows) {
            Ok(batch_windows) => batch_windows,
            Err(detail) => {
                return Bn254MsmDispatch::DispatchFailed {
                    detail,
                    telemetry: None,
                };
            }
        };
    let batch_segment_plan =
        match classic_segment_plan_for_context(ctx, n, num_buckets, batch_windows_per_dispatch) {
            Ok(plan) => plan,
            Err(detail) => {
                return Bn254MsmDispatch::DispatchFailed {
                    detail,
                    telemetry: None,
                };
            }
        };
    let telemetry = telemetry_for_batch(batch_windows_per_dispatch, batch_segment_plan);

    match metal_msm_partial(
        ctx,
        scalars,
        bases,
        c,
        0,
        num_windows,
        batch_windows_per_dispatch,
    ) {
        Ok(window_results) => Bn254MsmDispatch::Metal {
            projective: bn254::combine_windows(&window_results, c),
            telemetry,
        },
        Err(detail) => Bn254MsmDispatch::DispatchFailed {
            detail,
            telemetry: Some(telemetry),
        },
    }
}

/// Execute Pippenger MSM on Metal GPU.
///
/// Returns `None` for non-Metal outcomes so existing callers can continue to
/// fall back to CPU without handling the structured dispatch enum directly.
pub fn metal_msm(ctx: &MetalContext, scalars: &[Fr], bases: &[G1Affine]) -> Option<G1Projective> {
    match metal_msm_dispatch(ctx, scalars, bases) {
        Bn254MsmDispatch::Metal { projective, .. } => Some(projective),
        Bn254MsmDispatch::BelowThreshold
        | Bn254MsmDispatch::Unavailable
        | Bn254MsmDispatch::DispatchFailed { .. } => None,
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
        let gpu_result = metal_msm_partial(
            ctx,
            scalars,
            bases,
            c,
            0,
            gpu_windows as u32,
            gpu_windows as u32,
        );
        let cpu_result = cpu_handle.join().ok()?;

        let mut all_windows = gpu_result.ok()?;
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
    max_windows_per_dispatch: u32,
) -> Result<Vec<G1Projective>, String> {
    let n = scalars.len();
    let msm_lib = ctx
        .msm_library()
        .ok_or_else(|| "Metal MSM library is unavailable".to_string())?;

    let num_windows = max_windows;
    let num_buckets = bn254::num_buckets(c) as usize;

    let mut scalar_data = encode_scalar_data(scalars, bases);
    let scalar_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut scalar_data) } {
        b
    } else {
        ctx.new_buffer_from_slice(&scalar_data)
            .ok_or_else(|| "failed to allocate Metal scalar buffer".to_string())?
    };

    let (mut bases_x, mut bases_y) = encode_base_coordinates(bases);
    let bases_x_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_x) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_x)
            .ok_or_else(|| "failed to allocate Metal bases_x buffer".to_string())?
    };
    let bases_y_buf = if let Some(b) = unsafe { ctx.new_buffer_no_copy(&mut bases_y) } {
        b
    } else {
        ctx.new_buffer_from_slice(&bases_y)
            .ok_or_else(|| "failed to allocate Metal bases_y buffer".to_string())?
    };

    let assign_pipeline = ctx
        .pipeline_from_library(msm_lib, "msm_bucket_assign")
        .ok_or_else(|| "failed to load msm_bucket_assign pipeline".to_string())?;
    let acc_pipeline = ctx
        .pipeline_from_library(msm_lib, "msm_bucket_acc")
        .ok_or_else(|| "failed to load msm_bucket_acc pipeline".to_string())?;
    let acc_segmented_pipeline = ctx
        .pipeline_from_library(msm_lib, "msm_bucket_acc_segmented")
        .ok_or_else(|| "failed to load msm_bucket_acc_segmented pipeline".to_string())?;
    let mut window_results: Vec<G1Projective> = Vec::with_capacity(num_windows as usize);
    let batch_window_cap = max_windows_per_dispatch.max(1);

    for batch_start in (0..num_windows).step_by(batch_window_cap as usize) {
        let batch_windows = (num_windows - batch_start).min(batch_window_cap);
        let batch_total_buckets = batch_windows as usize * num_buckets;
        let batch_segment_plan =
            classic_segment_plan_for_context(ctx, n, num_buckets, batch_windows)?;
        let batch_telemetry = telemetry_for_batch(batch_windows, batch_segment_plan);
        let map_buf = ctx
            .acquire_buffer(n * batch_windows as usize * std::mem::size_of::<u32>())
            .ok_or_else(|| "failed to acquire Metal bucket map buffer".to_string())?;
        let bucket_buf = ctx
            .acquire_buffer(batch_total_buckets * 12 * std::mem::size_of::<u64>())
            .ok_or_else(|| "failed to acquire Metal bucket buffer".to_string())?;
        let segment_bucket_buf = if batch_segment_plan.segment_count > 1 {
            Some(
                ctx.acquire_buffer(batch_segment_plan.segment_bucket_bytes)
                    .ok_or_else(|| {
                        format!(
                            "failed to acquire Metal segment bucket buffer (segment_bucket_bytes={})",
                            batch_segment_plan.segment_bucket_bytes
                        )
                    })?,
            )
        } else {
            None
        };
        let assign_future = {
            let cmd = ctx.command_buffer().ok_or_else(|| {
                "failed to allocate Metal command buffer for bucket assignment".to_string()
            })?;
            let enc = cmd.computeCommandEncoder().ok_or_else(|| {
                "failed to allocate Metal compute encoder for bucket assignment".to_string()
            })?;
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
        wait_checked_or_dispatch_failure(
            &assign_future,
            ctx,
            "metal MSM bucket assignment failed",
        )?;

        if batch_segment_plan.segment_count == 1 {
            launch_contracts::msm_contract(MsmContractInput {
                kernel: "msm_bucket_acc",
                curve: CurveFamily::Bn254,
                route: MsmRouteClass::Classic,
                point_count: n,
                scalar_limbs: 4,
                base_coordinate_limbs: 4,
                map_entries: n * batch_windows as usize,
                bucket_entries: batch_total_buckets * 12,
                window_entries: 0,
                final_entries: 0,
                num_windows: batch_windows,
                num_buckets,
                max_threads_per_group: 256,
                certified_route: true,
            })
            .map_err(|err| err.detail)?;

            let acc_future = {
                let cmd = ctx.command_buffer().ok_or_else(|| {
                    "failed to allocate Metal command buffer for bucket accumulation".to_string()
                })?;
                let enc = cmd.computeCommandEncoder().ok_or_else(|| {
                    "failed to allocate Metal compute encoder for bucket accumulation".to_string()
                })?;
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
            wait_checked_or_dispatch_failure(
                &acc_future,
                ctx,
                "metal MSM bucket accumulation failed",
            )?;
        } else {
            for segment_index in 0..batch_segment_plan.segment_count {
                let point_start =
                    segment_index.saturating_mul(batch_segment_plan.points_per_segment);
                let segment_point_count =
                    (n.saturating_sub(point_start)).min(batch_segment_plan.points_per_segment);
                launch_contracts::msm_segmented_accumulate_contract(
                    MsmSegmentedAccumulateContractInput {
                        kernel: "msm_bucket_acc_segmented",
                        curve: CurveFamily::Bn254,
                        route: MsmRouteClass::Classic,
                        point_count: n,
                        point_start,
                        segment_point_count,
                        base_coordinate_limbs: 4,
                        map_entries: n * batch_windows as usize,
                        bucket_entries: batch_total_buckets * 12,
                        num_windows: batch_windows,
                        num_buckets,
                        max_threads_per_group: 256,
                        certified_route: true,
                    },
                )
                .map_err(|err| {
                    format!(
                        "{} (segment_index={}, point_start={}, point_count={}, segment_count={}, points_per_segment={}, segment_bucket_bytes={})",
                        err.detail,
                        segment_index,
                        point_start,
                        segment_point_count,
                        batch_telemetry.segment_count,
                        batch_telemetry.points_per_segment,
                        batch_telemetry.segment_bucket_bytes,
                    )
                })?;

                let target_buffer = segment_bucket_buf.as_ref().unwrap_or(&bucket_buf);
                let target_offset = segment_index
                    .saturating_mul(batch_total_buckets)
                    .saturating_mul(12)
                    .saturating_mul(std::mem::size_of::<u64>());
                let acc_future = {
                    let cmd = ctx.command_buffer().ok_or_else(|| {
                        format!(
                            "failed to allocate Metal command buffer for segmented bucket accumulation (segment_index={segment_index})"
                        )
                    })?;
                    let enc = cmd.computeCommandEncoder().ok_or_else(|| {
                        format!(
                            "failed to allocate Metal compute encoder for segmented bucket accumulation (segment_index={segment_index})"
                        )
                    })?;
                    let n_u32 = n as u32;
                    let c_u32 = c;
                    let nw_u32 = batch_windows;
                    let point_start_u32 = point_start as u32;
                    let segment_point_count_u32 = segment_point_count as u32;

                    unsafe {
                        enc.setComputePipelineState(&acc_segmented_pipeline);
                        enc.setBuffer_offset_atIndex(Some(&*bases_x_buf), 0, 0);
                        enc.setBuffer_offset_atIndex(Some(&*bases_y_buf), 0, 1);
                        enc.setBuffer_offset_atIndex(Some(&*map_buf), 0, 2);
                        enc.setBuffer_offset_atIndex(Some(&**target_buffer), target_offset, 3);
                        enc.setBytes_length_atIndex(NonNull::from(&n_u32).cast(), 4, 4);
                        enc.setBytes_length_atIndex(NonNull::from(&c_u32).cast(), 4, 5);
                        enc.setBytes_length_atIndex(NonNull::from(&nw_u32).cast(), 4, 6);
                        enc.setBytes_length_atIndex(NonNull::from(&point_start_u32).cast(), 4, 7);
                        enc.setBytes_length_atIndex(
                            NonNull::from(&segment_point_count_u32).cast(),
                            4,
                            8,
                        );

                        let max_threads = acc_segmented_pipeline
                            .maxTotalThreadsPerThreadgroup()
                            .min(256);
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
                wait_checked_or_dispatch_failure(
                    &acc_future,
                    ctx,
                    &format!(
                        "metal MSM segmented bucket accumulation failed (segment_index={}, point_start={}, point_count={}, segment_count={}, points_per_segment={}, segment_bucket_bytes={})",
                        segment_index,
                        point_start,
                        segment_point_count,
                        batch_telemetry.segment_count,
                        batch_telemetry.points_per_segment,
                        batch_telemetry.segment_bucket_bytes,
                    ),
                )?;
            }
        }

        if let Some(segment_bucket_buf) = segment_bucket_buf.as_ref() {
            launch_contracts::msm_segment_reduce_contract(MsmSegmentReduceContractInput {
                kernel: "msm_bucket_segment_reduce",
                curve: CurveFamily::Bn254,
                route: MsmRouteClass::Classic,
                segment_count: batch_segment_plan.segment_count,
                segment_bucket_entries: batch_segment_plan.segment_bucket_bytes
                    / std::mem::size_of::<u64>(),
                bucket_entries: batch_total_buckets * 12,
                num_windows: batch_windows,
                num_buckets,
                max_threads_per_group: 256,
                certified_route: true,
            })
            .map_err(|err| {
                format!(
                    "{} (segment_count={}, points_per_segment={}, segment_bucket_bytes={})",
                    err.detail,
                    batch_telemetry.segment_count,
                    batch_telemetry.points_per_segment,
                    batch_telemetry.segment_bucket_bytes,
                )
            })?;
            window_results.extend(decode_segmented_bucket_results(
                ctx,
                segment_bucket_buf,
                batch_segment_plan.segment_count,
                batch_windows,
                num_buckets,
            ));
        } else {
            window_results.extend(decode_bucket_results(
                ctx,
                &bucket_buf,
                batch_windows,
                num_buckets,
            ));
        }
    }

    Ok(window_results)
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
    use std::sync::{Mutex, OnceLock};

    fn msm_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_segment_overrides<T>(
        segment_budget: u64,
        max_points_per_segment: usize,
        f: impl FnOnce() -> T,
    ) -> T {
        let _guard = msm_env_lock().lock().expect("env lock");
        let old_budget = std::env::var_os("ZKF_METAL_MSM_SEGMENT_POINT_BUCKET_WORK_BUDGET");
        let old_max_points = std::env::var_os("ZKF_METAL_MSM_MAX_POINTS_PER_SEGMENT");
        unsafe {
            std::env::set_var(
                "ZKF_METAL_MSM_SEGMENT_POINT_BUCKET_WORK_BUDGET",
                segment_budget.to_string(),
            );
            std::env::set_var(
                "ZKF_METAL_MSM_MAX_POINTS_PER_SEGMENT",
                max_points_per_segment.to_string(),
            );
        }
        let result = f();
        match old_budget {
            Some(value) => unsafe {
                std::env::set_var("ZKF_METAL_MSM_SEGMENT_POINT_BUCKET_WORK_BUDGET", value)
            },
            None => unsafe {
                std::env::remove_var("ZKF_METAL_MSM_SEGMENT_POINT_BUCKET_WORK_BUDGET")
            },
        }
        match old_max_points {
            Some(value) => unsafe {
                std::env::set_var("ZKF_METAL_MSM_MAX_POINTS_PER_SEGMENT", value)
            },
            None => unsafe { std::env::remove_var("ZKF_METAL_MSM_MAX_POINTS_PER_SEGMENT") },
        }
        result
    }

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
    fn classic_dispatch_plan_scales_large_workloads_down_to_one_window() {
        let batch_windows = plan_classic_dispatch_batch_windows(
            27_500_000,
            1 << 15,
            17,
            16,
            1_100_000_000_000,
            Some(36 * 1024 * 1024 * 1024),
        )
        .expect("plan");
        assert_eq!(batch_windows, 1);
    }

    #[test]
    fn classic_dispatch_plan_over_budget_clamps_to_single_window() {
        let batch_windows = plan_classic_dispatch_batch_windows(
            60_000_000,
            1 << 15,
            17,
            16,
            1_100_000_000_000,
            Some(36 * 1024 * 1024 * 1024),
        )
        .expect("plan");
        assert_eq!(batch_windows, 1);
    }

    #[test]
    fn classic_dispatch_plan_rejects_one_window_over_memory_budget() {
        let err = plan_classic_dispatch_batch_windows(
            400_000_000,
            1 << 15,
            17,
            16,
            10_000_000_000_000,
            Some(8 * 1024 * 1024 * 1024),
        )
        .expect_err("expected rejection");
        assert!(err.contains("encoder footprint"));
    }

    #[test]
    fn classic_segment_plan_scales_failing_shape_into_multiple_segments() {
        let plan = plan_classic_point_segments(
            67_108_863,
            1 << 15,
            1,
            48_000_000_000,
            usize::MAX,
            1 << 30,
        )
        .expect("segment plan");
        assert!(plan.segment_count > 1);
        assert!(plan.points_per_segment < 67_108_863);
    }

    #[test]
    fn classic_segment_plan_rejects_merge_buffer_over_cap() {
        let err = plan_classic_point_segments(
            67_108_863,
            1 << 15,
            1,
            48_000_000_000,
            usize::MAX,
            64 * 1024 * 1024,
        )
        .expect_err("merge cap must reject oversized segment buffer");
        assert!(err.contains("merge cap"));
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
            Bn254MsmDispatch::Metal {
                projective,
                telemetry,
            } => {
                assert_eq!(projective.into_affine(), cpu_result.into_affine());
                assert!(telemetry.segment_count >= 1);
            }
            other => panic!("expected Metal dispatch result, got {other:?}"),
        }
    }

    #[test]
    fn forced_segmented_dispatch_matches_cpu() {
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
        let n = gpu_threshold_val().max(64);
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let cpu_result = cpu_pippenger(&scalars, &bases);

        with_segment_overrides(65_536, 8, || {
            match metal_msm_dispatch(ctx, &scalars, &bases) {
                Bn254MsmDispatch::Metal {
                    projective,
                    telemetry,
                } => {
                    assert!(telemetry.segment_count > 1);
                    assert_eq!(projective.into_affine(), cpu_result.into_affine());
                }
                other => panic!("expected segmented Metal dispatch result, got {other:?}"),
            }
        });
    }

    #[test]
    fn forced_segmented_and_unsegmented_dispatch_agree() {
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
        let n = gpu_threshold_val().max(64);
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        let baseline = match metal_msm_dispatch(ctx, &scalars, &bases) {
            Bn254MsmDispatch::Metal { projective, .. } => projective,
            other => panic!("expected baseline Metal dispatch result, got {other:?}"),
        };
        let segmented = with_segment_overrides(65_536, 8, || {
            match metal_msm_dispatch(ctx, &scalars, &bases) {
                Bn254MsmDispatch::Metal {
                    projective,
                    telemetry,
                } => {
                    assert!(telemetry.segment_count > 1);
                    projective
                }
                other => panic!("expected segmented Metal dispatch result, got {other:?}"),
            }
        });
        assert_eq!(baseline.into_affine(), segmented.into_affine());
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
