//! Radix-2 DIT butterfly dispatch for Metal GPU.

use crate::async_dispatch;
use crate::device::MetalContext;
use crate::shader_library::kernels;
use objc2::runtime::ProtocolObject;
use objc2_metal::{
    MTLBarrierScope, MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder,
    MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Threshold for using threadgroup-local NTT (shared memory).
const SMALL_NTT_THRESHOLD: usize = 1024;
const SMALL_BN254_NTT_THRESHOLD: usize = 256;

/// Dispatch NTT butterfly stages for Goldilocks field on Metal GPU.
pub fn dispatch_ntt_goldilocks(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
) -> Option<()> {
    let log_n = n.trailing_zeros();

    if n <= SMALL_NTT_THRESHOLD {
        dispatch_small_ntt(ctx, data_buffer, twiddle_buffer, log_n)
    } else {
        // Try hybrid (shared memory + global) first, fall back to pure global
        dispatch_hybrid_ntt(ctx, data_buffer, twiddle_buffer, n, log_n)
            .or_else(|| dispatch_large_ntt(ctx, data_buffer, twiddle_buffer, n, log_n))
    }
}

/// Dispatch NTT butterfly stages for BN254 Fr on Metal GPU.
pub fn dispatch_ntt_bn254(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
) -> Option<()> {
    let log_n = n.trailing_zeros();

    if n <= SMALL_BN254_NTT_THRESHOLD {
        dispatch_small_bn254_ntt(ctx, data_buffer, twiddle_buffer, log_n)
    } else {
        dispatch_hybrid_bn254_ntt(ctx, data_buffer, twiddle_buffer, n, log_n)
            .or_else(|| dispatch_large_bn254_ntt(ctx, data_buffer, twiddle_buffer, n, log_n))
    }
}

/// Small NTT: entire transform in threadgroup memory.
fn dispatch_small_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    log_n: u32,
) -> Option<()> {
    let pipeline = ctx.pipeline(kernels::NTT_SMALL_GOLDILOCKS)?;
    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    let n = 1usize << log_n;

    unsafe {
        encoder.setComputePipelineState(&pipeline);
        encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_n).cast(),
            std::mem::size_of::<u32>(),
            2,
        );

        let tg_mem_size = n * std::mem::size_of::<u64>();
        encoder.setThreadgroupMemoryLength_atIndex(tg_mem_size, 0);

        let max_threads = pipeline.maxTotalThreadsPerThreadgroup();
        let threads_per_group = n.min(max_threads);
        encoder.dispatchThreadgroups_threadsPerThreadgroup(
            MTLSize {
                width: 1,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: threads_per_group,
                height: 1,
                depth: 1,
            },
        );
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt").ok()?;

    Some(())
}

/// Hybrid NTT: early stages in threadgroup shared memory, later stages global.
///
/// For large NTTs (N > 1024), the first `log2(threadgroup_size)` stages use
/// fast threadgroup shared memory with barriers, then remaining stages use
/// global memory butterfly dispatches. This reduces global memory traffic
/// for early stages where butterfly span fits in shared memory.
fn dispatch_hybrid_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
    log_n: u32,
) -> Option<()> {
    let hybrid_pipeline = ctx.pipeline(kernels::NTT_HYBRID_GOLDILOCKS)?;
    let butterfly_pipeline = ctx.pipeline(kernels::NTT_BUTTERFLY_GOLDILOCKS)?;

    // Threadgroup size for the hybrid kernel (must be power of 2)
    let max_tg = hybrid_pipeline.maxTotalThreadsPerThreadgroup().min(1024);
    let log_tg_size = max_tg.trailing_zeros();
    let tg_size = 1usize << log_tg_size;

    // Phase 1: Hybrid kernel — early stages in shared memory
    let num_blocks = n / tg_size;
    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    unsafe {
        encoder.setComputePipelineState(&hybrid_pipeline);
        encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_n).cast(),
            std::mem::size_of::<u32>(),
            2,
        );
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_tg_size).cast(),
            std::mem::size_of::<u32>(),
            3,
        );
        let shared_mem_size = tg_size * std::mem::size_of::<u64>();
        encoder.setThreadgroupMemoryLength_atIndex(shared_mem_size, 0);

        encoder.dispatchThreadgroups_threadsPerThreadgroup(
            MTLSize {
                width: num_blocks,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: tg_size,
                height: 1,
                depth: 1,
            },
        );
    }

    // Phase 2: Remaining stages via global memory butterflies
    let shared_stages = log_tg_size.min(log_n);
    let n_u32 = n as u32;
    let num_butterflies = n / 2;
    let max_threads = butterfly_pipeline.maxTotalThreadsPerThreadgroup().min(256);
    let num_groups = num_butterflies.div_ceil(max_threads);

    for stage in shared_stages..log_n {
        unsafe {
            encoder.memoryBarrierWithScope(MTLBarrierScope::Buffers);
            encoder.setComputePipelineState(&butterfly_pipeline);
            encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
            encoder.setBytes_length_atIndex(
                NonNull::from(&stage).cast(),
                std::mem::size_of::<u32>(),
                2,
            );
            encoder.setBytes_length_atIndex(
                NonNull::from(&n_u32).cast(),
                std::mem::size_of::<u32>(),
                3,
            );

            encoder.dispatchThreadgroups_threadsPerThreadgroup(
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
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt").ok()?;

    Some(())
}

/// Large NTT: all stages in a single command buffer with memory barriers.
///
/// Encodes all butterfly stages into one command buffer with
/// `memoryBarrierWithScope:` between dispatches. For a 2^20 NTT this
/// reduces 20 GPU round-trips to 1.
fn dispatch_large_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
    log_n: u32,
) -> Option<()> {
    let pipeline = ctx.pipeline(kernels::NTT_BUTTERFLY_GOLDILOCKS)?;
    let n_u32 = n as u32;

    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    let num_butterflies = n / 2;
    let max_threads = pipeline.maxTotalThreadsPerThreadgroup().min(256);
    let num_groups = num_butterflies.div_ceil(max_threads);

    for stage in 0..log_n {
        unsafe {
            encoder.setComputePipelineState(&pipeline);
            encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
            encoder.setBytes_length_atIndex(
                NonNull::from(&stage).cast(),
                std::mem::size_of::<u32>(),
                2,
            );
            encoder.setBytes_length_atIndex(
                NonNull::from(&n_u32).cast(),
                std::mem::size_of::<u32>(),
                3,
            );

            encoder.dispatchThreadgroups_threadsPerThreadgroup(
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

            if stage + 1 < log_n {
                encoder.memoryBarrierWithScope(MTLBarrierScope::Buffers);
            }
        }
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt").ok()?;

    Some(())
}

fn dispatch_small_bn254_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    log_n: u32,
) -> Option<()> {
    let pipeline = ctx.pipeline(kernels::NTT_SMALL_BN254)?;
    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    let n = 1usize << log_n;

    unsafe {
        encoder.setComputePipelineState(&pipeline);
        encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_n).cast(),
            std::mem::size_of::<u32>(),
            2,
        );

        let tg_mem_size = n * 4 * std::mem::size_of::<u64>();
        encoder.setThreadgroupMemoryLength_atIndex(tg_mem_size, 0);

        let max_threads = pipeline.maxTotalThreadsPerThreadgroup();
        let threads_per_group = n.min(max_threads);
        encoder.dispatchThreadgroups_threadsPerThreadgroup(
            MTLSize {
                width: 1,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: threads_per_group,
                height: 1,
                depth: 1,
            },
        );
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt-bn254").ok()?;

    Some(())
}

fn dispatch_hybrid_bn254_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
    log_n: u32,
) -> Option<()> {
    let hybrid_pipeline = ctx.pipeline(kernels::NTT_HYBRID_BN254)?;
    let butterfly_pipeline = ctx.pipeline(kernels::NTT_BUTTERFLY_BN254)?;

    let max_tg = hybrid_pipeline.maxTotalThreadsPerThreadgroup().min(1024);
    let log_tg_size = max_tg.trailing_zeros();
    let tg_size = 1usize << log_tg_size;

    let num_blocks = n.div_ceil(tg_size);
    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    unsafe {
        encoder.setComputePipelineState(&hybrid_pipeline);
        encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_n).cast(),
            std::mem::size_of::<u32>(),
            2,
        );
        encoder.setBytes_length_atIndex(
            NonNull::from(&log_tg_size).cast(),
            std::mem::size_of::<u32>(),
            3,
        );
        let shared_mem_size = tg_size * 4 * std::mem::size_of::<u64>();
        encoder.setThreadgroupMemoryLength_atIndex(shared_mem_size, 0);

        encoder.dispatchThreadgroups_threadsPerThreadgroup(
            MTLSize {
                width: num_blocks,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: tg_size,
                height: 1,
                depth: 1,
            },
        );
    }

    let shared_stages = log_tg_size.min(log_n);
    let n_u32 = n as u32;
    let num_butterflies = n / 2;
    let max_threads = butterfly_pipeline.maxTotalThreadsPerThreadgroup().min(256);
    let num_groups = num_butterflies.div_ceil(max_threads);

    for stage in shared_stages..log_n {
        unsafe {
            encoder.memoryBarrierWithScope(MTLBarrierScope::Buffers);
            encoder.setComputePipelineState(&butterfly_pipeline);
            encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
            encoder.setBytes_length_atIndex(
                NonNull::from(&stage).cast(),
                std::mem::size_of::<u32>(),
                2,
            );
            encoder.setBytes_length_atIndex(
                NonNull::from(&n_u32).cast(),
                std::mem::size_of::<u32>(),
                3,
            );

            encoder.dispatchThreadgroups_threadsPerThreadgroup(
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
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt-bn254").ok()?;

    Some(())
}

fn dispatch_large_bn254_ntt(
    ctx: &MetalContext,
    data_buffer: &ProtocolObject<dyn MTLBuffer>,
    twiddle_buffer: &ProtocolObject<dyn MTLBuffer>,
    n: usize,
    log_n: u32,
) -> Option<()> {
    let pipeline = ctx.pipeline(kernels::NTT_BUTTERFLY_BN254)?;
    let n_u32 = n as u32;

    let cmd_buffer = ctx.command_buffer()?;
    let encoder = cmd_buffer.computeCommandEncoder()?;

    let num_butterflies = n / 2;
    let max_threads = pipeline.maxTotalThreadsPerThreadgroup().min(256);
    let num_groups = num_butterflies.div_ceil(max_threads);

    for stage in 0..log_n {
        unsafe {
            encoder.setComputePipelineState(&pipeline);
            encoder.setBuffer_offset_atIndex(Some(data_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(twiddle_buffer), 0, 1);
            encoder.setBytes_length_atIndex(
                NonNull::from(&stage).cast(),
                std::mem::size_of::<u32>(),
                2,
            );
            encoder.setBytes_length_atIndex(
                NonNull::from(&n_u32).cast(),
                std::mem::size_of::<u32>(),
                3,
            );

            encoder.dispatchThreadgroups_threadsPerThreadgroup(
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

            if stage + 1 < log_n {
                encoder.memoryBarrierWithScope(MTLBarrierScope::Buffers);
            }
        }
    }

    encoder.endEncoding();
    async_dispatch::commit_and_wait(cmd_buffer, "ntt-bn254").ok()?;

    Some(())
}
