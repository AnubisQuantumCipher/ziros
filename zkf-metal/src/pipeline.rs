//! GPU pipeline orchestrator for minimizing CPU-GPU sync points.
//!
//! Keeps 2-3 command buffers in flight simultaneously, overlapping GPU compute
//! with CPU preparation work. Uses `GpuFuture` for completion signaling.

use crate::async_dispatch::GpuFuture;
use crate::device::MetalContext;
use crate::tuning::throughput_for_device;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder};
use std::collections::VecDeque;

/// GPU pipeline that keeps multiple command buffers in flight.
///
/// Usage:
/// ```ignore
/// let mut pipeline = GpuPipeline::new(ctx);
/// pipeline.submit(|enc| { /* encode compute work */ });
/// pipeline.submit(|enc| { /* more work, may run concurrently */ });
/// pipeline.drain(); // wait for all in-flight work
/// ```
pub struct GpuPipeline {
    ctx: &'static MetalContext,
    in_flight: VecDeque<GpuFuture>,
    max_in_flight: usize,
}

impl GpuPipeline {
    /// Create a new pipeline with default max_in_flight.
    pub fn new(ctx: &'static MetalContext) -> Self {
        let tuning = throughput_for_device(&ctx.device_name());
        Self {
            ctx,
            in_flight: VecDeque::new(),
            max_in_flight: tuning.pipeline_max_in_flight.max(1),
        }
    }

    /// Create a new pipeline with custom max_in_flight.
    pub fn with_max_in_flight(ctx: &'static MetalContext, max: usize) -> Self {
        Self {
            ctx,
            in_flight: VecDeque::new(),
            max_in_flight: max.max(1),
        }
    }

    /// Submit a command buffer with encoded compute work.
    ///
    /// If the pipeline is at capacity, blocks until the oldest in-flight
    /// command buffer completes before submitting new work.
    ///
    /// The `encoder_fn` receives the compute command encoder — encode your
    /// dispatch calls within it. The encoder is ended and command buffer
    /// committed automatically.
    pub fn submit<F>(&mut self, encoder_fn: F) -> bool
    where
        F: FnOnce(&ProtocolObject<dyn MTLComputeCommandEncoder>),
    {
        // If at capacity, wait for oldest
        while self.in_flight.len() >= self.max_in_flight {
            if let Some(oldest) = self.in_flight.pop_front() {
                let _ = oldest.wait_checked();
            }
        }

        let cmd = match self.ctx.command_buffer() {
            Some(c) => c,
            None => return false,
        };
        let enc = match cmd.computeCommandEncoder() {
            Some(e) => e,
            None => return false,
        };

        encoder_fn(&enc);
        enc.endEncoding();

        self.in_flight
            .push_back(GpuFuture::submit_labeled(cmd, "pipeline"));
        true
    }

    /// Submit a pre-built command buffer (already encoded).
    pub fn submit_command_buffer(&mut self, cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>) {
        while self.in_flight.len() >= self.max_in_flight {
            if let Some(oldest) = self.in_flight.pop_front() {
                let _ = oldest.wait_checked();
            }
        }
        self.in_flight
            .push_back(GpuFuture::submit_labeled(cmd, "pipeline"));
    }

    /// Wait for all in-flight command buffers to complete.
    pub fn drain(&mut self) {
        while let Some(future) = self.in_flight.pop_front() {
            let _ = future.wait_checked();
        }
    }

    /// Number of currently in-flight command buffers.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Check if any in-flight work has completed and remove it.
    pub fn poll_completed(&mut self) -> usize {
        let mut completed = 0;
        while let Some(front) = self.in_flight.front() {
            if front.is_done() {
                self.in_flight.pop_front();
                completed += 1;
            } else {
                break;
            }
        }
        completed
    }
}

impl Drop for GpuPipeline {
    fn drop(&mut self) {
        self.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device;

    #[test]
    fn pipeline_basic() {
        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let mut pipeline = GpuPipeline::new(ctx);

        // Submit 5 no-op command buffers (more than max_in_flight)
        for _ in 0..5 {
            let ok = pipeline.submit(|_enc| {
                // No-op encode — just tests the pipeline mechanism
            });
            assert!(ok, "Pipeline submit should succeed");
        }

        pipeline.drain();
        assert_eq!(pipeline.in_flight_count(), 0);
    }

    #[test]
    fn pipeline_poll() {
        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let mut pipeline = GpuPipeline::with_max_in_flight(ctx, 4);

        for _ in 0..3 {
            pipeline.submit(|_enc| {});
        }

        // Wait a bit for GPU to complete trivial work
        std::thread::sleep(std::time::Duration::from_millis(10));
        let completed = pipeline.poll_completed();
        assert!(completed <= 3);

        pipeline.drain();
    }
}
