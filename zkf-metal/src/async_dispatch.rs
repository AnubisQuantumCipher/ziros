//! Async GPU dispatch primitives for pipeline parallelism.
//!
//! `GpuFuture` wraps a Metal command buffer with a completion handler and a
//! bounded watchdog. If Metal stops reporting completion or returns a command
//! buffer error, the runtime opens a circuit breaker and callers can fall back
//! to CPU code instead of waiting forever.

use crate::device;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_metal::{MTLCommandBuffer, MTLCommandBufferStatus};
use std::ptr::NonNull;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_WATCHDOG_MS: u64 = 120_000;
const DEFAULT_MSM_WATCHDOG_MS: u64 = 600_000;
const POLL_SLICE_MS: u64 = 100;

#[derive(Debug, Clone)]
pub struct GpuCompletion {
    pub stage: &'static str,
    pub elapsed_ms: u128,
    pub callback_observed: bool,
}

#[derive(Debug, Clone)]
pub struct GpuWaitError {
    pub stage: &'static str,
    pub status: &'static str,
    pub elapsed_ms: u128,
    pub command_buffer_error_code: Option<isize>,
    pub command_buffer_error: Option<String>,
    pub detail: String,
}

impl std::fmt::Display for GpuWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (stage={}, status={}, elapsed_ms={})",
            self.detail, self.stage, self.status, self.elapsed_ms
        )?;
        if let Some(code) = self.command_buffer_error_code {
            write!(f, ", metal_code={code}")?;
        }
        if let Some(error) = &self.command_buffer_error {
            write!(f, ", metal_error={error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GpuWaitError {}

fn watchdog_timeout(stage: &'static str) -> Duration {
    let stage_override = match stage {
        "msm" => std::env::var("ZKF_METAL_MSM_WATCHDOG_MS").ok(),
        _ => None,
    };
    let default_millis = match stage {
        "msm" => DEFAULT_MSM_WATCHDOG_MS,
        _ => DEFAULT_WATCHDOG_MS,
    };
    let millis = stage_override
        .or_else(|| std::env::var("ZKF_METAL_WATCHDOG_MS").ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 1_000)
        .unwrap_or(default_millis);
    Duration::from_millis(millis)
}

fn command_buffer_status_label(status: MTLCommandBufferStatus) -> &'static str {
    if status == MTLCommandBufferStatus::NotEnqueued {
        "not-enqueued"
    } else if status == MTLCommandBufferStatus::Enqueued {
        "enqueued"
    } else if status == MTLCommandBufferStatus::Committed {
        "committed"
    } else if status == MTLCommandBufferStatus::Scheduled {
        "scheduled"
    } else if status == MTLCommandBufferStatus::Completed {
        "completed"
    } else if status == MTLCommandBufferStatus::Error {
        "error"
    } else {
        "unknown"
    }
}

fn command_buffer_error_details(
    cmd: &ProtocolObject<dyn MTLCommandBuffer>,
) -> (Option<isize>, Option<String>) {
    let Some(error) = cmd.error() else {
        return (None, None);
    };
    (
        Some(error.code()),
        Some(error.localizedDescription().to_string()),
    )
}

/// A future representing an in-flight GPU command buffer.
///
/// Call `wait()` to block until the GPU finishes, or drop to detach.
/// Multiple `GpuFuture`s can be created before waiting on any of them,
/// enabling pipeline parallelism between CPU and GPU.
pub struct GpuFuture {
    cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>,
    signal: Arc<(Mutex<bool>, Condvar)>,
    stage: &'static str,
    submitted_at: Instant,
    watchdog_timeout: Duration,
}

impl GpuFuture {
    /// Submit a command buffer for async execution.
    ///
    /// The command buffer is committed immediately. A completion handler
    /// signals when the GPU finishes. Call `wait()` to block until done.
    pub fn submit(cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>) -> Self {
        Self::submit_labeled(cmd, "generic")
    }

    /// Submit a labeled command buffer for async execution.
    pub fn submit_labeled(
        cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>,
        stage: &'static str,
    ) -> Self {
        let signal = Arc::new((Mutex::new(false), Condvar::new()));
        let signal_clone = signal.clone();

        // addCompletedHandler is called on an internal Metal thread when done
        unsafe {
            let handler =
                block2::RcBlock::new(move |_buf: NonNull<ProtocolObject<dyn MTLCommandBuffer>>| {
                    let (lock, cvar) = &*signal_clone;
                    if let Ok(mut done) = lock.lock() {
                        *done = true;
                        cvar.notify_all();
                    }
                });
            cmd.addCompletedHandler(&*handler as *const _ as *mut _);
        }

        cmd.commit();
        Self {
            cmd,
            signal,
            stage,
            submitted_at: Instant::now(),
            watchdog_timeout: watchdog_timeout(stage),
        }
    }

    /// Block until the GPU command buffer completes.
    pub fn wait(&self) {
        let _ = self.wait_checked();
    }

    /// Block until the GPU command buffer completes, or return a typed failure.
    pub fn wait_checked(&self) -> Result<GpuCompletion, GpuWaitError> {
        loop {
            let status = self.cmd.status();
            if status == MTLCommandBufferStatus::Completed {
                return Ok(GpuCompletion {
                    stage: self.stage,
                    elapsed_ms: self.submitted_at.elapsed().as_millis(),
                    callback_observed: self.callback_observed(),
                });
            }
            if status == MTLCommandBufferStatus::Error {
                let err = self.build_error("Metal command buffer failed");
                self.trip_circuit(&err);
                return Err(err);
            }

            let elapsed = self.submitted_at.elapsed();
            if elapsed >= self.watchdog_timeout {
                let err = self.build_error("Metal command buffer watchdog timeout");
                self.trip_circuit(&err);
                return Err(err);
            }

            let remaining = self.watchdog_timeout.saturating_sub(elapsed);
            let sleep_for = remaining.min(Duration::from_millis(POLL_SLICE_MS));
            let (lock, cvar) = &*self.signal;
            let guard = match lock.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    let err = self.build_error("Metal completion lock poisoned");
                    self.trip_circuit(&err);
                    return Err(err);
                }
            };
            if *guard {
                continue;
            }
            if cvar.wait_timeout(guard, sleep_for).is_err() {
                let err = self.build_error("Metal completion wait poisoned");
                self.trip_circuit(&err);
                return Err(err);
            }
        }
    }

    /// Check if the GPU command buffer has completed without blocking.
    pub fn is_done(&self) -> bool {
        self.callback_observed() || self.status() == MTLCommandBufferStatus::Completed
    }

    fn callback_observed(&self) -> bool {
        self.signal.0.lock().map(|done| *done).unwrap_or(false)
    }

    /// Get the command buffer status.
    pub fn status(&self) -> MTLCommandBufferStatus {
        self.cmd.status()
    }

    /// Get a reference to the underlying command buffer (for reading results after wait).
    pub fn command_buffer(&self) -> &ProtocolObject<dyn MTLCommandBuffer> {
        &self.cmd
    }

    fn build_error(&self, detail: &str) -> GpuWaitError {
        let status = self.cmd.status();
        let (command_buffer_error_code, command_buffer_error) =
            command_buffer_error_details(&self.cmd);
        GpuWaitError {
            stage: self.stage,
            status: command_buffer_status_label(status),
            elapsed_ms: self.submitted_at.elapsed().as_millis(),
            command_buffer_error_code,
            command_buffer_error,
            detail: detail.to_string(),
        }
    }

    fn trip_circuit(&self, err: &GpuWaitError) {
        if let Some(ctx) = device::global_context() {
            ctx.disable_dispatch(err.to_string());
        }
    }
}

/// Submit multiple command buffers and wait for all to complete.
pub fn wait_all(futures: &[GpuFuture]) {
    for f in futures {
        let _ = f.wait_checked();
    }
}

pub fn commit_and_wait(
    cmd: Retained<ProtocolObject<dyn MTLCommandBuffer>>,
    stage: &'static str,
) -> Result<GpuCompletion, GpuWaitError> {
    GpuFuture::submit_labeled(cmd, stage).wait_checked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device;
    use objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue};

    #[test]
    fn gpu_future_basic() {
        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        // Create a trivial command buffer
        let cmd = ctx.queue().commandBuffer().expect("cmd buffer");
        // Encode nothing — just test the future mechanism
        let enc = cmd.computeCommandEncoder().expect("encoder");
        enc.endEncoding();

        let future = GpuFuture::submit(cmd);
        assert!(future.wait_checked().is_ok());
        assert!(future.is_done());
    }

    #[test]
    fn gpu_future_multiple() {
        let ctx = match device::global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let mut futures = Vec::new();
        for _ in 0..4 {
            let cmd = ctx.queue().commandBuffer().expect("cmd buffer");
            let enc = cmd.computeCommandEncoder().expect("encoder");
            enc.endEncoding();
            futures.push(GpuFuture::submit(cmd));
        }

        // All submitted before any waited on
        wait_all(&futures);
        for f in &futures {
            assert!(f.is_done());
        }
    }
}
