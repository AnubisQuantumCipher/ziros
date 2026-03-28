//! Metal dispatch driver trait: defines the GPU execution interface.
//!
//! The runtime defines the trait here.  The concrete implementation lives
//! in `zkf-metal` (which depends on `zkf-runtime`, not the reverse) and
//! registers itself via the `GpuDispatchDriver` trait.

use crate::buffer_bridge::BufferBridge;
use crate::error::RuntimeError;
use crate::execution::ExecutionContext;
use crate::graph::ProverNode;
use crate::memory::NodeId;
use std::time::Duration;

/// Verification policy for the GPU lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVerificationMode {
    /// Use the GPU opportunistically and allow CPU fallback.
    BestEffort,
    /// Execute only the pinned, attested GPU lane and fail closed on drift.
    VerifiedPinned,
}

impl GpuVerificationMode {
    pub const fn fail_closed(self) -> bool {
        matches!(self, Self::VerifiedPinned)
    }
}

/// Telemetry from a single GPU node dispatch.
#[derive(Debug, Clone)]
pub struct GpuNodeTelemetry {
    pub accelerator_name: String,
    pub fell_back: bool,
    pub wall_time: Duration,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub residency_class: String,
}

/// Signal returned when GPU dispatch fails and CPU fallback may be attempted.
#[derive(Debug)]
pub struct FallbackSignal {
    pub node_id: NodeId,
    pub reason: String,
}

/// Result of a GPU dispatch: either success telemetry or a fallback signal.
pub type DispatchResult = Result<GpuNodeTelemetry, FallbackSignal>;

/// Trait for a GPU dispatch driver.
///
/// The concrete Metal implementation lives in `zkf-metal` and implements
/// this trait.  The runtime calls through the trait object, breaking the
/// circular dependency.
pub trait GpuDispatchDriver: Send + Sync {
    /// Whether this driver is operational.
    fn is_available(&self) -> bool;

    /// Which verification policy governs this GPU lane.
    fn verification_mode(&self) -> GpuVerificationMode;

    /// Whether this driver is in fail-closed verified mode.
    fn strict_mode(&self) -> bool {
        self.verification_mode().fail_closed()
    }

    /// Whether this node is admitted to the pinned verified GPU lane.
    ///
    /// Best-effort drivers may return `true` for any node they can attempt.
    fn verified_lane_allows(&self, _node: &ProverNode) -> bool {
        true
    }

    /// Whether an `Either`-placed node should still be attempted on GPU first.
    ///
    /// Concrete drivers can use device-specific thresholds here without
    /// coupling the runtime crate to any specific accelerator backend.
    fn should_try_on_either(&self, _node: &ProverNode) -> bool {
        false
    }

    /// Execute a node on GPU.
    ///
    /// Returns `Ok(Ok(telemetry))` on success.
    /// Returns `Ok(Err(FallbackSignal))` if fallback to CPU is allowed.
    /// Returns `Err(RuntimeError)` on hard failure.
    fn execute(
        &self,
        node: &ProverNode,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<DispatchResult, RuntimeError>;
}

/// No-op GPU driver used when Metal is not available.
/// Always returns a fallback signal.
pub struct NullGpuDriver {
    verification_mode: GpuVerificationMode,
}

impl NullGpuDriver {
    pub fn new(verification_mode: GpuVerificationMode) -> Self {
        Self { verification_mode }
    }
}

impl GpuDispatchDriver for NullGpuDriver {
    fn is_available(&self) -> bool {
        false
    }

    fn verification_mode(&self) -> GpuVerificationMode {
        self.verification_mode
    }

    fn execute(
        &self,
        node: &ProverNode,
        _exec_ctx: &mut ExecutionContext,
        _bridge: &mut BufferBridge,
    ) -> Result<DispatchResult, RuntimeError> {
        if self.verification_mode.fail_closed() {
            return Err(RuntimeError::GpuFallbackRejected {
                node: format!(
                    "{:?} ({}) verified GPU lane unavailable",
                    node.id,
                    node.op.name()
                ),
            });
        }
        Ok(Err(FallbackSignal {
            node_id: node.id,
            reason: "no GPU driver available".into(),
        }))
    }
}

#[cfg(target_os = "macos")]
pub fn create_metal_dispatch_driver(
    verification_mode: GpuVerificationMode,
) -> Option<Box<dyn GpuDispatchDriver>> {
    crate::metal_dispatch_macos::create_metal_dispatch_driver(verification_mode)
        .or_else(|| Some(Box::new(NullGpuDriver::new(verification_mode)) as Box<dyn GpuDispatchDriver>))
}

#[cfg(not(target_os = "macos"))]
pub fn create_metal_dispatch_driver(
    verification_mode: GpuVerificationMode,
) -> Option<Box<dyn GpuDispatchDriver>> {
    Some(Box::new(NullGpuDriver::new(verification_mode)) as Box<dyn GpuDispatchDriver>)
}

#[cfg(target_os = "macos")]
pub fn create_metal_buffer_allocator() -> Option<Box<dyn crate::buffer_bridge::GpuBufferAllocator>>
{
    crate::metal_dispatch_macos::create_metal_buffer_allocator()
}

#[cfg(not(target_os = "macos"))]
pub fn create_metal_buffer_allocator() -> Option<Box<dyn crate::buffer_bridge::GpuBufferAllocator>>
{
    None
}
