//! GPU device abstraction.

use serde::{Deserialize, Serialize};

/// Identifies which GPU backend is in use.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuBackend {
    /// Apple Metal (macOS/iOS).
    Metal,
    /// WebGPU via wgpu (cross-platform).
    WebGpu,
    /// Vulkan (via wgpu or direct).
    Vulkan,
    /// No GPU available; CPU fallback.
    None,
}

impl std::fmt::Display for GpuBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuBackend::Metal => write!(f, "Metal"),
            GpuBackend::WebGpu => write!(f, "WebGPU"),
            GpuBackend::Vulkan => write!(f, "Vulkan"),
            GpuBackend::None => write!(f, "None (CPU)"),
        }
    }
}

/// Information about a GPU device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDeviceInfo {
    /// Device name (e.g., "Apple M4 Max GPU").
    pub name: String,
    /// GPU backend type.
    pub backend: GpuBackend,
    /// Number of compute cores/units.
    pub compute_units: Option<u32>,
    /// Maximum buffer size in bytes.
    pub max_buffer_size: Option<u64>,
    /// Whether the device has unified memory (shared CPU/GPU).
    pub unified_memory: bool,
    /// Total device memory in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum workgroup size (threads per group).
    pub max_workgroup_size: Option<u32>,
    /// Maximum number of workgroups.
    pub max_workgroups: Option<u32>,
}

/// Trait for GPU device abstraction.
///
/// Implementors provide device info and buffer allocation.
pub trait GpuDevice: Send + Sync {
    /// Get device information.
    fn info(&self) -> GpuDeviceInfo;

    /// Check if the device is available and functional.
    fn is_available(&self) -> bool;

    /// Get the backend type.
    fn backend(&self) -> GpuBackend;

    /// Maximum number of elements that can be processed in one dispatch.
    fn max_dispatch_size(&self) -> usize;
}
