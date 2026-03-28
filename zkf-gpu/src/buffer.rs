//! GPU buffer abstraction.

use serde::{Deserialize, Serialize};

/// How a GPU buffer will be used.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuBufferUsage {
    /// Read-only input to GPU computation.
    ReadOnly,
    /// Write-only output from GPU computation.
    WriteOnly,
    /// Read-write storage buffer.
    ReadWrite,
    /// Uniform buffer (small, constant data).
    Uniform,
}

/// Metadata about a GPU buffer allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuBuffer {
    /// Size in bytes.
    pub size_bytes: usize,
    /// Usage flags.
    pub usage: GpuBufferUsage,
    /// Whether this buffer uses unified/shared memory.
    pub unified: bool,
    /// Optional label for debugging.
    pub label: Option<String>,
}

impl GpuBuffer {
    /// Create a new buffer descriptor.
    pub fn new(size_bytes: usize, usage: GpuBufferUsage) -> Self {
        Self {
            size_bytes,
            usage,
            unified: false,
            label: None,
        }
    }

    /// Set unified memory flag.
    pub fn with_unified(mut self, unified: bool) -> Self {
        self.unified = unified;
        self
    }

    /// Set label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Size in kilobytes.
    pub fn size_kb(&self) -> f64 {
        self.size_bytes as f64 / 1024.0
    }

    /// Size in megabytes.
    pub fn size_mb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0)
    }
}
