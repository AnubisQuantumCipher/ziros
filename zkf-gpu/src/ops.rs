//! GPU operation traits for ZK proving stages.

use serde::{Deserialize, Serialize};

/// Result of a GPU operation with timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuOpResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Time spent on the GPU in milliseconds.
    pub gpu_time_ms: f64,
    /// Time spent on CPU setup/teardown in milliseconds.
    pub cpu_overhead_ms: f64,
    /// Number of elements processed.
    pub elements_processed: usize,
    /// Optional error message.
    pub error: Option<String>,
}

/// GPU operation identifier for the ZK proving pipeline.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuOperation {
    /// Multi-Scalar Multiplication.
    Msm,
    /// Number Theoretic Transform.
    Ntt,
    /// Inverse NTT.
    InverseNtt,
    /// Poseidon2 hash.
    Poseidon2Hash,
    /// Merkle tree construction.
    MerkleTree,
    /// FRI layer folding.
    FriFold,
    /// Field element arithmetic (batch).
    FieldArithmetic,
    /// Constraint evaluation.
    ConstraintEval,
    /// Polynomial evaluation.
    PolynomialEval,
    /// Bitonic sort (for MSM bucket sorting).
    BitonicSort,
}

impl std::fmt::Display for GpuOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuOperation::Msm => write!(f, "MSM"),
            GpuOperation::Ntt => write!(f, "NTT"),
            GpuOperation::InverseNtt => write!(f, "iNTT"),
            GpuOperation::Poseidon2Hash => write!(f, "Poseidon2"),
            GpuOperation::MerkleTree => write!(f, "Merkle"),
            GpuOperation::FriFold => write!(f, "FRI fold"),
            GpuOperation::FieldArithmetic => write!(f, "Field ops"),
            GpuOperation::ConstraintEval => write!(f, "Constraints"),
            GpuOperation::PolynomialEval => write!(f, "Polynomial"),
            GpuOperation::BitonicSort => write!(f, "Bitonic sort"),
        }
    }
}

/// Capability declaration: which operations a GPU backend supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuCapabilities {
    pub backend: super::device::GpuBackend,
    pub supported_ops: Vec<GpuOperation>,
    pub max_field_bits: u32,
    pub supports_u64: bool,
}

/// Trait for GPU-accelerated MSM.
pub trait GpuMsm: Send + Sync {
    /// Supported operations.
    fn supported_operations(&self) -> Vec<GpuOperation>;
}

/// Trait for GPU-accelerated NTT.
pub trait GpuNtt: Send + Sync {
    /// Supported operations.
    fn supported_operations(&self) -> Vec<GpuOperation>;
}

/// Trait for GPU-accelerated hashing.
pub trait GpuHash: Send + Sync {
    /// Supported operations.
    fn supported_operations(&self) -> Vec<GpuOperation>;
}
