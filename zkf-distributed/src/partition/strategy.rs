//! Partition strategy types.

use serde::{Deserialize, Serialize};

/// Strategy for partitioning a prover graph across cluster nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionStrategy {
    /// No partitioning: everything runs locally.
    None,
    /// Cut at phase boundaries (witness → NTT → MSM → hash → FRI → backend → finalize).
    #[default]
    PhaseBoundary,
    /// Partition by device placement affinity (GPU-heavy to GPU nodes, etc.).
    PlacementAffinity,
    /// Balanced partitioning: minimize boundary transfers while equalizing work.
    Balanced,
}

impl PartitionStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            PartitionStrategy::None => "none",
            PartitionStrategy::PhaseBoundary => "phase-boundary",
            PartitionStrategy::PlacementAffinity => "placement-affinity",
            PartitionStrategy::Balanced => "balanced",
        }
    }
}
