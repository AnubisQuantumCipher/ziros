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
