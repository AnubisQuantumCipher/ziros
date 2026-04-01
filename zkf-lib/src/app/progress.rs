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

use zkf_core::BackendKind;

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ProofStage {
    Compile,
    Witness,
    PrepareWitness,
    Prove,
}

impl ProofStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Compile => "Compile",
            Self::Witness => "Witness",
            Self::PrepareWitness => "Constraint Check",
            Self::Prove => "Prove",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProofEvent {
    StageStarted {
        stage: ProofStage,
    },
    CompileCompleted {
        backend: BackendKind,
        signal_count: usize,
        constraint_count: usize,
        duration_ms: u128,
    },
    WitnessCompleted {
        witness_values: usize,
        duration_ms: u128,
    },
    PrepareWitnessCompleted {
        witness_values: usize,
        public_inputs: usize,
        duration_ms: u128,
    },
    ProveCompleted {
        backend: BackendKind,
        proof_size_bytes: usize,
        duration_ms: u128,
    },
}

impl ProofEvent {
    pub fn stage(&self) -> ProofStage {
        match self {
            Self::StageStarted { stage } => *stage,
            Self::CompileCompleted { .. } => ProofStage::Compile,
            Self::WitnessCompleted { .. } => ProofStage::Witness,
            Self::PrepareWitnessCompleted { .. } => ProofStage::PrepareWitness,
            Self::ProveCompleted { .. } => ProofStage::Prove,
        }
    }

    pub fn duration_ms(&self) -> Option<u128> {
        match self {
            Self::StageStarted { .. } => None,
            Self::CompileCompleted { duration_ms, .. }
            | Self::WitnessCompleted { duration_ms, .. }
            | Self::PrepareWitnessCompleted { duration_ms, .. }
            | Self::ProveCompleted { duration_ms, .. } => Some(*duration_ms),
        }
    }
}
