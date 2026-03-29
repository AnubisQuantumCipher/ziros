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
