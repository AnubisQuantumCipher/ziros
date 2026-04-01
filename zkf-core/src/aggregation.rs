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

use crate::{BackendKind, CompiledProgram, FieldElement, ProofArtifact, ZkfResult};
use serde::{Deserialize, Serialize};

/// A proof aggregator combines multiple proofs into a single aggregate artifact.
///
/// Depending on the implementation, the result may be a true compressed proof or
/// a metadata-binding bundle that records manifests and digests across the input
/// proofs. Callers must inspect the aggregate metadata to understand which model
/// they received.
pub trait ProofAggregator: Send + Sync {
    /// Which backend this aggregator operates over.
    fn backend(&self) -> BackendKind;

    /// Aggregate multiple proofs into a single artifact.
    ///
    /// All proofs must be from the same backend. The compiled programs may differ
    /// (heterogeneous aggregation) or be the same (homogeneous aggregation),
    /// depending on the implementation.
    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof>;

    /// Verify an aggregated proof.
    fn verify_aggregated(&self, aggregated: &AggregatedProof) -> ZkfResult<bool>;
}

/// An aggregate artifact bundling multiple individual proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedProof {
    /// The backend used for aggregation.
    pub backend: BackendKind,
    /// The aggregate artifact bytes.
    pub proof: Vec<u8>,
    /// Verification key for the aggregated proof.
    pub verification_key: Vec<u8>,
    /// Public inputs required to verify the aggregate artifact.
    #[serde(default)]
    pub public_inputs: Vec<FieldElement>,
    /// Digests of the individual programs that were aggregated.
    pub program_digests: Vec<String>,
    /// Number of proofs aggregated.
    pub proof_count: usize,
    /// Optional metadata.
    pub metadata: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregated_proof_stores_metadata() {
        let proof = AggregatedProof {
            backend: BackendKind::ArkworksGroth16,
            proof: vec![1, 2, 3],
            verification_key: vec![4, 5, 6],
            public_inputs: vec![FieldElement::from_u64(7)],
            program_digests: vec!["abc".to_string(), "def".to_string()],
            proof_count: 2,
            metadata: std::collections::BTreeMap::new(),
        };
        assert_eq!(proof.proof_count, 2);
        assert_eq!(proof.program_digests.len(), 2);
        assert_eq!(proof.public_inputs.len(), 1);
    }
}
