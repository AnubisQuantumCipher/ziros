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

//! Proof aggregation implementations.
//!
//! Provides concrete implementations of `ProofAggregator` for batching
//! multiple proofs into a single aggregated proof. Supports:
//! - **Groth16Aggregator**: recursive in-circuit aggregation for BN254 Groth16 proofs
//! - **Plonky3Aggregator**: Plonky3 STARK wrapping into Groth16, then recursive Groth16 aggregation

use crate::wrapping::groth16_recursive_verifier::CryptographicGroth16Aggregator;
use crate::wrapping::stark_to_groth16::StarkToGroth16Wrapper;
use zkf_core::aggregation::{AggregatedProof, ProofAggregator};
use zkf_core::wrapping::ProofWrapper;
use zkf_core::{
    BackendKind, CompiledProgram, FieldId, Program, ProofArtifact, ZkfError, ZkfResult,
};

/// Groth16 proof aggregator using the recursive verifier circuit.
pub struct Groth16Aggregator;

impl ProofAggregator for Groth16Aggregator {
    fn backend(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof> {
        CryptographicGroth16Aggregator.aggregate(proofs)
    }

    fn verify_aggregated(&self, aggregated: &AggregatedProof) -> ZkfResult<bool> {
        CryptographicGroth16Aggregator.verify_aggregated(aggregated)
    }
}

/// Plonky3 STARK proof aggregator using STARK-to-Groth16 wrapping followed by
/// recursive Groth16 aggregation.
pub struct Plonky3Aggregator;

impl ProofAggregator for Plonky3Aggregator {
    fn backend(&self) -> BackendKind {
        BackendKind::Plonky3
    }

    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof> {
        if proofs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot aggregate zero proofs".to_string(),
            ));
        }

        for (artifact, _compiled) in proofs {
            if artifact.backend != BackendKind::Plonky3 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "plonky3 aggregator received proof from backend '{}', expected plonky3",
                    artifact.backend
                )));
            }
        }

        if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() != Some("1") {
            return Err(ZkfError::Backend(
                "Plonky3Aggregator now upgrades STARK aggregation through \
                 StarkToGroth16Wrapper -> CryptographicGroth16Aggregator. \
                 Set ZKF_RECURSIVE_PROVE=1 to enable the final recursive Groth16 \
                 aggregation step."
                    .to_string(),
            ));
        }

        let wrapper = StarkToGroth16Wrapper;
        let mut wrapped_pairs = Vec::with_capacity(proofs.len());
        for (artifact, compiled) in proofs {
            let wrapped = wrapper.wrap(artifact, compiled)?;
            wrapped_pairs.push((
                wrapped.clone(),
                synthetic_wrapped_groth16_compiled(&wrapped.program_digest),
            ));
        }

        let mut aggregated = CryptographicGroth16Aggregator.aggregate(&wrapped_pairs)?;
        aggregated.metadata.insert(
            "source_backend".to_string(),
            BackendKind::Plonky3.as_str().to_string(),
        );
        aggregated.metadata.insert(
            "wrapped_backend".to_string(),
            BackendKind::ArkworksGroth16.as_str().to_string(),
        );
        aggregated
            .metadata
            .insert("wrapper".to_string(), "stark-to-groth16".to_string());
        aggregated.metadata.insert(
            "aggregation_pipeline".to_string(),
            "stark-to-groth16-then-recursive-groth16".to_string(),
        );
        aggregated.metadata.insert(
            "proof_semantics".to_string(),
            "wrapped-stark-recursive-verification".to_string(),
        );
        aggregated.metadata.insert(
            "aggregation_semantics".to_string(),
            "stark-to-groth16-then-recursive-groth16".to_string(),
        );

        Ok(aggregated)
    }

    fn verify_aggregated(&self, aggregated: &AggregatedProof) -> ZkfResult<bool> {
        if aggregated.backend != BackendKind::ArkworksGroth16 {
            return Err(ZkfError::InvalidArtifact(format!(
                "plonky3 aggregator expects a wrapped Groth16 aggregate, got backend '{}'",
                aggregated.backend
            )));
        }
        CryptographicGroth16Aggregator.verify_aggregated(aggregated)
    }
}

fn synthetic_wrapped_groth16_compiled(source_digest: &str) -> CompiledProgram {
    let mut compiled = CompiledProgram::new(
        BackendKind::ArkworksGroth16,
        Program {
            name: "plonky3_wrapped_groth16_recursive_aggregate".to_string(),
            field: FieldId::Bn254,
            ..Default::default()
        },
    );
    compiled.program_digest = source_digest.to_string();
    compiled
        .metadata
        .insert("synthetic_wrapper_compiled".to_string(), "true".to_string());
    compiled
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{FieldElement, FieldId, Program};

    fn test_artifact(
        backend: BackendKind,
        program_digest: impl Into<String>,
        proof: Vec<u8>,
        verification_key: Vec<u8>,
        public_inputs: Vec<FieldElement>,
    ) -> ProofArtifact {
        ProofArtifact::new(
            backend,
            program_digest,
            proof,
            verification_key,
            public_inputs,
        )
}

    fn make_test_proof(digest: &str) -> (ProofArtifact, CompiledProgram) {
        let program = Program {
            name: format!("test-{digest}"),
            field: FieldId::Bn254,
            ..Default::default()
        };
        let compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, program);
        let artifact = test_artifact(
            BackendKind::ArkworksGroth16,
            compiled.program_digest.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            vec![FieldElement::from_i64(42)],
        );
        (artifact, compiled)
    }

    fn make_plonky3_proof(digest: &str) -> (ProofArtifact, CompiledProgram) {
        let program = Program {
            name: format!("test-{digest}"),
            field: FieldId::Goldilocks,
            ..Default::default()
        };
        let compiled = CompiledProgram::new(BackendKind::Plonky3, program);
        let artifact = test_artifact(
            BackendKind::Plonky3,
            compiled.program_digest.clone(),
            vec![10, 20, 30],
            vec![40, 50],
            vec![FieldElement::from_i64(7)],
        );
        (artifact, compiled)
    }

    #[test]
    fn groth16_requires_explicit_recursive_prove_enablement() {
        if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() == Some("1") {
            return;
        }

        let agg = Groth16Aggregator;
        let proofs = vec![
            make_test_proof("aaa"),
            make_test_proof("bbb"),
            make_test_proof("ccc"),
        ];
        let err = agg
            .aggregate(&proofs)
            .expect_err("recursive prove must be opt-in");
        assert!(err.to_string().contains("ZKF_RECURSIVE_PROVE=1"));
    }

    #[test]
    fn groth16_rejects_wrong_backend() {
        let agg = Groth16Aggregator;
        let (mut artifact, compiled) = make_test_proof("aaa");
        artifact.backend = BackendKind::Plonky3;
        assert!(agg.aggregate(&[(artifact, compiled)]).is_err());
    }

    #[test]
    fn groth16_rejects_empty() {
        let agg = Groth16Aggregator;
        assert!(agg.aggregate(&[]).is_err());
    }

    #[test]
    fn plonky3_requires_explicit_recursive_prove_enablement() {
        if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() == Some("1") {
            return;
        }

        let agg = Plonky3Aggregator;
        let proofs = vec![make_plonky3_proof("xxx"), make_plonky3_proof("yyy")];
        let err = agg
            .aggregate(&proofs)
            .expect_err("recursive prove must be opt-in");
        assert!(err.to_string().contains("ZKF_RECURSIVE_PROVE=1"));
    }
}
