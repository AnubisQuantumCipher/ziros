//! Halo2 IPA → Groth16 proof wrapper.
//!
//! Wraps a Halo2 IPA proof (Pasta curves) into a Groth16 proof (BN254) by
//! constructing a commitment-bound Groth16 circuit that constrains:
//!
//! 1. A public input `proof_commitment` that is the SHA-256 hash of the source
//!    Halo2 proof bytes, verification key, and public inputs.
//! 2. Private witness signals for each component of the commitment preimage.
//! 3. Equality constraints binding each private witness to its expected value.
//!
//! The resulting Groth16 proof is cryptographically binding: a verifier checks
//! both the Groth16 proof validity AND that the public `proof_commitment` matches
//! the original Halo2 artifacts. This is stronger than metadata-only binding
//! (the commitment is enforced inside the circuit) but does not require a full
//! in-circuit IPA verifier with non-native Pasta arithmetic.
//!
//! Verification protocol:
//! 1. Verify the wrapped Groth16 proof (standard pairing check).
//! 2. Recompute `proof_commitment = SHA256(proof || vk || public_inputs)`.
//! 3. Check that the Groth16 public input matches the recomputed commitment.

use crate::metal_runtime::{append_default_metal_telemetry, copy_standard_metal_metadata};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::wrapping::{ProofWrapper, WrapperPreview};
use zkf_core::{
    BackendKind, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact,
    Signal, Visibility, Witness, ZkfError, ZkfResult,
};

/// Wraps Halo2 IPA proofs (Pasta curves) into Groth16 proofs (BN254).
pub struct Halo2ToGroth16Wrapper;

impl Halo2ToGroth16Wrapper {
    /// Compute the binding commitment over the source proof artifacts.
    ///
    /// commitment = SHA256("zkf-halo2-wrap-v2" || proof || vk || pi_0 || ... || pi_n)
    fn compute_commitment(source_proof: &ProofArtifact) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkf-halo2-wrap-v2");
        hasher.update(&source_proof.proof);
        hasher.update(&source_proof.verification_key);
        for pi in &source_proof.public_inputs {
            hasher.update(pi.to_decimal_string().as_bytes());
            hasher.update([0u8]); // separator
        }
        format!("{:x}", hasher.finalize())
    }

    /// Build a wrapper program that constrains the proof commitment as a public input
    /// and binds each source public input as a private witness.
    fn build_wrapper_program(
        commitment_hex: &str,
        source_public_inputs: &[FieldElement],
    ) -> Program {
        let mut signals = Vec::new();
        let mut constraints = Vec::new();

        // Public input: the proof commitment (truncated to fit BN254 Fr)
        signals.push(Signal {
            name: "proof_commitment".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        });

        // Constrain commitment to its expected value
        let commitment_fe = FieldElement::new(
            num_bigint::BigInt::parse_bytes(commitment_hex.as_bytes(), 16)
                .unwrap_or_default()
                .to_string(),
        );
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal("proof_commitment".to_string()),
            rhs: Expr::Const(commitment_fe),
            label: Some("proof_commitment_binding".to_string()),
        });

        // Private inputs: each source public input, constrained to expected value
        for (i, pi) in source_public_inputs.iter().enumerate() {
            let name = format!("source_pi_{i}");
            signals.push(Signal {
                name: name.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(name),
                rhs: Expr::Const(pi.clone()),
                label: Some(format!("source_pi_{i}_binding")),
            });
        }

        Program {
            name: "halo2_to_groth16_wrapper".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints,
            ..Default::default()
        }
    }
}

impl ProofWrapper for Halo2ToGroth16Wrapper {
    fn source_backend(&self) -> BackendKind {
        BackendKind::Halo2
    }

    fn target_backend(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn wrap(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<ProofArtifact> {
        if source_proof.backend != BackendKind::Halo2 {
            return Err(ZkfError::InvalidArtifact(format!(
                "halo2-to-groth16 wrapper expected halo2 proof, got {}",
                source_proof.backend
            )));
        }

        // Step 1: Compute binding commitment
        let commitment = Self::compute_commitment(source_proof);

        // Step 2: Build wrapper program
        let program = Self::build_wrapper_program(&commitment, &source_proof.public_inputs);

        // Step 3: Build witness
        let commitment_bi =
            num_bigint::BigInt::parse_bytes(commitment.as_bytes(), 16).unwrap_or_default();
        let mut witness_values = BTreeMap::new();
        witness_values.insert(
            "proof_commitment".to_string(),
            FieldElement::from_bigint_with_field(commitment_bi, FieldId::Bn254),
        );
        for (i, pi) in source_proof.public_inputs.iter().enumerate() {
            witness_values.insert(format!("source_pi_{i}"), pi.clone());
        }
        let witness = Witness {
            values: witness_values,
        };

        // Step 4: Compile and prove with deterministic seed
        let groth16_engine = crate::backend_for(BackendKind::ArkworksGroth16);
        let mut setup_hasher = Sha256::new();
        setup_hasher.update(b"zkf-halo2-to-groth16-setup-v2");
        setup_hasher.update(source_compiled.program_digest.as_bytes());
        setup_hasher.update(commitment.as_bytes());
        let seed: [u8; 32] = setup_hasher.finalize().into();
        crate::set_setup_seed_override(Some(seed));
        let compiled = groth16_engine.compile(&program)?;
        crate::set_setup_seed_override(None);
        let groth16_proof = groth16_engine.prove(&compiled, &witness)?;

        // Step 5: Build wrapped artifact with full metadata
        let mut metadata = BTreeMap::new();
        append_default_metal_telemetry(&mut metadata);
        metadata.insert("wrapper".to_string(), "halo2-to-groth16".to_string());
        metadata.insert("wrapper_version".to_string(), "2".to_string());
        metadata.insert(
            "source_backend".to_string(),
            BackendKind::Halo2.as_str().to_string(),
        );
        metadata.insert(
            "source_digest".to_string(),
            source_compiled.program_digest.clone(),
        );
        metadata.insert(
            "source_proof_size".to_string(),
            source_proof.proof.len().to_string(),
        );
        metadata.insert("proof_commitment".to_string(), commitment.clone());
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("curve".to_string(), "bn254".to_string());
        metadata.insert("scheme".to_string(), "groth16".to_string());
        metadata.insert(
            "proof_semantics".to_string(),
            "commitment-bound-reprove".to_string(),
        );
        metadata.insert(
            "wrapper_semantics".to_string(),
            "commitment-bound".to_string(),
        );
        metadata.insert(
            "prover_acceleration_scope".to_string(),
            "target-groth16-prover-only".to_string(),
        );
        // Commitment-bound wrapping is attestation-level, not full algebraic binding.
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        metadata.insert("algebraic_binding".to_string(), "false".to_string());
        metadata.insert("in_circuit_verification".to_string(), "false".to_string());
        metadata.insert(
            "aggregation_semantics".to_string(),
            "commitment-bound-attestation-wrapper".to_string(),
        );
        metadata.insert(
            "batch_program_digest".to_string(),
            groth16_proof.program_digest.clone(),
        );

        // Store source VK and proof hashes for verification
        let source_vk_digest = {
            let mut h = Sha256::new();
            h.update(&source_proof.verification_key);
            format!("{:x}", h.finalize())
        };
        metadata.insert("source_vk_digest".to_string(), source_vk_digest);
        metadata.insert(
            "source_public_input_count".to_string(),
            source_proof.public_inputs.len().to_string(),
        );
        for (i, pi) in source_proof.public_inputs.iter().enumerate() {
            metadata.insert(format!("source_public_input_{i}"), pi.to_decimal_string());
        }

        // Track Metal acceleration
        let registry = zkf_core::acceleration::accelerator_registry();
        if let Ok(reg) = registry.lock() {
            metadata.insert(
                "msm_accelerator".to_string(),
                reg.best_msm().name().to_string(),
            );
        }
        copy_standard_metal_metadata(&groth16_proof.metadata, &mut metadata, None);

        for (k, v) in &groth16_proof.metadata {
            metadata
                .entry(format!("groth16_{k}"))
                .or_insert_with(|| v.clone());
        }

        Ok(ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: source_compiled.program_digest.clone(),
            proof: groth16_proof.proof,
            verification_key: groth16_proof.verification_key,
            public_inputs: groth16_proof.public_inputs,
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        })
    }

    fn preview_wrap(
        &self,
        _source_proof: &ProofArtifact,
        _source_compiled: &CompiledProgram,
    ) -> ZkfResult<Option<WrapperPreview>> {
        Ok(Some(WrapperPreview {
            wrapper: "halo2-to-groth16".to_string(),
            source_backend: BackendKind::Halo2,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "commitment-bound-v2".to_string(),
            trust_model: "attestation".to_string(),
            trust_model_description: Some(
                "Groth16 binds a source-proof commitment, but does not enforce a full in-circuit IPA verifier"
                    .to_string(),
            ),
            estimated_constraints: None,
            estimated_memory_bytes: None,
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: Some(
                "halo2-to-groth16 uses commitment-bound reprove semantics rather than full algebraic verification"
                    .to_string(),
            ),
        }))
    }

    fn verify_wrapped(&self, wrapped_proof: &ProofArtifact) -> ZkfResult<bool> {
        if wrapped_proof.backend != BackendKind::ArkworksGroth16 {
            return Err(ZkfError::InvalidArtifact(format!(
                "halo2-to-groth16 wrapper expected groth16 wrapped proof, got {}",
                wrapped_proof.backend
            )));
        }

        let status = wrapped_proof
            .metadata
            .get("status")
            .map(String::as_str)
            .unwrap_or("");

        match status {
            "wrapped-v2" => self.verify_wrapped_v2(wrapped_proof),
            "wrapped-v1" => self.verify_wrapped_v1(wrapped_proof),
            _ => Err(ZkfError::InvalidArtifact(format!(
                "unknown wrapped proof status: '{status}'"
            ))),
        }
    }
}

impl Halo2ToGroth16Wrapper {
    /// Verify a v2 commitment-bound wrapped proof.
    fn verify_wrapped_v2(&self, wrapped_proof: &ProofArtifact) -> ZkfResult<bool> {
        let commitment = wrapped_proof
            .metadata
            .get("proof_commitment")
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "missing proof_commitment in wrapped metadata".to_string(),
                )
            })?;

        let batch_digest = wrapped_proof
            .metadata
            .get("batch_program_digest")
            .cloned()
            .unwrap_or_default();
        let source_digest = wrapped_proof.metadata.get("source_digest").ok_or_else(|| {
            ZkfError::InvalidArtifact("missing source_digest in wrapped metadata".to_string())
        })?;

        // Reconstruct the public input (commitment as field element)
        let commitment_bi =
            num_bigint::BigInt::parse_bytes(commitment.as_bytes(), 16).unwrap_or_default();
        let public_inputs = vec![FieldElement::from_bigint_with_field(
            commitment_bi,
            FieldId::Bn254,
        )];

        // Build minimal compiled program for Groth16 verification
        let pi_count: usize = wrapped_proof
            .metadata
            .get("source_public_input_count")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut source_public_inputs = Vec::with_capacity(pi_count);
        for i in 0..pi_count {
            let encoded = wrapped_proof
                .metadata
                .get(&format!("source_public_input_{i}"))
                .ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "missing source_public_input_{i} in wrapped metadata"
                    ))
                })?;
            source_public_inputs.push(FieldElement::new(encoded.clone()));
        }
        let program = Self::build_wrapper_program(commitment, &source_public_inputs);

        let groth16_engine = crate::backend_for(BackendKind::ArkworksGroth16);
        let mut setup_hasher = Sha256::new();
        setup_hasher.update(b"zkf-halo2-to-groth16-setup-v2");
        setup_hasher.update(source_digest.as_bytes());
        setup_hasher.update(commitment.as_bytes());
        let setup_seed: [u8; 32] = setup_hasher.finalize().into();
        let compiled =
            crate::with_setup_seed_override(Some(setup_seed), || groth16_engine.compile(&program))?;
        if !batch_digest.is_empty() && compiled.program_digest != batch_digest {
            return Err(ZkfError::InvalidArtifact(
                "halo2-to-groth16 batch program digest mismatch".to_string(),
            ));
        }

        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: compiled.program_digest.clone(),
            proof: wrapped_proof.proof.clone(),
            verification_key: wrapped_proof.verification_key.clone(),
            public_inputs,
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };

        groth16_engine.verify(&compiled, &artifact)
    }

    /// Legacy v1 verification (metadata-only, no commitment binding).
    fn verify_wrapped_v1(&self, wrapped_proof: &ProofArtifact) -> ZkfResult<bool> {
        // v1 proofs don't have in-circuit commitment binding.
        // We can only verify the Groth16 proof itself.
        let groth16_engine = crate::backend_for(BackendKind::ArkworksGroth16);
        let program = Program {
            name: "halo2_wrapper_verify".to_string(),
            field: FieldId::Bn254,
            ..Default::default()
        };
        let compiled = groth16_engine.compile(&program)?;
        groth16_engine.verify(&compiled, wrapped_proof)
    }
}

/// Verify a wrapped Halo2 proof given the original source artifacts.
///
/// This performs the full verification:
/// 1. Recompute the commitment from source artifacts
/// 2. Check it matches the wrapped proof's commitment
/// 3. Verify the Groth16 proof
pub fn verify_wrapped_with_source(
    wrapped_proof: &ProofArtifact,
    source_proof: &ProofArtifact,
) -> ZkfResult<bool> {
    let stored_commitment = wrapped_proof
        .metadata
        .get("proof_commitment")
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("missing proof_commitment in wrapped metadata".to_string())
        })?;

    let recomputed = Halo2ToGroth16Wrapper::compute_commitment(source_proof);
    if &recomputed != stored_commitment {
        return Ok(false);
    }

    let wrapper = Halo2ToGroth16Wrapper;
    wrapper.verify_wrapped(wrapped_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldElement;

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

    #[test]
    fn source_and_target_backends() {
        let wrapper = Halo2ToGroth16Wrapper;
        assert_eq!(wrapper.source_backend(), BackendKind::Halo2);
        assert_eq!(wrapper.target_backend(), BackendKind::ArkworksGroth16);
    }

    #[test]
    fn rejects_wrong_source_backend() {
        let wrapper = Halo2ToGroth16Wrapper;
        let artifact = test_artifact(BackendKind::Plonky3, "test", vec![1, 2, 3], vec![], vec![]);
        let compiled = CompiledProgram::new(BackendKind::Halo2, Program::default());
        assert!(wrapper.wrap(&artifact, &compiled).is_err());
    }

    #[test]
    fn wrap_marks_commitment_bound_semantics() {
        let wrapper = Halo2ToGroth16Wrapper;
        let source_proof = test_artifact(
            BackendKind::Halo2,
            "test_halo2",
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![FieldElement::from_i64(7)],
        );
        let compiled = CompiledProgram::new(
            BackendKind::Halo2,
            Program {
                name: "halo2_wrapper_source".to_string(),
                field: FieldId::PastaFp,
                signals: vec![Signal {
                    name: "w0".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                }],
                ..Default::default()
            },
        );

        let wrapped = wrapper
            .wrap(&source_proof, &compiled)
            .expect("wrapped proof");
        assert_eq!(
            wrapped.metadata.get("proof_semantics").map(String::as_str),
            Some("commitment-bound-reprove")
        );
        assert_eq!(
            wrapped
                .metadata
                .get("wrapper_semantics")
                .map(String::as_str),
            Some("commitment-bound")
        );
        assert_eq!(
            wrapped
                .metadata
                .get("algebraic_binding")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            wrapped.metadata.get("trust_model").map(String::as_str),
            Some("attestation")
        );
        assert_eq!(
            wrapped.metadata.get("status").map(String::as_str),
            Some("wrapped-v2")
        );
        assert!(wrapped.metadata.contains_key("proof_commitment"));
    }

    #[test]
    fn wrap_and_verify_roundtrip() {
        let wrapper = Halo2ToGroth16Wrapper;
        let source_proof = test_artifact(
            BackendKind::Halo2,
            "roundtrip_test",
            vec![10, 20, 30, 40],
            vec![50, 60, 70, 80],
            vec![FieldElement::from_i64(42)],
        );
        let compiled = CompiledProgram::new(
            BackendKind::Halo2,
            Program {
                name: "halo2_roundtrip".to_string(),
                field: FieldId::PastaFp,
                ..Default::default()
            },
        );

        let wrapped = wrapper.wrap(&source_proof, &compiled).expect("wrap");

        // Verify the wrapped proof
        let verified = wrapper.verify_wrapped(&wrapped).expect("verify");
        assert!(verified);

        // Verify with source artifacts
        let full_verified =
            verify_wrapped_with_source(&wrapped, &source_proof).expect("verify with source");
        assert!(full_verified);
    }

    #[test]
    fn verify_detects_tampered_commitment() {
        let wrapper = Halo2ToGroth16Wrapper;
        let source_proof = test_artifact(
            BackendKind::Halo2,
            "tamper_test",
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![],
        );

        // Different source proof to create mismatched commitment
        let tampered_source = test_artifact(
            BackendKind::Halo2,
            "tamper_test",
            vec![99, 99, 99],
            vec![4, 5, 6],
            vec![],
        );

        let compiled = CompiledProgram::new(
            BackendKind::Halo2,
            Program {
                name: "halo2_tamper".to_string(),
                field: FieldId::PastaFp,
                ..Default::default()
            },
        );

        let wrapped = wrapper.wrap(&source_proof, &compiled).expect("wrap");

        // Verify with tampered source should fail (commitment mismatch)
        let result = verify_wrapped_with_source(&wrapped, &tampered_source).expect("verify");
        assert!(!result);
    }

    #[test]
    fn commitment_is_deterministic() {
        let proof = test_artifact(
            BackendKind::Halo2,
            "det_test",
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![FieldElement::from_i64(7)],
        );
        let c1 = Halo2ToGroth16Wrapper::compute_commitment(&proof);
        let c2 = Halo2ToGroth16Wrapper::compute_commitment(&proof);
        assert_eq!(c1, c2);
    }
}
