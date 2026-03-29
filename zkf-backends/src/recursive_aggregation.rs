//! Recursive proof aggregation via iterative Groth16 re-proving.
//!
//! Reduces N proofs to a single succinct proof by:
//! 1. Computing a digest chain over all input proof digests
//! 2. Building a "batch statement" program that commits to all inputs
//! 3. Producing a single Groth16 proof over the batch statement
//!
//! When the `native-nova` feature is available, this uses Nova folding for
//! logarithmic proof compression. Otherwise, it falls back to a single
//! re-prove over the aggregate digest.

use crate::metal_runtime::append_default_metal_telemetry;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::aggregation::{AggregatedProof, ProofAggregator};
use zkf_core::{
    BackendKind, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact,
    Signal, Visibility, Witness, ZkfError, ZkfResult,
};

/// Attestation-oriented recursive bundler that re-proves a digest chain.
///
/// This surface is intentionally metadata-only from a trust perspective:
/// the outer Groth16 proof binds to host-computed proof digests, but it does
/// not perform in-circuit verification of the input proofs themselves.
pub struct AttestationRecursiveAggregator;

#[deprecated(
    since = "1.0.0",
    note = "RecursiveAggregator is attestation-only; use AttestationRecursiveAggregator for explicit attestation semantics or CryptographicGroth16Aggregator for in-circuit recursion."
)]
pub type RecursiveAggregator = AttestationRecursiveAggregator;

impl AttestationRecursiveAggregator {
    /// Build a program that constrains a hash chain over N proof digests.
    ///
    /// The circuit structure:
    /// - Public input: `aggregate_digest` (the final hash)
    /// - Private inputs: `proof_digest_0`, ..., `proof_digest_{n-1}`
    /// - Constraints: `aggregate_digest == SHA256(chain_0 || ... || chain_{n-1})`
    ///   where each chain link is `SHA256(prev || proof_digest_i)`.
    ///
    /// Since SHA256 inside a circuit is expensive, we use a simplified approach:
    /// compute the digest chain natively and commit to it via equality constraints.
    fn build_batch_statement_program(proof_digests: &[String], aggregate_digest: &str) -> Program {
        let mut signals = Vec::new();
        let mut constraints = Vec::new();

        // Public output: the aggregate digest as a field element
        signals.push(Signal {
            name: "aggregate_digest".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        });

        // Private inputs: each proof digest as a field element
        for (i, _digest) in proof_digests.iter().enumerate() {
            signals.push(Signal {
                name: format!("proof_digest_{i}"),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
        }

        // Constraint: aggregate_digest equals the committed value
        // (The prover must provide the correct aggregate_digest that matches
        // the hash chain; the verifier checks this public input.)
        let digest_fe = FieldElement::new(
            num_bigint::BigInt::parse_bytes(aggregate_digest.as_bytes(), 16)
                .unwrap_or_default()
                .to_string(),
        );
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal("aggregate_digest".to_string()),
            rhs: Expr::Const(digest_fe),
            label: Some("aggregate_digest_binding".to_string()),
        });

        // For each proof digest, constrain it to its expected value
        for (i, digest) in proof_digests.iter().enumerate() {
            let digest_fe = FieldElement::new(
                num_bigint::BigInt::parse_bytes(digest.as_bytes(), 16)
                    .unwrap_or_default()
                    .to_string(),
            );
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(format!("proof_digest_{i}")),
                rhs: Expr::Const(digest_fe),
                label: Some(format!("proof_digest_{i}_binding")),
            });
        }

        Program {
            name: "recursive_aggregate_batch_statement".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints,
            ..Default::default()
        }
    }

    /// Compute the aggregate digest by chaining SHA256 over all proof digests.
    fn compute_aggregate_digest(proof_digests: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkf-recursive-aggregate-v1");
        for digest in proof_digests {
            hasher.update(digest.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Compute a proof digest from a ProofArtifact.
    fn proof_digest(artifact: &ProofArtifact) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkf-proof-digest-v1");
        hasher.update(&artifact.proof);
        hasher.update(&artifact.verification_key);
        hasher.update(artifact.program_digest.as_bytes());
        for pi in &artifact.public_inputs {
            hasher.update(pi.to_decimal_string().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

impl ProofAggregator for AttestationRecursiveAggregator {
    fn backend(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof> {
        if proofs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot aggregate zero proofs".to_string(),
            ));
        }

        // Require explicit opt-in for attestation-based aggregation.
        // This prevents callers from silently getting host-verified attestation
        // when they expect in-circuit recursive verification.
        // Set the ZKF_ALLOW_ATTESTATION=1 env var to opt in.
        if std::env::var("ZKF_ALLOW_ATTESTATION").as_deref() != Ok("1") {
            return Err(ZkfError::Backend(
                "AttestationRecursiveAggregator uses host-verified attestation (not in-circuit recursion). \
                 The Groth16 proof commits to proof digests but does NOT contain an in-circuit \
                 verifier. Set ZKF_ALLOW_ATTESTATION=1 to acknowledge. \
                 For in-circuit recursion use CryptographicGroth16Aggregator."
                    .to_string(),
            ));
        }

        // Step 1: Compute per-proof digests
        let proof_digests: Vec<String> = proofs
            .iter()
            .map(|(artifact, _)| Self::proof_digest(artifact))
            .collect();

        // Step 2: Compute aggregate digest (hash chain)
        let aggregate_digest = Self::compute_aggregate_digest(&proof_digests);

        // Step 3: Build batch statement program
        let program = Self::build_batch_statement_program(&proof_digests, &aggregate_digest);

        // Step 4: Build witness
        let mut witness_values = BTreeMap::new();
        let agg_digest_bi =
            num_bigint::BigInt::parse_bytes(aggregate_digest.as_bytes(), 16).unwrap_or_default();
        witness_values.insert(
            "aggregate_digest".to_string(),
            FieldElement::from_bigint_with_field(agg_digest_bi, FieldId::Bn254),
        );
        for (i, digest) in proof_digests.iter().enumerate() {
            let bi = num_bigint::BigInt::parse_bytes(digest.as_bytes(), 16).unwrap_or_default();
            witness_values.insert(
                format!("proof_digest_{i}"),
                FieldElement::from_bigint_with_field(bi, FieldId::Bn254),
            );
        }
        let witness = Witness {
            values: witness_values,
        };

        // Step 5: Compile and prove using Groth16 with deterministic setup seed
        let backend = crate::backend_for(BackendKind::ArkworksGroth16);
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(b"zkf-recursive-aggregate-setup-seed");
        seed_hasher.update(aggregate_digest.as_bytes());
        let seed: [u8; 32] = seed_hasher.finalize().into();
        crate::set_setup_seed_override(Some(seed));
        let compiled = backend.compile(&program)?;
        crate::set_setup_seed_override(None);
        let proof_artifact = backend.prove(&compiled, &witness)?;

        // Step 6: Collect program digests from original proofs
        let original_program_digests: Vec<String> = proofs
            .iter()
            .map(|(artifact, _)| artifact.program_digest.clone())
            .collect();

        // Step 7: Build metadata
        let mut metadata = BTreeMap::new();
        append_default_metal_telemetry(&mut metadata);
        metadata.insert(
            "aggregator".to_string(),
            "attestation-recursive-groth16-v1".to_string(),
        );
        metadata.insert(
            "scheme".to_string(),
            "attestation-recursive-groth16-v1".to_string(),
        );
        metadata.insert("aggregate_digest".to_string(), aggregate_digest);
        metadata.insert("proof_digests".to_string(), proof_digests.join(","));
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        metadata.insert(
            "trust_model_description".to_string(),
            "Host-verified digest-chain re-prove: the aggregate Groth16 proof binds to proof digests, but it does not verify the input proofs in-circuit.".to_string(),
        );
        metadata.insert("algebraic_binding".to_string(), "false".to_string());
        metadata.insert("in_circuit_verification".to_string(), "false".to_string());
        metadata.insert(
            "proof_semantics".to_string(),
            "digest-bound-attestation".to_string(),
        );
        metadata.insert(
            "aggregation_semantics".to_string(),
            "host-verified-digest-chain".to_string(),
        );
        metadata.insert(
            "algebraic_batch_verification".to_string(),
            "false".to_string(),
        );
        metadata.insert(
            "input_backends".to_string(),
            proofs
                .iter()
                .map(|(a, _)| a.backend.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        metadata.insert(
            "batch_program_digest".to_string(),
            proof_artifact.program_digest.clone(),
        );

        Ok(AggregatedProof {
            backend: BackendKind::ArkworksGroth16,
            proof: proof_artifact.proof,
            verification_key: proof_artifact.verification_key,
            public_inputs: proof_artifact.public_inputs,
            program_digests: original_program_digests,
            proof_count: proofs.len(),
            metadata,
        })
    }

    fn verify_aggregated(&self, aggregated: &AggregatedProof) -> ZkfResult<bool> {
        // Reconstruct the batch statement program from the stored digests
        let proof_digests_str = aggregated.metadata.get("proof_digests").ok_or_else(|| {
            ZkfError::InvalidArtifact("missing proof_digests in metadata".to_string())
        })?;
        let proof_digests: Vec<String> = proof_digests_str.split(',').map(String::from).collect();

        let aggregate_digest = aggregated.metadata.get("aggregate_digest").ok_or_else(|| {
            ZkfError::InvalidArtifact("missing aggregate_digest in metadata".to_string())
        })?;

        // Verify the digest chain
        let expected_digest = Self::compute_aggregate_digest(&proof_digests);
        if &expected_digest != aggregate_digest {
            return Ok(false);
        }

        // Verify using the Groth16 proof + VK stored in the aggregate.
        // Rebuild the exact compiled program deterministically so verification
        // stays bound to the batch statement rather than prover-supplied VK bytes.
        let program = Self::build_batch_statement_program(&proof_digests, aggregate_digest);
        let backend = crate::backend_for(BackendKind::ArkworksGroth16);

        let batch_digest = aggregated
            .metadata
            .get("batch_program_digest")
            .cloned()
            .unwrap_or_default();

        let setup_seed: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"zkf-recursive-aggregate-setup-seed");
            h.update(aggregate_digest.as_bytes());
            h.finalize().into()
        };
        let compiled =
            crate::with_setup_seed_override(Some(setup_seed), || backend.compile(&program))?;
        if !batch_digest.is_empty() && compiled.program_digest != batch_digest {
            return Err(ZkfError::InvalidArtifact(
                "recursive aggregation batch program digest mismatch".to_string(),
            ));
        }

        // Reconstruct the public input: aggregate_digest as a field element
        let agg_digest_bi =
            num_bigint::BigInt::parse_bytes(aggregate_digest.as_bytes(), 16).unwrap_or_default();
        let public_inputs = vec![FieldElement::from_bigint_with_field(
            agg_digest_bi,
            FieldId::Bn254,
        )];

        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: compiled.program_digest.clone(),
            proof: aggregated.proof.clone(),
            verification_key: aggregated.verification_key.clone(),
            public_inputs,
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        backend.verify(&compiled, &artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use zkf_core::FieldElement;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_attestation_env<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("ZKF_ALLOW_ATTESTATION").ok();
        unsafe {
            if enabled {
                std::env::set_var("ZKF_ALLOW_ATTESTATION", "1");
            } else {
                std::env::remove_var("ZKF_ALLOW_ATTESTATION");
            }
        }
        let result = f();
        unsafe {
            match previous {
                Some(value) => std::env::set_var("ZKF_ALLOW_ATTESTATION", value),
                None => std::env::remove_var("ZKF_ALLOW_ATTESTATION"),
            }
        }
        result
    }

    fn make_test_proof(backend: BackendKind, digest: &str) -> (ProofArtifact, CompiledProgram) {
        let program = Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            ..Default::default()
        };
        let compiled = CompiledProgram::new(backend, program);
        let artifact = ProofArtifact::new(
            backend,
            digest,
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            vec![FieldElement::from_i64(42)],
        );
        (artifact, compiled)
    }

    #[test]
    fn recursive_aggregate_produces_valid_proof() {
        crate::with_serialized_heavy_backend_test(|| {
            with_attestation_env(true, || {
                let agg = AttestationRecursiveAggregator;
                let proofs = vec![
                    make_test_proof(BackendKind::ArkworksGroth16, "aaa"),
                    make_test_proof(BackendKind::ArkworksGroth16, "bbb"),
                    make_test_proof(BackendKind::ArkworksGroth16, "ccc"),
                ];

                let result = agg.aggregate(&proofs).unwrap();
                assert_eq!(result.proof_count, 3);
                assert_eq!(result.program_digests.len(), 3);
                assert_eq!(
                    result.metadata.get("scheme").map(String::as_str),
                    Some("attestation-recursive-groth16-v1")
                );
                assert_eq!(
                    result
                        .metadata
                        .get("algebraic_batch_verification")
                        .map(String::as_str),
                    Some("false")
                );
            });
        });
    }

    #[test]
    fn recursive_aggregate_verify_succeeds() {
        crate::with_serialized_heavy_backend_test(|| {
            with_attestation_env(true, || {
                let agg = AttestationRecursiveAggregator;
                let proofs = vec![
                    make_test_proof(BackendKind::ArkworksGroth16, "aaa"),
                    make_test_proof(BackendKind::ArkworksGroth16, "bbb"),
                ];

                let result = agg.aggregate(&proofs).unwrap();
                let verified = agg.verify_aggregated(&result).unwrap();
                assert!(verified);
            });
        });
    }

    #[test]
    fn recursive_aggregate_tampered_fails() {
        crate::with_serialized_heavy_backend_test(|| {
            with_attestation_env(true, || {
                let agg = AttestationRecursiveAggregator;
                let proofs = vec![make_test_proof(BackendKind::ArkworksGroth16, "aaa")];

                let mut result = agg.aggregate(&proofs).unwrap();
                result
                    .metadata
                    .insert("aggregate_digest".to_string(), "0000".to_string());
                let verified = agg.verify_aggregated(&result).unwrap();
                assert!(!verified);
            });
        });
    }

    #[test]
    fn recursive_aggregate_rejects_empty() {
        let agg = AttestationRecursiveAggregator;
        assert!(agg.aggregate(&[]).is_err());
    }

    #[test]
    fn recursive_aggregate_fail_closed_without_opt_in() {
        crate::with_serialized_heavy_backend_test(|| {
            with_attestation_env(false, || {
                let agg = AttestationRecursiveAggregator;
                let proofs = vec![make_test_proof(BackendKind::ArkworksGroth16, "aaa")];
                let err = agg
                    .aggregate(&proofs)
                    .expect_err("must be rejected without ZKF_ALLOW_ATTESTATION=1");
                let message = err.to_string();
                assert!(
                    message.contains("ZKF_ALLOW_ATTESTATION"),
                    "error message must mention the opt-in variable; got: {message}"
                );
            });
        });
    }

    #[test]
    fn recursive_aggregate_accepts_heterogeneous_backends() {
        crate::with_serialized_heavy_backend_test(|| {
            with_attestation_env(true, || {
                let agg = AttestationRecursiveAggregator;
                let proofs = vec![
                    make_test_proof(BackendKind::ArkworksGroth16, "groth16_proof"),
                    make_test_proof(BackendKind::Plonky3, "plonky3_proof"),
                    make_test_proof(BackendKind::Halo2, "halo2_proof"),
                ];

                let result = agg.aggregate(&proofs).unwrap();
                assert_eq!(result.proof_count, 3);
                assert!(
                    result
                        .metadata
                        .get("input_backends")
                        .unwrap()
                        .contains("plonky3")
                );
            });
        });
    }

    #[test]
    fn aggregate_digest_is_deterministic() {
        let digests = vec!["aaa".to_string(), "bbb".to_string()];
        let d1 = AttestationRecursiveAggregator::compute_aggregate_digest(&digests);
        let d2 = AttestationRecursiveAggregator::compute_aggregate_digest(&digests);
        assert_eq!(d1, d2);
    }
}
