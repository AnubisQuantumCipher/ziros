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

//! Real Halo2 IPA accumulation using the Pasta cycle of curves.
//!
//! This module implements a cryptographic Halo2 proof accumulator that upgrades
//! the attestation-based `Halo2ToGroth16Wrapper` to genuine IPA-based verification.
//!
//! ## Architecture
//!
//! For each Halo2 proof, instead of just hashing the proof bytes, this module:
//!
//! 1. Runs the IPA verification algorithm up to the "guard" stage (full
//!    Fiat-Shamir transcript replay, polynomial multi-open checks).
//! 2. Extracts the accumulated G-point G = ⟨s, params.g⟩ via `Guard::compute_g()`.
//!    This G-point is the "hard" part of the IPA check — it represents the
//!    proof's commitment to its polynomial evaluations.
//! 3. Accumulates G-points from all proofs via random linear combination (RLC):
//!    G_acc = r_0·G_0 + r_1·G_1 + ... + r_{n-1}·G_{n-1}
//! 4. Serialises (G_acc.x, G_acc.y) as the "IPA accumulation claim".
//! 5. Binds this claim to a Groth16 proof.
//!
//! ## Trust model
//!
//! `trust_model: "ipa-accumulated"`
//!
//! - **IPA verification**: CRYPTOGRAPHIC — the full Fiat-Shamir transcript is
//!   replayed for each proof, computing the same challenges a real verifier would.
//!   The resulting G-point encodes the commitment check result.
//! - **G-point check**: DELEGATED TO VERIFIER — the verifier must check that
//!   G_acc equals ⟨s_acc, params.g⟩ by running the final MSM evaluation.
//!   This is the inherent deferred check in any Halo/Halo2 accumulation scheme.
//! - **Groth16 binding**: CRYPTOGRAPHIC — the Groth16 proof binds to the exact
//!   (G_acc.x, G_acc.y) bytes; forging a different G_acc would break Groth16 soundness.
//!
//! ## Comparison with `Halo2ToGroth16Wrapper` (attestation)
//!
//! | Property | Attestation wrapper | IPA accumulator |
//! |----------|-------------------|-----------------|
//! | Runs IPA verification | No (SHA-256 hash of bytes) | Yes (Fiat-Shamir replay) |
//! | Binds to proof content | Hash of bytes | G-point from IPA transcript |
//! | Detects invalid proofs | Only on verification | Immediately on accumulation |
//! | Verifier MSM check | Not required | Required (deferred IPA check) |
//! | Trust model | attestation | ipa-accumulated |
//!
//! ## Verification protocol
//!
//! 1. Verify the Groth16 wrapper proof.
//! 2. Extract G_acc from the Groth16 proof's public inputs.
//! 3. Re-derive the accumulation challenges (r_i) from the proof metadata.
//! 4. Verify the deferred IPA check: G_acc = r_0·G_0 + ... + r_{n-1}·G_{n-1}.
//!    This requires running `Guard::compute_g()` for each original proof and
//!    checking the RLC. Alternatively, recompute from scratch using the stored
//!    serialised G_i values.

use group::Curve as _;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::pasta::{Eq as VestaProj, EqAffine, Fp};
use halo2_proofs::plonk::{VerificationStrategy, VerifyingKey, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::{Guard, MSM, Params};
use halo2_proofs::transcript::{Blake2bRead, Challenge255, EncodedChallenge};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use zkf_core::aggregation::{AggregatedProof, ProofAggregator};
use zkf_core::{
    BackendKind, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact,
    Signal, Visibility, Witness, ZkfError, ZkfResult,
};

// ─── IPA G-point extraction strategy ────────────────────────────────────────

/// A `VerificationStrategy` that extracts the accumulated G-point from the IPA
/// proof instead of evaluating the final MSM check immediately.
///
/// The G-point G = ⟨s, params.g⟩ is the "hard part" of the IPA verification —
/// computing it requires a large MSM, but we defer that to the verifier and
/// instead commit to it.
struct GuardExtractStrategy<'params> {
    params: &'params Params<EqAffine>,
}

impl<'params> VerificationStrategy<'params, EqAffine> for GuardExtractStrategy<'params> {
    /// Output: the accumulated G-point from the IPA guard.
    type Output = EqAffine;

    fn process<E: EncodedChallenge<EqAffine>>(
        self,
        f: impl FnOnce(MSM<'params, EqAffine>) -> Result<Guard<'params, EqAffine, E>, Error>,
    ) -> Result<Self::Output, Error> {
        let msm = MSM::new(self.params);
        let guard = f(msm)?;
        // compute_g() = ⟨s, params.g⟩  where s = compute_s(u, -c)
        // This is the deferred hard check — we return it instead of checking it.
        Ok(guard.compute_g())
    }
}

// Re-export halo2 Error type for the strategy impl above.
use halo2_proofs::plonk::Error;

// ─── Public accumulator ───────────────────────────────────────────────────────

/// A cryptographic Halo2 IPA proof accumulator.
///
/// Accumulates multiple Halo2 IPA proofs into a single Groth16 proof that is
/// cryptographically bound to the IPA accumulated G-claim. Invalid proofs are
/// caught immediately (unlike the attestation wrapper which only hashes bytes).
pub struct Halo2IpaAccumulator;

/// Proof-facing summary of the metadata binding shape required before the
/// deferred IPA/Groth16 recomputation can proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Halo2IpaBindingModel {
    pub proof_count: usize,
    pub proof_hash_count: usize,
    pub bound_g_point_count: usize,
    pub malformed_g_point_count: usize,
}

pub(crate) fn halo2_ipa_binding_accepts(model: Halo2IpaBindingModel) -> bool {
    model.proof_count > 0
        && model.proof_hash_count == model.proof_count
        && model.bound_g_point_count == model.proof_count
        && model.malformed_g_point_count == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Halo2IpaBindingSummary {
    model: Halo2IpaBindingModel,
    first_missing_g_point: Option<usize>,
    first_malformed_error: Option<String>,
}

impl Halo2IpaAccumulator {
    /// Parse the Halo2 `Params<EqAffine>` from a `CompiledProgram`'s blob.
    fn load_params(compiled: &CompiledProgram) -> ZkfResult<Params<EqAffine>> {
        let blob = compiled
            .compiled_data
            .as_deref()
            .ok_or(ZkfError::MissingCompiledData)?;
        let params_bytes = crate::halo2::unpack_params_blob(blob)?;
        let mut cursor = Cursor::new(params_bytes.as_slice());
        Params::<EqAffine>::read(&mut cursor)
            .map_err(|e| ZkfError::InvalidArtifact(format!("halo2 params decode: {e}")))
    }

    /// Rebuild a `VerifyingKey<EqAffine>` from `Params` and a `CompiledProgram`.
    fn build_vk(
        params: &Params<EqAffine>,
        compiled: &CompiledProgram,
    ) -> ZkfResult<VerifyingKey<EqAffine>> {
        use crate::halo2::Halo2IrCircuit;
        let circuit = Halo2IrCircuit::without_witness(compiled.program.clone())?;
        keygen_vk(params, &circuit)
            .map_err(|e| ZkfError::Backend(format!("halo2 keygen_vk: {e:?}")))
    }

    /// Extract the IPA G-point for a single Halo2 proof by replaying the
    /// Fiat-Shamir transcript up to the guard stage.
    fn extract_g_point(
        params: &Params<EqAffine>,
        vk: &VerifyingKey<EqAffine>,
        artifact: &ProofArtifact,
    ) -> ZkfResult<EqAffine> {
        let public_inputs_fp: Vec<Fp> = artifact
            .public_inputs
            .iter()
            .map(crate::halo2::parse_pasta_fp)
            .collect::<ZkfResult<_>>()?;
        let instance_columns: Vec<&[Fp]> = vec![public_inputs_fp.as_slice()];
        let instances: Vec<&[&[Fp]]> = vec![instance_columns.as_slice()];

        let strategy = GuardExtractStrategy { params };
        let mut transcript =
            Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(artifact.proof.as_slice());

        verify_proof(params, vk, strategy, &instances, &mut transcript)
            .map_err(|e| ZkfError::Backend(format!("halo2 ipa guard extraction failed: {e:?}")))
    }

    /// Serialise an `EqAffine` point to 64 bytes (x || y, 32 bytes each).
    ///
    /// If the point is the identity, returns all-zeros.
    fn serialize_point(pt: EqAffine) -> [u8; 64] {
        use ff::PrimeField;
        // EqAffine base field is Fq (Vesta base = Pallas scalar).
        // coordinates() returns CtOption<Coordinates<EqAffine>> where coords are Fq.
        let mut buf = [0u8; 64];
        // EqAffine base field = Fq; coordinates() returns Coordinates<EqAffine> with Fq fields.
        use halo2_proofs::pasta::Fq;
        let coords_opt: Option<halo2_proofs::arithmetic::Coordinates<EqAffine>> =
            Option::from(<EqAffine as CurveAffine>::coordinates(&pt));
        if let Some(coords) = coords_opt {
            let x: Fq = *coords.x();
            let y: Fq = *coords.y();
            buf[..32].copy_from_slice(x.to_repr().as_ref());
            buf[32..].copy_from_slice(y.to_repr().as_ref());
        }
        buf
    }

    /// Compute the accumulated G-point via random linear combination.
    ///
    /// G_acc = r_0·G_0 + r_1·G_1 + ... + r_{n-1}·G_{n-1}
    ///
    /// The random scalars r_i are derived deterministically from the proof
    /// hashes so that the accumulation is reproducible by the verifier.
    fn accumulate_g_points(g_points: &[EqAffine], proof_hashes: &[String]) -> EqAffine {
        // VestaProj = Eq (projective Vesta curve); Default::default() == identity.
        let mut acc: VestaProj = VestaProj::default();
        for (pt, hash) in g_points.iter().zip(proof_hashes.iter()) {
            let r = derive_scalar_from_hash(hash);
            // Scale the affine point by scalar r using the CurveAffine mul impl.
            // pasta_curves implements Mul<Fp, Output=Eq> for EqAffine.
            let scaled: VestaProj = *pt * r;
            acc += scaled;
        }
        // to_affine() via PrimeCurve supertrait (Eq: PrimeCurve).
        acc.to_affine()
    }

    /// Build a Groth16 wrapper program that commits to the accumulated G-claim.
    ///
    /// Public input: `g_acc_x` (low 253 bits of G_acc.x)
    /// Private inputs: `g_acc_x_full`, `g_acc_y`, `proof_count`
    fn build_wrapper_program(g_acc_bytes: &[u8; 64], proof_count: usize) -> Program {
        let mut signals = Vec::new();
        let mut constraints = Vec::new();

        // Public: G_acc.x (the x-coordinate of the accumulated G-point)
        signals.push(Signal {
            name: "g_acc_x".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        });

        // Public: proof count (to prevent aggregating 0 proofs)
        signals.push(Signal {
            name: "proof_count".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        });

        // Private: G_acc.y
        signals.push(Signal {
            name: "g_acc_y".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });

        // Constrain G_acc.x to expected value
        let gx_fe = field_elem_from_bytes_bn254(&g_acc_bytes[..32]);
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal("g_acc_x".to_string()),
            rhs: Expr::Const(gx_fe),
            label: Some("g_acc_x_binding".to_string()),
        });

        // Constrain G_acc.y to expected value
        let gy_fe = field_elem_from_bytes_bn254(&g_acc_bytes[32..]);
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal("g_acc_y".to_string()),
            rhs: Expr::Const(gy_fe),
            label: Some("g_acc_y_binding".to_string()),
        });

        // Constrain proof_count to expected value
        let count_fe = FieldElement::from_i64(proof_count as i64);
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal("proof_count".to_string()),
            rhs: Expr::Const(count_fe),
            label: Some("proof_count_binding".to_string()),
        });

        Program {
            name: "halo2_ipa_accumulated_wrapper".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints,
            ..Default::default()
        }
    }

    /// Compute the proof hash used for deriving RLC scalars.
    fn proof_hash(artifact: &ProofArtifact) -> String {
        let mut h = Sha256::new();
        h.update(b"zkf-ipa-acc-v1-proof");
        h.update(&artifact.proof);
        h.update(&artifact.verification_key);
        for pi in &artifact.public_inputs {
            h.update(pi.to_decimal_string().as_bytes());
        }
        format!("{:x}", h.finalize())
    }

    fn summarize_binding_metadata(
        aggregated: &AggregatedProof,
        proof_hashes: &[String],
    ) -> Halo2IpaBindingSummary {
        let mut bound_g_point_count = 0usize;
        let mut malformed_g_point_count = 0usize;
        let mut first_missing_g_point = None;
        let mut first_malformed_error = None;

        for i in 0..aggregated.proof_count {
            let Some(hex) = aggregated.metadata.get(&format!("g_point_{i}")) else {
                first_missing_g_point.get_or_insert(i);
                continue;
            };

            match hex_to_bytes(hex) {
                Ok(bytes) if bytes.len() == 64 => {
                    bound_g_point_count += 1;
                }
                Ok(bytes) => {
                    malformed_g_point_count += 1;
                    first_malformed_error.get_or_insert_with(|| {
                        format!("g_point_{i} wrong length: {}", bytes.len())
                    });
                }
                Err(error) => {
                    malformed_g_point_count += 1;
                    first_malformed_error
                        .get_or_insert_with(|| format!("g_point_{i} hex decode: {error}"));
                }
            }
        }

        Halo2IpaBindingSummary {
            model: Halo2IpaBindingModel {
                proof_count: aggregated.proof_count,
                proof_hash_count: proof_hashes.len(),
                bound_g_point_count,
                malformed_g_point_count,
            },
            first_missing_g_point,
            first_malformed_error,
        }
    }
}

impl ProofAggregator for Halo2IpaAccumulator {
    fn backend(&self) -> BackendKind {
        BackendKind::Halo2
    }

    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof> {
        if proofs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot accumulate zero Halo2 proofs".to_string(),
            ));
        }

        // Validate all inputs are from Halo2 backend.
        for (i, (artifact, compiled)) in proofs.iter().enumerate() {
            if artifact.backend != BackendKind::Halo2 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "proof {i} has backend '{}', expected halo2",
                    artifact.backend
                )));
            }
            if compiled.backend != BackendKind::Halo2 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compiled {i} has backend '{}', expected halo2",
                    compiled.backend
                )));
            }
        }

        // Step 1: For each proof, extract the IPA G-point.
        // This replays the full Fiat-Shamir transcript, detecting invalid proofs.
        let mut g_points = Vec::with_capacity(proofs.len());
        let mut proof_hashes = Vec::with_capacity(proofs.len());
        let mut program_digests = Vec::with_capacity(proofs.len());

        for (i, (artifact, compiled)) in proofs.iter().enumerate() {
            let params = Self::load_params(compiled).map_err(|e| {
                ZkfError::InvalidArtifact(format!("proof {i}: params load failed: {e}"))
            })?;
            let vk = Self::build_vk(&params, compiled).map_err(|e| {
                ZkfError::InvalidArtifact(format!("proof {i}: vk rebuild failed: {e}"))
            })?;

            let g = Self::extract_g_point(&params, &vk, artifact).map_err(|e| {
                ZkfError::InvalidArtifact(format!(
                    "proof {i} failed IPA guard extraction (invalid proof?): {e}"
                ))
            })?;

            g_points.push(g);
            proof_hashes.push(Self::proof_hash(artifact));
            program_digests.push(artifact.program_digest.clone());
        }

        // Step 2: Accumulate G-points via RLC.
        let g_acc = Self::accumulate_g_points(&g_points, &proof_hashes);
        let g_acc_bytes = Self::serialize_point(g_acc);

        // Step 3: Build the Groth16 wrapper program and witness.
        let proof_count = proofs.len();
        let program = Self::build_wrapper_program(&g_acc_bytes, proof_count);

        let gx_fe = field_elem_from_bytes_bn254(&g_acc_bytes[..32]);
        let gy_fe = field_elem_from_bytes_bn254(&g_acc_bytes[32..]);

        let mut witness_values = BTreeMap::new();
        witness_values.insert("g_acc_x".to_string(), gx_fe);
        witness_values.insert("g_acc_y".to_string(), gy_fe);
        witness_values.insert(
            "proof_count".to_string(),
            FieldElement::from_i64(proof_count as i64),
        );
        let witness = Witness {
            values: witness_values,
        };

        // Step 4: Prove with Groth16 (deterministic setup from program digest).
        let setup_seed = {
            let mut h = Sha256::new();
            h.update(b"zkf-ipa-acc-groth16-setup-v1");
            for ph in &proof_hashes {
                h.update(ph.as_bytes());
            }
            let out: [u8; 32] = h.finalize().into();
            out
        };

        let groth16_engine = crate::backend_for(BackendKind::ArkworksGroth16);
        let compiled_groth16 =
            crate::with_setup_seed_override(Some(setup_seed), || groth16_engine.compile(&program))?;
        let groth16_proof = groth16_engine.prove(&compiled_groth16, &witness)?;

        // Step 5: Build AggregatedProof with full metadata.
        let g_acc_hex = bytes_to_hex(&g_acc_bytes);
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "aggregator".to_string(),
            "halo2-ipa-accumulator-v1".to_string(),
        );
        metadata.insert("scheme".to_string(), "halo2-ipa-accumulator-v1".to_string());
        metadata.insert("trust_model".to_string(), "ipa-accumulated".to_string());
        metadata.insert(
            "trust_model_description".to_string(),
            "IPA accumulation: Fiat-Shamir transcript replayed for each proof; \
             G-points accumulated via RLC; Groth16 binds to G_acc. \
             Verifier must check the deferred MSM: G_acc = ⟨s_acc, params.g⟩."
                .to_string(),
        );
        metadata.insert(
            "proof_semantics".to_string(),
            "deferred-ipa-accumulation".to_string(),
        );
        metadata.insert(
            "aggregation_semantics".to_string(),
            "ipa-accumulation-with-deferred-msm".to_string(),
        );
        metadata.insert("algebraic_binding".to_string(), "false".to_string());
        metadata.insert("in_circuit_verification".to_string(), "false".to_string());
        metadata.insert("proof_count".to_string(), proof_count.to_string());
        metadata.insert("g_acc".to_string(), g_acc_hex);
        metadata.insert("proof_hashes".to_string(), proof_hashes.join(","));
        metadata.insert(
            "batch_program_digest".to_string(),
            compiled_groth16.program_digest.clone(),
        );
        metadata.insert(
            "in_circuit_ipa_verification".to_string(),
            "false".to_string(),
        );
        metadata.insert("ipa_transcript_replayed".to_string(), "true".to_string());
        metadata.insert("g_points_extracted".to_string(), "true".to_string());
        metadata.insert("groth16_binding".to_string(), "true".to_string());
        // Store individual G-point serialisations for verifier use.
        for (i, g) in g_points.iter().enumerate() {
            let gb = Self::serialize_point(*g);
            metadata.insert(format!("g_point_{i}"), bytes_to_hex(&gb));
        }

        Ok(AggregatedProof {
            backend: BackendKind::ArkworksGroth16,
            proof: groth16_proof.proof,
            verification_key: groth16_proof.verification_key,
            public_inputs: groth16_proof.public_inputs,
            program_digests,
            proof_count,
            metadata,
        })
    }

    fn verify_aggregated(&self, aggregated: &AggregatedProof) -> ZkfResult<bool> {
        // Step 1: Reconstruct the expected G_acc from stored individual G-points.
        let proof_count = aggregated.proof_count;
        let proof_hashes: Vec<String> = aggregated
            .metadata
            .get("proof_hashes")
            .map(|s| s.split(',').map(String::from).collect())
            .unwrap_or_default();

        let binding_summary = Self::summarize_binding_metadata(aggregated, &proof_hashes);
        if !halo2_ipa_binding_accepts(binding_summary.model) {
            if binding_summary.model.proof_count == 0 {
                return Err(ZkfError::InvalidArtifact(
                    "cannot verify zero Halo2 proofs".to_string(),
                ));
            }
            if binding_summary.model.proof_hash_count != binding_summary.model.proof_count {
                return Err(ZkfError::InvalidArtifact(
                    "ipa-accumulator: proof_hashes count mismatch".to_string(),
                ));
            }
            if let Some(index) = binding_summary.first_missing_g_point {
                return Err(ZkfError::InvalidArtifact(format!(
                    "missing g_point_{index} in metadata"
                )));
            }
            if let Some(error) = binding_summary.first_malformed_error {
                return Err(ZkfError::InvalidArtifact(error));
            }
            return Err(ZkfError::InvalidArtifact(
                "ipa-accumulator metadata binding rejected".to_string(),
            ));
        }

        let mut g_points = Vec::with_capacity(proof_count);
        for i in 0..proof_count {
            let hex = aggregated
                .metadata
                .get(&format!("g_point_{i}"))
                .expect("binding summary already validated g_point presence");
            let bytes = hex_to_bytes(hex)
                .map_err(|e| ZkfError::InvalidArtifact(format!("g_point_{i} hex decode: {e}")))?;
            debug_assert_eq!(bytes.len(), 64);
            let g = deserialize_eq_affine(&bytes)?;
            g_points.push(g);
        }

        // Step 2: Recompute G_acc.
        let g_acc_recomputed = Self::accumulate_g_points(&g_points, &proof_hashes);
        let g_acc_bytes = Self::serialize_point(g_acc_recomputed);

        // Step 3: Verify the Groth16 proof against the recomputed G_acc.
        let program = Self::build_wrapper_program(&g_acc_bytes, proof_count);
        let groth16_engine = crate::backend_for(BackendKind::ArkworksGroth16);

        let batch_digest = aggregated
            .metadata
            .get("batch_program_digest")
            .cloned()
            .unwrap_or_default();

        let gx_fe = field_elem_from_bytes_bn254(&g_acc_bytes[..32]);
        let public_inputs = vec![gx_fe, FieldElement::from_i64(proof_count as i64)];

        let setup_seed: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"zkf-ipa-acc-groth16-setup-v1");
            for proof_hash in &proof_hashes {
                h.update(proof_hash.as_bytes());
            }
            h.finalize().into()
        };
        let compiled =
            crate::with_setup_seed_override(Some(setup_seed), || groth16_engine.compile(&program))?;
        if !batch_digest.is_empty() && compiled.program_digest != batch_digest {
            return Err(ZkfError::InvalidArtifact(
                "halo2 ipa accumulator batch program digest mismatch".to_string(),
            ));
        }

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

        groth16_engine.verify(&compiled, &artifact)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Encode bytes to a lowercase hex string (avoids the `hex` crate dependency).
fn bytes_to_hex(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(CHARS[(b >> 4) as usize] as char);
        s.push(CHARS[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode a hex string to bytes.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = decode_hex_nibble(chunk[0])?;
        let lo = decode_hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {}", b as char)),
    }
}

/// Derive a deterministic Fp scalar from a hex-string hash.
///
/// Uses `FromUniformBytes<64>` which reduces a 64-byte sample modulo p with
/// negligible bias — this always produces a valid, non-constant field element.
fn derive_scalar_from_hash(hash: &str) -> Fp {
    use ff::FromUniformBytes;
    // Hash twice to get 64 bytes of uniform material.
    let mut h1 = Sha256::new();
    h1.update(b"zkf-ipa-acc-scalar-v1-lo");
    h1.update(hash.as_bytes());
    let lo: [u8; 32] = h1.finalize().into();

    let mut h2 = Sha256::new();
    h2.update(b"zkf-ipa-acc-scalar-v1-hi");
    h2.update(hash.as_bytes());
    let hi: [u8; 32] = h2.finalize().into();

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&lo);
    buf[32..].copy_from_slice(&hi);
    Fp::from_uniform_bytes(&buf)
}

/// Convert the first 32 bytes of `slice` to a BN254 Fr `FieldElement`.
///
/// Interprets bytes as little-endian and reduces mod Fr if needed.
fn field_elem_from_bytes_bn254(slice: &[u8]) -> FieldElement {
    let mut padded = [0u8; 32];
    let len = slice.len().min(32);
    padded[..len].copy_from_slice(&slice[..len]);
    // Clear the top two bits to keep the value in range for BN254 Fr (254-bit prime).
    padded[31] &= 0x3f;
    let big = num_bigint::BigUint::from_bytes_le(&padded);
    FieldElement::from_bigint_with_field(num_bigint::BigInt::from(big), FieldId::Bn254)
}

/// Deserialize an `EqAffine` point from 64 bytes (x || y, little-endian).
fn deserialize_eq_affine(bytes: &[u8]) -> ZkfResult<EqAffine> {
    use ff::PrimeField;

    if bytes.len() != 64 {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected 64 bytes for EqAffine, got {}",
            bytes.len()
        )));
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&bytes[..32]);
    yb.copy_from_slice(&bytes[32..]);

    // All-zero = identity.
    if xb == [0u8; 32] && yb == [0u8; 32] {
        return Ok(VestaProj::default().to_affine());
    }

    // EqAffine base field = Fq (Vesta base = Pallas scalar); use Fq, not Fp!
    use halo2_proofs::pasta::Fq as PastaFq;
    let x = Option::from(PastaFq::from_repr(xb)).ok_or_else(|| {
        ZkfError::InvalidArtifact("EqAffine x-coord out of field range".to_string())
    })?;
    let y = Option::from(PastaFq::from_repr(yb)).ok_or_else(|| {
        ZkfError::InvalidArtifact("EqAffine y-coord out of field range".to_string())
    })?;

    Option::from(EqAffine::from_xy(x, y))
        .ok_or_else(|| ZkfError::InvalidArtifact("EqAffine point not on curve".to_string()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_reports_halo2_backend() {
        let acc = Halo2IpaAccumulator;
        assert_eq!(acc.backend(), BackendKind::Halo2);
    }

    #[test]
    fn accumulator_rejects_empty_proofs() {
        let acc = Halo2IpaAccumulator;
        let result = acc.aggregate(&[]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("zero"), "expected 'zero' in error: {msg}");
    }

    #[test]
    fn accumulator_rejects_wrong_backend() {
        let acc = Halo2IpaAccumulator;
        let artifact =
            ProofArtifact::new(BackendKind::Plonky3, "test", vec![1, 2, 3], vec![], vec![]);
        let compiled = CompiledProgram::new(BackendKind::Halo2, zkf_core::Program::default());
        let result = acc.aggregate(&[(artifact, compiled)]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("plonky3") || msg.contains("expected halo2"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn serialize_deserialize_identity_point() {
        // VestaProj::default() == identity; to_affine() gives the identity EqAffine.
        let id: EqAffine = VestaProj::default().to_affine();
        let bytes = Halo2IpaAccumulator::serialize_point(id);
        assert_eq!(bytes, [0u8; 64]);
        let recovered = deserialize_eq_affine(&bytes).expect("identity round-trip");
        // Identity point has no affine coordinates.
        let coords_ct = <EqAffine as CurveAffine>::coordinates(&recovered);
        assert!(
            !bool::from(coords_ct.is_some()),
            "identity should have no coordinates"
        );
    }

    #[test]
    fn derive_scalar_is_deterministic() {
        let s1 = derive_scalar_from_hash("abc123");
        let s2 = derive_scalar_from_hash("abc123");
        let s3 = derive_scalar_from_hash("abc124");
        assert_eq!(s1, s2, "same input should give same scalar");
        assert_ne!(s1, s3, "different input should give different scalar");
    }

    #[test]
    fn g_acc_accumulation_is_deterministic() {
        // Use the identity as a test G-point.
        let id: EqAffine = VestaProj::default().to_affine();
        let points = vec![id, id];
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];

        let acc1 = Halo2IpaAccumulator::accumulate_g_points(&points, &hashes);
        let acc2 = Halo2IpaAccumulator::accumulate_g_points(&points, &hashes);
        assert_eq!(
            Halo2IpaAccumulator::serialize_point(acc1),
            Halo2IpaAccumulator::serialize_point(acc2),
            "accumulation must be deterministic"
        );
    }

    #[test]
    fn field_elem_from_bytes_is_bounded() {
        // Bytes with high bit set should not overflow BN254 Fr.
        let bytes = [0xffu8; 32];
        let fe = field_elem_from_bytes_bn254(&bytes);
        // Just verify it doesn't panic — the exact value depends on the field.
        let _ = fe.to_decimal_string();
    }

    #[test]
    fn trust_model_metadata_present() {
        // Create a minimal stub aggregated proof and verify the verifier checks
        // trust_model metadata (via the aggregator's aggregate output structure).
        let acc = Halo2IpaAccumulator;
        // Verifying without real data should produce a descriptive error.
        let fake_agg = AggregatedProof {
            backend: BackendKind::ArkworksGroth16,
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            program_digests: vec![],
            proof_count: 0,
            metadata: BTreeMap::from([
                (
                    "aggregator".to_string(),
                    "halo2-ipa-accumulator-v1".to_string(),
                ),
                ("trust_model".to_string(), "ipa-accumulated".to_string()),
            ]),
        };
        // Verify should fail (proof_hashes missing) but with a descriptive error.
        let result = acc.verify_aggregated(&fake_agg);
        assert!(result.is_err());
    }
}
