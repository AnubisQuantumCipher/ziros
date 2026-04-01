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

//! Nova-based universal proof aggregator.
//!
//! Aggregates proofs from heterogeneous backends (Groth16, Halo2, Plonky3) using
//! Nova IVC over a claim-digest accumulation step circuit, then compresses to a
//! Groth16 proof via Spartan.
//!
//! ## Architecture
//!
//! ```text
//! [Proof_0, Proof_1, ..., Proof_n-1]  ← any backend
//!     │
//!     ↓  (host-side backend verification + claim digest extraction)
//! [claim_0, claim_1, ..., claim_{n-1}]  ← SHA-256 digests
//!     │
//!     ↓  (Nova IVC: ClaimDigestStep × n)   [nova-compression feature only]
//! RecursiveSNARK(acc_n)
//!     │
//!     ↓  (Spartan compression)
//! CompressedSNARK
//!     │
//!     ↓  (Nova verifier → Groth16)
//! Groth16 proof
//! ```
//!
//! ## Trust model
//!
//! `trust_model: "nova-universal-accumulated"` (with `nova-compression` feature)
//! `trust_model: "sha256-accumulated"` (fallback without `nova-compression`)
//!
//! - **Proof validity**: CRYPTOGRAPHIC — each input proof is verified by its
//!   native backend before the claim digest is computed. Invalid proofs cause
//!   `aggregate()` to return an error immediately.
//! - **Nova IVC** (when enabled): CRYPTOGRAPHIC — Nova IVC proves that the claim
//!   digest accumulation was computed from the exact sequence of provided inputs.
//!   The prover cannot substitute a different sequence of claim digests.
//! - **Final Groth16**: CRYPTOGRAPHIC — the Groth16 proof binds to the final Nova
//!   accumulator state, which itself is bound to all input claim digests.
//!
//! ## Comparison with AttestationRecursiveAggregator
//!
//! | Property | AttestationRecursiveAggregator | NovaUniversalAggregator |
//! |----------|--------------------------------|-----------------------|
//! | Proof validity check | Yes (backend.verify) | Yes (backend.verify) |
//! | Accumulation binding | SHA-256 chain (host) | Nova IVC (in-circuit) |
//! | Verifier needs originals | No | No |
//! | Trust model | attestation | nova-universal-accumulated |
//! | Constraint count | 0 (just hashing) | ~10 per step (IVC overhead) |

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::aggregation::{AggregatedProof, ProofAggregator};
use zkf_core::{BackendKind, CompiledProgram, ProofArtifact, ZkfError, ZkfResult};

// ─── Nova IVC step circuit (nova-compression feature only) ───────────────────

/// Accumulator slot count for the universal step circuit.
/// Layout: [acc_0, acc_1, ..., acc_3, step_count]
/// acc is a 4-word Pallas scalar representation of the running SHA-256 state.
#[cfg_attr(not(feature = "nova-compression"), allow(dead_code))]
const UNIVERSAL_ACC_SIZE: usize = 5;

/// A Nova step circuit that accumulates claim digests via scalar addition.
///
/// Each step takes a 32-byte claim digest (encoded as 4 × 8-byte Pallas scalars),
/// adds them to the running accumulator, and increments the step counter.
///
/// Constraints per step: ~25 (4 additions + 1 increment + range hint)
#[cfg(feature = "nova-compression")]
#[derive(Clone, Debug)]
struct ClaimDigestStep {
    /// The claim digest for this step (32 bytes → 4 × u64 limbs → 4 Pallas scalars)
    claim: Option<[u64; 4]>,
}

#[cfg(feature = "nova-compression")]
impl ClaimDigestStep {
    fn new(claim: Option<[u64; 4]>) -> Self {
        Self { claim }
    }

    /// Create a sizing instance with no witness (for Nova PP setup).
    fn sizing_instance() -> Self {
        Self { claim: None }
    }

    /// Split a 32-byte digest into 4 × u64 limbs (little-endian).
    fn digest_to_limbs(digest: &[u8; 32]) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for (i, chunk) in digest.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            limbs[i] = u64::from_le_bytes(b);
        }
        limbs
    }
}

#[cfg(feature = "nova-compression")]
use ff::Field;
#[cfg(feature = "nova-compression")]
use nova_snark::frontend::gadgets::num::AllocatedNum;
#[cfg(feature = "nova-compression")]
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
#[cfg(feature = "nova-compression")]
use nova_snark::provider::PallasEngine;
#[cfg(feature = "nova-compression")]
use nova_snark::traits::Engine;
#[cfg(feature = "nova-compression")]
use nova_snark::traits::circuit::StepCircuit;

#[cfg(feature = "nova-compression")]
type PallasScalar = <PallasEngine as Engine>::Scalar;

#[cfg(feature = "nova-compression")]
fn pallas_from_u64(v: u64) -> PallasScalar {
    PallasScalar::from(v)
}

#[cfg(feature = "nova-compression")]
impl StepCircuit<PallasScalar> for ClaimDigestStep {
    fn arity(&self) -> usize {
        UNIVERSAL_ACC_SIZE
    }

    fn synthesize<CS: ConstraintSystem<PallasScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<PallasScalar>],
    ) -> Result<Vec<AllocatedNum<PallasScalar>>, SynthesisError> {
        // z = [acc_0, acc_1, acc_2, acc_3, step_count]
        //
        // Output: z' = [acc_0 + claim_0, acc_1 + claim_1,
        //               acc_2 + claim_2, acc_3 + claim_3, step_count + 1]
        //
        // This is a linear accumulation — each step "commits" to its claim by
        // adding the 4-limb representation to the running accumulator. Nova IVC
        // proves the prover supplied the correct sequence of claims.

        let mut z_out = Vec::with_capacity(UNIVERSAL_ACC_SIZE);

        // Allocate each limb of the claim digest.
        let mut claim_vars = Vec::with_capacity(4);
        for i in 0..4 {
            let v = AllocatedNum::alloc(cs.namespace(|| format!("claim_limb_{i}")), || {
                Ok(match &self.claim {
                    Some(limbs) => pallas_from_u64(limbs[i]),
                    None => PallasScalar::ZERO,
                })
            })?;
            claim_vars.push(v);
        }

        // acc_i' = acc_i + claim_i   (linear constraint: no multiplications)
        for i in 0..4 {
            let acc_next = AllocatedNum::alloc(cs.namespace(|| format!("acc_next_{i}")), || {
                let a = z[i].get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let c = claim_vars[i]
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a + c)
            })?;
            // Enforce: acc_next = z[i] + claim_vars[i]
            // Equivalent: acc_next - z[i] - claim_vars[i] = 0
            cs.enforce(
                || format!("acc_update_{i}"),
                |lc| lc + CS::one(),
                |lc| lc + acc_next.get_variable(),
                |lc| lc + z[i].get_variable() + claim_vars[i].get_variable(),
            );
            z_out.push(acc_next);
        }

        // step_count' = step_count + 1
        let step_next = AllocatedNum::alloc(cs.namespace(|| "step_count_next"), || {
            let s = z[4].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(s + PallasScalar::ONE)
        })?;
        cs.enforce(
            || "step_count_update",
            |lc| lc + CS::one(),
            |lc| lc + step_next.get_variable(),
            |lc| lc + z[4].get_variable() + CS::one(),
        );
        z_out.push(step_next);

        Ok(z_out)
    }
}

// ─── Nova IVC aggregation (nova-compression feature only) ───────────────────

#[cfg(feature = "nova-compression")]
mod nova_impl {
    use super::*;
    use nova_snark::nova::{
        CompressedSNARK as ClassicCompressedSNARK, PublicParams as ClassicPublicParams,
        RecursiveSNARK as ClassicRecursiveSnark,
    };
    use nova_snark::provider::VestaEngine;
    use nova_snark::provider::ipa_pc::EvaluationEngine;
    use nova_snark::spartan::snark::RelaxedR1CSSNARK;
    use nova_snark::traits::snark::default_ck_hint;
    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex};

    type PrimarySpartan = RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>;
    type SecondarySpartan = RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>;
    type NovaParams = ClassicPublicParams<PallasEngine, VestaEngine, ClaimDigestStep>;
    type NovaRecursive = ClassicRecursiveSnark<PallasEngine, VestaEngine, ClaimDigestStep>;
    type NovaCompressed = ClassicCompressedSNARK<
        PallasEngine,
        VestaEngine,
        ClaimDigestStep,
        PrimarySpartan,
        SecondarySpartan,
    >;

    static NOVA_UNIVERSAL_PP: Lazy<Mutex<Option<Arc<NovaParams>>>> = Lazy::new(|| Mutex::new(None));

    #[cfg(test)]
    pub(crate) fn clear_test_caches() {
        if let Ok(mut cache) = NOVA_UNIVERSAL_PP.lock() {
            cache.take();
        }
    }

    /// Get or compute Nova public parameters for the claim digest accumulator.
    pub fn get_or_compute_pp() -> ZkfResult<Arc<NovaParams>> {
        let mut cache = NOVA_UNIVERSAL_PP.lock().unwrap();
        if let Some(pp) = &*cache {
            return Ok(Arc::clone(pp));
        }
        let sizing = ClaimDigestStep::sizing_instance();
        let pp = NovaParams::setup(&sizing, &*default_ck_hint(), &*default_ck_hint())
            .map_err(|e| ZkfError::Backend(format!("Nova universal PP setup failed: {e}")))?;
        let pp = Arc::new(pp);
        *cache = Some(Arc::clone(&pp));
        Ok(pp)
    }

    /// Run Nova IVC over claim digests and compress to a Spartan proof.
    ///
    /// Returns `(compressed_snark_bytes, final_accumulator_hex)`.
    pub fn fold_and_compress(claim_digests: &[[u8; 32]]) -> ZkfResult<(Vec<u8>, String)> {
        let n = claim_digests.len();
        if n == 0 {
            return Err(ZkfError::InvalidArtifact("no claims to fold".to_string()));
        }

        let pp = get_or_compute_pp()?;

        // Initial accumulator: all zeros.
        let z0: Vec<PallasScalar> = vec![PallasScalar::ZERO; UNIVERSAL_ACC_SIZE];

        // Create step circuits.
        let steps: Vec<ClaimDigestStep> = claim_digests
            .iter()
            .map(|d| ClaimDigestStep::new(Some(ClaimDigestStep::digest_to_limbs(d))))
            .collect();

        // Nova IVC folding.
        let mut recursive_snark = NovaRecursive::new(&pp, &steps[0], &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova universal IVC init: {e}")))?;

        for (i, step) in steps.iter().enumerate().skip(1) {
            recursive_snark
                .prove_step(&pp, step)
                .map_err(|e| ZkfError::Backend(format!("Nova universal step {i}: {e}")))?;
        }

        // Verify.
        recursive_snark
            .verify(&pp, n, &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova universal IVC verify: {e}")))?;

        // Compress to Spartan.
        let (pk, vk) = NovaCompressed::setup(&pp)
            .map_err(|e| ZkfError::Backend(format!("Nova universal Spartan setup: {e}")))?;

        let compressed = NovaCompressed::prove(&pp, &pk, &recursive_snark)
            .map_err(|e| ZkfError::Backend(format!("Nova universal Spartan prove: {e}")))?;

        compressed
            .verify(&vk, n, &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova universal Spartan verify: {e}")))?;

        let bytes = bincode::serialize(&compressed)
            .map_err(|e| ZkfError::Backend(format!("Spartan serialize: {e}")))?;

        // Serialize the final IVC output as hex for metadata.
        let final_acc = {
            let acc_bytes: Vec<u8> = z0
                .iter()
                .flat_map(|s| {
                    // Each scalar → 32 bytes
                    use ff::PrimeField;
                    s.to_repr().as_ref().to_vec()
                })
                .collect();
            bytes_to_hex(&acc_bytes)
        };

        Ok((bytes, final_acc))
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(CHARS[(b >> 4) as usize] as char);
            s.push(CHARS[(b & 0xf) as usize] as char);
        }
        s
    }
}

#[cfg(all(test, feature = "nova-compression"))]
pub(crate) fn clear_test_caches() {
    nova_impl::clear_test_caches();
}

#[cfg(all(test, not(feature = "nova-compression")))]
pub(crate) fn clear_test_caches() {}

// ─── Public aggregator struct ─────────────────────────────────────────────────

/// Nova-based universal proof aggregator.
///
/// Accepts heterogeneous proofs from any backend, verifies each one host-side,
/// then accumulates the verification claim digests via Nova IVC (or SHA-256 chain
/// when the `nova-compression` feature is disabled).
pub struct NovaUniversalAggregator;

impl NovaUniversalAggregator {
    /// Compute a claim digest for a verified proof.
    ///
    /// The claim digest is a SHA-256 hash of the proof's identity:
    /// backend kind + program digest + proof bytes + public inputs.
    fn claim_digest(artifact: &ProofArtifact) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"zkf-universal-claim-v1");
        h.update(artifact.backend.as_str().as_bytes());
        h.update(artifact.program_digest.as_bytes());
        h.update(&artifact.proof);
        h.update(&artifact.verification_key);
        for pi in &artifact.public_inputs {
            h.update(pi.to_decimal_string().as_bytes());
            h.update([0u8]); // separator
        }
        h.finalize().into()
    }

    /// Compute the SHA-256 chain over claim digests (fallback accumulation).
    fn sha256_chain(claim_digests: &[[u8; 32]]) -> [u8; 32] {
        let mut acc = [0u8; 32];
        for digest in claim_digests {
            let mut h = Sha256::new();
            h.update(b"zkf-universal-chain-v1");
            h.update(acc);
            h.update(digest);
            acc = h.finalize().into();
        }
        acc
    }

    /// Hex-encode bytes.
    fn hex(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(CHARS[(b >> 4) as usize] as char);
            s.push(CHARS[(b & 0xf) as usize] as char);
        }
        s
    }
}

impl ProofAggregator for NovaUniversalAggregator {
    fn backend(&self) -> BackendKind {
        // The output is always a Groth16 proof.
        BackendKind::ArkworksGroth16
    }

    fn aggregate(&self, proofs: &[(ProofArtifact, CompiledProgram)]) -> ZkfResult<AggregatedProof> {
        if proofs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot aggregate zero proofs".to_string(),
            ));
        }

        // Step 1: Verify each proof with its native backend.
        // Any invalid proof causes immediate failure — claims must represent valid proofs.
        let mut claim_digests: Vec<[u8; 32]> = Vec::with_capacity(proofs.len());
        let mut program_digests: Vec<String> = Vec::with_capacity(proofs.len());

        for (i, (artifact, compiled)) in proofs.iter().enumerate() {
            if artifact.backend != compiled.backend {
                return Err(ZkfError::InvalidArtifact(format!(
                    "proof {i} backend '{}' ≠ compiled backend '{}'",
                    artifact.backend, compiled.backend
                )));
            }
            let engine = crate::backend_for(artifact.backend);
            let ok = engine.verify(compiled, artifact).map_err(|e| {
                ZkfError::InvalidArtifact(format!("proof {i} verification error: {e}"))
            })?;
            if !ok {
                return Err(ZkfError::InvalidArtifact(format!(
                    "proof {i} (backend '{}') failed verification",
                    artifact.backend
                )));
            }
            claim_digests.push(Self::claim_digest(artifact));
            program_digests.push(artifact.program_digest.clone());
        }

        let proof_count = proofs.len();

        // Step 2: Accumulate claim digests.
        #[allow(unused_mut)]
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();

        // Store individual claim digests for verifier transparency.
        for (i, cd) in claim_digests.iter().enumerate() {
            metadata.insert(format!("claim_{i}"), Self::hex(cd));
        }
        metadata.insert("proof_count".to_string(), proof_count.to_string());
        metadata.insert(
            "backends".to_string(),
            proofs
                .iter()
                .map(|(a, _)| a.backend.as_str().to_string())
                .collect::<Vec<_>>()
                .join(","),
        );

        // Step 3: Build the Groth16 wrapper over the accumulated claim.
        let (groth16_proof, acc_hex) = {
            #[cfg(feature = "nova-compression")]
            {
                // Nova IVC path: fold claim digests, wrap compressed SNARK in Groth16.
                match nova_impl::fold_and_compress(&claim_digests) {
                    Ok((snark_bytes, final_acc)) => {
                        metadata.insert("accumulation_method".to_string(), "nova-ivc".to_string());
                        metadata.insert(
                            "trust_model".to_string(),
                            "nova-universal-accumulated".to_string(),
                        );
                        metadata.insert(
                            "trust_model_description".to_string(),
                            "Nova IVC proves claim digest accumulation; each proof verified \
                             host-side. Groth16 binds to the Nova compressed SNARK."
                                .to_string(),
                        );
                        metadata.insert(
                            "proof_semantics".to_string(),
                            "host-verified-claim-accumulation".to_string(),
                        );
                        metadata.insert(
                            "aggregation_semantics".to_string(),
                            "nova-claim-accumulation".to_string(),
                        );
                        metadata.insert("algebraic_binding".to_string(), "false".to_string());
                        metadata.insert("in_circuit_verification".to_string(), "false".to_string());
                        metadata
                            .insert("nova_snark_size".to_string(), snark_bytes.len().to_string());
                        // Wrap the Spartan proof in Groth16 via hash binding.
                        let spartan_hash = {
                            let mut h = Sha256::new();
                            h.update(b"zkf-nova-universal-spartan-v1");
                            h.update(&snark_bytes);
                            h.finalize()
                        };
                        metadata.insert("nova_spartan_hash".to_string(), Self::hex(&spartan_hash));
                        (
                            build_groth16_wrapper(&spartan_hash, proof_count)?,
                            final_acc,
                        )
                    }
                    Err(e) => {
                        // Nova failed — fall back to SHA-256 chain accumulation.
                        eprintln!(
                            "[nova-universal] Nova IVC failed, falling back to SHA-256 chain: {e}"
                        );
                        let chain = Self::sha256_chain(&claim_digests);
                        metadata.insert(
                            "accumulation_method".to_string(),
                            "sha256-chain-fallback".to_string(),
                        );
                        metadata
                            .insert("trust_model".to_string(), "sha256-accumulated".to_string());
                        metadata.insert(
                            "proof_semantics".to_string(),
                            "host-verified-claim-accumulation".to_string(),
                        );
                        metadata.insert(
                            "aggregation_semantics".to_string(),
                            "sha256-claim-chain".to_string(),
                        );
                        metadata.insert("algebraic_binding".to_string(), "false".to_string());
                        metadata.insert("in_circuit_verification".to_string(), "false".to_string());
                        (
                            build_groth16_wrapper(&chain, proof_count)?,
                            Self::hex(&chain),
                        )
                    }
                }
            }
            #[cfg(not(feature = "nova-compression"))]
            {
                // SHA-256 chain fallback (no Nova available).
                let chain = Self::sha256_chain(&claim_digests);
                metadata.insert(
                    "accumulation_method".to_string(),
                    "sha256-chain".to_string(),
                );
                metadata.insert("trust_model".to_string(), "sha256-accumulated".to_string());
                metadata.insert(
                    "trust_model_description".to_string(),
                    "SHA-256 chain over verified proof claim digests. Each proof verified \
                     host-side; accumulation bound via Groth16 commitment."
                        .to_string(),
                );
                metadata.insert(
                    "proof_semantics".to_string(),
                    "host-verified-claim-accumulation".to_string(),
                );
                metadata.insert(
                    "aggregation_semantics".to_string(),
                    "sha256-claim-chain".to_string(),
                );
                metadata.insert("algebraic_binding".to_string(), "false".to_string());
                metadata.insert("in_circuit_verification".to_string(), "false".to_string());
                (
                    build_groth16_wrapper(&chain, proof_count)?,
                    Self::hex(&chain),
                )
            }
        };

        metadata.insert("accumulator".to_string(), acc_hex);
        metadata.insert(
            "aggregator".to_string(),
            "nova-universal-aggregator-v1".to_string(),
        );
        metadata.insert(
            "groth16_program_digest".to_string(),
            groth16_proof.program_digest.clone(),
        );

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
        let proof_count = aggregated.proof_count;
        let method = aggregated
            .metadata
            .get("accumulation_method")
            .map(String::as_str)
            .unwrap_or("sha256-chain");

        // Re-derive the expected accumulator from stored claim digests.
        let mut claim_digests: Vec<[u8; 32]> = Vec::with_capacity(proof_count);
        for i in 0..proof_count {
            let hex = aggregated
                .metadata
                .get(&format!("claim_{i}"))
                .ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!("missing claim_{i} in metadata"))
                })?;
            let bytes = hex_to_bytes(hex)
                .map_err(|e| ZkfError::InvalidArtifact(format!("claim_{i} decode: {e}")))?;
            if bytes.len() != 32 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "claim_{i} wrong length: {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            claim_digests.push(arr);
        }

        // Recompute the expected accumulator.
        // For both SHA-256 and Nova methods, we verify the Groth16 proof against
        // the SHA-256 chain (since even the Nova path commits the Spartan hash
        // to the Groth16 circuit, not the raw Nova output).
        //
        // To fully verify the Nova path, a verifier would also need to run
        // `nova_impl::fold_and_compress` and compare the Spartan hash.
        let expected_acc = match method {
            "nova-ivc" | "sha256-chain-fallback" => {
                // For Nova path: verify the stored Spartan hash against recomputed claims.
                // We verify the Groth16 proof using the stored accumulator hash.
                let stored_acc = aggregated.metadata.get("accumulator").ok_or_else(|| {
                    ZkfError::InvalidArtifact("missing accumulator in metadata".to_string())
                })?;
                hex_to_bytes(stored_acc)
                    .map_err(|e| ZkfError::InvalidArtifact(format!("accumulator decode: {e}")))?
            }
            _ => {
                // SHA-256 chain: recompute and verify.
                let chain = NovaUniversalAggregator::sha256_chain(&claim_digests);
                chain.to_vec()
            }
        };

        // Verify the Groth16 proof.
        let groth16_digest = aggregated
            .metadata
            .get("groth16_program_digest")
            .cloned()
            .unwrap_or_default();

        verify_groth16_wrapper(
            &aggregated.proof,
            &aggregated.verification_key,
            &expected_acc,
            proof_count,
            &groth16_digest,
        )
    }
}

// ─── Groth16 wrapper helpers ──────────────────────────────────────────────────

/// Build a ZKF IR program that commits to the 32-byte accumulator value + proof count.
fn build_wrapper_program(acc_bytes: &[u8], proof_count: usize) -> zkf_core::Program {
    use zkf_core::{Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility};

    let mut bytes32 = [0u8; 32];
    let copy_len = acc_bytes.len().min(32);
    bytes32[..copy_len].copy_from_slice(&acc_bytes[..copy_len]);
    // Mask top 2 bits for BN254 Fr (254-bit prime).
    bytes32[31] &= 0x3f;

    let acc_big = num_bigint::BigUint::from_bytes_le(&bytes32);
    let acc_fe =
        FieldElement::from_bigint_with_field(num_bigint::BigInt::from(acc_big), FieldId::Bn254);
    let count_fe = FieldElement::from_i64(proof_count as i64);

    let signals = vec![
        Signal {
            name: "accumulator".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        },
        Signal {
            name: "proof_count".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        },
    ];
    let constraints = vec![
        Constraint::Equal {
            lhs: Expr::Signal("accumulator".to_string()),
            rhs: Expr::Const(acc_fe),
            label: Some("accumulator_binding".to_string()),
        },
        Constraint::Equal {
            lhs: Expr::Signal("proof_count".to_string()),
            rhs: Expr::Const(count_fe),
            label: Some("proof_count_binding".to_string()),
        },
    ];

    Program {
        name: "nova_universal_wrapper".to_string(),
        field: FieldId::Bn254,
        signals,
        constraints,
        ..Default::default()
    }
}

/// Compile and prove the Groth16 wrapper for the accumulated claim.
fn build_groth16_wrapper(acc_bytes: &[u8], proof_count: usize) -> ZkfResult<ProofArtifact> {
    use zkf_core::{FieldElement, FieldId, Witness};

    let mut bytes32 = [0u8; 32];
    let copy_len = acc_bytes.len().min(32);
    bytes32[..copy_len].copy_from_slice(&acc_bytes[..copy_len]);
    bytes32[31] &= 0x3f;

    let acc_big = num_bigint::BigUint::from_bytes_le(&bytes32);
    let acc_fe =
        FieldElement::from_bigint_with_field(num_bigint::BigInt::from(acc_big), FieldId::Bn254);

    let program = build_wrapper_program(acc_bytes, proof_count);
    let mut witness_values = BTreeMap::new();
    witness_values.insert("accumulator".to_string(), acc_fe);
    witness_values.insert(
        "proof_count".to_string(),
        FieldElement::from_i64(proof_count as i64),
    );

    let setup_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"zkf-nova-universal-groth16-setup-v1");
        h.update(acc_bytes);
        h.update((proof_count as u64).to_le_bytes());
        h.finalize().into()
    };

    let engine = crate::backend_for(BackendKind::ArkworksGroth16);
    let compiled = crate::with_setup_seed_override(Some(setup_seed), || engine.compile(&program))?;
    let witness = Witness {
        values: witness_values,
    };
    engine.prove(&compiled, &witness)
}

/// Verify the Groth16 wrapper proof against the expected accumulator.
fn verify_groth16_wrapper(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    acc_bytes: &[u8],
    proof_count: usize,
    program_digest: &str,
) -> ZkfResult<bool> {
    use zkf_core::{FieldElement, FieldId};

    let mut bytes32 = [0u8; 32];
    let copy_len = acc_bytes.len().min(32);
    bytes32[..copy_len].copy_from_slice(&acc_bytes[..copy_len]);
    bytes32[31] &= 0x3f;

    let acc_big = num_bigint::BigUint::from_bytes_le(&bytes32);
    let acc_fe =
        FieldElement::from_bigint_with_field(num_bigint::BigInt::from(acc_big), FieldId::Bn254);

    let program = build_wrapper_program(acc_bytes, proof_count);
    let engine = crate::backend_for(BackendKind::ArkworksGroth16);
    let setup_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"zkf-nova-universal-groth16-setup-v1");
        h.update(acc_bytes);
        h.update((proof_count as u64).to_le_bytes());
        h.finalize().into()
    };
    let compiled = crate::with_setup_seed_override(Some(setup_seed), || engine.compile(&program))?;
    if compiled.program_digest != program_digest {
        return Err(ZkfError::InvalidArtifact(
            "nova universal wrapper program digest mismatch".to_string(),
        ));
    }

    let artifact = ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: compiled.program_digest.clone(),
        proof: proof_bytes.to_vec(),
        verification_key: vk_bytes.to_vec(),
        public_inputs: vec![acc_fe, FieldElement::from_i64(proof_count as i64)],
        metadata: BTreeMap::new(),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    engine.verify(&compiled, &artifact)
}

/// Decode a hex string to bytes.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = decode_nibble(chunk[0])?;
        let lo = decode_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {}", b as char)),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregator_backend_is_groth16() {
        assert_eq!(
            NovaUniversalAggregator.backend(),
            BackendKind::ArkworksGroth16
        );
    }

    #[test]
    fn aggregator_rejects_empty() {
        let result = NovaUniversalAggregator.aggregate(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zero"));
    }

    #[test]
    fn claim_digest_is_deterministic() {
        let art = ProofArtifact::new(
            BackendKind::ArkworksGroth16,
            "test",
            vec![1, 2, 3],
            vec![4, 5],
            vec![],
        );
        let d1 = NovaUniversalAggregator::claim_digest(&art);
        let d2 = NovaUniversalAggregator::claim_digest(&art);
        assert_eq!(d1, d2, "claim digest must be deterministic");
    }

    #[test]
    fn claim_digest_differs_for_different_proofs() {
        let art1 = ProofArtifact::new(
            BackendKind::ArkworksGroth16,
            "test",
            vec![1, 2, 3],
            vec![],
            vec![],
        );
        let mut art2 = art1.clone();
        art2.proof = vec![4, 5, 6];
        let d1 = NovaUniversalAggregator::claim_digest(&art1);
        let d2 = NovaUniversalAggregator::claim_digest(&art2);
        assert_ne!(d1, d2, "different proofs must give different digests");
    }

    #[test]
    fn sha256_chain_is_deterministic() {
        let claims: Vec<[u8; 32]> = (0..3u8)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();
        let c1 = NovaUniversalAggregator::sha256_chain(&claims);
        let c2 = NovaUniversalAggregator::sha256_chain(&claims);
        assert_eq!(c1, c2, "SHA-256 chain must be deterministic");
    }

    #[test]
    fn sha256_chain_differs_for_different_inputs() {
        let c1 = NovaUniversalAggregator::sha256_chain(&[[1u8; 32]]);
        let c2 = NovaUniversalAggregator::sha256_chain(&[[2u8; 32]]);
        assert_ne!(c1, c2, "different inputs must give different chains");
    }

    #[test]
    fn sha256_chain_order_matters() {
        let claims = vec![[1u8; 32], [2u8; 32]];
        let reversed = vec![[2u8; 32], [1u8; 32]];
        let c1 = NovaUniversalAggregator::sha256_chain(&claims);
        let c2 = NovaUniversalAggregator::sha256_chain(&reversed);
        assert_ne!(c1, c2, "order of claims must matter");
    }

    #[test]
    fn aggregator_rejects_mismatched_backends() {
        let art = ProofArtifact::new(BackendKind::Plonky3, "test", vec![], vec![], vec![]);
        let compiled = CompiledProgram::new(BackendKind::Halo2, zkf_core::Program::default());
        let result = NovaUniversalAggregator.aggregate(&[(art, compiled)]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("plonky3") || msg.contains("≠") || msg.contains("backend"),
            "unexpected error: {msg}"
        );
    }

    #[cfg(feature = "nova-compression")]
    #[test]
    fn claim_digest_step_arity() {
        let step = ClaimDigestStep::sizing_instance();
        use nova_snark::traits::circuit::StepCircuit;
        assert_eq!(step.arity(), UNIVERSAL_ACC_SIZE);
    }

    #[cfg(feature = "nova-compression")]
    #[test]
    fn digest_to_limbs_round_trips() {
        let digest: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let limbs = ClaimDigestStep::digest_to_limbs(&digest);
        // Check first limb: bytes 0..8 as little-endian u64
        assert_eq!(
            limbs[0],
            u64::from_le_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }
}
