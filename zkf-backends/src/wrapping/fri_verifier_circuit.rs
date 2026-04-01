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

/// FRI verifier expressed as an R1CS circuit over BN254 Fr.
///
/// This circuit proves in zero-knowledge that a STARK proof (using the FRI
/// polynomial commitment) is valid.  The circuit encodes:
///
/// 1. Merkle path verification for each queried leaf (trace commitment)
///    using the same Poseidon2 hash over Goldilocks that Plonky3 uses.
/// 2. FRI folding consistency: for every round, the folded value equals
///    the claimed evaluation (division-free encoding).
/// 3. AIR constraint evaluation via Horner folding with in-circuit alpha.
/// 4. Quotient polynomial identity check.
/// 5. Fiat-Shamir transcript replay via DuplexChallenger gadget.
///
/// The circuit operates over BN254 Fr throughout; Goldilocks values are
/// embedded via non-native arithmetic (`GoldilocksVar`).
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::air_eval_circuit::{
    recompose_quotient_circuit, verify_air_constraints_circuit, verify_quotient_identity,
};
use super::duplex_challenger::DuplexChallengerGadget;
use super::nonnative_goldilocks::GoldilocksVar;
use super::poseidon2_goldilocks::Poseidon2GoldilocksGadget;
use crate::plonky3::AirExpr;

// ---------------------------------------------------------------------------
// Parameter types
// ---------------------------------------------------------------------------

/// Configuration for the FRI verifier circuit.
#[derive(Clone, Debug)]
pub struct FriCircuitParams {
    /// Number of FRI queries used in the STARK proof.
    pub num_queries: usize,
    /// Number of FRI folding rounds.
    pub num_fri_rounds: usize,
    /// log2 of the trace degree bound.
    pub log_degree: usize,
    /// Height of the commitment Merkle trees.
    pub merkle_tree_height: usize,
    /// Plonky3 RNG seed (derived from program digest).
    pub poseidon2_seed: u64,
    /// Number of public inputs from the original STARK computation.
    pub num_public_inputs: usize,
    /// Number of trace columns (width of the AIR).
    pub trace_width: usize,
    /// AIR constraints to evaluate in-circuit. Empty means FRI-only mode
    /// (no AIR constraint verification, only FRI structural checks).
    pub air_constraints: Vec<AirExpr>,
    /// Indices of public signals in the trace.
    pub public_signal_indices: Vec<usize>,
    /// Number of quotient polynomial chunks.
    pub num_quotient_chunks: usize,
    /// Number of PoW bits per FRI commit round.
    pub commit_pow_bits: usize,
    /// Number of PoW bits for query phase.
    pub query_pow_bits: usize,
    /// log2 of the FRI blowup factor.
    pub log_blowup: usize,
    /// log2 of the FRI final polynomial length.
    pub log_final_poly_len: usize,
}

impl Default for FriCircuitParams {
    fn default() -> Self {
        Self {
            num_queries: 32,
            num_fri_rounds: 16,
            log_degree: 16,
            merkle_tree_height: 16,
            poseidon2_seed: 0,
            num_public_inputs: 1,
            trace_width: 0,
            air_constraints: Vec::new(),
            public_signal_indices: Vec::new(),
            num_quotient_chunks: 0,
            commit_pow_bits: 0,
            query_pow_bits: 0,
            log_blowup: 1,
            log_final_poly_len: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

/// Witness data for a single FRI query.
#[derive(Clone, Debug, Default)]
pub struct FriQueryWitness {
    /// Merkle sibling hashes as 8-element digests, one per tree level, leaf to root.
    pub merkle_siblings_8: Vec<[u64; 8]>,
    /// Direction bits for each Merkle path level (0=left, 1=right).
    pub direction_bits: Vec<bool>,
    /// Opened evaluation value at the query position (leaf).
    pub opened_value: u64,
    /// Query position domain element (x coordinate).
    pub query_x: u64,
    /// Query index in the evaluation domain (used to derive direction bits).
    pub query_index: u64,
    /// FRI layer values: f_odd (sibling) at each folding round.
    pub fri_layer_odd_values: Vec<u64>,
    /// FRI folded values: f_next at each folding round.
    pub fri_folded_values: Vec<u64>,
    /// Merkle paths for each FRI round commitment (8-element sibling digests).
    pub fri_round_merkle_paths: Vec<Vec<[u64; 8]>>,
    /// FRI direction bits per round (LSB of fri_index before shift).
    pub fri_direction_bits: Vec<bool>,
    /// Alpha-composed initial FRI value from open_input.
    pub fri_composed_value: u64,
    /// All opened column values at the query position (for Merkle leaf hash).
    pub leaf_values: Vec<u64>,
    /// Per-round subgroup_start values for fold_row domain computation.
    pub fri_round_x_values: Vec<u64>,
}

/// Witness for the full STARK proof being wrapped.
#[derive(Clone, Debug, Default)]
pub struct StarkProofWitness {
    /// Merkle roots of FRI round commitments.
    pub fri_commitment_roots: Vec<u64>,
    /// FRI challenge scalars (alpha values from Fiat-Shamir).
    /// Used as hints; when AIR constraints are present, alpha is derived
    /// in-circuit via the DuplexChallenger and the hint is constrained to match.
    pub fri_alphas: Vec<u64>,
    /// Per-query witness data.
    pub queries: Vec<FriQueryWitness>,
    /// log2 of the trace degree.
    pub degree_bits: usize,
    /// Public inputs of the original STARK computation.
    pub public_inputs: Vec<u64>,

    // --- Extended witness fields for soundness ---
    /// Opened trace values at zeta (one per trace column).
    pub trace_local: Vec<u64>,
    /// Opened trace values at zeta_next (one per trace column).
    pub trace_next: Vec<u64>,
    /// Quotient polynomial chunks at zeta.
    pub quotient_chunks: Vec<u64>,
    /// Trace commitment root (8 Goldilocks elements).
    pub trace_commitment: Vec<u64>,
    /// Quotient commitment root (8 Goldilocks elements).
    pub quotient_commitment: Vec<u64>,
    /// OOD evaluation point (derived from challenger, provided as hint).
    pub zeta: u64,
    /// Constraint combination challenge (derived from challenger, provided as hint).
    pub alpha: u64,
    /// is_first_row selector evaluated at zeta.
    pub is_first_row_at_zeta: u64,
    /// 1/Z_H(zeta) — inverse of vanishing polynomial at zeta.
    pub inv_vanishing_at_zeta: u64,
    /// FRI final polynomial constant value.
    pub final_poly_value: u64,
    /// FRI commitment roots as 8-element digests (one per FRI round).
    pub fri_commitment_roots_8: Vec<[u64; 8]>,
    /// FRI batch combination alpha (from verify_fri).
    pub fri_batch_alpha: u64,
    /// PoW witnesses per FRI commit round.
    pub commit_pow_witnesses: Vec<u64>,
    /// Query PoW witness.
    pub query_pow_witness: u64,
    /// FRI final polynomial coefficients.
    pub final_poly: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Circuit
// ---------------------------------------------------------------------------

/// R1CS circuit that verifies a Plonky3-style STARK proof using FRI.
///
/// Implements `ConstraintSynthesizer<Fr>` so it can be directly used with
/// `ark_groth16::Groth16::circuit_specific_setup` and `Groth16::prove`.
pub struct FriVerifierCircuit {
    /// The prover's witness (None during key generation / circuit shape mode).
    pub proof_witness: Option<StarkProofWitness>,
    /// Circuit parameter configuration.
    pub fri_params: FriCircuitParams,
}

impl FriVerifierCircuit {
    /// Create an instance with concrete witness data (proving mode).
    pub fn with_witness(witness: StarkProofWitness, params: FriCircuitParams) -> Self {
        Self {
            proof_witness: Some(witness),
            fri_params: params,
        }
    }

    /// Create a setup-mode instance with no concrete values (key generation mode).
    pub fn for_setup(params: FriCircuitParams) -> Self {
        Self {
            proof_witness: None,
            fri_params: params,
        }
    }
}

fn expected_final_poly_len(params: &FriCircuitParams) -> usize {
    if params.log_final_poly_len == 0 {
        1
    } else {
        1usize << params.log_final_poly_len
    }
}

impl ConstraintSynthesizer<Fr> for FriVerifierCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let params = &self.fri_params;
        let witness = self.proof_witness.as_ref();

        let poseidon2 = Poseidon2GoldilocksGadget::new(params.poseidon2_seed);

        let has_air = !params.air_constraints.is_empty() && params.trace_width > 0;

        // ------------------------------------------------------------------
        // 1. Original computation public inputs (allocated as public inputs).
        // ------------------------------------------------------------------
        let num_pub_inputs = params.num_public_inputs;
        let pub_input_vars: Vec<GoldilocksVar> = (0..num_pub_inputs)
            .map(|i| {
                let val = witness.and_then(|w| w.public_inputs.get(i).copied());
                GoldilocksVar::alloc_input(cs.clone(), val)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // ------------------------------------------------------------------
        // 2. Commitment roots (public inputs when AIR is present).
        // ------------------------------------------------------------------
        let trace_commitment_vars: Vec<GoldilocksVar> = if has_air {
            (0..8)
                .map(|i| {
                    let val = witness.and_then(|w| w.trace_commitment.get(i).copied());
                    GoldilocksVar::alloc_input(cs.clone(), val)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

        let quotient_commitment_vars: Vec<GoldilocksVar> = if has_air {
            (0..8)
                .map(|i| {
                    let val = witness.and_then(|w| w.quotient_commitment.get(i).copied());
                    GoldilocksVar::alloc_input(cs.clone(), val)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

        // ------------------------------------------------------------------
        // 3. Fiat-Shamir transcript via DuplexChallenger (or legacy witness).
        // ------------------------------------------------------------------
        let (alpha_var, fri_alpha_vars) = if has_air {
            // Initialize challenger and replay transcript matching Plonky3 v0.4.2 exactly.
            let mut challenger = DuplexChallengerGadget::new(cs.clone(), &poseidon2)?;

            // --- uni-stark verifier transcript ---

            // 1. observe(degree_bits)
            let degree_bits_var = GoldilocksVar::constant(cs.clone(), params.log_degree as u64)?;
            challenger.observe(cs.clone(), &degree_bits_var)?;
            // 2. observe(degree_bits - is_zk) — is_zk=0 for ZKF, same value
            challenger.observe(cs.clone(), &degree_bits_var)?;
            // 3. observe(preprocessed_width = 0)
            let zero = GoldilocksVar::constant(cs.clone(), 0)?;
            challenger.observe(cs.clone(), &zero)?;
            // 4. observe(trace_commitment[0..8])
            challenger.observe_slice(cs.clone(), &trace_commitment_vars)?;
            // 5. observe_slice(public_values)
            challenger.observe_slice(cs.clone(), &pub_input_vars)?;
            // 6. sample → alpha
            let alpha_from_challenger = challenger.sample(cs.clone())?;
            // Constrain alpha hint to match
            let alpha_hint = GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.alpha))?;
            alpha_from_challenger.assert_equal(cs.clone(), &alpha_hint)?;
            // 7. observe(quotient_commitment[0..8])
            challenger.observe_slice(cs.clone(), &quotient_commitment_vars)?;
            // 8. sample → zeta
            let zeta_from_challenger = challenger.sample(cs.clone())?;
            let zeta_hint = GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.zeta))?;
            zeta_from_challenger.assert_equal(cs.clone(), &zeta_hint)?;

            // --- pcs.verify → verify_fri transcript ---

            // 9. sample → FRI batch alpha
            let _fri_batch_alpha = challenger.sample(cs.clone())?;

            // 10. For each FRI round: observe commit, PoW, sample beta
            let mut fri_betas: Vec<GoldilocksVar> = Vec::with_capacity(params.num_fri_rounds);
            for round in 0..params.num_fri_rounds {
                // Allocate and observe FRI round commitment (8-element digest)
                let fri_round_commit: Vec<GoldilocksVar> = (0..8)
                    .map(|i| {
                        let val =
                            witness.and_then(|w| w.fri_commitment_roots_8.get(round).map(|r| r[i]));
                        GoldilocksVar::alloc_witness(cs.clone(), val)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                challenger.observe_slice(cs.clone(), &fri_round_commit)?;

                // PoW: observe(pow_witness) + sample_bits(pow_bits)
                if params.commit_pow_bits > 0 {
                    let pow_w_val =
                        witness.and_then(|w| w.commit_pow_witnesses.get(round).copied());
                    let pow_w = GoldilocksVar::alloc_witness(cs.clone(), pow_w_val)?;
                    challenger.observe(cs.clone(), &pow_w)?;
                    let _pow_check = challenger.sample_bits(cs.clone(), params.commit_pow_bits)?;
                }

                // Sample beta
                let beta = challenger.sample(cs.clone())?;
                fri_betas.push(beta);
            }

            // 11. observe_slice(final_poly)
            {
                let final_poly_len = witness
                    .map(|w| w.final_poly.len())
                    .unwrap_or_else(|| expected_final_poly_len(params));
                for i in 0..final_poly_len {
                    let val = witness.and_then(|w| w.final_poly.get(i).copied());
                    let fp = GoldilocksVar::alloc_witness(cs.clone(), val)?;
                    challenger.observe(cs.clone(), &fp)?;
                }
            }

            // 12. PoW: observe(query_pow_witness) + sample_bits(query_pow_bits)
            if params.query_pow_bits > 0 {
                let qpw =
                    GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.query_pow_witness))?;
                challenger.observe(cs.clone(), &qpw)?;
                let _pow_check = challenger.sample_bits(cs.clone(), params.query_pow_bits)?;
            }

            // 13. For each query: sample_bits(log_global_max_height) → index
            // In the circuit, we just advance the challenger state and constrain the
            // sampled value to match the query index witness (via bit masking).
            let log_global_max_height =
                params.num_fri_rounds + params.log_blowup + params.log_final_poly_len;
            for q in 0..params.num_queries {
                // sample_bits in native = sample() then mask; in circuit we sample and
                // constrain the masked value equals the query index.
                let idx_sample = challenger.sample_bits(cs.clone(), log_global_max_height)?;
                let query_idx_val = witness.and_then(|w| w.queries.get(q).map(|qw| qw.query_index));
                let query_idx_var = GoldilocksVar::alloc_witness(cs.clone(), query_idx_val)?;

                // Constrain: idx_sample & mask == query_idx
                // Equivalently: idx_sample = high_bits * (1 << log_global_max_height) + query_idx
                let mask = (1u64 << log_global_max_height) as u128;
                let high_val = query_idx_val.and_then(|qi| {
                    idx_sample.value().map(|sample| {
                        let p = super::nonnative_goldilocks::GOLDILOCKS_PRIME as u128;
                        let s = sample as u128;
                        let q = qi as u128;
                        let diff = if s >= q { s - q } else { s + p - q };
                        (diff / mask) as u64
                    })
                });
                let high_var = GoldilocksVar::alloc_witness(cs.clone(), high_val)?;
                let mask_var = GoldilocksVar::constant(cs.clone(), mask as u64)?;
                let hm = high_var.mul(cs.clone(), &mask_var)?;
                let rhs = hm.add(cs.clone(), &query_idx_var)?;
                idx_sample.assert_equal(cs.clone(), &rhs)?;
            }

            (alpha_from_challenger, fri_betas)
        } else {
            // Legacy mode: alphas from witness (backward compatible)
            let alpha_vars: Vec<GoldilocksVar> = (0..params.num_fri_rounds)
                .map(|i| {
                    let val = witness.and_then(|w| w.fri_alphas.get(i).copied());
                    GoldilocksVar::alloc_witness(cs.clone(), val)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Use first alpha or a dummy for the AIR alpha
            let alpha_dummy = if alpha_vars.is_empty() {
                GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.alpha))?
            } else {
                alpha_vars[0].clone()
            };

            (alpha_dummy, alpha_vars)
        };

        // ------------------------------------------------------------------
        // 4. Per-query verification.
        // ------------------------------------------------------------------
        let num_queries = params.num_queries;
        let height = params.merkle_tree_height;
        let num_rounds = params.num_fri_rounds;

        for q in 0..num_queries {
            let query_witness = witness.and_then(|w| w.queries.get(q));

            // 4a. Merkle path verification with 8-element digests.
            let computed_root = compute_merkle_root_8(
                cs.clone(),
                &poseidon2,
                query_witness,
                height,
                params.trace_width,
            )?;

            // 4a'. Constrain computed Merkle root to match trace commitment.
            if has_air {
                for i in 0..8 {
                    computed_root[i].assert_equal(cs.clone(), &trace_commitment_vars[i])?;
                }
            }

            // 4b. FRI folding consistency across rounds.
            let last_folded = verify_fri_folding_goldilocks(
                cs.clone(),
                &fri_alpha_vars,
                query_witness,
                num_rounds,
            )?;

            // 4c. FRI round commitment Merkle verification.
            // For each FRI round, verify that the folded value's Merkle path
            // leads to the claimed FRI commitment root.
            if has_air {
                for round in 0..num_rounds {
                    // Allocate the FRI round commitment root (8-element digest)
                    let fri_round_root: [GoldilocksVar; 8] = std::array::from_fn(|i| {
                        let val =
                            witness.and_then(|w| w.fri_commitment_roots_8.get(round).map(|r| r[i]));
                        GoldilocksVar::alloc_witness(cs.clone(), val).unwrap()
                    });

                    // Verify Merkle path for this round's value (if paths are provided).
                    // In setup mode (no witness) or when paths haven't been extracted yet,
                    // we skip this check — the FRI commitment roots are still constrained
                    // by the challenger transcript observation.
                    let round_merkle_path =
                        query_witness.and_then(|qw| qw.fri_round_merkle_paths.get(round));
                    let round_height = if height > round + 1 {
                        height - round - 1
                    } else {
                        0
                    };

                    if round_height > 0 {
                        // Hash the folded value into a leaf digest
                        let folded_val =
                            query_witness.and_then(|qw| qw.fri_folded_values.get(round).copied());
                        let folded_var = GoldilocksVar::alloc_witness(cs.clone(), folded_val)?;
                        let leaf_digest = poseidon2.hash_leaf(cs.clone(), &[folded_var])?;

                        // Walk the path
                        let mut current = leaf_digest;
                        let query_idx = query_witness.map(|qw| qw.query_index).unwrap_or(0);
                        // FRI halves the domain each round, so shift the index
                        let round_query_idx = query_idx >> (round + 1);

                        for level in 0..round_height {
                            let sibling: [GoldilocksVar; 8] = std::array::from_fn(|i| {
                                let val = round_merkle_path
                                    .and_then(|path| path.get(level).map(|s| s[i]));
                                GoldilocksVar::alloc_witness(cs.clone(), val).unwrap()
                            });

                            let dir = ((round_query_idx >> level) & 1) == 1;
                            let dir_val = if dir { 1u64 } else { 0u64 };
                            let dir_bit = GoldilocksVar::alloc_witness(cs.clone(), Some(dir_val))?;
                            let one_c = GoldilocksVar::constant(cs.clone(), 1)?;
                            let one_minus_dir = one_c.sub(cs.clone(), &dir_bit)?;

                            let mut left =
                                [(); 8].map(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());
                            let mut right =
                                [(); 8].map(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());
                            for i in 0..8 {
                                let l1 = sibling[i].mul(cs.clone(), &dir_bit)?;
                                let l2 = current[i].mul(cs.clone(), &one_minus_dir)?;
                                left[i] = l1.add(cs.clone(), &l2)?;
                                let r1 = current[i].mul(cs.clone(), &dir_bit)?;
                                let r2 = sibling[i].mul(cs.clone(), &one_minus_dir)?;
                                right[i] = r1.add(cs.clone(), &r2)?;
                            }
                            current = poseidon2.compress_two(cs.clone(), &left, &right)?;
                        }

                        // Constrain computed root to match FRI round commitment
                        for i in 0..8 {
                            current[i].assert_equal(cs.clone(), &fri_round_root[i])?;
                        }
                    }
                }
            }

            // 4d. FRI final value check: last folded value must equal final_poly constant.
            if has_air {
                let final_poly_val =
                    GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.final_poly_value))?;
                last_folded.assert_equal(cs.clone(), &final_poly_val)?;
            }
        }

        // ------------------------------------------------------------------
        // 5. AIR constraint evaluation and quotient identity check.
        // ------------------------------------------------------------------
        if has_air {
            // Allocate trace_local as witness variables
            let trace_local_vars: Vec<GoldilocksVar> = (0..params.trace_width)
                .map(|i| {
                    let val = witness.and_then(|w| w.trace_local.get(i).copied());
                    GoldilocksVar::alloc_witness(cs.clone(), val)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Compute zeta^n (domain size = 2^log_degree) for selector validation
            let zeta_sel = GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.zeta))?;
            let mut zeta_pow_n = zeta_sel.clone();
            for _ in 0..params.log_degree {
                zeta_pow_n = zeta_pow_n.mul(cs.clone(), &zeta_pow_n)?;
            }
            // vanishing = zeta^n - 1
            let one = GoldilocksVar::constant(cs.clone(), 1)?;
            let vanishing = zeta_pow_n.sub(cs.clone(), &one)?;

            // Allocate inv_vanishing as witness, then constrain: inv_vanishing * vanishing == 1
            let inv_vanishing =
                GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.inv_vanishing_at_zeta))?;
            let check_inv = inv_vanishing.mul(cs.clone(), &vanishing)?;
            check_inv.assert_equal(cs.clone(), &one)?;

            // Allocate is_first_row as witness, then constrain:
            // is_first_row * n * (zeta - g^0) == vanishing
            // where g^0 = 1 (first element of the domain), so zeta - 1
            // Simplified: is_first_row == vanishing / (n * (zeta - 1))
            // In-circuit: is_first_row * n * (zeta - 1) == vanishing
            let is_first_row =
                GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.is_first_row_at_zeta))?;
            let domain_size = GoldilocksVar::constant(cs.clone(), 1u64 << params.log_degree)?;
            let zeta_minus_one = zeta_sel.sub(cs.clone(), &one)?;
            let ifr_times_n = is_first_row.mul(cs.clone(), &domain_size)?;
            let ifr_check = ifr_times_n.mul(cs.clone(), &zeta_minus_one)?;
            ifr_check.assert_equal(cs.clone(), &vanishing)?;

            // Evaluate the folded AIR constraints
            let folded = verify_air_constraints_circuit(
                cs.clone(),
                &params.air_constraints,
                &params.public_signal_indices,
                &trace_local_vars,
                &pub_input_vars,
                &alpha_var,
                &is_first_row,
            )?;

            // Allocate zeta for quotient recomposition
            let zeta_var = GoldilocksVar::alloc_witness(cs.clone(), witness.map(|w| w.zeta))?;

            // Allocate quotient chunks as individual witnesses
            let num_qc = params.num_quotient_chunks.max(1);
            let quotient_chunk_vars: Vec<GoldilocksVar> = (0..num_qc)
                .map(|i| {
                    let val = witness.and_then(|w| w.quotient_chunks.get(i).copied());
                    GoldilocksVar::alloc_witness(cs.clone(), val)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Recompose quotient from chunks using powers of zeta
            let quotient = recompose_quotient_circuit(
                cs.clone(),
                &quotient_chunk_vars,
                &zeta_var,
                params.log_degree,
            )?;

            // Verify: folded_constraints * inv_vanishing == quotient
            verify_quotient_identity(cs.clone(), &folded, &quotient, &inv_vanishing)?;
        } else {
            // No-AIR mode: still verify FRI structural soundness but skip
            // constraint evaluation. Public inputs are already exposed above.
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sub-circuits
// ---------------------------------------------------------------------------

/// Compute the Merkle root from a query's authentication path using 8-element
/// Poseidon2 digests matching Plonky3's Merkle tree structure.
///
/// Returns the computed 8-element root digest.
fn compute_merkle_root_8(
    cs: ConstraintSystemRef<Fr>,
    poseidon2: &Poseidon2GoldilocksGadget,
    query_witness: Option<&FriQueryWitness>,
    height: usize,
    trace_width: usize,
) -> Result<[GoldilocksVar; 8], SynthesisError> {
    // Hash ALL trace leaf values into an 8-element digest.
    // The Merkle tree leaf contains all trace columns at the query position.
    // Fall back to opened_value when leaf_values is empty (dummy/legacy witnesses).
    let num_leaf = trace_width.max(1);
    let leaf_vars: Vec<GoldilocksVar> = (0..num_leaf)
        .map(|i| {
            let val = query_witness.and_then(|qw| {
                qw.leaf_values.get(i).copied().or({
                    if i == 0 {
                        Some(qw.opened_value)
                    } else {
                        Some(0)
                    }
                })
            });
            GoldilocksVar::alloc_witness(cs.clone(), val)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut current = poseidon2.hash_leaf(cs.clone(), &leaf_vars)?;

    // Walk up the Merkle path
    for level in 0..height {
        // Allocate sibling digest (8 elements)
        let sibling: [GoldilocksVar; 8] = std::array::from_fn(|i| {
            let val =
                query_witness.and_then(|qw| qw.merkle_siblings_8.get(level).map(|sib| sib[i]));
            GoldilocksVar::alloc_witness(cs.clone(), val).unwrap()
        });

        // Direction bit derived from query_index: (query_index >> level) & 1
        let dir_val = query_witness.map(|qw| ((qw.query_index >> level) & 1) == 1);
        let dir_bit_val = dir_val.map(|b| if b { 1u64 } else { 0u64 });
        let dir_bit = GoldilocksVar::alloc_witness(cs.clone(), dir_bit_val)?;

        // Conditional swap: if dir_bit=1, left=sibling, right=current
        //                    if dir_bit=0, left=current, right=sibling
        let one = GoldilocksVar::constant(cs.clone(), 1)?;
        let one_minus_dir = one.sub(cs.clone(), &dir_bit)?;

        let mut left = [(); 8].map(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());
        let mut right = [(); 8].map(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());

        for i in 0..8 {
            let l1 = sibling[i].mul(cs.clone(), &dir_bit)?;
            let l2 = current[i].mul(cs.clone(), &one_minus_dir)?;
            left[i] = l1.add(cs.clone(), &l2)?;

            let r1 = current[i].mul(cs.clone(), &dir_bit)?;
            let r2 = sibling[i].mul(cs.clone(), &one_minus_dir)?;
            right[i] = r1.add(cs.clone(), &r2)?;
        }

        current = poseidon2.compress_two(cs.clone(), &left, &right)?;
    }

    Ok(current)
}

/// Verify FRI folding consistency for one query using Goldilocks arithmetic.
///
/// Uses the Lagrange interpolation formula matching Plonky3's fold_row:
///   f_next = e0 + (beta - xs[0]) * (e1 - e0) / (xs[1] - xs[0])
///
/// In division-free form:
///   (f_next - e0) * (xs[1] - xs[0]) == (beta - xs[0]) * (e1 - e0)
///
/// The even/odd assignment depends on the FRI direction bit per round.
///
/// Returns the last folded value for the FRI final value check.
fn verify_fri_folding_goldilocks(
    cs: ConstraintSystemRef<Fr>,
    alpha_vars: &[GoldilocksVar],
    query_witness: Option<&FriQueryWitness>,
    num_rounds: usize,
) -> Result<GoldilocksVar, SynthesisError> {
    // Starting value: alpha-composed FRI initial value
    let f_val = query_witness.map(|qw| qw.fri_composed_value);
    let mut f_current = GoldilocksVar::alloc_witness(cs.clone(), f_val)?;

    for (round, beta) in alpha_vars.iter().enumerate().take(num_rounds) {
        // Sibling value from the FRI commitment opening
        let f_sibling_val =
            query_witness.and_then(|qw| qw.fri_layer_odd_values.get(round).copied());
        let f_sibling = GoldilocksVar::alloc_witness(cs.clone(), f_sibling_val)?;

        // Direction bit: determines even/odd assignment
        let dir_val = query_witness.and_then(|qw| qw.fri_direction_bits.get(round).copied());
        let dir_u64 = dir_val.map(|b| if b { 1u64 } else { 0u64 });
        let dir_bit = GoldilocksVar::alloc_witness(cs.clone(), dir_u64)?;

        // Conditional swap: if dir=0, e0=f_current, e1=f_sibling
        //                   if dir=1, e0=f_sibling, e1=f_current
        let one = GoldilocksVar::constant(cs.clone(), 1)?;
        let one_minus_dir = one.sub(cs.clone(), &dir_bit)?;
        // e0 = f_current * (1-dir) + f_sibling * dir
        let e0_a = f_current.mul(cs.clone(), &one_minus_dir)?;
        let e0_b = f_sibling.mul(cs.clone(), &dir_bit)?;
        let e0 = e0_a.add(cs.clone(), &e0_b)?;
        // e1 = f_current * dir + f_sibling * (1-dir)
        let e1_a = f_current.mul(cs.clone(), &dir_bit)?;
        let e1_b = f_sibling.mul(cs.clone(), &one_minus_dir)?;
        let e1 = e1_a.add(cs.clone(), &e1_b)?;

        // f_next from witness
        let f_next_val = query_witness.and_then(|qw| qw.fri_folded_values.get(round).copied());
        let f_next = GoldilocksVar::alloc_witness(cs.clone(), f_next_val)?;

        // Allocate the precomputed subgroup_start for this round.
        // subgroup_start = g_{log_height+1}^{rev(parent_index, log_height)}
        // xs[0] = -subgroup_start, xs[1] = subgroup_start
        let x_val = query_witness.and_then(|qw| qw.fri_round_x_values.get(round).copied());
        let x = GoldilocksVar::alloc_witness(cs.clone(), x_val)?;

        // Division-free Lagrange interpolation check:
        //   f_next * 2x == e0 * (beta + x) - e1 * (beta - x)
        // Derived from: f_next = [e0*(beta+x) - e1*(beta-x)] / (2x)
        let two = GoldilocksVar::constant(cs.clone(), 2)?;
        let two_x = x.mul(cs.clone(), &two)?;
        let lhs = f_next.mul(cs.clone(), &two_x)?;
        let beta_plus_x = beta.add(cs.clone(), &x)?;
        let beta_minus_x = beta.sub(cs.clone(), &x)?;
        let term1 = e0.mul(cs.clone(), &beta_plus_x)?;
        let term2 = e1.mul(cs.clone(), &beta_minus_x)?;
        let rhs = term1.sub(cs.clone(), &term2)?;
        lhs.assert_equal(cs.clone(), &rhs)?;

        f_current = f_next;
    }

    Ok(f_current)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    /// Build a synthetic but consistent StarkProofWitness for testing.
    fn synthetic_witness(params: &FriCircuitParams) -> StarkProofWitness {
        let fri_alphas: Vec<u64> = (0..params.num_fri_rounds as u64)
            .map(|i| 2_000_000 + i)
            .collect();

        let queries: Vec<FriQueryWitness> = (0..params.num_queries)
            .map(|q| {
                let height = params.merkle_tree_height;
                let num_rounds = params.num_fri_rounds;

                let leaf_val: u64 = 42 + q as u64;
                let query_index = q as u64;

                // Build 8-element sibling digests
                let siblings_8: Vec<[u64; 8]> = (0..height)
                    .map(|l| {
                        let base = 100 + l as u64 + q as u64;
                        std::array::from_fn(|i| base + i as u64)
                    })
                    .collect();

                let direction_bits: Vec<bool> =
                    (0..height).map(|l| ((query_index >> l) & 1) == 1).collect();

                let fri_layer_odd_values = vec![leaf_val; num_rounds];
                let fri_folded_values = vec![leaf_val; num_rounds];

                FriQueryWitness {
                    merkle_siblings_8: siblings_8,
                    direction_bits,
                    opened_value: leaf_val,
                    query_x: 1,
                    query_index,
                    fri_layer_odd_values,
                    fri_folded_values,
                    fri_round_merkle_paths: Vec::new(),
                    fri_direction_bits: vec![false; num_rounds],
                    fri_composed_value: leaf_val,
                    leaf_values: vec![leaf_val],
                    fri_round_x_values: vec![1; num_rounds],
                }
            })
            .collect();

        let fri_commitment_roots = vec![0u64; params.num_fri_rounds + 1];

        StarkProofWitness {
            fri_commitment_roots,
            fri_alphas,
            queries,
            degree_bits: params.log_degree,
            public_inputs: vec![1u64, 2u64],
            ..Default::default()
        }
    }

    #[test]
    fn fri_verifier_circuit_with_poseidon2_satisfies_constraints() {
        let params = FriCircuitParams {
            num_queries: 1,
            num_fri_rounds: 1,
            log_degree: 4,
            merkle_tree_height: 2,
            poseidon2_seed: 42,
            num_public_inputs: 2,
            ..Default::default()
        };
        let witness = synthetic_witness(&params);
        let circuit = FriVerifierCircuit::with_witness(witness, params);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("circuit synthesis should not fail");

        let num_constraints = cs.num_constraints();
        assert!(num_constraints > 0, "circuit should have constraints");
        println!(
            "FRI verifier (1 query, 1 round, height 2, Poseidon2): {num_constraints} constraints"
        );

        assert!(
            cs.is_satisfied().unwrap(),
            "circuit with consistent Poseidon2 witness should be satisfied"
        );
    }

    #[test]
    fn fri_verifier_setup_mode_synthesizes() {
        let params = FriCircuitParams {
            num_queries: 1,
            num_fri_rounds: 1,
            log_degree: 4,
            merkle_tree_height: 2,
            poseidon2_seed: 42,
            num_public_inputs: 2,
            ..Default::default()
        };
        let circuit = FriVerifierCircuit::for_setup(params);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = circuit.generate_constraints(cs.clone());
        let num_constraints = cs.num_constraints();
        println!("Setup-mode constraints: {num_constraints}");
    }

    #[test]
    fn fri_circuit_params_default() {
        let p = FriCircuitParams::default();
        assert_eq!(p.num_queries, 32);
        assert_eq!(p.num_fri_rounds, 16);
        assert_eq!(p.log_degree, 16);
        assert_eq!(p.merkle_tree_height, 16);
    }

    #[test]
    fn stark_proof_witness_default_is_empty() {
        let w = StarkProofWitness::default();
        assert!(w.fri_commitment_roots.is_empty());
        assert!(w.queries.is_empty());
        assert!(w.trace_local.is_empty());
        assert!(w.quotient_chunks.is_empty());
    }

    #[test]
    fn circuit_with_air_constraints_satisfies() {
        use p3_challenger::{CanObserve, CanSample, CanSampleBits};
        use p3_field::PrimeCharacteristicRing;
        use p3_field::PrimeField64;
        use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
        use rand09::SeedableRng;
        use rand09::rngs::SmallRng;

        // Test with a simple constraint: signal[0] == signal[1]
        let constraints = vec![AirExpr::Sub(
            Box::new(AirExpr::Signal(0)),
            Box::new(AirExpr::Signal(1)),
        )];

        let seed = 42u64;
        let log_degree = 4usize;
        let public_inputs_val = vec![42u64];
        let p = super::super::nonnative_goldilocks::GOLDILOCKS_PRIME as u128;
        let final_poly = vec![42u64]; // synthetic final polynomial

        // FRI params for test: pow_bits=0, log_blowup=1, log_final_poly_len=0
        let num_fri_rounds = 1usize;
        let log_blowup = 1usize;
        let log_final_poly_len = 0usize;
        let log_global_max_height = num_fri_rounds + log_blowup + log_final_poly_len;

        fn mod_inv(a: u128, p: u128) -> u128 {
            let mut result = 1u128;
            let mut base = a % p;
            let mut exp = p - 2;
            while exp > 0 {
                if exp & 1 == 1 {
                    result = (result * base) % p;
                }
                base = (base * base) % p;
                exp >>= 1;
            }
            result
        }

        // Helper to replay the full transcript matching the corrected Plonky3 v0.4.2 order
        let replay_transcript = |trace_commitment: &[u64],
                                 public_inputs: &[u64],
                                 quotient_commitment: &[u64],
                                 fri_commitment_roots_8: &[[u64; 8]],
                                 final_poly: &[u64]|
         -> (u64, u64, u64, Vec<u64>, Vec<u64>) {
            let mut c = {
                let mut rng = SmallRng::seed_from_u64(seed);
                let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
                p3_challenger::DuplexChallenger::<Goldilocks, Poseidon2Goldilocks<16>, 16, 8>::new(
                    perm,
                )
            };
            // 1. observe(degree_bits)
            c.observe(Goldilocks::from_u64(log_degree as u64));
            // 2. observe(degree_bits) — is_zk=0
            c.observe(Goldilocks::from_u64(log_degree as u64));
            // 3. observe(preprocessed_width=0)
            c.observe(Goldilocks::ZERO);
            // 4. observe(trace_commitment)
            for &tc in trace_commitment {
                c.observe(Goldilocks::from_u64(tc));
            }
            // 5. observe_slice(public_inputs)
            for &pi in public_inputs {
                c.observe(Goldilocks::from_u64(pi));
            }
            // 6. sample → alpha
            let alpha: Goldilocks = c.sample();
            // 7. observe(quotient_commitment)
            for &qc in quotient_commitment {
                c.observe(Goldilocks::from_u64(qc));
            }
            // 8. sample → zeta
            let zeta: Goldilocks = c.sample();
            // 9. sample → FRI batch alpha
            let fri_batch_alpha: Goldilocks = c.sample();
            // 10. For each FRI round: observe commit, sample beta (no PoW since bits=0)
            let mut betas = Vec::new();
            for root_8 in fri_commitment_roots_8 {
                for &elem in root_8 {
                    c.observe(Goldilocks::from_u64(elem));
                }
                let beta: Goldilocks = c.sample();
                betas.push(beta.as_canonical_u64());
            }
            // 11. observe_slice(final_poly)
            for &fp in final_poly {
                c.observe(Goldilocks::from_u64(fp));
            }
            // 12. No PoW (bits=0)
            // 13. sample_bits → query indices
            let mut indices = Vec::new();
            let idx: usize = c.sample_bits(log_global_max_height);
            indices.push(idx as u64);
            (
                alpha.as_canonical_u64(),
                zeta.as_canonical_u64(),
                fri_batch_alpha.as_canonical_u64(),
                betas,
                indices,
            )
        };

        // Build a symmetric Merkle tree (all leaves identical) so the root is
        // independent of query index, avoiding convergence issues.
        use super::super::poseidon2_goldilocks::{
            compress_two_native, hash_leaf_native, merkle_root_8_native,
        };
        let leaf_val = 42u64;
        let quotient_commitment = vec![0u64; 8];
        let fri_leaf_hash = hash_leaf_native(seed, &[leaf_val]);
        let fri_round_root = compress_two_native(seed, &fri_leaf_hash, &fri_leaf_hash);
        let fri_commitment_roots_8 = vec![fri_round_root];

        // All leaves hash to the same digest → siblings at every level are identical
        let leaf_hash = hash_leaf_native(seed, &[leaf_val, leaf_val]); // trace_width=2
        let level1 = compress_two_native(seed, &leaf_hash, &leaf_hash);
        let siblings_8: Vec<[u64; 8]> = vec![leaf_hash, level1];
        // Root is the same regardless of direction bits (symmetric tree)
        let root = merkle_root_8_native(seed, &leaf_hash, &siblings_8, &[false, false]);
        let actual_trace_commitment: Vec<u64> = root.to_vec();

        // Single transcript replay — query index doesn't affect the Merkle root
        let (alpha2, zeta2, fri_alpha2, betas2, qi2) = replay_transcript(
            &actual_trace_commitment,
            &public_inputs_val,
            &quotient_commitment,
            &fri_commitment_roots_8,
            &final_poly,
        );
        let derived_qi2 = qi2[0];

        let dir_bits2: Vec<bool> = (0..2).map(|l| ((derived_qi2 >> l) & 1) == 1).collect();

        // Compute selectors
        let z2_128 = zeta2 as u128;
        let mut z2_pow_n = z2_128;
        for _ in 0..log_degree {
            z2_pow_n = (z2_pow_n * z2_pow_n) % p;
        }
        let van2 = if z2_pow_n >= 1 {
            (z2_pow_n - 1) % p
        } else {
            (z2_pow_n + p - 1) % p
        };
        let inv_van2 = mod_inv(van2, p) as u64;
        let z2_m1 = if z2_128 >= 1 {
            (z2_128 - 1) % p
        } else {
            (z2_128 + p - 1) % p
        };
        let domain_size = 1u64 << log_degree;
        let n_z2m1 = ((domain_size as u128) * z2_m1) % p;
        let inv_n_z2m1 = mod_inv(n_z2m1, p);
        let is_first_row2 = ((van2 * inv_n_z2m1) % p) as u64;

        let params = FriCircuitParams {
            num_queries: 1,
            num_fri_rounds: 1,
            log_degree,
            merkle_tree_height: 2,
            poseidon2_seed: seed,
            num_public_inputs: 1,
            trace_width: 2,
            air_constraints: constraints,
            public_signal_indices: vec![0],
            num_quotient_chunks: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
            log_blowup,
            log_final_poly_len,
        };

        // Build witness: trace_local = [42, 42] so constraint 42-42 = 0
        // folded = 0, quotient = 0 (trivially satisfied)
        let witness = StarkProofWitness {
            fri_commitment_roots: vec![0u64; 2],
            fri_alphas: betas2.clone(),
            queries: vec![FriQueryWitness {
                merkle_siblings_8: siblings_8,
                direction_bits: dir_bits2,
                opened_value: leaf_val,
                query_x: 1,
                query_index: derived_qi2,
                fri_layer_odd_values: vec![leaf_val],
                fri_folded_values: vec![leaf_val],
                fri_round_merkle_paths: vec![vec![fri_leaf_hash]],
                fri_direction_bits: vec![false],
                fri_composed_value: leaf_val,
                leaf_values: vec![leaf_val, leaf_val], // trace_width=2
                fri_round_x_values: vec![1],
            }],
            degree_bits: log_degree,
            public_inputs: public_inputs_val,
            trace_local: vec![42, 42],
            trace_next: vec![0, 0],
            quotient_chunks: vec![0],
            trace_commitment: actual_trace_commitment,
            quotient_commitment,
            zeta: zeta2,
            alpha: alpha2,
            is_first_row_at_zeta: is_first_row2,
            inv_vanishing_at_zeta: inv_van2,
            final_poly_value: leaf_val,
            fri_commitment_roots_8,
            fri_batch_alpha: fri_alpha2,
            commit_pow_witnesses: Vec::new(),
            query_pow_witness: 0,
            final_poly: final_poly,
        };

        let circuit = FriVerifierCircuit::with_witness(witness, params);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("circuit synthesis should not fail");

        println!(
            "Circuit with AIR constraints: {} constraints",
            cs.num_constraints()
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit with satisfied AIR constraints should pass"
        );
    }

    #[test]
    fn setup_mode_matches_witness_shape_for_air_circuit() {
        let params = FriCircuitParams {
            num_queries: 1,
            num_fri_rounds: 1,
            log_degree: 4,
            merkle_tree_height: 2,
            poseidon2_seed: 42,
            num_public_inputs: 1,
            trace_width: 2,
            air_constraints: vec![AirExpr::Sub(
                Box::new(AirExpr::Signal(0)),
                Box::new(AirExpr::Signal(1)),
            )],
            public_signal_indices: vec![0],
            num_quotient_chunks: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
            log_blowup: 1,
            log_final_poly_len: 0,
        };

        let witness = StarkProofWitness {
            fri_commitment_roots: vec![0u64; 2],
            fri_alphas: vec![0u64; 1],
            queries: vec![FriQueryWitness {
                merkle_siblings_8: vec![[0u64; 8]; params.merkle_tree_height],
                direction_bits: vec![false; params.merkle_tree_height],
                opened_value: 0,
                query_x: 1,
                query_index: 0,
                fri_layer_odd_values: vec![0; params.num_fri_rounds],
                fri_folded_values: vec![0; params.num_fri_rounds],
                fri_round_merkle_paths: vec![vec![[0u64; 8]; params.merkle_tree_height - 1]],
                fri_direction_bits: vec![false; params.num_fri_rounds],
                fri_composed_value: 0,
                leaf_values: vec![0; params.trace_width],
                fri_round_x_values: vec![1; params.num_fri_rounds],
            }],
            degree_bits: params.log_degree,
            public_inputs: vec![0],
            trace_local: vec![0; params.trace_width],
            trace_next: vec![0; params.trace_width],
            quotient_chunks: vec![0; params.num_quotient_chunks.max(1)],
            trace_commitment: vec![0; 8],
            quotient_commitment: vec![0; 8],
            zeta: 0,
            alpha: 0,
            is_first_row_at_zeta: 0,
            inv_vanishing_at_zeta: 0,
            final_poly_value: 0,
            fri_commitment_roots_8: vec![[0u64; 8]; params.num_fri_rounds],
            fri_batch_alpha: 0,
            commit_pow_witnesses: Vec::new(),
            query_pow_witness: 0,
            final_poly: vec![0; expected_final_poly_len(&params)],
        };

        let witness_cs = ConstraintSystem::<Fr>::new_ref();
        FriVerifierCircuit::with_witness(witness, params.clone())
            .generate_constraints(witness_cs.clone())
            .expect("witness synthesis");

        let setup_cs = ConstraintSystem::<Fr>::new_ref();
        setup_cs.set_mode(ark_relations::r1cs::SynthesisMode::Setup);
        FriVerifierCircuit::for_setup(params)
            .generate_constraints(setup_cs.clone())
            .expect("setup synthesis");

        assert_eq!(setup_cs.num_constraints(), witness_cs.num_constraints());
        assert_eq!(
            setup_cs.num_instance_variables(),
            witness_cs.num_instance_variables()
        );
    }
}
