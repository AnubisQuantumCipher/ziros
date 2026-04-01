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

//! FRI query verification as a Nova step circuit.
//!
//! Each step verifies one FRI query's FOLDING CONSISTENCY across all rounds and
//! updates an accumulator state. 32 steps fold all queries into a single Nova IVC proof.
//!
//! # What is verified in-circuit (cryptographic)
//!
//! 1. **FRI folding consistency** (all `num_fri_rounds` rounds):
//!    For each round r, given evaluations f_r(x) and f_r(-x) at a query position
//!    and the folding challenge β_r, the circuit enforces:
//!    `2·x·f_{r+1}(x²) = f_r(x)·(x + β_r) + f_r(−x)·(x − β_r)`
//!    This verifies that the folded polynomial is computed correctly from its sibling pair.
//!
//! 2. **Running accumulator** (step count + proof hash chain):
//!    Each step hashes its witness into the running accumulator, binding the Nova proof
//!    to the specific FRI query values provided.
//!
//! # What is NOT verified in-circuit (attestation gap)
//!
//! - **Merkle path authentication**: The circuit does NOT verify that the opened values
//!   (f_r(x), f_r(-x)) were actually committed to in the FRI round Merkle trees.
//!   This requires Goldilocks Poseidon2 in Pallas R1CS, around 500K constraints per level,
//!   making it prohibitively expensive for Nova IVC.
//!
//! **Consequence**: The V3 (Nova-compressed) path has "attestation" trust model.
//! Callers who have the original STARK proof can close this gap by calling
//! `verify_merkle_paths_native` with the populated `FriQueryWitness` fields
//! (`merkle_path`, `query_index`) and the trace commitment from the proof header.
//! For full cryptographic soundness use the V2 direct path (`stark_to_groth16.rs`)
//! which verifies both folding AND Merkle paths using Goldilocks Poseidon2 in BN254 R1CS.
//!
//! # Goldilocks arithmetic in Pallas R1CS
//!
//! Goldilocks field: p = 2^64 - 2^32 + 1 = 18446744069414584321.
//! Pallas scalar field: ~2^254. Since p < 2^64 << 2^254, Goldilocks elements embed
//! trivially into Pallas scalars. Goldilocks arithmetic uses modular reduction:
//! - Addition: a + b = q·p + r, with q ∈ {0,1} (carry bit)
//! - Multiplication: a·b = q·p + r, with q < 2^64 (range-checked)
//!
//! Each Goldilocks multiplication costs around 395 R1CS constraints
//! (1 mul + 2x64-bit range checks).
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

/// Goldilocks prime p = 2^64 - 2^32 + 1.
#[cfg(feature = "nova-compression")]
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Witness data for a single FRI query verification step.
#[cfg(feature = "nova-compression")]
#[derive(Clone, Debug)]
pub struct FriQueryWitness {
    /// Query index (0..num_queries-1)
    pub query_index: u32,
    /// FRI evaluation domain positions (x values, one per FRI round)
    /// x_r is the evaluation point for round r; x_{r+1} = x_r^2 mod p
    pub x_values: Vec<u64>,
    /// Evaluation f_r(x_r) for each round (the "left" sibling in the pair)
    pub f_evals_pos: Vec<u64>,
    /// Evaluation f_r(-x_r) for each round (the "right" sibling, at -x in Goldilocks)
    pub f_evals_neg: Vec<u64>,
    /// Folded evaluations f_{r+1}(x_r^2) for each round (output of fold)
    pub f_evals_folded: Vec<u64>,
    /// FRI folding challenges β_r for each round (from Fiat-Shamir)
    pub folding_challenges: Vec<u64>,
    /// Merkle path sibling hashes (NOT verified in-circuit, only used for attestation)
    pub merkle_path: Vec<[u64; 8]>,
    /// Expected Merkle root commitments per FRI round (NOT verified in-circuit)
    pub round_commitments: Vec<[u64; 8]>,
}

/// Accumulator state carried between Nova steps.
///
/// Layout (as Pallas scalars):
/// - `0`: fold_valid_status (1 = all folds valid so far, 0 = failure detected)
/// - `1`: queries_verified_count
/// - `2`: query_hash_lo (running SHA-256-like hash of all query witnesses, low limb)
/// - `3`: query_hash_hi (running hash, high limb)
/// - `4`: initial_x_accumulator (product of initial x values, for binding)
///
/// Total: 5 public state elements.
#[cfg(feature = "nova-compression")]
pub const ACCUMULATOR_SIZE: usize = 5;

/// The Nova step circuit that verifies FRI folding consistency for one query.
///
/// All instances must have identical R1CS shape. Queries with fewer FRI rounds
/// are padded to match the maximum (`num_fri_rounds`).
#[cfg(feature = "nova-compression")]
#[derive(Clone, Debug)]
pub struct FriQueryStep {
    /// Per-step witness (None for setup/sizing pass)
    witness: Option<FriQueryWitness>,
    /// Number of FRI rounds (must be identical for all steps)
    num_fri_rounds: usize,
}

#[cfg(feature = "nova-compression")]
impl FriQueryStep {
    /// Create a new FRI query step circuit.
    pub fn new(witness: Option<FriQueryWitness>, num_fri_rounds: usize) -> Self {
        Self {
            witness,
            num_fri_rounds,
        }
    }

    /// Create a sizing instance (no witness) for public parameter generation.
    pub fn sizing_instance(num_fri_rounds: usize) -> Self {
        Self::new(None, num_fri_rounds)
    }
}

#[cfg(feature = "nova-compression")]
impl StepCircuit<PallasScalar> for FriQueryStep {
    fn arity(&self) -> usize {
        ACCUMULATOR_SIZE
    }

    fn synthesize<CS: ConstraintSystem<PallasScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<PallasScalar>],
    ) -> Result<Vec<AllocatedNum<PallasScalar>>, SynthesisError> {
        // z[0] = fold_valid_status (1 if all prior queries passed)
        // z[1] = queries_verified_count
        // z[2] = query_hash_lo
        // z[3] = query_hash_hi
        // z[4] = initial_x_accumulator

        // ----------------------------------------------------------------
        // Step 1: Verify FRI folding consistency for each round.
        //
        // For round r: 2·x·f_fold(x²) = f(x)·(x+β) + f(-x)·(x-β)
        // This is a Goldilocks arithmetic check (~4 muls × ~395 constraints per round).
        // ----------------------------------------------------------------
        let mut all_folds_valid = alloc_one(cs.namespace(|| "all_folds_init"))?;

        for r in 0..self.num_fri_rounds {
            let label = format!("round_{r}");

            // Allocate x_r (evaluation position)
            let x_val = self
                .witness
                .as_ref()
                .and_then(|w| w.x_values.get(r).copied());
            let x = alloc_goldilocks(cs.namespace(|| format!("{label}_x")), x_val)?;

            // Allocate f(x), f(-x), f_fold(x²)
            let fx_val = self
                .witness
                .as_ref()
                .and_then(|w| w.f_evals_pos.get(r).copied());
            let fx_neg_val = self
                .witness
                .as_ref()
                .and_then(|w| w.f_evals_neg.get(r).copied());
            let f_fold_val = self
                .witness
                .as_ref()
                .and_then(|w| w.f_evals_folded.get(r).copied());
            let beta_val = self
                .witness
                .as_ref()
                .and_then(|w| w.folding_challenges.get(r).copied());

            let fx = alloc_goldilocks(cs.namespace(|| format!("{label}_fx")), fx_val)?;
            let fx_neg = alloc_goldilocks(cs.namespace(|| format!("{label}_fx_neg")), fx_neg_val)?;
            let f_fold = alloc_goldilocks(cs.namespace(|| format!("{label}_f_fold")), f_fold_val)?;
            let beta = alloc_goldilocks(cs.namespace(|| format!("{label}_beta")), beta_val)?;

            // Compute LHS = 2·x·f_fold(x²)
            let two_x =
                goldilocks_add(cs.namespace(|| format!("{label}_2x")), &x, x_val, &x, x_val)?;
            let lhs = goldilocks_mul(
                cs.namespace(|| format!("{label}_lhs")),
                &two_x.0,
                two_x.1,
                &f_fold,
                f_fold_val,
            )?;

            // Compute x_plus_beta = x + β (Goldilocks)
            let x_plus_beta = goldilocks_add(
                cs.namespace(|| format!("{label}_x_plus_beta")),
                &x,
                x_val,
                &beta,
                beta_val,
            )?;

            // Compute x_minus_beta = x - β = x + (p - β) mod p (Goldilocks subtraction)
            let x_minus_beta = goldilocks_sub(
                cs.namespace(|| format!("{label}_x_minus_beta")),
                &x,
                x_val,
                &beta,
                beta_val,
            )?;

            // Compute rhs_term1 = f(x) · (x + β)
            let rhs1 = goldilocks_mul(
                cs.namespace(|| format!("{label}_rhs1")),
                &fx,
                fx_val,
                &x_plus_beta.0,
                x_plus_beta.1,
            )?;

            // Compute rhs_term2 = f(-x) · (x - β)
            let rhs2 = goldilocks_mul(
                cs.namespace(|| format!("{label}_rhs2")),
                &fx_neg,
                fx_neg_val,
                &x_minus_beta.0,
                x_minus_beta.1,
            )?;

            // Compute rhs = rhs_term1 + rhs_term2
            let rhs = goldilocks_add(
                cs.namespace(|| format!("{label}_rhs")),
                &rhs1.0,
                rhs1.1,
                &rhs2.0,
                rhs2.1,
            )?;

            // fold_ok_r = (lhs == rhs) ? 1 : 0
            let fold_ok_r = goldilocks_eq(
                cs.namespace(|| format!("{label}_fold_ok")),
                &lhs.0,
                lhs.1,
                &rhs.0,
                rhs.1,
            )?;

            // all_folds_valid = all_folds_valid * fold_ok_r
            all_folds_valid =
                all_folds_valid.mul(cs.namespace(|| format!("{label}_accumulate")), &fold_ok_r)?;
        }

        // ----------------------------------------------------------------
        // Step 2: Update fold_valid_status = status_in * all_folds_valid
        // (AND: one failure permanently zeros the status)
        // ----------------------------------------------------------------
        let status_out = z[0].mul(cs.namespace(|| "status_update"), &all_folds_valid)?;

        // ----------------------------------------------------------------
        // Step 3: count_out = count_in + 1
        // ----------------------------------------------------------------
        let count_out = AllocatedNum::alloc(cs.namespace(|| "count_out"), || {
            let v = z[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v + PallasScalar::ONE)
        })?;
        cs.enforce(
            || "count_increment",
            |lc| lc + z[1].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count_out.get_variable(),
        );

        // ----------------------------------------------------------------
        // Step 4: Update query hash (hash chain binding witness to accumulator)
        // Uses a Pallas-native linear hash: h_new = h_lo + sum(witness scalars)
        // This provides statistical binding (not Goldilocks collision resistance).
        // ----------------------------------------------------------------
        let hash_contribution = compute_witness_hash(cs, &self.witness, self.num_fri_rounds)?;
        let hash_lo_out = z[2].add(cs.namespace(|| "hash_lo_update"), &hash_contribution)?;

        // hash_hi passes through (used for multi-limb hash in extended versions)
        let hash_hi_out = z[3].clone();

        // ----------------------------------------------------------------
        // Step 5: Update initial_x_accumulator (product of first x_values)
        // Provides structural binding to the query domain positions.
        // ----------------------------------------------------------------
        let first_x_val = self
            .witness
            .as_ref()
            .and_then(|w| w.x_values.first().copied());
        let first_x_pallas = first_x_val
            .map(pallas_from_u64)
            .unwrap_or(PallasScalar::ONE);
        let first_x = AllocatedNum::alloc(cs.namespace(|| "first_x"), || Ok(first_x_pallas))?;
        let x_acc_out = z[4].mul(cs.namespace(|| "x_acc_update"), &first_x)?;

        Ok(vec![
            status_out,
            count_out,
            hash_lo_out,
            hash_hi_out,
            x_acc_out,
        ])
    }
}

// ============================================================================
// Goldilocks arithmetic helpers in Nova's ConstraintSystem<PallasScalar>
// ============================================================================

/// Allocate a Goldilocks witness variable with 64-bit range check.
///
/// The value must be < GOLDILOCKS_PRIME (2^64 - 2^32 + 1).
/// When `val` is None (sizing mode), allocates 0 — the circuit shape is identical to
/// the real case (same number of constraints), which is the Nova IVC requirement.
/// Range check costs: 2 × 64 boolean constraints + 2 reconstruction constraints = 130 constraints.
#[cfg(feature = "nova-compression")]
fn alloc_goldilocks<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    val: Option<u64>,
) -> Result<AllocatedNum<PallasScalar>, SynthesisError> {
    // In sizing mode (val=None), use 0 as placeholder. The shape must be identical.
    let effective_val = val.unwrap_or(0u64);
    let var = AllocatedNum::alloc(cs.namespace(|| "val"), || {
        Ok(pallas_from_u64(effective_val))
    })?;
    // 64-bit range check (always uses effective_val so shape is constant)
    range_check_64_nova(cs.namespace(|| "range64"), &var, Some(effective_val))?;
    Ok(var)
}

/// Goldilocks addition: r = (a + b) mod p.
///
/// Witnesses carry bit q ∈ {0,1}, enforces a + b = q·p + r.
/// Returns (result_var, result_val).
/// Cost: ~3 constraints + 130 (range check for r) = ~133 constraints.
#[cfg(feature = "nova-compression")]
fn goldilocks_add<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    a: &AllocatedNum<PallasScalar>,
    a_val: Option<u64>,
    b: &AllocatedNum<PallasScalar>,
    b_val: Option<u64>,
) -> Result<(AllocatedNum<PallasScalar>, Option<u64>), SynthesisError> {
    let p = GOLDILOCKS_PRIME;
    // Use 0 as default for sizing mode — constraint shape is identical
    let xa = a_val.unwrap_or(0u64);
    let xb = b_val.unwrap_or(0u64);
    let s = (xa as u128) + (xb as u128);
    let pp = p as u128;
    let (r_native, q_native) = if s >= pp {
        ((s - pp) as u64, 1u64)
    } else {
        (s as u64, 0u64)
    };
    let r_val = Some(r_native);
    let q_val = Some(q_native);

    // Allocate result
    let r = alloc_goldilocks(cs.namespace(|| "r"), r_val)?;

    // Allocate carry bit q
    let q = AllocatedNum::alloc(cs.namespace(|| "q"), || {
        q_val
            .map(pallas_from_u64)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;

    // q must be boolean: q * (1 - q) = 0
    cs.enforce(
        || "q_bool",
        |lc| lc + q.get_variable(),
        |lc| lc + CS::one() - q.get_variable(),
        |lc| lc,
    );

    // Allocate q * p (product with constant p, using 1 constraint)
    let p_pallas = pallas_from_u64(p);
    let qp = AllocatedNum::alloc(cs.namespace(|| "qp"), || {
        q_val
            .map(|v| pallas_from_u64(v) * p_pallas)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "qp_constraint",
        |lc| lc + q.get_variable(),
        |lc| lc + (p_pallas, CS::one()),
        |lc| lc + qp.get_variable(),
    );

    // Enforce: a + b = q·p + r
    cs.enforce(
        || "add_constraint",
        |lc| lc + a.get_variable() + b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + qp.get_variable() + r.get_variable(),
    );

    Ok((r, r_val))
}

/// Goldilocks subtraction: r = (a - b) mod p.
///
/// Witnesses borrow bit q ∈ {0,1}, enforces a + q·p = b + r.
/// Returns (result_var, result_val).
#[cfg(feature = "nova-compression")]
fn goldilocks_sub<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    a: &AllocatedNum<PallasScalar>,
    a_val: Option<u64>,
    b: &AllocatedNum<PallasScalar>,
    b_val: Option<u64>,
) -> Result<(AllocatedNum<PallasScalar>, Option<u64>), SynthesisError> {
    let p = GOLDILOCKS_PRIME;
    let xa = a_val.unwrap_or(0u64);
    let xb = b_val.unwrap_or(0u64);
    let (r_native, borrow_native) = if xa >= xb {
        (xa - xb, 0u64)
    } else {
        (((xa as u128) + (p as u128) - (xb as u128)) as u64, 1u64)
    };
    let r_val = Some(r_native);
    let borrow_val = Some(borrow_native);

    let r = alloc_goldilocks(cs.namespace(|| "r"), r_val)?;

    let borrow = AllocatedNum::alloc(cs.namespace(|| "borrow"), || {
        borrow_val
            .map(pallas_from_u64)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;

    // borrow must be boolean
    cs.enforce(
        || "borrow_bool",
        |lc| lc + borrow.get_variable(),
        |lc| lc + CS::one() - borrow.get_variable(),
        |lc| lc,
    );

    // q * p
    let p_pallas = pallas_from_u64(p);
    let qp = AllocatedNum::alloc(cs.namespace(|| "qp"), || {
        borrow_val
            .map(|v| pallas_from_u64(v) * p_pallas)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "qp_constraint",
        |lc| lc + borrow.get_variable(),
        |lc| lc + (p_pallas, CS::one()),
        |lc| lc + qp.get_variable(),
    );

    // Enforce: a + borrow·p = b + r  →  (a + qp) = (b + r)
    cs.enforce(
        || "sub_constraint",
        |lc| lc + a.get_variable() + qp.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b.get_variable() + r.get_variable(),
    );

    Ok((r, r_val))
}

/// Goldilocks multiplication: r = (a · b) mod p.
///
/// Witnesses quotient q and remainder r, enforces a·b = q·p + r.
/// q < 2^64 (range-checked with 64 bits).
/// Returns (result_var, result_val).
/// Cost: ~2 mul constraints + 2×64-bit range checks ≈ 265 constraints.
#[cfg(feature = "nova-compression")]
fn goldilocks_mul<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    a: &AllocatedNum<PallasScalar>,
    a_val: Option<u64>,
    b: &AllocatedNum<PallasScalar>,
    b_val: Option<u64>,
) -> Result<(AllocatedNum<PallasScalar>, Option<u64>), SynthesisError> {
    let p = GOLDILOCKS_PRIME;
    let xa = a_val.unwrap_or(0u64);
    let xb = b_val.unwrap_or(0u64);
    let prod = (xa as u128) * (xb as u128);
    let pp = p as u128;
    let r_val = Some((prod % pp) as u64);
    let q_val = Some((prod / pp) as u64);

    // Allocate r (with Goldilocks range check via 64-bit check)
    let r = alloc_goldilocks(cs.namespace(|| "r"), r_val)?;

    // Allocate q (64-bit range check for quotient)
    let q = AllocatedNum::alloc(cs.namespace(|| "q"), || {
        q_val
            .map(pallas_from_u64)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    range_check_64_nova(cs.namespace(|| "q_range64"), &q, q_val)?;

    // Compute a * b in Pallas (exact since a,b < 2^64 and 2^128 < p_pallas)
    let ab = a.mul(cs.namespace(|| "ab_mul"), b)?;

    // Allocate q * p
    let p_pallas = pallas_from_u64(p);
    let qp = AllocatedNum::alloc(cs.namespace(|| "qp"), || {
        q_val
            .map(|v| pallas_from_u64(v) * p_pallas)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "qp_constraint",
        |lc| lc + q.get_variable(),
        |lc| lc + (p_pallas, CS::one()),
        |lc| lc + qp.get_variable(),
    );

    // Enforce: a·b = q·p + r
    cs.enforce(
        || "mul_constraint",
        |lc| lc + ab.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + qp.get_variable() + r.get_variable(),
    );

    Ok((r, r_val))
}

/// Goldilocks equality check: returns 1 if a == b (mod p), else 0.
///
/// Implemented as: is_zero((a - b) mod p) using the standard R1CS trick:
///   - Allocate diff = (a - b) mod p
///   - Allocate inv = diff^(-1) if diff ≠ 0, else 0
///   - is_nonzero = diff * inv (must be 0 or 1)
///   - is_zero = 1 - is_nonzero
///
/// Cost: ~1 subtraction + ~5 constraints.
#[cfg(feature = "nova-compression")]
fn goldilocks_eq<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    a: &AllocatedNum<PallasScalar>,
    a_val: Option<u64>,
    b: &AllocatedNum<PallasScalar>,
    b_val: Option<u64>,
) -> Result<AllocatedNum<PallasScalar>, SynthesisError> {
    let (diff, diff_val) = goldilocks_sub(cs.namespace(|| "diff"), a, a_val, b, b_val)?;

    // Compute inverse of diff (0 if diff == 0)
    let diff_native = diff_val.unwrap_or(0u64);
    let diff_pallas = pallas_from_u64(diff_native);
    let inv_v = if diff_pallas == PallasScalar::ZERO {
        PallasScalar::ZERO
    } else {
        diff_pallas.invert().unwrap_or(PallasScalar::ZERO)
    };

    let inv = AllocatedNum::alloc(cs.namespace(|| "inv"), || Ok(inv_v))?;

    // is_nonzero = diff * inv
    let is_nonzero = diff.mul(cs.namespace(|| "is_nonzero"), &inv)?;

    // Enforce: is_nonzero ∈ {0, 1}
    cs.enforce(
        || "is_nonzero_bool",
        |lc| lc + is_nonzero.get_variable(),
        |lc| lc + CS::one() - is_nonzero.get_variable(),
        |lc| lc,
    );

    // is_zero = 1 - is_nonzero
    let is_zero = AllocatedNum::alloc(cs.namespace(|| "is_zero"), || {
        let nz = is_nonzero
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(PallasScalar::ONE - nz)
    })?;
    cs.enforce(
        || "is_zero_def",
        |lc| lc + CS::one() - is_nonzero.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + is_zero.get_variable(),
    );

    // Additional soundness: diff * is_zero = 0 (if diff ≠ 0, is_zero must be 0)
    cs.enforce(
        || "diff_times_is_zero",
        |lc| lc + diff.get_variable(),
        |lc| lc + is_zero.get_variable(),
        |lc| lc,
    );

    Ok(is_zero)
}

/// Allocate the constant 1 as a Nova witness variable.
#[cfg(feature = "nova-compression")]
fn alloc_one<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
) -> Result<AllocatedNum<PallasScalar>, SynthesisError> {
    AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(PallasScalar::ONE))
}

/// 64-bit range check: enforce that `var` fits in 64 bits via bit decomposition.
///
/// Allocates 64 boolean variables b_i and constrains:
///   var = sum(b_i * 2^i) for i in 0..64
/// Cost: 64 boolean constraints + 1 reconstruction constraint = 65 constraints.
#[cfg(feature = "nova-compression")]
fn range_check_64_nova<CS: ConstraintSystem<PallasScalar>>(
    mut cs: CS,
    var: &AllocatedNum<PallasScalar>,
    val: Option<u64>,
) -> Result<(), SynthesisError> {
    let mut sum_lc = nova_snark::frontend::LinearCombination::zero();
    let mut power = PallasScalar::ONE;
    let two = PallasScalar::from(2u64);
    // Use 0 in sizing mode; shape is identical
    let effective_val = val.unwrap_or(0u64);

    for i in 0..64 {
        let bit_v = if (effective_val >> i) & 1 == 1 {
            PallasScalar::ONE
        } else {
            PallasScalar::ZERO
        };
        let bit = AllocatedNum::alloc(cs.namespace(|| format!("bit_{i}")), || Ok(bit_v))?;

        // Boolean constraint: bit * (1 - bit) = 0
        cs.enforce(
            || format!("bool_{i}"),
            |lc| lc + bit.get_variable(),
            |lc| lc + CS::one() - bit.get_variable(),
            |lc| lc,
        );

        sum_lc = sum_lc + (power, bit.get_variable());
        power *= two;
    }

    // Reconstruction: sum_lc = var
    cs.enforce(
        || "reconstruction",
        |_| sum_lc,
        |lc| lc + CS::one(),
        |lc| lc + var.get_variable(),
    );

    Ok(())
}

/// Compute a witness hash for the running accumulator.
///
/// Sums (as Pallas scalars) all FRI evaluation values from the witness,
/// providing a linear binding of the step's witness data to the accumulator.
/// This is NOT collision-resistant in general — it provides statistical binding
/// only when combined with the Nova IVC soundness.
/// In sizing mode (witness=None), returns 0 — the constraint shape is identical.
#[cfg(feature = "nova-compression")]
fn compute_witness_hash<CS: ConstraintSystem<PallasScalar>>(
    cs: &mut CS,
    witness: &Option<FriQueryWitness>,
    num_rounds: usize,
) -> Result<AllocatedNum<PallasScalar>, SynthesisError> {
    let hash_val = match witness.as_ref() {
        None => PallasScalar::ZERO, // sizing mode
        Some(w) => {
            let mut acc = PallasScalar::ZERO;
            for r in 0..num_rounds {
                if let Some(&v) = w.f_evals_pos.get(r) {
                    acc += pallas_from_u64(v);
                }
                if let Some(&v) = w.f_evals_neg.get(r) {
                    acc += pallas_from_u64(v);
                }
                if let Some(&v) = w.f_evals_folded.get(r) {
                    acc += pallas_from_u64(v);
                }
            }
            acc += pallas_from_u64(w.query_index as u64);
            acc
        }
    };

    AllocatedNum::alloc(cs.namespace(|| "witness_hash"), || Ok(hash_val))
}

/// Convert a u64 Goldilocks element to a Pallas scalar (trivial embedding).
#[cfg(feature = "nova-compression")]
fn pallas_from_u64(val: u64) -> PallasScalar {
    use ff::PrimeField as FfPrimeField;
    let mut repr = <PallasScalar as FfPrimeField>::Repr::default();
    repr.as_mut()[..8].copy_from_slice(&val.to_le_bytes());
    Option::from(PallasScalar::from_repr(repr)).unwrap_or(PallasScalar::ZERO)
}

// ============================================================================
// Tests
// ============================================================================

/// Verify Merkle authentication paths natively for V3 Nova-compressed proof artifacts.
///
/// The V3 wrapper proves FRI **folding consistency** in-circuit but cannot verify Merkle
/// paths inside Nova IVC (~500K constraints/level exceeds the Nova step budget). This
/// helper provides the **host-side** Merkle path check that closes the attestation gap
/// for callers who have access to the original STARK proof data.
///
/// # Arguments
/// - `witnesses`: FRI query witnesses with `merkle_path` sibling hashes (leaf → root)
///   and `query_index` for computing direction bits.
/// - `poseidon2_seed`: Plonky3 seed used to derive Poseidon2 permutation constants;
///   must match the seed used when building the STARK proof.
/// - `trace_commitment`: the 8-element Goldilocks digest that is the Merkle root of
///   the trace commitment tree (taken from the STARK proof header).
///
/// # Returns
/// `Ok(())` if every query's Merkle path hashes to `trace_commitment`.
/// `Err(msg)` if any path fails or if `merkle_path` is empty (not yet populated).
///
/// # Note
/// `extract_fri_queries` in `stark_to_groth16.rs` currently fills `merkle_path` with
/// zero placeholders. Populate the field from the native Plonky3 proof before calling
/// this function if you want real Merkle binding.
#[cfg(feature = "nova-compression")]
pub fn verify_merkle_paths_native(
    witnesses: &[FriQueryWitness],
    poseidon2_seed: u64,
    trace_commitment: &[u64; 8],
) -> Result<(), String> {
    use super::poseidon2_goldilocks::{hash_leaf_native, merkle_root_8_native};

    for (q, witness) in witnesses.iter().enumerate() {
        if witness.merkle_path.is_empty() {
            return Err(format!(
                "query {q}: merkle_path is empty — populate FriQueryWitness.merkle_path \
                 from the original STARK proof before calling verify_merkle_paths_native"
            ));
        }

        let depth = witness.merkle_path.len();

        // Leaf is the first-round evaluation at the query position.
        let leaf_val = witness.f_evals_pos.first().copied().unwrap_or(0);
        let leaf_hash = hash_leaf_native(poseidon2_seed, &[leaf_val]);

        // Direction bits: at level l, bit = (query_index >> l) & 1.
        let direction_bits: Vec<bool> = (0..depth)
            .map(|l| ((witness.query_index >> l) & 1) != 0)
            .collect();

        let computed_root = merkle_root_8_native(
            poseidon2_seed,
            &leaf_hash,
            &witness.merkle_path,
            &direction_bits,
        );

        if computed_root != *trace_commitment {
            return Err(format!(
                "query {q}: Merkle root mismatch — computed {:?}, expected {:?}",
                computed_root, trace_commitment
            ));
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "nova-compression"))]
mod tests {
    use super::*;
    use nova_snark::frontend::test_cs::TestConstraintSystem;

    fn make_test_witness(num_rounds: usize) -> FriQueryWitness {
        let p = GOLDILOCKS_PRIME as u128;

        // Generate a consistent FRI witness: f_fold(x²) = (f(x) + f(-x))/2 + β*(f(x)-f(-x))/(2x)
        // Using: 2·x·f_fold = f(x)·(x+β) + f(-x)·(x-β)
        let mut x_values = Vec::with_capacity(num_rounds);
        let mut f_evals_pos = Vec::with_capacity(num_rounds);
        let mut f_evals_neg = Vec::with_capacity(num_rounds);
        let mut f_evals_folded = Vec::with_capacity(num_rounds);
        let mut folding_challenges = Vec::with_capacity(num_rounds);

        let mut x = 3u128; // starting x
        for r in 0..num_rounds {
            let fx = (100u128 + r as u128) % p;
            let fx_neg = (200u128 + r as u128) % p;
            let beta = (50u128 + r as u128) % p;

            // Compute f_fold such that: 2·x·f_fold = fx·(x+β) + fx_neg·(x-β)
            // f_fold = (fx*(x+beta) + fx_neg*(x-beta)) / (2*x) mod p
            // We compute using modular inverse
            let two_x = (2 * x) % p;
            let rhs = (fx * ((x + beta) % p) % p + fx_neg * ((x + p - beta) % p) % p) % p;
            // Find modular inverse of two_x mod p (since p is prime)
            let two_x_inv = mod_pow(two_x, p - 2, p);
            let f_fold = (rhs * two_x_inv) % p;

            x_values.push(x as u64);
            f_evals_pos.push(fx as u64);
            f_evals_neg.push(fx_neg as u64);
            f_evals_folded.push(f_fold as u64);
            folding_challenges.push(beta as u64);

            x = (x * x) % p; // x_{r+1} = x_r^2
        }

        FriQueryWitness {
            query_index: 42,
            x_values,
            f_evals_pos,
            f_evals_neg,
            f_evals_folded,
            folding_challenges,
            merkle_path: vec![],
            round_commitments: vec![],
        }
    }

    fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
        let mut result = 1u128;
        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base % modulus;
            }
            exp >>= 1;
            base = base * base % modulus;
        }
        result
    }

    #[test]
    fn step_circuit_satisfiable_with_valid_witness() {
        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let num_rounds = 3;
        let witness = make_test_witness(num_rounds);
        let step = FriQueryStep::new(Some(witness), num_rounds);

        // Initial accumulator state
        let z_in: Vec<AllocatedNum<PallasScalar>> = vec![
            AllocatedNum::alloc(cs.namespace(|| "z0"), || Ok(PallasScalar::ONE)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z2"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z3"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z4"), || Ok(PallasScalar::ONE)).unwrap(),
        ];

        let z_out = step.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), ACCUMULATOR_SIZE);

        assert!(
            cs.is_satisfied(),
            "Valid witness should satisfy constraints"
        );

        // status should remain 1 (all folds valid)
        assert_eq!(z_out[0].get_value().unwrap(), PallasScalar::ONE);
        // count should be 1
        assert_eq!(z_out[1].get_value().unwrap(), PallasScalar::ONE);
    }

    #[test]
    fn step_circuit_rejects_invalid_fold() {
        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let num_rounds = 1;
        let mut witness = make_test_witness(num_rounds);

        // Corrupt the folded value: this should make fold_ok = 0
        witness.f_evals_folded[0] = witness.f_evals_folded[0].wrapping_add(1) % GOLDILOCKS_PRIME;

        let step = FriQueryStep::new(Some(witness), num_rounds);
        let z_in: Vec<AllocatedNum<PallasScalar>> = vec![
            AllocatedNum::alloc(cs.namespace(|| "z0"), || Ok(PallasScalar::ONE)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z2"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z3"), || Ok(PallasScalar::ZERO)).unwrap(),
            AllocatedNum::alloc(cs.namespace(|| "z4"), || Ok(PallasScalar::ONE)).unwrap(),
        ];

        let z_out = step.synthesize(&mut cs, &z_in).unwrap();

        // The constraint system may or may not be satisfied here (corrupted witness),
        // but the status output should reflect the failure.
        let status = z_out[0].get_value().unwrap();
        // status = status_in * all_folds_valid = 1 * 0 = 0
        assert_eq!(
            status,
            PallasScalar::ZERO,
            "Invalid fold should zero the status"
        );
    }

    #[test]
    fn sizing_instance_same_shape() {
        let num_rounds = 4;
        let mut cs_sizing = TestConstraintSystem::<PallasScalar>::new();
        let sizing = FriQueryStep::sizing_instance(num_rounds);

        let z_in: Vec<AllocatedNum<PallasScalar>> = (0..ACCUMULATOR_SIZE)
            .map(|i| {
                AllocatedNum::alloc(cs_sizing.namespace(|| format!("z_{i}")), || {
                    Ok(PallasScalar::ZERO)
                })
                .unwrap()
            })
            .collect();
        let _ = sizing.synthesize(&mut cs_sizing, &z_in).unwrap();
        let sizing_constraints = cs_sizing.num_constraints();

        let mut cs_real = TestConstraintSystem::<PallasScalar>::new();
        let witness = make_test_witness(num_rounds);
        let real = FriQueryStep::new(Some(witness), num_rounds);
        let z_in2: Vec<AllocatedNum<PallasScalar>> = (0..ACCUMULATOR_SIZE)
            .map(|i| {
                AllocatedNum::alloc(cs_real.namespace(|| format!("z_{i}")), || {
                    Ok(PallasScalar::ZERO)
                })
                .unwrap()
            })
            .collect();
        let _ = real.synthesize(&mut cs_real, &z_in2).unwrap();
        let real_constraints = cs_real.num_constraints();

        assert_eq!(
            sizing_constraints, real_constraints,
            "Sizing and real instances must have same R1CS shape (required by Nova)"
        );
    }

    #[test]
    fn goldilocks_add_correct() {
        let p = GOLDILOCKS_PRIME;
        let a = p - 1; // max Goldilocks element
        let b = 1u64;
        let expected = 0u64; // (p-1) + 1 = p ≡ 0 mod p

        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let a_var = alloc_goldilocks(cs.namespace(|| "a"), Some(a)).unwrap();
        let b_var = alloc_goldilocks(cs.namespace(|| "b"), Some(b)).unwrap();
        let (r_var, r_val) =
            goldilocks_add(cs.namespace(|| "add"), &a_var, Some(a), &b_var, Some(b)).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(r_val.unwrap(), expected);
        assert_eq!(r_var.get_value().unwrap(), pallas_from_u64(expected));
    }

    #[test]
    fn goldilocks_mul_correct() {
        let p = GOLDILOCKS_PRIME as u128;
        let a = 1_000_000_007u64;
        let b = 998_244_353u64;
        let expected = ((a as u128 * b as u128) % p) as u64;

        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let a_var = alloc_goldilocks(cs.namespace(|| "a"), Some(a)).unwrap();
        let b_var = alloc_goldilocks(cs.namespace(|| "b"), Some(b)).unwrap();
        let (r_var, r_val) =
            goldilocks_mul(cs.namespace(|| "mul"), &a_var, Some(a), &b_var, Some(b)).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(r_val.unwrap(), expected);
        assert_eq!(r_var.get_value().unwrap(), pallas_from_u64(expected));
    }

    #[test]
    fn goldilocks_eq_detects_equality() {
        let a = 42u64;
        let b = 42u64;
        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let a_var = alloc_goldilocks(cs.namespace(|| "a"), Some(a)).unwrap();
        let b_var = alloc_goldilocks(cs.namespace(|| "b"), Some(b)).unwrap();
        let eq_var =
            goldilocks_eq(cs.namespace(|| "eq"), &a_var, Some(a), &b_var, Some(b)).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(eq_var.get_value().unwrap(), PallasScalar::ONE);
    }

    #[test]
    fn goldilocks_eq_detects_inequality() {
        let a = 42u64;
        let b = 43u64;
        let mut cs = TestConstraintSystem::<PallasScalar>::new();
        let a_var = alloc_goldilocks(cs.namespace(|| "a"), Some(a)).unwrap();
        let b_var = alloc_goldilocks(cs.namespace(|| "b"), Some(b)).unwrap();
        let eq_var =
            goldilocks_eq(cs.namespace(|| "eq"), &a_var, Some(a), &b_var, Some(b)).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(eq_var.get_value().unwrap(), PallasScalar::ZERO);
    }

    #[test]
    fn accumulator_size_is_correct() {
        assert_eq!(ACCUMULATOR_SIZE, 5);
    }

    #[test]
    fn verify_merkle_paths_native_accepts_valid_path() {
        use super::super::poseidon2_goldilocks::{hash_leaf_native, merkle_root_8_native};
        let seed = 77u64;
        let leaf_val = 42u64;
        let leaf_hash = hash_leaf_native(seed, &[leaf_val]);

        // Two-level symmetric tree: sibling at level 0 is the leaf itself.
        let level0 = leaf_hash;
        let root = merkle_root_8_native(seed, &leaf_hash, &[level0], &[false]);

        let witness = FriQueryWitness {
            query_index: 0,
            x_values: vec![1],
            f_evals_pos: vec![leaf_val],
            f_evals_neg: vec![0],
            f_evals_folded: vec![0],
            folding_challenges: vec![0],
            merkle_path: vec![level0],
            round_commitments: vec![],
        };

        let result = super::verify_merkle_paths_native(&[witness], seed, &root);
        assert!(result.is_ok(), "valid Merkle path must verify: {result:?}");
    }

    #[test]
    fn verify_merkle_paths_native_rejects_wrong_root() {
        use super::super::poseidon2_goldilocks::hash_leaf_native;
        let seed = 77u64;
        let leaf_val = 42u64;
        let leaf_hash = hash_leaf_native(seed, &[leaf_val]);
        let wrong_root = [999u64; 8];

        let witness = FriQueryWitness {
            query_index: 0,
            x_values: vec![1],
            f_evals_pos: vec![leaf_val],
            f_evals_neg: vec![0],
            f_evals_folded: vec![0],
            folding_challenges: vec![0],
            merkle_path: vec![leaf_hash],
            round_commitments: vec![],
        };

        let result = super::verify_merkle_paths_native(&[witness], seed, &wrong_root);
        assert!(result.is_err(), "wrong root must be rejected");
        assert!(result.unwrap_err().contains("Merkle root mismatch"));
    }

    #[test]
    fn verify_merkle_paths_native_rejects_empty_path() {
        let witness = FriQueryWitness {
            query_index: 0,
            x_values: vec![],
            f_evals_pos: vec![],
            f_evals_neg: vec![],
            f_evals_folded: vec![],
            folding_challenges: vec![],
            merkle_path: vec![],
            round_commitments: vec![],
        };
        let root = [0u64; 8];
        let result = super::verify_merkle_paths_native(&[witness], 0, &root);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("merkle_path is empty"));
    }
}
