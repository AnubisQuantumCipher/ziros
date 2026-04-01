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

/// AIR constraint evaluation in R1CS.
///
/// Evaluates `AirExpr` trees as Goldilocks R1CS constraints, matching
/// `eval_air_expr_concrete` from plonky3.rs. Then folds all constraints
/// using Horner's method (matching `VerifierConstraintFolder`'s `assert_zero`)
/// and checks the quotient polynomial identity.
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::nonnative_goldilocks::GoldilocksVar;
use crate::plonky3::AirExpr;

/// Evaluate an AirExpr tree as a Goldilocks R1CS expression.
///
/// This is the in-circuit equivalent of `eval_air_expr_concrete`:
/// - `Const(v)` → constant GoldilocksVar
/// - `Signal(i)` → `trace_local[i]`
/// - `Add/Sub/Mul` → corresponding GoldilocksVar arithmetic
pub fn eval_air_expr_circuit(
    cs: ConstraintSystemRef<Fr>,
    expr: &AirExpr,
    trace_local: &[GoldilocksVar],
) -> Result<GoldilocksVar, SynthesisError> {
    match expr {
        AirExpr::Const(v) => GoldilocksVar::constant(cs, *v),
        AirExpr::Signal(i) => Ok(trace_local[*i].clone()),
        AirExpr::Add(values) => {
            let mut acc = GoldilocksVar::constant(cs.clone(), 0)?;
            for value in values {
                let v = eval_air_expr_circuit(cs.clone(), value, trace_local)?;
                acc = acc.add(cs.clone(), &v)?;
            }
            Ok(acc)
        }
        AirExpr::Sub(left, right) => {
            let l = eval_air_expr_circuit(cs.clone(), left, trace_local)?;
            let r = eval_air_expr_circuit(cs.clone(), right, trace_local)?;
            l.sub(cs, &r)
        }
        AirExpr::Mul(left, right) => {
            let l = eval_air_expr_circuit(cs.clone(), left, trace_local)?;
            let r = eval_air_expr_circuit(cs.clone(), right, trace_local)?;
            l.mul(cs, &r)
        }
    }
}

/// Compute the folded AIR constraint accumulator in R1CS.
///
/// Matches Plonky3's `VerifierConstraintFolder::assert_zero` which uses
/// Horner's method:
/// ```text
/// acc = 0
/// for each constraint c_i:
///     value = is_first_row * eval_air_expr(c_i, trace_local)
///     acc = acc * alpha + value
/// ```
///
/// Also handles public input equality constraints:
/// ```text
/// for (pi_idx, signal_idx) in public_signal_indices:
///     value = is_first_row * (trace_local[signal_idx] - public_values[pi_idx])
///     acc = acc * alpha + value
/// ```
///
/// Returns the folded accumulator.
pub fn verify_air_constraints_circuit(
    cs: ConstraintSystemRef<Fr>,
    constraints: &[AirExpr],
    public_signal_indices: &[usize],
    trace_local: &[GoldilocksVar],
    public_values: &[GoldilocksVar],
    alpha: &GoldilocksVar,
    is_first_row: &GoldilocksVar,
) -> Result<GoldilocksVar, SynthesisError> {
    let mut acc = GoldilocksVar::constant(cs.clone(), 0)?;

    // Public input equality constraints come first in the Plonky3 folder
    // (they are added first in Air::eval)
    for (pi_idx, &signal_idx) in public_signal_indices.iter().enumerate() {
        let diff = trace_local[signal_idx].sub(cs.clone(), &public_values[pi_idx])?;
        let value = is_first_row.mul(cs.clone(), &diff)?;
        acc = acc.mul(cs.clone(), alpha)?;
        acc = acc.add(cs.clone(), &value)?;
    }

    // Main constraints
    for constraint in constraints {
        let raw = eval_air_expr_circuit(cs.clone(), constraint, trace_local)?;
        let value = is_first_row.mul(cs.clone(), &raw)?;
        acc = acc.mul(cs.clone(), alpha)?;
        acc = acc.add(cs.clone(), &value)?;
    }

    Ok(acc)
}

/// Recompose the quotient polynomial from chunks using powers of zeta.
///
/// ```text
/// quotient(zeta) = sum_i( chunk_i * (zeta^degree)^i )
/// ```
///
/// Uses Horner's method for efficient evaluation:
/// ```text
/// result = chunks[n-1]
/// for i in (0..n-1).rev():
///     result = result * zeta_pow + chunks[i]
/// ```
///
/// `degree_bits` is log2 of the trace domain size; `zeta_pow = zeta^(2^degree_bits)`
/// is computed via repeated squaring.
pub fn recompose_quotient_circuit(
    cs: ConstraintSystemRef<Fr>,
    quotient_chunks: &[GoldilocksVar],
    zeta: &GoldilocksVar,
    degree_bits: usize,
) -> Result<GoldilocksVar, SynthesisError> {
    if quotient_chunks.is_empty() {
        return GoldilocksVar::constant(cs, 0);
    }
    if quotient_chunks.len() == 1 {
        return Ok(quotient_chunks[0].clone());
    }

    // Compute zeta^(2^degree_bits) via repeated squaring
    let mut zeta_pow = zeta.clone();
    for _ in 0..degree_bits {
        zeta_pow = zeta_pow.mul(cs.clone(), &zeta_pow)?;
    }

    // Horner's method: fold from the last chunk backwards
    let mut acc = quotient_chunks.last().unwrap().clone();
    for i in (0..quotient_chunks.len() - 1).rev() {
        acc = acc.mul(cs.clone(), &zeta_pow)?;
        acc = acc.add(cs.clone(), &quotient_chunks[i])?;
    }

    Ok(acc)
}

/// Verify the quotient polynomial identity:
///   folded_constraints == quotient * vanishing
///
/// Equivalently (using precomputed inverse):
///   folded_constraints * inv_vanishing == quotient
pub fn verify_quotient_identity(
    cs: ConstraintSystemRef<Fr>,
    folded_constraints: &GoldilocksVar,
    quotient: &GoldilocksVar,
    inv_vanishing: &GoldilocksVar,
) -> Result<(), SynthesisError> {
    let lhs = folded_constraints.mul(cs.clone(), inv_vanishing)?;
    lhs.assert_equal(cs, quotient)
}

#[cfg(test)]
mod tests {
    use super::super::nonnative_goldilocks::GOLDILOCKS_PRIME;
    use super::*;
    use crate::plonky3::eval_air_expr_concrete;
    use ark_relations::r1cs::ConstraintSystem;

    fn fresh_cs() -> ConstraintSystemRef<Fr> {
        ConstraintSystem::<Fr>::new_ref()
    }

    #[test]
    fn eval_const_matches_concrete() {
        let cs = fresh_cs();
        let expr = AirExpr::Const(42);
        let result = eval_air_expr_circuit(cs.clone(), &expr, &[]).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[], GOLDILOCKS_PRIME);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn eval_signal_matches_concrete() {
        let cs = fresh_cs();
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(100)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(200)).unwrap(),
        ];
        let expr = AirExpr::Signal(1);
        let result = eval_air_expr_circuit(cs.clone(), &expr, &trace).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[100, 200], GOLDILOCKS_PRIME);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn eval_add_matches_concrete() {
        let cs = fresh_cs();
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(10)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(20)).unwrap(),
        ];
        let expr = AirExpr::Add(vec![
            AirExpr::Signal(0),
            AirExpr::Signal(1),
            AirExpr::Const(5),
        ]);
        let result = eval_air_expr_circuit(cs.clone(), &expr, &trace).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[10, 20], GOLDILOCKS_PRIME);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn eval_sub_matches_concrete() {
        let cs = fresh_cs();
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(100)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(30)).unwrap(),
        ];
        let expr = AirExpr::Sub(Box::new(AirExpr::Signal(0)), Box::new(AirExpr::Signal(1)));
        let result = eval_air_expr_circuit(cs.clone(), &expr, &trace).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[100, 30], GOLDILOCKS_PRIME);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn eval_mul_matches_concrete() {
        let cs = fresh_cs();
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(7)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(13)).unwrap(),
        ];
        let expr = AirExpr::Mul(Box::new(AirExpr::Signal(0)), Box::new(AirExpr::Signal(1)));
        let result = eval_air_expr_circuit(cs.clone(), &expr, &trace).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[7, 13], GOLDILOCKS_PRIME);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn eval_nested_expr_matches_concrete() {
        let cs = fresh_cs();
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(5)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(3)).unwrap(),
        ];
        // (signal[0] * signal[1]) + const(10) - signal[0]
        let expr = AirExpr::Sub(
            Box::new(AirExpr::Add(vec![
                AirExpr::Mul(Box::new(AirExpr::Signal(0)), Box::new(AirExpr::Signal(1))),
                AirExpr::Const(10),
            ])),
            Box::new(AirExpr::Signal(0)),
        );
        let result = eval_air_expr_circuit(cs.clone(), &expr, &trace).unwrap();
        let expected = eval_air_expr_concrete(&expr, &[5, 3], GOLDILOCKS_PRIME);
        // (5 * 3) + 10 - 5 = 15 + 10 - 5 = 20
        assert_eq!(result.value().unwrap(), 20);
        assert_eq!(result.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn folded_constraints_satisfied_constraint() {
        let cs = fresh_cs();

        // Simple program: signal[0] == signal[1] (constraint: signal[0] - signal[1] = 0)
        let trace = vec![
            GoldilocksVar::alloc_witness(cs.clone(), Some(42)).unwrap(),
            GoldilocksVar::alloc_witness(cs.clone(), Some(42)).unwrap(),
        ];
        let constraints = vec![AirExpr::Sub(
            Box::new(AirExpr::Signal(0)),
            Box::new(AirExpr::Signal(1)),
        )];
        let public_signal_indices: Vec<usize> = vec![];
        let public_values: Vec<GoldilocksVar> = vec![];
        let alpha = GoldilocksVar::alloc_witness(cs.clone(), Some(7)).unwrap();
        let is_first_row = GoldilocksVar::alloc_witness(cs.clone(), Some(1)).unwrap();

        let acc = verify_air_constraints_circuit(
            cs.clone(),
            &constraints,
            &public_signal_indices,
            &trace,
            &public_values,
            &alpha,
            &is_first_row,
        )
        .unwrap();

        // When constraint is satisfied (42 - 42 = 0), folded accumulator should be 0
        assert_eq!(acc.value().unwrap(), 0);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn quotient_identity_holds() {
        let cs = fresh_cs();

        // folded_constraints = 0, quotient = 0, inv_vanishing = anything
        let folded = GoldilocksVar::alloc_witness(cs.clone(), Some(0)).unwrap();
        let quotient = GoldilocksVar::alloc_witness(cs.clone(), Some(0)).unwrap();
        let inv_van = GoldilocksVar::alloc_witness(cs.clone(), Some(12345)).unwrap();

        verify_quotient_identity(cs.clone(), &folded, &quotient, &inv_van).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn quotient_identity_nonzero() {
        let cs = fresh_cs();

        // folded = 15, inv_vanishing = 3, quotient = 15 * 3 mod p = 45
        let folded = GoldilocksVar::alloc_witness(cs.clone(), Some(15)).unwrap();
        let inv_van = GoldilocksVar::alloc_witness(cs.clone(), Some(3)).unwrap();
        let quotient = GoldilocksVar::alloc_witness(cs.clone(), Some(45)).unwrap();

        verify_quotient_identity(cs.clone(), &folded, &quotient, &inv_van).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
