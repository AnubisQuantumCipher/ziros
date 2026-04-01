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

#![allow(dead_code)]

use crate::FieldId;
use crate::field::{
    add as field_add, div as field_div, mul as field_mul, normalize as field_normalize,
    sub as field_sub,
};
use crate::proof_kernel::{KernelCheckError, KernelExpr, KernelWitness, kernel_signal_value};
use num_bigint::BigInt;
use num_traits::Zero;
use std::sync::atomic::{Ordering, compiler_fence};

// Production-called bridge for the recursive evaluator shell used by
// `proof_kernel::eval_expr_constant_time`. The F* proof surface below
// intentionally narrows the claim to the shipped shell's structural visit
// schedule and result-shape behavior, not to BigInt arithmetic latency.

fn combine_binary_results(
    lhs_result: Result<BigInt, KernelCheckError>,
    rhs_result: Result<BigInt, KernelCheckError>,
    op: impl FnOnce(BigInt, BigInt) -> Result<BigInt, KernelCheckError>,
) -> Result<BigInt, KernelCheckError> {
    match (lhs_result, rhs_result) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
        (Ok(lhs), Ok(rhs)) => op(lhs, rhs),
    }
}

pub(crate) fn eval_expr_constant_time_impl(
    expr: &KernelExpr,
    witness: &KernelWitness,
    field: FieldId,
) -> Result<BigInt, KernelCheckError> {
    match expr {
        KernelExpr::Const(value) => Ok(field_normalize(value.clone(), field)),
        KernelExpr::Signal(signal_index) => {
            compiler_fence(Ordering::SeqCst);
            let value = kernel_signal_value(witness, *signal_index, field);
            compiler_fence(Ordering::SeqCst);
            value
        }
        KernelExpr::Add(items) => {
            let mut acc = BigInt::zero();
            let mut first_error = None;
            for item in items {
                compiler_fence(Ordering::SeqCst);
                match eval_expr_constant_time_impl(item, witness, field) {
                    Ok(value) => {
                        compiler_fence(Ordering::SeqCst);
                        acc = field_add(&acc, &value, field);
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
                compiler_fence(Ordering::SeqCst);
            }
            first_error.map_or(Ok(acc), Err)
        }
        KernelExpr::Sub(lhs, rhs) => {
            compiler_fence(Ordering::SeqCst);
            let lhs_result = eval_expr_constant_time_impl(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time_impl(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                Ok(field_sub(&lhs, &rhs, field))
            })
        }
        KernelExpr::Mul(lhs, rhs) => {
            compiler_fence(Ordering::SeqCst);
            let lhs_result = eval_expr_constant_time_impl(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time_impl(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                Ok(field_mul(&lhs, &rhs, field))
            })
        }
        KernelExpr::Div(lhs, rhs) => {
            compiler_fence(Ordering::SeqCst);
            let lhs_result = eval_expr_constant_time_impl(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time_impl(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                field_div(&lhs, &rhs, field).ok_or(KernelCheckError::DivisionByZero)
            })
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtExpr {
    Const,
    Signal,
    Add(Box<CtExpr>, Box<CtExpr>),
    Sub(Box<CtExpr>, Box<CtExpr>),
    Mul(Box<CtExpr>, Box<CtExpr>),
    Div(Box<CtExpr>, Box<CtExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CtWitnessMask;

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CtFieldMarker {
    Primary,
    Secondary,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtTrace {
    Const,
    Signal,
    Add(Box<CtTrace>, Box<CtTrace>),
    Sub(Box<CtTrace>, Box<CtTrace>),
    Mul(Box<CtTrace>, Box<CtTrace>),
    Div(Box<CtTrace>, Box<CtTrace>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum CtEvalResult {
    Const,
    Signal,
    Add(Box<CtEvalResult>, Box<CtEvalResult>),
    Sub(Box<CtEvalResult>, Box<CtEvalResult>),
    Mul(Box<CtEvalResult>, Box<CtEvalResult>),
    Div(Box<CtEvalResult>, Box<CtEvalResult>),
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn structural_trace(expr: &CtExpr) -> CtTrace {
    match expr {
        CtExpr::Const => CtTrace::Const,
        CtExpr::Signal => CtTrace::Signal,
        CtExpr::Add(lhs, rhs) => CtTrace::Add(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Sub(lhs, rhs) => CtTrace::Sub(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Mul(lhs, rhs) => CtTrace::Mul(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
        CtExpr::Div(lhs, rhs) => CtTrace::Div(
            Box::new(structural_trace(lhs)),
            Box::new(structural_trace(rhs)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_reference_result(
    expr: &CtExpr,
    witness: &CtWitnessMask,
    field: CtFieldMarker,
) -> CtEvalResult {
    let _ = witness;
    let _ = field;
    match expr {
        CtExpr::Const => CtEvalResult::Const,
        CtExpr::Signal => CtEvalResult::Signal,
        CtExpr::Add(lhs, rhs) => CtEvalResult::Add(
            Box::new(eval_expr_reference_result(lhs, witness, field)),
            Box::new(eval_expr_reference_result(rhs, witness, field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtEvalResult::Sub(
            Box::new(eval_expr_reference_result(lhs, witness, field)),
            Box::new(eval_expr_reference_result(rhs, witness, field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtEvalResult::Mul(
            Box::new(eval_expr_reference_result(lhs, witness, field)),
            Box::new(eval_expr_reference_result(rhs, witness, field)),
        ),
        CtExpr::Div(lhs, rhs) => CtEvalResult::Div(
            Box::new(eval_expr_reference_result(lhs, witness, field)),
            Box::new(eval_expr_reference_result(rhs, witness, field)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_constant_time_trace(
    expr: &CtExpr,
    witness: &CtWitnessMask,
    field: CtFieldMarker,
) -> CtTrace {
    let _ = witness;
    let _ = field;
    match expr {
        CtExpr::Const => CtTrace::Const,
        CtExpr::Signal => CtTrace::Signal,
        CtExpr::Add(lhs, rhs) => CtTrace::Add(
            Box::new(eval_expr_constant_time_trace(lhs, witness, field)),
            Box::new(eval_expr_constant_time_trace(rhs, witness, field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtTrace::Sub(
            Box::new(eval_expr_constant_time_trace(lhs, witness, field)),
            Box::new(eval_expr_constant_time_trace(rhs, witness, field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtTrace::Mul(
            Box::new(eval_expr_constant_time_trace(lhs, witness, field)),
            Box::new(eval_expr_constant_time_trace(rhs, witness, field)),
        ),
        CtExpr::Div(lhs, rhs) => CtTrace::Div(
            Box::new(eval_expr_constant_time_trace(lhs, witness, field)),
            Box::new(eval_expr_constant_time_trace(rhs, witness, field)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr_constant_time_result(
    expr: &CtExpr,
    witness: &CtWitnessMask,
    field: CtFieldMarker,
) -> CtEvalResult {
    let _ = witness;
    let _ = field;
    match expr {
        CtExpr::Const => CtEvalResult::Const,
        CtExpr::Signal => CtEvalResult::Signal,
        CtExpr::Add(lhs, rhs) => CtEvalResult::Add(
            Box::new(eval_expr_constant_time_result(lhs, witness, field)),
            Box::new(eval_expr_constant_time_result(rhs, witness, field)),
        ),
        CtExpr::Sub(lhs, rhs) => CtEvalResult::Sub(
            Box::new(eval_expr_constant_time_result(lhs, witness, field)),
            Box::new(eval_expr_constant_time_result(rhs, witness, field)),
        ),
        CtExpr::Mul(lhs, rhs) => CtEvalResult::Mul(
            Box::new(eval_expr_constant_time_result(lhs, witness, field)),
            Box::new(eval_expr_constant_time_result(rhs, witness, field)),
        ),
        CtExpr::Div(lhs, rhs) => CtEvalResult::Div(
            Box::new(eval_expr_constant_time_result(lhs, witness, field)),
            Box::new(eval_expr_constant_time_result(rhs, witness, field)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_kernel::{KernelExpr, KernelWitness};

    fn sample_ct_expr() -> CtExpr {
        CtExpr::Div(
            Box::new(CtExpr::Add(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Const),
            )),
            Box::new(CtExpr::Mul(
                Box::new(CtExpr::Signal),
                Box::new(CtExpr::Sub(
                    Box::new(CtExpr::Const),
                    Box::new(CtExpr::Signal),
                )),
            )),
        )
    }

    fn sample_kernel_expr() -> KernelExpr {
        KernelExpr::Div(
            Box::new(KernelExpr::Add(vec![
                KernelExpr::Signal(0),
                KernelExpr::Const(BigInt::from(2u8)),
            ])),
            Box::new(KernelExpr::Mul(
                Box::new(KernelExpr::Signal(1)),
                Box::new(KernelExpr::Sub(
                    Box::new(KernelExpr::Const(BigInt::from(9u8))),
                    Box::new(KernelExpr::Signal(2)),
                )),
            )),
        )
    }

    #[test]
    fn structural_trace_matches_constant_time_trace() {
        let expr = sample_ct_expr();
        let witness = CtWitnessMask;
        assert_eq!(
            eval_expr_constant_time_trace(&expr, &witness, CtFieldMarker::Primary),
            structural_trace(&expr)
        );
    }

    #[test]
    fn reference_result_matches_constant_time_result() {
        let expr = sample_ct_expr();
        let witness = CtWitnessMask;
        assert_eq!(
            eval_expr_constant_time_result(&expr, &witness, CtFieldMarker::Secondary),
            eval_expr_reference_result(&expr, &witness, CtFieldMarker::Secondary)
        );
    }

    #[test]
    fn eval_expr_entrypoint_routes_through_constant_time_bridge() {
        let expr = sample_kernel_expr();
        let witness = KernelWitness {
            values: vec![
                Some(BigInt::from(5u8)),
                Some(BigInt::from(3u8)),
                Some(BigInt::from(1u8)),
            ],
        };
        let bridged =
            eval_expr_constant_time_impl(&expr, &witness, FieldId::Bn254).expect("bridge eval");
        let entry =
            crate::proof_kernel::eval_expr(&expr, &witness, FieldId::Bn254).expect("entry eval");
        assert_eq!(bridged, entry);
    }

    #[test]
    fn eval_expr_bridge_preserves_first_error() {
        let expr = KernelExpr::Add(vec![KernelExpr::Signal(0), KernelExpr::Signal(2)]);
        let witness = KernelWitness {
            values: vec![Some(BigInt::from(5u8)), Some(BigInt::from(7u8))],
        };
        let err =
            eval_expr_constant_time_impl(&expr, &witness, FieldId::Bn254).expect_err("missing");
        assert_eq!(err, KernelCheckError::MissingSignal { signal_index: 2 });
    }
}
