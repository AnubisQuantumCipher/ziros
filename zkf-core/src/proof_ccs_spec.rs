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
use crate::field::{FieldElement, normalize as field_normalize};
use crate::normalize_mod;
use crate::proof_kernel_spec::SpecFieldValue;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::collections::BTreeMap;

type LinearExpr = BTreeMap<usize, BigInt>;

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecCcsVisibility {
    Public,
    NonPublic,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsSignal {
    pub(crate) visibility: SpecCcsVisibility,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecCcsExpr {
    Const(SpecFieldValue),
    Signal(usize),
    Add(Vec<SpecCcsExpr>),
    Sub(Box<SpecCcsExpr>, Box<SpecCcsExpr>),
    Mul(Box<SpecCcsExpr>, Box<SpecCcsExpr>),
    Div(Box<SpecCcsExpr>, Box<SpecCcsExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecCcsBlackBoxKind {
    RecursiveAggregationMarker,
    Other,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecCcsConstraint {
    Equal { lhs: SpecCcsExpr, rhs: SpecCcsExpr },
    Boolean { signal_index: usize },
    Range { signal_index: usize, bits: u32 },
    Lookup,
    BlackBox { kind: SpecCcsBlackBoxKind },
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsConstraintProgram {
    pub(crate) field: FieldId,
    pub(crate) signals: Vec<SpecCcsSignal>,
    pub(crate) constraints: Vec<SpecCcsConstraint>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsMatrixEntry {
    pub(crate) row: usize,
    pub(crate) col: usize,
    pub(crate) value: SpecFieldValue,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsMatrix {
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) entries: Vec<SpecCcsMatrixEntry>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsMultiset {
    pub(crate) matrix_indices: Vec<usize>,
    pub(crate) coefficient: SpecFieldValue,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsProgram {
    pub(crate) field: FieldId,
    pub(crate) num_constraints: usize,
    pub(crate) num_variables: usize,
    pub(crate) num_public: usize,
    pub(crate) matrices: Vec<SpecCcsMatrix>,
    pub(crate) multisets: Vec<SpecCcsMultiset>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecCcsSynthesisErrorKind {
    InvalidSignalIndex,
    LookupRequiresLowering,
    BlackBoxRequiresLowering,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsSynthesisError {
    pub(crate) constraint_index: usize,
    pub(crate) kind: SpecCcsSynthesisErrorKind,
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_value_to_bigint(value: &SpecFieldValue, field: FieldId) -> BigInt {
    field_normalize(value.to_runtime().as_bigint(), field)
}

#[cfg_attr(hax, hax_lib::include)]
fn bigint_to_spec_value(value: BigInt, field: FieldId) -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(value, field))
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecCcsBuilder {
    pub(crate) field: FieldId,
    pub(crate) signal_columns: Vec<usize>,
    pub(crate) next_col: usize,
    pub(crate) num_public: usize,
    pub(crate) row: usize,
    pub(crate) a_entries: Vec<SpecCcsMatrixEntry>,
    pub(crate) b_entries: Vec<SpecCcsMatrixEntry>,
    pub(crate) c_entries: Vec<SpecCcsMatrixEntry>,
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_new(program: &SpecCcsConstraintProgram) -> SpecCcsBuilder {
    let mut signal_columns = vec![0usize; program.signals.len()];
    let mut next_col = 1usize;
    let mut num_public = 0usize;

    for (signal_index, signal) in program.signals.iter().enumerate() {
        if signal.visibility == SpecCcsVisibility::Public {
            signal_columns[signal_index] = next_col;
            next_col += 1;
            num_public += 1;
        }
    }

    for (signal_index, signal) in program.signals.iter().enumerate() {
        if signal.visibility != SpecCcsVisibility::Public {
            signal_columns[signal_index] = next_col;
            next_col += 1;
        }
    }

    SpecCcsBuilder {
        field: program.field,
        signal_columns,
        next_col,
        num_public,
        row: 0,
        a_entries: Vec::new(),
        b_entries: Vec::new(),
        c_entries: Vec::new(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_finish(builder: SpecCcsBuilder, field: FieldId) -> SpecCcsProgram {
    let num_constraints = builder.row;
    let rows = num_constraints;
    let cols = builder.next_col;

    SpecCcsProgram {
        field,
        num_constraints,
        num_variables: cols,
        num_public: builder.num_public,
        matrices: vec![
            SpecCcsMatrix {
                rows,
                cols,
                entries: builder.a_entries,
            },
            SpecCcsMatrix {
                rows,
                cols,
                entries: builder.b_entries,
            },
            SpecCcsMatrix {
                rows,
                cols,
                entries: builder.c_entries,
            },
        ],
        multisets: vec![
            SpecCcsMultiset {
                matrix_indices: vec![0, 1],
                coefficient: bigint_to_spec_value(BigInt::one(), field),
            },
            SpecCcsMultiset {
                matrix_indices: vec![2],
                coefficient: bigint_to_spec_value(-BigInt::one(), field),
            },
        ],
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_allocate_aux(builder: &mut SpecCcsBuilder) -> usize {
    let col = builder.next_col;
    builder.next_col += 1;
    col
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_signal_lc(
    builder: &SpecCcsBuilder,
    signal_index: usize,
    constraint_index: usize,
) -> Result<LinearExpr, SpecCcsSynthesisError> {
    let Some(col) = builder.signal_columns.get(signal_index).copied() else {
        return Err(SpecCcsSynthesisError {
            constraint_index,
            kind: SpecCcsSynthesisErrorKind::InvalidSignalIndex,
        });
    };
    Ok(lc_var(col))
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_add_row(builder: &mut SpecCcsBuilder, a: LinearExpr, b: LinearExpr, c: LinearExpr) {
    let row = builder.row;
    push_lc_entries(builder.field, &mut builder.a_entries, row, &a);
    push_lc_entries(builder.field, &mut builder.b_entries, row, &b);
    push_lc_entries(builder.field, &mut builder.c_entries, row, &c);
    builder.row += 1;
}

#[cfg_attr(hax, hax_lib::include)]
fn builder_expr_to_lc(
    builder: &mut SpecCcsBuilder,
    expr: &SpecCcsExpr,
    constraint_index: usize,
) -> Result<LinearExpr, SpecCcsSynthesisError> {
    match expr {
        SpecCcsExpr::Const(value) => Ok(lc_const(spec_value_to_bigint(value, builder.field))),
        SpecCcsExpr::Signal(signal_index) => {
            builder_signal_lc(builder, *signal_index, constraint_index)
        }
        SpecCcsExpr::Add(terms) => {
            let mut acc = LinearExpr::new();
            for term in terms {
                lc_add_assign(
                    &mut acc,
                    &builder_expr_to_lc(builder, term, constraint_index)?,
                );
            }
            Ok(acc)
        }
        SpecCcsExpr::Sub(lhs, rhs) => {
            let mut acc = builder_expr_to_lc(builder, lhs, constraint_index)?;
            lc_sub_assign(
                &mut acc,
                &builder_expr_to_lc(builder, rhs, constraint_index)?,
            );
            Ok(acc)
        }
        SpecCcsExpr::Mul(lhs, rhs) => {
            let lhs_lc = builder_expr_to_lc(builder, lhs, constraint_index)?;
            let rhs_lc = builder_expr_to_lc(builder, rhs, constraint_index)?;
            let aux_col = builder_allocate_aux(builder);
            builder_add_row(builder, lhs_lc, rhs_lc, lc_var(aux_col));
            Ok(lc_var(aux_col))
        }
        SpecCcsExpr::Div(lhs, rhs) => {
            let numerator = builder_expr_to_lc(builder, lhs, constraint_index)?;
            let denominator = builder_expr_to_lc(builder, rhs, constraint_index)?;
            let quotient_col = builder_allocate_aux(builder);
            let inverse_col = builder_allocate_aux(builder);

            builder_add_row(builder, denominator.clone(), lc_var(inverse_col), lc_one());
            builder_add_row(builder, lc_var(quotient_col), denominator, numerator);

            Ok(lc_var(quotient_col))
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn encode_constraint_runtime(
    builder: &mut SpecCcsBuilder,
    constraint: &SpecCcsConstraint,
    constraint_index: usize,
) -> Result<(), SpecCcsSynthesisError> {
    match constraint {
        SpecCcsConstraint::Equal { lhs, rhs } => {
            if let SpecCcsExpr::Mul(left, right) = lhs {
                let a = builder_expr_to_lc(builder, left, constraint_index)?;
                let b = builder_expr_to_lc(builder, right, constraint_index)?;
                let c = builder_expr_to_lc(builder, rhs, constraint_index)?;
                builder_add_row(builder, a, b, c);
                return Ok(());
            }

            if let SpecCcsExpr::Mul(left, right) = rhs {
                let a = builder_expr_to_lc(builder, left, constraint_index)?;
                let b = builder_expr_to_lc(builder, right, constraint_index)?;
                let c = builder_expr_to_lc(builder, lhs, constraint_index)?;
                builder_add_row(builder, a, b, c);
                return Ok(());
            }

            let lhs_lc = builder_expr_to_lc(builder, lhs, constraint_index)?;
            let rhs_lc = builder_expr_to_lc(builder, rhs, constraint_index)?;
            let mut diff = lhs_lc;
            lc_sub_assign(&mut diff, &rhs_lc);
            builder_add_row(builder, diff, lc_one(), LinearExpr::new());
            Ok(())
        }
        SpecCcsConstraint::Boolean { signal_index } => {
            let value = builder_signal_lc(builder, *signal_index, constraint_index)?;
            let col = builder.signal_columns.get(*signal_index).copied().ok_or(
                SpecCcsSynthesisError {
                    constraint_index,
                    kind: SpecCcsSynthesisErrorKind::InvalidSignalIndex,
                },
            )?;
            builder_add_row(builder, value, lc_one_minus_var(col), LinearExpr::new());
            Ok(())
        }
        SpecCcsConstraint::Range { signal_index, bits } => {
            let signal_value = builder_signal_lc(builder, *signal_index, constraint_index)?;
            let mut recomposed = LinearExpr::new();

            for bit in 0..*bits {
                let bit_col = builder_allocate_aux(builder);
                builder_add_row(
                    builder,
                    lc_var(bit_col),
                    lc_one_minus_var(bit_col),
                    LinearExpr::new(),
                );
                lc_add_term(
                    &mut recomposed,
                    bit_col,
                    BigInt::one() << usize::try_from(bit).unwrap_or(0),
                );
            }

            builder_add_row(builder, signal_value, lc_one(), recomposed);
            Ok(())
        }
        SpecCcsConstraint::Lookup => Err(SpecCcsSynthesisError {
            constraint_index,
            kind: SpecCcsSynthesisErrorKind::LookupRequiresLowering,
        }),
        SpecCcsConstraint::BlackBox {
            kind: SpecCcsBlackBoxKind::RecursiveAggregationMarker,
        } => Ok(()),
        SpecCcsConstraint::BlackBox { .. } => Err(SpecCcsSynthesisError {
            constraint_index,
            kind: SpecCcsSynthesisErrorKind::BlackBoxRequiresLowering,
        }),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn synthesize_constraints_from(
    mut builder: SpecCcsBuilder,
    constraints: &[SpecCcsConstraint],
    constraint_index: usize,
) -> Result<SpecCcsBuilder, SpecCcsSynthesisError> {
    for (offset, constraint) in constraints.iter().enumerate() {
        let current_index = constraint_index.saturating_add(offset);
        encode_constraint_runtime(&mut builder, constraint, current_index)?;
    }

    Ok(builder)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn synthesize_ccs_program(
    program: &SpecCcsConstraintProgram,
) -> Result<SpecCcsProgram, SpecCcsSynthesisError> {
    let builder = builder_new(program);
    match synthesize_constraints_from(builder, &program.constraints, 0) {
        Ok(builder) => Ok(builder_finish(builder, program.field)),
        Err(error) => Err(error),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_const(value: BigInt) -> LinearExpr {
    let mut expr = LinearExpr::new();
    lc_add_term(&mut expr, 0, value);
    expr
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_var(col: usize) -> LinearExpr {
    let mut expr = LinearExpr::new();
    lc_add_term(&mut expr, col, BigInt::one());
    expr
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_one() -> LinearExpr {
    lc_const(BigInt::one())
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_one_minus_var(col: usize) -> LinearExpr {
    let mut expr = lc_one();
    lc_add_term(&mut expr, col, -BigInt::one());
    expr
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_add_term(target: &mut LinearExpr, col: usize, coeff: BigInt) {
    if coeff.is_zero() {
        return;
    }

    let updated = target
        .remove(&col)
        .map(|existing| existing + coeff.clone())
        .unwrap_or(coeff);

    if !updated.is_zero() {
        target.insert(col, updated);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_add_assign(target: &mut LinearExpr, other: &LinearExpr) {
    for (col, coeff) in other {
        lc_add_term(target, *col, coeff.clone());
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn lc_sub_assign(target: &mut LinearExpr, other: &LinearExpr) {
    for (col, coeff) in other {
        lc_add_term(target, *col, -coeff.clone());
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn push_lc_entries(
    field: FieldId,
    entries: &mut Vec<SpecCcsMatrixEntry>,
    row: usize,
    lc: &LinearExpr,
) {
    for (col, coeff) in lc {
        let normalized = normalize_mod(coeff.clone(), field.modulus());
        if !normalized.is_zero() {
            entries.push(SpecCcsMatrixEntry {
                row,
                col: *col,
                value: bigint_to_spec_value(normalized, field),
            });
        }
    }
}
