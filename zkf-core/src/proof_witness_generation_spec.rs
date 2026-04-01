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
    FieldElement, add as field_add, div as field_div, inv as field_inv, mul as field_mul,
    normalize as field_normalize, sub as field_sub,
};
use crate::ir::WitnessHintKind;
use crate::proof_kernel_spec::{
    self, SpecFieldValue, SpecKernelCheckError, SpecKernelConstraint, SpecKernelExpr,
    SpecKernelProgram, SpecKernelWitness,
};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::collections::BTreeMap;

type NumericWitness = BTreeMap<usize, BigInt>;
type MissingAffine = (BigInt, BigInt);
type MissingTerms = Vec<(usize, BigInt)>;
type ScaledMissingTerms = (BigInt, MissingTerms);

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecWitnessSignal {
    pub(crate) constant_value: Option<SpecFieldValue>,
    pub(crate) required: bool,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecWitnessAssignment {
    pub(crate) target_signal_index: usize,
    pub(crate) expr: SpecKernelExpr,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecWitnessHint {
    pub(crate) target_signal_index: usize,
    pub(crate) source_signal_index: usize,
    pub(crate) kind: WitnessHintKind,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecWitnessGenerationProgram {
    pub(crate) kernel_program: SpecKernelProgram,
    pub(crate) signals: Vec<SpecWitnessSignal>,
    pub(crate) assignments: Vec<SpecWitnessAssignment>,
    pub(crate) hints: Vec<SpecWitnessHint>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecWitnessGenerationError {
    MissingRequiredSignal {
        signal_index: usize,
    },
    UnsupportedWitnessSolve {
        unresolved_signal_indices: Vec<usize>,
    },
    KernelCheck(SpecKernelCheckError),
    AmbiguousLookup {
        constraint_index: usize,
        table_index: usize,
    },
}

#[cfg_attr(hax, hax_lib::opaque)]
fn spec_value_to_bigint(value: &SpecFieldValue, field: FieldId) -> BigInt {
    field_normalize(value.to_runtime().as_bigint(), field)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn bigint_to_spec_value(value: BigInt, field: FieldId) -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(value, field))
}

#[cfg_attr(hax, hax_lib::opaque)]
fn eval_expr_bigint_runtime(
    expr: &SpecKernelExpr,
    values: &NumericWitness,
    field: FieldId,
) -> Result<BigInt, SpecKernelCheckError> {
    match expr {
        SpecKernelExpr::Const(value) => Ok(spec_value_to_bigint(value, field)),
        SpecKernelExpr::Signal(signal_index) => {
            values
                .get(signal_index)
                .cloned()
                .ok_or(SpecKernelCheckError::MissingSignal {
                    signal_index: *signal_index,
                })
        }
        SpecKernelExpr::Add(lhs, rhs) => Ok(field_add(
            &eval_expr_bigint_runtime(lhs, values, field)?,
            &eval_expr_bigint_runtime(rhs, values, field)?,
            field,
        )),
        SpecKernelExpr::Sub(lhs, rhs) => Ok(field_sub(
            &eval_expr_bigint_runtime(lhs, values, field)?,
            &eval_expr_bigint_runtime(rhs, values, field)?,
            field,
        )),
        SpecKernelExpr::Mul(lhs, rhs) => Ok(field_mul(
            &eval_expr_bigint_runtime(lhs, values, field)?,
            &eval_expr_bigint_runtime(rhs, values, field)?,
            field,
        )),
        SpecKernelExpr::Div(lhs, rhs) => field_div(
            &eval_expr_bigint_runtime(lhs, values, field)?,
            &eval_expr_bigint_runtime(rhs, values, field)?,
            field,
        )
        .ok_or(SpecKernelCheckError::DivisionByZero),
    }
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_assignments_runtime(
    program: &SpecWitnessGenerationProgram,
    values: &mut [Option<SpecFieldValue>],
    numeric_values: &mut NumericWitness,
    pending_assignments: Vec<SpecWitnessAssignment>,
) -> Result<(bool, Vec<SpecWitnessAssignment>), SpecWitnessGenerationError> {
    let field = program.kernel_program.field;
    let mut progress = false;
    let mut next_assignments = Vec::new();

    for assignment in pending_assignments {
        match eval_expr_bigint_runtime(&assignment.expr, numeric_values, field) {
            Ok(value) => {
                values[assignment.target_signal_index] =
                    Some(bigint_to_spec_value(value.clone(), field));
                numeric_values.insert(assignment.target_signal_index, value);
                progress = true;
            }
            Err(SpecKernelCheckError::MissingSignal { .. }) => next_assignments.push(assignment),
            Err(error) => return Err(SpecWitnessGenerationError::KernelCheck(error)),
        }
    }

    Ok((progress, next_assignments))
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_hints_runtime(
    program: &SpecWitnessGenerationProgram,
    values: &mut [Option<SpecFieldValue>],
    numeric_values: &mut NumericWitness,
    pending_hints: Vec<SpecWitnessHint>,
) -> (bool, Vec<SpecWitnessHint>) {
    let field = program.kernel_program.field;
    let mut progress = false;
    let mut next_hints = Vec::new();

    for hint in pending_hints {
        if values
            .get(hint.target_signal_index)
            .and_then(|value| value.as_ref())
            .is_some()
        {
            continue;
        }

        if let Some(source_value) = values
            .get(hint.source_signal_index)
            .and_then(|value| value.as_ref())
            .cloned()
        {
            let source_numeric = spec_value_to_bigint(&source_value, field);
            let (derived_value, derived_numeric) = match hint.kind {
                WitnessHintKind::Copy => (source_value, source_numeric),
                WitnessHintKind::InverseOrZero => {
                    if source_numeric.is_zero() {
                        (bigint_to_spec_value(BigInt::zero(), field), BigInt::zero())
                    } else {
                        let inverse = field_inv(&source_numeric, field).unwrap_or_default();
                        (bigint_to_spec_value(inverse.clone(), field), inverse)
                    }
                }
            };
            values[hint.target_signal_index] = Some(derived_value);
            numeric_values.insert(hint.target_signal_index, derived_numeric);
            progress = true;
        } else {
            next_hints.push(hint);
        }
    }

    (progress, next_hints)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn extract_affine_form_runtime(
    expr: &SpecKernelExpr,
    target: usize,
    values: &NumericWitness,
    field: FieldId,
) -> Result<Option<MissingAffine>, SpecKernelCheckError> {
    match expr {
        SpecKernelExpr::Const(value) => {
            Ok(Some((BigInt::zero(), spec_value_to_bigint(value, field))))
        }
        SpecKernelExpr::Signal(signal_index) if *signal_index == target => {
            Ok(Some((BigInt::one(), BigInt::zero())))
        }
        SpecKernelExpr::Signal(signal_index) => Ok(values
            .get(signal_index)
            .cloned()
            .map(|value| (BigInt::zero(), field_normalize(value, field)))),
        SpecKernelExpr::Add(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) =
                extract_affine_form_runtime(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) =
                extract_affine_form_runtime(rhs, target, values, field)?
            else {
                return Ok(None);
            };
            Ok(Some((
                field_add(&lhs_coeff, &rhs_coeff, field),
                field_add(&lhs_const, &rhs_const, field),
            )))
        }
        SpecKernelExpr::Sub(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) =
                extract_affine_form_runtime(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) =
                extract_affine_form_runtime(rhs, target, values, field)?
            else {
                return Ok(None);
            };
            Ok(Some((
                field_sub(&lhs_coeff, &rhs_coeff, field),
                field_sub(&lhs_const, &rhs_const, field),
            )))
        }
        SpecKernelExpr::Mul(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) =
                extract_affine_form_runtime(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) =
                extract_affine_form_runtime(rhs, target, values, field)?
            else {
                return Ok(None);
            };

            match (lhs_coeff.is_zero(), rhs_coeff.is_zero()) {
                (true, true) => Ok(Some((
                    BigInt::zero(),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
                (false, false) => Ok(None),
                (true, false) => Ok(Some((
                    field_mul(&lhs_const, &rhs_coeff, field),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
                (false, true) => Ok(Some((
                    field_mul(&rhs_const, &lhs_coeff, field),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
            }
        }
        SpecKernelExpr::Div(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) =
                extract_affine_form_runtime(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) =
                extract_affine_form_runtime(rhs, target, values, field)?
            else {
                return Ok(None);
            };
            if !rhs_coeff.is_zero() {
                return Ok(None);
            }
            let denominator = field_normalize(rhs_const, field);
            let Some(inverse) = field_inv(&denominator, field) else {
                return Ok(None);
            };
            Ok(Some((
                field_mul(&lhs_coeff, &inverse, field),
                field_mul(&lhs_const, &inverse, field),
            )))
        }
    }
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_single_missing_equality_runtime(
    lhs: &SpecKernelExpr,
    rhs: &SpecKernelExpr,
    values: &NumericWitness,
    field: FieldId,
) -> Result<Option<(usize, BigInt)>, SpecKernelCheckError> {
    let mut missing = Vec::new();
    collect_missing_signals_runtime(lhs, values, &mut missing);
    collect_missing_signals_runtime(rhs, values, &mut missing);
    missing.sort_unstable();
    missing.dedup();

    if missing.len() != 1 {
        return Ok(None);
    }

    let signal_index = missing[0];
    let Some((lhs_coeff, lhs_const)) =
        extract_affine_form_runtime(lhs, signal_index, values, field)?
    else {
        return Ok(None);
    };
    let Some((rhs_coeff, rhs_const)) =
        extract_affine_form_runtime(rhs, signal_index, values, field)?
    else {
        return Ok(None);
    };

    let coeff = field_sub(&lhs_coeff, &rhs_coeff, field);
    if coeff.is_zero() {
        return Ok(None);
    }
    let constant = field_sub(&lhs_const, &rhs_const, field);
    let Some(inv_coeff) = field_inv(&coeff, field) else {
        return Ok(None);
    };
    let solved = field_mul(&field_normalize(-constant, field), &inv_coeff, field);
    Ok(Some((signal_index, solved)))
}

#[cfg_attr(hax, hax_lib::opaque)]
fn collect_missing_signals_runtime(
    expr: &SpecKernelExpr,
    values: &NumericWitness,
    missing: &mut Vec<usize>,
) {
    match expr {
        SpecKernelExpr::Const(_) => {}
        SpecKernelExpr::Signal(signal_index) => {
            if !values.contains_key(signal_index) {
                missing.push(*signal_index);
            }
        }
        SpecKernelExpr::Add(lhs, rhs)
        | SpecKernelExpr::Sub(lhs, rhs)
        | SpecKernelExpr::Mul(lhs, rhs)
        | SpecKernelExpr::Div(lhs, rhs) => {
            collect_missing_signals_runtime(lhs, values, missing);
            collect_missing_signals_runtime(rhs, values, missing);
        }
    }
}

#[cfg_attr(hax, hax_lib::opaque)]
fn extract_known_scalar_runtime(
    expr: &SpecKernelExpr,
    values: &NumericWitness,
    field: FieldId,
) -> Result<Option<BigInt>, SpecKernelCheckError> {
    match expr {
        SpecKernelExpr::Const(value) => Ok(Some(spec_value_to_bigint(value, field))),
        SpecKernelExpr::Signal(signal_index) => Ok(values.get(signal_index).cloned()),
        _ => Ok(None),
    }
}

#[cfg_attr(hax, hax_lib::opaque)]
fn extract_scaled_missing_terms_runtime(
    expr: &SpecKernelExpr,
    values: &NumericWitness,
    field: FieldId,
) -> Result<Option<ScaledMissingTerms>, SpecKernelCheckError> {
    match expr {
        SpecKernelExpr::Const(value) => Ok(Some((spec_value_to_bigint(value, field), Vec::new()))),
        SpecKernelExpr::Signal(signal_index) => {
            if let Some(value) = values.get(signal_index) {
                Ok(Some((value.clone(), Vec::new())))
            } else {
                Ok(Some((BigInt::zero(), vec![(*signal_index, BigInt::one())])))
            }
        }
        SpecKernelExpr::Add(lhs, rhs) => {
            let Some((lhs_known, lhs_missing)) =
                extract_scaled_missing_terms_runtime(lhs, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_known, rhs_missing)) =
                extract_scaled_missing_terms_runtime(rhs, values, field)?
            else {
                return Ok(None);
            };
            let mut missing = lhs_missing;
            missing.extend(rhs_missing);
            Ok(Some((field_add(&lhs_known, &rhs_known, field), missing)))
        }
        SpecKernelExpr::Sub(lhs, rhs) => {
            let Some((lhs_known, lhs_missing)) =
                extract_scaled_missing_terms_runtime(lhs, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_known, rhs_missing)) =
                extract_scaled_missing_terms_runtime(rhs, values, field)?
            else {
                return Ok(None);
            };
            let mut missing = lhs_missing;
            for (signal_index, coeff) in rhs_missing {
                missing.push((signal_index, -coeff));
            }
            Ok(Some((field_sub(&lhs_known, &rhs_known, field), missing)))
        }
        SpecKernelExpr::Mul(lhs, rhs) => {
            if let Some(factor) = extract_known_scalar_runtime(lhs, values, field)? {
                let Some((known, missing)) =
                    extract_scaled_missing_terms_runtime(rhs, values, field)?
                else {
                    return Ok(None);
                };
                return Ok(Some((
                    field_mul(&known, &factor, field),
                    missing
                        .into_iter()
                        .map(|(signal_index, coeff)| {
                            (signal_index, field_mul(&coeff, &factor, field))
                        })
                        .collect(),
                )));
            }
            if let Some(factor) = extract_known_scalar_runtime(rhs, values, field)? {
                let Some((known, missing)) =
                    extract_scaled_missing_terms_runtime(lhs, values, field)?
                else {
                    return Ok(None);
                };
                return Ok(Some((
                    field_mul(&known, &factor, field),
                    missing
                        .into_iter()
                        .map(|(signal_index, coeff)| {
                            (signal_index, field_mul(&coeff, &factor, field))
                        })
                        .collect(),
                )));
            }
            Ok(None)
        }
        SpecKernelExpr::Div(_, _) => Ok(None),
    }
}

#[cfg_attr(hax, hax_lib::opaque)]
fn power_of_two_exponent_runtime(value: &BigInt) -> Option<usize> {
    if value.sign() != num_bigint::Sign::Plus || value.is_zero() {
        return None;
    }

    let mut current = value.clone();
    let mut exponent = 0usize;
    while current > BigInt::one() {
        if (&current & BigInt::one()) != BigInt::zero() {
            return None;
        }
        current >>= 1usize;
        exponent += 1;
    }
    Some(exponent)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn collect_signal_range_bits_runtime(
    program: &SpecWitnessGenerationProgram,
) -> BTreeMap<usize, u32> {
    let mut ranges = BTreeMap::new();
    for constraint in &program.kernel_program.constraints {
        match constraint {
            SpecKernelConstraint::Boolean { signal, .. } => {
                ranges
                    .entry(*signal)
                    .and_modify(|bits: &mut u32| *bits = (*bits).min(1))
                    .or_insert(1);
            }
            SpecKernelConstraint::Range { signal, bits, .. } => {
                ranges
                    .entry(*signal)
                    .and_modify(|existing| *existing = (*existing).min(*bits))
                    .or_insert(*bits);
            }
            _ => {}
        }
    }
    ranges
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_radix_decomposition_side_runtime(
    target: BigInt,
    expr: &SpecKernelExpr,
    values: &NumericWitness,
    range_bits: &BTreeMap<usize, u32>,
    field: FieldId,
) -> Result<Option<Vec<(usize, BigInt)>>, SpecKernelCheckError> {
    let Some((known_sum, missing_terms)) =
        extract_scaled_missing_terms_runtime(expr, values, field)?
    else {
        return Ok(None);
    };

    if missing_terms.len() < 2 {
        return Ok(None);
    }

    let target = field_sub(&target, &known_sum, field);

    let mut decoded_terms = Vec::with_capacity(missing_terms.len());
    for (signal_index, coeff) in missing_terms {
        if values.contains_key(&signal_index) {
            continue;
        }
        let Some(bits) = range_bits.get(&signal_index).copied() else {
            return Ok(None);
        };
        let Some(offset) = power_of_two_exponent_runtime(&coeff) else {
            return Ok(None);
        };
        decoded_terms.push((signal_index, offset, bits));
    }

    if decoded_terms.len() < 2 {
        return Ok(None);
    }

    decoded_terms.sort_by_key(|(_, offset, _)| *offset);
    for pair in decoded_terms.windows(2) {
        if let [(_, lhs_offset, lhs_bits), (_, rhs_offset, _)] = pair
            && *rhs_offset < lhs_offset.saturating_add(*lhs_bits as usize)
        {
            return Ok(None);
        }
    }

    let mut assignments = Vec::with_capacity(decoded_terms.len());
    let mut recomposed = BigInt::zero();
    for (signal_index, offset, bits) in decoded_terms {
        let mask = (BigInt::one() << bits) - BigInt::one();
        let digit = (target.clone() >> offset) & mask;
        recomposed += digit.clone() << offset;
        assignments.push((signal_index, digit));
    }

    if recomposed != target {
        return Ok(None);
    }

    Ok(Some(assignments))
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_radix_decomposition_equality_runtime(
    lhs: &SpecKernelExpr,
    rhs: &SpecKernelExpr,
    values: &NumericWitness,
    range_bits: &BTreeMap<usize, u32>,
    field: FieldId,
) -> Result<Option<Vec<(usize, BigInt)>>, SpecKernelCheckError> {
    if let Ok(target) = eval_expr_bigint_runtime(lhs, values, field)
        && let Some(assignments) =
            solve_radix_decomposition_side_runtime(target, rhs, values, range_bits, field)?
    {
        return Ok(Some(assignments));
    }

    if let Ok(target) = eval_expr_bigint_runtime(rhs, values, field)
        && let Some(assignments) =
            solve_radix_decomposition_side_runtime(target, lhs, values, range_bits, field)?
    {
        return Ok(Some(assignments));
    }

    Ok(None)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_lookup_outputs_runtime(
    program: &SpecWitnessGenerationProgram,
    values: &mut [Option<SpecFieldValue>],
    numeric_values: &mut NumericWitness,
) -> Result<bool, SpecWitnessGenerationError> {
    let field = program.kernel_program.field;
    let mut progress = false;

    for constraint in &program.kernel_program.constraints {
        let SpecKernelConstraint::Lookup {
            index,
            inputs,
            table_index,
            outputs,
        } = constraint
        else {
            continue;
        };

        let Some(output_signal_indices) = outputs.as_ref() else {
            continue;
        };

        if output_signal_indices.iter().all(|signal_index| {
            values
                .get(*signal_index)
                .and_then(|value| value.as_ref())
                .is_some()
        }) {
            continue;
        }

        let evaluated_inputs = match inputs
            .iter()
            .map(|expr| eval_expr_bigint_runtime(expr, numeric_values, field))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(values) => values,
            Err(SpecKernelCheckError::MissingSignal { .. }) => continue,
            Err(error) => return Err(SpecWitnessGenerationError::KernelCheck(error)),
        };

        let Some(lookup_table) = program.kernel_program.lookup_tables.get(*table_index) else {
            return Err(SpecWitnessGenerationError::KernelCheck(
                SpecKernelCheckError::UnknownLookupTable {
                    table_index: *table_index,
                },
            ));
        };

        let mut matched_row: Option<&Vec<SpecFieldValue>> = None;
        for row in &lookup_table.rows {
            let mut inputs_match = true;
            for (column_index, input_value) in evaluated_inputs.iter().enumerate() {
                let row_value = row
                    .get(column_index)
                    .map(|value| spec_value_to_bigint(value, field))
                    .unwrap_or_else(BigInt::zero);
                if row_value != *input_value {
                    inputs_match = false;
                    break;
                }
            }
            if !inputs_match {
                continue;
            }

            if let Some(existing) = matched_row {
                let outputs_equal =
                    output_signal_indices
                        .iter()
                        .enumerate()
                        .all(|(output_index, _)| {
                            let column_index = evaluated_inputs.len() + output_index;
                            existing.get(column_index) == row.get(column_index)
                        });
                if !outputs_equal {
                    return Err(SpecWitnessGenerationError::AmbiguousLookup {
                        constraint_index: *index,
                        table_index: *table_index,
                    });
                }
                continue;
            }

            matched_row = Some(row);
        }

        let Some(row) = matched_row else {
            continue;
        };

        for (output_index, signal_index) in output_signal_indices.iter().enumerate() {
            if values
                .get(*signal_index)
                .and_then(|value| value.as_ref())
                .is_some()
            {
                continue;
            }
            let column_index = evaluated_inputs.len() + output_index;
            let Some(row_value) = row.get(column_index) else {
                continue;
            };
            values[*signal_index] = Some(row_value.clone());
            numeric_values.insert(*signal_index, spec_value_to_bigint(row_value, field));
            progress = true;
        }
    }

    Ok(progress)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_radix_decompositions_runtime(
    program: &SpecWitnessGenerationProgram,
    values: &mut [Option<SpecFieldValue>],
    numeric_values: &mut NumericWitness,
) -> Result<bool, SpecWitnessGenerationError> {
    let range_bits = collect_signal_range_bits_runtime(program);
    let field = program.kernel_program.field;
    let mut progress = false;

    for constraint in &program.kernel_program.constraints {
        let SpecKernelConstraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        let Some(assignments) = solve_radix_decomposition_equality_runtime(
            lhs,
            rhs,
            numeric_values,
            &range_bits,
            field,
        )
        .map_err(SpecWitnessGenerationError::KernelCheck)?
        else {
            continue;
        };

        for (signal_index, value) in assignments {
            if values
                .get(signal_index)
                .and_then(|item| item.as_ref())
                .is_some()
            {
                continue;
            }
            values[signal_index] = Some(bigint_to_spec_value(value.clone(), field));
            numeric_values.insert(signal_index, value);
            progress = true;
        }
    }

    Ok(progress)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn solve_single_missing_equalities_runtime(
    program: &SpecWitnessGenerationProgram,
    values: &mut [Option<SpecFieldValue>],
    numeric_values: &mut NumericWitness,
) -> Result<bool, SpecWitnessGenerationError> {
    let field = program.kernel_program.field;
    let mut progress = false;

    for constraint in &program.kernel_program.constraints {
        let SpecKernelConstraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        let Some((signal_index, value)) =
            solve_single_missing_equality_runtime(lhs, rhs, numeric_values, field)
                .map_err(SpecWitnessGenerationError::KernelCheck)?
        else {
            continue;
        };

        if values
            .get(signal_index)
            .and_then(|item| item.as_ref())
            .is_some()
        {
            continue;
        }

        values[signal_index] = Some(bigint_to_spec_value(value.clone(), field));
        numeric_values.insert(signal_index, value);
        progress = true;
    }

    Ok(progress)
}

#[cfg_attr(hax, hax_lib::opaque)]
fn generate_non_blackbox_witness_unchecked_runtime(
    program: &SpecWitnessGenerationProgram,
    inputs: &[Option<SpecFieldValue>],
) -> Result<SpecKernelWitness, SpecWitnessGenerationError> {
    let field = program.kernel_program.field;
    let mut values = program
        .signals
        .iter()
        .map(|signal| signal.constant_value.clone())
        .collect::<Vec<_>>();
    let mut numeric_values = NumericWitness::new();

    for (signal_index, maybe_value) in values.iter().enumerate() {
        if let Some(value) = maybe_value {
            numeric_values.insert(signal_index, spec_value_to_bigint(value, field));
        }
    }

    for (signal_index, maybe_input) in inputs.iter().enumerate() {
        if signal_index >= values.len() {
            break;
        }
        if let Some(value) = maybe_input {
            values[signal_index] = Some(value.clone());
            numeric_values.insert(signal_index, spec_value_to_bigint(value, field));
        }
    }

    let mut pending_assignments = program.assignments.clone();
    let mut pending_hints = program.hints.clone();

    loop {
        let mut progress = false;

        let (assignment_progress, next_assignments) = solve_assignments_runtime(
            program,
            &mut values,
            &mut numeric_values,
            pending_assignments,
        )?;
        if assignment_progress {
            progress = true;
        }
        pending_assignments = next_assignments;

        let (hint_progress, next_hints) =
            solve_hints_runtime(program, &mut values, &mut numeric_values, pending_hints);
        if hint_progress {
            progress = true;
        }
        pending_hints = next_hints;

        if solve_lookup_outputs_runtime(program, &mut values, &mut numeric_values)? {
            progress = true;
        }

        if solve_radix_decompositions_runtime(program, &mut values, &mut numeric_values)? {
            progress = true;
        }

        if solve_single_missing_equalities_runtime(program, &mut values, &mut numeric_values)? {
            progress = true;
        }

        if !progress {
            break;
        }
    }

    let unresolved_signal_indices = program
        .signals
        .iter()
        .enumerate()
        .filter(|(signal_index, signal)| {
            signal.required
                && values
                    .get(*signal_index)
                    .and_then(|value| value.as_ref())
                    .is_none()
        })
        .map(|(signal_index, _)| signal_index)
        .collect::<Vec<_>>();

    if unresolved_signal_indices.is_empty() {
        Ok(SpecKernelWitness { values })
    } else {
        Err(SpecWitnessGenerationError::UnsupportedWitnessSolve {
            unresolved_signal_indices,
        })
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn generate_non_blackbox_witness_unchecked(
    program: &SpecWitnessGenerationProgram,
    inputs: &[Option<SpecFieldValue>],
) -> Result<SpecKernelWitness, SpecWitnessGenerationError> {
    generate_non_blackbox_witness_unchecked_runtime(program, inputs)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn validate_generated_witness(
    program: &SpecWitnessGenerationProgram,
    witness: SpecKernelWitness,
) -> Result<SpecKernelWitness, SpecWitnessGenerationError> {
    match proof_kernel_spec::check_program(&program.kernel_program, &witness) {
        Ok(()) => Ok(witness),
        Err(error) => Err(SpecWitnessGenerationError::KernelCheck(error)),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn generate_non_blackbox_witness(
    program: &SpecWitnessGenerationProgram,
    inputs: &[Option<SpecFieldValue>],
) -> Result<SpecKernelWitness, SpecWitnessGenerationError> {
    match generate_non_blackbox_witness_unchecked(program, inputs) {
        Ok(witness) => validate_generated_witness(program, witness),
        Err(error) => Err(error),
    }
}
