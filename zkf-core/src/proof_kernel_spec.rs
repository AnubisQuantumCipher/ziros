#![allow(dead_code)]

use crate::field::FieldElement;
use crate::{FieldId, mod_inverse_bigint, normalize_mod};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecFieldValue {
    bytes: [u8; 32],
    len: u8,
    negative: bool,
}

impl SpecFieldValue {
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn from_runtime(value: &FieldElement) -> Self {
        let bigint = value.as_bigint();
        let negative = bigint.sign() == Sign::Minus;
        let (_, magnitude_bytes) = bigint.to_bytes_le();
        let mut bytes = [0u8; 32];
        let copy_len = magnitude_bytes.len().min(32);
        bytes[..copy_len].copy_from_slice(&magnitude_bytes[..copy_len]);
        Self {
            bytes,
            len: copy_len as u8,
            negative,
        }
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn to_runtime(&self) -> FieldElement {
        let sign = if self.negative {
            Sign::Minus
        } else {
            Sign::Plus
        };
        FieldElement::from_bigint(BigInt::from_bytes_le(
            sign,
            &self.bytes[..self.len as usize],
        ))
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    fn as_bigint(&self) -> BigInt {
        self.to_runtime().as_bigint()
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_field_value_raw_bigint(value: &SpecFieldValue) -> BigInt {
    value.as_bigint()
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_field_value_from_bigint_with_field(
    value: BigInt,
    field: FieldId,
) -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(value, field))
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_field_value_zero() -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_i64(0))
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_field_value_is_zero_raw(value: &SpecFieldValue) -> bool {
    spec_field_value_raw_bigint(value).is_zero()
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_field_value_is_one_raw(value: &SpecFieldValue) -> bool {
    spec_field_value_raw_bigint(value).is_one()
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_normalize_mod_bigint(value: BigInt, modulus: &BigInt) -> BigInt {
    normalize_mod(value, modulus)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn spec_mod_inverse_bigint(value: BigInt, modulus: &BigInt) -> Option<BigInt> {
    mod_inverse_bigint(value, modulus)
}

pub(crate) mod spec_field_ops {
    use super::{FieldElement, FieldId, SpecFieldValue};
    use crate::field;

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn zero() -> SpecFieldValue {
        SpecFieldValue::from_runtime(&FieldElement::ZERO)
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn normalize(value: &SpecFieldValue, field: FieldId) -> SpecFieldValue {
        SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(
            value.as_bigint(),
            field,
        ))
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn add(
        lhs: &SpecFieldValue,
        rhs: &SpecFieldValue,
        field: FieldId,
    ) -> SpecFieldValue {
        SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(
            field::add(&lhs.as_bigint(), &rhs.as_bigint(), field),
            field,
        ))
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn sub(
        lhs: &SpecFieldValue,
        rhs: &SpecFieldValue,
        field: FieldId,
    ) -> SpecFieldValue {
        SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(
            field::sub(&lhs.as_bigint(), &rhs.as_bigint(), field),
            field,
        ))
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn mul(
        lhs: &SpecFieldValue,
        rhs: &SpecFieldValue,
        field: FieldId,
    ) -> SpecFieldValue {
        SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(
            field::mul(&lhs.as_bigint(), &rhs.as_bigint(), field),
            field,
        ))
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn div(
        lhs: &SpecFieldValue,
        rhs: &SpecFieldValue,
        field: FieldId,
    ) -> Option<SpecFieldValue> {
        field::div(&lhs.as_bigint(), &rhs.as_bigint(), field).map(|value| {
            SpecFieldValue::from_runtime(&FieldElement::from_bigint_with_field(value, field))
        })
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn eq(lhs: &SpecFieldValue, rhs: &SpecFieldValue, field: FieldId) -> bool {
        field::equal(&lhs.as_bigint(), &rhs.as_bigint(), field)
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn is_boolean(value: &SpecFieldValue, field: FieldId) -> bool {
        field::is_boolean(&value.as_bigint(), field)
    }

    #[cfg_attr(hax, hax_lib::include)]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn fits_bits(value: &SpecFieldValue, bits: u32, field: FieldId) -> bool {
        field::fits_in_bits(&value.as_bigint(), bits, field)
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecKernelExpr {
    Const(SpecFieldValue),
    Signal(usize),
    Add(Box<SpecKernelExpr>, Box<SpecKernelExpr>),
    Sub(Box<SpecKernelExpr>, Box<SpecKernelExpr>),
    Mul(Box<SpecKernelExpr>, Box<SpecKernelExpr>),
    Div(Box<SpecKernelExpr>, Box<SpecKernelExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecKernelConstraint {
    Equal {
        index: usize,
        lhs: SpecKernelExpr,
        rhs: SpecKernelExpr,
    },
    Boolean {
        index: usize,
        signal: usize,
    },
    Range {
        index: usize,
        signal: usize,
        bits: u32,
    },
    Lookup {
        index: usize,
        inputs: Vec<SpecKernelExpr>,
        table_index: usize,
        outputs: Option<Vec<usize>>,
    },
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecKernelLookupTable {
    pub(crate) column_count: usize,
    pub(crate) rows: Vec<Vec<SpecFieldValue>>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecKernelProgram {
    pub(crate) field: FieldId,
    pub(crate) constraints: Vec<SpecKernelConstraint>,
    pub(crate) lookup_tables: Vec<SpecKernelLookupTable>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecKernelWitness {
    pub(crate) values: Vec<Option<SpecFieldValue>>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecLookupFailureKind {
    InputArityMismatch { provided: usize, available: usize },
    NoMatchingRow,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecKernelCheckError {
    MissingSignal {
        signal_index: usize,
    },
    DivisionByZero,
    UnknownLookupTable {
        table_index: usize,
    },
    EqualViolation {
        constraint_index: usize,
        lhs: SpecFieldValue,
        rhs: SpecFieldValue,
    },
    BooleanViolation {
        constraint_index: usize,
        signal_index: usize,
        value: SpecFieldValue,
    },
    RangeViolation {
        constraint_index: usize,
        signal_index: usize,
        bits: u32,
        value: SpecFieldValue,
    },
    LookupViolation {
        constraint_index: usize,
        table_index: usize,
        inputs: Vec<SpecFieldValue>,
        outputs: Option<Vec<SpecFieldValue>>,
        kind: SpecLookupFailureKind,
    },
}

#[cfg_attr(hax, hax_lib::include)]
fn kernel_signal_value(
    witness: &SpecKernelWitness,
    signal_index: usize,
    field: FieldId,
) -> Result<SpecFieldValue, SpecKernelCheckError> {
    match witness.values.get(signal_index) {
        Some(Some(value)) => Ok(spec_field_ops::normalize(value, field)),
        _ => Err(SpecKernelCheckError::MissingSignal { signal_index }),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn render_lookup_outputs_from(
    signal_indices: &[usize],
    current_column: usize,
    lookup_table: &SpecKernelLookupTable,
    witness: &SpecKernelWitness,
    field: FieldId,
    mut acc: Vec<SpecFieldValue>,
) -> Result<Vec<SpecFieldValue>, SpecKernelCheckError> {
    match signal_indices.split_first() {
        Some((signal_index, remaining_signal_indices)) => {
            if current_column < lookup_table.column_count {
                match kernel_signal_value(witness, *signal_index, field) {
                    Ok(value) => {
                        acc.push(value);
                        render_lookup_outputs_from(
                            remaining_signal_indices,
                            current_column + 1,
                            lookup_table,
                            witness,
                            field,
                            acc,
                        )
                    }
                    Err(error) => Err(error),
                }
            } else {
                render_lookup_outputs_from(
                    remaining_signal_indices,
                    current_column + 1,
                    lookup_table,
                    witness,
                    field,
                    acc,
                )
            }
        }
        None => Ok(acc),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn render_lookup_outputs(
    signal_indices: &[usize],
    input_len: usize,
    lookup_table: &SpecKernelLookupTable,
    witness: &SpecKernelWitness,
    field: FieldId,
) -> Result<Vec<SpecFieldValue>, SpecKernelCheckError> {
    render_lookup_outputs_from(
        signal_indices,
        input_len,
        lookup_table,
        witness,
        field,
        Vec::new(),
    )
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_evaluated_inputs_from(
    inputs: &[SpecKernelExpr],
    witness: &SpecKernelWitness,
    field: FieldId,
    mut acc: Vec<SpecFieldValue>,
) -> Result<Vec<SpecFieldValue>, SpecKernelCheckError> {
    match inputs.split_first() {
        Some((input, remaining_inputs)) => match eval_expr(input, witness, field) {
            Ok(value) => {
                acc.push(value);
                collect_evaluated_inputs_from(remaining_inputs, witness, field, acc)
            }
            Err(error) => Err(error),
        },
        None => Ok(acc),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_evaluated_inputs(
    inputs: &[SpecKernelExpr],
    witness: &SpecKernelWitness,
    field: FieldId,
) -> Result<Vec<SpecFieldValue>, SpecKernelCheckError> {
    collect_evaluated_inputs_from(inputs, witness, field, Vec::new())
}

#[cfg_attr(hax, hax_lib::include)]
fn row_matches_inputs_from(
    row: &[SpecFieldValue],
    evaluated_inputs: &[SpecFieldValue],
    field: FieldId,
) -> bool {
    match evaluated_inputs.split_first() {
        Some((input_value, remaining_inputs)) => {
            let (row_value, remaining_row) = match row.split_first() {
                Some((value, remaining_row)) => (value.clone(), remaining_row),
                None => (spec_field_ops::zero(), row),
            };
            spec_field_ops::eq(&row_value, input_value, field)
                && row_matches_inputs_from(remaining_row, remaining_inputs, field)
        }
        None => true,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn row_matches_inputs(
    row: &[SpecFieldValue],
    evaluated_inputs: &[SpecFieldValue],
    field: FieldId,
) -> bool {
    row_matches_inputs_from(row, evaluated_inputs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn skip_row_prefix(row: &[SpecFieldValue], remaining_to_skip: usize) -> &[SpecFieldValue] {
    if remaining_to_skip == 0 {
        row
    } else {
        match row.split_first() {
            Some((_value, remaining_row)) => skip_row_prefix(remaining_row, remaining_to_skip - 1),
            None => row,
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn row_matches_outputs_from(
    row: &[SpecFieldValue],
    expected_outputs: &[SpecFieldValue],
    field: FieldId,
) -> bool {
    match expected_outputs.split_first() {
        Some((output_value, remaining_outputs)) => {
            let (row_value, remaining_row) = match row.split_first() {
                Some((value, remaining_row)) => (value.clone(), remaining_row),
                None => (spec_field_ops::zero(), row),
            };
            spec_field_ops::eq(&row_value, output_value, field)
                && row_matches_outputs_from(remaining_row, remaining_outputs, field)
        }
        None => true,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn row_matches_outputs(
    row: &[SpecFieldValue],
    input_len: usize,
    expected_outputs: &[SpecFieldValue],
    field: FieldId,
) -> bool {
    row_matches_outputs_from(skip_row_prefix(row, input_len), expected_outputs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn lookup_has_matching_row_from(
    rows: &[Vec<SpecFieldValue>],
    evaluated_inputs: &[SpecFieldValue],
    expected_outputs: &Option<Vec<SpecFieldValue>>,
    input_len: usize,
    field: FieldId,
) -> bool {
    match rows.split_first() {
        Some((row, remaining_rows)) => {
            let row_matches = if row_matches_inputs(row, evaluated_inputs, field) {
                match expected_outputs {
                    Some(outputs) => row_matches_outputs(row, input_len, outputs, field),
                    None => true,
                }
            } else {
                false
            };

            row_matches
                || lookup_has_matching_row_from(
                    remaining_rows,
                    evaluated_inputs,
                    expected_outputs,
                    input_len,
                    field,
                )
        }
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn eval_expr(
    expr: &SpecKernelExpr,
    witness: &SpecKernelWitness,
    field: FieldId,
) -> Result<SpecFieldValue, SpecKernelCheckError> {
    match expr {
        SpecKernelExpr::Const(value) => Ok(spec_field_ops::normalize(value, field)),
        SpecKernelExpr::Signal(signal_index) => kernel_signal_value(witness, *signal_index, field),
        SpecKernelExpr::Add(lhs, rhs) => match eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match eval_expr(rhs, witness, field) {
                Ok(rhs_value) => Ok(spec_field_ops::add(&lhs_value, &rhs_value, field)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        SpecKernelExpr::Sub(lhs, rhs) => match eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match eval_expr(rhs, witness, field) {
                Ok(rhs_value) => Ok(spec_field_ops::sub(&lhs_value, &rhs_value, field)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        SpecKernelExpr::Mul(lhs, rhs) => match eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match eval_expr(rhs, witness, field) {
                Ok(rhs_value) => Ok(spec_field_ops::mul(&lhs_value, &rhs_value, field)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        SpecKernelExpr::Div(lhs, rhs) => match eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match eval_expr(rhs, witness, field) {
                Ok(rhs_value) => match spec_field_ops::div(&lhs_value, &rhs_value, field) {
                    Some(value) => Ok(value),
                    None => Err(SpecKernelCheckError::DivisionByZero),
                },
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn check_constraints_from(
    constraints: &[SpecKernelConstraint],
    program: &SpecKernelProgram,
    witness: &SpecKernelWitness,
) -> Result<(), SpecKernelCheckError> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => match constraint {
            SpecKernelConstraint::Equal { index, lhs, rhs } => {
                match eval_expr(lhs, witness, program.field) {
                    Ok(lhs_value) => match eval_expr(rhs, witness, program.field) {
                        Ok(rhs_value) => {
                            if spec_field_ops::eq(&lhs_value, &rhs_value, program.field) {
                                check_constraints_from(remaining_constraints, program, witness)
                            } else {
                                Err(SpecKernelCheckError::EqualViolation {
                                    constraint_index: *index,
                                    lhs: lhs_value,
                                    rhs: rhs_value,
                                })
                            }
                        }
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            }
            SpecKernelConstraint::Boolean { index, signal } => {
                match kernel_signal_value(witness, *signal, program.field) {
                    Ok(value) => {
                        if spec_field_ops::is_boolean(&value, program.field) {
                            check_constraints_from(remaining_constraints, program, witness)
                        } else {
                            Err(SpecKernelCheckError::BooleanViolation {
                                constraint_index: *index,
                                signal_index: *signal,
                                value,
                            })
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            SpecKernelConstraint::Range {
                index,
                signal,
                bits,
            } => match kernel_signal_value(witness, *signal, program.field) {
                Ok(value) => {
                    if spec_field_ops::fits_bits(&value, *bits, program.field) {
                        check_constraints_from(remaining_constraints, program, witness)
                    } else {
                        Err(SpecKernelCheckError::RangeViolation {
                            constraint_index: *index,
                            signal_index: *signal,
                            bits: *bits,
                            value,
                        })
                    }
                }
                Err(error) => Err(error),
            },
            SpecKernelConstraint::Lookup {
                index,
                inputs,
                table_index,
                outputs,
            } => match program.lookup_tables.get(*table_index) {
                Some(lookup_table) => {
                    if inputs.len() > lookup_table.column_count {
                        match collect_evaluated_inputs(inputs, witness, program.field) {
                            Ok(rendered_inputs) => match outputs {
                                Some(signal_indices) => match render_lookup_outputs(
                                    signal_indices,
                                    inputs.len(),
                                    lookup_table,
                                    witness,
                                    program.field,
                                ) {
                                    Ok(values) => Err(SpecKernelCheckError::LookupViolation {
                                        constraint_index: *index,
                                        table_index: *table_index,
                                        inputs: rendered_inputs,
                                        outputs: Some(values),
                                        kind: SpecLookupFailureKind::InputArityMismatch {
                                            provided: inputs.len(),
                                            available: lookup_table.column_count,
                                        },
                                    }),
                                    Err(error) => Err(error),
                                },
                                None => Err(SpecKernelCheckError::LookupViolation {
                                    constraint_index: *index,
                                    table_index: *table_index,
                                    inputs: rendered_inputs,
                                    outputs: None,
                                    kind: SpecLookupFailureKind::InputArityMismatch {
                                        provided: inputs.len(),
                                        available: lookup_table.column_count,
                                    },
                                }),
                            },
                            Err(error) => Err(error),
                        }
                    } else {
                        match collect_evaluated_inputs(inputs, witness, program.field) {
                            Ok(evaluated_inputs) => match outputs {
                                Some(signal_indices) => match render_lookup_outputs(
                                    signal_indices,
                                    inputs.len(),
                                    lookup_table,
                                    witness,
                                    program.field,
                                ) {
                                    Ok(values) => {
                                        let expected_outputs = Some(values);
                                        if lookup_has_matching_row_from(
                                            &lookup_table.rows,
                                            &evaluated_inputs,
                                            &expected_outputs,
                                            inputs.len(),
                                            program.field,
                                        ) {
                                            check_constraints_from(
                                                remaining_constraints,
                                                program,
                                                witness,
                                            )
                                        } else {
                                            Err(SpecKernelCheckError::LookupViolation {
                                                constraint_index: *index,
                                                table_index: *table_index,
                                                inputs: evaluated_inputs,
                                                outputs: expected_outputs,
                                                kind: SpecLookupFailureKind::NoMatchingRow,
                                            })
                                        }
                                    }
                                    Err(error) => Err(error),
                                },
                                None => {
                                    let expected_outputs = None;
                                    if lookup_has_matching_row_from(
                                        &lookup_table.rows,
                                        &evaluated_inputs,
                                        &expected_outputs,
                                        inputs.len(),
                                        program.field,
                                    ) {
                                        check_constraints_from(
                                            remaining_constraints,
                                            program,
                                            witness,
                                        )
                                    } else {
                                        Err(SpecKernelCheckError::LookupViolation {
                                            constraint_index: *index,
                                            table_index: *table_index,
                                            inputs: evaluated_inputs,
                                            outputs: expected_outputs,
                                            kind: SpecLookupFailureKind::NoMatchingRow,
                                        })
                                    }
                                }
                            },
                            Err(error) => Err(error),
                        }
                    }
                }
                None => Err(SpecKernelCheckError::UnknownLookupTable {
                    table_index: *table_index,
                }),
            },
        },
        None => Ok(()),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn check_program(
    program: &SpecKernelProgram,
    witness: &SpecKernelWitness,
) -> Result<(), SpecKernelCheckError> {
    check_constraints_from(&program.constraints, program, witness)
}
