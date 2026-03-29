use crate::FieldId;
use crate::field::{
    add as field_add, div as field_div, equal as field_equal, fits_in_bits, is_boolean,
    mul as field_mul, normalize as field_normalize, sub as field_sub,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::BTreeMap;
use std::sync::atomic::{Ordering, compiler_fence};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum KernelExpr {
    Const(BigInt),
    Signal(usize),
    Add(Vec<KernelExpr>),
    Sub(Box<KernelExpr>, Box<KernelExpr>),
    Mul(Box<KernelExpr>, Box<KernelExpr>),
    Div(Box<KernelExpr>, Box<KernelExpr>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum KernelConstraint {
    Equal {
        index: usize,
        lhs: KernelExpr,
        rhs: KernelExpr,
        label: Option<String>,
    },
    Boolean {
        index: usize,
        signal: usize,
        label: Option<String>,
    },
    Range {
        index: usize,
        signal: usize,
        bits: u32,
        label: Option<String>,
    },
    Lookup {
        index: usize,
        inputs: Vec<KernelExpr>,
        table: String,
        outputs: Option<Vec<usize>>,
        label: Option<String>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct KernelLookupTable {
    pub(crate) column_count: usize,
    pub(crate) rows: Vec<Vec<BigInt>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct KernelProgram {
    pub(crate) field: FieldId,
    pub(crate) constraints: Vec<KernelConstraint>,
    pub(crate) lookup_tables: BTreeMap<String, KernelLookupTable>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct KernelWitness {
    pub(crate) values: Vec<Option<BigInt>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum KernelCheckError {
    MissingSignal {
        signal_index: usize,
    },
    DivisionByZero,
    UnknownLookupTable {
        table: String,
    },
    EqualViolation {
        constraint_index: usize,
        label: Option<String>,
        lhs: BigInt,
        rhs: BigInt,
    },
    BooleanViolation {
        constraint_index: usize,
        label: Option<String>,
        signal_index: usize,
        value: BigInt,
    },
    RangeViolation {
        constraint_index: usize,
        label: Option<String>,
        signal_index: usize,
        bits: u32,
        value: BigInt,
    },
    LookupViolation {
        constraint_index: usize,
        label: Option<String>,
        table: String,
        message: String,
    },
}

fn kernel_signal_value(
    witness: &KernelWitness,
    signal_index: usize,
    field: FieldId,
) -> Result<BigInt, KernelCheckError> {
    witness
        .values
        .get(signal_index)
        .and_then(Option::as_ref)
        .cloned()
        .map(|value| field_normalize(value, field))
        .ok_or(KernelCheckError::MissingSignal { signal_index })
}

#[cfg(kani)]
#[allow(dead_code)]
pub(crate) fn eval_expr_reference(
    expr: &KernelExpr,
    witness: &KernelWitness,
    field: FieldId,
) -> Result<BigInt, KernelCheckError> {
    match expr {
        KernelExpr::Const(value) => Ok(field_normalize(value.clone(), field)),
        KernelExpr::Signal(signal_index) => kernel_signal_value(witness, *signal_index, field),
        KernelExpr::Add(items) => {
            let mut acc = BigInt::zero();
            for item in items {
                acc = field_add(&acc, &eval_expr_reference(item, witness, field)?, field);
            }
            Ok(acc)
        }
        KernelExpr::Sub(lhs, rhs) => Ok(field_sub(
            &eval_expr_reference(lhs, witness, field)?,
            &eval_expr_reference(rhs, witness, field)?,
            field,
        )),
        KernelExpr::Mul(lhs, rhs) => Ok(field_mul(
            &eval_expr_reference(lhs, witness, field)?,
            &eval_expr_reference(rhs, witness, field)?,
            field,
        )),
        KernelExpr::Div(lhs, rhs) => field_div(
            &eval_expr_reference(lhs, witness, field)?,
            &eval_expr_reference(rhs, witness, field)?,
            field,
        )
        .ok_or(KernelCheckError::DivisionByZero),
    }
}

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

pub(crate) fn eval_expr_constant_time(
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
                match eval_expr_constant_time(item, witness, field) {
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
            let lhs_result = eval_expr_constant_time(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                Ok(field_sub(&lhs, &rhs, field))
            })
        }
        KernelExpr::Mul(lhs, rhs) => {
            compiler_fence(Ordering::SeqCst);
            let lhs_result = eval_expr_constant_time(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                Ok(field_mul(&lhs, &rhs, field))
            })
        }
        KernelExpr::Div(lhs, rhs) => {
            compiler_fence(Ordering::SeqCst);
            let lhs_result = eval_expr_constant_time(lhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            let rhs_result = eval_expr_constant_time(rhs, witness, field);
            compiler_fence(Ordering::SeqCst);
            combine_binary_results(lhs_result, rhs_result, |lhs, rhs| {
                field_div(&lhs, &rhs, field).ok_or(KernelCheckError::DivisionByZero)
            })
        }
    }
}

pub(crate) fn eval_expr(
    expr: &KernelExpr,
    witness: &KernelWitness,
    field: FieldId,
) -> Result<BigInt, KernelCheckError> {
    eval_expr_constant_time(expr, witness, field)
}

pub(crate) fn check_program(
    program: &KernelProgram,
    witness: &KernelWitness,
) -> Result<(), KernelCheckError> {
    for constraint in &program.constraints {
        match constraint {
            KernelConstraint::Equal {
                index,
                lhs,
                rhs,
                label,
            } => {
                let lhs_value = eval_expr(lhs, witness, program.field)?;
                let rhs_value = eval_expr(rhs, witness, program.field)?;
                if !field_equal(&lhs_value, &rhs_value, program.field) {
                    return Err(KernelCheckError::EqualViolation {
                        constraint_index: *index,
                        label: label.clone(),
                        lhs: lhs_value,
                        rhs: rhs_value,
                    });
                }
            }
            KernelConstraint::Boolean {
                index,
                signal,
                label,
            } => {
                let value = kernel_signal_value(witness, *signal, program.field)?;
                if !is_boolean(&value, program.field) {
                    return Err(KernelCheckError::BooleanViolation {
                        constraint_index: *index,
                        label: label.clone(),
                        signal_index: *signal,
                        value,
                    });
                }
            }
            KernelConstraint::Range {
                index,
                signal,
                bits,
                label,
            } => {
                let value = kernel_signal_value(witness, *signal, program.field)?;
                if !fits_in_bits(&value, *bits, program.field) {
                    return Err(KernelCheckError::RangeViolation {
                        constraint_index: *index,
                        label: label.clone(),
                        signal_index: *signal,
                        bits: *bits,
                        value,
                    });
                }
            }
            KernelConstraint::Lookup {
                index,
                inputs,
                table,
                outputs,
                label,
            } => {
                let lookup_table = program.lookup_tables.get(table).ok_or_else(|| {
                    KernelCheckError::UnknownLookupTable {
                        table: table.clone(),
                    }
                })?;

                if inputs.len() > lookup_table.column_count {
                    return Err(KernelCheckError::LookupViolation {
                        constraint_index: *index,
                        label: label.clone(),
                        table: table.clone(),
                        message: format!(
                            "constraint provides {} input columns but table '{}' has only {} columns",
                            inputs.len(),
                            table,
                            lookup_table.column_count
                        ),
                    });
                }

                let evaluated_inputs = inputs
                    .iter()
                    .map(|expr| eval_expr(expr, witness, program.field))
                    .collect::<Result<Vec<_>, _>>()?;

                let expected_outputs = outputs.as_ref().map(|signal_indices| {
                    signal_indices
                        .iter()
                        .enumerate()
                        .filter(|(output_idx, _)| {
                            inputs.len() + *output_idx < lookup_table.column_count
                        })
                        .map(|(_, signal_index)| {
                            kernel_signal_value(witness, *signal_index, program.field)
                        })
                        .collect::<Result<Vec<_>, _>>()
                });
                let expected_outputs = match expected_outputs {
                    Some(Ok(values)) => Some(values),
                    Some(Err(err)) => return Err(err),
                    None => None,
                };

                let row_matches = |row: &[BigInt]| -> bool {
                    for (column_index, input_value) in evaluated_inputs.iter().enumerate() {
                        let row_value = row.get(column_index).cloned().unwrap_or_else(BigInt::zero);
                        if !field_equal(&row_value, input_value, program.field) {
                            return false;
                        }
                    }

                    if let Some(expected_outputs) = &expected_outputs {
                        for (output_index, witness_value) in expected_outputs.iter().enumerate() {
                            let column_index = inputs.len() + output_index;
                            let row_value =
                                row.get(column_index).cloned().unwrap_or_else(BigInt::zero);
                            if !field_equal(&row_value, witness_value, program.field) {
                                return false;
                            }
                        }
                    }

                    true
                };

                let found_match = lookup_table.rows.iter().any(|row| row_matches(row));
                if !found_match {
                    let rendered_inputs = evaluated_inputs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    let rendered_outputs = expected_outputs
                        .as_ref()
                        .map(|values| {
                            values
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    let output_clause = if rendered_outputs.is_empty() {
                        String::new()
                    } else {
                        format!(" with outputs [{rendered_outputs}]")
                    };
                    return Err(KernelCheckError::LookupViolation {
                        constraint_index: *index,
                        label: label.clone(),
                        table: table.clone(),
                        message: format!(
                            "no row matched inputs [{rendered_inputs}]{}",
                            output_clause
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}
