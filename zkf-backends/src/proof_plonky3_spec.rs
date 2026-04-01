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

use crate::proof_plonky3_surface as surface;
use std::collections::BTreeMap;
use zkf_core::{Constraint, Expr, FieldElement, FieldId, Program, Visibility, Witness, ZkfError};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecPlonky3LoweringError {
    UnsupportedField(FieldId),
    UnknownSignal(String),
    ParseField(String),
    UnsupportedRangeBits {
        field: FieldId,
        bits: u32,
        max_bits: u32,
        signal: Option<String>,
        label: Option<String>,
        constraint_index: Option<usize>,
    },
    UnsupportedConstraint(String),
    DivisionByZero,
    MissingWitnessValue(String),
    BaseSignalCountOutOfBounds {
        base_signal_count: usize,
        lowered_width: usize,
    },
    PublicInputIndexOutOfBounds {
        public_index: usize,
        base_signal_count: usize,
    },
    RowIndexOutOfBounds {
        row_index: usize,
        row_len: usize,
    },
    DerivedSourceIndexOutOfBounds {
        source_index: usize,
        base_signal_count: usize,
    },
    DerivedTargetIndexOutOfBounds {
        derived_index: usize,
        lowered_width: usize,
    },
    MalformedLoweredProgram(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirExpr {
    Const(u64),
    Signal(usize),
    Add(Vec<AirExpr>),
    Sub(Box<AirExpr>, Box<AirExpr>),
    Mul(Box<AirExpr>, Box<AirExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredProgram {
    pub base_signal_count: usize,
    pub signal_order: Vec<String>,
    pub public_signal_indices: Vec<usize>,
    pub constraints: Vec<AirExpr>,
    pub derived_columns: Vec<DerivedColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedColumn {
    pub index: usize,
    pub computation: DerivedComputation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerivedComputation {
    Division {
        numerator: AirExpr,
        denominator: AirExpr,
    },
    RangeBit {
        source_index: usize,
        bit: u32,
    },
}

#[derive(Clone, Debug)]
struct RuntimeLoweringContext {
    field: FieldId,
    signal_order: Vec<String>,
    signal_indices: BTreeMap<String, usize>,
    public_signal_indices: Vec<usize>,
    constraints: Vec<AirExpr>,
    derived_columns: Vec<DerivedColumn>,
}

enum RuntimeExprFrame<'a> {
    Visit(&'a Expr),
    FinishAdd(usize),
    FinishSub,
    FinishMul,
    FinishDiv,
}

impl From<SpecPlonky3LoweringError> for ZkfError {
    fn from(value: SpecPlonky3LoweringError) -> Self {
        match value {
            SpecPlonky3LoweringError::UnsupportedField(field) => ZkfError::UnsupportedBackend {
                backend: "plonky3".to_string(),
                message: format!("field {field} is not supported by plonky3 adapter"),
            },
            SpecPlonky3LoweringError::UnknownSignal(signal) => ZkfError::UnknownSignal { signal },
            SpecPlonky3LoweringError::ParseField(value) => ZkfError::ParseField { value },
            SpecPlonky3LoweringError::UnsupportedRangeBits {
                field,
                bits,
                max_bits,
                signal,
                label,
                constraint_index,
            } => ZkfError::UnsupportedBackend {
                backend: "plonky3".to_string(),
                message: unsupported_range_bits_message(
                    field,
                    bits,
                    max_bits,
                    signal.as_deref(),
                    label.as_deref(),
                    constraint_index,
                ),
            },
            SpecPlonky3LoweringError::UnsupportedConstraint(kind) => ZkfError::Backend(format!(
                "constraint {kind} must be lowered before plonky3 synthesis"
            )),
            SpecPlonky3LoweringError::DivisionByZero => ZkfError::DivisionByZero,
            SpecPlonky3LoweringError::MissingWitnessValue(signal) => {
                ZkfError::MissingWitnessValue { signal }
            }
            SpecPlonky3LoweringError::BaseSignalCountOutOfBounds {
                base_signal_count,
                lowered_width,
            } => ZkfError::Backend(format!(
                "malformed plonky3 lowered program: base signal count {base_signal_count} exceeds width {lowered_width}"
            )),
            SpecPlonky3LoweringError::PublicInputIndexOutOfBounds {
                public_index,
                base_signal_count,
            } => ZkfError::Backend(format!(
                "malformed plonky3 lowered program: public index {public_index} exceeds base signal count {base_signal_count}"
            )),
            SpecPlonky3LoweringError::RowIndexOutOfBounds { row_index, row_len } => {
                ZkfError::Backend(format!(
                    "plonky3 proof kernel attempted to read row index {row_index} from width {row_len}"
                ))
            }
            SpecPlonky3LoweringError::DerivedSourceIndexOutOfBounds {
                source_index,
                base_signal_count,
            } => ZkfError::Backend(format!(
                "malformed plonky3 derived source index {source_index} exceeds base signal count {base_signal_count}"
            )),
            SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
                derived_index,
                lowered_width,
            } => ZkfError::Backend(format!(
                "malformed plonky3 derived target index {derived_index} exceeds width {lowered_width}"
            )),
            SpecPlonky3LoweringError::MalformedLoweredProgram(message) => {
                ZkfError::Backend(format!("malformed plonky3 lowered program: {message}"))
            }
        }
    }
}

fn unsupported_range_bits_message(
    field: FieldId,
    bits: u32,
    max_bits: u32,
    signal: Option<&str>,
    label: Option<&str>,
    constraint_index: Option<usize>,
) -> String {
    let mut message = format!(
        "plonky3 adapter currently supports range constraints up to {max_bits} bits for field {field}; found {bits}"
    );
    if signal.is_some() || label.is_some() || constraint_index.is_some() {
        message.push_str(" for");
        if let Some(signal) = signal {
            message.push_str(&format!(" signal {signal}"));
        }
        if let Some(constraint_index) = constraint_index {
            message.push_str(&format!(" at constraint #{constraint_index}"));
        }
        if let Some(label) = label {
            message.push_str(&format!(" ({label})"));
        }
    }
    message
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RangeConstraintProvenance {
    signal: String,
    label: Option<String>,
    constraint_index: usize,
}

pub(crate) fn plonky3_supported_field(field: FieldId) -> bool {
    matches!(
        field,
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31
    )
}

fn to_surface_field(
    field: FieldId,
) -> Result<surface::SpecPlonky3FieldId, SpecPlonky3LoweringError> {
    match field {
        FieldId::Goldilocks => Ok(surface::SpecPlonky3FieldId::Goldilocks),
        FieldId::BabyBear => Ok(surface::SpecPlonky3FieldId::BabyBear),
        FieldId::Mersenne31 => Ok(surface::SpecPlonky3FieldId::Mersenne31),
        other => Err(SpecPlonky3LoweringError::UnsupportedField(other)),
    }
}

pub(crate) fn field_modulus_u64(field: FieldId) -> Result<u64, SpecPlonky3LoweringError> {
    Ok(surface::field_modulus_u64(to_surface_field(field)?))
}

pub(crate) fn max_safe_range_bits(field: FieldId) -> u32 {
    match to_surface_field(field) {
        Ok(spec_field) => surface::max_safe_range_bits(spec_field),
        Err(_) => 0,
    }
}

pub(crate) fn parse_field_u64(
    value: &FieldElement,
    field: FieldId,
) -> Result<u64, SpecPlonky3LoweringError> {
    let bigint = value
        .normalized_bigint(field)
        .map_err(|_| SpecPlonky3LoweringError::ParseField(value.to_decimal_string()))?;
    let (_, bytes) = bigint.to_bytes_be();
    if bytes.len() > 8 {
        return Err(SpecPlonky3LoweringError::ParseField(
            value.to_decimal_string(),
        ));
    }

    let mut out = 0u64;
    for byte in bytes {
        out = (out << 8) | u64::from(byte);
    }
    let modulus = field_modulus_u64(field)?;
    if out >= modulus {
        return Err(SpecPlonky3LoweringError::ParseField(
            value.to_decimal_string(),
        ));
    }
    Ok(out)
}

fn to_surface_visibility(visibility: Visibility) -> surface::SpecVisibility {
    match visibility {
        Visibility::Public => surface::SpecVisibility::Public,
        Visibility::Constant => surface::SpecVisibility::Private,
        Visibility::Private => surface::SpecVisibility::Private,
    }
}

fn to_surface_expr(
    expr: &Expr,
    field: FieldId,
) -> Result<surface::SpecExpr, SpecPlonky3LoweringError> {
    match expr {
        Expr::Const(value) => Ok(surface::SpecExpr::Const(parse_field_u64(value, field)?)),
        Expr::Signal(name) => Ok(surface::SpecExpr::Signal(name.clone())),
        Expr::Add(values) => {
            let mut lowered = Vec::with_capacity(values.len());
            for value in values {
                lowered.push(to_surface_expr(value, field)?);
            }
            Ok(surface::SpecExpr::Add(lowered))
        }
        Expr::Sub(lhs, rhs) => Ok(surface::SpecExpr::Sub(
            Box::new(to_surface_expr(lhs, field)?),
            Box::new(to_surface_expr(rhs, field)?),
        )),
        Expr::Mul(lhs, rhs) => Ok(surface::SpecExpr::Mul(
            Box::new(to_surface_expr(lhs, field)?),
            Box::new(to_surface_expr(rhs, field)?),
        )),
        Expr::Div(lhs, rhs) => Ok(surface::SpecExpr::Div(
            Box::new(to_surface_expr(lhs, field)?),
            Box::new(to_surface_expr(rhs, field)?),
        )),
    }
}

fn to_surface_constraint(
    constraint: &Constraint,
    field: FieldId,
) -> Result<surface::SpecConstraint, SpecPlonky3LoweringError> {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => Ok(surface::SpecConstraint::Equal {
            equal_lhs: to_surface_expr(lhs, field)?,
            equal_rhs: to_surface_expr(rhs, field)?,
        }),
        Constraint::Boolean { signal, .. } => Ok(surface::SpecConstraint::Boolean {
            boolean_signal: signal.clone(),
        }),
        Constraint::Range { signal, bits, .. } => Ok(surface::SpecConstraint::Range {
            range_signal: signal.clone(),
            range_bits: *bits,
        }),
        Constraint::BlackBox {
            op,
            inputs,
            outputs,
            ..
        } => {
            let _ = (op, inputs, outputs);
            Ok(surface::SpecConstraint::BlackBox)
        }
        Constraint::Lookup { .. } => Ok(surface::SpecConstraint::Lookup),
    }
}

fn to_surface_program(program: &Program) -> Result<surface::SpecProgram, SpecPlonky3LoweringError> {
    let mut program_signals = Vec::with_capacity(program.signals.len());
    for signal in &program.signals {
        program_signals.push(surface::SpecSignal {
            signal_name: signal.name.clone(),
            signal_visibility: to_surface_visibility(signal.visibility.clone()),
        });
    }

    let mut program_constraints = Vec::with_capacity(program.constraints.len());
    for constraint in &program.constraints {
        program_constraints.push(to_surface_constraint(constraint, program.field)?);
    }

    Ok(surface::SpecProgram {
        program_field: to_surface_field(program.field)?,
        program_signals,
        program_constraints,
    })
}

fn runtime_signal_expr(
    name: &str,
    signal_indices: &BTreeMap<String, usize>,
) -> Result<AirExpr, SpecPlonky3LoweringError> {
    signal_indices
        .get(name)
        .copied()
        .map(AirExpr::Signal)
        .ok_or_else(|| SpecPlonky3LoweringError::UnknownSignal(name.to_string()))
}

fn runtime_range_bit_temp_name(signal: &str, current_bit: u32, bit_index: usize) -> String {
    format!("__range_{signal}_bit_{current_bit}_{bit_index}")
}

fn runtime_division_temp_name(derived_column_count: usize) -> String {
    format!("__div_tmp_{derived_column_count}")
}

fn runtime_lower_range_bits(
    signal: &str,
    source_index: usize,
    bits: u32,
    context: &mut RuntimeLoweringContext,
    mut recomposed_terms: Vec<AirExpr>,
) -> Result<Vec<AirExpr>, SpecPlonky3LoweringError> {
    for current_bit in 0..bits {
        let bit_index = context.signal_order.len();
        let bit_name = runtime_range_bit_temp_name(signal, current_bit, bit_index);
        context.signal_order.push(bit_name.clone());
        context.signal_indices.insert(bit_name, bit_index);
        context.derived_columns.push(DerivedColumn {
            index: bit_index,
            computation: DerivedComputation::RangeBit {
                source_index,
                bit: current_bit,
            },
        });

        let bit_signal = AirExpr::Signal(bit_index);
        context.constraints.push(AirExpr::Mul(
            Box::new(bit_signal.clone()),
            Box::new(AirExpr::Sub(
                Box::new(AirExpr::Const(1)),
                Box::new(bit_signal.clone()),
            )),
        ));

        let weighted = if current_bit == 0 {
            bit_signal
        } else {
            AirExpr::Mul(Box::new(AirExpr::Const(1u64 << current_bit)), Box::new(bit_signal))
        };
        recomposed_terms.push(weighted);
    }
    Ok(recomposed_terms)
}

fn runtime_lower_expr(
    expr: &Expr,
    context: &mut RuntimeLoweringContext,
) -> Result<AirExpr, SpecPlonky3LoweringError> {
    let mut frames = vec![RuntimeExprFrame::Visit(expr)];
    let mut lowered_stack = Vec::new();

    while let Some(frame) = frames.pop() {
        match frame {
            RuntimeExprFrame::Visit(current) => match current {
                Expr::Const(value) => {
                    lowered_stack.push(AirExpr::Const(parse_field_u64(value, context.field)?));
                }
                Expr::Signal(name) => {
                    lowered_stack.push(runtime_signal_expr(name, &context.signal_indices)?);
                }
                Expr::Add(values) => {
                    frames.push(RuntimeExprFrame::FinishAdd(values.len()));
                    for value in values.iter().rev() {
                        frames.push(RuntimeExprFrame::Visit(value));
                    }
                }
                Expr::Sub(lhs, rhs) => {
                    frames.push(RuntimeExprFrame::FinishSub);
                    frames.push(RuntimeExprFrame::Visit(rhs));
                    frames.push(RuntimeExprFrame::Visit(lhs));
                }
                Expr::Mul(lhs, rhs) => {
                    frames.push(RuntimeExprFrame::FinishMul);
                    frames.push(RuntimeExprFrame::Visit(rhs));
                    frames.push(RuntimeExprFrame::Visit(lhs));
                }
                Expr::Div(lhs, rhs) => {
                    frames.push(RuntimeExprFrame::FinishDiv);
                    frames.push(RuntimeExprFrame::Visit(rhs));
                    frames.push(RuntimeExprFrame::Visit(lhs));
                }
            },
            RuntimeExprFrame::FinishAdd(value_count) => {
                let split_point = lowered_stack
                    .len()
                    .checked_sub(value_count)
                    .ok_or_else(|| {
                        SpecPlonky3LoweringError::MalformedLoweredProgram(
                            "runtime add lowering stack underflow".to_string(),
                        )
                    })?;
                let lowered_values = lowered_stack.split_off(split_point);
                lowered_stack.push(AirExpr::Add(lowered_values));
            }
            RuntimeExprFrame::FinishSub => {
                let rhs = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime sub lowering rhs underflow".to_string(),
                    )
                })?;
                let lhs = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime sub lowering lhs underflow".to_string(),
                    )
                })?;
                lowered_stack.push(AirExpr::Sub(Box::new(lhs), Box::new(rhs)));
            }
            RuntimeExprFrame::FinishMul => {
                let rhs = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime mul lowering rhs underflow".to_string(),
                    )
                })?;
                let lhs = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime mul lowering lhs underflow".to_string(),
                    )
                })?;
                lowered_stack.push(AirExpr::Mul(Box::new(lhs), Box::new(rhs)));
            }
            RuntimeExprFrame::FinishDiv => {
                let denominator = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime div lowering denominator underflow".to_string(),
                    )
                })?;
                let numerator = lowered_stack.pop().ok_or_else(|| {
                    SpecPlonky3LoweringError::MalformedLoweredProgram(
                        "runtime div lowering numerator underflow".to_string(),
                    )
                })?;
                let div_index = context.signal_order.len();
                let div_name = runtime_division_temp_name(context.derived_columns.len());
                context.signal_order.push(div_name.clone());
                context.signal_indices.insert(div_name, div_index);
                let quotient = AirExpr::Signal(div_index);
                context.derived_columns.push(DerivedColumn {
                    index: div_index,
                    computation: DerivedComputation::Division {
                        numerator: numerator.clone(),
                        denominator: denominator.clone(),
                    },
                });
                context.constraints.push(AirExpr::Sub(
                    Box::new(AirExpr::Mul(
                        Box::new(denominator),
                        Box::new(quotient.clone()),
                    )),
                    Box::new(numerator),
                ));
                lowered_stack.push(quotient);
            }
        }
    }

    if lowered_stack.len() != 1 {
        return Err(SpecPlonky3LoweringError::MalformedLoweredProgram(
            format!(
                "runtime expression lowering produced {} values instead of 1",
                lowered_stack.len()
            ),
        ));
    }

    lowered_stack.pop().ok_or_else(|| {
        SpecPlonky3LoweringError::MalformedLoweredProgram(
            "runtime expression lowering produced no value".to_string(),
        )
    })
}

fn runtime_lower_constraint(
    constraint: &Constraint,
    constraint_index: usize,
    context: &mut RuntimeLoweringContext,
) -> Result<(), SpecPlonky3LoweringError> {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            let lhs = runtime_lower_expr(lhs, context)?;
            let rhs = runtime_lower_expr(rhs, context)?;
            context
                .constraints
                .push(AirExpr::Sub(Box::new(lhs), Box::new(rhs)));
            Ok(())
        }
        Constraint::Boolean { signal, .. } => {
            let signal_expr = runtime_signal_expr(signal, &context.signal_indices)?;
            context.constraints.push(AirExpr::Mul(
                Box::new(signal_expr.clone()),
                Box::new(AirExpr::Sub(
                    Box::new(AirExpr::Const(1)),
                    Box::new(signal_expr),
                )),
            ));
            Ok(())
        }
        Constraint::Range { signal, bits, label } => {
            let max_bits = max_safe_range_bits(context.field);
            if *bits > max_bits {
                return Err(SpecPlonky3LoweringError::UnsupportedRangeBits {
                    field: context.field,
                    bits: *bits,
                    max_bits,
                    signal: Some(signal.clone()),
                    label: label.clone(),
                    constraint_index: Some(constraint_index),
                });
            }
            let source_index = context
                .signal_indices
                .get(signal)
                .copied()
                .ok_or_else(|| SpecPlonky3LoweringError::UnknownSignal(signal.clone()))?;
            let source = AirExpr::Signal(source_index);
            let recomposed_terms =
                runtime_lower_range_bits(signal, source_index, *bits, context, Vec::new())?;
            let recomposed = match recomposed_terms.as_slice().split_first() {
                None => AirExpr::Const(0),
                Some((first, remaining)) => {
                    if remaining.is_empty() {
                        first.clone()
                    } else {
                        AirExpr::Add(recomposed_terms)
                    }
                }
            };
            context
                .constraints
                .push(AirExpr::Sub(Box::new(recomposed), Box::new(source)));
            Ok(())
        }
        Constraint::BlackBox { .. } => Err(SpecPlonky3LoweringError::UnsupportedConstraint(
            "blackbox".to_string(),
        )),
        Constraint::Lookup { .. } => Err(SpecPlonky3LoweringError::UnsupportedConstraint(
            "lookup".to_string(),
        )),
    }
}

fn to_surface_witness(
    witness: &Witness,
    field: FieldId,
) -> Result<surface::SpecWitness, SpecPlonky3LoweringError> {
    let mut witness_values = Vec::with_capacity(witness.values.len());
    for (name, value) in &witness.values {
        witness_values.push((name.clone(), parse_field_u64(value, field)?));
    }
    Ok(surface::SpecWitness { witness_values })
}

fn to_surface_air_expr(expr: &AirExpr) -> surface::AirExpr {
    match expr {
        AirExpr::Const(value) => surface::AirExpr::Const(*value),
        AirExpr::Signal(index) => surface::AirExpr::Signal(*index),
        AirExpr::Add(values) => {
            surface::AirExpr::Add(values.iter().map(to_surface_air_expr).collect())
        }
        AirExpr::Sub(lhs, rhs) => surface::AirExpr::Sub(
            Box::new(to_surface_air_expr(lhs)),
            Box::new(to_surface_air_expr(rhs)),
        ),
        AirExpr::Mul(lhs, rhs) => surface::AirExpr::Mul(
            Box::new(to_surface_air_expr(lhs)),
            Box::new(to_surface_air_expr(rhs)),
        ),
    }
}

fn to_runtime_air_expr(expr: &surface::AirExpr) -> AirExpr {
    match expr {
        surface::AirExpr::Const(value) => AirExpr::Const(*value),
        surface::AirExpr::Signal(index) => AirExpr::Signal(*index),
        surface::AirExpr::Add(values) => {
            AirExpr::Add(values.iter().map(to_runtime_air_expr).collect())
        }
        surface::AirExpr::Sub(lhs, rhs) => AirExpr::Sub(
            Box::new(to_runtime_air_expr(lhs)),
            Box::new(to_runtime_air_expr(rhs)),
        ),
        surface::AirExpr::Mul(lhs, rhs) => AirExpr::Mul(
            Box::new(to_runtime_air_expr(lhs)),
            Box::new(to_runtime_air_expr(rhs)),
        ),
    }
}

fn to_surface_derived_computation(computation: &DerivedComputation) -> surface::DerivedComputation {
    match computation {
        DerivedComputation::Division {
            numerator,
            denominator,
        } => surface::DerivedComputation::Division {
            division_numerator: to_surface_air_expr(numerator),
            division_denominator: to_surface_air_expr(denominator),
        },
        DerivedComputation::RangeBit { source_index, bit } => {
            surface::DerivedComputation::RangeBit {
                range_source_index: *source_index,
                range_bit: *bit,
            }
        }
    }
}

fn to_runtime_derived_computation(computation: &surface::DerivedComputation) -> DerivedComputation {
    match computation {
        surface::DerivedComputation::Division {
            division_numerator,
            division_denominator,
        } => DerivedComputation::Division {
            numerator: to_runtime_air_expr(division_numerator),
            denominator: to_runtime_air_expr(division_denominator),
        },
        surface::DerivedComputation::RangeBit {
            range_source_index,
            range_bit,
        } => DerivedComputation::RangeBit {
            source_index: *range_source_index,
            bit: *range_bit,
        },
    }
}

fn to_surface_lowered_program(lowered: &LoweredProgram) -> surface::LoweredProgram {
    surface::LoweredProgram {
        lowered_base_signal_count: lowered.base_signal_count,
        lowered_signal_order: lowered.signal_order.clone(),
        lowered_public_signal_indices: lowered.public_signal_indices.clone(),
        lowered_constraints: lowered
            .constraints
            .iter()
            .map(to_surface_air_expr)
            .collect(),
        lowered_derived_columns: lowered
            .derived_columns
            .iter()
            .map(|derived| surface::DerivedColumn {
                derived_index: derived.index,
                derived_computation: to_surface_derived_computation(&derived.computation),
            })
            .collect(),
    }
}

fn to_runtime_lowered_program(lowered: &surface::LoweredProgram) -> LoweredProgram {
    LoweredProgram {
        base_signal_count: lowered.lowered_base_signal_count,
        signal_order: lowered.lowered_signal_order.clone(),
        public_signal_indices: lowered.lowered_public_signal_indices.clone(),
        constraints: lowered
            .lowered_constraints
            .iter()
            .map(to_runtime_air_expr)
            .collect(),
        derived_columns: lowered
            .lowered_derived_columns
            .iter()
            .map(|derived| DerivedColumn {
                index: derived.derived_index,
                computation: to_runtime_derived_computation(&derived.derived_computation),
            })
            .collect(),
    }
}

fn from_surface_error(error: surface::SpecPlonky3LoweringError) -> SpecPlonky3LoweringError {
    match error {
        surface::SpecPlonky3LoweringError::UnknownSignal(signal) => {
            SpecPlonky3LoweringError::UnknownSignal(signal)
        }
        surface::SpecPlonky3LoweringError::UnsupportedRangeBits {
            unsupported_field,
            unsupported_bits,
            unsupported_max_bits,
        } => SpecPlonky3LoweringError::UnsupportedRangeBits {
            field: match unsupported_field {
                surface::SpecPlonky3FieldId::Goldilocks => FieldId::Goldilocks,
                surface::SpecPlonky3FieldId::BabyBear => FieldId::BabyBear,
                surface::SpecPlonky3FieldId::Mersenne31 => FieldId::Mersenne31,
            },
            bits: unsupported_bits,
            max_bits: unsupported_max_bits,
            signal: None,
            label: None,
            constraint_index: None,
        },
        surface::SpecPlonky3LoweringError::UnsupportedConstraint(kind) => {
            SpecPlonky3LoweringError::UnsupportedConstraint(kind)
        }
        surface::SpecPlonky3LoweringError::DivisionByZero => {
            SpecPlonky3LoweringError::DivisionByZero
        }
        surface::SpecPlonky3LoweringError::MissingWitnessValue(signal) => {
            SpecPlonky3LoweringError::MissingWitnessValue(signal)
        }
        surface::SpecPlonky3LoweringError::BaseSignalCountOutOfBounds {
            offending_base_signal_count,
            available_lowered_width,
        } => SpecPlonky3LoweringError::BaseSignalCountOutOfBounds {
            base_signal_count: offending_base_signal_count,
            lowered_width: available_lowered_width,
        },
        surface::SpecPlonky3LoweringError::PublicInputIndexOutOfBounds {
            offending_public_index,
            available_base_signal_count,
        } => SpecPlonky3LoweringError::PublicInputIndexOutOfBounds {
            public_index: offending_public_index,
            base_signal_count: available_base_signal_count,
        },
        surface::SpecPlonky3LoweringError::RowIndexOutOfBounds {
            offending_row_index,
            available_row_len,
        } => SpecPlonky3LoweringError::RowIndexOutOfBounds {
            row_index: offending_row_index,
            row_len: available_row_len,
        },
        surface::SpecPlonky3LoweringError::DerivedSourceIndexOutOfBounds {
            offending_source_index,
            available_base_signal_count,
        } => SpecPlonky3LoweringError::DerivedSourceIndexOutOfBounds {
            source_index: offending_source_index,
            base_signal_count: available_base_signal_count,
        },
        surface::SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
            offending_derived_index,
            available_lowered_width,
        } => SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
            derived_index: offending_derived_index,
            lowered_width: available_lowered_width,
        },
        surface::SpecPlonky3LoweringError::MalformedLoweredProgram(message) => {
            SpecPlonky3LoweringError::MalformedLoweredProgram(message)
        }
    }
}

pub(crate) fn is_supported_plonky3_program(program: &Program) -> bool {
    match to_surface_program(program) {
        Ok(spec_program) => surface::is_supported_plonky3_program(&spec_program),
        Err(_) => false,
    }
}

pub(crate) fn lower_program(program: &Program) -> Result<LoweredProgram, SpecPlonky3LoweringError> {
    let spec_program = to_surface_program(program)?;
    match surface::lower_program(&spec_program) {
        Ok(lowered) => Ok(to_runtime_lowered_program(&lowered)),
        Err(error) => Err(from_surface_error_with_program(program, error)),
    }
}

pub(crate) fn lower_program_runtime_fast(
    program: &Program,
) -> Result<LoweredProgram, SpecPlonky3LoweringError> {
    let _ = to_surface_field(program.field)?;
    if program.signals.is_empty() {
        return Ok(LoweredProgram {
            base_signal_count: 0,
            signal_order: Vec::new(),
            public_signal_indices: Vec::new(),
            constraints: Vec::new(),
            derived_columns: Vec::new(),
        });
    }

    let mut signal_order = Vec::with_capacity(program.signals.len());
    let mut signal_indices = BTreeMap::new();
    let mut public_signal_indices = Vec::new();
    for (index, signal) in program.signals.iter().enumerate() {
        signal_order.push(signal.name.clone());
        signal_indices.entry(signal.name.clone()).or_insert(index);
        if matches!(signal.visibility, Visibility::Public) {
            public_signal_indices.push(index);
        }
    }

    let mut context = RuntimeLoweringContext {
        field: program.field,
        signal_order,
        signal_indices,
        public_signal_indices,
        constraints: Vec::new(),
        derived_columns: Vec::new(),
    };

    for (constraint_index, constraint) in program.constraints.iter().enumerate() {
        runtime_lower_constraint(constraint, constraint_index, &mut context)?;
    }

    Ok(LoweredProgram {
        base_signal_count: program.signals.len(),
        signal_order: context.signal_order,
        public_signal_indices: context.public_signal_indices,
        constraints: context.constraints,
        derived_columns: context.derived_columns,
    })
}

fn locate_unsupported_range_constraint(
    program: &Program,
    max_bits: u32,
) -> Option<RangeConstraintProvenance> {
    for (constraint_index, constraint) in program.constraints.iter().enumerate() {
        if let Constraint::Range {
            signal,
            bits,
            label,
        } = constraint
            && *bits > max_bits
        {
            return Some(RangeConstraintProvenance {
                signal: signal.clone(),
                label: label.clone(),
                constraint_index,
            });
        }
    }
    None
}

fn from_surface_error_with_program(
    program: &Program,
    error: surface::SpecPlonky3LoweringError,
) -> SpecPlonky3LoweringError {
    match from_surface_error(error) {
        SpecPlonky3LoweringError::UnsupportedRangeBits {
            field,
            bits,
            max_bits,
            ..
        } => {
            let provenance = locate_unsupported_range_constraint(program, max_bits);
            SpecPlonky3LoweringError::UnsupportedRangeBits {
                field,
                bits,
                max_bits,
                signal: provenance.as_ref().map(|item| item.signal.clone()),
                label: provenance.as_ref().and_then(|item| item.label.clone()),
                constraint_index: provenance.map(|item| item.constraint_index),
            }
        }
        other => other,
    }
}

pub(crate) fn validate_lowered_program(
    lowered: &LoweredProgram,
) -> Result<(), SpecPlonky3LoweringError> {
    surface::validate_lowered_program(&to_surface_lowered_program(lowered))
        .map_err(from_surface_error)
}

pub(crate) fn public_input_positions_preserved_checked(
    program: &Program,
    lowered: &LoweredProgram,
) -> Result<bool, SpecPlonky3LoweringError> {
    let spec_program = to_surface_program(program)?;
    let spec_lowered = to_surface_lowered_program(lowered);
    surface::public_input_positions_preserved(&spec_program, &spec_lowered)
        .map_err(from_surface_error)
}

pub(crate) fn public_input_positions_preserved(
    program: &Program,
    lowered: &LoweredProgram,
) -> bool {
    public_input_positions_preserved_checked(program, lowered).unwrap_or(false)
}

pub(crate) fn eval_air_expr_concrete_checked(
    expr: &AirExpr,
    row: &[u64],
    modulus: u64,
) -> Result<u64, SpecPlonky3LoweringError> {
    surface::eval_air_expr_concrete(&to_surface_air_expr(expr), row, modulus)
        .map_err(from_surface_error)
}

pub(crate) fn eval_air_expr_concrete(expr: &AirExpr, row: &[u64], modulus: u64) -> u64 {
    eval_air_expr_concrete_checked(expr, row, modulus)
        .expect("proof_plonky3_spec::eval_air_expr_concrete called on malformed row")
}

pub(crate) fn build_trace_row(
    lowered: &LoweredProgram,
    witness: &Witness,
    field: FieldId,
) -> Result<Vec<u64>, SpecPlonky3LoweringError> {
    let spec_lowered = to_surface_lowered_program(lowered);
    let spec_witness = to_surface_witness(witness, field)?;
    surface::build_trace_row(&spec_lowered, &spec_witness, to_surface_field(field)?)
        .map_err(from_surface_error)
}

pub(crate) fn build_trace_row_runtime_fast(
    lowered: &LoweredProgram,
    witness: &Witness,
    field: FieldId,
) -> Result<Vec<u64>, SpecPlonky3LoweringError> {
    validate_lowered_program(lowered)?;

    let lowered_width = lowered.signal_order.len();
    let mut row = vec![0u64; lowered_width];
    let modulus = field_modulus_u64(field)?;

    for (index, signal_name) in lowered
        .signal_order
        .iter()
        .enumerate()
        .take(lowered.base_signal_count)
    {
        let value = witness
            .values
            .get(signal_name.as_str())
            .ok_or_else(|| SpecPlonky3LoweringError::MissingWitnessValue(signal_name.clone()))?;
        row[index] = parse_field_u64(value, field)?;
    }

    for derived in &lowered.derived_columns {
        let next_value = match &derived.computation {
            DerivedComputation::Division {
                numerator,
                denominator,
            } => {
                let denominator = eval_air_expr_concrete_checked(denominator, &row, modulus)?;
                let inverse = surface::mod_inverse_u64(denominator, modulus)
                    .ok_or(SpecPlonky3LoweringError::DivisionByZero)?;
                let numerator = eval_air_expr_concrete_checked(numerator, &row, modulus)?;
                surface::mul_mod_u64(numerator, inverse, modulus)
            }
            DerivedComputation::RangeBit { source_index, bit } => {
                let source_value = row.get(*source_index).copied().ok_or(
                    SpecPlonky3LoweringError::DerivedSourceIndexOutOfBounds {
                        source_index: *source_index,
                        base_signal_count: lowered.base_signal_count,
                    },
                )?;
                (source_value >> bit) & 1
            }
        };

        let target = row.get_mut(derived.index).ok_or(
            SpecPlonky3LoweringError::DerivedTargetIndexOutOfBounds {
                derived_index: derived.index,
                lowered_width,
            },
        )?;
        *target = next_value;
    }

    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::{
        AirExpr, SpecPlonky3LoweringError, build_trace_row, build_trace_row_runtime_fast,
        eval_air_expr_concrete_checked, is_supported_plonky3_program, lower_program,
        lower_program_runtime_fast,
        public_input_positions_preserved_checked,
    };
    use std::collections::BTreeMap;
    use zkf_core::{
        BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, Witness,
    };

    fn sample_program() -> Program {
        Program {
            field: FieldId::Goldilocks,
            signals: vec![
                Signal {
                    name: "a".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "c".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Range {
                    signal: "a".to_string(),
                    bits: 8,
                    label: None,
                },
                Constraint::Equal {
                    lhs: Expr::signal("c"),
                    rhs: Expr::Div(Box::new(Expr::signal("b")), Box::new(Expr::signal("a"))),
                    label: None,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn supported_subset_accepts_arithmetic_and_range() {
        assert!(is_supported_plonky3_program(&sample_program()));
    }

    #[test]
    fn supported_subset_rejects_lookup_and_blackbox() {
        let mut lookup = sample_program();
        lookup.constraints.push(Constraint::Lookup {
            inputs: vec![Expr::signal("a")],
            table: "table".to_string(),
            outputs: None,
            label: None,
        });
        assert!(!is_supported_plonky3_program(&lookup));

        let mut blackbox = sample_program();
        blackbox.constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Sha256,
            inputs: Vec::new(),
            outputs: Vec::new(),
            params: BTreeMap::new(),
            label: None,
        });
        assert!(!is_supported_plonky3_program(&blackbox));
    }

    #[test]
    fn lowered_program_preserves_public_input_positions() {
        let program = sample_program();
        let lowered = lower_program(&program).expect("lowering should pass");
        assert!(
            public_input_positions_preserved_checked(&program, &lowered)
                .expect("lowered program should be well formed")
        );
    }

    #[test]
    fn fast_runtime_lowering_matches_surface_lowering() {
        let program = sample_program();
        let lowered = lower_program(&program).expect("surface lowering should pass");
        let fast_lowered =
            lower_program_runtime_fast(&program).expect("fast runtime lowering should pass");
        assert_eq!(fast_lowered, lowered);
    }

    #[test]
    fn unsupported_range_bits_names_signal_and_constraint() {
        let program = Program {
            field: FieldId::Goldilocks,
            signals: vec![Signal {
                name: "value".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Range {
                signal: "value".to_string(),
                bits: 67,
                label: Some("value_range".to_string()),
            }],
            ..Default::default()
        };

        let error = lower_program(&program).expect_err("range should overflow Goldilocks");
        assert_eq!(
            error,
            SpecPlonky3LoweringError::UnsupportedRangeBits {
                field: FieldId::Goldilocks,
                bits: 67,
                max_bits: 63,
                signal: Some("value".to_string()),
                label: Some("value_range".to_string()),
                constraint_index: Some(0),
            }
        );

        let rendered = zkf_core::ZkfError::from(error).to_string();
        assert!(rendered.contains("signal value"));
        assert!(rendered.contains("constraint #0"));
        assert!(rendered.contains("value_range"));
    }

    #[test]
    fn fast_runtime_lowering_handles_deep_expression_trees() {
        let handle = std::thread::Builder::new()
            .name("plonky3-deep-lowering-test".to_string())
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut expr = Expr::signal("x");
                for _ in 0..20_000 {
                    expr = Expr::Sub(
                        Box::new(expr),
                        Box::new(Expr::Const(FieldElement::from_u64(0))),
                    );
                }
                let program = Program {
                    field: FieldId::Goldilocks,
                    signals: vec![
                        Signal {
                            name: "x".to_string(),
                            visibility: Visibility::Private,
                            constant: None,
                            ty: None,
                        },
                        Signal {
                            name: "out".to_string(),
                            visibility: Visibility::Public,
                            constant: None,
                            ty: None,
                        },
                    ],
                    constraints: vec![Constraint::Equal {
                        lhs: Expr::signal("out"),
                        rhs: expr,
                        label: Some("deep_expr".to_string()),
                    }],
                    ..Default::default()
                };

                let lowered =
                    lower_program_runtime_fast(&program).expect("deep runtime lowering should pass");
                assert_eq!(lowered.base_signal_count, 2);
                assert_eq!(lowered.constraints.len(), 1);
                std::mem::forget(lowered);
                std::mem::forget(program);
            })
            .expect("deep lowering worker should spawn");

        handle
            .join()
            .expect("deep runtime lowering worker should not panic");
    }

    #[test]
    fn trace_row_computes_division_and_range_bits() {
        let program = sample_program();
        let lowered = lower_program(&program).expect("lowering should pass");
        let mut values = BTreeMap::new();
        values.insert("a".to_string(), FieldElement::from_u64(4));
        values.insert("b".to_string(), FieldElement::from_u64(20));
        values.insert("c".to_string(), FieldElement::from_u64(5));
        let witness = Witness { values };
        let row =
            build_trace_row(&lowered, &witness, program.field).expect("trace row should build");
        let fast_row = build_trace_row_runtime_fast(&lowered, &witness, program.field)
            .expect("fast trace row should build");
        let modulus = super::field_modulus_u64(program.field).expect("supported field");

        assert_eq!(fast_row, row);

        for constraint in &lowered.constraints {
            assert_eq!(
                eval_air_expr_concrete_checked(constraint, &row, modulus)
                    .expect("constraint evaluation should remain in bounds"),
                0
            );
        }
        assert_eq!(
            eval_air_expr_concrete_checked(&AirExpr::Signal(2), &row, modulus)
                .expect("signal access should remain in bounds"),
            5
        );
    }
}
