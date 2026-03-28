#![allow(dead_code)]

use crate::proof_plonky3_surface as surface;
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
            } => ZkfError::UnsupportedBackend {
                backend: "plonky3".to_string(),
                message: format!(
                    "plonky3 adapter currently supports range constraints up to {max_bits} bits for field {field}; found {bits}"
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
    surface::lower_program(&spec_program)
        .map(|lowered| to_runtime_lowered_program(&lowered))
        .map_err(from_surface_error)
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

#[cfg(test)]
mod tests {
    use super::{
        AirExpr, build_trace_row, eval_air_expr_concrete_checked, is_supported_plonky3_program,
        lower_program, public_input_positions_preserved_checked,
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
        let modulus = super::field_modulus_u64(program.field).expect("supported field");

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
