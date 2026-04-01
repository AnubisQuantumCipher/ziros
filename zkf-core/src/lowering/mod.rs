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

pub mod hir_to_zir;

use crate::ir as ir_v2;
use crate::zir;
use crate::{ZkfError, ZkfResult};
use std::collections::{BTreeMap, BTreeSet};

/// A report describing how the program was adapted/lowered for a specific backend.
///
/// Tracks which features were natively supported, which required adaptation,
/// which were delegated, and which had to be dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoweringReport {
    /// Features lowered without any transformation (directly supported by backend).
    pub native_features: Vec<String>,
    /// Features that required adaptation (e.g., BlackBox → arithmetic constraints).
    pub adapted_features: Vec<String>,
    /// Features delegated to an external system or host.
    pub delegated_features: Vec<String>,
    /// Features that could not be supported and were dropped.
    pub dropped_features: Vec<String>,
    /// Number of auxiliary variables introduced during lowering.
    pub aux_variable_count: usize,
    /// Constraint count before lowering.
    pub original_constraint_count: usize,
    /// Constraint count after lowering.
    pub final_constraint_count: usize,
    /// Human-readable description of any incompatibilities found.
    pub incompatibilities: Vec<String>,
}

pub fn program_v2_to_zir(program: &ir_v2::Program) -> zir::Program {
    let mut metadata = BTreeMap::new();
    metadata.insert("ir_family".to_string(), "zir-v1".to_string());
    metadata.insert("source_ir".to_string(), "ir-v2".to_string());
    metadata.insert("program_digest_v2".to_string(), program.digest_hex());
    let inferred_signal_types = collect_inferred_signal_types(program);

    zir::Program {
        name: program.name.clone(),
        field: program.field,
        signals: program
            .signals
            .iter()
            .map(|signal| zir::Signal {
                name: signal.name.clone(),
                visibility: signal.visibility.clone(),
                ty: signal
                    .ty
                    .as_deref()
                    .and_then(parse_signal_type)
                    .unwrap_or_else(|| {
                        infer_signal_type(signal.name.as_str(), &inferred_signal_types)
                    }),
                constant: signal.constant.clone(),
            })
            .collect(),
        constraints: program
            .constraints
            .iter()
            .map(constraint_v2_to_zir)
            .collect(),
        witness_plan: zir::WitnessPlan {
            assignments: program
                .witness_plan
                .assignments
                .iter()
                .map(|assignment| zir::WitnessAssignment {
                    target: assignment.target.clone(),
                    expr: expr_v2_to_zir(&assignment.expr),
                })
                .collect(),
            hints: program
                .witness_plan
                .hints
                .iter()
                .map(|hint| zir::WitnessHint {
                    target: hint.target.clone(),
                    source: hint.source.clone(),
                    kind: match hint.kind {
                        ir_v2::WitnessHintKind::Copy => zir::WitnessHintKind::Copy,
                        ir_v2::WitnessHintKind::InverseOrZero => {
                            zir::WitnessHintKind::InverseOrZero
                        }
                    },
                })
                .collect(),
            acir_program_bytes: program.witness_plan.acir_program_bytes.clone(),
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata,
    }
}

pub fn program_v2_into_zir(program: ir_v2::Program) -> zir::Program {
    let mut metadata = BTreeMap::new();
    metadata.insert("ir_family".to_string(), "zir-v1".to_string());
    metadata.insert("source_ir".to_string(), "ir-v2".to_string());
    metadata.insert("program_digest_v2".to_string(), program.digest_hex());
    let inferred_signal_types = collect_inferred_signal_types(&program);

    let signal_types = program
        .signals
        .iter()
        .map(|signal| {
            signal
                .ty
                .as_deref()
                .and_then(parse_signal_type)
                .unwrap_or_else(|| infer_signal_type(signal.name.as_str(), &inferred_signal_types))
        })
        .collect::<Vec<_>>();

    let ir_v2::Program {
        name,
        field,
        signals,
        constraints,
        witness_plan,
        lookup_tables: _,
        metadata: _,
    } = program;
    let ir_v2::WitnessPlan {
        assignments,
        hints,
        input_aliases: _,
        acir_program_bytes,
    } = witness_plan;

    zir::Program {
        name,
        field,
        signals: signals
            .into_iter()
            .zip(signal_types)
            .map(|(signal, ty)| zir::Signal {
                name: signal.name,
                visibility: signal.visibility,
                ty,
                constant: signal.constant,
            })
            .collect(),
        constraints: constraints
            .into_iter()
            .map(constraint_v2_into_zir)
            .collect(),
        witness_plan: zir::WitnessPlan {
            assignments: assignments
                .into_iter()
                .map(|assignment| zir::WitnessAssignment {
                    target: assignment.target,
                    expr: expr_v2_into_zir(assignment.expr),
                })
                .collect(),
            hints: hints
                .into_iter()
                .map(|hint| zir::WitnessHint {
                    target: hint.target,
                    source: hint.source,
                    kind: match hint.kind {
                        ir_v2::WitnessHintKind::Copy => zir::WitnessHintKind::Copy,
                        ir_v2::WitnessHintKind::InverseOrZero => {
                            zir::WitnessHintKind::InverseOrZero
                        }
                    },
                })
                .collect(),
            acir_program_bytes,
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata,
    }
}

pub fn program_zir_to_v2(program: &zir::Program) -> ZkfResult<ir_v2::Program> {
    let mut constraints = Vec::with_capacity(program.constraints.len());
    for constraint in &program.constraints {
        constraints.push(constraint_zir_to_v2(constraint)?);
    }

    Ok(ir_v2::Program {
        name: program.name.clone(),
        field: program.field,
        signals: program
            .signals
            .iter()
            .map(|signal| ir_v2::Signal {
                name: signal.name.clone(),
                visibility: signal.visibility.clone(),
                constant: signal.constant.clone(),
                ty: Some(format_signal_type(&signal.ty)),
            })
            .collect(),
        constraints,
        witness_plan: ir_v2::WitnessPlan {
            assignments: program
                .witness_plan
                .assignments
                .iter()
                .map(|assignment| ir_v2::WitnessAssignment {
                    target: assignment.target.clone(),
                    expr: expr_zir_to_v2(&assignment.expr),
                })
                .collect(),
            hints: program
                .witness_plan
                .hints
                .iter()
                .map(|hint| ir_v2::WitnessHint {
                    target: hint.target.clone(),
                    source: hint.source.clone(),
                    kind: match hint.kind {
                        zir::WitnessHintKind::Copy => ir_v2::WitnessHintKind::Copy,
                        zir::WitnessHintKind::InverseOrZero => {
                            ir_v2::WitnessHintKind::InverseOrZero
                        }
                    },
                })
                .collect(),
            input_aliases: BTreeMap::new(),
            acir_program_bytes: program.witness_plan.acir_program_bytes.clone(),
        },
        lookup_tables: program
            .lookup_tables
            .iter()
            .map(|t| ir_v2::LookupTable {
                name: t.name.clone(),
                columns: (0..t.columns).map(|i| i.to_string()).collect(),
                values: t.values.clone(),
            })
            .collect(),
        metadata: program.metadata.clone(),
    })
}

fn collect_inferred_signal_types(program: &ir_v2::Program) -> BTreeMap<String, zir::SignalType> {
    let mut bool_signals = BTreeSet::new();
    let mut range_signals = BTreeMap::new();

    for constraint in &program.constraints {
        match constraint {
            ir_v2::Constraint::Boolean { signal, .. } => {
                bool_signals.insert(signal.as_str());
            }
            ir_v2::Constraint::Range { signal, bits, .. } => {
                range_signals
                    .entry(signal.as_str())
                    .or_insert(zir::SignalType::UInt { bits: *bits });
            }
            _ => {}
        }
    }

    let mut inferred = BTreeMap::new();
    for signal in &program.signals {
        if bool_signals.contains(signal.name.as_str()) {
            inferred.insert(signal.name.clone(), zir::SignalType::Bool);
        } else if let Some(ty) = range_signals.get(signal.name.as_str()) {
            inferred.insert(signal.name.clone(), ty.clone());
        }
    }

    inferred
}

fn infer_signal_type(
    name: &str,
    inferred_signal_types: &BTreeMap<String, zir::SignalType>,
) -> zir::SignalType {
    inferred_signal_types
        .get(name)
        .cloned()
        .unwrap_or(zir::SignalType::Field)
}

fn format_signal_type(ty: &zir::SignalType) -> String {
    match ty {
        zir::SignalType::Field => "field".to_string(),
        zir::SignalType::Bool => "bool".to_string(),
        zir::SignalType::UInt { bits } => format!("uint({bits})"),
        zir::SignalType::Array { element, len } => {
            format!("array({len},{})", format_signal_type(element))
        }
        zir::SignalType::Tuple { elements } => format!(
            "tuple({})",
            elements
                .iter()
                .map(format_signal_type)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn parse_signal_type(ty: &str) -> Option<zir::SignalType> {
    let ty = ty.trim();
    match ty {
        "field" => Some(zir::SignalType::Field),
        "bool" => Some(zir::SignalType::Bool),
        _ if ty.starts_with("uint(") && ty.ends_with(')') => ty[5..ty.len() - 1]
            .parse::<u32>()
            .ok()
            .map(|bits| zir::SignalType::UInt { bits }),
        _ if ty.starts_with("array(") && ty.ends_with(')') => {
            let parts = split_top_level(&ty[6..ty.len() - 1]);
            if parts.len() != 2 {
                return None;
            }
            Some(zir::SignalType::Array {
                len: parts[0].parse::<u32>().ok()?,
                element: Box::new(parse_signal_type(parts[1])?),
            })
        }
        _ if ty.starts_with("tuple(") && ty.ends_with(')') => {
            let inner = &ty[6..ty.len() - 1];
            let elements = if inner.is_empty() {
                Vec::new()
            } else {
                split_top_level(inner)
                    .into_iter()
                    .map(parse_signal_type)
                    .collect::<Option<Vec<_>>>()?
            };
            Some(zir::SignalType::Tuple { elements })
        }
        _ => None,
    }
}

fn split_top_level(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;

    for (index, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }

    parts.push(input[start..].trim());
    parts
}

fn expr_v2_to_zir(expr: &ir_v2::Expr) -> zir::Expr {
    match expr {
        ir_v2::Expr::Const(value) => zir::Expr::Const(value.clone()),
        ir_v2::Expr::Signal(name) => zir::Expr::Signal(name.clone()),
        ir_v2::Expr::Add(values) => zir::Expr::Add(values.iter().map(expr_v2_to_zir).collect()),
        ir_v2::Expr::Sub(left, right) => zir::Expr::Sub(
            Box::new(expr_v2_to_zir(left)),
            Box::new(expr_v2_to_zir(right)),
        ),
        ir_v2::Expr::Mul(left, right) => zir::Expr::Mul(
            Box::new(expr_v2_to_zir(left)),
            Box::new(expr_v2_to_zir(right)),
        ),
        ir_v2::Expr::Div(left, right) => zir::Expr::Div(
            Box::new(expr_v2_to_zir(left)),
            Box::new(expr_v2_to_zir(right)),
        ),
    }
}

fn expr_v2_into_zir(expr: ir_v2::Expr) -> zir::Expr {
    match expr {
        ir_v2::Expr::Const(value) => zir::Expr::Const(value),
        ir_v2::Expr::Signal(name) => zir::Expr::Signal(name),
        ir_v2::Expr::Add(values) => {
            zir::Expr::Add(values.into_iter().map(expr_v2_into_zir).collect())
        }
        ir_v2::Expr::Sub(left, right) => zir::Expr::Sub(
            Box::new(expr_v2_into_zir(*left)),
            Box::new(expr_v2_into_zir(*right)),
        ),
        ir_v2::Expr::Mul(left, right) => zir::Expr::Mul(
            Box::new(expr_v2_into_zir(*left)),
            Box::new(expr_v2_into_zir(*right)),
        ),
        ir_v2::Expr::Div(left, right) => zir::Expr::Div(
            Box::new(expr_v2_into_zir(*left)),
            Box::new(expr_v2_into_zir(*right)),
        ),
    }
}

fn expr_zir_to_v2(expr: &zir::Expr) -> ir_v2::Expr {
    match expr {
        zir::Expr::Const(value) => ir_v2::Expr::Const(value.clone()),
        zir::Expr::Signal(name) => ir_v2::Expr::Signal(name.clone()),
        zir::Expr::Add(values) => ir_v2::Expr::Add(values.iter().map(expr_zir_to_v2).collect()),
        zir::Expr::Sub(left, right) => ir_v2::Expr::Sub(
            Box::new(expr_zir_to_v2(left)),
            Box::new(expr_zir_to_v2(right)),
        ),
        zir::Expr::Mul(left, right) => ir_v2::Expr::Mul(
            Box::new(expr_zir_to_v2(left)),
            Box::new(expr_zir_to_v2(right)),
        ),
        zir::Expr::Div(left, right) => ir_v2::Expr::Div(
            Box::new(expr_zir_to_v2(left)),
            Box::new(expr_zir_to_v2(right)),
        ),
    }
}

fn blackbox_v2_to_zir(op: ir_v2::BlackBoxOp) -> zir::BlackBoxOp {
    match op {
        ir_v2::BlackBoxOp::Poseidon => zir::BlackBoxOp::Poseidon,
        ir_v2::BlackBoxOp::Sha256 => zir::BlackBoxOp::Sha256,
        ir_v2::BlackBoxOp::Keccak256 => zir::BlackBoxOp::Keccak256,
        ir_v2::BlackBoxOp::Pedersen => zir::BlackBoxOp::Pedersen,
        ir_v2::BlackBoxOp::EcdsaSecp256k1 => zir::BlackBoxOp::EcdsaSecp256k1,
        ir_v2::BlackBoxOp::EcdsaSecp256r1 => zir::BlackBoxOp::EcdsaSecp256r1,
        ir_v2::BlackBoxOp::SchnorrVerify => zir::BlackBoxOp::SchnorrVerify,
        ir_v2::BlackBoxOp::Blake2s => zir::BlackBoxOp::Blake2s,
        ir_v2::BlackBoxOp::RecursiveAggregationMarker => {
            zir::BlackBoxOp::RecursiveAggregationMarker
        }
        ir_v2::BlackBoxOp::ScalarMulG1 => zir::BlackBoxOp::ScalarMulG1,
        ir_v2::BlackBoxOp::PointAddG1 => zir::BlackBoxOp::PointAddG1,
        ir_v2::BlackBoxOp::PairingCheck => zir::BlackBoxOp::PairingCheck,
    }
}

fn blackbox_zir_to_v2(op: zir::BlackBoxOp) -> ZkfResult<ir_v2::BlackBoxOp> {
    match op {
        zir::BlackBoxOp::Poseidon => Ok(ir_v2::BlackBoxOp::Poseidon),
        zir::BlackBoxOp::Sha256 => Ok(ir_v2::BlackBoxOp::Sha256),
        zir::BlackBoxOp::Keccak256 => Ok(ir_v2::BlackBoxOp::Keccak256),
        zir::BlackBoxOp::Pedersen => Ok(ir_v2::BlackBoxOp::Pedersen),
        zir::BlackBoxOp::EcdsaSecp256k1 => Ok(ir_v2::BlackBoxOp::EcdsaSecp256k1),
        zir::BlackBoxOp::EcdsaSecp256r1 => Ok(ir_v2::BlackBoxOp::EcdsaSecp256r1),
        zir::BlackBoxOp::SchnorrVerify => Ok(ir_v2::BlackBoxOp::SchnorrVerify),
        zir::BlackBoxOp::Blake2s => Ok(ir_v2::BlackBoxOp::Blake2s),
        zir::BlackBoxOp::RecursiveAggregationMarker => {
            Ok(ir_v2::BlackBoxOp::RecursiveAggregationMarker)
        }
        zir::BlackBoxOp::ScalarMulG1 => Ok(ir_v2::BlackBoxOp::ScalarMulG1),
        zir::BlackBoxOp::PointAddG1 => Ok(ir_v2::BlackBoxOp::PointAddG1),
        zir::BlackBoxOp::PairingCheck => Ok(ir_v2::BlackBoxOp::PairingCheck),
    }
}

fn constraint_v2_to_zir(constraint: &ir_v2::Constraint) -> zir::Constraint {
    match constraint {
        ir_v2::Constraint::Equal { lhs, rhs, label } => zir::Constraint::Equal {
            lhs: expr_v2_to_zir(lhs),
            rhs: expr_v2_to_zir(rhs),
            label: label.clone(),
        },
        ir_v2::Constraint::Boolean { signal, label } => zir::Constraint::Boolean {
            signal: signal.clone(),
            label: label.clone(),
        },
        ir_v2::Constraint::Range {
            signal,
            bits,
            label,
        } => zir::Constraint::Range {
            signal: signal.clone(),
            bits: *bits,
            label: label.clone(),
        },
        ir_v2::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => zir::Constraint::BlackBox {
            op: blackbox_v2_to_zir(*op),
            inputs: inputs.iter().map(expr_v2_to_zir).collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        ir_v2::Constraint::Lookup {
            inputs,
            table,
            label,
            ..
        } => zir::Constraint::Lookup {
            inputs: inputs.iter().map(expr_v2_to_zir).collect(),
            table: table.clone(),
            label: label.clone(),
        },
    }
}

fn constraint_v2_into_zir(constraint: ir_v2::Constraint) -> zir::Constraint {
    match constraint {
        ir_v2::Constraint::Equal { lhs, rhs, label } => zir::Constraint::Equal {
            lhs: expr_v2_into_zir(lhs),
            rhs: expr_v2_into_zir(rhs),
            label,
        },
        ir_v2::Constraint::Boolean { signal, label } => zir::Constraint::Boolean { signal, label },
        ir_v2::Constraint::Range {
            signal,
            bits,
            label,
        } => zir::Constraint::Range {
            signal,
            bits,
            label,
        },
        ir_v2::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => zir::Constraint::BlackBox {
            op: blackbox_v2_to_zir(op),
            inputs: inputs.into_iter().map(expr_v2_into_zir).collect(),
            outputs,
            params,
            label,
        },
        ir_v2::Constraint::Lookup {
            inputs,
            table,
            label,
            ..
        } => zir::Constraint::Lookup {
            inputs: inputs.into_iter().map(expr_v2_into_zir).collect(),
            table,
            label,
        },
    }
}

fn constraint_zir_to_v2(constraint: &zir::Constraint) -> ZkfResult<ir_v2::Constraint> {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => Ok(ir_v2::Constraint::Equal {
            lhs: expr_zir_to_v2(lhs),
            rhs: expr_zir_to_v2(rhs),
            label: label.clone(),
        }),
        zir::Constraint::Boolean { signal, label } => Ok(ir_v2::Constraint::Boolean {
            signal: signal.clone(),
            label: label.clone(),
        }),
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => Ok(ir_v2::Constraint::Range {
            signal: signal.clone(),
            bits: *bits,
            label: label.clone(),
        }),
        zir::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => Ok(ir_v2::Constraint::BlackBox {
            op: blackbox_zir_to_v2(*op)?,
            inputs: inputs.iter().map(expr_zir_to_v2).collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        }),
        zir::Constraint::Permutation { left, right, label } => Ok(ir_v2::Constraint::Equal {
            lhs: ir_v2::Expr::Signal(left.clone()),
            rhs: ir_v2::Expr::Signal(right.clone()),
            label: label.clone(),
        }),
        zir::Constraint::Copy { from, to, label } => Ok(ir_v2::Constraint::Equal {
            lhs: ir_v2::Expr::Signal(from.clone()),
            rhs: ir_v2::Expr::Signal(to.clone()),
            label: label.clone(),
        }),
        zir::Constraint::Lookup {
            inputs,
            table,
            label,
        } => Ok(ir_v2::Constraint::Lookup {
            inputs: inputs.iter().map(expr_zir_to_v2).collect(),
            table: table.clone(),
            outputs: None,
            label: label.clone(),
        }),
        zir::Constraint::CustomGate { gate, .. } => Err(ZkfError::UnsupportedBackend {
            backend: "zir-to-ir-v2".to_string(),
            message: format!("custom gate '{}' is not representable in ir-v2", gate),
        }),
        zir::Constraint::MemoryRead { memory, .. } => Err(ZkfError::UnsupportedBackend {
            backend: "zir-to-ir-v2".to_string(),
            message: format!("memory read for '{}' is not representable in ir-v2", memory),
        }),
        zir::Constraint::MemoryWrite { memory, .. } => Err(ZkfError::UnsupportedBackend {
            backend: "zir-to-ir-v2".to_string(),
            message: format!(
                "memory write for '{}' is not representable in ir-v2",
                memory
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir;
    use crate::{
        Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessPlan,
    };

    #[test]
    fn v2_to_zir_roundtrip_preserves_supported_subset() {
        let program = Program {
            name: "bridge".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: Some("uint(8)".to_string()),
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: Some("bool".to_string()),
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("x".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("eq".to_string()),
                },
                Constraint::Range {
                    signal: "x".to_string(),
                    bits: 8,
                    label: Some("range".to_string()),
                },
                Constraint::BlackBox {
                    op: ir::BlackBoxOp::Sha256,
                    inputs: vec![Expr::Signal("x".to_string())],
                    outputs: vec!["y".to_string()],
                    params: BTreeMap::new(),
                    label: Some("bb".to_string()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        };

        let zir = program_v2_to_zir(&program);
        let restored = program_zir_to_v2(&zir).expect("zir subset should be convertible");
        assert_eq!(restored.name, program.name);
        assert_eq!(restored.field, program.field);
        assert_eq!(restored.signals, program.signals);
        assert_eq!(restored.constraints, program.constraints);
    }

    #[test]
    fn zir_signal_types_are_preserved_in_v2() {
        let program = zir::Program {
            name: "typed".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "flag".to_string(),
                    visibility: Visibility::Private,
                    ty: zir::SignalType::Bool,
                    constant: None,
                },
                zir::Signal {
                    name: "word".to_string(),
                    visibility: Visibility::Private,
                    ty: zir::SignalType::UInt { bits: 16 },
                    constant: None,
                },
                zir::Signal {
                    name: "tupled".to_string(),
                    visibility: Visibility::Private,
                    ty: zir::SignalType::Tuple {
                        elements: vec![
                            zir::SignalType::Field,
                            zir::SignalType::Array {
                                element: Box::new(zir::SignalType::Bool),
                                len: 2,
                            },
                        ],
                    },
                    constant: None,
                },
            ],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = program_zir_to_v2(&program).expect("typed program should lower");
        assert_eq!(lowered.signals[0].ty.as_deref(), Some("bool"));
        assert_eq!(lowered.signals[1].ty.as_deref(), Some("uint(16)"));
        assert_eq!(
            lowered.signals[2].ty.as_deref(),
            Some("tuple(field,array(2,bool))")
        );

        let restored = program_v2_to_zir(&lowered);
        assert_eq!(restored.signals, program.signals);
    }

    #[test]
    fn zir_poseidon_is_convertible_to_v2() {
        let program = zir::Program {
            name: "zir_poseidon".to_string(),
            field: FieldId::Bn254,
            signals: vec![],
            constraints: vec![zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Poseidon,
                inputs: vec![zir::Expr::Const(FieldElement::from_i64(1))],
                outputs: vec!["o".to_string()],
                params: BTreeMap::new(),
                label: Some("poseidon".to_string()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = program_zir_to_v2(&program).expect("poseidon should map into ir-v2");
        assert!(
            matches!(
                lowered.constraints.as_slice(),
                [ir::Constraint::BlackBox {
                    op: ir::BlackBoxOp::Poseidon,
                    ..
                }]
            ),
            "expected poseidon blackbox constraint after lowering"
        );
    }

    #[test]
    fn zir_lookup_is_preserved_in_v2_bridge() {
        let program = zir::Program {
            name: "zir_lookup".to_string(),
            field: FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![zir::Constraint::Lookup {
                inputs: vec![zir::Expr::Signal("x".to_string())],
                table: "small".to_string(),
                label: Some("lookup".to_string()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![zir::LookupTable {
                name: "small".to_string(),
                columns: 1,
                values: vec![
                    vec![FieldElement::from_i64(0)],
                    vec![FieldElement::from_i64(1)],
                ],
            }],
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = program_zir_to_v2(&program).expect("lookup should map into ir-v2");
        assert!(
            matches!(
                lowered.constraints.as_slice(),
                [ir::Constraint::Lookup {
                    table,
                    outputs: None,
                    ..
                }] if table == "small"
            ),
            "expected lookup constraint after lowering"
        );
    }
}
