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

use super::ZirLowering;
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{BackendKind, ZkfResult};

/// AIR expression for Plonky3 STARK.
#[derive(Debug, Clone)]
pub enum AirExpr {
    Const(u64),
    TraceCol(usize),
    Add(Box<AirExpr>, Box<AirExpr>),
    Sub(Box<AirExpr>, Box<AirExpr>),
    Mul(Box<AirExpr>, Box<AirExpr>),
}

/// Derived column computed from base signals.
#[derive(Debug, Clone)]
pub enum DerivedComputation {
    Division {
        numerator: usize,
        denominator: usize,
    },
    RangeBit {
        source: usize,
        bit: u32,
    },
}

/// A derived column added to the trace.
#[derive(Debug, Clone)]
pub struct DerivedColumn {
    pub index: usize,
    pub computation: DerivedComputation,
}

/// Lowered AIR representation for Plonky3.
#[derive(Debug, Clone)]
pub struct Plonky3LoweredIr {
    pub trace_width: usize,
    pub base_signal_count: usize,
    pub signal_order: Vec<String>,
    pub signal_indices: BTreeMap<String, usize>,
    pub public_signal_indices: Vec<usize>,
    pub air_constraints: Vec<AirExpr>,
    pub derived_columns: Vec<DerivedColumn>,
    pub field: zkf_core::FieldId,
    pub metadata: BTreeMap<String, String>,
}

pub struct Plonky3Lowering;

impl ZirLowering for Plonky3Lowering {
    type LoweredIr = Plonky3LoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::Plonky3
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<Plonky3LoweredIr> {
        let mut signal_indices = BTreeMap::new();
        let mut signal_order = Vec::new();
        let mut public_signal_indices = Vec::new();

        for (i, signal) in program.signals.iter().enumerate() {
            signal_indices.insert(signal.name.clone(), i);
            signal_order.push(signal.name.clone());
            if signal.visibility == zkf_core::Visibility::Public {
                public_signal_indices.push(i);
            }
        }

        let base_signal_count = program.signals.len();
        let mut next_col = base_signal_count;
        let mut derived_columns = Vec::new();
        let mut air_constraints = Vec::new();

        for constraint in &program.constraints {
            lower_air_constraint(
                constraint,
                &signal_indices,
                &mut air_constraints,
                &mut derived_columns,
                &mut signal_order,
                &mut next_col,
            )?;
        }

        let trace_width = next_col;

        Ok(Plonky3LoweredIr {
            trace_width,
            base_signal_count,
            signal_order,
            signal_indices,
            public_signal_indices,
            air_constraints,
            derived_columns,
            field: program.field,
            metadata: program.metadata.clone(),
        })
    }
}

fn lower_air_constraint(
    constraint: &zir::Constraint,
    indices: &BTreeMap<String, usize>,
    air: &mut Vec<AirExpr>,
    derived: &mut Vec<DerivedColumn>,
    signal_order: &mut Vec<String>,
    next_col: &mut usize,
) -> ZkfResult<()> {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, .. } => {
            let l = lower_air_expr(lhs, indices, derived, signal_order, next_col)?;
            let r = lower_air_expr(rhs, indices, derived, signal_order, next_col)?;
            air.push(AirExpr::Sub(Box::new(l), Box::new(r)));
        }
        zir::Constraint::Boolean { signal, .. } => {
            if let Some(&idx) = indices.get(signal) {
                // s * (1 - s) = 0
                air.push(AirExpr::Mul(
                    Box::new(AirExpr::TraceCol(idx)),
                    Box::new(AirExpr::Sub(
                        Box::new(AirExpr::Const(1)),
                        Box::new(AirExpr::TraceCol(idx)),
                    )),
                ));
            }
        }
        zir::Constraint::Range { signal, bits, .. } => {
            if let Some(&source_idx) = indices.get(signal) {
                // Native field decomposition for Plonky3:
                // Create bit columns and constrain each to be boolean,
                // then constrain recombination.
                let mut bit_indices = Vec::new();
                for bit in 0..*bits {
                    let col_idx = *next_col;
                    *next_col += 1;
                    signal_order.push(format!("__range_bit_{}_{}_{}", signal, bit, col_idx));
                    derived.push(DerivedColumn {
                        index: col_idx,
                        computation: DerivedComputation::RangeBit {
                            source: source_idx,
                            bit,
                        },
                    });
                    // Boolean constraint for this bit.
                    air.push(AirExpr::Mul(
                        Box::new(AirExpr::TraceCol(col_idx)),
                        Box::new(AirExpr::Sub(
                            Box::new(AirExpr::Const(1)),
                            Box::new(AirExpr::TraceCol(col_idx)),
                        )),
                    ));
                    bit_indices.push(col_idx);
                }
                // Recombination: sum(bit_i * 2^i) - source = 0.
                let mut recombination = AirExpr::Const(0);
                for (i, &bit_col) in bit_indices.iter().enumerate() {
                    let weighted = AirExpr::Mul(
                        Box::new(AirExpr::Const(1u64 << i)),
                        Box::new(AirExpr::TraceCol(bit_col)),
                    );
                    recombination = AirExpr::Add(Box::new(recombination), Box::new(weighted));
                }
                air.push(AirExpr::Sub(
                    Box::new(recombination),
                    Box::new(AirExpr::TraceCol(source_idx)),
                ));
            }
        }
        zir::Constraint::Lookup { .. } => {
            // Plonky3 AIR doesn't natively support lookups yet;
            // would require LogUp or similar protocol extension.
        }
        zir::Constraint::CustomGate { inputs, .. } => {
            // Custom gates map to custom AIR constraints.
            // For now, evaluate inputs as product = 0.
            if !inputs.is_empty() {
                let mut expr =
                    lower_air_expr(&inputs[0], indices, derived, signal_order, next_col)?;
                for input in &inputs[1..] {
                    let e = lower_air_expr(input, indices, derived, signal_order, next_col)?;
                    expr = AirExpr::Mul(Box::new(expr), Box::new(e));
                }
                air.push(expr);
            }
        }
        zir::Constraint::MemoryRead { .. } | zir::Constraint::MemoryWrite { .. } => {
            // Memory ops require a permutation-based memory checking protocol.
            // In AIR, this is typically handled via LogUp or multiset equality arguments,
            // which operate outside the transition constraint system.
        }
        zir::Constraint::BlackBox { .. } => {
            // Handled natively by the backend.
        }
        zir::Constraint::Permutation { left, right, .. } => {
            if let (Some(&l), Some(&r)) = (indices.get(left), indices.get(right)) {
                air.push(AirExpr::Sub(
                    Box::new(AirExpr::TraceCol(l)),
                    Box::new(AirExpr::TraceCol(r)),
                ));
            }
        }
        zir::Constraint::Copy { from, to, .. } => {
            if let (Some(&f), Some(&t)) = (indices.get(from), indices.get(to)) {
                air.push(AirExpr::Sub(
                    Box::new(AirExpr::TraceCol(f)),
                    Box::new(AirExpr::TraceCol(t)),
                ));
            }
        }
    }
    Ok(())
}

fn lower_air_expr(
    expr: &zir::Expr,
    indices: &BTreeMap<String, usize>,
    derived: &mut Vec<DerivedColumn>,
    signal_order: &mut Vec<String>,
    next_col: &mut usize,
) -> ZkfResult<AirExpr> {
    match expr {
        zir::Expr::Const(c) => {
            // Convert to u64; for AIR expressions we use u64.
            let val = c.as_bigint();
            let val_u64 = val.to_u64_digits().1.first().copied().unwrap_or(0);
            Ok(AirExpr::Const(val_u64))
        }
        zir::Expr::Signal(name) => {
            if let Some(&idx) = indices.get(name) {
                Ok(AirExpr::TraceCol(idx))
            } else {
                Ok(AirExpr::Const(0))
            }
        }
        zir::Expr::Add(values) => {
            let mut result = lower_air_expr(&values[0], indices, derived, signal_order, next_col)?;
            for value in &values[1..] {
                let e = lower_air_expr(value, indices, derived, signal_order, next_col)?;
                result = AirExpr::Add(Box::new(result), Box::new(e));
            }
            Ok(result)
        }
        zir::Expr::Sub(left, right) => {
            let l = lower_air_expr(left, indices, derived, signal_order, next_col)?;
            let r = lower_air_expr(right, indices, derived, signal_order, next_col)?;
            Ok(AirExpr::Sub(Box::new(l), Box::new(r)))
        }
        zir::Expr::Mul(left, right) => {
            let l = lower_air_expr(left, indices, derived, signal_order, next_col)?;
            let r = lower_air_expr(right, indices, derived, signal_order, next_col)?;
            Ok(AirExpr::Mul(Box::new(l), Box::new(r)))
        }
        zir::Expr::Div(left, right) => {
            // Division: introduce derived quotient column.
            // constraint: denom * quotient = numerator
            let l = lower_air_expr(left, indices, derived, signal_order, next_col)?;
            let r = lower_air_expr(right, indices, derived, signal_order, next_col)?;
            let quot_col = *next_col;
            *next_col += 1;
            signal_order.push(format!("__div_quot_{}", quot_col));

            // We need the column indices for numerator and denominator.
            // For complex expressions, we'd need to flatten first.
            // For now, store the derived column and return the quotient trace col.
            // The constraint denom * quot = num is added implicitly.
            let num_col = air_expr_col_index(&l).unwrap_or(quot_col);
            let den_col = air_expr_col_index(&r).unwrap_or(quot_col);
            derived.push(DerivedColumn {
                index: quot_col,
                computation: DerivedComputation::Division {
                    numerator: num_col,
                    denominator: den_col,
                },
            });

            Ok(AirExpr::TraceCol(quot_col))
        }
    }
}

/// Extract the trace column index from a simple AirExpr::TraceCol, if possible.
fn air_expr_col_index(expr: &AirExpr) -> Option<usize> {
    match expr {
        AirExpr::TraceCol(idx) => Some(*idx),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldId;

    #[test]
    fn lowers_simple_program() {
        let program = zir::Program {
            name: "p3_test".to_string(),
            field: FieldId::Goldilocks,
            signals: vec![
                zir::Signal {
                    name: "a".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "b".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir::Constraint::Equal {
                lhs: zir::Expr::Signal("a".to_string()),
                rhs: zir::Expr::Signal("b".to_string()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = Plonky3Lowering.lower(&program).unwrap();
        assert_eq!(lowered.base_signal_count, 2);
        assert_eq!(lowered.trace_width, 2); // no derived columns
        assert_eq!(lowered.air_constraints.len(), 1);
        assert_eq!(lowered.public_signal_indices, vec![1]);
    }

    #[test]
    fn range_creates_bit_columns() {
        let program = zir::Program {
            name: "p3_range".to_string(),
            field: FieldId::Goldilocks,
            signals: vec![zir::Signal {
                name: "v".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 4 },
                constant: None,
            }],
            constraints: vec![zir::Constraint::Range {
                signal: "v".to_string(),
                bits: 4,
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = Plonky3Lowering.lower(&program).unwrap();
        assert_eq!(lowered.derived_columns.len(), 4); // 4 bit columns
        assert_eq!(lowered.trace_width, 5); // 1 base + 4 derived
        // 4 boolean constraints + 1 recombination
        assert_eq!(lowered.air_constraints.len(), 5);
    }
}
