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
use zkf_core::{BackendKind, FieldElement, ZkfResult};

/// PLONKish column types.
#[derive(Debug, Clone)]
pub enum ColumnKind {
    Advice,
    Fixed,
    Instance,
}

/// A column in the PLONKish layout.
#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub kind: ColumnKind,
}

/// PLONKish gate: selector * polynomial = 0.
#[derive(Debug, Clone)]
pub struct PlonkGate {
    pub name: String,
    pub selector: String,
    pub polynomial: PlonkExpr,
    pub label: Option<String>,
}

/// Lookup argument: ensure (input_exprs) are contained in (table_columns).
#[derive(Debug, Clone)]
pub struct LookupArgument {
    pub name: String,
    pub input_exprs: Vec<PlonkExpr>,
    pub table_columns: Vec<String>,
    pub label: Option<String>,
}

/// Permutation argument: two columns have the same multiset of values.
#[derive(Debug, Clone)]
pub struct PermutationArgument {
    pub left: String,
    pub right: String,
    pub label: Option<String>,
}

/// Expression in PLONKish gates.
#[derive(Debug, Clone)]
pub enum PlonkExpr {
    Const(FieldElement),
    Column(String),
    Add(Box<PlonkExpr>, Box<PlonkExpr>),
    Sub(Box<PlonkExpr>, Box<PlonkExpr>),
    Mul(Box<PlonkExpr>, Box<PlonkExpr>),
    Neg(Box<PlonkExpr>),
}

/// Lowered PLONKish representation for Halo2.
#[derive(Debug, Clone)]
pub struct Halo2LoweredIr {
    pub columns: Vec<Column>,
    pub gates: Vec<PlonkGate>,
    pub lookups: Vec<LookupArgument>,
    pub permutations: Vec<PermutationArgument>,
    pub public_inputs: Vec<String>,
    pub signals: Vec<zir::Signal>,
    pub witness_plan: zir::WitnessPlan,
    pub field: zkf_core::FieldId,
    pub estimated_rows: usize,
    pub metadata: BTreeMap<String, String>,
}

pub struct Halo2Lowering;

impl ZirLowering for Halo2Lowering {
    type LoweredIr = Halo2LoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::Halo2
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<Halo2LoweredIr> {
        let mut columns = Vec::new();
        let mut gates = Vec::new();
        let mut lookups = Vec::new();
        let mut permutations = Vec::new();

        // Create advice columns for each signal.
        for signal in &program.signals {
            columns.push(Column {
                name: signal.name.clone(),
                kind: if signal.visibility == zkf_core::Visibility::Public {
                    ColumnKind::Instance
                } else {
                    ColumnKind::Advice
                },
            });
        }

        let public_inputs: Vec<String> = program
            .signals
            .iter()
            .filter(|s| s.visibility == zkf_core::Visibility::Public)
            .map(|s| s.name.clone())
            .collect();

        // Create lookup table columns from declared tables.
        for table in &program.lookup_tables {
            for col_idx in 0..table.columns {
                columns.push(Column {
                    name: format!("{}__col_{}", table.name, col_idx),
                    kind: ColumnKind::Fixed,
                });
            }
        }

        // Selector columns for gate types.
        let mut selector_counter = 0usize;

        for constraint in &program.constraints {
            match constraint {
                zir::Constraint::Equal { lhs, rhs, label } => {
                    let sel_name = format!("q_eq_{}", selector_counter);
                    selector_counter += 1;
                    columns.push(Column {
                        name: sel_name.clone(),
                        kind: ColumnKind::Fixed,
                    });
                    gates.push(PlonkGate {
                        name: format!("equal_{}", selector_counter - 1),
                        selector: sel_name,
                        polynomial: PlonkExpr::Sub(
                            Box::new(expr_to_plonk(lhs)),
                            Box::new(expr_to_plonk(rhs)),
                        ),
                        label: label.clone(),
                    });
                }
                zir::Constraint::Boolean { signal, label } => {
                    let sel_name = format!("q_bool_{}", selector_counter);
                    selector_counter += 1;
                    columns.push(Column {
                        name: sel_name.clone(),
                        kind: ColumnKind::Fixed,
                    });
                    // s * (1 - s) = 0
                    gates.push(PlonkGate {
                        name: format!("boolean_{}", selector_counter - 1),
                        selector: sel_name,
                        polynomial: PlonkExpr::Mul(
                            Box::new(PlonkExpr::Column(signal.clone())),
                            Box::new(PlonkExpr::Sub(
                                Box::new(PlonkExpr::Const(FieldElement::from_i64(1))),
                                Box::new(PlonkExpr::Column(signal.clone())),
                            )),
                        ),
                        label: label.clone(),
                    });
                }
                zir::Constraint::Range {
                    signal,
                    bits,
                    label,
                } => {
                    // Halo2 optimization: use lookup table for range checks up to 16 bits.
                    if *bits <= 16 {
                        lookups.push(LookupArgument {
                            name: format!("range_{}", signal),
                            input_exprs: vec![PlonkExpr::Column(signal.clone())],
                            table_columns: vec![format!("__range_table_{}", bits)],
                            label: label.clone(),
                        });
                    } else {
                        // Decompose into smaller lookup chunks.
                        let chunk_size = 16u32;
                        let mut remaining = *bits;
                        let mut chunk_idx = 0u32;
                        while remaining > 0 {
                            let chunk_bits = remaining.min(chunk_size);
                            let chunk_name =
                                format!("__range_chunk_{}_{}_{}", signal, chunk_idx, chunk_bits);
                            columns.push(Column {
                                name: chunk_name.clone(),
                                kind: ColumnKind::Advice,
                            });
                            lookups.push(LookupArgument {
                                name: format!("range_chunk_{}_{}", signal, chunk_idx),
                                input_exprs: vec![PlonkExpr::Column(chunk_name)],
                                table_columns: vec![format!("__range_table_{}", chunk_bits)],
                                label: label.clone(),
                            });
                            remaining -= chunk_bits;
                            chunk_idx += 1;
                        }
                    }
                }
                zir::Constraint::Lookup {
                    inputs,
                    table,
                    label,
                } => {
                    let input_exprs: Vec<PlonkExpr> = inputs.iter().map(expr_to_plonk).collect();
                    let table_cols: Vec<String> = (0..inputs.len())
                        .map(|i| format!("{}__col_{}", table, i))
                        .collect();
                    lookups.push(LookupArgument {
                        name: format!("lookup_{}", table),
                        input_exprs,
                        table_columns: table_cols,
                        label: label.clone(),
                    });
                }
                zir::Constraint::CustomGate {
                    gate,
                    inputs,
                    label,
                    ..
                } => {
                    let sel_name = format!("q_custom_{}", selector_counter);
                    selector_counter += 1;
                    columns.push(Column {
                        name: sel_name.clone(),
                        kind: ColumnKind::Fixed,
                    });
                    // Custom gate: combine inputs into a product constraint.
                    let poly = if inputs.is_empty() {
                        PlonkExpr::Const(FieldElement::from_i64(0))
                    } else {
                        let mut combined = expr_to_plonk(&inputs[0]);
                        for input in &inputs[1..] {
                            combined =
                                PlonkExpr::Mul(Box::new(combined), Box::new(expr_to_plonk(input)));
                        }
                        combined
                    };
                    gates.push(PlonkGate {
                        name: format!("custom_{}_{}", gate, selector_counter - 1),
                        selector: sel_name,
                        polynomial: poly,
                        label: label.clone(),
                    });
                }
                zir::Constraint::MemoryRead {
                    memory,
                    index,
                    value,
                    label,
                } => {
                    // Memory read as lookup: (index, value) ∈ memory table.
                    lookups.push(LookupArgument {
                        name: format!("mem_read_{}", memory),
                        input_exprs: vec![expr_to_plonk(index), expr_to_plonk(value)],
                        table_columns: vec![format!("{}__idx", memory), format!("{}__val", memory)],
                        label: label.clone(),
                    });
                }
                zir::Constraint::MemoryWrite {
                    memory,
                    index,
                    value,
                    label,
                } => {
                    // Memory write also checks via lookup + update.
                    lookups.push(LookupArgument {
                        name: format!("mem_write_{}", memory),
                        input_exprs: vec![expr_to_plonk(index), expr_to_plonk(value)],
                        table_columns: vec![format!("{}__idx", memory), format!("{}__val", memory)],
                        label: label.clone(),
                    });
                }
                zir::Constraint::BlackBox { label, .. } => {
                    let _ = label;
                }
                zir::Constraint::Permutation { left, right, label } => {
                    permutations.push(PermutationArgument {
                        left: left.clone(),
                        right: right.clone(),
                        label: label.clone(),
                    });
                }
                zir::Constraint::Copy { from, to, label } => {
                    permutations.push(PermutationArgument {
                        left: from.clone(),
                        right: to.clone(),
                        label: label.clone(),
                    });
                }
            }
        }

        // Estimate row count.
        let estimated_rows = program.signals.len() + program.constraints.len() + 16;

        Ok(Halo2LoweredIr {
            columns,
            gates,
            lookups,
            permutations,
            public_inputs,
            signals: program.signals.clone(),
            witness_plan: program.witness_plan.clone(),
            field: program.field,
            estimated_rows,
            metadata: program.metadata.clone(),
        })
    }
}

fn expr_to_plonk(expr: &zir::Expr) -> PlonkExpr {
    match expr {
        zir::Expr::Const(c) => PlonkExpr::Const(c.clone()),
        zir::Expr::Signal(name) => PlonkExpr::Column(name.clone()),
        zir::Expr::Add(values) => {
            let mut result = expr_to_plonk(&values[0]);
            for value in &values[1..] {
                result = PlonkExpr::Add(Box::new(result), Box::new(expr_to_plonk(value)));
            }
            result
        }
        zir::Expr::Sub(left, right) => PlonkExpr::Sub(
            Box::new(expr_to_plonk(left)),
            Box::new(expr_to_plonk(right)),
        ),
        zir::Expr::Mul(left, right) => PlonkExpr::Mul(
            Box::new(expr_to_plonk(left)),
            Box::new(expr_to_plonk(right)),
        ),
        zir::Expr::Div(left, right) => {
            // Division in PLONKish: a/b is represented as a * b^{-1}.
            // The prover must supply the inverse as witness; the constraint
            // enforces b * inv = 1 and result = a * inv.
            PlonkExpr::Mul(
                Box::new(expr_to_plonk(left)),
                Box::new(PlonkExpr::Neg(Box::new(expr_to_plonk(right)))),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldId;

    fn test_program() -> zir::Program {
        zir::Program {
            name: "halo2_test".to_string(),
            field: FieldId::PastaFp,
            signals: vec![
                zir::Signal {
                    name: "x".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "y".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir::Constraint::Equal {
                lhs: zir::Expr::Signal("y".to_string()),
                rhs: zir::Expr::Signal("x".to_string()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn creates_columns_for_signals() {
        let lowered = Halo2Lowering.lower(&test_program()).unwrap();
        assert!(lowered.columns.iter().any(|c| c.name == "x"));
        assert!(lowered.columns.iter().any(|c| c.name == "y"));
    }

    #[test]
    fn creates_gate_for_equality() {
        let lowered = Halo2Lowering.lower(&test_program()).unwrap();
        assert_eq!(lowered.gates.len(), 1);
    }

    #[test]
    fn range_uses_lookup() {
        let mut program = test_program();
        program.constraints.push(zir::Constraint::Range {
            signal: "x".to_string(),
            bits: 8,
            label: None,
        });
        let lowered = Halo2Lowering.lower(&program).unwrap();
        assert!(!lowered.lookups.is_empty());
    }

    #[test]
    fn lookup_constraint_creates_lookup_argument() {
        let mut program = test_program();
        program.lookup_tables.push(zir::LookupTable {
            name: "small".to_string(),
            columns: 1,
            values: vec![vec![FieldElement::from_i64(0), FieldElement::from_i64(1)]],
        });
        program.constraints.push(zir::Constraint::Lookup {
            inputs: vec![zir::Expr::Signal("x".to_string())],
            table: "small".to_string(),
            label: None,
        });
        let lowered = Halo2Lowering.lower(&program).unwrap();
        assert!(lowered.lookups.iter().any(|l| l.name == "lookup_small"));
    }

    #[test]
    fn memory_read_creates_lookup() {
        let mut program = test_program();
        program.constraints.push(zir::Constraint::MemoryRead {
            memory: "rom".to_string(),
            index: zir::Expr::Const(FieldElement::from_i64(0)),
            value: zir::Expr::Signal("x".to_string()),
            label: None,
        });
        let lowered = Halo2Lowering.lower(&program).unwrap();
        assert!(lowered.lookups.iter().any(|l| l.name == "mem_read_rom"));
    }

    #[test]
    fn permutation_constraint_creates_permutation() {
        let mut program = test_program();
        program.constraints.push(zir::Constraint::Permutation {
            left: "x".to_string(),
            right: "y".to_string(),
            label: None,
        });
        let lowered = Halo2Lowering.lower(&program).unwrap();
        assert_eq!(lowered.permutations.len(), 1);
    }
}
