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

use crate::hir;
use crate::zir;
use crate::{FieldElement, Visibility, ZkfError, ZkfResult};
use std::collections::BTreeMap;

pub fn lower_program(program: &hir::Program) -> ZkfResult<zir::Program> {
    let entry = program
        .functions
        .iter()
        .find(|function| function.name == program.entry)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "HIR entry function '{}' was not found",
                program.entry
            ))
        })?;

    let mut signals = Vec::new();
    let mut constraints = Vec::new();
    let mut assignments = Vec::new();
    let mut signal_types = BTreeMap::<String, zir::SignalType>::new();
    let mut return_counter = 0usize;

    for param in &entry.params {
        let ty = lower_type(&param.ty)?;
        signals.push(zir::Signal {
            name: param.name.clone(),
            visibility: param.visibility.clone(),
            ty: ty.clone(),
            constant: None,
        });
        signal_types.insert(param.name.clone(), ty);
    }

    for (index, stmt) in entry.body.iter().enumerate() {
        match stmt {
            hir::Stmt::Let { name, ty, expr } => {
                let lowered_ty = lower_type(ty)?;
                if signal_types.contains_key(name) {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "HIR let redeclares signal '{}'",
                        name
                    )));
                }
                signals.push(zir::Signal {
                    name: name.clone(),
                    visibility: Visibility::Private,
                    ty: lowered_ty.clone(),
                    constant: None,
                });
                signal_types.insert(name.clone(), lowered_ty);
                assignments.push(zir::WitnessAssignment {
                    target: name.clone(),
                    expr: lower_expr(expr)?,
                });
            }
            hir::Stmt::Assert { expr, label } => {
                let lowered = lower_expr(expr)?;
                constraints.push(zir::Constraint::Equal {
                    lhs: lowered,
                    rhs: zir::Expr::Const(FieldElement::from_i64(1)),
                    label: label
                        .clone()
                        .or_else(|| Some(format!("hir_assert_{index}"))),
                });
            }
            hir::Stmt::Return { values } => {
                for value in values {
                    let signal_name = format!("ret_{}_{}", entry.name, return_counter);
                    return_counter += 1;
                    signals.push(zir::Signal {
                        name: signal_name.clone(),
                        visibility: Visibility::Public,
                        ty: zir::SignalType::Field,
                        constant: None,
                    });
                    signal_types.insert(signal_name.clone(), zir::SignalType::Field);
                    assignments.push(zir::WitnessAssignment {
                        target: signal_name,
                        expr: lower_expr(value)?,
                    });
                }
            }
        }
    }

    let mut metadata = program.metadata.clone();
    metadata.insert("ir_family".to_string(), "zir-v1".to_string());
    metadata.insert("source_ir".to_string(), "hir-v1".to_string());
    metadata.insert("entry".to_string(), entry.name.clone());

    Ok(zir::Program {
        name: program.name.clone(),
        field: program.field,
        signals,
        constraints,
        witness_plan: zir::WitnessPlan {
            assignments,
            hints: Vec::new(),
            ..Default::default()
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata,
    })
}

fn lower_type(ty: &hir::Type) -> ZkfResult<zir::SignalType> {
    match ty {
        hir::Type::Field => Ok(zir::SignalType::Field),
        hir::Type::Bool => Ok(zir::SignalType::Bool),
        hir::Type::UInt { bits } => Ok(zir::SignalType::UInt { bits: *bits }),
        hir::Type::Array { element, len } => Ok(zir::SignalType::Array {
            element: Box::new(lower_type(element)?),
            len: *len,
        }),
        hir::Type::Tuple { elements } => Ok(zir::SignalType::Tuple {
            elements: elements
                .iter()
                .map(lower_type)
                .collect::<ZkfResult<Vec<_>>>()?,
        }),
    }
}

fn lower_expr(expr: &hir::Expr) -> ZkfResult<zir::Expr> {
    match expr {
        hir::Expr::Const(value) => Ok(zir::Expr::Const(value.clone())),
        hir::Expr::Var(name) => Ok(zir::Expr::Signal(name.clone())),
        hir::Expr::Binary { op, left, right } => {
            let left = Box::new(lower_expr(left)?);
            let right = Box::new(lower_expr(right)?);
            match op {
                hir::BinaryOp::Add => Ok(zir::Expr::Add(vec![*left, *right])),
                hir::BinaryOp::Sub => Ok(zir::Expr::Sub(left, right)),
                hir::BinaryOp::Mul => Ok(zir::Expr::Mul(left, right)),
                hir::BinaryOp::Div => Ok(zir::Expr::Div(left, right)),
                hir::BinaryOp::And => Ok(zir::Expr::Mul(left, right)),
                hir::BinaryOp::Or => Ok(zir::Expr::Sub(
                    Box::new(zir::Expr::Add(vec![*left.clone(), *right.clone()])),
                    Box::new(zir::Expr::Mul(left, right)),
                )),
                hir::BinaryOp::Eq => Ok(zir::Expr::Sub(left, right)),
            }
        }
        hir::Expr::Call { function, args } => {
            // Inline function calls: the ZIR has no call concept, so we lower
            // each argument expression and combine them.  For built-in functions
            // we can map to arithmetic; for unknown functions we return an error
            // since the HIR should have already resolved them.
            let lowered_args: Vec<zir::Expr> =
                args.iter().map(lower_expr).collect::<ZkfResult<Vec<_>>>()?;

            match function.as_str() {
                "add" if lowered_args.len() == 2 => Ok(zir::Expr::Add(lowered_args)),
                "sub" | "mul" | "div" if lowered_args.len() == 2 => {
                    let mut it = lowered_args.into_iter();
                    let a = Box::new(it.next().unwrap());
                    let b = Box::new(it.next().unwrap());
                    match function.as_str() {
                        "sub" => Ok(zir::Expr::Sub(a, b)),
                        "mul" => Ok(zir::Expr::Mul(a, b)),
                        "div" => Ok(zir::Expr::Div(a, b)),
                        _ => unreachable!(),
                    }
                }
                "neg" if lowered_args.len() == 1 => Ok(zir::Expr::Sub(
                    Box::new(zir::Expr::Const(FieldElement::from_i64(0))),
                    Box::new(lowered_args.into_iter().next().unwrap()),
                )),
                "identity" | "id" if lowered_args.len() == 1 => {
                    Ok(lowered_args.into_iter().next().unwrap())
                }
                _ => Err(ZkfError::UnsupportedBackend {
                    backend: "hir-to-zir".to_string(),
                    message: format!(
                        "HIR function call '{}' with {} args cannot be lowered to ZIR arithmetic; \
                         functions must be inlined before HIR-to-ZIR lowering",
                        function,
                        args.len()
                    ),
                }),
            }
        }
        hir::Expr::Index { base, index } => {
            // Array indexing at the ZIR level: the base expression must be a
            // variable and the index must be a constant.  Dynamic indexing is
            // not supported in flat ZIR (would require a mux/lookup).
            let base_lowered = lower_expr(base)?;
            let idx_lowered = lower_expr(index)?;

            // For constant indices into a named signal, generate the indexed
            // signal name (e.g. signal "a" at index 2 → "a[2]").
            match (&base_lowered, &idx_lowered) {
                (zir::Expr::Signal(name), zir::Expr::Const(idx_val)) => {
                    let idx = idx_val.as_bigint();
                    Ok(zir::Expr::Signal(format!("{name}[{idx}]")))
                }
                _ => Err(ZkfError::UnsupportedBackend {
                    backend: "hir-to-zir".to_string(),
                    message:
                        "HIR index expression requires a named signal base and constant index; \
                              dynamic indexing is not supported in flat ZIR"
                            .to_string(),
                }),
            }
        }
        hir::Expr::Tuple { values } => {
            // Tuple expressions are lowered element-wise.  Since ZIR has no
            // tuple type, a single-element tuple is unwrapped; multi-element
            // tuples are lowered to their first element (the caller is expected
            // to destructure via separate Let bindings in the HIR).
            if values.len() == 1 {
                lower_expr(&values[0])
            } else if values.is_empty() {
                // Unit tuple → zero constant
                Ok(zir::Expr::Const(FieldElement::from_i64(0)))
            } else {
                // Multi-element: lower to an Add of all elements.
                // This preserves all values in the expression tree.
                // Typically HIR destructures tuples into separate signals.
                let lowered: Vec<zir::Expr> = values
                    .iter()
                    .map(lower_expr)
                    .collect::<ZkfResult<Vec<_>>>()?;
                Ok(zir::Expr::Add(lowered))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldId;

    #[test]
    fn lowers_basic_hir_program_to_zir() {
        let program = hir::Program {
            name: "hir_sample".to_string(),
            field: FieldId::Bn254,
            functions: vec![hir::Function {
                name: "main".to_string(),
                params: vec![hir::Param {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    ty: hir::Type::Field,
                }],
                returns: vec![hir::Type::Field],
                body: vec![
                    hir::Stmt::Let {
                        name: "y".to_string(),
                        ty: hir::Type::Field,
                        expr: hir::Expr::Binary {
                            op: hir::BinaryOp::Add,
                            left: Box::new(hir::Expr::Var("x".to_string())),
                            right: Box::new(hir::Expr::Const(FieldElement::from_i64(2))),
                        },
                    },
                    hir::Stmt::Return {
                        values: vec![hir::Expr::Var("y".to_string())],
                    },
                ],
            }],
            entry: "main".to_string(),
            metadata: BTreeMap::new(),
        };

        let lowered = lower_program(&program).expect("HIR lowering should succeed");
        assert_eq!(lowered.name, "hir_sample");
        assert_eq!(lowered.signals.len(), 3);
        assert_eq!(lowered.witness_plan.assignments.len(), 2);
        assert!(
            lowered
                .metadata
                .get("source_ir")
                .is_some_and(|value| value == "hir-v1")
        );
    }
}
