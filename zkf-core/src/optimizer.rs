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

use crate::field::normalize_mod;
use crate::ir::{Constraint, Expr, Program, Visibility};
use crate::lowering::{program_v2_to_zir, program_zir_to_v2};
use crate::zir;
use crate::{FieldElement, ZkfResult};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OptimizeReport {
    pub input_signals: usize,
    pub output_signals: usize,
    pub input_constraints: usize,
    pub output_constraints: usize,
    pub folded_expr_nodes: usize,
    pub deduplicated_constraints: usize,
    pub removed_tautology_constraints: usize,
    pub removed_private_signals: usize,
}

pub fn optimize_program(program: &Program) -> (Program, OptimizeReport) {
    if let Some(result) = crate::proof_transform_spec::optimize_supported_ir_runtime(program) {
        return result;
    }
    optimize_program_runtime(program)
}

fn optimize_program_runtime(program: &Program) -> (Program, OptimizeReport) {
    let mut report = OptimizeReport {
        input_signals: program.signals.len(),
        output_signals: program.signals.len(),
        input_constraints: program.constraints.len(),
        output_constraints: program.constraints.len(),
        ..OptimizeReport::default()
    };

    let mut folded_constraints = Vec::new();
    for constraint in &program.constraints {
        let folded = fold_constraint(constraint, program.field, &mut report.folded_expr_nodes);
        if is_tautology(&folded) {
            report.removed_tautology_constraints += 1;
            continue;
        }
        folded_constraints.push(folded);
    }

    let mut deduped_constraints = Vec::new();
    let mut seen = BTreeSet::new();
    for constraint in folded_constraints {
        let key = dedup_key(&constraint);
        if seen.insert(key) {
            deduped_constraints.push(constraint);
        } else {
            report.deduplicated_constraints += 1;
        }
    }

    let referenced = collect_referenced_signals(
        &deduped_constraints,
        &program.witness_plan.assignments,
        &program.witness_plan.hints,
    );
    let mut signals = Vec::with_capacity(program.signals.len());
    for signal in &program.signals {
        let keep = signal.visibility != Visibility::Private || referenced.contains(&signal.name);
        if keep {
            signals.push(signal.clone());
        } else {
            report.removed_private_signals += 1;
        }
    }
    let kept_names = signals
        .iter()
        .map(|signal| signal.name.as_str())
        .collect::<BTreeSet<_>>();

    let assignments = program
        .witness_plan
        .assignments
        .iter()
        .filter(|assignment| kept_names.contains(assignment.target.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let hints = program
        .witness_plan
        .hints
        .iter()
        .filter(|hint| kept_names.contains(hint.target.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    let optimized = Program {
        name: program.name.clone(),
        field: program.field,
        signals,
        constraints: deduped_constraints,
        witness_plan: crate::WitnessPlan {
            assignments,
            hints,
            input_aliases: program.witness_plan.input_aliases.clone(),
            acir_program_bytes: program.witness_plan.acir_program_bytes.clone(),
        },
        lookup_tables: program.lookup_tables.clone(),
        metadata: program.metadata.clone(),
    };

    report.output_signals = optimized.signals.len();
    report.output_constraints = optimized.constraints.len();
    (optimized, report)
}

pub fn optimize_program_zir(program: &zir::Program) -> ZkfResult<(zir::Program, OptimizeReport)> {
    let lowered = program_zir_to_v2(program)?;
    let (optimized, report) = optimize_program(&lowered);
    let mut lifted = program_v2_to_zir(&optimized);
    // Preserve original ZIR metadata while stamping deterministic conversion lineage.
    for (key, value) in &program.metadata {
        lifted
            .metadata
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    lifted
        .metadata
        .insert("source_ir".to_string(), "ir-v2-optimized".to_string());
    Ok((lifted, report))
}

fn fold_constraint(
    constraint: &Constraint,
    field: crate::FieldId,
    folded_nodes: &mut usize,
) -> Constraint {
    match constraint {
        Constraint::Equal { lhs, rhs, label } => Constraint::Equal {
            lhs: fold_expr(lhs, field, folded_nodes),
            rhs: fold_expr(rhs, field, folded_nodes),
            label: label.clone(),
        },
        Constraint::Boolean { signal, label } => Constraint::Boolean {
            signal: signal.clone(),
            label: label.clone(),
        },
        Constraint::Range {
            signal,
            bits,
            label,
        } => Constraint::Range {
            signal: signal.clone(),
            bits: *bits,
            label: label.clone(),
        },
        Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => Constraint::BlackBox {
            op: *op,
            inputs: inputs
                .iter()
                .map(|expr| fold_expr(expr, field, folded_nodes))
                .collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        Constraint::Lookup { .. } => constraint.clone(),
    }
}

fn fold_expr(expr: &Expr, field: crate::FieldId, folded_nodes: &mut usize) -> Expr {
    match expr {
        Expr::Const(_) | Expr::Signal(_) => expr.clone(),
        Expr::Add(values) => {
            let mut terms = Vec::new();
            let mut const_acc = BigInt::zero();
            for value in values {
                let folded = fold_expr(value, field, folded_nodes);
                match folded {
                    Expr::Const(c) => {
                        if let Ok(v) = c.normalized_bigint(field) {
                            const_acc += v;
                            *folded_nodes += 1;
                        } else {
                            terms.push(Expr::Const(c));
                        }
                    }
                    Expr::Add(nested) => {
                        terms.extend(nested);
                        *folded_nodes += 1;
                    }
                    other => terms.push(other),
                }
            }

            let normalized_const = normalize_mod(const_acc, field.modulus());
            if !normalized_const.is_zero() {
                terms.push(Expr::Const(FieldElement::from_bigint_with_field(
                    normalized_const,
                    field,
                )));
            }

            match terms.len() {
                0 => Expr::Const(FieldElement::from_i64(0)),
                1 => terms.remove(0),
                _ => Expr::Add(terms),
            }
        }
        Expr::Sub(left, right) => {
            let left = fold_expr(left, field, folded_nodes);
            let right = fold_expr(right, field, folded_nodes);
            if let (Some(l), Some(r)) = (const_bigint(&left, field), const_bigint(&right, field)) {
                *folded_nodes += 1;
                Expr::Const(FieldElement::from_bigint_with_field(l - r, field))
            } else if matches!(right, Expr::Const(ref c) if c.is_zero()) {
                *folded_nodes += 1;
                left
            } else {
                Expr::Sub(Box::new(left), Box::new(right))
            }
        }
        Expr::Mul(left, right) => {
            let left = fold_expr(left, field, folded_nodes);
            let right = fold_expr(right, field, folded_nodes);
            match (const_bigint(&left, field), const_bigint(&right, field)) {
                (Some(l), Some(r)) => {
                    *folded_nodes += 1;
                    Expr::Const(FieldElement::from_bigint_with_field(l * r, field))
                }
                (Some(l), _) if l.is_zero() => {
                    *folded_nodes += 1;
                    Expr::Const(FieldElement::from_i64(0))
                }
                (_, Some(r)) if r.is_zero() => {
                    *folded_nodes += 1;
                    Expr::Const(FieldElement::from_i64(0))
                }
                (Some(l), _) if l.is_one() => {
                    *folded_nodes += 1;
                    right
                }
                (_, Some(r)) if r.is_one() => {
                    *folded_nodes += 1;
                    left
                }
                _ => Expr::Mul(Box::new(left), Box::new(right)),
            }
        }
        Expr::Div(left, right) => {
            let left = fold_expr(left, field, folded_nodes);
            let right = fold_expr(right, field, folded_nodes);
            if let (Some(l), Some(r)) = (const_bigint(&left, field), const_bigint(&right, field)) {
                if r.is_zero() {
                    return Expr::Div(Box::new(left), Box::new(right));
                }
                let modulus = field.modulus();
                let r = normalize_mod(r, modulus);
                if let Some(inv) = mod_inverse(r, modulus) {
                    *folded_nodes += 1;
                    Expr::Const(FieldElement::from_bigint_with_field(l * inv, field))
                } else {
                    Expr::Div(Box::new(left), Box::new(right))
                }
            } else if matches!(right, Expr::Const(ref c) if c.is_one()) {
                *folded_nodes += 1;
                left
            } else {
                Expr::Div(Box::new(left), Box::new(right))
            }
        }
    }
}

fn collect_referenced_signals(
    constraints: &[Constraint],
    assignments: &[crate::WitnessAssignment],
    hints: &[crate::WitnessHint],
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for constraint in constraints {
        match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                collect_expr_signals(lhs, &mut out);
                collect_expr_signals(rhs, &mut out);
            }
            Constraint::Boolean { signal, .. } | Constraint::Range { signal, .. } => {
                out.insert(signal.clone());
            }
            Constraint::BlackBox {
                inputs, outputs, ..
            } => {
                for input in inputs {
                    collect_expr_signals(input, &mut out);
                }
                for output in outputs {
                    out.insert(output.clone());
                }
            }
            Constraint::Lookup { inputs, .. } => {
                for input in inputs {
                    collect_expr_signals(input, &mut out);
                }
            }
        }
    }
    for assignment in assignments {
        out.insert(assignment.target.clone());
        collect_expr_signals(&assignment.expr, &mut out);
    }
    for hint in hints {
        out.insert(hint.target.clone());
        out.insert(hint.source.clone());
    }
    out
}

fn collect_expr_signals(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            out.insert(name.clone());
        }
        Expr::Add(values) => {
            for value in values {
                collect_expr_signals(value, out);
            }
        }
        Expr::Sub(left, right) | Expr::Mul(left, right) | Expr::Div(left, right) => {
            collect_expr_signals(left, out);
            collect_expr_signals(right, out);
        }
    }
}

fn const_bigint(expr: &Expr, field: crate::FieldId) -> Option<BigInt> {
    match expr {
        Expr::Const(value) => value.normalized_bigint(field).ok(),
        _ => None,
    }
}

fn is_tautology(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => lhs == rhs,
        _ => false,
    }
}

fn dedup_key(constraint: &Constraint) -> String {
    let canonical = match constraint {
        Constraint::Equal { lhs, rhs, .. } => Constraint::Equal {
            lhs: lhs.clone(),
            rhs: rhs.clone(),
            label: None,
        },
        Constraint::Boolean { signal, .. } => Constraint::Boolean {
            signal: signal.clone(),
            label: None,
        },
        Constraint::Range { signal, bits, .. } => Constraint::Range {
            signal: signal.clone(),
            bits: *bits,
            label: None,
        },
        Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            ..
        } => Constraint::BlackBox {
            op: *op,
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: None,
        },
        Constraint::Lookup {
            inputs,
            table,
            outputs,
            ..
        } => Constraint::Lookup {
            inputs: inputs.clone(),
            table: table.clone(),
            outputs: outputs.clone(),
            label: None,
        },
    };
    serde_json::to_string(&canonical).unwrap_or_else(|_| format!("{canonical:?}"))
}

fn mod_inverse(value: BigInt, modulus: &BigInt) -> Option<BigInt> {
    if value.is_zero() {
        return None;
    }
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = modulus.clone();
    let mut new_r = normalize_mod(value, modulus);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let next_t = &t - (&quotient * &new_t);
        t = new_t;
        new_t = next_t;
        let next_r = &r - (&quotient * &new_r);
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }
    if t < BigInt::zero() {
        t += modulus;
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldId, Signal, Visibility, WitnessPlan};
    use std::collections::BTreeMap;

    fn simple_program() -> Program {
        Program {
            name: "opt_ir_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "unused".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("x".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("tautology".to_string()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("y".to_string()),
                    rhs: Expr::Add(vec![
                        Expr::Signal("x".to_string()),
                        Expr::Const(FieldElement::from_i64(0)),
                    ]),
                    label: Some("foldable".to_string()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn supported_subset_dispatches_through_proof_transform_core() {
        let program = simple_program();
        assert!(crate::proof_transform_spec::supports_optimizer_ir_proof_subset(&program));
        let proof_path =
            crate::proof_transform_spec::optimize_supported_ir_runtime(&program).unwrap();
        let public_path = optimize_program(&program);
        assert_eq!(proof_path, public_path);
    }

    #[test]
    fn unsupported_subset_falls_back_to_runtime_path() {
        let mut program = simple_program();
        program.lookup_tables.push(crate::ir::LookupTable {
            name: "lookup".to_string(),
            columns: vec!["x".to_string()],
            values: vec![vec![FieldElement::from_i64(1)]],
        });
        program.constraints.push(Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "lookup".to_string(),
            outputs: None,
            label: Some("lookup".to_string()),
        });

        assert!(!crate::proof_transform_spec::supports_optimizer_ir_proof_subset(&program));
        assert!(crate::proof_transform_spec::optimize_supported_ir_runtime(&program).is_none());
        assert_eq!(
            optimize_program(&program),
            optimize_program_runtime(&program)
        );
    }
}
