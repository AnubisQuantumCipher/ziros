use crate::field::normalize_mod;
use crate::zir::{self, Constraint, Expr, Program};
use crate::{FieldElement, ZkfResult};
use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ZirOptimizeReport {
    pub input_signals: usize,
    pub output_signals: usize,
    pub input_constraints: usize,
    pub output_constraints: usize,
    pub folded_expr_nodes: usize,
    pub deduplicated_constraints: usize,
    pub removed_tautology_constraints: usize,
    pub removed_private_signals: usize,
}

/// Optimize a ZIR program directly, without lossy round-trip through IR v2.
/// Handles all ZIR constraint types including Lookup, CustomGate, Memory,
/// Permutation, and Copy.
pub fn optimize_zir(program: &Program) -> ZkfResult<(Program, ZirOptimizeReport)> {
    if let Some(result) = crate::proof_transform_spec::optimize_supported_zir_runtime(program) {
        return Ok(result);
    }
    optimize_zir_runtime(program)
}

fn optimize_zir_runtime(program: &Program) -> ZkfResult<(Program, ZirOptimizeReport)> {
    let mut report = ZirOptimizeReport {
        input_signals: program.signals.len(),
        output_signals: program.signals.len(),
        input_constraints: program.constraints.len(),
        output_constraints: program.constraints.len(),
        ..ZirOptimizeReport::default()
    };

    // Phase 1: Fold constant expressions and remove tautologies.
    let mut folded_constraints = Vec::new();
    for constraint in &program.constraints {
        let folded = fold_zir_constraint(constraint, program.field, &mut report.folded_expr_nodes);
        if is_tautology(&folded) {
            report.removed_tautology_constraints += 1;
            continue;
        }
        folded_constraints.push(folded);
    }

    // Phase 2: Deduplicate identical constraints.
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

    // Phase 3: Remove unreferenced private signals.
    let referenced = collect_referenced_signals(
        &deduped_constraints,
        &program.witness_plan.assignments,
        &program.witness_plan.hints,
    );
    let mut signals = Vec::with_capacity(program.signals.len());
    for signal in &program.signals {
        let keep =
            signal.visibility != crate::Visibility::Private || referenced.contains(&signal.name);
        if keep {
            signals.push(signal.clone());
        } else {
            report.removed_private_signals += 1;
        }
    }

    report.output_signals = signals.len();
    report.output_constraints = deduped_constraints.len();

    let optimized = Program {
        name: program.name.clone(),
        field: program.field,
        signals,
        constraints: deduped_constraints,
        witness_plan: program.witness_plan.clone(),
        lookup_tables: program.lookup_tables.clone(),
        memory_regions: program.memory_regions.clone(),
        custom_gates: program.custom_gates.clone(),
        metadata: program.metadata.clone(),
    };

    Ok((optimized, report))
}

fn fold_zir_constraint(
    constraint: &Constraint,
    field: crate::FieldId,
    folded_nodes: &mut usize,
) -> Constraint {
    match constraint {
        Constraint::Equal { lhs, rhs, label } => Constraint::Equal {
            lhs: fold_zir_expr(lhs, field, folded_nodes),
            rhs: fold_zir_expr(rhs, field, folded_nodes),
            label: label.clone(),
        },
        Constraint::Boolean { .. } | Constraint::Range { .. } => constraint.clone(),
        Constraint::Lookup {
            inputs,
            table,
            label,
        } => Constraint::Lookup {
            inputs: inputs
                .iter()
                .map(|e| fold_zir_expr(e, field, folded_nodes))
                .collect(),
            table: table.clone(),
            label: label.clone(),
        },
        Constraint::CustomGate {
            gate,
            inputs,
            outputs,
            params,
            label,
        } => Constraint::CustomGate {
            gate: gate.clone(),
            inputs: inputs
                .iter()
                .map(|e| fold_zir_expr(e, field, folded_nodes))
                .collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        Constraint::MemoryRead {
            memory,
            index,
            value,
            label,
        } => Constraint::MemoryRead {
            memory: memory.clone(),
            index: fold_zir_expr(index, field, folded_nodes),
            value: fold_zir_expr(value, field, folded_nodes),
            label: label.clone(),
        },
        Constraint::MemoryWrite {
            memory,
            index,
            value,
            label,
        } => Constraint::MemoryWrite {
            memory: memory.clone(),
            index: fold_zir_expr(index, field, folded_nodes),
            value: fold_zir_expr(value, field, folded_nodes),
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
                .map(|e| fold_zir_expr(e, field, folded_nodes))
                .collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        Constraint::Permutation { .. } | Constraint::Copy { .. } => constraint.clone(),
    }
}

fn fold_zir_expr(expr: &Expr, field: crate::FieldId, folded_nodes: &mut usize) -> Expr {
    match expr {
        Expr::Const(_) | Expr::Signal(_) => expr.clone(),
        Expr::Add(values) => {
            let mut terms = Vec::new();
            let mut const_acc = BigInt::zero();
            for value in values {
                let folded = fold_zir_expr(value, field, folded_nodes);
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
            if !const_acc.is_zero() {
                let modulus = field.modulus();
                let normalized = normalize_mod(const_acc, modulus);
                terms.push(Expr::Const(FieldElement::from_bigint(normalized)));
            }
            match terms.len() {
                0 => Expr::Const(FieldElement::from_i64(0)),
                1 => terms.remove(0),
                _ => Expr::Add(terms),
            }
        }
        Expr::Sub(left, right) => {
            let left = fold_zir_expr(left, field, folded_nodes);
            let right = fold_zir_expr(right, field, folded_nodes);
            if let (Expr::Const(a), Expr::Const(b)) = (&left, &right)
                && let (Ok(va), Ok(vb)) = (a.normalized_bigint(field), b.normalized_bigint(field))
            {
                *folded_nodes += 1;
                let modulus = field.modulus();
                let result = normalize_mod(va - vb, modulus);
                return Expr::Const(FieldElement::from_bigint(result));
            }
            Expr::Sub(Box::new(left), Box::new(right))
        }
        Expr::Mul(left, right) => {
            let left = fold_zir_expr(left, field, folded_nodes);
            let right = fold_zir_expr(right, field, folded_nodes);
            if let Expr::Const(c) = &left {
                if c.is_zero() {
                    *folded_nodes += 1;
                    return Expr::Const(FieldElement::from_i64(0));
                }
                if c.is_one() {
                    *folded_nodes += 1;
                    return right;
                }
            }
            if let Expr::Const(c) = &right {
                if c.is_zero() {
                    *folded_nodes += 1;
                    return Expr::Const(FieldElement::from_i64(0));
                }
                if c.is_one() {
                    *folded_nodes += 1;
                    return left;
                }
            }
            if let (Expr::Const(a), Expr::Const(b)) = (&left, &right)
                && let (Ok(va), Ok(vb)) = (a.normalized_bigint(field), b.normalized_bigint(field))
            {
                *folded_nodes += 1;
                let modulus = field.modulus();
                let result = normalize_mod(va * vb, modulus);
                return Expr::Const(FieldElement::from_bigint(result));
            }
            Expr::Mul(Box::new(left), Box::new(right))
        }
        Expr::Div(left, right) => {
            let left = fold_zir_expr(left, field, folded_nodes);
            let right = fold_zir_expr(right, field, folded_nodes);
            if let Expr::Const(c) = &right
                && c.is_one()
            {
                *folded_nodes += 1;
                return left;
            }
            Expr::Div(Box::new(left), Box::new(right))
        }
    }
}

fn is_tautology(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            if lhs == rhs {
                return true;
            }
            if let (Expr::Const(a), Expr::Const(b)) = (lhs, rhs) {
                return a == b;
            }
            false
        }
        _ => false,
    }
}

fn dedup_key(constraint: &Constraint) -> String {
    serde_json::to_string(constraint).unwrap_or_default()
}

fn collect_referenced_signals(
    constraints: &[Constraint],
    assignments: &[zir::WitnessAssignment],
    hints: &[zir::WitnessHint],
) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for constraint in constraints {
        collect_constraint_signals(constraint, &mut refs);
    }
    for assignment in assignments {
        refs.insert(assignment.target.clone());
        collect_expr_signals(&assignment.expr, &mut refs);
    }
    for hint in hints {
        refs.insert(hint.target.clone());
        refs.insert(hint.source.clone());
    }
    refs
}

fn collect_constraint_signals(constraint: &Constraint, refs: &mut BTreeSet<String>) {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            collect_expr_signals(lhs, refs);
            collect_expr_signals(rhs, refs);
        }
        Constraint::Boolean { signal, .. } => {
            refs.insert(signal.clone());
        }
        Constraint::Range { signal, .. } => {
            refs.insert(signal.clone());
        }
        Constraint::Lookup { inputs, .. } => {
            for input in inputs {
                collect_expr_signals(input, refs);
            }
        }
        Constraint::CustomGate {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_expr_signals(input, refs);
            }
            for output in outputs {
                refs.insert(output.clone());
            }
        }
        Constraint::MemoryRead { index, value, .. } => {
            collect_expr_signals(index, refs);
            collect_expr_signals(value, refs);
        }
        Constraint::MemoryWrite { index, value, .. } => {
            collect_expr_signals(index, refs);
            collect_expr_signals(value, refs);
        }
        Constraint::BlackBox {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_expr_signals(input, refs);
            }
            for output in outputs {
                refs.insert(output.clone());
            }
        }
        Constraint::Permutation { left, right, .. } => {
            refs.insert(left.clone());
            refs.insert(right.clone());
        }
        Constraint::Copy { from, to, .. } => {
            refs.insert(from.clone());
            refs.insert(to.clone());
        }
    }
}

fn collect_expr_signals(expr: &Expr, refs: &mut BTreeSet<String>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            refs.insert(name.clone());
        }
        Expr::Add(values) => {
            for value in values {
                collect_expr_signals(value, refs);
            }
        }
        Expr::Sub(left, right) | Expr::Mul(left, right) | Expr::Div(left, right) => {
            collect_expr_signals(left, refs);
            collect_expr_signals(right, refs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldId;
    use std::collections::BTreeMap;

    fn simple_program() -> Program {
        Program {
            name: "opt_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "x".to_string(),
                    visibility: crate::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "y".to_string(),
                    visibility: crate::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "unused".to_string(),
                    visibility: crate::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![
                // Tautology: x == x
                Constraint::Equal {
                    lhs: Expr::Signal("x".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("tautology".to_string()),
                },
                // Foldable: y == x + 0
                Constraint::Equal {
                    lhs: Expr::Signal("y".to_string()),
                    rhs: Expr::Add(vec![
                        Expr::Signal("x".to_string()),
                        Expr::Const(FieldElement::from_i64(0)),
                    ]),
                    label: Some("foldable".to_string()),
                },
            ],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn removes_tautology_constraints() {
        let (optimized, report) = optimize_zir(&simple_program()).unwrap();
        assert_eq!(report.removed_tautology_constraints, 1);
        assert_eq!(optimized.constraints.len(), 1);
    }

    #[test]
    fn removes_unreferenced_private_signals() {
        let (optimized, report) = optimize_zir(&simple_program()).unwrap();
        assert_eq!(report.removed_private_signals, 1);
        assert!(!optimized.signals.iter().any(|s| s.name == "unused"));
    }

    #[test]
    fn folds_constant_addition() {
        let (optimized, report) = optimize_zir(&simple_program()).unwrap();
        assert!(report.folded_expr_nodes > 0);
        // y == x after folding (x + 0 folds to x)
        if let Constraint::Equal { rhs, .. } = &optimized.constraints[0] {
            assert!(matches!(rhs, Expr::Signal(s) if s == "x"));
        } else {
            panic!("expected Equal constraint");
        }
    }

    #[test]
    fn preserves_lookup_constraints() {
        let mut program = simple_program();
        program.constraints.push(Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "my_table".to_string(),
            label: Some("lk".to_string()),
        });
        let (optimized, _) = optimize_zir(&program).unwrap();
        assert!(optimized.constraints.iter().any(|c| matches!(
            c,
            Constraint::Lookup { table, .. } if table == "my_table"
        )));
    }

    #[test]
    fn preserves_memory_constraints() {
        let mut program = simple_program();
        program.constraints.push(Constraint::MemoryRead {
            memory: "mem0".to_string(),
            index: Expr::Const(FieldElement::from_i64(0)),
            value: Expr::Signal("x".to_string()),
            label: None,
        });
        let (optimized, _) = optimize_zir(&program).unwrap();
        assert!(optimized.constraints.iter().any(|c| matches!(
            c,
            Constraint::MemoryRead { memory, .. } if memory == "mem0"
        )));
    }

    #[test]
    fn preserves_custom_gate_constraints() {
        let mut program = simple_program();
        program.constraints.push(Constraint::CustomGate {
            gate: "poseidon_sbox".to_string(),
            inputs: vec![Expr::Signal("x".to_string())],
            outputs: vec!["y".to_string()],
            params: BTreeMap::new(),
            label: None,
        });
        let (optimized, _) = optimize_zir(&program).unwrap();
        assert!(optimized.constraints.iter().any(|c| matches!(
            c,
            Constraint::CustomGate { gate, .. } if gate == "poseidon_sbox"
        )));
    }

    #[test]
    fn preserves_lookup_tables_and_metadata() {
        let mut program = simple_program();
        program.lookup_tables.push(zir::LookupTable {
            name: "range8".to_string(),
            columns: 1,
            values: vec![(0..=255).map(FieldElement::from_i64).collect()],
        });
        program.memory_regions.push(zir::MemoryRegion {
            name: "scratch".to_string(),
            size: 256,
            read_only: false,
        });
        program.custom_gates.push(zir::CustomGateDefinition {
            name: "poseidon_sbox".to_string(),
            input_count: 1,
            output_count: 1,
            constraint_expr: Some("x^5".to_string()),
        });
        let (optimized, _) = optimize_zir(&program).unwrap();
        assert_eq!(optimized.lookup_tables.len(), 1);
        assert_eq!(optimized.memory_regions.len(), 1);
        assert_eq!(optimized.custom_gates.len(), 1);
    }

    #[test]
    fn supported_subset_dispatches_through_proof_transform_core() {
        let program = simple_program();
        assert!(crate::proof_transform_spec::supports_optimizer_zir_proof_subset(&program));
        let proof_path =
            crate::proof_transform_spec::optimize_supported_zir_runtime(&program).unwrap();
        let public_path = optimize_zir(&program).unwrap();
        assert_eq!(proof_path, public_path);
    }

    #[test]
    fn unsupported_subset_falls_back_to_runtime_path() {
        let mut program = simple_program();
        program.constraints.push(Constraint::CustomGate {
            gate: "poseidon_sbox".to_string(),
            inputs: vec![Expr::Signal("x".to_string())],
            outputs: vec!["y".to_string()],
            params: BTreeMap::new(),
            label: None,
        });

        assert!(!crate::proof_transform_spec::supports_optimizer_zir_proof_subset(&program));
        assert!(crate::proof_transform_spec::optimize_supported_zir_runtime(&program).is_none());
        assert_eq!(
            optimize_zir(&program).unwrap(),
            optimize_zir_runtime(&program).unwrap()
        );
    }
}
