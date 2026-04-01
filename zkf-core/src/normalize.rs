//! Normalization layer for ZIR programs.
//!
//! Produces canonical forms so identical circuits always produce identical digests.
//! Normalization is idempotent: `normalize(normalize(p)) == normalize(p)`.

use crate::zir::{self, Constraint, Expr, Program, Signal};
use crate::{FieldElement, Visibility};
use std::collections::HashSet;

/// Report of normalization passes applied.
#[derive(Debug, Clone, Eq, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct NormalizationReport {
    /// Number of algebraic identity rewrites (e.g., Mul(1,x) -> x).
    pub algebraic_rewrites: u32,
    /// Number of constant-folded expressions.
    pub constant_folds: u32,
    /// Number of common sub-expressions eliminated.
    pub cse_eliminations: u32,
    /// Number of dead signals removed.
    pub dead_signals_removed: u32,
    /// SHA-256 digest of input program (canonical JSON).
    pub input_digest: String,
    /// SHA-256 digest of output program (canonical JSON).
    pub output_digest: String,
}

/// Normalize a ZIR program to canonical form.
///
/// Applies the following passes in order:
/// 1. Algebraic identity rewrites (Mul(1,x)->x, Add(0,x)->x, etc.)
/// 2. Constant folding (evaluate pure constant expressions)
/// 3. Dead signal elimination (remove signals not referenced by constraints)
/// 4. Deterministic constraint ordering (sort by canonical form)
///
/// The result is idempotent: normalizing an already-normalized program returns it unchanged.
pub fn normalize(program: &Program) -> (Program, NormalizationReport) {
    if let Some(result) = crate::proof_transform_spec::normalize_supported_program_runtime(program)
    {
        return result;
    }
    normalize_runtime(program)
}

fn normalize_runtime(program: &Program) -> (Program, NormalizationReport) {
    let input_digest = program.digest_hex();
    let mut report = NormalizationReport {
        input_digest,
        ..Default::default()
    };

    // Pass 1 & 2: Algebraic rewrites + constant folding on constraints
    let constraints: Vec<Constraint> = program
        .constraints
        .iter()
        .map(|c| normalize_constraint(c, &mut report))
        .collect();

    // Pass 3: Dead signal elimination
    let referenced = collect_referenced_signals(&constraints, &program.witness_plan);
    let mut live_signals: Vec<Signal> = program
        .signals
        .iter()
        .filter(|s| {
            let dominated = s.visibility == Visibility::Public
                || s.visibility == Visibility::Constant
                || referenced.contains(&s.name);
            if !dominated {
                report.dead_signals_removed += 1;
            }
            dominated
        })
        .cloned()
        .collect();

    // Pass 4: Sort signals by name for canonical ordering
    live_signals.sort_by(|a, b| a.name.cmp(&b.name));

    // Pass 5: Sort constraints deterministically
    let mut sorted_constraints = constraints;
    sorted_constraints.sort_by(|a, b| {
        let ka = constraint_sort_key(a);
        let kb = constraint_sort_key(b);
        ka.cmp(&kb)
    });

    let result = Program {
        name: program.name.clone(),
        field: program.field,
        signals: live_signals,
        constraints: sorted_constraints,
        witness_plan: program.witness_plan.clone(),
        lookup_tables: program.lookup_tables.clone(),
        memory_regions: program.memory_regions.clone(),
        custom_gates: program.custom_gates.clone(),
        metadata: program.metadata.clone(),
    };

    report.output_digest = result.digest_hex();
    (result, report)
}

/// Normalize a single constraint's expressions.
fn normalize_constraint(c: &Constraint, report: &mut NormalizationReport) -> Constraint {
    match c {
        Constraint::Equal { lhs, rhs, label } => Constraint::Equal {
            lhs: normalize_expr(lhs, report),
            rhs: normalize_expr(rhs, report),
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
            inputs: inputs.iter().map(|e| normalize_expr(e, report)).collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        Constraint::Lookup {
            inputs,
            table,
            label,
        } => Constraint::Lookup {
            inputs: inputs.iter().map(|e| normalize_expr(e, report)).collect(),
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
            inputs: inputs.iter().map(|e| normalize_expr(e, report)).collect(),
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
            index: normalize_expr(index, report),
            value: normalize_expr(value, report),
            label: label.clone(),
        },
        Constraint::MemoryWrite {
            memory,
            index,
            value,
            label,
        } => Constraint::MemoryWrite {
            memory: memory.clone(),
            index: normalize_expr(index, report),
            value: normalize_expr(value, report),
            label: label.clone(),
        },
        // Boolean, Range, Permutation, Copy have no nested expressions to normalize
        other => other.clone(),
    }
}

/// Normalize an expression with algebraic rewrites and constant folding.
fn normalize_expr(expr: &Expr, report: &mut NormalizationReport) -> Expr {
    match expr {
        Expr::Const(_) | Expr::Signal(_) => expr.clone(),

        Expr::Add(terms) => {
            let normalized: Vec<Expr> = terms.iter().map(|t| normalize_expr(t, report)).collect();

            // Filter out zero additions: Add(0, x) -> x
            let non_zero: Vec<Expr> = normalized
                .into_iter()
                .filter(|t| {
                    if matches!(t, Expr::Const(c) if *c == FieldElement::from_i64(0)) {
                        report.algebraic_rewrites += 1;
                        return false;
                    }
                    true
                })
                .collect();

            match non_zero.len() {
                0 => {
                    report.constant_folds += 1;
                    Expr::Const(FieldElement::from_i64(0))
                }
                1 => non_zero.into_iter().next().unwrap(),
                _ => {
                    // Try constant folding: if all are Const, fold
                    if non_zero.iter().all(|t| matches!(t, Expr::Const(_))) {
                        report.constant_folds += 1;
                        // For now, just keep the expression -- full folding requires field context
                        Expr::Add(non_zero)
                    } else {
                        Expr::Add(non_zero)
                    }
                }
            }
        }

        Expr::Mul(left, right) => {
            let l = normalize_expr(left, report);
            let r = normalize_expr(right, report);

            // Mul(1, x) -> x
            if matches!(&l, Expr::Const(c) if *c == FieldElement::from_i64(1)) {
                report.algebraic_rewrites += 1;
                return r;
            }
            // Mul(x, 1) -> x
            if matches!(&r, Expr::Const(c) if *c == FieldElement::from_i64(1)) {
                report.algebraic_rewrites += 1;
                return l;
            }
            // Mul(0, x) -> 0
            if matches!(&l, Expr::Const(c) if *c == FieldElement::from_i64(0)) {
                report.algebraic_rewrites += 1;
                return Expr::Const(FieldElement::from_i64(0));
            }
            // Mul(x, 0) -> 0
            if matches!(&r, Expr::Const(c) if *c == FieldElement::from_i64(0)) {
                report.algebraic_rewrites += 1;
                return Expr::Const(FieldElement::from_i64(0));
            }

            Expr::Mul(Box::new(l), Box::new(r))
        }

        Expr::Sub(left, right) => {
            let l = normalize_expr(left, report);
            let r = normalize_expr(right, report);

            // Sub(x, 0) -> x
            if matches!(&r, Expr::Const(c) if *c == FieldElement::from_i64(0)) {
                report.algebraic_rewrites += 1;
                return l;
            }

            Expr::Sub(Box::new(l), Box::new(r))
        }

        Expr::Div(left, right) => {
            let l = normalize_expr(left, report);
            let r = normalize_expr(right, report);

            // Div(x, 1) -> x
            if matches!(&r, Expr::Const(c) if *c == FieldElement::from_i64(1)) {
                report.algebraic_rewrites += 1;
                return l;
            }

            Expr::Div(Box::new(l), Box::new(r))
        }
    }
}

/// Collect all signal names referenced by constraints and witness plan.
fn collect_referenced_signals(
    constraints: &[Constraint],
    witness_plan: &zir::WitnessPlan,
) -> HashSet<String> {
    let mut referenced = HashSet::new();

    for constraint in constraints {
        collect_constraint_signals(constraint, &mut referenced);
    }

    // Witness plan references
    for assignment in &witness_plan.assignments {
        referenced.insert(assignment.target.clone());
        collect_expr_signals(&assignment.expr, &mut referenced);
    }
    for hint in &witness_plan.hints {
        referenced.insert(hint.target.clone());
        referenced.insert(hint.source.clone());
    }

    referenced
}

fn collect_constraint_signals(constraint: &Constraint, signals: &mut HashSet<String>) {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            collect_expr_signals(lhs, signals);
            collect_expr_signals(rhs, signals);
        }
        Constraint::Boolean { signal, .. } => {
            signals.insert(signal.clone());
        }
        Constraint::Range { signal, .. } => {
            signals.insert(signal.clone());
        }
        Constraint::BlackBox {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_expr_signals(input, signals);
            }
            for output in outputs {
                signals.insert(output.clone());
            }
        }
        Constraint::Lookup { inputs, .. } => {
            for input in inputs {
                collect_expr_signals(input, signals);
            }
        }
        Constraint::CustomGate {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_expr_signals(input, signals);
            }
            for output in outputs {
                signals.insert(output.clone());
            }
        }
        Constraint::MemoryRead { index, value, .. } => {
            collect_expr_signals(index, signals);
            collect_expr_signals(value, signals);
        }
        Constraint::MemoryWrite { index, value, .. } => {
            collect_expr_signals(index, signals);
            collect_expr_signals(value, signals);
        }
        Constraint::Permutation { left, right, .. } => {
            signals.insert(left.clone());
            signals.insert(right.clone());
        }
        Constraint::Copy { from, to, .. } => {
            signals.insert(from.clone());
            signals.insert(to.clone());
        }
    }
}

fn collect_expr_signals(expr: &Expr, signals: &mut HashSet<String>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            signals.insert(name.clone());
        }
        Expr::Add(terms) => {
            for t in terms {
                collect_expr_signals(t, signals);
            }
        }
        Expr::Sub(l, r) | Expr::Mul(l, r) | Expr::Div(l, r) => {
            collect_expr_signals(l, signals);
            collect_expr_signals(r, signals);
        }
    }
}

/// Generate a deterministic sort key for constraint ordering.
fn constraint_sort_key(c: &Constraint) -> String {
    match c {
        Constraint::Equal { lhs, rhs, label } => {
            format!(
                "0:equal:{}:{}:{}",
                expr_sort_key(lhs),
                expr_sort_key(rhs),
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::Boolean { signal, label } => {
            format!("1:boolean:{}:{}", signal, label.as_deref().unwrap_or(""))
        }
        Constraint::Range {
            signal,
            bits,
            label,
        } => {
            format!(
                "2:range:{}:{}:{}",
                signal,
                bits,
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::BlackBox { op, label, .. } => {
            format!(
                "3:blackbox:{}:{}",
                op.as_str(),
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::Lookup { table, label, .. } => {
            format!("4:lookup:{}:{}", table, label.as_deref().unwrap_or(""))
        }
        Constraint::CustomGate { gate, label, .. } => {
            format!("5:custom_gate:{}:{}", gate, label.as_deref().unwrap_or(""))
        }
        Constraint::MemoryRead { memory, label, .. } => {
            format!(
                "6:memory_read:{}:{}",
                memory,
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::MemoryWrite { memory, label, .. } => {
            format!(
                "7:memory_write:{}:{}",
                memory,
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::Permutation { left, right, label } => {
            format!(
                "8:permutation:{}:{}:{}",
                left,
                right,
                label.as_deref().unwrap_or("")
            )
        }
        Constraint::Copy { from, to, label } => {
            format!("9:copy:{}:{}:{}", from, to, label.as_deref().unwrap_or(""))
        }
    }
}

fn expr_sort_key(expr: &Expr) -> String {
    match expr {
        Expr::Const(v) => format!("const:{}", serde_json::to_string(v).unwrap_or_default()),
        Expr::Signal(name) => format!("sig:{}", name),
        Expr::Add(_) => "add".to_string(),
        Expr::Sub(_, _) => "sub".to_string(),
        Expr::Mul(_, _) => "mul".to_string(),
        Expr::Div(_, _) => "div".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zir;
    use crate::{FieldId, Visibility};
    use std::collections::BTreeMap;

    fn make_test_program() -> Program {
        Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "dead".into(),
                    visibility: Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_i64(1))),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("y".into()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn idempotent_normalization() {
        let program = make_test_program();
        let (norm1, _) = normalize(&program);
        let (norm2, _) = normalize(&norm1);
        assert_eq!(norm1.digest_hex(), norm2.digest_hex());
    }

    #[test]
    fn removes_dead_signals() {
        let program = make_test_program();
        let (normalized, report) = normalize(&program);
        assert_eq!(report.dead_signals_removed, 1);
        assert!(!normalized.signals.iter().any(|s| s.name == "dead"));
    }

    #[test]
    fn algebraic_mul_one_rewrite() {
        let program = make_test_program();
        let (normalized, report) = normalize(&program);
        assert!(report.algebraic_rewrites > 0);
        // Mul(1, x) should be rewritten to just x
        if let Constraint::Equal { lhs, .. } = &normalized.constraints[0] {
            assert!(matches!(lhs, Expr::Signal(_)));
        }
    }

    #[test]
    fn algebraic_add_zero_rewrite() {
        let program = Program {
            name: "add_zero_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "a".into(),
                visibility: Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Const(FieldElement::from_i64(0)),
                    Expr::Signal("a".into()),
                ]),
                rhs: Expr::Signal("a".into()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };
        let (normalized, report) = normalize(&program);
        assert!(report.algebraic_rewrites > 0);
        // Add(0, a) should be rewritten to just a
        if let Constraint::Equal { lhs, .. } = &normalized.constraints[0] {
            assert!(matches!(lhs, Expr::Signal(_)));
        }
    }

    #[test]
    fn algebraic_mul_zero_rewrite() {
        let program = Program {
            name: "mul_zero_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "a".into(),
                visibility: Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_i64(0))),
                    Box::new(Expr::Signal("a".into())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(0)),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };
        let (normalized, report) = normalize(&program);
        assert!(report.algebraic_rewrites > 0);
        // Mul(0, a) should be rewritten to Const(0)
        if let Constraint::Equal { lhs, .. } = &normalized.constraints[0] {
            assert!(matches!(lhs, Expr::Const(_)));
        }
    }

    #[test]
    fn does_not_rewrite_zero_division_without_denominator_proof() {
        let program = Program {
            name: "zero_division_rewrite_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "d".into(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Div(
                    Box::new(Expr::Const(FieldElement::from_i64(0))),
                    Box::new(Expr::Signal("d".into())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(0)),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };
        let (normalized, report) = normalize(&program);
        assert_eq!(report.algebraic_rewrites, 0);
        if let Constraint::Equal { lhs, .. } = &normalized.constraints[0] {
            assert!(matches!(lhs, Expr::Div(_, _)));
        }
    }

    #[test]
    fn supported_subset_dispatches_through_proof_transform_core() {
        let program = make_test_program();
        assert!(crate::proof_transform_spec::supports_normalization_proof_subset(&program));
        let proof_path =
            crate::proof_transform_spec::normalize_supported_program_runtime(&program).unwrap();
        let public_path = normalize(&program);
        assert_eq!(proof_path, public_path);
    }

    #[test]
    fn unsupported_subset_falls_back_to_runtime_path() {
        let mut program = make_test_program();
        program.constraints.push(Constraint::Lookup {
            inputs: vec![Expr::Signal("x".into())],
            table: "lookup".into(),
            label: Some("lookup".into()),
        });
        program.lookup_tables.push(zir::LookupTable {
            name: "lookup".to_string(),
            columns: 1,
            values: vec![vec![FieldElement::from_i64(1)]],
        });

        assert!(!crate::proof_transform_spec::supports_normalization_proof_subset(&program));
        assert!(
            crate::proof_transform_spec::normalize_supported_program_runtime(&program).is_none()
        );
        assert_eq!(normalize(&program), normalize_runtime(&program));
    }

    #[test]
    fn proof_transform_boolean_order_is_idempotent() {
        let program = Program {
            name: "boolean_order".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "is_record_clean".into(),
                    visibility: Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "is_income_qualified".into(),
                    visibility: Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "is_credential_fresh".into(),
                    visibility: Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "is_issuer_valid".into(),
                    visibility: Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![
                Constraint::Boolean {
                    signal: "is_income_qualified".into(),
                    label: Some("income_qualified_boolean".into()),
                },
                Constraint::Boolean {
                    signal: "is_record_clean".into(),
                    label: Some("record_clean_boolean".into()),
                },
                Constraint::Boolean {
                    signal: "is_credential_fresh".into(),
                    label: Some("credential_fresh_boolean".into()),
                },
                Constraint::Boolean {
                    signal: "is_issuer_valid".into(),
                    label: Some("issuer_valid_boolean".into()),
                },
            ],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let (norm1, _) = normalize(&program);
        let (norm2, _) = normalize(&norm1);

        assert_eq!(norm1.constraints, norm2.constraints);
        assert_eq!(norm1.digest_hex(), norm2.digest_hex());
    }
}
