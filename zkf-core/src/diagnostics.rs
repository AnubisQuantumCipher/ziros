use crate::FieldId;
use crate::debugger::{WitnessFlowGraph, build_witness_flow};
use crate::ir::{Constraint, Expr, Program, Visibility};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub signal_count: usize,
    pub constraint_count: usize,
    pub unconstrained_private_signals: Vec<String>,
    pub referenced_signals: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SignalVisibilitySummary {
    pub public: usize,
    pub private: usize,
    pub constant: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct CircuitSummaryOptions {
    pub include_assignments: bool,
    pub include_flow: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CircuitSummary {
    pub program_name: String,
    pub program_digest: String,
    pub field: FieldId,
    pub signal_count: usize,
    pub signals_by_visibility: SignalVisibilitySummary,
    pub constraint_count: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraint_kinds: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blackbox_ops: BTreeMap<String, usize>,
    pub witness_assignment_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_assignment_targets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconstrained_private_signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_flow: Option<WitnessFlowGraph>,
}

pub fn analyze_program(program: &Program) -> DiagnosticsReport {
    let mut referenced = BTreeSet::new();

    for constraint in &program.constraints {
        match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                collect_expr_signals(lhs, &mut referenced);
                collect_expr_signals(rhs, &mut referenced);
            }
            Constraint::Boolean { signal, .. } | Constraint::Range { signal, .. } => {
                referenced.insert(signal.as_str());
            }
            Constraint::BlackBox {
                inputs, outputs, ..
            } => {
                for input in inputs {
                    collect_expr_signals(input, &mut referenced);
                }
                for output in outputs {
                    referenced.insert(output.as_str());
                }
            }
            Constraint::Lookup {
                inputs, outputs, ..
            } => {
                for input in inputs {
                    collect_expr_signals(input, &mut referenced);
                }
                if let Some(outputs) = outputs {
                    for output in outputs {
                        referenced.insert(output.as_str());
                    }
                }
            }
        }
    }

    let unconstrained_private_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .filter(|signal| !referenced.contains(signal.name.as_str()))
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();

    DiagnosticsReport {
        signal_count: program.signals.len(),
        constraint_count: program.constraints.len(),
        unconstrained_private_signals,
        referenced_signals: referenced.into_iter().map(str::to_owned).collect(),
    }
}

pub fn summarize_program(program: &Program, options: CircuitSummaryOptions) -> CircuitSummary {
    let diagnostics = analyze_program(program);
    let mut signals_by_visibility = SignalVisibilitySummary::default();
    for signal in &program.signals {
        match signal.visibility {
            Visibility::Public => signals_by_visibility.public += 1,
            Visibility::Private => signals_by_visibility.private += 1,
            Visibility::Constant => signals_by_visibility.constant += 1,
        }
    }

    let mut constraint_kinds = BTreeMap::new();
    let mut blackbox_ops = BTreeMap::new();
    for constraint in &program.constraints {
        *constraint_kinds
            .entry(constraint_kind_name(constraint).to_string())
            .or_insert(0) += 1;
        if let Constraint::BlackBox { op, .. } = constraint {
            *blackbox_ops.entry(op.as_str().to_string()).or_insert(0) += 1;
        }
    }

    CircuitSummary {
        program_name: program.name.clone(),
        program_digest: program.digest_hex(),
        field: program.field,
        signal_count: diagnostics.signal_count,
        signals_by_visibility,
        constraint_count: diagnostics.constraint_count,
        constraint_kinds,
        blackbox_ops,
        witness_assignment_count: program.witness_plan.assignments.len(),
        witness_assignment_targets: options.include_assignments.then(|| {
            program
                .witness_plan
                .assignments
                .iter()
                .map(|assignment| assignment.target.clone())
                .collect()
        }),
        unconstrained_private_signals: diagnostics.unconstrained_private_signals,
        witness_flow: options.include_flow.then(|| build_witness_flow(program)),
    }
}

fn collect_expr_signals<'a>(expr: &'a Expr, out: &mut BTreeSet<&'a str>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            out.insert(name);
        }
        Expr::Add(values) => {
            for value in values {
                collect_expr_signals(value, out);
            }
        }
        Expr::Sub(a, b) | Expr::Mul(a, b) | Expr::Div(a, b) => {
            collect_expr_signals(a, out);
            collect_expr_signals(b, out);
        }
    }
}

fn constraint_kind_name(constraint: &Constraint) -> &'static str {
    match constraint {
        Constraint::Equal { .. } => "equal",
        Constraint::Boolean { .. } => "boolean",
        Constraint::Range { .. } => "range",
        Constraint::BlackBox { .. } => "blackbox",
        Constraint::Lookup { .. } => "lookup",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlackBoxOp, FieldElement, Signal, WitnessAssignment, WitnessPlan};

    #[test]
    fn analyze_program_treats_lookup_outputs_as_referenced() {
        let program = Program {
            name: "lookup-summary".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "selector".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "mapped".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Lookup {
                inputs: vec![Expr::signal("selector")],
                table: "lut".into(),
                outputs: Some(vec!["mapped".into()]),
                label: None,
            }],
            ..Program::default()
        };

        let diagnostics = analyze_program(&program);
        assert!(diagnostics.unconstrained_private_signals.is_empty());
    }

    #[test]
    fn summarize_program_reports_constraint_kinds_blackboxes_and_flow() {
        let program = Program {
            name: "summary-demo".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "a".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "digest".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Boolean {
                    signal: "a".into(),
                    label: None,
                },
                Constraint::BlackBox {
                    op: BlackBoxOp::Poseidon,
                    inputs: vec![Expr::signal("a")],
                    outputs: vec!["digest".into()],
                    params: BTreeMap::new(),
                    label: None,
                },
            ],
            witness_plan: WitnessPlan {
                assignments: vec![WitnessAssignment {
                    target: "digest".into(),
                    expr: Expr::Const(FieldElement::from_i64(7)),
                }],
                ..WitnessPlan::default()
            },
            ..Program::default()
        };

        let summary = summarize_program(
            &program,
            CircuitSummaryOptions {
                include_assignments: true,
                include_flow: true,
            },
        );

        assert_eq!(summary.program_name, "summary-demo");
        assert_eq!(summary.field, FieldId::Bn254);
        assert_eq!(summary.signal_count, 2);
        assert_eq!(summary.signals_by_visibility.private, 1);
        assert_eq!(summary.signals_by_visibility.public, 1);
        assert_eq!(summary.constraint_kinds.get("boolean"), Some(&1));
        assert_eq!(summary.constraint_kinds.get("blackbox"), Some(&1));
        assert_eq!(summary.blackbox_ops.get("poseidon"), Some(&1));
        assert_eq!(summary.witness_assignment_count, 1);
        assert_eq!(
            summary.witness_assignment_targets,
            Some(vec!["digest".to_string()])
        );
        assert!(summary.witness_flow.is_some());
    }
}
