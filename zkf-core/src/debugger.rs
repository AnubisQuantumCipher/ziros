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
use crate::ir::{BlackBoxOp, Constraint, Expr, Program, Visibility};
use crate::lowering::program_zir_to_v2;
use crate::witness::{Witness, eval_expr, mod_inverse};
use crate::zir;
use crate::{FieldElement, FieldId, ZkfError, ZkfResult};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DebugOptions {
    pub stop_on_first_failure: bool,
    #[serde(default)]
    pub include_poseidon_trace: bool,
}

impl Default for DebugOptions {
    fn default() -> Self {
        Self {
            stop_on_first_failure: true,
            include_poseidon_trace: false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DebugReport {
    pub program_name: String,
    pub program_digest: String,
    pub field: FieldId,
    pub passed: bool,
    pub total_constraints: usize,
    pub evaluated_constraints: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failure_index: Option<usize>,
    pub constraints: Vec<ConstraintTrace>,
    pub symbolic_constraints: Vec<SymbolicConstraint>,
    pub symbolic_witness: Vec<SymbolicSignal>,
    pub underconstrained: UnderconstrainedAnalysis,
    pub witness_flow: WitnessFlowGraph,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poseidon_trace: Vec<PoseidonTraceEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoseidonTraceEntry {
    pub constraint_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub op: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<PoseidonTraceValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<PoseidonTraceSignal>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoseidonTraceValue {
    pub expr: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signal_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldElement>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoseidonTraceSignal {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldElement>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolicConstraint {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub form: String,
    pub expanded_form: String,
    pub dependencies: Vec<String>,
    pub unresolved_dependencies: Vec<String>,
    pub degree_estimate: u32,
    pub nonlinear: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolicSignal {
    pub name: String,
    pub visibility: Visibility,
    pub origin: SymbolicOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expr: Option<String>,
    pub dependencies: Vec<String>,
    pub unresolved_dependencies: Vec<String>,
    pub degree_estimate: u32,
    pub nonlinear: bool,
    pub resolved: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolicOrigin {
    Input,
    Constant,
    Assignment,
    Hint,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConstraintTrace {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub passed: bool,
    pub detail: ConstraintTraceDetail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConstraintTraceDetail {
    Equal {
        lhs: ExprTrace,
        rhs: ExprTrace,
        lhs_value: FieldElement,
        rhs_value: FieldElement,
    },
    Boolean {
        signal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<FieldElement>,
    },
    Range {
        signal: String,
        bits: u32,
        limit: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<FieldElement>,
    },
    BlackBox {
        op: String,
        inputs: Vec<String>,
        outputs: Vec<String>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExprTrace {
    Const {
        literal: FieldElement,
        value: FieldElement,
    },
    Signal {
        name: String,
        value: FieldElement,
    },
    Add {
        value: FieldElement,
        terms: Vec<ExprTrace>,
    },
    Sub {
        value: FieldElement,
        left: Box<ExprTrace>,
        right: Box<ExprTrace>,
    },
    Mul {
        value: FieldElement,
        left: Box<ExprTrace>,
        right: Box<ExprTrace>,
    },
    Div {
        value: FieldElement,
        numerator: Box<ExprTrace>,
        denominator: Box<ExprTrace>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessFlowGraph {
    pub nodes: Vec<WitnessFlowNode>,
    pub edges: Vec<WitnessFlowEdge>,
    pub assignments: Vec<WitnessFlowStep>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessFlowNode {
    pub name: String,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct WitnessFlowEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessFlowStep {
    pub target: String,
    pub dependencies: Vec<String>,
    pub expr: Expr,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnderconstrainedAnalysis {
    pub unconstrained_private_signals: Vec<String>,
    pub referenced_private_signals: Vec<String>,
    pub linear_private_signal_count: usize,
    pub linear_constraint_count: usize,
    pub linear_rank: usize,
    pub linear_nullity: usize,
    pub linear_only_signals: Vec<String>,
    pub linearly_underdetermined_private_signals: Vec<String>,
    pub nonlinear_constraint_count: usize,
    pub nonlinear_private_signal_count: usize,
    pub nonlinear_private_signals: Vec<String>,
    pub nonlinear_only_private_signals: Vec<String>,
    pub nonlinear_private_components: Vec<Vec<String>>,
    pub nonlinear_unanchored_components: Vec<Vec<String>>,
    pub nonlinear_potentially_free_private_signals: Vec<String>,
    pub private_signal_constraint_counts: BTreeMap<String, usize>,
    pub note: String,
}

#[derive(Debug, Clone)]
enum SymbolicDefinition {
    Input,
    Constant(FieldElement),
    Assignment(Expr),
    Hint(String),
}

#[derive(Debug, Clone)]
struct SymbolicState {
    visibility: Visibility,
    origin: SymbolicOrigin,
    definition: SymbolicDefinition,
    dependencies: BTreeSet<String>,
    nonlinear: bool,
    degree_estimate: u32,
    resolved: bool,
}

pub fn debug_program(program: &Program, witness: &Witness, options: DebugOptions) -> DebugReport {
    let mut traces = Vec::with_capacity(program.constraints.len());
    let mut first_failure = None;

    for (index, constraint) in program.constraints.iter().enumerate() {
        let trace = trace_constraint(program, witness, index, constraint);
        if !trace.passed && first_failure.is_none() {
            first_failure = Some(index);
        }
        let should_stop = !trace.passed && options.stop_on_first_failure;
        traces.push(trace);
        if should_stop {
            break;
        }
    }

    let passed = first_failure.is_none() && traces.len() == program.constraints.len();

    let (symbolic_witness, symbolic_state) = build_symbolic_witness(program);

    DebugReport {
        program_name: program.name.clone(),
        program_digest: program.digest_hex(),
        field: program.field,
        passed,
        total_constraints: program.constraints.len(),
        evaluated_constraints: traces.len(),
        first_failure_index: first_failure,
        constraints: traces,
        symbolic_constraints: build_symbolic_constraints(program, &symbolic_state),
        symbolic_witness,
        underconstrained: analyze_underconstrained(program),
        witness_flow: build_witness_flow(program),
        poseidon_trace: if options.include_poseidon_trace {
            build_poseidon_trace(program, witness)
        } else {
            Vec::new()
        },
    }
}

pub fn debug_program_zir(
    program: &zir::Program,
    witness: &Witness,
    options: DebugOptions,
) -> ZkfResult<DebugReport> {
    let lowered = program_zir_to_v2(program)?;
    Ok(debug_program(&lowered, witness, options))
}

pub fn build_witness_flow(program: &Program) -> WitnessFlowGraph {
    let nodes = program
        .signals
        .iter()
        .map(|signal| WitnessFlowNode {
            name: signal.name.clone(),
            visibility: signal.visibility.clone(),
        })
        .collect();

    let mut edges = BTreeSet::new();
    let mut assignments = Vec::new();

    for assignment in &program.witness_plan.assignments {
        let mut deps = BTreeSet::new();
        collect_expr_signal_names(&assignment.expr, &mut deps);

        for dep in &deps {
            edges.insert(WitnessFlowEdge {
                from: dep.clone(),
                to: assignment.target.clone(),
            });
        }

        assignments.push(WitnessFlowStep {
            target: assignment.target.clone(),
            dependencies: deps.into_iter().collect(),
            expr: assignment.expr.clone(),
        });
    }
    for hint in &program.witness_plan.hints {
        edges.insert(WitnessFlowEdge {
            from: hint.source.clone(),
            to: hint.target.clone(),
        });
        assignments.push(WitnessFlowStep {
            target: hint.target.clone(),
            dependencies: vec![hint.source.clone()],
            expr: Expr::Signal(hint.source.clone()),
        });
    }

    WitnessFlowGraph {
        nodes,
        edges: edges.into_iter().collect(),
        assignments,
    }
}

pub fn build_witness_flow_zir(program: &zir::Program) -> ZkfResult<WitnessFlowGraph> {
    let lowered = program_zir_to_v2(program)?;
    Ok(build_witness_flow(&lowered))
}

pub fn analyze_underconstrained(program: &Program) -> UnderconstrainedAnalysis {
    let mut referenced_private = BTreeSet::new();
    let mut referenced_any = BTreeSet::new();
    let private_signal_set = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .map(|signal| signal.name.clone())
        .collect::<BTreeSet<_>>();
    let mut private_signal_constraint_counts = BTreeMap::<String, usize>::new();
    let mut nonlinear_private_signals = BTreeSet::new();
    let mut linear_private_signals = BTreeSet::new();
    let mut nonlinear_constraint_count = 0usize;
    let mut nonlinear_adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    let mut nonlinear_anchored_private = BTreeSet::new();

    for constraint in &program.constraints {
        let nonlinear = constraint_is_nonlinear(constraint);
        if nonlinear {
            nonlinear_constraint_count += 1;
        }
        let mut local_signals = BTreeSet::new();
        match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                collect_expr_signal_names(lhs, &mut referenced_any);
                collect_expr_signal_names(rhs, &mut referenced_any);
                collect_expr_signal_names(lhs, &mut local_signals);
                collect_expr_signal_names(rhs, &mut local_signals);
            }
            Constraint::Boolean { signal, .. } | Constraint::Range { signal, .. } => {
                referenced_any.insert(signal.clone());
                local_signals.insert(signal.clone());
            }
            Constraint::BlackBox {
                inputs, outputs, ..
            } => {
                for input in inputs {
                    collect_expr_signal_names(input, &mut referenced_any);
                    collect_expr_signal_names(input, &mut local_signals);
                }
                for output in outputs {
                    referenced_any.insert(output.clone());
                    local_signals.insert(output.clone());
                }
            }
            Constraint::Lookup { inputs, .. } => {
                for input in inputs {
                    collect_expr_signal_names(input, &mut referenced_any);
                    collect_expr_signal_names(input, &mut local_signals);
                }
            }
        }

        for signal in &local_signals {
            if private_signal_set.contains(signal) {
                *private_signal_constraint_counts
                    .entry(signal.clone())
                    .or_insert(0) += 1;
                if nonlinear {
                    nonlinear_private_signals.insert(signal.clone());
                } else {
                    linear_private_signals.insert(signal.clone());
                }
            }
        }

        if nonlinear {
            let private_locals = local_signals
                .iter()
                .filter(|signal| private_signal_set.contains(*signal))
                .cloned()
                .collect::<Vec<_>>();
            let has_non_private = local_signals
                .iter()
                .any(|signal| !private_signal_set.contains(signal));

            for signal in &private_locals {
                nonlinear_adjacency.entry(signal.clone()).or_default();
                if has_non_private {
                    nonlinear_anchored_private.insert(signal.clone());
                }
            }
            for i in 0..private_locals.len() {
                for j in (i + 1)..private_locals.len() {
                    let left = private_locals[i].clone();
                    let right = private_locals[j].clone();
                    nonlinear_adjacency
                        .entry(left.clone())
                        .or_default()
                        .insert(right.clone());
                    nonlinear_adjacency.entry(right).or_default().insert(left);
                }
            }
        }
    }

    for signal in &program.signals {
        if signal.visibility == Visibility::Private && referenced_any.contains(&signal.name) {
            referenced_private.insert(signal.name.clone());
        }
    }

    let unconstrained_private_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .filter(|signal| !referenced_any.contains(&signal.name))
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();

    let private_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();

    let (linear_constraint_count, rank, pivots) = linear_rank_analysis(program, &private_signals);
    let linearly_underdetermined_private_signals = private_signals
        .iter()
        .enumerate()
        .filter_map(|(index, signal)| (!pivots.contains(&index)).then_some(signal.clone()))
        .collect::<Vec<_>>();
    let nonlinear_private_signals = nonlinear_private_signals.into_iter().collect::<Vec<_>>();
    let nonlinear_only_private_signals = nonlinear_private_signals
        .iter()
        .filter(|signal| !linear_private_signals.contains(*signal))
        .cloned()
        .collect::<Vec<_>>();
    let (nonlinear_private_components, nonlinear_unanchored_components) =
        nonlinear_components(&nonlinear_adjacency, &nonlinear_anchored_private);
    let nonlinear_potentially_free_private_signals = nonlinear_unanchored_components
        .iter()
        .flat_map(|component| component.iter().cloned())
        .collect::<Vec<_>>();

    UnderconstrainedAnalysis {
        unconstrained_private_signals,
        referenced_private_signals: referenced_private.into_iter().collect(),
        linear_private_signal_count: private_signals.len(),
        linear_constraint_count,
        linear_rank: rank,
        linear_nullity: private_signals.len().saturating_sub(rank),
        linear_only_signals: linearly_underdetermined_private_signals.clone(),
        linearly_underdetermined_private_signals,
        nonlinear_constraint_count,
        nonlinear_private_signal_count: nonlinear_private_signals.len(),
        nonlinear_private_signals,
        nonlinear_only_private_signals,
        nonlinear_private_components,
        nonlinear_unanchored_components,
        nonlinear_potentially_free_private_signals,
        private_signal_constraint_counts,
        note: "Linear rank/nullity is conservative. Non-linear participation and component anchoring highlight private signal clusters that may remain underdetermined without public anchors.".to_string(),
    }
}

fn build_poseidon_trace(program: &Program, witness: &Witness) -> Vec<PoseidonTraceEntry> {
    let mut trace = Vec::new();
    for (constraint_index, constraint) in program.constraints.iter().enumerate() {
        let Constraint::BlackBox {
            op,
            inputs,
            outputs,
            label,
            ..
        } = constraint
        else {
            continue;
        };
        if *op != BlackBoxOp::Poseidon {
            continue;
        }

        let inputs = inputs
            .iter()
            .map(|expr| {
                let mut signal_names = BTreeSet::new();
                collect_expr_signal_names(expr, &mut signal_names);
                let value = eval_expr(expr, &witness.values, program.field)
                    .ok()
                    .map(|value| FieldElement::from_bigint_with_field(value, program.field));
                PoseidonTraceValue {
                    expr: render_symbolic_expr(expr),
                    signal_names: signal_names.into_iter().collect(),
                    value,
                }
            })
            .collect::<Vec<_>>();
        let outputs = outputs
            .iter()
            .map(|name| PoseidonTraceSignal {
                name: name.clone(),
                value: witness
                    .values
                    .get(name)
                    .cloned()
                    .or_else(|| {
                        witness_value_as_bigint(name, &witness.values, program.field)
                            .ok()
                            .map(|value| FieldElement::from_bigint_with_field(value, program.field))
                    }),
            })
            .collect::<Vec<_>>();
        trace.push(PoseidonTraceEntry {
            constraint_index,
            label: label.clone(),
            op: op.as_str().to_string(),
            inputs,
            outputs,
        });
    }
    trace
}

pub fn analyze_underconstrained_zir(program: &zir::Program) -> ZkfResult<UnderconstrainedAnalysis> {
    let lowered = program_zir_to_v2(program)?;
    Ok(analyze_underconstrained(&lowered))
}

fn build_symbolic_constraints(
    program: &Program,
    symbolic_state: &BTreeMap<String, SymbolicState>,
) -> Vec<SymbolicConstraint> {
    let mut out = Vec::with_capacity(program.constraints.len());
    for (index, constraint) in program.constraints.iter().enumerate() {
        let mut dependencies = BTreeSet::new();
        let (form, expanded_form, degree_estimate, nonlinear) = match constraint {
            Constraint::Equal { lhs, rhs, .. } => {
                collect_expr_signal_names(lhs, &mut dependencies);
                collect_expr_signal_names(rhs, &mut dependencies);
                (
                    format!(
                        "{} == {}",
                        render_symbolic_expr(lhs),
                        render_symbolic_expr(rhs)
                    ),
                    format!(
                        "{} == {}",
                        render_symbolic_expr_expanded(lhs, symbolic_state, 0, &mut BTreeSet::new()),
                        render_symbolic_expr_expanded(rhs, symbolic_state, 0, &mut BTreeSet::new())
                    ),
                    expr_degree(lhs, symbolic_state).max(expr_degree(rhs, symbolic_state)),
                    expr_is_nonlinear(lhs) || expr_is_nonlinear(rhs),
                )
            }
            Constraint::Boolean { signal, .. } => {
                dependencies.insert(signal.clone());
                (
                    format!("{signal} * (1 - {signal}) == 0"),
                    format!(
                        "{} * (1 - {}) == 0",
                        render_signal_expanded(signal, symbolic_state, 0, &mut BTreeSet::new()),
                        render_signal_expanded(signal, symbolic_state, 0, &mut BTreeSet::new())
                    ),
                    2,
                    false,
                )
            }
            Constraint::Range { signal, bits, .. } => {
                dependencies.insert(signal.clone());
                (
                    format!("0 <= {signal} < 2^{bits}"),
                    format!(
                        "0 <= {} < 2^{bits}",
                        render_signal_expanded(signal, symbolic_state, 0, &mut BTreeSet::new())
                    ),
                    1,
                    false,
                )
            }
            Constraint::BlackBox {
                op,
                inputs,
                outputs,
                ..
            } => {
                for input in inputs {
                    collect_expr_signal_names(input, &mut dependencies);
                }
                for output in outputs {
                    dependencies.insert(output.clone());
                }

                let rendered_inputs = inputs
                    .iter()
                    .map(render_symbolic_expr)
                    .collect::<Vec<_>>()
                    .join(", ");
                let expanded_inputs = inputs
                    .iter()
                    .map(|expr| {
                        render_symbolic_expr_expanded(expr, symbolic_state, 0, &mut BTreeSet::new())
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let rendered_outputs = outputs.join(", ");
                let expanded_outputs = outputs
                    .iter()
                    .map(|output| {
                        render_signal_expanded(output, symbolic_state, 0, &mut BTreeSet::new())
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let nonlinear = !matches!(op, BlackBoxOp::RecursiveAggregationMarker);
                (
                    format!(
                        "blackbox {}({}) -> [{}]",
                        op.as_str(),
                        rendered_inputs,
                        rendered_outputs
                    ),
                    format!(
                        "blackbox {}({}) -> [{}]",
                        op.as_str(),
                        expanded_inputs,
                        expanded_outputs
                    ),
                    2,
                    nonlinear,
                )
            }
            Constraint::Lookup { inputs, table, .. } => {
                for input in inputs {
                    collect_expr_signal_names(input, &mut dependencies);
                }
                let rendered_inputs = inputs
                    .iter()
                    .map(render_symbolic_expr)
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    format!("Lookup(table={table})({rendered_inputs})"),
                    format!("Lookup(table={table})({rendered_inputs})"),
                    1,
                    false,
                )
            }
        };
        let dependencies = dependencies.into_iter().collect::<Vec<_>>();
        let unresolved_dependencies = dependencies
            .iter()
            .filter(|name| {
                !symbolic_state
                    .get(*name)
                    .is_some_and(|state| state.resolved)
            })
            .cloned()
            .collect::<Vec<_>>();
        out.push(SymbolicConstraint {
            index,
            label: constraint.label().cloned(),
            form,
            expanded_form,
            dependencies,
            unresolved_dependencies,
            degree_estimate,
            nonlinear,
        });
    }
    out
}

fn build_symbolic_witness(
    program: &Program,
) -> (Vec<SymbolicSignal>, BTreeMap<String, SymbolicState>) {
    let mut state = BTreeMap::<String, SymbolicState>::new();
    for signal in &program.signals {
        let initial = if let Some(constant) = &signal.constant {
            SymbolicState {
                visibility: signal.visibility.clone(),
                origin: SymbolicOrigin::Constant,
                definition: SymbolicDefinition::Constant(constant.clone()),
                dependencies: BTreeSet::new(),
                nonlinear: false,
                degree_estimate: 0,
                resolved: true,
            }
        } else {
            SymbolicState {
                visibility: signal.visibility.clone(),
                origin: SymbolicOrigin::Input,
                definition: SymbolicDefinition::Input,
                dependencies: BTreeSet::new(),
                nonlinear: false,
                degree_estimate: 1,
                resolved: true,
            }
        };
        state.insert(signal.name.clone(), initial);
    }

    for assignment in &program.witness_plan.assignments {
        if !state.contains_key(&assignment.target) {
            continue;
        }
        let mut deps = BTreeSet::new();
        collect_expr_signal_names(&assignment.expr, &mut deps);
        let degree = expr_degree(&assignment.expr, &state);
        if let Some(target) = state.get_mut(&assignment.target) {
            target.origin = SymbolicOrigin::Assignment;
            target.definition = SymbolicDefinition::Assignment(assignment.expr.clone());
            target.dependencies = deps;
            target.nonlinear = expr_is_nonlinear(&assignment.expr);
            target.degree_estimate = degree;
            target.resolved = false;
        }
    }
    for hint in &program.witness_plan.hints {
        if let Some(target) = state.get_mut(&hint.target) {
            if matches!(target.origin, SymbolicOrigin::Assignment) {
                continue;
            }
            let mut deps = BTreeSet::new();
            deps.insert(hint.source.clone());
            target.origin = SymbolicOrigin::Hint;
            target.definition = SymbolicDefinition::Hint(hint.source.clone());
            target.dependencies = deps;
            target.nonlinear = false;
            target.degree_estimate = 1;
            target.resolved = false;
        }
    }

    let mut progress = true;
    while progress {
        progress = false;

        for assignment in &program.witness_plan.assignments {
            if !state.contains_key(&assignment.target) {
                continue;
            }
            let mut deps = BTreeSet::new();
            collect_expr_signal_names(&assignment.expr, &mut deps);
            let resolved = deps
                .iter()
                .all(|dep| state.get(dep).is_some_and(|s| s.resolved));
            let degree = expr_degree(&assignment.expr, &state);
            let nonlinear = expr_is_nonlinear(&assignment.expr) || degree > 1;

            if let Some(target) = state.get_mut(&assignment.target) {
                let was_resolved = target.resolved;
                target.origin = SymbolicOrigin::Assignment;
                target.definition = SymbolicDefinition::Assignment(assignment.expr.clone());
                target.dependencies = deps;
                target.degree_estimate = degree;
                target.nonlinear = nonlinear;
                target.resolved = resolved;
                if !was_resolved && resolved {
                    progress = true;
                }
            }
        }

        for hint in &program.witness_plan.hints {
            if !state.contains_key(&hint.target) {
                continue;
            }
            let source_resolved = state.get(&hint.source).is_some_and(|s| s.resolved);
            let source_degree = state.get(&hint.source).map_or(1, |s| s.degree_estimate);
            let source_nonlinear = state.get(&hint.source).is_some_and(|s| s.nonlinear);
            if let Some(target) = state.get(&hint.target)
                && target.resolved
            {
                continue;
            }
            if let Some(target) = state.get_mut(&hint.target) {
                let mut deps = BTreeSet::new();
                deps.insert(hint.source.clone());
                target.origin = SymbolicOrigin::Hint;
                target.definition = SymbolicDefinition::Hint(hint.source.clone());
                target.dependencies = deps;
                target.degree_estimate = source_degree;
                target.nonlinear = source_nonlinear;
                target.resolved = source_resolved;
                if source_resolved {
                    progress = true;
                }
            }
        }
    }

    let symbolic = program
        .signals
        .iter()
        .filter_map(|signal| {
            state.get(&signal.name).map(|entry| {
                let dependencies = entry.dependencies.iter().cloned().collect::<Vec<_>>();
                let unresolved_dependencies = dependencies
                    .iter()
                    .filter(|name| !state.get(*name).is_some_and(|dep| dep.resolved))
                    .cloned()
                    .collect::<Vec<_>>();
                let expr = if entry.resolved {
                    Some(render_signal_expanded(
                        &signal.name,
                        &state,
                        0,
                        &mut BTreeSet::new(),
                    ))
                } else {
                    match &entry.definition {
                        SymbolicDefinition::Assignment(expr) => Some(render_symbolic_expr(expr)),
                        SymbolicDefinition::Hint(source) => Some(source.clone()),
                        SymbolicDefinition::Constant(value) => Some(value.to_decimal_string()),
                        SymbolicDefinition::Input => None,
                    }
                };

                SymbolicSignal {
                    name: signal.name.clone(),
                    visibility: entry.visibility.clone(),
                    origin: entry.origin,
                    expr,
                    dependencies,
                    unresolved_dependencies,
                    degree_estimate: entry.degree_estimate,
                    nonlinear: entry.nonlinear,
                    resolved: entry.resolved,
                }
            })
        })
        .collect::<Vec<_>>();
    (symbolic, state)
}

fn render_signal_expanded(
    signal: &str,
    state: &BTreeMap<String, SymbolicState>,
    depth: usize,
    visiting: &mut BTreeSet<String>,
) -> String {
    const MAX_DEPTH: usize = 8;
    if depth >= MAX_DEPTH || visiting.contains(signal) {
        return signal.to_string();
    }
    let Some(entry) = state.get(signal) else {
        return signal.to_string();
    };
    match &entry.definition {
        SymbolicDefinition::Input => signal.to_string(),
        SymbolicDefinition::Constant(value) => value.to_decimal_string(),
        SymbolicDefinition::Hint(source) => {
            visiting.insert(signal.to_string());
            let out = render_signal_expanded(source, state, depth + 1, visiting);
            visiting.remove(signal);
            out
        }
        SymbolicDefinition::Assignment(expr) => {
            visiting.insert(signal.to_string());
            let out = render_symbolic_expr_expanded(expr, state, depth + 1, visiting);
            visiting.remove(signal);
            out
        }
    }
}

fn render_symbolic_expr_expanded(
    expr: &Expr,
    state: &BTreeMap<String, SymbolicState>,
    depth: usize,
    visiting: &mut BTreeSet<String>,
) -> String {
    match expr {
        Expr::Const(value) => value.to_decimal_string(),
        Expr::Signal(name) => render_signal_expanded(name, state, depth + 1, visiting),
        Expr::Add(values) => {
            let parts = values
                .iter()
                .map(|value| render_symbolic_expr_expanded(value, state, depth + 1, visiting))
                .collect::<Vec<_>>();
            format!("({})", parts.join(" + "))
        }
        Expr::Sub(left, right) => format!(
            "({} - {})",
            render_symbolic_expr_expanded(left, state, depth + 1, visiting),
            render_symbolic_expr_expanded(right, state, depth + 1, visiting)
        ),
        Expr::Mul(left, right) => format!(
            "({} * {})",
            render_symbolic_expr_expanded(left, state, depth + 1, visiting),
            render_symbolic_expr_expanded(right, state, depth + 1, visiting)
        ),
        Expr::Div(left, right) => format!(
            "({} / {})",
            render_symbolic_expr_expanded(left, state, depth + 1, visiting),
            render_symbolic_expr_expanded(right, state, depth + 1, visiting)
        ),
    }
}

fn expr_degree(expr: &Expr, state: &BTreeMap<String, SymbolicState>) -> u32 {
    match expr {
        Expr::Const(_) => 0,
        Expr::Signal(signal) => state.get(signal).map_or(1, |s| s.degree_estimate),
        Expr::Add(values) => values
            .iter()
            .map(|value| expr_degree(value, state))
            .max()
            .unwrap_or(0),
        Expr::Sub(left, right) => expr_degree(left, state).max(expr_degree(right, state)),
        Expr::Mul(left, right) => {
            expr_degree(left, state).saturating_add(expr_degree(right, state))
        }
        Expr::Div(left, right) => {
            let right_is_const = matches!(right.as_ref(), Expr::Const(_));
            if right_is_const {
                expr_degree(left, state)
            } else {
                expr_degree(left, state)
                    .saturating_add(expr_degree(right, state))
                    .saturating_add(1)
            }
        }
    }
}

fn nonlinear_components(
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    anchored: &BTreeSet<String>,
) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let mut visited = BTreeSet::new();
    let mut components = Vec::new();
    let mut unanchored = Vec::new();

    for node in adjacency.keys() {
        if visited.contains(node) {
            continue;
        }
        let mut stack = vec![node.clone()];
        let mut component = BTreeSet::new();
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            component.insert(current.clone());
            if let Some(neighbors) = adjacency.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        if component.is_empty() {
            continue;
        }
        let mut component_vec = component.into_iter().collect::<Vec<_>>();
        component_vec.sort();
        let component_is_anchored = component_vec.iter().any(|name| anchored.contains(name));
        if !component_is_anchored {
            unanchored.push(component_vec.clone());
        }
        components.push(component_vec);
    }
    components.sort();
    unanchored.sort();
    (components, unanchored)
}

fn render_symbolic_expr(expr: &Expr) -> String {
    match expr {
        Expr::Const(value) => value.to_decimal_string(),
        Expr::Signal(name) => name.clone(),
        Expr::Add(values) => {
            let parts = values.iter().map(render_symbolic_expr).collect::<Vec<_>>();
            format!("({})", parts.join(" + "))
        }
        Expr::Sub(left, right) => {
            format!(
                "({} - {})",
                render_symbolic_expr(left),
                render_symbolic_expr(right)
            )
        }
        Expr::Mul(left, right) => {
            format!(
                "({} * {})",
                render_symbolic_expr(left),
                render_symbolic_expr(right)
            )
        }
        Expr::Div(left, right) => {
            format!(
                "({} / {})",
                render_symbolic_expr(left),
                render_symbolic_expr(right)
            )
        }
    }
}

fn constraint_is_nonlinear(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => expr_is_nonlinear(lhs) || expr_is_nonlinear(rhs),
        Constraint::Boolean { .. } | Constraint::Range { .. } | Constraint::Lookup { .. } => false,
        Constraint::BlackBox { op, .. } => !matches!(op, BlackBoxOp::RecursiveAggregationMarker),
    }
}

fn expr_is_nonlinear(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) | Expr::Signal(_) => false,
        Expr::Add(values) => values.iter().any(expr_is_nonlinear),
        Expr::Sub(left, right) => expr_is_nonlinear(left) || expr_is_nonlinear(right),
        Expr::Mul(left, right) => {
            let left_const = matches!(left.as_ref(), Expr::Const(_));
            let right_const = matches!(right.as_ref(), Expr::Const(_));
            (!left_const && !right_const) || expr_is_nonlinear(left) || expr_is_nonlinear(right)
        }
        Expr::Div(left, right) => {
            let right_const = matches!(right.as_ref(), Expr::Const(_));
            !right_const || expr_is_nonlinear(left) || expr_is_nonlinear(right)
        }
    }
}

fn trace_constraint(
    program: &Program,
    witness: &Witness,
    index: usize,
    constraint: &Constraint,
) -> ConstraintTrace {
    match constraint {
        Constraint::Equal { lhs, rhs, label } => {
            let lhs_trace = trace_expr(lhs, &witness.values, program.field);
            let rhs_trace = trace_expr(rhs, &witness.values, program.field);

            match (lhs_trace, rhs_trace) {
                (Ok(lhs_trace), Ok(rhs_trace)) => {
                    let passed = lhs_trace.value == rhs_trace.value;
                    ConstraintTrace {
                        index,
                        label: label.clone(),
                        passed,
                        detail: ConstraintTraceDetail::Equal {
                            lhs: lhs_trace.expr,
                            rhs: rhs_trace.expr,
                            lhs_value: FieldElement::from_bigint_with_field(
                                lhs_trace.value,
                                program.field,
                            ),
                            rhs_value: FieldElement::from_bigint_with_field(
                                rhs_trace.value,
                                program.field,
                            ),
                        },
                        error: None,
                    }
                }
                (Err(err), _) | (_, Err(err)) => ConstraintTrace {
                    index,
                    label: label.clone(),
                    passed: false,
                    detail: ConstraintTraceDetail::Equal {
                        lhs: ExprTrace::Const {
                            literal: FieldElement::from_i64(0),
                            value: FieldElement::from_i64(0),
                        },
                        rhs: ExprTrace::Const {
                            literal: FieldElement::from_i64(0),
                            value: FieldElement::from_i64(0),
                        },
                        lhs_value: FieldElement::from_i64(0),
                        rhs_value: FieldElement::from_i64(0),
                    },
                    error: Some(err.to_string()),
                },
            }
        }
        Constraint::Boolean { signal, label } => {
            match witness_value_as_bigint(signal, &witness.values, program.field) {
                Ok(value) => {
                    let passed = value == BigInt::zero() || value == BigInt::one();
                    ConstraintTrace {
                        index,
                        label: label.clone(),
                        passed,
                        detail: ConstraintTraceDetail::Boolean {
                            signal: signal.clone(),
                            value: Some(FieldElement::from_bigint_with_field(value, program.field)),
                        },
                        error: None,
                    }
                }
                Err(err) => ConstraintTrace {
                    index,
                    label: label.clone(),
                    passed: false,
                    detail: ConstraintTraceDetail::Boolean {
                        signal: signal.clone(),
                        value: None,
                    },
                    error: Some(err.to_string()),
                },
            }
        }
        Constraint::Range {
            signal,
            bits,
            label,
        } => {
            let limit = (BigInt::from(1u8) << *bits).to_string();
            match witness_value_as_bigint(signal, &witness.values, program.field) {
                Ok(value) => {
                    let passed = value < (BigInt::from(1u8) << *bits);
                    ConstraintTrace {
                        index,
                        label: label.clone(),
                        passed,
                        detail: ConstraintTraceDetail::Range {
                            signal: signal.clone(),
                            bits: *bits,
                            limit,
                            value: Some(FieldElement::from_bigint_with_field(value, program.field)),
                        },
                        error: None,
                    }
                }
                Err(err) => ConstraintTrace {
                    index,
                    label: label.clone(),
                    passed: false,
                    detail: ConstraintTraceDetail::Range {
                        signal: signal.clone(),
                        bits: *bits,
                        limit,
                        value: None,
                    },
                    error: Some(err.to_string()),
                },
            }
        }
        Constraint::BlackBox {
            op,
            inputs,
            outputs,
            label,
            ..
        } => {
            let input_err = inputs
                .iter()
                .map(|input| eval_expr(input, &witness.values, program.field))
                .find_map(Result::err);
            let mut output_err = None;
            let mut boolean_err = None;
            for output in outputs {
                match witness_value_as_bigint(output, &witness.values, program.field) {
                    Ok(value) => {
                        if matches!(
                            op,
                            BlackBoxOp::SchnorrVerify
                                | BlackBoxOp::EcdsaSecp256k1
                                | BlackBoxOp::EcdsaSecp256r1
                        ) && value != BigInt::zero()
                            && value != BigInt::one()
                        {
                            boolean_err = Some(format!(
                                "boolean blackbox output '{}' for op '{}' was {}",
                                output,
                                op.as_str(),
                                value
                            ));
                            break;
                        }
                    }
                    Err(err) => {
                        output_err = Some(err.to_string());
                        break;
                    }
                }
            }

            let error = input_err
                .map(|err| err.to_string())
                .or(output_err)
                .or(boolean_err);
            ConstraintTrace {
                index,
                label: label.clone(),
                passed: error.is_none(),
                detail: ConstraintTraceDetail::BlackBox {
                    op: op.as_str().to_string(),
                    inputs: inputs.iter().map(render_symbolic_expr).collect(),
                    outputs: outputs.clone(),
                },
                error,
            }
        }
        Constraint::Lookup {
            table,
            inputs,
            label,
            ..
        } => {
            // Lookup constraints evaluated by backend after lowering
            ConstraintTrace {
                index,
                label: label.clone(),
                passed: true,
                detail: ConstraintTraceDetail::BlackBox {
                    op: format!("Lookup(table={table})"),
                    inputs: inputs.iter().map(render_symbolic_expr).collect(),
                    outputs: vec![],
                },
                error: None,
            }
        }
    }
}

#[derive(Debug, Clone)]
struct EvaluatedExprTrace {
    expr: ExprTrace,
    value: BigInt,
}

fn trace_expr(
    expr: &Expr,
    values: &BTreeMap<String, FieldElement>,
    field: FieldId,
) -> ZkfResult<EvaluatedExprTrace> {
    let modulus = field.modulus();
    match expr {
        Expr::Const(value) => {
            let literal = value.clone();
            let normalized = value.normalized_bigint(field)?;
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Const {
                    literal,
                    value: FieldElement::from_bigint_with_field(normalized.clone(), field),
                },
                value: normalized,
            })
        }
        Expr::Signal(name) => {
            let value = witness_value_as_bigint(name, values, field)?;
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Signal {
                    name: name.clone(),
                    value: FieldElement::from_bigint_with_field(value.clone(), field),
                },
                value,
            })
        }
        Expr::Add(terms) => {
            let mut out_terms = Vec::with_capacity(terms.len());
            let mut acc = BigInt::zero();
            for term in terms {
                let traced = trace_expr(term, values, field)?;
                acc += traced.value.clone();
                out_terms.push(traced.expr);
            }
            let normalized = normalize_mod(acc, modulus);
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Add {
                    value: FieldElement::from_bigint_with_field(normalized.clone(), field),
                    terms: out_terms,
                },
                value: normalized,
            })
        }
        Expr::Sub(left, right) => {
            let left = trace_expr(left, values, field)?;
            let right = trace_expr(right, values, field)?;
            let normalized = normalize_mod(left.value.clone() - right.value.clone(), modulus);
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Sub {
                    value: FieldElement::from_bigint_with_field(normalized.clone(), field),
                    left: Box::new(left.expr),
                    right: Box::new(right.expr),
                },
                value: normalized,
            })
        }
        Expr::Mul(left, right) => {
            let left = trace_expr(left, values, field)?;
            let right = trace_expr(right, values, field)?;
            let normalized = normalize_mod(left.value.clone() * right.value.clone(), modulus);
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Mul {
                    value: FieldElement::from_bigint_with_field(normalized.clone(), field),
                    left: Box::new(left.expr),
                    right: Box::new(right.expr),
                },
                value: normalized,
            })
        }
        Expr::Div(numerator, denominator) => {
            let numerator = trace_expr(numerator, values, field)?;
            let denominator = trace_expr(denominator, values, field)?;
            let denominator_norm = normalize_mod(denominator.value.clone(), modulus);
            let inverse = mod_inverse(denominator_norm, modulus).ok_or(ZkfError::DivisionByZero)?;
            let normalized = normalize_mod(numerator.value.clone() * inverse, modulus);
            Ok(EvaluatedExprTrace {
                expr: ExprTrace::Div {
                    value: FieldElement::from_bigint_with_field(normalized.clone(), field),
                    numerator: Box::new(numerator.expr),
                    denominator: Box::new(denominator.expr),
                },
                value: normalized,
            })
        }
    }
}

fn witness_value_as_bigint(
    signal: &str,
    values: &BTreeMap<String, FieldElement>,
    field: FieldId,
) -> ZkfResult<BigInt> {
    values
        .get(signal)
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: signal.to_string(),
        })?
        .normalized_bigint(field)
}

fn collect_expr_signal_names(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            out.insert(name.clone());
        }
        Expr::Add(values) => {
            for value in values {
                collect_expr_signal_names(value, out);
            }
        }
        Expr::Sub(left, right) | Expr::Mul(left, right) | Expr::Div(left, right) => {
            collect_expr_signal_names(left, out);
            collect_expr_signal_names(right, out);
        }
    }
}

#[derive(Debug, Clone)]
struct LinearExpr {
    coeffs: BTreeMap<String, BigInt>,
    constant: BigInt,
}

impl LinearExpr {
    fn zero() -> Self {
        Self {
            coeffs: BTreeMap::new(),
            constant: BigInt::zero(),
        }
    }

    fn add_scaled(&mut self, other: &LinearExpr, scale: &BigInt, field: FieldId) {
        self.constant = normalize_mod(
            self.constant.clone() + scale.clone() * other.constant.clone(),
            field.modulus(),
        );

        for (signal, coefficient) in &other.coeffs {
            let next = self
                .coeffs
                .get(signal)
                .cloned()
                .unwrap_or_else(BigInt::zero)
                + scale.clone() * coefficient.clone();
            let normalized = normalize_mod(next, field.modulus());
            if normalized.is_zero() {
                self.coeffs.remove(signal);
            } else {
                self.coeffs.insert(signal.clone(), normalized);
            }
        }
    }
}

fn linear_rank_analysis(
    program: &Program,
    private_signals: &[String],
) -> (usize, usize, BTreeSet<usize>) {
    if private_signals.is_empty() {
        return (0, 0, BTreeSet::new());
    }

    let column_index = private_signals
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect::<BTreeMap<_, _>>();

    let mut rows = Vec::new();
    let mut active_columns = BTreeSet::new();
    let mut linear_constraint_count = 0usize;

    for constraint in &program.constraints {
        let Constraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        let Some(lhs_linear) = extract_linear_expr(lhs, program.field) else {
            continue;
        };
        let Some(rhs_linear) = extract_linear_expr(rhs, program.field) else {
            continue;
        };

        linear_constraint_count += 1;
        let mut diff = LinearExpr::zero();
        diff.add_scaled(&lhs_linear, &BigInt::one(), program.field);
        diff.add_scaled(&rhs_linear, &BigInt::from(-1_i8), program.field);

        let mut row = BTreeMap::new();
        for (signal, coefficient) in diff.coeffs {
            if let Some(index) = column_index.get(&signal) {
                let coefficient = normalize_mod(coefficient, program.field.modulus());
                if !coefficient.is_zero() {
                    active_columns.insert(*index);
                    row.insert(*index, coefficient);
                }
            }
        }

        if !row.is_empty() {
            rows.push(row);
        }
    }

    let (rank, pivots) = gaussian_elimination_rank(
        &rows,
        active_columns.into_iter().collect(),
        program.field.modulus(),
    );
    (linear_constraint_count, rank, pivots.into_iter().collect())
}

fn extract_linear_expr(expr: &Expr, field: FieldId) -> Option<LinearExpr> {
    match expr {
        Expr::Const(value) => Some(LinearExpr {
            coeffs: BTreeMap::new(),
            constant: value.normalized_bigint(field).ok()?,
        }),
        Expr::Signal(signal) => {
            let mut coeffs = BTreeMap::new();
            coeffs.insert(signal.clone(), BigInt::one());
            Some(LinearExpr {
                coeffs,
                constant: BigInt::zero(),
            })
        }
        Expr::Add(values) => {
            let mut out = LinearExpr::zero();
            for value in values {
                let value = extract_linear_expr(value, field)?;
                out.add_scaled(&value, &BigInt::one(), field);
            }
            Some(out)
        }
        Expr::Sub(left, right) => {
            let left = extract_linear_expr(left, field)?;
            let right = extract_linear_expr(right, field)?;
            let mut out = LinearExpr::zero();
            out.add_scaled(&left, &BigInt::one(), field);
            out.add_scaled(&right, &BigInt::from(-1_i8), field);
            Some(out)
        }
        Expr::Mul(left, right) => {
            if let Some(scale) = const_value(left, field) {
                let mut out = extract_linear_expr(right, field)?;
                scale_linear_expr(&mut out, &scale, field);
                return Some(out);
            }
            if let Some(scale) = const_value(right, field) {
                let mut out = extract_linear_expr(left, field)?;
                scale_linear_expr(&mut out, &scale, field);
                return Some(out);
            }
            None
        }
        Expr::Div(numerator, denominator) => {
            let denominator = const_value(denominator, field)?;
            let inv = mod_inverse(denominator, field.modulus())?;
            let mut out = extract_linear_expr(numerator, field)?;
            scale_linear_expr(&mut out, &inv, field);
            Some(out)
        }
    }
}

fn const_value(expr: &Expr, field: FieldId) -> Option<BigInt> {
    let linear = extract_linear_expr(expr, field)?;
    if linear.coeffs.is_empty() {
        Some(linear.constant)
    } else {
        None
    }
}

fn scale_linear_expr(expr: &mut LinearExpr, scale: &BigInt, field: FieldId) {
    expr.constant = normalize_mod(expr.constant.clone() * scale.clone(), field.modulus());
    for coefficient in expr.coeffs.values_mut() {
        *coefficient = normalize_mod(coefficient.clone() * scale.clone(), field.modulus());
    }
}

#[allow(clippy::needless_range_loop)]
fn gaussian_elimination_rank(
    matrix: &[BTreeMap<usize, BigInt>],
    columns: Vec<usize>,
    modulus: &BigInt,
) -> (usize, Vec<usize>) {
    if matrix.is_empty() || columns.is_empty() {
        return (0, Vec::new());
    }

    let rows = matrix.len();
    let mut work = matrix.to_vec();
    let mut rank = 0usize;
    let mut pivots = Vec::new();

    for col in columns {
        if rank >= rows {
            break;
        }

        let mut pivot_row = None;
        for row in rank..rows {
            let Some(value) = work[row].get(&col) else {
                continue;
            };
            if !normalize_mod(value.clone(), modulus).is_zero() {
                pivot_row = Some(row);
                break;
            }
        }

        let Some(pivot_row) = pivot_row else {
            continue;
        };

        if pivot_row != rank {
            work.swap(pivot_row, rank);
        }

        let Some(pivot_value) = work[rank].get(&col).cloned() else {
            continue;
        };
        let pivot_value = normalize_mod(pivot_value, modulus);
        let Some(pivot_inverse) = mod_inverse(pivot_value, modulus) else {
            continue;
        };

        for value in work[rank].values_mut() {
            *value = normalize_mod(value.clone() * pivot_inverse.clone(), modulus);
        }
        work[rank].retain(|_, value| !value.is_zero());
        let pivot_entries = work[rank]
            .iter()
            .map(|(column, value)| (*column, value.clone()))
            .collect::<Vec<_>>();

        for row in 0..rows {
            if row == rank {
                continue;
            }
            let Some(factor) = work[row].get(&col).cloned() else {
                continue;
            };
            let factor = normalize_mod(factor, modulus);
            if factor.is_zero() {
                continue;
            }
            for (column, pivot_value) in &pivot_entries {
                let current = work[row].get(column).cloned().unwrap_or_else(BigInt::zero);
                let updated =
                    normalize_mod(current - factor.clone() * pivot_value.clone(), modulus);
                if updated.is_zero() {
                    work[row].remove(column);
                } else {
                    work[row].insert(*column, updated);
                }
            }
        }

        pivots.push(col);
        rank += 1;
    }

    (rank, pivots)
}
