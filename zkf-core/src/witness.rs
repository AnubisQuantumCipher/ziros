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

use crate::FieldId;
use crate::error::{ZkfError, ZkfResult};
use crate::field::{
    FieldElement, add as field_add, div as field_div, inv as field_inv,
    is_boolean as field_is_boolean, mul as field_mul, normalize as field_normalize,
    sub as field_sub,
};
use crate::ir::{BlackBoxOp, Constraint, Expr, Program, Visibility, WitnessHintKind};
use crate::proof_kernel::{
    self, KernelCheckError, KernelConstraint, KernelExpr, KernelLookupTable, KernelProgram,
    KernelWitness,
};
use crate::proof_kernel_spec;
use crate::proof_kernel_spec::{
    SpecFieldValue, SpecKernelCheckError, SpecKernelConstraint, SpecKernelExpr,
    SpecKernelLookupTable, SpecKernelProgram, SpecKernelWitness, SpecLookupFailureKind,
};
use crate::proof_witness_generation_spec::{
    SpecWitnessAssignment, SpecWitnessGenerationError, SpecWitnessGenerationProgram,
    SpecWitnessHint, SpecWitnessSignal,
};
#[cfg(feature = "acvm-solver-beta19")]
use acir_beta19::AcirField as _;
#[cfg(feature = "acvm-solver-beta19")]
use acir_beta19::FieldElement as Beta19FieldElement;
#[cfg(feature = "acvm-solver-beta19")]
use acir_beta19::circuit::Program as Beta19Program;
#[cfg(feature = "acvm-solver-beta19")]
use acir_beta19::native_types::{Witness as Beta19Witness, WitnessMap as Beta19WitnessMap};
#[cfg(feature = "acvm-solver-beta19")]
use acvm_beta19::brillig_vm::brillig::ForeignCallResult as Beta19ForeignCallResult;
#[cfg(feature = "acvm-solver-beta19")]
use acvm_beta19::pwg::{ACVM as Beta19Acvm, ACVMStatus as Beta19AcvmStatus};
#[cfg(feature = "acvm-solver-beta19")]
use base64::Engine;
#[cfg(feature = "acvm-solver-beta19")]
use bn254_blackbox_solver_beta19::Bn254BlackBoxSolver as Beta19Bn254BlackBoxSolver;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
#[cfg(feature = "acvm-solver-beta19")]
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub type WitnessInputs = BTreeMap<String, FieldElement>;
type MissingTermAssignments = Vec<(String, BigInt)>;
type ScaledMissingTerms = (BigInt, MissingTermAssignments);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Witness {
    pub values: BTreeMap<String, FieldElement>,
}

#[derive(Debug, Default)]
struct WitnessRuntimeState {
    values: BTreeMap<String, FieldElement>,
    numeric_values: BTreeMap<String, BigInt>,
}

#[derive(Debug)]
struct PureWitnessLoopState<'a> {
    pending_assignments: Vec<&'a crate::WitnessAssignment>,
    pending_hints: Vec<&'a crate::WitnessHint>,
}

#[derive(Debug, Default)]
struct PureWitnessProgress {
    assignments: bool,
    hints: bool,
    lookup_outputs: bool,
    radix_decomposition: bool,
    single_missing_equalities: bool,
}

impl PureWitnessProgress {
    fn made_progress(&self) -> bool {
        self.assignments
            || self.hints
            || self.lookup_outputs
            || self.radix_decomposition
            || self.single_missing_equalities
    }
}

#[cfg(test)]
mod witness_validation_tests {
    use super::*;
    use crate::{Signal, Visibility, WitnessPlan, ir::LookupTable};

    #[test]
    fn lookup_constraints_are_checked_in_core_witness_validation() {
        let program = Program {
            name: "lookup_core_check".into(),
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
                inputs: vec![Expr::Signal("selector".into())],
                table: "lut".into(),
                outputs: Some(vec!["mapped".into()]),
                label: Some("selector_to_value".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![LookupTable {
                name: "lut".into(),
                columns: vec!["selector".into(), "mapped".into()],
                values: vec![
                    vec![FieldElement::from_i64(1), FieldElement::from_i64(11)],
                    vec![FieldElement::from_i64(2), FieldElement::from_i64(22)],
                ],
            }],
            metadata: Default::default(),
        };

        let witness = Witness {
            values: BTreeMap::from([
                ("selector".into(), FieldElement::from_i64(2)),
                ("mapped".into(), FieldElement::from_i64(22)),
            ]),
        };
        check_constraints(&program, &witness).expect("matching lookup row should validate");

        let bad_witness = Witness {
            values: BTreeMap::from([
                ("selector".into(), FieldElement::from_i64(2)),
                ("mapped".into(), FieldElement::from_i64(99)),
            ]),
        };
        let err = check_constraints(&program, &bad_witness).expect_err("mismatched outputs fail");
        assert!(matches!(err, ZkfError::LookupConstraintViolation { .. }));
    }

    #[test]
    fn generate_witness_infers_lookup_outputs_from_inputs() {
        let program = Program {
            name: "lookup_inference".into(),
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
                inputs: vec![Expr::Signal("selector".into())],
                table: "lut".into(),
                outputs: Some(vec!["mapped".into()]),
                label: Some("selector_to_value".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![LookupTable {
                name: "lut".into(),
                columns: vec!["selector".into(), "mapped".into()],
                values: vec![
                    vec![FieldElement::from_i64(1), FieldElement::from_i64(11)],
                    vec![FieldElement::from_i64(2), FieldElement::from_i64(22)],
                ],
            }],
            metadata: Default::default(),
        };

        let witness = generate_witness(
            &program,
            &BTreeMap::from([("selector".into(), FieldElement::from_i64(2))]),
        )
        .expect("lookup outputs should be inferred");

        assert_eq!(
            witness.values.get("mapped"),
            Some(&FieldElement::from_i64(22))
        );
    }

    #[test]
    fn generate_witness_infers_radix_decomposition_limbs() {
        let program = Program {
            name: "radix_decomposition".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "value".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "lo".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "hi".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Range {
                    signal: "lo".into(),
                    bits: 4,
                    label: Some("lo_range".into()),
                },
                Constraint::Range {
                    signal: "hi".into(),
                    bits: 4,
                    label: Some("hi_range".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("value".into()),
                    rhs: Expr::Add(vec![
                        Expr::Signal("lo".into()),
                        Expr::Mul(
                            Box::new(Expr::Const(FieldElement::from_i64(16))),
                            Box::new(Expr::Signal("hi".into())),
                        ),
                    ]),
                    label: Some("recompose".into()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let witness = generate_witness(
            &program,
            &BTreeMap::from([("value".into(), FieldElement::from_i64(0xab))]),
        )
        .expect("radix limbs should be inferred");

        assert_eq!(witness.values.get("lo"), Some(&FieldElement::from_i64(0xb)));
        assert_eq!(witness.values.get("hi"), Some(&FieldElement::from_i64(0xa)));
    }

    #[test]
    fn nonlinear_unresolved_witness_reports_structured_solver_error() {
        let program = Program {
            name: "nonlinear".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("y".into()),
                label: Some("square".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let inputs = BTreeMap::from([("y".into(), FieldElement::from_i64(9))]);
        let err = generate_witness_unchecked(&program, &inputs)
            .expect_err("quadratic unresolved witness should fail explicitly");
        assert!(matches!(
            err,
            ZkfError::UnsupportedWitnessSolve {
                unresolved_signals,
                ..
            } if unresolved_signals == vec!["x".to_string()]
        ));
    }

    #[test]
    fn missing_user_input_still_reports_missing_witness_value() {
        let program = Program {
            name: "missing_input".into(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let err = generate_witness_unchecked(&program, &BTreeMap::new())
            .expect_err("unprovided unconstrained input should remain a missing witness");
        assert!(matches!(
            err,
            ZkfError::MissingWitnessValue { signal } if signal == "x"
        ));
    }

    #[test]
    fn pure_core_continues_until_equality_chain_stabilizes() {
        let program = Program {
            name: "equality_chain".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "a".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "c".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("a".into()),
                    rhs: Expr::Signal("b".into()),
                    label: Some("a_eq_b".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("b".into()),
                    rhs: Expr::Signal("c".into()),
                    label: Some("b_eq_c".into()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let witness = generate_witness(
            &program,
            &BTreeMap::from([("c".into(), FieldElement::from_i64(11))]),
        )
        .expect("fixpoint solver should resolve chained equalities");

        assert_eq!(witness.values.get("a"), Some(&FieldElement::from_i64(11)));
        assert_eq!(witness.values.get("b"), Some(&FieldElement::from_i64(11)));
    }
}

pub(crate) fn supports_pure_witness_core(program: &Program) -> bool {
    program.witness_plan.acir_program_bytes.is_none()
        && !program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::BlackBox { .. }))
}

fn requires_external_witness_adapters(program: &Program) -> bool {
    !supports_pure_witness_core(program)
}

fn seed_witness_runtime_state(
    program: &Program,
    inputs: &WitnessInputs,
) -> ZkfResult<WitnessRuntimeState> {
    let mut state = WitnessRuntimeState::default();

    for signal in &program.signals {
        if let Some(constant) = &signal.constant {
            state.values.insert(signal.name.clone(), constant.clone());
            state.numeric_values.insert(
                signal.name.clone(),
                constant.normalized_bigint(program.field)?,
            );
        }
    }

    for (name, value) in inputs {
        if !program.has_signal(name) {
            return Err(ZkfError::UnknownSignal {
                signal: name.clone(),
            });
        }
        state.values.insert(name.clone(), value.clone());
        state
            .numeric_values
            .insert(name.clone(), value.normalized_bigint(program.field)?);
    }

    Ok(state)
}

fn initial_pure_witness_loop_state(program: &Program) -> PureWitnessLoopState<'_> {
    PureWitnessLoopState {
        pending_assignments: program.witness_plan.assignments.iter().collect(),
        pending_hints: program.witness_plan.hints.iter().collect(),
    }
}

fn apply_pure_witness_core_iteration(
    program: &Program,
    state: &mut WitnessRuntimeState,
    loop_state: &mut PureWitnessLoopState<'_>,
) -> ZkfResult<PureWitnessProgress> {
    let mut progress = PureWitnessProgress::default();
    let mut next_assignments = Vec::new();
    let mut next_hints = Vec::new();

    for assignment in loop_state.pending_assignments.drain(..) {
        if !program.has_signal(&assignment.target) {
            return Err(ZkfError::UnknownSignal {
                signal: assignment.target.clone(),
            });
        }

        match eval_expr_bigint(&assignment.expr, &state.numeric_values, program.field) {
            Ok(value) => {
                state.values.insert(
                    assignment.target.clone(),
                    FieldElement::from_bigint_with_field(value.clone(), program.field),
                );
                state
                    .numeric_values
                    .insert(assignment.target.clone(), value);
                progress.assignments = true;
            }
            Err(ZkfError::MissingWitnessValue { .. }) => next_assignments.push(assignment),
            Err(error) => return Err(error),
        }
    }
    loop_state.pending_assignments = next_assignments;

    for hint in loop_state.pending_hints.drain(..) {
        if !program.has_signal(&hint.target) {
            return Err(ZkfError::UnknownSignal {
                signal: hint.target.clone(),
            });
        }
        if state.values.contains_key(&hint.target) {
            continue;
        }
        if let Some(source_value) = state.values.get(&hint.source) {
            if let Some(source_numeric) = state.numeric_values.get(&hint.source) {
                let (derived_value, derived_numeric) = match hint.kind {
                    WitnessHintKind::Copy => (source_value.clone(), source_numeric.clone()),
                    WitnessHintKind::InverseOrZero => {
                        if source_numeric.is_zero() {
                            (FieldElement::ZERO, BigInt::zero())
                        } else {
                            let inverse = field_inv(source_numeric, program.field)
                                .unwrap_or_else(BigInt::zero);
                            (
                                FieldElement::from_bigint_with_field(
                                    inverse.clone(),
                                    program.field,
                                ),
                                inverse,
                            )
                        }
                    }
                };
                state.values.insert(hint.target.clone(), derived_value);
                state
                    .numeric_values
                    .insert(hint.target.clone(), derived_numeric);
                progress.hints = true;
            } else {
                next_hints.push(hint);
            }
        } else {
            next_hints.push(hint);
        }
    }
    loop_state.pending_hints = next_hints;

    if solve_lookup_outputs(program, &mut state.values, &mut state.numeric_values)? {
        progress.lookup_outputs = true;
    }

    if solve_radix_decompositions(program, &mut state.values, &mut state.numeric_values)? {
        progress.radix_decomposition = true;
    }

    for constraint in &program.constraints {
        let Constraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        let Some((signal, value)) =
            solve_single_missing_equality(lhs, rhs, &state.numeric_values, program.field)?
        else {
            continue;
        };

        if state.values.contains_key(&signal) {
            continue;
        }

        state.values.insert(
            signal.clone(),
            FieldElement::from_bigint_with_field(value.clone(), program.field),
        );
        state.numeric_values.insert(signal, value);
        progress.single_missing_equalities = true;
    }

    Ok(progress)
}

fn drive_pure_witness_core_to_fixpoint(
    program: &Program,
    state: &mut WitnessRuntimeState,
    loop_state: &mut PureWitnessLoopState<'_>,
) -> ZkfResult<bool> {
    let mut any_progress = false;

    loop {
        let progress = apply_pure_witness_core_iteration(program, state, loop_state)?;
        if !progress.made_progress() {
            break;
        }
        any_progress = true;
    }

    Ok(any_progress)
}

fn finish_witness_runtime_state(state: WitnessRuntimeState) -> Witness {
    Witness {
        values: state.values,
    }
}

fn generate_partial_witness_pure_core_runtime(
    program: &Program,
    inputs: &WitnessInputs,
) -> ZkfResult<Witness> {
    let mut state = seed_witness_runtime_state(program, inputs)?;
    let mut loop_state = initial_pure_witness_loop_state(program);
    let _ = drive_pure_witness_core_to_fixpoint(program, &mut state, &mut loop_state)?;
    Ok(finish_witness_runtime_state(state))
}

fn run_external_witness_adapters_once(program: &Program, state: &mut WitnessRuntimeState) -> bool {
    let mut progress = false;

    if let Some(acir_b64) = &program.witness_plan.acir_program_bytes {
        progress |= try_acvm_presolver(
            acir_b64,
            program,
            &mut state.values,
            &mut state.numeric_values,
        );
    }

    #[cfg(feature = "acvm-solver")]
    {
        progress |=
            try_native_ec_blackbox_presolver(program, &mut state.values, &mut state.numeric_values);
    }

    progress
}

pub fn generate_witness(program: &Program, inputs: &WitnessInputs) -> ZkfResult<Witness> {
    if supports_pure_witness_core(program) {
        return spec_generate_non_blackbox_witness_checked(program, inputs);
    }
    let witness = generate_witness_unchecked(program, inputs)?;
    check_constraints(program, &witness)?;
    Ok(witness)
}

pub fn generate_witness_unchecked(program: &Program, inputs: &WitnessInputs) -> ZkfResult<Witness> {
    let witness = generate_partial_witness(program, inputs)?;
    if let Err(ZkfError::MissingWitnessValue { .. }) =
        ensure_witness_completeness(program, &witness)
    {
        return Err(diagnose_incomplete_witness(program, &witness));
    }
    Ok(witness)
}

pub fn generate_partial_witness(program: &Program, inputs: &WitnessInputs) -> ZkfResult<Witness> {
    if !requires_external_witness_adapters(program) {
        return generate_partial_witness_pure_core_runtime(program, inputs);
    }

    let mut state = seed_witness_runtime_state(program, inputs)?;
    let mut loop_state = initial_pure_witness_loop_state(program);

    loop {
        let pure_progress =
            drive_pure_witness_core_to_fixpoint(program, &mut state, &mut loop_state)?;
        let external_progress = run_external_witness_adapters_once(program, &mut state);
        if !pure_progress && !external_progress {
            break;
        }
    }

    Ok(finish_witness_runtime_state(state))
}

pub fn ensure_witness_completeness(program: &Program, witness: &Witness) -> ZkfResult<()> {
    for signal in &program.signals {
        if signal.visibility != Visibility::Constant && !witness.values.contains_key(&signal.name) {
            return Err(ZkfError::MissingWitnessValue {
                signal: signal.name.clone(),
            });
        }
    }
    Ok(())
}

const KERNEL_STACK_GROW_RED_ZONE: usize = 32 * 1024;
const KERNEL_STACK_GROW_SIZE: usize = 8 * 1024 * 1024;

pub fn check_constraints(program: &Program, witness: &Witness) -> ZkfResult<()> {
    stacker::maybe_grow(KERNEL_STACK_GROW_RED_ZONE, KERNEL_STACK_GROW_SIZE, || {
        check_constraints_inner(program, witness)
    })
}

fn check_constraints_inner(program: &Program, witness: &Witness) -> ZkfResult<()> {
    let (kernel_program, kernel_witness, kernel_context) =
        translate_program_to_kernel(program, witness)?;
    proof_kernel::check_program(&kernel_program, &kernel_witness)
        .map_err(|error| map_kernel_error(error, &kernel_context, program.field))?;

    let numeric_values = build_bigint_values(&witness.values, program.field)?;
    for (idx, constraint) in program.constraints.iter().enumerate() {
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

        for input in inputs {
            let _ = eval_expr_bigint(input, &numeric_values, program.field)?;
        }
        for output in outputs {
            let normalized =
                numeric_values
                    .get(output)
                    .ok_or_else(|| ZkfError::MissingWitnessValue {
                        signal: output.clone(),
                    })?;
            if matches!(
                op,
                BlackBoxOp::SchnorrVerify | BlackBoxOp::EcdsaSecp256k1 | BlackBoxOp::EcdsaSecp256r1
            ) && !field_is_boolean(normalized, program.field)
            {
                return Err(ZkfError::BooleanConstraintViolation {
                    index: idx,
                    label: label.clone(),
                    signal: output.clone(),
                    value: FieldElement::from_bigint_with_field(normalized.clone(), program.field),
                });
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct KernelAdapterContext {
    signal_names: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SpecKernelAdapterContext {
    constraint_labels: Vec<Option<String>>,
    signal_names: Vec<String>,
    table_names: Vec<String>,
}

fn collect_constraint_signal_names(constraint: &Constraint, names: &mut BTreeSet<String>) {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            collect_signal_names(lhs, names);
            collect_signal_names(rhs, names);
        }
        Constraint::Boolean { signal, .. } | Constraint::Range { signal, .. } => {
            names.insert(signal.clone());
        }
        Constraint::Lookup {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_signal_names(input, names);
            }
            if let Some(outputs) = outputs {
                names.extend(outputs.iter().cloned());
            }
        }
        Constraint::BlackBox {
            inputs, outputs, ..
        } => {
            for input in inputs {
                collect_signal_names(input, names);
            }
            names.extend(outputs.iter().cloned());
        }
    }
}

fn collect_kernel_signal_universe(program: &Program, witness: &Witness) -> Vec<String> {
    let mut names = BTreeSet::new();
    names.extend(program.signals.iter().map(|signal| signal.name.clone()));
    names.extend(witness.values.keys().cloned());
    for constraint in &program.constraints {
        collect_constraint_signal_names(constraint, &mut names);
    }
    names.into_iter().collect()
}

fn translate_signal_to_kernel(
    signal: &str,
    signal_indices: &BTreeMap<String, usize>,
) -> ZkfResult<usize> {
    signal_indices
        .get(signal)
        .copied()
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: signal.to_string(),
        })
}

fn translate_expr_to_kernel(
    expr: &Expr,
    signal_indices: &BTreeMap<String, usize>,
    field: FieldId,
) -> ZkfResult<KernelExpr> {
    Ok(match expr {
        Expr::Const(value) => KernelExpr::Const(value.normalized_bigint(field)?),
        Expr::Signal(signal) => {
            KernelExpr::Signal(translate_signal_to_kernel(signal, signal_indices)?)
        }
        Expr::Add(items) => KernelExpr::Add(
            items
                .iter()
                .map(|item| translate_expr_to_kernel(item, signal_indices, field))
                .collect::<ZkfResult<Vec<_>>>()?,
        ),
        Expr::Sub(lhs, rhs) => KernelExpr::Sub(
            Box::new(translate_expr_to_kernel(lhs, signal_indices, field)?),
            Box::new(translate_expr_to_kernel(rhs, signal_indices, field)?),
        ),
        Expr::Mul(lhs, rhs) => KernelExpr::Mul(
            Box::new(translate_expr_to_kernel(lhs, signal_indices, field)?),
            Box::new(translate_expr_to_kernel(rhs, signal_indices, field)?),
        ),
        Expr::Div(lhs, rhs) => KernelExpr::Div(
            Box::new(translate_expr_to_kernel(lhs, signal_indices, field)?),
            Box::new(translate_expr_to_kernel(rhs, signal_indices, field)?),
        ),
    })
}

#[allow(dead_code)]
fn build_spec_add_chain(mut items: Vec<SpecKernelExpr>) -> SpecKernelExpr {
    match items.len() {
        0 => SpecKernelExpr::Const(SpecFieldValue::from_runtime(&FieldElement::ZERO)),
        1 => items.pop().expect("single item add chain"),
        _ => {
            let first = items.remove(0);
            items.into_iter().fold(first, |acc, item| {
                SpecKernelExpr::Add(Box::new(acc), Box::new(item))
            })
        }
    }
}

#[allow(dead_code)]
fn translate_expr_to_spec_kernel(
    expr: &Expr,
    signal_indices: &BTreeMap<String, usize>,
) -> ZkfResult<SpecKernelExpr> {
    Ok(match expr {
        Expr::Const(value) => SpecKernelExpr::Const(SpecFieldValue::from_runtime(value)),
        Expr::Signal(signal) => {
            SpecKernelExpr::Signal(translate_signal_to_kernel(signal, signal_indices)?)
        }
        Expr::Add(items) => build_spec_add_chain(
            items
                .iter()
                .map(|item| translate_expr_to_spec_kernel(item, signal_indices))
                .collect::<ZkfResult<Vec<_>>>()?,
        ),
        Expr::Sub(lhs, rhs) => SpecKernelExpr::Sub(
            Box::new(translate_expr_to_spec_kernel(lhs, signal_indices)?),
            Box::new(translate_expr_to_spec_kernel(rhs, signal_indices)?),
        ),
        Expr::Mul(lhs, rhs) => SpecKernelExpr::Mul(
            Box::new(translate_expr_to_spec_kernel(lhs, signal_indices)?),
            Box::new(translate_expr_to_spec_kernel(rhs, signal_indices)?),
        ),
        Expr::Div(lhs, rhs) => SpecKernelExpr::Div(
            Box::new(translate_expr_to_spec_kernel(lhs, signal_indices)?),
            Box::new(translate_expr_to_spec_kernel(rhs, signal_indices)?),
        ),
    })
}

fn translate_constraint_to_kernel(
    index: usize,
    constraint: &Constraint,
    signal_indices: &BTreeMap<String, usize>,
    field: FieldId,
) -> ZkfResult<Option<KernelConstraint>> {
    Ok(match constraint {
        Constraint::Equal { lhs, rhs, label } => Some(KernelConstraint::Equal {
            index,
            lhs: translate_expr_to_kernel(lhs, signal_indices, field)?,
            rhs: translate_expr_to_kernel(rhs, signal_indices, field)?,
            label: label.clone(),
        }),
        Constraint::Boolean { signal, label } => Some(KernelConstraint::Boolean {
            index,
            signal: translate_signal_to_kernel(signal, signal_indices)?,
            label: label.clone(),
        }),
        Constraint::Range {
            signal,
            bits,
            label,
        } => Some(KernelConstraint::Range {
            index,
            signal: translate_signal_to_kernel(signal, signal_indices)?,
            bits: *bits,
            label: label.clone(),
        }),
        Constraint::Lookup {
            inputs,
            table,
            outputs,
            label,
        } => Some(KernelConstraint::Lookup {
            index,
            inputs: inputs
                .iter()
                .map(|expr| translate_expr_to_kernel(expr, signal_indices, field))
                .collect::<ZkfResult<Vec<_>>>()?,
            table: table.clone(),
            outputs: outputs
                .as_ref()
                .map(|outputs| {
                    outputs
                        .iter()
                        .map(|signal| translate_signal_to_kernel(signal, signal_indices))
                        .collect::<ZkfResult<Vec<_>>>()
                })
                .transpose()?,
            label: label.clone(),
        }),
        Constraint::BlackBox { .. } => None,
    })
}

#[allow(dead_code)]
fn translate_constraint_to_spec_kernel(
    index: usize,
    constraint: &Constraint,
    signal_indices: &BTreeMap<String, usize>,
    table_indices: &BTreeMap<String, usize>,
) -> ZkfResult<Option<SpecKernelConstraint>> {
    Ok(match constraint {
        Constraint::Equal { lhs, rhs, .. } => Some(SpecKernelConstraint::Equal {
            index,
            lhs: translate_expr_to_spec_kernel(lhs, signal_indices)?,
            rhs: translate_expr_to_spec_kernel(rhs, signal_indices)?,
        }),
        Constraint::Boolean { signal, .. } => Some(SpecKernelConstraint::Boolean {
            index,
            signal: translate_signal_to_kernel(signal, signal_indices)?,
        }),
        Constraint::Range { signal, bits, .. } => Some(SpecKernelConstraint::Range {
            index,
            signal: translate_signal_to_kernel(signal, signal_indices)?,
            bits: *bits,
        }),
        Constraint::Lookup {
            inputs,
            table,
            outputs,
            ..
        } => Some(SpecKernelConstraint::Lookup {
            index,
            inputs: inputs
                .iter()
                .map(|expr| translate_expr_to_spec_kernel(expr, signal_indices))
                .collect::<ZkfResult<Vec<_>>>()?,
            table_index: table_indices.get(table).copied().ok_or_else(|| {
                ZkfError::UnknownLookupTable {
                    table: table.clone(),
                }
            })?,
            outputs: outputs
                .as_ref()
                .map(|signals| {
                    signals
                        .iter()
                        .map(|signal| translate_signal_to_kernel(signal, signal_indices))
                        .collect::<ZkfResult<Vec<_>>>()
                })
                .transpose()?,
        }),
        Constraint::BlackBox { .. } => None,
    })
}

fn translate_program_to_kernel(
    program: &Program,
    witness: &Witness,
) -> ZkfResult<(KernelProgram, KernelWitness, KernelAdapterContext)> {
    let signal_names = collect_kernel_signal_universe(program, witness);
    let signal_indices = signal_names
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let constraints = program
        .constraints
        .iter()
        .enumerate()
        .filter_map(|(index, constraint)| {
            match translate_constraint_to_kernel(index, constraint, &signal_indices, program.field)
            {
                Ok(Some(kernel_constraint)) => Some(Ok(kernel_constraint)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let lookup_tables = program
        .lookup_tables
        .iter()
        .map(|table| {
            let rows = table
                .values
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|value| value.normalized_bigint(program.field))
                        .collect::<ZkfResult<Vec<_>>>()
                })
                .collect::<ZkfResult<Vec<_>>>()?;
            Ok((
                table.name.clone(),
                KernelLookupTable {
                    column_count: table.columns.len(),
                    rows,
                },
            ))
        })
        .collect::<ZkfResult<BTreeMap<_, _>>>()?;
    let values = signal_names
        .iter()
        .map(|signal| {
            witness
                .values
                .get(signal)
                .map(|value| value.normalized_bigint(program.field))
                .transpose()
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok((
        KernelProgram {
            field: program.field,
            constraints,
            lookup_tables,
        },
        KernelWitness { values },
        KernelAdapterContext { signal_names },
    ))
}

#[allow(dead_code)]
fn translate_program_to_spec_kernel(
    program: &Program,
    witness: &Witness,
) -> ZkfResult<(
    SpecKernelProgram,
    SpecKernelWitness,
    SpecKernelAdapterContext,
)> {
    let signal_names = collect_kernel_signal_universe(program, witness);
    let signal_indices = signal_names
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let table_names = program
        .lookup_tables
        .iter()
        .map(|table| table.name.clone())
        .collect::<Vec<_>>();
    let table_indices = table_names
        .iter()
        .enumerate()
        .map(|(index, table)| (table.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let constraints = program
        .constraints
        .iter()
        .enumerate()
        .filter_map(|(index, constraint)| {
            match translate_constraint_to_spec_kernel(
                index,
                constraint,
                &signal_indices,
                &table_indices,
            ) {
                Ok(Some(kernel_constraint)) => Some(Ok(kernel_constraint)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let lookup_tables = program
        .lookup_tables
        .iter()
        .map(|table| SpecKernelLookupTable {
            column_count: table.columns.len(),
            rows: table
                .values
                .iter()
                .map(|row| {
                    row.iter()
                        .map(SpecFieldValue::from_runtime)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>();
    let values = signal_names
        .iter()
        .map(|signal| witness.values.get(signal).map(SpecFieldValue::from_runtime))
        .collect::<Vec<_>>();
    let constraint_labels = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            Constraint::Equal { label, .. }
            | Constraint::Boolean { label, .. }
            | Constraint::Range { label, .. }
            | Constraint::Lookup { label, .. }
            | Constraint::BlackBox { label, .. } => label.clone(),
        })
        .collect::<Vec<_>>();

    Ok((
        SpecKernelProgram {
            field: program.field,
            constraints,
            lookup_tables,
        },
        SpecKernelWitness { values },
        SpecKernelAdapterContext {
            constraint_labels,
            signal_names,
            table_names,
        },
    ))
}

#[allow(dead_code)]
fn translate_program_to_spec_witness_generation(
    program: &Program,
) -> ZkfResult<(SpecWitnessGenerationProgram, SpecKernelAdapterContext)> {
    if !supports_pure_witness_core(program) {
        return Err(ZkfError::UnsupportedWitnessSolve {
            unresolved_signals: Vec::new(),
            reason: "program is outside the non-blackbox witness spec subset".to_string(),
        });
    }

    let signal_names = program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();
    let signal_indices = signal_names
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let table_names = program
        .lookup_tables
        .iter()
        .map(|table| table.name.clone())
        .collect::<Vec<_>>();
    let table_indices = table_names
        .iter()
        .enumerate()
        .map(|(index, table)| (table.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let constraints = program
        .constraints
        .iter()
        .enumerate()
        .filter_map(|(index, constraint)| {
            match translate_constraint_to_spec_kernel(
                index,
                constraint,
                &signal_indices,
                &table_indices,
            ) {
                Ok(Some(kernel_constraint)) => Some(Ok(kernel_constraint)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let lookup_tables = program
        .lookup_tables
        .iter()
        .map(|table| SpecKernelLookupTable {
            column_count: table.columns.len(),
            rows: table
                .values
                .iter()
                .map(|row| {
                    row.iter()
                        .map(SpecFieldValue::from_runtime)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>();
    let constraint_labels = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            Constraint::Equal { label, .. }
            | Constraint::Boolean { label, .. }
            | Constraint::Range { label, .. }
            | Constraint::Lookup { label, .. }
            | Constraint::BlackBox { label, .. } => label.clone(),
        })
        .collect::<Vec<_>>();
    let signals = program
        .signals
        .iter()
        .map(|signal| SpecWitnessSignal {
            constant_value: signal.constant.as_ref().map(SpecFieldValue::from_runtime),
            required: signal.visibility != Visibility::Constant,
        })
        .collect::<Vec<_>>();
    let assignments = program
        .witness_plan
        .assignments
        .iter()
        .map(|assignment| {
            Ok(SpecWitnessAssignment {
                target_signal_index: translate_signal_to_kernel(
                    &assignment.target,
                    &signal_indices,
                )?,
                expr: translate_expr_to_spec_kernel(&assignment.expr, &signal_indices)?,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let hints = program
        .witness_plan
        .hints
        .iter()
        .map(|hint| {
            Ok(SpecWitnessHint {
                target_signal_index: translate_signal_to_kernel(&hint.target, &signal_indices)?,
                source_signal_index: translate_signal_to_kernel(&hint.source, &signal_indices)?,
                kind: hint.kind,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok((
        SpecWitnessGenerationProgram {
            kernel_program: SpecKernelProgram {
                field: program.field,
                constraints,
                lookup_tables,
            },
            signals,
            assignments,
            hints,
        },
        SpecKernelAdapterContext {
            constraint_labels,
            signal_names,
            table_names,
        },
    ))
}

#[allow(dead_code)]
fn translate_inputs_to_spec_witness_generation(
    signal_names: &[String],
    inputs: &WitnessInputs,
) -> ZkfResult<Vec<Option<SpecFieldValue>>> {
    let signal_indices = signal_names
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut translated = vec![None; signal_names.len()];
    for (signal, value) in inputs {
        let signal_index =
            signal_indices
                .get(signal)
                .copied()
                .ok_or_else(|| ZkfError::UnknownSignal {
                    signal: signal.clone(),
                })?;
        translated[signal_index] = Some(SpecFieldValue::from_runtime(value));
    }
    Ok(translated)
}

fn kernel_signal_name(context: &KernelAdapterContext, signal_index: usize) -> String {
    context
        .signal_names
        .get(signal_index)
        .cloned()
        .unwrap_or_else(|| format!("signal_{signal_index}"))
}

#[allow(dead_code)]
fn spec_constraint_label(
    context: &SpecKernelAdapterContext,
    constraint_index: usize,
) -> Option<String> {
    context
        .constraint_labels
        .get(constraint_index)
        .cloned()
        .unwrap_or(None)
}

#[allow(dead_code)]
fn spec_kernel_signal_name(context: &SpecKernelAdapterContext, signal_index: usize) -> String {
    context
        .signal_names
        .get(signal_index)
        .cloned()
        .unwrap_or_else(|| format!("signal_{signal_index}"))
}

#[allow(dead_code)]
fn spec_kernel_table_name(context: &SpecKernelAdapterContext, table_index: usize) -> String {
    context
        .table_names
        .get(table_index)
        .cloned()
        .unwrap_or_else(|| format!("table_{table_index}"))
}

#[allow(dead_code)]
fn render_lookup_value_list(values: &[SpecFieldValue]) -> String {
    values
        .iter()
        .map(|value| value.to_runtime().to_decimal_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[allow(dead_code)]
fn render_spec_lookup_message(
    table_name: &str,
    inputs: &[SpecFieldValue],
    outputs: &Option<Vec<SpecFieldValue>>,
    kind: &SpecLookupFailureKind,
) -> String {
    match kind {
        SpecLookupFailureKind::InputArityMismatch {
            provided,
            available,
        } => format!(
            "constraint provides {} input columns but table '{}' has only {} columns",
            provided, table_name, available
        ),
        SpecLookupFailureKind::NoMatchingRow => {
            let rendered_inputs = render_lookup_value_list(inputs);
            let rendered_outputs = outputs
                .as_ref()
                .map(|values| render_lookup_value_list(values))
                .unwrap_or_default();
            let output_clause = if rendered_outputs.is_empty() {
                String::new()
            } else {
                format!(" with outputs [{rendered_outputs}]")
            };
            format!("no row matched inputs [{rendered_inputs}]{}", output_clause)
        }
    }
}

#[allow(dead_code)]
fn map_spec_witness_generation_error(
    error: SpecWitnessGenerationError,
    context: &SpecKernelAdapterContext,
) -> ZkfError {
    match error {
        SpecWitnessGenerationError::MissingRequiredSignal { signal_index } => {
            ZkfError::MissingWitnessValue {
                signal: spec_kernel_signal_name(context, signal_index),
            }
        }
        SpecWitnessGenerationError::UnsupportedWitnessSolve {
            unresolved_signal_indices,
        } => ZkfError::UnsupportedWitnessSolve {
            unresolved_signals: unresolved_signal_indices
                .into_iter()
                .map(|signal_index| spec_kernel_signal_name(context, signal_index))
                .collect::<Vec<_>>(),
            reason: "non-blackbox witness spec could not resolve all required signals".to_string(),
        },
        SpecWitnessGenerationError::KernelCheck(error) => map_spec_kernel_error(error, context),
        SpecWitnessGenerationError::AmbiguousLookup {
            constraint_index,
            table_index,
        } => {
            let table = spec_kernel_table_name(context, table_index);
            ZkfError::LookupConstraintViolation {
                index: constraint_index,
                label: spec_constraint_label(context, constraint_index),
                table: table.clone(),
                message: format!(
                    "lookup table '{}' is ambiguous for the provided inputs",
                    table
                ),
            }
        }
    }
}

#[allow(dead_code)]
fn witness_from_spec_witness(
    spec_witness: SpecKernelWitness,
    context: &SpecKernelAdapterContext,
) -> Witness {
    let values = context
        .signal_names
        .iter()
        .enumerate()
        .filter_map(|(signal_index, signal_name)| {
            spec_witness
                .values
                .get(signal_index)
                .and_then(|value| value.as_ref())
                .map(|value| (signal_name.clone(), value.to_runtime()))
        })
        .collect::<BTreeMap<_, _>>();
    Witness { values }
}

#[allow(dead_code)]
pub(crate) fn spec_generate_non_blackbox_witness_checked(
    program: &Program,
    inputs: &WitnessInputs,
) -> ZkfResult<Witness> {
    let (spec_program, context) = translate_program_to_spec_witness_generation(program)?;
    let spec_inputs = translate_inputs_to_spec_witness_generation(&context.signal_names, inputs)?;
    let spec_witness = crate::proof_witness_generation_spec::generate_non_blackbox_witness(
        &spec_program,
        &spec_inputs,
    )
    .map_err(|error| map_spec_witness_generation_error(error, &context))?;
    Ok(witness_from_spec_witness(spec_witness, &context))
}

#[allow(dead_code)]
pub(crate) fn spec_check_constraints_checked(
    program: &Program,
    witness: &Witness,
) -> ZkfResult<()> {
    let (kernel_program, kernel_witness, context) =
        translate_program_to_spec_kernel(program, witness)?;
    proof_kernel_spec::check_program(&kernel_program, &kernel_witness)
        .map_err(|error| map_spec_kernel_error(error, &context))
}

fn map_kernel_error(
    error: KernelCheckError,
    context: &KernelAdapterContext,
    field: FieldId,
) -> ZkfError {
    match error {
        KernelCheckError::MissingSignal { signal_index } => ZkfError::MissingWitnessValue {
            signal: kernel_signal_name(context, signal_index),
        },
        KernelCheckError::DivisionByZero => ZkfError::DivisionByZero,
        KernelCheckError::UnknownLookupTable { table } => ZkfError::UnknownLookupTable { table },
        KernelCheckError::EqualViolation {
            constraint_index,
            label,
            lhs,
            rhs,
        } => ZkfError::ConstraintViolation {
            index: constraint_index,
            label,
            lhs: FieldElement::from_bigint_with_field(lhs, field),
            rhs: FieldElement::from_bigint_with_field(rhs, field),
        },
        KernelCheckError::BooleanViolation {
            constraint_index,
            label,
            signal_index,
            value,
        } => ZkfError::BooleanConstraintViolation {
            index: constraint_index,
            label,
            signal: kernel_signal_name(context, signal_index),
            value: FieldElement::from_bigint_with_field(value, field),
        },
        KernelCheckError::RangeViolation {
            constraint_index,
            label,
            signal_index,
            bits,
            value,
        } => ZkfError::RangeConstraintViolation {
            index: constraint_index,
            label,
            signal: kernel_signal_name(context, signal_index),
            bits,
            value: FieldElement::from_bigint_with_field(value, field),
        },
        KernelCheckError::LookupViolation {
            constraint_index,
            label,
            table,
            message,
        } => ZkfError::LookupConstraintViolation {
            index: constraint_index,
            label,
            table,
            message,
        },
    }
}

#[allow(dead_code)]
fn map_spec_kernel_error(
    error: SpecKernelCheckError,
    context: &SpecKernelAdapterContext,
) -> ZkfError {
    match error {
        SpecKernelCheckError::MissingSignal { signal_index } => ZkfError::MissingWitnessValue {
            signal: spec_kernel_signal_name(context, signal_index),
        },
        SpecKernelCheckError::DivisionByZero => ZkfError::DivisionByZero,
        SpecKernelCheckError::UnknownLookupTable { table_index } => ZkfError::UnknownLookupTable {
            table: spec_kernel_table_name(context, table_index),
        },
        SpecKernelCheckError::EqualViolation {
            constraint_index,
            lhs,
            rhs,
        } => ZkfError::ConstraintViolation {
            index: constraint_index,
            label: spec_constraint_label(context, constraint_index),
            lhs: lhs.to_runtime(),
            rhs: rhs.to_runtime(),
        },
        SpecKernelCheckError::BooleanViolation {
            constraint_index,
            signal_index,
            value,
        } => ZkfError::BooleanConstraintViolation {
            index: constraint_index,
            label: spec_constraint_label(context, constraint_index),
            signal: spec_kernel_signal_name(context, signal_index),
            value: value.to_runtime(),
        },
        SpecKernelCheckError::RangeViolation {
            constraint_index,
            signal_index,
            bits,
            value,
        } => ZkfError::RangeConstraintViolation {
            index: constraint_index,
            label: spec_constraint_label(context, constraint_index),
            signal: spec_kernel_signal_name(context, signal_index),
            bits,
            value: value.to_runtime(),
        },
        SpecKernelCheckError::LookupViolation {
            constraint_index,
            table_index,
            inputs,
            outputs,
            kind,
        } => {
            let table = spec_kernel_table_name(context, table_index);
            ZkfError::LookupConstraintViolation {
                index: constraint_index,
                label: spec_constraint_label(context, constraint_index),
                table: table.clone(),
                message: render_spec_lookup_message(&table, &inputs, &outputs, &kind),
            }
        }
    }
}

fn diagnose_incomplete_witness(program: &Program, witness: &Witness) -> ZkfError {
    match first_partial_constraint_failure(program, witness) {
        Ok(Some(error)) | Err(error) => return error,
        Ok(None) => {}
    }

    let unresolved_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility != Visibility::Constant)
        .filter(|signal| !witness.values.contains_key(&signal.name))
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();

    if unresolved_signals.is_empty() {
        return ZkfError::MissingWitnessValue {
            signal: "<unknown>".to_string(),
        };
    }

    let unresolved = unresolved_signals
        .iter()
        .cloned()
        .collect::<BTreeSet<String>>();

    let blocked_assignments = program
        .witness_plan
        .assignments
        .iter()
        .filter(|assignment| unresolved.contains(&assignment.target))
        .map(|assignment| assignment.target.clone())
        .collect::<Vec<_>>();
    let blocked_hints = program
        .witness_plan
        .hints
        .iter()
        .filter(|hint| unresolved.contains(&hint.target))
        .map(|hint| hint.target.clone())
        .collect::<Vec<_>>();
    let blocked_constraints = program
        .constraints
        .iter()
        .enumerate()
        .filter_map(|(idx, constraint)| {
            let mut referenced = BTreeSet::new();
            collect_constraint_signal_names(constraint, &mut referenced);
            referenced
                .iter()
                .any(|name| unresolved.contains(name))
                .then_some(
                    constraint
                        .label()
                        .cloned()
                        .unwrap_or_else(|| format!("constraint_{idx}")),
                )
        })
        .collect::<Vec<_>>();

    if blocked_assignments.is_empty() && blocked_hints.is_empty() && blocked_constraints.is_empty()
    {
        return ZkfError::MissingWitnessValue {
            signal: unresolved_signals[0].clone(),
        };
    }

    let mut reasons = Vec::new();
    if !blocked_assignments.is_empty() {
        reasons.push(format!(
            "unresolved assignments: {}",
            blocked_assignments.join(", ")
        ));
    }
    if !blocked_hints.is_empty() {
        reasons.push(format!("blocked hints: {}", blocked_hints.join(", ")));
    }
    if !blocked_constraints.is_empty() {
        reasons.push(format!(
            "blocked constraints: {}",
            blocked_constraints.join(", ")
        ));
    }
    reasons.push(
        "next step: run `ziros debug --program <program.json> --inputs <inputs.json> --out debug.json` to inspect unresolved dependencies".to_string(),
    );

    ZkfError::UnsupportedWitnessSolve {
        unresolved_signals,
        reason: reasons.join("; "),
    }
}

fn first_partial_constraint_failure(
    program: &Program,
    witness: &Witness,
) -> ZkfResult<Option<ZkfError>> {
    let numeric_values = build_bigint_values(&witness.values, program.field)?;

    for (index, constraint) in program.constraints.iter().enumerate() {
        let failure = match constraint {
            Constraint::Equal { lhs, rhs, label } => {
                let lhs = match eval_expr_bigint(lhs, &numeric_values, program.field) {
                    Ok(value) => value,
                    Err(ZkfError::MissingWitnessValue { .. }) => continue,
                    Err(error) => return Err(error),
                };
                let rhs = match eval_expr_bigint(rhs, &numeric_values, program.field) {
                    Ok(value) => value,
                    Err(ZkfError::MissingWitnessValue { .. }) => continue,
                    Err(error) => return Err(error),
                };

                (lhs != rhs).then_some(ZkfError::ConstraintViolation {
                    index,
                    label: label.clone(),
                    lhs: FieldElement::from_bigint_with_field(lhs, program.field),
                    rhs: FieldElement::from_bigint_with_field(rhs, program.field),
                })
            }
            Constraint::Boolean { signal, label } => witness.values.get(signal).and_then(|value| {
                (!field_is_boolean(&value.as_bigint(), program.field)).then_some(
                    ZkfError::BooleanConstraintViolation {
                        index,
                        label: label.clone(),
                        signal: signal.clone(),
                        value: value.clone(),
                    },
                )
            }),
            Constraint::Range {
                signal,
                bits,
                label,
            } => {
                let Some(value) = witness.values.get(signal) else {
                    continue;
                };
                let normalized = value.normalized_bigint(program.field)?;
                let limit = BigInt::from(1u8) << *bits;
                (normalized >= limit).then_some(ZkfError::RangeConstraintViolation {
                    index,
                    label: label.clone(),
                    signal: signal.clone(),
                    bits: *bits,
                    value: value.clone(),
                })
            }
            Constraint::Lookup {
                inputs,
                table,
                outputs,
                label,
            } => first_lookup_constraint_failure(
                program,
                &numeric_values,
                index,
                inputs,
                table,
                outputs,
                label,
            )?,
            Constraint::BlackBox { .. } => None,
        };

        if let Some(failure) = failure {
            return Ok(Some(failure));
        }
    }

    Ok(None)
}

fn first_lookup_constraint_failure(
    program: &Program,
    numeric_values: &BTreeMap<String, BigInt>,
    index: usize,
    inputs: &[Expr],
    table: &str,
    outputs: &Option<Vec<String>>,
    label: &Option<String>,
) -> ZkfResult<Option<ZkfError>> {
    let evaluated_inputs = match inputs
        .iter()
        .map(|expr| eval_expr_bigint(expr, numeric_values, program.field))
        .collect::<ZkfResult<Vec<_>>>()
    {
        Ok(values) => values,
        Err(ZkfError::MissingWitnessValue { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };

    let lookup_table = program
        .lookup_tables
        .iter()
        .find(|item| item.name == table)
        .ok_or_else(|| ZkfError::UnknownLookupTable {
            table: table.to_string(),
        })?;

    if lookup_table.columns.len() < evaluated_inputs.len() {
        return Ok(Some(ZkfError::LookupConstraintViolation {
            index,
            label: label.clone(),
            table: table.to_string(),
            message: format!(
                "constraint provides {} input columns but table '{}' has only {} columns",
                evaluated_inputs.len(),
                table,
                lookup_table.columns.len()
            ),
        }));
    }

    let matched_rows = lookup_table
        .values
        .iter()
        .filter(|row| {
            evaluated_inputs
                .iter()
                .enumerate()
                .all(|(col_idx, input_value)| {
                    row.get(col_idx)
                        .and_then(|value| value.normalized_bigint(program.field).ok())
                        .is_some_and(|row_value| row_value == *input_value)
                })
        })
        .collect::<Vec<_>>();

    if matched_rows.is_empty() {
        return Ok(Some(ZkfError::LookupConstraintViolation {
            index,
            label: label.clone(),
            table: table.to_string(),
            message: format!(
                "no row matched inputs [{}]",
                render_runtime_lookup_value_list(&evaluated_inputs, program.field)
            ),
        }));
    }

    let Some(output_names) = outputs.as_ref() else {
        return Ok(None);
    };

    let expected_outputs = output_names
        .iter()
        .map(|name| {
            numeric_values
                .get(name)
                .cloned()
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: name.clone(),
                })
        })
        .collect::<ZkfResult<Vec<_>>>();
    let expected_outputs = match expected_outputs {
        Ok(values) => values,
        Err(ZkfError::MissingWitnessValue { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };

    let matching_output_row = matched_rows.iter().any(|row| {
        expected_outputs
            .iter()
            .enumerate()
            .all(|(output_idx, expected_value)| {
                row.get(evaluated_inputs.len() + output_idx)
                    .and_then(|value| value.normalized_bigint(program.field).ok())
                    .is_some_and(|row_value| row_value == *expected_value)
            })
    });
    if matching_output_row {
        return Ok(None);
    }

    Ok(Some(ZkfError::LookupConstraintViolation {
        index,
        label: label.clone(),
        table: table.to_string(),
        message: format!(
            "no row matched inputs [{}] with outputs [{}]",
            render_runtime_lookup_value_list(&evaluated_inputs, program.field),
            render_runtime_lookup_value_list(&expected_outputs, program.field)
        ),
    }))
}

fn render_runtime_lookup_value_list(values: &[BigInt], field: FieldId) -> String {
    values
        .iter()
        .map(|value| FieldElement::from_bigint_with_field(value.clone(), field).to_decimal_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn eval_expr(
    expr: &Expr,
    values: &BTreeMap<String, FieldElement>,
    field: FieldId,
) -> ZkfResult<BigInt> {
    stacker::maybe_grow(KERNEL_STACK_GROW_RED_ZONE, KERNEL_STACK_GROW_SIZE, || {
        let numeric_values = build_bigint_values(values, field)?;
        eval_expr_bigint_kernel(expr, &numeric_values, field)
    })
}

fn eval_expr_bigint_kernel(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<BigInt> {
    let mut signal_names = BTreeSet::new();
    collect_signal_names(expr, &mut signal_names);
    signal_names.extend(values.keys().cloned());

    let ordered_names = signal_names.into_iter().collect::<Vec<_>>();
    let signal_indices = ordered_names
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let kernel_expr = translate_expr_to_kernel(expr, &signal_indices, field)?;
    let kernel_values = ordered_names
        .iter()
        .map(|signal| values.get(signal).cloned())
        .collect::<Vec<_>>();
    let kernel_witness = KernelWitness {
        values: kernel_values,
    };
    let context = KernelAdapterContext {
        signal_names: ordered_names,
    };
    proof_kernel::eval_expr(&kernel_expr, &kernel_witness, field)
        .map_err(|error| map_kernel_error(error, &context, field))
}

fn eval_expr_bigint(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<BigInt> {
    match expr {
        Expr::Const(value) => value.normalized_bigint(field),
        Expr::Signal(name) => {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: name.clone(),
                })
        }
        Expr::Add(items) => {
            let mut acc = BigInt::zero();
            for item in items {
                acc = field_add(&acc, &eval_expr_bigint(item, values, field)?, field);
            }
            Ok(acc)
        }
        Expr::Sub(lhs, rhs) => Ok(field_sub(
            &eval_expr_bigint(lhs, values, field)?,
            &eval_expr_bigint(rhs, values, field)?,
            field,
        )),
        Expr::Mul(lhs, rhs) => Ok(field_mul(
            &eval_expr_bigint(lhs, values, field)?,
            &eval_expr_bigint(rhs, values, field)?,
            field,
        )),
        Expr::Div(lhs, rhs) => field_div(
            &eval_expr_bigint(lhs, values, field)?,
            &eval_expr_bigint(rhs, values, field)?,
            field,
        )
        .ok_or(ZkfError::DivisionByZero),
    }
}

#[cfg(feature = "full")]
pub(crate) fn mod_inverse(value: BigInt, modulus: &BigInt) -> Option<BigInt> {
    [
        FieldId::Bn254,
        FieldId::Bls12_381,
        FieldId::PastaFp,
        FieldId::PastaFq,
        FieldId::Goldilocks,
        FieldId::BabyBear,
        FieldId::Mersenne31,
    ]
    .into_iter()
    .find(|field| field.modulus() == modulus)
    .and_then(|field| field_inv(&value, field))
}

pub fn collect_public_inputs(program: &Program, witness: &Witness) -> ZkfResult<Vec<FieldElement>> {
    let mut out = Vec::new();

    for signal in &program.signals {
        if signal.visibility == Visibility::Public {
            let value =
                witness
                    .values
                    .get(&signal.name)
                    .ok_or_else(|| ZkfError::MissingWitnessValue {
                        signal: signal.name.clone(),
                    })?;
            out.push(value.clone());
        }
    }

    Ok(out)
}

fn build_bigint_values(
    values: &BTreeMap<String, FieldElement>,
    field: FieldId,
) -> ZkfResult<BTreeMap<String, BigInt>> {
    let mut numeric = BTreeMap::new();
    for (name, value) in values {
        numeric.insert(name.clone(), field_normalize(value.as_bigint(), field));
    }
    Ok(numeric)
}

fn solve_single_missing_equality(
    lhs: &Expr,
    rhs: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<Option<(String, BigInt)>> {
    let mut missing = BTreeSet::new();
    collect_missing_signals(lhs, values, &mut missing);
    collect_missing_signals(rhs, values, &mut missing);
    if missing.len() != 1 {
        return Ok(None);
    }

    let signal = missing.into_iter().next().expect("len checked");
    let Some((lhs_coeff, lhs_const)) = extract_affine_form(lhs, &signal, values, field)? else {
        return Ok(None);
    };
    let Some((rhs_coeff, rhs_const)) = extract_affine_form(rhs, &signal, values, field)? else {
        return Ok(None);
    };

    let coeff = field_sub(&lhs_coeff, &rhs_coeff, field);
    if coeff.is_zero() {
        return Ok(None);
    }
    let constant = field_sub(&lhs_const, &rhs_const, field);
    let Some(inv_coeff) = field_inv(&coeff, field) else {
        return Ok(None);
    };
    let solved = field_mul(&field_normalize(-constant, field), &inv_coeff, field);
    Ok(Some((signal, solved)))
}

fn solve_lookup_outputs(
    program: &Program,
    values: &mut BTreeMap<String, FieldElement>,
    numeric_values: &mut BTreeMap<String, BigInt>,
) -> ZkfResult<bool> {
    let mut progress = false;

    for constraint in &program.constraints {
        let Constraint::Lookup {
            inputs,
            table,
            outputs,
            ..
        } = constraint
        else {
            continue;
        };

        let Some(output_names) = outputs.as_ref() else {
            continue;
        };

        if output_names.iter().all(|name| values.contains_key(name)) {
            continue;
        }

        let evaluated_inputs = match inputs
            .iter()
            .map(|expr| eval_expr_bigint(expr, numeric_values, program.field))
            .collect::<ZkfResult<Vec<_>>>()
        {
            Ok(values) => values,
            Err(ZkfError::MissingWitnessValue { .. }) => continue,
            Err(err) => return Err(err),
        };

        let lookup_table = program
            .lookup_tables
            .iter()
            .find(|item| item.name == *table)
            .ok_or_else(|| ZkfError::UnknownLookupTable {
                table: table.clone(),
            })?;

        let mut matched_row: Option<&Vec<FieldElement>> = None;
        for row in &lookup_table.values {
            let mut inputs_match = true;
            for (col_idx, input_value) in evaluated_inputs.iter().enumerate() {
                let row_value = row.get(col_idx).cloned().unwrap_or(FieldElement::ZERO);
                if row_value.normalized_bigint(program.field)? != *input_value {
                    inputs_match = false;
                    break;
                }
            }
            if !inputs_match {
                continue;
            }

            if let Some(existing) = matched_row {
                let outputs_equal = output_names.iter().enumerate().all(|(output_idx, _)| {
                    let col_idx = evaluated_inputs.len() + output_idx;
                    existing.get(col_idx) == row.get(col_idx)
                });
                if !outputs_equal {
                    return Err(ZkfError::LookupConstraintViolation {
                        index: 0,
                        label: None,
                        table: table.clone(),
                        message: format!(
                            "lookup table '{}' is ambiguous for the provided inputs",
                            table
                        ),
                    });
                }
                continue;
            }

            matched_row = Some(row);
        }

        let Some(row) = matched_row else {
            continue;
        };

        for (output_idx, name) in output_names.iter().enumerate() {
            if values.contains_key(name) {
                continue;
            }
            let col_idx = evaluated_inputs.len() + output_idx;
            let Some(row_value) = row.get(col_idx) else {
                continue;
            };
            values.insert(name.clone(), row_value.clone());
            numeric_values.insert(name.clone(), row_value.normalized_bigint(program.field)?);
            progress = true;
        }
    }

    Ok(progress)
}

fn solve_radix_decompositions(
    program: &Program,
    values: &mut BTreeMap<String, FieldElement>,
    numeric_values: &mut BTreeMap<String, BigInt>,
) -> ZkfResult<bool> {
    let range_bits = collect_signal_range_bits(program);
    let mut progress = false;

    for constraint in &program.constraints {
        let Constraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        let Some(assignments) = solve_radix_decomposition_equality(
            lhs,
            rhs,
            numeric_values,
            &range_bits,
            program.field,
        )?
        else {
            continue;
        };

        for (signal, value) in assignments {
            if values.contains_key(&signal) {
                continue;
            }
            values.insert(
                signal.clone(),
                FieldElement::from_bigint_with_field(value.clone(), program.field),
            );
            numeric_values.insert(signal, value);
            progress = true;
        }
    }

    Ok(progress)
}

fn collect_missing_signals(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    missing: &mut BTreeSet<String>,
) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            if !values.contains_key(name) {
                missing.insert(name.clone());
            }
        }
        Expr::Add(items) => {
            for item in items {
                collect_missing_signals(item, values, missing);
            }
        }
        Expr::Sub(lhs, rhs) | Expr::Mul(lhs, rhs) | Expr::Div(lhs, rhs) => {
            collect_missing_signals(lhs, values, missing);
            collect_missing_signals(rhs, values, missing);
        }
    }
}

fn collect_signal_range_bits(program: &Program) -> BTreeMap<String, u32> {
    let mut ranges = BTreeMap::new();
    for constraint in &program.constraints {
        match constraint {
            Constraint::Boolean { signal, .. } => {
                ranges
                    .entry(signal.clone())
                    .and_modify(|bits: &mut u32| *bits = (*bits).min(1))
                    .or_insert(1);
            }
            Constraint::Range { signal, bits, .. } => {
                ranges
                    .entry(signal.clone())
                    .and_modify(|existing: &mut u32| *existing = (*existing).min(*bits))
                    .or_insert(*bits);
            }
            _ => {}
        }
    }
    ranges
}

fn collect_signal_names(expr: &Expr, names: &mut BTreeSet<String>) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            names.insert(name.clone());
        }
        Expr::Add(items) => {
            for item in items {
                collect_signal_names(item, names);
            }
        }
        Expr::Sub(lhs, rhs) | Expr::Mul(lhs, rhs) | Expr::Div(lhs, rhs) => {
            collect_signal_names(lhs, names);
            collect_signal_names(rhs, names);
        }
    }
}

fn extract_affine_form(
    expr: &Expr,
    target: &str,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<Option<(BigInt, BigInt)>> {
    match expr {
        Expr::Const(value) => Ok(Some((BigInt::zero(), value.normalized_bigint(field)?))),
        Expr::Signal(name) if name == target => Ok(Some((BigInt::one(), BigInt::zero()))),
        Expr::Signal(name) => Ok(values
            .get(name)
            .cloned()
            .map(|value| (BigInt::zero(), field_normalize(value, field)))),
        Expr::Add(items) => {
            let mut coeff = BigInt::zero();
            let mut constant = BigInt::zero();
            for item in items {
                let Some((item_coeff, item_const)) =
                    extract_affine_form(item, target, values, field)?
                else {
                    return Ok(None);
                };
                coeff = field_add(&coeff, &item_coeff, field);
                constant = field_add(&constant, &item_const, field);
            }
            Ok(Some((coeff, constant)))
        }
        Expr::Sub(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) = extract_affine_form(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) = extract_affine_form(rhs, target, values, field)?
            else {
                return Ok(None);
            };
            Ok(Some((
                field_sub(&lhs_coeff, &rhs_coeff, field),
                field_sub(&lhs_const, &rhs_const, field),
            )))
        }
        Expr::Mul(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) = extract_affine_form(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) = extract_affine_form(rhs, target, values, field)?
            else {
                return Ok(None);
            };

            match (lhs_coeff.is_zero(), rhs_coeff.is_zero()) {
                (true, true) => Ok(Some((
                    BigInt::zero(),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
                (false, false) => Ok(None),
                (true, false) => Ok(Some((
                    field_mul(&lhs_const, &rhs_coeff, field),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
                (false, true) => Ok(Some((
                    field_mul(&rhs_const, &lhs_coeff, field),
                    field_mul(&lhs_const, &rhs_const, field),
                ))),
            }
        }
        Expr::Div(lhs, rhs) => {
            let Some((lhs_coeff, lhs_const)) = extract_affine_form(lhs, target, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_coeff, rhs_const)) = extract_affine_form(rhs, target, values, field)?
            else {
                return Ok(None);
            };
            if !rhs_coeff.is_zero() {
                return Ok(None);
            }
            let denominator = field_normalize(rhs_const, field);
            let Some(inverse) = field_inv(&denominator, field) else {
                return Ok(None);
            };
            Ok(Some((
                field_mul(&lhs_coeff, &inverse, field),
                field_mul(&lhs_const, &inverse, field),
            )))
        }
    }
}

fn solve_radix_decomposition_equality(
    lhs: &Expr,
    rhs: &Expr,
    values: &BTreeMap<String, BigInt>,
    range_bits: &BTreeMap<String, u32>,
    field: FieldId,
) -> ZkfResult<Option<Vec<(String, BigInt)>>> {
    if let Ok(target) = eval_expr_bigint(lhs, values, field)
        && let Some(assignments) =
            solve_radix_decomposition_side(target, rhs, values, range_bits, field)?
    {
        return Ok(Some(assignments));
    }

    if let Ok(target) = eval_expr_bigint(rhs, values, field)
        && let Some(assignments) =
            solve_radix_decomposition_side(target, lhs, values, range_bits, field)?
    {
        return Ok(Some(assignments));
    }

    Ok(None)
}

fn solve_radix_decomposition_side(
    target: BigInt,
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    range_bits: &BTreeMap<String, u32>,
    field: FieldId,
) -> ZkfResult<Option<Vec<(String, BigInt)>>> {
    let Some((known_sum, missing_terms)) = extract_scaled_missing_terms(expr, values, field)?
    else {
        return Ok(None);
    };

    if missing_terms.len() < 2 {
        return Ok(None);
    }

    let target = field_sub(&target, &known_sum, field);

    let mut decoded_terms = Vec::with_capacity(missing_terms.len());
    for (signal, coeff) in missing_terms {
        if values.contains_key(&signal) {
            continue;
        }
        let Some(bits) = range_bits.get(&signal).copied() else {
            return Ok(None);
        };
        let Some(offset) = power_of_two_exponent(&coeff) else {
            return Ok(None);
        };
        decoded_terms.push((signal, offset, bits));
    }

    if decoded_terms.len() < 2 {
        return Ok(None);
    }

    decoded_terms.sort_by_key(|(_, offset, _)| *offset);
    for pair in decoded_terms.windows(2) {
        if let [(_, lhs_offset, lhs_bits), (_, rhs_offset, _)] = pair
            && *rhs_offset < lhs_offset.saturating_add(*lhs_bits as usize)
        {
            return Ok(None);
        }
    }

    let mut assignments = Vec::with_capacity(decoded_terms.len());
    let mut recomposed = BigInt::zero();
    for (signal, offset, bits) in decoded_terms {
        let mask = (BigInt::one() << bits) - BigInt::one();
        let digit = (target.clone() >> offset) & mask;
        recomposed += digit.clone() << offset;
        assignments.push((signal, digit));
    }

    if recomposed != target {
        return Ok(None);
    }

    Ok(Some(assignments))
}

fn extract_scaled_missing_terms(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<Option<ScaledMissingTerms>> {
    match expr {
        Expr::Const(value) => Ok(Some((value.normalized_bigint(field)?, Vec::new()))),
        Expr::Signal(name) => {
            if let Some(value) = values.get(name) {
                Ok(Some((value.clone(), Vec::new())))
            } else {
                Ok(Some((BigInt::zero(), vec![(name.clone(), BigInt::one())])))
            }
        }
        Expr::Add(items) => {
            let mut known = BigInt::zero();
            let mut missing = Vec::new();
            for item in items {
                let Some((item_known, item_missing)) =
                    extract_scaled_missing_terms(item, values, field)?
                else {
                    return Ok(None);
                };
                known = field_add(&known, &item_known, field);
                missing.extend(item_missing);
            }
            Ok(Some((known, missing)))
        }
        Expr::Sub(lhs, rhs) => {
            let Some((lhs_known, lhs_missing)) = extract_scaled_missing_terms(lhs, values, field)?
            else {
                return Ok(None);
            };
            let Some((rhs_known, rhs_missing)) = extract_scaled_missing_terms(rhs, values, field)?
            else {
                return Ok(None);
            };
            let mut missing = lhs_missing;
            for (signal, coeff) in rhs_missing {
                missing.push((signal, -coeff));
            }
            Ok(Some((field_sub(&lhs_known, &rhs_known, field), missing)))
        }
        Expr::Mul(lhs, rhs) => {
            if let Some(factor) = extract_known_scalar(lhs, values, field)? {
                let Some((known, missing)) = extract_scaled_missing_terms(rhs, values, field)?
                else {
                    return Ok(None);
                };
                return Ok(Some((
                    field_mul(&known, &factor, field),
                    missing
                        .into_iter()
                        .map(|(signal, coeff)| (signal, field_mul(&coeff, &factor, field)))
                        .collect(),
                )));
            }
            if let Some(factor) = extract_known_scalar(rhs, values, field)? {
                let Some((known, missing)) = extract_scaled_missing_terms(lhs, values, field)?
                else {
                    return Ok(None);
                };
                return Ok(Some((
                    field_mul(&known, &factor, field),
                    missing
                        .into_iter()
                        .map(|(signal, coeff)| (signal, field_mul(&coeff, &factor, field)))
                        .collect(),
                )));
            }
            Ok(None)
        }
        Expr::Div(_, _) => Ok(None),
    }
}

fn extract_known_scalar(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<Option<BigInt>> {
    match expr {
        Expr::Const(value) => Ok(Some(value.normalized_bigint(field)?)),
        Expr::Signal(name) => Ok(values.get(name).cloned()),
        _ => Ok(None),
    }
}

fn power_of_two_exponent(value: &BigInt) -> Option<usize> {
    if value.sign() != num_bigint::Sign::Plus || value.is_zero() {
        return None;
    }

    let mut current = value.clone();
    let mut exponent = 0usize;
    while current > BigInt::one() {
        if (&current & BigInt::one()) != BigInt::zero() {
            return None;
        }
        current >>= 1usize;
        exponent += 1;
    }
    Some(exponent)
}

/// Attempt to pre-solve witness values using the stored ACIR program bytes.
///
/// This decodes the base64-encoded Noir artifact JSON, parses it as an ACIR
/// program, and runs the ACVM solver to populate all solvable witness values
/// (including Brillig outputs). Failures are silently ignored — the normal
/// hint/assignment loop will handle whatever remains.
fn try_acvm_presolver(
    acir_b64: &str,
    program: &Program,
    values: &mut BTreeMap<String, FieldElement>,
    numeric_values: &mut BTreeMap<String, BigInt>,
) -> bool {
    #[cfg(feature = "acvm-solver-beta19")]
    {
        if try_noir_beta19_presolver(acir_b64, program, values, numeric_values) {
            return true;
        }
    }

    #[cfg(feature = "acvm-solver")]
    {
        use crate::solver::WitnessSolver;
        use crate::solver::acvm_adapter::AcvmWitnessSolver;

        let json_bytes = match base64::engine::general_purpose::STANDARD.decode(acir_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // The stored bytes are the full Noir artifact JSON. We need to extract
        // enough context for the ACVM solver. The solver works by re-lowering
        // the ZKF IR — but the real value here is that execute() may have
        // already populated values that are now in `values`. For programs
        // where the ACVM solver can operate (BN254), try it as a pre-pass.
        let _ = json_bytes; // Avoid unused warning when the block below is skipped.

        // Build a partial witness from current values and let the ACVM solver
        // fill in what it can from the ZKF IR constraints.
        let partial = Witness {
            values: values.clone(),
        };
        let solver = AcvmWitnessSolver;
        let mut progress = false;
        if let Ok(solved) = solver.solve(program, &partial) {
            for (name, value) in solved.values {
                if let std::collections::btree_map::Entry::Vacant(entry) = values.entry(name) {
                    if let Ok(bigint) = value.normalized_bigint(program.field) {
                        numeric_values.insert(entry.key().clone(), bigint);
                    }
                    entry.insert(value);
                    progress = true;
                }
            }
        }

        progress
    }

    #[cfg(not(feature = "acvm-solver"))]
    {
        let _ = (acir_b64, program, values, numeric_values);
        false
    }
}

#[cfg(feature = "acvm-solver-beta19")]
fn try_noir_beta19_presolver(
    acir_b64: &str,
    program: &Program,
    values: &mut BTreeMap<String, FieldElement>,
    numeric_values: &mut BTreeMap<String, BigInt>,
) -> bool {
    let json_bytes = match base64::engine::general_purpose::STANDARD.decode(acir_b64) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let artifact: Value = match serde_json::from_slice(&json_bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let version = artifact
        .get("noir_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if version.split('+').next().unwrap_or(version) != "1.0.0-beta.19" {
        return false;
    }

    let noir_program = match parse_beta19_program_value(&artifact) {
        Ok(program_value) => program_value,
        Err(_) => return false,
    };

    let mut initial_witness = Beta19WitnessMap::new();
    for (name, value) in values.iter() {
        let witness = match parse_signal_as_beta19_witness(name) {
            Ok(witness) => witness,
            Err(_) => continue,
        };
        let field = match parse_beta19_field_element(value) {
            Ok(field) => field,
            Err(_) => return false,
        };
        initial_witness.insert(witness, field);
    }

    let solved = match execute_beta19_function(&noir_program, 0, initial_witness) {
        Ok(solved) => solved,
        Err(_) => return false,
    };

    for (witness, value) in solved {
        let signal_name = format!("w{}", witness.0);
        let field_value = beta19_field_to_field_element(value);
        if let Ok(bigint) = field_value.normalized_bigint(program.field) {
            numeric_values.insert(signal_name.clone(), bigint);
        }
        values.entry(signal_name).or_insert(field_value);
    }

    true
}

#[cfg(feature = "acvm-solver-beta19")]
fn parse_beta19_program_value(value: &Value) -> ZkfResult<Beta19Program<Beta19FieldElement>> {
    if let Some(program) = value.get("program") {
        return serde_json::from_value(program.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize beta.19 program JSON: {err}"))
        });
    }

    let bytecode = value
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "noir artifact execution requires 'bytecode' or 'program'".to_string(),
            )
        })?;
    let program_bytes = base64::engine::general_purpose::STANDARD
        .decode(bytecode.trim())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid base64 Noir ACIR bytecode: {err}"))
        })?;
    Beta19Program::deserialize_program(&program_bytes).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize Noir beta.19 bytecode: {err}"
        ))
    })
}

#[cfg(feature = "acvm-solver-beta19")]
fn execute_beta19_function(
    program: &Beta19Program<Beta19FieldElement>,
    function_index: usize,
    initial_witness: Beta19WitnessMap<Beta19FieldElement>,
) -> ZkfResult<Beta19WitnessMap<Beta19FieldElement>> {
    let function = program.functions.get(function_index).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.19 execution referenced missing function {function_index}"
        ))
    })?;

    let backend = Beta19Bn254BlackBoxSolver;
    let mut acvm = Beta19Acvm::new(
        &backend,
        &function.opcodes,
        initial_witness,
        &program.unconstrained_functions,
        &function.assert_messages,
    );

    loop {
        match acvm.solve() {
            Beta19AcvmStatus::Solved => break,
            Beta19AcvmStatus::InProgress => continue,
            Beta19AcvmStatus::RequiresForeignCall(foreign_call) => {
                let normalized = foreign_call.function.to_ascii_lowercase();
                if normalized.contains("print") || normalized.contains("debug") {
                    acvm.resolve_pending_foreign_call(Beta19ForeignCallResult::default());
                    continue;
                }
                return Err(ZkfError::UnsupportedBackend {
                    backend: "witness:beta19-presolver".to_string(),
                    message: format!(
                        "beta.19 execution requires unresolved foreign call '{}'",
                        foreign_call.function
                    ),
                });
            }
            Beta19AcvmStatus::RequiresAcirCall(call_info) => {
                let callee_index = call_info.id.as_usize();
                let callee_witness =
                    execute_beta19_function(program, callee_index, call_info.initial_witness)?;
                let callee_function = program.functions.get(callee_index).ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "beta.19 execution referenced missing function {callee_index}"
                    ))
                })?;
                let mut outputs = Vec::new();
                let mut return_indices = callee_function
                    .return_values
                    .indices()
                    .into_iter()
                    .collect::<Vec<_>>();
                return_indices.sort_unstable();
                for return_index in return_indices {
                    let value = callee_witness
                        .get(&Beta19Witness(return_index))
                        .ok_or_else(|| {
                            ZkfError::InvalidArtifact(format!(
                                "beta.19 execution failed to resolve call output witness w{return_index} from function {callee_index}"
                            ))
                        })?;
                    outputs.push(*value);
                }
                acvm.resolve_pending_acir_call(outputs);
            }
            Beta19AcvmStatus::Failure(error) => return Err(ZkfError::Backend(error.to_string())),
        }
    }

    Ok(acvm.finalize())
}

#[cfg(feature = "acvm-solver-beta19")]
fn parse_signal_as_beta19_witness(name: &str) -> ZkfResult<Beta19Witness> {
    let index_str = name.strip_prefix('w').ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.19 execution expects witness-style signal names (w<index>), found '{name}'"
        ))
    })?;
    let index = index_str.parse::<u32>().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "invalid witness signal name '{name}', expected w<index>"
        ))
    })?;
    Ok(Beta19Witness(index))
}

#[cfg(feature = "acvm-solver-beta19")]
fn parse_beta19_field_element(value: &FieldElement) -> ZkfResult<Beta19FieldElement> {
    let normalized = value.normalized_bigint(FieldId::Bn254)?;
    let (_, mut bytes) = normalized.to_bytes_be();
    if bytes.is_empty() {
        bytes.push(0);
    }
    Ok(Beta19FieldElement::from_be_bytes_reduce(&bytes))
}

#[cfg(feature = "acvm-solver-beta19")]
fn beta19_field_to_field_element(value: Beta19FieldElement) -> FieldElement {
    let bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &value.to_be_bytes());
    FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
}

#[cfg(feature = "acvm-solver")]
fn try_native_ec_blackbox_presolver(
    program: &Program,
    values: &mut BTreeMap<String, FieldElement>,
    numeric_values: &mut BTreeMap<String, BigInt>,
) -> bool {
    use acvm::BlackBoxFunctionSolver;
    use acvm::acir::FieldElement as AcirFieldElement;
    use bn254_blackbox_solver::Bn254BlackBoxSolver;

    if program.field != FieldId::Bn254 {
        return false;
    }

    let solver = Bn254BlackBoxSolver::default();
    let mask_128 = (BigInt::from(1u8) << 128) - BigInt::from(1u8);
    let to_acir_field = |value: &FieldElement| -> Option<AcirFieldElement> {
        let normalized = value.normalized_bigint(FieldId::Bn254).ok()?;
        let (_, mut bytes) = normalized.to_bytes_be();
        if bytes.is_empty() {
            bytes.push(0);
        }
        Some(AcirFieldElement::from_be_bytes_reduce(&bytes))
    };
    let from_acir_field = |value: AcirFieldElement| -> FieldElement {
        let bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &value.to_be_bytes());
        FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
    };

    let mut any_progress = false;
    loop {
        let mut progress = false;

        for constraint in &program.constraints {
            let Constraint::BlackBox {
                op,
                inputs,
                outputs,
                ..
            } = constraint
            else {
                continue;
            };

            if outputs.is_empty() || outputs.iter().all(|output| values.contains_key(output)) {
                continue;
            }

            let input_values = match inputs
                .iter()
                .map(|expr| eval_expr_bigint(expr, numeric_values, program.field))
                .collect::<ZkfResult<Vec<_>>>()
            {
                Ok(values) => values,
                Err(ZkfError::MissingWitnessValue { .. }) => continue,
                Err(_) => continue,
            };

            let solved = match op {
                BlackBoxOp::ScalarMulG1 if input_values.len() == 3 && outputs.len() == 2 => {
                    let scalar = field_normalize(input_values[0].clone(), program.field);
                    let scalar_lo = field_normalize(&scalar & &mask_128, program.field);
                    let scalar_hi = field_normalize(scalar >> 128, program.field);
                    let Some(point_x) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[1].clone(),
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(point_y) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[2].clone(),
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(scalar_lo) = to_acir_field(&FieldElement::from_bigint_with_field(
                        scalar_lo,
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(scalar_hi) = to_acir_field(&FieldElement::from_bigint_with_field(
                        scalar_hi,
                        program.field,
                    )) else {
                        continue;
                    };

                    solver
                        .multi_scalar_mul(&[point_x, point_y], &[scalar_lo, scalar_hi])
                        .ok()
                        .map(|(x, y)| vec![from_acir_field(x), from_acir_field(y)])
                }
                BlackBoxOp::PointAddG1 if input_values.len() == 4 && outputs.len() == 2 => {
                    let Some(x1) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[0].clone(),
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(y1) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[1].clone(),
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(x2) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[2].clone(),
                        program.field,
                    )) else {
                        continue;
                    };
                    let Some(y2) = to_acir_field(&FieldElement::from_bigint_with_field(
                        input_values[3].clone(),
                        program.field,
                    )) else {
                        continue;
                    };

                    solver
                        .ec_add(&x1, &y1, &x2, &y2)
                        .ok()
                        .map(|(x, y)| vec![from_acir_field(x), from_acir_field(y)])
                }
                _ => None,
            };

            let Some(solved_outputs) = solved else {
                continue;
            };

            for (name, value) in outputs.iter().zip(solved_outputs.into_iter()) {
                if !values.contains_key(name.as_str()) {
                    if let Ok(bigint) = value.normalized_bigint(program.field) {
                        numeric_values.insert(name.clone(), bigint);
                    }
                    values.insert(name.clone(), value);
                    progress = true;
                    any_progress = true;
                }
            }
        }

        if !progress {
            break;
        }
    }

    any_progress
}

#[cfg(test)]
mod proof_kernel_tests {
    use super::*;
    use crate::{Signal, WitnessPlan, ir::LookupTable};
    use proptest::prelude::*;

    fn field_by_index(index: u8) -> FieldId {
        match index % 7 {
            0 => FieldId::Bn254,
            1 => FieldId::Bls12_381,
            2 => FieldId::PastaFp,
            3 => FieldId::PastaFq,
            4 => FieldId::Goldilocks,
            5 => FieldId::BabyBear,
            _ => FieldId::Mersenne31,
        }
    }

    fn lookup_program(field: FieldId) -> Program {
        Program {
            name: "kernel-lookup".into(),
            field,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "flag".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
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
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("out".into()),
                    rhs: Expr::Add(vec![Expr::Signal("x".into()), Expr::Signal("y".into())]),
                    label: Some("out_eq_sum".into()),
                },
                Constraint::Boolean {
                    signal: "flag".into(),
                    label: Some("flag_boolean".into()),
                },
                Constraint::Range {
                    signal: "selector".into(),
                    bits: 2,
                    label: Some("selector_range".into()),
                },
                Constraint::Lookup {
                    inputs: vec![Expr::Signal("selector".into())],
                    table: "selector_map".into(),
                    outputs: Some(vec!["mapped".into()]),
                    label: Some("selector_lookup".into()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![LookupTable {
                name: "selector_map".into(),
                columns: vec!["selector".into(), "mapped".into()],
                values: vec![
                    vec![FieldElement::from_u64(0), FieldElement::from_u64(5)],
                    vec![FieldElement::from_u64(1), FieldElement::from_u64(9)],
                    vec![FieldElement::from_u64(2), FieldElement::from_u64(17)],
                    vec![FieldElement::from_u64(3), FieldElement::from_u64(33)],
                ],
            }],
            metadata: Default::default(),
        }
    }

    fn mapped_value(selector: u64) -> u64 {
        match selector % 4 {
            0 => 5,
            1 => 9,
            2 => 17,
            _ => 33,
        }
    }

    fn affine_program(field: FieldId) -> Program {
        Program {
            name: "affine-recovery".into(),
            field,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal("x".into()),
                    Expr::Const(FieldElement::from_u64(5)),
                ]),
                rhs: Expr::Signal("y".into()),
                label: Some("recover_x".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn assignment_program(field: FieldId) -> Program {
        Program {
            name: "assignment-plan".into(),
            field,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("out".into()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".into()),
                    Expr::Const(FieldElement::from_u64(5)),
                ]),
                label: Some("assigned_out".into()),
            }],
            witness_plan: WitnessPlan {
                assignments: vec![crate::WitnessAssignment {
                    target: "out".into(),
                    expr: Expr::Add(vec![
                        Expr::Signal("x".into()),
                        Expr::Const(FieldElement::from_u64(5)),
                    ]),
                }],
                ..WitnessPlan::default()
            },
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn hint_program(field: FieldId) -> Program {
        Program {
            name: "hint-plan".into(),
            field,
            signals: vec![
                Signal {
                    name: "source".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "mirror".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("mirror".into()),
                rhs: Expr::Signal("source".into()),
                label: Some("hint_copies_source".into()),
            }],
            witness_plan: WitnessPlan {
                hints: vec![crate::WitnessHint {
                    target: "mirror".into(),
                    source: "source".into(),
                    kind: WitnessHintKind::Copy,
                }],
                ..WitnessPlan::default()
            },
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn mixed_assignment_hint_program(field: FieldId) -> Program {
        Program {
            name: "assignment-and-hint".into(),
            field,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "sum".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "mirror".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("sum".into()),
                    rhs: Expr::Add(vec![
                        Expr::Signal("x".into()),
                        Expr::Const(FieldElement::from_u64(7)),
                    ]),
                    label: Some("sum_assignment".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("mirror".into()),
                    rhs: Expr::Signal("sum".into()),
                    label: Some("mirror_hint".into()),
                },
            ],
            witness_plan: WitnessPlan {
                assignments: vec![crate::WitnessAssignment {
                    target: "sum".into(),
                    expr: Expr::Add(vec![
                        Expr::Signal("x".into()),
                        Expr::Const(FieldElement::from_u64(7)),
                    ]),
                }],
                hints: vec![crate::WitnessHint {
                    target: "mirror".into(),
                    source: "sum".into(),
                    kind: WitnessHintKind::Copy,
                }],
                ..WitnessPlan::default()
            },
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn radix_program(field: FieldId) -> Program {
        Program {
            name: "radix-decomposition".into(),
            field,
            signals: vec![
                Signal {
                    name: "value".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "lo".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "hi".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Range {
                    signal: "lo".into(),
                    bits: 4,
                    label: Some("lo_range".into()),
                },
                Constraint::Range {
                    signal: "hi".into(),
                    bits: 4,
                    label: Some("hi_range".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("value".into()),
                    rhs: Expr::Add(vec![
                        Expr::Signal("lo".into()),
                        Expr::Mul(
                            Box::new(Expr::Const(FieldElement::from_u64(16))),
                            Box::new(Expr::Signal("hi".into())),
                        ),
                    ]),
                    label: Some("recompose".into()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn blackbox_program(field: FieldId) -> Program {
        Program {
            name: "blackbox-path".into(),
            field,
            signals: vec![
                Signal {
                    name: "msg".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::BlackBox {
                op: BlackBoxOp::Pedersen,
                inputs: vec![Expr::Signal("msg".into())],
                outputs: vec!["out".into()],
                params: BTreeMap::new(),
                label: Some("pedersen".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn kernel_checked(program: &Program, witness: &Witness) -> ZkfResult<()> {
        let (kernel_program, kernel_witness, context) =
            translate_program_to_kernel(program, witness)?;
        proof_kernel::check_program(&kernel_program, &kernel_witness)
            .map_err(|error| map_kernel_error(error, &context, program.field))
    }

    fn spec_kernel_checked(program: &Program, witness: &Witness) -> ZkfResult<()> {
        let (kernel_program, kernel_witness, context) =
            translate_program_to_spec_kernel(program, witness)?;
        proof_kernel_spec::check_program(&kernel_program, &kernel_witness)
            .map_err(|error| map_spec_kernel_error(error, &context))
    }

    fn spec_eval_expr_checked(
        expr: &Expr,
        values: &BTreeMap<String, FieldElement>,
        field: FieldId,
    ) -> ZkfResult<FieldElement> {
        let mut signal_names = BTreeSet::new();
        collect_signal_names(expr, &mut signal_names);
        signal_names.extend(values.keys().cloned());

        let ordered_names = signal_names.into_iter().collect::<Vec<_>>();
        let signal_indices = ordered_names
            .iter()
            .enumerate()
            .map(|(index, signal)| (signal.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let kernel_expr = translate_expr_to_spec_kernel(expr, &signal_indices)?;
        let kernel_values = ordered_names
            .iter()
            .map(|signal| values.get(signal).map(SpecFieldValue::from_runtime))
            .collect::<Vec<_>>();
        let kernel_witness = SpecKernelWitness {
            values: kernel_values,
        };
        let context = SpecKernelAdapterContext {
            constraint_labels: Vec::new(),
            signal_names: ordered_names,
            table_names: Vec::new(),
        };
        proof_kernel_spec::eval_expr(&kernel_expr, &kernel_witness, field)
            .map_err(|error| map_spec_kernel_error(error, &context))
            .map(|value| value.to_runtime())
    }

    proptest! {
        #[test]
        fn public_eval_expr_matches_kernel_adapter(
            field_index in 0u8..7,
            x in 1u16..1024,
            y in 1u16..1024,
            z in 1u16..1024,
        ) {
            let field = field_by_index(field_index);
            let expr = Expr::Div(
                Box::new(Expr::Mul(
                    Box::new(Expr::Add(vec![
                        Expr::Signal("x".into()),
                        Expr::Signal("y".into()),
                    ])),
                    Box::new(Expr::Signal("z".into())),
                )),
                Box::new(Expr::Const(FieldElement::from_u64(3))),
            );
            let values = BTreeMap::from([
                ("x".to_string(), FieldElement::from_u64(u64::from(x))),
                ("y".to_string(), FieldElement::from_u64(u64::from(y))),
                ("z".to_string(), FieldElement::from_u64(u64::from(z))),
            ]);
            let numeric = build_bigint_values(&values, field).expect("numeric values should build");

            let adapter = eval_expr(&expr, &values, field).expect("public eval should succeed");
            let local = eval_expr_bigint(&expr, &numeric, field).expect("local eval should succeed");
            let spec = spec_eval_expr_checked(&expr, &values, field).expect("spec eval should succeed");
            prop_assert_eq!(adapter.clone(), local);
            prop_assert_eq!(
                FieldElement::from_bigint_with_field(adapter, field),
                spec
            );
        }

        #[test]
        fn check_constraints_matches_direct_kernel_for_core_constraint_kinds(
            field_index in 0u8..7,
            x in 0u16..1024,
            y in 0u16..1024,
            selector in 0u8..6,
            break_sum in any::<bool>(),
            break_flag in any::<bool>(),
            break_lookup in any::<bool>(),
        ) {
            let field = field_by_index(field_index);
            let program = lookup_program(field);
            let selector_u64 = u64::from(selector);
            let expected_sum = BigInt::from(u64::from(x)) + BigInt::from(u64::from(y));
            let out = if break_sum {
                FieldElement::from_bigint_with_field(expected_sum.clone() + BigInt::one(), field)
            } else {
                FieldElement::from_bigint_with_field(expected_sum, field)
            };
            let flag = if break_flag {
                FieldElement::from_u64(2)
            } else {
                FieldElement::from_u64(selector_u64 % 2)
            };
            let mapped = if break_lookup {
                FieldElement::from_u64(mapped_value(selector_u64).saturating_add(1))
            } else {
                FieldElement::from_u64(mapped_value(selector_u64))
            };
            let witness = Witness {
                values: BTreeMap::from([
                    ("x".into(), FieldElement::from_u64(u64::from(x))),
                    ("y".into(), FieldElement::from_u64(u64::from(y))),
                    ("flag".into(), flag),
                    ("selector".into(), FieldElement::from_u64(selector_u64)),
                    ("mapped".into(), mapped),
                    ("out".into(), out),
                ]),
            };

            let adapter = check_constraints(&program, &witness)
                .map(|_| "ok".to_string())
                .map_err(|error| error.to_string());
            let direct = kernel_checked(&program, &witness)
                .map(|_| "ok".to_string())
                .map_err(|error| error.to_string());
            let spec = spec_kernel_checked(&program, &witness)
                .map(|_| "ok".to_string())
                .map_err(|error| error.to_string());

            prop_assert_eq!(adapter, direct.clone());
            prop_assert_eq!(direct, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_affine_generation(
            field_index in 0u8..7,
            y in 5u16..2048,
        ) {
            let field = field_by_index(field_index);
            let program = affine_program(field);
            let inputs = BTreeMap::from([(
                "y".to_string(),
                FieldElement::from_u64(u64::from(y)),
            )]);

            let public = generate_witness(&program, &inputs).expect("public affine solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec affine solve should succeed");

            prop_assert_eq!(public, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_assignment_generation(
            field_index in 0u8..7,
            x in 0u16..2048,
        ) {
            let field = field_by_index(field_index);
            let program = assignment_program(field);
            let inputs = BTreeMap::from([(
                "x".to_string(),
                FieldElement::from_u64(u64::from(x)),
            )]);

            let public = generate_witness(&program, &inputs).expect("public assignment solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec assignment solve should succeed");

            prop_assert_eq!(public, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_hint_generation(
            field_index in 0u8..7,
            source in 0u16..2048,
        ) {
            let field = field_by_index(field_index);
            let program = hint_program(field);
            let inputs = BTreeMap::from([(
                "source".to_string(),
                FieldElement::from_u64(u64::from(source)),
            )]);

            let public = generate_witness(&program, &inputs).expect("public hint solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec hint solve should succeed");

            prop_assert_eq!(public, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_mixed_assignment_hint_generation(
            field_index in 0u8..7,
            x in 0u16..2048,
        ) {
            let field = field_by_index(field_index);
            let program = mixed_assignment_hint_program(field);
            let inputs = BTreeMap::from([(
                "x".to_string(),
                FieldElement::from_u64(u64::from(x)),
            )]);

            let public = generate_witness(&program, &inputs).expect("public mixed solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec mixed solve should succeed");

            prop_assert_eq!(public, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_lookup_generation(
            field_index in 0u8..7,
            x in 0u16..1024,
            y in 0u16..1024,
            selector in 0u8..4,
        ) {
            let field = field_by_index(field_index);
            let program = lookup_program(field);
            let selector_u64 = u64::from(selector);
            let inputs = BTreeMap::from([
                ("x".to_string(), FieldElement::from_u64(u64::from(x))),
                ("y".to_string(), FieldElement::from_u64(u64::from(y))),
                ("flag".to_string(), FieldElement::from_u64(selector_u64 % 2)),
                ("selector".to_string(), FieldElement::from_u64(selector_u64)),
            ]);

            let public = generate_witness(&program, &inputs).expect("public lookup solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec lookup solve should succeed");

            prop_assert_eq!(public, spec);
        }

        #[test]
        fn non_blackbox_spec_matches_public_radix_generation(
            field_index in 0u8..7,
            value in 0u16..256,
        ) {
            let field = field_by_index(field_index);
            let program = radix_program(field);
            let inputs = BTreeMap::from([(
                "value".to_string(),
                FieldElement::from_u64(u64::from(value)),
            )]);

            let public = generate_witness(&program, &inputs).expect("public radix solve should succeed");
            let spec = spec_generate_non_blackbox_witness_checked(&program, &inputs)
                .expect("spec radix solve should succeed");

            prop_assert_eq!(public, spec);
        }
    }

    #[test]
    fn non_blackbox_spec_rejects_nonlinear_unresolved_witness() {
        let program = Program {
            name: "nonlinear".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("y".into()),
                label: Some("square".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };
        let inputs = BTreeMap::from([("y".to_string(), FieldElement::from_u64(9))]);

        let err = spec_generate_non_blackbox_witness_checked(&program, &inputs)
            .expect_err("nonlinear solve should stay unsupported");
        assert!(matches!(
            err,
            ZkfError::UnsupportedWitnessSolve {
                unresolved_signals,
                ..
            } if unresolved_signals == vec!["x".to_string()]
        ));
    }

    #[test]
    fn non_blackbox_spec_rejects_blackbox_programs() {
        let program = blackbox_program(FieldId::Bn254);
        let inputs = BTreeMap::from([("msg".to_string(), FieldElement::from_u64(7))]);

        let err = spec_generate_non_blackbox_witness_checked(&program, &inputs)
            .expect_err("blackbox path should remain outside the spec subset");
        assert!(matches!(err, ZkfError::UnsupportedWitnessSolve { .. }));
    }
}

#[cfg(all(test, feature = "acvm-solver-beta19"))]
mod tests {
    use super::*;
    use crate::{Signal, Visibility, WitnessPlan, ir::LookupTable};
    mod private_identity_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/private_identity_fixture.rs"
        ));
    }
    #[cfg(feature = "acvm-solver")]
    use acvm::BlackBoxFunctionSolver;
    #[cfg(feature = "acvm-solver")]
    use acvm::acir::FieldElement as AcirFieldElement;
    #[cfg(feature = "acvm-solver")]
    use bn254_blackbox_solver::Bn254BlackBoxSolver;

    fn private_identity_initial_values() -> (
        Program,
        BTreeMap<String, FieldElement>,
        BTreeMap<String, BigInt>,
    ) {
        let artifact_path =
            private_identity_fixture::ensure_private_identity_artifact(env!("CARGO_MANIFEST_DIR"));
        let artifact_bytes =
            std::fs::read(&artifact_path).expect("private_identity beta.19 artifact should exist");
        let acir_b64 = base64::engine::general_purpose::STANDARD.encode(&artifact_bytes);

        let program = Program {
            field: FieldId::Bn254,
            ..Default::default()
        };
        let mut values = BTreeMap::new();
        let mut numeric = BTreeMap::new();
        for (name, value) in [
            ("w0", FieldElement::new("123456789")),
            ("w1", FieldElement::from_i64(30)),
            ("w2", FieldElement::new("100000")),
            ("w3", FieldElement::from_i64(18)),
            ("w4", FieldElement::new("50000")),
        ] {
            numeric.insert(
                name.to_string(),
                value
                    .normalized_bigint(FieldId::Bn254)
                    .expect("input should normalize"),
            );
            values.insert(name.to_string(), value);
        }

        assert!(
            try_noir_beta19_presolver(&acir_b64, &program, &mut values, &mut numeric),
            "beta.19 presolver should accept the private_identity artifact"
        );
        (program, values, numeric)
    }

    #[test]
    fn beta19_private_identity_presolver_populates_internal_witnesses() {
        let (_, values, _) = private_identity_initial_values();
        assert!(values.contains_key("w10"));
        assert!(values.contains_key("w11"));
        assert!(
            !values.contains_key("w64"),
            "beta.19 direct presolver does not materialize translated constant generator witnesses"
        );
        assert!(
            !values.contains_key("w65"),
            "beta.19 direct presolver does not materialize translated constant generator witnesses"
        );
    }

    #[cfg(feature = "acvm-solver")]
    #[test]
    fn native_ec_solver_handles_first_private_identity_scalar_mul() {
        let (_, mut values, _) = private_identity_initial_values();
        let const_to_field = |constant: &str| {
            let bigint =
                BigInt::parse_bytes(constant.as_bytes(), 10).expect("constant should parse");
            FieldElement::from_bigint_with_field(
                field_normalize(-bigint, FieldId::Bn254),
                FieldId::Bn254,
            )
        };

        values.insert(
            "w64".to_string(),
            const_to_field(
                "18159359972760556147084923566472887523181882502675694544217223899316187346343",
            ),
        );
        values.insert(
            "w65".to_string(),
            const_to_field(
                "9903063709032878667290627648209915537972247634463802596148419711785767431332",
            ),
        );

        let to_acir = |value: &FieldElement| {
            let normalized = value
                .normalized_bigint(FieldId::Bn254)
                .expect("value should normalize");
            let (_, mut bytes) = normalized.to_bytes_be();
            if bytes.is_empty() {
                bytes.push(0);
            }
            AcirFieldElement::from_be_bytes_reduce(&bytes)
        };

        let scalar = values["w10"]
            .normalized_bigint(FieldId::Bn254)
            .expect("w10 should normalize")
            + (values["w11"]
                .normalized_bigint(FieldId::Bn254)
                .expect("w11 should normalize")
                << 128);
        let mask_128 = (BigInt::from(1u8) << 128) - BigInt::from(1u8);
        let scalar_lo = FieldElement::from_bigint_with_field(
            field_normalize(&scalar & &mask_128, FieldId::Bn254),
            FieldId::Bn254,
        );
        let scalar_hi = FieldElement::from_bigint_with_field(
            field_normalize(scalar >> 128, FieldId::Bn254),
            FieldId::Bn254,
        );

        let solver = Bn254BlackBoxSolver::default();
        let result = solver.multi_scalar_mul(
            &[to_acir(&values["w64"]), to_acir(&values["w65"])],
            &[to_acir(&scalar_lo), to_acir(&scalar_hi)],
        );
        assert!(
            result.is_ok(),
            "direct EC solver should accept first private_identity scalar_mul: {result:?}"
        );
    }

    #[test]
    fn lookup_constraints_are_checked_in_core_witness_validation() {
        let program = Program {
            name: "lookup_core_check".into(),
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
                inputs: vec![Expr::Signal("selector".into())],
                table: "lut".into(),
                outputs: Some(vec!["mapped".into()]),
                label: Some("selector_to_value".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![LookupTable {
                name: "lut".into(),
                columns: vec!["selector".into(), "mapped".into()],
                values: vec![
                    vec![FieldElement::from_i64(1), FieldElement::from_i64(11)],
                    vec![FieldElement::from_i64(2), FieldElement::from_i64(22)],
                ],
            }],
            metadata: Default::default(),
        };

        let witness = Witness {
            values: BTreeMap::from([
                ("selector".into(), FieldElement::from_i64(2)),
                ("mapped".into(), FieldElement::from_i64(22)),
            ]),
        };
        check_constraints(&program, &witness).expect("matching lookup row should validate");

        let bad_witness = Witness {
            values: BTreeMap::from([
                ("selector".into(), FieldElement::from_i64(2)),
                ("mapped".into(), FieldElement::from_i64(99)),
            ]),
        };
        let err = check_constraints(&program, &bad_witness).expect_err("mismatched outputs fail");
        assert!(matches!(err, ZkfError::LookupConstraintViolation { .. }));
    }

    #[test]
    fn nonlinear_unresolved_witness_reports_structured_solver_error() {
        let program = Program {
            name: "nonlinear".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("y".into()),
                label: Some("square".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let inputs = BTreeMap::from([("y".into(), FieldElement::from_i64(9))]);
        let err = generate_witness_unchecked(&program, &inputs)
            .expect_err("quadratic unresolved witness should fail explicitly");
        assert!(matches!(
            err,
            ZkfError::UnsupportedWitnessSolve {
                unresolved_signals,
                ..
            } if unresolved_signals == vec!["x".to_string()]
        ));
    }

    #[test]
    fn missing_user_input_still_reports_missing_witness_value() {
        let program = Program {
            name: "missing_input".into(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        };

        let err = generate_witness_unchecked(&program, &BTreeMap::new())
            .expect_err("unprovided unconstrained input should remain a missing witness");
        assert!(matches!(
            err,
            ZkfError::MissingWitnessValue { signal } if signal == "x"
        ));
    }
}
