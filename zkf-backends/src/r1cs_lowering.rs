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

use crate::blackbox_gadgets;
use zkf_core::lowering::LoweringReport;
use zkf_core::{BackendKind, BlackBoxOp, Constraint, Program, ZkfError, ZkfResult};

#[derive(Debug, Clone, Default)]
pub struct LoweredR1csSummary {
    pub constraints_total: usize,
    pub equal_constraints: usize,
    pub boolean_constraints: usize,
    pub range_constraints: usize,
    pub recursive_marker_constraints: usize,
    /// Number of BlackBox constraints in the original program that were lowered.
    pub blackbox_constraints_lowered: usize,
    /// Number of BlackBox constraints remaining after lowering (delegated markers).
    pub blackbox_constraints_delegated: usize,
}

#[derive(Debug, Clone)]
pub struct LoweredR1csProgram {
    pub program: Program,
    pub summary: LoweredR1csSummary,
    pub lowering_report: LoweringReport,
}

pub fn lower_program_for_backend(
    program: &Program,
    _backend: BackendKind,
) -> ZkfResult<LoweredR1csProgram> {
    // Count original BlackBox constraints before lowering.
    let original_constraint_count = program.constraints.len();
    let original_signal_count = program.signals.len();
    let original_blackbox_count = program
        .constraints
        .iter()
        .filter(|c| matches!(c, Constraint::BlackBox { .. }))
        .count();

    // Classify original BlackBox ops for the lowering report.
    let original_blackbox_ops: Vec<String> = program
        .constraints
        .iter()
        .filter_map(|c| {
            if let Constraint::BlackBox { op, .. } = c {
                Some(format!("{op:?}"))
            } else {
                None
            }
        })
        .collect();

    // First, lower all BlackBox constraints into arithmetic constraints
    // so backends actually enforce them in-circuit.
    let blackbox_lowered_program = blackbox_gadgets::lower_blackbox_program(program)?;
    // Then lower Lookup constraints into arithmetic constraints before any
    // R1CS-family backend attempts synthesis.
    let lowered_program =
        blackbox_gadgets::lookup_lowering::lower_lookup_constraints(&blackbox_lowered_program)?;

    let aux_variable_count = lowered_program
        .signals
        .len()
        .saturating_sub(original_signal_count);
    let final_constraint_count = lowered_program.constraints.len();

    let mut summary = LoweredR1csSummary {
        constraints_total: final_constraint_count,
        ..LoweredR1csSummary::default()
    };

    // Count how many BlackBox constraints remain after lowering (delegated markers).
    let mut delegated_ops: Vec<String> = Vec::new();
    for constraint in &lowered_program.constraints {
        match constraint {
            Constraint::Equal { .. } => summary.equal_constraints += 1,
            Constraint::Boolean { .. } => summary.boolean_constraints += 1,
            Constraint::Range { .. } => summary.range_constraints += 1,
            Constraint::BlackBox { op, .. } => {
                if matches!(op, BlackBoxOp::RecursiveAggregationMarker) {
                    summary.recursive_marker_constraints += 1;
                }
                delegated_ops.push(format!("{op:?}"));
            }
            Constraint::Lookup { .. } => {
                return Err(ZkfError::Backend(
                    "Lookup constraint reached backend synthesis — call \
                     lower_lookup_constraints() before compiling with an R1CS backend"
                        .to_string(),
                ));
            }
        }
    }

    let blackbox_constraints_delegated = delegated_ops.len();
    let blackbox_constraints_lowered =
        original_blackbox_count.saturating_sub(blackbox_constraints_delegated);
    summary.blackbox_constraints_lowered = blackbox_constraints_lowered;
    summary.blackbox_constraints_delegated = blackbox_constraints_delegated;

    let lowering_report = {
        // Native features: non-BlackBox constraint types that pass through unchanged.
        let native_features: Vec<String> = {
            let mut kinds = Vec::new();
            if summary.equal_constraints > 0 {
                kinds.push("equal".to_string());
            }
            if summary.boolean_constraints > 0 {
                kinds.push("boolean".to_string());
            }
            if summary.range_constraints > 0 {
                kinds.push("range".to_string());
            }
            kinds
        };

        // Adapted features: BlackBox ops that were expanded into arithmetic constraints.
        let adapted_features: Vec<String> = original_blackbox_ops
            .iter()
            .filter(|op| !delegated_ops.contains(op))
            .cloned()
            .collect();

        // Delegated features: BlackBox ops still present after lowering (e.g., markers).
        let delegated_features = delegated_ops.clone();

        LoweringReport {
            native_features,
            adapted_features,
            delegated_features,
            dropped_features: Vec::new(),
            aux_variable_count,
            original_constraint_count,
            final_constraint_count,
            incompatibilities: Vec::new(),
        }
    };

    Ok(LoweredR1csProgram {
        program: lowered_program,
        summary,
        lowering_report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::ir::LookupTable;
    use zkf_core::{Expr, FieldElement, FieldId, Signal, Visibility, WitnessPlan};

    fn base_program() -> Program {
        Program {
            name: "r1cs_lowering_test".to_string(),
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
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("x".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("eq".to_string()),
                },
                Constraint::Boolean {
                    signal: "x".to_string(),
                    label: Some("bool".to_string()),
                },
                Constraint::Range {
                    signal: "y".to_string(),
                    bits: 8,
                    label: Some("range".to_string()),
                },
                Constraint::BlackBox {
                    op: BlackBoxOp::RecursiveAggregationMarker,
                    inputs: vec![Expr::Signal("x".to_string())],
                    outputs: vec!["y".to_string()],
                    params: std::collections::BTreeMap::new(),
                    label: Some("marker".to_string()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        }
    }

    #[test]
    fn lowering_collects_constraint_summary() {
        let lowered =
            lower_program_for_backend(&base_program(), BackendKind::ArkworksGroth16).expect("ok");
        assert_eq!(lowered.summary.constraints_total, 4);
        assert_eq!(lowered.summary.equal_constraints, 1);
        assert_eq!(lowered.summary.boolean_constraints, 1);
        assert_eq!(lowered.summary.range_constraints, 1);
        assert_eq!(lowered.summary.recursive_marker_constraints, 1);
    }

    #[test]
    fn lowering_expands_blackbox_into_arithmetic_constraints() {
        let mut program = base_program();
        program.signals.extend([
            Signal {
                name: "poseidon_in1".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "poseidon_in2".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "poseidon_in3".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "poseidon_out1".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "poseidon_out2".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "poseidon_out3".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ]);
        // Add a supported Poseidon BlackBox surface (`4 -> 4`) so lowering
        // expands it into arithmetic constraints instead of rejecting the ABI.
        let mut params = std::collections::BTreeMap::new();
        params.insert("state_len".to_string(), "4".to_string());
        program.constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: vec![
                Expr::Signal("x".to_string()),
                Expr::Signal("poseidon_in1".to_string()),
                Expr::Signal("poseidon_in2".to_string()),
                Expr::Signal("poseidon_in3".to_string()),
            ],
            outputs: vec![
                "y".to_string(),
                "poseidon_out1".to_string(),
                "poseidon_out2".to_string(),
                "poseidon_out3".to_string(),
            ],
            params,
            label: Some("pos".to_string()),
        });

        let lowered = lower_program_for_backend(&program, BackendKind::Nova).expect("must lower");
        // After lowering, the Poseidon BlackBox should be replaced with
        // arithmetic constraints (Equal, Boolean, etc.), so total should be more
        // than original, and no non-marker BlackBox constraints should remain.
        assert!(lowered.summary.constraints_total > program.constraints.len() - 1);
        assert!(lowered.summary.equal_constraints > 1);
    }

    #[test]
    fn lowering_expands_lookup_into_arithmetic_constraints() {
        let mut program = base_program();
        program.lookup_tables.push(LookupTable {
            name: "small".to_string(),
            columns: vec!["value".to_string()],
            values: vec![
                vec![FieldElement::from_i64(0)],
                vec![FieldElement::from_i64(1)],
            ],
        });
        program.constraints.push(Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "small".to_string(),
            outputs: None,
            label: Some("lk".to_string()),
        });

        let lowered = lower_program_for_backend(&program, BackendKind::ArkworksGroth16)
            .expect("lookup must lower");
        assert!(
            !lowered
                .program
                .constraints
                .iter()
                .any(|constraint| matches!(constraint, Constraint::Lookup { .. })),
            "lookup constraints must be eliminated before R1CS synthesis"
        );
    }
}
