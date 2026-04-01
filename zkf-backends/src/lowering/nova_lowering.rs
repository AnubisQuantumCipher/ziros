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
use super::arkworks_lowering::{ArkworksLoweredIr, ArkworksLowering};
use zkf_core::zir;
use zkf_core::{BackendKind, ZkfResult};

/// IVC-aware signals: identifies which signals carry state across folding steps.
#[derive(Debug, Clone)]
pub struct IvcStateSignal {
    pub name: String,
    pub step_input: bool,
    pub step_output: bool,
}

/// Lowered Nova IR: R1CS with IVC state tracking.
#[derive(Debug, Clone)]
pub struct NovaLoweredIr {
    pub r1cs: ArkworksLoweredIr,
    pub ivc_state_signals: Vec<IvcStateSignal>,
    pub step_circuit_inputs: Vec<String>,
    pub step_circuit_outputs: Vec<String>,
}

pub struct NovaLowering;

impl ZirLowering for NovaLowering {
    type LoweredIr = NovaLoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::Nova
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<NovaLoweredIr> {
        // Start with R1CS lowering (Nova uses relaxed R1CS).
        let r1cs = ArkworksLowering.lower(program)?;

        // Identify IVC state signals by naming convention or metadata.
        let mut ivc_state_signals = Vec::new();
        let mut step_inputs = Vec::new();
        let mut step_outputs = Vec::new();

        for signal in &program.signals {
            let is_step_input = signal.name.starts_with("step_in_")
                || signal.name.starts_with("state_in_")
                || program
                    .metadata
                    .get("ivc_inputs")
                    .is_some_and(|v| v.split(',').any(|s| s.trim() == signal.name));

            let is_step_output = signal.name.starts_with("step_out_")
                || signal.name.starts_with("state_out_")
                || program
                    .metadata
                    .get("ivc_outputs")
                    .is_some_and(|v| v.split(',').any(|s| s.trim() == signal.name));

            if is_step_input || is_step_output {
                ivc_state_signals.push(IvcStateSignal {
                    name: signal.name.clone(),
                    step_input: is_step_input,
                    step_output: is_step_output,
                });
                if is_step_input {
                    step_inputs.push(signal.name.clone());
                }
                if is_step_output {
                    step_outputs.push(signal.name.clone());
                }
            }
        }

        Ok(NovaLoweredIr {
            r1cs,
            ivc_state_signals,
            step_circuit_inputs: step_inputs,
            step_circuit_outputs: step_outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zkf_core::{FieldElement, FieldId};

    #[test]
    fn identifies_ivc_state_signals() {
        let program = zir::Program {
            name: "nova_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "step_in_counter".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "step_out_counter".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "witness".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir::Constraint::Equal {
                lhs: zir::Expr::Signal("step_out_counter".to_string()),
                rhs: zir::Expr::Add(vec![
                    zir::Expr::Signal("step_in_counter".to_string()),
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

        let lowered = NovaLowering.lower(&program).unwrap();
        assert_eq!(lowered.ivc_state_signals.len(), 2);
        assert_eq!(lowered.step_circuit_inputs, vec!["step_in_counter"]);
        assert_eq!(lowered.step_circuit_outputs, vec!["step_out_counter"]);
    }
}
