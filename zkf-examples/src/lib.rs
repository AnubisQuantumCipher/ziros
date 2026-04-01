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

use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessInputs, WitnessPlan,
};
use zkf_lib::{
    PRIVATE_POWERED_DESCENT_DEFAULT_STEPS, TemplateProgram, ZkfError,
    private_nbody_orbital_sample_inputs, private_nbody_orbital_showcase,
    private_nbody_orbital_showcase_with_steps, private_nbody_orbital_witness,
    private_nbody_orbital_witness_with_steps, private_powered_descent_sample_inputs,
    private_powered_descent_showcase, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness, private_powered_descent_witness_with_steps,
    private_satellite_conjunction_sample_inputs, private_satellite_conjunction_showcase,
    private_satellite_conjunction_witness,
};

pub fn mul_add_program() -> Program {
    mul_add_program_with_field(FieldId::Bn254)
}

pub fn mul_add_program_with_field(field: FieldId) -> Program {
    Program {
        name: "mul_add".to_string(),
        field,
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
                name: "sum".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "product".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum_constraint".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("product"),
                rhs: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("x"))),
                label: Some("product_constraint".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "sum".to_string(),
                    expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                },
                WitnessAssignment {
                    target: "product".to_string(),
                    expr: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("x"))),
                },
            ],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn mul_add_inputs(x: i64, y: i64) -> WitnessInputs {
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(x));
    inputs.insert("y".to_string(), FieldElement::from_i64(y));
    inputs
}

pub fn recurrence_program(field: FieldId, steps: usize) -> Program {
    let mut signals = vec![
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
    ];

    let mut constraints = Vec::with_capacity(1 + steps.saturating_mul(2));
    let mut assignments = Vec::with_capacity(1 + steps.saturating_mul(2));

    signals.push(Signal {
        name: "acc_0".to_string(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    });
    constraints.push(Constraint::Equal {
        lhs: Expr::signal("acc_0"),
        rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
        label: Some("acc_init".to_string()),
    });
    assignments.push(WitnessAssignment {
        target: "acc_0".to_string(),
        expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
    });

    for i in 0..steps {
        let mul_name = format!("mul_{i}");
        let acc_curr = format!("acc_{i}");
        let acc_next = format!("acc_{}", i + 1);

        signals.push(Signal {
            name: mul_name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        signals.push(Signal {
            name: acc_next.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });

        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&mul_name),
            rhs: Expr::Mul(
                Box::new(Expr::signal(&acc_curr)),
                Box::new(Expr::signal("x")),
            ),
            label: Some(format!("mul_step_{i}")),
        });
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&acc_next),
            rhs: Expr::Add(vec![Expr::signal(&mul_name), Expr::signal("y")]),
            label: Some(format!("acc_step_{i}")),
        });

        assignments.push(WitnessAssignment {
            target: mul_name.clone(),
            expr: Expr::Mul(
                Box::new(Expr::signal(&acc_curr)),
                Box::new(Expr::signal("x")),
            ),
        });
        assignments.push(WitnessAssignment {
            target: acc_next.clone(),
            expr: Expr::Add(vec![Expr::signal(&mul_name), Expr::signal("y")]),
        });
    }

    if let Some(last_acc) = signals
        .iter_mut()
        .find(|signal| signal.name == format!("acc_{steps}"))
    {
        last_acc.visibility = Visibility::Public;
    }

    Program {
        name: format!("recurrence_{steps}"),
        field,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn mul_add_program_json() -> String {
    serde_json::to_string_pretty(&mul_add_program()).expect("program serialization must succeed")
}

pub fn private_nbody_orbital_showcase_template() -> Result<TemplateProgram, ZkfError> {
    private_nbody_orbital_showcase()
}

pub fn private_nbody_orbital_showcase_template_with_steps(
    steps: usize,
) -> Result<TemplateProgram, ZkfError> {
    private_nbody_orbital_showcase_with_steps(steps)
}

pub fn private_nbody_orbital_showcase_sample_inputs() -> WitnessInputs {
    private_nbody_orbital_sample_inputs()
}

pub fn private_nbody_orbital_showcase_witness(
    inputs: &WitnessInputs,
) -> Result<zkf_core::Witness, ZkfError> {
    private_nbody_orbital_witness(inputs)
}

pub fn private_nbody_orbital_showcase_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> Result<zkf_core::Witness, ZkfError> {
    private_nbody_orbital_witness_with_steps(inputs, steps)
}

pub fn private_powered_descent_showcase_template() -> Result<TemplateProgram, ZkfError> {
    private_powered_descent_showcase()
}

pub fn private_powered_descent_showcase_template_with_steps(
    steps: usize,
) -> Result<TemplateProgram, ZkfError> {
    private_powered_descent_showcase_with_steps(steps)
}

pub fn private_powered_descent_showcase_default_steps() -> usize {
    PRIVATE_POWERED_DESCENT_DEFAULT_STEPS
}

pub fn private_powered_descent_showcase_sample_inputs() -> WitnessInputs {
    private_powered_descent_sample_inputs()
}

pub fn private_powered_descent_showcase_witness(
    inputs: &WitnessInputs,
) -> Result<zkf_core::Witness, ZkfError> {
    private_powered_descent_witness(inputs)
}

pub fn private_powered_descent_showcase_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> Result<zkf_core::Witness, ZkfError> {
    private_powered_descent_witness_with_steps(inputs, steps)
}

pub fn private_satellite_conjunction_showcase_template() -> Result<TemplateProgram, ZkfError> {
    private_satellite_conjunction_showcase()
}

pub fn private_satellite_conjunction_showcase_sample_inputs() -> WitnessInputs {
    private_satellite_conjunction_sample_inputs()
}

pub fn private_satellite_conjunction_showcase_witness(
    inputs: &WitnessInputs,
) -> Result<zkf_core::Witness, ZkfError> {
    private_satellite_conjunction_witness(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{FieldElement, Visibility, generate_witness};

    #[test]
    fn mul_add_program_json_roundtrips() {
        let program: Program = serde_json::from_str(&mul_add_program_json()).expect("program json");
        assert_eq!(program.name, "mul_add");
        assert_eq!(program.field, FieldId::Bn254);
        assert_eq!(program.constraints.len(), 2);
    }

    #[test]
    fn recurrence_program_exposes_final_accumulator_publicly() {
        let program = recurrence_program(FieldId::Goldilocks, 3);
        let final_signal = program
            .signals
            .iter()
            .find(|signal| signal.name == "acc_3")
            .expect("final accumulator");
        assert_eq!(final_signal.visibility, Visibility::Public);
    }

    #[test]
    fn mul_add_inputs_drive_expected_product() {
        let program = mul_add_program();
        let witness = generate_witness(&program, &mul_add_inputs(3, 5)).expect("witness");
        assert_eq!(
            witness
                .values
                .get("product")
                .cloned()
                .expect("product output"),
            FieldElement::from_i64(24)
        );
    }
}
