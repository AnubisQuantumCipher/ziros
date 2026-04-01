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

use rand::Rng;
use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessHint, WitnessPlan, ZkfError, generate_witness, generate_witness_unchecked,
};

fn program() -> Program {
    Program {
        name: "core_mul_add".to_string(),
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
                label: Some("sum".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("product"),
                rhs: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("x"))),
                label: Some("product".to_string()),
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

fn inputs(x: i64, y: i64) -> BTreeMap<String, FieldElement> {
    let mut map = BTreeMap::new();
    map.insert("x".to_string(), FieldElement::from_i64(x));
    map.insert("y".to_string(), FieldElement::from_i64(y));
    map
}

fn div_boolean_range_program() -> Program {
    Program {
        name: "div_boolean_range".to_string(),
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
            Signal {
                name: "b".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "q".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "z".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("q"),
                rhs: Expr::Div(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
                label: Some("div".to_string()),
            },
            Constraint::Boolean {
                signal: "b".to_string(),
                label: Some("bool_b".to_string()),
            },
            Constraint::Range {
                signal: "x".to_string(),
                bits: 8,
                label: Some("x_range".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("z"),
                rhs: Expr::Add(vec![Expr::signal("q"), Expr::signal("b")]),
                label: Some("output".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "q".to_string(),
                    expr: Expr::Div(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
                },
                WitnessAssignment {
                    target: "z".to_string(),
                    expr: Expr::Add(vec![Expr::signal("q"), Expr::signal("b")]),
                },
            ],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn div_boolean_range_inputs(x: i64, y: i64, b: i64) -> BTreeMap<String, FieldElement> {
    let mut map = BTreeMap::new();
    map.insert("x".to_string(), FieldElement::from_i64(x));
    map.insert("y".to_string(), FieldElement::from_i64(y));
    map.insert("b".to_string(), FieldElement::from_i64(b));
    map
}

#[test]
fn witness_generation_succeeds() {
    let witness = generate_witness(&program(), &inputs(3, 5)).expect("witness must build");

    assert_eq!(witness.values["sum"], FieldElement::new("8"));
    assert_eq!(witness.values["product"], FieldElement::new("24"));
}

#[test]
fn witness_generation_infers_values_from_equalities() {
    let mut program = program();
    program.witness_plan.assignments.pop();

    let witness = generate_witness(&program, &inputs(2, 3))
        .expect("equalities should infer the missing product witness");
    assert_eq!(witness.values["sum"], FieldElement::new("5"));
    assert_eq!(witness.values["product"], FieldElement::new("10"));
}

#[test]
fn randomized_completeness() {
    let mut rng = rand::thread_rng();

    for _ in 0..32 {
        let x = rng.gen_range(1..100i64);
        let y = rng.gen_range(1..100i64);

        let witness = generate_witness(&program(), &inputs(x, y)).expect("witness must build");
        let expected = (x + y) * x;
        assert_eq!(
            witness.values["product"],
            FieldElement::new(expected.to_string())
        );
    }
}

#[test]
fn witness_supports_div_boolean_and_range() {
    let witness = generate_witness(
        &div_boolean_range_program(),
        &div_boolean_range_inputs(21, 3, 1),
    )
    .expect("witness must build");
    assert_eq!(witness.values["q"], FieldElement::new("7"));
    assert_eq!(witness.values["z"], FieldElement::new("8"));
}

#[test]
fn boolean_constraint_rejects_non_binary_value() {
    let err = generate_witness(
        &div_boolean_range_program(),
        &div_boolean_range_inputs(21, 3, 2),
    )
    .expect_err("boolean constraint must fail");
    match err {
        ZkfError::BooleanConstraintViolation { signal, .. } => assert_eq!(signal, "b"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn range_constraint_rejects_out_of_range_value() {
    let err = generate_witness(
        &div_boolean_range_program(),
        &div_boolean_range_inputs(300, 3, 1),
    )
    .expect_err("range constraint must fail");
    match err {
        ZkfError::RangeConstraintViolation { signal, bits, .. } => {
            assert_eq!(signal, "x");
            assert_eq!(bits, 8);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn division_by_zero_is_rejected() {
    let err = generate_witness(
        &div_boolean_range_program(),
        &div_boolean_range_inputs(21, 0, 1),
    )
    .expect_err("division by zero must fail");
    match err {
        ZkfError::DivisionByZero => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn witness_generation_rejects_unknown_assignment_target() {
    let mut program = program();
    program.witness_plan.assignments.push(WitnessAssignment {
        target: "typo_product".to_string(),
        expr: Expr::signal("sum"),
    });

    let err = generate_witness(&program, &inputs(3, 5))
        .expect_err("unknown witness-plan assignment target must fail");
    match err {
        ZkfError::MissingWitnessValue { signal } => assert_eq!(signal, "typo_product"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn witness_generation_rejects_unknown_hint_target() {
    let mut program = program();
    program.witness_plan.hints.push(WitnessHint {
        target: "typo_product".to_string(),
        source: "sum".to_string(),
        kind: zkf_core::WitnessHintKind::Copy,
    });

    let err = generate_witness(&program, &inputs(3, 5))
        .expect_err("unknown witness-plan hint target must fail");
    match err {
        ZkfError::MissingWitnessValue { signal } => assert_eq!(signal, "typo_product"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn incomplete_witness_surfaces_range_failure_before_generic_solver_error() {
    let program = Program {
        name: "range_first".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "hidden".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Range {
            signal: "x".to_string(),
            bits: 8,
            label: Some("x_range".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let err = generate_witness_unchecked(
        &program,
        &BTreeMap::from([("x".to_string(), FieldElement::from_i64(300))]),
    )
    .expect_err("range failure should surface before generic unresolved-signal error");

    match err {
        ZkfError::RangeConstraintViolation {
            signal,
            bits,
            label,
            ..
        } => {
            assert_eq!(signal, "x");
            assert_eq!(bits, 8);
            assert_eq!(label.as_deref(), Some("x_range"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn incomplete_witness_surfaces_equality_failure_before_generic_solver_error() {
    let program = Program {
        name: "equality_first".to_string(),
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
                name: "result".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "hidden".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::Add(vec![Expr::signal("x"), Expr::constant_i64(1)]),
                rhs: Expr::signal("y"),
                label: Some("increment_matches_public".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("result"),
                rhs: Expr::signal("x"),
                label: Some("result_eq_x".to_string()),
            },
        ],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let err = generate_witness_unchecked(
        &program,
        &BTreeMap::from([
            ("x".to_string(), FieldElement::from_i64(3)),
            ("y".to_string(), FieldElement::from_i64(9)),
        ]),
    )
    .expect_err("equality failure should surface before generic unresolved-signal error");

    match err {
        ZkfError::ConstraintViolation { label, .. } => {
            assert_eq!(label.as_deref(), Some("increment_matches_public"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn unresolved_witness_error_includes_blocked_constraints_and_next_step() {
    let program = Program {
        name: "nonlinear".to_string(),
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
        ..Default::default()
    };

    let err = generate_witness_unchecked(
        &program,
        &BTreeMap::from([("y".to_string(), FieldElement::from_i64(9))]),
    )
    .expect_err("quadratic unresolved witness should still fail explicitly");

    match err {
        ZkfError::UnsupportedWitnessSolve {
            unresolved_signals,
            reason,
        } => {
            assert_eq!(unresolved_signals, vec!["x".to_string()]);
            assert!(reason.contains("blocked constraints: square"));
            assert!(reason.contains("next step: run `ziros debug"));
        }
        other => panic!("unexpected error: {other}"),
    }
}
