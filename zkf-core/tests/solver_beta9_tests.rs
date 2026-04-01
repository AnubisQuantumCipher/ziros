#![cfg(feature = "acvm-solver-beta9")]

use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessPlan,
    solve_and_validate_witness, solver_by_name,
};

fn linear_program() -> Program {
    Program {
        name: "beta9_linear".to_string(),
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
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("sum"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("sum".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn division_program() -> Program {
    Program {
        name: "beta9_div".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "a".to_string(),
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
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("q"),
            rhs: Expr::Div(Box::new(Expr::signal("a")), Box::new(Expr::signal("b"))),
            label: Some("q".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn poseidon_program() -> Program {
    Program {
        name: "beta9_poseidon".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "in_0".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_1".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_2".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_3".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_0".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_1".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_2".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_3".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Poseidon,
            inputs: vec![
                Expr::signal("in_0"),
                Expr::signal("in_1"),
                Expr::signal("in_2"),
                Expr::signal("in_3"),
            ],
            outputs: vec![
                "out_0".to_string(),
                "out_1".to_string(),
                "out_2".to_string(),
                "out_3".to_string(),
            ],
            params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
            label: Some("poseidon".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

#[test]
fn beta9_solver_solves_linear_program() {
    let solver = solver_by_name("acvm-beta9").expect("beta9 solver should be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(5));
    inputs.insert("y".to_string(), FieldElement::from_i64(8));
    let witness =
        solve_and_validate_witness(&linear_program(), &inputs, solver.as_ref()).expect("solve");
    assert_eq!(witness.values["sum"], FieldElement::new("13"));
}

#[test]
fn beta9_solver_solves_division_program() {
    let solver = solver_by_name("acvm-beta9").expect("beta9 solver should be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("a".to_string(), FieldElement::from_i64(28));
    inputs.insert("b".to_string(), FieldElement::from_i64(7));
    let witness =
        solve_and_validate_witness(&division_program(), &inputs, solver.as_ref()).expect("solve");
    assert_eq!(witness.values["q"], FieldElement::new("4"));
}

#[test]
fn beta9_solver_rejects_non_bn254() {
    let mut program = linear_program();
    program.field = FieldId::Goldilocks;
    let solver = solver_by_name("acvm-beta9").expect("beta9 solver should be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(1));
    inputs.insert("y".to_string(), FieldElement::from_i64(2));
    let err =
        solve_and_validate_witness(&program, &inputs, solver.as_ref()).expect_err("must fail");
    assert!(
        err.to_string().contains("BN254"),
        "unexpected error message: {err}"
    );
}

#[test]
fn beta9_solver_solves_poseidon_blackbox_constraint() {
    let solver = solver_by_name("acvm-beta9").expect("beta9 solver should be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("in_0".to_string(), FieldElement::from_i64(3));
    inputs.insert("in_1".to_string(), FieldElement::from_i64(9));
    inputs.insert("in_2".to_string(), FieldElement::from_i64(1));
    inputs.insert("in_3".to_string(), FieldElement::from_i64(2));

    let witness =
        solve_and_validate_witness(&poseidon_program(), &inputs, solver.as_ref()).expect("solve");
    for output in ["out_0", "out_1", "out_2", "out_3"] {
        assert!(
            witness.values.contains_key(output),
            "solver must populate output witness {output}"
        );
    }
}
