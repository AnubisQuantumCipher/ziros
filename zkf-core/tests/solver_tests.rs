use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, NoopWitnessSolver, Program, Signal, Visibility,
    Witness, WitnessPlan, WitnessSolver, ZkfError, available_solvers, solve_and_validate_witness,
    solve_witness, solver_by_name,
};

fn solver_program() -> Program {
    Program {
        name: "solver_demo".to_string(),
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

#[cfg(feature = "acvm-solver")]
fn division_program() -> Program {
    Program {
        name: "solver_div_demo".to_string(),
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
                name: "q".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("q"),
            rhs: Expr::Div(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
            label: Some("div".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn inputs() -> BTreeMap<String, FieldElement> {
    let mut out = BTreeMap::new();
    out.insert("x".to_string(), FieldElement::from_i64(4));
    out.insert("y".to_string(), FieldElement::from_i64(5));
    out
}

fn poseidon_program() -> Program {
    Program {
        name: "solver_poseidon_demo".to_string(),
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

fn sha256_program() -> Program {
    let mut signals = vec![Signal {
        name: "msg_0".to_string(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    }];
    signals.extend((0..32).map(|index| Signal {
        name: format!("digest_{index}"),
        visibility: Visibility::Public,
        constant: None,
        ty: None,
    }));

    Program {
        name: "solver_sha256_demo".to_string(),
        field: FieldId::Bn254,
        signals,
        constraints: vec![Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Sha256,
            inputs: vec![Expr::signal("msg_0")],
            outputs: (0..32).map(|index| format!("digest_{index}")).collect(),
            params: BTreeMap::from([("input_num_bits".to_string(), "8".to_string())]),
            label: Some("sha256".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

#[derive(Debug, Copy, Clone)]
struct SumSolver;

impl WitnessSolver for SumSolver {
    fn id(&self) -> &'static str {
        "sum-solver"
    }

    fn solve(&self, _program: &Program, partial: &Witness) -> zkf_core::ZkfResult<Witness> {
        let mut solved = partial.clone();
        let x = solved
            .values
            .get("x")
            .expect("x must exist")
            .to_bigint()
            .expect("x must parse");
        let y = solved
            .values
            .get("y")
            .expect("y must exist")
            .to_bigint()
            .expect("y must parse");
        solved.values.insert(
            "sum".to_string(),
            FieldElement::from_bigint_with_field(x + y, FieldId::Bn254),
        );
        Ok(solved)
    }
}

#[test]
fn noop_solver_preserves_partial_witness_with_presolved_values() {
    let witness = solve_witness(&solver_program(), &inputs(), &NoopWitnessSolver)
        .expect("partial witness build should pass");
    assert!(witness.values.contains_key("x"));
    assert!(witness.values.contains_key("y"));
    assert_eq!(witness.values["sum"], FieldElement::new("9"));
}

#[test]
fn custom_solver_can_complete_and_validate_witness() {
    let witness = solve_and_validate_witness(&solver_program(), &inputs(), &SumSolver)
        .expect("solver should complete witness");
    assert_eq!(witness.values["sum"], FieldElement::new("9"));
}

#[test]
fn unknown_solver_name_is_rejected() {
    let err = match solver_by_name("missing") {
        Ok(_) => panic!("unknown solver must fail"),
        Err(err) => err,
    };
    match err {
        ZkfError::UnsupportedBackend { backend, .. } => assert_eq!(backend, "solver:missing"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn noop_solver_is_listed() {
    assert!(available_solvers().contains(&"noop"));
}

#[cfg(not(feature = "acvm-solver"))]
#[test]
fn acvm_solver_requires_feature_flag() {
    let err = match solver_by_name("acvm") {
        Ok(_) => panic!("acvm should be feature-gated"),
        Err(err) => err,
    };
    match err {
        ZkfError::FeatureDisabled { backend } => assert_eq!(backend, "solver:acvm"),
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "acvm-solver")]
#[test]
fn acvm_solver_completes_simple_witness() {
    let solver = solver_by_name("acvm").expect("acvm solver must be available");
    let witness = solve_and_validate_witness(&solver_program(), &inputs(), solver.as_ref())
        .expect("acvm should solve simple linear constraint");
    assert_eq!(witness.values["sum"], FieldElement::new("9"));
}

#[cfg(feature = "acvm-solver")]
#[test]
fn acvm_solver_rejects_non_bn254_program() {
    let mut program = solver_program();
    program.field = FieldId::Goldilocks;
    let solver = solver_by_name("acvm").expect("acvm solver must be available");
    let err = solve_and_validate_witness(&program, &inputs(), solver.as_ref())
        .expect_err("non-bn254 program should fail");
    let rendered = err.to_string();
    assert!(rendered.contains("BN254"));
}

#[cfg(feature = "acvm-solver")]
#[test]
fn acvm_solver_solves_division_constraint() {
    let solver = solver_by_name("acvm").expect("acvm solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(21));
    inputs.insert("y".to_string(), FieldElement::from_i64(3));

    let witness = solve_and_validate_witness(&division_program(), &inputs, solver.as_ref())
        .expect("acvm should solve division via auxiliary witness lowering");
    assert_eq!(witness.values["q"], FieldElement::new("7"));
}

#[cfg(feature = "acvm-solver")]
#[test]
fn acvm_solver_solves_poseidon_blackbox_constraint() {
    let solver = solver_by_name("acvm").expect("acvm solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("in_0".to_string(), FieldElement::from_i64(3));
    inputs.insert("in_1".to_string(), FieldElement::from_i64(9));
    inputs.insert("in_2".to_string(), FieldElement::from_i64(1));
    inputs.insert("in_3".to_string(), FieldElement::from_i64(2));

    let witness = solve_and_validate_witness(&poseidon_program(), &inputs, solver.as_ref())
        .expect("acvm should solve poseidon2 permutation blackbox");
    for output in ["out_0", "out_1", "out_2", "out_3"] {
        assert!(
            witness.values.contains_key(output),
            "solver must populate output witness {output}"
        );
    }
}

#[cfg(feature = "acvm-solver")]
#[test]
fn acvm_solver_solves_sha256_blackbox_constraint() {
    let solver = solver_by_name("acvm").expect("acvm solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("msg_0".to_string(), FieldElement::from_i64(42));

    let witness = solve_and_validate_witness(&sha256_program(), &inputs, solver.as_ref())
        .expect("acvm should solve sha256 blackbox");
    for output in (0..32).map(|index| format!("digest_{index}")) {
        assert!(
            witness.values.contains_key(&output),
            "solver must populate output witness {output}"
        );
    }
}

#[cfg(feature = "acvm-solver-beta9")]
#[test]
fn acvm_beta9_solver_is_listed() {
    assert!(available_solvers().contains(&"acvm-beta9"));
}

#[cfg(feature = "acvm-solver-beta9")]
#[test]
fn acvm_beta9_solver_completes_simple_witness() {
    let solver = solver_by_name("acvm-beta9").expect("acvm-beta9 solver must be available");
    let witness = solve_and_validate_witness(&solver_program(), &inputs(), solver.as_ref())
        .expect("acvm-beta9 should solve simple linear constraint");
    assert_eq!(witness.values["sum"], FieldElement::new("9"));
}

#[cfg(feature = "acvm-solver-beta9")]
#[test]
fn acvm_beta9_solver_solves_division_constraint() {
    let solver = solver_by_name("acvm-beta9").expect("acvm-beta9 solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(21));
    inputs.insert("y".to_string(), FieldElement::from_i64(3));

    let witness = solve_and_validate_witness(&division_program(), &inputs, solver.as_ref())
        .expect("acvm-beta9 should solve division via auxiliary witness lowering");
    assert_eq!(witness.values["q"], FieldElement::new("7"));
}

#[cfg(feature = "acvm-solver-beta9")]
#[test]
fn acvm_beta9_solver_solves_poseidon_blackbox_constraint() {
    let solver = solver_by_name("acvm-beta9").expect("acvm-beta9 solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("in_0".to_string(), FieldElement::from_i64(3));
    inputs.insert("in_1".to_string(), FieldElement::from_i64(9));
    inputs.insert("in_2".to_string(), FieldElement::from_i64(1));
    inputs.insert("in_3".to_string(), FieldElement::from_i64(2));

    let witness = solve_and_validate_witness(&poseidon_program(), &inputs, solver.as_ref())
        .expect("acvm-beta9 should solve poseidon2 permutation blackbox");
    for output in ["out_0", "out_1", "out_2", "out_3"] {
        assert!(
            witness.values.contains_key(output),
            "solver must populate output witness {output}"
        );
    }
}

#[cfg(feature = "acvm-solver-beta9")]
#[test]
fn acvm_beta9_solver_rejects_sha256_blackbox_constraint() {
    let solver = solver_by_name("acvm-beta9").expect("acvm-beta9 solver must be available");
    let mut inputs = BTreeMap::new();
    inputs.insert("msg_0".to_string(), FieldElement::from_i64(42));

    let err = solve_and_validate_witness(&sha256_program(), &inputs, solver.as_ref())
        .expect_err("acvm-beta9 should reject sha256 blackbox lowering");
    assert!(
        err.to_string().contains("blackbox op 'sha256'"),
        "unexpected error: {err}"
    );
}
