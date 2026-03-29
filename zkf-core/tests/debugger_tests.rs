use std::collections::BTreeMap;
use zkf_core::{
    Constraint, DebugOptions, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, build_witness_flow, debug_program, generate_witness,
    generate_witness_unchecked,
};

fn program_with_plan() -> Program {
    Program {
        name: "debug_mul_add".to_string(),
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

fn program_without_plan() -> Program {
    let mut program = program_with_plan();
    program.witness_plan = WitnessPlan::default();
    program
}

fn inputs(values: &[(&str, i64)]) -> BTreeMap<String, FieldElement> {
    let mut out = BTreeMap::new();
    for (name, value) in values {
        out.insert((*name).to_string(), FieldElement::from_i64(*value));
    }
    out
}

#[test]
fn debug_report_passes_with_full_trace() {
    let program = program_with_plan();
    let witness =
        generate_witness(&program, &inputs(&[("x", 3), ("y", 5)])).expect("witness should pass");
    let report = debug_program(&program, &witness, DebugOptions::default());

    assert!(report.passed);
    assert_eq!(report.total_constraints, 2);
    assert_eq!(report.evaluated_constraints, 2);
    assert!(report.first_failure_index.is_none());
    assert!(report.constraints.iter().all(|trace| trace.passed));
    assert_eq!(report.symbolic_constraints.len(), 2);
    assert!(report.symbolic_constraints[1].nonlinear);
    assert_eq!(report.symbolic_witness.len(), 4);
    assert!(
        report
            .symbolic_witness
            .iter()
            .find(|signal| signal.name == "sum")
            .is_some_and(|signal| signal.resolved)
    );
}

#[test]
fn debug_stops_on_first_failure_by_default() {
    let program = program_without_plan();
    let witness = generate_witness_unchecked(
        &program,
        &inputs(&[("x", 3), ("y", 5), ("sum", 9), ("product", 40)]),
    )
    .expect("unchecked witness should build");

    let report = debug_program(&program, &witness, DebugOptions::default());
    assert!(!report.passed);
    assert_eq!(report.first_failure_index, Some(0));
    assert_eq!(report.evaluated_constraints, 1);
}

#[test]
fn debug_can_continue_after_failures() {
    let program = program_without_plan();
    let witness = generate_witness_unchecked(
        &program,
        &inputs(&[("x", 3), ("y", 5), ("sum", 9), ("product", 40)]),
    )
    .expect("unchecked witness should build");

    let report = debug_program(
        &program,
        &witness,
        DebugOptions {
            stop_on_first_failure: false,
        },
    );
    assert!(!report.passed);
    assert_eq!(report.first_failure_index, Some(0));
    assert_eq!(report.evaluated_constraints, 2);
    assert!(!report.constraints[0].passed);
    assert!(!report.constraints[1].passed);
}

#[test]
fn underconstrained_analysis_reports_linear_nullity() {
    let program = Program {
        name: "underdetermined_linear".to_string(),
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Add(vec![Expr::signal("a"), Expr::signal("b")]),
            rhs: Expr::signal("out"),
            label: Some("linear_relation".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let witness = generate_witness_unchecked(&program, &inputs(&[("a", 3), ("b", 4), ("out", 7)]))
        .expect("unchecked witness should build");
    let report = debug_program(
        &program,
        &witness,
        DebugOptions {
            stop_on_first_failure: false,
        },
    );

    assert_eq!(report.underconstrained.linear_private_signal_count, 2);
    assert_eq!(report.underconstrained.linear_rank, 1);
    assert_eq!(report.underconstrained.linear_nullity, 1);
    assert_eq!(report.underconstrained.nonlinear_constraint_count, 0);
    assert!(
        report
            .underconstrained
            .linearly_underdetermined_private_signals
            .contains(&"b".to_string())
    );
    assert!(
        report
            .underconstrained
            .unconstrained_private_signals
            .is_empty()
    );
}

#[test]
fn witness_flow_graph_tracks_dependencies() {
    let graph = build_witness_flow(&program_with_plan());
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == "x" && edge.to == "sum")
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == "y" && edge.to == "sum")
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == "sum" && edge.to == "product")
    );
}

#[test]
fn underconstrained_analysis_reports_nonlinear_private_participation() {
    let program = Program {
        name: "nonlinear_relation".to_string(),
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Mul(Box::new(Expr::signal("a")), Box::new(Expr::signal("b"))),
            rhs: Expr::signal("out"),
            label: Some("mul_relation".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let report = debug_program(
        &program,
        &generate_witness_unchecked(&program, &inputs(&[("a", 3), ("b", 4), ("out", 12)]))
            .expect("witness"),
        DebugOptions::default(),
    );
    assert_eq!(report.underconstrained.nonlinear_constraint_count, 1);
    assert_eq!(report.underconstrained.nonlinear_private_signal_count, 2);
    assert!(
        report
            .underconstrained
            .nonlinear_private_signals
            .contains(&"a".to_string())
    );
    assert!(
        report
            .underconstrained
            .nonlinear_only_private_signals
            .contains(&"b".to_string())
    );
    assert!(
        report
            .underconstrained
            .nonlinear_private_components
            .iter()
            .any(|component| component.contains(&"a".to_string()))
    );
}

#[test]
fn underconstrained_analysis_reports_unanchored_nonlinear_components() {
    let program = Program {
        name: "nonlinear_unanchored".to_string(),
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
                name: "c".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Mul(Box::new(Expr::signal("a")), Box::new(Expr::signal("b"))),
            rhs: Expr::signal("c"),
            label: Some("mul_private_relation".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let report = debug_program(
        &program,
        &generate_witness_unchecked(&program, &inputs(&[("a", 3), ("b", 4), ("c", 12)]))
            .expect("witness"),
        DebugOptions::default(),
    );
    assert_eq!(
        report
            .underconstrained
            .nonlinear_unanchored_components
            .len(),
        1
    );
    assert!(
        report
            .underconstrained
            .nonlinear_potentially_free_private_signals
            .contains(&"a".to_string())
    );
}
