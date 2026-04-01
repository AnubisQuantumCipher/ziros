use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessPlan, optimize_program,
};

fn demo_program() -> Program {
    Program {
        name: "opt_demo".to_string(),
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
                name: "dead".to_string(),
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
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::Add(vec![
                    Expr::signal("x"),
                    Expr::signal("y"),
                    Expr::Const(FieldElement::from_i64(0)),
                ]),
                label: Some("sum".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::Add(vec![
                    Expr::signal("x"),
                    Expr::signal("y"),
                    Expr::Const(FieldElement::from_i64(0)),
                ]),
                label: Some("sum-duplicate".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("x"),
                rhs: Expr::signal("x"),
                label: Some("tautology".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn optimizer_deduplicates_and_eliminates_dead_private_signal() {
    let (optimized, report) = optimize_program(&demo_program());
    assert_eq!(optimized.constraints.len(), 1);
    assert_eq!(report.removed_tautology_constraints, 1);
    assert_eq!(report.deduplicated_constraints, 1);
    assert_eq!(report.removed_private_signals, 1);
    assert!(!optimized.signals.iter().any(|s| s.name == "dead"));
}

#[test]
fn optimizer_folds_constant_subexpressions() {
    let program = Program {
        name: "fold_constants".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "out".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("out"),
            rhs: Expr::Add(vec![
                Expr::Const(FieldElement::from_i64(2)),
                Expr::Const(FieldElement::from_i64(3)),
                Expr::Const(FieldElement::from_i64(4)),
            ]),
            label: Some("const_sum".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };
    let (optimized, report) = optimize_program(&program);
    assert!(report.folded_expr_nodes > 0);
    let Constraint::Equal { rhs, .. } = &optimized.constraints[0] else {
        panic!("expected equal constraint");
    };
    assert_eq!(rhs, &Expr::Const(FieldElement::from_i64(9)));
}
