use serde_json::json;
use zkf_core::{
    Constraint, Expr, FieldId, Program, Signal, Visibility, WitnessAssignment, WitnessPlan,
};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

fn demo_program() -> Program {
    Program {
        name: "plonky3_air_export_demo".to_string(),
        field: FieldId::Goldilocks,
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("out"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("air_sum".to_string()),
        }],
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
fn plonky3_air_export_compiles_to_ir() {
    let engine = frontend_for(FrontendKind::Plonky3Air);
    let value = json!({
        "schema": "zkf-plonky3-air-export-v1",
        "program": demo_program(),
        "trace_width": 3,
        "rows": 16,
        "transition_constraints": [
            {"name": "transition_sum", "expression": "next.out - (cur.x + cur.y) = 0"}
        ],
        "boundary_constraints": [
            {"name": "boundary_out", "expression": "row0.out = 0"}
        ]
    });

    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("plonky3 AIR export compile should pass");
    assert_eq!(program.name, "plonky3_air_export_demo");
    assert_eq!(program.constraints.len(), 1);
}

#[test]
fn plonky3_air_export_rejects_unknown_schema() {
    let engine = frontend_for(FrontendKind::Plonky3Air);
    let value = json!({
        "schema": "unknown",
        "program": demo_program()
    });
    let err = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect_err("unknown schema must fail");
    let rendered = err.to_string();
    assert!(rendered.contains("unsupported plonky3 AIR export schema"));
}
