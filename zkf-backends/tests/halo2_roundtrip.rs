use std::collections::BTreeMap;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, generate_witness,
};

fn halo2_program() -> Program {
    Program {
        name: "halo2_extended".to_string(),
        field: FieldId::PastaFp,
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
                name: "sum".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "prod".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "quot".to_string(),
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
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("prod"),
                rhs: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("x"))),
                label: Some("prod".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("quot"),
                rhs: Expr::Div(Box::new(Expr::signal("prod")), Box::new(Expr::signal("y"))),
                label: Some("quot".to_string()),
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
                lhs: Expr::signal("out"),
                rhs: Expr::Add(vec![Expr::signal("quot"), Expr::signal("b")]),
                label: Some("out".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "sum".to_string(),
                    expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                },
                WitnessAssignment {
                    target: "prod".to_string(),
                    expr: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("x"))),
                },
                WitnessAssignment {
                    target: "quot".to_string(),
                    expr: Expr::Div(Box::new(Expr::signal("prod")), Box::new(Expr::signal("y"))),
                },
                WitnessAssignment {
                    target: "out".to_string(),
                    expr: Expr::Add(vec![Expr::signal("quot"), Expr::signal("b")]),
                },
            ],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn inputs(x: i64, y: i64, b: i64) -> BTreeMap<String, FieldElement> {
    let mut map = BTreeMap::new();
    map.insert("x".to_string(), FieldElement::from_i64(x));
    map.insert("y".to_string(), FieldElement::from_i64(y));
    map.insert("b".to_string(), FieldElement::from_i64(b));
    map
}

#[test]
fn halo2_roundtrip_extended_constraints() {
    let backend = backend_for(BackendKind::Halo2);
    let program = halo2_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    assert!(compiled.compiled_data.is_some());

    let witness = generate_witness(&program, &inputs(6, 3, 1)).expect("witness should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let verified = backend
        .verify(&compiled, &proof)
        .expect("verification should pass");

    assert!(verified);
}

#[test]
fn halo2_verification_key_fingerprint_is_stable() {
    let backend = backend_for(BackendKind::Halo2);
    let program = halo2_program();
    let compiled = backend.compile(&program).expect("compile should pass");

    let witness_a = generate_witness(&program, &inputs(6, 3, 1)).expect("witness_a should pass");
    let witness_b = generate_witness(&program, &inputs(8, 2, 0)).expect("witness_b should pass");

    let proof_a = backend
        .prove(&compiled, &witness_a)
        .expect("proof_a should pass");
    let proof_b = backend
        .prove(&compiled, &witness_b)
        .expect("proof_b should pass");

    assert_eq!(proof_a.verification_key, proof_b.verification_key);
}
