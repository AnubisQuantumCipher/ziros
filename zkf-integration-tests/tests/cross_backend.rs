use std::collections::BTreeMap;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessInputs, WitnessPlan, generate_witness, zir_v1 as zir,
};

/// Helper: create a simple ZIR program (y = x + 1) for a given field.
fn simple_addition_zir(field: FieldId) -> zir::Program {
    zir::Program {
        name: "cross_backend_add".to_string(),
        field,
        signals: vec![
            zir::Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "y".to_string(),
                visibility: Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            },
        ],
        constraints: vec![zir::Constraint::Equal {
            lhs: zir::Expr::Signal("y".to_string()),
            rhs: zir::Expr::Add(vec![
                zir::Expr::Signal("x".to_string()),
                zir::Expr::Const(FieldElement::from_i64(1)),
            ]),
            label: Some("y_eq_x_plus_1".to_string()),
        }],
        witness_plan: zir::WitnessPlan {
            assignments: vec![zir::WitnessAssignment {
                target: "y".to_string(),
                expr: zir::Expr::Add(vec![
                    zir::Expr::Signal("x".to_string()),
                    zir::Expr::Const(FieldElement::from_i64(1)),
                ]),
            }],
            hints: Vec::new(),
            acir_program_bytes: None,
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata: BTreeMap::new(),
    }
}

#[test]
fn zir_program_serialization_backward_compat() {
    let program = simple_addition_zir(FieldId::Bn254);
    let json = serde_json::to_string(&program).expect("serialize");
    let restored: zir::Program = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.name, program.name);
    assert_eq!(restored.signals.len(), program.signals.len());
    assert_eq!(restored.constraints.len(), program.constraints.len());
    // New fields should default to empty when not present in JSON.
    assert!(restored.lookup_tables.is_empty());
    assert!(restored.memory_regions.is_empty());
    assert!(restored.custom_gates.is_empty());
}

#[test]
fn zir_program_digest_deterministic() {
    let p1 = simple_addition_zir(FieldId::Bn254);
    let p2 = simple_addition_zir(FieldId::Bn254);
    assert_eq!(p1.digest_hex(), p2.digest_hex());
}

#[test]
fn zir_to_v2_roundtrip_preserves_semantics() {
    let program = simple_addition_zir(FieldId::Bn254);
    let lowered = zkf_core::program_zir_to_v2(&program).expect("lower to v2");
    let lifted = zkf_core::program_v2_to_zir(&lowered);

    assert_eq!(lifted.signals.len(), program.signals.len());
    assert_eq!(lifted.constraints.len(), program.constraints.len());
}

#[test]
fn gadget_registry_lists_builtins() {
    let registry = zkf_gadgets::GadgetRegistry::with_builtins();
    let names = registry.list();
    assert!(names.contains(&"boolean"));
    assert!(names.contains(&"range"));
    assert!(names.contains(&"poseidon"));
    assert!(names.contains(&"merkle"));
    assert!(names.contains(&"sha256"));
    assert!(names.contains(&"comparison"));
}

#[test]
fn gadget_emission_produces_valid_zir() {
    let registry = zkf_gadgets::GadgetRegistry::with_builtins();
    let boolean = registry.get("boolean").unwrap();
    let inputs = vec![
        zir::Expr::Signal("a".to_string()),
        zir::Expr::Signal("b".to_string()),
    ];
    let mut params = BTreeMap::new();
    params.insert("op".to_string(), "and".to_string());

    let emission = boolean
        .emit(&inputs, &["out".to_string()], FieldId::Bn254, &params)
        .expect("emit boolean AND");

    assert!(!emission.signals.is_empty());
    assert!(!emission.constraints.is_empty());
}

// ---------------------------------------------------------------------------
// End-to-end prove/verify tests (IR v2)
// ---------------------------------------------------------------------------

/// Build a simple v2 program: y = x * x + x, over the given field.
/// With x = 3 the expected output is y = 12.
fn quadratic_program_v2(field: FieldId) -> Program {
    // y = x * x + x
    let y_expr = Expr::Add(vec![
        Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("x"))),
        Expr::signal("x"),
    ]);

    Program {
        name: "e2e_quadratic".to_string(),
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
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("y"),
            rhs: y_expr.clone(),
            label: Some("y_eq_x_sq_plus_x".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "y".to_string(),
                expr: y_expr,
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Run the full compile -> prove -> verify cycle for a given backend and field.
fn run_e2e(backend_kind: BackendKind, field: FieldId) {
    let program = quadratic_program_v2(field);

    let backend = backend_for(backend_kind);

    let compiled = backend.compile(&program).expect("compile should succeed");

    let mut inputs: WitnessInputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(3));

    let witness = generate_witness(&program, &inputs).expect("witness generation should succeed");

    // Sanity: y should be 12
    let y_val = witness.values.get("y").expect("y must be in witness");
    assert_eq!(
        *y_val,
        FieldElement::from_i64(12),
        "y should equal 12 for x=3"
    );

    let proof_artifact = backend
        .prove(&compiled, &witness)
        .expect("prove should succeed");

    let valid = backend
        .verify(&compiled, &proof_artifact)
        .expect("verify should succeed");

    assert!(
        valid,
        "proof verification must return true for {backend_kind}"
    );
}

#[test]
fn arkworks_e2e() {
    run_e2e(BackendKind::ArkworksGroth16, FieldId::Bn254);
}

#[test]
fn halo2_e2e() {
    run_e2e(BackendKind::Halo2, FieldId::PastaFp);
}

#[test]
fn plonky3_goldilocks_e2e() {
    run_e2e(BackendKind::Plonky3, FieldId::Goldilocks);
}

#[test]
fn plonky3_babybear_e2e() {
    run_e2e(BackendKind::Plonky3, FieldId::BabyBear);
}

#[test]
fn plonky3_mersenne31_e2e() {
    run_e2e(BackendKind::Plonky3, FieldId::Mersenne31);
}
