use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessInputs, WitnessPlan, generate_witness,
};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_test_lock<T>(f: impl FnOnce() -> T) -> T {
    let lock = TEST_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f()
}

fn simple_mul_add_program() -> (Program, WitnessInputs) {
    let program = Program {
        name: "hypernova_mul_add".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            signal("x", Visibility::Private),
            signal("y", Visibility::Private),
            signal("sum", Visibility::Private),
            signal("y_square", Visibility::Private),
            signal("product", Visibility::Public),
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("y_square"),
                rhs: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
                label: Some("y_square".to_string()),
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
                WitnessAssignment {
                    target: "y_square".to_string(),
                    expr: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
                },
            ],
            ..WitnessPlan::default()
        },
        ..Program::default()
    };
    let inputs = BTreeMap::from([
        ("x".to_string(), FieldElement::from_i64(7)),
        ("y".to_string(), FieldElement::from_i64(5)),
    ]);
    (program, inputs)
}

fn fanout_sum_program(width: usize) -> (Program, WitnessInputs) {
    let mut signals = Vec::new();
    let mut constraints = Vec::new();
    let mut assignments = Vec::new();
    let mut inputs = BTreeMap::new();

    for index in 0..width {
        let name = format!("in_{index}");
        signals.push(signal(&name, Visibility::Private));
        let square = format!("{name}_square");
        signals.push(signal(&square, Visibility::Private));
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&square),
            rhs: Expr::Mul(Box::new(Expr::signal(&name)), Box::new(Expr::signal(&name))),
            label: Some(format!("input_square_{index}")),
        });
        assignments.push(WitnessAssignment {
            target: square,
            expr: Expr::Mul(Box::new(Expr::signal(&name)), Box::new(Expr::signal(&name))),
        });
        inputs.insert(name, FieldElement::from_i64((index as i64) + 2));
    }

    let mut current = "in_0".to_string();
    for index in 1..width {
        let next = format!("sum_{index}");
        let rhs = Expr::Add(vec![
            Expr::signal(&current),
            Expr::signal(format!("in_{index}")),
        ]);
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&next),
            rhs: rhs.clone(),
            label: Some(format!("fanout_sum_{index}")),
        });
        assignments.push(WitnessAssignment {
            target: next.clone(),
            expr: rhs,
        });
        signals.push(signal(
            &next,
            if index + 1 == width {
                Visibility::Public
            } else {
                Visibility::Private
            },
        ));
        if index + 1 != width {
            let square = format!("{next}_square");
            signals.push(signal(&square, Visibility::Private));
            constraints.push(Constraint::Equal {
                lhs: Expr::signal(&square),
                rhs: Expr::Mul(Box::new(Expr::signal(&next)), Box::new(Expr::signal(&next))),
                label: Some(format!("fanout_sum_square_{index}")),
            });
            assignments.push(WitnessAssignment {
                target: square,
                expr: Expr::Mul(Box::new(Expr::signal(&next)), Box::new(Expr::signal(&next))),
            });
        }
        current = next;
    }

    let program = Program {
        name: format!("hypernova_fanout_sum_{width}"),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            ..WitnessPlan::default()
        },
        ..Program::default()
    };
    (program, inputs)
}

fn recurrence_program(steps: usize) -> (Program, WitnessInputs) {
    let mut signals = vec![
        signal("x", Visibility::Private),
        signal("y", Visibility::Private),
        signal("y_square", Visibility::Private),
        signal("acc_0", Visibility::Private),
    ];
    let mut constraints = vec![
        Constraint::Equal {
            lhs: Expr::signal("y_square"),
            rhs: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
            label: Some("y_square".to_string()),
        },
        Constraint::Equal {
            lhs: Expr::signal("acc_0"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("acc_init".to_string()),
        },
    ];
    let mut assignments = vec![
        WitnessAssignment {
            target: "y_square".to_string(),
            expr: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
        },
        WitnessAssignment {
            target: "acc_0".to_string(),
            expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
        },
    ];

    for step in 0..steps {
        let mul = format!("mul_{step}");
        let acc_current = format!("acc_{step}");
        let acc_next = format!("acc_{}", step + 1);
        signals.push(signal(&mul, Visibility::Private));
        signals.push(signal(
            &acc_next,
            if step + 1 == steps {
                Visibility::Public
            } else {
                Visibility::Private
            },
        ));

        let mul_expr = Expr::Mul(
            Box::new(Expr::signal(&acc_current)),
            Box::new(Expr::signal("x")),
        );
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&mul),
            rhs: mul_expr.clone(),
            label: Some(format!("mul_step_{step}")),
        });
        assignments.push(WitnessAssignment {
            target: mul.clone(),
            expr: mul_expr,
        });

        let acc_expr = Expr::Add(vec![Expr::signal(&mul), Expr::signal("y")]);
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&acc_next),
            rhs: acc_expr.clone(),
            label: Some(format!("acc_step_{step}")),
        });
        assignments.push(WitnessAssignment {
            target: acc_next,
            expr: acc_expr,
        });
    }

    let program = Program {
        name: format!("hypernova_recurrence_{steps}"),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            ..WitnessPlan::default()
        },
        ..Program::default()
    };
    let inputs = BTreeMap::from([
        ("x".to_string(), FieldElement::from_i64(3)),
        ("y".to_string(), FieldElement::from_i64(4)),
    ]);
    (program, inputs)
}

fn signal(name: &str, visibility: Visibility) -> Signal {
    Signal {
        name: name.to_string(),
        visibility,
        constant: None,
        ty: None,
    }
}

fn run_roundtrip(program: Program, inputs: WitnessInputs) {
    let backend = backend_for(BackendKind::HyperNova);
    let compiled = backend
        .compile(&program)
        .expect("HyperNova compile should succeed");
    assert!(
        matches!(
            compiled.metadata.get("mode").map(String::as_str),
            Some("native") | Some("compatibility-delegate")
        ),
        "HyperNova integration tests require a recorded execution mode"
    );

    let witness = generate_witness(&program, &inputs).expect("witness should generate");
    let artifact = backend
        .prove(&compiled, &witness)
        .expect("HyperNova prove should succeed");
    assert!(
        backend
            .verify(&compiled, &artifact)
            .expect("HyperNova verification should run"),
        "HyperNova proof must verify"
    );
}

#[test]
fn hypernova_roundtrips_across_multiple_circuit_shapes() {
    with_test_lock(|| {
        for (program, inputs) in [
            simple_mul_add_program(),
            fanout_sum_program(8),
            recurrence_program(10),
        ] {
            run_roundtrip(program, inputs);
        }
    });
}

#[test]
fn hypernova_detects_tampered_integration_artifact() {
    with_test_lock(|| {
        let (program, inputs) = recurrence_program(6);
        let backend = backend_for(BackendKind::HyperNova);
        let compiled = backend.compile(&program).expect("compile should succeed");
        let witness = generate_witness(&program, &inputs).expect("witness should generate");
        let mut artifact = backend
            .prove(&compiled, &witness)
            .expect("prove should succeed");
        assert!(
            backend
                .verify(&compiled, &artifact)
                .expect("verification should run")
        );

        if let Some(byte) = artifact.proof.first_mut() {
            *byte ^= 0x01;
        } else if let Some(byte) = artifact.verification_key.first_mut() {
            *byte ^= 0x01;
        } else {
            panic!("artifact should contain proof material");
        }

        match backend.verify(&compiled, &artifact) {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("tampered HyperNova integration artifact unexpectedly verified"),
        }
    });
}
