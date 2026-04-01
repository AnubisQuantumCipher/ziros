#![cfg(feature = "native-nova")]

use std::sync::{Mutex, OnceLock};

use zkf_backends::{backend_for, try_fold_native, try_verify_fold_native};
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact, Signal,
    Visibility, Witness, generate_witness,
};
use zkf_examples::{mul_add_inputs, mul_add_program};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_test_lock<T>(f: impl FnOnce() -> T) -> T {
    let lock = TEST_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f()
}

fn simple_add_program() -> Program {
    let mut program = Program {
        name: "fold_test_add".to_string(),
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
                name: "y_anchor".to_string(),
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
                lhs: Expr::Signal("out".to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Signal("y".to_string()),
                ]),
                label: Some("out_eq_sum".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("y_anchor"),
                rhs: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
                label: Some("y_anchor".to_string()),
            },
        ],
        ..Default::default()
    };
    program
        .metadata
        .insert("nova_ivc_in".to_string(), "x".to_string());
    program
        .metadata
        .insert("nova_ivc_out".to_string(), "out".to_string());
    program
}

fn simple_add_witness(x: i64, y: i64) -> Witness {
    let mut values = std::collections::BTreeMap::new();
    values.insert("x".to_string(), FieldElement::from_i64(x));
    values.insert("y".to_string(), FieldElement::from_i64(y));
    values.insert("y_anchor".to_string(), FieldElement::from_i64(y * y));
    values.insert("out".to_string(), FieldElement::from_i64(x + y));
    Witness { values }
}

fn altered_program() -> Program {
    let mut program = simple_add_program();
    program.constraints.push(Constraint::Equal {
        lhs: Expr::signal("out"),
        rhs: Expr::signal("out"),
        label: Some("shape_guard".to_string()),
    });
    program
}

fn tamper_artifact(artifact: &mut ProofArtifact) {
    if let Some(byte) = artifact.proof.first_mut() {
        *byte ^= 0x01;
        return;
    }
    if let Some(byte) = artifact.verification_key.first_mut() {
        *byte ^= 0x01;
        return;
    }
    panic!("artifact must contain proof bytes or a verification key");
}

#[test]
fn compressed_nova_fold_roundtrip_rejects_tampering() {
    with_test_lock(|| {
        let program = simple_add_program();
        let backend = backend_for(BackendKind::Nova);
        let compiled = backend.compile(&program).expect("compile should succeed");
        let witnesses = vec![
            simple_add_witness(1, 2),
            simple_add_witness(3, 4),
            simple_add_witness(7, 6),
        ];

        let folded = try_fold_native(&compiled, &witnesses, true)
            .expect("native Nova fold should be available")
            .expect("compressed fold should succeed");
        assert!(folded.compressed, "expected compressed Nova fold");
        assert!(
            try_verify_fold_native(&compiled, &folded.artifact)
                .expect("native Nova folded verification should be available")
                .expect("folded proof verification should execute"),
            "compressed folded proof must verify"
        );

        let mut tampered = folded.artifact.clone();
        tamper_artifact(&mut tampered);
        match try_verify_fold_native(&compiled, &tampered)
            .expect("native Nova folded verification should be available")
        {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("tampered folded Nova artifact unexpectedly verified"),
        }
    });
}

#[test]
fn compressed_nova_fold_rejects_mismatched_compiled_program() {
    with_test_lock(|| {
        let program = simple_add_program();
        let backend = backend_for(BackendKind::Nova);
        let compiled = backend.compile(&program).expect("compile should succeed");
        let witnesses = vec![simple_add_witness(2, 3), simple_add_witness(5, 5)];
        let folded = try_fold_native(&compiled, &witnesses, true)
            .expect("native Nova fold should be available")
            .expect("compressed fold should succeed");

        let mismatched = backend
            .compile(&altered_program())
            .expect("mismatched compile should still succeed");
        match try_verify_fold_native(&mismatched, &folded.artifact)
            .expect("native Nova folded verification should be available")
        {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("folded Nova artifact verified against the wrong compiled circuit"),
        }
    });
}

#[test]
fn hypernova_roundtrip_rejects_tampering() {
    with_test_lock(|| {
        let program = mul_add_program();
        let backend = backend_for(BackendKind::HyperNova);
        let compiled = backend.compile(&program).expect("compile should succeed");
        let witness =
            generate_witness(&program, &mul_add_inputs(7, 9)).expect("witness should build");
        let artifact = backend
            .prove(&compiled, &witness)
            .expect("HyperNova prove should succeed");

        assert_eq!(
            compiled.metadata.get("mode").map(String::as_str),
            Some("native")
        );
        assert!(
            backend
                .verify(&compiled, &artifact)
                .expect("HyperNova verification should execute"),
            "native HyperNova artifact must verify"
        );

        let mut tampered = artifact.clone();
        tamper_artifact(&mut tampered);
        match backend.verify(&compiled, &tampered) {
            Ok(false) | Err(_) => {}
            Ok(true) => panic!("tampered HyperNova artifact unexpectedly verified"),
        }
    });
}
