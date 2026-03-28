use super::*;

fn nonlinear_square_program(field: FieldId, name: &str) -> Program {
    Program {
        name: name.to_string(),
        field,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: zkf_core::Expr::signal("out"),
            rhs: zkf_core::Expr::Mul(
                Box::new(zkf_core::Expr::signal("x")),
                Box::new(zkf_core::Expr::signal("x")),
            ),
            label: Some("out_eq_square".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "out".to_string(),
                expr: zkf_core::Expr::Mul(
                    Box::new(zkf_core::Expr::signal("x")),
                    Box::new(zkf_core::Expr::signal("x")),
                ),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn linear_underconstrained_program() -> Program {
    Program {
        name: "underconstrained_linear".to_string(),
        field: FieldId::Goldilocks,
        signals: vec![
            zkf_core::Signal {
                name: "lead_gap".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "allowed_gap".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "ok".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: zkf_core::Expr::signal("ok"),
            rhs: zkf_core::Expr::Sub(
                Box::new(zkf_core::Expr::signal("allowed_gap")),
                Box::new(zkf_core::Expr::signal("lead_gap")),
            ),
            label: Some("ok_eq_allowed_minus_gap".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    }
}

fn manual_multiply_program() -> Program {
    Program {
        name: "manual_multiply".to_string(),
        field: FieldId::Goldilocks,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "y".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: zkf_core::Expr::signal("out"),
            rhs: zkf_core::Expr::Mul(
                Box::new(zkf_core::Expr::signal("x")),
                Box::new(zkf_core::Expr::signal("y")),
            ),
            label: Some("out_eq_xy".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    }
}

fn ranged_identity_program() -> Program {
    Program {
        name: "range_identity".to_string(),
        field: FieldId::Goldilocks,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Range {
                signal: "x".to_string(),
                bits: 8,
                label: Some("x_in_u8".to_string()),
            },
            Constraint::Equal {
                lhs: zkf_core::Expr::signal("out"),
                rhs: zkf_core::Expr::signal("x"),
                label: Some("out_eq_x".to_string()),
            },
        ],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    }
}

#[test]
fn cli_audit_rejects_linear_underconstraint_with_plain_english_guidance() {
    let root = tempfile::tempdir().expect("tempdir");
    let program_path = root.path().join("underconstrained.json");
    let report_path = root.path().join("audit.json");
    write_json(&program_path, &linear_underconstrained_program()).expect("program");

    let err = cmd::audit::handle_audit(program_path, None, Some(report_path.clone()), false)
        .expect_err("audit should fail");
    assert!(err.contains("audit failed"));

    let report: zkf_core::AuditReport = read_json(&report_path).expect("report");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.message.contains("linearly underdetermined"))
        .expect("underconstrained finding");
    assert!(
        finding
            .suggestion
            .as_deref()
            .unwrap_or_default()
            .contains("docs/NONLINEAR_ANCHORING.md")
    );
}

#[test]
fn cli_prove_rejects_invalid_witness_values() {
    let root = tempfile::tempdir().expect("tempdir");
    let program_path = root.path().join("program.json");
    let inputs_path = root.path().join("inputs.json");
    let artifact_path = root.path().join("proof.json");
    write_json(&program_path, &manual_multiply_program()).expect("program");
    write_json(
        &inputs_path,
        &WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(3)),
            ("y".to_string(), FieldElement::from_i64(7)),
            ("out".to_string(), FieldElement::from_i64(22)),
        ]),
    )
    .expect("inputs");

    let err = cmd::prove::handle_prove(
        cmd::prove::ProveArgs {
            program: program_path,
            inputs: inputs_path,
            json: false,
            backend: None,
            objective: "fastest-prove".to_string(),
            mode: None,
            export: None,
            allow_attestation: false,
            out: artifact_path,
            compiled_out: None,
            solver: None,
            seed: None,
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: false,
            hybrid: false,
        },
        false,
    )
    .expect_err("invalid witness should fail");

    assert!(
        err.contains("constraint") || err.contains("witness"),
        "expected a witness/constraint failure, got: {err}"
    );
}

#[test]
fn cli_verify_rejects_tampered_proof() {
    let root = tempfile::tempdir().expect("tempdir");
    let program_path = root.path().join("program.json");
    let inputs_path = root.path().join("inputs.json");
    let artifact_path = root.path().join("proof.json");
    let compiled_path = root.path().join("compiled.json");
    write_json(
        &program_path,
        &nonlinear_square_program(FieldId::Goldilocks, "tamper-proof"),
    )
    .expect("program");
    write_json(
        &inputs_path,
        &WitnessInputs::from([("x".to_string(), FieldElement::from_i64(3))]),
    )
    .expect("inputs");

    cmd::prove::handle_prove(
        cmd::prove::ProveArgs {
            program: program_path.clone(),
            inputs: inputs_path,
            json: false,
            backend: None,
            objective: "fastest-prove".to_string(),
            mode: None,
            export: None,
            allow_attestation: false,
            out: artifact_path.clone(),
            compiled_out: Some(compiled_path.clone()),
            solver: None,
            seed: None,
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: false,
            hybrid: false,
        },
        false,
    )
    .expect("prove");

    let mut artifact: ProofArtifact = read_json(&artifact_path).expect("proof artifact");
    artifact.proof[0] ^= 0x01;
    write_json(&artifact_path, &artifact).expect("tampered proof");

    let err = cmd::prove::handle_verify(
        program_path,
        artifact_path,
        "plonky3".to_string(),
        Some(compiled_path),
        None,
        None,
        false,
        false,
        false,
    )
    .expect_err("tampered proof should fail verification");

    assert!(err.contains("verification failed"));
}

#[test]
fn cli_prove_rejects_out_of_range_inputs() {
    let root = tempfile::tempdir().expect("tempdir");
    let program_path = root.path().join("program.json");
    let inputs_path = root.path().join("inputs.json");
    let artifact_path = root.path().join("proof.json");
    write_json(&program_path, &ranged_identity_program()).expect("program");
    write_json(
        &inputs_path,
        &WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(300)),
            ("out".to_string(), FieldElement::from_i64(300)),
        ]),
    )
    .expect("inputs");

    let err = cmd::prove::handle_prove(
        cmd::prove::ProveArgs {
            program: program_path,
            inputs: inputs_path,
            json: false,
            backend: None,
            objective: "fastest-prove".to_string(),
            mode: None,
            export: None,
            allow_attestation: false,
            out: artifact_path,
            compiled_out: None,
            solver: None,
            seed: None,
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: false,
            hybrid: false,
        },
        false,
    )
    .expect_err("out-of-range input should fail");

    assert!(err.contains("range") || err.contains("constraint"));
}
