use super::*;

#[test]
fn zir_preflight_accepts_backend_with_lookup_lowering_support() {
    let zir_program = zkf_core::zir_v1::Program {
        name: "zir_lookup".to_string(),
        field: FieldId::Bn254,
        signals: vec![zkf_core::zir_v1::Signal {
            name: "x".to_string(),
            visibility: zkf_core::Visibility::Private,
            ty: zkf_core::zir_v1::SignalType::Field,
            constant: None,
        }],
        constraints: vec![zkf_core::zir_v1::Constraint::Lookup {
            inputs: vec![zkf_core::zir_v1::Expr::Signal("x".to_string())],
            table: "small_table".to_string(),
            label: Some("lk".to_string()),
        }],
        witness_plan: zkf_core::zir_v1::WitnessPlan::default(),
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata: BTreeMap::new(),
    };

    ensure_backend_supports_zir_constraints(BackendKind::ArkworksGroth16, &zir_program)
        .expect("arkworks lookup lowering should satisfy ZIR lookup preflight");
}

#[test]
fn zir_preflight_rejects_bn254_only_blackbox_outside_bn254() {
    for (op, name) in [
        (zkf_core::zir_v1::BlackBoxOp::Poseidon, "poseidon"),
        (zkf_core::zir_v1::BlackBoxOp::Pedersen, "pedersen"),
        (
            zkf_core::zir_v1::BlackBoxOp::SchnorrVerify,
            "schnorr_verify",
        ),
    ] {
        let zir_program = zkf_core::zir_v1::Program {
            name: format!("zir_bb_{name}"),
            field: FieldId::Goldilocks,
            signals: vec![
                zkf_core::zir_v1::Signal {
                    name: "in".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zkf_core::zir_v1::SignalType::Field,
                    constant: None,
                },
                zkf_core::zir_v1::Signal {
                    name: "out".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zkf_core::zir_v1::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zkf_core::zir_v1::Constraint::BlackBox {
                op,
                inputs: vec![zkf_core::zir_v1::Expr::Signal("in".to_string())],
                outputs: vec!["out".to_string()],
                params: BTreeMap::new(),
                label: Some(name.to_string()),
            }],
            witness_plan: zkf_core::zir_v1::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let err = ensure_backend_supports_zir_constraints(BackendKind::Plonky3, &zir_program)
            .expect_err("bn254-only blackbox should fail for non-bn254 zir program");
        assert!(
            err.contains("bn254"),
            "expected bn254 guard for {name} in zir preflight, got: {err}",
        );
    }
}

#[test]
fn run_package_accepts_zir_program_manifest() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-zir-manifest-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");

    let zir_program = zkf_core::zir_v1::Program {
        name: "zir_demo".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::zir_v1::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zkf_core::zir_v1::SignalType::Field,
                constant: None,
            },
            zkf_core::zir_v1::Signal {
                name: "y".to_string(),
                visibility: zkf_core::Visibility::Public,
                ty: zkf_core::zir_v1::SignalType::Field,
                constant: None,
            },
        ],
        constraints: vec![zkf_core::zir_v1::Constraint::Equal {
            lhs: zkf_core::zir_v1::Expr::Signal("y".to_string()),
            rhs: zkf_core::zir_v1::Expr::Add(vec![
                zkf_core::zir_v1::Expr::Signal("x".to_string()),
                zkf_core::zir_v1::Expr::Const(FieldElement::from_i64(1)),
            ]),
            label: Some("eq".to_string()),
        }],
        witness_plan: zkf_core::zir_v1::WitnessPlan {
            assignments: vec![zkf_core::zir_v1::WitnessAssignment {
                target: "y".to_string(),
                expr: zkf_core::zir_v1::Expr::Add(vec![
                    zkf_core::zir_v1::Expr::Signal("x".to_string()),
                    zkf_core::zir_v1::Expr::Const(FieldElement::from_i64(1)),
                ]),
            }],
            hints: Vec::new(),
            acir_program_bytes: None,
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata: BTreeMap::new(),
    };
    let program_sha =
        write_json_and_hash(&root.join("ir/program.json"), &zir_program).expect("program");
    let original_sha = write_json_and_hash(
        &root.join("frontends/noir/original.json"),
        &serde_json::json!({}),
    )
    .expect("original");

    let manifest_json = serde_json::json!({
        "schema_version": 2,
        "package_name": "zir_demo",
        "program_digest": zir_program.digest_hex(),
        "field": "bn254",
        "frontend": { "kind": "noir" },
        "backend_targets": [],
        "files": {
            "program": { "path": "ir/program.json", "sha256": program_sha },
            "original_artifact": { "path": "frontends/noir/original.json", "sha256": original_sha },
            "compiled": {},
            "proofs": {}
        },
        "runs": {},
        "metadata": {
            "ir_family": "zir-v1",
            "ir_version": "1",
            "strict_mode": "true",
            "requires_execution": "false",
            "requires_solver": "false",
            "allow_builtin_fallback": "false"
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");

    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "7" })).expect("inputs");

    let report = run_package(&manifest_path, &inputs_path, "main", None).expect("run");
    let witness: Witness = read_json(Path::new(&report.witness_path)).expect("witness");
    assert_eq!(
        witness.values.get("y").expect("y output"),
        &FieldElement::new("8")
    );
    let run_report: Value = read_json(Path::new(&report.run_report_path)).expect("run report read");
    assert!(
        run_report
            .get("solver_path")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "solver_path must be present in run report"
    );
    assert!(
        run_report
            .get("execution_path")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "execution_path must be present in run report"
    );

    let _ = fs::remove_dir_all(&root);
}
