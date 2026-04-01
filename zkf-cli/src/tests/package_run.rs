use super::*;

#[test]
fn run_package_rejects_manifest_missing_required_v2_metadata() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-metadata-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");

    let program = Program {
        name: "demo".to_string(),
        field: FieldId::Bn254,
        signals: vec![zkf_core::Signal {
            name: "x".to_string(),
            visibility: zkf_core::Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    };
    let program_sha =
        write_json_and_hash(&root.join("ir/program.json"), &program).expect("program");
    let original_sha = write_json_and_hash(
        &root.join("frontends/noir/original.json"),
        &serde_json::json!({}),
    )
    .expect("original");
    let manifest_json = serde_json::json!({
        "schema_version": 2,
        "package_name": "demo",
        "program_digest": program.digest_hex(),
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
        "metadata": {}
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "1" })).expect("inputs");

    let err = run_package(&manifest_path, &inputs_path, "main", None).expect_err("run error");
    assert!(err.contains("missing required v2 metadata"));
    assert!(err.contains("requires_execution"));

    let _ = fs::remove_dir_all(&root);
}

fn runtime_test_program(field: FieldId) -> Program {
    Program {
        name: format!("runtime_test_{}", field.as_str()),
        field,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "y".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![zkf_core::Constraint::Equal {
            lhs: zkf_core::Expr::signal("y"),
            rhs: zkf_core::Expr::Add(vec![
                zkf_core::Expr::signal("x"),
                zkf_core::Expr::Const(FieldElement::from_i64(1)),
            ]),
            label: Some("y_eq_x_plus_1".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "y".to_string(),
                expr: zkf_core::Expr::Add(vec![
                    zkf_core::Expr::signal("x"),
                    zkf_core::Expr::Const(FieldElement::from_i64(1)),
                ]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn write_test_manifest_v2(
    root: &Path,
    program: &Program,
    requires_execution: bool,
    requires_solver: bool,
    allow_builtin_fallback: bool,
) -> PathBuf {
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");
    let program_sha = write_json_and_hash(&root.join("ir/program.json"), program).expect("program");
    let original_sha = write_json_and_hash(
        &root.join("frontends/noir/original.json"),
        &serde_json::json!({}),
    )
    .expect("original");
    let manifest_json = serde_json::json!({
        "schema_version": 2,
        "package_name": program.name,
        "program_digest": program.digest_hex(),
        "field": program.field.as_str(),
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
            "ir_family": "ir-v2",
            "ir_version": "2",
            "strict_mode": "true",
            "requires_execution": if requires_execution { "true" } else { "false" },
            "requires_solver": if requires_solver { "true" } else { "false" },
            "allow_builtin_fallback": if allow_builtin_fallback { "true" } else { "false" }
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");
    manifest_path
}

#[test]
fn run_package_explicit_solver_reports_execution_path() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-explicit-solver-{nonce}"));
    let program = runtime_test_program(FieldId::Bn254);
    let manifest_path = write_test_manifest_v2(&root, &program, false, false, true);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "5" })).expect("inputs");

    let run = run_package(&manifest_path, &inputs_path, "main", Some("noop")).expect("run");
    let run_report: Value = read_json(Path::new(&run.run_report_path)).expect("run report");
    assert_eq!(
        run_report.get("solver_path").and_then(Value::as_str),
        Some("noop")
    );
    assert_eq!(
        run_report.get("execution_path").and_then(Value::as_str),
        Some("explicit-solver")
    );
    assert_eq!(
        run_report
            .get("attempted_solver_paths")
            .and_then(Value::as_array)
            .map(|items| { items.iter().filter_map(Value::as_str).collect::<Vec<_>>() }),
        Some(vec!["noop"])
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn run_package_uses_builtin_fallback_when_solver_paths_fail_and_allowed() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-builtin-fallback-{nonce}"));
    let program = runtime_test_program(FieldId::Goldilocks);
    let manifest_path = write_test_manifest_v2(&root, &program, false, false, true);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "5" })).expect("inputs");

    let run = run_package(&manifest_path, &inputs_path, "main", None).expect("run");
    let run_report: Value = read_json(Path::new(&run.run_report_path)).expect("run report");
    assert_eq!(
        run_report.get("solver_path").and_then(Value::as_str),
        Some("builtin")
    );
    assert_eq!(
        run_report.get("execution_path").and_then(Value::as_str),
        Some("builtin-fallback")
    );
    assert!(
        run_report
            .get("attempted_solver_paths")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty()),
        "expected attempted solver paths in fallback report"
    );
    assert!(
        run_report
            .get("solver_attempt_errors")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty()),
        "expected solver errors in fallback report"
    );
    assert!(
        run_report
            .get("fallback_reason")
            .and_then(Value::as_str)
            .is_some_and(|reason| reason.starts_with("acvm-solver-")),
        "expected ACVM fallback reason marker"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn run_package_rejects_solver_required_when_builtin_fallback_disabled() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-solver-required-{nonce}"));
    let program = runtime_test_program(FieldId::Goldilocks);
    let manifest_path = write_test_manifest_v2(&root, &program, false, true, false);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "5" })).expect("inputs");

    let err = run_package(&manifest_path, &inputs_path, "main", None).expect_err("run error");
    assert!(
        err.contains("requires solver-mode witness generation"),
        "unexpected error: {err}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn run_package_rejects_execution_required_when_frontend_and_solver_fail() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-run-execution-required-{nonce}"));
    let program = runtime_test_program(FieldId::Goldilocks);
    let manifest_path = write_test_manifest_v2(&root, &program, true, false, true);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "5" })).expect("inputs");

    let err = run_package(&manifest_path, &inputs_path, "main", None).expect_err("run error");
    assert!(
        err.contains("requires execution-mode witness generation"),
        "unexpected error: {err}"
    );

    let _ = fs::remove_dir_all(&root);
}
