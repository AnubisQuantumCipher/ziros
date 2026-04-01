use super::*;

#[test]
fn verify_manifest_v2_fails_when_run_report_missing_execution_path() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-run-report-missing-exec-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");
    fs::create_dir_all(root.join("runs/main")).expect("run dir");

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
    let run_report_sha = write_json_and_hash(
        &root.join("runs/main/run_report.json"),
        &serde_json::json!({
            "run_id": "main",
            "solver": "acvm",
            "solver_path": "acvm",
            "requires_execution": false,
            "requires_solver": true
        }),
    )
    .expect("run report");

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
            "run_report": { "path": "runs/main/run_report.json", "sha256": run_report_sha },
            "compiled": {},
            "proofs": {}
        },
        "runs": {
            "main": {
                "witness": { "path": "runs/main/witness.json", "sha256": "00" },
                "public_inputs": { "path": "runs/main/public_inputs.json", "sha256": "00" },
                "run_report": { "path": "runs/main/run_report.json", "sha256": run_report_sha }
            }
        },
        "metadata": {
            "ir_family": "ir-v2",
            "ir_version": "2",
            "strict_mode": "true",
            "requires_execution": "false",
            "requires_solver": "true",
            "allow_builtin_fallback": "false"
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");

    let report = verify_package_manifest(&manifest_path).expect("verify report");
    assert!(!report.ok);
    assert!(report.warnings.iter().any(|warning| {
        warning.contains("run report") && warning.contains("missing required key 'execution_path'")
    }));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn verify_manifest_v2_fails_when_run_report_has_empty_execution_path() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-run-report-empty-exec-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");
    fs::create_dir_all(root.join("runs/main")).expect("run dir");

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
    let run_report_sha = write_json_and_hash(
        &root.join("runs/main/run_report.json"),
        &serde_json::json!({
            "run_id": "main",
            "solver": "acvm",
            "solver_path": "acvm",
            "execution_path": "",
            "requires_execution": false,
            "requires_solver": true
        }),
    )
    .expect("run report");

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
            "run_report": { "path": "runs/main/run_report.json", "sha256": run_report_sha },
            "compiled": {},
            "proofs": {}
        },
        "runs": {
            "main": {
                "witness": { "path": "runs/main/witness.json", "sha256": "00" },
                "public_inputs": { "path": "runs/main/public_inputs.json", "sha256": "00" },
                "run_report": { "path": "runs/main/run_report.json", "sha256": run_report_sha }
            }
        },
        "metadata": {
            "ir_family": "ir-v2",
            "ir_version": "2",
            "strict_mode": "true",
            "requires_execution": "false",
            "requires_solver": "true",
            "allow_builtin_fallback": "false"
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");

    let report = verify_package_manifest(&manifest_path).expect("verify report");
    assert!(!report.ok);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("execution_path")
                && warning.contains("must not be empty"))
    );

    let _ = fs::remove_dir_all(&root);
}
