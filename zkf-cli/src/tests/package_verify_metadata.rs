use super::*;

#[test]
fn verify_manifest_v2_fails_when_required_metadata_missing() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-metadata-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");

    let program = Program {
        name: "demo".to_string(),
        field: FieldId::Bn254,
        signals: vec![zkf_core::Signal {
            name: "x".to_string(),
            visibility: zkf_core::Visibility::Private,
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

    let report = verify_package_manifest(&manifest_path).expect("verify report");
    assert!(!report.ok);
    assert!(
        report.warnings.iter().any(|warning| {
            warning.contains("missing required manifest metadata key 'ir_family'")
        })
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn verify_manifest_v2_fails_for_unknown_ir_family() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-ir-family-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");

    let program = Program {
        name: "demo".to_string(),
        field: FieldId::Bn254,
        signals: vec![zkf_core::Signal {
            name: "x".to_string(),
            visibility: zkf_core::Visibility::Private,
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
        "metadata": {
            "ir_family": "unknown-ir",
            "ir_version": "99",
            "strict_mode": "true",
            "requires_execution": "false",
            "requires_solver": "false",
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
            .any(|warning| warning.contains("unsupported manifest ir_family"))
    );

    let _ = fs::remove_dir_all(&root);
}
