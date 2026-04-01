// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use super::*;

#[test]
fn migrate_manifest_v1_to_v2_updates_run_report_and_metadata() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-migrate-test-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");
    fs::create_dir_all(root.join("runs/main")).expect("run dir");

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
    let run_report = serde_json::json!({
        "run_id": "main",
        "solver": "acvm",
        "witness_requirement": "solver",
        "witness_values": 1,
        "public_inputs": 0,
        "constraints": 0,
        "signals": 1,
        "requires_hints": false
    });
    let run_report_sha = write_json_and_hash(&root.join("runs/main/run_report.json"), &run_report)
        .expect("run report");

    let manifest_json = serde_json::json!({
        "schema_version": 1,
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
        "runs": {},
        "metadata": {
            "witness_requirement": "solver",
            "requires_hints": "false"
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");

    let report = migrate_package_manifest(&manifest_path, "1", "2").expect("migrate");
    assert_eq!(report.from_version, 1);
    assert_eq!(report.to_version, 2);

    let migrated: PackageManifest = read_json(&manifest_path).expect("read migrated");
    assert_eq!(migrated.schema_version, 2);
    assert_eq!(
        migrated.metadata.get("requires_execution"),
        Some(&"false".to_string())
    );
    assert_eq!(
        migrated.metadata.get("requires_solver"),
        Some(&"true".to_string())
    );
    assert_eq!(
        migrated.metadata.get("allow_builtin_fallback"),
        Some(&"false".to_string())
    );
    assert_eq!(
        migrated.metadata.get("ir_family"),
        Some(&"ir-v2".to_string())
    );
    assert_eq!(migrated.metadata.get("ir_version"), Some(&"2".to_string()));
    assert_eq!(
        migrated.metadata.get("strict_mode"),
        Some(&"true".to_string())
    );

    let migrated_report: Value =
        read_json(&root.join("runs/main/run_report.json")).expect("run report read");
    assert_eq!(
        migrated_report
            .get("requires_solver")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        migrated_report.get("solver_path").and_then(Value::as_str),
        Some("acvm")
    );
    assert_eq!(
        migrated_report
            .get("execution_path")
            .and_then(Value::as_str),
        Some("solver-fallback")
    );
    assert!(migrated_report.get("witness_requirement").is_none());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn migrate_manifest_v2_to_v4_updates_schema_version() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-migrate-v4-test-{nonce}"));
    fs::create_dir_all(root.join("ir")).expect("ir dir");
    fs::create_dir_all(root.join("frontends/noir")).expect("frontend dir");

    let program = Program {
        name: "demo-v3".to_string(),
        field: FieldId::Goldilocks,
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
        "package_name": "demo-v4",
        "program_digest": program.digest_hex(),
        "field": "goldilocks",
        "frontend": { "kind": "noir" },
        "backend_targets": ["plonky3"],
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
            "requires_execution": "false",
            "requires_solver": "false",
            "allow_builtin_fallback": "false"
        }
    });
    let manifest_path = root.join("manifest.json");
    write_json(&manifest_path, &manifest_json).expect("manifest");

    let report = migrate_package_manifest(&manifest_path, "2", "4").expect("migrate");
    assert_eq!(report.from_version, 2);
    assert_eq!(report.to_version, 4);

    let migrated: PackageManifest = read_json(&manifest_path).expect("read migrated");
    assert_eq!(migrated.schema_version, 4);

    let _ = fs::remove_dir_all(&root);
}
