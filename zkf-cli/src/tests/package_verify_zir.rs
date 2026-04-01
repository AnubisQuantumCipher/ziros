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
fn verify_manifest_accepts_zir_program_digest() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-zir-digest-{nonce}"));
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
            rhs: zkf_core::zir_v1::Expr::Signal("x".to_string()),
            label: Some("eq".to_string()),
        }],
        witness_plan: zkf_core::zir_v1::WitnessPlan::default(),
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

    let report = verify_package_manifest(&manifest_path).expect("verify report");
    assert!(report.ok, "expected package verify to accept zir digest");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn verify_manifest_accepts_zir_lowered_v2_digest() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-verify-zir-lowered-digest-{nonce}"));
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
    let lowered = program_zir_to_v2(&zir_program).expect("lowered");
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
        "program_digest": lowered.digest_hex(),
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

    let report = verify_package_manifest(&manifest_path).expect("verify report");
    assert!(
        report.ok,
        "expected package verify to accept lowered digest"
    );

    let _ = fs::remove_dir_all(&root);
}
