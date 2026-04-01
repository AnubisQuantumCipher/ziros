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

fn simple_package_program_with_field(field: FieldId) -> Program {
    Program {
        name: "package_bundle_demo".to_string(),
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
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: zkf_core::Expr::signal("out"),
            rhs: zkf_core::Expr::Add(vec![
                zkf_core::Expr::signal("x"),
                zkf_core::Expr::signal("y"),
            ]),
            label: Some("out_eq_sum".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "out".to_string(),
                expr: zkf_core::Expr::Add(vec![
                    zkf_core::Expr::signal("x"),
                    zkf_core::Expr::signal("y"),
                ]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn simple_package_program() -> Program {
    simple_package_program_with_field(FieldId::Bn254)
}

fn write_package_manifest_with_targets(
    root: &Path,
    program: &Program,
    backend_targets: &[&str],
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
        "backend_targets": backend_targets,
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
    manifest_path
}

fn write_inputs(root: &Path) -> PathBuf {
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "3", "y": "5" })).expect("inputs");
    inputs_path
}

fn run_and_prove(
    manifest_path: &Path,
    inputs_path: &Path,
    run_id: &str,
    backend: BackendKind,
) -> crate::ProveResult {
    run_package(manifest_path, inputs_path, run_id, None).expect("run package");
    let request = crate::util::BackendRequest::native(backend);
    let prove = || {
        cmd::package::prove::prove_package(
            manifest_path,
            &request,
            zkf_runtime::OptimizationObjective::FastestProve,
            run_id,
            None,
            false,
        )
    };
    if backend == BackendKind::ArkworksGroth16 {
        zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), prove)
            .expect("prove package")
    } else {
        prove().expect("prove package")
    }
}

#[test]
fn bundle_roundtrip_writes_manifest_refs_and_verifies() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-bundle-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "main",
        BackendKind::ArkworksGroth16,
    );

    let report = cmd::package::bundle::bundle_package_proofs(&manifest_path, "main", &[])
        .expect("bundle proofs");
    assert_eq!(report.entries, 1);

    let verify =
        cmd::package::bundle::verify_package_bundle(&manifest_path, "main").expect("verify bundle");
    assert!(verify.ok);
    assert_eq!(verify.entries, 1);

    let manifest: PackageManifest = read_json(&manifest_path).expect("manifest");
    assert!(
        manifest
            .files
            .proofs
            .contains_key(&crate::package_io::bundle_file_key("main"))
    );
    assert!(
        manifest
            .files
            .proofs
            .contains_key(crate::package_io::legacy_bundle_file_key())
    );
    assert!(
        manifest
            .files
            .proofs
            .contains_key(crate::package_io::legacy_aggregate_file_key())
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn verify_bundle_reads_legacy_aggregate_ref_for_main() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-bundle-legacy-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "main",
        BackendKind::ArkworksGroth16,
    );
    cmd::package::bundle::bundle_package_proofs(&manifest_path, "main", &[])
        .expect("bundle proofs");

    let mut manifest: PackageManifest = read_json(&manifest_path).expect("manifest");
    manifest
        .files
        .proofs
        .remove(&crate::package_io::bundle_file_key("main"));
    manifest
        .files
        .proofs
        .remove(crate::package_io::legacy_bundle_file_key());
    write_json(&manifest_path, &manifest).expect("rewrite manifest");

    let verify =
        cmd::package::bundle::verify_package_bundle(&manifest_path, "main").expect("verify bundle");
    assert!(verify.ok);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn verify_bundle_reads_legacy_run_scoped_aggregate_ref() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-bundle-legacy-run-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "alt",
        BackendKind::ArkworksGroth16,
    );
    cmd::package::bundle::bundle_package_proofs(&manifest_path, "alt", &[]).expect("bundle proofs");

    let mut manifest: PackageManifest = read_json(&manifest_path).expect("manifest");
    let bundle_key = crate::package_io::bundle_file_key("alt");
    let bundle_ref = manifest
        .files
        .proofs
        .remove(&bundle_key)
        .expect("bundle ref");
    manifest
        .files
        .proofs
        .insert("aggregate/alt".to_string(), bundle_ref);
    write_json(&manifest_path, &manifest).expect("rewrite manifest");

    let verify =
        cmd::package::bundle::verify_package_bundle(&manifest_path, "alt").expect("verify bundle");
    assert!(verify.ok);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn compose_auto_bundles_when_missing() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-compose-bundle-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "main",
        BackendKind::ArkworksGroth16,
    );

    let manifest_before: PackageManifest = read_json(&manifest_path).expect("manifest before");
    assert!(
        !manifest_before
            .files
            .proofs
            .contains_key(&crate::package_io::bundle_file_key("main"))
    );

    let compose = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::compose::compose_package_proofs(
            &manifest_path,
            "main",
            &crate::util::BackendRequest::native(BackendKind::ArkworksGroth16),
            None,
        )
    })
    .expect("compose proofs");
    assert_eq!(compose.carried_entries, 1);

    let manifest_after: PackageManifest = read_json(&manifest_path).expect("manifest after");
    assert!(
        manifest_after
            .files
            .proofs
            .contains_key(&crate::package_io::bundle_file_key("main"))
    );

    let verify = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::compose::verify_composed_package_proof(
            &manifest_path,
            "main",
            &crate::util::BackendRequest::native(BackendKind::ArkworksGroth16),
            None,
        )
    })
    .expect("verify compose");
    assert!(verify.ok);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn aggregate_rejects_mixed_backend_inputs_with_explicit_error() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-aggregate-mixed-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "main",
        BackendKind::ArkworksGroth16,
    );

    let mut manifest: PackageManifest = read_json(&manifest_path).expect("manifest");
    let proof_ref = manifest
        .files
        .proofs
        .get(&crate::package_io::proof_file_key(
            BackendKind::ArkworksGroth16,
            "main",
        ))
        .cloned()
        .expect("arkworks proof ref");
    manifest.files.proofs.insert(
        crate::package_io::proof_file_key(BackendKind::Halo2, "halo-run"),
        proof_ref,
    );
    write_json(&manifest_path, &manifest).expect("rewrite manifest");

    let err = cmd::package::aggregate::aggregate_package_proofs(
        &manifest_path,
        BackendKind::ArkworksGroth16,
        &["main".to_string(), "halo-run".to_string()],
        "batch",
    )
    .expect_err("mixed backend error");
    assert!(err.contains("homogeneous"), "{err}");
    assert!(err.contains("bundle"), "{err}");
    assert!(err.contains("compose"), "{err}");
    assert!(err.contains("halo2"), "{err}");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn halo2_crypto_aggregate_roundtrip_verifies() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-aggregate-halo2-{nonce}"));
    let program = simple_package_program_with_field(FieldId::PastaFp);
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["halo2"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(&manifest_path, &inputs_path, "run-a", BackendKind::Halo2);
    run_and_prove(&manifest_path, &inputs_path, "run-b", BackendKind::Halo2);

    let aggregate = cmd::package::aggregate::aggregate_package_proofs(
        &manifest_path,
        BackendKind::Halo2,
        &["run-a".to_string(), "run-b".to_string()],
        "batch",
    )
    .expect("halo2 aggregate");
    assert_eq!(aggregate.proof_count, 2);
    assert_eq!(aggregate.backend, "halo2");

    let verify = cmd::package::aggregate::verify_package_aggregate(
        &manifest_path,
        BackendKind::Halo2,
        "batch",
    )
    .expect("verify halo2 aggregate");
    assert!(verify.ok);
    assert_eq!(verify.proof_count, 2);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn arkworks_crypto_aggregate_requires_explicit_recursive_prove_enablement() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-aggregate-arkworks-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["arkworks-groth16"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(
        &manifest_path,
        &inputs_path,
        "run-a",
        BackendKind::ArkworksGroth16,
    );
    run_and_prove(
        &manifest_path,
        &inputs_path,
        "run-b",
        BackendKind::ArkworksGroth16,
    );

    if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() == Some("1") {
        eprintln!("skipping Arkworks aggregate enablement test because ZKF_RECURSIVE_PROVE=1");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let err = cmd::package::aggregate::aggregate_package_proofs(
        &manifest_path,
        BackendKind::ArkworksGroth16,
        &["run-a".to_string(), "run-b".to_string()],
        "batch",
    )
    .expect_err("arkworks aggregate should require explicit recursive prove");
    assert!(err.contains("ZKF_RECURSIVE_PROVE=1"), "{err}");
    assert!(err.contains("CryptographicGroth16Aggregator"), "{err}");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn plonky3_crypto_aggregate_requires_explicit_recursive_prove_enablement() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-aggregate-plonky3-{nonce}"));
    let program = simple_package_program_with_field(FieldId::Goldilocks);
    let manifest_path = write_package_manifest_with_targets(&root, &program, &["plonky3"]);
    let inputs_path = write_inputs(&root);

    run_and_prove(&manifest_path, &inputs_path, "run-a", BackendKind::Plonky3);
    run_and_prove(&manifest_path, &inputs_path, "run-b", BackendKind::Plonky3);

    if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() == Some("1") {
        eprintln!("skipping Plonky3 aggregate enablement test because ZKF_RECURSIVE_PROVE=1");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let err = cmd::package::aggregate::aggregate_package_proofs(
        &manifest_path,
        BackendKind::Plonky3,
        &["run-a".to_string(), "run-b".to_string()],
        "batch",
    )
    .expect_err("plonky3 aggregate should require explicit recursive prove");
    assert!(err.contains("ZKF_RECURSIVE_PROVE=1"), "{err}");
    assert!(err.contains("Plonky3Aggregator"), "{err}");

    let _ = fs::remove_dir_all(&root);
}
