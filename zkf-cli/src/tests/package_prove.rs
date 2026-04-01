use super::*;

fn simple_package_program_with_field(field: FieldId) -> Program {
    Program {
        name: "package_prove_demo".to_string(),
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

fn poseidon_identity_program() -> Program {
    Program {
        name: "poseidon_identity_demo".to_string(),
        field: FieldId::Bn254,
        signals: (0..4)
            .map(|index| zkf_core::Signal {
                name: format!("in_{index}"),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            })
            .chain((0..4).map(|index| zkf_core::Signal {
                name: format!("out_{index}"),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            }))
            .collect(),
        constraints: vec![Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Poseidon,
            inputs: (0..4)
                .map(|index| zkf_core::Expr::signal(format!("in_{index}")))
                .collect(),
            outputs: (0..4).map(|index| format!("out_{index}")).collect(),
            params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
            label: Some("identity_commitment".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    }
}

fn write_package_manifest(root: &Path, program: &Program) -> PathBuf {
    let backend_targets = match program.field {
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => vec!["plonky3"],
        FieldId::PastaFp => vec!["halo2"],
        _ => vec!["arkworks-groth16"],
    };
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

fn write_poseidon_inputs(root: &Path) -> PathBuf {
    let inputs_path = root.join("poseidon-inputs.json");
    write_json(
        &inputs_path,
        &serde_json::json!({
            "in_0": "1",
            "in_1": "2",
            "in_2": "3",
            "in_3": "4"
        }),
    )
    .expect("poseidon inputs");
    inputs_path
}

#[test]
fn prove_all_parallel_records_scheduler_metadata() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-prove-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest(&root, &program);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "3", "y": "5" })).expect("inputs");

    run_package(&manifest_path, &inputs_path, "main", None).expect("run package");

    let report = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::prove::prove_all_package(
            &manifest_path,
            &[crate::util::BackendRequest::native(
                BackendKind::ArkworksGroth16,
            )],
            "main",
            true,
            Some(8),
            None,
        )
    })
    .expect("prove all");

    assert!(report.parallel);
    assert_eq!(report.requested, 1);
    assert_eq!(report.succeeded, 1);
    let scheduler = report.scheduler.as_ref().expect("scheduler");
    assert_eq!(scheduler.requested_jobs, 8);
    assert_eq!(scheduler.recommended_jobs, report.jobs_used);

    let manifest: PackageManifest = read_json(&manifest_path).expect("manifest");
    assert_eq!(
        manifest
            .metadata
            .get("last_prove_jobs_requested")
            .map(String::as_str),
        Some("8")
    );
    assert!(
        manifest
            .metadata
            .get("last_prove_jobs_recommended")
            .is_some_and(|value| value == &report.jobs_used.to_string())
    );
    assert!(
        manifest
            .metadata
            .contains_key("last_prove_scheduler_reason")
    );

    let _ = fs::remove_dir_all(&root);
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn package_prove_mode_metal_first_picks_field_preferred_backend() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-prove-mode-{nonce}"));
    let program = simple_package_program_with_field(FieldId::Goldilocks);
    let manifest_path = write_package_manifest(&root, &program);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "2", "y": "9" })).expect("inputs");

    run_package(&manifest_path, &inputs_path, "main", None).expect("run package");

    let report = cmd::package::prove::prove_package(
        &manifest_path,
        &crate::util::resolve_backend_or_mode(
            None,
            Some("metal-first"),
            &program,
            zkf_runtime::OptimizationObjective::FastestProve,
        )
        .expect("backend"),
        zkf_runtime::OptimizationObjective::FastestProve,
        "main",
        None,
        false,
    )
    .expect("prove package");

    assert_eq!(report.backend, "plonky3");

    let _ = fs::remove_dir_all(&root);
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn package_prove_all_explicit_backend_allows_export_path() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-prove-all-explicit-{nonce}"));
    let program = simple_package_program();
    let manifest_path = write_package_manifest(&root, &program);
    let inputs_path = root.join("inputs.json");
    write_json(&inputs_path, &serde_json::json!({ "x": "4", "y": "6" })).expect("inputs");

    run_package(&manifest_path, &inputs_path, "main", None).expect("run package");

    let report = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::prove::prove_all_package(
            &manifest_path,
            &[crate::util::BackendRequest::native(
                BackendKind::ArkworksGroth16,
            )],
            "main",
            false,
            None,
            None,
        )
    })
    .expect("prove all");

    assert_eq!(report.requested, 1);
    assert_eq!(report.succeeded, 1);
    assert_eq!(report.results[0].backend, "arkworks-groth16");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn poseidon_identity_flow_uses_source_witness_and_prepares_proving_witness_in_memory() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-package-poseidon-{nonce}"));
    let program = poseidon_identity_program();
    let manifest_path = write_package_manifest(&root, &program);
    let inputs_path = write_poseidon_inputs(&root);
    let witness_out = root.join("witness.json");

    let program_path = root.join("ir/program.json");
    cmd::witness::handle_witness(program_path, inputs_path.clone(), witness_out.clone())
        .expect("cli witness");
    let witness: Witness = read_json(&witness_out).expect("source witness");
    assert!(witness.values.contains_key("out_0"));
    assert!(
        !witness
            .values
            .keys()
            .any(|name| name.contains("__bb_") || name.contains("merkle_")),
        "expected source/debug witness without lowered auxiliary signals"
    );

    let run = run_package(&manifest_path, &inputs_path, "main", None).expect("run package");
    let run_report: Value = read_json(Path::new(&run.run_report_path)).expect("run report");
    assert_eq!(
        run_report.get("prepared_witness_validated"),
        Some(&serde_json::json!(true))
    );

    let prove = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::prove::prove_package(
            &manifest_path,
            &crate::util::BackendRequest::native(BackendKind::ArkworksGroth16),
            zkf_runtime::OptimizationObjective::FastestProve,
            "main",
            None,
            false,
        )
    })
    .expect("prove package");
    assert_eq!(prove.backend, "arkworks-groth16");

    let verify = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        cmd::package::verify_proof::verify_package_proof(
            &manifest_path,
            &crate::util::BackendRequest::native(BackendKind::ArkworksGroth16),
            "main",
            None,
            None,
            false,
        )
    })
    .expect("verify proof");
    assert!(verify.ok);

    let _ = fs::remove_dir_all(&root);
}
