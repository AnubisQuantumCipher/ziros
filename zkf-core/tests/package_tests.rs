use zkf_core::{
    Constraint, Expr, FieldId, FrontendProvenance, PackageManifest, Program, Signal, Visibility,
    WitnessPlan,
};

#[test]
fn package_manifest_tracks_program_digest_and_field() {
    let program = Program {
        name: "pkg_demo".to_string(),
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
                name: "z".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("z"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("z_is_sum".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };
    let mut frontend = FrontendProvenance::new("noir");
    frontend.version = Some("1.0.0-beta.9".to_string());
    frontend.format = Some("noir-artifact-json".to_string());

    let manifest = PackageManifest::from_program(
        &program,
        frontend.clone(),
        "ir/program.json",
        "frontends/noir/original.json",
    );

    assert_eq!(manifest.schema_version, 4);
    assert_eq!(manifest.package_name, program.name);
    assert_eq!(manifest.program_digest, program.digest_hex());
    assert_eq!(manifest.field, FieldId::Bn254);
    assert_eq!(manifest.frontend, frontend);
    assert_eq!(manifest.files.program.path, "ir/program.json");
    assert_eq!(
        manifest.files.original_artifact.path,
        "frontends/noir/original.json"
    );
    assert!(manifest.files.witness.is_none());
    assert!(manifest.files.public_inputs.is_none());
    assert!(manifest.files.run_report.is_none());
    assert!(manifest.runs.is_empty());
    assert!(manifest.files.compiled.is_empty());
    assert!(manifest.files.proofs.is_empty());
}

#[test]
fn package_manifest_back_compat_without_runs_field() {
    let manifest_json = serde_json::json!({
        "schema_version": 1,
        "package_name": "legacy_pkg",
        "program_digest": "abc123",
        "field": "bn254",
        "frontend": { "kind": "noir" },
        "backend_targets": [],
        "files": {
            "program": { "path": "ir/program.json", "sha256": "p" },
            "original_artifact": { "path": "frontends/noir/original.json", "sha256": "o" },
            "proofs": {}
        },
        "metadata": {}
    });

    let manifest: PackageManifest =
        serde_json::from_value(manifest_json).expect("legacy manifest should deserialize");
    assert!(manifest.runs.is_empty());
}
