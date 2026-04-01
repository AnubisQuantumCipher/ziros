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
use clap::{CommandFactory, Parser};

fn audit_sample_program() -> Program {
    Program {
        name: "audit_demo".to_string(),
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

#[test]
fn audit_render_includes_suggestions_for_findings() {
    let mut report = zkf_core::AuditReport::new();
    report.add_check(zkf_core::AuditCheck {
        name: "underconstrained_signals".to_string(),
        category: zkf_core::AuditCategory::UnderconstrainedSignals,
        status: zkf_core::AuditStatus::Fail,
        evidence: Some("1 unconstrained".to_string()),
        duration_ms: None,
    });
    report.add_finding(zkf_core::AuditFinding {
        severity: zkf_core::AuditSeverity::Error,
        category: zkf_core::AuditCategory::UnderconstrainedSignals,
        message: "private signal 'x' is not referenced by any constraint".to_string(),
        location: Some("signal 'x'".to_string()),
        suggestion: None,
    });
    report.finalize();

    let rendered = crate::cmd::audit::render_audit_report(&report).expect("render audit report");
    assert!(rendered.contains("Findings:"));
    assert!(rendered.contains("suggestion:"));
    assert!(rendered.contains("Constrain the signal"));
}

#[test]
fn audit_render_includes_plain_english_nonlinear_anchoring_guidance() {
    let mut report = zkf_core::AuditReport::new();
    report.add_check(zkf_core::AuditCheck {
        name: "underconstrained_signals".to_string(),
        category: zkf_core::AuditCategory::UnderconstrainedSignals,
        status: zkf_core::AuditStatus::Fail,
        evidence: Some("1 linear-only underdetermined".to_string()),
        duration_ms: None,
    });
    report.add_finding(zkf_core::AuditFinding {
        severity: zkf_core::AuditSeverity::Error,
        category: zkf_core::AuditCategory::UnderconstrainedSignals,
        message: "private signal 'lead_gap' is only used in linear constraints and is linearly underdetermined without nonlinear anchoring (nullity>0). A malicious prover could manipulate this value without detection until it participates in a nonlinear relation.".to_string(),
        location: Some("signal 'lead_gap'".to_string()),
        suggestion: None,
    });
    report.finalize();

    let rendered = crate::cmd::audit::render_audit_report(&report).expect("render audit report");
    assert!(rendered.contains("A malicious prover could manipulate this value"));
    assert!(rendered.contains("Poseidon hash"));
    assert!(rendered.contains("docs/NONLINEAR_ANCHORING.md"));
}

#[test]
fn render_zkf_error_makes_range_failures_actionable() {
    let rendered = crate::util::render_zkf_error(zkf_core::ZkfError::RangeConstraintViolation {
        index: 3,
        label: Some("x_range".to_string()),
        signal: "x".to_string(),
        bits: 8,
        value: FieldElement::from_i64(300),
    });

    assert!(rendered.contains("Range check failed for signal 'x'"));
    assert!(rendered.contains("constraint #3 ('x_range')"));
    assert!(rendered.contains("max 255"));
    assert!(rendered.contains("ziros debug"));
}

#[test]
fn render_zkf_error_makes_unresolved_witness_failures_actionable() {
    let rendered = crate::util::render_zkf_error(zkf_core::ZkfError::UnsupportedWitnessSolve {
        unresolved_signals: vec!["__poseidon_state_0".to_string(), "data_commitment".to_string()],
        reason: "blocked constraints: measure_range, commitment_stage_1; next step: run `ziros debug --program <program.json> --inputs <inputs.json> --out debug.json` to inspect unresolved dependencies".to_string(),
    });

    assert!(rendered.contains("Witness generation stalled"));
    assert!(rendered.contains("__poseidon_state_0"));
    assert!(rendered.contains("blocked constraints: measure_range, commitment_stage_1"));
    assert!(rendered.contains("ziros debug"));
}

#[test]
fn cli_parses_audit_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "audit",
        "--program",
        "/tmp/program.json",
        "--backend",
        "sp1",
        "--out",
        "/tmp/audit.json",
        "--json",
    ]);

    match cli.command {
        crate::cli::Commands::Audit {
            program,
            backend,
            out,
            json,
        } => {
            assert_eq!(program, PathBuf::from("/tmp/program.json"));
            assert_eq!(backend.as_deref(), Some("sp1"));
            assert_eq!(out, Some(PathBuf::from("/tmp/audit.json")));
            assert!(json);
        }
        other => panic!("expected audit command, got {other:?}"),
    }
}

#[test]
fn cli_about_mentions_ziros_rebrand() {
    let about = crate::cli::Cli::command()
        .get_about()
        .map(|value| value.to_string())
        .unwrap_or_default();
    assert!(about.contains("ZirOS"));
    assert!(about.contains("ZKF"));
}

#[test]
fn cli_parses_conformance_command() {
    let cli = crate::cli::Cli::parse_from(["zkf", "conformance", "--backend", "plonky3", "--json"]);

    match cli.command {
        crate::cli::Commands::Conformance {
            backend,
            json,
            export_json,
            export_cbor,
        } => {
            assert_eq!(backend, "plonky3");
            assert!(json);
            assert!(export_json.is_none());
            assert!(export_cbor.is_none());
        }
        other => panic!("expected conformance command, got {other:?}"),
    }
}

#[test]
fn cli_parses_demo_command() {
    let cli = crate::cli::Cli::parse_from(["zkf", "demo", "--out", "/tmp/demo.json", "--json"]);

    match cli.command {
        crate::cli::Commands::Demo { out, json } => {
            assert_eq!(out, Some(PathBuf::from("/tmp/demo.json")));
            assert!(json);
        }
        other => panic!("expected demo command, got {other:?}"),
    }
}

#[test]
fn cli_inspect_defaults_to_auto_frontend() {
    let cli = crate::cli::Cli::parse_from(["zkf", "inspect", "--in", "/tmp/program.json"]);

    match cli.command {
        crate::cli::Commands::Inspect {
            frontend,
            input,
            json,
        } => {
            assert_eq!(frontend, "auto");
            assert_eq!(input, PathBuf::from("/tmp/program.json"));
            assert!(!json);
        }
        other => panic!("expected inspect command, got {other:?}"),
    }
}

#[test]
fn cli_parses_emit_example_field_override() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "emit-example",
        "--out",
        "/tmp/example.json",
        "--field",
        "goldilocks",
    ]);

    match cli.command {
        crate::cli::Commands::EmitExample { out, field } => {
            assert_eq!(out, PathBuf::from("/tmp/example.json"));
            assert_eq!(field.as_deref(), Some("goldilocks"));
        }
        other => panic!("expected emit-example command, got {other:?}"),
    }
}

#[test]
fn cli_parses_equivalence_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "equivalence",
        "--program",
        "/tmp/program.json",
        "--inputs",
        "/tmp/inputs.json",
        "--backends",
        "plonky3,halo2",
        "--seed",
        "demo-seed",
        "--groth16-setup-blob",
        "/tmp/groth16.setup",
        "--allow-dev-deterministic-groth16",
        "--json",
    ]);

    match cli.command {
        crate::cli::Commands::Equivalence {
            program,
            inputs,
            backends,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            json,
        } => {
            assert_eq!(program, PathBuf::from("/tmp/program.json"));
            assert_eq!(inputs, PathBuf::from("/tmp/inputs.json"));
            assert_eq!(backends, vec!["plonky3".to_string(), "halo2".to_string()]);
            assert_eq!(seed.as_deref(), Some("demo-seed"));
            assert_eq!(
                groth16_setup_blob,
                Some(PathBuf::from("/tmp/groth16.setup"))
            );
            assert!(allow_dev_deterministic_groth16);
            assert!(json);
        }
        other => panic!("expected equivalence command, got {other:?}"),
    }
}

#[test]
fn cli_parses_ir_validate_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "ir",
        "validate",
        "--program",
        "/tmp/program.json",
        "--json",
    ]);

    match cli.command {
        crate::cli::Commands::Ir {
            command: crate::cli::IrCommands::Validate { program, json },
        } => {
            assert_eq!(program, PathBuf::from("/tmp/program.json"));
            assert!(json);
        }
        other => panic!("expected ir validate command, got {other:?}"),
    }
}

#[test]
fn audit_command_uses_dynamic_backend_capability_truth() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-audit-test-{nonce}"));
    fs::create_dir_all(&root).expect("root dir");

    let program_path = root.join("program.json");
    let out_path = root.join("audit.json");
    write_json(&program_path, &audit_sample_program()).expect("program");

    cmd::audit::handle_audit(
        program_path.clone(),
        Some("sp1".to_string()),
        Some(out_path.clone()),
        true,
    )
    .expect("audit command should succeed in json mode");

    let report_json = fs::read_to_string(&out_path).expect("audit output");
    let report: zkf_core::AuditReport =
        serde_json::from_str(&report_json).expect("audit report JSON");
    let expected = zkf_backends::capability_report_for_backend(BackendKind::Sp1)
        .expect("sp1 capability report");

    assert_eq!(report.backend, Some(BackendKind::Sp1));
    assert_eq!(
        report.implementation_type.as_deref(),
        Some(expected.implementation_type.as_str())
    );
    assert_eq!(
        report.support_class.as_deref(),
        Some(expected.implementation_type.as_str())
    );
    assert_eq!(report.compiled_in, Some(expected.compiled_in));
    assert_eq!(report.toolchain_ready, Some(expected.toolchain_ready));
    assert_eq!(report.runtime_ready, Some(expected.runtime_ready));
    assert_eq!(report.production_ready, Some(expected.production_ready));
    assert_eq!(
        report.readiness.as_deref(),
        Some(expected.readiness.as_str())
    );
    assert_eq!(report.readiness_reason, expected.readiness_reason);
    assert_eq!(report.operator_action, expected.operator_action);
    assert_eq!(report.explicit_compat_alias, expected.explicit_compat_alias);
    assert_eq!(
        report.native_lookup_support,
        Some(expected.native_lookup_support)
    );
    assert_eq!(
        report.lookup_lowering_support,
        Some(expected.lookup_lowering_support)
    );
    assert_eq!(
        report.lookup_semantics.as_deref(),
        Some(expected.lookup_semantics.as_str())
    );
    assert_eq!(
        report.aggregation_semantics.as_deref(),
        Some(expected.aggregation_semantics.as_str())
    );

    let _ = fs::remove_dir_all(&root);
}
