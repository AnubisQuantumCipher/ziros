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
use zkf_runtime::OptimizationObjective;

#[test]
fn parse_step_mode_accepts_expected_aliases() {
    assert_eq!(
        parse_step_mode("reuse-inputs").expect("valid"),
        StepMode::ReuseInputs
    );
    assert_eq!(
        parse_step_mode("chain").expect("valid"),
        StepMode::ChainPublicOutputs
    );
    assert!(parse_step_mode("unknown-mode").is_err());
}

#[test]
fn chain_step_inputs_overrides_public_signals() {
    let mut base = BTreeMap::new();
    base.insert("state".to_string(), FieldElement::from_i64(5));
    base.insert("x".to_string(), FieldElement::from_i64(9));

    let public_names = vec!["state".to_string()];
    let public_values = vec![FieldElement::from_i64(12)];

    let chained =
        chain_step_inputs(&base, &public_names, &public_values).expect("chain should pass");
    assert_eq!(chained["state"], FieldElement::from_i64(12));
    assert_eq!(chained["x"], FieldElement::from_i64(9));
}

#[test]
fn nova_ivc_explicit_state_chaining_is_not_generic_public_output_chaining() {
    let mut base = BTreeMap::new();
    base.insert("counter_in".to_string(), FieldElement::from_i64(0));
    base.insert("x".to_string(), FieldElement::from_i64(9));

    let public_names = vec!["counter_in".to_string(), "counter_out".to_string()];
    let public_values = vec![FieldElement::from_i64(0), FieldElement::from_i64(1)];

    let generic =
        chain_step_inputs(&base, &public_names, &public_values).expect("generic chain should pass");
    let explicit = chain_nova_ivc_input(&base, "counter_in", &FieldElement::from_i64(1));

    assert_eq!(generic["counter_in"], FieldElement::from_i64(0));
    assert_eq!(generic["counter_out"], FieldElement::from_i64(1));
    assert_eq!(explicit["counter_in"], FieldElement::from_i64(1));
    assert!(!explicit.contains_key("counter_out"));
    assert_eq!(explicit["x"], FieldElement::from_i64(9));
}

#[test]
fn default_cli_build_exposes_native_nova_surface() {
    let nova = zkf_backends::backend_surface_status(BackendKind::Nova);
    assert!(
        nova.compiled_in,
        "default CLI build must compile native Nova"
    );
    assert_eq!(nova.implementation_type, zkf_core::SupportClass::Native);

    let hypernova = zkf_backends::backend_surface_status(BackendKind::HyperNova);
    assert!(
        hypernova.compiled_in,
        "default CLI build must compile native HyperNova routing"
    );
    assert_eq!(
        hypernova.implementation_type,
        zkf_core::SupportClass::Native
    );
}

#[test]
fn infer_witness_requirement_prefers_execution_for_hints() {
    let program = Program {
        name: "demo".to_string(),
        field: FieldId::Bn254,
        signals: Vec::new(),
        constraints: Vec::new(),
        witness_plan: zkf_core::WitnessPlan {
            assignments: Vec::new(),
            hints: vec![zkf_core::WitnessHint {
                target: "w1".to_string(),
                source: "hint".to_string(),
                kind: zkf_core::WitnessHintKind::Copy,
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let inspection = FrontendInspection {
        frontend: FrontendKind::Noir,
        format: None,
        version: None,
        functions: 1,
        unconstrained_functions: 0,
        opcode_counts: BTreeMap::new(),
        blackbox_counts: BTreeMap::new(),
        required_capabilities: vec!["hints".to_string()],
        dropped_features: Vec::new(),
        requires_hints: true,
    };
    assert_eq!(
        infer_witness_requirement(&program, Some(&inspection)),
        WitnessRequirement::Execution
    );
}

#[test]
fn infer_witness_requirement_marks_solver_when_assignments_absent() {
    let program = Program {
        name: "demo".to_string(),
        field: FieldId::Bn254,
        signals: Vec::new(),
        constraints: vec![zkf_core::Constraint::Boolean {
            signal: "w1".to_string(),
            label: None,
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    };
    assert_eq!(
        infer_witness_requirement(&program, None),
        WitnessRequirement::Solver
    );
}

#[test]
fn parse_setup_seed_accepts_hex_or_string() {
    let hex_seed =
        parse_setup_seed("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10")
            .expect("hex seed should parse");
    assert_eq!(hex_seed[0], 0x01);
    assert_eq!(hex_seed[15], 0x10);

    let a = parse_setup_seed("demo-seed").expect("string seed should hash");
    let b = parse_setup_seed("demo-seed").expect("string seed should hash deterministically");
    assert_eq!(a, b);
}

#[test]
fn ensure_backend_request_allowed_blocks_explicit_compat_without_flag() {
    let request = parse_backend_request("sp1-compat").expect("compat alias should parse");
    let err = ensure_backend_request_allowed(&request, false).expect_err("must block");
    assert!(err.contains("compat"));
    ensure_backend_request_allowed(&request, true).expect("allow-compat should pass");
}

#[test]
fn ensure_backend_supports_recursive_aggregation_marker_when_advertised() {
    let cases = [
        (BackendKind::ArkworksGroth16, FieldId::Bn254),
        (BackendKind::Halo2, FieldId::PastaFp),
        (BackendKind::Plonky3, FieldId::Goldilocks),
        (BackendKind::MidnightCompact, FieldId::PastaFp),
    ];

    for (backend, field) in cases {
        let program = Program {
            name: "bb_marker".to_string(),
            field,
            signals: vec![
                zkf_core::Signal {
                    name: "in".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "out".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![zkf_core::Constraint::BlackBox {
                op: zkf_core::BlackBoxOp::RecursiveAggregationMarker,
                inputs: vec![zkf_core::Expr::Signal("in".to_string())],
                outputs: vec!["out".to_string()],
                params: BTreeMap::new(),
                label: Some("marker".to_string()),
            }],
            witness_plan: zkf_core::WitnessPlan::default(),
            ..Default::default()
        };

        ensure_backend_supports_program_constraints(backend, &program)
            .expect("backend should advertise recursive marker blackbox support");
    }
}

#[test]
fn ensure_backend_supports_sha256_blackbox_succeeds_when_advertised() {
    let program = Program {
        name: "bb_sha".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::Signal {
                name: "in".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![zkf_core::Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Sha256,
            inputs: vec![zkf_core::Expr::Signal("in".to_string())],
            outputs: vec!["out".to_string()],
            params: BTreeMap::new(),
            label: Some("sha".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    };

    ensure_backend_supports_program_constraints(BackendKind::ArkworksGroth16, &program)
        .expect("sha256 should pass capability preflight once advertised");
}

#[test]
fn omitted_backend_uses_compact_preferred_backend_hint_only_for_compact_programs() {
    let compact_program = Program {
        field: FieldId::Bls12_381,
        metadata: BTreeMap::from([
            ("frontend".to_string(), "compact".to_string()),
            (
                "preferred_backend".to_string(),
                "halo2-bls12-381".to_string(),
            ),
        ]),
        ..Default::default()
    };
    let compact_backend = resolve_backend_or_mode(
        None,
        None,
        &compact_program,
        OptimizationObjective::FastestProve,
    )
    .expect("compact hint should resolve");
    assert_eq!(compact_backend.backend, BackendKind::Halo2Bls12381);

    let plain_bls_program = Program {
        field: FieldId::Bls12_381,
        ..Default::default()
    };
    let err = resolve_backend_or_mode(
        None,
        None,
        &plain_bls_program,
        OptimizationObjective::FastestProve,
    )
    .expect_err("non-compact bls program should still fail closed without --backend");
    assert!(err.contains("no default backend is selected"));
}

#[test]
fn ensure_backend_supports_poseidon_blackbox_only_on_bn254() {
    let program = Program {
        name: "bb_poseidon".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::Signal {
                name: "in".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![zkf_core::Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Poseidon,
            inputs: vec![zkf_core::Expr::Signal("in".to_string())],
            outputs: vec!["out".to_string()],
            params: BTreeMap::from([("state_len".to_string(), "1".to_string())]),
            label: Some("poseidon".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    };

    ensure_backend_supports_program_constraints(BackendKind::ArkworksGroth16, &program)
        .expect("poseidon on bn254 should pass capability preflight");

    let mut non_bn254 = program.clone();
    non_bn254.field = FieldId::Goldilocks;
    let err = ensure_backend_supports_program_constraints(BackendKind::Plonky3, &non_bn254)
        .expect_err("poseidon must fail preflight outside bn254");
    assert!(
        err.contains("bn254"),
        "expected bn254 field guard in error, got: {err}"
    );
}

#[test]
fn ensure_backend_supports_pedersen_and_schnorr_only_on_bn254() {
    for op in [
        zkf_core::BlackBoxOp::Pedersen,
        zkf_core::BlackBoxOp::SchnorrVerify,
    ] {
        let program = Program {
            name: format!("bb_{}", op.as_str()),
            field: FieldId::Bn254,
            signals: vec![
                zkf_core::Signal {
                    name: "in".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "out".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![zkf_core::Constraint::BlackBox {
                op,
                inputs: vec![zkf_core::Expr::Signal("in".to_string())],
                outputs: vec!["out".to_string()],
                params: BTreeMap::new(),
                label: Some(op.as_str().to_string()),
            }],
            witness_plan: zkf_core::WitnessPlan::default(),
            ..Default::default()
        };
        ensure_backend_supports_program_constraints(BackendKind::ArkworksGroth16, &program)
            .expect("bn254 program should pass preflight");

        let mut non_bn254 = program.clone();
        non_bn254.field = FieldId::Goldilocks;
        let err = ensure_backend_supports_program_constraints(BackendKind::Plonky3, &non_bn254)
            .expect_err("bn254-only blackbox must fail preflight outside bn254");
        assert!(
            err.contains("bn254"),
            "expected bn254 field guard in error for {}, got: {err}",
            op.as_str()
        );
    }
}
