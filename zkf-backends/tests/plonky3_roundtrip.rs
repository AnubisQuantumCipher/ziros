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

use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
#[allow(unused_imports)]
use zkf_backends::GpuStageCoverage;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, generate_witness, program_v2_to_zir,
};

fn plonky3_program(field: FieldId) -> Program {
    Program {
        name: "plonky3_mul_add".to_string(),
        field,
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
                name: "sum".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y_anchor".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "b".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum".to_string()),
            },
            Constraint::Boolean {
                signal: "b".to_string(),
                label: Some("b_boolean".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("y_anchor"),
                rhs: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
                label: Some("y_anchor".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("b"))),
                label: Some("out".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "sum".to_string(),
                    expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                },
                WitnessAssignment {
                    target: "out".to_string(),
                    expr: Expr::Mul(Box::new(Expr::signal("sum")), Box::new(Expr::signal("b"))),
                },
                WitnessAssignment {
                    target: "y_anchor".to_string(),
                    expr: Expr::Mul(Box::new(Expr::signal("y")), Box::new(Expr::signal("y"))),
                },
            ],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn plonky3_div_program(field: FieldId) -> Program {
    Program {
        name: "plonky3_div".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "den".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "quot".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("quot"),
            rhs: Expr::Div(Box::new(Expr::signal("x")), Box::new(Expr::signal("den"))),
            label: Some("quot".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "quot".to_string(),
                expr: Expr::Div(Box::new(Expr::signal("x")), Box::new(Expr::signal("den"))),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn plonky3_range_program(field: FieldId) -> Program {
    let bits = match field {
        FieldId::Goldilocks => 8,
        FieldId::BabyBear | FieldId::Mersenne31 => 6,
        _ => 4,
    };
    Program {
        name: "plonky3_range".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Range {
                signal: "x".to_string(),
                bits,
                label: Some("x_range".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::signal("x"),
                label: Some("out_eq_x".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::signal("x"),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn inputs(x: i64, y: i64, b: i64) -> BTreeMap<String, FieldElement> {
    let mut out = BTreeMap::new();
    out.insert("x".to_string(), FieldElement::from_i64(x));
    out.insert("y".to_string(), FieldElement::from_i64(y));
    out.insert("b".to_string(), FieldElement::from_i64(b));
    out
}

fn assert_ntt_metadata(metadata: &BTreeMap<String, String>) {
    let accelerator = metadata.get("ntt_accelerator").map(String::as_str);
    assert!(
        matches!(accelerator, Some("cpu") | Some("metal")),
        "expected ntt_accelerator metadata, got {accelerator:?}"
    );
}

#[test]
fn plonky3_roundtrip_equal_and_boolean() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");
        let witness = generate_witness(&program, &inputs(4, 9, 1)).expect("witness should pass");
        let proof = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &proof)
            .expect("verification should pass");
        assert!(ok);
    }
}

#[test]
fn plonky3_roundtrip_with_division() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_div_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");
        let mut inps = BTreeMap::new();
        inps.insert("x".to_string(), FieldElement::from_i64(12));
        inps.insert("den".to_string(), FieldElement::from_i64(3));
        let witness = generate_witness(&program, &inps).expect("witness should pass");
        let proof = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &proof)
            .expect("verification should pass");
        assert!(ok);
    }
}

#[test]
fn plonky3_roundtrip_with_small_range_constraint() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_range_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");
        let mut inps = BTreeMap::new();
        inps.insert("x".to_string(), FieldElement::from_i64(9));
        let witness = generate_witness(&program, &inps).expect("witness should pass");
        let proof = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &proof)
            .expect("verification should pass");
        assert!(ok);
    }
}

#[test]
fn plonky3_range_rejects_overflow_per_field() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_range_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");
        let bits = match field {
            FieldId::Goldilocks => 8_u32,
            FieldId::BabyBear | FieldId::Mersenne31 => 6_u32,
            _ => 4_u32,
        };
        let invalid_value = (1_i64 << bits) + 1;
        let mut inps = BTreeMap::new();
        inps.insert("x".to_string(), FieldElement::from_i64(invalid_value));
        let err = generate_witness(&program, &inps).expect_err("range overflow must fail");
        assert!(
            err.to_string().contains("range constraint violation"),
            "unexpected error for {field}: {err}"
        );

        // Prover should also reject an externally supplied invalid witness.
        let mut bad_witness_values = BTreeMap::new();
        bad_witness_values.insert("x".to_string(), FieldElement::from_i64(invalid_value));
        bad_witness_values.insert("out".to_string(), FieldElement::from_i64(invalid_value));
        let bad_witness = zkf_core::Witness {
            values: bad_witness_values,
        };
        let prove_err = backend
            .prove(&compiled, &bad_witness)
            .expect_err("prover must reject invalid range witness");
        assert!(
            prove_err.to_string().contains("range constraint violation"),
            "unexpected prove error for {field}: {prove_err}"
        );
    }
}

#[test]
fn plonky3_division_by_zero_is_rejected_per_field() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_div_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");

        let mut inputs = BTreeMap::new();
        inputs.insert("x".to_string(), FieldElement::from_i64(12));
        inputs.insert("den".to_string(), FieldElement::from_i64(0));

        let err = generate_witness(&program, &inputs).expect_err("division by zero must fail");
        assert!(
            err.to_string().contains("division by zero"),
            "unexpected witness error for {field}: {err}"
        );

        let mut bad_witness_values = BTreeMap::new();
        bad_witness_values.insert("x".to_string(), FieldElement::from_i64(12));
        bad_witness_values.insert("den".to_string(), FieldElement::from_i64(0));
        bad_witness_values.insert("quot".to_string(), FieldElement::from_i64(0));
        let bad_witness = zkf_core::Witness {
            values: bad_witness_values,
        };
        let prove_err = backend
            .prove(&compiled, &bad_witness)
            .expect_err("prover must reject invalid division witness");
        let rendered = prove_err.to_string();
        assert!(
            rendered.contains("constraint violation")
                || rendered.contains("division by zero")
                || rendered.contains("invalid"),
            "unexpected prove error for {field}: {prove_err}"
        );
    }
}

#[test]
fn plonky3_roundtrip_records_ntt_metadata_per_field() {
    let backend = backend_for(BackendKind::Plonky3);
    for field in [FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31] {
        let program = plonky3_program(field);
        let compiled = backend.compile(&program).expect("compile should pass");
        let witness = generate_witness(&program, &inputs(2, 7, 1)).expect("witness should pass");
        let proof = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &proof)
            .expect("verification should pass");

        assert!(ok);
        assert_ntt_metadata(&proof.metadata);

        if field == FieldId::Mersenne31 {
            assert_eq!(
                proof.metadata.get("ntt_accelerator").map(String::as_str),
                Some("cpu")
            );
            assert!(
                !proof.metadata.contains_key("ntt_fallback_reason"),
                "Circle PCS proofs should not report an NTT fallback reason"
            );
        }
    }
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn plonky3_goldilocks_roundtrip_reports_runtime_ntt_choice() {
    let backend = backend_for(BackendKind::Plonky3);
    let program = plonky3_program(FieldId::Goldilocks);
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &inputs(4, 9, 1)).expect("witness should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let ok = backend
        .verify(&compiled, &proof)
        .expect("verification should pass");

    assert!(ok);
    assert_ntt_metadata(&proof.metadata);

    if zkf_metal::global_context().is_none() {
        assert_eq!(
            proof.metadata.get("ntt_accelerator").map(String::as_str),
            Some("cpu")
        );
        assert_eq!(
            proof
                .metadata
                .get("ntt_fallback_reason")
                .map(String::as_str),
            Some("metal-unavailable")
        );
        return;
    }

    if proof.metadata.get("ntt_accelerator").map(String::as_str) == Some("cpu") {
        let fallback_reason = proof
            .metadata
            .get("ntt_fallback_reason")
            .map(String::as_str);
        assert!(
            matches!(
                fallback_reason,
                Some("below-threshold") | Some("metal-dispatch-failed")
            ),
            "unexpected Goldilocks NTT fallback reason: {fallback_reason:?}"
        );
    }
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn plonky3_goldilocks_narrow_trace_reports_actual_gpu_stage_coverage() {
    let Some(_) = zkf_metal::global_context() else {
        return;
    };

    let backend = backend_for(BackendKind::Plonky3);
    let program = plonky3_program(FieldId::Goldilocks);
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &inputs(4, 9, 1)).expect("witness should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");

    let coverage: GpuStageCoverage = serde_json::from_str(
        proof
            .metadata
            .get("gpu_stage_coverage")
            .expect("gpu stage coverage metadata should exist"),
    )
    .expect("coverage metadata should parse");

    assert_eq!(
        proof.metadata.get("ntt_accelerator").map(String::as_str),
        Some("metal")
    );
    assert_eq!(
        proof.metadata.get("hash_accelerator").map(String::as_str),
        Some("metal")
    );
    assert_eq!(
        proof
            .metadata
            .get("poseidon2_accelerator")
            .map(String::as_str),
        Some("metal")
    );
    assert_eq!(coverage.required_stages, vec!["fft-ntt", "hash-merkle"]);
    assert!(
        coverage.cpu_stages.is_empty(),
        "unexpected cpu stages: {:?}",
        coverage.cpu_stages
    );
    assert_eq!(
        proof.metadata.get("metal_complete").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        proof
            .metadata
            .get("metal_no_cpu_fallback")
            .map(String::as_str),
        Some("true")
    );
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn plonky3_goldilocks_wide_trace_reports_hash_cpu_fallback() {
    let Some(_) = zkf_metal::global_context() else {
        return;
    };

    let backend = backend_for(BackendKind::Plonky3);
    let program = plonky3_range_program(FieldId::Goldilocks);
    let compiled = backend.compile(&program).expect("compile should pass");
    let mut inps = BTreeMap::new();
    inps.insert("x".to_string(), FieldElement::from_i64(9));
    let witness = generate_witness(&program, &inps).expect("witness should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");

    let coverage: GpuStageCoverage = serde_json::from_str(
        proof
            .metadata
            .get("gpu_stage_coverage")
            .expect("gpu stage coverage metadata should exist"),
    )
    .expect("coverage metadata should parse");

    assert_eq!(
        proof.metadata.get("ntt_accelerator").map(String::as_str),
        Some("metal")
    );
    assert_eq!(
        proof.metadata.get("hash_accelerator").map(String::as_str),
        Some("cpu")
    );
    assert_eq!(
        proof
            .metadata
            .get("hash_fallback_reason")
            .map(String::as_str),
        Some("trace-width-exceeds-metal-mmcs-limit")
    );
    assert_eq!(coverage.required_stages, vec!["fft-ntt", "hash-merkle"]);
    assert_eq!(coverage.metal_stages, vec!["fft-ntt"]);
    assert_eq!(coverage.cpu_stages, vec!["hash-merkle"]);
    assert_eq!(
        proof.metadata.get("metal_complete").map(String::as_str),
        Some("false")
    );
}

#[test]
fn plonky3_compile_zir_and_prove_zir_route_through_ir_v2() {
    let backend = backend_for(BackendKind::Plonky3);
    let program = plonky3_div_program(FieldId::Goldilocks);
    let zir = program_v2_to_zir(&program);
    let compiled = backend.compile_zir(&zir).expect("compile_zir should pass");

    assert_ne!(
        compiled
            .metadata
            .get("zir_native_compile")
            .map(String::as_str),
        Some("true"),
        "plonky3 should no longer keep a separate theorem-bearing ZIR-native compile path",
    );

    let mut inps = BTreeMap::new();
    inps.insert("x".to_string(), FieldElement::from_i64(21));
    inps.insert("den".to_string(), FieldElement::from_i64(3));
    let witness = generate_witness(&program, &inps).expect("witness should pass");
    let proof = backend
        .prove_zir(&zir, &compiled, &witness)
        .expect("prove_zir should pass");
    let ok = backend
        .verify_zir(&zir, &compiled, &proof)
        .expect("verify_zir should pass");
    assert!(ok);
}
