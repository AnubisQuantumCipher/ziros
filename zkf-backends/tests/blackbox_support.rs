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

use acir::FieldElement as AcirFieldElement;
use acvm_blackbox_solver::BlackBoxFunctionSolver;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::thread;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    Witness, WitnessPlan,
};

fn with_dev_groth16<T>(f: impl FnOnce() -> T) -> T {
    zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), f)
}

fn run_with_large_stack<T>(f: impl FnOnce() -> T + Send + 'static) -> T
where
    T: Send + 'static,
{
    thread::Builder::new()
        .name("zkf-blackbox-support".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .expect("spawn blackbox support test thread")
        .join()
        .expect("join blackbox support test thread")
}

fn sha256_program(field: FieldId) -> Program {
    let mut signals = vec![Signal {
        name: "input".to_string(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    }];
    for i in 0..32 {
        signals.push(Signal {
            name: format!("out_{i}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
    }
    Program {
        name: "sha256_runtime_validation".to_string(),
        field,
        signals,
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::Sha256,
            inputs: vec![Expr::Signal("input".to_string())],
            outputs: (0..32).map(|i| format!("out_{i}")).collect(),
            params: BTreeMap::from([("input_num_bits".to_string(), "8".to_string())]),
            label: Some("sha256".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn sha256_witness(input_byte: u8, correct_digest: bool) -> Witness {
    let mut values = BTreeMap::new();
    values.insert(
        "input".to_string(),
        FieldElement::from_i64(input_byte as i64),
    );
    let digest = Sha256::digest([input_byte]);
    for (idx, byte) in digest.iter().enumerate() {
        let value = if correct_digest {
            *byte
        } else {
            byte.wrapping_add(1)
        };
        values.insert(format!("out_{idx}"), FieldElement::from_i64(value as i64));
    }
    Witness { values }
}

fn poseidon_program(field: FieldId) -> Program {
    Program {
        name: "poseidon_runtime_validation".to_string(),
        field,
        signals: vec![
            Signal {
                name: "in_0".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_1".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_2".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "in_3".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_0".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_1".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_2".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out_3".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: vec![
                Expr::Signal("in_0".to_string()),
                Expr::Signal("in_1".to_string()),
                Expr::Signal("in_2".to_string()),
                Expr::Signal("in_3".to_string()),
            ],
            outputs: vec![
                "out_0".to_string(),
                "out_1".to_string(),
                "out_2".to_string(),
                "out_3".to_string(),
            ],
            params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
            label: Some("poseidon".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn poseidon_witness(valid: bool) -> Witness {
    let mut values = BTreeMap::new();
    let in0 = FieldElement::from_i64(3);
    let in1 = FieldElement::from_i64(9);
    let in2 = FieldElement::from_i64(1);
    let in3 = FieldElement::from_i64(2);
    values.insert("in_0".to_string(), in0.clone());
    values.insert("in_1".to_string(), in1.clone());
    values.insert("in_2".to_string(), in2.clone());
    values.insert("in_3".to_string(), in3.clone());

    let solver = Bn254BlackBoxSolver::default();
    let acir_inputs = [in0, in1, in2, in3]
        .into_iter()
        .map(|value| {
            AcirFieldElement::try_from_str(&value.to_decimal_string()).expect("bn254 field literal")
        })
        .collect::<Vec<_>>();
    let mut expected = solver
        .poseidon2_permutation(&acir_inputs, 4)
        .expect("poseidon reference evaluation");
    if !valid {
        expected[0] += AcirFieldElement::from(1u128);
    }
    values.insert(
        "out_0".to_string(),
        FieldElement::new(expected[0].to_string()),
    );
    values.insert(
        "out_1".to_string(),
        FieldElement::new(expected[1].to_string()),
    );
    values.insert(
        "out_2".to_string(),
        FieldElement::new(expected[2].to_string()),
    );
    values.insert(
        "out_3".to_string(),
        FieldElement::new(expected[3].to_string()),
    );
    Witness { values }
}

fn pedersen_program(field: FieldId) -> Program {
    Program {
        name: "pedersen_field_guard".to_string(),
        field,
        signals: vec![
            Signal {
                name: "in".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::Pedersen,
            inputs: vec![Expr::Signal("in".to_string())],
            outputs: vec!["out".to_string()],
            params: BTreeMap::new(),
            label: Some("pedersen".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn schnorr_program(field: FieldId) -> Program {
    Program {
        name: "schnorr_field_guard".to_string(),
        field,
        signals: vec![
            Signal {
                name: "in".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::SchnorrVerify,
            inputs: vec![Expr::Signal("in".to_string())],
            outputs: vec!["out".to_string()],
            params: BTreeMap::new(),
            label: Some("schnorr".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn recursive_marker_program(field: FieldId) -> Program {
    let statement_digest =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let verification_key_digest =
        "2222222222222222222222222222222222222222222222222222222222222222".to_string();
    let public_input_commitment =
        "3333333333333333333333333333333333333333333333333333333333333333".to_string();
    let program_digest =
        "4444444444444444444444444444444444444444444444444444444444444444".to_string();
    let proof_digest =
        "5555555555555555555555555555555555555555555555555555555555555555".to_string();
    let mut statement_digest_v2 = recursive_marker_statement_v2_digest(
        "arkworks-groth16",
        &program_digest,
        &proof_digest,
        &verification_key_digest,
        &public_input_commitment,
    );
    if statement_digest_v2.is_empty() {
        statement_digest_v2 = "00".repeat(32);
    }

    Program {
        name: "recursive_marker_runtime_validation".to_string(),
        field,
        signals: vec![
            Signal {
                name: "statement_fe".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "statement_anchor".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "vk_fe".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "vk_anchor".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "pi_fe".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "pi_anchor".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("statement_anchor"),
                rhs: Expr::Mul(
                    Box::new(Expr::signal("statement_fe")),
                    Box::new(Expr::signal("statement_fe")),
                ),
                label: Some("statement_anchor".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("vk_anchor"),
                rhs: Expr::Mul(
                    Box::new(Expr::signal("vk_fe")),
                    Box::new(Expr::signal("vk_fe")),
                ),
                label: Some("vk_anchor".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::signal("pi_anchor"),
                rhs: Expr::Mul(
                    Box::new(Expr::signal("pi_fe")),
                    Box::new(Expr::signal("pi_fe")),
                ),
                label: Some("pi_anchor".to_string()),
            },
            Constraint::BlackBox {
                op: BlackBoxOp::RecursiveAggregationMarker,
                inputs: vec![
                    Expr::Signal("statement_fe".to_string()),
                    Expr::Signal("vk_fe".to_string()),
                    Expr::Signal("pi_fe".to_string()),
                ],
                outputs: Vec::new(),
                params: BTreeMap::from([
                    ("statement_digest".to_string(), statement_digest),
                    (
                        "verification_key_digest".to_string(),
                        verification_key_digest,
                    ),
                    (
                        "public_input_commitment".to_string(),
                        public_input_commitment,
                    ),
                    (
                        "carried_backend".to_string(),
                        "arkworks-groth16".to_string(),
                    ),
                    ("program_digest".to_string(), program_digest),
                    ("proof_digest".to_string(), proof_digest),
                    ("statement_digest_v2".to_string(), statement_digest_v2),
                ]),
                label: Some("recursive_marker".to_string()),
            },
        ],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn recursive_marker_witness(valid: bool) -> Witness {
    let mut values = BTreeMap::new();
    let statement = BigInt::parse_bytes(
        b"1111111111111111111111111111111111111111111111111111111111111111",
        16,
    )
    .expect("statement digest");
    let vk = BigInt::parse_bytes(
        b"2222222222222222222222222222222222222222222222222222222222222222",
        16,
    )
    .expect("vk digest");
    let pi = BigInt::parse_bytes(
        b"3333333333333333333333333333333333333333333333333333333333333333",
        16,
    )
    .expect("public input digest");

    values.insert(
        "statement_fe".to_string(),
        FieldElement::from_bigint_with_field(statement.clone(), FieldId::Bn254),
    );
    values.insert(
        "statement_anchor".to_string(),
        FieldElement::from_bigint_with_field(&statement * &statement, FieldId::Bn254),
    );
    values.insert(
        "vk_fe".to_string(),
        FieldElement::from_bigint_with_field(vk.clone(), FieldId::Bn254),
    );
    values.insert(
        "vk_anchor".to_string(),
        FieldElement::from_bigint_with_field(&vk * &vk, FieldId::Bn254),
    );
    values.insert(
        "pi_fe".to_string(),
        if valid {
            FieldElement::from_bigint_with_field(pi, FieldId::Bn254)
        } else {
            FieldElement::from_i64(0)
        },
    );
    let pi_value = values.get("pi_fe").expect("pi witness").as_bigint();
    values.insert(
        "pi_anchor".to_string(),
        FieldElement::from_bigint_with_field(&pi_value * &pi_value, FieldId::Bn254),
    );
    Witness { values }
}

fn recursive_marker_statement_v2_digest(
    carried_backend: &str,
    program_digest: &str,
    proof_digest: &str,
    verification_key_digest: &str,
    public_input_commitment: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"zkf-recursive-marker-statement-v2");
    hasher.update(carried_backend.as_bytes());
    hasher.update(program_digest.as_bytes());
    hasher.update(proof_digest.as_bytes());
    hasher.update(verification_key_digest.as_bytes());
    hasher.update(public_input_commitment.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[test]
fn native_backends_accept_required_blackbox_constraints() {
    run_with_large_stack(|| {
        // SHA-256 lowering requires exactly 32 output signals, so use the
        // proper sha256_program() helper instead of the generic blackbox_program().
        let cases = [
            (BackendKind::ArkworksGroth16, FieldId::Bn254),
            (BackendKind::Plonky3, FieldId::Goldilocks),
        ];

        for (backend_kind, field) in cases {
            let backend = backend_for(backend_kind);
            let program = sha256_program(field);
            let compile = || {
                backend.compile(&program).unwrap_or_else(|err| {
                    panic!(
                        "compile must accept required blackbox constraints for backend {}: {}",
                        backend_kind, err
                    )
                })
            };
            if backend_kind == BackendKind::ArkworksGroth16 {
                with_dev_groth16(compile);
            } else {
                compile();
            }
        }
    });
}

#[test]
#[ignore = "Poseidon blackbox lowering produces ~1600 constraints with high memory usage; run explicitly"]
fn native_backends_accept_poseidon_blackbox_constraints_on_bn254() {
    let cases = [
        (BackendKind::ArkworksGroth16, FieldId::Bn254),
        (BackendKind::MidnightCompact, FieldId::Bn254),
    ];

    for (backend_kind, field) in cases {
        let backend = backend_for(backend_kind);
        let program = poseidon_program(field);
        backend.compile(&program).unwrap_or_else(|err| {
            panic!(
                "compile must accept poseidon blackbox constraints for backend {}: {}",
                backend_kind, err
            )
        });
    }
}

#[test]
fn native_backends_accept_recursive_aggregation_marker_blackbox() {
    let cases = [
        (BackendKind::ArkworksGroth16, FieldId::Bn254),
        (BackendKind::Halo2, FieldId::PastaFp),
        (BackendKind::MidnightCompact, FieldId::Bn254),
    ];

    for (backend_kind, field) in cases {
        let backend = backend_for(backend_kind);
        let program = recursive_marker_program(field);
        let compile = || {
            backend.compile(&program).unwrap_or_else(|err| {
                panic!(
                    "compile must accept recursive_aggregation_marker for backend {}: {}",
                    backend_kind, err
                )
            })
        };
        if backend_kind == BackendKind::ArkworksGroth16 {
            with_dev_groth16(compile);
        } else {
            compile();
        }
    }
}

#[test]
fn plonky3_rejects_unlowered_recursive_aggregation_marker_blackbox_with_clear_error() {
    let backend = backend_for(BackendKind::Plonky3);
    let program = recursive_marker_program(FieldId::Goldilocks);
    let err = backend
        .compile(&program)
        .expect_err("plonky3 should reject metadata marker blackboxes at synthesis time");
    let message = err.to_string();
    assert!(
        message.contains("must be lowered before plonky3 synthesis"),
        "unexpected plonky3 recursive marker error: {message}"
    );
}

#[test]
fn native_backend_rejects_invalid_recursive_marker_witness_during_prove() {
    run_with_large_stack(|| {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let program = recursive_marker_program(FieldId::Bn254);
        let compiled = with_dev_groth16(|| {
            backend.compile(&program).unwrap_or_else(|err| {
                panic!(
                    "compile failed for backend {}: {err}",
                    BackendKind::ArkworksGroth16
                )
            })
        });
        let bad_witness = recursive_marker_witness(false);
        let err = with_dev_groth16(|| backend.prove(&compiled, &bad_witness))
            .expect_err("prove must reject invalid recursive marker inputs");
        let message = err.to_string();
        assert!(
            message.contains("recursive_aggregation_marker") || message.contains("blackbox"),
            "unexpected error message for backend {}: {message}",
            BackendKind::ArkworksGroth16
        );
    });
}

#[test]
fn native_backend_accepts_valid_recursive_marker_witness_during_prove() {
    run_with_large_stack(|| {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let program = recursive_marker_program(FieldId::Bn254);
        let compiled = with_dev_groth16(|| {
            backend.compile(&program).unwrap_or_else(|err| {
                panic!(
                    "compile failed for backend {}: {err}",
                    BackendKind::ArkworksGroth16
                )
            })
        });
        let witness = recursive_marker_witness(true);
        let artifact =
            with_dev_groth16(|| backend.prove(&compiled, &witness)).unwrap_or_else(|err| {
                panic!(
                    "prove failed for backend {}: {err}",
                    BackendKind::ArkworksGroth16
                )
            });
        let ok = backend.verify(&compiled, &artifact).unwrap_or_else(|err| {
            panic!(
                "verify failed for backend {}: {err}",
                BackendKind::ArkworksGroth16
            )
        });
        assert!(
            ok,
            "arkworks verify must succeed for valid recursive marker witness"
        );
    });
}

#[test]
fn native_backend_rejects_recursive_marker_with_mismatched_statement_v2_param() {
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let mut program = recursive_marker_program(FieldId::Bn254);
    let marker_params = program
        .constraints
        .iter_mut()
        .find_map(|constraint| match constraint {
            Constraint::BlackBox { params, .. } => Some(params),
            _ => None,
        })
        .expect("recursive marker constraint");
    marker_params.insert("statement_digest_v2".to_string(), "00".repeat(32));
    let compiled = with_dev_groth16(|| {
        backend.compile(&program).unwrap_or_else(|err| {
            panic!(
                "compile failed for backend {}: {err}",
                BackendKind::ArkworksGroth16
            )
        })
    });
    let witness = recursive_marker_witness(true);
    let err = with_dev_groth16(|| backend.prove(&compiled, &witness))
        .expect_err("prove must reject mismatched statement_digest_v2");
    let message = err.to_string();
    assert!(
        message.contains("statement_digest_v2"),
        "unexpected error message for backend {}: {message}",
        BackendKind::ArkworksGroth16
    );
}

#[test]
fn native_backends_reject_invalid_sha256_witness_during_prove() {
    run_with_large_stack(|| {
        let cases = [
            (BackendKind::ArkworksGroth16, FieldId::Bn254),
            (BackendKind::Plonky3, FieldId::Goldilocks),
        ];

        for (backend_kind, field) in cases {
            let backend = backend_for(backend_kind);
            let program = sha256_program(field);
            let compile = || {
                backend.compile(&program).unwrap_or_else(|err| {
                    panic!("compile failed for backend {backend_kind}: {err}")
                })
            };
            let compiled = if backend_kind == BackendKind::ArkworksGroth16 {
                with_dev_groth16(compile)
            } else {
                compile()
            };
            let bad_witness = sha256_witness(7, false);
            let prove = || backend.prove(&compiled, &bad_witness);
            let err = if backend_kind == BackendKind::ArkworksGroth16 {
                with_dev_groth16(prove)
            } else {
                prove()
            }
            .expect_err("prove must reject invalid sha256 outputs");
            let message = err.to_string();
            assert!(
                message.contains("sha256") || message.contains("blackbox"),
                "unexpected error message for backend {backend_kind}: {message}"
            );
        }
    });
}

#[test]
fn native_backends_accept_valid_sha256_witness_during_prove() {
    run_with_large_stack(|| {
        let backend = backend_for(BackendKind::Plonky3);
        let program = sha256_program(FieldId::Goldilocks);
        let compiled = backend.compile(&program).unwrap_or_else(|err| {
            panic!("compile failed for backend {}: {err}", BackendKind::Plonky3)
        });
        let witness = sha256_witness(7, true);
        let artifact = backend.prove(&compiled, &witness).unwrap_or_else(|err| {
            panic!("prove failed for backend {}: {err}", BackendKind::Plonky3)
        });
        let ok = backend.verify(&compiled, &artifact).unwrap_or_else(|err| {
            panic!("verify failed for backend {}: {err}", BackendKind::Plonky3)
        });
        assert!(ok, "plonky3 verify must succeed for valid sha256 witness");
    });
}

#[test]
#[ignore = "Poseidon blackbox lowering produces ~1600 constraints with high memory usage; run explicitly"]
fn native_backend_rejects_invalid_poseidon_witness_during_prove() {
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = poseidon_program(FieldId::Bn254);
    let compiled = backend.compile(&program).unwrap_or_else(|err| {
        panic!(
            "compile failed for backend {}: {err}",
            BackendKind::ArkworksGroth16
        )
    });
    let bad_witness = poseidon_witness(false);
    let err = backend
        .prove(&compiled, &bad_witness)
        .expect_err("prove must reject invalid poseidon outputs");
    let message = err.to_string();
    assert!(
        message.contains("poseidon") || message.contains("blackbox"),
        "unexpected error message for backend {}: {message}",
        BackendKind::ArkworksGroth16
    );
}

#[test]
#[ignore = "Poseidon blackbox lowering produces ~1600 constraints with high memory usage; run explicitly"]
fn native_backend_accepts_valid_poseidon_witness_during_prove() {
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = poseidon_program(FieldId::Bn254);
    let compiled = backend.compile(&program).unwrap_or_else(|err| {
        panic!(
            "compile failed for backend {}: {err}",
            BackendKind::ArkworksGroth16
        )
    });
    let witness = poseidon_witness(true);
    let artifact = backend.prove(&compiled, &witness).unwrap_or_else(|err| {
        panic!(
            "prove failed for backend {}: {err}",
            BackendKind::ArkworksGroth16
        )
    });
    let ok = backend.verify(&compiled, &artifact).unwrap_or_else(|err| {
        panic!(
            "verify failed for backend {}: {err}",
            BackendKind::ArkworksGroth16
        )
    });
    assert!(
        ok,
        "arkworks verify must succeed for valid poseidon witness"
    );
}

#[test]
fn native_backend_rejects_pedersen_and_schnorr_outside_bn254() {
    // With BlackBox lowering at compile time, pedersen/schnorr on non-BN254
    // fields are rejected during compile (lowering), not during prove.
    let backend = backend_for(BackendKind::Plonky3);

    for program in [
        pedersen_program(FieldId::Goldilocks),
        schnorr_program(FieldId::Goldilocks),
    ] {
        let op_name = match &program.constraints[0] {
            Constraint::BlackBox { op, .. } => op.as_str(),
            _ => "unknown",
        };
        let err = backend
            .compile(&program)
            .expect_err("compile must reject bn254-only blackbox on non-bn254 field");
        let message = err.to_string();
        assert!(
            message.contains("BN254") || message.contains("bn254"),
            "expected bn254 guard for {op_name}, got: {message}"
        );
    }
}
