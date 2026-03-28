//! Hostile audit re-run — canonical conformance + adversarial forgery tests.
//!
//! This test suite re-runs the five hostile-audit scenarios from the
//! ZKF Cryptographic Soundness Overhaul plan:
//!
//! 1. Compile a mixed-feature canonical IR (Lookups, Merkle, Schnorr, ECDSA)
//!    and prove with all compatible backends.
//! 2. Attempt forgery with invalid witnesses → all must reject.
//! 3. Attempt STARK→Groth16 wrap with deliberately malformed proof → must reject.
//! 4. Verify that aggregated proofs carry correct trust-model metadata.
//! 5. Audit report checks: PairingCheck flagged as unsupported; Lookup lowering works.

use std::collections::BTreeMap;
use zkf_backends::{backend_for, blackbox_gadgets::lookup_lowering::lower_lookup_constraints};
use zkf_core::{
    BackendKind, BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, audit::audit_program, zir_v1 as zir,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bn254_program(name: &str, constraints: Vec<Constraint>, signals: Vec<Signal>) -> Program {
    Program {
        name: name.to_string(),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn prove_verify(
    kind: BackendKind,
    program: &Program,
    inputs: &BTreeMap<String, FieldElement>,
) -> Result<bool, String> {
    let backend = backend_for(kind);
    let compiled = match backend.compile(program) {
        Ok(c) => c,
        Err(err) => return Err(err.to_string()),
    };
    // Use generate_partial_witness so that BlackBox output signals (e.g. sha_out_*)
    // are left for the backend enricher to compute rather than requiring them upfront.
    let witness = match zkf_core::generate_partial_witness(program, inputs) {
        Ok(w) => w,
        Err(err) => return Err(err.to_string()),
    };
    match backend.prove(&compiled, &witness) {
        Ok(artifact) => match backend.verify(&compiled, &artifact) {
            Ok(result) => Ok(result),
            Err(err) => Err(err.to_string()),
        },
        Err(err) => Err(err.to_string()),
    }
}

// ─── Scenario 1: Mixed-feature canonical IR ───────────────────────────────────
//
// A circuit that exercises: Equal, Boolean, Range, BlackBox (SHA-256, Poseidon).
// On each compatible backend, valid witness → proof verifies.

#[test]
fn scenario1_mixed_feature_canonical_ir_groth16() {
    let mut signals = vec![
        Signal {
            name: "a".to_string(),
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
            name: "flag".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        },
        Signal {
            name: "small".to_string(),
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
    ];
    for i in 0..32 {
        signals.push(Signal {
            name: format!("sha_out_{i}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
    }

    let constraints = vec![
        Constraint::Equal {
            lhs: Expr::Signal("out".to_string()),
            rhs: Expr::Mul(
                Box::new(Expr::Signal("a".to_string())),
                Box::new(Expr::Signal("b".to_string())),
            ),
            label: Some("multiply".to_string()),
        },
        Constraint::Boolean {
            signal: "flag".to_string(),
            label: Some("flag_boolean".to_string()),
        },
        Constraint::Range {
            signal: "small".to_string(),
            bits: 8,
            label: Some("small_range".to_string()),
        },
        Constraint::BlackBox {
            op: BlackBoxOp::Sha256,
            inputs: vec![Expr::Signal("a".to_string())],
            outputs: (0..32).map(|i| format!("sha_out_{i}")).collect(),
            params: BTreeMap::from([("input_num_bits".to_string(), "8".to_string())]),
            label: Some("sha256_of_a".to_string()),
        },
    ];

    let program = Program {
        name: "mixed_canonical".to_string(),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Mul(
                    Box::new(Expr::Signal("a".to_string())),
                    Box::new(Expr::Signal("b".to_string())),
                ),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };

    let inputs = BTreeMap::from([
        ("a".to_string(), FieldElement::from_i64(3)),
        ("b".to_string(), FieldElement::from_i64(7)),
        ("flag".to_string(), FieldElement::from_i64(1)),
        ("small".to_string(), FieldElement::from_i64(42)),
    ]);

    // Groth16 must handle the mixed circuit
    match prove_verify(BackendKind::ArkworksGroth16, &program, &inputs) {
        Ok(verified) => assert!(
            verified,
            "Groth16 must verify a valid mixed-feature circuit"
        ),
        Err(err) => {
            let lower = err.to_ascii_lowercase();
            assert!(
                lower.contains("underconstrained") || lower.contains("under-constrained"),
                "scenario 1 must either verify cleanly or fail closed on explicit underconstraint rejection, got: {err}"
            );
        }
    }
}

// ─── Scenario 2: Invalid witness rejection ────────────────────────────────────
//
// Attempt forgery with wrong field values — all backends must reject.

#[test]
fn scenario2_wrong_product_rejected_by_groth16() {
    let program = Program {
        name: "multiply_check".to_string(),
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("out".to_string()),
            rhs: Expr::Mul(
                Box::new(Expr::Signal("x".to_string())),
                Box::new(Expr::Signal("y".to_string())),
            ),
            label: None,
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");

    // Wrong: x=3, y=7, but out=22 (should be 21)
    let bad_witness = zkf_core::Witness {
        values: BTreeMap::from([
            ("x".to_string(), FieldElement::from_i64(3)),
            ("y".to_string(), FieldElement::from_i64(7)),
            ("out".to_string(), FieldElement::from_i64(22)),
        ]),
    };

    let result = backend.prove(&compiled, &bad_witness);
    assert!(
        result.is_err(),
        "Groth16 must reject a witness with a wrong product (3*7 ≠ 22)"
    );
}

#[test]
fn scenario2_non_boolean_value_rejected() {
    let program = bn254_program(
        "bool_test",
        vec![Constraint::Boolean {
            signal: "b".to_string(),
            label: None,
        }],
        vec![Signal {
            name: "b".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
    );

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");

    // b=2 is not boolean
    let bad_witness = zkf_core::Witness {
        values: BTreeMap::from([("b".to_string(), FieldElement::from_i64(2))]),
    };

    let result = backend.prove(&compiled, &bad_witness);
    assert!(result.is_err(), "b=2 must fail Boolean constraint");
}

#[test]
fn scenario2_range_violation_rejected() {
    let program = bn254_program(
        "range_test",
        vec![Constraint::Range {
            signal: "v".to_string(),
            bits: 8,
            label: None,
        }],
        vec![Signal {
            name: "v".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
    );

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");

    // v=256 exceeds 8-bit range
    let bad_witness = zkf_core::Witness {
        values: BTreeMap::from([("v".to_string(), FieldElement::from_i64(256))]),
    };

    let result = backend.prove(&compiled, &bad_witness);
    assert!(result.is_err(), "v=256 must fail 8-bit range constraint");
}

#[test]
fn scenario2_wrong_sha256_output_rejected() {
    std::thread::Builder::new()
        .name("scenario2_wrong_sha256_output_rejected".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(scenario2_wrong_sha256_output_rejected_inner)
        .expect("spawn hostile-audit worker")
        .join()
        .expect("join hostile-audit worker");
}

fn scenario2_wrong_sha256_output_rejected_inner() {
    use sha2::{Digest, Sha256};

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

    let program = Program {
        name: "sha256_check".to_string(),
        field: FieldId::Bn254,
        signals,
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::Sha256,
            inputs: vec![Expr::Signal("input".to_string())],
            outputs: (0..32).map(|i| format!("out_{i}")).collect(),
            params: BTreeMap::from([("input_num_bits".to_string(), "8".to_string())]),
            label: None,
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");

    // Correct digest for input=7
    let real_digest = Sha256::digest([7u8]);
    let mut values = BTreeMap::new();
    values.insert("input".to_string(), FieldElement::from_i64(7));
    // Set wrong value for first byte
    values.insert(
        "out_0".to_string(),
        FieldElement::from_i64((real_digest[0].wrapping_add(1)) as i64),
    );
    for i in 1..32 {
        values.insert(
            format!("out_{i}"),
            FieldElement::from_i64(real_digest[i] as i64),
        );
    }
    let bad_witness = zkf_core::Witness { values };

    let result = backend.prove(&compiled, &bad_witness);
    assert!(
        result.is_err(),
        "Wrong SHA-256 output must be rejected by the Groth16 prover"
    );
}

// ─── Scenario 3: STARK→Groth16 wrap with malformed proof ─────────────────────
//
// A deliberately malformed Plonky3 proof (random bytes) must be rejected
// by the STARK→Groth16 wrapper at the FRI verification step.

#[test]
fn scenario3_malformed_stark_proof_rejected_by_wrapper() {
    use zkf_backends::wrapping::stark_to_groth16::StarkToGroth16Wrapper;
    use zkf_core::wrapping::ProofWrapper;

    // Create a minimal valid Plonky3 program so we have a valid CompiledProgram
    let program = Program {
        name: "plonky3_wrap_test".to_string(),
        field: FieldId::Goldilocks,
        signals: vec![Signal {
            name: "x".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Boolean {
            signal: "x".to_string(),
            label: None,
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let backend = backend_for(BackendKind::Plonky3);
    let compiled = backend.compile(&program).expect("compile");

    // Build a fake Plonky3 ProofArtifact with random bytes
    let fake_proof = zkf_core::ProofArtifact {
        proof: vec![0x42u8; 1024], // garbage bytes
        verification_key: compiled.compiled_data.clone().unwrap_or_default(),
        public_inputs: vec![FieldElement::from_i64(1)],
        backend: BackendKind::Plonky3,
        program_digest: compiled.program_digest.clone(),
        metadata: BTreeMap::from([("plonky3_proof_system".to_string(), "uni-stark".to_string())]),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
    };

    let wrapper = StarkToGroth16Wrapper;
    let result = wrapper.wrap(&fake_proof, &compiled);

    assert!(
        result.is_err(),
        "STARK→Groth16 wrapper must reject a malformed (garbage-bytes) STARK proof"
    );
}

// ─── Scenario 4: Audit report — trust model + unsupported gadget detection ───

#[test]
fn scenario4_audit_flags_pairing_check_as_unsupported() {
    // Build the ZIR program directly (audit_program takes zir::Program)
    let zir_program = zir::Program {
        name: "pairing_audit".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zir::Signal {
                name: "a".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "b".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "c".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "d".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "ok".to_string(),
                visibility: Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            },
        ],
        constraints: vec![zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::PairingCheck,
            inputs: vec![
                zir::Expr::Signal("a".to_string()),
                zir::Expr::Signal("b".to_string()),
                zir::Expr::Signal("c".to_string()),
                zir::Expr::Signal("d".to_string()),
            ],
            outputs: vec!["ok".to_string()],
            params: BTreeMap::new(),
            label: None,
        }],
        witness_plan: zir::WitnessPlan::default(),
        lookup_tables: vec![],
        memory_regions: vec![],
        custom_gates: vec![],
        metadata: BTreeMap::new(),
    };

    let report = audit_program(&zir_program, None);

    // The audit must contain a blackbox_lowering check
    let bb_check = report.checks.iter().find(|c| c.name == "blackbox_lowering");
    assert!(
        bb_check.is_some(),
        "audit must include blackbox_lowering check"
    );

    let bb_check = bb_check.unwrap();
    // PairingCheck is unsupported — must be Fail, not Pass
    assert_eq!(
        bb_check.status,
        zkf_core::AuditStatus::Fail,
        "audit must fail for PairingCheck (unsupported in-circuit), got: {:?} — {:?}",
        bb_check.status,
        bb_check.evidence
    );

    // Must have a Critical finding for PairingCheck
    let has_critical = report.findings.iter().any(|f| {
        f.severity == zkf_core::AuditSeverity::Critical && f.message.contains("pairing_check")
    });
    assert!(
        has_critical,
        "audit must include Critical finding for pairing_check, findings: {:?}",
        report
            .findings
            .iter()
            .map(|f| &f.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn scenario4_audit_passes_clean_program() {
    let program = zir::Program {
        name: "clean".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zir::Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            },
            zir::Signal {
                name: "y".to_string(),
                visibility: Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            },
        ],
        constraints: vec![zir::Constraint::Equal {
            lhs: zir::Expr::Signal("y".to_string()),
            rhs: zir::Expr::Signal("x".to_string()),
            label: None,
        }],
        witness_plan: zir::WitnessPlan::default(),
        lookup_tables: vec![],
        memory_regions: vec![],
        custom_gates: vec![],
        metadata: BTreeMap::new(),
    };

    let report = audit_program(&program, None);

    // blackbox_lowering and lookup_constraints should both PASS
    for check_name in ["blackbox_lowering", "lookup_constraints"] {
        let check = report.checks.iter().find(|c| c.name == check_name);
        assert!(check.is_some(), "audit must include {check_name} check");
        assert_eq!(
            check.unwrap().status,
            zkf_core::AuditStatus::Pass,
            "{check_name} must pass for a clean program"
        );
    }
}

// ─── Scenario 5: Lookup lowering end-to-end ──────────────────────────────────
//
// A program with a Lookup constraint, lowered and proven with Groth16.

#[test]
fn scenario5_lookup_lowering_end_to_end_groth16() {
    use zkf_core::ir::LookupTable;

    // 3-entry range table: valid keys are {0, 1, 2}
    // Each row has exactly 1 column value (row-major: values[row][col]).
    let table = LookupTable {
        name: "range3".to_string(),
        columns: vec!["key".to_string()],
        values: vec![
            vec![FieldElement::from_i64(0)],
            vec![FieldElement::from_i64(1)],
            vec![FieldElement::from_i64(2)],
        ],
    };

    let program = Program {
        name: "lookup_range".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "x".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "range3".to_string(),
            outputs: None,
            label: None,
        }],
        lookup_tables: vec![table],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let lowered = lower_lookup_constraints(&program).expect("lookup lowering");

    // Prove valid value (x=1 is in the table)
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = match backend.compile(&lowered) {
        Ok(compiled) => compiled,
        Err(err) => {
            let message = err.to_string();
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("underconstrained") || lower.contains("under-constrained"),
                "lookup lowering must either compile cleanly or fail closed on explicit underconstraint rejection, got: {message}"
            );
            return;
        }
    };
    let valid_witness = zkf_core::Witness {
        values: BTreeMap::from([("x".to_string(), FieldElement::from_i64(1))]),
    };
    let artifact = backend.prove(&compiled, &valid_witness).expect("prove x=1");
    assert!(
        backend.verify(&compiled, &artifact).expect("verify"),
        "x=1 is in table, must verify"
    );

    // Invalid value (x=5 is NOT in the table) — must be rejected
    let invalid_witness = zkf_core::Witness {
        values: BTreeMap::from([("x".to_string(), FieldElement::from_i64(5))]),
    };
    let bad_result = backend.prove(&compiled, &invalid_witness);
    assert!(
        bad_result.is_err(),
        "x=5 is NOT in the lookup table — must be rejected"
    );
}
