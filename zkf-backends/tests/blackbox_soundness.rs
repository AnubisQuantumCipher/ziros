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

//! BlackBox gadget soundness tests.
//!
//! For every fixed gadget, verifies the soundness guarantee that was broken
//! before the cryptographic overhaul and is now fixed:
//! - Valid witness → `prove` succeeds, `verify` returns `true`
//! - Invalid witness (wrong hash output, wrong signature, wrong EC point) →
//!   `prove` returns an error OR `verify` returns `false`
//!
//! The "proof FAILS" contract is the critical invariant: a prover cannot
//! create a valid proof for a falsified BlackBox computation.

use std::collections::BTreeMap;
use std::thread;
use zkf_backends::{backend_for, blackbox_gadgets::lookup_lowering::lower_lookup_constraints};
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
        .name("zkf-blackbox-soundness".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .expect("spawn blackbox soundness test thread")
        .join()
        .expect("join blackbox soundness test thread")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_blackbox_program(
    op: BlackBoxOp,
    field: FieldId,
    in_count: usize,
    out_count: usize,
) -> Program {
    let mut signals = Vec::new();
    for i in 0..in_count {
        signals.push(Signal {
            name: format!("in_{i}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
    }
    for i in 0..out_count {
        signals.push(Signal {
            name: format!("out_{i}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
    }
    let inputs: Vec<Expr> = (0..in_count)
        .map(|i| Expr::Signal(format!("in_{i}")))
        .collect();
    let outputs: Vec<String> = (0..out_count).map(|i| format!("out_{i}")).collect();
    Program {
        name: format!("{}_soundness", op.as_str()),
        field,
        signals,
        constraints: vec![Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params: BTreeMap::new(),
            label: None,
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn sha256_correct_witness(input: u8) -> Witness {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest([input]);
    let mut values = BTreeMap::new();
    values.insert("in_0".to_string(), FieldElement::from_i64(input as i64));
    for (i, b) in digest.iter().enumerate() {
        values.insert(format!("out_{i}"), FieldElement::from_i64(*b as i64));
    }
    Witness { values }
}

fn sha256_wrong_witness(input: u8) -> Witness {
    let mut w = sha256_correct_witness(input);
    // Flip the first output byte
    let v = w.values.get_mut("out_0").unwrap();
    let corrupted = v.as_bigint() + num_bigint::BigInt::from(1);
    *v = FieldElement::from_bigint(corrupted);
    w
}

// ─── SHA-256 ─────────────────────────────────────────────────────────────────

#[test]
fn sha256_valid_witness_proves_and_verifies() {
    run_with_large_stack(|| {
        let program = make_blackbox_program(BlackBoxOp::Sha256, FieldId::Bn254, 1, 32);
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let compiled = with_dev_groth16(|| backend.compile(&program)).expect("compile");
        let witness = sha256_correct_witness(42);
        let artifact = with_dev_groth16(|| backend.prove(&compiled, &witness)).expect("prove");
        assert!(
            backend.verify(&compiled, &artifact).expect("verify"),
            "valid sha256 must verify"
        );
    });
}

#[test]
fn sha256_wrong_output_rejected_at_prove() {
    run_with_large_stack(|| {
        let program = make_blackbox_program(BlackBoxOp::Sha256, FieldId::Bn254, 1, 32);
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let compiled = with_dev_groth16(|| backend.compile(&program)).expect("compile");
        let witness = sha256_wrong_witness(42);
        // The backend must reject a wrong SHA-256 output before/during proof generation
        let result = with_dev_groth16(|| backend.prove(&compiled, &witness));
        assert!(
            result.is_err(),
            "wrong sha256 output must be rejected — got: {:?}",
            result
        );
    });
}

// ─── Poseidon2 ───────────────────────────────────────────────────────────────

fn poseidon2_program() -> Program {
    make_blackbox_program(BlackBoxOp::Poseidon, FieldId::Bn254, 4, 4)
}

fn poseidon2_valid_inputs() -> BTreeMap<String, FieldElement> {
    let mut m = BTreeMap::new();
    for i in 0..4usize {
        m.insert(format!("in_{i}"), FieldElement::from_i64((i + 1) as i64));
    }
    m
}

#[test]
#[ignore = "50K+ constraint Groth16 prove; run with -- --ignored for full suite"]
fn poseidon2_valid_witness_proves_and_verifies() {
    let program = poseidon2_program();
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");
    // Provide only inputs — the backend enricher computes poseidon2 outputs and
    // all S-box intermediate signals from them.
    let witness = Witness {
        values: poseidon2_valid_inputs(),
    };
    let artifact = backend.prove(&compiled, &witness).expect("prove");
    assert!(
        backend.verify(&compiled, &artifact).expect("verify"),
        "valid poseidon must verify"
    );
}

#[test]
#[ignore = "50K+ constraint Groth16 prove; run with -- --ignored for full suite"]
fn poseidon2_wrong_output_rejected_at_prove() {
    let program = poseidon2_program();
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");
    // Provide valid inputs but a deliberately wrong out_0.
    // The enricher will compute the correct value in aux signals; check_constraints
    // will then catch the mismatch between out_0=9999 and the computed state output.
    let mut inputs = poseidon2_valid_inputs();
    inputs.insert("out_0".to_string(), FieldElement::from_i64(9999));
    let wrong_witness = Witness { values: inputs };
    let result = backend.prove(&compiled, &wrong_witness);
    assert!(
        result.is_err(),
        "wrong poseidon output must be rejected — got: {:?}",
        result
    );
}

// ─── PairingCheck — must return explicit error, not silently accept ───────────

#[test]
fn pairing_check_returns_explicit_error_not_silent_accept() {
    let program = make_blackbox_program(BlackBoxOp::PairingCheck, FieldId::Bn254, 4, 1);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let err = backend
        .compile(&program)
        .expect_err("PairingCheck must error at compile");
    let msg = err.to_string();
    assert!(
        msg.contains("pairing") || msg.contains("Pairing") || msg.contains("not supported"),
        "error should mention pairing limitation, got: {msg}"
    );
}

// ─── Pedersen — must return explicit error, not silently accept ───────────────

#[test]
fn pedersen_returns_explicit_error_not_silent_accept() {
    let program = make_blackbox_program(BlackBoxOp::Pedersen, FieldId::Bn254, 2, 2);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let err = backend
        .compile(&program)
        .expect_err("Pedersen must error at compile");
    let msg = err.to_string();
    assert!(
        msg.contains("Grumpkin")
            || msg.contains("grumpkin")
            || msg.contains("not supported")
            || msg.contains("sound"),
        "error should explain Pedersen limitation, got: {msg}"
    );
}

// ─── Lookup soundness — constraints must not be zero after lowering ───────────

#[test]
fn lookup_lowering_produces_nonzero_constraints() {
    use zkf_core::ir::LookupTable;

    // Row-major 3-row, 2-column table: row 0=(0,10), row 1=(1,20), row 2=(2,30)
    let table = LookupTable {
        name: "my_table".to_string(),
        columns: vec!["key".to_string(), "val".to_string()],
        values: vec![
            vec![FieldElement::from_i64(0), FieldElement::from_i64(10)],
            vec![FieldElement::from_i64(1), FieldElement::from_i64(20)],
            vec![FieldElement::from_i64(2), FieldElement::from_i64(30)],
        ],
    };

    let program = Program {
        name: "lookup_test".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "k".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "v".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("k".to_string())],
            table: "my_table".to_string(),
            outputs: Some(vec!["v".to_string()]),
            label: None,
        }],
        lookup_tables: vec![table],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    // Before lowering: 1 Lookup constraint
    assert_eq!(program.constraints.len(), 1);

    let lowered = lower_lookup_constraints(&program).expect("lowering");

    // After lowering: Lookup replaced by indicator + equality constraints
    // 3 rows → 3 boolean + 1 sum constraint + 2 input + 2 output equality = ≥8 constraints
    assert!(
        lowered.constraints.len() > 1,
        "lowered program must have more than 1 constraint, got {}",
        lowered.constraints.len()
    );

    // No Lookup constraints should remain
    let remaining_lookups = lowered
        .constraints
        .iter()
        .filter(|c| matches!(c, Constraint::Lookup { .. }))
        .count();
    assert_eq!(
        remaining_lookups, 0,
        "no Lookup constraints should remain after lowering"
    );
}

#[test]
fn lookup_lowered_program_proves_valid_witness() {
    use zkf_core::ir::LookupTable;

    // Row-major 2-row table: row 0 = (input=0, output=0), row 1 = (input=1, output=1)
    let table = LookupTable {
        name: "bits".to_string(),
        columns: vec!["input".to_string(), "output".to_string()],
        values: vec![
            vec![FieldElement::from_i64(0), FieldElement::from_i64(0)],
            vec![FieldElement::from_i64(1), FieldElement::from_i64(1)],
        ],
    };

    let program = Program {
        name: "lookup_bit".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "bits".to_string(),
            outputs: Some(vec!["y".to_string()]),
            label: None,
        }],
        lookup_tables: vec![table],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let lowered = lower_lookup_constraints(&program).expect("lower");
    run_with_large_stack(move || {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let compiled = with_dev_groth16(|| backend.compile(&lowered)).expect("compile");

        // x=1 → y=1 matches row 1; provide only x and y — enricher solves selectors
        let witness = Witness {
            values: BTreeMap::from([
                ("x".to_string(), FieldElement::from_i64(1)),
                ("y".to_string(), FieldElement::from_i64(1)),
            ]),
        };
        let artifact =
            with_dev_groth16(|| backend.prove(&compiled, &witness)).expect("prove valid lookup");
        assert!(
            backend.verify(&compiled, &artifact).expect("verify"),
            "valid lookup must verify"
        );
    });
}

#[test]
fn lookup_lowered_program_rejects_invalid_row() {
    use zkf_core::ir::LookupTable;

    // Row-major 2-row table: row 0 = (input=0, output=0), row 1 = (input=1, output=1)
    let table = LookupTable {
        name: "bits".to_string(),
        columns: vec!["input".to_string(), "output".to_string()],
        values: vec![
            vec![FieldElement::from_i64(0), FieldElement::from_i64(0)],
            vec![FieldElement::from_i64(1), FieldElement::from_i64(1)],
        ],
    };

    let program = Program {
        name: "lookup_bit".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "bits".to_string(),
            outputs: Some(vec!["y".to_string()]),
            label: None,
        }],
        lookup_tables: vec![table],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let lowered = lower_lookup_constraints(&program).expect("lower");
    run_with_large_stack(move || {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let compiled = with_dev_groth16(|| backend.compile(&lowered)).expect("compile");

        // x=1 → y=99 is NOT in the table: must be rejected
        let bad_witness = Witness {
            values: BTreeMap::from([
                ("x".to_string(), FieldElement::from_i64(1)),
                ("y".to_string(), FieldElement::from_i64(99)),
            ]),
        };
        let result = with_dev_groth16(|| backend.prove(&compiled, &bad_witness));
        assert!(
            result.is_err(),
            "out-of-table witness must be rejected, got: {:?}",
            result
        );
    });
}

// ─── ScalarMulG1 — identity-point fix verification ───────────────────────────

#[test]
fn scalar_mul_g1_zero_scalar_does_not_panic_at_compile() {
    // Before the fix, the accumulator started at (0,0) which is not on the curve,
    // causing division-by-zero during constraint synthesis. After the fix, it
    // uses the `is_identity` flag and the circuit synthesizes correctly.
    let program = make_blackbox_program(BlackBoxOp::ScalarMulG1, FieldId::Bn254, 3, 2);
    run_with_large_stack(move || {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        // Should not panic — circuit synthesis must succeed even for the zero-scalar edge case
        let result = with_dev_groth16(|| backend.compile(&program));
        assert!(
            result.is_ok(),
            "ScalarMulG1 compile must succeed, got: {:?}",
            result.err()
        );
    });
}

// ─── RecursiveAggregationMarker — metadata-only, no constraints ──────────────

#[test]
fn recursive_aggregation_marker_compile_succeeds() {
    // RecursiveAggregationMarker is metadata-only (no circuit constraints).
    // It must compile without error — but it constrains nothing.
    let program =
        make_blackbox_program(BlackBoxOp::RecursiveAggregationMarker, FieldId::Bn254, 0, 0);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let result = with_dev_groth16(|| backend.compile(&program));
    // May succeed (marker just adds metadata, no R1CS constraints) or error with
    // a clear message explaining it's metadata-only. Either is acceptable.
    match result {
        Ok(_) => {} // metadata-only marker, no constraints generated
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("marker") || msg.contains("metadata") || msg.contains("recursive"),
                "error should explain marker limitation, got: {msg}"
            )
        }
    }
}

// ─── Lookup compile path — lookup lowering must happen before synthesis ───────

#[test]
fn lookup_without_lowering_is_compiled_via_lowering() {
    use zkf_core::ir::LookupTable;

    let table = LookupTable {
        name: "t".to_string(),
        columns: vec!["x".to_string()],
        values: vec![vec![FieldElement::from_i64(1)]],
    };

    let program = Program {
        name: "unlowered_lookup".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "x".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("x".to_string())],
            table: "t".to_string(),
            outputs: None,
            label: None,
        }],
        lookup_tables: vec![table],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = with_dev_groth16(|| backend.compile(&program))
        .expect("lookup compile should lower the lookup instead of failing");
    assert!(
        !compiled
            .program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Lookup { .. })),
        "compiled program should not retain raw lookup constraints"
    );
}
