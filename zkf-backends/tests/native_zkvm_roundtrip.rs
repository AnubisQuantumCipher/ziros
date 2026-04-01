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

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
use std::collections::BTreeMap;

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
use zkf_backends::{backend_for, capability_report_for_backend};
#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
use zkf_core::{BackendKind, FieldElement, FieldId, Program, generate_witness};
#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
use zkf_examples::{mul_add_program_with_field, recurrence_program};

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
fn inputs(x: i64, y: i64) -> BTreeMap<String, FieldElement> {
    let mut values = BTreeMap::new();
    values.insert("x".to_string(), FieldElement::from_i64(x));
    values.insert("y".to_string(), FieldElement::from_i64(y));
    values
}

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
fn native_ready(kind: BackendKind) -> bool {
    capability_report_for_backend(kind)
        .map(|report| report.production_ready)
        .unwrap_or(false)
}

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
fn build_cases() -> Vec<(Program, BTreeMap<String, FieldElement>)> {
    vec![
        (
            mul_add_program_with_field(FieldId::Goldilocks),
            inputs(3, 5),
        ),
        (recurrence_program(FieldId::Goldilocks, 4), inputs(2, 1)),
        (recurrence_program(FieldId::Goldilocks, 8), inputs(3, 2)),
    ]
}

#[cfg(any(feature = "native-sp1", feature = "native-risc-zero"))]
fn run_roundtrip_matrix(kind: BackendKind, mode_key: &str) {
    if !native_ready(kind) {
        eprintln!("skipping {kind} native roundtrip matrix: backend is not production-ready");
        return;
    }

    let backend = backend_for(kind);
    for (program, raw_inputs) in build_cases() {
        let compiled = backend.compile(&program).expect("compile should pass");
        let witness = generate_witness(&program, &raw_inputs).expect("witness should generate");
        let artifact = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        assert_eq!(artifact.backend, kind);
        assert!(
            artifact.metadata.contains_key(mode_key),
            "native artifact should record {mode_key}"
        );
        let ok = backend
            .verify(&compiled, &artifact)
            .expect("verify should pass");
        assert!(ok, "native backend should accept its own proof");

        let mut tampered_proof = artifact.clone();
        tampered_proof.proof[0] ^= 1;
        let tampered_proof_ok = backend.verify(&compiled, &tampered_proof);
        assert!(tampered_proof_ok.is_err() || !tampered_proof_ok.unwrap_or(false));

        let mut tampered_vk = artifact.clone();
        if tampered_vk.verification_key.is_empty() {
            tampered_vk.verification_key.push(1);
        } else {
            tampered_vk.verification_key[0] ^= 1;
        }
        let tampered_vk_ok = backend.verify(&compiled, &tampered_vk);
        assert!(tampered_vk_ok.is_err() || !tampered_vk_ok.unwrap_or(false));
    }
}

#[cfg(feature = "native-sp1")]
#[test]
fn sp1_native_roundtrip_matrix() {
    run_roundtrip_matrix(BackendKind::Sp1, "sp1_native_mode");
}

#[cfg(feature = "native-risc-zero")]
#[test]
fn risc_zero_native_roundtrip_matrix() {
    run_roundtrip_matrix(BackendKind::RiscZero, "risc0_native_mode");
}
