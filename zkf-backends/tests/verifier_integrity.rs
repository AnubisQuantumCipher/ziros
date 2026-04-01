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

use zkf_backends::backend_for;
use zkf_core::{BackendKind, FieldId, generate_witness};
use zkf_examples::{mul_add_inputs, mul_add_program_with_field};

fn assert_backend_rejects_tampering(kind: BackendKind, field: FieldId) {
    let backend = backend_for(kind);
    let program = mul_add_program_with_field(field);
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(3, 5)).expect("witness should build");
    let artifact = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");

    assert!(
        backend
            .verify(&compiled, &artifact)
            .expect("verify should pass"),
        "{kind} should accept its own proof"
    );

    let mut tampered_vk = artifact.clone();
    if tampered_vk.verification_key.is_empty() {
        tampered_vk.verification_key.push(1);
    } else {
        tampered_vk.verification_key[0] ^= 0x01;
    }
    let tampered_vk_ok = backend.verify(&compiled, &tampered_vk).unwrap_or(false);
    assert!(
        !tampered_vk_ok,
        "{kind} must reject a tampered verification-key artifact"
    );

    let mut tampered_proof = artifact.clone();
    tampered_proof.proof[0] ^= 0x01;
    let tampered_proof_ok = backend.verify(&compiled, &tampered_proof).unwrap_or(false);
    assert!(
        !tampered_proof_ok,
        "{kind} must reject a tampered proof artifact"
    );
}

#[test]
fn fingerprint_backed_backends_reject_tampered_artifacts() {
    assert_backend_rejects_tampering(BackendKind::Halo2, FieldId::PastaFp);
    assert_backend_rejects_tampering(BackendKind::Halo2Bls12381, FieldId::Bls12_381);
    assert_backend_rejects_tampering(BackendKind::Plonky3, FieldId::Goldilocks);
}

#[cfg(feature = "native-nova")]
#[test]
fn nova_rejects_tampered_artifacts_in_matrix() {
    assert_backend_rejects_tampering(BackendKind::Nova, FieldId::Bn254);
}
