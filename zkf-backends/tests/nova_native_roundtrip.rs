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

#![cfg(feature = "native-nova")]

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Mutex, OnceLock};
use zkf_backends::backend_for;
use zkf_core::{BackendKind, Program, generate_witness};
use zkf_examples::{mul_add_inputs, mul_add_program};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_nova_profile<T>(profile: Option<&str>, f: impl FnOnce() -> T) -> T {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("nova env lock poisoned");

    match profile {
        Some(value) => {
            // SAFETY: Tests serialize environment mutations with ENV_LOCK.
            unsafe { std::env::set_var("ZKF_NOVA_PROFILE", value) }
        }
        None => {
            // SAFETY: Tests serialize environment mutations with ENV_LOCK.
            unsafe { std::env::remove_var("ZKF_NOVA_PROFILE") }
        }
    }

    let result = catch_unwind(AssertUnwindSafe(f));

    // SAFETY: Tests serialize environment mutations with ENV_LOCK.
    unsafe { std::env::remove_var("ZKF_NOVA_PROFILE") };

    match result {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

fn prove_roundtrip(program: &Program) {
    let backend = backend_for(BackendKind::Nova);
    let compiled = backend.compile(program).expect("compile should succeed");
    assert!(
        compiled.metadata.contains_key("r1cs_constraints_total"),
        "native nova compile should include shared R1CS lowering summary"
    );
    assert!(
        compiled.metadata.contains_key("r1cs_recursive_markers"),
        "native nova compile should include recursive marker count"
    );
    let witness = generate_witness(program, &mul_add_inputs(3, 5)).expect("witness should build");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("native nova prove should succeed");
    assert!(
        backend
            .verify(&compiled, &proof)
            .expect("native nova verify should execute"),
        "native nova verify must return true"
    );
}

#[test]
fn nova_native_roundtrip_classic_profile() {
    with_nova_profile(None, || {
        let program = mul_add_program();
        prove_roundtrip(&program);
    });
}

#[test]
fn nova_native_roundtrip_hypernova_profile() {
    with_nova_profile(Some("hypernova"), || {
        let program = mul_add_program();
        prove_roundtrip(&program);
    });
}

#[test]
fn nova_native_rejects_tampered_verification_key() {
    with_nova_profile(None, || {
        let program = mul_add_program();
        let backend = backend_for(BackendKind::Nova);
        let compiled = backend.compile(&program).expect("compile should succeed");
        let witness =
            generate_witness(&program, &mul_add_inputs(2, 7)).expect("witness should build");
        let mut proof = backend
            .prove(&compiled, &witness)
            .expect("native nova prove should succeed");
        assert!(
            !proof.verification_key.is_empty(),
            "verification key fingerprint must not be empty"
        );
        proof.verification_key[0] ^= 0x01;

        let err = backend
            .verify(&compiled, &proof)
            .expect_err("tampered verification key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("verification key fingerprint mismatch"),
            "unexpected error message: {msg}"
        );
    });
}
