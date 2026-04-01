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
use zkf_backends::{backend_for, capability_report_for_backend};
use zkf_core::{BackendKind, BackendMode, FieldElement, FieldId, generate_witness};
use zkf_examples::mul_add_program_with_field;

fn inputs() -> BTreeMap<String, FieldElement> {
    let mut values = BTreeMap::new();
    values.insert("x".to_string(), FieldElement::from_i64(7));
    values.insert("y".to_string(), FieldElement::from_i64(4));
    values
}

#[test]
fn sp1_compat_roundtrip_uses_plonky3_delegate() {
    let backend = backend_for(BackendKind::Sp1);
    let program = mul_add_program_with_field(FieldId::Goldilocks);
    let witness = generate_witness(&program, &inputs()).expect("witness should generate");
    let compiled = backend.compile(&program).expect("compile should pass");
    if cfg!(feature = "native-sp1") {
        let readiness = capability_report_for_backend(BackendKind::Sp1).expect("sp1 readiness");
        if !readiness.production_ready {
            eprintln!(
                "skipping native SP1 compat baseline: {}",
                readiness
                    .readiness_reason
                    .unwrap_or_else(|| "not-production-ready".to_string())
            );
            return;
        }

        let artifact = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &artifact)
            .expect("verify should pass");
        assert!(ok);
    } else {
        let artifact = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        let ok = backend
            .verify(&compiled, &artifact)
            .expect("verify should pass");
        assert!(ok);
    }
}

#[test]
fn nova_compat_roundtrip_uses_arkworks_delegate() {
    let backend = backend_for(BackendKind::Nova);
    let program = mul_add_program_with_field(FieldId::Bn254);
    let witness = generate_witness(&program, &inputs()).expect("witness should generate");
    let compiled = backend.compile(&program).expect("compile should pass");
    let artifact = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let ok = backend
        .verify(&compiled, &artifact)
        .expect("verify should pass");
    assert!(ok);
}

#[test]
fn midnight_compat_roundtrip_delegates_by_field() {
    let backend = backend_for(BackendKind::MidnightCompact);
    let capabilities = backend.capabilities();
    let program = mul_add_program_with_field(FieldId::PastaFp);
    let witness = generate_witness(&program, &inputs()).expect("witness should generate");
    let compiled = backend.compile(&program).expect("compile should pass");
    assert!(
        compiled.metadata.contains_key("compact_source"),
        "midnight compile should capture compact source"
    );
    assert!(
        compiled.metadata.contains_key("compact_compile_status"),
        "midnight compile should record compact compilation status"
    );
    if capabilities.mode == BackendMode::Native {
        match backend.prove(&compiled, &witness) {
            Ok(artifact) => {
                let mode = artifact
                    .metadata
                    .get("proof_server_mode")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                assert!(
                    matches!(mode, "remote" | "delegate" | "delegate-fallback"),
                    "unexpected midnight native proof mode: {mode}"
                );
            }
            Err(err) => {
                let text = err.to_string().to_ascii_lowercase();
                assert!(
                    text.contains("proof server")
                        || text.contains("zkf_midnight_proof_server_prove_url"),
                    "unexpected midnight native error: {err}"
                );
            }
        }
    } else {
        let artifact = backend
            .prove(&compiled, &witness)
            .expect("proof should pass");
        assert_eq!(
            artifact
                .metadata
                .get("proof_server_mode")
                .map(String::as_str),
            Some("delegate")
        );
        let ok = backend
            .verify(&compiled, &artifact)
            .expect("verify should pass");
        assert!(ok);
    }
}
