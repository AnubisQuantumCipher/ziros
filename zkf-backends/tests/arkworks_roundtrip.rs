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

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::{
    GROTH16_CEREMONY_ID_METADATA_KEY, GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY,
    GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY, GROTH16_SETUP_BLOB_PATH_METADATA_KEY, backend_for,
    ensure_security_covered_groth16_setup, set_allow_dev_deterministic_groth16_override,
    set_proof_seed_override, set_setup_seed_override,
    with_allow_dev_deterministic_groth16_override, with_proof_seed_override,
    with_setup_seed_override,
};
use zkf_core::{BackendKind, generate_witness};
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessPlan, program_v2_to_zir,
};
use zkf_examples::{mul_add_inputs, mul_add_program};

fn setup_seed_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_setup_seed() -> std::sync::MutexGuard<'static, ()> {
    match setup_seed_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn unique_temp_setup_blob_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "zkf-groth16-setup-{}-{nanos}.bin",
        std::process::id()
    ))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn assert_cpu_or_metal(metadata: &std::collections::BTreeMap<String, String>, key: &str) {
    let value = metadata.get(key).map(String::as_str);
    assert!(
        matches!(value, Some("cpu") | Some("metal")),
        "{key} should be present and set to cpu or metal, got {value:?}"
    );
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn simple_zir_program() -> Program {
    Program {
        name: "arkworks_zir_simple".to_string(),
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
                visibility: Visibility::Public,
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
            lhs: Expr::signal("out"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("out".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn large_msm_program(chain_len: usize) -> Program {
    let mut signals = Vec::with_capacity(chain_len + 1);
    signals.push(Signal {
        name: "x0".to_string(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    });

    let mut constraints = Vec::with_capacity(chain_len);
    let mut assignments = Vec::with_capacity(chain_len);
    let mut previous = "x0".to_string();

    for i in 1..=chain_len {
        let name = if i == chain_len {
            "out".to_string()
        } else {
            format!("x{i}")
        };
        signals.push(Signal {
            name: name.clone(),
            visibility: if i == chain_len {
                Visibility::Public
            } else {
                Visibility::Private
            },
            constant: None,
            ty: None,
        });

        let expr = Expr::Add(vec![
            Expr::signal(previous.clone()),
            Expr::Const(FieldElement::from_i64(1)),
        ]);
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(name.clone()),
            rhs: expr.clone(),
            label: Some(format!("step_{i}")),
        });
        assignments.push(WitnessAssignment {
            target: name.clone(),
            expr,
        });
        previous = name;
    }

    Program {
        name: format!("groth16_large_msm_{chain_len}"),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn division_program() -> Program {
    let quotient_expr = Expr::Div(
        Box::new(Expr::signal("dividend")),
        Box::new(Expr::signal("divisor")),
    );

    Program {
        name: "arkworks_zir_division".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "dividend".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "divisor".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "quotient".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("quotient"),
            rhs: quotient_expr.clone(),
            label: Some("quotient".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "quotient".to_string(),
                expr: quotient_expr,
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn add_program() -> Program {
    Program {
        name: "arkworks_add".to_string(),
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
                visibility: Visibility::Public,
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
            lhs: Expr::signal("out"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("out".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn hex_seed(seed: [u8; 32]) -> String {
    seed.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn groth16_roundtrip_single_case() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let program = mul_add_program();
    let inputs = mul_add_inputs(3, 5);
    let witness = generate_witness(&program, &inputs).expect("witness generation should pass");

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let verified = backend
        .verify(&compiled, &proof)
        .expect("verification should pass");

    assert!(verified);
}

#[test]
fn groth16_roundtrip_randomized_completeness() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    assert!(
        compiled.compiled_data.is_some(),
        "compile should contain serialized setup data"
    );

    for x in 1..=8 {
        for y in 1..=8 {
            let inputs = mul_add_inputs(x, y);
            let witness =
                generate_witness(&program, &inputs).expect("witness generation should pass");
            let proof = backend
                .prove(&compiled, &witness)
                .expect("proof should pass");
            let verified = backend
                .verify(&compiled, &proof)
                .expect("verification should pass");
            assert!(verified, "verification failed for x={x}, y={y}");
        }
    }
}

#[test]
fn groth16_reuses_setup_keys_across_proofs() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");

    let witness_a =
        generate_witness(&program, &mul_add_inputs(5, 4)).expect("first witness should build");
    let witness_b =
        generate_witness(&program, &mul_add_inputs(7, 2)).expect("second witness should build");

    let proof_a = backend
        .prove(&compiled, &witness_a)
        .expect("first proof should pass");
    let proof_b = backend
        .prove(&compiled, &witness_b)
        .expect("second proof should pass");

    assert_eq!(
        proof_a.verification_key, proof_b.verification_key,
        "verification key should remain stable for a compiled program"
    );
}

#[test]
fn groth16_proof_uses_fresh_runtime_randomness_without_seed_leakage() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);
    set_proof_seed_override(None);
    set_allow_dev_deterministic_groth16_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(4, 9)).expect("witness should build");

    let proof_a = backend
        .prove(&compiled, &witness)
        .expect("first proof should pass");
    let proof_b = backend
        .prove(&compiled, &witness)
        .expect("second proof should pass");

    assert!(
        backend
            .verify(&compiled, &proof_a)
            .expect("proof_a should verify")
    );
    assert!(
        backend
            .verify(&compiled, &proof_b)
            .expect("proof_b should verify")
    );
    assert_eq!(
        proof_a
            .metadata
            .get("prove_deterministic")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        proof_a
            .metadata
            .get("prove_seed_source")
            .map(String::as_str),
        Some("system-rng")
    );
    assert!(
        !proof_a.metadata.contains_key("prove_seed_hex"),
        "proof metadata must not expose witness-derived seed material"
    );
    assert!(
        !proof_b.metadata.contains_key("prove_seed_hex"),
        "proof metadata must not expose witness-derived seed material"
    );
    assert_ne!(
        proof_a.proof, proof_b.proof,
        "fresh Groth16 proving randomness should produce distinct proof bytes for repeated proofs"
    );
}

#[test]
fn groth16_proof_is_byte_deterministic_with_explicit_seed() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);
    set_proof_seed_override(None);
    set_allow_dev_deterministic_groth16_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let seed = [0x42u8; 32];
    let compiled = with_setup_seed_override(Some(seed), || backend.compile(&program))
        .expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(4, 9)).expect("witness should build");

    let proof_a = with_proof_seed_override(Some(seed), || backend.prove(&compiled, &witness))
        .expect("first seeded proof should pass");
    let proof_b = with_proof_seed_override(Some(seed), || backend.prove(&compiled, &witness))
        .expect("second seeded proof should pass");
    let seed_hex = hex_seed(seed);

    assert!(
        backend
            .verify(&compiled, &proof_a)
            .expect("proof_a should verify")
    );
    assert!(
        backend
            .verify(&compiled, &proof_b)
            .expect("proof_b should verify")
    );
    assert_eq!(proof_a.proof, proof_b.proof);
    assert_eq!(
        proof_a
            .metadata
            .get("prove_deterministic")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        proof_a
            .metadata
            .get("prove_seed_source")
            .map(String::as_str),
        Some("explicit-seed")
    );
    assert_eq!(
        proof_a.metadata.get("prove_seed_hex").map(String::as_str),
        Some(seed_hex.as_str())
    );
}

#[test]
fn groth16_proof_is_byte_deterministic_with_dev_gate_and_derived_seed() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);
    set_proof_seed_override(None);
    set_allow_dev_deterministic_groth16_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(4, 9)).expect("witness should build");

    let proof_a = with_allow_dev_deterministic_groth16_override(Some(true), || {
        backend.prove(&compiled, &witness)
    })
    .expect("first dev-deterministic proof should pass");
    let proof_b = with_allow_dev_deterministic_groth16_override(Some(true), || {
        backend.prove(&compiled, &witness)
    })
    .expect("second dev-deterministic proof should pass");

    assert!(
        backend
            .verify(&compiled, &proof_a)
            .expect("proof_a should verify")
    );
    assert!(
        backend
            .verify(&compiled, &proof_b)
            .expect("proof_b should verify")
    );
    assert_eq!(proof_a.proof, proof_b.proof);
    assert_eq!(
        proof_a
            .metadata
            .get("prove_deterministic")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        proof_a
            .metadata
            .get("prove_seed_source")
            .map(String::as_str),
        Some("derived-dev-seed")
    );
    assert!(proof_a.metadata.contains_key("prove_seed_hex"));
}

#[test]
fn groth16_compile_honors_setup_seed_override() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();

    let seed = [0xabu8; 32];
    set_setup_seed_override(Some(seed));
    let compiled = backend.compile(&program).expect("compile should pass");
    set_setup_seed_override(None);

    assert_eq!(
        compiled
            .metadata
            .get("setup_seed_source")
            .map(String::as_str),
        Some("override")
    );
    assert_eq!(
        compiled.metadata.get("setup_seed_hex").map(String::as_str),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert!(
        compiled.metadata.contains_key("r1cs_constraints_total"),
        "compile metadata should include shared R1CS lowering summary"
    );
    assert!(
        compiled.metadata.contains_key("r1cs_recursive_markers"),
        "compile metadata should include recursive marker count"
    );
}

#[test]
fn groth16_compile_auto_ceremony_is_scoped_per_subsystem_and_reported() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);
    set_allow_dev_deterministic_groth16_override(None);

    let cache_dir = unique_temp_dir("zkf-groth16-auto-ceremony");
    std::fs::create_dir_all(&cache_dir).expect("create ceremony cache dir");
    let previous_cache_dir = std::env::var_os("ZKF_GROTH16_CEREMONY_CACHE_DIR");
    unsafe {
        std::env::set_var("ZKF_GROTH16_CEREMONY_CACHE_DIR", &cache_dir);
    }

    let result = (|| {
        let backend = backend_for(BackendKind::ArkworksGroth16);
        let mut program = mul_add_program();
        program
            .metadata
            .insert("application".to_string(), "test-subsystem".to_string());

        let compiled = backend.compile(&program).expect("compile should pass");
        ensure_security_covered_groth16_setup(&compiled)
            .expect("auto ceremony should satisfy security-covered setup");

        assert_eq!(
            compiled
                .metadata
                .get("setup_seed_source")
                .map(String::as_str),
            Some("auto-ceremony")
        );
        assert_eq!(
            compiled
                .metadata
                .get(GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY)
                .map(String::as_str),
            Some("test-subsystem")
        );
        assert!(
            !compiled.metadata.contains_key("setup_seed_hex"),
            "auto ceremony must not expose toxic-waste seed bytes in compiled metadata"
        );

        let report_path = PathBuf::from(
            compiled
                .metadata
                .get(GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY)
                .expect("ceremony report path metadata"),
        );
        let report_bytes = std::fs::read(&report_path).expect("read auto ceremony report");
        let report: serde_json::Value =
            serde_json::from_slice(&report_bytes).expect("parse auto ceremony report");
        assert_eq!(report["subsystem_id"], "test-subsystem");
        assert_eq!(report["program_digest"], compiled.program_digest);
        assert_eq!(report["security_boundary"], "auto-ceremony");

        let witness = generate_witness(&program, &mul_add_inputs(3, 4)).expect("witness");
        let proof = backend.prove(&compiled, &witness).expect("prove");
        assert_eq!(
            proof
                .metadata
                .get(GROTH16_CEREMONY_ID_METADATA_KEY)
                .map(String::as_str),
            compiled
                .metadata
                .get(GROTH16_CEREMONY_ID_METADATA_KEY)
                .map(String::as_str)
        );
        assert_eq!(
            proof
                .metadata
                .get(GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY)
                .map(String::as_str),
            Some(report_path.to_string_lossy().as_ref())
        );
    })();

    match previous_cache_dir {
        Some(value) => unsafe { std::env::set_var("ZKF_GROTH16_CEREMONY_CACHE_DIR", value) },
        None => unsafe { std::env::remove_var("ZKF_GROTH16_CEREMONY_CACHE_DIR") },
    }
    let _ = std::fs::remove_dir_all(&cache_dir);
    result
}

#[test]
fn groth16_compile_accepts_imported_setup_blob_and_marks_trusted_boundary() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let baseline = backend
        .compile(&program)
        .expect("baseline compile should pass");
    let blob_path = unique_temp_setup_blob_path();
    std::fs::write(
        &blob_path,
        baseline
            .compiled_data
            .as_ref()
            .expect("baseline setup blob should exist"),
    )
    .expect("write setup blob");

    let mut imported_program = program.clone();
    imported_program.metadata.insert(
        GROTH16_SETUP_BLOB_PATH_METADATA_KEY.to_string(),
        blob_path.display().to_string(),
    );

    let compiled = backend
        .compile(&imported_program)
        .expect("compile with imported setup blob should pass");

    assert_eq!(
        compiled
            .metadata
            .get("setup_deterministic")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        compiled
            .metadata
            .get("groth16_setup_provenance")
            .map(String::as_str),
        Some("trusted-imported-blob")
    );
    assert_eq!(
        compiled
            .metadata
            .get("groth16_setup_security_boundary")
            .map(String::as_str),
        Some("trusted-imported")
    );
    assert_eq!(
        compiled
            .metadata
            .get(GROTH16_SETUP_BLOB_PATH_METADATA_KEY)
            .map(String::as_str),
        Some(blob_path.to_string_lossy().as_ref())
    );

    let _ = std::fs::remove_file(blob_path);
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn groth16_small_roundtrip_reports_below_threshold_msm_fallback() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let ctx = match zkf_metal::global_context() {
        Some(ctx) if ctx.dispatch_allowed() => ctx,
        Some(_) => {
            eprintln!("Metal dispatch circuit is open, skipping");
            return;
        }
        None => {
            eprintln!("No Metal GPU available, skipping");
            return;
        }
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let chain_len = (zkf_metal::msm::pippenger::gpu_threshold() / 4).max(1);
    let program = large_msm_program(chain_len);
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("x0".to_string(), FieldElement::from_i64(3));
    let witness = generate_witness(&program, &inputs).expect("witness generation should pass");

    let compiled = backend.compile(&program).expect("compile should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let verified = backend
        .verify(&compiled, &proof)
        .expect("verification should pass");

    assert!(verified);
    assert!(ctx.dispatch_allowed(), "expected active Metal dispatch");
    assert_eq!(
        proof.metadata.get("msm_accelerator").map(String::as_str),
        Some("cpu")
    );
    assert_eq!(
        proof.metadata.get("groth16_msm_reason").map(String::as_str),
        Some("below-threshold")
    );
    assert_eq!(
        proof
            .metadata
            .get("groth16_msm_fallback_state")
            .map(String::as_str),
        Some("cpu-only")
    );
    assert!(!proof.metadata.contains_key("groth16_msm_dispatch_failure"));
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn groth16_large_roundtrip_uses_msm_metadata() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let ctx = match zkf_metal::global_context() {
        Some(ctx) if ctx.dispatch_allowed() => ctx,
        Some(_) => {
            eprintln!("Metal dispatch circuit is open, skipping");
            return;
        }
        None => {
            eprintln!("No Metal GPU available, skipping");
            return;
        }
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let chain_len = zkf_metal::msm::pippenger::gpu_threshold();
    let program = large_msm_program(chain_len);
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("x0".to_string(), FieldElement::from_i64(3));
    let witness = generate_witness(&program, &inputs).expect("witness generation should pass");

    let compiled = backend.compile(&program).expect("compile should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");
    let verified = backend
        .verify(&compiled, &proof)
        .expect("verification should pass");

    assert!(verified);
    assert!(ctx.dispatch_allowed(), "expected active Metal dispatch");
    assert_eq!(
        proof.metadata.get("msm_accelerator").map(String::as_str),
        Some("metal")
    );
    assert_eq!(
        proof.metadata.get("groth16_msm_reason").map(String::as_str),
        Some("bn254-groth16-metal-msm")
    );
    assert_eq!(
        proof
            .metadata
            .get("groth16_msm_fallback_state")
            .map(String::as_str),
        Some("none")
    );
    assert_eq!(
        proof
            .metadata
            .get("metal_no_cpu_fallback")
            .map(String::as_str),
        Some("true")
    );
    assert!(!proof.metadata.contains_key("groth16_msm_dispatch_failure"));
    assert!(proof.metadata.contains_key("metal_gpu_busy_ratio"));
    assert!(proof.metadata.contains_key("metal_stage_breakdown"));
    assert!(proof.metadata.contains_key("metal_inflight_jobs"));
    assert!(proof.metadata.contains_key("metal_no_cpu_fallback"));
    assert!(proof.metadata.contains_key("metal_counter_source"));
}

#[test]
fn groth16_zir_division_roundtrip_uses_safe_v2_path() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = division_program();
    let zir = program_v2_to_zir(&program);
    let compiled = backend.compile_zir(&zir).expect("compile_zir should pass");
    assert_ne!(
        compiled
            .metadata
            .get("zir_native_compile")
            .map(String::as_str),
        Some("true"),
        "non-affine ZIR should fall back to the safe v2 Arkworks path"
    );

    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("dividend".to_string(), FieldElement::from_i64(42));
    inputs.insert("divisor".to_string(), FieldElement::from_i64(6));
    let witness = generate_witness(&program, &inputs).expect("witness should build");
    let proof = backend
        .prove_zir(&zir, &compiled, &witness)
        .expect("prove_zir should pass");
    let verified = backend
        .verify_zir(&zir, &compiled, &proof)
        .expect("verify_zir should pass");

    assert!(verified);
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
#[test]
fn groth16_zir_roundtrip_records_msm_metadata() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = simple_zir_program();
    let zir = program_v2_to_zir(&program);
    let compiled = backend.compile_zir(&zir).expect("compile_zir should pass");
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(6));
    inputs.insert("y".to_string(), FieldElement::from_i64(8));
    let witness = generate_witness(&program, &inputs).expect("witness should build");
    let proof = backend
        .prove_zir(&zir, &compiled, &witness)
        .expect("prove_zir should pass");
    let verified = backend
        .verify_zir(&zir, &compiled, &proof)
        .expect("verify_zir should pass");

    assert!(verified);
    assert_eq!(
        proof.metadata.get("zir_native_prove").map(String::as_str),
        Some("true")
    );
    assert_cpu_or_metal(&proof.metadata, "msm_accelerator");
    if zkf_metal::global_context().is_none() {
        assert_eq!(
            proof
                .metadata
                .get("msm_fallback_reason")
                .map(String::as_str),
            Some("metal-unavailable")
        );
    }
}

#[test]
fn groth16_rejects_wrong_program_replay_with_original_vk() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program_a = mul_add_program();
    let program_b = add_program();

    let compiled_a = backend.compile(&program_a).expect("compile A should pass");
    let compiled_b = backend.compile(&program_b).expect("compile B should pass");

    let witness_a =
        generate_witness(&program_a, &mul_add_inputs(3, 5)).expect("witness A should build");
    let mut proof_a = backend
        .prove(&compiled_a, &witness_a)
        .expect("proof A should pass");

    proof_a.program_digest = compiled_b.program_digest.clone();

    let err = backend
        .verify(&compiled_b, &proof_a)
        .expect_err("cross-program replay with original VK must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("verification key mismatch"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn groth16_rejects_wrong_program_replay_even_with_swapped_valid_vk() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program_a = mul_add_program();
    let program_b = add_program();

    let compiled_a = backend.compile(&program_a).expect("compile A should pass");
    let compiled_b = backend.compile(&program_b).expect("compile B should pass");

    let witness_a =
        generate_witness(&program_a, &mul_add_inputs(3, 5)).expect("witness A should build");
    let proof_a = backend
        .prove(&compiled_a, &witness_a)
        .expect("proof A should pass");

    let witness_b =
        generate_witness(&program_b, &mul_add_inputs(3, 5)).expect("witness B should build");
    let proof_b = backend
        .prove(&compiled_b, &witness_b)
        .expect("proof B should pass");

    let mut tampered = proof_a.clone();
    tampered.program_digest = compiled_b.program_digest.clone();
    tampered.verification_key = proof_b.verification_key.clone();

    let ok = backend.verify(&compiled_b, &tampered).unwrap_or(false);
    assert!(
        !ok,
        "wrong-program replay must never verify under a swapped-in valid VK"
    );
}

#[test]
fn groth16_rejects_tampered_verification_key_bytes() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(4, 6)).expect("witness should build");
    let mut proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");

    proof.verification_key[0] ^= 0x01;

    let err = backend
        .verify(&compiled, &proof)
        .expect_err("tampered VK bytes must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("verification key mismatch"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn groth16_rejects_tampered_proof_bytes() {
    let _guard = lock_setup_seed();
    set_setup_seed_override(None);

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let program = mul_add_program();
    let compiled = backend.compile(&program).expect("compile should pass");
    let witness = generate_witness(&program, &mul_add_inputs(4, 6)).expect("witness should build");
    let mut proof = backend
        .prove(&compiled, &witness)
        .expect("proof should pass");

    proof.proof[0] ^= 0x01;

    let ok = backend.verify(&compiled, &proof).unwrap_or(false);
    assert!(!ok, "tampered proof bytes must never verify");
}
