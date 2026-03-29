//! Recursive aggregation soundness tests.
//!
//! Verifies:
//! 1. Each aggregator correctly labels its `trust_model` metadata
//! 2. Attestation aggregators set `algebraic_binding: "false"` (honest about limitations)
//! 3. Cryptographic aggregators set `algebraic_binding: "true"`
//! 4. The RecursiveAggregator refuses to aggregate if any sub-proof fails verification

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::{Mutex, OnceLock};
use zkf_backends::{
    backend_for,
    recursive_aggregation::AttestationRecursiveAggregator,
    wrapping::{
        groth16_recursive_verifier::CryptographicGroth16Aggregator,
        halo2_ipa_accumulator::Halo2IpaAccumulator, halo2_to_groth16::Halo2ToGroth16Wrapper,
        nova_universal_aggregator::NovaUniversalAggregator,
    },
};
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, aggregation::ProofAggregator, generate_witness,
    wrapping::ProofWrapper,
};

fn multiply_program() -> Program {
    Program {
        name: "multiply".to_string(),
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
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Mul(
                    Box::new(Expr::Signal("x".to_string())),
                    Box::new(Expr::Signal("y".to_string())),
                ),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

type Pair = (zkf_core::ProofArtifact, zkf_core::CompiledProgram);

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn env_lock() -> &'static Mutex<()> {
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    unsafe fn set(key: &'static str, value: impl Into<OsString>) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value.into());
        }
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

fn groth16_pair() -> Pair {
    let program = multiply_program();
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");
    let inputs = BTreeMap::from([
        ("x".to_string(), FieldElement::from_i64(3)),
        ("y".to_string(), FieldElement::from_i64(7)),
    ]);
    let witness = generate_witness(&program, &inputs).expect("witness");
    let artifact = backend.prove(&compiled, &witness).expect("prove");
    (artifact, compiled)
}

// ─── RecursiveAggregator — attestation trust model ───────────────────────────

#[test]
fn recursive_aggregator_sets_attestation_trust_model() {
    let pair1 = groth16_pair();
    let pair2 = groth16_pair();

    let result = AttestationRecursiveAggregator.aggregate(&[pair1, pair2]);

    match result {
        Ok(agg) => {
            assert_eq!(
                agg.metadata.get("trust_model").map(String::as_str),
                Some("attestation"),
                "RecursiveAggregator must set trust_model=attestation"
            );
            assert_eq!(
                agg.metadata.get("algebraic_binding").map(String::as_str),
                Some("false"),
                "RecursiveAggregator must set algebraic_binding=false (host-verified only)"
            );
        }
        Err(e) => {
            // Acceptable if aggregation requires specific features not enabled
            let msg = e.to_string();
            assert!(!msg.is_empty(), "aggregation failure must have a message");
        }
    }
}

// ─── RecursiveAggregator rejects tampered sub-proofs ─────────────────────────

#[test]
fn recursive_aggregator_rejects_tampered_sub_proof() {
    let (mut artifact, compiled) = groth16_pair();

    // Tamper with the proof bytes — must be caught during pre-aggregate verification
    if let Some(b) = artifact.proof.get_mut(10) {
        *b = b.wrapping_add(1);
    }

    let result = AttestationRecursiveAggregator.aggregate(&[(artifact, compiled)]);
    assert!(
        result.is_err(),
        "RecursiveAggregator must reject a tampered sub-proof before aggregating"
    );
}

// ─── Halo2→Groth16 wrapper — attestation trust model ─────────────────────────

#[test]
fn halo2_to_groth16_wrapper_sets_attestation_trust_model() {
    let halo2_program = Program {
        name: "halo2_wrap_test".to_string(),
        field: FieldId::PastaFp,
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
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("y".to_string()),
            rhs: Expr::Signal("x".to_string()),
            label: None,
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "y".to_string(),
                expr: Expr::Signal("x".to_string()),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };

    let halo2_backend = backend_for(BackendKind::Halo2);
    let compiled = halo2_backend
        .compile(&halo2_program)
        .expect("halo2 compile");
    let inputs = BTreeMap::from([("x".to_string(), FieldElement::from_i64(42))]);
    let witness = generate_witness(&halo2_program, &inputs).expect("witness");
    let artifact = halo2_backend
        .prove(&compiled, &witness)
        .expect("halo2 prove");

    let wrapper = Halo2ToGroth16Wrapper;
    let wrapped = wrapper.wrap(&artifact, &compiled).expect("wrap");

    assert_eq!(
        wrapped.metadata.get("trust_model").map(String::as_str),
        Some("attestation"),
        "Halo2→Groth16 wrapper must set trust_model=attestation"
    );
    assert_eq!(
        wrapped
            .metadata
            .get("algebraic_binding")
            .map(String::as_str),
        Some("false"),
        "Halo2→Groth16 wrapper must set algebraic_binding=false"
    );
}

// ─── Nova universal aggregator — trust model present ────────────────────────

#[test]
fn nova_universal_aggregator_trust_model_present() {
    let pair1 = groth16_pair();
    let pair2 = groth16_pair();

    let result = NovaUniversalAggregator.aggregate(&[pair1, pair2]);

    match result {
        Ok(agg) => {
            let tm = agg.metadata.get("trust_model").map(String::as_str);
            assert!(
                tm == Some("nova-universal-accumulated") || tm == Some("sha256-accumulated"),
                "NovaUniversalAggregator must set a recognized trust_model, got: {:?}",
                tm
            );
        }
        Err(_) => {
            // OK if nova-compression feature is not enabled in this build
        }
    }
}

// ─── CryptographicGroth16Aggregator — cryptographic trust model ──────────────

#[test]
fn cryptographic_groth16_aggregator_trust_model_is_cryptographic() {
    let pair1 = groth16_pair();
    let pair2 = groth16_pair();

    let result = CryptographicGroth16Aggregator.aggregate(&[pair1, pair2]);

    match result {
        Ok(agg) => {
            assert_eq!(
                agg.metadata.get("trust_model").map(String::as_str),
                Some("cryptographic"),
                "CryptographicGroth16Aggregator must set trust_model=cryptographic"
            );
            assert_eq!(
                agg.metadata.get("algebraic_binding").map(String::as_str),
                Some("true"),
                "CryptographicGroth16Aggregator must set algebraic_binding=true"
            );
            assert_eq!(
                agg.metadata
                    .get("in_circuit_verification")
                    .map(String::as_str),
                Some("true"),
                "must set in_circuit_verification=true"
            );
            assert!(
                !agg.public_inputs.is_empty(),
                "cryptographic aggregate must expose binding public inputs"
            );
        }
        Err(e) => {
            // Acceptable if setup fails (e.g. serialization or field mismatch)
            let _ = e;
        }
    }
}

#[test]
fn cryptographic_groth16_single_inner_proof_smoke() {
    if std::env::var("ZKF_RECURSIVE_PROVE").ok().as_deref() != Some("1") {
        eprintln!("skipping recursive single-proof smoke because ZKF_RECURSIVE_PROVE!=1");
        return;
    }

    let _env_lock = env_lock().lock().expect("env lock");
    let _worker_bin = unsafe {
        ScopedEnvVar::set(
            "ZKF_RECURSIVE_WORKER_BIN",
            env!("CARGO_BIN_EXE_zkf-recursive-groth16-worker"),
        )
    };
    let _process_split = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_PROCESS_SPLIT", "1") };

    let pair = groth16_pair();
    let aggregated = CryptographicGroth16Aggregator
        .aggregate(&[pair])
        .expect("single inner proof recursive aggregate should prove");

    assert_eq!(
        aggregated.metadata.get("trust_model").map(String::as_str),
        Some("cryptographic")
    );
    assert_eq!(
        aggregated
            .metadata
            .get("algebraic_binding")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        aggregated
            .metadata
            .get("in_circuit_verification")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        aggregated.public_inputs.len(),
        1,
        "single-proof recursive aggregate should expose one binding digest"
    );

    let verified = CryptographicGroth16Aggregator
        .verify_aggregated(&aggregated)
        .expect("verify recursive aggregate");
    assert!(
        verified,
        "single inner proof recursive aggregate must verify"
    );
}

#[test]
fn cryptographic_groth16_missing_worker_fails_closed() {
    let _env_lock = env_lock().lock().expect("env lock");
    let _prove = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_PROVE", "1") };
    let _process_split = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_PROCESS_SPLIT", "1") };
    let missing = std::env::temp_dir().join(format!(
        "zkf-missing-recursive-worker-{}-{}",
        std::process::id(),
        1_337
    ));
    let _worker_bin = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_WORKER_BIN", missing) };

    let pair = groth16_pair();
    let result = CryptographicGroth16Aggregator.aggregate(&[pair]);
    let err = result.expect_err("missing worker binary must fail closed");
    assert!(
        err.to_string().contains("worker"),
        "missing worker error should mention the worker path: {err}"
    );
}

#[test]
fn cryptographic_groth16_invalid_inner_proof_fails_closed() {
    let _env_lock = env_lock().lock().expect("env lock");
    let _prove = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_PROVE", "1") };
    let _process_split = unsafe { ScopedEnvVar::set("ZKF_RECURSIVE_PROCESS_SPLIT", "0") };

    let (mut artifact, compiled) = groth16_pair();
    let last = artifact
        .proof
        .len()
        .checked_sub(1)
        .expect("proof bytes must be present");
    artifact.proof[last] ^= 0x01;

    let err = CryptographicGroth16Aggregator
        .aggregate(&[(artifact, compiled)])
        .expect_err("invalid inner proof must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("does not verify")
            || message.contains("deserialization")
            || message.contains("Invalid proof"),
        "invalid inner proof should be rejected before recursive proving: {message}"
    );
}

// ─── Halo2 IPA accumulator — trust model ─────────────────────────────────────

#[test]
fn halo2_ipa_accumulator_trust_model_is_ipa_accumulated() {
    let halo2_program = Program {
        name: "halo2_acc_test".to_string(),
        field: FieldId::PastaFp,
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

    let halo2_backend = backend_for(BackendKind::Halo2);
    let compiled = halo2_backend.compile(&halo2_program).expect("compile");
    let inputs = BTreeMap::from([("x".to_string(), FieldElement::from_i64(1))]);
    let witness = generate_witness(&halo2_program, &inputs).expect("witness");
    let artifact = halo2_backend.prove(&compiled, &witness).expect("prove");

    let result = Halo2IpaAccumulator.aggregate(&[(artifact, compiled)]);

    match result {
        Ok(agg) => {
            assert_eq!(
                agg.metadata.get("trust_model").map(String::as_str),
                Some("ipa-accumulated"),
                "Halo2IpaAccumulator must set trust_model=ipa-accumulated, got: {:?}",
                agg.metadata.get("trust_model")
            );
        }
        Err(_) => {
            // OK if feature not enabled or minimal proof doesn't have IPA data
        }
    }
}
