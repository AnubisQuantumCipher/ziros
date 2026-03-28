//! Soundness regression tests — ensure tampered proofs/witnesses are rejected.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use zkf_backends::{BackendRoute, backend_for};
use zkf_core::artifact::ProofArtifact;
use zkf_core::wrapping::WrapperExecutionPolicy;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, Witness,
    WitnessAssignment, WitnessPlan, check_constraints, generate_witness,
};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor, SwarmTelemetryDigest};

fn multiply_program(field: FieldId) -> Program {
    Program {
        name: "multiply".to_string(),
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("out"),
            rhs: Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
            label: Some("multiply".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn valid_inputs() -> BTreeMap<String, FieldElement> {
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(3));
    inputs.insert("y".to_string(), FieldElement::from_i64(7));
    inputs
}

// --- Witness validation ---

#[test]
fn valid_witness_passes_constraint_check() {
    let program = multiply_program(FieldId::Bn254);
    let witness = generate_witness(&program, &valid_inputs());
    assert!(witness.is_ok());
}

#[test]
fn wrong_witness_fails_constraint_check() {
    let program = multiply_program(FieldId::Bn254);
    let mut values = BTreeMap::new();
    values.insert("x".to_string(), FieldElement::from_i64(3));
    values.insert("y".to_string(), FieldElement::from_i64(7));
    values.insert("out".to_string(), FieldElement::from_i64(22)); // wrong!
    let witness = Witness { values };
    let result = check_constraints(&program, &witness);
    assert!(
        result.is_err(),
        "Wrong witness should fail constraint check"
    );
}

#[test]
fn missing_signal_fails_witness_generation() {
    let program = multiply_program(FieldId::Bn254);
    let mut inputs = BTreeMap::new();
    inputs.insert("x".to_string(), FieldElement::from_i64(3));
    let result = generate_witness(&program, &inputs);
    assert!(
        result.is_err(),
        "Missing input should fail witness generation"
    );
}

#[test]
fn unknown_signal_fails_witness_generation() {
    let program = multiply_program(FieldId::Bn254);
    let mut inputs = valid_inputs();
    inputs.insert("nonexistent".to_string(), FieldElement::from_i64(99));
    let result = generate_witness(&program, &inputs);
    assert!(result.is_err(), "Unknown signal should fail");
}

// --- Backend prove/verify soundness ---

fn prove_verify_roundtrip(kind: BackendKind, field: FieldId) {
    let program = multiply_program(field);
    let witness = generate_witness(&program, &valid_inputs()).unwrap();
    let backend = backend_for(kind);
    let compiled = backend.compile(&program).unwrap();
    let artifact = backend.prove(&compiled, &witness).unwrap();
    let verified = backend.verify(&compiled, &artifact).unwrap();
    assert!(verified, "Valid proof must verify for {:?}", kind);
}

fn tampered_proof_rejected(kind: BackendKind, field: FieldId) {
    let program = multiply_program(field);
    let witness = generate_witness(&program, &valid_inputs()).unwrap();
    let backend = backend_for(kind);
    let compiled = backend.compile(&program).unwrap();
    let mut artifact = backend.prove(&compiled, &witness).unwrap();

    // Tamper with proof bytes
    if let Some(byte) = artifact.proof.get_mut(10) {
        *byte = byte.wrapping_add(1);
    }

    let result = backend.verify(&compiled, &artifact);
    let rejected = result.is_err() || matches!(result, Ok(false));
    assert!(rejected, "Tampered proof must not verify for {:?}", kind);
}

fn wrong_public_inputs_rejected(kind: BackendKind, field: FieldId) {
    let program = multiply_program(field);
    let witness = generate_witness(&program, &valid_inputs()).unwrap();
    let backend = backend_for(kind);
    let compiled = backend.compile(&program).unwrap();
    let mut artifact = backend.prove(&compiled, &witness).unwrap();

    artifact.public_inputs = vec![FieldElement::from_i64(999)];

    let result = backend.verify(&compiled, &artifact);
    let rejected = result.is_err() || matches!(result, Ok(false));
    assert!(
        rejected,
        "Wrong public inputs must not verify for {:?}",
        kind
    );
}

#[test]
fn groth16_roundtrip() {
    prove_verify_roundtrip(BackendKind::ArkworksGroth16, FieldId::Bn254);
}

#[test]
fn groth16_tampered() {
    tampered_proof_rejected(BackendKind::ArkworksGroth16, FieldId::Bn254);
}

#[test]
fn groth16_wrong_pi() {
    wrong_public_inputs_rejected(BackendKind::ArkworksGroth16, FieldId::Bn254);
}

#[test]
fn halo2_roundtrip() {
    prove_verify_roundtrip(BackendKind::Halo2, FieldId::PastaFp);
}

#[test]
fn halo2_tampered() {
    tampered_proof_rejected(BackendKind::Halo2, FieldId::PastaFp);
}

#[test]
fn plonky3_roundtrip() {
    prove_verify_roundtrip(BackendKind::Plonky3, FieldId::Goldilocks);
}

#[test]
fn plonky3_tampered() {
    tampered_proof_rejected(BackendKind::Plonky3, FieldId::Goldilocks);
}

// --- Field arithmetic soundness ---

#[test]
fn field_element_roundtrip_bigint() {
    use num_bigint::BigInt;

    for field in [
        FieldId::Bn254,
        FieldId::PastaFp,
        FieldId::PastaFq,
        FieldId::Bls12_381,
        FieldId::Goldilocks,
        FieldId::BabyBear,
        FieldId::Mersenne31,
    ] {
        for v in [0i64, 1, 2, 42, 255, 1000, -1, -42] {
            let fe = FieldElement::from_i64(v);
            let bi = fe.normalized_bigint(field).unwrap();
            let fe2 = FieldElement::from_bigint_with_field(bi.clone(), field);
            let bi2 = fe2.normalized_bigint(field).unwrap();
            assert_eq!(bi, bi2, "roundtrip failed for {v} in {field}");
        }

        // p should reduce to 0
        let modulus = field.modulus().clone();
        let fe_mod = FieldElement::from_bigint_with_field(modulus.clone(), field);
        let bi_mod = fe_mod.normalized_bigint(field).unwrap();
        assert_eq!(
            bi_mod,
            BigInt::from(0),
            "modulus should reduce to 0 in {field}"
        );

        // p+1 should reduce to 1
        let fe_mod_plus = FieldElement::from_bigint_with_field(modulus + BigInt::from(1), field);
        let bi_mod_plus = fe_mod_plus.normalized_bigint(field).unwrap();
        assert_eq!(
            bi_mod_plus,
            BigInt::from(1),
            "modulus+1 should reduce to 1 in {field}"
        );
    }
}

#[test]
fn field_inverse_identity() {
    use num_bigint::BigInt;
    use zkf_core::mod_inverse_bigint;

    for field in [
        FieldId::Bn254,
        FieldId::PastaFp,
        FieldId::Goldilocks,
        FieldId::BabyBear,
        FieldId::Mersenne31,
    ] {
        let modulus = field.modulus();
        for v in [1i64, 2, 3, 7, 42, 255, 1000] {
            let a = BigInt::from(v);
            let a_inv = mod_inverse_bigint(a.clone(), modulus).unwrap();
            let product = (&a * &a_inv) % modulus;
            assert_eq!(
                product,
                BigInt::from(1),
                "a * a_inv != 1 for a={v} in {field}"
            );
        }
    }
}

// --- Optimizer soundness ---

#[test]
fn optimizer_preserves_proof_validity() {
    let program = multiply_program(FieldId::Bn254);
    let (optimized, _report) = zkf_core::optimizer::optimize_program(&program);

    let inputs = valid_inputs();
    let witness_orig = generate_witness(&program, &inputs).unwrap();
    let witness_opt = generate_witness(&optimized, &inputs).unwrap();

    // Public outputs should match
    let out_orig = witness_orig.values.get("out").unwrap();
    let out_opt = witness_opt.values.get("out").unwrap();
    assert_eq!(
        out_orig.to_string(),
        out_opt.to_string(),
        "Optimizer must preserve public outputs"
    );

    // Both should prove and verify
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).unwrap();
    let artifact = backend.prove(&compiled, &witness_orig).unwrap();
    assert!(backend.verify(&compiled, &artifact).unwrap());

    let compiled_opt = backend.compile(&optimized).unwrap();
    let artifact_opt = backend.prove(&compiled_opt, &witness_opt).unwrap();
    assert!(backend.verify(&compiled_opt, &artifact_opt).unwrap());
}

// --- Boolean constraint soundness ---

#[test]
fn boolean_constraint_rejects_non_binary() {
    let program = Program {
        name: "bool_test".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "b".to_string(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Boolean {
            signal: "b".to_string(),
            label: Some("bool_check".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    // Value 2 should fail
    let witness = Witness {
        values: BTreeMap::from([("b".to_string(), FieldElement::from_i64(2))]),
    };
    assert!(check_constraints(&program, &witness).is_err());

    // 0 and 1 should pass
    for v in [0, 1] {
        let witness = Witness {
            values: BTreeMap::from([("b".to_string(), FieldElement::from_i64(v))]),
        };
        assert!(check_constraints(&program, &witness).is_ok());
    }
}

// --- Serialization soundness ---

#[test]
fn program_json_roundtrip() {
    let program = multiply_program(FieldId::Bn254);
    let json = serde_json::to_string(&program).unwrap();
    let deserialized: Program = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&deserialized).unwrap();
    assert_eq!(json, json2, "Program JSON roundtrip must be identity");
}

#[test]
fn malformed_program_json_rejected() {
    let bad_json = r#"{"name": "test", "field": "bn254", "signals": "not_an_array"}"#;
    let result: Result<Program, _> = serde_json::from_str(bad_json);
    assert!(result.is_err(), "Malformed JSON should be rejected");
}

#[derive(Clone)]
struct OperationSnapshot {
    artifact: ProofArtifact,
    swarm: Option<SwarmTelemetryDigest>,
    outputs: serde_json::Value,
}

struct KillSwitchSnapshot {
    prove: Result<OperationSnapshot, String>,
    fold: Result<OperationSnapshot, String>,
    wrap: Result<OperationSnapshot, String>,
    swarm_root_exists: bool,
}

static SWARM_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static NOVA_FOLD_FIXTURE: OnceLock<(Program, zkf_core::CompiledProgram)> = OnceLock::new();

fn nova_fold_fixture() -> &'static (Program, zkf_core::CompiledProgram) {
    NOVA_FOLD_FIXTURE.get_or_init(|| {
        let mut fold_program = zkf_examples::mul_add_program();
        fold_program
            .metadata
            .insert("nova_ivc_in".to_string(), "x".to_string());
        fold_program
            .metadata
            .insert("nova_ivc_out".to_string(), "product".to_string());
        let compiled = backend_for(BackendKind::Nova)
            .compile(&fold_program)
            .expect("compile nova fold fixture");
        (fold_program, compiled)
    })
}

fn with_swarm_home<T>(enabled: bool, f: impl FnOnce(&Path) -> T) -> T {
    let _guard = SWARM_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let previous = [
        ("HOME", std::env::var_os("HOME")),
        ("ZKF_SWARM", std::env::var_os("ZKF_SWARM")),
        (
            "ZKF_SWARM_KEY_BACKEND",
            std::env::var_os("ZKF_SWARM_KEY_BACKEND"),
        ),
        (
            "ZKF_SECURITY_POLICY_MODE",
            std::env::var_os("ZKF_SECURITY_POLICY_MODE"),
        ),
    ];
    unsafe {
        std::env::set_var("HOME", temp.path());
        std::env::set_var("ZKF_SWARM", if enabled { "1" } else { "0" });
        std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
    }
    let result = f(temp.path());
    unsafe {
        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
    result
}

fn snapshot_from_execution(
    result: &zkf_runtime::telemetry::PlanExecutionResult,
    artifact: &ProofArtifact,
) -> OperationSnapshot {
    OperationSnapshot {
        artifact: artifact.clone(),
        swarm: result.swarm.clone(),
        outputs: result.outputs.clone(),
    }
}

fn outputs_contain_swarm_state(outputs: &serde_json::Value) -> bool {
    outputs
        .as_object()
        .map(|map| map.keys().any(|key| key.contains("swarm")))
        .unwrap_or(false)
        || outputs
            .get("runtime_security_signals")
            .and_then(|value| value.as_array())
            .map(|signals| {
                signals.iter().any(|signal| {
                    signal
                        .get("source")
                        .and_then(|value| value.as_str())
                        .map(|source| source == "swarm")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
}

fn assert_swarm_disabled_surface(operation: &str, snapshot: &OperationSnapshot) {
    assert!(
        snapshot.swarm.is_none(),
        "{operation} should not emit swarm telemetry when ZKF_SWARM=0"
    );
    assert!(
        !outputs_contain_swarm_state(&snapshot.outputs),
        "{operation} should not emit residual swarm output state when ZKF_SWARM=0"
    );
}

fn assert_explicit_swarm_error(operation: &str, err: &str) {
    let lowered = err.to_ascii_lowercase();
    assert!(
        lowered.contains("swarm")
            || lowered.contains("security")
            || lowered.contains("watchdog")
            || lowered.contains("quarant")
            || lowered.contains("reject")
            || lowered.contains("wrap")
            || lowered.contains("metal")
            || lowered.contains("fallback"),
        "{operation} swarm-on failure was not explicit enough: {err}"
    );
}

fn assert_successful_artifact_bytes_or_explicit_swarm_error(
    operation: &str,
    baseline: Result<OperationSnapshot, String>,
    observed: Result<OperationSnapshot, String>,
) {
    match (baseline, observed) {
        (Ok(baseline), Ok(observed)) => {
            assert_eq!(
                observed.artifact.proof, baseline.artifact.proof,
                "{operation} proof bytes changed across swarm kill-switch boundary"
            );
            assert_eq!(
                observed.artifact.public_inputs, baseline.artifact.public_inputs,
                "{operation} public inputs changed across swarm kill-switch boundary"
            );
            assert_eq!(
                observed.artifact.verification_key, baseline.artifact.verification_key,
                "{operation} verification key changed across swarm kill-switch boundary"
            );
        }
        (Ok(_baseline), Err(err)) => {
            assert_explicit_swarm_error(operation, &err);
        }
        (Err(_baseline_err), Err(err)) => {
            assert_explicit_swarm_error(operation, &err);
        }
        (Err(baseline_err), Ok(_observed)) => {
            panic!(
                "{operation} unexpectedly succeeded with swarm enabled after baseline failure: {baseline_err}"
            );
        }
    }
}

fn assert_fold_equivalent_or_explicit_swarm_error(
    operation: &str,
    compiled: &zkf_core::CompiledProgram,
    baseline: Result<OperationSnapshot, String>,
    observed: Result<OperationSnapshot, String>,
) {
    match (baseline, observed) {
        (Ok(baseline), Ok(observed)) => {
            let baseline_verified =
                zkf_backends::try_verify_fold_native(compiled, &baseline.artifact)
                    .expect("native fold verifier available")
                    .expect("baseline fold verification should not error");
            let observed_verified =
                zkf_backends::try_verify_fold_native(compiled, &observed.artifact)
                    .expect("native fold verifier available")
                    .expect("swarm-on fold verification should not error");
            assert!(
                baseline_verified,
                "{operation} baseline fold artifact must verify"
            );
            assert!(
                observed_verified,
                "{operation} swarm-on fold artifact must verify"
            );
            assert_eq!(
                observed.artifact.backend, baseline.artifact.backend,
                "{operation} backend changed across swarm kill-switch boundary"
            );
            assert_eq!(
                observed.artifact.program_digest, baseline.artifact.program_digest,
                "{operation} program digest changed across swarm kill-switch boundary"
            );
            assert_eq!(
                observed.artifact.verification_key, baseline.artifact.verification_key,
                "{operation} verification key changed across swarm kill-switch boundary"
            );
            assert_eq!(
                observed.artifact.public_inputs, baseline.artifact.public_inputs,
                "{operation} public inputs changed across swarm kill-switch boundary"
            );
            for key in [
                "nova_native_mode",
                "nova_steps",
                "nova_curve_cycle",
                "nova_profile",
                "nova_compressed",
                "scheme",
                "nova_ivc_in",
                "nova_ivc_out",
                "nova_ivc_initial_state",
                "nova_ivc_final_state",
            ] {
                assert_eq!(
                    observed.artifact.metadata.get(key),
                    baseline.artifact.metadata.get(key),
                    "{operation} metadata field '{key}' changed across swarm kill-switch boundary"
                );
            }
        }
        (Ok(_baseline), Err(err)) => assert_explicit_swarm_error(operation, &err),
        (Err(_baseline_err), Err(err)) => assert_explicit_swarm_error(operation, &err),
        (Err(baseline_err), Ok(_observed)) => {
            panic!(
                "{operation} unexpectedly succeeded with swarm enabled after baseline failure: {baseline_err}"
            );
        }
    }
}

fn runtime_kill_switch_snapshot(enabled: bool) -> KillSwitchSnapshot {
    with_swarm_home(enabled, |home| {
        let prove_program = Arc::new(zkf_examples::mul_add_program_with_field(
            FieldId::Goldilocks,
        ));
        let prove_inputs = Arc::new(zkf_examples::mul_add_inputs(7, 5));
        let prove_execution = RuntimeExecutor::run_backend_prove_job(
            BackendKind::Plonky3,
            BackendRoute::Auto,
            Arc::clone(&prove_program),
            Some(prove_inputs),
            None,
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        );
        let prove = prove_execution
            .as_ref()
            .map(|execution| snapshot_from_execution(&execution.result, &execution.artifact))
            .map_err(|err| err.to_string());

        let (fold_program, compiled_fold_program) = nova_fold_fixture().clone();
        let fold = (|| {
            let witness_a = generate_witness(&fold_program, &zkf_examples::mul_add_inputs(7, 5))
                .map_err(|err| err.to_string())?;
            let witness_b_input = witness_a
                .values
                .get("product")
                .cloned()
                .ok_or_else(|| "missing folded product witness".to_string())?;
            let witness_b = generate_witness(
                &fold_program,
                &BTreeMap::from([
                    ("x".to_string(), witness_b_input),
                    ("y".to_string(), FieldElement::from_i64(4)),
                ]),
            )
            .map_err(|err| err.to_string())?;
            let native = zkf_backends::try_fold_native(
                &compiled_fold_program,
                &[witness_a, witness_b],
                false,
            )
            .ok_or_else(|| "native nova fold unavailable".to_string())?
            .map_err(|err| err.to_string())?;
            let verified =
                zkf_backends::try_verify_fold_native(&compiled_fold_program, &native.artifact)
                    .ok_or_else(|| "native nova fold verify unavailable".to_string())?
                    .map_err(|err| err.to_string())?;
            assert!(verified, "folded artifact must verify");
            Ok(OperationSnapshot {
                artifact: native.artifact,
                swarm: None,
                outputs: serde_json::json!({}),
            })
        })();

        let wrap = match prove_execution {
            Ok(prove_execution) => {
                let registry = zkf_backends::wrapping::default_wrapper_registry();
                let wrapper = registry
                    .find(BackendKind::Plonky3, BackendKind::ArkworksGroth16)
                    .ok_or_else(|| "missing Plonky3 -> ArkworksGroth16 wrapper".to_string());
                wrapper.and_then(|wrapper| {
                    let policy = WrapperExecutionPolicy::default();
                    let preview = wrapper
                        .preview_wrap_with_policy(
                            &prove_execution.artifact,
                            &prove_execution.compiled,
                            policy,
                        )
                        .map_err(|err| err.to_string())?
                        .ok_or_else(|| "wrapper preview unavailable".to_string())?;
                    let wrapped = RuntimeExecutor::run_wrapper_job_with_sources(
                        &preview,
                        Arc::new(prove_execution.artifact.clone()),
                        Arc::new(prove_execution.compiled.clone()),
                        policy,
                        ExecutionMode::Deterministic,
                    )
                    .map_err(|err| err.to_string())?;
                    let verified = wrapper
                        .verify_wrapped(&wrapped.artifact)
                        .map_err(|err| err.to_string())?;
                    assert!(verified, "wrapped proof must verify");
                    Ok(snapshot_from_execution(&wrapped.result, &wrapped.artifact))
                })
            }
            Err(err) => Err(format!("wrap prerequisite prove failed: {err}")),
        };

        KillSwitchSnapshot {
            prove,
            fold,
            wrap,
            swarm_root_exists: home.join(".zkf").join("swarm").exists(),
        }
    })
}

#[test]
fn swarm_kill_switch_preserves_prove_fold_and_wrap_or_errors_explicitly() {
    let without_swarm = runtime_kill_switch_snapshot(false);
    let with_swarm = runtime_kill_switch_snapshot(true);
    let fold_compiled = &nova_fold_fixture().1;

    let prove_without_swarm = without_swarm.prove.expect("prove without swarm");
    let fold_without_swarm = without_swarm.fold.expect("fold without swarm");

    assert_swarm_disabled_surface("prove", &prove_without_swarm);
    assert_swarm_disabled_surface("fold", &fold_without_swarm);
    if let Ok(wrap_without_swarm) = without_swarm.wrap.as_ref() {
        assert_swarm_disabled_surface("wrap", wrap_without_swarm);
    }
    assert!(
        !without_swarm.swarm_root_exists,
        "ZKF_SWARM=0 should not materialize ~/.zkf/swarm state"
    );

    assert_successful_artifact_bytes_or_explicit_swarm_error(
        "prove",
        Ok(prove_without_swarm),
        with_swarm.prove,
    );
    assert_fold_equivalent_or_explicit_swarm_error(
        "fold",
        fold_compiled,
        Ok(fold_without_swarm),
        with_swarm.fold,
    );
    assert_successful_artifact_bytes_or_explicit_swarm_error(
        "wrap",
        without_swarm.wrap,
        with_swarm.wrap,
    );
}
