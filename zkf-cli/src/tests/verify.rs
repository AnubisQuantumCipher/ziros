use super::*;

use std::sync::{Mutex, OnceLock};

use zkf_backends::{
    backend_for, with_allow_dev_deterministic_groth16_override, with_proof_seed_override,
    with_setup_seed_override,
};
use zkf_core::{BackendKind, generate_witness};
use zkf_examples::{mul_add_inputs, mul_add_program};

fn verify_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn direct_verify_recovers_seeded_groth16_context_from_compiled_or_seed() {
    let _guard = verify_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("zkf-direct-verify-{nonce}"));
    fs::create_dir_all(&root).expect("temp root");

    let program_path = root.join("program.json");
    let inputs_path = root.join("inputs.json");
    let artifact_path = root.join("proof.json");
    let compiled_path = root.join("compiled.json");
    let seed = "seeded-direct-verify";
    let setup_seed = crate::util::parse_setup_seed(seed).expect("parse seed");

    let program = mul_add_program();
    let inputs = mul_add_inputs(3, 5);
    write_json(&program_path, &program).expect("program");
    write_json(&inputs_path, &inputs).expect("inputs");

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_setup_seed_override(Some(setup_seed), || backend.compile(&program))
    })
    .expect("compile");
    let witness = generate_witness(&program, &inputs).expect("witness");
    let artifact = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_setup_seed_override(Some(setup_seed), || {
            with_proof_seed_override(Some(setup_seed), || backend.prove(&compiled, &witness))
        })
    })
    .expect("prove");
    write_json(&compiled_path, &compiled).expect("compiled");
    write_json(&artifact_path, &artifact).expect("artifact");

    let err = cmd::prove::handle_verify(
        program_path.clone(),
        artifact_path.clone(),
        "arkworks-groth16".to_string(),
        None,
        None,
        None,
        false,
        false,
        false,
    )
    .expect_err("verification should fail without the matching Groth16 context");
    assert!(
        err.contains("--seed") || err.contains("--compiled"),
        "expected actionable context hint, got: {err}"
    );

    cmd::prove::handle_verify(
        program_path.clone(),
        artifact_path.clone(),
        "arkworks-groth16".to_string(),
        Some(compiled_path),
        None,
        None,
        false,
        false,
        false,
    )
    .expect("compiled-context verify");

    cmd::prove::handle_verify(
        program_path,
        artifact_path,
        "arkworks-groth16".to_string(),
        None,
        Some(seed.to_string()),
        None,
        false,
        false,
        false,
    )
    .expect("seed-context verify");

    let _ = fs::remove_dir_all(&root);
}
