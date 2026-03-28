use base64::Engine;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Mutex, OnceLock};
use zkf_backends::backend_for;
use zkf_core::{BackendKind, generate_witness};
use zkf_examples::{mul_add_inputs, mul_add_program};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_midnight_env<T>(
    prove_url: Option<&str>,
    verify_url: Option<&str>,
    required: bool,
    allow_delegate: bool,
    f: impl FnOnce() -> T,
) -> T {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poison| poison.into_inner());

    // SAFETY: Tests serialize environment mutations with ENV_LOCK.
    unsafe {
        match prove_url {
            Some(value) => std::env::set_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL", value),
            None => std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL"),
        }
        match verify_url {
            Some(value) => std::env::set_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL", value),
            None => std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL"),
        }
        std::env::set_var(
            "ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED",
            if required { "true" } else { "false" },
        );
        std::env::set_var(
            "ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE",
            if allow_delegate { "true" } else { "false" },
        );
    }

    let result = catch_unwind(AssertUnwindSafe(f));

    // SAFETY: Tests serialize environment mutations with ENV_LOCK.
    unsafe {
        std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL");
        std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL");
        std::env::remove_var("ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED");
        std::env::remove_var("ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE");
    }

    match result {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

fn mock_response_url(body: &str) -> String {
    format!(
        "mock://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body.as_bytes())
    )
}

#[test]
fn midnight_native_prove_and_verify_with_mock_server() {
    let proof_json = serde_json::json!({
        "ok": true,
        "proof_b64": base64::engine::general_purpose::STANDARD.encode([1u8,2,3,4]),
        "vk_b64": base64::engine::general_purpose::STANDARD.encode([9u8,8,7]),
        "public_inputs": ["24"],
        "metadata": {"server_mode":"mock"}
    })
    .to_string();
    let verify_json = serde_json::json!({"ok": true}).to_string();

    let prove_url = mock_response_url(&proof_json);
    let verify_url = mock_response_url(&verify_json);

    with_midnight_env(
        Some(&prove_url),
        Some(&verify_url),
        true,
        false,
        move || {
            let backend = backend_for(BackendKind::MidnightCompact);
            let program = mul_add_program();
            let compiled = backend.compile(&program).expect("compile");
            let witness = generate_witness(&program, &mul_add_inputs(3, 5)).expect("build witness");
            let artifact = backend.prove(&compiled, &witness).expect("prove");
            assert_eq!(
                artifact
                    .metadata
                    .get("proof_server_mode")
                    .map(String::as_str),
                Some("remote")
            );
            assert!(
                backend
                    .verify(&compiled, &artifact)
                    .expect("verify should run"),
                "verify should return true from mock response"
            );
        },
    );
}

#[test]
fn midnight_native_strict_requires_prove_url() {
    with_midnight_env(None, None, true, false, || {
        let backend = backend_for(BackendKind::MidnightCompact);
        let program = mul_add_program();
        let compiled = backend.compile(&program).expect("compile");
        let witness = generate_witness(&program, &mul_add_inputs(1, 2)).expect("witness");
        let err = backend
            .prove(&compiled, &witness)
            .expect_err("strict mode should require prove URL");
        let msg = err.to_string();
        assert!(
            msg.contains("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL"),
            "unexpected message: {msg}"
        );
    });
}

#[test]
fn midnight_native_strict_rejects_malformed_prove_response() {
    let prove_url = mock_response_url("not-json");
    with_midnight_env(Some(&prove_url), None, true, false, || {
        let backend = backend_for(BackendKind::MidnightCompact);
        let program = mul_add_program();
        let compiled = backend.compile(&program).expect("compile");
        let witness = generate_witness(&program, &mul_add_inputs(4, 6)).expect("witness");
        let err = backend
            .prove(&compiled, &witness)
            .expect_err("malformed JSON should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("parse prove response")
                || msg.contains("invalid midnight prove response JSON"),
            "unexpected message: {msg}"
        );
    });
}

#[test]
fn midnight_native_verify_returns_false_when_server_says_not_ok() {
    let proof_json = serde_json::json!({
        "ok": true,
        "proof_b64": base64::engine::general_purpose::STANDARD.encode([1u8,2,3]),
        "vk_b64": base64::engine::general_purpose::STANDARD.encode([4u8,5]),
        "public_inputs": ["7"],
        "metadata": {}
    })
    .to_string();
    let verify_json = serde_json::json!({"ok": false}).to_string();

    let prove_url = mock_response_url(&proof_json);
    let verify_url = mock_response_url(&verify_json);

    with_midnight_env(
        Some(&prove_url),
        Some(&verify_url),
        true,
        false,
        move || {
            let backend = backend_for(BackendKind::MidnightCompact);
            let program = mul_add_program();
            let compiled = backend.compile(&program).expect("compile");
            let witness = generate_witness(&program, &mul_add_inputs(2, 2)).expect("build witness");
            let artifact = backend.prove(&compiled, &witness).expect("prove");
            assert!(
                !backend
                    .verify(&compiled, &artifact)
                    .expect("verify should execute"),
                "verify should reflect remote false result"
            );
        },
    );
}
