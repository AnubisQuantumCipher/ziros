use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::BufReader;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::{
    BackendRoute, backend_for, compile_arkworks_unchecked, prepare_witness_for_proving,
    with_allow_dev_deterministic_groth16_override, with_proof_seed_override,
    with_setup_seed_override,
};
use zkf_core::{
    BackendKind, CompiledProgram, Program, ProofArtifact, Witness, WitnessInputs,
    check_constraints, optimize_program,
};
use zkf_lib::app::descent::{
    PrivatePoweredDescentRequestV1, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness_with_steps,
};
use zkf_lib::{export_groth16_solidity_verifier, prove, verify};
use zkf_runtime::{ExecutionMode, OptimizationObjective, RequiredTrustLane, RuntimeExecutor};

const SETUP_SEED: [u8; 32] = [0x73; 32];
const PROOF_SEED: [u8; 32] = [0x29; 32];
const PRODUCTION_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_PRODUCTION";
const BUNDLE_MODE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_BUNDLE_MODE";
const TRUSTED_SETUP_MANIFEST_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_TRUSTED_SETUP_MANIFEST";
const GROTH16_SETUP_BLOB_PATH_ENV: &str = "ZKF_GROTH16_SETUP_BLOB_PATH";
const TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION: &str =
    "private-powered-descent-trusted-setup-manifest-v1";

static SWARM_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn run_with_large_stack<T, F>(name: &str, f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .expect("spawn large-stack integration worker")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

fn with_swarm_home<T>(f: impl FnOnce(&Path) -> T) -> T {
    let _guard = SWARM_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().expect("tempdir");
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
        (
            "ZKF_GROTH16_STREAMED_SETUP",
            std::env::var_os("ZKF_GROTH16_STREAMED_SETUP"),
        ),
    ];

    unsafe {
        std::env::set_var("HOME", temp.path());
        std::env::set_var("ZKF_SWARM", "1");
        std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
        std::env::set_var("ZKF_GROTH16_STREAMED_SETUP", "0");
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

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
}

fn cargo_target_dir() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("CARGO_TARGET_DIR") {
        return std::path::PathBuf::from(path);
    }

    let config_path = repo_root().join(".cargo/config.toml");
    if let Ok(contents) = fs::read_to_string(&config_path) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix("target-dir") {
                let configured = value
                    .split_once('=')
                    .map(|(_, value)| value.trim().trim_matches('"'));
                if let Some(configured) = configured.filter(|value| !value.is_empty()) {
                    return repo_root().join(configured);
                }
            }
        }
    }

    let target_local = repo_root().join("target-local");
    if target_local.exists() {
        target_local
    } else {
        repo_root().join("target")
    }
}

fn powered_descent_fixture_path(name: &str) -> std::path::PathBuf {
    repo_root()
        .join("zkf-integration-tests")
        .join("fixtures")
        .join("private_powered_descent")
        .join(name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os_string = path.as_os_str().to_os_string();
    os_string.push(suffix);
    PathBuf::from(os_string)
}

fn json_contains_key_recursive(value: &serde_json::Value, key: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.contains_key(key)
                || map
                    .values()
                    .any(|entry| json_contains_key_recursive(entry, key))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|entry| json_contains_key_recursive(entry, key)),
        _ => false,
    }
}

fn assert_text_has_no_public_path_leaks(text: &str, temp_home: &Path, output_dir: &Path) {
    for forbidden in [
        repo_root().display().to_string(),
        temp_home.display().to_string(),
        output_dir.display().to_string(),
        "/Users/".to_string(),
        "/home/".to_string(),
        "/tmp/".to_string(),
    ] {
        assert!(
            !text.contains(&forbidden),
            "public bundle text unexpectedly leaked {forbidden:?}\n{text}"
        );
    }
}

fn assert_json_has_no_public_path_leaks(
    value: &serde_json::Value,
    temp_home: &Path,
    output_dir: &Path,
) {
    let rendered = serde_json::to_string_pretty(value).expect("serialize json for leak check");
    assert_text_has_no_public_path_leaks(&rendered, temp_home, output_dir);
    assert!(
        !json_contains_key_recursive(value, "output_dir"),
        "public bundle JSON should not carry output_dir keys",
    );
    assert!(
        !json_contains_key_recursive(value, "request_source_path"),
        "public bundle JSON should not carry request_source_path keys",
    );
    assert!(
        !json_contains_key_recursive(value, "telemetry_paths"),
        "public bundle JSON should not carry telemetry_paths keys",
    );
}

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    let file = fs::File::open(path).expect("read json");
    let reader = BufReader::new(file);
    zkf_core::json_from_reader(reader).expect("parse json")
}

fn assert_file_exists(path: &Path) {
    let metadata = fs::metadata(path).unwrap_or_else(|error| {
        panic!("expected {} to exist: {error}", path.display());
    });
    assert!(
        metadata.is_file(),
        "expected {} to be a file",
        path.display()
    );
}

fn assert_dir_exists(path: &Path) {
    let metadata = fs::metadata(path).unwrap_or_else(|error| {
        panic!("expected {} to exist: {error}", path.display());
    });
    assert!(
        metadata.is_dir(),
        "expected {} to be a directory",
        path.display()
    );
}

fn assert_gpu_backed_attribution(gpu_attribution: &serde_json::Value) {
    let classification = gpu_attribution
        .get("classification")
        .and_then(serde_json::Value::as_str);
    assert!(
        matches!(
            classification,
            Some("backend-delegated") | Some("runtime-direct")
        ),
        "expected backend-delegated or runtime-direct GPU attribution, got {classification:?}",
    );
    assert_eq!(
        gpu_attribution
            .get("effective_gpu_participation")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "GPU attribution should record effective participation",
    );

    let artifact_evidence = gpu_attribution
        .get("artifact_metadata_evidence")
        .expect("gpu attribution artifact metadata evidence");
    assert_eq!(
        artifact_evidence
            .get("metal_complete")
            .and_then(serde_json::Value::as_str),
        Some("true"),
        "GPU attribution should preserve metal_complete=true",
    );
    let coverage = artifact_evidence
        .get("gpu_stage_coverage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        coverage.contains("fft-ntt")
            && coverage.contains("qap-witness-map")
            && coverage.contains("msm"),
        "GPU attribution should preserve Metal stage coverage, got {coverage:?}",
    );
    assert!(
        artifact_evidence
            .get("groth16_msm_engine")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|engine| engine.contains("metal")),
        "GPU attribution should preserve a Metal MSM engine marker",
    );
}

fn assert_metal_artifact_metadata(artifact_metadata: &serde_json::Value) {
    assert_eq!(
        artifact_metadata
            .get("metal_complete")
            .and_then(serde_json::Value::as_str),
        Some("true"),
        "artifact metadata should preserve metal_complete=true",
    );
    let coverage = artifact_metadata
        .get("gpu_stage_coverage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        coverage.contains("fft-ntt")
            && coverage.contains("qap-witness-map")
            && coverage.contains("msm"),
        "artifact metadata should preserve Metal stage coverage, got {coverage:?}",
    );
    assert!(
        artifact_metadata
            .get("groth16_msm_engine")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|engine| engine.contains("metal")),
        "artifact metadata should preserve a Metal MSM engine marker",
    );
    assert!(
        artifact_metadata
            .get("qap_witness_map_engine")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "artifact metadata should preserve qap_witness_map_engine",
    );
}

fn assert_execution_trace_checkpoint(
    trace: &serde_json::Value,
    full_audit_requested: bool,
    export_profile: &str,
    bundle_mode: &str,
) {
    assert_eq!(
        trace
            .get("schema_version")
            .and_then(serde_json::Value::as_str),
        Some("private-powered-descent-execution-trace-v3")
    );
    assert_eq!(
        trace.get("app_id").and_then(serde_json::Value::as_str),
        Some("private_powered_descent_showcase")
    );
    assert_eq!(
        trace
            .get("full_audit_requested")
            .and_then(serde_json::Value::as_bool),
        Some(full_audit_requested)
    );
    assert_eq!(
        trace
            .get("export_profile")
            .and_then(serde_json::Value::as_str),
        Some(export_profile)
    );
    assert_eq!(
        trace.get("bundle_mode").and_then(serde_json::Value::as_str),
        Some(bundle_mode)
    );
    assert!(
        trace
            .get("source_prove")
            .and_then(|value| value.get("runtime_report"))
            .is_some(),
        "execution trace should persist the serialized runtime report snapshot",
    );
    assert!(
        trace.get("formal_evidence").is_some(),
        "execution trace should persist formal evidence",
    );
    assert!(
        trace.get("generated_closure_summary").is_some(),
        "execution trace should persist generated closure summary",
    );
}

fn apply_toolchain_env(command: &mut Command) {
    if let Some(value) = std::env::var_os("CARGO_HOME") {
        command.env("CARGO_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("CARGO_HOME", Path::new(&home).join(".cargo"));
    }

    if let Some(value) = std::env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("RUSTUP_HOME", Path::new(&home).join(".rustup"));
    }

    if let Some(value) = std::env::var_os("OPAMROOT") {
        command.env("OPAMROOT", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("OPAMROOT", Path::new(&home).join(".opam"));
    }

    if let Some(value) = std::env::var_os("ELAN_HOME") {
        command.env("ELAN_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("ELAN_HOME", Path::new(&home).join(".elan"));
    }
}

fn run_powered_descent_example(
    example_binary: &Path,
    home: &Path,
    output_dir: &Path,
    request: Option<&Path>,
    full_audit: bool,
    steps_override: Option<&str>,
) {
    let mut example = Command::new(example_binary);
    example
        .current_dir(repo_root())
        .arg(output_dir)
        .env("HOME", home)
        .env("ZKF_SWARM", "1")
        .env("ZKF_SWARM_KEY_BACKEND", "file")
        .env("ZKF_SECURITY_POLICY_MODE", "observe");
    if let Some(request) = request {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_INPUTS_JSON", request);
    }
    if let Some(steps_override) = steps_override {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_STEPS_OVERRIDE", steps_override);
    }
    if full_audit {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT", "1");
    }
    apply_toolchain_env(&mut example);
    assert_command_success(
        example
            .output()
            .expect("run powered descent example binary"),
        "powered descent showcase example binary",
    );
}

fn run_powered_descent_example_output(
    example_binary: &Path,
    home: &Path,
    output_dir: &Path,
    request: Option<&Path>,
    full_audit: bool,
    steps_override: Option<&str>,
    extra_env: &[(&str, OsString)],
) -> Output {
    let mut example = Command::new(example_binary);
    example
        .current_dir(repo_root())
        .arg(output_dir)
        .env("HOME", home)
        .env("ZKF_SWARM", "1")
        .env("ZKF_SWARM_KEY_BACKEND", "file")
        .env("ZKF_SECURITY_POLICY_MODE", "observe");
    if let Some(request) = request {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_INPUTS_JSON", request);
    }
    if let Some(steps_override) = steps_override {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_STEPS_OVERRIDE", steps_override);
    }
    if full_audit {
        example.env("ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT", "1");
    }
    for (key, value) in extra_env {
        example.env(key, value);
    }
    apply_toolchain_env(&mut example);
    example
        .output()
        .expect("run powered descent example binary")
}

fn write_trusted_setup_fixture(root: &Path, steps: usize) -> (PathBuf, PathBuf) {
    let setup_dir = root.join("trusted-setup");
    fs::create_dir_all(&setup_dir).expect("create trusted setup fixture dir");
    let previous_streamed_setup = std::env::var_os("ZKF_GROTH16_STREAMED_SETUP");
    unsafe {
        std::env::set_var("ZKF_GROTH16_STREAMED_SETUP", "0");
    }

    let template = private_powered_descent_showcase_with_steps(steps).expect("descent template");
    let (optimized_program, _optimizer_report) = optimize_program(&template.program);
    let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_setup_seed_override(Some(SETUP_SEED), || {
            backend_for(BackendKind::ArkworksGroth16).compile(&optimized_program)
        })
    })
    .expect("compile trusted setup fixture");
    let setup_blob = compiled
        .compiled_data
        .clone()
        .expect("trusted setup fixture compiled_data");

    let base_witness = private_powered_descent_witness_with_steps(&template.sample_inputs, steps)
        .expect("descent witness");
    let prepared_witness =
        prepare_witness_for_proving(&compiled, &base_witness).expect("prepared witness");
    check_constraints(&compiled.program, &prepared_witness)
        .expect("prepared witness satisfies compiled program");
    let proof = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_proof_seed_override(Some(PROOF_SEED), || prove(&compiled, &prepared_witness))
    })
    .expect("prove trusted setup fixture");

    let setup_blob_path = setup_dir.join("private_powered_descent.groth16.setup.blob");
    fs::write(&setup_blob_path, &setup_blob).expect("write trusted setup blob");
    let manifest_path = append_path_suffix(&setup_blob_path, ".manifest.json");
    let manifest = serde_json::json!({
        "schema_version": TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION,
        "setup_blob_sha256": sha256_hex(&setup_blob),
        "vk_sha256": sha256_hex(&proof.verification_key),
        "ceremony_id": "integration-test-powered-descent-imported-setup",
        "ceremony_kind": "operator-imported-test-fixture",
        "ceremony_transcript_sha256": sha256_hex(b"integration-test-powered-descent-transcript"),
        "source": "zkf-integration-tests",
        "generated_at": "2026-03-27T00:00:00Z",
        "notes": {
            "test_fixture": true,
            "steps": steps,
        },
    });
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize trusted setup manifest"),
    )
    .expect("write trusted setup manifest");

    unsafe {
        if let Some(previous) = previous_streamed_setup {
            std::env::set_var("ZKF_GROTH16_STREAMED_SETUP", previous);
        } else {
            std::env::remove_var("ZKF_GROTH16_STREAMED_SETUP");
        }
    }

    (setup_blob_path, manifest_path)
}

fn build_showcase_example_binary() -> std::path::PathBuf {
    let mut build = Command::new("cargo");
    build
        .current_dir(repo_root())
        .arg("build")
        .arg("-p")
        .arg("zkf-lib")
        .arg("--example")
        .arg("private_powered_descent_showcase")
        .arg("--release");
    apply_toolchain_env(&mut build);
    assert_command_success(
        build.output().expect("build powered descent example"),
        "cargo build powered descent showcase example",
    );

    cargo_target_dir()
        .join("release")
        .join("examples")
        .join("private_powered_descent_showcase")
}

fn assert_command_success(output: Output, description: &str) {
    #[cfg(unix)]
    let status_detail = output
        .status
        .signal()
        .map(|signal| format!("signal {signal}"))
        .unwrap_or_else(|| format!("code {:?}", output.status.code()));
    #[cfg(not(unix))]
    let status_detail = format!("code {:?}", output.status.code());
    assert!(
        output.status.success(),
        "{description} failed with status {status_detail}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_command_failure_contains(output: Output, description: &str, needle: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "{description} unexpectedly succeeded\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stdout.contains(needle) || stderr.contains(needle),
        "{description} did not mention {needle:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
}

fn run_foundry_validation_suite(foundry_dir: &Path, home: &Path, description_prefix: &str) {
    for (subcommand, description) in [
        (
            vec!["fmt".to_string(), "--check".to_string()],
            format!("{description_prefix} forge fmt --check"),
        ),
        (
            vec!["test".to_string()],
            format!("{description_prefix} forge test"),
        ),
        (
            vec![
                "coverage".to_string(),
                "--report".to_string(),
                "summary".to_string(),
                "--report".to_string(),
                "lcov".to_string(),
            ],
            format!("{description_prefix} forge coverage"),
        ),
    ] {
        let mut forge = Command::new("forge");
        forge
            .current_dir(foundry_dir)
            .args(&subcommand)
            .env("HOME", home)
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe");
        apply_toolchain_env(&mut forge);
        assert_command_success(forge.output().expect("run forge command"), &description);
    }
}

#[test]
fn private_powered_descent_showcase_roundtrips_through_runtime_and_exports_assets() {
    run_with_large_stack("powered-descent-runtime-roundtrip", || {
        with_swarm_home(|home| {
            let template =
                private_powered_descent_showcase_with_steps(1).expect("descent template");
            let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
                with_setup_seed_override(Some(SETUP_SEED), || {
                    compile_arkworks_unchecked(&template.program)
                })
            })
            .expect("compile descent showcase");

            let base_witness =
                private_powered_descent_witness_with_steps(&template.sample_inputs, 1)
                    .expect("descent witness");
            let prepared_witness =
                prepare_witness_for_proving(&compiled, &base_witness).expect("prepared witness");

            check_constraints(&compiled.program, &prepared_witness)
                .expect("prepared witness satisfies compiled program");

            let direct_artifact = with_allow_dev_deterministic_groth16_override(Some(true), || {
                with_proof_seed_override(Some(PROOF_SEED), || prove(&compiled, &prepared_witness))
            })
            .expect("direct prove");
            assert!(
                verify(&compiled, &direct_artifact).expect("direct verify"),
                "direct proof must verify"
            );

            let runtime_execution =
                with_allow_dev_deterministic_groth16_override(Some(true), || {
                    with_proof_seed_override(Some(PROOF_SEED), || {
                        RuntimeExecutor::run_backend_prove_job_with_objective(
                            BackendKind::ArkworksGroth16,
                            BackendRoute::Auto,
                            Arc::new(template.program.clone()),
                            Some(Arc::new(template.sample_inputs.clone())),
                            Some(Arc::new(base_witness.clone())),
                            Some(Arc::new(compiled.clone())),
                            OptimizationObjective::FastestProve,
                            RequiredTrustLane::StrictCryptographic,
                            ExecutionMode::Deterministic,
                        )
                    })
                })
                .expect("runtime prove");

            assert!(
                verify(&runtime_execution.compiled, &runtime_execution.artifact)
                    .expect("runtime verify"),
                "runtime proof must verify"
            );
            assert_eq!(
                runtime_execution.artifact.public_inputs, direct_artifact.public_inputs,
                "runtime proof must preserve deterministic public inputs",
            );
            assert_eq!(
                runtime_execution.compiled.program_digest, compiled.program_digest,
                "runtime prove should reuse the supplied compiled artifact while normalizing the witness"
            );

            let verifier_source = export_groth16_solidity_verifier(
                &runtime_execution.artifact,
                Some("PrivatePoweredDescentVerifier"),
            )
            .expect("solidity verifier");
            assert!(
                verifier_source.contains("contract PrivatePoweredDescentVerifier"),
                "verifier contract name should match requested identifier"
            );

            let calldata = proof_to_calldata_json(
                &runtime_execution.artifact.proof,
                &runtime_execution.artifact.public_inputs,
            )
            .expect("calldata");
            assert!(
                calldata.is_object() || calldata.is_array(),
                "calldata export should be structured JSON"
            );

            let foundry = generate_foundry_test_from_artifact(
                &runtime_execution.artifact.proof,
                &runtime_execution.artifact.public_inputs,
                "../src/PrivatePoweredDescentVerifier.sol",
                "PrivatePoweredDescentVerifier",
            )
            .expect("foundry test");
            assert!(
                foundry.source.contains("PrivatePoweredDescentVerifier"),
                "foundry test should reference the generated verifier"
            );

            let telemetry_dir = home.join(".zkf").join("telemetry");
            let telemetry_files = std::fs::read_dir(&telemetry_dir)
                .expect("telemetry dir")
                .filter_map(Result::ok)
                .count();
            assert!(
                telemetry_files > 0,
                "runtime prove should emit telemetry records when swarm is enabled"
            );

            let swarm_root = home.join(".zkf").join("swarm");
            assert!(
                swarm_root.exists(),
                "swarm-enabled execution should materialize swarm state under HOME"
            );
        })
    });
}

#[test]
fn private_powered_descent_showcase_example_exports_bundle_and_reverifies_from_disk() {
    run_with_large_stack("powered-descent-example-export", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home.path().join("powered-descent-showcase");
        let example_binary = build_showcase_example_binary();

        run_powered_descent_example(
            &example_binary,
            temp_home.path(),
            &output_dir,
            None,
            false,
            Some("2"),
        );

        let program_original_path =
            output_dir.join("private_powered_descent.original.program.json");
        let program_optimized_path =
            output_dir.join("private_powered_descent.optimized.program.json");
        let compiled_path = output_dir.join("private_powered_descent.compiled.json");
        let inputs_path = output_dir.join("private_powered_descent.inputs.json");
        let witness_base_path = output_dir.join("private_powered_descent.witness.base.json");
        let witness_path = output_dir.join("private_powered_descent.witness.prepared.json");
        let proof_path = output_dir.join("private_powered_descent.runtime.proof.json");
        let verifier_path = output_dir.join("PrivatePoweredDescentVerifier.sol");
        let calldata_path = output_dir.join("private_powered_descent.calldata.json");
        let summary_path = output_dir.join("private_powered_descent.summary.json");
        let audit_path = output_dir.join("private_powered_descent.audit.json");
        let audit_summary_path = output_dir.join("private_powered_descent.audit_summary.json");
        let evidence_manifest_path =
            output_dir.join("private_powered_descent.evidence_manifest.json");
        let matrix_path = output_dir.join("private_powered_descent.matrix_ccs_summary.json");
        let runtime_trace_path = output_dir.join("private_powered_descent.runtime_trace.json");
        let execution_trace_path = output_dir.join("private_powered_descent.execution_trace.json");
        let report_path = output_dir.join("private_powered_descent.report.md");
        let mission_assurance_path =
            output_dir.join("private_powered_descent.mission_assurance.md");
        let formal_dir = output_dir.join("formal");
        let formal_status_path = formal_dir.join("STATUS.md");
        let rocq_log_path = formal_dir.join("rocq.log");
        let protocol_lean_log_path = formal_dir.join("protocol_lean.log");
        let verus_descent_log_path = formal_dir.join("verus_powered_descent.log");
        let exercised_surfaces_path = formal_dir.join("exercised_surfaces.json");
        let foundry_dir = output_dir.join("foundry");
        let foundry_toml_path = foundry_dir.join("foundry.toml");
        let foundry_verifier_path = foundry_dir.join("src/PrivatePoweredDescentVerifier.sol");
        let foundry_test_path = foundry_dir.join("test/PrivatePoweredDescentVerifier.t.sol");

        assert_file_exists(&program_original_path);
        assert_file_exists(&program_optimized_path);
        assert_file_exists(&compiled_path);
        assert_file_exists(&inputs_path);
        assert_file_exists(&witness_base_path);
        assert_file_exists(&witness_path);
        assert_file_exists(&proof_path);
        assert_file_exists(&verifier_path);
        assert_file_exists(&calldata_path);
        assert_file_exists(&summary_path);
        assert_file_exists(&audit_path);
        assert_file_exists(&audit_summary_path);
        assert_file_exists(&evidence_manifest_path);
        assert_file_exists(&matrix_path);
        assert_file_exists(&runtime_trace_path);
        assert_file_exists(&execution_trace_path);
        assert_file_exists(&report_path);
        assert_file_exists(&mission_assurance_path);
        assert_dir_exists(&formal_dir);
        assert_file_exists(&formal_status_path);
        assert_file_exists(&rocq_log_path);
        assert_file_exists(&protocol_lean_log_path);
        assert_file_exists(&verus_descent_log_path);
        assert_file_exists(&exercised_surfaces_path);
        assert_dir_exists(&foundry_dir);
        assert_file_exists(&foundry_toml_path);
        assert_file_exists(&foundry_verifier_path);
        assert_file_exists(&foundry_test_path);

        let _: Program = read_json(&program_original_path);
        let _: Program = read_json(&program_optimized_path);
        let compiled: CompiledProgram = read_json(&compiled_path);
        let _: WitnessInputs = read_json(&inputs_path);
        let _: Witness = read_json(&witness_base_path);
        let _: Witness = read_json(&witness_path);
        let runtime_artifact: ProofArtifact = read_json(&proof_path);
        let _: serde_json::Value = read_json(&calldata_path);
        let summary: serde_json::Value = read_json(&summary_path);
        let audit: serde_json::Value = read_json(&audit_path);
        let audit_summary: serde_json::Value = read_json(&audit_summary_path);
        let evidence_manifest: serde_json::Value = read_json(&evidence_manifest_path);
        let _: serde_json::Value = read_json(&matrix_path);
        let runtime_trace: serde_json::Value = read_json(&runtime_trace_path);
        let execution_trace: serde_json::Value = read_json(&execution_trace_path);
        let exercised_surfaces: serde_json::Value = read_json(&exercised_surfaces_path);
        let formal_status = evidence_manifest
            .get("formal_evidence")
            .and_then(|value| value.get("status"))
            .and_then(serde_json::Value::as_str);

        assert!(
            verify(&compiled, &runtime_artifact).expect("runtime proof reverify from disk"),
            "runtime proof exported by the example must verify from disk"
        );
        assert_eq!(
            audit, audit_summary,
            "audit.json and audit_summary.json should stay identical"
        );

        assert_eq!(
            audit.get("mode").and_then(serde_json::Value::as_str),
            Some("two-tier-showcase-audit-v1")
        );
        assert_eq!(
            audit_summary
                .get("mode")
                .and_then(serde_json::Value::as_str),
            Some("two-tier-showcase-audit-v1")
        );
        assert!(
            matches!(formal_status, Some("included") | Some("failed")),
            "formal evidence status should be explicit, got {formal_status:?}"
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("runs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|runs| runs.iter().any(|run| {
                    run.get("name").and_then(serde_json::Value::as_str) == Some("protocol_lean")
                })),
            "formal evidence should record the protocol_lean runner explicitly"
        );
        assert_eq!(
            evidence_manifest
                .get("audit_coverage")
                .and_then(|value| value.get("full_source_audit"))
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("omitted-by-default")
        );
        assert_eq!(
            evidence_manifest
                .get("audit_coverage")
                .and_then(|value| value.get("full_compiled_audit"))
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("omitted-by-default")
        );
        assert_eq!(
            summary
                .get("backend")
                .and_then(|value| value.get("export"))
                .and_then(serde_json::Value::as_str),
            Some("runtime-strict-groth16")
        );
        assert_eq!(
            runtime_trace
                .get("export")
                .and_then(|value| value.get("mode"))
                .and_then(serde_json::Value::as_str),
            Some("runtime-strict-groth16")
        );
        assert_eq!(
            runtime_trace
                .get("export")
                .and_then(|value| value.get("process_mode"))
                .and_then(serde_json::Value::as_str),
            Some("fresh-process-finalize-bundle")
        );
        assert_execution_trace_checkpoint(&execution_trace, false, "development", "debug");
        assert_eq!(
            exercised_surfaces
                .get("generated_closure_path")
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_powered_descent_showcase.json")
        );
        assert_eq!(
            evidence_manifest
                .get("generated_closure")
                .and_then(|value| value.get("extract_path"))
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_powered_descent_showcase.json")
        );
        assert_eq!(
            evidence_manifest
                .get("generated_closure")
                .and_then(|value| value.get("assurance_counts")),
            exercised_surfaces.get("assurance_counts")
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("files"))
                .and_then(|value| value.get("logs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|logs| logs
                    .iter()
                    .any(|entry| { entry.as_str() == Some("formal/verus_powered_descent.log") })),
            "formal evidence manifest should record the powered descent Verus log"
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("runs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|runs| runs.iter().any(|run| {
                    run.get("name").and_then(serde_json::Value::as_str)
                        == Some("verus_powered_descent")
                        && run.get("status").and_then(serde_json::Value::as_str) == Some("passed")
                })),
            "formal evidence manifest should record a passing powered descent Verus run"
        );
        assert_gpu_backed_attribution(
            summary
                .get("effective_gpu_attribution")
                .expect("summary effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            runtime_trace
                .get("effective_gpu_attribution")
                .expect("runtime trace effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            evidence_manifest
                .get("gpu_attribution")
                .expect("evidence manifest gpu attribution"),
        );
        assert_gpu_backed_attribution(
            runtime_trace
                .get("source_prove")
                .and_then(|value| value.get("effective_gpu_attribution"))
                .expect("runtime trace source_prove effective gpu attribution"),
        );
        assert_metal_artifact_metadata(
            summary
                .get("artifact_metadata")
                .expect("summary artifact metadata"),
        );

        let verifier_source = fs::read_to_string(&verifier_path).expect("read verifier");
        assert!(
            verifier_source.contains("contract PrivatePoweredDescentVerifier"),
            "exported verifier should contain the expected contract"
        );
        let foundry_manifest =
            fs::read_to_string(&foundry_toml_path).expect("read foundry manifest");
        assert!(
            foundry_manifest.contains("[profile.default]"),
            "generated Foundry manifest should contain a default profile"
        );
        assert!(
            foundry_manifest.contains("solc_version = \"0.8.26\""),
            "generated Foundry manifest should pin solc 0.8.26"
        );
        let foundry_test = fs::read_to_string(&foundry_test_path).expect("read foundry test");
        assert!(
            foundry_test.contains("PrivatePoweredDescentVerifier"),
            "generated Foundry test should reference the verifier contract"
        );
        let report = fs::read_to_string(&report_path).expect("read markdown report");
        assert!(
            report.contains("# ZirOS Private Powered Descent Showcase"),
            "generated report should contain the showcase heading"
        );
        assert!(
            report.contains("formal/STATUS.md"),
            "generated report should reference the bundled formal status file"
        );
        assert!(
            report.contains("formal/exercised_surfaces.json"),
            "generated report should reference the exercised surfaces bundle"
        );
        assert!(
            report.contains("powered-descent-Verus")
                || report.contains("verus_powered_descent")
                || report.contains("Powered Descent Verus"),
            "generated report should reference the bundled powered descent Verus log"
        );
        let formal_status = fs::read_to_string(&formal_status_path).expect("read formal status");
        assert!(
            formal_status.contains("formal/exercised_surfaces.json"),
            "formal status should reference the exercised surfaces bundle"
        );
        assert!(
            formal_status.contains("verus_powered_descent"),
            "formal status should record the powered descent Verus run"
        );
        let mission_assurance =
            fs::read_to_string(&mission_assurance_path).expect("read mission assurance report");
        assert!(
            mission_assurance.contains("# ZirOS Private Powered Descent Showcase"),
            "mission assurance report should contain the showcase heading"
        );

        let mut forge = Command::new("forge");
        forge
            .current_dir(&foundry_dir)
            .arg("test")
            .env("HOME", temp_home.path())
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe");
        apply_toolchain_env(&mut forge);
        assert_command_success(
            forge.output().expect("run forge test"),
            "forge test on exported Foundry project",
        );
    });
}

#[test]
fn private_powered_descent_showcase_small_full_audit_exports_finished_bundle() {
    run_with_large_stack("powered-descent-example-export-small-full-audit", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home
            .path()
            .join("powered-descent-showcase-small-full-audit");
        let example_binary = build_showcase_example_binary();

        run_powered_descent_example(
            &example_binary,
            temp_home.path(),
            &output_dir,
            None,
            true,
            Some("2"),
        );

        let audit_dir = output_dir.join("audit");
        let source_audit_path = audit_dir.join("private_powered_descent.source_audit.json");
        let compiled_audit_path = audit_dir.join("private_powered_descent.compiled_audit.json");
        let summary_path = output_dir.join("private_powered_descent.summary.json");
        let audit_path = output_dir.join("private_powered_descent.audit.json");
        let audit_summary_path = output_dir.join("private_powered_descent.audit_summary.json");
        let runtime_trace_path = output_dir.join("private_powered_descent.runtime_trace.json");
        let execution_trace_path = output_dir.join("private_powered_descent.execution_trace.json");
        let evidence_manifest_path =
            output_dir.join("private_powered_descent.evidence_manifest.json");
        let report_path = output_dir.join("private_powered_descent.report.md");
        let mission_assurance_path =
            output_dir.join("private_powered_descent.mission_assurance.md");
        let compiled_path = output_dir.join("private_powered_descent.compiled.json");
        let proof_path = output_dir.join("private_powered_descent.runtime.proof.json");

        assert_dir_exists(&audit_dir);
        assert_file_exists(&source_audit_path);
        assert_file_exists(&compiled_audit_path);
        assert_file_exists(&summary_path);
        assert_file_exists(&audit_path);
        assert_file_exists(&audit_summary_path);
        assert_file_exists(&runtime_trace_path);
        assert_file_exists(&execution_trace_path);
        assert_file_exists(&evidence_manifest_path);
        assert_file_exists(&report_path);
        assert_file_exists(&mission_assurance_path);

        let compiled: CompiledProgram = read_json(&compiled_path);
        let runtime_artifact: ProofArtifact = read_json(&proof_path);
        let source_audit: serde_json::Value = read_json(&source_audit_path);
        let compiled_audit: serde_json::Value = read_json(&compiled_audit_path);
        let summary: serde_json::Value = read_json(&summary_path);
        let audit: serde_json::Value = read_json(&audit_path);
        let audit_summary: serde_json::Value = read_json(&audit_summary_path);
        let runtime_trace: serde_json::Value = read_json(&runtime_trace_path);
        let execution_trace: serde_json::Value = read_json(&execution_trace_path);
        let evidence_manifest: serde_json::Value = read_json(&evidence_manifest_path);

        assert!(
            verify(&compiled, &runtime_artifact).expect("runtime proof reverify from disk"),
            "small full-audit runtime proof must verify from disk"
        );
        assert_eq!(
            audit, audit_summary,
            "audit.json and audit_summary.json should stay identical"
        );
        assert_execution_trace_checkpoint(&execution_trace, true, "development", "debug");
        assert_eq!(
            audit_summary
                .get("full_source_audit")
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            audit_summary
                .get("full_compiled_audit")
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            evidence_manifest
                .get("audit_coverage")
                .and_then(|value| value.get("full_source_audit"))
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            evidence_manifest
                .get("audit_coverage")
                .and_then(|value| value.get("full_compiled_audit"))
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            runtime_trace
                .get("export")
                .and_then(|value| value.get("process_mode"))
                .and_then(serde_json::Value::as_str),
            Some("fresh-process-finalize-bundle")
        );
        assert!(
            source_audit.get("summary").is_some(),
            "source audit should contain a summary",
        );
        assert!(
            compiled_audit.get("summary").is_some(),
            "compiled audit should contain a summary",
        );
        assert_gpu_backed_attribution(
            summary
                .get("effective_gpu_attribution")
                .expect("summary effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            runtime_trace
                .get("effective_gpu_attribution")
                .expect("runtime trace effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            evidence_manifest
                .get("gpu_attribution")
                .expect("evidence manifest gpu attribution"),
        );
        assert_metal_artifact_metadata(
            summary
                .get("artifact_metadata")
                .expect("summary artifact metadata"),
        );
    });
}

#[test]
fn private_powered_descent_showcase_public_bundle_omits_private_artifacts_and_sanitizes_metadata() {
    run_with_large_stack("powered-descent-public-bundle", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home.path().join("powered-descent-public-bundle");
        let example_binary = build_showcase_example_binary();
        let extra_env = [(BUNDLE_MODE_ENV, OsString::from("public"))];

        assert_command_success(
            run_powered_descent_example_output(
                &example_binary,
                temp_home.path(),
                &output_dir,
                None,
                false,
                Some("2"),
                &extra_env,
            ),
            "powered descent public bundle example binary",
        );

        let summary_path = output_dir.join("private_powered_descent.summary.json");
        let audit_summary_path = output_dir.join("private_powered_descent.audit_summary.json");
        let runtime_trace_path = output_dir.join("private_powered_descent.runtime_trace.json");
        let execution_trace_path = output_dir.join("private_powered_descent.execution_trace.json");
        let evidence_manifest_path =
            output_dir.join("private_powered_descent.evidence_manifest.json");
        let report_path = output_dir.join("private_powered_descent.report.md");
        let bundle_readme_path = output_dir.join("README.md");
        let foundry_dir = output_dir.join("foundry");

        for path in [
            output_dir.join("private_powered_descent.original.program.json"),
            output_dir.join("private_powered_descent.optimized.program.json"),
            output_dir.join("private_powered_descent.compiled.json"),
            output_dir.join("private_powered_descent.inputs.json"),
            output_dir.join("private_powered_descent.witness.base.json"),
            output_dir.join("private_powered_descent.witness.prepared.json"),
            output_dir.join("private_powered_descent.matrix_ccs_summary.json"),
            output_dir.join("private_powered_descent.request.json"),
        ] {
            assert!(
                !path.exists(),
                "public bundle should omit {}",
                path.display()
            );
        }

        assert_file_exists(&summary_path);
        assert_file_exists(&audit_summary_path);
        assert_file_exists(&runtime_trace_path);
        assert_file_exists(&execution_trace_path);
        assert_file_exists(&evidence_manifest_path);
        assert_file_exists(&report_path);
        assert_file_exists(&bundle_readme_path);
        assert_dir_exists(&foundry_dir);

        let summary: serde_json::Value = read_json(&summary_path);
        let audit_summary: serde_json::Value = read_json(&audit_summary_path);
        let runtime_trace: serde_json::Value = read_json(&runtime_trace_path);
        let execution_trace: serde_json::Value = read_json(&execution_trace_path);
        let evidence_manifest: serde_json::Value = read_json(&evidence_manifest_path);
        let report = fs::read_to_string(&report_path).expect("read public report");
        let bundle_readme = fs::read_to_string(&bundle_readme_path).expect("read bundle readme");
        let formal_status =
            fs::read_to_string(output_dir.join("formal/STATUS.md")).expect("read formal status");

        assert_eq!(
            summary
                .get("bundle_mode")
                .and_then(serde_json::Value::as_str),
            Some("public")
        );
        assert_eq!(
            summary
                .get("release_safety")
                .and_then(serde_json::Value::as_str),
            Some("demo-only")
        );
        assert_eq!(
            summary
                .get("request_source_ref")
                .and_then(serde_json::Value::as_str),
            Some("template-sample-inputs")
        );
        assert_execution_trace_checkpoint(&execution_trace, false, "development", "public");
        assert_eq!(
            execution_trace
                .get("release_safety")
                .and_then(serde_json::Value::as_str),
            Some("demo-only")
        );
        assert!(
            summary
                .get("telemetry_artifacts")
                .and_then(|value| value.get("count"))
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "public bundle summary should expose telemetry_artifacts count"
        );

        for value in [
            &summary,
            &audit_summary,
            &runtime_trace,
            &execution_trace,
            &evidence_manifest,
        ] {
            assert_json_has_no_public_path_leaks(value, temp_home.path(), &output_dir);
        }
        for text in [&report, &bundle_readme, &formal_status] {
            assert_text_has_no_public_path_leaks(text, temp_home.path(), &output_dir);
        }

        run_foundry_validation_suite(&foundry_dir, temp_home.path(), "public bundle");

        let validator = Command::new("python3")
            .current_dir(repo_root())
            .arg("scripts/check_powered_descent_release_bundle.py")
            .arg("--bundle")
            .arg(&output_dir)
            .output()
            .expect("run powered descent bundle validator");
        assert_command_success(validator, "public bundle validator");
    });
}

#[test]
fn private_powered_descent_showcase_public_imported_setup_bundle_stays_demo_only() {
    run_with_large_stack("powered-descent-public-imported-setup", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home
            .path()
            .join("powered-descent-public-imported-setup");
        let example_binary = build_showcase_example_binary();
        let (setup_blob_path, manifest_path) = write_trusted_setup_fixture(temp_home.path(), 2);
        let extra_env = [
            (BUNDLE_MODE_ENV, OsString::from("public")),
            (PRODUCTION_ENV, OsString::from("1")),
            (
                GROTH16_SETUP_BLOB_PATH_ENV,
                setup_blob_path.clone().into_os_string(),
            ),
            (
                TRUSTED_SETUP_MANIFEST_ENV,
                manifest_path.clone().into_os_string(),
            ),
        ];

        assert_command_success(
            run_powered_descent_example_output(
                &example_binary,
                temp_home.path(),
                &output_dir,
                None,
                false,
                Some("2"),
                &extra_env,
            ),
            "powered descent public imported-setup bundle example binary",
        );

        let summary: serde_json::Value =
            read_json(&output_dir.join("private_powered_descent.summary.json"));
        let evidence_manifest: serde_json::Value =
            read_json(&output_dir.join("private_powered_descent.evidence_manifest.json"));
        let execution_trace: serde_json::Value =
            read_json(&output_dir.join("private_powered_descent.execution_trace.json"));

        assert_eq!(
            summary
                .get("export_profile")
                .and_then(serde_json::Value::as_str),
            Some("production")
        );
        assert_eq!(
            summary
                .get("bundle_mode")
                .and_then(serde_json::Value::as_str),
            Some("public")
        );
        assert_eq!(
            summary
                .get("release_safety")
                .and_then(serde_json::Value::as_str),
            Some("demo-only")
        );
        assert_execution_trace_checkpoint(&execution_trace, false, "production", "public");
        assert_eq!(
            evidence_manifest
                .get("trusted_setup_manifest")
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        let source_ref = evidence_manifest
            .get("trusted_setup_manifest")
            .and_then(|value| value.get("source_ref"))
            .and_then(serde_json::Value::as_str)
            .expect("trusted setup source_ref");
        assert!(
            !source_ref.contains(&temp_home.path().display().to_string()),
            "trusted setup source_ref should be sanitized, got {source_ref}"
        );

        let validator = Command::new("python3")
            .current_dir(repo_root())
            .arg("scripts/check_powered_descent_release_bundle.py")
            .arg("--bundle")
            .arg(&output_dir)
            .arg("--require-release-safe")
            .output()
            .expect("run powered descent release-safe validator");
        assert_command_failure_contains(
            validator,
            "public imported-setup bundle release gate",
            "demo-only",
        );
    });
}

#[test]
fn private_powered_descent_showcase_request_fixture_200_step_exports_and_reverifies() {
    run_with_large_stack("powered-descent-example-export-200-step", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home.path().join("powered-descent-showcase-200-step");
        let example_binary = build_showcase_example_binary();
        let request_path = powered_descent_fixture_path("request_200_step.json");
        let request: PrivatePoweredDescentRequestV1 = read_json(&request_path);
        assert_eq!(request.public.step_count, 200);
        assert_eq!(request.private.thrust_profile.len(), 200);

        run_powered_descent_example(
            &example_binary,
            temp_home.path(),
            &output_dir,
            Some(&request_path),
            true,
            None,
        );

        let request_export_path = output_dir.join("private_powered_descent.request.json");
        let summary_path = output_dir.join("private_powered_descent.summary.json");
        let compiled_path = output_dir.join("private_powered_descent.compiled.json");
        let proof_path = output_dir.join("private_powered_descent.runtime.proof.json");
        let witness_path = output_dir.join("private_powered_descent.witness.prepared.json");
        let evidence_manifest_path =
            output_dir.join("private_powered_descent.evidence_manifest.json");
        let audit_path = output_dir.join("private_powered_descent.audit.json");
        let audit_summary_path = output_dir.join("private_powered_descent.audit_summary.json");
        let runtime_trace_path = output_dir.join("private_powered_descent.runtime_trace.json");
        let execution_trace_path = output_dir.join("private_powered_descent.execution_trace.json");
        let report_path = output_dir.join("private_powered_descent.report.md");
        let mission_assurance_path =
            output_dir.join("private_powered_descent.mission_assurance.md");
        let exercised_surfaces_path = output_dir.join("formal/exercised_surfaces.json");
        let foundry_dir = output_dir.join("foundry");
        let audit_dir = output_dir.join("audit");
        let source_audit_path = audit_dir.join("private_powered_descent.source_audit.json");
        let compiled_audit_path = audit_dir.join("private_powered_descent.compiled_audit.json");

        assert_file_exists(&request_export_path);
        assert_file_exists(&summary_path);
        assert_file_exists(&compiled_path);
        assert_file_exists(&proof_path);
        assert_file_exists(&witness_path);
        assert_file_exists(&evidence_manifest_path);
        assert_file_exists(&audit_path);
        assert_file_exists(&audit_summary_path);
        assert_file_exists(&runtime_trace_path);
        assert_file_exists(&execution_trace_path);
        assert_file_exists(&report_path);
        assert_file_exists(&mission_assurance_path);
        assert_file_exists(&exercised_surfaces_path);
        assert_dir_exists(&foundry_dir);
        assert_dir_exists(&audit_dir);
        assert_file_exists(&source_audit_path);
        assert_file_exists(&compiled_audit_path);

        let exported_request: PrivatePoweredDescentRequestV1 = read_json(&request_export_path);
        let summary: serde_json::Value = read_json(&summary_path);
        let compiled: CompiledProgram = read_json(&compiled_path);
        let runtime_artifact: ProofArtifact = read_json(&proof_path);
        let witness: Witness = read_json(&witness_path);
        let evidence_manifest: serde_json::Value = read_json(&evidence_manifest_path);
        let audit: serde_json::Value = read_json(&audit_path);
        let audit_summary: serde_json::Value = read_json(&audit_summary_path);
        let runtime_trace: serde_json::Value = read_json(&runtime_trace_path);
        let execution_trace: serde_json::Value = read_json(&execution_trace_path);
        let exercised_surfaces: serde_json::Value = read_json(&exercised_surfaces_path);
        let source_audit: serde_json::Value = read_json(&source_audit_path);
        let compiled_audit: serde_json::Value = read_json(&compiled_audit_path);

        assert_eq!(exported_request, request);
        assert_eq!(
            summary
                .get("input_mode")
                .and_then(serde_json::Value::as_str),
            Some("request-json-v1")
        );
        assert_eq!(
            summary
                .get("step_count")
                .and_then(serde_json::Value::as_u64),
            Some(200)
        );
        assert_eq!(
            summary
                .get("bundle_identity")
                .and_then(|value| value.get("integration_steps"))
                .and_then(serde_json::Value::as_u64),
            Some(200)
        );
        assert!(
            summary
                .get("runtime_memory_plan")
                .and_then(|value| value.get("compiled_constraint_count"))
                .is_some(),
            "summary should emit runtime memory-plan telemetry"
        );
        assert!(
            summary
                .get("runtime_memory_plan")
                .and_then(|value| value.get("high_constraint_mode"))
                .is_some(),
            "summary should record high_constraint_mode"
        );
        assert!(
            summary
                .get("original_constraint_count")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "summary should record measured original constraint count"
        );
        assert!(
            summary
                .get("final_constraint_count")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "summary should record measured final constraint count"
        );
        assert!(
            summary
                .get("public_outputs")
                .and_then(|value| value.get("constraint_satisfaction"))
                .and_then(serde_json::Value::as_str)
                == Some("1"),
            "prepared witness public outputs should keep constraint_satisfaction=1"
        );
        assert!(
            summary
                .get("public_outputs")
                .and_then(|value| value.get("final_mass"))
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "summary should expose final_mass"
        );
        assert!(
            summary
                .get("public_outputs")
                .and_then(|value| value.get("min_altitude"))
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "summary should expose min_altitude"
        );
        assert!(
            verify(&compiled, &runtime_artifact).expect("runtime proof reverify from disk"),
            "200-step runtime proof must verify from disk"
        );
        assert!(
            witness.values.contains_key("constraint_satisfaction"),
            "prepared witness should include the public certificate output"
        );
        assert_eq!(
            exercised_surfaces
                .get("generated_closure_path")
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_powered_descent_showcase.json")
        );
        assert_eq!(
            evidence_manifest
                .get("generated_closure")
                .and_then(|value| value.get("extract_path"))
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_powered_descent_showcase.json")
        );
        assert_eq!(
            audit, audit_summary,
            "audit.json and audit_summary.json should stay identical"
        );
        assert_execution_trace_checkpoint(&execution_trace, true, "development", "debug");
        assert_eq!(
            audit_summary
                .get("full_source_audit")
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            audit_summary
                .get("full_compiled_audit")
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("included")
        );
        assert_eq!(
            runtime_trace
                .get("export")
                .and_then(|value| value.get("process_mode"))
                .and_then(serde_json::Value::as_str),
            Some("fresh-process-finalize-bundle")
        );
        assert!(
            source_audit.get("summary").is_some(),
            "source audit should contain a summary",
        );
        assert!(
            compiled_audit.get("summary").is_some(),
            "compiled audit should contain a summary",
        );
        assert_gpu_backed_attribution(
            summary
                .get("effective_gpu_attribution")
                .expect("summary effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            runtime_trace
                .get("effective_gpu_attribution")
                .expect("runtime trace effective gpu attribution"),
        );
        assert_gpu_backed_attribution(
            evidence_manifest
                .get("gpu_attribution")
                .expect("evidence manifest gpu attribution"),
        );
        assert_metal_artifact_metadata(
            summary
                .get("artifact_metadata")
                .expect("summary artifact metadata"),
        );

        let mut forge = Command::new("forge");
        forge
            .current_dir(&foundry_dir)
            .arg("test")
            .env("HOME", temp_home.path())
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe");
        apply_toolchain_env(&mut forge);
        assert_command_success(
            forge.output().expect("run forge test"),
            "forge test on exported 200-step Foundry project",
        );
    });
}
