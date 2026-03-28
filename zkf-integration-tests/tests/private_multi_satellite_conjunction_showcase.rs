use serde::de::DeserializeOwned;
use std::fs;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

use zkf_core::{CompiledProgram, ProofArtifact, Witness, check_constraints};
use zkf_lib::app::multi_satellite::{
    PrivateMultiSatelliteScenario, private_multi_satellite_conjunction_showcase_for_scenario,
    private_multi_satellite_conjunction_witness,
};
use zkf_lib::verify;
const EXPORT_MINI_ENV: &str = "ZKF_RUN_MULTI_SATELLITE_EXPORT_MINI";
const EXPORT_BASE32_ENV: &str = "ZKF_RUN_MULTI_SATELLITE_EXPORT_BASE32";
const EXPORT_STRESS64_ENV: &str = "ZKF_RUN_MULTI_SATELLITE_EXPORT_STRESS64";

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
    ];

    unsafe {
        std::env::set_var("HOME", temp.path());
        std::env::set_var("ZKF_SWARM", "1");
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

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
}

fn cargo_target_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(path);
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

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    zkf_core::json_from_slice(&fs::read(path).expect("read json")).expect("parse json")
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

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
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

fn build_showcase_example_binary() -> PathBuf {
    let binary_path = cargo_target_dir()
        .join("release")
        .join("examples")
        .join("private_multi_satellite_conjunction_showcase");
    if binary_path.is_file() {
        return binary_path;
    }

    let mut build = Command::new("cargo");
    build
        .current_dir(repo_root())
        .arg("build")
        .arg("-p")
        .arg("zkf-lib")
        .arg("--example")
        .arg("private_multi_satellite_conjunction_showcase")
        .arg("--release");
    apply_toolchain_env(&mut build);
    assert_command_success(
        build.output().expect("build multi-satellite example"),
        "cargo build multi-satellite example",
    );

    binary_path
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

fn assert_bundle_contract(
    output_dir: &Path,
    scenario: &str,
    expected_satellites: u64,
    expected_pairs: u64,
    expected_steps: u64,
) {
    let compiled_path = output_dir.join("compiled_program.json");
    let witness_path = output_dir.join("witness.json");
    let proof_path = output_dir.join("proof.json");
    let public_inputs_path = output_dir.join("public_inputs.json");
    let verifier_path = output_dir.join("verifier.sol");
    let calldata_path = output_dir.join("calldata.json");
    let runtime_trace_path = output_dir.join("runtime_trace.json");
    let accelerator_trace_path = output_dir.join("accelerator_trace.json");
    let stage_metrics_path = output_dir.join("stage_metrics.json");
    let correctness_path = output_dir.join("correctness_report.json");
    let determinism_path = output_dir.join("determinism_report.json");
    let truth_path = output_dir.join("truth_report.json");
    let benchmark_path = output_dir.join("benchmark_summary.json");
    let audit_summary_path = output_dir.join("audit_summary.json");
    let mission_assurance_path = output_dir.join("mission_assurance_report.json");
    let formal_summary_path = output_dir.join("formal_evidence_summary.json");
    let manifest_path = output_dir.join("export_manifest.json");
    let foundry_report_path = output_dir.join("foundry_report.txt");
    let summary_path = output_dir.join("human_readable_summary.md");
    let formal_dir = output_dir.join("formal");
    let foundry_dir = output_dir.join("foundry");

    for path in [
        &compiled_path,
        &witness_path,
        &proof_path,
        &public_inputs_path,
        &verifier_path,
        &calldata_path,
        &runtime_trace_path,
        &accelerator_trace_path,
        &stage_metrics_path,
        &correctness_path,
        &determinism_path,
        &truth_path,
        &benchmark_path,
        &audit_summary_path,
        &mission_assurance_path,
        &formal_summary_path,
        &manifest_path,
        &foundry_report_path,
        &summary_path,
    ] {
        assert_file_exists(path);
    }

    assert_dir_exists(&formal_dir);
    assert_dir_exists(&foundry_dir);
    assert_file_exists(&formal_dir.join("STATUS.md"));
    assert_file_exists(&formal_dir.join("exercised_surfaces.json"));
    assert_file_exists(&formal_dir.join("rocq.log"));
    assert_file_exists(&formal_dir.join("protocol_lean.log"));
    assert_file_exists(&formal_dir.join("local_checks.json"));
    assert_file_exists(&foundry_dir.join("foundry.toml"));
    assert_file_exists(&foundry_dir.join("src/PrivateMultiSatelliteVerifier.sol"));
    assert_file_exists(&foundry_dir.join("test/PrivateMultiSatelliteVerifier.t.sol"));

    let compiled: CompiledProgram = read_json(&compiled_path);
    let _: Witness = read_json(&witness_path);
    let proof: ProofArtifact = read_json(&proof_path);
    let public_inputs: serde_json::Value = read_json(&public_inputs_path);
    let _: serde_json::Value = read_json(&calldata_path);
    let runtime_trace: serde_json::Value = read_json(&runtime_trace_path);
    let accelerator_trace: serde_json::Value = read_json(&accelerator_trace_path);
    let stage_metrics: serde_json::Value = read_json(&stage_metrics_path);
    let correctness: serde_json::Value = read_json(&correctness_path);
    let determinism: serde_json::Value = read_json(&determinism_path);
    let truth: serde_json::Value = read_json(&truth_path);
    let benchmark: serde_json::Value = read_json(&benchmark_path);
    let formal_summary: serde_json::Value = read_json(&formal_summary_path);
    let manifest: serde_json::Value = read_json(&manifest_path);

    assert!(
        verify(&compiled, &proof).expect("reverify multi-satellite proof from disk"),
        "multi-satellite proof exported by the example must verify from disk"
    );
    assert_eq!(
        public_inputs
            .get("satellite_count")
            .and_then(serde_json::Value::as_u64),
        Some(expected_satellites)
    );
    assert_eq!(
        public_inputs
            .get("conjunction_pair_count")
            .and_then(serde_json::Value::as_u64),
        Some(expected_pairs)
    );
    assert_eq!(
        public_inputs
            .get("timestep_count")
            .and_then(serde_json::Value::as_u64),
        Some(expected_steps)
    );
    assert_eq!(
        runtime_trace
            .get("scenario")
            .and_then(serde_json::Value::as_str),
        Some(scenario)
    );
    assert_eq!(
        accelerator_trace
            .get("scenario")
            .and_then(serde_json::Value::as_str),
        Some(scenario)
    );
    assert!(
        stage_metrics.as_array().is_some_and(|stages| {
            stages.iter().any(|stage| {
                stage.get("stage_name").and_then(serde_json::Value::as_str) == Some("msm")
            })
        }),
        "stage metrics should include the msm stage"
    );
    assert_eq!(
        formal_summary
            .get("generated_closure")
            .and_then(|value| value.get("extract_path"))
            .and_then(serde_json::Value::as_str),
        Some("forensics/generated/app_closure/private_multi_satellite_conjunction_showcase.json")
    );
    assert_eq!(
        formal_summary
            .get("repo_inherited")
            .and_then(|value| value.get("files"))
            .and_then(|value| value.get("logs"))
            .and_then(serde_json::Value::as_array)
            .map(|logs| logs.len()),
        Some(2)
    );
    assert_eq!(
        manifest.get("scenario").and_then(serde_json::Value::as_str),
        Some(scenario)
    );
    assert_eq!(
        benchmark
            .get("application")
            .and_then(|value| value.get("satellite_count"))
            .and_then(serde_json::Value::as_u64),
        Some(expected_satellites)
    );
    assert!(
        correctness
            .get("checks")
            .and_then(|value| value.get("poseidon2"))
            .and_then(|value| value.get("status"))
            .and_then(serde_json::Value::as_str)
            == Some("not_exercised")
    );
    assert_eq!(
        determinism
            .get("proof_hashes")
            .and_then(serde_json::Value::as_array)
            .map(|hashes| hashes.len()),
        Some(3)
    );
    assert!(
        truth.get("gpu_capable").is_some()
            && truth.get("gpu_selected").is_some()
            && truth.get("gpu_delegated").is_some()
            && truth.get("gpu_realized").is_some()
            && truth.get("cpu_realized").is_some()
            && truth.get("fallbacks").is_some()
            && truth.get("unverified_surfaces").is_some()
            && truth.get("contradictions_detected").is_some(),
        "truth report should expose the required truth buckets"
    );

    let report = fs::read_to_string(&summary_path).expect("read summary markdown");
    assert!(
        report.contains("# ZirOS Private Multi-Satellite Conjunction Showcase"),
        "summary markdown should contain the showcase heading"
    );
}

fn run_export_scenario_and_assert_bundle(
    scenario: &str,
    expected_satellites: u64,
    expected_pairs: u64,
    expected_steps: u64,
) {
    let worker_name = format!("multi-satellite-export-{scenario}");
    let scenario = scenario.to_string();
    run_with_large_stack(&worker_name, move || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home.path().join(format!("multi-satellite-{scenario}"));
        let example_binary = build_showcase_example_binary();

        let mut example = Command::new(&example_binary);
        example
            .current_dir(repo_root())
            .arg(&output_dir)
            .env("HOME", temp_home.path())
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe")
            .env("ZKF_PRIVATE_MULTI_SATELLITE_SCENARIOS", &scenario);
        apply_toolchain_env(&mut example);
        assert_command_success(
            example
                .output()
                .expect("run multi-satellite example binary"),
            "multi-satellite showcase example binary",
        );

        assert_bundle_contract(
            &output_dir,
            &scenario,
            expected_satellites,
            expected_pairs,
            expected_steps,
        );

        let mut forge = Command::new("forge");
        forge
            .current_dir(output_dir.join("foundry"))
            .arg("test")
            .env("HOME", temp_home.path())
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe");
        apply_toolchain_env(&mut forge);
        assert_command_success(
            forge.output().expect("run forge test"),
            "forge test on exported multi-satellite Foundry project",
        );
    });
}

#[test]
fn private_multi_satellite_conjunction_showcase_mini_compiles_and_prepares_witness() {
    run_with_large_stack("multi-satellite-mini-compile", || {
        with_swarm_home(|_home| {
            let template = private_multi_satellite_conjunction_showcase_for_scenario(
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("multi-satellite template");
            let base_witness = private_multi_satellite_conjunction_witness(
                &template.sample_inputs,
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("multi-satellite witness");
            check_constraints(&template.program, &base_witness)
                .expect("mini witness satisfies the template program");
            assert!(
                base_witness.values.len() > template.sample_inputs.len(),
                "mini witness should include derived private support values"
            );
            assert_eq!(
                template.sample_inputs.len(),
                46,
                "mini scenario should keep the fixed private/public input surface"
            );
            assert_eq!(
                template
                    .program
                    .signals
                    .iter()
                    .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
                    .count(),
                15,
                "mini scenario should expose 2 public inputs, 4 final commitments, 4 minima, 4 safe bits, and 1 mission digest"
            );
        })
    });
}

#[test]
fn private_multi_satellite_conjunction_showcase_example_exports_mini_bundle_and_reverifies_from_disk()
 {
    if !env_flag(EXPORT_MINI_ENV) {
        return;
    }
    run_export_scenario_and_assert_bundle("mini", 4, 4, 4);
}

#[test]
fn private_multi_satellite_conjunction_showcase_example_exports_base32_bundle_and_reverifies_from_disk()
 {
    if !env_flag(EXPORT_BASE32_ENV) {
        return;
    }
    run_export_scenario_and_assert_bundle("base32", 32, 64, 120);
}

#[test]
fn private_multi_satellite_conjunction_showcase_stress64_export_is_opt_in() {
    if !env_flag(EXPORT_STRESS64_ENV) {
        return;
    }
    run_export_scenario_and_assert_bundle("stress64", 64, 256, 240);
}
