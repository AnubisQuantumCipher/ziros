use serde::de::DeserializeOwned;
use std::fs;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::{BackendRoute, prepare_witness_for_proving};
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::{
    BackendKind, CompiledProgram, Program, ProofArtifact, Witness, WitnessInputs, check_constraints,
};
use zkf_lib::app::satellite::{
    private_satellite_conjunction_showcase_with_steps,
    private_satellite_conjunction_witness_with_steps,
};
use zkf_lib::{compile, export_groth16_solidity_verifier, prove, verify};
use zkf_runtime::{ExecutionMode, OptimizationObjective, RequiredTrustLane, RuntimeExecutor};

const SETUP_SEED: [u8; 32] = [0x51; 32];
const PROOF_SEED: [u8; 32] = [0x67; 32];

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

fn build_showcase_example_binary() -> std::path::PathBuf {
    let mut build = Command::new("cargo");
    build
        .current_dir(repo_root())
        .arg("build")
        .arg("-p")
        .arg("zkf-lib")
        .arg("--example")
        .arg("private_satellite_conjunction_showcase")
        .arg("--release");
    apply_toolchain_env(&mut build);
    assert_command_success(
        build.output().expect("build satellite example"),
        "cargo build satellite showcase example",
    );

    cargo_target_dir()
        .join("release")
        .join("examples")
        .join("private_satellite_conjunction_showcase")
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

#[test]
fn private_satellite_conjunction_showcase_roundtrips_through_runtime_and_exports_assets() {
    run_with_large_stack("satellite-runtime-roundtrip", || {
        with_swarm_home(|home| {
            let template =
                private_satellite_conjunction_showcase_with_steps(1).expect("satellite template");
            let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
                compile(&template.program, "arkworks-groth16", Some(SETUP_SEED))
            })
            .expect("compile satellite showcase");

            let base_witness =
                private_satellite_conjunction_witness_with_steps(&template.sample_inputs, 1)
                    .expect("satellite witness");
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
                Some("PrivateSatelliteVerifier"),
            )
            .expect("solidity verifier");
            assert!(
                verifier_source.contains("contract PrivateSatelliteVerifier"),
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
                "../src/PrivateSatelliteVerifier.sol",
                "PrivateSatelliteVerifier",
            )
            .expect("foundry test");
            assert!(
                foundry.source.contains("PrivateSatelliteVerifier"),
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
fn private_satellite_conjunction_showcase_example_exports_bundle_and_reverifies_from_disk() {
    run_with_large_stack("satellite-example-export", || {
        let _guard = SWARM_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_home = tempfile::tempdir().expect("temp home");
        let output_dir = temp_home.path().join("satellite-showcase");
        let example_binary = build_showcase_example_binary();

        let mut example = Command::new(&example_binary);
        example
            .current_dir(repo_root())
            .arg(&output_dir)
            .env("HOME", temp_home.path())
            .env("ZKF_SWARM", "1")
            .env("ZKF_SWARM_KEY_BACKEND", "file")
            .env("ZKF_SECURITY_POLICY_MODE", "observe")
            .env("ZKF_PRIVATE_SATELLITE_STEPS_OVERRIDE", "2");
        apply_toolchain_env(&mut example);
        assert_command_success(
            example.output().expect("run satellite example binary"),
            "satellite showcase example binary",
        );

        let program_original_path = output_dir.join("private_satellite.original.program.json");
        let program_optimized_path = output_dir.join("private_satellite.optimized.program.json");
        let compiled_path = output_dir.join("private_satellite.compiled.json");
        let inputs_path = output_dir.join("private_satellite.inputs.json");
        let witness_base_path = output_dir.join("private_satellite.witness.base.json");
        let witness_path = output_dir.join("private_satellite.witness.prepared.json");
        let proof_path = output_dir.join("private_satellite.runtime.proof.json");
        let verifier_path = output_dir.join("PrivateSatelliteConjunctionVerifier.sol");
        let calldata_path = output_dir.join("private_satellite.calldata.json");
        let summary_path = output_dir.join("private_satellite.summary.json");
        let audit_path = output_dir.join("private_satellite.audit.json");
        let audit_summary_path = output_dir.join("private_satellite.audit_summary.json");
        let evidence_manifest_path = output_dir.join("private_satellite.evidence_manifest.json");
        let matrix_path = output_dir.join("private_satellite.matrix_ccs_summary.json");
        let runtime_trace_path = output_dir.join("private_satellite.runtime_trace.json");
        let execution_trace_path = output_dir.join("private_satellite.execution_trace.json");
        let report_path = output_dir.join("private_satellite.report.md");
        let mission_assurance_path = output_dir.join("private_satellite.mission_assurance.md");
        let formal_dir = output_dir.join("formal");
        let formal_status_path = formal_dir.join("STATUS.md");
        let rocq_log_path = formal_dir.join("rocq.log");
        let protocol_lean_log_path = formal_dir.join("protocol_lean.log");
        let kani_satellite_log_path = formal_dir.join("kani_satellite.log");
        let verus_satellite_log_path = formal_dir.join("verus_satellite.log");
        let exercised_surfaces_path = formal_dir.join("exercised_surfaces.json");
        let foundry_dir = output_dir.join("foundry");
        let foundry_toml_path = foundry_dir.join("foundry.toml");
        let foundry_verifier_path = foundry_dir.join("src/PrivateSatelliteConjunctionVerifier.sol");
        let foundry_test_path = foundry_dir.join("test/PrivateSatelliteConjunctionVerifier.t.sol");

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
        assert_file_exists(&kani_satellite_log_path);
        assert_file_exists(&verus_satellite_log_path);
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
        let _: serde_json::Value = read_json(&execution_trace_path);
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
                    run.get("name").and_then(serde_json::Value::as_str)
                        == Some("protocol_lean")
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
            exercised_surfaces
                .get("generated_closure_path")
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_satellite_conjunction_showcase.json")
        );
        assert_eq!(
            evidence_manifest
                .get("generated_closure")
                .and_then(|value| value.get("extract_path"))
                .and_then(serde_json::Value::as_str),
            Some("forensics/generated/app_closure/private_satellite_conjunction_showcase.json")
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
                    .any(|entry| entry.as_str() == Some("formal/kani_satellite.log"))),
            "formal evidence manifest should record the satellite Kani log"
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("files"))
                .and_then(|value| value.get("logs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|logs| logs
                    .iter()
                    .any(|entry| entry.as_str() == Some("formal/verus_satellite.log"))),
            "formal evidence manifest should record the satellite Verus log"
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("runs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|runs| runs.iter().any(|run| {
                    run.get("name").and_then(serde_json::Value::as_str) == Some("kani_satellite")
                        && run.get("status").and_then(serde_json::Value::as_str) == Some("passed")
                })),
            "formal evidence manifest should record a passing satellite Kani run"
        );
        assert!(
            evidence_manifest
                .get("formal_evidence")
                .and_then(|value| value.get("runs"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|runs| runs.iter().any(|run| {
                    run.get("name").and_then(serde_json::Value::as_str) == Some("verus_satellite")
                        && run.get("status").and_then(serde_json::Value::as_str) == Some("passed")
                })),
            "formal evidence manifest should record a passing satellite Verus run"
        );

        let verifier_source = fs::read_to_string(&verifier_path).expect("read verifier");
        assert!(
            verifier_source.contains("contract PrivateSatelliteConjunctionVerifier"),
            "exported verifier should contain the expected contract"
        );
        let foundry_manifest =
            fs::read_to_string(&foundry_toml_path).expect("read foundry manifest");
        assert!(
            foundry_manifest.contains("[profile.default]"),
            "generated Foundry manifest should contain a default profile"
        );
        let foundry_test = fs::read_to_string(&foundry_test_path).expect("read foundry test");
        assert!(
            foundry_test.contains("PrivateSatelliteConjunctionVerifier"),
            "generated Foundry test should reference the verifier contract"
        );
        let report = fs::read_to_string(&report_path).expect("read markdown report");
        assert!(
            report.contains("# ZirOS Private Satellite Conjunction Showcase"),
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
            report.contains("satellite-Kani"),
            "generated report should reference the bundled satellite Kani log"
        );
        let formal_status = fs::read_to_string(&formal_status_path).expect("read formal status");
        assert!(
            formal_status.contains("formal/exercised_surfaces.json"),
            "formal status should reference the exercised surfaces bundle"
        );
        assert!(
            formal_status.contains("kani_satellite"),
            "formal status should record the satellite Kani run"
        );
        assert!(
            formal_status.contains("verus_satellite"),
            "formal status should record the satellite Verus run"
        );
        let mission_assurance =
            fs::read_to_string(&mission_assurance_path).expect("read mission assurance report");
        assert!(
            mission_assurance.contains("# ZirOS Private Satellite Conjunction Showcase"),
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
