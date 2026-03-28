use serde::de::DeserializeOwned;
use std::fs;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output};

use zkf_core::{CompiledProgram, ProofArtifact};
use zkf_lib::verify;

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

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    zkf_core::json_from_slice(&fs::read(path).expect("read json")).expect("parse json")
}

#[test]
fn private_voting_example_exports_mandatory_evidence_bundle() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let output_dir = temp_home.path().join("private-voting");

    let mut build = Command::new("cargo");
    build
        .current_dir(repo_root())
        .arg("build")
        .arg("-p")
        .arg("zkf-lib")
        .arg("--example")
        .arg("private_voting_commitment_pipeline")
        .arg("--release");
    apply_toolchain_env(&mut build);
    assert_command_success(
        build.output().expect("build private voting example"),
        "cargo build private voting example",
    );

    let example_binary = cargo_target_dir()
        .join("release")
        .join("examples")
        .join("private_voting_commitment_pipeline");

    let mut example = Command::new(&example_binary);
    example
        .current_dir(repo_root())
        .arg(&output_dir)
        .env("HOME", temp_home.path());
    apply_toolchain_env(&mut example);
    assert_command_success(
        example.output().expect("run private voting example"),
        "private voting example binary",
    );

    let compiled_path = output_dir.join("private_vote.compiled.json");
    let proof_first_path = output_dir.join("private_vote.proof.first.json");
    let proof_second_path = output_dir.join("private_vote.proof.second.json");
    let summary_path = output_dir.join("private_vote.summary.json");
    let audit_path = output_dir.join("private_vote.audit.json");
    let evidence_manifest_path = output_dir.join("private_vote.evidence_manifest.json");
    let report_path = output_dir.join("private_vote.report.md");
    let formal_dir = output_dir.join("formal");
    let foundry_dir = output_dir.join("foundry");

    assert_file_exists(&compiled_path);
    assert_file_exists(&proof_first_path);
    assert_file_exists(&proof_second_path);
    assert_file_exists(&summary_path);
    assert_file_exists(&audit_path);
    assert_file_exists(&evidence_manifest_path);
    assert_file_exists(&report_path);
    assert_dir_exists(&formal_dir);
    assert_file_exists(&formal_dir.join("STATUS.md"));
    assert_file_exists(&formal_dir.join("exercised_surfaces.json"));
    assert_file_exists(&formal_dir.join("rocq.log"));
    assert_file_exists(&formal_dir.join("protocol_lean.log"));
    assert_file_exists(&formal_dir.join("verus_orbital.log"));
    assert_dir_exists(&foundry_dir);
    assert_file_exists(&foundry_dir.join("foundry.toml"));
    assert_file_exists(&foundry_dir.join("src/PrivateVotingVerifier.sol"));
    assert_file_exists(&foundry_dir.join("test/PrivateVotingVerifier.t.sol"));
    assert_dir_exists(&output_dir.join("audit"));
    assert_file_exists(&output_dir.join("audit/private_vote.source_audit.json"));
    assert_file_exists(&output_dir.join("audit/private_vote.compiled_audit.json"));

    let compiled: CompiledProgram = read_json(&compiled_path);
    let proof_first: ProofArtifact = read_json(&proof_first_path);
    let proof_second: ProofArtifact = read_json(&proof_second_path);
    let audit: serde_json::Value = read_json(&audit_path);
    let evidence_manifest: serde_json::Value = read_json(&evidence_manifest_path);
    let exercised_surfaces: serde_json::Value =
        read_json(&formal_dir.join("exercised_surfaces.json"));
    let report = fs::read_to_string(&report_path).expect("read report");
    let formal_status = evidence_manifest
        .get("formal_evidence")
        .and_then(|value| value.get("status"))
        .and_then(serde_json::Value::as_str);

    assert!(verify(&compiled, &proof_first).expect("verify first proof"));
    assert!(verify(&compiled, &proof_second).expect("verify second proof"));
    assert_eq!(
        audit.get("mode").and_then(serde_json::Value::as_str),
        Some("zkf-application-audit-v1")
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
        Some("included")
    );
    assert_eq!(
        exercised_surfaces
            .get("generated_closure_path")
            .and_then(serde_json::Value::as_str),
        Some("forensics/generated/app_closure/private_voting_commitment_pipeline.json")
    );
    assert_eq!(
        evidence_manifest
            .get("generated_closure")
            .and_then(|value| value.get("extract_path"))
            .and_then(serde_json::Value::as_str),
        Some("forensics/generated/app_closure/private_voting_commitment_pipeline.json")
    );
    assert_eq!(
        evidence_manifest
            .get("generated_closure")
            .and_then(|value| value.get("assurance_counts")),
        exercised_surfaces.get("assurance_counts")
    );
    assert!(
        report.contains("Formal evidence"),
        "report should describe the bundled evidence"
    );

    let mut forge = Command::new("forge");
    forge
        .current_dir(&foundry_dir)
        .arg("test")
        .env("HOME", temp_home.path());
    apply_toolchain_env(&mut forge);
    assert_command_success(
        forge.output().expect("run forge test"),
        "forge test on private voting foundry project",
    );
}
