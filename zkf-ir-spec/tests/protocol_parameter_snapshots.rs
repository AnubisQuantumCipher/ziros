use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn rust_file_snapshot(root: &Path, relative: &str) -> serde_json::Value {
    json!({
        "path": relative,
        "sha256": sha256_file(&root.join(relative)),
    })
}

fn extract_plonky3_pin(cargo_toml: &str) -> String {
    let mut versions = cargo_toml
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("p3-") {
                return None;
            }
            let (_, value) = trimmed.split_once('=')?;
            let version = value.trim().trim_matches('"');
            version.strip_prefix('=').map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    versions.sort();
    versions.dedup();
    assert_eq!(versions.len(), 1, "expected one pinned Plonky3 version");
    versions.remove(0)
}

fn extract_u8_const(source: &str, name: &str) -> u64 {
    let needle = format!("const {name}: u8 = ");
    let line = source
        .lines()
        .find(|line| line.contains(&needle))
        .unwrap_or_else(|| panic!("failed to find const {name}"));
    let value = line
        .split('=')
        .nth(1)
        .expect("const rhs")
        .trim()
        .trim_end_matches(';');
    value.parse().expect("parse const value")
}

fn extract_str_const(source: &str, name: &str) -> String {
    let needle = format!("const {name}: &str = ");
    let line = source
        .lines()
        .find(|line| line.contains(&needle))
        .unwrap_or_else(|| panic!("failed to find const {name}"));
    line.split('=')
        .nth(1)
        .expect("const rhs")
        .trim()
        .trim_end_matches(';')
        .trim_matches('"')
        .to_string()
}

#[test]
fn protocol_parameter_snapshots_match_live_repo_state() {
    let root = repo_root();
    let cargo_toml =
        fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
    let plonky3_pin = extract_plonky3_pin(&cargo_toml);
    let arkworks_rs =
        fs::read_to_string(root.join("zkf-backends/src/arkworks.rs")).expect("read arkworks");
    let nova_rs =
        fs::read_to_string(root.join("zkf-backends/src/nova_native.rs")).expect("read nova");
    let setup_blob_version = extract_u8_const(&arkworks_rs, "SETUP_BLOB_VERSION");
    let nova_native_mode = extract_str_const(&nova_rs, "NOVA_NATIVE_MODE");

    let expected_groth16 = json!({
        "surface": "groth16",
        "backend": "arkworks-groth16",
        "field": "bn254",
        "curve": "bn254",
        "scheme": "groth16",
        "setup_blob_version": setup_blob_version,
        "rust_files": [
            rust_file_snapshot(&root, "zkf-backends/src/arkworks.rs"),
            rust_file_snapshot(&root, "zkf-backends/src/lib_non_hax.rs"),
        ],
        "security_boundary": "trusted-imported",
        "development_boundary": "development-only",
        "setup_provenance": "trusted-imported-blob",
        "setup_reporting_contracts": [
            {
                "when_setup_provenance": "trusted-imported-blob",
                "required_compiled_metadata": [
                    "groth16_setup_blob_path",
                ],
                "required_proof_metadata": [],
            },
            {
                "when_setup_provenance": "auto-ceremony-cached-entropy",
                "required_compiled_metadata": [
                    "groth16_ceremony_subsystem",
                    "groth16_ceremony_id",
                    "groth16_ceremony_kind",
                    "groth16_ceremony_report_path",
                    "groth16_ceremony_report_sha256",
                    "groth16_ceremony_seed_commitment_sha256",
                ],
                "required_proof_metadata": [
                    "groth16_ceremony_subsystem",
                    "groth16_ceremony_id",
                    "groth16_ceremony_kind",
                    "groth16_ceremony_report_path",
                    "groth16_ceremony_report_sha256",
                    "groth16_ceremony_seed_commitment_sha256",
                ],
            },
        ],
        "required_compiled_metadata": [
            "curve",
            "scheme",
            "setup_blob_version",
            "setup_deterministic",
            "setup_seed_source",
            "groth16_setup_provenance",
            "groth16_setup_security_boundary",
            "groth16_setup_blob_path",
        ],
        "required_proof_metadata": [
            "curve",
            "scheme",
            "prove_deterministic",
            "prove_seed_source",
        ],
        "verifier_checks": [
            "compiled_backend_matches",
            "artifact_backend_matches",
            "program_digest_matches",
            "verification_key_matches_compiled_setup_blob",
        ],
    });
    let expected_fri = json!({
        "surface": "fri",
        "backend": "plonky3",
        "scheme": "stark",
        "pcs": "fri",
        "plonky3_version": plonky3_pin,
        "seed_derivation": "program-digest",
        "rust_files": [
            rust_file_snapshot(&root, "zkf-backends/src/plonky3.rs"),
            rust_file_snapshot(&root, "zkf-backends/src/wrapping/stark_to_groth16.rs"),
        ],
        "wrapper_surface": "stark-to-groth16",
        "wrapper_statuses": ["wrapped-v2", "wrapped-v3"],
        "wrapper_strategies": ["direct-fri-v2", "nova-compressed-v3"],
        "wrapper_semantics": [
            "fri-verifier-circuit",
            "nova-compressed-attestation-binding",
        ],
        "source_verification_semantics": [
            "circuit-replayed",
            "host-compressed-check",
        ],
        "required_proof_metadata": [
            "field",
            "scheme",
            "pcs",
            "seed",
        ],
    });
    let expected_nova = json!({
        "surface": "nova-hypernova",
        "backend": "nova-native",
        "compile_scheme": "nova-ivc",
        "fold_scheme": "nova-ivc-fold",
        "native_mode": nova_native_mode,
        "primary_curve": "pallas",
        "profiles": ["classic", "hypernova"],
        "rust_files": [
            rust_file_snapshot(&root, "zkf-backends/src/nova_native.rs"),
        ],
        "secondary_curve": "vesta",
        "curve_cycle": "pallas-vesta",
        "step_arity": 1,
        "compressed_fold_supported_profiles": ["classic"],
        "required_compiled_metadata": [
            "nova_native_mode",
            "nova_profile",
            "nova_curve_cycle",
            "nova_step_arity",
            "scheme",
            "mode",
        ],
        "required_single_step_proof_metadata": [
            "nova_native_mode",
            "nova_steps",
            "nova_curve_cycle",
            "nova_profile",
        ],
        "required_fold_proof_metadata": [
            "nova_native_mode",
            "nova_steps",
            "nova_curve_cycle",
            "nova_profile",
            "nova_compressed",
            "nova_ivc_in",
            "nova_ivc_out",
            "nova_ivc_initial_state",
            "nova_ivc_final_state",
        ],
    });

    let groth16: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("zkf-ir-spec/protocol-parameters/groth16_surface.json"))
            .expect("read groth16 snapshot"),
    )
    .expect("parse groth16 snapshot");
    let fri: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("zkf-ir-spec/protocol-parameters/fri_surface.json"))
            .expect("read fri snapshot"),
    )
    .expect("parse fri snapshot");
    let nova: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("zkf-ir-spec/protocol-parameters/nova_surface.json"))
            .expect("read nova snapshot"),
    )
    .expect("parse nova snapshot");

    assert_eq!(groth16, expected_groth16);
    assert_eq!(fri, expected_fri);
    assert_eq!(nova, expected_nova);
}
