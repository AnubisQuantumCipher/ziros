use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{generate_key_pair, sign as mldsa_sign};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkf_command_surface::subsystem::SubsystemScaffoldReportV1;
use zkf_core::{
    BackendKind, FieldElement, Program, PublicKeyBundle, SignatureBundle, SignatureScheme,
    WitnessInputs, verify_bundle,
};
use zkf_command_surface::midnight::{
    MidnightNetworkV1, call_prepare as midnight_call_prepare,
    deploy_prepare as midnight_deploy_prepare,
};
use zkf_lib::{
    Expr, ProgramBuilder, SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED, SubsystemCircuitManifestV1,
    SubsystemManifestEnvelopeV1, audit_program_default, compile_and_prove, verify,
};
use zkf_lib::app::subsystem::{
    DeploymentProfileV1, DisclosurePolicyV1, EvmCompatibilityContractClassV1,
    MidnightContractClassV1, SubsystemCircuitModuleV1, SubsystemContractSpecV1,
    SubsystemReleaseContractV1,
};

use crate::cmd::deploy;
use crate::util::{read_json, write_json, write_text};

const SUBSYSTEM_SCHEMA_VERSION: &str = "1.0.0";
const SUBSYSTEM_CIRCUIT_ID: &str = "identity_mirror";
const SUBSYSTEM_BACKEND: &str = "arkworks-groth16";
const SUBSYSTEM_PUBLICATION_TARGET: &str = "midnight-or-offchain";
const SUBSYSTEM_CREDENTIAL_CONTEXT: &[u8] = b"zkf-subsystem-credential-v1";
const SUBSYSTEM_RELEASE_PIN_CONTEXT: &[u8] = b"zkf-subsystem-release-pin-v1";
const SUBSYSTEM_CREDENTIAL_SCHEMA: &str = "zkf-subsystem-credential-v1";
const SUBSYSTEM_RELEASE_PIN_SCHEMA: &str = "zkf-subsystem-release-pin-v1";
const SUBSYSTEM_COMPLETENESS_SCHEMA: &str = "zkf-subsystem-completeness-v1";
const MIN_REPORT_WORD_COUNT: usize = 150;
const REQUIRED_SLOT_DIRS: [&str; 20] = [
    "01_source",
    "02_manifest",
    "03_inputs",
    "04_tests",
    "05_scripts",
    "06_docs",
    "07_compiled",
    "08_proofs",
    "09_verification",
    "10_audit",
    "11_credentials",
    "12_signatures",
    "13_public_bundle",
    "14_icloud_manifest",
    "15_solidity",
    "16_compact",
    "17_report",
    "18_dapp",
    "19_cli",
    "20_release",
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SubsystemScaffoldStyle {
    Full,
    Rust,
    Dapp,
}

impl SubsystemScaffoldStyle {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" | "full" => Ok(Self::Full),
            "rust" => Ok(Self::Rust),
            "dapp" => Ok(Self::Dapp),
            other => Err(format!(
                "unknown subsystem style '{other}' (expected full, rust, or dapp)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Rust => "rust",
            Self::Dapp => "dapp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemCredentialV1 {
    schema: String,
    subsystem_id: String,
    circuit_id: String,
    backend_policy: String,
    backend: String,
    program_digest: String,
    compiled_digest: String,
    proof_digest: String,
    verification_passed: bool,
    audit_failed_checks: usize,
    generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedSubsystemCredentialV1 {
    credential: SubsystemCredentialV1,
    public_keys: PublicKeyBundle,
    signature_bundle: SignatureBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemReleasePinV1 {
    schema: String,
    subsystem_id: String,
    zkf_version: String,
    binary_name: String,
    binary_sha256: String,
    generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedSubsystemReleasePinV1 {
    pin: SubsystemReleasePinV1,
    public_keys: PublicKeyBundle,
    signature_bundle: SignatureBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompletenessCheckV1 {
    name: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemCompletenessReportV1 {
    schema: String,
    root: String,
    subsystem_id: Option<String>,
    overall_passed: bool,
    report_word_count: usize,
    checks: Vec<CompletenessCheckV1>,
    missing_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemProofLifecycleReportV1 {
    schema: String,
    root: String,
    subsystem_id: String,
    circuit_id: String,
    backend: String,
    compiled_path: String,
    proof_path: String,
    verification_path: String,
    verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemPublicBundleReportV1 {
    schema: String,
    generated_at: String,
    root: String,
    subsystem_id: String,
    manifest_path: String,
    public_bundle_manifest_path: String,
    release_pin_path: String,
}

pub(crate) fn scaffold_subsystem(
    name: &str,
    style_raw: &str,
    out: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let style = SubsystemScaffoldStyle::parse(style_raw)?;
    let root = scaffold_root(name, out)?;
    let subsystem_id = slugify(name);
    if subsystem_id.is_empty() {
        return Err("subsystem name must contain at least one alphanumeric character".to_string());
    }

    for dir in REQUIRED_SLOT_DIRS {
        fs::create_dir_all(root.join(dir))
            .map_err(|error| format!("{}: {error}", root.join(dir).display()))?;
    }
    fs::create_dir_all(root.join("01_source/src"))
        .map_err(|error| format!("{}: {error}", root.join("01_source/src").display()))?;
    fs::create_dir_all(root.join("01_source/tests"))
        .map_err(|error| format!("{}: {error}", root.join("01_source/tests").display()))?;
    fs::create_dir_all(root.join("18_dapp/src"))
        .map_err(|error| format!("{}: {error}", root.join("18_dapp/src").display()))?;
    fs::create_dir_all(root.join("20_release/bin"))
        .map_err(|error| format!("{}: {error}", root.join("20_release/bin").display()))?;

    write_text(
        &root.join("01_source/Cargo.toml"),
        &source_cargo_toml_content(&subsystem_id),
    )?;
    write_text(&root.join("01_source/src/lib.rs"), "pub mod subsystem;\n")?;
    write_text(
        &root.join("01_source/src/main.rs"),
        &source_main_rs_content(),
    )?;
    write_text(
        &root.join("01_source/src/subsystem.rs"),
        &source_subsystem_rs_content(&subsystem_id),
    )?;
    write_text(
        &root.join("01_source/tests/roundtrip.rs"),
        &source_roundtrip_test_content(&subsystem_id),
    )?;

    let program = build_identity_mirror_program(&subsystem_id)?;
    let sample_inputs = sample_witness_inputs();
    let audit = audit_program_default(&program, Some(BackendKind::ArkworksGroth16));
    if audit.summary.failed > 0 {
        return Err(audit
            .to_json()
            .unwrap_or_else(|_| "identity mirror subsystem audit failed".to_string()));
    }
    let embedded = compile_and_prove(&program, &sample_inputs, SUBSYSTEM_BACKEND, None, None)
        .map_err(|error| error.to_string())?;
    let verified =
        verify(&embedded.compiled, &embedded.artifact).map_err(|error| error.to_string())?;
    if !verified {
        return Err("identity mirror subsystem verification failed after proving".to_string());
    }

    write_json(&root.join("03_inputs/sample_input.json"), &sample_inputs)?;
    write_json(&root.join("07_compiled/program.json"), &program)?;
    write_json(&root.join("07_compiled/compiled.json"), &embedded.compiled)?;
    write_json(&root.join("08_proofs/proof.json"), &embedded.artifact)?;
    write_json(
        &root.join("09_verification/verification.json"),
        &serde_json::json!({
            "schema": "zkf-subsystem-verification-v1",
            "subsystem_id": subsystem_id,
            "circuit_id": SUBSYSTEM_CIRCUIT_ID,
            "backend": SUBSYSTEM_BACKEND,
            "verified": true,
        }),
    )?;
    write_json(&root.join("10_audit/audit.json"), &audit)?;

    let manifest = subsystem_manifest(&subsystem_id);
    write_json(&root.join("02_manifest/subsystem_manifest.json"), &manifest)?;

    let signed_credential = build_signed_credential(
        &subsystem_id,
        &program,
        &embedded.compiled,
        &embedded.artifact,
        audit.summary.failed,
    )?;
    write_json(
        &root.join("11_credentials/subsystem_credential.json"),
        &signed_credential.credential,
    )?;
    write_json(
        &root.join("12_signatures/subsystem_credential_public_keys.json"),
        &signed_credential.public_keys,
    )?;
    write_json(
        &root.join("12_signatures/subsystem_credential_signature.json"),
        &signed_credential.signature_bundle,
    )?;

    let release_pin = bundle_current_binary(&root, &subsystem_id)?;
    write_json(&root.join("20_release/zkf-release-pin.json"), &release_pin)?;

    write_text(
        &root.join("05_scripts/install.sh"),
        &install_script_content(&subsystem_id),
    )?;
    make_executable(&root.join("05_scripts/install.sh"))?;
    write_text(
        &root.join("05_scripts/run-midnight-proof-server.sh"),
        &run_midnight_proof_server_script_content(),
    )?;
    make_executable(&root.join("05_scripts/run-midnight-proof-server.sh"))?;
    write_text(
        &root.join("05_scripts/deploy-midnight.sh"),
        &deploy_midnight_script_content(),
    )?;
    make_executable(&root.join("05_scripts/deploy-midnight.sh"))?;
    write_text(
        &root.join("19_cli/prove.sh"),
        &prove_script_content(&subsystem_id),
    )?;
    make_executable(&root.join("19_cli/prove.sh"))?;
    write_text(
        &root.join("19_cli/verify.sh"),
        &verify_script_content(&subsystem_id),
    )?;
    make_executable(&root.join("19_cli/verify.sh"))?;

    write_text(
        &root.join("06_docs/README.md"),
        &subsystem_readme_content(&subsystem_id, style),
    )?;
    write_text(
        &root.join("06_docs/disclosure_policy.md"),
        &disclosure_policy_content(&subsystem_id),
    )?;
    write_text(
        &root.join("06_docs/night_dust_guide.md"),
        &night_dust_guide_content(),
    )?;
    write_text(
        &root.join("06_docs/post_quantum_anchor.md"),
        &post_quantum_anchor_content(&subsystem_id),
    )?;
    write_text(
        &root.join("13_public_bundle/README.md"),
        &public_bundle_readme_content(&subsystem_id),
    )?;
    write_json(
        &root.join("14_icloud_manifest/storage_policy.json"),
        &serde_json::json!({
            "schema": "zkf-subsystem-storage-policy-v1",
            "subsystem_id": subsystem_id,
            "persistent_root": "iCloud/ZirOS",
            "local_only_roots": ["~/.zkf/cache"],
            "witness_policy": "~/.zkf/cache only; witnesses never enter the persistent iCloud tree",
        }),
    )?;
    write_text(
        &root.join("15_solidity/SubsystemVerifierRegistry.sol"),
        &solidity_contract_content(&subsystem_id),
    )?;
    write_text(
        &root.join("16_compact/Subsystem.compact"),
        &compact_contract_content(&subsystem_id),
    )?;
    write_text(
        &root.join("17_report/report.md"),
        &report_markdown_content(&subsystem_id, &program, &audit),
    )?;
    write_text(
        &root.join("18_dapp/package.json"),
        &dapp_package_json_content(&subsystem_id),
    )?;
    write_text(
        &root.join("18_dapp/src/witness.mjs"),
        &dapp_witness_provider_content(),
    )?;
    write_text(
        &root.join("18_dapp/src/proof-server.mjs"),
        &dapp_proof_server_content(),
    )?;
    write_text(
        &root.join("18_dapp/src/midnight-wallet.mjs"),
        &dapp_wallet_helper_content(),
    )?;
    write_text(
        &root.join("18_dapp/src/dashboard.tsx"),
        &dapp_dashboard_content(&subsystem_id),
    )?;

    let cargo_test_output = run_source_cargo_test(&root.join("01_source"))?;
    write_text(&root.join("04_tests/cargo_test.txt"), &cargo_test_output)?;

    Ok(root)
}

pub(crate) fn handle_scaffold(
    name: &str,
    style: &str,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    let style = SubsystemScaffoldStyle::parse(style)?.as_str().to_string();
    let root = scaffold_subsystem(name, &style, out)?;
    let report = SubsystemScaffoldReportV1 {
        schema: "zkf-subsystem-scaffold-v1".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        name: name.to_string(),
        style,
        out_dir: root.display().to_string(),
        manifest_path: root
            .join("02_manifest/subsystem_manifest.json")
            .display()
            .to_string(),
        completeness_path: root
            .join("17_report/report.md")
            .display()
            .to_string(),
        release_pin_path: root
            .join("20_release/zkf-release-pin.json")
            .display()
            .to_string(),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem scaffold created: style={} -> {}\nnext:\n  cargo test --manifest-path {}/01_source/Cargo.toml\n  zkf subsystem verify-completeness --root {}",
            report.style,
            report.out_dir,
            report.out_dir,
            report.out_dir
        );
    }
    Ok(())
}

pub(crate) fn handle_verify_completeness(root: PathBuf, json: bool) -> Result<(), String> {
    let report = verify_completeness_report(&root)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem completeness: {} ({})",
            if report.overall_passed {
                "PASS"
            } else {
                "FAIL"
            },
            report.root
        );
        for check in &report.checks {
            println!(
                "  [{}] {}: {}",
                if check.passed { "ok" } else { "fail" },
                check.name,
                check.detail
            );
        }
        if !report.missing_paths.is_empty() {
            println!("  missing: {}", report.missing_paths.join(", "));
        }
    }
    if report.overall_passed {
        Ok(())
    } else {
        Err("subsystem completeness verification failed".to_string())
    }
}

pub(crate) fn handle_verify_release_pin(
    pin: PathBuf,
    binary: PathBuf,
    json: bool,
) -> Result<(), String> {
    let report = verify_release_pin_report(&pin, &binary)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "release pin: {} ({})",
            if report.overall_passed {
                "PASS"
            } else {
                "FAIL"
            },
            binary.display()
        );
        for check in &report.checks {
            println!(
                "  [{}] {}: {}",
                if check.passed { "ok" } else { "fail" },
                check.name,
                check.detail
            );
        }
    }
    if report.overall_passed {
        Ok(())
    } else {
        Err("subsystem release pin verification failed".to_string())
    }
}

pub(crate) fn handle_validate(root: PathBuf, json: bool) -> Result<(), String> {
    handle_verify_completeness(root, json)
}

pub(crate) fn handle_prove(root: PathBuf, json: bool) -> Result<(), String> {
    let report = reproving_report(&root)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem prove: {} {} -> {}",
            report.subsystem_id, report.backend, report.proof_path
        );
    }
    Ok(())
}

pub(crate) fn handle_verify(root: PathBuf, json: bool) -> Result<(), String> {
    let report = verification_report(&root)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem verify: {} ({})",
            if report.verified { "PASS" } else { "FAIL" },
            report.root
        );
    }
    if report.verified {
        Ok(())
    } else {
        Err("subsystem verification failed".to_string())
    }
}

pub(crate) fn handle_bundle_public(root: PathBuf, json: bool) -> Result<(), String> {
    let report = bundle_public_report(&root)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem public bundle refreshed: {} -> {}",
            report.subsystem_id, report.public_bundle_manifest_path
        );
    }
    Ok(())
}

pub(crate) fn handle_deploy_prepare(root: PathBuf, network: String, json: bool) -> Result<(), String> {
    let network = MidnightNetworkV1::parse(&network)?;
    let source = root.join("16_compact/Subsystem.compact");
    let out_path = root.join("16_compact/deploy-prepare.json");
    let report = midnight_deploy_prepare(network, &source, &out_path, None, None, Some(&root))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!("subsystem deploy-prepare -> {}", report.out_path);
    }
    Ok(())
}

pub(crate) fn handle_call_prepare(
    root: PathBuf,
    call: String,
    inputs: PathBuf,
    network: String,
    json: bool,
) -> Result<(), String> {
    let network = MidnightNetworkV1::parse(&network)?;
    let source = root.join("16_compact/Subsystem.compact");
    let out_path = root.join("16_compact/call-prepare.json");
    let report = midnight_call_prepare(
        network,
        &source,
        &call,
        &inputs,
        &out_path,
        None,
        None,
        Some(&root),
    )?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!("subsystem call-prepare -> {}", report.out_path);
    }
    Ok(())
}

pub(crate) fn handle_evm_export(
    root: PathBuf,
    evm_target: String,
    contract_name: Option<String>,
    json: bool,
) -> Result<(), String> {
    let manifest = load_subsystem_manifest(&root)?;
    let (_, circuit) = primary_circuit_entry(&manifest)?;
    let artifact_path = root.join(&circuit.proof_path);
    let out_path = root.join("15_solidity/SubsystemVerifier.sol");
    let report = deploy::export_verifier_to_path(
        artifact_path,
        circuit.backend.clone(),
        out_path,
        contract_name,
        evm_target,
    )?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "subsystem evm export: {} -> {}",
            manifest.subsystem_id, report.solidity_path
        );
    }
    Ok(())
}

fn verify_completeness_report(root: &Path) -> Result<SubsystemCompletenessReportV1, String> {
    let mut checks = Vec::new();
    let mut missing_paths = Vec::new();
    for dir in REQUIRED_SLOT_DIRS {
        let path = root.join(dir);
        let passed = path.is_dir();
        if !passed {
            missing_paths.push(dir.to_string());
        }
        checks.push(CompletenessCheckV1 {
            name: format!("slot:{dir}"),
            passed,
            detail: path.display().to_string(),
        });
    }

    let manifest_path = root.join("02_manifest/subsystem_manifest.json");
    let manifest: Option<SubsystemManifestEnvelopeV1> = if manifest_path.exists() {
        Some(read_json(&manifest_path)?)
    } else {
        missing_paths.push("02_manifest/subsystem_manifest.json".to_string());
        None
    };
    let subsystem_id = manifest.as_ref().map(|value| value.subsystem_id.clone());
    if let Some(manifest) = manifest.as_ref() {
        checks.push(CompletenessCheckV1 {
            name: "manifest:backend_policy".to_string(),
            passed: manifest.backend_policy == SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED,
            detail: manifest.backend_policy.clone(),
        });
        for (circuit_id, circuit) in &manifest.circuits {
            let compiled_path = root.join(&circuit.compiled_path);
            let artifact_path = root.join(&circuit.proof_path);
            let audit_path = root.join(&circuit.audit_path);
            let compiled_exists = compiled_path.is_file();
            let artifact_exists = artifact_path.is_file();
            let audit_exists = audit_path.is_file();
            if !(compiled_exists && artifact_exists) {
                if !compiled_exists {
                    missing_paths.push(circuit.compiled_path.clone());
                }
                if !artifact_exists {
                    missing_paths.push(circuit.proof_path.clone());
                }
            }
            checks.push(CompletenessCheckV1 {
                name: format!("artifact:{circuit_id}"),
                passed: compiled_exists && artifact_exists && audit_exists,
                detail: format!(
                    "compiled={} proof={} audit={}",
                    compiled_path.display(),
                    artifact_path.display(),
                    audit_path.display()
                ),
            });
            if compiled_exists && artifact_exists {
                let compiled: zkf_core::CompiledProgram = read_json(&compiled_path)?;
                let artifact: zkf_core::ProofArtifact = read_json(&artifact_path)?;
                let verified = verify(&compiled, &artifact).map_err(|error| error.to_string())?;
                checks.push(CompletenessCheckV1 {
                    name: format!("proof:{circuit_id}"),
                    passed: verified,
                    detail: if verified {
                        "proof verified from compiled artifact".to_string()
                    } else {
                        "proof verification returned false".to_string()
                    },
                });
            }
            if audit_exists {
                let audit: zkf_core::AuditReport = read_json(&audit_path)?;
                checks.push(CompletenessCheckV1 {
                    name: format!("audit:{circuit_id}"),
                    passed: audit.summary.failed == 0,
                    detail: format!(
                        "{} failed checks, {} warned",
                        audit.summary.failed, audit.summary.warned
                    ),
                });
            }
        }
    }

    let report_path = root.join("17_report/report.md");
    let report_text = fs::read_to_string(&report_path).unwrap_or_default();
    let report_word_count = report_text.split_whitespace().count();
    checks.push(CompletenessCheckV1 {
        name: "report:word_count".to_string(),
        passed: report_word_count >= MIN_REPORT_WORD_COUNT,
        detail: format!("{report_word_count} words"),
    });
    if report_word_count == 0 {
        missing_paths.push("17_report/report.md".to_string());
    }

    let cargo_test_log = root.join("04_tests/cargo_test.txt");
    let cargo_test_text = fs::read_to_string(&cargo_test_log).unwrap_or_default();
    let tests_captured =
        cargo_test_text.contains("test result: ok") || cargo_test_text.contains("passed");
    checks.push(CompletenessCheckV1 {
        name: "tests:cargo".to_string(),
        passed: tests_captured,
        detail: cargo_test_log.display().to_string(),
    });

    let install_script = root.join("05_scripts/install.sh");
    let install_valid = if install_script.is_file() {
        let output = Command::new("bash")
            .arg(&install_script)
            .arg("--check-only")
            .current_dir(root)
            .output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    } else {
        false
    };
    checks.push(CompletenessCheckV1 {
        name: "install:check_only".to_string(),
        passed: install_valid,
        detail: install_script.display().to_string(),
    });

    let credential_path = root.join("11_credentials/subsystem_credential.json");
    let credential_public_keys_path =
        root.join("12_signatures/subsystem_credential_public_keys.json");
    let credential_signature_path = root.join("12_signatures/subsystem_credential_signature.json");
    let credential_signed = if credential_path.is_file()
        && credential_public_keys_path.is_file()
        && credential_signature_path.is_file()
    {
        let credential: SubsystemCredentialV1 = read_json(&credential_path)?;
        let public_keys: PublicKeyBundle = read_json(&credential_public_keys_path)?;
        let signature_bundle: SignatureBundle = read_json(&credential_signature_path)?;
        let bytes = serde_json::to_vec(&credential).map_err(|error| error.to_string())?;
        verify_bundle(
            &public_keys,
            &bytes,
            &signature_bundle,
            SUBSYSTEM_CREDENTIAL_CONTEXT,
        )
    } else {
        false
    };
    checks.push(CompletenessCheckV1 {
        name: "credentials:signed".to_string(),
        passed: credential_signed,
        detail: credential_path.display().to_string(),
    });

    let overall_passed = missing_paths.is_empty() && checks.iter().all(|check| check.passed);
    Ok(SubsystemCompletenessReportV1 {
        schema: SUBSYSTEM_COMPLETENESS_SCHEMA.to_string(),
        root: root.display().to_string(),
        subsystem_id,
        overall_passed,
        report_word_count,
        checks,
        missing_paths,
    })
}

fn verify_release_pin_report(
    pin_path: &Path,
    binary_path: &Path,
) -> Result<SubsystemCompletenessReportV1, String> {
    let signed: SignedSubsystemReleasePinV1 = read_json(pin_path)?;
    let bytes =
        fs::read(binary_path).map_err(|error| format!("{}: {error}", binary_path.display()))?;
    let computed_sha = sha256_hex(&bytes);
    let signed_bytes = serde_json::to_vec(&signed.pin).map_err(|error| error.to_string())?;
    let checks = vec![
        CompletenessCheckV1 {
            name: "release-pin:checksum".to_string(),
            passed: computed_sha == signed.pin.binary_sha256,
            detail: format!(
                "expected={} actual={computed_sha}",
                signed.pin.binary_sha256
            ),
        },
        CompletenessCheckV1 {
            name: "release-pin:signature".to_string(),
            passed: verify_bundle(
                &signed.public_keys,
                &signed_bytes,
                &signed.signature_bundle,
                SUBSYSTEM_RELEASE_PIN_CONTEXT,
            ),
            detail: signed.pin.zkf_version.clone(),
        },
        CompletenessCheckV1 {
            name: "release-pin:version".to_string(),
            passed: !signed.pin.zkf_version.trim().is_empty(),
            detail: signed.pin.zkf_version.clone(),
        },
    ];
    let overall_passed = checks.iter().all(|check| check.passed);
    Ok(SubsystemCompletenessReportV1 {
        schema: SUBSYSTEM_COMPLETENESS_SCHEMA.to_string(),
        root: pin_path.display().to_string(),
        subsystem_id: Some(signed.pin.subsystem_id.clone()),
        overall_passed,
        report_word_count: 0,
        checks,
        missing_paths: Vec::new(),
    })
}

fn load_subsystem_manifest(root: &Path) -> Result<SubsystemManifestEnvelopeV1, String> {
    read_json(&root.join("02_manifest/subsystem_manifest.json"))
}

fn primary_circuit_entry(
    manifest: &SubsystemManifestEnvelopeV1,
) -> Result<(&str, &SubsystemCircuitManifestV1), String> {
    manifest
        .circuits
        .iter()
        .next()
        .map(|(circuit_id, circuit)| (circuit_id.as_str(), circuit))
        .ok_or_else(|| "subsystem manifest contains no circuits".to_string())
}

fn reproving_report(root: &Path) -> Result<SubsystemProofLifecycleReportV1, String> {
    let manifest = load_subsystem_manifest(root)?;
    let subsystem_id = manifest.subsystem_id.clone();
    let (circuit_id, circuit) = primary_circuit_entry(&manifest)?;
    let program: Program = read_json(&root.join(&circuit.program_path))?;
    let inputs: WitnessInputs = read_json(&root.join(&circuit.inputs_path))?;
    let embedded =
        compile_and_prove(&program, &inputs, &circuit.backend, None, None).map_err(|error| error.to_string())?;
    let verified = verify(&embedded.compiled, &embedded.artifact).map_err(|error| error.to_string())?;

    write_json(&root.join(&circuit.compiled_path), &embedded.compiled)?;
    write_json(&root.join(&circuit.proof_path), &embedded.artifact)?;
    write_json(
        &root.join(&circuit.verification_path),
        &serde_json::json!({
            "schema": "zkf-subsystem-verification-v1",
            "subsystem_id": manifest.subsystem_id.clone(),
            "circuit_id": circuit_id,
            "backend": circuit.backend.clone(),
            "verified": verified,
        }),
    )?;

    Ok(SubsystemProofLifecycleReportV1 {
        schema: "zkf-subsystem-proof-lifecycle-v1".to_string(),
        root: root.display().to_string(),
        subsystem_id,
        circuit_id: circuit_id.to_string(),
        backend: circuit.backend.clone(),
        compiled_path: root.join(&circuit.compiled_path).display().to_string(),
        proof_path: root.join(&circuit.proof_path).display().to_string(),
        verification_path: root.join(&circuit.verification_path).display().to_string(),
        verified,
    })
}

fn verification_report(root: &Path) -> Result<SubsystemProofLifecycleReportV1, String> {
    let manifest = load_subsystem_manifest(root)?;
    let subsystem_id = manifest.subsystem_id.clone();
    let (circuit_id, circuit) = primary_circuit_entry(&manifest)?;
    let compiled: zkf_core::CompiledProgram = read_json(&root.join(&circuit.compiled_path))?;
    let artifact: zkf_core::ProofArtifact = read_json(&root.join(&circuit.proof_path))?;
    let verified = verify(&compiled, &artifact).map_err(|error| error.to_string())?;
    write_json(
        &root.join(&circuit.verification_path),
        &serde_json::json!({
            "schema": "zkf-subsystem-verification-v1",
            "subsystem_id": manifest.subsystem_id.clone(),
            "circuit_id": circuit_id,
            "backend": circuit.backend.clone(),
            "verified": verified,
        }),
    )?;
    Ok(SubsystemProofLifecycleReportV1 {
        schema: "zkf-subsystem-proof-lifecycle-v1".to_string(),
        root: root.display().to_string(),
        subsystem_id,
        circuit_id: circuit_id.to_string(),
        backend: circuit.backend.clone(),
        compiled_path: root.join(&circuit.compiled_path).display().to_string(),
        proof_path: root.join(&circuit.proof_path).display().to_string(),
        verification_path: root.join(&circuit.verification_path).display().to_string(),
        verified,
    })
}

fn bundle_public_report(root: &Path) -> Result<SubsystemPublicBundleReportV1, String> {
    let manifest = load_subsystem_manifest(root)?;
    let report = SubsystemPublicBundleReportV1 {
        schema: "zkf-subsystem-public-bundle-v1".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        root: root.display().to_string(),
        subsystem_id: manifest.subsystem_id.clone(),
        manifest_path: root
            .join("02_manifest/subsystem_manifest.json")
            .display()
            .to_string(),
        public_bundle_manifest_path: root
            .join("13_public_bundle/subsystem_bundle.json")
            .display()
            .to_string(),
        release_pin_path: root
            .join("20_release/zkf-release-pin.json")
            .display()
            .to_string(),
    };
    write_json(
        Path::new(&report.public_bundle_manifest_path),
        &serde_json::json!({
            "schema": report.schema,
            "generated_at": report.generated_at,
            "subsystem_id": report.subsystem_id,
            "manifest_path": "02_manifest/subsystem_manifest.json",
            "release_pin_path": "20_release/zkf-release-pin.json",
            "report_path": "17_report/report.md",
            "disclosure_policy_path": "06_docs/disclosure_policy.md",
            "public_readme_path": "13_public_bundle/README.md",
        }),
    )?;
    Ok(report)
}

fn subsystem_manifest(subsystem_id: &str) -> SubsystemManifestEnvelopeV1 {
    let circuits = BTreeMap::from([(
        SUBSYSTEM_CIRCUIT_ID.to_string(),
        SubsystemCircuitManifestV1 {
            backend: SUBSYSTEM_BACKEND.to_string(),
            program_path: "07_compiled/program.json".to_string(),
            compiled_path: "07_compiled/compiled.json".to_string(),
            inputs_path: "03_inputs/sample_input.json".to_string(),
            proof_path: "08_proofs/proof.json".to_string(),
            verification_path: "09_verification/verification.json".to_string(),
            audit_path: "10_audit/audit.json".to_string(),
        },
    )]);
    let mut manifest = SubsystemManifestEnvelopeV1::author_fixed(
        subsystem_id,
        SUBSYSTEM_SCHEMA_VERSION,
        Utc::now().to_rfc3339(),
        SUBSYSTEM_PUBLICATION_TARGET,
        circuits,
    );
    manifest.circuit_modules = vec![SubsystemCircuitModuleV1 {
        module_id: SUBSYSTEM_CIRCUIT_ID.to_string(),
        backend: SUBSYSTEM_BACKEND.to_string(),
        program_path: "07_compiled/program.json".to_string(),
        compiled_path: Some("07_compiled/compiled.json".to_string()),
        proof_path: Some("08_proofs/proof.json".to_string()),
        audit_path: Some("10_audit/audit.json".to_string()),
        guaranteed_primitives: vec![
            "arithmetic".to_string(),
            "equality".to_string(),
            "public-output-binding".to_string(),
        ],
    }];
    manifest.contracts = vec![
        SubsystemContractSpecV1 {
            contract_id: "subsystem-compact".to_string(),
            primary_target: "midnight".to_string(),
            primary_circuit: Some(SUBSYSTEM_CIRCUIT_ID.to_string()),
            compact_source: Some("16_compact/Subsystem.compact".to_string()),
            solidity_output: None,
            verifier_contract_name: None,
            midnight_class: Some(MidnightContractClassV1::Custom),
            evm_class: None,
        },
        SubsystemContractSpecV1 {
            contract_id: "subsystem-verifier".to_string(),
            primary_target: "evm".to_string(),
            primary_circuit: Some(SUBSYSTEM_CIRCUIT_ID.to_string()),
            compact_source: None,
            solidity_output: Some("15_solidity/SubsystemVerifierRegistry.sol".to_string()),
            verifier_contract_name: Some("SubsystemVerifierRegistry".to_string()),
            midnight_class: None,
            evm_class: Some(EvmCompatibilityContractClassV1::VerifierExport),
        },
    ];
    manifest.disclosure_policy = Some(DisclosurePolicyV1 {
        policy_id: format!("{subsystem_id}-default-disclosure"),
        summary: "Witness data stays local; only documented public outputs and signed release artifacts leave the bundle.".to_string(),
        witness_local_only: true,
        public_inputs_documented: true,
        notes: vec![
            "Use the generated disclosure_policy.md as the operator-facing contract.".to_string(),
            "Do not publish cache-local witnesses or debug traces.".to_string(),
        ],
    });
    manifest.deployment_profile = Some(DeploymentProfileV1 {
        primary_chain: "midnight".to_string(),
        primary_network: "preprod".to_string(),
        supports_live_deploy: false,
        explorer_expected: true,
        secondary_targets: vec!["ethereum".to_string(), "generic-evm".to_string()],
    });
    manifest.release_contract = Some(SubsystemReleaseContractV1 {
        public_bundle_dir: "13_public_bundle".to_string(),
        evidence_bundle_path: "13_public_bundle/subsystem_bundle.json".to_string(),
        release_pin_path: "20_release/zkf-release-pin.json".to_string(),
        disclosure_policy_path: "06_docs/disclosure_policy.md".to_string(),
    });
    manifest
}

fn build_identity_mirror_program(subsystem_id: &str) -> Result<Program, String> {
    let mut builder = ProgramBuilder::new(
        format!("{subsystem_id}_identity_mirror"),
        zkf_core::FieldId::Bn254,
    );
    builder
        .subsystem_id(subsystem_id)
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("application", subsystem_id)
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("publication_target", SUBSYSTEM_PUBLICATION_TARGET)
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry(
            "subsystem_backend_policy",
            SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED,
        )
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("subsystem_backend", SUBSYSTEM_BACKEND)
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("circuit_id", SUBSYSTEM_CIRCUIT_ID)
        .map_err(|error| error.to_string())?;
    builder
        .private_input("input_value")
        .map_err(|error| error.to_string())?;
    builder
        .public_output("mirrored_value")
        .map_err(|error| error.to_string())?;
    builder
        .bind_labeled(
            "mirrored_value",
            Expr::signal("input_value"),
            Some("mirror_binding".to_string()),
        )
        .map_err(|error| error.to_string())?;
    builder.build().map_err(|error| error.to_string())
}

fn sample_witness_inputs() -> WitnessInputs {
    WitnessInputs::from([("input_value".to_string(), FieldElement::from_i64(21))])
}

fn build_signed_credential(
    subsystem_id: &str,
    program: &Program,
    compiled: &zkf_core::CompiledProgram,
    artifact: &zkf_core::ProofArtifact,
    audit_failed_checks: usize,
) -> Result<SignedSubsystemCredentialV1, String> {
    let compiled_bytes = serde_json::to_vec(compiled).map_err(|error| error.to_string())?;
    let artifact_bytes = serde_json::to_vec(artifact).map_err(|error| error.to_string())?;
    let credential = SubsystemCredentialV1 {
        schema: SUBSYSTEM_CREDENTIAL_SCHEMA.to_string(),
        subsystem_id: subsystem_id.to_string(),
        circuit_id: SUBSYSTEM_CIRCUIT_ID.to_string(),
        backend_policy: SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED.to_string(),
        backend: SUBSYSTEM_BACKEND.to_string(),
        program_digest: program.digest_hex(),
        compiled_digest: sha256_hex(&compiled_bytes),
        proof_digest: sha256_hex(&artifact_bytes),
        verification_passed: true,
        audit_failed_checks,
        generated_at: Utc::now().to_rfc3339(),
    };
    let bytes = serde_json::to_vec(&credential).map_err(|error| error.to_string())?;
    let (public_keys, signature_bundle) = sign_payload(&bytes, SUBSYSTEM_CREDENTIAL_CONTEXT)?;
    Ok(SignedSubsystemCredentialV1 {
        credential,
        public_keys,
        signature_bundle,
    })
}

fn bundle_current_binary(
    root: &Path,
    subsystem_id: &str,
) -> Result<SignedSubsystemReleasePinV1, String> {
    let current_exe = resolve_release_binary()?;
    let destination = root.join("20_release/bin/zkf");
    fs::copy(&current_exe, &destination).map_err(|error| {
        format!(
            "failed to copy current zkf binary from {} to {}: {error}",
            current_exe.display(),
            destination.display()
        )
    })?;
    make_executable(&destination)?;
    let bytes = fs::read(&destination).map_err(|error| error.to_string())?;
    let pin = SubsystemReleasePinV1 {
        schema: SUBSYSTEM_RELEASE_PIN_SCHEMA.to_string(),
        subsystem_id: subsystem_id.to_string(),
        zkf_version: env!("CARGO_PKG_VERSION").to_string(),
        binary_name: "zkf".to_string(),
        binary_sha256: sha256_hex(&bytes),
        generated_at: Utc::now().to_rfc3339(),
    };
    let signed_bytes = serde_json::to_vec(&pin).map_err(|error| error.to_string())?;
    let (public_keys, signature_bundle) =
        sign_payload(&signed_bytes, SUBSYSTEM_RELEASE_PIN_CONTEXT)?;
    Ok(SignedSubsystemReleasePinV1 {
        pin,
        public_keys,
        signature_bundle,
    })
}

fn resolve_release_binary() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_zkf-cli") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let current_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let deps_dir = current_exe.parent().and_then(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| (path, name))
    });
    if let Some((deps_path, "deps")) = deps_dir
        && let Some(debug_dir) = deps_path.parent()
    {
        let candidate = debug_dir.join("zkf-cli");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Ok(current_exe)
}

fn sign_payload(
    bytes: &[u8],
    ml_dsa_context: &[u8],
) -> Result<(PublicKeyBundle, SignatureBundle), String> {
    let mut ed25519_seed = [0u8; 32];
    zkf_core::secure_random::secure_random_bytes(&mut ed25519_seed)
        .map_err(|error| error.to_string())?;
    let ed25519_signing_key = SigningKey::from_bytes(&ed25519_seed);
    let ed25519_signature = ed25519_signing_key.sign(bytes).to_bytes().to_vec();

    let keypair = generate_key_pair(secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?);
    let ml_dsa_signature = mldsa_sign(
        &keypair.signing_key,
        bytes,
        ml_dsa_context,
        secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?,
    )
    .map_err(|error| format!("failed to sign subsystem payload with ML-DSA-87: {error:?}"))?;

    Ok((
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signing_key.verifying_key().to_bytes().to_vec(),
            ml_dsa87: keypair.verification_key.as_slice().to_vec(),
        },
        SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        },
    ))
}

fn run_source_cargo_test(source_root: &Path) -> Result<String, String> {
    let output = Command::new("cargo")
        .arg("test")
        .arg("--manifest-path")
        .arg(source_root.join("Cargo.toml"))
        .arg("--quiet")
        .output()
        .map_err(|error| {
            format!(
                "failed to run cargo test for {}: {error}",
                source_root.display()
            )
        })?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "scaffolded subsystem source crate failed cargo test:\n{}",
            combined
        ))
    }
}

fn scaffold_root(name: &str, out: Option<PathBuf>) -> Result<PathBuf, String> {
    let root = match out {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?
            .join(name),
    };
    if root.exists() {
        let mut entries = root
            .read_dir()
            .map_err(|error| format!("{}: {error}", root.display()))?;
        if entries
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(format!(
                "refusing to scaffold subsystem into non-empty directory '{}'",
                root.display()
            ));
        }
    }
    Ok(root)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zkf-cli lives under the workspace root")
        .to_path_buf()
}

fn source_cargo_toml_content(subsystem_id: &str) -> String {
    format!(
        r#"[package]
name = "{subsystem_id}-source"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
zkf-lib = {{ path = "{}" }}
"#,
        repo_root().join("zkf-lib").display()
    )
}

fn source_main_rs_content() -> String {
    r#"mod subsystem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = subsystem::sample_input();
    let embedded = subsystem::run_roundtrip(&input)?;
    println!(
        "subsystem={} backend={} public_inputs={:?}",
        subsystem::SUBSYSTEM_ID,
        embedded.compiled.backend,
        embedded.artifact.public_inputs
    );
    Ok(())
}
"#
    .to_string()
}

fn source_subsystem_rs_content(subsystem_id: &str) -> String {
    format!(
        r#"use serde::{{Deserialize, Serialize}};
use zkf_lib::{{
    BackendKind, EmbeddedProof, Expr, FieldElement, FieldId, Program, ProgramBuilder,
    WitnessInputs, audit_program_default, compile_and_prove, verify,
}};

pub const SUBSYSTEM_ID: &str = "{subsystem_id}";
pub const CIRCUIT_ID: &str = "{circuit_id}";
pub const FIXED_BACKEND: &str = "{backend}";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityMirrorInputV1 {{
    pub input_value: i64,
}}

pub fn build_program() -> Result<Program, String> {{
    let mut builder = ProgramBuilder::new(format!("{{SUBSYSTEM_ID}}_identity_mirror"), FieldId::Bn254);
    builder.subsystem_id(SUBSYSTEM_ID).map_err(|error| error.to_string())?;
    builder.metadata_entry("application", SUBSYSTEM_ID).map_err(|error| error.to_string())?;
    builder
        .metadata_entry("subsystem_backend_policy", "author_fixed")
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("subsystem_backend", FIXED_BACKEND)
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("publication_target", "{publication_target}")
        .map_err(|error| error.to_string())?;
    builder
        .metadata_entry("circuit_id", CIRCUIT_ID)
        .map_err(|error| error.to_string())?;
    builder.private_input("input_value").map_err(|error| error.to_string())?;
    builder.public_output("mirrored_value").map_err(|error| error.to_string())?;
    builder
        .bind_labeled(
            "mirrored_value",
            Expr::signal("input_value"),
            Some("mirror_binding".to_string()),
        )
        .map_err(|error| error.to_string())?;
    builder.build().map_err(|error| error.to_string())
}}

pub fn sample_input() -> IdentityMirrorInputV1 {{
    IdentityMirrorInputV1 {{ input_value: 21 }}
}}

pub fn witness_inputs(input: &IdentityMirrorInputV1) -> WitnessInputs {{
    WitnessInputs::from([("input_value".to_string(), FieldElement::from_i64(input.input_value))])
}}

pub fn audit_is_clean(program: &Program) -> Result<(), String> {{
    let report = audit_program_default(program, Some(BackendKind::ArkworksGroth16));
    if report.summary.failed > 0 {{
        return Err(report.to_json().unwrap_or_else(|_| "audit failed".to_string()));
    }}
    Ok(())
}}

pub fn run_roundtrip(input: &IdentityMirrorInputV1) -> Result<EmbeddedProof, String> {{
    let program = build_program()?;
    audit_is_clean(&program)?;
    let embedded = compile_and_prove(&program, &witness_inputs(input), FIXED_BACKEND, None, None)
        .map_err(|error| error.to_string())?;
    let verified = verify(&embedded.compiled, &embedded.artifact).map_err(|error| error.to_string())?;
    if !verified {{
        return Err("verification failed".to_string());
    }}
    Ok(embedded)
}}
"#,
        subsystem_id = subsystem_id,
        circuit_id = SUBSYSTEM_CIRCUIT_ID,
        backend = SUBSYSTEM_BACKEND,
        publication_target = SUBSYSTEM_PUBLICATION_TARGET,
    )
}

fn source_roundtrip_test_content(subsystem_id: &str) -> String {
    let crate_ident = format!("{}_source", subsystem_id.replace('-', "_"));
    format!(
        r#"use {crate_ident}::subsystem;

#[test]
fn identity_mirror_roundtrip_is_green() {{
    let input = subsystem::sample_input();
    let embedded = subsystem::run_roundtrip(&input).expect("subsystem roundtrip");
    assert_eq!(embedded.compiled.backend.to_string(), subsystem::FIXED_BACKEND);
    assert_eq!(embedded.artifact.public_inputs.len(), 1);
}}
"#
    )
}

fn subsystem_readme_content(subsystem_id: &str, style: SubsystemScaffoldStyle) -> String {
    format!(
        r#"# {subsystem_id}

This subsystem bundle is generated against a pinned ZirOS `zkf` binary and a fixed backend policy.

- Subsystem ID: `{subsystem_id}`
- Circuit ID: `{circuit_id}`
- Backend policy: `author_fixed`
- Fixed backend: `{backend}`
- Publication target: `{publication_target}`
- Scaffold style: `{style}`

## Working state

The authoring crate under `01_source/` is intentionally live. Running `cargo test --manifest-path 01_source/Cargo.toml` should pass immediately and prove the trivial identity-mirror circuit end to end.

The shipped subsystem interface is still the black-box `zkf` binary under `20_release/bin/zkf` plus the fixed scripts in `19_cli/`. End users do not choose the backend from those scripts; the subsystem author already pinned it.

## Key paths

- `02_manifest/subsystem_manifest.json`
- `03_inputs/sample_input.json`
- `05_scripts/install.sh`
- `05_scripts/run-midnight-proof-server.sh`
- `05_scripts/deploy-midnight.sh`
- `06_docs/disclosure_policy.md`
- `06_docs/night_dust_guide.md`
- `06_docs/post_quantum_anchor.md`
- `07_compiled/program.json`
- `07_compiled/compiled.json`
- `08_proofs/proof.json`
- `09_verification/verification.json`
- `10_audit/audit.json`
- `17_report/report.md`
- `18_dapp/src/proof-server.mjs`
- `18_dapp/src/midnight-wallet.mjs`
- `18_dapp/src/witness.mjs`
- `19_cli/prove.sh`
- `19_cli/verify.sh`
"#,
        subsystem_id = subsystem_id,
        circuit_id = SUBSYSTEM_CIRCUIT_ID,
        backend = SUBSYSTEM_BACKEND,
        publication_target = SUBSYSTEM_PUBLICATION_TARGET,
        style = style.as_str(),
    )
}

fn public_bundle_readme_content(subsystem_id: &str) -> String {
    format!(
        r#"# Public Bundle Policy

Publish-safe materials for `{subsystem_id}` live here. The intended public bundle includes the manifest, compiled artifact, proof, verification receipt, audit report, and subsystem report. Witness inputs and cache-only debug traces stay out of this directory and out of the persistent iCloud tree.
"#
    )
}

fn report_markdown_content(
    subsystem_id: &str,
    program: &Program,
    audit: &zkf_core::AuditReport,
) -> String {
    format!(
        r#"# Subsystem Delivery Report

This subsystem bundle is intentionally small, but it is not a stub. It ships a working identity-mirror Groth16 circuit on BN254, a real compiled artifact, a real proof artifact, a successful verification receipt, a clean audit report, a fixed backend policy, a pinned `zkf` binary, and fixed shell entrypoints that do not expose backend swapping to the subsystem consumer.

The authoring circuit is built through `ProgramBuilder`, tagged with the subsystem identifier `{subsystem_id}`, and constrained so that `mirrored_value` is the public projection of the private `input_value`. That makes the starting point useful for real work: the proof path is already wired, the audit is already passing, and the generated source crate under `01_source/` already has a green roundtrip test. Developers start from a functioning surface and then add additional constraints, witness shaping, and public outputs without first debugging scaffold breakage.

This report also records the black-box contract. The end-user-facing scripts only call the pinned `zkf` binary, only target `{backend}`, and only use the shipped program or compiled artifacts. They do not forward arbitrary backend, audit, or engine mutation flags. Witness material remains local-only by policy. Opt-in Poseidon traces, if later requested during debugging, belong in the cache tree rather than the persistent subsystem bundle.

The bundle also carries Midnight-oriented operator aids around that proof surface: a local proof-server launcher, wallet/provider helper modules, NIGHT/DUST notes, a disclosure policy, and an explicit post-quantum anchor boundary note. Those files are deployment scaffolding around the subsystem; they do not change the fact that the shipped sample circuit itself is the identity-mirror Groth16 example.

## Metrics

- Program name: `{program_name}`
- Program digest: `{program_digest}`
- Constraint count: `{constraint_count}`
- Signal count: `{signal_count}`
- Audit failures: `{audit_failures}`
- Audit warnings: `{audit_warnings}`
"#,
        subsystem_id = subsystem_id,
        backend = SUBSYSTEM_BACKEND,
        program_name = program.name,
        program_digest = program.digest_hex(),
        constraint_count = program.constraints.len(),
        signal_count = program.signals.len(),
        audit_failures = audit.summary.failed,
        audit_warnings = audit.summary.warned,
    )
}

fn dapp_package_json_content(subsystem_id: &str) -> String {
    format!(
        r#"{{
  "name": "{subsystem_id}-dapp",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {{
    "witness": "node ./src/witness.mjs",
    "wallet-config": "node ./src/midnight-wallet.mjs",
    "proof-server": "bash ../05_scripts/run-midnight-proof-server.sh"
  }}
}}
"#
    )
}

fn dapp_witness_provider_content() -> String {
    r#"import { localProofServer } from "./proof-server.mjs";

const sampleWitness = {
  input_value: 21
};

const payload = {
  witness: sampleWitness,
  proving: localProofServer()
};

console.log(JSON.stringify(payload, null, 2));
"#
    .to_string()
}

fn dapp_proof_server_content() -> String {
    r#"export function localProofServer(port = Number(process.env.MIDNIGHT_PROOF_SERVER_PORT ?? 6300)) {
  const baseUrl = `http://127.0.0.1:${port}`;
  return {
    baseUrl,
    prove: `${baseUrl}/prove`,
    check: `${baseUrl}/check`,
    health: `${baseUrl}/health`
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(localProofServer(), null, 2));
}
"#
    .to_string()
}

fn dapp_wallet_helper_content() -> String {
    r#"import { localProofServer } from "./proof-server.mjs";

export async function buildMidnightWalletConfig(wallet) {
  const provingProvider = typeof wallet?.getProvingProvider === "function"
    ? await wallet.getProvingProvider()
    : null;
  const configuration = typeof wallet?.getConfiguration === "function"
    ? await wallet.getConfiguration()
    : null;

  return {
    preferredMode: provingProvider ? "wallet-proving-provider" : "local-proof-server",
    provingProvider,
    localProofServer: localProofServer(),
    deprecatedProverServerUri: configuration?.proverServerUri ?? null,
    configuration
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(
    JSON.stringify(
      {
        preferredMode: "wallet-proving-provider",
        localProofServer: localProofServer(),
        note: "Pass your Lace-compatible wallet object into buildMidnightWalletConfig() at runtime."
      },
      null,
      2
    )
  );
}
"#
    .to_string()
}

fn dapp_dashboard_content(subsystem_id: &str) -> String {
    format!(
        r#"export function Dashboard() {{
  return (
    <main>
      <h1>{subsystem_id}</h1>
      <p>Fixed backend: {backend}</p>
      <p>Witness source: 03_inputs/sample_input.json</p>
      <p>Black-box binary: 20_release/bin/zkf</p>
      <p>Local Midnight proof server: http://127.0.0.1:6300</p>
      <p>Wallet proving preference: getProvingProvider() first, explicit local proof-server URL second.</p>
      <p>Post-quantum anchor notes: 06_docs/post_quantum_anchor.md</p>
    </main>
  );
}}
"#,
        subsystem_id = subsystem_id,
        backend = SUBSYSTEM_BACKEND,
    )
}

fn solidity_contract_content(subsystem_id: &str) -> String {
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SubsystemVerifierRegistry {{
    string public constant SUBSYSTEM_ID = "{subsystem_id}";
    string public constant FIXED_BACKEND = "{backend}";
    string public constant CIRCUIT_ID = "{circuit_id}";
}}
"#,
        subsystem_id = subsystem_id,
        backend = SUBSYSTEM_BACKEND,
        circuit_id = SUBSYSTEM_CIRCUIT_ID,
    )
}

fn compact_contract_content(subsystem_id: &str) -> String {
    format!(
        r#"contract {name} {{
  export circuit id() -> Field {{
    return 1;
  }}
}}
"#,
        name = subsystem_type_name(subsystem_id)
    )
}

fn disclosure_policy_content(subsystem_id: &str) -> String {
    format!(
        r#"# Disclosure Policy

This subsystem is scaffolded for Midnight-style selective disclosure, but the disclosure boundary is still author-controlled and must be reviewed before deployment.

## Default policy

- Public bundle: manifest, compiled artifact, proof artifact, verification receipt, audit report, subsystem report, and Compact contract source.
- Private bundle: witness material, cache-only traces, credential secrets, and any operator-local telemetry that could reveal confidential source data.
- Wallet-facing DApp surface: prefer a wallet proving provider (`getProvingProvider()`) when present; otherwise point the DApp to the local ZirOS proof server at `http://127.0.0.1:6300`.

## Review checkpoints

1. Verify that every disclosed field is required by the relying party.
2. Keep raw witness inputs out of `13_public_bundle/` and the persistent iCloud tree.
3. Treat ML-DSA proof-origin signatures and post-quantum anchor metadata as operator evidence, not as a replacement for Midnight's own authorization rules.

Subsystem `{subsystem_id}` ships these rules as working defaults, not as a blanket regulatory statement.
"#
    )
}

fn night_dust_guide_content() -> String {
    r#"# NIGHT And DUST Guide

Midnight transaction costs are paid in DUST generated from NIGHT holdings. ZirOS off-chain proving does not consume NIGHT or DUST by itself; the token spend happens only when the resulting transaction is balanced and submitted to Midnight.

## Operator order of operations

1. Start the local proof server with `bash 05_scripts/run-midnight-proof-server.sh` if your wallet does not provide a proving provider directly.
2. Ask the wallet for `getProvingProvider()` first.
3. Use wallet configuration and balance helpers such as `getDustBalance()`, `getUnshieldedBalances()`, and `balanceUnsealedTransaction()` before submission.
4. Submit only the finalized transaction; do not treat proof generation alone as a network-side deployment.

For compatibility debugging, run `MIDNIGHT_PROOF_SERVER_ENGINE=upstream bash 05_scripts/run-midnight-proof-server.sh`. The default launcher path is the UMPG-backed ZirOS compatibility engine.

The helpers under `18_dapp/src/` are written to prefer the wallet-provided proving path and fall back to the local proof server only when needed.
"#
    .to_string()
}

fn post_quantum_anchor_content(subsystem_id: &str) -> String {
    format!(
        r#"# Post-Quantum Anchor Boundary

ZirOS can wrap Midnight-facing workflows in a post-quantum envelope, but it does not make Midnight's own consensus or classical proving cryptography post-quantum.

## Honest boundary

- Post-quantum proof lane: Plonky3 STARK proofs generated and verified off-chain.
- Post-quantum signature lane: ML-DSA-87 proof-origin signatures over operator artifacts.
- Midnight role: public anchor for a commitment and timestamp, not the post-quantum verifier itself.

## What survives

If a subsystem publishes a hash commitment to Midnight and retains the STARK proof plus ML-DSA signature off-chain, an independent verifier can still:

1. Verify the STARK proof locally.
2. Verify the ML-DSA-87 signature locally.
3. Compare the locally recomputed commitment to the value anchored on Midnight.

## What does not follow from that

- This does not upgrade Midnight's base cryptography to post-quantum security.
- This does not make unauthorized Midnight state changes impossible if Midnight's own classical authorization layer fails.
- This does not apply to the default identity-mirror sample in this scaffold, which ships a BN254 Groth16 example circuit. Move the proof lane to `plonky3` before advertising post-quantum proof guarantees.

Use this document as the trust-boundary note for subsystem `{subsystem_id}` when you graduate the sample into a Midnight-anchored Plonky3 deployment.
"#
    )
}

fn install_script_content(subsystem_id: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
BINARY="$ROOT/20_release/bin/zkf"
PIN="$ROOT/20_release/zkf-release-pin.json"
TARGET_DIR="${{ZKF_SUBSYSTEM_INSTALL_DIR:-$ROOT/.runtime/bin}}"
TARGET="$TARGET_DIR/zkf"

if [[ "${{1:-}}" == "--check-only" ]]; then
  if [[ ! -f "$BINARY" ]]; then
    echo "missing bundled zkf binary: $BINARY" >&2
    exit 66
  fi
  if [[ ! -f "$PIN" ]]; then
    echo "missing release pin: $PIN" >&2
    exit 66
  fi
  exit 0
fi

if [[ ! -x "$BINARY" ]]; then
  chmod +x "$BINARY"
fi

"$BINARY" subsystem verify-release-pin --pin "$PIN" --binary "$BINARY"

mkdir -p "$TARGET_DIR"
cp "$BINARY" "$TARGET"
chmod +x "$TARGET"
printf 'installed pinned zkf for {subsystem_id} -> %s\n' "$TARGET"
"#
    )
}

fn run_midnight_proof_server_script_content() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ZKF_SUBSYSTEM_ZKF_BIN:-$ROOT/20_release/bin/zkf}"
PORT="${MIDNIGHT_PROOF_SERVER_PORT:-6300}"
ENGINE="${MIDNIGHT_PROOF_SERVER_ENGINE:-umpg}"

exec "$BIN" midnight proof-server serve --port "$PORT" --engine "$ENGINE" --json
"#
    .to_string()
}

fn deploy_midnight_script_content() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="$ROOT/16_compact/Subsystem.compact"
PORT="${MIDNIGHT_PROOF_SERVER_PORT:-6300}"
PROOF_SERVER_URL="${MIDNIGHT_PROOF_SERVER_URL:-http://127.0.0.1:$PORT}"

if [[ ! -f "$CONTRACT" ]]; then
  echo "missing Compact contract source: $CONTRACT" >&2
  exit 66
fi

if ! command -v compactc >/dev/null 2>&1; then
  echo "compactc is not installed. Install the Midnight Compact compiler before deployment." >&2
  exit 127
fi

cat <<EOF
Midnight deployment preflight
  contract: $CONTRACT
  proof-server-url: $PROOF_SERVER_URL
  wallet-preference: getProvingProvider() first, local proof server second

Next:
  1. Start the local prover with bash 05_scripts/run-midnight-proof-server.sh
  2. Compile the Compact contract with your installed compactc toolchain
  3. Balance and submit the resulting transaction through your Midnight wallet/DApp stack
EOF
"#
    .to_string()
}

fn prove_script_content(subsystem_id: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
BIN="${{ZKF_SUBSYSTEM_ZKF_BIN:-$ROOT/20_release/bin/zkf}}"
INPUTS="${{1:-$ROOT/03_inputs/sample_input.json}}"
OUT_DIR="${{2:-$ROOT/08_proofs}}"

if [[ $# -gt 2 ]]; then
  echo "usage: prove.sh [inputs.json] [out-dir]" >&2
  exit 64
fi
if [[ "${{1:-}}" == --* ]] || [[ "${{2:-}}" == --* ]]; then
  echo "backend and engine overrides are not accepted by this subsystem wrapper" >&2
  exit 64
fi

mkdir -p "$OUT_DIR"
"$BIN" prove \
  --program "$ROOT/07_compiled/program.json" \
  --inputs "$INPUTS" \
  --backend "{backend}" \
  --out "$OUT_DIR/proof.json" \
  --compiled-out "$ROOT/07_compiled/compiled.json"

printf 'subsystem %s proved with fixed backend %s\n' "{subsystem_id}" "{backend}"
"#,
        subsystem_id = subsystem_id,
        backend = SUBSYSTEM_BACKEND,
    )
}

fn verify_script_content(subsystem_id: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
BIN="${{ZKF_SUBSYSTEM_ZKF_BIN:-$ROOT/20_release/bin/zkf}}"
ARTIFACT="${{1:-$ROOT/08_proofs/proof.json}}"

if [[ $# -gt 1 ]]; then
  echo "usage: verify.sh [proof.json]" >&2
  exit 64
fi
if [[ "${{1:-}}" == --* ]]; then
  echo "backend and engine overrides are not accepted by this subsystem wrapper" >&2
  exit 64
fi

"$BIN" verify \
  --program "$ROOT/07_compiled/program.json" \
  --compiled "$ROOT/07_compiled/compiled.json" \
  --artifact "$ARTIFACT" \
  --backend "{backend}"

printf 'subsystem %s verified with fixed backend %s\n' "{subsystem_id}" "{backend}"
"#,
        subsystem_id = subsystem_id,
        backend = SUBSYSTEM_BACKEND,
    )
}

fn subsystem_type_name(subsystem_id: &str) -> String {
    let mut out = String::new();
    for part in subsystem_id.split('-').filter(|part| !part.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        "Subsystem".to_string()
    } else {
        out
    }
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_scaffold_slugifies_and_generates_working_source_crate() {
        let root = tempfile::tempdir().expect("tempdir");
        let out = root.path().join("demo-subsystem");
        let generated = scaffold_subsystem("Demo Subsystem", "full", Some(out.clone()))
            .expect("subsystem scaffold");
        assert_eq!(generated, out);
        assert!(
            generated
                .join("02_manifest/subsystem_manifest.json")
                .is_file()
        );
        assert!(generated.join("05_scripts/install.sh").is_file());
        assert!(
            generated
                .join("05_scripts/run-midnight-proof-server.sh")
                .is_file()
        );
        let launcher =
            fs::read_to_string(generated.join("05_scripts/run-midnight-proof-server.sh"))
                .expect("read proof-server launcher");
        assert!(launcher.contains("MIDNIGHT_PROOF_SERVER_ENGINE:-umpg"));
        assert!(launcher.contains("--engine \"$ENGINE\""));
        assert!(generated.join("05_scripts/deploy-midnight.sh").is_file());
        assert!(generated.join("06_docs/post_quantum_anchor.md").is_file());
        assert!(generated.join("07_compiled/program.json").is_file());
        assert!(generated.join("08_proofs/proof.json").is_file());
        assert!(generated.join("10_audit/audit.json").is_file());
        assert!(generated.join("01_source/tests/roundtrip.rs").is_file());
        assert!(generated.join("18_dapp/src/proof-server.mjs").is_file());
        assert!(generated.join("18_dapp/src/midnight-wallet.mjs").is_file());
        assert!(generated.join("18_dapp/src/witness.mjs").is_file());
        let manifest: SubsystemManifestEnvelopeV1 =
            read_json(&generated.join("02_manifest/subsystem_manifest.json")).expect("manifest");
        assert_eq!(
            manifest.backend_policy,
            SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED
        );
        assert_eq!(
            manifest
                .circuits
                .get(SUBSYSTEM_CIRCUIT_ID)
                .expect("identity mirror circuit")
                .backend,
            SUBSYSTEM_BACKEND
        );
    }

    #[test]
    fn verify_release_pin_detects_sha_mismatch() {
        let root = tempfile::tempdir().expect("tempdir");
        let binary = root.path().join("zkf");
        fs::write(&binary, b"good").expect("binary");
        let pin = SignedSubsystemReleasePinV1 {
            pin: SubsystemReleasePinV1 {
                schema: SUBSYSTEM_RELEASE_PIN_SCHEMA.to_string(),
                subsystem_id: "demo".to_string(),
                zkf_version: "0.1.0".to_string(),
                binary_name: "zkf".to_string(),
                binary_sha256: sha256_hex(b"other"),
                generated_at: Utc::now().to_rfc3339(),
            },
            public_keys: PublicKeyBundle::default(),
            signature_bundle: SignatureBundle::default(),
        };
        let pin_path = root.path().join("pin.json");
        write_json(&pin_path, &pin).expect("pin");
        let report = verify_release_pin_report(&pin_path, &binary).expect("report");
        assert!(!report.overall_passed);
    }

    #[test]
    fn verify_completeness_passes_for_fresh_scaffold() {
        let root = tempfile::tempdir().expect("tempdir");
        let generated = scaffold_subsystem(
            "Completeness Demo",
            "full",
            Some(root.path().join("completeness-demo")),
        )
        .expect("subsystem scaffold");
        let report = verify_completeness_report(&generated).expect("completeness report");
        assert!(report.overall_passed, "{report:#?}");
    }

    #[test]
    fn prove_wrapper_rejects_backend_override_flags() {
        let root = tempfile::tempdir().expect("tempdir");
        let generated = scaffold_subsystem(
            "Override Demo",
            "full",
            Some(root.path().join("override-demo")),
        )
        .expect("subsystem scaffold");
        let output = Command::new("bash")
            .arg(generated.join("19_cli/prove.sh"))
            .arg("--backend")
            .current_dir(&generated)
            .output()
            .expect("prove wrapper should run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("backend and engine overrides are not accepted"));
    }
}
