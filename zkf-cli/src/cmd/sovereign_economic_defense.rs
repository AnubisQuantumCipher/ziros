use crate::cli::{
    SovereignEconomicDefenseArgs, SovereignEconomicDefenseCircuitSelector,
    SovereignEconomicDefenseCommands,
};
use crate::cmd::runtime::wrap_artifact_via_runtime;
use crate::solidity::{EvmTarget, parse_evm_target, render_groth16_solidity_verifier_for_target};
use crate::util::{
    annotate_artifact_with_runtime_report, read_json, write_json, write_text,
    with_allow_dev_deterministic_groth16_override, with_groth16_setup_blob_path_override,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87SigningKey, MLDSA87VerificationKey, generate_key_pair, sign as mldsa_sign,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zkf_backends::{BackendRoute, metal_runtime_report, wrapping::default_wrapper_registry};
use zkf_cloudfs::CloudFS;
use zkf_core::{
    AuditReport, BackendKind, CompiledProgram, Program, ProofArtifact, PublicKeyBundle,
    SignatureBundle, SignatureScheme, Witness, verify_bundle,
};
use zkf_core::wrapping::{WrapModeOverride, WrapperExecutionPolicy};
use zkf_keymanager::KeyManager;
use zkf_lib::{
    RecirculationSovereigntyScoreRequestV1, SovereignEconomicDefenseRunManifestV1,
    anti_extraction_shield_witness_from_request, audit_program_default,
    build_anti_extraction_shield_program, build_community_land_trust_governance_program,
    build_cooperative_treasury_assurance_program,
    build_recirculation_sovereignty_score_program, build_wealth_trajectory_assurance_program,
    community_land_trust_governance_witness_from_request,
    cooperative_treasury_assurance_witness_from_request,
    recirculation_sovereignty_score_witness_from_request, verify,
    wealth_trajectory_assurance_witness_from_request,
};
use zkf_runtime::{
    ExecutionMode, HardwareProfile, OptimizationObjective, RequiredTrustLane, RuntimeExecutor,
};

const APP_ID: &str = "sovereign-economic-defense";
const PROOF_ORIGIN_CONTEXT: &[u8] = b"ZirOS Sovereign Economic Defense Proof Origin v1";
const CREDENTIAL_CONTEXT: &[u8] = b"ZirOS Sovereign Economic Defense Credential v1";

const PROOF_ORIGIN_ED25519_SERVICE: &str = "com.ziros.sed.proof-origin.ed25519";
const PROOF_ORIGIN_MLDSA_SIGNING_SERVICE: &str = "com.ziros.sed.proof-origin.mldsa87.signing";
const PROOF_ORIGIN_MLDSA_PUBLIC_SERVICE: &str = "com.ziros.sed.proof-origin.mldsa87.public";
const CREDENTIAL_ED25519_SERVICE: &str = "com.ziros.sed.credential.ed25519";
const CREDENTIAL_MLDSA_SIGNING_SERVICE: &str = "com.ziros.sed.credential.mldsa87.signing";
const CREDENTIAL_MLDSA_PUBLIC_SERVICE: &str = "com.ziros.sed.credential.mldsa87.public";
const DIRECT_WRAP_ESTIMATED_MEMORY_BYTES: u64 = 7_778_534_400_000;
const DIRECT_WRAP_MEMORY_BUDGET_BYTES: u64 = 36_977_885_184;
const DIRECT_WRAP_OBSERVED_PHYSICAL_FOOTPRINT: &str = "248.8G";

#[derive(Debug, Clone)]
struct HybridSignerMaterial {
    ed25519_seed: [u8; 32],
    ml_dsa87_signing_key: Vec<u8>,
    ml_dsa87_public_key: Vec<u8>,
}

impl HybridSignerMaterial {
    fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: SigningKey::from_bytes(&self.ed25519_seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            ml_dsa87: self.ml_dsa87_public_key.clone(),
        }
    }

    fn ml_dsa_signing_key(&self) -> Result<MLDSA87SigningKey, String> {
        let bytes: [u8; MLDSA87SigningKey::len()] = self
            .ml_dsa87_signing_key
            .clone()
            .try_into()
            .map_err(|_| "ML-DSA signing key material is corrupt".to_string())?;
        Ok(MLDSA87SigningKey::new(bytes))
    }

    fn validate(&self) -> Result<(), String> {
        if self.ml_dsa87_signing_key.len() != MLDSA87SigningKey::len() {
            return Err("ML-DSA signing key material is corrupt".to_string());
        }
        if self.ml_dsa87_public_key.len() != MLDSA87VerificationKey::len() {
            return Err("ML-DSA public key material is corrupt".to_string());
        }
        Ok(())
    }

    fn sign_message(&self, bytes: &[u8], context: &[u8]) -> Result<SignatureBundle, String> {
        self.validate()?;
        let ed25519_signature = SigningKey::from_bytes(&self.ed25519_seed)
            .sign(bytes)
            .to_bytes()
            .to_vec();
        let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?;
        let ml_dsa_signature = mldsa_sign(
            &self.ml_dsa_signing_key()?,
            bytes,
            context,
            randomness,
        )
        .map_err(|err| format!("failed to sign with ML-DSA-87: {err:?}"))?;
        Ok(SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovereignEconomicDefenseCredentialClaimsV1 {
    version: u32,
    schema: String,
    credential_type: String,
    subject: String,
    run_id: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    trust_lane: String,
    artifact_digests: Vec<String>,
    metadata: BTreeMap<String, String>,
}

impl SovereignEconomicDefenseCredentialClaimsV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| format!("failed to serialize credential: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedSovereignEconomicDefenseCredentialV1 {
    claims: SovereignEconomicDefenseCredentialClaimsV1,
    issuer_public_keys: PublicKeyBundle,
    issuer_signature_bundle: SignatureBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovereignEconomicDefenseCircuitBundleV1 {
    circuit_id: u8,
    circuit_name: String,
    slug: String,
    backend: String,
    audited: bool,
    verified: bool,
    wrapped_verified: Option<bool>,
    proof_origin_verified: bool,
    compiled_path: String,
    proof_path: String,
    audit_path: String,
    execution_trace_path: String,
    wrapped_proof_path: Option<String>,
    wrapped_status: Option<String>,
    wrapped_strategy: Option<String>,
    wrapped_trust_model: Option<String>,
    public_outputs: BTreeMap<String, String>,
    proof_sha256: String,
    wrapped_proof_sha256: Option<String>,
    runtime_gpu_busy_ratio: Option<f64>,
    used_metal: bool,
    icloud_proof_path: Option<String>,
    icloud_wrapped_proof_path: Option<String>,
    icloud_trace_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovereignEconomicDefenseStorageManifestV1 {
    version: u32,
    schema: String,
    persistent_root: String,
    cache_root: String,
    storage_mode: String,
    persistent_writes: Vec<String>,
    local_only_roots: Vec<String>,
    witness_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovereignEconomicDefenseBundleManifestV1 {
    version: u32,
    schema: String,
    application: String,
    run_id: String,
    created_at_unix: u64,
    timestamp: String,
    hardware_profile: String,
    evm_target: String,
    bundle_root: String,
    circuits: Vec<SovereignEconomicDefenseCircuitBundleV1>,
    credential_paths: Vec<String>,
    storage_manifest_path: String,
    mission_report_json_path: String,
    mission_report_markdown_path: String,
    verifier_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovereignEconomicDefenseMissionReportV1 {
    version: u32,
    schema: String,
    application: String,
    run_id: String,
    timestamp: String,
    hardware_profile: String,
    metal_runtime: Value,
    circuits: Vec<Value>,
    credentials: Vec<Value>,
    storage: SovereignEconomicDefenseStorageManifestV1,
    verifier: Option<Value>,
    honesty_notes: Vec<String>,
}

struct CircuitExecutionOutcome {
    bundle: SovereignEconomicDefenseCircuitBundleV1,
    proof_artifact: ProofArtifact,
}

#[derive(Debug, Clone, Copy)]
struct SovereignEconomicDefenseWrapRequest {
    allow_attestation: bool,
    compress: bool,
}

impl SovereignEconomicDefenseWrapRequest {
    fn disabled() -> Self {
        Self {
            allow_attestation: false,
            compress: false,
        }
    }

    fn enabled(self) -> bool {
        self.allow_attestation || self.compress
    }

    fn trust_lane(self) -> RequiredTrustLane {
        if self.allow_attestation {
            RequiredTrustLane::AllowAttestation
        } else {
            RequiredTrustLane::StrictCryptographic
        }
    }

    fn force_mode(self) -> Option<WrapModeOverride> {
        self.compress.then_some(WrapModeOverride::Nova)
    }
}

pub(crate) fn handle_sovereign_economic_defense_command(
    args: SovereignEconomicDefenseArgs,
) -> Result<(), String> {
    match args.command {
        SovereignEconomicDefenseCommands::Prove {
            inputs,
            out,
            circuit,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            evm_target,
            allow_attestation,
            compress,
            no_wrap,
        } => handle_prove(
            inputs,
            out,
            circuit,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            evm_target,
            allow_attestation,
            compress,
            no_wrap,
        ),
        SovereignEconomicDefenseCommands::Verify { bundle } => handle_verify(bundle),
        SovereignEconomicDefenseCommands::Report { bundle, out } => handle_report(bundle, out),
        SovereignEconomicDefenseCommands::ExportBundle {
            bundle,
            out,
            include_private,
        } => handle_export_bundle(bundle, out, include_private),
    }
}

fn handle_prove(
    inputs: PathBuf,
    out: PathBuf,
    circuit: SovereignEconomicDefenseCircuitSelector,
    groth16_setup_blob: Option<PathBuf>,
    allow_dev_deterministic_groth16: bool,
    evm_target: String,
    allow_attestation: bool,
    compress: bool,
    no_wrap: bool,
) -> Result<(), String> {
    let started = Instant::now();
    let inputs = resolve_cli_path(inputs)?;
    let out = resolve_cli_path(out)?;
    let bundle_root = out;
    fs::create_dir_all(&bundle_root)
        .map_err(|error| format!("failed to create {}: {error}", bundle_root.display()))?;

    let manifest: SovereignEconomicDefenseRunManifestV1 = read_json(&inputs)?;
    let timestamp = run_timestamp();
    let created_at_unix = unix_now_seconds()?;
    let evm_target = parse_evm_target(Some(&evm_target))?;
    let hardware_profile = HardwareProfile::detect();
    let cloudfs = CloudFS::new().map_err(|error| error.to_string())?;
    let key_manager = KeyManager::new().map_err(|error| error.to_string())?;
    let proof_origin_signer = load_or_create_hybrid_signer(
        &key_manager,
        "sovereign-economic-defense-proof-origin",
        PROOF_ORIGIN_ED25519_SERVICE,
        PROOF_ORIGIN_MLDSA_SIGNING_SERVICE,
        PROOF_ORIGIN_MLDSA_PUBLIC_SERVICE,
    )?;
    let credential_signer = load_or_create_hybrid_signer(
        &key_manager,
        "sovereign-economic-defense-credential-issuer",
        CREDENTIAL_ED25519_SERVICE,
        CREDENTIAL_MLDSA_SIGNING_SERVICE,
        CREDENTIAL_MLDSA_PUBLIC_SERVICE,
    )?;

    let mut persistent_writes = Vec::new();
    let mut circuit_bundles = Vec::new();
    let mut circuit_outcomes = Vec::new();
    let starks_wrap_request = if no_wrap {
        SovereignEconomicDefenseWrapRequest::disabled()
    } else {
        SovereignEconomicDefenseWrapRequest {
            allow_attestation,
            compress,
        }
    };

    if selector_includes(circuit, 1) || selector_requires_dependencies(circuit) {
        let outcome = execute_circuit(
            1,
            "cooperative-treasury-assurance",
            BackendKind::Plonky3,
            build_cooperative_treasury_assurance_program(&manifest.cooperative_treasury)
                .map_err(|error| error.to_string())?,
            cooperative_treasury_assurance_witness_from_request(&manifest.cooperative_treasury)
                .map_err(|error| error.to_string())?,
            starks_wrap_request,
            &bundle_root,
            &timestamp,
            &cloudfs,
            &proof_origin_signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            hardware_profile,
            &mut persistent_writes,
        )?;
        circuit_bundles.push(outcome.bundle.clone());
        circuit_outcomes.push(outcome);
    }
    if selector_includes(circuit, 2) || selector_requires_dependencies(circuit) {
        let outcome = execute_circuit(
            2,
            "community-land-trust-governance",
            BackendKind::Plonky3,
            build_community_land_trust_governance_program(&manifest.community_land_trust)
                .map_err(|error| error.to_string())?,
            community_land_trust_governance_witness_from_request(&manifest.community_land_trust)
                .map_err(|error| error.to_string())?,
            starks_wrap_request,
            &bundle_root,
            &timestamp,
            &cloudfs,
            &proof_origin_signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            hardware_profile,
            &mut persistent_writes,
        )?;
        circuit_bundles.push(outcome.bundle.clone());
        circuit_outcomes.push(outcome);
    }
    if selector_includes(circuit, 3) || selector_requires_dependencies(circuit) {
        let outcome = execute_circuit(
            3,
            "anti-extraction-shield",
            BackendKind::ArkworksGroth16,
            build_anti_extraction_shield_program(&manifest.anti_extraction_shield)
                .map_err(|error| error.to_string())?,
            anti_extraction_shield_witness_from_request(&manifest.anti_extraction_shield)
                .map_err(|error| error.to_string())?,
            SovereignEconomicDefenseWrapRequest::disabled(),
            &bundle_root,
            &timestamp,
            &cloudfs,
            &proof_origin_signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            hardware_profile,
            &mut persistent_writes,
        )?;
        circuit_bundles.push(outcome.bundle.clone());
        circuit_outcomes.push(outcome);
    }
    if selector_includes(circuit, 4) || selector_requires_dependencies(circuit) {
        let outcome = execute_circuit(
            4,
            "wealth-trajectory-assurance",
            BackendKind::Plonky3,
            build_wealth_trajectory_assurance_program(&manifest.wealth_trajectory)
                .map_err(|error| error.to_string())?,
            wealth_trajectory_assurance_witness_from_request(&manifest.wealth_trajectory)
                .map_err(|error| error.to_string())?,
            starks_wrap_request,
            &bundle_root,
            &timestamp,
            &cloudfs,
            &proof_origin_signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            hardware_profile,
            &mut persistent_writes,
        )?;
        circuit_bundles.push(outcome.bundle.clone());
        circuit_outcomes.push(outcome);
    }

    if selector_includes(circuit, 5) || circuit == SovereignEconomicDefenseCircuitSelector::All {
        let recirculation_request =
            resolved_recirculation_request(&manifest.recirculation_sovereignty, &circuit_bundles)?;
        let outcome = execute_circuit(
            5,
            "recirculation-sovereignty-score",
            BackendKind::Plonky3,
            build_recirculation_sovereignty_score_program(&recirculation_request)
                .map_err(|error| error.to_string())?,
            recirculation_sovereignty_score_witness_from_request(&recirculation_request)
                .map_err(|error| error.to_string())?,
            starks_wrap_request,
            &bundle_root,
            &timestamp,
            &cloudfs,
            &proof_origin_signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            hardware_profile,
            &mut persistent_writes,
        )?;
        circuit_bundles.push(outcome.bundle.clone());
        circuit_outcomes.push(outcome);
    }

    let proof_digests = circuit_bundles
        .iter()
        .map(|bundle| bundle.proof_sha256.clone())
        .collect::<Vec<_>>();
    let credential_paths = issue_credentials(
        &bundle_root,
        &manifest.run_id,
        hardware_profile,
        created_at_unix,
        &proof_digests,
        &credential_signer,
    )?;

    let credential_values = credential_paths
        .iter()
        .map(|path| read_json::<SignedSovereignEconomicDefenseCredentialV1>(Path::new(path)))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|credential| serde_json::to_value(credential).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    let verifier = circuit_outcomes
        .iter()
        .find(|outcome| outcome.bundle.circuit_id == 3)
        .map(|outcome| {
            build_solidity_verifier(
                bundle_root.as_path(),
                outcome.bundle.circuit_id,
                &outcome.bundle.slug,
                &outcome.proof_artifact,
                evm_target,
            )
        })
        .transpose()?;
    if let Some(verifier) = verifier.as_ref() {
        let relative = format!(
            "verifiers/{APP_ID}/{}/{}",
            timestamp,
            verifier
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    format!(
                        "invalid verifier file name '{}'",
                        verifier.path.display()
                    )
                })?
        );
        cloudfs
            .write(&relative, verifier.source.as_bytes())
            .map_err(|error| error.to_string())?;
        persistent_writes.push(relative);
    }

    let report_relative = format!("reports/{APP_ID}/{timestamp}/mission_report.json");
    persistent_writes.push(report_relative.clone());

    let storage_manifest = SovereignEconomicDefenseStorageManifestV1 {
        version: 1,
        schema: "zkf-sovereign-economic-defense-storage-manifest-v1".to_string(),
        persistent_root: cloudfs.persistent_root().display().to_string(),
        cache_root: cloudfs.cache_root().display().to_string(),
        storage_mode: cloudfs.sync_root_state().to_string(),
        persistent_writes,
        local_only_roots: vec![cloudfs.cache_root().display().to_string()],
        witness_policy: "~/.zkf/cache only; witnesses are never written into the persistent iCloud tree".to_string(),
    };
    let storage_manifest_path = bundle_root.join("14_icloud_manifest/storage_manifest.json");
    write_json(&storage_manifest_path, &storage_manifest)?;

    let mission_report = SovereignEconomicDefenseMissionReportV1 {
        version: 1,
        schema: "zkf-sovereign-economic-defense-mission-report-v1".to_string(),
        application: APP_ID.to_string(),
        run_id: manifest.run_id.clone(),
        timestamp: timestamp.clone(),
        hardware_profile: hardware_profile.as_str().to_string(),
        metal_runtime: serde_json::to_value(metal_runtime_report()).map_err(|e| e.to_string())?,
        circuits: circuit_bundles
            .iter()
            .map(|bundle| serde_json::to_value(bundle).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?,
        credentials: credential_values,
        storage: storage_manifest.clone(),
        verifier: verifier.as_ref().map(|value| {
            json!(SolidityVerifierReportV1 {
                contract_name: value.contract_name.clone(),
                path: value.path.display().to_string(),
                evm_target: value.target.as_str().to_string(),
                estimated_verify_gas: value.estimated_verify_gas,
                source_circuit_id: Some(value.source_circuit_id),
                source_circuit_slug: Some(value.source_circuit_slug.clone()),
                source_backend: Some(value.source_backend.clone()),
            })
        }),
        honesty_notes: mission_honesty_notes(&circuit_bundles),
    };
    let mission_report_json_path = bundle_root.join("17_report/mission_report.json");
    write_json(&mission_report_json_path, &mission_report)?;
    let mission_report_markdown_path = bundle_root.join("17_report/mission_report.md");
    write_text(
        &mission_report_markdown_path,
        &render_report_markdown(&mission_report, &circuit_bundles, verifier.as_ref()),
    )?;

    cloudfs
        .write_json(&report_relative, &mission_report)
        .map_err(|error| error.to_string())?;

    let bundle_manifest = SovereignEconomicDefenseBundleManifestV1 {
        version: 1,
        schema: "zkf-sovereign-economic-defense-bundle-manifest-v1".to_string(),
        application: APP_ID.to_string(),
        run_id: manifest.run_id,
        created_at_unix,
        timestamp: timestamp.clone(),
        hardware_profile: hardware_profile.as_str().to_string(),
        evm_target: evm_target.as_str().to_string(),
        bundle_root: bundle_root.display().to_string(),
        circuits: circuit_bundles.clone(),
        credential_paths: credential_paths
            .iter()
            .map(|path| path.to_string())
            .collect(),
        storage_manifest_path: storage_manifest_path.display().to_string(),
        mission_report_json_path: mission_report_json_path.display().to_string(),
        mission_report_markdown_path: mission_report_markdown_path.display().to_string(),
        verifier_path: verifier.as_ref().map(|value| value.path.display().to_string()),
    };
    write_json(&bundle_root.join("bundle_manifest.json"), &bundle_manifest)?;

    println!(
        "sovereign economic defense bundle written to {} (circuits={}, total_ms={})",
        bundle_root.display(),
        bundle_manifest.circuits.len(),
        started.elapsed().as_millis()
    );
    Ok(())
}

fn handle_verify(bundle: PathBuf) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let manifest: SovereignEconomicDefenseBundleManifestV1 = read_json(&bundle.join("bundle_manifest.json"))?;
    for circuit in &manifest.circuits {
        let compiled: CompiledProgram = read_json(Path::new(&circuit.compiled_path))?;
        let artifact: ProofArtifact = read_json(Path::new(&circuit.proof_path))?;
        let verified = verify(&compiled, &artifact).map_err(|error| error.to_string())?;
        if !verified {
            return Err(format!(
                "source proof verification failed for circuit {}",
                circuit.slug
            ));
        }
        verify_artifact_proof_origin(&artifact)?;
        if let Some(wrapped_path) = circuit.wrapped_proof_path.as_ref() {
            let registry = default_wrapper_registry();
            let wrapped: ProofArtifact = read_json(Path::new(wrapped_path))?;
            let wrapper = registry
                .find(artifact.backend, BackendKind::ArkworksGroth16)
                .ok_or_else(|| {
                    format!("no wrapper registered for {} -> arkworks-groth16", artifact.backend)
                })?;
            let wrapped_verified = wrapper
                .verify_wrapped(&wrapped)
                .map_err(|error| error.to_string())?;
            if !wrapped_verified {
                return Err(format!("wrapped proof verification failed for {}", circuit.slug));
            }
            verify_artifact_proof_origin(&wrapped)?;
        }
    }
    for credential_path in &manifest.credential_paths {
        let credential: SignedSovereignEconomicDefenseCredentialV1 =
            read_json(Path::new(credential_path))?;
        verify_credential(&credential)?;
    }
    println!("sovereign economic defense bundle verified: {}", bundle.display());
    Ok(())
}

fn handle_report(bundle: PathBuf, out: Option<PathBuf>) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let manifest: SovereignEconomicDefenseBundleManifestV1 = read_json(&bundle.join("bundle_manifest.json"))?;
    let mission_report: SovereignEconomicDefenseMissionReportV1 =
        read_json(Path::new(&manifest.mission_report_json_path))?;
    let output = out
        .map(resolve_cli_path)
        .transpose()?
        .unwrap_or_else(|| bundle.join("17_report/mission_report.md"));
    let verifier = load_verifier_bundle_for_report(&manifest, &mission_report)?;
    write_text(
        &output,
        &render_report_markdown(&mission_report, &manifest.circuits, verifier.as_ref()),
    )?;
    println!(
        "sovereign economic defense report written to {}",
        output.display()
    );
    Ok(())
}

fn handle_export_bundle(bundle: PathBuf, out: PathBuf, include_private: bool) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let out = resolve_cli_path(out)?;
    fs::create_dir_all(&out).map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let manifest: SovereignEconomicDefenseBundleManifestV1 = read_json(&bundle.join("bundle_manifest.json"))?;
    copy_bundle_file(&bundle.join("bundle_manifest.json"), &out.join("bundle_manifest.json"))?;
    copy_bundle_file(
        Path::new(&manifest.storage_manifest_path),
        &out.join("14_icloud_manifest/storage_manifest.json"),
    )?;
    copy_bundle_file(
        Path::new(&manifest.mission_report_json_path),
        &out.join("17_report/mission_report.json"),
    )?;
    copy_bundle_file(
        Path::new(&manifest.mission_report_markdown_path),
        &out.join("17_report/mission_report.md"),
    )?;
    if let Some(verifier_path) = manifest.verifier_path.as_ref() {
        let verifier_name = Path::new(verifier_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid verifier file path '{}'", verifier_path))?;
        copy_bundle_file(
            Path::new(verifier_path),
            &out.join("15_solidity").join(verifier_name),
        )?;
    }
    for circuit in &manifest.circuits {
        let destination = out.join("proofs").join(&circuit.slug);
        copy_bundle_file(Path::new(&circuit.compiled_path), &destination.join("compiled.json"))?;
        copy_bundle_file(Path::new(&circuit.proof_path), &destination.join("proof.json"))?;
        copy_bundle_file(
            Path::new(&circuit.audit_path),
            &destination.join("audit.json"),
        )?;
        copy_bundle_file(
            Path::new(&circuit.execution_trace_path),
            &destination.join("execution_trace.json"),
        )?;
        if let Some(wrapped_path) = circuit.wrapped_proof_path.as_ref() {
            copy_bundle_file(
                Path::new(wrapped_path),
                &destination.join("wrapped_groth16.json"),
            )?;
        }
    }
    if include_private {
        for credential_path in &manifest.credential_paths {
            let filename = Path::new(credential_path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("invalid credential file path '{}'", credential_path))?;
            copy_bundle_file(Path::new(credential_path), &out.join("11_credentials").join(filename))?;
        }
    }
    println!(
        "sovereign economic defense export bundle written to {}",
        out.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_circuit(
    circuit_id: u8,
    slug: &'static str,
    backend: BackendKind,
    program: Program,
    witness: Witness,
    wrap_request: SovereignEconomicDefenseWrapRequest,
    bundle_root: &Path,
    timestamp: &str,
    cloudfs: &CloudFS,
    proof_origin_signer: &HybridSignerMaterial,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
    hardware_profile: HardwareProfile,
    persistent_writes: &mut Vec<String>,
) -> Result<CircuitExecutionOutcome, String> {
    let circuit_dir = bundle_root.join("proofs").join(slug);
    fs::create_dir_all(&circuit_dir)
        .map_err(|error| format!("failed to create {}: {error}", circuit_dir.display()))?;

    let audit = ensure_fail_closed_audit(&program, backend)?;
    let audit_path = circuit_dir.join("audit.json");
    write_json(&audit_path, &audit)?;

    let started = Instant::now();
    let execution = prove_with_runtime(
        backend,
        program,
        witness,
        groth16_setup_blob,
        allow_dev_deterministic_groth16,
    )?;
    let mut artifact = execution.artifact;
    annotate_artifact_with_runtime_report(&mut artifact, &execution.result);
    sign_artifact_proof_origin(&mut artifact, proof_origin_signer)?;
    let verified = verify(&execution.compiled, &artifact).map_err(|error| error.to_string())?;
    if !verified {
        return Err(format!("proof verification failed for circuit {slug}"));
    }
    verify_artifact_proof_origin(&artifact)?;

    let compiled_path = circuit_dir.join("compiled.json");
    let proof_path = circuit_dir.join("proof.json");
    let execution_trace_path = circuit_dir.join("execution_trace.json");
    write_json(&compiled_path, &execution.compiled)?;
    write_json(&proof_path, &artifact)?;
    write_json(
        &execution_trace_path,
        &json!({
            "artifact_metadata": artifact.metadata.clone(),
            "runtime_outputs": execution.result.outputs,
            "security": execution.result.security,
            "model_integrity": execution.result.model_integrity,
            "swarm": execution.result.swarm,
            "duration_ms": started.elapsed().as_millis(),
        }),
    )?;

    let proof_relative = format!("proofs/{APP_ID}/{slug}/{timestamp}/proof.json");
    cloudfs
        .write_json(&proof_relative, &artifact)
        .map_err(|error| error.to_string())?;
    persistent_writes.push(proof_relative.clone());

    let trace_relative = format!("traces/{APP_ID}/{slug}/{timestamp}/execution_trace.json");
    cloudfs
        .write_json(
            &trace_relative,
            &json!({
                "compiled_backend": execution.compiled.backend,
                "runtime_gpu_busy_ratio": artifact.metadata.get("runtime_gpu_stage_busy_ratio"),
                "runtime_stage_breakdown": artifact.metadata.get("runtime_stage_breakdown"),
                "gpu_nodes": artifact.metadata.get("gpu_nodes"),
                "cpu_nodes": artifact.metadata.get("cpu_nodes"),
                "proof_sha256": sha256_hex(&artifact.proof),
            }),
        )
        .map_err(|error| error.to_string())?;
    persistent_writes.push(trace_relative.clone());

    let mut wrapped_proof_path = None;
    let mut wrapped_verified = None;
    let mut wrapped_proof_sha256 = None;
    let mut wrapped_status = None;
    let mut wrapped_strategy = None;
    let mut wrapped_trust_model = None;
    let mut icloud_wrapped_proof_path = None;
    if wrap_request.enabled() {
        let registry = default_wrapper_registry();
        let wrapper = registry
            .find(artifact.backend, BackendKind::ArkworksGroth16)
            .ok_or_else(|| {
                format!("no wrapper registered for {} -> arkworks-groth16", artifact.backend)
            })?;
        let direct_policy = WrapperExecutionPolicy {
            honor_env_overrides: false,
            allow_large_direct_materialization: true,
            force_mode: wrap_request.force_mode(),
        };
        if let Some(preview) = wrapper
            .preview_wrap_with_policy(&artifact, &execution.compiled, direct_policy)
            .map_err(|error| error.to_string())?
        {
            if !wrap_request.allow_attestation && preview.trust_model != "cryptographic" {
                return Err(format!(
                    "strict cryptographic wrap for {slug} is unavailable: preview trust_model={}",
                    preview.trust_model
                ));
            }
            if !wrap_request.allow_attestation
                && let (Some(estimated_memory_bytes), Some(memory_budget_bytes)) =
                (preview.estimated_memory_bytes, preview.memory_budget_bytes)
                && estimated_memory_bytes > memory_budget_bytes
            {
                let detail = preview
                    .reason
                    .clone()
                    .unwrap_or_else(|| "direct FRI wrap exceeds the detected runtime budget".to_string());
                return Err(format!(
                    "strict cryptographic wrap for {slug} is blocked: direct-fri-v2 estimated_memory_bytes={} exceeds memory_budget_bytes={}; attestation fallback is forbidden; {}",
                    estimated_memory_bytes, memory_budget_bytes, detail
                ));
            }
            if preview.prepare_required == Some(true) {
                let report = wrapper
                    .prepare_wrap_cache_with_policy(&artifact, &execution.compiled, direct_policy)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| {
                        format!(
                            "strict cryptographic wrap for {slug} requires cache preparation, but the wrapper returned no preparation report"
                        )
                    })?;
                if report.blocked || !report.setup_cache_ready {
                    return Err(report.blocked_reason.unwrap_or_else(|| {
                        format!(
                            "strict cryptographic wrap cache preparation did not complete for {slug}"
                        )
                    }));
                }
            }
        }
        let mut wrapped = wrap_artifact_via_runtime(
            &artifact,
            &execution.compiled,
            wrap_request.trust_lane(),
            hardware_profile,
            wrap_request.force_mode(),
        )?;
        sign_artifact_proof_origin(&mut wrapped, proof_origin_signer)?;
        let verified_wrapped = wrapper
            .verify_wrapped(&wrapped)
            .map_err(|error| error.to_string())?;
        if !verified_wrapped {
            return Err(format!("wrapped proof verification failed for {slug}"));
        }
        verify_artifact_proof_origin(&wrapped)?;
        wrapped_status = wrapped.metadata.get("status").cloned();
        wrapped_strategy = wrapped.metadata.get("wrapper_strategy").cloned();
        wrapped_trust_model = wrapped.metadata.get("trust_model").cloned();
        let path = circuit_dir.join("wrapped_groth16.json");
        write_json(&path, &wrapped)?;
        wrapped_proof_sha256 = Some(sha256_hex(&wrapped.proof));
        wrapped_proof_path = Some(path);
        wrapped_verified = Some(true);
        let wrapped_relative = format!("proofs/{APP_ID}/{slug}/{timestamp}/wrapped_groth16.json");
        cloudfs
            .write_json(&wrapped_relative, &wrapped)
            .map_err(|error| error.to_string())?;
        persistent_writes.push(wrapped_relative.clone());
        icloud_wrapped_proof_path = Some(
            cloudfs
                .persistent_root()
                .join(&wrapped_relative)
                .display()
                .to_string(),
        );
    }

    let public_outputs = public_outputs_for_circuit(circuit_id, &artifact)?;
    let bundle = SovereignEconomicDefenseCircuitBundleV1 {
        circuit_id,
        circuit_name: slug.replace('-', " "),
        slug: slug.to_string(),
        backend: backend.as_str().to_string(),
        audited: audit.summary.failed == 0,
        verified,
        wrapped_verified,
        proof_origin_verified: true,
        compiled_path: compiled_path.display().to_string(),
        proof_path: proof_path.display().to_string(),
        audit_path: audit_path.display().to_string(),
        execution_trace_path: execution_trace_path.display().to_string(),
        wrapped_proof_path: wrapped_proof_path
            .as_ref()
            .map(|path| path.display().to_string()),
        wrapped_status,
        wrapped_strategy,
        wrapped_trust_model,
        public_outputs,
        proof_sha256: sha256_hex(&artifact.proof),
        wrapped_proof_sha256,
        runtime_gpu_busy_ratio: artifact
            .metadata
            .get("runtime_gpu_stage_busy_ratio")
            .and_then(|value| value.parse::<f64>().ok()),
        used_metal: artifact
            .metadata
            .get("gpu_nodes")
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0),
        icloud_proof_path: Some(cloudfs.persistent_root().join(&proof_relative).display().to_string()),
        icloud_wrapped_proof_path,
        icloud_trace_path: Some(cloudfs.persistent_root().join(&trace_relative).display().to_string()),
    };

    Ok(CircuitExecutionOutcome {
        bundle,
        proof_artifact: artifact,
    })
}

fn ensure_fail_closed_audit(program: &Program, backend: BackendKind) -> Result<AuditReport, String> {
    let report = audit_program_default(program, Some(backend));
    if report.summary.failed > 0 {
        return Err(format!(
            "audit failed for '{}' on backend {} (failed_checks={})",
            program.name, backend, report.summary.failed
        ));
    }
    Ok(report)
}

fn prove_with_runtime(
    backend: BackendKind,
    program: Program,
    witness: Witness,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
) -> Result<zkf_runtime::BackendProofExecutionResult, String> {
    let groth16_setup_blob_override = groth16_setup_blob.map(|path| path.display().to_string());
    with_allow_dev_deterministic_groth16_override(
        allow_dev_deterministic_groth16.then_some(true),
        || {
            with_groth16_setup_blob_path_override(groth16_setup_blob_override.clone(), || {
                RuntimeExecutor::run_backend_prove_job_with_objective(
                    backend,
                    BackendRoute::Auto,
                    Arc::new(program),
                    None,
                    Some(Arc::new(witness)),
                    None,
                    OptimizationObjective::FastestProve,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                )
                .map_err(|error| error.to_string())
            })
        },
    )
}

fn public_outputs_for_circuit(
    circuit_id: u8,
    artifact: &ProofArtifact,
) -> Result<BTreeMap<String, String>, String> {
    let mut outputs = BTreeMap::new();
    match circuit_id {
        1 => {
            expect_public_inputs_len(artifact, 2, circuit_id)?;
            outputs.insert(
                "cta_treasury_commitment".to_string(),
                artifact.public_inputs[0].to_decimal_string(),
            );
            outputs.insert(
                "cta_compliance_bit".to_string(),
                artifact.public_inputs[1].to_decimal_string(),
            );
        }
        2 => {
            expect_public_inputs_len(artifact, 2, circuit_id)?;
            outputs.insert(
                "clt_governance_commitment".to_string(),
                artifact.public_inputs[0].to_decimal_string(),
            );
            outputs.insert(
                "clt_compliance_bit".to_string(),
                artifact.public_inputs[1].to_decimal_string(),
            );
        }
        3 => {
            expect_public_inputs_len(artifact, 2, circuit_id)?;
            outputs.insert(
                "aes_evaluation_commitment".to_string(),
                artifact.public_inputs[0].to_decimal_string(),
            );
            outputs.insert(
                "aes_predatory_bit".to_string(),
                artifact.public_inputs[1].to_decimal_string(),
            );
        }
        4 => {
            expect_public_inputs_len(artifact, 2, circuit_id)?;
            outputs.insert(
                "wta_portfolio_commitment".to_string(),
                artifact.public_inputs[0].to_decimal_string(),
            );
            outputs.insert(
                "wta_compliance_bit".to_string(),
                artifact.public_inputs[1].to_decimal_string(),
            );
        }
        5 => {
            expect_public_inputs_len(artifact, 3, circuit_id)?;
            outputs.insert(
                "rss_mission_commitment".to_string(),
                artifact.public_inputs[0].to_decimal_string(),
            );
            outputs.insert(
                "rss_overall_compliance_bit".to_string(),
                artifact.public_inputs[1].to_decimal_string(),
            );
            outputs.insert(
                "rss_summary_commitment".to_string(),
                artifact.public_inputs[2].to_decimal_string(),
            );
        }
        other => {
            return Err(format!("unknown circuit id {other}"));
        }
    }
    Ok(outputs)
}

fn expect_public_inputs_len(
    artifact: &ProofArtifact,
    expected: usize,
    circuit_id: u8,
) -> Result<(), String> {
    if artifact.public_inputs.len() != expected {
        return Err(format!(
            "circuit {circuit_id} expected {expected} public outputs, found {}",
            artifact.public_inputs.len()
        ));
    }
    Ok(())
}

fn resolved_recirculation_request(
    original: &RecirculationSovereigntyScoreRequestV1,
    circuits: &[SovereignEconomicDefenseCircuitBundleV1],
) -> Result<RecirculationSovereigntyScoreRequestV1, String> {
    let mut commitment_map = BTreeMap::new();
    let mut bit_map = BTreeMap::new();
    for circuit in circuits {
        match circuit.circuit_id {
            1 => {
                commitment_map.insert(
                    0usize,
                    circuit
                        .public_outputs
                        .get("cta_treasury_commitment")
                        .cloned()
                        .ok_or_else(|| "missing circuit 1 commitment".to_string())?,
                );
                bit_map.insert(
                    0usize,
                    circuit
                        .public_outputs
                        .get("cta_compliance_bit")
                        .is_some_and(|value| value == "1"),
                );
            }
            2 => {
                commitment_map.insert(
                    1usize,
                    circuit
                        .public_outputs
                        .get("clt_governance_commitment")
                        .cloned()
                        .ok_or_else(|| "missing circuit 2 commitment".to_string())?,
                );
                bit_map.insert(
                    1usize,
                    circuit
                        .public_outputs
                        .get("clt_compliance_bit")
                        .is_some_and(|value| value == "1"),
                );
            }
            3 => {
                commitment_map.insert(
                    2usize,
                    circuit
                        .public_outputs
                        .get("aes_evaluation_commitment")
                        .cloned()
                        .ok_or_else(|| "missing circuit 3 commitment".to_string())?,
                );
                bit_map.insert(
                    2usize,
                    circuit
                        .public_outputs
                        .get("aes_predatory_bit")
                        .is_some_and(|value| value == "1"),
                );
            }
            4 => {
                commitment_map.insert(
                    3usize,
                    circuit
                        .public_outputs
                        .get("wta_portfolio_commitment")
                        .cloned()
                        .ok_or_else(|| "missing circuit 4 commitment".to_string())?,
                );
                bit_map.insert(
                    3usize,
                    circuit
                        .public_outputs
                        .get("wta_compliance_bit")
                        .is_some_and(|value| value == "1"),
                );
            }
            _ => {}
        }
    }
    let mut resolved = original.clone();
    if commitment_map.len() == 4 {
        resolved.circuit_commitments = [
            commitment_map.get(&0).cloned().unwrap_or_default(),
            commitment_map.get(&1).cloned().unwrap_or_default(),
            commitment_map.get(&2).cloned().unwrap_or_default(),
            commitment_map.get(&3).cloned().unwrap_or_default(),
        ];
        resolved.circuit_status_bits = [
            *bit_map.get(&0).unwrap_or(&false),
            *bit_map.get(&1).unwrap_or(&false),
            *bit_map.get(&2).unwrap_or(&false),
            *bit_map.get(&3).unwrap_or(&false),
        ];
    }
    Ok(resolved)
}

fn issue_credentials(
    bundle_root: &Path,
    run_id: &str,
    hardware_profile: HardwareProfile,
    issued_at_unix: u64,
    artifact_digests: &[String],
    signer: &HybridSignerMaterial,
) -> Result<Vec<String>, String> {
    let credentials_dir = bundle_root.join("11_credentials");
    fs::create_dir_all(&credentials_dir)
        .map_err(|error| format!("failed to create {}: {error}", credentials_dir.display()))?;
    let expires_at_unix = issued_at_unix.saturating_add(365 * 24 * 60 * 60);
    let mut paths = Vec::new();
    for (credential_type, subject) in [
        ("membership", run_id.to_string()),
        ("proving-station", hardware_profile.as_str().to_string()),
        ("compliance", format!("sovereign-economic-defense:{run_id}")),
    ] {
        let claims = SovereignEconomicDefenseCredentialClaimsV1 {
            version: 1,
            schema: "zkf-sovereign-economic-defense-credential-v1".to_string(),
            credential_type: credential_type.to_string(),
            subject,
            run_id: run_id.to_string(),
            issued_at_unix,
            expires_at_unix,
            trust_lane: "strict-cryptographic".to_string(),
            artifact_digests: artifact_digests.to_vec(),
            metadata: BTreeMap::from([
                ("application".to_string(), APP_ID.to_string()),
                ("hardware_profile".to_string(), hardware_profile.as_str().to_string()),
            ]),
        };
        let signature = signer.sign_message(&claims.canonical_bytes()?, CREDENTIAL_CONTEXT)?;
        let signed = SignedSovereignEconomicDefenseCredentialV1 {
            claims,
            issuer_public_keys: signer.public_key_bundle(),
            issuer_signature_bundle: signature,
        };
        let path = credentials_dir.join(format!("{credential_type}.json"));
        write_json(&path, &signed)?;
        paths.push(path.display().to_string());
    }
    Ok(paths)
}

fn verify_credential(credential: &SignedSovereignEconomicDefenseCredentialV1) -> Result<(), String> {
    let bytes = credential.claims.canonical_bytes()?;
    if !verify_bundle(
        &credential.issuer_public_keys,
        &bytes,
        &credential.issuer_signature_bundle,
        CREDENTIAL_CONTEXT,
    ) {
        return Err(format!(
            "credential '{}' failed hybrid signature verification",
            credential.claims.credential_type
        ));
    }
    Ok(())
}

fn sign_artifact_proof_origin(
    artifact: &mut ProofArtifact,
    signer: &HybridSignerMaterial,
) -> Result<(), String> {
    let proof_hash = Sha384::digest(&artifact.proof);
    artifact.proof_origin_signature =
        Some(signer.sign_message(proof_hash.as_slice(), PROOF_ORIGIN_CONTEXT)?);
    artifact.proof_origin_public_keys = Some(signer.public_key_bundle());
    Ok(())
}

fn verify_artifact_proof_origin(artifact: &ProofArtifact) -> Result<(), String> {
    let Some(public_keys) = artifact.proof_origin_public_keys.as_ref() else {
        return Err("proof artifact is missing proof-origin public keys".to_string());
    };
    let Some(signature) = artifact.proof_origin_signature.as_ref() else {
        return Err("proof artifact is missing proof-origin signature".to_string());
    };
    let proof_hash = Sha384::digest(&artifact.proof);
    if !verify_bundle(public_keys, proof_hash.as_slice(), signature, PROOF_ORIGIN_CONTEXT) {
        return Err("proof-origin signature verification failed".to_string());
    }
    Ok(())
}

fn load_or_create_hybrid_signer(
    manager: &KeyManager,
    id_prefix: &str,
    ed25519_service: &str,
    ml_dsa_signing_service: &str,
    ml_dsa_public_service: &str,
) -> Result<HybridSignerMaterial, String> {
    let ed25519_id = format!("{id_prefix}-ed25519");
    let ml_dsa_signing_id = format!("{id_prefix}-mldsa87-signing");
    let ml_dsa_public_id = format!("{id_prefix}-mldsa87-public");
    let existing = (
        manager.retrieve_key(&ed25519_id, ed25519_service),
        manager.retrieve_key(&ml_dsa_signing_id, ml_dsa_signing_service),
        manager.retrieve_key(&ml_dsa_public_id, ml_dsa_public_service),
    );
    if let (Ok(ed25519), Ok(ml_dsa_signing), Ok(ml_dsa_public)) = existing {
        let ed25519_seed: [u8; 32] = ed25519
            .try_into()
            .map_err(|_| format!("stored key '{}' has invalid length", ed25519_id))?;
        let signer = HybridSignerMaterial {
            ed25519_seed,
            ml_dsa87_signing_key: ml_dsa_signing,
            ml_dsa87_public_key: ml_dsa_public,
        };
        signer.validate()?;
        return Ok(signer);
    }

    let mut ed25519_seed = [0u8; 32];
    zkf_core::secure_random::secure_random_bytes(&mut ed25519_seed)
        .map_err(|error| error.to_string())?;
    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    manager
        .store_key(&ed25519_id, ed25519_service, &ed25519_seed)
        .map_err(|error| error.to_string())?;
    manager
        .store_key(
            &ml_dsa_signing_id,
            ml_dsa_signing_service,
            keypair.signing_key.as_slice(),
        )
        .map_err(|error| error.to_string())?;
    manager
        .store_key(
            &ml_dsa_public_id,
            ml_dsa_public_service,
            keypair.verification_key.as_slice(),
        )
        .map_err(|error| error.to_string())?;
    Ok(HybridSignerMaterial {
        ed25519_seed,
        ml_dsa87_signing_key: keypair.signing_key.as_slice().to_vec(),
        ml_dsa87_public_key: keypair.verification_key.as_slice().to_vec(),
    })
}

struct SolidityVerifierBundle {
    path: PathBuf,
    source: String,
    contract_name: String,
    target: EvmTarget,
    estimated_verify_gas: Option<u64>,
    source_circuit_id: u8,
    source_circuit_slug: String,
    source_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolidityVerifierReportV1 {
    contract_name: String,
    path: String,
    evm_target: String,
    estimated_verify_gas: Option<u64>,
    source_circuit_id: Option<u8>,
    source_circuit_slug: Option<String>,
    source_backend: Option<String>,
}

fn build_solidity_verifier(
    bundle_root: &Path,
    source_circuit_id: u8,
    source_circuit_slug: &str,
    proof_artifact: &ProofArtifact,
    evm_target: EvmTarget,
) -> Result<SolidityVerifierBundle, String> {
    let contract_name = "AntiExtractionShieldVerifier";
    let path = bundle_root.join("15_solidity/AntiExtractionShieldVerifier.sol");
    let source =
        render_groth16_solidity_verifier_for_target(proof_artifact, contract_name, evm_target);
    write_text(&path, &source)?;
    Ok(SolidityVerifierBundle {
        path,
        source,
        contract_name: contract_name.to_string(),
        target: evm_target,
        estimated_verify_gas: Some(estimate_groth16_verify_gas(evm_target)),
        source_circuit_id,
        source_circuit_slug: source_circuit_slug.to_string(),
        source_backend: BackendKind::ArkworksGroth16.as_str().to_string(),
    })
}

fn estimate_groth16_verify_gas(target: EvmTarget) -> u64 {
    let base = 210_000u64;
    match target {
        EvmTarget::Ethereum => base,
        EvmTarget::OptimismArbitrumL2 => base.saturating_mul(86) / 100,
        EvmTarget::GenericEvm => base.saturating_mul(95) / 100,
    }
}

fn render_report_markdown(
    report: &SovereignEconomicDefenseMissionReportV1,
    circuits: &[SovereignEconomicDefenseCircuitBundleV1],
    verifier: Option<&SolidityVerifierBundle>,
) -> String {
    let mut lines = vec![
        "# Sovereign Economic Defense Report".to_string(),
        String::new(),
        format!("- Run ID: `{}`", report.run_id),
        format!("- Timestamp: `{}`", report.timestamp),
        format!("- Hardware profile: `{}`", report.hardware_profile),
        format!(
            "- Storage mode: `{}`",
            report.storage.storage_mode
        ),
        String::new(),
        "## Circuit Results".to_string(),
    ];
    for circuit in circuits {
        let wrap_status = match (
            circuit.wrapped_verified,
            circuit.wrapped_proof_path.as_ref(),
            circuit.backend.as_str(),
        ) {
            (Some(value), _, _) => value.to_string(),
            (None, None, backend) if backend == BackendKind::Plonky3.as_str() => {
                "omitted (repo-constrained; STARK proof is primary)".to_string()
            }
            _ => "n/a".to_string(),
        };
        lines.push(format!(
            "- Circuit {} (`{}`): backend=`{}`, verified=`{}`, wrapped_verified=`{}`",
            circuit.circuit_id,
            circuit.slug,
            circuit.backend,
            circuit.verified,
            wrap_status
        ));
        lines.push(format!(
            "  public_outputs={}",
            serde_json::to_string(&circuit.public_outputs).unwrap_or_else(|_| "{}".to_string())
        ));
        if let Some(path) = circuit.wrapped_proof_path.as_ref() {
            lines.push(format!(
                "  wrapped_path=`{}` status=`{}` strategy=`{}` trust_model=`{}`",
                path,
                circuit
                    .wrapped_status
                    .as_deref()
                    .unwrap_or("unknown"),
                circuit
                    .wrapped_strategy
                    .as_deref()
                    .unwrap_or("unknown"),
                circuit
                    .wrapped_trust_model
                    .as_deref()
                    .unwrap_or("unknown"),
            ));
            if let Some(icloud_path) = circuit.icloud_wrapped_proof_path.as_ref() {
                lines.push(format!("  icloud_wrapped_path=`{icloud_path}`"));
            }
        }
    }
    lines.push(String::new());
    lines.push("## Honesty Notes".to_string());
    for note in &report.honesty_notes {
        lines.push(format!("- {note}"));
    }
    if let Some(verifier) = verifier {
        lines.push(String::new());
        lines.push("## Solidity".to_string());
        lines.push(format!(
            "- Verifier: `{}` target=`{}` estimated_verify_gas=`{}`",
            verifier.path.display(),
            verifier.target.as_str(),
            verifier
                .estimated_verify_gas
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        lines.push(format!(
            "- Source circuit: {} (`{}`) backend=`{}` contract=`{}`",
            verifier.source_circuit_id,
            verifier.source_circuit_slug,
            verifier.source_backend,
            verifier.contract_name,
        ));
    }
    lines.join("\n")
}

fn mission_honesty_notes(
    circuits: &[SovereignEconomicDefenseCircuitBundleV1],
) -> Vec<String> {
    let attestation_wrapped = circuits
        .iter()
        .filter_map(|circuit| circuit.wrapped_trust_model.as_deref().map(|model| (circuit, model)))
        .filter(|(_, model)| *model == "attestation")
        .map(|(circuit, _)| circuit.slug.clone())
        .collect::<Vec<_>>();

    let mut notes = vec![
        "Circuit 3 uses arkworks-groth16 on BN254; this backend is present in the workspace but still carries the upstream limited/production disclaimer surfaces in ZirOS truth data.".to_string(),
        format!(
            "Measured strict direct wrap boundary on this host: circuit 1 direct-fri-v2 preview estimated {} bytes against a {} byte memory budget, and sampled Arkworks constraint-matrix materialization reached approximately {} resident footprint before termination.",
            DIRECT_WRAP_ESTIMATED_MEMORY_BYTES,
            DIRECT_WRAP_MEMORY_BUDGET_BYTES,
            DIRECT_WRAP_OBSERVED_PHYSICAL_FOOTPRINT,
        ),
        "Witness material is kept off the persistent CloudFS tree and is restricted to the local cache root managed by ZirOS runtime storage.".to_string(),
    ];

    if attestation_wrapped.is_empty() {
        notes.insert(
            0,
            "Circuits 1, 2, 4, and 5 ship their Plonky3 STARK proofs as the primary deliverable for this app. No STARK-to-Groth16 wrapper artifact is emitted in the repo-constrained delivery lane.".to_string(),
        );
        notes.push(
            "Recursive STARK compression of the FRI accumulator before any Groth16 wrap remains the honest roadmap path (Nova/HyperNova-style folding). That compression lane is not implemented for this app bundle today.".to_string(),
        );
        notes.push(
            "Attestation-backed wrapper outputs remain forbidden for this app bundle and are not used to satisfy any wrapped-proof or Solidity-verifier claim.".to_string(),
        );
    } else {
        notes.insert(
            0,
            format!(
                "This bundle includes attestation-level wrapped-v3 Nova-compressed wrapper artifacts for: {}. Those artifacts bind a host-verified compressed Nova accumulator and do not constitute strict cryptographic FRI closure.",
                attestation_wrapped.join(", "),
            ),
        );
        notes.push(
            "The current Nova-compressed wrapper proves folding consistency in-circuit but leaves FRI Merkle authentication off-circuit; the outer Groth16 circuit binds the accumulator rather than verifying the compressed Nova proof in-circuit.".to_string(),
        );
        notes.push(
            "Circuit 3 remains the only native Groth16 theorem lane in this bundle, and the exported Solidity verifier is still generated from circuit 3.".to_string(),
        );
    }

    notes
}

fn load_verifier_bundle_for_report(
    manifest: &SovereignEconomicDefenseBundleManifestV1,
    mission_report: &SovereignEconomicDefenseMissionReportV1,
) -> Result<Option<SolidityVerifierBundle>, String> {
    let path = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
        .or(manifest.verifier_path.as_deref());
    let Some(path) = path else {
        return Ok(None);
    };
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path))?;
    let target = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("evm_target"))
        .and_then(Value::as_str)
        .map(|value| parse_evm_target(Some(value)))
        .transpose()?
        .unwrap_or(EvmTarget::Ethereum);
    let estimated_verify_gas = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("estimated_verify_gas"))
        .and_then(Value::as_u64);
    let contract_name = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("contract_name"))
        .and_then(Value::as_str)
        .unwrap_or("AntiExtractionShieldVerifier")
        .to_string();
    let source_circuit_id = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("source_circuit_id"))
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(3);
    let source_circuit_slug = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("source_circuit_slug"))
        .and_then(Value::as_str)
        .unwrap_or("anti-extraction-shield")
        .to_string();
    let source_backend = mission_report
        .verifier
        .as_ref()
        .and_then(|value| value.get("source_backend"))
        .and_then(Value::as_str)
        .unwrap_or(BackendKind::ArkworksGroth16.as_str())
        .to_string();
    Ok(Some(SolidityVerifierBundle {
        path: PathBuf::from(path),
        source,
        contract_name,
        target,
        estimated_verify_gas,
        source_circuit_id,
        source_circuit_slug,
        source_backend,
    }))
}

fn selector_includes(selector: SovereignEconomicDefenseCircuitSelector, circuit_id: u8) -> bool {
    matches!(
        (selector, circuit_id),
        (SovereignEconomicDefenseCircuitSelector::All, _)
            | (SovereignEconomicDefenseCircuitSelector::One, 1)
            | (SovereignEconomicDefenseCircuitSelector::Two, 2)
            | (SovereignEconomicDefenseCircuitSelector::Three, 3)
            | (SovereignEconomicDefenseCircuitSelector::Four, 4)
            | (SovereignEconomicDefenseCircuitSelector::Five, 5)
    )
}

fn selector_requires_dependencies(selector: SovereignEconomicDefenseCircuitSelector) -> bool {
    matches!(selector, SovereignEconomicDefenseCircuitSelector::All)
}

fn resolve_cli_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir()
        .map_err(|error| format!("failed to read current directory: {error}"))?;
    let joined = cwd.join(path);
    match joined.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(_) => Ok(joined),
    }
}

fn unix_now_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("failed to read system clock: {error}"))
}

fn run_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string()
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn copy_bundle_file(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::copy(source, destination).map_err(|error| {
        format!(
            "failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}
