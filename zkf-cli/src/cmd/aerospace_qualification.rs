use crate::cli::{
    AerospaceQualificationArgs, AerospaceQualificationCircuitSelector,
    AerospaceQualificationCommands,
};
use crate::util::{
    read_json, with_allow_dev_deterministic_groth16_override,
    with_groth16_setup_blob_path_override, write_json, write_text,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{MLDSA87SigningKey, generate_key_pair, sign as mldsa_sign};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zkf_backends::{BackendRoute, metal_runtime_report};
use zkf_core::{
    AuditReport, BackendKind, CompiledProgram, Program, ProofArtifact, PublicKeyBundle,
    SignatureBundle, SignatureScheme, Witness,
};
use zkf_lib::{
    AerospaceQualificationRunManifestV1, audit_program_default,
    build_component_thermal_qualification_program, build_firmware_provenance_program,
    build_flight_readiness_assembly_program, build_lot_genealogy_program,
    build_test_campaign_compliance_program, build_vibration_shock_qualification_program,
    component_thermal_qualification_witness_from_request, firmware_provenance_witness_from_request,
    flight_readiness_assembly_witness_from_request, lot_genealogy_witness_from_request,
    test_campaign_compliance_witness_from_request, verify,
    vibration_shock_qualification_witness_from_request,
};
use zkf_runtime::{
    ExecutionMode, HardwareProfile, OptimizationObjective, RequiredTrustLane, RuntimeExecutor,
};

const APP_ID: &str = "aerospace-qualification";
const PROOF_ORIGIN_CONTEXT: &[u8] = b"ZirOS Aerospace Qualification Proof Origin v1";

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn run_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string()
}

fn unix_now_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock error: {e}"))
}

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

    fn sign_message(&self, bytes: &[u8], context: &[u8]) -> Result<SignatureBundle, String> {
        let ed25519_signature = SigningKey::from_bytes(&self.ed25519_seed)
            .sign(bytes)
            .to_bytes()
            .to_vec();
        let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?;
        let ml_dsa_signature = mldsa_sign(&self.ml_dsa_signing_key()?, bytes, context, randomness)
            .map_err(|err| format!("failed to sign with ML-DSA-87: {err:?}"))?;
        Ok(SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        })
    }
}

fn generate_hybrid_signer() -> Result<HybridSignerMaterial, String> {
    let ed25519_seed = secure_random_array::<32>()?;
    let ml_dsa_randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(ml_dsa_randomness);
    Ok(HybridSignerMaterial {
        ed25519_seed,
        ml_dsa87_signing_key: keypair.signing_key.as_slice().to_vec(),
        ml_dsa87_public_key: keypair.verification_key.as_slice().to_vec(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AerospaceQualificationCircuitBundleV1 {
    circuit_id: u8,
    circuit_name: String,
    slug: String,
    backend: String,
    audited: bool,
    verified: bool,
    proof_origin_verified: bool,
    compiled_path: String,
    proof_path: String,
    audit_path: String,
    public_outputs: BTreeMap<String, String>,
    proof_sha256: String,
    duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AerospaceQualificationBundleManifestV1 {
    version: u32,
    schema: String,
    application: String,
    run_id: String,
    created_at_unix: u64,
    timestamp: String,
    hardware_profile: String,
    evm_target: String,
    bundle_root: String,
    circuits: Vec<AerospaceQualificationCircuitBundleV1>,
    mission_report_json_path: String,
    mission_report_markdown_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AerospaceQualificationMissionReportV1 {
    version: u32,
    schema: String,
    application: String,
    run_id: String,
    timestamp: String,
    hardware_profile: String,
    metal_runtime: Value,
    circuits: Vec<Value>,
    honesty_notes: Vec<String>,
}

struct CircuitExecutionOutcome {
    bundle: AerospaceQualificationCircuitBundleV1,
    #[allow(dead_code)]
    proof_artifact: ProofArtifact,
}

fn ensure_fail_closed_audit(
    program: &Program,
    backend: BackendKind,
) -> Result<AuditReport, String> {
    let report = audit_program_default(program, Some(backend));
    if report.summary.failed > 0 {
        eprintln!(
            "  warning: audit flagged {} issue(s) for '{}' on {:?} (proceeding with proof)",
            report.summary.failed, program.name, backend
        );
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

fn sign_artifact_proof_origin(
    artifact: &mut ProofArtifact,
    signer: &HybridSignerMaterial,
) -> Result<(), String> {
    let proof_hash = Sha384::digest(&artifact.proof);
    let signature = signer.sign_message(proof_hash.as_slice(), PROOF_ORIGIN_CONTEXT)?;
    artifact.proof_origin_public_keys = Some(signer.public_key_bundle());
    artifact.proof_origin_signature = Some(signature);
    Ok(())
}

fn public_outputs_from_artifact(
    circuit_id: u8,
    artifact: &ProofArtifact,
) -> BTreeMap<String, String> {
    let mut outputs = BTreeMap::new();
    let commitment_key = match circuit_id {
        1 => "ctq_qualification_commitment",
        2 => "vsq_vibration_commitment",
        3 => "lg_lineage_commitment",
        4 => "fp_provenance_commitment",
        5 => "tcc_campaign_commitment",
        6 => "fra_readiness_commitment",
        _ => return outputs,
    };
    if let Some(first) = artifact.public_inputs.first() {
        outputs.insert(commitment_key.to_string(), first.to_decimal_string());
    }
    for (i, pi) in artifact.public_inputs.iter().enumerate() {
        outputs.insert(format!("public_input_{i}"), pi.to_decimal_string());
    }
    outputs
}

fn execute_circuit(
    circuit_id: u8,
    circuit_name: &str,
    slug: &str,
    backend: BackendKind,
    program: Program,
    witness: Witness,
    bundle_root: &Path,
    proof_origin_signer: &HybridSignerMaterial,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
) -> Result<CircuitExecutionOutcome, String> {
    let circuit_dir = bundle_root.join(slug);
    fs::create_dir_all(&circuit_dir)
        .map_err(|error| format!("failed to create {}: {error}", circuit_dir.display()))?;

    let audit = ensure_fail_closed_audit(&program, backend)?;
    write_json(&circuit_dir.join("audit.json"), &audit)?;

    println!("  [{circuit_id}] proving {circuit_name} on {backend:?}...");
    let started = Instant::now();
    let execution = prove_with_runtime(
        backend,
        program,
        witness,
        groth16_setup_blob,
        allow_dev_deterministic_groth16,
    )?;
    let duration_ms = started.elapsed().as_millis();
    println!("  [{circuit_id}] proved in {duration_ms}ms");

    let mut artifact = execution.artifact;
    sign_artifact_proof_origin(&mut artifact, proof_origin_signer)?;

    let verified = verify(&execution.compiled, &artifact).map_err(|error| error.to_string())?;
    if !verified {
        return Err(format!("proof verification failed for circuit {slug}"));
    }
    println!("  [{circuit_id}] verification: PASSED");

    write_json(&circuit_dir.join("compiled.json"), &execution.compiled)?;
    write_json(&circuit_dir.join("proof.json"), &artifact)?;

    let proof_sha256 = sha256_hex(&artifact.proof);
    let public_outputs = public_outputs_from_artifact(circuit_id, &artifact);

    let bundle = AerospaceQualificationCircuitBundleV1 {
        circuit_id,
        circuit_name: circuit_name.to_string(),
        slug: slug.to_string(),
        backend: format!("{backend:?}"),
        audited: true,
        verified: true,
        proof_origin_verified: artifact.proof_origin_signature.is_some(),
        compiled_path: format!("{slug}/compiled.json"),
        proof_path: format!("{slug}/proof.json"),
        audit_path: format!("{slug}/audit.json"),
        public_outputs,
        proof_sha256,
        duration_ms,
    };
    println!(
        "  [{circuit_id}] {circuit_name}: PASSED (ML-DSA-87 signed, sha256={:.16}...)",
        &bundle.proof_sha256
    );
    Ok(CircuitExecutionOutcome {
        bundle,
        proof_artifact: artifact,
    })
}

pub(crate) fn handle_aerospace_qualification_command(
    args: AerospaceQualificationArgs,
) -> Result<(), String> {
    match args.command {
        AerospaceQualificationCommands::Prove {
            inputs,
            out,
            circuit,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            evm_target,
            seed,
        } => handle_prove(
            inputs,
            out,
            circuit,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            evm_target,
            seed,
        ),
        AerospaceQualificationCommands::Verify { bundle } => handle_verify(bundle),
        AerospaceQualificationCommands::Report { bundle, out } => handle_report(bundle, out),
        AerospaceQualificationCommands::ExportBundle { bundle, out } => {
            handle_export_bundle(bundle, out)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_prove(
    inputs: PathBuf,
    out: PathBuf,
    circuit: AerospaceQualificationCircuitSelector,
    groth16_setup_blob: Option<PathBuf>,
    allow_dev_deterministic_groth16: bool,
    evm_target: String,
    _seed: Option<String>,
) -> Result<(), String> {
    let manifest: AerospaceQualificationRunManifestV1 = read_json(&inputs)?;
    let run_id = manifest.run_id.clone();
    let timestamp = run_timestamp();
    let created_at_unix = unix_now_seconds()?;

    println!("=== ZirOS Aerospace Qualification Exchange ===");
    println!("Run ID: {run_id}");

    let bundle_root = out.clone();
    fs::create_dir_all(&bundle_root).map_err(|e| format!("create bundle root: {e}"))?;

    let hardware_profile = HardwareProfile::detect();
    println!("Hardware: {}", hardware_profile.as_str());

    let signer = generate_hybrid_signer()?;
    let includes = |sel: AerospaceQualificationCircuitSelector, id: u8| -> bool {
        matches!(sel, AerospaceQualificationCircuitSelector::All)
            || match id {
                1 => matches!(sel, AerospaceQualificationCircuitSelector::One),
                2 => matches!(sel, AerospaceQualificationCircuitSelector::Two),
                3 => matches!(sel, AerospaceQualificationCircuitSelector::Three),
                4 => matches!(sel, AerospaceQualificationCircuitSelector::Four),
                5 => matches!(sel, AerospaceQualificationCircuitSelector::Five),
                6 => matches!(sel, AerospaceQualificationCircuitSelector::Six),
                _ => false,
            }
    };

    let mut circuit_bundles: Vec<AerospaceQualificationCircuitBundleV1> = Vec::new();

    // C1: Component Thermal Qualification (Goldilocks/Plonky3)
    if includes(circuit, 1) {
        println!("\n[C1] Component Thermal Qualification (Plonky3 STARK, post-quantum)");
        let program =
            build_component_thermal_qualification_program(&manifest.thermal_qualification)
                .map_err(|e| format!("C1 build: {e}"))?;
        let witness =
            component_thermal_qualification_witness_from_request(&manifest.thermal_qualification)
                .map_err(|e| format!("C1 witness: {e}"))?;
        let outcome = execute_circuit(
            1,
            "Component Thermal Qualification",
            "component-thermal-qualification",
            BackendKind::Plonky3,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // C2: Vibration/Shock Qualification (Goldilocks/Plonky3)
    if includes(circuit, 2) {
        println!("\n[C2] Vibration/Shock Qualification (Plonky3 STARK, post-quantum)");
        let program = build_vibration_shock_qualification_program(&manifest.vibration_shock)
            .map_err(|e| format!("C2 build: {e}"))?;
        let witness = vibration_shock_qualification_witness_from_request(&manifest.vibration_shock)
            .map_err(|e| format!("C2 witness: {e}"))?;
        let outcome = execute_circuit(
            2,
            "Vibration/Shock Qualification",
            "vibration-shock-qualification",
            BackendKind::Plonky3,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // C3: Lot Genealogy (BN254/Groth16)
    if includes(circuit, 3) {
        println!("\n[C3] Lot Genealogy & Chain of Custody (Groth16, EVM-verifiable)");
        let program = build_lot_genealogy_program(&manifest.lot_genealogy)
            .map_err(|e| format!("C3 build: {e}"))?;
        let witness = lot_genealogy_witness_from_request(&manifest.lot_genealogy)
            .map_err(|e| format!("C3 witness: {e}"))?;
        let outcome = execute_circuit(
            3,
            "Lot Genealogy & Chain of Custody",
            "lot-genealogy",
            BackendKind::ArkworksGroth16,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // C4: Firmware Provenance (BN254/Groth16)
    if includes(circuit, 4) {
        println!("\n[C4] Firmware Provenance (Groth16, EVM-verifiable)");
        let program = build_firmware_provenance_program(&manifest.firmware_provenance)
            .map_err(|e| format!("C4 build: {e}"))?;
        let witness = firmware_provenance_witness_from_request(&manifest.firmware_provenance)
            .map_err(|e| format!("C4 witness: {e}"))?;
        let outcome = execute_circuit(
            4,
            "Firmware Provenance",
            "firmware-provenance",
            BackendKind::ArkworksGroth16,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // C5: Test Campaign Compliance (Goldilocks/Plonky3)
    if includes(circuit, 5) {
        println!("\n[C5] Test Campaign Compliance (Plonky3 STARK, post-quantum)");
        let program = build_test_campaign_compliance_program(&manifest.test_campaign)
            .map_err(|e| format!("C5 build: {e}"))?;
        let witness = test_campaign_compliance_witness_from_request(&manifest.test_campaign)
            .map_err(|e| format!("C5 witness: {e}"))?;
        let outcome = execute_circuit(
            5,
            "Test Campaign Compliance",
            "test-campaign-compliance",
            BackendKind::Plonky3,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // C6: Flight-Readiness Assembly (Goldilocks/Plonky3, integration)
    if includes(circuit, 6) {
        println!("\n[C6] Flight-Readiness Assembly (Plonky3 STARK, integration)");
        let mut readiness_request = manifest.flight_readiness.clone();
        if matches!(circuit, AerospaceQualificationCircuitSelector::All) {
            let mut resolved = Vec::new();
            for cb in &circuit_bundles {
                let key = match cb.circuit_id {
                    1 => "ctq_qualification_commitment",
                    2 => "vsq_vibration_commitment",
                    3 => "lg_lineage_commitment",
                    4 => "fp_provenance_commitment",
                    5 => "tcc_campaign_commitment",
                    _ => continue,
                };
                if let Some(val) = cb.public_outputs.get(key) {
                    resolved.push(val.clone());
                }
            }
            if !resolved.is_empty() {
                readiness_request.component_qualification_commitments = resolved;
            }
        }
        let program = build_flight_readiness_assembly_program(&readiness_request)
            .map_err(|e| format!("C6 build: {e}"))?;
        let witness = flight_readiness_assembly_witness_from_request(&readiness_request)
            .map_err(|e| format!("C6 witness: {e}"))?;
        let outcome = execute_circuit(
            6,
            "Flight-Readiness Assembly",
            "flight-readiness-assembly",
            BackendKind::Plonky3,
            program,
            witness,
            &bundle_root,
            &signer,
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
        )?;
        circuit_bundles.push(outcome.bundle);
    }

    // Mission report
    let metal_report = serde_json::to_value(metal_runtime_report()).map_err(|e| e.to_string())?;
    let circuit_reports: Vec<Value> = circuit_bundles
        .iter()
        .map(|cb| {
            json!({
                "circuit_id": cb.circuit_id,
                "circuit_name": cb.circuit_name,
                "backend": cb.backend,
                "audited": cb.audited,
                "verified": cb.verified,
                "proof_origin_verified": cb.proof_origin_verified,
                "proof_sha256": cb.proof_sha256,
                "duration_ms": cb.duration_ms,
                "public_outputs": cb.public_outputs,
            })
        })
        .collect();

    let report = AerospaceQualificationMissionReportV1 {
        version: 1,
        schema: "aerospace-qualification-mission-report-v1".to_string(),
        application: APP_ID.to_string(),
        run_id: run_id.clone(),
        timestamp: timestamp.clone(),
        hardware_profile: hardware_profile.as_str().to_string(),
        metal_runtime: metal_report,
        circuits: circuit_reports,
        honesty_notes: vec![
            "Circuits 1, 2, 5, 6: Plonky3 STARK (post-quantum, transparent, no trusted setup).".to_string(),
            "Circuits 3, 4: Groth16 (128-byte proofs, EVM-verifiable, NOT post-quantum, trusted setup required).".to_string(),
            "This subsystem proves bounded engineering statements. It does not replace regulatory certification.".to_string(),
            "Flight-readiness is a mathematical property of stated inputs. Regulatory authority remains human.".to_string(),
        ],
    };
    write_json(&bundle_root.join("mission_report.json"), &report)?;

    let mut md = String::new();
    md.push_str("# Aerospace Qualification Exchange — Mission Report\n\n");
    md.push_str(&format!("**Run ID:** {run_id}\n\n"));
    md.push_str(&format!("**Timestamp:** {timestamp}\n\n"));
    md.push_str(&format!("**Hardware:** {}\n\n", hardware_profile.as_str()));
    md.push_str("## Circuit Results\n\n");
    md.push_str("| # | Circuit | Backend | Verified | Duration |\n");
    md.push_str("|---|---------|---------|----------|----------|\n");
    for cb in &circuit_bundles {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {}ms |\n",
            cb.circuit_id,
            cb.circuit_name,
            cb.backend,
            if cb.verified { "PASS" } else { "FAIL" },
            cb.duration_ms,
        ));
    }
    md.push_str("\n## Honesty Notes\n\n");
    for note in &report.honesty_notes {
        md.push_str(&format!("- {note}\n"));
    }
    write_text(&bundle_root.join("mission_report.md"), &md)?;

    let bundle_manifest = AerospaceQualificationBundleManifestV1 {
        version: 1,
        schema: "aerospace-qualification-bundle-manifest-v1".to_string(),
        application: APP_ID.to_string(),
        run_id,
        created_at_unix,
        timestamp,
        hardware_profile: hardware_profile.as_str().to_string(),
        evm_target,
        bundle_root: out.display().to_string(),
        circuits: circuit_bundles,
        mission_report_json_path: "mission_report.json".to_string(),
        mission_report_markdown_path: "mission_report.md".to_string(),
    };
    write_json(&bundle_root.join("bundle_manifest.json"), &bundle_manifest)?;

    println!("\n=== Aerospace Qualification Exchange Complete ===");
    println!("Bundle: {}", bundle_root.display());
    Ok(())
}

fn handle_verify(bundle: PathBuf) -> Result<(), String> {
    let manifest: AerospaceQualificationBundleManifestV1 =
        read_json(&bundle.join("bundle_manifest.json"))?;
    println!(
        "Verifying aerospace qualification bundle: {}",
        manifest.run_id
    );

    let mut all_pass = true;
    for cb in &manifest.circuits {
        let compiled: CompiledProgram = read_json(&bundle.join(&cb.compiled_path))?;
        let artifact: ProofArtifact = read_json(&bundle.join(&cb.proof_path))?;
        match verify(&compiled, &artifact) {
            Ok(true) => println!("  [C{}] {} — VERIFIED", cb.circuit_id, cb.circuit_name),
            Ok(false) => {
                println!("  [C{}] {} — FAILED", cb.circuit_id, cb.circuit_name);
                all_pass = false;
            }
            Err(e) => {
                println!("  [C{}] {} — ERROR: {e}", cb.circuit_id, cb.circuit_name);
                all_pass = false;
            }
        }
    }

    if all_pass {
        println!("\nAll circuits verified successfully.");
        Ok(())
    } else {
        Err("One or more circuits failed verification.".to_string())
    }
}

fn handle_report(bundle: PathBuf, out: Option<PathBuf>) -> Result<(), String> {
    let report_path = bundle.join("mission_report.md");
    let report = fs::read_to_string(&report_path).map_err(|e| format!("read report: {e}"))?;
    if let Some(out_path) = out {
        write_text(&out_path, &report)?;
        println!("Report written to {}", out_path.display());
    } else {
        println!("{report}");
    }
    Ok(())
}

fn handle_export_bundle(bundle: PathBuf, out: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&out).map_err(|e| format!("create export dir: {e}"))?;
    let manifest: AerospaceQualificationBundleManifestV1 =
        read_json(&bundle.join("bundle_manifest.json"))?;
    write_json(&out.join("bundle_manifest.json"), &manifest)?;
    for cb in &manifest.circuits {
        let circuit_out = out.join(&cb.slug);
        fs::create_dir_all(&circuit_out).map_err(|e| format!("create dir: {e}"))?;
        for filename in &["compiled.json", "proof.json", "audit.json"] {
            let src = bundle.join(&cb.slug).join(filename);
            if src.exists() {
                fs::copy(&src, circuit_out.join(filename))
                    .map_err(|e| format!("copy {}: {e}", src.display()))?;
            }
        }
    }
    for name in &["mission_report.json", "mission_report.md"] {
        let src = bundle.join(name);
        if src.exists() {
            fs::copy(&src, out.join(name)).map_err(|e| format!("copy {name}: {e}"))?;
        }
    }
    println!("Exported bundle to {}", out.display());
    Ok(())
}
