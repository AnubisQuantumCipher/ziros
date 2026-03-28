use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{
    BackendRoute, GROTH16_DETERMINISTIC_DEV_PROVENANCE,
    GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY, GROTH16_IMPORTED_SETUP_PROVENANCE,
    GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY, GROTH16_SETUP_PROVENANCE_METADATA_KEY,
    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY, prepare_witness_for_proving,
    requested_groth16_setup_blob_path,
};
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendKind, Program, Witness, WitnessInputs, check_constraints, json_from_slice,
    json_to_vec_pretty, optimize_program,
};
use zkf_lib::app::satellite::{
    PRIVATE_SATELLITE_DEFAULT_STEPS, PRIVATE_SATELLITE_PRIVATE_INPUTS,
    PRIVATE_SATELLITE_PUBLIC_INPUTS, PRIVATE_SATELLITE_PUBLIC_OUTPUTS,
    private_satellite_conjunction_showcase_with_steps,
    private_satellite_conjunction_witness_with_steps,
};
use zkf_lib::evidence::{
    archive_showcase_artifacts,
    collect_formal_evidence_for_generated_app, effective_gpu_attribution_summary,
    ensure_dir_exists, ensure_file_exists, ensure_foundry_layout, foundry_project_dir,
    generated_app_closure_bundle_summary, purge_showcase_witness_artifacts,
};
use zkf_lib::{
    ZkfError, ZkfResult, audit_program_with_live_capabilities, compile,
    export_groth16_solidity_verifier, verify,
};
use zkf_runtime::{
    BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
    RuntimeExecutor, SwarmConfig,
};

const SETUP_SEED: [u8; 32] = [0x31; 32];
const PROOF_SEED: [u8; 32] = [0x47; 32];
const STEPS_OVERRIDE_ENV: &str = "ZKF_PRIVATE_SATELLITE_STEPS_OVERRIDE";
const FULL_AUDIT_ENV: &str = "ZKF_PRIVATE_SATELLITE_FULL_AUDIT";

fn with_showcase_groth16_mode<T, F: FnOnce() -> ZkfResult<T>>(
    trusted_setup_used: bool,
    f: F,
) -> ZkfResult<T> {
    if trusted_setup_used {
        f()
    } else {
        with_allow_dev_deterministic_groth16_override(Some(true), f)
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Serialize)]
struct ProgramStats {
    signals: usize,
    constraints: usize,
    public_inputs: usize,
    public_outputs: usize,
    blackbox_constraints: usize,
}

fn stats(program: &Program) -> ProgramStats {
    ProgramStats {
        signals: program.signals.len(),
        constraints: program.constraints.len(),
        public_inputs: program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .count(),
        public_outputs: program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .count(),
        blackbox_constraints: program
            .constraints
            .iter()
            .filter(|constraint| matches!(constraint, zkf_core::Constraint::BlackBox { .. }))
            .count(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = json_to_vec_pretty(value).map_err(|error| {
        ZkfError::Serialization(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> ZkfResult<()> {
    fs::write(path, value)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn read_text(path: &Path) -> ZkfResult<String> {
    fs::read_to_string(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))
}

fn output_dir(steps: usize) -> PathBuf {
    env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(format!(
            "Desktop/ZirOS_Private_Satellite_Conjunction_2Spacecraft_{steps}Step"
        ))
    })
}

fn foundry_project_dir_for_bundle(out_dir: &Path) -> PathBuf {
    foundry_project_dir(out_dir)
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn integration_steps() -> ZkfResult<usize> {
    match env::var(STEPS_OVERRIDE_ENV) {
        Ok(raw) => {
            let steps = raw.parse::<usize>().map_err(|error| {
                ZkfError::Backend(format!("parse {STEPS_OVERRIDE_ENV}={raw:?}: {error}"))
            })?;
            if steps < 2 {
                return Err(ZkfError::Backend(
                    "satellite step override must be at least two for the internal regression helper"
                        .to_string(),
                ));
            }
            Ok(steps)
        }
        Err(env::VarError::NotPresent) => Ok(PRIVATE_SATELLITE_DEFAULT_STEPS),
        Err(error) => Err(ZkfError::Backend(format!(
            "read {STEPS_OVERRIDE_ENV}: {error}"
        ))),
    }
}

fn full_audit_requested() -> bool {
    env_flag(FULL_AUDIT_ENV)
}

fn ensure_foundry_layout_local(project_dir: &Path) -> ZkfResult<()> {
    ensure_foundry_layout(project_dir)
}

fn public_outputs(program: &Program, witness: &Witness) -> BTreeMap<String, String> {
    program
        .signals
        .iter()
        .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
        .filter_map(|signal| {
            witness
                .values
                .get(&signal.name)
                .map(|value| (signal.name.clone(), value.to_decimal_string()))
        })
        .collect()
}

fn stage_summary(
    report: &zkf_runtime::GraphExecutionReport,
    artifact_metadata: &BTreeMap<String, String>,
) -> serde_json::Value {
    let gpu_attribution = effective_gpu_attribution_summary(
        report.gpu_nodes,
        report.gpu_stage_busy_ratio(),
        artifact_metadata,
    );
    json!({
        "total_wall_time_ms": report.total_wall_time.as_secs_f64() * 1_000.0,
        "peak_memory_bytes": report.peak_memory_bytes,
        "gpu_nodes": report.gpu_nodes,
        "cpu_nodes": report.cpu_nodes,
        "delegated_nodes": report.delegated_nodes,
        "fallback_nodes": report.fallback_nodes,
        "gpu_busy_ratio": report.gpu_stage_busy_ratio(),
        "effective_gpu_attribution": gpu_attribution,
        "stage_breakdown": report.stage_breakdown(),
        "watchdog_alerts": report.watchdog_alerts,
    })
}

fn telemetry_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".zkf/telemetry")
}

fn telemetry_snapshot() -> BTreeSet<String> {
    let mut snapshot = BTreeSet::new();
    if let Ok(read_dir) = fs::read_dir(telemetry_dir()) {
        for entry in read_dir.flatten() {
            snapshot.insert(entry.path().display().to_string());
        }
    }
    snapshot
}

fn new_telemetry_paths(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after.difference(before).cloned().collect()
}

fn ccs_summary(compiled: &zkf_core::CompiledProgram) -> ZkfResult<serde_json::Value> {
    let ccs = CcsProgram::try_from_program(&compiled.program)?;
    Ok(json!({
        "program_name": ccs.name,
        "field": ccs.field.as_str(),
        "num_constraints": ccs.num_constraints,
        "num_variables": ccs.num_variables,
        "num_public": ccs.num_public,
        "num_matrices": ccs.num_matrices(),
        "num_terms": ccs.num_terms(),
        "degree": ccs.degree(),
        "matrix_nnz": ccs.matrices.iter().enumerate().map(|(index, matrix)| {
            json!({
                "index": index,
                "rows": matrix.rows,
                "cols": matrix.cols,
                "nnz": matrix.nnz(),
            })
        }).collect::<Vec<_>>(),
        "compiled_metadata": compiled.metadata,
    }))
}

fn json_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn report_markdown(
    compiled: &zkf_core::CompiledProgram,
    runtime_artifact: &zkf_core::ProofArtifact,
    prepared: &Witness,
    runtime_result: &zkf_runtime::PlanExecutionResult,
    integration_steps: usize,
    setup_provenance: &str,
    security_boundary: &str,
    determinism: serde_json::Value,
    telemetry_paths: &[String],
    gpu_attribution: &serde_json::Value,
    formal_evidence: &serde_json::Value,
    audit_summary: &serde_json::Value,
    generated_closure: &serde_json::Value,
) -> String {
    let proof_size = runtime_artifact.proof.len();
    let vk_size = runtime_artifact.verification_key.len();
    let stage_breakdown = runtime_result.report.stage_breakdown();
    let public_map = public_outputs(&compiled.program, prepared);
    let formal_status = formal_evidence
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let formal_sentence = if formal_status == "included" {
        "The bundle includes `formal/STATUS.md`, `formal/exercised_surfaces.json`, and bundled Rocq, protocol-Lean, satellite-Verus, and satellite-Kani logs for this surface."
    } else {
        "The bundle attempted to collect formal evidence under `formal/`; `formal/STATUS.md`, `formal/exercised_surfaces.json`, and the Rocq, protocol-Lean, satellite-Verus, and satellite-Kani logs record any runner failures explicitly."
    };
    let final_takeaway = if formal_status == "included" {
        "The mission-level takeaway is simple: the satellite conjunction showcase is exported as a deterministic, replayable artifact bundle with bundled formal logs, a generated implementation-closure extract, explicit provenance, and explicit audit boundaries."
    } else {
        "The mission-level takeaway is simple: the satellite conjunction showcase is exported as a deterministic, replayable artifact bundle with a generated implementation-closure extract, explicit provenance, explicit audit boundaries, and an explicit formal-evidence failure record when any configured proof runner does not pass."
    };
    let telemetry_lines = if telemetry_paths.is_empty() {
        "- No new telemetry file paths were detected while generating this bundle.\n".to_string()
    } else {
        telemetry_paths
            .iter()
            .map(|path| format!("- `{path}`\n"))
            .collect::<String>()
    };

    format!(
        r#"# ZirOS Private Satellite Conjunction Showcase

## Executive Summary

This bundle contains a private two-spacecraft conjunction-avoidance showcase built on ZirOS and emitted through the strict cryptographic Groth16 runtime/export stack. The circuit is built with `ProgramBuilder` over BN254, uses exactly {steps} one-minute steps by default, keeps all maneuver inputs private, and exposes five public outputs: two final-state commitments, the minimum separation, a safe-indicator safety-certificate bit, and a commitment to the maneuver plan.

The runtime proof was `{proof_size}` bytes and the verification key was `{vk_size}` bytes.

The Groth16 setup provenance for this run was `{setup_provenance}` and the security boundary label was `{security_boundary}`. When the security boundary is `development-only`, the export is intentionally marked as development-only and should not be treated as release-safe.

The kernel uses deterministic fixed-point arithmetic at scale `10^18`, Earth-centered Cartesian state, `dt = 60s`, and a bounded perturbation witness family for drag/model uncertainty. The shipped deterministic sample/export witness uses the zero member of that bounded family. The `safe_indicator` public output is a safety-certificate bit fixed to `1` for accepted safe trajectories; unsafe trajectories fail closed instead of exporting `0`. The circuit does not approximate the maneuver as a summary hash; it carries the burn timing, propagation trace, running minimum, delta-v accounting, and final commitments as explicit proof material.

## What Was Exported

The bundle exports the standard downstream surfaces:

- compiled artifact JSON
- prepared witness JSON
- Groth16 proof artifact JSON
- Solidity verifier source
- calldata JSON
- Foundry project
- CCS / matrix summary JSON
- runtime trace JSON
- audit summary JSON
- evidence manifest JSON
- mission assurance report

## Runtime Path

The proving path used the strict runtime lane with deterministic execution and Swarm enabled. The current stage snapshot was:

`{stage_breakdown:?}`

Telemetry paths created during the bundle run:

{telemetry_lines}

Bundle-local GPU attribution summary:

`{gpu_attribution}`

## Formal Evidence

{formal_sentence}

Formal evidence record:

`{formal_evidence}`

Generated implementation-closure extract:

`{generated_closure}`

The exact claimed or exercised proof surfaces are listed in `formal/exercised_surfaces.json`, and that file is a generated repo closure extract rather than a hand-curated proof inventory.

Audit summary:

`{audit_summary}`

## Determinism

Deterministic seeds and reproducible export settings were used throughout:

`{determinism}`

## Public Surface

Public inputs:

- `collision_threshold`
- `delta_v_budget`

Public outputs:

`{public_map:?}`

## Assessment

This export keeps the proof surface explicit and inspectable. The verifier assets, calldata, and Foundry harness are generated from the same proof artifact, and the bundle records the model boundary honestly: `development-only` stays `development-only`, and imported trusted CRS stays `trusted-imported`.

{final_takeaway}
"#,
        steps = integration_steps,
        setup_provenance = setup_provenance,
        security_boundary = security_boundary,
        stage_breakdown = stage_breakdown,
        proof_size = proof_size,
        vk_size = vk_size,
        telemetry_lines = telemetry_lines,
        gpu_attribution = json_pretty(gpu_attribution),
        formal_evidence = json_pretty(formal_evidence),
        generated_closure = json_pretty(generated_closure),
        audit_summary = json_pretty(audit_summary),
        determinism = determinism,
        final_takeaway = final_takeaway,
    )
}

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ZkfResult<T> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(256 * 1024 * 1024)
        .spawn(f)
        .map_err(|error| ZkfError::Backend(format!("spawn {name} worker: {error}")))?;
    handle.join().map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else if let Some(message) = panic.downcast_ref::<String>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else {
            ZkfError::Backend(format!("{name} worker panicked"))
        }
    })?
}

struct ShowcaseExportInputs {
    out_dir: PathBuf,
    integration_steps: usize,
    original_program: Program,
    optimized_program: Program,
    optimizer_report: zkf_core::OptimizeReport,
    valid_inputs: WitnessInputs,
    base_witness: Witness,
    prepared_witness: Witness,
    source_execution: BackendProofExecutionResult,
    compile_ms: f64,
    witness_ms: f64,
    source_runtime_ms: f64,
    wrap_ms: f64,
    trusted_setup_requested: bool,
    trusted_setup_used: bool,
    setup_provenance: String,
    security_boundary: String,
    telemetry_before: BTreeSet<String>,
    telemetry_after: BTreeSet<String>,
}

fn export_showcase_bundle(inputs: ShowcaseExportInputs) -> ZkfResult<()> {
    let ShowcaseExportInputs {
        out_dir,
        integration_steps,
        original_program,
        optimized_program,
        optimizer_report,
        valid_inputs,
        base_witness,
        prepared_witness,
        source_execution,
        compile_ms,
        witness_ms,
        source_runtime_ms,
        wrap_ms,
        trusted_setup_requested,
        trusted_setup_used,
        setup_provenance,
        security_boundary,
        telemetry_before,
        telemetry_after,
    } = inputs;

    let runtime_artifact = source_execution.artifact.clone();
    let wrapped_compiled = source_execution.compiled.clone();
    let verifier_source = export_groth16_solidity_verifier(
        &runtime_artifact,
        Some("PrivateSatelliteConjunctionVerifier"),
    )?;
    let calldata = proof_to_calldata_json(&runtime_artifact.proof, &runtime_artifact.public_inputs)
        .map_err(ZkfError::Backend)?;
    let foundry_test = generate_foundry_test_from_artifact(
        &runtime_artifact.proof,
        &runtime_artifact.public_inputs,
        "../src/PrivateSatelliteConjunctionVerifier.sol",
        "PrivateSatelliteConjunctionVerifier",
    )
    .map_err(ZkfError::Backend)?;

    let project_dir = foundry_project_dir_for_bundle(&out_dir);
    ensure_foundry_layout_local(&project_dir)?;

    let matrix_summary = ccs_summary(&source_execution.compiled)?;
    let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
    let gpu_attribution = effective_gpu_attribution_summary(
        source_execution.result.report.gpu_nodes,
        source_execution.result.report.gpu_stage_busy_ratio(),
        &runtime_artifact.metadata,
    );

    let mut determinism = json!({
        "source_compiled_digest": source_execution.compiled.program_digest,
        "wrapped_compiled_digest": wrapped_compiled.program_digest,
        "runtime_public_input_count": runtime_artifact.public_inputs.len(),
        "proof_seed_hex": hex_string(&PROOF_SEED),
        "export_mode": "direct-groth16",
    });
    if !trusted_setup_used {
        determinism["setup_seed_hex"] = serde_json::Value::String(hex_string(&SETUP_SEED));
    }

    let program_original_path = out_dir.join("private_satellite.original.program.json");
    let program_optimized_path = out_dir.join("private_satellite.optimized.program.json");
    let compiled_path = out_dir.join("private_satellite.compiled.json");
    let inputs_path = out_dir.join("private_satellite.inputs.json");
    let witness_base_path = out_dir.join("private_satellite.witness.base.json");
    let witness_path = out_dir.join("private_satellite.witness.prepared.json");
    let proof_path = out_dir.join("private_satellite.runtime.proof.json");
    let verifier_path = out_dir.join("PrivateSatelliteConjunctionVerifier.sol");
    let calldata_path = out_dir.join("private_satellite.calldata.json");
    let summary_path = out_dir.join("private_satellite.summary.json");
    let audit_path = out_dir.join("private_satellite.audit.json");
    let audit_summary_path = out_dir.join("private_satellite.audit_summary.json");
    let evidence_manifest_path = out_dir.join("private_satellite.evidence_manifest.json");
    let matrix_path = out_dir.join("private_satellite.matrix_ccs_summary.json");
    let runtime_trace_path = out_dir.join("private_satellite.runtime_trace.json");
    let execution_trace_path = out_dir.join("private_satellite.execution_trace.json");
    let report_path = out_dir.join("private_satellite.report.md");
    let mission_assurance_path = out_dir.join("private_satellite.mission_assurance.md");
    let foundry_verifier_path = project_dir.join("src/PrivateSatelliteConjunctionVerifier.sol");
    let foundry_test_path = project_dir.join("test/PrivateSatelliteConjunctionVerifier.t.sol");
    let audit_dir = out_dir.join("audit");

    write_json(&program_original_path, &original_program)?;
    write_json(&program_optimized_path, &optimized_program)?;
    write_json(&compiled_path, &wrapped_compiled)?;
    write_json(&inputs_path, &valid_inputs)?;
    write_json(&witness_base_path, &base_witness)?;
    write_json(&witness_path, &prepared_witness)?;
    write_json(&proof_path, &runtime_artifact)?;
    write_text(&verifier_path, &verifier_source)?;
    write_json(&calldata_path, &calldata)?;
    write_json(&matrix_path, &matrix_summary)?;
    write_json(
        &execution_trace_path,
        &json!({
            "source_prove": {
                "outputs": source_execution.result.outputs,
                "control_plane": source_execution.result.control_plane,
                "security": source_execution.result.security,
                "model_integrity": source_execution.result.model_integrity,
                "swarm": source_execution.result.swarm,
            },
            "export": {
                "mode": "direct-groth16",
                "artifact_metadata": runtime_artifact.metadata,
            },
        }),
    )?;

    write_text(&foundry_verifier_path, &verifier_source)?;
    write_text(&foundry_test_path, &foundry_test.source)?;

    ensure_file_exists(&program_original_path)?;
    ensure_file_exists(&program_optimized_path)?;
    ensure_file_exists(&compiled_path)?;
    ensure_file_exists(&inputs_path)?;
    ensure_file_exists(&witness_base_path)?;
    ensure_file_exists(&witness_path)?;
    ensure_file_exists(&proof_path)?;
    ensure_file_exists(&verifier_path)?;
    ensure_file_exists(&calldata_path)?;
    ensure_file_exists(&matrix_path)?;
    ensure_file_exists(&execution_trace_path)?;
    ensure_dir_exists(&project_dir)?;
    ensure_file_exists(&project_dir.join("foundry.toml"))?;
    ensure_file_exists(&foundry_verifier_path)?;
    ensure_file_exists(&foundry_test_path)?;

    let _: Program = read_json(&program_original_path)?;
    let _: Program = read_json(&program_optimized_path)?;
    let compiled_from_disk: zkf_core::CompiledProgram = read_json(&compiled_path)?;
    let _: WitnessInputs = read_json(&inputs_path)?;
    let _: Witness = read_json(&witness_base_path)?;
    let _: Witness = read_json(&witness_path)?;
    let runtime_artifact_from_disk: zkf_core::ProofArtifact = read_json(&proof_path)?;
    let _: serde_json::Value = read_json(&calldata_path)?;
    let _: serde_json::Value = read_json(&matrix_path)?;
    let _: serde_json::Value = read_json(&execution_trace_path)?;

    if !verify(&compiled_from_disk, &runtime_artifact_from_disk)? {
        return Err(ZkfError::Backend(
            "disk-loaded runtime proof verification returned false".to_string(),
        ));
    }

    let verifier_source_from_disk = read_text(&verifier_path)?;
    if !verifier_source_from_disk.contains("contract PrivateSatelliteConjunctionVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not contain the expected verifier contract",
            verifier_path.display()
        )));
    }

    let foundry_toml = read_text(&project_dir.join("foundry.toml"))?;
    if !foundry_toml.contains("[profile.default]") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} is not a valid Foundry project manifest",
            project_dir.join("foundry.toml").display()
        )));
    }

    let foundry_test_source = read_text(&foundry_test_path)?;
    if !foundry_test_source.contains("PrivateSatelliteConjunctionVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not reference the expected verifier contract",
            foundry_test_path.display()
        )));
    }

    let (generated_closure, formal_evidence) = collect_formal_evidence_for_generated_app(
        &out_dir,
        "private_satellite_conjunction_showcase",
    )?;
    let generated_closure_summary =
        generated_app_closure_bundle_summary("private_satellite_conjunction_showcase")?;
    let formal_dir = out_dir.join("formal");
    ensure_dir_exists(&formal_dir)?;
    ensure_file_exists(&formal_dir.join("STATUS.md"))?;
    ensure_file_exists(&formal_dir.join("rocq.log"))?;
    ensure_file_exists(&formal_dir.join("protocol_lean.log"))?;
    ensure_file_exists(&formal_dir.join("verus_satellite.log"))?;
    ensure_file_exists(&formal_dir.join("kani_satellite.log"))?;
    ensure_file_exists(&formal_dir.join("exercised_surfaces.json"))?;

    let full_audit_enabled = full_audit_requested();
    let structural_summary = json!({
        "status": "included",
        "paths": {
            "matrix_summary": "private_satellite.matrix_ccs_summary.json",
        },
        "original": {
            "program_digest": original_program.digest_hex(),
            "program_stats": stats(&original_program),
        },
        "optimized": {
            "program_digest": optimized_program.digest_hex(),
            "program_stats": stats(&optimized_program),
            "compiled_into_proof_path": false,
        },
        "compiled": {
            "source_program_digest": original_program.digest_hex(),
            "program_digest": wrapped_compiled.program_digest,
            "program_stats": stats(&source_execution.compiled.program),
            "export": "direct-groth16",
        },
    });
    let (full_source_audit, full_compiled_audit) = if full_audit_enabled {
        fs::create_dir_all(&audit_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
        let source_audit_path = audit_dir.join("private_satellite.source_audit.json");
        let compiled_audit_path = audit_dir.join("private_satellite.compiled_audit.json");
        let source_audit = audit_program_with_live_capabilities(
            &original_program,
            Some(BackendKind::ArkworksGroth16),
        );
        let compiled_audit = audit_program_with_live_capabilities(
            &source_execution.compiled.program,
            Some(BackendKind::ArkworksGroth16),
        );
        write_json(&source_audit_path, &source_audit)?;
        write_json(&compiled_audit_path, &compiled_audit)?;
        ensure_file_exists(&source_audit_path)?;
        ensure_file_exists(&compiled_audit_path)?;
        (
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_SATELLITE_FULL_AUDIT=1",
                "path": "audit/private_satellite.source_audit.json",
                "producer": "audit_program_with_live_capabilities(original_program, Some(arkworks-groth16))",
                "summary": source_audit.summary,
            }),
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_SATELLITE_FULL_AUDIT=1",
                "path": "audit/private_satellite.compiled_audit.json",
                "producer": "audit_program_with_live_capabilities(compiled_program, Some(arkworks-groth16))",
                "summary": compiled_audit.summary,
            }),
        )
    } else {
        (
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_SATELLITE_FULL_AUDIT=1 to include the heavyweight live source audit in the bundle",
                "path": serde_json::Value::Null,
            }),
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_SATELLITE_FULL_AUDIT=1 to include the heavyweight live compiled audit in the bundle",
                "path": serde_json::Value::Null,
            }),
        )
    };

    let audit_summary = json!({
        "mode": "two-tier-showcase-audit-v1",
        "structural_summary": structural_summary,
        "full_source_audit": full_source_audit,
        "full_compiled_audit": full_compiled_audit,
    });

    let runtime_trace = json!({
        "source_prove": stage_summary(&source_execution.result.report, &runtime_artifact.metadata),
        "effective_gpu_attribution": gpu_attribution,
        "telemetry_paths": telemetry_paths,
        "export": {
            "mode": "runtime-strict-groth16",
            "wall_time_ms": wrap_ms,
        }
    });

    let evidence_manifest = json!({
        "bundle_evidence_version": "satellite-showcase-evidence-v1",
        "generated_closure": generated_closure_summary,
        "formal_evidence": formal_evidence,
        "audit_coverage": {
            "mode": "two-tier-showcase-audit-v1",
            "full_audit_requested": full_audit_enabled,
            "structural_summary": audit_summary["structural_summary"],
            "full_source_audit": audit_summary["full_source_audit"],
            "full_compiled_audit": audit_summary["full_compiled_audit"],
        },
        "gpu_attribution": gpu_attribution,
        "trusted_setup": {
            "provenance": setup_provenance,
            "security_boundary": security_boundary,
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
        },
    });

    let summary = json!({
        "circuit_name": original_program.name,
        "field": "bn254",
        "spacecraft_count": 2,
        "integration_steps": integration_steps,
        "backend": {
            "source": BackendKind::ArkworksGroth16.as_str(),
            "final": BackendKind::ArkworksGroth16.as_str(),
            "export": "runtime-strict-groth16",
        },
        "private_inputs": PRIVATE_SATELLITE_PRIVATE_INPUTS,
        "public_inputs": PRIVATE_SATELLITE_PUBLIC_INPUTS,
        "public_outputs": PRIVATE_SATELLITE_PUBLIC_OUTPUTS,
        "original_program": stats(&original_program),
        "optimized_program": stats(&optimized_program),
        "source_compiled_program": stats(&source_execution.compiled.program),
        "compile_source_program_digest": original_program.digest_hex(),
        "optimizer_report": optimizer_report,
        "groth16_setup": {
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
            "provenance": setup_provenance,
            "security_boundary": security_boundary,
        },
        "runtime_witness_mode": "authoritative-base-witness-normalized-by-runtime",
        "timings_ms": {
            "compile": compile_ms,
            "witness_prepare": witness_ms,
            "runtime_strict_lane_source_prove": source_runtime_ms,
            "groth16_export_wrap": wrap_ms,
        },
        "determinism": determinism,
        "public_outputs": public_outputs(&source_execution.compiled.program, &prepared_witness),
        "runtime_public_inputs": runtime_artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect::<Vec<_>>(),
        "proof_sizes": {
            "runtime_proof_bytes": runtime_artifact.proof.len(),
            "runtime_verification_key_bytes": runtime_artifact.verification_key.len(),
            "source_proof_bytes": source_execution.artifact.proof.len(),
        },
        "runtime": runtime_trace,
        "control_plane": source_execution.result.control_plane,
        "security": source_execution.result.security,
        "model_integrity": source_execution.result.model_integrity,
        "swarm": source_execution.result.swarm,
        "artifact_metadata": runtime_artifact.metadata,
        "effective_gpu_attribution": gpu_attribution,
        "metal_runtime": metal_runtime_report(),
        "telemetry_paths": telemetry_paths,
        "evidence_manifest_path": "private_satellite.evidence_manifest.json",
        "generated_closure": evidence_manifest["generated_closure"],
        "formal_evidence": evidence_manifest["formal_evidence"],
        "audit_coverage": evidence_manifest["audit_coverage"],
    });

    write_json(&summary_path, &summary)?;
    write_json(&audit_path, &audit_summary)?;
    write_json(&audit_summary_path, &audit_summary)?;
    write_json(&runtime_trace_path, &runtime_trace)?;
    write_json(&evidence_manifest_path, &evidence_manifest)?;

    let mission_assurance_report = report_markdown(
        &source_execution.compiled,
        &runtime_artifact,
        &prepared_witness,
        &source_execution.result,
        integration_steps,
        &setup_provenance,
        &security_boundary,
        determinism.clone(),
        &telemetry_paths,
        &gpu_attribution,
        evidence_manifest
            .get("formal_evidence")
            .expect("formal evidence"),
        &audit_summary,
        &generated_closure,
    );
    write_text(&report_path, &mission_assurance_report)?;
    write_text(&mission_assurance_path, &mission_assurance_report)?;

    ensure_file_exists(&summary_path)?;
    ensure_file_exists(&audit_path)?;
    ensure_file_exists(&audit_summary_path)?;
    ensure_file_exists(&runtime_trace_path)?;
    ensure_file_exists(&evidence_manifest_path)?;
    ensure_file_exists(&report_path)?;
    ensure_file_exists(&mission_assurance_path)?;

    archive_showcase_artifacts(
        "private_satellite_conjunction_showcase",
        &[
            proof_path.as_path(),
            verifier_path.as_path(),
            calldata_path.as_path(),
            execution_trace_path.as_path(),
            runtime_trace_path.as_path(),
            summary_path.as_path(),
            audit_path.as_path(),
            audit_summary_path.as_path(),
            report_path.as_path(),
            mission_assurance_path.as_path(),
            evidence_manifest_path.as_path(),
        ],
    )?;
    purge_showcase_witness_artifacts(&[witness_base_path.as_path(), witness_path.as_path()])?;

    println!("{}", summary_path.display());
    println!("{}", verifier_path.display());
    println!("{}", calldata_path.display());
    println!("{}", audit_summary_path.display());
    println!("{}", evidence_manifest_path.display());
    println!("{}", mission_assurance_path.display());
    println!("{}", project_dir.display());
    Ok(())
}

fn main() -> ZkfResult<()> {
    if !SwarmConfig::is_enabled() {
        return Err(ZkfError::Backend(
            "swarm monitoring is required for this showcase; set ZKF_SWARM=1".to_string(),
        ));
    }

    let steps = integration_steps()?;
    let out_dir = output_dir(steps);
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;

    let template = private_satellite_conjunction_showcase_with_steps(steps)?;
    let original_program = template.program.clone();
    let valid_inputs: WitnessInputs = template.sample_inputs.clone();
    let (optimized_program, optimizer_report) = optimize_program(&original_program);

    let trusted_setup_requested = requested_groth16_setup_blob_path(&original_program).is_some();

    let compile_start = Instant::now();
    let source_compiled = with_showcase_groth16_mode(trusted_setup_requested, || {
        compile(&original_program, "arkworks-groth16", Some(SETUP_SEED))
    })?;
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;
    let default_setup_provenance = if trusted_setup_requested {
        GROTH16_IMPORTED_SETUP_PROVENANCE
    } else {
        GROTH16_DETERMINISTIC_DEV_PROVENANCE
    };
    let default_security_boundary = if trusted_setup_requested {
        GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY
    } else {
        GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY
    };
    let setup_provenance = source_compiled
        .metadata
        .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
        .cloned()
        .unwrap_or_else(|| default_setup_provenance.to_string());
    let security_boundary = source_compiled
        .metadata
        .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
        .cloned()
        .unwrap_or_else(|| default_security_boundary.to_string());
    let trusted_setup_used = security_boundary == GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY
        || setup_provenance == GROTH16_IMPORTED_SETUP_PROVENANCE;

    let witness_start = Instant::now();
    let base_witness = private_satellite_conjunction_witness_with_steps(&valid_inputs, steps)?;
    let prepared_witness = prepare_witness_for_proving(&source_compiled, &base_witness)?;
    check_constraints(&source_compiled.program, &prepared_witness)?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    let telemetry_before = telemetry_snapshot();
    let source_runtime_start = Instant::now();
    let source_execution = with_showcase_groth16_mode(trusted_setup_used, || {
        with_proof_seed_override(Some(PROOF_SEED), || {
            RuntimeExecutor::run_backend_prove_job_with_objective(
                BackendKind::ArkworksGroth16,
                BackendRoute::Auto,
                Arc::new(source_compiled.program.clone()),
                Some(Arc::new(valid_inputs.clone())),
                Some(Arc::new(base_witness.clone())),
                Some(Arc::new(source_compiled.clone())),
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .map_err(|error| ZkfError::Backend(error.to_string()))
        })
    })?;
    let source_runtime_ms = source_runtime_start.elapsed().as_secs_f64() * 1_000.0;
    if !verify(&source_execution.compiled, &source_execution.artifact)? {
        return Err(ZkfError::Backend(
            "runtime groth16 proof verification returned false".to_string(),
        ));
    }
    let telemetry_after = telemetry_snapshot();
    let wrap_ms = 0.0;

    run_with_large_stack_result("private-satellite-export", move || {
        let inputs = ShowcaseExportInputs {
            out_dir,
            integration_steps: steps,
            original_program,
            optimized_program,
            optimizer_report,
            valid_inputs,
            base_witness,
            prepared_witness,
            source_execution,
            compile_ms,
            witness_ms,
            source_runtime_ms,
            wrap_ms,
            trusted_setup_requested,
            trusted_setup_used,
            setup_provenance,
            security_boundary,
            telemetry_before,
            telemetry_after,
        };
        export_showcase_bundle(inputs)
    })
}
