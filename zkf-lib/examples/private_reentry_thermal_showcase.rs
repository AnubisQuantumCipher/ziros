//! ZirOS Private Reentry Thermal-Safety Showcase
//!
//! Exercises ZirOS as a complete operating system for a reentry vehicle
//! thermal-safety circuit:
//!
//! 1. Build the reentry circuit (configurable integration steps)
//! 2. Audit the program with live backend capabilities
//! 3. Compile for Groth16 (arkworks, deterministic dev mode by default)
//! 4. Generate and prepare witness
//! 5. Prove via RuntimeExecutor (strict cryptographic lane)
//! 6. Capture full telemetry (GPU attribution, stage breakdown, watchdog)
//! 7. Verify the proof
//! 8. Export Solidity verifier
//! 9. Write all artifacts to an output directory

use serde::Serialize;
use serde_json::json;
// sha2 re-exported through zkf-core for digest operations
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zkf_backends::foundry_test::proof_to_calldata_json;
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{
    BackendRoute, GROTH16_DETERMINISTIC_DEV_PROVENANCE,
    GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY, GROTH16_IMPORTED_SETUP_PROVENANCE,
    GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY, GROTH16_SETUP_PROVENANCE_METADATA_KEY,
    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY, compile_arkworks_unchecked,
    prepare_witness_for_proving, requested_groth16_setup_blob_path,
};
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendKind, Program, Witness, WitnessInputs, check_constraints, optimize_program,
};
use zkf_lib::app::audit::audit_program_with_live_capabilities_owned;
use zkf_lib::app::reentry::{
    PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS, PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS,
    PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS, PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS,
    private_reentry_thermal_sample_request_with_steps,
    private_reentry_thermal_showcase_with_steps, private_reentry_thermal_witness_with_steps,
};
use zkf_lib::evidence::{
    archive_showcase_artifacts,
    collect_formal_evidence_for_generated_app, effective_gpu_attribution_summary,
    ensure_file_exists, ensure_foundry_layout, foundry_project_dir,
    generated_app_closure_bundle_summary, purge_showcase_witness_artifacts,
    two_tier_audit_record,
};
use zkf_lib::{ZkfError, ZkfResult, export_groth16_solidity_verifier, verify};
use zkf_runtime::{
    BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
    RuntimeExecutor, SwarmConfig,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APP_ID: &str = "private_reentry_thermal_showcase";
const SETUP_SEED: [u8; 32] = [0x52; 32]; // 'R' for reentry
const PROOF_SEED: [u8; 32] = [0x54; 32]; // 'T' for thermal
const STEPS_OVERRIDE_ENV: &str = "ZKF_PRIVATE_REENTRY_THERMAL_STEPS_OVERRIDE";
const FULL_AUDIT_ENV: &str = "ZKF_PRIVATE_REENTRY_THERMAL_FULL_AUDIT";
const EXPORT_STACK_GROW_SIZE: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Groth16 mode helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn full_audit_requested() -> bool {
    env_flag(FULL_AUDIT_ENV)
}

// ---------------------------------------------------------------------------
// Program statistics
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Runtime report snapshot (serializable mirror of GraphExecutionReport)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct RuntimeReportSnapshot {
    total_wall_time_ms: f64,
    peak_memory_bytes: usize,
    gpu_nodes: usize,
    cpu_nodes: usize,
    delegated_nodes: usize,
    fallback_nodes: usize,
    gpu_busy_ratio: f64,
    counter_source: String,
    stage_breakdown: serde_json::Value,
    watchdog_alerts: Vec<zkf_runtime::WatchdogAlert>,
}

impl RuntimeReportSnapshot {
    fn from_report(report: &zkf_runtime::GraphExecutionReport) -> ZkfResult<Self> {
        Ok(Self {
            total_wall_time_ms: report.total_wall_time.as_secs_f64() * 1_000.0,
            peak_memory_bytes: report.peak_memory_bytes,
            gpu_nodes: report.gpu_nodes,
            cpu_nodes: report.cpu_nodes,
            delegated_nodes: report.delegated_nodes,
            fallback_nodes: report.fallback_nodes,
            gpu_busy_ratio: report.gpu_stage_busy_ratio(),
            counter_source: report.counter_source().to_string(),
            stage_breakdown: serde_json::to_value(report.stage_breakdown()).map_err(|error| {
                ZkfError::Serialization(format!(
                    "serialize reentry thermal runtime stage breakdown: {error}"
                ))
            })?,
            watchdog_alerts: report.watchdog_alerts.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// JSON / text I/O helpers
// ---------------------------------------------------------------------------

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    let file = fs::File::create(path)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", path.display())))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, value).map_err(|error| {
        ZkfError::Serialization(format!("serialize {}: {error}", path.display()))
    })?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> ZkfResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    fs::write(path, value)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    zkf_core::json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn read_text(path: &Path) -> ZkfResult<String> {
    fs::read_to_string(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))
}

// ---------------------------------------------------------------------------
// Integration step override
// ---------------------------------------------------------------------------

fn integration_steps() -> ZkfResult<usize> {
    match env::var(STEPS_OVERRIDE_ENV) {
        Ok(raw) => {
            let steps = raw.parse::<usize>().map_err(|error| {
                ZkfError::Backend(format!("parse {STEPS_OVERRIDE_ENV}={raw:?}: {error}"))
            })?;
            if steps == 0 {
                return Err(ZkfError::Backend(
                    "reentry thermal step override must be greater than zero".to_string(),
                ));
            }
            Ok(steps)
        }
        Err(env::VarError::NotPresent) => Ok(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS),
        Err(error) => Err(ZkfError::Backend(format!(
            "read {STEPS_OVERRIDE_ENV}: {error}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Output directory
// ---------------------------------------------------------------------------

fn output_dir(steps: usize) -> PathBuf {
    env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(format!(
            "Desktop/ZirOS_Reentry_Thermal_{steps}Step_Default"
        ))
    })
}

// ---------------------------------------------------------------------------
// Public output extraction
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Runtime stage summary
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Telemetry snapshots
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CCS matrix summary
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Foundry layout
// ---------------------------------------------------------------------------

fn foundry_project_dir_for_bundle(out_dir: &Path) -> PathBuf {
    foundry_project_dir(out_dir)
}

fn ensure_foundry_layout_local(project_dir: &Path) -> ZkfResult<()> {
    ensure_foundry_layout(project_dir)
}

// ---------------------------------------------------------------------------
// Large-stack runner
// ---------------------------------------------------------------------------

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ZkfResult<T> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(EXPORT_STACK_GROW_SIZE)
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

// ---------------------------------------------------------------------------
// Mission assurance report (Markdown)
// ---------------------------------------------------------------------------

fn report_markdown(
    compiled: &zkf_core::CompiledProgram,
    prepared: &Witness,
    runtime_report: &RuntimeReportSnapshot,
    runtime_artifact: &zkf_core::ProofArtifact,
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
    let public_map = public_outputs(&compiled.program, prepared);
    let formal_status = formal_evidence
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let formal_sentence = if formal_status == "included" {
        "The bundle includes formal evidence under `formal/`."
    } else {
        "The bundle attempted to collect formal evidence under `formal/`; see logs for details."
    };

    format!(
        r#"# ZirOS Private Reentry Thermal-Safety — Mission Assurance Report

## Circuit

- **Name**: `{circuit_name}`
- **Integration steps**: {steps}
- **Default steps**: {default_steps}
- **Field**: bn254

## Groth16 Setup

- **Provenance**: `{setup_provenance}`
- **Security boundary**: `{security_boundary}`

## Proof Sizes

| Artifact | Bytes |
|----------|-------|
| Proof | {proof_size} |
| Verification key | {vk_size} |

## Runtime Telemetry

- **Total wall time**: {wall_time:.2} ms
- **Peak memory**: {peak_mem} bytes
- **GPU nodes**: {gpu} | **CPU nodes**: {cpu}
- **Delegated**: {delegated} | **Fallback**: {fallback}
- **GPU busy ratio**: {gpu_ratio:.4}
- **Counter source**: `{counter_source}`

## Watchdog Alerts

{watchdog_section}

## Public Outputs

```json
{public_outputs}
```

## Determinism

```json
{determinism}
```

## Telemetry Paths

{telemetry_count} telemetry path(s) captured during proving.

## GPU Attribution

```json
{gpu_attribution}
```

## Formal Evidence

{formal_sentence}

```json
{formal_evidence}
```

## Audit Coverage

```json
{audit_summary}
```

## Generated Closure

```json
{generated_closure}
```
"#,
        circuit_name = compiled.program.name,
        steps = integration_steps,
        default_steps = PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS,
        setup_provenance = setup_provenance,
        security_boundary = security_boundary,
        proof_size = proof_size,
        vk_size = vk_size,
        wall_time = runtime_report.total_wall_time_ms,
        peak_mem = runtime_report.peak_memory_bytes,
        gpu = runtime_report.gpu_nodes,
        cpu = runtime_report.cpu_nodes,
        delegated = runtime_report.delegated_nodes,
        fallback = runtime_report.fallback_nodes,
        gpu_ratio = runtime_report.gpu_busy_ratio,
        counter_source = runtime_report.counter_source,
        watchdog_section = if runtime_report.watchdog_alerts.is_empty() {
            "No watchdog alerts.".to_string()
        } else {
            runtime_report
                .watchdog_alerts
                .iter()
                .map(|alert| format!("- `{alert:?}`"))
                .collect::<Vec<_>>()
                .join("\n")
        },
        public_outputs = serde_json::to_string_pretty(&public_map).unwrap_or_default(),
        determinism = serde_json::to_string_pretty(&determinism).unwrap_or_default(),
        telemetry_count = telemetry_paths.len(),
        gpu_attribution = serde_json::to_string_pretty(gpu_attribution).unwrap_or_default(),
        formal_evidence = serde_json::to_string_pretty(formal_evidence).unwrap_or_default(),
        audit_summary = serde_json::to_string_pretty(audit_summary).unwrap_or_default(),
        generated_closure = serde_json::to_string_pretty(generated_closure).unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// Bundle README
// ---------------------------------------------------------------------------

fn bundle_readme_markdown(steps: usize) -> String {
    format!(
        r#"# ZirOS Private Reentry Thermal-Safety Bundle

This directory contains a complete ZirOS-generated reentry thermal-safety
proof bundle with {steps} integration steps.

## Contents

| File | Description |
|------|-------------|
| `private_reentry_thermal.original.program.json` | Original circuit before optimization |
| `private_reentry_thermal.optimized.program.json` | Optimized circuit |
| `private_reentry_thermal.compiled.json` | Compiled Groth16 artifact |
| `private_reentry_thermal.request.json` | Sample request parameters |
| `private_reentry_thermal.inputs.json` | Witness inputs |
| `private_reentry_thermal.witness.prepared.json` | Prepared witness |
| `private_reentry_thermal.runtime.proof.json` | Groth16 proof artifact |
| `private_reentry_thermal.calldata.json` | Solidity calldata |
| `private_reentry_thermal.summary.json` | Full summary |
| `private_reentry_thermal.execution_trace.json` | Execution trace |
| `private_reentry_thermal.runtime_trace.json` | Runtime telemetry trace |
| `PrivateReentryThermalVerifier.sol` | Solidity verifier contract |
| `audit/` | Audit reports |

## Verification

The Groth16 proof in this bundle has been verified against the compiled
verification key. The Solidity verifier can be deployed on-chain to
verify proofs independently.

## Generated by

ZirOS — Zero-Knowledge Operating System
"#,
        steps = steps,
    )
}

// ---------------------------------------------------------------------------
// Export showcase bundle
// ---------------------------------------------------------------------------

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
        base_witness: _base_witness,
        prepared_witness,
        source_execution,
        compile_ms,
        witness_ms,
        source_runtime_ms,
        trusted_setup_requested,
        trusted_setup_used,
        setup_provenance,
        security_boundary,
        telemetry_before,
        telemetry_after,
    } = inputs;

    let wrap_start = Instant::now();

    let runtime_artifact = source_execution.artifact.clone();
    let runtime_result = &source_execution.result;
    let compiled = source_execution.compiled.clone();

    // -----------------------------------------------------------------------
    // Solidity verifier export
    // -----------------------------------------------------------------------

    eprintln!("  [7/8] Exporting Solidity verifier...");

    let verifier_source =
        export_groth16_solidity_verifier(&runtime_artifact, Some("PrivateReentryThermalVerifier"))?;

    let calldata = proof_to_calldata_json(&runtime_artifact.proof, &runtime_artifact.public_inputs)
        .map_err(ZkfError::Backend)?;

    // -----------------------------------------------------------------------
    // Foundry layout
    // -----------------------------------------------------------------------

    let project_dir = foundry_project_dir_for_bundle(&out_dir);
    ensure_foundry_layout_local(&project_dir)?;

    // -----------------------------------------------------------------------
    // Telemetry capture
    // -----------------------------------------------------------------------

    let runtime_report = RuntimeReportSnapshot::from_report(&runtime_result.report)?;
    let _matrix_summary = ccs_summary(&compiled)?;
    let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
    let gpu_attribution = effective_gpu_attribution_summary(
        runtime_result.report.gpu_nodes,
        runtime_result.report.gpu_stage_busy_ratio(),
        &runtime_artifact.metadata,
    );

    // -----------------------------------------------------------------------
    // Control plane / security / model integrity / swarm
    // -----------------------------------------------------------------------

    let control_plane = runtime_result
        .control_plane
        .as_ref()
        .map(|cp| serde_json::to_value(cp).ok())
        .flatten();
    let security = runtime_result
        .security
        .as_ref()
        .map(|s| serde_json::to_value(s).ok())
        .flatten();
    let model_integrity = runtime_result
        .model_integrity
        .as_ref()
        .map(|mi| serde_json::to_value(mi).ok())
        .flatten();
    let swarm = runtime_result
        .swarm
        .as_ref()
        .map(|sw| serde_json::to_value(sw).ok())
        .flatten();

    // -----------------------------------------------------------------------
    // Determinism snapshot
    // -----------------------------------------------------------------------

    let mut determinism = json!({
        "source_compiled_digest": compiled.program_digest,
        "runtime_public_input_count": runtime_artifact.public_inputs.len(),
        "proof_seed_hex": hex_string(&PROOF_SEED),
        "export_mode": "direct-groth16",
    });
    if !trusted_setup_used {
        determinism["setup_seed_hex"] = serde_json::Value::String(hex_string(&SETUP_SEED));
    }

    // -----------------------------------------------------------------------
    // Sample request
    // -----------------------------------------------------------------------

    let effective_request =
        private_reentry_thermal_sample_request_with_steps(integration_steps)?;

    // -----------------------------------------------------------------------
    // File paths
    // -----------------------------------------------------------------------

    let program_original_path =
        out_dir.join("private_reentry_thermal.original.program.json");
    let program_optimized_path =
        out_dir.join("private_reentry_thermal.optimized.program.json");
    let compiled_path = out_dir.join("private_reentry_thermal.compiled.json");
    let request_path = out_dir.join("private_reentry_thermal.request.json");
    let inputs_path = out_dir.join("private_reentry_thermal.inputs.json");
    let witness_path = out_dir.join("private_reentry_thermal.witness.prepared.json");
    let proof_path = out_dir.join("private_reentry_thermal.runtime.proof.json");
    let verifier_path = out_dir.join("PrivateReentryThermalVerifier.sol");
    let calldata_path = out_dir.join("private_reentry_thermal.calldata.json");
    let summary_path = out_dir.join("private_reentry_thermal.summary.json");
    let audit_path = out_dir.join("private_reentry_thermal.audit.json");
    let execution_trace_path = out_dir.join("private_reentry_thermal.execution_trace.json");
    let runtime_trace_path = out_dir.join("private_reentry_thermal.runtime_trace.json");
    let report_path = out_dir.join("private_reentry_thermal.report.md");
    let bundle_readme_path = out_dir.join("README.md");
    let audit_dir = out_dir.join("audit");

    // -----------------------------------------------------------------------
    // Write primary artifacts
    // -----------------------------------------------------------------------

    eprintln!("  [8/8] Writing bundle...");

    write_json(&program_original_path, &original_program)?;
    write_json(&program_optimized_path, &optimized_program)?;
    write_json(&compiled_path, &compiled)?;
    write_json(&request_path, &effective_request)?;
    write_json(&inputs_path, &valid_inputs)?;
    write_json(&witness_path, &prepared_witness)?;
    write_json(&proof_path, &runtime_artifact)?;
    write_text(&verifier_path, &verifier_source)?;
    write_json(&calldata_path, &calldata)?;

    // -----------------------------------------------------------------------
    // Execution trace
    // -----------------------------------------------------------------------

    write_json(
        &execution_trace_path,
        &json!({
            "schema_version": "private-reentry-thermal-execution-trace-v1",
            "app_id": APP_ID,
            "integration_steps": integration_steps,
            "default_step_count": PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS,
            "source_prove": {
                "runtime_report": runtime_report,
                "outputs": runtime_result.outputs,
                "control_plane": control_plane,
                "security": security,
                "model_integrity": model_integrity,
                "swarm": swarm,
            },
            "export": {
                "mode": "direct-groth16",
                "artifact_metadata": runtime_artifact.metadata,
            },
            "determinism": determinism,
            "timings_ms": {
                "compile": compile_ms,
                "witness_prepare": witness_ms,
                "runtime_strict_lane_source_prove": source_runtime_ms,
            },
            "groth16_setup": {
                "trusted_setup_requested": trusted_setup_requested,
                "trusted_setup_used": trusted_setup_used,
                "provenance": setup_provenance,
                "security_boundary": security_boundary,
            },
        }),
    )?;

    // -----------------------------------------------------------------------
    // Runtime trace
    // -----------------------------------------------------------------------

    let runtime_trace = json!({
        "source_prove": stage_summary(&runtime_result.report, &runtime_artifact.metadata),
        "effective_gpu_attribution": gpu_attribution,
        "telemetry_paths": telemetry_paths,
        "metal_runtime": metal_runtime_report(),
        "export": {
            "mode": "runtime-strict-groth16",
            "wall_time_ms": wrap_start.elapsed().as_secs_f64() * 1_000.0,
        }
    });
    write_json(&runtime_trace_path, &runtime_trace)?;

    // -----------------------------------------------------------------------
    // Formal evidence and audit
    // -----------------------------------------------------------------------

    let (generated_closure, formal_evidence) =
        collect_formal_evidence_for_generated_app(&out_dir, APP_ID)
            .unwrap_or_else(|_| (json!({"status": "not-available", "reason": "no forensics manifest for this application"}), json!({"status": "not-available"})));
    let generated_closure_summary = generated_app_closure_bundle_summary(APP_ID)
        .unwrap_or_else(|_| json!({"status": "not-available", "reason": "no closure manifest for this application"}));

    let full_audit_enabled = full_audit_requested();
    let structural_summary = json!({
        "status": "included",
        "paths": {
            "matrix_summary": "private_reentry_thermal.matrix_ccs_summary.json",
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
            "program_digest": compiled.program_digest,
            "program_stats": stats(&compiled.program),
            "export": "direct-groth16",
        },
    });

    let (full_source_audit, full_compiled_audit) = if full_audit_enabled {
        fs::create_dir_all(&audit_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
        let source_audit_path = audit_dir.join("private_reentry_thermal.source_audit.json");
        let compiled_audit_path = audit_dir.join("private_reentry_thermal.compiled_audit.json");
        let source_audit = audit_program_with_live_capabilities_owned(
            original_program.clone(),
            Some(BackendKind::ArkworksGroth16),
        );
        let compiled_audit = audit_program_with_live_capabilities_owned(
            compiled.program.clone(),
            Some(BackendKind::ArkworksGroth16),
        );
        write_json(&source_audit_path, &source_audit)?;
        write_json(&compiled_audit_path, &compiled_audit)?;
        ensure_file_exists(&source_audit_path)?;
        ensure_file_exists(&compiled_audit_path)?;
        (
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_REENTRY_THERMAL_FULL_AUDIT=1",
                "path": "audit/private_reentry_thermal.source_audit.json",
                "producer": "audit_program_with_live_capabilities_owned(original_program, Some(arkworks-groth16))",
                "summary": source_audit.summary,
            }),
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_REENTRY_THERMAL_FULL_AUDIT=1",
                "path": "audit/private_reentry_thermal.compiled_audit.json",
                "producer": "audit_program_with_live_capabilities_owned(compiled_program, Some(arkworks-groth16))",
                "summary": compiled_audit.summary,
            }),
        )
    } else {
        (
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_REENTRY_THERMAL_FULL_AUDIT=1 to include the heavyweight live source audit in the bundle",
                "path": serde_json::Value::Null,
            }),
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_REENTRY_THERMAL_FULL_AUDIT=1 to include the heavyweight live compiled audit in the bundle",
                "path": serde_json::Value::Null,
            }),
        )
    };

    let audit_summary = two_tier_audit_record(
        "two-tier-showcase-audit-v1",
        structural_summary,
        full_source_audit,
        full_compiled_audit,
    );

    write_json(&audit_path, &audit_summary)?;

    // -----------------------------------------------------------------------
    // Evidence manifest
    // -----------------------------------------------------------------------

    let evidence_manifest = json!({
        "bundle_evidence_version": "reentry-thermal-showcase-evidence-v1",
        "app_id": APP_ID,
        "circuit_name": original_program.name,
        "integration_steps": integration_steps,
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

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------

    let wrap_ms = wrap_start.elapsed().as_secs_f64() * 1_000.0;
    let public_output_map = public_outputs(&compiled.program, &prepared_witness);
    let declared_private_inputs = PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS
        + integration_steps * 4; // per-step: bank_cos, sin_gamma, cos_gamma, rho

    let summary = json!({
        "app_id": APP_ID,
        "circuit_name": original_program.name,
        "field": "bn254",
        "step_count": integration_steps,
        "default_step_count": PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS,
        "integration_steps": integration_steps,
        "backend": {
            "source": BackendKind::ArkworksGroth16.as_str(),
            "final": BackendKind::ArkworksGroth16.as_str(),
            "export": "runtime-strict-groth16",
        },
        "original_constraint_count": original_program.constraints.len(),
        "final_constraint_count": compiled.program.constraints.len(),
        "peak_memory_bytes": runtime_report.peak_memory_bytes,
        "private_inputs": declared_private_inputs,
        "public_inputs": PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS,
        "declared_public_outputs": PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS,
        "original_program": stats(&original_program),
        "optimized_program": stats(&optimized_program),
        "source_compiled_program": stats(&compiled.program),
        "compile_source_program_digest": original_program.digest_hex(),
        "optimizer_report": optimizer_report,
        "groth16_setup": {
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
            "provenance": setup_provenance,
            "security_boundary": security_boundary,
        },
        "runtime_witness_mode": "authoritative-base-witness-normalized-by-runtime",
        "vehicle_parameters": {
            "private": effective_request.private,
            "public": effective_request.public,
        },
        "timings_ms": {
            "compile": compile_ms,
            "witness_prepare": witness_ms,
            "runtime_strict_lane_source_prove": source_runtime_ms,
            "groth16_export_wrap": wrap_ms,
        },
        "determinism": determinism,
        "public_outputs": public_output_map,
        "runtime_public_inputs": runtime_artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect::<Vec<_>>(),
        "proof_sizes": {
            "runtime_proof_bytes": runtime_artifact.proof.len(),
            "runtime_verification_key_bytes": runtime_artifact.verification_key.len(),
            "source_proof_bytes": runtime_artifact.proof.len(),
        },
        "runtime": runtime_trace,
        "control_plane": control_plane,
        "security": security,
        "model_integrity": model_integrity,
        "swarm": swarm,
        "artifact_metadata": runtime_artifact.metadata,
        "effective_gpu_attribution": gpu_attribution,
        "metal_runtime": metal_runtime_report(),
        "telemetry_paths": telemetry_paths,
        "evidence_manifest_path": "private_reentry_thermal.evidence_manifest.json",
        "generated_closure": evidence_manifest["generated_closure"],
        "formal_evidence": evidence_manifest["formal_evidence"],
        "audit_coverage": evidence_manifest["audit_coverage"],
    });

    write_json(&summary_path, &summary)?;

    // -----------------------------------------------------------------------
    // Markdown report
    // -----------------------------------------------------------------------

    let mission_assurance_report = report_markdown(
        &compiled,
        &prepared_witness,
        &runtime_report,
        &runtime_artifact,
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
    write_text(&bundle_readme_path, &bundle_readme_markdown(integration_steps))?;

    // -----------------------------------------------------------------------
    // Verify all files exist on disk
    // -----------------------------------------------------------------------

    ensure_file_exists(&program_original_path)?;
    ensure_file_exists(&program_optimized_path)?;
    ensure_file_exists(&compiled_path)?;
    ensure_file_exists(&request_path)?;
    ensure_file_exists(&inputs_path)?;
    ensure_file_exists(&witness_path)?;
    ensure_file_exists(&proof_path)?;
    ensure_file_exists(&verifier_path)?;
    ensure_file_exists(&calldata_path)?;
    ensure_file_exists(&execution_trace_path)?;
    ensure_file_exists(&runtime_trace_path)?;
    ensure_file_exists(&summary_path)?;
    ensure_file_exists(&audit_path)?;
    ensure_file_exists(&report_path)?;
    ensure_file_exists(&bundle_readme_path)?;

    // -----------------------------------------------------------------------
    // Re-read and verify from disk
    // -----------------------------------------------------------------------

    let _: Program = read_json(&program_original_path)?;
    let _: Program = read_json(&program_optimized_path)?;
    let compiled_from_disk: zkf_core::CompiledProgram = read_json(&compiled_path)?;
    let _: WitnessInputs = read_json(&inputs_path)?;
    let _: Witness = read_json(&witness_path)?;
    let runtime_artifact_from_disk: zkf_core::ProofArtifact = read_json(&proof_path)?;
    let _: serde_json::Value = read_json(&calldata_path)?;
    let _: serde_json::Value = read_json(&execution_trace_path)?;

    if !verify(&compiled_from_disk, &runtime_artifact_from_disk)? {
        return Err(ZkfError::Backend(
            "disk-loaded runtime proof verification returned false".to_string(),
        ));
    }

    let verifier_source_from_disk = read_text(&verifier_path)?;
    if !verifier_source_from_disk.contains("contract PrivateReentryThermalVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not contain the expected verifier contract",
            verifier_path.display()
        )));
    }

    archive_showcase_artifacts(
        APP_ID,
        &[
            proof_path.as_path(),
            verifier_path.as_path(),
            calldata_path.as_path(),
            execution_trace_path.as_path(),
            runtime_trace_path.as_path(),
            summary_path.as_path(),
            audit_path.as_path(),
            report_path.as_path(),
        ],
    )?;
    purge_showcase_witness_artifacts(&[witness_path.as_path()])?;

    // -----------------------------------------------------------------------
    // Print output paths
    // -----------------------------------------------------------------------

    println!("{}", summary_path.display());
    println!("{}", verifier_path.display());
    println!("{}", calldata_path.display());
    println!("{}", audit_path.display());
    println!("{}", report_path.display());
    if project_dir.exists() {
        println!("{}", project_dir.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Core run function
// ---------------------------------------------------------------------------

fn run() -> ZkfResult<()> {
    if !SwarmConfig::is_enabled() {
        return Err(ZkfError::Backend(
            "swarm monitoring is required for this showcase; set ZKF_SWARM=1".to_string(),
        ));
    }

    let steps = integration_steps()?;
    let out_dir = output_dir(steps);
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;

    eprintln!("--- ZirOS Private Reentry Thermal-Safety Showcase ---");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 1: Build reentry circuit
    // -----------------------------------------------------------------------

    eprintln!("  [1/8] Building reentry circuit ({steps} integration steps)...");
    let build_start = Instant::now();

    let template = private_reentry_thermal_showcase_with_steps(steps)?;
    let original_program = template.program.clone();
    let valid_inputs: WitnessInputs = template.sample_inputs.clone();
    let (optimized_program, optimizer_report) = optimize_program(&original_program);

    let trusted_setup_requested = requested_groth16_setup_blob_path(&original_program).is_some();

    eprintln!(
        "         Circuit built in {:.2}s — {} constraints, {} signals",
        build_start.elapsed().as_secs_f64(),
        original_program.constraints.len(),
        original_program.signals.len(),
    );

    // -----------------------------------------------------------------------
    // Step 2: Audit the program
    // -----------------------------------------------------------------------

    eprintln!("  [2/8] Auditing program...");
    let audit_start = Instant::now();

    let audit = audit_program_with_live_capabilities_owned(
        original_program.clone(),
        Some(BackendKind::ArkworksGroth16),
    );
    let audit_dir = out_dir.join("audit");
    fs::create_dir_all(&audit_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
    let audit_report_path = audit_dir.join("private_reentry_thermal.audit.json");
    write_json(&audit_report_path, &audit)?;

    eprintln!(
        "         Audit complete in {:.2}s — {} checks, {} findings",
        audit_start.elapsed().as_secs_f64(),
        audit.summary.total_checks,
        audit.summary.failed + audit.summary.warned,
    );

    // -----------------------------------------------------------------------
    // Step 3: Compile for Groth16
    // -----------------------------------------------------------------------

    eprintln!("  [3/8] Compiling for Groth16...");
    let compile_start = Instant::now();

    let source_compiled = with_showcase_groth16_mode(trusted_setup_requested, || {
        zkf_backends::with_setup_seed_override(Some(SETUP_SEED), || {
            compile_arkworks_unchecked(&optimized_program)
        })
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

    eprintln!(
        "         Compiled in {:.2}s — digest: {}",
        compile_start.elapsed().as_secs_f64(),
        &source_compiled.program_digest[..16],
    );

    // -----------------------------------------------------------------------
    // Step 4: Generate witness
    // -----------------------------------------------------------------------

    eprintln!("  [4/8] Generating witness...");
    let witness_start = Instant::now();

    let base_witness = private_reentry_thermal_witness_with_steps(&valid_inputs, steps)?;
    let prepared_witness = prepare_witness_for_proving(&source_compiled, &base_witness)?;
    check_constraints(&source_compiled.program, &prepared_witness)?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    eprintln!(
        "         Witness generated and validated in {:.2}s — {} assignments",
        witness_start.elapsed().as_secs_f64(),
        prepared_witness.values.len(),
    );

    // -----------------------------------------------------------------------
    // Step 5: Prove via RuntimeExecutor
    // -----------------------------------------------------------------------

    eprintln!("  [5/8] Proving via RuntimeExecutor (strict cryptographic lane)...");
    let telemetry_before = telemetry_snapshot();
    let prove_start = Instant::now();

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
    let source_runtime_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;

    eprintln!(
        "         Proof generated in {:.2}s — {} bytes proof, {} bytes vk",
        prove_start.elapsed().as_secs_f64(),
        source_execution.artifact.proof.len(),
        source_execution.artifact.verification_key.len(),
    );
    eprintln!(
        "         GPU nodes: {} | CPU nodes: {} | Peak memory: {} bytes",
        source_execution.result.report.gpu_nodes,
        source_execution.result.report.cpu_nodes,
        source_execution.result.report.peak_memory_bytes,
    );
    if !source_execution.result.report.watchdog_alerts.is_empty() {
        eprintln!(
            "         Watchdog alerts: {}",
            source_execution.result.report.watchdog_alerts.len(),
        );
    }

    // -----------------------------------------------------------------------
    // Step 6: Verify the proof
    // -----------------------------------------------------------------------

    eprintln!("  [6/8] Verifying proof...");
    let verify_start = Instant::now();

    if !verify(&source_execution.compiled, &source_execution.artifact)? {
        return Err(ZkfError::Backend(
            "runtime groth16 proof verification returned false".to_string(),
        ));
    }

    eprintln!(
        "         Proof verified in {:.2}s",
        verify_start.elapsed().as_secs_f64(),
    );

    let telemetry_after = telemetry_snapshot();

    // -----------------------------------------------------------------------
    // Steps 7-8: Export and bundle (in large stack)
    // -----------------------------------------------------------------------

    run_with_large_stack_result("private-reentry-thermal-export", move || {
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
            trusted_setup_requested,
            trusted_setup_used,
            setup_provenance,
            security_boundary,
            telemetry_before,
            telemetry_after,
        };
        export_showcase_bundle(inputs)
    })?;

    eprintln!();
    eprintln!("--- Showcase complete ---");

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point — 256 MB stack
// ---------------------------------------------------------------------------

fn main() {
    let result = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .name("reentry-showcase".to_string())
        .spawn(|| run())
        .expect("thread spawn")
        .join()
        .expect("thread join");

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
