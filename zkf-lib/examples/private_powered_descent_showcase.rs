#![recursion_limit = "512"]

use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{
    ALLOW_DEV_DETERMINISTIC_GROTH16_ENV, BackendRoute, GROTH16_DETERMINISTIC_DEV_PROVENANCE,
    GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY, GROTH16_IMPORTED_SETUP_PROVENANCE,
    GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY, GROTH16_SETUP_BLOB_PATH_METADATA_KEY,
    GROTH16_SETUP_PROVENANCE_METADATA_KEY, GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY,
    capability_report_for_backend, compile_arkworks_unchecked, prepare_witness_for_proving,
    requested_groth16_setup_blob_path, with_setup_seed_override,
};
use zkf_backends::{
    Groth16ExecutionClassification, Groth16ExecutionSummary,
    groth16_execution_summary_from_metadata, with_proof_seed_override,
};
use zkf_core::ccs::CcsProgram;
use zkf_core::ir::LookupTable;
use zkf_core::{
    BackendKind, Constraint, FieldId, Program, Signal, Witness, WitnessInputs, check_constraints,
    json_from_reader, json_from_slice, optimize_program,
};
use zkf_lib::app::audit::audit_program_with_live_capabilities_owned;
use zkf_lib::app::descent::{
    PRIVATE_POWERED_DESCENT_DEFAULT_STEPS, PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS,
    PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS, PrivatePoweredDescentRequestV1,
    private_powered_descent_sample_request_with_steps, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness_with_steps,
};
use zkf_lib::evidence::{
    ShowcaseGroth16TrustMode, audit_entry_included, audit_entry_omitted_by_default,
    collect_formal_evidence_for_generated_app, effective_gpu_attribution_summary_with_outputs,
    ensure_dir_exists, ensure_file_exists, ensure_foundry_layout, foundry_project_dir,
    generated_app_closure_bundle_summary, repo_root, resolve_showcase_groth16_trust_mode,
    two_tier_audit_record, with_showcase_groth16_trust_mode,
};
use zkf_lib::{ZkfError, ZkfResult, export_groth16_solidity_verifier, verify};
use zkf_runtime::{
    BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
    RuntimeExecutor, SwarmConfig,
};

const APP_ID: &str = "private_powered_descent_showcase";
const SETUP_SEED: [u8; 32] = [0x31; 32];
const PROOF_SEED: [u8; 32] = [0x47; 32];
const FULL_AUDIT_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT";
const INPUTS_JSON_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_INPUTS_JSON";
const INTERNAL_MODE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_INTERNAL_MODE";
const PRODUCTION_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_PRODUCTION";
const BUNDLE_MODE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_BUNDLE_MODE";
const TRUSTED_SETUP_MANIFEST_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_TRUSTED_SETUP_MANIFEST";
const INTERNAL_MODE_PROVE_CORE: &str = "prove-core";
const INTERNAL_MODE_FINALIZE_BUNDLE: &str = "finalize-bundle";
const INTERNAL_MODE_FULL_SOURCE_AUDIT: &str = "full-source-audit";
const INTERNAL_MODE_FULL_COMPILED_AUDIT: &str = "full-compiled-audit";
const STEPS_OVERRIDE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_STEPS_OVERRIDE";
const TEST_FORCE_EXPLICIT_PROOF_SEED_ENV: &str =
    "ZKF_PRIVATE_POWERED_DESCENT_TEST_FORCE_EXPLICIT_PROOF_SEED";
const AUDIT_UNDERCONSTRAINED_MAX_DENSE_CELLS_ENV: &str =
    "ZKF_AUDIT_UNDERCONSTRAINED_MAX_DENSE_CELLS";
const COMPILED_AUDIT_UNDERCONSTRAINED_DENSE_CELL_CAP: usize = 50_000_000;
const EXPORT_STACK_GROW_RED_ZONE: usize = 8 * 1024 * 1024;
const EXPORT_STACK_GROW_SIZE: usize = 256 * 1024 * 1024;
const EXECUTION_TRACE_SCHEMA_VERSION: &str = "private-powered-descent-execution-trace-v3";
const TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION: &str =
    "private-powered-descent-trusted-setup-manifest-v1";
const TRUSTED_SETUP_MANIFEST_BUNDLE_FILENAME: &str =
    "private_powered_descent.groth16_setup_manifest.json";
const ARKWORKS_PRODUCTION_DISCLAIMER_REASON: &str = "upstream-ark-groth16-production-disclaimer";

fn with_showcase_groth16_mode<T, F: FnOnce() -> ZkfResult<T>>(
    trust_mode: ShowcaseGroth16TrustMode,
    f: F,
) -> ZkfResult<T> {
    with_showcase_groth16_trust_mode(trust_mode, f)
}

#[allow(unsafe_code)]
fn set_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: this example mutates process environment only from its single-threaded
    // CLI/test entrypoints, before spawning any worker threads that could observe
    // concurrent environment mutation.
    unsafe {
        env::set_var(key, value);
    }
}

#[allow(unsafe_code)]
fn remove_env_var(key: &str) {
    // SAFETY: see `set_env_var`; callers use this helper in the same single-threaded
    // setup/teardown path before concurrent work begins.
    unsafe {
        env::remove_var(key);
    }
}

fn ensure_showcase_groth16_setup_mode() {
    // Respect explicit operator overrides. Otherwise leave streamed-setup
    // selection to the backend so capable Apple Silicon hosts can choose the
    // streamed witness-map path instead of forcing CPU-only reduction.
}

fn log_runtime_gpu_summary(metadata: &BTreeMap<String, String>) {
    if let Some(summary) = groth16_execution_summary_from_metadata(metadata) {
        eprintln!(
            "private_powered_descent_showcase: runtime GPU summary: classification={} metal_available={} witness_map_engine={} witness_map_reason={} msm_engine={} msm_reason={} msm_fallback_state={} msm_dispatch_failure={}",
            summary.classification.as_str(),
            summary.metal_available,
            summary.witness_map.engine,
            summary.witness_map.reason,
            summary.msm.engine,
            summary.msm.reason,
            summary.msm.fallback_state,
            summary.msm.dispatch_failure.as_deref().unwrap_or("none"),
        );
        return;
    }

    let msm_engine = metadata
        .get("groth16_msm_engine")
        .map(String::as_str)
        .unwrap_or("unknown");
    let witness_map_engine = metadata
        .get("qap_witness_map_engine")
        .map(String::as_str)
        .unwrap_or("unknown");
    let no_cpu_fallback = metadata
        .get("metal_no_cpu_fallback")
        .map(String::as_str)
        .unwrap_or("unknown");
    let gpu_busy_ratio = metadata
        .get("metal_gpu_busy_ratio")
        .map(String::as_str)
        .unwrap_or("0.0");
    let stage_breakdown = metadata
        .get("metal_stage_breakdown")
        .map(String::as_str)
        .unwrap_or("{}");
    eprintln!(
        "private_powered_descent_showcase: runtime GPU summary: msm_engine={msm_engine} witness_map_engine={witness_map_engine} metal_no_cpu_fallback={no_cpu_fallback} metal_gpu_busy_ratio={gpu_busy_ratio} metal_stage_breakdown={stage_breakdown}"
    );
}

fn ensure_showcase_metal_realization(summary: &Groth16ExecutionSummary) -> ZkfResult<()> {
    if !summary.metal_available {
        eprintln!(
            "private_powered_descent_showcase: Metal unavailable on this host; allowing non-GPU Groth16 execution with classification={}",
            summary.classification.as_str()
        );
        return Ok(());
    }

    if summary.classification == Groth16ExecutionClassification::MetalRealized {
        return Ok(());
    }

    Err(ZkfError::Backend(format!(
        "powered descent showcase requires realized Metal Groth16 MSM when Metal is available, but execution classified as `{}` (witness_map_engine={} witness_map_reason={} msm_engine={} msm_reason={} msm_fallback_state={} msm_dispatch_failure={}).",
        summary.classification.as_str(),
        summary.witness_map.engine,
        summary.witness_map.reason,
        summary.msm.engine,
        summary.msm.reason,
        summary.msm.fallback_state,
        summary.msm.dispatch_failure.as_deref().unwrap_or("none"),
    )))
}

fn with_env_override<T, F: FnOnce() -> ZkfResult<T>>(
    key: &str,
    value: Option<OsString>,
    f: F,
) -> ZkfResult<T> {
    let previous = env::var_os(key);
    match value.as_ref() {
        Some(value) => set_env_var(key, value),
        None => remove_env_var(key),
    }
    let result = f();
    match previous {
        Some(previous) => set_env_var(key, previous),
        None => remove_env_var(key),
    }
    result
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
                    "serialize powered descent runtime stage breakdown: {error}"
                ))
            })?,
            watchdog_alerts: report.watchdog_alerts.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct TimingsSnapshot {
    compile_ms: f64,
    witness_prepare_ms: f64,
    runtime_strict_lane_source_prove_ms: f64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct SourceProveCheckpoint {
    runtime_report: RuntimeReportSnapshot,
    outputs: serde_json::Value,
    control_plane: Option<serde_json::Value>,
    security: Option<serde_json::Value>,
    model_integrity: Option<serde_json::Value>,
    swarm: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct ExportCheckpoint {
    mode: String,
    artifact_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ExportProfile {
    Development,
    Production,
}

impl ExportProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }

    fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BundleMode {
    Debug,
    Public,
}

impl BundleMode {
    fn parse(value: &str) -> ZkfResult<Self> {
        match value {
            "debug" => Ok(Self::Debug),
            "public" => Ok(Self::Public),
            other => Err(ZkfError::Backend(format!(
                "unsupported {BUNDLE_MODE_ENV} value {other:?} (expected `debug` or `public`)"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Public => "public",
        }
    }

    fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
struct TrustedSetupManifest {
    schema_version: String,
    setup_blob_sha256: String,
    vk_sha256: String,
    ceremony_id: String,
    ceremony_kind: String,
    ceremony_transcript_sha256: String,
    source: String,
    generated_at: String,
    notes: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
struct TrustedSetupManifestCheckpoint {
    bundle_relative_path: String,
    source_ref: String,
    manifest_sha256: String,
    manifest: TrustedSetupManifest,
    #[serde(skip, default)]
    source_manifest_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct ExecutionTraceCheckpoint {
    schema_version: String,
    app_id: String,
    export_profile: String,
    bundle_mode: String,
    release_safety: String,
    bundle_identity: serde_json::Value,
    request_mode: String,
    request_mode_sentence: String,
    request_source_ref: String,
    integration_steps: usize,
    default_step_count: usize,
    full_audit_requested: bool,
    declared_private_inputs: usize,
    optimizer_report: serde_json::Value,
    trusted_setup_requested: bool,
    trusted_setup_used: bool,
    setup_provenance: String,
    security_boundary: String,
    determinism: serde_json::Value,
    trusted_setup_manifest: Option<TrustedSetupManifestCheckpoint>,
    telemetry_artifacts: serde_json::Value,
    vehicle_parameters: serde_json::Value,
    formal_evidence: serde_json::Value,
    generated_closure: serde_json::Value,
    generated_closure_summary: serde_json::Value,
    timings_ms: TimingsSnapshot,
    source_prove: SourceProveCheckpoint,
    export: ExportCheckpoint,
}

#[derive(Debug, Clone)]
struct ShowcaseBundlePaths {
    project_dir: PathBuf,
    audit_dir: PathBuf,
    formal_dir: PathBuf,
    program_original_path: PathBuf,
    program_optimized_path: PathBuf,
    compiled_path: PathBuf,
    request_path: PathBuf,
    inputs_path: PathBuf,
    witness_base_path: PathBuf,
    witness_path: PathBuf,
    proof_path: PathBuf,
    verifier_path: PathBuf,
    calldata_path: PathBuf,
    summary_path: PathBuf,
    audit_path: PathBuf,
    audit_summary_path: PathBuf,
    evidence_manifest_path: PathBuf,
    matrix_path: PathBuf,
    runtime_trace_path: PathBuf,
    execution_trace_path: PathBuf,
    report_path: PathBuf,
    mission_assurance_path: PathBuf,
    bundle_readme_path: PathBuf,
    setup_manifest_path: PathBuf,
    foundry_verifier_path: PathBuf,
    foundry_test_path: PathBuf,
}

impl ShowcaseBundlePaths {
    fn new(out_dir: PathBuf) -> Self {
        let project_dir = foundry_project_dir_for_bundle(&out_dir);
        Self {
            audit_dir: out_dir.join("audit"),
            formal_dir: out_dir.join("formal"),
            program_original_path: out_dir.join("private_powered_descent.original.program.json"),
            program_optimized_path: out_dir.join("private_powered_descent.optimized.program.json"),
            compiled_path: out_dir.join("private_powered_descent.compiled.json"),
            request_path: out_dir.join("private_powered_descent.request.json"),
            inputs_path: out_dir.join("private_powered_descent.inputs.json"),
            witness_base_path: out_dir.join("private_powered_descent.witness.base.json"),
            witness_path: out_dir.join("private_powered_descent.witness.prepared.json"),
            proof_path: out_dir.join("private_powered_descent.runtime.proof.json"),
            verifier_path: out_dir.join("PrivatePoweredDescentVerifier.sol"),
            calldata_path: out_dir.join("private_powered_descent.calldata.json"),
            summary_path: out_dir.join("private_powered_descent.summary.json"),
            audit_path: out_dir.join("private_powered_descent.audit.json"),
            audit_summary_path: out_dir.join("private_powered_descent.audit_summary.json"),
            evidence_manifest_path: out_dir.join("private_powered_descent.evidence_manifest.json"),
            matrix_path: out_dir.join("private_powered_descent.matrix_ccs_summary.json"),
            runtime_trace_path: out_dir.join("private_powered_descent.runtime_trace.json"),
            execution_trace_path: out_dir.join("private_powered_descent.execution_trace.json"),
            report_path: out_dir.join("private_powered_descent.report.md"),
            mission_assurance_path: out_dir.join("private_powered_descent.mission_assurance.md"),
            bundle_readme_path: out_dir.join("README.md"),
            setup_manifest_path: out_dir.join(TRUSTED_SETUP_MANIFEST_BUNDLE_FILENAME),
            foundry_verifier_path: project_dir.join("src/PrivatePoweredDescentVerifier.sol"),
            foundry_test_path: project_dir.join("test/PrivatePoweredDescentVerifier.t.sol"),
            project_dir,
        }
    }
}

struct ShowcaseBundleDiskState {
    original_program: Program,
    optimized_program: Program,
    compiled: zkf_core::CompiledProgram,
    checkpoint: ExecutionTraceCheckpoint,
}

struct RuntimeArtifactSummary {
    proof_bytes: usize,
    verification_key_bytes: usize,
    verification_key_sha256: String,
    public_inputs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ProgramAuditView {
    #[serde(default)]
    name: String,
    #[serde(default)]
    field: FieldId,
    #[serde(default)]
    signals: Vec<Signal>,
    #[serde(default)]
    constraints: Vec<Constraint>,
    #[serde(default)]
    lookup_tables: Vec<LookupTable>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

impl From<ProgramAuditView> for Program {
    fn from(value: ProgramAuditView) -> Self {
        Self {
            name: value.name,
            field: value.field,
            signals: value.signals,
            constraints: value.constraints,
            witness_plan: Default::default(),
            lookup_tables: value.lookup_tables,
            metadata: value.metadata,
        }
    }
}

#[derive(serde::Deserialize)]
struct CompiledProgramAuditView {
    program_digest: String,
    program: ProgramAuditView,
}

struct LoadedAuditProgram {
    program: Program,
    program_digest_override: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InternalMode {
    Coordinator,
    ProveCore,
    FinalizeBundle,
    FullSourceAudit,
    FullCompiledAudit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FullAuditTarget {
    Source,
    Compiled,
}

impl FullAuditTarget {
    fn internal_mode(self) -> &'static str {
        match self {
            Self::Source => INTERNAL_MODE_FULL_SOURCE_AUDIT,
            Self::Compiled => INTERNAL_MODE_FULL_COMPILED_AUDIT,
        }
    }

    fn worker_name(self) -> &'static str {
        match self {
            Self::Source => "private-powered-descent-full-source-audit",
            Self::Compiled => "private-powered-descent-full-compiled-audit",
        }
    }

    fn heartbeat_label(self) -> &'static str {
        match self {
            Self::Source => "full-source-audit",
            Self::Compiled => "full-compiled-audit",
        }
    }

    fn checkpoint_label(self) -> &'static str {
        match self {
            Self::Source => "full source audit",
            Self::Compiled => "full compiled audit",
        }
    }

    fn bundle_relative_path(self) -> &'static str {
        match self {
            Self::Source => "audit/private_powered_descent.source_audit.json",
            Self::Compiled => "audit/private_powered_descent.compiled_audit.json",
        }
    }

    fn producer(self) -> &'static str {
        match self {
            Self::Source => {
                "audit_program_with_live_capabilities(original_program, Some(arkworks-groth16))"
            }
            Self::Compiled => {
                "audit_program_with_live_capabilities(compiled_program, Some(arkworks-groth16))"
            }
        }
    }

    fn output_path(self, paths: &ShowcaseBundlePaths) -> PathBuf {
        match self {
            Self::Source => paths
                .audit_dir
                .join("private_powered_descent.source_audit.json"),
            Self::Compiled => paths
                .audit_dir
                .join("private_powered_descent.compiled_audit.json"),
        }
    }
}

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

fn read_json<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn read_json_stream<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let file = fs::File::open(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    let reader = BufReader::new(file);
    json_from_reader(reader)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn read_text(path: &Path) -> ZkfResult<String> {
    fs::read_to_string(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))
}

fn args() -> Vec<OsString> {
    env::args_os().skip(1).collect()
}

fn serialize_value(label: &str, value: &impl Serialize) -> ZkfResult<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|error| ZkfError::Serialization(format!("serialize {label}: {error}")))
}

fn serialize_optional_value<T: Serialize>(
    label: &str,
    value: &Option<T>,
) -> ZkfResult<Option<serde_json::Value>> {
    value
        .as_ref()
        .map(|value| serialize_value(label, value))
        .transpose()
}

fn internal_mode() -> ZkfResult<InternalMode> {
    match env::var(INTERNAL_MODE_ENV) {
        Ok(value) if value == INTERNAL_MODE_PROVE_CORE => Ok(InternalMode::ProveCore),
        Ok(value) if value == INTERNAL_MODE_FINALIZE_BUNDLE => Ok(InternalMode::FinalizeBundle),
        Ok(value) if value == INTERNAL_MODE_FULL_SOURCE_AUDIT => Ok(InternalMode::FullSourceAudit),
        Ok(value) if value == INTERNAL_MODE_FULL_COMPILED_AUDIT => {
            Ok(InternalMode::FullCompiledAudit)
        }
        Ok(value) => Err(ZkfError::Backend(format!(
            "unsupported {INTERNAL_MODE_ENV} value {value:?}"
        ))),
        Err(env::VarError::NotPresent) => Ok(InternalMode::Coordinator),
        Err(error) => Err(ZkfError::Backend(format!(
            "read {INTERNAL_MODE_ENV}: {error}"
        ))),
    }
}

fn input_request_path() -> Option<PathBuf> {
    env::var_os(INPUTS_JSON_ENV).map(PathBuf::from).or_else(|| {
        let args = args();
        if args.len() >= 2 {
            args.first().map(PathBuf::from)
        } else {
            None
        }
    })
}

fn output_dir(steps: usize, request_driven: bool) -> PathBuf {
    let args = args();
    let out_arg = if env::var_os(INPUTS_JSON_ENV).is_some() {
        args.first()
    } else if args.len() >= 2 {
        args.get(1)
    } else {
        args.first()
    };
    out_arg.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(format!(
            "Desktop/ZirOS_Private_Powered_Descent_{steps}Step_{}",
            if request_driven { "Request" } else { "Default" }
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

fn bundle_mode() -> ZkfResult<BundleMode> {
    match env::var(BUNDLE_MODE_ENV) {
        Ok(value) => BundleMode::parse(value.trim()),
        Err(env::VarError::NotPresent) => Ok(BundleMode::Debug),
        Err(error) => Err(ZkfError::Backend(format!(
            "read {BUNDLE_MODE_ENV}: {error}"
        ))),
    }
}

fn export_profile() -> ExportProfile {
    if env_flag(PRODUCTION_ENV) {
        ExportProfile::Production
    } else {
        ExportProfile::Development
    }
}

fn full_audit_requested() -> bool {
    env_flag(FULL_AUDIT_ENV)
}

fn ensure_production_runtime_env_contract(export_profile: ExportProfile) -> ZkfResult<()> {
    if !export_profile.is_production() {
        return Ok(());
    }
    if env_flag(ALLOW_DEV_DETERMINISTIC_GROTH16_ENV) {
        return Err(ZkfError::Backend(format!(
            "powered descent production mode rejects {} because it re-enables deterministic development proving",
            ALLOW_DEV_DETERMINISTIC_GROTH16_ENV
        )));
    }
    if env_flag(TEST_FORCE_EXPLICIT_PROOF_SEED_ENV) {
        return Err(ZkfError::Backend(format!(
            "powered descent production mode rejects {} because explicit proof seed requests are not allowed",
            TEST_FORCE_EXPLICIT_PROOF_SEED_ENV
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_string(digest.as_ref())
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os_string = path.as_os_str().to_os_string();
    os_string.push(suffix);
    PathBuf::from(os_string)
}

fn trusted_setup_manifest_source_path(setup_blob_path: &Path) -> PathBuf {
    append_path_suffix(setup_blob_path, ".manifest.json")
}

fn requested_trusted_setup_manifest_path(setup_blob_path: &Path) -> PathBuf {
    env::var_os(TRUSTED_SETUP_MANIFEST_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| trusted_setup_manifest_source_path(setup_blob_path))
}

fn repo_relative_path_string(path: &Path) -> Option<String> {
    path.strip_prefix(repo_root()).ok().map(|relative| {
        relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    })
}

fn request_source_ref(path: Option<&Path>) -> String {
    match path {
        Some(path) => repo_relative_path_string(path)
            .unwrap_or_else(|| "redacted-external-request".to_string()),
        None => "template-sample-inputs".to_string(),
    }
}

fn trusted_setup_source_ref(path: &Path) -> String {
    repo_relative_path_string(path)
        .unwrap_or_else(|| "redacted-operator-supplied-setup".to_string())
}

fn sanitize_text_for_public_bundle(value: &str) -> String {
    let mut sanitized = value.to_string();
    let repo_root_text = repo_root().display().to_string();
    if !repo_root_text.is_empty() {
        sanitized = sanitized.replace(&repo_root_text, ".");
    }
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            sanitized = sanitized.replace(&home, "[redacted-home]");
        }
    }
    let temp_dir = std::env::temp_dir().display().to_string();
    if !temp_dir.is_empty() {
        sanitized = sanitized.replace(&temp_dir, "redacted-temporary-path");
    }
    for (needle, replacement) in [
        ("/Users/", "/redacted-users/"),
        ("/home/", "/redacted-home/"),
        ("/private/var/folders/", "/redacted-tmp/"),
        ("/var/folders/", "/redacted-tmp/"),
    ] {
        if sanitized.contains(needle) {
            sanitized = sanitized.replace(needle, replacement);
        }
    }
    sanitized
}

fn sanitize_json_for_public_bundle(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "output_dir" | "request_source_path" | "telemetry_paths"
                ) {
                    continue;
                }
                out.insert(key.clone(), sanitize_json_for_public_bundle(value));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sanitize_json_for_public_bundle).collect())
        }
        serde_json::Value::String(value) => {
            serde_json::Value::String(sanitize_text_for_public_bundle(value))
        }
        _ => value.clone(),
    }
}

fn telemetry_artifacts_surface(
    bundle_mode: BundleMode,
    telemetry_paths: &[String],
) -> serde_json::Value {
    if bundle_mode.is_public() || telemetry_paths.is_empty() {
        json!({
            "included": false,
            "count": telemetry_paths.len(),
        })
    } else {
        json!({
            "included": false,
            "count": telemetry_paths.len(),
            "paths": telemetry_paths,
        })
    }
}

fn ceremony_kind_is_demo_only(kind: &str) -> bool {
    let lowered = kind.to_ascii_lowercase();
    ["test", "demo", "fixture", "deterministic", "dev", "local"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

fn bundle_release_safety(
    bundle_mode: BundleMode,
    export_profile: ExportProfile,
    security_boundary: &str,
    determinism: &serde_json::Value,
    trusted_setup_manifest: Option<&TrustedSetupManifestCheckpoint>,
) -> &'static str {
    let deterministic_material_present = determinism.get("proof_seed_hex").is_some()
        || determinism.get("setup_seed_hex").is_some()
        || determinism
            .get("prove_deterministic")
            .and_then(serde_json::Value::as_str)
            == Some("true")
        || determinism
            .get("setup_deterministic")
            .and_then(serde_json::Value::as_str)
            == Some("true");
    if !bundle_mode.is_public()
        || !export_profile.is_production()
        || security_boundary != GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY
        || deterministic_material_present
    {
        return "demo-only";
    }
    match trusted_setup_manifest {
        Some(manifest) if !ceremony_kind_is_demo_only(&manifest.manifest.ceremony_kind) => {
            "release-safe"
        }
        _ => "demo-only",
    }
}

fn delete_if_exists(path: &Path) -> ZkfResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::metadata(path)
        .map_err(|error| ZkfError::Io(format!("stat {}: {error}", path.display())))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
            .map_err(|error| ZkfError::Io(format!("remove {}: {error}", path.display())))?;
    } else {
        fs::remove_file(path)
            .map_err(|error| ZkfError::Io(format!("remove {}: {error}", path.display())))?;
    }
    Ok(())
}

fn ensure_nonempty_manifest_field(value: &str, field: &str, path: &Path) -> ZkfResult<()> {
    if value.trim().is_empty() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} field `{field}` must be non-empty in {}",
            TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION,
            path.display()
        )));
    }
    Ok(())
}

fn load_and_validate_trusted_setup_manifest(
    setup_blob_path: &Path,
) -> ZkfResult<TrustedSetupManifestCheckpoint> {
    let manifest_path = requested_trusted_setup_manifest_path(setup_blob_path);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", manifest_path.display())))?;
    let manifest: TrustedSetupManifest = json_from_slice(&manifest_bytes).map_err(|error| {
        ZkfError::Serialization(format!("parse {}: {error}", manifest_path.display()))
    })?;
    if manifest.schema_version != TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} schema version {:?} does not match {}",
            manifest_path.display(),
            manifest.schema_version,
            TRUSTED_SETUP_MANIFEST_SCHEMA_VERSION
        )));
    }
    ensure_nonempty_manifest_field(
        &manifest.setup_blob_sha256,
        "setup_blob_sha256",
        &manifest_path,
    )?;
    ensure_nonempty_manifest_field(&manifest.vk_sha256, "vk_sha256", &manifest_path)?;
    ensure_nonempty_manifest_field(&manifest.ceremony_id, "ceremony_id", &manifest_path)?;
    ensure_nonempty_manifest_field(&manifest.ceremony_kind, "ceremony_kind", &manifest_path)?;
    ensure_nonempty_manifest_field(
        &manifest.ceremony_transcript_sha256,
        "ceremony_transcript_sha256",
        &manifest_path,
    )?;
    ensure_nonempty_manifest_field(&manifest.source, "source", &manifest_path)?;
    ensure_nonempty_manifest_field(&manifest.generated_at, "generated_at", &manifest_path)?;

    let setup_blob = fs::read(setup_blob_path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", setup_blob_path.display())))?;
    let actual_setup_blob_sha256 = sha256_hex(&setup_blob);
    if manifest.setup_blob_sha256 != actual_setup_blob_sha256 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} setup_blob_sha256 {} does not match the referenced setup blob digest {}",
            manifest_path.display(),
            manifest.setup_blob_sha256,
            actual_setup_blob_sha256
        )));
    }

    Ok(TrustedSetupManifestCheckpoint {
        bundle_relative_path: TRUSTED_SETUP_MANIFEST_BUNDLE_FILENAME.to_string(),
        source_ref: trusted_setup_source_ref(&manifest_path),
        manifest_sha256: sha256_hex(&manifest_bytes),
        manifest,
        source_manifest_path: manifest_path,
    })
}

fn copy_file(src: &Path, dst: &Path) -> ZkfResult<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    fs::copy(src, dst).map_err(|error| {
        ZkfError::Io(format!(
            "copy {} -> {}: {error}",
            src.display(),
            dst.display()
        ))
    })?;
    Ok(())
}

fn integration_steps_override() -> ZkfResult<usize> {
    match env::var(STEPS_OVERRIDE_ENV) {
        Ok(raw) => {
            let steps = raw.parse::<usize>().map_err(|error| {
                ZkfError::Backend(format!("parse {STEPS_OVERRIDE_ENV}={raw:?}: {error}"))
            })?;
            if steps == 0 {
                return Err(ZkfError::Backend(
                    "powered descent step override must be greater than zero".to_string(),
                ));
            }
            Ok(steps)
        }
        Err(env::VarError::NotPresent) => Ok(PRIVATE_POWERED_DESCENT_DEFAULT_STEPS),
        Err(error) => Err(ZkfError::Backend(format!(
            "read {STEPS_OVERRIDE_ENV}: {error}"
        ))),
    }
}

fn resolve_current_output_dir() -> ZkfResult<PathBuf> {
    let request_source_path = input_request_path();
    let steps = match request_source_path.as_deref() {
        Some(path) => request_input_payload(path)?.3,
        None => integration_steps_override()?,
    };
    Ok(output_dir(steps, request_source_path.is_some()))
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

fn stage_summary_from_snapshot(
    report: &RuntimeReportSnapshot,
    runtime_outputs: &serde_json::Value,
    artifact_metadata: &BTreeMap<String, String>,
) -> serde_json::Value {
    let gpu_attribution = effective_gpu_attribution_summary_with_outputs(
        report.gpu_nodes,
        report.gpu_busy_ratio,
        Some(runtime_outputs),
        artifact_metadata,
    );
    let groth16_execution = groth16_execution_summary_from_metadata(artifact_metadata);
    json!({
        "total_wall_time_ms": report.total_wall_time_ms,
        "peak_memory_bytes": report.peak_memory_bytes,
        "gpu_nodes": report.gpu_nodes,
        "cpu_nodes": report.cpu_nodes,
        "delegated_nodes": report.delegated_nodes,
        "fallback_nodes": report.fallback_nodes,
        "gpu_busy_ratio": report.gpu_busy_ratio,
        "groth16_execution": groth16_execution,
        "effective_gpu_attribution": gpu_attribution,
        "counter_source": report.counter_source,
        "stage_breakdown": report.stage_breakdown,
        "watchdog_alerts": report.watchdog_alerts,
    })
}

fn trusted_setup_manifest_surface(
    manifest: Option<&TrustedSetupManifestCheckpoint>,
    export_profile: ExportProfile,
) -> serde_json::Value {
    match manifest {
        Some(manifest) => json!({
            "status": "included",
            "operator_supplied": true,
            "bundle_path": manifest.bundle_relative_path,
            "source_ref": manifest.source_ref,
            "manifest_sha256": manifest.manifest_sha256,
            "schema_version": manifest.manifest.schema_version,
            "setup_blob_sha256": manifest.manifest.setup_blob_sha256,
            "vk_sha256": manifest.manifest.vk_sha256,
            "ceremony_id": manifest.manifest.ceremony_id,
            "ceremony_kind": manifest.manifest.ceremony_kind,
            "ceremony_transcript_sha256": manifest.manifest.ceremony_transcript_sha256,
            "source": manifest.manifest.source,
            "generated_at": manifest.manifest.generated_at,
            "notes": manifest.manifest.notes,
            "boundary": "operator-supplied-trusted-setup-record",
        }),
        None => json!({
            "status": if export_profile.is_production() {
                "missing"
            } else {
                "not-required"
            },
            "reason": if export_profile.is_production() {
                "production export profile requires a pinned trusted setup manifest"
            } else {
                "development export profile does not require a pinned trusted setup manifest"
            },
        }),
    }
}

fn production_readiness_surface(export_profile: ExportProfile) -> serde_json::Value {
    match capability_report_for_backend(BackendKind::ArkworksGroth16) {
        Some(report) => {
            let readiness_reason = report
                .readiness_reason
                .clone()
                .unwrap_or_else(|| ARKWORKS_PRODUCTION_DISCLAIMER_REASON.to_string());
            json!({
                "requested_profile": export_profile.as_str(),
                "ready": export_profile.is_production() && report.production_ready,
                "backend": BackendKind::ArkworksGroth16.as_str(),
                "backend_production_ready": report.production_ready,
                "backend_readiness": report.readiness,
                "backend_readiness_reason": readiness_reason,
                "operator_action": report.operator_action,
                "assurance_lane": report.assurance_lane,
            })
        }
        None => json!({
            "requested_profile": export_profile.as_str(),
            "ready": false,
            "backend": BackendKind::ArkworksGroth16.as_str(),
            "backend_production_ready": false,
            "backend_readiness": "unknown",
            "backend_readiness_reason": ARKWORKS_PRODUCTION_DISCLAIMER_REASON,
        }),
    }
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

fn request_input_payload(
    path: &Path,
) -> ZkfResult<(
    PrivatePoweredDescentRequestV1,
    WitnessInputs,
    serde_json::Value,
    usize,
)> {
    let raw = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    let request_json: serde_json::Value = serde_json::from_slice(&raw).map_err(|error| {
        ZkfError::Serialization(format!(
            "parse powered descent request {}: {error}",
            path.display()
        ))
    })?;
    let request: PrivatePoweredDescentRequestV1 = serde_json::from_value(request_json.clone())
        .map_err(|error| {
            ZkfError::Serialization(format!(
                "decode powered descent request {}: {error}",
                path.display()
            ))
        })?;
    let step_count = request.public.step_count;
    let witness_inputs = WitnessInputs::try_from(request.clone()).map_err(|error| {
        ZkfError::Serialization(format!(
            "convert powered descent request {} into WitnessInputs: {error}",
            path.display()
        ))
    })?;
    Ok((request, witness_inputs, request_json, step_count))
}

fn ensure_production_compile_contract(
    compiled: &zkf_core::CompiledProgram,
    trusted_setup_requested: bool,
    trusted_setup_used: bool,
    setup_provenance: &str,
    security_boundary: &str,
) -> ZkfResult<()> {
    if !trusted_setup_requested {
        return Err(ZkfError::Backend(
            "powered descent production mode requires an imported Groth16 setup blob before compile".to_string(),
        ));
    }
    if !trusted_setup_used {
        return Err(ZkfError::Backend(
            "powered descent production mode requires imported trusted setup material; deterministic and local-ceremony setup lanes are not accepted".to_string(),
        ));
    }
    if setup_provenance != GROTH16_IMPORTED_SETUP_PROVENANCE {
        return Err(ZkfError::InvalidArtifact(format!(
            "powered descent production mode expected setup provenance {}, got {setup_provenance}",
            GROTH16_IMPORTED_SETUP_PROVENANCE
        )));
    }
    if security_boundary != GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY {
        return Err(ZkfError::InvalidArtifact(format!(
            "powered descent production mode expected security boundary {}, got {security_boundary}",
            GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY
        )));
    }
    if compiled
        .metadata
        .get(GROTH16_SETUP_BLOB_PATH_METADATA_KEY)
        .is_none()
    {
        return Err(ZkfError::InvalidArtifact(
            "powered descent production mode compiled artifact is missing groth16_setup_blob_path metadata".to_string(),
        ));
    }
    if compiled.metadata.contains_key("setup_seed_hex") {
        return Err(ZkfError::InvalidArtifact(
            "powered descent production mode compiled artifact must not expose setup_seed_hex"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_production_proof_contract(runtime_artifact: &zkf_core::ProofArtifact) -> ZkfResult<()> {
    let prove_deterministic = runtime_artifact
        .metadata
        .get("prove_deterministic")
        .map(String::as_str);
    if prove_deterministic != Some("false") {
        return Err(ZkfError::InvalidArtifact(format!(
            "powered descent production mode expected prove_deterministic=false, got {prove_deterministic:?}"
        )));
    }
    let prove_seed_source = runtime_artifact
        .metadata
        .get("prove_seed_source")
        .map(String::as_str);
    if prove_seed_source != Some("system-rng") {
        return Err(ZkfError::InvalidArtifact(format!(
            "powered descent production mode expected prove_seed_source=system-rng, got {prove_seed_source:?}"
        )));
    }
    if runtime_artifact.metadata.contains_key("prove_seed_hex") {
        return Err(ZkfError::InvalidArtifact(
            "powered descent production mode proof metadata must not expose prove_seed_hex"
                .to_string(),
        ));
    }
    Ok(())
}

fn load_trusted_setup_manifest_from_bundle(
    paths: &ShowcaseBundlePaths,
    checkpoint: &ExecutionTraceCheckpoint,
    verification_key_sha256: &str,
) -> ZkfResult<Option<TrustedSetupManifestCheckpoint>> {
    let Some(expected_manifest) = checkpoint.trusted_setup_manifest.as_ref() else {
        return Ok(None);
    };

    ensure_file_exists(&paths.setup_manifest_path)?;
    let manifest_bytes = fs::read(&paths.setup_manifest_path).map_err(|error| {
        ZkfError::Io(format!(
            "read {}: {error}",
            paths.setup_manifest_path.display()
        ))
    })?;
    let manifest: TrustedSetupManifest = json_from_slice(&manifest_bytes).map_err(|error| {
        ZkfError::Serialization(format!(
            "parse {}: {error}",
            paths.setup_manifest_path.display()
        ))
    })?;
    let actual_manifest = TrustedSetupManifestCheckpoint {
        bundle_relative_path: expected_manifest.bundle_relative_path.clone(),
        source_ref: expected_manifest.source_ref.clone(),
        manifest_sha256: sha256_hex(&manifest_bytes),
        manifest,
        source_manifest_path: PathBuf::new(),
    };
    if &actual_manifest != expected_manifest {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not match the prove-core checkpoint manifest record",
            paths.setup_manifest_path.display()
        )));
    }
    if actual_manifest.manifest.vk_sha256 != verification_key_sha256 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} vk_sha256 {} does not match the proof-facing verification key digest {}",
            paths.setup_manifest_path.display(),
            actual_manifest.manifest.vk_sha256,
            verification_key_sha256
        )));
    }

    Ok(Some(actual_manifest))
}

fn report_markdown(
    _compiled: &zkf_core::CompiledProgram,
    public_map: &BTreeMap<String, String>,
    runtime_proof_bytes: usize,
    runtime_verification_key_bytes: usize,
    runtime_report: &RuntimeReportSnapshot,
    integration_steps: usize,
    bundle_identity: &serde_json::Value,
    runtime_memory_plan: &serde_json::Value,
    runtime_buffer_bridge: &serde_json::Value,
    request_mode_sentence: &str,
    vehicle_parameters: &serde_json::Value,
    export_profile: ExportProfile,
    bundle_mode: BundleMode,
    release_safety: &str,
    setup_provenance: &str,
    security_boundary: &str,
    determinism: serde_json::Value,
    request_source_ref: &str,
    telemetry_artifacts: &serde_json::Value,
    gpu_attribution: &serde_json::Value,
    formal_evidence: &serde_json::Value,
    audit_summary: &serde_json::Value,
    generated_closure: &serde_json::Value,
    production_readiness: &serde_json::Value,
    trusted_setup_manifest: &serde_json::Value,
) -> String {
    let stage_breakdown = json_pretty(&runtime_report.stage_breakdown);
    let formal_status = formal_evidence
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let formal_sentence = if formal_status == "included" {
        "The bundle includes `formal/STATUS.md`, `formal/exercised_surfaces.json`, and bundled Rocq, protocol-Lean, and powered-descent Verus logs for this surface."
    } else {
        "The bundle attempted to collect formal evidence under `formal/`; `formal/STATUS.md`, `formal/exercised_surfaces.json`, and the Rocq, protocol-Lean, and powered-descent Verus logs record any runner failures explicitly."
    };
    let final_takeaway = if formal_status == "included" {
        "The mission-level takeaway is simple: the powered descent showcase is exported as a deterministic, replayable artifact bundle with bundled formal logs, a generated implementation-closure extract, explicit provenance, and explicit audit boundaries."
    } else {
        "The mission-level takeaway is simple: the powered descent showcase is exported as a deterministic, replayable artifact bundle with a generated implementation-closure extract, explicit provenance, explicit audit boundaries, and an explicit formal-evidence failure record when any configured proof runner does not pass."
    };
    let exported_surface_lines = if bundle_mode.is_public() {
        [
            "- Groth16 proof artifact JSON",
            "- Solidity verifier source",
            "- calldata JSON",
            "- Foundry project with pinned `solc 0.8.26`",
            "- summary / audit / runtime trace / evidence manifest JSON",
            "- bundle-local README and assurance report",
            "- formal evidence subtree and generated closure extract",
        ]
        .join("\n")
    } else {
        [
            "- original / optimized / compiled program JSON",
            "- request / inputs / witness JSON",
            "- Groth16 proof artifact JSON",
            "- Solidity verifier source",
            "- calldata JSON",
            "- Foundry project with pinned `solc 0.8.26`",
            "- CCS / matrix summary JSON",
            "- runtime trace / audit summary / evidence manifest JSON",
            "- mission assurance report",
        ]
        .join("\n")
    };

    format!(
        r#"# ZirOS Private Powered Descent Showcase

## Executive Summary

This bundle contains a private powered-descent guidance showcase built on ZirOS and emitted through the strict cryptographic Groth16 runtime/export stack. The circuit is built with `ProgramBuilder` over BN254, uses exactly {steps} fixed `dt` steps, keeps the initial state, wet mass, specific impulse, and per-step thrust vectors private, and exposes five public outputs: a trajectory commitment, a final landing-position commitment, a fail-closed constraint-satisfaction certificate fixed to `1`, the final mass, and the running minimum altitude.

{request_mode_sentence}

The runtime proof was `{proof_size}` bytes and the verification key was `{vk_size}` bytes.

This bundle was emitted under the `{export_profile}` export profile.
The exported distribution surface is `{bundle_mode}` and the release safety label is `{release_safety}`.

The Groth16 setup provenance for this run was `{setup_provenance}` and the security boundary label was `{security_boundary}`. When the security boundary is `development-only`, the export is intentionally marked as development-only and should not be treated as release-safe.

Production readiness summary:

`{production_readiness}`

Trusted setup manifest surface:

`{trusted_setup_manifest}`

The kernel uses deterministic fixed-point arithmetic at scale `10^18`, Euler integration over the translational 6-state `[r_x, r_y, r_z, v_x, v_y, v_z]`, bounded quotient/remainder witnesses for division, and witnessed integer square roots for thrust magnitude and glide-slope checks. The `constraint_satisfaction` output is a certificate bit fixed to `1` for accepted descents; invalid descents fail closed instead of exporting `0`.

## What Was Exported

The bundle exports the standard downstream surfaces:

{exported_surface_lines}

## Runtime Path

The proving path used the strict runtime lane with deterministic execution and Swarm enabled. The current stage snapshot was:

`{stage_breakdown}`

Request source reference:

`{request_source_ref}`

Telemetry artifact summary:

`{telemetry_artifacts}`

Bundle-local GPU attribution summary:

`{gpu_attribution}`

Bundle identity:

`{bundle_identity}`

Runtime memory plan:

`{runtime_memory_plan}`

Buffer residency / spill summary:

`{runtime_buffer_bridge}`

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

Determinism and exported trust-lane settings:

`{determinism}`

## Public Surface

Public inputs:

- `thrust_min`
- `thrust_max`
- `glide_slope_tangent`
- `max_landing_velocity`
- `landing_zone_radius`
- `landing_zone_center_x`
- `landing_zone_center_y`
- `g_z`

Public outputs:

`{public_map:?}`

Vehicle parameters:

`{vehicle_parameters}`

## Assessment

This export keeps the proof surface explicit and inspectable. The verifier assets, calldata, and Foundry harness are generated from the same proof artifact, and the bundle records the model boundary honestly: `development-only` stays `development-only`, imported trusted CRS stays `trusted-imported`, and `demo-only` never claims to be `release-safe`.

{final_takeaway}
"#,
        steps = integration_steps,
        bundle_identity = json_pretty(bundle_identity),
        runtime_memory_plan = json_pretty(runtime_memory_plan),
        runtime_buffer_bridge = json_pretty(runtime_buffer_bridge),
        request_mode_sentence = request_mode_sentence,
        vehicle_parameters = json_pretty(vehicle_parameters),
        export_profile = export_profile.as_str(),
        bundle_mode = bundle_mode.as_str(),
        release_safety = release_safety,
        setup_provenance = setup_provenance,
        security_boundary = security_boundary,
        stage_breakdown = stage_breakdown,
        proof_size = runtime_proof_bytes,
        vk_size = runtime_verification_key_bytes,
        request_source_ref = request_source_ref,
        telemetry_artifacts = json_pretty(telemetry_artifacts),
        gpu_attribution = json_pretty(gpu_attribution),
        formal_evidence = json_pretty(formal_evidence),
        generated_closure = json_pretty(generated_closure),
        audit_summary = json_pretty(audit_summary),
        production_readiness = json_pretty(production_readiness),
        trusted_setup_manifest = json_pretty(trusted_setup_manifest),
        determinism = determinism,
        public_map = public_map,
        exported_surface_lines = exported_surface_lines,
        final_takeaway = final_takeaway,
    )
}

fn bundle_readme_markdown(bundle_mode: BundleMode, release_safety: &str) -> String {
    format!(
        r#"# Private Powered Descent Bundle

This directory is a self-contained powered descent showcase bundle emitted by ZirOS.

- `bundle_mode`: `{bundle_mode}`
- `release_safety`: `{release_safety}`
- `formal/STATUS.md`: current bundled formal-evidence status
- `private_powered_descent.summary.json`: bundle summary and trust-lane metadata
- `private_powered_descent.evidence_manifest.json`: machine-readable audit / formal / GPU evidence

Verification commands:

```sh
cd foundry
forge fmt --check
forge test
forge coverage --report summary --report lcov
```

Release policy:

- `demo-only` bundles are reproducible showcase artifacts, not release-safe proof-bearing releases.
- `release-safe` bundles require operator-supplied trusted setup provenance and a public bundle surface.
"#,
        bundle_mode = bundle_mode.as_str(),
        release_safety = release_safety,
    )
}

fn sanitize_public_text_artifacts(paths: &[&Path]) -> ZkfResult<()> {
    for path in paths {
        if !path.exists() {
            continue;
        }
        let text = read_text(path)?;
        write_text(path, &sanitize_text_for_public_bundle(&text))?;
    }
    Ok(())
}

fn finalize_public_bundle(
    paths: &ShowcaseBundlePaths,
    full_audit_requested: bool,
) -> ZkfResult<()> {
    for path in [
        &paths.program_original_path,
        &paths.program_optimized_path,
        &paths.compiled_path,
        &paths.request_path,
        &paths.inputs_path,
        &paths.witness_base_path,
        &paths.witness_path,
        &paths.matrix_path,
    ] {
        delete_if_exists(path)?;
    }
    if !full_audit_requested {
        delete_if_exists(&paths.audit_dir)?;
    }
    sanitize_public_text_artifacts(&[
        &paths.formal_dir.join("STATUS.md"),
        &paths.formal_dir.join("rocq.log"),
        &paths.formal_dir.join("protocol_lean.log"),
        &paths.formal_dir.join("verus_powered_descent.log"),
        &paths.report_path,
        &paths.mission_assurance_path,
        &paths.bundle_readme_path,
    ])?;
    Ok(())
}

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    F: FnOnce() -> ZkfResult<T>,
{
    let _ = name;
    stacker::maybe_grow(EXPORT_STACK_GROW_RED_ZONE, EXPORT_STACK_GROW_SIZE, f)
}

fn run_with_heartbeat_result<T, F>(label: &str, f: F) -> ZkfResult<T>
where
    F: FnOnce() -> ZkfResult<T>,
{
    let label = label.to_string();
    let start = Instant::now();
    let result = std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<()>();
        let heartbeat_label = label.clone();
        scope.spawn(move || loop {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    eprintln!(
                        "private_powered_descent_showcase: export heartbeat: {heartbeat_label} running ({:.2}s)",
                        start.elapsed().as_secs_f64()
                    );
                }
            }
        });

        let result = stacker::maybe_grow(EXPORT_STACK_GROW_RED_ZONE, EXPORT_STACK_GROW_SIZE, f);
        let _ = tx.send(());
        result
    });
    eprintln!(
        "private_powered_descent_showcase: export checkpoint: {label} complete in {:.2}s",
        start.elapsed().as_secs_f64()
    );
    result
}

struct ShowcaseExportInputs {
    out_dir: PathBuf,
    export_profile: ExportProfile,
    integration_steps: usize,
    declared_private_inputs: usize,
    original_program: Program,
    optimized_program: Program,
    optimizer_report: zkf_core::OptimizeReport,
    valid_inputs: WitnessInputs,
    base_witness: Witness,
    prepared_witness: Witness,
    effective_request: PrivatePoweredDescentRequestV1,
    request_json: Option<serde_json::Value>,
    request_source_path: Option<PathBuf>,
    source_execution: BackendProofExecutionResult,
    compile_ms: f64,
    witness_ms: f64,
    source_runtime_ms: f64,
    trusted_setup_requested: bool,
    trusted_setup_used: bool,
    setup_provenance: String,
    security_boundary: String,
    trusted_setup_manifest: Option<TrustedSetupManifestCheckpoint>,
    full_audit_requested: bool,
    telemetry_before: BTreeSet<String>,
    telemetry_after: BTreeSet<String>,
}

fn ensure_core_bundle_files(
    paths: &ShowcaseBundlePaths,
    request_json_present: bool,
    trusted_setup_manifest_present: bool,
) -> ZkfResult<()> {
    ensure_file_exists(&paths.program_original_path)?;
    ensure_file_exists(&paths.program_optimized_path)?;
    ensure_file_exists(&paths.compiled_path)?;
    if request_json_present {
        ensure_file_exists(&paths.request_path)?;
    }
    ensure_file_exists(&paths.inputs_path)?;
    ensure_file_exists(&paths.witness_base_path)?;
    ensure_file_exists(&paths.witness_path)?;
    ensure_file_exists(&paths.proof_path)?;
    ensure_file_exists(&paths.verifier_path)?;
    ensure_file_exists(&paths.calldata_path)?;
    ensure_file_exists(&paths.matrix_path)?;
    ensure_file_exists(&paths.execution_trace_path)?;
    ensure_dir_exists(&paths.project_dir)?;
    ensure_file_exists(&paths.project_dir.join("foundry.toml"))?;
    ensure_file_exists(&paths.foundry_verifier_path)?;
    ensure_file_exists(&paths.foundry_test_path)?;
    if trusted_setup_manifest_present {
        ensure_file_exists(&paths.setup_manifest_path)?;
    }
    Ok(())
}

fn ensure_formal_bundle_files(paths: &ShowcaseBundlePaths) -> ZkfResult<()> {
    ensure_dir_exists(&paths.formal_dir)?;
    ensure_file_exists(&paths.formal_dir.join("STATUS.md"))?;
    ensure_file_exists(&paths.formal_dir.join("rocq.log"))?;
    ensure_file_exists(&paths.formal_dir.join("protocol_lean.log"))?;
    ensure_file_exists(&paths.formal_dir.join("verus_powered_descent.log"))?;
    ensure_file_exists(&paths.formal_dir.join("exercised_surfaces.json"))?;
    Ok(())
}

fn validate_verifier_and_foundry(paths: &ShowcaseBundlePaths) -> ZkfResult<()> {
    let verifier_source_from_disk = read_text(&paths.verifier_path)?;
    if !verifier_source_from_disk.contains("contract PrivatePoweredDescentVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not contain the expected verifier contract",
            paths.verifier_path.display()
        )));
    }

    let foundry_toml = read_text(&paths.project_dir.join("foundry.toml"))?;
    if !foundry_toml.contains("[profile.default]")
        || !foundry_toml.contains("solc_version = \"0.8.26\"")
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} is not a valid Foundry project manifest",
            paths.project_dir.join("foundry.toml").display()
        )));
    }

    let foundry_test_source = read_text(&paths.foundry_test_path)?;
    if !foundry_test_source.contains("PrivatePoweredDescentVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not reference the expected verifier contract",
            paths.foundry_test_path.display()
        )));
    }

    Ok(())
}

fn format_foundry_project(paths: &ShowcaseBundlePaths) -> ZkfResult<()> {
    let status = Command::new("forge")
        .current_dir(&paths.project_dir)
        .arg("fmt")
        .status()
        .map_err(|error| {
            ZkfError::Io(format!(
                "run forge fmt in {}: {error}",
                paths.project_dir.display()
            ))
        })?;
    if !status.success() {
        return Err(ZkfError::Backend(format!(
            "forge fmt failed for {} with status {status}",
            paths.project_dir.display()
        )));
    }
    let formatted_verifier = read_text(&paths.foundry_verifier_path)?;
    let formatted_test = read_text(&paths.foundry_test_path)?;
    let normalized_test = normalize_foundry_test_view_annotations(&formatted_test);
    write_text(&paths.verifier_path, &formatted_verifier)?;
    write_text(&paths.foundry_verifier_path, &formatted_verifier)?;
    write_text(&paths.foundry_test_path, &normalized_test)?;
    Ok(())
}

fn normalize_foundry_test_view_annotations(source: &str) -> String {
    [
        (
            "function test_tamperedProofFails() public {",
            "function test_tamperedProofFails() public view {",
        ),
        (
            "function test_wrongPublicInputArityFails() public {",
            "function test_wrongPublicInputArityFails() public view {",
        ),
        (
            "function test_scalarFieldOverflowInputFails() public {",
            "function test_scalarFieldOverflowInputFails() public view {",
        ),
        (
            "function testFuzz_nonZeroPublicInputDeltaFails(uint256 deltaRaw) public {",
            "function testFuzz_nonZeroPublicInputDeltaFails(uint256 deltaRaw) public view {",
        ),
        (
            "function testFuzz_proofCoordinateTamperingFails(uint256 deltaRaw) public {",
            "function testFuzz_proofCoordinateTamperingFails(uint256 deltaRaw) public view {",
        ),
    ]
    .into_iter()
    .fold(source.to_owned(), |acc, (from, to)| acc.replace(from, to))
}

fn load_execution_trace_checkpoint(
    paths: &ShowcaseBundlePaths,
) -> ZkfResult<ExecutionTraceCheckpoint> {
    ensure_file_exists(&paths.execution_trace_path)?;
    let checkpoint: ExecutionTraceCheckpoint = read_json(&paths.execution_trace_path)?;
    if checkpoint.schema_version != EXECUTION_TRACE_SCHEMA_VERSION {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} schema version {:?} does not match {}",
            paths.execution_trace_path.display(),
            checkpoint.schema_version,
            EXECUTION_TRACE_SCHEMA_VERSION
        )));
    }
    if checkpoint.app_id != APP_ID {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} app_id {:?} does not match {}",
            paths.execution_trace_path.display(),
            checkpoint.app_id,
            APP_ID
        )));
    }
    match checkpoint.export_profile.as_str() {
        "development" | "production" => {}
        other => {
            return Err(ZkfError::InvalidArtifact(format!(
                "{} export_profile {:?} is not one of [\"development\", \"production\"]",
                paths.execution_trace_path.display(),
                other
            )));
        }
    }
    match checkpoint.bundle_mode.as_str() {
        "debug" | "public" => {}
        other => {
            return Err(ZkfError::InvalidArtifact(format!(
                "{} bundle_mode {:?} is not one of [\"debug\", \"public\"]",
                paths.execution_trace_path.display(),
                other
            )));
        }
    }
    Ok(checkpoint)
}

fn ensure_bundle_checkpoint_files(
    paths: &ShowcaseBundlePaths,
    checkpoint: &ExecutionTraceCheckpoint,
) -> ZkfResult<()> {
    let request_json_present = checkpoint.request_mode == "request-json-v1";
    ensure_core_bundle_files(
        paths,
        request_json_present,
        checkpoint.trusted_setup_manifest.is_some(),
    )?;
    ensure_formal_bundle_files(paths)?;
    Ok(())
}

fn load_bundle_disk_state(paths: &ShowcaseBundlePaths) -> ZkfResult<ShowcaseBundleDiskState> {
    let checkpoint = load_execution_trace_checkpoint(paths)?;
    ensure_bundle_checkpoint_files(paths, &checkpoint)?;
    let request_json_present = checkpoint.request_mode == "request-json-v1";

    let original_program: Program = read_json(&paths.program_original_path)?;
    let optimized_program: Program = read_json(&paths.program_optimized_path)?;
    let compiled: zkf_core::CompiledProgram = read_json_stream(&paths.compiled_path)?;
    let _request_json_from_disk: Option<serde_json::Value> = if request_json_present {
        Some(read_json(&paths.request_path)?)
    } else if paths.request_path.exists() {
        Some(read_json(&paths.request_path)?)
    } else {
        None
    };
    let _: serde_json::Value = read_json(&paths.calldata_path)?;
    let _: serde_json::Value = read_json(&paths.matrix_path)?;
    validate_verifier_and_foundry(paths)?;

    Ok(ShowcaseBundleDiskState {
        original_program,
        optimized_program,
        compiled,
        checkpoint,
    })
}

fn load_program_for_full_audit(
    paths: &ShowcaseBundlePaths,
    target: FullAuditTarget,
) -> ZkfResult<LoadedAuditProgram> {
    let _checkpoint = load_execution_trace_checkpoint(paths)?;
    match target {
        FullAuditTarget::Source => {
            ensure_file_exists(&paths.program_original_path)?;
            Ok(LoadedAuditProgram {
                program: read_json(&paths.program_original_path)?,
                program_digest_override: None,
            })
        }
        FullAuditTarget::Compiled => {
            ensure_file_exists(&paths.compiled_path)?;
            let compiled: CompiledProgramAuditView = read_json_stream(&paths.compiled_path)?;
            Ok(LoadedAuditProgram {
                program: compiled.program.into(),
                program_digest_override: Some(compiled.program_digest),
            })
        }
    }
}

fn load_full_audit_report_from_disk(
    paths: &ShowcaseBundlePaths,
    target: FullAuditTarget,
) -> ZkfResult<serde_json::Value> {
    let audit_path = target.output_path(paths);
    ensure_file_exists(&audit_path)?;
    let audit_report: serde_json::Value = read_json(&audit_path)?;
    if audit_report.get("summary").is_none() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not contain an audit summary",
            audit_path.display()
        )));
    }
    Ok(audit_report)
}

fn run_full_audit_worker(out_dir: PathBuf, target: FullAuditTarget) -> ZkfResult<()> {
    let paths = ShowcaseBundlePaths::new(out_dir);
    fs::create_dir_all(&paths.audit_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", paths.audit_dir.display())))?;
    let LoadedAuditProgram {
        program,
        program_digest_override,
    } = load_program_for_full_audit(&paths, target)?;
    let underconstrained_cell_cap = match target {
        FullAuditTarget::Source => None,
        FullAuditTarget::Compiled => Some(OsString::from(
            COMPILED_AUDIT_UNDERCONSTRAINED_DENSE_CELL_CAP.to_string(),
        )),
    };
    let mut audit_report = run_with_heartbeat_result(target.heartbeat_label(), move || {
        with_env_override(
            AUDIT_UNDERCONSTRAINED_MAX_DENSE_CELLS_ENV,
            underconstrained_cell_cap,
            || {
                Ok(audit_program_with_live_capabilities_owned(
                    program,
                    Some(BackendKind::ArkworksGroth16),
                ))
            },
        )
    })?;
    if let Some(program_digest) = program_digest_override {
        audit_report.program_digest = Some(program_digest);
    }
    let audit_path = target.output_path(&paths);
    write_json(&audit_path, &audit_report)?;
    let _: serde_json::Value = load_full_audit_report_from_disk(&paths, target)?;
    Ok(())
}

fn spawn_full_audit_child_and_reload(
    paths: &ShowcaseBundlePaths,
    target: FullAuditTarget,
) -> ZkfResult<serde_json::Value> {
    eprintln!(
        "private_powered_descent_showcase: export checkpoint: {}",
        target.checkpoint_label()
    );
    spawn_showcase_child(target.internal_mode())?;
    load_full_audit_report_from_disk(paths, target)
}

fn load_verified_runtime_artifact_summary(
    paths: &ShowcaseBundlePaths,
    compiled: &zkf_core::CompiledProgram,
    expected_metadata: &BTreeMap<String, String>,
) -> ZkfResult<RuntimeArtifactSummary> {
    let runtime_artifact: zkf_core::ProofArtifact = read_json(&paths.proof_path)?;
    if !verify(compiled, &runtime_artifact)? {
        return Err(ZkfError::Backend(
            "disk-loaded runtime proof verification returned false".to_string(),
        ));
    }
    if &runtime_artifact.metadata != expected_metadata {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} metadata does not match the prove-core checkpoint",
            paths.proof_path.display()
        )));
    }

    Ok(RuntimeArtifactSummary {
        proof_bytes: runtime_artifact.proof.len(),
        verification_key_bytes: runtime_artifact.verification_key.len(),
        verification_key_sha256: sha256_hex(&runtime_artifact.verification_key),
        public_inputs: runtime_artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect(),
    })
}

fn write_core_artifacts_and_checkpoint(inputs: ShowcaseExportInputs) -> ZkfResult<()> {
    eprintln!("private_powered_descent_showcase: export checkpoint: prove-core start");
    let ShowcaseExportInputs {
        out_dir,
        export_profile,
        integration_steps,
        declared_private_inputs,
        original_program,
        optimized_program,
        optimizer_report,
        valid_inputs,
        base_witness,
        prepared_witness,
        effective_request,
        request_json,
        request_source_path,
        source_execution,
        compile_ms,
        witness_ms,
        source_runtime_ms,
        trusted_setup_requested,
        trusted_setup_used,
        setup_provenance,
        security_boundary,
        trusted_setup_manifest,
        full_audit_requested,
        telemetry_before,
        telemetry_after,
    } = inputs;

    let paths = ShowcaseBundlePaths::new(out_dir.clone());
    ensure_foundry_layout_local(&paths.project_dir)?;
    let bundle_mode = bundle_mode()?;

    let BackendProofExecutionResult {
        result: runtime_result,
        compiled,
        artifact: runtime_artifact,
    } = source_execution;

    if export_profile.is_production() {
        ensure_production_compile_contract(
            &compiled,
            trusted_setup_requested,
            trusted_setup_used,
            &setup_provenance,
            &security_boundary,
        )?;
        ensure_production_proof_contract(&runtime_artifact)?;
    }

    let runtime_report = RuntimeReportSnapshot::from_report(&runtime_result.report)?;
    let verifier_source =
        export_groth16_solidity_verifier(&runtime_artifact, Some("PrivatePoweredDescentVerifier"))?;
    let calldata = proof_to_calldata_json(&runtime_artifact.proof, &runtime_artifact.public_inputs)
        .map_err(ZkfError::Backend)?;
    let foundry_test = generate_foundry_test_from_artifact(
        &runtime_artifact.proof,
        &runtime_artifact.public_inputs,
        "../src/PrivatePoweredDescentVerifier.sol",
        "PrivatePoweredDescentVerifier",
    )
    .map_err(ZkfError::Backend)?;
    let matrix_summary = ccs_summary(&compiled)?;
    let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
    let runtime_memory_plan = runtime_result
        .outputs
        .get("runtime_memory_plan")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let runtime_buffer_bridge = runtime_result
        .outputs
        .get("runtime_buffer_bridge")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let request_mode = if request_json.is_some() {
        "request-json-v1"
    } else {
        "template-sample-inputs"
    };
    let request_source_ref = request_source_ref(request_source_path.as_deref());
    let bundle_identity = json!({
        "app_id": APP_ID,
        "bundle_root": ".",
        "artifact_prefix": "private_powered_descent",
        "circuit_name": original_program.name,
        "integration_steps": integration_steps,
        "default_step_count": PRIVATE_POWERED_DESCENT_DEFAULT_STEPS,
        "request_mode": request_mode,
        "bundle_mode": bundle_mode.as_str(),
    });
    let vehicle_parameters = json!({
        "private": effective_request.private,
        "public": effective_request.public,
    });
    let request_mode_sentence = if request_json.is_some() {
        format!(
            "This export is a request-driven `{integration_steps}`-step instance; the built-in showcase default remains `{PRIVATE_POWERED_DESCENT_DEFAULT_STEPS}` steps."
        )
    } else if integration_steps == PRIVATE_POWERED_DESCENT_DEFAULT_STEPS {
        format!(
            "This export is the built-in default `{PRIVATE_POWERED_DESCENT_DEFAULT_STEPS}`-step showcase instance."
        )
    } else {
        format!(
            "This export is a non-default sample-input override using `{integration_steps}` steps; the built-in showcase default remains `{PRIVATE_POWERED_DESCENT_DEFAULT_STEPS}` steps."
        )
    };

    let mut determinism = json!({
        "source_compiled_digest": compiled.program_digest,
        "wrapped_compiled_digest": compiled.program_digest,
        "runtime_public_input_count": runtime_artifact.public_inputs.len(),
        "export_mode": "direct-groth16",
        "export_profile": export_profile.as_str(),
        "prove_deterministic": runtime_artifact.metadata.get("prove_deterministic").cloned(),
        "prove_seed_source": runtime_artifact.metadata.get("prove_seed_source").cloned(),
        "setup_deterministic": compiled.metadata.get("setup_deterministic").cloned(),
        "setup_seed_source": compiled.metadata.get("setup_seed_source").cloned(),
    });
    if let Some(prove_seed_hex) = runtime_artifact.metadata.get("prove_seed_hex") {
        determinism["proof_seed_hex"] = serde_json::Value::String(prove_seed_hex.clone());
    }
    if let Some(setup_seed_hex) = compiled.metadata.get("setup_seed_hex") {
        determinism["setup_seed_hex"] = serde_json::Value::String(setup_seed_hex.clone());
    }

    write_json(&paths.program_original_path, &original_program)?;
    write_json(&paths.program_optimized_path, &optimized_program)?;
    write_json(&paths.compiled_path, &compiled)?;
    if let Some(request_json) = &request_json {
        write_json(&paths.request_path, request_json)?;
    }
    write_json(&paths.inputs_path, &valid_inputs)?;
    write_json(&paths.witness_base_path, &base_witness)?;
    write_json(&paths.witness_path, &prepared_witness)?;
    write_json(&paths.proof_path, &runtime_artifact)?;
    write_text(&paths.verifier_path, &verifier_source)?;
    write_json(&paths.calldata_path, &calldata)?;
    write_json(&paths.matrix_path, &matrix_summary)?;
    write_text(&paths.foundry_verifier_path, &verifier_source)?;
    write_text(&paths.foundry_test_path, &foundry_test.source)?;
    format_foundry_project(&paths)?;
    if let Some(manifest) = trusted_setup_manifest.as_ref() {
        copy_file(&manifest.source_manifest_path, &paths.setup_manifest_path)?;
    }

    let formal_out_dir = out_dir.clone();
    eprintln!("private_powered_descent_showcase: export checkpoint: formal evidence");
    let (generated_closure, formal_evidence) =
        run_with_heartbeat_result("formal-evidence", move || {
            collect_formal_evidence_for_generated_app(&formal_out_dir, APP_ID)
        })?;
    eprintln!("private_powered_descent_showcase: export checkpoint: generated closure summary");
    let generated_closure_summary = generated_app_closure_bundle_summary(APP_ID)?;
    if bundle_mode.is_public()
        && formal_evidence
            .get("status")
            .and_then(serde_json::Value::as_str)
            != Some("included")
    {
        return Err(ZkfError::Backend(
            "powered descent public bundle export requires all configured formal runners to pass"
                .to_string(),
        ));
    }
    let telemetry_artifacts = telemetry_artifacts_surface(bundle_mode, &telemetry_paths);
    let release_safety = bundle_release_safety(
        bundle_mode,
        export_profile,
        &security_boundary,
        &determinism,
        trusted_setup_manifest.as_ref(),
    );

    let checkpoint = ExecutionTraceCheckpoint {
        schema_version: EXECUTION_TRACE_SCHEMA_VERSION.to_string(),
        app_id: APP_ID.to_string(),
        export_profile: export_profile.as_str().to_string(),
        bundle_mode: bundle_mode.as_str().to_string(),
        release_safety: release_safety.to_string(),
        bundle_identity: bundle_identity.clone(),
        request_mode: request_mode.to_string(),
        request_mode_sentence,
        request_source_ref,
        integration_steps,
        default_step_count: PRIVATE_POWERED_DESCENT_DEFAULT_STEPS,
        full_audit_requested,
        declared_private_inputs,
        optimizer_report: serialize_value("powered descent optimizer report", &optimizer_report)?,
        trusted_setup_requested,
        trusted_setup_used,
        setup_provenance: setup_provenance.clone(),
        security_boundary: security_boundary.clone(),
        determinism: determinism.clone(),
        trusted_setup_manifest,
        telemetry_artifacts,
        vehicle_parameters,
        formal_evidence,
        generated_closure,
        generated_closure_summary,
        timings_ms: TimingsSnapshot {
            compile_ms,
            witness_prepare_ms: witness_ms,
            runtime_strict_lane_source_prove_ms: source_runtime_ms,
        },
        source_prove: SourceProveCheckpoint {
            runtime_report,
            outputs: runtime_result.outputs,
            control_plane: serialize_optional_value(
                "powered descent control plane summary",
                &runtime_result.control_plane,
            )?,
            security: serialize_optional_value(
                "powered descent security verdict",
                &runtime_result.security,
            )?,
            model_integrity: serialize_optional_value(
                "powered descent model integrity summary",
                &runtime_result.model_integrity,
            )?,
            swarm: serialize_optional_value(
                "powered descent swarm telemetry digest",
                &runtime_result.swarm,
            )?,
        },
        export: ExportCheckpoint {
            mode: "direct-groth16".to_string(),
            artifact_metadata: runtime_artifact.metadata.clone(),
        },
    };
    let _ = (runtime_memory_plan, runtime_buffer_bridge);
    if bundle_mode.is_public() {
        let checkpoint_value = sanitize_json_for_public_bundle(&serialize_value(
            "execution trace checkpoint",
            &checkpoint,
        )?);
        write_json(&paths.execution_trace_path, &checkpoint_value)?;
    } else {
        write_json(&paths.execution_trace_path, &checkpoint)?;
    }

    ensure_core_bundle_files(
        &paths,
        request_json.is_some(),
        checkpoint.trusted_setup_manifest.is_some(),
    )?;
    ensure_formal_bundle_files(&paths)?;
    let _: serde_json::Value = read_json(&paths.execution_trace_path)?;
    let runtime_artifact_from_disk: zkf_core::ProofArtifact = read_json(&paths.proof_path)?;
    if !verify(&compiled, &runtime_artifact_from_disk)? {
        return Err(ZkfError::Backend(
            "disk-loaded runtime proof verification returned false".to_string(),
        ));
    }
    validate_verifier_and_foundry(&paths)?;
    eprintln!("private_powered_descent_showcase: export checkpoint: prove-core complete");
    Ok(())
}

fn finalize_showcase_bundle(out_dir: PathBuf) -> ZkfResult<()> {
    eprintln!("private_powered_descent_showcase: export checkpoint: finalize start");
    let finalize_started = Instant::now();
    let paths = ShowcaseBundlePaths::new(out_dir);
    let checkpoint = load_execution_trace_checkpoint(&paths)?;
    ensure_bundle_checkpoint_files(&paths, &checkpoint)?;
    validate_verifier_and_foundry(&paths)?;
    let compiled_for_verification: zkf_core::CompiledProgram =
        read_json_stream(&paths.compiled_path)?;
    let runtime_artifact_summary = load_verified_runtime_artifact_summary(
        &paths,
        &compiled_for_verification,
        &checkpoint.export.artifact_metadata,
    )?;
    let export_profile = match checkpoint.export_profile.as_str() {
        "production" => ExportProfile::Production,
        _ => ExportProfile::Development,
    };
    let bundle_mode = match checkpoint.bundle_mode.as_str() {
        "public" => BundleMode::Public,
        _ => BundleMode::Debug,
    };
    let trusted_setup_manifest = load_trusted_setup_manifest_from_bundle(
        &paths,
        &checkpoint,
        &runtime_artifact_summary.verification_key_sha256,
    )?;
    drop(compiled_for_verification);

    let runtime_memory_plan = checkpoint
        .source_prove
        .outputs
        .get("runtime_memory_plan")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let runtime_buffer_bridge = checkpoint
        .source_prove
        .outputs
        .get("runtime_buffer_bridge")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let groth16_execution =
        groth16_execution_summary_from_metadata(&checkpoint.export.artifact_metadata);
    let gpu_attribution = effective_gpu_attribution_summary_with_outputs(
        checkpoint.source_prove.runtime_report.gpu_nodes,
        checkpoint.source_prove.runtime_report.gpu_busy_ratio,
        Some(&checkpoint.source_prove.outputs),
        &checkpoint.export.artifact_metadata,
    );
    let trusted_setup_manifest_surface =
        trusted_setup_manifest_surface(trusted_setup_manifest.as_ref(), export_profile);
    let production_readiness = production_readiness_surface(export_profile);

    let structural_summary = if bundle_mode.is_public() {
        json!({
            "status": "public-sanitized",
            "paths": {
                "matrix_summary": serde_json::Value::Null,
            },
            "notes": [
                "matrix summary is generated during bundle creation but omitted from public bundles"
            ],
        })
    } else {
        json!({
            "status": "included",
            "paths": {
                "matrix_summary": "private_powered_descent.matrix_ccs_summary.json",
            },
        })
    };

    let (full_source_audit, full_compiled_audit) = if checkpoint.full_audit_requested {
        fs::create_dir_all(&paths.audit_dir).map_err(|error| {
            ZkfError::Io(format!("create {}: {error}", paths.audit_dir.display()))
        })?;
        let source_audit = spawn_full_audit_child_and_reload(&paths, FullAuditTarget::Source)?;
        let compiled_audit = spawn_full_audit_child_and_reload(&paths, FullAuditTarget::Compiled)?;
        (
            audit_entry_included(
                "requested via ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT=1",
                FullAuditTarget::Source.bundle_relative_path(),
                FullAuditTarget::Source.producer(),
                source_audit.get("summary").cloned().ok_or_else(|| {
                    ZkfError::InvalidArtifact(
                        "source audit JSON is missing its summary field".to_string(),
                    )
                })?,
            ),
            audit_entry_included(
                "requested via ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT=1",
                FullAuditTarget::Compiled.bundle_relative_path(),
                FullAuditTarget::Compiled.producer(),
                compiled_audit.get("summary").cloned().ok_or_else(|| {
                    ZkfError::InvalidArtifact(
                        "compiled audit JSON is missing its summary field".to_string(),
                    )
                })?,
            ),
        )
    } else {
        (
            audit_entry_omitted_by_default(
                "set ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT=1 to include the heavyweight live source audit in the bundle",
            ),
            audit_entry_omitted_by_default(
                "set ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT=1 to include the heavyweight live compiled audit in the bundle",
            ),
        )
    };

    let ShowcaseBundleDiskState {
        original_program,
        optimized_program,
        compiled,
        checkpoint: _disk_checkpoint,
    } = load_bundle_disk_state(&paths)?;
    let mut structural_summary = structural_summary;
    let structural_summary_object = structural_summary.as_object_mut().ok_or_else(|| {
        ZkfError::Serialization(
            "powered descent structural summary should serialize to a JSON object".to_string(),
        )
    })?;
    structural_summary_object.insert(
        "original".to_string(),
        json!({
            "program_digest": original_program.digest_hex(),
            "program_stats": stats(&original_program),
        }),
    );
    structural_summary_object.insert(
        "optimized".to_string(),
        json!({
            "program_digest": optimized_program.digest_hex(),
            "program_stats": stats(&optimized_program),
            "compiled_into_proof_path": false,
        }),
    );
    structural_summary_object.insert(
        "compiled".to_string(),
        json!({
            "source_program_digest": original_program.digest_hex(),
            "program_digest": compiled.program_digest,
            "program_stats": stats(&compiled.program),
            "export": checkpoint.export.mode,
        }),
    );

    if checkpoint.request_mode == "request-json-v1" || paths.request_path.exists() {
        let _: serde_json::Value = read_json(&paths.request_path)?;
    }
    let prepared_witness: Witness = read_json(&paths.witness_path)?;
    let public_output_map = public_outputs(&compiled.program, &prepared_witness);
    drop(prepared_witness);

    let mut audit_summary = two_tier_audit_record(
        "two-tier-showcase-audit-v1",
        structural_summary,
        full_source_audit,
        full_compiled_audit,
    );
    let audit_summary_object = audit_summary.as_object_mut().ok_or_else(|| {
        ZkfError::Serialization(
            "powered descent audit summary should serialize to a JSON object".to_string(),
        )
    })?;
    audit_summary_object.insert(
        "bundle_identity".to_string(),
        checkpoint.bundle_identity.clone(),
    );
    audit_summary_object.insert("bundle_mode".to_string(), json!(checkpoint.bundle_mode));
    audit_summary_object.insert(
        "release_safety".to_string(),
        json!(checkpoint.release_safety),
    );
    audit_summary_object.insert("request_mode".to_string(), json!(checkpoint.request_mode));
    audit_summary_object.insert(
        "request_source_ref".to_string(),
        json!(checkpoint.request_source_ref),
    );
    audit_summary_object.insert(
        "integration_steps".to_string(),
        json!(checkpoint.integration_steps),
    );
    audit_summary_object.insert(
        "export_profile".to_string(),
        json!(checkpoint.export_profile),
    );

    let runtime_trace = json!({
        "source_prove": stage_summary_from_snapshot(
            &checkpoint.source_prove.runtime_report,
            &checkpoint.source_prove.outputs,
            &checkpoint.export.artifact_metadata,
        ),
        "bundle_mode": checkpoint.bundle_mode,
        "release_safety": checkpoint.release_safety,
        "groth16_execution": groth16_execution,
        "effective_gpu_attribution": gpu_attribution,
        "production_readiness": production_readiness,
        "trusted_setup_manifest": trusted_setup_manifest_surface,
        "telemetry_artifacts": checkpoint.telemetry_artifacts,
        "memory_plan": runtime_memory_plan,
        "buffer_bridge": runtime_buffer_bridge,
        "request_source_ref": checkpoint.request_source_ref,
        "export": {
            "mode": "runtime-strict-groth16",
            "profile": checkpoint.export_profile,
            "process_mode": "fresh-process-finalize-bundle",
            "wall_time_ms": finalize_started.elapsed().as_secs_f64() * 1_000.0,
            "bundle_identity": checkpoint.bundle_identity,
        }
    });

    let evidence_manifest = json!({
        "bundle_evidence_version": "powered-descent-showcase-evidence-v1",
        "app_id": APP_ID,
        "circuit_name": original_program.name,
        "integration_steps": checkpoint.integration_steps,
        "export_profile": checkpoint.export_profile,
        "bundle_mode": checkpoint.bundle_mode,
        "release_safety": checkpoint.release_safety,
        "bundle_identity": checkpoint.bundle_identity,
        "generated_closure": checkpoint.generated_closure_summary,
        "formal_evidence": checkpoint.formal_evidence,
        "audit_coverage": {
            "mode": "two-tier-showcase-audit-v1",
            "full_audit_requested": checkpoint.full_audit_requested,
            "structural_summary": audit_summary["structural_summary"],
            "full_source_audit": audit_summary["full_source_audit"],
            "full_compiled_audit": audit_summary["full_compiled_audit"],
        },
        "gpu_attribution": gpu_attribution,
        "groth16_execution": groth16_execution,
        "production_readiness": production_readiness,
        "trusted_setup_manifest": trusted_setup_manifest_surface,
        "trusted_setup": {
            "provenance": checkpoint.setup_provenance,
            "security_boundary": checkpoint.security_boundary,
            "trusted_setup_requested": checkpoint.trusted_setup_requested,
            "trusted_setup_used": checkpoint.trusted_setup_used,
        },
        "runtime_memory_plan": runtime_memory_plan,
        "runtime_buffer_bridge": runtime_buffer_bridge,
        "request_source_ref": checkpoint.request_source_ref,
        "telemetry_artifacts": checkpoint.telemetry_artifacts,
    });

    let summary = json!({
        "app_id": APP_ID,
        "circuit_name": original_program.name,
        "bundle_identity": checkpoint.bundle_identity,
        "field": "bn254",
        "step_count": checkpoint.integration_steps,
        "default_step_count": PRIVATE_POWERED_DESCENT_DEFAULT_STEPS,
        "integration_steps": checkpoint.integration_steps,
        "export_profile": checkpoint.export_profile,
        "bundle_mode": checkpoint.bundle_mode,
        "release_safety": checkpoint.release_safety,
        "backend": {
            "source": BackendKind::ArkworksGroth16.as_str(),
            "final": BackendKind::ArkworksGroth16.as_str(),
            "export": "runtime-strict-groth16",
        },
        "original_constraint_count": original_program.constraints.len(),
        "final_constraint_count": compiled.program.constraints.len(),
        "peak_memory_bytes": checkpoint.source_prove.runtime_report.peak_memory_bytes,
        "private_inputs": checkpoint.declared_private_inputs,
        "public_inputs": PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS,
        "declared_public_outputs": PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS,
        "original_program": stats(&original_program),
        "optimized_program": stats(&optimized_program),
        "source_compiled_program": stats(&compiled.program),
        "compile_source_program_digest": original_program.digest_hex(),
        "optimizer_report": checkpoint.optimizer_report,
        "groth16_setup": {
            "trusted_setup_requested": checkpoint.trusted_setup_requested,
            "trusted_setup_used": checkpoint.trusted_setup_used,
            "provenance": checkpoint.setup_provenance,
            "security_boundary": checkpoint.security_boundary,
        },
        "runtime_witness_mode": "authoritative-base-witness-normalized-by-runtime",
        "input_mode": checkpoint.request_mode,
        "vehicle_parameters": checkpoint.vehicle_parameters,
        "production_readiness": production_readiness,
        "trusted_setup_manifest": trusted_setup_manifest_surface,
        "timings_ms": {
            "compile": checkpoint.timings_ms.compile_ms,
            "witness_prepare": checkpoint.timings_ms.witness_prepare_ms,
            "runtime_strict_lane_source_prove": checkpoint.timings_ms.runtime_strict_lane_source_prove_ms,
            "groth16_export_wrap": finalize_started.elapsed().as_secs_f64() * 1_000.0,
        },
        "determinism": checkpoint.determinism,
        "public_outputs": public_output_map,
        "runtime_public_inputs": runtime_artifact_summary.public_inputs,
        "proof_sizes": {
            "runtime_proof_bytes": runtime_artifact_summary.proof_bytes,
            "runtime_verification_key_bytes": runtime_artifact_summary.verification_key_bytes,
            "source_proof_bytes": runtime_artifact_summary.proof_bytes,
        },
        "runtime": runtime_trace,
        "control_plane": checkpoint.source_prove.control_plane,
        "security": checkpoint.source_prove.security,
        "model_integrity": checkpoint.source_prove.model_integrity,
        "swarm": checkpoint.source_prove.swarm,
        "artifact_metadata": checkpoint.export.artifact_metadata,
        "groth16_execution": groth16_execution,
        "effective_gpu_attribution": gpu_attribution,
        "metal_runtime": metal_runtime_report(),
        "runtime_memory_plan": runtime_memory_plan,
        "runtime_buffer_bridge": runtime_buffer_bridge,
        "telemetry_artifacts": checkpoint.telemetry_artifacts,
        "request_source_ref": checkpoint.request_source_ref,
        "evidence_manifest_path": "private_powered_descent.evidence_manifest.json",
        "generated_closure": evidence_manifest["generated_closure"],
        "formal_evidence": evidence_manifest["formal_evidence"],
        "audit_coverage": evidence_manifest["audit_coverage"],
    });

    eprintln!("private_powered_descent_showcase: export checkpoint: summary artifacts");
    let summary = if bundle_mode.is_public() {
        sanitize_json_for_public_bundle(&summary)
    } else {
        summary
    };
    let audit_summary = if bundle_mode.is_public() {
        sanitize_json_for_public_bundle(&audit_summary)
    } else {
        audit_summary
    };
    let runtime_trace = if bundle_mode.is_public() {
        sanitize_json_for_public_bundle(&runtime_trace)
    } else {
        runtime_trace
    };
    let evidence_manifest = if bundle_mode.is_public() {
        sanitize_json_for_public_bundle(&evidence_manifest)
    } else {
        evidence_manifest
    };
    write_json(&paths.summary_path, &summary)?;
    write_json(&paths.audit_path, &audit_summary)?;
    write_json(&paths.audit_summary_path, &audit_summary)?;
    write_json(&paths.runtime_trace_path, &runtime_trace)?;
    write_json(&paths.evidence_manifest_path, &evidence_manifest)?;

    eprintln!("private_powered_descent_showcase: export checkpoint: markdown report");
    let mission_assurance_report = report_markdown(
        &compiled,
        &public_output_map,
        runtime_artifact_summary.proof_bytes,
        runtime_artifact_summary.verification_key_bytes,
        &checkpoint.source_prove.runtime_report,
        checkpoint.integration_steps,
        &checkpoint.bundle_identity,
        &runtime_memory_plan,
        &runtime_buffer_bridge,
        &checkpoint.request_mode_sentence,
        &checkpoint.vehicle_parameters,
        export_profile,
        bundle_mode,
        &checkpoint.release_safety,
        &checkpoint.setup_provenance,
        &checkpoint.security_boundary,
        checkpoint.determinism.clone(),
        &checkpoint.request_source_ref,
        &checkpoint.telemetry_artifacts,
        &gpu_attribution,
        &checkpoint.formal_evidence,
        &audit_summary,
        &checkpoint.generated_closure,
        &production_readiness,
        &trusted_setup_manifest_surface,
    );
    write_text(&paths.report_path, &mission_assurance_report)?;
    write_text(&paths.mission_assurance_path, &mission_assurance_report)?;
    write_text(
        &paths.bundle_readme_path,
        &bundle_readme_markdown(bundle_mode, &checkpoint.release_safety),
    )?;

    ensure_file_exists(&paths.summary_path)?;
    ensure_file_exists(&paths.audit_path)?;
    ensure_file_exists(&paths.audit_summary_path)?;
    ensure_file_exists(&paths.runtime_trace_path)?;
    ensure_file_exists(&paths.evidence_manifest_path)?;
    ensure_file_exists(&paths.report_path)?;
    ensure_file_exists(&paths.mission_assurance_path)?;
    ensure_file_exists(&paths.bundle_readme_path)?;

    if bundle_mode.is_public() {
        finalize_public_bundle(&paths, checkpoint.full_audit_requested)?;
    }

    println!("{}", paths.summary_path.display());
    println!("{}", paths.verifier_path.display());
    println!("{}", paths.calldata_path.display());
    println!("{}", paths.audit_summary_path.display());
    println!("{}", paths.evidence_manifest_path.display());
    println!("{}", paths.mission_assurance_path.display());
    println!("{}", paths.project_dir.display());
    Ok(())
}

fn spawn_showcase_child(mode: &str) -> ZkfResult<()> {
    let executable = env::current_exe()
        .map_err(|error| ZkfError::Io(format!("resolve current executable: {error}")))?;
    eprintln!("private_powered_descent_showcase: internal spawn: {mode}");
    let status = Command::new(&executable)
        .args(args())
        .env(INTERNAL_MODE_ENV, mode)
        .status()
        .map_err(|error| {
            ZkfError::Io(format!(
                "spawn powered descent showcase child {}: {error}",
                executable.display()
            ))
        })?;
    if !status.success() {
        return Err(ZkfError::Backend(format!(
            "powered descent showcase child mode `{mode}` exited with status {status}"
        )));
    }
    Ok(())
}

fn run_coordinator() -> ZkfResult<()> {
    spawn_showcase_child(INTERNAL_MODE_PROVE_CORE)?;
    spawn_showcase_child(INTERNAL_MODE_FINALIZE_BUNDLE)
}

fn run_prove_core() -> ZkfResult<()> {
    let export_profile = export_profile();
    ensure_production_runtime_env_contract(export_profile)?;
    let request_source_path = input_request_path();
    let (steps, template, valid_inputs, request_json, effective_request) = match request_source_path
        .as_deref()
    {
        Some(path) => {
            let (request, witness_inputs, request_json, step_count) = request_input_payload(path)?;
            let template = private_powered_descent_showcase_with_steps(step_count)?;
            (
                step_count,
                template,
                witness_inputs,
                Some(request_json),
                request,
            )
        }
        None => {
            let steps = integration_steps_override()?;
            let template = private_powered_descent_showcase_with_steps(steps)?;
            (
                steps,
                template.clone(),
                template.sample_inputs.clone(),
                None,
                private_powered_descent_sample_request_with_steps(steps)?,
            )
        }
    };
    let out_dir = output_dir(steps, request_source_path.is_some());
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;

    let declared_private_inputs = template
        .expected_inputs
        .len()
        .saturating_sub(PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS);
    let original_program = template.program.clone();
    let (optimized_program, optimizer_report) = optimize_program(&original_program);

    let trust_mode = resolve_showcase_groth16_trust_mode(APP_ID, &optimized_program)?;
    let trusted_setup_blob_path = requested_groth16_setup_blob_path(&optimized_program);
    let trusted_setup_requested = trust_mode.trusted_setup_requested();
    let trusted_setup_manifest = match (export_profile, trusted_setup_blob_path.as_deref()) {
        (ExportProfile::Production, Some(path)) => {
            Some(load_and_validate_trusted_setup_manifest(Path::new(path))?)
        }
        (ExportProfile::Production, None) => {
            return Err(ZkfError::Backend(
                "powered descent production mode requires ZKF_GROTH16_SETUP_BLOB_PATH or program metadata `groth16_setup_blob_path` to point to an imported setup blob".to_string(),
            ))
        }
        (ExportProfile::Development, _) => None,
    };

    let compile_start = Instant::now();
    let optimized_program_for_compile = optimized_program.clone();
    let source_compiled = run_with_heartbeat_result("compile", move || {
        with_showcase_groth16_mode(trust_mode, || {
            if export_profile.is_production() {
                Ok(compile_arkworks_unchecked(&optimized_program_for_compile)?)
            } else if trust_mode.uses_explicit_dev_deterministic() {
                Ok(with_setup_seed_override(Some(SETUP_SEED), || {
                    compile_arkworks_unchecked(&optimized_program_for_compile)
                })?)
            } else {
                Ok(compile_arkworks_unchecked(&optimized_program_for_compile)?)
            }
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

    let witness_start = Instant::now();
    let valid_inputs_for_witness = valid_inputs.clone();
    let source_compiled_for_witness = source_compiled.clone();
    let (base_witness, prepared_witness) =
        run_with_heartbeat_result("witness-prepare", move || {
            let base_witness =
                private_powered_descent_witness_with_steps(&valid_inputs_for_witness, steps)?;
            let prepared_witness =
                prepare_witness_for_proving(&source_compiled_for_witness, &base_witness)?;
            check_constraints(&source_compiled_for_witness.program, &prepared_witness)?;
            Ok((base_witness, prepared_witness))
        })?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    let telemetry_before = telemetry_snapshot();
    let source_runtime_start = Instant::now();
    let source_compiled_for_runtime = source_compiled.clone();
    let valid_inputs_for_runtime = valid_inputs.clone();
    let base_witness_for_runtime = base_witness.clone();
    let source_execution = run_with_heartbeat_result("runtime-prove", move || {
        with_showcase_groth16_mode(trust_mode, || {
            let prove = || {
                RuntimeExecutor::run_backend_prove_job_with_objective(
                    BackendKind::ArkworksGroth16,
                    BackendRoute::Auto,
                    Arc::new(source_compiled_for_runtime.program.clone()),
                    Some(Arc::new(valid_inputs_for_runtime.clone())),
                    Some(Arc::new(base_witness_for_runtime.clone())),
                    Some(Arc::new(source_compiled_for_runtime.clone())),
                    OptimizationObjective::FastestProve,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                )
                .map_err(|error| ZkfError::Backend(error.to_string()))
            };
            if export_profile.is_production() {
                prove()
            } else if trust_mode.uses_explicit_dev_deterministic() {
                with_proof_seed_override(Some(PROOF_SEED), prove)
            } else {
                prove()
            }
        })
    })?;
    let source_runtime_ms = source_runtime_start.elapsed().as_secs_f64() * 1_000.0;
    if !verify(&source_execution.compiled, &source_execution.artifact)? {
        return Err(ZkfError::Backend(
            "runtime groth16 proof verification returned false".to_string(),
        ));
    }
    let source_execution_summary = groth16_execution_summary_from_metadata(
        &source_execution.artifact.metadata,
    )
    .ok_or_else(|| {
        ZkfError::InvalidArtifact(
            "runtime Groth16 artifact is missing execution summary metadata".to_string(),
        )
    })?;
    ensure_showcase_metal_realization(&source_execution_summary)?;
    log_runtime_gpu_summary(&source_execution.artifact.metadata);
    let telemetry_after = telemetry_snapshot();

    run_with_large_stack_result("private-powered-descent-prove-core", move || {
        let inputs = ShowcaseExportInputs {
            out_dir,
            export_profile,
            integration_steps: steps,
            declared_private_inputs,
            original_program,
            optimized_program,
            optimizer_report,
            valid_inputs,
            base_witness,
            prepared_witness,
            effective_request,
            request_json,
            request_source_path,
            source_execution,
            compile_ms,
            witness_ms,
            source_runtime_ms,
            trusted_setup_requested,
            trusted_setup_used,
            setup_provenance,
            security_boundary,
            trusted_setup_manifest,
            full_audit_requested: full_audit_requested(),
            telemetry_before,
            telemetry_after,
        };
        write_core_artifacts_and_checkpoint(inputs)
    })
}

fn run_finalize_bundle() -> ZkfResult<()> {
    let out_dir = resolve_current_output_dir()?;
    run_with_large_stack_result("private-powered-descent-finalize-bundle", move || {
        finalize_showcase_bundle(out_dir)
    })
}

fn run_audit_worker(target: FullAuditTarget) -> ZkfResult<()> {
    let out_dir = resolve_current_output_dir()?;
    run_with_large_stack_result(target.worker_name(), move || {
        run_full_audit_worker(out_dir, target)
    })
}

fn try_main() -> ZkfResult<()> {
    ensure_showcase_groth16_setup_mode();

    if !SwarmConfig::is_enabled() {
        return Err(ZkfError::Backend(
            "swarm monitoring is required for this showcase; set ZKF_SWARM=1".to_string(),
        ));
    }

    match internal_mode()? {
        InternalMode::Coordinator => run_coordinator(),
        InternalMode::ProveCore => run_prove_core(),
        InternalMode::FinalizeBundle => run_finalize_bundle(),
        InternalMode::FullSourceAudit => run_audit_worker(FullAuditTarget::Source),
        InternalMode::FullCompiledAudit => run_audit_worker(FullAuditTarget::Compiled),
    }
}

fn main() {
    if let Err(error) = try_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
