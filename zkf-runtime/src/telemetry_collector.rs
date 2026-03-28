use crate::adaptive_tuning::{AdaptiveTuningStatus, adaptive_tuning_status};
use crate::control_plane::{ControlPlaneExecutionSummary, JobKind, ModelCatalog};
use crate::gpu_attribution::{artifact_gpu_busy_ratio, effective_realized_gpu_capable_stages};
use crate::graph::gpu_capable_stage_keys;
use crate::security::{RuntimeModelIntegrity, SecurityVerdict};
use crate::swarm::SwarmTelemetryDigest;
use crate::telemetry::GraphExecutionReport;
use crate::watchdog::WatchdogAlert;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_core::artifact::{BackendKind, CompiledProgram, ProofArtifact};
use zkf_core::ccs::program_constraint_degree;
use zkf_core::ir::{Constraint, Program};
use zkf_core::{FieldId, PlatformCapability, SystemResources, Witness, WitnessInputs};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryRecord {
    pub schema: String,
    pub circuit_features: CircuitFeatures,
    pub hardware_state: HardwareState,
    pub dispatch_config: DispatchConfig,
    pub outcome: TelemetryOutcome,
    pub metadata: TelemetryMetadata,
    pub platform_capability: PlatformCapability,
    pub adaptive_tuning: AdaptiveTuningStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watchdog_alerts: Vec<WatchdogAlert>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane: Option<ControlPlaneExecutionSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_verdict: Option<SecurityVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_integrity: Option<RuntimeModelIntegrity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swarm_telemetry: Option<SwarmTelemetryDigest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitFeatures {
    pub constraint_count: usize,
    pub signal_count: usize,
    pub blackbox_op_distribution: BTreeMap<String, usize>,
    pub max_constraint_degree: usize,
    pub witness_size: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareState {
    pub gpu_utilization: f64,
    pub memory_pressure_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_state_celsius: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_speed_limit: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_frequency_mhz: Option<u64>,
    pub pressure_level: String,
    pub metal_available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchConfig {
    pub stages_on_gpu: Vec<String>,
    pub stages_on_cpu: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_stage_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realized_gpu_capable_stages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_candidate: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub batch_sizes: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryOutcome {
    pub total_proving_time_ms: f64,
    pub per_stage_times_ms: BTreeMap<String, f64>,
    pub gpu_was_faster: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryMetadata {
    pub job_kind: String,
    pub optimization_objective: String,
    pub backend_used: String,
    pub field_used: String,
    pub timestamp_unix_ms: u128,
    pub mode: String,
    pub program_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_catalog: Option<ModelCatalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_policy_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_identity_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_rejection_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integrity_mismatch_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_sequence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_replay_guard: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCorpusStats {
    pub schema: String,
    pub directory: String,
    pub record_count: u64,
    pub corpus_hash: String,
}

static TELEMETRY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[allow(clippy::too_many_arguments)]
pub fn emit_prove_telemetry(
    program: &Program,
    compiled: &CompiledProgram,
    witness: Option<&Witness>,
    witness_inputs: Option<&WitnessInputs>,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    emit_prove_telemetry_to_dir(
        &resolve_telemetry_dir(),
        program,
        compiled,
        witness,
        witness_inputs,
        report,
        artifact,
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn emit_fold_telemetry(
    compiled: &CompiledProgram,
    witnesses: &[Witness],
    compress: bool,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    emit_fold_telemetry_to_dir(
        &resolve_telemetry_dir(),
        compiled,
        witnesses,
        compress,
        report,
        artifact,
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn emit_wrap_telemetry(
    preview: &zkf_core::wrapping::WrapperPreview,
    compiled: &CompiledProgram,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    emit_wrap_telemetry_to_dir(
        &resolve_telemetry_dir(),
        preview,
        compiled,
        report,
        artifact,
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_prove_telemetry_to_dir(
    dir: &Path,
    program: &Program,
    compiled: &CompiledProgram,
    witness: Option<&Witness>,
    witness_inputs: Option<&WitnessInputs>,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    let witness_size = witness
        .map(serialized_size)
        .or_else(|| witness_inputs.map(serialized_size))
        .unwrap_or_default();
    let record = build_record(
        compiled.original_program.as_ref().unwrap_or(program),
        compiled.backend,
        compiled.program_digest.as_str(),
        witness_size,
        "prove",
        JobKind::Prove,
        report,
        Some(artifact),
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    );
    write_record(dir, &record).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn emit_fold_telemetry_to_dir(
    dir: &Path,
    compiled: &CompiledProgram,
    witnesses: &[Witness],
    compress: bool,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    let witness_size = witnesses.iter().map(serialized_size).sum();
    let mode = if compress { "fold-compress" } else { "fold" };
    let record = build_record(
        compiled
            .original_program
            .as_ref()
            .unwrap_or(&compiled.program),
        compiled.backend,
        compiled.program_digest.as_str(),
        witness_size,
        mode,
        JobKind::Fold,
        report,
        Some(artifact),
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    );
    write_record(dir, &record).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn emit_wrap_telemetry_to_dir(
    dir: &Path,
    preview: &zkf_core::wrapping::WrapperPreview,
    compiled: &CompiledProgram,
    report: &GraphExecutionReport,
    artifact: &ProofArtifact,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> io::Result<Option<PathBuf>> {
    let record = build_record(
        compiled
            .original_program
            .as_ref()
            .unwrap_or(&compiled.program),
        preview.target_backend,
        compiled.program_digest.as_str(),
        preview
            .estimated_memory_bytes
            .unwrap_or(preview.memory_budget_bytes.unwrap_or_default()) as usize,
        "wrap",
        JobKind::Wrap,
        report,
        Some(artifact),
        control_plane,
        security_verdict,
        model_integrity,
        swarm_telemetry,
    );
    write_record(dir, &record).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    program: &Program,
    backend: BackendKind,
    program_digest: &str,
    witness_size: usize,
    mode: &str,
    job_kind: JobKind,
    report: &GraphExecutionReport,
    artifact: Option<&ProofArtifact>,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security_verdict: Option<&SecurityVerdict>,
    model_integrity: Option<&RuntimeModelIntegrity>,
    swarm_telemetry: Option<&SwarmTelemetryDigest>,
) -> TelemetryRecord {
    let resources = SystemResources::detect();
    let metal_runtime = metal_runtime_report();
    let platform_capability = PlatformCapability::detect();
    let adaptive_tuning = adaptive_tuning_status();
    let stage_breakdown = report.stage_breakdown();
    let artifact_gpu_busy_ratio = artifact_gpu_busy_ratio(artifact);
    let effective_gpu_stages = effective_realized_gpu_capable_stages(report, artifact);
    let timestamp_unix_ms = unix_time_now_ms();
    let telemetry_sequence_id = next_telemetry_sequence_id(timestamp_unix_ms);
    let mut per_stage_times_ms = BTreeMap::new();
    let mut stages_on_gpu = Vec::new();
    let mut stages_on_cpu = Vec::new();
    let mut batch_sizes = BTreeMap::new();
    let mut runtime_stage_keys = BTreeSet::new();

    for (stage, telemetry) in &stage_breakdown {
        per_stage_times_ms.insert(stage.clone(), telemetry.duration_ms);
        batch_sizes.insert(stage.clone(), telemetry.node_count);
        runtime_stage_keys.insert(stage.clone());
        if telemetry.gpu_nodes > 0 {
            stages_on_gpu.push(stage.clone());
        }
        if telemetry.cpu_nodes > 0 || telemetry.fallback_nodes > 0 {
            stages_on_cpu.push(stage.clone());
        }
    }
    for stage in &effective_gpu_stages {
        if !stages_on_gpu.iter().any(|existing| existing == stage) {
            stages_on_gpu.push(stage.clone());
        }
    }
    stages_on_gpu.sort();
    stages_on_gpu.dedup();

    let memory_pressure_bytes = resources
        .total_ram_bytes
        .saturating_sub(resources.available_ram_bytes);
    let realized_gpu_capable_stages = control_plane
        .map(|value| value.realized_gpu_capable_stages.clone())
        .unwrap_or_else(|| {
            gpu_capable_stage_keys()
                .iter()
                .filter(|stage| effective_gpu_stages.iter().any(|candidate| candidate == **stage))
                .map(|stage| (*stage).to_string())
                .collect()
        });
    let dispatch_candidate =
        control_plane.map(|value| value.decision.dispatch_plan.candidate.as_str().to_string());
    let integrity_mismatch_flags = model_integrity
        .map(|value| value.integrity_failures.clone())
        .unwrap_or_default();
    let telemetry_replay_guard = Some(telemetry_replay_guard(
        &telemetry_sequence_id,
        backend.as_str(),
        program_digest,
        timestamp_unix_ms,
    ));

    TelemetryRecord {
        schema: "zkf-telemetry-v4".to_string(),
        circuit_features: CircuitFeatures {
            constraint_count: program.constraints.len(),
            signal_count: program.signals.len(),
            blackbox_op_distribution: blackbox_distribution(program),
            max_constraint_degree: max_constraint_degree(program),
            witness_size,
        },
        hardware_state: HardwareState {
            gpu_utilization: report
                .gpu_stage_busy_ratio()
                .max(metal_runtime.metal_gpu_busy_ratio)
                .max(artifact_gpu_busy_ratio),
            memory_pressure_bytes,
            thermal_pressure: control_plane
                .and_then(|value| value.decision.features.thermal_pressure),
            thermal_state_celsius: control_plane
                .and_then(|value| value.decision.features.thermal_state_celsius),
            cpu_speed_limit: control_plane
                .and_then(|value| value.decision.features.cpu_speed_limit),
            core_frequency_mhz: control_plane
                .and_then(|value| value.decision.features.core_frequency_mhz),
            pressure_level: resources.pressure.level.to_string(),
            metal_available: metal_runtime.metal_available,
        },
        dispatch_config: DispatchConfig {
            stages_on_gpu,
            stages_on_cpu,
            runtime_stage_keys: runtime_stage_keys.into_iter().collect(),
            realized_gpu_capable_stages,
            dispatch_candidate,
            batch_sizes,
        },
        outcome: TelemetryOutcome {
            total_proving_time_ms: report.total_wall_time.as_secs_f64() * 1_000.0,
            per_stage_times_ms,
            gpu_was_faster: infer_gpu_was_faster(report),
        },
        metadata: TelemetryMetadata {
            job_kind: job_kind.as_str().to_string(),
            optimization_objective: control_plane
                .map(|value| {
                    value
                        .decision
                        .backend_recommendation
                        .objective
                        .as_str()
                        .to_string()
                })
                .unwrap_or_else(|| "fastest-prove".to_string()),
            backend_used: backend.as_str().to_string(),
            field_used: field_name(program.field).to_string(),
            timestamp_unix_ms,
            mode: mode.to_string(),
            program_digest: program_digest.to_string(),
            backend_route: control_plane
                .and_then(|value| value.decision.features.backend_route.clone()),
            trust_lane: control_plane.map(|value| match value.decision.job_kind {
                JobKind::Wrap => "strict-cryptographic".to_string(),
                JobKind::Fold => "strict-cryptographic".to_string(),
                JobKind::Prove => "strict-cryptographic".to_string(),
            }),
            hardware_profile: control_plane
                .map(|value| value.decision.features.hardware_profile.clone()),
            proof_size_bytes: artifact.map(|value| value.proof.len() as u64),
            proof_backend: artifact.map(|value| value.backend.as_str().to_string()),
            model_catalog: control_plane.map(|value| value.decision.model_catalog.clone()),
            feature_schema_version: control_plane
                .map(|value| value.decision.features.feature_schema.clone()),
            model_fingerprint: security_verdict.and_then(|value| value.model_fingerprint.clone()),
            security_policy_mode: model_integrity
                .map(|value| value.policy_mode.as_str().to_string()),
            caller_class: None,
            api_identity_hash: None,
            security_rejection_reason: security_verdict.map(|value| value.reason.clone()),
            integrity_mismatch_flags,
            telemetry_sequence_id: Some(telemetry_sequence_id),
            telemetry_replay_guard,
        },
        platform_capability,
        adaptive_tuning,
        watchdog_alerts: report.watchdog_alerts.clone(),
        control_plane: control_plane.cloned(),
        security_verdict: security_verdict.cloned(),
        model_integrity: model_integrity.cloned(),
        swarm_telemetry: swarm_telemetry.cloned(),
    }
}

fn blackbox_distribution(program: &Program) -> BTreeMap<String, usize> {
    let mut distribution = BTreeMap::new();
    for constraint in &program.constraints {
        if let Constraint::BlackBox { op, .. } = constraint {
            *distribution.entry(op.as_str().to_string()).or_insert(0) += 1;
        }
    }
    distribution
}

fn max_constraint_degree(program: &Program) -> usize {
    program_constraint_degree(program)
}

fn infer_gpu_was_faster(report: &GraphExecutionReport) -> bool {
    report.gpu_nodes > 0 && report.fallback_nodes == 0 && report.gpu_stage_busy_ratio() > 0.0
}

fn resolve_telemetry_dir() -> PathBuf {
    if let Some(explicit) = std::env::var_os("ZKF_TELEMETRY_DIR") {
        return PathBuf::from(explicit);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".zkf").join("telemetry");
    }
    std::env::temp_dir().join("zkf-telemetry")
}

pub fn telemetry_corpus_stats() -> io::Result<TelemetryCorpusStats> {
    telemetry_corpus_stats_for_dir(&resolve_telemetry_dir())
}

pub fn telemetry_corpus_stats_for_dir(dir: &Path) -> io::Result<TelemetryCorpusStats> {
    use sha2::{Digest, Sha256};

    let mut entries = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    let mut hasher = Sha256::new();
    let mut record_count = 0u64;
    for entry in entries {
        let path = entry.path();
        let bytes = fs::read(&path)?;
        hasher.update(
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default(),
        );
        hasher.update([0u8]);
        hasher.update(&bytes);
        hasher.update([0u8]);
        record_count += 1;
    }

    Ok(TelemetryCorpusStats {
        schema: "zkf-telemetry-corpus-v1".to_string(),
        directory: dir.display().to_string(),
        record_count,
        corpus_hash: format!("{:x}", hasher.finalize()),
    })
}

fn next_telemetry_sequence_id(timestamp_unix_ms: u128) -> String {
    let sequence = TELEMETRY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp_unix_ms}-{sequence}")
}

fn telemetry_replay_guard(
    sequence_id: &str,
    backend: &str,
    program_digest: &str,
    timestamp_unix_ms: u128,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sequence_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(backend.as_bytes());
    hasher.update([0u8]);
    hasher.update(program_digest.as_bytes());
    hasher.update([0u8]);
    hasher.update(timestamp_unix_ms.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn write_record(dir: &Path, record: &TelemetryRecord) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let file_name = format!(
        "{}-{}-{}.json",
        record.metadata.timestamp_unix_ms,
        record.metadata.backend_used,
        &record
            .metadata
            .program_digest
            .chars()
            .take(16)
            .collect::<String>()
    );
    let path = dir.join(file_name);
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(&path, payload)?;
    Ok(path)
}

fn serialized_size<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or_default()
}

fn field_name(field: FieldId) -> &'static str {
    field.as_str()
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{
        AnomalySeverity, AnomalyVerdict, BackendRecommendation, BoundSource, CircuitFeatureProfile,
        ControlPlaneDecision, ControlPlaneFeatures, DispatchCandidate, DispatchCandidateScore,
        DispatchPlan, DurationEstimate, EtaSemantics, ExecutionRegime,
    };
    use crate::graph::DevicePlacement;
    use crate::memory::NodeId;
    use crate::telemetry::NodeTrace;
    use crate::trust::TrustModel;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use zkf_core::ir::{BlackBoxOp, Expr, Program, Signal, Visibility};

    fn sample_program() -> Program {
        Program {
            name: "telemetry-sample".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "a".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::signal("b"),
                    rhs: Expr::Mul(Box::new(Expr::signal("a")), Box::new(Expr::signal("a"))),
                    label: Some("square".to_string()),
                },
                Constraint::BlackBox {
                    op: BlackBoxOp::Sha256,
                    inputs: vec![Expr::signal("a")],
                    outputs: vec!["b".to_string()],
                    params: BTreeMap::new(),
                    label: Some("sha".to_string()),
                },
            ],
            ..Program::default()
        }
    }

    fn sample_report() -> GraphExecutionReport {
        GraphExecutionReport {
            node_traces: vec![
                NodeTrace {
                    node_id: NodeId::new(),
                    op_name: "Sha256Batch",
                    stage_key: "sha256-batch".to_string(),
                    placement: DevicePlacement::Gpu,
                    trust_model: TrustModel::Cryptographic,
                    wall_time: Duration::from_millis(12),
                    problem_size: Some(32),
                    input_bytes: 256,
                    output_bytes: 64,
                    predicted_cpu_ms: Some(18.0),
                    predicted_gpu_ms: Some(10.0),
                    prediction_confidence: Some(0.55),
                    prediction_observation_count: Some(0),
                    input_digest: [0; 8],
                    output_digest: [1; 8],
                    allocated_bytes_after: 1024,
                    accelerator_name: Some("metal-sha256".to_string()),
                    fell_back: false,
                    buffer_residency: Some("shared".to_string()),
                    delegated: false,
                    delegated_backend: None,
                },
                NodeTrace {
                    node_id: NodeId::new(),
                    op_name: "WitnessSolve",
                    stage_key: "witness-solve".to_string(),
                    placement: DevicePlacement::Cpu,
                    trust_model: TrustModel::Cryptographic,
                    wall_time: Duration::from_millis(8),
                    problem_size: Some(2),
                    input_bytes: 64,
                    output_bytes: 128,
                    predicted_cpu_ms: Some(8.0),
                    predicted_gpu_ms: Some(9.0),
                    prediction_confidence: Some(0.35),
                    prediction_observation_count: Some(0),
                    input_digest: [2; 8],
                    output_digest: [3; 8],
                    allocated_bytes_after: 2048,
                    accelerator_name: None,
                    fell_back: false,
                    buffer_residency: Some("host".to_string()),
                    delegated: false,
                    delegated_backend: None,
                },
            ],
            total_wall_time: Duration::from_millis(20),
            peak_memory_bytes: 4096,
            gpu_nodes: 1,
            cpu_nodes: 1,
            delegated_nodes: 0,
            final_trust_model: TrustModel::Cryptographic,
            fallback_nodes: 0,
            watchdog_alerts: Vec::new(),
        }
    }

    fn sample_control_plane_summary() -> ControlPlaneExecutionSummary {
        ControlPlaneExecutionSummary {
            decision: ControlPlaneDecision {
                job_kind: JobKind::Wrap,
                features: ControlPlaneFeatures {
                    feature_schema: "zkf-neural-control-plane-v2".to_string(),
                    job_kind: JobKind::Wrap,
                    objective: crate::control_plane::OptimizationObjective::FastestProve,
                    circuit: CircuitFeatureProfile {
                        constraint_count: 2,
                        signal_count: 2,
                        blackbox_op_distribution: BTreeMap::new(),
                        max_constraint_degree: 2,
                        witness_size: 2,
                    },
                    stage_node_counts: BTreeMap::from([
                        ("ntt".to_string(), 1usize),
                        ("sha256-batch".to_string(), 1usize),
                    ]),
                    gpu_capable_stage_counts: BTreeMap::from([
                        ("ntt".to_string(), 1usize),
                        ("sha256-batch".to_string(), 1usize),
                    ]),
                    hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
                    chip_family: "m4".to_string(),
                    form_factor: "laptop".to_string(),
                    gpu_core_count: Some(40),
                    ane_tops: Some(38.0),
                    metal_available: true,
                    unified_memory: true,
                    ram_utilization: 0.42,
                    memory_pressure_ratio: 0.18,
                    battery_present: true,
                    on_external_power: true,
                    low_power_mode: false,
                    power_mode: "automatic".to_string(),
                    thermal_pressure: Some(0.12),
                    thermal_state_celsius: Some(51.0),
                    cpu_speed_limit: Some(0.97),
                    core_frequency_mhz: Some(4040),
                    requested_backend: None,
                    backend_route: Some("native-auto".to_string()),
                    requested_jobs: 2,
                    total_jobs: 4,
                },
                dispatch_plan: DispatchPlan::from_candidate(DispatchCandidate::Balanced),
                candidate_rankings: vec![DispatchCandidateScore {
                    candidate: DispatchCandidate::Balanced,
                    predicted_duration_ms: 240.0,
                    source: "model-or-heuristic".to_string(),
                }],
                backend_recommendation: BackendRecommendation {
                    selected: BackendKind::ArkworksGroth16,
                    objective: crate::control_plane::OptimizationObjective::FastestProve,
                    source: "model".to_string(),
                    rankings: vec![],
                    notes: vec![],
                },
                duration_estimate: DurationEstimate {
                    estimate_ms: 240.0,
                    upper_bound_ms: Some(300.0),
                    predicted_wall_time_ms: 240.0,
                    source: "model".to_string(),
                    execution_regime: ExecutionRegime::PartialFallback,
                    eta_semantics: EtaSemantics::ModelEstimate,
                    bound_source: BoundSource::ModelDerived,
                    countdown_safe: true,
                    note: Some(
                        "Dispatch mixes GPU-capable and CPU stages; use the conservative upper bound for operator planning"
                            .to_string(),
                    ),
                    backend: Some(BackendKind::ArkworksGroth16),
                    dispatch_candidate: Some(DispatchCandidate::Balanced),
                },
                anomaly_baseline: AnomalyVerdict {
                    severity: AnomalySeverity::Normal,
                    source: "model".to_string(),
                    reason: "baseline residual envelope".to_string(),
                    predicted_anomaly_score: Some(1.25),
                    advisory_estimate_ms: Some(240.0),
                    conservative_upper_bound_ms: Some(300.0),
                    execution_regime: Some(ExecutionRegime::PartialFallback),
                    eta_semantics: Some(EtaSemantics::ModelEstimate),
                    bound_source: Some(BoundSource::ModelDerived),
                    duration_interpretation: None,
                    expected_duration_ms: Some(240.0),
                    expected_duration_ratio_limit: Some(1.25),
                    observed_duration_ms: None,
                    duration_ratio: None,
                    expected_proof_size_bytes: Some(128),
                    expected_proof_size_ratio_limit: Some(1.25),
                    observed_proof_size_bytes: None,
                    proof_size_ratio: None,
                },
                model_catalog: ModelCatalog {
                    scheduler: Some(crate::control_plane::ModelDescriptor {
                        lane: crate::control_plane::ModelLane::Scheduler,
                        path: "/tmp/scheduler_v1.mlpackage".to_string(),
                        source: crate::control_plane::ModelSource::RepoLocal,
                        version: Some("v1".to_string()),
                        schema_fingerprint: Some("fixture".to_string()),
                        input_shape: Some(47),
                        output_name: Some("predicted_duration_ms".to_string()),
                        quality_gate: Some(crate::control_plane::ModelQualityGate {
                            passed: true,
                            thresholds: BTreeMap::new(),
                            measurements: BTreeMap::new(),
                            reasons: vec![],
                        }),
                        corpus_hash: Some("fixture-corpus".to_string()),
                        corpus_record_count: Some(72),
                        trained_at: Some("2026-03-17T00:00:00Z".to_string()),
                        freshness_notice: None,
                        package_tree_sha256: None,
                        sidecar_sha256: None,
                        manifest_sha256: None,
                        model_fingerprint: None,
                        pinned: false,
                        trusted: false,
                        quarantined: false,
                        allow_unpinned_dev_bypass: false,
                        integrity_failures: vec![],
                    }),
                    backend: None,
                    duration: None,
                    anomaly: None,
                    security: None,
                    threshold_optimizer: None,
                    failures: BTreeMap::new(),
                },
                notes: vec![],
            },
            anomaly_verdict: AnomalyVerdict {
                severity: AnomalySeverity::Notice,
                source: "model".to_string(),
                reason: "observed execution was slower than the advisory model estimate".to_string(),
                predicted_anomaly_score: Some(1.25),
                advisory_estimate_ms: Some(240.0),
                conservative_upper_bound_ms: Some(300.0),
                execution_regime: Some(ExecutionRegime::PartialFallback),
                eta_semantics: Some(EtaSemantics::ModelEstimate),
                bound_source: Some(BoundSource::ModelDerived),
                duration_interpretation: Some("slower-than-advisory-estimate".to_string()),
                expected_duration_ms: Some(240.0),
                expected_duration_ratio_limit: Some(1.25),
                observed_duration_ms: Some(260.0),
                duration_ratio: Some(1.0833),
                expected_proof_size_bytes: Some(128),
                expected_proof_size_ratio_limit: Some(1.25),
                observed_proof_size_bytes: Some(128),
                proof_size_ratio: Some(1.0),
            },
            realized_gpu_capable_stages: vec!["ntt".to_string(), "sha256-batch".to_string()],
            proof_size_bytes: Some(128),
        }
    }

    #[test]
    fn prove_telemetry_persists_expected_fields() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let program = sample_program();
        let compiled = CompiledProgram::new(BackendKind::Nova, program.clone());
        let witness = Witness {
            values: BTreeMap::from([
                ("a".to_string(), zkf_core::FieldElement::from_i64(3)),
                ("b".to_string(), zkf_core::FieldElement::from_i64(9)),
            ]),
        };
        let artifact = ProofArtifact {
            backend: BackendKind::Nova,
            program_digest: compiled.program_digest.clone(),
            proof: vec![1, 2, 3],
            verification_key: vec![4, 5, 6],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };

        let path = emit_prove_telemetry_to_dir(
            tempdir.path(),
            &program,
            &compiled,
            Some(&witness),
            None,
            &sample_report(),
            &artifact,
            None,
            None,
            None,
            None,
        )
        .expect("telemetry write should succeed")
        .expect("telemetry path should be returned");

        let payload: TelemetryRecord =
            serde_json::from_slice(&fs::read(path).expect("telemetry bytes")).expect("json");
        assert_eq!(payload.metadata.backend_used, "nova");
        assert_eq!(payload.metadata.mode, "prove");
        assert_eq!(
            payload.circuit_features.blackbox_op_distribution["sha256"],
            1
        );
        assert_eq!(payload.circuit_features.max_constraint_degree, 2);
        assert!(
            payload
                .dispatch_config
                .stages_on_gpu
                .contains(&"sha256-batch".to_string())
        );
        assert!(
            payload
                .dispatch_config
                .stages_on_cpu
                .contains(&"witness-solve".to_string())
        );
        assert!(payload.outcome.gpu_was_faster);
    }

    #[test]
    fn fold_telemetry_marks_compression_mode() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let compiled = CompiledProgram::new(BackendKind::HyperNova, sample_program());
        let witnesses = vec![Witness {
            values: BTreeMap::from([
                ("a".to_string(), zkf_core::FieldElement::from_i64(2)),
                ("b".to_string(), zkf_core::FieldElement::from_i64(4)),
            ]),
        }];
        let artifact = ProofArtifact {
            backend: BackendKind::HyperNova,
            program_digest: compiled.program_digest.clone(),
            proof: vec![7, 8, 9],
            verification_key: vec![0],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };

        let path = emit_fold_telemetry_to_dir(
            tempdir.path(),
            &compiled,
            &witnesses,
            true,
            &sample_report(),
            &artifact,
            None,
            None,
            None,
            None,
        )
        .expect("telemetry write should succeed")
        .expect("telemetry path should be returned");
        let payload: TelemetryRecord =
            serde_json::from_slice(&fs::read(path).expect("telemetry bytes")).expect("json");
        assert_eq!(payload.metadata.mode, "fold-compress");
        assert_eq!(payload.metadata.backend_used, "hypernova");
    }

    #[test]
    fn wrap_telemetry_persists_model_catalog_and_job_kind() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let compiled = CompiledProgram::new(BackendKind::Plonky3, sample_program());
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: compiled.program_digest.clone(),
            proof: vec![1, 2, 3],
            verification_key: vec![4, 5, 6],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };
        let preview = zkf_core::wrapping::WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: None,
            estimated_constraints: Some(1024),
            estimated_memory_bytes: Some(64 * 1024 * 1024),
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: None,
        };

        let path = emit_wrap_telemetry_to_dir(
            tempdir.path(),
            &preview,
            &compiled,
            &sample_report(),
            &artifact,
            Some(&sample_control_plane_summary()),
            None,
            None,
            None,
        )
        .expect("telemetry write should succeed")
        .expect("telemetry path should be returned");
        let payload: TelemetryRecord =
            serde_json::from_slice(&fs::read(path).expect("telemetry bytes")).expect("json");
        assert_eq!(payload.metadata.job_kind, "wrap");
        assert_eq!(payload.metadata.mode, "wrap");
        assert_eq!(
            payload
                .control_plane
                .as_ref()
                .and_then(|summary| summary.decision.model_catalog.scheduler.as_ref())
                .and_then(|descriptor| descriptor.version.as_deref()),
            Some("v1")
        );
    }
}
