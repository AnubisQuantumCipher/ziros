use crate::error::RuntimeError;
use crate::graph::{
    DevicePlacement, ProverGraph, gpu_capable_stage_keys, is_gpu_capable_stage_key,
};
use crate::telemetry::GraphExecutionReport;
use crate::telemetry_collector::telemetry_corpus_stats;
use crate::trust::{HardwareProfile, RequiredTrustLane};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use zkf_backends::{
    BackendRoute, backend_for, capability_report_for_backend, metal_runtime_report,
    preferred_backend_for_program,
};
use zkf_core::artifact::{BackendKind, CompiledProgram, ProofArtifact};
use zkf_core::ccs::program_constraint_degree;
use zkf_core::ir::{Constraint, Program};
use zkf_core::wrapping::WrapperPreview;
use zkf_core::{FieldId, PlatformCapability, SystemResources, Witness, WitnessInputs};

#[cfg(target_vendor = "apple")]
use halo2curves::group::{Curve, Group};
#[cfg(target_vendor = "apple")]
use halo2curves::pasta::{Fq as PastaFq, Pallas, PallasAffine};
#[cfg(target_vendor = "apple")]
use p3_dft::TwoAdicSubgroupDft;
#[cfg(target_vendor = "apple")]
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
#[cfg(target_vendor = "apple")]
use p3_goldilocks::Goldilocks;
#[cfg(target_vendor = "apple")]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(target_vendor = "apple")]
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobKind {
    Prove,
    Fold,
    Wrap,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prove => "prove",
            Self::Fold => "fold",
            Self::Wrap => "wrap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptimizationObjective {
    #[default]
    FastestProve,
    SmallestProof,
    NoTrustedSetup,
}

impl OptimizationObjective {
    pub const ALL: [Self; 3] = [
        Self::FastestProve,
        Self::SmallestProof,
        Self::NoTrustedSetup,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastestProve => "fastest-prove",
            Self::SmallestProof => "smallest-proof",
            Self::NoTrustedSetup => "no-trusted-setup",
        }
    }
}

impl FromStr for OptimizationObjective {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "fastest-prove" | "fastest_prove" => Ok(Self::FastestProve),
            "smallest-proof" | "smallest_proof" => Ok(Self::SmallestProof),
            "no-trusted-setup" | "no_trusted_setup" => Ok(Self::NoTrustedSetup),
            other => Err(format!(
                "unknown optimization objective '{other}' (expected fastest-prove, smallest-proof, or no-trusted-setup)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelLane {
    Scheduler,
    Backend,
    Duration,
    Anomaly,
    Security,
    ThresholdOptimizer,
}

impl ModelLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Backend => "backend",
            Self::Duration => "duration",
            Self::Anomaly => "anomaly",
            Self::Security => "security",
            Self::ThresholdOptimizer => "threshold-optimizer",
        }
    }

    pub fn env_var(self) -> &'static str {
        match self {
            Self::Scheduler => "ZKF_SCHEDULER_MODEL",
            Self::Backend => "ZKF_BACKEND_RECOMMENDER_MODEL",
            Self::Duration => "ZKF_DURATION_ESTIMATOR_MODEL",
            Self::Anomaly => "ZKF_ANOMALY_DETECTOR_MODEL",
            Self::Security => "ZKF_SECURITY_DETECTOR_MODEL",
            Self::ThresholdOptimizer => "ZKF_THRESHOLD_OPTIMIZER_MODEL",
        }
    }

    pub fn compatibility_env_var(self) -> Option<&'static str> {
        match self {
            Self::Scheduler => Some("ZKF_ANE_POLICY_MODEL"),
            _ => None,
        }
    }

    pub fn default_file_names(self) -> &'static [&'static str] {
        match self {
            Self::Scheduler => &[
                "scheduler_v2.mlpackage",
                "scheduler_v1.mlpackage",
                "zkf-runtime-policy.mlpackage",
            ],
            Self::Backend => &[
                "backend_recommender_v2.mlpackage",
                "backend_recommender_v1.mlpackage",
            ],
            Self::Duration => &[
                "duration_estimator_v2.mlpackage",
                "duration_estimator_v1.mlpackage",
            ],
            Self::Anomaly => &[
                "anomaly_detector_v2.mlpackage",
                "anomaly_detector_v1.mlpackage",
            ],
            Self::Security => &[
                "security_detector_v2.mlpackage",
                "security_detector_v1.mlpackage",
            ],
            Self::ThresholdOptimizer => &["threshold_optimizer_v1.mlpackage"],
        }
    }

    pub fn expected_output_name(self) -> &'static str {
        match self {
            Self::Scheduler => "predicted_duration_ms",
            Self::Backend => "backend_score",
            Self::Duration => "predicted_duration_ms",
            Self::Anomaly => "anomaly_score",
            Self::Security => "risk_score",
            Self::ThresholdOptimizer => "gpu_lane_score",
        }
    }

    pub fn supported_input_shapes(self) -> &'static [usize] {
        match self {
            Self::Scheduler | Self::Backend | Self::Duration | Self::Anomaly => &[57, 47],
            Self::Security => &[68, 58],
            Self::ThresholdOptimizer => &[12],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelSource {
    Environment,
    UserHome,
    RepoLocal,
}

impl ModelSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::UserHome => "user-home",
            Self::RepoLocal => "repo-local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelQualityGate {
    pub passed: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub thresholds: BTreeMap<String, f64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub measurements: BTreeMap<String, f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    pub lane: ModelLane,
    pub path: String,
    pub source: ModelSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_shape: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_gate: Option<ModelQualityGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_record_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trained_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_tree_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_fingerprint: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub allow_unpinned_dev_bypass: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integrity_failures: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModelCatalog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomaly: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_optimizer: Option<ModelDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, String>,
}

impl ModelCatalog {
    pub fn discover() -> Self {
        let mut catalog = Self::default();
        for lane in [
            ModelLane::Scheduler,
            ModelLane::Backend,
            ModelLane::Duration,
            ModelLane::Anomaly,
            ModelLane::Security,
            ModelLane::ThresholdOptimizer,
        ] {
            match discover_model(lane) {
                Ok(Some(descriptor)) => catalog.set_lane(lane, descriptor),
                Ok(None) => {}
                Err(err) => {
                    catalog.failures.insert(lane.as_str().to_string(), err);
                }
            }
        }
        catalog
    }

    fn lane(&self, lane: ModelLane) -> Option<&ModelDescriptor> {
        match lane {
            ModelLane::Scheduler => self.scheduler.as_ref(),
            ModelLane::Backend => self.backend.as_ref(),
            ModelLane::Duration => self.duration.as_ref(),
            ModelLane::Anomaly => self.anomaly.as_ref(),
            ModelLane::Security => self.security.as_ref(),
            ModelLane::ThresholdOptimizer => self.threshold_optimizer.as_ref(),
        }
    }

    fn set_lane(&mut self, lane: ModelLane, descriptor: ModelDescriptor) {
        match lane {
            ModelLane::Scheduler => self.scheduler = Some(descriptor),
            ModelLane::Backend => self.backend = Some(descriptor),
            ModelLane::Duration => self.duration = Some(descriptor),
            ModelLane::Anomaly => self.anomaly = Some(descriptor),
            ModelLane::Security => self.security = Some(descriptor),
            ModelLane::ThresholdOptimizer => self.threshold_optimizer = Some(descriptor),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchCandidate {
    CpuOnly,
    HashOnly,
    AlgebraOnly,
    StarkHeavy,
    Balanced,
    FullGpu,
}

impl DispatchCandidate {
    pub const ALL: [Self; 6] = [
        Self::CpuOnly,
        Self::HashOnly,
        Self::AlgebraOnly,
        Self::StarkHeavy,
        Self::Balanced,
        Self::FullGpu,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpuOnly => "cpu-only",
            Self::HashOnly => "hash-only",
            Self::AlgebraOnly => "algebra-only",
            Self::StarkHeavy => "stark-heavy",
            Self::Balanced => "balanced",
            Self::FullGpu => "full-gpu",
        }
    }

    pub fn stages_on_gpu(self) -> &'static [&'static str] {
        match self {
            Self::CpuOnly => &[],
            Self::HashOnly => &["poseidon-batch", "sha256-batch", "merkle-layer"],
            Self::AlgebraOnly => &["ntt", "lde", "msm"],
            Self::StarkHeavy => &["ntt", "lde", "merkle-layer", "fri-fold", "fri-query-open"],
            Self::Balanced => &[
                "ntt",
                "lde",
                "msm",
                "poseidon-batch",
                "merkle-layer",
                "fri-fold",
            ],
            Self::FullGpu => gpu_capable_stage_keys(),
        }
    }

    pub fn to_plan(self) -> DispatchPlan {
        DispatchPlan::from_candidate(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchPlan {
    pub candidate: DispatchCandidate,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages_on_gpu: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages_on_cpu: Vec<String>,
}

impl DispatchPlan {
    pub fn from_candidate(candidate: DispatchCandidate) -> Self {
        let stages_on_gpu = candidate
            .stages_on_gpu()
            .iter()
            .map(|stage| (*stage).to_string())
            .collect::<BTreeSet<_>>();
        let stages_on_cpu = gpu_capable_stage_keys()
            .iter()
            .filter(|stage| !stages_on_gpu.contains(**stage))
            .map(|stage| (*stage).to_string())
            .collect::<Vec<_>>();
        Self {
            candidate,
            stages_on_gpu: stages_on_gpu.into_iter().collect(),
            stages_on_cpu,
        }
    }

    pub fn placement_for_stage(&self, stage: &str) -> Option<DevicePlacement> {
        if self
            .stages_on_gpu
            .iter()
            .any(|candidate| candidate == stage)
        {
            return Some(DevicePlacement::Gpu);
        }
        if self
            .stages_on_cpu
            .iter()
            .any(|candidate| candidate == stage)
        {
            return Some(DevicePlacement::Cpu);
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitFeatureProfile {
    pub constraint_count: usize,
    pub signal_count: usize,
    pub blackbox_op_distribution: BTreeMap<String, usize>,
    pub max_constraint_degree: usize,
    pub witness_size: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlPlaneFeatures {
    pub feature_schema: String,
    pub job_kind: JobKind,
    pub objective: OptimizationObjective,
    pub circuit: CircuitFeatureProfile,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stage_node_counts: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gpu_capable_stage_counts: BTreeMap<String, usize>,
    pub hardware_profile: String,
    pub chip_family: String,
    pub form_factor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_core_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ane_tops: Option<f32>,
    pub metal_available: bool,
    pub unified_memory: bool,
    pub ram_utilization: f64,
    pub memory_pressure_ratio: f64,
    pub battery_present: bool,
    pub on_external_power: bool,
    pub low_power_mode: bool,
    #[serde(default)]
    pub power_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_state_celsius: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_speed_limit: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_frequency_mhz: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_route: Option<String>,
    pub requested_jobs: usize,
    pub total_jobs: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchCandidateScore {
    pub candidate: DispatchCandidate,
    pub predicted_duration_ms: f64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendScore {
    pub backend: BackendKind,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendRecommendation {
    pub selected: BackendKind,
    pub objective: OptimizationObjective,
    pub source: String,
    pub rankings: Vec<BackendScore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DurationEstimate {
    pub estimate_ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_bound_ms: Option<f64>,
    pub predicted_wall_time_ms: f64,
    pub source: String,
    pub execution_regime: ExecutionRegime,
    pub eta_semantics: EtaSemantics,
    pub bound_source: BoundSource,
    #[serde(default)]
    pub countdown_safe: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_candidate: Option<DispatchCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionRegime {
    GpuCapable,
    PartialFallback,
    CpuOnly,
}

impl ExecutionRegime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GpuCapable => "gpu-capable",
            Self::PartialFallback => "partial-fallback",
            Self::CpuOnly => "cpu-only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtaSemantics {
    ModelEstimate,
    HeuristicEstimate,
    HeuristicBound,
    NonSlaFallback,
}

impl EtaSemantics {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModelEstimate => "model-estimate",
            Self::HeuristicEstimate => "heuristic-estimate",
            Self::HeuristicBound => "heuristic-bound",
            Self::NonSlaFallback => "non-sla-fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundSource {
    ModelDerived,
    HeuristicEnvelope,
    Unavailable,
}

impl BoundSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModelDerived => "model-derived",
            Self::HeuristicEnvelope => "heuristic-envelope",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnomalySeverity {
    Normal,
    Notice,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyVerdict {
    pub severity: AnomalySeverity,
    pub source: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicted_anomaly_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_estimate_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conservative_upper_bound_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_regime: Option<ExecutionRegime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eta_semantics: Option<EtaSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_source: Option<BoundSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_interpretation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_duration_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_duration_ratio_limit: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_duration_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_proof_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_proof_size_ratio_limit: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_proof_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_ratio: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlPlaneDecision {
    pub job_kind: JobKind,
    pub features: ControlPlaneFeatures,
    pub dispatch_plan: DispatchPlan,
    pub candidate_rankings: Vec<DispatchCandidateScore>,
    pub backend_recommendation: BackendRecommendation,
    pub duration_estimate: DurationEstimate,
    pub anomaly_baseline: AnomalyVerdict,
    pub model_catalog: ModelCatalog,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlPlaneExecutionSummary {
    pub decision: ControlPlaneDecision,
    pub anomaly_verdict: AnomalyVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realized_gpu_capable_stages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneReplayManifest {
    pub replay_id: String,
    pub transcript_hash: String,
    pub backend_route: String,
    pub hardware_profile: String,
    pub stage_manifest_digest: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stage_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proof_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_catalog_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProbeSample {
    pub lane: String,
    pub matched: bool,
    pub expected_digest: String,
    pub observed_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProbeSummary {
    pub ok: bool,
    pub mismatch_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<HardwareProbeSample>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityFeatureInputs {
    pub watchdog_notice_count: usize,
    pub watchdog_warning_count: usize,
    pub watchdog_critical_count: usize,
    pub timing_alert_count: usize,
    pub thermal_alert_count: usize,
    pub memory_alert_count: usize,
    pub gpu_circuit_breaker_count: usize,
    pub repeated_fallback_count: usize,
    pub anomaly_severity_score: f64,
    pub model_integrity_failure_count: usize,
    pub rate_limit_violation_count: usize,
    pub auth_failure_count: usize,
    pub malformed_request_count: usize,
    pub backend_incompatibility_attempt_count: usize,
    pub telemetry_replay_flag: bool,
    pub integrity_mismatch_flag: bool,
    pub anonymous_burst_flag: bool,
}

#[derive(Clone)]
pub struct ControlPlaneRequest<'a> {
    pub job_kind: JobKind,
    pub objective: OptimizationObjective,
    pub graph: Option<&'a ProverGraph>,
    pub constraint_count_override: Option<usize>,
    pub signal_count_override: Option<usize>,
    pub stage_node_counts_override: Option<BTreeMap<String, usize>>,
    pub field_hint: Option<FieldId>,
    pub program: Option<&'a Program>,
    pub compiled: Option<&'a CompiledProgram>,
    pub preview: Option<&'a WrapperPreview>,
    pub witness: Option<&'a Witness>,
    pub witness_inputs: Option<&'a WitnessInputs>,
    pub requested_backend: Option<BackendKind>,
    pub backend_route: Option<BackendRoute>,
    pub trust_lane: RequiredTrustLane,
    pub requested_jobs: Option<usize>,
    pub total_jobs: Option<usize>,
    pub backend_candidates: Vec<BackendKind>,
}

impl<'a> ControlPlaneRequest<'a> {
    pub fn for_program(
        job_kind: JobKind,
        graph: Option<&'a ProverGraph>,
        program: Option<&'a Program>,
        compiled: Option<&'a CompiledProgram>,
    ) -> Self {
        Self {
            job_kind,
            objective: OptimizationObjective::FastestProve,
            graph,
            constraint_count_override: None,
            signal_count_override: None,
            stage_node_counts_override: None,
            field_hint: program
                .map(|candidate| candidate.field)
                .or_else(|| compiled.map(|candidate| candidate.program.field)),
            program,
            compiled,
            preview: None,
            witness: None,
            witness_inputs: None,
            requested_backend: None,
            backend_route: None,
            trust_lane: RequiredTrustLane::StrictCryptographic,
            requested_jobs: None,
            total_jobs: None,
            backend_candidates: Vec::new(),
        }
    }
}

pub fn evaluate_control_plane(request: &ControlPlaneRequest<'_>) -> ControlPlaneDecision {
    let model_catalog = ModelCatalog::discover();
    let features = extract_features(request);
    let backend_recommendation = recommend_backend(request, &features, &model_catalog);
    let mut candidate_rankings = rank_dispatch_candidates(
        &features,
        backend_recommendation.selected,
        request.objective,
        &model_catalog,
    );
    let mut notes = vec![
        "control-plane inference is advisory only; proof arithmetic and verification semantics are unchanged"
            .to_string(),
    ];
    apply_mobile_dispatch_policy(&features, &mut candidate_rankings, &mut notes);
    let dispatch_plan = candidate_rankings
        .first()
        .map(|score| score.candidate.to_plan())
        .unwrap_or_else(|| DispatchCandidate::CpuOnly.to_plan());
    let duration_estimate = estimate_duration(
        &features,
        backend_recommendation.selected,
        dispatch_plan.candidate,
        request.objective,
        &candidate_rankings,
        &model_catalog,
    );
    let anomaly_baseline = baseline_anomaly(
        &features,
        backend_recommendation.selected,
        dispatch_plan.candidate,
        request.objective,
        &duration_estimate,
        &model_catalog,
    );

    if model_catalog.scheduler.is_none() {
        notes.push("scheduler model unavailable; using heuristic candidate scoring".to_string());
    }
    if model_catalog.backend.is_none() {
        notes.push("backend recommender unavailable; using heuristic backend ranking".to_string());
    }
    if model_catalog.duration.is_none() {
        notes.push(
            "duration estimator unavailable; using heuristic advisory estimate/bound semantics"
                .to_string(),
        );
    }
    if model_catalog.anomaly.is_none() {
        notes.push("anomaly detector unavailable; using residual envelope heuristics".to_string());
    }
    if model_catalog.security.is_none() {
        notes.push(
            "security detector unavailable; deterministic security supervision remains active"
                .to_string(),
        );
    }
    if model_catalog.threshold_optimizer.is_none() {
        notes.push(
            "threshold optimizer model unavailable; using adaptive EMA crossover learning only"
                .to_string(),
        );
    }
    for descriptor in [
        model_catalog.scheduler.as_ref(),
        model_catalog.backend.as_ref(),
        model_catalog.duration.as_ref(),
        model_catalog.anomaly.as_ref(),
        model_catalog.security.as_ref(),
        model_catalog.threshold_optimizer.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(notice) = &descriptor.freshness_notice {
            notes.push(format!(
                "{} model freshness notice: {}",
                descriptor.lane.as_str(),
                notice
            ));
        }
    }
    notes.extend(backend_recommendation.notes.iter().cloned());

    ControlPlaneDecision {
        job_kind: request.job_kind,
        features,
        dispatch_plan,
        candidate_rankings,
        backend_recommendation,
        duration_estimate,
        anomaly_baseline,
        model_catalog,
        notes,
    }
}

pub fn finalize_control_plane_execution(
    mut decision: ControlPlaneDecision,
    report: &GraphExecutionReport,
    artifact: Option<&ProofArtifact>,
) -> ControlPlaneExecutionSummary {
    let proof_size_bytes = artifact.map(|value| value.proof.len() as u64).or_else(|| {
        artifact.and_then(|value| {
            value
                .metadata
                .get("proof_size_bytes")
                .and_then(|raw| raw.parse().ok())
        })
    });
    let realized_gpu_capable_stages = report
        .stage_breakdown()
        .into_iter()
        .filter(|(stage, telemetry)| is_gpu_capable_stage_key(stage) && telemetry.gpu_nodes > 0)
        .map(|(stage, _)| stage)
        .collect::<Vec<_>>();
    apply_realized_eta_fallback(&mut decision, &realized_gpu_capable_stages);
    let anomaly_verdict = evaluate_observed_anomaly(
        &decision.anomaly_baseline,
        report.total_wall_time.as_secs_f64() * 1_000.0,
        proof_size_bytes,
    );

    ControlPlaneExecutionSummary {
        decision,
        anomaly_verdict,
        realized_gpu_capable_stages,
        proof_size_bytes,
    }
}

pub fn enforce_apple_silicon_production_lane(
    hardware_profile: HardwareProfile,
    hybrid_mode: bool,
    swarm_production_mode: bool,
) -> Result<(), RuntimeError> {
    if !(hybrid_mode || swarm_production_mode) {
        return Ok(());
    }

    if hardware_profile.is_apple() {
        return Ok(());
    }

    Err(RuntimeError::HardwareProfileMismatch {
        required: "apple-silicon production proving lane".to_string(),
        detected: hardware_profile.as_str().to_string(),
    })
}

pub fn replay_manifest_digest(manifest: &ControlPlaneReplayManifest) -> String {
    let bytes = serde_json::to_vec(manifest).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

pub fn persist_replay_manifest(
    manifest: &ControlPlaneReplayManifest,
) -> Result<(PathBuf, String), RuntimeError> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        RuntimeError::Execution("HOME is not set; cannot persist replay manifest".to_string())
    })?;
    let root = PathBuf::from(home).join(".zkf").join("replay-manifests");
    fs::create_dir_all(&root).map_err(|err| {
        RuntimeError::Execution(format!(
            "failed to create replay manifest directory {}: {err}",
            root.display()
        ))
    })?;

    let path = root.join(format!("{}.json", manifest.replay_id));
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|err| {
        RuntimeError::Execution(format!("failed to serialize replay manifest: {err}"))
    })?;
    fs::write(&path, &bytes).map_err(|err| {
        RuntimeError::Execution(format!(
            "failed to write replay manifest {}: {err}",
            path.display()
        ))
    })?;
    Ok((path, format!("{:x}", Sha256::digest(bytes))))
}

pub fn run_continuous_hardware_probes() -> Result<HardwareProbeSummary, RuntimeError> {
    #[cfg(target_vendor = "apple")]
    {
        run_continuous_hardware_probes_apple()
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        Ok(HardwareProbeSummary {
            ok: false,
            mismatch_count: 1,
            samples: vec![HardwareProbeSample {
                lane: "host".to_string(),
                matched: false,
                expected_digest: "apple-silicon".to_string(),
                observed_digest: HardwareProfile::detect().as_str().to_string(),
                detail: Some(
                    "continuous hardware probes require Apple Silicon + Metal runtime support"
                        .to_string(),
                ),
            }],
        })
    }
}

#[cfg(target_vendor = "apple")]
fn run_continuous_hardware_probes_apple() -> Result<HardwareProbeSummary, RuntimeError> {
    let samples = vec![
        hash_probe_sha256()?,
        hash_probe_keccak256()?,
        ntt_probe_goldilocks()?,
        msm_probe_pallas()?,
    ];
    let mismatch_count = samples.iter().filter(|sample| !sample.matched).count();
    Ok(HardwareProbeSummary {
        ok: mismatch_count == 0,
        mismatch_count,
        samples,
    })
}

#[cfg(target_vendor = "apple")]
fn hash_probe_sha256() -> Result<HardwareProbeSample, RuntimeError> {
    use sha2::Sha256;

    let hasher = zkf_metal::MetalHasher::new().ok_or_else(|| {
        RuntimeError::Device("Metal hash accelerator unavailable for SHA-256 probe".to_string())
    })?;
    let input_len = 64usize;
    let batch = 1_024usize;
    let inputs = (0..batch * input_len)
        .map(|idx| ((idx * 17 + 11) % 251) as u8)
        .collect::<Vec<_>>();

    let mut expected = Vec::with_capacity(batch * 32);
    for chunk in inputs.chunks_exact(input_len) {
        let mut digest = Sha256::new();
        digest.update(chunk);
        expected.extend_from_slice(&digest.finalize());
    }
    let observed = hasher
        .batch_sha256(&inputs, input_len)
        .ok_or_else(|| RuntimeError::Device("Metal SHA-256 probe dispatch failed".to_string()))?;
    Ok(probe_sample("hash-sha256", &expected, &observed, None))
}

#[cfg(target_vendor = "apple")]
fn hash_probe_keccak256() -> Result<HardwareProbeSample, RuntimeError> {
    let hasher = zkf_metal::MetalHasher::new().ok_or_else(|| {
        RuntimeError::Device("Metal hash accelerator unavailable for Keccak-256 probe".to_string())
    })?;
    let input_len = 136usize;
    let batch = 1_024usize;
    let inputs = (0..batch * input_len)
        .map(|idx| ((idx * 29 + 7) % 253) as u8)
        .collect::<Vec<_>>();

    let mut expected = Vec::with_capacity(batch * 32);
    for chunk in inputs.chunks_exact(input_len) {
        let mut keccak = Keccak::v256();
        keccak.update(chunk);
        let mut output = [0u8; 32];
        keccak.finalize(&mut output);
        expected.extend_from_slice(&output);
    }
    let observed = hasher.batch_keccak256(&inputs, input_len).ok_or_else(|| {
        RuntimeError::Device("Metal Keccak-256 probe dispatch failed".to_string())
    })?;
    Ok(probe_sample("hash-keccak256", &expected, &observed, None))
}

#[cfg(target_vendor = "apple")]
fn ntt_probe_goldilocks() -> Result<HardwareProbeSample, RuntimeError> {
    let metal = zkf_metal::MetalDft::<Goldilocks>::new().ok_or_else(|| {
        RuntimeError::Device("Metal Goldilocks NTT accelerator unavailable".to_string())
    })?;
    let height = 1 << 10;
    let values = (0..height as u64)
        .map(|idx| Goldilocks::from_u64(idx + 1))
        .collect::<Vec<_>>();
    let cpu = cpu_dft_batch_goldilocks(RowMajorMatrix::new(values.clone(), 1));
    let gpu = metal.dft_batch(RowMajorMatrix::new(values, 1));
    let expected = serde_json::to_vec(
        &cpu.values
            .iter()
            .map(|value| value.as_canonical_u64())
            .collect::<Vec<_>>(),
    )
    .map_err(|err| RuntimeError::Execution(format!("failed to serialize CPU NTT probe: {err}")))?;
    let observed = serde_json::to_vec(
        &gpu.values
            .iter()
            .map(|value| value.as_canonical_u64())
            .collect::<Vec<_>>(),
    )
    .map_err(|err| RuntimeError::Execution(format!("failed to serialize GPU NTT probe: {err}")))?;
    Ok(probe_sample("ntt-goldilocks", &expected, &observed, None))
}

#[cfg(target_vendor = "apple")]
fn msm_probe_pallas() -> Result<HardwareProbeSample, RuntimeError> {
    let n = zkf_metal::current_thresholds().msm.max(64);
    let bases = (0..n)
        .map(|idx| (Pallas::generator() * PastaFq::from((idx + 2) as u64)).to_affine())
        .collect::<Vec<PallasAffine>>();
    let scalars = (0..n)
        .map(|idx| PastaFq::from((idx + 11) as u64))
        .collect::<Vec<_>>();
    let expected = scalars
        .iter()
        .zip(bases.iter())
        .map(|(scalar, base)| Pallas::from(*base) * scalar)
        .fold(Pallas::identity(), |acc, point| acc + point)
        .to_affine();
    let observed = zkf_metal::try_metal_pallas_msm(&scalars, &bases).ok_or_else(|| {
        RuntimeError::Device("Metal Pallas MSM probe dispatch failed".to_string())
    })?;
    let expected_bytes = serde_json::to_vec(&format!("{:?}", expected)).map_err(|err| {
        RuntimeError::Execution(format!("failed to serialize CPU MSM probe: {err}"))
    })?;
    let observed_bytes =
        serde_json::to_vec(&format!("{:?}", observed.to_affine())).map_err(|err| {
            RuntimeError::Execution(format!("failed to serialize GPU MSM probe: {err}"))
        })?;
    Ok(probe_sample(
        "msm-pallas",
        &expected_bytes,
        &observed_bytes,
        None,
    ))
}

#[cfg(target_vendor = "apple")]
fn cpu_dft_batch_goldilocks(mut mat: RowMajorMatrix<Goldilocks>) -> RowMajorMatrix<Goldilocks> {
    let width = mat.width;
    let n = mat.values.len();
    if width == 0 || n == 0 {
        return mat;
    }
    let height = n / width;
    let log_n = height.trailing_zeros() as usize;
    let g = Goldilocks::two_adic_generator(log_n);

    for col in 0..width {
        let mut column = (0..height)
            .map(|row| mat.values[row * width + col])
            .collect::<Vec<_>>();
        bit_reverse_permute(&mut column);

        for stage in 0..log_n {
            let half = 1usize << stage;
            let group_size = half << 1;
            let step = height >> (stage + 1);

            for group in 0..(height / group_size) {
                for j in 0..half {
                    let idx0 = group * group_size + j;
                    let idx1 = idx0 + half;
                    let w = g.exp_u64((j * step) as u64);
                    let a = column[idx0];
                    let b = column[idx1];
                    let wb = w * b;
                    column[idx0] = a + wb;
                    column[idx1] = a - wb;
                }
            }
        }

        for (row, value) in column.into_iter().enumerate() {
            mat.values[row * width + col] = value;
        }
    }

    mat
}

#[cfg(target_vendor = "apple")]
fn bit_reverse_permute<F: Copy>(values: &mut [F]) {
    let n = values.len();
    let log_n = n.trailing_zeros();
    for idx in 0..n {
        let rev = idx.reverse_bits() >> (usize::BITS - log_n);
        if idx < rev {
            values.swap(idx, rev);
        }
    }
}

#[cfg(target_vendor = "apple")]
fn probe_sample(
    lane: &str,
    expected: &[u8],
    observed: &[u8],
    detail: Option<String>,
) -> HardwareProbeSample {
    let expected_digest = format!("{:x}", Sha256::digest(expected));
    let observed_digest = format!("{:x}", Sha256::digest(observed));
    HardwareProbeSample {
        lane: lane.to_string(),
        matched: expected_digest == observed_digest,
        expected_digest,
        observed_digest,
        detail,
    }
}

pub fn recommend_backend_for_program(
    program: &Program,
    requested_jobs: Option<usize>,
    objective: OptimizationObjective,
) -> BackendRecommendation {
    let request = ControlPlaneRequest {
        job_kind: JobKind::Prove,
        objective,
        graph: None,
        constraint_count_override: None,
        signal_count_override: None,
        stage_node_counts_override: None,
        field_hint: Some(program.field),
        program: Some(program),
        compiled: None,
        preview: None,
        witness: None,
        witness_inputs: None,
        requested_backend: None,
        backend_route: None,
        trust_lane: RequiredTrustLane::StrictCryptographic,
        requested_jobs,
        total_jobs: requested_jobs,
        backend_candidates: vec![
            BackendKind::ArkworksGroth16,
            BackendKind::Plonky3,
            BackendKind::Nova,
            BackendKind::HyperNova,
            BackendKind::Halo2,
            BackendKind::Halo2Bls12381,
            BackendKind::Sp1,
            BackendKind::RiscZero,
            BackendKind::MidnightCompact,
        ],
    };
    let features = extract_features(&request);
    recommend_backend(&request, &features, &ModelCatalog::discover())
}

fn requested_field(request: &ControlPlaneRequest<'_>) -> Option<FieldId> {
    request
        .program
        .map(|program| program.field)
        .or_else(|| request.compiled.map(|compiled| compiled.program.field))
        .or(request.field_hint)
}

fn supported_fields_for_backend(backend: BackendKind) -> &'static [FieldId] {
    match backend {
        BackendKind::ArkworksGroth16 | BackendKind::Nova | BackendKind::HyperNova => {
            &[FieldId::Bn254]
        }
        BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => {
            &[FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
        }
        BackendKind::Halo2 => &[FieldId::PastaFp],
        BackendKind::Halo2Bls12381 => &[FieldId::Bls12_381],
        BackendKind::MidnightCompact => &[FieldId::PastaFp, FieldId::PastaFq],
    }
}

fn is_bn254_only_blackbox(op: &str) -> bool {
    matches!(
        op.to_ascii_lowercase().as_str(),
        "poseidon" | "poseidon2" | "pedersen" | "schnorr_verify"
    )
}

fn backend_program_constraint_error(backend: BackendKind, program: &Program) -> Option<String> {
    let report = capability_report_for_backend(backend);
    let required_kinds = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            Constraint::Equal { .. } => "equal".to_string(),
            Constraint::Boolean { .. } => "boolean".to_string(),
            Constraint::Range { .. } => "range".to_string(),
            Constraint::BlackBox { .. } => "blackbox".to_string(),
            Constraint::Lookup { .. } => "lookup".to_string(),
        })
        .collect::<BTreeSet<_>>();

    let capabilities = backend_for(backend).capabilities();
    let supported_kinds = capabilities
        .supported_constraint_kinds
        .iter()
        .map(|kind| kind.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if supported_kinds.is_empty() && !required_kinds.is_empty() {
        return Some(format!(
            "backend '{}' does not advertise native constraint kind support; program requires [{}]",
            backend,
            required_kinds
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let missing_kinds = required_kinds
        .iter()
        .filter(|kind| {
            let kind_lower = kind.to_ascii_lowercase();
            if kind_lower == "lookup" {
                let Some(report) = &report else {
                    return !supported_kinds.contains(&kind_lower);
                };
                return !(report.native_lookup_support || report.lookup_lowering_support);
            }
            !supported_kinds.contains(&kind_lower)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing_kinds.is_empty() {
        return Some(format!(
            "backend '{}' missing required constraint kinds: [{}] (supports [{}])",
            backend,
            missing_kinds.join(", "),
            capabilities.supported_constraint_kinds.join(", ")
        ));
    }

    let required_ops = program
        .constraints
        .iter()
        .filter_map(|constraint| {
            if let Constraint::BlackBox { op, .. } = constraint {
                Some(op.as_str().to_string())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    if required_ops.is_empty() {
        return None;
    }

    let supported_ops = capabilities
        .supported_blackbox_ops
        .iter()
        .map(|op| op.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if supported_ops.is_empty() {
        return Some(format!(
            "backend '{}' does not advertise native blackbox op support; program requires [{}]",
            backend,
            required_ops.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    let missing_ops = required_ops
        .iter()
        .filter(|op| !supported_ops.contains(&op.to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_ops.is_empty() {
        return Some(format!(
            "backend '{}' missing required blackbox ops: [{}] (supports [{}])",
            backend,
            missing_ops.join(", "),
            capabilities.supported_blackbox_ops.join(", ")
        ));
    }

    let bn254_only_required_ops = required_ops
        .iter()
        .filter(|op| is_bn254_only_blackbox(op))
        .cloned()
        .collect::<Vec<_>>();
    if !bn254_only_required_ops.is_empty() && program.field != FieldId::Bn254 {
        return Some(format!(
            "backend '{}' currently supports [{}] blackbox ops only for bn254 field programs; found {}",
            backend,
            bn254_only_required_ops.join(", "),
            program.field
        ));
    }

    None
}

fn backend_structural_filter_reasons(
    request: &ControlPlaneRequest<'_>,
    backend: BackendKind,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(field) = requested_field(request) {
        let supported_fields = supported_fields_for_backend(backend);
        if !supported_fields.is_empty() && !supported_fields.contains(&field) {
            reasons.push(format!(
                "field '{}' is incompatible (supported fields: {})",
                field,
                supported_fields
                    .iter()
                    .map(|candidate| candidate.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if let Some(program) = request.program
        && let Some(error) = backend_program_constraint_error(backend, program)
    {
        reasons.push(error);
    }
    reasons
}

fn backend_readiness_filter_reason(
    request: &ControlPlaneRequest<'_>,
    backend: BackendKind,
) -> Option<String> {
    if request.backend_route == Some(BackendRoute::ExplicitCompat)
        && request.requested_backend == Some(backend)
    {
        return None;
    }
    if request.requested_backend == Some(backend) {
        return None;
    }
    let report = capability_report_for_backend(backend)?;
    if report.production_ready {
        return None;
    }
    Some(format!(
        "host readiness is '{}' (reason={})",
        report.readiness,
        report.readiness_reason.as_deref().unwrap_or("not-ready")
    ))
}

fn discover_model(lane: ModelLane) -> Result<Option<ModelDescriptor>, String> {
    if let Some(explicit) = std::env::var_os(lane.env_var()) {
        let path = PathBuf::from(explicit);
        if !path.exists() {
            return Err(format!(
                "{} points to a missing model: {}",
                lane.env_var(),
                path.display()
            ));
        }
        return load_model_descriptor(lane, &path, ModelSource::Environment).map(Some);
    }
    if let Some(env_var) = lane.compatibility_env_var()
        && let Some(explicit) = std::env::var_os(env_var)
    {
        let path = PathBuf::from(explicit);
        if !path.exists() {
            return Err(format!(
                "{env_var} points to a missing model: {}",
                path.display()
            ));
        }
        return load_model_descriptor(lane, &path, ModelSource::Environment).map(Some);
    }

    let mut auto_discovery_errors = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let root = PathBuf::from(home).join(".zkf").join("models");
        for file_name in lane.default_file_names() {
            let candidate = root.join(file_name);
            if candidate.exists() {
                match load_model_descriptor(lane, &candidate, ModelSource::UserHome) {
                    Ok(descriptor) => return Ok(Some(descriptor)),
                    Err(err) => auto_discovery_errors.push(err),
                }
            }
        }
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let coreml_root = repo_root.join("target").join("coreml");
    for file_name in lane.default_file_names() {
        let candidate = coreml_root.join(file_name);
        if candidate.exists() {
            match load_model_descriptor(lane, &candidate, ModelSource::RepoLocal) {
                Ok(descriptor) => return Ok(Some(descriptor)),
                Err(err) => auto_discovery_errors.push(err),
            }
        }
    }

    if auto_discovery_errors.is_empty() {
        Ok(None)
    } else {
        Err(auto_discovery_errors.join(" | "))
    }
}

fn load_model_descriptor(
    lane: ModelLane,
    path: &Path,
    source: ModelSource,
) -> Result<ModelDescriptor, String> {
    let (sidecar_path, sidecar) = load_model_sidecar(path);
    let quality_gate = match sidecar.as_ref() {
        Some(payload) => parse_model_quality_gate(payload)?,
        None => None,
    };
    validate_model_sidecar(lane, path, source, sidecar.as_ref(), quality_gate.as_ref())?;
    let integrity = inspect_model_integrity(
        lane,
        path,
        source,
        sidecar_path.as_deref(),
        sidecar.as_ref(),
    )?;

    Ok(ModelDescriptor {
        lane,
        path: path.display().to_string(),
        source,
        version: sidecar
            .as_ref()
            .and_then(|payload| payload.get("version"))
            .and_then(|value| value.as_str())
            .map(str::to_string),
        schema_fingerprint: sidecar
            .as_ref()
            .and_then(|payload| payload.get("schema_fingerprint"))
            .and_then(|value| value.as_str())
            .map(str::to_string),
        input_shape: sidecar
            .as_ref()
            .and_then(|payload| payload.get("input_shape"))
            .and_then(|value| value.as_u64())
            .map(|value| value as usize),
        output_name: sidecar
            .as_ref()
            .and_then(|payload| payload.get("output_name"))
            .and_then(|value| value.as_str())
            .map(str::to_string),
        quality_gate,
        corpus_hash: sidecar
            .as_ref()
            .and_then(|payload| payload.get("corpus_hash"))
            .and_then(|value| value.as_str())
            .map(str::to_string),
        corpus_record_count: sidecar
            .as_ref()
            .and_then(|payload| payload.get("record_count"))
            .and_then(|value| value.as_u64()),
        trained_at: sidecar
            .as_ref()
            .and_then(|payload| payload.get("trained_at"))
            .and_then(|value| value.as_str())
            .map(str::to_string),
        freshness_notice: model_freshness_notice(sidecar.as_ref()),
        package_tree_sha256: integrity.package_tree_sha256,
        sidecar_sha256: integrity.sidecar_sha256,
        manifest_sha256: integrity.manifest_sha256,
        model_fingerprint: integrity.model_fingerprint,
        pinned: integrity.pinned,
        trusted: integrity.trusted,
        quarantined: integrity.quarantined,
        allow_unpinned_dev_bypass: integrity.allow_unpinned_dev_bypass,
        integrity_failures: integrity.integrity_failures,
    })
}

fn load_model_sidecar(path: &Path) -> (Option<PathBuf>, Option<serde_json::Value>) {
    let mut candidates = Vec::new();
    let path_json = PathBuf::from(format!("{}.json", path.display()));
    candidates.push(path_json);
    if path.is_dir() {
        candidates.push(path.join("zkf-model.json"));
    }
    for candidate in candidates {
        if let Ok(bytes) = fs::read(&candidate)
            && let Ok(payload) = serde_json::from_slice(&bytes)
        {
            return (Some(candidate), Some(payload));
        }
    }
    (None, None)
}

fn parse_model_quality_gate(
    payload: &serde_json::Value,
) -> Result<Option<ModelQualityGate>, String> {
    payload
        .get("quality_gate")
        .cloned()
        .map(serde_json::from_value::<ModelQualityGate>)
        .transpose()
        .map_err(|err| format!("invalid quality_gate metadata: {err}"))
}

fn validate_model_sidecar(
    lane: ModelLane,
    path: &Path,
    source: ModelSource,
    sidecar: Option<&serde_json::Value>,
    quality_gate: Option<&ModelQualityGate>,
) -> Result<(), String> {
    let descriptor_label = format!("{} model {}", lane.as_str(), path.display());
    let allowed_shapes = lane.supported_input_shapes();
    let auto_discovered = source != ModelSource::Environment;

    let Some(sidecar) = sidecar else {
        if auto_discovered {
            return Err(format!(
                "{descriptor_label} is missing sidecar metadata required for auto-discovery"
            ));
        }
        return Ok(());
    };

    if let Some(raw_lane) = sidecar.get("lane").and_then(|value| value.as_str())
        && raw_lane != lane.as_str()
    {
        return Err(format!(
            "{descriptor_label} sidecar lane mismatch: expected '{}' but found '{}'",
            lane.as_str(),
            raw_lane
        ));
    }
    if let Some(raw_output_name) = sidecar.get("output_name").and_then(|value| value.as_str())
        && raw_output_name != lane.expected_output_name()
    {
        return Err(format!(
            "{descriptor_label} sidecar output mismatch: expected '{}' but found '{}'",
            lane.expected_output_name(),
            raw_output_name
        ));
    }
    if let Some(raw_shape) = sidecar.get("input_shape").and_then(|value| value.as_u64())
        && !allowed_shapes.contains(&(raw_shape as usize))
    {
        return Err(format!(
            "{descriptor_label} sidecar input shape mismatch: expected one of {:?} but found {raw_shape}",
            allowed_shapes
        ));
    }
    if let Some(raw_schema) = sidecar
        .get("schema_fingerprint")
        .and_then(|value| value.as_str())
    {
        let raw_shape = sidecar
            .get("input_shape")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize)
            .unwrap_or_else(|| lane.supported_input_shapes()[0]);
        let expected_schema = schema_fingerprint_for_lane_shape(lane, raw_shape);
        if let Some(expected_schema) = expected_schema
            && raw_schema != expected_schema
        {
            return Err(format!(
                "{descriptor_label} sidecar schema fingerprint mismatch: expected '{expected_schema}' but found '{raw_schema}'"
            ));
        }
    }

    match (auto_discovered, quality_gate) {
        (true, Some(gate)) if gate.passed => Ok(()),
        (true, Some(gate)) => Err(format!(
            "{descriptor_label} failed quality gate: {}",
            if gate.reasons.is_empty() {
                "sidecar marked the model as failed".to_string()
            } else {
                gate.reasons.join(", ")
            }
        )),
        (true, None) => Err(format!(
            "{descriptor_label} is missing quality_gate metadata required for auto-discovery"
        )),
        (false, Some(gate)) if !gate.passed => Err(format!(
            "{descriptor_label} failed explicit quality gate: {}",
            if gate.reasons.is_empty() {
                "sidecar marked the model as failed".to_string()
            } else {
                gate.reasons.join(", ")
            }
        )),
        _ => Ok(()),
    }
}

#[derive(Debug, Default)]
struct ModelIntegrityInspection {
    package_tree_sha256: Option<String>,
    sidecar_sha256: Option<String>,
    manifest_sha256: Option<String>,
    model_fingerprint: Option<String>,
    pinned: bool,
    trusted: bool,
    quarantined: bool,
    allow_unpinned_dev_bypass: bool,
    integrity_failures: Vec<String>,
}

fn inspect_model_integrity(
    lane: ModelLane,
    path: &Path,
    source: ModelSource,
    sidecar_path: Option<&Path>,
    sidecar: Option<&serde_json::Value>,
) -> Result<ModelIntegrityInspection, String> {
    let mut inspection = ModelIntegrityInspection::default();
    let package_tree_sha256 = hash_model_package(path).ok();
    let sidecar_sha256 = sidecar_path.and_then(|candidate| hash_path(candidate).ok());
    let model_fingerprint =
        model_fingerprint(package_tree_sha256.as_deref(), sidecar_sha256.as_deref());
    let allow_unpinned_dev_bypass = allow_unpinned_models()
        || matches!(source, ModelSource::RepoLocal)
        || (matches!(source, ModelSource::Environment) && is_explicit_development_model_path(path));
    let auto_discovered_user_model = matches!(source, ModelSource::UserHome);

    inspection.package_tree_sha256 = package_tree_sha256.clone();
    inspection.sidecar_sha256 = sidecar_sha256.clone();
    inspection.model_fingerprint = model_fingerprint.clone();
    inspection.allow_unpinned_dev_bypass = allow_unpinned_dev_bypass;

    if let Some(fingerprint) = model_fingerprint.as_deref()
        && is_quarantined_model_fingerprint(fingerprint)
    {
        inspection.quarantined = true;
        inspection
            .integrity_failures
            .push(format!("model fingerprint {fingerprint} is quarantined"));
    }

    if let Some((manifest_path, manifest)) = load_model_bundle_manifest(path) {
        inspection.manifest_sha256 = hash_path(&manifest_path).ok();
        match validate_manifest_lane_entry(
            lane,
            path,
            sidecar_path,
            sidecar,
            &manifest_path,
            &manifest,
            package_tree_sha256.as_deref(),
            sidecar_sha256.as_deref(),
        ) {
            Ok(()) => {
                inspection.pinned = true;
                inspection.trusted = !inspection.quarantined;
            }
            Err(err) => {
                inspection.integrity_failures.push(err);
            }
        }
    } else if auto_discovered_user_model && !allow_unpinned_dev_bypass {
        inspection
            .integrity_failures
            .push("installed production model is missing a pinned bundle manifest".to_string());
    }

    if auto_discovered_user_model && !allow_unpinned_dev_bypass && !inspection.pinned {
        return Err(format!(
            "{} model {} rejected: {}",
            lane.as_str(),
            path.display(),
            inspection.integrity_failures.join(", ")
        ));
    }

    if inspection.quarantined {
        return Err(format!(
            "{} model {} rejected: {}",
            lane.as_str(),
            path.display(),
            inspection.integrity_failures.join(", ")
        ));
    }

    if inspection.pinned && inspection.integrity_failures.is_empty() {
        inspection.trusted = true;
    }

    Ok(inspection)
}

fn load_model_bundle_manifest(path: &Path) -> Option<(PathBuf, serde_json::Value)> {
    let root = if path.is_dir() {
        Some(path)
    } else {
        path.parent()
    }?;
    for file_name in [
        "control_plane_models_manifest.json",
        "fixture_manifest.json",
        "zkf-model-bundle-manifest.json",
    ] {
        let candidate = root.join(file_name);
        if let Ok(bytes) = fs::read(&candidate)
            && let Ok(payload) = serde_json::from_slice(&bytes)
        {
            return Some((candidate, payload));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn validate_manifest_lane_entry(
    lane: ModelLane,
    package_path: &Path,
    sidecar_path: Option<&Path>,
    sidecar: Option<&serde_json::Value>,
    manifest_path: &Path,
    manifest: &serde_json::Value,
    package_tree_sha256: Option<&str>,
    sidecar_sha256: Option<&str>,
) -> Result<(), String> {
    let Some(entry) = manifest
        .get("lanes")
        .and_then(|value| value.get(lane.as_str()))
    else {
        return Err(format!(
            "bundle manifest {} does not contain a '{}' lane entry",
            manifest_path.display(),
            lane.as_str()
        ));
    };

    let manifest_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let package_path_in_manifest = entry
        .get("package")
        .and_then(|value| value.as_str())
        .map(|raw| resolve_manifest_artifact_path(manifest_root, raw));
    if let Some(expected_path) = package_path_in_manifest
        && expected_path != package_path
    {
        return Err(format!(
            "bundle manifest {} points '{}' to {} but runtime discovered {}",
            manifest_path.display(),
            lane.as_str(),
            expected_path.display(),
            package_path.display()
        ));
    }
    if let (Some(actual), Some(expected)) = (
        package_tree_sha256,
        entry
            .get("package_tree_sha256")
            .and_then(|value| value.as_str()),
    ) && actual != expected
    {
        return Err(format!(
            "package hash mismatch for '{}' (expected {expected}, found {actual})",
            lane.as_str()
        ));
    }

    let sidecar_manifest_path = entry
        .get("sidecar")
        .and_then(|value| value.as_str())
        .map(|raw| resolve_manifest_artifact_path(manifest_root, raw));
    if let (Some(expected_path), Some(actual_path)) = (sidecar_manifest_path, sidecar_path)
        && expected_path != actual_path
    {
        return Err(format!(
            "sidecar path mismatch for '{}' (manifest={}, runtime={})",
            lane.as_str(),
            expected_path.display(),
            actual_path.display()
        ));
    }
    if let (Some(actual), Some(expected)) = (
        sidecar_sha256,
        entry.get("sidecar_sha256").and_then(|value| value.as_str()),
    ) && actual != expected
    {
        return Err(format!(
            "sidecar hash mismatch for '{}' (expected {expected}, found {actual})",
            lane.as_str()
        ));
    }
    if let Some(raw_output_name) = entry.get("output_name").and_then(|value| value.as_str())
        && raw_output_name != lane.expected_output_name()
    {
        return Err(format!(
            "manifest output mismatch for '{}' (expected {}, found {})",
            lane.as_str(),
            lane.expected_output_name(),
            raw_output_name
        ));
    }
    if let Some(raw_shape) = entry.get("input_shape").and_then(|value| value.as_u64())
        && !lane
            .supported_input_shapes()
            .contains(&(raw_shape as usize))
    {
        return Err(format!(
            "manifest input shape mismatch for '{}' (shape={raw_shape})",
            lane.as_str()
        ));
    }
    if let Some(schema_fingerprint) = sidecar
        .and_then(|value| value.get("schema_fingerprint"))
        .and_then(|value| value.as_str())
        && let Some(expected_schema) = entry
            .get("schema_fingerprint")
            .and_then(|value| value.as_str())
        && schema_fingerprint != expected_schema
    {
        return Err(format!(
            "schema fingerprint drift for '{}' (expected {expected_schema}, found {schema_fingerprint})",
            lane.as_str()
        ));
    }
    if let Some(raw_lane) = entry.get("lane").and_then(|value| value.as_str())
        && raw_lane != lane.as_str()
    {
        return Err(format!(
            "manifest lane mismatch for '{}' (found {raw_lane})",
            lane.as_str()
        ));
    }
    if let Some(sidecar_schema) = sidecar
        .and_then(|value| value.get("schema"))
        .and_then(|value| value.as_str())
        && let Some(expected_schema) = entry.get("schema").and_then(|value| value.as_str())
        && sidecar_schema != expected_schema
    {
        return Err(format!(
            "manifest schema mismatch for '{}' (expected {expected_schema}, found {sidecar_schema})",
            lane.as_str()
        ));
    }
    if let Some(sidecar_version) = sidecar
        .and_then(|value| value.get("version"))
        .and_then(|value| value.as_str())
        && let Some(expected_version) = entry.get("version").and_then(|value| value.as_str())
        && sidecar_version != expected_version
    {
        return Err(format!(
            "manifest version mismatch for '{}' (expected {expected_version}, found {sidecar_version})",
            lane.as_str()
        ));
    }
    Ok(())
}

fn resolve_manifest_artifact_path(root: &Path, raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    }
}

fn hash_model_package(path: &Path) -> Result<String, String> {
    if path.is_file() {
        return hash_path(path);
    }
    let mut hasher = Sha256::new();
    let entries = collect_file_entries(path)?;
    for entry in entries {
        hasher.update(
            entry
                .strip_prefix(path)
                .unwrap_or(entry.as_path())
                .to_string_lossy()
                .as_bytes(),
        );
        hasher.update([0u8]);
        hasher.update(fs::read(&entry).map_err(|err| format!("hash {}: {err}", entry.display()))?);
        hasher.update([0u8]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_file_entries(root: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut entries = fs::read_dir(current)
            .map_err(|err| format!("read_dir {}: {err}", current.display()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("file_type {}: {err}", path.display()))?;
            if file_type.is_dir() {
                walk(&path, out)?;
            } else if file_type.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn hash_path(path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).map_err(|err| format!("hash {}: {err}", path.display()))?);
    Ok(format!("{:x}", hasher.finalize()))
}

fn model_fingerprint(
    package_tree_sha256: Option<&str>,
    sidecar_sha256: Option<&str>,
) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut touched = false;
    if let Some(value) = package_tree_sha256 {
        hasher.update(value.as_bytes());
        touched = true;
    }
    if let Some(value) = sidecar_sha256 {
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        touched = true;
    }
    touched.then(|| format!("{:x}", hasher.finalize()))
}

fn allow_unpinned_models() -> bool {
    matches!(
        std::env::var("ZKF_ALLOW_UNPINNED_MODELS")
            .ok()
            .as_deref()
            .map(|value| value.trim().to_ascii_lowercase()),
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on")
    )
}

fn is_explicit_development_model_path(path: &Path) -> bool {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    path.starts_with(&repo_root) || path.starts_with(std::env::temp_dir())
}

fn security_quarantine_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".zkf").join("security").join("quarantine"))
}

fn is_quarantined_model_fingerprint(fingerprint: &str) -> bool {
    security_quarantine_dir()
        .map(|dir| dir.join(format!("{fingerprint}.json")))
        .is_some_and(|path| path.exists())
}

fn extract_features(request: &ControlPlaneRequest<'_>) -> ControlPlaneFeatures {
    let resources = SystemResources::detect();
    let platform = PlatformCapability::detect();
    let hardware_profile = HardwareProfile::from_resources(&resources);
    let metal_runtime = metal_runtime_report();
    let host_snapshot = detect_host_snapshot();
    let circuit = circuit_profile(
        request.program,
        request.compiled,
        request.preview,
        request.witness,
        request.witness_inputs,
        request.constraint_count_override,
        request.signal_count_override,
    );
    let (requested_jobs, total_jobs) = {
        let recommendation = resources.recommend();
        let requested = request
            .requested_jobs
            .unwrap_or(recommendation.proving_threads.max(1))
            .max(1);
        let total = request.total_jobs.unwrap_or(requested).max(requested);
        (requested, total)
    };
    let stage_node_counts = request
        .stage_node_counts_override
        .clone()
        .or_else(|| request.graph.map(stage_counts_from_graph))
        .unwrap_or_default();
    let gpu_capable_stage_counts = stage_node_counts
        .iter()
        .filter(|(stage, _)| is_gpu_capable_stage_key(stage))
        .map(|(stage, count)| (stage.clone(), *count))
        .collect();

    ControlPlaneFeatures {
        feature_schema: "zkf-neural-control-plane-v2".to_string(),
        job_kind: request.job_kind,
        objective: request.objective,
        circuit,
        stage_node_counts,
        gpu_capable_stage_counts,
        hardware_profile: hardware_profile.as_str().to_string(),
        chip_family: platform.identity.chip_family.as_str().to_string(),
        form_factor: platform.identity.form_factor.as_str().to_string(),
        gpu_core_count: platform.identity.gpu.core_count,
        ane_tops: platform.identity.neural_engine.tops,
        metal_available: metal_runtime.metal_available && !metal_runtime.metal_disabled_by_env,
        unified_memory: resources.unified_memory,
        ram_utilization: resources.ram_utilization(),
        memory_pressure_ratio: (resources.pressure.utilization_pct / 100.0).clamp(0.0, 1.0),
        battery_present: platform.thermal_envelope.battery_present,
        on_external_power: platform.thermal_envelope.on_external_power,
        low_power_mode: platform.thermal_envelope.low_power_mode,
        power_mode: platform.thermal_envelope.power_mode.as_str().to_string(),
        thermal_pressure: platform
            .thermal_envelope
            .thermal_pressure
            .or(host_snapshot.thermal_pressure),
        thermal_state_celsius: platform
            .thermal_envelope
            .thermal_state_celsius
            .or(host_snapshot.thermal_state_celsius),
        cpu_speed_limit: platform
            .thermal_envelope
            .cpu_speed_limit
            .or(host_snapshot.cpu_speed_limit),
        core_frequency_mhz: host_snapshot.core_frequency_mhz,
        requested_backend: request
            .requested_backend
            .map(|backend| backend.as_str().to_string()),
        backend_route: request.backend_route.map(backend_route_label),
        requested_jobs,
        total_jobs,
    }
}

fn control_plane_base_feature_vector(features: &ControlPlaneFeatures) -> Vec<f32> {
    let total_blackboxes = features
        .circuit
        .blackbox_op_distribution
        .values()
        .copied()
        .sum::<usize>()
        .max(1) as f64;
    let requested_jobs_ratio = if features.total_jobs == 0 {
        0.0
    } else {
        features.requested_jobs as f64 / features.total_jobs as f64
    };
    let lookup_ratio =
        count_lookup_constraints(features) as f64 / features.circuit.constraint_count.max(1) as f64;

    vec![
        normalized_log2(features.circuit.constraint_count, 24.0),
        normalized_log2(features.circuit.signal_count, 24.0),
        normalized_log2(features.circuit.witness_size.max(1), 24.0),
        (features.circuit.max_constraint_degree as f64 / 8.0).clamp(0.0, 1.0) as f32,
        blackbox_ratio(features, "poseidon2", total_blackboxes),
        blackbox_ratio(features, "sha256", total_blackboxes),
        blackbox_ratio(features, "keccak256", total_blackboxes),
        blackbox_ratio(features, "pedersen", total_blackboxes),
        blackbox_ratio(features, "schnorr", total_blackboxes),
        lookup_ratio.clamp(0.0, 1.0) as f32,
        stage_ratio(features, &["ntt"]),
        stage_ratio(features, &["lde"]),
        stage_ratio(features, &["msm"]),
        stage_ratio(features, &["poseidon-batch"]),
        stage_ratio(features, &["sha256-batch"]),
        stage_ratio(features, &["merkle-layer"]),
        stage_ratio(features, &["fri-fold", "fri-query-open"]),
        requested_jobs_ratio.clamp(0.0, 1.0) as f32,
        normalized_log2(features.total_jobs.max(1), 8.0),
        features.ram_utilization.clamp(0.0, 1.0) as f32,
        features.memory_pressure_ratio.clamp(0.0, 1.0) as f32,
        features.thermal_pressure.unwrap_or(0.0).clamp(0.0, 1.0) as f32,
        features.cpu_speed_limit.unwrap_or(1.0).clamp(0.0, 1.0) as f32,
        if features.metal_available { 1.0 } else { 0.0 },
        if features.unified_memory { 1.0 } else { 0.0 },
        if features.hardware_profile == "apple-silicon-m4-max-48gb" {
            1.0
        } else {
            0.0
        },
        if features.hardware_profile.starts_with("apple") || features.chip_family != "non-apple" {
            1.0
        } else {
            0.0
        },
        if features.job_kind == JobKind::Prove {
            1.0
        } else {
            0.0
        },
        if features.job_kind == JobKind::Fold {
            1.0
        } else {
            0.0
        },
        if features.job_kind == JobKind::Wrap {
            1.0
        } else {
            0.0
        },
    ]
}

fn rank_dispatch_candidates(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    objective: OptimizationObjective,
    model_catalog: &ModelCatalog,
) -> Vec<DispatchCandidateScore> {
    let mut scores = DispatchCandidate::ALL
        .into_iter()
        .map(|candidate| {
            let predicted = model_catalog
                .lane(ModelLane::Scheduler)
                .and_then(|descriptor| {
                    predict_numeric(
                        descriptor,
                        &build_feature_vector_for_descriptor(
                            descriptor,
                            features,
                            Some(candidate),
                            Some(backend),
                            Some(objective),
                        ),
                    )
                    .ok()
                })
                .unwrap_or_else(|| heuristic_scheduler_ms(features, backend, candidate));
            let source = if model_catalog.lane(ModelLane::Scheduler).is_some() {
                "model".to_string()
            } else {
                "heuristic".to_string()
            };
            DispatchCandidateScore {
                candidate,
                predicted_duration_ms: predicted.max(1.0),
                source,
            }
        })
        .collect::<Vec<_>>();
    scores.sort_by(|left, right| {
        left.predicted_duration_ms
            .total_cmp(&right.predicted_duration_ms)
    });
    scores
}

fn recommend_backend(
    request: &ControlPlaneRequest<'_>,
    features: &ControlPlaneFeatures,
    model_catalog: &ModelCatalog,
) -> BackendRecommendation {
    let candidates = if request.backend_candidates.is_empty() {
        vec![
            BackendKind::ArkworksGroth16,
            BackendKind::Plonky3,
            BackendKind::Nova,
            BackendKind::HyperNova,
            BackendKind::Halo2,
            BackendKind::Halo2Bls12381,
            BackendKind::Sp1,
            BackendKind::RiscZero,
            BackendKind::MidnightCompact,
        ]
    } else {
        request.backend_candidates.clone()
    };

    let mut rankings = candidates
        .iter()
        .copied()
        .map(|backend| {
            let score = model_catalog
                .lane(ModelLane::Backend)
                .and_then(|descriptor| {
                    predict_numeric(
                        descriptor,
                        &build_feature_vector_for_descriptor(
                            descriptor,
                            features,
                            None,
                            Some(backend),
                            Some(request.objective),
                        ),
                    )
                    .ok()
                })
                .unwrap_or_else(|| heuristic_backend_score(features, backend, request.objective));
            BackendScore { backend, score }
        })
        .collect::<Vec<_>>();
    rankings.sort_by(|left, right| left.score.total_cmp(&right.score));

    let fallback_backend = request
        .requested_backend
        .or_else(|| request.program.map(preferred_backend_for_program))
        .or(request.compiled.map(|compiled| compiled.backend))
        .or_else(|| requested_field(request).map(zkf_backends::preferred_backend_for_field))
        .unwrap_or(BackendKind::ArkworksGroth16);

    let mut recommendation_notes = Vec::new();
    let mut structural_candidates = Vec::new();
    let mut removed_reasons: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for backend in &candidates {
        let reasons = backend_structural_filter_reasons(request, *backend);
        if reasons.is_empty() {
            structural_candidates.push(*backend);
        } else {
            removed_reasons.insert(backend.as_str().to_string(), reasons);
        }
    }

    let mut filtered_candidates = if structural_candidates.is_empty() {
        recommendation_notes.push(
            "no backend in the provided candidate set satisfied the requested field/program constraints; keeping the highest-ranked original candidate"
                .to_string(),
        );
        rankings
            .first()
            .map(|candidate| vec![candidate.backend])
            .unwrap_or_else(|| vec![fallback_backend])
    } else {
        structural_candidates
    };

    let ready_candidates = filtered_candidates
        .iter()
        .copied()
        .filter(|backend| backend_readiness_filter_reason(request, *backend).is_none())
        .collect::<Vec<_>>();
    if !ready_candidates.is_empty() {
        for backend in filtered_candidates
            .iter()
            .copied()
            .filter(|backend| !ready_candidates.contains(backend))
        {
            if let Some(reason) = backend_readiness_filter_reason(request, backend) {
                removed_reasons
                    .entry(backend.as_str().to_string())
                    .or_default()
                    .push(reason);
            }
        }
        filtered_candidates = ready_candidates;
    } else if filtered_candidates
        .iter()
        .copied()
        .any(|backend| backend_readiness_filter_reason(request, backend).is_some())
    {
        recommendation_notes.push(
            "no production-ready backend satisfied the requested field/program constraints on this host; keeping structurally compatible candidates only"
                .to_string(),
        );
    }

    if request.objective == OptimizationObjective::NoTrustedSetup {
        let transparent_candidates = filtered_candidates
            .iter()
            .copied()
            .filter(|backend| !backend_for(*backend).capabilities().trusted_setup)
            .collect::<Vec<_>>();
        if !transparent_candidates.is_empty() {
            for backend in filtered_candidates
                .iter()
                .copied()
                .filter(|backend| !transparent_candidates.contains(backend))
            {
                removed_reasons
                    .entry(backend.as_str().to_string())
                    .or_default()
                    .push("objective 'no-trusted-setup' excludes trusted-setup backends when transparent candidates are available".to_string());
            }
            filtered_candidates = transparent_candidates;
        } else if filtered_candidates
            .iter()
            .any(|backend| backend_for(*backend).capabilities().trusted_setup)
        {
            recommendation_notes.push(
                "no transparent backend satisfied the requested field/program constraints on this host; keeping the best remaining candidate"
                    .to_string(),
            );
        }
    }

    let filtered_set = filtered_candidates
        .iter()
        .map(|backend| backend.as_str().to_string())
        .collect::<BTreeSet<_>>();
    if let Some(model_preferred) = rankings.first()
        && !filtered_set.contains(model_preferred.backend.as_str())
        && let Some(reasons) = removed_reasons.get(model_preferred.backend.as_str())
    {
        recommendation_notes.push(format!(
            "filtered model-preferred backend '{}' from final selection: {}",
            model_preferred.backend,
            reasons.join("; ")
        ));
    }
    for backend in &candidates {
        if let Some(reasons) = removed_reasons.get(backend.as_str()) {
            recommendation_notes.push(format!(
                "filtered backend '{}' from runtime auto-selection: {}",
                backend,
                reasons.join("; ")
            ));
        }
    }

    let rankings = rankings
        .into_iter()
        .filter(|candidate| filtered_set.contains(candidate.backend.as_str()))
        .collect::<Vec<_>>();

    let valid_requested_backend = request
        .requested_backend
        .filter(|backend| filtered_set.contains(backend.as_str()));
    if request.requested_backend.is_some() && valid_requested_backend.is_none() {
        recommendation_notes.push(format!(
            "requested backend '{}' did not satisfy the runtime control-plane validity filters; using the best remaining candidate instead",
            request
                .requested_backend
                .expect("checked requested backend")
        ));
    }

    let selected = valid_requested_backend
        .or_else(|| rankings.first().map(|candidate| candidate.backend))
        .unwrap_or(fallback_backend);
    let source = if valid_requested_backend.is_some() {
        "explicit".to_string()
    } else if model_catalog.backend.is_some() {
        "model".to_string()
    } else {
        "heuristic".to_string()
    };
    BackendRecommendation {
        selected,
        objective: request.objective,
        source,
        rankings,
        notes: recommendation_notes,
    }
}

fn estimate_duration(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    candidate: DispatchCandidate,
    objective: OptimizationObjective,
    candidate_rankings: &[DispatchCandidateScore],
    model_catalog: &ModelCatalog,
) -> DurationEstimate {
    let execution_regime = planned_execution_regime(features, candidate);
    let advisory_candidate = if features.metal_available {
        candidate
    } else {
        DispatchCandidate::CpuOnly
    };
    let estimate_ms = model_catalog
        .lane(ModelLane::Duration)
        .and_then(|descriptor| {
            predict_numeric(
                descriptor,
                &build_feature_vector_for_descriptor(
                    descriptor,
                    features,
                    Some(advisory_candidate),
                    Some(backend),
                    Some(objective),
                ),
            )
            .ok()
        })
        .or_else(|| {
            candidate_rankings
                .iter()
                .find(|score| score.candidate == advisory_candidate)
                .map(|score| score.predicted_duration_ms)
        })
        .unwrap_or_else(|| heuristic_scheduler_ms(features, backend, advisory_candidate));
    let anomaly_score = predicted_anomaly_score(
        features,
        backend,
        advisory_candidate,
        objective,
        model_catalog,
    );
    let (upper_bound_ms, bound_source) =
        duration_upper_bound(features, execution_regime, estimate_ms, anomaly_score);
    let countdown_safe = upper_bound_ms.is_some() && features.metal_available;
    let eta_semantics = if !features.metal_available {
        EtaSemantics::NonSlaFallback
    } else if model_catalog.duration.is_some() {
        EtaSemantics::ModelEstimate
    } else if execution_regime == ExecutionRegime::CpuOnly {
        EtaSemantics::HeuristicBound
    } else {
        EtaSemantics::HeuristicEstimate
    };
    DurationEstimate {
        estimate_ms,
        upper_bound_ms,
        predicted_wall_time_ms: estimate_ms,
        source: if model_catalog.duration.is_some() {
            "model".to_string()
        } else {
            "heuristic".to_string()
        },
        execution_regime,
        eta_semantics,
        bound_source,
        countdown_safe,
        note: duration_estimate_note(features, execution_regime, eta_semantics),
        backend: Some(backend),
        dispatch_candidate: Some(candidate),
    }
}

fn baseline_anomaly(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    candidate: DispatchCandidate,
    objective: OptimizationObjective,
    estimate: &DurationEstimate,
    model_catalog: &ModelCatalog,
) -> AnomalyVerdict {
    let expected_proof_size_bytes = heuristic_expected_proof_size_bytes(features, backend);
    let predicted_anomaly_score =
        predicted_anomaly_score(features, backend, candidate, objective, model_catalog);
    let duration_ratio_limit = estimate.upper_bound_ms.and_then(|upper_bound_ms| {
        if estimate.estimate_ms > 0.0 {
            Some((upper_bound_ms / estimate.estimate_ms).max(1.0))
        } else {
            None
        }
    });
    let proof_size_ratio_limit = predicted_anomaly_score.map(|score| score.clamp(1.05, 4.0));
    AnomalyVerdict {
        severity: AnomalySeverity::Normal,
        source: if predicted_anomaly_score.is_some() {
            "model".to_string()
        } else {
            "heuristic".to_string()
        },
        reason: baseline_reason(estimate, predicted_anomaly_score),
        predicted_anomaly_score,
        advisory_estimate_ms: Some(estimate.estimate_ms),
        conservative_upper_bound_ms: estimate.upper_bound_ms,
        execution_regime: Some(estimate.execution_regime),
        eta_semantics: Some(estimate.eta_semantics),
        bound_source: Some(estimate.bound_source),
        duration_interpretation: None,
        expected_duration_ms: Some(estimate.estimate_ms),
        expected_duration_ratio_limit: duration_ratio_limit,
        observed_duration_ms: None,
        duration_ratio: None,
        expected_proof_size_bytes: Some(expected_proof_size_bytes),
        expected_proof_size_ratio_limit: proof_size_ratio_limit,
        observed_proof_size_bytes: None,
        proof_size_ratio: None,
    }
}

fn evaluate_observed_anomaly(
    baseline: &AnomalyVerdict,
    observed_duration_ms: f64,
    observed_proof_size_bytes: Option<u64>,
) -> AnomalyVerdict {
    let advisory_estimate_ms = baseline
        .advisory_estimate_ms
        .or(baseline.expected_duration_ms);
    let conservative_upper_bound_ms = baseline.conservative_upper_bound_ms;
    let eta_semantics = baseline.eta_semantics;
    let duration_ratio = baseline
        .advisory_estimate_ms
        .or(baseline.expected_duration_ms)
        .filter(|expected| *expected > 0.0)
        .map(|expected| observed_duration_ms / expected);
    let upper_bound_ratio = conservative_upper_bound_ms
        .filter(|upper_bound| *upper_bound > 0.0)
        .map(|upper_bound| observed_duration_ms / upper_bound);
    let proof_size_ratio = match (
        baseline.expected_proof_size_bytes,
        observed_proof_size_bytes,
    ) {
        (Some(expected), Some(observed)) if expected > 0 => Some(observed as f64 / expected as f64),
        _ => None,
    };

    let severity = match (
        eta_semantics,
        upper_bound_ratio,
        baseline.expected_proof_size_ratio_limit,
    ) {
        (Some(EtaSemantics::NonSlaFallback), _, _) => {
            if duration_ratio.unwrap_or(1.0) >= 10.0 || proof_size_ratio.unwrap_or(1.0) >= 8.0 {
                AnomalySeverity::Critical
            } else if duration_ratio.unwrap_or(1.0) >= 4.0 || proof_size_ratio.unwrap_or(1.0) >= 4.0
            {
                AnomalySeverity::Warning
            } else if duration_ratio.unwrap_or(1.0) >= 2.0 || proof_size_ratio.unwrap_or(1.0) >= 2.0
            {
                AnomalySeverity::Notice
            } else {
                AnomalySeverity::Normal
            }
        }
        (_, Some(duration_bound_ratio), Some(proof_limit)) if baseline.source == "model" => {
            let duration_budget_ratio = duration_bound_ratio.max(1.0);
            let proof_budget_ratio = proof_size_ratio
                .map(|value| value / proof_limit.max(1.0))
                .unwrap_or(1.0);
            let excursion = duration_budget_ratio.max(proof_budget_ratio);
            if excursion >= 4.0 {
                AnomalySeverity::Critical
            } else if excursion >= 2.0 {
                AnomalySeverity::Warning
            } else if excursion >= 1.25 || duration_ratio.unwrap_or(1.0) > 1.0 {
                AnomalySeverity::Notice
            } else {
                AnomalySeverity::Normal
            }
        }
        (_, Some(duration_bound_ratio), _) => {
            let excursion = duration_bound_ratio.max(1.0);
            if excursion >= 4.0 {
                AnomalySeverity::Critical
            } else if excursion >= 2.0 {
                AnomalySeverity::Warning
            } else if excursion >= 1.25 || duration_ratio.unwrap_or(1.0) > 1.0 {
                AnomalySeverity::Notice
            } else {
                AnomalySeverity::Normal
            }
        }
        (Some(EtaSemantics::ModelEstimate), _, Some(proof_limit))
            if baseline.expected_duration_ratio_limit.is_some() && baseline.source == "model" =>
        {
            let duration_limit = baseline.expected_duration_ratio_limit.unwrap_or(1.0);
            let duration_budget_ratio = duration_ratio
                .map(|value| value / duration_limit.max(1.0))
                .unwrap_or(1.0);
            let proof_budget_ratio = proof_size_ratio
                .map(|value| value / proof_limit.max(1.0))
                .unwrap_or(1.0);
            let excursion = duration_budget_ratio.max(proof_budget_ratio);
            if excursion >= 4.0 {
                AnomalySeverity::Critical
            } else if excursion >= 2.0 {
                AnomalySeverity::Warning
            } else if excursion >= 1.25 {
                AnomalySeverity::Notice
            } else {
                AnomalySeverity::Normal
            }
        }
        _ => {
            if duration_ratio.unwrap_or(1.0) >= 10.0 || proof_size_ratio.unwrap_or(1.0) >= 8.0 {
                AnomalySeverity::Critical
            } else if duration_ratio.unwrap_or(1.0) >= 4.0 || proof_size_ratio.unwrap_or(1.0) >= 4.0
            {
                AnomalySeverity::Warning
            } else if duration_ratio.unwrap_or(1.0) >= 2.0 || proof_size_ratio.unwrap_or(1.0) >= 2.0
            {
                AnomalySeverity::Notice
            } else {
                AnomalySeverity::Normal
            }
        }
    };
    let duration_interpretation = if eta_semantics == Some(EtaSemantics::NonSlaFallback) {
        Some("fallback-path-not-eligible-for-sla-interpretation".to_string())
    } else if upper_bound_ratio.map(|ratio| ratio > 1.0).unwrap_or(false) {
        Some("exceeded-conservative-bound".to_string())
    } else if duration_ratio.map(|ratio| ratio > 1.0).unwrap_or(false) {
        Some("slower-than-advisory-estimate".to_string())
    } else if advisory_estimate_ms.is_some() {
        Some("within-advisory-estimate".to_string())
    } else {
        None
    };

    AnomalyVerdict {
        severity,
        source: baseline.source.clone(),
        reason: anomaly_reason(
            baseline.source.as_str(),
            severity,
            eta_semantics,
            upper_bound_ratio,
            duration_ratio,
        ),
        predicted_anomaly_score: baseline.predicted_anomaly_score,
        advisory_estimate_ms,
        conservative_upper_bound_ms,
        execution_regime: baseline.execution_regime,
        eta_semantics,
        bound_source: baseline.bound_source,
        duration_interpretation,
        expected_duration_ms: baseline.expected_duration_ms,
        expected_duration_ratio_limit: baseline.expected_duration_ratio_limit,
        observed_duration_ms: Some(observed_duration_ms),
        duration_ratio,
        expected_proof_size_bytes: baseline.expected_proof_size_bytes,
        expected_proof_size_ratio_limit: baseline.expected_proof_size_ratio_limit,
        observed_proof_size_bytes,
        proof_size_ratio,
    }
}

fn heuristic_scheduler_ms(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    candidate: DispatchCandidate,
) -> f64 {
    let constraints = features.circuit.constraint_count.max(1) as f64;
    let signals = features.circuit.signal_count.max(1) as f64;
    let witness_scale = (features.circuit.witness_size.max(1) as f64)
        .log2()
        .max(1.0);
    let stage_weight = features
        .stage_node_counts
        .values()
        .copied()
        .sum::<usize>()
        .max(1) as f64;
    let pressure_penalty = match features.memory_pressure_ratio {
        ratio if ratio >= 0.95 => 2.3,
        ratio if ratio >= 0.85 => 1.8,
        ratio if ratio >= 0.70 => 1.25,
        _ => 1.0,
    };
    let thermal_penalty = 1.0 + features.thermal_pressure.unwrap_or(0.0) * 0.50;
    let mobile_penalty = match features.form_factor.as_str() {
        "mobile" => 1.35,
        "headset" => 1.20,
        _ => 1.0,
    };
    let low_power_penalty = if features.low_power_mode { 1.18 } else { 1.0 };
    let backend_weight = match backend {
        BackendKind::Plonky3 => 0.85,
        BackendKind::ArkworksGroth16 => 1.0,
        BackendKind::Nova | BackendKind::HyperNova => 1.20,
        BackendKind::Halo2 | BackendKind::Halo2Bls12381 => 1.15,
        BackendKind::Sp1 | BackendKind::RiscZero => 1.40,
        BackendKind::MidnightCompact => 1.30,
    };
    let gpu_discount = match candidate {
        DispatchCandidate::CpuOnly => 1.20,
        DispatchCandidate::HashOnly => 1.00 - hash_stage_ratio(features) * 0.18,
        DispatchCandidate::AlgebraOnly => 1.00 - algebra_stage_ratio(features) * 0.22,
        DispatchCandidate::StarkHeavy => 1.00 - stark_stage_ratio(features) * 0.28,
        DispatchCandidate::Balanced => 0.84,
        DispatchCandidate::FullGpu => {
            if !features.metal_available {
                1.25
            } else {
                0.76 + features.memory_pressure_ratio * 0.20
            }
        }
    };

    ((constraints.log2() * 18.0)
        + (signals.log2() * 12.0)
        + (witness_scale * 8.0)
        + (stage_weight * 6.0))
        * backend_weight
        * pressure_penalty
        * thermal_penalty
        * mobile_penalty
        * low_power_penalty
        * gpu_discount.max(0.40)
}

fn planned_execution_regime(
    features: &ControlPlaneFeatures,
    candidate: DispatchCandidate,
) -> ExecutionRegime {
    if !features.metal_available || candidate.stages_on_gpu().is_empty() {
        ExecutionRegime::CpuOnly
    } else if candidate.stages_on_gpu().len() == gpu_capable_stage_keys().len() {
        ExecutionRegime::GpuCapable
    } else {
        ExecutionRegime::PartialFallback
    }
}

fn predicted_anomaly_score(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    candidate: DispatchCandidate,
    objective: OptimizationObjective,
    model_catalog: &ModelCatalog,
) -> Option<f64> {
    model_catalog
        .lane(ModelLane::Anomaly)
        .and_then(|descriptor| {
            predict_numeric(
                descriptor,
                &build_feature_vector_for_descriptor(
                    descriptor,
                    features,
                    Some(candidate),
                    Some(backend),
                    Some(objective),
                ),
            )
            .ok()
        })
}

fn heuristic_duration_bound_multiplier(
    features: &ControlPlaneFeatures,
    execution_regime: ExecutionRegime,
) -> f64 {
    let base = match execution_regime {
        ExecutionRegime::GpuCapable => 1.35,
        ExecutionRegime::PartialFallback => 1.65,
        ExecutionRegime::CpuOnly => 1.95,
    };
    let memory_penalty = 1.0 + features.memory_pressure_ratio.clamp(0.0, 1.0) * 0.75;
    let thermal_penalty = 1.0 + features.thermal_pressure.unwrap_or(0.0).clamp(0.0, 1.0) * 0.50;
    let low_power_penalty = if features.low_power_mode { 1.10 } else { 1.0 };
    (base * memory_penalty * thermal_penalty * low_power_penalty).clamp(1.10, 4.0)
}

fn duration_upper_bound(
    features: &ControlPlaneFeatures,
    execution_regime: ExecutionRegime,
    estimate_ms: f64,
    predicted_anomaly_score: Option<f64>,
) -> (Option<f64>, BoundSource) {
    if !features.metal_available {
        return (None, BoundSource::Unavailable);
    }
    if let Some(score) = predicted_anomaly_score {
        let ratio = score.clamp(1.05, 4.0);
        return (Some(estimate_ms * ratio), BoundSource::ModelDerived);
    }
    let ratio = heuristic_duration_bound_multiplier(features, execution_regime);
    (Some(estimate_ms * ratio), BoundSource::HeuristicEnvelope)
}

fn duration_estimate_note(
    features: &ControlPlaneFeatures,
    execution_regime: ExecutionRegime,
    eta_semantics: EtaSemantics,
) -> Option<String> {
    if !features.metal_available || eta_semantics == EtaSemantics::NonSlaFallback {
        return Some(
            "Metal GPU acceleration is unavailable; exported ETA is advisory only and not countdown-safe"
                .to_string(),
        );
    }
    if execution_regime == ExecutionRegime::PartialFallback {
        return Some(
            "Dispatch mixes GPU-capable and CPU stages; use the conservative upper bound for operator planning"
                .to_string(),
        );
    }
    None
}

fn baseline_reason(estimate: &DurationEstimate, predicted_anomaly_score: Option<f64>) -> String {
    if estimate.eta_semantics == EtaSemantics::NonSlaFallback {
        return estimate.note.clone().unwrap_or_else(|| {
            "fallback ETA is advisory only and not eligible for SLA/countdown interpretation"
                .to_string()
        });
    }
    if let Some(score) = predicted_anomaly_score {
        return format!(
            "learned anomaly envelope capped at {:.3}x the advisory estimate",
            score.clamp(1.05, 4.0)
        );
    }
    if let Some(upper_bound_ms) = estimate.upper_bound_ms
        && estimate.estimate_ms > 0.0
    {
        return format!(
            "conservative heuristic envelope capped at {:.3}x the advisory estimate",
            (upper_bound_ms / estimate.estimate_ms).max(1.0)
        );
    }
    "no conservative duration bound available".to_string()
}

fn anomaly_reason(
    source: &str,
    severity: AnomalySeverity,
    eta_semantics: Option<EtaSemantics>,
    upper_bound_ratio: Option<f64>,
    duration_ratio: Option<f64>,
) -> String {
    if eta_semantics == Some(EtaSemantics::NonSlaFallback) {
        return match severity {
            AnomalySeverity::Normal => {
                "fallback path remained within the diagnostic advisory estimate; ETA was not countdown-safe"
                    .to_string()
            }
            AnomalySeverity::Notice => {
                "fallback path was slower than the advisory estimate; ETA was not countdown-safe"
                    .to_string()
            }
            AnomalySeverity::Warning => {
                "fallback path materially exceeded the advisory estimate; ETA was not countdown-safe"
                    .to_string()
            }
            AnomalySeverity::Critical => {
                "fallback path diverged from the advisory estimate by a critical margin; ETA was not countdown-safe"
                    .to_string()
            }
        };
    }
    if upper_bound_ratio.map(|ratio| ratio > 1.0).unwrap_or(false) {
        return match severity {
            AnomalySeverity::Critical => {
                "observed execution exceeded the conservative bound by a critical margin"
                    .to_string()
            }
            AnomalySeverity::Warning => {
                "observed execution materially exceeded the conservative bound".to_string()
            }
            _ => "observed execution exceeded the conservative bound".to_string(),
        };
    }
    if duration_ratio.map(|ratio| ratio > 1.0).unwrap_or(false) {
        return if source == "model" {
            "observed execution was slower than the advisory model estimate".to_string()
        } else {
            "observed execution was slower than the advisory heuristic estimate".to_string()
        };
    }
    "observed execution is within the advisory estimate and conservative envelope".to_string()
}

fn apply_realized_eta_fallback(
    decision: &mut ControlPlaneDecision,
    realized_gpu_capable_stages: &[String],
) {
    if decision.dispatch_plan.stages_on_gpu.is_empty() || !realized_gpu_capable_stages.is_empty() {
        return;
    }
    decision.duration_estimate.execution_regime = ExecutionRegime::CpuOnly;
    decision.duration_estimate.eta_semantics = EtaSemantics::NonSlaFallback;
    decision.duration_estimate.upper_bound_ms = None;
    decision.duration_estimate.bound_source = BoundSource::Unavailable;
    decision.duration_estimate.countdown_safe = false;
    decision.duration_estimate.note = Some(
        "planned GPU-capable execution realized no GPU-capable stages; ETA is advisory only and not countdown-safe"
            .to_string(),
    );
    decision.anomaly_baseline.execution_regime = Some(ExecutionRegime::CpuOnly);
    decision.anomaly_baseline.eta_semantics = Some(EtaSemantics::NonSlaFallback);
    decision.anomaly_baseline.bound_source = Some(BoundSource::Unavailable);
    decision.anomaly_baseline.conservative_upper_bound_ms = None;
    decision.anomaly_baseline.expected_duration_ratio_limit = None;
    decision.anomaly_baseline.reason =
        "planned GPU-capable execution realized no GPU-capable stages; fallback path is advisory only and not countdown-safe"
            .to_string();
}

fn heuristic_backend_score(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
    objective: OptimizationObjective,
) -> f64 {
    if objective == OptimizationObjective::SmallestProof {
        return heuristic_expected_proof_size_bytes(features, backend) as f64;
    }
    if objective == OptimizationObjective::NoTrustedSetup {
        let transparency_cost = match backend {
            BackendKind::Plonky3 => 80.0,
            BackendKind::Nova => 95.0,
            BackendKind::HyperNova => 92.0,
            BackendKind::Sp1 => 135.0,
            BackendKind::RiscZero => 145.0,
            BackendKind::MidnightCompact => 210.0,
            BackendKind::ArkworksGroth16 | BackendKind::Halo2 | BackendKind::Halo2Bls12381 => 420.0,
        };
        return transparency_cost
            + heuristic_scheduler_ms(features, backend, DispatchCandidate::CpuOnly);
    }

    let preferred =
        features.hardware_profile.starts_with("apple") || features.chip_family != "non-apple";
    let field_hint = features
        .requested_backend
        .as_deref()
        .and_then(|value| value.parse::<BackendKind>().ok());
    let field_bias = if field_hint == Some(backend) {
        0.85
    } else {
        1.0
    };
    let transparent_bonus = match backend {
        BackendKind::Plonky3 | BackendKind::Nova | BackendKind::HyperNova => 0.92,
        _ => 1.0,
    };
    let metal_bonus = if preferred && features.metal_available && backend == BackendKind::Plonky3 {
        0.78
    } else if preferred && backend == BackendKind::ArkworksGroth16 {
        0.90
    } else {
        1.0
    };
    let baseline = match backend {
        BackendKind::ArkworksGroth16 => 100.0,
        BackendKind::Plonky3 => 92.0,
        BackendKind::Nova => 130.0,
        BackendKind::HyperNova => 128.0,
        BackendKind::Halo2 => 118.0,
        BackendKind::Halo2Bls12381 => 124.0,
        BackendKind::Sp1 => 160.0,
        BackendKind::RiscZero => 166.0,
        BackendKind::MidnightCompact => 140.0,
    };
    baseline * field_bias * transparent_bonus * metal_bonus
}

fn heuristic_expected_proof_size_bytes(
    features: &ControlPlaneFeatures,
    backend: BackendKind,
) -> u64 {
    let scale = (features.circuit.constraint_count.max(1) as f64)
        .log2()
        .max(1.0);
    let base = match backend {
        BackendKind::ArkworksGroth16 => 128.0,
        BackendKind::Plonky3 => 24_576.0,
        BackendKind::Nova => 1_770_000.0,
        BackendKind::HyperNova => 1_200_000.0,
        BackendKind::Halo2 => 8_192.0,
        BackendKind::Halo2Bls12381 => 9_216.0,
        BackendKind::Sp1 | BackendKind::RiscZero => 65_536.0,
        BackendKind::MidnightCompact => 4_096.0,
    };
    (base + scale * 96.0) as u64
}

fn build_feature_vector_for_descriptor(
    descriptor: &ModelDescriptor,
    features: &ControlPlaneFeatures,
    candidate: Option<DispatchCandidate>,
    backend: Option<BackendKind>,
    objective: Option<OptimizationObjective>,
) -> Vec<f32> {
    let shape = descriptor
        .input_shape
        .unwrap_or_else(|| descriptor.lane.supported_input_shapes()[0]);
    build_feature_vector_for_shape(
        descriptor.lane,
        shape,
        features,
        candidate,
        backend,
        objective,
    )
}

fn build_feature_vector_for_shape(
    lane: ModelLane,
    shape: usize,
    features: &ControlPlaneFeatures,
    candidate: Option<DispatchCandidate>,
    backend: Option<BackendKind>,
    objective: Option<OptimizationObjective>,
) -> Vec<f32> {
    if lane == ModelLane::ThresholdOptimizer {
        return threshold_optimizer_feature_vector(features);
    }
    if lane == ModelLane::Security {
        return build_security_feature_vector(
            shape,
            features,
            candidate,
            backend,
            objective,
            &SecurityFeatureInputs::default(),
        );
    }

    let vector = extend_control_plane_one_hots(
        control_plane_base_feature_vector(features),
        candidate,
        backend,
        objective,
    );
    match shape {
        47 => vector,
        57 => extend_platform_features(vector, features),
        _ => extend_platform_features(vector, features),
    }
}

pub(crate) fn build_security_feature_vector(
    shape: usize,
    features: &ControlPlaneFeatures,
    candidate: Option<DispatchCandidate>,
    backend: Option<BackendKind>,
    objective: Option<OptimizationObjective>,
    security_inputs: &SecurityFeatureInputs,
) -> Vec<f32> {
    let mut vector = match shape {
        58 => build_feature_vector_for_shape(
            ModelLane::Scheduler,
            47,
            features,
            candidate,
            backend,
            objective,
        ),
        _ => build_feature_vector_for_shape(
            ModelLane::Scheduler,
            57,
            features,
            candidate,
            backend,
            objective,
        ),
    };
    vector.extend([
        normalized_log2(security_inputs.watchdog_notice_count, 5.0),
        normalized_log2(security_inputs.watchdog_warning_count, 5.0),
        normalized_log2(security_inputs.watchdog_critical_count, 5.0),
        normalized_log2(security_inputs.timing_alert_count, 5.0),
        normalized_log2(security_inputs.thermal_alert_count, 4.0),
        normalized_log2(security_inputs.memory_alert_count, 4.0),
        normalized_log2(security_inputs.gpu_circuit_breaker_count, 4.0),
        normalized_log2(security_inputs.repeated_fallback_count, 5.0),
        security_inputs.anomaly_severity_score.clamp(0.0, 1.0) as f32,
        normalized_log2(security_inputs.model_integrity_failure_count, 4.0),
        normalized_log2(security_inputs.rate_limit_violation_count, 5.0),
        normalized_log2(security_inputs.auth_failure_count, 5.0),
        normalized_log2(security_inputs.malformed_request_count, 5.0),
        normalized_log2(security_inputs.backend_incompatibility_attempt_count, 5.0),
        if security_inputs.telemetry_replay_flag {
            1.0
        } else {
            0.0
        },
        if security_inputs.integrity_mismatch_flag {
            1.0
        } else {
            0.0
        },
        if security_inputs.anonymous_burst_flag {
            1.0
        } else {
            0.0
        },
    ]);
    vector
}

fn extend_control_plane_one_hots(
    mut vector: Vec<f32>,
    candidate: Option<DispatchCandidate>,
    backend: Option<BackendKind>,
    objective: Option<OptimizationObjective>,
) -> Vec<f32> {
    for lane in DispatchCandidate::ALL {
        vector.push(if Some(lane) == candidate { 1.0 } else { 0.0 });
    }
    for supported in [
        BackendKind::Plonky3,
        BackendKind::ArkworksGroth16,
        BackendKind::Nova,
        BackendKind::HyperNova,
        BackendKind::Sp1,
        BackendKind::RiscZero,
        BackendKind::Halo2,
        BackendKind::MidnightCompact,
    ] {
        vector.push(if Some(supported) == backend { 1.0 } else { 0.0 });
    }
    for supported in OptimizationObjective::ALL {
        vector.push(if Some(supported) == objective {
            1.0
        } else {
            0.0
        });
    }
    vector
}

fn extend_platform_features(mut vector: Vec<f32>, features: &ControlPlaneFeatures) -> Vec<f32> {
    vector.push(platform_chip_generation_norm(features));
    vector.push((features.gpu_core_count.unwrap_or_default() as f32 / 64.0).clamp(0.0, 1.0));
    vector.push((features.ane_tops.unwrap_or_default() / 40.0).clamp(0.0, 1.0));
    vector.push(if features.battery_present { 1.0 } else { 0.0 });
    vector.push(if features.on_external_power { 1.0 } else { 0.0 });
    vector.push(if features.low_power_mode { 1.0 } else { 0.0 });
    vector.push(if features.form_factor == "desktop" {
        1.0
    } else {
        0.0
    });
    vector.push(if features.form_factor == "laptop" {
        1.0
    } else {
        0.0
    });
    vector.push(if features.form_factor == "mobile" {
        1.0
    } else {
        0.0
    });
    vector.push(if features.form_factor == "headset" {
        1.0
    } else {
        0.0
    });
    vector
}

fn threshold_optimizer_feature_vector(features: &ControlPlaneFeatures) -> Vec<f32> {
    vec![
        platform_chip_generation_norm(features),
        (features.gpu_core_count.unwrap_or_default() as f32 / 64.0).clamp(0.0, 1.0),
        (features.ane_tops.unwrap_or_default() / 40.0).clamp(0.0, 1.0),
        if features.battery_present { 1.0 } else { 0.0 },
        if features.on_external_power { 1.0 } else { 0.0 },
        if features.low_power_mode { 1.0 } else { 0.0 },
        if features.form_factor == "desktop" {
            1.0
        } else {
            0.0
        },
        if features.form_factor == "laptop" {
            1.0
        } else {
            0.0
        },
        if features.form_factor == "mobile" {
            1.0
        } else {
            0.0
        },
        if features.form_factor == "headset" {
            1.0
        } else {
            0.0
        },
        normalized_log2(
            features
                .stage_node_counts
                .values()
                .copied()
                .sum::<usize>()
                .max(1),
            16.0,
        ),
        normalized_log2(features.circuit.constraint_count.max(1), 24.0),
    ]
}

pub fn feature_vector_labels_v1() -> Vec<String> {
    let mut labels = vec![
        "constraints_log2_norm",
        "signals_log2_norm",
        "witness_size_log2_norm",
        "max_constraint_degree_norm",
        "blackbox_poseidon_ratio",
        "blackbox_sha256_ratio",
        "blackbox_keccak_ratio",
        "blackbox_pedersen_ratio",
        "blackbox_schnorr_ratio",
        "lookup_ratio",
        "stage_ntt_ratio",
        "stage_lde_ratio",
        "stage_msm_ratio",
        "stage_poseidon_ratio",
        "stage_sha256_ratio",
        "stage_merkle_ratio",
        "stage_fri_ratio",
        "requested_jobs_ratio",
        "total_jobs_log2_norm",
        "ram_utilization",
        "memory_pressure_ratio",
        "thermal_pressure",
        "cpu_speed_limit",
        "metal_available",
        "unified_memory",
        "hardware_profile_m4_max",
        "hardware_profile_apple_silicon",
        "job_kind_prove",
        "job_kind_fold",
        "job_kind_wrap",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    labels.extend(
        DispatchCandidate::ALL
            .into_iter()
            .map(|candidate| format!("dispatch_candidate_{}", candidate.as_str())),
    );
    labels.extend(
        [
            BackendKind::Plonky3,
            BackendKind::ArkworksGroth16,
            BackendKind::Nova,
            BackendKind::HyperNova,
            BackendKind::Sp1,
            BackendKind::RiscZero,
            BackendKind::Halo2,
            BackendKind::MidnightCompact,
        ]
        .into_iter()
        .map(|backend| format!("backend_{}", backend.as_str())),
    );
    labels.extend(
        OptimizationObjective::ALL
            .into_iter()
            .map(|objective| format!("objective_{}", objective.as_str())),
    );
    labels
}

pub fn feature_vector_labels_v2() -> Vec<String> {
    let mut labels = feature_vector_labels_v1();
    labels.extend(
        [
            "chip_generation_norm",
            "gpu_cores_norm",
            "ane_tops_norm",
            "battery_present",
            "on_external_power",
            "low_power_mode",
            "form_factor_desktop",
            "form_factor_laptop",
            "form_factor_mobile",
            "form_factor_headset",
        ]
        .into_iter()
        .map(str::to_string),
    );
    labels
}

pub fn threshold_optimizer_feature_labels() -> Vec<String> {
    [
        "chip_generation_norm",
        "gpu_cores_norm",
        "ane_tops_norm",
        "battery_present",
        "on_external_power",
        "low_power_mode",
        "form_factor_desktop",
        "form_factor_laptop",
        "form_factor_mobile",
        "form_factor_headset",
        "stage_node_count_log2_norm",
        "constraint_count_log2_norm",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub fn security_feature_labels_v1() -> Vec<String> {
    let mut labels = feature_vector_labels_v1();
    labels.extend(
        [
            "watchdog_notice_count_log2_norm",
            "watchdog_warning_count_log2_norm",
            "watchdog_critical_count_log2_norm",
            "timing_alert_count_log2_norm",
            "thermal_alert_count_log2_norm",
            "memory_alert_count_log2_norm",
            "gpu_circuit_breaker_count_log2_norm",
            "repeated_fallback_count_log2_norm",
            "anomaly_severity_score_norm",
            "model_integrity_failure_count_log2_norm",
            "rate_limit_violation_count_log2_norm",
            "auth_failure_count_log2_norm",
            "malformed_request_count_log2_norm",
            "backend_incompatibility_attempt_count_log2_norm",
            "telemetry_replay_flag",
            "integrity_mismatch_flag",
            "anonymous_burst_flag",
        ]
        .into_iter()
        .map(str::to_string),
    );
    labels
}

pub fn security_feature_labels_v2() -> Vec<String> {
    let mut labels = feature_vector_labels_v2();
    labels.extend(
        [
            "watchdog_notice_count_log2_norm",
            "watchdog_warning_count_log2_norm",
            "watchdog_critical_count_log2_norm",
            "timing_alert_count_log2_norm",
            "thermal_alert_count_log2_norm",
            "memory_alert_count_log2_norm",
            "gpu_circuit_breaker_count_log2_norm",
            "repeated_fallback_count_log2_norm",
            "anomaly_severity_score_norm",
            "model_integrity_failure_count_log2_norm",
            "rate_limit_violation_count_log2_norm",
            "auth_failure_count_log2_norm",
            "malformed_request_count_log2_norm",
            "backend_incompatibility_attempt_count_log2_norm",
            "telemetry_replay_flag",
            "integrity_mismatch_flag",
            "anonymous_burst_flag",
        ]
        .into_iter()
        .map(str::to_string),
    );
    labels
}

pub fn feature_vector_labels() -> Vec<String> {
    feature_vector_labels_v2()
}

pub fn dispatch_candidates() -> &'static [DispatchCandidate] {
    &DispatchCandidate::ALL
}

fn platform_chip_generation_norm(features: &ControlPlaneFeatures) -> f32 {
    match features.chip_family.as_str() {
        "m1" => 0.25,
        "m2" | "vision-pro" => 0.50,
        "m3" => 0.75,
        "m4" => 1.00,
        "a17-pro" => 0.90,
        "a18" => 0.95,
        "a18-pro" => 1.00,
        _ => 0.60,
    }
}

fn fingerprint_for_labels(labels: &[String]) -> String {
    let mut hasher = Sha256::new();
    for label in labels {
        hasher.update(label.as_bytes());
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

fn schema_fingerprint_for_lane_shape(lane: ModelLane, shape: usize) -> Option<String> {
    let labels = match (lane, shape) {
        (ModelLane::ThresholdOptimizer, 12) => threshold_optimizer_feature_labels(),
        (ModelLane::Security, 58) => security_feature_labels_v1(),
        (ModelLane::Security, 68) => security_feature_labels_v2(),
        (
            ModelLane::Scheduler | ModelLane::Backend | ModelLane::Duration | ModelLane::Anomaly,
            47,
        ) => feature_vector_labels_v1(),
        (
            ModelLane::Scheduler | ModelLane::Backend | ModelLane::Duration | ModelLane::Anomaly,
            57,
        ) => feature_vector_labels_v2(),
        _ => return None,
    };
    Some(fingerprint_for_labels(&labels))
}

fn model_freshness_notice(sidecar: Option<&serde_json::Value>) -> Option<String> {
    let sidecar = sidecar?;
    let trained_corpus_hash = sidecar.get("corpus_hash").and_then(|value| value.as_str());
    let trained_record_count = sidecar.get("record_count").and_then(|value| value.as_u64());
    let trained_at = sidecar.get("trained_at").and_then(|value| value.as_str());
    let corpus_stats = telemetry_corpus_stats().ok()?;

    if let Some(model_hash) = trained_corpus_hash
        && model_hash != corpus_stats.corpus_hash
    {
        return Some(format!(
            "local telemetry corpus hash changed{}; retraining recommended (trained_corpus_hash={}, current_corpus_hash={}, current_records={})",
            trained_at
                .map(|value| format!(" since {value}"))
                .unwrap_or_default(),
            model_hash,
            corpus_stats.corpus_hash,
            corpus_stats.record_count
        ));
    }

    if let Some(model_records) = trained_record_count {
        let growth_floor = model_records.saturating_add(100);
        let percentage_floor = ((model_records as f64) * 1.20).ceil() as u64;
        let required_records = growth_floor.max(percentage_floor);
        if corpus_stats.record_count >= required_records {
            return Some(format!(
                "local telemetry corpus grew from {} to {} records{}; retraining recommended",
                model_records,
                corpus_stats.record_count,
                trained_at
                    .map(|value| format!(" since {value}"))
                    .unwrap_or_default()
            ));
        }
    }

    None
}

fn mobile_dispatch_candidates(
    features: &ControlPlaneFeatures,
) -> Option<&'static [DispatchCandidate]> {
    match features.form_factor.as_str() {
        "mobile" | "headset" => {
            if features.low_power_mode || !features.metal_available {
                Some(&[DispatchCandidate::CpuOnly])
            } else {
                Some(&[DispatchCandidate::HashOnly, DispatchCandidate::CpuOnly])
            }
        }
        _ => None,
    }
}

fn apply_mobile_dispatch_policy(
    features: &ControlPlaneFeatures,
    scores: &mut Vec<DispatchCandidateScore>,
    notes: &mut Vec<String>,
) {
    let Some(allowed) = mobile_dispatch_candidates(features) else {
        return;
    };
    let original_best = scores.first().map(|score| score.candidate);
    let allowed_set = allowed.iter().copied().collect::<BTreeSet<_>>();
    scores.retain(|score| allowed_set.contains(&score.candidate));
    scores.sort_by(|left, right| {
        left.predicted_duration_ms
            .total_cmp(&right.predicted_duration_ms)
    });
    if original_best != scores.first().map(|score| score.candidate) {
        notes.push(format!(
            "mobile policy clamped dispatch candidates to [{}] for form factor '{}'{}",
            allowed
                .iter()
                .map(|candidate| candidate.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            features.form_factor,
            if features.low_power_mode {
                " while low-power mode is enabled"
            } else {
                ""
            }
        ));
    }
}

fn blackbox_ratio(features: &ControlPlaneFeatures, key: &str, total_blackboxes: f64) -> f32 {
    (features
        .circuit
        .blackbox_op_distribution
        .get(key)
        .copied()
        .unwrap_or(0) as f64
        / total_blackboxes)
        .clamp(0.0, 1.0) as f32
}

fn count_lookup_constraints(features: &ControlPlaneFeatures) -> usize {
    features
        .stage_node_counts
        .get("lookup-expand")
        .copied()
        .unwrap_or(0)
}

fn normalized_log2(value: usize, max_log2: f64) -> f32 {
    if value == 0 {
        0.0
    } else {
        (((value as f64) + 1.0).log2() / max_log2).clamp(0.0, 1.0) as f32
    }
}

fn stage_ratio(features: &ControlPlaneFeatures, stages: &[&str]) -> f32 {
    let total = features
        .stage_node_counts
        .values()
        .copied()
        .sum::<usize>()
        .max(1) as f64;
    let matched = stages
        .iter()
        .map(|stage| features.stage_node_counts.get(*stage).copied().unwrap_or(0))
        .sum::<usize>() as f64;
    (matched / total).clamp(0.0, 1.0) as f32
}

fn hash_stage_ratio(features: &ControlPlaneFeatures) -> f64 {
    stage_ratio(
        features,
        &["poseidon-batch", "sha256-batch", "merkle-layer"],
    ) as f64
}

fn algebra_stage_ratio(features: &ControlPlaneFeatures) -> f64 {
    stage_ratio(features, &["ntt", "lde", "msm"]) as f64
}

fn stark_stage_ratio(features: &ControlPlaneFeatures) -> f64 {
    stage_ratio(
        features,
        &[
            "ntt",
            "lde",
            "poseidon-batch",
            "merkle-layer",
            "fri-fold",
            "fri-query-open",
        ],
    ) as f64
}

fn stage_counts_from_graph(graph: &ProverGraph) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for node in graph.iter_nodes() {
        *counts.entry(node.op.stage_key().to_string()).or_insert(0) += 1;
    }
    counts
}

fn circuit_profile(
    program: Option<&Program>,
    compiled: Option<&CompiledProgram>,
    preview: Option<&WrapperPreview>,
    witness: Option<&Witness>,
    witness_inputs: Option<&WitnessInputs>,
    constraint_count_override: Option<usize>,
    signal_count_override: Option<usize>,
) -> CircuitFeatureProfile {
    let witness_size = witness
        .map(serialized_size)
        .or_else(|| witness_inputs.map(serialized_size))
        .unwrap_or_else(|| {
            preview
                .and_then(|value| value.estimated_memory_bytes)
                .unwrap_or_default() as usize
        });

    if let Some(program) = program
        .or_else(|| compiled.map(|value| value.original_program.as_ref().unwrap_or(&value.program)))
    {
        return CircuitFeatureProfile {
            constraint_count: program.constraints.len(),
            signal_count: program.signals.len(),
            blackbox_op_distribution: blackbox_distribution(program),
            max_constraint_degree: max_constraint_degree(program),
            witness_size,
        };
    }

    CircuitFeatureProfile {
        constraint_count: constraint_count_override
            .or_else(|| {
                preview.and_then(|value| value.estimated_constraints.map(|value| value as usize))
            })
            .unwrap_or(1),
        signal_count: signal_count_override.unwrap_or(1),
        blackbox_op_distribution: BTreeMap::new(),
        max_constraint_degree: 1,
        witness_size,
    }
}

fn backend_route_label(route: BackendRoute) -> String {
    match route {
        BackendRoute::Auto => "native-auto".to_string(),
        BackendRoute::ExplicitCompat => "explicit-compat".to_string(),
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

fn serialized_size<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default)]
struct HostSnapshot {
    thermal_pressure: Option<f64>,
    thermal_state_celsius: Option<f64>,
    cpu_speed_limit: Option<f64>,
    core_frequency_mhz: Option<u64>,
}

fn detect_host_snapshot() -> HostSnapshot {
    #[cfg(target_os = "macos")]
    {
        detect_host_snapshot_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        HostSnapshot::default()
    }
}

#[cfg(target_os = "macos")]
fn detect_host_snapshot_macos() -> HostSnapshot {
    let mut snapshot = HostSnapshot::default();
    if let Ok(output) = Command::new("pmset").args(["-g", "therm"]).output()
        && output.status.success()
    {
        let payload = String::from_utf8_lossy(&output.stdout);
        for line in payload.lines() {
            let normalized = line.trim();
            if let Some(value) = normalized
                .strip_prefix("CPU_Speed_Limit = ")
                .and_then(|raw| raw.trim().parse::<f64>().ok())
            {
                snapshot.cpu_speed_limit = Some((value / 100.0).clamp(0.0, 1.0));
            }
            if let Some(value) = normalized
                .strip_prefix("ThermalLevel = ")
                .and_then(|raw| raw.trim().parse::<f64>().ok())
            {
                snapshot.thermal_pressure = Some((value / 20.0).clamp(0.0, 1.0));
            }
        }
    }
    if let Ok(output) = Command::new("sysctl")
        .args(["-n", "hw.cpufrequency"])
        .output()
        && output.status.success()
    {
        let payload = String::from_utf8_lossy(&output.stdout);
        if let Ok(hz) = payload.trim().parse::<u64>() {
            snapshot.core_frequency_mhz = Some(hz / 1_000_000);
        }
    }
    snapshot
}

#[cfg(all(target_vendor = "apple", feature = "neural-engine"))]
#[allow(deprecated)]
pub(crate) fn predict_numeric(
    model: &ModelDescriptor,
    feature_vector: &[f32],
) -> Result<f64, String> {
    use objc2::AnyThread;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, ProtocolObject};
    use objc2_core_ml::{
        MLDictionaryFeatureProvider, MLFeatureValue, MLModel, MLModelConfiguration, MLMultiArray,
        MLMultiArrayDataType,
    };
    use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSString};

    let model_path = PathBuf::from(&model.path);
    let model_url = nsurl_for_path(&model_path);
    let compiled_url = if model_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mlmodelc"))
    {
        model_url
    } else {
        unsafe { MLModel::compileModelAtURL_error(&model_url) }
            .map_err(|err| format!("failed to compile CoreML model {}: {err:?}", model.path))?
    };

    let configuration = unsafe { MLModelConfiguration::new() };
    unsafe {
        configuration.setComputeUnits(objc2_core_ml::MLComputeUnits::CPUAndNeuralEngine);
    }
    let loaded = unsafe {
        MLModel::modelWithContentsOfURL_configuration_error(&compiled_url, &configuration)
    }
    .map_err(|err| format!("failed to load CoreML model {}: {err:?}", model.path))?;

    let shape = NSArray::from_retained_slice(&[NSNumber::numberWithUnsignedLongLong(
        feature_vector.len() as u64,
    )]);
    let input_array = unsafe {
        MLMultiArray::initWithShape_dataType_error(
            MLMultiArray::alloc(),
            &shape,
            MLMultiArrayDataType::Float32,
        )
    }
    .map_err(|err| {
        format!(
            "failed to allocate MLMultiArray for {}: {err:?}",
            model.path
        )
    })?;

    unsafe {
        let ptr = input_array.dataPointer().as_ptr() as *mut f32;
        std::ptr::copy_nonoverlapping(feature_vector.as_ptr(), ptr, feature_vector.len());
    }

    let feature_name = NSString::from_str("features");
    let feature_value = unsafe { MLFeatureValue::featureValueWithMultiArray(&input_array) };
    let dictionary: Retained<NSDictionary<NSString, AnyObject>> =
        NSDictionary::from_retained_objects(&[&*feature_name], &[feature_value.into()]);
    let provider = unsafe {
        MLDictionaryFeatureProvider::initWithDictionary_error(
            MLDictionaryFeatureProvider::alloc(),
            &dictionary,
        )
    }
    .map_err(|err| {
        format!(
            "failed to create CoreML feature provider for {}: {err:?}",
            model.path
        )
    })?;

    let prediction =
        unsafe { loaded.predictionFromFeatures_error(ProtocolObject::from_ref(&*provider)) }
            .map_err(|err| format!("CoreML inference failed for {}: {err:?}", model.path))?;
    extract_numeric_prediction(ProtocolObject::from_ref(&*prediction))
}

#[cfg(all(target_vendor = "apple", feature = "neural-engine"))]
fn extract_numeric_prediction(
    provider: &objc2::runtime::ProtocolObject<dyn objc2_core_ml::MLFeatureProvider>,
) -> Result<f64, String> {
    use objc2_core_ml::MLFeatureProvider;
    use objc2_foundation::NSString;

    for key in [
        "predicted_duration_ms",
        "score",
        "backend_score",
        "anomaly_score",
        "risk_score",
        "gpu_lane_score",
    ] {
        let name = NSString::from_str(key);
        if let Some(value) = unsafe { provider.featureValueForName(&name) } {
            if let Some(array) = unsafe { value.multiArrayValue() } {
                return multi_array_first_f64(&array)
                    .ok_or_else(|| "CoreML output multiarray was empty".to_string());
            }
            let numeric = unsafe { value.doubleValue() };
            if numeric.is_finite() {
                return Ok(numeric);
            }
        }
    }

    let keys = unsafe { provider.featureNames() };
    for key in keys.iter() {
        if let Some(value) = unsafe { provider.featureValueForName(&key) } {
            if let Some(array) = unsafe { value.multiArrayValue() }
                && let Some(candidate) = multi_array_first_f64(&array)
            {
                return Ok(candidate);
            }
            let numeric = unsafe { value.doubleValue() };
            if numeric.is_finite() {
                return Ok(numeric);
            }
        }
    }

    Err("CoreML model did not expose a numeric output".to_string())
}

#[cfg(all(target_vendor = "apple", feature = "neural-engine"))]
#[allow(deprecated)]
fn multi_array_first_f64(value: &objc2_core_ml::MLMultiArray) -> Option<f64> {
    let count = unsafe { value.count() };
    if count <= 0 {
        return None;
    }
    let ptr = unsafe { value.dataPointer().as_ptr() };
    match unsafe { value.dataType() } {
        objc2_core_ml::MLMultiArrayDataType::Float32 => {
            let typed = ptr as *const f32;
            Some(unsafe { *typed } as f64)
        }
        objc2_core_ml::MLMultiArrayDataType::Float64 => {
            let typed = ptr as *const f64;
            Some(unsafe { *typed })
        }
        objc2_core_ml::MLMultiArrayDataType::Int32 => {
            let typed = ptr as *const i32;
            Some(unsafe { *typed } as f64)
        }
        objc2_core_ml::MLMultiArrayDataType::Int8 => {
            let typed = ptr as *const i8;
            Some(unsafe { *typed } as f64)
        }
        _ => None,
    }
}

#[cfg(all(target_vendor = "apple", feature = "neural-engine"))]
fn nsurl_for_path(path: &Path) -> objc2::rc::Retained<objc2_foundation::NSURL> {
    let ns_path = objc2_foundation::NSString::from_str(&path.display().to_string());
    objc2_foundation::NSURL::fileURLWithPath(&ns_path)
}

#[cfg(not(all(target_vendor = "apple", feature = "neural-engine")))]
pub(crate) fn predict_numeric(
    _model: &ModelDescriptor,
    _feature_vector: &[f32],
) -> Result<f64, String> {
    Err(
        "native CoreML inference is unavailable without an Apple target and feature=neural-engine"
            .to_string(),
    )
}

pub fn stable_feature_schema_fingerprint() -> String {
    schema_fingerprint_for_lane_shape(ModelLane::Scheduler, feature_vector_labels().len())
        .expect("scheduler v2 schema fingerprint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{ProverNode, ProverOp};
    use crate::memory::{MemoryClass, UnifiedBufferPool};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use zkf_core::ir::{BlackBoxOp, Expr, Program, Signal, Visibility};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("neural_engine")
    }

    fn fixture_model_path(name: &str) -> PathBuf {
        fixture_root().join("models").join(name)
    }

    fn sample_request<'a>(program: &'a Program, graph: &'a ProverGraph) -> ControlPlaneRequest<'a> {
        ControlPlaneRequest {
            job_kind: JobKind::Prove,
            objective: OptimizationObjective::FastestProve,
            graph: Some(graph),
            constraint_count_override: None,
            signal_count_override: None,
            stage_node_counts_override: None,
            field_hint: Some(program.field),
            program: Some(program),
            compiled: None,
            preview: None,
            witness: None,
            witness_inputs: None,
            requested_backend: None,
            backend_route: Some(BackendRoute::Auto),
            trust_lane: RequiredTrustLane::StrictCryptographic,
            requested_jobs: Some(2),
            total_jobs: Some(4),
            backend_candidates: vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3],
        }
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    fn with_fixture_model_env<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = [
            (
                "ZKF_SCHEDULER_MODEL",
                fixture_model_path("scheduler_v1.mlpackage"),
            ),
            (
                "ZKF_BACKEND_RECOMMENDER_MODEL",
                fixture_model_path("backend_recommender_v1.mlpackage"),
            ),
            (
                "ZKF_DURATION_ESTIMATOR_MODEL",
                fixture_model_path("duration_estimator_v1.mlpackage"),
            ),
            (
                "ZKF_ANOMALY_DETECTOR_MODEL",
                fixture_model_path("anomaly_detector_v1.mlpackage"),
            ),
        ];
        let previous = entries
            .iter()
            .map(|(key, _)| (key.to_string(), std::env::var_os(key)))
            .collect::<Vec<_>>();
        for (key, value) in &entries {
            unsafe {
                std::env::set_var(key, value);
            }
        }
        let result = f();
        for (key, value) in previous {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(&key, value);
                } else {
                    std::env::remove_var(&key);
                }
            }
        }
        result
    }

    fn with_repo_local_fixture_models_root<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let target_root = repo_root.join("target").join("coreml");
        fs::create_dir_all(&target_root).expect("target/coreml");
        let home = tempfile::tempdir().expect("home tempdir");
        let backup_root = tempfile::tempdir().expect("backup tempdir");
        let model_names = [
            "scheduler_v1.mlpackage",
            "backend_recommender_v1.mlpackage",
            "duration_estimator_v1.mlpackage",
            "anomaly_detector_v1.mlpackage",
        ];
        let env_keys = [
            "ZKF_SCHEDULER_MODEL",
            "ZKF_BACKEND_RECOMMENDER_MODEL",
            "ZKF_DURATION_ESTIMATOR_MODEL",
            "ZKF_ANOMALY_DETECTOR_MODEL",
            "ZKF_ANE_POLICY_MODEL",
            "HOME",
        ];
        let previous = env_keys
            .iter()
            .map(|key| (key.to_string(), std::env::var_os(key)))
            .collect::<Vec<_>>();
        for (idx, model_name) in model_names.iter().enumerate() {
            let dest_package = target_root.join(model_name);
            let dest_sidecar = PathBuf::from(format!("{}.json", dest_package.display()));
            let source_package = fixture_model_path(model_name);
            let source_sidecar = PathBuf::from(format!("{}.json", source_package.display()));
            let backup_package = backup_root.path().join(format!("{idx}-{model_name}"));
            let backup_sidecar = backup_root.path().join(format!("{idx}-{model_name}.json"));
            if dest_package.exists() {
                fs::rename(&dest_package, &backup_package).expect("backup package");
            }
            if dest_sidecar.exists() {
                fs::rename(&dest_sidecar, &backup_sidecar).expect("backup sidecar");
            }
            fs::remove_dir_all(&dest_package).ok();
            fs::copy(&source_sidecar, &dest_sidecar).expect("copy sidecar");
            fs::create_dir_all(dest_package.parent().expect("dest parent")).expect("target parent");
            fs::remove_dir_all(&dest_package).ok();
            copy_dir_all(&source_package, &dest_package).expect("copy package");
        }
        unsafe {
            for key in [
                "ZKF_SCHEDULER_MODEL",
                "ZKF_BACKEND_RECOMMENDER_MODEL",
                "ZKF_DURATION_ESTIMATOR_MODEL",
                "ZKF_ANOMALY_DETECTOR_MODEL",
                "ZKF_ANE_POLICY_MODEL",
            ] {
                std::env::remove_var(key);
            }
            std::env::set_var("HOME", home.path());
        }
        let result = f(&target_root);
        for model_name in model_names {
            let dest_package = target_root.join(model_name);
            let dest_sidecar = PathBuf::from(format!("{}.json", dest_package.display()));
            fs::remove_dir_all(&dest_package).ok();
            fs::remove_file(&dest_sidecar).ok();
        }
        for (idx, model_name) in model_names.iter().enumerate() {
            let dest_package = target_root.join(model_name);
            let dest_sidecar = PathBuf::from(format!("{}.json", dest_package.display()));
            let backup_package = backup_root.path().join(format!("{idx}-{model_name}"));
            let backup_sidecar = backup_root.path().join(format!("{idx}-{model_name}.json"));
            if backup_package.exists() {
                fs::rename(&backup_package, &dest_package).expect("restore package");
            }
            if backup_sidecar.exists() {
                fs::rename(&backup_sidecar, &dest_sidecar).expect("restore sidecar");
            }
        }
        for (key, value) in previous {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(&key, value);
                } else {
                    std::env::remove_var(&key);
                }
            }
        }
        result
    }

    fn with_repo_local_fixture_models<T>(f: impl FnOnce() -> T) -> T {
        with_repo_local_fixture_models_root(|_| f())
    }

    fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
            } else {
                fs::copy(entry.path(), dst.join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    fn sample_program() -> Program {
        Program {
            name: "policy-sample".to_string(),
            field: zkf_core::FieldId::Bn254,
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

    fn sample_graph() -> ProverGraph {
        let mut pool = UnifiedBufferPool::new(1024 * 1024);
        let hash = pool.alloc(64, MemoryClass::EphemeralScratch).unwrap();
        let mut graph = ProverGraph::new();
        graph.add_node(ProverNode::new(ProverOp::Sha256Batch { count: 512 }).with_outputs([hash]));
        graph.add_node(ProverNode::new(ProverOp::Ntt {
            size: 1 << 16,
            field: "bn254",
            inverse: false,
        }));
        graph
    }

    #[test]
    fn dispatch_plan_round_trips_expected_stages() {
        let plan = DispatchCandidate::Balanced.to_plan();
        assert_eq!(plan.candidate, DispatchCandidate::Balanced);
        assert!(plan.stages_on_gpu.iter().any(|stage| stage == "ntt"));
        assert_eq!(plan.placement_for_stage("ntt"), Some(DevicePlacement::Gpu));
        assert_eq!(
            plan.placement_for_stage("sha256-batch"),
            Some(DevicePlacement::Cpu)
        );
    }

    #[test]
    fn feature_vector_schema_is_stable() {
        assert_eq!(feature_vector_labels().len(), 57);
        assert_eq!(stable_feature_schema_fingerprint().len(), 64);
        assert_eq!(
            schema_fingerprint_for_lane_shape(ModelLane::Scheduler, 47),
            Some("3e05b7ee88d044937f9d6fb44d741b530bea8d9295e1adf384d85c059cbde14e".to_string())
        );
    }

    #[test]
    fn control_plane_falls_back_without_models() {
        let program = sample_program();
        let graph = sample_graph();
        let request = sample_request(&program, &graph);
        let decision = evaluate_control_plane(&request);
        assert_eq!(decision.job_kind, JobKind::Prove);
        assert!(!decision.candidate_rankings.is_empty());
        assert!(decision.duration_estimate.estimate_ms > 0.0);
        assert!(decision.duration_estimate.predicted_wall_time_ms > 0.0);
        assert!(
            decision
                .features
                .gpu_capable_stage_counts
                .contains_key("ntt")
        );
    }

    #[test]
    fn no_metal_duration_estimate_is_cpu_only_non_sla_fallback() {
        let program = sample_program();
        let graph = sample_graph();
        let request = sample_request(&program, &graph);
        let mut features = extract_features(&request);
        features.metal_available = false;
        let estimate = estimate_duration(
            &features,
            BackendKind::ArkworksGroth16,
            DispatchCandidate::Balanced,
            OptimizationObjective::FastestProve,
            &[],
            &ModelCatalog::default(),
        );

        assert_eq!(estimate.execution_regime, ExecutionRegime::CpuOnly);
        assert_eq!(estimate.eta_semantics, EtaSemantics::NonSlaFallback);
        assert_eq!(estimate.bound_source, BoundSource::Unavailable);
        assert_eq!(estimate.upper_bound_ms, None);
        assert!(!estimate.countdown_safe);
        assert!(
            estimate
                .note
                .as_deref()
                .unwrap_or_default()
                .contains("not countdown-safe")
        );
    }

    #[test]
    fn backend_recommendation_honors_requested_objective() {
        let program = sample_program();
        let graph = sample_graph();
        let mut request = sample_request(&program, &graph);
        request.backend_candidates = vec![
            BackendKind::ArkworksGroth16,
            BackendKind::Plonky3,
            BackendKind::Nova,
        ];

        request.objective = OptimizationObjective::FastestProve;
        let fastest = evaluate_control_plane(&request).backend_recommendation;

        request.objective = OptimizationObjective::SmallestProof;
        let smallest = evaluate_control_plane(&request).backend_recommendation;

        request.objective = OptimizationObjective::NoTrustedSetup;
        let mut transparent_program = sample_program();
        transparent_program.field = FieldId::Goldilocks;
        let mut transparent_request = sample_request(&transparent_program, &graph);
        transparent_request.backend_candidates =
            vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
        transparent_request.objective = OptimizationObjective::NoTrustedSetup;
        let transparent = evaluate_control_plane(&transparent_request).backend_recommendation;

        assert_eq!(fastest.objective, OptimizationObjective::FastestProve);
        assert_eq!(smallest.objective, OptimizationObjective::SmallestProof);
        assert_eq!(transparent.objective, OptimizationObjective::NoTrustedSetup);
        assert!(matches!(
            fastest.selected,
            BackendKind::Plonky3 | BackendKind::Nova
        ));
        assert!(matches!(smallest.selected, BackendKind::Plonky3 | BackendKind::Nova));
        assert!(fastest.notes.iter().any(|note| {
            note.contains("arkworks-groth16") && note.contains("filtered backend")
        }));
        assert!(smallest.notes.iter().any(|note| {
            note.contains("arkworks-groth16") && note.contains("filtered backend")
        }));
        assert!(matches!(
            transparent.selected,
            BackendKind::Plonky3
                | BackendKind::Nova
                | BackendKind::HyperNova
                | BackendKind::Sp1
                | BackendKind::RiscZero
        ));
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn model_backed_smallest_proof_keeps_groth16_when_allowed() {
        with_fixture_model_env(|| {
            let program = sample_program();
            let graph = sample_graph();
            let mut request = sample_request(&program, &graph);
            request.backend_candidates = vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
            request.requested_backend = Some(BackendKind::ArkworksGroth16);
            request.objective = OptimizationObjective::SmallestProof;

            let recommendation = evaluate_control_plane(&request).backend_recommendation;
            assert_eq!(recommendation.source, "model");
            assert_eq!(recommendation.selected, BackendKind::ArkworksGroth16);
        });
    }

    #[test]
    fn explicit_requested_backend_bypasses_readiness_filter() {
        let program = sample_program();
        let graph = sample_graph();
        let mut request = sample_request(&program, &graph);
        request.requested_backend = Some(BackendKind::ArkworksGroth16);

        assert_eq!(
            backend_readiness_filter_reason(&request, BackendKind::ArkworksGroth16),
            None
        );
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn model_backed_no_trusted_setup_filters_trusted_setup_backends() {
        with_fixture_model_env(|| {
            let mut program = sample_program();
            program.field = FieldId::Goldilocks;
            let graph = sample_graph();
            let mut request = sample_request(&program, &graph);
            request.backend_candidates = vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
            request.objective = OptimizationObjective::NoTrustedSetup;

            let recommendation = evaluate_control_plane(&request).backend_recommendation;
            assert_eq!(recommendation.source, "model");
            assert_eq!(recommendation.selected, BackendKind::Plonky3);
            assert!(recommendation.notes.iter().any(|note| {
                note.contains("arkworks-groth16") && note.contains("filtered backend")
            }));
        });
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn model_backed_invalid_preference_is_filtered_and_noted() {
        with_fixture_model_env(|| {
            let mut program = sample_program();
            program.field = FieldId::Goldilocks;
            let graph = sample_graph();
            let mut request = sample_request(&program, &graph);
            request.backend_candidates = vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
            request.objective = OptimizationObjective::SmallestProof;

            let recommendation = evaluate_control_plane(&request).backend_recommendation;
            assert_eq!(recommendation.source, "model");
            assert_eq!(recommendation.selected, BackendKind::Plonky3);
            assert!(recommendation.notes.iter().any(|note| {
                note.contains("filtered model-preferred backend 'arkworks-groth16'")
            }));
        });
    }

    #[test]
    fn model_discovery_prefers_explicit_env() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tempdir = tempfile::tempdir().unwrap();
        let explicit = tempdir.path().join("scheduler_v1.mlpackage");
        fs::create_dir_all(&explicit).unwrap();
        unsafe {
            std::env::set_var("ZKF_SCHEDULER_MODEL", &explicit);
        }
        let catalog = ModelCatalog::discover();
        unsafe {
            std::env::remove_var("ZKF_SCHEDULER_MODEL");
        }
        assert_eq!(
            catalog
                .scheduler
                .as_ref()
                .map(|descriptor| descriptor.path.as_str()),
            Some(explicit.display().to_string().as_str())
        );
        assert_eq!(
            catalog
                .scheduler
                .as_ref()
                .map(|descriptor| descriptor.source),
            Some(ModelSource::Environment)
        );
        assert_eq!(
            catalog
                .scheduler
                .as_ref()
                .and_then(|descriptor| descriptor.quality_gate.as_ref()),
            None
        );
    }

    #[test]
    fn repo_local_fixture_models_are_discoverable_without_env_or_home_models() {
        with_repo_local_fixture_models(|| {
            let catalog = ModelCatalog::discover();
            assert_eq!(
                catalog
                    .scheduler
                    .as_ref()
                    .map(|descriptor| descriptor.source),
                Some(ModelSource::RepoLocal),
                "catalog failures: {:?}",
                catalog.failures
            );
            assert_eq!(
                catalog.backend.as_ref().map(|descriptor| descriptor.source),
                Some(ModelSource::RepoLocal),
                "catalog failures: {:?}",
                catalog.failures
            );
            assert_eq!(
                catalog
                    .duration
                    .as_ref()
                    .map(|descriptor| descriptor.source),
                Some(ModelSource::RepoLocal),
                "catalog failures: {:?}",
                catalog.failures
            );
            assert_eq!(
                catalog.anomaly.as_ref().map(|descriptor| descriptor.source),
                Some(ModelSource::RepoLocal),
                "catalog failures: {:?}",
                catalog.failures
            );
        });
    }

    #[test]
    fn missing_explicit_scheduler_model_falls_back_with_recorded_failure() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempfile::tempdir().expect("home");
        let env_keys = [
            "HOME",
            "ZKF_SCHEDULER_MODEL",
            "ZKF_BACKEND_RECOMMENDER_MODEL",
            "ZKF_DURATION_ESTIMATOR_MODEL",
            "ZKF_ANOMALY_DETECTOR_MODEL",
            "ZKF_ANE_POLICY_MODEL",
        ];
        let previous = env_keys
            .iter()
            .map(|key| (key.to_string(), std::env::var_os(key)))
            .collect::<Vec<_>>();
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("ZKF_SCHEDULER_MODEL", home.path().join("missing.mlpackage"));
            std::env::remove_var("ZKF_BACKEND_RECOMMENDER_MODEL");
            std::env::remove_var("ZKF_DURATION_ESTIMATOR_MODEL");
            std::env::remove_var("ZKF_ANOMALY_DETECTOR_MODEL");
            std::env::remove_var("ZKF_ANE_POLICY_MODEL");
        }
        let program = sample_program();
        let graph = sample_graph();
        let decision = evaluate_control_plane(&sample_request(&program, &graph));
        for (key, value) in previous {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(&key, value);
                } else {
                    std::env::remove_var(&key);
                }
            }
        }
        assert!(decision.model_catalog.scheduler.is_none());
        assert!(decision.model_catalog.failures.contains_key("scheduler"));
        assert!(!decision.candidate_rankings.is_empty());
        assert!(decision.duration_estimate.estimate_ms > 0.0);
        assert!(decision.duration_estimate.predicted_wall_time_ms > 0.0);
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn fixture_models_load_natively_and_drive_model_sources() {
        with_fixture_model_env(|| {
            let program = sample_program();
            let graph = sample_graph();
            let decision = evaluate_control_plane(&sample_request(&program, &graph));
            assert!(decision.model_catalog.scheduler.is_some());
            assert!(decision.model_catalog.backend.is_some());
            assert!(decision.model_catalog.duration.is_some());
            assert!(decision.model_catalog.anomaly.is_some());
            assert_eq!(decision.backend_recommendation.source, "model");
            assert_eq!(decision.duration_estimate.source, "model");
            assert_eq!(decision.anomaly_baseline.source, "model");

            let scheduler = decision
                .model_catalog
                .scheduler
                .as_ref()
                .expect("scheduler");
            let backend = decision.model_catalog.backend.as_ref().expect("backend");
            let duration = decision.model_catalog.duration.as_ref().expect("duration");
            let anomaly = decision.model_catalog.anomaly.as_ref().expect("anomaly");
            let scheduler_score = predict_numeric(
                scheduler,
                &build_feature_vector_for_descriptor(
                    scheduler,
                    &decision.features,
                    Some(DispatchCandidate::Balanced),
                    Some(BackendKind::ArkworksGroth16),
                    None,
                ),
            )
            .expect("scheduler prediction");
            let backend_score = predict_numeric(
                backend,
                &build_feature_vector_for_descriptor(
                    backend,
                    &decision.features,
                    None,
                    Some(BackendKind::Plonky3),
                    Some(OptimizationObjective::FastestProve),
                ),
            )
            .expect("backend prediction");
            let duration_score = predict_numeric(
                duration,
                &build_feature_vector_for_descriptor(
                    duration,
                    &decision.features,
                    Some(DispatchCandidate::Balanced),
                    Some(BackendKind::ArkworksGroth16),
                    None,
                ),
            )
            .expect("duration prediction");
            let anomaly_score = predict_numeric(
                anomaly,
                &build_feature_vector_for_descriptor(
                    anomaly,
                    &decision.features,
                    Some(DispatchCandidate::Balanced),
                    Some(BackendKind::ArkworksGroth16),
                    None,
                ),
            )
            .expect("anomaly prediction");

            assert!(scheduler_score.is_finite());
            assert!(backend_score.is_finite());
            assert!(duration_score.is_finite());
            assert!(anomaly_score.is_finite());
        });
    }

    #[test]
    fn auto_discovery_rejects_failed_quality_gate_and_records_failure() {
        with_repo_local_fixture_models_root(|target_root| {
            let sidecar_path = target_root.join("scheduler_v1.mlpackage.json");
            let mut payload = serde_json::from_slice::<serde_json::Value>(
                &fs::read(&sidecar_path).expect("read sidecar"),
            )
            .expect("parse sidecar");
            payload["quality_gate"]["passed"] = serde_json::Value::Bool(false);
            payload["quality_gate"]["reasons"] =
                serde_json::json!(["fixture smoke floor did not clear the scheduler gate"]);
            fs::write(
                &sidecar_path,
                serde_json::to_vec_pretty(&payload).expect("encode sidecar"),
            )
            .expect("write sidecar");

            let catalog = ModelCatalog::discover();
            assert!(catalog.scheduler.is_none());
            assert_eq!(
                catalog.backend.as_ref().map(|descriptor| descriptor.source),
                Some(ModelSource::RepoLocal),
                "catalog failures: {:?}",
                catalog.failures
            );
            let failure = catalog
                .failures
                .get("scheduler")
                .expect("scheduler failure");
            assert!(failure.contains("failed quality gate"));
            assert!(failure.contains("fixture smoke floor did not clear the scheduler gate"));
        });
    }

    #[test]
    fn anomaly_verdict_uses_model_budget_and_falls_back_to_heuristic_thresholds() {
        let model_baseline = AnomalyVerdict {
            severity: AnomalySeverity::Normal,
            source: "model".to_string(),
            reason: "baseline residual envelope".to_string(),
            predicted_anomaly_score: Some(1.2),
            advisory_estimate_ms: Some(100.0),
            conservative_upper_bound_ms: Some(120.0),
            execution_regime: Some(ExecutionRegime::GpuCapable),
            eta_semantics: Some(EtaSemantics::ModelEstimate),
            bound_source: Some(BoundSource::ModelDerived),
            duration_interpretation: None,
            expected_duration_ms: Some(100.0),
            expected_duration_ratio_limit: Some(1.2),
            observed_duration_ms: None,
            duration_ratio: None,
            expected_proof_size_bytes: Some(128),
            expected_proof_size_ratio_limit: Some(1.2),
            observed_proof_size_bytes: None,
            proof_size_ratio: None,
        };
        let heuristic_baseline = AnomalyVerdict {
            source: "heuristic".to_string(),
            predicted_anomaly_score: None,
            conservative_upper_bound_ms: None,
            bound_source: Some(BoundSource::Unavailable),
            expected_duration_ratio_limit: None,
            expected_proof_size_ratio_limit: None,
            ..model_baseline.clone()
        };

        let model_verdict = evaluate_observed_anomaly(&model_baseline, 260.0, Some(180));
        let heuristic_verdict = evaluate_observed_anomaly(&heuristic_baseline, 180.0, Some(180));

        assert_eq!(model_verdict.severity, AnomalySeverity::Warning);
        assert_eq!(heuristic_verdict.severity, AnomalySeverity::Normal);
        assert_eq!(model_verdict.predicted_anomaly_score, Some(1.2));
        assert_eq!(model_verdict.expected_duration_ratio_limit, Some(1.2));
        assert_eq!(heuristic_verdict.expected_duration_ratio_limit, None);
        assert_eq!(
            model_verdict.duration_interpretation.as_deref(),
            Some("exceeded-conservative-bound")
        );
        assert_eq!(
            heuristic_verdict.duration_interpretation.as_deref(),
            Some("slower-than-advisory-estimate")
        );
        assert!(model_verdict.reason.contains("conservative bound"));
        assert!(
            heuristic_verdict
                .reason
                .contains("advisory heuristic estimate")
        );
    }
}
