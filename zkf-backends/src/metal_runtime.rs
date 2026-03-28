use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::midnight_client::MidnightClient;
use crate::{BoundedStringCache, bounded_cache_limit};
use zkf_core::acceleration::accelerator_registry;
use zkf_core::{
    BackendCapabilities, BackendCapabilityEntry, BackendCapabilityMatrix, BackendKind, FieldId,
    SupportClass,
};

#[derive(Debug, Clone, Serialize)]
pub struct MetalRuntimeReport {
    pub metal_compiled: bool,
    pub metal_available: bool,
    pub metal_disabled_by_env: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metallib_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_working_set_size_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_allocated_size_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_set_headroom_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_set_utilization_pct: Option<f64>,
    pub metal_dispatch_circuit_open: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_dispatch_last_failure: Option<String>,
    pub prewarmed_pipelines: usize,
    pub metal_primary_queue_depth: usize,
    pub metal_secondary_queue_depth: usize,
    pub metal_pipeline_max_in_flight: usize,
    pub metal_scheduler_max_jobs: usize,
    pub metal_working_set_headroom_target_pct: u8,
    pub metal_gpu_busy_ratio: f64,
    pub metal_stage_breakdown: String,
    pub metal_inflight_jobs: usize,
    pub metal_no_cpu_fallback: bool,
    pub metal_counter_source: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub active_accelerators: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub registered_accelerators: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cpu_fallback_reasons: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    #[serde(flatten)]
    pub capabilities: BackendCapabilities,
    pub supported_fields: Vec<FieldId>,
    pub implementation_type: SupportClass,
    pub compiled_in: bool,
    pub toolchain_ready: bool,
    pub runtime_ready: bool,
    pub production_ready: bool,
    pub readiness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_compat_alias: Option<String>,
    pub native_lookup_support: bool,
    pub lookup_lowering_support: bool,
    pub lookup_semantics: String,
    pub assurance_lane: String,
    pub aggregation_semantics: String,
    pub proof_engine: String,
    pub proof_semantics: String,
    pub blackbox_semantics: String,
    pub prover_acceleration_scope: String,
    pub gpu_stage_coverage: GpuStageCoverage,
    pub metal_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_math_fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuSchedulerDecision {
    pub requested_jobs: usize,
    pub total_jobs: usize,
    pub recommended_jobs: usize,
    pub estimated_job_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_budget_bytes: Option<usize>,
    pub metal_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_device: Option<String>,
    pub reason: String,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuStage {
    WitnessBuild,
    FftNtt,
    ConstraintEval,
    HashMerkle,
    FriFold,
    Msm,
    QapWitnessMap,
    ProofAssemble,
}

impl GpuStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WitnessBuild => "witness-build",
            Self::FftNtt => "fft-ntt",
            Self::ConstraintEval => "constraint-eval",
            Self::HashMerkle => "hash-merkle",
            Self::FriFold => "fri-fold",
            Self::Msm => "msm",
            Self::QapWitnessMap => "qap-witness-map",
            Self::ProofAssemble => "proof-assemble",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuStageCoverage {
    pub coverage_ratio: f64,
    pub required_stages: Vec<String>,
    pub metal_stages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpu_stages: Vec<String>,
}

#[derive(Debug, Clone)]
struct BackendReadiness {
    implementation_type: SupportClass,
    compiled_in: bool,
    toolchain_ready: bool,
    runtime_ready: bool,
    production_ready: bool,
    readiness: &'static str,
    readiness_reason: Option<String>,
    operator_action: Option<String>,
    explicit_compat_alias: Option<String>,
}

const ARKWORKS_PRODUCTION_DISCLAIMER_REASON: &str =
    "upstream-ark-groth16-production-disclaimer";

const STANDARD_METAL_METADATA_KEYS: [&str; 7] = [
    "metal_gpu_busy_ratio",
    "metal_stage_breakdown",
    "metal_inflight_jobs",
    "metal_no_cpu_fallback",
    "metal_counter_source",
    "metal_dispatch_circuit_open",
    "metal_dispatch_last_failure",
];

static COMMAND_AVAILABLE_CACHE: Lazy<Mutex<BoundedStringCache<bool>>> = Lazy::new(|| {
    Mutex::new(BoundedStringCache::new(bounded_cache_limit(
        "ZKF_COMMAND_AVAILABLE_CACHE_ENTRIES",
        64,
    )))
});
static TOOLCHAIN_TARGET_CACHE: Lazy<Mutex<BoundedStringCache<bool>>> = Lazy::new(|| {
    Mutex::new(BoundedStringCache::new(bounded_cache_limit(
        "ZKF_TOOLCHAIN_TARGET_CACHE_ENTRIES",
        32,
    )))
});
#[cfg(test)]
static BACKEND_TOOLCHAIN_STATUS_PROBE_COUNTS: Lazy<Mutex<BTreeMap<String, usize>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

#[cfg(test)]
fn note_backend_toolchain_status_probe(kind: BackendKind) {
    if let Ok(mut counts) = BACKEND_TOOLCHAIN_STATUS_PROBE_COUNTS.lock() {
        *counts.entry(kind.as_str().to_string()).or_insert(0) += 1;
    }
}

#[cfg(test)]
fn reset_backend_toolchain_status_probe_counts() {
    if let Ok(mut counts) = BACKEND_TOOLCHAIN_STATUS_PROBE_COUNTS.lock() {
        counts.clear();
    }
}

#[cfg(test)]
fn backend_toolchain_status_probe_count(kind: BackendKind) -> usize {
    BACKEND_TOOLCHAIN_STATUS_PROBE_COUNTS
        .lock()
        .ok()
        .and_then(|counts| counts.get(kind.as_str()).copied())
        .unwrap_or(0)
}

pub fn append_default_metal_telemetry(metadata: &mut BTreeMap<String, String>) {
    metadata
        .entry("metal_gpu_busy_ratio".to_string())
        .or_insert_with(|| "0.0".to_string());
    metadata
        .entry("metal_stage_breakdown".to_string())
        .or_insert_with(|| "{}".to_string());
    metadata
        .entry("metal_inflight_jobs".to_string())
        .or_insert_with(|| "0".to_string());
    metadata
        .entry("metal_no_cpu_fallback".to_string())
        .or_insert_with(|| "false".to_string());
    metadata
        .entry("metal_counter_source".to_string())
        .or_insert_with(|| "not-measured".to_string());
    metadata
        .entry("metal_dispatch_circuit_open".to_string())
        .or_insert_with(|| "false".to_string());
    metadata
        .entry("metal_dispatch_last_failure".to_string())
        .or_default();
}

pub fn copy_standard_metal_metadata(
    source: &BTreeMap<String, String>,
    target: &mut BTreeMap<String, String>,
    prefix: Option<&str>,
) {
    let prefix = prefix.unwrap_or_default();
    for key in STANDARD_METAL_METADATA_KEYS {
        if let Some(value) = source.get(key) {
            target.insert(format!("{prefix}{key}"), value.clone());
        }
    }
}

pub fn runtime_hardware_profile(runtime: &MetalRuntimeReport) -> &'static str {
    match runtime.metal_device.as_deref() {
        Some(device) if device.contains("M4 Max") => "apple-silicon-m4-max-48gb",
        Some(_) if runtime.metal_available => "apple-silicon-generic",
        _ => "cpu-only",
    }
}

fn runtime_is_certified_m4_max(runtime: &MetalRuntimeReport) -> bool {
    runtime.metal_compiled
        && runtime.metal_available
        && !runtime.metal_dispatch_circuit_open
        && runtime_hardware_profile(runtime) == "apple-silicon-m4-max-48gb"
        && runtime
            .recommended_working_set_size_bytes
            .unwrap_or_default()
            > 0
        && runtime.working_set_headroom_bytes.unwrap_or_default() > 0
}

pub fn strict_bn254_gpu_stage_coverage(runtime: &MetalRuntimeReport) -> GpuStageCoverage {
    gpu_stage_coverage_from_runtime(BackendKind::ArkworksGroth16, Some(FieldId::Bn254), runtime)
}

pub fn strict_bn254_auto_route_ready_with_runtime(runtime: &MetalRuntimeReport) -> bool {
    if !runtime_is_certified_m4_max(runtime) {
        return false;
    }
    let coverage = strict_bn254_gpu_stage_coverage(runtime);
    !coverage.required_stages.is_empty() && coverage.cpu_stages.is_empty()
}

pub fn strict_bn254_auto_route_ready() -> bool {
    strict_bn254_auto_route_ready_with_runtime(&metal_runtime_report())
}

pub fn metal_runtime_report() -> MetalRuntimeReport {
    crate::init_accelerators();

    let (active_accelerators, registered_accelerators) = {
        let reg = accelerator_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut active = BTreeMap::new();
        let mut registered = BTreeMap::new();

        let msm_registered = reg
            .msm_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !msm_registered.is_empty() {
            active.insert("msm".to_string(), reg.best_msm().name().to_string());
            registered.insert("msm".to_string(), msm_registered);
        }

        let ntt_registered = reg
            .ntt_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !ntt_registered.is_empty() {
            active.insert("ntt".to_string(), reg.best_ntt().name().to_string());
            registered.insert("ntt".to_string(), ntt_registered);
        }

        let hash_registered = reg
            .hash_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !hash_registered.is_empty() {
            if let Some(best) = reg.best_hash() {
                active.insert("hash".to_string(), best.name().to_string());
            }
            registered.insert("hash".to_string(), hash_registered);
        }

        let poseidon2_registered = reg
            .poseidon2_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !poseidon2_registered.is_empty() {
            if let Some(best) = reg.best_poseidon2() {
                active.insert("poseidon2".to_string(), best.name().to_string());
            }
            registered.insert("poseidon2".to_string(), poseidon2_registered);
        }

        let field_ops_registered = reg
            .field_ops_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !field_ops_registered.is_empty() {
            if let Some(best) = reg.best_field_ops() {
                active.insert("field_ops".to_string(), best.name().to_string());
            }
            registered.insert("field_ops".to_string(), field_ops_registered);
        }

        let poly_ops_registered = reg
            .poly_ops_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !poly_ops_registered.is_empty() {
            if let Some(best) = reg.best_poly_ops() {
                active.insert("poly_ops".to_string(), best.name().to_string());
            }
            registered.insert("poly_ops".to_string(), poly_ops_registered);
        }

        let fri_registered = reg
            .fri_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !fri_registered.is_empty() {
            if let Some(best) = reg.best_fri() {
                active.insert("fri".to_string(), best.name().to_string());
            }
            registered.insert("fri".to_string(), fri_registered);
        }

        let constraint_eval_registered = reg
            .constraint_eval_accelerators()
            .iter()
            .map(|acc| acc.name().to_string())
            .collect::<Vec<_>>();
        if !constraint_eval_registered.is_empty() {
            if let Some(best) = reg.best_constraint_eval() {
                active.insert("constraint_eval".to_string(), best.name().to_string());
            }
            registered.insert("constraint_eval".to_string(), constraint_eval_registered);
        }

        (active, registered)
    };

    let mut cpu_fallback_reasons = BTreeMap::new();
    for (stage, active) in &active_accelerators {
        if !active.starts_with("metal-") {
            cpu_fallback_reasons.insert(
                stage.clone(),
                runtime_fallback_reason(stage, &registered_accelerators),
            );
        }
    }
    for stage in [
        "hash",
        "poseidon2",
        "field_ops",
        "poly_ops",
        "fri",
        "constraint_eval",
    ] {
        if !active_accelerators.contains_key(stage) {
            cpu_fallback_reasons.insert(
                stage.to_string(),
                runtime_fallback_reason(stage, &registered_accelerators),
            );
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        let metal_disabled_by_env = zkf_metal::is_disabled_by_env();
        let metal_device = zkf_metal::global_context().map(|ctx| ctx.device_name());
        let thresholds = zkf_metal::current_thresholds();
        let throughput = *zkf_metal::current_throughput_config();
        let threshold_summary = Some(format!(
            "msm={}, ntt={}, poseidon2={}, field_ops={}, merkle={}",
            thresholds.msm,
            thresholds.ntt,
            thresholds.poseidon2,
            thresholds.field_ops,
            thresholds.merkle
        ));
        let (
            recommended_working_set_size_bytes,
            current_allocated_size_bytes,
            working_set_headroom_bytes,
            working_set_utilization_pct,
            metal_dispatch_circuit_open,
            metal_dispatch_last_failure,
        ) = if let Some(ctx) = zkf_metal::global_context() {
            (
                ctx.recommended_working_set_size(),
                Some(ctx.current_allocated_size()),
                ctx.working_set_headroom(),
                ctx.working_set_utilization_ratio()
                    .map(|ratio| ratio * 100.0),
                !ctx.dispatch_allowed(),
                ctx.last_dispatch_failure(),
            )
        } else {
            (None, None, None, None, false, None)
        };

        MetalRuntimeReport {
            metal_compiled: true,
            metal_available: zkf_metal::is_available(),
            metal_disabled_by_env,
            metal_device,
            metallib_mode: zkf_metal::metallib_mode().map(str::to_string),
            threshold_profile: Some(zkf_metal::current_threshold_profile_name().to_string()),
            threshold_summary,
            recommended_working_set_size_bytes,
            current_allocated_size_bytes,
            working_set_headroom_bytes,
            working_set_utilization_pct,
            metal_dispatch_circuit_open,
            metal_dispatch_last_failure,
            prewarmed_pipelines: zkf_metal::prewarm_default_pipelines(),
            metal_primary_queue_depth: throughput.primary_queue_depth,
            metal_secondary_queue_depth: throughput.secondary_queue_depth,
            metal_pipeline_max_in_flight: throughput.pipeline_max_in_flight,
            metal_scheduler_max_jobs: throughput.batch_profile_cap,
            metal_working_set_headroom_target_pct: throughput.working_set_headroom_target_pct,
            metal_gpu_busy_ratio: 0.0,
            metal_stage_breakdown: "{}".to_string(),
            metal_inflight_jobs: 0,
            metal_no_cpu_fallback: false,
            metal_counter_source: "runtime-support-only".to_string(),
            active_accelerators,
            registered_accelerators,
            cpu_fallback_reasons,
        }
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        MetalRuntimeReport {
            metal_compiled: false,
            metal_available: false,
            metal_disabled_by_env: false,
            metal_device: None,
            metallib_mode: None,
            threshold_profile: None,
            threshold_summary: None,
            recommended_working_set_size_bytes: None,
            current_allocated_size_bytes: None,
            working_set_headroom_bytes: None,
            working_set_utilization_pct: None,
            metal_dispatch_circuit_open: false,
            metal_dispatch_last_failure: None,
            prewarmed_pipelines: 0,
            metal_primary_queue_depth: 0,
            metal_secondary_queue_depth: 0,
            metal_pipeline_max_in_flight: 0,
            metal_scheduler_max_jobs: 0,
            metal_working_set_headroom_target_pct: 0,
            metal_gpu_busy_ratio: 0.0,
            metal_stage_breakdown: "{}".to_string(),
            metal_inflight_jobs: 0,
            metal_no_cpu_fallback: false,
            metal_counter_source: "not-compiled".to_string(),
            active_accelerators,
            registered_accelerators,
            cpu_fallback_reasons,
        }
    }
}

pub fn append_backend_runtime_metadata(
    metadata: &mut BTreeMap<String, String>,
    backend: BackendKind,
) {
    append_backend_runtime_metadata_for_field(metadata, backend, None);
}

pub fn append_trust_metadata(
    metadata: &mut BTreeMap<String, String>,
    support_class: &str,
    trust_model: &str,
    trust_tier: u8,
) {
    metadata.insert("support_class".to_string(), support_class.to_string());
    metadata.insert("trust_model".to_string(), trust_model.to_string());
    metadata.insert("trust_tier".to_string(), trust_tier.to_string());
}

pub fn append_backend_runtime_metadata_for_field(
    metadata: &mut BTreeMap<String, String>,
    backend: BackendKind,
    field: Option<FieldId>,
) {
    let runtime = metal_runtime_report();
    let gpu_stage_coverage = gpu_stage_coverage_from_runtime(backend, field, &runtime);
    let metal_complete = metal_complete_for_backend_runtime(backend, &gpu_stage_coverage);
    let cpu_math_fallback_reason =
        cpu_math_fallback_reason_for_backend_runtime(backend, field, &gpu_stage_coverage);
    append_default_metal_telemetry(metadata);
    metadata.insert(
        "proof_engine".to_string(),
        proof_engine_for_backend(backend).to_string(),
    );
    metadata.insert(
        "proof_semantics".to_string(),
        proof_semantics_for_backend(backend).to_string(),
    );
    metadata.insert(
        "lookup_semantics".to_string(),
        lookup_semantics_for_backend(backend).to_string(),
    );
    metadata.insert(
        "assurance_lane".to_string(),
        assurance_lane_for_backend(backend).to_string(),
    );
    metadata.insert(
        "native_lookup_support".to_string(),
        native_lookup_support_for_backend(backend).to_string(),
    );
    metadata.insert(
        "lookup_lowering_support".to_string(),
        lookup_lowering_support_for_backend(backend).to_string(),
    );
    metadata.insert(
        "aggregation_semantics".to_string(),
        aggregation_semantics_for_backend(backend).to_string(),
    );
    metadata.insert(
        "blackbox_semantics".to_string(),
        blackbox_semantics_for_backend(backend).to_string(),
    );
    metadata.insert(
        "prover_acceleration_scope".to_string(),
        prover_acceleration_scope_for_backend(backend).to_string(),
    );
    metadata.insert(
        "prover_acceleration_claimed".to_string(),
        prover_acceleration_claimed_for_backend(backend).to_string(),
    );
    metadata.insert(
        "gpu_stage_coverage".to_string(),
        serde_json::to_string(&gpu_stage_coverage).unwrap_or_else(|_| {
            "{\"coverage_ratio\":0.0,\"required_stages\":[],\"metal_stages\":[],\"cpu_stages\":[]}"
                .to_string()
        }),
    );
    metadata.insert("metal_complete".to_string(), metal_complete.to_string());
    if let Some(reason) = &cpu_math_fallback_reason {
        metadata.insert("cpu_math_fallback_reason".to_string(), reason.clone());
    }
    if let Some(export_scheme) = export_scheme_for_backend(backend) {
        metadata.insert("export_scheme".to_string(), export_scheme.to_string());
    }
    metadata.insert(
        "metal_compiled".to_string(),
        runtime.metal_compiled.to_string(),
    );
    metadata.insert(
        "metal_available".to_string(),
        runtime.metal_available.to_string(),
    );
    metadata.insert(
        "metal_disabled_by_env".to_string(),
        runtime.metal_disabled_by_env.to_string(),
    );
    metadata.insert(
        "metal_prewarmed_pipelines".to_string(),
        runtime.prewarmed_pipelines.to_string(),
    );
    metadata.insert(
        "metal_primary_queue_depth".to_string(),
        runtime.metal_primary_queue_depth.to_string(),
    );
    metadata.insert(
        "metal_secondary_queue_depth".to_string(),
        runtime.metal_secondary_queue_depth.to_string(),
    );
    metadata.insert(
        "metal_pipeline_max_in_flight".to_string(),
        runtime.metal_pipeline_max_in_flight.to_string(),
    );
    metadata.insert(
        "metal_scheduler_max_jobs".to_string(),
        runtime.metal_scheduler_max_jobs.to_string(),
    );
    metadata.insert(
        "metal_working_set_headroom_target_pct".to_string(),
        runtime.metal_working_set_headroom_target_pct.to_string(),
    );
    metadata
        .entry("metal_gpu_busy_ratio".to_string())
        .or_insert_with(|| runtime.metal_gpu_busy_ratio.to_string());
    metadata
        .entry("metal_stage_breakdown".to_string())
        .or_insert_with(|| runtime.metal_stage_breakdown.clone());
    metadata
        .entry("metal_inflight_jobs".to_string())
        .or_insert_with(|| runtime.metal_inflight_jobs.to_string());
    metadata
        .entry("metal_no_cpu_fallback".to_string())
        .or_insert_with(|| runtime.metal_no_cpu_fallback.to_string());
    metadata
        .entry("metal_counter_source".to_string())
        .or_insert_with(|| runtime.metal_counter_source.clone());

    if let Some(device) = &runtime.metal_device {
        metadata.insert("metal_device".to_string(), device.clone());
    }
    if let Some(mode) = &runtime.metallib_mode {
        metadata.insert("metal_metallib_mode".to_string(), mode.clone());
    }
    if let Some(profile) = &runtime.threshold_profile {
        metadata.insert("metal_threshold_profile".to_string(), profile.clone());
    }
    if let Some(summary) = &runtime.threshold_summary {
        metadata.insert("metal_thresholds".to_string(), summary.clone());
    }
    if let Some(bytes) = runtime.recommended_working_set_size_bytes {
        metadata.insert(
            "metal_recommended_working_set_size_bytes".to_string(),
            bytes.to_string(),
        );
    }
    if let Some(bytes) = runtime.current_allocated_size_bytes {
        metadata.insert(
            "metal_current_allocated_size_bytes".to_string(),
            bytes.to_string(),
        );
    }
    if let Some(bytes) = runtime.working_set_headroom_bytes {
        metadata.insert(
            "metal_working_set_headroom_bytes".to_string(),
            bytes.to_string(),
        );
    }
    if let Some(utilization_pct) = runtime.working_set_utilization_pct {
        metadata.insert(
            "metal_working_set_utilization_pct".to_string(),
            format!("{utilization_pct:.2}"),
        );
    }
    metadata
        .entry("metal_dispatch_circuit_open".to_string())
        .or_insert_with(|| runtime.metal_dispatch_circuit_open.to_string());
    if let Some(reason) = &runtime.metal_dispatch_last_failure {
        metadata
            .entry("metal_dispatch_last_failure".to_string())
            .or_insert_with(|| reason.clone());
    }
    if !runtime.active_accelerators.is_empty() {
        metadata.insert(
            "metal_active_accelerators".to_string(),
            serde_json::to_string(&runtime.active_accelerators)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        for (stage, accelerator) in &runtime.active_accelerators {
            metadata.insert(format!("best_{stage}_accelerator"), accelerator.clone());
        }
    }
    if !runtime.cpu_fallback_reasons.is_empty() {
        metadata.insert(
            "metal_cpu_fallback_reasons".to_string(),
            serde_json::to_string(&runtime.cpu_fallback_reasons)
                .unwrap_or_else(|_| "{}".to_string()),
        );
    }
}

pub fn capabilities_report() -> Vec<CapabilityReport> {
    let runtime = metal_runtime_report();
    crate::capabilities_matrix()
        .into_iter()
        .map(|capabilities| capability_report_with_runtime(capabilities, &runtime))
        .collect()
}

pub(crate) fn capability_report_with_runtime(
    capabilities: BackendCapabilities,
    runtime: &MetalRuntimeReport,
) -> CapabilityReport {
    let coverage = gpu_stage_coverage_from_runtime(capabilities.backend, None, runtime);
    let readiness = backend_readiness(capabilities.backend, runtime);
    CapabilityReport {
        supported_fields: supported_fields(capabilities.backend),
        implementation_type: readiness.implementation_type,
        compiled_in: readiness.compiled_in,
        toolchain_ready: readiness.toolchain_ready,
        runtime_ready: readiness.runtime_ready,
        production_ready: readiness.production_ready,
        readiness: readiness.readiness.to_string(),
        readiness_reason: readiness.readiness_reason,
        operator_action: readiness.operator_action,
        explicit_compat_alias: readiness.explicit_compat_alias,
        native_lookup_support: native_lookup_support_for_backend(capabilities.backend),
        lookup_lowering_support: lookup_lowering_support_for_backend(capabilities.backend),
        lookup_semantics: lookup_semantics_for_backend(capabilities.backend).to_string(),
        assurance_lane: assurance_lane_for_backend(capabilities.backend).to_string(),
        aggregation_semantics: aggregation_semantics_for_backend(capabilities.backend).to_string(),
        proof_engine: proof_engine_for_backend(capabilities.backend).to_string(),
        proof_semantics: proof_semantics_for_backend(capabilities.backend).to_string(),
        blackbox_semantics: blackbox_semantics_for_backend(capabilities.backend).to_string(),
        prover_acceleration_scope: prover_acceleration_scope_for_backend(capabilities.backend)
            .to_string(),
        metal_complete: metal_complete_for_backend_runtime(capabilities.backend, &coverage),
        cpu_math_fallback_reason: cpu_math_fallback_reason_for_backend_runtime(
            capabilities.backend,
            None,
            &coverage,
        ),
        export_scheme: export_scheme_for_backend(capabilities.backend).map(str::to_string),
        gpu_stage_coverage: coverage,
        capabilities,
    }
}

pub fn backend_capability_matrix() -> BackendCapabilityMatrix {
    let reports = capabilities_report();
    BackendCapabilityMatrix {
        schema_version: 3,
        audit_date: "dynamic".to_string(),
        entries: reports
            .into_iter()
            .map(|report| BackendCapabilityEntry {
                backend: report.capabilities.backend,
                support_class: report.implementation_type,
                delegates_to: delegated_backend(report.capabilities.backend),
                supported_fields: supported_fields(report.capabilities.backend),
                max_range_bits: max_range_bits(report.capabilities.backend),
                gpu_acceleration: zkf_core::GpuAcceleration {
                    claimed: prover_acceleration_claimed_for_backend(report.capabilities.backend),
                    actual: report.gpu_stage_coverage.coverage_ratio > 0.0,
                    stages: report.gpu_stage_coverage.metal_stages.clone(),
                },
                accepts_canonical_ir: accepts_canonical_ir(report.capabilities.backend),
                trusted_setup_required: report.capabilities.trusted_setup,
                recursion_ready: report.capabilities.recursion_ready,
                solidity_export: matches!(
                    report.capabilities.backend,
                    BackendKind::ArkworksGroth16 | BackendKind::Sp1
                ),
                proof_size_estimate: proof_size_estimate(report.capabilities.backend).to_string(),
                supported_constraint_kinds: report.capabilities.supported_constraint_kinds.clone(),
                supported_blackbox_ops: report.capabilities.supported_blackbox_ops.clone(),
                implementation_type: Some(report.implementation_type),
                compiled_in: Some(report.compiled_in),
                toolchain_ready: Some(report.toolchain_ready),
                runtime_ready: Some(report.runtime_ready),
                production_ready: Some(report.production_ready),
                readiness: Some(report.readiness.clone()),
                readiness_reason: report.readiness_reason.clone(),
                operator_action: report.operator_action.clone(),
                explicit_compat_alias: report.explicit_compat_alias.clone(),
                native_lookup_support: Some(report.native_lookup_support),
                lookup_lowering_support: Some(report.lookup_lowering_support),
                lookup_semantics: Some(report.lookup_semantics.clone()),
                aggregation_semantics: Some(report.aggregation_semantics.clone()),
                notes: capability_notes(&report),
            })
            .collect(),
    }
}

pub fn capability_notes(report: &CapabilityReport) -> String {
    let mut notes = vec![report.capabilities.notes.clone()];
    notes.push(format!(
        "implementation_type={}",
        report.implementation_type
    ));
    notes.push(format!("compiled_in={}", report.compiled_in));
    notes.push(format!("production_ready={}", report.production_ready));
    notes.push(format!("assurance_lane={}", report.assurance_lane));
    notes.push(format!("proof_semantics={}", report.proof_semantics));
    notes.push(format!(
        "aggregation_semantics={}",
        report.aggregation_semantics
    ));
    if let Some(alias) = &report.explicit_compat_alias {
        notes.push(format!("explicit_compat_alias={alias}"));
    }
    if let Some(reason) = &report.readiness_reason {
        notes.push(format!("readiness_reason={reason}"));
    }
    if let Some(action) = &report.operator_action {
        notes.push(format!("operator_action={action}"));
    }
    notes.join(" ")
}

pub fn proof_engine_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Plonky3 => "metal-first-stark",
        BackendKind::ArkworksGroth16 => "groth16-compatibility",
        BackendKind::Halo2 => "halo2-ipa",
        BackendKind::Halo2Bls12381 => "halo2-kzg",
        BackendKind::Nova | BackendKind::HyperNova => "recursive-folding",
        BackendKind::Sp1 => "zkvm-attestation",
        BackendKind::RiscZero => "zkvm-attestation",
        BackendKind::MidnightCompact => "external-compact-delegate",
    }
}

pub fn export_scheme_for_backend(kind: BackendKind) -> Option<&'static str> {
    match kind {
        BackendKind::Plonky3 => Some("optional-groth16-wrapper"),
        BackendKind::ArkworksGroth16 => Some("groth16"),
        _ => None,
    }
}

pub fn gpu_stage_coverage_for_backend(kind: BackendKind) -> GpuStageCoverage {
    gpu_stage_coverage_from_runtime(kind, None, &metal_runtime_report())
}

pub fn gpu_stage_coverage_for_backend_field(
    kind: BackendKind,
    field: Option<FieldId>,
) -> GpuStageCoverage {
    gpu_stage_coverage_from_runtime(kind, field, &metal_runtime_report())
}

pub fn metal_complete_for_backend(kind: BackendKind) -> bool {
    let coverage = gpu_stage_coverage_for_backend(kind);
    metal_complete_for_backend_runtime(kind, &coverage)
}

pub fn cpu_math_fallback_reason_for_backend(kind: BackendKind) -> Option<String> {
    let coverage = gpu_stage_coverage_for_backend(kind);
    cpu_math_fallback_reason_for_backend_runtime(kind, None, &coverage)
}

fn gpu_stage_coverage_from_runtime(
    kind: BackendKind,
    field: Option<FieldId>,
    runtime: &MetalRuntimeReport,
) -> GpuStageCoverage {
    let required = required_gpu_stages(kind, field);
    let required_stages = required
        .iter()
        .map(|stage| stage.as_str().to_string())
        .collect::<Vec<_>>();
    let mut metal_stages = Vec::new();
    let mut cpu_stages = Vec::new();

    for stage in required {
        if stage_is_gpu_backed(stage, kind, field, runtime) {
            metal_stages.push(stage.as_str().to_string());
        } else {
            cpu_stages.push(stage.as_str().to_string());
        }
    }

    let coverage_ratio = if required_stages.is_empty() {
        0.0
    } else {
        metal_stages.len() as f64 / required_stages.len() as f64
    };

    GpuStageCoverage {
        coverage_ratio,
        required_stages,
        metal_stages,
        cpu_stages,
    }
}

fn backend_readiness(kind: BackendKind, runtime: &MetalRuntimeReport) -> BackendReadiness {
    let surface = crate::backend_surface_status(kind);
    let explicit_compat_alias = match kind {
        BackendKind::Sp1 => Some("sp1-compat".to_string()),
        BackendKind::RiscZero => Some("risc-zero-compat".to_string()),
        _ => None,
    };

    if !surface.compiled_in {
        return BackendReadiness {
            implementation_type: surface.implementation_type,
            compiled_in: false,
            toolchain_ready: false,
            runtime_ready: false,
            production_ready: false,
            readiness: "blocked",
            readiness_reason: Some("native-backend-not-compiled".to_string()),
            operator_action: explicit_compat_alias
                .as_ref()
                .map(|alias| format!("build a binary with the native feature enabled or request `{alias}` with --allow-compat")),
            explicit_compat_alias,
        };
    }

    let toolchain_status = backend_toolchain_status(kind);
    let runtime_status = backend_runtime_status(kind);
    let toolchain_ready = toolchain_status.is_none();
    let runtime_ready = toolchain_ready
        && match kind {
            BackendKind::ArkworksGroth16 => {
                let _ = runtime;
                true
            }
            _ => runtime_status.is_none(),
        };
    let base_readiness_reason = toolchain_status
        .as_ref()
        .map(|(reason, _)| reason.clone())
        .or_else(|| runtime_status.as_ref().map(|(reason, _)| reason.clone()));
    let base_operator_action = toolchain_status
        .map(|(_, action)| action)
        .or_else(|| runtime_status.map(|(_, action)| action));
    let production_ready = runtime_ready && kind != BackendKind::ArkworksGroth16;
    let (readiness, readiness_reason, operator_action) = if kind == BackendKind::ArkworksGroth16
        && runtime_ready
    {
        (
            "limited",
            Some(ARKWORKS_PRODUCTION_DISCLAIMER_REASON.to_string()),
            Some(
                "treat arkworks-groth16 as non-production until the upstream production disclaimer is resolved or the dependency is replaced"
                    .to_string(),
            ),
        )
    } else {
        (
            if runtime_ready { "ready" } else { "blocked" },
            base_readiness_reason,
            base_operator_action,
        )
    };

    BackendReadiness {
        implementation_type: surface.implementation_type,
        compiled_in: true,
        toolchain_ready,
        runtime_ready,
        production_ready,
        readiness,
        readiness_reason,
        operator_action,
        explicit_compat_alias,
    }
}

fn backend_runtime_status(kind: BackendKind) -> Option<(String, String)> {
    match kind {
        BackendKind::MidnightCompact => midnight_runtime_status(),
        _ => None,
    }
}

fn midnight_runtime_status() -> Option<(String, String)> {
    let prove_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL").ok();
    let verify_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL").ok();
    let allow_delegate = std::env::var("ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    let action =
        "configure real http(s) ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL and ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL endpoints and ensure GET /health succeeds".to_string();

    let Some(prove_url) = prove_url else {
        return Some((
            if allow_delegate {
                "midnight-proof-server-delegate-only".to_string()
            } else {
                "midnight-proof-server-unconfigured".to_string()
            },
            action,
        ));
    };
    let Some(verify_url) = verify_url else {
        return Some((
            if allow_delegate {
                "midnight-proof-server-delegate-only".to_string()
            } else {
                "midnight-proof-server-unconfigured".to_string()
            },
            action,
        ));
    };

    if is_mock_midnight_url(&prove_url) || is_mock_midnight_url(&verify_url) {
        return Some(("midnight-proof-server-mock-only".to_string(), action));
    }

    if !is_http_midnight_url(&prove_url) || !is_http_midnight_url(&verify_url) {
        return Some(("midnight-proof-server-invalid-url".to_string(), action));
    }

    let client = MidnightClient::new(prove_url, verify_url)
        .with_timeout(1_500)
        .with_max_retries(0);
    match client.health_check() {
        Ok(true) => None,
        Ok(false) => Some(("midnight-proof-server-unhealthy".to_string(), action)),
        Err(_) => Some(("midnight-proof-server-unhealthy".to_string(), action)),
    }
}

fn is_http_midnight_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn is_mock_midnight_url(url: &str) -> bool {
    url.starts_with("mock://")
}

fn backend_toolchain_status(kind: BackendKind) -> Option<(String, String)> {
    #[cfg(test)]
    note_backend_toolchain_status_probe(kind);

    match kind {
        BackendKind::Sp1 => {
            if !command_available("cargo", &["--version"]) {
                return Some((
                    "cargo-missing".to_string(),
                    "install Rust and ensure `cargo` is on PATH".to_string(),
                ));
            }
            if !command_available("cargo", &["+succinct", "--version"]) {
                return Some((
                    "sp1-toolchain-missing".to_string(),
                    "install the SP1 toolchain via `sp1up`".to_string(),
                ));
            }
            if !toolchain_supports_target("succinct", "riscv32im-succinct-zkvm-elf") {
                return Some((
                    "sp1-guest-target-missing".to_string(),
                    "install or refresh the SP1 toolchain via `sp1up` so `rustc +succinct` supports `riscv32im-succinct-zkvm-elf`".to_string(),
                ));
            }
            None
        }
        BackendKind::RiscZero => {
            if !command_available("cargo", &["--version"]) {
                return Some((
                    "cargo-missing".to_string(),
                    "install Rust and ensure `cargo` is on PATH".to_string(),
                ));
            }
            if !command_available("cargo", &["+risc0", "--version"]) {
                return Some((
                    "risc0-toolchain-missing".to_string(),
                    "install the RISC Zero toolchain via `rzup install rust`".to_string(),
                ));
            }
            if !toolchain_supports_target("risc0", "riscv32im-risc0-zkvm-elf") {
                return Some((
                    "risc0-guest-target-missing".to_string(),
                    "install or refresh the RISC Zero toolchain via `rzup install rust` so `rustc +risc0` supports `riscv32im-risc0-zkvm-elf`".to_string(),
                ));
            }
            None
        }
        _ => None,
    }
}

fn command_available(tool: &str, args: &[&str]) -> bool {
    let cache_key = format!("{tool}\u{1f}{args:?}");
    if let Ok(mut cache) = COMMAND_AVAILABLE_CACHE.lock()
        && let Some(cached) = cache.get_cloned(&cache_key)
    {
        return cached;
    }

    let available = std::process::Command::new(tool)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if let Ok(mut cache) = COMMAND_AVAILABLE_CACHE.lock() {
        cache.insert(cache_key, available);
    }
    available
}

fn toolchain_supports_target(toolchain: &str, target: &str) -> bool {
    let cache_key = format!("{toolchain}\u{1f}{target}");
    if let Ok(mut cache) = TOOLCHAIN_TARGET_CACHE.lock()
        && let Some(cached) = cache.get_cloned(&cache_key)
    {
        return cached;
    }

    let supported = std::process::Command::new("rustc")
        .args([&format!("+{toolchain}"), "--print", "target-list"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == target)
        })
        .unwrap_or(false);

    if let Ok(mut cache) = TOOLCHAIN_TARGET_CACHE.lock() {
        cache.insert(cache_key, supported);
    }
    supported
}

fn delegated_backend(kind: BackendKind) -> Option<BackendKind> {
    match kind {
        BackendKind::Sp1 if !cfg!(feature = "native-sp1") => Some(BackendKind::Plonky3),
        BackendKind::RiscZero if !cfg!(feature = "native-risc-zero") => Some(BackendKind::Plonky3),
        BackendKind::Nova if !cfg!(feature = "native-nova") => Some(BackendKind::ArkworksGroth16),
        BackendKind::HyperNova if !cfg!(feature = "native-nova") => Some(BackendKind::Nova),
        _ => None,
    }
}

fn supported_fields(kind: BackendKind) -> Vec<FieldId> {
    match kind {
        BackendKind::ArkworksGroth16 | BackendKind::Nova | BackendKind::HyperNova => {
            vec![FieldId::Bn254]
        }
        BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => {
            vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
        }
        BackendKind::Halo2 => vec![FieldId::PastaFp],
        BackendKind::Halo2Bls12381 => vec![FieldId::Bls12_381],
        BackendKind::MidnightCompact => vec![FieldId::PastaFp, FieldId::PastaFq],
    }
}

fn max_range_bits(kind: BackendKind) -> Option<u32> {
    let _ = kind;
    None
}

fn accepts_canonical_ir(kind: BackendKind) -> bool {
    !matches!(kind, BackendKind::MidnightCompact)
}

fn proof_size_estimate(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16 => "~128 bytes",
        BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => "~13.5 KB",
        BackendKind::Halo2 => "~3 KB",
        BackendKind::Halo2Bls12381 => "~3 KB",
        BackendKind::Nova => "~1.77 MB",
        BackendKind::HyperNova => "~1.05 MB",
        BackendKind::MidnightCompact => "Variable",
    }
}

fn required_gpu_stages(kind: BackendKind, field: Option<FieldId>) -> Vec<GpuStage> {
    match kind {
        BackendKind::Plonky3 => match field {
            Some(FieldId::Goldilocks) | Some(FieldId::BabyBear) | None => {
                vec![GpuStage::FftNtt, GpuStage::HashMerkle]
            }
            Some(FieldId::Mersenne31) => Vec::new(),
            Some(_) => Vec::new(),
        },
        BackendKind::ArkworksGroth16 => {
            vec![GpuStage::FftNtt, GpuStage::QapWitnessMap, GpuStage::Msm]
        }
        BackendKind::Halo2 => vec![GpuStage::FftNtt, GpuStage::Msm],
        BackendKind::Halo2Bls12381 => vec![GpuStage::FftNtt, GpuStage::Msm],
        BackendKind::Nova | BackendKind::HyperNova => vec![GpuStage::Msm],
        BackendKind::Sp1 | BackendKind::RiscZero | BackendKind::MidnightCompact => Vec::new(),
    }
}

fn stage_is_gpu_backed(
    stage: GpuStage,
    kind: BackendKind,
    field: Option<FieldId>,
    runtime: &MetalRuntimeReport,
) -> bool {
    let plonky3_field_is_metal = !matches!(field, Some(FieldId::Mersenne31));
    let groth16_strict_ready =
        matches!(field, Some(FieldId::Bn254) | None) && runtime_is_certified_m4_max(runtime);
    match (kind, stage) {
        (BackendKind::Plonky3, GpuStage::FftNtt) => {
            plonky3_field_is_metal && active_stage_is_metal(runtime, "ntt")
        }
        (BackendKind::Plonky3, GpuStage::HashMerkle) => {
            plonky3_field_is_metal
                && active_stage_is_metal(runtime, "hash")
                && active_stage_is_metal(runtime, "poseidon2")
        }
        (BackendKind::ArkworksGroth16, GpuStage::FftNtt)
        | (BackendKind::ArkworksGroth16, GpuStage::QapWitnessMap) => {
            groth16_strict_ready && active_stage_is_metal(runtime, "ntt")
        }
        (BackendKind::ArkworksGroth16, GpuStage::Msm) => {
            groth16_strict_ready && active_stage_is_metal(runtime, "msm")
        }
        (BackendKind::Halo2, GpuStage::Msm) => active_stage_is_metal(runtime, "msm"),
        (BackendKind::Halo2 | BackendKind::Halo2Bls12381, GpuStage::FftNtt) => false,
        (BackendKind::Halo2Bls12381, GpuStage::Msm) => false,
        _ => false,
    }
}

fn active_stage_is_metal(runtime: &MetalRuntimeReport, stage: &str) -> bool {
    runtime
        .active_accelerators
        .get(stage)
        .is_some_and(|name| name.starts_with("metal-"))
}

fn metal_complete_for_backend_runtime(kind: BackendKind, coverage: &GpuStageCoverage) -> bool {
    prover_acceleration_claimed_for_backend(kind)
        && !coverage.required_stages.is_empty()
        && coverage.cpu_stages.is_empty()
}

fn cpu_math_fallback_reason_for_backend_runtime(
    kind: BackendKind,
    field: Option<FieldId>,
    coverage: &GpuStageCoverage,
) -> Option<String> {
    if !prover_acceleration_claimed_for_backend(kind) {
        return Some("not-claimed-for-this-backend".to_string());
    }
    if coverage.cpu_stages.is_empty() {
        return None;
    }

    match (kind, field) {
        (BackendKind::Plonky3, Some(FieldId::Mersenne31)) => {
            Some("mersenne31-circle-path-remains-cpu-classified".to_string())
        }
        (BackendKind::Plonky3, _) => Some(
            "plonky3-metal-complete-requires-goldilocks-or-babybear-with-metal-ntt-and-mmcs"
                .to_string(),
        ),
        (BackendKind::ArkworksGroth16, Some(FieldId::Bn254) | None) => Some(format!(
            "certified-bn254-strict-route-requires-apple-silicon-m4-max-48gb-with-active-metal-ntt-and-metal-msm (cpu stages: {})",
            coverage.cpu_stages.join(",")
        )),
        (BackendKind::Halo2, _) => Some(format!(
            "halo2-pasta-msm-is-metal-accelerated-on-macos-but-fft-ntt-remains-cpu-classified (cpu stages: {})",
            coverage.cpu_stages.join(",")
        )),
        (BackendKind::Halo2Bls12381, _) => {
            Some("halo2-bls12-381-msm-and-fft-hot-paths-remain-cpu-classified".to_string())
        }
        (BackendKind::Nova | BackendKind::HyperNova, _) => {
            Some("nova-provider-msm-hot-path-is-not-patched-to-metal".to_string())
        }
        _ => Some(format!("cpu-only-stages:{}", coverage.cpu_stages.join(","))),
    }
}

pub fn proof_semantics_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16 => "proof-enforced-basic-ir",
        BackendKind::Halo2 | BackendKind::Halo2Bls12381 => "proof-enforced-basic-ir",
        BackendKind::Plonky3 => "proof-enforced-lowered-ir",
        BackendKind::Nova | BackendKind::HyperNova => "proof-enforced-basic-ir-recursive-shell",
        BackendKind::Sp1 | BackendKind::RiscZero => "attestation-over-host-validation",
        BackendKind::MidnightCompact => "external-or-delegated",
    }
}

pub fn assurance_lane_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Plonky3
        | BackendKind::Nova
        | BackendKind::HyperNova => "native-cryptographic-proof",
        BackendKind::Sp1 | BackendKind::RiscZero => "attestation-backed-host-validated-lane",
        BackendKind::MidnightCompact => "delegated-or-external-lane",
    }
}

pub fn native_lookup_support_for_backend(kind: BackendKind) -> bool {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Plonky3
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Nova
        | BackendKind::HyperNova
        | BackendKind::Sp1
        | BackendKind::RiscZero
        | BackendKind::MidnightCompact => false,
    }
}

pub fn lookup_lowering_support_for_backend(kind: BackendKind) -> bool {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Plonky3
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Nova
        | BackendKind::HyperNova => true,
        BackendKind::Sp1 | BackendKind::RiscZero | BackendKind::MidnightCompact => false,
    }
}

pub fn lookup_semantics_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Plonky3
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Nova
        | BackendKind::HyperNova => "arithmetic-lowering-required",
        BackendKind::Sp1 | BackendKind::RiscZero | BackendKind::MidnightCompact => {
            "not-supported-on-ir-constraints"
        }
    }
}

pub fn aggregation_semantics_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Nova => "cryptographic-recursive-folding",
        BackendKind::HyperNova => {
            if cfg!(feature = "native-nova") {
                "cryptographic-recursive-multifolding"
            } else {
                "compat-delegated-surface"
            }
        }
        BackendKind::Sp1 | BackendKind::RiscZero => "zkvm-attestation",
        BackendKind::Plonky3 => "single-proof-with-optional-wrapper",
        BackendKind::ArkworksGroth16
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::MidnightCompact => "single-proof-only",
    }
}

pub fn blackbox_semantics_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Plonky3
        | BackendKind::Nova
        | BackendKind::HyperNova => "host-validated-blackbox",
        BackendKind::Sp1 | BackendKind::RiscZero => "host-validated-before-attestation",
        BackendKind::MidnightCompact => "external-or-host-validated",
    }
}

pub fn prover_acceleration_scope_for_backend(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::ArkworksGroth16
        | BackendKind::Halo2
        | BackendKind::Halo2Bls12381
        | BackendKind::Plonky3
        | BackendKind::Nova
        | BackendKind::HyperNova => "proof-enforced-prover-stages",
        BackendKind::Sp1 | BackendKind::RiscZero => "not-claimed-host-validation",
        BackendKind::MidnightCompact => "not-claimed-external-or-delegated",
    }
}

pub fn prover_acceleration_claimed_for_backend(kind: BackendKind) -> bool {
    !prover_acceleration_scope_for_backend(kind).starts_with("not-claimed")
}

pub fn recommend_gpu_jobs(
    backends: &[BackendKind],
    constraints: usize,
    signals: usize,
    requested_jobs: Option<usize>,
    total_jobs: usize,
) -> GpuSchedulerDecision {
    let estimated_job_bytes = estimate_job_bytes(backends, constraints, signals);

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        let hint = zkf_metal::recommend_job_count(total_jobs, requested_jobs, estimated_job_bytes);
        GpuSchedulerDecision {
            requested_jobs: hint.requested_jobs,
            total_jobs: hint.total_jobs,
            recommended_jobs: hint.recommended_jobs,
            estimated_job_bytes: hint.estimated_job_bytes,
            memory_budget_bytes: hint.memory_budget_bytes,
            metal_available: hint.metal_available,
            metal_device: hint.device_name,
            reason: hint.reason,
        }
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        let cpu_cap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);
        let requested_jobs = requested_jobs.unwrap_or(cpu_cap).max(1);
        GpuSchedulerDecision {
            requested_jobs,
            total_jobs,
            recommended_jobs: requested_jobs.min(total_jobs).min(cpu_cap).max(1),
            estimated_job_bytes,
            memory_budget_bytes: None,
            metal_available: false,
            metal_device: None,
            reason: "Metal feature not compiled; using CPU worker cap".to_string(),
        }
    }
}

fn estimate_job_bytes(backends: &[BackendKind], constraints: usize, signals: usize) -> usize {
    let base_units = constraints
        .saturating_add(signals)
        .max(constraints.max(signals))
        .max(1);
    let kib_per_unit = backends
        .iter()
        .map(|backend| match backend {
            BackendKind::Plonky3 => 192usize,
            BackendKind::Halo2 | BackendKind::Halo2Bls12381 => 160usize,
            BackendKind::Nova | BackendKind::HyperNova => 128usize,
            BackendKind::ArkworksGroth16 => 96usize,
            BackendKind::Sp1 | BackendKind::RiscZero | BackendKind::MidnightCompact => 48usize,
        })
        .max()
        .unwrap_or(64);

    base_units.saturating_mul(kib_per_unit).saturating_mul(1024)
}

fn runtime_fallback_reason(
    stage: &str,
    registered_accelerators: &BTreeMap<String, Vec<String>>,
) -> String {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if zkf_metal::is_disabled_by_env() {
            return "metal-disabled-by-env".to_string();
        }
        if !zkf_metal::is_available() {
            return "metal-unavailable".to_string();
        }
        if registered_accelerators
            .get(stage)
            .map(|registered| registered.iter().any(|name| name.starts_with("metal-")))
            .unwrap_or(false)
        {
            return "metal-registered-but-not-selected".to_string();
        }
        "no-metal-accelerator-registered".to_string()
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        let _ = (stage, registered_accelerators);
        "metal-feature-disabled".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceleration_scope_is_not_claimed_for_attestation_backends() {
        assert_eq!(
            prover_acceleration_scope_for_backend(BackendKind::Sp1),
            "not-claimed-host-validation"
        );
        assert_eq!(
            prover_acceleration_scope_for_backend(BackendKind::RiscZero),
            "not-claimed-host-validation"
        );
        assert_eq!(
            prover_acceleration_scope_for_backend(BackendKind::MidnightCompact),
            "not-claimed-external-or-delegated"
        );
        assert!(!prover_acceleration_claimed_for_backend(BackendKind::Sp1));
    }

    #[test]
    fn capabilities_report_includes_semantic_scope() {
        let reports = capabilities_report();
        assert!(
            reports
                .iter()
                .all(|report| !report.prover_acceleration_scope.is_empty())
        );
        assert!(
            reports
                .iter()
                .all(|report| !report.assurance_lane.is_empty())
        );
        assert!(reports.iter().all(|report| !report.proof_engine.is_empty()));
        assert!(
            reports
                .iter()
                .all(|report| report.gpu_stage_coverage.coverage_ratio >= 0.0)
        );
        assert_eq!(
            reports
                .iter()
                .find(|report| report.capabilities.backend == BackendKind::Sp1)
                .map(|report| report.assurance_lane.as_str()),
            Some("attestation-backed-host-validated-lane")
        );
    }

    #[test]
    fn groth16_runtime_tracks_certified_strict_route() {
        let coverage = gpu_stage_coverage_for_backend(BackendKind::ArkworksGroth16);
        assert!(coverage.coverage_ratio >= 0.0);
        let reason = cpu_math_fallback_reason_for_backend(BackendKind::ArkworksGroth16);
        if strict_bn254_auto_route_ready() {
            assert!(metal_complete_for_backend_runtime(
                BackendKind::ArkworksGroth16,
                &coverage
            ));
            assert!(reason.is_none());
        } else {
            assert!(!metal_complete_for_backend_runtime(
                BackendKind::ArkworksGroth16,
                &coverage
            ));
            assert!(reason.is_some());
        }
    }

    #[test]
    fn plonky3_goldilocks_only_claims_wired_gpu_stages() {
        let coverage =
            gpu_stage_coverage_for_backend_field(BackendKind::Plonky3, Some(FieldId::Goldilocks));
        assert_eq!(coverage.required_stages, vec!["fft-ntt", "hash-merkle"]);
    }

    #[test]
    fn plonky3_mersenne31_is_not_claimed_metal_complete() {
        let coverage =
            gpu_stage_coverage_for_backend_field(BackendKind::Plonky3, Some(FieldId::Mersenne31));
        assert!(coverage.required_stages.is_empty());
        assert!(!metal_complete_for_backend_runtime(
            BackendKind::Plonky3,
            &coverage
        ));
    }

    #[test]
    fn single_backend_capability_lookup_skips_unrelated_toolchain_probes() {
        reset_backend_toolchain_status_probe_counts();

        let report = crate::capability_report_for_backend(BackendKind::ArkworksGroth16)
            .expect("arkworks capability report");

        assert_eq!(report.capabilities.backend, BackendKind::ArkworksGroth16);
        assert_eq!(backend_toolchain_status_probe_count(BackendKind::Sp1), 0);
        assert_eq!(
            backend_toolchain_status_probe_count(BackendKind::RiscZero),
            0
        );
    }

    #[test]
    fn arkworks_capability_report_marks_production_disclaimer_honestly() {
        let report = crate::capability_report_for_backend(BackendKind::ArkworksGroth16)
            .expect("arkworks capability report");

        assert!(report.runtime_ready);
        assert!(!report.production_ready);
        assert_eq!(report.readiness, "limited");
        assert_eq!(
            report.readiness_reason.as_deref(),
            Some(ARKWORKS_PRODUCTION_DISCLAIMER_REASON)
        );
    }
}
