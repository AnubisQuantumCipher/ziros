use crate::control_plane::{ControlPlaneExecutionSummary, ControlPlaneRequest, JobKind};
use crate::execution::ExecutionContext;
use crate::execution_core;
use crate::security::SecurityEvaluation;
use crate::telemetry::GraphExecutionReport;
use crate::trust::RequiredTrustLane;
use std::collections::VecDeque;
use zkf_backends::BackendRoute;
use zkf_core::FieldId;
use zkf_core::artifact::{BackendKind, CompiledProgram};
use zkf_core::ir::Program;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchSchedulerPlan {
    pub(crate) requested_jobs: usize,
    pub(crate) scheduled_jobs: usize,
    pub(crate) reason: String,
}

#[derive(Debug)]
pub(crate) struct ControlPlaneProjection<'a> {
    pub(crate) job_kind: JobKind,
    pub(crate) program: Option<&'a Program>,
    pub(crate) requested_backend: Option<BackendKind>,
    pub(crate) backend_route: Option<BackendRoute>,
    pub(crate) backend_candidates: Vec<BackendKind>,
}

pub(crate) fn default_requested_jobs() -> usize {
    std::env::var("ZKF_PROVING_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| {
            zkf_core::SystemResources::detect()
                .recommend()
                .proving_threads
        })
        .max(1)
}

pub(crate) fn default_backend_candidates(
    program: Option<&Program>,
    compiled: Option<&CompiledProgram>,
) -> Vec<BackendKind> {
    if let Some(compiled) = compiled {
        return vec![compiled.backend];
    }
    if let Some(program) = program {
        return match program.field {
            FieldId::Bn254 => vec![
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
            FieldId::Bls12_381 => vec![
                BackendKind::Halo2Bls12381,
                BackendKind::ArkworksGroth16,
                BackendKind::Plonky3,
                BackendKind::Nova,
                BackendKind::HyperNova,
                BackendKind::Halo2,
                BackendKind::Sp1,
                BackendKind::RiscZero,
                BackendKind::MidnightCompact,
            ],
            FieldId::PastaFp | FieldId::PastaFq => vec![
                BackendKind::Halo2,
                BackendKind::ArkworksGroth16,
                BackendKind::Plonky3,
                BackendKind::Nova,
                BackendKind::HyperNova,
                BackendKind::Halo2Bls12381,
                BackendKind::Sp1,
                BackendKind::RiscZero,
                BackendKind::MidnightCompact,
            ],
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => vec![
                BackendKind::Plonky3,
                BackendKind::ArkworksGroth16,
                BackendKind::Nova,
                BackendKind::HyperNova,
                BackendKind::Halo2,
                BackendKind::Halo2Bls12381,
                BackendKind::Sp1,
                BackendKind::RiscZero,
                BackendKind::MidnightCompact,
            ],
        };
    }
    vec![BackendKind::ArkworksGroth16]
}

pub(crate) fn project_control_plane_inputs<'a>(
    ctx: &'a ExecutionContext,
) -> ControlPlaneProjection<'a> {
    let job_kind = execution_core::classify_job(ctx);
    let program = execution_core::effective_program(ctx);
    let requested_backend = match job_kind {
        JobKind::Wrap => ctx
            .wrapper_preview
            .as_ref()
            .map(|preview| preview.target_backend)
            .or(ctx.requested_backend)
            .or_else(|| ctx.compiled.as_ref().map(|compiled| compiled.backend)),
        _ => ctx
            .requested_backend
            .or_else(|| ctx.compiled.as_ref().map(|compiled| compiled.backend)),
    };
    let backend_candidates = match job_kind {
        JobKind::Wrap => ctx
            .wrapper_preview
            .as_ref()
            .map(|preview| vec![preview.target_backend])
            .unwrap_or_default(),
        _ => ctx
            .requested_backend_candidates
            .clone()
            .unwrap_or_else(|| default_backend_candidates(program, ctx.compiled.as_deref())),
    };
    let backend_route = ctx.requested_backend_route.or_else(|| {
        ctx.compiled
            .as_ref()
            .and_then(|compiled| compiled.metadata.get("backend_route"))
            .map(|route| match route.as_str() {
                "explicit-compat" => BackendRoute::ExplicitCompat,
                _ => BackendRoute::Auto,
            })
    });
    ControlPlaneProjection {
        job_kind,
        program,
        requested_backend,
        backend_route,
        backend_candidates,
    }
}

pub(crate) fn build_control_plane_request<'a>(
    graph: &'a crate::graph::ProverGraph,
    ctx: &'a ExecutionContext,
) -> ControlPlaneRequest<'a> {
    let projection = project_control_plane_inputs(ctx);
    ControlPlaneRequest {
        job_kind: projection.job_kind,
        objective: ctx.optimization_objective,
        graph: Some(graph),
        constraint_count_override: None,
        signal_count_override: None,
        stage_node_counts_override: None,
        field_hint: projection
            .program
            .map(|candidate| candidate.field)
            .or_else(|| ctx.compiled.as_ref().map(|compiled| compiled.program.field)),
        program: projection.program,
        compiled: ctx.compiled.as_deref(),
        preview: ctx.wrapper_preview.as_ref(),
        witness: ctx.witness.as_deref(),
        witness_inputs: ctx.witness_inputs.as_deref(),
        requested_backend: projection.requested_backend,
        backend_route: projection.backend_route,
        trust_lane: RequiredTrustLane::StrictCryptographic,
        requested_jobs: None,
        total_jobs: None,
        backend_candidates: projection.backend_candidates,
    }
}

pub(crate) fn cpu_batch_scheduler_plan(
    total_jobs: usize,
    requested_jobs: usize,
    estimated_job_bytes: usize,
) -> BatchSchedulerPlan {
    let scheduled_jobs = requested_jobs.min(total_jobs).max(1);
    BatchSchedulerPlan {
        requested_jobs,
        scheduled_jobs,
        reason: format!(
            "executed {total_jobs} batch proof jobs via CPU worker pool (estimated_job_bytes={estimated_job_bytes})"
        ),
    }
}

pub(crate) fn queue_batch_requests(
    requests: Vec<crate::api::BatchBackendProofRequest>,
) -> VecDeque<(usize, crate::api::BatchBackendProofRequest)> {
    requests.into_iter().enumerate().collect()
}

pub(crate) fn build_runtime_outputs(
    exec_ctx: &ExecutionContext,
    report: &GraphExecutionReport,
    control_plane: Option<&ControlPlaneExecutionSummary>,
    security: Option<&SecurityEvaluation>,
) -> serde_json::Value {
    let mut map = execution_core::output_presence_map(&exec_ctx.outputs);
    map.insert(
        "trust_model".into(),
        serde_json::Value::String(report.final_trust_model.as_str().to_string()),
    );
    map.insert(
        "fallback_nodes".into(),
        serde_json::json!(report.fallback_nodes),
    );
    let artifact_state = match execution_core::artifact_state(exec_ctx) {
        execution_core::ArtifactState::Empty => "empty",
        execution_core::ArtifactState::PrimaryOnly => "primary-only",
        execution_core::ArtifactState::WrappedOnly => "wrapped-only",
        execution_core::ArtifactState::Dual => "dual",
    };
    map.insert(
        "runtime_artifact_state".into(),
        serde_json::json!(artifact_state),
    );
    map.insert(
        "peak_memory_bytes".into(),
        serde_json::json!(report.peak_memory_bytes),
    );
    map.insert(
        "runtime_gpu_stage_busy_ratio".into(),
        serde_json::json!(report.gpu_stage_busy_ratio()),
    );
    map.insert(
        "runtime_gpu_wall_time_ms".into(),
        serde_json::json!(report.gpu_wall_time().as_secs_f64() * 1000.0),
    );
    map.insert(
        "runtime_cpu_wall_time_ms".into(),
        serde_json::json!(report.cpu_wall_time().as_secs_f64() * 1000.0),
    );
    map.insert(
        "runtime_stage_breakdown".into(),
        serde_json::to_value(report.stage_breakdown()).unwrap_or_else(|_| serde_json::json!({})),
    );
    map.insert(
        "runtime_metal_counter_source".into(),
        serde_json::json!(report.counter_source()),
    );

    if let Some(control_plane) = control_plane {
        map.insert(
            "runtime_job_kind".into(),
            serde_json::json!(control_plane.decision.job_kind.as_str()),
        );
        map.insert(
            "runtime_dispatch_plan".into(),
            serde_json::to_value(&control_plane.decision.dispatch_plan)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_dispatch_candidate_rankings".into(),
            serde_json::to_value(&control_plane.decision.candidate_rankings)
                .unwrap_or_else(|_| serde_json::json!([])),
        );
        map.insert(
            "runtime_backend_recommendation".into(),
            serde_json::to_value(&control_plane.decision.backend_recommendation)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_duration_estimate".into(),
            serde_json::to_value(&control_plane.decision.duration_estimate)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_duration_estimate_ms".into(),
            serde_json::json!(control_plane.decision.duration_estimate.estimate_ms),
        );
        map.insert(
            "runtime_duration_upper_bound_ms".into(),
            serde_json::json!(control_plane.decision.duration_estimate.upper_bound_ms),
        );
        map.insert(
            "runtime_execution_regime".into(),
            serde_json::json!(
                control_plane
                    .decision
                    .duration_estimate
                    .execution_regime
                    .as_str()
            ),
        );
        map.insert(
            "runtime_eta_semantics".into(),
            serde_json::json!(
                control_plane
                    .decision
                    .duration_estimate
                    .eta_semantics
                    .as_str()
            ),
        );
        map.insert(
            "runtime_duration_bound_source".into(),
            serde_json::json!(
                control_plane
                    .decision
                    .duration_estimate
                    .bound_source
                    .as_str()
            ),
        );
        map.insert(
            "runtime_duration_countdown_safe".into(),
            serde_json::json!(control_plane.decision.duration_estimate.countdown_safe),
        );
        map.insert(
            "runtime_duration_note".into(),
            serde_json::json!(control_plane.decision.duration_estimate.note),
        );
        map.insert(
            "runtime_anomaly_baseline".into(),
            serde_json::to_value(&control_plane.decision.anomaly_baseline)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_anomaly_verdict".into(),
            serde_json::to_value(&control_plane.anomaly_verdict)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_duration_interpretation".into(),
            serde_json::json!(control_plane.anomaly_verdict.duration_interpretation),
        );
        map.insert(
            "runtime_model_catalog".into(),
            serde_json::to_value(&control_plane.decision.model_catalog)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_control_plane_features".into(),
            serde_json::to_value(&control_plane.decision.features)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_realized_gpu_capable_stages".into(),
            serde_json::to_value(&control_plane.realized_gpu_capable_stages)
                .unwrap_or_else(|_| serde_json::json!([])),
        );
        map.insert(
            "runtime_prover_acceleration_realized".into(),
            serde_json::json!(!control_plane.realized_gpu_capable_stages.is_empty()),
        );
    }

    if let Some(security) = security {
        map.insert(
            "runtime_security_verdict".into(),
            serde_json::to_value(&security.verdict).unwrap_or_else(|_| serde_json::json!({})),
        );
        map.insert(
            "runtime_security_signals".into(),
            serde_json::to_value(&security.verdict.signals)
                .unwrap_or_else(|_| serde_json::json!([])),
        );
        map.insert(
            "runtime_security_actions".into(),
            serde_json::to_value(&security.verdict.actions)
                .unwrap_or_else(|_| serde_json::json!([])),
        );
        map.insert(
            "runtime_model_integrity".into(),
            serde_json::to_value(&security.model_integrity)
                .unwrap_or_else(|_| serde_json::json!({})),
        );
    }

    map.insert(
        "runtime_watchdog_alerts".into(),
        serde_json::to_value(&report.watchdog_alerts).unwrap_or_else(|_| serde_json::json!([])),
    );
    serde_json::Value::Object(map)
}
