use axum::{
    Json,
    extract::{MatchedPath, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use zkf_backends::{
    BackendRoute, BackendSelection, backend_for_selection, capabilities_report,
    ensure_backend_selection_production_ready, parse_backend_selection,
    preferred_backend_for_field, validate_backend_selection_identity,
    wrapping::default_wrapper_registry,
};
use zkf_core::{
    BackendKind, CompiledProgram, Program, ProofArtifact, WitnessInputs, generate_witness,
    program_zir_to_v2, wrapping::WrapperExecutionPolicy, zir_v1,
};
use zkf_frontends::IrFamilyPreference;
use zkf_lib::{
    CredentialPublicInputsV1, PrivateIdentityPathProveRequestV1, PrivateIdentityPolicyV1,
    private_identity_public_inputs_from_artifact, prove_private_identity_with_paths,
    verify_private_identity_artifact,
};
use zkf_runtime::{
    EntrypointGuard, EntrypointSurface, ExecutionMode, PlanExecutionResult, RequiredTrustLane,
    RuntimeExecutor, RuntimeSecurityContext, SecurityEvaluation, SecuritySupervisor,
};

use crate::AppState;
use crate::auth;
use crate::metering;
use crate::solidity;
use crate::types::*;

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

type ApiResponse = (StatusCode, Json<Value>);

#[derive(Clone, Debug, Serialize)]
struct RuntimeMetadata {
    trust_model: String,
    node_count: usize,
    gpu_nodes: usize,
    cpu_nodes: usize,
    delegated_nodes: usize,
    fallback_nodes: usize,
    peak_memory_bytes: usize,
    gpu_stage_busy_ratio: f64,
    gpu_wall_time_ms: f64,
    cpu_wall_time_ms: f64,
    counter_source: String,
    stage_breakdown: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_verdict: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_signals: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_actions: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_integrity: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct BenchmarkRuntimeSummary {
    runs: usize,
    trust_models: Vec<String>,
    gpu_nodes_total: usize,
    cpu_nodes_total: usize,
    delegated_nodes_total: usize,
    fallback_nodes_total: usize,
    peak_memory_bytes_max: usize,
    gpu_stage_busy_ratio_avg: f64,
    gpu_wall_time_ms_avg: f64,
    cpu_wall_time_ms_avg: f64,
    latest: Option<RuntimeMetadata>,
}

fn start_time() -> &'static Instant {
    START_TIME.get_or_init(Instant::now)
}

fn json_error(status: StatusCode, message: impl Into<String>) -> ApiResponse {
    (status, Json(json!({ "error": message.into() })))
}

fn parse_value<T: DeserializeOwned>(value: Value, label: &str) -> Result<T, ApiResponse> {
    serde_json::from_value(value)
        .map_err(|err| json_error(StatusCode::BAD_REQUEST, format!("invalid {label}: {err}")))
}

#[derive(Debug, Clone)]
struct ResolvedProgramRequest {
    program: Program,
    source_ir_family: &'static str,
}

fn parse_ir_family_request(value: Option<&str>) -> Result<IrFamilyPreference, String> {
    value.unwrap_or("auto").parse::<IrFamilyPreference>()
}

fn resolve_program_request(
    value: Value,
    ir_family: Option<&str>,
) -> Result<ResolvedProgramRequest, String> {
    match parse_ir_family_request(ir_family)? {
        IrFamilyPreference::IrV2 => {
            let program = serde_json::from_value::<Program>(value)
                .map_err(|err| format!("invalid ir-v2 program: {err}"))?;
            Ok(ResolvedProgramRequest {
                program,
                source_ir_family: "ir-v2",
            })
        }
        IrFamilyPreference::ZirV1 => {
            let zir_program = serde_json::from_value::<zir_v1::Program>(value)
                .map_err(|err| format!("invalid zir-v1 program: {err}"))?;
            let program = program_zir_to_v2(&zir_program)
                .map_err(|err| format!("zir-v1 lowering failed: {err}"))?;
            Ok(ResolvedProgramRequest {
                program,
                source_ir_family: "zir-v1",
            })
        }
        IrFamilyPreference::Auto => {
            if let Ok(program) = serde_json::from_value::<Program>(value.clone()) {
                return Ok(ResolvedProgramRequest {
                    program,
                    source_ir_family: "ir-v2",
                });
            }
            let zir_program = serde_json::from_value::<zir_v1::Program>(value)
                .map_err(|err| format!("invalid program (expected ir-v2 or zir-v1): {err}"))?;
            let program = program_zir_to_v2(&zir_program)
                .map_err(|err| format!("zir-v1 lowering failed: {err}"))?;
            Ok(ResolvedProgramRequest {
                program,
                source_ir_family: "zir-v1",
            })
        }
    }
}

fn resolve_program_request_http(
    value: Value,
    ir_family: Option<&str>,
) -> Result<ResolvedProgramRequest, ApiResponse> {
    resolve_program_request(value, ir_family)
        .map_err(|err| json_error(StatusCode::BAD_REQUEST, err))
}

fn runtime_metadata(
    result: &PlanExecutionResult,
    security_override: Option<&SecurityEvaluation>,
) -> RuntimeMetadata {
    let report = &result.report;
    RuntimeMetadata {
        trust_model: report.final_trust_model.as_str().to_string(),
        node_count: report.node_traces.len(),
        gpu_nodes: report.gpu_nodes,
        cpu_nodes: report.cpu_nodes,
        delegated_nodes: report.delegated_nodes,
        fallback_nodes: report.fallback_nodes,
        peak_memory_bytes: report.peak_memory_bytes,
        gpu_stage_busy_ratio: report.gpu_stage_busy_ratio(),
        gpu_wall_time_ms: report.gpu_wall_time().as_secs_f64() * 1000.0,
        cpu_wall_time_ms: report.cpu_wall_time().as_secs_f64() * 1000.0,
        counter_source: report.counter_source().to_string(),
        stage_breakdown: serde_json::to_value(report.stage_breakdown())
            .unwrap_or_else(|_| json!({})),
        security_verdict: security_override
            .and_then(|value| serde_json::to_value(&value.verdict).ok())
            .or_else(|| {
                result
                    .security
                    .as_ref()
                    .and_then(|value| serde_json::to_value(value).ok())
            }),
        security_signals: security_override
            .and_then(|value| serde_json::to_value(&value.verdict.signals).ok())
            .or_else(|| {
                result
                    .security
                    .as_ref()
                    .and_then(|value| serde_json::to_value(&value.signals).ok())
            }),
        security_actions: security_override
            .and_then(|value| serde_json::to_value(&value.verdict.actions).ok())
            .or_else(|| {
                result
                    .security
                    .as_ref()
                    .and_then(|value| serde_json::to_value(&value.actions).ok())
            }),
        model_integrity: security_override
            .and_then(|value| serde_json::to_value(&value.model_integrity).ok())
            .or_else(|| {
                result
                    .model_integrity
                    .as_ref()
                    .and_then(|value| serde_json::to_value(value).ok())
            }),
    }
}

pub(crate) fn api_security_context(api_key_hash: &str) -> RuntimeSecurityContext {
    RuntimeSecurityContext {
        caller_class: Some("api-key".to_string()),
        api_identity_hash: Some(api_key_hash.to_string()),
        ..RuntimeSecurityContext::default()
    }
}

fn api_entrypoint_context(headers: &HeaderMap) -> RuntimeSecurityContext {
    let Some(api_key) = auth::extract_api_key_from_headers(headers) else {
        return RuntimeSecurityContext {
            caller_class: Some("anonymous".to_string()),
            ..RuntimeSecurityContext::default()
        };
    };

    RuntimeSecurityContext {
        caller_class: Some("api-key".to_string()),
        api_identity_hash: Some(auth::hash_api_key(&api_key)),
        ..RuntimeSecurityContext::default()
    }
}

fn classify_api_response(
    mut context: RuntimeSecurityContext,
    status: StatusCode,
    had_auth_header: bool,
) -> RuntimeSecurityContext {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            context.auth_failure_count = context.auth_failure_count.saturating_add(1);
        }
        StatusCode::TOO_MANY_REQUESTS => {
            context.rate_limit_violation_count =
                context.rate_limit_violation_count.saturating_add(1);
        }
        StatusCode::BAD_REQUEST
        | StatusCode::METHOD_NOT_ALLOWED
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNSUPPORTED_MEDIA_TYPE
        | StatusCode::UNPROCESSABLE_ENTITY => {
            context.malformed_request_count = context.malformed_request_count.saturating_add(1);
        }
        _ => {}
    }

    if !had_auth_header
        && status == StatusCode::UNAUTHORIZED
        && context.caller_class.as_deref() == Some("anonymous")
    {
        context.auth_failure_count = context.auth_failure_count.saturating_add(1);
    }

    if status.is_client_error() || status.is_server_error() {
        context.rejection_reason = Some(status.to_string());
    }
    context
}

pub(crate) async fn observe_api_entrypoint(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let had_auth_header = auth::extract_api_key_from_headers(request.headers()).is_some();
    let guard = EntrypointGuard::begin(EntrypointSurface::Api, format!("{method} {route}"));
    let base_context = api_entrypoint_context(request.headers());
    let response = next.run(request).await;
    let status = response.status();
    let detail = if status.is_success() {
        None
    } else {
        Some(status.to_string())
    };
    let _ = guard.finish(
        classify_api_response(base_context, status, had_auth_header),
        status.is_success(),
        Some(status.as_u16()),
        detail,
    );
    response
}

fn benchmark_runtime_summary(runs: &[RuntimeMetadata]) -> BenchmarkRuntimeSummary {
    let runs_len = runs.len();
    let latest = runs.last().cloned();
    let mut trust_models = runs
        .iter()
        .map(|run| run.trust_model.clone())
        .collect::<Vec<_>>();
    trust_models.sort();
    trust_models.dedup();

    let gpu_stage_busy_ratio_avg = if runs_len == 0 {
        0.0
    } else {
        runs.iter().map(|run| run.gpu_stage_busy_ratio).sum::<f64>() / runs_len as f64
    };
    let gpu_wall_time_ms_avg = if runs_len == 0 {
        0.0
    } else {
        runs.iter().map(|run| run.gpu_wall_time_ms).sum::<f64>() / runs_len as f64
    };
    let cpu_wall_time_ms_avg = if runs_len == 0 {
        0.0
    } else {
        runs.iter().map(|run| run.cpu_wall_time_ms).sum::<f64>() / runs_len as f64
    };

    BenchmarkRuntimeSummary {
        runs: runs_len,
        trust_models,
        gpu_nodes_total: runs.iter().map(|run| run.gpu_nodes).sum(),
        cpu_nodes_total: runs.iter().map(|run| run.cpu_nodes).sum(),
        delegated_nodes_total: runs.iter().map(|run| run.delegated_nodes).sum(),
        fallback_nodes_total: runs.iter().map(|run| run.fallback_nodes).sum(),
        peak_memory_bytes_max: runs
            .iter()
            .map(|run| run.peak_memory_bytes)
            .max()
            .unwrap_or(0),
        gpu_stage_busy_ratio_avg,
        gpu_wall_time_ms_avg,
        cpu_wall_time_ms_avg,
        latest,
    }
}

fn authorize(state: &AppState, headers: &HeaderMap, kind: &str) -> Result<String, ApiResponse> {
    let api_key = auth::extract_api_key_from_headers(headers);
    let (api_key_hash, tier) =
        auth::validate_key(&state.db, api_key.as_deref()).map_err(|status| match status {
            StatusCode::UNAUTHORIZED => json_error(status, "missing, invalid, or inactive API key"),
            _ => json_error(status, "authorization failed"),
        })?;
    let rate_limit_key = auth::rate_limit_key(headers, Some(&api_key_hash));

    metering::check_rate_limit(&state.rate_limiter, &rate_limit_key)
        .map_err(|err| json_error(StatusCode::TOO_MANY_REQUESTS, err))?;

    metering::check_quota(&state.db, &api_key_hash, tier, kind)
        .map_err(|err| json_error(StatusCode::TOO_MANY_REQUESTS, err))?;

    metering::check_concurrency(&state.db, &api_key_hash, tier)
        .map_err(|err| json_error(StatusCode::TOO_MANY_REQUESTS, err))?;

    Ok(api_key_hash)
}

fn authorize_readonly(state: &AppState, headers: &HeaderMap) -> Result<String, ApiResponse> {
    let api_key = auth::extract_api_key_from_headers(headers);
    let (api_key_hash, _) =
        auth::validate_key(&state.db, api_key.as_deref()).map_err(|status| match status {
            StatusCode::UNAUTHORIZED => json_error(status, "missing, invalid, or inactive API key"),
            _ => json_error(status, "authorization failed"),
        })?;
    let rate_limit_key = auth::rate_limit_key(headers, Some(&api_key_hash));
    metering::check_rate_limit(&state.rate_limiter, &rate_limit_key)
        .map_err(|err| json_error(StatusCode::TOO_MANY_REQUESTS, err))?;
    Ok(api_key_hash)
}

async fn enqueue_job<T: Serialize>(
    state: &AppState,
    kind: &str,
    api_key_hash: &str,
    request: &T,
) -> Result<String, String> {
    let request_json = serde_json::to_string(request).unwrap_or_else(|_| "{}".to_string());
    state
        .job_queue
        .enqueue(kind, api_key_hash, &request_json)
        .await
}

fn accepted_job_response(id: String) -> ApiResponse {
    let response = JobResponse {
        id,
        status: JobStatus::Queued,
        result: None,
        security: None,
        error: None,
        created_at: None,
        completed_at: None,
    };
    (
        StatusCode::ACCEPTED,
        Json(
            serde_json::to_value(response)
                .unwrap_or_else(|_| json!({"error": "serialization failure"})),
        ),
    )
}

fn parse_backend_name(name: &str) -> Result<BackendSelection, ApiResponse> {
    let selection =
        parse_backend_selection(name).map_err(|err| json_error(StatusCode::BAD_REQUEST, err))?;
    validate_backend_selection_identity(&selection)
        .map_err(|err| json_error(StatusCode::BAD_REQUEST, err))?;
    Ok(selection)
}

fn selected_backend(
    program: &Program,
    backend: Option<&str>,
) -> Result<BackendSelection, ApiResponse> {
    match backend {
        Some(name) => parse_backend_name(name),
        None => Ok(BackendSelection::native(preferred_backend_for_field(
            program.field,
        ))),
    }
}

fn credential_public_surface(surface: &CredentialPolicySurfaceRequest) -> CredentialPublicInputsV1 {
    CredentialPublicInputsV1 {
        issuer_tree_root: surface.issuer_tree_root.clone(),
        active_tree_root: surface.active_tree_root.clone(),
        required_age: surface.required_age,
        required_status_mask: surface.required_status_mask,
        current_epoch_day: surface.current_epoch_day,
    }
}

pub(crate) fn run_prove(
    req: &ProveRequest,
    security_context: Option<RuntimeSecurityContext>,
) -> Result<Value, String> {
    let resolved_program = resolve_program_request(req.program.clone(), req.ir_family.as_deref())?;
    let program = resolved_program.program;
    let hybrid = req.hybrid.unwrap_or(false);
    if hybrid
        && let Some(requested) = req.backend.as_deref()
        && requested != "plonky3"
    {
        return Err(
            "hybrid proving currently requires backend=plonky3 or no explicit backend".to_string(),
        );
    }
    let inputs: WitnessInputs = serde_json::from_value(req.inputs.clone())
        .map_err(|err| format!("invalid inputs: {err}"))?;
    let backend = if hybrid {
        BackendSelection::native(BackendKind::Plonky3)
    } else {
        req.backend
            .as_deref()
            .map(parse_backend_selection)
            .transpose()
            .map_err(|err| err.to_string())?
            .unwrap_or_else(|| BackendSelection::native(preferred_backend_for_field(program.field)))
    };
    validate_backend_selection_identity(&backend).map_err(|err| err.to_string())?;
    ensure_backend_selection_production_ready(&backend).map_err(|err| err.to_string())?;

    let witness_started = Instant::now();
    let witness = generate_witness(&program, &inputs).map_err(|err| err.to_string())?;
    let witness_ms = witness_started.elapsed().as_millis();

    let prove_started = Instant::now();
    let (compiled, artifact, plan_result) = if hybrid {
        let execution = zkf_runtime::run_hybrid_prove_job_with_objective(
            Arc::new(program.clone()),
            None,
            Some(Arc::new(witness.clone())),
            zkf_runtime::OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map_err(|err| err.to_string())?;
        (
            execution.source.compiled,
            execution.artifact,
            execution.wrapped.result,
        )
    } else {
        let execution = RuntimeExecutor::run_backend_prove_job(
            backend.backend,
            backend.route,
            Arc::new(program.clone()),
            None,
            Some(Arc::new(witness.clone())),
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map_err(|err| err.to_string())?;
        (execution.compiled, execution.artifact, execution.result)
    };
    let prove_ms = prove_started.elapsed().as_millis();
    let security = security_context.as_ref().map(|context| {
        SecuritySupervisor::evaluate(
            &plan_result.report,
            plan_result.control_plane.as_ref(),
            Some(context),
            None,
        )
    });
    let runtime = runtime_metadata(&plan_result, security.as_ref());

    let verify_started = Instant::now();
    let verified = if hybrid || artifact.hybrid_bundle.is_some() {
        zkf_runtime::verify_hybrid_artifact(&program, &artifact).map_err(|err| err.to_string())?
    } else {
        let backend_engine = backend_for_selection(&backend).map_err(|err| err.to_string())?;
        backend_engine
            .verify(&compiled, &artifact)
            .map_err(|err| err.to_string())?
    };
    let verify_ms = verify_started.elapsed().as_millis();

    if !verified {
        return Err("backend produced a proof that did not verify".to_string());
    }

    Ok(json!({
        "backend": backend.backend.as_str(),
        "requested_backend": backend.requested_name,
        "hybrid": hybrid,
        "backend_route": match backend.route {
            BackendRoute::Auto => "native-auto",
            BackendRoute::ExplicitCompat => "explicit-compat",
        },
        "source_ir_family": resolved_program.source_ir_family,
        "mode": req.mode.as_deref().unwrap_or("auto"),
        "compiled": compiled,
        "proof": artifact,
        "verified": true,
        "runtime": runtime,
        "timings_ms": {
            "compile": 0,
            "witness": witness_ms,
            "prove": prove_ms,
            "verify": verify_ms,
        }
    }))
}

pub(crate) fn run_wrap(
    req: &WrapRequest,
    security_context: Option<RuntimeSecurityContext>,
) -> Result<Value, String> {
    let source_proof: ProofArtifact =
        serde_json::from_value(req.proof.clone()).map_err(|err| format!("invalid proof: {err}"))?;
    let source_compiled: CompiledProgram = serde_json::from_value(req.compiled.clone())
        .map_err(|err| format!("invalid compiled artifact: {err}"))?;
    if source_compiled.backend != source_proof.backend {
        return Err(format!(
            "compiled backend '{}' does not match proof backend '{}'",
            source_compiled.backend, source_proof.backend
        ));
    }

    let target = req
        .target
        .as_deref()
        .map(BackendKind::from_str)
        .transpose()
        .map_err(|err| err.to_string())?
        .unwrap_or(BackendKind::ArkworksGroth16);

    let registry = default_wrapper_registry();
    let wrapper = registry.find(source_proof.backend, target).ok_or_else(|| {
        format!(
            "no wrapping path registered from '{}' to '{}'",
            source_proof.backend, target
        )
    })?;

    let policy = WrapperExecutionPolicy::default();
    let preview = wrapper
        .preview_wrap_with_policy(&source_proof, &source_compiled, policy)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| {
            format!(
                "wrapper '{}' -> '{}' did not provide a runtime execution preview",
                source_proof.backend, target
            )
        })?;
    let started = Instant::now();
    let wrapped = RuntimeExecutor::run_wrapper_job_with_sources(
        &preview,
        Arc::new(source_proof.clone()),
        Arc::new(source_compiled.clone()),
        policy,
        ExecutionMode::Deterministic,
    )
    .map_err(|err| err.to_string())?;
    let security = security_context.as_ref().map(|context| {
        SecuritySupervisor::evaluate(
            &wrapped.result.report,
            wrapped.result.control_plane.as_ref(),
            Some(context),
            None,
        )
    });
    let runtime = runtime_metadata(&wrapped.result, security.as_ref());
    let wrapped_artifact = wrapped.artifact;
    let wrap_ms = started.elapsed().as_millis();
    let verified = wrapper
        .verify_wrapped(&wrapped_artifact)
        .map_err(|err| err.to_string())?;

    if !verified {
        return Err("wrapper produced a proof that did not verify".to_string());
    }

    Ok(json!({
        "source_backend": source_proof.backend.as_str(),
        "target_backend": target.as_str(),
        "proof": wrapped_artifact,
        "verified": true,
        "runtime": runtime,
        "timings_ms": {
            "wrap": wrap_ms,
        }
    }))
}

fn estimate_verification_gas(backend: BackendKind, proof_size_bytes: usize) -> Result<u64, String> {
    let size = proof_size_bytes as u64;
    let gas = match backend {
        BackendKind::ArkworksGroth16 => 210_000,
        BackendKind::Halo2 => 280_000 + size.saturating_mul(16),
        BackendKind::Halo2Bls12381 => 300_000 + size.saturating_mul(18),
        BackendKind::Plonky3 => 350_000 + size.saturating_mul(12),
        BackendKind::Sp1 => 450_000 + size.saturating_mul(20),
        BackendKind::RiscZero => 420_000 + size.saturating_mul(18),
        BackendKind::Nova => 300_000 + size.saturating_mul(15),
        BackendKind::HyperNova => 320_000 + size.saturating_mul(16),
        BackendKind::MidnightCompact => {
            return Err(
                "gas estimation for midnight-compact is not applicable in EVM gas units"
                    .to_string(),
            );
        }
    };
    Ok(gas)
}

fn default_benchmark_backends(program: &Program) -> Vec<BackendSelection> {
    vec![BackendSelection::native(preferred_backend_for_field(
        program.field,
    ))]
}

pub(crate) fn run_benchmark(
    req: &BenchmarkRequest,
    security_context: Option<RuntimeSecurityContext>,
) -> Result<Value, String> {
    let resolved_program = resolve_program_request(req.program.clone(), req.ir_family.as_deref())?;
    let program = resolved_program.program;
    let inputs: WitnessInputs = serde_json::from_value(req.inputs.clone())
        .map_err(|err| format!("invalid inputs: {err}"))?;
    let iterations = req.iterations.unwrap_or(1).clamp(1, 25);
    let backends = if let Some(requested) = &req.backends {
        requested
            .iter()
            .map(|backend| -> Result<BackendSelection, String> {
                let selection = parse_backend_selection(backend)?;
                validate_backend_selection_identity(&selection)?;
                ensure_backend_selection_production_ready(&selection)?;
                Ok(selection)
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        default_benchmark_backends(&program)
    };

    let witness_started = Instant::now();
    let witness = generate_witness(&program, &inputs).map_err(|err| err.to_string())?;
    let witness_ms = witness_started.elapsed().as_millis();

    let mut results = Vec::with_capacity(backends.len());
    for backend in backends {
        let backend_engine = backend_for_selection(&backend).map_err(|err| err.to_string())?;
        let compile_started = Instant::now();
        let compiled = match backend_engine.compile(&program) {
            Ok(compiled) => compiled,
            Err(err) => {
                results.push(json!({
                    "backend": backend.backend.as_str(),
                    "requested_backend": backend.requested_name,
                    "backend_route": match backend.route {
                        BackendRoute::Auto => "native-auto",
                        BackendRoute::ExplicitCompat => "explicit-compat",
                    },
                    "status": "failed",
                    "error": err.to_string(),
                }));
                continue;
            }
        };
        let compile_ms = compile_started.elapsed().as_millis();

        let mut prove_runs_ms = Vec::with_capacity(iterations);
        let mut verify_runs_ms = Vec::with_capacity(iterations);
        let mut runtime_runs = Vec::with_capacity(iterations);
        let mut proof_size_bytes = 0usize;
        let mut vk_size_bytes = 0usize;

        let mut failed = None;
        for _ in 0..iterations {
            let prove_started = Instant::now();
            let artifact = match RuntimeExecutor::run_backend_prove_job(
                backend.backend,
                backend.route,
                Arc::new(program.clone()),
                None,
                Some(Arc::new(witness.clone())),
                Some(Arc::new(compiled.clone())),
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            ) {
                Ok(execution) => {
                    let security = security_context.as_ref().map(|context| {
                        SecuritySupervisor::evaluate(
                            &execution.result.report,
                            execution.result.control_plane.as_ref(),
                            Some(context),
                            None,
                        )
                    });
                    runtime_runs.push(runtime_metadata(&execution.result, security.as_ref()));
                    execution.artifact
                }
                Err(err) => {
                    failed = Some(err.to_string());
                    break;
                }
            };
            prove_runs_ms.push(prove_started.elapsed().as_millis());
            proof_size_bytes = artifact.proof.len();
            vk_size_bytes = artifact.verification_key.len();

            let verify_started = Instant::now();
            match backend_engine.verify(&compiled, &artifact) {
                Ok(true) => {
                    verify_runs_ms.push(verify_started.elapsed().as_millis());
                }
                Ok(false) => {
                    failed = Some("proof verification returned false".to_string());
                    break;
                }
                Err(err) => {
                    failed = Some(err.to_string());
                    break;
                }
            }
        }

        if let Some(error) = failed {
            results.push(json!({
                "backend": backend.backend.as_str(),
                "requested_backend": backend.requested_name,
                "backend_route": match backend.route {
                    BackendRoute::Auto => "native-auto",
                    BackendRoute::ExplicitCompat => "explicit-compat",
                },
                "status": "failed",
                "compile_ms": compile_ms,
                "witness_ms": witness_ms,
                "error": error,
            }));
            continue;
        }

        let prove_avg_ms = if prove_runs_ms.is_empty() {
            0
        } else {
            prove_runs_ms.iter().sum::<u128>() / prove_runs_ms.len() as u128
        };
        let verify_avg_ms = if verify_runs_ms.is_empty() {
            0
        } else {
            verify_runs_ms.iter().sum::<u128>() / verify_runs_ms.len() as u128
        };

        results.push(json!({
            "backend": backend.backend.as_str(),
            "requested_backend": backend.requested_name,
            "backend_route": match backend.route {
                BackendRoute::Auto => "native-auto",
                BackendRoute::ExplicitCompat => "explicit-compat",
            },
            "status": "completed",
            "iterations": iterations,
            "compile_ms": compile_ms,
            "witness_ms": witness_ms,
            "prove_ms_each": prove_runs_ms,
            "verify_ms_each": verify_runs_ms,
            "prove_ms_avg": prove_avg_ms,
            "verify_ms_avg": verify_avg_ms,
            "proof_size_bytes": proof_size_bytes,
            "verification_key_size_bytes": vk_size_bytes,
            "runtime": benchmark_runtime_summary(&runtime_runs),
        }));
    }

    Ok(json!({
        "program": program.name,
        "source_ir_family": resolved_program.source_ir_family,
        "field": program.field.as_str(),
        "results": results,
    }))
}

pub(crate) fn run_credential_prove(req: &CredentialProveRequest) -> Result<Value, String> {
    let proof = prove_private_identity_with_paths(&PrivateIdentityPathProveRequestV1 {
        signed_credential: req.signed_credential.clone(),
        subject_secret: req.subject_secret.as_bytes().to_vec(),
        subject_salt: req.subject_salt.as_bytes().to_vec(),
        issuer_tree_root: req.surface.issuer_tree_root.clone(),
        active_tree_root: req.surface.active_tree_root.clone(),
        issuer_path: req.issuer_path.clone(),
        active_path: req.active_path.clone(),
        policy: PrivateIdentityPolicyV1 {
            required_age: req.surface.required_age,
            required_status_mask: req.surface.required_status_mask,
            current_epoch_day: req.surface.current_epoch_day,
        },
        backend: req.backend.clone(),
        groth16_setup_blob: req.groth16_setup_blob.clone(),
        allow_dev_deterministic_groth16: req.allow_dev_deterministic_groth16,
    })?;
    let _public_inputs = private_identity_public_inputs_from_artifact(&proof.artifact)?;
    let expected = credential_public_surface(&req.surface);
    let report = verify_private_identity_artifact(&proof.artifact, Some(&expected))?;

    Ok(json!({
        "backend": proof.artifact.backend.as_str(),
        "proof": proof.artifact,
        "verified": true,
        "report": report,
    }))
}

pub(crate) fn run_credential_verify(req: &CredentialVerifyRequest) -> Result<Value, String> {
    let _public_inputs = private_identity_public_inputs_from_artifact(&req.artifact)?;
    let expected = credential_public_surface(&req.surface);
    let report = verify_private_identity_artifact(&req.artifact, Some(&expected))?;
    Ok(json!({
        "verified": true,
        "report": report,
    }))
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: start_time().elapsed().as_secs(),
    })
}

pub async fn capabilities() -> Json<CapabilitiesResponse> {
    let registry = default_wrapper_registry();
    let wrapping_paths: Vec<(String, String)> = registry
        .available_paths()
        .into_iter()
        .map(|(s, t)| (s.to_string(), t.to_string()))
        .collect();

    let gpu_available = cfg!(all(target_os = "macos", feature = "metal-gpu"));

    Json(CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        backends: capabilities_report(),
        frontends: vec![
            "noir".into(),
            "circom".into(),
            "cairo".into(),
            "compact".into(),
            "halo2-rust".into(),
            "plonky3-air".into(),
            "zkvm".into(),
        ],
        wrapping_paths,
        gpu_available,
    })
}

pub async fn prove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    let api_key = match authorize(&state, &headers, "prove") {
        Ok(api_key) => api_key,
        Err(response) => return response,
    };

    let resolved_program =
        match resolve_program_request_http(req.program.clone(), req.ir_family.as_deref()) {
            Ok(program) => program,
            Err(response) => return response,
        };
    if req.hybrid.unwrap_or(false)
        && let Some(requested) = req.backend.as_deref()
        && requested != "plonky3"
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "hybrid proving currently requires backend=plonky3 or no explicit backend",
        );
    }
    if let Err(response) = parse_value::<WitnessInputs>(req.inputs.clone(), "inputs") {
        return response;
    }
    let backend_name = if req.hybrid.unwrap_or(false) {
        Some("plonky3")
    } else {
        req.backend.as_deref()
    };
    if let Err(response) = selected_backend(&resolved_program.program, backend_name) {
        return response;
    }

    match enqueue_job(&state, "prove", &api_key, &req).await {
        Ok(job_id) => accepted_job_response(job_id),
        Err(err) => json_error(StatusCode::SERVICE_UNAVAILABLE, err),
    }
}

pub async fn wrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WrapRequest>,
) -> impl IntoResponse {
    let api_key = match authorize(&state, &headers, "wrap") {
        Ok(api_key) => api_key,
        Err(response) => return response,
    };

    if let Err(response) = parse_value::<ProofArtifact>(req.proof.clone(), "proof") {
        return response;
    }
    if let Err(response) = parse_value::<CompiledProgram>(req.compiled.clone(), "compiled artifact")
    {
        return response;
    }
    if let Some(target) = req.target.as_deref()
        && let Err(response) = parse_backend_name(target)
    {
        return response;
    }

    match enqueue_job(&state, "wrap", &api_key, &req).await {
        Ok(job_id) => accepted_job_response(job_id),
        Err(err) => json_error(StatusCode::SERVICE_UNAVAILABLE, err),
    }
}

pub async fn deploy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeployRequest>,
) -> impl IntoResponse {
    let api_key = match authorize(&state, &headers, "deploy") {
        Ok(api_key) => api_key,
        Err(response) => return response,
    };

    let artifact: ProofArtifact = match parse_value(req.proof.clone(), "proof") {
        Ok(artifact) => artifact,
        Err(response) => return response,
    };
    let backend = match parse_backend_name(&req.backend) {
        Ok(backend) => backend,
        Err(response) => return response,
    };
    let contract_name = req
        .contract_name
        .clone()
        .unwrap_or_else(|| solidity::default_contract_name(backend.backend));

    let solidity_source =
        match solidity::render_solidity_verifier(backend.backend, &artifact, &contract_name) {
            Ok(source) => source,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, err),
        };

    let estimated_verify_gas =
        estimate_verification_gas(backend.backend, artifact.proof.len()).ok();
    let estimated_deploy_gas = estimated_verify_gas.map(|gas| gas.saturating_mul(5));
    let _ = metering::record_usage(&state.db, &api_key, "deploy");

    (
        StatusCode::OK,
        Json(json!({
            "backend": backend.backend.as_str(),
            "requested_backend": backend.requested_name,
            "backend_route": match backend.route {
                BackendRoute::Auto => "native-auto",
                BackendRoute::ExplicitCompat => "explicit-compat",
            },
            "contract_name": contract_name,
            "solidity": solidity_source,
            "solidity_bytes": solidity_source.len(),
            "estimated_deploy_gas": estimated_deploy_gas,
            "estimated_verify_gas": estimated_verify_gas,
        })),
    )
}

pub async fn benchmark(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BenchmarkRequest>,
) -> impl IntoResponse {
    let api_key = match authorize(&state, &headers, "benchmark") {
        Ok(api_key) => api_key,
        Err(response) => return response,
    };

    if let Err(response) =
        resolve_program_request_http(req.program.clone(), req.ir_family.as_deref())
    {
        return response;
    }
    if let Err(response) = parse_value::<WitnessInputs>(req.inputs.clone(), "inputs") {
        return response;
    }
    if let Some(backends) = &req.backends {
        for backend in backends {
            if let Err(response) = parse_backend_name(backend) {
                return response;
            }
        }
    }

    match enqueue_job(&state, "benchmark", &api_key, &req).await {
        Ok(job_id) => accepted_job_response(job_id),
        Err(err) => json_error(StatusCode::SERVICE_UNAVAILABLE, err),
    }
}

pub async fn credential_prove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialProveRequest>,
) -> impl IntoResponse {
    let api_key = match authorize(&state, &headers, "prove") {
        Ok(api_key) => api_key,
        Err(response) => return response,
    };
    if let Some(backend) = req.backend.as_deref()
        && let Err(response) = parse_backend_name(backend)
    {
        return response;
    }

    let result = tokio::task::spawn_blocking(move || run_credential_prove(&req))
        .await
        .map_err(|err| format!("credential prove task join error: {err}"));
    match result {
        Ok(Ok(response)) => {
            let _ = metering::record_usage(&state.db, &api_key, "prove");
            (StatusCode::OK, Json(response))
        }
        Ok(Err(err)) => json_error(StatusCode::BAD_REQUEST, err),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub async fn credential_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialVerifyRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize_readonly(&state, &headers) {
        return response;
    }

    let result = tokio::task::spawn_blocking(move || run_credential_verify(&req))
        .await
        .map_err(|err| format!("credential verify task join error: {err}"));
    match result {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)),
        Ok(Err(err)) => json_error(StatusCode::BAD_REQUEST, err),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router, middleware,
        routing::{get, post},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_87::{generate_key_pair, sign as mldsa_sign};
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
    use std::fs;
    use std::sync::{Arc, Mutex, OnceLock};
    use tower::util::ServiceExt;
    use zkf_core::{
        Constraint, CredentialClaimsV1, Expr, FieldElement, FieldId, IssuerSignedCredentialV1,
        Signal, Visibility,
    };
    use zkf_lib::{
        MerklePathNodeV1, PRIVATE_IDENTITY_ML_DSA_CONTEXT, PrivateIdentityRegistryV1,
        active_leaf_from_credential_id, credential_id_from_claims,
    };
    use zkf_runtime::SwarmConfig;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[allow(unsafe_code)]
    async fn with_temp_home_async<T>(f: impl std::future::Future<Output = T>) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_swarm = std::env::var_os("ZKF_SWARM");
        let old_backend = std::env::var_os("ZKF_SWARM_KEY_BACKEND");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("ZKF_SWARM", "1");
            std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        }
        let result = f.await;
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(old_swarm) = old_swarm {
                std::env::set_var("ZKF_SWARM", old_swarm);
            } else {
                std::env::remove_var("ZKF_SWARM");
            }
            if let Some(old_backend) = old_backend {
                std::env::set_var("ZKF_SWARM_KEY_BACKEND", old_backend);
            } else {
                std::env::remove_var("ZKF_SWARM_KEY_BACKEND");
            }
        }
        result
    }

    fn temp_sqlite_path(name: &str) -> String {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("zkf-api-handlers-{name}-{nonce}.sqlite"))
            .display()
            .to_string()
    }

    async fn test_state(name: &str) -> AppState {
        let db = Arc::new(
            crate::db::Database::open(&temp_sqlite_path(name), crate::db::DeploymentMode::Test)
                .expect("db"),
        );
        let job_queue = Arc::new(crate::jobs::JobQueue::new(db.clone()).await);
        AppState {
            db,
            job_queue,
            rate_limiter: Arc::new(crate::metering::RateLimiter::new()),
        }
    }

    fn demo_ir_program() -> Program {
        Program {
            name: "demo".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".to_string()),
                rhs: Expr::Signal("x".to_string()),
                label: Some("self".to_string()),
            }],
            witness_plan: Default::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    fn demo_zir_program() -> zir_v1::Program {
        zir_v1::Program {
            name: "demo-zir".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                zir_v1::Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
                zir_v1::Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir_v1::Constraint::Equal {
                lhs: zir_v1::Expr::Signal("y".to_string()),
                rhs: zir_v1::Expr::Add(vec![
                    zir_v1::Expr::Signal("x".to_string()),
                    zir_v1::Expr::Const(FieldElement::from_i64(1)),
                ]),
                label: Some("eq".to_string()),
            }],
            witness_plan: zir_v1::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: Default::default(),
        }
    }

    #[test]
    fn resolve_program_request_accepts_forced_zir_v1() {
        let value = serde_json::to_value(demo_zir_program()).expect("zir program json");
        let resolved = resolve_program_request(value, Some("zir-v1")).expect("resolve zir");
        assert_eq!(resolved.source_ir_family, "zir-v1");
        assert_eq!(resolved.program.field, FieldId::Bn254);
        assert_eq!(resolved.program.constraints.len(), 1);
    }

    #[test]
    fn resolve_program_request_auto_prefers_ir_v2_when_present() {
        let value = serde_json::to_value(demo_ir_program()).expect("ir program json");
        let resolved = resolve_program_request(value, Some("auto")).expect("resolve ir");
        assert_eq!(resolved.source_ir_family, "ir-v2");
        assert_eq!(resolved.program.name, "demo");
    }

    #[tokio::test]
    async fn api_entrypoint_middleware_logs_health_requests() {
        with_temp_home_async(async {
            let app = Router::new()
                .route("/health", get(health))
                .layer(middleware::from_fn(observe_api_entrypoint));

            let response = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/health")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);

            let entrypoints_dir = SwarmConfig::from_env().swarm_root().join("entrypoints");
            let mut entries = fs::read_dir(&entrypoints_dir)
                .expect("entrypoints dir")
                .collect::<Result<Vec<_>, _>>()
                .expect("read dir");
            entries.sort_by_key(|entry| entry.file_name());
            assert_eq!(entries.len(), 1);
            let payload = fs::read_to_string(entries[0].path()).expect("payload");
            assert!(payload.contains("\"surface\": \"api\""));
            assert!(payload.contains("\"name\": \"GET /health\""));
        })
        .await;
    }

    #[tokio::test]
    async fn protected_prove_endpoint_requires_bearer_auth() {
        let state = test_state("prove-auth").await;
        let app = Router::new()
            .route("/v1/prove", post(prove))
            .with_state(state.clone());

        let body = serde_json::to_vec(&ProveRequest {
            program: serde_json::to_value(demo_ir_program()).expect("program"),
            ir_family: None,
            inputs: serde_json::json!({"x": FieldElement::from_i64(1)}),
            backend: Some("plonky3".to_string()),
            mode: None,
            hybrid: None,
        })
        .expect("request json");
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/prove")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        state.job_queue.shutdown().await;
    }

    #[tokio::test]
    async fn status_endpoint_is_owner_scoped() {
        let state = test_state("status-owner").await;
        state
            .db
            .create_api_key("owner-one", "developer", None)
            .expect("owner one");
        state
            .db
            .create_api_key("owner-two", "developer", None)
            .expect("owner two");
        state
            .db
            .create_job(
                "owner-one-job",
                &auth::hash_api_key("owner-one"),
                "prove",
                "{\"queued\":true}",
            )
            .expect("job");

        let app = Router::new()
            .route("/v1/status/{id}", get(status))
            .route("/v1/jobs/{id}", get(status))
            .with_state(state.clone());

        let owner_one = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status/owner-one-job")
                    .header("authorization", "Bearer owner-one")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(owner_one.status(), StatusCode::OK);

        let owner_two = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/jobs/owner-one-job")
                    .header("authorization", "Bearer owner-two")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(owner_two.status(), StatusCode::NOT_FOUND);

        let missing_auth = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status/owner-one-job")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);
        state.job_queue.shutdown().await;
    }

    fn sample_signed_credential_and_paths() -> (
        IssuerSignedCredentialV1,
        Vec<MerklePathNodeV1>,
        Vec<MerklePathNodeV1>,
    ) {
        let subject_secret = b"subject-secret";
        let subject_salt = b"subject-salt";
        let subject_key_hash =
            zkf_core::derive_subject_key_hash(subject_secret, subject_salt).expect("subject hash");
        let mut claims = CredentialClaimsV1 {
            subject_key_hash,
            age_years: 29,
            status_flags: CredentialClaimsV1::STATUS_KYC_PASSED
                | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
            expires_at_epoch_day: 20_111,
            issuer_tree_root: FieldElement::ZERO,
            active_tree_root: FieldElement::ZERO,
            tree_depth: CredentialClaimsV1::FIXED_TREE_DEPTH,
        };
        let credential_id = credential_id_from_claims(&claims).expect("credential id");
        let active_leaf = active_leaf_from_credential_id(&credential_id).expect("active leaf");

        let mut issuer_registry = PrivateIdentityRegistryV1::zeroed();
        let mut active_registry = PrivateIdentityRegistryV1::zeroed();
        issuer_registry
            .set_leaf(6, credential_id)
            .expect("issuer leaf");
        active_registry
            .set_leaf(6, active_leaf)
            .expect("active leaf");
        claims.issuer_tree_root = issuer_registry.root().expect("issuer root");
        claims.active_tree_root = active_registry.root().expect("active root");

        let message = claims.canonical_bytes().expect("canonical bytes");
        let ed25519_signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keypair = generate_key_pair([5u8; KEY_GENERATION_RANDOMNESS_SIZE]);
        let ml_dsa_signature = mldsa_sign(
            &keypair.signing_key,
            &message,
            PRIVATE_IDENTITY_ML_DSA_CONTEXT,
            [9u8; SIGNING_RANDOMNESS_SIZE],
        )
        .expect("ml-dsa sign");

        let signed_credential = IssuerSignedCredentialV1 {
            claims,
            issuer_public_keys: zkf_core::PublicKeyBundle {
                scheme: zkf_core::SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signing_key.verifying_key().to_bytes().to_vec(),
                ml_dsa87: keypair.verification_key.as_slice().to_vec(),
            },
            issuer_signature_bundle: zkf_core::SignatureBundle {
                scheme: zkf_core::SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signing_key.sign(&message).to_bytes().to_vec(),
                ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
            },
        };

        let issuer_path = issuer_registry.authentication_path(6).expect("issuer path");
        let active_path = active_registry.authentication_path(6).expect("active path");
        (signed_credential, issuer_path, active_path)
    }

    #[test]
    fn credential_api_roundtrip_and_fail_closed_bundle_check() {
        let (signed_credential, issuer_path, active_path) = sample_signed_credential_and_paths();
        let surface = CredentialPolicySurfaceRequest {
            issuer_tree_root: signed_credential.claims.issuer_tree_root.clone(),
            active_tree_root: signed_credential.claims.active_tree_root.clone(),
            required_age: 21,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 20_000,
        };
        let prove = run_credential_prove(&CredentialProveRequest {
            signed_credential: signed_credential.clone(),
            subject_secret: "subject-secret".to_string(),
            subject_salt: "subject-salt".to_string(),
            issuer_path: issuer_path.clone(),
            active_path: active_path.clone(),
            surface: surface.clone(),
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        })
        .expect("credential prove");

        let age_error = run_credential_prove(&CredentialProveRequest {
            signed_credential: signed_credential.clone(),
            subject_secret: "subject-secret".to_string(),
            subject_salt: "subject-salt".to_string(),
            issuer_path: issuer_path.clone(),
            active_path: active_path.clone(),
            surface: CredentialPolicySurfaceRequest {
                required_age: 40,
                ..surface.clone()
            },
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        })
        .expect_err("underage prove request should fail");
        assert!(age_error.contains("required age"));

        let status_error = run_credential_prove(&CredentialProveRequest {
            signed_credential: signed_credential.clone(),
            subject_secret: "subject-secret".to_string(),
            subject_salt: "subject-salt".to_string(),
            issuer_path: issuer_path.clone(),
            active_path: active_path.clone(),
            surface: CredentialPolicySurfaceRequest {
                required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED
                    | CredentialClaimsV1::STATUS_ACCREDITED,
                ..surface.clone()
            },
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        })
        .expect_err("status-mismatched prove request should fail");
        assert!(status_error.contains("required mask"));

        let expiry_error = run_credential_prove(&CredentialProveRequest {
            signed_credential: signed_credential.clone(),
            subject_secret: "subject-secret".to_string(),
            subject_salt: "subject-salt".to_string(),
            issuer_path: issuer_path.clone(),
            active_path: active_path.clone(),
            surface: CredentialPolicySurfaceRequest {
                current_epoch_day: 20_200,
                ..surface.clone()
            },
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        })
        .expect_err("expired prove request should fail");
        assert!(expiry_error.contains("expired"));

        let artifact: ProofArtifact =
            serde_json::from_value(prove.get("proof").cloned().expect("proof field"))
                .expect("artifact json");

        run_credential_verify(&CredentialVerifyRequest {
            artifact: artifact.clone(),
            surface: surface.clone(),
        })
        .expect("credential verify");

        let wrong_root_error = run_credential_verify(&CredentialVerifyRequest {
            artifact: artifact.clone(),
            surface: CredentialPolicySurfaceRequest {
                issuer_tree_root: FieldElement::from_i64(1),
                ..surface.clone()
            },
        })
        .expect_err("wrong issuer root must fail");
        assert!(wrong_root_error.contains("expected policy/root surface"));

        let mut tampered_signature = artifact.clone();
        tampered_signature
            .credential_bundle
            .as_mut()
            .expect("credential bundle")
            .signed_credential
            .issuer_signature_bundle
            .ed25519[0] ^= 0x01;
        let tampered_signature_error = run_credential_verify(&CredentialVerifyRequest {
            artifact: tampered_signature,
            surface: surface.clone(),
        })
        .expect_err("tampered credential signature must fail");
        assert!(tampered_signature_error.contains("issuer signature bundle failed verification"));

        let mut tampered_mode = artifact.clone();
        tampered_mode.metadata.insert(
            "credential_verification_mode".to_string(),
            "tampered-mode".to_string(),
        );
        let tampered_mode_error = run_credential_verify(&CredentialVerifyRequest {
            artifact: tampered_mode,
            surface: surface.clone(),
        })
        .expect_err("tampered credential verification mode must fail");
        assert!(tampered_mode_error.contains("verification mode mismatch"));

        let mut missing_bundle = artifact;
        missing_bundle.credential_bundle = None;
        let error = run_credential_verify(&CredentialVerifyRequest {
            artifact: missing_bundle,
            surface,
        })
        .expect_err("missing credential bundle must fail");
        assert!(error.contains("credential bundle"));
    }
}

pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let owner_key_hash = match authorize_readonly(&state, &headers) {
        Ok(owner_key_hash) => owner_key_hash,
        Err(response) => return response,
    };

    match state.db.get_job_for_owner(&id, &owner_key_hash) {
        Ok(row) => {
            let status = match row.status.as_str() {
                "queued" => JobStatus::Queued,
                "running" => JobStatus::Running,
                "completed" => JobStatus::Completed,
                "failed" => JobStatus::Failed,
                _ => JobStatus::Queued,
            };
            let result = row.result.and_then(|r| serde_json::from_str(&r).ok());
            let security = result.as_ref().and_then(extract_job_security_verdict);
            (
                StatusCode::OK,
                Json(serde_json::json!(JobResponse {
                    id: row.id,
                    status,
                    result,
                    security,
                    error: row.error,
                    created_at: Some(row.created_at),
                    completed_at: row.completed_at,
                })),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "job not found"})),
        ),
    }
}

fn extract_job_security_verdict(result: &Value) -> Option<Value> {
    result
        .get("runtime")
        .and_then(|runtime| runtime.get("security_verdict").cloned())
        .or_else(|| result.get("runtime_security_verdict").cloned())
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateKeyRequest {
    pub tier: Option<String>,
    pub email: Option<String>,
}

pub async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    // Admin endpoint — require the admin secret from ZKF_ADMIN_SECRET env var.
    let admin_secret = std::env::var("ZKF_ADMIN_SECRET").unwrap_or_default();
    if admin_secret.is_empty() {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin endpoint not configured (set ZKF_ADMIN_SECRET)",
        );
    }
    let provided = auth::extract_api_key_from_headers(&headers);
    if provided.as_deref() != Some(admin_secret.as_str()) {
        return json_error(StatusCode::UNAUTHORIZED, "invalid admin credentials");
    }

    let key = auth::generate_api_key();
    let key_prefix = auth::api_key_prefix(&key);
    let tier = req.tier.as_deref().unwrap_or("free");
    match state.db.create_api_key(&key, tier, req.email.as_deref()) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "api_key": key,
                "key_prefix": key_prefix,
                "tier": tier,
                "email": req.email,
            })),
        ),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}
