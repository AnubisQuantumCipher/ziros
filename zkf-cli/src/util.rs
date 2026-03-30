use num_bigint::BigInt;
use num_traits::Num;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::{
    BackendRoute, CapabilityReport, GROTH16_SETUP_BLOB_PATH_METADATA_KEY,
    assurance_lane_for_backend, backend_for, backend_for_route, backend_surface_status,
    capabilities_report, gpu_stage_coverage_for_backend_field, metal_first_benchmark_backends,
    preferred_backend_for_program, prover_acceleration_claimed_for_backend,
    set_allow_dev_deterministic_groth16_override, set_groth16_setup_blob_path_override,
    set_proof_seed_override, set_setup_seed_override, strict_bn254_auto_route_ready,
};
use zkf_core::{
    BackendCapabilityMatrix, BackendKind, BackendMode, CompiledProgram, Constraint, FieldElement,
    FieldId, PackageManifest, Program, StepMode, SupportClass, Witness, WitnessInputs, ZkfError,
    ensure_witness_completeness, generate_witness, program_v2_to_zir, program_zir_to_v2,
    solve_and_validate_witness, solver_by_name,
};
use zkf_frontends::{FrontendInspection, FrontendKind};
use zkf_runtime::OptimizationObjective;

const RAW_CLI_ERROR_PREFIX: &str = "__zkf_raw_cli_error__:";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum WitnessRequirement {
    Execution,
    Solver,
    Constraint,
}

impl WitnessRequirement {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            WitnessRequirement::Execution => "execution",
            WitnessRequirement::Solver => "solver",
            WitnessRequirement::Constraint => "constraint",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct BackendRequest {
    pub(crate) backend: BackendKind,
    pub(crate) route: BackendRoute,
    pub(crate) requested_name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedWitnessArtifacts {
    pub(crate) compiled: CompiledProgram,
    pub(crate) source_witness: Witness,
    pub(crate) prepared_witness: Witness,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeExecutionRealization {
    pub(crate) execution_regime: Option<String>,
    pub(crate) gpu_stage_busy_ratio: Option<f64>,
    pub(crate) prover_acceleration_realized: Option<bool>,
    pub(crate) acceleration_label: Option<String>,
}

impl BackendRequest {
    pub(crate) fn native(backend: BackendKind) -> Self {
        Self {
            backend,
            route: BackendRoute::Auto,
            requested_name: backend.as_str().to_string(),
        }
    }
}

pub(crate) fn parse_backend(value: &str) -> Result<BackendKind, String> {
    value.parse::<BackendKind>()
}

pub(crate) fn warn_if_r1cs_lookup_limit_exceeded(
    backend: BackendKind,
    program: &Program,
    context: &str,
) {
    if backend != BackendKind::ArkworksGroth16 {
        return;
    }
    let max_rows = max_lookup_rows(program);
    if max_rows <= 256 {
        return;
    }
    eprintln!(
        "warning: {context} requested backend '{}' for a program with lookup tables up to {max_rows} rows. The Groth16/R1CS lowering path supports at most 256 rows; use --backend plonky3 or --backend halo2 for native lookup support.",
        backend.as_str()
    );
}

fn max_lookup_rows(program: &Program) -> usize {
    program
        .lookup_tables
        .iter()
        .map(|table| table.values.len())
        .max()
        .unwrap_or(0)
}

pub(crate) fn parse_backend_request(value: &str) -> Result<BackendRequest, String> {
    match value {
        "sp1-compat" | "sp1_compat" => Ok(BackendRequest {
            backend: BackendKind::Sp1,
            route: BackendRoute::ExplicitCompat,
            requested_name: "sp1-compat".to_string(),
        }),
        "risc-zero-compat" | "risc_zero_compat" | "risc0-compat" | "risc0_compat" => {
            Ok(BackendRequest {
                backend: BackendKind::RiscZero,
                route: BackendRoute::ExplicitCompat,
                requested_name: "risc-zero-compat".to_string(),
            })
        }
        other => Ok(BackendRequest {
            backend: parse_backend(other)?,
            route: BackendRoute::Auto,
            requested_name: other.to_string(),
        }),
    }
}

pub(crate) fn backend_for_request(
    request: &BackendRequest,
) -> Box<dyn zkf_backends::BackendEngine> {
    backend_for_route(request.backend, request.route)
}

pub(crate) fn backend_route_label(route: BackendRoute) -> &'static str {
    match route {
        BackendRoute::Auto => "native-auto",
        BackendRoute::ExplicitCompat => "explicit-compat",
    }
}

pub(crate) fn annotate_compiled_for_request(
    compiled: &mut CompiledProgram,
    request: &BackendRequest,
) {
    compiled.metadata.insert(
        "backend_route".to_string(),
        backend_route_label(request.route).to_string(),
    );
    compiled.metadata.insert(
        "requested_backend_name".to_string(),
        request.requested_name.clone(),
    );
}

pub(crate) fn compiled_matches_request(
    compiled: &CompiledProgram,
    request: &BackendRequest,
) -> bool {
    match compiled.metadata.get("backend_route").map(String::as_str) {
        Some(route) => route == backend_route_label(request.route),
        None => request.route == BackendRoute::Auto,
    }
}

pub(crate) fn validate_compiled_artifact_for_request(
    compiled: &CompiledProgram,
    request: &BackendRequest,
    expected_program_digest: &str,
    source: &str,
) -> Result<(), String> {
    let compiled_source_digest = compiled
        .original_program
        .as_ref()
        .map(Program::digest_hex)
        .unwrap_or_else(|| compiled.program_digest.clone());
    if compiled.backend != request.backend {
        return Err(format!(
            "{source} backend mismatch: found {}, expected {}",
            compiled.backend, request.backend
        ));
    }
    if compiled_source_digest != expected_program_digest {
        return Err(format!(
            "{source} program digest mismatch: expected {}, found {}",
            expected_program_digest, compiled_source_digest
        ));
    }
    if !compiled_matches_request(compiled, request) {
        return Err(format!(
            "{source} route mismatch: found {:?}, expected {}",
            compiled.metadata.get("backend_route"),
            backend_route_label(request.route)
        ));
    }
    Ok(())
}

pub(crate) fn compile_program_for_request_with_overrides(
    program: &Program,
    request: &BackendRequest,
    seed: Option<[u8; 32]>,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
    context: &str,
) -> Result<CompiledProgram, String> {
    let mut program = program.clone();
    attach_groth16_setup_blob_path(&mut program, request.backend, groth16_setup_blob);
    ensure_backend_supports_program_constraints(request.backend, &program)?;
    warn_if_r1cs_lookup_limit_exceeded(request.backend, &program, context);
    let groth16_setup_blob_override = groth16_setup_blob.map(path_to_override_string);
    let engine = backend_for_request(request);
    let mut compiled = with_allow_dev_deterministic_groth16_override(
        allow_dev_deterministic_groth16.then_some(true),
        || {
            with_groth16_setup_blob_path_override(groth16_setup_blob_override, || {
                with_setup_seed_override(seed, || {
                    engine.compile(&program).map_err(render_zkf_error)
                })
            })
        },
    )?;
    annotate_compiled_for_request(&mut compiled, request);
    Ok(compiled)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_compiled_artifact_for_request(
    program: &Program,
    request: &BackendRequest,
    candidate: Option<CompiledProgram>,
    strict_candidate: bool,
    seed: Option<[u8; 32]>,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
    context: &str,
) -> Result<(CompiledProgram, bool), String> {
    let expected_program_digest = program.digest_hex();
    if let Some(compiled) = candidate {
        match validate_compiled_artifact_for_request(
            &compiled,
            request,
            &expected_program_digest,
            "compiled artifact",
        ) {
            Ok(()) => return Ok((compiled, false)),
            Err(err) if strict_candidate => return Err(err),
            Err(_) => {}
        }
    }

    Ok((
        compile_program_for_request_with_overrides(
            program,
            request,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            context,
        )?,
        true,
    ))
}

pub(crate) fn source_witness_from_inputs(
    program: &Program,
    inputs: &WitnessInputs,
    solver_name: Option<&str>,
) -> Result<Witness, String> {
    match solver_name {
        Some(solver_name) => {
            let solver = solver_by_name(solver_name).map_err(render_zkf_error)?;
            solve_and_validate_witness(program, inputs, solver.as_ref()).map_err(render_zkf_error)
        }
        None => generate_witness(program, inputs).map_err(render_zkf_error),
    }
}

pub(crate) fn prepare_existing_source_witness(
    compiled: &CompiledProgram,
    source_witness: &Witness,
) -> Result<Witness, String> {
    let prepared = zkf_backends::prepare_witness_for_proving(compiled, source_witness)
        .map_err(render_zkf_error)?;
    ensure_witness_completeness(&compiled.program, &prepared).map_err(render_zkf_error)?;
    Ok(prepared)
}

pub(crate) fn project_witness_to_program(program: &Program, witness: &Witness) -> Witness {
    let values = program
        .signals
        .iter()
        .filter_map(|signal| {
            witness
                .values
                .get(&signal.name)
                .cloned()
                .map(|value| (signal.name.clone(), value))
        })
        .collect();
    Witness { values }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_witness_for_request_from_inputs(
    source_program: &Program,
    inputs: &WitnessInputs,
    solver_name: Option<&str>,
    request: &BackendRequest,
    seed: Option<[u8; 32]>,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
    context: &str,
) -> Result<PreparedWitnessArtifacts, String> {
    let mut resolved_inputs = inputs.clone();
    resolve_input_aliases(&mut resolved_inputs, source_program);
    let (compiled, _) = resolve_compiled_artifact_for_request(
        source_program,
        request,
        None,
        false,
        seed,
        groth16_setup_blob,
        allow_dev_deterministic_groth16,
        context,
    )?;

    let source_witness =
        match source_witness_from_inputs(source_program, &resolved_inputs, solver_name) {
            Ok(witness) => witness,
            Err(source_err) if solver_name.is_none() => {
                match generate_witness(&compiled.program, &resolved_inputs) {
                    Ok(compiled_witness) => {
                        project_witness_to_program(source_program, &compiled_witness)
                    }
                    Err(_) => return Err(source_err),
                }
            }
            Err(err) => return Err(err),
        };

    let prepared_witness = if solver_name.is_none() {
        match generate_witness(&compiled.program, &resolved_inputs) {
            Ok(witness) => {
                ensure_witness_completeness(&compiled.program, &witness)
                    .map_err(render_zkf_error)?;
                witness
            }
            Err(_) => prepare_existing_source_witness(&compiled, &source_witness)?,
        }
    } else {
        prepare_existing_source_witness(&compiled, &source_witness)?
    };

    Ok(PreparedWitnessArtifacts {
        compiled,
        source_witness,
        prepared_witness,
    })
}

pub(crate) fn runtime_execution_realization(
    metadata: &BTreeMap<String, String>,
) -> RuntimeExecutionRealization {
    let execution_regime = metadata.get("runtime_execution_regime").cloned();
    let gpu_stage_busy_ratio = metadata
        .get("runtime_gpu_stage_busy_ratio")
        .and_then(|value| value.parse::<f64>().ok());
    let prover_acceleration_realized = metadata
        .get("runtime_prover_acceleration_realized")
        .and_then(|value| value.parse::<bool>().ok())
        .or_else(|| gpu_stage_busy_ratio.map(|ratio| ratio > 0.0));
    let acceleration_label = Some(match prover_acceleration_realized {
        Some(true) => "gpu-realized".to_string(),
        Some(false) => "cpu-only-realized".to_string(),
        None => "unknown".to_string(),
    });

    RuntimeExecutionRealization {
        execution_regime,
        gpu_stage_busy_ratio,
        prover_acceleration_realized,
        acceleration_label,
    }
}

fn path_to_override_string(path: &Path) -> String {
    path.display().to_string()
}

pub(crate) fn parse_frontend(value: &str) -> Result<FrontendKind, String> {
    value.parse::<FrontendKind>()
}

pub(crate) fn parse_field(value: &str) -> Result<FieldId, String> {
    value.parse::<FieldId>()
}

pub(crate) fn parse_optimization_objective(
    value: Option<&str>,
) -> Result<OptimizationObjective, String> {
    match value {
        Some(value) => value.parse::<OptimizationObjective>(),
        None => Ok(OptimizationObjective::FastestProve),
    }
}

pub(crate) fn parse_prove_mode(value: Option<&str>) -> Result<Option<&'static str>, String> {
    match value {
        None => Ok(None),
        Some("metal-first" | "metal_first") => Ok(Some("metal-first")),
        Some(other) => Err(format!(
            "unknown prove mode '{other}' (expected metal-first)"
        )),
    }
}

pub(crate) fn parse_export_scheme(value: Option<&str>) -> Result<Option<&'static str>, String> {
    match value {
        None => Ok(None),
        Some("groth16") => Ok(Some("groth16")),
        Some(other) => Err(format!(
            "unknown export scheme '{other}' (expected groth16)"
        )),
    }
}

pub(crate) fn default_prove_mode() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", feature = "metal-gpu")) {
        Some("metal-first")
    } else {
        None
    }
}

fn resolve_metal_first_backend(program: &Program) -> Result<BackendKind, String> {
    let backend = preferred_backend_for_program(program);
    let coverage = gpu_stage_coverage_for_backend_field(backend, Some(program.field));
    let is_certified_bn254_strict = backend == BackendKind::ArkworksGroth16
        && program.field == FieldId::Bn254
        && strict_bn254_auto_route_ready();
    let is_metal_complete = is_certified_bn254_strict
        || (prover_acceleration_claimed_for_backend(backend)
            && !coverage.required_stages.is_empty()
            && coverage.cpu_stages.is_empty());
    if is_metal_complete {
        ensure_backend_is_metal_complete_for_program(backend, program)?;
        return Ok(backend);
    }

    if backend == BackendKind::ArkworksGroth16 && program.field == FieldId::Bn254 {
        return Err(format!(
            "mode metal-first requires the certified strict BN254 route on hardware_profile=apple-silicon-m4-max-48gb with active metal witness-map and MSM stages, but '{}' is unavailable on this host (cpu stages: {}). Pass --backend explicitly to use the CPU/export path, or run on the certified host with the Metal production build.",
            backend,
            if coverage.cpu_stages.is_empty() {
                "not-claimed".to_string()
            } else {
                coverage.cpu_stages.join(",")
            }
        ));
    }

    Err(format!(
        "mode metal-first requires a metal-complete backend for field '{}' but '{}' is not metal-complete (cpu stages: {}). Pass --backend explicitly to use the CPU/export path, or use a Metal-native proving field/backend.",
        program.field,
        backend,
        if coverage.cpu_stages.is_empty() {
            "not-claimed".to_string()
        } else {
            coverage.cpu_stages.join(",")
        }
    ))
}

fn ensure_backend_is_metal_complete_for_program(
    backend: BackendKind,
    program: &Program,
) -> Result<(), String> {
    if backend != BackendKind::Plonky3 {
        return Ok(());
    }

    let compiled = backend_for(backend)
        .compile(program)
        .map_err(|err| format!("failed to inspect Metal suitability for '{backend}': {err}"))?;
    let trace_width = compiled
        .metadata
        .get("trace_width")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(program.signals.len());

    if trace_width > 8 {
        return Err(format!(
            "mode metal-first requires a metal-complete backend for field '{}' but '{}' lowers to trace width {trace_width}, which exceeds the current Metal MMCS width limit of 8. Pass --backend explicitly to use the CPU/export path, or reduce the lowered trace width.",
            program.field, backend
        ));
    }

    Ok(())
}

pub(crate) fn resolve_backend_or_mode(
    backend: Option<&str>,
    mode: Option<&str>,
    program: &Program,
    objective: OptimizationObjective,
) -> Result<BackendRequest, String> {
    if let Some(backend) = backend {
        if backend == "auto" {
            return auto_backend_request(program, objective);
        }
        return parse_backend_request(backend);
    }

    match parse_prove_mode(mode)? {
        Some("metal-first") => resolve_metal_first_backend(program).map(BackendRequest::native),
        _ => auto_backend_request(program, objective),
    }
}

pub(crate) fn resolve_backend_targets_or_mode(
    selected_backends: &[BackendRequest],
    mode: Option<&str>,
    program: &Program,
    _manifest_targets: &[BackendKind],
) -> Result<Vec<BackendRequest>, String> {
    if !selected_backends.is_empty() {
        return Ok(selected_backends.to_vec());
    }

    match parse_prove_mode(mode)? {
        Some("metal-first") => Ok(vec![BackendRequest::native(resolve_metal_first_backend(
            program,
        )?)]),
        _ => Ok(default_package_prove_all_requests()),
    }
}

pub(crate) fn default_package_prove_all_requests() -> Vec<BackendRequest> {
    capabilities_report()
        .into_iter()
        .filter(|report| {
            report.production_ready && report.implementation_type != SupportClass::Delegated
        })
        .map(|report| BackendRequest::native(report.capabilities.backend))
        .collect()
}

fn auto_backend_request(
    program: &Program,
    objective: OptimizationObjective,
) -> Result<BackendRequest, String> {
    if program.metadata.get("frontend").map(String::as_str) == Some("compact")
        && let Some(preferred_backend) = program.metadata.get("preferred_backend")
    {
        return parse_backend_request(preferred_backend).map_err(|err| {
            format!(
                "invalid Compact preferred backend hint '{}': {err}",
                preferred_backend
            )
        });
    }

    if matches!(
        program.field,
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31
    ) {
        return Ok(BackendRequest::native(
            zkf_runtime::recommend_backend_for_program(program, None, objective).selected,
        ));
    }

    Err(format!(
        "no default backend is selected for field '{}'. Omitted --backend now defaults only to transparent Plonky3 fields (goldilocks, babybear, mersenne31). Pass --backend explicitly for {} circuits.",
        program.field, program.field
    ))
}

pub(crate) fn parse_step_mode(value: &str) -> Result<StepMode, String> {
    match value {
        "reuse-inputs" | "reuse_inputs" | "reuse" => Ok(StepMode::ReuseInputs),
        "chain-public-outputs" | "chain_public_outputs" | "chain" => {
            Ok(StepMode::ChainPublicOutputs)
        }
        other => Err(format!(
            "unknown step mode '{other}' (expected reuse-inputs or chain-public-outputs)"
        )),
    }
}

pub(crate) fn parse_setup_seed(value: &str) -> Result<[u8; 32], String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err("setup seed cannot be empty".to_string());
    }

    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .ok_or_else(|| format!("invalid hex seed nibble '{}'", chunk[0] as char))?;
            let low = (chunk[1] as char)
                .to_digit(16)
                .ok_or_else(|| format!("invalid hex seed nibble '{}'", chunk[1] as char))?;
            out[index] = ((high << 4) | low) as u8;
        }
        return Ok(out);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"zkf-cli-setup-seed-v1");
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub(crate) fn annotate_artifact_with_runtime_report(
    artifact: &mut zkf_core::ProofArtifact,
    result: &zkf_runtime::PlanExecutionResult,
) {
    let report = &result.report;
    artifact
        .metadata
        .insert("umpg_execution".to_string(), "true".to_string());
    artifact.metadata.insert(
        "umpg_node_count".to_string(),
        report.node_traces.len().to_string(),
    );
    artifact.metadata.insert(
        "umpg_delegated_nodes".to_string(),
        report.delegated_nodes.to_string(),
    );
    artifact
        .metadata
        .insert("gpu_nodes".to_string(), report.gpu_nodes.to_string());
    artifact
        .metadata
        .insert("cpu_nodes".to_string(), report.cpu_nodes.to_string());
    artifact.metadata.insert(
        "fallback_nodes".to_string(),
        report.fallback_nodes.to_string(),
    );
    artifact.metadata.insert(
        "peak_memory_bytes".to_string(),
        report.peak_memory_bytes.to_string(),
    );
    artifact.metadata.insert(
        "runtime_gpu_stage_busy_ratio".to_string(),
        format!("{:.6}", report.gpu_stage_busy_ratio()),
    );
    artifact.metadata.insert(
        "runtime_gpu_wall_time_ms".to_string(),
        format!("{:.3}", report.gpu_wall_time().as_secs_f64() * 1000.0),
    );
    artifact.metadata.insert(
        "runtime_cpu_wall_time_ms".to_string(),
        format!("{:.3}", report.cpu_wall_time().as_secs_f64() * 1000.0),
    );
    if let Ok(stage_breakdown) = serde_json::to_string(&report.stage_breakdown()) {
        artifact
            .metadata
            .insert("runtime_stage_breakdown".to_string(), stage_breakdown);
    }
    if let Some(control_plane) = &result.control_plane {
        artifact.metadata.insert(
            "runtime_optimization_objective".to_string(),
            control_plane
                .decision
                .backend_recommendation
                .objective
                .as_str()
                .to_string(),
        );
        artifact.metadata.insert(
            "runtime_job_kind".to_string(),
            control_plane.decision.job_kind.as_str().to_string(),
        );
        artifact.metadata.insert(
            "runtime_dispatch_candidate".to_string(),
            control_plane
                .decision
                .dispatch_plan
                .candidate
                .as_str()
                .to_string(),
        );
        artifact.metadata.insert(
            "runtime_predicted_duration_ms".to_string(),
            format!(
                "{:.3}",
                control_plane.decision.duration_estimate.estimate_ms
            ),
        );
        artifact.metadata.insert(
            "runtime_duration_estimate_ms".to_string(),
            format!(
                "{:.3}",
                control_plane.decision.duration_estimate.estimate_ms
            ),
        );
        if let Some(upper_bound_ms) = control_plane.decision.duration_estimate.upper_bound_ms {
            artifact.metadata.insert(
                "runtime_duration_upper_bound_ms".to_string(),
                format!("{upper_bound_ms:.3}"),
            );
        }
        artifact.metadata.insert(
            "runtime_execution_regime".to_string(),
            control_plane
                .decision
                .duration_estimate
                .execution_regime
                .as_str()
                .to_string(),
        );
        artifact.metadata.insert(
            "runtime_eta_semantics".to_string(),
            control_plane
                .decision
                .duration_estimate
                .eta_semantics
                .as_str()
                .to_string(),
        );
        artifact.metadata.insert(
            "runtime_duration_bound_source".to_string(),
            control_plane
                .decision
                .duration_estimate
                .bound_source
                .as_str()
                .to_string(),
        );
        artifact.metadata.insert(
            "runtime_duration_countdown_safe".to_string(),
            control_plane
                .decision
                .duration_estimate
                .countdown_safe
                .to_string(),
        );
        if let Some(note) = &control_plane.decision.duration_estimate.note {
            artifact
                .metadata
                .insert("runtime_duration_note".to_string(), note.clone());
        }
        artifact.metadata.insert(
            "runtime_dispatch_plan_json".to_string(),
            serde_json::to_string(&control_plane.decision.dispatch_plan)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_dispatch_candidate_rankings_json".to_string(),
            serde_json::to_string(&control_plane.decision.candidate_rankings)
                .unwrap_or_else(|_| "[]".to_string()),
        );
        artifact.metadata.insert(
            "runtime_backend_recommendation_json".to_string(),
            serde_json::to_string(&control_plane.decision.backend_recommendation)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_duration_estimate_json".to_string(),
            serde_json::to_string(&control_plane.decision.duration_estimate)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_anomaly_verdict_json".to_string(),
            serde_json::to_string(&control_plane.anomaly_verdict)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_model_catalog_json".to_string(),
            serde_json::to_string(&control_plane.decision.model_catalog)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_control_plane_features_json".to_string(),
            serde_json::to_string(&control_plane.decision.features)
                .unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_realized_gpu_capable_stages_json".to_string(),
            serde_json::to_string(&control_plane.realized_gpu_capable_stages)
                .unwrap_or_else(|_| "[]".to_string()),
        );
        if let Some(interpretation) = &control_plane.anomaly_verdict.duration_interpretation {
            artifact.metadata.insert(
                "runtime_duration_interpretation".to_string(),
                interpretation.clone(),
            );
        }
        let acceleration_realized = !control_plane.realized_gpu_capable_stages.is_empty();
        artifact.metadata.insert(
            "runtime_prover_acceleration_realized".to_string(),
            acceleration_realized.to_string(),
        );
        if !acceleration_realized {
            artifact.metadata.insert(
                "prover_acceleration_claimed".to_string(),
                "false".to_string(),
            );
            artifact.metadata.insert(
                "prover_acceleration_scope".to_string(),
                "not-realized-cpu-only-fallback".to_string(),
            );
            artifact.metadata.insert(
                "runtime_prover_acceleration_note".to_string(),
                "planned accelerator-capable route realized no GPU-capable stages; treat this run as CPU-only"
                    .to_string(),
            );
        }
    }
    if let Some(security) = &result.security {
        artifact.metadata.insert(
            "runtime_security_risk_level".to_string(),
            security.risk_level.as_str().to_string(),
        );
        if let Some(risk_score) = security.risk_score {
            artifact.metadata.insert(
                "runtime_security_risk_score".to_string(),
                format!("{risk_score:.6}"),
            );
        }
        artifact.metadata.insert(
            "runtime_security_countdown_safe".to_string(),
            security.countdown_safe.to_string(),
        );
        artifact.metadata.insert(
            "runtime_security_reason".to_string(),
            security.reason.clone(),
        );
        artifact.metadata.insert(
            "runtime_security_verdict_json".to_string(),
            serde_json::to_string(security).unwrap_or_else(|_| "{}".to_string()),
        );
        artifact.metadata.insert(
            "runtime_security_signals_json".to_string(),
            serde_json::to_string(&security.signals).unwrap_or_else(|_| "[]".to_string()),
        );
        artifact.metadata.insert(
            "runtime_security_actions_json".to_string(),
            serde_json::to_string(&security.actions).unwrap_or_else(|_| "[]".to_string()),
        );
    }
    if let Some(model_integrity) = &result.model_integrity {
        artifact.metadata.insert(
            "runtime_model_integrity_json".to_string(),
            serde_json::to_string(model_integrity).unwrap_or_else(|_| "{}".to_string()),
        );
    }
}

const REQUIRED_V2_MANIFEST_METADATA_KEYS: [&str; 6] = [
    "ir_family",
    "ir_version",
    "strict_mode",
    "requires_execution",
    "requires_solver",
    "allow_builtin_fallback",
];

pub(crate) fn validate_v2_manifest_metadata(manifest: &PackageManifest) -> Vec<String> {
    if manifest.schema_version < 2 {
        return Vec::new();
    }

    let mut issues = Vec::new();
    for key in REQUIRED_V2_MANIFEST_METADATA_KEYS {
        match manifest.metadata.get(key) {
            Some(value) if !value.trim().is_empty() => {}
            _ => issues.push(format!("missing required manifest metadata key '{key}'")),
        }
    }

    for key in [
        "strict_mode",
        "requires_execution",
        "requires_solver",
        "allow_builtin_fallback",
    ] {
        if let Some(value) = manifest.metadata.get(key)
            && !matches!(value.as_str(), "true" | "false")
        {
            issues.push(format!(
                "manifest metadata key '{key}' must be 'true' or 'false', found '{value}'"
            ));
        }
    }

    if let Some(value) = manifest.metadata.get("ir_version")
        && value.parse::<u32>().is_err()
    {
        issues.push(format!(
            "manifest metadata key 'ir_version' must be a non-negative integer, found '{value}'"
        ));
    }

    if let (Some(ir_family), Some(ir_version)) = (
        manifest.metadata.get("ir_family"),
        manifest.metadata.get("ir_version"),
    ) {
        match ir_family.as_str() {
            "ir-v2" => {
                if ir_version != "2" {
                    issues.push(format!(
                        "manifest metadata ir_family='ir-v2' must use ir_version='2', found '{ir_version}'"
                    ));
                }
            }
            "zir-v1" => {
                if ir_version != "1" {
                    issues.push(format!(
                        "manifest metadata ir_family='zir-v1' must use ir_version='1', found '{ir_version}'"
                    ));
                }
            }
            other => {
                issues.push(format!(
                    "unsupported manifest ir_family '{other}' (expected 'ir-v2' or 'zir-v1')"
                ));
            }
        }
    }

    issues
}

pub(crate) fn validate_v2_run_report(path: &Path) -> Result<Vec<String>, String> {
    let mut issues = Vec::new();
    if !path.exists() {
        return Ok(issues);
    }

    let report: Value = read_json(path)?;
    let Some(obj) = report.as_object() else {
        issues.push(format!(
            "run report '{}' is not a JSON object",
            path.display()
        ));
        return Ok(issues);
    };

    let mut solver_path_value = None::<String>;
    let mut execution_path_value = None::<String>;

    match obj.get("solver_path") {
        Some(Value::String(value)) if !value.trim().is_empty() => {
            solver_path_value = Some(value.clone());
        }
        Some(Value::String(_)) => issues.push(format!(
            "run report '{}' key 'solver_path' must not be empty",
            path.display()
        )),
        Some(value) => issues.push(format!(
            "run report '{}' key 'solver_path' must be a string, found {}",
            path.display(),
            value
        )),
        None => issues.push(format!(
            "run report '{}' is missing required key 'solver_path'",
            path.display()
        )),
    }
    match obj.get("execution_path") {
        Some(Value::String(value)) if !value.trim().is_empty() => {
            execution_path_value = Some(value.clone());
        }
        Some(Value::String(_)) => issues.push(format!(
            "run report '{}' key 'execution_path' must not be empty",
            path.display()
        )),
        Some(value) => issues.push(format!(
            "run report '{}' key 'execution_path' must be a string, found {}",
            path.display(),
            value
        )),
        None => issues.push(format!(
            "run report '{}' is missing required key 'execution_path'",
            path.display()
        )),
    }
    for key in ["requires_execution", "requires_solver"] {
        match obj.get(key) {
            Some(Value::Bool(_)) => {}
            Some(value) => issues.push(format!(
                "run report '{}' key '{}' must be a boolean, found {}",
                path.display(),
                key,
                value
            )),
            None => issues.push(format!(
                "run report '{}' is missing required key '{}'",
                path.display(),
                key
            )),
        }
    }

    if let Some(Value::Array(paths)) = obj.get("attempted_solver_paths") {
        if paths.iter().any(|value| {
            !value
                .as_str()
                .map(|item| !item.trim().is_empty())
                .unwrap_or(false)
        }) {
            issues.push(format!(
                "run report '{}' key 'attempted_solver_paths' must be an array of non-empty strings",
                path.display()
            ));
        }
    } else if obj.get("attempted_solver_paths").is_some() {
        issues.push(format!(
            "run report '{}' key 'attempted_solver_paths' must be an array",
            path.display()
        ));
    }

    if let Some(Value::Array(items)) = obj.get("solver_attempt_errors") {
        if items.iter().any(|value| {
            !value
                .as_str()
                .map(|item| !item.trim().is_empty())
                .unwrap_or(false)
        }) {
            issues.push(format!(
                "run report '{}' key 'solver_attempt_errors' must be an array of non-empty strings",
                path.display()
            ));
        }
    } else if obj.get("solver_attempt_errors").is_some() {
        issues.push(format!(
            "run report '{}' key 'solver_attempt_errors' must be an array",
            path.display()
        ));
    }

    for key in ["frontend_execution_error", "fallback_reason"] {
        match obj.get(key) {
            Some(Value::String(value)) if !value.trim().is_empty() => {}
            Some(Value::String(_)) => issues.push(format!(
                "run report '{}' key '{}' must not be empty when present",
                path.display(),
                key
            )),
            Some(value) => issues.push(format!(
                "run report '{}' key '{}' must be a string when present, found {}",
                path.display(),
                key,
                value
            )),
            None => {}
        }
    }

    let expected_paths = [
        "explicit-solver",
        "frontend-execute",
        "solver-fallback",
        "builtin-fallback",
    ];
    if let Some(execution_path) = execution_path_value.as_deref()
        && !expected_paths.contains(&execution_path)
    {
        issues.push(format!(
            "run report '{}' key 'execution_path' has unsupported value '{}'",
            path.display(),
            execution_path
        ));
    }

    if let (Some(solver_path), Some(execution_path)) = (
        solver_path_value.as_deref(),
        execution_path_value.as_deref(),
    ) {
        if execution_path == "frontend-execute" && !solver_path.starts_with("frontend/") {
            issues.push(format!(
                "run report '{}' execution_path 'frontend-execute' requires solver_path prefixed with 'frontend/', found '{}'",
                path.display(),
                solver_path
            ));
        }
        if execution_path == "builtin-fallback" && solver_path != "builtin" {
            issues.push(format!(
                "run report '{}' execution_path 'builtin-fallback' requires solver_path 'builtin', found '{}'",
                path.display(),
                solver_path
            ));
        }
        if execution_path == "explicit-solver"
            && let Some(Value::Array(paths)) = obj.get("attempted_solver_paths")
        {
            let has_solver = paths
                .iter()
                .any(|value| value.as_str().is_some_and(|item| item == solver_path));
            if !has_solver {
                issues.push(format!(
                    "run report '{}' explicit-solver path must include solver_path '{}' in attempted_solver_paths",
                    path.display(),
                    solver_path
                ));
            }
        }
    }

    Ok(issues)
}

fn parse_compose_artifact_key<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = key.strip_prefix(prefix)?;
    let mut parts = rest.split('/');
    let backend = parts.next()?;
    let run_id = parts.next()?;
    if parts.next().is_some() || backend.is_empty() || run_id.is_empty() {
        return None;
    }
    Some((backend, run_id))
}

fn is_hex_digest_64(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn validate_compose_report_file(path: &Path, key: &str) -> Result<Vec<String>, String> {
    let mut issues = Vec::new();
    let report: Value = read_json(path)?;
    let Some(obj) = report.as_object() else {
        issues.push(format!(
            "compose report '{}' is not a JSON object",
            path.display()
        ));
        return Ok(issues);
    };

    let expected_fields = [
        "run_id",
        "backend",
        "carried_entries",
        "aggregate_digest",
        "composition_digest",
        "carried_backends",
        "carried_statement_digests",
        "carried_verification_key_digests",
        "carried_public_input_commitments",
    ];
    for field in expected_fields {
        if !obj.contains_key(field) {
            issues.push(format!(
                "compose report '{}' missing required key '{}'",
                path.display(),
                field
            ));
        }
    }

    let run_id = obj
        .get("run_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let backend = obj
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if run_id.is_empty() || backend.is_empty() {
        issues.push(format!(
            "compose report '{}' has empty run_id/backend",
            path.display()
        ));
    }
    if let Some((expected_backend, expected_run_id)) =
        parse_compose_artifact_key(key, "compose-report/")
    {
        if backend != expected_backend {
            issues.push(format!(
                "compose report '{}' backend '{}' does not match manifest key backend '{}'",
                path.display(),
                backend,
                expected_backend
            ));
        }
        if run_id != expected_run_id {
            issues.push(format!(
                "compose report '{}' run_id '{}' does not match manifest key run_id '{}'",
                path.display(),
                run_id,
                expected_run_id
            ));
        }
    }

    if let Some(Value::String(digest)) = obj.get("aggregate_digest")
        && !is_hex_digest_64(digest)
    {
        issues.push(format!(
            "compose report '{}' has invalid aggregate_digest",
            path.display()
        ));
    }
    if let Some(Value::String(digest)) = obj.get("composition_digest")
        && !is_hex_digest_64(digest)
    {
        issues.push(format!(
            "compose report '{}' has invalid composition_digest",
            path.display()
        ));
    }

    let carried_entries = obj
        .get("carried_entries")
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize;
    for key_name in [
        "carried_backends",
        "carried_statement_digests",
        "carried_verification_key_digests",
        "carried_public_input_commitments",
    ] {
        match obj.get(key_name) {
            Some(Value::Array(items)) => {
                if items.len() != carried_entries {
                    issues.push(format!(
                        "compose report '{}' key '{}' length {} does not match carried_entries {}",
                        path.display(),
                        key_name,
                        items.len(),
                        carried_entries
                    ));
                }
                if key_name != "carried_backends"
                    && items
                        .iter()
                        .any(|item| !item.as_str().map(is_hex_digest_64).unwrap_or(false))
                {
                    issues.push(format!(
                        "compose report '{}' key '{}' must contain 64-char hex digests",
                        path.display(),
                        key_name
                    ));
                }
                if key_name == "carried_backends"
                    && items
                        .iter()
                        .any(|item| !item.as_str().map(|s| !s.is_empty()).unwrap_or(false))
                {
                    issues.push(format!(
                        "compose report '{}' key '{}' must contain non-empty backend names",
                        path.display(),
                        key_name
                    ));
                }
            }
            Some(_) => issues.push(format!(
                "compose report '{}' key '{}' must be an array",
                path.display(),
                key_name
            )),
            None => {}
        }
    }

    Ok(issues)
}

pub(crate) fn validate_compose_proof_file(path: &Path, key: &str) -> Result<Vec<String>, String> {
    let mut issues = Vec::new();
    let artifact: zkf_core::ProofArtifact = read_json(path)?;

    let Some((backend, run_id)) = parse_compose_artifact_key(key, "compose-proof/") else {
        issues.push(format!(
            "compose proof key '{}' is malformed (expected compose-proof/<backend>/<run_id>)",
            key
        ));
        return Ok(issues);
    };

    let metadata = &artifact.metadata;
    let required_pairs = [
        ("compose_scheme", "attestation-composition-v3"),
        ("compose_run_id", run_id),
        ("compose_backend", backend),
    ];
    for (field, expected) in required_pairs {
        match metadata.get(field) {
            Some(value) if value == expected => {}
            Some(value) => issues.push(format!(
                "compose proof '{}' metadata '{}' expected '{}', found '{}'",
                path.display(),
                field,
                expected,
                value
            )),
            None => issues.push(format!(
                "compose proof '{}' missing metadata '{}'",
                path.display(),
                field
            )),
        }
    }

    if let Ok(parsed_backend) = parse_backend(backend) {
        let semantic_pairs = [
            (
                "proof_semantics",
                crate::compose::compose_proof_semantics().to_string(),
            ),
            (
                "blackbox_semantics",
                crate::compose::compose_blackbox_semantics().to_string(),
            ),
            (
                "prover_acceleration_scope",
                crate::compose::compose_prover_acceleration_scope(parsed_backend),
            ),
        ];
        for (field, expected) in semantic_pairs {
            match metadata.get(field) {
                Some(value) if value == &expected => {}
                Some(value) => issues.push(format!(
                    "compose proof '{}' metadata '{}' expected '{}', found '{}'",
                    path.display(),
                    field,
                    expected,
                    value
                )),
                None => issues.push(format!(
                    "compose proof '{}' missing metadata '{}'",
                    path.display(),
                    field
                )),
            }
        }
    }

    for field in [
        "compose_aggregate_digest",
        "compose_composition_digest",
        "compose_binding_digest",
    ] {
        match metadata.get(field) {
            Some(value) if is_hex_digest_64(value) => {}
            Some(value) => issues.push(format!(
                "compose proof '{}' metadata '{}' must be 64-char hex digest, found '{}'",
                path.display(),
                field,
                value
            )),
            None => issues.push(format!(
                "compose proof '{}' missing metadata '{}'",
                path.display(),
                field
            )),
        }
    }

    match metadata
        .get("compose_carried_entries")
        .and_then(|value| value.parse::<usize>().ok())
    {
        Some(_) => {}
        None => issues.push(format!(
            "compose proof '{}' metadata 'compose_carried_entries' must be a non-negative integer",
            path.display()
        )),
    }

    Ok(issues)
}

pub(crate) fn ensure_manifest_v2_metadata_for_command(
    manifest_path: &Path,
    manifest: &PackageManifest,
    command_name: &str,
) -> Result<(), String> {
    let metadata_issues = validate_v2_manifest_metadata(manifest);
    if metadata_issues.is_empty() {
        return Ok(());
    }
    Err(format!(
        "manifest '{}' is missing required v2 metadata for `{command_name}`: {}. Run `zkf package migrate --manifest {} --from 1 --to 2` or regenerate the package.",
        manifest_path.display(),
        metadata_issues.join("; "),
        manifest_path.display()
    ))
}

pub(crate) fn with_setup_seed_override<T>(
    seed: Option<[u8; 32]>,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let previous = zkf_backends::setup_seed_override();
    set_setup_seed_override(seed);
    let result = op();
    set_setup_seed_override(previous);
    result
}

pub(crate) fn with_proof_seed_override<T>(
    seed: Option<[u8; 32]>,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let previous = zkf_backends::proof_seed_override();
    set_proof_seed_override(seed);
    let result = op();
    set_proof_seed_override(previous);
    result
}

pub(crate) fn with_allow_dev_deterministic_groth16_override<T>(
    allow: Option<bool>,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let previous = zkf_backends::allow_dev_deterministic_groth16_override();
    set_allow_dev_deterministic_groth16_override(allow);
    let result = op();
    set_allow_dev_deterministic_groth16_override(previous);
    result
}

pub(crate) fn with_groth16_setup_blob_path_override<T>(
    path: Option<String>,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let previous = zkf_backends::groth16_setup_blob_path_override();
    set_groth16_setup_blob_path_override(path);
    let result = op();
    set_groth16_setup_blob_path_override(previous);
    result
}

pub(crate) fn attach_groth16_setup_blob_path(
    program: &mut Program,
    backend: BackendKind,
    path: Option<&Path>,
) {
    if backend != BackendKind::ArkworksGroth16 {
        return;
    }
    if let Some(path) = path {
        program.metadata.insert(
            GROTH16_SETUP_BLOB_PATH_METADATA_KEY.to_string(),
            path.display().to_string(),
        );
    }
}

pub(crate) fn parse_witness_requirement(value: &str) -> Option<WitnessRequirement> {
    match value {
        "execution" => Some(WitnessRequirement::Execution),
        "solver" => Some(WitnessRequirement::Solver),
        "constraint" => Some(WitnessRequirement::Constraint),
        _ => None,
    }
}

pub(crate) fn infer_witness_requirement(
    program: &Program,
    inspection: Option<&FrontendInspection>,
) -> WitnessRequirement {
    let Some(inspection) = inspection else {
        if !program.witness_plan.hints.is_empty() {
            return WitnessRequirement::Execution;
        }
        if program.witness_plan.assignments.is_empty() && !program.constraints.is_empty() {
            return WitnessRequirement::Solver;
        }
        return WitnessRequirement::Constraint;
    };

    if inspection.requires_hints
        || inspection
            .required_capabilities
            .iter()
            .any(|capability| capability == "hints")
    {
        return WitnessRequirement::Execution;
    }

    let requires_solver_capability = inspection.required_capabilities.iter().any(|capability| {
        capability == "memory"
            || capability == "call"
            || capability == "directive"
            || capability == "multi-function"
            || capability
                .strip_prefix("blackbox:")
                .is_some_and(|name| !matches!(name, "range" | "and" | "xor"))
    });
    if requires_solver_capability {
        return WitnessRequirement::Solver;
    }

    if program.witness_plan.assignments.is_empty() && !program.constraints.is_empty() {
        return WitnessRequirement::Solver;
    }

    WitnessRequirement::Constraint
}

pub(crate) fn parse_benchmark_backends(
    value: Option<Vec<String>>,
    mode: Option<&str>,
) -> Result<Vec<BackendKind>, String> {
    let raw = match value {
        Some(value) => value,
        None if parse_prove_mode(mode)?.or(default_prove_mode()) == Some("metal-first") => {
            metal_first_benchmark_backends()
                .into_iter()
                .map(|backend| backend.as_str().to_string())
                .collect()
        }
        None => vec![
            "arkworks-groth16".to_string(),
            "halo2".to_string(),
            "plonky3".to_string(),
        ],
    };

    if raw.is_empty() {
        return Err("benchmark backend list cannot be empty".to_string());
    }

    raw.into_iter().map(|name| parse_backend(&name)).collect()
}

pub(crate) fn ensure_backend_allowed(
    backend: BackendKind,
    allow_compat: bool,
) -> Result<(), String> {
    let capabilities = backend_for(backend).capabilities();
    if capabilities.mode == BackendMode::Compat && !allow_compat {
        return Err(format!(
            "backend '{}' is in '{}' mode: {}. Re-run with --allow-compat to use compatibility backends.",
            backend,
            capabilities.mode.as_str(),
            capabilities.notes
        ));
    }
    Ok(())
}

pub(crate) fn ensure_backend_request_allowed(
    request: &BackendRequest,
    allow_compat: bool,
) -> Result<(), String> {
    if request.route == BackendRoute::ExplicitCompat && !allow_compat {
        return Err(format!(
            "backend '{}' is an explicit compatibility backend. Re-run with --allow-compat to use it.",
            request.requested_name
        ));
    }

    let surface = backend_surface_status(request.backend);
    let report = capability_report_for_backend(request.backend)?;
    if request.route == BackendRoute::Auto
        && matches!(request.backend, BackendKind::Sp1 | BackendKind::RiscZero)
        && surface.implementation_type == SupportClass::Delegated
    {
        let alias = match request.backend {
            BackendKind::Sp1 => "sp1-compat",
            BackendKind::RiscZero => "risc-zero-compat",
            _ => unreachable!(),
        };
        return Err(format!(
            "backend '{}' is reserved for the native backend, but this binary only has the compatibility implementation. Build with the native feature enabled or request '{}' with --allow-compat.",
            request.requested_name, alias
        ));
    }

    if request.route == BackendRoute::Auto
        && matches!(request.backend, BackendKind::Sp1 | BackendKind::RiscZero)
        && !report.production_ready
    {
        return Err(format!(
            "backend '{}' is reserved for the native backend, but this host is not production-ready for it (readiness={}, reason={}). {}",
            request.requested_name,
            report.readiness,
            report
                .readiness_reason
                .as_deref()
                .unwrap_or("not-ready"),
            report
                .operator_action
                .as_deref()
                .unwrap_or("Install the required native toolchain or use the explicit compat alias with --allow-compat.")
        ));
    }

    if request.route == BackendRoute::Auto {
        return ensure_backend_allowed(request.backend, allow_compat);
    }

    Ok(())
}

pub(crate) fn capability_report_for_backend(
    backend: BackendKind,
) -> Result<CapabilityReport, String> {
    capabilities_report()
        .into_iter()
        .find(|report| report.capabilities.backend == backend)
        .ok_or_else(|| format!("backend capability report unavailable for '{}'", backend))
}

pub(crate) fn ensure_backend_supports_program_constraints(
    backend: BackendKind,
    program: &Program,
) -> Result<(), String> {
    ensure_backend_supports_field(backend, program.field)?;
    let report = capability_report_for_backend(backend).ok();
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
        return Err(format!(
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
        return Err(format!(
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
        return Ok(());
    }

    let supported_ops = capabilities
        .supported_blackbox_ops
        .iter()
        .map(|op| op.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();

    if supported_ops.is_empty() {
        return Err(format!(
            "backend '{}' does not advertise native blackbox op support; program requires [{}]",
            backend,
            required_ops.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    let missing = required_ops
        .iter()
        .filter(|op| !supported_ops.contains(&op.to_ascii_lowercase()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "backend '{}' missing required blackbox ops: [{}] (supports [{}])",
            backend,
            missing.join(", "),
            capabilities.supported_blackbox_ops.join(", ")
        ));
    }

    let bn254_only_required_ops = required_ops
        .iter()
        .filter(|op| is_bn254_only_blackbox(op))
        .cloned()
        .collect::<Vec<_>>();
    if !bn254_only_required_ops.is_empty() && program.field != FieldId::Bn254 {
        return Err(format!(
            "backend '{}' currently supports [{}] blackbox ops only for bn254 field programs; found {}",
            backend,
            bn254_only_required_ops.join(", "),
            program.field
        ));
    }

    Ok(())
}

pub(crate) fn ensure_backend_supports_zir_constraints(
    backend: BackendKind,
    program: &zkf_core::zir_v1::Program,
) -> Result<(), String> {
    ensure_backend_supports_field(backend, program.field)?;
    let report = capability_report_for_backend(backend).ok();
    let required_kinds = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            zkf_core::zir_v1::Constraint::Equal { .. } => "equal".to_string(),
            zkf_core::zir_v1::Constraint::Boolean { .. } => "boolean".to_string(),
            zkf_core::zir_v1::Constraint::Range { .. } => "range".to_string(),
            zkf_core::zir_v1::Constraint::Lookup { .. } => "lookup".to_string(),
            zkf_core::zir_v1::Constraint::CustomGate { .. } => "custom_gate".to_string(),
            zkf_core::zir_v1::Constraint::MemoryRead { .. } => "memory_read".to_string(),
            zkf_core::zir_v1::Constraint::MemoryWrite { .. } => "memory_write".to_string(),
            zkf_core::zir_v1::Constraint::BlackBox { .. } => "blackbox".to_string(),
            zkf_core::zir_v1::Constraint::Permutation { .. } => "permutation".to_string(),
            zkf_core::zir_v1::Constraint::Copy { .. } => "copy".to_string(),
        })
        .collect::<BTreeSet<_>>();

    let capabilities = backend_for(backend).capabilities();
    let supported_kinds = capabilities
        .supported_constraint_kinds
        .iter()
        .map(|kind| kind.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if supported_kinds.is_empty() && !required_kinds.is_empty() {
        return Err(format!(
            "backend '{}' does not advertise native constraint kind support; zir program requires [{}]",
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
        return Err(format!(
            "backend '{}' missing required zir constraint kinds: [{}] (supports [{}])",
            backend,
            missing_kinds.join(", "),
            capabilities.supported_constraint_kinds.join(", ")
        ));
    }

    let required_ops = program
        .constraints
        .iter()
        .filter_map(|constraint| {
            if let zkf_core::zir_v1::Constraint::BlackBox { op, .. } = constraint {
                Some(op.as_str().to_string())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    if required_ops.is_empty() {
        return Ok(());
    }

    let supported_ops = capabilities
        .supported_blackbox_ops
        .iter()
        .map(|op| op.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if supported_ops.is_empty() {
        return Err(format!(
            "backend '{}' does not advertise native blackbox op support; zir program requires [{}]",
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
        return Err(format!(
            "backend '{}' missing required zir blackbox ops: [{}] (supports [{}])",
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
        return Err(format!(
            "backend '{}' currently supports [{}] blackbox ops only for bn254 field zir programs; found {}",
            backend,
            bn254_only_required_ops.join(", "),
            program.field
        ));
    }

    Ok(())
}

fn is_bn254_only_blackbox(op: &str) -> bool {
    matches!(
        op.to_ascii_lowercase().as_str(),
        "poseidon" | "pedersen" | "schnorr_verify"
    )
}

pub(crate) fn infer_translator_family(
    frontend: FrontendKind,
    probe: &zkf_frontends::FrontendProbe,
) -> String {
    if frontend != FrontendKind::Noir {
        return format!("{}-auto-bridge", frontend.as_str());
    }
    let Some(version) = probe.noir_version.as_deref() else {
        return "noir-auto-bridge".to_string();
    };
    let normalized = version.split('+').next().unwrap_or(version);
    if normalized == "1.0.0-beta.9" {
        return "noir-beta9".to_string();
    }
    if normalized == "1.0.0-beta.10" {
        return "noir-beta10".to_string();
    }
    if normalized.starts_with("1.0.0-beta.") {
        return "noir-v1-program-json".to_string();
    }
    if normalized.starts_with("1.") {
        return "noir-v1-stable".to_string();
    }
    "noir-auto-bridge".to_string()
}

pub(crate) fn read_inputs(path: &Path) -> Result<WitnessInputs, String> {
    let value: Value = read_json(path)?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("inputs must be a JSON object: {}", path.display()))?;

    let mut out = BTreeMap::new();
    for (name, value) in object {
        let rendered = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => {
                return Err(format!(
                    "inputs value for '{name}' must be string or number in {}",
                    path.display()
                ));
            }
        };

        out.insert(name.clone(), FieldElement::new(rendered));
    }

    Ok(out)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ProgramArtifact {
    IrV2(Program),
    ZirV1(zkf_core::zir_v1::Program),
}

impl ProgramArtifact {
    pub(crate) fn ir_family(&self) -> &'static str {
        match self {
            Self::IrV2(_) => "ir-v2",
            Self::ZirV1(_) => "zir-v1",
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Self::IrV2(program) => &program.name,
            Self::ZirV1(program) => &program.name,
        }
    }

    pub(crate) fn field(&self) -> FieldId {
        match self {
            Self::IrV2(program) => program.field,
            Self::ZirV1(program) => program.field,
        }
    }

    pub(crate) fn signal_count(&self) -> usize {
        match self {
            Self::IrV2(program) => program.signals.len(),
            Self::ZirV1(program) => program.signals.len(),
        }
    }

    pub(crate) fn constraint_count(&self) -> usize {
        match self {
            Self::IrV2(program) => program.constraints.len(),
            Self::ZirV1(program) => program.constraints.len(),
        }
    }

    pub(crate) fn digest_hex(&self) -> String {
        match self {
            Self::IrV2(program) => program.digest_hex(),
            Self::ZirV1(program) => program.digest_hex(),
        }
    }

    pub(crate) fn lower_to_ir_v2(&self) -> Result<Program, String> {
        match self {
            Self::IrV2(program) => Ok(program.clone()),
            Self::ZirV1(program) => program_zir_to_v2(program).map_err(render_zkf_error),
        }
    }

    pub(crate) fn promote_to_zir_v1(&self) -> zkf_core::zir_v1::Program {
        match self {
            Self::IrV2(program) => program_v2_to_zir(program),
            Self::ZirV1(program) => program.clone(),
        }
    }
}

pub(crate) fn read_program_artifact(path: &Path) -> Result<ProgramArtifact, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if matches!(serde_json::from_str::<Value>(&content), Ok(Value::Object(map)) if map.is_empty()) {
        return Err(format!(
            "{}: invalid program JSON: empty object; expected a 'zirapp', 'zir-v1', or 'ir-v2' program with signals and constraints",
            path.display()
        ));
    }
    if let Ok(program) = serde_json::from_str::<zkf_core::zir_v1::Program>(&content) {
        return Ok(ProgramArtifact::ZirV1(program));
    }
    if let Ok(spec) = serde_json::from_str::<zkf_lib::AppSpecV1>(&content) {
        let program = zkf_lib::build_app_spec(&spec).map_err(|err| {
            format!(
                "{}: failed to build 'zirapp' spec into a program: {err}",
                path.display()
            )
        })?;
        return Ok(ProgramArtifact::IrV2(program));
    }
    if let Ok(program) = serde_json::from_str::<Program>(&content) {
        return Ok(ProgramArtifact::IrV2(program));
    }
    Err(format!(
        "{}: failed to parse as 'zirapp', 'zir-v1', or 'ir-v2' program JSON",
        path.display()
    ))
}

pub(crate) fn load_program_v2(path: &Path) -> Result<Program, String> {
    read_program_artifact(path)?.lower_to_ir_v2()
}

pub(crate) fn load_program_zir(path: &Path) -> Result<zkf_core::zir_v1::Program, String> {
    Ok(read_program_artifact(path)?.promote_to_zir_v1())
}

/// Resolve input aliases: if an input key matches an alias (e.g., "a" → "w0"),
/// rename it to the internal signal name. This lets developers use original
/// parameter names from Noir/Circom instead of witness indices.
pub(crate) fn resolve_input_aliases(inputs: &mut WitnessInputs, program: &Program) {
    let aliases = &program.witness_plan.input_aliases;
    if aliases.is_empty() {
        return;
    }
    let keys_to_resolve: Vec<(String, String)> = inputs
        .keys()
        .filter_map(|k| aliases.get(k).map(|target| (k.clone(), target.clone())))
        .collect();
    for (alias, target) in keys_to_resolve {
        if let Some(value) = inputs.remove(&alias) {
            inputs.insert(target, value);
        }
    }
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("{}: {e}", path.display()))
}

fn supported_fields_for_backend(backend: BackendKind) -> Vec<FieldId> {
    BackendCapabilityMatrix::current()
        .entries
        .into_iter()
        .find(|entry| entry.backend == backend)
        .map(|entry| entry.supported_fields)
        .unwrap_or_default()
}

fn field_label(field: FieldId) -> &'static str {
    match field {
        FieldId::Bn254 => "Bn254",
        FieldId::Bls12_381 => "Bls12_381",
        FieldId::PastaFp => "PastaFp",
        FieldId::PastaFq => "PastaFq",
        FieldId::Goldilocks => "Goldilocks",
        FieldId::BabyBear => "BabyBear",
        FieldId::Mersenne31 => "Mersenne31",
    }
}

fn format_supported_fields(fields: &[FieldId]) -> String {
    fields
        .iter()
        .map(|field| field_label(*field))
        .collect::<Vec<_>>()
        .join(", ")
}

fn backend_field_guidance(backend: BackendKind, field: FieldId) -> Option<String> {
    match (backend, field) {
        (BackendKind::Halo2, FieldId::Bls12_381) => Some(
            "Use backend 'halo2-bls12-381' for Bls12_381 circuits, or switch the circuit field to PastaFp for backend 'halo2'.".to_string(),
        ),
        (BackendKind::Halo2Bls12381, FieldId::PastaFp) => Some(
            "Use backend 'halo2' for PastaFp circuits, or keep backend 'halo2-bls12-381' and switch the circuit field to Bls12_381.".to_string(),
        ),
        (BackendKind::Halo2, _) => {
            Some("Backend 'halo2' only supports PastaFp circuits.".to_string())
        }
        (BackendKind::Halo2Bls12381, _) => Some(
            "Backend 'halo2-bls12-381' only supports Bls12_381 circuits.".to_string(),
        ),
        _ => None,
    }
}

fn ensure_backend_supports_field(backend: BackendKind, field: FieldId) -> Result<(), String> {
    let supported_fields = supported_fields_for_backend(backend);
    if supported_fields.is_empty() || supported_fields.contains(&field) {
        return Ok(());
    }

    let mut message = format!(
        "backend '{}' does not support field {}; supported fields: [{}]",
        backend,
        field_label(field),
        format_supported_fields(&supported_fields)
    );
    if let Some(guidance) = backend_field_guidance(backend, field) {
        message.push(' ');
        message.push_str(&guidance);
    }
    Err(message)
}

pub(crate) fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let content = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    write_bytes_atomic(path, content.as_bytes())
}

pub(crate) fn write_text(path: &Path, content: &str) -> Result<(), String> {
    write_bytes_atomic(path, content.as_bytes())
}

pub(crate) fn write_json_and_hash(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<String, String> {
    let content = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    write_bytes_atomic(path, content.as_bytes())?;
    Ok(sha256_hex(content.as_bytes()))
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact.json");

    let pid = std::process::id();
    for attempt in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let temp_path = parent.join(format!(".{file_name}.tmp-{pid}-{nanos}-{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                file.write_all(bytes)
                    .map_err(|e| format!("{}: {e}", temp_path.display()))?;
                file.sync_all()
                    .map_err(|e| format!("{}: {e}", temp_path.display()))?;
                drop(file);
                fs::rename(&temp_path, path).map_err(|e| format!("{}: {e}", path.display()))?;
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!("{}: {err}", temp_path.display()));
            }
        }
    }

    Err(format!(
        "failed to create temporary file for atomic write: {}",
        path.display()
    ))
}

pub(crate) fn render_zkf_error(err: ZkfError) -> String {
    match err {
        ZkfError::RangeConstraintViolation {
            index,
            label,
            signal,
            bits,
            value,
        } => {
            let max = (BigInt::from(1u8) << bits) - BigInt::from(1u8);
            let constraint_label = label
                .as_deref()
                .map(|label| format!("constraint #{index} ('{label}')"))
                .unwrap_or_else(|| format!("constraint #{index}"));
            format!(
                "Range check failed for signal '{signal}' at {constraint_label}: got {value}, expected max {max} for a {bits}-bit value. Run `ziros debug --program <program.json> --inputs <inputs.json> --out debug.json` to inspect the failing witness path."
            )
        }
        ZkfError::UnsupportedWitnessSolve {
            unresolved_signals,
            reason,
        } => format!(
            "Witness generation stalled. Unresolved derived signals: {}. {reason}",
            unresolved_signals.join(", ")
        ),
        ZkfError::AuditFailure {
            message,
            failed_checks,
            report,
            analysis,
        } => {
            let failed_categories = report
                .checks
                .iter()
                .filter(|check| check.status == zkf_core::AuditStatus::Fail)
                .map(|check| format!("{:?}", check.category).to_lowercase())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut rendered = format!("{message} ({failed_checks} blocking check(s))");
            if !failed_categories.is_empty() {
                rendered.push_str(&format!(
                    "; failed_categories={}",
                    failed_categories.join(",")
                ));
            }
            if let Some(analysis) = analysis.as_deref() {
                rendered.push_str(&format!(
                    "; linear_nullity={}; linear_only_signals={:?}; linearly_underdetermined_private_signals={:?}; nonlinear_unanchored_components={:?}",
                    analysis.linear_nullity,
                    analysis.linear_only_signals,
                    analysis.linearly_underdetermined_private_signals,
                    analysis.nonlinear_unanchored_components
                ));
            }
            rendered
        }
        other => other.to_string(),
    }
}

pub(crate) fn raw_cli_error(payload: impl Into<String>) -> String {
    format!("{RAW_CLI_ERROR_PREFIX}{}", payload.into())
}

pub(crate) fn raw_cli_error_payload(err: &str) -> Option<&str> {
    err.strip_prefix(RAW_CLI_ERROR_PREFIX)
}

pub(crate) fn manifest_ir_family(manifest: &zkf_core::PackageManifest) -> &str {
    manifest
        .metadata
        .get("ir_family")
        .map(String::as_str)
        .unwrap_or("ir-v2")
}

pub(crate) fn load_program_v2_from_manifest(
    root: &Path,
    manifest: &zkf_core::PackageManifest,
) -> Result<Program, String> {
    let program_path = root.join(&manifest.files.program.path);
    let mut program = match manifest_ir_family(manifest) {
        "ir-v2" => read_json(&program_path),
        "zir-v1" => {
            let zir_program: zkf_core::zir_v1::Program = read_json(&program_path)?;
            program_zir_to_v2(&zir_program).map_err(render_zkf_error)
        }
        other => Err(format!(
            "unsupported ir_family '{other}' in manifest metadata; supported values are 'ir-v2' and 'zir-v1'"
        )),
    }?;
    promote_manifest_metadata_into_program(manifest, &mut program);
    Ok(program)
}

pub(crate) fn load_program_v2_for_backend(
    root: &Path,
    manifest: &zkf_core::PackageManifest,
    backend: BackendKind,
) -> Result<Program, String> {
    if manifest_ir_family(manifest) == "zir-v1" {
        let program_path = root.join(&manifest.files.program.path);
        let zir_program: zkf_core::zir_v1::Program = read_json(&program_path)?;
        ensure_backend_supports_zir_constraints(backend, &zir_program)?;
        let mut lowered = program_zir_to_v2(&zir_program).map_err(render_zkf_error)?;
        promote_manifest_metadata_into_program(manifest, &mut lowered);
        ensure_backend_supports_program_constraints(backend, &lowered)?;
        return Ok(lowered);
    }

    let program = load_program_v2_from_manifest(root, manifest)?;
    ensure_backend_supports_program_constraints(backend, &program)?;
    Ok(program)
}

fn promote_manifest_metadata_into_program(
    manifest: &zkf_core::PackageManifest,
    program: &mut Program,
) {
    for key in ["nova_ivc_in", "nova_ivc_out"] {
        if let Some(value) = manifest.metadata.get(key) {
            program
                .metadata
                .entry(key.to_string())
                .or_insert_with(|| value.clone());
        }
    }
}

pub(crate) fn program_digest_matches_manifest(
    root: &Path,
    manifest: &zkf_core::PackageManifest,
) -> Result<bool, String> {
    let program_path = root.join(&manifest.files.program.path);
    match manifest_ir_family(manifest) {
        "ir-v2" => {
            let program: Program = read_json(&program_path)?;
            Ok(program.digest_hex() == manifest.program_digest)
        }
        "zir-v1" => {
            let zir_program: zkf_core::zir_v1::Program = read_json(&program_path)?;
            if zir_program.digest_hex() == manifest.program_digest {
                return Ok(true);
            }
            let lowered = program_zir_to_v2(&zir_program).map_err(render_zkf_error)?;
            Ok(lowered.digest_hex() == manifest.program_digest)
        }
        other => Err(format!(
            "unsupported ir_family '{other}' in manifest metadata; cannot verify program digest"
        )),
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn digest_to_field_element(
    digest_hex: &str,
    field: FieldId,
) -> Result<FieldElement, String> {
    let digest = digest_hex.trim();
    if digest.is_empty() {
        return Err("cannot map empty digest to field element".to_string());
    }
    if !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid digest hex: '{digest}'"));
    }
    let value = BigInt::from_str_radix(digest, 16).map_err(|err| err.to_string())?;
    Ok(FieldElement::from_bigint_with_field(value, field))
}

pub(crate) fn proof_artifact_trust_model(artifact: &zkf_core::ProofArtifact) -> &str {
    artifact
        .metadata
        .get("trust_model")
        .map(String::as_str)
        .unwrap_or("cryptographic")
}

pub(crate) fn proof_artifact_assurance_lane(artifact: &zkf_core::ProofArtifact) -> &str {
    artifact
        .metadata
        .get("assurance_lane")
        .map(String::as_str)
        .unwrap_or_else(|| assurance_lane_for_backend(artifact.backend))
}

pub(crate) fn ensure_release_safe_proof_artifact(
    artifact: &zkf_core::ProofArtifact,
    context: &str,
) -> Result<(), String> {
    let trust_model = proof_artifact_trust_model(artifact);
    let assurance_lane = proof_artifact_assurance_lane(artifact);
    let is_native_lane = assurance_lane == "native-cryptographic-proof";
    if trust_model == "cryptographic" && is_native_lane {
        return Ok(());
    }

    Err(format!(
        "{context} rejects non-release proof artifacts (trust_model={trust_model}, assurance_lane={assurance_lane}); attestation-backed, delegated, and accumulated wrappers are internal-only"
    ))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::{
        default_prove_mode, ensure_backend_supports_program_constraints,
        ensure_release_safe_proof_artifact, max_lookup_rows, parse_benchmark_backends,
        parse_export_scheme, parse_optimization_objective, parse_prove_mode, read_program_artifact,
        resolve_backend_or_mode, resolve_backend_targets_or_mode, sha256_hex, write_json,
        write_json_and_hash,
    };
    use std::collections::BTreeMap;
    use std::fs;
    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    use std::path::PathBuf;
    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    use std::sync::Mutex;
    use zkf_backends::strict_bn254_auto_route_ready;
    use zkf_core::ir::LookupTable;
    #[allow(unused_imports)]
    use zkf_core::{
        BackendKind, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact, Signal,
        Visibility,
    };
    use zkf_runtime::OptimizationObjective;

    #[test]
    fn read_program_artifact_rejects_empty_json_object_with_actionable_error() {
        let root = std::env::temp_dir().join(format!("zkf-empty-program-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("empty.json");
        fs::write(&path, "{}").unwrap();

        let err = read_program_artifact(&path).unwrap_err();
        assert!(err.contains("invalid program JSON: empty object"));
    }

    #[test]
    fn read_program_artifact_accepts_app_spec_and_lowers_it() {
        let root = std::env::temp_dir().join(format!("zkf-appspec-program-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("zirapp.json");
        let spec = zkf_lib::instantiate_template("range-proof", &BTreeMap::new()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();

        let artifact = read_program_artifact(&path).expect("app spec should parse");
        let program = artifact.lower_to_ir_v2().expect("app spec should lower");

        assert_eq!(program.name, spec.program.name);
        assert_eq!(program.field, spec.program.field);
        assert!(!program.constraints.is_empty());
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    fn fixture_model_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("zkf-runtime")
            .join("tests")
            .join("fixtures")
            .join("neural_engine")
            .join("models")
            .join(name)
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    fn with_fixture_models_env<T>(f: impl FnOnce() -> T) -> T {
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

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    fn minimal_goldilocks_program() -> Program {
        Program {
            field: FieldId::Goldilocks,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::signal("x"),
                label: Some("out_eq_x".to_string()),
            }],
            ..Default::default()
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn metal_first_mode_picks_preferred_backend_for_program_field() {
        let program = minimal_goldilocks_program();
        let backend = resolve_backend_or_mode(
            None,
            Some("metal-first"),
            &program,
            OptimizationObjective::FastestProve,
        )
        .expect("backend");
        assert_eq!(backend.backend, BackendKind::Plonky3);
    }

    #[test]
    fn explicit_backend_overrides_mode() {
        let program = Program {
            field: FieldId::Goldilocks,
            ..Default::default()
        };
        let backend = resolve_backend_or_mode(
            Some("arkworks-groth16"),
            Some("metal-first"),
            &program,
            OptimizationObjective::FastestProve,
        )
        .expect("backend");
        assert_eq!(backend.backend, BackendKind::ArkworksGroth16);
    }

    #[test]
    fn write_json_and_hash_writes_expected_content_hash() {
        let root = std::env::temp_dir().join(format!("zkf-util-write-json-{}", std::process::id()));
        fs::create_dir_all(&root).expect("mkdir");
        let path = root.join("nested/out.json");
        let value = serde_json::json!({ "ok": true, "n": 7 });

        let hash = write_json_and_hash(&path, &value).expect("write");
        let content = fs::read_to_string(&path).expect("read");

        assert_eq!(hash, sha256_hex(content.as_bytes()));
    }

    #[test]
    fn write_json_replaces_existing_file_content() {
        let root =
            std::env::temp_dir().join(format!("zkf-util-replace-json-{}", std::process::id()));
        fs::create_dir_all(&root).expect("mkdir");
        let path = root.join("replace.json");

        write_json(&path, &serde_json::json!({ "v": 1 })).expect("first");
        write_json(&path, &serde_json::json!({ "v": 2 })).expect("second");

        let content = fs::read_to_string(&path).expect("read");
        assert!(content.contains("\"v\": 2"));
        assert!(!content.contains("\"v\": 1"));
    }

    #[test]
    fn release_safe_proof_artifact_rejects_attestation() {
        let mut artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: Default::default(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        artifact
            .metadata
            .insert("trust_model".to_string(), "attestation".to_string());

        let err = ensure_release_safe_proof_artifact(&artifact, "deploy").unwrap_err();
        assert!(err.contains("trust_model=attestation"));
    }

    #[test]
    fn release_safe_proof_artifact_rejects_attestation_backed_lane_even_with_crypto_label() {
        let mut artifact = ProofArtifact {
            backend: BackendKind::Sp1,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: Default::default(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        artifact
            .metadata
            .insert("trust_model".to_string(), "cryptographic".to_string());
        artifact.metadata.insert(
            "assurance_lane".to_string(),
            "attestation-backed-host-validated-lane".to_string(),
        );

        let err = ensure_release_safe_proof_artifact(&artifact, "deploy").unwrap_err();
        assert!(err.contains("assurance_lane=attestation-backed-host-validated-lane"));
    }

    #[test]
    fn max_lookup_rows_reflects_largest_table() {
        let program = Program {
            lookup_tables: vec![
                LookupTable {
                    name: "small".to_string(),
                    columns: vec!["x".to_string()],
                    values: vec![vec![FieldElement::from_u64(1)]; 4],
                },
                LookupTable {
                    name: "large".to_string(),
                    columns: vec!["x".to_string()],
                    values: vec![vec![FieldElement::from_u64(2)]; 300],
                },
            ],
            ..Default::default()
        };

        assert_eq!(max_lookup_rows(&program), 300);
    }

    #[test]
    fn metal_first_benchmark_defaults_track_certified_backends() {
        let backends = parse_benchmark_backends(None, Some("metal-first")).expect("backends");
        if cfg!(target_os = "macos") && strict_bn254_auto_route_ready() {
            assert_eq!(
                backends,
                vec![BackendKind::Plonky3, BackendKind::ArkworksGroth16]
            );
            return;
        }
        assert_eq!(backends, vec![BackendKind::Plonky3]);
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn metal_first_target_resolution_prefers_single_metal_complete_backend() {
        let program = minimal_goldilocks_program();
        let backends =
            resolve_backend_targets_or_mode(&[], Some("metal-first"), &program, &[]).unwrap();
        assert_eq!(
            backends
                .into_iter()
                .map(|request| request.backend)
                .collect::<Vec<_>>(),
            vec![BackendKind::Plonky3]
        );
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn apple_metal_default_backend_resolution_uses_auto_recommender() {
        let program = Program {
            field: FieldId::Goldilocks,
            ..Default::default()
        };
        assert_eq!(default_prove_mode(), Some("metal-first"));
        let backend =
            resolve_backend_or_mode(None, None, &program, OptimizationObjective::FastestProve)
                .expect("backend");
        assert_eq!(backend.backend, BackendKind::Plonky3);
        let backends = parse_benchmark_backends(None, None).expect("backends");
        if strict_bn254_auto_route_ready() {
            assert_eq!(
                backends,
                vec![BackendKind::Plonky3, BackendKind::ArkworksGroth16]
            );
        } else {
            assert_eq!(backends, vec![BackendKind::Plonky3]);
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu", feature = "neural-engine"))]
    #[test]
    fn omitted_backend_resolution_uses_fixture_model_recommendation_when_available() {
        with_fixture_models_env(|| {
            let program = Program {
                field: FieldId::Goldilocks,
                ..Default::default()
            };
            let recommendation = zkf_runtime::recommend_backend_for_program(
                &program,
                None,
                OptimizationObjective::FastestProve,
            );
            let backend =
                resolve_backend_or_mode(None, None, &program, OptimizationObjective::FastestProve)
                    .expect("backend");

            assert_eq!(recommendation.source, "model");
            assert_eq!(backend.backend, recommendation.selected);
        });
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn apple_metal_explicit_mode_routes_bn254_when_certified_or_fails_closed() {
        let program = Program {
            field: FieldId::Bn254,
            ..Default::default()
        };
        if strict_bn254_auto_route_ready() {
            let backends = resolve_backend_targets_or_mode(&[], Some("metal-first"), &program, &[])
                .expect("route");
            assert_eq!(
                backends
                    .into_iter()
                    .map(|request| request.backend)
                    .collect::<Vec<_>>(),
                vec![BackendKind::ArkworksGroth16]
            );
        } else {
            let err = resolve_backend_targets_or_mode(&[], Some("metal-first"), &program, &[])
                .expect_err("reject");
            assert!(err.contains("certified strict BN254 route"));
            assert!(err.contains("arkworks-groth16"));
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn apple_metal_explicit_mode_routes_bn254_backend_when_certified_or_fails_closed() {
        let program = Program {
            field: FieldId::Bn254,
            ..Default::default()
        };
        if strict_bn254_auto_route_ready() {
            let backend = resolve_backend_or_mode(
                None,
                Some("metal-first"),
                &program,
                OptimizationObjective::FastestProve,
            )
            .expect("backend");
            assert_eq!(backend.backend, BackendKind::ArkworksGroth16);
        } else {
            let err = resolve_backend_or_mode(
                None,
                Some("metal-first"),
                &program,
                OptimizationObjective::FastestProve,
            )
            .expect_err("must reject");
            assert!(err.contains("certified strict BN254 route"));
            assert!(err.contains("bn254"));
            assert!(err.contains("arkworks-groth16"));
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn apple_metal_explicit_mode_rejects_goldilocks_programs_that_exceed_mmcs_width_limit() {
        let program = Program {
            field: FieldId::Goldilocks,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Range {
                    signal: "x".to_string(),
                    bits: 8,
                    label: Some("x_range".to_string()),
                },
                Constraint::Equal {
                    lhs: Expr::signal("out"),
                    rhs: Expr::signal("x"),
                    label: Some("out_eq_x".to_string()),
                },
            ],
            ..Default::default()
        };

        let err = resolve_backend_or_mode(
            None,
            Some("metal-first"),
            &program,
            OptimizationObjective::FastestProve,
        )
        .expect_err("must reject");
        assert!(err.contains("trace width"));
        assert!(err.contains("Metal MMCS width limit"));
    }

    #[test]
    fn export_parser_accepts_groth16() {
        assert_eq!(
            parse_export_scheme(Some("groth16")).unwrap(),
            Some("groth16")
        );
        assert_eq!(
            parse_prove_mode(Some("metal-first")).unwrap(),
            Some("metal-first")
        );
    }

    #[test]
    fn optimization_objective_parser_accepts_supported_values() {
        assert_eq!(
            parse_optimization_objective(Some("fastest-prove")).unwrap(),
            OptimizationObjective::FastestProve
        );
        assert_eq!(
            parse_optimization_objective(Some("smallest-proof")).unwrap(),
            OptimizationObjective::SmallestProof
        );
        assert_eq!(
            parse_optimization_objective(Some("no-trusted-setup")).unwrap(),
            OptimizationObjective::NoTrustedSetup
        );
    }

    #[test]
    fn halo2_field_preflight_suggests_exact_alternative() {
        let program = Program {
            field: FieldId::Bls12_381,
            ..Default::default()
        };
        let err = ensure_backend_supports_program_constraints(BackendKind::Halo2, &program)
            .expect_err("field mismatch should fail");
        assert!(err.contains("PastaFp"));
        assert!(err.contains("halo2-bls12-381"));
    }
}
