// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! `zkf runtime` subcommand group.

use crate::cli::RuntimeCommands;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zkf_backends::GpuSchedulerDecision;
use zkf_backends::metal_runtime::MetalRuntimeReport;
use zkf_core::ir::Program;
use zkf_core::witness::WitnessInputs;
use zkf_core::wrapping::{
    WrapModeOverride, WrapperCachePrepareReport, WrapperExecutionPolicy, WrapperPreview,
};
use zkf_core::{BackendKind, FieldId};
use zkf_core::{CompiledProgram, ProofArtifact};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WrapperPlanBindings {
    proof_sha256: String,
    compiled_sha256: String,
    source_backend: String,
    source_program_digest: String,
    compiled_backend: String,
    compiled_program_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GenericPlanBindings {
    program_sha256: String,
    inputs_sha256: String,
    program_digest: String,
    field: String,
    constraint_count: usize,
    signal_count: usize,
}

const PLAN_SCHEMA_V1: &str = "zkf-runtime-plan-v1";
const PLAN_SCHEMA_V2: &str = "zkf-runtime-plan-v2";
const STRICT_CERTIFICATION_SCHEMA_V1: &str = "zkf-strict-certification-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificationMode {
    Gate,
    Soak,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StrictCertificationMatch {
    pub(crate) present: bool,
    pub(crate) matches_current: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) failures: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) report_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) certified_at_unix_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) strict_gpu_busy_ratio_peak: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StrictCertificationBuildInfo {
    binary_path: String,
    binary_sha256: String,
    build_features: Vec<String>,
    rustc_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StrictCertificationDoctorSnapshot {
    production_ready: Option<bool>,
    certified_hardware_profile: String,
    strict_bn254_ready: bool,
    strict_bn254_auto_route: bool,
    strict_gpu_stage_coverage: Value,
    strict_gpu_busy_ratio_peak: Option<f64>,
    runtime: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StrictCertificationRunSummary {
    label: String,
    proof_path: String,
    proof_sha256: String,
    artifact_path: String,
    artifact_sha256: String,
    execution_trace_path: String,
    execution_trace_sha256: String,
    runtime_trace_path: String,
    runtime_trace_sha256: String,
    wrapper_cache_hit: bool,
    wrapper_cache_source: Option<String>,
    duration_ms: f64,
    peak_memory_bytes: Option<u64>,
    gpu_stage_busy_ratio: f64,
    qap_witness_map_engine: String,
    groth16_msm_engine: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StrictCertificationSummary {
    gate_passed: bool,
    soak_passed: bool,
    doctor_flips: usize,
    degraded_runs: usize,
    cold_gpu_stage_busy_ratio: Option<f64>,
    warm_gpu_stage_busy_ratio: Option<f64>,
    parallel_gpu_stage_busy_ratio_peak: Option<f64>,
    strict_gpu_busy_ratio_peak: f64,
    parallel_jobs: usize,
    fault_injection_failed_closed: bool,
    final_pass: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StrictCertificationSoakProgress {
    progress_schema: String,
    certification_mode: String,
    phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subphase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_label: Option<String>,
    updated_at_unix_ms: u128,
    soak_started_at_unix_ms: u128,
    elapsed_ms: u128,
    min_duration_ms: u128,
    remaining_duration_ms: u128,
    current_cycle: usize,
    required_cycles: usize,
    parallel_jobs: usize,
    strict_gpu_busy_ratio_peak: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    warm_gpu_stage_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parallel_gpu_stage_busy_ratio_peak: Option<f64>,
    doctor_flips: usize,
    degraded_runs: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resumed_from_cycle: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StrictCertificationFaultCheckpoint {
    checkpoint_schema: String,
    cycle: usize,
    failed_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdout_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stderr_path: Option<String>,
    updated_at_unix_ms: u128,
}

#[derive(Debug, Clone)]
struct SoakResumeState {
    soak_started_at_unix_ms: u128,
    current_cycle: usize,
    runs: Vec<StrictCertificationRunSummary>,
    strict_gpu_busy_ratio_peak: f64,
    warm_run_gpu: Option<f64>,
    parallel_gpu_peak: Option<f64>,
    max_parallel_jobs_observed: usize,
    doctor_flips: usize,
    fault_injection_failed_closed: bool,
    resumed_from_cycle: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StrictCertificationReport {
    report_schema: String,
    certification_mode: String,
    certified_at_unix_ms: u128,
    hardware_profile: String,
    proof: String,
    compiled: String,
    proof_sha256: String,
    compiled_sha256: String,
    strict_cache_prepare_sha256: String,
    build: StrictCertificationBuildInfo,
    doctor_preflight: StrictCertificationDoctorSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    doctor_postflight: Option<StrictCertificationDoctorSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepare_report_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepare_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    runs: Vec<StrictCertificationRunSummary>,
    summary: StrictCertificationSummary,
}

#[derive(Debug, Clone, Default)]
struct RuntimePolicyTraceInputs {
    field: Option<String>,
    backends: Vec<String>,
    constraints: Option<usize>,
    signals: Option<usize>,
    requested_jobs: Option<usize>,
    total_jobs: Option<usize>,
    gpu_stage_busy_ratio: Option<f64>,
    fallback_nodes: Option<usize>,
    node_count: Option<usize>,
    gpu_nodes: Option<usize>,
    cpu_nodes: Option<usize>,
    peak_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct RuntimePolicyFeatures {
    constraints: usize,
    signals: usize,
    requested_jobs: usize,
    total_jobs: usize,
    runtime_gpu_stage_busy_ratio: f64,
    runtime_fallback_ratio: f64,
    runtime_gpu_nodes: usize,
    runtime_cpu_nodes: usize,
    peak_memory_bytes: u64,
    ram_utilization: f64,
    metal_available: bool,
    strict_runtime_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct RuntimePolicyModelPrediction {
    runner: String,
    model_path: String,
    compute_units: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_lane_score: Option<f64>,
    outputs: Value,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimePolicyReport {
    policy_schema: String,
    generated_at_unix_ms: u128,
    field: String,
    backends: Vec<String>,
    objective: zkf_runtime::OptimizationObjective,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_path: Option<String>,
    features: RuntimePolicyFeatures,
    feature_labels: Vec<String>,
    feature_vector: Vec<f32>,
    scheduler: GpuSchedulerDecision,
    heuristic_gpu_lane_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_gpu_lane_score: Option<f64>,
    final_gpu_lane_score: f64,
    recommend_metal_first: bool,
    recommended_parallel_jobs: usize,
    certification: StrictCertificationMatch,
    resources: zkf_core::SystemResources,
    metal_runtime: MetalRuntimeReport,
    job_kind: String,
    dispatch_plan: zkf_runtime::DispatchPlan,
    candidate_rankings: Vec<zkf_runtime::DispatchCandidateScore>,
    backend_recommendation: zkf_runtime::BackendRecommendation,
    duration_estimate: zkf_runtime::DurationEstimate,
    anomaly_baseline: zkf_runtime::AnomalyVerdict,
    model_catalog: zkf_runtime::ModelCatalog,
    control_plane_features: zkf_runtime::ControlPlaneFeatures,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<RuntimePolicyModelPrediction>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct CommandCapture {
    stdout: String,
    stderr: String,
    status_ok: bool,
    exit_code: Option<i32>,
    peak_memory_bytes: Option<u64>,
}

fn unix_time_now_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .map(|duration| duration.as_millis())
}

#[allow(clippy::too_many_arguments)]
fn write_soak_progress(
    path: &Path,
    phase: &str,
    subphase: Option<&str>,
    active_label: Option<&str>,
    soak_started_at_unix_ms: u128,
    min_duration_ms: u128,
    current_cycle: usize,
    required_cycles: usize,
    parallel_jobs: usize,
    strict_gpu_busy_ratio_peak: f64,
    warm_gpu_stage_busy_ratio: Option<f64>,
    parallel_gpu_stage_busy_ratio_peak: Option<f64>,
    doctor_flips: usize,
    degraded_runs: usize,
    resumed_from_cycle: Option<usize>,
    failures: &[String],
) -> Result<(), String> {
    let updated_at_unix_ms = unix_time_now_ms()?;
    let elapsed_ms = updated_at_unix_ms.saturating_sub(soak_started_at_unix_ms);
    let remaining_duration_ms = min_duration_ms.saturating_sub(elapsed_ms);
    let progress = StrictCertificationSoakProgress {
        progress_schema: "zkf-strict-soak-progress-v1".to_string(),
        certification_mode: "soak".to_string(),
        phase: phase.to_string(),
        subphase: subphase.map(str::to_string),
        active_label: active_label.map(str::to_string),
        updated_at_unix_ms,
        soak_started_at_unix_ms,
        elapsed_ms,
        min_duration_ms,
        remaining_duration_ms,
        current_cycle,
        required_cycles,
        parallel_jobs,
        strict_gpu_busy_ratio_peak,
        warm_gpu_stage_busy_ratio,
        parallel_gpu_stage_busy_ratio_peak,
        doctor_flips,
        degraded_runs,
        resumed_from_cycle,
        failures: failures.to_vec(),
    };
    crate::util::write_json(path, &progress)
}

fn read_soak_progress(path: &Path) -> Option<StrictCertificationSoakProgress> {
    path.is_file().then(|| read_json_path(path).ok()).flatten()
}

fn fault_checkpoint_path(out_dir: &Path, cycle: usize) -> PathBuf {
    out_dir.join(format!("fault-cycle-{}.status.json", cycle))
}

fn write_fault_checkpoint(
    out_dir: &Path,
    cycle: usize,
    failed_closed: bool,
    capture: &CommandCapture,
    stdout_path: Option<&Path>,
    stderr_path: Option<&Path>,
) -> Result<(), String> {
    let checkpoint = StrictCertificationFaultCheckpoint {
        checkpoint_schema: "zkf-strict-fault-checkpoint-v1".to_string(),
        cycle,
        failed_closed,
        exit_code: capture.exit_code,
        stdout_path: stdout_path.map(|path| path.display().to_string()),
        stderr_path: stderr_path.map(|path| path.display().to_string()),
        updated_at_unix_ms: unix_time_now_ms()?,
    };
    crate::util::write_json(&fault_checkpoint_path(out_dir, cycle), &checkpoint)
}

fn aggregate_parallel_gpu_stage_busy_ratio(runs: &[StrictCertificationRunSummary]) -> f64 {
    runs.iter()
        .map(|run| run.gpu_stage_busy_ratio.clamp(0.0, 1.0))
        .sum::<f64>()
        .min(1.0)
}

fn min_parallel_gpu_stage_busy_ratio_for_jobs(parallel_jobs: usize) -> f64 {
    if parallel_jobs <= 1 { 0.20 } else { 0.60 }
}

#[cfg(target_os = "macos")]
fn macos_user_is_active() -> Option<bool> {
    let output = Command::new("pmset")
        .args(["-g", "assertions"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("UserIsActive"), Some("1")) => Some(true),
            (Some("UserIsActive"), Some("0")) => Some(false),
            _ => None,
        }
    })
}

#[derive(Debug, Clone, Default)]
struct RuntimePressureSample {
    user_active: Option<bool>,
    thermal_warning: bool,
    performance_warning: bool,
    memory_pressure: Option<u32>,
}

#[cfg(target_os = "macos")]
fn macos_runtime_pressure_sample() -> RuntimePressureSample {
    let mut sample = RuntimePressureSample {
        user_active: macos_user_is_active(),
        ..RuntimePressureSample::default()
    };

    if let Ok(output) = Command::new("pmset").args(["-g", "therm"]).output()
        && output.status.success()
        && let Ok(stdout) = String::from_utf8(output.stdout)
    {
        sample.thermal_warning = !stdout.contains("No thermal warning level has been recorded");
        sample.performance_warning =
            !stdout.contains("No performance warning level has been recorded");
    }

    if let Ok(output) = Command::new("sysctl")
        .args(["-n", "vm.memory_pressure"])
        .output()
        && output.status.success()
        && let Ok(stdout) = String::from_utf8(output.stdout)
    {
        sample.memory_pressure = stdout.trim().parse::<u32>().ok();
    }

    sample
}

#[cfg(not(target_os = "macos"))]
fn macos_runtime_pressure_sample() -> RuntimePressureSample {
    RuntimePressureSample::default()
}

fn desktop_safe_parallel_cap(requested_jobs: usize) -> (usize, Option<String>, Option<Duration>) {
    #[cfg(target_os = "macos")]
    {
        let sample = macos_runtime_pressure_sample();
        let (cap, reason, cooldown) = if sample.thermal_warning || sample.performance_warning {
            (
                1usize,
                "thermal or performance pressure active",
                Some(Duration::from_secs(60)),
            )
        } else if sample.memory_pressure.unwrap_or(0) > 0 {
            (
                2usize,
                "memory pressure active",
                Some(Duration::from_secs(30)),
            )
        } else {
            match sample.user_active {
                Some(false) => (2usize, "display idle or user inactive", None),
                Some(true) => (4usize, "desktop-safe WindowServer cap", None),
                None => (4usize, "desktop-safe macOS cap", None),
            }
        };
        let capped = requested_jobs.min(cap).max(1);
        if capped < requested_jobs {
            return (
                capped,
                Some(format!(
                    "reduced auto parallel jobs from {requested_jobs} to {capped} ({reason})"
                )),
                cooldown,
            );
        }
        if let Some(cooldown) = cooldown {
            return (
                capped,
                Some(format!(
                    "holding at {capped} parallel job(s) because {reason}; cooldown={}s",
                    cooldown.as_secs()
                )),
                Some(cooldown),
            );
        }
        if reason == "display idle or user inactive" {
            return (capped, Some(reason.to_string()), None);
        }
    }

    (requested_jobs.max(1), None, None)
}

#[cfg(target_os = "macos")]
fn spawn_soak_caffeinate_guard() -> Option<std::process::Child> {
    let pid = std::process::id().to_string();
    match Command::new("caffeinate")
        .args(["-dimsu", "-w", &pid])
        .spawn()
    {
        Ok(child) => Some(child),
        Err(err) => {
            eprintln!("warning: failed to start caffeinate guard for soak: {err}");
            None
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn spawn_soak_caffeinate_guard() -> Option<std::process::Child> {
    None
}

pub(crate) fn handle_runtime(command: RuntimeCommands) -> Result<(), String> {
    match command {
        RuntimeCommands::Plan {
            backend,
            constraints,
            field,
            program,
            inputs,
            trust,
            hardware_profile,
            proof,
            compiled,
            output,
        } => handle_plan(
            backend,
            constraints,
            field,
            program,
            inputs,
            trust,
            hardware_profile,
            proof,
            compiled,
            output,
        ),
        RuntimeCommands::Execute {
            plan,
            backend,
            program,
            inputs,
            witness,
            out,
            proof,
            compiled,
            trust,
            hardware_profile,
            trace,
        } => handle_execute(
            plan,
            backend,
            program,
            inputs,
            witness,
            out,
            proof,
            compiled,
            trust,
            hardware_profile,
            trace,
        ),
        RuntimeCommands::Prepare {
            proof,
            compiled,
            trust,
            hardware_profile,
            allow_large_direct_materialization,
            install_bundle,
            export_bundle,
            output,
            json,
        } => handle_prepare(
            proof,
            compiled,
            trust,
            hardware_profile,
            allow_large_direct_materialization,
            install_bundle,
            export_bundle,
            output,
            json,
        ),
        RuntimeCommands::Trace { proof, plan, json } => handle_trace(proof, plan, json),
        RuntimeCommands::Certify {
            mode,
            proof,
            compiled,
            out_dir,
            json_out,
            parallel_jobs,
            hours,
            cycles,
        } => handle_certify(
            mode,
            proof,
            compiled,
            out_dir,
            json_out,
            parallel_jobs,
            hours,
            cycles,
        ),
        RuntimeCommands::Policy {
            trace,
            field,
            backends,
            objective,
            constraints,
            signals,
            requested_jobs,
            total_jobs,
            model,
            compute_units,
            json,
        } => handle_policy(
            trace,
            field,
            backends,
            objective,
            constraints,
            signals,
            requested_jobs,
            total_jobs,
            model,
            compute_units,
            json,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_policy(
    trace: Option<PathBuf>,
    field: Option<String>,
    backends: Option<String>,
    objective: String,
    constraints: Option<usize>,
    signals: Option<usize>,
    requested_jobs: Option<usize>,
    total_jobs: Option<usize>,
    model: Option<PathBuf>,
    compute_units: String,
    json_output: bool,
) -> Result<(), String> {
    let report = build_runtime_policy_report(
        trace,
        field,
        backends,
        objective,
        constraints,
        signals,
        requested_jobs,
        total_jobs,
        model,
        compute_units,
    )?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("field: {}", report.field);
        println!("backends: {}", report.backends.join(", "));
        println!("objective: {}", report.objective.as_str());
        println!("job kind: {}", report.job_kind);
        println!("dispatch plan: {}", report.dispatch_plan.candidate.as_str());
        println!(
            "recommended backend: {}",
            report.backend_recommendation.selected
        );
        println!(
            "advisory duration estimate ms: {:.3}",
            report.duration_estimate.estimate_ms
        );
        match report.duration_estimate.upper_bound_ms {
            Some(value) => println!("conservative duration upper bound ms: {value:.3}"),
            None => println!("conservative duration upper bound ms: unavailable"),
        }
        println!(
            "execution regime: {}",
            report.duration_estimate.execution_regime.as_str()
        );
        println!(
            "eta semantics: {}",
            report.duration_estimate.eta_semantics.as_str()
        );
        println!(
            "countdown safe: {}",
            report.duration_estimate.countdown_safe
        );
        if let Some(note) = &report.duration_estimate.note {
            println!("duration note: {note}");
        }
        println!(
            "heuristic gpu lane score: {:.3}",
            report.heuristic_gpu_lane_score
        );
        if let Some(score) = report.model_gpu_lane_score {
            println!("model gpu lane score: {:.3}", score);
        }
        println!("final gpu lane score: {:.3}", report.final_gpu_lane_score);
        println!(
            "recommended parallel jobs: {}",
            report.recommended_parallel_jobs
        );
        println!("prefer metal-first: {}", report.recommend_metal_first);
        println!(
            "strict runtime ready: {}",
            report.features.strict_runtime_ready
        );
        println!(
            "current certification installed: {}",
            report.certification.matches_current
        );
        for note in &report.notes {
            println!("note: {note}");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_runtime_policy_report(
    trace: Option<PathBuf>,
    field: Option<String>,
    backends: Option<String>,
    objective: String,
    constraints: Option<usize>,
    signals: Option<usize>,
    requested_jobs: Option<usize>,
    total_jobs: Option<usize>,
    model: Option<PathBuf>,
    compute_units: String,
) -> Result<RuntimePolicyReport, String> {
    let trace_value = trace
        .as_ref()
        .map(|path| read_json_path::<Value>(path.as_path()))
        .transpose()?;
    let trace_inputs = trace_value
        .as_ref()
        .map(extract_runtime_policy_trace_inputs)
        .unwrap_or_default();
    let compute_units = normalize_policy_compute_units(&compute_units)?;
    let objective = crate::util::parse_optimization_objective(Some(&objective))?;

    let resources = zkf_core::SystemResources::detect();
    let metal_runtime = zkf_backends::metal_runtime_report();
    let certification = installed_strict_certification_match();
    let strict_runtime_ready =
        zkf_backends::strict_bn254_auto_route_ready_with_runtime(&metal_runtime);

    let selected_field = field
        .or_else(|| trace_inputs.field.clone())
        .unwrap_or_else(|| "bn254".to_string());
    let field_hint = parse_runtime_policy_field(&selected_field)?;
    let selected_backends =
        parse_policy_backends(backends.as_deref(), &trace_inputs, Some(field_hint))?;

    let constraints = constraints.or(trace_inputs.constraints).unwrap_or(1).max(1);
    let signals = signals.or(trace_inputs.signals).unwrap_or(1).max(1);
    let requested_jobs = requested_jobs
        .or(trace_inputs.requested_jobs)
        .unwrap_or_else(|| resources.recommend().proving_threads.max(1))
        .max(1);
    let total_jobs = total_jobs
        .or(trace_inputs.total_jobs)
        .unwrap_or_else(|| requested_jobs.max(selected_backends.len()).max(1))
        .max(1);
    let control_plane_decision = with_scheduler_model_override(model.as_deref(), || {
        zkf_runtime::evaluate_control_plane(&zkf_runtime::ControlPlaneRequest {
            job_kind: infer_runtime_policy_job_kind(trace_value.as_ref()),
            objective,
            graph: None,
            constraint_count_override: Some(constraints),
            signal_count_override: Some(signals),
            stage_node_counts_override: trace_value
                .as_ref()
                .map(extract_runtime_policy_stage_counts)
                .filter(|counts| !counts.is_empty()),
            field_hint: Some(field_hint),
            program: None,
            compiled: None,
            preview: None,
            witness: None,
            witness_inputs: None,
            requested_backend: None,
            backend_route: None,
            trust_lane: zkf_runtime::RequiredTrustLane::StrictCryptographic,
            requested_jobs: Some(requested_jobs),
            total_jobs: Some(total_jobs),
            backend_candidates: selected_backends.clone(),
        })
    })?;

    let scheduler = zkf_backends::recommend_gpu_jobs(
        &selected_backends,
        constraints,
        signals,
        Some(requested_jobs),
        total_jobs,
    );
    let node_count = trace_inputs.node_count.unwrap_or_else(|| {
        trace_inputs
            .gpu_nodes
            .unwrap_or(0)
            .saturating_add(trace_inputs.cpu_nodes.unwrap_or(0))
    });
    let runtime_fallback_ratio = if node_count == 0 {
        0.0
    } else {
        trace_inputs.fallback_nodes.unwrap_or(0) as f64 / node_count as f64
    };
    let features = RuntimePolicyFeatures {
        constraints,
        signals,
        requested_jobs,
        total_jobs,
        runtime_gpu_stage_busy_ratio: trace_inputs.gpu_stage_busy_ratio.unwrap_or(0.0),
        runtime_fallback_ratio: runtime_fallback_ratio.clamp(0.0, 1.0),
        runtime_gpu_nodes: trace_inputs.gpu_nodes.unwrap_or(0),
        runtime_cpu_nodes: trace_inputs.cpu_nodes.unwrap_or(0),
        peak_memory_bytes: trace_inputs.peak_memory_bytes.unwrap_or(0),
        ram_utilization: resources.ram_utilization(),
        metal_available: scheduler.metal_available,
        strict_runtime_ready,
    };
    let feature_labels = runtime_policy_feature_labels();
    let feature_vector = build_runtime_policy_feature_vector(&features, resources.total_ram_bytes);
    let heuristic_gpu_lane_score = compute_runtime_policy_heuristic_score(
        &features,
        &scheduler,
        &metal_runtime,
        &resources,
        &certification,
    );
    let model_prediction = control_plane_decision.model_catalog.scheduler.as_ref().map(
        |descriptor| RuntimePolicyModelPrediction {
            runner: "zkf-runtime-native".to_string(),
            model_path: descriptor.path.clone(),
            compute_units: "cpu-and-neural-engine".to_string(),
            gpu_lane_score: None,
            outputs: json!({
                "dispatch_candidate_rankings": control_plane_decision.candidate_rankings.clone(),
                "best_predicted_duration_ms": control_plane_decision
                    .candidate_rankings
                    .first()
                    .map(|candidate| candidate.predicted_duration_ms),
            }),
        },
    );
    let model_gpu_lane_score = None;
    let final_gpu_lane_score =
        combine_runtime_policy_scores(heuristic_gpu_lane_score, model_gpu_lane_score);
    let recommended_parallel_jobs =
        adjust_runtime_policy_jobs(scheduler.recommended_jobs, final_gpu_lane_score, &resources);
    let recommend_metal_first = scheduler.metal_available
        && !metal_runtime.metal_dispatch_circuit_open
        && final_gpu_lane_score >= 0.45;
    let mut notes = build_runtime_policy_notes(
        &features,
        &scheduler,
        &metal_runtime,
        &resources,
        &certification,
        model_prediction.as_ref(),
    );
    if compute_units != "cpu-and-neural-engine" {
        notes.push(
            "runtime-native policy fixes Core ML compute units to cpu-and-neural-engine; the CLI override is ignored on this path"
                .to_string(),
        );
    }
    notes.extend(control_plane_decision.notes.iter().cloned());

    let report = RuntimePolicyReport {
        policy_schema: "zkf-runtime-policy-v2".to_string(),
        generated_at_unix_ms: unix_time_now_ms()?,
        field: field_hint.as_str().to_string(),
        backends: selected_backends
            .iter()
            .map(|backend| backend.to_string())
            .collect(),
        objective,
        trace_path: trace.as_ref().map(|path| path.display().to_string()),
        features,
        feature_labels,
        feature_vector,
        scheduler,
        heuristic_gpu_lane_score,
        model_gpu_lane_score,
        final_gpu_lane_score,
        recommend_metal_first,
        recommended_parallel_jobs,
        certification,
        resources,
        metal_runtime,
        job_kind: control_plane_decision.job_kind.as_str().to_string(),
        dispatch_plan: control_plane_decision.dispatch_plan.clone(),
        candidate_rankings: control_plane_decision.candidate_rankings.clone(),
        backend_recommendation: control_plane_decision.backend_recommendation.clone(),
        duration_estimate: control_plane_decision.duration_estimate.clone(),
        anomaly_baseline: control_plane_decision.anomaly_baseline.clone(),
        model_catalog: control_plane_decision.model_catalog.clone(),
        control_plane_features: control_plane_decision.features.clone(),
        model: model_prediction,
        notes,
    };
    Ok(report)
}

fn infer_runtime_policy_job_kind(trace: Option<&Value>) -> zkf_runtime::JobKind {
    let Some(trace) = trace else {
        return zkf_runtime::JobKind::Prove;
    };
    if trace.get("wrapper_preview").is_some()
        || trace.get("wrapper_strategy").is_some()
        || trace.get("source_backend").is_some()
    {
        return zkf_runtime::JobKind::Wrap;
    }
    let mode = string_value_at(trace, "mode")
        .or_else(|| string_pointer(trace, "/metadata/mode"))
        .unwrap_or_default();
    if mode.starts_with("fold") {
        zkf_runtime::JobKind::Fold
    } else {
        zkf_runtime::JobKind::Prove
    }
}

fn extract_runtime_policy_stage_counts(trace: &Value) -> BTreeMap<String, usize> {
    let breakdown = trace
        .get("runtime_stage_breakdown")
        .or_else(|| trace.get("stage_breakdown"))
        .and_then(Value::as_object);
    let mut counts = BTreeMap::new();
    if let Some(breakdown) = breakdown {
        for (stage, payload) in breakdown {
            let count = payload
                .get("node_count")
                .and_then(Value::as_u64)
                .or_else(|| {
                    Some(
                        payload
                            .get("gpu_nodes")
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                            + payload
                                .get("cpu_nodes")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                    )
                })
                .unwrap_or(0) as usize;
            if count > 0 {
                counts.insert(stage.clone(), count);
            }
        }
    }
    counts
}

fn with_scheduler_model_override<T>(
    model: Option<&Path>,
    f: impl FnOnce() -> T,
) -> Result<T, String> {
    let Some(model) = model else {
        return Ok(f());
    };
    let prior = std::env::var_os("ZKF_SCHEDULER_MODEL");
    unsafe {
        std::env::set_var("ZKF_SCHEDULER_MODEL", model);
    }
    let result = f();
    if let Some(prior) = prior {
        unsafe {
            std::env::set_var("ZKF_SCHEDULER_MODEL", prior);
        }
    } else {
        unsafe {
            std::env::remove_var("ZKF_SCHEDULER_MODEL");
        }
    }
    Ok(result)
}

fn extract_runtime_policy_trace_inputs(trace: &Value) -> RuntimePolicyTraceInputs {
    let mut inputs = RuntimePolicyTraceInputs {
        field: string_value_at(trace, "field")
            .or_else(|| string_pointer(trace, "/runtime_plan/field"))
            .or_else(|| string_pointer(trace, "/wrapper_preview/source_field"))
            .or_else(|| string_pointer(trace, "/metadata/source_field")),
        backends: Vec::new(),
        constraints: usize_value_at(trace, "constraints")
            .or_else(|| usize_value_at(trace, "constraint_count"))
            .or_else(|| usize_value_at(trace, "umpg_estimated_constraints"))
            .or_else(|| usize_pointer(trace, "/runtime_plan/constraints"))
            .or_else(|| usize_pointer(trace, "/runtime_plan/constraint_count"))
            .or_else(|| usize_pointer(trace, "/metadata/constraints"))
            .or_else(|| usize_pointer(trace, "/metadata/constraint_count")),
        signals: usize_value_at(trace, "signals")
            .or_else(|| usize_value_at(trace, "signal_count"))
            .or_else(|| usize_pointer(trace, "/runtime_plan/signals"))
            .or_else(|| usize_pointer(trace, "/runtime_plan/signal_count"))
            .or_else(|| usize_pointer(trace, "/metadata/signals"))
            .or_else(|| usize_pointer(trace, "/metadata/signal_count")),
        requested_jobs: usize_value_at(trace, "requested_jobs")
            .or_else(|| usize_value_at(trace, "parallel_jobs")),
        total_jobs: usize_value_at(trace, "total_jobs"),
        gpu_stage_busy_ratio: f64_value_at(trace, "runtime_gpu_stage_busy_ratio")
            .or_else(|| f64_value_at(trace, "gpu_stage_busy_ratio"))
            .or_else(|| f64_pointer(trace, "/metadata/runtime_gpu_stage_busy_ratio"))
            .or_else(|| f64_pointer(trace, "/metadata/gpu_stage_busy_ratio")),
        fallback_nodes: usize_value_at(trace, "fallback_nodes")
            .or_else(|| usize_pointer(trace, "/metadata/fallback_nodes")),
        node_count: usize_value_at(trace, "node_count")
            .or_else(|| usize_value_at(trace, "runtime_stage_count"))
            .or_else(|| usize_pointer(trace, "/metadata/umpg_node_count"))
            .or_else(|| usize_pointer(trace, "/metadata/node_count")),
        gpu_nodes: usize_value_at(trace, "gpu_nodes")
            .or_else(|| usize_pointer(trace, "/metadata/gpu_nodes")),
        cpu_nodes: usize_value_at(trace, "cpu_nodes")
            .or_else(|| usize_pointer(trace, "/metadata/cpu_nodes")),
        peak_memory_bytes: u64_value_at(trace, "peak_memory_bytes")
            .or_else(|| u64_pointer(trace, "/metadata/peak_memory_bytes")),
    };

    for candidate in [
        string_value_at(trace, "source_backend"),
        string_value_at(trace, "backend"),
        string_pointer(trace, "/runtime_plan/backend"),
        string_pointer(trace, "/lowering_report/backend"),
        string_pointer(trace, "/metadata/umpg_backend_prove_backend"),
    ]
    .into_iter()
    .flatten()
    {
        if !candidate.is_empty() {
            inputs.backends.push(candidate);
        }
    }

    inputs
}

fn parse_policy_backends(
    raw: Option<&str>,
    trace_inputs: &RuntimePolicyTraceInputs,
    field_hint: Option<FieldId>,
) -> Result<Vec<BackendKind>, String> {
    let mut names = Vec::new();
    if let Some(raw) = raw {
        names.extend(
            raw.split(',')
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .map(str::to_string),
        );
    } else {
        names.extend(trace_inputs.backends.iter().cloned());
    }
    if names.is_empty() {
        return Ok(default_runtime_policy_backends(
            field_hint.unwrap_or(FieldId::Bn254),
        ));
    }

    let mut parsed = Vec::new();
    let mut seen = BTreeSet::new();
    for name in names {
        let backend = name.parse::<BackendKind>()?;
        if seen.insert(backend.as_str().to_string()) {
            parsed.push(backend);
        }
    }
    Ok(parsed)
}

fn parse_runtime_policy_field(value: &str) -> Result<FieldId, String> {
    match value {
        "bn254_fr" => Ok(FieldId::Bn254),
        other => crate::util::parse_field(other),
    }
}

fn default_runtime_policy_backends(field: FieldId) -> Vec<BackendKind> {
    let mut backends = vec![
        zkf_backends::preferred_backend_for_field(field),
        BackendKind::ArkworksGroth16,
        BackendKind::Plonky3,
        BackendKind::Nova,
        BackendKind::HyperNova,
        BackendKind::Halo2,
        BackendKind::Halo2Bls12381,
        BackendKind::Sp1,
        BackendKind::RiscZero,
        BackendKind::MidnightCompact,
    ];
    let mut parsed = Vec::new();
    let mut seen = BTreeSet::new();
    for backend in backends.drain(..) {
        let supported = match backend {
            BackendKind::ArkworksGroth16 | BackendKind::Nova | BackendKind::HyperNova => {
                &[FieldId::Bn254][..]
            }
            BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => {
                &[FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31][..]
            }
            BackendKind::Halo2 => &[FieldId::PastaFp][..],
            BackendKind::Halo2Bls12381 => &[FieldId::Bls12_381][..],
            BackendKind::MidnightCompact => &[FieldId::PastaFp, FieldId::PastaFq][..],
        };
        if supported.contains(&field) && seen.insert(backend.as_str().to_string()) {
            parsed.push(backend);
        }
    }
    parsed
}

fn runtime_policy_feature_labels() -> Vec<String> {
    [
        "constraints_log2_norm",
        "signals_log2_norm",
        "requested_jobs_ratio",
        "total_jobs_log2_norm",
        "gpu_busy_ratio",
        "fallback_ratio",
        "ram_utilization",
        "peak_memory_ratio",
        "metal_available",
        "strict_runtime_ready",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn build_runtime_policy_feature_vector(
    features: &RuntimePolicyFeatures,
    total_ram_bytes: u64,
) -> Vec<f32> {
    let requested_jobs_ratio = if features.total_jobs == 0 {
        0.0
    } else {
        features.requested_jobs as f64 / features.total_jobs as f64
    };
    let peak_memory_ratio = if total_ram_bytes == 0 {
        0.0
    } else {
        features.peak_memory_bytes as f64 / total_ram_bytes as f64
    };

    vec![
        normalized_log2(features.constraints, 24.0),
        normalized_log2(features.signals, 24.0),
        requested_jobs_ratio.clamp(0.0, 1.0) as f32,
        normalized_log2(features.total_jobs, 8.0),
        features.runtime_gpu_stage_busy_ratio.clamp(0.0, 1.0) as f32,
        features.runtime_fallback_ratio.clamp(0.0, 1.0) as f32,
        features.ram_utilization.clamp(0.0, 1.0) as f32,
        peak_memory_ratio.clamp(0.0, 1.0) as f32,
        if features.metal_available { 1.0 } else { 0.0 },
        if features.strict_runtime_ready {
            1.0
        } else {
            0.0
        },
    ]
}

fn normalized_log2(value: usize, max_log2: f64) -> f32 {
    if value == 0 {
        return 0.0;
    }
    (((value as f64) + 1.0).log2() / max_log2).clamp(0.0, 1.0) as f32
}

fn compute_runtime_policy_heuristic_score(
    features: &RuntimePolicyFeatures,
    scheduler: &GpuSchedulerDecision,
    metal_runtime: &MetalRuntimeReport,
    resources: &zkf_core::SystemResources,
    certification: &StrictCertificationMatch,
) -> f64 {
    let accelerator_strength =
        (metal_runtime.active_accelerators.len().min(6) as f64 / 6.0).clamp(0.0, 1.0);
    let job_scale = if scheduler.total_jobs == 0 {
        0.0
    } else {
        scheduler.recommended_jobs as f64 / scheduler.total_jobs as f64
    };
    let certification_score = if certification.matches_current {
        1.0
    } else {
        0.0
    };
    let strict_score = if features.strict_runtime_ready {
        1.0
    } else {
        0.0
    };

    let mut score = 0.10;
    if scheduler.metal_available {
        score += 0.20;
    }
    if !metal_runtime.metal_dispatch_circuit_open {
        score += 0.10;
    }
    score += 0.20 * features.runtime_gpu_stage_busy_ratio.clamp(0.0, 1.0);
    score += 0.10 * (1.0 - features.runtime_fallback_ratio.clamp(0.0, 1.0));
    score += 0.10 * accelerator_strength;
    score += 0.10 * job_scale.clamp(0.0, 1.0);
    score += 0.10 * (1.0 - features.ram_utilization.clamp(0.0, 1.0));
    score += 0.05 * strict_score;
    score += 0.05 * certification_score;

    if metal_runtime.metal_disabled_by_env {
        score -= 0.30;
    }
    if metal_runtime.metal_dispatch_circuit_open {
        score -= 0.25;
    }
    score -= match resources.pressure.level {
        zkf_core::PressureLevel::Normal => 0.0,
        zkf_core::PressureLevel::Elevated => 0.05,
        zkf_core::PressureLevel::High => 0.15,
        zkf_core::PressureLevel::Critical => 0.30,
    };

    score.clamp(0.0, 1.0)
}

fn combine_runtime_policy_scores(heuristic: f64, model: Option<f64>) -> f64 {
    match model {
        Some(model_score) => {
            ((heuristic * 0.70) + (model_score.clamp(0.0, 1.0) * 0.30)).clamp(0.0, 1.0)
        }
        None => heuristic.clamp(0.0, 1.0),
    }
}

fn adjust_runtime_policy_jobs(
    recommended_jobs: usize,
    final_score: f64,
    resources: &zkf_core::SystemResources,
) -> usize {
    let mut jobs = recommended_jobs.max(1);
    jobs = match resources.pressure.level {
        zkf_core::PressureLevel::Normal => jobs,
        zkf_core::PressureLevel::Elevated => jobs.min(2),
        zkf_core::PressureLevel::High | zkf_core::PressureLevel::Critical => 1,
    };
    if final_score < 0.35 {
        1
    } else if final_score < 0.55 {
        jobs.clamp(1, 2)
    } else {
        jobs.max(1)
    }
}

fn build_runtime_policy_notes(
    features: &RuntimePolicyFeatures,
    scheduler: &GpuSchedulerDecision,
    metal_runtime: &MetalRuntimeReport,
    resources: &zkf_core::SystemResources,
    certification: &StrictCertificationMatch,
    model: Option<&RuntimePolicyModelPrediction>,
) -> Vec<String> {
    let mut notes = Vec::new();
    notes.push(
        "Neural Engine policy only steers scheduling and diagnostics; proof arithmetic still runs on Metal or CPU."
            .to_string(),
    );
    if model.is_none() {
        notes.push(
            "No Core ML model was provided; policy output is heuristic-only. Pass --model to execute a local control-plane model on CPU/ANE."
                .to_string(),
        );
    }
    if let Some(model) = model {
        notes.push(format!(
            "Core ML control-plane model executed via {} using compute_units={}.",
            model.runner, model.compute_units
        ));
    }
    if metal_runtime.metal_dispatch_circuit_open {
        notes.push(
            "Metal dispatch circuit is open; keep proofs on CPU until the driver stabilizes."
                .to_string(),
        );
    }
    if !features.strict_runtime_ready {
        notes.push(
            "Strict BN254 auto-route is not fully ready for this runtime snapshot.".to_string(),
        );
    }
    if !certification.matches_current {
        notes.push(
            "This host is not yet carrying a current strict soak certification report.".to_string(),
        );
    }
    if !scheduler.metal_available {
        notes.push(
            "Metal is not available, so the control plane should stay conservative.".to_string(),
        );
    }
    if resources.pressure.level != zkf_core::PressureLevel::Normal {
        notes.push(format!(
            "Current memory pressure is {}; policy is reducing parallelism.",
            resources.pressure.level
        ));
    }
    if features.runtime_gpu_stage_busy_ratio <= 0.0 {
        notes.push(
            "No runtime GPU trace was supplied, so busy ratio is inferred as zero.".to_string(),
        );
    }
    notes
}

#[allow(dead_code)]
fn run_ane_policy_model(
    model_path: &Path,
    feature_vector: &[f32],
    compute_units: &str,
) -> Result<RuntimePolicyModelPrediction, String> {
    let compute_units = normalize_policy_compute_units(compute_units)?;
    let input_json =
        serde_json::to_string(&json!({ "features": feature_vector })).map_err(|e| e.to_string())?;
    let output = if let Some(runner) = std::env::var_os("ZKF_ANE_POLICY_RUNNER") {
        let runner = PathBuf::from(runner);
        let output = Command::new(&runner)
            .args([
                "--model",
                &model_path.display().to_string(),
                "--features",
                &input_json,
                "--compute-units",
                compute_units,
            ])
            .output()
            .map_err(|e| format!("failed to invoke {}: {e}", runner.display()))?;
        (output, runner.display().to_string())
    } else {
        let helper_path = ane_policy_helper_path();
        if !helper_path.exists() {
            return Err(format!(
                "ANE policy runner is missing: {}",
                helper_path.display()
            ));
        }
        let args = [
            helper_path.display().to_string(),
            "--model".to_string(),
            model_path.display().to_string(),
            "--features".to_string(),
            input_json,
            "--compute-units".to_string(),
            compute_units.to_string(),
        ];
        let output = Command::new("swift")
            .args(&args)
            .output()
            .or_else(|_| Command::new("xcrun").arg("swift").args(&args).output())
            .map_err(|e| format!("failed to invoke swift Core ML runner: {e}"))?;
        (output, helper_path.display().to_string())
    };

    if !output.0.status.success() {
        return Err(format!(
            "ANE policy model execution failed: {}",
            String::from_utf8_lossy(&output.0.stderr).trim()
        ));
    }

    let prediction: Value = serde_json::from_slice(&output.0.stdout)
        .map_err(|e| format!("invalid ANE policy JSON: {e}"))?;
    let gpu_lane_score = prediction
        .get("gpu_lane_score")
        .and_then(Value::as_f64)
        .or_else(|| {
            prediction
                .pointer("/outputs/gpu_lane_score")
                .and_then(Value::as_f64)
        })
        .or_else(|| first_numeric_output(prediction.get("outputs")));

    Ok(RuntimePolicyModelPrediction {
        runner: output.1,
        model_path: model_path.display().to_string(),
        compute_units: compute_units.to_string(),
        gpu_lane_score,
        outputs: prediction.get("outputs").cloned().unwrap_or(prediction),
    })
}

#[allow(dead_code)]
fn ane_policy_helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts")
        .join("zkf_ane_policy.swift")
}

#[allow(dead_code)]
fn default_ane_policy_model_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ZKF_ANE_POLICY_MODEL") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    [
        root.join("target")
            .join("coreml")
            .join("zkf-runtime-policy.mlpackage"),
        root.join("tmp_ane_policy.mlpackage"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn normalize_policy_compute_units(value: &str) -> Result<&str, String> {
    match value {
        "all" | "cpu-and-neural-engine" | "cpu-only" => Ok(value),
        other => Err(format!(
            "invalid --compute-units value '{other}' (expected all, cpu-and-neural-engine, or cpu-only)"
        )),
    }
}

#[allow(dead_code)]
fn first_numeric_output(value: Option<&Value>) -> Option<f64> {
    let Value::Object(map) = value? else {
        return None;
    };
    map.values().find_map(|candidate| match candidate {
        Value::Number(number) => number.as_f64(),
        Value::Array(values) if values.len() == 1 => values.first().and_then(Value::as_f64),
        _ => None,
    })
}

fn string_value_at(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn string_pointer(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn usize_value_at(value: &Value, key: &str) -> Option<usize> {
    value.get(key).and_then(value_to_usize)
}

fn usize_pointer(value: &Value, pointer: &str) -> Option<usize> {
    value.pointer(pointer).and_then(value_to_usize)
}

fn u64_value_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(value_to_u64)
}

fn u64_pointer(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(value_to_u64)
}

fn f64_value_at(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(value_to_f64)
}

fn f64_pointer(value: &Value, pointer: &str) -> Option<f64> {
    value.pointer(pointer).and_then(value_to_f64)
}

fn value_to_usize(value: &Value) -> Option<usize> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| usize::try_from(value).ok()),
        Value::String(raw) => raw.parse::<usize>().ok(),
        _ => None,
    }
}

fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => raw.parse::<u64>().ok(),
        _ => None,
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(raw) => raw.parse::<f64>().ok(),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_plan(
    backend: Option<String>,
    constraints: Option<usize>,
    field: Option<String>,
    program: Option<PathBuf>,
    inputs: Option<PathBuf>,
    trust: Option<String>,
    hardware_profile: Option<String>,
    proof: Option<PathBuf>,
    compiled: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<(), String> {
    use zkf_runtime::{ExecutionMode, RuntimeCompiler};

    let trust_lane = parse_cli_trust_lane(trust.as_deref())?;
    let hardware_profile = resolve_hardware_profile(hardware_profile.as_deref())?;
    let plan_json = if let Some((proof_path, compiled_path)) =
        resolve_wrapper_inputs(proof, compiled)?
    {
        if backend.is_some()
            || constraints.is_some()
            || field.is_some()
            || program.is_some()
            || inputs.is_some()
        {
            return Err(
                "runtime plan wrapper mode cannot be combined with --backend, --constraints, --field, --program, or --inputs"
                    .to_string(),
            );
        }
        let source_proof: ProofArtifact = read_json_path(&proof_path)?;
        let source_compiled: CompiledProgram = read_json_path(&compiled_path)?;
        let (plan, _, _) = build_wrapper_runtime_plan_document_from_inputs(
            Some(&proof_path),
            Some(&compiled_path),
            &source_proof,
            &source_compiled,
            trust_lane,
            hardware_profile,
            None,
        )?;
        plan
    } else if let Some((program_path, inputs_path, program_doc, witness_inputs)) =
        resolve_generic_program_inputs(program, inputs)?
    {
        let backend = backend.as_deref().unwrap_or("groth16");
        let constraint_count = program_doc.constraints.len();
        if let Some(expected) = constraints
            && expected != constraint_count
        {
            return Err(format!(
                "runtime plan constraint count mismatch: --constraints requested {expected}, but {} has {constraint_count}",
                program_path.display()
            ));
        }
        let field_str = field_name_for_program(&program_doc)?;
        if let Some(requested_field) = field.as_deref() {
            let requested_field = parse_field_name(Some(requested_field))?;
            if requested_field != field_str {
                return Err(format!(
                    "runtime plan field mismatch: --field requested {requested_field}, but {} uses {field_str}",
                    program_path.display()
                ));
            }
        }
        let graph = RuntimeCompiler::build_plan(
            constraint_count,
            field_str,
            backend,
            trust_lane,
            ExecutionMode::Deterministic,
        )
        .map_err(|e| e.to_string())?;
        let bindings = build_generic_plan_bindings_from_inputs(
            Some(&program_path),
            Some(&inputs_path),
            &program_doc,
            &witness_inputs,
        )?;
        build_generic_plan_document(
            backend,
            constraint_count,
            field_str,
            trust_lane,
            hardware_profile,
            Some(&program_path),
            Some(&inputs_path),
            Some(&bindings),
            &graph,
        )?
    } else {
        let backend = backend.as_deref().unwrap_or("groth16");
        let n = constraints.unwrap_or(1024);
        let field_str = parse_field_name(field.as_deref())?;
        let graph = RuntimeCompiler::build_plan(
            n,
            field_str,
            backend,
            trust_lane,
            ExecutionMode::Deterministic,
        )
        .map_err(|e| e.to_string())?;
        build_generic_plan_document(
            backend,
            n,
            field_str,
            trust_lane,
            hardware_profile,
            None,
            None,
            None,
            &graph,
        )?
    };

    let json_str = serde_json::to_string_pretty(&plan_json).map_err(|e| e.to_string())?;

    if let Some(path) = output {
        crate::util::write_json(&path, &plan_json)?;
        println!("wrote plan to {}", path.display());
    } else {
        println!("{json_str}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_execute(
    plan: Option<PathBuf>,
    backend: Option<String>,
    program: Option<PathBuf>,
    inputs: Option<PathBuf>,
    witness: Option<PathBuf>,
    out: Option<PathBuf>,
    proof: Option<PathBuf>,
    compiled: Option<PathBuf>,
    trust: Option<String>,
    hardware_profile: Option<String>,
    trace_out: Option<PathBuf>,
) -> Result<(), String> {
    use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeCompiler};

    if let Some(path) = witness {
        return Err(format!(
            "runtime execute does not yet consume witness payloads: {}",
            path.display()
        ));
    }

    let (emission, plan_json) = if let Some(plan_path) = plan {
        if proof.is_some()
            || compiled.is_some()
            || trust.is_some()
            || backend.is_some()
            || program.is_some()
            || inputs.is_some()
        {
            return Err(
                "runtime execute --plan cannot be combined with --proof, --compiled, --trust, --backend, --program, or --inputs"
                    .to_string(),
            );
        }
        let plan_json = read_plan_document(&plan_path)?;
        if is_wrapper_plan(&plan_json) {
            let trace_json =
                execute_wrapper_runtime_plan(&plan_json, out.as_deref(), trace_out.as_deref())?;
            emit_json_output(trace_json, trace_out)?;
            return Ok(());
        }
        if out.is_some() {
            return Err("runtime execute --out is only valid for wrapper plans".to_string());
        }
        let emission = build_generic_emission_from_plan_document(&plan_json)?;
        (emission, plan_json)
    } else if let Some((proof_path, compiled_path)) = resolve_wrapper_inputs(proof, compiled)? {
        if backend.is_some() || program.is_some() || inputs.is_some() {
            return Err(
                "runtime execute wrapper mode cannot be combined with --backend, --program, or --inputs"
                    .to_string(),
            );
        }
        let trust_lane = parse_cli_trust_lane(trust.as_deref())?;
        let hardware_profile = resolve_hardware_profile(hardware_profile.as_deref())?;
        let source_proof: ProofArtifact = read_json_path(&proof_path)?;
        let source_compiled: CompiledProgram = read_json_path(&compiled_path)?;
        let (plan_json, _, _) = build_wrapper_runtime_plan_document_from_inputs(
            Some(&proof_path),
            Some(&compiled_path),
            &source_proof,
            &source_compiled,
            trust_lane,
            hardware_profile,
            None,
        )?;
        let trace_json =
            execute_wrapper_runtime_plan(&plan_json, out.as_deref(), trace_out.as_deref())?;
        emit_json_output(trace_json, trace_out)?;
        return Ok(());
    } else {
        if out.is_some() {
            return Err("runtime execute --out is only valid for wrapper plans".to_string());
        }
        let trust_lane = match trust.as_deref() {
            Some(value) => parse_cli_trust_lane(Some(value))?,
            None => RequiredTrustLane::StrictCryptographic,
        };
        let hardware_profile = resolve_hardware_profile(hardware_profile.as_deref())?;
        let backend = backend.as_deref().unwrap_or("groth16");
        let Some((program_path, inputs_path, program_doc, witness_inputs)) =
            resolve_generic_program_inputs(program, inputs)?
        else {
            return Err(
                "runtime execute requires either --plan, --proof/--compiled, or a generic --program plus --inputs"
                    .to_string(),
            );
        };
        let constraint_count = program_doc.constraints.len();
        let field = field_name_for_program(&program_doc)?;
        let graph = RuntimeCompiler::build_plan(
            constraint_count,
            field,
            backend,
            trust_lane,
            ExecutionMode::Deterministic,
        )
        .map_err(|e| e.to_string())?;
        let bindings = build_generic_plan_bindings_from_inputs(
            Some(&program_path),
            Some(&inputs_path),
            &program_doc,
            &witness_inputs,
        )?;
        let plan_json = build_generic_plan_document(
            backend,
            constraint_count,
            field,
            trust_lane,
            hardware_profile,
            Some(&program_path),
            Some(&inputs_path),
            Some(&bindings),
            &graph,
        )?;
        let emission = RuntimeCompiler::build_plan_with_context(
            constraint_count,
            field,
            backend,
            trust_lane,
            ExecutionMode::Deterministic,
            Some(Arc::new(program_doc)),
            Some(Arc::new(witness_inputs)),
        )
        .map_err(|e| e.to_string())?;
        (emission, plan_json)
    };

    let result = execute_generic_runtime_emission(emission, &plan_json)?;

    let trace_json = build_execution_trace(&plan_json, &result);
    emit_json_output(trace_json, trace_out)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_prepare(
    proof: PathBuf,
    compiled: PathBuf,
    trust: Option<String>,
    hardware_profile: Option<String>,
    allow_large_direct_materialization: bool,
    install_bundle: Option<PathBuf>,
    export_bundle: Option<PathBuf>,
    output: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    use zkf_backends::wrapping::default_wrapper_registry;
    use zkf_backends::wrapping::stark_to_groth16::{
        export_direct_wrap_cache_bundle, install_direct_wrap_cache_bundle,
    };

    let trust_lane = parse_cli_trust_lane(trust.as_deref())?;
    let hardware_profile = resolve_hardware_profile(hardware_profile.as_deref())?;
    if install_bundle.is_some() && export_bundle.is_some() {
        return Err(
            "runtime prepare cannot combine --install-bundle with --export-bundle".to_string(),
        );
    }
    let source_proof: ProofArtifact = read_json_path(&proof)?;
    let source_compiled: CompiledProgram = read_json_path(&compiled)?;
    let (_plan, preview, _) = build_wrapper_runtime_plan_document_from_inputs(
        Some(&proof),
        Some(&compiled),
        &source_proof,
        &source_compiled,
        trust_lane,
        hardware_profile,
        None,
    )?;
    let registry = default_wrapper_registry();
    let wrapper = registry
        .find(source_proof.backend, zkf_core::BackendKind::ArkworksGroth16)
        .ok_or_else(|| {
            format!(
                "no wrapper found for {} -> arkworks-groth16",
                source_proof.backend
            )
        })?;
    let policy = prepare_wrapper_execution_policy(trust_lane, allow_large_direct_materialization);
    let bundle_manifest = if let Some(bundle_dir) = install_bundle.as_ref() {
        Some(
            install_direct_wrap_cache_bundle(
                &source_proof,
                &source_compiled,
                policy,
                bundle_dir,
                hardware_profile.as_str(),
            )
            .map_err(crate::util::render_zkf_error)?,
        )
    } else if let Some(bundle_dir) = export_bundle.as_ref() {
        Some(
            export_direct_wrap_cache_bundle(
                &source_proof,
                &source_compiled,
                policy,
                bundle_dir,
                hardware_profile.as_str(),
            )
            .map_err(crate::util::render_zkf_error)?,
        )
    } else {
        None
    };
    let report = if let Some(manifest) = bundle_manifest.as_ref() {
        build_bundle_prepare_report(&preview, manifest, install_bundle.is_some())
    } else {
        wrapper
            .prepare_wrap_cache_with_policy(&source_proof, &source_compiled, policy)
            .map_err(crate::util::render_zkf_error)?
            .ok_or_else(|| {
                format!(
                    "wrapper {} -> {} does not expose cache preparation",
                    source_proof.backend,
                    zkf_core::BackendKind::ArkworksGroth16
                )
            })?
    };

    let (report_plan, report_preview, _) = build_wrapper_runtime_plan_document_from_inputs(
        Some(&proof),
        Some(&compiled),
        &source_proof,
        &source_compiled,
        trust_lane,
        hardware_profile,
        None,
    )?;

    let mut report_json = build_wrapper_prepare_report(
        &proof,
        &compiled,
        trust_lane,
        hardware_profile,
        &report_plan,
        &report_preview,
        &report,
    );
    if let Some(manifest) = bundle_manifest.as_ref()
        && let Some(object) = report_json.as_object_mut()
    {
        object.insert(
            "cache_bundle_action".to_string(),
            Value::String(if install_bundle.is_some() {
                "install".to_string()
            } else {
                "export".to_string()
            }),
        );
        object.insert(
            "cache_bundle_manifest".to_string(),
            serde_json::to_value(manifest).unwrap_or(Value::Null),
        );
    }
    if let Some(path) = output.as_ref() {
        crate::util::write_json(path, &report_json)?;
        println!("wrote wrapper cache report to {}", path.display());
    } else if json || report.blocked {
        println!(
            "{}",
            serde_json::to_string_pretty(&report_json).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "wrapper cache prepared: strategy={} trust_model={} shape_cache_ready={} pk_format={} migrated={}",
            report.strategy,
            report.trust_model,
            report.shape_cache_ready.unwrap_or(false),
            report.setup_cache_pk_format.as_deref().unwrap_or("unknown"),
            report.setup_cache_pk_migrated
        );
        if let Some(detail) = report.detail.as_deref() {
            println!("detail: {detail}");
        }
    }

    if report.blocked {
        return Err(report.blocked_reason.clone().unwrap_or_else(|| {
            "wrapper cache preparation was blocked by runtime policy".to_string()
        }));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_certify(
    mode: String,
    proof: PathBuf,
    compiled: PathBuf,
    out_dir: Option<PathBuf>,
    json_out: Option<PathBuf>,
    parallel_jobs: String,
    hours: u64,
    cycles: usize,
) -> Result<(), String> {
    let mode = parse_certification_mode(&mode)?;
    if !proof.is_file() {
        return Err(format!(
            "certification proof not found: {}",
            proof.display()
        ));
    }
    if !compiled.is_file() {
        return Err(format!(
            "certification compiled program not found: {}",
            compiled.display()
        ));
    }
    let out_dir = out_dir.unwrap_or_else(create_runtime_certification_temp_dir);
    fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let report_path = json_out.unwrap_or_else(|| out_dir.join("strict-certification.json"));
    let proof_bytes = fs::read(&proof).map_err(|e| format!("{}: {e}", proof.display()))?;
    let compiled_bytes = fs::read(&compiled).map_err(|e| format!("{}: {e}", compiled.display()))?;
    let source_compiled: CompiledProgram =
        serde_json::from_slice(&compiled_bytes).map_err(|e| {
            format!(
                "invalid compiled program JSON at {}: {e}",
                compiled.display()
            )
        })?;
    let build = current_certification_build_info()?;
    let soak_progress_path =
        matches!(mode, CertificationMode::Soak).then(|| out_dir.join("soak-progress.json"));
    let existing_soak_progress = soak_progress_path
        .as_ref()
        .and_then(|path| read_soak_progress(path));
    let soak_started_at = if matches!(mode, CertificationMode::Soak) {
        Some(
            existing_soak_progress
                .as_ref()
                .map(|progress| progress.soak_started_at_unix_ms)
                .unwrap_or(unix_time_now_ms()?),
        )
    } else {
        None
    };

    if matches!(mode, CertificationMode::Soak) {
        clear_installed_strict_certification_report()?;
    }
    let _soak_caffeinate_guard = if matches!(mode, CertificationMode::Soak) {
        let guard = spawn_soak_caffeinate_guard();
        if guard.is_some() {
            eprintln!("strict soak caffeinate guard enabled");
        }
        guard
    } else {
        None
    };
    if let (Some(path), Some(started_at)) = (soak_progress_path.as_ref(), soak_started_at) {
        write_soak_progress(
            path,
            "preflight",
            Some("doctor-preflight"),
            Some("doctor-preflight"),
            started_at,
            hours.max(12) as u128 * 60 * 60 * 1000,
            0,
            cycles.max(20),
            0,
            0.0,
            None,
            None,
            0,
            0,
            existing_soak_progress
                .as_ref()
                .and_then(|progress| progress.resumed_from_cycle),
            &[],
        )?;
    }

    let preflight_path = out_dir.join("doctor-preflight.json");
    let preflight_capture = run_self_cli_json(
        &["metal-doctor".to_string(), "--json".to_string()],
        &[],
        Some(&preflight_path),
        false,
    )?;
    let preflight_json: Value = serde_json::from_str(&preflight_capture.stdout)
        .map_err(|e| format!("invalid preflight metal-doctor JSON: {e}"))?;
    let preflight_failures = runtime_only_metal_doctor_failures(&preflight_json);
    if !preflight_failures.is_empty() {
        return Err(format!(
            "strict certification preflight failed: {}",
            preflight_failures.join("; ")
        ));
    }
    let doctor_preflight = doctor_snapshot_from_value(&preflight_json)?;
    if let (Some(path), Some(started_at)) = (soak_progress_path.as_ref(), soak_started_at) {
        write_soak_progress(
            path,
            "prepare",
            Some("prepare"),
            Some("prepare"),
            started_at,
            hours.max(12) as u128 * 60 * 60 * 1000,
            0,
            cycles.max(20),
            0,
            0.0,
            None,
            None,
            0,
            0,
            existing_soak_progress
                .as_ref()
                .and_then(|progress| progress.resumed_from_cycle),
            &[],
        )?;
    }

    let prepare_path = out_dir.join("prepare.json");
    let existing_prepare_path = if prepare_path.is_file() {
        Some(prepare_path.clone())
    } else {
        let legacy = out_dir.join("prepare-report.json");
        legacy.is_file().then_some(legacy)
    };
    let prepare_json: Value = if let Some(path) = existing_prepare_path {
        let existing: Value = read_json_path(&path)?;
        if existing_prepare_report_reusable(
            &existing,
            &proof,
            &compiled,
            zkf_runtime::HardwareProfile::M4,
        )? {
            if path != prepare_path {
                crate::util::write_json(&prepare_path, &existing)?;
            }
            eprintln!(
                "strict certification: reusing existing prepare report {}",
                path.display()
            );
            existing
        } else {
            eprintln!(
                "strict certification: existing prepare report {} is stale; regenerating",
                path.display()
            );
            run_strict_certification_prepare(&proof, &compiled, &prepare_path)?
        }
    } else {
        run_strict_certification_prepare(&proof, &compiled, &prepare_path)?
    };
    validate_prepare_report(&prepare_json)?;
    let prepare_preview = parse_prepare_report_preview(&prepare_json)?;
    if let Some(reason) = strict_certification_wrap_admission_failure(
        &preflight_json,
        &prepare_preview,
        source_compiled.program.constraints.len(),
    ) {
        return Err(format!("strict certification admission failed: {reason}"));
    }
    let prepare_report_sha256 = crate::util::sha256_hex(
        &fs::read(&prepare_path).map_err(|e| format!("{}: {e}", prepare_path.display()))?,
    );
    if let (Some(path), Some(started_at)) = (soak_progress_path.as_ref(), soak_started_at) {
        write_soak_progress(
            path,
            "cold-wrap",
            Some("cold-wrap"),
            Some("cold"),
            started_at,
            hours.max(12) as u128 * 60 * 60 * 1000,
            0,
            cycles.max(20),
            0,
            0.0,
            None,
            None,
            0,
            0,
            existing_soak_progress
                .as_ref()
                .and_then(|progress| progress.resumed_from_cycle),
            &[],
        )?;
    }

    let mut runs = Vec::new();
    let mut failures = Vec::new();
    let mut degraded_runs = 0usize;
    let mut doctor_flips = 0usize;
    let mut strict_gpu_busy_ratio_peak = 0.0_f64;

    let cold_dir = out_dir.join("cold");
    let mut warm_run_gpu = None;
    let mut parallel_gpu_peak: Option<f64> = None;
    let mut doctor_postflight = None;
    let mut fault_injection_failed_closed = false;
    let mut resolved_parallel_jobs = 0usize;
    let mut soak_passed = false;
    let mut resumed_from_cycle = None;
    let mut max_parallel_jobs_observed = 0usize;

    let cold_run = if matches!(mode, CertificationMode::Soak) {
        resolved_parallel_jobs = resolve_certification_parallel_jobs(&parallel_jobs, &compiled)?;
        if let Some(path) = soak_progress_path.as_ref() {
            if let Some(resume) = try_resume_soak_state(&out_dir, path, resolved_parallel_jobs)? {
                eprintln!(
                    "strict soak: resuming from completed cycle {}",
                    resume.current_cycle
                );
                resumed_from_cycle = resume.resumed_from_cycle;
                warm_run_gpu = resume.warm_run_gpu;
                parallel_gpu_peak = resume.parallel_gpu_peak;
                max_parallel_jobs_observed = resume.max_parallel_jobs_observed;
                doctor_flips = resume.doctor_flips;
                fault_injection_failed_closed = resume.fault_injection_failed_closed;
                strict_gpu_busy_ratio_peak = resume.strict_gpu_busy_ratio_peak;
                runs = resume.runs;
                let cold = runs
                    .first()
                    .cloned()
                    .ok_or_else(|| "resume state missing cold run".to_string())?;
                write_soak_progress(
                    path,
                    "resuming",
                    Some("resume"),
                    Some("resume"),
                    resume.soak_started_at_unix_ms,
                    hours.max(12) as u128 * 60 * 60 * 1000,
                    resume.current_cycle,
                    cycles.max(20),
                    resolved_parallel_jobs,
                    strict_gpu_busy_ratio_peak,
                    warm_run_gpu,
                    parallel_gpu_peak,
                    doctor_flips,
                    degraded_runs,
                    resumed_from_cycle,
                    &[],
                )?;
                cold
            } else {
                let cold_run = run_certified_wrap_run(
                    "cold",
                    &proof,
                    &compiled,
                    &cold_dir,
                    0.20,
                    Some(false),
                )?;
                strict_gpu_busy_ratio_peak =
                    strict_gpu_busy_ratio_peak.max(cold_run.gpu_stage_busy_ratio);
                runs.push(cold_run.clone());
                cold_run
            }
        } else {
            let cold_run =
                run_certified_wrap_run("cold", &proof, &compiled, &cold_dir, 0.20, Some(false))?;
            strict_gpu_busy_ratio_peak =
                strict_gpu_busy_ratio_peak.max(cold_run.gpu_stage_busy_ratio);
            runs.push(cold_run.clone());
            cold_run
        }
    } else {
        let cold_run =
            run_certified_wrap_run("cold", &proof, &compiled, &cold_dir, 0.20, Some(false))?;
        strict_gpu_busy_ratio_peak = strict_gpu_busy_ratio_peak.max(cold_run.gpu_stage_busy_ratio);
        runs.push(cold_run.clone());
        cold_run
    };
    let cold_proof_path = PathBuf::from(cold_run.proof_path.clone());

    if matches!(mode, CertificationMode::Soak) {
        let total_cycles = cycles.max(20);
        let min_duration_ms = hours.max(12) as u128 * 60 * 60 * 1000;
        let soak_start = soak_started_at.unwrap_or(unix_time_now_ms()?);
        let requested_parallel_jobs = resolved_parallel_jobs.max(1);
        let (desktop_safe_parallel_jobs, desktop_safe_reason, desktop_safe_cooldown) =
            desktop_safe_parallel_cap(requested_parallel_jobs);
        resolved_parallel_jobs = desktop_safe_parallel_jobs;
        max_parallel_jobs_observed = max_parallel_jobs_observed.max(resolved_parallel_jobs);
        if let Some(reason) = desktop_safe_reason {
            eprintln!("strict soak desktop safety guard: {reason}");
        }
        if let Some(cooldown) = desktop_safe_cooldown {
            eprintln!(
                "strict soak cooldown before parallel certification: {}s",
                cooldown.as_secs()
            );
            std::thread::sleep(cooldown);
        }
        let soak_progress_path = soak_progress_path
            .clone()
            .unwrap_or_else(|| out_dir.join("soak-progress.json"));

        eprintln!(
            "starting strict soak: min_cycles={}, min_hours={}, parallel_jobs={}, progress={}",
            total_cycles,
            hours.max(12),
            resolved_parallel_jobs,
            soak_progress_path.display()
        );
        write_soak_progress(
            &soak_progress_path,
            "starting",
            Some("starting"),
            None,
            soak_start,
            min_duration_ms,
            resumed_from_cycle.unwrap_or(0),
            total_cycles,
            resolved_parallel_jobs,
            strict_gpu_busy_ratio_peak,
            warm_run_gpu,
            parallel_gpu_peak,
            doctor_flips,
            degraded_runs,
            resumed_from_cycle,
            &failures,
        )?;

        let mut cycle = resumed_from_cycle.unwrap_or(0);
        loop {
            let next_cycle = cycle + 1;
            let warm_dir = out_dir.join(format!("warm-cycle-{}", next_cycle));
            write_soak_progress(
                &soak_progress_path,
                "running",
                Some("warm-wrap"),
                Some(&format!("warm-cycle-{}", next_cycle)),
                soak_start,
                min_duration_ms,
                cycle,
                total_cycles,
                resolved_parallel_jobs,
                strict_gpu_busy_ratio_peak,
                warm_run_gpu,
                parallel_gpu_peak,
                doctor_flips,
                degraded_runs,
                resumed_from_cycle,
                &failures,
            )?;
            let warm_run = run_certified_wrap_run(
                &format!("warm-cycle-{}", next_cycle),
                &cold_proof_path,
                &compiled,
                &warm_dir,
                0.0,
                Some(true),
            )?;
            strict_gpu_busy_ratio_peak =
                strict_gpu_busy_ratio_peak.max(warm_run.gpu_stage_busy_ratio);
            warm_run_gpu = Some(warm_run.gpu_stage_busy_ratio);
            runs.push(warm_run);

            let (cycle_parallel_jobs, cycle_parallel_reason, cycle_parallel_cooldown) =
                desktop_safe_parallel_cap(resolved_parallel_jobs);
            if let Some(reason) = cycle_parallel_reason {
                eprintln!("strict soak cycle {} guard: {}", cycle + 1, reason);
            }
            if let Some(cooldown) = cycle_parallel_cooldown {
                eprintln!(
                    "strict soak cycle {} cooldown: {}s",
                    next_cycle,
                    cooldown.as_secs()
                );
                std::thread::sleep(cooldown);
            }
            write_soak_progress(
                &soak_progress_path,
                "running",
                Some("parallel-wrap"),
                Some(&format!("parallel-cycle-{}", next_cycle)),
                soak_start,
                min_duration_ms,
                cycle,
                total_cycles,
                resolved_parallel_jobs,
                strict_gpu_busy_ratio_peak,
                warm_run_gpu,
                parallel_gpu_peak,
                doctor_flips,
                degraded_runs,
                resumed_from_cycle,
                &failures,
            )?;
            let parallel_runs = run_parallel_certified_wraps(
                next_cycle,
                cycle_parallel_jobs,
                &proof,
                &compiled,
                &out_dir.join(format!("parallel-cycle-{}", next_cycle)),
            )?;
            if parallel_runs.is_empty() {
                failures.push("parallel certification produced no runs".to_string());
                write_soak_progress(
                    &soak_progress_path,
                    "failed",
                    Some("parallel-wrap"),
                    Some(&format!("parallel-cycle-{}", next_cycle)),
                    soak_start,
                    min_duration_ms,
                    cycle,
                    total_cycles,
                    resolved_parallel_jobs,
                    strict_gpu_busy_ratio_peak,
                    warm_run_gpu,
                    parallel_gpu_peak,
                    doctor_flips,
                    degraded_runs,
                    resumed_from_cycle,
                    &failures,
                )?;
                break;
            }
            let cycle_parallel_peak = aggregate_parallel_gpu_stage_busy_ratio(&parallel_runs);
            max_parallel_jobs_observed = max_parallel_jobs_observed.max(parallel_runs.len());
            parallel_gpu_peak = Some(match parallel_gpu_peak {
                Some(value) => value.max(cycle_parallel_peak),
                None => cycle_parallel_peak,
            });
            strict_gpu_busy_ratio_peak = strict_gpu_busy_ratio_peak.max(cycle_parallel_peak);
            runs.extend(parallel_runs);

            let doctor_cycle_path = out_dir.join(format!("doctor-cycle-{}.json", next_cycle));
            write_soak_progress(
                &soak_progress_path,
                "running",
                Some("doctor"),
                Some(&format!("doctor-cycle-{}", next_cycle)),
                soak_start,
                min_duration_ms,
                cycle,
                total_cycles,
                resolved_parallel_jobs,
                strict_gpu_busy_ratio_peak,
                warm_run_gpu,
                parallel_gpu_peak,
                doctor_flips,
                degraded_runs,
                resumed_from_cycle,
                &failures,
            )?;
            let doctor_cycle = run_self_cli_json(
                &["metal-doctor".to_string(), "--json".to_string()],
                &[],
                Some(&doctor_cycle_path),
                false,
            )?;
            let doctor_cycle_json: Value = serde_json::from_str(&doctor_cycle.stdout)
                .map_err(|e| format!("invalid soak doctor JSON: {e}"))?;
            let cycle_failures = runtime_only_metal_doctor_failures(&doctor_cycle_json);
            if !cycle_failures.is_empty() {
                doctor_flips += 1;
                failures.extend(cycle_failures);
                write_soak_progress(
                    &soak_progress_path,
                    "failed",
                    Some("doctor"),
                    Some(&format!("doctor-cycle-{}", next_cycle)),
                    soak_start,
                    min_duration_ms,
                    cycle,
                    total_cycles,
                    resolved_parallel_jobs,
                    strict_gpu_busy_ratio_peak,
                    warm_run_gpu,
                    parallel_gpu_peak,
                    doctor_flips,
                    degraded_runs,
                    resumed_from_cycle,
                    &failures,
                )?;
                break;
            }

            if next_cycle % 5 == 0 || next_cycle == total_cycles {
                let fault_stdout_path = out_dir.join(format!("fault-cycle-{}.json", next_cycle));
                let fault_stderr_path =
                    out_dir.join(format!("fault-cycle-{}.stderr.log", next_cycle));
                write_soak_progress(
                    &soak_progress_path,
                    "running",
                    Some("fault-injection"),
                    Some(&format!("fault-cycle-{}", next_cycle)),
                    soak_start,
                    min_duration_ms,
                    cycle,
                    total_cycles,
                    resolved_parallel_jobs,
                    strict_gpu_busy_ratio_peak,
                    warm_run_gpu,
                    parallel_gpu_peak,
                    doctor_flips,
                    degraded_runs,
                    resumed_from_cycle,
                    &failures,
                )?;
                let fault_capture = run_self_cli_json_logged(
                    &[
                        "metal-doctor".to_string(),
                        "--strict".to_string(),
                        "--json".to_string(),
                    ],
                    &[("ZKF_DISABLE_METAL", "1")],
                    &fault_stdout_path,
                    &fault_stderr_path,
                    true,
                )?;
                fault_injection_failed_closed = !fault_capture.status_ok;
                write_fault_checkpoint(
                    &out_dir,
                    next_cycle,
                    fault_injection_failed_closed,
                    &fault_capture,
                    Some(&fault_stdout_path),
                    Some(&fault_stderr_path),
                )?;
                if !fault_injection_failed_closed {
                    failures.push(
                        "fault injection failed: strict metal-doctor unexpectedly succeeded with ZKF_DISABLE_METAL=1"
                            .to_string(),
                    );
                    write_soak_progress(
                        &soak_progress_path,
                        "failed",
                        Some("fault-injection"),
                        Some(&format!("fault-cycle-{}", next_cycle)),
                        soak_start,
                        min_duration_ms,
                        next_cycle,
                        total_cycles,
                        resolved_parallel_jobs,
                        strict_gpu_busy_ratio_peak,
                        warm_run_gpu,
                        parallel_gpu_peak,
                        doctor_flips,
                        degraded_runs,
                        resumed_from_cycle,
                        &failures,
                    )?;
                    break;
                }
            }

            let now_ms = unix_time_now_ms()?;
            let elapsed_ms = now_ms.saturating_sub(soak_start);
            cycle += 1;
            eprintln!(
                "strict soak progress: cycle {}/{} elapsed={:.2}h remaining_min={:.2}h peak_gpu={:.3} warm_gpu={:.3} parallel_peak={:.3}",
                cycle,
                total_cycles,
                elapsed_ms as f64 / 3_600_000.0,
                min_duration_ms.saturating_sub(elapsed_ms) as f64 / 3_600_000.0,
                strict_gpu_busy_ratio_peak,
                warm_run_gpu.unwrap_or(0.0),
                parallel_gpu_peak.unwrap_or(0.0),
            );
            write_soak_progress(
                &soak_progress_path,
                "running",
                Some("cycle-complete"),
                Some(&format!("cycle-{}", cycle)),
                soak_start,
                min_duration_ms,
                cycle,
                total_cycles,
                resolved_parallel_jobs,
                strict_gpu_busy_ratio_peak,
                warm_run_gpu,
                parallel_gpu_peak,
                doctor_flips,
                degraded_runs,
                resumed_from_cycle,
                &failures,
            )?;
            if cycle >= total_cycles && now_ms.saturating_sub(soak_start) >= min_duration_ms {
                break;
            }
        }

        degraded_runs = runs
            .iter()
            .filter(|run| {
                run.groth16_msm_engine == "unknown" || run.qap_witness_map_engine == "unknown"
            })
            .count();
        if degraded_runs > 0 {
            failures.push(format!(
                "strict certification detected {degraded_runs} degraded run(s)"
            ));
        }
        let min_parallel_gpu_stage_busy_ratio =
            min_parallel_gpu_stage_busy_ratio_for_jobs(max_parallel_jobs_observed.max(1));
        if parallel_gpu_peak.unwrap_or(0.0) < min_parallel_gpu_stage_busy_ratio {
            failures.push(format!(
                "parallel strict certification peak gpu_stage_busy_ratio below threshold: {:.3} < {:.3} (parallel_jobs={})",
                parallel_gpu_peak.unwrap_or(0.0),
                min_parallel_gpu_stage_busy_ratio,
                max_parallel_jobs_observed.max(1)
            ));
        }
        if doctor_flips > 0 {
            failures.push(format!(
                "strict certification detected {doctor_flips} doctor health flip(s)"
            ));
        }
        if !fault_injection_failed_closed {
            failures.push("fault injection did not fail closed".to_string());
        }

        soak_passed = failures.is_empty();
        write_soak_progress(
            &soak_progress_path,
            if soak_passed { "passed" } else { "failed" },
            Some(if soak_passed { "passed" } else { "failed" }),
            None,
            soak_start,
            min_duration_ms,
            cycle,
            total_cycles,
            resolved_parallel_jobs,
            strict_gpu_busy_ratio_peak,
            warm_run_gpu,
            parallel_gpu_peak,
            doctor_flips,
            degraded_runs,
            resumed_from_cycle,
            &failures,
        )?;
    }

    let gate_passed = failures.is_empty();
    let summary = StrictCertificationSummary {
        gate_passed,
        soak_passed,
        doctor_flips,
        degraded_runs,
        cold_gpu_stage_busy_ratio: Some(runs[0].gpu_stage_busy_ratio),
        warm_gpu_stage_busy_ratio: warm_run_gpu,
        parallel_gpu_stage_busy_ratio_peak: parallel_gpu_peak,
        strict_gpu_busy_ratio_peak,
        parallel_jobs: max_parallel_jobs_observed
            .max(resolved_parallel_jobs)
            .max(1),
        fault_injection_failed_closed,
        final_pass: if matches!(mode, CertificationMode::Soak) {
            soak_passed
        } else {
            gate_passed
        },
        failures,
    };

    let report = StrictCertificationReport {
        report_schema: STRICT_CERTIFICATION_SCHEMA_V1.to_string(),
        certification_mode: certification_mode_name(mode).to_string(),
        certified_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis(),
        hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
        proof: proof.display().to_string(),
        compiled: compiled.display().to_string(),
        proof_sha256: crate::util::sha256_hex(&proof_bytes),
        compiled_sha256: crate::util::sha256_hex(&compiled_bytes),
        strict_cache_prepare_sha256: prepare_report_sha256.clone(),
        build,
        doctor_preflight,
        doctor_postflight,
        prepare_report_path: Some(prepare_path.display().to_string()),
        prepare_report_sha256: Some(prepare_report_sha256),
        runs,
        summary,
    };

    let mut report = report;

    if matches!(mode, CertificationMode::Soak) && report.summary.final_pass {
        install_strict_certification_report(&report)?;
        let strict_doctor_path = out_dir.join("doctor-postflight.json");
        let strict_doctor_capture = run_self_cli_json(
            &[
                "metal-doctor".to_string(),
                "--strict".to_string(),
                "--json".to_string(),
            ],
            &[],
            Some(&strict_doctor_path),
            false,
        )?;
        if !strict_doctor_capture.status_ok {
            report.summary.final_pass = false;
            report.summary.soak_passed = false;
            report.summary.failures.push(format!(
                "post-certification strict metal-doctor failed: {}",
                stderr_summary(&strict_doctor_capture.stderr)
            ));
            clear_installed_strict_certification_report()?;
        } else {
            let strict_doctor_json: Value = serde_json::from_str(&strict_doctor_capture.stdout)
                .map_err(|e| format!("invalid postflight metal-doctor JSON: {e}"))?;
            doctor_postflight = Some(doctor_snapshot_from_value(&strict_doctor_json)?);
            report.doctor_postflight = doctor_postflight;
            install_strict_certification_report(&report)?;
        }
    }

    crate::util::write_json(&report_path, &report)?;
    println!(
        "wrote strict certification report to {}",
        report_path.display()
    );

    if !report.summary.final_pass {
        return Err(format!(
            "strict certification {} failed: {}",
            certification_mode_name(mode),
            report.summary.failures.join("; ")
        ));
    }

    Ok(())
}

fn parse_certification_mode(value: &str) -> Result<CertificationMode, String> {
    match value {
        "gate" => Ok(CertificationMode::Gate),
        "soak" => Ok(CertificationMode::Soak),
        other => Err(format!(
            "unknown certification mode '{other}' (expected gate or soak)"
        )),
    }
}

fn certification_mode_name(mode: CertificationMode) -> &'static str {
    match mode {
        CertificationMode::Gate => "gate",
        CertificationMode::Soak => "soak",
    }
}

fn create_runtime_certification_temp_dir() -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("zkf-strict-certification-{pid}-{nanos}"))
}

fn default_zkf_cache_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".zkf").join("cache"))
        .unwrap_or_else(std::env::temp_dir)
}

fn strict_certification_cache_dir() -> PathBuf {
    if let Some(root) = std::env::var_os("ZKF_CACHE_DIR") {
        PathBuf::from(root)
            .join("stark-to-groth16")
            .join("certification")
    } else {
        default_zkf_cache_root()
            .join("stark-to-groth16")
            .join("certification")
    }
}

fn strict_certification_report_path() -> PathBuf {
    strict_certification_cache_dir().join("strict-m4-max.json")
}

fn install_strict_certification_report(report: &StrictCertificationReport) -> Result<(), String> {
    let path = strict_certification_report_path();
    crate::util::write_json(&path, report)?;
    println!(
        "installed strict certification report at {}",
        path.display()
    );
    Ok(())
}

fn clear_installed_strict_certification_report() -> Result<(), String> {
    let path = strict_certification_report_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("{}: {err}", path.display())),
    }
}

fn current_certification_build_info() -> Result<StrictCertificationBuildInfo, String> {
    let binary_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let binary_bytes =
        fs::read(&binary_path).map_err(|e| format!("{}: {e}", binary_path.display()))?;
    Ok(StrictCertificationBuildInfo {
        binary_path: binary_path.display().to_string(),
        binary_sha256: crate::util::sha256_hex(&binary_bytes),
        build_features: current_build_features(),
        rustc_version: current_rustc_version(),
    })
}

fn current_build_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "acvm-solver") {
        features.push("acvm-solver".to_string());
    }
    if cfg!(feature = "acvm-solver-beta9") {
        features.push("acvm-solver-beta9".to_string());
    }
    if cfg!(all(target_os = "macos", feature = "metal-gpu")) {
        features.push("metal-gpu".to_string());
    }
    if cfg!(feature = "native-nova") {
        features.push("native-nova".to_string());
    }
    features
}

fn current_rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

pub(crate) fn installed_strict_certification_match() -> StrictCertificationMatch {
    let path = strict_certification_report_path();
    if !path.is_file() {
        return StrictCertificationMatch {
            present: false,
            matches_current: false,
            failures: vec![format!(
                "strict certification report missing at {}",
                path.display()
            )],
            report_path: Some(path.display().to_string()),
            certified_at_unix_ms: None,
            strict_gpu_busy_ratio_peak: None,
        };
    }

    let report: StrictCertificationReport = match read_json_path(&path) {
        Ok(report) => report,
        Err(err) => {
            return StrictCertificationMatch {
                present: true,
                matches_current: false,
                failures: vec![format!(
                    "failed to parse strict certification report at {}: {err}",
                    path.display()
                )],
                report_path: Some(path.display().to_string()),
                certified_at_unix_ms: None,
                strict_gpu_busy_ratio_peak: None,
            };
        }
    };

    let mut failures = Vec::new();
    if report.report_schema != STRICT_CERTIFICATION_SCHEMA_V1 {
        failures.push(format!(
            "strict certification schema mismatch: expected {}, found {}",
            STRICT_CERTIFICATION_SCHEMA_V1, report.report_schema
        ));
    }
    if report.certification_mode != "soak" {
        failures.push(format!(
            "strict certification report must be mode=soak, found {}",
            report.certification_mode
        ));
    }
    if !report.summary.final_pass {
        failures
            .push("strict certification report did not record a final passing soak".to_string());
    }
    match current_certification_build_info() {
        Ok(current) => {
            if report.build.binary_sha256 != current.binary_sha256 {
                failures.push("strict certification binary hash mismatch".to_string());
            }
            if report.build.build_features != current.build_features {
                failures.push("strict certification build feature mismatch".to_string());
            }
        }
        Err(err) => failures.push(format!("failed to inspect current binary: {err}")),
    }
    if report.hardware_profile != "apple-silicon-m4-max-48gb" {
        failures.push(format!(
            "strict certification hardware profile mismatch: {}",
            report.hardware_profile
        ));
    }

    StrictCertificationMatch {
        present: true,
        matches_current: failures.is_empty(),
        failures,
        report_path: Some(path.display().to_string()),
        certified_at_unix_ms: Some(report.certified_at_unix_ms),
        strict_gpu_busy_ratio_peak: Some(report.summary.strict_gpu_busy_ratio_peak),
    }
}

fn doctor_snapshot_from_value(value: &Value) -> Result<StrictCertificationDoctorSnapshot, String> {
    Ok(StrictCertificationDoctorSnapshot {
        production_ready: value.get("production_ready").and_then(Value::as_bool),
        certified_hardware_profile: value
            .get("certified_hardware_profile")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        strict_bn254_ready: value
            .get("strict_bn254_ready")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        strict_bn254_auto_route: value
            .get("strict_bn254_auto_route")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        strict_gpu_stage_coverage: value
            .get("strict_gpu_stage_coverage")
            .cloned()
            .unwrap_or(Value::Null),
        strict_gpu_busy_ratio_peak: value
            .get("strict_gpu_busy_ratio_peak")
            .and_then(Value::as_f64),
        runtime: value.get("runtime").cloned().unwrap_or(Value::Null),
    })
}

fn runtime_only_metal_doctor_failures(value: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if value
        .get("certified_hardware_profile")
        .and_then(Value::as_str)
        != Some("apple-silicon-m4-max-48gb")
    {
        failures.push("certified hardware profile is not apple-silicon-m4-max-48gb".to_string());
    }
    if value.get("strict_bn254_ready").and_then(Value::as_bool) != Some(true) {
        failures.push("strict_bn254_ready is false".to_string());
    }
    if value
        .get("strict_bn254_auto_route")
        .and_then(Value::as_bool)
        != Some(true)
    {
        failures.push("strict_bn254_auto_route is false".to_string());
    }
    let runtime = value.get("runtime").unwrap_or(&Value::Null);
    if runtime.get("metal_compiled").and_then(Value::as_bool) != Some(true) {
        failures.push("Metal build support is unavailable".to_string());
    }
    if runtime.get("metal_available").and_then(Value::as_bool) != Some(true) {
        failures.push("Metal runtime is unavailable".to_string());
    }
    if runtime
        .get("metal_dispatch_circuit_open")
        .and_then(Value::as_bool)
        == Some(true)
    {
        failures.push("Metal dispatch circuit is open".to_string());
    }
    let required_stages = value
        .pointer("/strict_gpu_stage_coverage/required_stages")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    if required_stages == 0 {
        failures.push("strict_gpu_stage_coverage.required_stages is empty".to_string());
    }
    let cpu_stages = value
        .pointer("/strict_gpu_stage_coverage/cpu_stages")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    if cpu_stages != 0 {
        failures.push("strict_gpu_stage_coverage.cpu_stages is non-empty".to_string());
    }
    failures
}

fn parse_prepare_report_preview(value: &Value) -> Result<WrapperPreview, String> {
    let preview = value.get("wrapper_preview").cloned().ok_or_else(|| {
        "strict certification prepare report is missing wrapper_preview".to_string()
    })?;
    serde_json::from_value(preview)
        .map_err(|e| format!("invalid wrapper_preview in strict certification prepare report: {e}"))
}

fn strict_certification_runtime_metal_probe(
    preflight_doctor: &Value,
) -> zkf_runtime::RuntimeMemoryProbe {
    let runtime = preflight_doctor.get("runtime").unwrap_or(&Value::Null);
    zkf_runtime::RuntimeMemoryProbe {
        recommended_working_set_size_bytes: runtime
            .get("recommended_working_set_size_bytes")
            .and_then(value_to_u64),
        current_allocated_size_bytes: runtime
            .get("current_allocated_size_bytes")
            .and_then(value_to_u64),
    }
}

fn strict_certification_wrap_memory_plan_with_host(
    host: &zkf_runtime::RuntimeHostSnapshot,
    preflight_doctor: &Value,
    preview: &WrapperPreview,
    fallback_constraint_count: usize,
) -> zkf_runtime::RuntimeMemoryPlan {
    use zkf_runtime::{
        RuntimeMemoryPlanInput, compute_runtime_memory_plan,
        estimate_job_bytes_from_constraint_count,
    };

    let compiled_constraint_count = preview
        .estimated_constraints
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(fallback_constraint_count);
    let graph_required_bytes = preview.estimated_memory_bytes.filter(|value| *value > 0);
    let baseline_job_estimate_bytes =
        estimate_job_bytes_from_constraint_count(compiled_constraint_count);
    let job_estimate_bytes = graph_required_bytes
        .unwrap_or(baseline_job_estimate_bytes)
        .max(baseline_job_estimate_bytes);

    compute_runtime_memory_plan(
        host,
        RuntimeMemoryPlanInput {
            compiled_constraint_count,
            job_estimate_bytes,
            graph_required_bytes,
            metal: strict_certification_runtime_metal_probe(preflight_doctor),
        },
    )
}

fn gib_string(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

fn gib_option_string(bytes: Option<u64>) -> String {
    bytes
        .map(gib_string)
        .unwrap_or_else(|| "unknown".to_string())
}

fn strict_certification_wrap_admission_failure_with_host(
    host: &zkf_runtime::RuntimeHostSnapshot,
    preflight_doctor: &Value,
    preview: &WrapperPreview,
    fallback_constraint_count: usize,
) -> Option<String> {
    let plan = strict_certification_wrap_memory_plan_with_host(
        host,
        preflight_doctor,
        preview,
        fallback_constraint_count,
    );
    if plan.gpu_allowed && !plan.cpu_override_active {
        return None;
    }

    Some(format!(
        "current strict-wrap memory admission predicts degraded Metal execution (pressure={}, available_ram={}, execution_budget={}, projected_peak={}, wrap_estimate={}, metal_headroom={}, metal_residency_budget={}); refusing to enter a cold wrap that would likely fall back to CPU or hit the MSM watchdog",
        plan.pressure_level,
        gib_string(plan.available_ram_bytes),
        gib_string(plan.execution_budget_bytes),
        gib_string(plan.projected_peak_bytes),
        gib_option_string(preview.estimated_memory_bytes),
        gib_option_string(plan.metal_working_set_headroom_bytes),
        gib_string(plan.metal_residency_budget_bytes),
    ))
}

fn strict_certification_wrap_admission_failure(
    preflight_doctor: &Value,
    preview: &WrapperPreview,
    fallback_constraint_count: usize,
) -> Option<String> {
    let host = zkf_runtime::RuntimeHostSnapshot::detect();
    strict_certification_wrap_admission_failure_with_host(
        &host,
        preflight_doctor,
        preview,
        fallback_constraint_count,
    )
}

fn validate_prepare_report(value: &Value) -> Result<(), String> {
    if value.get("requested_trust_lane").and_then(Value::as_str) != Some("strict-cryptographic") {
        return Err("strict certification prepare report used a non-strict trust lane".to_string());
    }
    let blocked = value
        .pointer("/cache_report/blocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if blocked {
        let reason = value
            .pointer("/cache_report/blocked_reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(format!(
            "strict certification prepare report is blocked: {reason}"
        ));
    }
    Ok(())
}

fn strict_certification_prepare_args(
    proof: &Path,
    compiled: &Path,
    prepare_path: &Path,
) -> Vec<String> {
    vec![
        "runtime".to_string(),
        "prepare".to_string(),
        "--proof".to_string(),
        proof.display().to_string(),
        "--compiled".to_string(),
        compiled.display().to_string(),
        "--allow-large-direct-materialization".to_string(),
        "--output".to_string(),
        prepare_path.display().to_string(),
    ]
}

fn run_strict_certification_prepare(
    proof: &Path,
    compiled: &Path,
    prepare_path: &Path,
) -> Result<Value, String> {
    let prepare_capture = run_self_cli_json(
        &strict_certification_prepare_args(proof, compiled, prepare_path),
        &[],
        None,
        false,
    )?;
    if !prepare_capture.status_ok {
        return Err(format!(
            "strict certification prepare failed: {}",
            stderr_summary(&prepare_capture.stderr)
        ));
    }
    let generated: Value = read_json_path(prepare_path)?;
    validate_prepare_report(&generated)?;
    Ok(generated)
}

fn prepare_report_reusable_with_live_preview(
    report: &Value,
    proof_path: &Path,
    compiled_path: &Path,
    hardware_profile: zkf_runtime::HardwareProfile,
    live_preview: &WrapperPreview,
) -> bool {
    if validate_prepare_report(report).is_err() {
        return false;
    }
    if report.get("proof").and_then(Value::as_str) != Some(proof_path.to_string_lossy().as_ref()) {
        return false;
    }
    if report.get("compiled").and_then(Value::as_str)
        != Some(compiled_path.to_string_lossy().as_ref())
    {
        return false;
    }
    if report.get("hardware_profile").and_then(Value::as_str) != Some(hardware_profile.as_str()) {
        return false;
    }
    if enforce_preview_trust_lane(
        live_preview,
        zkf_runtime::RequiredTrustLane::StrictCryptographic,
    )
    .is_err()
    {
        return false;
    }
    if enforce_prepare_ready_preview(live_preview).is_err() {
        return false;
    }
    let Some(expected_value) = report.get("wrapper_preview") else {
        return false;
    };
    let Ok(expected_preview) = serde_json::from_value::<WrapperPreview>(expected_value.clone())
    else {
        return false;
    };
    wrapper_preview_matches_plan(&expected_preview, live_preview)
}

fn existing_prepare_report_reusable(
    report: &Value,
    proof_path: &Path,
    compiled_path: &Path,
    hardware_profile: zkf_runtime::HardwareProfile,
) -> Result<bool, String> {
    let source_proof: ProofArtifact = read_json_path(proof_path)?;
    let source_compiled: CompiledProgram = read_json_path(compiled_path)?;
    let live_preview = preview_wrapper_inputs(
        &source_proof,
        &source_compiled,
        zkf_runtime::RequiredTrustLane::StrictCryptographic,
        None,
    )?;
    Ok(prepare_report_reusable_with_live_preview(
        report,
        proof_path,
        compiled_path,
        hardware_profile,
        &live_preview,
    ))
}

fn resolve_certification_parallel_jobs(value: &str, compiled_path: &Path) -> Result<usize, String> {
    if value != "auto" {
        return value
            .parse::<usize>()
            .map(|jobs| jobs.max(1))
            .map_err(|e| format!("invalid --parallel-jobs value '{value}': {e}"));
    }
    let compiled: CompiledProgram = read_json_path(compiled_path)?;
    let total_jobs = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(2)
        .max(2);
    let scheduler = zkf_backends::recommend_gpu_jobs(
        &[zkf_core::BackendKind::ArkworksGroth16],
        compiled.program.constraints.len(),
        compiled.program.signals.len(),
        None,
        total_jobs,
    );
    Ok(scheduler.recommended_jobs.max(2))
}

fn try_load_completed_certified_run(
    label: &str,
    proof_path: &Path,
    out_dir: &Path,
    min_gpu_stage_busy_ratio: f64,
    require_cache_hit: Option<bool>,
) -> Result<Option<StrictCertificationRunSummary>, String> {
    let artifact_path = out_dir.join(format!("{label}.wrapped.groth16.json"));
    let execution_trace_path = out_dir.join(format!("{label}.execution-trace.json"));
    let runtime_trace_path = out_dir.join(format!("{label}.runtime-trace.json"));
    if !proof_path.is_file()
        || !artifact_path.is_file()
        || !execution_trace_path.is_file()
        || !runtime_trace_path.is_file()
    {
        return Ok(None);
    }

    let artifact: ProofArtifact = read_json_path(&artifact_path)?;
    let runtime_trace: Value = read_json_path(&runtime_trace_path)?;
    let validation = validate_certified_run(
        &artifact,
        &runtime_trace,
        min_gpu_stage_busy_ratio,
        require_cache_hit,
    )?;
    Ok(Some(StrictCertificationRunSummary {
        label: label.to_string(),
        proof_path: proof_path.display().to_string(),
        proof_sha256: crate::util::sha256_hex(
            &fs::read(proof_path).map_err(|e| format!("{}: {e}", proof_path.display()))?,
        ),
        artifact_path: artifact_path.display().to_string(),
        artifact_sha256: crate::util::sha256_hex(
            &fs::read(&artifact_path).map_err(|e| format!("{}: {e}", artifact_path.display()))?,
        ),
        execution_trace_path: execution_trace_path.display().to_string(),
        execution_trace_sha256: crate::util::sha256_hex(
            &fs::read(&execution_trace_path)
                .map_err(|e| format!("{}: {e}", execution_trace_path.display()))?,
        ),
        runtime_trace_path: runtime_trace_path.display().to_string(),
        runtime_trace_sha256: crate::util::sha256_hex(
            &fs::read(&runtime_trace_path)
                .map_err(|e| format!("{}: {e}", runtime_trace_path.display()))?,
        ),
        wrapper_cache_hit: validation.wrapper_cache_hit,
        wrapper_cache_source: validation.wrapper_cache_source,
        duration_ms: validation.duration_ms,
        peak_memory_bytes: None,
        gpu_stage_busy_ratio: validation.gpu_stage_busy_ratio,
        qap_witness_map_engine: validation.qap_witness_map_engine,
        groth16_msm_engine: validation.groth16_msm_engine,
    }))
}

fn legacy_fault_cycle_can_be_trusted(out_dir: &Path, cycle: usize, progress_cycle: usize) -> bool {
    if !out_dir
        .join(format!("fault-cycle-{}.json", cycle))
        .is_file()
    {
        return false;
    }
    if progress_cycle > cycle {
        return true;
    }
    out_dir.join(format!("warm-cycle-{}", cycle + 1)).is_dir()
        || out_dir
            .join(format!("parallel-cycle-{}", cycle + 1))
            .is_dir()
        || out_dir
            .join(format!("doctor-cycle-{}.json", cycle + 1))
            .is_file()
}

fn fault_cycle_completed(
    out_dir: &Path,
    cycle: usize,
    progress_cycle: usize,
) -> Result<bool, String> {
    let checkpoint_path = fault_checkpoint_path(out_dir, cycle);
    if checkpoint_path.is_file() {
        let checkpoint: StrictCertificationFaultCheckpoint = read_json_path(&checkpoint_path)?;
        return Ok(checkpoint.failed_closed);
    }
    Ok(legacy_fault_cycle_can_be_trusted(
        out_dir,
        cycle,
        progress_cycle,
    ))
}

fn try_resume_soak_state(
    out_dir: &Path,
    progress_path: &Path,
    resolved_parallel_jobs: usize,
) -> Result<Option<SoakResumeState>, String> {
    let progress = read_soak_progress(progress_path);
    let soak_started_at_unix_ms = progress
        .as_ref()
        .map(|progress| progress.soak_started_at_unix_ms)
        .unwrap_or_else(|| unix_time_now_ms().unwrap_or_default());

    let cold_dir = out_dir.join("cold");
    let Some(cold_run) = try_load_completed_certified_run(
        "cold",
        &cold_dir.join("cold.proof.json"),
        &cold_dir,
        0.20,
        Some(false),
    )?
    else {
        return Ok(None);
    };

    let cold_proof_path = PathBuf::from(cold_run.proof_path.clone());
    let mut runs = vec![cold_run.clone()];
    let mut strict_gpu_busy_ratio_peak = cold_run.gpu_stage_busy_ratio;
    let mut warm_run_gpu = None;
    let mut parallel_gpu_peak: Option<f64> = None;
    let mut max_parallel_jobs_observed = 0usize;
    let mut current_cycle = 0usize;
    let progress_cycle = progress
        .as_ref()
        .map(|item| item.current_cycle)
        .unwrap_or(0);

    loop {
        let cycle = current_cycle + 1;
        let warm_dir = out_dir.join(format!("warm-cycle-{}", cycle));
        let warm_label = format!("warm-cycle-{}", cycle);
        let Some(warm_run) = try_load_completed_certified_run(
            &warm_label,
            &cold_proof_path,
            &warm_dir,
            0.0,
            Some(true),
        )?
        else {
            break;
        };

        let mut cycle_parallel_runs = Vec::with_capacity(resolved_parallel_jobs);
        let mut parallel_complete = true;
        for idx in 0..resolved_parallel_jobs {
            let label = format!("parallel-cycle-{}-job-{}", cycle, idx + 1);
            let run_dir = out_dir.join(format!("parallel-cycle-{}/job-{}", cycle, idx + 1));
            let proof_path = run_dir.join(format!("{label}.proof.json"));
            match try_load_completed_certified_run(
                &label,
                &proof_path,
                &run_dir,
                0.20,
                Some(false),
            )? {
                Some(run) => cycle_parallel_runs.push(run),
                None => {
                    parallel_complete = false;
                    break;
                }
            }
        }
        if !parallel_complete {
            break;
        }

        let doctor_cycle_path = out_dir.join(format!("doctor-cycle-{}.json", cycle));
        if !doctor_cycle_path.is_file() {
            break;
        }
        let doctor_cycle_json: Value = read_json_path(&doctor_cycle_path)?;
        if !runtime_only_metal_doctor_failures(&doctor_cycle_json).is_empty() {
            break;
        }

        if cycle.is_multiple_of(5) && !fault_cycle_completed(out_dir, cycle, progress_cycle)? {
            break;
        }

        strict_gpu_busy_ratio_peak = strict_gpu_busy_ratio_peak.max(warm_run.gpu_stage_busy_ratio);
        let cycle_parallel_peak = aggregate_parallel_gpu_stage_busy_ratio(&cycle_parallel_runs);
        strict_gpu_busy_ratio_peak = strict_gpu_busy_ratio_peak.max(cycle_parallel_peak);
        warm_run_gpu = Some(warm_run.gpu_stage_busy_ratio);
        max_parallel_jobs_observed = max_parallel_jobs_observed.max(cycle_parallel_runs.len());
        parallel_gpu_peak = Some(match parallel_gpu_peak {
            Some(value) => value.max(cycle_parallel_peak),
            None => cycle_parallel_peak,
        });
        runs.push(warm_run);
        runs.extend(cycle_parallel_runs);
        current_cycle = cycle;
    }

    Ok(Some(SoakResumeState {
        soak_started_at_unix_ms,
        current_cycle,
        runs,
        strict_gpu_busy_ratio_peak,
        warm_run_gpu,
        parallel_gpu_peak,
        max_parallel_jobs_observed,
        doctor_flips: 0,
        fault_injection_failed_closed: true,
        resumed_from_cycle: Some(current_cycle),
    }))
}

fn run_certified_wrap_run(
    label: &str,
    proof_source: &Path,
    compiled_path: &Path,
    out_dir: &Path,
    min_gpu_stage_busy_ratio: f64,
    require_cache_hit: Option<bool>,
) -> Result<StrictCertificationRunSummary, String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let proof_path = if require_cache_hit == Some(true) {
        proof_source.to_path_buf()
    } else {
        let source_proof: ProofArtifact = read_json_path(proof_source)?;
        let mut mutated = source_proof;
        mutated.metadata.insert(
            "_strict_certification_nonce".to_string(),
            format!("{label}-{}", nonce_string()),
        );
        let path = out_dir.join(format!("{label}.proof.json"));
        crate::util::write_json(&path, &mutated)?;
        path
    };
    let artifact_path = out_dir.join(format!("{label}.wrapped.groth16.json"));
    let execution_trace_path = out_dir.join(format!("{label}.execution-trace.json"));
    let runtime_trace_path = out_dir.join(format!("{label}.runtime-trace.json"));
    let wrap_stdout_path = out_dir.join(format!("{label}.wrap.stdout.log"));
    let wrap_stderr_path = out_dir.join(format!("{label}.wrap.stderr.log"));
    let trace_stdout_path = out_dir.join(format!("{label}.trace.stdout.log"));
    let trace_stderr_path = out_dir.join(format!("{label}.trace.stderr.log"));

    let wrap_capture = run_self_cli_json_logged(
        &[
            "wrap".to_string(),
            "--proof".to_string(),
            proof_path.display().to_string(),
            "--compiled".to_string(),
            compiled_path.display().to_string(),
            "--out".to_string(),
            artifact_path.display().to_string(),
            "--trace-out".to_string(),
            execution_trace_path.display().to_string(),
        ],
        &[],
        &wrap_stdout_path,
        &wrap_stderr_path,
        false,
    )?;
    if !wrap_capture.status_ok {
        return Err(format!(
            "strict wrap '{}' failed: {} (stdout={}, stderr={})",
            label,
            command_capture_summary(&wrap_capture.stdout, &wrap_capture.stderr),
            wrap_stdout_path.display(),
            wrap_stderr_path.display(),
        ));
    }
    let trace_capture = run_self_cli_json_logged(
        &[
            "runtime".to_string(),
            "trace".to_string(),
            "--proof".to_string(),
            artifact_path.display().to_string(),
            "--json".to_string(),
        ],
        &[],
        &runtime_trace_path,
        &trace_stderr_path,
        false,
    )?;
    if !trace_capture.status_ok {
        crate::util::write_bytes_atomic(&trace_stdout_path, trace_capture.stdout.as_bytes())?;
        return Err(format!(
            "runtime trace for '{}' failed: {} (stdout={}, stderr={})",
            label,
            command_capture_summary(&trace_capture.stdout, &trace_capture.stderr),
            trace_stdout_path.display(),
            trace_stderr_path.display(),
        ));
    }

    let artifact: ProofArtifact = read_json_path(&artifact_path)?;
    let runtime_trace: Value = read_json_path(&runtime_trace_path)?;
    let validation = validate_certified_run(
        &artifact,
        &runtime_trace,
        min_gpu_stage_busy_ratio,
        require_cache_hit,
    )?;
    let summary = StrictCertificationRunSummary {
        label: label.to_string(),
        proof_path: proof_path.display().to_string(),
        proof_sha256: crate::util::sha256_hex(
            &fs::read(&proof_path).map_err(|e| format!("{}: {e}", proof_path.display()))?,
        ),
        artifact_path: artifact_path.display().to_string(),
        artifact_sha256: crate::util::sha256_hex(
            &fs::read(&artifact_path).map_err(|e| format!("{}: {e}", artifact_path.display()))?,
        ),
        execution_trace_path: execution_trace_path.display().to_string(),
        execution_trace_sha256: crate::util::sha256_hex(
            &fs::read(&execution_trace_path)
                .map_err(|e| format!("{}: {e}", execution_trace_path.display()))?,
        ),
        runtime_trace_path: runtime_trace_path.display().to_string(),
        runtime_trace_sha256: crate::util::sha256_hex(
            &fs::read(&runtime_trace_path)
                .map_err(|e| format!("{}: {e}", runtime_trace_path.display()))?,
        ),
        wrapper_cache_hit: validation.wrapper_cache_hit,
        wrapper_cache_source: validation.wrapper_cache_source,
        duration_ms: validation.duration_ms,
        peak_memory_bytes: wrap_capture.peak_memory_bytes,
        gpu_stage_busy_ratio: validation.gpu_stage_busy_ratio,
        qap_witness_map_engine: validation.qap_witness_map_engine,
        groth16_msm_engine: validation.groth16_msm_engine,
    };
    crate::util::write_json(&out_dir.join(format!("{label}.summary.json")), &summary)?;
    Ok(summary)
}

fn run_parallel_certified_wraps(
    cycle: usize,
    jobs: usize,
    proof_path: &Path,
    compiled_path: &Path,
    out_dir: &Path,
) -> Result<Vec<StrictCertificationRunSummary>, String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let mut handles = Vec::new();
    for idx in 0..jobs {
        let proof_path = proof_path.to_path_buf();
        let compiled_path = compiled_path.to_path_buf();
        let run_dir = out_dir.join(format!("job-{}", idx + 1));
        handles.push(std::thread::spawn(move || {
            run_certified_wrap_run(
                &format!("parallel-cycle-{}-job-{}", cycle, idx + 1),
                &proof_path,
                &compiled_path,
                &run_dir,
                0.20,
                Some(false),
            )
        }));
    }
    let mut runs = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.join() {
            Ok(Ok(run)) => runs.push(run),
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err("parallel strict certification worker panicked".to_string());
            }
        }
    }
    Ok(runs)
}

#[derive(Debug)]
struct ValidatedCertifiedRun {
    wrapper_cache_hit: bool,
    wrapper_cache_source: Option<String>,
    duration_ms: f64,
    gpu_stage_busy_ratio: f64,
    qap_witness_map_engine: String,
    groth16_msm_engine: String,
}

fn validate_certified_run(
    artifact: &ProofArtifact,
    runtime_trace: &Value,
    min_gpu_stage_busy_ratio: f64,
    require_cache_hit: Option<bool>,
) -> Result<ValidatedCertifiedRun, String> {
    let metadata = &artifact.metadata;
    assert_metadata_string(metadata, "status", "wrapped-v2")?;
    assert_metadata_string(metadata, "trust_model", "cryptographic")?;
    assert_metadata_string(metadata, "wrapper_strategy", "direct-fri-v2")?;
    assert_metadata_string(metadata, "qap_witness_map_fallback_state", "none")?;
    assert_metadata_string(metadata, "groth16_msm_fallback_state", "none")?;
    assert_metadata_string(metadata, "metal_dispatch_circuit_open", "false")?;
    assert_metadata_string(
        metadata,
        "target_groth16_metal_dispatch_circuit_open",
        "false",
    )?;
    assert_metadata_string(metadata, "metal_dispatch_last_failure", "")?;
    assert_metadata_string(metadata, "target_groth16_metal_dispatch_last_failure", "")?;
    let qap_engine = non_unknown_metadata(metadata, "qap_witness_map_engine")?;
    let msm_engine = non_unknown_metadata(metadata, "groth16_msm_engine")?;
    let gpu_stage_busy_ratio = metadata
        .get("gpu_stage_busy_ratio")
        .and_then(|raw| raw.parse::<f64>().ok())
        .ok_or_else(|| "wrapped proof missing gpu_stage_busy_ratio".to_string())?;
    if gpu_stage_busy_ratio < min_gpu_stage_busy_ratio {
        return Err(format!(
            "wrapped proof gpu_stage_busy_ratio below threshold: {:.3} < {:.3}",
            gpu_stage_busy_ratio, min_gpu_stage_busy_ratio
        ));
    }

    let wrapper_cache_hit = metadata
        .get("wrapper_cache_hit")
        .map(|raw| raw == "true")
        .unwrap_or(false);
    match require_cache_hit {
        Some(true) if !wrapper_cache_hit => {
            return Err("expected warm strict wrap to be a cache hit".to_string());
        }
        Some(false) if wrapper_cache_hit => {
            return Err("expected cold strict wrap to miss the wrapped artifact cache".to_string());
        }
        _ => {}
    }

    compare_trace_scalar(runtime_trace, "status", "wrapped-v2")?;
    compare_trace_scalar(runtime_trace, "trust_model", "cryptographic")?;
    compare_trace_scalar(runtime_trace, "wrapper_strategy", "direct-fri-v2")?;
    compare_trace_scalar(runtime_trace, "qap_witness_map_fallback_state", "none")?;
    compare_trace_scalar(runtime_trace, "groth16_msm_fallback_state", "none")?;
    compare_trace_bool(runtime_trace, "metal_dispatch_circuit_open", false)?;
    compare_trace_bool(
        runtime_trace,
        "target_groth16_metal_dispatch_circuit_open",
        false,
    )?;
    compare_trace_scalar(runtime_trace, "metal_dispatch_last_failure", "")?;
    compare_trace_scalar(
        runtime_trace,
        "target_groth16_metal_dispatch_last_failure",
        "",
    )?;
    compare_trace_scalar(runtime_trace, "qap_witness_map_engine", &qap_engine)?;
    compare_trace_scalar(runtime_trace, "groth16_msm_engine", &msm_engine)?;
    let trace_gpu_stage_busy_ratio = runtime_trace
        .get("gpu_stage_busy_ratio")
        .and_then(Value::as_f64)
        .ok_or_else(|| "runtime trace missing gpu_stage_busy_ratio".to_string())?;
    if (trace_gpu_stage_busy_ratio - gpu_stage_busy_ratio).abs() > 0.000_001 {
        return Err(format!(
            "runtime trace gpu_stage_busy_ratio mismatch: artifact {:.3}, trace {:.3}",
            gpu_stage_busy_ratio, trace_gpu_stage_busy_ratio
        ));
    }

    Ok(ValidatedCertifiedRun {
        wrapper_cache_hit,
        wrapper_cache_source: metadata.get("wrapper_cache_source").cloned(),
        duration_ms: runtime_trace
            .get("stage_duration_ms")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        gpu_stage_busy_ratio,
        qap_witness_map_engine: qap_engine,
        groth16_msm_engine: msm_engine,
    })
}

fn assert_metadata_string(
    metadata: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    match metadata.get(key) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{key} expected {expected} but found {actual}")),
        None => Err(format!("{key} missing from wrapped proof metadata")),
    }
}

fn non_unknown_metadata(metadata: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    match metadata.get(key) {
        Some(value) if !value.is_empty() && value != "unknown" => Ok(value.clone()),
        Some(_) => Err(format!("{key} is unknown in wrapped proof metadata")),
        None => Err(format!("{key} missing from wrapped proof metadata")),
    }
}

fn compare_trace_scalar(trace: &Value, key: &str, expected: &str) -> Result<(), String> {
    match trace.get(key) {
        Some(Value::String(actual)) if actual == expected => Ok(()),
        Some(Value::String(actual)) => Err(format!("{key} expected {expected} but found {actual}")),
        Some(other) => Err(format!("{key} expected {expected} but found {other}")),
        None => Err(format!("{key} missing from runtime trace")),
    }
}

fn compare_trace_bool(trace: &Value, key: &str, expected: bool) -> Result<(), String> {
    match trace.get(key).and_then(Value::as_bool) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{key} expected {expected} but found {actual}")),
        None => Err(format!("{key} missing from runtime trace")),
    }
}

fn run_self_cli_json(
    args: &[String],
    envs: &[(&str, &str)],
    stdout_path: Option<&Path>,
    expect_failure: bool,
) -> Result<CommandCapture, String> {
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut command = if cfg!(target_os = "macos") {
        let mut time = Command::new("/usr/bin/time");
        time.arg("-l");
        time.arg(&binary);
        time
    } else {
        Command::new(&binary)
    };
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().map_err(|e| {
        format!(
            "failed to execute {} {}: {e}",
            binary.display(),
            args.join(" ")
        )
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let peak_memory_bytes = parse_peak_memory_bytes_from_stderr(&stderr);
    if let Some(path) = stdout_path {
        crate::util::write_bytes_atomic(path, stdout.as_bytes())?;
    }
    let status_ok = output.status.success();
    let exit_code = output.status.code();
    if expect_failure && status_ok {
        return Err(format!(
            "expected command to fail but it succeeded: {} {}",
            binary.display(),
            args.join(" ")
        ));
    }
    if !expect_failure && !status_ok {
        return Ok(CommandCapture {
            stdout,
            stderr,
            status_ok,
            exit_code,
            peak_memory_bytes,
        });
    }
    Ok(CommandCapture {
        stdout,
        stderr,
        status_ok,
        exit_code,
        peak_memory_bytes,
    })
}

fn run_self_cli_json_logged(
    args: &[String],
    envs: &[(&str, &str)],
    stdout_path: &Path,
    stderr_path: &Path,
    expect_failure: bool,
) -> Result<CommandCapture, String> {
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    if let Some(parent) = stdout_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    if let Some(parent) = stderr_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let stdout_file =
        fs::File::create(stdout_path).map_err(|e| format!("{}: {e}", stdout_path.display()))?;
    let stderr_file =
        fs::File::create(stderr_path).map_err(|e| format!("{}: {e}", stderr_path.display()))?;

    let mut command = if cfg!(target_os = "macos") {
        let mut time = Command::new("/usr/bin/time");
        time.arg("-l");
        time.arg(&binary);
        time
    } else {
        Command::new(&binary)
    };
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.stdout(Stdio::from(stdout_file));
    command.stderr(Stdio::from(stderr_file));
    let status = command.status().map_err(|e| {
        format!(
            "failed to execute {} {}: {e}",
            binary.display(),
            args.join(" ")
        )
    })?;
    let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
    let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
    let peak_memory_bytes = parse_peak_memory_bytes_from_stderr(&stderr);
    let status_ok = status.success();
    let exit_code = status.code();

    if expect_failure && status_ok {
        return Err(format!(
            "expected command to fail but it succeeded: {} {}",
            binary.display(),
            args.join(" ")
        ));
    }
    Ok(CommandCapture {
        stdout,
        stderr,
        status_ok,
        exit_code,
        peak_memory_bytes,
    })
}

fn parse_peak_memory_bytes_from_stderr(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|line| {
        let (value, label) = line.split_once("  maximum resident set size")?;
        let raw = value.trim().parse::<u64>().ok()?;
        if label.trim().is_empty() {
            Some(raw)
        } else {
            None
        }
    })
}

fn stderr_summary(stderr: &str) -> String {
    stderr_summary_filtered(stderr)
        .or_else(|| {
            stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
        })
        .unwrap_or_else(|| "command failed".to_string())
}

fn command_capture_summary(stdout: &str, stderr: &str) -> String {
    stderr_summary_filtered(stderr)
        .or_else(|| stdout_summary_filtered(stdout))
        .or_else(|| {
            stdout
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
        })
        .unwrap_or_else(|| stderr_summary(stderr))
}

fn stderr_summary_filtered(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty() && !is_time_metric_stderr_line(line))
        .map(str::to_string)
}

fn stdout_summary_filtered(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn is_time_metric_stderr_line(line: &str) -> bool {
    if line.contains(" real") && line.contains(" user") && line.contains(" sys") {
        return true;
    }
    const TIME_LABELS: &[&str] = &[
        "maximum resident set size",
        "average shared memory size",
        "average unshared data size",
        "average unshared stack size",
        "page reclaims",
        "page faults",
        "swaps",
        "block input operations",
        "block output operations",
        "messages sent",
        "messages received",
        "signals received",
        "voluntary context switches",
        "involuntary context switches",
        "instructions retired",
        "cycles elapsed",
        "peak memory footprint",
    ];
    TIME_LABELS.iter().any(|label| {
        line.ends_with(label)
            && line[..line.len() - label.len()]
                .trim()
                .parse::<u64>()
                .is_ok()
    })
}

fn nonce_string() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    )
}

fn parse_field_name(field: Option<&str>) -> Result<&'static str, String> {
    match field.unwrap_or("bn254_fr") {
        "bn254_fr" | "bn254" => Ok("bn254_fr"),
        "goldilocks" => Ok("goldilocks"),
        "babybear" | "baby-bear" => Ok("babybear"),
        other => Err(format!("unknown field: {other}")),
    }
}

fn parse_required_trust_lane(
    trust: Option<&str>,
) -> Result<zkf_runtime::RequiredTrustLane, String> {
    use zkf_runtime::RequiredTrustLane;

    match trust.unwrap_or("strict-cryptographic") {
        "strict-cryptographic" | "strict" => Ok(RequiredTrustLane::StrictCryptographic),
        "allow-attestation" | "attestation" => Ok(RequiredTrustLane::AllowAttestation),
        "allow-metadata" | "metadata" => Ok(RequiredTrustLane::AllowMetadataOnly),
        other => Err(format!("unknown trust lane: {other}")),
    }
}

fn parse_cli_trust_lane(trust: Option<&str>) -> Result<zkf_runtime::RequiredTrustLane, String> {
    use zkf_runtime::RequiredTrustLane;

    match trust.unwrap_or("strict-cryptographic") {
        "strict-cryptographic" | "strict" => Ok(RequiredTrustLane::StrictCryptographic),
        "allow-attestation" | "attestation" => Ok(RequiredTrustLane::AllowAttestation),
        other => Err(format!(
            "unknown trust lane: {other} (expected strict-cryptographic or allow-attestation)"
        )),
    }
}

fn trust_lane_name(trust_lane: zkf_runtime::RequiredTrustLane) -> &'static str {
    match trust_lane {
        zkf_runtime::RequiredTrustLane::StrictCryptographic => "strict-cryptographic",
        zkf_runtime::RequiredTrustLane::AllowAttestation => "allow-attestation",
        zkf_runtime::RequiredTrustLane::AllowMetadataOnly => "allow-metadata",
    }
}

pub(crate) fn parse_hardware_profile(
    value: Option<&str>,
) -> Result<zkf_runtime::HardwareProfile, String> {
    value
        .map(str::parse)
        .transpose()?
        .ok_or_else(|| "missing hardware profile".to_string())
}

fn resolve_hardware_profile(value: Option<&str>) -> Result<zkf_runtime::HardwareProfile, String> {
    let detected = zkf_runtime::HardwareProfile::detect();
    let requested = value.map(str::parse).transpose()?.unwrap_or(detected);
    if !detected.supports_required(requested) {
        return Err(format!(
            "requested hardware profile {} but detected {}; strict production wrapping is local to the certified host profile",
            requested, detected
        ));
    }
    Ok(requested)
}

fn enforce_wrap_mode_policy(trust_lane: zkf_runtime::RequiredTrustLane) -> Result<(), String> {
    if trust_lane == zkf_runtime::RequiredTrustLane::StrictCryptographic {
        return Ok(());
    }

    if let Ok(mode) = std::env::var("ZKF_WRAP_MODE") {
        let mode = mode.to_ascii_lowercase();
        if !matches!(mode.as_str(), "auto" | "direct" | "nova") {
            return Err(format!(
                "unknown ZKF_WRAP_MODE '{mode}' (expected auto, direct, or nova)"
            ));
        }
    }
    Ok(())
}

fn wrapper_execution_policy(
    trust_lane: zkf_runtime::RequiredTrustLane,
    force_mode: Option<WrapModeOverride>,
) -> WrapperExecutionPolicy {
    WrapperExecutionPolicy {
        honor_env_overrides: trust_lane != zkf_runtime::RequiredTrustLane::StrictCryptographic,
        allow_large_direct_materialization: false,
        force_mode,
    }
}

fn prepare_wrapper_execution_policy(
    trust_lane: zkf_runtime::RequiredTrustLane,
    allow_large_direct_materialization: bool,
) -> WrapperExecutionPolicy {
    WrapperExecutionPolicy {
        honor_env_overrides: trust_lane != zkf_runtime::RequiredTrustLane::StrictCryptographic,
        allow_large_direct_materialization,
        force_mode: None,
    }
}

fn wrap_mode_override_for_strategy(strategy: &str) -> Option<WrapModeOverride> {
    match strategy {
        "direct-fri-v2" => Some(WrapModeOverride::Direct),
        "nova-compressed-v3" => Some(WrapModeOverride::Nova),
        _ => None,
    }
}

fn enforce_wrapper_hardware_policy(
    hardware_profile: zkf_runtime::HardwareProfile,
    trust_lane: zkf_runtime::RequiredTrustLane,
    preview: &WrapperPreview,
) -> Result<(), String> {
    enforce_certified_build_support(hardware_profile, trust_lane)?;
    let resources = zkf_core::SystemResources::detect();
    if trust_lane == zkf_runtime::RequiredTrustLane::StrictCryptographic
        && !hardware_profile.supports_strict_cryptographic_wrap(&resources)
    {
        let recommendation = resources.recommend();
        return Err(format!(
            "strict cryptographic wrapping requires certified hardware_profile=apple-silicon-m4-max-48gb; detected {} (budget={} bytes, estimate={:?}, reason={})",
            hardware_profile,
            recommendation.max_circuit_memory_bytes,
            preview.estimated_memory_bytes,
            preview.reason.as_deref().unwrap_or("unavailable"),
        ));
    }
    Ok(())
}

fn enforce_certified_build_support(
    hardware_profile: zkf_runtime::HardwareProfile,
    trust_lane: zkf_runtime::RequiredTrustLane,
) -> Result<(), String> {
    if trust_lane == zkf_runtime::RequiredTrustLane::StrictCryptographic
        && hardware_profile == zkf_runtime::HardwareProfile::M4
        && !cfg!(all(target_os = "macos", feature = "metal-gpu"))
    {
        return Err(
            "strict cryptographic wrapping on hardware_profile=apple-silicon-m4-max-48gb requires a binary built with --features metal-gpu"
                .to_string(),
        );
    }
    Ok(())
}

fn resolve_wrapper_inputs(
    proof: Option<PathBuf>,
    compiled: Option<PathBuf>,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    match (proof, compiled) {
        (Some(proof), Some(compiled)) => Ok(Some((proof, compiled))),
        (None, None) => Ok(None),
        (Some(_), None) => Err("wrapper runtime mode requires --compiled with --proof".to_string()),
        (None, Some(_)) => Err("wrapper runtime mode requires --proof with --compiled".to_string()),
    }
}

fn preview_wrapper_inputs(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    trust_lane: zkf_runtime::RequiredTrustLane,
    force_mode: Option<WrapModeOverride>,
) -> Result<WrapperPreview, String> {
    use zkf_backends::wrapping::default_wrapper_registry;

    let registry = default_wrapper_registry();
    let wrapper = registry
        .find(source_proof.backend, zkf_core::BackendKind::ArkworksGroth16)
        .ok_or_else(|| {
            format!(
                "no wrapper found for {} -> arkworks-groth16",
                source_proof.backend
            )
        })?;

    wrapper
        .preview_wrap_with_policy(
            source_proof,
            source_compiled,
            wrapper_execution_policy(trust_lane, force_mode),
        )
        .map_err(crate::util::render_zkf_error)?
        .ok_or_else(|| {
            format!(
                "wrapper {} -> {} does not expose a preview",
                source_proof.backend,
                zkf_core::BackendKind::ArkworksGroth16
            )
        })
}

fn build_wrapper_runtime_plan_document_from_inputs(
    proof_path: Option<&Path>,
    compiled_path: Option<&Path>,
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    trust_lane: zkf_runtime::RequiredTrustLane,
    hardware_profile: zkf_runtime::HardwareProfile,
    force_mode: Option<WrapModeOverride>,
) -> Result<(Value, WrapperPreview, WrapperPlanBindings), String> {
    use zkf_runtime::{ExecutionMode, RuntimeCompiler};

    enforce_wrap_mode_policy(trust_lane)?;
    let preview = preview_wrapper_inputs(source_proof, source_compiled, trust_lane, force_mode)?;
    enforce_wrapper_hardware_policy(hardware_profile, trust_lane, &preview)?;
    enforce_preview_trust_lane(&preview, trust_lane)?;
    let graph = RuntimeCompiler::build_wrapper_plan(&preview, ExecutionMode::Deterministic)
        .map_err(|e| e.to_string())?;
    let bindings = build_wrapper_plan_bindings_from_inputs(
        proof_path,
        compiled_path,
        source_proof,
        source_compiled,
    )?;
    let plan = build_wrapper_plan_document(
        proof_path,
        compiled_path,
        trust_lane,
        hardware_profile,
        &preview,
        &bindings,
        &graph,
    )?;
    Ok((plan, preview, bindings))
}

fn read_json_path<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("invalid JSON at {}: {e}", path.display()))
}

fn enforce_preview_trust_lane(
    preview: &WrapperPreview,
    trust_lane: zkf_runtime::RequiredTrustLane,
) -> Result<(), String> {
    use zkf_runtime::RequiredTrustLane;

    let allowed = match trust_lane {
        RequiredTrustLane::StrictCryptographic => preview.trust_model == "cryptographic",
        RequiredTrustLane::AllowAttestation => {
            matches!(
                preview.trust_model.as_str(),
                "cryptographic" | "attestation"
            )
        }
        RequiredTrustLane::AllowMetadataOnly => {
            matches!(
                preview.trust_model.as_str(),
                "cryptographic" | "attestation" | "metadata-only" | "metadata"
            )
        }
    };

    if allowed {
        Ok(())
    } else {
        Err(format!(
            "wrapper preview requires trust_model={} ({}); rerun with --trust {} if that downgrade is intentional",
            preview.trust_model,
            preview.planned_status,
            match preview.trust_model.as_str() {
                "attestation" => "allow-attestation",
                _ => "allow-metadata",
            }
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_generic_plan_document(
    backend: &str,
    constraint_count: usize,
    field: &str,
    trust_lane: zkf_runtime::RequiredTrustLane,
    hardware_profile: zkf_runtime::HardwareProfile,
    program_path: Option<&Path>,
    inputs_path: Option<&Path>,
    bindings: Option<&GenericPlanBindings>,
    graph: &zkf_runtime::ProverGraph,
) -> Result<Value, String> {
    let mut plan = json!({
        "plan_schema": PLAN_SCHEMA_V2,
        "plan_kind": "generic",
        "backend": backend,
        "constraint_count": constraint_count,
        "field": field,
        "trust_lane": trust_lane_name(trust_lane),
        "required_trust_lane": trust_lane_name(trust_lane),
        "hardware_profile": hardware_profile.as_str(),
        "trust_summary": build_generic_trust_summary(backend, trust_lane),
        "lowering_report": build_generic_lowering_report(backend, field, trust_lane),
        "runtime_plan": summarize_runtime_plan(graph),
        "execution_ready": bindings.is_some(),
    });
    if let Some(path) = program_path {
        plan["program"] = Value::String(path.display().to_string());
    }
    if let Some(path) = inputs_path {
        plan["inputs"] = Value::String(path.display().to_string());
    }
    if let Some(bindings) = bindings {
        plan["program_bindings"] = serde_json::to_value(bindings)
            .map_err(|e| format!("serialize program bindings: {e}"))?;
    }
    finalize_plan_document(plan)
}

fn build_wrapper_plan_document(
    proof_path: Option<&Path>,
    compiled_path: Option<&Path>,
    trust_lane: zkf_runtime::RequiredTrustLane,
    hardware_profile: zkf_runtime::HardwareProfile,
    preview: &WrapperPreview,
    bindings: &WrapperPlanBindings,
    graph: &zkf_runtime::ProverGraph,
) -> Result<Value, String> {
    let mut plan = json!({
        "plan_schema": PLAN_SCHEMA_V2,
        "plan_kind": "wrapper",
        "trust_lane": trust_lane_name(trust_lane),
        "required_trust_lane": trust_lane_name(trust_lane),
        "hardware_profile": hardware_profile.as_str(),
        "trust_summary": build_wrapper_trust_summary(preview),
        "lowering_report": build_wrapper_lowering_report(preview),
        "wrapper_preview": preview,
        "input_bindings": bindings,
        "runtime_plan": summarize_runtime_plan(graph),
    });
    if let Some(path) = proof_path {
        plan["proof"] = Value::String(path.display().to_string());
    }
    if let Some(path) = compiled_path {
        plan["compiled"] = Value::String(path.display().to_string());
    }
    finalize_plan_document(plan)
}

fn read_plan_document(path: &Path) -> Result<Value, String> {
    let plan: Value = read_json_path(path)?;
    match plan.get("plan_schema").and_then(Value::as_str) {
        Some(PLAN_SCHEMA_V1 | PLAN_SCHEMA_V2) => Ok(plan),
        Some(other) => Err(format!("unsupported runtime plan schema: {other}")),
        None => Err(format!(
            "runtime plan is missing plan_schema: {}",
            path.display()
        )),
    }
}

fn resolve_generic_program_inputs(
    program: Option<PathBuf>,
    inputs: Option<PathBuf>,
) -> Result<Option<(PathBuf, PathBuf, Program, WitnessInputs)>, String> {
    match (program, inputs) {
        (Some(program_path), Some(inputs_path)) => {
            let program_doc = crate::util::load_program_v2(&program_path)?;
            let witness_inputs: WitnessInputs = read_json_path(&inputs_path)?;
            Ok(Some((
                program_path,
                inputs_path,
                program_doc,
                witness_inputs,
            )))
        }
        (None, None) => Ok(None),
        (Some(_), None) => Err(
            "runtime generic execution requires --inputs whenever --program is provided"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "runtime generic execution requires --program whenever --inputs is provided"
                .to_string(),
        ),
    }
}

fn field_name_for_program(program: &Program) -> Result<&'static str, String> {
    match program.field {
        zkf_core::FieldId::Bn254 => Ok("bn254_fr"),
        zkf_core::FieldId::Goldilocks => Ok("goldilocks"),
        zkf_core::FieldId::BabyBear => Ok("babybear"),
        zkf_core::FieldId::Bls12_381 => Ok("bls12_381"),
        other => Err(format!(
            "runtime generic execution does not support program field {other:?}"
        )),
    }
}

fn build_generic_plan_bindings_from_inputs(
    program_path: Option<&Path>,
    inputs_path: Option<&Path>,
    program: &Program,
    inputs: &WitnessInputs,
) -> Result<GenericPlanBindings, String> {
    let program_bytes = match program_path {
        Some(path) => std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => serde_json::to_vec_pretty(program).map_err(|e| e.to_string())?,
    };
    let inputs_bytes = match inputs_path {
        Some(path) => std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => serde_json::to_vec_pretty(inputs).map_err(|e| e.to_string())?,
    };

    Ok(GenericPlanBindings {
        program_sha256: crate::util::sha256_hex(&program_bytes),
        inputs_sha256: crate::util::sha256_hex(&inputs_bytes),
        program_digest: program.digest_hex(),
        field: field_name_for_program(program)?.to_string(),
        constraint_count: program.constraints.len(),
        signal_count: program.signals.len(),
    })
}

fn validate_generic_plan_bindings(
    plan: &Value,
    program_path: &Path,
    inputs_path: &Path,
    program: &Program,
    inputs: &WitnessInputs,
) -> Result<(), String> {
    let Some(bindings_value) = plan.get("program_bindings") else {
        return Err(
            "runtime generic plan is not execution-ready; recreate it with --program and --inputs"
                .to_string(),
        );
    };
    let bindings: GenericPlanBindings = serde_json::from_value(bindings_value.clone())
        .map_err(|e| format!("invalid program_bindings in runtime plan: {e}"))?;
    let actual = build_generic_plan_bindings_from_inputs(
        Some(program_path),
        Some(inputs_path),
        program,
        inputs,
    )?;

    if bindings.program_sha256 != actual.program_sha256 {
        return Err(format!(
            "runtime generic plan program hash mismatch for {}: expected {}, found {}",
            program_path.display(),
            bindings.program_sha256,
            actual.program_sha256
        ));
    }
    if bindings.inputs_sha256 != actual.inputs_sha256 {
        return Err(format!(
            "runtime generic plan inputs hash mismatch for {}: expected {}, found {}",
            inputs_path.display(),
            bindings.inputs_sha256,
            actual.inputs_sha256
        ));
    }
    if bindings.program_digest != actual.program_digest {
        return Err(format!(
            "runtime generic plan program digest mismatch: expected {}, found {}",
            bindings.program_digest, actual.program_digest
        ));
    }
    if bindings.field != actual.field {
        return Err(format!(
            "runtime generic plan field mismatch: expected {}, found {}",
            bindings.field, actual.field
        ));
    }
    if bindings.constraint_count != actual.constraint_count {
        return Err(format!(
            "runtime generic plan constraint count mismatch: expected {}, found {}",
            bindings.constraint_count, actual.constraint_count
        ));
    }
    if bindings.signal_count != actual.signal_count {
        return Err(format!(
            "runtime generic plan signal count mismatch: expected {}, found {}",
            bindings.signal_count, actual.signal_count
        ));
    }

    Ok(())
}

#[allow(dead_code)]
fn build_graph_from_plan_document(plan: &Value) -> Result<zkf_runtime::ProverGraph, String> {
    use zkf_runtime::{ExecutionMode, RuntimeCompiler};

    match plan.get("plan_kind").and_then(Value::as_str) {
        Some("generic") => {
            let backend = required_string(plan, "backend")?;
            let constraint_count = required_u64(plan, "constraint_count")? as usize;
            let field = parse_field_name(Some(required_string(plan, "field")?))?;
            let trust_lane = parse_required_trust_lane(Some(required_string(plan, "trust_lane")?))?;
            RuntimeCompiler::build_plan(
                constraint_count,
                field,
                backend,
                trust_lane,
                ExecutionMode::Deterministic,
            )
            .map_err(|e| e.to_string())
        }
        Some("wrapper") => {
            let trust_lane = parse_required_trust_lane(Some(required_string(plan, "trust_lane")?))?;
            let preview_value = plan
                .get("wrapper_preview")
                .cloned()
                .ok_or_else(|| "runtime wrapper plan is missing wrapper_preview".to_string())?;
            let preview: WrapperPreview = serde_json::from_value(preview_value)
                .map_err(|e| format!("invalid wrapper_preview in runtime plan: {e}"))?;
            enforce_preview_trust_lane(&preview, trust_lane)?;
            RuntimeCompiler::build_wrapper_plan(&preview, ExecutionMode::Deterministic)
                .map_err(|e| e.to_string())
        }
        Some(other) => Err(format!("unsupported runtime plan kind: {other}")),
        None => Err("runtime plan is missing plan_kind".to_string()),
    }
}

fn build_generic_emission_from_plan_document(
    plan: &Value,
) -> Result<zkf_runtime::GraphEmission, String> {
    use zkf_runtime::{ExecutionMode, RuntimeCompiler};

    let backend = required_string(plan, "backend")?;
    let constraint_count = required_u64(plan, "constraint_count")? as usize;
    let field = parse_field_name(Some(required_string(plan, "field")?))?;
    let trust_lane = parse_required_trust_lane(Some(required_string(plan, "trust_lane")?))?;
    let program_path = plan
        .get("program")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            "runtime generic plan is not execution-ready; recreate it with --program and --inputs"
                .to_string()
        })?;
    let inputs_path = plan
        .get("inputs")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            "runtime generic plan is not execution-ready; recreate it with --program and --inputs"
                .to_string()
        })?;
    let program_doc = crate::util::load_program_v2(&program_path)?;
    let witness_inputs: WitnessInputs = read_json_path(&inputs_path)?;
    let actual_constraint_count = program_doc.constraints.len();
    if actual_constraint_count != constraint_count {
        return Err(format!(
            "runtime generic plan constraint count mismatch: plan expects {}, but {} has {}",
            constraint_count,
            program_path.display(),
            actual_constraint_count
        ));
    }
    let actual_field = field_name_for_program(&program_doc)?;
    if actual_field != field {
        return Err(format!(
            "runtime generic plan field mismatch: plan expects {}, but {} uses {}",
            field,
            program_path.display(),
            actual_field
        ));
    }
    validate_generic_plan_bindings(
        plan,
        &program_path,
        &inputs_path,
        &program_doc,
        &witness_inputs,
    )?;
    RuntimeCompiler::build_plan_with_context(
        constraint_count,
        field,
        backend,
        trust_lane,
        ExecutionMode::Deterministic,
        Some(Arc::new(program_doc)),
        Some(Arc::new(witness_inputs)),
    )
    .map_err(|e| e.to_string())
}

struct RuntimeExecutionOutcome {
    result: zkf_runtime::PlanExecutionResult,
    exec_ctx: zkf_runtime::ExecutionContext,
}

fn build_wrapper_emission_from_inputs(
    preview: &WrapperPreview,
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    trust_lane: zkf_runtime::RequiredTrustLane,
) -> Result<zkf_runtime::GraphEmission, String> {
    use zkf_runtime::{ExecutionMode, RuntimeCompiler};

    let mut emission =
        RuntimeCompiler::build_wrapper_plan_with_context(preview, ExecutionMode::Deterministic)
            .map_err(|e| e.to_string())?;
    emission.exec_ctx.source_proof = Some(Arc::new(source_proof.clone()));
    emission.exec_ctx.compiled = Some(Arc::new(source_compiled.clone()));
    emission
        .exec_ctx
        .set_wrapper_policy(wrapper_execution_policy(
            trust_lane,
            wrap_mode_override_for_strategy(&preview.strategy),
        ));
    Ok(emission)
}

fn execute_runtime_emission(
    emission: zkf_runtime::GraphEmission,
    plan: &Value,
) -> Result<RuntimeExecutionOutcome, String> {
    use zkf_runtime::{BufferBridge, DeterministicScheduler, PlacementContext, UnifiedBufferPool};

    let mut exec_ctx = emission.exec_ctx;
    let graph = emission.graph;
    let mut bridge = BufferBridge::with_temp_spill();
    let trust_lane = parse_required_trust_lane(Some(required_string(plan, "trust_lane")?))?;

    #[cfg(all(feature = "metal-gpu", target_os = "macos"))]
    {
        use crate::runtime_metal::{create_metal_buffer_allocator, create_metal_dispatch_driver};
        use zkf_runtime::GpuVerificationMode;

        let verification_mode = if matches!(
            trust_lane,
            zkf_runtime::RequiredTrustLane::StrictCryptographic
        ) {
            GpuVerificationMode::VerifiedPinned
        } else {
            GpuVerificationMode::BestEffort
        };
        let mut placement_ctx = PlacementContext::default();
        if let Some(allocator) = create_metal_buffer_allocator() {
            bridge.set_gpu_allocator(allocator);
            placement_ctx.gpu_available = true;
            placement_ctx.gpu_cores = 40;
        }
        let scheduler =
            DeterministicScheduler::new(UnifiedBufferPool::new(512 * 1024 * 1024), placement_ctx);
        let report = if let Some(driver) = create_metal_dispatch_driver(verification_mode) {
            scheduler
                .execute_with_context_and_drivers(
                    graph,
                    &mut exec_ctx,
                    &mut bridge,
                    Some(driver.as_ref()),
                )
                .map_err(|e| e.to_string())?
        } else {
            scheduler
                .execute_with_context_and_drivers(graph, &mut exec_ctx, &mut bridge, None)
                .map_err(|e| e.to_string())?
        };
        Ok(RuntimeExecutionOutcome {
            result: zkf_runtime::PlanExecutionResult {
                report,
                outputs: summarize_runtime_outputs(&exec_ctx),
                control_plane: None,
                security: None,
                model_integrity: None,
                swarm: None,
            },
            exec_ctx,
        })
    }

    #[cfg(not(all(feature = "metal-gpu", target_os = "macos")))]
    {
        let _ = trust_lane;
        let scheduler = DeterministicScheduler::new(
            UnifiedBufferPool::new(512 * 1024 * 1024),
            PlacementContext::default(),
        );
        let report = scheduler
            .execute_with_context_and_drivers(graph, &mut exec_ctx, &mut bridge, None)
            .map_err(|e| e.to_string())?;
        Ok(RuntimeExecutionOutcome {
            result: zkf_runtime::PlanExecutionResult {
                report,
                outputs: summarize_runtime_outputs(&exec_ctx),
                control_plane: None,
                security: None,
                model_integrity: None,
                swarm: None,
            },
            exec_ctx,
        })
    }
}

fn execute_generic_runtime_emission(
    emission: zkf_runtime::GraphEmission,
    plan: &Value,
) -> Result<zkf_runtime::PlanExecutionResult, String> {
    Ok(execute_runtime_emission(emission, plan)?.result)
}

fn summarize_runtime_outputs(exec_ctx: &zkf_runtime::ExecutionContext) -> Value {
    if exec_ctx.outputs.is_empty() {
        return Value::Null;
    }
    let mut map = Map::new();
    for (key, value) in &exec_ctx.outputs {
        map.insert(
            key.clone(),
            json!({
                "bytes": value.len(),
                "present": true,
            }),
        );
    }
    Value::Object(map)
}

fn is_wrapper_plan(plan: &Value) -> bool {
    matches!(
        plan.get("plan_kind").and_then(Value::as_str),
        Some("wrapper")
    )
}

fn execute_wrapper_runtime_plan(
    plan: &Value,
    out_path: Option<&Path>,
    trace_out: Option<&Path>,
) -> Result<Value, String> {
    let proof_path = PathBuf::from(required_string(plan, "proof")?);
    let compiled_path = PathBuf::from(required_string(plan, "compiled")?);
    let source_proof: ProofArtifact = read_json_path(&proof_path)?;
    let source_compiled: CompiledProgram = read_json_path(&compiled_path)?;
    let (_, trace) = execute_wrapper_runtime_job(
        plan,
        &source_proof,
        &source_compiled,
        Some((&proof_path, &compiled_path)),
        out_path,
        trace_out,
    )?;
    Ok(trace)
}

pub(crate) fn execute_wrapper_runtime_job(
    plan: &Value,
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    source_paths: Option<(&Path, &Path)>,
    out_path: Option<&Path>,
    trace_out: Option<&Path>,
) -> Result<(ProofArtifact, Value), String> {
    use std::time::Instant;
    use zkf_backends::wrapping::default_wrapper_registry;

    let trust_lane = parse_required_trust_lane(Some(required_string(plan, "trust_lane")?))?;
    enforce_wrap_mode_policy(trust_lane)?;
    let preview_value = plan
        .get("wrapper_preview")
        .cloned()
        .ok_or_else(|| "runtime wrapper plan is missing wrapper_preview".to_string())?;
    let preview: WrapperPreview = serde_json::from_value(preview_value)
        .map_err(|e| format!("invalid wrapper_preview in runtime plan: {e}"))?;
    if let Some(profile) = plan.get("hardware_profile").and_then(Value::as_str) {
        enforce_wrapper_hardware_policy(
            parse_hardware_profile(Some(profile))?,
            trust_lane,
            &preview,
        )?;
    }
    enforce_preview_trust_lane(&preview, trust_lane)?;
    if let Some((proof_path, compiled_path)) = source_paths {
        validate_wrapper_plan_bindings(
            plan,
            proof_path,
            compiled_path,
            source_proof,
            source_compiled,
        )?;
    } else if plan.get("input_bindings").is_some() {
        let expected = parse_wrapper_plan_bindings(plan)?;
        let actual =
            build_wrapper_plan_bindings_from_inputs(None, None, source_proof, source_compiled)?;
        if expected != actual {
            return Err(
                "runtime wrapper plan bindings do not match the in-memory source artifact; regenerate the plan"
                    .to_string(),
            );
        }
    }
    let input_bindings = parse_wrapper_plan_bindings(plan)?;
    let current_preview = preview_wrapper_inputs(
        source_proof,
        source_compiled,
        trust_lane,
        wrap_mode_override_for_strategy(&preview.strategy),
    )?;
    if let Err(err) = enforce_prepare_ready_preview(&current_preview) {
        if let Some(trace_path) = trace_out {
            emit_prepare_required_trace(plan, source_paths, &current_preview, trace_path)?;
        }
        return Err(err);
    }
    if !wrapper_preview_matches_plan(&preview, &current_preview) {
        return Err(
            "runtime wrapper plan no longer matches the current inputs or environment; regenerate the plan"
                .to_string(),
        );
    }
    let registry = default_wrapper_registry();
    let wrapper = registry
        .find(source_proof.backend, zkf_core::BackendKind::ArkworksGroth16)
        .ok_or_else(|| {
            format!(
                "no wrapper found for {} -> arkworks-groth16",
                source_proof.backend
            )
        })?;

    eprintln!(
        "executing wrapper runtime job: {} -> groth16 (this may take several minutes)...",
        source_proof.backend
    );

    let execution_start = Instant::now();
    let emission =
        build_wrapper_emission_from_inputs(&preview, source_proof, source_compiled, trust_lane)?;
    let mut execution = execute_runtime_emission(emission, plan)?;
    let op_names: Vec<&str> = execution
        .result
        .report
        .node_traces
        .iter()
        .map(|trace| trace.op_name)
        .collect();
    if execution.result.report.node_traces.is_empty()
        || !op_names.contains(&"WitnessSolve")
        || !op_names.contains(&"TranscriptUpdate")
        || !op_names.contains(&"VerifierEmbed")
        || !op_names.contains(&"OuterProve")
        || !op_names.contains(&"ProofEncode")
    {
        return Err(
            "runtime wrapper execution did not complete through the expected scheduler stages"
                .to_string(),
        );
    }
    if execution.result.report.delegated_nodes != 0 {
        return Err(
            "runtime wrapper execution unexpectedly delegated wrapper stages outside the native scheduler path"
                .to_string(),
        );
    }
    let mut wrapped = execution.exec_ctx.take_wrapped_artifact().ok_or_else(|| {
        "runtime wrapper execution completed without producing a wrapped artifact".to_string()
    })?;
    let ok = wrapper
        .verify_wrapped(&wrapped)
        .map_err(crate::util::render_zkf_error)?;
    if !ok {
        return Err(
            "runtime wrapper execution produced a proof that fails verification".to_string(),
        );
    }
    annotate_wrapper_runtime_metadata(&mut wrapped, plan, &input_bindings, out_path)?;
    enforce_artifact_trust_lane(&wrapped, trust_lane)?;
    if let Some(output_path) = out_path {
        crate::util::write_json(output_path, &wrapped)?;
        println!("wrapped proof written to {}", output_path.display());
        println!("verification: OK");
    }

    let execution_duration_ms = execution_start.elapsed().as_secs_f64() * 1_000.0;
    let trace = build_wrapper_execution_trace_with_runtime_result(
        plan,
        out_path,
        trace_out,
        &wrapped,
        execution_duration_ms,
        &execution.result,
    );
    if let Some(trace_path) = trace_out {
        crate::util::write_json(trace_path, &trace)?;
        println!("runtime trace written to {}", trace_path.display());
    }
    Ok((wrapped, trace))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_wrap_via_runtime(
    proof_path: PathBuf,
    compiled_path: PathBuf,
    hardware_profile: Option<String>,
    allow_attestation: bool,
    compress: bool,
    dry_run: bool,
    out: PathBuf,
    trace_out: Option<PathBuf>,
) -> Result<(), String> {
    let trust_lane = if allow_attestation {
        zkf_runtime::RequiredTrustLane::AllowAttestation
    } else {
        zkf_runtime::RequiredTrustLane::StrictCryptographic
    };
    let hardware_profile = resolve_hardware_profile(hardware_profile.as_deref())?;
    let source_proof: ProofArtifact = read_json_path(&proof_path)?;
    let source_compiled: CompiledProgram = read_json_path(&compiled_path)?;
    let force_mode = compress.then_some(WrapModeOverride::Nova);
    let (plan, preview, _) = build_wrapper_runtime_plan_document_from_inputs(
        Some(&proof_path),
        Some(&compiled_path),
        &source_proof,
        &source_compiled,
        trust_lane,
        hardware_profile,
        force_mode,
    )?;

    if dry_run {
        let trace = build_wrapper_preview_trace_from_plan(Some(&proof_path), &preview, &plan);
        if let Some(trace_path) = trace_out {
            crate::util::write_json(&trace_path, &trace)?;
            println!("runtime trace written to {}", trace_path.display());
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&trace).map_err(|e| e.to_string())?
            );
        }
        println!("dry run only: no wrapped proof generated");
        return Ok(());
    }

    let (_, trace) = execute_wrapper_runtime_job(
        &plan,
        &source_proof,
        &source_compiled,
        Some((&proof_path, &compiled_path)),
        Some(&out),
        trace_out.as_deref(),
    )?;
    if trace_out.is_none() {
        println!(
            "{}",
            serde_json::to_string_pretty(&trace).map_err(|e| e.to_string())?
        );
    }
    println!("wrap succeeded: {} -> groth16", source_proof.backend);
    Ok(())
}

pub(crate) fn wrap_artifact_via_runtime(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    trust_lane: zkf_runtime::RequiredTrustLane,
    hardware_profile: zkf_runtime::HardwareProfile,
    force_mode: Option<WrapModeOverride>,
) -> Result<ProofArtifact, String> {
    let (plan, _, _) = build_wrapper_runtime_plan_document_from_inputs(
        None,
        None,
        source_proof,
        source_compiled,
        trust_lane,
        hardware_profile,
        force_mode,
    )?;
    let (wrapped, _) =
        execute_wrapper_runtime_job(&plan, source_proof, source_compiled, None, None, None)?;
    Ok(wrapped)
}

fn build_execution_trace(plan: &Value, result: &zkf_runtime::PlanExecutionResult) -> Value {
    let mut trace = Map::new();
    trace.insert(
        "trace_schema".to_string(),
        Value::String("zkf-runtime-execution-v1".to_string()),
    );
    if let Some(kind) = plan.get("plan_kind") {
        trace.insert("plan_kind".to_string(), kind.clone());
    }
    if let Some(trust_lane) = plan.get("trust_lane") {
        trace.insert("requested_trust_lane".to_string(), trust_lane.clone());
    }
    if let Some(required_trust_lane) = plan.get("required_trust_lane") {
        trace.insert(
            "required_trust_lane".to_string(),
            required_trust_lane.clone(),
        );
    }
    if let Some(profile) = plan.get("hardware_profile") {
        trace.insert("hardware_profile".to_string(), profile.clone());
    }
    if let Some(digest) = plan.get("plan_digest") {
        trace.insert("plan_digest".to_string(), digest.clone());
    }
    if let Some(summary) = plan.get("trust_summary") {
        trace.insert("trust_summary".to_string(), summary.clone());
    }
    if let Some(report) = plan.get("lowering_report") {
        trace.insert("lowering_report".to_string(), report.clone());
    }
    if let Some(proof) = plan.get("proof") {
        trace.insert("proof".to_string(), proof.clone());
    }
    if let Some(compiled) = plan.get("compiled") {
        trace.insert("compiled".to_string(), compiled.clone());
    }
    if let Some(program) = plan.get("program") {
        trace.insert("program".to_string(), program.clone());
    }
    if let Some(inputs) = plan.get("inputs") {
        trace.insert("inputs".to_string(), inputs.clone());
    }
    if let Some(bindings) = plan.get("program_bindings") {
        trace.insert("program_bindings".to_string(), bindings.clone());
        trace.insert("program_bindings_verified".to_string(), Value::Bool(true));
    }
    if let Some(runtime_plan) = plan.get("runtime_plan") {
        trace.insert("runtime_plan".to_string(), runtime_plan.clone());
        if let Some(buffer_lineage) = runtime_plan.get("buffers") {
            trace.insert("buffer_lineage".to_string(), buffer_lineage.clone());
        }
    }
    if let Some(preview_value) = plan.get("wrapper_preview")
        && let Ok(preview) = serde_json::from_value::<WrapperPreview>(preview_value.clone())
    {
        insert_wrapper_preview_fields(&mut trace, None, &preview);
    }
    insert_runtime_execution_report(&mut trace, result);
    Value::Object(trace)
}

fn insert_runtime_execution_report(
    trace: &mut Map<String, Value>,
    result: &zkf_runtime::PlanExecutionResult,
) {
    let runtime_stage_breakdown =
        serde_json::to_value(result.report.stage_breakdown()).unwrap_or_else(|_| json!({}));
    trace.insert(
        "total_wall_time_ms".to_string(),
        json!(result.report.total_wall_time.as_millis()),
    );
    trace.insert(
        "peak_memory_bytes".to_string(),
        Value::from(result.report.peak_memory_bytes as u64),
    );
    trace.insert(
        "gpu_nodes".to_string(),
        Value::from(result.report.gpu_nodes as u64),
    );
    trace.insert(
        "cpu_nodes".to_string(),
        Value::from(result.report.cpu_nodes as u64),
    );
    trace.insert(
        "delegated_nodes".to_string(),
        Value::from(result.report.delegated_nodes as u64),
    );
    trace.insert(
        "final_trust_model".to_string(),
        Value::String(result.report.final_trust_model.as_str().to_string()),
    );
    trace.insert(
        "node_count".to_string(),
        Value::from(result.report.node_traces.len() as u64),
    );
    trace.insert(
        "runtime_gpu_stage_busy_ratio".to_string(),
        json!(result.report.gpu_stage_busy_ratio()),
    );
    trace.insert(
        "runtime_gpu_wall_time_ms".to_string(),
        json!(result.report.gpu_wall_time().as_secs_f64() * 1000.0),
    );
    trace.insert(
        "runtime_cpu_wall_time_ms".to_string(),
        json!(result.report.cpu_wall_time().as_secs_f64() * 1000.0),
    );
    trace.insert(
        "runtime_metal_counter_source".to_string(),
        Value::String(result.report.counter_source().to_string()),
    );
    trace.insert(
        "runtime_stage_breakdown".to_string(),
        runtime_stage_breakdown.clone(),
    );
    trace.insert(
        "runtime_stage_count".to_string(),
        Value::from(count_stage_nodes(&runtime_stage_breakdown) as u64),
    );
    trace.insert(
        "runtime_stage_duration_ms".to_string(),
        Value::from(sum_stage_durations_ms(&runtime_stage_breakdown)),
    );
    trace.insert(
        "node_traces".to_string(),
        Value::Array(
            result
                .report
                .node_traces
                .iter()
                .map(|node| {
                    json!({
                        "node_id": node.node_id.as_u64(),
                        "op": node.op_name,
                        "placement": placement_name(node.placement),
                        "trust_model": node.trust_model.as_str(),
                        "wall_time_ms": node.wall_time.as_secs_f64() * 1000.0,
                        "input_bytes": node.input_bytes,
                        "output_bytes": node.output_bytes,
                        "input_digest": hex_bytes(&node.input_digest),
                        "output_digest": hex_bytes(&node.output_digest),
                        "allocated_bytes_after": node.allocated_bytes_after,
                        "accelerator_name": node.accelerator_name,
                        "fell_back": node.fell_back,
                        "buffer_residency": node.buffer_residency,
                        "delegated": node.delegated,
                        "delegated_backend": node.delegated_backend,
                    })
                })
                .collect(),
        ),
    );
    if let Some(control_plane) = &result.control_plane {
        trace.insert(
            "runtime_job_kind".to_string(),
            Value::String(control_plane.decision.job_kind.as_str().to_string()),
        );
        trace.insert(
            "dispatch_plan".to_string(),
            serde_json::to_value(&control_plane.decision.dispatch_plan)
                .unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "dispatch_candidate_rankings".to_string(),
            serde_json::to_value(&control_plane.decision.candidate_rankings)
                .unwrap_or_else(|_| json!([])),
        );
        trace.insert(
            "backend_recommendation".to_string(),
            serde_json::to_value(&control_plane.decision.backend_recommendation)
                .unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "duration_estimate".to_string(),
            serde_json::to_value(&control_plane.decision.duration_estimate)
                .unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "anomaly_baseline".to_string(),
            serde_json::to_value(&control_plane.decision.anomaly_baseline)
                .unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "anomaly_verdict".to_string(),
            serde_json::to_value(&control_plane.anomaly_verdict).unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "model_catalog".to_string(),
            serde_json::to_value(&control_plane.decision.model_catalog)
                .unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "control_plane_features".to_string(),
            serde_json::to_value(&control_plane.decision.features).unwrap_or_else(|_| json!({})),
        );
        trace.insert(
            "realized_gpu_capable_stages".to_string(),
            serde_json::to_value(&control_plane.realized_gpu_capable_stages)
                .unwrap_or_else(|_| json!([])),
        );
    }
}

fn build_wrapper_execution_trace(
    plan: &Value,
    artifact_path: Option<&Path>,
    trace_path: Option<&Path>,
    artifact: &ProofArtifact,
    execution_duration_ms: f64,
) -> Value {
    let mut trace = match build_artifact_runtime_trace(artifact_path, artifact) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    trace.insert(
        "trace_schema".to_string(),
        Value::String("zkf-runtime-wrapper-execution-v1".to_string()),
    );
    trace.insert(
        "plan_kind".to_string(),
        Value::String("wrapper".to_string()),
    );
    if let Some(trust_lane) = plan.get("trust_lane") {
        trace.insert("requested_trust_lane".to_string(), trust_lane.clone());
    }
    if let Some(required_trust_lane) = plan.get("required_trust_lane") {
        trace.insert(
            "required_trust_lane".to_string(),
            required_trust_lane.clone(),
        );
    }
    if let Some(profile) = plan.get("hardware_profile") {
        trace.insert("hardware_profile".to_string(), profile.clone());
    }
    if let Some(digest) = plan.get("plan_digest") {
        trace.insert("plan_digest".to_string(), digest.clone());
    }
    if let Some(summary) = plan.get("trust_summary") {
        trace.insert("trust_summary".to_string(), summary.clone());
    }
    if let Some(report) = plan.get("lowering_report") {
        trace.insert("lowering_report".to_string(), report.clone());
    }
    if let Some(source_proof) = plan.get("proof") {
        trace.insert("source_proof".to_string(), source_proof.clone());
    }
    if let Some(source_compiled) = plan.get("compiled") {
        trace.insert("source_compiled".to_string(), source_compiled.clone());
    }
    if let Some(runtime_plan) = plan.get("runtime_plan") {
        trace.insert("runtime_plan".to_string(), runtime_plan.clone());
        if let Some(buffer_lineage) = runtime_plan.get("buffers") {
            trace.insert("buffer_lineage".to_string(), buffer_lineage.clone());
        }
    }
    trace.insert("input_bindings_verified".to_string(), Value::Bool(true));
    trace.insert(
        "runtime_execution_duration_ms".to_string(),
        json!(execution_duration_ms),
    );
    let cache_hit = trace
        .get("wrapper_cache_hit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if cache_hit {
        let artifact_stage_breakdown = trace.get("stage_breakdown").cloned().unwrap_or(Value::Null);
        let artifact_stage_count = trace
            .get("stage_count")
            .cloned()
            .unwrap_or_else(|| Value::from(0u64));
        let artifact_stage_duration_ms = trace
            .get("stage_duration_ms")
            .cloned()
            .unwrap_or_else(|| json!(0.0));
        let cache_source = trace
            .get("wrapper_cache_source")
            .and_then(Value::as_str)
            .unwrap_or("cache")
            .to_string();
        trace.insert(
            "artifact_stage_breakdown".to_string(),
            artifact_stage_breakdown,
        );
        trace.insert("artifact_stage_count".to_string(), artifact_stage_count);
        trace.insert(
            "artifact_stage_duration_ms".to_string(),
            artifact_stage_duration_ms,
        );
        trace.insert(
            "stage_breakdown".to_string(),
            json!({
                "artifact_cache": {
                    "accelerator": "cpu",
                    "duration_ms": execution_duration_ms,
                    "inflight_jobs": 1,
                    "no_cpu_fallback": false,
                    "fallback_reason": format!("wrapper-cache-{cache_source}"),
                }
            }),
        );
        trace.insert("stage_count".to_string(), Value::from(1u64));
        trace.insert(
            "stage_duration_ms".to_string(),
            json!(execution_duration_ms),
        );
    }
    if let Some(path) = trace_path {
        trace.insert(
            "trace_output".to_string(),
            Value::String(path.display().to_string()),
        );
    }
    Value::Object(trace)
}

fn build_wrapper_execution_trace_with_runtime_result(
    plan: &Value,
    artifact_path: Option<&Path>,
    trace_path: Option<&Path>,
    artifact: &ProofArtifact,
    execution_duration_ms: f64,
    result: &zkf_runtime::PlanExecutionResult,
) -> Value {
    let mut trace = match build_wrapper_execution_trace(
        plan,
        artifact_path,
        trace_path,
        artifact,
        execution_duration_ms,
    ) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    insert_runtime_execution_report(&mut trace, result);
    Value::Object(trace)
}

fn build_wrapper_prepare_report(
    proof_path: &Path,
    compiled_path: &Path,
    trust_lane: zkf_runtime::RequiredTrustLane,
    hardware_profile: zkf_runtime::HardwareProfile,
    plan: &Value,
    preview: &WrapperPreview,
    report: &WrapperCachePrepareReport,
) -> Value {
    let mut out = Map::new();
    out.insert(
        "report_schema".to_string(),
        Value::String("zkf-runtime-wrapper-prepare-v1".to_string()),
    );
    out.insert(
        "proof".to_string(),
        Value::String(proof_path.display().to_string()),
    );
    out.insert(
        "compiled".to_string(),
        Value::String(compiled_path.display().to_string()),
    );
    out.insert(
        "requested_trust_lane".to_string(),
        Value::String(trust_lane_name(trust_lane).to_string()),
    );
    out.insert(
        "hardware_profile".to_string(),
        Value::String(hardware_profile.as_str().to_string()),
    );
    if let Some(required_trust_lane) = plan.get("required_trust_lane") {
        out.insert(
            "required_trust_lane".to_string(),
            required_trust_lane.clone(),
        );
    }
    if let Some(digest) = plan.get("plan_digest") {
        out.insert("plan_digest".to_string(), digest.clone());
    }
    if let Some(summary) = plan.get("trust_summary") {
        out.insert("trust_summary".to_string(), summary.clone());
    }
    if let Some(lowering) = plan.get("lowering_report") {
        out.insert("lowering_report".to_string(), lowering.clone());
    }
    out.insert(
        "wrapper_preview".to_string(),
        serde_json::to_value(preview).unwrap_or(Value::Null),
    );
    out.insert(
        "cache_report".to_string(),
        serde_json::to_value(report).unwrap_or(Value::Null),
    );
    Value::Object(out)
}

fn build_bundle_prepare_report(
    preview: &WrapperPreview,
    manifest: &zkf_backends::wrapping::stark_to_groth16::WrapperCacheBundleManifest,
    installed: bool,
) -> WrapperCachePrepareReport {
    WrapperCachePrepareReport {
        wrapper: preview.wrapper.clone(),
        source_backend: preview.source_backend,
        target_backend: preview.target_backend,
        strategy: manifest.strategy.clone(),
        trust_model: manifest.trust_model.clone(),
        setup_cache_ready: true,
        shape_cache_ready: Some(manifest.shape_cache_ready),
        setup_cache_pk_format: Some(manifest.setup_cache_pk_format.clone()),
        setup_cache_pk_migrated: false,
        blocked: false,
        setup_cache_state: Some(manifest.cache_state.clone()),
        blocked_reason: None,
        operator_action: None,
        detail: Some(if installed {
            "installed prepared direct-wrap cache bundle".to_string()
        } else {
            "exported prepared direct-wrap cache bundle".to_string()
        }),
    }
}

fn summarize_runtime_plan(graph: &zkf_runtime::ProverGraph) -> Value {
    let mut buffer_catalog = BTreeMap::<u32, RuntimePlanBufferSummary>::new();
    let nodes = graph
        .iter_nodes()
        .enumerate()
        .map(|(index, node)| {
            record_runtime_plan_buffers(&mut buffer_catalog, node, true);
            record_runtime_plan_buffers(&mut buffer_catalog, node, false);
            json!({
                "index": index,
                "node_id": node.id.as_u64(),
                "op": node.op.name(),
                "placement": placement_name(node.device_pref),
                "trust_model": node.trust_model.as_str(),
                "deterministic": node.deterministic,
                "dependencies": node.deps.iter().map(|dep| dep.as_u64()).collect::<Vec<_>>(),
                "inputs": node.input_buffers.iter().map(buffer_summary).collect::<Vec<_>>(),
                "outputs": node.output_buffers.iter().map(buffer_summary).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let graph_nodes = graph
        .iter_nodes()
        .map(|node| {
            json!({
                "node_id": node.id.as_u64(),
                "op": node.op.name(),
                "dependencies": node.deps.iter().map(|dep| dep.as_u64()).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let graph_edges = graph
        .iter_nodes()
        .flat_map(|node| {
            node.deps.iter().map(move |dep| {
                json!({
                    "from": dep.as_u64(),
                    "to": node.id.as_u64(),
                })
            })
        })
        .collect::<Vec<_>>();
    let placement_nodes = graph
        .iter_nodes()
        .map(|node| {
            json!({
                "node_id": node.id.as_u64(),
                "requested": placement_name(node.device_pref),
                "trust_model": node.trust_model.as_str(),
                "deterministic": node.deterministic,
                "input_slots": node.input_buffers.iter().map(|handle| handle.slot).collect::<Vec<_>>(),
                "output_slots": node.output_buffers.iter().map(|handle| handle.slot).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let contains_attestation_nodes = graph
        .iter_nodes()
        .any(|node| node.trust_model.as_str() == "attestation");
    let contains_gpu_candidates = graph
        .iter_nodes()
        .any(|node| placement_name(node.device_pref) == "gpu");
    let buffers = buffer_catalog
        .into_values()
        .map(|buffer| {
            json!({
                "slot": buffer.slot,
                "size_bytes": buffer.size_bytes,
                "class": buffer.class,
                "producer_node_ids": buffer.producer_node_ids,
                "consumer_node_ids": buffer.consumer_node_ids,
            })
        })
        .collect::<Vec<_>>();
    let total_buffer_bytes = buffers
        .iter()
        .filter_map(|buffer| buffer.get("size_bytes").and_then(Value::as_u64))
        .sum::<u64>();
    let hot_resident_bytes = buffers
        .iter()
        .filter(|buffer| buffer.get("class").and_then(Value::as_str) == Some("hot-resident"))
        .filter_map(|buffer| buffer.get("size_bytes").and_then(Value::as_u64))
        .sum::<u64>();
    let scratch_bytes = buffers
        .iter()
        .filter(|buffer| buffer.get("class").and_then(Value::as_str) == Some("scratch"))
        .filter_map(|buffer| buffer.get("size_bytes").and_then(Value::as_u64))
        .sum::<u64>();
    let spill_bytes = buffers
        .iter()
        .filter(|buffer| buffer.get("class").and_then(Value::as_str) == Some("spill"))
        .filter_map(|buffer| buffer.get("size_bytes").and_then(Value::as_u64))
        .sum::<u64>();
    let gpu_candidate_count = graph
        .iter_nodes()
        .filter(|node| placement_name(node.device_pref) == "gpu")
        .count();
    let cpu_only_count = graph
        .iter_nodes()
        .filter(|node| placement_name(node.device_pref) == "cpu")
        .count();
    let either_count = graph
        .iter_nodes()
        .filter(|node| placement_name(node.device_pref) == "either")
        .count();

    json!({
        "node_count": graph.node_count(),
        "ops": graph.iter_nodes().map(|node| node.op.name()).collect::<Vec<_>>(),
        "contains_attestation_nodes": contains_attestation_nodes,
        "contains_gpu_candidates": contains_gpu_candidates,
        "nodes": nodes,
        "graph": {
            "node_count": graph.node_count(),
            "nodes": graph_nodes,
            "edges": graph_edges,
        },
        "buffers": {
            "count": buffers.len(),
            "total_size_bytes": total_buffer_bytes,
            "class_totals_bytes": {
                "hot_resident": hot_resident_bytes,
                "scratch": scratch_bytes,
                "spill": spill_bytes,
            },
            "items": buffers,
        },
        "placement": {
            "gpu_candidate_count": gpu_candidate_count,
            "cpu_only_count": cpu_only_count,
            "either_count": either_count,
            "nodes": placement_nodes,
        },
    })
}

#[derive(Debug, Clone)]
struct RuntimePlanBufferSummary {
    slot: u32,
    size_bytes: usize,
    class: &'static str,
    producer_node_ids: Vec<u64>,
    consumer_node_ids: Vec<u64>,
}

fn record_runtime_plan_buffers(
    catalog: &mut BTreeMap<u32, RuntimePlanBufferSummary>,
    node: &zkf_runtime::ProverNode,
    outputs: bool,
) {
    let handles = if outputs {
        &node.output_buffers
    } else {
        &node.input_buffers
    };
    for handle in handles {
        let summary = catalog
            .entry(handle.slot)
            .or_insert_with(|| RuntimePlanBufferSummary {
                slot: handle.slot,
                size_bytes: handle.size_bytes,
                class: memory_class_name(handle.class),
                producer_node_ids: Vec::new(),
                consumer_node_ids: Vec::new(),
            });
        summary.size_bytes = summary.size_bytes.max(handle.size_bytes);
        if outputs {
            if !summary.producer_node_ids.contains(&node.id.as_u64()) {
                summary.producer_node_ids.push(node.id.as_u64());
            }
        } else if !summary.consumer_node_ids.contains(&node.id.as_u64()) {
            summary.consumer_node_ids.push(node.id.as_u64());
        }
    }
}

fn buffer_summary(handle: &zkf_runtime::BufferHandle) -> Value {
    json!({
        "slot": handle.slot,
        "size_bytes": handle.size_bytes,
        "class": memory_class_name(handle.class),
    })
}

fn memory_class_name(class: zkf_runtime::MemoryClass) -> &'static str {
    match class {
        zkf_runtime::MemoryClass::HotResident => "hot-resident",
        zkf_runtime::MemoryClass::EphemeralScratch => "scratch",
        zkf_runtime::MemoryClass::Spillable => "spill",
    }
}

fn placement_name(placement: zkf_runtime::DevicePlacement) -> &'static str {
    match placement {
        zkf_runtime::DevicePlacement::Cpu => "cpu",
        zkf_runtime::DevicePlacement::Gpu => "gpu",
        zkf_runtime::DevicePlacement::CpuCrypto => "cpu-crypto",
        zkf_runtime::DevicePlacement::CpuSme => "cpu-sme",
        zkf_runtime::DevicePlacement::Either => "either",
    }
}

fn finalize_plan_document(mut plan: Value) -> Result<Value, String> {
    let digest = plan_digest(&plan)?;
    let obj = plan
        .as_object_mut()
        .ok_or_else(|| "runtime plan document must be an object".to_string())?;
    obj.insert("plan_digest".to_string(), Value::String(digest));
    Ok(plan)
}

fn plan_digest(plan: &Value) -> Result<String, String> {
    let mut canonical = plan.clone();
    if let Some(map) = canonical.as_object_mut() {
        map.remove("plan_digest");
    }
    let bytes = serde_json::to_vec_pretty(&canonical).map_err(|e| e.to_string())?;
    Ok(crate::util::sha256_hex(&bytes))
}

fn build_generic_trust_summary(backend: &str, trust_lane: zkf_runtime::RequiredTrustLane) -> Value {
    let support_class = match backend {
        "groth16" | "arkworks-groth16" | "plonky3" => "native",
        _ => "adapted",
    };
    let trust_model = match trust_lane {
        zkf_runtime::RequiredTrustLane::StrictCryptographic => "cryptographic",
        zkf_runtime::RequiredTrustLane::AllowAttestation => "attestation",
        zkf_runtime::RequiredTrustLane::AllowMetadataOnly => "metadata-only",
    };
    json!({
        "support_class": support_class,
        "trust_model": trust_model,
        "contains_delegated_nodes": false,
        "contains_attestation_nodes": trust_model == "attestation",
        "contains_metadata_only_nodes": trust_model == "metadata-only",
    })
}

fn build_generic_lowering_report(
    backend: &str,
    field: &str,
    trust_lane: zkf_runtime::RequiredTrustLane,
) -> Value {
    json!({
        "backend": backend,
        "support_class": match backend {
            "groth16" | "arkworks-groth16" | "plonky3" => "native",
            _ => "adapted",
        },
        "trust_model": match trust_lane {
            zkf_runtime::RequiredTrustLane::StrictCryptographic => "cryptographic",
            zkf_runtime::RequiredTrustLane::AllowAttestation => "attestation",
            zkf_runtime::RequiredTrustLane::AllowMetadataOnly => "metadata-only",
        },
        "preserved_features": ["canonical-ir", field],
        "adapted_features": [],
        "delegated_features": [],
        "rejected_features": [],
    })
}

fn build_wrapper_trust_summary(preview: &WrapperPreview) -> Value {
    json!({
        "support_class": "adapted",
        "trust_model": preview.trust_model,
        "contains_delegated_nodes": false,
        "contains_attestation_nodes": preview.trust_model == "attestation",
        "contains_metadata_only_nodes": matches!(preview.trust_model.as_str(), "metadata" | "metadata-only"),
    })
}

fn build_wrapper_lowering_report(preview: &WrapperPreview) -> Value {
    json!({
        "backend": preview.source_backend.to_string(),
        "support_class": "adapted",
        "trust_model": preview.trust_model,
        "preserved_features": ["source-proof-binding", "target-groth16-output"],
        "adapted_features": [
            {
                "feature": "wrapper",
                "original_semantics": preview.source_backend.to_string(),
                "adapted_semantics": preview.strategy,
                "soundness_note": preview.trust_model_description,
            }
        ],
        "delegated_features": [],
        "rejected_features": [],
    })
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("runtime plan is missing string field: {key}"))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("runtime plan is missing integer field: {key}"))
}

fn build_wrapper_plan_bindings_from_inputs(
    proof_path: Option<&Path>,
    compiled_path: Option<&Path>,
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
) -> Result<WrapperPlanBindings, String> {
    let proof_bytes = match proof_path {
        Some(path) => std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => serde_json::to_vec_pretty(source_proof).map_err(|e| e.to_string())?,
    };
    let compiled_bytes = match compiled_path {
        Some(path) => std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => serde_json::to_vec_pretty(source_compiled).map_err(|e| e.to_string())?,
    };

    Ok(WrapperPlanBindings {
        proof_sha256: crate::util::sha256_hex(&proof_bytes),
        compiled_sha256: crate::util::sha256_hex(&compiled_bytes),
        source_backend: source_proof.backend.to_string(),
        source_program_digest: source_proof.program_digest.clone(),
        compiled_backend: source_compiled.backend.to_string(),
        compiled_program_digest: source_compiled.program_digest.clone(),
    })
}

fn validate_wrapper_plan_bindings(
    plan: &Value,
    proof_path: &Path,
    compiled_path: &Path,
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
) -> Result<(), String> {
    let Some(bindings_value) = plan.get("input_bindings") else {
        return Ok(());
    };
    let bindings: WrapperPlanBindings = serde_json::from_value(bindings_value.clone())
        .map_err(|e| format!("invalid input_bindings in runtime plan: {e}"))?;
    let actual = build_wrapper_plan_bindings_from_inputs(
        Some(proof_path),
        Some(compiled_path),
        source_proof,
        source_compiled,
    )?;

    if bindings.proof_sha256 != actual.proof_sha256 {
        return Err(format!(
            "runtime wrapper plan proof hash mismatch for {}: expected {}, found {}",
            proof_path.display(),
            bindings.proof_sha256,
            actual.proof_sha256
        ));
    }
    if bindings.compiled_sha256 != actual.compiled_sha256 {
        return Err(format!(
            "runtime wrapper plan compiled hash mismatch for {}: expected {}, found {}",
            compiled_path.display(),
            bindings.compiled_sha256,
            actual.compiled_sha256
        ));
    }
    if bindings.source_backend != source_proof.backend.to_string() {
        return Err(format!(
            "runtime wrapper plan source backend mismatch: expected {}, found {}",
            bindings.source_backend, source_proof.backend
        ));
    }
    if bindings.compiled_backend != source_compiled.backend.to_string() {
        return Err(format!(
            "runtime wrapper plan compiled backend mismatch: expected {}, found {}",
            bindings.compiled_backend, source_compiled.backend
        ));
    }
    if bindings.source_program_digest != source_proof.program_digest {
        return Err(format!(
            "runtime wrapper plan source program digest mismatch: expected {}, found {}",
            bindings.source_program_digest, source_proof.program_digest
        ));
    }
    if bindings.compiled_program_digest != source_compiled.program_digest {
        return Err(format!(
            "runtime wrapper plan compiled program digest mismatch: expected {}, found {}",
            bindings.compiled_program_digest, source_compiled.program_digest
        ));
    }

    Ok(())
}

fn wrapper_preview_matches_plan(expected: &WrapperPreview, actual: &WrapperPreview) -> bool {
    expected.wrapper == actual.wrapper
        && expected.source_backend == actual.source_backend
        && expected.target_backend == actual.target_backend
        && expected.planned_status == actual.planned_status
        && expected.strategy == actual.strategy
        && expected.trust_model == actual.trust_model
        && expected.estimated_constraints == actual.estimated_constraints
        && expected.low_memory_mode == actual.low_memory_mode
}

fn enforce_prepare_ready_preview(preview: &WrapperPreview) -> Result<(), String> {
    if preview.prepare_required == Some(true) {
        return Err(preview.reason.clone().unwrap_or_else(|| {
            "wrapper execution is blocked until `zkf runtime prepare` completes".to_string()
        }));
    }
    Ok(())
}

fn emit_prepare_required_trace(
    plan: &Value,
    source_paths: Option<(&Path, &Path)>,
    preview: &WrapperPreview,
    trace_path: &Path,
) -> Result<(), String> {
    let proof_path = source_paths
        .map(|(proof_path, _)| proof_path)
        .or_else(|| plan.get("proof").and_then(Value::as_str).map(Path::new));
    let trace = build_wrapper_preview_trace_from_plan(proof_path, preview, plan);
    emit_json_output(trace, Some(trace_path.to_path_buf()))
}

fn verify_artifact_plan_provenance(
    plan_path: &Path,
    artifact: &ProofArtifact,
) -> Result<Value, String> {
    let plan_bytes =
        std::fs::read(plan_path).map_err(|e| format!("{}: {e}", plan_path.display()))?;
    let plan: Value = serde_json::from_slice(&plan_bytes)
        .map_err(|e| format!("invalid runtime plan JSON at {}: {e}", plan_path.display()))?;
    let plan_sha256 = crate::util::sha256_hex(&plan_bytes);
    let mismatches = collect_artifact_plan_mismatches(&plan, &plan_sha256, artifact)?;
    if !mismatches.is_empty() {
        return Err(format!(
            "runtime plan provenance mismatch for {}: {}",
            plan_path.display(),
            mismatches.join("; ")
        ));
    }

    Ok(json!({
        "matches": true,
        "plan": plan_path.display().to_string(),
        "plan_sha256": plan_sha256,
        "plan_schema": required_string(&plan, "plan_schema")?,
        "plan_kind": required_string(&plan, "plan_kind")?,
    }))
}

fn collect_artifact_plan_mismatches(
    plan: &Value,
    plan_sha256: &str,
    artifact: &ProofArtifact,
) -> Result<Vec<String>, String> {
    let mut mismatches = Vec::new();
    let metadata = &artifact.metadata;

    compare_metadata_field(
        &mut mismatches,
        metadata,
        "runtime_plan_schema",
        required_string(plan, "plan_schema")?,
    );
    compare_metadata_field(
        &mut mismatches,
        metadata,
        "runtime_plan_kind",
        required_string(plan, "plan_kind")?,
    );
    compare_metadata_field(
        &mut mismatches,
        metadata,
        "runtime_plan_sha256",
        plan_sha256,
    );
    if let Some(trust_lane) = plan.get("trust_lane").and_then(Value::as_str) {
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_requested_trust_lane",
            trust_lane,
        );
    }
    if let Some(required_trust_lane) = plan.get("required_trust_lane").and_then(Value::as_str) {
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_required_trust_lane",
            required_trust_lane,
        );
    }
    if let Some(profile) = plan.get("hardware_profile").and_then(Value::as_str) {
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_hardware_profile",
            profile,
        );
    }
    if let Some(bindings_value) = plan.get("input_bindings") {
        let bindings: WrapperPlanBindings = serde_json::from_value(bindings_value.clone())
            .map_err(|e| format!("invalid input_bindings in runtime plan: {e}"))?;
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_source_proof_sha256",
            &bindings.proof_sha256,
        );
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_source_compiled_sha256",
            &bindings.compiled_sha256,
        );
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_source_backend",
            &bindings.source_backend,
        );
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_source_program_digest",
            &bindings.source_program_digest,
        );
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_compiled_backend",
            &bindings.compiled_backend,
        );
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_compiled_program_digest",
            &bindings.compiled_program_digest,
        );
    }
    compare_metadata_field(
        &mut mismatches,
        metadata,
        "runtime_input_bindings_verified",
        "true",
    );
    if let Some(summary) = plan.get("trust_summary") {
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_trust_summary_json",
            &serde_json::to_string(summary).map_err(|e| e.to_string())?,
        );
    }
    if let Some(report) = plan.get("lowering_report") {
        compare_metadata_field(
            &mut mismatches,
            metadata,
            "runtime_lowering_report_json",
            &serde_json::to_string(report).map_err(|e| e.to_string())?,
        );
    }

    Ok(mismatches)
}

fn compare_metadata_field(
    mismatches: &mut Vec<String>,
    metadata: &std::collections::BTreeMap<String, String>,
    key: &str,
    expected: &str,
) {
    match metadata.get(key) {
        Some(actual) if actual == expected => {}
        Some(actual) => mismatches.push(format!("{key} expected {expected} but found {actual}")),
        None => mismatches.push(format!("{key} missing")),
    }
}

fn parse_wrapper_plan_bindings(plan: &Value) -> Result<WrapperPlanBindings, String> {
    let bindings_value = plan
        .get("input_bindings")
        .cloned()
        .ok_or_else(|| "runtime wrapper plan is missing input_bindings".to_string())?;
    serde_json::from_value(bindings_value)
        .map_err(|e| format!("invalid input_bindings in runtime plan: {e}"))
}

fn annotate_wrapper_runtime_metadata(
    artifact: &mut ProofArtifact,
    plan: &Value,
    bindings: &WrapperPlanBindings,
    output_path: Option<&Path>,
) -> Result<(), String> {
    let plan_bytes = serde_json::to_vec_pretty(plan).map_err(|e| e.to_string())?;
    artifact.metadata.insert(
        "runtime_plan_schema".to_string(),
        required_string(plan, "plan_schema")?.to_string(),
    );
    artifact.metadata.insert(
        "runtime_plan_kind".to_string(),
        required_string(plan, "plan_kind")?.to_string(),
    );
    artifact.metadata.insert(
        "runtime_plan_sha256".to_string(),
        crate::util::sha256_hex(&plan_bytes),
    );
    artifact.metadata.insert(
        "runtime_requested_trust_lane".to_string(),
        required_string(plan, "trust_lane")?.to_string(),
    );
    let required_trust_lane = plan
        .get("required_trust_lane")
        .and_then(Value::as_str)
        .unwrap_or(required_string(plan, "trust_lane")?);
    artifact.metadata.insert(
        "runtime_required_trust_lane".to_string(),
        required_trust_lane.to_string(),
    );
    if let Some(profile) = plan.get("hardware_profile").and_then(Value::as_str) {
        artifact
            .metadata
            .insert("runtime_hardware_profile".to_string(), profile.to_string());
    }
    artifact.metadata.insert(
        "runtime_source_proof_sha256".to_string(),
        bindings.proof_sha256.clone(),
    );
    artifact.metadata.insert(
        "runtime_source_compiled_sha256".to_string(),
        bindings.compiled_sha256.clone(),
    );
    artifact.metadata.insert(
        "runtime_source_backend".to_string(),
        bindings.source_backend.clone(),
    );
    artifact.metadata.insert(
        "runtime_source_program_digest".to_string(),
        bindings.source_program_digest.clone(),
    );
    artifact.metadata.insert(
        "runtime_compiled_backend".to_string(),
        bindings.compiled_backend.clone(),
    );
    artifact.metadata.insert(
        "runtime_compiled_program_digest".to_string(),
        bindings.compiled_program_digest.clone(),
    );
    artifact.metadata.insert(
        "runtime_input_bindings_verified".to_string(),
        "true".to_string(),
    );
    if let Some(summary) = plan.get("trust_summary") {
        artifact.metadata.insert(
            "runtime_trust_summary_json".to_string(),
            serde_json::to_string(summary).map_err(|e| e.to_string())?,
        );
    }
    if let Some(report) = plan.get("lowering_report") {
        artifact.metadata.insert(
            "runtime_lowering_report_json".to_string(),
            serde_json::to_string(report).map_err(|e| e.to_string())?,
        );
    }
    artifact.metadata.insert(
        "runtime_output_path".to_string(),
        output_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<in-memory>".to_string()),
    );
    Ok(())
}

fn enforce_artifact_trust_lane(
    artifact: &ProofArtifact,
    trust_lane: zkf_runtime::RequiredTrustLane,
) -> Result<(), String> {
    use zkf_runtime::RequiredTrustLane;

    let trust_model = artifact
        .metadata
        .get("trust_model")
        .map(String::as_str)
        .unwrap_or("cryptographic");

    let allowed = match trust_lane {
        RequiredTrustLane::StrictCryptographic => trust_model == "cryptographic",
        RequiredTrustLane::AllowAttestation => {
            matches!(trust_model, "cryptographic" | "attestation")
        }
        RequiredTrustLane::AllowMetadataOnly => {
            matches!(
                trust_model,
                "cryptographic" | "attestation" | "metadata-only" | "metadata"
            )
        }
    };

    if allowed {
        Ok(())
    } else {
        Err(format!(
            "wrapped proof produced trust_model={trust_model}; rerun with --trust {} if that downgrade is intentional",
            match trust_model {
                "attestation" => "allow-attestation",
                _ => "allow-metadata",
            }
        ))
    }
}

fn emit_json_output(trace_json: Value, trace_out: Option<PathBuf>) -> Result<(), String> {
    let json_str = serde_json::to_string_pretty(&trace_json).map_err(|e| e.to_string())?;

    if let Some(path) = trace_out {
        crate::util::write_json(&path, &trace_json)?;
        println!("wrote execution trace to {}", path.display());
    } else {
        println!("{json_str}");
    }

    Ok(())
}

fn handle_trace(proof: PathBuf, plan: Option<PathBuf>, json: bool) -> Result<(), String> {
    let data = std::fs::read_to_string(&proof).map_err(|e| format!("{}: {e}", proof.display()))?;

    let artifact: ProofArtifact =
        serde_json::from_str(&data).map_err(|e| format!("invalid proof JSON: {e}"))?;

    let mut trace = build_artifact_runtime_trace(Some(&proof), &artifact);
    if let Some(plan_path) = plan.as_ref() {
        let verification = verify_artifact_plan_provenance(plan_path, &artifact)?;
        if let Value::Object(map) = &mut trace {
            map.insert("plan_verification".to_string(), verification);
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&trace).unwrap_or_default()
        );
    } else {
        for key in [
            "proof",
            "backend",
            "status",
            "wrapper_strategy",
            "trust_model",
            "wrapper_cache_hit",
            "wrapper_cache_source",
            "umpg_plan_reason",
        ] {
            if let Some(value) = trace.get(key) {
                println!("{key}: {value}");
            }
        }
        if let Some(plan_verification) = trace.get("plan_verification") {
            println!(
                "plan_verification: {}",
                serde_json::to_string(plan_verification).unwrap_or_default()
            );
        }
        if let Some(stages) = trace.get("stage_breakdown").and_then(Value::as_object) {
            println!("stage_breakdown:");
            for (name, value) in stages {
                println!(
                    "  {name}: {}",
                    serde_json::to_string(value).unwrap_or_default()
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn build_artifact_runtime_trace(
    proof_path: Option<&Path>,
    artifact: &ProofArtifact,
) -> Value {
    let metadata = &artifact.metadata;
    let stage_breakdown = metadata
        .get("metal_stage_breakdown")
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or(Value::Null);

    let mut trace = Map::new();
    trace.insert(
        "trace_schema".to_string(),
        Value::String("zkf-wrapper-trace-v1".to_string()),
    );
    if let Some(path) = proof_path {
        trace.insert(
            "proof".to_string(),
            Value::String(path.display().to_string()),
        );
    }
    trace.insert(
        "backend".to_string(),
        Value::String(artifact.backend.to_string()),
    );

    for key in [
        "status",
        "source_backend",
        "wrapper",
        "wrapper_strategy",
        "wrapper_cache_hit",
        "wrapper_cache_source",
        "wrapper_setup_cache_pk_format",
        "wrapper_setup_cache_pk_migrated",
        "trust_model",
        "trust_model_description",
        "gpu_stage_coverage",
        "gpu_stage_busy_ratio",
        "msm_accelerator",
        "qap_witness_map_engine",
        "qap_witness_map_reason",
        "qap_witness_map_parallelism",
        "qap_witness_map_fallback_state",
        "groth16_msm_engine",
        "groth16_msm_reason",
        "groth16_msm_parallelism",
        "groth16_msm_fallback_state",
        "source_verification_semantics",
        "wrapper_semantics",
        "proof_engine",
        "umpg_estimated_constraints",
        "umpg_estimated_memory_bytes",
        "umpg_memory_budget_bytes",
        "umpg_low_memory_mode",
        "umpg_plan_reason",
        "runtime_plan_schema",
        "runtime_plan_kind",
        "runtime_plan_sha256",
        "runtime_job_kind",
        "runtime_dispatch_candidate",
        "runtime_predicted_duration_ms",
        "runtime_duration_estimate_ms",
        "runtime_duration_upper_bound_ms",
        "runtime_execution_regime",
        "runtime_eta_semantics",
        "runtime_duration_bound_source",
        "runtime_duration_countdown_safe",
        "runtime_duration_note",
        "runtime_duration_interpretation",
        "runtime_security_risk_level",
        "runtime_security_risk_score",
        "runtime_security_countdown_safe",
        "runtime_security_reason",
        "runtime_prover_acceleration_realized",
        "runtime_prover_acceleration_note",
        "runtime_requested_trust_lane",
        "runtime_required_trust_lane",
        "runtime_hardware_profile",
        "runtime_source_proof_sha256",
        "runtime_source_compiled_sha256",
        "runtime_source_backend",
        "runtime_source_program_digest",
        "runtime_compiled_backend",
        "runtime_compiled_program_digest",
        "runtime_input_bindings_verified",
        "runtime_output_path",
        "metal_dispatch_circuit_open",
        "metal_dispatch_last_failure",
        "target_groth16_metal_dispatch_circuit_open",
        "target_groth16_metal_dispatch_last_failure",
    ] {
        if let Some(value) = metadata.get(key) {
            trace.insert(key.to_string(), metadata_scalar(value));
        }
    }
    for (meta_key, trace_key) in [
        ("gpu_stage_coverage", "gpu_stage_coverage"),
        ("runtime_trust_summary_json", "trust_summary"),
        ("runtime_lowering_report_json", "lowering_report"),
        ("runtime_dispatch_plan_json", "dispatch_plan"),
        (
            "runtime_dispatch_candidate_rankings_json",
            "dispatch_candidate_rankings",
        ),
        (
            "runtime_backend_recommendation_json",
            "backend_recommendation",
        ),
        ("runtime_duration_estimate_json", "duration_estimate"),
        ("runtime_anomaly_verdict_json", "anomaly_verdict"),
        ("runtime_model_catalog_json", "model_catalog"),
        ("runtime_security_verdict_json", "security_verdict"),
        ("runtime_security_signals_json", "security_signals"),
        ("runtime_security_actions_json", "security_actions"),
        ("runtime_model_integrity_json", "model_integrity"),
        (
            "runtime_control_plane_features_json",
            "control_plane_features",
        ),
        (
            "runtime_realized_gpu_capable_stages_json",
            "realized_gpu_capable_stages",
        ),
    ] {
        if let Some(raw) = metadata.get(meta_key)
            && let Ok(parsed) = serde_json::from_str::<Value>(raw)
        {
            trace.insert(trace_key.to_string(), parsed);
        }
    }

    trace.insert("stage_breakdown".to_string(), stage_breakdown.clone());
    trace.insert(
        "stage_count".to_string(),
        Value::from(count_stage_nodes(&stage_breakdown) as u64),
    );
    trace.insert(
        "stage_duration_ms".to_string(),
        Value::from(sum_stage_durations_ms(&stage_breakdown)),
    );
    Value::Object(trace)
}

pub(crate) fn build_wrapper_preview_trace(
    proof_path: Option<&Path>,
    preview: &WrapperPreview,
) -> Value {
    let mut trace = Map::new();
    trace.insert(
        "trace_schema".to_string(),
        Value::String("zkf-wrapper-preview-v1".to_string()),
    );
    insert_wrapper_preview_fields(&mut trace, proof_path, preview);
    if let Some(plan) = build_wrapper_runtime_plan_summary(preview) {
        trace.insert("runtime_plan".to_string(), plan);
    }
    Value::Object(trace)
}

fn build_wrapper_preview_trace_from_plan(
    proof_path: Option<&Path>,
    preview: &WrapperPreview,
    plan: &Value,
) -> Value {
    let mut trace = match build_wrapper_preview_trace(proof_path, preview) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    if let Some(profile) = plan.get("hardware_profile") {
        trace.insert("hardware_profile".to_string(), profile.clone());
    }
    if let Some(digest) = plan.get("plan_digest") {
        trace.insert("plan_digest".to_string(), digest.clone());
    }
    if let Some(summary) = plan.get("trust_summary") {
        trace.insert("trust_summary".to_string(), summary.clone());
    }
    if let Some(report) = plan.get("lowering_report") {
        trace.insert("lowering_report".to_string(), report.clone());
    }
    Value::Object(trace)
}

fn build_wrapper_runtime_plan_summary(preview: &WrapperPreview) -> Option<Value> {
    let graph = zkf_runtime::RuntimeCompiler::build_wrapper_plan(
        preview,
        zkf_runtime::ExecutionMode::Deterministic,
    )
    .ok()?;
    Some(summarize_runtime_plan(&graph))
}

fn insert_wrapper_preview_fields(
    trace: &mut Map<String, Value>,
    proof_path: Option<&Path>,
    preview: &WrapperPreview,
) {
    if let Some(path) = proof_path {
        trace.insert(
            "proof".to_string(),
            Value::String(path.display().to_string()),
        );
    }
    trace.insert(
        "wrapper".to_string(),
        Value::String(preview.wrapper.clone()),
    );
    trace.insert(
        "source_backend".to_string(),
        Value::String(preview.source_backend.to_string()),
    );
    trace.insert(
        "target_backend".to_string(),
        Value::String(preview.target_backend.to_string()),
    );
    trace.insert(
        "status".to_string(),
        Value::String(preview.planned_status.clone()),
    );
    trace.insert(
        "wrapper_strategy".to_string(),
        Value::String(preview.strategy.clone()),
    );
    trace.insert(
        "trust_model".to_string(),
        Value::String(preview.trust_model.clone()),
    );
    if let Some(value) = &preview.trust_model_description {
        trace.insert(
            "trust_model_description".to_string(),
            Value::String(value.clone()),
        );
    }
    if let Some(value) = preview.estimated_constraints {
        trace.insert("umpg_estimated_constraints".to_string(), Value::from(value));
    }
    if let Some(value) = preview.estimated_memory_bytes {
        trace.insert(
            "umpg_estimated_memory_bytes".to_string(),
            Value::from(value),
        );
    }
    if let Some(value) = preview.memory_budget_bytes {
        trace.insert("umpg_memory_budget_bytes".to_string(), Value::from(value));
    }
    if let Some(value) = preview.low_memory_mode {
        trace.insert("umpg_low_memory_mode".to_string(), Value::Bool(value));
    }
    if let Some(value) = preview.prepare_required {
        trace.insert("prepare_required".to_string(), Value::Bool(value));
    }
    if let Some(value) = &preview.setup_cache_state {
        trace.insert(
            "setup_cache_state".to_string(),
            Value::String(value.clone()),
        );
    }
    if let Some(value) = &preview.reason {
        trace.insert("umpg_plan_reason".to_string(), Value::String(value.clone()));
    }
}

fn metadata_scalar(raw: &str) -> Value {
    match raw {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => {
            if let Ok(num) = raw.parse::<u64>() {
                return Value::from(num);
            }
            if let Ok(num) = raw.parse::<i64>() {
                return Value::from(num);
            }
            if let Ok(num) = raw.parse::<f64>() {
                return json!(num);
            }
            Value::String(raw.to_string())
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn count_stage_nodes(value: &Value) -> usize {
    match value {
        Value::Object(map) => map
            .values()
            .map(|child| {
                if child.is_object() {
                    1 + count_stage_nodes(child)
                } else {
                    0
                }
            })
            .sum(),
        _ => 0,
    }
}

fn sum_stage_durations_ms(value: &Value) -> f64 {
    match value {
        Value::Object(map) => {
            let own = map
                .get("duration_ms")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            own + map.values().map(sum_stage_durations_ms).sum::<f64>()
        }
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    use std::path::PathBuf;
    use std::sync::Mutex;
    use zkf_core::{BackendKind, FieldElement};
    use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeCompiler};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
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

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
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

    #[test]
    fn wrapper_trace_extracts_structured_fields() {
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v3".to_string());
        metadata.insert(
            "wrapper_strategy".to_string(),
            "nova-compressed-v3".to_string(),
        );
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        metadata.insert(
            "trust_model_description".to_string(),
            "host-verified compressed Nova accumulator".to_string(),
        );
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt+streamed-reduction".to_string(),
        );
        metadata.insert(
            "qap_witness_map_reason".to_string(),
            "bn254-witness-map-metal-ntt".to_string(),
        );
        metadata.insert("qap_witness_map_parallelism".to_string(), "8".to_string());
        metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            "none".to_string(),
        );
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert(
            "groth16_msm_reason".to_string(),
            "bn254-groth16-metal-msm".to_string(),
        );
        metadata.insert("groth16_msm_parallelism".to_string(), "4".to_string());
        metadata.insert("groth16_msm_fallback_state".to_string(), "none".to_string());
        metadata.insert("gpu_stage_busy_ratio".to_string(), "0.875".to_string());
        metadata.insert(
            "metal_stage_breakdown".to_string(),
            r#"{"plan":{"duration_ms":1.5},"prove":{"duration_ms":2.5,"nested":{"duration_ms":3.0}}}"#
                .to_string(),
        );
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![FieldElement::from_u64(1)],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let trace = build_artifact_runtime_trace(None, &artifact);
        assert_eq!(
            trace.get("wrapper_strategy"),
            Some(&Value::String("nova-compressed-v3".to_string()))
        );
        assert_eq!(
            trace.get("trust_model"),
            Some(&Value::String("attestation".to_string()))
        );
        assert_eq!(
            trace.get("qap_witness_map_engine"),
            Some(&Value::String(
                "metal-bn254-ntt+streamed-reduction".to_string()
            ))
        );
        assert_eq!(
            trace.get("qap_witness_map_reason"),
            Some(&Value::String("bn254-witness-map-metal-ntt".to_string()))
        );
        assert_eq!(
            trace.get("qap_witness_map_parallelism"),
            Some(&Value::from(8u64))
        );
        assert_eq!(
            trace.get("qap_witness_map_fallback_state"),
            Some(&Value::String("none".to_string()))
        );
        assert_eq!(
            trace.get("groth16_msm_engine"),
            Some(&Value::String("metal-bn254-msm".to_string()))
        );
        assert_eq!(
            trace.get("groth16_msm_reason"),
            Some(&Value::String("bn254-groth16-metal-msm".to_string()))
        );
        assert_eq!(
            trace.get("groth16_msm_parallelism"),
            Some(&Value::from(4u64))
        );
        assert_eq!(
            trace.get("groth16_msm_fallback_state"),
            Some(&Value::String("none".to_string()))
        );
        assert_eq!(trace.get("gpu_stage_busy_ratio"), Some(&json!(0.875)));
        assert_eq!(trace.get("stage_count"), Some(&Value::from(3u64)));
        assert_eq!(trace.get("stage_duration_ms"), Some(&json!(7.0)));
        assert!(trace.get("stage_breakdown").unwrap().is_object());
    }

    #[test]
    fn preview_trace_extracts_preview_fields() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v3".to_string(),
            strategy: "nova-compressed-v3".to_string(),
            trust_model: "attestation".to_string(),
            trust_model_description: Some("preview".to_string()),
            estimated_constraints: Some(1400),
            estimated_memory_bytes: Some(256 * 1024 * 1024),
            memory_budget_bytes: Some(4),
            low_memory_mode: Some(false),
            prepare_required: Some(true),
            setup_cache_state: Some("legacy-compressed".to_string()),
            reason: Some("test preview".to_string()),
        };

        let trace = build_wrapper_preview_trace(None, &preview);
        assert_eq!(
            trace.get("trace_schema"),
            Some(&Value::String("zkf-wrapper-preview-v1".to_string()))
        );
        assert_eq!(
            trace.get("wrapper_strategy"),
            Some(&Value::String("nova-compressed-v3".to_string()))
        );
        assert_eq!(
            trace.get("trust_model"),
            Some(&Value::String("attestation".to_string()))
        );
        assert_eq!(
            trace.get("umpg_estimated_constraints"),
            Some(&Value::from(1400u64))
        );
        assert_eq!(
            trace
                .get("runtime_plan")
                .and_then(|value| value.get("node_count")),
            Some(&Value::from(5u64))
        );
        assert_eq!(trace.get("prepare_required"), Some(&Value::Bool(true)));
        assert_eq!(
            trace.get("setup_cache_state"),
            Some(&Value::String("legacy-compressed".to_string()))
        );
    }

    #[test]
    fn prepare_report_includes_cache_fields() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(123),
            estimated_memory_bytes: Some(456),
            memory_budget_bytes: Some(789),
            low_memory_mode: Some(false),
            prepare_required: Some(false),
            setup_cache_state: Some("ready".to_string()),
            reason: Some("fits".to_string()),
        };
        let report = WrapperCachePrepareReport {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            setup_cache_ready: true,
            shape_cache_ready: Some(true),
            setup_cache_pk_format: Some("fast-uncompressed-v2".to_string()),
            setup_cache_pk_migrated: true,
            blocked: false,
            setup_cache_state: Some("ready".to_string()),
            blocked_reason: None,
            operator_action: None,
            detail: Some("migrated".to_string()),
        };
        let plan = json!({
            "plan_digest": "digest",
            "required_trust_lane": "strict-cryptographic",
            "trust_summary": {"trust_model": "cryptographic"},
            "lowering_report": {"backend": "plonky3"}
        });

        let out = build_wrapper_prepare_report(
            Path::new("/tmp/proof.json"),
            Path::new("/tmp/compiled.json"),
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::M4,
            &plan,
            &preview,
            &report,
        );

        assert_eq!(
            out.get("report_schema"),
            Some(&Value::String("zkf-runtime-wrapper-prepare-v1".to_string()))
        );
        assert_eq!(
            out.get("plan_digest"),
            Some(&Value::String("digest".to_string()))
        );
        assert_eq!(
            out.pointer("/cache_report/setup_cache_pk_format"),
            Some(&Value::String("fast-uncompressed-v2".to_string()))
        );
        assert_eq!(
            out.pointer("/cache_report/setup_cache_pk_migrated"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            out.pointer("/cache_report/setup_cache_state"),
            Some(&Value::String("ready".to_string()))
        );
        assert_eq!(
            out.pointer("/cache_report/blocked"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn prepare_report_includes_blocked_policy_fields() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(39_900_000),
            estimated_memory_bytes: Some(35_750_400_000),
            memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
            low_memory_mode: Some(false),
            prepare_required: Some(true),
            setup_cache_state: Some("fast-missing-shape".to_string()),
            reason: Some("blocked".to_string()),
        };
        let report = WrapperCachePrepareReport {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            setup_cache_ready: false,
            shape_cache_ready: Some(false),
            setup_cache_pk_format: Some("fast-uncompressed-v2".to_string()),
            setup_cache_pk_migrated: false,
            blocked: true,
            setup_cache_state: Some("fast-missing-shape".to_string()),
            blocked_reason: Some("unsafe by default".to_string()),
            operator_action: Some("rerun with override".to_string()),
            detail: Some("direct path".to_string()),
        };
        let plan = json!({
            "plan_digest": "digest",
            "required_trust_lane": "strict-cryptographic",
            "trust_summary": {"trust_model": "cryptographic"},
            "lowering_report": {"backend": "plonky3"}
        });

        let out = build_wrapper_prepare_report(
            Path::new("/tmp/proof.json"),
            Path::new("/tmp/compiled.json"),
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::M4,
            &plan,
            &preview,
            &report,
        );

        assert_eq!(
            out.pointer("/cache_report/blocked"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            out.pointer("/cache_report/blocked_reason"),
            Some(&Value::String("unsafe by default".to_string()))
        );
        assert_eq!(
            out.pointer("/cache_report/operator_action"),
            Some(&Value::String("rerun with override".to_string()))
        );
    }

    #[test]
    fn strict_certification_prepare_args_request_large_materialization() {
        let args = strict_certification_prepare_args(
            Path::new("/tmp/source-proof.json"),
            Path::new("/tmp/source-compiled.json"),
            Path::new("/tmp/prepare.json"),
        );

        assert!(
            args.iter()
                .any(|arg| arg == "--allow-large-direct-materialization")
        );
    }

    #[test]
    fn prepare_report_reuse_accepts_matching_live_ready_preview() {
        let live_preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(30_000_000),
            estimated_memory_bytes: Some(26_880_000_000),
            memory_budget_bytes: Some(36_977_885_184),
            low_memory_mode: Some(false),
            prepare_required: Some(false),
            setup_cache_state: Some("ready".to_string()),
            reason: Some("fits".to_string()),
        };
        let report = json!({
            "requested_trust_lane": "strict-cryptographic",
            "proof": "/tmp/source-proof.json",
            "compiled": "/tmp/source-compiled.json",
            "hardware_profile": "apple-silicon-m4-max-48gb",
            "cache_report": {
                "blocked": false
            },
            "wrapper_preview": serde_json::to_value(&live_preview).unwrap(),
        });

        assert!(prepare_report_reusable_with_live_preview(
            &report,
            Path::new("/tmp/source-proof.json"),
            Path::new("/tmp/source-compiled.json"),
            zkf_runtime::HardwareProfile::M4,
            &live_preview,
        ));
    }

    #[test]
    fn prepare_report_reuse_rejects_stale_missing_cache_preview() {
        let report_preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(30_000_000),
            estimated_memory_bytes: Some(26_880_000_000),
            memory_budget_bytes: Some(36_977_885_184),
            low_memory_mode: Some(false),
            prepare_required: Some(false),
            setup_cache_state: Some("ready".to_string()),
            reason: Some("fits".to_string()),
        };
        let live_preview = WrapperPreview {
            prepare_required: Some(true),
            setup_cache_state: Some("missing".to_string()),
            reason: Some("run `zkf runtime prepare` first".to_string()),
            ..report_preview.clone()
        };
        let report = json!({
            "requested_trust_lane": "strict-cryptographic",
            "proof": "/tmp/source-proof.json",
            "compiled": "/tmp/source-compiled.json",
            "hardware_profile": "apple-silicon-m4-max-48gb",
            "cache_report": {
                "blocked": false
            },
            "wrapper_preview": serde_json::to_value(&report_preview).unwrap(),
        });

        assert!(!prepare_report_reusable_with_live_preview(
            &report,
            Path::new("/tmp/source-proof.json"),
            Path::new("/tmp/source-compiled.json"),
            zkf_runtime::HardwareProfile::M4,
            &live_preview,
        ));
    }

    fn strict_wrap_runtime_host(
        total_gib: u64,
        available_gib: u64,
        pressure_level: zkf_core::PressureLevel,
    ) -> zkf_runtime::RuntimeHostSnapshot {
        let resources = zkf_core::SystemResources {
            total_ram_bytes: total_gib * 1024 * 1024 * 1024,
            available_ram_bytes: available_gib * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 12,
            unified_memory: true,
            gpu_memory_bytes: Some(total_gib * 1024 * 1024 * 1024),
            pressure: zkf_core::MemoryPressure {
                level: pressure_level,
                utilization_pct: 0.0,
                compressed_bytes: 0,
                swap_used_bytes: 0,
                raw_available_i64: (available_gib * 1024 * 1024 * 1024) as i64,
                compressor_overflow: false,
                free_bytes: 0,
                inactive_bytes: 0,
                purgeable_bytes: 0,
                wired_bytes: 0,
            },
        };
        let recommendation = resources.recommend();
        zkf_runtime::RuntimeHostSnapshot {
            resources,
            recommendation,
        }
    }

    fn strict_wrap_preview(
        estimated_constraints: u64,
        estimated_memory_gib: u64,
    ) -> WrapperPreview {
        WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(estimated_constraints),
            estimated_memory_bytes: Some(estimated_memory_gib * 1024 * 1024 * 1024),
            memory_budget_bytes: Some(36 * 1024 * 1024 * 1024),
            low_memory_mode: Some(false),
            prepare_required: Some(false),
            setup_cache_state: Some("ready".to_string()),
            reason: Some("fits".to_string()),
        }
    }

    fn strict_wrap_doctor(recommended_working_set_gib: u64, current_allocated_gib: u64) -> Value {
        json!({
            "runtime": {
                "recommended_working_set_size_bytes": recommended_working_set_gib * 1024_u64 * 1024 * 1024,
                "current_allocated_size_bytes": current_allocated_gib * 1024_u64 * 1024 * 1024,
            }
        })
    }

    #[test]
    fn strict_certification_admission_rejects_high_pressure_direct_wrap() {
        let host = strict_wrap_runtime_host(48, 12, zkf_core::PressureLevel::High);
        let preview = strict_wrap_preview(30_000_000, 27);
        let doctor = strict_wrap_doctor(40, 2);

        let failure =
            strict_certification_wrap_admission_failure_with_host(&host, &doctor, &preview, 1_024)
                .unwrap();

        assert!(failure.contains("pressure=HIGH"));
        assert!(failure.contains("projected_peak="));
        assert!(failure.contains("metal_headroom="));
    }

    #[test]
    fn strict_certification_admission_accepts_healthy_headroom() {
        let host = strict_wrap_runtime_host(48, 44, zkf_core::PressureLevel::Normal);
        let preview = strict_wrap_preview(30_000_000, 27);
        let doctor = strict_wrap_doctor(40, 2);

        let failure =
            strict_certification_wrap_admission_failure_with_host(&host, &doctor, &preview, 1_024);

        assert!(failure.is_none());
        let plan = strict_certification_wrap_memory_plan_with_host(&host, &doctor, &preview, 1_024);
        assert!(plan.gpu_allowed);
        assert!(!plan.cpu_override_active);
    }

    #[test]
    fn generic_plan_document_round_trips_into_graph() {
        let graph = RuntimeCompiler::build_plan(
            1024,
            "bn254_fr",
            "groth16",
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .unwrap();
        let plan = build_generic_plan_document(
            "groth16",
            1024,
            "bn254_fr",
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::CpuOnly,
            None,
            None,
            None,
            &graph,
        )
        .unwrap();

        assert_eq!(
            plan.get("plan_schema"),
            Some(&Value::String(PLAN_SCHEMA_V2.to_string()))
        );
        assert_eq!(
            plan.get("plan_kind"),
            Some(&Value::String("generic".to_string()))
        );
        assert_eq!(
            plan.get("required_trust_lane"),
            Some(&Value::String("strict-cryptographic".to_string()))
        );
        assert_eq!(
            plan.pointer("/runtime_plan/node_count"),
            Some(&Value::from(graph.node_count() as u64))
        );
        assert_eq!(
            plan.pointer("/runtime_plan/graph/node_count"),
            Some(&Value::from(graph.node_count() as u64))
        );
        assert!(
            plan.pointer("/runtime_plan/buffers/items")
                .and_then(Value::as_array)
                .is_some()
        );
        assert!(
            plan.pointer("/runtime_plan/placement/nodes")
                .and_then(Value::as_array)
                .is_some()
        );

        let rebuilt = build_graph_from_plan_document(&plan).unwrap();
        assert_eq!(rebuilt.node_count(), graph.node_count());
        assert_eq!(plan.get("execution_ready"), Some(&Value::Bool(false)));
    }

    #[test]
    fn generic_plan_document_with_bound_program_and_inputs_builds_execution_context() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-generic-plan-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let program_path = temp_root.join("program.json");
        let inputs_path = temp_root.join("inputs.json");

        let program = zkf_examples::mul_add_program();
        let inputs: WitnessInputs = BTreeMap::from([
            ("x".to_string(), FieldElement::from_u64(7)),
            ("y".to_string(), FieldElement::from_u64(5)),
        ]);
        crate::util::write_json(&program_path, &program).unwrap();
        crate::util::write_json(&inputs_path, &inputs).unwrap();

        let graph = RuntimeCompiler::build_plan(
            program.constraints.len(),
            "bn254_fr",
            "groth16",
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .unwrap();
        let bindings = build_generic_plan_bindings_from_inputs(
            Some(&program_path),
            Some(&inputs_path),
            &program,
            &inputs,
        )
        .unwrap();
        let plan = build_generic_plan_document(
            "groth16",
            program.constraints.len(),
            "bn254_fr",
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::CpuOnly,
            Some(&program_path),
            Some(&inputs_path),
            Some(&bindings),
            &graph,
        )
        .unwrap();

        let emission = build_generic_emission_from_plan_document(&plan).unwrap();
        assert_eq!(emission.graph.node_count(), graph.node_count());
        assert!(emission.exec_ctx.program.is_some());
        assert!(emission.exec_ctx.witness_inputs.is_some());
        assert_eq!(plan.get("execution_ready"), Some(&Value::Bool(true)));
    }

    #[test]
    fn generic_plan_document_rejects_input_drift() {
        let temp_root = std::env::temp_dir().join(format!(
            "zkf-runtime-generic-bindings-{}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_root).unwrap();
        let program_path = temp_root.join("program.json");
        let inputs_path = temp_root.join("inputs.json");

        let program = zkf_examples::mul_add_program();
        let inputs: WitnessInputs = BTreeMap::from([
            ("x".to_string(), FieldElement::from_u64(7)),
            ("y".to_string(), FieldElement::from_u64(5)),
        ]);
        crate::util::write_json(&program_path, &program).unwrap();
        crate::util::write_json(&inputs_path, &inputs).unwrap();

        let graph = RuntimeCompiler::build_plan(
            program.constraints.len(),
            "bn254_fr",
            "groth16",
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .unwrap();
        let bindings = build_generic_plan_bindings_from_inputs(
            Some(&program_path),
            Some(&inputs_path),
            &program,
            &inputs,
        )
        .unwrap();
        let plan = build_generic_plan_document(
            "groth16",
            program.constraints.len(),
            "bn254_fr",
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::CpuOnly,
            Some(&program_path),
            Some(&inputs_path),
            Some(&bindings),
            &graph,
        )
        .unwrap();

        let modified_inputs: WitnessInputs = BTreeMap::from([
            ("x".to_string(), FieldElement::from_u64(9)),
            ("y".to_string(), FieldElement::from_u64(5)),
        ]);
        crate::util::write_json(&inputs_path, &modified_inputs).unwrap();

        let err = match build_generic_emission_from_plan_document(&plan) {
            Ok(_) => panic!("expected generic plan input drift to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("inputs hash mismatch"));
    }

    #[test]
    fn generic_plan_without_bound_inputs_is_not_execution_ready() {
        let graph = RuntimeCompiler::build_plan(
            1024,
            "bn254_fr",
            "groth16",
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .unwrap();
        let plan = build_generic_plan_document(
            "groth16",
            1024,
            "bn254_fr",
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::CpuOnly,
            None,
            None,
            None,
            &graph,
        )
        .unwrap();

        let err = match build_generic_emission_from_plan_document(&plan) {
            Ok(_) => panic!("expected shape-only generic plan to be rejected for execution"),
            Err(err) => err,
        };
        assert!(err.contains("not execution-ready"));
    }

    #[test]
    fn cli_trust_lane_rejects_metadata_mode() {
        let err = parse_cli_trust_lane(Some("allow-metadata")).unwrap_err();
        assert!(err.contains("strict-cryptographic"));
        assert!(err.contains("allow-attestation"));
    }

    #[test]
    fn certified_profile_requires_metal_gpu_for_strict_wraps() {
        let result = enforce_certified_build_support(
            zkf_runtime::HardwareProfile::M4,
            RequiredTrustLane::StrictCryptographic,
        );

        if cfg!(all(target_os = "macos", feature = "metal-gpu")) {
            assert!(result.is_ok());
        } else {
            let err = result.unwrap_err();
            assert!(err.contains("--features metal-gpu"));
        }
    }

    #[test]
    fn wrapper_plan_document_round_trips_into_graph() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v3".to_string(),
            strategy: "nova-compressed-v3".to_string(),
            trust_model: "attestation".to_string(),
            trust_model_description: Some("preview".to_string()),
            estimated_constraints: Some(1400),
            estimated_memory_bytes: Some(256 * 1024 * 1024),
            memory_budget_bytes: Some(4 * 1024 * 1024 * 1024),
            low_memory_mode: Some(true),
            prepare_required: None,
            setup_cache_state: None,
            reason: Some("test preview".to_string()),
        };
        let graph =
            RuntimeCompiler::build_wrapper_plan(&preview, ExecutionMode::Deterministic).unwrap();
        let bindings = WrapperPlanBindings {
            proof_sha256: "proof".to_string(),
            compiled_sha256: "compiled".to_string(),
            source_backend: "plonky3".to_string(),
            source_program_digest: "digest".to_string(),
            compiled_backend: "plonky3".to_string(),
            compiled_program_digest: "digest".to_string(),
        };
        let plan = build_wrapper_plan_document(
            Some(Path::new("/tmp/source-proof.json")),
            Some(Path::new("/tmp/source-compiled.json")),
            RequiredTrustLane::AllowAttestation,
            zkf_runtime::HardwareProfile::CpuOnly,
            &preview,
            &bindings,
            &graph,
        )
        .unwrap();

        assert_eq!(
            plan.get("plan_kind"),
            Some(&Value::String("wrapper".to_string()))
        );
        assert_eq!(
            plan.get("required_trust_lane"),
            Some(&Value::String("allow-attestation".to_string()))
        );
        assert_eq!(
            plan.pointer("/runtime_plan/node_count"),
            Some(&Value::from(graph.node_count() as u64))
        );
        assert_eq!(
            plan.pointer("/runtime_plan/graph/node_count"),
            Some(&Value::from(graph.node_count() as u64))
        );
        assert!(
            plan.pointer("/runtime_plan/buffers/items")
                .and_then(Value::as_array)
                .is_some()
        );
        assert!(
            plan.pointer("/runtime_plan/placement/nodes")
                .and_then(Value::as_array)
                .is_some()
        );
        assert_eq!(
            plan.pointer("/wrapper_preview/strategy"),
            Some(&Value::String("nova-compressed-v3".to_string()))
        );
        assert_eq!(
            plan.pointer("/input_bindings/source_backend"),
            Some(&Value::String("plonky3".to_string()))
        );

        let rebuilt = build_graph_from_plan_document(&plan).unwrap();
        assert_eq!(rebuilt.node_count(), graph.node_count());
    }

    #[test]
    fn wrapper_plan_document_rejects_strict_lane_for_attestation_preview() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v3".to_string(),
            strategy: "nova-compressed-v3".to_string(),
            trust_model: "attestation".to_string(),
            trust_model_description: Some("preview".to_string()),
            estimated_constraints: Some(1400),
            estimated_memory_bytes: Some(256 * 1024 * 1024),
            memory_budget_bytes: Some(4 * 1024 * 1024 * 1024),
            low_memory_mode: Some(true),
            prepare_required: None,
            setup_cache_state: None,
            reason: Some("test preview".to_string()),
        };
        let graph =
            RuntimeCompiler::build_wrapper_plan(&preview, ExecutionMode::Deterministic).unwrap();
        let bindings = WrapperPlanBindings {
            proof_sha256: "proof".to_string(),
            compiled_sha256: "compiled".to_string(),
            source_backend: "plonky3".to_string(),
            source_program_digest: "digest".to_string(),
            compiled_backend: "plonky3".to_string(),
            compiled_program_digest: "digest".to_string(),
        };
        let plan = build_wrapper_plan_document(
            Some(Path::new("/tmp/source-proof.json")),
            Some(Path::new("/tmp/source-compiled.json")),
            RequiredTrustLane::StrictCryptographic,
            zkf_runtime::HardwareProfile::CpuOnly,
            &preview,
            &bindings,
            &graph,
        )
        .unwrap();

        let err = match build_graph_from_plan_document(&plan) {
            Ok(_) => panic!("expected strict trust lane to reject attestation wrapper plan"),
            Err(err) => err,
        };
        assert!(err.contains("allow-attestation"));
    }

    #[test]
    fn wrapper_execution_trace_merges_runtime_and_artifact_fields() {
        let plan = json!({
            "plan_schema": PLAN_SCHEMA_V2,
            "plan_kind": "wrapper",
            "proof": "/tmp/source-proof.json",
            "compiled": "/tmp/source-compiled.json",
            "trust_lane": "allow-attestation",
            "hardware_profile": "cpu-only",
            "runtime_plan": {
                "node_count": 6,
                "ops": ["WitnessSolve", "ProofEncode"],
                "buffers": {
                    "count": 1,
                    "items": [
                        {
                            "slot": 1,
                            "size_bytes": 4096,
                            "class": "spill",
                            "producer_node_ids": [1],
                            "consumer_node_ids": [2]
                        }
                    ]
                }
            }
        });
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v3".to_string());
        metadata.insert(
            "wrapper_strategy".to_string(),
            "nova-compressed-v3".to_string(),
        );
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        metadata.insert(
            "metal_stage_breakdown".to_string(),
            r#"{"plan":{"duration_ms":4.0},"prove":{"duration_ms":6.0}}"#.to_string(),
        );
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![FieldElement::from_u64(1)],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let trace = build_wrapper_execution_trace(
            &plan,
            Some(Path::new("/tmp/wrapped-proof.json")),
            Some(Path::new("/tmp/wrapped-trace.json")),
            &artifact,
            12.5,
        );

        assert_eq!(
            trace.get("trace_schema"),
            Some(&Value::String(
                "zkf-runtime-wrapper-execution-v1".to_string()
            ))
        );
        assert_eq!(
            trace.get("proof"),
            Some(&Value::String("/tmp/wrapped-proof.json".to_string()))
        );
        assert_eq!(
            trace.get("source_proof"),
            Some(&Value::String("/tmp/source-proof.json".to_string()))
        );
        assert_eq!(
            trace.get("requested_trust_lane"),
            Some(&Value::String("allow-attestation".to_string()))
        );
        assert_eq!(trace.get("stage_duration_ms"), Some(&json!(10.0)));
        assert_eq!(
            trace.get("runtime_execution_duration_ms"),
            Some(&json!(12.5))
        );
        assert_eq!(
            trace.pointer("/runtime_plan/node_count"),
            Some(&Value::from(6u64))
        );
        assert_eq!(
            trace.pointer("/buffer_lineage/count"),
            Some(&Value::from(1u64))
        );
        assert_eq!(
            trace.get("input_bindings_verified"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn wrapper_execution_trace_rewrites_cache_hit_stage_timing() {
        let plan = json!({
            "plan_schema": PLAN_SCHEMA_V2,
            "plan_kind": "wrapper",
            "trust_lane": "strict-cryptographic",
        });
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("wrapper_strategy".to_string(), "direct-fri-v2".to_string());
        metadata.insert("trust_model".to_string(), "cryptographic".to_string());
        metadata.insert("wrapper_cache_hit".to_string(), "true".to_string());
        metadata.insert("wrapper_cache_source".to_string(), "disk".to_string());
        metadata.insert(
            "metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert("metal_dispatch_last_failure".to_string(), "".to_string());
        metadata.insert(
            "target_groth16_metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_dispatch_last_failure".to_string(),
            "".to_string(),
        );
        metadata.insert(
            "metal_stage_breakdown".to_string(),
            r#"{"prove":{"duration_ms":200.0}}"#.to_string(),
        );
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let trace = build_wrapper_execution_trace(&plan, None, None, &artifact, 3.5);

        assert_eq!(trace.get("stage_duration_ms"), Some(&json!(3.5)));
        assert_eq!(trace.get("artifact_stage_duration_ms"), Some(&json!(200.0)));
        assert_eq!(
            trace.get("runtime_execution_duration_ms"),
            Some(&json!(3.5))
        );
        assert_eq!(trace.get("stage_count"), Some(&json!(1)));
        assert_eq!(trace.get("artifact_stage_count"), Some(&json!(1)));
        assert_eq!(
            trace.get("metal_dispatch_circuit_open"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            trace.get("target_groth16_metal_dispatch_circuit_open"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            trace.pointer("/stage_breakdown/artifact_cache/fallback_reason"),
            Some(&Value::String("wrapper-cache-disk".to_string()))
        );
        assert_eq!(
            trace.pointer("/artifact_stage_breakdown/prove/duration_ms"),
            Some(&json!(200.0))
        );
    }

    #[test]
    fn wrapper_execution_trace_with_runtime_result_includes_scheduler_telemetry() {
        let plan = json!({
            "plan_schema": PLAN_SCHEMA_V2,
            "plan_kind": "wrapper",
            "trust_lane": "allow-attestation",
        });
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v3".to_string());
        metadata.insert(
            "wrapper_strategy".to_string(),
            "nova-compressed-v3".to_string(),
        );
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![1, 2, 3],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        let result = zkf_runtime::PlanExecutionResult {
            report: zkf_runtime::GraphExecutionReport {
                node_traces: vec![zkf_runtime::NodeTrace {
                    node_id: zkf_runtime::NodeId::new(),
                    op_name: "OuterProve",
                    stage_key: "outer-prove".to_string(),
                    placement: zkf_runtime::DevicePlacement::Cpu,
                    trust_model: zkf_runtime::TrustModel::Attestation,
                    wall_time: std::time::Duration::from_millis(25),
                    problem_size: Some(1),
                    input_bytes: 64,
                    output_bytes: 128,
                    predicted_cpu_ms: Some(25.0),
                    predicted_gpu_ms: Some(40.0),
                    prediction_confidence: Some(0.96),
                    prediction_observation_count: Some(48),
                    input_digest: [0x11; 8],
                    output_digest: [0x22; 8],
                    allocated_bytes_after: 1024,
                    accelerator_name: Some("OuterProve-groth16".to_string()),
                    fell_back: false,
                    buffer_residency: Some("shared-metal".to_string()),
                    delegated: false,
                    delegated_backend: None,
                }],
                total_wall_time: std::time::Duration::from_millis(25),
                peak_memory_bytes: 4096,
                gpu_nodes: 0,
                cpu_nodes: 1,
                delegated_nodes: 0,
                final_trust_model: zkf_runtime::TrustModel::Attestation,
                fallback_nodes: 0,
                watchdog_alerts: Vec::new(),
            },
            outputs: Value::Null,
            control_plane: Some(zkf_runtime::ControlPlaneExecutionSummary {
                decision: zkf_runtime::ControlPlaneDecision {
                    job_kind: zkf_runtime::JobKind::Wrap,
                    features: zkf_runtime::ControlPlaneFeatures {
                        feature_schema: "zkf-neural-control-plane-v2".to_string(),
                        job_kind: zkf_runtime::JobKind::Wrap,
                        objective: zkf_runtime::OptimizationObjective::FastestProve,
                        circuit: zkf_runtime::CircuitFeatureProfile {
                            constraint_count: 2048,
                            signal_count: 512,
                            blackbox_op_distribution: BTreeMap::new(),
                            max_constraint_degree: 2,
                            witness_size: 256,
                        },
                        stage_node_counts: BTreeMap::from([("ntt".to_string(), 2usize)]),
                        gpu_capable_stage_counts: BTreeMap::from([("ntt".to_string(), 2usize)]),
                        hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
                        chip_family: "m4".to_string(),
                        form_factor: "laptop".to_string(),
                        gpu_core_count: Some(40),
                        ane_tops: Some(38.0),
                        metal_available: true,
                        unified_memory: true,
                        ram_utilization: 0.41,
                        memory_pressure_ratio: 0.18,
                        battery_present: true,
                        on_external_power: true,
                        low_power_mode: false,
                        power_mode: "automatic".to_string(),
                        thermal_pressure: Some(0.12),
                        thermal_state_celsius: Some(50.0),
                        cpu_speed_limit: Some(0.97),
                        core_frequency_mhz: Some(4040),
                        requested_backend: None,
                        backend_route: Some("native-auto".to_string()),
                        requested_jobs: 2,
                        total_jobs: 4,
                    },
                    dispatch_plan: zkf_runtime::DispatchPlan::from_candidate(
                        zkf_runtime::DispatchCandidate::Balanced,
                    ),
                    candidate_rankings: vec![zkf_runtime::DispatchCandidateScore {
                        candidate: zkf_runtime::DispatchCandidate::Balanced,
                        predicted_duration_ms: 32.0,
                        source: "model-or-heuristic".to_string(),
                    }],
                    backend_recommendation: zkf_runtime::BackendRecommendation {
                        selected: BackendKind::ArkworksGroth16,
                        objective: zkf_runtime::OptimizationObjective::FastestProve,
                        source: "model".to_string(),
                        rankings: vec![],
                        notes: vec![],
                    },
                    duration_estimate: zkf_runtime::DurationEstimate {
                        estimate_ms: 32.0,
                        upper_bound_ms: Some(38.4),
                        predicted_wall_time_ms: 32.0,
                        source: "model".to_string(),
                        execution_regime: zkf_runtime::ExecutionRegime::PartialFallback,
                        eta_semantics: zkf_runtime::EtaSemantics::ModelEstimate,
                        bound_source: zkf_runtime::BoundSource::ModelDerived,
                        countdown_safe: true,
                        note: Some(
                            "Dispatch mixes GPU-capable and CPU stages; use the conservative upper bound for operator planning"
                                .to_string(),
                        ),
                        backend: Some(BackendKind::ArkworksGroth16),
                        dispatch_candidate: Some(zkf_runtime::DispatchCandidate::Balanced),
                    },
                    anomaly_baseline: zkf_runtime::AnomalyVerdict {
                        severity: zkf_runtime::AnomalySeverity::Normal,
                        source: "model".to_string(),
                        reason: "baseline".to_string(),
                        predicted_anomaly_score: Some(1.2),
                        advisory_estimate_ms: Some(32.0),
                        conservative_upper_bound_ms: Some(38.4),
                        execution_regime: Some(zkf_runtime::ExecutionRegime::PartialFallback),
                        eta_semantics: Some(zkf_runtime::EtaSemantics::ModelEstimate),
                        bound_source: Some(zkf_runtime::BoundSource::ModelDerived),
                        duration_interpretation: None,
                        expected_duration_ms: Some(32.0),
                        expected_duration_ratio_limit: Some(1.2),
                        observed_duration_ms: None,
                        duration_ratio: None,
                        expected_proof_size_bytes: Some(128),
                        expected_proof_size_ratio_limit: Some(1.2),
                        observed_proof_size_bytes: None,
                        proof_size_ratio: None,
                    },
                    model_catalog: zkf_runtime::ModelCatalog {
                        scheduler: Some(zkf_runtime::ModelDescriptor {
                            lane: zkf_runtime::ModelLane::Scheduler,
                            path: "/tmp/scheduler_v1.mlpackage".to_string(),
                            source: zkf_runtime::ModelSource::RepoLocal,
                            version: Some("v1".to_string()),
                            schema_fingerprint: Some("fixture".to_string()),
                            input_shape: Some(47),
                            output_name: Some("predicted_duration_ms".to_string()),
                            quality_gate: Some(zkf_runtime::ModelQualityGate {
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
                anomaly_verdict: zkf_runtime::AnomalyVerdict {
                    severity: zkf_runtime::AnomalySeverity::Normal,
                    source: "model".to_string(),
                    reason: "within baseline".to_string(),
                    predicted_anomaly_score: Some(1.2),
                    advisory_estimate_ms: Some(32.0),
                    conservative_upper_bound_ms: Some(38.4),
                    execution_regime: Some(zkf_runtime::ExecutionRegime::PartialFallback),
                    eta_semantics: Some(zkf_runtime::EtaSemantics::ModelEstimate),
                    bound_source: Some(zkf_runtime::BoundSource::ModelDerived),
                    duration_interpretation: Some("within-advisory-estimate".to_string()),
                    expected_duration_ms: Some(32.0),
                    expected_duration_ratio_limit: Some(1.2),
                    observed_duration_ms: Some(25.0),
                    duration_ratio: Some(0.78125),
                    expected_proof_size_bytes: Some(128),
                    expected_proof_size_ratio_limit: Some(1.2),
                    observed_proof_size_bytes: Some(128),
                    proof_size_ratio: Some(1.0),
                },
                realized_gpu_capable_stages: vec!["ntt".to_string()],
                proof_size_bytes: Some(128),
            }),
            security: None,
            model_integrity: None,
            swarm: None,
        };

        let trace = build_wrapper_execution_trace_with_runtime_result(
            &plan, None, None, &artifact, 12.5, &result,
        );

        assert_eq!(trace.get("node_count"), Some(&Value::from(1u64)));
        assert_eq!(trace.get("cpu_nodes"), Some(&Value::from(1u64)));
        assert_eq!(trace.get("delegated_nodes"), Some(&Value::from(0u64)));
        assert_eq!(trace.get("peak_memory_bytes"), Some(&Value::from(4096u64)));
        assert_eq!(trace.get("runtime_gpu_stage_busy_ratio"), Some(&json!(0.0)));
        assert_eq!(
            trace.get("runtime_metal_counter_source"),
            Some(&Value::String("runtime-node-trace-v1".to_string()))
        );
        assert_eq!(trace.get("runtime_stage_count"), Some(&Value::from(1u64)));
        assert_eq!(trace.get("runtime_stage_duration_ms"), Some(&json!(25.0)));
        assert_eq!(
            trace.pointer("/runtime_stage_breakdown/outer-prove/duration_ms"),
            Some(&json!(25.0))
        );
        assert_eq!(
            trace.pointer("/node_traces/0/accelerator_name"),
            Some(&Value::String("OuterProve-groth16".to_string()))
        );
        assert_eq!(
            trace.pointer("/node_traces/0/buffer_residency"),
            Some(&Value::String("shared-metal".to_string()))
        );
        assert_eq!(
            trace.pointer("/node_traces/0/delegated"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            trace.pointer("/node_traces/0/delegated_backend"),
            Some(&Value::Null)
        );
        assert_eq!(
            trace.pointer("/model_catalog/scheduler/version"),
            Some(&Value::String("v1".to_string()))
        );
        assert_eq!(
            trace.pointer("/duration_estimate/source"),
            Some(&Value::String("model".to_string()))
        );
        assert_eq!(
            trace.pointer("/anomaly_verdict/source"),
            Some(&Value::String("model".to_string()))
        );
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn runtime_policy_report_uses_fixture_models_when_installed() {
        with_fixture_models_env(|| {
            let report = build_runtime_policy_report(
                None,
                Some("goldilocks".to_string()),
                Some("plonky3,arkworks-groth16".to_string()),
                "fastest-prove".to_string(),
                Some(16384),
                Some(4096),
                Some(4),
                Some(8),
                None,
                "cpu-and-neural-engine".to_string(),
            )
            .expect("runtime policy report");

            assert_eq!(report.job_kind, "prove");
            assert!(report.model_catalog.scheduler.is_some());
            assert!(report.model_catalog.backend.is_some());
            assert!(report.model_catalog.duration.is_some());
            assert!(report.model_catalog.anomaly.is_some());
            assert_eq!(report.backend_recommendation.source, "model");
            assert_eq!(report.duration_estimate.source, "model");
            assert_eq!(report.anomaly_baseline.source, "model");
            assert_eq!(
                report.objective,
                zkf_runtime::OptimizationObjective::FastestProve
            );
            assert_eq!(
                report
                    .model_catalog
                    .scheduler
                    .as_ref()
                    .and_then(|descriptor| descriptor.quality_gate.as_ref())
                    .map(|gate| gate.passed),
                Some(true)
            );
            assert_eq!(
                report.model.as_ref().map(|model| model.runner.as_str()),
                Some("zkf-runtime-native")
            );
        });
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn runtime_policy_report_filters_invalid_model_choice_and_records_note() {
        with_fixture_models_env(|| {
            let report = build_runtime_policy_report(
                None,
                Some("goldilocks".to_string()),
                Some("arkworks-groth16,plonky3".to_string()),
                "smallest-proof".to_string(),
                Some(4096),
                Some(1024),
                Some(2),
                Some(4),
                None,
                "cpu-and-neural-engine".to_string(),
            )
            .expect("runtime policy report");

            assert_eq!(report.backend_recommendation.source, "model");
            assert_eq!(report.backend_recommendation.selected, BackendKind::Plonky3);
            assert!(report.backend_recommendation.notes.iter().any(|note| {
                note.contains("filtered model-preferred backend 'arkworks-groth16'")
            }));
            assert!(report.notes.iter().any(|note| {
                note.contains("filtered model-preferred backend 'arkworks-groth16'")
            }));
        });
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn runtime_policy_report_no_trusted_setup_prefers_transparent_backend() {
        with_fixture_models_env(|| {
            let report = build_runtime_policy_report(
                None,
                Some("goldilocks".to_string()),
                Some("arkworks-groth16,plonky3".to_string()),
                "no-trusted-setup".to_string(),
                Some(4096),
                Some(1024),
                Some(2),
                Some(4),
                None,
                "cpu-and-neural-engine".to_string(),
            )
            .expect("runtime policy report");

            assert_eq!(report.backend_recommendation.source, "model");
            assert_eq!(report.backend_recommendation.selected, BackendKind::Plonky3);
            assert!(report.backend_recommendation.notes.iter().any(|note| {
                note.contains("arkworks-groth16") && note.contains("filtered backend")
            }));
        });
    }

    #[test]
    fn wrapper_plan_metadata_no_longer_claims_delegated_outer_prove() {
        let preview = WrapperPreview {
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

        let trust_summary = build_wrapper_trust_summary(&preview);
        let lowering_report = build_wrapper_lowering_report(&preview);

        assert_eq!(
            trust_summary.get("contains_delegated_nodes"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            lowering_report.get("delegated_features"),
            Some(&Value::Array(vec![]))
        );
    }

    #[test]
    #[ignore = "expensive native wrapper smoke"]
    fn runtime_execute_native_wrapper_plan_end_to_end() {
        zkf_backends::init_accelerators();
        zkf_backends::harden_accelerators_for_current_pressure();

        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let proof = workspace_root.join("proof-plonky3.json");
        let compiled = workspace_root.join("compiled-plonky3.json");
        assert!(proof.exists(), "missing fixture: {}", proof.display());
        assert!(compiled.exists(), "missing fixture: {}", compiled.display());

        let out_dir = std::env::temp_dir().join(format!(
            "zkf-runtime-native-wrapper-smoke-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&out_dir).expect("create output dir");
        let plan_path = out_dir.join("plan.json");
        let proof_out = out_dir.join("wrapped.json");
        let trace_out = out_dir.join("trace.json");

        handle_plan(
            None,
            None,
            None,
            None,
            None,
            Some("allow-attestation".to_string()),
            None,
            Some(proof.clone()),
            Some(compiled.clone()),
            Some(plan_path.clone()),
        )
        .expect("plan wrapper job");

        handle_execute(
            Some(plan_path.clone()),
            None,
            None,
            None,
            None,
            Some(proof_out.clone()),
            None,
            None,
            None,
            None,
            Some(trace_out.clone()),
        )
        .expect("execute wrapper job");

        let trace: Value = read_json_path(&trace_out).expect("read trace");
        let artifact: ProofArtifact = read_json_path(&proof_out).expect("read artifact");
        assert_eq!(trace.get("delegated_nodes"), Some(&Value::from(0u64)));
        assert!(
            trace.get("node_count").and_then(Value::as_u64).unwrap_or(0) >= 5,
            "unexpected node count in trace: {trace}"
        );
        assert_eq!(
            artifact
                .metadata
                .get("runtime_plan_schema")
                .map(String::as_str),
            Some(PLAN_SCHEMA_V2)
        );
    }

    #[test]
    fn annotate_wrapper_runtime_metadata_stamps_provenance() {
        let plan = json!({
            "plan_schema": PLAN_SCHEMA_V2,
            "plan_kind": "wrapper",
            "trust_lane": "allow-attestation",
            "hardware_profile": "cpu-only",
        });
        let bindings = WrapperPlanBindings {
            proof_sha256: "proof-sha".to_string(),
            compiled_sha256: "compiled-sha".to_string(),
            source_backend: "plonky3".to_string(),
            source_program_digest: "prog-digest".to_string(),
            compiled_backend: "plonky3".to_string(),
            compiled_program_digest: "compiled-digest".to_string(),
        };
        let mut artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        annotate_wrapper_runtime_metadata(
            &mut artifact,
            &plan,
            &bindings,
            Some(Path::new("/tmp/wrapped-proof.json")),
        )
        .unwrap();

        assert_eq!(
            artifact.metadata.get("runtime_plan_kind"),
            Some(&"wrapper".to_string())
        );
        assert_eq!(
            artifact.metadata.get("runtime_requested_trust_lane"),
            Some(&"allow-attestation".to_string())
        );
        assert_eq!(
            artifact.metadata.get("runtime_required_trust_lane"),
            Some(&"allow-attestation".to_string())
        );
        assert_eq!(
            artifact.metadata.get("runtime_hardware_profile"),
            Some(&"cpu-only".to_string())
        );
        assert_eq!(
            artifact.metadata.get("runtime_source_proof_sha256"),
            Some(&"proof-sha".to_string())
        );
        assert_eq!(
            artifact.metadata.get("runtime_input_bindings_verified"),
            Some(&"true".to_string())
        );
        assert!(artifact.metadata.contains_key("runtime_plan_sha256"));
    }

    #[test]
    fn artifact_trust_lane_rejects_attestation_under_strict() {
        let mut metadata = BTreeMap::new();
        metadata.insert("trust_model".to_string(), "attestation".to_string());
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![FieldElement::from_u64(1)],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let err = enforce_artifact_trust_lane(&artifact, RequiredTrustLane::StrictCryptographic)
            .unwrap_err();
        assert!(err.contains("allow-attestation"));
    }

    #[test]
    fn wrapper_plan_bindings_detect_source_file_drift() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-bindings-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let proof_path = temp_root.join("proof.json");
        let compiled_path = temp_root.join("compiled.json");

        let proof = ProofArtifact {
            backend: BackendKind::Plonky3,
            program_digest: "digest".to_string(),
            proof: vec![1, 2, 3],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        let compiled = CompiledProgram::new(BackendKind::Plonky3, zkf_examples::mul_add_program());
        crate::util::write_json(&proof_path, &proof).unwrap();
        crate::util::write_json(&compiled_path, &compiled).unwrap();
        let bindings = build_wrapper_plan_bindings_from_inputs(
            Some(&proof_path),
            Some(&compiled_path),
            &proof,
            &compiled,
        )
        .unwrap();

        crate::util::write_json(
            &proof_path,
            &ProofArtifact {
                proof: vec![9, 9, 9],
                ..proof.clone()
            },
        )
        .unwrap();

        let plan = json!({
            "input_bindings": bindings,
        });
        let current_proof: ProofArtifact = read_json_path(&proof_path).unwrap();
        let current_compiled: CompiledProgram = read_json_path(&compiled_path).unwrap();
        let err = validate_wrapper_plan_bindings(
            &plan,
            &proof_path,
            &compiled_path,
            &current_proof,
            &current_compiled,
        )
        .unwrap_err();
        assert!(err.contains("proof hash mismatch"));
    }

    #[test]
    fn wrapper_preview_plan_match_ignores_budget_and_reason_drift() {
        let expected = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v3".to_string(),
            strategy: "nova-compressed-v3".to_string(),
            trust_model: "attestation".to_string(),
            trust_model_description: Some("old description".to_string()),
            estimated_constraints: Some(1400),
            estimated_memory_bytes: Some(256 * 1024 * 1024),
            memory_budget_bytes: Some(4 * 1024 * 1024 * 1024),
            low_memory_mode: Some(true),
            prepare_required: Some(true),
            setup_cache_state: Some("legacy-compressed".to_string()),
            reason: Some("old reason".to_string()),
        };
        let actual = WrapperPreview {
            trust_model_description: Some("new description".to_string()),
            estimated_memory_bytes: Some(512 * 1024 * 1024),
            memory_budget_bytes: Some(8 * 1024 * 1024 * 1024),
            prepare_required: Some(false),
            setup_cache_state: Some("ready".to_string()),
            reason: Some("new reason".to_string()),
            ..expected.clone()
        };

        assert!(wrapper_preview_matches_plan(&expected, &actual));
    }

    #[test]
    fn prepare_required_preview_fails_closed() {
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(39_900_000),
            estimated_memory_bytes: Some(35_750_400_000),
            memory_budget_bytes: Some(38_654_705_664),
            low_memory_mode: Some(false),
            prepare_required: Some(true),
            setup_cache_state: Some("fast-missing-shape".to_string()),
            reason: Some("run `zkf runtime prepare` first".to_string()),
        };

        let err = enforce_prepare_ready_preview(&preview).unwrap_err();
        assert!(err.contains("zkf runtime prepare"));
    }

    #[test]
    fn prepare_required_preview_writes_preview_trace() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-prepare-trace-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let trace_path = temp_root.join("preview-trace.json");
        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: Some("strict".to_string()),
            estimated_constraints: Some(39_900_000),
            estimated_memory_bytes: Some(35_750_400_000),
            memory_budget_bytes: Some(38_654_705_664),
            low_memory_mode: Some(false),
            prepare_required: Some(true),
            setup_cache_state: Some("fast-missing-shape".to_string()),
            reason: Some("run `zkf runtime prepare` first".to_string()),
        };
        let plan = json!({
            "plan_schema": PLAN_SCHEMA_V2,
            "plan_kind": "wrapper",
            "proof": "/tmp/source-proof.json",
            "hardware_profile": "apple-silicon-m4-max-48gb",
            "plan_digest": "digest",
        });

        emit_prepare_required_trace(&plan, None, &preview, &trace_path).unwrap();

        let trace: Value = read_json_path(&trace_path).unwrap();
        assert_eq!(
            trace.get("trace_schema"),
            Some(&Value::String("zkf-wrapper-preview-v1".to_string()))
        );
        assert_eq!(trace.get("prepare_required"), Some(&Value::Bool(true)));
        assert_eq!(
            trace.get("setup_cache_state"),
            Some(&Value::String("fast-missing-shape".to_string()))
        );
    }

    #[test]
    fn artifact_plan_provenance_verifies_matching_plan() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-plan-verify-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let plan_path = temp_root.join("plan.json");
        let plan = json!({
            "plan_schema": "zkf-runtime-plan-v1",
            "plan_kind": "wrapper",
            "trust_lane": "allow-attestation",
            "input_bindings": {
                "proof_sha256": "proof-sha",
                "compiled_sha256": "compiled-sha",
                "source_backend": "plonky3",
                "source_program_digest": "program-digest",
                "compiled_backend": "plonky3",
                "compiled_program_digest": "program-digest"
            }
        });
        crate::util::write_json(&plan_path, &plan).unwrap();
        let plan_bytes = fs::read(&plan_path).unwrap();
        let plan_sha = crate::util::sha256_hex(&plan_bytes);

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "runtime_plan_schema".to_string(),
            "zkf-runtime-plan-v1".to_string(),
        );
        metadata.insert("runtime_plan_kind".to_string(), "wrapper".to_string());
        metadata.insert("runtime_plan_sha256".to_string(), plan_sha.clone());
        metadata.insert(
            "runtime_requested_trust_lane".to_string(),
            "allow-attestation".to_string(),
        );
        metadata.insert(
            "runtime_source_proof_sha256".to_string(),
            "proof-sha".to_string(),
        );
        metadata.insert(
            "runtime_source_compiled_sha256".to_string(),
            "compiled-sha".to_string(),
        );
        metadata.insert("runtime_source_backend".to_string(), "plonky3".to_string());
        metadata.insert(
            "runtime_source_program_digest".to_string(),
            "program-digest".to_string(),
        );
        metadata.insert(
            "runtime_compiled_backend".to_string(),
            "plonky3".to_string(),
        );
        metadata.insert(
            "runtime_compiled_program_digest".to_string(),
            "program-digest".to_string(),
        );
        metadata.insert(
            "runtime_input_bindings_verified".to_string(),
            "true".to_string(),
        );
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let verification = verify_artifact_plan_provenance(&plan_path, &artifact).unwrap();
        assert_eq!(verification.get("matches"), Some(&Value::Bool(true)));
        assert_eq!(
            verification.get("plan_sha256"),
            Some(&Value::String(plan_sha))
        );
    }

    #[test]
    fn artifact_plan_provenance_rejects_mismatch() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-plan-mismatch-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let plan_path = temp_root.join("plan.json");
        let plan = json!({
            "plan_schema": "zkf-runtime-plan-v1",
            "plan_kind": "wrapper",
            "trust_lane": "allow-attestation",
        });
        crate::util::write_json(&plan_path, &plan).unwrap();

        let mut metadata = BTreeMap::new();
        metadata.insert("runtime_plan_schema".to_string(), "wrong".to_string());
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };

        let err = verify_artifact_plan_provenance(&plan_path, &artifact).unwrap_err();
        assert!(err.contains("runtime_plan_schema"));
    }

    #[test]
    fn installed_strict_certification_match_requires_current_soak_report() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-cert-match-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        unsafe {
            std::env::set_var("ZKF_CACHE_DIR", &temp_root);
        }

        let current = current_certification_build_info().unwrap();
        let path = strict_certification_report_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let mut report = StrictCertificationReport {
            report_schema: STRICT_CERTIFICATION_SCHEMA_V1.to_string(),
            certification_mode: "soak".to_string(),
            certified_at_unix_ms: 1,
            hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
            proof: "/tmp/proof.json".to_string(),
            compiled: "/tmp/compiled.json".to_string(),
            proof_sha256: "proof".to_string(),
            compiled_sha256: "compiled".to_string(),
            strict_cache_prepare_sha256: "prepare".to_string(),
            build: StrictCertificationBuildInfo {
                binary_sha256: "wrong".to_string(),
                ..current.clone()
            },
            doctor_preflight: StrictCertificationDoctorSnapshot {
                production_ready: Some(true),
                certified_hardware_profile: "apple-silicon-m4-max-48gb".to_string(),
                strict_bn254_ready: true,
                strict_bn254_auto_route: true,
                strict_gpu_stage_coverage: json!({"required_stages":["fft-ntt","qap-witness-map","msm"],"cpu_stages":[]}),
                strict_gpu_busy_ratio_peak: Some(0.75),
                runtime: Value::Null,
            },
            doctor_postflight: None,
            prepare_report_path: None,
            prepare_report_sha256: None,
            runs: Vec::new(),
            summary: StrictCertificationSummary {
                gate_passed: true,
                soak_passed: true,
                doctor_flips: 0,
                degraded_runs: 0,
                cold_gpu_stage_busy_ratio: Some(0.25),
                warm_gpu_stage_busy_ratio: Some(0.10),
                parallel_gpu_stage_busy_ratio_peak: Some(0.80),
                strict_gpu_busy_ratio_peak: 0.80,
                parallel_jobs: 2,
                fault_injection_failed_closed: true,
                final_pass: true,
                failures: Vec::new(),
            },
        };
        crate::util::write_json(&path, &report).unwrap();
        let mismatch = installed_strict_certification_match();
        assert!(mismatch.present);
        assert!(!mismatch.matches_current);

        report.build = current;
        crate::util::write_json(&path, &report).unwrap();
        let matched = installed_strict_certification_match();
        assert!(matched.present);
        assert!(matched.matches_current);

        unsafe {
            std::env::remove_var("ZKF_CACHE_DIR");
        }
    }

    #[test]
    fn strict_certification_report_defaults_to_home_cache_root() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-cert-home-{}", std::process::id()));
        let fake_home = temp_root.join("home");
        fs::create_dir_all(&fake_home).unwrap();

        let previous_home = std::env::var_os("HOME");
        let previous_cache_dir = std::env::var_os("ZKF_CACHE_DIR");
        unsafe {
            std::env::set_var("HOME", &fake_home);
            std::env::remove_var("ZKF_CACHE_DIR");
        }

        let path = strict_certification_report_path();
        assert_eq!(
            path,
            fake_home
                .join(".zkf")
                .join("cache")
                .join("stark-to-groth16")
                .join("certification")
                .join("strict-m4-max.json")
        );

        match previous_home {
            Some(value) => unsafe { std::env::set_var("HOME", value) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match previous_cache_dir {
            Some(value) => unsafe { std::env::set_var("ZKF_CACHE_DIR", value) },
            None => unsafe { std::env::remove_var("ZKF_CACHE_DIR") },
        }
    }

    #[test]
    fn validate_certified_run_rejects_low_gpu_busy_ratio() {
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("trust_model".to_string(), "cryptographic".to_string());
        metadata.insert("wrapper_strategy".to_string(), "direct-fri-v2".to_string());
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt".to_string(),
        );
        metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            "none".to_string(),
        );
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert("groth16_msm_fallback_state".to_string(), "none".to_string());
        metadata.insert(
            "metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert("metal_dispatch_last_failure".to_string(), "".to_string());
        metadata.insert(
            "target_groth16_metal_dispatch_last_failure".to_string(),
            "".to_string(),
        );
        metadata.insert("gpu_stage_busy_ratio".to_string(), "0.100".to_string());
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        let trace = json!({
            "status": "wrapped-v2",
            "trust_model": "cryptographic",
            "wrapper_strategy": "direct-fri-v2",
            "qap_witness_map_engine": "metal-bn254-ntt",
            "qap_witness_map_fallback_state": "none",
            "groth16_msm_engine": "metal-bn254-msm",
            "groth16_msm_fallback_state": "none",
            "metal_dispatch_circuit_open": false,
            "target_groth16_metal_dispatch_circuit_open": false,
            "metal_dispatch_last_failure": "",
            "target_groth16_metal_dispatch_last_failure": "",
            "gpu_stage_busy_ratio": 0.1,
            "stage_duration_ms": 1.0
        });
        let err = validate_certified_run(&artifact, &trace, 0.20, Some(false)).unwrap_err();
        assert!(err.contains("gpu_stage_busy_ratio"));
    }

    fn fake_certified_artifact(cache_hit: bool) -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("trust_model".to_string(), "cryptographic".to_string());
        metadata.insert("wrapper_strategy".to_string(), "direct-fri-v2".to_string());
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt".to_string(),
        );
        metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            "none".to_string(),
        );
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert("groth16_msm_fallback_state".to_string(), "none".to_string());
        metadata.insert(
            "metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_dispatch_circuit_open".to_string(),
            "false".to_string(),
        );
        metadata.insert("metal_dispatch_last_failure".to_string(), "".to_string());
        metadata.insert(
            "target_groth16_metal_dispatch_last_failure".to_string(),
            "".to_string(),
        );
        metadata.insert("gpu_stage_busy_ratio".to_string(), "0.250".to_string());
        metadata.insert(
            "wrapper_cache_hit".to_string(),
            if cache_hit { "true" } else { "false" }.to_string(),
        );
        metadata.insert(
            "wrapper_cache_source".to_string(),
            if cache_hit { "disk" } else { "" }.to_string(),
        );
        ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![1, 2, 3],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        }
    }

    fn fake_certified_trace() -> Value {
        json!({
            "status": "wrapped-v2",
            "trust_model": "cryptographic",
            "wrapper_strategy": "direct-fri-v2",
            "qap_witness_map_engine": "metal-bn254-ntt",
            "qap_witness_map_fallback_state": "none",
            "groth16_msm_engine": "metal-bn254-msm",
            "groth16_msm_fallback_state": "none",
            "metal_dispatch_circuit_open": false,
            "target_groth16_metal_dispatch_circuit_open": false,
            "metal_dispatch_last_failure": "",
            "target_groth16_metal_dispatch_last_failure": "",
            "gpu_stage_busy_ratio": 0.25,
            "stage_duration_ms": 10.0
        })
    }

    fn write_fake_certified_run(run_dir: &Path, label: &str, proof_path: &Path, cache_hit: bool) {
        let artifact = fake_certified_artifact(cache_hit);
        crate::util::write_json(proof_path, &artifact).unwrap();
        crate::util::write_json(
            &run_dir.join(format!("{label}.wrapped.groth16.json")),
            &artifact,
        )
        .unwrap();
        crate::util::write_json(
            &run_dir.join(format!("{label}.execution-trace.json")),
            &json!({"ok": true}),
        )
        .unwrap();
        crate::util::write_json(
            &run_dir.join(format!("{label}.runtime-trace.json")),
            &fake_certified_trace(),
        )
        .unwrap();
    }

    fn fake_healthy_doctor() -> Value {
        json!({
            "certified_hardware_profile": "apple-silicon-m4-max-48gb",
            "strict_bn254_ready": true,
            "strict_bn254_auto_route": true,
            "strict_gpu_stage_coverage": {
                "required_stages": ["fft-ntt", "qap-witness-map", "msm"],
                "cpu_stages": []
            },
            "runtime": {
                "metal_compiled": true,
                "metal_available": true,
                "metal_dispatch_circuit_open": false
            }
        })
    }

    #[test]
    fn fault_cycle_completed_accepts_checkpoint_sidecar() {
        let temp_root = std::env::temp_dir().join(format!(
            "zkf-runtime-fault-checkpoint-{}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_root).unwrap();
        let checkpoint = StrictCertificationFaultCheckpoint {
            checkpoint_schema: "zkf-strict-fault-checkpoint-v1".to_string(),
            cycle: 5,
            failed_closed: true,
            exit_code: Some(1),
            stdout_path: None,
            stderr_path: None,
            updated_at_unix_ms: 1,
        };
        crate::util::write_json(&fault_checkpoint_path(&temp_root, 5), &checkpoint).unwrap();

        assert!(fault_cycle_completed(&temp_root, 5, 0).unwrap());
    }

    #[test]
    fn try_resume_soak_state_reuses_completed_cycles_and_stops_before_partial_cycle() {
        let temp_root =
            std::env::temp_dir().join(format!("zkf-runtime-soak-resume-{}", std::process::id()));
        fs::create_dir_all(&temp_root).unwrap();
        let progress_path = temp_root.join("soak-progress.json");
        let cold_dir = temp_root.join("cold");
        let warm_dir = temp_root.join("warm-cycle-1");
        let parallel_dir = temp_root.join("parallel-cycle-1").join("job-1");
        let partial_parallel_dir = temp_root.join("parallel-cycle-2").join("job-1");
        fs::create_dir_all(&cold_dir).unwrap();
        fs::create_dir_all(&warm_dir).unwrap();
        fs::create_dir_all(&parallel_dir).unwrap();
        fs::create_dir_all(&partial_parallel_dir).unwrap();

        let cold_proof = cold_dir.join("cold.proof.json");
        write_fake_certified_run(&cold_dir, "cold", &cold_proof, false);
        write_fake_certified_run(&warm_dir, "warm-cycle-1", &cold_proof, true);
        let parallel_proof = parallel_dir.join("parallel-cycle-1-job-1.proof.json");
        write_fake_certified_run(
            &parallel_dir,
            "parallel-cycle-1-job-1",
            &parallel_proof,
            false,
        );
        crate::util::write_json(
            &temp_root.join("doctor-cycle-1.json"),
            &fake_healthy_doctor(),
        )
        .unwrap();

        let partial_proof = partial_parallel_dir.join("parallel-cycle-2-job-1.proof.json");
        crate::util::write_json(&partial_proof, &fake_certified_artifact(false)).unwrap();

        let progress = StrictCertificationSoakProgress {
            progress_schema: "zkf-strict-soak-progress-v1".to_string(),
            certification_mode: "soak".to_string(),
            phase: "running".to_string(),
            subphase: Some("parallel-wrap".to_string()),
            active_label: Some("parallel-cycle-2".to_string()),
            updated_at_unix_ms: 100,
            soak_started_at_unix_ms: 50,
            elapsed_ms: 50,
            min_duration_ms: 1000,
            remaining_duration_ms: 950,
            current_cycle: 1,
            required_cycles: 20,
            parallel_jobs: 1,
            strict_gpu_busy_ratio_peak: 0.25,
            warm_gpu_stage_busy_ratio: Some(0.25),
            parallel_gpu_stage_busy_ratio_peak: Some(0.25),
            doctor_flips: 0,
            degraded_runs: 0,
            resumed_from_cycle: None,
            failures: Vec::new(),
        };
        crate::util::write_json(&progress_path, &progress).unwrap();

        let resume = try_resume_soak_state(&temp_root, &progress_path, 1)
            .unwrap()
            .expect("resume state");
        assert_eq!(resume.current_cycle, 1);
        assert_eq!(resume.runs.len(), 3);
        assert_eq!(resume.resumed_from_cycle, Some(1));
        assert_eq!(resume.soak_started_at_unix_ms, 50);
        assert_eq!(resume.max_parallel_jobs_observed, 1);
    }

    #[test]
    fn aggregate_parallel_gpu_stage_busy_ratio_sums_parallel_runs() {
        let runs = vec![
            StrictCertificationRunSummary {
                label: "job-1".to_string(),
                proof_path: "/tmp/job-1.proof.json".to_string(),
                proof_sha256: "proof-1".to_string(),
                artifact_path: "/tmp/job-1.wrapped.groth16.json".to_string(),
                artifact_sha256: "artifact-1".to_string(),
                execution_trace_path: "/tmp/job-1.execution-trace.json".to_string(),
                execution_trace_sha256: "exec-1".to_string(),
                runtime_trace_path: "/tmp/job-1.runtime-trace.json".to_string(),
                runtime_trace_sha256: "runtime-1".to_string(),
                wrapper_cache_hit: false,
                wrapper_cache_source: None,
                duration_ms: 1.0,
                peak_memory_bytes: None,
                gpu_stage_busy_ratio: 0.25,
                qap_witness_map_engine: "metal-bn254-ntt".to_string(),
                groth16_msm_engine: "metal-bn254-msm".to_string(),
            },
            StrictCertificationRunSummary {
                label: "job-2".to_string(),
                proof_path: "/tmp/job-2.proof.json".to_string(),
                proof_sha256: "proof-2".to_string(),
                artifact_path: "/tmp/job-2.wrapped.groth16.json".to_string(),
                artifact_sha256: "artifact-2".to_string(),
                execution_trace_path: "/tmp/job-2.execution-trace.json".to_string(),
                execution_trace_sha256: "exec-2".to_string(),
                runtime_trace_path: "/tmp/job-2.runtime-trace.json".to_string(),
                runtime_trace_sha256: "runtime-2".to_string(),
                wrapper_cache_hit: false,
                wrapper_cache_source: None,
                duration_ms: 1.0,
                peak_memory_bytes: None,
                gpu_stage_busy_ratio: 0.25,
                qap_witness_map_engine: "metal-bn254-ntt".to_string(),
                groth16_msm_engine: "metal-bn254-msm".to_string(),
            },
        ];

        assert!((aggregate_parallel_gpu_stage_busy_ratio(&runs) - 0.50).abs() < 0.000_001);
    }

    #[test]
    fn desktop_safe_single_job_soak_uses_gate_floor_threshold() {
        assert!((min_parallel_gpu_stage_busy_ratio_for_jobs(1) - 0.20).abs() < 0.000_001);
        assert!((min_parallel_gpu_stage_busy_ratio_for_jobs(2) - 0.60).abs() < 0.000_001);
    }

    #[test]
    fn stderr_summary_ignores_time_footer_lines() {
        let stderr = "\
error: strict direct wrap failed\n\
123  page reclaims\n\
4569747320  peak memory footprint\n";
        assert_eq!(stderr_summary(stderr), "error: strict direct wrap failed");
    }

    #[test]
    fn command_capture_summary_prefers_meaningful_stdout_over_time_footer() {
        let stdout = "wrapper preview requires trust_model=attestation\n";
        let stderr = "4569747320  peak memory footprint\n";
        assert_eq!(
            command_capture_summary(stdout, stderr),
            "wrapper preview requires trust_model=attestation"
        );
    }

    #[test]
    fn stderr_summary_ignores_bsd_time_footer_line() {
        let stderr = "\
error: execution error: backend failure\n\
321.72 real        10.72 user         1.55 sys\n";
        assert_eq!(
            stderr_summary(stderr),
            "error: execution error: backend failure"
        );
    }

    #[test]
    fn runtime_policy_extracts_trace_inputs_from_runtime_trace() {
        let trace = json!({
            "backend": "arkworks-groth16",
            "source_backend": "plonky3",
            "runtime_plan": {
                "field": "goldilocks",
                "constraint_count": 4096,
                "signal_count": 1024
            },
            "runtime_gpu_stage_busy_ratio": 0.75,
            "fallback_nodes": 2,
            "node_count": 8,
            "gpu_nodes": 6,
            "cpu_nodes": 2,
            "peak_memory_bytes": 1048576
        });

        let inputs = extract_runtime_policy_trace_inputs(&trace);
        assert_eq!(inputs.field.as_deref(), Some("goldilocks"));
        assert_eq!(inputs.constraints, Some(4096));
        assert_eq!(inputs.signals, Some(1024));
        assert_eq!(inputs.gpu_stage_busy_ratio, Some(0.75));
        assert_eq!(inputs.fallback_nodes, Some(2));
        assert_eq!(inputs.backends, vec!["plonky3", "arkworks-groth16"]);
    }

    #[test]
    fn runtime_policy_feature_vector_is_stable_and_bounded() {
        let features = RuntimePolicyFeatures {
            constraints: 1 << 16,
            signals: 1 << 12,
            requested_jobs: 4,
            total_jobs: 8,
            runtime_gpu_stage_busy_ratio: 0.80,
            runtime_fallback_ratio: 0.10,
            runtime_gpu_nodes: 8,
            runtime_cpu_nodes: 2,
            peak_memory_bytes: 8 * 1024 * 1024,
            ram_utilization: 0.40,
            metal_available: true,
            strict_runtime_ready: true,
        };
        let feature_vector =
            build_runtime_policy_feature_vector(&features, 48 * 1024 * 1024 * 1024);

        assert_eq!(feature_vector.len(), runtime_policy_feature_labels().len());
        assert!(
            feature_vector
                .iter()
                .all(|value| *value >= 0.0 && *value <= 1.0)
        );
        assert_eq!(feature_vector[8], 1.0);
        assert_eq!(feature_vector[9], 1.0);
    }

    #[test]
    fn runtime_policy_backend_parser_dedupes_trace_candidates() {
        let trace_inputs = RuntimePolicyTraceInputs {
            backends: vec![
                "plonky3".to_string(),
                "plonky3".to_string(),
                "arkworks-groth16".to_string(),
            ],
            ..RuntimePolicyTraceInputs::default()
        };

        let backends = parse_policy_backends(None, &trace_inputs, Some(FieldId::Bn254)).unwrap();
        assert_eq!(
            backends,
            vec![BackendKind::Plonky3, BackendKind::ArkworksGroth16]
        );
    }

    #[test]
    fn runtime_policy_default_candidates_follow_field_hint() {
        let bn254 = parse_policy_backends(
            None,
            &RuntimePolicyTraceInputs::default(),
            Some(FieldId::Bn254),
        )
        .unwrap();
        let goldilocks = parse_policy_backends(
            None,
            &RuntimePolicyTraceInputs::default(),
            Some(FieldId::Goldilocks),
        )
        .unwrap();

        assert_eq!(
            bn254,
            vec![
                BackendKind::ArkworksGroth16,
                BackendKind::Nova,
                BackendKind::HyperNova
            ]
        );
        assert_eq!(
            goldilocks,
            vec![
                BackendKind::Plonky3,
                BackendKind::Sp1,
                BackendKind::RiscZero
            ]
        );
    }

    #[test]
    fn runtime_policy_explicit_backends_override_field_defaults() {
        let backends = parse_policy_backends(
            Some("plonky3"),
            &RuntimePolicyTraceInputs::default(),
            Some(FieldId::Bn254),
        )
        .unwrap();
        assert_eq!(backends, vec![BackendKind::Plonky3]);
    }

    #[test]
    fn runtime_policy_field_changes_default_candidate_set() {
        let bn254 = build_runtime_policy_report(
            None,
            Some("bn254".to_string()),
            None,
            "fastest-prove".to_string(),
            Some(4096),
            Some(1024),
            Some(2),
            Some(4),
            None,
            "cpu-and-neural-engine".to_string(),
        )
        .expect("bn254 report");
        let goldilocks = build_runtime_policy_report(
            None,
            Some("goldilocks".to_string()),
            None,
            "fastest-prove".to_string(),
            Some(4096),
            Some(1024),
            Some(2),
            Some(4),
            None,
            "cpu-and-neural-engine".to_string(),
        )
        .expect("goldilocks report");

        assert_eq!(
            bn254.backends,
            vec!["arkworks-groth16", "nova", "hypernova"]
        );
        assert_eq!(goldilocks.backends, vec!["plonky3", "sp1", "risc-zero"]);
        assert_ne!(
            bn254.backend_recommendation.selected,
            goldilocks.backend_recommendation.selected
        );
    }
}
