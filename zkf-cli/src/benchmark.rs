use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zkf_backends::{
    backend_for, blackbox_semantics_for_backend, cpu_math_fallback_reason_for_backend,
    gpu_stage_coverage_for_backend_field, metal_complete_for_backend, proof_engine_for_backend,
    proof_semantics_for_backend, prover_acceleration_claimed_for_backend,
    prover_acceleration_scope_for_backend, recommend_gpu_jobs, GpuSchedulerDecision,
    GpuStageCoverage,
};
use zkf_core::{generate_witness, BackendKind, FieldElement, FieldId, Program};
use zkf_examples::{mul_add_program_with_field, recurrence_program};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::util::annotate_artifact_with_runtime_report;

#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    pub backends: Vec<BackendKind>,
    pub skip_large: bool,
    pub continue_on_error: bool,
    pub iterations: usize,
    pub parallel: bool,
    pub metal_first: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub generated_unix_ms: u128,
    pub benchmark_version: String,
    pub iterations: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<GpuSchedulerDecision>,
    pub cases: Vec<CircuitCaseSummary>,
    pub results: Vec<BenchmarkResult>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CircuitCaseSummary {
    pub name: String,
    pub family: String,
    pub constraints: usize,
    pub signals: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkResult {
    pub case_name: String,
    pub backend: BackendKind,
    pub field: FieldId,
    pub constraints: usize,
    pub signals: usize,
    pub iterations: usize,
    pub successful_iterations: usize,
    pub failed_iterations: usize,
    pub witness_ms_mean: f64,
    pub witness_ms_stddev: f64,
    pub compile_ms_mean: f64,
    pub compile_ms_stddev: f64,
    pub prove_ms_mean: f64,
    pub prove_ms_stddev: f64,
    pub verify_ms_mean: f64,
    pub verify_ms_stddev: f64,
    pub proof_size_bytes_mean: f64,
    pub proof_size_bytes_stddev: f64,
    pub public_inputs_mean: f64,
    pub public_inputs_stddev: f64,
    pub process_peak_rss_after_bytes: Option<u64>,
    pub witness_peak_rss_delta_bytes_max: Option<u64>,
    pub compile_peak_rss_delta_bytes_max: Option<u64>,
    pub prove_peak_rss_delta_bytes_max: Option<u64>,
    pub verify_peak_rss_delta_bytes_max: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackbox_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_acceleration_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_stage_coverage: Option<GpuStageCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_execution_regime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_gpu_stage_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_prover_acceleration_realized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_acceleration_realization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_math_fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_metallib_mode: Option<String>,
    pub metal_gpu_busy_ratio: f64,
    pub metal_stage_breakdown: String,
    pub metal_inflight_jobs: usize,
    pub metal_no_cpu_fallback: bool,
    pub metal_counter_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msm_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntt_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poseidon2_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fri_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_eval_accelerator: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accelerator_fallback_reasons: Vec<String>,
    pub status: BenchmarkStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BenchmarkStatus {
    Ok,
    Partial {
        failed_iterations: usize,
        first_error: String,
    },
    Failed {
        stage: String,
        error: String,
    },
}

#[derive(Debug, Clone)]
struct CircuitCase {
    name: &'static str,
    family: &'static str,
    steps: Option<usize>,
}

impl CircuitCase {
    fn build_program(&self, field: FieldId) -> Program {
        match self.steps {
            Some(steps) => recurrence_program(field, steps),
            None => mul_add_program_with_field(field),
        }
    }

    fn inputs(&self) -> BTreeMap<String, FieldElement> {
        let mut inputs = BTreeMap::new();
        inputs.insert("x".to_string(), FieldElement::from_i64(3));
        inputs.insert("y".to_string(), FieldElement::from_i64(11));
        inputs
    }
}

#[derive(Debug, Clone)]
struct StageSample {
    elapsed_ms: f64,
    peak_rss_delta_bytes: Option<u64>,
    process_peak_after_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct IterationMetrics {
    witness_ms: f64,
    compile_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_size_bytes: usize,
    public_inputs: usize,
    process_peak_rss_after_bytes: Option<u64>,
    witness_peak_rss_delta_bytes: Option<u64>,
    compile_peak_rss_delta_bytes: Option<u64>,
    prove_peak_rss_delta_bytes: Option<u64>,
    verify_peak_rss_delta_bytes: Option<u64>,
    proof_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct IterationFailure {
    iteration: usize,
    stage: String,
    error: String,
}

#[derive(Debug)]
enum StageError {
    Witness(String),
    Compile(String),
    Prove(String),
    Verify(String),
}

impl StageError {
    fn stage_name(&self) -> &'static str {
        match self {
            Self::Witness(_) => "witness",
            Self::Compile(_) => "compile",
            Self::Prove(_) => "prove",
            Self::Verify(_) => "verify",
        }
    }
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Witness(err) => write!(f, "witness stage failed: {err}"),
            Self::Compile(err) => write!(f, "compile stage failed: {err}"),
            Self::Prove(err) => write!(f, "prove stage failed: {err}"),
            Self::Verify(err) => write!(f, "verify stage failed: {err}"),
        }
    }
}

pub fn run_benchmarks(options: &BenchmarkOptions) -> Result<BenchmarkReport, String> {
    run_benchmarks_with_iteration_runner(options, run_single_benchmark_iteration)
}

type BenchmarkIterationRunner = fn(
    &dyn zkf_backends::BackendEngine,
    BackendKind,
    &Program,
    &BTreeMap<String, FieldElement>,
) -> Result<IterationMetrics, StageError>;

fn run_benchmarks_with_iteration_runner(
    options: &BenchmarkOptions,
    iteration_runner: BenchmarkIterationRunner,
) -> Result<BenchmarkReport, String> {
    if options.backends.is_empty() {
        return Err("benchmark requires at least one backend".to_string());
    }
    if options.iterations == 0 {
        return Err("benchmark iterations must be >= 1".to_string());
    }

    let cases = benchmark_cases(options.skip_large);
    let mut case_summaries = Vec::with_capacity(cases.len());
    for case in &cases {
        let sample_program = case.build_program(FieldId::Goldilocks);
        case_summaries.push(CircuitCaseSummary {
            name: case.name.to_string(),
            family: case.family.to_string(),
            constraints: sample_program.constraints.len(),
            signals: sample_program.signals.len(),
        });
    }

    let mut results = Vec::with_capacity(cases.len().saturating_mul(options.backends.len()));
    let max_constraints = case_summaries
        .iter()
        .map(|case| case.constraints)
        .max()
        .unwrap_or(1);
    let max_signals = case_summaries
        .iter()
        .map(|case| case.signals)
        .max()
        .unwrap_or(1);
    let mut scheduler = None;
    if options.parallel {
        let mut jobs = Vec::new();
        for (backend_index, backend) in options.backends.iter().enumerate() {
            let fields = benchmark_fields_for_backend(*backend, options.metal_first)?;
            for (field_index, field) in fields.into_iter().enumerate() {
                for (case_index, case) in cases.iter().cloned().enumerate() {
                    jobs.push((
                        backend_index,
                        field_index,
                        case_index,
                        *backend,
                        field,
                        case,
                    ));
                }
            }
        }

        scheduler = Some(recommend_gpu_jobs(
            &options.backends,
            max_constraints,
            max_signals,
            None,
            jobs.len(),
        ));
        let worker_count = scheduler
            .as_ref()
            .map(|decision| decision.recommended_jobs.max(1))
            .unwrap_or(1);

        let jobs = Arc::new(jobs);
        let next_index = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::channel();
        for _ in 0..worker_count {
            let sender = sender.clone();
            let iterations = options.iterations;
            let continue_on_error = options.continue_on_error;
            let jobs = Arc::clone(&jobs);
            let next_index = Arc::clone(&next_index);
            thread::spawn(move || loop {
                let index = next_index.fetch_add(1, Ordering::SeqCst);
                if index >= jobs.len() {
                    break;
                }
                let (backend_index, field_index, case_index, backend, field, case) =
                    jobs[index].clone();
                let engine = backend_for(backend);
                let program = case.build_program(field);
                let result = run_case_iterations(
                    engine.as_ref(),
                    backend,
                    field,
                    &case,
                    &program,
                    iterations,
                    continue_on_error,
                    iteration_runner,
                );
                let _ = sender.send((backend_index, field_index, case_index, result));
            });
        }
        drop(sender);

        let mut ordered = Vec::with_capacity(jobs.len());
        for _ in 0..jobs.len() {
            let message = receiver
                .recv()
                .map_err(|err| format!("parallel benchmark worker failed: {err}"))?;
            ordered.push(message);
        }
        ordered.sort_by_key(|(backend_index, field_index, case_index, _)| {
            (*backend_index, *field_index, *case_index)
        });

        for (_, _, _, result) in ordered {
            let result = result?;
            results.push(result);
        }
    } else {
        for backend in &options.backends {
            let fields = benchmark_fields_for_backend(*backend, options.metal_first)?;
            let engine = backend_for(*backend);

            for field in fields {
                for case in &cases {
                    let program = case.build_program(field);
                    let result = run_case_iterations(
                        engine.as_ref(),
                        *backend,
                        field,
                        case,
                        &program,
                        options.iterations,
                        options.continue_on_error,
                        iteration_runner,
                    )?;
                    results.push(result);
                }
            }
        }
    }

    Ok(BenchmarkReport {
        generated_unix_ms: unix_timestamp_ms(),
        benchmark_version: "v6".to_string(),
        iterations: options.iterations,
        scheduler: scheduler.clone(),
        cases: case_summaries,
        results,
        notes: vec![
            "Programs are generated per backend using a field-parametric circuit template."
                .to_string(),
            "Timing statistics are reported as mean and sample standard deviation across iterations."
                .to_string(),
            "Peak RSS uses process-level max RSS; max stage deltas are reported per case/backend."
                .to_string(),
            "Circuit family uses only Equal/Add/Mul so all operational backends are benchmarked on identical logic."
                .to_string(),
            if options.parallel {
                format!(
                    "Parallel mode enabled: GPU-aware worker pool selected {} jobs. {}",
                    scheduler
                        .as_ref()
                        .map(|decision| decision.recommended_jobs)
                        .unwrap_or(1),
                    scheduler
                        .as_ref()
                        .map(|decision| decision.reason.clone())
                        .unwrap_or_else(|| "No scheduler decision available.".to_string())
                )
            } else {
                "Parallel mode disabled: backend/case pairs are benchmarked sequentially.".to_string()
            },
        ],
    })
}

pub fn render_markdown_table(report: &BenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str("| Circuit | Backend | Field | Iter (ok/total) | Constraints | Signals | Witness ms (avg ± sd) | Compile ms (avg ± sd) | Prove ms (avg ± sd) | Verify ms (avg ± sd) | Proof bytes (avg ± sd) | Status |\n");
    out.push_str("|---|---|---|---:|---:|---:|---|---|---|---|---|---|\n");

    for result in &report.results {
        let status = match &result.status {
            BenchmarkStatus::Ok => "ok".to_string(),
            BenchmarkStatus::Partial {
                failed_iterations,
                first_error,
            } => format!("partial ({failed_iterations} failed, {first_error})"),
            BenchmarkStatus::Failed { stage, error } => format!("failed ({stage}: {error})"),
        };

        out.push_str(&format!(
            "| {} | {} | {} | {}/{} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            result.case_name,
            result.backend,
            result.field,
            result.successful_iterations,
            result.iterations,
            result.constraints,
            result.signals,
            format_mean_stddev(result.witness_ms_mean, result.witness_ms_stddev, 3),
            format_mean_stddev(result.compile_ms_mean, result.compile_ms_stddev, 3),
            format_mean_stddev(result.prove_ms_mean, result.prove_ms_stddev, 3),
            format_mean_stddev(result.verify_ms_mean, result.verify_ms_stddev, 3),
            format_mean_stddev(
                result.proof_size_bytes_mean,
                result.proof_size_bytes_stddev,
                1
            ),
            status
        ));
    }

    out
}

fn run_case_iterations(
    engine: &dyn zkf_backends::BackendEngine,
    backend: BackendKind,
    field: FieldId,
    case: &CircuitCase,
    program: &Program,
    iterations: usize,
    continue_on_error: bool,
    iteration_runner: BenchmarkIterationRunner,
) -> Result<BenchmarkResult, String> {
    let inputs = case.inputs();
    let mut successes = Vec::with_capacity(iterations);
    let mut failures = Vec::new();

    for iteration in 1..=iterations {
        match iteration_runner(engine, backend, program, &inputs) {
            Ok(metrics) => successes.push(metrics),
            Err(err) => {
                let failure = IterationFailure {
                    iteration,
                    stage: err.stage_name().to_string(),
                    error: err.to_string(),
                };

                if !continue_on_error {
                    return Err(format!(
                        "benchmark failed for case '{}' on {} iteration {}: {}",
                        case.name, backend, iteration, failure.error
                    ));
                }

                failures.push(failure);
            }
        }
    }

    if successes.is_empty() {
        let first = failures.first().ok_or_else(|| {
            format!(
                "benchmark produced no successes for case '{}' on {}",
                case.name, backend
            )
        })?;
        let gpu_stage_coverage = gpu_stage_coverage_for_backend_field(backend, Some(field));

        return Ok(BenchmarkResult {
            case_name: case.name.to_string(),
            backend,
            field,
            constraints: program.constraints.len(),
            signals: program.signals.len(),
            iterations,
            successful_iterations: 0,
            failed_iterations: failures.len(),
            witness_ms_mean: 0.0,
            witness_ms_stddev: 0.0,
            compile_ms_mean: 0.0,
            compile_ms_stddev: 0.0,
            prove_ms_mean: 0.0,
            prove_ms_stddev: 0.0,
            verify_ms_mean: 0.0,
            verify_ms_stddev: 0.0,
            proof_size_bytes_mean: 0.0,
            proof_size_bytes_stddev: 0.0,
            public_inputs_mean: 0.0,
            public_inputs_stddev: 0.0,
            process_peak_rss_after_bytes: current_peak_rss_bytes(),
            witness_peak_rss_delta_bytes_max: None,
            compile_peak_rss_delta_bytes_max: None,
            prove_peak_rss_delta_bytes_max: None,
            verify_peak_rss_delta_bytes_max: None,
            proof_semantics: Some(proof_semantics_for_backend(backend).to_string()),
            blackbox_semantics: Some(blackbox_semantics_for_backend(backend).to_string()),
            prover_acceleration_scope: Some(
                prover_acceleration_scope_for_backend(backend).to_string(),
            ),
            proof_engine: Some(proof_engine_for_backend(backend).to_string()),
            gpu_stage_coverage: Some(gpu_stage_coverage.clone()),
            metal_complete: Some(
                metal_complete_for_backend(backend) && gpu_stage_coverage.cpu_stages.is_empty(),
            ),
            runtime_execution_regime: None,
            runtime_gpu_stage_busy_ratio: None,
            runtime_prover_acceleration_realized: None,
            prover_acceleration_realization: None,
            cpu_math_fallback_reason: fallback_reason_from_coverage(
                backend,
                field,
                &gpu_stage_coverage,
            ),
            export_scheme: zkf_backends::export_scheme_for_backend(backend).map(str::to_string),
            metal_runtime: None,
            metal_device: None,
            metal_metallib_mode: None,
            metal_gpu_busy_ratio: 0.0,
            metal_stage_breakdown: "{}".to_string(),
            metal_inflight_jobs: 0,
            metal_no_cpu_fallback: false,
            metal_counter_source: "not-measured".to_string(),
            msm_accelerator: None,
            ntt_accelerator: None,
            hash_accelerator: None,
            poseidon2_accelerator: None,
            fri_accelerator: None,
            constraint_eval_accelerator: None,
            accelerator_fallback_reasons: Vec::new(),
            status: BenchmarkStatus::Failed {
                stage: first.stage.clone(),
                error: format!("iteration {}: {}", first.iteration, first.error),
            },
        });
    }

    let witness_values: Vec<f64> = successes.iter().map(|m| m.witness_ms).collect();
    let compile_values: Vec<f64> = successes.iter().map(|m| m.compile_ms).collect();
    let prove_values: Vec<f64> = successes.iter().map(|m| m.prove_ms).collect();
    let verify_values: Vec<f64> = successes.iter().map(|m| m.verify_ms).collect();
    let proof_size_values: Vec<f64> = successes
        .iter()
        .map(|m| m.proof_size_bytes as f64)
        .collect();
    let public_inputs_values: Vec<f64> = successes.iter().map(|m| m.public_inputs as f64).collect();

    let (witness_ms_mean, witness_ms_stddev) = mean_stddev(&witness_values);
    let (compile_ms_mean, compile_ms_stddev) = mean_stddev(&compile_values);
    let (prove_ms_mean, prove_ms_stddev) = mean_stddev(&prove_values);
    let (verify_ms_mean, verify_ms_stddev) = mean_stddev(&verify_values);
    let (proof_size_bytes_mean, proof_size_bytes_stddev) = mean_stddev(&proof_size_values);
    let (public_inputs_mean, public_inputs_stddev) = mean_stddev(&public_inputs_values);

    let status = if failures.is_empty() {
        BenchmarkStatus::Ok
    } else {
        let first = &failures[0];
        BenchmarkStatus::Partial {
            failed_iterations: failures.len(),
            first_error: format!("iteration {}: {}", first.iteration, first.error),
        }
    };
    let metadata = successes
        .first()
        .map(|sample| sample.proof_metadata.clone())
        .unwrap_or_default();
    let gpu_stage_coverage = metadata
        .get("gpu_stage_coverage")
        .and_then(|value| serde_json::from_str::<GpuStageCoverage>(value).ok())
        .unwrap_or_else(|| gpu_stage_coverage_for_backend_field(backend, Some(field)));
    let proof_semantics = metadata
        .get("proof_semantics")
        .cloned()
        .unwrap_or_else(|| proof_semantics_for_backend(backend).to_string());
    let blackbox_semantics = metadata
        .get("blackbox_semantics")
        .cloned()
        .unwrap_or_else(|| blackbox_semantics_for_backend(backend).to_string());
    let prover_acceleration_scope = metadata
        .get("prover_acceleration_scope")
        .cloned()
        .unwrap_or_else(|| prover_acceleration_scope_for_backend(backend).to_string());
    let proof_engine = metadata
        .get("proof_engine")
        .cloned()
        .unwrap_or_else(|| proof_engine_for_backend(backend).to_string());
    let metal_complete = metadata
        .get("metal_complete")
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or_else(|| {
            metal_complete_for_backend(backend) && gpu_stage_coverage.cpu_stages.is_empty()
        });
    let cpu_math_fallback_reason = metadata
        .get("cpu_math_fallback_reason")
        .cloned()
        .or_else(|| fallback_reason_from_coverage(backend, field, &gpu_stage_coverage));
    let export_scheme = metadata
        .get("export_scheme")
        .cloned()
        .or_else(|| zkf_backends::export_scheme_for_backend(backend).map(str::to_string));
    let surface_prover_accelerators =
        should_surface_prover_accelerators(&prover_acceleration_scope, backend);
    let runtime_realization = crate::util::runtime_execution_realization(&metadata);
    let mut accelerator_fallback_reasons = metadata
        .iter()
        .filter(|(key, _)| key.ends_with("_fallback_reason"))
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    if !surface_prover_accelerators {
        accelerator_fallback_reasons.push(format!(
            "accelerators-not-claimed scope={prover_acceleration_scope}"
        ));
    }

    Ok(BenchmarkResult {
        case_name: case.name.to_string(),
        backend,
        field,
        constraints: program.constraints.len(),
        signals: program.signals.len(),
        iterations,
        successful_iterations: successes.len(),
        failed_iterations: failures.len(),
        witness_ms_mean,
        witness_ms_stddev,
        compile_ms_mean,
        compile_ms_stddev,
        prove_ms_mean,
        prove_ms_stddev,
        verify_ms_mean,
        verify_ms_stddev,
        proof_size_bytes_mean,
        proof_size_bytes_stddev,
        public_inputs_mean,
        public_inputs_stddev,
        process_peak_rss_after_bytes: successes
            .iter()
            .filter_map(|m| m.process_peak_rss_after_bytes)
            .max(),
        witness_peak_rss_delta_bytes_max: successes
            .iter()
            .filter_map(|m| m.witness_peak_rss_delta_bytes)
            .max(),
        compile_peak_rss_delta_bytes_max: successes
            .iter()
            .filter_map(|m| m.compile_peak_rss_delta_bytes)
            .max(),
        prove_peak_rss_delta_bytes_max: successes
            .iter()
            .filter_map(|m| m.prove_peak_rss_delta_bytes)
            .max(),
        verify_peak_rss_delta_bytes_max: successes
            .iter()
            .filter_map(|m| m.verify_peak_rss_delta_bytes)
            .max(),
        proof_semantics: Some(proof_semantics),
        blackbox_semantics: Some(blackbox_semantics),
        prover_acceleration_scope: Some(prover_acceleration_scope),
        proof_engine: Some(proof_engine),
        gpu_stage_coverage: Some(gpu_stage_coverage),
        metal_complete: Some(metal_complete),
        runtime_execution_regime: runtime_realization.execution_regime,
        runtime_gpu_stage_busy_ratio: runtime_realization.gpu_stage_busy_ratio,
        runtime_prover_acceleration_realized: runtime_realization.prover_acceleration_realized,
        prover_acceleration_realization: runtime_realization.acceleration_label,
        cpu_math_fallback_reason,
        export_scheme,
        metal_runtime: Some(
            metadata
                .get("metal_available")
                .cloned()
                .unwrap_or_else(|| "false".to_string()),
        ),
        metal_device: metadata.get("metal_device").cloned(),
        metal_metallib_mode: metadata.get("metal_metallib_mode").cloned(),
        metal_gpu_busy_ratio: parse_metadata_f64(&metadata, "metal_gpu_busy_ratio").unwrap_or(0.0),
        metal_stage_breakdown: metadata
            .get("metal_stage_breakdown")
            .cloned()
            .unwrap_or_else(|| "{}".to_string()),
        metal_inflight_jobs: parse_metadata_usize(&metadata, "metal_inflight_jobs").unwrap_or(0),
        metal_no_cpu_fallback: parse_metadata_bool(&metadata, "metal_no_cpu_fallback")
            .unwrap_or(false),
        metal_counter_source: metadata
            .get("metal_counter_source")
            .cloned()
            .unwrap_or_else(|| "not-measured".to_string()),
        msm_accelerator: surface_prover_accelerators
            .then(|| metadata.get("msm_accelerator").cloned())
            .flatten(),
        ntt_accelerator: surface_prover_accelerators
            .then(|| metadata.get("ntt_accelerator").cloned())
            .flatten(),
        hash_accelerator: surface_prover_accelerators
            .then(|| metadata.get("hash_accelerator").cloned())
            .flatten(),
        poseidon2_accelerator: surface_prover_accelerators
            .then(|| metadata.get("poseidon2_accelerator").cloned())
            .flatten(),
        fri_accelerator: surface_prover_accelerators
            .then(|| metadata.get("fri_accelerator").cloned())
            .flatten(),
        constraint_eval_accelerator: surface_prover_accelerators
            .then(|| metadata.get("constraint_eval_accelerator").cloned())
            .flatten(),
        accelerator_fallback_reasons,
        status,
    })
}

fn should_surface_prover_accelerators(scope: &str, backend: BackendKind) -> bool {
    if scope.starts_with("not-claimed") {
        return false;
    }
    prover_acceleration_claimed_for_backend(backend)
}

fn parse_metadata_f64(metadata: &BTreeMap<String, String>, key: &str) -> Option<f64> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn parse_metadata_usize(metadata: &BTreeMap<String, String>, key: &str) -> Option<usize> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
}

fn parse_metadata_bool(metadata: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<bool>().ok())
}

fn fallback_reason_from_coverage(
    backend: BackendKind,
    field: FieldId,
    coverage: &GpuStageCoverage,
) -> Option<String> {
    if coverage.cpu_stages.is_empty() {
        return None;
    }
    if backend == BackendKind::Plonky3 && field == FieldId::Mersenne31 {
        return Some("mersenne31-circle-path-remains-cpu-classified".to_string());
    }
    cpu_math_fallback_reason_for_backend(backend)
        .or_else(|| Some(format!("cpu-only-stages:{}", coverage.cpu_stages.join(","))))
}

fn run_single_benchmark_iteration(
    engine: &dyn zkf_backends::BackendEngine,
    backend: BackendKind,
    program: &Program,
    inputs: &BTreeMap<String, FieldElement>,
) -> Result<IterationMetrics, StageError> {
    let (witness, witness_sample) = measure_stage(|| {
        generate_witness(program, inputs).map_err(|err| StageError::Witness(err.to_string()))
    })?;

    let (compiled, compile_sample) = measure_stage(|| {
        engine
            .compile(program)
            .map_err(|err| StageError::Compile(err.to_string()))
    })?;

    let (artifact, prove_sample) = measure_stage(|| {
        RuntimeExecutor::run_backend_prove_job(
            backend,
            zkf_backends::BackendRoute::Auto,
            Arc::new(program.clone()),
            None,
            Some(Arc::new(witness.clone())),
            Some(Arc::new(compiled.clone())),
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map(|execution| {
            let mut artifact = execution.artifact;
            annotate_artifact_with_runtime_report(&mut artifact, &execution.result);
            artifact
        })
        .map_err(|err| StageError::Prove(err.to_string()))
    })?;

    let (_, verify_sample) = measure_stage(|| {
        let ok = engine
            .verify(&compiled, &artifact)
            .map_err(|err| StageError::Verify(err.to_string()))?;
        if ok {
            Ok(())
        } else {
            Err(StageError::Verify(
                "verification returned false".to_string(),
            ))
        }
    })?;

    Ok(IterationMetrics {
        witness_ms: witness_sample.elapsed_ms,
        compile_ms: compile_sample.elapsed_ms,
        prove_ms: prove_sample.elapsed_ms,
        verify_ms: verify_sample.elapsed_ms,
        proof_size_bytes: artifact.proof.len(),
        public_inputs: artifact.public_inputs.len(),
        process_peak_rss_after_bytes: verify_sample
            .process_peak_after_bytes
            .or(prove_sample.process_peak_after_bytes)
            .or(compile_sample.process_peak_after_bytes)
            .or(witness_sample.process_peak_after_bytes),
        witness_peak_rss_delta_bytes: witness_sample.peak_rss_delta_bytes,
        compile_peak_rss_delta_bytes: compile_sample.peak_rss_delta_bytes,
        prove_peak_rss_delta_bytes: prove_sample.peak_rss_delta_bytes,
        verify_peak_rss_delta_bytes: verify_sample.peak_rss_delta_bytes,
        proof_metadata: artifact.metadata.clone(),
    })
}

fn measure_stage<T, E>(op: impl FnOnce() -> Result<T, E>) -> Result<(T, StageSample), E> {
    let before = current_peak_rss_bytes();
    let start = Instant::now();
    let value = op()?;
    let elapsed = start.elapsed();
    let after = current_peak_rss_bytes();

    let sample = StageSample {
        elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
        peak_rss_delta_bytes: match (before, after) {
            (Some(a), Some(b)) => Some(b.saturating_sub(a)),
            _ => None,
        },
        process_peak_after_bytes: after,
    };

    Ok((value, sample))
}

fn benchmark_cases(skip_large: bool) -> Vec<CircuitCase> {
    let mut cases = vec![
        CircuitCase {
            name: "tiny_mul_add",
            family: "mul_add",
            steps: None,
        },
        CircuitCase {
            name: "small_recurrence_40",
            family: "recurrence",
            steps: Some(40),
        },
        CircuitCase {
            name: "medium_recurrence_500",
            family: "recurrence",
            steps: Some(500),
        },
    ];

    if !skip_large {
        cases.push(CircuitCase {
            name: "large_recurrence_2500",
            family: "recurrence",
            steps: Some(2500),
        });
    }

    cases
}

fn benchmark_fields_for_backend(
    backend: BackendKind,
    metal_first: bool,
) -> Result<Vec<FieldId>, String> {
    match backend {
        BackendKind::ArkworksGroth16 => Ok(vec![FieldId::Bn254]),
        BackendKind::Halo2 => Ok(vec![FieldId::PastaFp]),
        BackendKind::Plonky3 => Ok(if metal_first {
            vec![FieldId::Goldilocks, FieldId::BabyBear]
        } else {
            vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
        }),
        other => Err(format!(
            "benchmark currently supports plonky3, halo2, arkworks-groth16; got {other}"
        )),
    }
}

fn mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if values.len() < 2 {
        return (mean, 0.0);
    }

    let variance = values
        .iter()
        .map(|value| {
            let delta = *value - mean;
            delta * delta
        })
        .sum::<f64>()
        / (values.len() as f64 - 1.0);

    (mean, variance.sqrt())
}

fn format_mean_stddev(mean: f64, stddev: f64, decimals: usize) -> String {
    match decimals {
        1 => format!("{mean:.1} ± {stddev:.1}"),
        2 => format!("{mean:.2} ± {stddev:.2}"),
        _ => format!("{mean:.3} ± {stddev:.3}"),
    }
}

fn unix_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(unix)]
fn current_peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }

    let usage = unsafe { usage.assume_init() };
    let raw = u64::try_from(usage.ru_maxrss).ok()?;

    #[cfg(target_os = "macos")]
    {
        Some(raw)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Some(raw.saturating_mul(1024))
    }
}

#[cfg(not(unix))]
fn current_peak_rss_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::{
        benchmark_fields_for_backend, mean_stddev, run_benchmarks_with_iteration_runner,
        should_surface_prover_accelerators, BenchmarkOptions,
    };
    use zkf_core::{BackendKind, FieldId};

    #[test]
    fn mean_stddev_handles_single_sample() {
        let (mean, stddev) = mean_stddev(&[42.0]);
        assert!((mean - 42.0).abs() < 1e-12);
        assert!(stddev.abs() < 1e-12);
    }

    #[test]
    fn mean_stddev_uses_sample_stddev() {
        let (mean, stddev) = mean_stddev(&[1.0, 2.0, 3.0]);
        assert!((mean - 2.0).abs() < 1e-12);
        assert!((stddev - 1.0).abs() < 1e-12);
    }

    #[test]
    fn benchmark_field_matrix_includes_all_native_plonky3_fields() {
        let fields =
            benchmark_fields_for_backend(BackendKind::Plonky3, false).expect("plonky3 fields");
        assert_eq!(
            fields,
            vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
        );
    }

    #[test]
    fn metal_first_benchmark_limits_plonky3_to_metal_fields() {
        let fields =
            benchmark_fields_for_backend(BackendKind::Plonky3, true).expect("plonky3 fields");
        assert_eq!(fields, vec![FieldId::Goldilocks, FieldId::BabyBear]);
    }

    #[test]
    fn benchmark_field_matrix_rejects_unsupported_backends() {
        let err = benchmark_fields_for_backend(BackendKind::Nova, false).expect_err("unsupported");
        assert!(err.contains("benchmark currently supports"));
    }

    #[test]
    fn benchmark_parallel_job_order_is_deterministic_with_multi_field_backend() {
        let backends = vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
        let cases = ["tiny_mul_add", "small_recurrence_40"];
        let mut jobs = Vec::new();
        for (backend_index, backend) in backends.into_iter().enumerate() {
            let fields = benchmark_fields_for_backend(backend, false).expect("fields");
            for (field_index, field) in fields.into_iter().enumerate() {
                for (case_index, case_name) in cases.iter().enumerate() {
                    jobs.push((
                        backend_index,
                        field_index,
                        case_index,
                        backend,
                        field,
                        *case_name,
                    ));
                }
            }
        }
        jobs.sort_by_key(|(backend_index, field_index, case_index, _, _, _)| {
            (*backend_index, *field_index, *case_index)
        });

        let ordered = jobs
            .iter()
            .map(|(_, _, _, backend, field, case_name)| {
                format!("{}:{}:{case_name}", backend.as_str(), field.as_str())
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                "arkworks-groth16:bn254:tiny_mul_add",
                "arkworks-groth16:bn254:small_recurrence_40",
                "plonky3:goldilocks:tiny_mul_add",
                "plonky3:goldilocks:small_recurrence_40",
                "plonky3:babybear:tiny_mul_add",
                "plonky3:babybear:small_recurrence_40",
                "plonky3:mersenne31:tiny_mul_add",
                "plonky3:mersenne31:small_recurrence_40",
            ]
        );
    }

    #[test]
    fn benchmark_accelerator_visibility_respects_semantic_scope() {
        assert!(!should_surface_prover_accelerators(
            "not-claimed-host-validation",
            BackendKind::Sp1
        ));
        assert!(should_surface_prover_accelerators(
            "proof-enforced-prover-stages",
            BackendKind::ArkworksGroth16
        ));
    }

    #[test]
    #[ignore = "slow benchmark integration path; run explicitly when validating scheduler metadata"]
    fn parallel_benchmark_report_includes_scheduler_and_scope() {
        let report = run_benchmarks_with_iteration_runner(
            &BenchmarkOptions {
                backends: vec![BackendKind::ArkworksGroth16],
                skip_large: true,
                continue_on_error: false,
                iterations: 1,
                parallel: true,
                metal_first: false,
            },
            synthetic_benchmark_iteration,
        )
        .expect("benchmark report");

        assert!(report.scheduler.is_some());
        assert!(report
            .results
            .iter()
            .all(|result| result.prover_acceleration_scope.is_some()));
        assert!(report
            .results
            .iter()
            .all(|result| !result.metal_stage_breakdown.is_empty()));
        assert!(report
            .results
            .iter()
            .all(|result| !result.metal_counter_source.is_empty()));
    }

    fn synthetic_benchmark_iteration(
        _engine: &dyn zkf_backends::BackendEngine,
        backend: BackendKind,
        program: &zkf_core::Program,
        inputs: &std::collections::BTreeMap<String, zkf_core::FieldElement>,
    ) -> Result<super::IterationMetrics, super::StageError> {
        let mut proof_metadata = std::collections::BTreeMap::new();
        zkf_backends::append_backend_runtime_metadata_for_field(
            &mut proof_metadata,
            backend,
            Some(program.field),
        );

        Ok(super::IterationMetrics {
            witness_ms: 0.1,
            compile_ms: 0.2,
            prove_ms: 0.3,
            verify_ms: 0.1,
            proof_size_bytes: program.constraints.len().max(1) * 8,
            public_inputs: inputs.len(),
            process_peak_rss_after_bytes: None,
            witness_peak_rss_delta_bytes: None,
            compile_peak_rss_delta_bytes: None,
            prove_peak_rss_delta_bytes: None,
            verify_peak_rss_delta_bytes: None,
            proof_metadata,
        })
    }

    #[test]
    fn runtime_realization_marks_cpu_only_fallback_even_with_metal_capability_metadata() {
        let metadata = std::collections::BTreeMap::from([
            ("metal_complete".to_string(), "true".to_string()),
            (
                "runtime_execution_regime".to_string(),
                "cpu-only".to_string(),
            ),
            (
                "runtime_gpu_stage_busy_ratio".to_string(),
                "0.000000".to_string(),
            ),
            (
                "runtime_prover_acceleration_realized".to_string(),
                "false".to_string(),
            ),
        ]);
        let realization = crate::util::runtime_execution_realization(&metadata);

        assert_eq!(realization.execution_regime.as_deref(), Some("cpu-only"));
        assert_eq!(realization.gpu_stage_busy_ratio, Some(0.0));
        assert_eq!(realization.prover_acceleration_realized, Some(false));
        assert_eq!(
            realization.acceleration_label.as_deref(),
            Some("cpu-only-realized")
        );
    }
}
