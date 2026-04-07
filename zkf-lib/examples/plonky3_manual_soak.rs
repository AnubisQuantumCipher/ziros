use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{BackendRoute, GpuStageCoverage, backend_for};
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, ProofArtifact, Signal,
    Visibility, Witness, WitnessAssignment, WitnessPlan, ZkfError, ZkfResult, generate_witness,
};
use zkf_lib::{
    AscentTrajectoryRequestV1, EDL_MC_TRAJECTORY_STEPS, EdlTrajectoryRequestV1,
    FALCON_HEAVY_ASCENT_STEPS, ascent_trajectory_witness_from_request,
    build_ascent_trajectory_program, build_edl_trajectory_program_with_steps, compile,
    edl_trajectory_witness_from_request_with_steps,
};
use zkf_runtime::telemetry::RuntimeStageTelemetry;
use zkf_runtime::watchdog::WatchdogAlertSeverity;
use zkf_runtime::{
    ExecutionMode, HardwareProfile, OptimizationObjective, RequiredTrustLane, RuntimeExecutor,
    TrustModel, WatchdogAlert, WatchdogRecommendation,
};

const DEFAULT_OUT_DIR: &str = "/tmp/zkf-production-soak-v0.4.1-plonky3";
const DEFAULT_HOURS: f64 = 12.0;
const REPORT_SCHEMA: &str = "zkf-manual-plonky3-soak-report-v1";
const REQUIRED_GPU_STAGES: [&str; 2] = ["fft-ntt", "hash-merkle"];
const STACK_GROW_RED_ZONE: usize = 8 * 1024 * 1024;
const STACK_GROW_SIZE: usize = 256 * 1024 * 1024;
const NARROW_METAL_BATCH_INSTANCES: usize = 4_096;

#[derive(Debug)]
struct Args {
    out_dir: PathBuf,
    workload: WorkloadKind,
    hours: f64,
    duration_seconds: Option<u64>,
    max_cycles: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum WorkloadKind {
    EdlTrajectory500,
    FalconAscent187,
    NarrowMetalBatch4096,
}

impl WorkloadKind {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "edl-trajectory-500" | "edl" => Ok(Self::EdlTrajectory500),
            "falcon-ascent-187" | "falcon-ascent" | "falcon" => Ok(Self::FalconAscent187),
            "narrow-metal-batch-4096" | "narrow-metal-batch" | "narrow" => {
                Ok(Self::NarrowMetalBatch4096)
            }
            other => Err(format!(
                "unknown workload '{other}' (expected edl-trajectory-500, falcon-ascent-187, or narrow-metal-batch-4096)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EdlTrajectory500 => "edl-trajectory-500",
            Self::FalconAscent187 => "falcon-ascent-187",
            Self::NarrowMetalBatch4096 => "narrow-metal-batch-4096",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::EdlTrajectory500 => {
                "EDL Monte Carlo trajectory propagation, 500 Goldilocks integration steps"
            }
            Self::FalconAscent187 => {
                "Falcon Heavy ascent trajectory certification, 187 Goldilocks ascent steps"
            }
            Self::NarrowMetalBatch4096 => {
                "Synthetic Goldilocks narrow-trace Metal batch, 4096 fully-metal-complete mul/add/boolean lanes"
            }
        }
    }
}

#[derive(Debug)]
struct WorkloadBundle {
    id: String,
    description: String,
    program: Program,
    witness: Witness,
}

#[derive(Debug, Clone, Serialize)]
struct ProgramSummary {
    name: String,
    field: String,
    signals: usize,
    constraints: usize,
}

#[derive(Debug, Clone, Serialize)]
struct WorkloadSummary {
    id: String,
    description: String,
    program: ProgramSummary,
}

#[derive(Debug, Serialize)]
struct CycleRuntimeSummary {
    total_wall_time_ms: f64,
    peak_memory_bytes: usize,
    gpu_nodes: usize,
    cpu_nodes: usize,
    delegated_nodes: usize,
    fallback_nodes: usize,
    final_trust_model: String,
    gpu_stage_busy_ratio: f64,
    counter_source: String,
    gpu_stages: Vec<String>,
    stage_breakdown: BTreeMap<String, RuntimeStageTelemetry>,
    watchdog_alerts: Value,
    artifact_gpu_stage_coverage: Option<GpuStageCoverage>,
    artifact_metal_complete: Option<bool>,
    artifact_gpu_busy_ratio: Option<f64>,
    artifact_metal_stage_breakdown: Option<Value>,
    artifact_cpu_math_fallback_reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct CycleSummary {
    cycle: u64,
    started_at_unix_ms: u128,
    prove_ms: f64,
    verify_ms: f64,
    verified: bool,
    proof_size_bytes: usize,
    public_inputs: usize,
    degraded: bool,
    degradation_reasons: Vec<String>,
    runtime: Option<CycleRuntimeSummary>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProgressReport {
    schema: &'static str,
    status: String,
    started_at_unix_ms: u128,
    updated_at_unix_ms: u128,
    requested_duration_seconds: u64,
    elapsed_seconds: u64,
    cycles_completed: u64,
    degraded_cycles: u64,
    current_cycle: Option<u64>,
    current_phase: String,
    workload: WorkloadSummary,
}

#[derive(Debug, Serialize)]
struct FinalReport {
    schema: &'static str,
    status: String,
    started_at_unix_ms: u128,
    finished_at_unix_ms: u128,
    requested_duration_seconds: u64,
    elapsed_seconds: u64,
    cycles_completed: u64,
    degraded_cycles: u64,
    zero_degraded_runs: bool,
    compile_ms: f64,
    hardware_profile: String,
    workload: WorkloadSummary,
    required_gpu_stages: Vec<String>,
    metal_runtime: zkf_backends::metal_runtime::MetalRuntimeReport,
    evidence: EvidencePaths,
    cycles: Vec<CycleSummary>,
}

#[derive(Debug, Serialize)]
struct EvidencePaths {
    program_json: String,
    witness_json: String,
    compiled_json: String,
    first_proof_json: Option<String>,
    progress_json: String,
}

fn main() -> ZkfResult<()> {
    let args = parse_args().map_err(ZkfError::InvalidArtifact)?;
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || run(args))
}

fn run(args: Args) -> ZkfResult<()> {
    fs::create_dir_all(&args.out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", args.out_dir.display())))?;
    let cycles_dir = args.out_dir.join("cycles");
    fs::create_dir_all(&cycles_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", cycles_dir.display())))?;

    let started_at_unix_ms = now_unix_ms();
    let requested_duration_seconds = args
        .duration_seconds
        .unwrap_or_else(|| (args.hours * 3600.0).round() as u64);
    let requested_duration = Duration::from_secs(requested_duration_seconds.max(1));

    let bundle = build_workload(args.workload)?;
    let workload = WorkloadSummary {
        id: bundle.id.clone(),
        description: bundle.description.clone(),
        program: ProgramSummary {
            name: bundle.program.name.clone(),
            field: bundle.program.field.to_string(),
            signals: bundle.program.signals.len(),
            constraints: bundle.program.constraints.len(),
        },
    };

    let program_path = args.out_dir.join("program.json");
    let witness_path = args.out_dir.join("witness.json");
    let compiled_path = args.out_dir.join("compiled.json");
    let progress_path = args.out_dir.join("progress.json");
    let report_path = args.out_dir.join("plonky3-soak-report.json");
    write_json(&program_path, &bundle.program)?;
    write_json(&witness_path, &bundle.witness)?;

    write_progress(
        &progress_path,
        ProgressReport {
            schema: REPORT_SCHEMA,
            status: "running".to_string(),
            started_at_unix_ms,
            updated_at_unix_ms: now_unix_ms(),
            requested_duration_seconds,
            elapsed_seconds: 0,
            cycles_completed: 0,
            degraded_cycles: 0,
            current_cycle: None,
            current_phase: "compile".to_string(),
            workload: workload.clone(),
        },
    )?;

    let metal_report = metal_runtime_report();
    if cfg!(all(target_os = "macos", target_vendor = "apple"))
        && (!metal_report.metal_compiled || !metal_report.metal_available)
    {
        return Err(ZkfError::Backend(format!(
            "manual Plonky3 soak requires a Metal-enabled build on this host; metal_compiled={} metal_available={}",
            metal_report.metal_compiled, metal_report.metal_available
        )));
    }
    eprintln!(
        "plonky3-manual-soak: workload={} constraints={} signals={} hardware={}",
        workload.id,
        workload.program.constraints,
        workload.program.signals,
        HardwareProfile::detect().as_str()
    );

    let compile_started = Instant::now();
    let compiled = compile(&bundle.program, "plonky3", None)?;
    let compile_ms = compile_started.elapsed().as_secs_f64() * 1_000.0;
    write_json(&compiled_path, &compiled)?;
    let soak_started = Instant::now();

    let program = Arc::new(bundle.program);
    let witness = Arc::new(bundle.witness);
    let compiled = Arc::new(compiled);
    let verifier = backend_for(BackendKind::Plonky3);

    let mut cycles = Vec::<CycleSummary>::new();
    let mut degraded_cycles = 0u64;
    let mut first_proof_path: Option<String> = None;
    let mut current_cycle = 0u64;

    write_progress(
        &progress_path,
        ProgressReport {
            schema: REPORT_SCHEMA,
            status: "running".to_string(),
            started_at_unix_ms,
            updated_at_unix_ms: now_unix_ms(),
            requested_duration_seconds,
            elapsed_seconds: 0,
            cycles_completed: 0,
            degraded_cycles: 0,
            current_cycle: None,
            current_phase: "compile-complete".to_string(),
            workload: workload.clone(),
        },
    )?;

    while soak_started.elapsed() < requested_duration {
        if let Some(max_cycles) = args.max_cycles
            && current_cycle >= max_cycles
        {
            break;
        }

        current_cycle += 1;
        write_progress(
            &progress_path,
            ProgressReport {
                schema: REPORT_SCHEMA,
                status: "running".to_string(),
                started_at_unix_ms,
                updated_at_unix_ms: now_unix_ms(),
                requested_duration_seconds,
                elapsed_seconds: soak_started.elapsed().as_secs(),
                cycles_completed: cycles.len() as u64,
                degraded_cycles,
                current_cycle: Some(current_cycle),
                current_phase: "prove".to_string(),
                workload: workload.clone(),
            },
        )?;

        let cycle_started = now_unix_ms();
        eprintln!("plonky3-manual-soak: cycle {} prove", current_cycle);
        let prove_started = Instant::now();
        let execution = RuntimeExecutor::run_backend_prove_job_with_objective(
            BackendKind::Plonky3,
            BackendRoute::Auto,
            Arc::clone(&program),
            None,
            Some(Arc::clone(&witness)),
            Some(Arc::clone(&compiled)),
            OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Adaptive,
        );
        let prove_ms = prove_started.elapsed().as_secs_f64() * 1_000.0;

        let cycle_summary = match execution {
            Ok(execution) => {
                eprintln!("plonky3-manual-soak: cycle {} verify", current_cycle);
                let verify_started = Instant::now();
                let verified = verifier
                    .verify(compiled.as_ref(), &execution.artifact)
                    .map_err(|error| error.to_string());
                let verify_ms = verify_started.elapsed().as_secs_f64() * 1_000.0;
                let cycle = build_cycle_summary(
                    current_cycle,
                    cycle_started,
                    prove_ms,
                    verify_ms,
                    verified,
                    &execution.artifact,
                    &execution.result.report,
                );

                if first_proof_path.is_none() && cycle.verified {
                    let proof_path = args.out_dir.join("first-success-proof.json");
                    write_json(&proof_path, &execution.artifact)?;
                    first_proof_path = Some(proof_path.display().to_string());
                }
                cycle
            }
            Err(error) => CycleSummary {
                cycle: current_cycle,
                started_at_unix_ms: cycle_started,
                prove_ms,
                verify_ms: 0.0,
                verified: false,
                proof_size_bytes: 0,
                public_inputs: 0,
                degraded: true,
                degradation_reasons: vec!["prove-error".to_string()],
                runtime: None,
                error: Some(error.to_string()),
            },
        };

        if cycle_summary.degraded {
            degraded_cycles += 1;
        }

        let cycle_path = cycles_dir.join(format!("cycle-{:05}.json", current_cycle));
        write_json(&cycle_path, &cycle_summary)?;
        eprintln!(
            "plonky3-manual-soak: cycle {} complete verified={} degraded={} prove_ms={:.1} gpu_busy={:.3}",
            current_cycle,
            cycle_summary.verified,
            cycle_summary.degraded,
            cycle_summary.prove_ms,
            cycle_summary
                .runtime
                .as_ref()
                .map(|runtime| runtime.gpu_stage_busy_ratio)
                .unwrap_or(0.0)
        );
        cycles.push(cycle_summary);

        write_progress(
            &progress_path,
            ProgressReport {
                schema: REPORT_SCHEMA,
                status: "running".to_string(),
                started_at_unix_ms,
                updated_at_unix_ms: now_unix_ms(),
                requested_duration_seconds,
                elapsed_seconds: soak_started.elapsed().as_secs(),
                cycles_completed: cycles.len() as u64,
                degraded_cycles,
                current_cycle: Some(current_cycle),
                current_phase: "cycle-complete".to_string(),
                workload: workload.clone(),
            },
        )?;

        if cycles
            .last()
            .and_then(|cycle| cycle.error.as_ref())
            .is_some()
        {
            break;
        }
    }

    let elapsed_seconds = soak_started.elapsed().as_secs();
    let completed_duration = elapsed_seconds >= requested_duration_seconds;
    let zero_degraded_runs = degraded_cycles == 0 && !cycles.is_empty() && completed_duration;
    let status = if zero_degraded_runs {
        "passed"
    } else if cycles.is_empty() {
        "failed"
    } else if completed_duration {
        "completed-with-degraded-runs"
    } else {
        "partial"
    };

    let final_report = FinalReport {
        schema: REPORT_SCHEMA,
        status: status.to_string(),
        started_at_unix_ms,
        finished_at_unix_ms: now_unix_ms(),
        requested_duration_seconds,
        elapsed_seconds,
        cycles_completed: cycles.len() as u64,
        degraded_cycles,
        zero_degraded_runs,
        compile_ms,
        hardware_profile: HardwareProfile::detect().as_str().to_string(),
        workload,
        required_gpu_stages: REQUIRED_GPU_STAGES
            .iter()
            .map(|stage| stage.to_string())
            .collect(),
        metal_runtime: metal_report,
        evidence: EvidencePaths {
            program_json: program_path.display().to_string(),
            witness_json: witness_path.display().to_string(),
            compiled_json: compiled_path.display().to_string(),
            first_proof_json: first_proof_path,
            progress_json: progress_path.display().to_string(),
        },
        cycles,
    };
    write_json(&report_path, &final_report)?;
    write_progress(
        &progress_path,
        ProgressReport {
            schema: REPORT_SCHEMA,
            status: status.to_string(),
            started_at_unix_ms,
            updated_at_unix_ms: now_unix_ms(),
            requested_duration_seconds,
            elapsed_seconds,
            cycles_completed: final_report.cycles_completed,
            degraded_cycles,
            current_cycle: None,
            current_phase: "finished".to_string(),
            workload: final_report.workload.clone(),
        },
    )?;

    println!("{}", report_path.display());
    Ok(())
}

fn build_cycle_summary(
    cycle: u64,
    started_at_unix_ms: u128,
    prove_ms: f64,
    verify_ms: f64,
    verified: Result<bool, String>,
    artifact: &ProofArtifact,
    report: &zkf_runtime::GraphExecutionReport,
) -> CycleSummary {
    let verify_error = verified.as_ref().err().cloned();
    let verified_ok = verified.unwrap_or(false);
    let artifact_gpu_stage_coverage = parse_artifact_gpu_stage_coverage(&artifact.metadata);
    let artifact_metal_complete = metadata_bool(&artifact.metadata, "metal_complete");
    let artifact_gpu_busy_ratio = metadata_f64(&artifact.metadata, "metal_gpu_busy_ratio");
    let artifact_metal_stage_breakdown = metadata_json(&artifact.metadata, "metal_stage_breakdown");
    let artifact_cpu_math_fallback_reason =
        artifact.metadata.get("cpu_math_fallback_reason").cloned();
    let artifact_gpu_stages = artifact_gpu_stage_coverage
        .as_ref()
        .map(|coverage| coverage.metal_stages.clone())
        .unwrap_or_default();
    let observed_gpu_from_artifact =
        !artifact_gpu_stages.is_empty() || artifact_gpu_busy_ratio.unwrap_or(0.0) > 0.0;
    let mut degradation_reasons = Vec::new();
    if !verified_ok {
        degradation_reasons.push("verify-failed".to_string());
    }
    if report.final_trust_model != TrustModel::Cryptographic {
        degradation_reasons.push(format!("trust-model:{}", report.final_trust_model.as_str()));
    }
    if report.gpu_nodes == 0 && !observed_gpu_from_artifact {
        degradation_reasons.push("no-gpu-nodes".to_string());
    }
    if artifact_gpu_busy_ratio.unwrap_or_else(|| report.gpu_stage_busy_ratio()) <= 0.0 {
        degradation_reasons.push("gpu-stage-busy-ratio-zero".to_string());
    }
    if report.fallback_nodes > 0 {
        degradation_reasons.push(format!("gpu-fallback-nodes:{}", report.fallback_nodes));
    }
    if has_actionable_watchdog_alert(&report.watchdog_alerts) {
        degradation_reasons.push(format!("watchdog-alerts:{}", report.watchdog_alerts.len()));
    }

    let stage_breakdown = report.stage_breakdown();
    let runtime_gpu_stages = stage_breakdown
        .iter()
        .filter_map(|(stage, telemetry)| (telemetry.gpu_nodes > 0).then_some(stage.clone()))
        .collect::<Vec<_>>();
    let gpu_stages = if !artifact_gpu_stages.is_empty() {
        artifact_gpu_stages
    } else {
        runtime_gpu_stages
    };
    if let Some(coverage) = &artifact_gpu_stage_coverage {
        if coverage.metal_stages.is_empty() || coverage.coverage_ratio <= 0.0 {
            degradation_reasons.push("no-artifact-metal-stages".to_string());
        }
    } else {
        for required in REQUIRED_GPU_STAGES {
            if !gpu_stages.iter().any(|stage| stage == required) {
                degradation_reasons.push(format!("missing-gpu-stage:{required}"));
            }
        }
    }

    CycleSummary {
        cycle,
        started_at_unix_ms,
        prove_ms,
        verify_ms,
        verified: verified_ok,
        proof_size_bytes: artifact.proof.len(),
        public_inputs: artifact.public_inputs.len(),
        degraded: !degradation_reasons.is_empty(),
        degradation_reasons,
        runtime: Some(CycleRuntimeSummary {
            total_wall_time_ms: report.total_wall_time.as_secs_f64() * 1_000.0,
            peak_memory_bytes: report.peak_memory_bytes,
            gpu_nodes: report.gpu_nodes,
            cpu_nodes: report.cpu_nodes,
            delegated_nodes: report.delegated_nodes,
            fallback_nodes: report.fallback_nodes,
            final_trust_model: report.final_trust_model.as_str().to_string(),
            gpu_stage_busy_ratio: artifact_gpu_busy_ratio
                .unwrap_or_else(|| report.gpu_stage_busy_ratio()),
            counter_source: report.counter_source().to_string(),
            gpu_stages,
            stage_breakdown,
            watchdog_alerts: serde_json::to_value(&report.watchdog_alerts)
                .unwrap_or_else(|_| Value::Array(Vec::new())),
            artifact_gpu_stage_coverage,
            artifact_metal_complete,
            artifact_gpu_busy_ratio,
            artifact_metal_stage_breakdown,
            artifact_cpu_math_fallback_reason,
        }),
        error: verify_error,
    }
}

fn build_workload(kind: WorkloadKind) -> ZkfResult<WorkloadBundle> {
    match kind {
        WorkloadKind::EdlTrajectory500 => {
            let request = sample_edl_trajectory_request(EDL_MC_TRAJECTORY_STEPS);
            Ok(WorkloadBundle {
                id: kind.as_str().to_string(),
                description: kind.description().to_string(),
                program: build_edl_trajectory_program_with_steps(
                    &request,
                    EDL_MC_TRAJECTORY_STEPS,
                )?,
                witness: edl_trajectory_witness_from_request_with_steps(
                    &request,
                    EDL_MC_TRAJECTORY_STEPS,
                )?,
            })
        }
        WorkloadKind::FalconAscent187 => {
            let request = sample_falcon_ascent_request();
            Ok(WorkloadBundle {
                id: kind.as_str().to_string(),
                description: kind.description().to_string(),
                program: build_ascent_trajectory_program(&request)?,
                witness: ascent_trajectory_witness_from_request(&request)?,
            })
        }
        WorkloadKind::NarrowMetalBatch4096 => {
            build_narrow_metal_batch_workload(kind, NARROW_METAL_BATCH_INSTANCES)
        }
    }
}

fn build_narrow_metal_batch_workload(
    kind: WorkloadKind,
    instances: usize,
) -> ZkfResult<WorkloadBundle> {
    let mut signals = Vec::with_capacity(instances * 6 + 1);
    let mut constraints = Vec::with_capacity(instances * 5 + 1);
    let mut assignments = Vec::with_capacity(instances * 4 + 1);
    let mut inputs = BTreeMap::new();
    let mut accumulator_terms = Vec::with_capacity(instances);

    for index in 0..instances {
        let x = format!("x_{index}");
        let y = format!("y_{index}");
        let sum = format!("sum_{index}");
        let y_anchor = format!("y_anchor_{index}");
        let b = format!("b_{index}");
        let out = format!("out_{index}");

        signals.push(private_signal(&x));
        signals.push(private_signal(&y));
        signals.push(private_signal(&sum));
        signals.push(private_signal(&y_anchor));
        signals.push(private_signal(&b));
        signals.push(private_signal(&out));

        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&sum),
            rhs: Expr::Add(vec![Expr::signal(&x), Expr::signal(&y)]),
            label: Some(format!("sum_{index}")),
        });
        constraints.push(Constraint::Boolean {
            signal: b.clone(),
            label: Some(format!("b_boolean_{index}")),
        });
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&y_anchor),
            rhs: Expr::Mul(Box::new(Expr::signal(&y)), Box::new(Expr::signal(&y))),
            label: Some(format!("y_anchor_{index}")),
        });
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(&out),
            rhs: Expr::Mul(Box::new(Expr::signal(&sum)), Box::new(Expr::signal(&b))),
            label: Some(format!("out_{index}")),
        });

        assignments.push(WitnessAssignment {
            target: sum.clone(),
            expr: Expr::Add(vec![Expr::signal(&x), Expr::signal(&y)]),
        });
        assignments.push(WitnessAssignment {
            target: y_anchor.clone(),
            expr: Expr::Mul(Box::new(Expr::signal(&y)), Box::new(Expr::signal(&y))),
        });
        assignments.push(WitnessAssignment {
            target: out.clone(),
            expr: Expr::Mul(Box::new(Expr::signal(&sum)), Box::new(Expr::signal(&b))),
        });

        accumulator_terms.push(Expr::signal(&out));
        inputs.insert(x, FieldElement::from_u64(((index as u64) * 13 % 97) + 1));
        inputs.insert(y, FieldElement::from_u64(((index as u64) * 17 % 89) + 1));
        inputs.insert(b, FieldElement::from_u64((index & 1) as u64));
    }

    let accumulator = "batch_accumulator".to_string();
    signals.push(Signal {
        name: accumulator.clone(),
        visibility: Visibility::Public,
        constant: None,
        ty: None,
    });
    constraints.push(Constraint::Equal {
        lhs: Expr::signal(&accumulator),
        rhs: Expr::Add(accumulator_terms.clone()),
        label: Some("batch_accumulator".to_string()),
    });
    assignments.push(WitnessAssignment {
        target: accumulator.clone(),
        expr: Expr::Add(accumulator_terms),
    });

    let program = Program {
        name: format!("plonky3_narrow_metal_batch_{instances}"),
        field: FieldId::Goldilocks,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let witness = generate_witness(&program, &inputs)?;
    Ok(WorkloadBundle {
        id: kind.as_str().to_string(),
        description: kind.description().to_string(),
        program,
        witness,
    })
}

fn private_signal(name: &str) -> Signal {
    Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    }
}

fn parse_artifact_gpu_stage_coverage(
    metadata: &BTreeMap<String, String>,
) -> Option<GpuStageCoverage> {
    metadata
        .get("gpu_stage_coverage")
        .and_then(|value| serde_json::from_str::<GpuStageCoverage>(value).ok())
}

fn metadata_bool(metadata: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<bool>().ok())
}

fn metadata_f64(metadata: &BTreeMap<String, String>, key: &str) -> Option<f64> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn metadata_json(metadata: &BTreeMap<String, String>, key: &str) -> Option<Value> {
    metadata
        .get(key)
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
}

fn has_actionable_watchdog_alert(alerts: &[WatchdogAlert]) -> bool {
    alerts.iter().any(|alert| {
        alert.severity == WatchdogAlertSeverity::Critical
            || alert.recommendation != WatchdogRecommendation::Continue
    })
}

fn sample_edl_trajectory_request(steps: usize) -> EdlTrajectoryRequestV1 {
    EdlTrajectoryRequestV1 {
        initial_altitude: "100.000".to_string(),
        initial_velocity: "5.000".to_string(),
        initial_flight_path_angle: "-0.010".to_string(),
        vehicle_mass: "10.000".to_string(),
        drag_coefficient: "1.000".to_string(),
        lift_coefficient: "0.100".to_string(),
        reference_area: "5.000".to_string(),
        nose_radius: "1.000".to_string(),
        bank_angle_cosines: vec!["0.950".to_string(); steps],
        atmosphere_density: vec!["0.001".to_string(); steps],
        max_dynamic_pressure: "500.000".to_string(),
        max_heating_rate: "500.000".to_string(),
        min_altitude: "0.000".to_string(),
        gravity: "0.003".to_string(),
    }
}

fn sample_falcon_ascent_request() -> AscentTrajectoryRequestV1 {
    let steps = FALCON_HEAVY_ASCENT_STEPS;
    let mut altitude = Vec::with_capacity(steps);
    let mut velocity = Vec::with_capacity(steps);
    let mut acceleration = Vec::with_capacity(steps);
    let mut dynamic_pressure = Vec::with_capacity(steps);
    let mut throttle_pct = Vec::with_capacity(steps);
    let mut mass = Vec::with_capacity(steps);

    for i in 0..steps {
        let t = i as f64;
        altitude.push(format!("{:.3}", 100.0 + t * 960.0));
        velocity.push(format!("{:.3}", 50.0 + t * 41.0));
        acceleration.push(format!("{:.3}", 15.0 + t * 0.04));
        let q = if t < 60.0 {
            20.0 + t * 0.5
        } else {
            50.0 - (t - 60.0) * 0.2
        };
        dynamic_pressure.push(format!("{:.3}", q.max(1.0)));
        throttle_pct.push("0.900".to_string());
        mass.push(format!("{:.3}", 1_420_788.0 - t * 2600.0));
    }

    AscentTrajectoryRequestV1 {
        altitude,
        velocity,
        acceleration,
        dynamic_pressure,
        throttle_pct,
        mass,
        max_q: "50.000".to_string(),
        max_axial_load: "5.000".to_string(),
        max_lateral_load: "2.000".to_string(),
        meco_altitude_min: "100.000".to_string(),
        meco_velocity_min: "50.000".to_string(),
        gravity: "9.807".to_string(),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut out_dir = PathBuf::from(DEFAULT_OUT_DIR);
    let mut workload = WorkloadKind::EdlTrajectory500;
    let mut hours = DEFAULT_HOURS;
    let mut duration_seconds = None;
    let mut max_cycles = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => {
                out_dir = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--out-dir requires a value".to_string())?,
                );
            }
            "--workload" => {
                workload = WorkloadKind::parse(
                    &args
                        .next()
                        .ok_or_else(|| "--workload requires a value".to_string())?,
                )?;
            }
            "--hours" => {
                hours = args
                    .next()
                    .ok_or_else(|| "--hours requires a value".to_string())?
                    .parse::<f64>()
                    .map_err(|error| format!("parse --hours: {error}"))?;
            }
            "--duration-seconds" => {
                duration_seconds = Some(
                    args.next()
                        .ok_or_else(|| "--duration-seconds requires a value".to_string())?
                        .parse::<u64>()
                        .map_err(|error| format!("parse --duration-seconds: {error}"))?,
                );
            }
            "--max-cycles" => {
                max_cycles = Some(
                    args.next()
                        .ok_or_else(|| "--max-cycles requires a value".to_string())?
                        .parse::<u64>()
                        .map_err(|error| format!("parse --max-cycles: {error}"))?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: plonky3_manual_soak [--out-dir PATH] [--workload edl-trajectory-500|falcon-ascent-187|narrow-metal-batch-4096] [--hours N] [--duration-seconds N] [--max-cycles N]"
                );
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument '{other}'"));
            }
        }
    }

    Ok(Args {
        out_dir,
        workload,
        hours,
        duration_seconds,
        max_cycles,
    })
}

fn write_progress(path: &Path, progress: ProgressReport) -> ZkfResult<()> {
    write_json(path, &progress)
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

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}
