//! RuntimeCompiler and RuntimeExecutor: the public API entry points.

use crate::adapters::{
    GraphAdapter, GraphEmission, GraphParams, Groth16GraphAdapter, Plonky3GraphAdapter,
    emit_backend_fold_graph_with_context, emit_backend_prove_graph_with_context,
    emit_wrapper_graph, emit_wrapper_graph_with_context,
};
use crate::adaptive_tuning::AdaptiveThresholdScope;
use crate::api_core;
use crate::buffer_bridge::BufferBridge;
use crate::control_plane::{
    self, ControlPlaneRequest, OptimizationObjective, finalize_control_plane_execution,
};
use crate::error::RuntimeError;
use crate::execution::ExecutionContext;
use crate::execution_core;
use crate::graph::ProverGraph;
use crate::memory::UnifiedBufferPool;
use crate::memory_plan::{
    RuntimeHostSnapshot, RuntimeMemoryPlanInput, RuntimeMemoryProbe, compute_runtime_memory_plan,
    estimate_job_bytes_from_constraint_count,
};
use crate::scheduler::{DeterministicScheduler, PlacementContext};
use crate::security::SecuritySupervisor;
use crate::swarm::{SwarmConfig, SwarmController};
use crate::swarm_artifact_core::preserve_successful_proof_artifact;
use crate::telemetry::PlanExecutionResult;
use crate::telemetry_collector;
use crate::trust::{ExecutionMode, RequiredTrustLane, TrustModel};
use crate::watchdog::ProofWatchdog;
use std::sync::Arc;
use std::sync::mpsc;
use zkf_backends::{
    BackendRoute, backend_for_route, capability_report_for_backend,
    ensure_security_covered_groth16_setup, prepare_witness_for_proving,
};
use zkf_core::SupportClass;
use zkf_core::Visibility;
use zkf_core::Witness;
use zkf_core::artifact::{CompiledProgram, ProofArtifact};
use zkf_core::ir::Program;
use zkf_core::witness::{WitnessInputs, ensure_witness_completeness};
use zkf_core::wrapping::{WrapperExecutionPolicy, WrapperPreview};

/// Compiles a program description into a ProverGraph plan.
pub struct RuntimeCompiler;

fn graph_required_bytes(graph: &ProverGraph, exec_ctx: &ExecutionContext) -> u64 {
    let mut seen = std::collections::BTreeMap::<u32, usize>::new();
    for node in graph.iter_nodes() {
        for handle in node.input_buffers.iter().chain(node.output_buffers.iter()) {
            seen.entry(handle.slot)
                .and_modify(|existing| *existing = (*existing).max(handle.size_bytes))
                .or_insert(handle.size_bytes);
        }
    }
    let graph_bytes = seen
        .values()
        .fold(0u64, |acc, size| acc.saturating_add(*size as u64));
    let initial_bytes = exec_ctx
        .initial_buffers
        .values()
        .fold(0u64, |acc, bytes| acc.saturating_add(bytes.len() as u64));
    graph_bytes.saturating_add(initial_bytes)
}

fn runtime_metal_probe() -> RuntimeMemoryProbe {
    let report = zkf_backends::metal_runtime::metal_runtime_report();
    RuntimeMemoryProbe {
        recommended_working_set_size_bytes: report
            .recommended_working_set_size_bytes
            .map(|value| value as u64),
        current_allocated_size_bytes: report
            .current_allocated_size_bytes
            .map(|value| value as u64),
    }
}

fn planner_pool_limit(
    compiled_constraint_count: usize,
    job_estimate_bytes: u64,
    graph_required_bytes: Option<u64>,
) -> usize {
    let host = RuntimeHostSnapshot::detect();
    let plan = compute_runtime_memory_plan(
        &host,
        RuntimeMemoryPlanInput {
            compiled_constraint_count,
            job_estimate_bytes,
            graph_required_bytes,
            metal: runtime_metal_probe(),
        },
    );
    plan.runtime_pool_limit_bytes as usize
}

fn validate_supplied_inputs_against_witness(
    program: &Program,
    inputs: &WitnessInputs,
    witness: &Witness,
) -> Result<(), RuntimeError> {
    for (signal_name, expected_value) in inputs {
        if !program
            .signals
            .iter()
            .any(|signal| signal.name == *signal_name && signal.visibility != Visibility::Constant)
        {
            return Err(RuntimeError::WitnessGeneration(format!(
                "supplied input '{signal_name}' is not declared by the program"
            )));
        }

        let actual_value = witness.values.get(signal_name).ok_or_else(|| {
            RuntimeError::WitnessGeneration(format!(
                "supplied witness is missing declared input signal '{signal_name}'"
            ))
        })?;

        if actual_value != expected_value {
            return Err(RuntimeError::WitnessGeneration(format!(
                "supplied witness value for input '{signal_name}' does not match provided inputs"
            )));
        }
    }

    Ok(())
}

fn normalize_authoritative_witness_for_backend_prove(
    backend: zkf_core::artifact::BackendKind,
    route: BackendRoute,
    program: &Arc<Program>,
    inputs: Option<&Arc<WitnessInputs>>,
    witness: Option<Arc<Witness>>,
    compiled: Option<Arc<CompiledProgram>>,
) -> Result<NormalizedAuthoritativeWitness, RuntimeError> {
    let Some(witness) = witness else {
        return Ok((None, compiled));
    };

    if let Some(inputs) = inputs {
        validate_supplied_inputs_against_witness(program.as_ref(), inputs, witness.as_ref())?;
    }

    let compiled = match compiled {
        Some(compiled) => compiled,
        None => Arc::new(
            backend_for_route(backend, route)
                .compile(program.as_ref())
                .map_err(|error| RuntimeError::Execution(format!("compile {backend}: {error}")))?,
        ),
    };

    let prepared = if ensure_witness_completeness(&compiled.program, witness.as_ref()).is_ok() {
        witness.as_ref().clone()
    } else {
        prepare_witness_for_proving(compiled.as_ref(), witness.as_ref()).map_err(|error| {
            RuntimeError::WitnessGeneration(format!(
                "backend prove entry could not normalize supplied witness: {error}"
            ))
        })?
    };

    Ok((Some(Arc::new(prepared)), Some(compiled)))
}

type NormalizedAuthoritativeWitness = (Option<Arc<Witness>>, Option<Arc<CompiledProgram>>);

fn enforce_strict_cryptographic_backend_request(
    backend: zkf_core::artifact::BackendKind,
    route: BackendRoute,
    operator_pinned: bool,
) -> Result<(), RuntimeError> {
    let report = capability_report_for_backend(backend).ok_or_else(|| {
        RuntimeError::Execution(format!(
            "strict cryptographic lane could not resolve backend status for '{backend}'"
        ))
    })?;

    if route == BackendRoute::ExplicitCompat {
        let alias = report
            .explicit_compat_alias
            .as_deref()
            .unwrap_or("explicit-compat");
        return Err(RuntimeError::Execution(format!(
            "strict cryptographic lane rejects compatibility alias '{alias}' for backend '{backend}'; compatibility routes are never proof-bearing strict lanes"
        )));
    }

    if report.implementation_type == SupportClass::Delegated {
        return Err(RuntimeError::Execution(format!(
            "strict cryptographic lane rejects backend '{backend}' because this build only exposes a delegated surface (implementation_type={}, readiness={}, reason={}). {}",
            report.implementation_type,
            report.readiness,
            report.readiness_reason.as_deref().unwrap_or("not-ready"),
            report.operator_action.as_deref().unwrap_or(
                "Build with the native backend compiled in before requesting this backend on the strict lane."
            )
        )));
    }

    if report.assurance_lane != "native-cryptographic-proof" {
        return Err(RuntimeError::Execution(format!(
            "strict cryptographic lane rejects backend '{backend}' because assurance_lane={} is not a strict cryptographic proof lane",
            report.assurance_lane
        )));
    }

    if !report.production_ready && !operator_pinned {
        return Err(RuntimeError::Execution(format!(
            "strict cryptographic lane rejects backend '{backend}' on this host (implementation_type={}, readiness={}, reason={}). {}",
            report.implementation_type,
            report.readiness,
            report.readiness_reason.as_deref().unwrap_or("not-ready"),
            report.operator_action.as_deref().unwrap_or(
                "Choose a backend that is production-ready on this host or fix the reported operator action before retrying."
            )
        )));
    }

    Ok(())
}

impl RuntimeCompiler {
    pub fn build_plan(
        constraint_count: usize,
        field: &'static str,
        backend: &str,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<ProverGraph, RuntimeError> {
        let declared_trust = match trust {
            RequiredTrustLane::StrictCryptographic => TrustModel::Cryptographic,
            RequiredTrustLane::AllowAttestation => TrustModel::Attestation,
            RequiredTrustLane::AllowMetadataOnly => TrustModel::MetadataOnly,
        };
        let deterministic = mode == ExecutionMode::Deterministic;
        let params = GraphParams {
            constraint_count,
            field,
            deterministic,
            declared_trust,
        };

        let mut pool = UnifiedBufferPool::new(planner_pool_limit(
            constraint_count,
            estimate_job_bytes_from_constraint_count(constraint_count),
            None,
        ));

        let adapter: Box<dyn GraphAdapter> = match backend {
            "groth16" | "arkworks-groth16" => Box::new(Groth16GraphAdapter),
            "plonky3" => Box::new(Plonky3GraphAdapter),
            other => return Err(RuntimeError::UnsupportedBackend(other.to_string())),
        };

        adapter.emit_graph(&mut pool, &params)
    }

    /// Build plan with execution context (returns both graph and context).
    pub fn build_plan_with_context(
        constraint_count: usize,
        field: &'static str,
        backend: &str,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
        program: Option<Arc<Program>>,
        inputs: Option<Arc<WitnessInputs>>,
    ) -> Result<GraphEmission, RuntimeError> {
        let declared_trust = match trust {
            RequiredTrustLane::StrictCryptographic => TrustModel::Cryptographic,
            RequiredTrustLane::AllowAttestation => TrustModel::Attestation,
            RequiredTrustLane::AllowMetadataOnly => TrustModel::MetadataOnly,
        };
        let deterministic = mode == ExecutionMode::Deterministic;
        let params = GraphParams {
            constraint_count,
            field,
            deterministic,
            declared_trust,
        };

        let mut pool = UnifiedBufferPool::new(planner_pool_limit(
            constraint_count,
            estimate_job_bytes_from_constraint_count(constraint_count),
            None,
        ));

        let adapter: Box<dyn GraphAdapter> = match backend {
            "groth16" | "arkworks-groth16" => Box::new(Groth16GraphAdapter),
            "plonky3" => Box::new(Plonky3GraphAdapter),
            other => return Err(RuntimeError::UnsupportedBackend(other.to_string())),
        };

        adapter.emit_graph_with_context(&mut pool, &params, program, inputs)
    }

    pub fn build_wrapper_plan(
        preview: &WrapperPreview,
        mode: ExecutionMode,
    ) -> Result<ProverGraph, RuntimeError> {
        let deterministic = mode == ExecutionMode::Deterministic;
        let pool_ceiling = planner_pool_limit(
            preview.estimated_constraints.unwrap_or_default() as usize,
            preview
                .estimated_memory_bytes
                .or(preview.memory_budget_bytes)
                .unwrap_or(estimate_job_bytes_from_constraint_count(
                    preview.estimated_constraints.unwrap_or_default() as usize,
                )),
            None,
        );
        let mut pool = UnifiedBufferPool::new(pool_ceiling);
        emit_wrapper_graph(&mut pool, preview, deterministic)
    }

    /// Build wrapper plan with execution context.
    pub fn build_wrapper_plan_with_context(
        preview: &WrapperPreview,
        mode: ExecutionMode,
    ) -> Result<GraphEmission, RuntimeError> {
        let deterministic = mode == ExecutionMode::Deterministic;
        let pool_ceiling = planner_pool_limit(
            preview.estimated_constraints.unwrap_or_default() as usize,
            preview
                .estimated_memory_bytes
                .or(preview.memory_budget_bytes)
                .unwrap_or(estimate_job_bytes_from_constraint_count(
                    preview.estimated_constraints.unwrap_or_default() as usize,
                )),
            None,
        );
        let mut pool = UnifiedBufferPool::new(pool_ceiling);
        emit_wrapper_graph_with_context(&mut pool, preview, deterministic)
    }
}

/// Executes a ProverGraph plan.
pub struct RuntimeExecutor;

#[derive(Debug)]
pub struct BackendProofExecutionResult {
    pub result: PlanExecutionResult,
    pub compiled: CompiledProgram,
    pub artifact: ProofArtifact,
}

pub struct WrapperExecutionResult {
    pub result: PlanExecutionResult,
    pub artifact: ProofArtifact,
}

pub struct BatchBackendProofRequest {
    pub job_id: String,
    pub backend: zkf_core::artifact::BackendKind,
    pub route: BackendRoute,
    pub program: Arc<Program>,
    pub inputs: Option<Arc<WitnessInputs>>,
    pub witness: Option<Arc<Witness>>,
    pub compiled: Option<Arc<CompiledProgram>>,
    pub objective: OptimizationObjective,
    pub trust: RequiredTrustLane,
    pub mode: ExecutionMode,
    pub estimated_job_bytes: usize,
}

impl BatchBackendProofRequest {
    pub fn estimated_job_bytes(&self) -> usize {
        if self.estimated_job_bytes > 0 {
            return self.estimated_job_bytes;
        }
        let constraint_bytes = self.program.constraints.len().saturating_mul(96);
        let signal_bytes = self.program.signals.len().saturating_mul(64);
        let witness_bytes = self
            .witness
            .as_ref()
            .map(|witness| witness.values.len().saturating_mul(64))
            .unwrap_or(0);
        constraint_bytes
            .saturating_add(signal_bytes)
            .saturating_add(witness_bytes)
            .max(1)
    }
}

pub struct BatchBackendProofSuccess {
    pub compiled: CompiledProgram,
    pub artifact: ProofArtifact,
}

pub struct BatchBackendProofFailure {
    pub stage: &'static str,
    pub message: String,
}

pub enum BatchBackendProofOutcome {
    Success(Box<BatchBackendProofSuccess>),
    Failure(BatchBackendProofFailure),
}

pub struct BatchBackendProofJobResult {
    pub job_id: String,
    pub backend: zkf_core::artifact::BackendKind,
    pub route: BackendRoute,
    pub outcome: BatchBackendProofOutcome,
}

pub struct BatchBackendProofScheduler {
    pub strategy: String,
    pub requested_jobs: usize,
    pub scheduled_jobs: usize,
    pub reason: String,
    pub metal_hint: Option<serde_json::Value>,
}

pub struct BatchBackendProofBatchResult {
    pub scheduler: BatchBackendProofScheduler,
    pub results: Vec<BatchBackendProofJobResult>,
}

impl RuntimeExecutor {
    /// Contextless execution is no longer supported because UMPG now
    /// requires an `ExecutionContext` with real operands.
    pub fn run(
        _graph: ProverGraph,
        _inputs: serde_json::Value,
    ) -> Result<PlanExecutionResult, RuntimeError> {
        Err(RuntimeError::UnsupportedFeature {
            backend: "runtime".to_string(),
            feature:
                "RuntimeExecutor::run requires an ExecutionContext; use run_with_context, run_with_context_and_drivers, run_backend_job, or a wrapper plan with attached sources".to_string(),
        })
    }

    /// Real execution with an `ExecutionContext` and `BufferBridge`.
    ///
    /// Dispatches nodes to Metal or CPU drivers.  Returns proof
    /// artifact path / in-memory artifact, trace metadata, and
    /// final trust/fallback summary.
    pub fn run_with_context(
        graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
    ) -> Result<PlanExecutionResult, RuntimeError> {
        Self::run_with_context_and_drivers(graph, exec_ctx, None)
    }

    /// Real execution with an `ExecutionContext`, plus an optional GPU driver.
    pub fn run_with_context_and_drivers(
        graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
        gpu_driver: Option<&dyn crate::metal_driver::GpuDispatchDriver>,
    ) -> Result<PlanExecutionResult, RuntimeError> {
        let mut adaptive_threshold_scope = AdaptiveThresholdScope::enter();
        let host = RuntimeHostSnapshot::detect();
        let resources = host.resources.clone();
        exec_ctx.verify_wrapper_source_artifacts()?;
        let _ = execution_core::initial_buffer_plan(exec_ctx);
        let control_plane_request = build_control_plane_request(&graph, exec_ctx);
        let control_plane_decision = control_plane::evaluate_control_plane(&control_plane_request);
        let compiled_constraint_count = execution_core::effective_program(exec_ctx)
            .map(|program| program.constraints.len())
            .or_else(|| {
                exec_ctx
                    .compiled
                    .as_ref()
                    .map(|compiled| compiled.program.constraints.len())
            })
            .unwrap_or_default();
        let graph_required_bytes = graph_required_bytes(&graph, exec_ctx);
        let job_estimate_bytes = graph_required_bytes.max(
            estimate_job_bytes_from_constraint_count(compiled_constraint_count),
        );
        let memory_plan = compute_runtime_memory_plan(
            &host,
            RuntimeMemoryPlanInput {
                compiled_constraint_count,
                job_estimate_bytes,
                graph_required_bytes: Some(graph_required_bytes),
                metal: runtime_metal_probe(),
            },
        );
        let pool = UnifiedBufferPool::new(memory_plan.runtime_pool_limit_bytes as usize);
        let gpu_available =
            gpu_driver.is_some_and(|driver| driver.is_available()) && memory_plan.gpu_allowed;
        let swarm_config = SwarmConfig::from_env();
        let swarm_controller = SwarmController::new(swarm_config.clone());

        let placement_ctx = PlacementContext {
            gpu_available,
            memory_pressure: (resources.pressure.utilization_pct / 100.0).clamp(0.0, 1.0),
            gpu_cores: 0,
            deterministic_mode: false,
            chosen_dispatch_plan: Some(control_plane_decision.dispatch_plan.clone()),
            swarm_activation_level: swarm_controller.activation_level() as u8,
            gpu_working_set_headroom_bytes: memory_plan
                .metal_working_set_headroom_bytes
                .map(|value| value as usize),
            gpu_residency_budget_bytes: Some(memory_plan.metal_residency_budget_bytes as usize),
            low_memory_mode: memory_plan.low_memory_mode,
        };

        let mut scheduler = DeterministicScheduler::new(pool, placement_ctx);
        let watchdog = ProofWatchdog::new(
            &zkf_core::PlatformCapability::detect(),
            false,
            swarm_config
                .enabled
                .then_some(swarm_config.sentinel.clone()),
        );
        scheduler.attach_watchdog(watchdog.clone());
        scheduler.attach_swarm(swarm_controller.clone());
        let mut bridge = BufferBridge::with_temp_spill();
        bridge.set_resident_limit_bytes(Some(memory_plan.bridge_resident_limit_bytes as usize));
        if gpu_available
            && let Some(allocator) = crate::metal_driver::create_metal_buffer_allocator()
        {
            bridge.set_gpu_allocator(allocator);
        }
        let mut report =
            scheduler.execute_with_context_and_drivers(graph, exec_ctx, &mut bridge, gpu_driver)?;
        report.peak_memory_bytes = report.peak_memory_bytes.max(bridge.peak_resident_bytes());
        adaptive_threshold_scope.finish(&report);
        let produced_artifact = execution_core::preferred_output_artifact(exec_ctx);
        let expected_proof_size = control_plane_decision
            .anomaly_baseline
            .expected_proof_size_bytes;
        let observed_proof_size = produced_artifact.map(|artifact| artifact.proof.len() as u64);
        let (watchdog_alerts, threat_digests) =
            watchdog.finalize_with_digests(expected_proof_size, observed_proof_size);
        report.watchdog_alerts = watchdog_alerts;
        swarm_controller.record_digests(&threat_digests);
        if let Ok(count) = crate::swarm::builder::pattern_count() {
            swarm_controller.note_builder_pattern_count(count);
        }
        let control_plane = Some(finalize_control_plane_execution(
            control_plane_decision,
            &report,
            produced_artifact,
        ));
        let security = Some(SecuritySupervisor::evaluate(
            &report,
            control_plane.as_ref(),
            None,
            Some(&swarm_controller.verdict()),
        ));

        let mut outputs = api_core::build_runtime_outputs(
            exec_ctx,
            &report,
            control_plane.as_ref(),
            security.as_ref(),
        );
        if let Some(map) = outputs.as_object_mut() {
            map.insert(
                "runtime_memory_plan".into(),
                serde_json::to_value(&memory_plan).unwrap_or_else(|_| serde_json::json!({})),
            );
            map.insert(
                "runtime_buffer_bridge".into(),
                serde_json::to_value(bridge.stats()).unwrap_or_else(|_| serde_json::json!({})),
            );
        }

        Ok(PlanExecutionResult {
            report,
            outputs,
            control_plane,
            security: security.as_ref().map(|value| value.verdict.clone()),
            model_integrity: security.map(|value| value.model_integrity),
            swarm: swarm_controller.telemetry_digest(),
        })
    }

    /// Convenience: build plan from backend/program/inputs and execute
    /// through the real scheduler path.
    pub fn run_backend_job(
        backend: &str,
        program: Arc<Program>,
        inputs: Arc<WitnessInputs>,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<PlanExecutionResult, RuntimeError> {
        let constraint_count = program.constraints.len();
        let field = match program.field {
            zkf_core::FieldId::Bn254 => "bn254_fr",
            zkf_core::FieldId::Goldilocks => "goldilocks",
            zkf_core::FieldId::BabyBear => "babybear",
            zkf_core::FieldId::Bls12_381 => "bls12_381",
            _ => "bn254_fr",
        };

        let emission = RuntimeCompiler::build_plan_with_context(
            constraint_count,
            field,
            backend,
            trust,
            mode,
            Some(program),
            Some(inputs),
        )?;

        let mut exec_ctx = emission.exec_ctx;
        Self::run_with_context(emission.graph, &mut exec_ctx)
    }

    /// Convenience: build wrapper plan and execute through the real
    /// scheduler path. This fails closed without attached source artifacts.
    pub fn run_wrapper_job(
        preview: &WrapperPreview,
        mode: ExecutionMode,
    ) -> Result<PlanExecutionResult, RuntimeError> {
        let emission = RuntimeCompiler::build_wrapper_plan_with_context(preview, mode)?;
        let mut exec_ctx = emission.exec_ctx;
        Self::run_with_context(emission.graph, &mut exec_ctx).map_err(|err| match err {
            RuntimeError::UnsupportedFeature { backend, feature } if backend == "runtime-wrapper" => {
                RuntimeError::UnsupportedFeature {
                    backend,
                    feature: format!(
                        "{feature}; attach a source proof artifact, compiled artifact, and wrapper policy before executing the wrapper graph"
                    ),
                }
            }
            other => other,
        })
    }

    /// Convenience: build wrapper plan with sources attached and execute it
    /// through the native runtime scheduler path.
    pub fn run_wrapper_job_with_sources(
        preview: &WrapperPreview,
        source_proof: Arc<ProofArtifact>,
        compiled: Arc<CompiledProgram>,
        policy: WrapperExecutionPolicy,
        mode: ExecutionMode,
    ) -> Result<WrapperExecutionResult, RuntimeError> {
        let emission = RuntimeCompiler::build_wrapper_plan_with_context(preview, mode)?;
        let mut exec_ctx = emission.exec_ctx;
        exec_ctx.source_proof = Some(source_proof);
        exec_ctx.compiled = Some(Arc::clone(&compiled));
        exec_ctx.set_wrapper_policy(policy);
        let result = Self::run_with_context(emission.graph, &mut exec_ctx)?;
        let artifact = preserve_successful_proof_artifact(
            exec_ctx.take_wrapped_artifact().ok_or_else(|| {
                RuntimeError::Execution(
                    "runtime wrapper job did not materialize a wrapped artifact".into(),
                )
            })?,
        );
        if let Err(err) = telemetry_collector::emit_wrap_telemetry(
            preview,
            exec_ctx.compiled.as_deref().unwrap_or(compiled.as_ref()),
            &result.report,
            &artifact,
            result.control_plane.as_ref(),
            result.security.as_ref(),
            result.model_integrity.as_ref(),
            result.swarm.as_ref(),
        ) {
            log::warn!("failed to persist wrap telemetry: {err}");
        }
        Ok(WrapperExecutionResult { result, artifact })
    }

    /// Build a delegated backend-prove graph and execute it under UMPG.
    #[allow(clippy::too_many_arguments)]
    pub fn run_backend_prove_job(
        backend: zkf_core::artifact::BackendKind,
        route: BackendRoute,
        program: Arc<Program>,
        inputs: Option<Arc<WitnessInputs>>,
        witness: Option<Arc<Witness>>,
        compiled: Option<Arc<CompiledProgram>>,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<BackendProofExecutionResult, RuntimeError> {
        Self::run_backend_prove_job_with_objective(
            backend,
            route,
            program,
            inputs,
            witness,
            compiled,
            OptimizationObjective::FastestProve,
            trust,
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_backend_prove_job_with_objective(
        backend: zkf_core::artifact::BackendKind,
        route: BackendRoute,
        program: Arc<Program>,
        inputs: Option<Arc<WitnessInputs>>,
        witness: Option<Arc<Witness>>,
        compiled: Option<Arc<CompiledProgram>>,
        objective: OptimizationObjective,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<BackendProofExecutionResult, RuntimeError> {
        let declared_trust = match trust {
            RequiredTrustLane::StrictCryptographic => TrustModel::Cryptographic,
            RequiredTrustLane::AllowAttestation => TrustModel::Attestation,
            RequiredTrustLane::AllowMetadataOnly => TrustModel::MetadataOnly,
        };
        if trust == RequiredTrustLane::StrictCryptographic {
            enforce_strict_cryptographic_backend_request(backend, route, true)?;
        }
        let deterministic = mode == ExecutionMode::Deterministic;
        let (witness, compiled) = normalize_authoritative_witness_for_backend_prove(
            backend,
            route,
            &program,
            inputs.as_ref(),
            witness,
            compiled,
        )?;
        let mut pool = UnifiedBufferPool::new(planner_pool_limit(
            program.constraints.len(),
            estimate_job_bytes_from_constraint_count(program.constraints.len()),
            None,
        ));
        let mut emission = emit_backend_prove_graph_with_context(
            &mut pool,
            backend,
            route,
            Arc::clone(&program),
            inputs,
            witness,
            declared_trust,
            deterministic,
        )?;
        emission.exec_ctx.requested_backend = Some(backend);
        emission.exec_ctx.requested_backend_route = Some(route);
        emission.exec_ctx.requested_backend_candidates = Some(vec![backend]);
        if let Some(compiled) = compiled {
            emission.exec_ctx.compiled = Some(compiled);
        }
        emission.exec_ctx.optimization_objective = objective;
        let result = Self::run_with_context(emission.graph, &mut emission.exec_ctx)?;
        let compiled = emission
            .exec_ctx
            .compiled
            .as_ref()
            .map(|value| value.as_ref().clone())
            .ok_or_else(|| {
                RuntimeError::Execution(
                    "runtime backend prove did not materialize a compiled artifact".into(),
                )
            })?;
        if trust == RequiredTrustLane::StrictCryptographic {
            ensure_security_covered_groth16_setup(&compiled)
                .map_err(|err| RuntimeError::Execution(err.to_string()))?;
        }
        let artifact = preserve_successful_proof_artifact(
            emission.exec_ctx.take_proof_artifact().ok_or_else(|| {
                RuntimeError::Execution(
                    "runtime backend prove did not materialize a proof artifact".into(),
                )
            })?,
        );
        if let Err(err) = telemetry_collector::emit_prove_telemetry(
            program.as_ref(),
            &compiled,
            emission.exec_ctx.witness.as_deref(),
            emission.exec_ctx.witness_inputs.as_deref(),
            &result.report,
            &artifact,
            result.control_plane.as_ref(),
            result.security.as_ref(),
            result.model_integrity.as_ref(),
            result.swarm.as_ref(),
        ) {
            log::warn!("failed to persist prove telemetry: {err}");
        }
        Ok(BackendProofExecutionResult {
            result,
            compiled,
            artifact,
        })
    }

    /// Execute a batch of backend proving jobs and return per-job proof artifacts
    /// or structured failures. On Apple hosts with Metal available, the low-level
    /// job scheduling is delegated to `zkf-metal::BatchProver`; otherwise this
    /// runs through a CPU thread pool.
    pub fn run_backend_prove_batch(
        requests: Vec<BatchBackendProofRequest>,
        requested_jobs: Option<usize>,
    ) -> BatchBackendProofBatchResult {
        if requests.is_empty() {
            return BatchBackendProofBatchResult {
                scheduler: BatchBackendProofScheduler {
                    strategy: "empty".to_string(),
                    requested_jobs: requested_jobs.unwrap_or(0),
                    scheduled_jobs: 0,
                    reason: "no batch jobs requested".to_string(),
                    metal_hint: None,
                },
                results: Vec::new(),
            };
        }

        let total_jobs = requests.len();
        let requested_jobs = requested_jobs.unwrap_or_else(default_requested_jobs);
        let estimated_job_bytes = requests
            .iter()
            .map(BatchBackendProofRequest::estimated_job_bytes)
            .max()
            .unwrap_or(1);

        #[cfg(target_os = "macos")]
        {
            let job_headers = requests
                .iter()
                .map(|request| (request.job_id.clone(), request.backend, request.route))
                .collect::<Vec<_>>();
            let hint = zkf_metal::recommend_job_count(
                total_jobs,
                Some(requested_jobs),
                estimated_job_bytes,
            );
            if let Some(mut prover) = zkf_metal::BatchProver::new(hint.recommended_jobs.max(1)) {
                let (tx, rx) = mpsc::channel::<(usize, BatchBackendProofJobResult)>();
                for (idx, request) in requests.into_iter().enumerate() {
                    let tx = tx.clone();
                    let estimated = request.estimated_job_bytes();
                    prover.add_named_job(Some(request.job_id.clone()), estimated, move || {
                        let result = execute_batch_backend_request(request);
                        let proof = match &result.outcome {
                            BatchBackendProofOutcome::Success(success) => {
                                Ok(success.artifact.clone())
                            }
                            BatchBackendProofOutcome::Failure(failure) => {
                                Err(failure.message.clone())
                            }
                        };
                        let _ = tx.send((idx, result));
                        proof
                    });
                }
                drop(tx);

                let _ = prover.prove_all();
                let mut ordered = std::iter::repeat_with(|| None)
                    .take(total_jobs)
                    .collect::<Vec<Option<BatchBackendProofJobResult>>>();
                for (idx, result) in rx {
                    ordered[idx] = Some(result);
                }
                for idx in 0..total_jobs {
                    if ordered[idx].is_none() {
                        let (job_id, backend, route) = &job_headers[idx];
                        let fallback = BatchBackendProofJobResult {
                            job_id: job_id.clone(),
                            backend: *backend,
                            route: *route,
                            outcome: BatchBackendProofOutcome::Failure(BatchBackendProofFailure {
                                stage: "scheduler",
                                message: prover
                                    .job_error(idx)
                                    .unwrap_or("batch prover did not return a result")
                                    .to_string(),
                            }),
                        };
                        ordered[idx] = Some(fallback);
                    }
                }
                return BatchBackendProofBatchResult {
                    scheduler: BatchBackendProofScheduler {
                        strategy: if hint.metal_available {
                            "metal-batch-prover".to_string()
                        } else {
                            "cpu-fallback".to_string()
                        },
                        requested_jobs,
                        scheduled_jobs: hint.recommended_jobs,
                        reason: hint.reason.clone(),
                        metal_hint: serde_json::to_value(&hint).ok(),
                    },
                    results: ordered.into_iter().flatten().collect(),
                };
            }
        }

        run_batch_backend_requests_cpu(requests, requested_jobs, estimated_job_bytes)
    }

    /// Build a native backend-fold graph and execute it under UMPG.
    pub fn run_backend_fold_job(
        compiled: Arc<CompiledProgram>,
        witnesses: Arc<Vec<Witness>>,
        compress: bool,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<BackendProofExecutionResult, RuntimeError> {
        Self::run_backend_fold_job_with_objective(
            compiled,
            witnesses,
            compress,
            OptimizationObjective::FastestProve,
            trust,
            mode,
        )
    }

    /// Build a native backend-fold graph and execute it under UMPG with an explicit objective.
    pub fn run_backend_fold_job_with_objective(
        compiled: Arc<CompiledProgram>,
        witnesses: Arc<Vec<Witness>>,
        compress: bool,
        objective: OptimizationObjective,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<BackendProofExecutionResult, RuntimeError> {
        let declared_trust = match trust {
            RequiredTrustLane::StrictCryptographic => TrustModel::Cryptographic,
            RequiredTrustLane::AllowAttestation => TrustModel::Attestation,
            RequiredTrustLane::AllowMetadataOnly => TrustModel::MetadataOnly,
        };
        if trust == RequiredTrustLane::StrictCryptographic {
            enforce_strict_cryptographic_backend_request(
                compiled.backend,
                BackendRoute::Auto,
                true,
            )?;
        }
        let deterministic = mode == ExecutionMode::Deterministic;
        let mut pool = UnifiedBufferPool::new(planner_pool_limit(
            compiled.program.constraints.len(),
            estimate_job_bytes_from_constraint_count(compiled.program.constraints.len()),
            None,
        ));
        let mut emission = emit_backend_fold_graph_with_context(
            &mut pool,
            Arc::clone(&compiled),
            witnesses,
            compress,
            declared_trust,
            deterministic,
        )?;
        emission.exec_ctx.optimization_objective = objective;
        let result = Self::run_with_context(emission.graph, &mut emission.exec_ctx)?;
        let compiled = emission
            .exec_ctx
            .compiled
            .as_ref()
            .map(|value| value.as_ref().clone())
            .ok_or_else(|| {
                RuntimeError::Execution(
                    "runtime backend fold did not retain the compiled artifact".into(),
                )
            })?;
        let artifact = preserve_successful_proof_artifact(
            emission.exec_ctx.take_proof_artifact().ok_or_else(|| {
                RuntimeError::Execution(
                    "runtime backend fold did not materialize a proof artifact".into(),
                )
            })?,
        );
        if let Err(err) = telemetry_collector::emit_fold_telemetry(
            &compiled,
            emission
                .exec_ctx
                .fold_witnesses
                .as_deref()
                .map_or(&[][..], |value| value.as_slice()),
            compress,
            &result.report,
            &artifact,
            result.control_plane.as_ref(),
            result.security.as_ref(),
            result.model_integrity.as_ref(),
            result.swarm.as_ref(),
        ) {
            log::warn!("failed to persist fold telemetry: {err}");
        }
        Ok(BackendProofExecutionResult {
            result,
            compiled,
            artifact,
        })
    }
}

fn default_requested_jobs() -> usize {
    api_core::default_requested_jobs()
}

fn execute_batch_backend_request(request: BatchBackendProofRequest) -> BatchBackendProofJobResult {
    let BatchBackendProofRequest {
        job_id,
        backend,
        route,
        program,
        inputs,
        witness,
        compiled,
        objective,
        trust,
        mode,
        ..
    } = request;

    if let Some(compiled) = &compiled
        && compiled.program_digest != program.digest_hex()
    {
        return BatchBackendProofJobResult {
            job_id,
            backend,
            route,
            outcome: BatchBackendProofOutcome::Failure(BatchBackendProofFailure {
                stage: "compile",
                message: "provided compiled artifact does not match batch program digest".into(),
            }),
        };
    }

    let result = RuntimeExecutor::run_backend_prove_job_with_objective(
        backend,
        route,
        Arc::clone(&program),
        inputs,
        witness,
        compiled,
        objective,
        trust,
        mode,
    );

    let outcome = match result {
        Ok(success) => BatchBackendProofOutcome::Success(Box::new(BatchBackendProofSuccess {
            compiled: success.compiled,
            artifact: success.artifact,
        })),
        Err(err) => BatchBackendProofOutcome::Failure(BatchBackendProofFailure {
            stage: "runtime",
            message: err.to_string(),
        }),
    };

    BatchBackendProofJobResult {
        job_id,
        backend,
        route,
        outcome,
    }
}

fn run_batch_backend_requests_cpu(
    requests: Vec<BatchBackendProofRequest>,
    requested_jobs: usize,
    estimated_job_bytes: usize,
) -> BatchBackendProofBatchResult {
    let total_jobs = requests.len();
    let scheduler_plan =
        api_core::cpu_batch_scheduler_plan(total_jobs, requested_jobs, estimated_job_bytes);
    let queue = Arc::new(std::sync::Mutex::new(api_core::queue_batch_requests(
        requests,
    )));
    let (tx, rx) = mpsc::channel::<(usize, BatchBackendProofJobResult)>();

    let mut handles = Vec::with_capacity(scheduler_plan.scheduled_jobs);
    for _ in 0..scheduler_plan.scheduled_jobs {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            loop {
                let next = match queue.lock() {
                    Ok(mut guard) => guard.pop_front(),
                    Err(poisoned) => poisoned.into_inner().pop_front(),
                };
                let Some((idx, request)) = next else {
                    break;
                };
                let result = execute_batch_backend_request(request);
                let _ = tx.send((idx, result));
            }
        }));
    }
    drop(tx);

    let mut ordered = std::iter::repeat_with(|| None)
        .take(total_jobs)
        .collect::<Vec<Option<BatchBackendProofJobResult>>>();
    for (idx, result) in rx {
        ordered[idx] = Some(result);
    }
    for handle in handles {
        let _ = handle.join();
    }

    BatchBackendProofBatchResult {
        scheduler: BatchBackendProofScheduler {
            strategy: "cpu-thread-pool".to_string(),
            requested_jobs: scheduler_plan.requested_jobs,
            scheduled_jobs: scheduler_plan.scheduled_jobs,
            reason: scheduler_plan.reason,
            metal_hint: None,
        },
        results: ordered.into_iter().flatten().collect(),
    }
}

fn build_control_plane_request<'a>(
    graph: &'a ProverGraph,
    exec_ctx: &'a ExecutionContext,
) -> ControlPlaneRequest<'a> {
    api_core::build_control_plane_request(graph, exec_ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::emit_backend_prove_graph_with_context;
    use crate::memory::UnifiedBufferPool;
    use crate::trust::TrustModel;
    use zkf_backends::backend_for_route;
    use zkf_core::ir::{Constraint, Expr, Signal, Visibility, WitnessPlan};
    use zkf_core::{FieldElement, FieldId, SupportClass};

    fn sample_program() -> Program {
        Program {
            name: "batch-runtime-sample".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "sum".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Program::default()
        }
    }

    fn witness(x: i64, y: i64) -> Witness {
        Witness {
            values: std::collections::BTreeMap::from([
                ("x".to_string(), FieldElement::from_i64(x)),
                ("y".to_string(), FieldElement::from_i64(y)),
                ("sum".to_string(), FieldElement::from_i64(x + y)),
            ]),
        }
    }

    #[test]
    fn batch_backend_prove_returns_real_artifacts() {
        let program = Arc::new(sample_program());
        let requests = vec![
            BatchBackendProofRequest {
                job_id: "job-a".to_string(),
                backend: zkf_core::artifact::BackendKind::ArkworksGroth16,
                route: BackendRoute::Auto,
                program: Arc::clone(&program),
                inputs: None,
                witness: Some(Arc::new(witness(2, 5))),
                compiled: None,
                objective: OptimizationObjective::FastestProve,
                trust: RequiredTrustLane::StrictCryptographic,
                mode: ExecutionMode::Deterministic,
                estimated_job_bytes: 0,
            },
            BatchBackendProofRequest {
                job_id: "job-b".to_string(),
                backend: zkf_core::artifact::BackendKind::ArkworksGroth16,
                route: BackendRoute::Auto,
                program,
                inputs: None,
                witness: Some(Arc::new(witness(7, 9))),
                compiled: None,
                objective: OptimizationObjective::FastestProve,
                trust: RequiredTrustLane::StrictCryptographic,
                mode: ExecutionMode::Deterministic,
                estimated_job_bytes: 0,
            },
        ];

        let batch = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
            RuntimeExecutor::run_backend_prove_batch(requests, Some(2))
        });
        assert_eq!(batch.results.len(), 2);
        assert!(batch.scheduler.scheduled_jobs >= 1);

        for result in batch.results {
            match result.outcome {
                BatchBackendProofOutcome::Success(success) => {
                    let engine = backend_for_route(result.backend, result.route);
                    assert!(
                        engine
                            .verify(&success.compiled, &success.artifact)
                            .expect("verify should succeed"),
                        "artifact must verify for {}",
                        result.job_id
                    );
                }
                BatchBackendProofOutcome::Failure(failure) => {
                    panic!(
                        "unexpected batch failure in {}: {}",
                        result.job_id, failure.message
                    );
                }
            }
        }
    }

    #[test]
    fn batch_backend_prove_rejects_mismatched_compiled_artifact() {
        let program = Arc::new(sample_program());
        let mismatched = Program {
            name: "other".to_string(),
            ..sample_program()
        };
        let engine = backend_for_route(
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
        );
        let compiled = engine
            .compile(&mismatched)
            .expect("compile mismatched program");

        let batch = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
            RuntimeExecutor::run_backend_prove_batch(
                vec![BatchBackendProofRequest {
                    job_id: "bad-compiled".to_string(),
                    backend: zkf_core::artifact::BackendKind::ArkworksGroth16,
                    route: BackendRoute::Auto,
                    program,
                    inputs: None,
                    witness: Some(Arc::new(witness(1, 1))),
                    compiled: Some(Arc::new(compiled)),
                    objective: OptimizationObjective::FastestProve,
                    trust: RequiredTrustLane::StrictCryptographic,
                    mode: ExecutionMode::Deterministic,
                    estimated_job_bytes: 0,
                }],
                Some(1),
            )
        });

        assert_eq!(batch.results.len(), 1);
        match &batch.results[0].outcome {
            BatchBackendProofOutcome::Failure(failure) => {
                assert_eq!(failure.stage, "compile");
                assert!(failure.message.contains("does not match"));
            }
            BatchBackendProofOutcome::Success(_) => {
                panic!("mismatched compiled artifact should fail");
            }
        }
    }

    #[test]
    fn strict_runtime_lane_rejects_deterministic_groth16_artifacts() {
        let program = Arc::new(sample_program());
        let result = RuntimeExecutor::run_backend_prove_job_with_objective(
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
            Arc::clone(&program),
            None,
            Some(Arc::new(witness(2, 3))),
            None,
            OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        );
        let err = match result {
            Ok(_) => panic!("strict cryptographic lane should reject deterministic Groth16 setup"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("requires imported trusted CRS material"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_runtime_preflight_allows_operator_pinned_arkworks_backend() {
        enforce_strict_cryptographic_backend_request(
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
            true,
        )
        .expect("operator-pinned strict request should survive readiness preflight");
    }

    #[test]
    fn strict_runtime_preflight_rejects_unpinned_nonproduction_backend() {
        let err = enforce_strict_cryptographic_backend_request(
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
            false,
        )
        .expect_err("unpinned non-production backend should be rejected");

        assert!(
            err.to_string()
                .contains("upstream-ark-groth16-production-disclaimer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_runtime_lane_rejects_explicit_compat_routes_before_execution() {
        let program = Arc::new(sample_program());
        let err = RuntimeExecutor::run_backend_prove_job_with_objective(
            zkf_core::artifact::BackendKind::Sp1,
            BackendRoute::ExplicitCompat,
            program,
            None,
            Some(Arc::new(witness(2, 3))),
            None,
            OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .expect_err("strict lane should reject explicit compatibility routes");

        assert!(
            err.to_string().contains("rejects compatibility alias"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn strict_runtime_lane_rejects_delegated_native_surfaces() {
        let surface = zkf_backends::backend_surface_status(zkf_core::artifact::BackendKind::Nova);
        if surface.implementation_type != SupportClass::Delegated {
            return;
        }

        let program = Arc::new(sample_program());
        let err = RuntimeExecutor::run_backend_prove_job_with_objective(
            zkf_core::artifact::BackendKind::Nova,
            BackendRoute::Auto,
            program,
            None,
            Some(Arc::new(witness(2, 3))),
            None,
            OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .expect_err("strict lane should reject delegated native-auto surfaces");

        assert!(
            err.to_string().contains("only exposes a delegated surface"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn explicit_backend_compiled_request_uses_single_backend_candidate_set() {
        let program = Arc::new(sample_program());
        let compiled = backend_for_route(
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
        )
        .compile(program.as_ref())
        .expect("compile should succeed");

        let mut pool = UnifiedBufferPool::new(8 * 1024 * 1024);
        let mut emission = emit_backend_prove_graph_with_context(
            &mut pool,
            zkf_core::artifact::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
            Arc::clone(&program),
            None,
            Some(Arc::new(witness(2, 3))),
            TrustModel::Cryptographic,
            true,
        )
        .expect("graph emission should succeed");
        emission.exec_ctx.requested_backend =
            Some(zkf_core::artifact::BackendKind::ArkworksGroth16);
        emission.exec_ctx.requested_backend_route = Some(BackendRoute::Auto);
        emission.exec_ctx.requested_backend_candidates =
            Some(vec![zkf_core::artifact::BackendKind::ArkworksGroth16]);
        emission.exec_ctx.compiled = Some(Arc::new(compiled));

        let request = build_control_plane_request(&emission.graph, &emission.exec_ctx);
        assert_eq!(
            request.requested_backend,
            Some(zkf_core::artifact::BackendKind::ArkworksGroth16)
        );
        assert_eq!(
            request.backend_candidates,
            vec![zkf_core::artifact::BackendKind::ArkworksGroth16]
        );
        assert_eq!(request.backend_route, Some(BackendRoute::Auto));
    }

    #[test]
    fn field_default_backend_candidates_follow_runtime_policy() {
        let expected = [
            (
                zkf_core::FieldId::Bn254,
                vec![
                    zkf_core::artifact::BackendKind::ArkworksGroth16,
                    zkf_core::artifact::BackendKind::Plonky3,
                ],
            ),
            (
                zkf_core::FieldId::Bls12_381,
                vec![
                    zkf_core::artifact::BackendKind::Halo2Bls12381,
                    zkf_core::artifact::BackendKind::ArkworksGroth16,
                ],
            ),
            (
                zkf_core::FieldId::PastaFp,
                vec![
                    zkf_core::artifact::BackendKind::Halo2,
                    zkf_core::artifact::BackendKind::ArkworksGroth16,
                ],
            ),
            (
                zkf_core::FieldId::Goldilocks,
                vec![
                    zkf_core::artifact::BackendKind::Plonky3,
                    zkf_core::artifact::BackendKind::ArkworksGroth16,
                ],
            ),
        ];

        for (field, prefix) in expected {
            let mut program = sample_program();
            program.field = field;
            let candidates = api_core::default_backend_candidates(Some(&program), None);
            assert!(
                candidates.starts_with(&prefix),
                "unexpected candidates for {field:?}: {candidates:?}"
            );
        }
    }

    #[test]
    fn wrapper_projection_prefers_target_backend_candidates() {
        let mut ctx = ExecutionContext::new();
        ctx.wrapper_preview = Some(WrapperPreview {
            wrapper: "plonky3-to-groth16".to_string(),
            source_backend: zkf_core::artifact::BackendKind::Plonky3,
            target_backend: zkf_core::artifact::BackendKind::ArkworksGroth16,
            planned_status: "ready".to_string(),
            strategy: "wrap".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: None,
            estimated_constraints: Some(1024),
            estimated_memory_bytes: Some(8 * 1024 * 1024),
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: None,
        });
        ctx.requested_backend = Some(zkf_core::artifact::BackendKind::Nova);
        ctx.requested_backend_candidates = Some(vec![zkf_core::artifact::BackendKind::Nova]);

        let projection = api_core::project_control_plane_inputs(&ctx);
        assert_eq!(
            projection.requested_backend,
            Some(zkf_core::artifact::BackendKind::ArkworksGroth16)
        );
        assert_eq!(
            projection.backend_candidates,
            vec![zkf_core::artifact::BackendKind::ArkworksGroth16]
        );
    }
}
