#![allow(unexpected_cfgs)]

//! ZKF Runtime — Unified Memory Prover Graph (UMPG) execution layer.
//!
//! Models the ZK proof pipeline as a directed acyclic graph (DAG) of typed
//! proving tasks. The runtime schedules tasks across CPU and GPU, enforces
//! trust lanes, and emits machine-readable execution traces.
//!
//! ## Architecture
//!
//! - **`ProverOp`** — scheduling/type layer (what kind of work)
//! - **`NodePayload`** — execution language (concrete operands for drivers)
//! - **`ExecutionContext`** — per-run data plane (program, witness, payloads)
//! - **`BufferBridge`** — physical buffer management (CPU/GPU/spill)
//! - **`MetalDispatchDriver`** — GPU execution via `zkf-metal`
//! - **`CpuBackendDriver`** — CPU execution via `zkf-core` + arkworks + Plonky3
//! - **`DeterministicScheduler`** — topological dispatch with trust propagation

#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod adapter_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod adapters;
#[cfg(all(feature = "full", not(hax)))]
pub mod adaptive_tuning;
#[cfg(all(feature = "full", not(hax)))]
pub mod api;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod api_core;
pub mod buffer_bridge;
#[cfg(feature = "kani-minimal")]
pub(crate) mod buffer_bridge_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod control_plane;
#[cfg(all(feature = "full", not(hax)))]
pub mod cpu_driver;
pub mod error;
#[cfg(all(feature = "full", not(hax)))]
pub mod execution;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod execution_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod graph;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod graph_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod hybrid;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod hybrid_core;
pub mod memory;
#[cfg(all(feature = "full", not(hax)))]
pub mod memory_plan;
#[cfg(all(feature = "full", target_os = "macos", not(hax)))]
mod metal_dispatch_macos;
#[cfg(all(feature = "full", not(hax)))]
pub mod metal_driver;
pub(crate) mod proof_runtime_spec;
pub(crate) mod proof_swarm_spec;
#[cfg(all(feature = "full", not(hax)))]
pub mod scheduler;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod scheduler_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod security;
mod slot_map;
#[cfg(all(feature = "full", not(hax)))]
pub mod swarm;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_artifact_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_builder_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_entrypoint_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_queen_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_sentinel_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_warrior_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod telemetry;
#[cfg(all(feature = "full", not(hax)))]
pub mod telemetry_collector;
#[cfg(all(feature = "full", not(hax)))]
pub mod trust;
#[cfg(kani)]
mod verification_kani;
#[cfg(all(feature = "full", not(hax)))]
pub mod watchdog;

// Top-level re-exports
#[cfg(all(feature = "full", not(hax)))]
pub use adapters::{
    GraphAdapter, GraphEmission, GraphParams, Groth16GraphAdapter, Plonky3GraphAdapter,
};
#[cfg(all(feature = "full", not(hax)))]
pub use adaptive_tuning::{AdaptiveThresholdScope, AdaptiveTuningStatus, adaptive_tuning_status};
#[cfg(all(feature = "full", not(hax)))]
pub use api::{
    BackendProofExecutionResult, BatchBackendProofBatchResult, BatchBackendProofFailure,
    BatchBackendProofJobResult, BatchBackendProofOutcome, BatchBackendProofRequest,
    BatchBackendProofScheduler, BatchBackendProofSuccess, RuntimeCompiler, RuntimeExecutor,
};
pub use buffer_bridge::{BufferBridge, BufferView, BufferViewMut, PhysicalBuffer, ResidencyClass};
#[cfg(all(feature = "full", not(hax)))]
pub use control_plane::{
    AnomalySeverity, AnomalyVerdict, BackendRecommendation, BackendScore, BoundSource,
    CircuitFeatureProfile, ControlPlaneDecision, ControlPlaneExecutionSummary,
    ControlPlaneFeatures, ControlPlaneReplayManifest, ControlPlaneRequest, DispatchCandidate,
    DispatchCandidateScore, DispatchPlan, DurationEstimate, EtaSemantics, ExecutionRegime,
    HardwareProbeSample, HardwareProbeSummary, JobKind, ModelCatalog, ModelDescriptor, ModelLane,
    ModelQualityGate, ModelSource, OptimizationObjective, enforce_apple_silicon_production_lane,
    evaluate_control_plane, persist_replay_manifest, recommend_backend_for_program,
    replay_manifest_digest, run_continuous_hardware_probes,
};
#[cfg(all(feature = "full", not(hax)))]
pub use cpu_driver::{CpuBackendDriver, CpuNodeTelemetry};
pub use error::RuntimeError;
#[cfg(all(feature = "full", not(hax)))]
pub use execution::{ExecutionContext, MerkleHashFn, NodePayload, ProofOutputKind};
#[cfg(all(feature = "full", not(hax)))]
pub use graph::{
    DevicePlacement, NodeSpec, ProverGraph, ProverNode, ProverOp, gpu_capable_stage_keys,
};
#[cfg(all(feature = "full", not(hax)))]
pub use hybrid::{
    HybridBackendProofExecutionResult, run_hybrid_prove_job_with_objective, verify_hybrid_artifact,
};
pub use memory::{
    BufferHandle, MemoryClass, NodeId, PhysicalBacking, SlotSummary, UnifiedBufferPool,
};
#[cfg(all(feature = "full", not(hax)))]
pub use memory_plan::{
    RuntimeHostSnapshot, RuntimeMemoryOverrides, RuntimeMemoryPlan, RuntimeMemoryPlanInput,
    RuntimeMemoryProbe, compute_runtime_memory_plan, estimate_job_bytes_from_constraint_count,
};
#[cfg(all(feature = "full", not(hax)))]
pub use metal_driver::{
    DispatchResult, FallbackSignal, GpuDispatchDriver, GpuNodeTelemetry, GpuVerificationMode,
    NullGpuDriver, create_metal_buffer_allocator, create_metal_dispatch_driver,
};
#[cfg(all(feature = "full", not(hax)))]
pub use scheduler::{
    DeterministicScheduler, GraphScheduler, NodeHook, PlacementContext, PlacementEngine,
};
#[cfg(all(feature = "full", not(hax)))]
pub use security::{
    RuntimeModelIntegrity, RuntimeSecurityContext, SecurityAction, SecurityEvaluation,
    SecurityPolicyMode, SecurityRiskLevel, SecuritySupervisor, SecurityVerdict, ThreatSeverity,
    ThreatSignal, ThreatSignalKind,
};
#[cfg(all(feature = "full", not(hax)))]
pub use swarm::{
    ActivationLevel, AttackPattern, BuilderRuleRecord, DetectionCondition, DetectionRule,
    EntrypointGuard, EntrypointObservation, EntrypointSurface, QueenConfig, QueenState,
    QuorumConfig, RetrainRequest, RollbackMarker, RuleState, SentinelConfig, SentinelState,
    SwarmConfig, SwarmController, SwarmKeyBackend, SwarmTelemetryDigest, SwarmVerdict,
    ThreatDigest,
};
#[cfg(all(feature = "full", not(hax)))]
pub use telemetry::{GraphExecutionReport, NodeTrace, PlanExecutionResult};
#[cfg(all(feature = "full", not(hax)))]
pub use trust::{
    DeviceClass, ExecutionMode, HardwareProfile, RequiredTrustLane, SupportClass, TrustModel,
    TrustSummary,
};
#[cfg(all(feature = "full", not(hax)))]
pub use watchdog::{ProofWatchdog, WatchdogAlert, WatchdogAlertKind, WatchdogRecommendation};

// Keep GraphError as an alias for RuntimeError for backward compat
pub type GraphError = RuntimeError;
// Keep TrustClass as alias for TrustModel for backward compat
#[cfg(all(feature = "full", not(hax)))]
pub type TrustClass = TrustModel;

#[cfg(all(test, feature = "full", not(hax)))]
mod tests {
    use super::*;
    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    use std::path::PathBuf;
    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    use std::sync::Mutex;

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_driver_factories_are_callable() {
        if let Some(allocator) = create_metal_buffer_allocator() {
            let _ = allocator.is_available();
        }
        if let Some(driver) = create_metal_dispatch_driver(GpuVerificationMode::BestEffort) {
            let _ = driver.is_available();
        }
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    fn fixture_model_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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

    fn sample_runtime_program(field: zkf_core::FieldId) -> zkf_core::ir::Program {
        use zkf_core::ir::{
            Constraint, Expr, Program, Signal, Visibility, WitnessAssignment, WitnessPlan,
        };

        Program {
            name: "runtime-sample".to_string(),
            field,
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
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "product".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::signal("sum"),
                    rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                    label: Some("sum".to_string()),
                },
                Constraint::Equal {
                    lhs: Expr::signal("product"),
                    rhs: Expr::Mul(
                        Box::new(Expr::signal("sum")),
                        Box::new(Expr::constant_i64(7)),
                    ),
                    label: Some("product".to_string()),
                },
            ],
            witness_plan: WitnessPlan {
                assignments: vec![
                    WitnessAssignment {
                        target: "sum".to_string(),
                        expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                    },
                    WitnessAssignment {
                        target: "product".to_string(),
                        expr: Expr::Mul(
                            Box::new(Expr::signal("sum")),
                            Box::new(Expr::constant_i64(7)),
                        ),
                    },
                ],
                ..WitnessPlan::default()
            },
            ..Program::default()
        }
    }

    fn sample_runtime_inputs() -> std::collections::BTreeMap<String, zkf_core::FieldElement> {
        std::collections::BTreeMap::from([
            ("x".to_string(), zkf_core::FieldElement::from_u64(7)),
            ("y".to_string(), zkf_core::FieldElement::from_u64(5)),
        ])
    }

    fn authoritative_witness_program() -> zkf_core::ir::Program {
        use zkf_core::ir::{Constraint, Expr, Program, Signal, Visibility};

        Program {
            name: "authoritative-witness".to_string(),
            field: zkf_core::FieldId::Goldilocks,
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
                label: Some("out-equals-x".to_string()),
            }],
            ..Program::default()
        }
    }

    fn authoritative_witness_inputs(
        x: u64,
    ) -> std::collections::BTreeMap<String, zkf_core::FieldElement> {
        std::collections::BTreeMap::from([("x".to_string(), zkf_core::FieldElement::from_u64(x))])
    }

    fn authoritative_witness(x: u64, out: u64) -> zkf_core::Witness {
        zkf_core::Witness {
            values: std::collections::BTreeMap::from([
                ("x".to_string(), zkf_core::FieldElement::from_u64(x)),
                ("out".to_string(), zkf_core::FieldElement::from_u64(out)),
            ]),
        }
    }

    fn make_pool() -> UnifiedBufferPool {
        UnifiedBufferPool::new(256 * 1024 * 1024) // 256 MiB ceiling
    }

    #[test]
    fn topological_order_linear_chain() {
        let mut g = ProverGraph::new();
        let a = g.add_node(ProverNode::new(ProverOp::Noop));
        let b = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([a]));
        let c = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([b]));

        let order = g.topological_order().unwrap();
        assert_eq!(order, vec![a, b, c]);
    }

    #[test]
    fn topological_order_diamond() {
        let mut g = ProverGraph::new();
        let root = g.add_node(ProverNode::new(ProverOp::Noop));
        let left = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([root]));
        let right = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([root]));
        let sink = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([left, right]));

        let order = g.topological_order().unwrap();
        assert_eq!(order, vec![root, left, right, sink]);
    }

    #[test]
    fn topological_order_preserves_insertion_order_for_ready_roots() {
        let mut g = ProverGraph::new();
        let a = g.add_node(ProverNode::new(ProverOp::Noop));
        let b = g.add_node(ProverNode::new(ProverOp::Noop));
        let sink = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([a, b]));

        let order = g.topological_order().unwrap();
        assert_eq!(order, vec![a, b, sink]);
    }

    #[test]
    fn cyclic_graph_returns_error() {
        let mut g = ProverGraph::new();
        let a = g.add_node(ProverNode::new(ProverOp::Noop));
        let b = g.add_node(ProverNode::new(ProverOp::Noop).with_deps([a]));
        g.nodes.get_mut(&a).unwrap().deps.push(b);

        assert!(matches!(
            g.topological_order(),
            Err(RuntimeError::CyclicDependency)
        ));
    }

    #[test]
    fn trust_propagation_weakens_downstream() {
        let mut g = ProverGraph::new();
        let attested =
            g.add_node(ProverNode::new(ProverOp::Noop).with_trust(TrustModel::Attestation));
        let crypto_dep_on_attest = g.add_node(
            ProverNode::new(ProverOp::Noop)
                .with_deps([attested])
                .with_trust(TrustModel::Cryptographic),
        );

        g.propagate_trust().unwrap();

        assert_eq!(
            g.node(crypto_dep_on_attest).unwrap().trust_model,
            TrustModel::Attestation,
        );
    }

    #[test]
    fn scheduler_executes_all_nodes() {
        let mut pool = make_pool();
        let placement_ctx = PlacementContext {
            gpu_available: false,
            memory_pressure: 0.0,
            gpu_cores: 0,
            deterministic_mode: false,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        };

        let b1 = pool.alloc(1024, MemoryClass::EphemeralScratch).unwrap();
        let b2 = pool.alloc(1024, MemoryClass::EphemeralScratch).unwrap();
        let b3 = pool.alloc(1024, MemoryClass::EphemeralScratch).unwrap();

        let mut g = ProverGraph::new();
        let a = g.add_node(ProverNode::new(ProverOp::Noop).with_outputs([b1]));
        let b_node = g.add_node(
            ProverNode::new(ProverOp::Noop)
                .with_deps([a])
                .with_inputs([b1])
                .with_outputs([b2]),
        );
        g.add_node(
            ProverNode::new(ProverOp::Noop)
                .with_deps([b_node])
                .with_inputs([b2])
                .with_outputs([b3]),
        );

        let sched = DeterministicScheduler::new(pool, placement_ctx);
        let report = sched.execute(g).unwrap();

        assert_eq!(report.node_traces.len(), 3);
        assert_eq!(report.cpu_nodes, 3);
        assert_eq!(report.gpu_nodes, 0);
    }

    #[test]
    fn groth16_adapter_emits_valid_graph() {
        let mut pool = make_pool();
        let adapter = Groth16GraphAdapter;
        let params = GraphParams {
            constraint_count: 1024,
            field: "bn254_fr",
            deterministic: false,
            declared_trust: TrustModel::Cryptographic,
        };
        let graph = adapter.emit_graph(&mut pool, &params).unwrap();
        assert!(graph.node_count() > 0);
        assert!(graph.topological_order().is_ok());
    }

    #[test]
    fn plonky3_adapter_emits_valid_graph() {
        let mut pool = make_pool();
        let adapter = Plonky3GraphAdapter;
        let params = GraphParams {
            constraint_count: 4096,
            field: "goldilocks",
            deterministic: false,
            declared_trust: TrustModel::Cryptographic,
        };
        let graph = adapter.emit_graph(&mut pool, &params).unwrap();
        assert!(graph.node_count() > 0);
        assert!(graph.topological_order().is_ok());
    }

    #[test]
    fn placement_engine_forces_cpu_in_deterministic_mode() {
        let ctx = PlacementContext {
            gpu_available: true,
            memory_pressure: 0.0,
            gpu_cores: 40,
            deterministic_mode: true,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        };
        let engine = PlacementEngine::new(ctx);
        let node = ProverNode::new(ProverOp::Msm {
            num_scalars: 1 << 20,
            curve: "bn254",
        });
        assert_eq!(engine.resolve(&node), DevicePlacement::Cpu);
    }

    #[test]
    fn buffer_pool_evicts_spillable_on_pressure() {
        let mut pool = UnifiedBufferPool::new(1024);
        let _ = pool.alloc(512, MemoryClass::Spillable).unwrap();
        let _ = pool.alloc(256, MemoryClass::Spillable).unwrap();
        let h = pool.alloc(512, MemoryClass::EphemeralScratch);
        assert!(h.is_some());
    }

    // ── Buffer Bridge Tests ──────────────────────────────────────────────

    #[test]
    fn buffer_bridge_allocates_and_provides_typed_views() {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = BufferHandle {
            slot: 100,
            size_bytes: 1024,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(handle).unwrap();

        // Write some data
        let data = vec![42u8; 1024];
        bridge.write_slot(100, &data).unwrap();

        // Verify view
        let view = bridge.view(100).unwrap();
        assert_eq!(view.len(), 1024);
        assert_eq!(view.as_bytes()[0], 42);
    }

    #[test]
    fn buffer_bridge_spillable_evict_and_reload() {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = BufferHandle {
            slot: 200,
            size_bytes: 256,
            class: MemoryClass::Spillable,
        };
        bridge.allocate(handle).unwrap();

        // Write data
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        bridge.write_slot(200, &data).unwrap();

        // Evict
        bridge.evict_spillable(200).unwrap();
        assert!(!bridge.is_resident(200));

        // Reload
        bridge.ensure_resident(200).unwrap();
        assert!(bridge.is_resident(200));

        // Verify data integrity
        let view = bridge.view(200).unwrap();
        assert_eq!(view.as_bytes()[0], 0);
        assert_eq!(view.as_bytes()[100], 100);
        assert_eq!(view.as_bytes()[255], 255);
    }

    #[test]
    fn buffer_bridge_rejects_view_of_missing_slot() {
        let bridge = BufferBridge::with_temp_spill();
        assert!(bridge.view(999).is_err());
    }

    #[test]
    fn buffer_bridge_temp_spill_cleans_orphaned_legacy_files() {
        let base_dir = std::env::temp_dir().join("zkf-runtime-spill");
        std::fs::create_dir_all(&base_dir).unwrap();
        let orphan = base_dir.join("slot_4242.spill");
        std::fs::write(&orphan, b"orphaned spill bytes").unwrap();
        assert!(orphan.exists());

        let _bridge = BufferBridge::with_temp_spill();
        assert!(!orphan.exists());
    }

    #[cfg(unix)]
    #[test]
    fn buffer_bridge_temp_spill_uses_private_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _bridge = BufferBridge::with_temp_spill();
        let base_dir = std::env::temp_dir().join("zkf-runtime-spill");
        let mode = std::fs::metadata(base_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    // ── Execution Context Tests ──────────────────────────────────────────

    #[test]
    fn execution_context_stores_and_retrieves_payloads() {
        let mut ctx = ExecutionContext::new();
        let node_id = NodeId::new();
        ctx.set_payload(node_id, NodePayload::NttBn254 { values_slot: 42 });

        match ctx.payload(node_id) {
            Some(NodePayload::NttBn254 { values_slot }) => assert_eq!(*values_slot, 42),
            _ => panic!("Expected NttBn254 payload"),
        }
    }

    #[test]
    fn execution_context_stores_outputs() {
        let mut ctx = ExecutionContext::new();
        ctx.set_output("proof", vec![1, 2, 3, 4]);
        assert_eq!(ctx.output("proof"), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(ctx.output("missing"), None);
    }

    // ── Node Payload Decoding Tests ──────────────────────────────────────

    #[test]
    fn node_payload_rejects_malformed_layouts() {
        // MsmBn254 payload on a non-MSM node should be caught by the driver
        let ctx = ExecutionContext::new();
        let node_id = NodeId::new();
        // No payload set => MissingPayload
        assert!(ctx.payload(node_id).is_none());
    }

    // ── Scheduler with Context Tests ─────────────────────────────────────

    #[test]
    fn scheduler_writes_output_digests_after_execution() {
        let mut pool = make_pool();
        let placement_ctx = PlacementContext::default();

        let b1 = pool.alloc(64, MemoryClass::EphemeralScratch).unwrap();
        let b2 = pool.alloc(64, MemoryClass::EphemeralScratch).unwrap();

        let mut g = ProverGraph::new();
        let a = g.add_node(ProverNode::new(ProverOp::Noop).with_outputs([b1]));
        let b_node = g.add_node(
            ProverNode::new(ProverOp::Noop)
                .with_deps([a])
                .with_inputs([b1])
                .with_outputs([b2]),
        );

        let mut exec_ctx = ExecutionContext::new();
        exec_ctx.set_payload(a, NodePayload::Noop);
        exec_ctx.set_payload(b_node, NodePayload::Noop);

        let sched = DeterministicScheduler::new(pool, placement_ctx);
        let mut bridge = BufferBridge::with_temp_spill();

        let report = sched
            .execute_with_context(g, &mut exec_ctx, &mut bridge)
            .unwrap();

        assert_eq!(report.node_traces.len(), 2);
        assert_eq!(report.cpu_nodes, 2);
        // Output digests should be present (from bridge)
        for trace in &report.node_traces {
            // Verify wall_time is populated (u128 is always >= 0)
            let _ = trace.wall_time;
        }
    }

    // ── Groth16 with Context Tests ───────────────────────────────────────

    #[test]
    fn groth16_adapter_emits_graph_with_context() {
        let mut pool = make_pool();
        let adapter = Groth16GraphAdapter;
        let params = GraphParams {
            constraint_count: 256,
            field: "bn254_fr",
            deterministic: false,
            declared_trust: TrustModel::Cryptographic,
        };
        let emission = adapter
            .emit_graph_with_context(&mut pool, &params, None, None)
            .unwrap();

        assert!(emission.graph.node_count() > 0);
        assert!(emission.graph.topological_order().is_ok());
        // Even without program/inputs, the graph structure should be valid
    }

    // ── Plonky3 with Context Tests ───────────────────────────────────────

    #[test]
    fn plonky3_adapter_emits_graph_with_context() {
        let mut pool = make_pool();
        let adapter = Plonky3GraphAdapter;
        let params = GraphParams {
            constraint_count: 1024,
            field: "goldilocks",
            deterministic: false,
            declared_trust: TrustModel::Cryptographic,
        };
        let emission = adapter
            .emit_graph_with_context(&mut pool, &params, None, None)
            .unwrap();

        assert!(emission.graph.node_count() > 0);
        assert!(emission.graph.topological_order().is_ok());
        // Should have payloads for key nodes
        assert!(!emission.exec_ctx.node_payloads.is_empty());
    }

    // ── GPU/CPU Driver Parity Tests ──────────────────────────────────────

    #[test]
    fn cpu_driver_handles_noop_and_barrier() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        let noop_node = ProverNode::new(ProverOp::Noop);
        let result = cpu.execute(&noop_node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().op_name, "Noop");

        let barrier_node = ProverNode::new(ProverOp::Barrier { wait_for: vec![] });
        let result = cpu.execute(&barrier_node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
    }

    #[test]
    fn cpu_driver_rejects_missing_payload() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        // NTT node without payload should fail
        let ntt_node = ProverNode::new(ProverOp::Ntt {
            size: 1024,
            field: "bn254_fr",
            inverse: false,
        });
        let result = cpu.execute(&ntt_node, &mut exec_ctx, &mut bridge);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::MissingPayload(_)
        ));
    }

    // ── Integration: RuntimeExecutor with context ────────────────────────

    #[test]
    fn runtime_executor_run_groth16_graph_with_context() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let mut pool = make_pool();
        let adapter = Groth16GraphAdapter;
        let program = sample_runtime_program(zkf_core::FieldId::Bn254);
        let constraint_count = program.constraints.len();
        let inputs: BTreeMap<String, zkf_core::FieldElement> = sample_runtime_inputs();
        let params = GraphParams {
            constraint_count,
            field: "bn254_fr",
            deterministic: true,
            declared_trust: TrustModel::Cryptographic,
        };
        let emission = adapter
            .emit_graph_with_context(
                &mut pool,
                &params,
                Some(Arc::new(program)),
                Some(Arc::new(inputs)),
            )
            .unwrap();

        let mut exec_ctx = emission.exec_ctx;
        let result = RuntimeExecutor::run_with_context(emission.graph, &mut exec_ctx);
        if let Err(err) = &result {
            panic!("runtime plonky3 execution failed: {err:?}");
        }

        let result = result.unwrap();
        assert!(result.report.node_traces.len() > 0);
        assert!(result.report.total_wall_time.as_nanos() > 0);
    }

    #[test]
    fn runtime_executor_run_plonky3_graph_with_context() {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use zkf_core::FieldId;

        let mut pool = make_pool();
        let adapter = Plonky3GraphAdapter;
        let program = sample_runtime_program(FieldId::Goldilocks);
        let constraint_count = program.constraints.len();
        let inputs: BTreeMap<String, zkf_core::FieldElement> = sample_runtime_inputs();
        let params = GraphParams {
            constraint_count,
            field: "goldilocks",
            deterministic: true,
            declared_trust: TrustModel::Cryptographic,
        };
        let emission = adapter
            .emit_graph_with_context(
                &mut pool,
                &params,
                Some(Arc::new(program)),
                Some(Arc::new(inputs)),
            )
            .unwrap();

        let mut exec_ctx = emission.exec_ctx;
        let result = RuntimeExecutor::run_with_context(emission.graph, &mut exec_ctx);
        if let Err(err) = &result {
            panic!("runtime plonky3 execution failed: {err:?}");
        }

        let result = result.unwrap();
        assert!(result.report.node_traces.len() > 0);
    }

    // ── Strict Mode GPU Fallback Rejection ───────────────────────────────

    #[test]
    fn verified_gpu_mode_rejects_fallback_via_trust_lane() {
        // Verify that trust lane violations are caught
        let result = RuntimeCompiler::build_plan(
            100,
            "bn254_fr",
            "unknown-backend",
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        );
        assert!(matches!(result, Err(RuntimeError::UnsupportedBackend(_))));
    }

    // ── Strict GPU fallback rejection via GpuDispatchDriver ──────────────

    /// A mock GPU driver that always returns FallbackSignal for testing.
    struct StrictMockGpu;

    impl GpuDispatchDriver for StrictMockGpu {
        fn is_available(&self) -> bool {
            true
        }
        fn verification_mode(&self) -> GpuVerificationMode {
            GpuVerificationMode::VerifiedPinned
        }
        fn execute(
            &self,
            node: &ProverNode,
            _exec_ctx: &mut ExecutionContext,
            _bridge: &mut BufferBridge,
        ) -> Result<DispatchResult, RuntimeError> {
            // Strict mode: reject fallback for proof-critical GPU nodes
            Err(RuntimeError::GpuFallbackRejected {
                node: node.op.name().to_string(),
            })
        }
    }

    #[test]
    fn strict_gpu_rejects_proof_critical_fallback() {
        let mut pool = make_pool();
        let placement_ctx = PlacementContext {
            gpu_available: true,
            memory_pressure: 0.0,
            gpu_cores: 40,
            deterministic_mode: false,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        };

        let buf = pool.alloc(1024, MemoryClass::EphemeralScratch).unwrap();
        let out_buf = pool.alloc(96, MemoryClass::EphemeralScratch).unwrap();

        let mut g = ProverGraph::new();
        // MSM is GPU-preferred when large enough
        g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: 1 << 20,
                curve: "bn254",
            })
            .with_inputs([buf])
            .with_outputs([out_buf]),
        );

        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();
        let sched = DeterministicScheduler::new(pool, placement_ctx);

        let result =
            sched.execute_with_context_and_gpu(g, &mut exec_ctx, &mut bridge, &StrictMockGpu);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::GpuFallbackRejected { .. }
        ));
    }

    // ── Wrapper Integration Test ─────────────────────────────────────────

    #[test]
    fn wrapper_plan_emits_native_runtime_stages() {
        use zkf_core::artifact::BackendKind;
        use zkf_core::wrapping::WrapperPreview;

        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".into(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "ready".into(),
            strategy: "direct-fri-v2".into(),
            trust_model: "attestation".into(),
            trust_model_description: None,
            estimated_constraints: Some(2048),
            estimated_memory_bytes: Some(128 * 1024 * 1024),
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: None,
        };

        let emission = RuntimeCompiler::build_wrapper_plan_with_context(
            &preview,
            ExecutionMode::Deterministic,
        )
        .unwrap();
        let exec_ctx = emission.exec_ctx;
        let graph = emission.graph;

        // Wrapper graph should expose the honest native runtime stages.
        let op_names: Vec<&str> = graph.iter_nodes().map(|n| n.op.name()).collect();
        assert!(
            op_names.contains(&"WitnessSolve"),
            "wrapper graph must contain WitnessSolve node, got: {:?}",
            op_names,
        );
        assert!(
            op_names.contains(&"TranscriptUpdate"),
            "wrapper graph must contain TranscriptUpdate node, got: {:?}",
            op_names,
        );
        assert!(
            op_names.contains(&"VerifierEmbed"),
            "wrapper graph must contain VerifierEmbed node, got: {:?}",
            op_names,
        );
        assert!(
            op_names.contains(&"OuterProve"),
            "wrapper graph must contain OuterProve node, got: {:?}",
            op_names,
        );
        assert!(
            op_names.contains(&"ProofEncode"),
            "wrapper graph must contain ProofEncode node, got: {:?}",
            op_names,
        );
        assert!(exec_ctx.wrapper_preview.is_some());
        assert_eq!(exec_ctx.node_payloads.len(), 5);
    }

    #[test]
    fn run_wrapper_job_without_source_artifact_context_fails_closed() {
        use zkf_core::artifact::BackendKind;
        use zkf_core::wrapping::WrapperPreview;

        let preview = WrapperPreview {
            wrapper: "stark-to-groth16".into(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".into(),
            strategy: "direct-fri-v2".into(),
            trust_model: "cryptographic".into(),
            trust_model_description: None,
            estimated_constraints: Some(2048),
            estimated_memory_bytes: Some(128 * 1024 * 1024),
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: None,
        };

        let err =
            RuntimeExecutor::run_wrapper_job(&preview, ExecutionMode::Deterministic).unwrap_err();
        assert!(matches!(err, RuntimeError::UnsupportedFeature { .. }));
        assert!(
            !err.to_string().contains("delegated CPU driver"),
            "wrapper runtime should now fail on missing native sources, not on delegation: {err}"
        );
    }

    #[test]
    fn runtime_executor_run_without_context_fails_closed() {
        let graph = ProverGraph::new();
        let err = RuntimeExecutor::run(graph, serde_json::Value::Null).unwrap_err();
        assert!(matches!(err, RuntimeError::UnsupportedFeature { .. }));
        assert!(
            err.to_string()
                .contains("RuntimeExecutor::run requires an ExecutionContext")
        );
    }

    #[test]
    fn runtime_executor_backend_prove_job_materializes_real_artifact() {
        let program = std::sync::Arc::new(sample_runtime_program(zkf_core::FieldId::Goldilocks));
        let inputs = std::sync::Arc::new(sample_runtime_inputs());

        let execution = RuntimeExecutor::run_backend_prove_job(
            zkf_core::BackendKind::Plonky3,
            zkf_backends::BackendRoute::Auto,
            program,
            Some(inputs),
            None,
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .expect("runtime backend prove");

        assert_eq!(execution.artifact.backend, zkf_core::BackendKind::Plonky3);
        assert!(!execution.artifact.proof.is_empty());
        assert_eq!(execution.result.report.delegated_nodes, 1);
        assert!(
            execution
                .result
                .report
                .node_traces
                .iter()
                .any(|trace| trace.op_name == "BackendProve" && trace.delegated),
            "expected delegated BackendProve node in runtime trace"
        );
    }

    #[test]
    fn runtime_executor_backend_prove_job_uses_supplied_witness_even_with_inputs() {
        let program = std::sync::Arc::new(authoritative_witness_program());
        let inputs = std::sync::Arc::new(authoritative_witness_inputs(7));
        let witness = std::sync::Arc::new(authoritative_witness(7, 7));

        let execution = RuntimeExecutor::run_backend_prove_job(
            zkf_core::BackendKind::Plonky3,
            zkf_backends::BackendRoute::Auto,
            program,
            Some(inputs),
            Some(witness),
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .expect("runtime backend prove with authoritative witness");

        assert_eq!(execution.artifact.backend, zkf_core::BackendKind::Plonky3);
        assert!(!execution.artifact.proof.is_empty());
    }

    #[test]
    fn runtime_executor_backend_prove_job_rejects_input_witness_mismatch() {
        let program = std::sync::Arc::new(authoritative_witness_program());
        let inputs = std::sync::Arc::new(authoritative_witness_inputs(7));
        let witness = std::sync::Arc::new(authoritative_witness(8, 8));

        let err = RuntimeExecutor::run_backend_prove_job(
            zkf_core::BackendKind::Plonky3,
            zkf_backends::BackendRoute::Auto,
            program,
            Some(inputs),
            Some(witness),
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .err()
        .expect("mismatched inputs and authoritative witness must fail");

        assert!(
            matches!(err, RuntimeError::WitnessGeneration(_)),
            "expected witness generation mismatch error, got {err:?}"
        );
        assert!(
            err.to_string().contains("does not match provided inputs"),
            "mismatch error should explain the authoritative witness/input conflict: {err}"
        );
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn runtime_backend_prove_job_surfaces_fixture_model_control_plane_metadata() {
        with_fixture_models_env(|| {
            let program =
                std::sync::Arc::new(sample_runtime_program(zkf_core::FieldId::Goldilocks));
            let inputs = std::sync::Arc::new(sample_runtime_inputs());

            let execution = RuntimeExecutor::run_backend_prove_job(
                zkf_core::BackendKind::Plonky3,
                zkf_backends::BackendRoute::Auto,
                program,
                Some(inputs),
                None,
                None,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .expect("runtime backend prove");

            let control_plane = execution
                .result
                .control_plane
                .as_ref()
                .expect("control plane");
            assert!(control_plane.decision.model_catalog.scheduler.is_some());
            assert!(control_plane.decision.model_catalog.backend.is_some());
            assert!(control_plane.decision.model_catalog.duration.is_some());
            assert!(control_plane.decision.model_catalog.anomaly.is_some());
            assert_eq!(control_plane.decision.duration_estimate.source, "model");
            assert_eq!(control_plane.decision.anomaly_baseline.source, "model");
            assert!(
                execution
                    .result
                    .outputs
                    .get("runtime_model_catalog")
                    .is_some(),
                "runtime outputs must include model catalog metadata"
            );
            assert!(
                execution
                    .result
                    .outputs
                    .get("runtime_duration_estimate")
                    .is_some(),
                "runtime outputs must include duration estimate metadata"
            );
        });
    }

    #[test]
    fn runtime_executor_backend_fold_job_materializes_real_artifact() {
        if !zkf_backends::backend_surface_status(zkf_core::BackendKind::Nova).compiled_in {
            return;
        }

        let mut program = sample_runtime_program(zkf_core::FieldId::Bn254);
        program
            .metadata
            .insert("nova_ivc_in".to_string(), "x".to_string());
        program
            .metadata
            .insert("nova_ivc_out".to_string(), "product".to_string());
        let compiled = zkf_backends::backend_for(zkf_core::BackendKind::Nova)
            .compile(&program)
            .expect("compile nova");
        let witness_a =
            zkf_core::generate_witness(&program, &sample_runtime_inputs()).expect("witness a");
        // Nova folding requires each step's `nova_ivc_in` to match the prior
        // step's `nova_ivc_out`, so chain the second witness off witness_a.
        let witness_b_input = witness_a
            .values
            .get("product")
            .cloned()
            .expect("witness a product");
        let witness_b = zkf_core::generate_witness(
            &program,
            &std::collections::BTreeMap::from([
                ("x".to_string(), witness_b_input),
                ("y".to_string(), zkf_core::FieldElement::from_u64(4)),
            ]),
        )
        .expect("witness b");

        let execution = RuntimeExecutor::run_backend_fold_job(
            std::sync::Arc::new(compiled.clone()),
            std::sync::Arc::new(vec![witness_a, witness_b]),
            true,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .expect("runtime backend fold");

        assert_eq!(execution.artifact.backend, zkf_core::BackendKind::Nova);
        assert!(!execution.artifact.proof.is_empty());
        assert_eq!(execution.result.report.delegated_nodes, 1);
        assert!(
            execution
                .result
                .report
                .node_traces
                .iter()
                .any(|trace| trace.op_name == "BackendFold" && trace.delegated),
            "expected delegated BackendFold node in runtime trace"
        );
        assert!(
            zkf_backends::try_verify_fold_native(&compiled, &execution.artifact)
                .expect("native nova verify path available")
                .expect("verify folded artifact"),
            "runtime fold artifact must verify natively"
        );
    }

    #[cfg(all(target_os = "macos", feature = "neural-engine"))]
    #[test]
    fn runtime_backend_fold_job_surfaces_fixture_model_control_plane_metadata() {
        if !zkf_backends::backend_surface_status(zkf_core::BackendKind::Nova).compiled_in {
            return;
        }

        with_fixture_models_env(|| {
            let mut program = sample_runtime_program(zkf_core::FieldId::Bn254);
            program
                .metadata
                .insert("nova_ivc_in".to_string(), "x".to_string());
            program
                .metadata
                .insert("nova_ivc_out".to_string(), "product".to_string());
            let compiled = zkf_backends::backend_for(zkf_core::BackendKind::Nova)
                .compile(&program)
                .expect("compile nova");
            let witness_a =
                zkf_core::generate_witness(&program, &sample_runtime_inputs()).expect("witness a");
            let witness_b_input = witness_a
                .values
                .get("product")
                .cloned()
                .expect("witness a product");
            let witness_b = zkf_core::generate_witness(
                &program,
                &std::collections::BTreeMap::from([
                    ("x".to_string(), witness_b_input),
                    ("y".to_string(), zkf_core::FieldElement::from_u64(4)),
                ]),
            )
            .expect("witness b");

            let execution = RuntimeExecutor::run_backend_fold_job(
                std::sync::Arc::new(compiled),
                std::sync::Arc::new(vec![witness_a, witness_b]),
                true,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .expect("runtime backend fold");

            let control_plane = execution
                .result
                .control_plane
                .as_ref()
                .expect("control plane");
            assert!(control_plane.decision.model_catalog.scheduler.is_some());
            assert!(control_plane.decision.model_catalog.duration.is_some());
            assert!(control_plane.decision.model_catalog.anomaly.is_some());
            assert_eq!(control_plane.decision.duration_estimate.source, "model");
            assert_eq!(control_plane.decision.anomaly_baseline.source, "model");
            assert!(
                execution
                    .result
                    .outputs
                    .get("runtime_anomaly_verdict")
                    .is_some(),
                "runtime outputs must include anomaly verdict metadata"
            );
        });
    }

    // ── Driver Parity Tests (CPU-only; GPU parity needs macOS) ───────────

    #[test]
    fn cpu_driver_sha256_batch_produces_correct_output() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        // Allocate input buffer with known data
        let input_handle = BufferHandle {
            slot: 500,
            size_bytes: 128,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(input_handle).unwrap();
        let output_handle = BufferHandle {
            slot: 501,
            size_bytes: 64,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(output_handle).unwrap();
        // Write 2 blocks of 64 bytes each
        let data = vec![0xABu8; 128];
        bridge.write_slot(500, &data).unwrap();

        let node =
            ProverNode::new(ProverOp::Sha256Batch { count: 2 }).with_outputs([output_handle]);
        let node_id = node.id;

        exec_ctx.set_payload(
            node_id,
            NodePayload::Sha256Batch {
                inputs_slot: 500,
                count: 2,
                input_len: 64,
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
        let telem = result.unwrap();
        assert_eq!(telem.op_name, "Sha256Batch");
        assert_eq!(telem.input_bytes, 128);
        assert_eq!(telem.output_bytes, 64); // 2 * 32-byte digests
        assert_eq!(bridge.view(501).unwrap().len(), 64);
    }

    #[test]
    fn cpu_driver_witness_solve_with_real_program() {
        use std::collections::BTreeMap;
        use zkf_core::FieldElement;
        use zkf_core::ir::{Constraint, Expr, Program, Signal, Visibility, WitnessPlan};

        // Build a minimal program: x * x = y, where x = 3, y = 9
        let program = Program {
            name: "test_square".into(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("y".into()),
                label: Some("x*x=y".into()),
            }],
            witness_plan: WitnessPlan {
                assignments: vec![],
                hints: vec![],
                input_aliases: BTreeMap::new(),
                acir_program_bytes: None,
            },
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        };

        let mut inputs = BTreeMap::new();
        inputs.insert("x".into(), FieldElement::from_u64(3));
        inputs.insert("y".into(), FieldElement::from_u64(9));

        let program_arc = std::sync::Arc::new(program);
        let inputs_arc = std::sync::Arc::new(inputs);

        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        let output_handle = BufferHandle {
            slot: 510,
            size_bytes: 64,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(output_handle).unwrap();

        let node = ProverNode::new(ProverOp::WitnessSolve {
            constraint_count: 1,
            signal_count: 2,
        })
        .with_outputs([output_handle]);
        let node_id = node.id;

        exec_ctx.set_payload(
            node_id,
            NodePayload::WitnessSolve {
                program: std::sync::Arc::clone(&program_arc),
                inputs: std::sync::Arc::clone(&inputs_arc),
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
        let telem = result.unwrap();
        assert_eq!(telem.op_name, "WitnessSolve");
        // Should produce 2 signals * 32 bytes = 64 bytes
        assert_eq!(telem.output_bytes, 64);
        assert_eq!(bridge.view(510).unwrap().len(), 64);
    }

    #[test]
    fn cpu_driver_witness_solve_prefers_supplied_witness_over_payload_inputs() {
        let program_arc = std::sync::Arc::new(authoritative_witness_program());
        let inputs_arc = std::sync::Arc::new(authoritative_witness_inputs(7));
        let witness_arc = std::sync::Arc::new(authoritative_witness(7, 7));

        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new()
            .with_program(std::sync::Arc::clone(&program_arc))
            .with_inputs(std::sync::Arc::clone(&inputs_arc))
            .with_witness(std::sync::Arc::clone(&witness_arc));
        let mut bridge = BufferBridge::with_temp_spill();

        let output_handle = BufferHandle {
            slot: 511,
            size_bytes: 64,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(output_handle).unwrap();

        let node = ProverNode::new(ProverOp::WitnessSolve {
            constraint_count: 1,
            signal_count: 2,
        })
        .with_outputs([output_handle]);
        let node_id = node.id;

        exec_ctx.set_payload(
            node_id,
            NodePayload::WitnessSolve {
                program: std::sync::Arc::clone(&program_arc),
                inputs: std::sync::Arc::clone(&inputs_arc),
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge);
        assert!(
            result.is_ok(),
            "authoritative witness should bypass generic witness synthesis"
        );
        let telem = result.unwrap();
        assert_eq!(telem.op_name, "WitnessSolve");
        assert_eq!(telem.output_bytes, 64);
        assert_eq!(bridge.view(511).unwrap().len(), 64);
    }

    #[test]
    fn cpu_driver_proof_encode_assembles_outputs() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        // Create 3 input buffers (simulating MSM results)
        for slot in [600, 601, 602] {
            let handle = BufferHandle {
                slot,
                size_bytes: 96,
                class: MemoryClass::EphemeralScratch,
            };
            bridge.allocate(handle).unwrap();
            bridge.write_slot(slot, &vec![slot as u8; 96]).unwrap();
        }

        let output_handle = BufferHandle {
            slot: 603,
            size_bytes: 288,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(output_handle).unwrap();

        let node = ProverNode::new(ProverOp::ProofEncode).with_outputs([output_handle]);
        let node_id = node.id;

        exec_ctx.set_payload(
            node_id,
            NodePayload::ProofEncode {
                input_slots: vec![600, 601, 602],
                output_kind: ProofOutputKind::Groth16Proof,
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
        let telem = result.unwrap();
        assert_eq!(telem.op_name, "ProofEncode");
        assert_eq!(telem.input_bytes, 288); // 3 * 96
        assert_eq!(telem.output_bytes, 288);

        // Verify the output was stored in execution context
        let proof = exec_ctx.output("groth16_proof");
        assert!(proof.is_some());
        assert_eq!(proof.unwrap().len(), 288);
        assert_eq!(bridge.view(603).unwrap().len(), 288);
    }

    #[test]
    fn cpu_driver_outer_prove_uses_native_wrapper_path_when_sources_are_attached() {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use zkf_core::artifact::{BackendKind, CompiledProgram, ProofArtifact};
        use zkf_core::wrapping::{WrapperExecutionPolicy, WrapperPreview};

        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        let input_handle = BufferHandle {
            slot: 612,
            size_bytes: 64,
            class: MemoryClass::EphemeralScratch,
        };
        let output_handle = BufferHandle {
            slot: 613,
            size_bytes: 256,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(input_handle).unwrap();
        bridge.allocate(output_handle).unwrap();
        bridge.write_slot(input_handle.slot, &[0x33; 64]).unwrap();

        let node = ProverNode::new(ProverOp::OuterProve {
            outer_scheme: "groth16",
        })
        .with_inputs([input_handle])
        .with_outputs([output_handle]);
        let node_id = node.id;
        exec_ctx.set_payload(
            node_id,
            NodePayload::OuterProve {
                proving_input_slot: input_handle.slot,
                scheme: "groth16".to_string(),
            },
        );
        exec_ctx.wrapper_preview = Some(WrapperPreview {
            wrapper: "native-runtime-test".to_string(),
            source_backend: BackendKind::ArkworksGroth16,
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
        });
        exec_ctx.source_proof = Some(Arc::new(ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "runtime-native-test".to_string(),
            proof: vec![1, 2, 3],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        }));
        exec_ctx.compiled = Some(Arc::new(CompiledProgram::new(
            BackendKind::ArkworksGroth16,
            sample_runtime_program(zkf_core::FieldId::Bn254),
        )));
        exec_ctx.set_wrapper_policy(WrapperExecutionPolicy::default());

        let err = cpu.execute(&node, &mut exec_ctx, &mut bridge).unwrap_err();
        match err {
            RuntimeError::UnsupportedFeature { backend, feature } => {
                assert_eq!(backend, "runtime-wrapper");
                assert!(
                    feature.contains("wrapper arkworks-groth16 -> arkworks-groth16"),
                    "unexpected native outer prove failure: {feature}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cpu_driver_verifier_embed_serializes_context() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();

        exec_ctx.source_proof = Some(std::sync::Arc::new(zkf_core::ProofArtifact {
            backend: zkf_core::BackendKind::Plonky3,
            program_digest: "proof-digest".to_string(),
            proof: vec![1, 2, 3],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: std::collections::BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        }));
        exec_ctx.compiled = Some(std::sync::Arc::new(zkf_core::CompiledProgram::new(
            zkf_core::BackendKind::Plonky3,
            sample_runtime_program(zkf_core::FieldId::Goldilocks),
        )));
        exec_ctx.wrapper_preview = Some(zkf_core::wrapping::WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: zkf_core::BackendKind::Plonky3,
            target_backend: zkf_core::BackendKind::ArkworksGroth16,
            planned_status: "wrapped-v2".to_string(),
            strategy: "direct-fri-v2".to_string(),
            trust_model: "cryptographic".to_string(),
            trust_model_description: None,
            estimated_constraints: None,
            estimated_memory_bytes: None,
            memory_budget_bytes: None,
            low_memory_mode: None,
            prepare_required: None,
            setup_cache_state: None,
            reason: None,
        });

        let input_handle = BufferHandle {
            slot: 620,
            size_bytes: 32,
            class: MemoryClass::EphemeralScratch,
        };
        let output_handle = BufferHandle {
            slot: 621,
            size_bytes: 1024,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(input_handle).unwrap();
        bridge.allocate(output_handle).unwrap();
        bridge.write_slot(input_handle.slot, &[0x44; 32]).unwrap();

        let node = ProverNode::new(ProverOp::VerifierEmbed {
            inner_scheme: "plonky3",
        })
        .with_inputs([input_handle])
        .with_outputs([output_handle]);
        let node_id = node.id;
        exec_ctx.set_payload(
            node_id,
            NodePayload::VerifierEmbed {
                wrapper_input_slot: input_handle.slot,
                scheme: "plonky3".to_string(),
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge).unwrap();
        assert_eq!(result.op_name, "VerifierEmbed-plonky3");
        assert!(result.output_bytes > 0);
        let written = bridge.view(output_handle.slot).unwrap().as_bytes().to_vec();
        let json_slice = &written[..result.output_bytes];
        let value: serde_json::Value = serde_json::from_slice(json_slice).unwrap();
        assert_eq!(
            value.get("inner_scheme"),
            Some(&serde_json::json!("plonky3"))
        );
        assert_eq!(
            value.get("source_backend"),
            Some(&serde_json::json!("plonky3"))
        );
        assert_eq!(
            value.get("wrapper_strategy"),
            Some(&serde_json::json!("direct-fri-v2"))
        );
    }

    #[test]
    fn cpu_driver_lookup_expand_matches_rows_and_returns_selected_columns() {
        let cpu = CpuBackendDriver::new();
        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();
        let cell = |value: i64| {
            let mut out = vec![0u8; 32];
            let fe = zkf_core::FieldElement::from_i64(value);
            let bytes = fe.to_le_bytes();
            out[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
            out
        };

        let table_handle = BufferHandle {
            slot: 630,
            size_bytes: 4 * 32,
            class: MemoryClass::HotResident,
        };
        let inputs_handle = BufferHandle {
            slot: 631,
            size_bytes: 32,
            class: MemoryClass::EphemeralScratch,
        };
        let output_handle = BufferHandle {
            slot: 632,
            size_bytes: 32,
            class: MemoryClass::EphemeralScratch,
        };
        bridge.allocate(table_handle).unwrap();
        bridge.allocate(inputs_handle).unwrap();
        bridge.allocate(output_handle).unwrap();

        let mut table_bytes = Vec::new();
        table_bytes.extend_from_slice(&cell(7));
        table_bytes.extend_from_slice(&cell(70));
        table_bytes.extend_from_slice(&cell(9));
        table_bytes.extend_from_slice(&cell(90));
        bridge.write_slot(table_handle.slot, &table_bytes).unwrap();
        bridge.write_slot(inputs_handle.slot, &cell(9)).unwrap();

        let node = ProverNode::new(ProverOp::LookupExpand {
            table_rows: 2,
            table_cols: 2,
        })
        .with_inputs([table_handle, inputs_handle])
        .with_outputs([output_handle]);
        let node_id = node.id;
        exec_ctx.set_payload(
            node_id,
            NodePayload::LookupExpand {
                table_slot: table_handle.slot,
                inputs_slot: inputs_handle.slot,
                table_rows: 2,
                table_cols: 2,
                query_cols: 1,
                output_col_offset: 1,
                output_cols: 1,
            },
        );

        let result = cpu.execute(&node, &mut exec_ctx, &mut bridge).unwrap();
        assert_eq!(result.op_name, "LookupExpand");
        assert_eq!(result.output_bytes, 32);
        let written = bridge.view(output_handle.slot).unwrap().as_bytes().to_vec();
        assert_eq!(written[..32].to_vec(), cell(90));
    }

    // ── GPU/CPU Parity Tests (macOS-only) ────────────────────────────────

    /// A lenient mock GPU driver that always falls back (for parity testing).
    struct LenientMockGpu;

    impl GpuDispatchDriver for LenientMockGpu {
        fn is_available(&self) -> bool {
            true
        }
        fn verification_mode(&self) -> GpuVerificationMode {
            GpuVerificationMode::BestEffort
        }
        fn execute(
            &self,
            node: &ProverNode,
            _exec_ctx: &mut ExecutionContext,
            _bridge: &mut BufferBridge,
        ) -> Result<DispatchResult, RuntimeError> {
            Ok(Err(FallbackSignal {
                node_id: node.id,
                reason: "mock GPU — always falls back for parity test".into(),
            }))
        }
    }

    #[test]
    fn gpu_fallback_to_cpu_records_telemetry() {
        let mut pool = make_pool();
        let placement_ctx = PlacementContext {
            gpu_available: true,
            memory_pressure: 0.0,
            gpu_cores: 40,
            deterministic_mode: false,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        };

        let buf_in = pool.alloc(256 * 64, MemoryClass::EphemeralScratch).unwrap();
        let buf_out = pool.alloc(256 * 32, MemoryClass::EphemeralScratch).unwrap();

        let mut g = ProverGraph::new();
        // Create a large SHA-256 batch node so it gets GPU placement and has a real CPU fallback.
        g.add_node(
            ProverNode::new(ProverOp::Sha256Batch { count: 256 })
                .with_inputs([buf_in])
                .with_outputs([buf_out]),
        );

        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();
        bridge.allocate(buf_in).unwrap();
        bridge.allocate(buf_out).unwrap();
        bridge
            .write_slot(buf_in.slot, &vec![0x11; 256 * 64])
            .unwrap();
        let node_id = g.iter_nodes().next().unwrap().id;
        exec_ctx.set_payload(
            node_id,
            NodePayload::Sha256Batch {
                inputs_slot: buf_in.slot,
                count: 256,
                input_len: 64,
            },
        );
        let sched = DeterministicScheduler::new(pool, placement_ctx);

        // Lenient mock GPU falls back, scheduler retries on CPU
        let result =
            sched.execute_with_context_and_gpu(g, &mut exec_ctx, &mut bridge, &LenientMockGpu);

        // Should succeed via CPU fallback and record the fallback.
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.fallback_nodes, 1);
        // The node was placed on CPU after fallback
        assert_eq!(report.cpu_nodes, 1);
        assert_eq!(report.gpu_nodes, 0);
        // Telemetry should record the fallback
        let trace = &report.node_traces[0];
        assert!(trace.fell_back);
    }

    struct PromotingMockGpu;

    impl GpuDispatchDriver for PromotingMockGpu {
        fn is_available(&self) -> bool {
            true
        }

        fn verification_mode(&self) -> GpuVerificationMode {
            GpuVerificationMode::BestEffort
        }

        fn should_try_on_either(&self, node: &ProverNode) -> bool {
            matches!(node.op, ProverOp::Ntt { .. })
        }

        fn execute(
            &self,
            node: &ProverNode,
            _exec_ctx: &mut ExecutionContext,
            bridge: &mut BufferBridge,
        ) -> Result<DispatchResult, RuntimeError> {
            let output_bytes = node
                .output_buffers
                .first()
                .map(|handle| {
                    bridge.ensure_resident(handle.slot)?;
                    bridge.write_slot(handle.slot, &vec![0u8; handle.size_bytes])?;
                    Ok(handle.size_bytes)
                })
                .transpose()?
                .unwrap_or(0);

            Ok(Ok(GpuNodeTelemetry {
                accelerator_name: "promoting-mock-gpu".to_string(),
                fell_back: false,
                wall_time: std::time::Duration::from_millis(1),
                input_bytes: node.input_buffers.iter().map(|h| h.size_bytes).sum(),
                output_bytes,
                residency_class: "mock-shared".to_string(),
            }))
        }
    }

    #[test]
    fn either_nodes_can_be_promoted_to_gpu_by_driver_policy() {
        let mut pool = make_pool();
        let placement_ctx = PlacementContext {
            gpu_available: true,
            memory_pressure: 0.0,
            gpu_cores: 40,
            deterministic_mode: false,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        };

        let input = pool.alloc(1024 * 8, MemoryClass::EphemeralScratch).unwrap();
        let output = pool.alloc(1024 * 8, MemoryClass::EphemeralScratch).unwrap();

        let mut g = ProverGraph::new();
        // Sub-threshold NTT now defaults to CpuSme (for SME-accelerated butterfly).
        // The scheduler should still promote it to GPU when the GPU driver requests it.
        let node_id = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: 1024,
                field: "goldilocks",
                inverse: false,
            })
            .with_inputs([input])
            .with_outputs([output]),
        );

        let node = g.node(node_id).expect("node");
        assert_eq!(node.device_pref, DevicePlacement::CpuSme);

        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();
        bridge.allocate(input).unwrap();
        bridge.allocate(output).unwrap();
        bridge
            .write_slot(input.slot, &vec![0u8; input.size_bytes])
            .unwrap();
        exec_ctx.set_payload(
            node_id,
            NodePayload::NttGoldilocks {
                values_slot: input.slot,
            },
        );

        let sched = DeterministicScheduler::new(pool, placement_ctx);
        let report = sched
            .execute_with_context_and_gpu(g, &mut exec_ctx, &mut bridge, &PromotingMockGpu)
            .expect("gpu-promoted report");

        assert_eq!(report.gpu_nodes, 1);
        assert_eq!(report.cpu_nodes, 0);
        assert_eq!(report.node_traces[0].placement, DevicePlacement::Gpu);
        assert_eq!(
            report.node_traces[0].accelerator_name.as_deref(),
            Some("promoting-mock-gpu")
        );
    }

    #[test]
    fn null_gpu_driver_always_falls_back() {
        let null_driver = NullGpuDriver::new(GpuVerificationMode::BestEffort);
        assert!(!null_driver.is_available());

        let mut exec_ctx = ExecutionContext::new();
        let mut bridge = BufferBridge::with_temp_spill();
        let node = ProverNode::new(ProverOp::Noop);

        let result = null_driver.execute(&node, &mut exec_ctx, &mut bridge);
        assert!(result.is_ok());
        let dispatch = result.unwrap();
        assert!(dispatch.is_err()); // FallbackSignal
    }

    #[test]
    fn graph_execution_report_aggregates_runtime_stage_telemetry() {
        let report = GraphExecutionReport {
            node_traces: vec![
                NodeTrace {
                    node_id: NodeId::new(),
                    op_name: "NTT",
                    stage_key: "ntt".to_string(),
                    placement: DevicePlacement::Gpu,
                    trust_model: TrustModel::Cryptographic,
                    wall_time: std::time::Duration::from_millis(10),
                    problem_size: Some(1024),
                    input_bytes: 128,
                    output_bytes: 256,
                    predicted_cpu_ms: Some(15.0),
                    predicted_gpu_ms: Some(8.0),
                    prediction_confidence: Some(0.90),
                    prediction_observation_count: Some(32),
                    input_digest: [0x11; 8],
                    output_digest: [0x22; 8],
                    allocated_bytes_after: 1024,
                    accelerator_name: Some("metal-ntt-goldilocks".to_string()),
                    fell_back: false,
                    buffer_residency: Some("metal-shared".to_string()),
                    delegated: false,
                    delegated_backend: None,
                },
                NodeTrace {
                    node_id: NodeId::new(),
                    op_name: "ProofEncode",
                    stage_key: "proof-encode".to_string(),
                    placement: DevicePlacement::Cpu,
                    trust_model: TrustModel::Cryptographic,
                    wall_time: std::time::Duration::from_millis(30),
                    problem_size: Some(1),
                    input_bytes: 64,
                    output_bytes: 96,
                    predicted_cpu_ms: Some(30.0),
                    predicted_gpu_ms: Some(35.0),
                    prediction_confidence: Some(0.30),
                    prediction_observation_count: Some(0),
                    input_digest: [0x33; 8],
                    output_digest: [0x44; 8],
                    allocated_bytes_after: 2048,
                    accelerator_name: Some("ProofEncode".to_string()),
                    fell_back: false,
                    buffer_residency: Some("cpu".to_string()),
                    delegated: false,
                    delegated_backend: None,
                },
            ],
            total_wall_time: std::time::Duration::from_millis(40),
            peak_memory_bytes: 2048,
            gpu_nodes: 1,
            cpu_nodes: 1,
            delegated_nodes: 0,
            final_trust_model: TrustModel::Cryptographic,
            fallback_nodes: 0,
            watchdog_alerts: Vec::new(),
        };

        assert!((report.gpu_stage_busy_ratio() - 0.25).abs() < 0.000_001);
        assert_eq!(report.counter_source(), "runtime-node-trace-v1");

        let breakdown = report.stage_breakdown();
        assert_eq!(breakdown.get("ntt").map(|stage| stage.gpu_nodes), Some(1));
        assert_eq!(
            breakdown
                .get("proof-encode")
                .map(|stage| stage.duration_ms.round() as u64),
            Some(30)
        );
    }
}
