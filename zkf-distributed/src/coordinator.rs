//! Distributed coordinator for TCP-based remote prove execution.

use crate::bundle::DistributedExecutionBundle;
use crate::config::ClusterConfig;
use crate::discovery::{PeerDiscovery, create_discovery};
use crate::error::DistributedError;
use crate::execution::{execute_assignment_with_capability, placement_label};
use crate::health::HealthMonitor;
use crate::identity::{
    NodeCapability, PROTOCOL_VERSION, PeerId, PeerState, SWARM_PROTOCOL_VERSION,
};
use crate::partition::strategy::PartitionStrategy;
use crate::partition::{DefaultGraphPartitioner, GraphPartition, GraphPartitioner};
use crate::protocol::{
    AssignSubgraphMsg, AttestationChainMsg, AttestationMetadata, ConsensusVoteMsg,
    EncryptedThreatEnvelopeMsg, ExecuteSubgraphMsg, HandshakeMsg, HeartbeatAckMsg, HeartbeatMsg,
    JobAbortMsg, JobCompleteMsg, MessageBody, SubgraphResultMsg, ThreatGossipMsg, WireMessage,
    heartbeat_ack_signing_bytes, heartbeat_signing_bytes,
};
use crate::swarm::{
    ConsensusCollector, Diplomat, LocalPeerIdentity, PeerThreatChannel, ReputationEvidence,
    ReputationEvidenceKind, ReputationTracker, SwarmEpochManager, ThreatIntelPayload,
    admission_pow_identity_bytes, attestation_signing_bytes, compute_admission_pow,
    decode_threat_digest, has_plaintext_threat_surface, local_identity_label, output_digest,
    persist_attestation_chain, persist_threat_intelligence_outcome, severity_to_string,
    trace_digest,
};
use crate::telemetry::{
    DistributedExecutionReport, DistributedNodeTrace, TransferDirection, TransferTrace,
};
use crate::swarm_coordinator_core;
use crate::transfer::BufferTransferManager;
use crate::transport::{Transport, create_transport};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zkf_backends::BackendRoute;
use zkf_core::artifact::{BackendKind, CompiledProgram, ProofArtifact};
use zkf_core::ir::Program;
use zkf_core::witness::{Witness, WitnessInputs};
use zkf_runtime::RuntimeExecutor;
use zkf_runtime::adapters::emit_backend_prove_graph_with_context;
use zkf_runtime::buffer_bridge::BufferBridge;
use zkf_runtime::control_plane::OptimizationObjective;
use zkf_runtime::execution::ExecutionContext;
use zkf_runtime::graph::ProverGraph;
use zkf_runtime::memory::UnifiedBufferPool;
use zkf_runtime::security::ThreatSeverity;
use zkf_runtime::swarm::{ActivationLevel, SwarmConfig, SwarmController, median_activation_level};
use zkf_runtime::telemetry::PlanExecutionResult;
use zkf_runtime::trust::{ExecutionMode, RequiredTrustLane, TrustModel};

struct RemoteExecutionResult {
    output_data: Vec<(u32, Vec<u8>)>,
    node_trace: DistributedNodeTrace,
    transfer_traces: Vec<TransferTrace>,
    total_transfer_bytes: usize,
    total_transfer_wall_time: Duration,
    compiled: Option<CompiledProgram>,
    artifact: Option<ProofArtifact>,
}

struct PartitionExecutionResult {
    output_data: Vec<(u32, Vec<u8>)>,
    node_trace: DistributedNodeTrace,
    transfer_traces: Vec<TransferTrace>,
    total_transfer_bytes: usize,
    total_transfer_wall_time: Duration,
    compiled: Option<CompiledProgram>,
    artifact: Option<ProofArtifact>,
    remote: bool,
}

struct PartitionedJobResult {
    report: DistributedExecutionReport,
    compiled: Option<CompiledProgram>,
    artifact: Option<ProofArtifact>,
}

#[derive(Default)]
struct ThreatIntelWireSurface {
    threat_digests: Vec<crate::protocol::ThreatDigestMsg>,
    activation_level: Option<u8>,
    intelligence_root: Option<String>,
    local_pressure: Option<f64>,
    network_pressure: Option<f64>,
    encrypted_threat_payload: Option<EncryptedThreatEnvelopeMsg>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterPeerReport {
    pub peer_id: String,
    pub addr: std::net::SocketAddr,
    pub alive: bool,
    pub gpu_available: bool,
    pub available_memory_bytes: u64,
    pub protocol_version: u32,
    pub swarm_capable: bool,
    pub swarm_activation_level: u8,
    pub reputation: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterStatusReport {
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_note: Option<String>,
    pub discovery: String,
    pub peer_count: usize,
    pub peers: Vec<ClusterPeerReport>,
}

pub struct DistributedBackendProofResult {
    pub report: DistributedExecutionReport,
    pub runtime_result: Option<PlanExecutionResult>,
    pub compiled: CompiledProgram,
    pub artifact: ProofArtifact,
}

/// Orchestrates distributed proving across a cluster of ZKF nodes.
pub struct DistributedCoordinator {
    config: ClusterConfig,
    swarm_config: SwarmConfig,
    transport: Box<dyn Transport>,
    transport_note: Option<String>,
    discovery: Box<dyn PeerDiscovery>,
    health: HealthMonitor,
    local_capability: NodeCapability,
    swarm_identity: LocalPeerIdentity,
    swarm_controller: SwarmController,
    diplomat: Diplomat,
    reputation: ReputationTracker,
    consensus: ConsensusCollector,
    local_excluded_peers: BTreeSet<String>,
    admitted_swarm_peers: BTreeMap<String, u128>,
    peer_threat_channels: BTreeMap<String, PeerThreatChannel>,
    admission_pow_nonce: Option<u64>,
    threat_epoch_manager: SwarmEpochManager,
    sequence: u64,
}

impl DistributedCoordinator {
    /// Create a new coordinator with a fail-closed transport selection.
    pub fn new(config: ClusterConfig) -> Result<Self, DistributedError> {
        if !ClusterConfig::is_enabled() {
            return Err(DistributedError::Disabled);
        }

        let resolved = create_transport(config.transport)?;
        let discovery = create_discovery(&config)?;
        let health = HealthMonitor::new(config.heartbeat_timeout);
        let swarm_config = SwarmConfig::from_env();
        let mut local_capability = NodeCapability::local();
        let identity_label =
            local_identity_label(&local_capability.hostname, config.bind_addr.port());
        let swarm_identity = LocalPeerIdentity::load_or_create(&swarm_config, &identity_label)
            .map_err(|err| DistributedError::Config(err.to_string()))?;
        local_capability.peer_id = swarm_identity.stable_peer_id();
        local_capability.ed25519_public_key = swarm_identity.public_key_bytes();
        local_capability.signature_scheme = Some(swarm_identity.signature_scheme());
        local_capability.public_key_bundle = Some(swarm_identity.public_key_bundle());
        let swarm_controller = if swarm_config.enabled {
            SwarmController::new(swarm_config.clone())
        } else {
            SwarmController::disabled()
        };
        let diplomat = Diplomat::new(swarm_config.gossip_max_digests_per_heartbeat);
        let reputation = ReputationTracker::new(&swarm_config)
            .map_err(|err| DistributedError::Config(err.to_string()))?;
        let consensus = ConsensusCollector::new(swarm_config.warrior.timeout_ms);

        Ok(Self {
            config,
            swarm_config,
            transport: resolved.transport,
            transport_note: resolved.fallback_note,
            discovery,
            health,
            local_capability,
            swarm_identity,
            swarm_controller,
            diplomat,
            reputation,
            consensus,
            local_excluded_peers: BTreeSet::new(),
            admitted_swarm_peers: BTreeMap::new(),
            peer_threat_channels: BTreeMap::new(),
            admission_pow_nonce: None,
            threat_epoch_manager: SwarmEpochManager::new(),
            sequence: 0,
        })
    }

    pub fn transport_name(&self) -> &'static str {
        self.transport.name()
    }

    pub fn transport_note(&self) -> Option<&str> {
        self.transport_note.as_deref()
    }

    fn cluster_activation_level(&self) -> ActivationLevel {
        let mut levels = self.health.alive_swarm_activation_levels();
        levels.push(self.swarm_controller.activation_level() as u8);
        median_activation_level(&levels)
    }

    fn cluster_activation_level_u8(&self) -> u8 {
        self.cluster_activation_level() as u8
    }

    fn local_admission_pow_nonce(&mut self) -> Option<u64> {
        if !self.swarm_config.enabled {
            return None;
        }
        if let Some(nonce) = self.admission_pow_nonce {
            return Some(nonce);
        }
        let admission_identity = admission_pow_identity_bytes(
            &self.local_capability.ed25519_public_key,
            self.local_capability.public_key_bundle.as_ref(),
        );
        let nonce = compute_admission_pow(
            &admission_identity,
            self.swarm_config.admission_pow_difficulty,
        );
        self.admission_pow_nonce = Some(nonce);
        Some(nonce)
    }

    fn register_admitted_swarm_peer(&mut self, peer_id: &PeerId) -> Result<(), DistributedError> {
        let now_ms = unix_time_now_ms();
        self.admitted_swarm_peers
            .retain(|_, seen_at| now_ms.saturating_sub(*seen_at) <= 2 * 60 * 60 * 1000);
        if self.admitted_swarm_peers.contains_key(&peer_id.0) {
            return Ok(());
        }
        let recent_cutoff = now_ms.saturating_sub(60 * 60 * 1000);
        let new_peers_in_last_hour = self
            .admitted_swarm_peers
            .values()
            .filter(|seen_at| **seen_at >= recent_cutoff)
            .count();
        let established_peer_count = self
            .admitted_swarm_peers
            .values()
            .filter(|seen_at| **seen_at < recent_cutoff)
            .count()
            .max(1);
        let allowed_new_peers = established_peer_count
            .saturating_mul(self.swarm_config.max_new_peers_per_hour_multiplier.max(1));
        if new_peers_in_last_hour >= allowed_new_peers {
            return Err(DistributedError::HandshakeFailed {
                peer_id: peer_id.0.clone(),
                reason: format!(
                    "admission rate limit exceeded: {} new peers in the last hour with {} established peers",
                    new_peers_in_last_hour, established_peer_count
                ),
            });
        }
        self.admitted_swarm_peers.insert(peer_id.0.clone(), now_ms);
        Ok(())
    }

    fn fan_out_attestation_chain(&mut self, origin_peer: &PeerId, chain: &AttestationChainMsg) {
        let recipients = self
            .health
            .alive_peers()
            .into_iter()
            .filter(|peer| peer.swarm_capable && peer.capability.peer_id != *origin_peer)
            .map(|peer| (peer.capability.peer_id.clone(), peer.addr))
            .collect::<Vec<_>>();
        for (peer_id, addr) in recipients {
            match self.transport.connect(addr) {
                Ok(mut conn) => {
                    let message = WireMessage {
                        version: PROTOCOL_VERSION,
                        sender: self.local_capability.peer_id.clone(),
                        sequence: self.sequence,
                        body: MessageBody::AttestationChain(chain.clone()),
                    };
                    self.sequence += 1;
                    if let Err(err) = conn.send(&message) {
                        log::warn!("failed to fan out attestation chain to {}: {err}", peer_id);
                    }
                }
                Err(err) => {
                    log::warn!(
                        "failed to connect for attestation fan-out to {}: {err}",
                        peer_id
                    );
                }
            }
        }
    }

    fn verify_attestation_chain(&self, chain: &AttestationChainMsg) -> bool {
        chain.attestations.iter().all(|attestation| {
            LocalPeerIdentity::verify_signed_message(
                &attestation.public_key,
                attestation.public_key_bundle.as_ref(),
                &attestation_signing_bytes(
                    &chain.job_id,
                    chain.partition_id,
                    attestation.output_digest,
                    attestation.trace_digest,
                    attestation.activation_level,
                ),
                &attestation.signature,
                attestation.signature_bundle.as_ref(),
            )
        })
    }

    pub fn status(&mut self) -> Result<ClusterStatusReport, DistributedError> {
        let peers = self.discover_live_peers()?;
        Ok(ClusterStatusReport {
            transport: self.transport.name().to_string(),
            transport_note: self.transport_note.clone(),
            discovery: self.discovery.name().to_string(),
            peer_count: peers.len(),
            peers: peers
                .into_iter()
                .map(|peer| ClusterPeerReport {
                    peer_id: peer.capability.peer_id.0,
                    addr: peer.addr,
                    alive: peer.alive,
                    gpu_available: peer.capability.gpu_available,
                    available_memory_bytes: peer.capability.resources.available_memory_bytes,
                    protocol_version: peer.capability.protocol_version,
                    swarm_capable: peer.swarm_capable,
                    swarm_activation_level: peer.swarm_activation_level,
                    reputation: peer.reputation,
                })
                .collect(),
        })
    }

    /// Execute a graph remotely when peers are available; otherwise return an honest
    /// local-fallback telemetry report without pretending remote execution happened.
    pub fn prove_distributed(
        &mut self,
        graph: &ProverGraph,
        exec_ctx: &ExecutionContext,
        _bridge: &mut BufferBridge,
    ) -> Result<DistributedExecutionReport, DistributedError> {
        let job_id = self.next_job_id();
        if graph.node_count() < self.config.min_distribute_graph_nodes {
            return Ok(DistributedExecutionReport::local_fallback(
                job_id,
                Duration::ZERO,
            ));
        }
        let live_peers = self.discover_live_peers()?;
        self.swarm_controller.note_gossip_peers_count(
            live_peers.iter().filter(|peer| peer.swarm_capable).count() as u32,
        );
        if live_peers.is_empty() {
            return Ok(DistributedExecutionReport::local_fallback(
                job_id,
                Duration::ZERO,
            ));
        }
        Ok(self
            .execute_partitioned_job(&job_id, graph, exec_ctx, &live_peers)?
            .report)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_backend_job_distributed(
        &mut self,
        backend: BackendKind,
        route: BackendRoute,
        program: Arc<Program>,
        inputs: Option<Arc<WitnessInputs>>,
        witness: Option<Arc<Witness>>,
        compiled: Option<Arc<CompiledProgram>>,
        objective: OptimizationObjective,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<DistributedBackendProofResult, DistributedError> {
        let job_id = self.next_job_id();
        let compiled_for_local = compiled.clone();
        let graph_emission = {
            let mut pool = UnifiedBufferPool::new(512 * 1024 * 1024);
            let mut emission = emit_backend_prove_graph_with_context(
                &mut pool,
                backend,
                route,
                Arc::clone(&program),
                inputs.clone(),
                witness.clone(),
                trust_model_for_lane(trust),
                mode == ExecutionMode::Deterministic,
            )?;
            if let Some(compiled) = compiled {
                emission.exec_ctx.compiled = Some(compiled);
            }
            emission.exec_ctx.optimization_objective = objective;
            emission
        };

        if graph_emission.graph.node_count() < self.config.min_distribute_graph_nodes {
            return self.run_backend_prove_locally(
                job_id,
                backend,
                route,
                program,
                inputs,
                witness,
                compiled_for_local.clone(),
                objective,
                trust,
                mode,
            );
        }

        let live_peers = self.discover_live_peers()?;
        if live_peers.is_empty() {
            return self.run_backend_prove_locally(
                job_id,
                backend,
                route,
                program,
                inputs,
                witness,
                compiled_for_local,
                objective,
                trust,
                mode,
            );
        }

        let distributed = self.execute_partitioned_job(
            &job_id,
            &graph_emission.graph,
            &graph_emission.exec_ctx,
            &live_peers,
        )?;
        let compiled =
            distributed
                .compiled
                .ok_or_else(|| DistributedError::PeerExecutionFailed {
                    peer_id: self.local_capability.peer_id.0.clone(),
                    reason: "distributed execution did not materialize a compiled program".into(),
                })?;
        let artifact =
            distributed
                .artifact
                .ok_or_else(|| DistributedError::PeerExecutionFailed {
                    peer_id: self.local_capability.peer_id.0.clone(),
                    reason: "distributed execution did not materialize a proof artifact".into(),
                })?;

        Ok(DistributedBackendProofResult {
            report: distributed.report,
            runtime_result: None,
            compiled,
            artifact,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_backend_prove_locally(
        &mut self,
        job_id: String,
        backend: BackendKind,
        route: BackendRoute,
        program: Arc<Program>,
        inputs: Option<Arc<WitnessInputs>>,
        witness: Option<Arc<Witness>>,
        compiled: Option<Arc<CompiledProgram>>,
        objective: OptimizationObjective,
        trust: RequiredTrustLane,
        mode: ExecutionMode,
    ) -> Result<DistributedBackendProofResult, DistributedError> {
        let started = Instant::now();
        let execution = RuntimeExecutor::run_backend_prove_job_with_objective(
            backend,
            route,
            Arc::clone(&program),
            inputs,
            witness,
            compiled,
            objective,
            trust,
            mode,
        )?;
        let total_wall_time = started.elapsed();

        let report = DistributedExecutionReport {
            job_id,
            total_wall_time,
            partition_count: 1,
            remote_partition_count: 0,
            local_partition_count: 1,
            peer_count: 0,
            node_traces: vec![DistributedNodeTrace {
                peer_id: self.local_capability.peer_id.clone(),
                partition_id: 0,
                wall_time: execution.result.report.total_wall_time,
                node_count: execution.result.report.node_traces.len(),
                trace_entries: execution
                    .result
                    .report
                    .node_traces
                    .iter()
                    .map(|trace| crate::protocol::SubgraphTraceEntry {
                        node_name: trace.op_name.to_string(),
                        wall_time_ms: trace.wall_time.as_millis() as u64,
                        device: placement_label(trace.placement).to_string(),
                    })
                    .collect(),
            }],
            transfer_traces: Vec::new(),
            total_transfer_bytes: 0,
            total_compute_wall_time: execution.result.report.total_wall_time,
            total_transfer_wall_time: Duration::ZERO,
            fallback_partitions: 0,
            distribution_profitable: false,
            speedup_ratio: 1.0,
        };

        Ok(DistributedBackendProofResult {
            report,
            runtime_result: Some(execution.result),
            compiled: execution.compiled,
            artifact: execution.artifact,
        })
    }

    fn execute_partitioned_job(
        &mut self,
        job_id: &str,
        graph: &ProverGraph,
        exec_ctx: &ExecutionContext,
        live_peers: &[PeerState],
    ) -> Result<PartitionedJobResult, DistributedError> {
        let started = Instant::now();
        let partitioner = DefaultGraphPartitioner::new();
        let partitions = partitioner.partition(graph, PartitionStrategy::PhaseBoundary)?;
        if partitions.is_empty() {
            return Err(DistributedError::PartitionFailed {
                reason: "partitioner produced no partitions".into(),
            });
        }
        let dependencies = self.partition_dependencies(graph, &partitions)?;
        let mut completed = BTreeSet::new();
        let mut boundary_buffers: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut compiled = exec_ctx.compiled.as_deref().cloned();
        let mut artifact = exec_ctx.proof_artifact.clone();
        let mut node_traces = Vec::new();
        let mut transfer_traces = Vec::new();
        let mut total_transfer_bytes = 0usize;
        let mut total_compute_wall_time = Duration::ZERO;
        let mut total_transfer_wall_time = Duration::ZERO;
        let mut remote_partition_count = 0usize;
        let mut local_partition_count = 0usize;
        let mut fallback_partitions = 0usize;
        let mut used_remote_peers = HashSet::new();

        while completed.len() < partitions.len() {
            let ready: Vec<usize> = dependencies
                .iter()
                .enumerate()
                .filter(|(index, deps)| {
                    !completed.contains(index) && deps.iter().all(|dep| completed.contains(dep))
                })
                .map(|(index, _)| index)
                .collect();
            if ready.is_empty() {
                return Err(DistributedError::PartitionFailed {
                    reason: "partition dependency graph stalled before completion".into(),
                });
            }

            for partition_index in ready {
                let partition = &partitions[partition_index];
                let input_buffers =
                    self.resolve_partition_inputs(exec_ctx, partition, &boundary_buffers)?;
                let required_output_slots: Vec<u32> = partition
                    .output_boundary_slots
                    .iter()
                    .map(|(slot, _)| *slot)
                    .collect();
                let bundle = DistributedExecutionBundle::from_partition_and_context(
                    graph,
                    exec_ctx,
                    &partition.node_ids,
                    &required_output_slots,
                    compiled.as_ref(),
                    artifact.as_ref(),
                )?;

                let execution_result = if partition.local_only {
                    self.execute_local_partition(partition, bundle, input_buffers)?
                } else if let Some(peer) = self.select_peer(live_peers, partition.estimated_work) {
                    match self.execute_remote_bundle(
                        job_id,
                        partition,
                        peer,
                        &bundle,
                        &input_buffers,
                    ) {
                        Ok(remote) => PartitionExecutionResult {
                            output_data: remote.output_data,
                            node_trace: remote.node_trace,
                            transfer_traces: remote.transfer_traces,
                            total_transfer_bytes: remote.total_transfer_bytes,
                            total_transfer_wall_time: remote.total_transfer_wall_time,
                            compiled: remote.compiled,
                            artifact: remote.artifact,
                            remote: true,
                        },
                        Err(err) if should_retry_locally(&err) => {
                            fallback_partitions += 1;
                            log::warn!(
                                "remote partition {} of job {} failed on peer {}: {err}; retrying locally",
                                partition.partition_id,
                                job_id,
                                peer.capability.peer_id
                            );
                            self.execute_local_partition(partition, bundle, input_buffers)?
                        }
                        Err(err) => return Err(err),
                    }
                } else {
                    self.execute_local_partition(partition, bundle, input_buffers)?
                };

                for (slot, bytes) in &execution_result.output_data {
                    boundary_buffers.insert(*slot, bytes.clone());
                }
                if let Some(next_compiled) = execution_result.compiled {
                    compiled = Some(next_compiled);
                }
                if let Some(next_artifact) = execution_result.artifact {
                    artifact = Some(next_artifact);
                }
                total_transfer_bytes += execution_result.total_transfer_bytes;
                total_transfer_wall_time += execution_result.total_transfer_wall_time;
                total_compute_wall_time += execution_result.node_trace.wall_time;
                if execution_result.remote {
                    remote_partition_count += 1;
                    used_remote_peers.insert(execution_result.node_trace.peer_id.0.clone());
                } else {
                    local_partition_count += 1;
                }
                node_traces.push(execution_result.node_trace);
                transfer_traces.extend(execution_result.transfer_traces);
                completed.insert(partition_index);
            }
        }

        let total_wall_time = started.elapsed();
        let distribution_profitable =
            remote_partition_count > 0 && fallback_partitions == 0 && total_transfer_bytes > 0;

        Ok(PartitionedJobResult {
            report: DistributedExecutionReport {
                job_id: job_id.to_string(),
                total_wall_time,
                partition_count: partitions.len(),
                remote_partition_count,
                local_partition_count,
                peer_count: used_remote_peers.len(),
                node_traces,
                transfer_traces,
                total_transfer_bytes,
                total_compute_wall_time,
                total_transfer_wall_time,
                fallback_partitions,
                distribution_profitable,
                speedup_ratio: 1.0,
            },
            compiled,
            artifact,
        })
    }

    fn partition_dependencies(
        &self,
        graph: &ProverGraph,
        partitions: &[GraphPartition],
    ) -> Result<Vec<BTreeSet<usize>>, DistributedError> {
        let mut partition_by_node = HashMap::new();
        for (partition_index, partition) in partitions.iter().enumerate() {
            for node_id in &partition.node_ids {
                partition_by_node.insert(*node_id, partition_index);
            }
        }

        let mut dependencies = vec![BTreeSet::new(); partitions.len()];
        for (partition_index, partition) in partitions.iter().enumerate() {
            for node_id in &partition.node_ids {
                let node =
                    graph
                        .node(*node_id)
                        .ok_or_else(|| DistributedError::PartitionFailed {
                            reason: format!("partition referenced missing node {:?}", node_id),
                        })?;
                for dep_id in &node.deps {
                    if let Some(dep_partition_index) = partition_by_node.get(dep_id)
                        && *dep_partition_index != partition_index
                    {
                        dependencies[partition_index].insert(*dep_partition_index);
                    }
                }
            }
        }

        Ok(dependencies)
    }

    fn resolve_partition_inputs(
        &self,
        exec_ctx: &ExecutionContext,
        partition: &GraphPartition,
        boundary_buffers: &HashMap<u32, Vec<u8>>,
    ) -> Result<HashMap<u32, Vec<u8>>, DistributedError> {
        let mut resolved = HashMap::with_capacity(partition.input_boundary_slots.len());
        for (slot, _) in &partition.input_boundary_slots {
            if let Some(bytes) = boundary_buffers.get(slot) {
                resolved.insert(*slot, bytes.clone());
                continue;
            }
            if let Some(bytes) = exec_ctx.initial_buffer(*slot) {
                resolved.insert(*slot, bytes.to_vec());
                continue;
            }
            return Err(DistributedError::TransferFailed {
                slot: *slot,
                reason: format!(
                    "missing boundary buffer for partition {} of distributed job",
                    partition.partition_id
                ),
            });
        }
        Ok(resolved)
    }

    fn execute_local_partition(
        &self,
        partition: &GraphPartition,
        bundle: DistributedExecutionBundle,
        input_buffers: HashMap<u32, Vec<u8>>,
    ) -> Result<PartitionExecutionResult, DistributedError> {
        let executed = execute_assignment_with_capability(
            &self.local_capability,
            bundle,
            input_buffers,
            self.cluster_activation_level_u8(),
        )?;
        log::info!(
            "executed partition {} locally (nodes={}, outputs={}, gpu_driver={})",
            partition.partition_id,
            partition.node_ids.len(),
            executed.output_data.len(),
            executed.gpu_driver_used
        );
        Ok(PartitionExecutionResult {
            output_data: executed.output_data,
            node_trace: DistributedNodeTrace {
                peer_id: self.local_capability.peer_id.clone(),
                partition_id: partition.partition_id,
                wall_time: executed.wall_time,
                node_count: partition.node_ids.len(),
                trace_entries: executed.trace_entries,
            },
            transfer_traces: Vec::new(),
            total_transfer_bytes: 0,
            total_transfer_wall_time: Duration::ZERO,
            compiled: executed.compiled_program,
            artifact: executed.proof_artifact,
            remote: false,
        })
    }

    fn discover_live_peers(&mut self) -> Result<Vec<PeerState>, DistributedError> {
        if let Some(note) = &self.transport_note {
            log::warn!("{note}");
        }

        for peer_id in self.health.check_liveness() {
            let _ = self.reputation.record_event(
                &peer_id,
                ReputationEvidenceKind::HeartbeatTimeout,
                ReputationEvidence {
                    observed_at_unix_ms: unix_time_now_ms(),
                    ..Default::default()
                },
            );
        }

        let discovered = self.discovery.discover()?;
        let mut live_peers = Vec::new();
        for peer in &discovered {
            let was_timed_out = self
                .health
                .get_peer(&peer.capability.peer_id)
                .map(|state| !state.alive)
                .unwrap_or(false);
            match self.handshake_peer(peer) {
                Ok(state) => {
                    if was_timed_out {
                        let _ = self.reputation.record_event(
                            &state.capability.peer_id,
                            ReputationEvidenceKind::HeartbeatResumed,
                            ReputationEvidence {
                                observed_at_unix_ms: unix_time_now_ms(),
                                ..Default::default()
                            },
                        );
                    }
                    self.health.update_peer(state.clone());
                    live_peers.push(state);
                }
                Err(err) => {
                    log::warn!("handshake failed with {}: {err}", peer.addr);
                }
            }
        }
        Ok(live_peers)
    }

    fn handshake_peer(&mut self, peer: &PeerState) -> Result<PeerState, DistributedError> {
        let mut conn = self.transport.connect(peer.addr)?;

        let threat_advertisement = self.local_threat_epoch_advertisement();
        let signing_bytes = handshake_signing_bytes(
            &self.local_capability,
            SWARM_PROTOCOL_VERSION,
            threat_advertisement.encrypted_threat_gossip_supported,
            threat_advertisement.threat_epoch_id,
            threat_advertisement.threat_epoch_public_key.as_deref(),
        );
        let handshake_signature = self.swarm_identity.sign(&signing_bytes);
        let handshake_signature_bundle = self.swarm_identity.sign_bundle(&signing_bytes);
        let msg = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::Handshake(HandshakeMsg {
                capability: self.local_capability.clone(),
                ed25519_public_key: self.local_capability.ed25519_public_key.clone(),
                handshake_signature,
                public_key_bundle: self.local_capability.public_key_bundle.clone(),
                handshake_signature_bundle: Some(handshake_signature_bundle),
                swarm_protocol_version: if self.swarm_config.enabled {
                    SWARM_PROTOCOL_VERSION
                } else {
                    0
                },
                admission_pow_nonce: self.local_admission_pow_nonce(),
                encrypted_threat_gossip_supported: threat_advertisement
                    .encrypted_threat_gossip_supported,
                threat_epoch_id: threat_advertisement.threat_epoch_id,
                threat_epoch_public_key: threat_advertisement.threat_epoch_public_key,
            }),
        };
        self.sequence += 1;
        conn.send(&msg)?;

        let response = conn.recv(Some(Duration::from_secs(5)))?;
        match response.body {
            MessageBody::HandshakeAck(ref ack) => {
                if !ack.accepted {
                    return Err(DistributedError::HandshakeFailed {
                        peer_id: peer.capability.peer_id.0.clone(),
                        reason: ack.reason.clone().unwrap_or_else(|| "rejected".into()),
                    });
                }
                if ack.capability.protocol_version != PROTOCOL_VERSION {
                    return Err(DistributedError::ProtocolVersionMismatch {
                        local: PROTOCOL_VERSION,
                        remote: ack.capability.protocol_version,
                    });
                }
                let swarm_capable = ack.swarm_protocol_version >= SWARM_PROTOCOL_VERSION
                    && !ack.ed25519_public_key.is_empty()
                    && !ack.handshake_signature.is_empty();
                if swarm_capable
                    && !LocalPeerIdentity::verify_signed_message(
                        &ack.ed25519_public_key,
                        ack.public_key_bundle.as_ref(),
                        &handshake_signing_bytes(
                            &ack.capability,
                            ack.swarm_protocol_version,
                            ack.encrypted_threat_gossip_supported,
                            ack.threat_epoch_id,
                            ack.threat_epoch_public_key.as_deref(),
                        ),
                        &ack.handshake_signature,
                        ack.handshake_signature_bundle.as_ref(),
                    )
                {
                    return Err(DistributedError::HandshakeFailed {
                        peer_id: ack.capability.peer_id.0.clone(),
                        reason: "invalid swarm handshake signature".into(),
                    });
                }

                let mut capability = ack.capability.clone();
                if capability.ed25519_public_key.is_empty() {
                    capability.ed25519_public_key = ack.ed25519_public_key.clone();
                }
                if capability.public_key_bundle.is_none() {
                    capability.public_key_bundle = ack.public_key_bundle.clone();
                }
                if capability.signature_scheme.is_none() {
                    capability.signature_scheme =
                        ack.public_key_bundle.as_ref().map(|bundle| bundle.scheme);
                }
                self.register_admitted_swarm_peer(&capability.peer_id)?;
                let mut state = PeerState::new(capability.clone(), peer.addr);
                state.reputation = self.reputation.score_for(&capability.peer_id);
                state.swarm_capable = swarm_capable;
                self.note_peer_threat_advertisement(
                    &capability.peer_id,
                    ack.encrypted_threat_gossip_supported,
                    ack.threat_epoch_id,
                    ack.threat_epoch_public_key.as_deref(),
                    None,
                );
                Ok(state)
            }
            _ => Err(DistributedError::HandshakeFailed {
                peer_id: peer.capability.peer_id.0.clone(),
                reason: "unexpected response type".into(),
            }),
        }
    }

    fn select_peer<'a>(
        &self,
        peers: &'a [PeerState],
        estimated_work: u64,
    ) -> Option<&'a PeerState> {
        peers
            .iter()
            .filter(|peer| peer.alive)
            .filter(|peer| {
                !self
                    .local_excluded_peers
                    .contains(&peer.capability.peer_id.0)
            })
            .max_by_key(|peer| {
                peer.capability
                    .placement_score(true, Some(peer.reputation))
                    .saturating_add(estimated_work)
                    .saturating_sub(peer.current_buffer_bytes / (1024 * 1024))
            })
    }

    fn execute_remote_bundle(
        &mut self,
        job_id: &str,
        partition: &GraphPartition,
        peer: &PeerState,
        bundle: &DistributedExecutionBundle,
        input_buffers: &HashMap<u32, Vec<u8>>,
    ) -> Result<RemoteExecutionResult, DistributedError> {
        let mut conn = self.transport.connect(peer.addr)?;
        let transfer_manager = BufferTransferManager::new(&self.config);

        let assign = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::AssignSubgraph(AssignSubgraphMsg {
                job_id: job_id.to_string(),
                partition_id: partition.partition_id,
                subgraph_data: bundle.encode_postcard()?,
                input_boundary_slots: partition.input_boundary_slots.clone(),
                output_boundary_slots: partition.output_boundary_slots.clone(),
                estimated_work: partition.estimated_work,
            }),
        };
        self.sequence += 1;
        conn.send(&assign)?;

        let ack = conn.recv(Some(Duration::from_secs(10)))?;
        match ack.body {
            MessageBody::AssignAck(ref assign_ack) if assign_ack.accepted => {}
            MessageBody::AssignAck(ref assign_ack) => {
                return Err(DistributedError::PeerRejected {
                    peer_id: peer.capability.peer_id.0.clone(),
                    reason: assign_ack
                        .reason
                        .clone()
                        .unwrap_or_else(|| "assignment rejected".into()),
                });
            }
            _ => {
                return Err(DistributedError::PeerRejected {
                    peer_id: peer.capability.peer_id.0.clone(),
                    reason: "unexpected response to assignment".into(),
                });
            }
        }

        if peer.swarm_capable && self.swarm_config.enabled {
            self.send_reputation_sync(&mut *conn)?;
        }

        let mut transfer_traces = Vec::new();
        let mut total_transfer_bytes = 0usize;
        let mut total_transfer_wall_time = Duration::ZERO;
        for (slot, _) in &partition.input_boundary_slots {
            let data = input_buffers
                .get(slot)
                .ok_or_else(|| DistributedError::TransferFailed {
                    slot: *slot,
                    reason: format!(
                        "coordinator could not resolve boundary input slot {} for partition {}",
                        slot, partition.partition_id
                    ),
                })?;
            let stats = transfer_manager.send_buffer(
                &mut *conn,
                &self.local_capability.peer_id,
                job_id,
                *slot,
                data,
                &mut self.sequence,
            )?;
            total_transfer_bytes += stats.total_bytes;
            total_transfer_wall_time += stats.wall_time;
            transfer_traces.push(TransferTrace {
                slot: *slot,
                direction: TransferDirection::Send,
                peer_id: peer.capability.peer_id.clone(),
                total_bytes: stats.total_bytes,
                compressed_bytes: stats.compressed_bytes,
                wall_time: stats.wall_time,
                throughput_gbps: stats.throughput_gbps,
            });
        }

        let exec = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::ExecuteSubgraph(ExecuteSubgraphMsg {
                job_id: job_id.to_string(),
                partition_id: partition.partition_id,
            }),
        };
        self.sequence += 1;
        conn.send(&exec)?;

        let overall_timeout = Duration::from_secs(300);
        let deadline = Instant::now() + overall_timeout;
        let mut next_heartbeat = Instant::now() + self.config.heartbeat_interval;
        let mut last_liveness = Instant::now();

        loop {
            let now = Instant::now();
            if now >= deadline {
                self.health.mark_dead(&peer.capability.peer_id);
                let _ = self.reputation.record_event(
                    &peer.capability.peer_id,
                    ReputationEvidenceKind::HeartbeatTimeout,
                    ReputationEvidence {
                        job_id: Some(job_id.to_string()),
                        partition_id: Some(partition.partition_id),
                        observed_at_unix_ms: unix_time_now_ms(),
                        ..Default::default()
                    },
                );
                return Err(DistributedError::Timeout {
                    peer_id: peer.capability.peer_id.0.clone(),
                    operation: "execute-subgraph".to_string(),
                });
            }

            if now >= next_heartbeat {
                self.send_heartbeat(&peer.capability.peer_id, &mut *conn)?;
                next_heartbeat = now + self.config.heartbeat_interval;
            }

            let poll_timeout = deadline.saturating_duration_since(now).min(
                self.config
                    .heartbeat_interval
                    .max(Duration::from_millis(50)),
            );
            let result = match conn.recv(Some(poll_timeout)) {
                Ok(result) => result,
                Err(err) if is_timeout_error(&err) => {
                    if now.duration_since(last_liveness) >= self.config.heartbeat_timeout {
                        self.health.mark_dead(&peer.capability.peer_id);
                        let _ = self.reputation.record_event(
                            &peer.capability.peer_id,
                            ReputationEvidenceKind::HeartbeatTimeout,
                            ReputationEvidence {
                                job_id: Some(job_id.to_string()),
                                partition_id: Some(partition.partition_id),
                                observed_at_unix_ms: unix_time_now_ms(),
                                ..Default::default()
                            },
                        );
                        return Err(DistributedError::Timeout {
                            peer_id: peer.capability.peer_id.0.clone(),
                            operation: "heartbeat".to_string(),
                        });
                    }
                    continue;
                }
                Err(err) => {
                    self.health.mark_dead(&peer.capability.peer_id);
                    return Err(err);
                }
            };
            let message_sequence = result.sequence;

            match result.body {
                MessageBody::HeartbeatAck(ref heartbeat_ack) if heartbeat_ack.acknowledged => {
                    if heartbeat_ack.signature_bundle.is_some()
                        && !LocalPeerIdentity::verify_signed_message(
                            &peer.capability.ed25519_public_key,
                            peer.capability.public_key_bundle.as_ref(),
                            &heartbeat_ack_signing_bytes(heartbeat_ack),
                            &[],
                            heartbeat_ack.signature_bundle.as_ref(),
                        )
                    {
                        log::warn!(
                            "invalid signed heartbeat acknowledgement from {}",
                            peer.capability.peer_id
                        );
                        continue;
                    }
                    last_liveness = Instant::now();
                    self.health.record_heartbeat(
                        &peer.capability.peer_id,
                        peer.capability.pressure_level,
                        0,
                        0,
                        heartbeat_ack.activation_level,
                    );
                    self.note_peer_threat_advertisement(
                        &peer.capability.peer_id,
                        heartbeat_ack.encrypted_threat_gossip_supported,
                        heartbeat_ack.threat_epoch_id,
                        heartbeat_ack.threat_epoch_public_key.as_deref(),
                        Some("encrypted-threat-intel-advertisement"),
                    );
                    if let Some(payload) = self.decode_threat_wire_surface(
                        peer,
                        "heartbeat-ack",
                        message_sequence,
                        &heartbeat_ack.threat_digests,
                        heartbeat_ack.activation_level,
                        heartbeat_ack.intelligence_root.as_deref(),
                        heartbeat_ack.local_pressure,
                        heartbeat_ack.network_pressure,
                        heartbeat_ack.encrypted_threat_payload.as_ref(),
                    ) {
                        let intelligence_root = self.ingest_swarm_digests(
                            peer,
                            &payload.digests,
                            payload.activation_level,
                            combine_pressure(payload.local_pressure, payload.network_pressure),
                        );
                        self.persist_peer_threat_intelligence(
                            &peer.capability.peer_id,
                            "encrypted-threat-intelligence",
                            &intelligence_root,
                            &payload,
                        );
                    }
                }
                MessageBody::Heartbeat(ref heartbeat) => {
                    if heartbeat.signature_bundle.is_some()
                        && !LocalPeerIdentity::verify_signed_message(
                            &peer.capability.ed25519_public_key,
                            peer.capability.public_key_bundle.as_ref(),
                            &heartbeat_signing_bytes(heartbeat),
                            &[],
                            heartbeat.signature_bundle.as_ref(),
                        )
                    {
                        log::warn!("invalid signed heartbeat from {}", peer.capability.peer_id);
                        continue;
                    }
                    last_liveness = Instant::now();
                    self.health.record_heartbeat(
                        &peer.capability.peer_id,
                        heartbeat.pressure,
                        heartbeat.active_subgraph_count,
                        heartbeat.current_buffer_bytes,
                        heartbeat.activation_level,
                    );
                    self.note_peer_threat_advertisement(
                        &peer.capability.peer_id,
                        heartbeat.encrypted_threat_gossip_supported,
                        heartbeat.threat_epoch_id,
                        heartbeat.threat_epoch_public_key.as_deref(),
                        Some("encrypted-threat-intel-advertisement"),
                    );
                    if let Some(payload) = self.decode_threat_wire_surface(
                        peer,
                        "heartbeat",
                        message_sequence,
                        &heartbeat.threat_digests,
                        heartbeat.activation_level,
                        heartbeat.intelligence_root.as_deref(),
                        heartbeat.local_pressure,
                        heartbeat.network_pressure,
                        heartbeat.encrypted_threat_payload.as_ref(),
                    ) {
                        let intelligence_root = self.ingest_swarm_digests(
                            peer,
                            &payload.digests,
                            payload.activation_level,
                            combine_pressure(payload.local_pressure, payload.network_pressure),
                        );
                        self.persist_peer_threat_intelligence(
                            &peer.capability.peer_id,
                            "encrypted-threat-intelligence",
                            &intelligence_root,
                            &payload,
                        );
                    }
                    self.send_heartbeat_ack(&peer.capability.peer_id, &mut *conn)?;
                }
                MessageBody::ThreatGossip(ref gossip) => {
                    if let Some(payload) = self.decode_threat_wire_surface(
                        peer,
                        "threat-gossip",
                        message_sequence,
                        &gossip.digests,
                        gossip.activation_level,
                        gossip.intelligence_root.as_deref(),
                        gossip.local_pressure,
                        gossip.network_pressure,
                        gossip.encrypted_threat_payload.as_ref(),
                    ) {
                        let intelligence_root = self.ingest_swarm_gossip(
                            peer,
                            &ThreatGossipMsg {
                                digests: payload.digests.clone(),
                                activation_level: payload.activation_level,
                                intelligence_root: payload.intelligence_root.clone(),
                                local_pressure: payload.local_pressure,
                                network_pressure: payload.network_pressure,
                                encrypted_threat_payload: None,
                            },
                        );
                        self.persist_peer_threat_intelligence(
                            &peer.capability.peer_id,
                            "encrypted-threat-intelligence",
                            &intelligence_root,
                            &payload,
                        );
                    }
                }
                MessageBody::AttestationChain(ref chain) => {
                    if self.verify_attestation_chain(chain) {
                        let _ = persist_attestation_chain(&self.swarm_config, chain);
                    } else {
                        log::warn!(
                            "ignoring invalid attestation chain for job {} partition {} from {}",
                            chain.job_id,
                            chain.partition_id,
                            peer.capability.peer_id
                        );
                    }
                }
                MessageBody::ReputationSync(ref sync) => {
                    let _ = self.reputation.apply_advisory_snapshot(sync);
                }
                MessageBody::SubgraphResult(ref subgraph) => {
                    let wall_time = Duration::from_millis(subgraph.wall_time_ms);
                    if let Some(attestation) = &subgraph.attestation
                        && !self.verify_attestation(
                            job_id,
                            partition.partition_id,
                            subgraph,
                            attestation,
                        )
                    {
                        let _ = self.reputation.record_event(
                            &peer.capability.peer_id,
                            ReputationEvidenceKind::AttestationInvalid,
                            ReputationEvidence {
                                job_id: Some(job_id.to_string()),
                                partition_id: Some(partition.partition_id),
                                digest_hash: Some(output_digest(
                                    &subgraph.output_data,
                                    &subgraph.named_outputs,
                                )),
                                signature: Some(attestation.signature.clone()),
                                observed_at_unix_ms: unix_time_now_ms(),
                                ..Default::default()
                            },
                        );
                        self.local_excluded_peers
                            .insert(peer.capability.peer_id.0.clone());
                        self.swarm_controller
                            .note_low_reputation_peer(peer.capability.peer_id.0.clone());
                        self.swarm_controller
                            .record_consensus_result(false, ThreatSeverity::Critical);
                        return Err(DistributedError::PeerExecutionFailed {
                            peer_id: peer.capability.peer_id.0.clone(),
                            reason: "swarm attestation verification failed".into(),
                        });
                    }
                    let compiled = subgraph
                        .compiled_program
                        .as_ref()
                        .map(|bytes| serde_json::from_slice(bytes))
                        .transpose()?;
                    let artifact = subgraph
                        .proof_artifact
                        .as_ref()
                        .map(|bytes| serde_json::from_slice(bytes))
                        .transpose()?;
                    for (slot, bytes) in &subgraph.output_data {
                        total_transfer_bytes += bytes.len();
                        transfer_traces.push(TransferTrace {
                            slot: *slot,
                            direction: TransferDirection::Recv,
                            peer_id: peer.capability.peer_id.clone(),
                            total_bytes: bytes.len(),
                            compressed_bytes: None,
                            wall_time: Duration::ZERO,
                            throughput_gbps: 0.0,
                        });
                    }
                    if self.should_require_quorum(peer) {
                        self.verify_quorum_result(
                            job_id,
                            partition.partition_id,
                            peer,
                            bundle,
                            input_buffers,
                            subgraph,
                        )?;
                    } else if let Some(attestation) = &subgraph.attestation {
                        let _ = self.reputation.record_event(
                            &peer.capability.peer_id,
                            ReputationEvidenceKind::AttestationValid,
                            ReputationEvidence {
                                job_id: Some(job_id.to_string()),
                                partition_id: Some(partition.partition_id),
                                digest_hash: Some(output_digest(
                                    &subgraph.output_data,
                                    &subgraph.named_outputs,
                                )),
                                signature: Some(attestation.signature.clone()),
                                observed_at_unix_ms: unix_time_now_ms(),
                                ..Default::default()
                            },
                        );
                    }
                    if let Some(attestation) = subgraph.attestation.clone() {
                        let chain = AttestationChainMsg {
                            job_id: job_id.to_string(),
                            partition_id: partition.partition_id,
                            attestations: vec![attestation],
                        };
                        let _ = persist_attestation_chain(&self.swarm_config, &chain);
                        self.fan_out_attestation_chain(&peer.capability.peer_id, &chain);
                    }
                    self.send_job_complete(&mut *conn, job_id)?;

                    return Ok(RemoteExecutionResult {
                        output_data: subgraph.output_data.clone(),
                        node_trace: DistributedNodeTrace {
                            peer_id: peer.capability.peer_id.clone(),
                            partition_id: partition.partition_id,
                            wall_time,
                            node_count: partition.node_ids.len(),
                            trace_entries: subgraph.trace_entries.clone(),
                        },
                        transfer_traces,
                        total_transfer_bytes,
                        total_transfer_wall_time,
                        compiled,
                        artifact,
                    });
                }
                MessageBody::SubgraphFailed(ref failed) => {
                    let _ = self.send_job_abort(&mut *conn, job_id, &failed.reason);
                    return Err(DistributedError::PeerExecutionFailed {
                        peer_id: peer.capability.peer_id.0.clone(),
                        reason: failed.reason.clone(),
                    });
                }
                _ => {
                    let _ = self.send_job_abort(
                        &mut *conn,
                        job_id,
                        "unexpected response to ExecuteSubgraph",
                    );
                    return Err(DistributedError::PeerExecutionFailed {
                        peer_id: peer.capability.peer_id.0.clone(),
                        reason: "unexpected response to ExecuteSubgraph".into(),
                    });
                }
            }
        }
    }

    fn next_job_id(&mut self) -> String {
        let job_id = format!("job-{}", self.sequence);
        self.sequence += 1;
        job_id
    }

    fn send_heartbeat(
        &mut self,
        peer_id: &PeerId,
        conn: &mut dyn crate::transport::Connection,
    ) -> Result<(), DistributedError> {
        let threat_advertisement = self.local_threat_epoch_advertisement();
        let threat_surface = self.prepare_threat_wire_surface(peer_id, "heartbeat", self.sequence);
        let mut heartbeat_msg = HeartbeatMsg {
            pressure: self.local_capability.pressure_level,
            active_subgraph_count: 0,
            current_buffer_bytes: 0,
            encrypted_threat_gossip_supported: threat_advertisement
                .encrypted_threat_gossip_supported,
            threat_epoch_id: threat_advertisement.threat_epoch_id,
            threat_epoch_public_key: threat_advertisement.threat_epoch_public_key,
            threat_digests: threat_surface.threat_digests,
            activation_level: threat_surface.activation_level,
            intelligence_root: threat_surface.intelligence_root,
            local_pressure: threat_surface.local_pressure,
            network_pressure: threat_surface.network_pressure,
            encrypted_threat_payload: threat_surface.encrypted_threat_payload,
            signature_bundle: None,
        };
        let signing_bytes = heartbeat_signing_bytes(&heartbeat_msg);
        heartbeat_msg.signature_bundle = Some(self.swarm_identity.sign_bundle(&signing_bytes));
        let heartbeat = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::Heartbeat(heartbeat_msg),
        };
        self.sequence += 1;
        conn.send(&heartbeat)
    }

    fn send_heartbeat_ack(
        &mut self,
        peer_id: &PeerId,
        conn: &mut dyn crate::transport::Connection,
    ) -> Result<(), DistributedError> {
        let threat_advertisement = self.local_threat_epoch_advertisement();
        let threat_surface =
            self.prepare_threat_wire_surface(peer_id, "heartbeat-ack", self.sequence);
        let mut heartbeat_ack = HeartbeatAckMsg {
            acknowledged: true,
            encrypted_threat_gossip_supported: threat_advertisement
                .encrypted_threat_gossip_supported,
            threat_epoch_id: threat_advertisement.threat_epoch_id,
            threat_epoch_public_key: threat_advertisement.threat_epoch_public_key,
            threat_digests: threat_surface.threat_digests,
            activation_level: threat_surface.activation_level,
            intelligence_root: threat_surface.intelligence_root,
            local_pressure: threat_surface.local_pressure,
            network_pressure: threat_surface.network_pressure,
            encrypted_threat_payload: threat_surface.encrypted_threat_payload,
            signature_bundle: None,
        };
        let signing_bytes = heartbeat_ack_signing_bytes(&heartbeat_ack);
        heartbeat_ack.signature_bundle = Some(self.swarm_identity.sign_bundle(&signing_bytes));
        let ack = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::HeartbeatAck(heartbeat_ack),
        };
        self.sequence += 1;
        conn.send(&ack)
    }

    fn send_job_complete(
        &mut self,
        conn: &mut dyn crate::transport::Connection,
        job_id: &str,
    ) -> Result<(), DistributedError> {
        let msg = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::JobComplete(JobCompleteMsg {
                job_id: job_id.to_string(),
            }),
        };
        self.sequence += 1;
        conn.send(&msg)
    }

    fn send_job_abort(
        &mut self,
        conn: &mut dyn crate::transport::Connection,
        job_id: &str,
        reason: &str,
    ) -> Result<(), DistributedError> {
        let msg = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::JobAbort(JobAbortMsg {
                job_id: job_id.to_string(),
                reason: reason.to_string(),
            }),
        };
        self.sequence += 1;
        conn.send(&msg)
    }

    fn send_reputation_sync(
        &mut self,
        conn: &mut dyn crate::transport::Connection,
    ) -> Result<(), DistributedError> {
        let msg = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::ReputationSync(self.diplomat.reputation_sync(&self.reputation)),
        };
        self.sequence += 1;
        conn.send(&msg)
    }

    fn local_threat_epoch_advertisement(&mut self) -> crate::swarm::ThreatEpochAdvertisement {
        if !self.swarm_config.enabled {
            return crate::swarm::ThreatEpochAdvertisement::default();
        }
        self.threat_epoch_manager.current_advertisement()
    }

    fn note_peer_threat_advertisement(
        &mut self,
        peer_id: &PeerId,
        remote_support: bool,
        epoch_id: Option<u64>,
        public_key: Option<&[u8]>,
        entry_kind: Option<&str>,
    ) {
        if !self.swarm_config.enabled {
            return;
        }
        let result = self
            .peer_threat_channels
            .entry(peer_id.0.clone())
            .or_default()
            .update_from_advertisement(
                true,
                remote_support,
                epoch_id,
                public_key,
                unix_time_now_secs(),
            );
        if let Err(err) = result {
            self.record_peer_threat_intel_failure(
                peer_id,
                entry_kind.unwrap_or("encrypted-threat-intel-auth-failure"),
                &err.to_string(),
            );
        }
    }

    fn prepare_threat_wire_surface(
        &mut self,
        peer_id: &PeerId,
        message_kind: &str,
        sequence: u64,
    ) -> ThreatIntelWireSurface {
        if !self.swarm_config.enabled {
            return ThreatIntelWireSurface::default();
        }
        let Some(channel) = self.peer_threat_channels.get(&peer_id.0).cloned() else {
            return ThreatIntelWireSurface::default();
        };
        if !channel.remote_supports_encryption || !channel.encrypted_negotiated {
            return ThreatIntelWireSurface::default();
        }
        let swarm_telemetry = self.swarm_controller.telemetry_digest();
        let payload = self.diplomat.drain_threat_payload(
            Some(self.cluster_activation_level_u8()),
            swarm_telemetry.as_ref(),
        );
        if payload.is_empty() {
            return ThreatIntelWireSurface::default();
        }
        match self.threat_epoch_manager.encrypt_for_peer(
            unix_time_now_secs(),
            &self.local_capability.peer_id,
            peer_id,
            message_kind,
            sequence,
            &channel,
            &payload,
        ) {
            Ok(encrypted_threat_payload) => ThreatIntelWireSurface {
                encrypted_threat_payload: Some(encrypted_threat_payload),
                ..ThreatIntelWireSurface::default()
            },
            Err(err) => {
                self.record_peer_threat_intel_failure(
                    peer_id,
                    "encrypted-threat-intel-auth-failure",
                    &err.to_string(),
                );
                ThreatIntelWireSurface::default()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_threat_wire_surface(
        &mut self,
        peer: &PeerState,
        message_kind: &str,
        sequence: u64,
        digests: &[crate::protocol::ThreatDigestMsg],
        activation_level: Option<u8>,
        intelligence_root: Option<&str>,
        local_pressure: Option<f64>,
        network_pressure: Option<f64>,
        encrypted_threat_payload: Option<&EncryptedThreatEnvelopeMsg>,
    ) -> Option<ThreatIntelPayload> {
        if !self.swarm_config.enabled {
            return None;
        }
        let channel = self
            .peer_threat_channels
            .get(&peer.capability.peer_id.0)
            .cloned()
            .unwrap_or_default();
        let plaintext_present = has_plaintext_threat_surface(
            digests,
            activation_level,
            intelligence_root,
            local_pressure,
            network_pressure,
        );
        if channel.encrypted_negotiated {
            if plaintext_present {
                self.record_peer_threat_intel_failure(
                    &peer.capability.peer_id,
                    "encrypted-threat-intel-auth-failure",
                    "plaintext threat intelligence was sent after encrypted negotiation completed",
                );
                return None;
            }
            let envelope = encrypted_threat_payload?;
            match self.threat_epoch_manager.decrypt_from_peer(
                unix_time_now_secs(),
                &peer.capability.peer_id,
                &self.local_capability.peer_id,
                message_kind,
                sequence,
                &channel,
                envelope,
            ) {
                Ok(payload) => Some(payload),
                Err(err) => {
                    self.record_peer_threat_intel_failure(
                        &peer.capability.peer_id,
                        "encrypted-threat-intel-auth-failure",
                        &err.to_string(),
                    );
                    None
                }
            }
        } else {
            if plaintext_present || encrypted_threat_payload.is_some() {
                let reason = if channel.remote_supports_encryption {
                    "threat intelligence was sent before encrypted gossip negotiation completed"
                } else {
                    "threat intelligence is disabled when peers do not support encrypted gossip"
                };
                self.record_peer_threat_intel_failure(
                    &peer.capability.peer_id,
                    "encrypted-threat-intel-auth-failure",
                    reason,
                );
            }
            None
        }
    }

    fn record_peer_threat_intel_failure(
        &mut self,
        peer_id: &PeerId,
        entry_kind: &str,
        reason: &str,
    ) {
        let observed_at_unix_ms = unix_time_now_ms();
        let _ = self.reputation.record_event(
            peer_id,
            ReputationEvidenceKind::ThreatDigestContradicted,
            ReputationEvidence {
                observed_at_unix_ms,
                ..Default::default()
            },
        );
        let payload = serde_json::json!({
            "peer_id": peer_id.0,
            "reason": reason,
            "observed_at_unix_ms": observed_at_unix_ms,
        });
        let _ = persist_threat_intelligence_outcome(
            &self.swarm_config,
            entry_kind,
            &self.local_capability.peer_id.0,
            &[],
            "auth-failure",
            &payload,
        );
    }

    fn persist_peer_threat_intelligence(
        &mut self,
        peer_id: &PeerId,
        entry_kind: &str,
        intelligence_root: &str,
        payload: &ThreatIntelPayload,
    ) {
        let payload = serde_json::json!({
            "peer_id": peer_id.0,
            "digest_count": payload.digests.len(),
            "activation_level": payload.activation_level,
            "intelligence_root": payload.intelligence_root,
            "local_pressure": payload.local_pressure,
            "network_pressure": payload.network_pressure,
        });
        let _ = persist_threat_intelligence_outcome(
            &self.swarm_config,
            entry_kind,
            &self.local_capability.peer_id.0,
            &[],
            intelligence_root,
            &payload,
        );
    }

    fn ingest_swarm_digests(
        &mut self,
        peer: &PeerState,
        digests: &[crate::protocol::ThreatDigestMsg],
        activation_level: Option<u8>,
        reported_pressure: Option<f64>,
    ) -> String {
        let ingest = self.diplomat.ingest_verified_heartbeat(
            &peer.capability.peer_id,
            &peer.capability.ed25519_public_key,
            peer.capability.public_key_bundle.as_ref(),
            digests,
            activation_level,
        );
        let runtime_digests = ingest
            .accepted_digests
            .iter()
            .map(decode_threat_digest)
            .collect::<Vec<_>>();
        if !runtime_digests.is_empty() {
            self.swarm_controller.record_digests(&runtime_digests);
        }
        if let Some(pressure) = reported_pressure {
            self.swarm_controller.record_peer_pressure(
                peer.capability.peer_id.0.clone(),
                activation_level.unwrap_or_default(),
                pressure,
                peer.reputation,
            );
        }
        for report in ingest.corroborated_reports {
            for peer_id in report.peer_ids {
                let _ = self.reputation.record_event(
                    &PeerId(peer_id),
                    ReputationEvidenceKind::ThreatDigestCorroborated,
                    ReputationEvidence {
                        observed_at_unix_ms: unix_time_now_ms(),
                        ..Default::default()
                    },
                );
            }
        }
        for report in ingest.contradiction_reports {
            let _ = self.reputation.record_event(
                &PeerId(report.reporting_peer_id),
                ReputationEvidenceKind::ThreatDigestContradicted,
                ReputationEvidence {
                    observed_at_unix_ms: unix_time_now_ms(),
                    ..Default::default()
                },
            );
        }
        self.swarm_controller
            .note_gossip_peers_count(self.diplomat.gossip_peer_count() as u32);
        ingest.intelligence_root
    }

    fn ingest_swarm_gossip(&mut self, peer: &PeerState, gossip: &ThreatGossipMsg) -> String {
        let ingest = self.diplomat.ingest_verified_threat_gossip(
            &peer.capability.peer_id,
            &peer.capability.ed25519_public_key,
            peer.capability.public_key_bundle.as_ref(),
            gossip,
        );
        let runtime_digests = ingest
            .accepted_digests
            .iter()
            .map(decode_threat_digest)
            .collect::<Vec<_>>();
        if !runtime_digests.is_empty() {
            self.swarm_controller.record_digests(&runtime_digests);
        }
        if let Some(pressure) = combine_pressure(gossip.local_pressure, gossip.network_pressure) {
            self.swarm_controller.record_peer_pressure(
                peer.capability.peer_id.0.clone(),
                gossip.activation_level.unwrap_or_default(),
                pressure,
                peer.reputation,
            );
        }
        self.swarm_controller
            .note_gossip_peers_count(self.diplomat.gossip_peer_count() as u32);
        ingest.intelligence_root
    }

    fn should_require_quorum(&self, peer: &PeerState) -> bool {
        coordinator_requires_quorum(
            self.cluster_activation_level(),
            peer.reputation,
            u32::from(peer.swarm_activation_level >= 1),
            1,
        )
    }

    fn verify_attestation(
        &self,
        job_id: &str,
        partition_id: u32,
        subgraph: &SubgraphResultMsg,
        attestation: &AttestationMetadata,
    ) -> bool {
        let (expected_output_digest, expected_trace_digest) =
            subgraph_attestation_digests(subgraph);
        if !attestation_matches_subgraph_digests(
            expected_output_digest,
            expected_trace_digest,
            attestation,
        ) {
            return false;
        }
        let signing_bytes = attestation_signing_bytes(
            job_id,
            partition_id,
            expected_output_digest,
            expected_trace_digest,
            attestation.activation_level,
        );
        LocalPeerIdentity::verify_signed_message(
            &attestation.public_key,
            attestation.public_key_bundle.as_ref(),
            &signing_bytes,
            &attestation.signature,
            attestation.signature_bundle.as_ref(),
        )
    }

    fn verify_quorum_result(
        &mut self,
        job_id: &str,
        partition_id: u32,
        peer: &PeerState,
        bundle: &DistributedExecutionBundle,
        input_buffers: &HashMap<u32, Vec<u8>>,
        subgraph: &SubgraphResultMsg,
    ) -> Result<(), DistributedError> {
        let remote_digest = output_digest(&subgraph.output_data, &subgraph.named_outputs);
        let local = execute_assignment_with_capability(
            &self.local_capability,
            bundle.clone(),
            input_buffers.clone(),
            self.cluster_activation_level_u8(),
        )?;
        let local_digest = output_digest(&local.output_data, &local.named_outputs);
        let decision = coordinator_quorum_decision(
            &peer.capability.peer_id.0,
            remote_digest,
            &self.local_capability.peer_id.0,
            local_digest,
            &self.swarm_config.warrior,
        );
        let severity = if decision.accepted {
            ThreatSeverity::Low
        } else {
            ThreatSeverity::Critical
        };
        let vote_time = unix_time_now_ms();
        let _ = self.consensus.record_vote(
            ConsensusVoteMsg {
                job_id: job_id.to_string(),
                partition_id,
                voter_peer_id: peer.capability.peer_id.0.clone(),
                severity: severity_to_string(severity),
                accepted: remote_digest == local_digest,
                output_digest: remote_digest,
                recorded_unix_ms: vote_time,
            },
            2,
        );
        let consensus = self.consensus.record_vote(
            ConsensusVoteMsg {
                job_id: job_id.to_string(),
                partition_id,
                voter_peer_id: self.local_capability.peer_id.0.clone(),
                severity: severity_to_string(severity),
                accepted: true,
                output_digest: local_digest,
                recorded_unix_ms: vote_time,
            },
            2,
        );
        self.swarm_controller
            .record_consensus_result(decision.accepted, severity);
        if !decision.accepted {
            let _ = self.reputation.record_event(
                &peer.capability.peer_id,
                ReputationEvidenceKind::QuorumDisagreement,
                ReputationEvidence {
                    job_id: Some(job_id.to_string()),
                    partition_id: Some(partition_id),
                    digest_hash: Some(remote_digest),
                    consensus_round_id: Some(format!("{job_id}:{partition_id}")),
                    observed_at_unix_ms: unix_time_now_ms(),
                    ..Default::default()
                },
            );
            self.local_excluded_peers
                .insert(peer.capability.peer_id.0.clone());
            self.swarm_controller
                .note_low_reputation_peer(peer.capability.peer_id.0.clone());
            return Err(DistributedError::PeerExecutionFailed {
                peer_id: peer.capability.peer_id.0.clone(),
                reason: "swarm quorum verification rejected remote output".into(),
            });
        }
        let _ = self.reputation.record_event(
            &peer.capability.peer_id,
            ReputationEvidenceKind::QuorumAgreement,
            ReputationEvidence {
                job_id: Some(job_id.to_string()),
                partition_id: Some(partition_id),
                digest_hash: Some(remote_digest),
                consensus_round_id: Some(format!("{job_id}:{partition_id}")),
                observed_at_unix_ms: unix_time_now_ms(),
                ..Default::default()
            },
        );
        if let Some(result) = consensus
            && !result.accepted
        {
            return Err(DistributedError::PeerExecutionFailed {
                peer_id: peer.capability.peer_id.0.clone(),
                reason: format!(
                    "swarm consensus rejected result at severity {}",
                    result.severity
                ),
            });
        }
        Ok(())
    }
}

fn trust_model_for_lane(lane: RequiredTrustLane) -> TrustModel {
    match lane {
        RequiredTrustLane::StrictCryptographic => TrustModel::Cryptographic,
        RequiredTrustLane::AllowAttestation => TrustModel::Attestation,
        RequiredTrustLane::AllowMetadataOnly => TrustModel::MetadataOnly,
    }
}

fn should_retry_locally(err: &DistributedError) -> bool {
    match err {
        DistributedError::PeerExecutionFailed { reason, .. }
        | DistributedError::PeerRejected { reason, .. } => {
            !reason.to_ascii_lowercase().contains("unexpected response")
        }
        DistributedError::PeerUnreachable { .. } | DistributedError::Timeout { .. } => true,
        DistributedError::TransferFailed { .. }
        | DistributedError::IntegrityFailed { .. }
        | DistributedError::PartitionFailed { .. }
        | DistributedError::Serialization(_)
        | DistributedError::Runtime(_)
        | DistributedError::Config(_)
        | DistributedError::Disabled
        | DistributedError::NoPeersAvailable
        | DistributedError::HandshakeFailed { .. }
        | DistributedError::ProtocolVersionMismatch { .. }
        | DistributedError::Io(_) => false,
    }
}

fn is_timeout_error(err: &DistributedError) -> bool {
    match err {
        DistributedError::Io(message) => {
            let message = message.to_ascii_lowercase();
            message.contains("timed out")
                || message.contains("would block")
                || message.contains("temporarily unavailable")
        }
        _ => false,
    }
}

fn handshake_signing_bytes(
    capability: &NodeCapability,
    swarm_protocol_version: u32,
    encrypted_threat_gossip_supported: bool,
    threat_epoch_id: Option<u64>,
    threat_epoch_public_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(capability.peer_id.0.as_bytes());
    bytes.extend_from_slice(capability.hostname.as_bytes());
    bytes.extend_from_slice(&capability.protocol_version.to_le_bytes());
    bytes.extend_from_slice(&swarm_protocol_version.to_le_bytes());
    bytes.extend_from_slice(&capability.ed25519_public_key);
    if let Some(bundle) = &capability.public_key_bundle {
        bytes.extend_from_slice(&bundle.canonical_bytes());
    }
    crate::protocol::append_threat_epoch_advertisement_bytes(
        &mut bytes,
        encrypted_threat_gossip_supported,
        threat_epoch_id,
        threat_epoch_public_key,
    );
    bytes
}

fn unix_time_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn unix_time_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn combine_pressure(local_pressure: Option<f64>, network_pressure: Option<f64>) -> Option<f64> {
    match (local_pressure, network_pressure) {
        (Some(local), Some(network)) => Some(local.max(network)),
        (Some(local), None) => Some(local),
        (None, Some(network)) => Some(network),
        (None, None) => None,
    }
}

fn digest_prefix8(digest: [u8; 32]) -> [u8; 8] {
    let mut short = [0u8; 8];
    short.copy_from_slice(&digest[..8]);
    short
}

pub(crate) fn coordinator_requires_quorum(
    activation_level: ActivationLevel,
    peer_reputation: f64,
    stage_anomaly_streak: u32,
    backend_trust_tier: u8,
) -> bool {
    zkf_runtime::swarm::warrior::requires_quorum(
        activation_level,
        peer_reputation,
        stage_anomaly_streak,
        backend_trust_tier,
    )
}

pub(crate) fn subgraph_attestation_digests(subgraph: &SubgraphResultMsg) -> ([u8; 32], [u8; 32]) {
    (
        output_digest(&subgraph.output_data, &subgraph.named_outputs),
        trace_digest(&subgraph.trace_entries),
    )
}

pub(crate) fn attestation_matches_subgraph_digests(
    expected_output_digest: [u8; 32],
    expected_trace_digest: [u8; 32],
    attestation: &AttestationMetadata,
) -> bool {
    swarm_coordinator_core::attestation_matches_subgraph_digests(
        expected_output_digest,
        expected_trace_digest,
        attestation.output_digest,
        attestation.trace_digest,
    )
}

pub(crate) fn coordinator_quorum_decision(
    remote_peer_id: &str,
    remote_digest: [u8; 32],
    local_peer_id: &str,
    local_digest: [u8; 32],
    _base_config: &zkf_runtime::swarm::warrior::QuorumConfig,
) -> zkf_runtime::swarm::warrior::WarriorDecision {
    let remote_short = digest_prefix8(remote_digest);
    let local_short = digest_prefix8(local_digest);
    if coordinator_two_party_unanimous_quorum_accepts(remote_digest, local_digest) {
        return zkf_runtime::swarm::warrior::WarriorDecision {
            accepted: true,
            majority_digest: Some(remote_short),
            agreeing_peers: vec![remote_peer_id.to_string(), local_peer_id.to_string()],
            disagreeing_peers: Vec::new(),
            randomized_execution_order: false,
            backend_diversification_required: false,
            honeypot_rejected: false,
        };
    }

    let (majority_digest, agreeing_peer, disagreeing_peer) = if remote_short <= local_short {
        (
            remote_short,
            remote_peer_id.to_string(),
            local_peer_id.to_string(),
        )
    } else {
        (
            local_short,
            local_peer_id.to_string(),
            remote_peer_id.to_string(),
        )
    };
    zkf_runtime::swarm::warrior::WarriorDecision {
        accepted: false,
        majority_digest: Some(majority_digest),
        agreeing_peers: vec![agreeing_peer],
        disagreeing_peers: vec![disagreeing_peer],
        randomized_execution_order: false,
        backend_diversification_required: false,
        honeypot_rejected: false,
    }
}

pub(crate) fn coordinator_two_party_unanimous_quorum_accepts(
    remote_digest: [u8; 32],
    local_digest: [u8; 32],
) -> bool {
    swarm_coordinator_core::coordinator_two_party_unanimous_quorum_accepts(
        remote_digest,
        local_digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SubgraphTraceEntry;

    fn sample_subgraph() -> SubgraphResultMsg {
        SubgraphResultMsg {
            job_id: "job-1".to_string(),
            partition_id: 0,
            output_data: vec![(0, vec![1, 2, 3])],
            named_outputs: vec![("answer".to_string(), vec![4, 5])],
            compiled_program: None,
            proof_artifact: None,
            wall_time_ms: 1,
            trace_entries: vec![SubgraphTraceEntry {
                node_name: "node-a".to_string(),
                wall_time_ms: 7,
                device: "cpu".to_string(),
            }],
            final_trust_model: None,
            peak_memory_bytes: None,
            attestation: None,
        }
    }

    fn matching_attestation(subgraph: &SubgraphResultMsg) -> AttestationMetadata {
        let (output_digest, trace_digest) = subgraph_attestation_digests(subgraph);
        AttestationMetadata {
            signer_peer_id: "peer-a".to_string(),
            public_key: vec![0; 32],
            #[cfg(feature = "full")]
            public_key_bundle: None,
            output_digest,
            trace_digest,
            signature: vec![0; 64],
            #[cfg(feature = "full")]
            signature_bundle: None,
            activation_level: Some(1),
        }
    }

    #[test]
    fn attestation_digest_helper_rejects_output_or_trace_drift() {
        let subgraph = sample_subgraph();
        let attestation = matching_attestation(&subgraph);
        let (expected_output_digest, expected_trace_digest) =
            subgraph_attestation_digests(&subgraph);

        assert!(attestation_matches_subgraph_digests(
            expected_output_digest,
            expected_trace_digest,
            &attestation,
        ));

        let mut bad_output = attestation.clone();
        bad_output.output_digest[0] ^= 0x01;
        assert!(!attestation_matches_subgraph_digests(
            expected_output_digest,
            expected_trace_digest,
            &bad_output,
        ));

        let mut bad_trace = attestation;
        bad_trace.trace_digest[0] ^= 0x01;
        assert!(!attestation_matches_subgraph_digests(
            expected_output_digest,
            expected_trace_digest,
            &bad_trace,
        ));
    }

    #[test]
    fn coordinator_quorum_helper_rejects_mismatched_two_party_digests() {
        let decision = coordinator_quorum_decision(
            "remote",
            [1; 32],
            "local",
            [2; 32],
            &zkf_runtime::swarm::warrior::QuorumConfig::default(),
        );
        assert!(!decision.accepted);

        let accepted = coordinator_quorum_decision(
            "remote",
            [3; 32],
            "local",
            [3; 32],
            &zkf_runtime::swarm::warrior::QuorumConfig::default(),
        );
        assert!(accepted.accepted);
    }

    #[test]
    fn coordinator_quorum_gate_requires_low_reputation_anomaly_or_low_trust() {
        assert!(coordinator_requires_quorum(
            ActivationLevel::Active,
            0.69,
            0,
            2,
        ));
        assert!(coordinator_requires_quorum(
            ActivationLevel::Active,
            0.95,
            1,
            2,
        ));
        assert!(coordinator_requires_quorum(
            ActivationLevel::Active,
            0.95,
            0,
            1,
        ));
        assert!(!coordinator_requires_quorum(
            ActivationLevel::Alert,
            0.95,
            0,
            2,
        ));
    }
}
