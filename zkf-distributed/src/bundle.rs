//! Serializable execution bundles for distributed runtime offload.

use crate::error::DistributedError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use zkf_backends::BackendRoute;
use zkf_core::artifact::{CompiledProgram, ProofArtifact};
use zkf_core::ir::Program;
use zkf_core::witness::{Witness, WitnessInputs};
use zkf_core::wrapping::{WrapperExecutionPolicy, WrapperPreview};
use zkf_runtime::control_plane::OptimizationObjective;
use zkf_runtime::execution::{ExecutionContext, MerkleHashFn, NodePayload, ProofOutputKind};
use zkf_runtime::graph::{DevicePlacement, ProverGraph, ProverNode, ProverOp};
use zkf_runtime::memory::{BufferHandle, MemoryClass};
use zkf_runtime::trust::TrustModel;

const EXECUTION_BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedExecutionBundle {
    pub version: u32,
    pub source_digests: BTreeMap<String, String>,
    pub optimization_objective: OptimizationObjective,
    pub required_output_slots: Vec<u32>,
    pub graph_nodes: Vec<GraphNodeBundle>,
    pub context: ExecutionContextBundle,
}

impl DistributedExecutionBundle {
    pub fn from_graph_and_context(
        graph: &ProverGraph,
        exec_ctx: &ExecutionContext,
    ) -> Result<Self, DistributedError> {
        let order = graph.topological_order()?;
        let mut index_by_id = HashMap::with_capacity(order.len());
        for (index, node_id) in order.iter().enumerate() {
            index_by_id.insert(*node_id, index);
        }

        let mut graph_nodes = Vec::with_capacity(order.len());
        for node_id in &order {
            let node = graph
                .node(*node_id)
                .ok_or_else(|| DistributedError::Serialization("graph node disappeared".into()))?;
            let payload = exec_ctx
                .payload(*node_id)
                .cloned()
                .unwrap_or(NodePayload::Noop);
            graph_nodes.push(GraphNodeBundle::from_runtime(node, &index_by_id, payload)?);
        }

        Ok(Self {
            version: EXECUTION_BUNDLE_VERSION,
            source_digests: source_digests(exec_ctx)?,
            optimization_objective: exec_ctx.optimization_objective,
            required_output_slots: infer_required_output_slots(&graph_nodes),
            graph_nodes,
            context: ExecutionContextBundle::from_runtime(exec_ctx),
        })
    }

    pub fn from_partition_and_context(
        graph: &ProverGraph,
        exec_ctx: &ExecutionContext,
        node_ids: &[zkf_runtime::memory::NodeId],
        required_output_slots: &[u32],
        compiled_override: Option<&CompiledProgram>,
        proof_artifact_override: Option<&ProofArtifact>,
    ) -> Result<Self, DistributedError> {
        let selected: HashSet<_> = node_ids.iter().copied().collect();
        let order: Vec<_> = graph
            .topological_order()?
            .into_iter()
            .filter(|node_id| selected.contains(node_id))
            .collect();
        if order.len() != selected.len() {
            return Err(DistributedError::PartitionFailed {
                reason: "partition node subset did not match graph topology".into(),
            });
        }

        let mut index_by_id = HashMap::with_capacity(order.len());
        for (index, node_id) in order.iter().enumerate() {
            index_by_id.insert(*node_id, index);
        }

        let mut graph_nodes = Vec::with_capacity(order.len());
        for node_id in &order {
            let node = graph
                .node(*node_id)
                .ok_or_else(|| DistributedError::Serialization("graph node disappeared".into()))?;
            let payload = exec_ctx
                .payload(*node_id)
                .cloned()
                .unwrap_or(NodePayload::Noop);
            graph_nodes.push(GraphNodeBundle::from_runtime_partition(
                node,
                &index_by_id,
                payload,
            )?);
        }

        let mut context = ExecutionContextBundle::from_runtime(exec_ctx);
        context.initial_buffers.clear();
        if let Some(compiled) = compiled_override {
            context.compiled = Some(encode_json_value(compiled)?);
        }
        if let Some(artifact) = proof_artifact_override {
            context.proof_artifact = Some(encode_json_value(artifact)?);
        }

        let mut required_output_slots = required_output_slots.to_vec();
        if required_output_slots.is_empty() {
            required_output_slots = infer_required_output_slots(&graph_nodes);
        } else {
            required_output_slots.sort_unstable();
            required_output_slots.dedup();
        }

        Ok(Self {
            version: EXECUTION_BUNDLE_VERSION,
            source_digests: source_digests(exec_ctx)?,
            optimization_objective: exec_ctx.optimization_objective,
            required_output_slots,
            graph_nodes,
            context,
        })
    }

    pub fn into_graph_and_context(
        self,
    ) -> Result<(ProverGraph, ExecutionContext), DistributedError> {
        if self.version != EXECUTION_BUNDLE_VERSION {
            return Err(DistributedError::Serialization(format!(
                "unsupported execution bundle version {}",
                self.version
            )));
        }

        let mut graph = ProverGraph::new();
        let mut graph_nodes = Vec::with_capacity(self.graph_nodes.len());
        let mut runtime_ids = Vec::with_capacity(self.graph_nodes.len());
        for node_bundle in &self.graph_nodes {
            let node = node_bundle.to_runtime_node()?;
            let node_id = graph.add_node(node);
            graph_nodes.push(node_bundle.clone());
            runtime_ids.push(node_id);
        }

        for (index, node_bundle) in graph_nodes.iter().enumerate() {
            for dep_index in &node_bundle.deps {
                let dep_id = *runtime_ids.get(*dep_index).ok_or_else(|| {
                    DistributedError::Serialization(format!(
                        "dependency index {} out of range",
                        dep_index
                    ))
                })?;
                graph.add_dep(dep_id, runtime_ids[index]);
            }
        }

        let mut exec_ctx = self.context.into_runtime(self.optimization_objective);
        for (index, node_bundle) in graph_nodes.into_iter().enumerate() {
            let payload = node_bundle.payload.into_runtime_payload(&exec_ctx)?;
            exec_ctx.set_payload(runtime_ids[index], payload);
        }

        Ok((graph, exec_ctx))
    }

    pub fn encode_postcard(&self) -> Result<Vec<u8>, DistributedError> {
        postcard::to_allocvec(self).map_err(DistributedError::from)
    }

    pub fn decode_postcard(bytes: &[u8]) -> Result<Self, DistributedError> {
        postcard::from_bytes(bytes).map_err(DistributedError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContextBundle {
    pub source_proof: Option<Vec<u8>>,
    pub program: Option<Vec<u8>>,
    pub compiled: Option<Vec<u8>>,
    #[serde(default)]
    pub proof_artifact: Option<Vec<u8>>,
    pub witness_inputs: Option<Vec<u8>>,
    pub witness: Option<Vec<u8>>,
    pub fold_witnesses: Option<Vec<u8>>,
    pub wrapper_preview: Option<Vec<u8>>,
    pub wrapper_policy: Option<Vec<u8>>,
    pub initial_buffers: Vec<SlotBufferBundle>,
}

impl ExecutionContextBundle {
    fn from_runtime(exec_ctx: &ExecutionContext) -> Self {
        let mut initial_buffers: Vec<SlotBufferBundle> = exec_ctx
            .initial_buffers
            .iter()
            .map(|(slot, data)| SlotBufferBundle {
                slot: *slot,
                data: data.clone(),
            })
            .collect();
        initial_buffers.sort_by_key(|entry| entry.slot);

        Self {
            source_proof: exec_ctx
                .source_proof
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("proof artifact should serialize"),
            program: exec_ctx
                .program
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("program should serialize"),
            compiled: exec_ctx
                .compiled
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("compiled program should serialize"),
            proof_artifact: exec_ctx
                .proof_artifact
                .as_ref()
                .map(encode_json_value)
                .transpose()
                .expect("proof artifact should serialize"),
            witness_inputs: exec_ctx
                .witness_inputs
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("witness inputs should serialize"),
            witness: exec_ctx
                .witness
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("witness should serialize"),
            fold_witnesses: exec_ctx
                .fold_witnesses
                .as_ref()
                .map(|value| encode_json_value(value.as_ref()))
                .transpose()
                .expect("fold witnesses should serialize"),
            wrapper_preview: exec_ctx
                .wrapper_preview
                .as_ref()
                .map(encode_json_value)
                .transpose()
                .expect("wrapper preview should serialize"),
            wrapper_policy: exec_ctx
                .wrapper_policy
                .as_ref()
                .map(encode_json_value)
                .transpose()
                .expect("wrapper policy should serialize"),
            initial_buffers,
        }
    }

    fn into_runtime(self, optimization_objective: OptimizationObjective) -> ExecutionContext {
        let mut exec_ctx = ExecutionContext::new();
        exec_ctx.source_proof = self
            .source_proof
            .map(|bytes| decode_json_value::<ProofArtifact>(&bytes))
            .transpose()
            .expect("bundle proof artifact should deserialize")
            .map(Arc::new);
        exec_ctx.program = self
            .program
            .map(|bytes| decode_json_value::<Program>(&bytes))
            .transpose()
            .expect("bundle program should deserialize")
            .map(Arc::new);
        exec_ctx.compiled = self
            .compiled
            .map(|bytes| decode_json_value::<CompiledProgram>(&bytes))
            .transpose()
            .expect("bundle compiled program should deserialize")
            .map(Arc::new);
        exec_ctx.proof_artifact = self
            .proof_artifact
            .map(|bytes| decode_json_value::<ProofArtifact>(&bytes))
            .transpose()
            .expect("bundle proof artifact should deserialize");
        exec_ctx.witness_inputs = self
            .witness_inputs
            .map(|bytes| decode_json_value::<WitnessInputs>(&bytes))
            .transpose()
            .expect("bundle witness inputs should deserialize")
            .map(Arc::new);
        exec_ctx.witness = self
            .witness
            .map(|bytes| decode_json_value::<Witness>(&bytes))
            .transpose()
            .expect("bundle witness should deserialize")
            .map(Arc::new);
        exec_ctx.fold_witnesses = self
            .fold_witnesses
            .map(|bytes| decode_json_value::<Vec<Witness>>(&bytes))
            .transpose()
            .expect("bundle fold witnesses should deserialize")
            .map(Arc::new);
        exec_ctx.wrapper_preview = self
            .wrapper_preview
            .map(|bytes| decode_json_value::<WrapperPreview>(&bytes))
            .transpose()
            .expect("bundle wrapper preview should deserialize");
        exec_ctx.wrapper_policy = self
            .wrapper_policy
            .map(|bytes| decode_json_value::<WrapperExecutionPolicy>(&bytes))
            .transpose()
            .expect("bundle wrapper policy should deserialize");
        exec_ctx.optimization_objective = optimization_objective;

        for buffer in self.initial_buffers {
            exec_ctx.set_initial_buffer(buffer.slot, buffer.data);
        }

        exec_ctx
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotBufferBundle {
    pub slot: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNodeBundle {
    pub op: ProverOpBundle,
    pub deps: Vec<usize>,
    pub device_pref: DevicePlacement,
    pub trust_model: TrustModel,
    pub deterministic: bool,
    pub input_buffers: Vec<BufferHandleBundle>,
    pub output_buffers: Vec<BufferHandleBundle>,
    pub payload: NodePayloadBundle,
}

impl GraphNodeBundle {
    fn from_runtime(
        node: &ProverNode,
        index_by_id: &HashMap<zkf_runtime::memory::NodeId, usize>,
        payload: NodePayload,
    ) -> Result<Self, DistributedError> {
        let mut deps = Vec::with_capacity(node.deps.len());
        for dep in &node.deps {
            deps.push(*index_by_id.get(dep).ok_or_else(|| {
                DistributedError::Serialization(format!(
                    "dependency {:?} missing from graph order",
                    dep
                ))
            })?);
        }
        Ok(Self {
            op: ProverOpBundle::from_runtime(&node.op),
            deps,
            device_pref: node.device_pref,
            trust_model: node.trust_model,
            deterministic: node.deterministic,
            input_buffers: node
                .input_buffers
                .iter()
                .copied()
                .map(BufferHandleBundle::from_runtime)
                .collect(),
            output_buffers: node
                .output_buffers
                .iter()
                .copied()
                .map(BufferHandleBundle::from_runtime)
                .collect(),
            payload: NodePayloadBundle::from_runtime(payload),
        })
    }

    fn from_runtime_partition(
        node: &ProverNode,
        index_by_id: &HashMap<zkf_runtime::memory::NodeId, usize>,
        payload: NodePayload,
    ) -> Result<Self, DistributedError> {
        let deps = node
            .deps
            .iter()
            .filter_map(|dep| index_by_id.get(dep).copied())
            .collect();
        Ok(Self {
            op: ProverOpBundle::from_runtime(&node.op),
            deps,
            device_pref: node.device_pref,
            trust_model: node.trust_model,
            deterministic: node.deterministic,
            input_buffers: node
                .input_buffers
                .iter()
                .copied()
                .map(BufferHandleBundle::from_runtime)
                .collect(),
            output_buffers: node
                .output_buffers
                .iter()
                .copied()
                .map(BufferHandleBundle::from_runtime)
                .collect(),
            payload: NodePayloadBundle::from_runtime(payload),
        })
    }

    fn to_runtime_node(&self) -> Result<ProverNode, DistributedError> {
        let mut node = ProverNode::new(self.op.to_runtime()?);
        node.device_pref = self.device_pref;
        node.trust_model = self.trust_model;
        node.deterministic = self.deterministic;
        node.input_buffers = self
            .input_buffers
            .iter()
            .copied()
            .map(BufferHandleBundle::into_runtime)
            .collect();
        node.output_buffers = self
            .output_buffers
            .iter()
            .copied()
            .map(BufferHandleBundle::into_runtime)
            .collect();
        Ok(node)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BufferHandleBundle {
    pub slot: u32,
    pub size_bytes: usize,
    pub class: MemoryClassBundle,
}

impl BufferHandleBundle {
    fn from_runtime(handle: BufferHandle) -> Self {
        Self {
            slot: handle.slot,
            size_bytes: handle.size_bytes,
            class: MemoryClassBundle::from_runtime(handle.class),
        }
    }

    fn into_runtime(self) -> BufferHandle {
        BufferHandle {
            slot: self.slot,
            size_bytes: self.size_bytes,
            class: self.class.into_runtime(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MemoryClassBundle {
    HotResident,
    EphemeralScratch,
    Spillable,
}

impl MemoryClassBundle {
    fn from_runtime(value: MemoryClass) -> Self {
        match value {
            MemoryClass::HotResident => Self::HotResident,
            MemoryClass::EphemeralScratch => Self::EphemeralScratch,
            MemoryClass::Spillable => Self::Spillable,
        }
    }

    fn into_runtime(self) -> MemoryClass {
        match self {
            Self::HotResident => MemoryClass::HotResident,
            Self::EphemeralScratch => MemoryClass::EphemeralScratch,
            Self::Spillable => MemoryClass::Spillable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProverOpBundle {
    WitnessSolve {
        constraint_count: usize,
        signal_count: usize,
    },
    BooleanizeSignals {
        count: usize,
    },
    RangeCheckExpand {
        bits: u32,
        count: usize,
    },
    LookupExpand {
        table_rows: usize,
        table_cols: usize,
    },
    Ntt {
        size: usize,
        field: String,
        inverse: bool,
    },
    Lde {
        size: usize,
        blowup: usize,
        field: String,
    },
    Msm {
        num_scalars: usize,
        curve: String,
    },
    PoseidonBatch {
        count: usize,
        width: usize,
    },
    Sha256Batch {
        count: usize,
    },
    MerkleLayer {
        level: usize,
        leaf_count: usize,
    },
    FriFold {
        folding_factor: usize,
        codeword_len: usize,
    },
    FriQueryOpen {
        query_count: usize,
        tree_depth: usize,
    },
    VerifierEmbed {
        inner_scheme: String,
    },
    BackendProve {
        backend: String,
    },
    BackendFold {
        backend: String,
    },
    OuterProve {
        outer_scheme: String,
    },
    TranscriptUpdate,
    ProofEncode,
    Barrier {
        wait_for: Vec<usize>,
    },
    Noop,
}

impl ProverOpBundle {
    fn from_runtime(op: &ProverOp) -> Self {
        match op {
            ProverOp::WitnessSolve {
                constraint_count,
                signal_count,
            } => Self::WitnessSolve {
                constraint_count: *constraint_count,
                signal_count: *signal_count,
            },
            ProverOp::BooleanizeSignals { count } => Self::BooleanizeSignals { count: *count },
            ProverOp::RangeCheckExpand { bits, count } => Self::RangeCheckExpand {
                bits: *bits,
                count: *count,
            },
            ProverOp::LookupExpand {
                table_rows,
                table_cols,
            } => Self::LookupExpand {
                table_rows: *table_rows,
                table_cols: *table_cols,
            },
            ProverOp::Ntt {
                size,
                field,
                inverse,
            } => Self::Ntt {
                size: *size,
                field: (*field).to_string(),
                inverse: *inverse,
            },
            ProverOp::Lde {
                size,
                blowup,
                field,
            } => Self::Lde {
                size: *size,
                blowup: *blowup,
                field: (*field).to_string(),
            },
            ProverOp::Msm { num_scalars, curve } => Self::Msm {
                num_scalars: *num_scalars,
                curve: (*curve).to_string(),
            },
            ProverOp::PoseidonBatch { count, width } => Self::PoseidonBatch {
                count: *count,
                width: *width,
            },
            ProverOp::Sha256Batch { count } => Self::Sha256Batch { count: *count },
            ProverOp::MerkleLayer { level, leaf_count } => Self::MerkleLayer {
                level: *level,
                leaf_count: *leaf_count,
            },
            ProverOp::FriFold {
                folding_factor,
                codeword_len,
            } => Self::FriFold {
                folding_factor: *folding_factor,
                codeword_len: *codeword_len,
            },
            ProverOp::FriQueryOpen {
                query_count,
                tree_depth,
            } => Self::FriQueryOpen {
                query_count: *query_count,
                tree_depth: *tree_depth,
            },
            ProverOp::VerifierEmbed { inner_scheme } => Self::VerifierEmbed {
                inner_scheme: (*inner_scheme).to_string(),
            },
            ProverOp::BackendProve { backend } => Self::BackendProve {
                backend: (*backend).to_string(),
            },
            ProverOp::BackendFold { backend } => Self::BackendFold {
                backend: (*backend).to_string(),
            },
            ProverOp::OuterProve { outer_scheme } => Self::OuterProve {
                outer_scheme: (*outer_scheme).to_string(),
            },
            ProverOp::TranscriptUpdate => Self::TranscriptUpdate,
            ProverOp::ProofEncode => Self::ProofEncode,
            ProverOp::Barrier { wait_for } => Self::Barrier {
                wait_for: wait_for.iter().map(|id| id.as_u64() as usize).collect(),
            },
            ProverOp::Noop => Self::Noop,
        }
    }

    fn to_runtime(&self) -> Result<ProverOp, DistributedError> {
        Ok(match self {
            Self::WitnessSolve {
                constraint_count,
                signal_count,
            } => ProverOp::WitnessSolve {
                constraint_count: *constraint_count,
                signal_count: *signal_count,
            },
            Self::BooleanizeSignals { count } => ProverOp::BooleanizeSignals { count: *count },
            Self::RangeCheckExpand { bits, count } => ProverOp::RangeCheckExpand {
                bits: *bits,
                count: *count,
            },
            Self::LookupExpand {
                table_rows,
                table_cols,
            } => ProverOp::LookupExpand {
                table_rows: *table_rows,
                table_cols: *table_cols,
            },
            Self::Ntt {
                size,
                field,
                inverse,
            } => ProverOp::Ntt {
                size: *size,
                field: static_runtime_label(field)?,
                inverse: *inverse,
            },
            Self::Lde {
                size,
                blowup,
                field,
            } => ProverOp::Lde {
                size: *size,
                blowup: *blowup,
                field: static_runtime_label(field)?,
            },
            Self::Msm { num_scalars, curve } => ProverOp::Msm {
                num_scalars: *num_scalars,
                curve: static_runtime_label(curve)?,
            },
            Self::PoseidonBatch { count, width } => ProverOp::PoseidonBatch {
                count: *count,
                width: *width,
            },
            Self::Sha256Batch { count } => ProverOp::Sha256Batch { count: *count },
            Self::MerkleLayer { level, leaf_count } => ProverOp::MerkleLayer {
                level: *level,
                leaf_count: *leaf_count,
            },
            Self::FriFold {
                folding_factor,
                codeword_len,
            } => ProverOp::FriFold {
                folding_factor: *folding_factor,
                codeword_len: *codeword_len,
            },
            Self::FriQueryOpen {
                query_count,
                tree_depth,
            } => ProverOp::FriQueryOpen {
                query_count: *query_count,
                tree_depth: *tree_depth,
            },
            Self::VerifierEmbed { inner_scheme } => ProverOp::VerifierEmbed {
                inner_scheme: static_runtime_label(inner_scheme)?,
            },
            Self::BackendProve { backend } => ProverOp::BackendProve {
                backend: static_runtime_label(backend)?,
            },
            Self::BackendFold { backend } => ProverOp::BackendFold {
                backend: static_runtime_label(backend)?,
            },
            Self::OuterProve { outer_scheme } => ProverOp::OuterProve {
                outer_scheme: static_runtime_label(outer_scheme)?,
            },
            Self::TranscriptUpdate => ProverOp::TranscriptUpdate,
            Self::ProofEncode => ProverOp::ProofEncode,
            Self::Barrier { .. } => ProverOp::Barrier {
                wait_for: Vec::new(),
            },
            Self::Noop => ProverOp::Noop,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodePayloadBundle {
    WitnessSolve,
    BooleanizeSignals {
        signals_slot: u32,
        count: usize,
    },
    RangeCheckExpand {
        signals_slot: u32,
        bits: u32,
        count: usize,
    },
    LookupExpand {
        table_slot: u32,
        inputs_slot: u32,
        table_rows: usize,
        table_cols: usize,
        query_cols: usize,
        output_col_offset: usize,
        output_cols: usize,
    },
    NttBn254 {
        values_slot: u32,
    },
    NttGoldilocks {
        values_slot: u32,
    },
    LdeGoldilocks {
        values_slot: u32,
        blowup: usize,
    },
    MsmBn254 {
        scalars_slot: u32,
        bases_slot: u32,
    },
    PoseidonGoldilocks {
        states_slot: u32,
        round_constants_slot: u32,
        n_ext: u32,
        n_int: u32,
    },
    Sha256Batch {
        inputs_slot: u32,
        count: usize,
        input_len: usize,
    },
    MerkleGoldilocks {
        leaves_slot: u32,
        digest_slot: u32,
        leaf_count: usize,
        hash_fn: MerkleHashFnBundle,
    },
    FriFoldGoldilocks {
        evals_slot: u32,
        alpha_slot: u32,
        twiddles_slot: u32,
    },
    FriFoldBabyBear {
        evals_slot: u32,
        alpha_slot: u32,
        twiddles_slot: u32,
    },
    FriQueryOpen {
        proof_slot: u32,
        query_slot: u32,
        query_count: usize,
        tree_depth: usize,
    },
    VerifierEmbed {
        wrapper_input_slot: u32,
        scheme: String,
    },
    BackendProve {
        backend: String,
        route: BackendRouteBundle,
        transcript_slot: u32,
    },
    BackendFold {
        backend: String,
        compress: bool,
        transcript_slot: u32,
    },
    OuterProve {
        proving_input_slot: u32,
        scheme: String,
    },
    TranscriptUpdate {
        state_slot: u32,
    },
    ProofEncode {
        input_slots: Vec<u32>,
        output_kind: ProofOutputKindBundle,
    },
    Barrier,
    Noop,
}

impl NodePayloadBundle {
    fn from_runtime(payload: NodePayload) -> Self {
        match payload {
            NodePayload::WitnessSolve { .. } => Self::WitnessSolve,
            NodePayload::BooleanizeSignals {
                signals_slot,
                count,
            } => Self::BooleanizeSignals {
                signals_slot,
                count,
            },
            NodePayload::RangeCheckExpand {
                signals_slot,
                bits,
                count,
            } => Self::RangeCheckExpand {
                signals_slot,
                bits,
                count,
            },
            NodePayload::LookupExpand {
                table_slot,
                inputs_slot,
                table_rows,
                table_cols,
                query_cols,
                output_col_offset,
                output_cols,
            } => Self::LookupExpand {
                table_slot,
                inputs_slot,
                table_rows,
                table_cols,
                query_cols,
                output_col_offset,
                output_cols,
            },
            NodePayload::NttBn254 { values_slot } => Self::NttBn254 { values_slot },
            NodePayload::NttGoldilocks { values_slot } => Self::NttGoldilocks { values_slot },
            NodePayload::LdeGoldilocks {
                values_slot,
                blowup,
            } => Self::LdeGoldilocks {
                values_slot,
                blowup,
            },
            NodePayload::MsmBn254 {
                scalars_slot,
                bases_slot,
            } => Self::MsmBn254 {
                scalars_slot,
                bases_slot,
            },
            NodePayload::PoseidonGoldilocks {
                states_slot,
                round_constants_slot,
                n_ext,
                n_int,
            } => Self::PoseidonGoldilocks {
                states_slot,
                round_constants_slot,
                n_ext,
                n_int,
            },
            NodePayload::Sha256Batch {
                inputs_slot,
                count,
                input_len,
            } => Self::Sha256Batch {
                inputs_slot,
                count,
                input_len,
            },
            NodePayload::MerkleGoldilocks {
                leaves_slot,
                digest_slot,
                leaf_count,
                hash_fn,
            } => Self::MerkleGoldilocks {
                leaves_slot,
                digest_slot,
                leaf_count,
                hash_fn: MerkleHashFnBundle::from_runtime(hash_fn),
            },
            NodePayload::FriFoldGoldilocks {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            } => Self::FriFoldGoldilocks {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            },
            NodePayload::FriFoldBabyBear {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            } => Self::FriFoldBabyBear {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            },
            NodePayload::FriQueryOpen {
                proof_slot,
                query_slot,
                query_count,
                tree_depth,
            } => Self::FriQueryOpen {
                proof_slot,
                query_slot,
                query_count,
                tree_depth,
            },
            NodePayload::VerifierEmbed {
                wrapper_input_slot,
                scheme,
            } => Self::VerifierEmbed {
                wrapper_input_slot,
                scheme,
            },
            NodePayload::BackendProve {
                backend,
                route,
                transcript_slot,
            } => Self::BackendProve {
                backend,
                route: BackendRouteBundle::from_runtime(route),
                transcript_slot,
            },
            NodePayload::BackendFold {
                backend,
                compress,
                transcript_slot,
            } => Self::BackendFold {
                backend,
                compress,
                transcript_slot,
            },
            NodePayload::OuterProve {
                proving_input_slot,
                scheme,
            } => Self::OuterProve {
                proving_input_slot,
                scheme,
            },
            NodePayload::TranscriptUpdate { state_slot } => Self::TranscriptUpdate { state_slot },
            NodePayload::ProofEncode {
                input_slots,
                output_kind,
            } => Self::ProofEncode {
                input_slots,
                output_kind: ProofOutputKindBundle::from_runtime(output_kind),
            },
            NodePayload::Barrier => Self::Barrier,
            NodePayload::Noop => Self::Noop,
        }
    }

    fn into_runtime_payload(
        self,
        exec_ctx: &ExecutionContext,
    ) -> Result<NodePayload, DistributedError> {
        Ok(match self {
            Self::WitnessSolve => {
                let program = exec_ctx.program.as_ref().ok_or_else(|| {
                    DistributedError::Serialization(
                        "bundle missing program for WitnessSolve payload".into(),
                    )
                })?;
                let inputs = exec_ctx.witness_inputs.as_ref().ok_or_else(|| {
                    DistributedError::Serialization(
                        "bundle missing witness inputs for WitnessSolve payload".into(),
                    )
                })?;
                NodePayload::WitnessSolve {
                    program: Arc::clone(program),
                    inputs: Arc::clone(inputs),
                }
            }
            Self::BooleanizeSignals {
                signals_slot,
                count,
            } => NodePayload::BooleanizeSignals {
                signals_slot,
                count,
            },
            Self::RangeCheckExpand {
                signals_slot,
                bits,
                count,
            } => NodePayload::RangeCheckExpand {
                signals_slot,
                bits,
                count,
            },
            Self::LookupExpand {
                table_slot,
                inputs_slot,
                table_rows,
                table_cols,
                query_cols,
                output_col_offset,
                output_cols,
            } => NodePayload::LookupExpand {
                table_slot,
                inputs_slot,
                table_rows,
                table_cols,
                query_cols,
                output_col_offset,
                output_cols,
            },
            Self::NttBn254 { values_slot } => NodePayload::NttBn254 { values_slot },
            Self::NttGoldilocks { values_slot } => NodePayload::NttGoldilocks { values_slot },
            Self::LdeGoldilocks {
                values_slot,
                blowup,
            } => NodePayload::LdeGoldilocks {
                values_slot,
                blowup,
            },
            Self::MsmBn254 {
                scalars_slot,
                bases_slot,
            } => NodePayload::MsmBn254 {
                scalars_slot,
                bases_slot,
            },
            Self::PoseidonGoldilocks {
                states_slot,
                round_constants_slot,
                n_ext,
                n_int,
            } => NodePayload::PoseidonGoldilocks {
                states_slot,
                round_constants_slot,
                n_ext,
                n_int,
            },
            Self::Sha256Batch {
                inputs_slot,
                count,
                input_len,
            } => NodePayload::Sha256Batch {
                inputs_slot,
                count,
                input_len,
            },
            Self::MerkleGoldilocks {
                leaves_slot,
                digest_slot,
                leaf_count,
                hash_fn,
            } => NodePayload::MerkleGoldilocks {
                leaves_slot,
                digest_slot,
                leaf_count,
                hash_fn: hash_fn.into_runtime(),
            },
            Self::FriFoldGoldilocks {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            } => NodePayload::FriFoldGoldilocks {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            },
            Self::FriFoldBabyBear {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            } => NodePayload::FriFoldBabyBear {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            },
            Self::FriQueryOpen {
                proof_slot,
                query_slot,
                query_count,
                tree_depth,
            } => NodePayload::FriQueryOpen {
                proof_slot,
                query_slot,
                query_count,
                tree_depth,
            },
            Self::VerifierEmbed {
                wrapper_input_slot,
                scheme,
            } => NodePayload::VerifierEmbed {
                wrapper_input_slot,
                scheme,
            },
            Self::BackendProve {
                backend,
                route,
                transcript_slot,
            } => NodePayload::BackendProve {
                backend,
                route: route.into_runtime(),
                transcript_slot,
            },
            Self::BackendFold {
                backend,
                compress,
                transcript_slot,
            } => NodePayload::BackendFold {
                backend,
                compress,
                transcript_slot,
            },
            Self::OuterProve {
                proving_input_slot,
                scheme,
            } => NodePayload::OuterProve {
                proving_input_slot,
                scheme,
            },
            Self::TranscriptUpdate { state_slot } => NodePayload::TranscriptUpdate { state_slot },
            Self::ProofEncode {
                input_slots,
                output_kind,
            } => NodePayload::ProofEncode {
                input_slots,
                output_kind: output_kind.into_runtime(),
            },
            Self::Barrier => NodePayload::Barrier,
            Self::Noop => NodePayload::Noop,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MerkleHashFnBundle {
    Poseidon2Goldilocks,
    Poseidon2BabyBear,
    Sha256,
    Keccak256,
}

impl MerkleHashFnBundle {
    fn from_runtime(value: MerkleHashFn) -> Self {
        match value {
            MerkleHashFn::Poseidon2Goldilocks => Self::Poseidon2Goldilocks,
            MerkleHashFn::Poseidon2BabyBear => Self::Poseidon2BabyBear,
            MerkleHashFn::Sha256 => Self::Sha256,
            MerkleHashFn::Keccak256 => Self::Keccak256,
        }
    }

    fn into_runtime(self) -> MerkleHashFn {
        match self {
            Self::Poseidon2Goldilocks => MerkleHashFn::Poseidon2Goldilocks,
            Self::Poseidon2BabyBear => MerkleHashFn::Poseidon2BabyBear,
            Self::Sha256 => MerkleHashFn::Sha256,
            Self::Keccak256 => MerkleHashFn::Keccak256,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProofOutputKindBundle {
    Groth16Proof,
    Plonky3Proof,
    BackendArtifact,
    WrappedProof,
    RawBytes,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BackendRouteBundle {
    Auto,
    ExplicitCompat,
}

impl BackendRouteBundle {
    fn from_runtime(value: BackendRoute) -> Self {
        match value {
            BackendRoute::Auto => Self::Auto,
            BackendRoute::ExplicitCompat => Self::ExplicitCompat,
        }
    }

    fn into_runtime(self) -> BackendRoute {
        match self {
            Self::Auto => BackendRoute::Auto,
            Self::ExplicitCompat => BackendRoute::ExplicitCompat,
        }
    }
}

impl ProofOutputKindBundle {
    fn from_runtime(value: ProofOutputKind) -> Self {
        match value {
            ProofOutputKind::Groth16Proof => Self::Groth16Proof,
            ProofOutputKind::Plonky3Proof => Self::Plonky3Proof,
            ProofOutputKind::BackendArtifact => Self::BackendArtifact,
            ProofOutputKind::WrappedProof => Self::WrappedProof,
            ProofOutputKind::RawBytes => Self::RawBytes,
        }
    }

    pub fn into_runtime(self) -> ProofOutputKind {
        match self {
            Self::Groth16Proof => ProofOutputKind::Groth16Proof,
            Self::Plonky3Proof => ProofOutputKind::Plonky3Proof,
            Self::BackendArtifact => ProofOutputKind::BackendArtifact,
            Self::WrappedProof => ProofOutputKind::WrappedProof,
            Self::RawBytes => ProofOutputKind::RawBytes,
        }
    }
}

fn infer_required_output_slots(graph_nodes: &[GraphNodeBundle]) -> Vec<u32> {
    let mut non_sinks = HashSet::new();
    for node in graph_nodes {
        for dep in &node.deps {
            non_sinks.insert(*dep);
        }
    }

    let mut slots = Vec::new();
    for (index, node) in graph_nodes.iter().enumerate() {
        if non_sinks.contains(&index) {
            continue;
        }
        slots.extend(node.output_buffers.iter().map(|handle| handle.slot));
    }

    if slots.is_empty()
        && let Some(last) = graph_nodes.last()
    {
        slots.extend(last.output_buffers.iter().map(|handle| handle.slot));
    }

    slots.sort_unstable();
    slots.dedup();
    slots
}

fn source_digests(
    exec_ctx: &ExecutionContext,
) -> Result<BTreeMap<String, String>, DistributedError> {
    let mut digests = BTreeMap::new();
    if let Some(program) = &exec_ctx.program {
        digests.insert("program_digest".into(), program.digest_hex());
    }
    if let Some(compiled) = &exec_ctx.compiled {
        digests.insert(
            "compiled_program_digest".into(),
            compiled.program_digest.clone(),
        );
    }
    if let Some(witness_inputs) = &exec_ctx.witness_inputs {
        digests.insert(
            "witness_inputs_sha256".into(),
            digest_json(witness_inputs.as_ref())?,
        );
    }
    if let Some(witness) = &exec_ctx.witness {
        digests.insert("witness_sha256".into(), digest_json(witness.as_ref())?);
    }
    if let Some(source_proof) = &exec_ctx.source_proof {
        digests.insert(
            "source_proof_sha256".into(),
            digest_json(source_proof.as_ref())?,
        );
        digests.insert(
            "source_proof_program_digest".into(),
            source_proof.program_digest.clone(),
        );
    }
    Ok(digests)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, DistributedError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| DistributedError::Serialization(format!("serialize digest input: {err}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn encode_json_value<T: Serialize>(value: &T) -> Result<Vec<u8>, DistributedError> {
    serde_json::to_vec(value).map_err(|err| {
        DistributedError::Serialization(format!("serialize execution context: {err}"))
    })
}

fn decode_json_value<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, DistributedError> {
    serde_json::from_slice(bytes).map_err(|err| {
        DistributedError::Serialization(format!("deserialize execution context: {err}"))
    })
}

fn static_runtime_label(label: &str) -> Result<&'static str, DistributedError> {
    match label {
        "bn254" => Ok("bn254"),
        "bn254_fr" => Ok("bn254_fr"),
        "goldilocks" => Ok("goldilocks"),
        "babybear" => Ok("babybear"),
        "bls12_381" => Ok("bls12_381"),
        "grumpkin" => Ok("grumpkin"),
        "pallas" => Ok("pallas"),
        "vesta" => Ok("vesta"),
        "arkworks-groth16" => Ok("arkworks-groth16"),
        "groth16" => Ok("groth16"),
        "plonky3" => Ok("plonky3"),
        "nova" => Ok("nova"),
        "hypernova" => Ok("hypernova"),
        "halo2" => Ok("halo2"),
        "halo2-bls12-381" => Ok("halo2-bls12-381"),
        "midnight-compact" => Ok("midnight-compact"),
        "stark-to-groth16" => Ok("stark-to-groth16"),
        other => Err(DistributedError::Serialization(format!(
            "unsupported runtime label '{other}' in execution bundle"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zkf_runtime::adapters::emit_backend_prove_graph_with_context;
    use zkf_runtime::memory::UnifiedBufferPool;

    #[test]
    fn execution_bundle_roundtrip_preserves_backend_job() {
        let program = Arc::new(zkf_examples::mul_add_program());
        let inputs: WitnessInputs = [
            ("x".to_string(), zkf_core::FieldElement::from_i64(3)),
            ("y".to_string(), zkf_core::FieldElement::from_i64(9)),
        ]
        .into_iter()
        .collect();
        let mut pool = UnifiedBufferPool::new(512 * 1024 * 1024);
        let emission = emit_backend_prove_graph_with_context(
            &mut pool,
            zkf_core::BackendKind::ArkworksGroth16,
            BackendRoute::Auto,
            Arc::clone(&program),
            Some(Arc::new(inputs.clone())),
            None,
            TrustModel::Cryptographic,
            true,
        )
        .unwrap();

        let bundle =
            DistributedExecutionBundle::from_graph_and_context(&emission.graph, &emission.exec_ctx)
                .unwrap();
        assert!(!bundle.required_output_slots.is_empty());
        assert_eq!(
            bundle.source_digests.get("program_digest"),
            Some(&program.digest_hex())
        );

        let encoded = bundle.encode_postcard().unwrap();
        let decoded = DistributedExecutionBundle::decode_postcard(&encoded).unwrap();
        let (graph, exec_ctx) = decoded.into_graph_and_context().unwrap();

        assert_eq!(graph.node_count(), emission.graph.node_count());
        assert!(exec_ctx.program.is_some());
        assert!(exec_ctx.witness_inputs.is_some());
        assert_eq!(
            exec_ctx.optimization_objective,
            emission.exec_ctx.optimization_objective
        );
    }
}
