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

//! ProverGraph: directed acyclic graph of proving tasks.

use crate::error::RuntimeError;
use crate::graph_core;
use crate::memory::{BufferHandle, NodeId};
use crate::trust::TrustModel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Where a node should execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DevicePlacement {
    Cpu,
    Gpu,
    /// CPU with hardware crypto extensions (FEAT_SHA256, FEAT_SHA3, etc.)
    /// Used for sub-GPU-threshold hash operations.
    CpuCrypto,
    /// CPU with SME/AMX matrix coprocessor.
    /// Used for sub-GPU-threshold field arithmetic.
    CpuSme,
    /// No preference; the scheduler decides.
    Either,
}

pub const GPU_CAPABLE_STAGE_KEYS: [&str; 8] = [
    "ntt",
    "lde",
    "msm",
    "poseidon-batch",
    "sha256-batch",
    "merkle-layer",
    "fri-fold",
    "fri-query-open",
];

pub fn gpu_capable_stage_keys() -> &'static [&'static str] {
    &graph_core::GPU_CAPABLE_STAGE_KEYS
}

pub fn is_gpu_capable_stage_key(stage: &str) -> bool {
    graph_core::GPU_CAPABLE_STAGE_KEYS.contains(&stage)
}

pub fn runtime_stage_key_for_op_name(op_name: &str) -> &'static str {
    graph_core::runtime_stage_key_for_op_name(op_name)
}

/// The type of computation a `ProverNode` performs.
#[derive(Debug, Clone)]
pub enum ProverOp {
    // ── Witness / constraint phase ──
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

    // ── NTT ──
    Ntt {
        size: usize,
        field: &'static str,
        inverse: bool,
    },
    Lde {
        size: usize,
        blowup: usize,
        field: &'static str,
    },

    // ── MSM ──
    Msm {
        num_scalars: usize,
        curve: &'static str,
    },

    // ── Hashing / commitment ──
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

    // ── FRI ──
    FriFold {
        folding_factor: usize,
        codeword_len: usize,
    },
    FriQueryOpen {
        query_count: usize,
        tree_depth: usize,
    },

    // ── Recursive / wrapping ──
    VerifierEmbed {
        inner_scheme: &'static str,
    },
    BackendProve {
        backend: &'static str,
    },
    BackendFold {
        backend: &'static str,
    },
    OuterProve {
        outer_scheme: &'static str,
    },

    // ── Finalization ──
    TranscriptUpdate,
    ProofEncode,

    // ── Scheduling hints ──
    Barrier {
        wait_for: Vec<NodeId>,
    },
    Noop,
}

impl ProverOp {
    pub fn name(&self) -> &'static str {
        match self {
            ProverOp::WitnessSolve { .. } => "WitnessSolve",
            ProverOp::BooleanizeSignals { .. } => "BooleanizeSignals",
            ProverOp::RangeCheckExpand { .. } => "RangeCheckExpand",
            ProverOp::LookupExpand { .. } => "LookupExpand",
            ProverOp::Ntt { .. } => "NTT",
            ProverOp::Lde { .. } => "LDE",
            ProverOp::Msm { .. } => "MSM",
            ProverOp::PoseidonBatch { .. } => "PoseidonBatch",
            ProverOp::Sha256Batch { .. } => "Sha256Batch",
            ProverOp::MerkleLayer { .. } => "MerkleLayer",
            ProverOp::FriFold { .. } => "FRIFold",
            ProverOp::FriQueryOpen { .. } => "FRIQueryOpen",
            ProverOp::VerifierEmbed { .. } => "VerifierEmbed",
            ProverOp::BackendProve { .. } => "BackendProve",
            ProverOp::BackendFold { .. } => "BackendFold",
            ProverOp::OuterProve { .. } => "OuterProve",
            ProverOp::TranscriptUpdate => "TranscriptUpdate",
            ProverOp::ProofEncode => "ProofEncode",
            ProverOp::Barrier { .. } => "Barrier",
            ProverOp::Noop => "Noop",
        }
    }

    pub fn default_placement(&self) -> DevicePlacement {
        graph_core::default_placement(self)
    }

    pub fn stage_key(&self) -> &'static str {
        runtime_stage_key_for_op_name(self.name())
    }

    pub fn is_gpu_capable_stage(&self) -> bool {
        is_gpu_capable_stage_key(self.stage_key())
    }

    pub fn problem_size_hint(&self) -> Option<usize> {
        graph_core::problem_size_hint(self)
    }
}

/// Specification for building a ProverNode (builder pattern).
pub struct NodeSpec {
    pub op: ProverOp,
    pub deps: Vec<NodeId>,
    pub trust_model: TrustModel,
    pub deterministic: bool,
    pub input_buffers: Vec<BufferHandle>,
    pub output_buffers: Vec<BufferHandle>,
}

impl NodeSpec {
    pub fn new(op: ProverOp) -> Self {
        Self {
            op,
            deps: Vec::new(),
            trust_model: TrustModel::Cryptographic,
            deterministic: false,
            input_buffers: Vec::new(),
            output_buffers: Vec::new(),
        }
    }
}

/// A single node in the proving DAG.
pub struct ProverNode {
    pub id: NodeId,
    pub op: ProverOp,
    pub deps: Vec<NodeId>,
    pub device_pref: DevicePlacement,
    pub trust_model: TrustModel,
    pub deterministic: bool,
    pub input_buffers: Vec<BufferHandle>,
    pub output_buffers: Vec<BufferHandle>,
}

impl ProverNode {
    pub fn new(op: ProverOp) -> Self {
        let device_pref = op.default_placement();
        Self {
            id: NodeId::new(),
            op,
            deps: Vec::new(),
            device_pref,
            trust_model: TrustModel::Cryptographic,
            deterministic: false,
            input_buffers: Vec::new(),
            output_buffers: Vec::new(),
        }
    }

    pub fn with_deps(mut self, deps: impl IntoIterator<Item = NodeId>) -> Self {
        self.deps.extend(deps);
        self
    }

    pub fn with_trust(mut self, trust: TrustModel) -> Self {
        self.trust_model = trust;
        self
    }

    pub fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self
    }

    pub fn with_inputs(mut self, inputs: impl IntoIterator<Item = BufferHandle>) -> Self {
        self.input_buffers.extend(inputs);
        self
    }

    pub fn with_outputs(mut self, outputs: impl IntoIterator<Item = BufferHandle>) -> Self {
        self.output_buffers.extend(outputs);
        self
    }
}

/// A directed acyclic graph of `ProverNode`s describing a full proving job.
pub struct ProverGraph {
    pub(crate) nodes: HashMap<NodeId, ProverNode>,
    pub(crate) order: Vec<NodeId>,
}

impl ProverGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: ProverNode) -> NodeId {
        let id = node.id;
        self.order.push(id);
        self.nodes.insert(id, node);
        id
    }

    pub fn add_dep(&mut self, from: NodeId, to: NodeId) {
        if let Some(node) = self.nodes.get_mut(&to)
            && !node.deps.contains(&from)
        {
            node.deps.push(from);
        }
    }

    pub fn topological_order(&self) -> Result<Vec<NodeId>, RuntimeError> {
        graph_core::topological_order(&self.nodes, &self.order)
    }

    pub fn propagate_trust(&mut self) -> Result<(), RuntimeError> {
        for step in graph_core::trust_propagation_plan(&self.nodes, &self.order)? {
            if let Some(node) = self.nodes.get_mut(&step.node_id) {
                node.trust_model = step.trust_model;
            }
        }
        Ok(())
    }

    pub fn node(&self, id: NodeId) -> Option<&ProverNode> {
        self.nodes.get(&id)
    }

    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut ProverNode> {
        self.nodes.get_mut(&id)
    }

    pub fn node_count(&self) -> usize {
        self.order.len()
    }

    pub fn iter_nodes(&self) -> impl Iterator<Item = &ProverNode> {
        self.order.iter().filter_map(|id| self.nodes.get(id))
    }
}

impl Default for ProverGraph {
    fn default() -> Self {
        Self::new()
    }
}
