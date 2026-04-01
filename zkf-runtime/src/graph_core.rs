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

use crate::error::RuntimeError;
use crate::graph::{DevicePlacement, ProverNode, ProverOp};
use crate::memory::NodeId;
use crate::trust::TrustModel;
use std::collections::{HashMap, VecDeque};

pub(crate) struct TrustPropagation {
    pub(crate) node_id: NodeId,
    pub(crate) trust_model: TrustModel,
}

pub(crate) const GPU_CAPABLE_STAGE_KEYS: [&str; 8] = [
    "ntt",
    "lde",
    "msm",
    "poseidon-batch",
    "sha256-batch",
    "merkle-layer",
    "fri-fold",
    "fri-query-open",
];

pub(crate) fn runtime_stage_key_for_op_name(op_name: &str) -> &'static str {
    match op_name {
        "WitnessSolve" => "witness-solve",
        "BooleanizeSignals" => "booleanize-signals",
        "RangeCheckExpand" => "range-check-expand",
        "LookupExpand" => "lookup-expand",
        "NTT" => "ntt",
        "LDE" => "lde",
        "MSM" => "msm",
        "PoseidonBatch" => "poseidon-batch",
        "Sha256Batch" => "sha256-batch",
        "MerkleLayer" => "merkle-layer",
        "FRIFold" => "fri-fold",
        "FRIQueryOpen" => "fri-query-open",
        "VerifierEmbed" => "verifier-embed",
        "BackendProve" => "backend-prove",
        "BackendFold" => "backend-fold",
        "OuterProve" => "outer-prove",
        "TranscriptUpdate" => "transcript-update",
        "ProofEncode" => "proof-encode",
        "Barrier" => "barrier",
        "Noop" => "noop",
        _ => "unknown",
    }
}

pub(crate) fn default_placement(op: &ProverOp) -> DevicePlacement {
    match op {
        ProverOp::Ntt { size, .. } if *size >= 1 << 16 => DevicePlacement::Gpu,
        ProverOp::Lde { size, .. } if *size >= 1 << 16 => DevicePlacement::Gpu,
        ProverOp::Msm { num_scalars, .. } if *num_scalars >= 1 << 16 => DevicePlacement::Gpu,
        ProverOp::PoseidonBatch { count, .. } if *count >= 256 => DevicePlacement::Gpu,
        ProverOp::Sha256Batch { count } if *count >= 256 => DevicePlacement::Gpu,
        ProverOp::MerkleLayer { leaf_count, .. } if *leaf_count >= 1 << 16 => DevicePlacement::Gpu,
        ProverOp::FriFold { codeword_len, .. } if *codeword_len >= 1 << 18 => DevicePlacement::Gpu,
        ProverOp::Sha256Batch { count } if *count > 0 => DevicePlacement::CpuCrypto,
        ProverOp::MerkleLayer { .. } => DevicePlacement::CpuCrypto,
        ProverOp::Ntt { .. } => DevicePlacement::CpuSme,
        ProverOp::Lde { .. } => DevicePlacement::CpuSme,
        ProverOp::FriFold { .. } => DevicePlacement::CpuSme,
        ProverOp::WitnessSolve { .. } => DevicePlacement::Cpu,
        ProverOp::BooleanizeSignals { .. } => DevicePlacement::Cpu,
        ProverOp::RangeCheckExpand { .. } => DevicePlacement::Cpu,
        ProverOp::LookupExpand { .. } => DevicePlacement::Cpu,
        ProverOp::TranscriptUpdate => DevicePlacement::Cpu,
        ProverOp::ProofEncode => DevicePlacement::Cpu,
        ProverOp::VerifierEmbed { .. } => DevicePlacement::Cpu,
        ProverOp::BackendProve { .. } => DevicePlacement::Cpu,
        ProverOp::BackendFold { .. } => DevicePlacement::Cpu,
        ProverOp::Barrier { .. } => DevicePlacement::Cpu,
        ProverOp::Noop => DevicePlacement::Cpu,
        _ => DevicePlacement::Either,
    }
}

pub(crate) fn problem_size_hint(op: &ProverOp) -> Option<usize> {
    match op {
        ProverOp::WitnessSolve {
            constraint_count,
            signal_count,
        } => Some(constraint_count.saturating_add(*signal_count).max(1)),
        ProverOp::BooleanizeSignals { count } => Some((*count).max(1)),
        ProverOp::RangeCheckExpand { count, .. } => Some((*count).max(1)),
        ProverOp::LookupExpand {
            table_rows,
            table_cols,
        } => Some(table_rows.saturating_mul(*table_cols).max(1)),
        ProverOp::Ntt { size, .. } => Some((*size).max(1)),
        ProverOp::Lde { size, blowup, .. } => Some(size.saturating_mul(*blowup).max(1)),
        ProverOp::Msm { num_scalars, .. } => Some((*num_scalars).max(1)),
        ProverOp::PoseidonBatch { count, width } => Some(count.saturating_mul(*width).max(1)),
        ProverOp::Sha256Batch { count } => Some((*count).max(1)),
        ProverOp::MerkleLayer { leaf_count, .. } => Some((*leaf_count).max(1)),
        ProverOp::FriFold {
            folding_factor,
            codeword_len,
        } => Some(codeword_len.saturating_mul(*folding_factor).max(1)),
        ProverOp::FriQueryOpen {
            query_count,
            tree_depth,
        } => Some(query_count.saturating_mul(*tree_depth).max(1)),
        _ => None,
    }
}

pub(crate) fn topological_order(
    nodes: &HashMap<NodeId, ProverNode>,
    order: &[NodeId],
) -> Result<Vec<NodeId>, RuntimeError> {
    let mut in_degree: HashMap<NodeId, usize> = order.iter().map(|id| (*id, 0)).collect();
    let mut successors: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for id in order {
        if let Some(node) = nodes.get(id) {
            for dep in &node.deps {
                successors.entry(*dep).or_default().push(*id);
                *in_degree.entry(*id).or_insert(0) += 1;
            }
        }
    }

    let mut queue: VecDeque<NodeId> = order
        .iter()
        .copied()
        .filter(|id| in_degree.get(id).copied().unwrap_or_default() == 0)
        .collect();

    let mut result = Vec::with_capacity(order.len());
    while let Some(id) = queue.pop_front() {
        result.push(id);
        if let Some(succs) = successors.get(&id) {
            for succ in succs {
                let deg = in_degree
                    .get_mut(succ)
                    .expect("successor must exist in graph");
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(*succ);
                }
            }
        }
    }

    if result.len() != order.len() {
        return Err(RuntimeError::CyclicDependency);
    }

    Ok(result)
}

pub(crate) fn trust_propagation_plan(
    nodes: &HashMap<NodeId, ProverNode>,
    order: &[NodeId],
) -> Result<Vec<TrustPropagation>, RuntimeError> {
    let topo = topological_order(nodes, order)?;
    let mut result = Vec::with_capacity(topo.len());
    for id in topo {
        let Some(node) = nodes.get(&id) else {
            continue;
        };
        let mut inherited = node.trust_model;
        for dep_id in &node.deps {
            if let Some(dep) = nodes.get(dep_id) {
                inherited = inherited.weaken(dep.trust_model);
            }
        }
        result.push(TrustPropagation {
            node_id: id,
            trust_model: inherited,
        });
    }
    Ok(result)
}
