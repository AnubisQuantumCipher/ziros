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

//! Shared execution helpers for coordinator-local and worker-side partition runs.

use crate::bundle::{DistributedExecutionBundle, GraphNodeBundle, NodePayloadBundle};
use crate::error::DistributedError;
use crate::identity::NodeCapability;
use crate::protocol::SubgraphTraceEntry;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use zkf_core::artifact::{CompiledProgram, ProofArtifact};
use zkf_runtime::buffer_bridge::BufferBridge;
use zkf_runtime::graph::DevicePlacement;
use zkf_runtime::memory::{MemoryClass, UnifiedBufferPool};
use zkf_runtime::scheduler::{DeterministicScheduler, PlacementContext};
use zkf_runtime::{
    GpuVerificationMode, NodeTrace, create_metal_buffer_allocator, create_metal_dispatch_driver,
};

pub(crate) struct ExecutedAssignment {
    pub output_data: Vec<(u32, Vec<u8>)>,
    pub named_outputs: Vec<(String, Vec<u8>)>,
    pub compiled_program: Option<CompiledProgram>,
    pub proof_artifact: Option<ProofArtifact>,
    pub wall_time: Duration,
    pub trace_entries: Vec<SubgraphTraceEntry>,
    pub node_traces: Vec<NodeTrace>,
    pub final_trust_model: Option<String>,
    pub peak_memory_bytes: Option<u64>,
    pub gpu_driver_used: bool,
}

pub(crate) fn execute_assignment_with_capability(
    local_capability: &NodeCapability,
    bundle: DistributedExecutionBundle,
    injected_initial_buffers: HashMap<u32, Vec<u8>>,
    swarm_activation_level: u8,
) -> Result<ExecutedAssignment, DistributedError> {
    let required_output_slots = bundle.required_output_slots.clone();
    let slot_output_names = slot_output_names(&bundle.graph_nodes);
    let (mut graph, mut exec_ctx) = bundle.into_graph_and_context()?;
    let graph_nodes = graph.node_count();
    preserve_required_output_slots(&mut graph, &required_output_slots);

    for (slot, data) in injected_initial_buffers {
        exec_ctx.set_initial_buffer(slot, data);
    }

    let mut bridge = BufferBridge::with_temp_spill();
    let gpu_allocator = if local_capability.gpu_available {
        create_metal_buffer_allocator()
    } else {
        None
    };
    if let Some(allocator) = gpu_allocator {
        bridge.set_gpu_allocator(allocator);
    }
    let gpu_driver = if local_capability.gpu_available {
        create_metal_dispatch_driver(GpuVerificationMode::BestEffort)
    } else {
        None
    };

    let placement_ctx = PlacementContext {
        gpu_available: gpu_driver
            .as_ref()
            .is_some_and(|driver| driver.is_available()),
        memory_pressure: memory_pressure_ratio(local_capability),
        gpu_cores: local_capability.gpu_cores,
        gpu_working_set_headroom_bytes: None,
        gpu_residency_budget_bytes: None,
        low_memory_mode: false,
        deterministic_mode: false,
        chosen_dispatch_plan: None,
        swarm_activation_level,
    };
    let scheduler =
        DeterministicScheduler::new(UnifiedBufferPool::new(512 * 1024 * 1024), placement_ctx);
    let started = Instant::now();
    let report = scheduler.execute_with_context_and_drivers(
        graph,
        &mut exec_ctx,
        &mut bridge,
        gpu_driver.as_deref(),
    )?;
    let wall_time = started.elapsed();

    let mut output_data = Vec::new();
    for slot in required_output_slots {
        if let Some(output_name) = slot_output_names.get(&slot)
            && let Some(bytes) = exec_ctx.outputs.get(output_name)
        {
            output_data.push((slot, bytes.clone()));
            continue;
        }
        if bridge.is_resident(slot) {
            let bytes = bridge.view(slot)?.as_bytes().to_vec();
            output_data.push((slot, bytes));
        }
    }

    let mut named_outputs: Vec<(String, Vec<u8>)> = exec_ctx.outputs.into_iter().collect();
    named_outputs.sort_by(|a, b| a.0.cmp(&b.0));
    if output_data.is_empty()
        && let Some((name, bytes)) = named_outputs.first()
    {
        let synthetic_slot = slot_output_names
            .iter()
            .find_map(|(slot, candidate)| (candidate == name).then_some(*slot))
            .unwrap_or(0);
        output_data.push((synthetic_slot, bytes.clone()));
    }

    let trace_entries = report
        .node_traces
        .iter()
        .map(|trace| SubgraphTraceEntry {
            node_name: trace.op_name.to_string(),
            wall_time_ms: trace.wall_time.as_millis() as u64,
            device: placement_label(trace.placement).to_string(),
        })
        .collect();

    log::info!(
        "executed distributed assignment (nodes={}, outputs={}, proof={}, gpu_driver={})",
        graph_nodes,
        output_data.len(),
        exec_ctx.proof_artifact.is_some(),
        gpu_driver.is_some()
    );

    Ok(ExecutedAssignment {
        output_data,
        named_outputs,
        compiled_program: exec_ctx.compiled.as_deref().cloned(),
        proof_artifact: exec_ctx.proof_artifact,
        wall_time,
        trace_entries,
        node_traces: report.node_traces.clone(),
        final_trust_model: Some(report.final_trust_model.as_str().to_string()),
        peak_memory_bytes: Some(report.peak_memory_bytes as u64),
        gpu_driver_used: gpu_driver.is_some(),
    })
}

pub(crate) fn placement_label(placement: DevicePlacement) -> &'static str {
    match placement {
        DevicePlacement::Cpu => "cpu",
        DevicePlacement::Gpu => "gpu",
        DevicePlacement::CpuCrypto => "cpu-crypto",
        DevicePlacement::CpuSme => "cpu-sme",
        DevicePlacement::Either => "either",
    }
}

fn slot_output_names(graph_nodes: &[GraphNodeBundle]) -> HashMap<u32, String> {
    let mut slot_names = HashMap::new();
    for node in graph_nodes {
        let Some(slot) = node.output_buffers.first().map(|handle| handle.slot) else {
            continue;
        };
        if let Some(name) = output_name_for_payload(&node.payload) {
            slot_names.insert(slot, name.to_string());
        }
    }
    slot_names
}

fn preserve_required_output_slots(graph: &mut zkf_runtime::graph::ProverGraph, slots: &[u32]) {
    if slots.is_empty() {
        return;
    }
    let required: HashSet<u32> = slots.iter().copied().collect();
    let order = match graph.topological_order() {
        Ok(order) => order,
        Err(_) => return,
    };
    for node_id in order {
        let Some(node) = graph.node_mut(node_id) else {
            continue;
        };
        for handle in &mut node.output_buffers {
            if required.contains(&handle.slot) {
                handle.class = MemoryClass::HotResident;
            }
        }
    }
}

fn output_name_for_payload(payload: &NodePayloadBundle) -> Option<&'static str> {
    match payload {
        NodePayloadBundle::BackendProve { .. } => Some("backend_proof_runtime"),
        NodePayloadBundle::BackendFold { .. } => Some("backend_fold_runtime"),
        NodePayloadBundle::OuterProve { .. } => Some("wrapped_proof_runtime"),
        NodePayloadBundle::ProofEncode { output_kind, .. } => Some(match output_kind {
            crate::bundle::ProofOutputKindBundle::Groth16Proof => "groth16_proof",
            crate::bundle::ProofOutputKindBundle::Plonky3Proof => "plonky3_proof",
            crate::bundle::ProofOutputKindBundle::BackendArtifact => "proof_artifact",
            crate::bundle::ProofOutputKindBundle::WrappedProof => "wrapped_proof",
            crate::bundle::ProofOutputKindBundle::RawBytes => "raw_proof",
        }),
        _ => None,
    }
}

fn memory_pressure_ratio(capability: &NodeCapability) -> f64 {
    if capability.resources.total_memory_bytes == 0 {
        return 0.0;
    }
    let used = capability
        .resources
        .total_memory_bytes
        .saturating_sub(capability.resources.available_memory_bytes);
    (used as f64 / capability.resources.total_memory_bytes as f64).clamp(0.0, 1.0)
}
