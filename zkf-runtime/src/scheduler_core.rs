use crate::adaptive_tuning::StageTimingPrediction;
use crate::control_plane::DispatchPlan;
use crate::graph::{DevicePlacement, ProverGraph, ProverNode};
use crate::memory::{NodeId, digest_handles};
use crate::swarm::ActivationLevel;
use crate::telemetry::{GraphExecutionReport, NodeTrace};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlacementInputs {
    pub gpu_available: bool,
    pub memory_pressure: f64,
    pub deterministic_mode: bool,
    pub swarm_activation_level: u8,
    pub gpu_working_set_headroom_bytes: Option<usize>,
    pub gpu_residency_budget_bytes: Option<usize>,
    pub low_memory_mode: bool,
}

pub(crate) fn resolve_placement(
    inputs: PlacementInputs,
    chosen_dispatch_plan: Option<&DispatchPlan>,
    node: &ProverNode,
) -> DevicePlacement {
    if inputs.deterministic_mode || node.deterministic {
        return DevicePlacement::Cpu;
    }
    if inputs.swarm_activation_level >= ActivationLevel::Emergency as u8 {
        return fail_closed_cpuish_placement(node.device_pref);
    }
    let gpu_headroom_insufficient = match (
        inputs.gpu_working_set_headroom_bytes,
        inputs.gpu_residency_budget_bytes,
    ) {
        (Some(headroom), Some(required)) => headroom < required,
        _ => false,
    };
    if !inputs.gpu_available
        || inputs.memory_pressure > 0.9
        || inputs.low_memory_mode
        || gpu_headroom_insufficient
    {
        return fail_closed_cpuish_placement(node.device_pref);
    }
    if let Some(plan) = chosen_dispatch_plan
        && node.op.is_gpu_capable_stage()
        && let Some(placement) = plan.placement_for_stage(node.op.stage_key())
    {
        return placement;
    }
    node.device_pref
}

pub(crate) fn resolve_all_placements(
    graph: &ProverGraph,
    inputs: PlacementInputs,
    chosen_dispatch_plan: Option<&DispatchPlan>,
) -> Result<HashMap<NodeId, DevicePlacement>, crate::RuntimeError> {
    let order = graph.topological_order()?;
    let mut placements = HashMap::with_capacity(order.len());
    for id in order {
        if let Some(node) = graph.node(id) {
            placements.insert(id, resolve_placement(inputs, chosen_dispatch_plan, node));
        }
    }
    Ok(placements)
}

pub(crate) fn apply_watchdog_cpu_override(
    node: &ProverNode,
    placement: DevicePlacement,
    force_gpu_capable_to_cpu: bool,
    force_stage_to_cpu: bool,
) -> DevicePlacement {
    if (force_gpu_capable_to_cpu && node.op.is_gpu_capable_stage()) || force_stage_to_cpu {
        DevicePlacement::Cpu
    } else {
        placement
    }
}

pub(crate) fn gpu_requested(placement: DevicePlacement, driver_promotes_non_gpu: bool) -> bool {
    placement == DevicePlacement::Gpu
        || (matches!(
            placement,
            DevicePlacement::Either | DevicePlacement::CpuCrypto | DevicePlacement::CpuSme
        ) && driver_promotes_non_gpu)
}

pub(crate) fn promote_gpu_placement(placement: DevicePlacement) -> DevicePlacement {
    if matches!(
        placement,
        DevicePlacement::Either | DevicePlacement::CpuCrypto | DevicePlacement::CpuSme
    ) {
        DevicePlacement::Gpu
    } else {
        placement
    }
}

pub(crate) fn cpu_dispatch_required(placement: DevicePlacement, dispatch_ok: bool) -> bool {
    matches!(
        placement,
        DevicePlacement::Cpu
            | DevicePlacement::CpuCrypto
            | DevicePlacement::CpuSme
            | DevicePlacement::Either
    ) && !dispatch_ok
}

pub(crate) fn node_io_bytes(node: &ProverNode) -> (usize, usize) {
    let input_bytes = node.input_buffers.iter().map(|h| h.size_bytes).sum();
    let output_bytes = node.output_buffers.iter().map(|h| h.size_bytes).sum();
    (input_bytes, output_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_node_trace(
    node: &ProverNode,
    placement: DevicePlacement,
    wall_time: Duration,
    timing_prediction: Option<StageTimingPrediction>,
    input_bytes: usize,
    output_bytes: usize,
    output_digest: [u8; 8],
    allocated_bytes_after: usize,
    accelerator_name: Option<String>,
    fell_back: bool,
    buffer_residency: Option<String>,
    delegated: bool,
    delegated_backend: Option<String>,
) -> NodeTrace {
    NodeTrace {
        node_id: node.id,
        op_name: node.op.name(),
        stage_key: node.op.stage_key().to_string(),
        placement,
        trust_model: node.trust_model,
        wall_time,
        problem_size: node.op.problem_size_hint(),
        input_bytes,
        output_bytes,
        predicted_cpu_ms: timing_prediction.map(|prediction| prediction.cpu_ms),
        predicted_gpu_ms: timing_prediction.map(|prediction| prediction.gpu_ms),
        prediction_confidence: timing_prediction.map(|prediction| prediction.confidence),
        prediction_observation_count: timing_prediction
            .map(|prediction| prediction.observation_count),
        input_digest: digest_handles(&node.input_buffers),
        output_digest,
        allocated_bytes_after,
        accelerator_name,
        fell_back,
        buffer_residency,
        delegated,
        delegated_backend,
    }
}

pub(crate) fn record_trace(
    report: &mut GraphExecutionReport,
    trace: NodeTrace,
    peak_allocated_bytes: usize,
) {
    match trace.placement {
        DevicePlacement::Gpu => report.gpu_nodes += 1,
        _ => report.cpu_nodes += 1,
    }
    if trace.fell_back {
        report.fallback_nodes += 1;
    }
    if trace.delegated {
        report.delegated_nodes += 1;
    }
    report.final_trust_model = report.final_trust_model.weaken(trace.trust_model);
    report.peak_memory_bytes = report.peak_memory_bytes.max(peak_allocated_bytes);
    report.node_traces.push(trace);
}

fn fail_closed_cpuish_placement(placement: DevicePlacement) -> DevicePlacement {
    match placement {
        DevicePlacement::Gpu | DevicePlacement::Either => DevicePlacement::Cpu,
        DevicePlacement::CpuCrypto => DevicePlacement::CpuCrypto,
        DevicePlacement::CpuSme => DevicePlacement::CpuSme,
        other => other,
    }
}
