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

//! DeterministicScheduler: executes a ProverGraph in topological order.

use crate::adaptive_tuning::stage_timing_prediction;
use crate::buffer_bridge::BufferBridge;
use crate::control_plane::DispatchPlan;
use crate::cpu_driver::CpuBackendDriver;
use crate::error::RuntimeError;
use crate::execution::ExecutionContext;
use crate::graph::{DevicePlacement, ProverGraph, ProverNode};
use crate::memory::{BufferHandle, MemoryClass, NodeId, UnifiedBufferPool, digest_handles};
use crate::scheduler_core;
use crate::swarm::SwarmController;
use crate::telemetry::{GraphExecutionReport, NodeTrace};
use crate::watchdog::ProofWatchdog;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Decision parameters passed to the placement engine.
#[derive(Debug, Clone)]
pub struct PlacementContext {
    pub gpu_available: bool,
    pub memory_pressure: f64,
    pub gpu_cores: u32,
    pub deterministic_mode: bool,
    pub chosen_dispatch_plan: Option<DispatchPlan>,
    pub swarm_activation_level: u8,
    pub gpu_working_set_headroom_bytes: Option<usize>,
    pub gpu_residency_budget_bytes: Option<usize>,
    pub low_memory_mode: bool,
}

impl Default for PlacementContext {
    fn default() -> Self {
        Self {
            gpu_available: false,
            memory_pressure: 0.0,
            gpu_cores: 0,
            deterministic_mode: false,
            chosen_dispatch_plan: None,
            swarm_activation_level: 0,
            gpu_working_set_headroom_bytes: None,
            gpu_residency_budget_bytes: None,
            low_memory_mode: false,
        }
    }
}

/// Decides the final execution device for each node.
pub struct PlacementEngine {
    ctx: PlacementContext,
}

impl PlacementEngine {
    pub fn new(ctx: PlacementContext) -> Self {
        Self { ctx }
    }

    pub fn resolve(&self, node: &ProverNode) -> DevicePlacement {
        scheduler_core::resolve_placement(
            scheduler_core::PlacementInputs {
                gpu_available: self.ctx.gpu_available,
                memory_pressure: self.ctx.memory_pressure,
                deterministic_mode: self.ctx.deterministic_mode,
                swarm_activation_level: self.ctx.swarm_activation_level,
                gpu_working_set_headroom_bytes: self.ctx.gpu_working_set_headroom_bytes,
                gpu_residency_budget_bytes: self.ctx.gpu_residency_budget_bytes,
                low_memory_mode: self.ctx.low_memory_mode,
            },
            self.ctx.chosen_dispatch_plan.as_ref(),
            node,
        )
    }

    pub fn assign_all(
        &self,
        graph: &ProverGraph,
    ) -> Result<HashMap<NodeId, DevicePlacement>, RuntimeError> {
        scheduler_core::resolve_all_placements(
            graph,
            scheduler_core::PlacementInputs {
                gpu_available: self.ctx.gpu_available,
                memory_pressure: self.ctx.memory_pressure,
                deterministic_mode: self.ctx.deterministic_mode,
                swarm_activation_level: self.ctx.swarm_activation_level,
                gpu_working_set_headroom_bytes: self.ctx.gpu_working_set_headroom_bytes,
                gpu_residency_budget_bytes: self.ctx.gpu_residency_budget_bytes,
                low_memory_mode: self.ctx.low_memory_mode,
            },
            self.ctx.chosen_dispatch_plan.as_ref(),
        )
    }
}

/// Callback invoked when a node completes.
pub type NodeHook = Box<dyn Fn(&NodeTrace) + Send + Sync>;

/// Schedules and executes a `ProverGraph` in topological order.
///
/// Renamed from `GraphScheduler` to `DeterministicScheduler`.
pub struct DeterministicScheduler {
    pool: Arc<Mutex<UnifiedBufferPool>>,
    engine: PlacementEngine,
    hooks: Vec<NodeHook>,
    watchdog: Option<ProofWatchdog>,
}

impl DeterministicScheduler {
    pub fn new(pool: UnifiedBufferPool, placement_ctx: PlacementContext) -> Self {
        Self {
            pool: Arc::new(Mutex::new(pool)),
            engine: PlacementEngine::new(placement_ctx),
            hooks: Vec::new(),
            watchdog: None,
        }
    }

    pub fn on_node_complete(&mut self, hook: NodeHook) {
        self.hooks.push(hook);
    }

    pub fn attach_watchdog(&mut self, watchdog: ProofWatchdog) {
        self.hooks.push(watchdog.node_hook());
        self.watchdog = Some(watchdog);
    }

    pub fn attach_swarm(&mut self, controller: SwarmController) {
        self.hooks.push(controller.sentinel_hook());
    }

    /// Legacy execute path: symbolic scheduling only (no real drivers).
    /// Kept as a convenience wrapper.
    pub fn execute(&self, mut graph: ProverGraph) -> Result<GraphExecutionReport, RuntimeError> {
        graph.propagate_trust()?;
        let order = graph.topological_order()?;
        let placements = self.engine.assign_all(&graph)?;

        let mut report = GraphExecutionReport::new();
        let job_start = Instant::now();

        for node_id in &order {
            let node = graph
                .node(*node_id)
                .ok_or(RuntimeError::NodeNotFound(*node_id))?;
            let mut placement = placements[node_id];
            if let Some(watchdog) = &self.watchdog
                && watchdog.should_force_gpu_capable_to_cpu()
                && node.op.is_gpu_capable_stage()
            {
                placement = DevicePlacement::Cpu;
            } else if let Some(watchdog) = &self.watchdog
                && watchdog.should_force_stage_to_cpu(node.op.stage_key())
            {
                placement = DevicePlacement::Cpu;
            }

            let node_start = Instant::now();
            let (input_bytes, output_bytes) = scheduler_core::node_io_bytes(node);

            if let Ok(mut pool) = self.pool.lock() {
                for &out in &node.output_buffers {
                    pool.mark_written(out, *node_id);
                }
            }

            let wall_time = node_start.elapsed();

            let timing_prediction = node
                .op
                .problem_size_hint()
                .map(|size| stage_timing_prediction(node.op.stage_key(), size));
            let trace = scheduler_core::build_node_trace(
                node,
                placement,
                wall_time,
                timing_prediction,
                input_bytes,
                output_bytes,
                digest_handles(&node.output_buffers),
                self.pool
                    .lock()
                    .map(|pool| pool.allocated_bytes())
                    .unwrap_or_default(),
                None,
                false,
                None,
                false,
                None,
            );

            for hook in &self.hooks {
                hook(&trace);
            }

            let peak_allocated_bytes = self
                .pool
                .lock()
                .map(|pool| pool.allocated_bytes())
                .unwrap_or_default();
            scheduler_core::record_trace(&mut report, trace, peak_allocated_bytes);
        }

        report.total_wall_time = job_start.elapsed();
        Ok(report)
    }

    /// Real execution path: dispatches to Metal or CPU drivers using
    /// `ExecutionContext` and `BufferBridge`.
    ///
    /// Keeps topological order and trust propagation as-is.  On each node:
    /// 1. Resolve placement
    /// 2. Ensure input buffers are resident
    /// 3. Dispatch to Metal or CPU driver
    /// 4. Record output digests *after* execution, not before
    /// 5. Update peak allocated bytes from the bridge/pool
    ///
    /// Real execution path with an externally-provided GPU driver.
    pub fn execute_with_context_and_gpu(
        &self,
        graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
        gpu_driver: &dyn crate::metal_driver::GpuDispatchDriver,
    ) -> Result<GraphExecutionReport, RuntimeError> {
        self.execute_with_context_inner(graph, exec_ctx, bridge, Some(gpu_driver))
    }

    pub fn execute_with_context_and_drivers(
        &self,
        graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
        gpu_driver: Option<&dyn crate::metal_driver::GpuDispatchDriver>,
    ) -> Result<GraphExecutionReport, RuntimeError> {
        self.execute_with_context_inner(graph, exec_ctx, bridge, gpu_driver)
    }

    pub fn execute_with_context(
        &self,
        graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<GraphExecutionReport, RuntimeError> {
        self.execute_with_context_inner(graph, exec_ctx, bridge, None)
    }

    fn execute_with_context_inner(
        &self,
        mut graph: ProverGraph,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
        gpu_driver: Option<&dyn crate::metal_driver::GpuDispatchDriver>,
    ) -> Result<GraphExecutionReport, RuntimeError> {
        graph.propagate_trust()?;
        let order = graph.topological_order()?;
        let placements = self.engine.assign_all(&graph)?;

        let cpu_driver = CpuBackendDriver::new();
        let mut remaining_consumers = buffer_consumer_counts(&graph);

        let mut report = GraphExecutionReport::new();
        let job_start = Instant::now();
        register_graph_handles(&self.pool, &graph);
        for (&slot, data) in &exec_ctx.initial_buffers {
            if !bridge.is_resident(slot) {
                bridge.allocate(BufferHandle {
                    slot,
                    size_bytes: data.len(),
                    class: MemoryClass::EphemeralScratch,
                })?;
            }
            bridge.ensure_resident(slot)?;
            bridge.write_slot(slot, data)?;
            bridge.mark_written(slot, NodeId::new());
        }

        for node_id in &order {
            let node = graph
                .node(*node_id)
                .ok_or(RuntimeError::NodeNotFound(*node_id))?;
            let mut placement = placements[node_id];
            if let Some(watchdog) = &self.watchdog {
                if watchdog.take_flush_gpu_buffers() {
                    zkf_backends::harden_accelerators_for_current_pressure();
                }
                placement = scheduler_core::apply_watchdog_cpu_override(
                    node,
                    placement,
                    watchdog.should_force_gpu_capable_to_cpu(),
                    watchdog.should_force_stage_to_cpu(node.op.stage_key()),
                );
            }

            let node_start = Instant::now();

            // 1. Ensure input buffers are resident
            for buf in &node.input_buffers {
                if !bridge.is_resident(buf.slot) {
                    bridge.allocate(*buf)?;
                }
            }
            for buf in &node.output_buffers {
                if !bridge.is_resident(buf.slot) {
                    bridge.allocate(*buf)?;
                }
            }
            let input_slots: Vec<u32> = node.input_buffers.iter().map(|h| h.slot).collect();
            bridge.ensure_inputs_resident(&input_slots)?;

            // 2. Dispatch to appropriate driver
            let mut accelerator_name: Option<String> = None;
            let mut fell_back = false;
            let mut driver_input_bytes = 0usize;
            let mut driver_output_bytes = 0usize;
            let mut buffer_residency: Option<String> = None;
            let mut delegated = false;
            let mut delegated_backend: Option<String> = None;

            let mut dispatch_ok = false;
            let verified_gpu_lane = gpu_driver.is_some_and(|gpu| {
                gpu.verification_mode() == crate::metal_driver::GpuVerificationMode::VerifiedPinned
            });

            if verified_gpu_lane
                && node.op.is_gpu_capable_stage()
                && gpu_driver.is_some_and(|gpu| !gpu.verified_lane_allows(node))
            {
                placement = DevicePlacement::Cpu;
            }

            // GPU can promote: Gpu placements, Either placements, and
            // CpuCrypto/CpuSme placements when the GPU driver opts in.
            let gpu_requested = scheduler_core::gpu_requested(
                placement,
                gpu_driver.is_some_and(|gpu| gpu.should_try_on_either(node)),
            );

            // Try GPU first if placement is GPU, or if the GPU driver wants
            // to promote an `Either`/`CpuCrypto`/`CpuSme` node.
            if gpu_requested {
                if matches!(
                    placement,
                    DevicePlacement::Either | DevicePlacement::CpuCrypto | DevicePlacement::CpuSme
                ) {
                    placement = scheduler_core::promote_gpu_placement(placement);
                }
                if let Some(gpu) = gpu_driver {
                    if gpu.is_available() {
                        match gpu.execute(node, exec_ctx, bridge) {
                            Ok(Ok(telem)) => {
                                accelerator_name = Some(telem.accelerator_name);
                                fell_back = false;
                                driver_input_bytes = telem.input_bytes;
                                driver_output_bytes = telem.output_bytes;
                                buffer_residency = Some(telem.residency_class);
                                dispatch_ok = true;
                            }
                            Ok(Err(fallback)) => {
                                log::info!(
                                    "GPU fallback for node {:?}: {}",
                                    node_id,
                                    fallback.reason
                                );
                                fell_back = true;
                                placement = DevicePlacement::Cpu;
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        if gpu.verification_mode().fail_closed() {
                            return Err(RuntimeError::GpuFallbackRejected {
                                node: format!(
                                    "{:?} ({}) verified GPU lane unavailable",
                                    node_id,
                                    node.op.name()
                                ),
                            });
                        }
                        fell_back = true;
                        placement = DevicePlacement::Cpu;
                    }
                } else {
                    fell_back = true;
                    placement = DevicePlacement::Cpu;
                }
            }

            // CPU dispatch (primary or fallback).
            // CpuCrypto and CpuSme still execute on the CPU (with HW extensions).
            if scheduler_core::cpu_dispatch_required(placement, dispatch_ok) {
                match cpu_driver.execute(node, exec_ctx, bridge) {
                    Ok(telem) => {
                        accelerator_name = Some(telem.op_name.clone());
                        driver_input_bytes = telem.input_bytes;
                        driver_output_bytes = telem.output_bytes;
                        delegated = telem.delegated;
                        delegated_backend = telem.delegated_backend.clone();
                        dispatch_ok = true;
                    }
                    Err(e) => return Err(e),
                }
            }

            // 3. Mark output buffers as written AFTER successful execution
            if dispatch_ok {
                for &out in &node.output_buffers {
                    bridge.mark_written(out.slot, *node_id);
                    if let Ok(mut pool) = self.pool.lock() {
                        pool.mark_written(out, *node_id);
                    }
                }
            }

            // 4. Compute digests from bridge (post-execution)
            let (input_bytes, output_bytes) = scheduler_core::node_io_bytes(node);

            let output_digest = if !node.output_buffers.is_empty() {
                let first_slot = node.output_buffers[0].slot;
                bridge
                    .slot_digest(first_slot)
                    .unwrap_or(digest_handles(&node.output_buffers))
            } else {
                digest_handles(&node.output_buffers)
            };

            let wall_time = node_start.elapsed();
            let problem_size = node.op.problem_size_hint();
            let timing_prediction =
                problem_size.map(|size| stage_timing_prediction(node.op.stage_key(), size));

            let trace = scheduler_core::build_node_trace(
                node,
                placement,
                wall_time,
                timing_prediction,
                driver_input_bytes.max(input_bytes),
                driver_output_bytes.max(output_bytes),
                output_digest,
                bridge.current_resident_bytes(),
                accelerator_name,
                fell_back,
                buffer_residency,
                delegated,
                delegated_backend,
            );

            for hook in &self.hooks {
                hook(&trace);
            }

            let bridge_bytes = bridge.current_resident_bytes();
            let pool_bytes = self
                .pool
                .lock()
                .map(|pool| pool.allocated_bytes())
                .unwrap_or_default();
            let current = bridge_bytes.max(pool_bytes);
            scheduler_core::record_trace(&mut report, trace, current);
            release_completed_handles(&self.pool, bridge, node, &mut remaining_consumers);
        }

        report.total_wall_time = job_start.elapsed();
        Ok(report)
    }
}

fn buffer_consumer_counts(graph: &ProverGraph) -> HashMap<u32, usize> {
    let mut counts = HashMap::new();
    for node in graph.iter_nodes() {
        for handle in &node.input_buffers {
            *counts.entry(handle.slot).or_insert(0) += 1;
        }
    }
    counts
}

fn register_graph_handles(pool: &Arc<Mutex<UnifiedBufferPool>>, graph: &ProverGraph) {
    if let Ok(mut pool) = pool.lock() {
        let mut seen = HashSet::new();
        for node in graph.iter_nodes() {
            for handle in node.input_buffers.iter().chain(node.output_buffers.iter()) {
                if seen.insert(handle.slot) {
                    pool.track_handle(*handle);
                }
            }
        }
    }
}

fn release_completed_handles(
    pool: &Arc<Mutex<UnifiedBufferPool>>,
    bridge: &mut BufferBridge,
    node: &ProverNode,
    remaining_consumers: &mut HashMap<u32, usize>,
) {
    let mut releasable = HashSet::new();
    for handle in &node.input_buffers {
        if let Some(count) = remaining_consumers.get_mut(&handle.slot) {
            *count = count.saturating_sub(1);
            if *count == 0 && handle.class != MemoryClass::HotResident {
                releasable.insert(*handle);
            }
        }
    }
    for handle in &node.output_buffers {
        if remaining_consumers.get(&handle.slot).copied().unwrap_or(0) == 0
            && handle.class != MemoryClass::HotResident
        {
            releasable.insert(*handle);
        }
    }
    if releasable.is_empty() {
        return;
    }
    if let Ok(mut locked_pool) = pool.lock() {
        for handle in releasable {
            bridge.free(handle.slot);
            locked_pool.free(handle);
        }
    } else {
        for handle in releasable {
            bridge.free(handle.slot);
        }
    }
}

/// Backwards-compatible alias.
pub type GraphScheduler = DeterministicScheduler;
