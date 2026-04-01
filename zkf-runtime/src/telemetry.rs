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

//! Execution telemetry: per-node traces and graph execution reports.

use crate::graph::{DevicePlacement, runtime_stage_key_for_op_name};
use crate::memory::NodeId;
use crate::trust::TrustModel;
use crate::watchdog::WatchdogAlert;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Per-node execution record.
#[derive(Debug, Clone)]
pub struct NodeTrace {
    pub node_id: NodeId,
    pub op_name: &'static str,
    pub stage_key: String,
    pub placement: DevicePlacement,
    pub trust_model: TrustModel,
    pub wall_time: Duration,
    pub problem_size: Option<usize>,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub predicted_cpu_ms: Option<f64>,
    pub predicted_gpu_ms: Option<f64>,
    pub prediction_confidence: Option<f64>,
    pub prediction_observation_count: Option<u64>,
    pub input_digest: [u8; 8],
    pub output_digest: [u8; 8],
    pub allocated_bytes_after: usize,
    /// Accelerator that actually executed this node (e.g. "metal-msm-bn254").
    pub accelerator_name: Option<String>,
    /// Whether the node fell back from its preferred device.
    pub fell_back: bool,
    /// Residency class of the primary input buffer.
    pub buffer_residency: Option<String>,
    /// Whether this node was executed through an explicit delegated driver.
    pub delegated: bool,
    /// Logical delegated backend label, if any.
    pub delegated_backend: Option<String>,
}

/// Execution report for a complete graph run.
#[derive(Debug)]
pub struct GraphExecutionReport {
    pub node_traces: Vec<NodeTrace>,
    pub total_wall_time: Duration,
    pub peak_memory_bytes: usize,
    pub gpu_nodes: usize,
    pub cpu_nodes: usize,
    pub delegated_nodes: usize,
    pub final_trust_model: TrustModel,
    /// Number of nodes that fell back from GPU to CPU.
    pub fallback_nodes: usize,
    pub watchdog_alerts: Vec<WatchdogAlert>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuntimeStageTelemetry {
    pub node_count: usize,
    pub gpu_nodes: usize,
    pub cpu_nodes: usize,
    pub fallback_nodes: usize,
    pub duration_ms: f64,
    pub input_bytes: usize,
    pub output_bytes: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accelerators: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residency_classes: Vec<String>,
}

impl GraphExecutionReport {
    pub(crate) fn new() -> Self {
        Self {
            node_traces: Vec::new(),
            total_wall_time: Duration::ZERO,
            peak_memory_bytes: 0,
            gpu_nodes: 0,
            cpu_nodes: 0,
            delegated_nodes: 0,
            final_trust_model: TrustModel::Cryptographic,
            fallback_nodes: 0,
            watchdog_alerts: Vec::new(),
        }
    }

    pub fn gpu_wall_time(&self) -> Duration {
        self.node_traces
            .iter()
            .filter(|trace| trace.placement == DevicePlacement::Gpu)
            .map(|trace| trace.wall_time)
            .sum()
    }

    pub fn cpu_wall_time(&self) -> Duration {
        self.node_traces
            .iter()
            .filter(|trace| trace.placement != DevicePlacement::Gpu)
            .map(|trace| trace.wall_time)
            .sum()
    }

    pub fn gpu_stage_busy_ratio(&self) -> f64 {
        let total = self.total_wall_time.as_secs_f64();
        if total <= 0.0 {
            return 0.0;
        }
        (self.gpu_wall_time().as_secs_f64() / total).clamp(0.0, 1.0)
    }

    pub fn counter_source(&self) -> &'static str {
        "runtime-node-trace-v1"
    }

    pub fn stage_breakdown(&self) -> BTreeMap<String, RuntimeStageTelemetry> {
        let mut breakdown = BTreeMap::<String, RuntimeStageTelemetry>::new();
        let mut accelerator_sets = BTreeMap::<String, BTreeSet<String>>::new();
        let mut residency_sets = BTreeMap::<String, BTreeSet<String>>::new();

        for trace in &self.node_traces {
            let key = runtime_stage_key(trace.op_name);
            let stage = breakdown
                .entry(key.clone())
                .or_insert_with(|| RuntimeStageTelemetry {
                    node_count: 0,
                    gpu_nodes: 0,
                    cpu_nodes: 0,
                    fallback_nodes: 0,
                    duration_ms: 0.0,
                    input_bytes: 0,
                    output_bytes: 0,
                    accelerators: Vec::new(),
                    residency_classes: Vec::new(),
                });

            stage.node_count += 1;
            stage.duration_ms += trace.wall_time.as_secs_f64() * 1000.0;
            stage.input_bytes += trace.input_bytes;
            stage.output_bytes += trace.output_bytes;

            if trace.placement == DevicePlacement::Gpu {
                stage.gpu_nodes += 1;
            } else {
                stage.cpu_nodes += 1;
            }
            if trace.fell_back {
                stage.fallback_nodes += 1;
            }

            if let Some(accelerator_name) = &trace.accelerator_name {
                accelerator_sets
                    .entry(key.clone())
                    .or_default()
                    .insert(accelerator_name.clone());
            }
            if let Some(residency_class) = &trace.buffer_residency {
                residency_sets
                    .entry(key.clone())
                    .or_default()
                    .insert(residency_class.clone());
            }
        }

        for (key, stage) in &mut breakdown {
            if let Some(accelerators) = accelerator_sets.remove(key) {
                stage.accelerators = accelerators.into_iter().collect();
            }
            if let Some(residency_classes) = residency_sets.remove(key) {
                stage.residency_classes = residency_classes.into_iter().collect();
            }
        }

        breakdown
    }
}

fn runtime_stage_key(op_name: &str) -> String {
    runtime_stage_key_for_op_name(op_name).to_string()
}

/// Result of a complete plan execution.
#[derive(Debug)]
pub struct PlanExecutionResult {
    pub report: GraphExecutionReport,
    pub outputs: serde_json::Value,
    pub control_plane: Option<crate::control_plane::ControlPlaneExecutionSummary>,
    pub security: Option<crate::security::SecurityVerdict>,
    pub model_integrity: Option<crate::security::RuntimeModelIntegrity>,
    pub swarm: Option<crate::swarm::SwarmTelemetryDigest>,
}
