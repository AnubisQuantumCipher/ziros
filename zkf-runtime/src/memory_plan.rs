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

use serde::{Deserialize, Serialize};
use zkf_core::{PressureLevel, SystemResources};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMemoryProbe {
    pub recommended_working_set_size_bytes: Option<u64>,
    pub current_allocated_size_bytes: Option<u64>,
}

impl RuntimeMemoryProbe {
    pub fn working_set_headroom_bytes(self) -> Option<u64> {
        match (
            self.recommended_working_set_size_bytes,
            self.current_allocated_size_bytes,
        ) {
            (Some(recommended), Some(current)) => Some(recommended.saturating_sub(current)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMemoryPlanInput {
    pub compiled_constraint_count: usize,
    pub job_estimate_bytes: u64,
    pub graph_required_bytes: Option<u64>,
    pub metal: RuntimeMemoryProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMemoryPlan {
    pub plan_version: String,
    pub total_ram_bytes: u64,
    pub available_ram_bytes: u64,
    pub unified_memory: bool,
    pub pressure_level: PressureLevel,
    pub os_headroom_bytes: u64,
    pub execution_budget_bytes: u64,
    pub runtime_pool_limit_bytes: u64,
    pub bridge_resident_limit_bytes: u64,
    pub metal_recommended_working_set_size_bytes: Option<u64>,
    pub metal_current_allocated_size_bytes: Option<u64>,
    pub metal_working_set_headroom_bytes: Option<u64>,
    pub metal_residency_budget_bytes: u64,
    pub compiled_constraint_count: usize,
    pub job_estimate_bytes: u64,
    pub graph_required_bytes: Option<u64>,
    pub projected_peak_bytes: u64,
    pub recommended_proving_threads: usize,
    pub high_constraint_mode: bool,
    pub low_memory_mode: bool,
    pub spill_preferred: bool,
    pub gpu_allowed: bool,
    pub cpu_override_active: bool,
    pub adaptive_memory_enabled: bool,
    pub debug_overrides: RuntimeMemoryOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeMemoryOverrides {
    pub max_circuit_memory_bytes: Option<u64>,
    pub runtime_pool_bytes: Option<u64>,
    pub metal_residency_bytes: Option<u64>,
    pub low_memory_forced: bool,
    pub adaptive_disabled: bool,
    pub proving_threads_override: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct RuntimeHostSnapshot {
    pub resources: SystemResources,
    pub recommendation: zkf_core::ResourceRecommendation,
}

impl RuntimeHostSnapshot {
    pub fn detect() -> Self {
        let resources = SystemResources::detect();
        let recommendation = resources.recommend();
        Self {
            resources,
            recommendation,
        }
    }
}

pub fn estimate_job_bytes_from_constraint_count(compiled_constraint_count: usize) -> u64 {
    (compiled_constraint_count as u64)
        .saturating_mul(256)
        .max(64 * MIB)
}

pub fn compute_runtime_memory_plan(
    host: &RuntimeHostSnapshot,
    input: RuntimeMemoryPlanInput,
) -> RuntimeMemoryPlan {
    let overrides = RuntimeMemoryOverrides {
        max_circuit_memory_bytes: parse_env_u64("ZKF_MAX_CIRCUIT_MEMORY"),
        runtime_pool_bytes: parse_env_u64("ZKF_RUNTIME_POOL_BYTES"),
        metal_residency_bytes: parse_env_u64("ZKF_METAL_RESIDENCY_BYTES"),
        low_memory_forced: env_flag("ZKF_LOW_MEMORY"),
        adaptive_disabled: env_flag("ZKF_DISABLE_ADAPTIVE_MEMORY"),
        proving_threads_override: parse_env_usize("ZKF_PROVING_THREADS"),
    };

    let total_ram_bytes = host.resources.total_ram_bytes.max(1);
    let available_ram_bytes = host.resources.available_ram_bytes.min(total_ram_bytes);
    let unified_memory = host.resources.unified_memory;
    let pressure_level = host.resources.pressure.level;
    let compiled_constraint_count = input.compiled_constraint_count;
    let graph_required_bytes = input.graph_required_bytes.filter(|value| *value > 0);
    let job_estimate_bytes = input.job_estimate_bytes.max(1);
    let projected_peak_bytes = graph_required_bytes
        .map(|graph| graph.saturating_mul(5).saturating_div(4))
        .unwrap_or(job_estimate_bytes)
        .max(job_estimate_bytes);
    let high_constraint_mode =
        compiled_constraint_count >= 100_000 || job_estimate_bytes >= 2 * GIB;

    if overrides.adaptive_disabled {
        let legacy_pool = overrides
            .runtime_pool_bytes
            .or(overrides.max_circuit_memory_bytes)
            .unwrap_or(512 * MIB)
            .clamp(64 * MIB, total_ram_bytes);
        let legacy_residency = overrides
            .metal_residency_bytes
            .unwrap_or(4 * GIB)
            .clamp(64 * MIB, total_ram_bytes);
        let recommended_threads = overrides
            .proving_threads_override
            .unwrap_or_else(|| host.recommendation.proving_threads.max(1));
        let metal_working_set_headroom_bytes = input.metal.working_set_headroom_bytes();
        let gpu_allowed = metal_working_set_headroom_bytes
            .map(|headroom| headroom >= legacy_residency)
            .unwrap_or(!overrides.low_memory_forced);
        return RuntimeMemoryPlan {
            plan_version: "adaptive-unified-memory-v1".to_string(),
            total_ram_bytes,
            available_ram_bytes,
            unified_memory,
            pressure_level,
            os_headroom_bytes: host.recommendation.os_headroom_bytes,
            execution_budget_bytes: overrides
                .max_circuit_memory_bytes
                .unwrap_or(host.recommendation.max_circuit_memory_bytes)
                .max(GIB),
            runtime_pool_limit_bytes: legacy_pool,
            bridge_resident_limit_bytes: legacy_pool,
            metal_recommended_working_set_size_bytes: input
                .metal
                .recommended_working_set_size_bytes,
            metal_current_allocated_size_bytes: input.metal.current_allocated_size_bytes,
            metal_working_set_headroom_bytes,
            metal_residency_budget_bytes: legacy_residency,
            compiled_constraint_count,
            job_estimate_bytes,
            graph_required_bytes,
            projected_peak_bytes,
            recommended_proving_threads: recommended_threads,
            high_constraint_mode,
            low_memory_mode: overrides.low_memory_forced,
            spill_preferred: overrides.low_memory_forced,
            gpu_allowed,
            cpu_override_active: !gpu_allowed,
            adaptive_memory_enabled: false,
            debug_overrides: overrides,
        };
    }

    let os_headroom_bytes = if unified_memory {
        (total_ram_bytes / 5).max(8 * GIB)
    } else {
        (total_ram_bytes.saturating_mul(15) / 100).max(4 * GIB)
    };
    let available_after_headroom = available_ram_bytes.saturating_sub(os_headroom_bytes);
    let total_cap = total_ram_bytes.saturating_mul(70) / 100;
    let mut execution_budget_bytes = available_after_headroom.min(total_cap).max(GIB);
    if let Some(limit) = overrides.max_circuit_memory_bytes {
        execution_budget_bytes = execution_budget_bytes.min(limit).max(GIB);
    }

    let mut recommended_proving_threads = overrides
        .proving_threads_override
        .unwrap_or_else(|| host.recommendation.proving_threads.max(1));
    if matches!(
        pressure_level,
        PressureLevel::High | PressureLevel::Critical
    ) {
        recommended_proving_threads = 1;
    } else if pressure_level == PressureLevel::Elevated {
        recommended_proving_threads = recommended_proving_threads.clamp(1, 4);
    }

    let mut low_memory_mode = overrides.low_memory_forced
        || host.recommendation.low_memory_mode
        || matches!(
            pressure_level,
            PressureLevel::High | PressureLevel::Critical
        );
    if pressure_level == PressureLevel::Elevated && projected_peak_bytes > execution_budget_bytes {
        low_memory_mode = true;
    }

    let mut runtime_pool_limit_bytes = projected_peak_bytes
        .clamp(512 * MIB, execution_budget_bytes)
        .max(512 * MIB);
    if let Some(override_bytes) = overrides.runtime_pool_bytes {
        runtime_pool_limit_bytes = override_bytes.clamp(64 * MIB, execution_budget_bytes);
    }

    let default_residency = match input.metal.recommended_working_set_size_bytes {
        Some(recommended) => execution_budget_bytes
            .saturating_mul(60)
            .saturating_div(100)
            .min(recommended.saturating_mul(70).saturating_div(100)),
        None => execution_budget_bytes
            .saturating_mul(40)
            .saturating_div(100)
            .min(12 * GIB),
    }
    .max(64 * MIB);
    let mut metal_residency_budget_bytes = overrides
        .metal_residency_bytes
        .unwrap_or(default_residency)
        .clamp(64 * MIB, execution_budget_bytes);

    if low_memory_mode && pressure_level == PressureLevel::High {
        metal_residency_budget_bytes = metal_residency_budget_bytes
            .min(execution_budget_bytes / 4)
            .max(64 * MIB);
    }

    let metal_working_set_headroom_bytes = input.metal.working_set_headroom_bytes();
    let headroom_ok = metal_working_set_headroom_bytes
        .map(|headroom| headroom >= metal_residency_budget_bytes)
        .unwrap_or(true);
    let projected_peak_ok = projected_peak_bytes <= execution_budget_bytes;

    let mut gpu_allowed = headroom_ok && pressure_level != PressureLevel::Critical;
    if low_memory_mode
        && matches!(
            pressure_level,
            PressureLevel::High | PressureLevel::Critical
        )
    {
        gpu_allowed = false;
    }
    if !projected_peak_ok && pressure_level != PressureLevel::Normal {
        gpu_allowed = false;
    }

    let spill_preferred = high_constraint_mode
        || low_memory_mode
        || pressure_level == PressureLevel::Elevated
        || !projected_peak_ok;

    let cpu_override_active = !gpu_allowed
        || matches!(
            pressure_level,
            PressureLevel::High | PressureLevel::Critical
        );

    RuntimeMemoryPlan {
        plan_version: "adaptive-unified-memory-v1".to_string(),
        total_ram_bytes,
        available_ram_bytes,
        unified_memory,
        pressure_level,
        os_headroom_bytes,
        execution_budget_bytes,
        runtime_pool_limit_bytes,
        bridge_resident_limit_bytes: runtime_pool_limit_bytes,
        metal_recommended_working_set_size_bytes: input.metal.recommended_working_set_size_bytes,
        metal_current_allocated_size_bytes: input.metal.current_allocated_size_bytes,
        metal_working_set_headroom_bytes,
        metal_residency_budget_bytes,
        compiled_constraint_count,
        job_estimate_bytes,
        graph_required_bytes,
        projected_peak_bytes,
        recommended_proving_threads,
        high_constraint_mode,
        low_memory_mode,
        spill_preferred,
        gpu_allowed,
        cpu_override_active,
        adaptive_memory_enabled: true,
        debug_overrides: overrides,
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn parse_env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn parse_env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::MemoryPressure;

    fn host(
        total_gib: u64,
        available_gib: u64,
        unified_memory: bool,
        pressure_level: PressureLevel,
    ) -> RuntimeHostSnapshot {
        let resources = SystemResources {
            total_ram_bytes: total_gib * GIB,
            available_ram_bytes: available_gib * GIB,
            cpu_cores_logical: 16,
            cpu_cores_physical: 12,
            unified_memory,
            gpu_memory_bytes: unified_memory.then_some(total_gib * GIB),
            pressure: MemoryPressure {
                level: pressure_level,
                utilization_pct: 0.0,
                compressed_bytes: 0,
                swap_used_bytes: 0,
                raw_available_i64: (available_gib * GIB) as i64,
                compressor_overflow: false,
                free_bytes: 0,
                inactive_bytes: 0,
                purgeable_bytes: 0,
                wired_bytes: 0,
            },
        };
        let recommendation = resources.recommend();
        RuntimeHostSnapshot {
            resources,
            recommendation,
        }
    }

    fn input(
        compiled_constraint_count: usize,
        job_estimate_gib: u64,
        graph_required_gib: Option<u64>,
        recommended_working_set_gib: Option<u64>,
        current_allocated_gib: Option<u64>,
    ) -> RuntimeMemoryPlanInput {
        RuntimeMemoryPlanInput {
            compiled_constraint_count,
            job_estimate_bytes: job_estimate_gib * GIB,
            graph_required_bytes: graph_required_gib.map(|value| value * GIB),
            metal: RuntimeMemoryProbe {
                recommended_working_set_size_bytes: recommended_working_set_gib
                    .map(|value| value * GIB),
                current_allocated_size_bytes: current_allocated_gib.map(|value| value * GIB),
            },
        }
    }

    #[test]
    fn unified_memory_headroom_uses_twenty_percent_or_eight_gib() {
        let host = host(48, 36, true, PressureLevel::Normal);
        let plan =
            compute_runtime_memory_plan(&host, input(620_000, 6, Some(8), Some(24), Some(4)));
        assert_eq!(plan.os_headroom_bytes, 9 * GIB + (3 * GIB) / 5);
        assert!(plan.execution_budget_bytes > 0);
        assert!(plan.runtime_pool_limit_bytes >= 512 * MIB);
    }

    #[test]
    fn non_unified_memory_headroom_uses_fifteen_percent_or_four_gib() {
        let host = host(32, 20, false, PressureLevel::Normal);
        let plan = compute_runtime_memory_plan(&host, input(120_000, 3, Some(4), None, None));
        assert_eq!(plan.os_headroom_bytes, 4 * GIB + (4 * GIB) / 5);
        assert!(plan.execution_budget_bytes >= GIB);
    }

    #[test]
    fn high_pressure_forces_low_memory_cpu_first_mode() {
        let host = host(48, 12, true, PressureLevel::High);
        let plan =
            compute_runtime_memory_plan(&host, input(620_000, 6, Some(8), Some(24), Some(10)));
        assert!(plan.low_memory_mode);
        assert!(plan.cpu_override_active);
        assert!(!plan.gpu_allowed);
        assert_eq!(plan.recommended_proving_threads, 1);
    }

    #[test]
    fn elevated_pressure_prefers_spill_when_projected_peak_exceeds_budget() {
        let host = host(16, 7, true, PressureLevel::Elevated);
        let plan =
            compute_runtime_memory_plan(&host, input(180_000, 4, Some(6), Some(10), Some(1)));
        assert!(plan.spill_preferred);
        assert!(plan.low_memory_mode);
    }

    #[test]
    fn headroom_gates_gpu_even_when_metal_is_available() {
        let host = host(48, 32, true, PressureLevel::Normal);
        let plan =
            compute_runtime_memory_plan(&host, input(200_000, 3, Some(4), Some(10), Some(8)));
        assert!(!plan.gpu_allowed);
    }
}
