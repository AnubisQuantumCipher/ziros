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

use vstd::prelude::*;

verus! {

pub enum PlacementModel {
    Cpu,
    Gpu,
    CpuCrypto,
    CpuSme,
    Either,
}

pub open spec fn fail_closed_cpuish(placement: PlacementModel) -> PlacementModel {
    match placement {
        PlacementModel::Gpu | PlacementModel::Either => PlacementModel::Cpu,
        PlacementModel::CpuCrypto => PlacementModel::CpuCrypto,
        PlacementModel::CpuSme => PlacementModel::CpuSme,
        PlacementModel::Cpu => PlacementModel::Cpu,
    }
}

pub open spec fn resolve_placement(
    deterministic_mode: bool,
    node_deterministic: bool,
    swarm_emergency: bool,
    gpu_available: bool,
    memory_pressure_high: bool,
    has_plan_override: bool,
    plan_placement: PlacementModel,
    stage_gpu_capable: bool,
    device_pref: PlacementModel,
) -> PlacementModel {
    if deterministic_mode || node_deterministic {
        PlacementModel::Cpu
    } else if swarm_emergency {
        fail_closed_cpuish(device_pref)
    } else if !gpu_available || memory_pressure_high {
        fail_closed_cpuish(device_pref)
    } else if has_plan_override && stage_gpu_capable {
        plan_placement
    } else {
        device_pref
    }
}

pub open spec fn gpu_requested(
    placement: PlacementModel,
    driver_promotes_non_gpu: bool,
) -> bool {
    placement == PlacementModel::Gpu
        || (
            (placement == PlacementModel::Either
                || placement == PlacementModel::CpuCrypto
                || placement == PlacementModel::CpuSme)
                && driver_promotes_non_gpu
        )
}

pub open spec fn promote_gpu_placement(placement: PlacementModel) -> PlacementModel {
    if placement == PlacementModel::Either
        || placement == PlacementModel::CpuCrypto
        || placement == PlacementModel::CpuSme
    {
        PlacementModel::Gpu
    } else {
        placement
    }
}

pub open spec fn cpu_dispatch_required(
    placement: PlacementModel,
    dispatch_ok: bool,
) -> bool {
    (placement == PlacementModel::Cpu
        || placement == PlacementModel::CpuCrypto
        || placement == PlacementModel::CpuSme
        || placement == PlacementModel::Either) && !dispatch_ok
}

pub open spec fn verified_gpu_lane_allowed(
    verified_mode: bool,
    stage_gpu_capable: bool,
    stage_on_verified_whitelist: bool,
) -> bool {
    if verified_mode {
        stage_gpu_capable && stage_on_verified_whitelist
    } else {
        stage_gpu_capable
    }
}

pub open spec fn verified_gpu_plan_preserves_truth(
    gpu_stage_truth: bool,
    cpu_stage_truth: bool,
    gpu_lane_allowed: bool,
) -> bool {
    if gpu_lane_allowed {
        gpu_stage_truth
    } else {
        cpu_stage_truth
    }
}

pub struct ReportModel {
    pub gpu_nodes: int,
    pub cpu_nodes: int,
    pub fallback_nodes: int,
    pub delegated_nodes: int,
}

pub struct TraceModel {
    pub placement: PlacementModel,
    pub fell_back: bool,
    pub delegated: bool,
}

pub open spec fn next_report(report: ReportModel, trace: TraceModel) -> ReportModel {
    ReportModel {
        gpu_nodes: report.gpu_nodes + if trace.placement == PlacementModel::Gpu { 1int } else { 0int },
        cpu_nodes: report.cpu_nodes + if trace.placement == PlacementModel::Gpu { 0int } else { 1int },
        fallback_nodes: report.fallback_nodes + if trace.fell_back { 1int } else { 0int },
        delegated_nodes: report.delegated_nodes + if trace.delegated { 1int } else { 0int },
    }
}

pub proof fn runtime_scheduler_placement_resolution(
    deterministic_mode: bool,
    node_deterministic: bool,
    swarm_emergency: bool,
    gpu_available: bool,
    memory_pressure_high: bool,
    has_plan_override: bool,
    plan_placement: PlacementModel,
    stage_gpu_capable: bool,
    device_pref: PlacementModel,
)
    ensures
        (deterministic_mode || node_deterministic) ==> resolve_placement(
            deterministic_mode,
            node_deterministic,
            swarm_emergency,
            gpu_available,
            memory_pressure_high,
            has_plan_override,
            plan_placement,
            stage_gpu_capable,
            device_pref,
        ) == PlacementModel::Cpu,
        !(deterministic_mode || node_deterministic) && swarm_emergency ==> resolve_placement(
            deterministic_mode,
            node_deterministic,
            swarm_emergency,
            gpu_available,
            memory_pressure_high,
            has_plan_override,
            plan_placement,
            stage_gpu_capable,
            device_pref,
        ) == fail_closed_cpuish(device_pref),
        !(deterministic_mode || node_deterministic) && !swarm_emergency && gpu_available
            && !memory_pressure_high && has_plan_override && stage_gpu_capable ==> resolve_placement(
                deterministic_mode,
                node_deterministic,
                swarm_emergency,
                gpu_available,
                memory_pressure_high,
                has_plan_override,
                plan_placement,
                stage_gpu_capable,
                device_pref,
            ) == plan_placement,
{
}

pub proof fn runtime_scheduler_gpu_fallback_fail_closed(
    device_pref: PlacementModel,
    swarm_emergency: bool,
    gpu_available: bool,
    memory_pressure_high: bool,
)
    ensures
        fail_closed_cpuish(device_pref) != PlacementModel::Gpu,
        (swarm_emergency || !gpu_available || memory_pressure_high) ==> resolve_placement(
            false,
            false,
            swarm_emergency,
            gpu_available,
            memory_pressure_high,
            false,
            PlacementModel::Cpu,
            false,
            device_pref,
        ) != PlacementModel::Gpu,
{
}

pub proof fn runtime_scheduler_trace_accounting(
    report: ReportModel,
    trace: TraceModel,
)
    requires
        report.gpu_nodes >= 0,
        report.cpu_nodes >= 0,
        report.fallback_nodes >= 0,
        report.delegated_nodes >= 0,
        report.fallback_nodes <= report.gpu_nodes + report.cpu_nodes,
        report.delegated_nodes <= report.gpu_nodes + report.cpu_nodes,
    ensures
        next_report(report, trace).gpu_nodes >= report.gpu_nodes,
        next_report(report, trace).cpu_nodes >= report.cpu_nodes,
        next_report(report, trace).fallback_nodes >= report.fallback_nodes,
        next_report(report, trace).delegated_nodes >= report.delegated_nodes,
        next_report(report, trace).fallback_nodes <= next_report(report, trace).gpu_nodes + next_report(report, trace).cpu_nodes,
        next_report(report, trace).delegated_nodes <= next_report(report, trace).gpu_nodes + next_report(report, trace).cpu_nodes,
{
}

pub proof fn gpu_runtime_fail_closed(
    verified_mode: bool,
    gpu_available: bool,
    stage_gpu_capable: bool,
    stage_on_verified_whitelist: bool,
)
    ensures
        verified_mode && (!stage_gpu_capable || !stage_on_verified_whitelist) ==> !verified_gpu_lane_allowed(
            verified_mode,
            stage_gpu_capable,
            stage_on_verified_whitelist,
        ),
        verified_mode && !gpu_available ==> fail_closed_cpuish(PlacementModel::Gpu) != PlacementModel::Gpu,
{
}

pub proof fn gpu_cpu_gpu_partition_equivalence(
    verified_mode: bool,
    gpu_stage_truth: bool,
    cpu_stage_truth: bool,
    stage_gpu_capable: bool,
    stage_on_verified_whitelist: bool,
)
    requires
        !verified_mode ==> (gpu_stage_truth == cpu_stage_truth),
        verified_mode ==> (gpu_stage_truth == cpu_stage_truth),
    ensures
        verified_gpu_plan_preserves_truth(
            gpu_stage_truth,
            cpu_stage_truth,
            verified_gpu_lane_allowed(
                verified_mode,
                stage_gpu_capable,
                stage_on_verified_whitelist,
            ),
        ) == cpu_stage_truth,
{
}

} // verus!
