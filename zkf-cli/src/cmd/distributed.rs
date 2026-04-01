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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use zkf_backends::backend_for_route;
use zkf_core::FieldElement;
use zkf_core::artifact::BackendKind;
use zkf_core::witness::WitnessInputs;
use zkf_distributed::{ClusterConfig, DistributedCoordinator, WorkerService};
use zkf_runtime::{ExecutionMode, OptimizationObjective, RequiredTrustLane};

use crate::util::write_json;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DistributedBenchmarkRun {
    pub backend: BackendKind,
    pub iteration: usize,
    pub remote_partition_count: usize,
    pub peer_count: usize,
    pub total_wall_time_ms: f64,
    pub proof_size_bytes: usize,
    pub public_inputs: usize,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DistributedBenchmarkReport {
    pub generated_unix_ms: u128,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_note: Option<String>,
    pub peer_count: usize,
    pub iterations: usize,
    pub runs: Vec<DistributedBenchmarkRun>,
    pub notes: Vec<String>,
}

pub(crate) fn handle_cluster_start(json: bool) -> Result<(), String> {
    let config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let mut worker = WorkerService::new(config.clone()).map_err(|err| err.to_string())?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "listening",
                "role": format!("{:?}", config.role).to_lowercase(),
                "bind_addr": config.bind_addr,
                "transport": worker.transport_name(),
                "transport_note": worker.transport_note(),
            })
        );
    } else {
        println!(
            "distributed worker listening on {} via {}",
            config.bind_addr,
            worker.transport_name()
        );
        if let Some(note) = worker.transport_note() {
            println!("{note}");
        }
    }

    worker.run().map_err(|err| err.to_string())
}

pub(crate) fn handle_cluster_status(json: bool) -> Result<(), String> {
    let config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let mut coordinator = DistributedCoordinator::new(config).map_err(|err| err.to_string())?;
    let status = coordinator.status().map_err(|err| err.to_string())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(|err| err.to_string())?
        );
        return Ok(());
    }

    println!(
        "cluster status: transport={} discovery={} peers={}",
        status.transport, status.discovery, status.peer_count
    );
    if let Some(note) = status.transport_note.as_deref() {
        println!("{note}");
    }
    for peer in status.peers {
        println!(
            "{} {} gpu={} avail_mem={}MiB proto={} swarm={} activation={} reputation={:.2}",
            peer.peer_id,
            peer.addr,
            peer.gpu_available,
            peer.available_memory_bytes / (1024 * 1024),
            peer.protocol_version,
            peer.swarm_capable,
            peer.swarm_activation_level,
            peer.reputation
        );
    }
    Ok(())
}

pub(crate) fn handle_cluster_benchmark(out: Option<PathBuf>, json: bool) -> Result<(), String> {
    let report = run_distributed_benchmark(vec![BackendKind::ArkworksGroth16], 1, false)?;

    if let Some(path) = out.as_ref() {
        write_json(path, &report)?;
        if !json {
            println!("wrote distributed benchmark report: {}", path.display());
        }
    }

    if json || out.is_none() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "distributed benchmark completed: runs={} peers={}",
            report.runs.len(),
            report.peer_count
        );
    }

    Ok(())
}

pub(crate) fn handle_distributed_benchmark(
    out: PathBuf,
    markdown_out: Option<PathBuf>,
    backends: Vec<BackendKind>,
    iterations: usize,
    continue_on_error: bool,
) -> Result<(), String> {
    let report = run_distributed_benchmark(backends, iterations, continue_on_error)?;
    write_json(&out, &report)?;
    if let Some(markdown_path) = markdown_out {
        std::fs::write(&markdown_path, render_markdown(&report))
            .map_err(|err| format!("{}: {err}", markdown_path.display()))?;
    }
    println!(
        "distributed benchmark completed for {} runs -> {}",
        report.runs.len(),
        out.display()
    );
    Ok(())
}

fn run_distributed_benchmark(
    backends: Vec<BackendKind>,
    iterations: usize,
    continue_on_error: bool,
) -> Result<DistributedBenchmarkReport, String> {
    if backends.is_empty() {
        return Err("distributed benchmark requires at least one backend".into());
    }
    if iterations == 0 {
        return Err("distributed benchmark iterations must be >= 1".into());
    }

    let config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let mut coordinator = DistributedCoordinator::new(config).map_err(|err| err.to_string())?;
    let status = coordinator.status().map_err(|err| err.to_string())?;
    let mut runs = Vec::new();
    let mut notes = Vec::new();

    for backend in backends {
        for iteration in 0..iterations {
            match benchmark_one_backend(&mut coordinator, backend) {
                Ok(run) => runs.push(DistributedBenchmarkRun { iteration, ..run }),
                Err(err) if continue_on_error => notes.push(format!(
                    "backend {} iteration {} failed: {err}",
                    backend.as_str(),
                    iteration
                )),
                Err(err) => return Err(err),
            }
        }
    }

    Ok(DistributedBenchmarkReport {
        generated_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        transport: status.transport,
        transport_note: status.transport_note,
        peer_count: status.peer_count,
        iterations,
        runs,
        notes,
    })
}

fn benchmark_one_backend(
    coordinator: &mut DistributedCoordinator,
    backend: BackendKind,
) -> Result<DistributedBenchmarkRun, String> {
    let program = Arc::new(zkf_examples::mul_add_program());
    let inputs: WitnessInputs = [
        ("x".to_string(), FieldElement::from_i64(5)),
        ("y".to_string(), FieldElement::from_i64(8)),
    ]
    .into_iter()
    .collect();
    let result = coordinator
        .prove_backend_job_distributed(
            backend,
            zkf_backends::BackendRoute::Auto,
            Arc::clone(&program),
            Some(Arc::new(inputs)),
            None,
            None,
            OptimizationObjective::FastestProve,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map_err(|err| err.to_string())?;

    let engine = backend_for_route(backend, zkf_backends::BackendRoute::Auto);
    let verified = engine
        .verify(&result.compiled, &result.artifact)
        .map_err(crate::util::render_zkf_error)?;

    Ok(DistributedBenchmarkRun {
        backend,
        iteration: 0,
        remote_partition_count: result.report.remote_partition_count,
        peer_count: result.report.peer_count,
        total_wall_time_ms: result.report.total_wall_time.as_secs_f64() * 1000.0,
        proof_size_bytes: result.artifact.proof.len(),
        public_inputs: result.artifact.public_inputs.len(),
        verified,
    })
}

fn render_markdown(report: &DistributedBenchmarkReport) -> String {
    let mut out = String::from(
        "| backend | iteration | remote partitions | peers | wall ms | proof bytes | verified |\n",
    );
    out.push_str("|---|---:|---:|---:|---:|---:|---|\n");
    for run in &report.runs {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {:.2} | {} | {} |\n",
            run.backend.as_str(),
            run.iteration,
            run.remote_partition_count,
            run.peer_count,
            run.total_wall_time_ms,
            run.proof_size_bytes,
            run.verified
        ));
    }
    out
}
