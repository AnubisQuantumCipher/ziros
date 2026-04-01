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

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use zkf_backends::{backend_for_route, with_allow_dev_deterministic_groth16_override};
use zkf_core::artifact::BackendKind;
use zkf_core::witness::WitnessInputs;
use zkf_core::{FieldElement, FieldId};
use zkf_distributed::{
    ClusterConfig, DefaultGraphPartitioner, DiscoveryMethod, DistributedCoordinator,
    GraphPartitioner, NodeRole, PartitionStrategy, TransportPreference, WorkerService,
};
use zkf_runtime::adapters::emit_backend_prove_graph_with_context;
use zkf_runtime::memory::UnifiedBufferPool;
use zkf_runtime::{ExecutionMode, OptimizationObjective, RequiredTrustLane};

fn free_local_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn wait_for_listener(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("worker listener did not start on {addr}");
}

fn worker_config(bind_addr: SocketAddr) -> ClusterConfig {
    ClusterConfig {
        role: NodeRole::Worker,
        bind_addr,
        static_peers: Vec::new(),
        discovery: DiscoveryMethod::Static,
        transport: TransportPreference::Tcp,
        ..ClusterConfig::default()
    }
}

fn coordinator_config(peer_addr: SocketAddr) -> ClusterConfig {
    ClusterConfig {
        role: NodeRole::Coordinator,
        bind_addr: free_local_addr(),
        static_peers: vec![peer_addr],
        discovery: DiscoveryMethod::Static,
        transport: TransportPreference::Tcp,
        min_distribute_graph_nodes: 1,
        ..ClusterConfig::default()
    }
}

fn first_remote_partition_id(program: Arc<zkf_core::ir::Program>, inputs: WitnessInputs) -> u32 {
    let mut pool = UnifiedBufferPool::new(512 * 1024 * 1024);
    let emission = emit_backend_prove_graph_with_context(
        &mut pool,
        BackendKind::ArkworksGroth16,
        zkf_backends::BackendRoute::Auto,
        program,
        Some(Arc::new(inputs)),
        None,
        zkf_runtime::trust::TrustModel::Cryptographic,
        true,
    )
    .unwrap();
    DefaultGraphPartitioner::new()
        .partition(&emission.graph, PartitionStrategy::PhaseBoundary)
        .unwrap()
        .into_iter()
        .find(|partition| !partition.local_only)
        .expect("graph should produce at least one remote-capable partition")
        .partition_id
}

fn with_dev_groth16<T>(f: impl FnOnce() -> T) -> T {
    with_allow_dev_deterministic_groth16_override(Some(true), f)
}

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_file_swarm_keys<T>(f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let old_backend = std::env::var_os("ZKF_SWARM_KEY_BACKEND");
    let old_swarm = std::env::var_os("ZKF_SWARM");
    let old_policy = std::env::var_os("ZKF_SECURITY_POLICY_MODE");
    unsafe {
        std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        std::env::set_var("ZKF_SWARM", "1");
        std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
    }
    let result = f();
    unsafe {
        if let Some(value) = old_backend {
            std::env::set_var("ZKF_SWARM_KEY_BACKEND", value);
        } else {
            std::env::remove_var("ZKF_SWARM_KEY_BACKEND");
        }
        if let Some(value) = old_swarm {
            std::env::set_var("ZKF_SWARM", value);
        } else {
            std::env::remove_var("ZKF_SWARM");
        }
        if let Some(value) = old_policy {
            std::env::set_var("ZKF_SECURITY_POLICY_MODE", value);
        } else {
            std::env::remove_var("ZKF_SECURITY_POLICY_MODE");
        }
    }
    result
}

#[test]
fn loopback_distributed_backend_prove_returns_real_artifact() {
    with_file_swarm_keys(|| with_dev_groth16(|| {
        let worker_addr = free_local_addr();
        let mut worker = WorkerService::new(worker_config(worker_addr)).unwrap();
        let shutdown = worker.shutdown_handle();
        let worker_thread = thread::spawn(move || worker.run());
        wait_for_listener(worker_addr);

        let mut coordinator = DistributedCoordinator::new(coordinator_config(worker_addr)).unwrap();
        let program = Arc::new(zkf_examples::mul_add_program());
        let inputs: WitnessInputs = [
            ("x".to_string(), FieldElement::from_i64(7)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]
        .into_iter()
        .collect();

        let result = coordinator
            .prove_backend_job_distributed(
                BackendKind::ArkworksGroth16,
                zkf_backends::BackendRoute::Auto,
                Arc::clone(&program),
                Some(Arc::new(inputs)),
                None,
                None,
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .unwrap();

        assert!(result.report.peer_count <= 1);
        assert!(result.report.remote_partition_count <= result.report.partition_count);
        assert!(!result.report.node_traces.is_empty());
        assert!(!result.report.node_traces[0].trace_entries.is_empty());
        assert!(!result.artifact.proof.is_empty());

        let engine = backend_for_route(
            BackendKind::ArkworksGroth16,
            zkf_backends::BackendRoute::Auto,
        );
        let verified = engine.verify(&result.compiled, &result.artifact).unwrap();
        assert!(verified, "remote artifact should verify");

        shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(worker_addr);
        worker_thread
            .join()
            .expect("worker thread")
            .expect("worker run");
    }));
}

#[test]
fn loopback_distributed_backend_prove_survives_heartbeat_timeout_enforcement() {
    with_file_swarm_keys(|| with_dev_groth16(|| {
        let worker_addr = free_local_addr();
        let mut worker_cfg = worker_config(worker_addr);
        worker_cfg.heartbeat_interval = Duration::from_millis(5);
        worker_cfg.heartbeat_timeout = Duration::from_millis(50);
        let mut worker = WorkerService::new(worker_cfg).unwrap();
        let shutdown = worker.shutdown_handle();
        let worker_thread = thread::spawn(move || worker.run());
        wait_for_listener(worker_addr);

        let mut coordinator_cfg = coordinator_config(worker_addr);
        coordinator_cfg.heartbeat_interval = Duration::from_millis(5);
        coordinator_cfg.heartbeat_timeout = Duration::from_millis(50);
        let mut coordinator = DistributedCoordinator::new(coordinator_cfg).unwrap();
        let program = Arc::new(zkf_examples::recurrence_program(FieldId::Bn254, 512));
        let inputs: WitnessInputs = [
            ("x".to_string(), FieldElement::from_i64(7)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]
        .into_iter()
        .collect();

        let result = coordinator
            .prove_backend_job_distributed(
                BackendKind::ArkworksGroth16,
                zkf_backends::BackendRoute::Auto,
                Arc::clone(&program),
                Some(Arc::new(inputs)),
                None,
                None,
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .unwrap();

        assert!(result.report.remote_partition_count <= result.report.partition_count);
        assert!(!result.artifact.proof.is_empty());

        shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(worker_addr);
        worker_thread
            .join()
            .expect("worker thread")
            .expect("worker run");
    }));
}

#[test]
fn loopback_distributed_backend_prove_transfers_partition_boundaries() {
    with_file_swarm_keys(|| with_dev_groth16(|| {
        let worker_addr = free_local_addr();
        let mut worker = WorkerService::new(worker_config(worker_addr)).unwrap();
        let shutdown = worker.shutdown_handle();
        let worker_thread = thread::spawn(move || worker.run());
        wait_for_listener(worker_addr);

        let mut coordinator = DistributedCoordinator::new(coordinator_config(worker_addr)).unwrap();
        let program = Arc::new(zkf_examples::recurrence_program(FieldId::Bn254, 512));
        let inputs: WitnessInputs = [
            ("x".to_string(), FieldElement::from_i64(7)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]
        .into_iter()
        .collect();

        let result = coordinator
            .prove_backend_job_distributed(
                BackendKind::ArkworksGroth16,
                zkf_backends::BackendRoute::Auto,
                Arc::clone(&program),
                Some(Arc::new(inputs)),
                None,
                None,
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .unwrap();

        assert!(result.report.partition_count >= 1);
        assert!(result.report.remote_partition_count <= result.report.partition_count);
        if result.report.remote_partition_count > 0 {
            assert!(result.report.total_transfer_bytes > 0);
            assert!(!result.report.transfer_traces.is_empty());
            assert!(result.report.transfer_traces.iter().any(|trace| matches!(
                trace.direction,
                zkf_distributed::telemetry::TransferDirection::Send
            )));
        } else {
            assert_eq!(result.report.total_transfer_bytes, 0);
            assert!(result.report.transfer_traces.is_empty());
        }
        let has_gpu_trace = result
            .report
            .node_traces
            .iter()
            .flat_map(|trace| trace.trace_entries.iter())
            .any(|entry| entry.device == "gpu");
        #[cfg(target_os = "macos")]
        {
            if !zkf_runtime::create_metal_dispatch_driver(
                zkf_runtime::GpuVerificationMode::BestEffort,
            )
            .is_some_and(|driver| driver.is_available())
            {
                assert!(
                    !has_gpu_trace,
                    "worker must not claim GPU placements when Metal is unavailable"
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        assert!(
            !has_gpu_trace,
            "non-macOS distributed workers must not claim GPU placements"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(worker_addr);
        worker_thread
            .join()
            .expect("worker thread")
            .expect("worker run");
    }));
}

#[test]
fn loopback_distributed_backend_prove_retries_only_failed_partition_locally() {
    with_file_swarm_keys(|| with_dev_groth16(|| {
        let worker_addr = free_local_addr();
        let program = Arc::new(zkf_examples::recurrence_program(FieldId::Bn254, 512));
        let inputs: WitnessInputs = [
            ("x".to_string(), FieldElement::from_i64(7)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]
        .into_iter()
        .collect();
        let failed_partition_id = first_remote_partition_id(Arc::clone(&program), inputs.clone());
        let mut worker = WorkerService::new(worker_config(worker_addr)).unwrap();
        worker.inject_partition_failure_once(
            failed_partition_id,
            "forced partition failure for retry coverage",
        );
        let shutdown = worker.shutdown_handle();
        let worker_thread = thread::spawn(move || worker.run());
        wait_for_listener(worker_addr);

        let mut coordinator = DistributedCoordinator::new(coordinator_config(worker_addr)).unwrap();

        let result = coordinator
            .prove_backend_job_distributed(
                BackendKind::ArkworksGroth16,
                zkf_backends::BackendRoute::Auto,
                Arc::clone(&program),
                Some(Arc::new(inputs)),
                None,
                None,
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .unwrap();

        assert!(result.report.partition_count >= 1);
        assert!(result.report.fallback_partitions <= result.report.partition_count);
        assert_eq!(
            result.report.remote_partition_count + result.report.local_partition_count,
            result.report.partition_count
        );
        assert!(result.report.local_partition_count >= 1);
        let unique_partitions: BTreeSet<u32> = result
            .report
            .node_traces
            .iter()
            .map(|trace| trace.partition_id)
            .collect();
        assert_eq!(unique_partitions.len(), result.report.partition_count);
        assert!(!result.artifact.proof.is_empty());

        shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(worker_addr);
        worker_thread
            .join()
            .expect("worker thread")
            .expect("worker run");
    }));
}
