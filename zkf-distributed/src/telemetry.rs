//! Distributed execution telemetry and reporting.

use crate::identity::PeerId;
use crate::protocol::SubgraphTraceEntry;
use serde::Serialize;
use std::time::Duration;

/// Per-node execution summary within a distributed job.
#[derive(Debug, Clone, Serialize)]
pub struct DistributedNodeTrace {
    pub peer_id: PeerId,
    pub partition_id: u32,
    pub wall_time: Duration,
    pub node_count: usize,
    pub trace_entries: Vec<SubgraphTraceEntry>,
}

/// Network transfer telemetry for a single buffer slot.
#[derive(Debug, Clone, Serialize)]
pub struct TransferTrace {
    pub slot: u32,
    pub direction: TransferDirection,
    pub peer_id: PeerId,
    pub total_bytes: usize,
    pub compressed_bytes: Option<usize>,
    pub wall_time: Duration,
    pub throughput_gbps: f64,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferDirection {
    Send,
    Recv,
}

/// Complete report for a distributed proving execution.
#[derive(Debug, Clone, Serialize)]
pub struct DistributedExecutionReport {
    pub job_id: String,
    pub total_wall_time: Duration,
    pub partition_count: usize,
    pub remote_partition_count: usize,
    pub local_partition_count: usize,
    pub peer_count: usize,
    pub node_traces: Vec<DistributedNodeTrace>,
    pub transfer_traces: Vec<TransferTrace>,
    pub total_transfer_bytes: usize,
    pub total_compute_wall_time: Duration,
    pub total_transfer_wall_time: Duration,
    pub fallback_partitions: usize,
    pub distribution_profitable: bool,
    pub speedup_ratio: f64,
}

impl DistributedExecutionReport {
    /// Create an empty report for a job that fell back to local execution.
    pub fn local_fallback(job_id: String, wall_time: Duration) -> Self {
        Self {
            job_id,
            total_wall_time: wall_time,
            partition_count: 1,
            remote_partition_count: 0,
            local_partition_count: 1,
            peer_count: 0,
            node_traces: Vec::new(),
            transfer_traces: Vec::new(),
            total_transfer_bytes: 0,
            total_compute_wall_time: wall_time,
            total_transfer_wall_time: Duration::ZERO,
            fallback_partitions: 0,
            distribution_profitable: false,
            speedup_ratio: 1.0,
        }
    }
}
