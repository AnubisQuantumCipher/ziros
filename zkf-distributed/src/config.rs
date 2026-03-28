//! Cluster configuration from environment variables and defaults.

use crate::error::DistributedError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Role this node plays in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Coordinator,
    Worker,
    Auto,
}

/// How peers are discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryMethod {
    Mdns,
    Static,
    Manual,
}

/// Preferred transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportPreference {
    Tcp,
    PreferRdma,
    RdmaOnly,
}

/// Integrity check algorithm for buffer transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityAlgorithm {
    Fnv,
    Sha256,
}

/// Full cluster configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub role: NodeRole,
    pub bind_addr: SocketAddr,
    pub static_peers: Vec<SocketAddr>,
    pub discovery: DiscoveryMethod,
    pub transport: TransportPreference,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub transfer_chunk_bytes: usize,
    pub max_concurrent_transfers: usize,
    pub compress_transfers: bool,
    pub integrity_algorithm: IntegrityAlgorithm,
    pub min_distribute_buffer_bytes: usize,
    pub min_distribute_graph_nodes: usize,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            role: NodeRole::Auto,
            bind_addr: "0.0.0.0:9471".parse().expect("valid default bind addr"),
            static_peers: Vec::new(),
            discovery: DiscoveryMethod::Static,
            transport: TransportPreference::Tcp,
            heartbeat_interval: Duration::from_secs(2),
            heartbeat_timeout: Duration::from_secs(10),
            transfer_chunk_bytes: 4 * 1024 * 1024, // 4 MiB
            max_concurrent_transfers: 4,
            compress_transfers: true,
            integrity_algorithm: IntegrityAlgorithm::Fnv,
            min_distribute_buffer_bytes: 64 * 1024, // 64 KiB
            min_distribute_graph_nodes: 8,
        }
    }
}

impl ClusterConfig {
    /// Check the kill switch: `ZKF_DISTRIBUTED=0` disables everything.
    pub fn is_enabled() -> bool {
        match std::env::var("ZKF_DISTRIBUTED") {
            Ok(v) => v != "0",
            Err(_) => true,
        }
    }

    /// Build config from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, DistributedError> {
        let mut cfg = Self::default();

        if let Ok(role) = std::env::var("ZKF_DISTRIBUTED_ROLE") {
            cfg.role = match role.to_lowercase().as_str() {
                "coordinator" => NodeRole::Coordinator,
                "worker" => NodeRole::Worker,
                "auto" => NodeRole::Auto,
                other => {
                    return Err(DistributedError::Config(format!("unknown role: {other}")));
                }
            };
        }

        if let Ok(bind) = std::env::var("ZKF_DISTRIBUTED_BIND") {
            cfg.bind_addr = bind
                .parse()
                .map_err(|e| DistributedError::Config(format!("invalid bind addr: {e}")))?;
        }

        if let Ok(peers) = std::env::var("ZKF_DISTRIBUTED_PEERS") {
            cfg.static_peers = peers
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.trim().parse().map_err(|e| {
                        DistributedError::Config(format!("invalid peer addr '{s}': {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        }

        if let Ok(disc) = std::env::var("ZKF_DISTRIBUTED_DISCOVERY") {
            cfg.discovery = match disc.to_lowercase().as_str() {
                "mdns" => DiscoveryMethod::Mdns,
                "static" => DiscoveryMethod::Static,
                "manual" => DiscoveryMethod::Manual,
                other => {
                    return Err(DistributedError::Config(format!(
                        "unknown discovery method: {other}"
                    )));
                }
            };
        }

        if let Ok(t) = std::env::var("ZKF_DISTRIBUTED_TRANSPORT") {
            cfg.transport = match t.to_lowercase().as_str() {
                "tcp" => TransportPreference::Tcp,
                "prefer-rdma" => TransportPreference::PreferRdma,
                "rdma-only" => TransportPreference::RdmaOnly,
                other => {
                    return Err(DistributedError::Config(format!(
                        "unknown transport: {other}"
                    )));
                }
            };
        }

        if let Ok(c) = std::env::var("ZKF_DISTRIBUTED_COMPRESS") {
            cfg.compress_transfers = c != "0";
        }

        if let Ok(i) = std::env::var("ZKF_DISTRIBUTED_INTEGRITY") {
            cfg.integrity_algorithm = match i.to_lowercase().as_str() {
                "fnv" => IntegrityAlgorithm::Fnv,
                "sha256" => IntegrityAlgorithm::Sha256,
                other => {
                    return Err(DistributedError::Config(format!(
                        "unknown integrity algorithm: {other}"
                    )));
                }
            };
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = ClusterConfig::default();
        assert_eq!(cfg.role, NodeRole::Auto);
        assert_eq!(cfg.bind_addr.port(), 9471);
        assert!(cfg.static_peers.is_empty());
        assert_eq!(cfg.transfer_chunk_bytes, 4 * 1024 * 1024);
        assert!(cfg.compress_transfers);
    }

    #[test]
    fn kill_switch_respects_env() {
        // With no env var set, distributed is enabled by default.
        // We don't modify env in tests to avoid races; just test the logic.
        assert!(
            ClusterConfig::is_enabled()
                || std::env::var("ZKF_DISTRIBUTED").ok().as_deref() == Some("0")
        );
    }
}
