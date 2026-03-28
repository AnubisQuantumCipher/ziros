#![allow(unexpected_cfgs)]

//! ZKF Distributed — TCP-based multi-node proving offload.
//!
//! Production distributed proving currently uses postcard-encoded execution
//! bundles over TCP. Experimental RDMA and feature-gated discovery backends are
//! explicitly fail-closed until they have real implementations.
//!
//! **Cardinal rule**: Distributed acceleration never affects proof correctness.
//! `ZKF_DISTRIBUTED=0` disables everything. Proofs are bit-identical to
//! single-node execution.
//!
//! ## Kill switch
//!
//! Set `ZKF_DISTRIBUTED=0` to disable all distributed proving. When disabled,
//! [`is_enabled`] returns `false` and the coordinator falls back to local
//! execution via `DeterministicScheduler`.

#[cfg(all(feature = "full", not(hax)))]
pub mod bundle;
#[cfg(not(hax))]
pub mod config;
#[cfg(all(feature = "full", not(hax)))]
pub mod coordinator;
#[cfg(all(feature = "full", not(hax)))]
pub mod discovery;
#[cfg(not(hax))]
pub mod error;
#[cfg(all(feature = "full", not(hax)))]
mod execution;
#[cfg(all(feature = "full", not(hax)))]
pub mod health;
#[cfg(not(hax))]
pub mod identity;
#[cfg(all(feature = "full", not(hax)))]
pub mod partition;
pub(crate) mod proof_swarm_reputation_spec;
#[cfg(not(hax))]
pub mod protocol;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_consensus_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_coordinator_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_diplomat_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_epoch_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_identity_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_memory_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_protocol_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_reputation_core;
#[cfg(all(feature = "full", not(hax)))]
pub(crate) mod swarm_transport_core;
#[cfg(all(feature = "full", not(hax)))]
pub mod swarm;
#[cfg(all(feature = "full", not(hax)))]
pub mod telemetry;
#[cfg(not(hax))]
pub mod transfer;
#[cfg(not(hax))]
pub mod transport;
#[cfg(kani)]
mod verification_kani;
#[cfg(all(feature = "full", not(hax)))]
pub mod worker;

// ─── Top-level re-exports ────────────────────────────────────────────────

#[cfg(not(hax))]
pub use config::{ClusterConfig, DiscoveryMethod, NodeRole, TransportPreference};
#[cfg(all(feature = "full", not(hax)))]
pub use coordinator::{
    ClusterPeerReport, ClusterStatusReport, DistributedBackendProofResult, DistributedCoordinator,
};
#[cfg(not(hax))]
pub use error::DistributedError;
#[cfg(not(hax))]
pub use identity::{NodeCapability, PeerId, PeerState};
#[cfg(all(feature = "full", not(hax)))]
pub use partition::strategy::PartitionStrategy;
#[cfg(all(feature = "full", not(hax)))]
pub use partition::{DefaultGraphPartitioner, GraphPartition, GraphPartitioner};
#[cfg(not(hax))]
pub use protocol::{MessageBody, WireMessage};
#[cfg(all(feature = "full", not(hax)))]
pub use swarm::{
    ConsensusCollector, Diplomat, FileBackend, KeyStorageBackend, LocalPeerIdentity,
    MlDsaKeyProvenance, PeerReputation, PublicKeyBundle, ReputationEvent, ReputationEvidence,
    ReputationEvidenceKind, ReputationTracker, ReputationVerificationReport, SecureEnclaveBackend,
    SignatureBundle, SignatureScheme, load_reputation_events, load_reputation_events_for,
    load_reputation_score_for, load_reputation_scores, local_identity_label, verify_reputation_log,
    verify_reputation_log_report,
};
#[cfg(all(feature = "full", not(hax)))]
pub use telemetry::DistributedExecutionReport;
#[cfg(not(hax))]
pub use transfer::BufferTransferManager;
#[cfg(not(hax))]
pub use transport::{Connection, Listener, Transport};
#[cfg(all(feature = "full", not(hax)))]
pub use worker::WorkerService;

/// Check whether distributed proving is enabled.
///
/// Returns `false` if `ZKF_DISTRIBUTED=0`.
#[cfg(not(hax))]
pub fn is_enabled() -> bool {
    ClusterConfig::is_enabled()
}

#[cfg(all(test, not(hax)))]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_function_works() {
        // Just verify is_enabled() doesn't panic.
        let _ = is_enabled();
    }

    #[test]
    fn default_config_roundtrip() {
        let cfg = ClusterConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: ClusterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.role, cfg.role);
        assert_eq!(decoded.bind_addr, cfg.bind_addr);
    }

    #[test]
    fn peer_id_display() {
        let id = PeerId("test-node-1".into());
        assert_eq!(format!("{id}"), "test-node-1");
    }
}
