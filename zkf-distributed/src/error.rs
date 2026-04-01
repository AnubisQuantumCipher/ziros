//! Distributed proving error types.

use thiserror::Error;
#[cfg(feature = "full")]
use zkf_runtime::error::RuntimeError;

#[derive(Debug, Error)]
pub enum DistributedError {
    #[error("distributed proving is disabled (ZKF_DISTRIBUTED=0)")]
    Disabled,

    #[error("no peers available for distributed proving")]
    NoPeersAvailable,

    #[error("peer {peer_id} unreachable: {reason}")]
    PeerUnreachable { peer_id: String, reason: String },

    #[error("peer {peer_id} rejected assignment: {reason}")]
    PeerRejected { peer_id: String, reason: String },

    #[error("peer {peer_id} execution failed: {reason}")]
    PeerExecutionFailed { peer_id: String, reason: String },

    #[error("graph partitioning failed: {reason}")]
    PartitionFailed { reason: String },

    #[error("buffer transfer failed for slot {slot}: {reason}")]
    TransferFailed { slot: u32, reason: String },

    #[error("integrity check failed for slot {slot}: expected {expected}, got {actual}")]
    IntegrityFailed {
        slot: u32,
        expected: String,
        actual: String,
    },

    #[error("handshake failed with peer {peer_id}: {reason}")]
    HandshakeFailed { peer_id: String, reason: String },

    #[error("protocol version mismatch: local={local}, remote={remote}")]
    ProtocolVersionMismatch { local: u32, remote: u32 },

    #[error("timeout communicating with peer {peer_id} during {operation}")]
    Timeout { peer_id: String, operation: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error("configuration error: {0}")]
    Config(String),
}

impl From<std::io::Error> for DistributedError {
    fn from(e: std::io::Error) -> Self {
        DistributedError::Io(e.to_string())
    }
}

#[cfg(feature = "full")]
impl From<RuntimeError> for DistributedError {
    fn from(e: RuntimeError) -> Self {
        DistributedError::Runtime(e.to_string())
    }
}

impl From<postcard::Error> for DistributedError {
    fn from(e: postcard::Error) -> Self {
        DistributedError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for DistributedError {
    fn from(e: serde_json::Error) -> Self {
        DistributedError::Serialization(e.to_string())
    }
}
