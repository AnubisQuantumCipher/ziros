//! Wire protocol: message envelope and all body variants.

use crate::identity::{NodeCapability, PeerId, PressureLevel};
use serde::{Deserialize, Serialize};

#[cfg(feature = "full")]
use crate::swarm::{PublicKeyBundle, SignatureBundle};

/// Wire message envelope wrapping all protocol communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub version: u32,
    pub sender: PeerId,
    pub sequence: u64,
    pub body: MessageBody,
}

/// All protocol message variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageBody {
    // ── Connection ──
    Handshake(HandshakeMsg),
    HandshakeAck(HandshakeAckMsg),

    // ── Health ──
    Heartbeat(HeartbeatMsg),
    HeartbeatAck(HeartbeatAckMsg),
    ThreatGossip(ThreatGossipMsg),
    ReputationSync(ReputationSyncMsg),
    ConsensusVote(ConsensusVoteMsg),
    ConsensusResult(ConsensusResultMsg),
    AttestationChain(AttestationChainMsg),

    // ── Assignment ──
    AssignSubgraph(AssignSubgraphMsg),
    AssignAck(AssignAckMsg),

    // ── Transfer ──
    TransferRequest(TransferRequestMsg),
    TransferChunk(TransferChunkMsg),
    TransferComplete(TransferCompleteMsg),
    TransferAck(TransferAckMsg),

    // ── Execution ──
    ExecuteSubgraph(ExecuteSubgraphMsg),
    SubgraphResult(SubgraphResultMsg),
    SubgraphFailed(SubgraphFailedMsg),

    // ── Job lifecycle ──
    JobComplete(JobCompleteMsg),
    JobAbort(JobAbortMsg),
}

// ─── Handshake ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMsg {
    pub capability: NodeCapability,
    #[serde(default)]
    pub ed25519_public_key: Vec<u8>,
    #[serde(default)]
    pub handshake_signature: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub public_key_bundle: Option<PublicKeyBundle>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub handshake_signature_bundle: Option<SignatureBundle>,
    #[serde(default)]
    pub swarm_protocol_version: u32,
    #[serde(default)]
    pub admission_pow_nonce: Option<u64>,
    #[serde(default)]
    pub encrypted_threat_gossip_supported: bool,
    #[serde(default)]
    pub threat_epoch_id: Option<u64>,
    #[serde(default)]
    pub threat_epoch_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAckMsg {
    pub capability: NodeCapability,
    pub accepted: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub ed25519_public_key: Vec<u8>,
    #[serde(default)]
    pub handshake_signature: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub public_key_bundle: Option<PublicKeyBundle>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub handshake_signature_bundle: Option<SignatureBundle>,
    #[serde(default)]
    pub swarm_protocol_version: u32,
    #[serde(default)]
    pub encrypted_threat_gossip_supported: bool,
    #[serde(default)]
    pub threat_epoch_id: Option<u64>,
    #[serde(default)]
    pub threat_epoch_public_key: Option<Vec<u8>>,
}

// ─── Heartbeat ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    pub pressure: PressureLevel,
    pub active_subgraph_count: u32,
    pub current_buffer_bytes: u64,
    #[serde(default)]
    pub encrypted_threat_gossip_supported: bool,
    #[serde(default)]
    pub threat_epoch_id: Option<u64>,
    #[serde(default)]
    pub threat_epoch_public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub threat_digests: Vec<ThreatDigestMsg>,
    #[serde(default)]
    pub activation_level: Option<u8>,
    #[serde(default)]
    pub intelligence_root: Option<String>,
    #[serde(default)]
    pub local_pressure: Option<f64>,
    #[serde(default)]
    pub network_pressure: Option<f64>,
    #[serde(default)]
    pub encrypted_threat_payload: Option<EncryptedThreatEnvelopeMsg>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub signature_bundle: Option<SignatureBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAckMsg {
    pub acknowledged: bool,
    #[serde(default)]
    pub encrypted_threat_gossip_supported: bool,
    #[serde(default)]
    pub threat_epoch_id: Option<u64>,
    #[serde(default)]
    pub threat_epoch_public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub threat_digests: Vec<ThreatDigestMsg>,
    #[serde(default)]
    pub activation_level: Option<u8>,
    #[serde(default)]
    pub intelligence_root: Option<String>,
    #[serde(default)]
    pub local_pressure: Option<f64>,
    #[serde(default)]
    pub network_pressure: Option<f64>,
    #[serde(default)]
    pub encrypted_threat_payload: Option<EncryptedThreatEnvelopeMsg>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub signature_bundle: Option<SignatureBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EncryptedThreatEnvelopeMsg {
    pub epoch_id: u64,
    pub nonce: [u8; 12],
    #[serde(default)]
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub payload_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ThreatDigestMsg {
    pub source_peer: [u8; 32],
    #[serde(default)]
    pub source_peer_id: Option<String>,
    pub timestamp_unix_ms: u64,
    pub stage_key_hash: u64,
    #[serde(default)]
    pub stage_key: Option<String>,
    pub severity: String,
    #[serde(default)]
    pub kind: String,
    pub z_score: f32,
    pub observation_count: u32,
    #[serde(default)]
    pub signature: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub signature_bundle: Option<SignatureBundle>,
    #[serde(default)]
    pub baseline_commitment: Option<String>,
    #[serde(default)]
    pub execution_fingerprint: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatGossipMsg {
    #[serde(default)]
    pub digests: Vec<ThreatDigestMsg>,
    #[serde(default)]
    pub activation_level: Option<u8>,
    #[serde(default)]
    pub intelligence_root: Option<String>,
    #[serde(default)]
    pub local_pressure: Option<f64>,
    #[serde(default)]
    pub network_pressure: Option<f64>,
    #[serde(default)]
    pub encrypted_threat_payload: Option<EncryptedThreatEnvelopeMsg>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationRecordMsg {
    pub peer_id: String,
    pub score: f64,
    pub evidence: String,
    pub recorded_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationSyncMsg {
    #[serde(default)]
    pub records: Vec<ReputationRecordMsg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVoteMsg {
    pub job_id: String,
    pub partition_id: u32,
    pub voter_peer_id: String,
    pub severity: String,
    pub accepted: bool,
    pub output_digest: [u8; 32],
    pub recorded_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResultMsg {
    pub job_id: String,
    pub partition_id: u32,
    pub accepted: bool,
    pub severity: String,
    #[serde(default)]
    pub agreeing_peers: Vec<String>,
    #[serde(default)]
    pub disagreeing_peers: Vec<String>,
    pub decided_unix_ms: u128,
}

// ─── Assignment ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignSubgraphMsg {
    pub job_id: String,
    pub partition_id: u32,
    /// Serialized subgraph (postcard-encoded ProverGraph subset).
    pub subgraph_data: Vec<u8>,
    /// Input boundary slots this partition needs to receive.
    pub input_boundary_slots: Vec<(u32, usize)>,
    /// Output boundary slots this partition should send back.
    pub output_boundary_slots: Vec<(u32, usize)>,
    pub estimated_work: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignAckMsg {
    pub job_id: String,
    pub partition_id: u32,
    pub accepted: bool,
    pub reason: Option<String>,
}

// ─── Transfer ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequestMsg {
    pub job_id: String,
    pub slot: u32,
    pub total_bytes: usize,
    pub chunk_count: u32,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferChunkMsg {
    pub job_id: String,
    pub slot: u32,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    /// Integrity digest for this chunk (FNV or SHA-256, per config).
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompleteMsg {
    pub job_id: String,
    pub slot: u32,
    pub total_digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferAckMsg {
    pub job_id: String,
    pub slot: u32,
    pub accepted: bool,
    pub reason: Option<String>,
}

// ─── Execution ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteSubgraphMsg {
    pub job_id: String,
    pub partition_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgraphResultMsg {
    pub job_id: String,
    pub partition_id: u32,
    /// Serialized output buffers.
    pub output_data: Vec<(u32, Vec<u8>)>,
    /// Named runtime outputs materialized by the worker execution context.
    pub named_outputs: Vec<(String, Vec<u8>)>,
    /// Serialized `CompiledProgram` produced by the worker, when applicable.
    pub compiled_program: Option<Vec<u8>>,
    /// Serialized `ProofArtifact` produced by the worker, when applicable.
    pub proof_artifact: Option<Vec<u8>>,
    /// Execution wall time in milliseconds.
    pub wall_time_ms: u64,
    /// Per-node trace summaries.
    pub trace_entries: Vec<SubgraphTraceEntry>,
    /// Final trust model realized by the worker.
    pub final_trust_model: Option<String>,
    /// Peak resident memory observed during execution.
    pub peak_memory_bytes: Option<u64>,
    /// Optional swarm attestation material for the hot path.
    #[serde(default)]
    pub attestation: Option<AttestationMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgraphTraceEntry {
    pub node_name: String,
    pub wall_time_ms: u64,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgraphFailedMsg {
    pub job_id: String,
    pub partition_id: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMetadata {
    pub signer_peer_id: String,
    #[serde(default)]
    pub public_key: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub public_key_bundle: Option<PublicKeyBundle>,
    pub output_digest: [u8; 32],
    pub trace_digest: [u8; 32],
    #[serde(default)]
    pub signature: Vec<u8>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub signature_bundle: Option<SignatureBundle>,
    #[serde(default)]
    pub activation_level: Option<u8>,
}

#[cfg(feature = "full")]
pub fn heartbeat_signing_bytes(heartbeat: &HeartbeatMsg) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + heartbeat.threat_digests.len() * 96);
    bytes.push(match heartbeat.pressure {
        PressureLevel::Normal => 0,
        PressureLevel::Warning => 1,
        PressureLevel::Critical => 2,
    });
    bytes.extend_from_slice(&heartbeat.active_subgraph_count.to_le_bytes());
    bytes.extend_from_slice(&heartbeat.current_buffer_bytes.to_le_bytes());
    append_threat_epoch_advertisement_bytes(
        &mut bytes,
        heartbeat.encrypted_threat_gossip_supported,
        heartbeat.threat_epoch_id,
        heartbeat.threat_epoch_public_key.as_deref(),
    );
    bytes.push(heartbeat.activation_level.unwrap_or_default());
    if let Some(root) = &heartbeat.intelligence_root {
        bytes.extend_from_slice(&(root.len() as u32).to_le_bytes());
        bytes.extend_from_slice(root.as_bytes());
    } else {
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.extend_from_slice(&heartbeat.local_pressure.unwrap_or_default().to_le_bytes());
    bytes.extend_from_slice(&heartbeat.network_pressure.unwrap_or_default().to_le_bytes());
    bytes.extend_from_slice(&(heartbeat.threat_digests.len() as u32).to_le_bytes());
    for digest in &heartbeat.threat_digests {
        bytes.extend_from_slice(&digest.source_peer);
        if let Some(source_peer_id) = &digest.source_peer_id {
            bytes.extend_from_slice(&(source_peer_id.len() as u32).to_le_bytes());
            bytes.extend_from_slice(source_peer_id.as_bytes());
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes.extend_from_slice(&digest.timestamp_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&digest.stage_key_hash.to_le_bytes());
        if let Some(stage_key) = &digest.stage_key {
            bytes.extend_from_slice(&(stage_key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(stage_key.as_bytes());
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes.extend_from_slice(&digest.z_score.to_le_bytes());
        bytes.extend_from_slice(&digest.observation_count.to_le_bytes());
        bytes.extend_from_slice(digest.severity.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.kind.as_bytes());
        bytes.push(0);
    }
    append_encrypted_threat_envelope_bytes(&mut bytes, heartbeat.encrypted_threat_payload.as_ref());
    bytes
}

#[cfg(feature = "full")]
pub fn heartbeat_ack_signing_bytes(heartbeat: &HeartbeatAckMsg) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + heartbeat.threat_digests.len() * 96);
    bytes.push(u8::from(heartbeat.acknowledged));
    append_threat_epoch_advertisement_bytes(
        &mut bytes,
        heartbeat.encrypted_threat_gossip_supported,
        heartbeat.threat_epoch_id,
        heartbeat.threat_epoch_public_key.as_deref(),
    );
    bytes.push(heartbeat.activation_level.unwrap_or_default());
    if let Some(root) = &heartbeat.intelligence_root {
        bytes.extend_from_slice(&(root.len() as u32).to_le_bytes());
        bytes.extend_from_slice(root.as_bytes());
    } else {
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.extend_from_slice(&heartbeat.local_pressure.unwrap_or_default().to_le_bytes());
    bytes.extend_from_slice(&heartbeat.network_pressure.unwrap_or_default().to_le_bytes());
    bytes.extend_from_slice(&(heartbeat.threat_digests.len() as u32).to_le_bytes());
    for digest in &heartbeat.threat_digests {
        bytes.extend_from_slice(&digest.source_peer);
        if let Some(source_peer_id) = &digest.source_peer_id {
            bytes.extend_from_slice(&(source_peer_id.len() as u32).to_le_bytes());
            bytes.extend_from_slice(source_peer_id.as_bytes());
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes.extend_from_slice(&digest.timestamp_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&digest.stage_key_hash.to_le_bytes());
        if let Some(stage_key) = &digest.stage_key {
            bytes.extend_from_slice(&(stage_key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(stage_key.as_bytes());
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes.extend_from_slice(&digest.z_score.to_le_bytes());
        bytes.extend_from_slice(&digest.observation_count.to_le_bytes());
        bytes.extend_from_slice(digest.severity.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.kind.as_bytes());
        bytes.push(0);
    }
    append_encrypted_threat_envelope_bytes(&mut bytes, heartbeat.encrypted_threat_payload.as_ref());
    bytes
}

#[cfg(feature = "full")]
pub fn append_threat_epoch_advertisement_bytes(
    bytes: &mut Vec<u8>,
    encrypted_threat_gossip_supported: bool,
    threat_epoch_id: Option<u64>,
    threat_epoch_public_key: Option<&[u8]>,
) {
    bytes.push(u8::from(encrypted_threat_gossip_supported));
    bytes.extend_from_slice(&threat_epoch_id.unwrap_or_default().to_le_bytes());
    bytes.push(u8::from(threat_epoch_id.is_some()));
    match threat_epoch_public_key {
        Some(public_key) => {
            bytes.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(public_key);
        }
        None => bytes.extend_from_slice(&0u32.to_le_bytes()),
    }
}

#[cfg(feature = "full")]
fn append_encrypted_threat_envelope_bytes(
    bytes: &mut Vec<u8>,
    envelope: Option<&EncryptedThreatEnvelopeMsg>,
) {
    match envelope {
        Some(envelope) => {
            bytes.push(1);
            bytes.extend_from_slice(&envelope.epoch_id.to_le_bytes());
            bytes.extend_from_slice(&envelope.nonce);
            bytes.extend_from_slice(&(envelope.ciphertext.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&envelope.ciphertext);
            bytes.extend_from_slice(&envelope.payload_version.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttestationChainMsg {
    pub job_id: String,
    pub partition_id: u32,
    #[serde(default)]
    pub attestations: Vec<AttestationMetadata>,
}

// ─── Job lifecycle ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCompleteMsg {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAbortMsg {
    pub job_id: String,
    pub reason: String,
}
