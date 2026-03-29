pub mod consensus;
pub mod diplomat;
pub mod epoch;
pub mod identity;
pub mod memory;
pub mod reputation;

use crate::protocol::ThreatDigestMsg;
use zkf_runtime::security::{ThreatSeverity, ThreatSignalKind};
use zkf_runtime::swarm::ThreatDigest;

pub use consensus::ConsensusCollector;
pub use diplomat::Diplomat;
pub use epoch::{
    PeerThreatChannel, SwarmEpochManager, ThreatEpochAdvertisement, ThreatEpochError,
    ThreatEpochErrorKind, ThreatIntelPayload, has_plaintext_threat_surface,
};
pub use identity::{
    FileBackend, KeyStorageBackend, LocalPeerIdentity, MlDsaKeyProvenance, PublicKeyBundle,
    SecureEnclaveBackend, SignatureBundle, SignatureScheme, admission_pow_identity_bytes,
    compute_admission_pow, local_identity_label, verify_admission_pow,
};
pub use memory::{
    attestation_signing_bytes, current_intelligence_root, output_digest, persist_attestation_chain,
    persist_threat_intelligence_outcome, trace_digest,
};
pub use reputation::{
    PeerReputation, ReputationEvent, ReputationEvidence, ReputationEvidenceKind, ReputationTracker,
    ReputationVerificationReport, load_reputation_events, load_reputation_events_for,
    load_reputation_score_for, load_reputation_scores, verify_reputation_log,
    verify_reputation_log_report,
};

pub fn encode_threat_digest(digest: &ThreatDigest) -> ThreatDigestMsg {
    crate::swarm_protocol_core::encode_threat_digest(digest)
}

pub fn decode_threat_digest(digest: &ThreatDigestMsg) -> ThreatDigest {
    crate::swarm_protocol_core::decode_threat_digest(digest)
}

pub fn severity_to_string(severity: ThreatSeverity) -> String {
    crate::swarm_protocol_core::severity_to_string(severity)
}

pub fn severity_from_string(severity: &str) -> ThreatSeverity {
    crate::swarm_protocol_core::severity_from_string(severity)
}

pub fn threat_kind_to_string(kind: ThreatSignalKind) -> String {
    crate::swarm_protocol_core::threat_kind_to_string(kind)
}

pub fn threat_kind_from_string(kind: &str) -> ThreatSignalKind {
    crate::swarm_protocol_core::threat_kind_from_string(kind)
}
