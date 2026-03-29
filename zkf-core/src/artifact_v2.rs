//! Unified artifact model for ZKF.
//!
//! Every artifact (program, compiled circuit, witness, proof, verification key,
//! proving key, verifier, audit report) is wrapped in a `ZkfArtifactBundle`
//! that carries provenance, digests, and metadata.

use crate::artifact::{ArtifactProvenance, BackendKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema version for the artifact bundle format.
pub const ARTIFACT_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The kind of artifact contained in a bundle.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Source IR program (IR v2 or ZIR v1).
    Program,
    /// Backend-compiled circuit (R1CS, AIR, Plonkish, etc.).
    CompiledCircuit,
    /// Witness (satisfying assignment).
    Witness,
    /// Zero-knowledge proof.
    Proof,
    /// Verification key.
    VerificationKey,
    /// Proving key (may be large).
    ProvingKey,
    /// Exported verifier (e.g., Solidity contract).
    Verifier,
    /// Structured audit report.
    AuditReport,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Program => "program",
            ArtifactKind::CompiledCircuit => "compiled_circuit",
            ArtifactKind::Witness => "witness",
            ArtifactKind::Proof => "proof",
            ArtifactKind::VerificationKey => "verification_key",
            ArtifactKind::ProvingKey => "proving_key",
            ArtifactKind::Verifier => "verifier",
            ArtifactKind::AuditReport => "audit_report",
        }
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A universal artifact bundle wrapping any ZKF artifact with provenance and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkfArtifactBundle {
    /// Schema version of this bundle format.
    pub schema_version: u32,
    /// What kind of artifact this is.
    pub kind: ArtifactKind,
    /// Full provenance chain (who created this, from what, when).
    pub provenance: ArtifactProvenance,
    /// The artifact content as JSON value (backend-specific).
    pub content: serde_json::Value,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: ArtifactMetadata,
}

/// Metadata attached to an artifact bundle.
pub type ArtifactMetadata = BTreeMap<String, serde_json::Value>;

impl ZkfArtifactBundle {
    /// Create a new artifact bundle.
    pub fn new(
        kind: ArtifactKind,
        provenance: ArtifactProvenance,
        content: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: ARTIFACT_BUNDLE_SCHEMA_VERSION,
            kind,
            provenance,
            content,
            metadata: BTreeMap::new(),
        }
    }

    /// Add a metadata entry.
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the artifact's content digest (from provenance).
    pub fn digest(&self) -> &str {
        &self.provenance.artifact_digest
    }

    /// Get the parent artifact digests.
    pub fn parent_digests(&self) -> &[String] {
        &self.provenance.parent_digests
    }

    /// Get the backend that produced this artifact (if any).
    pub fn backend(&self) -> Option<BackendKind> {
        self.provenance.backend
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> crate::ZkfResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::ZkfError::Serialization(format!("artifact bundle: {e}")))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> crate::ZkfResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::ZkfError::InvalidArtifact(format!("artifact bundle parse: {e}")))
    }

    /// Verify that the provenance digest matches the content.
    pub fn verify_integrity(&self) -> bool {
        use sha2::{Digest, Sha256};
        let content_json = serde_json::to_string(&self.content).unwrap_or_default();
        let computed = format!("{:x}", Sha256::digest(content_json.as_bytes()));
        computed == self.provenance.artifact_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldId;
    use crate::artifact::ArtifactProvenance;

    #[test]
    fn bundle_roundtrip() {
        let prov = ArtifactProvenance::new(
            "abc123".into(),
            vec!["parent1".into()],
            "compile",
            Some(BackendKind::ArkworksGroth16),
            Some(FieldId::Bn254),
        );

        let bundle = ZkfArtifactBundle::new(
            ArtifactKind::CompiledCircuit,
            prov,
            serde_json::json!({"test": true}),
        )
        .with_metadata("circuit_name", serde_json::Value::String("multiply".into()));

        let json = bundle.to_json().unwrap();
        let restored = ZkfArtifactBundle::from_json(&json).unwrap();

        assert_eq!(restored.kind, ArtifactKind::CompiledCircuit);
        assert_eq!(restored.digest(), "abc123");
        assert_eq!(restored.parent_digests(), &["parent1"]);
        assert_eq!(restored.backend(), Some(BackendKind::ArkworksGroth16));
    }

    #[test]
    fn artifact_kind_display() {
        assert_eq!(ArtifactKind::Proof.as_str(), "proof");
        assert_eq!(
            ArtifactKind::VerificationKey.to_string(),
            "verification_key"
        );
    }
}
