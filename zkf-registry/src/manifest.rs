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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkf_core::FieldId;

/// Manifest describing a published gadget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_fields: Vec<FieldId>,
    pub dependencies: Vec<GadgetDependency>,
    pub author: Option<String>,
    pub license: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// SHA-256 digest of the gadget content (hex-encoded).
    #[serde(default)]
    pub content_sha256: Option<String>,
    /// Optional Ed25519 signature (hex-encoded). Verification is handled separately.
    #[serde(default)]
    pub signature: Option<String>,
}

/// A dependency on another gadget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetDependency {
    pub name: String,
    pub version_req: String,
}

impl GadgetManifest {
    pub fn new(name: &str, version: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
            supported_fields: Vec::new(),
            dependencies: Vec::new(),
            author: None,
            license: None,
            tags: Vec::new(),
            content_sha256: None,
            signature: None,
        }
    }

    pub fn with_fields(mut self, fields: Vec<FieldId>) -> Self {
        self.supported_fields = fields;
        self
    }

    /// Verify that the given content matches the stored SHA-256 digest.
    /// Returns `true` if `content_sha256` is `None` (no digest to check) or if the
    /// digest matches. Returns `false` only when a digest is present and does not match.
    pub fn verify_content_digest(&self, content: &[u8]) -> bool {
        match &self.content_sha256 {
            None => true,
            Some(expected) => {
                let actual = format!("{:x}", Sha256::digest(content));
                actual == *expected
            }
        }
    }

    /// Compute and set the content SHA-256 digest from the given content bytes.
    pub fn set_content_digest(&mut self, content: &[u8]) {
        self.content_sha256 = Some(format!("{:x}", Sha256::digest(content)));
    }

    /// Verify the Ed25519 signature over the content digest.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if no signature
    /// is present, and `Err` if verification fails or the feature is not enabled.
    #[cfg(feature = "ed25519")]
    pub fn verify_signature(
        &self,
        content: &[u8],
        public_key_bytes: &[u8; 32],
    ) -> Result<bool, String> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_hex = match &self.signature {
            Some(s) => s,
            None => return Ok(false),
        };

        let sig_bytes = hex_decode(sig_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid Ed25519 signature: {e}"))?;

        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;

        // Verify over the content digest (SHA-256 of content)
        let digest = Sha256::digest(content);
        verifying_key
            .verify(&digest, &signature)
            .map_err(|e| format!("Ed25519 signature verification failed: {e}"))?;

        Ok(true)
    }

    /// Fallback when the `ed25519` feature is not enabled.
    #[cfg(not(feature = "ed25519"))]
    pub fn verify_signature(
        &self,
        _content: &[u8],
        _public_key_bytes: &[u8; 32],
    ) -> Result<bool, String> {
        if self.signature.is_some() {
            Err("Ed25519 signature verification requires the `ed25519` feature".to_string())
        } else {
            Ok(false)
        }
    }
}

#[cfg(feature = "ed25519")]
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_serialization_roundtrip() {
        let manifest = GadgetManifest::new("poseidon", "1.0.0", "Poseidon hash gadget")
            .with_fields(vec![FieldId::Bn254, FieldId::Goldilocks]);

        let json = serde_json::to_string(&manifest).unwrap();
        let restored: GadgetManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "poseidon");
        assert_eq!(restored.supported_fields.len(), 2);
    }

    #[test]
    fn verify_content_digest_none_returns_true() {
        let manifest = GadgetManifest::new("test", "0.1.0", "test");
        assert!(manifest.verify_content_digest(b"anything"));
    }

    #[test]
    fn verify_content_digest_matching() {
        let content = b"hello world";
        let mut manifest = GadgetManifest::new("test", "0.1.0", "test");
        manifest.set_content_digest(content);
        assert!(manifest.verify_content_digest(content));
    }

    #[test]
    fn verify_content_digest_mismatch() {
        let mut manifest = GadgetManifest::new("test", "0.1.0", "test");
        manifest.set_content_digest(b"original content");
        assert!(!manifest.verify_content_digest(b"tampered content"));
    }

    #[test]
    fn security_fields_serialize() {
        let mut manifest = GadgetManifest::new("secure", "1.0.0", "secure gadget");
        manifest.set_content_digest(b"data");
        manifest.signature = Some("abcdef1234".to_string());

        let json = serde_json::to_string(&manifest).unwrap();
        let restored: GadgetManifest = serde_json::from_str(&json).unwrap();
        assert!(restored.content_sha256.is_some());
        assert_eq!(restored.signature.as_deref(), Some("abcdef1234"));
    }

    #[test]
    fn missing_security_fields_deserialize_as_none() {
        let json = r#"{"name":"old","version":"0.1.0","description":"legacy","supported_fields":[],"dependencies":[],"author":null,"license":null,"tags":[]}"#;
        let manifest: GadgetManifest = serde_json::from_str(json).unwrap();
        assert!(manifest.content_sha256.is_none());
        assert!(manifest.signature.is_none());
    }
}
