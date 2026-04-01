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

//! Privacy discipline -- export modes that control what data leaves the system.
//!
//! Defines [`ExportMode`] levels (Debug, Local, ExportSafe, PrivacyMinimized) and
//! a [`sanitize_artifact`] helper that strips sensitive fields from artifact bundles.

use serde::{Deserialize, Serialize};

/// Export mode controlling what artifact data is exposed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    /// Everything visible — for local debugging only.
    Debug,
    /// No witness values — safe for local storage.
    Local,
    /// Proof + VK + public inputs only — safe for external sharing.
    ExportSafe,
    /// Proof + public inputs only — minimal privacy exposure.
    PrivacyMinimized,
}

impl ExportMode {
    /// Whether witness data should be included.
    pub fn includes_witness(&self) -> bool {
        matches!(self, ExportMode::Debug)
    }

    /// Whether verification key should be included.
    pub fn includes_vk(&self) -> bool {
        matches!(
            self,
            ExportMode::Debug | ExportMode::Local | ExportMode::ExportSafe
        )
    }

    /// Whether proving key should be included.
    pub fn includes_pk(&self) -> bool {
        matches!(self, ExportMode::Debug | ExportMode::Local)
    }

    /// Whether private signal values should be included.
    pub fn includes_private_signals(&self) -> bool {
        matches!(self, ExportMode::Debug)
    }
}

/// Sanitize an artifact bundle according to the export mode.
/// Returns a new bundle with sensitive fields stripped.
pub fn sanitize_artifact(
    bundle: &crate::artifact_v2::ZkfArtifactBundle,
    mode: ExportMode,
) -> crate::artifact_v2::ZkfArtifactBundle {
    let mut sanitized = bundle.clone();

    match mode {
        ExportMode::Debug => { /* keep everything */ }
        ExportMode::Local => {
            strip_witness_values(&mut sanitized.content);
        }
        ExportMode::ExportSafe => {
            strip_witness_values(&mut sanitized.content);
            strip_proving_key(&mut sanitized.content);
            strip_internal_metadata(&mut sanitized.metadata);
        }
        ExportMode::PrivacyMinimized => {
            strip_witness_values(&mut sanitized.content);
            strip_proving_key(&mut sanitized.content);
            strip_verification_key(&mut sanitized.content);
            strip_internal_metadata(&mut sanitized.metadata);
        }
    }

    sanitized
}

fn strip_witness_values(content: &mut serde_json::Value) {
    if let Some(obj) = content.as_object_mut() {
        obj.remove("witness");
        obj.remove("witness_values");
        obj.remove("private_inputs");
        obj.remove("secret_inputs");
    }
}

fn strip_proving_key(content: &mut serde_json::Value) {
    if let Some(obj) = content.as_object_mut() {
        obj.remove("proving_key");
        obj.remove("pk");
        obj.remove("pk_data");
    }
}

fn strip_verification_key(content: &mut serde_json::Value) {
    if let Some(obj) = content.as_object_mut() {
        obj.remove("verification_key");
        obj.remove("vk");
        obj.remove("vk_data");
    }
}

fn strip_internal_metadata(metadata: &mut crate::artifact_v2::ArtifactMetadata) {
    metadata.remove("internal_timings");
    metadata.remove("debug_info");
    metadata.remove("compiler_internals");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldId;
    use crate::artifact::{ArtifactProvenance, BackendKind};
    use crate::artifact_v2::{ArtifactKind, ZkfArtifactBundle};

    fn make_test_bundle() -> ZkfArtifactBundle {
        let prov = ArtifactProvenance::new(
            "test_digest".into(),
            vec![],
            "test",
            Some(BackendKind::ArkworksGroth16),
            Some(FieldId::Bn254),
        );

        let content = serde_json::json!({
            "proof": "base64_proof_data",
            "verification_key": "vk_bytes",
            "vk": "vk_alt",
            "vk_data": "vk_data_alt",
            "proving_key": "pk_bytes",
            "pk": "pk_alt",
            "pk_data": "pk_data_alt",
            "witness": [1, 2, 3],
            "witness_values": {"x": 5},
            "private_inputs": {"secret": 42},
            "secret_inputs": {"key": 99},
            "public_inputs": [10, 20],
        });

        ZkfArtifactBundle::new(ArtifactKind::Proof, prov, content)
            .with_metadata("internal_timings", serde_json::json!({"compile_ms": 100}))
            .with_metadata("debug_info", serde_json::json!({"trace": "abc"}))
            .with_metadata("compiler_internals", serde_json::json!({"ir_dump": "..."}))
            .with_metadata("circuit_name", serde_json::json!("multiply"))
    }

    #[test]
    fn debug_mode_keeps_everything() {
        let bundle = make_test_bundle();
        let sanitized = sanitize_artifact(&bundle, ExportMode::Debug);
        let obj = sanitized.content.as_object().unwrap();
        assert!(obj.contains_key("witness"));
        assert!(obj.contains_key("proving_key"));
        assert!(obj.contains_key("verification_key"));
        assert!(obj.contains_key("public_inputs"));
        assert!(sanitized.metadata.contains_key("internal_timings"));
        assert!(sanitized.metadata.contains_key("debug_info"));
    }

    #[test]
    fn local_mode_strips_witness() {
        let bundle = make_test_bundle();
        let sanitized = sanitize_artifact(&bundle, ExportMode::Local);
        let obj = sanitized.content.as_object().unwrap();
        // Witness fields stripped
        assert!(!obj.contains_key("witness"));
        assert!(!obj.contains_key("witness_values"));
        assert!(!obj.contains_key("private_inputs"));
        assert!(!obj.contains_key("secret_inputs"));
        // Keys still present
        assert!(obj.contains_key("proving_key"));
        assert!(obj.contains_key("verification_key"));
        assert!(obj.contains_key("public_inputs"));
        // Metadata untouched
        assert!(sanitized.metadata.contains_key("internal_timings"));
    }

    #[test]
    fn export_safe_mode_strips_witness_and_pk_and_internal_metadata() {
        let bundle = make_test_bundle();
        let sanitized = sanitize_artifact(&bundle, ExportMode::ExportSafe);
        let obj = sanitized.content.as_object().unwrap();
        // Witness stripped
        assert!(!obj.contains_key("witness"));
        assert!(!obj.contains_key("witness_values"));
        // PK stripped (all variants)
        assert!(!obj.contains_key("proving_key"));
        assert!(!obj.contains_key("pk"));
        assert!(!obj.contains_key("pk_data"));
        // VK still present
        assert!(obj.contains_key("verification_key"));
        // Public inputs still present
        assert!(obj.contains_key("public_inputs"));
        // Internal metadata stripped
        assert!(!sanitized.metadata.contains_key("internal_timings"));
        assert!(!sanitized.metadata.contains_key("debug_info"));
        assert!(!sanitized.metadata.contains_key("compiler_internals"));
        // Non-internal metadata preserved
        assert!(sanitized.metadata.contains_key("circuit_name"));
    }

    #[test]
    fn privacy_minimized_mode_strips_everything_except_proof_and_public() {
        let bundle = make_test_bundle();
        let sanitized = sanitize_artifact(&bundle, ExportMode::PrivacyMinimized);
        let obj = sanitized.content.as_object().unwrap();
        // Witness stripped
        assert!(!obj.contains_key("witness"));
        // PK stripped
        assert!(!obj.contains_key("proving_key"));
        // VK stripped (all variants)
        assert!(!obj.contains_key("verification_key"));
        assert!(!obj.contains_key("vk"));
        assert!(!obj.contains_key("vk_data"));
        // Proof and public inputs remain
        assert!(obj.contains_key("proof"));
        assert!(obj.contains_key("public_inputs"));
        // Internal metadata stripped
        assert!(!sanitized.metadata.contains_key("internal_timings"));
        // Non-internal metadata preserved
        assert!(sanitized.metadata.contains_key("circuit_name"));
    }

    #[test]
    fn export_mode_query_methods() {
        assert!(ExportMode::Debug.includes_witness());
        assert!(!ExportMode::Local.includes_witness());
        assert!(!ExportMode::ExportSafe.includes_witness());
        assert!(!ExportMode::PrivacyMinimized.includes_witness());

        assert!(ExportMode::Debug.includes_vk());
        assert!(ExportMode::Local.includes_vk());
        assert!(ExportMode::ExportSafe.includes_vk());
        assert!(!ExportMode::PrivacyMinimized.includes_vk());

        assert!(ExportMode::Debug.includes_pk());
        assert!(ExportMode::Local.includes_pk());
        assert!(!ExportMode::ExportSafe.includes_pk());
        assert!(!ExportMode::PrivacyMinimized.includes_pk());

        assert!(ExportMode::Debug.includes_private_signals());
        assert!(!ExportMode::Local.includes_private_signals());
    }

    #[test]
    fn sanitize_does_not_mutate_original() {
        let bundle = make_test_bundle();
        let _sanitized = sanitize_artifact(&bundle, ExportMode::PrivacyMinimized);
        // Original bundle unchanged
        let obj = bundle.content.as_object().unwrap();
        assert!(obj.contains_key("witness"));
        assert!(obj.contains_key("proving_key"));
        assert!(obj.contains_key("verification_key"));
    }

    #[test]
    fn export_mode_serde_roundtrip() {
        for mode in [
            ExportMode::Debug,
            ExportMode::Local,
            ExportMode::ExportSafe,
            ExportMode::PrivacyMinimized,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: ExportMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn export_mode_serde_names() {
        assert_eq!(
            serde_json::to_string(&ExportMode::Debug).unwrap(),
            "\"debug\""
        );
        assert_eq!(
            serde_json::to_string(&ExportMode::ExportSafe).unwrap(),
            "\"export_safe\""
        );
        assert_eq!(
            serde_json::to_string(&ExportMode::PrivacyMinimized).unwrap(),
            "\"privacy_minimized\""
        );
    }
}
