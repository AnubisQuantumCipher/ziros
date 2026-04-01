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

use zkf_backends::verifier_export::{
    VerifierExportResult, VerifierLanguage, verifier_exporter_for,
};
use zkf_core::{BackendKind, ProofArtifact, ZkfError, ZkfResult};

pub fn export_verifier(
    artifact: &ProofArtifact,
    language: VerifierLanguage,
    contract_name: Option<&str>,
) -> ZkfResult<VerifierExportResult> {
    let exporter =
        verifier_exporter_for(artifact.backend).ok_or_else(|| ZkfError::UnsupportedBackend {
            backend: artifact.backend.as_str().to_string(),
            message: "verifier export is not available for this backend".to_string(),
        })?;
    let value = serde_json::to_value(artifact).map_err(|error| {
        ZkfError::Serialization(format!("failed to serialize proof artifact: {error}"))
    })?;
    exporter
        .export_verifier(&value, language, contract_name)
        .map_err(|message| {
            ZkfError::InvalidArtifact(format!("failed to export verifier: {message}"))
        })
}

pub fn export_groth16_solidity_verifier(
    artifact: &ProofArtifact,
    contract_name: Option<&str>,
) -> ZkfResult<String> {
    if artifact.backend != BackendKind::ArkworksGroth16 {
        return Err(ZkfError::UnsupportedBackend {
            backend: artifact.backend.as_str().to_string(),
            message: "the library-side Solidity verifier path only supports arkworks-groth16 in v1"
                .to_string(),
        });
    }
    Ok(export_verifier(artifact, VerifierLanguage::Solidity, contract_name)?.source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::api::compile_and_prove_default;
    use crate::app::templates::poseidon_commitment;

    #[test]
    fn groth16_solidity_export_succeeds_for_real_artifact() {
        let template = poseidon_commitment().expect("poseidon template");
        let embedded =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                compile_and_prove_default(&template.program, &template.sample_inputs, None, None)
            })
            .expect("prove");
        let source = export_groth16_solidity_verifier(&embedded.artifact, Some("AppVerifier"))
            .expect("solidity export");
        assert!(source.contains("contract AppVerifier"));
    }

    #[test]
    fn unsupported_backend_language_pairs_error_cleanly() {
        let artifact = ProofArtifact {
            backend: BackendKind::Nova,
            program_digest: "digest".to_string(),
            proof: Vec::new(),
            verification_key: Vec::new(),
            public_inputs: Vec::new(),
            metadata: Default::default(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        let err = export_verifier(&artifact, VerifierLanguage::Solidity, None).unwrap_err();
        assert!(matches!(err, ZkfError::UnsupportedBackend { .. }));
    }
}
