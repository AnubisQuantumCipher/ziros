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

//! Verifier export framework — trait-based multi-backend, multi-language verifier generation.
//!
//! This module defines the [`VerifierExport`] trait, which backends implement to generate
//! standalone verifier code and behavioral tests in various languages. Currently supported:
//!
//! - **ArkworksGroth16** -> Solidity verifier + Foundry test
//! - **Plonky3** -> Rust STARK verifier
//! - **Halo2** -> Rust IPA verifier

use serde::{Deserialize, Serialize};
use zkf_core::BackendKind;

pub mod groth16;
pub mod halo2;
pub mod plonky3;

/// Supported output languages for exported verifiers.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierLanguage {
    Solidity,
    Rust,
    TypeScript,
}

impl std::fmt::Display for VerifierLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifierLanguage::Solidity => write!(f, "solidity"),
            VerifierLanguage::Rust => write!(f, "rust"),
            VerifierLanguage::TypeScript => write!(f, "typescript"),
        }
    }
}

/// Result of a verifier export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierExportResult {
    /// The language the verifier was generated in.
    pub language: VerifierLanguage,
    /// The generated verifier source code.
    pub source: String,
    /// Name of the generated contract/module (e.g., `"ZkfGroth16Verifier"`).
    pub contract_name: Option<String>,
    /// Name of the primary verification entry point (e.g., `"verifyProof"`).
    pub verification_function: String,
    /// Optional test source code (e.g., a Foundry `.t.sol` file).
    pub test_source: Option<String>,
    /// Name of the test contract/module, if a test was generated.
    pub test_name: Option<String>,
}

/// Trait for backends that can export standalone verifier code.
///
/// Implementors generate language-specific verifier source from proof artifacts,
/// and optionally generate behavioral tests to validate the exported verifier.
pub trait VerifierExport {
    /// Export a standalone verifier from a proof artifact.
    ///
    /// The `proof_data` JSON value must contain the fields expected by the backend
    /// (e.g., `verification_key`, `proof`, `public_inputs` for Groth16).
    ///
    /// Returns an error string if the requested language is unsupported or if the
    /// proof data cannot be parsed.
    fn export_verifier(
        &self,
        proof_data: &serde_json::Value,
        language: VerifierLanguage,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String>;

    /// Export a behavioral test for the verifier.
    ///
    /// The test exercises the exported verifier with the proof embedded in `proof_data`,
    /// verifying that valid proofs pass, tampered proofs fail, and wrong inputs fail.
    fn export_behavioral_test(
        &self,
        proof_data: &serde_json::Value,
        verifier_import_path: &str,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String>;

    /// Which languages does this backend support for verifier export?
    fn supported_languages(&self) -> Vec<VerifierLanguage>;
}

/// Look up a verifier exporter for the given backend.
///
/// Returns `None` for backends that do not (yet) support verifier export.
pub fn verifier_exporter_for(backend: BackendKind) -> Option<Box<dyn VerifierExport>> {
    match backend {
        BackendKind::ArkworksGroth16 => Some(Box::new(groth16::Groth16VerifierExporter)),
        BackendKind::Plonky3 => Some(Box::new(plonky3::Plonky3VerifierExporter)),
        BackendKind::Halo2 => Some(Box::new(halo2::Halo2VerifierExporter)),
        _ => None,
    }
}
