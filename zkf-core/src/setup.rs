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

//! Setup modeling for ZKF backends.
//!
//! Models the different kinds of trusted setup (ceremony, universal SRS, transparent)
//! and their security properties.

use crate::artifact::BackendKind;
use serde::{Deserialize, Serialize};

/// The kind of setup a backend requires.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupKind {
    /// Fully deterministic setup (for testing only — NOT secure for production).
    Deterministic,
    /// Universal Structured Reference String (e.g., Powers of Tau).
    /// Can be reused across circuits up to a max constraint count.
    UniversalSrs {
        /// Maximum supported constraint count (2^power).
        max_constraints: u64,
    },
    /// Circuit-specific ceremony (e.g., Groth16 Phase 2 per-circuit keys).
    CircuitSpecificCeremony,
    /// Transparent setup (no trusted setup required — e.g., STARKs, FRI).
    TransparentSetup,
}

impl SetupKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SetupKind::Deterministic => "deterministic",
            SetupKind::UniversalSrs { .. } => "universal_srs",
            SetupKind::CircuitSpecificCeremony => "circuit_specific_ceremony",
            SetupKind::TransparentSetup => "transparent",
        }
    }

    /// Whether this setup kind requires trust assumptions.
    pub fn requires_trust(&self) -> bool {
        matches!(
            self,
            SetupKind::UniversalSrs { .. } | SetupKind::CircuitSpecificCeremony
        )
    }
}

/// Security model of a setup.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityModel {
    /// 1-of-N honest participant model (MPC ceremony).
    OneOfNHonest { n: u32 },
    /// Transparent — no trust assumptions.
    Transparent,
    /// Deterministic testing setup — NOT SECURE for production.
    DeterministicTesting,
}

impl SecurityModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityModel::OneOfNHonest { .. } => "one_of_n_honest",
            SecurityModel::Transparent => "transparent",
            SecurityModel::DeterministicTesting => "deterministic_testing",
        }
    }
}

impl std::fmt::Display for SecurityModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityModel::OneOfNHonest { n } => write!(f, "1-of-{n} honest"),
            SecurityModel::Transparent => write!(f, "transparent"),
            SecurityModel::DeterministicTesting => write!(f, "deterministic (TESTING ONLY)"),
        }
    }
}

/// Where a setup's keys are stored.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreProvenance {
    /// Keys stored in Secure Enclave-backed keychain (macOS).
    SecureEnclave { label: String },
    /// Keys stored in file-based keystore with restricted permissions.
    FileStore { path: String },
    /// Keys are ephemeral (in-memory only, not persisted).
    Ephemeral,
}

impl KeystoreProvenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecureEnclave { .. } => "secure_enclave",
            Self::FileStore { .. } => "file_store",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// Provenance of a setup artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupProvenance {
    /// What kind of setup this is.
    pub kind: SetupKind,
    /// When the setup was created (Unix timestamp).
    pub timestamp_unix: u64,
    /// SHA-256 digest of the setup artifact.
    pub digest: String,
    /// Security model of this setup.
    pub security_model: SecurityModel,
    /// Optional: number of ceremony contributions (for MPC setups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contributions: Option<u32>,
    /// Optional: ceremony transcript digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_digest: Option<String>,
    /// Optional: where proving keys are stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keystore: Option<KeystoreProvenance>,
}

impl SetupProvenance {
    /// Create provenance for a deterministic testing setup.
    pub fn deterministic_testing(digest: String) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            kind: SetupKind::Deterministic,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            digest,
            security_model: SecurityModel::DeterministicTesting,
            contributions: None,
            transcript_digest: None,
            keystore: None,
        }
    }

    /// Create provenance for a transparent setup.
    pub fn transparent(digest: String) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            kind: SetupKind::TransparentSetup,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            digest,
            security_model: SecurityModel::Transparent,
            contributions: None,
            transcript_digest: None,
            keystore: None,
        }
    }

    /// Create provenance for a ceremony-derived setup.
    pub fn ceremony(
        digest: String,
        contributions: u32,
        transcript_digest: Option<String>,
        max_constraints: Option<u64>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let kind = if let Some(max) = max_constraints {
            SetupKind::UniversalSrs {
                max_constraints: max,
            }
        } else {
            SetupKind::CircuitSpecificCeremony
        };
        Self {
            kind,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            digest,
            security_model: SecurityModel::OneOfNHonest { n: contributions },
            contributions: Some(contributions),
            transcript_digest,
            keystore: None,
        }
    }
}

/// Determine the default setup kind for a given backend.
pub fn default_setup_for_backend(backend: BackendKind) -> SetupKind {
    match backend {
        BackendKind::ArkworksGroth16 => SetupKind::CircuitSpecificCeremony,
        BackendKind::Plonky3 => SetupKind::TransparentSetup,
        BackendKind::Halo2 | BackendKind::Halo2Bls12381 => SetupKind::Deterministic,
        BackendKind::Nova | BackendKind::HyperNova => SetupKind::Deterministic,
        BackendKind::Sp1 | BackendKind::RiscZero => SetupKind::TransparentSetup,
        BackendKind::MidnightCompact => SetupKind::Deterministic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_kind_trust() {
        assert!(!SetupKind::Deterministic.requires_trust());
        assert!(!SetupKind::TransparentSetup.requires_trust());
        assert!(SetupKind::CircuitSpecificCeremony.requires_trust());
        assert!(
            SetupKind::UniversalSrs {
                max_constraints: 1024
            }
            .requires_trust()
        );
    }

    #[test]
    fn groth16_requires_ceremony() {
        let setup = default_setup_for_backend(BackendKind::ArkworksGroth16);
        assert!(matches!(setup, SetupKind::CircuitSpecificCeremony));
        assert!(setup.requires_trust());
    }

    #[test]
    fn plonky3_is_transparent() {
        let setup = default_setup_for_backend(BackendKind::Plonky3);
        assert!(matches!(setup, SetupKind::TransparentSetup));
        assert!(!setup.requires_trust());
    }

    #[test]
    fn ceremony_provenance() {
        let prov = SetupProvenance::ceremony(
            "abc".into(),
            80,
            Some("transcript_hash".into()),
            Some(1 << 20),
        );
        assert_eq!(prov.contributions, Some(80));
        assert!(matches!(
            prov.security_model,
            SecurityModel::OneOfNHonest { n: 80 }
        ));
    }
}
