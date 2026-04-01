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

//! ZKF IR Specification — formal definition of the ZKF intermediate representation.
//!
//! This crate defines the canonical IR specification including constraint kinds,
//! signal types, blackbox operations, and their semantics. It serves as the
//! single source of truth for what the IR means.

pub mod canonical;
pub mod formal;
pub mod schema;
pub mod semantics;
pub mod verification;
pub mod version;

use serde::{Deserialize, Serialize};

/// The current major version of the IR specification.
pub const IR_SPEC_MAJOR: u32 = 2;
/// The current minor version of the IR specification.
pub const IR_SPEC_MINOR: u32 = 0;

/// Top-level IR specification document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrSpec {
    pub version: version::IrVersion,
    pub constraint_kinds: Vec<semantics::ConstraintKindSpec>,
    pub signal_types: Vec<semantics::SignalTypeSpec>,
    pub blackbox_ops: Vec<semantics::BlackBoxOpSpec>,
    pub field_ids: Vec<String>,
}

impl Default for IrSpec {
    fn default() -> Self {
        Self {
            version: version::IrVersion {
                major: IR_SPEC_MAJOR,
                minor: IR_SPEC_MINOR,
            },
            constraint_kinds: semantics::all_constraint_kinds(),
            signal_types: semantics::all_signal_types(),
            blackbox_ops: semantics::all_blackbox_ops(),
            field_ids: vec![
                "bn254".into(),
                "bls12-381".into(),
                "pasta-fp".into(),
                "pasta-fq".into(),
                "goldilocks".into(),
                "babybear".into(),
                "mersenne31".into(),
            ],
        }
    }
}

impl IrSpec {
    /// Create the canonical spec for the current version.
    pub fn current() -> Self {
        Self::default()
    }

    /// Serialize to canonical JSON (sorted keys, deterministic).
    pub fn to_canonical_json(&self) -> String {
        canonical::to_canonical_json(self)
    }
}

pub use verification::{
    VerificationCheckerKind, VerificationLedger, VerificationLedgerEntry, VerificationStatus,
    verification_ledger,
};
