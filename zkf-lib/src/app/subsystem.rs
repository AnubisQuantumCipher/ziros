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
use std::collections::BTreeMap;

pub const SUBSYSTEM_MANIFEST_SCHEMA_V1: &str = "zkf-subsystem-manifest-v1";
pub const SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED: &str = "author_fixed";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemCircuitManifestV1 {
    pub backend: String,
    pub program_path: String,
    pub compiled_path: String,
    pub inputs_path: String,
    pub proof_path: String,
    pub verification_path: String,
    pub audit_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemManifestEnvelopeV1 {
    pub schema: String,
    pub subsystem_id: String,
    pub version: String,
    pub created_at: String,
    pub backend_policy: String,
    pub publication_target: String,
    pub circuits: BTreeMap<String, SubsystemCircuitManifestV1>,
}

impl SubsystemManifestEnvelopeV1 {
    pub fn author_fixed(
        subsystem_id: impl Into<String>,
        version: impl Into<String>,
        created_at: impl Into<String>,
        publication_target: impl Into<String>,
        circuits: BTreeMap<String, SubsystemCircuitManifestV1>,
    ) -> Self {
        Self {
            schema: SUBSYSTEM_MANIFEST_SCHEMA_V1.to_string(),
            subsystem_id: subsystem_id.into(),
            version: version.into(),
            created_at: created_at.into(),
            backend_policy: SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED.to_string(),
            publication_target: publication_target.into(),
            circuits,
        }
    }
}
