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

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const NASA_CLASS_D_GROUND_SUPPORT_MISSION_OPS_ASSURANCE: &str =
    "NASA Class D ground-support mission-ops assurance";
pub const NASA_CLASS_C_PLUS_INDEPENDENT_ASSESSMENT_NOTE: &str = "Any mission that wants to place ZirOS outputs inside a NASA Class C or higher decision chain must perform an independent program assessment outside ZirOS.";
pub const NORMALIZED_EXPORT_BASED_INGESTION_MODE: &str = "normalized-export-based ingestion";
pub const MISSION_OPS_NON_REPLACEMENT_TARGETS: [&str; 8] = [
    "GMAT",
    "SPICE",
    "Dymos/OpenMDAO",
    "Trick/JEOD",
    "Basilisk",
    "cFS",
    "F Prime",
    "native upstream aerospace engineering tools",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NasaClassificationBoundaryV1 {
    pub target_classification: String,
    pub target_use: String,
    pub requires_independent_assessment_for_class_c_or_higher: bool,
    pub boundary_note: String,
}

impl Default for NasaClassificationBoundaryV1 {
    fn default() -> Self {
        Self {
            target_classification: NASA_CLASS_D_GROUND_SUPPORT_MISSION_OPS_ASSURANCE.to_string(),
            target_use: "ground-side mission operations and mission assurance".to_string(),
            requires_independent_assessment_for_class_c_or_higher: true,
            boundary_note: NASA_CLASS_C_PLUS_INDEPENDENT_ASSESSMENT_NOTE.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MissionOpsBoundaryContractV1 {
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    pub mission_scope: String,
    pub ingestion_mode: String,
    pub no_native_replacement_claim: bool,
    pub non_replacement_targets: Vec<String>,
}

pub fn mission_ops_boundary_contract_v1() -> MissionOpsBoundaryContractV1 {
    MissionOpsBoundaryContractV1 {
        nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
        mission_scope: "ground-side mission assurance".to_string(),
        ingestion_mode: NORMALIZED_EXPORT_BASED_INGESTION_MODE.to_string(),
        no_native_replacement_claim: true,
        non_replacement_targets: MISSION_OPS_NON_REPLACEMENT_TARGETS
            .iter()
            .map(|item| (*item).to_string())
            .collect(),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClassV1 {
    ProofBearing,
    GovernedUpstreamEvidence,
    OperationalAnnex,
    DownstreamIntegrationArtifact,
    HumanReadableReportOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorV1 {
    pub relative_path: String,
    pub artifact_class: ArtifactClassV1,
    pub trust_lane: String,
    pub classification_boundary: NasaClassificationBoundaryV1,
    pub contains_private_data: bool,
    pub public_export_allowed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

pub fn artifact_descriptor_v1(
    relative_path: impl Into<String>,
    artifact_class: ArtifactClassV1,
    trust_lane: impl Into<String>,
    contains_private_data: bool,
    public_export_allowed: bool,
    notes: Vec<String>,
) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        relative_path: relative_path.into(),
        artifact_class,
        trust_lane: trust_lane.into(),
        classification_boundary: NasaClassificationBoundaryV1::default(),
        contains_private_data,
        public_export_allowed,
        notes,
    }
}

pub fn exportable_artifacts(
    artifacts: &[ArtifactDescriptorV1],
    include_private: bool,
) -> Vec<ArtifactDescriptorV1> {
    artifacts
        .iter()
        .filter(|artifact| artifact.public_export_allowed || include_private)
        .cloned()
        .collect()
}

pub fn scrub_public_export_text(text: &str) -> String {
    text.replace("/Users/", "/redacted-user-home/")
        .replace("/private/var/", "/redacted-private-var/")
        .replace("sicarii", "redacted-user")
        .replace(
            "\"signed_mission_pack.json\"",
            "\"private_mission_pack_omitted\"",
        )
        .replace(
            "signed_mission_pack.json",
            "private mission pack omitted from public export",
        )
        .replace("\"witness.json\"", "\"private_witness_omitted\"")
        .replace("witness.json", "private witness omitted from public export")
}

pub fn scrub_public_export_text_tree(root: &Path) -> Result<(), String> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata =
            fs::metadata(&path).map_err(|error| format!("metadata {}: {error}", path.display()))?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("read_dir {}: {error}", path.display()))?
            {
                let entry =
                    entry.map_err(|error| format!("dir entry {}: {error}", path.display()))?;
                stack.push(entry.path());
            }
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let sanitized = scrub_public_export_text(&text);
        if sanitized != text {
            fs::write(&path, sanitized)
                .map_err(|error| format!("write {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

pub fn mission_ops_boundary_lines(contract: &MissionOpsBoundaryContractV1) -> Vec<String> {
    vec![
        format!("Mission scope: {}", contract.mission_scope),
        format!(
            "NASA classification boundary: {}",
            contract.nasa_classification_boundary.target_classification
        ),
        format!("Ingestion mode: {}", contract.ingestion_mode),
        format!(
            "No native replacement claim: {}",
            contract.non_replacement_targets.join(", ")
        ),
        contract.nasa_classification_boundary.boundary_note.clone(),
    ]
}

pub fn mission_ops_boundary_markdown(contract: &MissionOpsBoundaryContractV1) -> String {
    mission_ops_boundary_lines(contract)
        .into_iter()
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn release_block_on_oracle_mismatch<M: std::fmt::Debug>(
    context: &str,
    matched: bool,
    mismatches: &M,
) -> Result<(), String> {
    if matched {
        return Ok(());
    }
    Err(format!(
        "{context} deterministic oracle mismatch blocked release use: {mismatches:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("zkf-mission-ops-{name}-{nonce}"))
    }

    #[test]
    fn mission_ops_boundary_contract_is_explicit_and_non_replacement() {
        let contract = mission_ops_boundary_contract_v1();
        assert_eq!(
            contract.nasa_classification_boundary.target_classification,
            NASA_CLASS_D_GROUND_SUPPORT_MISSION_OPS_ASSURANCE
        );
        assert_eq!(
            contract.ingestion_mode,
            NORMALIZED_EXPORT_BASED_INGESTION_MODE
        );
        assert!(contract.no_native_replacement_claim);
        assert!(
            contract
                .non_replacement_targets
                .iter()
                .any(|item| item == "GMAT")
        );
        assert!(
            contract
                .non_replacement_targets
                .iter()
                .any(|item| item == "F Prime")
        );
    }

    #[test]
    fn artifact_descriptor_roundtrips_with_snake_case_class() {
        let descriptor = artifact_descriptor_v1(
            "proof.json",
            ArtifactClassV1::ProofBearing,
            "plonky3-cpu-first",
            false,
            true,
            vec!["proof artifact".to_string()],
        );
        let value = to_value(&descriptor).expect("serialize");
        assert_eq!(value["artifact_class"], json!("proof_bearing"));
    }

    #[test]
    fn exportable_artifacts_filter_private_by_default() {
        let artifacts = vec![
            artifact_descriptor_v1(
                "receipt.json",
                ArtifactClassV1::ProofBearing,
                "plonky3",
                false,
                true,
                vec![],
            ),
            artifact_descriptor_v1(
                "signed_mission_pack.json",
                ArtifactClassV1::GovernedUpstreamEvidence,
                "signed-ingress-authority",
                true,
                false,
                vec![],
            ),
        ];
        let public_only = exportable_artifacts(&artifacts, false);
        assert_eq!(public_only.len(), 1);
        assert_eq!(public_only[0].relative_path, "receipt.json");
        let with_private = exportable_artifacts(&artifacts, true);
        assert_eq!(with_private.len(), 2);
    }

    #[test]
    fn scrub_public_export_text_redacts_private_markers() {
        let text =
            "/Users/example/workspace\nsigned_mission_pack.json\nwitness.json\n/private/var/tmp";
        let sanitized = scrub_public_export_text(text);
        assert!(!sanitized.contains("/Users/"));
        assert!(!sanitized.contains("signed_mission_pack.json"));
        assert!(!sanitized.contains("witness.json"));
        assert!(!sanitized.contains("/private/var/"));
    }

    #[test]
    fn scrub_public_export_text_tree_rewrites_files() {
        let root = temp_dir("scrub-tree");
        fs::create_dir_all(&root).expect("mkdir");
        let file = root.join("report.md");
        fs::write(&file, "path=/Users/example/report").expect("write");
        scrub_public_export_text_tree(&root).expect("scrub tree");
        let rewritten = fs::read_to_string(&file).expect("read");
        assert!(!rewritten.contains("/Users/"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn release_block_on_oracle_mismatch_fails_closed() {
        let err = release_block_on_oracle_mismatch(
            "reentry bundle",
            false,
            &["peak_dynamic_pressure".to_string()],
        )
        .expect_err("mismatch blocked");
        assert!(err.contains("reentry bundle"));
        assert!(err.contains("peak_dynamic_pressure"));
    }
}
