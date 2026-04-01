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

use crate::control_plane::ControlPlaneReplayManifest;
use crate::control_plane::HardwareProbeSummary;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::{HybridProofBundle, ProofArtifact};

pub(crate) fn hardware_probes_clean(hardware_probes: &HardwareProbeSummary) -> bool {
    hardware_probes.ok && hardware_probes.mismatch_count == 0
}

pub(crate) fn hybrid_verify_decision(primary_ok: bool, companion_ok: bool) -> bool {
    primary_ok && companion_ok
}

pub(crate) fn hybrid_primary_leg_byte_components_match(
    artifact_proof: &[u8],
    artifact_verification_key: &[u8],
    primary_leg_proof: &[u8],
    primary_leg_verification_key: &[u8],
) -> bool {
    artifact_proof == primary_leg_proof && artifact_verification_key == primary_leg_verification_key
}

#[allow(dead_code)]
pub(crate) fn hybrid_primary_leg_matches_outer_artifact(
    artifact: &ProofArtifact,
    bundle: &HybridProofBundle,
) -> bool {
    hybrid_primary_leg_byte_components_match(
        &artifact.proof,
        &artifact.verification_key,
        &bundle.primary_leg.proof,
        &bundle.primary_leg.verification_key,
    ) && bundle.primary_leg.public_inputs == artifact.public_inputs
}

pub(crate) fn public_inputs_digest_from_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn digest_matches_recorded_hash(
    recorded_hash: Option<&str>,
    expected_hash: &str,
) -> bool {
    recorded_hash.is_some_and(|recorded| recorded == expected_hash)
}

#[allow(dead_code)]
pub(crate) fn transcript_hash_entry_matches(
    transcript_hashes: &BTreeMap<String, String>,
    label: &str,
    expected_hash: &str,
) -> bool {
    digest_matches_recorded_hash(
        transcript_hashes.get(label).map(String::as_str),
        expected_hash,
    )
}

#[allow(dead_code)]
pub(crate) fn hybrid_public_inputs_digest_entry_matches(
    transcript_hashes: &BTreeMap<String, String>,
    recomputed_public_inputs_hash: &str,
) -> bool {
    transcript_hash_entry_matches(
        transcript_hashes,
        "public-inputs",
        recomputed_public_inputs_hash,
    )
}

#[allow(dead_code)]
pub(crate) fn hybrid_public_inputs_hash_matches(
    transcript_hashes: &BTreeMap<String, String>,
    public_inputs_bytes: &[u8],
) -> bool {
    hybrid_public_inputs_digest_entry_matches(
        transcript_hashes,
        &public_inputs_digest_from_bytes(public_inputs_bytes),
    )
}

pub(crate) fn replay_manifest_identity_components(
    manifest: &ControlPlaneReplayManifest,
) -> (&str, &str, &str, &str, &str) {
    (
        manifest.replay_id.as_str(),
        manifest.transcript_hash.as_str(),
        manifest.backend_route.as_str(),
        manifest.hardware_profile.as_str(),
        manifest.stage_manifest_digest.as_str(),
    )
}

pub(crate) fn replay_manifest_identity_is_deterministic(
    manifest: &ControlPlaneReplayManifest,
) -> bool {
    replay_manifest_identity_components(manifest)
        == replay_manifest_identity_components(&manifest.clone())
}
