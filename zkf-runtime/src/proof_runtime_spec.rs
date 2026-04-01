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

#![allow(dead_code)]

use zkf_core::{BackendKind, FieldId};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofRuntimeFieldId {
    Bn254,
    Bls12_381,
    PastaFp,
    PastaFq,
    Goldilocks,
    BabyBear,
    Mersenne31,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofRuntimeBackendKind {
    ArkworksGroth16,
    Plonky3,
    Nova,
    HyperNova,
    Halo2,
    Halo2Bls12381,
    Sp1,
    RiscZero,
    MidnightCompact,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn preferred_backend_for_proof_field_spec(
    field: ProofRuntimeFieldId,
) -> ProofRuntimeBackendKind {
    match field {
        ProofRuntimeFieldId::Bn254 => ProofRuntimeBackendKind::ArkworksGroth16,
        ProofRuntimeFieldId::Bls12_381 => ProofRuntimeBackendKind::Halo2Bls12381,
        ProofRuntimeFieldId::PastaFp | ProofRuntimeFieldId::PastaFq => {
            ProofRuntimeBackendKind::Halo2
        }
        ProofRuntimeFieldId::Goldilocks
        | ProofRuntimeFieldId::BabyBear
        | ProofRuntimeFieldId::Mersenne31 => ProofRuntimeBackendKind::Plonky3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn default_backend_candidates_for_proof_field(
    field: ProofRuntimeFieldId,
) -> Vec<ProofRuntimeBackendKind> {
    match field {
        ProofRuntimeFieldId::Bn254 => vec![
            ProofRuntimeBackendKind::ArkworksGroth16,
            ProofRuntimeBackendKind::Plonky3,
            ProofRuntimeBackendKind::Nova,
            ProofRuntimeBackendKind::HyperNova,
            ProofRuntimeBackendKind::Halo2,
            ProofRuntimeBackendKind::Halo2Bls12381,
            ProofRuntimeBackendKind::Sp1,
            ProofRuntimeBackendKind::RiscZero,
            ProofRuntimeBackendKind::MidnightCompact,
        ],
        ProofRuntimeFieldId::Bls12_381 => vec![
            ProofRuntimeBackendKind::Halo2Bls12381,
            ProofRuntimeBackendKind::ArkworksGroth16,
            ProofRuntimeBackendKind::Plonky3,
            ProofRuntimeBackendKind::Nova,
            ProofRuntimeBackendKind::HyperNova,
            ProofRuntimeBackendKind::Halo2,
            ProofRuntimeBackendKind::Sp1,
            ProofRuntimeBackendKind::RiscZero,
            ProofRuntimeBackendKind::MidnightCompact,
        ],
        ProofRuntimeFieldId::PastaFp | ProofRuntimeFieldId::PastaFq => vec![
            ProofRuntimeBackendKind::Halo2,
            ProofRuntimeBackendKind::ArkworksGroth16,
            ProofRuntimeBackendKind::Plonky3,
            ProofRuntimeBackendKind::Nova,
            ProofRuntimeBackendKind::HyperNova,
            ProofRuntimeBackendKind::Halo2Bls12381,
            ProofRuntimeBackendKind::Sp1,
            ProofRuntimeBackendKind::RiscZero,
            ProofRuntimeBackendKind::MidnightCompact,
        ],
        ProofRuntimeFieldId::Goldilocks
        | ProofRuntimeFieldId::BabyBear
        | ProofRuntimeFieldId::Mersenne31 => vec![
            ProofRuntimeBackendKind::Plonky3,
            ProofRuntimeBackendKind::ArkworksGroth16,
            ProofRuntimeBackendKind::Nova,
            ProofRuntimeBackendKind::HyperNova,
            ProofRuntimeBackendKind::Halo2,
            ProofRuntimeBackendKind::Halo2Bls12381,
            ProofRuntimeBackendKind::Sp1,
            ProofRuntimeBackendKind::RiscZero,
            ProofRuntimeBackendKind::MidnightCompact,
        ],
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn runtime_default_backend_candidates_are_nonempty(_field: ProofRuntimeFieldId) -> bool {
    true
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hybrid_verify_decision_spec(primary_ok: bool, companion_ok: bool) -> bool {
    primary_ok && companion_ok
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn runtime_digest_bytes_match(expected: Vec<u8>, found: Vec<u8>) -> bool {
    runtime_digest_bytes_match_slices(&expected, &found)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn runtime_digest_bytes_match_slices(expected: &[u8], found: &[u8]) -> bool {
    match (expected.split_first(), found.split_first()) {
        (None, None) => true,
        (Some((expected_head, expected_tail)), Some((found_head, found_tail))) => {
            expected_head == found_head
                && runtime_digest_bytes_match_slices(expected_tail, found_tail)
        }
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn digest_matches_recorded_hash_spec(
    recorded_hash: Option<Vec<u8>>,
    expected_hash: Vec<u8>,
) -> bool {
    match recorded_hash {
        Some(recorded) => runtime_digest_bytes_match(recorded, expected_hash),
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProofRuntimeHardwareProbeSummary {
    pub ok: bool,
    pub mismatch_free: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hardware_probes_clean_spec(summary: ProofRuntimeHardwareProbeSummary) -> bool {
    summary.ok && summary.mismatch_free
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hybrid_primary_leg_byte_components_match_spec(
    artifact_proof: Vec<u8>,
    artifact_verification_key: Vec<u8>,
    primary_leg_proof: Vec<u8>,
    primary_leg_verification_key: Vec<u8>,
) -> bool {
    runtime_digest_bytes_match(artifact_proof, primary_leg_proof)
        && runtime_digest_bytes_match(artifact_verification_key, primary_leg_verification_key)
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProofRuntimeReplayManifestIdentity {
    pub replay_id: String,
    pub transcript_hash: String,
    pub backend_route: String,
    pub hardware_profile: String,
    pub stage_manifest_digest: String,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn replay_manifest_identity_is_deterministic_spec(
    _manifest: ProofRuntimeReplayManifestIdentity,
) -> bool {
    true
}

pub(crate) fn default_backend_candidates_for_field(field: FieldId) -> Vec<BackendKind> {
    default_backend_candidates_for_proof_field(proof_runtime_field_of_field(field))
        .into_iter()
        .map(proof_backend_to_backend_kind)
        .collect()
}

fn proof_runtime_field_of_field(field: FieldId) -> ProofRuntimeFieldId {
    match field {
        FieldId::Bn254 => ProofRuntimeFieldId::Bn254,
        FieldId::Bls12_381 => ProofRuntimeFieldId::Bls12_381,
        FieldId::PastaFp => ProofRuntimeFieldId::PastaFp,
        FieldId::PastaFq => ProofRuntimeFieldId::PastaFq,
        FieldId::Goldilocks => ProofRuntimeFieldId::Goldilocks,
        FieldId::BabyBear => ProofRuntimeFieldId::BabyBear,
        FieldId::Mersenne31 => ProofRuntimeFieldId::Mersenne31,
    }
}

fn proof_backend_to_backend_kind(kind: ProofRuntimeBackendKind) -> BackendKind {
    match kind {
        ProofRuntimeBackendKind::ArkworksGroth16 => BackendKind::ArkworksGroth16,
        ProofRuntimeBackendKind::Plonky3 => BackendKind::Plonky3,
        ProofRuntimeBackendKind::Nova => BackendKind::Nova,
        ProofRuntimeBackendKind::HyperNova => BackendKind::HyperNova,
        ProofRuntimeBackendKind::Halo2 => BackendKind::Halo2,
        ProofRuntimeBackendKind::Halo2Bls12381 => BackendKind::Halo2Bls12381,
        ProofRuntimeBackendKind::Sp1 => BackendKind::Sp1,
        ProofRuntimeBackendKind::RiscZero => BackendKind::RiscZero,
        ProofRuntimeBackendKind::MidnightCompact => BackendKind::MidnightCompact,
    }
}
