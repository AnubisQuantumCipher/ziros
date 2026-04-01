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

use zkf_core::{BackendKind, FieldId};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofEmbeddedFieldId {
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
pub(crate) enum ProofEmbeddedBackendKind {
    ArkworksGroth16,
    Plonky3,
    Halo2,
    Halo2Bls12381,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn canonical_input_key_string(
    requested: String,
    alias_target: Option<String>,
) -> String {
    alias_target.unwrap_or(requested)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn digest_bytes_match(expected: Vec<u8>, found: Vec<u8>) -> bool {
    digest_bytes_match_slices(&expected, &found)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn digest_bytes_match_slices(expected: &[u8], found: &[u8]) -> bool {
    match (expected.split_first(), found.split_first()) {
        (None, None) => true,
        (Some((expected_head, expected_tail)), Some((found_head, found_tail))) => {
            expected_head == found_head && digest_bytes_match_slices(expected_tail, found_tail)
        }
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn program_digests_match(expected: String, found: String) -> bool {
    digest_bytes_match(expected.into_bytes(), found.into_bytes())
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProgramMismatchFields {
    pub(crate) expected: String,
    pub(crate) found: String,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn program_digest_guard_accepts(expected: String, found: String) -> bool {
    program_digests_match(expected, found)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn program_mismatch_fields(expected: String, found: String) -> ProgramMismatchFields {
    ProgramMismatchFields { expected, found }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn default_backend_for_proof_field_spec(
    field: ProofEmbeddedFieldId,
) -> ProofEmbeddedBackendKind {
    match field {
        ProofEmbeddedFieldId::Bn254 => ProofEmbeddedBackendKind::ArkworksGroth16,
        ProofEmbeddedFieldId::Bls12_381 => ProofEmbeddedBackendKind::Halo2Bls12381,
        ProofEmbeddedFieldId::PastaFp | ProofEmbeddedFieldId::PastaFq => {
            ProofEmbeddedBackendKind::Halo2
        }
        ProofEmbeddedFieldId::Goldilocks
        | ProofEmbeddedFieldId::BabyBear
        | ProofEmbeddedFieldId::Mersenne31 => ProofEmbeddedBackendKind::Plonky3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[cfg_attr(not(hax), allow(dead_code))]
pub(crate) fn private_identity_merkle_direction_is_binary(direction: u8) -> bool {
    matches!(direction, 0 | 1)
}

#[cfg_attr(hax, hax_lib::include)]
#[cfg_attr(not(hax), allow(dead_code))]
pub(crate) fn private_identity_expected_public_input_arity() -> usize {
    5
}

#[cfg_attr(hax, hax_lib::include)]
#[cfg_attr(not(hax), allow(dead_code))]
pub(crate) fn private_identity_public_input_arity_is_expected(len: usize) -> bool {
    len == private_identity_expected_public_input_arity()
}

pub(crate) fn default_backend_for_field_spec(field: FieldId) -> BackendKind {
    match default_backend_for_proof_field_spec(proof_embedded_field_of_field(field)) {
        ProofEmbeddedBackendKind::ArkworksGroth16 => BackendKind::ArkworksGroth16,
        ProofEmbeddedBackendKind::Plonky3 => BackendKind::Plonky3,
        ProofEmbeddedBackendKind::Halo2 => BackendKind::Halo2,
        ProofEmbeddedBackendKind::Halo2Bls12381 => BackendKind::Halo2Bls12381,
    }
}

fn proof_embedded_field_of_field(field: FieldId) -> ProofEmbeddedFieldId {
    match field {
        FieldId::Bn254 => ProofEmbeddedFieldId::Bn254,
        FieldId::Bls12_381 => ProofEmbeddedFieldId::Bls12_381,
        FieldId::PastaFp => ProofEmbeddedFieldId::PastaFp,
        FieldId::PastaFq => ProofEmbeddedFieldId::PastaFq,
        FieldId::Goldilocks => ProofEmbeddedFieldId::Goldilocks,
        FieldId::BabyBear => ProofEmbeddedFieldId::BabyBear,
        FieldId::Mersenne31 => ProofEmbeddedFieldId::Mersenne31,
    }
}
