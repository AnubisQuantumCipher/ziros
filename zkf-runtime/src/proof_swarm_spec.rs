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

use zkf_core::artifact::ProofArtifact;

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn preserve_successful_artifact_bytes(artifact: Vec<u8>) -> Vec<u8> {
    artifact
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn artifact_bytes_eq(left: [u8; 4], right: [u8; 4]) -> bool {
    left[0] == right[0] && left[1] == right[1] && left[2] == right[2] && left[3] == right[3]
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProofSwarmActivationLevel {
    Dormant,
    Alert,
    Active,
    Emergency,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofDisabledSwarmSurfaceState {
    pub activation_level: ProofSwarmActivationLevel,
    pub verdict_activation_level: ProofSwarmActivationLevel,
    pub threat_digest_count: usize,
    pub consensus_confirmed: bool,
    pub telemetry_present: bool,
    pub bias_basis_points: u16,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn activation_level_rank(level: ProofSwarmActivationLevel) -> u8 {
    match level {
        ProofSwarmActivationLevel::Dormant => 0,
        ProofSwarmActivationLevel::Alert => 1,
        ProofSwarmActivationLevel::Active => 2,
        ProofSwarmActivationLevel::Emergency => 3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn disabled_surface_state_spec() -> ProofDisabledSwarmSurfaceState {
    ProofDisabledSwarmSurfaceState {
        activation_level: ProofSwarmActivationLevel::Dormant,
        verdict_activation_level: ProofSwarmActivationLevel::Dormant,
        threat_digest_count: 0,
        consensus_confirmed: false,
        telemetry_present: false,
        bias_basis_points: 1000,
    }
}

pub(crate) fn preserve_successful_proof_artifact(artifact: ProofArtifact) -> ProofArtifact {
    artifact
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn controller_artifact_path(
    enabled: bool,
    artifact: [u8; 4],
    reject: bool,
) -> Result<[u8; 4], ()> {
    match (enabled, reject) {
        (false, _) => Ok(artifact),
        (true, true) => Err(()),
        (true, false) => Ok(artifact),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn controller_artifact_path_matches_pure_helper(
    enabled: bool,
    artifact: [u8; 4],
    reject: bool,
) -> bool {
    match controller_artifact_path(enabled, artifact, reject) {
        Ok(artifact_out) => artifact_bytes_eq(artifact_out, artifact),
        Err(()) => enabled && reject,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn successful_artifact_path_preserves_bytes(enabled: bool, artifact: [u8; 4]) -> bool {
    match controller_artifact_path(enabled, artifact, false) {
        Ok(artifact_out) => artifact_bytes_eq(artifact_out, artifact),
        Err(()) => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn encrypted_gossip_artifact_projection(artifact: [u8; 4]) -> [u8; 4] {
    artifact
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn encrypted_gossip_surface_preserves_artifact_bytes(artifact: [u8; 4]) -> bool {
    artifact_bytes_eq(encrypted_gossip_artifact_projection(artifact), artifact)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn encrypted_gossip_fail_closed_spec(
    negotiated: bool,
    plaintext_present: bool,
    encrypted_payload_present: bool,
) -> bool {
    if negotiated {
        !plaintext_present
    } else {
        !plaintext_present && !encrypted_payload_present
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn controller_artifact_mutation_surface_count() -> usize {
    0
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn cooldown_tick_level(
    level: ProofSwarmActivationLevel,
    cooldown_active: bool,
) -> ProofSwarmActivationLevel {
    if cooldown_active {
        level
    } else {
        match level {
            ProofSwarmActivationLevel::Dormant => ProofSwarmActivationLevel::Dormant,
            ProofSwarmActivationLevel::Alert => ProofSwarmActivationLevel::Dormant,
            ProofSwarmActivationLevel::Active => ProofSwarmActivationLevel::Alert,
            ProofSwarmActivationLevel::Emergency => ProofSwarmActivationLevel::Active,
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn cooldown_tick_is_non_deescalating(level: ProofSwarmActivationLevel) -> bool {
    match level {
        ProofSwarmActivationLevel::Dormant => matches!(
            cooldown_tick_level(level, true),
            ProofSwarmActivationLevel::Dormant
        ),
        ProofSwarmActivationLevel::Alert => matches!(
            cooldown_tick_level(level, true),
            ProofSwarmActivationLevel::Alert
        ),
        ProofSwarmActivationLevel::Active => matches!(
            cooldown_tick_level(level, true),
            ProofSwarmActivationLevel::Active
        ),
        ProofSwarmActivationLevel::Emergency => matches!(
            cooldown_tick_level(level, true),
            ProofSwarmActivationLevel::Emergency
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn cooldown_tick_drops_at_most_one_level(level: ProofSwarmActivationLevel) -> bool {
    match level {
        ProofSwarmActivationLevel::Dormant => matches!(
            cooldown_tick_level(level, false),
            ProofSwarmActivationLevel::Dormant
        ),
        ProofSwarmActivationLevel::Alert => matches!(
            cooldown_tick_level(level, false),
            ProofSwarmActivationLevel::Dormant
        ),
        ProofSwarmActivationLevel::Active => matches!(
            cooldown_tick_level(level, false),
            ProofSwarmActivationLevel::Alert
        ),
        ProofSwarmActivationLevel::Emergency => matches!(
            cooldown_tick_level(level, false),
            ProofSwarmActivationLevel::Active
        ),
    }
}
