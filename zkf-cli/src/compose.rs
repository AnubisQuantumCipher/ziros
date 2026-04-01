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

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_backends::{
    prover_acceleration_claimed_for_backend, prover_acceleration_scope_for_backend,
};
use zkf_core::{
    BackendKind, FieldElement, FieldId, Program, ProofArtifact, ZkfError, collect_public_inputs,
    generate_witness,
};

use crate::util::{digest_to_field_element, sha256_hex};

pub(crate) fn composition_program_for_digest(
    backend: BackendKind,
    run_id: &str,
    digest_hex: &str,
    aggregate: &crate::AggregateArtifact,
) -> Result<Program, String> {
    let field = backend_default_field(backend);
    let digest_fe = digest_to_field_element(digest_hex, field)?;
    let mut constraints = Vec::new();
    constraints.push(zkf_core::Constraint::Equal {
        lhs: zkf_core::Expr::signal("composition_digest"),
        rhs: zkf_core::Expr::Const(digest_fe.clone()),
        label: Some("composition_digest_matches".to_string()),
    });

    for (index, entry) in aggregate.entries.iter().enumerate() {
        let vk_digest = if entry.verification_key_digest.is_empty() {
            sha256_hex(entry.statement_digest.as_bytes())
        } else {
            entry.verification_key_digest.clone()
        };
        let public_input_commitment = if entry.public_input_commitment.is_empty() {
            let fallback = format!(
                "{}:{}:{}",
                entry.backend, entry.program_digest, entry.proof_digest
            );
            sha256_hex(fallback.as_bytes())
        } else {
            entry.public_input_commitment.clone()
        };
        let statement_fe = digest_to_field_element(&entry.statement_digest, field)?;
        let vk_fe = digest_to_field_element(&vk_digest, field)?;
        let public_inputs_fe = digest_to_field_element(&public_input_commitment, field)?;
        let mut params = BTreeMap::new();
        params.insert("run_id".to_string(), run_id.to_string());
        params.insert("entry_index".to_string(), index.to_string());
        params.insert("carried_backend".to_string(), entry.backend.clone());
        params.insert("proof_digest".to_string(), entry.proof_digest.clone());
        params.insert("program_digest".to_string(), entry.program_digest.clone());
        params.insert(
            "statement_digest".to_string(),
            entry.statement_digest.clone(),
        );
        params.insert("verification_key_digest".to_string(), vk_digest);
        params.insert(
            "public_input_commitment".to_string(),
            public_input_commitment,
        );
        params.insert(
            "statement_digest_v2".to_string(),
            recursive_marker_statement_v2_digest(
                &entry.backend,
                &entry.program_digest,
                &entry.proof_digest,
                params
                    .get("verification_key_digest")
                    .map(String::as_str)
                    .unwrap_or_default(),
                params
                    .get("public_input_commitment")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ),
        );
        constraints.push(zkf_core::Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::RecursiveAggregationMarker,
            inputs: vec![
                zkf_core::Expr::Const(statement_fe),
                zkf_core::Expr::Const(vk_fe),
                zkf_core::Expr::Const(public_inputs_fe),
            ],
            outputs: Vec::new(),
            params,
            label: Some(format!("compose_marker_{index}")),
        });
    }

    Ok(Program {
        name: format!("compose_{}_{}", backend.as_str(), run_id),
        field,
        signals: vec![zkf_core::Signal {
            name: "composition_digest".to_string(),
            visibility: zkf_core::Visibility::Public,
            constant: None,
            ty: None,
        }],
        constraints,
        witness_plan: zkf_core::WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "composition_digest".to_string(),
                expr: zkf_core::Expr::Const(digest_fe),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    })
}

pub(crate) fn compute_composition_digest(
    backend: BackendKind,
    run_id: &str,
    aggregate: &crate::AggregateArtifact,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-compose-v2");
    hasher.update(backend.as_str());
    hasher.update(run_id.as_bytes());
    hasher.update(aggregate.aggregate_digest.as_bytes());
    for entry in &aggregate.entries {
        hasher.update(entry.backend.as_bytes());
        if !entry.statement_digest.is_empty() {
            hasher.update(entry.statement_digest.as_bytes());
        }
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.program_digest.as_bytes());
        hasher.update(entry.verification_key_digest.as_bytes());
        hasher.update(entry.public_input_commitment.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn compute_compose_binding_digest(aggregate: &crate::AggregateArtifact) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-compose-proof-binding-v1");
    hasher.update(aggregate.run_id.as_bytes());
    hasher.update(aggregate.aggregate_digest.as_bytes());
    hasher.update(aggregate.scheme.as_bytes());
    for entry in &aggregate.entries {
        hasher.update(entry.backend.as_bytes());
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.program_digest.as_bytes());
        hasher.update(entry.statement_digest.as_bytes());
        hasher.update(entry.verification_key_digest.as_bytes());
        hasher.update(entry.public_input_commitment.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn compose_proof_semantics() -> &'static str {
    "proof-enforced-digest-equality-plus-host-validated-markers"
}

pub(crate) fn compose_blackbox_semantics() -> &'static str {
    "host-validated-recursive-markers"
}

pub(crate) fn compose_prover_acceleration_scope(backend: BackendKind) -> String {
    if prover_acceleration_claimed_for_backend(backend) {
        "composition-backend-prover-only".to_string()
    } else {
        prover_acceleration_scope_for_backend(backend).to_string()
    }
}

pub(crate) fn compose_proof_metadata_matches(
    artifact: &ProofArtifact,
    aggregate: &crate::AggregateArtifact,
    backend: BackendKind,
    run_id: &str,
    composition_digest: &str,
) -> bool {
    let expected_binding_digest = compute_compose_binding_digest(aggregate);
    let expected_entries = aggregate.entries.len().to_string();
    artifact
        .metadata
        .get("compose_scheme")
        .is_some_and(|value| value == "attestation-composition-v3")
        && artifact
            .metadata
            .get("compose_run_id")
            .is_some_and(|value| value == run_id)
        && artifact
            .metadata
            .get("compose_backend")
            .is_some_and(|value| value == backend.as_str())
        && artifact
            .metadata
            .get("compose_aggregate_digest")
            .is_some_and(|value| value == &aggregate.aggregate_digest)
        && artifact
            .metadata
            .get("compose_composition_digest")
            .is_some_and(|value| value == composition_digest)
        && artifact
            .metadata
            .get("compose_carried_entries")
            .is_some_and(|value| value == &expected_entries)
        && artifact
            .metadata
            .get("compose_binding_digest")
            .is_some_and(|value| value == &expected_binding_digest)
        && artifact
            .metadata
            .get("proof_semantics")
            .is_some_and(|value| value == compose_proof_semantics())
        && artifact
            .metadata
            .get("blackbox_semantics")
            .is_some_and(|value| value == compose_blackbox_semantics())
        && artifact
            .metadata
            .get("prover_acceleration_scope")
            .is_some_and(|value| value == &compose_prover_acceleration_scope(backend))
}

pub(crate) fn compose_expected_public_inputs(
    program: &Program,
) -> Result<Vec<FieldElement>, ZkfError> {
    let witness = generate_witness(program, &BTreeMap::new())?;
    collect_public_inputs(program, &witness)
}

pub(crate) fn compose_report_matches_aggregate(
    compose_report: &crate::ComposeReport,
    aggregate: &crate::AggregateArtifact,
    backend: BackendKind,
    run_id: &str,
) -> bool {
    let expected_backends = aggregate
        .entries
        .iter()
        .map(|entry| entry.backend.clone())
        .collect::<Vec<_>>();
    let expected_statement_digests = aggregate
        .entries
        .iter()
        .map(|entry| entry.statement_digest.clone())
        .collect::<Vec<_>>();
    let expected_vk_digests = aggregate
        .entries
        .iter()
        .map(|entry| entry.verification_key_digest.clone())
        .collect::<Vec<_>>();
    let expected_public_input_commitments = aggregate
        .entries
        .iter()
        .map(|entry| entry.public_input_commitment.clone())
        .collect::<Vec<_>>();
    compose_report.run_id == run_id
        && compose_report.backend == backend.as_str()
        && compose_report.carried_entries == aggregate.entries.len()
        && compose_report.proof_semantics == compose_proof_semantics()
        && compose_report.blackbox_semantics == compose_blackbox_semantics()
        && compose_report.prover_acceleration_scope == compose_prover_acceleration_scope(backend)
        && compose_report.composition_digest
            == compute_composition_digest(backend, run_id, aggregate)
        && compose_report.aggregate_digest == aggregate.aggregate_digest
        && compose_report.carried_backends == expected_backends
        && compose_report.carried_statement_digests == expected_statement_digests
        && compose_report.carried_verification_key_digests == expected_vk_digests
        && compose_report.carried_public_input_commitments == expected_public_input_commitments
}

pub(crate) fn recursive_marker_statement_v2_digest(
    carried_backend: &str,
    program_digest: &str,
    proof_digest: &str,
    verification_key_digest: &str,
    public_input_commitment: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-recursive-marker-statement-v2");
    hasher.update(carried_backend.as_bytes());
    hasher.update(program_digest.as_bytes());
    hasher.update(proof_digest.as_bytes());
    hasher.update(verification_key_digest.as_bytes());
    hasher.update(public_input_commitment.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn statement_digest_for_artifact(
    backend: BackendKind,
    artifact: &ProofArtifact,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-statement-v1");
    hasher.update(backend.as_str().as_bytes());
    hasher.update(artifact.program_digest.as_bytes());
    for value in &artifact.public_inputs {
        hasher.update(value.to_decimal_string().as_bytes());
        hasher.update([0u8]);
    }
    hasher.update(Sha256::digest(artifact.verification_key.as_slice()));
    hasher.update(Sha256::digest(artifact.proof.as_slice()));
    format!("{:x}", hasher.finalize())
}

pub(crate) fn verification_key_digest_for_artifact(artifact: &ProofArtifact) -> String {
    sha256_hex(artifact.verification_key.as_slice())
}

pub(crate) fn public_input_commitment_for_artifact(
    backend: BackendKind,
    artifact: &ProofArtifact,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-public-input-commitment-v1");
    hasher.update(backend.as_str().as_bytes());
    hasher.update(artifact.program_digest.as_bytes());
    for value in &artifact.public_inputs {
        hasher.update(value.to_decimal_string().as_bytes());
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn backend_default_field(backend: BackendKind) -> FieldId {
    match backend {
        BackendKind::ArkworksGroth16 | BackendKind::Nova | BackendKind::HyperNova => FieldId::Bn254,
        BackendKind::Halo2 | BackendKind::MidnightCompact => FieldId::PastaFp,
        BackendKind::Halo2Bls12381 => FieldId::Bls12_381,
        BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => FieldId::Goldilocks,
    }
}
