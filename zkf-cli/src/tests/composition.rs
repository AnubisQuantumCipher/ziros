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

use super::*;

#[test]
fn composition_program_uses_backend_field_and_public_signal() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: Vec::new(),
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let program = composition_program_for_digest(BackendKind::Nova, "main", "0a", &aggregate)
        .expect("compose IR");
    assert_eq!(program.field, FieldId::Bn254);
    assert_eq!(program.signals.len(), 1);
    assert_eq!(program.signals[0].name, "composition_digest");
    assert_eq!(program.public_signal_names(), vec!["composition_digest"]);
}

#[test]
fn composition_digest_changes_with_backend() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "abc".to_string(),
            program_digest: "def".to_string(),
            statement_digest: "123".to_string(),
            verification_key_digest: "456".to_string(),
            public_input_commitment: "789".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let d1 = compute_composition_digest(BackendKind::Nova, "main", &aggregate);
    let d2 = compute_composition_digest(BackendKind::Sp1, "main", &aggregate);
    assert_ne!(d1, d2);
}

#[test]
fn composition_program_includes_recursive_markers_for_carried_entries() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            program_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            statement_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            verification_key_digest:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            public_input_commitment:
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let program = composition_program_for_digest(BackendKind::Nova, "main", "0a", &aggregate)
        .expect("compose IR");
    assert_eq!(program.constraints.len(), 2, "digest check + one marker");
    let marker = program
        .constraints
        .iter()
        .find_map(|constraint| match constraint {
            Constraint::BlackBox { params, .. } => Some(params),
            _ => None,
        })
        .expect("marker constraint");
    assert_eq!(
        marker.get("carried_backend").map(String::as_str),
        Some("arkworks-groth16")
    );
    assert_eq!(
        marker
            .get("verification_key_digest")
            .map(String::as_str)
            .unwrap_or_default()
            .len(),
        64
    );
    assert_eq!(
        marker
            .get("statement_digest_v2")
            .map(String::as_str)
            .unwrap_or_default()
            .len(),
        64
    );
}

#[test]
fn composition_digest_changes_when_vk_or_public_input_commitment_changes() {
    let mut aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "abc".to_string(),
            program_digest: "def".to_string(),
            statement_digest: "123".to_string(),
            verification_key_digest: "456".to_string(),
            public_input_commitment: "789".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let original = compute_composition_digest(BackendKind::Nova, "main", &aggregate);
    aggregate.entries[0].verification_key_digest = "999".to_string();
    let vk_changed = compute_composition_digest(BackendKind::Nova, "main", &aggregate);
    assert_ne!(original, vk_changed);
    aggregate.entries[0].verification_key_digest = "456".to_string();
    aggregate.entries[0].public_input_commitment = "111".to_string();
    let pi_changed = compute_composition_digest(BackendKind::Nova, "main", &aggregate);
    assert_ne!(original, pi_changed);
}

#[test]
fn compose_proof_metadata_match_requires_all_binding_fields() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            program_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            statement_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            verification_key_digest:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            public_input_commitment:
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let composition_digest = compute_composition_digest(BackendKind::Nova, "main", &aggregate);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "compose_scheme".to_string(),
        "attestation-composition-v3".to_string(),
    );
    metadata.insert("compose_run_id".to_string(), "main".to_string());
    metadata.insert(
        "compose_backend".to_string(),
        BackendKind::Nova.as_str().to_string(),
    );
    metadata.insert(
        "compose_aggregate_digest".to_string(),
        aggregate.aggregate_digest.clone(),
    );
    metadata.insert(
        "compose_composition_digest".to_string(),
        composition_digest.clone(),
    );
    metadata.insert("compose_carried_entries".to_string(), "1".to_string());
    metadata.insert(
        "compose_binding_digest".to_string(),
        compute_compose_binding_digest(&aggregate),
    );
    metadata.insert(
        "proof_semantics".to_string(),
        compose_proof_semantics().to_string(),
    );
    metadata.insert(
        "blackbox_semantics".to_string(),
        compose_blackbox_semantics().to_string(),
    );
    metadata.insert(
        "prover_acceleration_scope".to_string(),
        compose_prover_acceleration_scope(BackendKind::Nova),
    );
    let artifact = ProofArtifact {
        backend: BackendKind::Nova,
        program_digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_string(),
        proof: vec![1, 2, 3],
        verification_key: vec![4, 5, 6],
        public_inputs: vec![FieldElement::from_i64(7)],
        metadata: metadata.clone(),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    assert!(compose_proof_metadata_matches(
        &artifact,
        &aggregate,
        BackendKind::Nova,
        "main",
        &composition_digest
    ));

    let mut missing = artifact.clone();
    missing.metadata.remove("compose_binding_digest");
    assert!(!compose_proof_metadata_matches(
        &missing,
        &aggregate,
        BackendKind::Nova,
        "main",
        &composition_digest
    ));
}

#[test]
fn compose_expected_public_inputs_match_digest_signal() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: Vec::new(),
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };
    let program = composition_program_for_digest(BackendKind::Nova, "main", "0a", &aggregate)
        .expect("compose program");
    let expected_inputs = compose_expected_public_inputs(&program).expect("public inputs");
    assert_eq!(expected_inputs.len(), 1);
    assert_eq!(
        expected_inputs[0],
        digest_to_field_element("0a", FieldId::Bn254).unwrap()
    );
}

#[test]
fn compose_report_match_requires_exact_v3_metadata() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            program_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            statement_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            verification_key_digest:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            public_input_commitment:
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };

    let compose_report = ComposeReport {
        run_id: "main".to_string(),
        backend: BackendKind::Nova.as_str().to_string(),
        carried_entries: aggregate.entries.len(),
        aggregate_digest: aggregate.aggregate_digest.clone(),
        composition_digest: compute_composition_digest(BackendKind::Nova, "main", &aggregate),
        proof_semantics: compose_proof_semantics().to_string(),
        blackbox_semantics: compose_blackbox_semantics().to_string(),
        prover_acceleration_scope: compose_prover_acceleration_scope(BackendKind::Nova),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "not-measured".to_string(),
        carried_backends: aggregate
            .entries
            .iter()
            .map(|entry| entry.backend.clone())
            .collect(),
        carried_statement_digests: aggregate
            .entries
            .iter()
            .map(|entry| entry.statement_digest.clone())
            .collect(),
        carried_verification_key_digests: aggregate
            .entries
            .iter()
            .map(|entry| entry.verification_key_digest.clone())
            .collect(),
        carried_public_input_commitments: aggregate
            .entries
            .iter()
            .map(|entry| entry.public_input_commitment.clone())
            .collect(),
    };

    assert!(compose_report_matches_aggregate(
        &compose_report,
        &aggregate,
        BackendKind::Nova,
        "main"
    ));
}

#[test]
fn compose_report_match_rejects_legacy_empty_digest_lists() {
    let aggregate = AggregateArtifact {
        run_id: "main".to_string(),
        entries: vec![BundleEntry {
            backend: "arkworks-groth16".to_string(),
            proof_path: "proofs/arkworks/main/proof.json".to_string(),
            proof_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            program_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            statement_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            verification_key_digest:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            public_input_commitment:
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        }],
        aggregate_digest: "feed".to_string(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };

    let compose_report = ComposeReport {
        run_id: "main".to_string(),
        backend: BackendKind::Nova.as_str().to_string(),
        carried_entries: aggregate.entries.len(),
        aggregate_digest: aggregate.aggregate_digest.clone(),
        composition_digest: compute_composition_digest(BackendKind::Nova, "main", &aggregate),
        proof_semantics: compose_proof_semantics().to_string(),
        blackbox_semantics: compose_blackbox_semantics().to_string(),
        prover_acceleration_scope: compose_prover_acceleration_scope(BackendKind::Nova),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "not-measured".to_string(),
        carried_backends: aggregate
            .entries
            .iter()
            .map(|entry| entry.backend.clone())
            .collect(),
        carried_statement_digests: Vec::new(),
        carried_verification_key_digests: Vec::new(),
        carried_public_input_commitments: Vec::new(),
    };

    assert!(!compose_report_matches_aggregate(
        &compose_report,
        &aggregate,
        BackendKind::Nova,
        "main"
    ));
}

#[test]
fn artifact_commitments_change_when_vk_or_public_inputs_change() {
    let mut artifact = ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        proof: vec![1, 2, 3],
        verification_key: vec![4, 5, 6],
        public_inputs: vec![FieldElement::from_i64(7)],
        metadata: BTreeMap::new(),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };

    let vk_a = verification_key_digest_for_artifact(&artifact);
    let pi_a = public_input_commitment_for_artifact(BackendKind::ArkworksGroth16, &artifact);

    artifact.verification_key[0] ^= 0x01;
    let vk_b = verification_key_digest_for_artifact(&artifact);
    assert_ne!(vk_a, vk_b);

    artifact.public_inputs[0] = FieldElement::from_i64(8);
    let pi_b = public_input_commitment_for_artifact(BackendKind::ArkworksGroth16, &artifact);
    assert_ne!(pi_a, pi_b);
}

#[test]
fn render_sp1_solidity_verifier_renders_native_wrapper_when_metadata_present() {
    let mut metadata = BTreeMap::new();
    metadata.insert("sp1_program_vkey_bn254".to_string(), "1".to_string());
    metadata.insert("sp1_public_values_hash_bn254".to_string(), "2".to_string());
    metadata.insert(
        "sp1_onchain_proof_sha256".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );
    metadata.insert(
        "sp1_onchain_proof_selector".to_string(),
        "0x01020304".to_string(),
    );

    let artifact = ProofArtifact {
        backend: BackendKind::Sp1,
        program_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        proof: vec![1, 2, 3, 4],
        verification_key: vec![5, 6, 7],
        public_inputs: Vec::new(),
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    let source = render_sp1_solidity_verifier(&artifact).expect("solidity should render");
    assert!(source.contains("contract ZkfSp1BoundVerifier"));
    assert!(source.contains("interface ISP1Verifier"));
    assert!(source.contains(
        "PROGRAM_VKEY = 0x0000000000000000000000000000000000000000000000000000000000000001"
    ));
    assert!(source.contains(
        "PUBLIC_VALUES_DIGEST = 0x0000000000000000000000000000000000000000000000000000000000000002"
    ));
    assert!(source.contains("PROOF_SELECTOR = 0x01020304"));
    assert!(source.contains("verifier.verifyProof(PROGRAM_VKEY, publicValues, proofBytes)"));
}

#[test]
fn render_sp1_solidity_verifier_falls_back_to_attestation_without_metadata() {
    let artifact = ProofArtifact {
        backend: BackendKind::Sp1,
        program_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        proof: vec![1, 2, 3, 4],
        verification_key: vec![5, 6, 7],
        public_inputs: Vec::new(),
        metadata: BTreeMap::new(),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    let source = render_sp1_solidity_verifier(&artifact).expect("solidity should render");
    assert!(source.contains("contract ZkfSp1ProofAttestation"));
    assert!(source.contains("PROOF_SHA256"));
    assert!(source.contains("verifyAttestation(bytes calldata proof"));
}

#[test]
fn render_sp1_solidity_verifier_accepts_public_values_base64_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("sp1_program_vkey_bn254".to_string(), "1".to_string());
    metadata.insert(
        "sp1_public_values_base64".to_string(),
        "cHVibGljLXZhbHVlcy1kZW1v".to_string(),
    );
    metadata.insert(
        "sp1_onchain_proof_sha256".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );

    let artifact = ProofArtifact {
        backend: BackendKind::Sp1,
        program_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        proof: vec![1, 2, 3, 4],
        verification_key: vec![5, 6, 7],
        public_inputs: Vec::new(),
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    let source = render_sp1_solidity_verifier(&artifact).expect("solidity should render");
    assert!(source.contains("contract ZkfSp1BoundVerifier"));
    assert!(source.contains(
        "PUBLIC_VALUES_DIGEST = 0x10a288d8195b7c57c1c7d32b3dba7cc114bd956263d796efe125e58bc8ef8a5a"
    ));
}

#[test]
fn render_groth16_solidity_verifier_produces_nonzero_vk_from_real_proof() {
    // Build a real Groth16 proof so we get a real compressed VK
    let program = Program {
        name: "groth16_sol_test".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "y".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: zkf_core::Expr::Signal("x".to_string()),
            rhs: zkf_core::Expr::Mul(
                Box::new(zkf_core::Expr::Signal("y".to_string())),
                Box::new(zkf_core::Expr::Signal("y".to_string())),
            ),
            label: Some("x_eq_y_squared".to_string()),
        }],
        ..Default::default()
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile should succeed");

    let mut witness = Witness::default();
    witness
        .values
        .insert("x".to_string(), FieldElement::from_i64(9));
    witness
        .values
        .insert("y".to_string(), FieldElement::from_i64(3));

    let artifact = backend
        .prove(&compiled, &witness)
        .expect("prove should succeed");

    // The VK should be non-empty arkworks compressed data
    assert!(
        !artifact.verification_key.is_empty(),
        "VK should not be empty"
    );

    let source = render_groth16_solidity_verifier(&artifact, "TestVerifier");

    // Should contain the contract
    assert!(
        source.contains("contract TestVerifier"),
        "Should have the contract name"
    );

    // The VK constants should NOT be all zeros
    let all_zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    // Check that alpha_g1 is not zero (it appears as the first uint256 in verifyingKey())
    let alpha_line = source
        .lines()
        .find(|l| l.contains("vk.alpha1 = Pairing.G1Point("))
        .expect("should have alpha1 line");
    assert!(
        !alpha_line.contains(all_zero),
        "alpha_g1 should not be zeroed. Got: {}",
        alpha_line.trim()
    );

    // Check IC has at least 2 entries (constant term + 1 public input)
    let ic_count = source.matches("vk.IC[").count();
    assert!(
        ic_count >= 2,
        "IC should have at least 2 entries (got {ic_count})"
    );

    // IC entries should not be zero
    let ic0_line = source
        .lines()
        .find(|l| l.contains("vk.IC[0]"))
        .expect("should have IC[0]");
    assert!(
        !ic0_line.contains(all_zero),
        "IC[0] should not be zeroed. Got: {}",
        ic0_line.trim()
    );
}

#[test]
fn render_groth16_solidity_verifier_falls_back_to_zeros_for_empty_vk() {
    let artifact = ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: "0".repeat(64),
        proof: vec![],
        verification_key: vec![],
        public_inputs: Vec::new(),
        metadata: BTreeMap::new(),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    let source = render_groth16_solidity_verifier(&artifact, "EmptyVkVerifier");

    // Should still produce valid Solidity with zeroed constants
    assert!(source.contains("contract EmptyVkVerifier"));
    let all_zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    assert!(
        source.contains(all_zero),
        "Empty VK should fall back to zeroed constants"
    );
}
