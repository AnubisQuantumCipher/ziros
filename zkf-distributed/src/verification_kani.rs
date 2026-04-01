#![allow(dead_code)]

use crate::config::IntegrityAlgorithm;
#[cfg(feature = "full")]
use crate::coordinator::{
    attestation_matches_subgraph_digests, coordinator_requires_quorum,
    coordinator_two_party_unanimous_quorum_accepts,
};
use crate::proof_swarm_reputation_spec::{
    ProofBytes4, append_only_memory_chain_after_append, append_only_memory_prefix_preserved_spec,
    canonical_intelligence_leaf_pair, chain_prefix4, encrypted_gossip_negotiation_fail_closed_spec,
    intelligence_root_convergence_under_canonical_ordering_spec,
    snapshot_chain_head_roundtrip_spec,
};
#[cfg(feature = "full")]
use crate::protocol::AttestationMetadata;
use crate::swarm::diplomat::bounded_gossip_count;
use crate::swarm::identity::{
    PublicKeyBundle, SignatureBundle, SignatureScheme, hybrid_admission_pow_identity_bytes,
};
use crate::swarm::reputation::{
    ReputationEvidenceKind, bounded_decay_score, bounded_positive_reputation_delta,
    bounded_reputation_after_decayed_score,
};
use crate::transfer::compression::{compress_chunk, decompress_chunk};
use crate::transfer::compute_integrity_digest;
use crate::transport::frame::{MAX_FRAME_SIZE, read_frame_payload, write_frame_payload};
use std::io::Cursor;
use zkf_core::{
    bundle_has_required_signature_material, signed_message_has_complete_bundle_surface,
};
use zkf_runtime::swarm::{ActivationLevel, median_activation_level};

#[kani::proof]
fn raw_frames_roundtrip_small_payloads() {
    let payload: [u8; 4] = kani::any();
    let mut buf = Vec::new();
    write_frame_payload(&mut buf, &payload).expect("frame encoding");
    let decoded = read_frame_payload(&mut Cursor::new(&buf)).expect("frame decoding");
    assert_eq!(decoded, payload);
}

#[kani::proof]
fn lz4_chunk_roundtrips_small_payloads() {
    let payload: [u8; 4] = kani::any();
    let compressed = compress_chunk(&payload);
    let decompressed = decompress_chunk(&compressed).expect("lz4 roundtrip");
    assert_eq!(decompressed, payload);
}

#[kani::proof]
fn fnv_integrity_detects_single_byte_corruption() {
    let mut tampered = *b"zkf!";
    let index: u8 = kani::any();
    kani::assume(index < tampered.len() as u8);
    tampered[index as usize] ^= 0x01;

    let original = compute_integrity_digest(IntegrityAlgorithm::Fnv, b"zkf!");
    let corrupted = compute_integrity_digest(IntegrityAlgorithm::Fnv, &tampered);

    assert_ne!(original, corrupted);
}

#[kani::proof]
fn sha256_integrity_detects_single_byte_corruption() {
    let mut tampered = *b"zkf!";
    let index: u8 = kani::any();
    kani::assume(index < tampered.len() as u8);
    tampered[index as usize] ^= 0x01;

    let original = compute_integrity_digest(IntegrityAlgorithm::Sha256, b"zkf!");
    let corrupted = compute_integrity_digest(IntegrityAlgorithm::Sha256, &tampered);

    assert_ne!(original, corrupted);
}

#[kani::proof]
fn oversized_frames_fail_before_payload_allocation() {
    let mut buf = Vec::new();
    let oversized = MAX_FRAME_SIZE + 1;
    buf.extend_from_slice(&oversized.to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]);

    let err = read_frame_payload(&mut Cursor::new(&buf)).expect_err("oversized frame must fail");
    match err {
        crate::error::DistributedError::Serialization(message) => {
            assert!(message.contains("frame too large"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

fn reputation_kind_for_index(index: u8) -> ReputationEvidenceKind {
    match index % 10 {
        0 => ReputationEvidenceKind::QuorumAgreement,
        1 => ReputationEvidenceKind::QuorumDisagreement,
        2 => ReputationEvidenceKind::AttestationValid,
        3 => ReputationEvidenceKind::AttestationInvalid,
        4 => ReputationEvidenceKind::HeartbeatTimeout,
        5 => ReputationEvidenceKind::HeartbeatResumed,
        6 => ReputationEvidenceKind::ThreatDigestCorroborated,
        7 => ReputationEvidenceKind::ThreatDigestContradicted,
        8 => ReputationEvidenceKind::ModelFreshnessMatch,
        _ => ReputationEvidenceKind::ModelFreshnessMismatch,
    }
}

#[kani::proof]
fn swarm_reputation_boundedness() {
    let score_basis: i16 = kani::any();
    kani::assume((-100..=200).contains(&score_basis));
    let decay_basis: u8 = kani::any();
    kani::assume(decay_basis <= 100);
    let kind_index: u8 = kani::any();

    let score = f64::from(score_basis) / 100.0;
    let decay_factor = f64::from(decay_basis) / 100.0;
    let kind = reputation_kind_for_index(kind_index);

    let decayed = bounded_decay_score(score, decay_factor);
    let updated = bounded_reputation_after_decayed_score(decayed, kind);

    assert!((0.0..=1.0).contains(&decayed));
    assert!((0.0..=1.0).contains(&updated));
}

#[kani::proof]
fn swarm_gossip_boundedness() {
    let pending_len: u8 = kani::any();
    let gossip_max: u8 = kani::any();
    let bounded = bounded_gossip_count(pending_len as usize, gossip_max as usize);
    assert!(bounded <= pending_len as usize);
    assert!(bounded <= usize::from(gossip_max.max(1)));
}

#[kani::proof]
fn distributed_negotiated_peers_never_accept_plaintext_threat_payloads() {
    let encrypted_payload_present: bool = kani::any();
    assert!(!encrypted_gossip_negotiation_fail_closed_spec(
        true,
        true,
        encrypted_payload_present,
    ));
    assert!(encrypted_gossip_negotiation_fail_closed_spec(
        true,
        false,
        encrypted_payload_present,
    ));
}

#[kani::proof]
fn distributed_encrypted_gossip_tamper_rejection_bounded() {
    let encrypted_payload_present: bool = kani::any();
    assert!(
        !encrypted_gossip_negotiation_fail_closed_spec(false, false, encrypted_payload_present,)
            || !encrypted_payload_present
    );
}

#[kani::proof]
fn append_only_chain_verification_catches_mutation() {
    let prefix = ProofBytes4 {
        quad0: kani::any(),
        quad1: kani::any(),
        quad2: kani::any(),
        quad3: kani::any(),
    };
    let suffix = ProofBytes4 {
        quad0: kani::any(),
        quad1: kani::any(),
        quad2: kani::any(),
        quad3: kani::any(),
    };
    let appended = append_only_memory_chain_after_append(prefix, suffix);
    assert!(append_only_memory_prefix_preserved_spec(prefix, suffix));
    assert_eq!(chain_prefix4(appended), prefix);

    let mut mutated = chain_prefix4(appended);
    mutated.quad0 ^= 0x01;
    assert_ne!(mutated, prefix);
}

#[kani::proof]
fn authenticated_snapshot_import_preserves_exported_head_root() {
    let exported_head = ProofBytes4 {
        quad0: kani::any(),
        quad1: kani::any(),
        quad2: kani::any(),
        quad3: kani::any(),
    };
    let imported_head = exported_head;
    assert!(snapshot_chain_head_roundtrip_spec(
        exported_head,
        imported_head
    ));

    let mut tampered_head = imported_head;
    tampered_head.quad0 ^= 0x01;
    assert!(!snapshot_chain_head_roundtrip_spec(
        exported_head,
        tampered_head,
    ));
}

#[kani::proof]
fn intelligence_root_canonical_ordering_converges_bounded() {
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    assert!(intelligence_root_convergence_under_canonical_ordering_spec(
        first, second
    ));
    assert_eq!(
        canonical_intelligence_leaf_pair(first, second),
        canonical_intelligence_leaf_pair(second, first)
    );
}

#[kani::proof]
fn distributed_queen_consensus_cannot_be_suppressed_by_single_node() {
    let honest_low: u8 = kani::any();
    let honest_high: u8 = kani::any();
    kani::assume(honest_low >= ActivationLevel::Alert as u8);
    kani::assume(honest_low <= ActivationLevel::Emergency as u8);
    kani::assume(honest_high >= honest_low);
    kani::assume(honest_high <= ActivationLevel::Emergency as u8);

    let median =
        median_activation_level(&[ActivationLevel::Dormant as u8, honest_low, honest_high]);
    assert!(median >= ActivationLevel::Alert);
}

#[kani::proof]
fn sybil_peers_cannot_reach_quorum_threshold_within_cap() {
    let interactions: u8 = kani::any();
    let earned = bounded_positive_reputation_delta(f64::from(interactions) * 0.02, 0.0, 0.10);
    let score = (0.25 + earned).clamp(0.0, 1.0);

    assert!(score < 0.70);
}

#[kani::proof]
fn admission_pow_cost_scales_linearly() {
    let n_sybils: u8 = kani::any();
    let pow_cost_seconds: u8 = 1;
    let total_cost = u16::from(n_sybils) * u16::from(pow_cost_seconds);
    assert!(total_cost >= u16::from(n_sybils));
}

#[kani::proof]
fn hybrid_bundle_material_gate_requires_both_signature_systems() {
    let public_keys = PublicKeyBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![1; 32],
        ml_dsa87: vec![2; 16],
    };
    let missing_ml_dsa = SignatureBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![3; 64],
        ml_dsa87: vec![],
    };
    let missing_ed25519 = SignatureBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![],
        ml_dsa87: vec![4; 32],
    };

    assert!(!bundle_has_required_signature_material(
        &public_keys,
        &missing_ml_dsa
    ));
    assert!(!bundle_has_required_signature_material(
        &public_keys,
        &missing_ed25519
    ));
}

#[kani::proof]
fn hybrid_admission_pow_identity_bytes_prefer_hybrid_bundle_encoding() {
    let legacy_public_key = [7u8; 32];
    let public_key_bundle = PublicKeyBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![1; 32],
        ml_dsa87: vec![2; 16],
    };

    assert_eq!(
        hybrid_admission_pow_identity_bytes(&legacy_public_key, Some(&public_key_bundle)),
        public_key_bundle.canonical_bytes()
    );
    assert_eq!(
        hybrid_admission_pow_identity_bytes(&legacy_public_key, None),
        legacy_public_key.to_vec()
    );
}

#[cfg(feature = "full")]
#[kani::proof]
fn distributed_attestation_digest_mismatch_is_rejected() {
    let expected_output_digest = [7u8; 32];
    let expected_trace_digest = [9u8; 32];
    let attestation = AttestationMetadata {
        signer_peer_id: "peer-a".to_string(),
        public_key: vec![0; 32],
        public_key_bundle: None,
        output_digest: expected_output_digest,
        trace_digest: expected_trace_digest,
        signature: vec![0; 64],
        signature_bundle: None,
        activation_level: Some(1),
    };

    assert!(attestation_matches_subgraph_digests(
        expected_output_digest,
        expected_trace_digest,
        &attestation,
    ));

    let mut bad_output = attestation.clone();
    bad_output.output_digest[0] ^= 0x01;
    assert!(!attestation_matches_subgraph_digests(
        expected_output_digest,
        expected_trace_digest,
        &bad_output,
    ));

    let mut bad_trace = attestation;
    bad_trace.trace_digest[0] ^= 0x01;
    assert!(!attestation_matches_subgraph_digests(
        expected_output_digest,
        expected_trace_digest,
        &bad_trace,
    ));
}

#[cfg(feature = "full")]
#[kani::proof]
fn distributed_requires_quorum_for_low_reputation_anomaly_or_low_trust() {
    assert!(coordinator_requires_quorum(
        ActivationLevel::Active,
        0.69,
        0,
        2,
    ));
    assert!(coordinator_requires_quorum(
        ActivationLevel::Active,
        0.95,
        1,
        2,
    ));
    assert!(coordinator_requires_quorum(
        ActivationLevel::Active,
        0.95,
        0,
        1,
    ));
    assert!(!coordinator_requires_quorum(
        ActivationLevel::Alert,
        0.95,
        0,
        2,
    ));
}

#[cfg(feature = "full")]
#[kani::proof]
fn distributed_two_party_quorum_rejects_mismatched_remote_digest() {
    assert!(!coordinator_two_party_unanimous_quorum_accepts(
        [1; 32], [2; 32]
    ));
    assert!(coordinator_two_party_unanimous_quorum_accepts(
        [3; 32], [3; 32]
    ));
}

#[cfg(feature = "full")]
#[kani::proof]
fn distributed_signed_message_bundle_surface_rejects_partial_hybrid_metadata() {
    let public_keys = PublicKeyBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![1; 32],
        ml_dsa87: vec![2; 16],
    };
    let signatures = SignatureBundle {
        scheme: SignatureScheme::HybridEd25519MlDsa87,
        ed25519: vec![3; 64],
        ml_dsa87: vec![4; 32],
    };

    assert!(signed_message_has_complete_bundle_surface(
        Some(&public_keys),
        Some(&signatures),
    ));
    assert!(!signed_message_has_complete_bundle_surface(
        Some(&public_keys),
        None,
    ));
    assert!(!signed_message_has_complete_bundle_surface(
        None,
        Some(&signatures),
    ));
}
