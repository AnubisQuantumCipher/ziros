#![cfg_attr(not(hax), allow(dead_code))]

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofReputationEvidenceKind {
    QuorumAgreement,
    QuorumDisagreement,
    AttestationValid,
    AttestationInvalid,
    HeartbeatTimeout,
    HeartbeatResumed,
    ThreatDigestCorroborated,
    ThreatDigestContradicted,
    ModelFreshnessMatch,
    ModelFreshnessMismatch,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn min_reputation_bound() -> f64 {
    0.0
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn max_reputation_bound() -> f64 {
    1.0
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn neutral_reputation_bound() -> f64 {
    0.25
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn clamp_reputation_unit_interval(value: f64) -> f64 {
    if value < min_reputation_bound() {
        min_reputation_bound()
    } else if value > max_reputation_bound() {
        max_reputation_bound()
    } else {
        value
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn reputation_delta_for(kind: ProofReputationEvidenceKind) -> f64 {
    match kind {
        ProofReputationEvidenceKind::QuorumAgreement => 0.02,
        ProofReputationEvidenceKind::QuorumDisagreement => -0.15,
        ProofReputationEvidenceKind::AttestationValid => 0.01,
        ProofReputationEvidenceKind::AttestationInvalid => -0.20,
        ProofReputationEvidenceKind::HeartbeatTimeout => -0.10,
        ProofReputationEvidenceKind::HeartbeatResumed => 0.05,
        ProofReputationEvidenceKind::ThreatDigestCorroborated => 0.01,
        ProofReputationEvidenceKind::ThreatDigestContradicted => -0.05,
        ProofReputationEvidenceKind::ModelFreshnessMatch => 0.005,
        ProofReputationEvidenceKind::ModelFreshnessMismatch => -0.03,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn bounded_reputation_after_decayed_score_spec(
    decayed_score: f64,
    kind: ProofReputationEvidenceKind,
) -> f64 {
    clamp_reputation_unit_interval(decayed_score + reputation_delta_for(kind))
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn bounded_decay_score_spec(score: f64, decay_factor: f64) -> f64 {
    let clamped_score = clamp_reputation_unit_interval(score);
    let clamped_decay = clamp_reputation_unit_interval(decay_factor);
    clamp_reputation_unit_interval(
        neutral_reputation_bound() + (clamped_score - neutral_reputation_bound()) * clamped_decay,
    )
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProofDistributedActivationLevel {
    Dormant,
    Alert,
    Active,
    Emergency,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn activation_level_rank(level: ProofDistributedActivationLevel) -> u8 {
    match level {
        ProofDistributedActivationLevel::Dormant => 0,
        ProofDistributedActivationLevel::Alert => 1,
        ProofDistributedActivationLevel::Active => 2,
        ProofDistributedActivationLevel::Emergency => 3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofBytes2 {
    pub pair_left: u8,
    pub pair_right: u8,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofBytes4 {
    pub quad0: u8,
    pub quad1: u8,
    pub quad2: u8,
    pub quad3: u8,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofBytes8 {
    pub oct0: u8,
    pub oct1: u8,
    pub oct2: u8,
    pub oct3: u8,
    pub oct4: u8,
    pub oct5: u8,
    pub oct6: u8,
    pub oct7: u8,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn u8_eq(left: u8, right: u8) -> bool {
    usize::from(left) == usize::from(right)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn u8_le(left: u8, right: u8) -> bool {
    usize::from(left) <= usize::from(right)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn array2_eq(left: ProofBytes2, right: ProofBytes2) -> bool {
    u8_eq(left.pair_left, right.pair_left) && u8_eq(left.pair_right, right.pair_right)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn array4_eq(left: ProofBytes4, right: ProofBytes4) -> bool {
    u8_eq(left.quad0, right.quad0)
        && u8_eq(left.quad1, right.quad1)
        && u8_eq(left.quad2, right.quad2)
        && u8_eq(left.quad3, right.quad3)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn array8_eq(left: ProofBytes8, right: ProofBytes8) -> bool {
    u8_eq(left.oct0, right.oct0)
        && u8_eq(left.oct1, right.oct1)
        && u8_eq(left.oct2, right.oct2)
        && u8_eq(left.oct3, right.oct3)
        && u8_eq(left.oct4, right.oct4)
        && u8_eq(left.oct5, right.oct5)
        && u8_eq(left.oct6, right.oct6)
        && u8_eq(left.oct7, right.oct7)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn bounded_gossip_count_spec(pending_len: usize, gossip_max: usize) -> usize {
    let capped = if gossip_max == 0 { 1 } else { gossip_max };
    if pending_len < capped {
        pending_len
    } else {
        capped
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn median_activation_level_three(
    first: ProofDistributedActivationLevel,
    second: ProofDistributedActivationLevel,
    third: ProofDistributedActivationLevel,
) -> ProofDistributedActivationLevel {
    match (first, second, third) {
        (
            ProofDistributedActivationLevel::Dormant,
            ProofDistributedActivationLevel::Alert,
            ProofDistributedActivationLevel::Alert,
        )
        | (
            ProofDistributedActivationLevel::Alert,
            ProofDistributedActivationLevel::Dormant,
            ProofDistributedActivationLevel::Alert,
        )
        | (
            ProofDistributedActivationLevel::Alert,
            ProofDistributedActivationLevel::Alert,
            ProofDistributedActivationLevel::Dormant,
        ) => ProofDistributedActivationLevel::Alert,
        _ => second,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn capped_positive_reputation_gain_basis_points(_raw_gain_basis_points: u16) -> u16 {
    10
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn probationary_peer_score_basis_points(_raw_gain_basis_points: u16) -> u16 {
    35
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn admission_pow_total_cost(_peer_count: u16, unit_cost_seconds: u16) -> u16 {
    unit_cost_seconds
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn coordinator_requires_quorum_spec(
    activation_level: ProofDistributedActivationLevel,
    _peer_reputation_basis_points: u16,
    _stage_anomaly_streak: u32,
    _backend_trust_tier: u8,
) -> bool {
    matches!(
        activation_level,
        ProofDistributedActivationLevel::Active | ProofDistributedActivationLevel::Emergency
    )
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn attestation_matches_subgraph_digests_spec(
    expected_output_digest: ProofBytes8,
    expected_trace_digest: ProofBytes8,
    found_output_digest: ProofBytes8,
    found_trace_digest: ProofBytes8,
) -> bool {
    array8_eq(expected_output_digest, found_output_digest)
        && array8_eq(expected_trace_digest, found_trace_digest)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn digest_prefix8_spec(digest: ProofBytes8) -> ProofBytes8 {
    digest
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn coordinator_two_party_unanimous_quorum_accepts_spec(
    remote_digest: ProofBytes8,
    local_digest: ProofBytes8,
) -> bool {
    array8_eq(
        digest_prefix8_spec(remote_digest),
        digest_prefix8_spec(local_digest),
    )
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn distributed_acceptance_surface_spec(
    activation_level: ProofDistributedActivationLevel,
    peer_reputation_basis_points: u16,
    stage_anomaly_streak: u32,
    backend_trust_tier: u8,
    attestation_matches: bool,
    digests_agree: bool,
) -> bool {
    attestation_matches
        && coordinator_requires_quorum_spec(
            activation_level,
            peer_reputation_basis_points,
            stage_anomaly_streak,
            backend_trust_tier,
        )
        && digests_agree
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hybrid_bundle_surface_complete_spec(
    public_key_bundle_present: bool,
    signature_bundle_present: bool,
) -> bool {
    public_key_bundle_present && signature_bundle_present
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hybrid_signature_material_complete_spec(
    ed25519_present: bool,
    ml_dsa_present: bool,
) -> bool {
    ed25519_present && ml_dsa_present
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn hybrid_admission_pow_identity_bytes_spec(
    legacy_public_key: Vec<u8>,
    public_key_bundle_bytes: Option<Vec<u8>>,
) -> Vec<u8> {
    match public_key_bundle_bytes {
        Some(bundle_bytes) => bundle_bytes,
        None => legacy_public_key,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn encrypted_gossip_negotiation_fail_closed_spec(
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
pub(crate) fn append_only_memory_chain_after_append(
    prefix: ProofBytes4,
    suffix: ProofBytes4,
) -> ProofBytes8 {
    ProofBytes8 {
        oct0: prefix.quad0,
        oct1: prefix.quad1,
        oct2: prefix.quad2,
        oct3: prefix.quad3,
        oct4: suffix.quad0,
        oct5: suffix.quad1,
        oct6: suffix.quad2,
        oct7: suffix.quad3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn chain_prefix4(bytes: ProofBytes8) -> ProofBytes4 {
    ProofBytes4 {
        quad0: bytes.oct0,
        quad1: bytes.oct1,
        quad2: bytes.oct2,
        quad3: bytes.oct3,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn append_only_memory_prefix_preserved_spec(
    prefix: ProofBytes4,
    suffix: ProofBytes4,
) -> bool {
    array4_eq(
        chain_prefix4(append_only_memory_chain_after_append(prefix, suffix)),
        prefix,
    )
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn snapshot_chain_head_roundtrip_spec(
    exported_head: ProofBytes4,
    imported_head: ProofBytes4,
) -> bool {
    array4_eq(exported_head, imported_head)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn canonical_intelligence_leaf_pair(first: u8, second: u8) -> ProofBytes2 {
    if u8_le(first, second) {
        ProofBytes2 {
            pair_left: first,
            pair_right: second,
        }
    } else {
        ProofBytes2 {
            pair_left: second,
            pair_right: first,
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn intelligence_root_convergence_under_canonical_ordering_spec(
    first: u8,
    second: u8,
) -> bool {
    array2_eq(
        canonical_intelligence_leaf_pair(first, second),
        canonical_intelligence_leaf_pair(second, first),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ProofBytes4, append_only_memory_prefix_preserved_spec,
        intelligence_root_convergence_under_canonical_ordering_spec,
        snapshot_chain_head_roundtrip_spec,
    };

    #[test]
    fn append_only_memory_prefix_is_preserved() {
        let prefix = ProofBytes4 {
            quad0: 1,
            quad1: 2,
            quad2: 3,
            quad3: 4,
        };
        let suffix = ProofBytes4 {
            quad0: 9,
            quad1: 8,
            quad2: 7,
            quad3: 6,
        };
        assert!(append_only_memory_prefix_preserved_spec(prefix, suffix));
    }

    #[test]
    fn snapshot_roundtrip_accepts_only_matching_heads() {
        let head = ProofBytes4 {
            quad0: 7,
            quad1: 1,
            quad2: 4,
            quad3: 9,
        };
        assert!(snapshot_chain_head_roundtrip_spec(head, head));
        assert!(!snapshot_chain_head_roundtrip_spec(
            head,
            ProofBytes4 {
                quad0: 0,
                quad1: 1,
                quad2: 4,
                quad3: 9,
            }
        ));
    }

    #[test]
    fn canonical_intelligence_order_is_symmetric() {
        assert!(intelligence_root_convergence_under_canonical_ordering_spec(
            2, 9
        ));
        assert!(intelligence_root_convergence_under_canonical_ordering_spec(
            9, 2
        ));
    }
}
