#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReputationEvidenceKindCore {
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

const MIN_REPUTATION_BASIS_POINTS: i32 = 0;
const MAX_REPUTATION_BASIS_POINTS: i32 = 1000;
const NEUTRAL_REPUTATION_BASIS_POINTS: i32 = 250;

pub(crate) fn clamp_reputation_basis_points(value: i32) -> i32 {
    value.clamp(MIN_REPUTATION_BASIS_POINTS, MAX_REPUTATION_BASIS_POINTS)
}

pub(crate) fn basis_points_to_f64(value: i32) -> f64 {
    clamp_reputation_basis_points(value) as f64 / 1000.0
}

pub(crate) fn signed_basis_points_to_f64(value: i32) -> f64 {
    value as f64 / 1000.0
}

pub(crate) fn f64_to_basis_points(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    clamp_reputation_basis_points((value * 1000.0).round() as i32)
}

pub(crate) fn reputation_delta_basis_points(kind: ReputationEvidenceKindCore) -> i32 {
    match kind {
        ReputationEvidenceKindCore::QuorumAgreement => 20,
        ReputationEvidenceKindCore::QuorumDisagreement => -150,
        ReputationEvidenceKindCore::AttestationValid => 10,
        ReputationEvidenceKindCore::AttestationInvalid => -200,
        ReputationEvidenceKindCore::HeartbeatTimeout => -100,
        ReputationEvidenceKindCore::HeartbeatResumed => 50,
        ReputationEvidenceKindCore::ThreatDigestCorroborated => 10,
        ReputationEvidenceKindCore::ThreatDigestContradicted => -50,
        ReputationEvidenceKindCore::ModelFreshnessMatch => 5,
        ReputationEvidenceKindCore::ModelFreshnessMismatch => -30,
    }
}

pub(crate) fn bounded_reputation_after_decayed_score_basis_points(
    decayed_score_basis_points: i32,
    kind: ReputationEvidenceKindCore,
) -> i32 {
    clamp_reputation_basis_points(decayed_score_basis_points + reputation_delta_basis_points(kind))
}

pub(crate) fn bounded_decay_score_basis_points(
    score_basis_points: i32,
    decay_factor_basis_points: i32,
) -> i32 {
    let clamped_score = clamp_reputation_basis_points(score_basis_points);
    let clamped_decay = clamp_reputation_basis_points(decay_factor_basis_points);
    let decayed = NEUTRAL_REPUTATION_BASIS_POINTS
        + ((clamped_score - NEUTRAL_REPUTATION_BASIS_POINTS) * clamped_decay) / 1000;
    clamp_reputation_basis_points(decayed)
}

pub(crate) fn bounded_positive_reputation_delta_basis_points(
    requested_delta_basis_points: i32,
    earned_in_window_basis_points: i32,
    hourly_cap_basis_points: i32,
) -> i32 {
    if requested_delta_basis_points <= 0 {
        return requested_delta_basis_points;
    }
    let remaining = (clamp_reputation_basis_points(hourly_cap_basis_points)
        - clamp_reputation_basis_points(earned_in_window_basis_points.max(0)))
    .max(0);
    requested_delta_basis_points.min(remaining)
}

pub(crate) fn bounded_reputation_after_decayed_score(
    decayed_score: f64,
    kind: ReputationEvidenceKindCore,
) -> f64 {
    basis_points_to_f64(bounded_reputation_after_decayed_score_basis_points(
        f64_to_basis_points(decayed_score),
        kind,
    ))
}

pub(crate) fn bounded_decay_score(score: f64, decay_factor: f64) -> f64 {
    basis_points_to_f64(bounded_decay_score_basis_points(
        f64_to_basis_points(score),
        f64_to_basis_points(decay_factor),
    ))
}

pub(crate) fn bounded_positive_reputation_delta(
    requested_delta: f64,
    earned_in_window: f64,
    hourly_cap: f64,
) -> f64 {
    bounded_positive_reputation_delta_basis_points(
        (requested_delta * 1000.0).round() as i32,
        (earned_in_window * 1000.0).round() as i32,
        (hourly_cap * 1000.0).round() as i32,
    ) as f64
        / 1000.0
}

#[cfg(test)]
mod tests {
    use super::{
        ReputationEvidenceKindCore, bounded_decay_score,
        bounded_positive_reputation_delta_basis_points,
        bounded_reputation_after_decayed_score_basis_points, reputation_delta_basis_points,
        signed_basis_points_to_f64,
    };

    #[test]
    fn reputation_updates_stay_bounded() {
        assert_eq!(
            bounded_reputation_after_decayed_score_basis_points(
                995,
                ReputationEvidenceKindCore::QuorumAgreement
            ),
            1000
        );
        assert!(bounded_decay_score(0.9, 0.5) <= 1.0);
    }

    #[test]
    fn hourly_cap_is_fail_closed() {
        assert_eq!(
            bounded_positive_reputation_delta_basis_points(20, 990, 1000),
            10
        );
    }

    #[test]
    fn signed_delta_conversion_preserves_penalties() {
        assert_eq!(
            signed_basis_points_to_f64(reputation_delta_basis_points(
                ReputationEvidenceKindCore::QuorumDisagreement
            )),
            -0.15
        );
    }
}
