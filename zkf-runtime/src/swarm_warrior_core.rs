use crate::swarm::builder::AttackTaxonomy;
use crate::swarm::queen::ActivationLevel;

pub(crate) fn requires_quorum(
    activation_level: ActivationLevel,
    peer_reputation_basis_points: u32,
    stage_anomaly_streak: u32,
    backend_trust_tier: u8,
) -> bool {
    activation_level >= ActivationLevel::Active
        && (backend_trust_tier < 2
            || peer_reputation_basis_points < 700
            || stage_anomaly_streak >= 1)
}

pub(crate) fn adaptive_policy_adjustments(
    activation_level: ActivationLevel,
    taxonomy: AttackTaxonomy,
    base_min_voters: usize,
    reconnaissance_extra_voters: usize,
) -> (usize, u32, bool, bool, bool) {
    let mut min_voters = base_min_voters;
    let mut agreement_threshold_basis_points = 666;
    let mut randomized_execution_order = false;

    match taxonomy {
        AttackTaxonomy::Reconnaissance => {
            min_voters += reconnaissance_extra_voters;
        }
        AttackTaxonomy::Injection => {
            agreement_threshold_basis_points = 1000;
        }
        AttackTaxonomy::SideChannel => {
            randomized_execution_order = true;
        }
        AttackTaxonomy::ResourceExhaustion
        | AttackTaxonomy::IntegrityCompromise
        | AttackTaxonomy::Coordination
        | AttackTaxonomy::Unknown => {}
    }

    let require_backend_diversity = activation_level >= ActivationLevel::Emergency;
    let honeypot_required = activation_level >= ActivationLevel::Emergency
        || matches!(
            taxonomy,
            AttackTaxonomy::Injection | AttackTaxonomy::IntegrityCompromise
        );
    (
        min_voters,
        agreement_threshold_basis_points,
        randomized_execution_order,
        require_backend_diversity,
        honeypot_required,
    )
}

pub(crate) fn quorum_accepts(
    agreeing_voters: usize,
    total_voters: usize,
    threshold_basis_points: u32,
) -> bool {
    agreeing_voters.saturating_mul(1000)
        >= total_voters.saturating_mul(threshold_basis_points as usize)
}

pub(crate) fn honeypot_accepts(failing_results: usize) -> bool {
    failing_results == 0
}

#[cfg(test)]
mod tests {
    use super::{adaptive_policy_adjustments, honeypot_accepts, quorum_accepts, requires_quorum};
    use crate::swarm::builder::AttackTaxonomy;
    use crate::swarm::queen::ActivationLevel;

    #[test]
    fn quorum_gate_is_fail_closed_for_low_reputation() {
        assert!(requires_quorum(ActivationLevel::Active, 650, 0, 2));
        assert!(!requires_quorum(ActivationLevel::Alert, 900, 0, 3));
    }

    #[test]
    fn adaptive_policy_escalates_injection_and_emergency() {
        let (_, threshold, randomized, diversified, honeypot) = adaptive_policy_adjustments(
            ActivationLevel::Emergency,
            AttackTaxonomy::Injection,
            3,
            1,
        );
        assert_eq!(threshold, 1000);
        assert!(!randomized);
        assert!(diversified);
        assert!(honeypot);
    }

    #[test]
    fn quorum_and_honeypot_checks_are_monotone() {
        assert!(quorum_accepts(2, 3, 666));
        assert!(!quorum_accepts(1, 3, 666));
        assert!(honeypot_accepts(0));
        assert!(!honeypot_accepts(1));
    }
}
