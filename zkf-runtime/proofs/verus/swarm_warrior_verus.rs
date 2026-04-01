use vstd::prelude::*;

verus! {

pub open spec fn requires_quorum(
    activation_rank: nat,
    peer_reputation_basis_points: nat,
    stage_anomaly_streak: nat,
    backend_trust_tier: nat,
) -> bool {
    activation_rank >= 2
        && (backend_trust_tier < 2 || peer_reputation_basis_points < 700 || stage_anomaly_streak >= 1)
}

pub open spec fn quorum_accepts(
    agreeing_voters: nat,
    total_voters: nat,
    threshold_basis_points: nat,
) -> bool {
    agreeing_voters * 1000 >= total_voters * threshold_basis_points
}

pub open spec fn honeypot_accepts(failing_results: nat) -> bool {
    failing_results == 0
}

pub proof fn swarm_warrior_quorum_diversity_honeypot(
    activation_rank: nat,
    peer_reputation_basis_points: nat,
    stage_anomaly_streak: nat,
    backend_trust_tier: nat,
    agreeing_voters: nat,
    total_voters: nat,
)
    ensures
        activation_rank < 2 ==> !requires_quorum(
            activation_rank,
            peer_reputation_basis_points,
            stage_anomaly_streak,
            backend_trust_tier,
        ),
        quorum_accepts(2, 3, 666),
        !quorum_accepts(1, 3, 666),
        honeypot_accepts(0),
        !honeypot_accepts(1),
{
}

} // verus!
