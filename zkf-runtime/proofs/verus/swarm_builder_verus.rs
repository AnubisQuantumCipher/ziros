use vstd::prelude::*;

verus! {

pub enum RuleStateModel {
    Candidate,
    Validated,
    Shadow,
    Live,
    Revoked,
}

pub open spec fn transition_allowed(current: RuleStateModel, next: RuleStateModel) -> bool {
    match next {
        RuleStateModel::Shadow | RuleStateModel::Live => current != RuleStateModel::Candidate,
        RuleStateModel::Candidate | RuleStateModel::Validated | RuleStateModel::Revoked => true,
    }
}

pub open spec fn next_shadow_state(
    current: RuleStateModel,
    shadow_observation_count: nat,
    shadow_false_positive_rate_basis_points: nat,
    auto_promote: bool,
) -> RuleStateModel {
    if current == RuleStateModel::Shadow && shadow_observation_count >= 50 {
        if shadow_false_positive_rate_basis_points > 50 {
            RuleStateModel::Revoked
        } else if auto_promote {
            RuleStateModel::Live
        } else {
            RuleStateModel::Shadow
        }
    } else if current == RuleStateModel::Live
        && shadow_observation_count >= 100
        && shadow_false_positive_rate_basis_points > 100
    {
        RuleStateModel::Revoked
    } else {
        current
    }
}

pub proof fn swarm_builder_rule_state_machine(
    current: RuleStateModel,
    shadow_observation_count: nat,
    shadow_false_positive_rate_basis_points: nat,
    auto_promote: bool,
)
    ensures
        !transition_allowed(RuleStateModel::Candidate, RuleStateModel::Live),
        !transition_allowed(RuleStateModel::Candidate, RuleStateModel::Shadow),
        current == RuleStateModel::Shadow
            && shadow_observation_count >= 50
            && shadow_false_positive_rate_basis_points > 50
            ==> next_shadow_state(
                current,
                shadow_observation_count,
                shadow_false_positive_rate_basis_points,
                auto_promote,
            ) == RuleStateModel::Revoked,
        current == RuleStateModel::Shadow
            && shadow_observation_count >= 50
            && shadow_false_positive_rate_basis_points <= 50
            && auto_promote
            ==> next_shadow_state(
                current,
                shadow_observation_count,
                shadow_false_positive_rate_basis_points,
                auto_promote,
            ) == RuleStateModel::Live,
{
}

} // verus!
