use vstd::prelude::*;

verus! {

pub open spec fn clamp_basis_points(value: int) -> int {
    if value < 0 { 0 } else if value > 1000 { 1000 } else { value }
}

pub open spec fn bounded_decay_score(score_basis_points: int, decay_factor_basis_points: int) -> int {
    let clamped_score = clamp_basis_points(score_basis_points);
    let clamped_decay = clamp_basis_points(decay_factor_basis_points);
    clamp_basis_points(250 + ((clamped_score - 250) * clamped_decay) / 1000)
}

pub open spec fn bounded_positive_delta(
    requested_delta_basis_points: int,
    earned_in_window_basis_points: int,
    hourly_cap_basis_points: int,
) -> int {
    if requested_delta_basis_points <= 0 {
        requested_delta_basis_points
    } else {
        let remaining = clamp_basis_points(hourly_cap_basis_points) - clamp_basis_points(earned_in_window_basis_points);
        if remaining <= 0 {
            0
        } else if requested_delta_basis_points <= remaining {
            requested_delta_basis_points
        } else {
            remaining
        }
    }
}

pub proof fn swarm_reputation_clamp_decay_hourly_cap(
    score_basis_points: int,
    decay_factor_basis_points: int,
    requested_delta_basis_points: int,
    earned_in_window_basis_points: int,
    hourly_cap_basis_points: int,
)
    ensures
        0 <= bounded_decay_score(score_basis_points, decay_factor_basis_points) <= 1000,
        0 <= clamp_basis_points(score_basis_points) <= 1000,
        requested_delta_basis_points > 0 ==> bounded_positive_delta(
            requested_delta_basis_points,
            earned_in_window_basis_points,
            hourly_cap_basis_points,
        ) <= clamp_basis_points(hourly_cap_basis_points),
{
}

} // verus!
