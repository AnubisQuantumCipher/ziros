use vstd::prelude::*;

verus! {

pub closed spec fn satellite_spacecraft_count() -> nat {
    2
}

pub closed spec fn satellite_step_count() -> nat {
    1440
}

pub closed spec fn satellite_private_inputs() -> nat {
    22
}

pub closed spec fn satellite_public_inputs() -> nat {
    2
}

pub closed spec fn satellite_public_outputs() -> nat {
    5
}

pub open spec fn one_hot_burn_flag(step: nat, burn_step: nat, total_steps: nat) -> bool {
    step < total_steps && step == burn_step
}

pub open spec fn deterministic_burn_velocity(v: int, dv: int, flag: bool) -> int {
    if flag {
        v + dv
    } else {
        v
    }
}

pub open spec fn running_min_step(curr: int, prev: int) -> int {
    if curr <= prev {
        curr
    } else {
        prev
    }
}

pub open spec fn safe_indicator_impl(min_sep: int, threshold: int) -> bool {
    min_sep >= threshold
}

pub open spec fn total_delta_v(dv0: int, dv1: int) -> int {
    dv0 + dv1
}

pub proof fn satellite_surface_constants()
    ensures
        satellite_spacecraft_count() == 2,
        satellite_step_count() == 1440,
        satellite_private_inputs() == 22,
        satellite_public_inputs() == 2,
        satellite_public_outputs() == 5,
{
    assert(satellite_spacecraft_count() == 2);
    assert(satellite_step_count() == 1440);
    assert(satellite_private_inputs() == 22);
    assert(satellite_public_inputs() == 2);
    assert(satellite_public_outputs() == 5);
}

pub proof fn satellite_burn_application_is_deterministic(v: int, dv: int, flag: bool)
    ensures
        deterministic_burn_velocity(v, dv, flag)
            == deterministic_burn_velocity(v, dv, flag),
{
    assert(deterministic_burn_velocity(v, dv, flag) == deterministic_burn_velocity(v, dv, flag));
}

pub proof fn satellite_one_hot_burn_flag_is_selected(step: nat, burn_step: nat)
    requires
        step < satellite_step_count(),
        burn_step < satellite_step_count(),
    ensures
        one_hot_burn_flag(step, burn_step, satellite_step_count()) == (step == burn_step),
{
    if step == burn_step {
        assert(one_hot_burn_flag(step, burn_step, satellite_step_count()));
    } else {
        assert(!one_hot_burn_flag(step, burn_step, satellite_step_count()));
    }
}

pub proof fn satellite_running_min_is_bounded(curr: int, prev: int)
    ensures
        running_min_step(curr, prev) <= curr,
        running_min_step(curr, prev) <= prev,
{
    if curr <= prev {
        assert(running_min_step(curr, prev) == curr);
        assert(running_min_step(curr, prev) <= prev);
    } else {
        assert(running_min_step(curr, prev) == prev);
        assert(running_min_step(curr, prev) <= curr);
    }
}

pub proof fn satellite_running_min_matches_threshold(
    curr: int,
    prev: int,
    threshold: int,
)
    requires
        running_min_step(curr, prev) >= threshold,
    ensures
        safe_indicator_impl(running_min_step(curr, prev), threshold),
{
    assert(safe_indicator_impl(running_min_step(curr, prev), threshold));
}

pub proof fn satellite_safe_indicator_implies_threshold(min_sep: int, threshold: int)
    requires
        safe_indicator_impl(min_sep, threshold),
    ensures
        min_sep >= threshold,
{
}

pub proof fn satellite_total_delta_v_is_accumulated(dv0: int, dv1: int)
    ensures
        total_delta_v(dv0, dv1) == dv0 + dv1,
{
    assert(total_delta_v(dv0, dv1) == dv0 + dv1);
}

pub proof fn satellite_delta_v_budget_slack_is_nonnegative(
    dv0: int,
    dv1: int,
    budget: int,
)
    requires
        total_delta_v(dv0, dv1) <= budget,
    ensures
        budget - total_delta_v(dv0, dv1) >= 0,
{
    assert(budget - total_delta_v(dv0, dv1) >= 0);
}

} // verus!
