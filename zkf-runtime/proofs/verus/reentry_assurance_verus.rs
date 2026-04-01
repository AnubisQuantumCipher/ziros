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

use vstd::prelude::*;

verus! {

pub closed spec fn reentry_default_step_count() -> nat {
    256
}

pub closed spec fn reentry_public_outputs() -> nat {
    5
}

pub closed spec fn reentry_fixed_point_scale() -> int {
    1_000_000
}

pub closed spec fn reentry_accepted_fixed_point_scale() -> int {
    1_000
}

pub closed spec fn goldilocks_modulus() -> int {
    18_446_744_069_414_584_321
}

pub closed spec fn reentry_altitude_bound() -> int {
    200 * reentry_fixed_point_scale()
}

pub closed spec fn reentry_velocity_bound() -> int {
    8 * reentry_fixed_point_scale()
}

pub closed spec fn reentry_accepted_velocity_bound() -> int {
    8 * reentry_accepted_fixed_point_scale()
}

pub closed spec fn reentry_accepted_density_bound() -> int {
    2 * reentry_accepted_fixed_point_scale()
}

pub closed spec fn reentry_accepted_v_sq_bound() -> int {
    reentry_accepted_velocity_bound() * reentry_accepted_velocity_bound()
}

pub closed spec fn reentry_accepted_rho_v_sq_numerator_bound() -> int {
    reentry_accepted_density_bound() * reentry_accepted_v_sq_bound()
}

pub open spec fn signed_bound_relation(value: int, bound: int, slack: int) -> bool {
    value * value + slack == bound * bound && 0 <= slack
}

pub open spec fn split_signed_residual(residual: int, positive: int, negative: int) -> bool {
    residual == positive - negative
        && 0 <= positive
        && 0 <= negative
        && (positive == 0 || negative == 0)
}

pub open spec fn floor_sqrt_relation(value: int, sqrt: int, remainder: int, upper_slack: int) -> bool {
    value == sqrt * sqrt + remainder
        && value + upper_slack + 1 == (sqrt + 1) * (sqrt + 1)
        && 0 <= sqrt
        && 0 <= remainder
        && 0 <= upper_slack
}

pub open spec fn exact_division_relation(
    numerator: int,
    denominator: int,
    quotient: int,
    remainder: int,
    slack: int,
) -> bool {
    0 < denominator
        && numerator == denominator * quotient + remainder
        && denominator == remainder + slack + 1
        && 0 <= remainder
        && 0 <= slack
}

pub open spec fn running_max_step(previous_max: int, current_value: int) -> int {
    if current_value >= previous_max {
        current_value
    } else {
        previous_max
    }
}

pub open spec fn compliance_bit(pass: bool) -> int {
    if pass { 1 } else { 0 }
}

pub open spec fn manifest_window_contains_pack_window(
    manifest_not_before: int,
    manifest_not_after: int,
    pack_not_before: int,
    pack_not_after: int,
) -> bool {
    manifest_not_before <= pack_not_before
        && pack_not_before <= pack_not_after
        && pack_not_after <= manifest_not_after
}

pub open spec fn receipt_projection_matches_signed_inputs(
    receipt_pack_digest: int,
    signed_pack_digest: int,
    receipt_manifest_digest: int,
    manifest_digest: int,
    receipt_horizon: int,
    declared_horizon: int,
) -> bool {
    receipt_pack_digest == signed_pack_digest
        && receipt_manifest_digest == manifest_digest
        && receipt_horizon == declared_horizon
}

pub open spec fn rk4_weighted_step_relation(
    k1: int,
    k2: int,
    k3: int,
    k4: int,
    weighted_sum: int,
    remainder: int,
) -> bool {
    k1 + 2 * k2 + 2 * k3 + k4 == 6 * weighted_sum + remainder
        && 0 <= remainder
        && remainder < 6
}

pub open spec fn interpolation_relation(
    input: int,
    band_start: int,
    band_end: int,
    value_start: int,
    value_end: int,
    interpolated: int,
    remainder: int,
) -> bool {
    band_start <= input
        && input <= band_end
        && band_start < band_end
        && (input - band_start) * (value_end - value_start)
            == (band_end - band_start) * (interpolated - value_start) + remainder
        && 0 <= remainder
        && remainder < (band_end - band_start)
}

pub open spec fn cosine_closure_relation(sine: int, cosine: int, remainder: int, upper_slack: int) -> bool {
    floor_sqrt_relation(
        reentry_accepted_fixed_point_scale() * reentry_accepted_fixed_point_scale() - sine * sine,
        cosine,
        remainder,
        upper_slack,
    )
}

pub open spec fn abort_latch_transition(previous_latch: bool, trigger: bool, next_latch: bool) -> bool {
    next_latch == (previous_latch || trigger)
}

pub open spec fn first_trigger_relation(
    previous_latch: bool,
    trigger: bool,
    first_trigger: bool,
) -> bool {
    first_trigger == (trigger && !previous_latch)
}

pub open spec fn abort_mode_branch(
    next_latch: bool,
    nominal_constraints_hold: bool,
    abort_constraints_hold: bool,
) -> bool {
    if next_latch { abort_constraints_hold } else { nominal_constraints_hold }
}

pub proof fn reentry_surface_constants()
    ensures
        reentry_default_step_count() == 256,
        reentry_public_outputs() == 5,
        reentry_fixed_point_scale() == 1_000_000,
        reentry_accepted_fixed_point_scale() == 1_000,
        goldilocks_modulus() == 18_446_744_069_414_584_321,
        reentry_altitude_bound() == 200_000_000,
        reentry_velocity_bound() == 8_000_000,
{
    assert(reentry_default_step_count() == 256);
    assert(reentry_public_outputs() == 5);
    assert(reentry_fixed_point_scale() == 1_000_000);
    assert(reentry_accepted_fixed_point_scale() == 1_000);
    assert(goldilocks_modulus() == 18_446_744_069_414_584_321);
    assert(reentry_altitude_bound() == 200 * reentry_fixed_point_scale());
    assert(reentry_velocity_bound() == 8 * reentry_fixed_point_scale());
}

pub proof fn reentry_accepted_profile_fits_goldilocks_modulus()
    ensures
        reentry_accepted_velocity_bound() == 8_000,
        reentry_accepted_density_bound() == 2_000,
        reentry_accepted_v_sq_bound() == 64_000_000,
        reentry_accepted_rho_v_sq_numerator_bound() == 128_000_000_000,
        reentry_accepted_v_sq_bound() < goldilocks_modulus(),
        reentry_accepted_rho_v_sq_numerator_bound() < goldilocks_modulus(),
{
    assert(reentry_accepted_velocity_bound() == 8_000);
    assert(reentry_accepted_density_bound() == 2_000);
    assert(reentry_accepted_v_sq_bound() == 64_000_000);
    assert(reentry_accepted_rho_v_sq_numerator_bound() == 128_000_000_000);
    assert(reentry_accepted_v_sq_bound() < goldilocks_modulus());
    assert(reentry_accepted_rho_v_sq_numerator_bound() < goldilocks_modulus());
}

pub proof fn reentry_signed_bound_slack_reconstructs(
    value: int,
    bound: int,
    slack: int,
)
    requires
        signed_bound_relation(value, bound, slack),
    ensures
        value * value + slack == bound * bound,
        0 <= slack,
{
}

pub proof fn reentry_signed_residual_split_reconstructs(
    residual: int,
    residual_positive: int,
    residual_negative: int,
)
    requires
        split_signed_residual(residual, residual_positive, residual_negative),
    ensures
        residual == residual_positive - residual_negative,
        0 <= residual_positive,
        0 <= residual_negative,
{
}

pub proof fn reentry_floor_sqrt_brackets_value(
    value: int,
    sqrt: int,
    remainder: int,
    upper_slack: int,
)
    requires
        floor_sqrt_relation(value, sqrt, remainder, upper_slack),
    ensures
        value == sqrt * sqrt + remainder,
        value + upper_slack + 1 == (sqrt + 1) * (sqrt + 1),
        0 <= remainder,
        0 <= upper_slack,
{
    assert(value == sqrt * sqrt + remainder);
    assert(value + upper_slack + 1 == (sqrt + 1) * (sqrt + 1));
    assert(0 <= remainder);
    assert(0 <= upper_slack);
}

pub proof fn reentry_exact_division_reconstructs(
    numerator: int,
    denominator: int,
    quotient: int,
    remainder: int,
    slack: int,
)
    requires
        exact_division_relation(numerator, denominator, quotient, remainder, slack),
    ensures
        numerator == denominator * quotient + remainder,
        denominator == remainder + slack + 1,
        0 < denominator,
        0 <= remainder,
        0 <= slack,
{
    assert(numerator == denominator * quotient + remainder);
    assert(denominator == remainder + slack + 1);
    assert(0 < denominator);
    assert(0 <= remainder);
    assert(0 <= slack);
}

pub proof fn reentry_heating_rate_factorization_reconstructs(
    k_sg: int,
    sqrt_rho_over_rn: int,
    v_cubed_fp: int,
    heating_factor: int,
    heating_factor_remainder: int,
    heating_factor_slack: int,
    q_dot: int,
    q_dot_remainder: int,
    q_dot_slack: int,
)
    requires
        exact_division_relation(
            k_sg * sqrt_rho_over_rn,
            reentry_fixed_point_scale(),
            heating_factor,
            heating_factor_remainder,
            heating_factor_slack,
        ),
        exact_division_relation(
            heating_factor * v_cubed_fp,
            reentry_fixed_point_scale(),
            q_dot,
            q_dot_remainder,
            q_dot_slack,
        ),
    ensures
        k_sg * sqrt_rho_over_rn
            == reentry_fixed_point_scale() * heating_factor + heating_factor_remainder,
        heating_factor * v_cubed_fp
            == reentry_fixed_point_scale() * q_dot + q_dot_remainder,
        0 <= q_dot_remainder,
        0 <= q_dot_slack,
{
    assert(
        k_sg * sqrt_rho_over_rn
            == reentry_fixed_point_scale() * heating_factor + heating_factor_remainder
    );
    assert(
        heating_factor * v_cubed_fp
            == reentry_fixed_point_scale() * q_dot + q_dot_remainder
    );
    assert(0 <= q_dot_remainder);
    assert(0 <= q_dot_slack);
}

pub proof fn reentry_running_max_is_monotone(
    previous_max: int,
    current_value: int,
    next_value: int,
)
    ensures
        running_max_step(previous_max, current_value) >= previous_max,
        running_max_step(running_max_step(previous_max, current_value), next_value)
            >= running_max_step(previous_max, current_value),
{
    if current_value >= previous_max {
        assert(running_max_step(previous_max, current_value) == current_value);
        if next_value >= current_value {
            assert(
                running_max_step(running_max_step(previous_max, current_value), next_value)
                    == next_value
            );
        } else {
            assert(
                running_max_step(running_max_step(previous_max, current_value), next_value)
                    == current_value
            );
        }
    } else {
        assert(running_max_step(previous_max, current_value) == previous_max);
        if next_value >= previous_max {
            assert(
                running_max_step(running_max_step(previous_max, current_value), next_value)
                    == next_value
            );
        } else {
            assert(
                running_max_step(running_max_step(previous_max, current_value), next_value)
                    == previous_max
            );
        }
    }
}

pub proof fn reentry_compliance_bit_is_boolean(pass: bool)
    ensures
        compliance_bit(pass) == 0 || compliance_bit(pass) == 1,
{
    if pass {
        assert(compliance_bit(pass) == 1);
    } else {
        assert(compliance_bit(pass) == 0);
    }
}

pub proof fn reentry_manifest_window_contains_signed_pack(
    manifest_not_before: int,
    manifest_not_after: int,
    pack_not_before: int,
    pack_not_after: int,
)
    requires
        manifest_window_contains_pack_window(
            manifest_not_before,
            manifest_not_after,
            pack_not_before,
            pack_not_after,
        ),
    ensures
        manifest_not_before <= pack_not_before,
        pack_not_before <= pack_not_after,
        pack_not_after <= manifest_not_after,
{
}

pub proof fn reentry_receipt_projection_preserves_signed_digests(
    receipt_pack_digest: int,
    signed_pack_digest: int,
    receipt_manifest_digest: int,
    manifest_digest: int,
    receipt_horizon: int,
    declared_horizon: int,
)
    requires
        receipt_projection_matches_signed_inputs(
            receipt_pack_digest,
            signed_pack_digest,
            receipt_manifest_digest,
            manifest_digest,
            receipt_horizon,
            declared_horizon,
        ),
    ensures
        receipt_pack_digest == signed_pack_digest,
        receipt_manifest_digest == manifest_digest,
        receipt_horizon == declared_horizon,
{
}

pub proof fn reentry_rk4_weighted_step_reconstructs(
    k1: int,
    k2: int,
    k3: int,
    k4: int,
    weighted_sum: int,
    remainder: int,
)
    requires
        rk4_weighted_step_relation(k1, k2, k3, k4, weighted_sum, remainder),
    ensures
        k1 + 2 * k2 + 2 * k3 + k4 == 6 * weighted_sum + remainder,
        0 <= remainder < 6,
{
}

pub proof fn reentry_interpolation_respects_selected_band(
    input: int,
    band_start: int,
    band_end: int,
    value_start: int,
    value_end: int,
    interpolated: int,
    remainder: int,
)
    requires
        interpolation_relation(
            input,
            band_start,
            band_end,
            value_start,
            value_end,
            interpolated,
            remainder,
        ),
    ensures
        band_start <= input <= band_end,
        band_start < band_end,
{
}

pub proof fn reentry_cosine_closure_tracks_unit_circle(
    sine: int,
    cosine: int,
    remainder: int,
    upper_slack: int,
)
    requires
        cosine_closure_relation(sine, cosine, remainder, upper_slack),
    ensures
        reentry_accepted_fixed_point_scale() * reentry_accepted_fixed_point_scale() - sine * sine
            == cosine * cosine + remainder,
        0 <= remainder,
        0 <= upper_slack,
{
}

pub proof fn reentry_abort_latch_is_sticky(
    previous_latch: bool,
    trigger: bool,
    next_latch: bool,
)
    requires
        abort_latch_transition(previous_latch, trigger, next_latch),
    ensures
        previous_latch ==> next_latch,
        trigger ==> next_latch,
        next_latch == (previous_latch || trigger),
{
}

pub proof fn reentry_first_trigger_marks_latch_rise(
    previous_latch: bool,
    trigger: bool,
    first_trigger: bool,
)
    requires
        first_trigger_relation(previous_latch, trigger, first_trigger),
    ensures
        first_trigger ==> trigger,
        first_trigger ==> !previous_latch,
        trigger && !previous_latch ==> first_trigger,
{
}

pub proof fn reentry_abort_branch_selects_only_one_mode(
    next_latch: bool,
    nominal_constraints_hold: bool,
    abort_constraints_hold: bool,
)
    requires
        abort_mode_branch(next_latch, nominal_constraints_hold, abort_constraints_hold),
    ensures
        next_latch ==> abort_constraints_hold,
        !next_latch ==> nominal_constraints_hold,
{
}

} // verus!
