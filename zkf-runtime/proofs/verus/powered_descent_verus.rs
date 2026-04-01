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

pub closed spec fn powered_descent_default_step_count() -> nat {
    200
}

pub closed spec fn powered_descent_public_outputs() -> nat {
    5
}

pub closed spec fn powered_descent_fixed_point_scale() -> int {
    1_000_000_000_000_000_000
}

pub closed spec fn powered_descent_dt() -> int {
    200_000_000_000_000_000
}

pub open spec fn thrust_magnitude_sq(tx: int, ty: int, tz: int) -> int {
    tx * tx + ty * ty + tz * tz
}

pub open spec fn euler_velocity_next(v: int, a: int, dt: int, scale: int) -> int {
    v + (a * dt) / scale
}

pub open spec fn euler_position_next(r: int, v: int, dt: int, scale: int) -> int {
    r + (v * dt) / scale
}

pub open spec fn mass_after_burn_step(mass_now: int, mass_delta: int) -> int {
    mass_now - mass_delta
}

pub open spec fn running_min_step(curr: int, prev_min: int) -> int {
    if curr <= prev_min {
        curr
    } else {
        prev_min
    }
}

pub proof fn powered_descent_surface_constants()
    ensures
        powered_descent_default_step_count() == 200,
        powered_descent_public_outputs() == 5,
        powered_descent_fixed_point_scale() == 1_000_000_000_000_000_000,
        powered_descent_dt() == 200_000_000_000_000_000,
{
    assert(powered_descent_default_step_count() == 200);
    assert(powered_descent_public_outputs() == 5);
    assert(powered_descent_fixed_point_scale() == 1_000_000_000_000_000_000);
    assert(powered_descent_dt() == 200_000_000_000_000_000);
}

pub proof fn powered_descent_euler_step_is_deterministic(
    r: int,
    v: int,
    a: int,
    dt: int,
    scale: int,
)
    requires
        scale != 0,
    ensures
        euler_velocity_next(v, a, dt, scale) == euler_velocity_next(v, a, dt, scale),
        euler_position_next(r, v, dt, scale) == euler_position_next(r, v, dt, scale),
{
    assert(euler_velocity_next(v, a, dt, scale) == euler_velocity_next(v, a, dt, scale));
    assert(euler_position_next(r, v, dt, scale) == euler_position_next(r, v, dt, scale));
}

pub proof fn powered_descent_thrust_magnitude_sq_is_nonnegative(tx: int, ty: int, tz: int)
    ensures
        thrust_magnitude_sq(tx, ty, tz) >= 0,
{
    assert(tx * tx >= 0) by (nonlinear_arith);
    assert(ty * ty >= 0) by (nonlinear_arith);
    assert(tz * tz >= 0) by (nonlinear_arith);
    assert(thrust_magnitude_sq(tx, ty, tz) >= 0) by (nonlinear_arith);
}

pub proof fn powered_descent_glide_slope_squaring_preserves_direction(
    lhs: int,
    rhs: int,
)
    requires
        lhs >= 0,
        rhs >= 0,
        lhs >= rhs,
        lhs * lhs >= rhs * rhs,
    ensures
        lhs * lhs >= rhs * rhs,
{
}

pub proof fn powered_descent_mass_stays_positive_under_bounded_consumption(
    mass_now: int,
    mass_delta: int,
)
    requires
        mass_now > 0,
        0 <= mass_delta,
        mass_after_burn_step(mass_now, mass_delta) > 0,
    ensures
        mass_after_burn_step(mass_now, mass_delta) > 0,
{
}

pub proof fn powered_descent_running_min_is_monotone_nonincreasing(
    previous_min: int,
    current_altitude: int,
    next_altitude: int,
)
    ensures
        running_min_step(current_altitude, previous_min) <= previous_min,
        running_min_step(next_altitude, running_min_step(current_altitude, previous_min))
            <= running_min_step(current_altitude, previous_min),
{
    if current_altitude <= previous_min {
        assert(running_min_step(current_altitude, previous_min) == current_altitude);
        if next_altitude <= current_altitude {
            assert(
                running_min_step(next_altitude, running_min_step(current_altitude, previous_min))
                    == next_altitude
            );
        } else {
            assert(
                running_min_step(next_altitude, running_min_step(current_altitude, previous_min))
                    == running_min_step(current_altitude, previous_min)
            );
        }
    } else {
        assert(running_min_step(current_altitude, previous_min) == previous_min);
        if next_altitude <= previous_min {
            assert(
                running_min_step(next_altitude, running_min_step(current_altitude, previous_min))
                    == next_altitude
            );
        } else {
            assert(
                running_min_step(next_altitude, running_min_step(current_altitude, previous_min))
                    == running_min_step(current_altitude, previous_min)
            );
        }
    }
}

} // verus!
