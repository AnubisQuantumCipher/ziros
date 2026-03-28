use vstd::prelude::*;

verus! {

pub closed spec fn private_nbody_body_count() -> nat {
    5
}

pub closed spec fn private_nbody_step_count() -> nat {
    1000
}

pub closed spec fn private_nbody_private_inputs() -> nat {
    35
}

pub closed spec fn private_nbody_public_outputs() -> nat {
    5
}

pub closed spec fn fixed_scale() -> int {
    1_000_000_000_000_000_000
}

pub closed spec fn gravity_scaled() -> int {
    66_743_000
}

pub closed spec fn position_bound() -> int {
    1_000 * fixed_scale()
}

pub closed spec fn velocity_bound() -> int {
    100 * fixed_scale()
}

pub closed spec fn acceleration_bound() -> int {
    1_000_000 * fixed_scale()
}

pub closed spec fn min_distance() -> int {
    1_000_000_000_000_000
}

pub closed spec fn remainder_bound_for_half() -> int {
    1
}

pub closed spec fn inv_r3_remainder_bound() -> int {
    fixed_scale() / 2
}

pub closed spec fn factor_remainder_bound() -> int {
    fixed_scale() / 2
}

pub closed spec fn acceleration_remainder_bound() -> int {
    fixed_scale() * fixed_scale() / 2
}

pub closed spec fn bn254_nonwrap_domain_bound() -> int {
    fixed_scale() * fixed_scale() * 4
}

pub closed spec fn body_tag(body: nat) -> int {
    body as int + 1
}

pub open spec fn orbital_pair_count(body_count: nat) -> nat
    decreases body_count
{
    if body_count <= 1nat {
        0nat
    } else {
        orbital_pair_count((body_count - 1) as nat) + ((body_count - 1) as nat)
    }
}

pub open spec fn pair_index_valid(i: nat, j: nat) -> bool {
    i < j && j < private_nbody_body_count()
}

pub open spec fn pairwise_delta(ri: int, rj: int) -> int {
    rj - ri
}

pub open spec fn half_step_residual_relation(value: int, rounded: int, residual: int) -> bool {
    value == 2 * rounded + residual
        && -remainder_bound_for_half() <= residual
        && residual <= remainder_bound_for_half()
}

pub open spec fn split_signed_residual(residual: int, positive: int, negative: int) -> bool {
    residual == positive - negative
        && 0 <= positive
        && 0 <= negative
        && (positive == 0 || negative == 0)
}

pub open spec fn velocity_verlet_position_next(x: int, v: int, half_acc: int) -> int {
    x + v + half_acc
}

pub open spec fn velocity_verlet_velocity_next(v: int, half_accel_sum: int) -> int {
    v + half_accel_sum
}

pub proof fn orbital_surface_constants()
    ensures
        private_nbody_body_count() == 5,
        private_nbody_step_count() == 1000,
        private_nbody_private_inputs() == 35,
        private_nbody_public_outputs() == 5,
        orbital_pair_count(private_nbody_body_count()) == 10,
        fixed_scale() == 1_000_000_000_000_000_000,
        gravity_scaled() == 66_743_000,
        remainder_bound_for_half() == 1,
{
    assert(orbital_pair_count(private_nbody_body_count()) == orbital_pair_count(5nat));
    assert(orbital_pair_count(5nat) == orbital_pair_count(4nat) + 4nat);
    assert(orbital_pair_count(4nat) == orbital_pair_count(3nat) + 3nat);
    assert(orbital_pair_count(3nat) == orbital_pair_count(2nat) + 2nat);
    assert(orbital_pair_count(2nat) == orbital_pair_count(1nat) + 1nat);
    assert(orbital_pair_count(1nat) == 0nat);
    assert(orbital_pair_count(private_nbody_body_count()) == 10nat);
}

pub proof fn orbital_pair_enumeration_is_ordered(i: nat, j: nat)
    requires
        pair_index_valid(i, j),
    ensures
        i < j,
        j < private_nbody_body_count(),
        i < private_nbody_body_count(),
{
}

pub proof fn orbital_pairwise_delta_zero_self(r: int)
    ensures
        pairwise_delta(r, r) == 0,
{
}

pub proof fn orbital_pairwise_delta_antisymmetric(ri: int, rj: int)
    ensures
        pairwise_delta(ri, rj) + pairwise_delta(rj, ri) == 0,
{
}

pub proof fn orbital_body_tags_are_domain_separated(i: nat, j: nat)
    requires
        i < private_nbody_body_count(),
        j < private_nbody_body_count(),
        i != j,
    ensures
        body_tag(i) != body_tag(j),
        1 <= body_tag(i) <= private_nbody_body_count() as int,
        1 <= body_tag(j) <= private_nbody_body_count() as int,
{
    assert(body_tag(i) == i as int + 1);
    assert(body_tag(j) == j as int + 1);
}

pub proof fn orbital_position_update_reconstructs_exact_half_step(
    x: int,
    v: int,
    a_now: int,
    half_acc: int,
    residual: int,
)
    requires
        half_step_residual_relation(a_now, half_acc, residual),
    ensures
        2 * (velocity_verlet_position_next(x, v, half_acc) - x - v) + residual == a_now,
        -remainder_bound_for_half() <= residual <= remainder_bound_for_half(),
{
    assert(velocity_verlet_position_next(x, v, half_acc) - x - v == half_acc);
}

pub proof fn orbital_velocity_update_reconstructs_exact_half_step(
    v: int,
    a_now: int,
    a_next: int,
    half_accel_sum: int,
    residual: int,
)
    requires
        half_step_residual_relation(a_now + a_next, half_accel_sum, residual),
    ensures
        2 * (velocity_verlet_velocity_next(v, half_accel_sum) - v) + residual == a_now + a_next,
        -remainder_bound_for_half() <= residual <= remainder_bound_for_half(),
{
    assert(velocity_verlet_velocity_next(v, half_accel_sum) - v == half_accel_sum);
}

pub proof fn orbital_signed_residual_split_reconstructs(
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

pub proof fn orbital_fixed_point_bounds_fit_inside_bn254()
    ensures
        0 < fixed_scale(),
        0 < gravity_scaled(),
        0 < position_bound(),
        0 < velocity_bound(),
        0 < acceleration_bound(),
        0 < min_distance(),
        0 < min_distance() * min_distance(),
        2 * (position_bound() + velocity_bound()) + acceleration_bound() + remainder_bound_for_half()
            < bn254_nonwrap_domain_bound(),
        2 * velocity_bound() + 2 * acceleration_bound() + remainder_bound_for_half()
            < bn254_nonwrap_domain_bound(),
        fixed_scale() * fixed_scale() + inv_r3_remainder_bound() < bn254_nonwrap_domain_bound(),
        fixed_scale() * fixed_scale() + factor_remainder_bound() < bn254_nonwrap_domain_bound(),
        fixed_scale() * fixed_scale() + acceleration_remainder_bound() < bn254_nonwrap_domain_bound(),
{
    assert(position_bound() == 1_000 * fixed_scale());
    assert(velocity_bound() == 100 * fixed_scale());
    assert(acceleration_bound() == 1_000_000 * fixed_scale());
    assert(min_distance() * min_distance() > 0);
    assert(inv_r3_remainder_bound() == fixed_scale() / 2);
    assert(factor_remainder_bound() == fixed_scale() / 2);
    assert(acceleration_remainder_bound() == fixed_scale() * fixed_scale() / 2);
    assert(fixed_scale() * fixed_scale() + inv_r3_remainder_bound() < bn254_nonwrap_domain_bound());
    assert(fixed_scale() * fixed_scale() + factor_remainder_bound() < bn254_nonwrap_domain_bound());
    assert(
        fixed_scale() * fixed_scale() + acceleration_remainder_bound()
            < bn254_nonwrap_domain_bound()
    );
}

} // verus!
