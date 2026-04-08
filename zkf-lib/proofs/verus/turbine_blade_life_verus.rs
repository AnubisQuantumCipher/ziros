use vstd::prelude::*;

verus! {

pub closed spec fn turbine_default_step_count() -> nat {
    500
}

pub closed spec fn turbine_control_sections() -> nat {
    3
}

pub closed spec fn turbine_geometry_stations() -> nat {
    8
}

pub open spec fn thermal_strain_relation(
    alpha: int,
    metal_temp: int,
    radius: int,
    strain: int,
) -> bool {
    strain == alpha * (metal_temp + radius)
}

pub open spec fn equivalent_stress_relation(
    sigma_cf: int,
    sigma_pr: int,
    sigma_th: int,
    sigma_eq: int,
) -> bool {
    sigma_eq == sigma_cf + sigma_pr + sigma_th
}

pub open spec fn damage_update_relation(
    previous: int,
    fatigue: int,
    creep: int,
    next: int,
) -> bool {
    next == previous + fatigue + creep
}

pub open spec fn crack_update_relation(previous: int, increment: int, next: int) -> bool {
    next == previous + increment
}

pub open spec fn safe_decision_relation(
    damage: int,
    crack: int,
    min_margin: int,
    damage_limit: int,
    crack_limit: int,
    reserve_margin: int,
    operating_bounds_ok: bool,
    safe: bool,
) -> bool {
    safe
        == (damage <= damage_limit
            && crack <= crack_limit
            && reserve_margin <= min_margin
            && operating_bounds_ok)
}

pub proof fn turbine_surface_constants()
    ensures
        turbine_default_step_count() == 500,
        turbine_control_sections() == 3,
        turbine_geometry_stations() == 8,
{
    assert(turbine_default_step_count() == 500);
    assert(turbine_control_sections() == 3);
    assert(turbine_geometry_stations() == 8);
}

pub proof fn thermal_strain_unique(
    alpha: int,
    metal_temp: int,
    radius: int,
    strain_a: int,
    strain_b: int,
)
    requires
        thermal_strain_relation(alpha, metal_temp, radius, strain_a),
        thermal_strain_relation(alpha, metal_temp, radius, strain_b),
    ensures
        strain_a == strain_b,
{
}

pub proof fn equivalent_stress_nonnegative(
    sigma_cf: int,
    sigma_pr: int,
    sigma_th: int,
    sigma_eq: int,
)
    requires
        0 <= sigma_cf,
        0 <= sigma_pr,
        0 <= sigma_th,
        equivalent_stress_relation(sigma_cf, sigma_pr, sigma_th, sigma_eq),
    ensures
        0 <= sigma_eq,
{
}

pub proof fn damage_update_preserves_monotonicity(
    previous: int,
    fatigue: int,
    creep: int,
    next: int,
)
    requires
        0 <= fatigue,
        0 <= creep,
        damage_update_relation(previous, fatigue, creep, next),
    ensures
        previous <= next,
{
}

pub proof fn crack_update_preserves_monotonicity(
    previous: int,
    increment: int,
    next: int,
)
    requires
        0 <= increment,
        crack_update_relation(previous, increment, next),
    ensures
        previous <= next,
{
}

pub proof fn safe_decision_is_sound(
    damage: int,
    crack: int,
    min_margin: int,
    damage_limit: int,
    crack_limit: int,
    reserve_margin: int,
    operating_bounds_ok: bool,
    safe: bool,
)
    requires
        safe_decision_relation(
            damage,
            crack,
            min_margin,
            damage_limit,
            crack_limit,
            reserve_margin,
            operating_bounds_ok,
            safe,
        ),
        safe,
    ensures
        damage <= damage_limit,
        crack <= crack_limit,
        reserve_margin <= min_margin,
        operating_bounds_ok,
{
}

pub open spec fn serialization_round_trip_preserves_lengths(
    public_inputs_len: nat,
    proof_bytes_len: nat,
    decoded_public_inputs_len: nat,
    decoded_proof_bytes_len: nat,
) -> bool {
    public_inputs_len == decoded_public_inputs_len
        && proof_bytes_len == decoded_proof_bytes_len
}

pub open spec fn witness_shape_consistency(
    mission_steps: nat,
    sections: nat,
    geometry_stations: nat,
) -> bool {
    mission_steps == turbine_default_step_count()
        && sections == turbine_control_sections()
        && geometry_stations == turbine_geometry_stations()
}

pub proof fn witness_shape_matches_fixed_surface(
    mission_steps: nat,
    sections: nat,
    geometry_stations: nat,
)
    requires
        witness_shape_consistency(mission_steps, sections, geometry_stations),
    ensures
        mission_steps == 500,
        sections == 3,
        geometry_stations == 8,
{
}

}
