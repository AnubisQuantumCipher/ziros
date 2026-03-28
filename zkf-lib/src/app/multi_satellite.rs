#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use num_bigint::{BigInt, Sign};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::f64::consts::PI;
use zkf_core::{
    BigIntFieldValue, BlackBoxOp, Expr, FieldElement, FieldId, FieldValue, Witness, WitnessInputs,
    mod_inverse_bigint,
};
use zkf_core::{ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::private_identity::poseidon_permutation4_bn254;
use super::templates::TemplateProgram;

pub const PRIVATE_MULTI_SATELLITE_DIMENSIONS: usize = 3;
pub const PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS: usize = 2;
pub const PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE: usize = 11;
pub const PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS: usize = 60;

pub const PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT: usize = 32;
pub const PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT: usize = 64;
pub const PRIVATE_MULTI_SATELLITE_BASE_STEPS: usize = 120;
pub const PRIVATE_MULTI_SATELLITE_BASE_PUBLIC_OUTPUTS: usize =
    PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT
        + (PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT * 2)
        + 1;

pub const PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT: usize = 64;
pub const PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT: usize = 256;
pub const PRIVATE_MULTI_SATELLITE_STRESS_STEPS: usize = 240;
pub const PRIVATE_MULTI_SATELLITE_STRESS_PUBLIC_OUTPUTS: usize =
    PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT
        + (PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT * 2)
        + 1;

const PRIVATE_MULTI_SATELLITE_MINI_SATELLITE_COUNT: usize = 4;
const PRIVATE_MULTI_SATELLITE_MINI_PAIR_COUNT: usize = 4;
const PRIVATE_MULTI_SATELLITE_MINI_STEPS: usize = 4;
const PRIVATE_MULTI_SATELLITE_BASE_OFFSETS: &[usize] = &[1, 5];
const PRIVATE_MULTI_SATELLITE_STRESS_OFFSETS: &[usize] = &[1, 5, 9, 13];
const PRIVATE_MULTI_SATELLITE_MINI_OFFSETS: &[usize] = &[1];
const AXES: [&str; PRIVATE_MULTI_SATELLITE_DIMENSIONS] = ["x", "y", "z"];

const BASE32_DESCRIPTION: &str = "Simulate a private 32-satellite Earth-dominant conjunction-screening batch for 120 one-minute steps, prove 64 designated conjunction checks and per-satellite delta-v budgets, and reveal only final-state commitments, pairwise minimum separations, pairwise safety bits, and a mission safety commitment.";
const STRESS64_DESCRIPTION: &str = "Simulate a private 64-satellite Earth-dominant conjunction-screening batch for 240 one-minute steps, prove 256 designated conjunction checks and per-satellite delta-v budgets, and reveal only final-state commitments, pairwise minimum separations, pairwise safety bits, and a mission safety commitment.";
const MINI_DESCRIPTION: &str =
    "Doc-hidden mini regression helper for the private multi-satellite conjunction showcase.";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMultiSatelliteScenario {
    Base32,
    Stress64,
    Mini,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PrivateMultiSatelliteScenarioSpec {
    pub scenario: PrivateMultiSatelliteScenario,
    pub scenario_id: &'static str,
    pub satellite_count: usize,
    pub pair_count: usize,
    pub steps: usize,
    pub timestep_seconds: usize,
    pub pair_offsets: &'static [usize],
    pub collision_threshold: &'static str,
    pub delta_v_budget: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PairCheck {
    pub index: usize,
    pub offset: usize,
    pub sat_a: usize,
    pub sat_b: usize,
}

const BASE32_SPEC: PrivateMultiSatelliteScenarioSpec = PrivateMultiSatelliteScenarioSpec {
    scenario: PrivateMultiSatelliteScenario::Base32,
    scenario_id: "base32",
    satellite_count: PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT,
    pair_count: PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT,
    steps: PRIVATE_MULTI_SATELLITE_BASE_STEPS,
    timestep_seconds: PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS,
    pair_offsets: PRIVATE_MULTI_SATELLITE_BASE_OFFSETS,
    collision_threshold: "100",
    delta_v_budget: "0.005",
    description: BASE32_DESCRIPTION,
};

const STRESS64_SPEC: PrivateMultiSatelliteScenarioSpec = PrivateMultiSatelliteScenarioSpec {
    scenario: PrivateMultiSatelliteScenario::Stress64,
    scenario_id: "stress64",
    satellite_count: PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT,
    pair_count: PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT,
    steps: PRIVATE_MULTI_SATELLITE_STRESS_STEPS,
    timestep_seconds: PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS,
    pair_offsets: PRIVATE_MULTI_SATELLITE_STRESS_OFFSETS,
    collision_threshold: "100",
    delta_v_budget: "0.005",
    description: STRESS64_DESCRIPTION,
};

const MINI_SPEC: PrivateMultiSatelliteScenarioSpec = PrivateMultiSatelliteScenarioSpec {
    scenario: PrivateMultiSatelliteScenario::Mini,
    scenario_id: "mini",
    satellite_count: PRIVATE_MULTI_SATELLITE_MINI_SATELLITE_COUNT,
    pair_count: PRIVATE_MULTI_SATELLITE_MINI_PAIR_COUNT,
    steps: PRIVATE_MULTI_SATELLITE_MINI_STEPS,
    timestep_seconds: PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS,
    pair_offsets: PRIVATE_MULTI_SATELLITE_MINI_OFFSETS,
    collision_threshold: "50",
    delta_v_budget: "0.002",
    description: MINI_DESCRIPTION,
};

pub fn private_multi_satellite_scenario_spec(
    scenario: PrivateMultiSatelliteScenario,
) -> &'static PrivateMultiSatelliteScenarioSpec {
    match scenario {
        PrivateMultiSatelliteScenario::Base32 => &BASE32_SPEC,
        PrivateMultiSatelliteScenario::Stress64 => &STRESS64_SPEC,
        PrivateMultiSatelliteScenario::Mini => &MINI_SPEC,
    }
}

pub fn private_multi_satellite_pair_schedule(
    scenario: PrivateMultiSatelliteScenario,
) -> ZkfResult<Vec<PairCheck>> {
    let spec = private_multi_satellite_scenario_spec(scenario);
    pair_schedule_for_spec(spec)
}

fn zero() -> BigInt {
    BigInt::from(0u8)
}

fn one() -> BigInt {
    BigInt::from(1u8)
}

fn two() -> BigInt {
    BigInt::from(2u8)
}

fn fixed_scale() -> BigInt {
    BigInt::from(10u8).pow(18)
}

fn fixed_scale_squared() -> BigInt {
    let scale = fixed_scale();
    &scale * &scale
}

fn fixed_scale_fourth() -> BigInt {
    let scale = fixed_scale();
    &scale * &scale * &scale * &scale
}

fn bn254_square(value: &BigInt) -> FieldElement {
    let value = BigIntFieldValue::new(FieldId::Bn254, value.clone());
    value.mul(&value).to_field_element()
}

fn decimal_scaled(value: &str) -> BigInt {
    fn decimal_digits_to_bigint(digits: &str) -> BigInt {
        digits
            .bytes()
            .filter(|digit| digit.is_ascii_digit())
            .fold(zero(), |acc, digit| {
                acc * BigInt::from(10u8) + BigInt::from(u32::from(digit - b'0'))
            })
    }

    let negative = value.starts_with('-');
    let body = if negative { &value[1..] } else { value };
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    let whole_value = if whole.is_empty() {
        zero()
    } else {
        decimal_digits_to_bigint(whole)
    };
    let mut fraction_digits = fraction.to_string();
    if fraction_digits.len() > 18 {
        fraction_digits.truncate(18);
    }
    while fraction_digits.len() < 18 {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        decimal_digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * fixed_scale() + fraction_value;
    if negative { -scaled } else { scaled }
}

fn decimal_scaled_f64(value: f64) -> BigInt {
    decimal_scaled(&format!("{value:.18}"))
}

fn field(value: BigInt) -> FieldElement {
    FieldElement::from_bigint(value)
}

fn field_ref(value: &BigInt) -> FieldElement {
    FieldElement::from_bigint(value.clone())
}

fn const_expr(value: &BigInt) -> Expr {
    Expr::Const(field_ref(value))
}

fn signal_expr(name: &str) -> Expr {
    Expr::signal(name)
}

fn mul_expr(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

fn sub_expr(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

fn add_expr(mut values: Vec<Expr>) -> Expr {
    if values.len() == 1 {
        values.remove(0)
    } else {
        Expr::Add(values)
    }
}

fn neg_expr(expr: Expr) -> Expr {
    sub_expr(const_expr(&zero()), expr)
}

fn time_step_seconds() -> BigInt {
    BigInt::from(PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS as u64)
}

fn time_step_squared() -> BigInt {
    let dt = time_step_seconds();
    &dt * &dt
}

fn mu_earth_scaled() -> BigInt {
    decimal_scaled("398600.4418")
}

fn position_bound() -> BigInt {
    decimal_scaled("50000")
}

fn velocity_bound() -> BigInt {
    decimal_scaled("20")
}

fn delta_v_component_bound() -> BigInt {
    decimal_scaled("0.10")
}

fn burn_velocity_bound() -> BigInt {
    velocity_bound() + delta_v_component_bound()
}

fn mass_bound() -> BigInt {
    decimal_scaled("20000")
}

fn perturbation_bound() -> BigInt {
    decimal_scaled("0.00010")
}

fn acceleration_bound() -> BigInt {
    decimal_scaled("0.050")
}

fn min_radius() -> BigInt {
    decimal_scaled("6500")
}

fn max_separation_bound() -> BigInt {
    decimal_scaled("200000")
}

fn delta_v_total_bound() -> BigInt {
    decimal_scaled("0.50")
}

fn min_radius_squared() -> BigInt {
    let radius = min_radius();
    &radius * &radius
}

fn max_radius_squared() -> BigInt {
    BigInt::from(3u8) * position_bound() * position_bound()
}

fn inv_r_squared_residual_bound() -> BigInt {
    BigInt::from(8u8) * max_radius_squared() * fixed_scale_fourth()
}

fn inv_r3_remainder_bound() -> BigInt {
    fixed_scale_squared() / BigInt::from(2u8)
}

fn factor_remainder_bound() -> BigInt {
    fixed_scale() / BigInt::from(2u8)
}

fn component_remainder_bound() -> BigInt {
    fixed_scale() / BigInt::from(2u8)
}

fn integration_remainder_bound() -> BigInt {
    one()
}

fn impulse_remainder_bound() -> BigInt {
    fixed_scale() / BigInt::from(2u8)
}

fn sqrt_residual_bound(distance_bound: &BigInt) -> BigInt {
    (distance_bound * BigInt::from(2u8)) + one()
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
}

fn burn_step_bits(steps: usize) -> u32 {
    let max = if steps > 0 { steps - 1 } else { 0 };
    bits_for_bound(&BigInt::from(max as u64))
}

fn abs_bigint(value: BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        -value
    } else {
        value
    }
}

fn bigint_isqrt_floor(value: &BigInt) -> BigInt {
    if *value <= one() {
        return value.clone();
    }

    let mut low = one();
    let mut high = one() << ((bits_for_bound(value) / 2) + 2);
    while &low + &one() < high {
        let mid = (&low + &high) / BigInt::from(2u8);
        let mid_sq = &mid * &mid;
        if mid_sq <= *value {
            low = mid;
        } else {
            high = mid;
        }
    }
    low
}

fn nearest_integer_sqrt(value: &BigInt) -> BigInt {
    let floor = bigint_isqrt_floor(value);
    let next = &floor + &one();
    let floor_err = abs_bigint((&floor * &floor) - value);
    let next_err = abs_bigint((&next * &next) - value);
    if next_err < floor_err { next } else { floor }
}

fn nearest_inverse_distance(distance_squared: &BigInt) -> BigInt {
    let target = fixed_scale_fourth();
    let upper = fixed_scale_squared() / min_radius_squared();
    let mut low = zero();
    let mut high = &upper + &one();
    while &low + &one() < high {
        let mid = (&low + &high) / BigInt::from(2u8);
        let probe = distance_squared * &mid * &mid;
        if probe <= target {
            low = mid;
        } else {
            high = mid;
        }
    }

    let low_err = abs_bigint(target.clone() - distance_squared * &low * &low);
    if high <= upper {
        let high_err = abs_bigint(target.clone() - distance_squared * &high * &high);
        if high_err < low_err {
            return high;
        }
    }
    low
}

fn div_round_nearest(value: &BigInt, denominator: &BigInt) -> (BigInt, BigInt) {
    let negative = value.sign() == Sign::Minus;
    let magnitude = if negative {
        -value.clone()
    } else {
        value.clone()
    };
    let quotient = &magnitude / denominator;
    let remainder = &magnitude % denominator;
    let rounded = if &remainder * BigInt::from(2u8) >= *denominator {
        quotient + one()
    } else {
        quotient
    };
    let signed = if negative { -rounded } else { rounded };
    let residual = value - (&signed * denominator);
    (signed, residual)
}

fn window_hours_metadata(steps: usize) -> String {
    if steps.is_multiple_of(60) {
        (steps / 60).to_string()
    } else {
        format!("{:.6}", steps as f64 / 60.0)
    }
}

fn collision_threshold_name() -> &'static str {
    "collision_threshold"
}

fn delta_v_budget_name() -> &'static str {
    "delta_v_budget"
}

fn mission_safety_commitment_name() -> &'static str {
    "mission_safety_commitment"
}

fn mass_name(satellite: usize) -> String {
    format!("sat{satellite}_mass")
}

fn pos_input_name(satellite: usize, axis: &str) -> String {
    format!("sat{satellite}_pos_{axis}")
}

fn vel_input_name(satellite: usize, axis: &str) -> String {
    format!("sat{satellite}_vel_{axis}")
}

fn dv_name(satellite: usize, axis: &str) -> String {
    format!("sat{satellite}_dv_{axis}")
}

fn burn_step_name(satellite: usize) -> String {
    format!("sat{satellite}_burn_step")
}

fn pos_name(step: usize, satellite: usize, axis: &str) -> String {
    if step == 0 {
        pos_input_name(satellite, axis)
    } else {
        format!("step_{step}_sat{satellite}_pos_{axis}")
    }
}

fn vel_name(step: usize, satellite: usize, axis: &str) -> String {
    if step == 0 {
        vel_input_name(satellite, axis)
    } else {
        format!("step_{step}_sat{satellite}_vel_{axis}")
    }
}

fn burn_flag_name(satellite: usize, step: usize) -> String {
    format!("sat{satellite}_burn_flag_{step}")
}

fn burn_velocity_name(step: usize, satellite: usize, axis: &str) -> String {
    format!("step_{step}_sat{satellite}_burn_vel_{axis}")
}

fn perturbation_name(state: usize, satellite: usize, axis: &str) -> String {
    format!("state_{state}_sat{satellite}_perturb_{axis}")
}

fn acceleration_name(state: usize, satellite: usize, axis: &str) -> String {
    format!("state_{state}_sat{satellite}_acc_{axis}")
}

fn radius_sq_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_radius_sq")
}

fn radius_floor_slack_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_radius_floor_slack")
}

fn radius_floor_anchor_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_radius_floor_anchor")
}

fn inverse_distance_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r")
}

fn inverse_distance_sq_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r_sq")
}

fn inverse_distance_sq_residual_positive_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r_sq_residual_positive")
}

fn inverse_distance_sq_residual_negative_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r_sq_residual_negative")
}

fn inverse_distance_cubed_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r_cubed")
}

fn inverse_distance_cubed_residual_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_inv_r_cubed_residual")
}

fn gravity_factor_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_gravity_factor")
}

fn gravity_factor_residual_name(state: usize, satellite: usize) -> String {
    format!("state_{state}_sat{satellite}_gravity_factor_residual")
}

fn gravity_component_name(state: usize, satellite: usize, axis: &str) -> String {
    format!("state_{state}_sat{satellite}_gravity_component_{axis}")
}

fn gravity_component_residual_name(state: usize, satellite: usize, axis: &str) -> String {
    format!("state_{state}_sat{satellite}_gravity_component_residual_{axis}")
}

fn position_update_residual_name(step: usize, satellite: usize, axis: &str) -> String {
    format!("step_{step}_sat{satellite}_position_update_residual_{axis}")
}

fn velocity_update_residual_name(step: usize, satellite: usize, axis: &str) -> String {
    format!("step_{step}_sat{satellite}_velocity_update_residual_{axis}")
}

fn delta_v_norm_sq_name(satellite: usize) -> String {
    format!("sat{satellite}_dv_norm_sq")
}

fn delta_v_norm_name(satellite: usize) -> String {
    format!("sat{satellite}_dv_norm")
}

fn delta_v_norm_residual_name(satellite: usize) -> String {
    format!("sat{satellite}_dv_norm_residual")
}

fn delta_v_budget_slack_name(satellite: usize) -> String {
    format!("sat{satellite}_dv_budget_slack")
}

fn impulse_name(satellite: usize, axis: &str) -> String {
    format!("sat{satellite}_impulse_{axis}")
}

fn impulse_residual_name(satellite: usize, axis: &str) -> String {
    format!("sat{satellite}_impulse_residual_{axis}")
}

fn pair_delta_name(pair_index: usize, state: usize, axis: &str) -> String {
    format!("pair_{pair_index}_state_{state}_delta_{axis}")
}

fn pair_distance_sq_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_distance_sq")
}

fn pair_distance_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_distance")
}

fn pair_distance_residual_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_distance_residual")
}

fn pair_run_min_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_running_min")
}

fn pair_run_min_prev_slack_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_running_min_prev_slack")
}

fn pair_run_min_curr_slack_name(pair_index: usize, state: usize) -> String {
    format!("pair_{pair_index}_state_{state}_running_min_curr_slack")
}

fn pair_minimum_separation_output_name(pair_index: usize) -> String {
    format!("pair_{pair_index}_minimum_separation")
}

fn pair_safe_output_name(pair_index: usize) -> String {
    format!("pair_{pair_index}_safe")
}

fn pair_safe_slack_name(pair_index: usize) -> String {
    format!("pair_{pair_index}_safe_slack")
}

fn pair_unsafe_shortfall_name(pair_index: usize) -> String {
    format!("pair_{pair_index}_unsafe_shortfall")
}

fn final_position_tag(satellite: usize) -> BigInt {
    BigInt::from(10_000u64 + satellite as u64)
}

fn final_velocity_tag(satellite: usize) -> BigInt {
    BigInt::from(20_000u64 + satellite as u64)
}

fn final_state_tag(satellite: usize) -> BigInt {
    BigInt::from(30_000u64 + satellite as u64)
}

fn mission_fold_domain_tag() -> BigInt {
    BigInt::from(50_000u64)
}

fn final_state_commitment_output_name(satellite: usize) -> String {
    format!("sat{satellite}_final_state_commitment")
}

fn positive_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_positive_bound_slack")
}

fn positive_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_positive_bound_anchor")
}

fn signed_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_signed_bound_slack")
}

fn nonnegative_upper_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_upper_bound_slack")
}

fn nonnegative_upper_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_upper_bound_anchor")
}

fn nonzero_inverse_name(prefix: &str) -> String {
    format!("{prefix}_nonzero_inverse")
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ]
}

fn pair_schedule_for_spec(spec: &PrivateMultiSatelliteScenarioSpec) -> ZkfResult<Vec<PairCheck>> {
    let mut seen = BTreeSet::new();
    let mut schedule = Vec::with_capacity(spec.pair_count);
    for &offset in spec.pair_offsets {
        if offset == 0 || offset >= spec.satellite_count {
            return Err(ZkfError::InvalidArtifact(format!(
                "invalid pair offset {offset} for scenario {}",
                spec.scenario_id
            )));
        }
        for sat_a in 0..spec.satellite_count {
            let sat_b = (sat_a + offset) % spec.satellite_count;
            let unordered = if sat_a < sat_b {
                (sat_a, sat_b)
            } else {
                (sat_b, sat_a)
            };
            if !seen.insert((offset, unordered.0, unordered.1)) {
                return Err(ZkfError::InvalidArtifact(format!(
                    "duplicate pair schedule entry for scenario {} offset {} pair ({}, {})",
                    spec.scenario_id, offset, unordered.0, unordered.1
                )));
            }
            schedule.push(PairCheck {
                index: schedule.len(),
                offset,
                sat_a,
                sat_b,
            });
        }
    }
    if schedule.len() != spec.pair_count {
        return Err(ZkfError::InvalidArtifact(format!(
            "scenario {} expected {} designated pairs but produced {}",
            spec.scenario_id,
            spec.pair_count,
            schedule.len()
        )));
    }
    Ok(schedule)
}

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: BigInt,
) {
    values.insert(name.into(), field(value));
}

fn write_signed_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = (bound * bound) - (value * value);
    if slack < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed bound slack underflow for {prefix}"
        )));
    }
    write_value(values, signed_bound_slack_name(prefix), slack);
    Ok(())
}

fn write_positive_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = bound - value;
    if slack < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "positive bound slack underflow for {prefix}"
        )));
    }
    let slack_field = field_ref(&slack);
    values.insert(positive_bound_slack_name(prefix), slack_field.clone());
    values.insert(positive_bound_anchor_name(prefix), bn254_square(&slack));
    Ok(())
}

fn write_nonnegative_upper_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = bound - value;
    if slack < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "nonnegative upper bound slack underflow for {prefix}"
        )));
    }
    let slack_field = field_ref(&slack);
    values.insert(
        nonnegative_upper_bound_slack_name(prefix),
        slack_field.clone(),
    );
    values.insert(
        nonnegative_upper_bound_anchor_name(prefix),
        bn254_square(&slack),
    );
    Ok(())
}

fn write_nonzero_inverse_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let inverse = mod_inverse_bigint(value.clone(), FieldId::Bn254.modulus()).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!("failed to compute field inverse for {prefix}"))
    })?;
    write_value(values, nonzero_inverse_name(prefix), inverse);
    Ok(())
}

fn read_input(inputs: &WitnessInputs, name: &str) -> ZkfResult<BigInt> {
    inputs
        .get(name)
        .map(FieldElement::as_bigint)
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: name.to_string(),
        })
}

fn ensure_abs_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if abs_bigint(value.clone()) > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} exceeded bound {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn ensure_positive_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value <= zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} must satisfy 0 < value <= {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn ensure_nonnegative_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value < zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} must satisfy 0 <= value <= {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn append_signed_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = signed_bound_slack_name(prefix);
    let bound_squared = bound * bound;
    builder.private_signal(&slack)?;
    builder.constrain_equal(
        add_expr(vec![
            mul_expr(signal_expr(signal), signal_expr(signal)),
            signal_expr(&slack),
        ]),
        const_expr(&bound_squared),
    )?;
    builder.constrain_range(&slack, bits_for_bound(&bound_squared))?;
    Ok(())
}

fn append_positive_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = positive_bound_slack_name(prefix);
    let anchor = positive_bound_anchor_name(prefix);
    builder.private_signal(&slack)?;
    builder.private_signal(&anchor)?;
    builder.constrain_equal(
        add_expr(vec![signal_expr(signal), signal_expr(&slack)]),
        const_expr(bound),
    )?;
    builder.constrain_range(&slack, bits_for_bound(bound))?;
    builder.constrain_equal(
        signal_expr(&anchor),
        mul_expr(signal_expr(&slack), signal_expr(&slack)),
    )?;
    Ok(())
}

fn append_nonnegative_upper_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = nonnegative_upper_bound_slack_name(prefix);
    let anchor = nonnegative_upper_bound_anchor_name(prefix);
    builder.private_signal(&slack)?;
    builder.private_signal(&anchor)?;
    builder.constrain_equal(
        add_expr(vec![signal_expr(signal), signal_expr(&slack)]),
        const_expr(bound),
    )?;
    builder.constrain_range(&slack, bits_for_bound(bound))?;
    builder.constrain_equal(
        signal_expr(&anchor),
        mul_expr(signal_expr(&slack), signal_expr(&slack)),
    )?;
    Ok(())
}

fn append_nonzero_constraint(
    builder: &mut ProgramBuilder,
    signal: &str,
    prefix: &str,
) -> ZkfResult<()> {
    let inverse = nonzero_inverse_name(prefix);
    builder.private_signal(&inverse)?;
    builder.constrain_equal(
        mul_expr(signal_expr(signal), signal_expr(&inverse)),
        Expr::Const(FieldElement::ONE),
    )?;
    Ok(())
}

fn append_poseidon_hash(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: [Expr; 4],
) -> ZkfResult<String> {
    let states = hash_state_names(prefix);
    for lane in &states {
        builder.private_signal(lane)?;
    }
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    builder.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &inputs,
        &[
            states[0].as_str(),
            states[1].as_str(),
            states[2].as_str(),
            states[3].as_str(),
        ],
        &params,
    )?;
    Ok(states[0].clone())
}

fn append_poseidon_fold(
    builder: &mut ProgramBuilder,
    prefix: &str,
    values: &[Expr],
    domain_tag: &BigInt,
) -> ZkfResult<String> {
    let mut acc = append_poseidon_hash(
        builder,
        &format!("{prefix}_seed"),
        [
            const_expr(&zero()),
            const_expr(&zero()),
            const_expr(domain_tag),
            const_expr(&BigInt::from(values.len() as u64)),
        ],
    )?;
    for (index, value) in values.iter().enumerate() {
        acc = append_poseidon_hash(
            builder,
            &format!("{prefix}_fold_{index}"),
            [
                signal_expr(&acc),
                value.clone(),
                const_expr(&BigInt::from(index as u64)),
                const_expr(domain_tag),
            ],
        )?;
    }
    Ok(acc)
}

fn append_pair_separation_constraints(
    builder: &mut ProgramBuilder,
    pair_index: usize,
    pair: PairCheck,
    state: usize,
) -> ZkfResult<()> {
    let delta_names = AXES
        .iter()
        .map(|axis| pair_delta_name(pair_index, state, axis))
        .collect::<Vec<_>>();
    for (axis_index, axis) in AXES.iter().enumerate() {
        builder.private_signal(&delta_names[axis_index])?;
        builder.constrain_equal(
            signal_expr(&delta_names[axis_index]),
            sub_expr(
                signal_expr(&pos_name(state, pair.sat_b, axis)),
                signal_expr(&pos_name(state, pair.sat_a, axis)),
            ),
        )?;
    }

    let distance_sq = pair_distance_sq_name(pair_index, state);
    let distance = pair_distance_name(pair_index, state);
    let distance_residual = pair_distance_residual_name(pair_index, state);

    builder.private_signal(&distance_sq)?;
    builder.private_signal(&distance)?;
    builder.private_signal(&distance_residual)?;
    builder.constrain_equal(
        signal_expr(&distance_sq),
        add_expr(
            delta_names
                .iter()
                .map(|name| mul_expr(signal_expr(name), signal_expr(name)))
                .collect(),
        ),
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr(&distance), signal_expr(&distance)),
        add_expr(vec![
            signal_expr(&distance_sq),
            signal_expr(&distance_residual),
        ]),
    )?;
    append_signed_bound(
        builder,
        &distance_residual,
        &sqrt_residual_bound(&max_separation_bound()),
        &format!("pair_{pair_index}_state_{state}_distance_residual_bound"),
    )?;
    append_nonnegative_upper_bound(
        builder,
        &distance,
        &max_separation_bound(),
        &format!("pair_{pair_index}_state_{state}_distance_bound"),
    )?;
    Ok(())
}

fn append_pair_running_min_and_safety_constraints(
    builder: &mut ProgramBuilder,
    pair_index: usize,
    steps: usize,
) -> ZkfResult<()> {
    let run_min_0 = pair_run_min_name(pair_index, 0);
    builder.private_signal(&run_min_0)?;
    builder.constrain_equal(
        signal_expr(&run_min_0),
        signal_expr(&pair_distance_name(pair_index, 0)),
    )?;
    append_nonnegative_upper_bound(
        builder,
        &run_min_0,
        &max_separation_bound(),
        &format!("pair_{pair_index}_state_0_running_min_bound"),
    )?;

    for state in 1..=steps {
        let current = pair_run_min_name(pair_index, state);
        let previous = pair_run_min_name(pair_index, state - 1);
        let prev_slack = pair_run_min_prev_slack_name(pair_index, state);
        let curr_slack = pair_run_min_curr_slack_name(pair_index, state);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_upper_bound(
            builder,
            &current,
            &max_separation_bound(),
            &format!("pair_{pair_index}_state_{state}_running_min_bound"),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&prev_slack)]),
            signal_expr(&previous),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&curr_slack)]),
            signal_expr(&pair_distance_name(pair_index, state)),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&max_separation_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&max_separation_bound()))?;
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    let minimum_output = pair_minimum_separation_output_name(pair_index);
    let safe_output = pair_safe_output_name(pair_index);
    let safe_slack = pair_safe_slack_name(pair_index);
    let unsafe_shortfall = pair_unsafe_shortfall_name(pair_index);
    builder.public_output(&minimum_output)?;
    builder.public_output(&safe_output)?;
    builder.private_signal(&safe_slack)?;
    builder.private_signal(&unsafe_shortfall)?;
    builder.constrain_equal(
        signal_expr(&minimum_output),
        signal_expr(&pair_run_min_name(pair_index, steps)),
    )?;
    append_nonnegative_upper_bound(
        builder,
        &minimum_output,
        &max_separation_bound(),
        &format!("pair_{pair_index}_minimum_separation_public_bound"),
    )?;
    builder.constrain_boolean(&safe_output)?;
    builder.constrain_equal(
        add_expr(vec![
            signal_expr(&minimum_output),
            signal_expr(&unsafe_shortfall),
            sub_expr(const_expr(&one()), signal_expr(&safe_output)),
        ]),
        add_expr(vec![
            signal_expr(collision_threshold_name()),
            signal_expr(&safe_slack),
        ]),
    )?;
    builder.constrain_range(&safe_slack, bits_for_bound(&max_separation_bound()))?;
    builder.constrain_range(&unsafe_shortfall, bits_for_bound(&max_separation_bound()))?;
    builder.constrain_equal(
        mul_expr(
            signal_expr(&safe_slack),
            sub_expr(const_expr(&one()), signal_expr(&safe_output)),
        ),
        const_expr(&zero()),
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr(&unsafe_shortfall), signal_expr(&safe_output)),
        const_expr(&zero()),
    )?;
    Ok(())
}

fn append_acceleration_constraints(
    builder: &mut ProgramBuilder,
    satellite_count: usize,
    state: usize,
) -> ZkfResult<()> {
    for satellite in 0..satellite_count {
        let radius_sq = radius_sq_name(state, satellite);
        let radius_floor_slack = radius_floor_slack_name(state, satellite);
        let radius_floor_anchor = radius_floor_anchor_name(state, satellite);
        let inverse_distance = inverse_distance_name(state, satellite);
        let inverse_distance_sq = inverse_distance_sq_name(state, satellite);
        let inverse_distance_sq_residual_positive =
            inverse_distance_sq_residual_positive_name(state, satellite);
        let inverse_distance_sq_residual_negative =
            inverse_distance_sq_residual_negative_name(state, satellite);
        let inverse_distance_cubed = inverse_distance_cubed_name(state, satellite);
        let inverse_distance_cubed_residual =
            inverse_distance_cubed_residual_name(state, satellite);
        let gravity_factor = gravity_factor_name(state, satellite);
        let gravity_factor_residual = gravity_factor_residual_name(state, satellite);

        builder.private_signal(&radius_sq)?;
        builder.private_signal(&radius_floor_slack)?;
        builder.private_signal(&radius_floor_anchor)?;
        builder.private_signal(&inverse_distance)?;
        builder.private_signal(&inverse_distance_sq)?;
        builder.private_signal(&inverse_distance_sq_residual_positive)?;
        builder.private_signal(&inverse_distance_sq_residual_negative)?;
        builder.private_signal(&inverse_distance_cubed)?;
        builder.private_signal(&inverse_distance_cubed_residual)?;
        builder.private_signal(&gravity_factor)?;
        builder.private_signal(&gravity_factor_residual)?;

        builder.constrain_equal(
            signal_expr(&radius_sq),
            add_expr(
                AXES.iter()
                    .map(|axis| {
                        mul_expr(
                            signal_expr(&pos_name(state, satellite, axis)),
                            signal_expr(&pos_name(state, satellite, axis)),
                        )
                    })
                    .collect(),
            ),
        )?;
        builder.constrain_equal(
            add_expr(vec![
                const_expr(&min_radius_squared()),
                signal_expr(&radius_floor_slack),
            ]),
            signal_expr(&radius_sq),
        )?;
        builder.constrain_range(
            &radius_floor_slack,
            bits_for_bound(&(max_radius_squared() - min_radius_squared())),
        )?;
        builder.constrain_equal(
            signal_expr(&radius_floor_anchor),
            mul_expr(
                signal_expr(&radius_floor_slack),
                signal_expr(&radius_floor_slack),
            ),
        )?;

        builder.constrain_equal(
            signal_expr(&inverse_distance_sq),
            mul_expr(
                signal_expr(&inverse_distance),
                signal_expr(&inverse_distance),
            ),
        )?;
        builder.constrain_equal(
            add_expr(vec![
                mul_expr(signal_expr(&radius_sq), signal_expr(&inverse_distance_sq)),
                signal_expr(&inverse_distance_sq_residual_positive),
            ]),
            add_expr(vec![
                const_expr(&fixed_scale_fourth()),
                signal_expr(&inverse_distance_sq_residual_negative),
            ]),
        )?;
        builder.constrain_range(
            &inverse_distance_sq_residual_positive,
            bits_for_bound(&inv_r_squared_residual_bound()),
        )?;
        builder.constrain_range(
            &inverse_distance_sq_residual_negative,
            bits_for_bound(&inv_r_squared_residual_bound()),
        )?;
        builder.constrain_equal(
            mul_expr(
                signal_expr(&inverse_distance_sq_residual_positive),
                signal_expr(&inverse_distance_sq_residual_negative),
            ),
            const_expr(&zero()),
        )?;

        builder.constrain_equal(
            mul_expr(
                signal_expr(&inverse_distance_sq),
                signal_expr(&inverse_distance),
            ),
            add_expr(vec![
                mul_expr(
                    signal_expr(&inverse_distance_cubed),
                    const_expr(&fixed_scale_squared()),
                ),
                signal_expr(&inverse_distance_cubed_residual),
            ]),
        )?;
        append_signed_bound(
            builder,
            &inverse_distance_cubed_residual,
            &inv_r3_remainder_bound(),
            &format!("state_{state}_sat{satellite}_inverse_distance_cubed_bound"),
        )?;

        builder.constrain_equal(
            mul_expr(
                const_expr(&mu_earth_scaled()),
                signal_expr(&inverse_distance_cubed),
            ),
            add_expr(vec![
                mul_expr(signal_expr(&gravity_factor), const_expr(&fixed_scale())),
                signal_expr(&gravity_factor_residual),
            ]),
        )?;
        append_signed_bound(
            builder,
            &gravity_factor_residual,
            &factor_remainder_bound(),
            &format!("state_{state}_sat{satellite}_gravity_factor_bound"),
        )?;

        for axis in AXES {
            let perturbation = perturbation_name(state, satellite, axis);
            let gravity_component = gravity_component_name(state, satellite, axis);
            let gravity_component_residual =
                gravity_component_residual_name(state, satellite, axis);
            let acceleration = acceleration_name(state, satellite, axis);
            builder.private_signal(&perturbation)?;
            builder.private_signal(&gravity_component)?;
            builder.private_signal(&gravity_component_residual)?;
            builder.private_signal(&acceleration)?;
            append_signed_bound(
                builder,
                &perturbation,
                &perturbation_bound(),
                &format!("state_{state}_sat{satellite}_perturbation_bound_{axis}"),
            )?;
            builder.constrain_equal(
                mul_expr(
                    neg_expr(signal_expr(&pos_name(state, satellite, axis))),
                    signal_expr(&gravity_factor),
                ),
                add_expr(vec![
                    mul_expr(signal_expr(&gravity_component), const_expr(&fixed_scale())),
                    signal_expr(&gravity_component_residual),
                ]),
            )?;
            append_signed_bound(
                builder,
                &gravity_component_residual,
                &component_remainder_bound(),
                &format!("state_{state}_sat{satellite}_gravity_component_bound_{axis}"),
            )?;
            builder.constrain_equal(
                signal_expr(&acceleration),
                add_expr(vec![
                    signal_expr(&gravity_component),
                    signal_expr(&perturbation),
                ]),
            )?;
            append_signed_bound(
                builder,
                &acceleration,
                &acceleration_bound(),
                &format!("state_{state}_sat{satellite}_acceleration_bound_{axis}"),
            )?;
        }
    }
    Ok(())
}

fn sample_inputs_for_spec(spec: &PrivateMultiSatelliteScenarioSpec) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    inputs.insert(
        collision_threshold_name().to_string(),
        field(decimal_scaled(spec.collision_threshold)),
    );
    inputs.insert(
        delta_v_budget_name().to_string(),
        field(decimal_scaled(spec.delta_v_budget)),
    );

    for satellite in 0..spec.satellite_count {
        let angle = (2.0 * PI * satellite as f64) / spec.satellite_count as f64;
        let radius = 7_000.0 + ((satellite % 4) as f64 * 12.5);
        let z = ((satellite % 5) as f64 - 2.0) * 1.25;
        let speed = (398_600.441_8_f64 / radius).sqrt();
        let mass = 850.0 + ((satellite * 37) % 250) as f64;
        let dv_scale_x = (satellite % 7) as f64 - 3.0;
        let dv_scale_y = ((satellite * 3) % 5) as f64 - 2.0;
        let dv_scale_z = ((satellite * 5) % 3) as f64 - 1.0;
        let position = [radius * angle.cos(), radius * angle.sin(), z];
        let velocity = [-speed * angle.sin(), speed * angle.cos(), 0.0];
        let delta_v = [
            dv_scale_x * 0.000002,
            dv_scale_y * 0.000002,
            dv_scale_z * 0.000001,
        ];
        let burn_step = BigInt::from(((satellite * 11) % spec.steps) as u64);

        inputs.insert(mass_name(satellite), field(decimal_scaled_f64(mass)));
        inputs.insert(burn_step_name(satellite), field_ref(&burn_step));
        for (axis_index, axis) in AXES.iter().enumerate() {
            inputs.insert(
                pos_input_name(satellite, axis),
                field(decimal_scaled_f64(position[axis_index])),
            );
            inputs.insert(
                vel_input_name(satellite, axis),
                field(decimal_scaled_f64(velocity[axis_index])),
            );
            inputs.insert(
                dv_name(satellite, axis),
                field(decimal_scaled_f64(delta_v[axis_index])),
            );
        }
    }

    inputs
}

pub fn private_multi_satellite_conjunction_showcase_base32() -> ZkfResult<TemplateProgram> {
    private_multi_satellite_conjunction_showcase_for_scenario(PrivateMultiSatelliteScenario::Base32)
}

pub fn private_multi_satellite_conjunction_showcase_stress64() -> ZkfResult<TemplateProgram> {
    private_multi_satellite_conjunction_showcase_for_scenario(
        PrivateMultiSatelliteScenario::Stress64,
    )
}

#[doc(hidden)]
pub fn private_multi_satellite_conjunction_showcase_for_scenario(
    scenario: PrivateMultiSatelliteScenario,
) -> ZkfResult<TemplateProgram> {
    let spec = private_multi_satellite_scenario_spec(scenario);
    let pair_schedule = pair_schedule_for_spec(spec)?;

    let mut builder = ProgramBuilder::new(
        format!(
            "private_multi_satellite_conjunction_{}_sat_{}_pair_{}_step",
            spec.satellite_count, spec.pair_count, spec.steps
        ),
        FieldId::Bn254,
    );
    builder.metadata_entry(
        "application",
        "private-multi-satellite-conjunction-showcase",
    )?;
    builder.metadata_entry("scenario", spec.scenario_id)?;
    builder.metadata_entry("satellite_count", spec.satellite_count.to_string())?;
    builder.metadata_entry("designated_pair_count", spec.pair_count.to_string())?;
    builder.metadata_entry("pair_offsets", format!("{:?}", spec.pair_offsets))?;
    builder.metadata_entry(
        "pair_schedule",
        serde_json::to_string(&pair_schedule).map_err(|error| {
            ZkfError::Serialization(format!("serialize pair schedule: {error}"))
        })?,
    )?;
    builder.metadata_entry("dimensions", PRIVATE_MULTI_SATELLITE_DIMENSIONS.to_string())?;
    builder.metadata_entry("integration_steps", spec.steps.to_string())?;
    builder.metadata_entry("integrator", "velocity-verlet")?;
    builder.metadata_entry("time_step_seconds", spec.timestep_seconds.to_string())?;
    builder.metadata_entry("window_hours", window_hours_metadata(spec.steps))?;
    builder.metadata_entry("gravity_model", "earth-dominant-newtonian")?;
    builder.metadata_entry(
        "pair_schedule_ordering",
        "stable (offset, satellite_index) cyclic designated pairs",
    )?;
    builder.metadata_entry(
        "safe_indicator_semantics",
        "public pair safe bit is 1 iff pair minimum separation is greater than or equal to the public collision threshold",
    )?;
    builder.metadata_entry(
        "delta_v_budget_semantics",
        "public per-satellite budget enforced as dv_norm <= delta_v_budget for every satellite; violations invalidate the proof",
    )?;
    builder.metadata_entry("fixed_point_scale", fixed_scale().to_str_radix(10))?;
    builder.metadata_entry("mu_earth_scaled", mu_earth_scaled().to_str_radix(10))?;
    builder.metadata_entry("position_bound_scaled", position_bound().to_str_radix(10))?;
    builder.metadata_entry("velocity_bound_scaled", velocity_bound().to_str_radix(10))?;
    builder.metadata_entry(
        "burn_velocity_bound_scaled",
        burn_velocity_bound().to_str_radix(10),
    )?;
    builder.metadata_entry("mass_bound_scaled", mass_bound().to_str_radix(10))?;
    builder.metadata_entry(
        "perturbation_bound_scaled",
        perturbation_bound().to_str_radix(10),
    )?;
    builder.metadata_entry(
        "acceleration_bound_scaled",
        acceleration_bound().to_str_radix(10),
    )?;
    builder.metadata_entry("min_radius_scaled", min_radius().to_str_radix(10))?;
    builder.metadata_entry(
        "max_separation_bound_scaled",
        max_separation_bound().to_str_radix(10),
    )?;
    builder.metadata_entry(
        "delta_v_component_bound_scaled",
        delta_v_component_bound().to_str_radix(10),
    )?;
    builder.metadata_entry(
        "delta_v_total_bound_scaled",
        delta_v_total_bound().to_str_radix(10),
    )?;
    builder.metadata_entry("burn_schedule", "exactly-one-impulse-per-satellite")?;
    builder.metadata_entry("determinism", "fixed-seed-runtime-and-proof-path")?;

    let mut expected_inputs = Vec::with_capacity(
        (spec.satellite_count * PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE)
            + PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS,
    );
    let mut public_outputs = Vec::with_capacity(spec.satellite_count + (spec.pair_count * 2) + 1);

    builder.public_input(collision_threshold_name())?;
    builder.public_input(delta_v_budget_name())?;
    expected_inputs.push(collision_threshold_name().to_string());
    expected_inputs.push(delta_v_budget_name().to_string());
    append_positive_bound(
        &mut builder,
        collision_threshold_name(),
        &max_separation_bound(),
        "collision_threshold_bound",
    )?;
    append_positive_bound(
        &mut builder,
        delta_v_budget_name(),
        &delta_v_total_bound(),
        "delta_v_budget_bound",
    )?;
    append_nonzero_constraint(
        &mut builder,
        collision_threshold_name(),
        "collision_threshold_nonzero",
    )?;
    append_nonzero_constraint(
        &mut builder,
        delta_v_budget_name(),
        "delta_v_budget_nonzero",
    )?;

    for satellite in 0..spec.satellite_count {
        let mass = mass_name(satellite);
        let burn_step = burn_step_name(satellite);
        builder.private_input(&mass)?;
        builder.private_input(&burn_step)?;
        expected_inputs.push(mass.clone());
        expected_inputs.push(burn_step.clone());
        append_positive_bound(
            &mut builder,
            &mass,
            &mass_bound(),
            &format!("sat{satellite}_mass_bound"),
        )?;
        append_nonzero_constraint(&mut builder, &mass, &format!("sat{satellite}_mass_nonzero"))?;
        builder.constrain_range(&burn_step, burn_step_bits(spec.steps))?;

        let mut burn_flags = Vec::with_capacity(spec.steps);
        let mut weighted_flags = Vec::with_capacity(spec.steps);
        for step in 0..spec.steps {
            let flag = burn_flag_name(satellite, step);
            builder.private_signal(&flag)?;
            builder.constrain_boolean(&flag)?;
            burn_flags.push(signal_expr(&flag));
            weighted_flags.push(mul_expr(
                const_expr(&BigInt::from(step as u64)),
                signal_expr(&flag),
            ));
        }
        builder.constrain_equal(add_expr(burn_flags), const_expr(&one()))?;
        builder.constrain_equal(signal_expr(&burn_step), add_expr(weighted_flags))?;

        for axis in AXES {
            let position = pos_input_name(satellite, axis);
            let velocity = vel_input_name(satellite, axis);
            let delta_v = dv_name(satellite, axis);
            builder.private_input(&position)?;
            builder.private_input(&velocity)?;
            builder.private_input(&delta_v)?;
            expected_inputs.push(position.clone());
            expected_inputs.push(velocity.clone());
            expected_inputs.push(delta_v.clone());
            append_signed_bound(
                &mut builder,
                &position,
                &position_bound(),
                &format!("sat{satellite}_position_input_bound_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &velocity,
                &velocity_bound(),
                &format!("sat{satellite}_velocity_input_bound_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &delta_v,
                &delta_v_component_bound(),
                &format!("sat{satellite}_delta_v_input_bound_{axis}"),
            )?;
        }
    }

    for satellite in 0..spec.satellite_count {
        let dv_norm_sq = delta_v_norm_sq_name(satellite);
        let dv_norm = delta_v_norm_name(satellite);
        let dv_norm_residual = delta_v_norm_residual_name(satellite);
        let budget_slack = delta_v_budget_slack_name(satellite);
        builder.private_signal(&dv_norm_sq)?;
        builder.private_signal(&dv_norm)?;
        builder.private_signal(&dv_norm_residual)?;
        builder.private_signal(&budget_slack)?;
        builder.constrain_equal(
            signal_expr(&dv_norm_sq),
            add_expr(
                AXES.iter()
                    .map(|axis| {
                        mul_expr(
                            signal_expr(&dv_name(satellite, axis)),
                            signal_expr(&dv_name(satellite, axis)),
                        )
                    })
                    .collect(),
            ),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&dv_norm), signal_expr(&dv_norm)),
            add_expr(vec![
                signal_expr(&dv_norm_sq),
                signal_expr(&dv_norm_residual),
            ]),
        )?;
        append_signed_bound(
            &mut builder,
            &dv_norm_residual,
            &sqrt_residual_bound(&delta_v_total_bound()),
            &format!("sat{satellite}_delta_v_norm_residual_bound"),
        )?;
        append_nonnegative_upper_bound(
            &mut builder,
            &dv_norm,
            &delta_v_total_bound(),
            &format!("sat{satellite}_delta_v_norm_bound"),
        )?;
        builder.constrain_equal(
            signal_expr(delta_v_budget_name()),
            add_expr(vec![signal_expr(&dv_norm), signal_expr(&budget_slack)]),
        )?;
        builder.constrain_range(&budget_slack, bits_for_bound(&delta_v_total_bound()))?;

        for axis in AXES {
            let impulse = impulse_name(satellite, axis);
            let impulse_residual = impulse_residual_name(satellite, axis);
            builder.private_signal(&impulse)?;
            builder.private_signal(&impulse_residual)?;
            builder.constrain_equal(
                mul_expr(
                    signal_expr(&mass_name(satellite)),
                    signal_expr(&dv_name(satellite, axis)),
                ),
                add_expr(vec![
                    mul_expr(signal_expr(&impulse), const_expr(&fixed_scale())),
                    signal_expr(&impulse_residual),
                ]),
            )?;
            append_signed_bound(
                &mut builder,
                &impulse_residual,
                &impulse_remainder_bound(),
                &format!("sat{satellite}_impulse_residual_bound_{axis}"),
            )?;
        }
    }

    append_acceleration_constraints(&mut builder, spec.satellite_count, 0)?;

    for step in 0..spec.steps {
        for satellite in 0..spec.satellite_count {
            let burn_flag = burn_flag_name(satellite, step);
            for axis in AXES {
                let burn_velocity = burn_velocity_name(step, satellite, axis);
                let next_position = pos_name(step + 1, satellite, axis);
                let next_velocity = vel_name(step + 1, satellite, axis);
                let position_residual = position_update_residual_name(step, satellite, axis);
                builder.private_signal(&burn_velocity)?;
                builder.private_signal(&next_position)?;
                builder.private_signal(&next_velocity)?;
                builder.private_signal(&position_residual)?;
                builder.constrain_equal(
                    signal_expr(&burn_velocity),
                    add_expr(vec![
                        signal_expr(&vel_name(step, satellite, axis)),
                        mul_expr(
                            signal_expr(&burn_flag),
                            signal_expr(&dv_name(satellite, axis)),
                        ),
                    ]),
                )?;
                append_signed_bound(
                    &mut builder,
                    &burn_velocity,
                    &burn_velocity_bound(),
                    &format!("step_{step}_sat{satellite}_burn_velocity_bound_{axis}"),
                )?;
                append_signed_bound(
                    &mut builder,
                    &next_position,
                    &position_bound(),
                    &format!("step_{}_sat{satellite}_position_bound_{axis}", step + 1),
                )?;
                append_signed_bound(
                    &mut builder,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("step_{}_sat{satellite}_velocity_bound_{axis}", step + 1),
                )?;
                builder.constrain_equal(
                    mul_expr(
                        signal_expr(&acceleration_name(step, satellite, axis)),
                        const_expr(&time_step_squared()),
                    ),
                    add_expr(vec![
                        mul_expr(
                            const_expr(&two()),
                            add_expr(vec![
                                signal_expr(&next_position),
                                neg_expr(signal_expr(&pos_name(step, satellite, axis))),
                                neg_expr(mul_expr(
                                    signal_expr(&burn_velocity),
                                    const_expr(&time_step_seconds()),
                                )),
                            ]),
                        ),
                        signal_expr(&position_residual),
                    ]),
                )?;
                append_signed_bound(
                    &mut builder,
                    &position_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sat{satellite}_position_update_residual_bound_{axis}"),
                )?;
            }
        }

        append_acceleration_constraints(&mut builder, spec.satellite_count, step + 1)?;

        for satellite in 0..spec.satellite_count {
            for axis in AXES {
                let burn_velocity = burn_velocity_name(step, satellite, axis);
                let velocity_residual = velocity_update_residual_name(step, satellite, axis);
                let next_velocity = vel_name(step + 1, satellite, axis);
                builder.private_signal(&velocity_residual)?;
                builder.constrain_equal(
                    mul_expr(
                        add_expr(vec![
                            signal_expr(&acceleration_name(step, satellite, axis)),
                            signal_expr(&acceleration_name(step + 1, satellite, axis)),
                        ]),
                        const_expr(&time_step_seconds()),
                    ),
                    add_expr(vec![
                        mul_expr(
                            const_expr(&two()),
                            add_expr(vec![
                                signal_expr(&next_velocity),
                                neg_expr(signal_expr(&burn_velocity)),
                            ]),
                        ),
                        signal_expr(&velocity_residual),
                    ]),
                )?;
                append_signed_bound(
                    &mut builder,
                    &velocity_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sat{satellite}_velocity_update_residual_bound_{axis}"),
                )?;
            }
        }
    }

    for (pair_index, pair) in pair_schedule.iter().copied().enumerate() {
        for state in 0..=spec.steps {
            append_pair_separation_constraints(&mut builder, pair_index, pair, state)?;
        }
        append_pair_running_min_and_safety_constraints(&mut builder, pair_index, spec.steps)?;
    }

    let mut mission_digest_items = Vec::with_capacity(spec.satellite_count + spec.pair_count + 2);
    for satellite in 0..spec.satellite_count {
        let output = final_state_commitment_output_name(satellite);
        builder.public_output(&output)?;
        let pos_digest = append_poseidon_hash(
            &mut builder,
            &format!("sat{satellite}_final_position_commitment"),
            [
                signal_expr(&pos_name(spec.steps, satellite, "x")),
                signal_expr(&pos_name(spec.steps, satellite, "y")),
                signal_expr(&pos_name(spec.steps, satellite, "z")),
                const_expr(&final_position_tag(satellite)),
            ],
        )?;
        let vel_digest = append_poseidon_hash(
            &mut builder,
            &format!("sat{satellite}_final_velocity_commitment"),
            [
                signal_expr(&vel_name(spec.steps, satellite, "x")),
                signal_expr(&vel_name(spec.steps, satellite, "y")),
                signal_expr(&vel_name(spec.steps, satellite, "z")),
                const_expr(&final_velocity_tag(satellite)),
            ],
        )?;
        let state_digest = append_poseidon_hash(
            &mut builder,
            &format!("sat{satellite}_final_state_commitment"),
            [
                signal_expr(&pos_digest),
                signal_expr(&vel_digest),
                const_expr(&final_state_tag(satellite)),
                const_expr(&BigInt::from(spec.steps as u64)),
            ],
        )?;
        builder.constrain_equal(signal_expr(&output), signal_expr(&state_digest))?;
        public_outputs.push(output.clone());
        mission_digest_items.push(signal_expr(&output));
    }

    for (pair_index, pair) in pair_schedule.iter().copied().enumerate() {
        let pair_leaf = append_poseidon_hash(
            &mut builder,
            &format!("pair_{pair_index}_result_leaf"),
            [
                signal_expr(&pair_minimum_separation_output_name(pair_index)),
                signal_expr(&pair_safe_output_name(pair_index)),
                const_expr(&BigInt::from(pair.sat_a as u64)),
                const_expr(&BigInt::from(pair.sat_b as u64)),
            ],
        )?;
        public_outputs.push(pair_minimum_separation_output_name(pair_index));
        public_outputs.push(pair_safe_output_name(pair_index));
        mission_digest_items.push(signal_expr(&pair_leaf));
    }

    mission_digest_items.push(signal_expr(collision_threshold_name()));
    mission_digest_items.push(signal_expr(delta_v_budget_name()));
    let mission_digest = append_poseidon_fold(
        &mut builder,
        "mission_safety_commitment",
        &mission_digest_items,
        &mission_fold_domain_tag(),
    )?;
    builder.public_output(mission_safety_commitment_name())?;
    builder.constrain_equal(
        signal_expr(mission_safety_commitment_name()),
        signal_expr(&mission_digest),
    )?;
    public_outputs.push(mission_safety_commitment_name().to_string());

    let sample_inputs = sample_inputs_for_spec(spec);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(collision_threshold_name().to_string(), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: spec.description,
    })
}

pub fn private_multi_satellite_conjunction_sample_inputs(
    scenario: PrivateMultiSatelliteScenario,
) -> WitnessInputs {
    sample_inputs_for_spec(private_multi_satellite_scenario_spec(scenario))
}

pub fn private_multi_satellite_conjunction_witness(
    inputs: &WitnessInputs,
    scenario: PrivateMultiSatelliteScenario,
) -> ZkfResult<Witness> {
    let spec = private_multi_satellite_scenario_spec(scenario);
    let pair_schedule = pair_schedule_for_spec(spec)?;
    let mut values = BTreeMap::<String, FieldElement>::new();
    let collision_threshold = read_input(inputs, collision_threshold_name())?;
    let delta_v_budget = read_input(inputs, delta_v_budget_name())?;
    ensure_positive_le(
        collision_threshold_name(),
        &collision_threshold,
        &max_separation_bound(),
    )?;
    ensure_positive_le(
        delta_v_budget_name(),
        &delta_v_budget,
        &delta_v_total_bound(),
    )?;
    write_value(
        &mut values,
        collision_threshold_name(),
        collision_threshold.clone(),
    );
    write_value(&mut values, delta_v_budget_name(), delta_v_budget.clone());
    write_positive_bound_support(
        &mut values,
        &collision_threshold,
        &max_separation_bound(),
        "collision_threshold_bound",
    )?;
    write_positive_bound_support(
        &mut values,
        &delta_v_budget,
        &delta_v_total_bound(),
        "delta_v_budget_bound",
    )?;
    write_nonzero_inverse_support(
        &mut values,
        &collision_threshold,
        "collision_threshold_nonzero",
    )?;
    write_nonzero_inverse_support(&mut values, &delta_v_budget, "delta_v_budget_nonzero")?;

    let mut masses = (0..spec.satellite_count)
        .map(|_| zero())
        .collect::<Vec<_>>();
    let mut positions = (0..spec.satellite_count)
        .map(|_| std::array::from_fn(|_| zero()))
        .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
    let mut velocities = (0..spec.satellite_count)
        .map(|_| std::array::from_fn(|_| zero()))
        .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
    let mut delta_vs = (0..spec.satellite_count)
        .map(|_| std::array::from_fn(|_| zero()))
        .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
    let mut burn_steps = vec![0usize; spec.satellite_count];

    for satellite in 0..spec.satellite_count {
        let mass = read_input(inputs, &mass_name(satellite))?;
        let burn_step = read_input(inputs, &burn_step_name(satellite))?;
        ensure_positive_le(&mass_name(satellite), &mass, &mass_bound())?;
        ensure_nonnegative_le(
            &burn_step_name(satellite),
            &burn_step,
            &BigInt::from((spec.steps - 1) as u64),
        )?;
        write_value(&mut values, mass_name(satellite), mass.clone());
        write_value(&mut values, burn_step_name(satellite), burn_step.clone());
        write_positive_bound_support(
            &mut values,
            &mass,
            &mass_bound(),
            &format!("sat{satellite}_mass_bound"),
        )?;
        write_nonzero_inverse_support(&mut values, &mass, &format!("sat{satellite}_mass_nonzero"))?;
        masses[satellite] = mass;
        burn_steps[satellite] = burn_step
            .to_str_radix(10)
            .parse::<usize>()
            .map_err(|error| {
                ZkfError::InvalidArtifact(format!("invalid burn step for sat{satellite}: {error}"))
            })?;

        for step in 0..spec.steps {
            write_value(
                &mut values,
                burn_flag_name(satellite, step),
                if burn_steps[satellite] == step {
                    one()
                } else {
                    zero()
                },
            );
        }

        for (axis_index, axis) in AXES.iter().enumerate() {
            let position = read_input(inputs, &pos_input_name(satellite, axis))?;
            let velocity = read_input(inputs, &vel_input_name(satellite, axis))?;
            let delta_v = read_input(inputs, &dv_name(satellite, axis))?;
            ensure_abs_le(
                &pos_input_name(satellite, axis),
                &position,
                &position_bound(),
            )?;
            ensure_abs_le(
                &vel_input_name(satellite, axis),
                &velocity,
                &velocity_bound(),
            )?;
            ensure_abs_le(
                &dv_name(satellite, axis),
                &delta_v,
                &delta_v_component_bound(),
            )?;
            write_value(
                &mut values,
                pos_input_name(satellite, axis),
                position.clone(),
            );
            write_value(
                &mut values,
                vel_input_name(satellite, axis),
                velocity.clone(),
            );
            write_value(&mut values, dv_name(satellite, axis), delta_v.clone());
            write_signed_bound_support(
                &mut values,
                &position,
                &position_bound(),
                &format!("sat{satellite}_position_input_bound_{axis}"),
            )?;
            write_signed_bound_support(
                &mut values,
                &velocity,
                &velocity_bound(),
                &format!("sat{satellite}_velocity_input_bound_{axis}"),
            )?;
            write_signed_bound_support(
                &mut values,
                &delta_v,
                &delta_v_component_bound(),
                &format!("sat{satellite}_delta_v_input_bound_{axis}"),
            )?;
            positions[satellite][axis_index] = position;
            velocities[satellite][axis_index] = velocity;
            delta_vs[satellite][axis_index] = delta_v;
        }
    }

    for satellite in 0..spec.satellite_count {
        let dv_norm_sq = AXES
            .iter()
            .enumerate()
            .fold(zero(), |acc, (axis_index, _)| {
                acc + &delta_vs[satellite][axis_index] * &delta_vs[satellite][axis_index]
            });
        let dv_norm = nearest_integer_sqrt(&dv_norm_sq);
        let dv_norm_residual = (&dv_norm * &dv_norm) - &dv_norm_sq;
        if dv_norm > delta_v_budget {
            return Err(ZkfError::InvalidArtifact(format!(
                "satellite {satellite} exceeded the public per-satellite delta-v budget"
            )));
        }
        ensure_nonnegative_le(
            &delta_v_norm_name(satellite),
            &dv_norm,
            &delta_v_total_bound(),
        )?;
        write_value(
            &mut values,
            delta_v_norm_sq_name(satellite),
            dv_norm_sq.clone(),
        );
        write_value(&mut values, delta_v_norm_name(satellite), dv_norm.clone());
        write_value(
            &mut values,
            delta_v_norm_residual_name(satellite),
            dv_norm_residual.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &dv_norm_residual,
            &sqrt_residual_bound(&delta_v_total_bound()),
            &format!("sat{satellite}_delta_v_norm_residual_bound"),
        )?;
        write_nonnegative_upper_bound_support(
            &mut values,
            &dv_norm,
            &delta_v_total_bound(),
            &format!("sat{satellite}_delta_v_norm_bound"),
        )?;
        write_value(
            &mut values,
            delta_v_budget_slack_name(satellite),
            &delta_v_budget - &dv_norm,
        );

        for (axis_index, axis) in AXES.iter().enumerate() {
            let (impulse, impulse_residual) = div_round_nearest(
                &(&masses[satellite] * &delta_vs[satellite][axis_index]),
                &fixed_scale(),
            );
            write_value(&mut values, impulse_name(satellite, axis), impulse.clone());
            write_value(
                &mut values,
                impulse_residual_name(satellite, axis),
                impulse_residual.clone(),
            );
            write_signed_bound_support(
                &mut values,
                &impulse_residual,
                &impulse_remainder_bound(),
                &format!("sat{satellite}_impulse_residual_bound_{axis}"),
            )?;
        }
    }

    let mut trajectory_positions = Vec::with_capacity(spec.steps + 1);
    trajectory_positions.push(positions.clone());
    let mut current_accelerations =
        compute_acceleration_state(&mut values, 0, positions.as_slice())?;

    for step in 0..spec.steps {
        let mut burn_velocities = (0..spec.satellite_count)
            .map(|_| std::array::from_fn(|_| zero()))
            .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
        for satellite in 0..spec.satellite_count {
            let flag = if burn_steps[satellite] == step {
                one()
            } else {
                zero()
            };
            for (axis_index, axis) in AXES.iter().enumerate() {
                let burn_velocity =
                    &velocities[satellite][axis_index] + (&flag * &delta_vs[satellite][axis_index]);
                ensure_abs_le(
                    &burn_velocity_name(step, satellite, axis),
                    &burn_velocity,
                    &burn_velocity_bound(),
                )?;
                write_value(
                    &mut values,
                    burn_velocity_name(step, satellite, axis),
                    burn_velocity.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &burn_velocity,
                    &burn_velocity_bound(),
                    &format!("step_{step}_sat{satellite}_burn_velocity_bound_{axis}"),
                )?;
                burn_velocities[satellite][axis_index] = burn_velocity;
            }
        }

        let mut next_positions = (0..spec.satellite_count)
            .map(|_| std::array::from_fn(|_| zero()))
            .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
        for satellite in 0..spec.satellite_count {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let velocity_term = &burn_velocities[satellite][axis_index] * &time_step_seconds();
                let accel_numerator =
                    &current_accelerations[satellite][axis_index] * &time_step_squared();
                let (half_accel_term, position_residual) =
                    div_round_nearest(&accel_numerator, &two());
                let next_position =
                    &positions[satellite][axis_index] + velocity_term + &half_accel_term;
                ensure_abs_le(
                    &pos_name(step + 1, satellite, axis),
                    &next_position,
                    &position_bound(),
                )?;
                write_value(
                    &mut values,
                    position_update_residual_name(step, satellite, axis),
                    position_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &position_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sat{satellite}_position_update_residual_bound_{axis}"),
                )?;
                write_value(
                    &mut values,
                    pos_name(step + 1, satellite, axis),
                    next_position.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_position,
                    &position_bound(),
                    &format!("step_{}_sat{satellite}_position_bound_{axis}", step + 1),
                )?;
                next_positions[satellite][axis_index] = next_position;
            }
        }

        let next_accelerations =
            compute_acceleration_state(&mut values, step + 1, next_positions.as_slice())?;
        let mut next_velocities = (0..spec.satellite_count)
            .map(|_| std::array::from_fn(|_| zero()))
            .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();
        for satellite in 0..spec.satellite_count {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let accel_sum_dt = (&current_accelerations[satellite][axis_index]
                    + &next_accelerations[satellite][axis_index])
                    * &time_step_seconds();
                let (half_velocity_term, velocity_residual) =
                    div_round_nearest(&accel_sum_dt, &two());
                let next_velocity = &burn_velocities[satellite][axis_index] + &half_velocity_term;
                ensure_abs_le(
                    &vel_name(step + 1, satellite, axis),
                    &next_velocity,
                    &velocity_bound(),
                )?;
                write_value(
                    &mut values,
                    velocity_update_residual_name(step, satellite, axis),
                    velocity_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &velocity_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sat{satellite}_velocity_update_residual_bound_{axis}"),
                )?;
                write_value(
                    &mut values,
                    vel_name(step + 1, satellite, axis),
                    next_velocity.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("step_{}_sat{satellite}_velocity_bound_{axis}", step + 1),
                )?;
                next_velocities[satellite][axis_index] = next_velocity;
            }
        }

        positions = next_positions.clone();
        velocities = next_velocities;
        current_accelerations = next_accelerations;
        trajectory_positions.push(next_positions);
    }

    let mut final_commitments = Vec::with_capacity(spec.satellite_count);
    for satellite in 0..spec.satellite_count {
        let pos_state = poseidon_permutation4_bn254(&[
            field_ref(&positions[satellite][0]),
            field_ref(&positions[satellite][1]),
            field_ref(&positions[satellite][2]),
            field_ref(&final_position_tag(satellite)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sat{satellite}_final_position_commitment"))
            .into_iter()
            .zip(pos_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        let vel_state = poseidon_permutation4_bn254(&[
            field_ref(&velocities[satellite][0]),
            field_ref(&velocities[satellite][1]),
            field_ref(&velocities[satellite][2]),
            field_ref(&final_velocity_tag(satellite)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sat{satellite}_final_velocity_commitment"))
            .into_iter()
            .zip(vel_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        let state_state = poseidon_permutation4_bn254(&[
            pos_state[0].clone(),
            vel_state[0].clone(),
            field_ref(&final_state_tag(satellite)),
            field(BigInt::from(spec.steps as u64)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sat{satellite}_final_state_commitment"))
            .into_iter()
            .zip(state_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        let output_name = final_state_commitment_output_name(satellite);
        values.insert(output_name, state_state[0].clone());
        final_commitments.push(state_state[0].clone());
    }

    let mut pair_leaf_digests = Vec::with_capacity(spec.pair_count);
    for (pair_index, pair) in pair_schedule.iter().copied().enumerate() {
        let mut running_min: Option<BigInt> = None;
        for (state, positions) in trajectory_positions.iter().enumerate().take(spec.steps + 1) {
            let separation =
                compute_pair_separation_state(&mut values, pair_index, state, pair, positions)?;
            match running_min.clone() {
                None => {
                    write_value(
                        &mut values,
                        pair_run_min_name(pair_index, state),
                        separation.clone(),
                    );
                    write_nonnegative_upper_bound_support(
                        &mut values,
                        &separation,
                        &max_separation_bound(),
                        &format!("pair_{pair_index}_state_{state}_running_min_bound"),
                    )?;
                    running_min = Some(separation);
                }
                Some(previous) => {
                    let next_min = if separation < previous {
                        separation.clone()
                    } else {
                        previous.clone()
                    };
                    let prev_slack = &previous - &next_min;
                    let curr_slack = &separation - &next_min;
                    write_value(
                        &mut values,
                        pair_run_min_name(pair_index, state),
                        next_min.clone(),
                    );
                    write_nonnegative_upper_bound_support(
                        &mut values,
                        &next_min,
                        &max_separation_bound(),
                        &format!("pair_{pair_index}_state_{state}_running_min_bound"),
                    )?;
                    write_value(
                        &mut values,
                        pair_run_min_prev_slack_name(pair_index, state),
                        prev_slack,
                    );
                    write_value(
                        &mut values,
                        pair_run_min_curr_slack_name(pair_index, state),
                        curr_slack,
                    );
                    running_min = Some(next_min);
                }
            }
        }

        let minimum = running_min.ok_or_else(|| {
            ZkfError::InvalidArtifact(format!("pair {pair_index} produced no separation states"))
        })?;
        let minimum_output = pair_minimum_separation_output_name(pair_index);
        write_value(&mut values, minimum_output.clone(), minimum.clone());
        write_nonnegative_upper_bound_support(
            &mut values,
            &minimum,
            &max_separation_bound(),
            &format!("pair_{pair_index}_minimum_separation_public_bound"),
        )?;

        let safe = minimum >= collision_threshold;
        let safe_slack = if safe {
            &minimum - &collision_threshold
        } else {
            zero()
        };
        let unsafe_shortfall = if safe {
            zero()
        } else {
            &collision_threshold - &minimum - &one()
        };
        write_value(
            &mut values,
            pair_safe_output_name(pair_index),
            if safe { one() } else { zero() },
        );
        write_value(&mut values, pair_safe_slack_name(pair_index), safe_slack);
        write_value(
            &mut values,
            pair_unsafe_shortfall_name(pair_index),
            unsafe_shortfall,
        );

        let pair_leaf_state = poseidon_permutation4_bn254(&[
            field_ref(&minimum),
            field(if safe { one() } else { zero() }),
            field(BigInt::from(pair.sat_a as u64)),
            field(BigInt::from(pair.sat_b as u64)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("pair_{pair_index}_result_leaf"))
            .into_iter()
            .zip(pair_leaf_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        pair_leaf_digests.push(pair_leaf_state[0].clone());
    }

    let mission_seed = poseidon_permutation4_bn254(&[
        FieldElement::ZERO,
        FieldElement::ZERO,
        field_ref(&mission_fold_domain_tag()),
        field(BigInt::from(
            (final_commitments.len() + pair_leaf_digests.len() + 2) as u64,
        )),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("mission_safety_commitment_seed")
        .into_iter()
        .zip(mission_seed.iter().cloned())
    {
        values.insert(lane, value);
    }
    let mut mission_acc = mission_seed[0].clone();
    let mut mission_items = final_commitments;
    mission_items.extend(pair_leaf_digests);
    mission_items.push(field_ref(&collision_threshold));
    mission_items.push(field_ref(&delta_v_budget));
    for (index, item) in mission_items.iter().enumerate() {
        let state = poseidon_permutation4_bn254(&[
            mission_acc.clone(),
            item.clone(),
            field(BigInt::from(index as u64)),
            field_ref(&mission_fold_domain_tag()),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("mission_safety_commitment_fold_{index}"))
            .into_iter()
            .zip(state.iter().cloned())
        {
            values.insert(lane, value);
        }
        mission_acc = state[0].clone();
    }
    values.insert(
        mission_safety_commitment_name().to_string(),
        mission_acc.clone(),
    );

    Ok(Witness { values })
}

fn compute_acceleration_state(
    values: &mut BTreeMap<String, FieldElement>,
    state: usize,
    positions: &[[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]],
) -> ZkfResult<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>> {
    let mut accelerations = (0..positions.len())
        .map(|_| std::array::from_fn(|_| zero()))
        .collect::<Vec<[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]>>();

    for satellite in 0..positions.len() {
        let radius_sq = positions[satellite]
            .iter()
            .fold(zero(), |acc, value| acc + value * value);
        if radius_sq < min_radius_squared() {
            return Err(ZkfError::InvalidArtifact(format!(
                "satellite {satellite} violated the minimum modeled orbital radius at state {state}"
            )));
        }
        let radius_floor_slack = &radius_sq - &min_radius_squared();
        let radius_floor_slack_field = field_ref(&radius_floor_slack);
        write_value(values, radius_sq_name(state, satellite), radius_sq.clone());
        values.insert(
            radius_floor_slack_name(state, satellite),
            radius_floor_slack_field.clone(),
        );
        values.insert(
            radius_floor_anchor_name(state, satellite),
            bn254_square(&radius_floor_slack),
        );

        let inverse_distance = nearest_inverse_distance(&radius_sq);
        let inverse_distance_sq = &inverse_distance * &inverse_distance;
        let inverse_distance_sq_residual =
            fixed_scale_fourth() - (&radius_sq * &inverse_distance_sq);
        write_value(
            values,
            inverse_distance_name(state, satellite),
            inverse_distance.clone(),
        );
        write_value(
            values,
            inverse_distance_sq_name(state, satellite),
            inverse_distance_sq.clone(),
        );
        write_value(
            values,
            inverse_distance_sq_residual_positive_name(state, satellite),
            if inverse_distance_sq_residual.sign() == Sign::Minus {
                zero()
            } else {
                inverse_distance_sq_residual.clone()
            },
        );
        write_value(
            values,
            inverse_distance_sq_residual_negative_name(state, satellite),
            if inverse_distance_sq_residual.sign() == Sign::Minus {
                -inverse_distance_sq_residual.clone()
            } else {
                zero()
            },
        );

        let inverse_distance_cubed_numerator = &inverse_distance_sq * &inverse_distance;
        let (inverse_distance_cubed, inverse_distance_cubed_residual) =
            div_round_nearest(&inverse_distance_cubed_numerator, &fixed_scale_squared());
        write_value(
            values,
            inverse_distance_cubed_name(state, satellite),
            inverse_distance_cubed.clone(),
        );
        write_value(
            values,
            inverse_distance_cubed_residual_name(state, satellite),
            inverse_distance_cubed_residual.clone(),
        );
        write_signed_bound_support(
            values,
            &inverse_distance_cubed_residual,
            &inv_r3_remainder_bound(),
            &format!("state_{state}_sat{satellite}_inverse_distance_cubed_bound"),
        )?;

        let (gravity_factor, gravity_factor_residual) = div_round_nearest(
            &(mu_earth_scaled() * &inverse_distance_cubed),
            &fixed_scale(),
        );
        write_value(
            values,
            gravity_factor_name(state, satellite),
            gravity_factor.clone(),
        );
        write_value(
            values,
            gravity_factor_residual_name(state, satellite),
            gravity_factor_residual.clone(),
        );
        write_signed_bound_support(
            values,
            &gravity_factor_residual,
            &factor_remainder_bound(),
            &format!("state_{state}_sat{satellite}_gravity_factor_bound"),
        )?;

        for (axis_index, axis) in AXES.iter().enumerate() {
            let perturbation = zero();
            let numerator = -positions[satellite][axis_index].clone() * &gravity_factor;
            let (gravity_component, gravity_component_residual) =
                div_round_nearest(&numerator, &fixed_scale());
            let acceleration = &gravity_component + &perturbation;
            ensure_abs_le(
                &acceleration_name(state, satellite, axis),
                &acceleration,
                &acceleration_bound(),
            )?;
            write_value(
                values,
                perturbation_name(state, satellite, axis),
                perturbation,
            );
            write_signed_bound_support(
                values,
                &zero(),
                &perturbation_bound(),
                &format!("state_{state}_sat{satellite}_perturbation_bound_{axis}"),
            )?;
            write_value(
                values,
                gravity_component_name(state, satellite, axis),
                gravity_component.clone(),
            );
            write_value(
                values,
                gravity_component_residual_name(state, satellite, axis),
                gravity_component_residual.clone(),
            );
            write_signed_bound_support(
                values,
                &gravity_component_residual,
                &component_remainder_bound(),
                &format!("state_{state}_sat{satellite}_gravity_component_bound_{axis}"),
            )?;
            write_value(
                values,
                acceleration_name(state, satellite, axis),
                acceleration.clone(),
            );
            write_signed_bound_support(
                values,
                &acceleration,
                &acceleration_bound(),
                &format!("state_{state}_sat{satellite}_acceleration_bound_{axis}"),
            )?;
            accelerations[satellite][axis_index] = acceleration;
        }
    }

    Ok(accelerations)
}

fn compute_pair_separation_state(
    values: &mut BTreeMap<String, FieldElement>,
    pair_index: usize,
    state: usize,
    pair: PairCheck,
    positions: &[[BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS]],
) -> ZkfResult<BigInt> {
    let deltas: [BigInt; PRIVATE_MULTI_SATELLITE_DIMENSIONS] = std::array::from_fn(|axis| {
        positions[pair.sat_b][axis].clone() - positions[pair.sat_a][axis].clone()
    });
    for (axis_index, axis) in AXES.iter().enumerate() {
        write_value(
            values,
            pair_delta_name(pair_index, state, axis),
            deltas[axis_index].clone(),
        );
    }
    let distance_sq = deltas.iter().fold(zero(), |acc, value| acc + value * value);
    let distance = nearest_integer_sqrt(&distance_sq);
    let distance_residual = (&distance * &distance) - &distance_sq;
    ensure_nonnegative_le(
        &pair_distance_name(pair_index, state),
        &distance,
        &max_separation_bound(),
    )?;
    write_value(
        values,
        pair_distance_sq_name(pair_index, state),
        distance_sq,
    );
    write_value(
        values,
        pair_distance_name(pair_index, state),
        distance.clone(),
    );
    write_value(
        values,
        pair_distance_residual_name(pair_index, state),
        distance_residual.clone(),
    );
    write_signed_bound_support(
        values,
        &distance_residual,
        &sqrt_residual_bound(&max_separation_bound()),
        &format!("pair_{pair_index}_state_{state}_distance_residual_bound"),
    )?;
    write_nonnegative_upper_bound_support(
        values,
        &distance,
        &max_separation_bound(),
        &format!("pair_{pair_index}_state_{state}_distance_bound"),
    )?;
    Ok(distance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::thread;
    use zkf_backends::blackbox_gadgets::enrich_witness_for_proving;
    use zkf_core::{BackendKind, CompiledProgram, Program, check_constraints};

    const MULTI_SATELLITE_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_multi_satellite_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(MULTI_SATELLITE_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn lowered_compiled_program_for_test(program: &Program) -> CompiledProgram {
        let lowered =
            zkf_backends::lower_program_for_backend(program, BackendKind::ArkworksGroth16)
                .expect("lower");
        let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, lowered.program);
        if program.digest_hex() != compiled.program.digest_hex() {
            compiled.original_program = Some(program.clone());
        }
        compiled
    }

    #[test]
    fn pair_schedule_for_base32_is_unique_and_stable() {
        let schedule =
            private_multi_satellite_pair_schedule(PrivateMultiSatelliteScenario::Base32).unwrap();
        assert_eq!(schedule.len(), PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT);
        assert_eq!(schedule.first().unwrap().offset, 1);
        assert_eq!(schedule.last().unwrap().offset, 5);
        let unique = schedule
            .iter()
            .map(|pair| {
                if pair.sat_a < pair.sat_b {
                    (pair.offset, pair.sat_a, pair.sat_b)
                } else {
                    (pair.offset, pair.sat_b, pair.sat_a)
                }
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), schedule.len());
    }

    #[test]
    fn pair_schedule_for_stress64_is_unique_and_stable() {
        let schedule =
            private_multi_satellite_pair_schedule(PrivateMultiSatelliteScenario::Stress64).unwrap();
        assert_eq!(schedule.len(), PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT);
        assert_eq!(schedule.first().unwrap().offset, 1);
        assert_eq!(schedule.last().unwrap().offset, 13);
        let unique = schedule
            .iter()
            .map(|pair| {
                if pair.sat_a < pair.sat_b {
                    (pair.offset, pair.sat_a, pair.sat_b)
                } else {
                    (pair.offset, pair.sat_b, pair.sat_a)
                }
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), schedule.len());
    }

    #[test]
    fn mini_template_has_expected_surface() {
        let template = private_multi_satellite_conjunction_showcase_for_scenario(
            PrivateMultiSatelliteScenario::Mini,
        )
        .expect("template");
        let spec = private_multi_satellite_scenario_spec(PrivateMultiSatelliteScenario::Mini);
        assert_eq!(
            template.expected_inputs.len(),
            (spec.satellite_count * PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE)
                + PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS
        );
        assert_eq!(
            template.public_outputs.len(),
            spec.satellite_count + (spec.pair_count * 2) + 1
        );
        assert_eq!(
            template
                .program
                .metadata
                .get("scenario")
                .map(String::as_str),
            Some("mini")
        );
    }

    #[test]
    fn mini_witness_satisfies_constraints() {
        run_multi_satellite_test_on_large_stack("mini_witness_satisfies_constraints", || {
            let template = private_multi_satellite_conjunction_showcase_for_scenario(
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let witness = private_multi_satellite_conjunction_witness(
                &template.sample_inputs,
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("witness");
            let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            check_constraints(&compiled.program, &prepared).expect("constraints");
        });
    }

    #[test]
    fn min_separation_tamper_fails() {
        run_multi_satellite_test_on_large_stack("min_separation_tamper_fails", || {
            let template = private_multi_satellite_conjunction_showcase_for_scenario(
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let mut witness = private_multi_satellite_conjunction_witness(
                &template.sample_inputs,
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("witness");
            let name = pair_minimum_separation_output_name(0);
            witness.values.insert(name.clone(), FieldElement::ZERO);
            let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            assert!(
                check_constraints(&compiled.program, &prepared).is_err(),
                "tampering {} should break constraints",
                name
            );
        });
    }

    #[test]
    fn safe_bit_tamper_fails() {
        run_multi_satellite_test_on_large_stack("safe_bit_tamper_fails", || {
            let template = private_multi_satellite_conjunction_showcase_for_scenario(
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let mut witness = private_multi_satellite_conjunction_witness(
                &template.sample_inputs,
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("witness");
            let name = pair_safe_output_name(0);
            witness.values.insert(name.clone(), FieldElement::ZERO);
            let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            assert!(
                check_constraints(&compiled.program, &prepared).is_err(),
                "tampering {} should break constraints",
                name
            );
        });
    }

    #[test]
    fn per_satellite_budget_violation_fails_closed() {
        let mut inputs =
            private_multi_satellite_conjunction_sample_inputs(PrivateMultiSatelliteScenario::Mini);
        inputs.insert(
            dv_name(0, "x"),
            field(decimal_scaled("0.050000000000000000")),
        );
        let error = private_multi_satellite_conjunction_witness(
            &inputs,
            PrivateMultiSatelliteScenario::Mini,
        )
        .expect_err("budget violation should fail");
        assert!(
            error
                .to_string()
                .contains("exceeded the public per-satellite delta-v budget")
        );
    }

    #[test]
    fn mission_digest_tamper_fails() {
        run_multi_satellite_test_on_large_stack("mission_digest_tamper_fails", || {
            let template = private_multi_satellite_conjunction_showcase_for_scenario(
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let mut witness = private_multi_satellite_conjunction_witness(
                &template.sample_inputs,
                PrivateMultiSatelliteScenario::Mini,
            )
            .expect("witness");
            witness.values.insert(
                mission_safety_commitment_name().to_string(),
                FieldElement::ZERO,
            );
            let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            assert!(
                check_constraints(&compiled.program, &prepared).is_err(),
                "tampering mission digest should break constraints"
            );
        });
    }
}
