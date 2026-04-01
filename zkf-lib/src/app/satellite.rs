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

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use num_bigint::{BigInt, Sign};
use std::collections::BTreeMap;
use zkf_core::{
    BigIntFieldValue, BlackBoxOp, Expr, FieldElement, FieldId, FieldValue, Witness, WitnessInputs,
    mod_inverse_bigint,
};
use zkf_core::{ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::private_identity::poseidon_permutation4_bn254;
use super::templates::TemplateProgram;

pub const PRIVATE_SATELLITE_SPACECRAFT_COUNT: usize = 2;
pub const PRIVATE_SATELLITE_DEFAULT_STEPS: usize = 1440;
pub const PRIVATE_SATELLITE_DIMENSIONS: usize = 3;
pub const PRIVATE_SATELLITE_PRIVATE_INPUTS: usize = 22;
pub const PRIVATE_SATELLITE_PUBLIC_INPUTS: usize = 2;
pub const PRIVATE_SATELLITE_PUBLIC_OUTPUTS: usize = 5;

const AXES: [&str; PRIVATE_SATELLITE_DIMENSIONS] = ["x", "y", "z"];
const PRIVATE_SATELLITE_DESCRIPTION: &str = "Simulate a private two-spacecraft conjunction-avoidance maneuver over a fixed 24-hour, 1440-step Earth-dominant propagation window and expose Poseidon commitments to the final 3D states, the minimum separation, a safe-indicator safety-certificate output, and the committed maneuver plan.";
const PRIVATE_SATELLITE_TEST_HELPER_DESCRIPTION: &str = "Doc-hidden arbitrary-step helper for in-repo testing and exporter regression of the private two-spacecraft conjunction showcase. The shipped showcase remains fixed to the 24-hour, 1440-step surface.";

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

fn window_hours_metadata(steps: usize) -> String {
    if steps.is_multiple_of(60) {
        (steps / 60).to_string()
    } else {
        format!("{:.6}", steps as f64 / 60.0)
    }
}

fn sample_burn_steps_for_horizon(steps: usize) -> [BigInt; PRIVATE_SATELLITE_SPACECRAFT_COUNT] {
    if steps == PRIVATE_SATELLITE_DEFAULT_STEPS {
        [BigInt::from(180u64), BigInt::from(720u64)]
    } else if steps == 1 {
        [zero(), zero()]
    } else {
        let first = steps / 4;
        let second = (steps / 2).min(steps - 1);
        [BigInt::from(first as u64), BigInt::from(second as u64)]
    }
}

pub fn private_satellite_conjunction_sample_inputs_for_steps(steps: usize) -> WitnessInputs {
    let burn_steps = sample_burn_steps_for_horizon(steps);
    let mut inputs = WitnessInputs::new();
    inputs.insert(
        collision_threshold_name().to_string(),
        field(decimal_scaled("50")),
    );
    inputs.insert(
        delta_v_budget_name().to_string(),
        field(decimal_scaled("0.020")),
    );

    let sample = [
        (
            decimal_scaled("1200"),
            [
                decimal_scaled("7000"),
                decimal_scaled("0"),
                decimal_scaled("0"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("7.546053290"),
                decimal_scaled("0"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("0.0020"),
                decimal_scaled("0.0001"),
            ],
            burn_steps[0].clone(),
        ),
        (
            decimal_scaled("950"),
            [
                decimal_scaled("0"),
                decimal_scaled("7100"),
                decimal_scaled("25"),
            ],
            [
                decimal_scaled("-7.492719470"),
                decimal_scaled("0"),
                decimal_scaled("0.0100"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("-0.0015"),
                decimal_scaled("0.00005"),
            ],
            burn_steps[1].clone(),
        ),
    ];

    for (spacecraft, (mass, position, velocity, delta_v, burn_step)) in sample.iter().enumerate() {
        inputs.insert(mass_name(spacecraft), field_ref(mass));
        inputs.insert(burn_step_name(spacecraft), field_ref(burn_step));
        for (axis_index, axis) in AXES.iter().enumerate() {
            inputs.insert(
                pos_input_name(spacecraft, axis),
                field_ref(&position[axis_index]),
            );
            inputs.insert(
                vel_input_name(spacecraft, axis),
                field_ref(&velocity[axis_index]),
            );
            inputs.insert(dv_name(spacecraft, axis), field_ref(&delta_v[axis_index]));
        }
    }

    inputs
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
    BigInt::from(60u64)
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

fn final_position_tag(spacecraft: usize) -> BigInt {
    BigInt::from(100u64 + spacecraft as u64)
}

fn final_velocity_tag(spacecraft: usize) -> BigInt {
    BigInt::from(200u64 + spacecraft as u64)
}

fn final_state_tag(spacecraft: usize) -> BigInt {
    BigInt::from(300u64 + spacecraft as u64)
}

fn mass_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_mass")
}

fn pos_input_name(spacecraft: usize, axis: &str) -> String {
    format!("sc{spacecraft}_pos_{axis}")
}

fn vel_input_name(spacecraft: usize, axis: &str) -> String {
    format!("sc{spacecraft}_vel_{axis}")
}

fn dv_name(spacecraft: usize, axis: &str) -> String {
    format!("sc{spacecraft}_dv_{axis}")
}

fn burn_step_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_burn_step")
}

fn collision_threshold_name() -> &'static str {
    "collision_threshold"
}

fn delta_v_budget_name() -> &'static str {
    "delta_v_budget"
}

fn pos_name(step: usize, spacecraft: usize, axis: &str) -> String {
    if step == 0 {
        pos_input_name(spacecraft, axis)
    } else {
        format!("step_{step}_sc{spacecraft}_pos_{axis}")
    }
}

fn vel_name(step: usize, spacecraft: usize, axis: &str) -> String {
    if step == 0 {
        vel_input_name(spacecraft, axis)
    } else {
        format!("step_{step}_sc{spacecraft}_vel_{axis}")
    }
}

fn burn_flag_name(spacecraft: usize, step: usize) -> String {
    format!("sc{spacecraft}_burn_flag_{step}")
}

fn burn_velocity_name(step: usize, spacecraft: usize, axis: &str) -> String {
    format!("step_{step}_sc{spacecraft}_burn_vel_{axis}")
}

fn perturbation_name(state: usize, spacecraft: usize, axis: &str) -> String {
    format!("state_{state}_sc{spacecraft}_perturb_{axis}")
}

fn acceleration_name(state: usize, spacecraft: usize, axis: &str) -> String {
    format!("state_{state}_sc{spacecraft}_acc_{axis}")
}

fn radius_sq_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_radius_sq")
}

fn radius_floor_slack_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_radius_floor_slack")
}

fn radius_floor_anchor_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_radius_floor_anchor")
}

fn inverse_distance_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r")
}

fn inverse_distance_sq_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r_sq")
}

fn inverse_distance_sq_residual_positive_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r_sq_residual_positive")
}

fn inverse_distance_sq_residual_negative_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r_sq_residual_negative")
}

fn inverse_distance_cubed_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r_cubed")
}

fn inverse_distance_cubed_residual_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_inv_r_cubed_residual")
}

fn gravity_factor_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_gravity_factor")
}

fn gravity_factor_residual_name(state: usize, spacecraft: usize) -> String {
    format!("state_{state}_sc{spacecraft}_gravity_factor_residual")
}

fn gravity_component_name(state: usize, spacecraft: usize, axis: &str) -> String {
    format!("state_{state}_sc{spacecraft}_gravity_component_{axis}")
}

fn gravity_component_residual_name(state: usize, spacecraft: usize, axis: &str) -> String {
    format!("state_{state}_sc{spacecraft}_gravity_component_residual_{axis}")
}

fn position_update_residual_name(step: usize, spacecraft: usize, axis: &str) -> String {
    format!("step_{step}_sc{spacecraft}_position_update_residual_{axis}")
}

fn velocity_update_residual_name(step: usize, spacecraft: usize, axis: &str) -> String {
    format!("step_{step}_sc{spacecraft}_velocity_update_residual_{axis}")
}

fn separation_delta_name(state: usize, axis: &str) -> String {
    format!("state_{state}_separation_delta_{axis}")
}

fn separation_distance_sq_name(state: usize) -> String {
    format!("state_{state}_separation_distance_sq")
}

fn separation_distance_name(state: usize) -> String {
    format!("state_{state}_separation_distance")
}

fn separation_distance_residual_name(state: usize) -> String {
    format!("state_{state}_separation_distance_residual")
}

fn run_min_name(state: usize) -> String {
    format!("state_{state}_running_min_separation")
}

fn run_min_prev_slack_name(state: usize) -> String {
    format!("state_{state}_running_min_prev_slack")
}

fn run_min_curr_slack_name(state: usize) -> String {
    format!("state_{state}_running_min_curr_slack")
}

fn safe_indicator_name() -> &'static str {
    "safe_indicator"
}

fn minimum_separation_output_name() -> &'static str {
    "minimum_separation"
}

fn safety_slack_name() -> &'static str {
    "safety_slack"
}

fn delta_v_norm_sq_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_dv_norm_sq")
}

fn delta_v_norm_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_dv_norm")
}

fn delta_v_norm_residual_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_dv_norm_residual")
}

fn impulse_name(spacecraft: usize, axis: &str) -> String {
    format!("sc{spacecraft}_impulse_{axis}")
}

fn impulse_residual_name(spacecraft: usize, axis: &str) -> String {
    format!("sc{spacecraft}_impulse_residual_{axis}")
}

fn total_delta_v_name() -> &'static str {
    "total_delta_v"
}

fn delta_v_budget_slack_name() -> &'static str {
    "delta_v_budget_slack"
}

fn final_state_commitment_output_name(spacecraft: usize) -> String {
    format!("sc{spacecraft}_final_state_commitment")
}

fn maneuver_plan_commitment_output_name() -> &'static str {
    "maneuver_plan_commitment"
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

fn append_separation_constraints(builder: &mut ProgramBuilder, state: usize) -> ZkfResult<()> {
    let delta_names = AXES
        .iter()
        .map(|axis| separation_delta_name(state, axis))
        .collect::<Vec<_>>();
    for (axis_index, axis) in AXES.iter().enumerate() {
        builder.private_signal(&delta_names[axis_index])?;
        builder.constrain_equal(
            signal_expr(&delta_names[axis_index]),
            sub_expr(
                signal_expr(&pos_name(state, 1, axis)),
                signal_expr(&pos_name(state, 0, axis)),
            ),
        )?;
    }

    let distance_sq = separation_distance_sq_name(state);
    let distance = separation_distance_name(state);
    let distance_residual = separation_distance_residual_name(state);

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
        &format!("state_{state}_separation_distance_residual_bound"),
    )?;
    append_positive_bound(
        builder,
        &distance,
        &max_separation_bound(),
        &format!("state_{state}_separation_distance_bound"),
    )?;
    Ok(())
}

fn append_running_min_constraints(builder: &mut ProgramBuilder, steps: usize) -> ZkfResult<()> {
    let run_min_0 = run_min_name(0);
    builder.private_signal(&run_min_0)?;
    builder.constrain_equal(
        signal_expr(&run_min_0),
        signal_expr(&separation_distance_name(0)),
    )?;
    append_positive_bound(
        builder,
        &run_min_0,
        &max_separation_bound(),
        "state_0_running_min_bound",
    )?;

    for state in 1..=steps {
        let current = run_min_name(state);
        let previous = run_min_name(state - 1);
        let prev_slack = run_min_prev_slack_name(state);
        let curr_slack = run_min_curr_slack_name(state);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_positive_bound(
            builder,
            &current,
            &max_separation_bound(),
            &format!("state_{state}_running_min_bound"),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&prev_slack)]),
            signal_expr(&previous),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&curr_slack)]),
            signal_expr(&separation_distance_name(state)),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&max_separation_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&max_separation_bound()))?;
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(minimum_separation_output_name())?;
    builder.constrain_equal(
        signal_expr(minimum_separation_output_name()),
        signal_expr(&run_min_name(steps)),
    )?;
    append_positive_bound(
        builder,
        minimum_separation_output_name(),
        &max_separation_bound(),
        "minimum_separation_public_bound",
    )?;
    Ok(())
}

fn append_acceleration_constraints(builder: &mut ProgramBuilder, state: usize) -> ZkfResult<()> {
    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let radius_sq = radius_sq_name(state, spacecraft);
        let radius_floor_slack = radius_floor_slack_name(state, spacecraft);
        let radius_floor_anchor = radius_floor_anchor_name(state, spacecraft);
        let inverse_distance = inverse_distance_name(state, spacecraft);
        let inverse_distance_sq = inverse_distance_sq_name(state, spacecraft);
        let inverse_distance_sq_residual_positive =
            inverse_distance_sq_residual_positive_name(state, spacecraft);
        let inverse_distance_sq_residual_negative =
            inverse_distance_sq_residual_negative_name(state, spacecraft);
        let inverse_distance_cubed = inverse_distance_cubed_name(state, spacecraft);
        let inverse_distance_cubed_residual =
            inverse_distance_cubed_residual_name(state, spacecraft);
        let gravity_factor = gravity_factor_name(state, spacecraft);
        let gravity_factor_residual = gravity_factor_residual_name(state, spacecraft);

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
                            signal_expr(&pos_name(state, spacecraft, axis)),
                            signal_expr(&pos_name(state, spacecraft, axis)),
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
            &format!("state_{state}_sc{spacecraft}_inverse_distance_cubed_bound"),
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
            &format!("state_{state}_sc{spacecraft}_gravity_factor_bound"),
        )?;

        for axis in AXES {
            let perturbation = perturbation_name(state, spacecraft, axis);
            let gravity_component = gravity_component_name(state, spacecraft, axis);
            let gravity_component_residual =
                gravity_component_residual_name(state, spacecraft, axis);
            let acceleration = acceleration_name(state, spacecraft, axis);
            builder.private_signal(&perturbation)?;
            builder.private_signal(&gravity_component)?;
            builder.private_signal(&gravity_component_residual)?;
            builder.private_signal(&acceleration)?;
            append_signed_bound(
                builder,
                &perturbation,
                &perturbation_bound(),
                &format!("state_{state}_sc{spacecraft}_perturbation_bound_{axis}"),
            )?;
            builder.constrain_equal(
                mul_expr(
                    neg_expr(signal_expr(&pos_name(state, spacecraft, axis))),
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
                &format!("state_{state}_sc{spacecraft}_gravity_component_bound_{axis}"),
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
                &format!("state_{state}_sc{spacecraft}_acceleration_bound_{axis}"),
            )?;
        }
    }
    Ok(())
}

pub fn private_satellite_conjunction_showcase() -> ZkfResult<TemplateProgram> {
    private_satellite_conjunction_showcase_with_steps(PRIVATE_SATELLITE_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_satellite_conjunction_showcase_with_steps(
    steps: usize,
) -> ZkfResult<TemplateProgram> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private satellite conjunction showcase requires at least one integration step"
                .to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("private_satellite_conjunction_2_spacecraft_{steps}_step"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "private-satellite-conjunction-showcase")?;
    builder.metadata_entry(
        "spacecraft_count",
        PRIVATE_SATELLITE_SPACECRAFT_COUNT.to_string(),
    )?;
    builder.metadata_entry("dimensions", PRIVATE_SATELLITE_DIMENSIONS.to_string())?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "velocity-verlet")?;
    builder.metadata_entry("time_step_seconds", "60")?;
    builder.metadata_entry("window_hours", window_hours_metadata(steps))?;
    builder.metadata_entry("gravity_model", "earth-dominant-newtonian")?;
    builder.metadata_entry(
        "perturbation_model",
        "bounded per-step drag/model-uncertainty surrogate with explicit per-axis witness bounds; the shipped deterministic sample/export path uses the zero member of that bounded family",
    )?;
    builder.metadata_entry(
        "safe_indicator_semantics",
        "public safety-certificate bit fixed to 1 for accepted safe trajectories; unsafe trajectories fail closed during witness generation",
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
    builder.metadata_entry("burn_schedule", "exactly-one-impulse-per-spacecraft")?;
    builder.metadata_entry("determinism", "fixed-seed-runtime-and-proof-path")?;
    builder.metadata_entry(
        "error_model",
        "deterministic fixed-point residual witnesses with explicit algebraic bounds",
    )?;

    let mut expected_inputs =
        Vec::with_capacity(PRIVATE_SATELLITE_PRIVATE_INPUTS + PRIVATE_SATELLITE_PUBLIC_INPUTS);
    let public_outputs = vec![
        final_state_commitment_output_name(0),
        final_state_commitment_output_name(1),
        minimum_separation_output_name().to_string(),
        safe_indicator_name().to_string(),
        maneuver_plan_commitment_output_name().to_string(),
    ];

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

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let mass = mass_name(spacecraft);
        let burn_step = burn_step_name(spacecraft);
        builder.private_input(&mass)?;
        builder.private_input(&burn_step)?;
        expected_inputs.push(mass.clone());
        expected_inputs.push(burn_step.clone());
        append_positive_bound(
            &mut builder,
            &mass,
            &mass_bound(),
            &format!("sc{spacecraft}_mass_bound"),
        )?;
        append_nonzero_constraint(&mut builder, &mass, &format!("sc{spacecraft}_mass_nonzero"))?;
        builder.constrain_range(&burn_step, burn_step_bits(steps))?;

        let mut burn_flags = Vec::with_capacity(steps);
        let mut weighted_flags = Vec::with_capacity(steps);
        for step in 0..steps {
            let flag = burn_flag_name(spacecraft, step);
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
            let position = pos_input_name(spacecraft, axis);
            let velocity = vel_input_name(spacecraft, axis);
            let delta_v = dv_name(spacecraft, axis);
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
                &format!("sc{spacecraft}_position_input_bound_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &velocity,
                &velocity_bound(),
                &format!("sc{spacecraft}_velocity_input_bound_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &delta_v,
                &delta_v_component_bound(),
                &format!("sc{spacecraft}_delta_v_input_bound_{axis}"),
            )?;
        }
    }

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let dv_norm_sq = delta_v_norm_sq_name(spacecraft);
        let dv_norm = delta_v_norm_name(spacecraft);
        let dv_norm_residual = delta_v_norm_residual_name(spacecraft);
        builder.private_signal(&dv_norm_sq)?;
        builder.private_signal(&dv_norm)?;
        builder.private_signal(&dv_norm_residual)?;
        builder.constrain_equal(
            signal_expr(&dv_norm_sq),
            add_expr(
                AXES.iter()
                    .map(|axis| {
                        mul_expr(
                            signal_expr(&dv_name(spacecraft, axis)),
                            signal_expr(&dv_name(spacecraft, axis)),
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
            &format!("sc{spacecraft}_delta_v_norm_residual_bound"),
        )?;
        append_positive_bound(
            &mut builder,
            &dv_norm,
            &delta_v_total_bound(),
            &format!("sc{spacecraft}_delta_v_norm_bound"),
        )?;

        for axis in AXES {
            let impulse = impulse_name(spacecraft, axis);
            let impulse_residual = impulse_residual_name(spacecraft, axis);
            builder.private_signal(&impulse)?;
            builder.private_signal(&impulse_residual)?;
            builder.constrain_equal(
                mul_expr(
                    signal_expr(&mass_name(spacecraft)),
                    signal_expr(&dv_name(spacecraft, axis)),
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
                &format!("sc{spacecraft}_impulse_residual_bound_{axis}"),
            )?;
        }
    }

    builder.private_signal(total_delta_v_name())?;
    builder.private_signal(delta_v_budget_slack_name())?;
    builder.constrain_equal(
        signal_expr(total_delta_v_name()),
        add_expr(
            (0..PRIVATE_SATELLITE_SPACECRAFT_COUNT)
                .map(|spacecraft| signal_expr(&delta_v_norm_name(spacecraft)))
                .collect(),
        ),
    )?;
    append_positive_bound(
        &mut builder,
        total_delta_v_name(),
        &delta_v_total_bound(),
        "total_delta_v_bound",
    )?;
    builder.constrain_equal(
        signal_expr(delta_v_budget_name()),
        add_expr(vec![
            signal_expr(total_delta_v_name()),
            signal_expr(delta_v_budget_slack_name()),
        ]),
    )?;
    builder.constrain_range(
        delta_v_budget_slack_name(),
        bits_for_bound(&delta_v_total_bound()),
    )?;

    append_acceleration_constraints(&mut builder, 0)?;

    for step in 0..steps {
        for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
            let burn_flag = burn_flag_name(spacecraft, step);
            for axis in AXES {
                let burn_velocity = burn_velocity_name(step, spacecraft, axis);
                let next_position = pos_name(step + 1, spacecraft, axis);
                let next_velocity = vel_name(step + 1, spacecraft, axis);
                let position_residual = position_update_residual_name(step, spacecraft, axis);
                builder.private_signal(&burn_velocity)?;
                builder.private_signal(&next_position)?;
                builder.private_signal(&next_velocity)?;
                builder.private_signal(&position_residual)?;
                builder.constrain_equal(
                    signal_expr(&burn_velocity),
                    add_expr(vec![
                        signal_expr(&vel_name(step, spacecraft, axis)),
                        mul_expr(
                            signal_expr(&burn_flag),
                            signal_expr(&dv_name(spacecraft, axis)),
                        ),
                    ]),
                )?;
                append_signed_bound(
                    &mut builder,
                    &burn_velocity,
                    &burn_velocity_bound(),
                    &format!("step_{step}_sc{spacecraft}_burn_velocity_bound_{axis}"),
                )?;
                append_signed_bound(
                    &mut builder,
                    &next_position,
                    &position_bound(),
                    &format!("step_{}_sc{spacecraft}_position_bound_{axis}", step + 1),
                )?;
                append_signed_bound(
                    &mut builder,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("step_{}_sc{spacecraft}_velocity_bound_{axis}", step + 1),
                )?;
                builder.constrain_equal(
                    mul_expr(
                        signal_expr(&acceleration_name(step, spacecraft, axis)),
                        const_expr(&time_step_squared()),
                    ),
                    add_expr(vec![
                        mul_expr(
                            const_expr(&two()),
                            add_expr(vec![
                                signal_expr(&next_position),
                                neg_expr(signal_expr(&pos_name(step, spacecraft, axis))),
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
                    &format!("step_{step}_sc{spacecraft}_position_update_residual_bound_{axis}"),
                )?;
            }
        }

        append_acceleration_constraints(&mut builder, step + 1)?;

        for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
            for axis in AXES {
                let burn_velocity = burn_velocity_name(step, spacecraft, axis);
                let velocity_residual = velocity_update_residual_name(step, spacecraft, axis);
                let next_velocity = vel_name(step + 1, spacecraft, axis);
                builder.private_signal(&velocity_residual)?;
                builder.constrain_equal(
                    mul_expr(
                        add_expr(vec![
                            signal_expr(&acceleration_name(step, spacecraft, axis)),
                            signal_expr(&acceleration_name(step + 1, spacecraft, axis)),
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
                    &format!("step_{step}_sc{spacecraft}_velocity_update_residual_bound_{axis}"),
                )?;
            }
        }
    }

    for state in 0..=steps {
        append_separation_constraints(&mut builder, state)?;
    }
    append_running_min_constraints(&mut builder, steps)?;

    builder.public_output(safe_indicator_name())?;
    builder.private_signal(safety_slack_name())?;
    builder.constrain_boolean(safe_indicator_name())?;
    builder.constrain_equal(signal_expr(safe_indicator_name()), const_expr(&one()))?;
    builder.constrain_equal(
        signal_expr(minimum_separation_output_name()),
        add_expr(vec![
            signal_expr(collision_threshold_name()),
            signal_expr(safety_slack_name()),
        ]),
    )?;
    builder.constrain_range(safety_slack_name(), bits_for_bound(&max_separation_bound()))?;

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let output = final_state_commitment_output_name(spacecraft);
        builder.public_output(&output)?;
        let pos_digest = append_poseidon_hash(
            &mut builder,
            &format!("sc{spacecraft}_final_position_commitment"),
            [
                signal_expr(&pos_name(steps, spacecraft, "x")),
                signal_expr(&pos_name(steps, spacecraft, "y")),
                signal_expr(&pos_name(steps, spacecraft, "z")),
                const_expr(&final_position_tag(spacecraft)),
            ],
        )?;
        let vel_digest = append_poseidon_hash(
            &mut builder,
            &format!("sc{spacecraft}_final_velocity_commitment"),
            [
                signal_expr(&vel_name(steps, spacecraft, "x")),
                signal_expr(&vel_name(steps, spacecraft, "y")),
                signal_expr(&vel_name(steps, spacecraft, "z")),
                const_expr(&final_velocity_tag(spacecraft)),
            ],
        )?;
        let state_digest = append_poseidon_hash(
            &mut builder,
            &format!("sc{spacecraft}_final_state_commitment"),
            [
                signal_expr(&pos_digest),
                signal_expr(&vel_digest),
                const_expr(&final_state_tag(spacecraft)),
                const_expr(&BigInt::from(steps as u64)),
            ],
        )?;
        builder.constrain_equal(signal_expr(&output), signal_expr(&state_digest))?;
    }

    builder.public_output(maneuver_plan_commitment_output_name())?;
    let leaf_0 = append_poseidon_hash(
        &mut builder,
        "sc0_plan_leaf",
        [
            signal_expr(&dv_name(0, "x")),
            signal_expr(&dv_name(0, "y")),
            signal_expr(&dv_name(0, "z")),
            signal_expr(&burn_step_name(0)),
        ],
    )?;
    let leaf_1 = append_poseidon_hash(
        &mut builder,
        "sc0_mass_impulse_leaf",
        [
            signal_expr(&mass_name(0)),
            signal_expr(&impulse_name(0, "x")),
            signal_expr(&impulse_name(0, "y")),
            signal_expr(&impulse_name(0, "z")),
        ],
    )?;
    let leaf_2 = append_poseidon_hash(
        &mut builder,
        "sc1_plan_leaf",
        [
            signal_expr(&dv_name(1, "x")),
            signal_expr(&dv_name(1, "y")),
            signal_expr(&dv_name(1, "z")),
            signal_expr(&burn_step_name(1)),
        ],
    )?;
    let leaf_3 = append_poseidon_hash(
        &mut builder,
        "sc1_mass_impulse_leaf",
        [
            signal_expr(&mass_name(1)),
            signal_expr(&impulse_name(1, "x")),
            signal_expr(&impulse_name(1, "y")),
            signal_expr(&impulse_name(1, "z")),
        ],
    )?;
    let plan_digest = append_poseidon_hash(
        &mut builder,
        "maneuver_plan_commitment",
        [
            signal_expr(&leaf_0),
            signal_expr(&leaf_1),
            signal_expr(&leaf_2),
            signal_expr(&leaf_3),
        ],
    )?;
    builder.constrain_equal(
        signal_expr(maneuver_plan_commitment_output_name()),
        signal_expr(&plan_digest),
    )?;

    let sample_inputs = private_satellite_conjunction_sample_inputs_for_steps(steps);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(collision_threshold_name().to_string(), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: if steps == PRIVATE_SATELLITE_DEFAULT_STEPS {
            PRIVATE_SATELLITE_DESCRIPTION
        } else {
            PRIVATE_SATELLITE_TEST_HELPER_DESCRIPTION
        },
    })
}

pub fn private_satellite_conjunction_sample_inputs() -> WitnessInputs {
    private_satellite_conjunction_sample_inputs_for_steps(PRIVATE_SATELLITE_DEFAULT_STEPS)
}

pub fn private_satellite_conjunction_witness(inputs: &WitnessInputs) -> ZkfResult<Witness> {
    private_satellite_conjunction_witness_with_steps(inputs, PRIVATE_SATELLITE_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_satellite_conjunction_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private satellite conjunction witness generation requires at least one integration step"
                .to_string(),
        ));
    }

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

    let mut masses: [BigInt; PRIVATE_SATELLITE_SPACECRAFT_COUNT] = std::array::from_fn(|_| zero());
    let mut positions: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS];
        PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));
    let mut velocities: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS];
        PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));
    let mut delta_vs: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS]; PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));
    let mut burn_steps: [usize; PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
        std::array::from_fn(|_| 0usize);

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let mass = read_input(inputs, &mass_name(spacecraft))?;
        let burn_step = read_input(inputs, &burn_step_name(spacecraft))?;
        ensure_positive_le(&mass_name(spacecraft), &mass, &mass_bound())?;
        ensure_nonnegative_le(
            &burn_step_name(spacecraft),
            &burn_step,
            &BigInt::from((steps - 1) as u64),
        )?;
        write_value(&mut values, mass_name(spacecraft), mass.clone());
        write_value(&mut values, burn_step_name(spacecraft), burn_step.clone());
        write_positive_bound_support(
            &mut values,
            &mass,
            &mass_bound(),
            &format!("sc{spacecraft}_mass_bound"),
        )?;
        write_nonzero_inverse_support(&mut values, &mass, &format!("sc{spacecraft}_mass_nonzero"))?;
        masses[spacecraft] = mass;
        burn_steps[spacecraft] = burn_step
            .to_str_radix(10)
            .parse::<usize>()
            .map_err(|error| {
                ZkfError::InvalidArtifact(format!("invalid burn step for sc{spacecraft}: {error}"))
            })?;

        for step in 0..steps {
            write_value(
                &mut values,
                burn_flag_name(spacecraft, step),
                if burn_steps[spacecraft] == step {
                    one()
                } else {
                    zero()
                },
            );
        }

        for (axis_index, axis) in AXES.iter().enumerate() {
            let position = read_input(inputs, &pos_input_name(spacecraft, axis))?;
            let velocity = read_input(inputs, &vel_input_name(spacecraft, axis))?;
            let delta_v = read_input(inputs, &dv_name(spacecraft, axis))?;
            ensure_abs_le(
                &pos_input_name(spacecraft, axis),
                &position,
                &position_bound(),
            )?;
            ensure_abs_le(
                &vel_input_name(spacecraft, axis),
                &velocity,
                &velocity_bound(),
            )?;
            ensure_abs_le(
                &dv_name(spacecraft, axis),
                &delta_v,
                &delta_v_component_bound(),
            )?;
            write_value(
                &mut values,
                pos_input_name(spacecraft, axis),
                position.clone(),
            );
            write_value(
                &mut values,
                vel_input_name(spacecraft, axis),
                velocity.clone(),
            );
            write_value(&mut values, dv_name(spacecraft, axis), delta_v.clone());
            write_signed_bound_support(
                &mut values,
                &position,
                &position_bound(),
                &format!("sc{spacecraft}_position_input_bound_{axis}"),
            )?;
            write_signed_bound_support(
                &mut values,
                &velocity,
                &velocity_bound(),
                &format!("sc{spacecraft}_velocity_input_bound_{axis}"),
            )?;
            write_signed_bound_support(
                &mut values,
                &delta_v,
                &delta_v_component_bound(),
                &format!("sc{spacecraft}_delta_v_input_bound_{axis}"),
            )?;
            positions[spacecraft][axis_index] = position;
            velocities[spacecraft][axis_index] = velocity;
            delta_vs[spacecraft][axis_index] = delta_v;
        }
    }

    let mut dv_norms: [BigInt; PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
        std::array::from_fn(|_| zero());
    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let dv_norm_sq = AXES
            .iter()
            .enumerate()
            .fold(zero(), |acc, (axis_index, _)| {
                acc + &delta_vs[spacecraft][axis_index] * &delta_vs[spacecraft][axis_index]
            });
        let dv_norm = nearest_integer_sqrt(&dv_norm_sq);
        let dv_norm_residual = (&dv_norm * &dv_norm) - &dv_norm_sq;
        ensure_nonnegative_le(
            &delta_v_norm_name(spacecraft),
            &dv_norm,
            &delta_v_total_bound(),
        )?;
        write_value(
            &mut values,
            delta_v_norm_sq_name(spacecraft),
            dv_norm_sq.clone(),
        );
        write_value(&mut values, delta_v_norm_name(spacecraft), dv_norm.clone());
        write_value(
            &mut values,
            delta_v_norm_residual_name(spacecraft),
            dv_norm_residual.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &dv_norm_residual,
            &sqrt_residual_bound(&delta_v_total_bound()),
            &format!("sc{spacecraft}_delta_v_norm_residual_bound"),
        )?;
        write_positive_bound_support(
            &mut values,
            &dv_norm,
            &delta_v_total_bound(),
            &format!("sc{spacecraft}_delta_v_norm_bound"),
        )?;
        dv_norms[spacecraft] = dv_norm;

        for (axis_index, axis) in AXES.iter().enumerate() {
            let (impulse, impulse_residual) = div_round_nearest(
                &(&masses[spacecraft] * &delta_vs[spacecraft][axis_index]),
                &fixed_scale(),
            );
            write_value(&mut values, impulse_name(spacecraft, axis), impulse.clone());
            write_value(
                &mut values,
                impulse_residual_name(spacecraft, axis),
                impulse_residual.clone(),
            );
            write_signed_bound_support(
                &mut values,
                &impulse_residual,
                &impulse_remainder_bound(),
                &format!("sc{spacecraft}_impulse_residual_bound_{axis}"),
            )?;
        }
    }

    let total_delta_v = &dv_norms[0] + &dv_norms[1];
    if total_delta_v > delta_v_budget {
        return Err(ZkfError::InvalidArtifact(
            "total delta-v exceeded the public mission budget threshold".to_string(),
        ));
    }
    write_value(&mut values, total_delta_v_name(), total_delta_v.clone());
    write_positive_bound_support(
        &mut values,
        &total_delta_v,
        &delta_v_total_bound(),
        "total_delta_v_bound",
    )?;
    write_value(
        &mut values,
        delta_v_budget_slack_name(),
        &delta_v_budget - &total_delta_v,
    );

    let mut current_accelerations = compute_acceleration_state(&mut values, 0, &positions)?;

    for step in 0..steps {
        let mut burn_velocities: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS];
            PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
            let flag = if burn_steps[spacecraft] == step {
                one()
            } else {
                zero()
            };
            for (axis_index, axis) in AXES.iter().enumerate() {
                let burn_velocity = &velocities[spacecraft][axis_index]
                    + (&flag * &delta_vs[spacecraft][axis_index]);
                ensure_abs_le(
                    &burn_velocity_name(step, spacecraft, axis),
                    &burn_velocity,
                    &burn_velocity_bound(),
                )?;
                write_value(
                    &mut values,
                    burn_velocity_name(step, spacecraft, axis),
                    burn_velocity.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &burn_velocity,
                    &burn_velocity_bound(),
                    &format!("step_{step}_sc{spacecraft}_burn_velocity_bound_{axis}"),
                )?;
                burn_velocities[spacecraft][axis_index] = burn_velocity;
            }
        }

        let mut next_positions: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS];
            PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let velocity_term = &burn_velocities[spacecraft][axis_index] * &time_step_seconds();
                let accel_numerator =
                    &current_accelerations[spacecraft][axis_index] * &time_step_squared();
                let (half_accel_term, position_residual) =
                    div_round_nearest(&accel_numerator, &two());
                let next_position =
                    &positions[spacecraft][axis_index] + velocity_term + &half_accel_term;
                ensure_abs_le(
                    &pos_name(step + 1, spacecraft, axis),
                    &next_position,
                    &position_bound(),
                )?;
                write_value(
                    &mut values,
                    position_update_residual_name(step, spacecraft, axis),
                    position_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &position_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sc{spacecraft}_position_update_residual_bound_{axis}"),
                )?;
                write_value(
                    &mut values,
                    pos_name(step + 1, spacecraft, axis),
                    next_position.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_position,
                    &position_bound(),
                    &format!("step_{}_sc{spacecraft}_position_bound_{axis}", step + 1),
                )?;
                next_positions[spacecraft][axis_index] = next_position;
            }
        }

        let next_accelerations =
            compute_acceleration_state(&mut values, step + 1, &next_positions)?;
        let mut next_velocities: [[BigInt; PRIVATE_SATELLITE_DIMENSIONS];
            PRIVATE_SATELLITE_SPACECRAFT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let accel_sum_dt = (&current_accelerations[spacecraft][axis_index]
                    + &next_accelerations[spacecraft][axis_index])
                    * &time_step_seconds();
                let (half_velocity_term, velocity_residual) =
                    div_round_nearest(&accel_sum_dt, &two());
                let next_velocity = &burn_velocities[spacecraft][axis_index] + &half_velocity_term;
                ensure_abs_le(
                    &vel_name(step + 1, spacecraft, axis),
                    &next_velocity,
                    &velocity_bound(),
                )?;
                write_value(
                    &mut values,
                    velocity_update_residual_name(step, spacecraft, axis),
                    velocity_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &velocity_residual,
                    &integration_remainder_bound(),
                    &format!("step_{step}_sc{spacecraft}_velocity_update_residual_bound_{axis}"),
                )?;
                write_value(
                    &mut values,
                    vel_name(step + 1, spacecraft, axis),
                    next_velocity.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("step_{}_sc{spacecraft}_velocity_bound_{axis}", step + 1),
                )?;
                next_velocities[spacecraft][axis_index] = next_velocity;
            }
        }

        positions = next_positions;
        velocities = next_velocities;
        current_accelerations = next_accelerations;
    }

    let mut separations = Vec::with_capacity(steps + 1);
    let trajectory_positions = reconstruct_positions_from_values(&values, steps)?;
    for (state, positions) in trajectory_positions.iter().enumerate().take(steps + 1) {
        let sep = compute_separation_state(&mut values, state, positions)?;
        separations.push(sep);
    }

    let mut running_min = separations[0].clone();
    write_value(&mut values, run_min_name(0), running_min.clone());
    write_positive_bound_support(
        &mut values,
        &running_min,
        &max_separation_bound(),
        "state_0_running_min_bound",
    )?;
    for (state, current_sep) in separations.iter().enumerate().take(steps + 1).skip(1) {
        let current_sep = current_sep.clone();
        let next_min = if current_sep < running_min {
            current_sep.clone()
        } else {
            running_min.clone()
        };
        let prev_slack = &running_min - &next_min;
        let curr_slack = &current_sep - &next_min;
        write_value(&mut values, run_min_name(state), next_min.clone());
        write_positive_bound_support(
            &mut values,
            &next_min,
            &max_separation_bound(),
            &format!("state_{state}_running_min_bound"),
        )?;
        write_value(&mut values, run_min_prev_slack_name(state), prev_slack);
        write_value(&mut values, run_min_curr_slack_name(state), curr_slack);
        running_min = next_min;
    }

    if running_min < collision_threshold {
        return Err(ZkfError::InvalidArtifact(
            "minimum separation dropped below the required collision threshold".to_string(),
        ));
    }
    let safety_slack = &running_min - &collision_threshold;
    write_value(
        &mut values,
        minimum_separation_output_name(),
        running_min.clone(),
    );
    write_positive_bound_support(
        &mut values,
        &running_min,
        &max_separation_bound(),
        "minimum_separation_public_bound",
    )?;
    write_value(&mut values, safety_slack_name(), safety_slack);
    write_value(&mut values, safe_indicator_name(), one());

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let pos_state = poseidon_permutation4_bn254(&[
            field_ref(&positions[spacecraft][0]),
            field_ref(&positions[spacecraft][1]),
            field_ref(&positions[spacecraft][2]),
            field_ref(&final_position_tag(spacecraft)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sc{spacecraft}_final_position_commitment"))
            .into_iter()
            .zip(pos_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        let vel_state = poseidon_permutation4_bn254(&[
            field_ref(&velocities[spacecraft][0]),
            field_ref(&velocities[spacecraft][1]),
            field_ref(&velocities[spacecraft][2]),
            field_ref(&final_velocity_tag(spacecraft)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sc{spacecraft}_final_velocity_commitment"))
            .into_iter()
            .zip(vel_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        let state_state = poseidon_permutation4_bn254(&[
            pos_state[0].clone(),
            vel_state[0].clone(),
            field_ref(&final_state_tag(spacecraft)),
            field(BigInt::from(steps as u64)),
        ])
        .map_err(ZkfError::Backend)?;
        for (lane, value) in hash_state_names(&format!("sc{spacecraft}_final_state_commitment"))
            .into_iter()
            .zip(state_state.iter().cloned())
        {
            values.insert(lane, value);
        }
        values.insert(
            final_state_commitment_output_name(spacecraft),
            state_state[0].clone(),
        );
    }

    let leaf_0_state = poseidon_permutation4_bn254(&[
        field_ref(&delta_vs[0][0]),
        field_ref(&delta_vs[0][1]),
        field_ref(&delta_vs[0][2]),
        field(BigInt::from(burn_steps[0] as u64)),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("sc0_plan_leaf")
        .into_iter()
        .zip(leaf_0_state.iter().cloned())
    {
        values.insert(lane, value);
    }
    let leaf_1_state = poseidon_permutation4_bn254(&[
        field_ref(&masses[0]),
        values[&impulse_name(0, "x")].clone(),
        values[&impulse_name(0, "y")].clone(),
        values[&impulse_name(0, "z")].clone(),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("sc0_mass_impulse_leaf")
        .into_iter()
        .zip(leaf_1_state.iter().cloned())
    {
        values.insert(lane, value);
    }
    let leaf_2_state = poseidon_permutation4_bn254(&[
        field_ref(&delta_vs[1][0]),
        field_ref(&delta_vs[1][1]),
        field_ref(&delta_vs[1][2]),
        field(BigInt::from(burn_steps[1] as u64)),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("sc1_plan_leaf")
        .into_iter()
        .zip(leaf_2_state.iter().cloned())
    {
        values.insert(lane, value);
    }
    let leaf_3_state = poseidon_permutation4_bn254(&[
        field_ref(&masses[1]),
        values[&impulse_name(1, "x")].clone(),
        values[&impulse_name(1, "y")].clone(),
        values[&impulse_name(1, "z")].clone(),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("sc1_mass_impulse_leaf")
        .into_iter()
        .zip(leaf_3_state.iter().cloned())
    {
        values.insert(lane, value);
    }
    let plan_state = poseidon_permutation4_bn254(&[
        leaf_0_state[0].clone(),
        leaf_1_state[0].clone(),
        leaf_2_state[0].clone(),
        leaf_3_state[0].clone(),
    ])
    .map_err(ZkfError::Backend)?;
    for (lane, value) in hash_state_names("maneuver_plan_commitment")
        .into_iter()
        .zip(plan_state.iter().cloned())
    {
        values.insert(lane, value);
    }
    values.insert(
        maneuver_plan_commitment_output_name().to_string(),
        plan_state[0].clone(),
    );

    Ok(Witness { values })
}

fn compute_acceleration_state(
    values: &mut BTreeMap<String, FieldElement>,
    state: usize,
    positions: &[[BigInt; PRIVATE_SATELLITE_DIMENSIONS]; PRIVATE_SATELLITE_SPACECRAFT_COUNT],
) -> ZkfResult<[[BigInt; PRIVATE_SATELLITE_DIMENSIONS]; PRIVATE_SATELLITE_SPACECRAFT_COUNT]> {
    let mut accelerations = std::array::from_fn(|_| std::array::from_fn(|_| zero()));

    for spacecraft in 0..PRIVATE_SATELLITE_SPACECRAFT_COUNT {
        let radius_sq = positions[spacecraft]
            .iter()
            .fold(zero(), |acc, value| acc + value * value);
        if radius_sq < min_radius_squared() {
            return Err(ZkfError::InvalidArtifact(format!(
                "spacecraft {spacecraft} violated the minimum modeled orbital radius at state {state}"
            )));
        }
        let radius_floor_slack = &radius_sq - &min_radius_squared();
        let radius_floor_slack_field = field_ref(&radius_floor_slack);
        write_value(
            &mut *values,
            radius_sq_name(state, spacecraft),
            radius_sq.clone(),
        );
        values.insert(
            radius_floor_slack_name(state, spacecraft),
            radius_floor_slack_field.clone(),
        );
        values.insert(
            radius_floor_anchor_name(state, spacecraft),
            bn254_square(&radius_floor_slack),
        );

        let inverse_distance = nearest_inverse_distance(&radius_sq);
        let inverse_distance_sq = &inverse_distance * &inverse_distance;
        let inverse_distance_sq_residual =
            fixed_scale_fourth() - (&radius_sq * &inverse_distance_sq);
        write_value(
            &mut *values,
            inverse_distance_name(state, spacecraft),
            inverse_distance.clone(),
        );
        write_value(
            &mut *values,
            inverse_distance_sq_name(state, spacecraft),
            inverse_distance_sq.clone(),
        );
        write_value(
            &mut *values,
            inverse_distance_sq_residual_positive_name(state, spacecraft),
            if inverse_distance_sq_residual.sign() == Sign::Minus {
                zero()
            } else {
                inverse_distance_sq_residual.clone()
            },
        );
        write_value(
            &mut *values,
            inverse_distance_sq_residual_negative_name(state, spacecraft),
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
            &mut *values,
            inverse_distance_cubed_name(state, spacecraft),
            inverse_distance_cubed.clone(),
        );
        write_value(
            &mut *values,
            inverse_distance_cubed_residual_name(state, spacecraft),
            inverse_distance_cubed_residual.clone(),
        );
        write_signed_bound_support(
            &mut *values,
            &inverse_distance_cubed_residual,
            &inv_r3_remainder_bound(),
            &format!("state_{state}_sc{spacecraft}_inverse_distance_cubed_bound"),
        )?;

        let (gravity_factor, gravity_factor_residual) = div_round_nearest(
            &(mu_earth_scaled() * &inverse_distance_cubed),
            &fixed_scale(),
        );
        write_value(
            &mut *values,
            gravity_factor_name(state, spacecraft),
            gravity_factor.clone(),
        );
        write_value(
            &mut *values,
            gravity_factor_residual_name(state, spacecraft),
            gravity_factor_residual.clone(),
        );
        write_signed_bound_support(
            &mut *values,
            &gravity_factor_residual,
            &factor_remainder_bound(),
            &format!("state_{state}_sc{spacecraft}_gravity_factor_bound"),
        )?;

        for (axis_index, axis) in AXES.iter().enumerate() {
            let perturbation = zero();
            let numerator = -positions[spacecraft][axis_index].clone() * &gravity_factor;
            let (gravity_component, gravity_component_residual) =
                div_round_nearest(&numerator, &fixed_scale());
            let acceleration = &gravity_component + &perturbation;
            ensure_abs_le(
                &acceleration_name(state, spacecraft, axis),
                &acceleration,
                &acceleration_bound(),
            )?;
            write_value(
                &mut *values,
                perturbation_name(state, spacecraft, axis),
                perturbation,
            );
            write_signed_bound_support(
                &mut *values,
                &zero(),
                &perturbation_bound(),
                &format!("state_{state}_sc{spacecraft}_perturbation_bound_{axis}"),
            )?;
            write_value(
                &mut *values,
                gravity_component_name(state, spacecraft, axis),
                gravity_component.clone(),
            );
            write_value(
                &mut *values,
                gravity_component_residual_name(state, spacecraft, axis),
                gravity_component_residual.clone(),
            );
            write_signed_bound_support(
                &mut *values,
                &gravity_component_residual,
                &component_remainder_bound(),
                &format!("state_{state}_sc{spacecraft}_gravity_component_bound_{axis}"),
            )?;
            write_value(
                &mut *values,
                acceleration_name(state, spacecraft, axis),
                acceleration.clone(),
            );
            write_signed_bound_support(
                &mut *values,
                &acceleration,
                &acceleration_bound(),
                &format!("state_{state}_sc{spacecraft}_acceleration_bound_{axis}"),
            )?;
            accelerations[spacecraft][axis_index] = acceleration;
        }
    }

    Ok(accelerations)
}

fn reconstruct_positions_from_values(
    values: &BTreeMap<String, FieldElement>,
    steps: usize,
) -> ZkfResult<Vec<[[BigInt; PRIVATE_SATELLITE_DIMENSIONS]; PRIVATE_SATELLITE_SPACECRAFT_COUNT]>> {
    let mut states = Vec::with_capacity(steps + 1);
    for step in 0..=steps {
        let mut snapshot = std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for (spacecraft, entry) in snapshot
            .iter_mut()
            .enumerate()
            .take(PRIVATE_SATELLITE_SPACECRAFT_COUNT)
        {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let name = pos_name(step, spacecraft, axis);
                entry[axis_index] = values
                    .get(&name)
                    .ok_or_else(|| ZkfError::MissingWitnessValue {
                        signal: name.clone(),
                    })?
                    .as_bigint();
            }
        }
        states.push(snapshot);
    }
    Ok(states)
}

fn compute_separation_state(
    values: &mut BTreeMap<String, FieldElement>,
    state: usize,
    positions: &[[BigInt; PRIVATE_SATELLITE_DIMENSIONS]; PRIVATE_SATELLITE_SPACECRAFT_COUNT],
) -> ZkfResult<BigInt> {
    let deltas: [BigInt; PRIVATE_SATELLITE_DIMENSIONS] =
        std::array::from_fn(|axis| positions[1][axis].clone() - positions[0][axis].clone());
    for (axis_index, axis) in AXES.iter().enumerate() {
        write_value(
            values,
            separation_delta_name(state, axis),
            deltas[axis_index].clone(),
        );
    }
    let distance_sq = deltas.iter().fold(zero(), |acc, value| acc + value * value);
    let distance = nearest_integer_sqrt(&distance_sq);
    let distance_residual = (&distance * &distance) - &distance_sq;
    ensure_nonnegative_le(
        &separation_distance_name(state),
        &distance,
        &max_separation_bound(),
    )?;
    write_value(values, separation_distance_sq_name(state), distance_sq);
    write_value(values, separation_distance_name(state), distance.clone());
    write_value(
        values,
        separation_distance_residual_name(state),
        distance_residual.clone(),
    );
    write_signed_bound_support(
        values,
        &distance_residual,
        &sqrt_residual_bound(&max_separation_bound()),
        &format!("state_{state}_separation_distance_residual_bound"),
    )?;
    write_positive_bound_support(
        values,
        &distance,
        &max_separation_bound(),
        &format!("state_{state}_separation_distance_bound"),
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

    const SATELLITE_TEST_STACK_SIZE: usize = 64 * 1024 * 1024;

    fn sample_inputs_for_steps(steps: usize) -> WitnessInputs {
        let mut inputs = private_satellite_conjunction_sample_inputs();
        inputs.insert(burn_step_name(0), field(BigInt::from(0u64)));
        inputs.insert(
            burn_step_name(1),
            field(BigInt::from(steps.saturating_sub(1) as u64)),
        );
        inputs
    }

    fn run_satellite_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(SATELLITE_TEST_STACK_SIZE)
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
    fn satellite_template_has_expected_surface() {
        let template = private_satellite_conjunction_showcase_with_steps(2).expect("template");
        assert_eq!(
            template.expected_inputs.len(),
            PRIVATE_SATELLITE_PRIVATE_INPUTS + PRIVATE_SATELLITE_PUBLIC_INPUTS
        );
        assert_eq!(
            template.public_outputs.len(),
            PRIVATE_SATELLITE_PUBLIC_OUTPUTS
        );
        assert_eq!(PRIVATE_SATELLITE_DEFAULT_STEPS, 1440);
        assert_eq!(
            template
                .program
                .metadata
                .get("integration_steps")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            template
                .program
                .metadata
                .get("integrator")
                .map(String::as_str),
            Some("velocity-verlet")
        );
    }

    #[test]
    fn satellite_small_step_witness_satisfies_constraints() {
        run_satellite_test_on_large_stack(
            "satellite_small_step_witness_satisfies_constraints",
            || {
                for steps in 1..=2 {
                    let template =
                        private_satellite_conjunction_showcase_with_steps(steps).expect("template");
                    let compiled = lowered_compiled_program_for_test(&template.program);
                    let inputs = sample_inputs_for_steps(steps);
                    let witness = private_satellite_conjunction_witness_with_steps(&inputs, steps)
                        .expect("witness");
                    let prepared =
                        enrich_witness_for_proving(&compiled, &witness).expect("prepared");
                    if let Err(error) = check_constraints(&compiled.program, &prepared) {
                        let (failing_constraint, witness_detail) = match &error {
                        zkf_core::ZkfError::ConstraintViolation { index, .. }
                        | zkf_core::ZkfError::BooleanConstraintViolation { index, .. }
                        | zkf_core::ZkfError::RangeConstraintViolation { index, .. }
                        | zkf_core::ZkfError::LookupConstraintViolation { index, .. } => compiled
                            .program
                            .constraints
                            .get(*index)
                            .map(|constraint| {
                                let detail = match constraint {
                                    zkf_core::Constraint::Equal {
                                        lhs: zkf_core::Expr::Signal(anchor),
                                        rhs: zkf_core::Expr::Mul(
                                            left,
                                            right,
                                        ),
                                        ..
                                    } => match (&**left, &**right) {
                                        (
                                            zkf_core::Expr::Signal(left_name),
                                            zkf_core::Expr::Signal(right_name),
                                        ) => {
                                            let base_anchor_value = witness.values.get(anchor);
                                            let base_left_value = witness.values.get(left_name);
                                            let base_right_value = witness.values.get(right_name);
                                            let anchor_value = prepared.values.get(anchor);
                                            let left_value = prepared.values.get(left_name);
                                            let right_value = prepared.values.get(right_name);
                                            format!(
                                                "base_anchor_value={base_anchor_value:?} base_left_value={base_left_value:?} base_right_value={base_right_value:?} anchor_value={anchor_value:?} left_value={left_value:?} right_value={right_value:?}"
                                            )
                                        }
                                        _ => "<non-signal multiplication>".to_string(),
                                    },
                                    _ => "<no witness detail>".to_string(),
                                };
                                (format!("{constraint:?}"), detail)
                            })
                            .unwrap_or_else(|| {
                                (
                                    "<missing constraint>".to_string(),
                                    "<missing witness detail>".to_string(),
                                )
                            }),
                        _ => (
                            "<non-constraint error>".to_string(),
                            "<non-constraint error>".to_string(),
                        ),
                    };
                        panic!(
                            "constraints failed for steps={steps}: {error:?}\nfailing_constraint={failing_constraint}\nwitness_detail={witness_detail}"
                        );
                    }
                }
            },
        );
    }

    #[test]
    fn satellite_wrong_burn_step_fails() {
        let mut inputs = private_satellite_conjunction_sample_inputs();
        inputs.insert(
            burn_step_name(0),
            field(BigInt::from(PRIVATE_SATELLITE_DEFAULT_STEPS as u64)),
        );
        private_satellite_conjunction_witness_with_steps(&inputs, 4)
            .expect_err("out-of-range burn step must fail");
    }

    #[test]
    fn satellite_threshold_violation_fails() {
        let mut inputs = private_satellite_conjunction_sample_inputs();
        inputs.insert(
            collision_threshold_name().to_string(),
            field(decimal_scaled("500000")),
        );
        private_satellite_conjunction_witness_with_steps(&inputs, 4)
            .expect_err("excess threshold must fail");
    }

    #[test]
    fn satellite_budget_violation_fails() {
        let mut inputs = private_satellite_conjunction_sample_inputs();
        inputs.insert(
            delta_v_budget_name().to_string(),
            field(decimal_scaled("0.001")),
        );
        private_satellite_conjunction_witness_with_steps(&inputs, 4)
            .expect_err("budget violation must fail");
    }

    #[test]
    fn satellite_tampered_running_minimum_fails() {
        run_satellite_test_on_large_stack("satellite_tampered_running_minimum_fails", || {
            let template = private_satellite_conjunction_showcase_with_steps(2).expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let inputs = sample_inputs_for_steps(2);
            let witness =
                private_satellite_conjunction_witness_with_steps(&inputs, 2).expect("witness");
            let mut prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            prepared
                .values
                .insert(run_min_name(1), field(decimal_scaled("1")));
            check_constraints(&compiled.program, &prepared)
                .expect_err("tampered running minimum must fail");
        });
    }

    #[test]
    fn satellite_state_commitment_tamper_fails() {
        run_satellite_test_on_large_stack("satellite_state_commitment_tamper_fails", || {
            let template = private_satellite_conjunction_showcase_with_steps(1).expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let inputs = sample_inputs_for_steps(1);
            let witness =
                private_satellite_conjunction_witness_with_steps(&inputs, 1).expect("witness");
            let mut prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            prepared.values.insert(
                final_state_commitment_output_name(0),
                FieldElement::from_i64(1234),
            );
            check_constraints(&compiled.program, &prepared)
                .expect_err("tampered final state commitment must fail");
        });
    }

    #[test]
    fn satellite_plan_commitment_tamper_fails() {
        run_satellite_test_on_large_stack("satellite_plan_commitment_tamper_fails", || {
            let template = private_satellite_conjunction_showcase_with_steps(1).expect("template");
            let compiled = lowered_compiled_program_for_test(&template.program);
            let inputs = sample_inputs_for_steps(1);
            let witness =
                private_satellite_conjunction_witness_with_steps(&inputs, 1).expect("witness");
            let mut prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            prepared.values.insert(
                maneuver_plan_commitment_output_name().to_string(),
                FieldElement::from_i64(5678),
            );
            check_constraints(&compiled.program, &prepared)
                .expect_err("tampered plan commitment must fail");
        });
    }
}
