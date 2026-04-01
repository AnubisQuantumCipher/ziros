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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_core::{
    BigIntFieldValue, BlackBoxOp, Expr, FieldElement, FieldId, FieldValue, Witness, WitnessInputs,
    mod_inverse_bigint,
};
use zkf_core::{ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::private_identity::poseidon_permutation4_bn254;
use super::subsystem_support;
use super::templates::TemplateProgram;

pub const PRIVATE_POWERED_DESCENT_DEFAULT_STEPS: usize = 200;
pub const PRIVATE_POWERED_DESCENT_DIMENSIONS: usize = 3;
pub const PRIVATE_POWERED_DESCENT_PRIVATE_INPUTS: usize =
    8 + (PRIVATE_POWERED_DESCENT_DEFAULT_STEPS * PRIVATE_POWERED_DESCENT_DIMENSIONS);
pub const PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS: usize = 8;
pub const PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS: usize = 5;

const AXES: [&str; PRIVATE_POWERED_DESCENT_DIMENSIONS] = ["x", "y", "z"];
const PRIVATE_POWERED_DESCENT_DESCRIPTION: &str = "Propagate a private Falcon 9-scale powered-descent trajectory over a fixed 40-second, 200-step burn window with fixed-point Euler integration, and expose Poseidon commitments to the full trajectory and final landing position plus a fail-closed constraint certificate, the final mass, and the running minimum altitude.";
const PRIVATE_POWERED_DESCENT_TEST_HELPER_DESCRIPTION: &str = "Doc-hidden arbitrary-step helper for in-repo testing and exporter regression of the private powered-descent showcase. The shipped showcase remains fixed to the 200-step surface.";
const STACK_GROW_RED_ZONE: usize = 1024 * 1024;
const STACK_GROW_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivatePoweredDescentRequestV1 {
    pub private: PrivatePoweredDescentPrivateInputsV1,
    pub public: PrivatePoweredDescentPublicInputsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivatePoweredDescentPrivateInputsV1 {
    pub initial_position: [String; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    pub initial_velocity: [String; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    pub wet_mass_at_ignition: String,
    pub thrust_profile: Vec<[String; PRIVATE_POWERED_DESCENT_DIMENSIONS]>,
    pub specific_impulse: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivatePoweredDescentPublicInputsV1 {
    pub thrust_min: String,
    pub thrust_max: String,
    pub glide_slope_tangent: String,
    pub max_landing_velocity: String,
    pub landing_zone_radius: String,
    pub landing_zone_center: [String; 2],
    pub g_z: String,
    pub step_count: usize,
}

#[derive(Debug, Clone)]
struct DescentPublicParameters {
    thrust_min: BigInt,
    thrust_max: BigInt,
    glide_slope_tangent: BigInt,
    max_landing_velocity: BigInt,
    landing_zone_radius: BigInt,
    landing_zone_center: [BigInt; 2],
    g_z: BigInt,
}

#[derive(Debug, Clone)]
struct StepComputation {
    thrust_mag_sq: BigInt,
    thrust_min_slack: BigInt,
    thrust_max_slack: BigInt,
    thrust_mag: BigInt,
    thrust_sqrt_remainder: BigInt,
    thrust_sqrt_upper_slack: BigInt,
    engine_acceleration: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    engine_acceleration_remainder: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    engine_acceleration_slack: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    velocity_delta: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    velocity_delta_remainder: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    velocity_delta_slack: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    position_delta: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    position_delta_remainder: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    position_delta_slack: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    next_position: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    next_velocity: [BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    mass_decrement: BigInt,
    mass_decrement_remainder: BigInt,
    mass_decrement_slack: BigInt,
    next_mass: BigInt,
}

#[derive(Debug, Clone)]
struct StateSafetyComputation {
    radial_sq: BigInt,
    altitude_sq: BigInt,
    glide_cone_sq: BigInt,
    glide_division_remainder: BigInt,
    glide_division_slack: BigInt,
    glide_slack: BigInt,
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

fn bn254_square(value: &BigInt) -> FieldElement {
    let value = BigIntFieldValue::new(FieldId::Bn254, value.clone());
    value.mul(&value).to_field_element()
}

fn decimal_scaled(value: &str) -> BigInt {
    subsystem_support::decimal_scaled(value, 18)
}

fn scaled_bigint_to_decimal_string(value: &BigInt) -> String {
    let negative = value.sign() == Sign::Minus;
    let abs = abs_bigint(value.clone());
    let scale = fixed_scale();
    let whole = &abs / &scale;
    let fraction = (&abs % &scale).to_str_radix(10);
    let mut fraction = format!("{fraction:0>18}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    let mut out = if fraction.is_empty() {
        whole.to_str_radix(10)
    } else {
        format!("{}.{}", whole.to_str_radix(10), fraction)
    };
    if negative && out != "0" {
        out.insert(0, '-');
    }
    out
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    subsystem_support::bits_for_bound(bound)
}

fn abs_bigint(value: BigInt) -> BigInt {
    subsystem_support::abs_bigint(&value)
}

fn bigint_isqrt_floor(value: &BigInt) -> BigInt {
    subsystem_support::bigint_isqrt_floor(value)
}

fn bigint_isqrt_ceil(value: &BigInt) -> BigInt {
    let floor = bigint_isqrt_floor(value);
    if &floor * &floor == *value {
        floor
    } else {
        floor + one()
    }
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

fn position_bound() -> BigInt {
    decimal_scaled("5000")
}

fn velocity_bound() -> BigInt {
    decimal_scaled("200")
}

fn acceleration_bound() -> BigInt {
    decimal_scaled("100")
}

fn position_delta_bound() -> BigInt {
    decimal_scaled("100")
}

fn velocity_delta_bound() -> BigInt {
    decimal_scaled("50")
}

fn mass_bound() -> BigInt {
    decimal_scaled("100000")
}

fn mass_delta_bound() -> BigInt {
    decimal_scaled("1000")
}

fn thrust_component_bound() -> BigInt {
    decimal_scaled("1000000")
}

fn thrust_magnitude_bound() -> BigInt {
    decimal_scaled("1000000")
}

fn specific_impulse_bound() -> BigInt {
    decimal_scaled("1000")
}

fn gravity_bound() -> BigInt {
    decimal_scaled("20")
}

fn glide_slope_tangent_bound() -> BigInt {
    decimal_scaled("20")
}

fn landing_zone_radius_bound() -> BigInt {
    decimal_scaled("100")
}

fn landing_zone_center_bound() -> BigInt {
    decimal_scaled("1000")
}

fn max_landing_velocity_bound() -> BigInt {
    decimal_scaled("100")
}

fn thrust_magnitude_squared_bound() -> BigInt {
    let bound = thrust_magnitude_bound();
    &bound * &bound
}

fn radial_squared_bound() -> BigInt {
    let bound = position_bound();
    BigInt::from(2u8) * &bound * &bound
}

fn glide_cone_squared_bound() -> BigInt {
    let altitude = position_bound();
    let tangent = glide_slope_tangent_bound();
    (&altitude * &altitude * &tangent * &tangent) / fixed_scale_squared()
}

fn final_speed_squared_bound() -> BigInt {
    let bound = velocity_bound();
    BigInt::from(3u8) * &bound * &bound
}

fn landing_distance_squared_bound() -> BigInt {
    let delta_bound = position_bound() + landing_zone_center_bound();
    BigInt::from(2u8) * &delta_bound * &delta_bound
}

fn exact_division_remainder_bound_for_scale() -> BigInt {
    fixed_scale()
}

fn exact_division_remainder_bound_for_scale_squared() -> BigInt {
    fixed_scale_squared()
}

fn sqrt_support_bound(sqrt_bound: &BigInt) -> BigInt {
    (sqrt_bound * BigInt::from(2u8)) + one()
}

fn dt_scaled() -> BigInt {
    decimal_scaled("0.2")
}

fn trajectory_seed_tag() -> BigInt {
    BigInt::from(91_001u64)
}

fn trajectory_step_tag(step: usize) -> BigInt {
    BigInt::from(100_000u64 + step as u64)
}

fn landing_position_tag() -> BigInt {
    BigInt::from(200_001u64)
}

fn private_input_count_for_steps(steps: usize) -> usize {
    8 + (steps * PRIVATE_POWERED_DESCENT_DIMENSIONS)
}

fn thrust_min_name() -> &'static str {
    "thrust_min"
}

fn thrust_max_name() -> &'static str {
    "thrust_max"
}

fn glide_slope_tangent_name() -> &'static str {
    "glide_slope_tangent"
}

fn max_landing_velocity_name() -> &'static str {
    "max_landing_velocity"
}

fn landing_zone_radius_name() -> &'static str {
    "landing_zone_radius"
}

fn landing_zone_center_x_name() -> &'static str {
    "landing_zone_center_x"
}

fn landing_zone_center_y_name() -> &'static str {
    "landing_zone_center_y"
}

fn gravity_name() -> &'static str {
    "g_z"
}

fn wet_mass_name() -> &'static str {
    "m0"
}

fn specific_impulse_name() -> &'static str {
    "i_sp"
}

fn initial_position_name(axis: &str) -> String {
    format!("r0_{axis}")
}

fn initial_velocity_name(axis: &str) -> String {
    format!("v0_{axis}")
}

fn thrust_name(step: usize, axis: &str) -> String {
    format!("step_{step}_thrust_{axis}")
}

fn pos_name(step: usize, axis: &str) -> String {
    if step == 0 {
        initial_position_name(axis)
    } else {
        format!("step_{step}_pos_{axis}")
    }
}

fn vel_name(step: usize, axis: &str) -> String {
    if step == 0 {
        initial_velocity_name(axis)
    } else {
        format!("step_{step}_vel_{axis}")
    }
}

fn mass_name(step: usize) -> String {
    if step == 0 {
        wet_mass_name().to_string()
    } else {
        format!("step_{step}_mass")
    }
}

fn engine_acc_name(step: usize, axis: &str) -> String {
    format!("step_{step}_engine_acc_{axis}")
}

fn engine_acc_remainder_name(step: usize, axis: &str) -> String {
    format!("step_{step}_engine_acc_remainder_{axis}")
}

fn engine_acc_slack_name(step: usize, axis: &str) -> String {
    format!("step_{step}_engine_acc_remainder_slack_{axis}")
}

fn net_acc_z_name(step: usize) -> String {
    format!("step_{step}_net_acc_z")
}

fn velocity_delta_name(step: usize, axis: &str) -> String {
    format!("step_{step}_velocity_delta_{axis}")
}

fn velocity_delta_remainder_name(step: usize, axis: &str) -> String {
    format!("step_{step}_velocity_delta_remainder_{axis}")
}

fn velocity_delta_slack_name(step: usize, axis: &str) -> String {
    format!("step_{step}_velocity_delta_remainder_slack_{axis}")
}

fn position_delta_name(step: usize, axis: &str) -> String {
    format!("step_{step}_position_delta_{axis}")
}

fn position_delta_remainder_name(step: usize, axis: &str) -> String {
    format!("step_{step}_position_delta_remainder_{axis}")
}

fn position_delta_slack_name(step: usize, axis: &str) -> String {
    format!("step_{step}_position_delta_remainder_slack_{axis}")
}

fn thrust_mag_sq_name(step: usize) -> String {
    format!("step_{step}_thrust_mag_sq")
}

fn thrust_min_slack_name(step: usize) -> String {
    format!("step_{step}_thrust_min_slack")
}

fn thrust_max_slack_name(step: usize) -> String {
    format!("step_{step}_thrust_max_slack")
}

fn thrust_mag_name(step: usize) -> String {
    format!("step_{step}_thrust_mag")
}

fn thrust_sqrt_remainder_name(step: usize) -> String {
    format!("step_{step}_thrust_sqrt_remainder")
}

fn thrust_sqrt_upper_slack_name(step: usize) -> String {
    format!("step_{step}_thrust_sqrt_upper_slack")
}

fn mass_decrement_name(step: usize) -> String {
    format!("step_{step}_mass_decrement")
}

fn mass_decrement_remainder_name(step: usize) -> String {
    format!("step_{step}_mass_decrement_remainder")
}

fn mass_decrement_slack_name(step: usize) -> String {
    format!("step_{step}_mass_decrement_remainder_slack")
}

fn radial_sq_name(step: usize) -> String {
    format!("state_{step}_radial_sq")
}

fn altitude_sq_name(step: usize) -> String {
    format!("state_{step}_altitude_sq")
}

fn glide_cone_sq_name(step: usize) -> String {
    format!("state_{step}_glide_cone_sq")
}

fn glide_division_remainder_name(step: usize) -> String {
    format!("state_{step}_glide_division_remainder")
}

fn glide_division_slack_name(step: usize) -> String {
    format!("state_{step}_glide_division_remainder_slack")
}

fn glide_slack_name(step: usize) -> String {
    format!("state_{step}_glide_slack")
}

fn running_min_name(step: usize) -> String {
    format!("state_{step}_running_min_altitude")
}

fn running_min_prev_slack_name(step: usize) -> String {
    format!("state_{step}_running_min_prev_slack")
}

fn running_min_curr_slack_name(step: usize) -> String {
    format!("state_{step}_running_min_curr_slack")
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ]
}

fn trajectory_commitment_output_name() -> &'static str {
    "trajectory_commitment"
}

fn landing_position_commitment_output_name() -> &'static str {
    "landing_position_commitment"
}

fn constraint_satisfaction_output_name() -> &'static str {
    "constraint_satisfaction"
}

fn final_mass_output_name() -> &'static str {
    "final_mass"
}

fn min_altitude_output_name() -> &'static str {
    "min_altitude"
}

fn signed_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_signed_bound_slack")
}

fn nonnegative_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_slack")
}

fn nonnegative_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_anchor")
}

fn nonzero_inverse_name(prefix: &str) -> String {
    format!("{prefix}_nonzero_inverse")
}

fn exact_division_slack_anchor_name(prefix: &str) -> String {
    format!("{prefix}_slack_anchor")
}

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: BigInt,
) {
    values.insert(name.into(), field(value));
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
            "{name} exceeded signed bound {}",
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

fn ensure_positive_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value <= zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} must satisfy 0 < value <= {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
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

fn write_nonnegative_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    signal_name: impl Into<String>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    ensure_nonnegative_le(prefix, value, bound)?;
    let signal_name = signal_name.into();
    values.insert(signal_name, field_ref(value));
    let slack = bound - value;
    let slack_field = field_ref(&slack);
    values.insert(nonnegative_bound_slack_name(prefix), slack_field.clone());
    values.insert(nonnegative_bound_anchor_name(prefix), bn254_square(&slack));
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

fn write_exact_division_slack_anchor(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    slack: &BigInt,
) {
    values.insert(
        exact_division_slack_anchor_name(prefix),
        bn254_square(slack),
    );
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

fn append_nonnegative_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = nonnegative_bound_slack_name(prefix);
    let anchor = nonnegative_bound_anchor_name(prefix);
    builder.private_signal(&slack)?;
    builder.private_signal(&anchor)?;
    builder.constrain_range(signal, bits_for_bound(bound))?;
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

#[allow(clippy::too_many_arguments)]
fn append_exact_division_constraints(
    builder: &mut ProgramBuilder,
    numerator: Expr,
    denominator: Expr,
    quotient: &str,
    remainder: &str,
    slack: &str,
    remainder_bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack_anchor = exact_division_slack_anchor_name(prefix);
    builder.private_signal(quotient)?;
    builder.private_signal(remainder)?;
    builder.private_signal(slack)?;
    builder.private_signal(&slack_anchor)?;
    builder.constrain_equal(
        numerator,
        add_expr(vec![
            mul_expr(denominator.clone(), signal_expr(quotient)),
            signal_expr(remainder),
        ]),
    )?;
    builder.constrain_equal(
        denominator,
        add_expr(vec![
            signal_expr(remainder),
            signal_expr(slack),
            const_expr(&one()),
        ]),
    )?;
    builder.constrain_range(remainder, bits_for_bound(remainder_bound))?;
    builder.constrain_range(slack, bits_for_bound(remainder_bound))?;
    builder.constrain_equal(
        signal_expr(&slack_anchor),
        mul_expr(signal_expr(slack), signal_expr(slack)),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_floor_sqrt_constraints(
    builder: &mut ProgramBuilder,
    value: Expr,
    sqrt_signal: &str,
    remainder_signal: &str,
    upper_slack_signal: &str,
    sqrt_bound: &BigInt,
    support_bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    builder.private_signal(sqrt_signal)?;
    builder.private_signal(remainder_signal)?;
    builder.private_signal(upper_slack_signal)?;
    append_nonnegative_bound(
        builder,
        sqrt_signal,
        sqrt_bound,
        &format!("{prefix}_sqrt_bound"),
    )?;
    builder.constrain_equal(
        value.clone(),
        add_expr(vec![
            mul_expr(signal_expr(sqrt_signal), signal_expr(sqrt_signal)),
            signal_expr(remainder_signal),
        ]),
    )?;
    builder.constrain_equal(
        add_expr(vec![
            value,
            signal_expr(upper_slack_signal),
            const_expr(&one()),
        ]),
        mul_expr(
            add_expr(vec![signal_expr(sqrt_signal), const_expr(&one())]),
            add_expr(vec![signal_expr(sqrt_signal), const_expr(&one())]),
        ),
    )?;
    builder.constrain_range(remainder_signal, bits_for_bound(support_bound))?;
    builder.constrain_range(upper_slack_signal, bits_for_bound(support_bound))?;
    Ok(())
}

fn parse_decimal_string(name: &str, value: &str) -> ZkfResult<BigInt> {
    if value.trim().is_empty() {
        return Err(ZkfError::Serialization(format!("{name} must not be empty")));
    }
    Ok(decimal_scaled(value))
}

fn insert_request_inputs(
    inputs: &mut WitnessInputs,
    request: &PrivatePoweredDescentRequestV1,
) -> ZkfResult<()> {
    if request.public.step_count == 0 {
        return Err(ZkfError::Serialization(
            "powered descent request step_count must be greater than zero".to_string(),
        ));
    }
    if request.private.thrust_profile.len() != request.public.step_count {
        return Err(ZkfError::Serialization(format!(
            "powered descent request step_count={} does not match thrust_profile length={}",
            request.public.step_count,
            request.private.thrust_profile.len()
        )));
    }

    inputs.insert(
        thrust_min_name().to_string(),
        field(parse_decimal_string(
            thrust_min_name(),
            &request.public.thrust_min,
        )?),
    );
    inputs.insert(
        thrust_max_name().to_string(),
        field(parse_decimal_string(
            thrust_max_name(),
            &request.public.thrust_max,
        )?),
    );
    inputs.insert(
        glide_slope_tangent_name().to_string(),
        field(parse_decimal_string(
            glide_slope_tangent_name(),
            &request.public.glide_slope_tangent,
        )?),
    );
    inputs.insert(
        max_landing_velocity_name().to_string(),
        field(parse_decimal_string(
            max_landing_velocity_name(),
            &request.public.max_landing_velocity,
        )?),
    );
    inputs.insert(
        landing_zone_radius_name().to_string(),
        field(parse_decimal_string(
            landing_zone_radius_name(),
            &request.public.landing_zone_radius,
        )?),
    );
    inputs.insert(
        landing_zone_center_x_name().to_string(),
        field(parse_decimal_string(
            landing_zone_center_x_name(),
            &request.public.landing_zone_center[0],
        )?),
    );
    inputs.insert(
        landing_zone_center_y_name().to_string(),
        field(parse_decimal_string(
            landing_zone_center_y_name(),
            &request.public.landing_zone_center[1],
        )?),
    );
    inputs.insert(
        gravity_name().to_string(),
        field(parse_decimal_string(gravity_name(), &request.public.g_z)?),
    );
    inputs.insert(
        wet_mass_name().to_string(),
        field(parse_decimal_string(
            wet_mass_name(),
            &request.private.wet_mass_at_ignition,
        )?),
    );
    inputs.insert(
        specific_impulse_name().to_string(),
        field(parse_decimal_string(
            specific_impulse_name(),
            &request.private.specific_impulse,
        )?),
    );

    for (axis_index, axis) in AXES.iter().enumerate() {
        inputs.insert(
            initial_position_name(axis),
            field(parse_decimal_string(
                &initial_position_name(axis),
                &request.private.initial_position[axis_index],
            )?),
        );
        inputs.insert(
            initial_velocity_name(axis),
            field(parse_decimal_string(
                &initial_velocity_name(axis),
                &request.private.initial_velocity[axis_index],
            )?),
        );
    }

    for (step, thrust) in request.private.thrust_profile.iter().enumerate() {
        for (axis_index, axis) in AXES.iter().enumerate() {
            let name = thrust_name(step, axis);
            inputs.insert(
                name.clone(),
                field(parse_decimal_string(&name, &thrust[axis_index])?),
            );
        }
    }
    Ok(())
}

impl TryFrom<PrivatePoweredDescentRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: PrivatePoweredDescentRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, &request)?;
        Ok(inputs)
    }
}

impl TryFrom<&PrivatePoweredDescentRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: &PrivatePoweredDescentRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, request)?;
        Ok(inputs)
    }
}

fn sample_public_parameters() -> DescentPublicParameters {
    DescentPublicParameters {
        thrust_min: decimal_scaled("300000"),
        thrust_max: decimal_scaled("845000"),
        glide_slope_tangent: decimal_scaled("8"),
        max_landing_velocity: decimal_scaled("10"),
        landing_zone_radius: decimal_scaled("15"),
        landing_zone_center: [zero(), zero()],
        g_z: decimal_scaled("9.80665"),
    }
}

fn sample_initial_altitude_for_steps(steps: usize) -> BigInt {
    let default_altitude = decimal_scaled("1500");
    let scaled = (&default_altitude * BigInt::from(steps as u64))
        / BigInt::from(PRIVATE_POWERED_DESCENT_DEFAULT_STEPS as u64);
    if scaled < decimal_scaled("7.5") {
        decimal_scaled("7.5")
    } else {
        scaled
    }
}

fn sample_initial_descent_rate_for_steps(steps: usize) -> BigInt {
    let default_rate = decimal_scaled("80");
    let scaled = (&default_rate * BigInt::from(steps as u64))
        / BigInt::from(PRIVATE_POWERED_DESCENT_DEFAULT_STEPS as u64);
    let clamped = if scaled < decimal_scaled("0.4") {
        decimal_scaled("0.4")
    } else {
        scaled
    };
    -clamped
}

fn sample_thrust_profile_for_steps(
    steps: usize,
    public: &DescentPublicParameters,
    initial_position: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    initial_velocity: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    wet_mass: &BigInt,
    specific_impulse: &BigInt,
) -> ZkfResult<Vec<[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS]>> {
    let target_altitude_candidates = [
        decimal_scaled("5"),
        decimal_scaled("8"),
        decimal_scaled("10"),
        decimal_scaled("20"),
        decimal_scaled("50"),
        decimal_scaled("100"),
        decimal_scaled("140"),
    ];
    let target_final_velocity_candidates = [
        zero(),
        decimal_scaled("2"),
        -decimal_scaled("2"),
        decimal_scaled("5"),
        -decimal_scaled("5"),
    ];
    let controller_weight_candidates = [(1u8, 0u8), (2u8, 1u8), (1u8, 1u8)];
    let lateral_pattern = [one(), -one(), -one(), one()];
    let min_sq = &public.thrust_min * &public.thrust_min;

    for target_altitude in target_altitude_candidates {
        for target_final_velocity in &target_final_velocity_candidates {
            for (pos_weight, vel_weight) in controller_weight_candidates {
                let mut position = initial_position.clone();
                let mut velocity = initial_velocity.clone();
                let mut mass = wet_mass.clone();
                let mut thrust_profile = Vec::with_capacity(steps);
                let mut min_altitude = position[2].clone();

                let mut valid = true;
                let mut step = 0usize;
                while step < steps {
                    let tau = BigInt::from((steps - step) as u64) * dt_scaled();
                    let (vertical_motion, _, _) =
                        euclidean_division(&(&velocity[2] * &tau), &fixed_scale())?;
                    let delta = target_altitude.clone() - &position[2] - vertical_motion;
                    let (a_pos, _, _) = euclidean_division(
                        &(two() * delta * fixed_scale_squared()),
                        &(&tau * &tau),
                    )?;
                    let (a_vel, _, _) = euclidean_division(
                        &((target_final_velocity - &velocity[2]) * fixed_scale()),
                        &tau,
                    )?;
                    let net_vertical_acc = if vel_weight == 0 {
                        a_pos
                    } else {
                        let numerator =
                            (a_pos * BigInt::from(pos_weight)) + (a_vel * BigInt::from(vel_weight));
                        numerator / BigInt::from(pos_weight + vel_weight)
                    };
                    let desired_engine_acc_z = &net_vertical_acc + &public.g_z;
                    let (mut thrust_z, _, _) =
                        euclidean_division(&(&mass * &desired_engine_acc_z), &fixed_scale())?;
                    if thrust_z < zero() {
                        thrust_z = zero();
                    }
                    if thrust_z > public.thrust_max {
                        valid = false;
                        break;
                    }

                    let thrust_z_sq = &thrust_z * &thrust_z;
                    let lateral_mag = if thrust_z_sq < min_sq {
                        bigint_isqrt_ceil(&(min_sq.clone() - thrust_z_sq))
                    } else {
                        zero()
                    };
                    let block_len = (steps - step).min(lateral_pattern.len());
                    for direction in lateral_pattern.iter().take(block_len) {
                        let signed_lateral = direction * &lateral_mag;
                        let thrust = [signed_lateral, zero(), thrust_z.clone()];
                        let step_result = match compute_step_dynamics(
                            &position,
                            &velocity,
                            &mass,
                            &thrust,
                            specific_impulse,
                            public,
                        ) {
                            Ok(step_result) => step_result,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        };
                        position = step_result.next_position.clone();
                        velocity = step_result.next_velocity.clone();
                        mass = step_result.next_mass.clone();
                        if position[2] < min_altitude {
                            min_altitude = position[2].clone();
                        }
                        if compute_state_safety(&position, public).is_err() {
                            valid = false;
                            break;
                        }
                        thrust_profile.push(thrust);
                    }
                    if !valid {
                        break;
                    }
                    step += block_len;
                }

                if !valid {
                    continue;
                }
                if thrust_profile.len() != steps {
                    continue;
                }

                if min_altitude < zero() {
                    continue;
                }
                let final_speed_sq = velocity
                    .iter()
                    .fold(zero(), |acc, value| acc + (value * value));
                let max_speed_sq = &public.max_landing_velocity * &public.max_landing_velocity;
                if final_speed_sq > max_speed_sq {
                    continue;
                }
                let landing_dx = &position[0] - &public.landing_zone_center[0];
                let landing_dy = &position[1] - &public.landing_zone_center[1];
                let landing_distance_sq = (&landing_dx * &landing_dx) + (&landing_dy * &landing_dy);
                let landing_radius_sq = &public.landing_zone_radius * &public.landing_zone_radius;
                if landing_distance_sq > landing_radius_sq {
                    continue;
                }
                if compute_state_safety(&position, public).is_err() {
                    continue;
                }
                return Ok(thrust_profile);
            }
        }
    }

    Err(ZkfError::InvalidArtifact(
        "failed to synthesize a valid powered descent sample profile".to_string(),
    ))
}

#[allow(clippy::expect_used)]
fn private_powered_descent_sample_inputs_for_steps(steps: usize) -> WitnessInputs {
    let public = sample_public_parameters();
    let initial_position = [zero(), zero(), sample_initial_altitude_for_steps(steps)];
    let initial_velocity = [zero(), zero(), sample_initial_descent_rate_for_steps(steps)];
    let wet_mass = decimal_scaled("25000");
    let specific_impulse = decimal_scaled("282");
    let thrust_profile = sample_thrust_profile_for_steps(
        steps,
        &public,
        &initial_position,
        &initial_velocity,
        &wet_mass,
        &specific_impulse,
    )
    .expect("sample powered descent profile");

    let mut inputs = WitnessInputs::new();
    inputs.insert(thrust_min_name().to_string(), field_ref(&public.thrust_min));
    inputs.insert(thrust_max_name().to_string(), field_ref(&public.thrust_max));
    inputs.insert(
        glide_slope_tangent_name().to_string(),
        field_ref(&public.glide_slope_tangent),
    );
    inputs.insert(
        max_landing_velocity_name().to_string(),
        field_ref(&public.max_landing_velocity),
    );
    inputs.insert(
        landing_zone_radius_name().to_string(),
        field_ref(&public.landing_zone_radius),
    );
    inputs.insert(
        landing_zone_center_x_name().to_string(),
        field_ref(&public.landing_zone_center[0]),
    );
    inputs.insert(
        landing_zone_center_y_name().to_string(),
        field_ref(&public.landing_zone_center[1]),
    );
    inputs.insert(gravity_name().to_string(), field_ref(&public.g_z));
    inputs.insert(wet_mass_name().to_string(), field_ref(&wet_mass));
    inputs.insert(
        specific_impulse_name().to_string(),
        field_ref(&specific_impulse),
    );
    for (axis_index, axis) in AXES.iter().enumerate() {
        inputs.insert(
            initial_position_name(axis),
            field_ref(&initial_position[axis_index]),
        );
        inputs.insert(
            initial_velocity_name(axis),
            field_ref(&initial_velocity[axis_index]),
        );
    }
    for (step, thrust) in thrust_profile.iter().enumerate() {
        for (axis_index, axis) in AXES.iter().enumerate() {
            inputs.insert(thrust_name(step, axis), field_ref(&thrust[axis_index]));
        }
    }
    inputs
}

#[doc(hidden)]
pub fn private_powered_descent_sample_request_with_steps(
    steps: usize,
) -> ZkfResult<PrivatePoweredDescentRequestV1> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private powered descent sample request requires at least one integration step"
                .to_string(),
        ));
    }
    let public = sample_public_parameters();
    let initial_position = [zero(), zero(), sample_initial_altitude_for_steps(steps)];
    let initial_velocity = [zero(), zero(), sample_initial_descent_rate_for_steps(steps)];
    let wet_mass = decimal_scaled("25000");
    let specific_impulse = decimal_scaled("282");
    let thrust_profile = sample_thrust_profile_for_steps(
        steps,
        &public,
        &initial_position,
        &initial_velocity,
        &wet_mass,
        &specific_impulse,
    )?;
    Ok(PrivatePoweredDescentRequestV1 {
        private: PrivatePoweredDescentPrivateInputsV1 {
            initial_position: initial_position.map(|value| scaled_bigint_to_decimal_string(&value)),
            initial_velocity: initial_velocity.map(|value| scaled_bigint_to_decimal_string(&value)),
            wet_mass_at_ignition: scaled_bigint_to_decimal_string(&wet_mass),
            thrust_profile: thrust_profile
                .into_iter()
                .map(|vector| vector.map(|value| scaled_bigint_to_decimal_string(&value)))
                .collect(),
            specific_impulse: scaled_bigint_to_decimal_string(&specific_impulse),
        },
        public: PrivatePoweredDescentPublicInputsV1 {
            thrust_min: scaled_bigint_to_decimal_string(&public.thrust_min),
            thrust_max: scaled_bigint_to_decimal_string(&public.thrust_max),
            glide_slope_tangent: scaled_bigint_to_decimal_string(&public.glide_slope_tangent),
            max_landing_velocity: scaled_bigint_to_decimal_string(&public.max_landing_velocity),
            landing_zone_radius: scaled_bigint_to_decimal_string(&public.landing_zone_radius),
            landing_zone_center: public
                .landing_zone_center
                .map(|value| scaled_bigint_to_decimal_string(&value)),
            g_z: scaled_bigint_to_decimal_string(&public.g_z),
            step_count: steps,
        },
    })
}

fn load_public_parameters(inputs: &WitnessInputs) -> ZkfResult<DescentPublicParameters> {
    let parameters = DescentPublicParameters {
        thrust_min: read_input(inputs, thrust_min_name())?,
        thrust_max: read_input(inputs, thrust_max_name())?,
        glide_slope_tangent: read_input(inputs, glide_slope_tangent_name())?,
        max_landing_velocity: read_input(inputs, max_landing_velocity_name())?,
        landing_zone_radius: read_input(inputs, landing_zone_radius_name())?,
        landing_zone_center: [
            read_input(inputs, landing_zone_center_x_name())?,
            read_input(inputs, landing_zone_center_y_name())?,
        ],
        g_z: read_input(inputs, gravity_name())?,
    };
    ensure_positive_le(
        thrust_min_name(),
        &parameters.thrust_min,
        &thrust_magnitude_bound(),
    )?;
    ensure_positive_le(
        thrust_max_name(),
        &parameters.thrust_max,
        &thrust_magnitude_bound(),
    )?;
    if parameters.thrust_max < parameters.thrust_min {
        return Err(ZkfError::InvalidArtifact(
            "thrust_max must be greater than or equal to thrust_min".to_string(),
        ));
    }
    ensure_positive_le(
        glide_slope_tangent_name(),
        &parameters.glide_slope_tangent,
        &glide_slope_tangent_bound(),
    )?;
    ensure_positive_le(
        max_landing_velocity_name(),
        &parameters.max_landing_velocity,
        &max_landing_velocity_bound(),
    )?;
    ensure_positive_le(
        landing_zone_radius_name(),
        &parameters.landing_zone_radius,
        &landing_zone_radius_bound(),
    )?;
    ensure_abs_le(
        landing_zone_center_x_name(),
        &parameters.landing_zone_center[0],
        &landing_zone_center_bound(),
    )?;
    ensure_abs_le(
        landing_zone_center_y_name(),
        &parameters.landing_zone_center[1],
        &landing_zone_center_bound(),
    )?;
    ensure_positive_le(gravity_name(), &parameters.g_z, &gravity_bound())?;
    Ok(parameters)
}

fn write_public_parameter_support(
    values: &mut BTreeMap<String, FieldElement>,
    parameters: &DescentPublicParameters,
) -> ZkfResult<()> {
    write_nonnegative_bound_support(
        values,
        thrust_min_name(),
        &parameters.thrust_min,
        &thrust_magnitude_bound(),
        "thrust_min_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        thrust_max_name(),
        &parameters.thrust_max,
        &thrust_magnitude_bound(),
        "thrust_max_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        glide_slope_tangent_name(),
        &parameters.glide_slope_tangent,
        &glide_slope_tangent_bound(),
        "glide_slope_tangent_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        max_landing_velocity_name(),
        &parameters.max_landing_velocity,
        &max_landing_velocity_bound(),
        "max_landing_velocity_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        landing_zone_radius_name(),
        &parameters.landing_zone_radius,
        &landing_zone_radius_bound(),
        "landing_zone_radius_bound",
    )?;
    write_value(
        values,
        landing_zone_center_x_name(),
        parameters.landing_zone_center[0].clone(),
    );
    write_value(
        values,
        landing_zone_center_y_name(),
        parameters.landing_zone_center[1].clone(),
    );
    write_signed_bound_support(
        values,
        &parameters.landing_zone_center[0],
        &landing_zone_center_bound(),
        "landing_zone_center_x_bound",
    )?;
    write_signed_bound_support(
        values,
        &parameters.landing_zone_center[1],
        &landing_zone_center_bound(),
        "landing_zone_center_y_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        gravity_name(),
        &parameters.g_z,
        &gravity_bound(),
        "gravity_bound",
    )?;
    write_nonzero_inverse_support(values, &parameters.g_z, "gravity_nonzero")?;
    write_value(
        values,
        "thrust_order_slack",
        &parameters.thrust_max - &parameters.thrust_min,
    );
    write_nonzero_inverse_support(values, &parameters.thrust_min, "thrust_min_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.thrust_max, "thrust_max_nonzero")?;
    write_nonzero_inverse_support(
        values,
        &parameters.glide_slope_tangent,
        "glide_slope_tangent_nonzero",
    )?;
    write_nonzero_inverse_support(
        values,
        &parameters.max_landing_velocity,
        "max_landing_velocity_nonzero",
    )?;
    write_nonzero_inverse_support(
        values,
        &parameters.landing_zone_radius,
        "landing_zone_radius_nonzero",
    )?;
    Ok(())
}

fn euclidean_division(
    numerator: &BigInt,
    denominator: &BigInt,
) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    subsystem_support::euclidean_division(numerator, denominator)
}

fn floor_sqrt_support(value: &BigInt) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    subsystem_support::floor_sqrt_support(value)
}

fn compute_state_safety(
    position: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    parameters: &DescentPublicParameters,
) -> ZkfResult<StateSafetyComputation> {
    ensure_abs_le("state_pos_x", &position[0], &position_bound())?;
    ensure_abs_le("state_pos_y", &position[1], &position_bound())?;
    ensure_nonnegative_le("state_pos_z", &position[2], &position_bound())?;

    let radial_sq = (&position[0] * &position[0]) + (&position[1] * &position[1]);
    let altitude_sq = &position[2] * &position[2];
    ensure_nonnegative_le("state_radial_sq", &radial_sq, &radial_squared_bound())?;
    let glide_numerator =
        altitude_sq.clone() * &parameters.glide_slope_tangent * &parameters.glide_slope_tangent;
    let (glide_cone_sq, glide_division_remainder, glide_division_slack) =
        euclidean_division(&glide_numerator, &fixed_scale_squared())?;
    ensure_nonnegative_le(
        "state_glide_cone_sq",
        &glide_cone_sq,
        &glide_cone_squared_bound(),
    )?;
    if glide_cone_sq < radial_sq {
        return Err(ZkfError::InvalidArtifact(
            "glide-slope constraint violated".to_string(),
        ));
    }
    Ok(StateSafetyComputation {
        radial_sq: radial_sq.clone(),
        altitude_sq,
        glide_cone_sq: glide_cone_sq.clone(),
        glide_division_remainder,
        glide_division_slack,
        glide_slack: glide_cone_sq - radial_sq,
    })
}

fn compute_step_dynamics(
    position: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    velocity: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    mass: &BigInt,
    thrust: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    specific_impulse: &BigInt,
    parameters: &DescentPublicParameters,
) -> ZkfResult<StepComputation> {
    ensure_positive_le("current_mass", mass, &mass_bound())?;
    ensure_positive_le(
        specific_impulse_name(),
        specific_impulse,
        &specific_impulse_bound(),
    )?;
    ensure_positive_le(gravity_name(), &parameters.g_z, &gravity_bound())?;
    for (axis_index, axis) in AXES.iter().enumerate() {
        ensure_abs_le(
            &format!("thrust_{axis}"),
            &thrust[axis_index],
            &thrust_component_bound(),
        )?;
    }

    let thrust_mag_sq = thrust
        .iter()
        .fold(zero(), |acc, value| acc + (value * value));
    let min_thrust_sq = &parameters.thrust_min * &parameters.thrust_min;
    let max_thrust_sq = &parameters.thrust_max * &parameters.thrust_max;
    if thrust_mag_sq < min_thrust_sq || thrust_mag_sq > max_thrust_sq {
        return Err(ZkfError::InvalidArtifact(
            "thrust magnitude violated the public throttle bounds".to_string(),
        ));
    }
    let (thrust_mag, thrust_sqrt_remainder, thrust_sqrt_upper_slack) =
        floor_sqrt_support(&thrust_mag_sq)?;
    let mut engine_acceleration = std::array::from_fn(|_| zero());
    let mut engine_acceleration_remainder = std::array::from_fn(|_| zero());
    let mut engine_acceleration_slack = std::array::from_fn(|_| zero());
    let mut velocity_delta = std::array::from_fn(|_| zero());
    let mut velocity_delta_remainder = std::array::from_fn(|_| zero());
    let mut velocity_delta_slack = std::array::from_fn(|_| zero());
    let mut position_delta = std::array::from_fn(|_| zero());
    let mut position_delta_remainder = std::array::from_fn(|_| zero());
    let mut position_delta_slack = std::array::from_fn(|_| zero());
    let mut next_position = std::array::from_fn(|_| zero());
    let mut next_velocity = std::array::from_fn(|_| zero());

    for axis_index in 0..PRIVATE_POWERED_DESCENT_DIMENSIONS {
        let (engine_acc, engine_rem, engine_slack) =
            euclidean_division(&(&thrust[axis_index] * fixed_scale()), mass)?;
        ensure_abs_le("engine_acceleration", &engine_acc, &acceleration_bound())?;
        ensure_nonnegative_le("engine_acceleration_remainder", &engine_rem, &mass_bound())?;
        ensure_nonnegative_le(
            "engine_acceleration_remainder_slack",
            &engine_slack,
            &mass_bound(),
        )?;
        engine_acceleration[axis_index] = engine_acc.clone();
        engine_acceleration_remainder[axis_index] = engine_rem;
        engine_acceleration_slack[axis_index] = engine_slack;

        let effective_acceleration = if axis_index == 2 {
            &engine_acc - &parameters.g_z
        } else {
            engine_acc
        };
        let (dv, dv_rem, dv_slack) =
            euclidean_division(&(&effective_acceleration * dt_scaled()), &fixed_scale())?;
        ensure_abs_le("velocity_delta", &dv, &velocity_delta_bound())?;
        ensure_nonnegative_le(
            "velocity_delta_remainder",
            &dv_rem,
            &exact_division_remainder_bound_for_scale(),
        )?;
        ensure_nonnegative_le(
            "velocity_delta_remainder_slack",
            &dv_slack,
            &exact_division_remainder_bound_for_scale(),
        )?;
        let next_v = &velocity[axis_index] + &dv;
        ensure_abs_le("next_velocity", &next_v, &velocity_bound())?;
        velocity_delta[axis_index] = dv;
        velocity_delta_remainder[axis_index] = dv_rem;
        velocity_delta_slack[axis_index] = dv_slack;
        next_velocity[axis_index] = next_v;

        let (dr, dr_rem, dr_slack) =
            euclidean_division(&(&velocity[axis_index] * dt_scaled()), &fixed_scale())?;
        ensure_abs_le("position_delta", &dr, &position_delta_bound())?;
        ensure_nonnegative_le(
            "position_delta_remainder",
            &dr_rem,
            &exact_division_remainder_bound_for_scale(),
        )?;
        ensure_nonnegative_le(
            "position_delta_remainder_slack",
            &dr_slack,
            &exact_division_remainder_bound_for_scale(),
        )?;
        let next_r = &position[axis_index] + &dr;
        if axis_index == 2 {
            ensure_nonnegative_le("next_altitude", &next_r, &position_bound())?;
        } else {
            ensure_abs_le("next_position", &next_r, &position_bound())?;
        }
        position_delta[axis_index] = dr;
        position_delta_remainder[axis_index] = dr_rem;
        position_delta_slack[axis_index] = dr_slack;
        next_position[axis_index] = next_r;
    }

    let denominator = specific_impulse * &parameters.g_z;
    let (mass_decrement, mass_decrement_remainder, mass_decrement_slack) =
        euclidean_division(&(&thrust_mag * dt_scaled() * fixed_scale()), &denominator)?;
    ensure_nonnegative_le("mass_decrement", &mass_decrement, &mass_delta_bound())?;
    ensure_nonnegative_le(
        "mass_decrement_remainder",
        &mass_decrement_remainder,
        &(specific_impulse_bound() * gravity_bound()),
    )?;
    ensure_nonnegative_le(
        "mass_decrement_remainder_slack",
        &mass_decrement_slack,
        &(specific_impulse_bound() * gravity_bound()),
    )?;
    let next_mass = mass - &mass_decrement;
    ensure_positive_le("next_mass", &next_mass, &mass_bound())?;

    Ok(StepComputation {
        thrust_min_slack: &thrust_mag_sq - &min_thrust_sq,
        thrust_max_slack: &max_thrust_sq - &thrust_mag_sq,
        thrust_mag_sq,
        thrust_mag,
        thrust_sqrt_remainder,
        thrust_sqrt_upper_slack,
        engine_acceleration,
        engine_acceleration_remainder,
        engine_acceleration_slack,
        velocity_delta,
        velocity_delta_remainder,
        velocity_delta_slack,
        position_delta,
        position_delta_remainder,
        position_delta_slack,
        next_position,
        next_velocity,
        mass_decrement,
        mass_decrement_remainder,
        mass_decrement_slack,
        next_mass,
    })
}

fn append_state_constraints(builder: &mut ProgramBuilder, step: usize) -> ZkfResult<()> {
    append_nonnegative_bound(
        builder,
        &pos_name(step, "z"),
        &position_bound(),
        &format!("state_{step}_altitude_bound"),
    )?;
    append_nonnegative_bound(
        builder,
        &mass_name(step),
        &mass_bound(),
        &format!("state_{step}_mass_bound"),
    )?;
    append_nonzero_constraint(builder, &mass_name(step), &format!("state_{step}_mass"))?;

    let radial_sq = radial_sq_name(step);
    let altitude_sq = altitude_sq_name(step);
    let glide_cone_sq = glide_cone_sq_name(step);
    let glide_division_remainder = glide_division_remainder_name(step);
    let glide_division_slack = glide_division_slack_name(step);
    let glide_slack = glide_slack_name(step);

    builder.private_signal(&radial_sq)?;
    builder.private_signal(&altitude_sq)?;
    builder.private_signal(&glide_slack)?;
    builder.constrain_equal(
        signal_expr(&radial_sq),
        add_expr(vec![
            mul_expr(
                signal_expr(&pos_name(step, "x")),
                signal_expr(&pos_name(step, "x")),
            ),
            mul_expr(
                signal_expr(&pos_name(step, "y")),
                signal_expr(&pos_name(step, "y")),
            ),
        ]),
    )?;
    builder.constrain_equal(
        signal_expr(&altitude_sq),
        mul_expr(
            signal_expr(&pos_name(step, "z")),
            signal_expr(&pos_name(step, "z")),
        ),
    )?;
    append_nonnegative_bound(
        builder,
        &radial_sq,
        &radial_squared_bound(),
        &format!("state_{step}_radial_sq_bound"),
    )?;
    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&altitude_sq),
            mul_expr(
                signal_expr(glide_slope_tangent_name()),
                signal_expr(glide_slope_tangent_name()),
            ),
        ),
        const_expr(&fixed_scale_squared()),
        &glide_cone_sq,
        &glide_division_remainder,
        &glide_division_slack,
        &exact_division_remainder_bound_for_scale_squared(),
        &format!("state_{step}_glide_division"),
    )?;
    append_nonnegative_bound(
        builder,
        &glide_cone_sq,
        &glide_cone_squared_bound(),
        &format!("state_{step}_glide_cone_sq_bound"),
    )?;
    builder.constrain_equal(
        signal_expr(&glide_cone_sq),
        add_expr(vec![signal_expr(&radial_sq), signal_expr(&glide_slack)]),
    )?;
    builder.constrain_range(&glide_slack, bits_for_bound(&glide_cone_squared_bound()))?;
    Ok(())
}

fn append_running_min_constraints(builder: &mut ProgramBuilder, steps: usize) -> ZkfResult<()> {
    let run_min_0 = running_min_name(0);
    builder.private_signal(&run_min_0)?;
    builder.constrain_equal(signal_expr(&run_min_0), signal_expr(&pos_name(0, "z")))?;
    append_nonnegative_bound(
        builder,
        &run_min_0,
        &position_bound(),
        "state_0_running_min_bound",
    )?;

    for step in 1..=steps {
        let current = running_min_name(step);
        let previous = running_min_name(step - 1);
        let prev_slack = running_min_prev_slack_name(step);
        let curr_slack = running_min_curr_slack_name(step);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_bound(
            builder,
            &current,
            &position_bound(),
            &format!("state_{step}_running_min_bound"),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&prev_slack)]),
            signal_expr(&previous),
        )?;
        builder.constrain_equal(
            add_expr(vec![signal_expr(&current), signal_expr(&curr_slack)]),
            signal_expr(&pos_name(step, "z")),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&position_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&position_bound()))?;
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(min_altitude_output_name())?;
    builder.constrain_equal(
        signal_expr(min_altitude_output_name()),
        signal_expr(&running_min_name(steps)),
    )?;
    append_nonnegative_bound(
        builder,
        min_altitude_output_name(),
        &position_bound(),
        "min_altitude_public_bound",
    )?;
    Ok(())
}

fn private_powered_descent_showcase_inner(steps: usize) -> ZkfResult<TemplateProgram> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private powered descent showcase requires at least one integration step".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("private_powered_descent_showcase_{steps}_step"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "private-powered-descent-showcase")?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "euler")?;
    builder.metadata_entry("time_step_seconds", "0.2")?;
    builder.metadata_entry("fixed_point_scale", fixed_scale().to_str_radix(10))?;
    builder.metadata_entry(
        "safe_certificate_semantics",
        "constraint_satisfaction is fixed to 1 for accepted descents; invalid descents fail closed during witness generation",
    )?;
    builder.metadata_entry("position_bound_scaled", position_bound().to_str_radix(10))?;
    builder.metadata_entry("velocity_bound_scaled", velocity_bound().to_str_radix(10))?;
    builder.metadata_entry("mass_bound_scaled", mass_bound().to_str_radix(10))?;
    builder.metadata_entry(
        "thrust_component_bound_scaled",
        thrust_component_bound().to_str_radix(10),
    )?;
    builder.metadata_entry(
        "acceleration_bound_scaled",
        acceleration_bound().to_str_radix(10),
    )?;
    builder.metadata_entry(
        "stack_grow_strategy",
        "stacker::maybe_grow used for template build and witness generation",
    )?;

    let mut expected_inputs = Vec::with_capacity(
        PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS + private_input_count_for_steps(steps),
    );
    let public_outputs = vec![
        trajectory_commitment_output_name().to_string(),
        landing_position_commitment_output_name().to_string(),
        constraint_satisfaction_output_name().to_string(),
        final_mass_output_name().to_string(),
        min_altitude_output_name().to_string(),
    ];

    for public_name in [
        thrust_min_name(),
        thrust_max_name(),
        glide_slope_tangent_name(),
        max_landing_velocity_name(),
        landing_zone_radius_name(),
        landing_zone_center_x_name(),
        landing_zone_center_y_name(),
        gravity_name(),
    ] {
        builder.public_input(public_name)?;
        expected_inputs.push(public_name.to_string());
    }

    append_nonnegative_bound(
        &mut builder,
        thrust_min_name(),
        &thrust_magnitude_bound(),
        "thrust_min_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        thrust_max_name(),
        &thrust_magnitude_bound(),
        "thrust_max_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        glide_slope_tangent_name(),
        &glide_slope_tangent_bound(),
        "glide_slope_tangent_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        max_landing_velocity_name(),
        &max_landing_velocity_bound(),
        "max_landing_velocity_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        landing_zone_radius_name(),
        &landing_zone_radius_bound(),
        "landing_zone_radius_bound",
    )?;
    append_signed_bound(
        &mut builder,
        landing_zone_center_x_name(),
        &landing_zone_center_bound(),
        "landing_zone_center_x_bound",
    )?;
    append_signed_bound(
        &mut builder,
        landing_zone_center_y_name(),
        &landing_zone_center_bound(),
        "landing_zone_center_y_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        gravity_name(),
        &gravity_bound(),
        "gravity_bound",
    )?;
    append_nonzero_constraint(&mut builder, gravity_name(), "gravity_nonzero")?;
    append_nonzero_constraint(&mut builder, thrust_min_name(), "thrust_min_nonzero")?;
    append_nonzero_constraint(&mut builder, thrust_max_name(), "thrust_max_nonzero")?;
    append_nonzero_constraint(
        &mut builder,
        glide_slope_tangent_name(),
        "glide_slope_tangent_nonzero",
    )?;
    append_nonzero_constraint(
        &mut builder,
        max_landing_velocity_name(),
        "max_landing_velocity_nonzero",
    )?;
    append_nonzero_constraint(
        &mut builder,
        landing_zone_radius_name(),
        "landing_zone_radius_nonzero",
    )?;
    builder.private_signal("thrust_order_slack")?;
    builder.constrain_equal(
        signal_expr(thrust_max_name()),
        add_expr(vec![
            signal_expr(thrust_min_name()),
            signal_expr("thrust_order_slack"),
        ]),
    )?;
    builder.constrain_range(
        "thrust_order_slack",
        bits_for_bound(&thrust_magnitude_bound()),
    )?;

    builder.private_input(wet_mass_name())?;
    builder.private_input(specific_impulse_name())?;
    expected_inputs.push(wet_mass_name().to_string());
    expected_inputs.push(specific_impulse_name().to_string());
    append_nonnegative_bound(
        &mut builder,
        specific_impulse_name(),
        &specific_impulse_bound(),
        "specific_impulse_bound",
    )?;
    append_nonzero_constraint(
        &mut builder,
        specific_impulse_name(),
        "specific_impulse_nonzero",
    )?;

    for axis in AXES {
        let position = initial_position_name(axis);
        let velocity = initial_velocity_name(axis);
        builder.private_input(&position)?;
        builder.private_input(&velocity)?;
        expected_inputs.push(position.clone());
        expected_inputs.push(velocity.clone());
        if axis != "z" {
            append_signed_bound(
                &mut builder,
                &position,
                &position_bound(),
                &format!("initial_position_bound_{axis}"),
            )?;
        }
        append_signed_bound(
            &mut builder,
            &velocity,
            &velocity_bound(),
            &format!("initial_velocity_bound_{axis}"),
        )?;
    }

    for step in 0..steps {
        for axis in AXES {
            let thrust = thrust_name(step, axis);
            builder.private_input(&thrust)?;
            expected_inputs.push(thrust.clone());
            append_signed_bound(
                &mut builder,
                &thrust,
                &thrust_component_bound(),
                &format!("step_{step}_thrust_bound_{axis}"),
            )?;
        }
    }

    for step in 0..steps {
        let thrust_mag_sq = thrust_mag_sq_name(step);
        let thrust_min_slack = thrust_min_slack_name(step);
        let thrust_max_slack = thrust_max_slack_name(step);
        let thrust_mag = thrust_mag_name(step);
        let thrust_sqrt_remainder = thrust_sqrt_remainder_name(step);
        let thrust_sqrt_upper_slack = thrust_sqrt_upper_slack_name(step);
        builder.private_signal(&thrust_mag_sq)?;
        builder.private_signal(&thrust_min_slack)?;
        builder.private_signal(&thrust_max_slack)?;
        builder.constrain_equal(
            signal_expr(&thrust_mag_sq),
            add_expr(
                AXES.iter()
                    .map(|axis| {
                        mul_expr(
                            signal_expr(&thrust_name(step, axis)),
                            signal_expr(&thrust_name(step, axis)),
                        )
                    })
                    .collect(),
            ),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &thrust_mag_sq,
            &thrust_magnitude_squared_bound(),
            &format!("step_{step}_thrust_mag_sq_bound"),
        )?;
        builder.constrain_equal(
            signal_expr(&thrust_mag_sq),
            add_expr(vec![
                mul_expr(
                    signal_expr(thrust_min_name()),
                    signal_expr(thrust_min_name()),
                ),
                signal_expr(&thrust_min_slack),
            ]),
        )?;
        builder.constrain_equal(
            mul_expr(
                signal_expr(thrust_max_name()),
                signal_expr(thrust_max_name()),
            ),
            add_expr(vec![
                signal_expr(&thrust_mag_sq),
                signal_expr(&thrust_max_slack),
            ]),
        )?;
        builder.constrain_range(
            &thrust_min_slack,
            bits_for_bound(&thrust_magnitude_squared_bound()),
        )?;
        builder.constrain_range(
            &thrust_max_slack,
            bits_for_bound(&thrust_magnitude_squared_bound()),
        )?;
        append_floor_sqrt_constraints(
            &mut builder,
            signal_expr(&thrust_mag_sq),
            &thrust_mag,
            &thrust_sqrt_remainder,
            &thrust_sqrt_upper_slack,
            &thrust_magnitude_bound(),
            &sqrt_support_bound(&thrust_magnitude_bound()),
            &format!("step_{step}_thrust_sqrt"),
        )?;

        for axis in AXES {
            append_exact_division_constraints(
                &mut builder,
                mul_expr(
                    signal_expr(&thrust_name(step, axis)),
                    const_expr(&fixed_scale()),
                ),
                signal_expr(&mass_name(step)),
                &engine_acc_name(step, axis),
                &engine_acc_remainder_name(step, axis),
                &engine_acc_slack_name(step, axis),
                &mass_bound(),
                &format!("step_{step}_engine_acc_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &engine_acc_name(step, axis),
                &acceleration_bound(),
                &format!("step_{step}_engine_acc_{axis}"),
            )?;
            if axis == "z" {
                builder.private_signal(net_acc_z_name(step))?;
                builder.constrain_equal(
                    signal_expr(&net_acc_z_name(step)),
                    sub_expr(
                        signal_expr(&engine_acc_name(step, axis)),
                        signal_expr(gravity_name()),
                    ),
                )?;
                append_signed_bound(
                    &mut builder,
                    &net_acc_z_name(step),
                    &acceleration_bound(),
                    &format!("step_{step}_net_acc_z_bound"),
                )?;
            }
            append_exact_division_constraints(
                &mut builder,
                mul_expr(
                    if axis == "z" {
                        signal_expr(&net_acc_z_name(step))
                    } else {
                        signal_expr(&engine_acc_name(step, axis))
                    },
                    const_expr(&dt_scaled()),
                ),
                const_expr(&fixed_scale()),
                &velocity_delta_name(step, axis),
                &velocity_delta_remainder_name(step, axis),
                &velocity_delta_slack_name(step, axis),
                &exact_division_remainder_bound_for_scale(),
                &format!("step_{step}_velocity_delta_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &velocity_delta_name(step, axis),
                &velocity_delta_bound(),
                &format!("step_{step}_velocity_delta_{axis}"),
            )?;
            append_exact_division_constraints(
                &mut builder,
                mul_expr(signal_expr(&vel_name(step, axis)), const_expr(&dt_scaled())),
                const_expr(&fixed_scale()),
                &position_delta_name(step, axis),
                &position_delta_remainder_name(step, axis),
                &position_delta_slack_name(step, axis),
                &exact_division_remainder_bound_for_scale(),
                &format!("step_{step}_position_delta_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &position_delta_name(step, axis),
                &position_delta_bound(),
                &format!("step_{step}_position_delta_{axis}"),
            )?;

            let next_position = pos_name(step + 1, axis);
            let next_velocity = vel_name(step + 1, axis);
            builder.private_signal(&next_position)?;
            builder.private_signal(&next_velocity)?;
            builder.constrain_equal(
                signal_expr(&next_velocity),
                add_expr(vec![
                    signal_expr(&vel_name(step, axis)),
                    signal_expr(&velocity_delta_name(step, axis)),
                ]),
            )?;
            builder.constrain_equal(
                signal_expr(&next_position),
                add_expr(vec![
                    signal_expr(&pos_name(step, axis)),
                    signal_expr(&position_delta_name(step, axis)),
                ]),
            )?;
            if axis != "z" {
                append_signed_bound(
                    &mut builder,
                    &next_position,
                    &position_bound(),
                    &format!("state_{}_position_bound_{axis}", step + 1),
                )?;
            }
            append_signed_bound(
                &mut builder,
                &next_velocity,
                &velocity_bound(),
                &format!("state_{}_velocity_bound_{axis}", step + 1),
            )?;
        }

        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                mul_expr(signal_expr(&thrust_mag), const_expr(&dt_scaled())),
                const_expr(&fixed_scale()),
            ),
            mul_expr(
                signal_expr(specific_impulse_name()),
                signal_expr(gravity_name()),
            ),
            &mass_decrement_name(step),
            &mass_decrement_remainder_name(step),
            &mass_decrement_slack_name(step),
            &(specific_impulse_bound() * gravity_bound()),
            &format!("step_{step}_mass_decrement"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &mass_decrement_name(step),
            &mass_delta_bound(),
            &format!("step_{step}_mass_decrement_bound"),
        )?;
        let next_mass = mass_name(step + 1);
        builder.private_signal(&next_mass)?;
        builder.constrain_equal(
            signal_expr(&next_mass),
            sub_expr(
                signal_expr(&mass_name(step)),
                signal_expr(&mass_decrement_name(step)),
            ),
        )?;
    }

    for step in 0..=steps {
        append_state_constraints(&mut builder, step)?;
    }

    append_running_min_constraints(&mut builder, steps)?;

    let final_speed_sq = "final_speed_sq";
    let terminal_velocity_slack = "terminal_velocity_slack";
    builder.private_signal(final_speed_sq)?;
    builder.private_signal(terminal_velocity_slack)?;
    builder.constrain_equal(
        signal_expr(final_speed_sq),
        add_expr(
            AXES.iter()
                .map(|axis| {
                    mul_expr(
                        signal_expr(&vel_name(steps, axis)),
                        signal_expr(&vel_name(steps, axis)),
                    )
                })
                .collect(),
        ),
    )?;
    append_nonnegative_bound(
        &mut builder,
        final_speed_sq,
        &final_speed_squared_bound(),
        "final_speed_sq_bound",
    )?;
    builder.constrain_equal(
        mul_expr(
            signal_expr(max_landing_velocity_name()),
            signal_expr(max_landing_velocity_name()),
        ),
        add_expr(vec![
            signal_expr(final_speed_sq),
            signal_expr(terminal_velocity_slack),
        ]),
    )?;
    builder.constrain_range(
        terminal_velocity_slack,
        bits_for_bound(&final_speed_squared_bound()),
    )?;

    let landing_dx = "landing_dx";
    let landing_dy = "landing_dy";
    let landing_distance_sq = "landing_distance_sq";
    let landing_zone_slack = "landing_zone_slack";
    builder.private_signal(landing_dx)?;
    builder.private_signal(landing_dy)?;
    builder.private_signal(landing_distance_sq)?;
    builder.private_signal(landing_zone_slack)?;
    builder.constrain_equal(
        signal_expr(landing_dx),
        sub_expr(
            signal_expr(&pos_name(steps, "x")),
            signal_expr(landing_zone_center_x_name()),
        ),
    )?;
    builder.constrain_equal(
        signal_expr(landing_dy),
        sub_expr(
            signal_expr(&pos_name(steps, "y")),
            signal_expr(landing_zone_center_y_name()),
        ),
    )?;
    append_signed_bound(
        &mut builder,
        landing_dx,
        &(position_bound() + landing_zone_center_bound()),
        "landing_dx_bound",
    )?;
    append_signed_bound(
        &mut builder,
        landing_dy,
        &(position_bound() + landing_zone_center_bound()),
        "landing_dy_bound",
    )?;
    builder.constrain_equal(
        signal_expr(landing_distance_sq),
        add_expr(vec![
            mul_expr(signal_expr(landing_dx), signal_expr(landing_dx)),
            mul_expr(signal_expr(landing_dy), signal_expr(landing_dy)),
        ]),
    )?;
    append_nonnegative_bound(
        &mut builder,
        landing_distance_sq,
        &landing_distance_squared_bound(),
        "landing_distance_sq_bound",
    )?;
    builder.constrain_equal(
        mul_expr(
            signal_expr(landing_zone_radius_name()),
            signal_expr(landing_zone_radius_name()),
        ),
        add_expr(vec![
            signal_expr(landing_distance_sq),
            signal_expr(landing_zone_slack),
        ]),
    )?;
    builder.constrain_range(
        landing_zone_slack,
        bits_for_bound(&landing_distance_squared_bound()),
    )?;

    builder.public_output(trajectory_commitment_output_name())?;
    let mut previous_digest = const_expr(&trajectory_seed_tag());
    for step in 0..=steps {
        let pos_mass_digest = append_poseidon_hash(
            &mut builder,
            &format!("trajectory_step_{step}_pos_mass"),
            [
                signal_expr(&pos_name(step, "x")),
                signal_expr(&pos_name(step, "y")),
                signal_expr(&pos_name(step, "z")),
                signal_expr(&mass_name(step)),
            ],
        )?;
        let vel_digest = append_poseidon_hash(
            &mut builder,
            &format!("trajectory_step_{step}_vel"),
            [
                signal_expr(&vel_name(step, "x")),
                signal_expr(&vel_name(step, "y")),
                signal_expr(&vel_name(step, "z")),
                const_expr(&BigInt::from(step as u64)),
            ],
        )?;
        let state_digest = append_poseidon_hash(
            &mut builder,
            &format!("trajectory_step_{step}_digest"),
            [
                signal_expr(&pos_mass_digest),
                signal_expr(&vel_digest),
                previous_digest,
                const_expr(&trajectory_step_tag(step)),
            ],
        )?;
        previous_digest = signal_expr(&state_digest);
    }
    builder.constrain_equal(
        signal_expr(trajectory_commitment_output_name()),
        previous_digest,
    )?;

    builder.public_output(landing_position_commitment_output_name())?;
    let landing_position_digest = append_poseidon_hash(
        &mut builder,
        "landing_position_commitment",
        [
            signal_expr(&pos_name(steps, "x")),
            signal_expr(&pos_name(steps, "y")),
            signal_expr(&pos_name(steps, "z")),
            const_expr(&landing_position_tag()),
        ],
    )?;
    builder.constrain_equal(
        signal_expr(landing_position_commitment_output_name()),
        signal_expr(&landing_position_digest),
    )?;

    builder.public_output(constraint_satisfaction_output_name())?;
    builder.constrain_boolean(constraint_satisfaction_output_name())?;
    builder.constrain_equal(
        signal_expr(constraint_satisfaction_output_name()),
        const_expr(&one()),
    )?;

    builder.public_output(final_mass_output_name())?;
    builder.constrain_equal(
        signal_expr(final_mass_output_name()),
        signal_expr(&mass_name(steps)),
    )?;
    append_nonnegative_bound(
        &mut builder,
        final_mass_output_name(),
        &mass_bound(),
        "final_mass_public_bound",
    )?;

    let sample_inputs = private_powered_descent_sample_inputs_for_steps(steps);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(wet_mass_name().to_string(), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: if steps == PRIVATE_POWERED_DESCENT_DEFAULT_STEPS {
            PRIVATE_POWERED_DESCENT_DESCRIPTION
        } else {
            PRIVATE_POWERED_DESCENT_TEST_HELPER_DESCRIPTION
        },
    })
}

pub fn build_private_powered_descent_program(steps: usize) -> ZkfResult<zkf_core::Program> {
    private_powered_descent_showcase_with_steps(steps).map(|template| template.program)
}

pub fn private_powered_descent_showcase() -> ZkfResult<TemplateProgram> {
    private_powered_descent_showcase_with_steps(PRIVATE_POWERED_DESCENT_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_powered_descent_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_powered_descent_showcase_inner(steps)
    })
}

pub fn private_powered_descent_sample_inputs() -> WitnessInputs {
    private_powered_descent_sample_inputs_for_steps(PRIVATE_POWERED_DESCENT_DEFAULT_STEPS)
}

fn write_hash_lanes(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    lanes: [FieldElement; 4],
) -> FieldElement {
    for (lane_name, lane) in hash_state_names(prefix)
        .into_iter()
        .zip(lanes.iter().cloned())
    {
        values.insert(lane_name, lane);
    }
    lanes[0].clone()
}

fn write_state_safety_support(
    values: &mut BTreeMap<String, FieldElement>,
    step: usize,
    position: &[BigInt; PRIVATE_POWERED_DESCENT_DIMENSIONS],
    mass: &BigInt,
    parameters: &DescentPublicParameters,
) -> ZkfResult<StateSafetyComputation> {
    write_nonnegative_bound_support(
        values,
        pos_name(step, "z"),
        &position[2],
        &position_bound(),
        &format!("state_{step}_altitude_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        mass_name(step),
        mass,
        &mass_bound(),
        &format!("state_{step}_mass_bound"),
    )?;
    write_nonzero_inverse_support(values, mass, &format!("state_{step}_mass"))?;
    let safety = compute_state_safety(position, parameters)?;
    write_value(values, radial_sq_name(step), safety.radial_sq.clone());
    write_value(values, altitude_sq_name(step), safety.altitude_sq.clone());
    write_value(
        values,
        glide_cone_sq_name(step),
        safety.glide_cone_sq.clone(),
    );
    write_value(
        values,
        glide_division_remainder_name(step),
        safety.glide_division_remainder.clone(),
    );
    write_value(
        values,
        glide_division_slack_name(step),
        safety.glide_division_slack.clone(),
    );
    write_exact_division_slack_anchor(
        values,
        &format!("state_{step}_glide_division"),
        &safety.glide_division_slack,
    );
    write_value(values, glide_slack_name(step), safety.glide_slack.clone());
    write_nonnegative_bound_support(
        values,
        radial_sq_name(step),
        &safety.radial_sq,
        &radial_squared_bound(),
        &format!("state_{step}_radial_sq_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        glide_cone_sq_name(step),
        &safety.glide_cone_sq,
        &glide_cone_squared_bound(),
        &format!("state_{step}_glide_cone_sq_bound"),
    )?;
    Ok(safety)
}

fn private_powered_descent_witness_inner(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private powered descent witness generation requires at least one integration step"
                .to_string(),
        ));
    }

    let parameters = load_public_parameters(inputs)?;
    let mut values = BTreeMap::<String, FieldElement>::new();
    write_public_parameter_support(&mut values, &parameters)?;

    let wet_mass = read_input(inputs, wet_mass_name())?;
    let specific_impulse = read_input(inputs, specific_impulse_name())?;
    ensure_positive_le(wet_mass_name(), &wet_mass, &mass_bound())?;
    ensure_positive_le(
        specific_impulse_name(),
        &specific_impulse,
        &specific_impulse_bound(),
    )?;
    write_nonnegative_bound_support(
        &mut values,
        wet_mass_name(),
        &wet_mass,
        &mass_bound(),
        "state_0_mass_bound",
    )?;
    write_nonzero_inverse_support(&mut values, &wet_mass, "state_0_mass")?;
    write_nonnegative_bound_support(
        &mut values,
        specific_impulse_name(),
        &specific_impulse,
        &specific_impulse_bound(),
        "specific_impulse_bound",
    )?;
    write_nonzero_inverse_support(&mut values, &specific_impulse, "specific_impulse_nonzero")?;

    let mut positions = Vec::with_capacity(steps + 1);
    let mut velocities = Vec::with_capacity(steps + 1);
    let mut masses = Vec::with_capacity(steps + 1);
    let mut current_position = std::array::from_fn(|_| zero());
    let mut current_velocity = std::array::from_fn(|_| zero());
    let mut current_mass = wet_mass.clone();
    for (axis_index, axis) in AXES.iter().enumerate() {
        current_position[axis_index] = read_input(inputs, &initial_position_name(axis))?;
        current_velocity[axis_index] = read_input(inputs, &initial_velocity_name(axis))?;
        if axis == &"z" {
            ensure_nonnegative_le(
                &initial_position_name(axis),
                &current_position[axis_index],
                &position_bound(),
            )?;
            write_nonnegative_bound_support(
                &mut values,
                initial_position_name(axis),
                &current_position[axis_index],
                &position_bound(),
                "state_0_altitude_bound",
            )?;
        } else {
            ensure_abs_le(
                &initial_position_name(axis),
                &current_position[axis_index],
                &position_bound(),
            )?;
            write_value(
                &mut values,
                initial_position_name(axis),
                current_position[axis_index].clone(),
            );
            write_signed_bound_support(
                &mut values,
                &current_position[axis_index],
                &position_bound(),
                &format!("initial_position_bound_{axis}"),
            )?;
        }
        ensure_abs_le(
            &initial_velocity_name(axis),
            &current_velocity[axis_index],
            &velocity_bound(),
        )?;
        write_value(
            &mut values,
            initial_velocity_name(axis),
            current_velocity[axis_index].clone(),
        );
        write_signed_bound_support(
            &mut values,
            &current_velocity[axis_index],
            &velocity_bound(),
            &format!("initial_velocity_bound_{axis}"),
        )?;
    }
    positions.push(current_position.clone());
    velocities.push(current_velocity.clone());
    masses.push(current_mass.clone());

    let mut thrust_profile = Vec::with_capacity(steps);
    for step in 0..steps {
        let mut thrust = std::array::from_fn(|_| zero());
        for (axis_index, axis) in AXES.iter().enumerate() {
            thrust[axis_index] = read_input(inputs, &thrust_name(step, axis))?;
            ensure_abs_le(
                &thrust_name(step, axis),
                &thrust[axis_index],
                &thrust_component_bound(),
            )?;
            write_value(
                &mut values,
                thrust_name(step, axis),
                thrust[axis_index].clone(),
            );
            write_signed_bound_support(
                &mut values,
                &thrust[axis_index],
                &thrust_component_bound(),
                &format!("step_{step}_thrust_bound_{axis}"),
            )?;
        }
        thrust_profile.push(thrust);
    }

    for (step, thrust) in thrust_profile.iter().enumerate() {
        let step_result = compute_step_dynamics(
            &current_position,
            &current_velocity,
            &current_mass,
            thrust,
            &specific_impulse,
            &parameters,
        )?;
        write_nonnegative_bound_support(
            &mut values,
            thrust_mag_sq_name(step),
            &step_result.thrust_mag_sq,
            &thrust_magnitude_squared_bound(),
            &format!("step_{step}_thrust_mag_sq_bound"),
        )?;
        write_value(
            &mut values,
            thrust_min_slack_name(step),
            step_result.thrust_min_slack.clone(),
        );
        write_value(
            &mut values,
            thrust_max_slack_name(step),
            step_result.thrust_max_slack.clone(),
        );
        write_nonnegative_bound_support(
            &mut values,
            thrust_mag_name(step),
            &step_result.thrust_mag,
            &thrust_magnitude_bound(),
            &format!("step_{step}_thrust_sqrt_sqrt_bound"),
        )?;
        write_value(
            &mut values,
            thrust_sqrt_remainder_name(step),
            step_result.thrust_sqrt_remainder.clone(),
        );
        write_value(
            &mut values,
            thrust_sqrt_upper_slack_name(step),
            step_result.thrust_sqrt_upper_slack.clone(),
        );
        for (axis_index, axis) in AXES.iter().enumerate() {
            write_value(
                &mut values,
                engine_acc_name(step, axis),
                step_result.engine_acceleration[axis_index].clone(),
            );
            write_value(
                &mut values,
                engine_acc_remainder_name(step, axis),
                step_result.engine_acceleration_remainder[axis_index].clone(),
            );
            write_value(
                &mut values,
                engine_acc_slack_name(step, axis),
                step_result.engine_acceleration_slack[axis_index].clone(),
            );
            write_exact_division_slack_anchor(
                &mut values,
                &format!("step_{step}_engine_acc_{axis}"),
                &step_result.engine_acceleration_slack[axis_index],
            );
            write_signed_bound_support(
                &mut values,
                &step_result.engine_acceleration[axis_index],
                &acceleration_bound(),
                &format!("step_{step}_engine_acc_{axis}"),
            )?;
            write_value(
                &mut values,
                velocity_delta_name(step, axis),
                step_result.velocity_delta[axis_index].clone(),
            );
            write_value(
                &mut values,
                velocity_delta_remainder_name(step, axis),
                step_result.velocity_delta_remainder[axis_index].clone(),
            );
            write_value(
                &mut values,
                velocity_delta_slack_name(step, axis),
                step_result.velocity_delta_slack[axis_index].clone(),
            );
            write_exact_division_slack_anchor(
                &mut values,
                &format!("step_{step}_velocity_delta_{axis}"),
                &step_result.velocity_delta_slack[axis_index],
            );
            write_signed_bound_support(
                &mut values,
                &step_result.velocity_delta[axis_index],
                &velocity_delta_bound(),
                &format!("step_{step}_velocity_delta_{axis}"),
            )?;
            write_value(
                &mut values,
                position_delta_name(step, axis),
                step_result.position_delta[axis_index].clone(),
            );
            write_value(
                &mut values,
                position_delta_remainder_name(step, axis),
                step_result.position_delta_remainder[axis_index].clone(),
            );
            write_value(
                &mut values,
                position_delta_slack_name(step, axis),
                step_result.position_delta_slack[axis_index].clone(),
            );
            write_exact_division_slack_anchor(
                &mut values,
                &format!("step_{step}_position_delta_{axis}"),
                &step_result.position_delta_slack[axis_index],
            );
            write_signed_bound_support(
                &mut values,
                &step_result.position_delta[axis_index],
                &position_delta_bound(),
                &format!("step_{step}_position_delta_{axis}"),
            )?;
            let next_position_name = pos_name(step + 1, axis);
            let next_velocity_name = vel_name(step + 1, axis);
            if axis == &"z" {
                write_nonnegative_bound_support(
                    &mut values,
                    next_position_name,
                    &step_result.next_position[axis_index],
                    &position_bound(),
                    &format!("state_{}_altitude_bound", step + 1),
                )?;
            } else {
                write_value(
                    &mut values,
                    next_position_name,
                    step_result.next_position[axis_index].clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &step_result.next_position[axis_index],
                    &position_bound(),
                    &format!("state_{}_position_bound_{axis}", step + 1),
                )?;
            }
            write_value(
                &mut values,
                next_velocity_name,
                step_result.next_velocity[axis_index].clone(),
            );
            write_signed_bound_support(
                &mut values,
                &step_result.next_velocity[axis_index],
                &velocity_bound(),
                &format!("state_{}_velocity_bound_{axis}", step + 1),
            )?;
        }
        write_value(
            &mut values,
            net_acc_z_name(step),
            &step_result.engine_acceleration[2] - &parameters.g_z,
        );
        write_signed_bound_support(
            &mut values,
            &(&step_result.engine_acceleration[2] - &parameters.g_z),
            &acceleration_bound(),
            &format!("step_{step}_net_acc_z_bound"),
        )?;
        write_value(
            &mut values,
            mass_decrement_name(step),
            step_result.mass_decrement.clone(),
        );
        write_nonnegative_bound_support(
            &mut values,
            mass_decrement_name(step),
            &step_result.mass_decrement,
            &mass_delta_bound(),
            &format!("step_{step}_mass_decrement_bound"),
        )?;
        write_value(
            &mut values,
            mass_decrement_remainder_name(step),
            step_result.mass_decrement_remainder.clone(),
        );
        write_value(
            &mut values,
            mass_decrement_slack_name(step),
            step_result.mass_decrement_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_mass_decrement"),
            &step_result.mass_decrement_slack,
        );
        current_position = step_result.next_position.clone();
        current_velocity = step_result.next_velocity.clone();
        current_mass = step_result.next_mass.clone();
        positions.push(current_position.clone());
        velocities.push(current_velocity.clone());
        masses.push(current_mass.clone());
    }

    let mut min_altitude = positions[0][2].clone();
    write_value(&mut values, running_min_name(0), min_altitude.clone());
    write_nonnegative_bound_support(
        &mut values,
        running_min_name(0),
        &min_altitude,
        &position_bound(),
        "state_0_running_min_bound",
    )?;

    for step in 0..=steps {
        write_state_safety_support(
            &mut values,
            step,
            &positions[step],
            &masses[step],
            &parameters,
        )?;
        if step > 0 {
            let next_min = if positions[step][2] < min_altitude {
                positions[step][2].clone()
            } else {
                min_altitude.clone()
            };
            let prev_slack = &min_altitude - &next_min;
            let curr_slack = &positions[step][2] - &next_min;
            write_nonnegative_bound_support(
                &mut values,
                running_min_name(step),
                &next_min,
                &position_bound(),
                &format!("state_{step}_running_min_bound"),
            )?;
            write_value(&mut values, running_min_prev_slack_name(step), prev_slack);
            write_value(&mut values, running_min_curr_slack_name(step), curr_slack);
            min_altitude = next_min;
        }
    }

    let final_speed_sq = velocities[steps]
        .iter()
        .fold(zero(), |acc, value| acc + (value * value));
    let max_landing_speed_sq = &parameters.max_landing_velocity * &parameters.max_landing_velocity;
    if final_speed_sq > max_landing_speed_sq {
        return Err(ZkfError::InvalidArtifact(
            "terminal velocity exceeded the public landing-speed cap".to_string(),
        ));
    }
    write_nonnegative_bound_support(
        &mut values,
        "final_speed_sq",
        &final_speed_sq,
        &final_speed_squared_bound(),
        "final_speed_sq_bound",
    )?;
    write_value(
        &mut values,
        "terminal_velocity_slack",
        max_landing_speed_sq - final_speed_sq.clone(),
    );

    let landing_dx = &positions[steps][0] - &parameters.landing_zone_center[0];
    let landing_dy = &positions[steps][1] - &parameters.landing_zone_center[1];
    let landing_distance_sq = (&landing_dx * &landing_dx) + (&landing_dy * &landing_dy);
    let landing_radius_sq = &parameters.landing_zone_radius * &parameters.landing_zone_radius;
    if landing_distance_sq > landing_radius_sq {
        return Err(ZkfError::InvalidArtifact(
            "final landing point fell outside the public landing zone".to_string(),
        ));
    }
    write_value(&mut values, "landing_dx", landing_dx.clone());
    write_value(&mut values, "landing_dy", landing_dy.clone());
    write_signed_bound_support(
        &mut values,
        &landing_dx,
        &(position_bound() + landing_zone_center_bound()),
        "landing_dx_bound",
    )?;
    write_signed_bound_support(
        &mut values,
        &landing_dy,
        &(position_bound() + landing_zone_center_bound()),
        "landing_dy_bound",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        "landing_distance_sq",
        &landing_distance_sq,
        &landing_distance_squared_bound(),
        "landing_distance_sq_bound",
    )?;
    write_value(
        &mut values,
        "landing_zone_slack",
        landing_radius_sq - landing_distance_sq,
    );

    let mut previous_digest = field_ref(&trajectory_seed_tag());
    for step in 0..=steps {
        let pos_mass_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_pos_mass"),
            poseidon_permutation4_bn254(&[
                field_ref(&positions[step][0]),
                field_ref(&positions[step][1]),
                field_ref(&positions[step][2]),
                field_ref(&masses[step]),
            ])
            .map_err(ZkfError::Backend)?,
        );
        let vel_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_vel"),
            poseidon_permutation4_bn254(&[
                field_ref(&velocities[step][0]),
                field_ref(&velocities[step][1]),
                field_ref(&velocities[step][2]),
                field(BigInt::from(step as u64)),
            ])
            .map_err(ZkfError::Backend)?,
        );
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_digest"),
            poseidon_permutation4_bn254(&[
                pos_mass_digest,
                vel_digest,
                previous_digest,
                field(trajectory_step_tag(step)),
            ])
            .map_err(ZkfError::Backend)?,
        );
    }
    values.insert(
        trajectory_commitment_output_name().to_string(),
        previous_digest.clone(),
    );

    let landing_position_digest = write_hash_lanes(
        &mut values,
        "landing_position_commitment",
        poseidon_permutation4_bn254(&[
            field_ref(&positions[steps][0]),
            field_ref(&positions[steps][1]),
            field_ref(&positions[steps][2]),
            field(landing_position_tag()),
        ])
        .map_err(ZkfError::Backend)?,
    );
    values.insert(
        landing_position_commitment_output_name().to_string(),
        landing_position_digest,
    );
    values.insert(
        constraint_satisfaction_output_name().to_string(),
        FieldElement::ONE,
    );
    values.insert(
        final_mass_output_name().to_string(),
        field_ref(&masses[steps]),
    );
    write_nonnegative_bound_support(
        &mut values,
        final_mass_output_name(),
        &masses[steps],
        &mass_bound(),
        "final_mass_public_bound",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        min_altitude_output_name(),
        &min_altitude,
        &position_bound(),
        "min_altitude_public_bound",
    )?;

    Ok(Witness { values })
}

pub fn private_powered_descent_witness(inputs: &WitnessInputs) -> ZkfResult<Witness> {
    private_powered_descent_witness_with_steps(inputs, PRIVATE_POWERED_DESCENT_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_powered_descent_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_powered_descent_witness_inner(inputs, steps)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::thread;
    use zkf_backends::blackbox_gadgets::enrich_witness_for_proving;
    use zkf_core::{BackendKind, CompiledProgram, Program, check_constraints};

    const DESCENT_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_descent_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(DESCENT_TEST_STACK_SIZE)
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
    fn descent_template_has_expected_surface() {
        let steps = 2;
        let template = private_powered_descent_showcase_with_steps(steps).expect("template");
        assert_eq!(
            template.expected_inputs.len(),
            PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS + private_input_count_for_steps(steps)
        );
        assert_eq!(
            template.public_outputs.len(),
            PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS
        );
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
            Some("euler")
        );
    }

    #[test]
    fn descent_small_step_witness_satisfies_constraints() {
        run_descent_test_on_large_stack("descent_small_step_witness_satisfies_constraints", || {
            for steps in 1..=2 {
                let template =
                    private_powered_descent_showcase_with_steps(steps).expect("template");
                let compiled = lowered_compiled_program_for_test(&template.program);
                let witness =
                    private_powered_descent_witness_with_steps(&template.sample_inputs, steps)
                        .expect("witness");
                let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
                if let Err(error) = check_constraints(&compiled.program, &prepared) {
                    let failing_constraint = match &error {
                        zkf_core::ZkfError::ConstraintViolation { index, .. }
                        | zkf_core::ZkfError::BooleanConstraintViolation { index, .. }
                        | zkf_core::ZkfError::RangeConstraintViolation { index, .. }
                        | zkf_core::ZkfError::LookupConstraintViolation { index, .. } => compiled
                            .program
                            .constraints
                            .get(*index)
                            .map(|constraint| format!("{constraint:?}"))
                            .unwrap_or_else(|| "<missing constraint>".to_string()),
                        _ => "<non-constraint error>".to_string(),
                    };
                    let extra = prepared
                        .values
                        .get("step_0_thrust_mag_sq_bound_nonnegative_bound_slack")
                        .zip(
                            prepared
                                .values
                                .get("step_0_thrust_mag_sq_bound_nonnegative_bound_anchor"),
                        )
                        .map(|(slack, anchor)| {
                            format!(
                                "\nslack={:?}\nanchor={:?}",
                                slack.to_decimal_string(),
                                anchor.to_decimal_string()
                            )
                        })
                        .unwrap_or_default();
                    panic!(
                        "constraints failed for steps={steps}: {error:?}\nfailing_constraint={failing_constraint}{extra}"
                    );
                }
            }
        });
    }

    #[test]
    fn descent_negative_altitude_fails() {
        let mut inputs = private_powered_descent_sample_inputs_for_steps(2);
        inputs.insert(initial_position_name("z"), field(decimal_scaled("-1")));
        private_powered_descent_witness_with_steps(&inputs, 2)
            .expect_err("negative altitude must fail");
    }

    #[test]
    fn descent_out_of_range_thrust_fails() {
        let mut inputs = private_powered_descent_sample_inputs_for_steps(2);
        inputs.insert(thrust_name(0, "x"), field(decimal_scaled("1000001")));
        private_powered_descent_witness_with_steps(&inputs, 2)
            .expect_err("out-of-range thrust must fail");
    }

    #[test]
    fn descent_mass_exhaustion_fails() {
        let mut inputs = private_powered_descent_sample_inputs_for_steps(2);
        inputs.insert(wet_mass_name().to_string(), field(decimal_scaled("1")));
        private_powered_descent_witness_with_steps(&inputs, 2)
            .expect_err("mass exhaustion must fail");
    }

    #[test]
    fn descent_terminal_velocity_violation_fails() {
        let mut inputs = private_powered_descent_sample_inputs_for_steps(2);
        inputs.insert(
            max_landing_velocity_name().to_string(),
            field(decimal_scaled("0.01")),
        );
        private_powered_descent_witness_with_steps(&inputs, 2)
            .expect_err("terminal velocity violation must fail");
    }

    #[test]
    fn descent_landing_zone_violation_fails() {
        let mut inputs = private_powered_descent_sample_inputs_for_steps(2);
        inputs.insert(
            landing_zone_radius_name().to_string(),
            field(decimal_scaled("0.01")),
        );
        private_powered_descent_witness_with_steps(&inputs, 2)
            .expect_err("landing zone violation must fail");
    }

    #[test]
    fn descent_request_step_mismatch_fails() {
        let request = PrivatePoweredDescentRequestV1 {
            private: PrivatePoweredDescentPrivateInputsV1 {
                initial_position: ["0".to_string(), "0".to_string(), "10".to_string()],
                initial_velocity: ["0".to_string(), "0".to_string(), "-1".to_string()],
                wet_mass_at_ignition: "25000".to_string(),
                thrust_profile: vec![["0".to_string(), "0".to_string(), "300000".to_string()]],
                specific_impulse: "282".to_string(),
            },
            public: PrivatePoweredDescentPublicInputsV1 {
                thrust_min: "300000".to_string(),
                thrust_max: "845000".to_string(),
                glide_slope_tangent: "8".to_string(),
                max_landing_velocity: "10".to_string(),
                landing_zone_radius: "15".to_string(),
                landing_zone_center: ["0".to_string(), "0".to_string()],
                g_z: "9.80665".to_string(),
                step_count: 2,
            },
        };
        WitnessInputs::try_from(request).expect_err("step-count mismatch must fail");
    }

    #[test]
    fn descent_public_commitments_match_recomputed_witness_values() {
        run_descent_test_on_large_stack(
            "descent_public_commitments_match_recomputed_witness_values",
            || {
                let steps = 2;
                let template =
                    private_powered_descent_showcase_with_steps(steps).expect("template");
                let witness =
                    private_powered_descent_witness_with_steps(&template.sample_inputs, steps)
                        .expect("witness");
                assert!(
                    witness
                        .values
                        .contains_key(trajectory_commitment_output_name())
                );
                assert!(
                    witness
                        .values
                        .contains_key(landing_position_commitment_output_name())
                );
                assert_eq!(
                    witness.values[constraint_satisfaction_output_name()],
                    FieldElement::ONE
                );
                assert_eq!(
                    witness.values[final_mass_output_name()],
                    witness.values[&mass_name(steps)]
                );
                assert_eq!(
                    witness.values[min_altitude_output_name()],
                    witness.values[&running_min_name(steps)]
                );
            },
        );
    }
}
