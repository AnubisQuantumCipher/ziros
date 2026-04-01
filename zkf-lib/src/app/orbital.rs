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

use num_bigint::{BigInt, Sign};
use std::collections::BTreeMap;
use zkf_core::{
    BlackBoxOp, Expr, FieldElement, FieldId, Witness, WitnessInputs, mod_inverse_bigint,
};
use zkf_core::{ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
#[cfg(not(target_arch = "wasm32"))]
pub use super::evidence::effective_gpu_attribution_summary;
use super::private_identity::poseidon_hash4_bn254;
use super::templates::TemplateProgram;

pub const PRIVATE_NBODY_BODY_COUNT: usize = 5;
pub const PRIVATE_NBODY_DEFAULT_STEPS: usize = 1000;
pub const PRIVATE_NBODY_DIMENSIONS: usize = 3;
pub const PRIVATE_NBODY_PRIVATE_INPUTS: usize = 35;
pub const PRIVATE_NBODY_PUBLIC_OUTPUTS: usize = 5;

const AXES: [&str; PRIVATE_NBODY_DIMENSIONS] = ["x", "y", "z"];

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

fn gravity_scaled() -> BigInt {
    BigInt::from(66_743_000u64)
}

fn position_bound() -> BigInt {
    BigInt::from(1_000u64) * fixed_scale()
}

fn velocity_bound() -> BigInt {
    BigInt::from(100u64) * fixed_scale()
}

fn mass_bound() -> BigInt {
    BigInt::from(1_000_000_000_000u64) * fixed_scale()
}

fn acceleration_bound() -> BigInt {
    BigInt::from(1_000_000u64) * fixed_scale()
}

fn min_distance() -> BigInt {
    BigInt::from(1_000_000_000_000_000u64)
}

fn max_distance_squared() -> BigInt {
    let delta_bound = position_bound() * BigInt::from(2u8);
    BigInt::from(3u8) * &delta_bound * &delta_bound
}

fn inv_r_squared_residual_bound() -> BigInt {
    BigInt::from(4u8) * fixed_scale_squared() * bigint_isqrt_floor(&max_distance_squared())
}

fn remainder_bound_for_half() -> BigInt {
    one()
}

fn inv_r3_remainder_bound() -> BigInt {
    fixed_scale_squared() / BigInt::from(2u8)
}

fn factor_remainder_bound() -> BigInt {
    fixed_scale() / BigInt::from(2u8)
}

fn acceleration_remainder_bound() -> BigInt {
    fixed_scale_squared() / BigInt::from(2u8)
}

fn body_tag(body: usize) -> BigInt {
    BigInt::from((body + 1) as u64)
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
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

fn neg_expr(expr: Expr) -> Expr {
    sub_expr(const_expr(&zero()), expr)
}

fn mass_name(body: usize) -> String {
    format!("mass_{body}")
}

fn pos_input_name(body: usize, axis: &str) -> String {
    format!("pos_{body}_{axis}")
}

fn vel_input_name(body: usize, axis: &str) -> String {
    format!("vel_{body}_{axis}")
}

fn pos_name(step: usize, body: usize, axis: &str) -> String {
    if step == 0 {
        pos_input_name(body, axis)
    } else {
        format!("step_{step}_pos_{body}_{axis}")
    }
}

fn vel_name(step: usize, body: usize, axis: &str) -> String {
    if step == 0 {
        vel_input_name(body, axis)
    } else {
        format!("step_{step}_vel_{body}_{axis}")
    }
}

fn acc_name(step: usize, body: usize, axis: &str) -> String {
    format!("step_{step}_acc_{body}_{axis}")
}

fn position_update_residual_name(step: usize, body: usize, axis: &str) -> String {
    format!("step_{step}_position_update_residual_{body}_{axis}")
}

fn velocity_update_residual_name(step: usize, body: usize, axis: &str) -> String {
    format!("step_{step}_velocity_update_residual_{body}_{axis}")
}

fn pair_prefix(step: usize, phase: &str, left: usize, right: usize) -> String {
    format!("step_{step}_{phase}_pair_{left}_{right}")
}

fn signed_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_signed_bound_slack")
}

fn positive_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_positive_bound_slack")
}

fn positive_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_positive_bound_anchor")
}

fn nonzero_inverse_name(prefix: &str) -> String {
    format!("{prefix}_nonzero_inverse")
}

fn pair_delta_name(prefix: &str, axis: &str) -> String {
    format!("{prefix}_delta_{axis}")
}

fn pair_dist_sq_name(prefix: &str) -> String {
    format!("{prefix}_distance_squared")
}

fn pair_distance_slack_name(prefix: &str) -> String {
    format!("{prefix}_minimum_distance_slack")
}

fn pair_inv_r_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance")
}

fn pair_inv_r_sq_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance_squared")
}

fn pair_inv_r_sq_residual_positive_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance_squared_residual_positive")
}

fn pair_inv_r_sq_residual_negative_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance_squared_residual_negative")
}

fn pair_inv_r3_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance_cubed")
}

fn pair_inv_r3_residual_name(prefix: &str) -> String {
    format!("{prefix}_inverse_distance_cubed_residual")
}

fn pair_factor_name(prefix: &str) -> String {
    format!("{prefix}_pair_factor")
}

fn pair_factor_residual_name(prefix: &str) -> String {
    format!("{prefix}_pair_factor_residual")
}

fn pair_tmp_name(prefix: &str, body: usize, axis: &str) -> String {
    format!("{prefix}_tmp_to_{body}_{axis}")
}

fn pair_contrib_name(prefix: &str, body: usize, axis: &str) -> String {
    format!("{prefix}_contrib_to_{body}_{axis}")
}

fn pair_contrib_residual_name(prefix: &str, body: usize, axis: &str) -> String {
    format!("{prefix}_contrib_to_{body}_{axis}_residual")
}

fn commitment_output_name(body: usize) -> String {
    format!("commit_body_{body}")
}

fn commitment_state_name(body: usize, lane: usize) -> String {
    format!("final_commit_body_{body}_state_{lane}")
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

fn nearest_inverse_distance(distance_squared: &BigInt) -> BigInt {
    let target = fixed_scale_fourth();
    let upper = fixed_scale_squared() / min_distance();
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
    write_value(values, positive_bound_slack_name(prefix), slack.clone());
    write_value(values, positive_bound_anchor_name(prefix), &slack * &slack);
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

fn append_residual_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    append_signed_bound(builder, signal, bound, prefix)
}

fn append_acceleration_constraints(
    builder: &mut ProgramBuilder,
    step_label: usize,
    phase: &str,
    position_step: usize,
    acceleration_step: usize,
) -> ZkfResult<()> {
    let mut contributions =
        vec![vec![Vec::<String>::new(); PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT];

    for body in 0..PRIVATE_NBODY_BODY_COUNT {
        for axis in AXES {
            builder.private_signal(acc_name(acceleration_step, body, axis))?;
        }
    }

    for left in 0..PRIVATE_NBODY_BODY_COUNT {
        for right in (left + 1)..PRIVATE_NBODY_BODY_COUNT {
            let prefix = pair_prefix(step_label, phase, left, right);
            let delta_names = AXES
                .iter()
                .map(|axis| pair_delta_name(&prefix, axis))
                .collect::<Vec<_>>();
            for (axis_index, axis) in AXES.iter().enumerate() {
                builder.private_signal(&delta_names[axis_index])?;
                builder.constrain_equal(
                    signal_expr(&delta_names[axis_index]),
                    sub_expr(
                        signal_expr(&pos_name(position_step, right, axis)),
                        signal_expr(&pos_name(position_step, left, axis)),
                    ),
                )?;
            }

            let distance_squared = pair_dist_sq_name(&prefix);
            builder.private_signal(&distance_squared)?;
            builder.constrain_equal(
                signal_expr(&distance_squared),
                add_expr(
                    delta_names
                        .iter()
                        .map(|name| mul_expr(signal_expr(name), signal_expr(name)))
                        .collect(),
                ),
            )?;

            let minimum_distance_slack = pair_distance_slack_name(&prefix);
            let minimum_distance_anchor = positive_bound_anchor_name(&minimum_distance_slack);
            builder.private_signal(&minimum_distance_slack)?;
            builder.private_signal(&minimum_distance_anchor)?;
            builder.constrain_equal(
                signal_expr(&distance_squared),
                add_expr(vec![
                    const_expr(&(min_distance() * min_distance())),
                    signal_expr(&minimum_distance_slack),
                ]),
            )?;
            builder.constrain_range(
                &minimum_distance_slack,
                bits_for_bound(&(max_distance_squared() - min_distance() * min_distance())),
            )?;

            let inverse_distance = pair_inv_r_name(&prefix);
            let inverse_distance_squared = pair_inv_r_sq_name(&prefix);
            let inverse_distance_squared_residual_positive =
                pair_inv_r_sq_residual_positive_name(&prefix);
            let inverse_distance_squared_residual_negative =
                pair_inv_r_sq_residual_negative_name(&prefix);
            let inverse_distance_cubed = pair_inv_r3_name(&prefix);
            let inverse_distance_cubed_residual = pair_inv_r3_residual_name(&prefix);
            let pair_factor = pair_factor_name(&prefix);
            let pair_factor_residual = pair_factor_residual_name(&prefix);

            builder.private_signal(&inverse_distance)?;
            builder.private_signal(&inverse_distance_squared)?;
            builder.private_signal(&inverse_distance_squared_residual_positive)?;
            builder.private_signal(&inverse_distance_squared_residual_negative)?;
            builder.private_signal(&inverse_distance_cubed)?;
            builder.private_signal(&inverse_distance_cubed_residual)?;
            builder.private_signal(&pair_factor)?;
            builder.private_signal(&pair_factor_residual)?;
            builder.constrain_equal(
                signal_expr(&minimum_distance_anchor),
                mul_expr(
                    signal_expr(&minimum_distance_slack),
                    signal_expr(&inverse_distance),
                ),
            )?;

            builder.constrain_equal(
                signal_expr(&inverse_distance_squared),
                mul_expr(
                    signal_expr(&inverse_distance),
                    signal_expr(&inverse_distance),
                ),
            )?;
            builder.constrain_equal(
                add_expr(vec![
                    mul_expr(
                        signal_expr(&distance_squared),
                        signal_expr(&inverse_distance_squared),
                    ),
                    signal_expr(&inverse_distance_squared_residual_positive),
                ]),
                add_expr(vec![
                    const_expr(&fixed_scale_fourth()),
                    signal_expr(&inverse_distance_squared_residual_negative),
                ]),
            )?;
            builder.constrain_range(
                &inverse_distance_squared_residual_positive,
                bits_for_bound(&inv_r_squared_residual_bound()),
            )?;
            builder.constrain_range(
                &inverse_distance_squared_residual_negative,
                bits_for_bound(&inv_r_squared_residual_bound()),
            )?;
            builder.constrain_equal(
                mul_expr(
                    signal_expr(&inverse_distance_squared_residual_positive),
                    signal_expr(&inverse_distance_squared_residual_negative),
                ),
                const_expr(&zero()),
            )?;

            builder.constrain_equal(
                mul_expr(
                    signal_expr(&inverse_distance_squared),
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
            append_residual_bound(
                builder,
                &inverse_distance_cubed_residual,
                &inv_r3_remainder_bound(),
                &format!("{prefix}_inverse_distance_cubed_bound"),
            )?;

            builder.constrain_equal(
                mul_expr(
                    const_expr(&gravity_scaled()),
                    signal_expr(&inverse_distance_cubed),
                ),
                add_expr(vec![
                    mul_expr(signal_expr(&pair_factor), const_expr(&fixed_scale())),
                    signal_expr(&pair_factor_residual),
                ]),
            )?;
            append_residual_bound(
                builder,
                &pair_factor_residual,
                &factor_remainder_bound(),
                &format!("{prefix}_pair_factor_bound"),
            )?;

            for (axis_index, axis) in AXES.iter().enumerate() {
                for body in [left, right] {
                    let other = if body == left { right } else { left };
                    let tmp = pair_tmp_name(&prefix, body, axis);
                    let contribution = pair_contrib_name(&prefix, body, axis);
                    let residual = pair_contrib_residual_name(&prefix, body, axis);
                    builder.private_signal(&tmp)?;
                    builder.private_signal(&contribution)?;
                    builder.private_signal(&residual)?;
                    let delta_expr = signal_expr(&delta_names[axis_index]);
                    let directional = if body == left {
                        delta_expr
                    } else {
                        neg_expr(delta_expr)
                    };
                    builder.constrain_equal(
                        signal_expr(&tmp),
                        mul_expr(directional, signal_expr(&mass_name(other))),
                    )?;
                    builder.constrain_equal(
                        mul_expr(signal_expr(&tmp), signal_expr(&pair_factor)),
                        add_expr(vec![
                            mul_expr(
                                signal_expr(&contribution),
                                const_expr(&fixed_scale_squared()),
                            ),
                            signal_expr(&residual),
                        ]),
                    )?;
                    append_residual_bound(
                        builder,
                        &residual,
                        &acceleration_remainder_bound(),
                        &format!("{prefix}_contribution_bound_to_{body}_{axis}"),
                    )?;
                    contributions[body][axis_index].push(contribution);
                }
            }
        }
    }

    for (body, body_contributions) in contributions
        .iter()
        .enumerate()
        .take(PRIVATE_NBODY_BODY_COUNT)
    {
        for (axis_index, axis) in AXES.iter().enumerate() {
            builder.constrain_equal(
                signal_expr(&acc_name(acceleration_step, body, axis)),
                add_expr(
                    body_contributions[axis_index]
                        .iter()
                        .map(|name| signal_expr(name))
                        .collect(),
                ),
            )?;
            append_signed_bound(
                builder,
                &acc_name(acceleration_step, body, axis),
                &acceleration_bound(),
                &format!("acceleration_bound_step_{acceleration_step}_{body}_{axis}"),
            )?;
        }
    }

    Ok(())
}

pub fn private_nbody_orbital_showcase() -> ZkfResult<TemplateProgram> {
    private_nbody_orbital_showcase_with_steps(PRIVATE_NBODY_DEFAULT_STEPS)
}

pub fn private_nbody_orbital_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private N-body showcase requires at least one integration step".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("private_nbody_orbital_5_body_{steps}_step"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "private-nbody-orbital-showcase")?;
    builder.metadata_entry("body_count", PRIVATE_NBODY_BODY_COUNT.to_string())?;
    builder.metadata_entry("dimensions", PRIVATE_NBODY_DIMENSIONS.to_string())?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "velocity-verlet")?;
    builder.metadata_entry("time_step", "1.0")?;
    builder.metadata_entry("fixed_point_scale", fixed_scale().to_str_radix(10))?;
    builder.metadata_entry("gravity_constant_scaled", gravity_scaled().to_str_radix(10))?;
    builder.metadata_entry("gravity_constant_real", "6.67430e-11")?;
    builder.metadata_entry("position_bound_scaled", position_bound().to_str_radix(10))?;
    builder.metadata_entry("velocity_bound_scaled", velocity_bound().to_str_radix(10))?;
    builder.metadata_entry("mass_bound_scaled", mass_bound().to_str_radix(10))?;
    builder.metadata_entry(
        "acceleration_bound_scaled",
        acceleration_bound().to_str_radix(10),
    )?;
    builder.metadata_entry("minimum_distance_scaled", min_distance().to_str_radix(10))?;
    builder.metadata_entry("determinism", "fixed-seed-runtime-and-proof-path")?;
    builder.metadata_entry(
        "error_model",
        "fixed-point residual witnesses bounded against a double-precision envelope",
    )?;

    let mut expected_inputs = Vec::with_capacity(PRIVATE_NBODY_PRIVATE_INPUTS);
    let public_outputs = (0..PRIVATE_NBODY_PUBLIC_OUTPUTS)
        .map(commitment_output_name)
        .collect::<Vec<_>>();

    for body in 0..PRIVATE_NBODY_BODY_COUNT {
        let mass = mass_name(body);
        builder.private_input(&mass)?;
        expected_inputs.push(mass.clone());
        append_positive_bound(
            &mut builder,
            &mass,
            &mass_bound(),
            &format!("mass_bound_{body}"),
        )?;
        append_nonzero_constraint(&mut builder, &mass, &format!("mass_nonzero_{body}"))?;

        for axis in AXES {
            let position = pos_input_name(body, axis);
            let velocity = vel_input_name(body, axis);
            builder.private_input(&position)?;
            builder.private_input(&velocity)?;
            expected_inputs.push(position.clone());
            expected_inputs.push(velocity.clone());
            append_signed_bound(
                &mut builder,
                &position,
                &position_bound(),
                &format!("position_input_bound_{body}_{axis}"),
            )?;
            append_signed_bound(
                &mut builder,
                &velocity,
                &velocity_bound(),
                &format!("velocity_input_bound_{body}_{axis}"),
            )?;
        }
    }

    append_acceleration_constraints(&mut builder, 0, "curr", 0, 0)?;

    for step in 0..steps {
        for body in 0..PRIVATE_NBODY_BODY_COUNT {
            for axis in AXES {
                let next_position = pos_name(step + 1, body, axis);
                let next_velocity = vel_name(step + 1, body, axis);
                builder.private_signal(&next_position)?;
                builder.private_signal(&next_velocity)?;
                append_signed_bound(
                    &mut builder,
                    &next_position,
                    &position_bound(),
                    &format!("position_bound_step_{}_{}_{}", step + 1, body, axis),
                )?;
                append_signed_bound(
                    &mut builder,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("velocity_bound_step_{}_{}_{}", step + 1, body, axis),
                )?;

                let position_residual = position_update_residual_name(step, body, axis);
                builder.private_signal(&position_residual)?;
                builder.constrain_equal(
                    signal_expr(&acc_name(step, body, axis)),
                    add_expr(vec![
                        mul_expr(
                            const_expr(&two()),
                            add_expr(vec![
                                signal_expr(&next_position),
                                neg_expr(signal_expr(&pos_name(step, body, axis))),
                                neg_expr(signal_expr(&vel_name(step, body, axis))),
                            ]),
                        ),
                        signal_expr(&position_residual),
                    ]),
                )?;
                append_residual_bound(
                    &mut builder,
                    &position_residual,
                    &remainder_bound_for_half(),
                    &format!("position_update_residual_bound_{step}_{body}_{axis}"),
                )?;
            }
        }

        append_acceleration_constraints(&mut builder, step, "next", step + 1, step + 1)?;

        for body in 0..PRIVATE_NBODY_BODY_COUNT {
            for axis in AXES {
                let velocity_residual = velocity_update_residual_name(step, body, axis);
                let next_velocity = vel_name(step + 1, body, axis);
                builder.private_signal(&velocity_residual)?;
                builder.constrain_equal(
                    add_expr(vec![
                        signal_expr(&acc_name(step, body, axis)),
                        signal_expr(&acc_name(step + 1, body, axis)),
                    ]),
                    add_expr(vec![
                        mul_expr(
                            const_expr(&two()),
                            add_expr(vec![
                                signal_expr(&next_velocity),
                                neg_expr(signal_expr(&vel_name(step, body, axis))),
                            ]),
                        ),
                        signal_expr(&velocity_residual),
                    ]),
                )?;
                append_residual_bound(
                    &mut builder,
                    &velocity_residual,
                    &remainder_bound_for_half(),
                    &format!("velocity_update_residual_bound_{step}_{body}_{axis}"),
                )?;
            }
        }
    }

    for body in 0..PRIVATE_NBODY_BODY_COUNT {
        let output = commitment_output_name(body);
        let state_names = [
            commitment_state_name(body, 0),
            commitment_state_name(body, 1),
            commitment_state_name(body, 2),
            commitment_state_name(body, 3),
        ];
        builder.public_output(&output)?;
        for lane in &state_names {
            builder.private_signal(lane)?;
        }
        let width = BTreeMap::from([("width".to_string(), "4".to_string())]);
        builder.constrain_blackbox(
            BlackBoxOp::Poseidon,
            &[
                signal_expr(&pos_name(steps, body, "x")),
                signal_expr(&pos_name(steps, body, "y")),
                signal_expr(&pos_name(steps, body, "z")),
                const_expr(&body_tag(body)),
            ],
            &[
                state_names[0].as_str(),
                state_names[1].as_str(),
                state_names[2].as_str(),
                state_names[3].as_str(),
            ],
            &width,
        )?;
        builder.constrain_equal(signal_expr(&output), signal_expr(&state_names[0]))?;
    }

    let sample_inputs = private_nbody_orbital_sample_inputs();
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(mass_name(0), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: "Simulate a private five-body Newtonian system for a fixed 1000-step Velocity-Verlet trace and expose Poseidon commitments to the final positions.",
    })
}

pub fn private_nbody_orbital_sample_inputs() -> WitnessInputs {
    let sample = [
        (
            "mass_0",
            decimal_scaled("10000000000"),
            [
                decimal_scaled("0"),
                decimal_scaled("0"),
                decimal_scaled("0"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("0"),
                decimal_scaled("0"),
            ],
        ),
        (
            "mass_1",
            decimal_scaled("1"),
            [
                decimal_scaled("10"),
                decimal_scaled("0"),
                decimal_scaled("0.25"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("0.258346667"),
                decimal_scaled("0"),
            ],
        ),
        (
            "mass_2",
            decimal_scaled("1"),
            [
                decimal_scaled("-10"),
                decimal_scaled("0"),
                decimal_scaled("-0.25"),
            ],
            [
                decimal_scaled("0"),
                decimal_scaled("-0.258346667"),
                decimal_scaled("0"),
            ],
        ),
        (
            "mass_3",
            decimal_scaled("1"),
            [
                decimal_scaled("0"),
                decimal_scaled("10"),
                decimal_scaled("0.5"),
            ],
            [
                decimal_scaled("-0.258346667"),
                decimal_scaled("0"),
                decimal_scaled("0"),
            ],
        ),
        (
            "mass_4",
            decimal_scaled("1"),
            [
                decimal_scaled("0"),
                decimal_scaled("-10"),
                decimal_scaled("-0.5"),
            ],
            [
                decimal_scaled("0.258346667"),
                decimal_scaled("0"),
                decimal_scaled("0"),
            ],
        ),
    ];

    let mut inputs = WitnessInputs::new();
    for (body, (_, mass, position, velocity)) in sample.iter().enumerate() {
        inputs.insert(mass_name(body), field_ref(mass));
        for (axis_index, axis) in AXES.iter().enumerate() {
            inputs.insert(pos_input_name(body, axis), field_ref(&position[axis_index]));
            inputs.insert(vel_input_name(body, axis), field_ref(&velocity[axis_index]));
        }
    }
    inputs
}

pub fn private_nbody_orbital_witness(inputs: &WitnessInputs) -> ZkfResult<Witness> {
    private_nbody_orbital_witness_with_steps(inputs, PRIVATE_NBODY_DEFAULT_STEPS)
}

pub fn private_nbody_orbital_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private N-body witness generation requires at least one step".to_string(),
        ));
    }

    let mut values = BTreeMap::<String, FieldElement>::new();
    let mut masses: [BigInt; PRIVATE_NBODY_BODY_COUNT] = std::array::from_fn(|_| zero());
    let mut positions: [[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));
    let mut velocities: [[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));

    for body in 0..PRIVATE_NBODY_BODY_COUNT {
        let mass = read_input(inputs, &mass_name(body))?;
        ensure_positive_le(&mass_name(body), &mass, &mass_bound())?;
        write_value(&mut values, mass_name(body), mass.clone());
        write_positive_bound_support(
            &mut values,
            &mass,
            &mass_bound(),
            &format!("mass_bound_{body}"),
        )?;
        write_nonzero_inverse_support(&mut values, &mass, &format!("mass_nonzero_{body}"))?;
        masses[body] = mass;

        for (axis_index, axis) in AXES.iter().enumerate() {
            let position = read_input(inputs, &pos_input_name(body, axis))?;
            let velocity = read_input(inputs, &vel_input_name(body, axis))?;
            ensure_abs_le(&pos_input_name(body, axis), &position, &position_bound())?;
            ensure_abs_le(&vel_input_name(body, axis), &velocity, &velocity_bound())?;
            write_value(&mut values, pos_input_name(body, axis), position.clone());
            write_value(&mut values, vel_input_name(body, axis), velocity.clone());
            write_signed_bound_support(
                &mut values,
                &position,
                &position_bound(),
                &format!("position_input_bound_{body}_{axis}"),
            )?;
            write_signed_bound_support(
                &mut values,
                &velocity,
                &velocity_bound(),
                &format!("velocity_input_bound_{body}_{axis}"),
            )?;
            positions[body][axis_index] = position;
            velocities[body][axis_index] = velocity;
        }
    }

    let mut current_accelerations =
        compute_acceleration_state(&mut values, 0, "curr", &positions, &masses, 0)?;

    for step in 0..steps {
        let mut next_positions: [[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for body in 0..PRIVATE_NBODY_BODY_COUNT {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let displacement = &positions[body][axis_index] + &velocities[body][axis_index];
                let (half_acc, position_residual) =
                    div_round_nearest(&current_accelerations[body][axis_index], &two());
                let next_position = displacement + &half_acc;
                ensure_abs_le(
                    &pos_name(step + 1, body, axis),
                    &next_position,
                    &position_bound(),
                )?;
                write_value(
                    &mut values,
                    position_update_residual_name(step, body, axis),
                    position_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &position_residual,
                    &remainder_bound_for_half(),
                    &format!("position_update_residual_bound_{step}_{body}_{axis}"),
                )?;
                write_value(
                    &mut values,
                    pos_name(step + 1, body, axis),
                    next_position.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_position,
                    &position_bound(),
                    &format!("position_bound_step_{}_{}_{}", step + 1, body, axis),
                )?;
                next_positions[body][axis_index] = next_position;
            }
        }

        let next_accelerations = compute_acceleration_state(
            &mut values,
            step,
            "next",
            &next_positions,
            &masses,
            step + 1,
        )?;

        let mut next_velocities: [[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| zero()));
        for body in 0..PRIVATE_NBODY_BODY_COUNT {
            for (axis_index, axis) in AXES.iter().enumerate() {
                let accel_sum = &current_accelerations[body][axis_index]
                    + &next_accelerations[body][axis_index];
                let (half_accel_sum, velocity_residual) = div_round_nearest(&accel_sum, &two());
                let next_velocity = &velocities[body][axis_index] + &half_accel_sum;
                ensure_abs_le(
                    &vel_name(step + 1, body, axis),
                    &next_velocity,
                    &velocity_bound(),
                )?;
                write_value(
                    &mut values,
                    velocity_update_residual_name(step, body, axis),
                    velocity_residual.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &velocity_residual,
                    &remainder_bound_for_half(),
                    &format!("velocity_update_residual_bound_{step}_{body}_{axis}"),
                )?;
                write_value(
                    &mut values,
                    vel_name(step + 1, body, axis),
                    next_velocity.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &next_velocity,
                    &velocity_bound(),
                    &format!("velocity_bound_step_{}_{}_{}", step + 1, body, axis),
                )?;
                next_velocities[body][axis_index] = next_velocity;
            }
        }

        positions = next_positions;
        velocities = next_velocities;
        current_accelerations = next_accelerations;
    }

    for (body, position) in positions.iter().enumerate().take(PRIVATE_NBODY_BODY_COUNT) {
        let commitment = poseidon_hash4_bn254(&[
            field_ref(&position[0]),
            field_ref(&position[1]),
            field_ref(&position[2]),
            field_ref(&body_tag(body)),
        ])
        .map_err(ZkfError::Backend)?;
        values.insert(commitment_output_name(body), commitment);
    }

    Ok(Witness { values })
}

fn compute_acceleration_state(
    values: &mut BTreeMap<String, FieldElement>,
    step_label: usize,
    phase: &str,
    positions: &[[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT],
    masses: &[BigInt; PRIVATE_NBODY_BODY_COUNT],
    acceleration_step: usize,
) -> ZkfResult<[[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT]> {
    let mut totals: [[BigInt; PRIVATE_NBODY_DIMENSIONS]; PRIVATE_NBODY_BODY_COUNT] =
        std::array::from_fn(|_| std::array::from_fn(|_| zero()));

    for left in 0..PRIVATE_NBODY_BODY_COUNT {
        for right in (left + 1)..PRIVATE_NBODY_BODY_COUNT {
            let prefix = pair_prefix(step_label, phase, left, right);
            let deltas: [BigInt; PRIVATE_NBODY_DIMENSIONS] = std::array::from_fn(|axis| {
                positions[right][axis].clone() - positions[left][axis].clone()
            });
            for (axis_index, axis) in AXES.iter().enumerate() {
                write_value(
                    values,
                    pair_delta_name(&prefix, axis),
                    deltas[axis_index].clone(),
                );
            }

            let distance_squared = deltas.iter().fold(zero(), |acc, value| acc + value * value);
            if distance_squared < min_distance() * min_distance() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "pairwise distance floor violated for pair ({left},{right}) at step {step_label}:{phase}"
                )));
            }
            write_value(values, pair_dist_sq_name(&prefix), distance_squared.clone());
            write_value(
                values,
                pair_distance_slack_name(&prefix),
                &distance_squared - &(min_distance() * min_distance()),
            );
            let min_distance_slack = &distance_squared - &(min_distance() * min_distance());

            let inverse_distance = nearest_inverse_distance(&distance_squared);
            let inverse_distance_squared = &inverse_distance * &inverse_distance;
            let inverse_distance_squared_residual =
                fixed_scale_fourth() - (&distance_squared * &inverse_distance_squared);
            write_value(values, pair_inv_r_name(&prefix), inverse_distance.clone());
            write_value(
                values,
                positive_bound_anchor_name(&pair_distance_slack_name(&prefix)),
                &min_distance_slack * &inverse_distance,
            );
            write_value(
                values,
                pair_inv_r_sq_name(&prefix),
                inverse_distance_squared.clone(),
            );
            write_value(
                values,
                pair_inv_r_sq_residual_positive_name(&prefix),
                if inverse_distance_squared_residual.sign() == Sign::Minus {
                    zero()
                } else {
                    inverse_distance_squared_residual.clone()
                },
            );
            write_value(
                values,
                pair_inv_r_sq_residual_negative_name(&prefix),
                if inverse_distance_squared_residual.sign() == Sign::Minus {
                    -inverse_distance_squared_residual.clone()
                } else {
                    zero()
                },
            );

            let inverse_distance_cubed_numerator = &inverse_distance_squared * &inverse_distance;
            let (inverse_distance_cubed, inverse_distance_cubed_residual) =
                div_round_nearest(&inverse_distance_cubed_numerator, &fixed_scale_squared());
            write_value(
                values,
                pair_inv_r3_name(&prefix),
                inverse_distance_cubed.clone(),
            );
            write_value(
                values,
                pair_inv_r3_residual_name(&prefix),
                inverse_distance_cubed_residual.clone(),
            );
            write_signed_bound_support(
                values,
                &inverse_distance_cubed_residual,
                &inv_r3_remainder_bound(),
                &format!("{prefix}_inverse_distance_cubed_bound"),
            )?;

            let factor_numerator = gravity_scaled() * &inverse_distance_cubed;
            let (pair_factor, pair_factor_residual) =
                div_round_nearest(&factor_numerator, &fixed_scale());
            write_value(values, pair_factor_name(&prefix), pair_factor.clone());
            write_value(
                values,
                pair_factor_residual_name(&prefix),
                pair_factor_residual.clone(),
            );
            write_signed_bound_support(
                values,
                &pair_factor_residual,
                &factor_remainder_bound(),
                &format!("{prefix}_pair_factor_bound"),
            )?;

            for (axis_index, axis) in AXES.iter().enumerate() {
                let delta = deltas[axis_index].clone();

                let tmp_left = &delta * &masses[right];
                let (contribution_left, contribution_left_residual) =
                    div_round_nearest(&(tmp_left.clone() * &pair_factor), &fixed_scale_squared());
                write_value(values, pair_tmp_name(&prefix, left, axis), tmp_left);
                write_value(
                    values,
                    pair_contrib_name(&prefix, left, axis),
                    contribution_left.clone(),
                );
                write_value(
                    values,
                    pair_contrib_residual_name(&prefix, left, axis),
                    contribution_left_residual.clone(),
                );
                write_signed_bound_support(
                    values,
                    &contribution_left_residual,
                    &acceleration_remainder_bound(),
                    &format!("{prefix}_contribution_bound_to_{left}_{axis}"),
                )?;
                totals[left][axis_index] += contribution_left;

                let tmp_right = (-delta) * &masses[left];
                let (contribution_right, contribution_right_residual) =
                    div_round_nearest(&(tmp_right.clone() * &pair_factor), &fixed_scale_squared());
                write_value(values, pair_tmp_name(&prefix, right, axis), tmp_right);
                write_value(
                    values,
                    pair_contrib_name(&prefix, right, axis),
                    contribution_right.clone(),
                );
                write_value(
                    values,
                    pair_contrib_residual_name(&prefix, right, axis),
                    contribution_right_residual.clone(),
                );
                write_signed_bound_support(
                    values,
                    &contribution_right_residual,
                    &acceleration_remainder_bound(),
                    &format!("{prefix}_contribution_bound_to_{right}_{axis}"),
                )?;
                totals[right][axis_index] += contribution_right;
            }
        }
    }

    for (body, body_totals) in totals.iter().enumerate().take(PRIVATE_NBODY_BODY_COUNT) {
        for (axis_index, axis) in AXES.iter().enumerate() {
            ensure_abs_le(
                &acc_name(acceleration_step, body, axis),
                &body_totals[axis_index],
                &acceleration_bound(),
            )?;
            write_value(
                values,
                acc_name(acceleration_step, body, axis),
                body_totals[axis_index].clone(),
            );
            write_signed_bound_support(
                values,
                &totals[body][axis_index],
                &acceleration_bound(),
                &format!("acceleration_bound_step_{acceleration_step}_{body}_{axis}"),
            )?;
        }
    }

    Ok(totals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;
    use zkf_backends::prepare_witness_for_proving;
    use zkf_core::check_constraints;

    #[test]
    fn orbital_template_has_expected_surface() {
        let template = private_nbody_orbital_showcase_with_steps(1).expect("template");
        assert_eq!(template.expected_inputs.len(), PRIVATE_NBODY_PRIVATE_INPUTS);
        assert_eq!(template.public_outputs.len(), PRIVATE_NBODY_PUBLIC_OUTPUTS);
        assert_eq!(PRIVATE_NBODY_DEFAULT_STEPS, 1000);
        assert_eq!(
            template
                .program
                .metadata
                .get("integration_steps")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn orbital_small_step_witness_satisfies_constraints() {
        let template = private_nbody_orbital_showcase_with_steps(2).expect("template");
        let compiled =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                compile(&template.program, "arkworks-groth16", Some([0x44; 32]))
            })
            .expect("compile");
        let witness = private_nbody_orbital_witness_with_steps(&template.sample_inputs, 2)
            .expect("custom witness");
        let prepared = prepare_witness_for_proving(&compiled, &witness).expect("prepared");
        check_constraints(&compiled.program, &prepared).expect("constraints");
    }

    #[test]
    fn orbital_small_step_tamper_fails() {
        let template = private_nbody_orbital_showcase_with_steps(1).expect("template");
        let compiled =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                compile(&template.program, "arkworks-groth16", Some([0x55; 32]))
            })
            .expect("compile");
        let mut witness = private_nbody_orbital_witness_with_steps(&template.sample_inputs, 1)
            .expect("custom witness");
        witness
            .values
            .insert(commitment_output_name(0), FieldElement::from_i64(12345));
        match prepare_witness_for_proving(&compiled, &witness) {
            Ok(prepared) => {
                check_constraints(&compiled.program, &prepared).expect_err("tampered commitment");
            }
            Err(_) => {}
        }
    }

    #[test]
    fn orbital_small_step_prepared_witness_reprepare_is_stable() {
        let template = private_nbody_orbital_showcase_with_steps(1).expect("template");
        let compiled =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                compile(&template.program, "arkworks-groth16", Some([0x66; 32]))
            })
            .expect("compile");
        let witness = private_nbody_orbital_witness_with_steps(&template.sample_inputs, 1)
            .expect("custom witness");
        let prepared = prepare_witness_for_proving(&compiled, &witness).expect("prepared once");
        let reprepared = prepare_witness_for_proving(&compiled, &prepared).expect("prepared twice");
        check_constraints(&compiled.program, &reprepared).expect("constraints");
    }

    #[test]
    fn orbital_gpu_attribution_detects_backend_delegated_metal() {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "groth16_execution_classification".to_string(),
            "metal-realized".to_string(),
        );
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt+streamed-reduction".to_string(),
        );
        metadata.insert("metal_gpu_busy_ratio".to_string(), "0.75".to_string());
        metadata.insert("metal_available".to_string(), "true".to_string());
        metadata.insert("metal_compiled".to_string(), "true".to_string());
        metadata.insert("metal_complete".to_string(), "true".to_string());

        let summary = effective_gpu_attribution_summary(0, 0.0, &metadata);
        assert_eq!(
            summary
                .get("classification")
                .and_then(serde_json::Value::as_str),
            Some("backend-delegated")
        );
        assert_eq!(
            summary
                .get("effective_gpu_participation")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            summary
                .get("effective_gpu_busy_ratio")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default()
                > 0.0
        );
        let sources = summary
            .get("evidence_sources")
            .and_then(serde_json::Value::as_array)
            .expect("evidence sources");
        assert!(
            sources
                .iter()
                .any(|value| value.as_str() == Some("artifact.metadata.groth16_execution.msm"))
        );
        assert!(
            sources
                .iter()
                .any(|value| value.as_str()
                    == Some("artifact.metadata.groth16_execution.witness_map"))
        );
    }

    #[test]
    fn orbital_gpu_attribution_ignores_capability_only_hints() {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "best_msm_accelerator".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert(
            "gpu_stage_coverage".to_string(),
            r#"{"coverage_ratio":1.0,"metal_stages":["msm","fft-ntt"],"cpu_stages":[]}"#
                .to_string(),
        );
        metadata.insert("metal_available".to_string(), "true".to_string());
        metadata.insert("metal_compiled".to_string(), "true".to_string());
        metadata.insert("metal_complete".to_string(), "true".to_string());

        let summary = effective_gpu_attribution_summary(0, 0.0, &metadata);
        assert_eq!(
            summary
                .get("classification")
                .and_then(serde_json::Value::as_str),
            Some("none")
        );
        assert_eq!(
            summary
                .get("effective_gpu_participation")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            summary
                .get("realized_gpu_capable_stages")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }
}
