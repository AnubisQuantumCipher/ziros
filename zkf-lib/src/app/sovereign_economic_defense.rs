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

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
use zkf_core::{
    Expr, FieldElement, FieldId, Program, Witness, WitnessInputs, ZkfError, ZkfResult,
    generate_witness,
};

use super::builder::ProgramBuilder;
use super::subsystem_support;

pub const SOVEREIGN_ECONOMIC_DEFENSE_GOLDILOCKS_SCALE_DECIMALS: u32 = 3;
pub const SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS: u32 = 18;
pub const SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS: usize = 96;

const SED_GOLDILOCKS_FIELD: FieldId = FieldId::Goldilocks;
const SED_BN254_FIELD: FieldId = FieldId::Bn254;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CooperativeTreasuryAssuranceRequestV1 {
    pub treasury_id: String,
    pub contributions: Vec<String>,
    pub distributions: Vec<String>,
    pub reserve_balance: String,
    pub min_reserve_ratio: String,
    pub max_distribution_per_member: String,
    pub fairness_tolerance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommunityLandTrustGovernanceRequestV1 {
    pub land_trust_id: String,
    pub property_values: Vec<String>,
    pub equity_shares: Vec<String>,
    pub occupancy_flags: Vec<bool>,
    pub tenure_buckets: Vec<u64>,
    pub maintenance_reserve: String,
    pub min_equity_share: String,
    pub max_equity_concentration: String,
    pub min_maintenance_reserve: String,
    pub required_occupancy_rate: String,
    pub max_rms_equity_deviation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AntiExtractionShieldRequestV1 {
    pub loan_id: String,
    pub principal: String,
    pub interest_rate_components: Vec<String>,
    pub scheduled_payments: Vec<String>,
    pub balloon_payment: bool,
    pub balloon_prohibited: bool,
    pub borrower_income_proxy: String,
    pub apr_ceiling: String,
    pub max_debt_to_income_ratio: String,
    pub minimum_term_length: u64,
    pub loan_type_code: u64,
    pub term_bucket: u64,
    pub marginal_threshold: String,
    pub predatory_threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WealthTrajectoryAssuranceRequestV1 {
    pub portfolio_id: String,
    pub asset_allocations: Vec<String>,
    pub return_rates: Vec<String>,
    pub target_allocations: Vec<String>,
    pub prohibited_flags: Vec<bool>,
    pub distribution_schedule: Vec<String>,
    pub max_single_asset_concentration: String,
    pub max_variance_proxy: String,
    pub min_return_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecirculationSovereigntyScoreRequestV1 {
    pub mission_id: String,
    pub internal_spend: Vec<String>,
    pub external_spend: Vec<String>,
    pub circuit_commitments: [String; 4],
    pub circuit_status_bits: [bool; 4],
    pub initial_circulating_capital: String,
    pub initial_cooperative_equity: String,
    pub initial_asset_ownership_pct: String,
    pub initial_reserve_level: String,
    pub initial_recirculation_rate: String,
    pub recirculation_target: String,
    pub leakage_cap: String,
    pub asset_ownership_goal: String,
    pub reserve_floor: String,
    pub min_investment_return: String,
    pub investment_return_reference: String,
    pub class_d_nominal_margin: String,
    pub class_d_stress_margin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SovereignEconomicDefenseRunManifestV1 {
    pub run_id: String,
    pub cooperative_treasury: CooperativeTreasuryAssuranceRequestV1,
    pub community_land_trust: CommunityLandTrustGovernanceRequestV1,
    pub anti_extraction_shield: AntiExtractionShieldRequestV1,
    pub wealth_trajectory: WealthTrajectoryAssuranceRequestV1,
    pub recirculation_sovereignty: RecirculationSovereigntyScoreRequestV1,
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

fn fixed_scale(decimals: u32) -> BigInt {
    BigInt::from(10u8).pow(decimals)
}

fn sed_goldilocks_scale() -> BigInt {
    fixed_scale(SOVEREIGN_ECONOMIC_DEFENSE_GOLDILOCKS_SCALE_DECIMALS)
}

fn sed_bn254_scale() -> BigInt {
    fixed_scale(SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS)
}

fn sed_goldilocks_amount_bound() -> BigInt {
    BigInt::from(1_000_000_000u64)
}

fn sed_goldilocks_score_bound() -> BigInt {
    BigInt::from(1_000_000u64)
}

fn sed_bn254_amount_bound() -> BigInt {
    fixed_scale(SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS) * BigInt::from(1_000_000u64)
}

fn abs_bigint(value: &BigInt) -> BigInt {
    subsystem_support::abs_bigint(value)
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    subsystem_support::bits_for_bound(bound)
}

fn decimal_scaled(value: &str, decimals: u32) -> BigInt {
    subsystem_support::decimal_scaled(value, decimals)
}

fn bigint_isqrt_floor(value: &BigInt) -> BigInt {
    subsystem_support::bigint_isqrt_floor(value)
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

fn add_expr(mut values: Vec<Expr>) -> Expr {
    if values.len() == 1 {
        values.remove(0)
    } else {
        Expr::Add(values)
    }
}

fn sub_expr(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

fn mul_expr(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_poseidon_state_0"),
        format!("{prefix}_poseidon_state_1"),
        format!("{prefix}_poseidon_state_2"),
        format!("{prefix}_poseidon_state_3"),
    ]
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

fn exact_division_slack_anchor_name(prefix: &str) -> String {
    format!("{prefix}_exact_division_slack_anchor")
}

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: impl Into<BigInt>,
) {
    values.insert(name.into(), field(value.into()));
}

fn write_bool_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: bool,
) {
    values.insert(
        name.into(),
        if value {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
    );
}

fn ensure_nonnegative_le(label: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value < zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} must be in [0, {}], got {}",
            bound.to_str_radix(10),
            value.to_str_radix(10)
        )));
    }
    Ok(())
}

fn ensure_abs_le(label: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if abs_bigint(value) > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} exceeds signed bound {}",
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
    ensure_abs_le(prefix, value, bound)?;
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
    values.insert(nonnegative_bound_slack_name(prefix), field_ref(&slack));
    values.insert(
        nonnegative_bound_anchor_name(prefix),
        field_ref(&(&slack * &slack)),
    );
    Ok(())
}

fn write_exact_division_support(
    values: &mut BTreeMap<String, FieldElement>,
    quotient_name: &str,
    quotient: &BigInt,
    remainder_name: &str,
    remainder: &BigInt,
    slack_name: &str,
    slack: &BigInt,
    prefix: &str,
) {
    write_value(values, quotient_name, quotient.clone());
    write_value(values, remainder_name, remainder.clone());
    write_value(values, slack_name, slack.clone());
    write_value(
        values,
        exact_division_slack_anchor_name(prefix),
        slack * slack,
    );
}

fn write_floor_sqrt_support(
    values: &mut BTreeMap<String, FieldElement>,
    sqrt_signal: &str,
    sqrt_value: &BigInt,
    remainder_signal: &str,
    remainder_value: &BigInt,
    upper_slack_signal: &str,
    upper_slack_value: &BigInt,
    sqrt_bound: &BigInt,
    support_bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    write_nonnegative_bound_support(
        values,
        sqrt_signal,
        sqrt_value,
        sqrt_bound,
        &format!("{prefix}_sqrt_bound"),
    )?;
    ensure_nonnegative_le(remainder_signal, remainder_value, support_bound)?;
    ensure_nonnegative_le(upper_slack_signal, upper_slack_value, support_bound)?;
    write_value(values, remainder_signal, remainder_value.clone());
    write_value(values, upper_slack_signal, upper_slack_value.clone());
    Ok(())
}

fn write_hash_lanes(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    lanes: [FieldElement; 4],
) -> FieldElement {
    for (name, lane) in hash_state_names(prefix).into_iter().zip(lanes) {
        values.insert(name, lane);
    }
    values
        .get(&hash_state_names(prefix)[0])
        .cloned()
        .unwrap_or(FieldElement::ZERO)
}

fn poseidon_permutation4(field_id: FieldId, inputs: [&BigInt; 4]) -> ZkfResult<[FieldElement; 4]> {
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    let lanes = poseidon2_permutation_native(
        &inputs.into_iter().cloned().collect::<Vec<_>>(),
        &params,
        field_id,
    )
    .map_err(ZkfError::Backend)?;
    if lanes.len() != 4 {
        return Err(ZkfError::Backend(format!(
            "poseidon permutation returned {} lanes instead of 4",
            lanes.len()
        )));
    }
    Ok([
        field(lanes[0].clone()),
        field(lanes[1].clone()),
        field(lanes[2].clone()),
        field(lanes[3].clone()),
    ])
}

fn positive_comparison_offset(bound: &BigInt) -> BigInt {
    bound + one()
}

fn signed_comparison_offset(bound: &BigInt) -> BigInt {
    (bound * two()) + one()
}

fn comparator_slack(lhs: &BigInt, rhs: &BigInt, offset: &BigInt) -> BigInt {
    if lhs >= rhs {
        lhs - rhs
    } else {
        lhs - rhs + offset
    }
}

fn append_geq_comparator_bit(
    builder: &mut ProgramBuilder,
    lhs: Expr,
    rhs: Expr,
    bit_signal: &str,
    slack_signal: &str,
    offset: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    builder.private_signal(bit_signal)?;
    builder.constrain_boolean(bit_signal)?;
    builder.private_signal(slack_signal)?;
    builder.constrain_equal(
        add_expr(vec![lhs, const_expr(offset)]),
        add_expr(vec![
            rhs,
            signal_expr(slack_signal),
            mul_expr(signal_expr(bit_signal), const_expr(offset)),
        ]),
    )?;
    builder.append_nonnegative_bound(
        slack_signal,
        &(offset - one()),
        &format!("{prefix}_comparator_slack"),
    )?;
    Ok(())
}

fn append_boolean_not(builder: &mut ProgramBuilder, target: &str, source: &str) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        sub_expr(const_expr(&one()), signal_expr(source)),
    )?;
    Ok(())
}

fn append_boolean_and(
    builder: &mut ProgramBuilder,
    target: &str,
    left: &str,
    right: &str,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        mul_expr(signal_expr(left), signal_expr(right)),
    )?;
    Ok(())
}

fn append_boolean_or(
    builder: &mut ProgramBuilder,
    target: &str,
    left: &str,
    right: &str,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        sub_expr(
            add_expr(vec![signal_expr(left), signal_expr(right)]),
            mul_expr(signal_expr(left), signal_expr(right)),
        ),
    )?;
    Ok(())
}

fn append_pairwise_max_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let bit_signal = format!("{prefix}_geq_bit");
    let slack_signal = format!("{prefix}_geq_slack");
    append_geq_comparator_bit(
        builder,
        signal_expr(left_signal),
        signal_expr(right_signal),
        &bit_signal,
        &slack_signal,
        &positive_comparison_offset(bound),
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.constrain_select(
        target,
        &bit_signal,
        signal_expr(left_signal),
        signal_expr(right_signal),
    )?;
    builder.append_nonnegative_bound(target, bound, &format!("{prefix}_bound"))?;
    Ok(())
}

fn validate_equal_lengths(label: &str, lengths: &[usize]) -> ZkfResult<()> {
    if lengths.is_empty() || lengths[0] == 0 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} requires at least one element"
        )));
    }
    if lengths.windows(2).any(|window| window[0] != window[1]) {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} requires equal-length vectors"
        )));
    }
    Ok(())
}

fn parse_goldilocks_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, SOVEREIGN_ECONOMIC_DEFENSE_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &sed_goldilocks_amount_bound())?;
    Ok(parsed)
}

fn parse_goldilocks_ratio(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, SOVEREIGN_ECONOMIC_DEFENSE_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &sed_goldilocks_scale())?;
    Ok(parsed)
}

fn parse_bn254_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &sed_bn254_amount_bound())?;
    Ok(parsed)
}

fn parse_bn254_ratio(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &sed_bn254_scale())?;
    Ok(parsed)
}

fn parse_nonnegative_integer(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = BigInt::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| ZkfError::InvalidArtifact(format!("{label} must be a base-10 integer")))?;
    if parsed < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} must be nonnegative"
        )));
    }
    Ok(parsed)
}

fn sum_bigints(values: &[BigInt]) -> BigInt {
    values.iter().fold(zero(), |acc, value| acc + value)
}

fn sum_exprs(names: &[String]) -> Expr {
    add_expr(names.iter().map(|name| signal_expr(name)).collect())
}

fn materialize_seeded_witness(program: &Program, values: WitnessInputs) -> ZkfResult<Witness> {
    generate_witness(program, &values)
}

pub fn build_cooperative_treasury_assurance_program(
    request: &CooperativeTreasuryAssuranceRequestV1,
) -> ZkfResult<Program> {
    validate_equal_lengths(
        "cooperative treasury assurance",
        &[request.contributions.len(), request.distributions.len()],
    )?;
    let members = request.contributions.len();
    let amount_bits = bits_for_bound(&sed_goldilocks_amount_bound());
    let ratio_bits = bits_for_bound(&sed_goldilocks_scale());

    let mut builder = ProgramBuilder::new(
        format!("sovereign_economic_defense_cooperative_treasury_{members}"),
        SED_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "sovereign-economic-defense")?;
    builder.metadata_entry("circuit", "cooperative-treasury-assurance")?;
    builder.metadata_entry("members", members.to_string())?;
    builder.metadata_entry("fixed_point_scale", sed_goldilocks_scale().to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut contribution_names = Vec::with_capacity(members);
    let mut distribution_names = Vec::with_capacity(members);
    for index in 0..members {
        let contribution = format!("cta_contribution_{index}");
        let distribution = format!("cta_distribution_{index}");
        builder.private_input(&contribution)?;
        builder.private_input(&distribution)?;
        builder.constrain_range(&contribution, amount_bits)?;
        builder.constrain_range(&distribution, amount_bits)?;
        contribution_names.push(contribution);
        distribution_names.push(distribution);
    }
    builder.private_input("cta_reserve_balance")?;
    builder.private_input("cta_min_reserve_ratio")?;
    builder.private_input("cta_max_distribution_per_member")?;
    builder.private_input("cta_fairness_tolerance")?;
    builder.constrain_range("cta_reserve_balance", amount_bits)?;
    builder.constrain_range("cta_min_reserve_ratio", ratio_bits)?;
    builder.constrain_range("cta_max_distribution_per_member", amount_bits)?;
    builder.constrain_range("cta_fairness_tolerance", amount_bits)?;

    builder.public_output("cta_treasury_commitment")?;
    builder.public_output("cta_compliance_bit")?;
    builder.constant_signal("cta_chain_seed", FieldElement::ZERO)?;

    builder.private_signal("cta_total_contributions")?;
    builder.private_signal("cta_total_distributions")?;
    builder.private_signal("cta_reserve_ratio")?;
    builder.private_signal("cta_reserve_ratio_remainder")?;
    builder.private_signal("cta_reserve_ratio_slack")?;
    builder.private_signal("cta_buffer_ok")?;
    builder.private_signal("cta_buffer_ok_slack")?;
    builder.private_signal("cta_emergency_mode")?;
    builder.private_signal("cta_active_cap_multiplier")?;
    builder.private_signal("cta_active_distribution_cap")?;
    builder.private_signal("cta_active_distribution_cap_remainder")?;
    builder.private_signal("cta_active_distribution_cap_slack")?;
    builder.private_signal("cta_mean_distribution")?;
    builder.private_signal("cta_mean_distribution_remainder")?;
    builder.private_signal("cta_mean_distribution_slack")?;
    builder.private_signal("cta_mean_square_deviation")?;
    builder.private_signal("cta_mean_square_deviation_remainder")?;
    builder.private_signal("cta_mean_square_deviation_slack")?;
    builder.private_signal("cta_fairness_rms")?;
    builder.private_signal("cta_fairness_rms_remainder")?;
    builder.private_signal("cta_fairness_rms_upper_slack")?;

    builder.constrain_equal(
        signal_expr("cta_total_contributions"),
        sum_exprs(&contribution_names),
    )?;
    builder.constrain_equal(
        signal_expr("cta_total_distributions"),
        sum_exprs(&distribution_names),
    )?;
    builder.constrain_nonzero("cta_total_contributions")?;
    builder.append_exact_division_constraints(
        mul_expr(
            signal_expr("cta_reserve_balance"),
            const_expr(&sed_goldilocks_scale()),
        ),
        signal_expr("cta_total_contributions"),
        "cta_reserve_ratio",
        "cta_reserve_ratio_remainder",
        "cta_reserve_ratio_slack",
        &sed_goldilocks_amount_bound(),
        "cta_reserve_ratio",
    )?;
    builder.constrain_geq(
        "cta_reserve_ratio_floor_slack",
        signal_expr("cta_reserve_ratio"),
        signal_expr("cta_min_reserve_ratio"),
        ratio_bits,
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("cta_reserve_ratio"),
        signal_expr("cta_min_reserve_ratio"),
        "cta_buffer_ok",
        "cta_buffer_ok_slack",
        &positive_comparison_offset(&sed_goldilocks_scale()),
        "cta_buffer_ok",
    )?;
    append_boolean_not(&mut builder, "cta_emergency_mode", "cta_buffer_ok")?;
    builder.add_lookup_table(
        "cta_distribution_mode_schedule",
        2,
        vec![
            vec![FieldElement::ZERO, field_ref(&sed_goldilocks_scale())],
            vec![
                FieldElement::ONE,
                field_ref(&(sed_goldilocks_scale() / two())),
            ],
        ],
    )?;
    builder.constrain_lookup(
        &[
            signal_expr("cta_emergency_mode"),
            signal_expr("cta_active_cap_multiplier"),
        ],
        "cta_distribution_mode_schedule",
    )?;
    builder.append_exact_division_constraints(
        mul_expr(
            signal_expr("cta_max_distribution_per_member"),
            signal_expr("cta_active_cap_multiplier"),
        ),
        const_expr(&sed_goldilocks_scale()),
        "cta_active_distribution_cap",
        "cta_active_distribution_cap_remainder",
        "cta_active_distribution_cap_slack",
        &sed_goldilocks_scale(),
        "cta_active_distribution_cap",
    )?;
    for (index, distribution) in distribution_names.iter().enumerate() {
        builder.constrain_leq(
            format!("cta_distribution_cap_slack_{index}"),
            signal_expr(distribution),
            signal_expr("cta_active_distribution_cap"),
            amount_bits,
        )?;
    }
    builder.append_exact_division_constraints(
        signal_expr("cta_total_distributions"),
        const_expr(&BigInt::from(members as u64)),
        "cta_mean_distribution",
        "cta_mean_distribution_remainder",
        "cta_mean_distribution_slack",
        &BigInt::from(members as u64),
        "cta_mean_distribution",
    )?;
    builder.append_nonnegative_bound(
        "cta_mean_distribution",
        &sed_goldilocks_amount_bound(),
        "cta_mean_distribution_bound",
    )?;

    let mut squared_deviations = Vec::with_capacity(members);
    for index in 0..members {
        let deviation = format!("cta_distribution_deviation_{index}");
        builder.private_signal(&deviation)?;
        builder.constrain_equal(
            signal_expr(&deviation),
            sub_expr(
                signal_expr(&distribution_names[index]),
                signal_expr("cta_mean_distribution"),
            ),
        )?;
        builder.append_signed_bound(
            &deviation,
            &sed_goldilocks_amount_bound(),
            &format!("cta_distribution_deviation_{index}"),
        )?;
        squared_deviations.push(mul_expr(signal_expr(&deviation), signal_expr(&deviation)));
    }
    builder.constrain_equal(
        signal_expr("cta_mean_square_deviation"),
        signal_expr("cta_mean_square_deviation"),
    )?;
    builder.append_exact_division_constraints(
        add_expr(squared_deviations),
        const_expr(&BigInt::from(members as u64)),
        "cta_mean_square_deviation",
        "cta_mean_square_deviation_remainder",
        "cta_mean_square_deviation_slack",
        &BigInt::from(members as u64),
        "cta_mean_square_deviation",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("cta_mean_square_deviation"),
        "cta_fairness_rms",
        "cta_fairness_rms_remainder",
        "cta_fairness_rms_upper_slack",
        &sed_goldilocks_score_bound(),
        &sed_goldilocks_score_bound(),
        "cta_fairness_rms",
    )?;
    builder.constrain_leq(
        "cta_fairness_tolerance_slack",
        signal_expr("cta_fairness_rms"),
        signal_expr("cta_fairness_tolerance"),
        amount_bits,
    )?;

    let mut previous_digest = signal_expr("cta_chain_seed");
    for index in 0..members {
        let step_digest = builder.append_poseidon_hash(
            &format!("cta_member_commitment_{index}"),
            [
                signal_expr(&contribution_names[index]),
                signal_expr(&distribution_names[index]),
                previous_digest.clone(),
                signal_expr("cta_reserve_ratio"),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "cta_final_commitment",
        [
            previous_digest,
            signal_expr("cta_reserve_balance"),
            signal_expr("cta_fairness_rms"),
            signal_expr("cta_active_distribution_cap"),
        ],
    )?;
    builder.bind("cta_treasury_commitment", signal_expr(&final_digest))?;
    builder.bind("cta_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn cooperative_treasury_assurance_witness_from_request(
    request: &CooperativeTreasuryAssuranceRequestV1,
) -> ZkfResult<Witness> {
    validate_equal_lengths(
        "cooperative treasury assurance",
        &[request.contributions.len(), request.distributions.len()],
    )?;
    let members = request.contributions.len();
    let scale = sed_goldilocks_scale();
    let mut values = BTreeMap::new();

    let contributions = request
        .contributions
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("contribution {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let distributions = request
        .distributions
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("distribution {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let reserve_balance = parse_goldilocks_amount(&request.reserve_balance, "reserve balance")?;
    let min_reserve_ratio =
        parse_goldilocks_ratio(&request.min_reserve_ratio, "min reserve ratio")?;
    let max_distribution_per_member = parse_goldilocks_amount(
        &request.max_distribution_per_member,
        "max distribution per member",
    )?;
    let fairness_tolerance =
        parse_goldilocks_amount(&request.fairness_tolerance, "fairness tolerance")?;

    for (index, value) in contributions.iter().enumerate() {
        write_value(
            &mut values,
            format!("cta_contribution_{index}"),
            value.clone(),
        );
    }
    for (index, value) in distributions.iter().enumerate() {
        write_value(
            &mut values,
            format!("cta_distribution_{index}"),
            value.clone(),
        );
    }
    write_value(&mut values, "cta_reserve_balance", reserve_balance.clone());
    write_value(
        &mut values,
        "cta_min_reserve_ratio",
        min_reserve_ratio.clone(),
    );
    write_value(
        &mut values,
        "cta_max_distribution_per_member",
        max_distribution_per_member.clone(),
    );
    write_value(
        &mut values,
        "cta_fairness_tolerance",
        fairness_tolerance.clone(),
    );
    write_value(&mut values, "cta_chain_seed", zero());

    let total_contributions = sum_bigints(&contributions);
    let total_distributions = sum_bigints(&distributions);
    if total_contributions == zero() {
        return Err(ZkfError::InvalidArtifact(
            "cooperative treasury requires nonzero total contributions".to_string(),
        ));
    }
    write_value(
        &mut values,
        "cta_total_contributions",
        total_contributions.clone(),
    );
    write_value(
        &mut values,
        "cta_total_distributions",
        total_distributions.clone(),
    );

    let reserve_ratio_numerator = &reserve_balance * &scale;
    let reserve_ratio = &reserve_ratio_numerator / &total_contributions;
    let reserve_ratio_remainder = &reserve_ratio_numerator % &total_contributions;
    let reserve_ratio_slack = &total_contributions - &reserve_ratio_remainder - one();
    write_exact_division_support(
        &mut values,
        "cta_reserve_ratio",
        &reserve_ratio,
        "cta_reserve_ratio_remainder",
        &reserve_ratio_remainder,
        "cta_reserve_ratio_slack",
        &reserve_ratio_slack,
        "cta_reserve_ratio",
    );
    write_value(
        &mut values,
        "cta_reserve_ratio_floor_slack",
        &reserve_ratio - &min_reserve_ratio,
    );
    let buffer_target = min_reserve_ratio.clone();
    let buffer_ok = reserve_ratio >= buffer_target;
    write_bool_value(&mut values, "cta_buffer_ok", buffer_ok);
    write_nonnegative_bound_support(
        &mut values,
        "cta_buffer_ok_slack",
        &comparator_slack(
            &reserve_ratio,
            &buffer_target,
            &positive_comparison_offset(&scale),
        ),
        &scale,
        "cta_buffer_ok_comparator_slack",
    )?;
    write_bool_value(&mut values, "cta_emergency_mode", !buffer_ok);
    let active_multiplier = if buffer_ok {
        scale.clone()
    } else {
        &scale / two()
    };
    write_value(
        &mut values,
        "cta_active_cap_multiplier",
        active_multiplier.clone(),
    );
    let active_distribution_cap_numerator = &max_distribution_per_member * &active_multiplier;
    let active_distribution_cap = &active_distribution_cap_numerator / &scale;
    let active_distribution_cap_remainder = &active_distribution_cap_numerator % &scale;
    let active_distribution_cap_slack = &scale - &active_distribution_cap_remainder - one();
    write_exact_division_support(
        &mut values,
        "cta_active_distribution_cap",
        &active_distribution_cap,
        "cta_active_distribution_cap_remainder",
        &active_distribution_cap_remainder,
        "cta_active_distribution_cap_slack",
        &active_distribution_cap_slack,
        "cta_active_distribution_cap",
    );
    for (index, distribution) in distributions.iter().enumerate() {
        if *distribution > active_distribution_cap {
            return Err(ZkfError::InvalidArtifact(format!(
                "distribution {index} exceeds the active treasury cap"
            )));
        }
        write_value(
            &mut values,
            format!("cta_distribution_cap_slack_{index}"),
            &active_distribution_cap - distribution,
        );
    }

    let member_count = BigInt::from(members as u64);
    let mean_distribution = &total_distributions / &member_count;
    let mean_distribution_remainder = &total_distributions % &member_count;
    let mean_distribution_slack = &member_count - &mean_distribution_remainder - one();
    write_exact_division_support(
        &mut values,
        "cta_mean_distribution",
        &mean_distribution,
        "cta_mean_distribution_remainder",
        &mean_distribution_remainder,
        "cta_mean_distribution_slack",
        &mean_distribution_slack,
        "cta_mean_distribution",
    );

    let mut sum_squared_deviations = zero();
    for (index, distribution) in distributions.iter().enumerate() {
        let deviation = distribution - &mean_distribution;
        write_value(
            &mut values,
            format!("cta_distribution_deviation_{index}"),
            deviation.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &deviation,
            &sed_goldilocks_amount_bound(),
            &format!("cta_distribution_deviation_{index}"),
        )?;
        sum_squared_deviations += &deviation * &deviation;
    }
    let mean_square_deviation = &sum_squared_deviations / &member_count;
    let mean_square_deviation_remainder = &sum_squared_deviations % &member_count;
    let mean_square_deviation_slack = &member_count - &mean_square_deviation_remainder - one();
    write_exact_division_support(
        &mut values,
        "cta_mean_square_deviation",
        &mean_square_deviation,
        "cta_mean_square_deviation_remainder",
        &mean_square_deviation_remainder,
        "cta_mean_square_deviation_slack",
        &mean_square_deviation_slack,
        "cta_mean_square_deviation",
    );
    let fairness_rms = bigint_isqrt_floor(&mean_square_deviation);
    if fairness_rms > fairness_tolerance {
        return Err(ZkfError::InvalidArtifact(
            "cooperative treasury fairness tolerance exceeded".to_string(),
        ));
    }
    let fairness_rms_remainder = &mean_square_deviation - (&fairness_rms * &fairness_rms);
    let fairness_rms_upper_slack =
        ((&fairness_rms + one()) * (&fairness_rms + one())) - &mean_square_deviation - one();
    write_floor_sqrt_support(
        &mut values,
        "cta_fairness_rms",
        &fairness_rms,
        "cta_fairness_rms_remainder",
        &fairness_rms_remainder,
        "cta_fairness_rms_upper_slack",
        &fairness_rms_upper_slack,
        &sed_goldilocks_score_bound(),
        &sed_goldilocks_score_bound(),
        "cta_fairness_rms",
    )?;
    write_value(
        &mut values,
        "cta_fairness_tolerance_slack",
        fairness_tolerance - &fairness_rms,
    );

    let mut previous_digest = zero();
    for index in 0..members {
        let digest = poseidon_permutation4(
            SED_GOLDILOCKS_FIELD,
            [
                &contributions[index],
                &distributions[index],
                &previous_digest,
                &reserve_ratio,
            ],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("cta_member_commitment_{index}"),
            digest,
        )
        .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &reserve_balance,
            &fairness_rms,
            &active_distribution_cap,
        ],
    )?;
    let treasury_commitment = write_hash_lanes(&mut values, "cta_final_commitment", final_digest);
    values.insert("cta_treasury_commitment".to_string(), treasury_commitment);
    values.insert("cta_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_cooperative_treasury_assurance_program(request)?;
    materialize_seeded_witness(&program, values)
}

pub fn build_community_land_trust_governance_program(
    request: &CommunityLandTrustGovernanceRequestV1,
) -> ZkfResult<Program> {
    validate_equal_lengths(
        "community land trust governance",
        &[
            request.property_values.len(),
            request.equity_shares.len(),
            request.occupancy_flags.len(),
            request.tenure_buckets.len(),
        ],
    )?;
    let households = request.property_values.len();
    let amount_bits = bits_for_bound(&sed_goldilocks_amount_bound());
    let ratio_bits = bits_for_bound(&sed_goldilocks_scale());
    let scale = sed_goldilocks_scale();

    let mut builder = ProgramBuilder::new(
        format!("sovereign_economic_defense_clt_governance_{households}"),
        SED_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "sovereign-economic-defense")?;
    builder.metadata_entry("circuit", "community-land-trust-governance")?;
    builder.metadata_entry("households", households.to_string())?;
    builder.metadata_entry("fixed_point_scale", sed_goldilocks_scale().to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut property_names = Vec::with_capacity(households);
    let mut equity_names = Vec::with_capacity(households);
    let mut occupancy_names = Vec::with_capacity(households);
    let mut tenure_names = Vec::with_capacity(households);
    for index in 0..households {
        let property = format!("clt_property_value_{index}");
        let equity = format!("clt_equity_share_{index}");
        let occupancy = format!("clt_occupancy_flag_{index}");
        let tenure = format!("clt_tenure_bucket_{index}");
        builder.private_input(&property)?;
        builder.private_input(&equity)?;
        builder.private_input(&occupancy)?;
        builder.private_input(&tenure)?;
        builder.constrain_range(&property, amount_bits)?;
        builder.constrain_range(&equity, amount_bits)?;
        builder.constrain_boolean(&occupancy)?;
        builder.constrain_range(&tenure, 3)?;
        builder.append_nonnegative_bound(
            &tenure,
            &BigInt::from(4u8),
            &format!("clt_tenure_bucket_{index}_bound"),
        )?;
        property_names.push(property);
        equity_names.push(equity);
        occupancy_names.push(occupancy);
        tenure_names.push(tenure);
    }
    for input in [
        "clt_maintenance_reserve",
        "clt_min_equity_share",
        "clt_max_equity_concentration",
        "clt_min_maintenance_reserve",
        "clt_required_occupancy_rate",
        "clt_max_rms_equity_deviation",
    ] {
        builder.private_input(input)?;
    }
    builder.constrain_range("clt_maintenance_reserve", amount_bits)?;
    builder.constrain_range("clt_min_equity_share", ratio_bits)?;
    builder.constrain_range("clt_max_equity_concentration", ratio_bits)?;
    builder.constrain_range("clt_min_maintenance_reserve", amount_bits)?;
    builder.constrain_range("clt_required_occupancy_rate", ratio_bits)?;
    builder.constrain_range("clt_max_rms_equity_deviation", ratio_bits)?;
    builder.append_nonnegative_bound(
        "clt_min_maintenance_reserve",
        &sed_goldilocks_amount_bound(),
        "clt_min_maintenance_reserve_bound",
    )?;
    builder.public_output("clt_governance_commitment")?;
    builder.public_output("clt_compliance_bit")?;
    builder.constant_signal("clt_chain_seed", FieldElement::ZERO)?;

    builder.private_signal("clt_total_property_value")?;
    builder.private_signal("clt_total_equity")?;
    builder.private_signal("clt_occupied_units")?;
    builder.private_signal("clt_occupancy_rate")?;
    builder.private_signal("clt_occupancy_rate_remainder")?;
    builder.private_signal("clt_occupancy_rate_slack")?;
    builder.private_signal("clt_reserve_buffer_ok")?;
    builder.private_signal("clt_reserve_buffer_ok_slack")?;
    builder.private_signal("clt_emergency_mode")?;
    builder.private_signal("clt_selected_occupancy_target")?;
    builder.private_signal("clt_mean_square_equity_deviation")?;
    builder.private_signal("clt_mean_square_equity_deviation_remainder")?;
    builder.private_signal("clt_mean_square_equity_deviation_slack")?;
    builder.private_signal("clt_rms_equity_deviation")?;
    builder.private_signal("clt_rms_equity_deviation_remainder")?;
    builder.private_signal("clt_rms_equity_deviation_upper_slack")?;

    builder.constrain_equal(
        signal_expr("clt_total_property_value"),
        sum_exprs(&property_names),
    )?;
    builder.constrain_equal(signal_expr("clt_total_equity"), sum_exprs(&equity_names))?;
    builder.constrain_equal(
        signal_expr("clt_occupied_units"),
        sum_exprs(&occupancy_names),
    )?;
    builder.constrain_nonzero("clt_total_property_value")?;
    builder.constrain_nonzero("clt_total_equity")?;
    builder.constrain_geq(
        "clt_maintenance_reserve_floor_slack",
        signal_expr("clt_maintenance_reserve"),
        signal_expr("clt_min_maintenance_reserve"),
        amount_bits,
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("clt_maintenance_reserve"),
        signal_expr("clt_min_maintenance_reserve"),
        "clt_reserve_buffer_ok",
        "clt_reserve_buffer_ok_slack",
        &positive_comparison_offset(&sed_goldilocks_amount_bound()),
        "clt_reserve_buffer_ok",
    )?;
    append_boolean_not(&mut builder, "clt_emergency_mode", "clt_reserve_buffer_ok")?;
    builder.constrain_select(
        "clt_selected_occupancy_target",
        "clt_emergency_mode",
        add_expr(vec![
            signal_expr("clt_required_occupancy_rate"),
            const_expr(&(sed_goldilocks_scale() / BigInt::from(20u8))),
        ]),
        signal_expr("clt_required_occupancy_rate"),
    )?;
    builder.append_exact_division_constraints(
        mul_expr(
            signal_expr("clt_occupied_units"),
            const_expr(&sed_goldilocks_scale()),
        ),
        const_expr(&BigInt::from(households as u64)),
        "clt_occupancy_rate",
        "clt_occupancy_rate_remainder",
        "clt_occupancy_rate_slack",
        &BigInt::from(households as u64),
        "clt_occupancy_rate",
    )?;
    builder.constrain_geq(
        "clt_occupancy_target_slack",
        signal_expr("clt_occupancy_rate"),
        signal_expr("clt_selected_occupancy_target"),
        ratio_bits,
    )?;
    builder.add_lookup_table(
        "clt_tenure_schedule",
        2,
        vec![
            vec![
                field(BigInt::from(0u8)),
                field(scale.clone() / BigInt::from(20u8)),
            ],
            vec![
                field(BigInt::from(1u8)),
                field(scale.clone() / BigInt::from(10u8)),
            ],
            vec![
                field(BigInt::from(2u8)),
                field(scale.clone() / BigInt::from(5u8)),
            ],
            vec![
                field(BigInt::from(3u8)),
                field(scale.clone() / BigInt::from(4u8)),
            ],
            vec![
                field(BigInt::from(4u8)),
                field(scale.clone() / BigInt::from(3u8)),
            ],
        ],
    )?;

    let mut squared_deviations = Vec::with_capacity(households);
    for index in 0..households {
        let equity_ratio = format!("clt_equity_ratio_{index}");
        let ratio_remainder = format!("clt_equity_ratio_remainder_{index}");
        let ratio_slack = format!("clt_equity_ratio_slack_{index}");
        let target_share = format!("clt_target_share_{index}");
        let deviation = format!("clt_equity_deviation_{index}");
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&equity_names[index]),
                const_expr(&sed_goldilocks_scale()),
            ),
            signal_expr("clt_total_equity"),
            &equity_ratio,
            &ratio_remainder,
            &ratio_slack,
            &sed_goldilocks_amount_bound(),
            &format!("clt_equity_ratio_{index}"),
        )?;
        builder.constrain_geq(
            format!("clt_min_equity_share_slack_{index}"),
            signal_expr(&equity_ratio),
            signal_expr("clt_min_equity_share"),
            ratio_bits,
        )?;
        builder.constrain_leq(
            format!("clt_max_equity_share_slack_{index}"),
            signal_expr(&equity_ratio),
            signal_expr("clt_max_equity_concentration"),
            ratio_bits,
        )?;
        builder.private_signal(&target_share)?;
        builder.constrain_lookup(
            &[
                signal_expr(&tenure_names[index]),
                signal_expr(&target_share),
            ],
            "clt_tenure_schedule",
        )?;
        builder.append_nonnegative_bound(
            &target_share,
            &sed_goldilocks_scale(),
            &format!("clt_target_share_{index}_bound"),
        )?;
        builder.private_signal(&deviation)?;
        builder.constrain_equal(
            signal_expr(&deviation),
            sub_expr(signal_expr(&equity_ratio), signal_expr(&target_share)),
        )?;
        builder.append_signed_bound(
            &deviation,
            &sed_goldilocks_scale(),
            &format!("clt_equity_deviation_{index}"),
        )?;
        squared_deviations.push(mul_expr(signal_expr(&deviation), signal_expr(&deviation)));
    }
    builder.append_exact_division_constraints(
        add_expr(squared_deviations),
        const_expr(&BigInt::from(households as u64)),
        "clt_mean_square_equity_deviation",
        "clt_mean_square_equity_deviation_remainder",
        "clt_mean_square_equity_deviation_slack",
        &BigInt::from(households as u64),
        "clt_mean_square_equity_deviation",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("clt_mean_square_equity_deviation"),
        "clt_rms_equity_deviation",
        "clt_rms_equity_deviation_remainder",
        "clt_rms_equity_deviation_upper_slack",
        &sed_goldilocks_scale(),
        &sed_goldilocks_scale(),
        "clt_rms_equity_deviation",
    )?;
    builder.constrain_leq(
        "clt_rms_equity_deviation_slack",
        signal_expr("clt_rms_equity_deviation"),
        signal_expr("clt_max_rms_equity_deviation"),
        ratio_bits,
    )?;

    let mut previous_digest = signal_expr("clt_chain_seed");
    for index in 0..households {
        let step_digest = builder.append_poseidon_hash(
            &format!("clt_household_commitment_{index}"),
            [
                signal_expr(&property_names[index]),
                signal_expr(&equity_names[index]),
                signal_expr(&occupancy_names[index]),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "clt_final_commitment",
        [
            previous_digest,
            signal_expr("clt_maintenance_reserve"),
            signal_expr("clt_occupancy_rate"),
            signal_expr("clt_rms_equity_deviation"),
        ],
    )?;
    builder.bind("clt_governance_commitment", signal_expr(&final_digest))?;
    builder.bind("clt_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn community_land_trust_governance_witness_from_request(
    request: &CommunityLandTrustGovernanceRequestV1,
) -> ZkfResult<Witness> {
    validate_equal_lengths(
        "community land trust governance",
        &[
            request.property_values.len(),
            request.equity_shares.len(),
            request.occupancy_flags.len(),
            request.tenure_buckets.len(),
        ],
    )?;
    let households = request.property_values.len();
    let scale = sed_goldilocks_scale();
    let mut values = BTreeMap::new();

    let property_values = request
        .property_values
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("property value {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let equity_shares = request
        .equity_shares
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("equity share {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let maintenance_reserve =
        parse_goldilocks_amount(&request.maintenance_reserve, "maintenance reserve")?;
    let min_equity_share =
        parse_goldilocks_ratio(&request.min_equity_share, "minimum equity share")?;
    let max_equity_concentration = parse_goldilocks_ratio(
        &request.max_equity_concentration,
        "maximum equity concentration",
    )?;
    let min_maintenance_reserve = parse_goldilocks_amount(
        &request.min_maintenance_reserve,
        "minimum maintenance reserve",
    )?;
    let required_occupancy_rate =
        parse_goldilocks_ratio(&request.required_occupancy_rate, "required occupancy rate")?;
    let max_rms_equity_deviation = parse_goldilocks_ratio(
        &request.max_rms_equity_deviation,
        "maximum rms equity deviation",
    )?;

    for (index, value) in property_values.iter().enumerate() {
        write_value(
            &mut values,
            format!("clt_property_value_{index}"),
            value.clone(),
        );
    }
    for (index, value) in equity_shares.iter().enumerate() {
        write_value(
            &mut values,
            format!("clt_equity_share_{index}"),
            value.clone(),
        );
    }
    for (index, value) in request.occupancy_flags.iter().enumerate() {
        write_bool_value(&mut values, format!("clt_occupancy_flag_{index}"), *value);
    }
    for (index, value) in request.tenure_buckets.iter().enumerate() {
        if *value > 4 {
            return Err(ZkfError::InvalidArtifact(format!(
                "tenure bucket {index} must be in [0, 4]"
            )));
        }
        write_value(
            &mut values,
            format!("clt_tenure_bucket_{index}"),
            BigInt::from(*value),
        );
    }
    write_value(
        &mut values,
        "clt_maintenance_reserve",
        maintenance_reserve.clone(),
    );
    write_value(
        &mut values,
        "clt_min_equity_share",
        min_equity_share.clone(),
    );
    write_value(
        &mut values,
        "clt_max_equity_concentration",
        max_equity_concentration.clone(),
    );
    write_value(
        &mut values,
        "clt_min_maintenance_reserve",
        min_maintenance_reserve.clone(),
    );
    write_value(
        &mut values,
        "clt_required_occupancy_rate",
        required_occupancy_rate.clone(),
    );
    write_value(
        &mut values,
        "clt_max_rms_equity_deviation",
        max_rms_equity_deviation.clone(),
    );
    write_value(&mut values, "clt_chain_seed", zero());

    let total_property_value = sum_bigints(&property_values);
    let total_equity = sum_bigints(&equity_shares);
    if total_property_value == zero() || total_equity == zero() {
        return Err(ZkfError::InvalidArtifact(
            "community land trust requires nonzero total property value and total equity"
                .to_string(),
        ));
    }
    let occupied_units = BigInt::from(
        request
            .occupancy_flags
            .iter()
            .filter(|occupied| **occupied)
            .count() as u64,
    );
    write_value(
        &mut values,
        "clt_total_property_value",
        total_property_value,
    );
    write_value(&mut values, "clt_total_equity", total_equity.clone());
    write_value(&mut values, "clt_occupied_units", occupied_units.clone());
    if maintenance_reserve < min_maintenance_reserve {
        return Err(ZkfError::InvalidArtifact(
            "maintenance reserve fell below the charter floor".to_string(),
        ));
    }
    write_value(
        &mut values,
        "clt_maintenance_reserve_floor_slack",
        &maintenance_reserve - &min_maintenance_reserve,
    );
    let reserve_buffer_target = min_maintenance_reserve.clone();
    let reserve_buffer_ok = maintenance_reserve >= reserve_buffer_target;
    write_bool_value(&mut values, "clt_reserve_buffer_ok", reserve_buffer_ok);
    write_nonnegative_bound_support(
        &mut values,
        "clt_reserve_buffer_ok_slack",
        &comparator_slack(
            &maintenance_reserve,
            &reserve_buffer_target,
            &positive_comparison_offset(&sed_goldilocks_amount_bound()),
        ),
        &sed_goldilocks_amount_bound(),
        "clt_reserve_buffer_ok_comparator_slack",
    )?;
    write_bool_value(&mut values, "clt_emergency_mode", !reserve_buffer_ok);
    let selected_occupancy_target = if reserve_buffer_ok {
        required_occupancy_rate.clone()
    } else {
        &required_occupancy_rate + (&scale / BigInt::from(20u8))
    };
    write_value(
        &mut values,
        "clt_selected_occupancy_target",
        selected_occupancy_target.clone(),
    );

    let household_count = BigInt::from(households as u64);
    let occupancy_rate_numerator = &occupied_units * &scale;
    let occupancy_rate = &occupancy_rate_numerator / &household_count;
    let occupancy_rate_remainder = &occupancy_rate_numerator % &household_count;
    let occupancy_rate_slack = &household_count - &occupancy_rate_remainder - one();
    if occupancy_rate < selected_occupancy_target {
        return Err(ZkfError::InvalidArtifact(
            "occupancy rate fell below the required floor".to_string(),
        ));
    }
    write_exact_division_support(
        &mut values,
        "clt_occupancy_rate",
        &occupancy_rate,
        "clt_occupancy_rate_remainder",
        &occupancy_rate_remainder,
        "clt_occupancy_rate_slack",
        &occupancy_rate_slack,
        "clt_occupancy_rate",
    );
    write_value(
        &mut values,
        "clt_occupancy_target_slack",
        &occupancy_rate - &selected_occupancy_target,
    );

    let tenure_targets = [
        &scale / BigInt::from(20u8),
        &scale / BigInt::from(10u8),
        &scale / BigInt::from(5u8),
        &scale / BigInt::from(4u8),
        &scale / BigInt::from(3u8),
    ];
    let mut sum_squared_deviations = zero();
    for index in 0..households {
        let equity_ratio_numerator = &equity_shares[index] * &scale;
        let equity_ratio = &equity_ratio_numerator / &total_equity;
        let equity_ratio_remainder = &equity_ratio_numerator % &total_equity;
        let equity_ratio_slack = &total_equity - &equity_ratio_remainder - one();
        if equity_ratio < min_equity_share || equity_ratio > max_equity_concentration {
            return Err(ZkfError::InvalidArtifact(format!(
                "household {index} violates the CLT equity envelope"
            )));
        }
        write_exact_division_support(
            &mut values,
            &format!("clt_equity_ratio_{index}"),
            &equity_ratio,
            &format!("clt_equity_ratio_remainder_{index}"),
            &equity_ratio_remainder,
            &format!("clt_equity_ratio_slack_{index}"),
            &equity_ratio_slack,
            &format!("clt_equity_ratio_{index}"),
        );
        write_value(
            &mut values,
            format!("clt_min_equity_share_slack_{index}"),
            &equity_ratio - &min_equity_share,
        );
        write_value(
            &mut values,
            format!("clt_max_equity_share_slack_{index}"),
            &max_equity_concentration - &equity_ratio,
        );
        let target_share = tenure_targets[request.tenure_buckets[index] as usize].clone();
        write_value(
            &mut values,
            format!("clt_target_share_{index}"),
            target_share.clone(),
        );
        let deviation = &equity_ratio - &target_share;
        write_value(
            &mut values,
            format!("clt_equity_deviation_{index}"),
            deviation.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &deviation,
            &scale,
            &format!("clt_equity_deviation_{index}"),
        )?;
        sum_squared_deviations += &deviation * &deviation;
    }

    let mean_square_equity_deviation = &sum_squared_deviations / &household_count;
    let mean_square_equity_deviation_remainder = &sum_squared_deviations % &household_count;
    let mean_square_equity_deviation_slack =
        &household_count - &mean_square_equity_deviation_remainder - one();
    write_exact_division_support(
        &mut values,
        "clt_mean_square_equity_deviation",
        &mean_square_equity_deviation,
        "clt_mean_square_equity_deviation_remainder",
        &mean_square_equity_deviation_remainder,
        "clt_mean_square_equity_deviation_slack",
        &mean_square_equity_deviation_slack,
        "clt_mean_square_equity_deviation",
    );
    let rms_equity_deviation = bigint_isqrt_floor(&mean_square_equity_deviation);
    if rms_equity_deviation > max_rms_equity_deviation {
        return Err(ZkfError::InvalidArtifact(
            "equity deviation exceeded the CLT RMS threshold".to_string(),
        ));
    }
    let rms_equity_deviation_remainder =
        &mean_square_equity_deviation - (&rms_equity_deviation * &rms_equity_deviation);
    let rms_equity_deviation_upper_slack = ((&rms_equity_deviation + one())
        * (&rms_equity_deviation + one()))
        - &mean_square_equity_deviation
        - one();
    write_floor_sqrt_support(
        &mut values,
        "clt_rms_equity_deviation",
        &rms_equity_deviation,
        "clt_rms_equity_deviation_remainder",
        &rms_equity_deviation_remainder,
        "clt_rms_equity_deviation_upper_slack",
        &rms_equity_deviation_upper_slack,
        &scale,
        &scale,
        "clt_rms_equity_deviation",
    )?;
    write_value(
        &mut values,
        "clt_rms_equity_deviation_slack",
        &max_rms_equity_deviation - &rms_equity_deviation,
    );

    let mut previous_digest = zero();
    for index in 0..households {
        let occupancy_bigint = if request.occupancy_flags[index] {
            one()
        } else {
            zero()
        };
        let digest = poseidon_permutation4(
            SED_GOLDILOCKS_FIELD,
            [
                &property_values[index],
                &equity_shares[index],
                &occupancy_bigint,
                &previous_digest,
            ],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("clt_household_commitment_{index}"),
            digest,
        )
        .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &maintenance_reserve,
            &occupancy_rate,
            &rms_equity_deviation,
        ],
    )?;
    let governance_commitment = write_hash_lanes(&mut values, "clt_final_commitment", final_digest);
    values.insert(
        "clt_governance_commitment".to_string(),
        governance_commitment,
    );
    values.insert("clt_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_community_land_trust_governance_program(request)?;
    materialize_seeded_witness(&program, values)
}

pub fn build_anti_extraction_shield_program(
    request: &AntiExtractionShieldRequestV1,
) -> ZkfResult<Program> {
    if request.interest_rate_components.is_empty() || request.scheduled_payments.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "anti extraction shield requires at least one rate component and one payment"
                .to_string(),
        ));
    }
    let rate_components = request.interest_rate_components.len();
    let payment_count = request.scheduled_payments.len();
    let amount_bits = bits_for_bound(&sed_bn254_amount_bound());
    let ratio_bits = bits_for_bound(&sed_bn254_scale());

    let mut builder = ProgramBuilder::new(
        format!("sovereign_economic_defense_anti_extraction_{payment_count}"),
        SED_BN254_FIELD,
    );
    builder.metadata_entry("application", "sovereign-economic-defense")?;
    builder.metadata_entry("circuit", "anti-extraction-shield")?;
    builder.metadata_entry("payment_count", payment_count.to_string())?;
    builder.metadata_entry("fixed_point_scale", sed_bn254_scale().to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "arkworks-groth16-bn254")?;

    let mut rate_names = Vec::with_capacity(rate_components);
    let mut payment_names = Vec::with_capacity(payment_count);
    for index in 0..rate_components {
        let name = format!("aes_rate_component_{index}");
        builder.private_input(&name)?;
        builder.constrain_range(&name, ratio_bits)?;
        builder.append_nonnegative_bound(
            &name,
            &sed_bn254_scale(),
            &format!("aes_rate_component_{index}_bound"),
        )?;
        rate_names.push(name);
    }
    for index in 0..payment_count {
        let name = format!("aes_payment_{index}");
        builder.private_input(&name)?;
        builder.constrain_range(&name, amount_bits)?;
        payment_names.push(name);
    }
    for input in [
        "aes_principal",
        "aes_balloon_payment",
        "aes_balloon_prohibited",
        "aes_borrower_income_proxy",
        "aes_apr_ceiling",
        "aes_max_debt_to_income_ratio",
        "aes_minimum_term_length",
        "aes_term_length",
        "aes_loan_type_code",
        "aes_term_bucket",
        "aes_marginal_threshold",
        "aes_predatory_threshold",
    ] {
        builder.private_input(input)?;
    }
    builder.constrain_range("aes_principal", amount_bits)?;
    builder.constrain_boolean("aes_balloon_payment")?;
    builder.constrain_boolean("aes_balloon_prohibited")?;
    builder.constrain_range("aes_borrower_income_proxy", amount_bits)?;
    builder.constrain_range("aes_apr_ceiling", ratio_bits)?;
    builder.constrain_range("aes_max_debt_to_income_ratio", ratio_bits)?;
    builder.constrain_range("aes_minimum_term_length", 16)?;
    builder.constrain_range("aes_term_length", 16)?;
    builder.constrain_range("aes_loan_type_code", 1)?;
    builder.constrain_range("aes_term_bucket", 1)?;
    builder.constrain_range("aes_marginal_threshold", ratio_bits)?;
    builder.constrain_range("aes_predatory_threshold", ratio_bits)?;
    builder.append_nonnegative_bound("aes_loan_type_code", &one(), "aes_loan_type_code_bound")?;
    builder.append_nonnegative_bound("aes_term_bucket", &one(), "aes_term_bucket_bound")?;
    builder.public_output("aes_evaluation_commitment")?;
    builder.public_output("aes_predatory_bit")?;
    builder.constant_signal("aes_chain_seed", FieldElement::ZERO)?;

    builder.private_signal("aes_total_rate")?;
    builder.private_signal("aes_effective_apr")?;
    builder.private_signal("aes_effective_apr_remainder")?;
    builder.private_signal("aes_effective_apr_slack")?;
    builder.private_signal("aes_total_payments")?;
    builder.private_signal("aes_average_payment")?;
    builder.private_signal("aes_average_payment_remainder")?;
    builder.private_signal("aes_average_payment_slack")?;
    builder.private_signal("aes_debt_to_income_ratio")?;
    builder.private_signal("aes_debt_to_income_remainder")?;
    builder.private_signal("aes_debt_to_income_slack")?;
    builder.private_signal("aes_lookup_apr_ceiling")?;
    builder.private_signal("aes_balloon_violation")?;
    builder.private_signal("aes_apr_violation_bit")?;
    builder.private_signal("aes_apr_violation_slack")?;
    builder.private_signal("aes_apr_violation_mag")?;
    builder.private_signal("aes_dti_violation_bit")?;
    builder.private_signal("aes_dti_violation_slack")?;
    builder.private_signal("aes_dti_violation_mag")?;
    builder.private_signal("aes_term_violation_bit")?;
    builder.private_signal("aes_term_violation_slack")?;
    builder.private_signal("aes_term_violation_mag")?;
    builder.private_signal("aes_balloon_violation_mag")?;
    builder.private_signal("aes_any_violation_left")?;
    builder.private_signal("aes_any_violation_right")?;
    builder.private_signal("aes_any_violation")?;
    builder.private_signal("aes_mean_square_violation")?;
    builder.private_signal("aes_mean_square_violation_remainder")?;
    builder.private_signal("aes_mean_square_violation_slack")?;
    builder.private_signal("aes_severity_score")?;
    builder.private_signal("aes_severity_score_remainder")?;
    builder.private_signal("aes_severity_score_upper_slack")?;
    builder.private_signal("aes_marginal_bit")?;
    builder.private_signal("aes_marginal_slack")?;
    builder.private_signal("aes_predatory_class_bit")?;
    builder.private_signal("aes_predatory_class_slack")?;
    builder.private_signal("aes_predatory_margin")?;
    builder.private_signal("aes_urgency_score")?;
    builder.private_signal("aes_urgency_score_remainder")?;
    builder.private_signal("aes_urgency_score_slack")?;

    builder.constrain_equal(signal_expr("aes_total_rate"), sum_exprs(&rate_names))?;
    builder.constrain_equal(signal_expr("aes_total_payments"), sum_exprs(&payment_names))?;
    builder.constrain_nonzero("aes_principal")?;
    builder.constrain_nonzero("aes_term_length")?;
    builder.constrain_nonzero("aes_borrower_income_proxy")?;
    builder.append_exact_division_constraints(
        signal_expr("aes_total_rate"),
        signal_expr("aes_term_length"),
        "aes_effective_apr",
        "aes_effective_apr_remainder",
        "aes_effective_apr_slack",
        &BigInt::from(payment_count as u64 + 8),
        "aes_effective_apr",
    )?;
    builder.append_exact_division_constraints(
        signal_expr("aes_total_payments"),
        signal_expr("aes_term_length"),
        "aes_average_payment",
        "aes_average_payment_remainder",
        "aes_average_payment_slack",
        &BigInt::from(payment_count as u64 + 8),
        "aes_average_payment",
    )?;
    builder.append_exact_division_constraints(
        mul_expr(
            signal_expr("aes_average_payment"),
            const_expr(&sed_bn254_scale()),
        ),
        signal_expr("aes_borrower_income_proxy"),
        "aes_debt_to_income_ratio",
        "aes_debt_to_income_remainder",
        "aes_debt_to_income_slack",
        &sed_bn254_amount_bound(),
        "aes_debt_to_income",
    )?;
    builder.add_lookup_table(
        "aes_apr_schedule",
        3,
        vec![
            vec![
                field(BigInt::from(0u8)),
                field(BigInt::from(0u8)),
                field(decimal_scaled(
                    "0.18",
                    SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS,
                )),
            ],
            vec![
                field(BigInt::from(0u8)),
                field(BigInt::from(1u8)),
                field(decimal_scaled(
                    "0.21",
                    SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS,
                )),
            ],
            vec![
                field(BigInt::from(1u8)),
                field(BigInt::from(0u8)),
                field(decimal_scaled(
                    "0.24",
                    SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS,
                )),
            ],
            vec![
                field(BigInt::from(1u8)),
                field(BigInt::from(1u8)),
                field(decimal_scaled(
                    "0.30",
                    SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS,
                )),
            ],
        ],
    )?;
    builder.constrain_lookup(
        &[
            signal_expr("aes_loan_type_code"),
            signal_expr("aes_term_bucket"),
            signal_expr("aes_lookup_apr_ceiling"),
        ],
        "aes_apr_schedule",
    )?;
    builder.append_nonnegative_bound(
        "aes_lookup_apr_ceiling",
        &sed_bn254_scale(),
        "aes_lookup_apr_ceiling_bound",
    )?;
    builder.constrain_equal(
        signal_expr("aes_lookup_apr_ceiling"),
        signal_expr("aes_apr_ceiling"),
    )?;
    builder.constrain_select(
        "aes_balloon_violation",
        "aes_balloon_prohibited",
        signal_expr("aes_balloon_payment"),
        const_expr(&zero()),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr("aes_effective_apr"),
        add_expr(vec![signal_expr("aes_apr_ceiling"), const_expr(&one())]),
        "aes_apr_violation_bit",
        "aes_apr_violation_slack",
        &positive_comparison_offset(&sed_bn254_scale()),
        "aes_apr_violation",
    )?;
    builder.constrain_select(
        "aes_apr_violation_mag",
        "aes_apr_violation_bit",
        sub_expr(
            signal_expr("aes_effective_apr"),
            signal_expr("aes_apr_ceiling"),
        ),
        const_expr(&zero()),
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("aes_debt_to_income_ratio"),
        add_expr(vec![
            signal_expr("aes_max_debt_to_income_ratio"),
            const_expr(&one()),
        ]),
        "aes_dti_violation_bit",
        "aes_dti_violation_slack",
        &positive_comparison_offset(&sed_bn254_scale()),
        "aes_dti_violation",
    )?;
    builder.constrain_select(
        "aes_dti_violation_mag",
        "aes_dti_violation_bit",
        sub_expr(
            signal_expr("aes_debt_to_income_ratio"),
            signal_expr("aes_max_debt_to_income_ratio"),
        ),
        const_expr(&zero()),
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("aes_minimum_term_length"),
        add_expr(vec![signal_expr("aes_term_length"), const_expr(&one())]),
        "aes_term_violation_bit",
        "aes_term_violation_slack",
        &positive_comparison_offset(&BigInt::from(65_535u64)),
        "aes_term_violation",
    )?;
    builder.constrain_select(
        "aes_term_violation_mag",
        "aes_term_violation_bit",
        sub_expr(
            signal_expr("aes_minimum_term_length"),
            signal_expr("aes_term_length"),
        ),
        const_expr(&zero()),
    )?;
    builder.constrain_select(
        "aes_balloon_violation_mag",
        "aes_balloon_violation",
        const_expr(&sed_bn254_scale()),
        const_expr(&zero()),
    )?;
    append_boolean_or(
        &mut builder,
        "aes_any_violation_left",
        "aes_apr_violation_bit",
        "aes_dti_violation_bit",
    )?;
    append_boolean_or(
        &mut builder,
        "aes_any_violation_right",
        "aes_term_violation_bit",
        "aes_balloon_violation",
    )?;
    append_boolean_or(
        &mut builder,
        "aes_any_violation",
        "aes_any_violation_left",
        "aes_any_violation_right",
    )?;
    builder.constrain_equal(signal_expr("aes_any_violation"), const_expr(&one()))?;

    for (signal, bound) in [
        ("aes_apr_violation_mag", sed_bn254_scale()),
        ("aes_dti_violation_mag", sed_bn254_scale()),
        ("aes_term_violation_mag", BigInt::from(65_535u64)),
        ("aes_balloon_violation_mag", sed_bn254_scale()),
    ] {
        builder.append_nonnegative_bound(signal, &bound, signal)?;
    }
    for (signal, bound) in [
        ("aes_effective_apr", sed_bn254_scale()),
        ("aes_debt_to_income_ratio", sed_bn254_scale()),
        ("aes_apr_violation_mag", sed_bn254_scale()),
        ("aes_dti_violation_mag", sed_bn254_scale()),
        ("aes_term_violation_mag", BigInt::from(65_535u64)),
        ("aes_balloon_violation_mag", sed_bn254_scale()),
    ] {
        builder.append_signed_bound(signal, &bound, signal)?;
    }

    builder.append_exact_division_constraints(
        add_expr(vec![
            mul_expr(
                signal_expr("aes_apr_violation_mag"),
                signal_expr("aes_apr_violation_mag"),
            ),
            mul_expr(
                signal_expr("aes_dti_violation_mag"),
                signal_expr("aes_dti_violation_mag"),
            ),
            mul_expr(
                signal_expr("aes_term_violation_mag"),
                signal_expr("aes_term_violation_mag"),
            ),
            mul_expr(
                signal_expr("aes_balloon_violation_mag"),
                signal_expr("aes_balloon_violation_mag"),
            ),
        ]),
        const_expr(&BigInt::from(4u8)),
        "aes_mean_square_violation",
        "aes_mean_square_violation_remainder",
        "aes_mean_square_violation_slack",
        &BigInt::from(4u8),
        "aes_mean_square_violation",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("aes_mean_square_violation"),
        "aes_severity_score",
        "aes_severity_score_remainder",
        "aes_severity_score_upper_slack",
        &sed_bn254_scale(),
        &sed_bn254_scale(),
        "aes_severity_score",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("aes_severity_score"),
        signal_expr("aes_marginal_threshold"),
        "aes_marginal_bit",
        "aes_marginal_slack",
        &positive_comparison_offset(&sed_bn254_scale()),
        "aes_marginal",
    )?;
    builder.private_signal("aes_marginal_bit_anchor")?;
    builder.constrain_equal(
        signal_expr("aes_marginal_bit_anchor"),
        mul_expr(
            signal_expr("aes_marginal_bit"),
            signal_expr("aes_marginal_bit"),
        ),
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("aes_severity_score"),
        signal_expr("aes_predatory_threshold"),
        "aes_predatory_class_bit",
        "aes_predatory_class_slack",
        &positive_comparison_offset(&sed_bn254_scale()),
        "aes_predatory_class",
    )?;
    builder.constrain_equal(signal_expr("aes_predatory_class_bit"), const_expr(&one()))?;
    builder.constrain_geq(
        "aes_predatory_margin",
        signal_expr("aes_severity_score"),
        signal_expr("aes_predatory_threshold"),
        ratio_bits,
    )?;
    builder.append_exact_division_constraints(
        const_expr(&(&sed_bn254_scale() * &sed_bn254_scale())),
        add_expr(vec![
            signal_expr("aes_predatory_margin"),
            const_expr(&one()),
        ]),
        "aes_urgency_score",
        "aes_urgency_score_remainder",
        "aes_urgency_score_slack",
        &sed_bn254_scale(),
        "aes_urgency_score",
    )?;

    for index in 0..payment_count {
        builder.append_poseidon_hash(
            &format!("aes_payment_commitment_{index}"),
            [
                signal_expr(&payment_names[index]),
                signal_expr("aes_effective_apr"),
                signal_expr("aes_debt_to_income_ratio"),
                if index == 0 {
                    signal_expr("aes_chain_seed")
                } else {
                    signal_expr(&format!(
                        "aes_payment_commitment_{}_poseidon_state_0",
                        index - 1
                    ))
                },
            ],
        )?;
    }
    let final_digest = builder.append_poseidon_hash(
        "aes_final_commitment",
        [
            signal_expr("aes_principal"),
            signal_expr("aes_severity_score"),
            signal_expr("aes_urgency_score"),
            signal_expr("aes_predatory_class_bit"),
        ],
    )?;
    builder.bind("aes_evaluation_commitment", signal_expr(&final_digest))?;
    builder.bind("aes_predatory_bit", const_expr(&one()))?;
    builder.build()
}

pub fn anti_extraction_shield_witness_from_request(
    request: &AntiExtractionShieldRequestV1,
) -> ZkfResult<Witness> {
    if request.interest_rate_components.is_empty() || request.scheduled_payments.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "anti extraction shield requires at least one rate component and one payment"
                .to_string(),
        ));
    }
    let scale = sed_bn254_scale();
    let mut values = BTreeMap::new();

    let rate_components = request
        .interest_rate_components
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_ratio(value, &format!("rate component {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let payments = request
        .scheduled_payments
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_amount(value, &format!("payment {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let principal = parse_bn254_amount(&request.principal, "principal")?;
    let borrower_income_proxy =
        parse_bn254_amount(&request.borrower_income_proxy, "borrower income proxy")?;
    let apr_ceiling = parse_bn254_ratio(&request.apr_ceiling, "apr ceiling")?;
    let max_dti = parse_bn254_ratio(
        &request.max_debt_to_income_ratio,
        "maximum debt to income ratio",
    )?;
    let marginal_threshold = parse_bn254_ratio(&request.marginal_threshold, "marginal threshold")?;
    let predatory_threshold =
        parse_bn254_ratio(&request.predatory_threshold, "predatory threshold")?;
    let term_length = BigInt::from(request.scheduled_payments.len() as u64);
    let minimum_term_length = BigInt::from(request.minimum_term_length);

    for (index, value) in rate_components.iter().enumerate() {
        write_value(
            &mut values,
            format!("aes_rate_component_{index}"),
            value.clone(),
        );
    }
    for (index, value) in payments.iter().enumerate() {
        write_value(&mut values, format!("aes_payment_{index}"), value.clone());
    }
    write_value(&mut values, "aes_principal", principal.clone());
    write_bool_value(&mut values, "aes_balloon_payment", request.balloon_payment);
    write_bool_value(
        &mut values,
        "aes_balloon_prohibited",
        request.balloon_prohibited,
    );
    write_value(
        &mut values,
        "aes_borrower_income_proxy",
        borrower_income_proxy.clone(),
    );
    write_value(&mut values, "aes_apr_ceiling", apr_ceiling.clone());
    write_value(&mut values, "aes_max_debt_to_income_ratio", max_dti.clone());
    write_value(
        &mut values,
        "aes_minimum_term_length",
        minimum_term_length.clone(),
    );
    write_value(&mut values, "aes_term_length", term_length.clone());
    write_value(
        &mut values,
        "aes_loan_type_code",
        BigInt::from(request.loan_type_code),
    );
    write_value(
        &mut values,
        "aes_term_bucket",
        BigInt::from(request.term_bucket),
    );
    write_value(
        &mut values,
        "aes_marginal_threshold",
        marginal_threshold.clone(),
    );
    write_value(
        &mut values,
        "aes_predatory_threshold",
        predatory_threshold.clone(),
    );
    write_value(&mut values, "aes_chain_seed", zero());

    if principal == zero() || term_length == zero() || borrower_income_proxy == zero() {
        return Err(ZkfError::InvalidArtifact(
            "principal, term length, and borrower income proxy must all be nonzero".to_string(),
        ));
    }

    let total_rate = sum_bigints(&rate_components);
    let total_payments = sum_bigints(&payments);
    write_value(&mut values, "aes_total_rate", total_rate.clone());
    write_value(&mut values, "aes_total_payments", total_payments.clone());

    let effective_apr = &total_rate / &term_length;
    let effective_apr_remainder = &total_rate % &term_length;
    let effective_apr_slack = &term_length - &effective_apr_remainder - one();
    write_exact_division_support(
        &mut values,
        "aes_effective_apr",
        &effective_apr,
        "aes_effective_apr_remainder",
        &effective_apr_remainder,
        "aes_effective_apr_slack",
        &effective_apr_slack,
        "aes_effective_apr",
    );
    let average_payment = &total_payments / &term_length;
    let average_payment_remainder = &total_payments % &term_length;
    let average_payment_slack = &term_length - &average_payment_remainder - one();
    write_exact_division_support(
        &mut values,
        "aes_average_payment",
        &average_payment,
        "aes_average_payment_remainder",
        &average_payment_remainder,
        "aes_average_payment_slack",
        &average_payment_slack,
        "aes_average_payment",
    );
    let dti_numerator = &average_payment * &scale;
    let debt_to_income_ratio = &dti_numerator / &borrower_income_proxy;
    let debt_to_income_remainder = &dti_numerator % &borrower_income_proxy;
    let debt_to_income_slack = &borrower_income_proxy - &debt_to_income_remainder - one();
    write_exact_division_support(
        &mut values,
        "aes_debt_to_income_ratio",
        &debt_to_income_ratio,
        "aes_debt_to_income_remainder",
        &debt_to_income_remainder,
        "aes_debt_to_income_slack",
        &debt_to_income_slack,
        "aes_debt_to_income",
    );

    let lookup_apr_ceiling = match (request.loan_type_code, request.term_bucket) {
        (0, 0) => decimal_scaled("0.18", SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS),
        (0, 1) => decimal_scaled("0.21", SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS),
        (1, 0) => decimal_scaled("0.24", SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS),
        (1, 1) => decimal_scaled("0.30", SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS),
        _ => {
            return Err(ZkfError::InvalidArtifact(
                "loan type code and term bucket do not match the supported APR schedule"
                    .to_string(),
            ));
        }
    };
    if lookup_apr_ceiling != apr_ceiling {
        return Err(ZkfError::InvalidArtifact(
            "provided APR ceiling does not match the fair-lending schedule".to_string(),
        ));
    }
    write_value(
        &mut values,
        "aes_lookup_apr_ceiling",
        lookup_apr_ceiling.clone(),
    );

    let balloon_violation = request.balloon_payment && request.balloon_prohibited;
    write_bool_value(&mut values, "aes_balloon_violation", balloon_violation);
    let apr_violation = effective_apr > apr_ceiling;
    let apr_violation_mag = if apr_violation {
        &effective_apr - &apr_ceiling
    } else {
        zero()
    };
    write_bool_value(&mut values, "aes_apr_violation_bit", apr_violation);
    write_nonnegative_bound_support(
        &mut values,
        "aes_apr_violation_slack",
        &comparator_slack(
            &effective_apr,
            &(&apr_ceiling + one()),
            &positive_comparison_offset(&scale),
        ),
        &scale,
        "aes_apr_violation_comparator_slack",
    )?;
    write_value(
        &mut values,
        "aes_apr_violation_mag",
        apr_violation_mag.clone(),
    );

    let dti_violation = debt_to_income_ratio > max_dti;
    let dti_violation_mag = if dti_violation {
        &debt_to_income_ratio - &max_dti
    } else {
        zero()
    };
    write_bool_value(&mut values, "aes_dti_violation_bit", dti_violation);
    write_nonnegative_bound_support(
        &mut values,
        "aes_dti_violation_slack",
        &comparator_slack(
            &debt_to_income_ratio,
            &(&max_dti + one()),
            &positive_comparison_offset(&scale),
        ),
        &scale,
        "aes_dti_violation_comparator_slack",
    )?;
    write_value(
        &mut values,
        "aes_dti_violation_mag",
        dti_violation_mag.clone(),
    );

    let term_violation = minimum_term_length > term_length;
    let term_violation_mag = if term_violation {
        &minimum_term_length - &term_length
    } else {
        zero()
    };
    write_bool_value(&mut values, "aes_term_violation_bit", term_violation);
    write_nonnegative_bound_support(
        &mut values,
        "aes_term_violation_slack",
        &comparator_slack(
            &minimum_term_length,
            &(&term_length + one()),
            &positive_comparison_offset(&BigInt::from(65_535u64)),
        ),
        &BigInt::from(65_535u64),
        "aes_term_violation_comparator_slack",
    )?;
    write_value(
        &mut values,
        "aes_term_violation_mag",
        term_violation_mag.clone(),
    );
    let balloon_violation_mag = if balloon_violation {
        scale.clone()
    } else {
        zero()
    };
    write_value(
        &mut values,
        "aes_balloon_violation_mag",
        balloon_violation_mag.clone(),
    );
    let any_violation_left = apr_violation || dti_violation;
    let any_violation_right = term_violation || balloon_violation;
    let any_violation = any_violation_left || any_violation_right;
    if !any_violation {
        return Err(ZkfError::InvalidArtifact(
            "loan does not trigger any fair-lending violation".to_string(),
        ));
    }
    write_bool_value(&mut values, "aes_any_violation_left", any_violation_left);
    write_bool_value(&mut values, "aes_any_violation_right", any_violation_right);
    write_bool_value(&mut values, "aes_any_violation", any_violation);

    for (signal_name, value, bound) in [
        ("aes_apr_violation_mag", &apr_violation_mag, &scale),
        ("aes_dti_violation_mag", &dti_violation_mag, &scale),
        (
            "aes_term_violation_mag",
            &term_violation_mag,
            &BigInt::from(65_535u64),
        ),
        ("aes_balloon_violation_mag", &balloon_violation_mag, &scale),
    ] {
        write_nonnegative_bound_support(&mut values, signal_name, value, bound, signal_name)?;
    }
    for (signal_name, value, bound) in [
        ("aes_apr_violation_mag", &apr_violation_mag, &scale),
        ("aes_dti_violation_mag", &dti_violation_mag, &scale),
        (
            "aes_term_violation_mag",
            &term_violation_mag,
            &BigInt::from(65_535u64),
        ),
        ("aes_balloon_violation_mag", &balloon_violation_mag, &scale),
        ("aes_effective_apr", &effective_apr, &scale),
        ("aes_debt_to_income_ratio", &debt_to_income_ratio, &scale),
    ] {
        write_signed_bound_support(&mut values, value, bound, signal_name)?;
    }

    let sum_squared_violations = (&apr_violation_mag * &apr_violation_mag)
        + (&dti_violation_mag * &dti_violation_mag)
        + (&term_violation_mag * &term_violation_mag)
        + (&balloon_violation_mag * &balloon_violation_mag);
    let mean_square_violation = &sum_squared_violations / BigInt::from(4u8);
    let mean_square_violation_remainder = &sum_squared_violations % BigInt::from(4u8);
    let mean_square_violation_slack = BigInt::from(4u8) - &mean_square_violation_remainder - one();
    write_exact_division_support(
        &mut values,
        "aes_mean_square_violation",
        &mean_square_violation,
        "aes_mean_square_violation_remainder",
        &mean_square_violation_remainder,
        "aes_mean_square_violation_slack",
        &mean_square_violation_slack,
        "aes_mean_square_violation",
    );
    let severity_score = bigint_isqrt_floor(&mean_square_violation);
    let severity_score_remainder = &mean_square_violation - (&severity_score * &severity_score);
    let severity_score_upper_slack =
        ((&severity_score + one()) * (&severity_score + one())) - &mean_square_violation - one();
    write_floor_sqrt_support(
        &mut values,
        "aes_severity_score",
        &severity_score,
        "aes_severity_score_remainder",
        &severity_score_remainder,
        "aes_severity_score_upper_slack",
        &severity_score_upper_slack,
        &scale,
        &scale,
        "aes_severity_score",
    )?;
    let marginal_bit = severity_score >= marginal_threshold;
    let predatory_class_bit = severity_score >= predatory_threshold;
    if !predatory_class_bit {
        return Err(ZkfError::InvalidArtifact(
            "severity score did not reach the predatory threshold".to_string(),
        ));
    }
    write_bool_value(&mut values, "aes_marginal_bit", marginal_bit);
    write_nonnegative_bound_support(
        &mut values,
        "aes_marginal_slack",
        &comparator_slack(
            &severity_score,
            &marginal_threshold,
            &positive_comparison_offset(&scale),
        ),
        &scale,
        "aes_marginal_comparator_slack",
    )?;
    write_bool_value(&mut values, "aes_predatory_class_bit", predatory_class_bit);
    write_nonnegative_bound_support(
        &mut values,
        "aes_predatory_class_slack",
        &comparator_slack(
            &severity_score,
            &predatory_threshold,
            &positive_comparison_offset(&scale),
        ),
        &scale,
        "aes_predatory_class_comparator_slack",
    )?;
    let predatory_margin = &severity_score - &predatory_threshold;
    write_value(
        &mut values,
        "aes_predatory_margin",
        predatory_margin.clone(),
    );
    let urgency_numerator = &scale * &scale;
    let urgency_denominator = &predatory_margin + one();
    let urgency_score = &urgency_numerator / &urgency_denominator;
    let urgency_score_remainder = &urgency_numerator % &urgency_denominator;
    let urgency_score_slack = &urgency_denominator - &urgency_score_remainder - one();
    write_exact_division_support(
        &mut values,
        "aes_urgency_score",
        &urgency_score,
        "aes_urgency_score_remainder",
        &urgency_score_remainder,
        "aes_urgency_score_slack",
        &urgency_score_slack,
        "aes_urgency_score",
    );

    let mut previous_digest = zero();
    for (index, payment) in payments.iter().enumerate() {
        let digest = poseidon_permutation4(
            SED_BN254_FIELD,
            [
                payment,
                &effective_apr,
                &debt_to_income_ratio,
                &previous_digest,
            ],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("aes_payment_commitment_{index}"),
            digest,
        )
        .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        SED_BN254_FIELD,
        [&principal, &severity_score, &urgency_score, &one()],
    )?;
    let evaluation_commitment = write_hash_lanes(&mut values, "aes_final_commitment", final_digest);
    values.insert(
        "aes_evaluation_commitment".to_string(),
        evaluation_commitment,
    );
    values.insert("aes_predatory_bit".to_string(), FieldElement::ONE);
    let program = build_anti_extraction_shield_program(request)?;
    materialize_seeded_witness(&program, values)
}

pub fn build_wealth_trajectory_assurance_program(
    request: &WealthTrajectoryAssuranceRequestV1,
) -> ZkfResult<Program> {
    validate_equal_lengths(
        "wealth trajectory assurance",
        &[
            request.asset_allocations.len(),
            request.return_rates.len(),
            request.target_allocations.len(),
            request.prohibited_flags.len(),
            request.distribution_schedule.len(),
        ],
    )?;
    let assets = request.asset_allocations.len();
    let scale = sed_goldilocks_scale();
    let amount_bits = bits_for_bound(&sed_goldilocks_amount_bound());
    let ratio_bits = bits_for_bound(&scale);

    let mut builder = ProgramBuilder::new(
        format!("sovereign_economic_defense_wealth_trajectory_{assets}"),
        SED_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "sovereign-economic-defense")?;
    builder.metadata_entry("circuit", "wealth-trajectory-assurance")?;
    builder.metadata_entry("asset_count", assets.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut allocation_names = Vec::with_capacity(assets);
    let mut return_names = Vec::with_capacity(assets);
    let mut target_names = Vec::with_capacity(assets);
    let mut prohibited_names = Vec::with_capacity(assets);
    let mut distribution_names = Vec::with_capacity(assets);
    for index in 0..assets {
        let allocation = format!("wta_allocation_{index}");
        let rate = format!("wta_return_rate_{index}");
        let target = format!("wta_target_allocation_{index}");
        let prohibited = format!("wta_prohibited_flag_{index}");
        let distribution = format!("wta_distribution_{index}");
        builder.private_input(&allocation)?;
        builder.private_input(&rate)?;
        builder.private_input(&target)?;
        builder.private_input(&prohibited)?;
        builder.private_input(&distribution)?;
        builder.constrain_range(&allocation, amount_bits)?;
        builder.constrain_range(&rate, ratio_bits)?;
        builder.constrain_range(&target, ratio_bits)?;
        builder.constrain_boolean(&prohibited)?;
        builder.constrain_range(&distribution, amount_bits)?;
        allocation_names.push(allocation);
        return_names.push(rate);
        target_names.push(target);
        prohibited_names.push(prohibited);
        distribution_names.push(distribution);
    }
    for input in [
        "wta_max_single_asset_concentration",
        "wta_max_variance_proxy",
        "wta_min_return_target",
    ] {
        builder.private_input(input)?;
        builder.constrain_range(input, ratio_bits)?;
    }
    builder.public_output("wta_portfolio_commitment")?;
    builder.public_output("wta_compliance_bit")?;
    builder.constant_signal("wta_chain_seed", FieldElement::ZERO)?;

    builder.private_signal("wta_total_portfolio_value")?;
    builder.private_signal("wta_total_distribution_value")?;
    builder.private_signal("wta_portfolio_return")?;
    builder.private_signal("wta_running_max_ratio")?;
    builder.private_signal("wta_penalty_score")?;
    builder.private_signal("wta_penalty_score_remainder")?;
    builder.private_signal("wta_penalty_score_slack")?;
    builder.private_signal("wta_mean_square_variance")?;
    builder.private_signal("wta_mean_square_variance_remainder")?;
    builder.private_signal("wta_mean_square_variance_slack")?;
    builder.private_signal("wta_risk_score")?;
    builder.private_signal("wta_risk_score_remainder")?;
    builder.private_signal("wta_risk_score_upper_slack")?;

    builder.constrain_equal(
        signal_expr("wta_total_portfolio_value"),
        sum_exprs(&allocation_names),
    )?;
    builder.constrain_equal(
        signal_expr("wta_total_distribution_value"),
        sum_exprs(&distribution_names),
    )?;
    builder.constrain_nonzero("wta_total_portfolio_value")?;
    builder.constrain_nonzero("wta_total_distribution_value")?;

    let mut weighted_returns = Vec::with_capacity(assets);
    let mut variance_terms = Vec::with_capacity(assets);
    for index in 0..assets {
        let ratio = format!("wta_allocation_ratio_{index}");
        let ratio_remainder = format!("wta_allocation_ratio_remainder_{index}");
        let ratio_slack = format!("wta_allocation_ratio_slack_{index}");
        let allowed = format!("wta_allowed_allocation_{index}");
        let weighted_return = format!("wta_weighted_return_{index}");
        let weighted_return_remainder = format!("wta_weighted_return_remainder_{index}");
        let weighted_return_slack = format!("wta_weighted_return_slack_{index}");
        let distribution_ratio = format!("wta_distribution_ratio_{index}");
        let distribution_ratio_remainder = format!("wta_distribution_ratio_remainder_{index}");
        let distribution_ratio_slack = format!("wta_distribution_ratio_slack_{index}");
        let deviation = format!("wta_variance_deviation_{index}");

        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&allocation_names[index]), const_expr(&scale)),
            signal_expr("wta_total_portfolio_value"),
            &ratio,
            &ratio_remainder,
            &ratio_slack,
            &sed_goldilocks_amount_bound(),
            &format!("wta_ratio_{index}"),
        )?;
        builder.constrain_leq(
            format!("wta_concentration_slack_{index}"),
            signal_expr(&ratio),
            signal_expr("wta_max_single_asset_concentration"),
            ratio_bits,
        )?;
        builder.constrain_select(
            &allowed,
            &prohibited_names[index],
            const_expr(&zero()),
            signal_expr(&allocation_names[index]),
        )?;
        builder.constrain_equal(signal_expr(&allowed), signal_expr(&allocation_names[index]))?;
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&allocation_names[index]),
                signal_expr(&return_names[index]),
            ),
            signal_expr("wta_total_portfolio_value"),
            &weighted_return,
            &weighted_return_remainder,
            &weighted_return_slack,
            &sed_goldilocks_amount_bound(),
            &format!("wta_weighted_return_{index}"),
        )?;
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&distribution_names[index]), const_expr(&scale)),
            signal_expr("wta_total_distribution_value"),
            &distribution_ratio,
            &distribution_ratio_remainder,
            &distribution_ratio_slack,
            &sed_goldilocks_amount_bound(),
            &format!("wta_distribution_ratio_{index}"),
        )?;
        builder.constrain_equal(
            signal_expr(&distribution_ratio),
            signal_expr(&target_names[index]),
        )?;
        builder.private_signal(&deviation)?;
        builder.constrain_equal(
            signal_expr(&deviation),
            sub_expr(signal_expr(&ratio), signal_expr(&target_names[index])),
        )?;
        builder.append_signed_bound(
            &deviation,
            &scale,
            &format!("wta_variance_deviation_{index}"),
        )?;
        weighted_returns.push(signal_expr(&weighted_return));
        variance_terms.push(mul_expr(signal_expr(&deviation), signal_expr(&deviation)));
    }

    builder.constrain_equal(
        signal_expr("wta_portfolio_return"),
        add_expr(weighted_returns),
    )?;
    builder.constrain_geq(
        "wta_return_target_slack",
        signal_expr("wta_portfolio_return"),
        signal_expr("wta_min_return_target"),
        ratio_bits,
    )?;
    builder.append_exact_division_constraints(
        add_expr(variance_terms),
        const_expr(&BigInt::from(assets as u64)),
        "wta_mean_square_variance",
        "wta_mean_square_variance_remainder",
        "wta_mean_square_variance_slack",
        &BigInt::from(assets as u64),
        "wta_mean_square_variance",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("wta_mean_square_variance"),
        "wta_risk_score",
        "wta_risk_score_remainder",
        "wta_risk_score_upper_slack",
        &scale,
        &scale,
        "wta_risk_score",
    )?;
    builder.constrain_leq(
        "wta_risk_score_slack",
        signal_expr("wta_risk_score"),
        signal_expr("wta_max_variance_proxy"),
        ratio_bits,
    )?;

    if assets == 1 {
        builder.constrain_equal(
            signal_expr("wta_running_max_ratio"),
            signal_expr("wta_allocation_ratio_0"),
        )?;
    } else {
        append_pairwise_max_signal(
            &mut builder,
            "wta_running_max_ratio_1",
            "wta_allocation_ratio_0",
            "wta_allocation_ratio_1",
            &scale,
            "wta_running_max_ratio_1",
        )?;
        for index in 2..assets {
            append_pairwise_max_signal(
                &mut builder,
                &format!("wta_running_max_ratio_{index}"),
                &format!("wta_running_max_ratio_{}", index - 1),
                &format!("wta_allocation_ratio_{index}"),
                &scale,
                &format!("wta_running_max_ratio_{index}"),
            )?;
        }
        builder.constrain_equal(
            signal_expr("wta_running_max_ratio"),
            signal_expr(&format!("wta_running_max_ratio_{}", assets - 1)),
        )?;
    }
    builder.constrain_leq(
        "wta_concentration_headroom",
        signal_expr("wta_running_max_ratio"),
        signal_expr("wta_max_single_asset_concentration"),
        ratio_bits,
    )?;
    builder.append_exact_division_constraints(
        const_expr(&(&scale * &scale)),
        add_expr(vec![
            signal_expr("wta_concentration_headroom"),
            const_expr(&one()),
        ]),
        "wta_penalty_score",
        "wta_penalty_score_remainder",
        "wta_penalty_score_slack",
        &scale,
        "wta_penalty_score",
    )?;

    let mut previous_digest = signal_expr("wta_chain_seed");
    for index in 0..assets {
        let step_digest = builder.append_poseidon_hash(
            &format!("wta_asset_commitment_{index}"),
            [
                signal_expr(&allocation_names[index]),
                signal_expr(&return_names[index]),
                previous_digest.clone(),
                signal_expr(&format!("wta_allocation_ratio_{index}")),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "wta_final_commitment",
        [
            previous_digest,
            signal_expr("wta_portfolio_return"),
            signal_expr("wta_risk_score"),
            signal_expr("wta_penalty_score"),
        ],
    )?;
    builder.bind("wta_portfolio_commitment", signal_expr(&final_digest))?;
    builder.bind("wta_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn wealth_trajectory_assurance_witness_from_request(
    request: &WealthTrajectoryAssuranceRequestV1,
) -> ZkfResult<Witness> {
    validate_equal_lengths(
        "wealth trajectory assurance",
        &[
            request.asset_allocations.len(),
            request.return_rates.len(),
            request.target_allocations.len(),
            request.prohibited_flags.len(),
            request.distribution_schedule.len(),
        ],
    )?;
    let assets = request.asset_allocations.len();
    let scale = sed_goldilocks_scale();
    let mut values = BTreeMap::new();

    let allocations = request
        .asset_allocations
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("allocation {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let return_rates = request
        .return_rates
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_ratio(value, &format!("return rate {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let target_allocations = request
        .target_allocations
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_ratio(value, &format!("target allocation {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let distributions = request
        .distribution_schedule
        .iter()
        .enumerate()
        .map(|(index, value)| parse_goldilocks_amount(value, &format!("distribution {index}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let max_single_asset_concentration = parse_goldilocks_ratio(
        &request.max_single_asset_concentration,
        "max single asset concentration",
    )?;
    let max_variance_proxy =
        parse_goldilocks_ratio(&request.max_variance_proxy, "max variance proxy")?;
    let min_return_target =
        parse_goldilocks_ratio(&request.min_return_target, "minimum return target")?;

    for (index, value) in allocations.iter().enumerate() {
        write_value(
            &mut values,
            format!("wta_allocation_{index}"),
            value.clone(),
        );
    }
    for (index, value) in return_rates.iter().enumerate() {
        write_value(
            &mut values,
            format!("wta_return_rate_{index}"),
            value.clone(),
        );
    }
    for (index, value) in target_allocations.iter().enumerate() {
        write_value(
            &mut values,
            format!("wta_target_allocation_{index}"),
            value.clone(),
        );
    }
    for (index, value) in request.prohibited_flags.iter().enumerate() {
        write_bool_value(&mut values, format!("wta_prohibited_flag_{index}"), *value);
    }
    for (index, value) in distributions.iter().enumerate() {
        write_value(
            &mut values,
            format!("wta_distribution_{index}"),
            value.clone(),
        );
    }
    write_value(
        &mut values,
        "wta_max_single_asset_concentration",
        max_single_asset_concentration.clone(),
    );
    write_value(
        &mut values,
        "wta_max_variance_proxy",
        max_variance_proxy.clone(),
    );
    write_value(
        &mut values,
        "wta_min_return_target",
        min_return_target.clone(),
    );
    write_value(&mut values, "wta_chain_seed", zero());

    let total_portfolio_value = sum_bigints(&allocations);
    let total_distribution_value = sum_bigints(&distributions);
    if total_portfolio_value == zero() || total_distribution_value == zero() {
        return Err(ZkfError::InvalidArtifact(
            "wealth trajectory assurance requires nonzero portfolio value and distribution total"
                .to_string(),
        ));
    }
    write_value(
        &mut values,
        "wta_total_portfolio_value",
        total_portfolio_value.clone(),
    );
    write_value(
        &mut values,
        "wta_total_distribution_value",
        total_distribution_value.clone(),
    );

    let mut portfolio_return = zero();
    let mut running_max_ratio = zero();
    let mut sum_squared_variance = zero();
    for index in 0..assets {
        let allocation_ratio_numerator = &allocations[index] * &scale;
        let allocation_ratio = &allocation_ratio_numerator / &total_portfolio_value;
        let allocation_ratio_remainder = &allocation_ratio_numerator % &total_portfolio_value;
        let allocation_ratio_slack = &total_portfolio_value - &allocation_ratio_remainder - one();
        if allocation_ratio > max_single_asset_concentration {
            return Err(ZkfError::InvalidArtifact(format!(
                "asset {index} exceeded the concentration ceiling"
            )));
        }
        write_exact_division_support(
            &mut values,
            &format!("wta_allocation_ratio_{index}"),
            &allocation_ratio,
            &format!("wta_allocation_ratio_remainder_{index}"),
            &allocation_ratio_remainder,
            &format!("wta_allocation_ratio_slack_{index}"),
            &allocation_ratio_slack,
            &format!("wta_ratio_{index}"),
        );
        write_value(
            &mut values,
            format!("wta_concentration_slack_{index}"),
            &max_single_asset_concentration - &allocation_ratio,
        );
        let allowed_allocation = if request.prohibited_flags[index] {
            if allocations[index] != zero() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "prohibited asset {index} still carried a positive allocation"
                )));
            }
            zero()
        } else {
            allocations[index].clone()
        };
        write_value(
            &mut values,
            format!("wta_allowed_allocation_{index}"),
            allowed_allocation,
        );
        let weighted_return_numerator = &allocations[index] * &return_rates[index];
        let weighted_return = &weighted_return_numerator / &total_portfolio_value;
        let weighted_return_remainder = &weighted_return_numerator % &total_portfolio_value;
        let weighted_return_slack = &total_portfolio_value - &weighted_return_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("wta_weighted_return_{index}"),
            &weighted_return,
            &format!("wta_weighted_return_remainder_{index}"),
            &weighted_return_remainder,
            &format!("wta_weighted_return_slack_{index}"),
            &weighted_return_slack,
            &format!("wta_weighted_return_{index}"),
        );
        portfolio_return += weighted_return;

        let distribution_ratio_numerator = &distributions[index] * &scale;
        let distribution_ratio = &distribution_ratio_numerator / &total_distribution_value;
        let distribution_ratio_remainder =
            &distribution_ratio_numerator % &total_distribution_value;
        let distribution_ratio_slack =
            &total_distribution_value - &distribution_ratio_remainder - one();
        if distribution_ratio != target_allocations[index] {
            return Err(ZkfError::InvalidArtifact(format!(
                "distribution ratio {index} did not match the required schedule"
            )));
        }
        write_exact_division_support(
            &mut values,
            &format!("wta_distribution_ratio_{index}"),
            &distribution_ratio,
            &format!("wta_distribution_ratio_remainder_{index}"),
            &distribution_ratio_remainder,
            &format!("wta_distribution_ratio_slack_{index}"),
            &distribution_ratio_slack,
            &format!("wta_distribution_ratio_{index}"),
        );
        let deviation = &allocation_ratio - &target_allocations[index];
        write_value(
            &mut values,
            format!("wta_variance_deviation_{index}"),
            deviation.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &deviation,
            &scale,
            &format!("wta_variance_deviation_{index}"),
        )?;
        sum_squared_variance += &deviation * &deviation;
        if allocation_ratio > running_max_ratio {
            running_max_ratio = allocation_ratio;
        }
        if index > 0 {
            let left = if index == 1 {
                values["wta_allocation_ratio_0"].as_bigint()
            } else {
                values
                    .get(&format!("wta_running_max_ratio_{}", index - 1))
                    .map(FieldElement::as_bigint)
                    .unwrap_or_else(zero)
            };
            let current_ratio = values[&format!("wta_allocation_ratio_{index}")].as_bigint();
            let geq_bit = left >= current_ratio;
            write_bool_value(
                &mut values,
                format!("wta_running_max_ratio_{index}_geq_bit"),
                geq_bit,
            );
            write_nonnegative_bound_support(
                &mut values,
                format!("wta_running_max_ratio_{index}_geq_slack"),
                &comparator_slack(&left, &current_ratio, &positive_comparison_offset(&scale)),
                &scale,
                &format!("wta_running_max_ratio_{index}_comparator_slack"),
            )?;
            write_nonnegative_bound_support(
                &mut values,
                format!("wta_running_max_ratio_{index}"),
                &running_max_ratio,
                &scale,
                &format!("wta_running_max_ratio_{index}_bound"),
            )?;
        }
    }
    if portfolio_return < min_return_target {
        return Err(ZkfError::InvalidArtifact(
            "portfolio return fell below the minimum target".to_string(),
        ));
    }
    write_value(
        &mut values,
        "wta_portfolio_return",
        portfolio_return.clone(),
    );
    write_value(
        &mut values,
        "wta_return_target_slack",
        &portfolio_return - &min_return_target,
    );
    write_value(
        &mut values,
        "wta_running_max_ratio",
        running_max_ratio.clone(),
    );

    let mean_square_variance = &sum_squared_variance / BigInt::from(assets as u64);
    let mean_square_variance_remainder = &sum_squared_variance % BigInt::from(assets as u64);
    let mean_square_variance_slack =
        BigInt::from(assets as u64) - &mean_square_variance_remainder - one();
    write_exact_division_support(
        &mut values,
        "wta_mean_square_variance",
        &mean_square_variance,
        "wta_mean_square_variance_remainder",
        &mean_square_variance_remainder,
        "wta_mean_square_variance_slack",
        &mean_square_variance_slack,
        "wta_mean_square_variance",
    );
    let risk_score = bigint_isqrt_floor(&mean_square_variance);
    if risk_score > max_variance_proxy {
        return Err(ZkfError::InvalidArtifact(
            "portfolio variance proxy exceeded the risk ceiling".to_string(),
        ));
    }
    let risk_score_remainder = &mean_square_variance - (&risk_score * &risk_score);
    let risk_score_upper_slack =
        ((&risk_score + one()) * (&risk_score + one())) - &mean_square_variance - one();
    write_floor_sqrt_support(
        &mut values,
        "wta_risk_score",
        &risk_score,
        "wta_risk_score_remainder",
        &risk_score_remainder,
        "wta_risk_score_upper_slack",
        &risk_score_upper_slack,
        &scale,
        &scale,
        "wta_risk_score",
    )?;
    write_value(
        &mut values,
        "wta_risk_score_slack",
        &max_variance_proxy - &risk_score,
    );

    if running_max_ratio > max_single_asset_concentration {
        return Err(ZkfError::InvalidArtifact(
            "running max ratio exceeded the concentration ceiling".to_string(),
        ));
    }
    let concentration_headroom = &max_single_asset_concentration - &running_max_ratio;
    write_value(
        &mut values,
        "wta_concentration_headroom",
        concentration_headroom.clone(),
    );
    let penalty_numerator = &scale * &scale;
    let penalty_denominator = &concentration_headroom + one();
    let penalty_score = &penalty_numerator / &penalty_denominator;
    let penalty_score_remainder = &penalty_numerator % &penalty_denominator;
    let penalty_score_slack = &penalty_denominator - &penalty_score_remainder - one();
    write_exact_division_support(
        &mut values,
        "wta_penalty_score",
        &penalty_score,
        "wta_penalty_score_remainder",
        &penalty_score_remainder,
        "wta_penalty_score_slack",
        &penalty_score_slack,
        "wta_penalty_score",
    );

    let mut previous_digest = zero();
    for index in 0..assets {
        let allocation_ratio = values[&format!("wta_allocation_ratio_{index}")].as_bigint();
        let digest = poseidon_permutation4(
            SED_GOLDILOCKS_FIELD,
            [
                &allocations[index],
                &return_rates[index],
                &previous_digest,
                &allocation_ratio,
            ],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("wta_asset_commitment_{index}"),
            digest,
        )
        .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &portfolio_return,
            &risk_score,
            &penalty_score,
        ],
    )?;
    let portfolio_commitment = write_hash_lanes(&mut values, "wta_final_commitment", final_digest);
    values.insert("wta_portfolio_commitment".to_string(), portfolio_commitment);
    values.insert("wta_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_wealth_trajectory_assurance_program(request)?;
    materialize_seeded_witness(&program, values)
}

pub fn build_recirculation_sovereignty_score_program(
    request: &RecirculationSovereigntyScoreRequestV1,
) -> ZkfResult<Program> {
    if request.internal_spend.len() != SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
        || request.external_spend.len() != SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "recirculation sovereignty score requires exactly {} internal and external flow steps",
            SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
        )));
    }
    let steps = SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS;
    let scale = sed_goldilocks_scale();
    let amount_bits = bits_for_bound(&sed_goldilocks_amount_bound());
    let ratio_bits = bits_for_bound(&scale);

    let mut builder = ProgramBuilder::new(
        format!("sovereign_economic_defense_recirculation_sovereignty_{steps}"),
        SED_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "sovereign-economic-defense")?;
    builder.metadata_entry("circuit", "recirculation-sovereignty-score")?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "economic-euler-verlet")?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;
    builder.metadata_entry("gpu_expectation", "metal-threshold-target")?;

    let mut internal_names = Vec::with_capacity(steps);
    let mut external_names = Vec::with_capacity(steps);
    for step in 0..steps {
        let internal = format!("rss_internal_spend_{step}");
        let external = format!("rss_external_spend_{step}");
        builder.private_input(&internal)?;
        builder.private_input(&external)?;
        builder.constrain_range(&internal, amount_bits)?;
        builder.constrain_range(&external, amount_bits)?;
        internal_names.push(internal);
        external_names.push(external);
    }
    for index in 0..4 {
        builder.private_input(format!("rss_circuit_commitment_{index}"))?;
        builder.private_input(format!("rss_circuit_status_{index}"))?;
        builder.constrain_boolean(format!("rss_circuit_status_{index}"))?;
        builder.constrain_equal(
            signal_expr(&format!("rss_circuit_status_{index}")),
            const_expr(&one()),
        )?;
    }
    for input in [
        "rss_initial_circulating_capital",
        "rss_initial_cooperative_equity",
        "rss_initial_asset_ownership_pct",
        "rss_initial_reserve_level",
        "rss_initial_recirculation_rate",
        "rss_recirculation_target",
        "rss_leakage_cap",
        "rss_asset_ownership_goal",
        "rss_reserve_floor",
        "rss_min_investment_return",
        "rss_investment_return_reference",
        "rss_class_d_nominal_margin",
        "rss_class_d_stress_margin",
    ] {
        builder.private_input(input)?;
    }
    for input in [
        "rss_initial_circulating_capital",
        "rss_initial_cooperative_equity",
        "rss_initial_reserve_level",
    ] {
        builder.constrain_range(input, amount_bits)?;
    }
    for input in [
        "rss_initial_asset_ownership_pct",
        "rss_initial_recirculation_rate",
        "rss_recirculation_target",
        "rss_leakage_cap",
        "rss_asset_ownership_goal",
        "rss_min_investment_return",
        "rss_investment_return_reference",
        "rss_class_d_nominal_margin",
        "rss_class_d_stress_margin",
    ] {
        builder.constrain_range(input, ratio_bits)?;
    }
    builder.constrain_range("rss_reserve_floor", amount_bits)?;
    // Nonlinear anchoring: rss_initial_recirculation_rate only appears in a
    // Range constraint and is never referenced by any Equal constraint in the
    // loop (current_recirculation is reassigned before first use).  A
    // self-multiplication makes it nonlinear-participating.
    builder.private_signal("rss_initial_recirculation_rate_nl_sq")?;
    builder.constrain_equal(
        signal_expr("rss_initial_recirculation_rate_nl_sq"),
        mul_expr(
            signal_expr("rss_initial_recirculation_rate"),
            signal_expr("rss_initial_recirculation_rate"),
        ),
    )?;
    builder.public_output("rss_mission_commitment")?;
    builder.public_output("rss_overall_compliance_bit")?;
    builder.public_output("rss_summary_commitment")?;
    builder.constant_signal("rss_chain_seed", FieldElement::ZERO)?;

    let commitment_root = builder.append_poseidon_hash(
        "rss_commitment_root",
        [
            signal_expr("rss_circuit_commitment_0"),
            signal_expr("rss_circuit_commitment_1"),
            signal_expr("rss_circuit_commitment_2"),
            signal_expr("rss_circuit_commitment_3"),
        ],
    )?;
    builder.constrain_geq(
        "rss_investment_return_floor_slack",
        signal_expr("rss_investment_return_reference"),
        signal_expr("rss_min_investment_return"),
        ratio_bits,
    )?;

    let mut current_capital = "rss_initial_circulating_capital".to_string();
    let mut current_equity = "rss_initial_cooperative_equity".to_string();
    let mut current_asset = "rss_initial_asset_ownership_pct".to_string();
    let mut current_reserve = "rss_initial_reserve_level".to_string();
    let mut current_recirculation = "rss_initial_recirculation_rate".to_string();
    let mut previous_digest = signal_expr("rss_chain_seed");

    for step in 0..steps {
        let total_flow = format!("rss_total_flow_{step}");
        let recirculation = format!("rss_recirculation_rate_{step}");
        let recirculation_remainder = format!("rss_recirculation_rate_remainder_{step}");
        let recirculation_slack = format!("rss_recirculation_rate_slack_{step}");
        let leakage = format!("rss_leakage_rate_{step}");
        let leakage_remainder = format!("rss_leakage_rate_remainder_{step}");
        let leakage_slack = format!("rss_leakage_rate_slack_{step}");
        let leakage_buffer_ok = format!("rss_leakage_buffer_ok_{step}");
        let leakage_buffer_ok_slack = format!("rss_leakage_buffer_ok_slack_{step}");
        let stress_mode = format!("rss_stress_mode_{step}");
        let selected_margin = format!("rss_selected_margin_{step}");
        let capital_gain = format!("rss_capital_gain_{step}");
        let capital_gain_remainder = format!("rss_capital_gain_remainder_{step}");
        let capital_gain_slack = format!("rss_capital_gain_slack_{step}");
        let equity_gain = format!("rss_equity_gain_{step}");
        let equity_gain_remainder = format!("rss_equity_gain_remainder_{step}");
        let equity_gain_slack = format!("rss_equity_gain_slack_{step}");
        let asset_gain = format!("rss_asset_gain_{step}");
        let asset_gain_remainder = format!("rss_asset_gain_remainder_{step}");
        let asset_gain_slack = format!("rss_asset_gain_slack_{step}");
        let reserve_gain = format!("rss_reserve_gain_{step}");
        let reserve_gain_remainder = format!("rss_reserve_gain_remainder_{step}");
        let reserve_gain_slack = format!("rss_reserve_gain_slack_{step}");
        let reserve_drain = format!("rss_reserve_drain_{step}");
        let reserve_drain_remainder = format!("rss_reserve_drain_remainder_{step}");
        let reserve_drain_slack = format!("rss_reserve_drain_slack_{step}");
        let next_capital = format!("rss_next_capital_{step}");
        let next_equity = format!("rss_next_equity_{step}");
        let next_asset = format!("rss_next_asset_ownership_{step}");
        let next_reserve = format!("rss_next_reserve_{step}");
        let next_recirculation = format!("rss_next_recirculation_rate_{step}");
        let recirculation_deviation = format!("rss_recirculation_deviation_{step}");
        let asset_deviation = format!("rss_asset_deviation_{step}");
        let reserve_deviation = format!("rss_reserve_deviation_{step}");

        builder.private_signal(&total_flow)?;
        builder.constrain_equal(
            signal_expr(&total_flow),
            add_expr(vec![
                signal_expr(&internal_names[step]),
                signal_expr(&external_names[step]),
            ]),
        )?;
        builder.constrain_nonzero(&total_flow)?;
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&internal_names[step]), const_expr(&scale)),
            signal_expr(&total_flow),
            &recirculation,
            &recirculation_remainder,
            &recirculation_slack,
            &sed_goldilocks_amount_bound(),
            &format!("rss_recirculation_rate_{step}"),
        )?;
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&external_names[step]), const_expr(&scale)),
            signal_expr(&total_flow),
            &leakage,
            &leakage_remainder,
            &leakage_slack,
            &sed_goldilocks_amount_bound(),
            &format!("rss_leakage_rate_{step}"),
        )?;
        builder.constrain_geq(
            format!("rss_recirculation_target_slack_{step}"),
            signal_expr(&recirculation),
            signal_expr("rss_recirculation_target"),
            ratio_bits,
        )?;
        builder.constrain_leq(
            format!("rss_leakage_cap_slack_{step}"),
            signal_expr(&leakage),
            signal_expr("rss_leakage_cap"),
            ratio_bits,
        )?;
        append_geq_comparator_bit(
            &mut builder,
            signal_expr("rss_leakage_cap"),
            add_expr(vec![
                signal_expr(&leakage),
                signal_expr("rss_class_d_nominal_margin"),
            ]),
            &leakage_buffer_ok,
            &leakage_buffer_ok_slack,
            &positive_comparison_offset(&scale),
            &format!("rss_leakage_buffer_ok_{step}"),
        )?;
        append_boolean_not(&mut builder, &stress_mode, &leakage_buffer_ok)?;
        builder.constrain_select(
            &selected_margin,
            &stress_mode,
            signal_expr("rss_class_d_stress_margin"),
            signal_expr("rss_class_d_nominal_margin"),
        )?;
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&internal_names[step]),
                signal_expr(&selected_margin),
            ),
            const_expr(&scale),
            &capital_gain,
            &capital_gain_remainder,
            &capital_gain_slack,
            &scale,
            &format!("rss_capital_gain_{step}"),
        )?;
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&capital_gain),
                signal_expr("rss_investment_return_reference"),
            ),
            const_expr(&scale),
            &equity_gain,
            &equity_gain_remainder,
            &equity_gain_slack,
            &scale,
            &format!("rss_equity_gain_{step}"),
        )?;
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&internal_names[step]),
                signal_expr(&selected_margin),
            ),
            const_expr(&(scale.clone() * BigInt::from(20u8))),
            &asset_gain,
            &asset_gain_remainder,
            &asset_gain_slack,
            &(scale.clone() * BigInt::from(20u8)),
            &format!("rss_asset_gain_{step}"),
        )?;
        builder.append_exact_division_constraints(
            signal_expr(&internal_names[step]),
            const_expr(&BigInt::from(8u8)),
            &reserve_gain,
            &reserve_gain_remainder,
            &reserve_gain_slack,
            &BigInt::from(8u8),
            &format!("rss_reserve_gain_{step}"),
        )?;
        builder.append_exact_division_constraints(
            signal_expr(&external_names[step]),
            const_expr(&BigInt::from(16u8)),
            &reserve_drain,
            &reserve_drain_remainder,
            &reserve_drain_slack,
            &BigInt::from(16u8),
            &format!("rss_reserve_drain_{step}"),
        )?;
        // Nonlinear anchoring for reserve_gain and reserve_drain: these quotients
        // arise from division by a constant, so all their constraints are linear.
        // A self-multiplication constraint makes them nonlinear-participating.
        let reserve_gain_sq = format!("rss_reserve_gain_sq_{step}");
        builder.private_signal(&reserve_gain_sq)?;
        builder.constrain_equal(
            signal_expr(&reserve_gain_sq),
            mul_expr(signal_expr(&reserve_gain), signal_expr(&reserve_gain)),
        )?;
        let reserve_drain_sq = format!("rss_reserve_drain_sq_{step}");
        builder.private_signal(&reserve_drain_sq)?;
        builder.constrain_equal(
            signal_expr(&reserve_drain_sq),
            mul_expr(signal_expr(&reserve_drain), signal_expr(&reserve_drain)),
        )?;
        builder.private_signal(&next_capital)?;
        builder.private_signal(&next_equity)?;
        builder.private_signal(&next_asset)?;
        builder.private_signal(&next_reserve)?;
        builder.private_signal(&next_recirculation)?;
        builder.constrain_equal(
            signal_expr(&next_capital),
            sub_expr(
                add_expr(vec![
                    signal_expr(&current_capital),
                    signal_expr(&capital_gain),
                ]),
                signal_expr(&external_names[step]),
            ),
        )?;
        builder.constrain_equal(
            signal_expr(&next_equity),
            add_expr(vec![
                signal_expr(&current_equity),
                signal_expr(&equity_gain),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_asset),
            add_expr(vec![signal_expr(&current_asset), signal_expr(&asset_gain)]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_reserve),
            sub_expr(
                add_expr(vec![
                    signal_expr(&current_reserve),
                    signal_expr(&reserve_gain),
                ]),
                signal_expr(&reserve_drain),
            ),
        )?;
        builder.constrain_equal(
            signal_expr(&next_recirculation),
            signal_expr(&recirculation),
        )?;
        builder.constrain_geq(
            format!("rss_reserve_floor_slack_{step}"),
            signal_expr(&next_reserve),
            signal_expr("rss_reserve_floor"),
            amount_bits,
        )?;
        builder.private_signal(&recirculation_deviation)?;
        builder.private_signal(&asset_deviation)?;
        builder.private_signal(&reserve_deviation)?;
        builder.constrain_equal(
            signal_expr(&recirculation_deviation),
            sub_expr(
                signal_expr(&recirculation),
                signal_expr("rss_recirculation_target"),
            ),
        )?;
        builder.constrain_equal(
            signal_expr(&asset_deviation),
            sub_expr(
                signal_expr(&next_asset),
                signal_expr("rss_asset_ownership_goal"),
            ),
        )?;
        builder.constrain_equal(
            signal_expr(&reserve_deviation),
            sub_expr(signal_expr(&next_reserve), signal_expr("rss_reserve_floor")),
        )?;
        builder.append_signed_bound(
            &recirculation_deviation,
            &scale,
            &format!("rss_recirculation_deviation_{step}"),
        )?;
        builder.append_signed_bound(
            &asset_deviation,
            &scale,
            &format!("rss_asset_deviation_{step}"),
        )?;
        builder.append_signed_bound(
            &reserve_deviation,
            &sed_goldilocks_amount_bound(),
            &format!("rss_reserve_deviation_{step}"),
        )?;
        let state_hi = builder.append_poseidon_hash(
            &format!("rss_step_state_hi_{step}"),
            [
                signal_expr(&current_capital),
                signal_expr(&current_equity),
                signal_expr(&current_asset),
                signal_expr(&current_reserve),
            ],
        )?;
        let step_chain = builder.append_poseidon_hash(
            &format!("rss_step_chain_{step}"),
            [
                signal_expr(&state_hi),
                signal_expr(&recirculation),
                previous_digest.clone(),
                const_expr(&BigInt::from(step as u64)),
            ],
        )?;
        previous_digest = signal_expr(&step_chain);
        current_capital = next_capital;
        current_equity = next_equity;
        current_asset = next_asset;
        current_reserve = next_reserve;
        current_recirculation = next_recirculation;
    }

    // Nonlinear anchoring: rss_next_equity_95 (current_equity after the
    // loop) is never referenced in the finalization section—only capital,
    // asset, reserve, and recirculation are used.  Anchor it with a
    // self-multiplication so it becomes nonlinear-participating.
    let equity_nl_sq = format!("{}_nl_sq", current_equity);
    builder.private_signal(&equity_nl_sq)?;
    builder.constrain_equal(
        signal_expr(&equity_nl_sq),
        mul_expr(signal_expr(&current_equity), signal_expr(&current_equity)),
    )?;

    builder.append_exact_division_constraints(
        add_expr(vec![
            mul_expr(
                sub_expr(
                    signal_expr(&current_recirculation),
                    signal_expr("rss_recirculation_target"),
                ),
                sub_expr(
                    signal_expr(&current_recirculation),
                    signal_expr("rss_recirculation_target"),
                ),
            ),
            mul_expr(
                sub_expr(
                    signal_expr(&current_asset),
                    signal_expr("rss_asset_ownership_goal"),
                ),
                sub_expr(
                    signal_expr(&current_asset),
                    signal_expr("rss_asset_ownership_goal"),
                ),
            ),
            mul_expr(
                sub_expr(
                    signal_expr(&current_reserve),
                    signal_expr("rss_reserve_floor"),
                ),
                sub_expr(
                    signal_expr(&current_reserve),
                    signal_expr("rss_reserve_floor"),
                ),
            ),
            mul_expr(
                sub_expr(
                    signal_expr("rss_investment_return_reference"),
                    signal_expr("rss_min_investment_return"),
                ),
                sub_expr(
                    signal_expr("rss_investment_return_reference"),
                    signal_expr("rss_min_investment_return"),
                ),
            ),
        ]),
        const_expr(&BigInt::from(4u8)),
        "rss_mean_square_sovereignty_gap",
        "rss_mean_square_sovereignty_gap_remainder",
        "rss_mean_square_sovereignty_gap_slack",
        &BigInt::from(4u8),
        "rss_mean_square_sovereignty_gap",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("rss_mean_square_sovereignty_gap"),
        "rss_sovereignty_score",
        "rss_sovereignty_score_remainder",
        "rss_sovereignty_score_upper_slack",
        &sed_goldilocks_amount_bound(),
        &sed_goldilocks_amount_bound(),
        "rss_sovereignty_score",
    )?;
    let summary_commitment = builder.append_poseidon_hash(
        "rss_summary_commitment_internal",
        [
            signal_expr(&current_recirculation),
            signal_expr(&current_asset),
            signal_expr(&current_reserve),
            signal_expr("rss_sovereignty_score"),
        ],
    )?;
    let mission_commitment = builder.append_poseidon_hash(
        "rss_mission_commitment_internal",
        [
            previous_digest,
            signal_expr(&commitment_root),
            signal_expr(&current_capital),
            signal_expr("rss_sovereignty_score"),
        ],
    )?;
    builder.bind("rss_mission_commitment", signal_expr(&mission_commitment))?;
    builder.bind("rss_summary_commitment", signal_expr(&summary_commitment))?;
    builder.bind("rss_overall_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn recirculation_sovereignty_score_witness_from_request(
    request: &RecirculationSovereigntyScoreRequestV1,
) -> ZkfResult<Witness> {
    if request.internal_spend.len() != SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
        || request.external_spend.len() != SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "recirculation sovereignty score requires exactly {} internal and external flow steps",
            SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS
        )));
    }
    let steps = SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS;
    let scale = sed_goldilocks_scale();
    let mut values = BTreeMap::new();

    let internal_spend = request
        .internal_spend
        .iter()
        .enumerate()
        .map(|(step, value)| parse_goldilocks_amount(value, &format!("internal spend {step}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let external_spend = request
        .external_spend
        .iter()
        .enumerate()
        .map(|(step, value)| parse_goldilocks_amount(value, &format!("external spend {step}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let commitments = request
        .circuit_commitments
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_nonnegative_integer(value, &format!("circuit commitment {index}"))
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let initial_circulating_capital = parse_goldilocks_amount(
        &request.initial_circulating_capital,
        "initial circulating capital",
    )?;
    let initial_cooperative_equity = parse_goldilocks_amount(
        &request.initial_cooperative_equity,
        "initial cooperative equity",
    )?;
    let initial_asset_ownership_pct = parse_goldilocks_ratio(
        &request.initial_asset_ownership_pct,
        "initial asset ownership percentage",
    )?;
    let initial_reserve_level =
        parse_goldilocks_amount(&request.initial_reserve_level, "initial reserve level")?;
    let initial_recirculation_rate = parse_goldilocks_ratio(
        &request.initial_recirculation_rate,
        "initial recirculation rate",
    )?;
    let recirculation_target =
        parse_goldilocks_ratio(&request.recirculation_target, "recirculation target")?;
    let leakage_cap = parse_goldilocks_ratio(&request.leakage_cap, "leakage cap")?;
    let asset_ownership_goal =
        parse_goldilocks_ratio(&request.asset_ownership_goal, "asset ownership goal")?;
    let reserve_floor = parse_goldilocks_amount(&request.reserve_floor, "reserve floor")?;
    let min_investment_return =
        parse_goldilocks_ratio(&request.min_investment_return, "minimum investment return")?;
    let investment_return_reference = parse_goldilocks_ratio(
        &request.investment_return_reference,
        "investment return reference",
    )?;
    let class_d_nominal_margin =
        parse_goldilocks_ratio(&request.class_d_nominal_margin, "class d nominal margin")?;
    let class_d_stress_margin =
        parse_goldilocks_ratio(&request.class_d_stress_margin, "class d stress margin")?;

    for (step, value) in internal_spend.iter().enumerate() {
        write_value(
            &mut values,
            format!("rss_internal_spend_{step}"),
            value.clone(),
        );
    }
    for (step, value) in external_spend.iter().enumerate() {
        write_value(
            &mut values,
            format!("rss_external_spend_{step}"),
            value.clone(),
        );
    }
    for (index, commitment) in commitments.iter().enumerate() {
        write_value(
            &mut values,
            format!("rss_circuit_commitment_{index}"),
            commitment.clone(),
        );
    }
    for (index, status) in request.circuit_status_bits.iter().enumerate() {
        if !*status {
            return Err(ZkfError::InvalidArtifact(format!(
                "subcircuit status bit {index} must be true before integration"
            )));
        }
        write_bool_value(&mut values, format!("rss_circuit_status_{index}"), *status);
    }
    for (name, value) in [
        (
            "rss_initial_circulating_capital",
            &initial_circulating_capital,
        ),
        (
            "rss_initial_cooperative_equity",
            &initial_cooperative_equity,
        ),
        (
            "rss_initial_asset_ownership_pct",
            &initial_asset_ownership_pct,
        ),
        ("rss_initial_reserve_level", &initial_reserve_level),
        (
            "rss_initial_recirculation_rate",
            &initial_recirculation_rate,
        ),
        ("rss_recirculation_target", &recirculation_target),
        ("rss_leakage_cap", &leakage_cap),
        ("rss_asset_ownership_goal", &asset_ownership_goal),
        ("rss_reserve_floor", &reserve_floor),
        ("rss_min_investment_return", &min_investment_return),
        (
            "rss_investment_return_reference",
            &investment_return_reference,
        ),
        ("rss_class_d_nominal_margin", &class_d_nominal_margin),
        ("rss_class_d_stress_margin", &class_d_stress_margin),
    ] {
        write_value(&mut values, name, value.clone());
    }
    write_value(&mut values, "rss_chain_seed", zero());
    write_value(
        &mut values,
        "rss_initial_recirculation_rate_nl_sq",
        &initial_recirculation_rate * &initial_recirculation_rate,
    );

    if investment_return_reference < min_investment_return {
        return Err(ZkfError::InvalidArtifact(
            "investment return reference fell below the minimum target".to_string(),
        ));
    }
    write_value(
        &mut values,
        "rss_investment_return_floor_slack",
        &investment_return_reference - &min_investment_return,
    );
    let commitment_root = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &commitments[0],
            &commitments[1],
            &commitments[2],
            &commitments[3],
        ],
    )?;
    let commitment_root_lane =
        write_hash_lanes(&mut values, "rss_commitment_root", commitment_root);

    let mut current_capital = initial_circulating_capital.clone();
    let mut current_equity = initial_cooperative_equity.clone();
    let mut current_asset = initial_asset_ownership_pct.clone();
    let mut current_reserve = initial_reserve_level.clone();
    let mut current_recirculation = initial_recirculation_rate.clone();
    let mut previous_digest = zero();

    for step in 0..steps {
        let total_flow = &internal_spend[step] + &external_spend[step];
        if total_flow == zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "integration step {step} had zero total flow"
            )));
        }
        write_value(
            &mut values,
            format!("rss_total_flow_{step}"),
            total_flow.clone(),
        );
        let recirculation_numerator = &internal_spend[step] * &scale;
        let recirculation_rate = &recirculation_numerator / &total_flow;
        let recirculation_remainder = &recirculation_numerator % &total_flow;
        let recirculation_slack = &total_flow - &recirculation_remainder - one();
        if recirculation_rate < recirculation_target {
            return Err(ZkfError::InvalidArtifact(format!(
                "integration step {step} violated the recirculation floor"
            )));
        }
        write_exact_division_support(
            &mut values,
            &format!("rss_recirculation_rate_{step}"),
            &recirculation_rate,
            &format!("rss_recirculation_rate_remainder_{step}"),
            &recirculation_remainder,
            &format!("rss_recirculation_rate_slack_{step}"),
            &recirculation_slack,
            &format!("rss_recirculation_rate_{step}"),
        );
        write_value(
            &mut values,
            format!("rss_recirculation_target_slack_{step}"),
            &recirculation_rate - &recirculation_target,
        );

        let leakage_numerator = &external_spend[step] * &scale;
        let leakage_rate = &leakage_numerator / &total_flow;
        let leakage_remainder = &leakage_numerator % &total_flow;
        let leakage_slack = &total_flow - &leakage_remainder - one();
        if leakage_rate > leakage_cap {
            return Err(ZkfError::InvalidArtifact(format!(
                "integration step {step} exceeded the leakage cap"
            )));
        }
        write_exact_division_support(
            &mut values,
            &format!("rss_leakage_rate_{step}"),
            &leakage_rate,
            &format!("rss_leakage_rate_remainder_{step}"),
            &leakage_remainder,
            &format!("rss_leakage_rate_slack_{step}"),
            &leakage_slack,
            &format!("rss_leakage_rate_{step}"),
        );
        write_value(
            &mut values,
            format!("rss_leakage_cap_slack_{step}"),
            &leakage_cap - &leakage_rate,
        );

        let leakage_buffer_target = &leakage_rate + &class_d_nominal_margin;
        let leakage_buffer_ok = leakage_cap >= leakage_buffer_target;
        write_bool_value(
            &mut values,
            format!("rss_leakage_buffer_ok_{step}"),
            leakage_buffer_ok,
        );
        write_nonnegative_bound_support(
            &mut values,
            format!("rss_leakage_buffer_ok_slack_{step}"),
            &comparator_slack(
                &leakage_cap,
                &leakage_buffer_target,
                &positive_comparison_offset(&scale),
            ),
            &scale,
            &format!("rss_leakage_buffer_ok_{step}_comparator_slack"),
        )?;
        let stress_mode = !leakage_buffer_ok;
        write_bool_value(&mut values, format!("rss_stress_mode_{step}"), stress_mode);
        let selected_margin = if stress_mode {
            class_d_stress_margin.clone()
        } else {
            class_d_nominal_margin.clone()
        };
        write_value(
            &mut values,
            format!("rss_selected_margin_{step}"),
            selected_margin.clone(),
        );

        let capital_gain_numerator = &internal_spend[step] * &selected_margin;
        let capital_gain = &capital_gain_numerator / &scale;
        let capital_gain_remainder = &capital_gain_numerator % &scale;
        let capital_gain_slack = &scale - &capital_gain_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("rss_capital_gain_{step}"),
            &capital_gain,
            &format!("rss_capital_gain_remainder_{step}"),
            &capital_gain_remainder,
            &format!("rss_capital_gain_slack_{step}"),
            &capital_gain_slack,
            &format!("rss_capital_gain_{step}"),
        );
        let equity_gain_numerator = &capital_gain * &investment_return_reference;
        let equity_gain = &equity_gain_numerator / &scale;
        let equity_gain_remainder = &equity_gain_numerator % &scale;
        let equity_gain_slack = &scale - &equity_gain_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("rss_equity_gain_{step}"),
            &equity_gain,
            &format!("rss_equity_gain_remainder_{step}"),
            &equity_gain_remainder,
            &format!("rss_equity_gain_slack_{step}"),
            &equity_gain_slack,
            &format!("rss_equity_gain_{step}"),
        );
        let asset_gain_denominator = &scale * BigInt::from(20u8);
        let asset_gain_numerator = &internal_spend[step] * &selected_margin;
        let asset_gain = &asset_gain_numerator / &asset_gain_denominator;
        let asset_gain_remainder = &asset_gain_numerator % &asset_gain_denominator;
        let asset_gain_slack = &asset_gain_denominator - &asset_gain_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("rss_asset_gain_{step}"),
            &asset_gain,
            &format!("rss_asset_gain_remainder_{step}"),
            &asset_gain_remainder,
            &format!("rss_asset_gain_slack_{step}"),
            &asset_gain_slack,
            &format!("rss_asset_gain_{step}"),
        );
        let reserve_gain = &internal_spend[step] / BigInt::from(8u8);
        let reserve_gain_remainder = &internal_spend[step] % BigInt::from(8u8);
        let reserve_gain_slack = BigInt::from(8u8) - &reserve_gain_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("rss_reserve_gain_{step}"),
            &reserve_gain,
            &format!("rss_reserve_gain_remainder_{step}"),
            &reserve_gain_remainder,
            &format!("rss_reserve_gain_slack_{step}"),
            &reserve_gain_slack,
            &format!("rss_reserve_gain_{step}"),
        );
        let reserve_drain = &external_spend[step] / BigInt::from(16u8);
        let reserve_drain_remainder = &external_spend[step] % BigInt::from(16u8);
        let reserve_drain_slack = BigInt::from(16u8) - &reserve_drain_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("rss_reserve_drain_{step}"),
            &reserve_drain,
            &format!("rss_reserve_drain_remainder_{step}"),
            &reserve_drain_remainder,
            &format!("rss_reserve_drain_slack_{step}"),
            &reserve_drain_slack,
            &format!("rss_reserve_drain_{step}"),
        );
        write_value(
            &mut values,
            format!("rss_reserve_gain_sq_{step}"),
            &reserve_gain * &reserve_gain,
        );
        write_value(
            &mut values,
            format!("rss_reserve_drain_sq_{step}"),
            &reserve_drain * &reserve_drain,
        );

        let next_capital = &current_capital + &capital_gain - &external_spend[step];
        let next_equity = &current_equity + &equity_gain;
        let next_asset = &current_asset + &asset_gain;
        let next_reserve = &current_reserve + &reserve_gain - &reserve_drain;
        if next_capital < zero() || next_reserve < reserve_floor {
            return Err(ZkfError::InvalidArtifact(format!(
                "integration step {step} crossed a fail-closed economic envelope"
            )));
        }
        write_value(
            &mut values,
            format!("rss_next_capital_{step}"),
            next_capital.clone(),
        );
        write_value(
            &mut values,
            format!("rss_next_equity_{step}"),
            next_equity.clone(),
        );
        write_value(
            &mut values,
            format!("rss_next_asset_ownership_{step}"),
            next_asset.clone(),
        );
        write_value(
            &mut values,
            format!("rss_next_reserve_{step}"),
            next_reserve.clone(),
        );
        write_value(
            &mut values,
            format!("rss_next_recirculation_rate_{step}"),
            recirculation_rate.clone(),
        );
        write_value(
            &mut values,
            format!("rss_reserve_floor_slack_{step}"),
            &next_reserve - &reserve_floor,
        );

        let recirculation_deviation = &recirculation_rate - &recirculation_target;
        let asset_deviation = &next_asset - &asset_ownership_goal;
        let reserve_deviation = &next_reserve - &reserve_floor;
        write_value(
            &mut values,
            format!("rss_recirculation_deviation_{step}"),
            recirculation_deviation.clone(),
        );
        write_value(
            &mut values,
            format!("rss_asset_deviation_{step}"),
            asset_deviation.clone(),
        );
        write_value(
            &mut values,
            format!("rss_reserve_deviation_{step}"),
            reserve_deviation.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &recirculation_deviation,
            &scale,
            &format!("rss_recirculation_deviation_{step}"),
        )?;
        write_signed_bound_support(
            &mut values,
            &asset_deviation,
            &scale,
            &format!("rss_asset_deviation_{step}"),
        )?;
        write_signed_bound_support(
            &mut values,
            &reserve_deviation,
            &sed_goldilocks_amount_bound(),
            &format!("rss_reserve_deviation_{step}"),
        )?;

        let state_hi = poseidon_permutation4(
            SED_GOLDILOCKS_FIELD,
            [
                &current_capital,
                &current_equity,
                &current_asset,
                &current_reserve,
            ],
        )?;
        let state_hi_lane =
            write_hash_lanes(&mut values, &format!("rss_step_state_hi_{step}"), state_hi)
                .as_bigint();
        let step_chain = poseidon_permutation4(
            SED_GOLDILOCKS_FIELD,
            [
                &state_hi_lane,
                &recirculation_rate,
                &previous_digest,
                &BigInt::from(step as u64),
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("rss_step_chain_{step}"), step_chain)
                .as_bigint();

        current_capital = next_capital;
        current_equity = next_equity;
        current_asset = next_asset;
        current_reserve = next_reserve;
        current_recirculation = recirculation_rate;
    }

    write_value(
        &mut values,
        format!("{}_nl_sq", format!("rss_next_equity_{}", steps - 1)),
        &current_equity * &current_equity,
    );

    let final_return_gap = &investment_return_reference - &min_investment_return;
    let sum_squared_gap = (&(&current_recirculation - &recirculation_target)
        * &(&current_recirculation - &recirculation_target))
        + (&(&current_asset - &asset_ownership_goal) * &(&current_asset - &asset_ownership_goal))
        + (&(&current_reserve - &reserve_floor) * &(&current_reserve - &reserve_floor))
        + (&final_return_gap * &final_return_gap);
    let mean_square_gap = &sum_squared_gap / BigInt::from(4u8);
    let mean_square_gap_remainder = &sum_squared_gap % BigInt::from(4u8);
    let mean_square_gap_slack = BigInt::from(4u8) - &mean_square_gap_remainder - one();
    write_exact_division_support(
        &mut values,
        "rss_mean_square_sovereignty_gap",
        &mean_square_gap,
        "rss_mean_square_sovereignty_gap_remainder",
        &mean_square_gap_remainder,
        "rss_mean_square_sovereignty_gap_slack",
        &mean_square_gap_slack,
        "rss_mean_square_sovereignty_gap",
    );
    let sovereignty_score = bigint_isqrt_floor(&mean_square_gap);
    let sovereignty_score_remainder = &mean_square_gap - (&sovereignty_score * &sovereignty_score);
    let sovereignty_score_upper_slack =
        ((&sovereignty_score + one()) * (&sovereignty_score + one())) - &mean_square_gap - one();
    write_floor_sqrt_support(
        &mut values,
        "rss_sovereignty_score",
        &sovereignty_score,
        "rss_sovereignty_score_remainder",
        &sovereignty_score_remainder,
        "rss_sovereignty_score_upper_slack",
        &sovereignty_score_upper_slack,
        &sed_goldilocks_amount_bound(),
        &sed_goldilocks_amount_bound(),
        "rss_sovereignty_score",
    )?;

    let summary_commitment = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &current_recirculation,
            &current_asset,
            &current_reserve,
            &sovereignty_score,
        ],
    )?;
    let summary_lane = write_hash_lanes(
        &mut values,
        "rss_summary_commitment_internal",
        summary_commitment,
    );
    let mission_commitment = poseidon_permutation4(
        SED_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &commitment_root_lane.as_bigint(),
            &current_capital,
            &sovereignty_score,
        ],
    )?;
    let mission_lane = write_hash_lanes(
        &mut values,
        "rss_mission_commitment_internal",
        mission_commitment,
    );
    values.insert("rss_mission_commitment".to_string(), mission_lane);
    values.insert("rss_summary_commitment".to_string(), summary_lane);
    values.insert("rss_overall_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_recirculation_sovereignty_score_program(request)?;
    materialize_seeded_witness(&program, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit_program_default, compile, prove, verify};
    use std::panic;
    use std::thread;
    use zkf_backends::with_allow_dev_deterministic_groth16_override;
    use zkf_core::{BackendKind, analyze_underconstrained};

    const SOVEREIGN_ECONOMIC_DEFENSE_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_sed_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(SOVEREIGN_ECONOMIC_DEFENSE_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn cooperative_treasury_request() -> CooperativeTreasuryAssuranceRequestV1 {
        CooperativeTreasuryAssuranceRequestV1 {
            treasury_id: "treasury-alpha".to_string(),
            contributions: vec!["1000.000".to_string(), "1000.000".to_string()],
            distributions: vec!["600.000".to_string(), "600.000".to_string()],
            reserve_balance: "800.000".to_string(),
            min_reserve_ratio: "0.200".to_string(),
            max_distribution_per_member: "650.000".to_string(),
            fairness_tolerance: "25.000".to_string(),
        }
    }

    fn community_land_trust_request() -> CommunityLandTrustGovernanceRequestV1 {
        CommunityLandTrustGovernanceRequestV1 {
            land_trust_id: "clt-alpha".to_string(),
            property_values: vec!["500.000".to_string(), "500.000".to_string()],
            equity_shares: vec!["0.500".to_string(), "0.500".to_string()],
            occupancy_flags: vec![true, true],
            tenure_buckets: vec![4, 4],
            maintenance_reserve: "250.000".to_string(),
            min_equity_share: "0.200".to_string(),
            max_equity_concentration: "0.700".to_string(),
            min_maintenance_reserve: "200.000".to_string(),
            required_occupancy_rate: "0.800".to_string(),
            max_rms_equity_deviation: "0.200".to_string(),
        }
    }

    fn anti_extraction_request() -> AntiExtractionShieldRequestV1 {
        AntiExtractionShieldRequestV1 {
            loan_id: "loan-alpha".to_string(),
            principal: "1000.0".to_string(),
            interest_rate_components: vec![
                "0.40".to_string(),
                "0.40".to_string(),
                "0.40".to_string(),
                "0.40".to_string(),
            ],
            scheduled_payments: vec![
                "100.0".to_string(),
                "100.0".to_string(),
                "100.0".to_string(),
                "100.0".to_string(),
            ],
            balloon_payment: true,
            balloon_prohibited: true,
            borrower_income_proxy: "100.0".to_string(),
            apr_ceiling: "0.30".to_string(),
            max_debt_to_income_ratio: "0.30".to_string(),
            minimum_term_length: 12,
            loan_type_code: 1,
            term_bucket: 1,
            marginal_threshold: "0.05".to_string(),
            predatory_threshold: "0.10".to_string(),
        }
    }

    fn wealth_trajectory_request() -> WealthTrajectoryAssuranceRequestV1 {
        WealthTrajectoryAssuranceRequestV1 {
            portfolio_id: "portfolio-alpha".to_string(),
            asset_allocations: vec!["500.000".to_string(), "500.000".to_string()],
            return_rates: vec!["0.080".to_string(), "0.090".to_string()],
            target_allocations: vec!["0.500".to_string(), "0.500".to_string()],
            prohibited_flags: vec![false, false],
            distribution_schedule: vec!["10.000".to_string(), "10.000".to_string()],
            max_single_asset_concentration: "0.600".to_string(),
            max_variance_proxy: "0.200".to_string(),
            min_return_target: "0.050".to_string(),
        }
    }

    fn recirculation_request(
        commitments: [String; 4],
        status_bits: [bool; 4],
    ) -> RecirculationSovereigntyScoreRequestV1 {
        RecirculationSovereigntyScoreRequestV1 {
            mission_id: "mission-alpha".to_string(),
            internal_spend: vec!["2.000".to_string(); SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS],
            external_spend: vec!["0.200".to_string(); SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS],
            circuit_commitments: commitments,
            circuit_status_bits: status_bits,
            initial_circulating_capital: "1000.000".to_string(),
            initial_cooperative_equity: "600.000".to_string(),
            initial_asset_ownership_pct: "0.600".to_string(),
            initial_reserve_level: "250.000".to_string(),
            initial_recirculation_rate: "0.700".to_string(),
            recirculation_target: "0.650".to_string(),
            leakage_cap: "0.300".to_string(),
            asset_ownership_goal: "0.650".to_string(),
            reserve_floor: "200.000".to_string(),
            min_investment_return: "0.050".to_string(),
            investment_return_reference: "0.080".to_string(),
            class_d_nominal_margin: "0.100".to_string(),
            class_d_stress_margin: "0.050".to_string(),
        }
    }

    #[test]
    fn sovereign_economic_defense_circuit_roundtrip() {
        run_sed_test_on_large_stack("sed-circuit-roundtrip", || {
            let cta_request = cooperative_treasury_request();
            let cta_program =
                build_cooperative_treasury_assurance_program(&cta_request).expect("cta program");
            let cta_audit = audit_program_default(&cta_program, Some(BackendKind::Plonky3));
            if cta_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&cta_program);
                panic!(
                    "cta audit must pass: {:?}\nunderconstrained={:?}",
                    cta_audit.checks, analysis
                );
            }
            let cta_witness = cooperative_treasury_assurance_witness_from_request(&cta_request)
                .expect("cta witness");
            let cta_compiled = compile(&cta_program, "plonky3", None).expect("cta compile");
            let cta_artifact = prove(&cta_compiled, &cta_witness).expect("cta prove");
            assert!(verify(&cta_compiled, &cta_artifact).expect("cta verify"));
            assert_eq!(cta_artifact.public_inputs.len(), 2);
            assert_eq!(cta_artifact.public_inputs[1].to_decimal_string(), "1");

            let clt_request = community_land_trust_request();
            let clt_program =
                build_community_land_trust_governance_program(&clt_request).expect("clt program");
            let clt_audit = audit_program_default(&clt_program, Some(BackendKind::Plonky3));
            if clt_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&clt_program);
                panic!(
                    "clt audit must pass: {:?}\nunderconstrained={:?}",
                    clt_audit.checks, analysis
                );
            }
            let clt_witness = community_land_trust_governance_witness_from_request(&clt_request)
                .expect("clt witness");
            let clt_compiled = compile(&clt_program, "plonky3", None).expect("clt compile");
            let clt_artifact = prove(&clt_compiled, &clt_witness).expect("clt prove");
            assert!(verify(&clt_compiled, &clt_artifact).expect("clt verify"));
            assert_eq!(clt_artifact.public_inputs.len(), 2);
            assert_eq!(clt_artifact.public_inputs[1].to_decimal_string(), "1");

            let aes_request = anti_extraction_request();
            let aes_program =
                build_anti_extraction_shield_program(&aes_request).expect("aes program");
            let aes_audit = audit_program_default(&aes_program, Some(BackendKind::ArkworksGroth16));
            if aes_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&aes_program);
                panic!(
                    "aes audit must pass: {:?}\nunderconstrained={:?}",
                    aes_audit.checks, analysis
                );
            }
            let aes_witness =
                anti_extraction_shield_witness_from_request(&aes_request).expect("aes witness");
            let (aes_compiled, aes_artifact) =
                with_allow_dev_deterministic_groth16_override(Some(true), || {
                    let compiled =
                        compile(&aes_program, "arkworks-groth16", None).expect("aes compile");
                    let artifact = prove(&compiled, &aes_witness).expect("aes prove");
                    (compiled, artifact)
                });
            assert!(verify(&aes_compiled, &aes_artifact).expect("aes verify"));
            assert_eq!(aes_artifact.public_inputs.len(), 2);
            assert_eq!(aes_artifact.public_inputs[1].to_decimal_string(), "1");

            let wta_request = wealth_trajectory_request();
            let wta_program =
                build_wealth_trajectory_assurance_program(&wta_request).expect("wta program");
            let wta_audit = audit_program_default(&wta_program, Some(BackendKind::Plonky3));
            if wta_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&wta_program);
                panic!(
                    "wta audit must pass: {:?}\nunderconstrained={:?}",
                    wta_audit.checks, analysis
                );
            }
            let wta_witness = wealth_trajectory_assurance_witness_from_request(&wta_request)
                .expect("wta witness");
            let wta_compiled = compile(&wta_program, "plonky3", None).expect("wta compile");
            let wta_artifact = prove(&wta_compiled, &wta_witness).expect("wta prove");
            assert!(verify(&wta_compiled, &wta_artifact).expect("wta verify"));
            assert_eq!(wta_artifact.public_inputs.len(), 2);
            assert_eq!(wta_artifact.public_inputs[1].to_decimal_string(), "1");

            let rss_request = recirculation_request(
                [
                    cta_artifact.public_inputs[0].to_decimal_string(),
                    clt_artifact.public_inputs[0].to_decimal_string(),
                    aes_artifact.public_inputs[0].to_decimal_string(),
                    wta_artifact.public_inputs[0].to_decimal_string(),
                ],
                [true, true, true, true],
            );
            let rss_program =
                build_recirculation_sovereignty_score_program(&rss_request).expect("rss program");
            let rss_audit = audit_program_default(&rss_program, Some(BackendKind::Plonky3));
            assert_eq!(
                rss_audit.summary.failed, 0,
                "rss audit must pass: {:?}",
                rss_audit.checks
            );
            let rss_witness = recirculation_sovereignty_score_witness_from_request(&rss_request)
                .expect("rss witness");
            let rss_compiled = compile(&rss_program, "plonky3", None).expect("rss compile");
            let rss_artifact = prove(&rss_compiled, &rss_witness).expect("rss prove");
            assert!(verify(&rss_compiled, &rss_artifact).expect("rss verify"));
            assert_eq!(rss_artifact.public_inputs.len(), 3);
            assert_eq!(rss_artifact.public_inputs[1].to_decimal_string(), "1");
        });
    }

    #[test]
    fn anti_extraction_shield_rejects_non_predatory_requests() {
        let mut request = anti_extraction_request();
        request.interest_rate_components = vec![
            "0.05".to_string(),
            "0.05".to_string(),
            "0.05".to_string(),
            "0.05".to_string(),
        ];
        request.balloon_payment = false;
        request.borrower_income_proxy = "1000.0".to_string();
        request.minimum_term_length = 4;
        request.marginal_threshold = "0.20".to_string();
        request.predatory_threshold = "0.30".to_string();
        let err = anti_extraction_shield_witness_from_request(&request)
            .expect_err("non-predatory request must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("fair-lending violation") || message.contains("predatory threshold"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn cta_rejects_empty_contributions() {
        let request = CooperativeTreasuryAssuranceRequestV1 {
            treasury_id: "treasury-empty".to_string(),
            contributions: vec![],
            distributions: vec![],
            reserve_balance: "100.000".to_string(),
            min_reserve_ratio: "0.200".to_string(),
            max_distribution_per_member: "650.000".to_string(),
            fairness_tolerance: "25.000".to_string(),
        };
        build_cooperative_treasury_assurance_program(&request)
            .expect_err("empty contributions must reject at build");
        cooperative_treasury_assurance_witness_from_request(&request)
            .expect_err("empty contributions must reject at witness");
    }

    #[test]
    fn cta_rejects_reserve_below_minimum() {
        let request = CooperativeTreasuryAssuranceRequestV1 {
            treasury_id: "treasury-low-reserve".to_string(),
            contributions: vec!["1000.000".to_string(), "1000.000".to_string()],
            distributions: vec!["600.000".to_string(), "600.000".to_string()],
            reserve_balance: "1.000".to_string(),
            min_reserve_ratio: "0.200".to_string(),
            max_distribution_per_member: "650.000".to_string(),
            fairness_tolerance: "25.000".to_string(),
        };
        cooperative_treasury_assurance_witness_from_request(&request)
            .expect_err("reserve far below minimum must reject witness generation");
    }

    #[test]
    fn cta_handles_single_member() {
        run_sed_test_on_large_stack("cta-single-member", || {
            let request = CooperativeTreasuryAssuranceRequestV1 {
                treasury_id: "treasury-single".to_string(),
                contributions: vec!["1000.000".to_string()],
                distributions: vec!["500.000".to_string()],
                reserve_balance: "500.000".to_string(),
                min_reserve_ratio: "0.200".to_string(),
                max_distribution_per_member: "600.000".to_string(),
                fairness_tolerance: "25.000".to_string(),
            };
            build_cooperative_treasury_assurance_program(&request)
                .expect("single member build must succeed");
            cooperative_treasury_assurance_witness_from_request(&request)
                .expect("single member witness must succeed");
        });
    }

    #[test]
    fn clt_rejects_equity_above_concentration() {
        let request = CommunityLandTrustGovernanceRequestV1 {
            land_trust_id: "clt-concentrated".to_string(),
            property_values: vec!["500.000".to_string(), "500.000".to_string()],
            equity_shares: vec!["0.900".to_string(), "0.100".to_string()],
            occupancy_flags: vec![true, true],
            tenure_buckets: vec![4, 4],
            maintenance_reserve: "250.000".to_string(),
            min_equity_share: "0.050".to_string(),
            max_equity_concentration: "0.700".to_string(),
            min_maintenance_reserve: "200.000".to_string(),
            required_occupancy_rate: "0.800".to_string(),
            max_rms_equity_deviation: "0.200".to_string(),
        };
        community_land_trust_governance_witness_from_request(&request)
            .expect_err("equity above concentration limit must reject witness");
    }

    #[test]
    fn wta_rejects_prohibited_asset_with_allocation() {
        let request = WealthTrajectoryAssuranceRequestV1 {
            portfolio_id: "portfolio-prohibited".to_string(),
            asset_allocations: vec!["500.000".to_string(), "500.000".to_string()],
            return_rates: vec!["0.080".to_string(), "0.090".to_string()],
            target_allocations: vec!["0.500".to_string(), "0.500".to_string()],
            prohibited_flags: vec![false, true],
            distribution_schedule: vec!["10.000".to_string(), "10.000".to_string()],
            max_single_asset_concentration: "0.600".to_string(),
            max_variance_proxy: "0.200".to_string(),
            min_return_target: "0.050".to_string(),
        };
        wealth_trajectory_assurance_witness_from_request(&request)
            .expect_err("prohibited asset with positive allocation must reject witness");
    }

    #[test]
    fn rss_rejects_when_one_status_bit_false() {
        let request = recirculation_request(
            [
                "12345".to_string(),
                "67890".to_string(),
                "11111".to_string(),
                "22222".to_string(),
            ],
            [true, true, true, false],
        );
        recirculation_sovereignty_score_witness_from_request(&request)
            .expect_err("false status bit must reject witness");
    }

    #[test]
    fn cta_rejects_distribution_above_cap() {
        let request = CooperativeTreasuryAssuranceRequestV1 {
            treasury_id: "treasury-overcap".to_string(),
            contributions: vec!["1000.000".to_string(), "1000.000".to_string()],
            distributions: vec!["900.000".to_string(), "100.000".to_string()],
            reserve_balance: "800.000".to_string(),
            min_reserve_ratio: "0.200".to_string(),
            max_distribution_per_member: "650.000".to_string(),
            fairness_tolerance: "25.000".to_string(),
        };
        cooperative_treasury_assurance_witness_from_request(&request)
            .expect_err("distribution above cap must reject witness");
    }
}
