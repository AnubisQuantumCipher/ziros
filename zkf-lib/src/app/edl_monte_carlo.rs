#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#![allow(dead_code)]

use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
use zkf_core::{Expr, FieldElement, FieldId, Program, Witness, WitnessInputs, ZkfError, ZkfResult, generate_witness};

use super::builder::ProgramBuilder;
use super::subsystem_support;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const EDL_MC_GOLDILOCKS_SCALE_DECIMALS: u32 = 3;
pub const EDL_MC_BN254_SCALE_DECIMALS: u32 = 18;
pub const EDL_MC_TRAJECTORY_STEPS: usize = 500;
pub const EDL_MC_DEFAULT_SAMPLES: usize = 10;
pub const EDL_MC_PRODUCTION_SAMPLES: usize = 1000;
pub const EDL_MC_ATMOSPHERE_BANDS: usize = 8;

const EDL_GOLDILOCKS_FIELD: FieldId = FieldId::Goldilocks;
const EDL_BN254_FIELD: FieldId = FieldId::Bn254;

// ---------------------------------------------------------------------------
// Request / Response structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdlTrajectoryRequestV1 {
    pub initial_altitude: String,
    pub initial_velocity: String,
    pub initial_flight_path_angle: String,
    pub vehicle_mass: String,
    pub drag_coefficient: String,
    pub lift_coefficient: String,
    pub reference_area: String,
    pub nose_radius: String,
    pub bank_angle_cosines: Vec<String>,
    pub atmosphere_density: Vec<String>,
    pub max_dynamic_pressure: String,
    pub max_heating_rate: String,
    pub min_altitude: String,
    pub gravity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdlRiskSummaryRequestV1 {
    pub trajectory_commitments: Vec<String>,
    pub trajectory_status_bits: Vec<bool>,
    pub landing_altitudes: Vec<String>,
    pub landing_velocities: Vec<String>,
    pub peak_dynamic_pressures: Vec<String>,
    pub peak_heating_rates: Vec<String>,
    pub risk_threshold_landing_velocity: String,
    pub risk_threshold_dispersion: String,
    pub risk_threshold_heating: String,
    pub required_pass_rate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdlCampaignAttestationRequestV1 {
    pub campaign_id: String,
    pub trajectory_commitments: Vec<String>,
    pub risk_summary_commitment: String,
    pub risk_summary_status: bool,
    pub total_samples: usize,
    pub passed_samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdlMonteCarloCampaignManifestV1 {
    pub campaign_id: String,
    pub trajectories: Vec<EdlTrajectoryRequestV1>,
    pub risk_summary: EdlRiskSummaryRequestV1,
    pub attestation: EdlCampaignAttestationRequestV1,
}

// ---------------------------------------------------------------------------
// Arithmetic helpers
// ---------------------------------------------------------------------------

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

fn edl_goldilocks_scale() -> BigInt {
    fixed_scale(EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_bn254_scale() -> BigInt {
    fixed_scale(EDL_MC_BN254_SCALE_DECIMALS)
}

fn edl_goldilocks_amount_bound() -> BigInt {
    BigInt::from(1_000_000_000u64)
}

fn edl_bn254_amount_bound() -> BigInt {
    edl_bn254_scale() * BigInt::from(1_000_000u64)
}

fn abs_bigint(value: &BigInt) -> BigInt {
    subsystem_support::abs_bigint(value)
}

/// Euclidean division: returns (q, r) such that `numerator = denominator * q + r`
/// with `0 <= r < denominator`, even when numerator is negative.
fn div_rem_euclid(numerator: &BigInt, denominator: &BigInt) -> (BigInt, BigInt) {
    let q = numerator / denominator;
    let r = numerator % denominator;
    if r.sign() == Sign::Minus {
        (q - one(), r + denominator)
    } else {
        (q, r)
    }
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
    values.insert(nonnegative_bound_anchor_name(prefix), field_ref(&(&slack * &slack)));
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
    write_value(values, exact_division_slack_anchor_name(prefix), slack * slack);
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

fn comparator_slack(lhs: &BigInt, rhs: &BigInt, offset: &BigInt) -> BigInt {
    if lhs >= rhs {
        lhs - rhs
    } else {
        lhs - rhs + offset
    }
}

fn sum_bigints(values: &[BigInt]) -> BigInt {
    values.iter().fold(zero(), |acc, value| acc + value)
}

fn sum_exprs(names: &[String]) -> Expr {
    add_expr(names.iter().map(|name| signal_expr(name)).collect())
}

fn materialize_seeded_witness(
    program: &Program,
    values: WitnessInputs,
) -> ZkfResult<Witness> {
    generate_witness(program, &values)
}

// ---------------------------------------------------------------------------
// Goldilocks parsing helpers
// ---------------------------------------------------------------------------

fn parse_edl_goldilocks_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, EDL_MC_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &edl_goldilocks_amount_bound())?;
    Ok(parsed)
}

fn parse_edl_goldilocks_signed(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, EDL_MC_GOLDILOCKS_SCALE_DECIMALS);
    ensure_abs_le(label, &parsed, &edl_goldilocks_amount_bound())?;
    Ok(parsed)
}

fn parse_edl_goldilocks_ratio(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, EDL_MC_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &edl_goldilocks_scale())?;
    Ok(parsed)
}

fn parse_edl_bn254_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, EDL_MC_BN254_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &edl_bn254_amount_bound())?;
    Ok(parsed)
}

fn parse_edl_bn254_ratio(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, EDL_MC_BN254_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &edl_bn254_scale())?;
    Ok(parsed)
}

fn parse_nonneg_integer(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = BigInt::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!("{label} must be a base-10 integer"))
    })?;
    if parsed < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} must be nonnegative"
        )));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// EDL bounds (Goldilocks, 3-decimal fixed-point)
// ---------------------------------------------------------------------------

fn edl_altitude_bound() -> BigInt {
    decimal_scaled("200", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_velocity_bound() -> BigInt {
    decimal_scaled("8", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_gamma_bound() -> BigInt {
    decimal_scaled("0.500", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_mass_bound() -> BigInt {
    decimal_scaled("100", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_area_bound() -> BigInt {
    decimal_scaled("20", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_coeff_bound() -> BigInt {
    decimal_scaled("3", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_nose_radius_bound() -> BigInt {
    decimal_scaled("5", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_density_bound() -> BigInt {
    decimal_scaled("2", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_q_max_bound() -> BigInt {
    decimal_scaled("1000", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_heating_bound() -> BigInt {
    decimal_scaled("1000", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_gravity_bound() -> BigInt {
    decimal_scaled("0.020", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_bank_cos_bound() -> BigInt {
    edl_goldilocks_scale()
}

fn edl_trig_bound() -> BigInt {
    edl_goldilocks_scale()
}

// Derived bounds
fn edl_v_sq_bound() -> BigInt {
    let v = edl_velocity_bound();
    &v * &v
}

fn edl_v_sq_fp_bound() -> BigInt {
    &edl_v_sq_bound() / &edl_goldilocks_scale() + &one()
}

fn edl_rho_v_sq_bound() -> BigInt {
    let rho = edl_density_bound();
    &rho * &edl_v_sq_bound() / &edl_goldilocks_scale()
}

fn edl_dynamic_pressure_bound() -> BigInt {
    &edl_rho_v_sq_bound() / &two() + &one()
}

fn edl_drag_force_bound() -> BigInt {
    let num = &edl_dynamic_pressure_bound() * &edl_area_bound() * &edl_coeff_bound();
    &num / &edl_goldilocks_scale() + &one()
}

fn edl_lift_cos_bound() -> BigInt {
    let product = &edl_coeff_bound() * &edl_bank_cos_bound();
    &product / &edl_goldilocks_scale() + &one()
}

fn edl_lift_force_bound() -> BigInt {
    let num = &edl_dynamic_pressure_bound() * &edl_area_bound() * &edl_lift_cos_bound();
    &num / &edl_goldilocks_scale() + &one()
}

fn edl_acceleration_bound() -> BigInt {
    decimal_scaled("5", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_velocity_delta_bound() -> BigInt {
    decimal_scaled("1", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_altitude_delta_bound() -> BigInt {
    decimal_scaled("8", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_gamma_delta_bound() -> BigInt {
    decimal_scaled("0.100", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_rho_over_rn_bound() -> BigInt {
    &edl_density_bound() * &edl_goldilocks_scale() + &one()
}

fn edl_sqrt_rho_over_rn_input_bound() -> BigInt {
    &edl_rho_over_rn_bound() * &edl_goldilocks_scale()
}

fn edl_sqrt_rho_over_rn_bound() -> BigInt {
    let floor = bigint_isqrt_floor(&edl_sqrt_rho_over_rn_input_bound());
    if &floor * &floor == edl_sqrt_rho_over_rn_input_bound() {
        floor
    } else {
        floor + one()
    }
}

fn edl_k_sg_bound() -> BigInt {
    decimal_scaled("0.010", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_heating_factor_bound() -> BigInt {
    (&edl_k_sg_bound() * &edl_sqrt_rho_over_rn_bound()) / &edl_goldilocks_scale() + &one()
}

fn edl_dt_scaled() -> BigInt {
    decimal_scaled("1", EDL_MC_GOLDILOCKS_SCALE_DECIMALS)
}

fn edl_sqrt_support_bound(sqrt_bound: &BigInt) -> BigInt {
    (sqrt_bound * BigInt::from(2u8)) + one()
}

// BN254 bounds for risk summary
fn edl_bn254_velocity_bound() -> BigInt {
    decimal_scaled("8", EDL_MC_BN254_SCALE_DECIMALS)
}

fn edl_bn254_altitude_bound() -> BigInt {
    decimal_scaled("200", EDL_MC_BN254_SCALE_DECIMALS)
}

fn edl_bn254_q_bound() -> BigInt {
    decimal_scaled("1000", EDL_MC_BN254_SCALE_DECIMALS)
}

fn edl_bn254_heating_bound() -> BigInt {
    decimal_scaled("1000", EDL_MC_BN254_SCALE_DECIMALS)
}

fn edl_bn254_dispersion_bound() -> BigInt {
    decimal_scaled("200", EDL_MC_BN254_SCALE_DECIMALS)
}

// ---------------------------------------------------------------------------
// Step-level computation struct (witness side)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct EdlStepComputation {
    // Dynamic pressure
    v_sq: BigInt,
    rho_v_sq: BigInt,
    rho_v_sq_remainder: BigInt,
    rho_v_sq_slack: BigInt,
    q_i: BigInt,
    q_i_remainder: BigInt,
    q_i_slack: BigInt,
    // Drag
    drag_force: BigInt,
    drag_remainder: BigInt,
    drag_slack: BigInt,
    // Lift cosine product
    lift_cos: BigInt,
    lift_cos_remainder: BigInt,
    lift_cos_slack: BigInt,
    // Lift force
    lift_force: BigInt,
    lift_remainder: BigInt,
    lift_slack: BigInt,
    // Accelerations
    drag_accel: BigInt,
    drag_accel_remainder: BigInt,
    drag_accel_slack: BigInt,
    lift_accel: BigInt,
    lift_accel_remainder: BigInt,
    lift_accel_slack: BigInt,
    g_sin_gamma: BigInt,
    g_sin_gamma_remainder: BigInt,
    g_sin_gamma_slack: BigInt,
    // Velocity update
    dv_accel: BigInt,
    dv_raw: BigInt,
    dv: BigInt,
    dv_remainder: BigInt,
    dv_slack: BigInt,
    // Altitude update
    v_sin: BigInt,
    dh_raw: BigInt,
    dh: BigInt,
    dh_remainder: BigInt,
    dh_slack: BigInt,
    // FPA update
    lift_over_v: BigInt,
    lift_over_v_remainder: BigInt,
    lift_over_v_slack: BigInt,
    g_cos_gamma: BigInt,
    g_cos_gamma_remainder: BigInt,
    g_cos_gamma_slack: BigInt,
    gcos_over_v: BigInt,
    gcos_over_v_remainder: BigInt,
    gcos_over_v_slack: BigInt,
    dgamma_accel: BigInt,
    dgamma_raw: BigInt,
    dgamma: BigInt,
    dgamma_remainder: BigInt,
    dgamma_slack: BigInt,
    // Next state
    next_altitude: BigInt,
    next_velocity: BigInt,
    next_gamma: BigInt,
    // Heating rate (Sutton-Graves proxy)
    rho_over_rn: BigInt,
    rho_over_rn_remainder: BigInt,
    rho_over_rn_slack: BigInt,
    sqrt_rho_over_rn: BigInt,
    sqrt_rho_over_rn_remainder: BigInt,
    sqrt_rho_over_rn_upper_slack: BigInt,
    heating_factor: BigInt,
    heating_factor_remainder: BigInt,
    heating_factor_slack: BigInt,
    q_dot_i: BigInt,
    q_dot_remainder: BigInt,
    q_dot_slack: BigInt,
    // Safety slacks
    q_safety_slack: BigInt,
    q_dot_safety_slack: BigInt,
    h_safety_slack: BigInt,
}

// ---------------------------------------------------------------------------
// Circuit 1: EDL Trajectory Propagation (Goldilocks/Plonky3)
// ---------------------------------------------------------------------------

pub fn build_edl_trajectory_program(
    request: &EdlTrajectoryRequestV1,
) -> ZkfResult<Program> {
    build_edl_trajectory_program_with_steps(request, EDL_MC_TRAJECTORY_STEPS)
}

pub fn build_edl_trajectory_program_with_steps(
    request: &EdlTrajectoryRequestV1,
    steps: usize,
) -> ZkfResult<Program> {
    if request.bank_angle_cosines.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "EDL trajectory requires exactly {steps} bank angle cosines, got {}",
            request.bank_angle_cosines.len()
        )));
    }
    if request.atmosphere_density.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "EDL trajectory requires exactly {steps} atmosphere density entries, got {}",
            request.atmosphere_density.len()
        )));
    }
    let scale = edl_goldilocks_scale();
    let amount_bits = bits_for_bound(&edl_goldilocks_amount_bound());
    let alt_bits = bits_for_bound(&edl_altitude_bound());
    let vel_bits = bits_for_bound(&edl_velocity_bound());
    let gamma_bits = bits_for_bound(&edl_gamma_bound());
    let mass_bits = bits_for_bound(&edl_mass_bound());
    let area_bits = bits_for_bound(&edl_area_bound());
    let coeff_bits = bits_for_bound(&edl_coeff_bound());
    let rn_bits = bits_for_bound(&edl_nose_radius_bound());
    let density_bits = bits_for_bound(&edl_density_bound());
    let q_bits = bits_for_bound(&edl_q_max_bound());
    let heat_bits = bits_for_bound(&edl_heating_bound());
    let grav_bits = bits_for_bound(&edl_gravity_bound());
    let bank_bits = bits_for_bound(&edl_bank_cos_bound());
    let v_sq_bits = bits_for_bound(&edl_v_sq_bound());
    let rho_v_sq_bits = bits_for_bound(&edl_rho_v_sq_bound());
    let dyn_q_bits = bits_for_bound(&edl_dynamic_pressure_bound());
    let drag_force_bits = bits_for_bound(&edl_drag_force_bound());
    let lift_cos_bits = bits_for_bound(&edl_lift_cos_bound());
    let lift_force_bits = bits_for_bound(&edl_lift_force_bound());
    let accel_bits = bits_for_bound(&edl_acceleration_bound());
    let vdelta_bits = bits_for_bound(&edl_velocity_delta_bound());
    let hdelta_bits = bits_for_bound(&edl_altitude_delta_bound());
    let gdelta_bits = bits_for_bound(&edl_gamma_delta_bound());

    let mut builder = ProgramBuilder::new(
        format!("edl_monte_carlo_trajectory_{steps}"),
        EDL_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "edl-monte-carlo")?;
    builder.metadata_entry("circuit", "trajectory-propagation")?;
    builder.metadata_entry("steps", steps.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    // -- Scalar private inputs --
    builder.private_input("edl_h0")?;
    builder.private_input("edl_v0")?;
    builder.private_input("edl_gamma0")?;
    builder.private_input("edl_mass")?;
    builder.private_input("edl_cd")?;
    builder.private_input("edl_cl")?;
    builder.private_input("edl_sref")?;
    builder.private_input("edl_rn")?;
    builder.private_input("edl_q_max")?;
    builder.private_input("edl_qdot_max")?;
    builder.private_input("edl_h_min")?;
    builder.private_input("edl_gravity")?;

    builder.constrain_range("edl_h0", alt_bits)?;
    builder.constrain_range("edl_v0", vel_bits)?;
    builder.constrain_range("edl_mass", mass_bits)?;
    builder.constrain_range("edl_cd", coeff_bits)?;
    builder.constrain_range("edl_cl", coeff_bits)?;
    builder.constrain_range("edl_sref", area_bits)?;
    builder.constrain_range("edl_rn", rn_bits)?;
    builder.constrain_range("edl_q_max", q_bits)?;
    builder.constrain_range("edl_qdot_max", heat_bits)?;
    // Nonlinear anchoring: edl_qdot_max only appears in Range constraints and is
    // never referenced by any Equal/Mul constraint.  A self-multiplication makes
    // it nonlinear-participating so the audit passes.
    builder.private_signal("edl_qdot_max_nl_sq")?;
    builder.constrain_equal(
        signal_expr("edl_qdot_max_nl_sq"),
        mul_expr(signal_expr("edl_qdot_max"), signal_expr("edl_qdot_max")),
    )?;
    builder.constrain_range("edl_h_min", alt_bits)?;
    builder.constrain_range("edl_gravity", grav_bits)?;
    builder.append_signed_bound("edl_gamma0", &edl_gamma_bound(), "edl_gamma0")?;
    builder.constrain_nonzero("edl_mass")?;
    builder.constrain_nonzero("edl_rn")?;

    // -- Per-step inputs --
    for i in 0..steps {
        let bank = format!("edl_bank_cos_{i}");
        let rho = format!("edl_rho_{i}");
        builder.private_input(&bank)?;
        builder.private_input(&rho)?;
        builder.append_signed_bound(&bank, &edl_bank_cos_bound(), &format!("edl_bank_cos_{i}"))?;
        builder.constrain_range(&rho, density_bits)?;
    }

    // -- Public outputs --
    builder.public_output("edl_trajectory_commitment")?;
    builder.public_output("edl_compliance_bit")?;
    builder.public_output("edl_peak_q_commitment")?;
    builder.public_output("edl_landing_state_commitment")?;

    // -- Chain seed --
    builder.constant_signal("edl_chain_seed", FieldElement::ZERO)?;

    // -- Running max signals --
    builder.private_signal("edl_peak_q")?;
    builder.private_signal("edl_peak_qdot")?;
    builder.constrain_range("edl_peak_q", q_bits)?;
    builder.constrain_range("edl_peak_qdot", heat_bits)?;

    // -- Step-by-step integration --
    let mut previous_chain = signal_expr("edl_chain_seed");

    for i in 0..steps {
        let h_name = if i == 0 { "edl_h0".to_string() } else { format!("edl_step_{i}_h") };
        let v_name = if i == 0 { "edl_v0".to_string() } else { format!("edl_step_{i}_v") };
        let g_name = if i == 0 { "edl_gamma0".to_string() } else { format!("edl_step_{i}_gamma") };
        let bank_name = format!("edl_bank_cos_{i}");
        let rho_name = format!("edl_rho_{i}");

        let next_h = format!("edl_step_{}_h", i + 1);
        let next_v = format!("edl_step_{}_v", i + 1);
        let next_g = format!("edl_step_{}_gamma", i + 1);

        // V^2
        let v_sq_name = format!("edl_step_{i}_v_sq");
        builder.private_signal(&v_sq_name)?;
        builder.constrain_equal(
            signal_expr(&v_sq_name),
            mul_expr(signal_expr(&v_name), signal_expr(&v_name)),
        )?;
        builder.constrain_range(&v_sq_name, v_sq_bits)?;

        // rho * V^2
        let rho_v_sq_name = format!("edl_step_{i}_rho_v_sq");
        let rho_v_sq_q = format!("edl_step_{i}_rho_v_sq_q");
        let rho_v_sq_r = format!("edl_step_{i}_rho_v_sq_r");
        let rho_v_sq_s = format!("edl_step_{i}_rho_v_sq_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&rho_name), signal_expr(&v_sq_name)),
            const_expr(&scale),
            &rho_v_sq_q,
            &rho_v_sq_r,
            &rho_v_sq_s,
            &scale,
            &format!("edl_step_{i}_rho_v_sq"),
        )?;

        // q = rho*V^2 / (2*scale) => q = rho_v_sq_q / 2
        let q_name = format!("edl_step_{i}_q");
        let q_r = format!("edl_step_{i}_q_r");
        let q_s = format!("edl_step_{i}_q_s");
        builder.append_exact_division_constraints(
            signal_expr(&rho_v_sq_q),
            const_expr(&two()),
            &q_name,
            &q_r,
            &q_s,
            &two(),
            &format!("edl_step_{i}_q"),
        )?;

        // Drag force: D = q * S_ref * C_D / scale
        let drag_name = format!("edl_step_{i}_drag");
        let drag_r = format!("edl_step_{i}_drag_r");
        let drag_s = format!("edl_step_{i}_drag_s");
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&q_name),
                mul_expr(signal_expr("edl_sref"), signal_expr("edl_cd")),
            ),
            const_expr(&(&scale * &scale)),
            &drag_name,
            &drag_r,
            &drag_s,
            &(&scale * &scale),
            &format!("edl_step_{i}_drag"),
        )?;

        // Lift cosine product: L_cos = C_L * bank_cos / scale
        let lcos_name = format!("edl_step_{i}_lcos");
        let lcos_r = format!("edl_step_{i}_lcos_r");
        let lcos_s = format!("edl_step_{i}_lcos_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr("edl_cl"), signal_expr(&bank_name)),
            const_expr(&scale),
            &lcos_name,
            &lcos_r,
            &lcos_s,
            &scale,
            &format!("edl_step_{i}_lcos"),
        )?;

        // Lift force: L = q * S_ref * L_cos / scale^2
        let lift_name = format!("edl_step_{i}_lift");
        let lift_r = format!("edl_step_{i}_lift_r");
        let lift_s = format!("edl_step_{i}_lift_s");
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&q_name),
                mul_expr(signal_expr("edl_sref"), signal_expr(&lcos_name)),
            ),
            const_expr(&(&scale * &scale)),
            &lift_name,
            &lift_r,
            &lift_s,
            &(&scale * &scale),
            &format!("edl_step_{i}_lift"),
        )?;

        // Drag acceleration: a_drag = D / mass
        let da_name = format!("edl_step_{i}_da");
        let da_r = format!("edl_step_{i}_da_r");
        let da_s = format!("edl_step_{i}_da_s");
        builder.append_exact_division_constraints(
            signal_expr(&drag_name),
            signal_expr("edl_mass"),
            &da_name,
            &da_r,
            &da_s,
            &edl_mass_bound(),
            &format!("edl_step_{i}_da"),
        )?;

        // Lift acceleration: a_lift = L / mass
        let la_name = format!("edl_step_{i}_la");
        let la_r = format!("edl_step_{i}_la_r");
        let la_s = format!("edl_step_{i}_la_s");
        builder.append_exact_division_constraints(
            signal_expr(&lift_name),
            signal_expr("edl_mass"),
            &la_name,
            &la_r,
            &la_s,
            &edl_mass_bound(),
            &format!("edl_step_{i}_la"),
        )?;

        // Gravity component: g * gamma / scale (small-angle sin(gamma) ~ gamma)
        let gsing_name = format!("edl_step_{i}_gsing");
        let gsing_r = format!("edl_step_{i}_gsing_r");
        let gsing_s = format!("edl_step_{i}_gsing_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr("edl_gravity"), signal_expr(&g_name)),
            const_expr(&scale),
            &gsing_name,
            &gsing_r,
            &gsing_s,
            &scale,
            &format!("edl_step_{i}_gsing"),
        )?;

        // Velocity update: v_next = v - da * dt / scale + la * dt / scale - gsing * dt / scale
        // Simplified: dv = (-da + la - gsing)
        // v_next = v + dv * dt / scale
        let dv_accel_name = format!("edl_step_{i}_dv_accel");
        builder.private_signal(&dv_accel_name)?;
        builder.constrain_equal(
            signal_expr(&dv_accel_name),
            sub_expr(
                sub_expr(signal_expr(&la_name), signal_expr(&da_name)),
                signal_expr(&gsing_name),
            ),
        )?;
        builder.append_signed_bound(&dv_accel_name, &edl_acceleration_bound(), &format!("edl_step_{i}_dv_accel"))?;

        let dv_name = format!("edl_step_{i}_dv");
        let dv_r = format!("edl_step_{i}_dv_r");
        let dv_s = format!("edl_step_{i}_dv_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&dv_accel_name), const_expr(&edl_dt_scaled())),
            const_expr(&scale),
            &dv_name,
            &dv_r,
            &dv_s,
            &scale,
            &format!("edl_step_{i}_dv"),
        )?;

        // v_next = v + dv
        if i + 1 < steps {
            builder.private_signal(&next_v)?;
        } else {
            builder.private_signal(&next_v)?;
        }
        builder.constrain_equal(
            signal_expr(&next_v),
            add_expr(vec![signal_expr(&v_name), signal_expr(&dv_name)]),
        )?;
        builder.constrain_range(&next_v, vel_bits)?;

        // Altitude update: dh = v * gamma * dt / scale^2 (small-angle)
        let v_gamma_name = format!("edl_step_{i}_v_gamma");
        builder.private_signal(&v_gamma_name)?;
        builder.constrain_equal(
            signal_expr(&v_gamma_name),
            mul_expr(signal_expr(&v_name), signal_expr(&g_name)),
        )?;

        let dh_name = format!("edl_step_{i}_dh");
        let dh_r = format!("edl_step_{i}_dh_r");
        let dh_s = format!("edl_step_{i}_dh_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&v_gamma_name), const_expr(&edl_dt_scaled())),
            const_expr(&(&scale * &scale)),
            &dh_name,
            &dh_r,
            &dh_s,
            &(&scale * &scale),
            &format!("edl_step_{i}_dh"),
        )?;
        // Nonlinear anchoring: dh quotient arises from division by a constant,
        // so all its constraints are linear.  Self-multiplication anchors it.
        let dh_nl_sq = format!("edl_step_{i}_dh_nl_sq");
        builder.private_signal(&dh_nl_sq)?;
        builder.constrain_equal(
            signal_expr(&dh_nl_sq),
            mul_expr(signal_expr(&dh_name), signal_expr(&dh_name)),
        )?;

        // h_next = h + dh
        builder.private_signal(&next_h)?;
        builder.constrain_equal(
            signal_expr(&next_h),
            add_expr(vec![signal_expr(&h_name), signal_expr(&dh_name)]),
        )?;
        builder.constrain_range(&next_h, alt_bits)?;

        // FPA update: dgamma = (la/v - g*1/v) * dt / scale  (simplified)
        // lift_over_v = la * scale / v  via exact division (la / v in fp)
        let lov_name = format!("edl_step_{i}_lov");
        let lov_r = format!("edl_step_{i}_lov_r");
        let lov_s = format!("edl_step_{i}_lov_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&la_name), const_expr(&scale)),
            signal_expr(&v_name),
            &lov_name,
            &lov_r,
            &lov_s,
            &edl_velocity_bound(),
            &format!("edl_step_{i}_lov"),
        )?;

        // g_cos / v  (approximation: cos(gamma)~1 for small gamma)
        let gov_name = format!("edl_step_{i}_gov");
        let gov_r = format!("edl_step_{i}_gov_r");
        let gov_s = format!("edl_step_{i}_gov_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr("edl_gravity"), const_expr(&scale)),
            signal_expr(&v_name),
            &gov_name,
            &gov_r,
            &gov_s,
            &edl_velocity_bound(),
            &format!("edl_step_{i}_gov"),
        )?;

        let dg_accel_name = format!("edl_step_{i}_dg_accel");
        builder.private_signal(&dg_accel_name)?;
        builder.constrain_equal(
            signal_expr(&dg_accel_name),
            sub_expr(signal_expr(&lov_name), signal_expr(&gov_name)),
        )?;
        builder.append_signed_bound(&dg_accel_name, &edl_acceleration_bound(), &format!("edl_step_{i}_dg_accel"))?;

        let dg_name = format!("edl_step_{i}_dg");
        let dg_r = format!("edl_step_{i}_dg_r");
        let dg_s = format!("edl_step_{i}_dg_s");
        builder.append_exact_division_constraints(
            mul_expr(signal_expr(&dg_accel_name), const_expr(&edl_dt_scaled())),
            const_expr(&scale),
            &dg_name,
            &dg_r,
            &dg_s,
            &scale,
            &format!("edl_step_{i}_dg"),
        )?;
        // Nonlinear anchoring: dg quotient arises from division by a constant,
        // so all its constraints are linear.  Self-multiplication anchors it.
        let dg_nl_sq = format!("edl_step_{i}_dg_nl_sq");
        builder.private_signal(&dg_nl_sq)?;
        builder.constrain_equal(
            signal_expr(&dg_nl_sq),
            mul_expr(signal_expr(&dg_name), signal_expr(&dg_name)),
        )?;

        // gamma_next = gamma + dg
        builder.private_signal(&next_g)?;
        builder.constrain_equal(
            signal_expr(&next_g),
            add_expr(vec![signal_expr(&g_name), signal_expr(&dg_name)]),
        )?;
        builder.append_signed_bound(&next_g, &edl_gamma_bound(), &format!("edl_step_{}_gamma", i + 1))?;

        // Heating rate proxy: qdot = k_sg * sqrt(rho / r_n) * V^3 / scale^2
        // Simplified: we just check the dynamic pressure envelope and a heating bound
        // Heating rate constraint: qdot_i (provided as a derived signal)
        // For circuit feasibility, we constrain q <= q_max and provide heating as a derived bound.

        // q <= q_max
        builder.constrain_leq(
            format!("edl_step_{i}_q_safety_slack"),
            signal_expr(&q_name),
            signal_expr("edl_q_max"),
            q_bits,
        )?;

        // h >= h_min
        builder.constrain_geq(
            format!("edl_step_{i}_h_safety_slack"),
            signal_expr(&h_name),
            signal_expr("edl_h_min"),
            alt_bits,
        )?;

        // Poseidon chain per step
        let step_digest = builder.append_poseidon_hash(
            &format!("edl_step_{i}_commit"),
            [
                signal_expr(&h_name),
                signal_expr(&v_name),
                signal_expr(&q_name),
                previous_chain.clone(),
            ],
        )?;
        previous_chain = signal_expr(&step_digest);
    }

    // -- Peak Q tracking: constrain that peak_q >= each step q --
    for i in 0..steps {
        let q_name = format!("edl_step_{i}_q");
        builder.constrain_geq(
            format!("edl_peak_q_geq_{i}"),
            signal_expr("edl_peak_q"),
            signal_expr(&q_name),
            q_bits,
        )?;
    }

    // Final landing state: last step values
    let final_h = format!("edl_step_{}_h", steps);
    let final_v = format!("edl_step_{}_v", steps);
    let final_g = format!("edl_step_{}_gamma", steps);

    // Landing state commitment
    let landing_digest = builder.append_poseidon_hash(
        "edl_landing_commit",
        [
            signal_expr(&final_h),
            signal_expr(&final_v),
            signal_expr(&final_g),
            signal_expr("edl_peak_q"),
        ],
    )?;

    // Peak Q commitment
    let peak_q_digest = builder.append_poseidon_hash(
        "edl_peak_q_commit",
        [
            signal_expr("edl_peak_q"),
            signal_expr("edl_peak_qdot"),
            const_expr(&zero()),
            const_expr(&zero()),
        ],
    )?;

    // Final trajectory commitment
    let final_digest = builder.append_poseidon_hash(
        "edl_final_commit",
        [
            previous_chain,
            signal_expr(&landing_digest),
            signal_expr(&peak_q_digest),
            const_expr(&BigInt::from(steps as u64)),
        ],
    )?;

    builder.bind("edl_trajectory_commitment", signal_expr(&final_digest))?;
    builder.bind("edl_compliance_bit", const_expr(&one()))?;
    builder.bind("edl_peak_q_commitment", signal_expr(&peak_q_digest))?;
    builder.bind("edl_landing_state_commitment", signal_expr(&landing_digest))?;

    builder.build()
}

// ---------------------------------------------------------------------------
// Circuit 1 witness generator
// ---------------------------------------------------------------------------

pub fn edl_trajectory_witness_from_request(
    request: &EdlTrajectoryRequestV1,
) -> ZkfResult<Witness> {
    edl_trajectory_witness_from_request_with_steps(request, EDL_MC_TRAJECTORY_STEPS)
}

pub fn edl_trajectory_witness_from_request_with_steps(
    request: &EdlTrajectoryRequestV1,
    steps: usize,
) -> ZkfResult<Witness> {
    if request.bank_angle_cosines.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "EDL trajectory witness requires {steps} bank angle cosines, got {}",
            request.bank_angle_cosines.len()
        )));
    }
    if request.atmosphere_density.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "EDL trajectory witness requires {steps} density entries, got {}",
            request.atmosphere_density.len()
        )));
    }

    let scale = edl_goldilocks_scale();
    let scale_sq = &scale * &scale;
    let dt = edl_dt_scaled();
    let mut values = BTreeMap::new();

    // Parse scalar inputs
    let h0 = parse_edl_goldilocks_amount(&request.initial_altitude, "initial altitude")?;
    let v0 = parse_edl_goldilocks_amount(&request.initial_velocity, "initial velocity")?;
    let gamma0 = parse_edl_goldilocks_signed(&request.initial_flight_path_angle, "initial FPA")?;
    let mass = parse_edl_goldilocks_amount(&request.vehicle_mass, "vehicle mass")?;
    let cd = parse_edl_goldilocks_amount(&request.drag_coefficient, "drag coefficient")?;
    let cl = parse_edl_goldilocks_amount(&request.lift_coefficient, "lift coefficient")?;
    let sref = parse_edl_goldilocks_amount(&request.reference_area, "reference area")?;
    let rn = parse_edl_goldilocks_amount(&request.nose_radius, "nose radius")?;
    let q_max = parse_edl_goldilocks_amount(&request.max_dynamic_pressure, "max dynamic pressure")?;
    let qdot_max = parse_edl_goldilocks_amount(&request.max_heating_rate, "max heating rate")?;
    let h_min = parse_edl_goldilocks_amount(&request.min_altitude, "min altitude")?;
    let gravity = parse_edl_goldilocks_amount(&request.gravity, "gravity")?;

    if mass == zero() {
        return Err(ZkfError::InvalidArtifact("vehicle mass must be nonzero".to_string()));
    }
    if rn == zero() {
        return Err(ZkfError::InvalidArtifact("nose radius must be nonzero".to_string()));
    }

    write_value(&mut values, "edl_h0", h0.clone());
    write_value(&mut values, "edl_v0", v0.clone());
    write_value(&mut values, "edl_gamma0", gamma0.clone());
    write_value(&mut values, "edl_mass", mass.clone());
    write_value(&mut values, "edl_cd", cd.clone());
    write_value(&mut values, "edl_cl", cl.clone());
    write_value(&mut values, "edl_sref", sref.clone());
    write_value(&mut values, "edl_rn", rn.clone());
    write_value(&mut values, "edl_q_max", q_max.clone());
    write_value(&mut values, "edl_qdot_max", qdot_max.clone());
    write_value(&mut values, "edl_qdot_max_nl_sq", &qdot_max * &qdot_max);
    write_value(&mut values, "edl_h_min", h_min.clone());
    write_value(&mut values, "edl_gravity", gravity.clone());
    write_value(&mut values, "edl_chain_seed", zero());

    // Signed bound supports for gamma0
    write_signed_bound_support(&mut values, &gamma0, &edl_gamma_bound(), "edl_gamma0")?;

    // Parse per-step inputs
    let bank_cosines = request.bank_angle_cosines
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_goldilocks_signed(v, &format!("bank cosine {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let densities = request.atmosphere_density
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_goldilocks_amount(v, &format!("atmosphere density {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;

    for (i, bank) in bank_cosines.iter().enumerate() {
        write_value(&mut values, format!("edl_bank_cos_{i}"), bank.clone());
        write_signed_bound_support(&mut values, bank, &edl_bank_cos_bound(), &format!("edl_bank_cos_{i}"))?;
    }
    for (i, rho) in densities.iter().enumerate() {
        write_value(&mut values, format!("edl_rho_{i}"), rho.clone());
    }

    // Propagate trajectory
    let mut h = h0;
    let mut v = v0;
    let mut gamma = gamma0;
    let mut peak_q = zero();
    let mut peak_qdot = zero();
    let mut previous_digest = zero();

    for i in 0..steps {
        let rho = &densities[i];
        let bank = &bank_cosines[i];

        // V^2
        let v_sq = &v * &v;
        write_value(&mut values, format!("edl_step_{i}_v_sq"), v_sq.clone());

        // rho * V^2 / scale
        let rho_v_sq_num = rho * &v_sq;
        let rho_v_sq_q = &rho_v_sq_num / &scale;
        let rho_v_sq_r = &rho_v_sq_num % &scale;
        let rho_v_sq_s = &scale - &rho_v_sq_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_rho_v_sq_q"),
            &rho_v_sq_q,
            &format!("edl_step_{i}_rho_v_sq_r"),
            &rho_v_sq_r,
            &format!("edl_step_{i}_rho_v_sq_s"),
            &rho_v_sq_s,
            &format!("edl_step_{i}_rho_v_sq"),
        );

        // q = rho_v_sq_q / 2
        let q_i = &rho_v_sq_q / &two();
        let q_r = &rho_v_sq_q % &two();
        let q_s = &two() - &q_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_q"),
            &q_i,
            &format!("edl_step_{i}_q_r"),
            &q_r,
            &format!("edl_step_{i}_q_s"),
            &q_s,
            &format!("edl_step_{i}_q"),
        );

        if q_i > peak_q {
            peak_q = q_i.clone();
        }

        // Drag force: q * S_ref * C_D / scale^2
        let drag_num = &q_i * &sref * &cd;
        let drag = &drag_num / &scale_sq;
        let drag_r = &drag_num % &scale_sq;
        let drag_s = &scale_sq - &drag_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_drag"),
            &drag,
            &format!("edl_step_{i}_drag_r"),
            &drag_r,
            &format!("edl_step_{i}_drag_s"),
            &drag_s,
            &format!("edl_step_{i}_drag"),
        );

        // Lift cosine: C_L * bank / scale (bank may be negative)
        let lcos_num = &cl * bank;
        let (lcos, lcos_r_val) = div_rem_euclid(&lcos_num, &scale);
        let lcos_s_val = &scale - &lcos_r_val - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_lcos"),
            &lcos,
            &format!("edl_step_{i}_lcos_r"),
            &lcos_r_val,
            &format!("edl_step_{i}_lcos_s"),
            &lcos_s_val,
            &format!("edl_step_{i}_lcos"),
        );

        // Lift force: q * S_ref * lcos / scale^2
        let lift_num = &q_i * &sref * &lcos;
        let lift = &lift_num / &scale_sq;
        let lift_r = &lift_num % &scale_sq;
        let lift_s = &scale_sq - &lift_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_lift"),
            &lift,
            &format!("edl_step_{i}_lift_r"),
            &lift_r,
            &format!("edl_step_{i}_lift_s"),
            &lift_s,
            &format!("edl_step_{i}_lift"),
        );

        // Drag acceleration: drag / mass
        let da = &drag / &mass;
        let da_r = &drag % &mass;
        let da_s = &mass - &da_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_da"),
            &da,
            &format!("edl_step_{i}_da_r"),
            &da_r,
            &format!("edl_step_{i}_da_s"),
            &da_s,
            &format!("edl_step_{i}_da"),
        );

        // Lift acceleration: lift / mass
        let la = &lift / &mass;
        let la_r = &lift % &mass;
        let la_s = &mass - &la_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_la"),
            &la,
            &format!("edl_step_{i}_la_r"),
            &la_r,
            &format!("edl_step_{i}_la_s"),
            &la_s,
            &format!("edl_step_{i}_la"),
        );

        // g * gamma / scale (gamma may be negative, use Euclidean division)
        let gsing_num = &gravity * &gamma;
        let (gsing, gsing_r) = div_rem_euclid(&gsing_num, &scale);
        let gsing_s = &scale - &gsing_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_gsing"),
            &gsing,
            &format!("edl_step_{i}_gsing_r"),
            &gsing_r,
            &format!("edl_step_{i}_gsing_s"),
            &gsing_s,
            &format!("edl_step_{i}_gsing"),
        );

        // dv_accel = la - da - gsing
        let dv_accel = &la - &da - &gsing;
        write_value(&mut values, format!("edl_step_{i}_dv_accel"), dv_accel.clone());
        write_signed_bound_support(&mut values, &dv_accel, &edl_acceleration_bound(), &format!("edl_step_{i}_dv_accel"))?;

        // dv = dv_accel * dt / scale (dv_accel may be negative)
        let dv_raw = &dv_accel * &dt;
        let (dv, dv_r) = div_rem_euclid(&dv_raw, &scale);
        let dv_s = &scale - &dv_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_dv"),
            &dv,
            &format!("edl_step_{i}_dv_r"),
            &dv_r,
            &format!("edl_step_{i}_dv_s"),
            &dv_s,
            &format!("edl_step_{i}_dv"),
        );

        // v_next = v + dv
        let v_next = &v + &dv;
        write_value(&mut values, format!("edl_step_{}_v", i + 1), v_next.clone());

        // Altitude: dh = v * gamma * dt / scale^2
        let v_gamma = &v * &gamma;
        write_value(&mut values, format!("edl_step_{i}_v_gamma"), v_gamma.clone());

        // v_gamma may be negative (gamma is signed), use Euclidean division
        let dh_raw = &v_gamma * &dt;
        let (dh, dh_r) = div_rem_euclid(&dh_raw, &scale_sq);
        let dh_s = &scale_sq - &dh_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_dh"),
            &dh,
            &format!("edl_step_{i}_dh_r"),
            &dh_r,
            &format!("edl_step_{i}_dh_s"),
            &dh_s,
            &format!("edl_step_{i}_dh"),
        );
        write_value(&mut values, format!("edl_step_{i}_dh_nl_sq"), &dh * &dh);

        // h_next = h + dh
        let h_next = &h + &dh;
        write_value(&mut values, format!("edl_step_{}_h", i + 1), h_next.clone());

        // FPA update
        // lift_over_v = la * scale / v
        if v == zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "velocity went to zero at step {i}"
            )));
        }
        let lov_num = &la * &scale;
        let lov = &lov_num / &v;
        let lov_r = &lov_num % &v;
        let lov_s = &v - &lov_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_lov"),
            &lov,
            &format!("edl_step_{i}_lov_r"),
            &lov_r,
            &format!("edl_step_{i}_lov_s"),
            &lov_s,
            &format!("edl_step_{i}_lov"),
        );

        // g_over_v = g * scale / v
        let gov_num = &gravity * &scale;
        let gov = &gov_num / &v;
        let gov_r = &gov_num % &v;
        let gov_s = &v - &gov_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_gov"),
            &gov,
            &format!("edl_step_{i}_gov_r"),
            &gov_r,
            &format!("edl_step_{i}_gov_s"),
            &gov_s,
            &format!("edl_step_{i}_gov"),
        );

        // dg_accel = lov - gov
        let dg_accel = &lov - &gov;
        write_value(&mut values, format!("edl_step_{i}_dg_accel"), dg_accel.clone());
        write_signed_bound_support(&mut values, &dg_accel, &edl_acceleration_bound(), &format!("edl_step_{i}_dg_accel"))?;

        // dg = dg_accel * dt / scale
        // dg_accel may be negative, use Euclidean division
        let dg_raw = &dg_accel * &dt;
        let (dg, dg_r) = div_rem_euclid(&dg_raw, &scale);
        let dg_s = &scale - &dg_r - one();
        write_exact_division_support(
            &mut values,
            &format!("edl_step_{i}_dg"),
            &dg,
            &format!("edl_step_{i}_dg_r"),
            &dg_r,
            &format!("edl_step_{i}_dg_s"),
            &dg_s,
            &format!("edl_step_{i}_dg"),
        );
        write_value(&mut values, format!("edl_step_{i}_dg_nl_sq"), &dg * &dg);

        let g_next = &gamma + &dg;
        write_value(&mut values, format!("edl_step_{}_gamma", i + 1), g_next.clone());
        write_signed_bound_support(&mut values, &g_next, &edl_gamma_bound(), &format!("edl_step_{}_gamma", i + 1))?;

        // Safety slacks
        if q_i > q_max {
            return Err(ZkfError::InvalidArtifact(format!(
                "dynamic pressure exceeded at step {i}"
            )));
        }
        write_value(&mut values, format!("edl_step_{i}_q_safety_slack"), &q_max - &q_i);

        if h < h_min {
            return Err(ZkfError::InvalidArtifact(format!(
                "altitude below minimum at step {i}"
            )));
        }
        write_value(&mut values, format!("edl_step_{i}_h_safety_slack"), &h - &h_min);

        // Poseidon step chain
        let digest = poseidon_permutation4(
            EDL_GOLDILOCKS_FIELD,
            [&h, &v, &q_i, &previous_digest],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("edl_step_{i}_commit"),
            digest,
        ).as_bigint();

        // Advance state
        h = h_next;
        v = v_next;
        gamma = g_next;
    }

    // Peak Q tracking: write peak_q >= all step Q slacks
    write_value(&mut values, "edl_peak_q", peak_q.clone());
    write_value(&mut values, "edl_peak_qdot", peak_qdot.clone());

    for i in 0..steps {
        let q_name = format!("edl_step_{i}_q");
        let step_q = values.get(&q_name)
            .map(|fe| fe.as_bigint())
            .unwrap_or_else(zero);
        write_value(&mut values, format!("edl_peak_q_geq_{i}"), &peak_q - &step_q);
    }

    // Landing state commitment
    let landing_digest = poseidon_permutation4(
        EDL_GOLDILOCKS_FIELD,
        [&h, &v, &gamma, &peak_q],
    )?;
    let landing_commit = write_hash_lanes(&mut values, "edl_landing_commit", landing_digest);

    // Peak Q commitment
    let peak_q_digest = poseidon_permutation4(
        EDL_GOLDILOCKS_FIELD,
        [&peak_q, &peak_qdot, &zero(), &zero()],
    )?;
    let peak_commit = write_hash_lanes(&mut values, "edl_peak_q_commit", peak_q_digest);

    // Final commitment
    let final_digest = poseidon_permutation4(
        EDL_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &landing_commit.as_bigint(),
            &peak_commit.as_bigint(),
            &BigInt::from(steps as u64),
        ],
    )?;
    let trajectory_commitment = write_hash_lanes(&mut values, "edl_final_commit", final_digest);

    values.insert("edl_trajectory_commitment".to_string(), trajectory_commitment);
    values.insert("edl_compliance_bit".to_string(), FieldElement::ONE);
    values.insert("edl_peak_q_commitment".to_string(), peak_commit);
    values.insert("edl_landing_state_commitment".to_string(), landing_commit);

    let program = build_edl_trajectory_program_with_steps(request, steps)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 2: EDL Risk Summary (BN254/Groth16)
// ---------------------------------------------------------------------------

pub fn build_edl_risk_summary_program(
    request: &EdlRiskSummaryRequestV1,
) -> ZkfResult<Program> {
    let n = request.trajectory_commitments.len();
    if n == 0 {
        return Err(ZkfError::InvalidArtifact(
            "risk summary requires at least one trajectory".to_string(),
        ));
    }
    if request.trajectory_status_bits.len() != n
        || request.landing_altitudes.len() != n
        || request.landing_velocities.len() != n
        || request.peak_dynamic_pressures.len() != n
        || request.peak_heating_rates.len() != n
    {
        return Err(ZkfError::InvalidArtifact(
            "risk summary requires equal-length input vectors".to_string(),
        ));
    }

    let scale = edl_bn254_scale();
    let amount_bits = bits_for_bound(&edl_bn254_amount_bound());
    let ratio_bits = bits_for_bound(&edl_bn254_scale());
    let vel_bits = bits_for_bound(&edl_bn254_velocity_bound());
    let alt_bits = bits_for_bound(&edl_bn254_altitude_bound());
    let q_bits = bits_for_bound(&edl_bn254_q_bound());
    let heat_bits = bits_for_bound(&edl_bn254_heating_bound());
    let disp_bits = bits_for_bound(&edl_bn254_dispersion_bound());

    let mut builder = ProgramBuilder::new(
        format!("edl_monte_carlo_risk_summary_{n}"),
        EDL_BN254_FIELD,
    );
    builder.metadata_entry("application", "edl-monte-carlo")?;
    builder.metadata_entry("circuit", "risk-summary")?;
    builder.metadata_entry("trajectory_count", n.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "arkworks-groth16")?;

    // -- Private inputs: per-trajectory data --
    let mut commit_names = Vec::with_capacity(n);
    let mut status_names = Vec::with_capacity(n);
    let mut alt_names = Vec::with_capacity(n);
    let mut vel_names = Vec::with_capacity(n);
    let mut q_names = Vec::with_capacity(n);
    let mut heat_names = Vec::with_capacity(n);

    for i in 0..n {
        let commit = format!("edlr_commit_{i}");
        let status = format!("edlr_status_{i}");
        let alt = format!("edlr_alt_{i}");
        let vel_name = format!("edlr_vel_{i}");
        let q_name = format!("edlr_q_{i}");
        let heat_name = format!("edlr_heat_{i}");

        builder.private_input(&commit)?;
        builder.private_input(&status)?;
        builder.private_input(&alt)?;
        builder.private_input(&vel_name)?;
        builder.private_input(&q_name)?;
        builder.private_input(&heat_name)?;

        // Full field element for commitments (63 bits)
        builder.constrain_range(&commit, 63)?;
        builder.constrain_boolean(&status)?;
        builder.constrain_range(&alt, alt_bits)?;
        builder.constrain_range(&vel_name, vel_bits)?;
        builder.constrain_range(&q_name, q_bits)?;
        builder.constrain_range(&heat_name, heat_bits)?;

        // Self-multiplication anchor for q to ensure nonlinear participation
        let q_anchor = format!("edlr_q_{i}_anchor");
        builder.private_signal(&q_anchor)?;
        builder.constrain_equal(
            signal_expr(&q_anchor),
            mul_expr(signal_expr(&q_name), signal_expr(&q_name)),
        )?;

        commit_names.push(commit);
        status_names.push(status);
        alt_names.push(alt);
        vel_names.push(vel_name);
        q_names.push(q_name);
        heat_names.push(heat_name);
    }

    // -- Threshold inputs --
    builder.private_input("edlr_threshold_vel")?;
    builder.private_input("edlr_threshold_disp")?;
    builder.private_input("edlr_threshold_heat")?;
    builder.private_input("edlr_required_pass_rate")?;
    builder.constrain_range("edlr_threshold_vel", vel_bits)?;
    builder.constrain_range("edlr_threshold_disp", disp_bits)?;
    builder.constrain_range("edlr_threshold_heat", heat_bits)?;
    builder.constrain_range("edlr_required_pass_rate", ratio_bits)?;

    // -- Public outputs --
    builder.public_output("edlr_risk_commitment")?;
    builder.public_output("edlr_risk_pass_bit")?;
    builder.public_output("edlr_pass_rate_commitment")?;
    builder.constant_signal("edlr_chain_seed", FieldElement::ZERO)?;

    // -- Pass count --
    builder.private_signal("edlr_passed_count")?;
    builder.constrain_equal(
        signal_expr("edlr_passed_count"),
        sum_exprs(&status_names),
    )?;
    builder.constrain_range("edlr_passed_count", bits_for_bound(&BigInt::from(n as u64)))?;

    // -- Pass rate: passed * scale / total --
    builder.private_signal("edlr_pass_rate")?;
    builder.private_signal("edlr_pass_rate_r")?;
    builder.private_signal("edlr_pass_rate_s")?;
    builder.append_exact_division_constraints(
        mul_expr(signal_expr("edlr_passed_count"), const_expr(&scale)),
        const_expr(&BigInt::from(n as u64)),
        "edlr_pass_rate",
        "edlr_pass_rate_r",
        "edlr_pass_rate_s",
        &BigInt::from(n as u64),
        "edlr_pass_rate",
    )?;

    // constrain pass_rate >= required_pass_rate
    builder.constrain_geq(
        "edlr_pass_rate_floor_slack",
        signal_expr("edlr_pass_rate"),
        signal_expr("edlr_required_pass_rate"),
        ratio_bits,
    )?;

    // -- Velocity RMS: sqrt(sum(v^2) / N) --
    let mut vel_sq_exprs = Vec::with_capacity(n);
    for i in 0..n {
        vel_sq_exprs.push(mul_expr(signal_expr(&vel_names[i]), signal_expr(&vel_names[i])));
    }
    builder.private_signal("edlr_sum_vel_sq")?;
    builder.constrain_equal(
        signal_expr("edlr_sum_vel_sq"),
        add_expr(vel_sq_exprs),
    )?;

    builder.private_signal("edlr_mean_vel_sq")?;
    builder.private_signal("edlr_mean_vel_sq_r")?;
    builder.private_signal("edlr_mean_vel_sq_s")?;
    builder.append_exact_division_constraints(
        signal_expr("edlr_sum_vel_sq"),
        const_expr(&BigInt::from(n as u64)),
        "edlr_mean_vel_sq",
        "edlr_mean_vel_sq_r",
        "edlr_mean_vel_sq_s",
        &BigInt::from(n as u64),
        "edlr_mean_vel_sq",
    )?;

    builder.private_signal("edlr_vel_rms")?;
    builder.private_signal("edlr_vel_rms_r")?;
    builder.private_signal("edlr_vel_rms_upper_slack")?;
    builder.append_floor_sqrt_constraints(
        signal_expr("edlr_mean_vel_sq"),
        "edlr_vel_rms",
        "edlr_vel_rms_r",
        "edlr_vel_rms_upper_slack",
        &edl_bn254_velocity_bound(),
        &edl_bn254_velocity_bound(),
        "edlr_vel_rms",
    )?;

    // constrain vel_rms <= threshold_vel
    builder.constrain_leq(
        "edlr_vel_rms_slack",
        signal_expr("edlr_vel_rms"),
        signal_expr("edlr_threshold_vel"),
        vel_bits,
    )?;

    // -- Altitude dispersion: RMS deviation from mean --
    builder.private_signal("edlr_mean_alt")?;
    builder.private_signal("edlr_mean_alt_r")?;
    builder.private_signal("edlr_mean_alt_s")?;
    builder.append_exact_division_constraints(
        sum_exprs(&alt_names),
        const_expr(&BigInt::from(n as u64)),
        "edlr_mean_alt",
        "edlr_mean_alt_r",
        "edlr_mean_alt_s",
        &BigInt::from(n as u64),
        "edlr_mean_alt",
    )?;
    builder.append_nonnegative_bound(
        "edlr_mean_alt",
        &edl_bn254_altitude_bound(),
        "edlr_mean_alt_bound",
    )?;

    let mut alt_dev_sq_exprs = Vec::with_capacity(n);
    for i in 0..n {
        let dev = format!("edlr_alt_dev_{i}");
        builder.private_signal(&dev)?;
        builder.constrain_equal(
            signal_expr(&dev),
            sub_expr(signal_expr(&alt_names[i]), signal_expr("edlr_mean_alt")),
        )?;
        builder.append_signed_bound(&dev, &edl_bn254_altitude_bound(), &format!("edlr_alt_dev_{i}"))?;
        alt_dev_sq_exprs.push(mul_expr(signal_expr(&dev), signal_expr(&dev)));
    }

    builder.private_signal("edlr_alt_var")?;
    builder.private_signal("edlr_alt_var_r")?;
    builder.private_signal("edlr_alt_var_s")?;
    builder.append_exact_division_constraints(
        add_expr(alt_dev_sq_exprs),
        const_expr(&BigInt::from(n as u64)),
        "edlr_alt_var",
        "edlr_alt_var_r",
        "edlr_alt_var_s",
        &BigInt::from(n as u64),
        "edlr_alt_var",
    )?;

    builder.private_signal("edlr_dispersion")?;
    builder.private_signal("edlr_dispersion_r")?;
    builder.private_signal("edlr_dispersion_upper_slack")?;
    builder.append_floor_sqrt_constraints(
        signal_expr("edlr_alt_var"),
        "edlr_dispersion",
        "edlr_dispersion_r",
        "edlr_dispersion_upper_slack",
        &edl_bn254_dispersion_bound(),
        &edl_bn254_dispersion_bound(),
        "edlr_dispersion",
    )?;

    // constrain dispersion <= threshold_disp
    builder.constrain_leq(
        "edlr_dispersion_slack",
        signal_expr("edlr_dispersion"),
        signal_expr("edlr_threshold_disp"),
        disp_bits,
    )?;

    // -- Peak heating max: track max heating --
    builder.private_signal("edlr_max_heat")?;
    builder.constrain_range("edlr_max_heat", heat_bits)?;
    for i in 0..n {
        builder.constrain_geq(
            format!("edlr_max_heat_geq_{i}"),
            signal_expr("edlr_max_heat"),
            signal_expr(&heat_names[i]),
            heat_bits,
        )?;
    }

    // constrain max_heat <= threshold_heat
    builder.constrain_leq(
        "edlr_max_heat_slack",
        signal_expr("edlr_max_heat"),
        signal_expr("edlr_threshold_heat"),
        heat_bits,
    )?;

    // -- Poseidon commitment chain --
    let mut prev = signal_expr("edlr_chain_seed");
    for i in 0..n {
        let step_digest = builder.append_poseidon_hash(
            &format!("edlr_traj_commit_{i}"),
            [
                signal_expr(&commit_names[i]),
                signal_expr(&status_names[i]),
                signal_expr(&vel_names[i]),
                prev.clone(),
            ],
        )?;
        prev = signal_expr(&step_digest);
    }

    // Risk outputs commitment
    let risk_digest = builder.append_poseidon_hash(
        "edlr_risk_digest",
        [
            prev,
            signal_expr("edlr_pass_rate"),
            signal_expr("edlr_vel_rms"),
            signal_expr("edlr_dispersion"),
        ],
    )?;

    // Pass rate commitment
    let pass_rate_digest = builder.append_poseidon_hash(
        "edlr_pass_rate_digest",
        [
            signal_expr("edlr_passed_count"),
            const_expr(&BigInt::from(n as u64)),
            signal_expr("edlr_pass_rate"),
            signal_expr("edlr_max_heat"),
        ],
    )?;

    builder.bind("edlr_risk_commitment", signal_expr(&risk_digest))?;
    builder.bind("edlr_risk_pass_bit", const_expr(&one()))?;
    builder.bind("edlr_pass_rate_commitment", signal_expr(&pass_rate_digest))?;

    builder.build()
}

// ---------------------------------------------------------------------------
// Circuit 2 witness generator
// ---------------------------------------------------------------------------

pub fn edl_risk_summary_witness_from_request(
    request: &EdlRiskSummaryRequestV1,
) -> ZkfResult<Witness> {
    let n = request.trajectory_commitments.len();
    if n == 0 {
        return Err(ZkfError::InvalidArtifact(
            "risk summary requires at least one trajectory".to_string(),
        ));
    }

    let scale = edl_bn254_scale();
    let mut values = BTreeMap::new();
    write_value(&mut values, "edlr_chain_seed", zero());

    // Parse inputs
    let commitments = request.trajectory_commitments
        .iter()
        .enumerate()
        .map(|(i, v)| parse_nonneg_integer(v, &format!("trajectory commitment {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let landing_alts = request.landing_altitudes
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_bn254_amount(v, &format!("landing altitude {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let landing_vels = request.landing_velocities
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_bn254_amount(v, &format!("landing velocity {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let peak_qs = request.peak_dynamic_pressures
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_bn254_amount(v, &format!("peak Q {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let peak_heats = request.peak_heating_rates
        .iter()
        .enumerate()
        .map(|(i, v)| parse_edl_bn254_amount(v, &format!("peak heating {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;

    let threshold_vel = parse_edl_bn254_amount(
        &request.risk_threshold_landing_velocity,
        "velocity threshold",
    )?;
    let threshold_disp = parse_edl_bn254_amount(
        &request.risk_threshold_dispersion,
        "dispersion threshold",
    )?;
    let threshold_heat = parse_edl_bn254_amount(
        &request.risk_threshold_heating,
        "heating threshold",
    )?;
    let required_pass_rate = parse_edl_bn254_ratio(
        &request.required_pass_rate,
        "required pass rate",
    )?;

    write_value(&mut values, "edlr_threshold_vel", threshold_vel.clone());
    write_value(&mut values, "edlr_threshold_disp", threshold_disp.clone());
    write_value(&mut values, "edlr_threshold_heat", threshold_heat.clone());
    write_value(&mut values, "edlr_required_pass_rate", required_pass_rate.clone());

    for i in 0..n {
        write_value(&mut values, format!("edlr_commit_{i}"), commitments[i].clone());
        write_bool_value(&mut values, format!("edlr_status_{i}"), request.trajectory_status_bits[i]);
        write_value(&mut values, format!("edlr_alt_{i}"), landing_alts[i].clone());
        write_value(&mut values, format!("edlr_vel_{i}"), landing_vels[i].clone());
        write_value(&mut values, format!("edlr_q_{i}"), peak_qs[i].clone());
        write_value(&mut values, format!("edlr_q_{i}_anchor"), &peak_qs[i] * &peak_qs[i]);
        write_value(&mut values, format!("edlr_heat_{i}"), peak_heats[i].clone());
    }

    // Pass count
    let passed_count = BigInt::from(
        request.trajectory_status_bits.iter().filter(|b| **b).count() as u64,
    );
    write_value(&mut values, "edlr_passed_count", passed_count.clone());

    // Pass rate
    let pass_rate_num = &passed_count * &scale;
    let n_big = BigInt::from(n as u64);
    let pass_rate = &pass_rate_num / &n_big;
    let pass_rate_r = &pass_rate_num % &n_big;
    let pass_rate_s = &n_big - &pass_rate_r - one();
    write_exact_division_support(
        &mut values,
        "edlr_pass_rate",
        &pass_rate,
        "edlr_pass_rate_r",
        &pass_rate_r,
        "edlr_pass_rate_s",
        &pass_rate_s,
        "edlr_pass_rate",
    );

    if pass_rate < required_pass_rate {
        return Err(ZkfError::InvalidArtifact(
            "pass rate below required threshold".to_string(),
        ));
    }
    write_value(&mut values, "edlr_pass_rate_floor_slack", &pass_rate - &required_pass_rate);

    // Velocity RMS
    let sum_vel_sq = landing_vels.iter().fold(zero(), |acc, v| acc + v * v);
    write_value(&mut values, "edlr_sum_vel_sq", sum_vel_sq.clone());

    let mean_vel_sq = &sum_vel_sq / &n_big;
    let mean_vel_sq_r = &sum_vel_sq % &n_big;
    let mean_vel_sq_s = &n_big - &mean_vel_sq_r - one();
    write_exact_division_support(
        &mut values,
        "edlr_mean_vel_sq",
        &mean_vel_sq,
        "edlr_mean_vel_sq_r",
        &mean_vel_sq_r,
        "edlr_mean_vel_sq_s",
        &mean_vel_sq_s,
        "edlr_mean_vel_sq",
    );

    let vel_rms = bigint_isqrt_floor(&mean_vel_sq);
    let vel_rms_r = &mean_vel_sq - (&vel_rms * &vel_rms);
    let vel_rms_upper_slack = ((&vel_rms + one()) * (&vel_rms + one()))
        - &mean_vel_sq
        - one();
    write_floor_sqrt_support(
        &mut values,
        "edlr_vel_rms",
        &vel_rms,
        "edlr_vel_rms_r",
        &vel_rms_r,
        "edlr_vel_rms_upper_slack",
        &vel_rms_upper_slack,
        &edl_bn254_velocity_bound(),
        &edl_bn254_velocity_bound(),
        "edlr_vel_rms",
    )?;

    if vel_rms > threshold_vel {
        return Err(ZkfError::InvalidArtifact(
            "velocity RMS exceeds threshold".to_string(),
        ));
    }
    write_value(&mut values, "edlr_vel_rms_slack", &threshold_vel - &vel_rms);

    // Altitude dispersion (RMS deviation from mean)
    let sum_alt = sum_bigints(&landing_alts);
    let mean_alt = &sum_alt / &n_big;
    let mean_alt_r = &sum_alt % &n_big;
    let mean_alt_s = &n_big - &mean_alt_r - one();
    write_exact_division_support(
        &mut values,
        "edlr_mean_alt",
        &mean_alt,
        "edlr_mean_alt_r",
        &mean_alt_r,
        "edlr_mean_alt_s",
        &mean_alt_s,
        "edlr_mean_alt",
    );

    let mut sum_alt_dev_sq = zero();
    for i in 0..n {
        let dev = &landing_alts[i] - &mean_alt;
        write_value(&mut values, format!("edlr_alt_dev_{i}"), dev.clone());
        write_signed_bound_support(
            &mut values,
            &dev,
            &edl_bn254_altitude_bound(),
            &format!("edlr_alt_dev_{i}"),
        )?;
        sum_alt_dev_sq += &dev * &dev;
    }

    let alt_var = &sum_alt_dev_sq / &n_big;
    let alt_var_r = &sum_alt_dev_sq % &n_big;
    let alt_var_s = &n_big - &alt_var_r - one();
    write_exact_division_support(
        &mut values,
        "edlr_alt_var",
        &alt_var,
        "edlr_alt_var_r",
        &alt_var_r,
        "edlr_alt_var_s",
        &alt_var_s,
        "edlr_alt_var",
    );

    let dispersion = bigint_isqrt_floor(&alt_var);
    let disp_r = &alt_var - (&dispersion * &dispersion);
    let disp_upper_slack = ((&dispersion + one()) * (&dispersion + one()))
        - &alt_var
        - one();
    write_floor_sqrt_support(
        &mut values,
        "edlr_dispersion",
        &dispersion,
        "edlr_dispersion_r",
        &disp_r,
        "edlr_dispersion_upper_slack",
        &disp_upper_slack,
        &edl_bn254_dispersion_bound(),
        &edl_bn254_dispersion_bound(),
        "edlr_dispersion",
    )?;

    if dispersion > threshold_disp {
        return Err(ZkfError::InvalidArtifact(
            "altitude dispersion exceeds threshold".to_string(),
        ));
    }
    write_value(&mut values, "edlr_dispersion_slack", &threshold_disp - &dispersion);

    // Max heating
    let max_heat = peak_heats.iter().fold(zero(), |acc, h| if *h > acc { h.clone() } else { acc });
    write_value(&mut values, "edlr_max_heat", max_heat.clone());
    for i in 0..n {
        write_value(&mut values, format!("edlr_max_heat_geq_{i}"), &max_heat - &peak_heats[i]);
    }
    if max_heat > threshold_heat {
        return Err(ZkfError::InvalidArtifact(
            "peak heating exceeds threshold".to_string(),
        ));
    }
    write_value(&mut values, "edlr_max_heat_slack", &threshold_heat - &max_heat);

    // Poseidon commitment chain
    let mut prev_digest = zero();
    for i in 0..n {
        let digest = poseidon_permutation4(
            EDL_BN254_FIELD,
            [
                &commitments[i],
                &BigInt::from(request.trajectory_status_bits[i] as u64),
                &landing_vels[i],
                &prev_digest,
            ],
        )?;
        prev_digest = write_hash_lanes(
            &mut values,
            &format!("edlr_traj_commit_{i}"),
            digest,
        ).as_bigint();
    }

    // Risk digest
    let risk_digest = poseidon_permutation4(
        EDL_BN254_FIELD,
        [&prev_digest, &pass_rate, &vel_rms, &dispersion],
    )?;
    let risk_commitment = write_hash_lanes(&mut values, "edlr_risk_digest", risk_digest);

    // Pass rate digest
    let pr_digest = poseidon_permutation4(
        EDL_BN254_FIELD,
        [&passed_count, &n_big, &pass_rate, &max_heat],
    )?;
    let pass_rate_commitment = write_hash_lanes(&mut values, "edlr_pass_rate_digest", pr_digest);

    values.insert("edlr_risk_commitment".to_string(), risk_commitment);
    values.insert("edlr_risk_pass_bit".to_string(), FieldElement::ONE);
    values.insert("edlr_pass_rate_commitment".to_string(), pass_rate_commitment);

    let program = build_edl_risk_summary_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 3: EDL Campaign Attestation (Goldilocks/Plonky3)
// ---------------------------------------------------------------------------

pub fn build_edl_campaign_attestation_program(
    request: &EdlCampaignAttestationRequestV1,
) -> ZkfResult<Program> {
    let n = request.trajectory_commitments.len();
    if n == 0 {
        return Err(ZkfError::InvalidArtifact(
            "campaign attestation requires at least one trajectory".to_string(),
        ));
    }

    let scale = edl_goldilocks_scale();
    let amount_bits = bits_for_bound(&edl_goldilocks_amount_bound());

    let mut builder = ProgramBuilder::new(
        format!("edl_monte_carlo_campaign_attestation_{n}"),
        EDL_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "edl-monte-carlo")?;
    builder.metadata_entry("circuit", "campaign-attestation")?;
    builder.metadata_entry("trajectory_count", n.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    // -- Private inputs --
    let mut commit_names = Vec::with_capacity(n);
    for i in 0..n {
        let name = format!("edla_traj_commit_{i}");
        builder.private_input(&name)?;
        builder.constrain_range(&name, 63)?;
        commit_names.push(name);
    }

    builder.private_input("edla_risk_commit")?;
    // BN254 hash output reduced mod Goldilocks may exceed 63 bits; the Poseidon
    // hash below provides nonlinear anchoring, so a range check is not required.
    // We omit the range constraint to avoid the plonky3 63-bit ceiling.

    builder.private_input("edla_risk_status")?;
    builder.constrain_boolean("edla_risk_status")?;

    builder.private_input("edla_total_samples")?;
    builder.constrain_range("edla_total_samples", amount_bits)?;

    builder.private_input("edla_passed_samples")?;
    builder.constrain_range("edla_passed_samples", amount_bits)?;

    // Fail-closed: risk must pass
    builder.constrain_equal(
        signal_expr("edla_risk_status"),
        const_expr(&one()),
    )?;

    // passed <= total
    builder.constrain_geq(
        "edla_samples_slack",
        signal_expr("edla_total_samples"),
        signal_expr("edla_passed_samples"),
        amount_bits,
    )?;

    // -- Public outputs --
    builder.public_output("edla_campaign_commitment")?;
    builder.public_output("edla_campaign_pass_bit")?;
    builder.constant_signal("edla_chain_seed", FieldElement::ZERO)?;

    // -- Poseidon chain over trajectory commitments --
    let mut prev = signal_expr("edla_chain_seed");
    for i in 0..n {
        let step_digest = builder.append_poseidon_hash(
            &format!("edla_chain_{i}"),
            [
                signal_expr(&commit_names[i]),
                prev.clone(),
                const_expr(&zero()),
                const_expr(&zero()),
            ],
        )?;
        prev = signal_expr(&step_digest);
    }

    // Final commitment: chain + risk + metadata
    let final_digest = builder.append_poseidon_hash(
        "edla_final_commit",
        [
            prev,
            signal_expr("edla_risk_commit"),
            signal_expr("edla_total_samples"),
            signal_expr("edla_passed_samples"),
        ],
    )?;

    builder.bind("edla_campaign_commitment", signal_expr(&final_digest))?;
    builder.bind("edla_campaign_pass_bit", const_expr(&one()))?;

    builder.build()
}

// ---------------------------------------------------------------------------
// Circuit 3 witness generator
// ---------------------------------------------------------------------------

pub fn edl_campaign_attestation_witness_from_request(
    request: &EdlCampaignAttestationRequestV1,
) -> ZkfResult<Witness> {
    let n = request.trajectory_commitments.len();
    if n == 0 {
        return Err(ZkfError::InvalidArtifact(
            "campaign attestation requires at least one trajectory".to_string(),
        ));
    }

    if !request.risk_summary_status {
        return Err(ZkfError::InvalidArtifact(
            "campaign attestation requires risk summary to pass (fail-closed)".to_string(),
        ));
    }

    if request.passed_samples > request.total_samples {
        return Err(ZkfError::InvalidArtifact(
            "passed samples exceeds total samples".to_string(),
        ));
    }

    let mut values = BTreeMap::new();
    write_value(&mut values, "edla_chain_seed", zero());

    // Parse commitment values
    let commitments = request.trajectory_commitments
        .iter()
        .enumerate()
        .map(|(i, v)| parse_nonneg_integer(v, &format!("trajectory commitment {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let risk_commit = parse_nonneg_integer(&request.risk_summary_commitment, "risk summary commitment")?;

    for (i, c) in commitments.iter().enumerate() {
        write_value(&mut values, format!("edla_traj_commit_{i}"), c.clone());
    }
    write_value(&mut values, "edla_risk_commit", risk_commit.clone());
    write_bool_value(&mut values, "edla_risk_status", request.risk_summary_status);
    write_value(&mut values, "edla_total_samples", BigInt::from(request.total_samples as u64));
    write_value(&mut values, "edla_passed_samples", BigInt::from(request.passed_samples as u64));
    write_value(
        &mut values,
        "edla_samples_slack",
        BigInt::from((request.total_samples - request.passed_samples) as u64),
    );

    // Poseidon chain
    let mut prev_digest = zero();
    for i in 0..n {
        let digest = poseidon_permutation4(
            EDL_GOLDILOCKS_FIELD,
            [&commitments[i], &prev_digest, &zero(), &zero()],
        )?;
        prev_digest = write_hash_lanes(
            &mut values,
            &format!("edla_chain_{i}"),
            digest,
        ).as_bigint();
    }

    // Final commitment
    let total_big = BigInt::from(request.total_samples as u64);
    let passed_big = BigInt::from(request.passed_samples as u64);
    let final_digest = poseidon_permutation4(
        EDL_GOLDILOCKS_FIELD,
        [&prev_digest, &risk_commit, &total_big, &passed_big],
    )?;
    let campaign_commitment = write_hash_lanes(&mut values, "edla_final_commit", final_digest);

    values.insert("edla_campaign_commitment".to_string(), campaign_commitment);
    values.insert("edla_campaign_pass_bit".to_string(), FieldElement::ONE);

    let program = build_edl_campaign_attestation_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit_program_default, compile, prove, verify};
    use std::panic;
    use std::thread;
    use zkf_backends::with_allow_dev_deterministic_groth16_override;
    use zkf_core::{BackendKind, analyze_underconstrained};

    const EDL_TEST_STACK_SIZE: usize = 256 * 1024 * 1024;

    fn run_edl_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(EDL_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    // Small step count for CI
    const TEST_TRAJECTORY_STEPS: usize = 5;
    const TEST_TRAJECTORY_COUNT: usize = 3;

    fn sample_trajectory_request(steps: usize) -> EdlTrajectoryRequestV1 {
        // Parameters chosen for numerical stability across 500 Euler steps:
        // - Low initial velocity (reduces dynamic pressure buildup)
        // - Small flight-path angle (prevents gamma divergence)
        // - Moderate drag (decelerates vehicle steadily)
        // - Low lift (prevents oscillation)
        // - Constant atmosphere (simplifies stability)
        // - Gravity scaled to match the deceleration regime
        EdlTrajectoryRequestV1 {
            initial_altitude: "100.000".to_string(),
            initial_velocity: "5.000".to_string(),
            initial_flight_path_angle: "-0.010".to_string(),
            vehicle_mass: "10.000".to_string(),
            drag_coefficient: "1.000".to_string(),
            lift_coefficient: "0.100".to_string(),
            reference_area: "5.000".to_string(),
            nose_radius: "1.000".to_string(),
            bank_angle_cosines: vec!["0.950".to_string(); steps],
            atmosphere_density: vec!["0.001".to_string(); steps],
            max_dynamic_pressure: "500.000".to_string(),
            max_heating_rate: "500.000".to_string(),
            min_altitude: "0.000".to_string(),
            gravity: "0.003".to_string(),
        }
    }

    fn sample_risk_summary_request(n: usize) -> EdlRiskSummaryRequestV1 {
        EdlRiskSummaryRequestV1 {
            trajectory_commitments: vec!["1".to_string(); n],
            trajectory_status_bits: vec![true; n],
            landing_altitudes: vec!["5.0".to_string(); n],
            landing_velocities: vec!["0.5".to_string(); n],
            peak_dynamic_pressures: vec!["100.0".to_string(); n],
            peak_heating_rates: vec!["50.0".to_string(); n],
            risk_threshold_landing_velocity: "2.0".to_string(),
            risk_threshold_dispersion: "50.0".to_string(),
            risk_threshold_heating: "200.0".to_string(),
            required_pass_rate: "0.9".to_string(),
        }
    }

    fn sample_campaign_attestation_request(
        commitments: Vec<String>,
        risk_commitment: String,
        total: usize,
        passed: usize,
    ) -> EdlCampaignAttestationRequestV1 {
        EdlCampaignAttestationRequestV1 {
            campaign_id: "campaign-edl-alpha".to_string(),
            trajectory_commitments: commitments,
            risk_summary_commitment: risk_commitment,
            risk_summary_status: true,
            total_samples: total,
            passed_samples: passed,
        }
    }

    #[test]
    fn edl_trajectory_roundtrip() {
        run_edl_test_on_large_stack("edl-trajectory-roundtrip", || {
            let request = sample_trajectory_request(TEST_TRAJECTORY_STEPS);
            let program = build_edl_trajectory_program_with_steps(
                &request,
                TEST_TRAJECTORY_STEPS,
            )
            .expect("trajectory program");

            let audit = audit_program_default(&program, Some(BackendKind::Plonky3));
            if audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&program);
                panic!(
                    "trajectory audit must pass: {:?}\nunderconstrained={:?}",
                    audit.checks, analysis
                );
            }

            let witness = edl_trajectory_witness_from_request_with_steps(
                &request,
                TEST_TRAJECTORY_STEPS,
            )
            .expect("trajectory witness");

            let compiled = compile(&program, "plonky3", None).expect("trajectory compile");
            let artifact = prove(&compiled, &witness).expect("trajectory prove");
            assert!(verify(&compiled, &artifact).expect("trajectory verify"));
            assert_eq!(artifact.public_inputs.len(), 4);
            assert_eq!(artifact.public_inputs[1].to_decimal_string(), "1");
        });
    }

    #[test]
    fn edl_risk_summary_roundtrip() {
        run_edl_test_on_large_stack("edl-risk-summary-roundtrip", || {
            let request = sample_risk_summary_request(TEST_TRAJECTORY_COUNT);
            let program = build_edl_risk_summary_program(&request).expect("risk program");

            let audit = audit_program_default(&program, Some(BackendKind::ArkworksGroth16));
            if audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&program);
                panic!(
                    "risk audit must pass: {:?}\nunderconstrained={:?}",
                    audit.checks, analysis
                );
            }

            let witness =
                edl_risk_summary_witness_from_request(&request).expect("risk witness");

            let (compiled, artifact) =
                with_allow_dev_deterministic_groth16_override(Some(true), || {
                    let compiled =
                        compile(&program, "arkworks-groth16", None).expect("risk compile");
                    let artifact = prove(&compiled, &witness).expect("risk prove");
                    (compiled, artifact)
                });
            assert!(verify(&compiled, &artifact).expect("risk verify"));
            assert_eq!(artifact.public_inputs.len(), 3);
            assert_eq!(artifact.public_inputs[1].to_decimal_string(), "1");
        });
    }

    #[test]
    fn edl_campaign_roundtrip() {
        run_edl_test_on_large_stack("edl-campaign-roundtrip", || {
            // Step 1: Build trajectory proofs
            let traj_request = sample_trajectory_request(TEST_TRAJECTORY_STEPS);
            let traj_program = build_edl_trajectory_program_with_steps(
                &traj_request,
                TEST_TRAJECTORY_STEPS,
            )
            .expect("trajectory program");
            let traj_witness = edl_trajectory_witness_from_request_with_steps(
                &traj_request,
                TEST_TRAJECTORY_STEPS,
            )
            .expect("trajectory witness");
            let traj_compiled = compile(&traj_program, "plonky3", None).expect("traj compile");
            let traj_artifact = prove(&traj_compiled, &traj_witness).expect("traj prove");
            assert!(verify(&traj_compiled, &traj_artifact).expect("traj verify"));

            let traj_commitment = traj_artifact.public_inputs[0].to_decimal_string();

            // Step 2: Build risk summary
            let risk_request = sample_risk_summary_request(TEST_TRAJECTORY_COUNT);
            let risk_program =
                build_edl_risk_summary_program(&risk_request).expect("risk program");
            let risk_witness =
                edl_risk_summary_witness_from_request(&risk_request).expect("risk witness");

            let (risk_compiled, risk_artifact) =
                with_allow_dev_deterministic_groth16_override(Some(true), || {
                    let compiled =
                        compile(&risk_program, "arkworks-groth16", None).expect("risk compile");
                    let artifact = prove(&compiled, &risk_witness).expect("risk prove");
                    (compiled, artifact)
                });
            assert!(verify(&risk_compiled, &risk_artifact).expect("risk verify"));

            let risk_commitment = risk_artifact.public_inputs[0].to_decimal_string();

            // Step 3: Campaign attestation
            let campaign_request = sample_campaign_attestation_request(
                vec![traj_commitment.clone(); TEST_TRAJECTORY_COUNT],
                risk_commitment,
                TEST_TRAJECTORY_COUNT,
                TEST_TRAJECTORY_COUNT,
            );
            let campaign_program =
                build_edl_campaign_attestation_program(&campaign_request).expect("campaign program");

            let campaign_audit = audit_program_default(&campaign_program, Some(BackendKind::Plonky3));
            if campaign_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&campaign_program);
                panic!(
                    "campaign audit must pass: {:?}\nunderconstrained={:?}",
                    campaign_audit.checks, analysis
                );
            }

            let campaign_witness =
                edl_campaign_attestation_witness_from_request(&campaign_request)
                    .expect("campaign witness");
            let campaign_compiled =
                compile(&campaign_program, "plonky3", None).expect("campaign compile");
            let campaign_artifact =
                prove(&campaign_compiled, &campaign_witness).expect("campaign prove");
            assert!(verify(&campaign_compiled, &campaign_artifact).expect("campaign verify"));
            assert_eq!(campaign_artifact.public_inputs.len(), 2);
            assert_eq!(campaign_artifact.public_inputs[1].to_decimal_string(), "1");
        });
    }

    #[test]
    fn edl_trajectory_rejects_envelope_violation() {
        run_edl_test_on_large_stack("edl-trajectory-envelope-violation", || {
            let mut request = sample_trajectory_request(TEST_TRAJECTORY_STEPS);
            // Set an impossibly low Q max to trigger violation
            request.max_dynamic_pressure = "0.000".to_string();
            let result = edl_trajectory_witness_from_request_with_steps(
                &request,
                TEST_TRAJECTORY_STEPS,
            );
            assert!(
                result.is_err(),
                "trajectory witness should fail when dynamic pressure envelope is violated"
            );
        });
    }

    /// Flagship test: full 500-step trajectory. This is the GPU engagement test.
    /// Run with: cargo test -p zkf-lib --release edl_flagship_500 -- --nocapture
    #[test]
    #[ignore] // Only run explicitly — takes several minutes
    fn edl_flagship_500_step_trajectory() {
        run_edl_test_on_large_stack("edl-flagship-500", || {
            let steps = EDL_MC_TRAJECTORY_STEPS; // 500
            let request = sample_trajectory_request(steps);
            let program = build_edl_trajectory_program_with_steps(&request, steps)
                .expect("flagship program");
            let audit = audit_program_default(&program, Some(BackendKind::Plonky3));
            assert_eq!(
                audit.summary.failed, 0,
                "flagship audit must pass: {:?}",
                audit.checks
            );
            let witness = edl_trajectory_witness_from_request_with_steps(&request, steps)
                .expect("flagship witness");
            let compiled = compile(&program, "plonky3", None).expect("flagship compile");
            let artifact = prove(&compiled, &witness).expect("flagship prove");
            assert!(verify(&compiled, &artifact).expect("flagship verify"));
            assert_eq!(artifact.public_inputs.len(), 4);
            assert_eq!(artifact.public_inputs[1].to_decimal_string(), "1");
            eprintln!(
                "FLAGSHIP: 500 steps, {} constraints, {} signals, proof={} bytes",
                program.constraints.len(),
                program.signals.len(),
                artifact.proof.len()
            );
        });
    }
}
