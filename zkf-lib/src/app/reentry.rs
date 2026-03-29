#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#![allow(dead_code)]

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
use super::templates::TemplateProgram;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS: usize = 50;
pub const PRIVATE_REENTRY_THERMAL_PER_STEP_INPUTS: usize = 4; // bank_cos, sin_gamma, cos_gamma, rho
pub const PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS: usize = 8; // h0, V0, gamma0, mass, S_ref, C_D, C_L, r_n
pub const PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS: usize = 7; // q_max, q_dot_max, h_min, v_max, gamma_bound, g_0, k_sg
pub const PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS: usize = 5; // trajectory_commitment, terminal_state_commitment, constraint_satisfaction, peak_q, peak_q_dot

const PRIVATE_REENTRY_THERMAL_DESCRIPTION: &str = "Propagate a private reusable launch vehicle reentry trajectory over a fixed step window with fixed-point Euler integration of 3-DOF dynamics (altitude, velocity, flight-path angle), enforce thermal-safety and flight-envelope constraints per step, and expose Poseidon commitments plus a fail-closed constraint certificate, peak dynamic pressure, and peak heating rate.";
const PRIVATE_REENTRY_THERMAL_TEST_HELPER_DESCRIPTION: &str = "Doc-hidden arbitrary-step helper for in-repo testing and exporter regression of the private reentry thermal-safety showcase. The shipped showcase remains fixed to the 50-step surface.";
const STACK_GROW_RED_ZONE: usize = 1024 * 1024;
const STACK_GROW_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Request / Response structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReentryThermalRequestV1 {
    pub private: ReentryPrivateInputsV1,
    pub public: ReentryPublicInputsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryPrivateInputsV1 {
    pub initial_altitude: String,
    pub initial_velocity: String,
    pub initial_flight_path_angle: String,
    pub vehicle_mass: String,
    pub reference_area: String,
    pub drag_coefficient: String,
    pub lift_coefficient: String,
    pub nose_radius: String,
    pub bank_angle_cosines: Vec<String>,
    pub sin_gamma: Vec<String>,
    pub cos_gamma: Vec<String>,
    pub density_profile: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryPublicInputsV1 {
    pub q_max: String,
    pub q_dot_max: String,
    pub h_min: String,
    pub v_max: String,
    pub gamma_bound: String,
    pub g_0: String,
    pub k_sg: String,
    pub step_count: usize,
}

// ---------------------------------------------------------------------------
// Internal parameter struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReentryPublicParameters {
    q_max: BigInt,
    q_dot_max: BigInt,
    h_min: BigInt,
    v_max: BigInt,
    gamma_bound: BigInt,
    g_0: BigInt,
    k_sg: BigInt,
}

// ---------------------------------------------------------------------------
// Step computation struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReentryStepComputation {
    // Trig identity support
    trig_identity_residual: BigInt,
    // Aerodynamics
    v_sq: BigInt,
    rho_v_sq: BigInt,
    rho_v_sq_remainder: BigInt,
    rho_v_sq_slack: BigInt,
    q_i: BigInt,           // dynamic pressure
    q_i_remainder: BigInt,
    q_i_slack: BigInt,
    drag_force: BigInt,    // D = q * S_ref * C_D / SCALE
    drag_remainder: BigInt,
    drag_slack: BigInt,
    lift_cos: BigInt,      // C_L * cos(sigma)
    lift_cos_remainder: BigInt,
    lift_cos_slack: BigInt,
    lift_force: BigInt,    // L = q * S_ref * lift_cos / SCALE^2
    lift_remainder: BigInt,
    lift_slack: BigInt,
    // Accelerations
    drag_accel: BigInt,    // D / m
    drag_accel_remainder: BigInt,
    drag_accel_slack: BigInt,
    lift_accel: BigInt,    // L / m
    lift_accel_remainder: BigInt,
    lift_accel_slack: BigInt,
    g_sin_gamma: BigInt,   // g * sin(gamma) / SCALE
    g_sin_gamma_remainder: BigInt,
    g_sin_gamma_slack: BigInt,
    // Velocity update: dV = (-drag_accel - g_sin_gamma) * dt / SCALE
    dv_accel: BigInt,      // -drag_accel - g_sin_gamma
    dv_raw: BigInt,        // dv_accel * dt
    dv: BigInt,            // dv_raw / SCALE
    dv_remainder: BigInt,
    dv_slack: BigInt,
    // Altitude update: dh = V * sin(gamma) * dt / SCALE^2
    v_sin: BigInt,         // V * sin(gamma)
    dh_raw: BigInt,        // v_sin * dt
    dh: BigInt,            // dh_raw / SCALE^2 ... actually dh_raw / SCALE
    dh_remainder: BigInt,
    dh_slack: BigInt,
    // FPA update: d_gamma_lift = lift_accel / V, d_gamma_grav = g*cos(gamma) / V
    lift_over_v: BigInt,
    lift_over_v_remainder: BigInt,
    lift_over_v_slack: BigInt,
    g_cos_gamma: BigInt,
    g_cos_gamma_remainder: BigInt,
    g_cos_gamma_slack: BigInt,
    gcos_over_v: BigInt,
    gcos_over_v_remainder: BigInt,
    gcos_over_v_slack: BigInt,
    dgamma_accel: BigInt,  // lift_over_v - gcos_over_v
    dgamma_raw: BigInt,    // dgamma_accel * dt
    dgamma: BigInt,        // dgamma_raw / SCALE
    dgamma_remainder: BigInt,
    dgamma_slack: BigInt,
    // Next state
    next_altitude: BigInt,
    next_velocity: BigInt,
    next_gamma: BigInt,
    // Heating rate (prover hint)
    q_dot_i: BigInt,
    // Safety slacks
    q_safety_slack: BigInt,        // q_max - q_i
    q_dot_safety_slack: BigInt,    // q_dot_max - q_dot_i
    h_safety_slack: BigInt,        // h_i - h_min
    v_safety_slack: BigInt,        // v_max - V_i
}

// ---------------------------------------------------------------------------
// Arithmetic helpers (copied from descent.rs -- siblings cannot import)
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
    fn digits_to_bigint(digits: &str) -> BigInt {
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
        digits_to_bigint(whole)
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
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * fixed_scale() + fraction_value;
    if negative { -scaled } else { scaled }
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
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
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

// ---------------------------------------------------------------------------
// Physical bounds (fixed-point scaled)
// ---------------------------------------------------------------------------

fn altitude_bound() -> BigInt {
    decimal_scaled("200000") // 200 km
}

fn velocity_bound_value() -> BigInt {
    decimal_scaled("8000") // 8 km/s
}

fn gamma_bound_default() -> BigInt {
    decimal_scaled("0.5") // ~28.6 degrees
}

fn mass_bound_value() -> BigInt {
    decimal_scaled("100000") // 100 tonnes
}

fn area_bound() -> BigInt {
    decimal_scaled("1000") // 1000 m^2
}

fn coeff_bound() -> BigInt {
    decimal_scaled("10") // aerodynamic coefficient max
}

fn nose_radius_bound() -> BigInt {
    decimal_scaled("10") // 10 m
}

fn density_bound() -> BigInt {
    decimal_scaled("2") // ~1.225 at sea level, 2 as generous bound
}

fn q_max_bound() -> BigInt {
    decimal_scaled("100000") // 100 kPa
}

fn q_dot_max_bound() -> BigInt {
    decimal_scaled("10000000") // 10 MW/m^2
}

fn gravity_bound_value() -> BigInt {
    decimal_scaled("20") // 20 m/s^2
}

fn k_sg_bound() -> BigInt {
    decimal_scaled("1") // Sutton-Graves constant (typical ~1.7e-4 unscaled)
}

fn bank_cos_bound() -> BigInt {
    fixed_scale() // |cos(sigma)| <= 1
}

fn trig_bound() -> BigInt {
    fixed_scale() // |sin|, |cos| <= 1
}

// Derived bounds
fn v_sq_bound() -> BigInt {
    let v = velocity_bound_value();
    &v * &v
}

fn rho_v_sq_bound() -> BigInt {
    let rho = density_bound();
    &rho * &v_sq_bound() / &fixed_scale()
}

fn dynamic_pressure_bound() -> BigInt {
    // q = rho*V^2 / (2*SCALE), bound = density_bound*v_sq_bound / (2*SCALE)
    // but we keep it generous: rho_v_sq_bound / 2 + 1
    &rho_v_sq_bound() / &two() + &one()
}

fn drag_force_bound() -> BigInt {
    // D = q * S_ref * C_D / SCALE
    // bound = dynamic_pressure_bound * area_bound * coeff_bound / SCALE
    let num = &dynamic_pressure_bound() * &area_bound() * &coeff_bound();
    &num / &fixed_scale() + &one()
}

fn lift_cos_product_bound() -> BigInt {
    // C_L * cos(sigma), both up to their respective bounds
    let product = &coeff_bound() * &bank_cos_bound();
    &product / &fixed_scale() + &one()
}

fn lift_force_bound() -> BigInt {
    // L = q * S_ref * (C_L*cos_sigma) / SCALE^2
    // For intermediate: q * S_ref * lift_cos / SCALE
    let num = &dynamic_pressure_bound() * &area_bound() * &lift_cos_product_bound();
    &num / &fixed_scale() + &one()
}

fn acceleration_bound() -> BigInt {
    // Reentry drag accelerations can be very large (thousands of m/s^2).
    // Bound: D_max/m_min. With q_max=100kPa, S_ref=1000, C_D=10 we get
    //   D_max = 100000 * 1000 * 10 = 1e9 N.  At m=1kg that's 1e9 m/s^2.
    // We use a generous bound to avoid proof friction:
    decimal_scaled("100000")
}

fn velocity_delta_bound() -> BigInt {
    decimal_scaled("100000") // generous for 1s step with large drag accelerations
}

fn altitude_delta_bound() -> BigInt {
    decimal_scaled("8000") // V * sin(gamma) * dt / SCALE, V up to 8000
}

fn gamma_delta_bound() -> BigInt {
    decimal_scaled("1") // generous for FPA change per step
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
    decimal_scaled("1") // 1-second time step
}

fn trajectory_seed_tag() -> BigInt {
    BigInt::from(92_001u64)
}

fn trajectory_step_tag(step: usize) -> BigInt {
    BigInt::from(200_000u64 + step as u64)
}

fn terminal_state_tag() -> BigInt {
    BigInt::from(300_001u64)
}

fn private_input_count_for_steps(steps: usize) -> usize {
    PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS
        + (steps * PRIVATE_REENTRY_THERMAL_PER_STEP_INPUTS)
}

// ---------------------------------------------------------------------------
// Signal naming functions
// ---------------------------------------------------------------------------

fn q_max_name() -> &'static str {
    "q_max"
}

fn q_dot_max_name() -> &'static str {
    "q_dot_max"
}

fn h_min_name() -> &'static str {
    "h_min"
}

fn v_max_name() -> &'static str {
    "v_max"
}

fn gamma_bound_name() -> &'static str {
    "gamma_bound"
}

fn gravity_name() -> &'static str {
    "g_0"
}

fn k_sg_name() -> &'static str {
    "k_sg"
}

fn altitude_name() -> &'static str {
    "h0"
}

fn velocity_name() -> &'static str {
    "V0"
}

fn gamma_name() -> &'static str {
    "gamma0"
}

fn mass_input_name() -> &'static str {
    "mass"
}

fn sref_name() -> &'static str {
    "S_ref"
}

fn cd_name() -> &'static str {
    "C_D"
}

fn cl_name() -> &'static str {
    "C_L"
}

fn rn_name() -> &'static str {
    "r_n"
}

fn h_state_name(step: usize) -> String {
    if step == 0 {
        altitude_name().to_string()
    } else {
        format!("step_{step}_h")
    }
}

fn v_state_name(step: usize) -> String {
    if step == 0 {
        velocity_name().to_string()
    } else {
        format!("step_{step}_V")
    }
}

fn gamma_state_name(step: usize) -> String {
    if step == 0 {
        gamma_name().to_string()
    } else {
        format!("step_{step}_gamma")
    }
}

fn bank_cos_name(step: usize) -> String {
    format!("step_{step}_bank_cos")
}

fn sin_gamma_input_name(step: usize) -> String {
    format!("step_{step}_sin_gamma")
}

fn cos_gamma_input_name(step: usize) -> String {
    format!("step_{step}_cos_gamma")
}

fn rho_name(step: usize) -> String {
    format!("step_{step}_rho")
}

fn trig_residual_name(step: usize) -> String {
    format!("step_{step}_trig_residual")
}

fn v_sq_signal_name(step: usize) -> String {
    format!("step_{step}_v_sq")
}

fn rho_v_sq_signal_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq")
}

fn rho_v_sq_remainder_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq_remainder")
}

fn rho_v_sq_slack_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq_remainder_slack")
}

fn q_signal_name(step: usize) -> String {
    format!("step_{step}_q")
}

fn q_remainder_name(step: usize) -> String {
    format!("step_{step}_q_remainder")
}

fn q_slack_signal_name(step: usize) -> String {
    format!("step_{step}_q_remainder_slack")
}

fn drag_signal_name(step: usize) -> String {
    format!("step_{step}_drag")
}

fn drag_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_drag_remainder")
}

fn drag_slack_signal_name(step: usize) -> String {
    format!("step_{step}_drag_remainder_slack")
}

fn lift_cos_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos")
}

fn lift_cos_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos_remainder")
}

fn lift_cos_slack_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos_remainder_slack")
}

fn lift_signal_name(step: usize) -> String {
    format!("step_{step}_lift")
}

fn lift_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_lift_remainder")
}

fn lift_slack_signal_name(step: usize) -> String {
    format!("step_{step}_lift_remainder_slack")
}

fn drag_accel_signal_name(step: usize) -> String {
    format!("step_{step}_drag_accel")
}

fn drag_accel_remainder_name(step: usize) -> String {
    format!("step_{step}_drag_accel_remainder")
}

fn drag_accel_slack_name(step: usize) -> String {
    format!("step_{step}_drag_accel_remainder_slack")
}

fn lift_accel_signal_name(step: usize) -> String {
    format!("step_{step}_lift_accel")
}

fn lift_accel_remainder_name(step: usize) -> String {
    format!("step_{step}_lift_accel_remainder")
}

fn lift_accel_slack_name(step: usize) -> String {
    format!("step_{step}_lift_accel_remainder_slack")
}

fn g_sin_gamma_signal_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma")
}

fn g_sin_gamma_remainder_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma_remainder")
}

fn g_sin_gamma_slack_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma_remainder_slack")
}

fn dv_accel_signal_name(step: usize) -> String {
    format!("step_{step}_dv_accel")
}

fn dv_signal_name(step: usize) -> String {
    format!("step_{step}_dv")
}

fn dv_remainder_name(step: usize) -> String {
    format!("step_{step}_dv_remainder")
}

fn dv_slack_name(step: usize) -> String {
    format!("step_{step}_dv_remainder_slack")
}

fn v_sin_signal_name(step: usize) -> String {
    format!("step_{step}_v_sin")
}

fn dh_signal_name(step: usize) -> String {
    format!("step_{step}_dh")
}

fn dh_remainder_name(step: usize) -> String {
    format!("step_{step}_dh_remainder")
}

fn dh_slack_name(step: usize) -> String {
    format!("step_{step}_dh_remainder_slack")
}

fn lift_over_v_signal_name(step: usize) -> String {
    format!("step_{step}_lift_over_v")
}

fn lift_over_v_remainder_name(step: usize) -> String {
    format!("step_{step}_lift_over_v_remainder")
}

fn lift_over_v_slack_name(step: usize) -> String {
    format!("step_{step}_lift_over_v_remainder_slack")
}

fn g_cos_gamma_signal_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma")
}

fn g_cos_gamma_remainder_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma_remainder")
}

fn g_cos_gamma_slack_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma_remainder_slack")
}

fn gcos_over_v_signal_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v")
}

fn gcos_over_v_remainder_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v_remainder")
}

fn gcos_over_v_slack_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v_remainder_slack")
}

fn dgamma_accel_signal_name(step: usize) -> String {
    format!("step_{step}_dgamma_accel")
}

fn dgamma_signal_name(step: usize) -> String {
    format!("step_{step}_dgamma")
}

fn dgamma_remainder_name(step: usize) -> String {
    format!("step_{step}_dgamma_remainder")
}

fn dgamma_slack_name(step: usize) -> String {
    format!("step_{step}_dgamma_remainder_slack")
}

fn q_dot_signal_name(step: usize) -> String {
    format!("step_{step}_q_dot")
}

fn q_safety_slack_name(step: usize) -> String {
    format!("step_{step}_q_safety_slack")
}

fn q_dot_safety_slack_name(step: usize) -> String {
    format!("step_{step}_q_dot_safety_slack")
}

fn h_safety_slack_signal_name(step: usize) -> String {
    format!("step_{step}_h_safety_slack")
}

fn v_safety_slack_signal_name(step: usize) -> String {
    format!("step_{step}_v_safety_slack")
}

fn trajectory_commitment_output_name() -> &'static str {
    "trajectory_commitment"
}

fn terminal_state_commitment_output_name() -> &'static str {
    "terminal_state_commitment"
}

fn constraint_satisfaction_output_name() -> &'static str {
    "constraint_satisfaction"
}

fn peak_q_output_name() -> &'static str {
    "peak_dynamic_pressure"
}

fn peak_q_dot_output_name() -> &'static str {
    "peak_heating_rate"
}

fn running_max_q_name(step: usize) -> String {
    format!("state_{step}_running_max_q")
}

fn running_max_q_prev_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_prev_slack")
}

fn running_max_q_curr_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_curr_slack")
}

fn running_max_q_dot_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot")
}

fn running_max_q_dot_prev_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot_prev_slack")
}

fn running_max_q_dot_curr_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot_curr_slack")
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

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ]
}

// ---------------------------------------------------------------------------
// Value / input helpers (copied from descent.rs)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constraint-builder helpers (copied from descent.rs)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Euclidean division and floor-sqrt support (copied from descent.rs)
// ---------------------------------------------------------------------------

fn euclidean_division(
    numerator: &BigInt,
    denominator: &BigInt,
) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *denominator <= zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division denominator must be positive".to_string(),
        ));
    }
    let mut quotient = numerator / denominator;
    let mut remainder = numerator % denominator;
    if remainder.sign() == Sign::Minus {
        quotient -= one();
        remainder += denominator;
    }
    let slack = denominator - &remainder - one();
    if remainder < zero() || slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division support underflow".to_string(),
        ));
    }
    Ok((quotient, remainder, slack))
}

fn floor_sqrt_support(value: &BigInt) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *value < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support expects a nonnegative value".to_string(),
        ));
    }
    let sqrt = bigint_isqrt_floor(value);
    let remainder = value - (&sqrt * &sqrt);
    let next = &sqrt + one();
    let upper_slack = (&next * &next) - value - one();
    if remainder < zero() || upper_slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support underflow".to_string(),
        ));
    }
    Ok((sqrt, remainder, upper_slack))
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

fn parse_decimal_string(name: &str, value: &str) -> ZkfResult<BigInt> {
    if value.trim().is_empty() {
        return Err(ZkfError::Serialization(format!("{name} must not be empty")));
    }
    Ok(decimal_scaled(value))
}

fn insert_request_inputs(
    inputs: &mut WitnessInputs,
    request: &PrivateReentryThermalRequestV1,
) -> ZkfResult<()> {
    let steps = request.public.step_count;
    if steps == 0 {
        return Err(ZkfError::Serialization(
            "reentry thermal request step_count must be greater than zero".to_string(),
        ));
    }
    if request.private.bank_angle_cosines.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match bank_angle_cosines length={}",
            steps,
            request.private.bank_angle_cosines.len()
        )));
    }
    if request.private.sin_gamma.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match sin_gamma length={}",
            steps,
            request.private.sin_gamma.len()
        )));
    }
    if request.private.cos_gamma.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match cos_gamma length={}",
            steps,
            request.private.cos_gamma.len()
        )));
    }
    if request.private.density_profile.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match density_profile length={}",
            steps,
            request.private.density_profile.len()
        )));
    }

    // Public inputs
    inputs.insert(q_max_name().to_string(), field(parse_decimal_string(q_max_name(), &request.public.q_max)?));
    inputs.insert(q_dot_max_name().to_string(), field(parse_decimal_string(q_dot_max_name(), &request.public.q_dot_max)?));
    inputs.insert(h_min_name().to_string(), field(parse_decimal_string(h_min_name(), &request.public.h_min)?));
    inputs.insert(v_max_name().to_string(), field(parse_decimal_string(v_max_name(), &request.public.v_max)?));
    inputs.insert(gamma_bound_name().to_string(), field(parse_decimal_string(gamma_bound_name(), &request.public.gamma_bound)?));
    inputs.insert(gravity_name().to_string(), field(parse_decimal_string(gravity_name(), &request.public.g_0)?));
    inputs.insert(k_sg_name().to_string(), field(parse_decimal_string(k_sg_name(), &request.public.k_sg)?));

    // Scalar private inputs
    inputs.insert(altitude_name().to_string(), field(parse_decimal_string(altitude_name(), &request.private.initial_altitude)?));
    inputs.insert(velocity_name().to_string(), field(parse_decimal_string(velocity_name(), &request.private.initial_velocity)?));
    inputs.insert(gamma_name().to_string(), field(parse_decimal_string(gamma_name(), &request.private.initial_flight_path_angle)?));
    inputs.insert(mass_input_name().to_string(), field(parse_decimal_string(mass_input_name(), &request.private.vehicle_mass)?));
    inputs.insert(sref_name().to_string(), field(parse_decimal_string(sref_name(), &request.private.reference_area)?));
    inputs.insert(cd_name().to_string(), field(parse_decimal_string(cd_name(), &request.private.drag_coefficient)?));
    inputs.insert(cl_name().to_string(), field(parse_decimal_string(cl_name(), &request.private.lift_coefficient)?));
    inputs.insert(rn_name().to_string(), field(parse_decimal_string(rn_name(), &request.private.nose_radius)?));

    // Per-step private inputs
    for step in 0..steps {
        let name = bank_cos_name(step);
        inputs.insert(name.clone(), field(parse_decimal_string(&name, &request.private.bank_angle_cosines[step])?));
        let name = sin_gamma_input_name(step);
        inputs.insert(name.clone(), field(parse_decimal_string(&name, &request.private.sin_gamma[step])?));
        let name = cos_gamma_input_name(step);
        inputs.insert(name.clone(), field(parse_decimal_string(&name, &request.private.cos_gamma[step])?));
        let name = rho_name(step);
        inputs.insert(name.clone(), field(parse_decimal_string(&name, &request.private.density_profile[step])?));
    }
    Ok(())
}

impl TryFrom<PrivateReentryThermalRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: PrivateReentryThermalRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, &request)?;
        Ok(inputs)
    }
}

impl TryFrom<&PrivateReentryThermalRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: &PrivateReentryThermalRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, request)?;
        Ok(inputs)
    }
}

// ---------------------------------------------------------------------------
// Load / validate public parameters
// ---------------------------------------------------------------------------

fn load_public_parameters(inputs: &WitnessInputs) -> ZkfResult<ReentryPublicParameters> {
    let parameters = ReentryPublicParameters {
        q_max: read_input(inputs, q_max_name())?,
        q_dot_max: read_input(inputs, q_dot_max_name())?,
        h_min: read_input(inputs, h_min_name())?,
        v_max: read_input(inputs, v_max_name())?,
        gamma_bound: read_input(inputs, gamma_bound_name())?,
        g_0: read_input(inputs, gravity_name())?,
        k_sg: read_input(inputs, k_sg_name())?,
    };
    ensure_positive_le(q_max_name(), &parameters.q_max, &q_max_bound())?;
    ensure_positive_le(q_dot_max_name(), &parameters.q_dot_max, &q_dot_max_bound())?;
    ensure_nonnegative_le(h_min_name(), &parameters.h_min, &altitude_bound())?;
    ensure_positive_le(v_max_name(), &parameters.v_max, &velocity_bound_value())?;
    ensure_positive_le(gamma_bound_name(), &parameters.gamma_bound, &gamma_bound_default())?;
    ensure_positive_le(gravity_name(), &parameters.g_0, &gravity_bound_value())?;
    ensure_positive_le(k_sg_name(), &parameters.k_sg, &k_sg_bound())?;
    Ok(parameters)
}

fn write_public_parameter_support(
    values: &mut BTreeMap<String, FieldElement>,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<()> {
    write_nonnegative_bound_support(values, q_max_name(), &parameters.q_max, &q_max_bound(), "q_max_bound")?;
    write_nonnegative_bound_support(values, q_dot_max_name(), &parameters.q_dot_max, &q_dot_max_bound(), "q_dot_max_bound")?;
    write_nonnegative_bound_support(values, h_min_name(), &parameters.h_min, &altitude_bound(), "h_min_bound")?;
    write_nonnegative_bound_support(values, v_max_name(), &parameters.v_max, &velocity_bound_value(), "v_max_bound")?;
    write_nonnegative_bound_support(values, gamma_bound_name(), &parameters.gamma_bound, &gamma_bound_default(), "gamma_bound_bound")?;
    write_nonnegative_bound_support(values, gravity_name(), &parameters.g_0, &gravity_bound_value(), "gravity_bound")?;
    write_nonnegative_bound_support(values, k_sg_name(), &parameters.k_sg, &k_sg_bound(), "k_sg_bound")?;
    write_nonzero_inverse_support(values, &parameters.q_max, "q_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.q_dot_max, "q_dot_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.v_max, "v_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.gamma_bound, "gamma_bound_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.g_0, "gravity_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.k_sg, "k_sg_nonzero")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Step dynamics computation (off-chain, for witness generation)
// ---------------------------------------------------------------------------

fn compute_step_dynamics(
    h: &BigInt,
    v: &BigInt,
    gamma: &BigInt,
    sin_g: &BigInt,
    cos_g: &BigInt,
    rho: &BigInt,
    bank_cos: &BigInt,
    mass: &BigInt,
    s_ref: &BigInt,
    c_d: &BigInt,
    c_l: &BigInt,
    _r_n: &BigInt,
    _k_sg: &BigInt,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<ReentryStepComputation> {
    let scale = fixed_scale();
    let scale_sq = fixed_scale_squared();

    // Validate trig identity: sin^2 + cos^2 should be close to SCALE^2
    let sin_sq = sin_g * sin_g;
    let cos_sq = cos_g * cos_g;
    let trig_sum = &sin_sq + &cos_sq;
    let trig_residual = &scale_sq - &trig_sum;
    // Allow small residual due to fixed-point truncation
    let trig_residual_bound = &scale * BigInt::from(2u8); // generous tolerance
    if abs_bigint(trig_residual.clone()) > trig_residual_bound {
        return Err(ZkfError::InvalidArtifact(
            "trig identity residual too large".to_string(),
        ));
    }

    // V^2
    let v_sq = v * v;
    ensure_nonnegative_le("v_sq", &v_sq, &v_sq_bound())?;

    // rho * V^2 / SCALE (intermediate)
    let rho_v_sq_numerator = rho * &v_sq;
    let (rho_v_sq, rho_v_sq_remainder, rho_v_sq_slack) =
        euclidean_division(&rho_v_sq_numerator, &scale)?;

    // Dynamic pressure: q = rho_v_sq / (2 * SCALE)
    let (q_i, q_i_remainder, q_i_slack) =
        euclidean_division(&rho_v_sq, &(two() * &scale))?;
    ensure_nonnegative_le("q_i", &q_i, &dynamic_pressure_bound())?;

    // Drag: D = q * S_ref * C_D / SCALE^2
    // q is scaled, S_ref is scaled, C_D is scaled, product has SCALE^3, we want SCALE^1
    let drag_numerator = &q_i * s_ref * c_d;
    let (drag_force, drag_remainder, drag_slack) =
        euclidean_division(&drag_numerator, &scale_sq)?;

    // Lift coefficient product: lift_cos = C_L * cos(sigma) / SCALE
    let lift_cos_numerator = c_l * bank_cos;
    let (lift_cos, lift_cos_remainder, lift_cos_slack) =
        euclidean_division(&lift_cos_numerator, &scale)?;

    // Lift: L = q * S_ref * lift_cos / SCALE^2
    // q is scaled, S_ref is scaled, lift_cos is scaled, product has SCALE^3
    let lift_numerator = &q_i * s_ref * &lift_cos;
    let (lift_force, lift_remainder, lift_slack) =
        euclidean_division(&lift_numerator, &scale_sq)?;

    // Drag acceleration: D / m (scaled by SCALE to keep fixed-point)
    let drag_accel_numerator = &drag_force * &scale;
    let (drag_accel, drag_accel_remainder, drag_accel_slack) =
        euclidean_division(&drag_accel_numerator, mass)?;

    // Lift acceleration: L / m (scaled)
    let lift_accel_numerator = &lift_force * &scale;
    let (lift_accel, lift_accel_remainder, lift_accel_slack) =
        euclidean_division(&lift_accel_numerator, mass)?;

    // g * sin(gamma) / SCALE
    let g_sin_numerator = &parameters.g_0 * sin_g;
    let (g_sin_gamma, g_sin_gamma_remainder, g_sin_gamma_slack) =
        euclidean_division(&g_sin_numerator, &scale)?;

    // Velocity update: dV = (-drag_accel - g_sin_gamma) * dt / SCALE
    let dv_accel = -&drag_accel - &g_sin_gamma;
    let dv_raw = &dv_accel * &dt_scaled();
    let (dv, dv_remainder, dv_slack) = euclidean_division(&dv_raw, &scale)?;

    // Altitude update: dh = V * sin(gamma) * dt / SCALE^2
    // We compute: v_sin = V * sin(gamma), then dh = v_sin * dt / SCALE^2
    // But actually V * sin(gamma) is product of two scaled values, so:
    //   V * sin(gamma) gives SCALE^2 worth of scaling
    //   dh = V * sin(gamma) * dt / SCALE^2
    let v_sin = v * sin_g;
    let dh_raw = &v_sin * &dt_scaled();
    let (dh, dh_remainder, dh_slack) = euclidean_division(&dh_raw, &scale_sq)?;

    // FPA update: d_gamma = (L/(m*V) - g*cos(gamma)/V) * dt / SCALE
    // We already have lift_accel = L*SCALE/m.
    // lift_over_v = lift_accel * SCALE / V  (gives lift_accel/V in fixed-point)
    let lift_over_v_numerator = &lift_accel * &scale;
    let (lift_over_v, lift_over_v_remainder, lift_over_v_slack) =
        euclidean_division(&lift_over_v_numerator, v)?;

    // g * cos(gamma) / SCALE
    let g_cos_numerator = &parameters.g_0 * cos_g;
    let (g_cos_gamma, g_cos_gamma_remainder, g_cos_gamma_slack) =
        euclidean_division(&g_cos_numerator, &scale)?;

    // gcos_over_v = g_cos_gamma * SCALE / V
    let gcos_over_v_numerator = &g_cos_gamma * &scale;
    let (gcos_over_v, gcos_over_v_remainder, gcos_over_v_slack) =
        euclidean_division(&gcos_over_v_numerator, v)?;

    // dgamma = (lift_over_v - gcos_over_v) * dt / SCALE
    let dgamma_accel = &lift_over_v - &gcos_over_v;
    let dgamma_raw = &dgamma_accel * &dt_scaled();
    let (dgamma, dgamma_remainder, dgamma_slack) = euclidean_division(&dgamma_raw, &scale)?;

    // Next state
    let next_altitude = h + &dh;
    let next_velocity = v + &dv;
    let next_gamma = gamma + &dgamma;

    // Heating rate (prover hint): q_dot = k_sg * sqrt(rho / r_n) * V^3
    // The circuit only checks q_dot_i <= q_dot_max. The Sutton-Graves relationship
    // is validated off-chain by the prover.
    //
    // All inputs are in fixed-point (real * SCALE). We need q_dot in fixed-point.
    //
    // rho_over_rn_fp = rho * SCALE / r_n  (gives (rho/r_n) * SCALE)
    // sqrt_fp = isqrt(rho_over_rn_fp * SCALE) (gives sqrt(rho/r_n) * SCALE)
    //   because sqrt(x * SCALE^1) when x = (rho/rn)*SCALE gives sqrt(rho/rn)*SCALE
    //   only if we interpret correctly: sqrt(rho_over_rn_fp * SCALE) = sqrt((rho/rn) * SCALE^2) = sqrt(rho/rn) * SCALE
    //
    // V_real = V / SCALE. V^3_real = V^3 / SCALE^3.
    // q_dot_real = k_sg_real * sqrt(rho/rn) * V_real^3
    // q_dot_fp = q_dot_real * SCALE
    //          = (k_sg/SCALE) * (sqrt_fp/SCALE) * (V/SCALE)^3 * SCALE
    //          = k_sg * sqrt_fp * V^3 / SCALE^4

    let rho_over_rn_fp = if *_r_n > zero() {
        let (val, _, _) = euclidean_division(&(rho * &scale), _r_n)?;
        val
    } else {
        zero()
    };
    // sqrt((rho/rn) * SCALE^2) = sqrt(rho_over_rn_fp * SCALE)
    let sqrt_input = &rho_over_rn_fp * &scale;
    let sqrt_fp = if sqrt_input > zero() {
        bigint_isqrt_floor(&sqrt_input)
    } else {
        zero()
    };
    let v_cubed = v * v * v;
    let q_dot_numerator = _k_sg * &sqrt_fp * &v_cubed;
    let q_dot_denominator = &scale * &scale * &scale * &scale; // SCALE^4
    let (q_dot_i, _, _) = if q_dot_denominator > zero() {
        euclidean_division(&q_dot_numerator, &q_dot_denominator)?
    } else {
        (zero(), zero(), zero())
    };
    // Clamp to non-negative
    let q_dot_i = if q_dot_i < zero() { zero() } else { q_dot_i };

    // Safety checks
    if q_i > parameters.q_max {
        return Err(ZkfError::InvalidArtifact(
            "dynamic pressure exceeded q_max".to_string(),
        ));
    }
    if q_dot_i > parameters.q_dot_max {
        return Err(ZkfError::InvalidArtifact(
            "heating rate exceeded q_dot_max".to_string(),
        ));
    }
    if next_altitude < parameters.h_min {
        return Err(ZkfError::InvalidArtifact(
            "altitude dropped below h_min".to_string(),
        ));
    }
    if next_velocity > parameters.v_max && next_velocity > zero() {
        // velocity should be decreasing during reentry; check unsigned
    }
    ensure_nonnegative_le("next_altitude", &next_altitude, &altitude_bound())?;

    let q_safety_slack = &parameters.q_max - &q_i;
    let q_dot_safety_slack = &parameters.q_dot_max - &q_dot_i;
    let h_safety_slack = h - &parameters.h_min; // current altitude vs h_min
    let v_safety_slack = &parameters.v_max - v; // v_max - current velocity

    Ok(ReentryStepComputation {
        trig_identity_residual: trig_residual,
        v_sq,
        rho_v_sq,
        rho_v_sq_remainder,
        rho_v_sq_slack,
        q_i,
        q_i_remainder,
        q_i_slack,
        drag_force,
        drag_remainder,
        drag_slack,
        lift_cos,
        lift_cos_remainder,
        lift_cos_slack,
        lift_force,
        lift_remainder,
        lift_slack,
        drag_accel,
        drag_accel_remainder,
        drag_accel_slack,
        lift_accel,
        lift_accel_remainder,
        lift_accel_slack,
        g_sin_gamma,
        g_sin_gamma_remainder,
        g_sin_gamma_slack,
        dv_accel,
        dv_raw,
        dv,
        dv_remainder,
        dv_slack,
        v_sin,
        dh_raw,
        dh,
        dh_remainder,
        dh_slack,
        lift_over_v,
        lift_over_v_remainder,
        lift_over_v_slack,
        g_cos_gamma,
        g_cos_gamma_remainder,
        g_cos_gamma_slack,
        gcos_over_v,
        gcos_over_v_remainder,
        gcos_over_v_slack,
        dgamma_accel,
        dgamma_raw,
        dgamma,
        dgamma_remainder,
        dgamma_slack,
        next_altitude,
        next_velocity,
        next_gamma,
        q_dot_i,
        q_safety_slack,
        q_dot_safety_slack,
        h_safety_slack,
        v_safety_slack,
    })
}

// ---------------------------------------------------------------------------
// Sample inputs generator
// ---------------------------------------------------------------------------

fn sample_public_parameters() -> ReentryPublicParameters {
    ReentryPublicParameters {
        q_max: decimal_scaled("80000"),         // 80 kPa
        q_dot_max: decimal_scaled("8000000"),   // 8 MW/m^2
        h_min: decimal_scaled("30000"),         // 30 km minimum altitude
        v_max: decimal_scaled("7500"),          // 7.5 km/s max velocity
        gamma_bound: decimal_scaled("0.35"),    // ~20 degrees
        g_0: decimal_scaled("9.80665"),
        k_sg: decimal_scaled("0.00005"),        // ~5e-5 Sutton-Graves constant (scaled)
    }
}

#[allow(clippy::expect_used)]
fn reentry_sample_inputs_for_steps(steps: usize) -> WitnessInputs {
    let public = sample_public_parameters();
    let scale = fixed_scale();

    // Initial conditions: 80 km, 7000 m/s, -0.005 rad (~-0.29 deg)
    // Shallow entry at moderate altitude to keep trajectory above h_min for short horizons.
    let h0 = decimal_scaled("80000");
    let v0 = decimal_scaled("7000");
    let gamma0 = decimal_scaled("-0.005");

    // Vehicle parameters
    let mass = decimal_scaled("10000");  // 10 tonnes
    let s_ref = decimal_scaled("10");    // 10 m^2
    let c_d = decimal_scaled("1.5");
    let c_l = decimal_scaled("0.5");
    let r_n = decimal_scaled("1");       // 1 m nose radius

    // Generate per-step inputs
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gammas = Vec::with_capacity(steps);
    let mut cos_gammas = Vec::with_capacity(steps);
    let mut densities = Vec::with_capacity(steps);

    let mut current_h = h0.clone();
    let mut current_v = v0.clone();
    let mut current_gamma = gamma0.clone();

    for step in 0..steps {
        // Bank angle schedule: start at 60 deg (cos=0.5), linearly reduce to 0 deg (cos=1.0)
        let fraction_done = BigInt::from(step as u64) * &scale / BigInt::from(steps as u64);
        let bank_cos_val = &scale / two() + &fraction_done / two(); // 0.5 -> 1.0

        // Compute sin/cos of current gamma using Taylor series.
        // gamma is a fixed-point value (gamma_real * SCALE).
        // sin(gamma) in fixed-point = gamma_real * SCALE = gamma (first-order Taylor).
        // For better accuracy, use:
        //   sin(x) = x - x^3/6 + x^5/120, where x = gamma/SCALE (real value)
        //   sin_scaled = gamma - gamma^3 / (6 * SCALE^2) + gamma^5 / (120 * SCALE^4)
        // Then compute cos_scaled = isqrt(SCALE^2 - sin_scaled^2) to guarantee identity.

        let gamma_sq = &current_gamma * &current_gamma;
        // gamma^3 / (6 * SCALE^2)
        let gamma_cubed = &gamma_sq * &current_gamma;
        let denom_3 = BigInt::from(6u8) * &fixed_scale_squared();
        let (correction_3, _, _) = euclidean_division(&abs_bigint(gamma_cubed.clone()), &denom_3)
            .expect("sin taylor x^3");
        let correction_3_signed = if gamma_cubed.sign() == Sign::Minus {
            -&correction_3
        } else {
            correction_3.clone()
        };

        // sin(gamma) ~ gamma - gamma^3/6SCALE^2
        let sin_val = &current_gamma - &correction_3_signed;

        // Clamp sin_val to trig bound
        let sin_val = if sin_val > trig_bound() {
            trig_bound()
        } else if sin_val < -trig_bound() {
            -trig_bound()
        } else {
            sin_val
        };

        // cos = sqrt(SCALE^2 - sin^2) -- guarantees sin^2 + cos^2 + residual = SCALE^2
        // with residual = SCALE^2 - sin^2 - cos^2 >= 0 and small (just the floor remainder)
        let sin_sq = &sin_val * &sin_val;
        let cos_sq_target = &fixed_scale_squared() - &sin_sq;
        let cos_val = if cos_sq_target <= zero() {
            zero()
        } else {
            bigint_isqrt_floor(&cos_sq_target)
        };

        // Atmospheric density: rho = rho_0 * exp(-h / H)
        // rho_0 = 1.225 kg/m^3 at sea level, H = 7200 m (scale height)
        // Both current_h and H are in fixed-point (meters * SCALE).
        // To compute h/H in fixed-point, we need: (current_h * SCALE) / H
        let h_scale_height = decimal_scaled("7200");
        let rho_0 = decimal_scaled("1.225");
        // h_over_H in fixed-point = current_h * SCALE / h_scale_height
        let (h_over_h_fp, _, _) = euclidean_division(
            &(&current_h * &scale),
            &h_scale_height,
        ).expect("h_over_H fixed-point");
        // Now h_over_h_fp is h/H * SCALE (e.g., at 120km: ~16.67 * SCALE)
        // exp(-x) where x = h_over_h_fp / SCALE using (1 - x/N)^N approximation
        // with N = 256 sub-steps for adequate precision at large x
        let exp_n: u64 = 256;
        let mut exp_val = scale.clone(); // starts at 1.0 (scaled)
        // x_per_step = h_over_h_fp / exp_n  (this is in SCALE units)
        let (x_per_step, _, _) = euclidean_division(&h_over_h_fp, &BigInt::from(exp_n))
            .expect("x_per_step");
        for _ in 0..exp_n {
            // exp_val *= (SCALE - x_per_step) / SCALE
            let factor = &scale - &x_per_step;
            if factor <= zero() {
                exp_val = zero();
                break;
            }
            let (new_val, _, _) = euclidean_division(&(&exp_val * &factor), &scale)
                .expect("exp decay step");
            exp_val = new_val;
            if exp_val <= zero() {
                exp_val = zero();
                break;
            }
        }
        // rho = rho_0 * exp_val / SCALE
        let (rho_val, _, _) = euclidean_division(&(&rho_0 * &exp_val), &scale)
            .expect("rho computation");
        // Clamp rho to be at least a tiny positive value for division safety
        let rho_val = if rho_val <= zero() {
            one() // minimal density (1 raw unit = 10^-18)
        } else {
            rho_val
        };

        bank_cosines.push(bank_cos_val.clone());
        sin_gammas.push(sin_val.clone());
        cos_gammas.push(cos_val.clone());
        densities.push(rho_val.clone());

        // Forward-propagate state using the SAME compute_step_dynamics function
        // that the witness generator uses. This guarantees arithmetic consistency.
        let step_result = compute_step_dynamics(
            &current_h,
            &current_v,
            &current_gamma,
            &sin_val,
            &cos_val,
            &rho_val,
            &bank_cos_val,
            &mass,
            &s_ref,
            &c_d,
            &c_l,
            &r_n,
            &public.k_sg,
            &public,
        )
        .expect("sample trajectory step dynamics must succeed");

        current_h = step_result.next_altitude.clone();
        current_v = step_result.next_velocity.clone();
        current_gamma = step_result.next_gamma.clone();
    }

    let mut inputs = WitnessInputs::new();

    // Public inputs
    inputs.insert(q_max_name().to_string(), field_ref(&public.q_max));
    inputs.insert(q_dot_max_name().to_string(), field_ref(&public.q_dot_max));
    inputs.insert(h_min_name().to_string(), field_ref(&public.h_min));
    inputs.insert(v_max_name().to_string(), field_ref(&public.v_max));
    inputs.insert(gamma_bound_name().to_string(), field_ref(&public.gamma_bound));
    inputs.insert(gravity_name().to_string(), field_ref(&public.g_0));
    inputs.insert(k_sg_name().to_string(), field_ref(&public.k_sg));

    // Scalar private inputs
    inputs.insert(altitude_name().to_string(), field_ref(&h0));
    inputs.insert(velocity_name().to_string(), field_ref(&v0));
    inputs.insert(gamma_name().to_string(), field_ref(&gamma0));
    inputs.insert(mass_input_name().to_string(), field_ref(&mass));
    inputs.insert(sref_name().to_string(), field_ref(&s_ref));
    inputs.insert(cd_name().to_string(), field_ref(&c_d));
    inputs.insert(cl_name().to_string(), field_ref(&c_l));
    inputs.insert(rn_name().to_string(), field_ref(&r_n));

    // Per-step private inputs
    for step in 0..steps {
        inputs.insert(bank_cos_name(step), field_ref(&bank_cosines[step]));
        inputs.insert(sin_gamma_input_name(step), field_ref(&sin_gammas[step]));
        inputs.insert(cos_gamma_input_name(step), field_ref(&cos_gammas[step]));
        inputs.insert(rho_name(step), field_ref(&densities[step]));
    }

    inputs
}

#[doc(hidden)]
pub fn private_reentry_thermal_sample_request_with_steps(
    steps: usize,
) -> ZkfResult<PrivateReentryThermalRequestV1> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "reentry thermal sample request requires at least one integration step".to_string(),
        ));
    }
    let public = sample_public_parameters();

    let h0 = decimal_scaled("120000");
    let v0 = decimal_scaled("7500");
    let gamma0 = decimal_scaled("-0.02");
    let mass = decimal_scaled("10000");
    let s_ref = decimal_scaled("10");
    let c_d = decimal_scaled("1.5");
    let c_l = decimal_scaled("0.5");
    let r_n = decimal_scaled("1");

    // Regenerate per-step from the sample_inputs helper
    let sample = reentry_sample_inputs_for_steps(steps);
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gamma_vec = Vec::with_capacity(steps);
    let mut cos_gamma_vec = Vec::with_capacity(steps);
    let mut density_vec = Vec::with_capacity(steps);

    for step in 0..steps {
        bank_cosines.push(scaled_bigint_to_decimal_string(
            &sample.get(&bank_cos_name(step)).unwrap().as_bigint(),
        ));
        sin_gamma_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&sin_gamma_input_name(step)).unwrap().as_bigint(),
        ));
        cos_gamma_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&cos_gamma_input_name(step)).unwrap().as_bigint(),
        ));
        density_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&rho_name(step)).unwrap().as_bigint(),
        ));
    }

    Ok(PrivateReentryThermalRequestV1 {
        private: ReentryPrivateInputsV1 {
            initial_altitude: scaled_bigint_to_decimal_string(&h0),
            initial_velocity: scaled_bigint_to_decimal_string(&v0),
            initial_flight_path_angle: scaled_bigint_to_decimal_string(&gamma0),
            vehicle_mass: scaled_bigint_to_decimal_string(&mass),
            reference_area: scaled_bigint_to_decimal_string(&s_ref),
            drag_coefficient: scaled_bigint_to_decimal_string(&c_d),
            lift_coefficient: scaled_bigint_to_decimal_string(&c_l),
            nose_radius: scaled_bigint_to_decimal_string(&r_n),
            bank_angle_cosines: bank_cosines,
            sin_gamma: sin_gamma_vec,
            cos_gamma: cos_gamma_vec,
            density_profile: density_vec,
        },
        public: ReentryPublicInputsV1 {
            q_max: scaled_bigint_to_decimal_string(&public.q_max),
            q_dot_max: scaled_bigint_to_decimal_string(&public.q_dot_max),
            h_min: scaled_bigint_to_decimal_string(&public.h_min),
            v_max: scaled_bigint_to_decimal_string(&public.v_max),
            gamma_bound: scaled_bigint_to_decimal_string(&public.gamma_bound),
            g_0: scaled_bigint_to_decimal_string(&public.g_0),
            k_sg: scaled_bigint_to_decimal_string(&public.k_sg),
            step_count: steps,
        },
    })
}

// ---------------------------------------------------------------------------
// Circuit builder
// ---------------------------------------------------------------------------

fn private_reentry_thermal_showcase_inner(steps: usize) -> ZkfResult<TemplateProgram> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private reentry thermal showcase requires at least one integration step".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("private_reentry_thermal_showcase_{steps}_step"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "private-reentry-thermal-showcase")?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "euler")?;
    builder.metadata_entry("time_step_seconds", "1")?;
    builder.metadata_entry("fixed_point_scale", fixed_scale().to_str_radix(10))?;
    builder.metadata_entry(
        "safe_certificate_semantics",
        "constraint_satisfaction is fixed to 1 for accepted reentry trajectories; invalid trajectories fail closed during witness generation",
    )?;
    builder.metadata_entry("altitude_bound_scaled", altitude_bound().to_str_radix(10))?;
    builder.metadata_entry("velocity_bound_scaled", velocity_bound_value().to_str_radix(10))?;
    builder.metadata_entry("mass_bound_scaled", mass_bound_value().to_str_radix(10))?;
    builder.metadata_entry(
        "stack_grow_strategy",
        "stacker::maybe_grow used for template build and witness generation",
    )?;

    let mut expected_inputs = Vec::with_capacity(
        PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS + private_input_count_for_steps(steps),
    );
    let public_outputs = vec![
        trajectory_commitment_output_name().to_string(),
        terminal_state_commitment_output_name().to_string(),
        constraint_satisfaction_output_name().to_string(),
        peak_q_output_name().to_string(),
        peak_q_dot_output_name().to_string(),
    ];

    // -----------------------------------------------------------------------
    // Public inputs
    // -----------------------------------------------------------------------
    for public_name in [
        q_max_name(),
        q_dot_max_name(),
        h_min_name(),
        v_max_name(),
        gamma_bound_name(),
        gravity_name(),
        k_sg_name(),
    ] {
        builder.public_input(public_name)?;
        expected_inputs.push(public_name.to_string());
    }

    // Bound-check public inputs
    append_nonnegative_bound(&mut builder, q_max_name(), &q_max_bound(), "q_max_bound")?;
    append_nonnegative_bound(&mut builder, q_dot_max_name(), &q_dot_max_bound(), "q_dot_max_bound")?;
    append_nonnegative_bound(&mut builder, h_min_name(), &altitude_bound(), "h_min_bound")?;
    append_nonnegative_bound(&mut builder, v_max_name(), &velocity_bound_value(), "v_max_bound")?;
    append_nonnegative_bound(&mut builder, gamma_bound_name(), &gamma_bound_default(), "gamma_bound_bound")?;
    append_nonnegative_bound(&mut builder, gravity_name(), &gravity_bound_value(), "gravity_bound")?;
    append_nonnegative_bound(&mut builder, k_sg_name(), &k_sg_bound(), "k_sg_bound")?;

    // Non-zero constraints on public parameters
    append_nonzero_constraint(&mut builder, q_max_name(), "q_max_nonzero")?;
    append_nonzero_constraint(&mut builder, q_dot_max_name(), "q_dot_max_nonzero")?;
    append_nonzero_constraint(&mut builder, v_max_name(), "v_max_nonzero")?;
    append_nonzero_constraint(&mut builder, gamma_bound_name(), "gamma_bound_nonzero")?;
    append_nonzero_constraint(&mut builder, gravity_name(), "gravity_nonzero")?;
    append_nonzero_constraint(&mut builder, k_sg_name(), "k_sg_nonzero")?;

    // -----------------------------------------------------------------------
    // Scalar private inputs
    // -----------------------------------------------------------------------
    builder.private_input(altitude_name())?;
    builder.private_input(velocity_name())?;
    builder.private_input(gamma_name())?;
    builder.private_input(mass_input_name())?;
    builder.private_input(sref_name())?;
    builder.private_input(cd_name())?;
    builder.private_input(cl_name())?;
    builder.private_input(rn_name())?;
    expected_inputs.push(altitude_name().to_string());
    expected_inputs.push(velocity_name().to_string());
    expected_inputs.push(gamma_name().to_string());
    expected_inputs.push(mass_input_name().to_string());
    expected_inputs.push(sref_name().to_string());
    expected_inputs.push(cd_name().to_string());
    expected_inputs.push(cl_name().to_string());
    expected_inputs.push(rn_name().to_string());

    // Bound-check scalar private inputs
    append_nonnegative_bound(&mut builder, altitude_name(), &altitude_bound(), "initial_altitude_bound")?;
    append_nonnegative_bound(&mut builder, velocity_name(), &velocity_bound_value(), "initial_velocity_bound")?;
    append_signed_bound(&mut builder, gamma_name(), &gamma_bound_default(), "initial_gamma_bound")?;
    append_nonnegative_bound(&mut builder, mass_input_name(), &mass_bound_value(), "mass_bound")?;
    append_nonzero_constraint(&mut builder, mass_input_name(), "mass_nonzero")?;
    append_nonnegative_bound(&mut builder, sref_name(), &area_bound(), "sref_bound")?;
    append_nonzero_constraint(&mut builder, sref_name(), "sref_nonzero")?;
    append_nonnegative_bound(&mut builder, cd_name(), &coeff_bound(), "cd_bound")?;
    append_nonnegative_bound(&mut builder, cl_name(), &coeff_bound(), "cl_bound")?;
    append_nonnegative_bound(&mut builder, rn_name(), &nose_radius_bound(), "rn_bound")?;
    append_nonzero_constraint(&mut builder, rn_name(), "rn_nonzero")?;
    append_nonzero_constraint(&mut builder, velocity_name(), "initial_velocity_nonzero")?;

    // -----------------------------------------------------------------------
    // Per-step private inputs
    // -----------------------------------------------------------------------
    for step in 0..steps {
        let bc = bank_cos_name(step);
        let sg = sin_gamma_input_name(step);
        let cg = cos_gamma_input_name(step);
        let rho = rho_name(step);
        builder.private_input(&bc)?;
        builder.private_input(&sg)?;
        builder.private_input(&cg)?;
        builder.private_input(&rho)?;
        expected_inputs.push(bc.clone());
        expected_inputs.push(sg.clone());
        expected_inputs.push(cg.clone());
        expected_inputs.push(rho.clone());

        // Bound checks
        append_signed_bound(&mut builder, &bc, &bank_cos_bound(), &format!("step_{step}_bank_cos_bound"))?;
        append_signed_bound(&mut builder, &sg, &trig_bound(), &format!("step_{step}_sin_gamma_bound"))?;
        append_signed_bound(&mut builder, &cg, &trig_bound(), &format!("step_{step}_cos_gamma_bound"))?;
        append_nonnegative_bound(&mut builder, &rho, &density_bound(), &format!("step_{step}_rho_bound"))?;
    }

    // -----------------------------------------------------------------------
    // Per-step dynamics constraints
    // -----------------------------------------------------------------------
    for step in 0..steps {
        let h_name = h_state_name(step);
        let v_name_s = v_state_name(step);
        let gamma_name_s = gamma_state_name(step);
        let sg = sin_gamma_input_name(step);
        let cg = cos_gamma_input_name(step);
        let rho_s = rho_name(step);
        let bc = bank_cos_name(step);

        // (a) Trig identity: sin^2 + cos^2 + residual = SCALE^2
        let trig_res = trig_residual_name(step);
        builder.private_signal(&trig_res)?;
        builder.constrain_equal(
            add_expr(vec![
                mul_expr(signal_expr(&sg), signal_expr(&sg)),
                mul_expr(signal_expr(&cg), signal_expr(&cg)),
                signal_expr(&trig_res),
            ]),
            const_expr(&fixed_scale_squared()),
        )?;
        // Range-bound the residual (generous: up to 2*SCALE)
        let trig_residual_max = &fixed_scale() * two();
        builder.constrain_range(&trig_res, bits_for_bound(&trig_residual_max))?;

        // (b) V^2 signal
        let v_sq = v_sq_signal_name(step);
        builder.private_signal(&v_sq)?;
        builder.constrain_equal(
            signal_expr(&v_sq),
            mul_expr(signal_expr(&v_name_s), signal_expr(&v_name_s)),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &v_sq,
            &v_sq_bound(),
            &format!("step_{step}_v_sq_bound"),
        )?;

        // (c) rho * V^2 / SCALE  (intermediate for dynamic pressure)
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&rho_s), signal_expr(&v_sq)),
            const_expr(&fixed_scale()),
            &rho_v_sq_signal_name(step),
            &rho_v_sq_remainder_name(step),
            &rho_v_sq_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_rho_v_sq"),
        )?;

        // (d) Dynamic pressure: q = rho_v_sq / (2 * SCALE)
        append_exact_division_constraints(
            &mut builder,
            signal_expr(&rho_v_sq_signal_name(step)),
            const_expr(&(two() * fixed_scale())),
            &q_signal_name(step),
            &q_remainder_name(step),
            &q_slack_signal_name(step),
            &(two() * fixed_scale()),
            &format!("step_{step}_q"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &q_signal_name(step),
            &dynamic_pressure_bound(),
            &format!("step_{step}_q_bound"),
        )?;

        // (e) Drag force: D = q * S_ref * C_D / SCALE^2
        // Three scaled factors multiply to SCALE^3; divide by SCALE^2 leaves SCALE^1
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&q_signal_name(step)),
                mul_expr(signal_expr(sref_name()), signal_expr(cd_name())),
            ),
            const_expr(&fixed_scale_squared()),
            &drag_signal_name(step),
            &drag_remainder_signal_name(step),
            &drag_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_drag"),
        )?;

        // (f) Lift coefficient product: lift_cos = C_L * cos(sigma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(cl_name()), signal_expr(&bc)),
            const_expr(&fixed_scale()),
            &lift_cos_signal_name(step),
            &lift_cos_remainder_signal_name(step),
            &lift_cos_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_lift_cos"),
        )?;

        // (g) Lift force: L = q * S_ref * lift_cos / SCALE^2
        // Three scaled factors multiply to SCALE^3; divide by SCALE^2 leaves SCALE^1
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&q_signal_name(step)),
                mul_expr(signal_expr(sref_name()), signal_expr(&lift_cos_signal_name(step))),
            ),
            const_expr(&fixed_scale_squared()),
            &lift_signal_name(step),
            &lift_remainder_signal_name(step),
            &lift_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_lift"),
        )?;

        // (h) Drag acceleration: drag_accel = D * SCALE / m
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&drag_signal_name(step)), const_expr(&fixed_scale())),
            signal_expr(mass_input_name()),
            &drag_accel_signal_name(step),
            &drag_accel_remainder_name(step),
            &drag_accel_slack_name(step),
            &mass_bound_value(),
            &format!("step_{step}_drag_accel"),
        )?;
        append_signed_bound(
            &mut builder,
            &drag_accel_signal_name(step),
            &acceleration_bound(),
            &format!("step_{step}_drag_accel_bound"),
        )?;

        // (i) Lift acceleration: lift_accel = L * SCALE / m
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&lift_signal_name(step)), const_expr(&fixed_scale())),
            signal_expr(mass_input_name()),
            &lift_accel_signal_name(step),
            &lift_accel_remainder_name(step),
            &lift_accel_slack_name(step),
            &mass_bound_value(),
            &format!("step_{step}_lift_accel"),
        )?;
        append_signed_bound(
            &mut builder,
            &lift_accel_signal_name(step),
            &acceleration_bound(),
            &format!("step_{step}_lift_accel_bound"),
        )?;

        // (j) g * sin(gamma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(gravity_name()), signal_expr(&sg)),
            const_expr(&fixed_scale()),
            &g_sin_gamma_signal_name(step),
            &g_sin_gamma_remainder_name(step),
            &g_sin_gamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_g_sin_gamma"),
        )?;

        // (k) dv_accel = -drag_accel - g_sin_gamma
        let dv_accel_name = dv_accel_signal_name(step);
        builder.private_signal(&dv_accel_name)?;
        builder.constrain_equal(
            add_expr(vec![
                signal_expr(&dv_accel_name),
                signal_expr(&drag_accel_signal_name(step)),
                signal_expr(&g_sin_gamma_signal_name(step)),
            ]),
            const_expr(&zero()),
        )?;
        append_signed_bound(
            &mut builder,
            &dv_accel_name,
            &acceleration_bound(),
            &format!("step_{step}_dv_accel_bound"),
        )?;

        // (l) dV = dv_accel * dt / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&dv_accel_name), const_expr(&dt_scaled())),
            const_expr(&fixed_scale()),
            &dv_signal_name(step),
            &dv_remainder_name(step),
            &dv_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_dv"),
        )?;
        append_signed_bound(
            &mut builder,
            &dv_signal_name(step),
            &velocity_delta_bound(),
            &format!("step_{step}_dv_bound"),
        )?;

        // (m) V * sin(gamma) intermediate
        let v_sin = v_sin_signal_name(step);
        builder.private_signal(&v_sin)?;
        builder.constrain_equal(
            signal_expr(&v_sin),
            mul_expr(signal_expr(&v_name_s), signal_expr(&sg)),
        )?;

        // (n) dh = V * sin(gamma) * dt / SCALE^2
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&v_sin), const_expr(&dt_scaled())),
            const_expr(&fixed_scale_squared()),
            &dh_signal_name(step),
            &dh_remainder_name(step),
            &dh_slack_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_dh"),
        )?;
        append_signed_bound(
            &mut builder,
            &dh_signal_name(step),
            &altitude_delta_bound(),
            &format!("step_{step}_dh_bound"),
        )?;

        // (o) lift_over_v = lift_accel * SCALE / V
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&lift_accel_signal_name(step)), const_expr(&fixed_scale())),
            signal_expr(&v_name_s),
            &lift_over_v_signal_name(step),
            &lift_over_v_remainder_name(step),
            &lift_over_v_slack_name(step),
            &velocity_bound_value(),
            &format!("step_{step}_lift_over_v"),
        )?;

        // (p) g * cos(gamma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(gravity_name()), signal_expr(&cg)),
            const_expr(&fixed_scale()),
            &g_cos_gamma_signal_name(step),
            &g_cos_gamma_remainder_name(step),
            &g_cos_gamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_g_cos_gamma"),
        )?;

        // (q) gcos_over_v = g_cos_gamma * SCALE / V
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&g_cos_gamma_signal_name(step)), const_expr(&fixed_scale())),
            signal_expr(&v_name_s),
            &gcos_over_v_signal_name(step),
            &gcos_over_v_remainder_name(step),
            &gcos_over_v_slack_name(step),
            &velocity_bound_value(),
            &format!("step_{step}_gcos_over_v"),
        )?;

        // (r) dgamma_accel = lift_over_v - gcos_over_v
        let dgamma_accel = dgamma_accel_signal_name(step);
        builder.private_signal(&dgamma_accel)?;
        builder.constrain_equal(
            signal_expr(&dgamma_accel),
            sub_expr(
                signal_expr(&lift_over_v_signal_name(step)),
                signal_expr(&gcos_over_v_signal_name(step)),
            ),
        )?;

        // (s) dgamma = dgamma_accel * dt / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&dgamma_accel), const_expr(&dt_scaled())),
            const_expr(&fixed_scale()),
            &dgamma_signal_name(step),
            &dgamma_remainder_name(step),
            &dgamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_dgamma"),
        )?;
        append_signed_bound(
            &mut builder,
            &dgamma_signal_name(step),
            &gamma_delta_bound(),
            &format!("step_{step}_dgamma_bound"),
        )?;

        // (t) Next state signals
        let next_h = h_state_name(step + 1);
        let next_v = v_state_name(step + 1);
        let next_gamma = gamma_state_name(step + 1);
        builder.private_signal(&next_h)?;
        builder.private_signal(&next_v)?;
        builder.private_signal(&next_gamma)?;

        builder.constrain_equal(
            signal_expr(&next_h),
            add_expr(vec![
                signal_expr(&h_name),
                signal_expr(&dh_signal_name(step)),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_v),
            add_expr(vec![
                signal_expr(&v_name_s),
                signal_expr(&dv_signal_name(step)),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_gamma),
            add_expr(vec![
                signal_expr(&gamma_name_s),
                signal_expr(&dgamma_signal_name(step)),
            ]),
        )?;

        // Bound next state
        append_nonnegative_bound(
            &mut builder,
            &next_h,
            &altitude_bound(),
            &format!("state_{}_altitude_bound", step + 1),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &next_v,
            &velocity_bound_value(),
            &format!("state_{}_velocity_bound", step + 1),
        )?;
        append_nonzero_constraint(
            &mut builder,
            &next_v,
            &format!("state_{}_velocity_nonzero", step + 1),
        )?;
        append_signed_bound(
            &mut builder,
            &next_gamma,
            &gamma_bound_default(),
            &format!("state_{}_gamma_bound", step + 1),
        )?;

        // (u) Heating rate (prover hint, bound-checked)
        let q_dot = q_dot_signal_name(step);
        builder.private_signal(&q_dot)?;
        append_nonnegative_bound(
            &mut builder,
            &q_dot,
            &q_dot_max_bound(),
            &format!("step_{step}_q_dot_bound"),
        )?;

        // (v) Safety envelope checks
        // q_i <= q_max:  q_max = q_i + q_safety_slack, slack >= 0
        let q_slack = q_safety_slack_name(step);
        builder.private_signal(&q_slack)?;
        builder.constrain_equal(
            signal_expr(q_max_name()),
            add_expr(vec![
                signal_expr(&q_signal_name(step)),
                signal_expr(&q_slack),
            ]),
        )?;
        builder.constrain_range(&q_slack, bits_for_bound(&q_max_bound()))?;

        // q_dot_i <= q_dot_max
        let qd_slack = q_dot_safety_slack_name(step);
        builder.private_signal(&qd_slack)?;
        builder.constrain_equal(
            signal_expr(q_dot_max_name()),
            add_expr(vec![
                signal_expr(&q_dot),
                signal_expr(&qd_slack),
            ]),
        )?;
        builder.constrain_range(&qd_slack, bits_for_bound(&q_dot_max_bound()))?;

        // h_i >= h_min: h_i = h_min + h_safety_slack, slack >= 0
        let h_slack = h_safety_slack_signal_name(step);
        builder.private_signal(&h_slack)?;
        builder.constrain_equal(
            signal_expr(&h_name),
            add_expr(vec![
                signal_expr(h_min_name()),
                signal_expr(&h_slack),
            ]),
        )?;
        builder.constrain_range(&h_slack, bits_for_bound(&altitude_bound()))?;

        // V_i <= v_max: v_max = V_i + v_safety_slack, slack >= 0
        let v_slack = v_safety_slack_signal_name(step);
        builder.private_signal(&v_slack)?;
        builder.constrain_equal(
            signal_expr(v_max_name()),
            add_expr(vec![
                signal_expr(&v_name_s),
                signal_expr(&v_slack),
            ]),
        )?;
        builder.constrain_range(&v_slack, bits_for_bound(&velocity_bound_value()))?;

        // gamma within bounds (already constrained via signed_bound on next_gamma)
    }

    // -----------------------------------------------------------------------
    // Running max for peak dynamic pressure
    // -----------------------------------------------------------------------
    let run_max_q_0 = running_max_q_name(0);
    builder.private_signal(&run_max_q_0)?;
    builder.constrain_equal(signal_expr(&run_max_q_0), signal_expr(&q_signal_name(0)))?;
    append_nonnegative_bound(
        &mut builder,
        &run_max_q_0,
        &dynamic_pressure_bound(),
        "state_0_running_max_q_bound",
    )?;

    for step in 1..steps {
        let current = running_max_q_name(step);
        let previous = running_max_q_name(step - 1);
        let prev_slack = running_max_q_prev_slack_name(step);
        let curr_slack = running_max_q_curr_slack_name(step);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_bound(
            &mut builder,
            &current,
            &dynamic_pressure_bound(),
            &format!("state_{step}_running_max_q_bound"),
        )?;
        // current = previous + prev_slack  (current >= previous)
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&previous), signal_expr(&prev_slack)]),
        )?;
        // current = q_i + curr_slack  (current >= q_i)
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&q_signal_name(step)), signal_expr(&curr_slack)]),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&dynamic_pressure_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&dynamic_pressure_bound()))?;
        // Exactly one of prev_slack or curr_slack is zero (either we kept previous or took new)
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(peak_q_output_name())?;
    let last_max_q = running_max_q_name(if steps > 0 { steps - 1 } else { 0 });
    builder.constrain_equal(
        signal_expr(peak_q_output_name()),
        signal_expr(&last_max_q),
    )?;
    append_nonnegative_bound(
        &mut builder,
        peak_q_output_name(),
        &dynamic_pressure_bound(),
        "peak_q_public_bound",
    )?;

    // -----------------------------------------------------------------------
    // Running max for peak heating rate
    // -----------------------------------------------------------------------
    let run_max_qd_0 = running_max_q_dot_name(0);
    builder.private_signal(&run_max_qd_0)?;
    builder.constrain_equal(signal_expr(&run_max_qd_0), signal_expr(&q_dot_signal_name(0)))?;
    append_nonnegative_bound(
        &mut builder,
        &run_max_qd_0,
        &q_dot_max_bound(),
        "state_0_running_max_q_dot_bound",
    )?;

    for step in 1..steps {
        let current = running_max_q_dot_name(step);
        let previous = running_max_q_dot_name(step - 1);
        let prev_slack = running_max_q_dot_prev_slack_name(step);
        let curr_slack = running_max_q_dot_curr_slack_name(step);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_bound(
            &mut builder,
            &current,
            &q_dot_max_bound(),
            &format!("state_{step}_running_max_q_dot_bound"),
        )?;
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&previous), signal_expr(&prev_slack)]),
        )?;
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&q_dot_signal_name(step)), signal_expr(&curr_slack)]),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&q_dot_max_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&q_dot_max_bound()))?;
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(peak_q_dot_output_name())?;
    let last_max_qd = running_max_q_dot_name(if steps > 0 { steps - 1 } else { 0 });
    builder.constrain_equal(
        signal_expr(peak_q_dot_output_name()),
        signal_expr(&last_max_qd),
    )?;
    append_nonnegative_bound(
        &mut builder,
        peak_q_dot_output_name(),
        &q_dot_max_bound(),
        "peak_q_dot_public_bound",
    )?;

    // -----------------------------------------------------------------------
    // Trajectory Poseidon commitment
    // -----------------------------------------------------------------------
    builder.public_output(trajectory_commitment_output_name())?;
    let mut previous_digest = const_expr(&trajectory_seed_tag());
    for step in 0..=steps {
        let state_digest = append_poseidon_hash(
            &mut builder,
            &format!("trajectory_step_{step}_state"),
            [
                signal_expr(&h_state_name(step)),
                signal_expr(&v_state_name(step)),
                signal_expr(&gamma_state_name(step)),
                const_expr(&BigInt::from(step as u64)),
            ],
        )?;
        previous_digest = {
            let chain_digest = append_poseidon_hash(
                &mut builder,
                &format!("trajectory_step_{step}_chain"),
                [
                    signal_expr(&state_digest),
                    previous_digest,
                    const_expr(&trajectory_step_tag(step)),
                    const_expr(&zero()),
                ],
            )?;
            signal_expr(&chain_digest)
        };
    }
    builder.constrain_equal(
        signal_expr(trajectory_commitment_output_name()),
        previous_digest,
    )?;

    // -----------------------------------------------------------------------
    // Terminal state commitment
    // -----------------------------------------------------------------------
    builder.public_output(terminal_state_commitment_output_name())?;
    let terminal_digest = append_poseidon_hash(
        &mut builder,
        "terminal_state_commitment",
        [
            signal_expr(&h_state_name(steps)),
            signal_expr(&v_state_name(steps)),
            signal_expr(&gamma_state_name(steps)),
            const_expr(&terminal_state_tag()),
        ],
    )?;
    builder.constrain_equal(
        signal_expr(terminal_state_commitment_output_name()),
        signal_expr(&terminal_digest),
    )?;

    // -----------------------------------------------------------------------
    // Constraint satisfaction (fail-closed certificate)
    // -----------------------------------------------------------------------
    builder.public_output(constraint_satisfaction_output_name())?;
    builder.constrain_boolean(constraint_satisfaction_output_name())?;
    builder.constrain_equal(
        signal_expr(constraint_satisfaction_output_name()),
        const_expr(&one()),
    )?;

    // -----------------------------------------------------------------------
    // Build
    // -----------------------------------------------------------------------
    let sample_inputs = reentry_sample_inputs_for_steps(steps);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(mass_input_name().to_string(), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: if steps == PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS {
            PRIVATE_REENTRY_THERMAL_DESCRIPTION
        } else {
            PRIVATE_REENTRY_THERMAL_TEST_HELPER_DESCRIPTION
        },
    })
}

// ---------------------------------------------------------------------------
// Public showcase entry points (with stacker)
// ---------------------------------------------------------------------------

pub fn build_private_reentry_thermal_program(steps: usize) -> ZkfResult<zkf_core::Program> {
    private_reentry_thermal_showcase_with_steps(steps).map(|template| template.program)
}

pub fn private_reentry_thermal_showcase() -> ZkfResult<TemplateProgram> {
    private_reentry_thermal_showcase_with_steps(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_reentry_thermal_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_reentry_thermal_showcase_inner(steps)
    })
}

pub fn private_reentry_thermal_sample_inputs() -> WitnessInputs {
    reentry_sample_inputs_for_steps(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

// ---------------------------------------------------------------------------
// Witness generation
// ---------------------------------------------------------------------------

fn private_reentry_thermal_witness_inner(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private reentry thermal witness generation requires at least one integration step"
                .to_string(),
        ));
    }

    let parameters = load_public_parameters(inputs)?;
    let mut values = BTreeMap::<String, FieldElement>::new();
    write_public_parameter_support(&mut values, &parameters)?;

    // Read scalar private inputs
    let h0 = read_input(inputs, altitude_name())?;
    let v0 = read_input(inputs, velocity_name())?;
    let gamma0 = read_input(inputs, gamma_name())?;
    let mass = read_input(inputs, mass_input_name())?;
    let s_ref = read_input(inputs, sref_name())?;
    let c_d = read_input(inputs, cd_name())?;
    let c_l = read_input(inputs, cl_name())?;
    let r_n = read_input(inputs, rn_name())?;

    // Validate scalar private inputs
    ensure_nonnegative_le(altitude_name(), &h0, &altitude_bound())?;
    ensure_nonnegative_le(velocity_name(), &v0, &velocity_bound_value())?;
    ensure_positive_le(velocity_name(), &v0, &velocity_bound_value())?;
    ensure_abs_le(gamma_name(), &gamma0, &gamma_bound_default())?;
    ensure_positive_le(mass_input_name(), &mass, &mass_bound_value())?;
    ensure_positive_le(sref_name(), &s_ref, &area_bound())?;
    ensure_nonnegative_le(cd_name(), &c_d, &coeff_bound())?;
    ensure_nonnegative_le(cl_name(), &c_l, &coeff_bound())?;
    ensure_positive_le(rn_name(), &r_n, &nose_radius_bound())?;

    // Write scalar private input support
    write_nonnegative_bound_support(&mut values, altitude_name(), &h0, &altitude_bound(), "initial_altitude_bound")?;
    write_nonnegative_bound_support(&mut values, velocity_name(), &v0, &velocity_bound_value(), "initial_velocity_bound")?;
    write_signed_bound_support(&mut values, &gamma0, &gamma_bound_default(), "initial_gamma_bound")?;
    write_value(&mut values, gamma_name(), gamma0.clone());
    write_nonnegative_bound_support(&mut values, mass_input_name(), &mass, &mass_bound_value(), "mass_bound")?;
    write_nonzero_inverse_support(&mut values, &mass, "mass_nonzero")?;
    write_nonnegative_bound_support(&mut values, sref_name(), &s_ref, &area_bound(), "sref_bound")?;
    write_nonzero_inverse_support(&mut values, &s_ref, "sref_nonzero")?;
    write_nonnegative_bound_support(&mut values, cd_name(), &c_d, &coeff_bound(), "cd_bound")?;
    write_nonnegative_bound_support(&mut values, cl_name(), &c_l, &coeff_bound(), "cl_bound")?;
    write_nonnegative_bound_support(&mut values, rn_name(), &r_n, &nose_radius_bound(), "rn_bound")?;
    write_nonzero_inverse_support(&mut values, &r_n, "rn_nonzero")?;
    write_nonzero_inverse_support(&mut values, &v0, "initial_velocity_nonzero")?;

    // Read per-step inputs and validate
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gammas = Vec::with_capacity(steps);
    let mut cos_gammas = Vec::with_capacity(steps);
    let mut densities = Vec::with_capacity(steps);

    for step in 0..steps {
        let bc = read_input(inputs, &bank_cos_name(step))?;
        let sg = read_input(inputs, &sin_gamma_input_name(step))?;
        let cg = read_input(inputs, &cos_gamma_input_name(step))?;
        let rho = read_input(inputs, &rho_name(step))?;

        ensure_abs_le(&bank_cos_name(step), &bc, &bank_cos_bound())?;
        ensure_abs_le(&sin_gamma_input_name(step), &sg, &trig_bound())?;
        ensure_abs_le(&cos_gamma_input_name(step), &cg, &trig_bound())?;
        ensure_nonnegative_le(&rho_name(step), &rho, &density_bound())?;

        write_value(&mut values, bank_cos_name(step), bc.clone());
        write_signed_bound_support(&mut values, &bc, &bank_cos_bound(), &format!("step_{step}_bank_cos_bound"))?;
        write_value(&mut values, sin_gamma_input_name(step), sg.clone());
        write_signed_bound_support(&mut values, &sg, &trig_bound(), &format!("step_{step}_sin_gamma_bound"))?;
        write_value(&mut values, cos_gamma_input_name(step), cg.clone());
        write_signed_bound_support(&mut values, &cg, &trig_bound(), &format!("step_{step}_cos_gamma_bound"))?;
        write_nonnegative_bound_support(&mut values, rho_name(step), &rho, &density_bound(), &format!("step_{step}_rho_bound"))?;

        bank_cosines.push(bc);
        sin_gammas.push(sg);
        cos_gammas.push(cg);
        densities.push(rho);
    }

    // Forward-propagate state and write witness values
    let mut altitudes = Vec::with_capacity(steps + 1);
    let mut velocities = Vec::with_capacity(steps + 1);
    let mut gammas = Vec::with_capacity(steps + 1);
    let mut q_values = Vec::with_capacity(steps);
    let mut q_dot_values = Vec::with_capacity(steps);

    let mut current_h = h0.clone();
    let mut current_v = v0.clone();
    let mut current_gamma = gamma0.clone();

    altitudes.push(current_h.clone());
    velocities.push(current_v.clone());
    gammas.push(current_gamma.clone());

    for step in 0..steps {
        let step_result = compute_step_dynamics(
            &current_h,
            &current_v,
            &current_gamma,
            &sin_gammas[step],
            &cos_gammas[step],
            &densities[step],
            &bank_cosines[step],
            &mass,
            &s_ref,
            &c_d,
            &c_l,
            &r_n,
            &parameters.k_sg,
            &parameters,
        )?;

        // Write trig identity support
        write_value(&mut values, trig_residual_name(step), step_result.trig_identity_residual.clone());

        // Write V^2
        write_nonnegative_bound_support(
            &mut values,
            v_sq_signal_name(step),
            &step_result.v_sq,
            &v_sq_bound(),
            &format!("step_{step}_v_sq_bound"),
        )?;

        // Write rho*V^2/SCALE division support
        write_value(&mut values, rho_v_sq_signal_name(step), step_result.rho_v_sq.clone());
        write_value(&mut values, rho_v_sq_remainder_name(step), step_result.rho_v_sq_remainder.clone());
        write_value(&mut values, rho_v_sq_slack_name(step), step_result.rho_v_sq_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_rho_v_sq"), &step_result.rho_v_sq_slack);

        // Write dynamic pressure division support
        write_value(&mut values, q_signal_name(step), step_result.q_i.clone());
        write_value(&mut values, q_remainder_name(step), step_result.q_i_remainder.clone());
        write_value(&mut values, q_slack_signal_name(step), step_result.q_i_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_q"), &step_result.q_i_slack);
        write_nonnegative_bound_support(
            &mut values,
            q_signal_name(step),
            &step_result.q_i,
            &dynamic_pressure_bound(),
            &format!("step_{step}_q_bound"),
        )?;

        // Write drag force division support
        write_value(&mut values, drag_signal_name(step), step_result.drag_force.clone());
        write_value(&mut values, drag_remainder_signal_name(step), step_result.drag_remainder.clone());
        write_value(&mut values, drag_slack_signal_name(step), step_result.drag_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_drag"), &step_result.drag_slack);

        // Write lift_cos division support
        write_value(&mut values, lift_cos_signal_name(step), step_result.lift_cos.clone());
        write_value(&mut values, lift_cos_remainder_signal_name(step), step_result.lift_cos_remainder.clone());
        write_value(&mut values, lift_cos_slack_signal_name(step), step_result.lift_cos_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_lift_cos"), &step_result.lift_cos_slack);

        // Write lift force division support
        write_value(&mut values, lift_signal_name(step), step_result.lift_force.clone());
        write_value(&mut values, lift_remainder_signal_name(step), step_result.lift_remainder.clone());
        write_value(&mut values, lift_slack_signal_name(step), step_result.lift_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_lift"), &step_result.lift_slack);

        // Write drag accel division support
        write_value(&mut values, drag_accel_signal_name(step), step_result.drag_accel.clone());
        write_value(&mut values, drag_accel_remainder_name(step), step_result.drag_accel_remainder.clone());
        write_value(&mut values, drag_accel_slack_name(step), step_result.drag_accel_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_drag_accel"), &step_result.drag_accel_slack);
        write_signed_bound_support(&mut values, &step_result.drag_accel, &acceleration_bound(), &format!("step_{step}_drag_accel_bound"))?;

        // Write lift accel division support
        write_value(&mut values, lift_accel_signal_name(step), step_result.lift_accel.clone());
        write_value(&mut values, lift_accel_remainder_name(step), step_result.lift_accel_remainder.clone());
        write_value(&mut values, lift_accel_slack_name(step), step_result.lift_accel_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_lift_accel"), &step_result.lift_accel_slack);
        write_signed_bound_support(&mut values, &step_result.lift_accel, &acceleration_bound(), &format!("step_{step}_lift_accel_bound"))?;

        // Write g*sin(gamma)/SCALE division support
        write_value(&mut values, g_sin_gamma_signal_name(step), step_result.g_sin_gamma.clone());
        write_value(&mut values, g_sin_gamma_remainder_name(step), step_result.g_sin_gamma_remainder.clone());
        write_value(&mut values, g_sin_gamma_slack_name(step), step_result.g_sin_gamma_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_g_sin_gamma"), &step_result.g_sin_gamma_slack);

        // Write dv_accel
        write_value(&mut values, dv_accel_signal_name(step), step_result.dv_accel.clone());
        write_signed_bound_support(&mut values, &step_result.dv_accel, &acceleration_bound(), &format!("step_{step}_dv_accel_bound"))?;

        // Write dv division support
        write_value(&mut values, dv_signal_name(step), step_result.dv.clone());
        write_value(&mut values, dv_remainder_name(step), step_result.dv_remainder.clone());
        write_value(&mut values, dv_slack_name(step), step_result.dv_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_dv"), &step_result.dv_slack);
        write_signed_bound_support(&mut values, &step_result.dv, &velocity_delta_bound(), &format!("step_{step}_dv_bound"))?;

        // Write v_sin intermediate
        write_value(&mut values, v_sin_signal_name(step), step_result.v_sin.clone());

        // Write dh division support
        write_value(&mut values, dh_signal_name(step), step_result.dh.clone());
        write_value(&mut values, dh_remainder_name(step), step_result.dh_remainder.clone());
        write_value(&mut values, dh_slack_name(step), step_result.dh_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_dh"), &step_result.dh_slack);
        write_signed_bound_support(&mut values, &step_result.dh, &altitude_delta_bound(), &format!("step_{step}_dh_bound"))?;

        // Write lift_over_v division support
        write_value(&mut values, lift_over_v_signal_name(step), step_result.lift_over_v.clone());
        write_value(&mut values, lift_over_v_remainder_name(step), step_result.lift_over_v_remainder.clone());
        write_value(&mut values, lift_over_v_slack_name(step), step_result.lift_over_v_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_lift_over_v"), &step_result.lift_over_v_slack);

        // Write g*cos(gamma)/SCALE division support
        write_value(&mut values, g_cos_gamma_signal_name(step), step_result.g_cos_gamma.clone());
        write_value(&mut values, g_cos_gamma_remainder_name(step), step_result.g_cos_gamma_remainder.clone());
        write_value(&mut values, g_cos_gamma_slack_name(step), step_result.g_cos_gamma_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_g_cos_gamma"), &step_result.g_cos_gamma_slack);

        // Write gcos_over_v division support
        write_value(&mut values, gcos_over_v_signal_name(step), step_result.gcos_over_v.clone());
        write_value(&mut values, gcos_over_v_remainder_name(step), step_result.gcos_over_v_remainder.clone());
        write_value(&mut values, gcos_over_v_slack_name(step), step_result.gcos_over_v_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_gcos_over_v"), &step_result.gcos_over_v_slack);

        // Write dgamma_accel
        write_value(&mut values, dgamma_accel_signal_name(step), step_result.dgamma_accel.clone());

        // Write dgamma division support
        write_value(&mut values, dgamma_signal_name(step), step_result.dgamma.clone());
        write_value(&mut values, dgamma_remainder_name(step), step_result.dgamma_remainder.clone());
        write_value(&mut values, dgamma_slack_name(step), step_result.dgamma_slack.clone());
        write_exact_division_slack_anchor(&mut values, &format!("step_{step}_dgamma"), &step_result.dgamma_slack);
        write_signed_bound_support(&mut values, &step_result.dgamma, &gamma_delta_bound(), &format!("step_{step}_dgamma_bound"))?;

        // Write next state
        write_nonnegative_bound_support(
            &mut values,
            h_state_name(step + 1),
            &step_result.next_altitude,
            &altitude_bound(),
            &format!("state_{}_altitude_bound", step + 1),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            v_state_name(step + 1),
            &step_result.next_velocity,
            &velocity_bound_value(),
            &format!("state_{}_velocity_bound", step + 1),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &step_result.next_velocity,
            &format!("state_{}_velocity_nonzero", step + 1),
        )?;
        write_value(&mut values, gamma_state_name(step + 1), step_result.next_gamma.clone());
        write_signed_bound_support(
            &mut values,
            &step_result.next_gamma,
            &gamma_bound_default(),
            &format!("state_{}_gamma_bound", step + 1),
        )?;

        // Write heating rate hint
        write_nonnegative_bound_support(
            &mut values,
            q_dot_signal_name(step),
            &step_result.q_dot_i,
            &q_dot_max_bound(),
            &format!("step_{step}_q_dot_bound"),
        )?;

        // Write safety envelope slacks
        write_value(&mut values, q_safety_slack_name(step), step_result.q_safety_slack.clone());
        write_value(&mut values, q_dot_safety_slack_name(step), step_result.q_dot_safety_slack.clone());
        write_value(&mut values, h_safety_slack_signal_name(step), step_result.h_safety_slack.clone());
        write_value(&mut values, v_safety_slack_signal_name(step), step_result.v_safety_slack.clone());

        q_values.push(step_result.q_i.clone());
        q_dot_values.push(step_result.q_dot_i.clone());

        current_h = step_result.next_altitude.clone();
        current_v = step_result.next_velocity.clone();
        current_gamma = step_result.next_gamma.clone();

        altitudes.push(current_h.clone());
        velocities.push(current_v.clone());
        gammas.push(current_gamma.clone());
    }

    // Write running max q support
    let mut max_q = q_values[0].clone();
    write_nonnegative_bound_support(
        &mut values,
        running_max_q_name(0),
        &max_q,
        &dynamic_pressure_bound(),
        "state_0_running_max_q_bound",
    )?;

    for step in 1..steps {
        let next_max = if q_values[step] > max_q {
            q_values[step].clone()
        } else {
            max_q.clone()
        };
        let prev_slack = &next_max - &max_q;
        let curr_slack = &next_max - &q_values[step];
        write_nonnegative_bound_support(
            &mut values,
            running_max_q_name(step),
            &next_max,
            &dynamic_pressure_bound(),
            &format!("state_{step}_running_max_q_bound"),
        )?;
        write_value(&mut values, running_max_q_prev_slack_name(step), prev_slack);
        write_value(&mut values, running_max_q_curr_slack_name(step), curr_slack);
        max_q = next_max;
    }

    // Write running max q_dot support
    let mut max_q_dot = q_dot_values[0].clone();
    write_nonnegative_bound_support(
        &mut values,
        running_max_q_dot_name(0),
        &max_q_dot,
        &q_dot_max_bound(),
        "state_0_running_max_q_dot_bound",
    )?;

    for step in 1..steps {
        let next_max = if q_dot_values[step] > max_q_dot {
            q_dot_values[step].clone()
        } else {
            max_q_dot.clone()
        };
        let prev_slack = &next_max - &max_q_dot;
        let curr_slack = &next_max - &q_dot_values[step];
        write_nonnegative_bound_support(
            &mut values,
            running_max_q_dot_name(step),
            &next_max,
            &q_dot_max_bound(),
            &format!("state_{step}_running_max_q_dot_bound"),
        )?;
        write_value(&mut values, running_max_q_dot_prev_slack_name(step), prev_slack);
        write_value(&mut values, running_max_q_dot_curr_slack_name(step), curr_slack);
        max_q_dot = next_max;
    }

    // Write peak q and peak q_dot public outputs
    write_nonnegative_bound_support(
        &mut values,
        peak_q_output_name(),
        &max_q,
        &dynamic_pressure_bound(),
        "peak_q_public_bound",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        peak_q_dot_output_name(),
        &max_q_dot,
        &q_dot_max_bound(),
        "peak_q_dot_public_bound",
    )?;

    // Trajectory Poseidon commitment
    let mut previous_digest = field_ref(&trajectory_seed_tag());
    for step in 0..=steps {
        let state_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_state"),
            poseidon_permutation4_bn254(&[
                field_ref(&altitudes[step]),
                field_ref(&velocities[step]),
                field_ref(&gammas[step]),
                field(BigInt::from(step as u64)),
            ])
            .map_err(ZkfError::Backend)?,
        );
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_chain"),
            poseidon_permutation4_bn254(&[
                state_digest,
                previous_digest,
                field(trajectory_step_tag(step)),
                FieldElement::ZERO,
            ])
            .map_err(ZkfError::Backend)?,
        );
    }
    values.insert(
        trajectory_commitment_output_name().to_string(),
        previous_digest,
    );

    // Terminal state commitment
    let terminal_digest = write_hash_lanes(
        &mut values,
        "terminal_state_commitment",
        poseidon_permutation4_bn254(&[
            field_ref(&altitudes[steps]),
            field_ref(&velocities[steps]),
            field_ref(&gammas[steps]),
            field(terminal_state_tag()),
        ])
        .map_err(ZkfError::Backend)?,
    );
    values.insert(
        terminal_state_commitment_output_name().to_string(),
        terminal_digest,
    );

    // Constraint satisfaction
    values.insert(
        constraint_satisfaction_output_name().to_string(),
        FieldElement::ONE,
    );

    Ok(Witness { values })
}

pub fn private_reentry_thermal_witness(inputs: &WitnessInputs) -> ZkfResult<Witness> {
    private_reentry_thermal_witness_with_steps(inputs, PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_reentry_thermal_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_reentry_thermal_witness_inner(inputs, steps)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::thread;
    use zkf_backends::blackbox_gadgets::enrich_witness_for_proving;
    use zkf_core::{BackendKind, CompiledProgram, Program, check_constraints};

    const REENTRY_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_reentry_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(REENTRY_TEST_STACK_SIZE)
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
    fn reentry_template_has_expected_surface() {
        let steps = 2;
        let template = private_reentry_thermal_showcase_with_steps(steps).expect("template");
        assert_eq!(
            template.expected_inputs.len(),
            PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS + private_input_count_for_steps(steps)
        );
        assert_eq!(
            template.public_outputs.len(),
            PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS
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
    fn reentry_small_step_witness_satisfies_constraints() {
        run_reentry_test_on_large_stack("reentry_small_step_witness_satisfies_constraints", || {
            for steps in 1..=2 {
                let template =
                    private_reentry_thermal_showcase_with_steps(steps).expect("template");
                let compiled = lowered_compiled_program_for_test(&template.program);
                let witness =
                    private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
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
                    panic!(
                        "constraints failed for steps={steps}: {error:?}\nfailing_constraint={failing_constraint}"
                    );
                }
            }
        });
    }

    #[test]
    fn reentry_zero_mass_fails() {
        let mut inputs = reentry_sample_inputs_for_steps(2);
        inputs.insert(mass_input_name().to_string(), field(zero()));
        private_reentry_thermal_witness_with_steps(&inputs, 2)
            .expect_err("zero mass must fail");
    }

    #[test]
    fn reentry_request_step_mismatch_fails() {
        let request = PrivateReentryThermalRequestV1 {
            private: ReentryPrivateInputsV1 {
                initial_altitude: "120000".to_string(),
                initial_velocity: "7500".to_string(),
                initial_flight_path_angle: "-0.02".to_string(),
                vehicle_mass: "10000".to_string(),
                reference_area: "10".to_string(),
                drag_coefficient: "1.5".to_string(),
                lift_coefficient: "0.5".to_string(),
                nose_radius: "1".to_string(),
                bank_angle_cosines: vec!["0.5".to_string()],
                sin_gamma: vec!["-0.02".to_string()],
                cos_gamma: vec!["0.9998".to_string()],
                density_profile: vec!["0.00001".to_string()],
            },
            public: ReentryPublicInputsV1 {
                q_max: "50000".to_string(),
                q_dot_max: "5000000".to_string(),
                h_min: "30000".to_string(),
                v_max: "7800".to_string(),
                gamma_bound: "0.35".to_string(),
                g_0: "9.80665".to_string(),
                k_sg: "0.0001".to_string(),
                step_count: 2,
            },
        };
        WitnessInputs::try_from(request).expect_err("step-count mismatch must fail");
    }

    #[test]
    fn reentry_public_commitments_present_in_witness() {
        run_reentry_test_on_large_stack(
            "reentry_public_commitments_present_in_witness",
            || {
                let steps = 2;
                let template =
                    private_reentry_thermal_showcase_with_steps(steps).expect("template");
                let witness =
                    private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
                        .expect("witness");
                assert!(
                    witness
                        .values
                        .contains_key(trajectory_commitment_output_name())
                );
                assert!(
                    witness
                        .values
                        .contains_key(terminal_state_commitment_output_name())
                );
                assert_eq!(
                    witness.values[constraint_satisfaction_output_name()],
                    FieldElement::ONE
                );
                assert!(
                    witness
                        .values
                        .contains_key(peak_q_output_name())
                );
                assert!(
                    witness
                        .values
                        .contains_key(peak_q_dot_output_name())
                );
            },
        );
    }
}
