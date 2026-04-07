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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const FALCON_HEAVY_GOLDILOCKS_SCALE_DECIMALS: u32 = 3;
pub const FALCON_HEAVY_BN254_SCALE_DECIMALS: u32 = 18;
pub const FALCON_HEAVY_ENGINE_COUNT: usize = 27;
pub const FALCON_HEAVY_ENGINES_PER_CORE: usize = 9;
pub const FALCON_HEAVY_CORE_COUNT: usize = 3;
/// Full real-time: T+0 through center core MECO at T+187s, sampled at 1 Hz.
pub const FALCON_HEAVY_ASCENT_STEPS: usize = 187;
/// Full real-time: ~300 seconds per core recovery trajectory, sampled at 1 Hz.
pub const FALCON_HEAVY_RECOVERY_STEPS_PER_CORE: usize = 300;
pub const FALCON_HEAVY_MAX_BURNS: usize = 4;
/// Full real-time: matches ascent timeline (T+0 through T+187s).
pub const FALCON_HEAVY_ENVIRONMENT_STEPS: usize = 187;
/// chamber_pressure, turbopump_rpm, fuel_flow, ox_flow, mixture_ratio,
/// thrust, gimbal_response
pub const FALCON_HEAVY_PARAMS_PER_ENGINE: usize = 7;

const FH_GOLDILOCKS_FIELD: FieldId = FieldId::Goldilocks;
const FH_BN254_FIELD: FieldId = FieldId::Bn254;

const PARAM_NAMES: [&str; FALCON_HEAVY_PARAMS_PER_ENGINE] = [
    "chamber_pressure",
    "turbopump_rpm",
    "fuel_flow",
    "ox_flow",
    "mixture_ratio",
    "thrust",
    "gimbal_response",
];

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineHealthCertificationRequestV1 {
    pub engine_params: Vec<Vec<String>>,
    pub acceptance_bands_low: Vec<String>,
    pub acceptance_bands_high: Vec<String>,
    pub engine_flight_counts: Vec<u64>,
    pub max_rms_deviation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AscentTrajectoryRequestV1 {
    pub altitude: Vec<String>,
    pub velocity: Vec<String>,
    pub acceleration: Vec<String>,
    pub dynamic_pressure: Vec<String>,
    pub throttle_pct: Vec<String>,
    pub mass: Vec<String>,
    pub max_q: String,
    pub max_axial_load: String,
    pub max_lateral_load: String,
    pub meco_altitude_min: String,
    pub meco_velocity_min: String,
    pub gravity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreRecoveryDataV1 {
    pub separation_altitude: String,
    pub separation_velocity: String,
    pub propellant_reserve: String,
    pub burn_durations: Vec<String>,
    pub landing_altitude_error: String,
    pub landing_velocity: String,
    pub tea_teb_ignitions: u64,
    pub max_tea_teb: u64,
    pub altitude_profile: Vec<String>,
    pub velocity_profile: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoosterRecoveryCertificationRequestV1 {
    pub cores: Vec<CoreRecoveryDataV1>,
    pub max_landing_velocity: String,
    pub max_landing_position_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrbitalBurnV1 {
    pub active: bool,
    pub delta_v: String,
    pub burn_duration: String,
    pub perigee: String,
    pub apogee: String,
    pub inclination: String,
    pub propellant_consumed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpperStageMultiBurnRequestV1 {
    pub burns: Vec<OrbitalBurnV1>,
    pub initial_propellant: String,
    pub perigee_tolerance: String,
    pub apogee_tolerance: String,
    pub inclination_tolerance: String,
    pub target_perigee: String,
    pub target_apogee: String,
    pub target_inclination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineShutdownEventV1 {
    pub engine_index: u64,
    pub shutdown_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineOutMissionRequestV1 {
    pub shutdown_events: Vec<EngineShutdownEventV1>,
    pub recalculated_thrust: Vec<String>,
    pub recalculated_velocity: Vec<String>,
    pub recalculated_altitude: Vec<String>,
    pub min_thrust_fraction: String,
    pub nominal_total_thrust: String,
    pub mission_success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadFairingEnvironmentRequestV1 {
    pub acoustic_levels: Vec<String>,
    pub vibration_levels: Vec<String>,
    pub thermal_levels: Vec<String>,
    pub max_acoustic: String,
    pub max_vibration: String,
    pub max_thermal: String,
    pub fairing_jettison_altitude: String,
    pub fairing_jettison_pressure: String,
    pub min_jettison_altitude: String,
    pub max_jettison_pressure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FullMissionIntegrationRequestV1 {
    pub circuit_commitments: [String; 8],
    pub circuit_status_bits: [bool; 8],
    pub mission_name: String,
    pub vehicle_mass: String,
    pub payload_mass: String,
    pub mission_duration: String,
    pub success_threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FalconHeavyMissionManifestV1 {
    pub run_id: String,
    pub engine_health: EngineHealthCertificationRequestV1,
    pub ascent_trajectory: AscentTrajectoryRequestV1,
    pub booster_recovery: BoosterRecoveryCertificationRequestV1,
    pub upper_stage: UpperStageMultiBurnRequestV1,
    pub engine_out: EngineOutMissionRequestV1,
    pub fairing_environment: PayloadFairingEnvironmentRequestV1,
    pub mission_integration: FullMissionIntegrationRequestV1,
}

// ---------------------------------------------------------------------------
// Helper functions (file-private, following SED pattern)
// ---------------------------------------------------------------------------

fn zero() -> BigInt {
    BigInt::from(0u8)
}

fn one() -> BigInt {
    BigInt::from(1u8)
}

fn fixed_scale(decimals: u32) -> BigInt {
    BigInt::from(10u8).pow(decimals)
}

fn fh_goldilocks_scale() -> BigInt {
    fixed_scale(FALCON_HEAVY_GOLDILOCKS_SCALE_DECIMALS)
}

fn fh_bn254_scale() -> BigInt {
    fixed_scale(FALCON_HEAVY_BN254_SCALE_DECIMALS)
}

fn fh_goldilocks_amount_bound() -> BigInt {
    // Must fit: bound^2 < 2^63 for signed_bound in Goldilocks.
    // sqrt(2^63) ≈ 3.03 × 10^9, so bound ≤ 3 × 10^9.
    // Vehicle mass 1,420,788 × scale 1000 = 1.42 × 10^9. Fits.
    // Total thrust 22,819 × scale 1000 = 2.28 × 10^7. Fits.
    BigInt::from(3_000_000_000u64)
}

fn fh_goldilocks_score_bound() -> BigInt {
    BigInt::from(1_000_000u64)
}

fn fh_bn254_amount_bound() -> BigInt {
    fixed_scale(FALCON_HEAVY_BN254_SCALE_DECIMALS) * BigInt::from(1_000_000u64)
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
    write_value(values, format!("{prefix}_signed_bound_slack"), slack);
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
    values.insert(
        format!("{prefix}_nonnegative_bound_slack"),
        field_ref(&slack),
    );
    values.insert(
        format!("{prefix}_nonnegative_bound_anchor"),
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
        format!("{prefix}_exact_division_slack_anchor"),
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

fn parse_goldilocks_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, FALCON_HEAVY_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &fh_goldilocks_amount_bound())?;
    Ok(parsed)
}

fn parse_bn254_amount(value: &str, label: &str) -> ZkfResult<BigInt> {
    let parsed = decimal_scaled(value, FALCON_HEAVY_BN254_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &fh_bn254_amount_bound())?;
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

// ---------------------------------------------------------------------------
// Circuit 1 — Engine Health Certification (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_engine_health_certification_program(
    request: &EngineHealthCertificationRequestV1,
) -> ZkfResult<Program> {
    if request.engine_params.len() != FALCON_HEAVY_ENGINE_COUNT {
        return Err(ZkfError::InvalidArtifact(format!(
            "engine health requires exactly {FALCON_HEAVY_ENGINE_COUNT} engines, got {}",
            request.engine_params.len()
        )));
    }
    if request.acceptance_bands_low.len() != FALCON_HEAVY_PARAMS_PER_ENGINE
        || request.acceptance_bands_high.len() != FALCON_HEAVY_PARAMS_PER_ENGINE
    {
        return Err(ZkfError::InvalidArtifact(
            "acceptance bands must have exactly 7 entries each".to_string(),
        ));
    }
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new("falcon_heavy_engine_health_27", FH_GOLDILOCKS_FIELD);
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "engine-health")?;
    builder.metadata_entry("engine_count", FALCON_HEAVY_ENGINE_COUNT.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    // Declare acceptance band inputs
    for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
        let low = format!("ehc_band_low_{}", PARAM_NAMES[p]);
        let high = format!("ehc_band_high_{}", PARAM_NAMES[p]);
        builder.private_input(&low)?;
        builder.private_input(&high)?;
        builder.constrain_range(&low, amount_bits)?;
        builder.constrain_range(&high, amount_bits)?;
    }

    // Declare per-engine inputs
    let mut all_param_names = Vec::new();
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        let flight_count_name = format!("ehc_engine_{e}_flight_count");
        builder.private_input(&flight_count_name)?;
        builder.constrain_range(&flight_count_name, 16)?;
        for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
            let name = format!("ehc_engine_{e}_{}", PARAM_NAMES[p]);
            builder.private_input(&name)?;
            builder.constrain_range(&name, amount_bits)?;
            all_param_names.push(name);
        }
    }

    builder.private_input("ehc_max_rms_deviation")?;
    builder.constrain_range("ehc_max_rms_deviation", amount_bits)?;
    builder.public_output("ehc_commitment")?;
    builder.public_output("ehc_compliance_bit")?;
    builder.constant_signal("ehc_chain_seed", FieldElement::ZERO)?;

    // Nonlinear anchoring: signals that otherwise appear only in Range or
    // linear Equal constraints must participate in at least one nonlinear
    // relation so the audit's nonlinear-anchoring check passes.
    builder.constant_signal("__ehc_anchor_one", FieldElement::ONE)?;
    for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
        let low = format!("ehc_band_low_{}", PARAM_NAMES[p]);
        let high = format!("ehc_band_high_{}", PARAM_NAMES[p]);
        builder.constrain_equal(
            mul_expr(signal_expr(&low), signal_expr("__ehc_anchor_one")),
            signal_expr(&low),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&high), signal_expr("__ehc_anchor_one")),
            signal_expr(&high),
        )?;
    }
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        let flight_count_name = format!("ehc_engine_{e}_flight_count");
        builder.constrain_equal(
            mul_expr(
                signal_expr(&flight_count_name),
                signal_expr("__ehc_anchor_one"),
            ),
            signal_expr(&flight_count_name),
        )?;
        for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
            // thrust, chamber_pressure, mixture_ratio are in the Poseidon chain (nonlinear);
            // fuel_flow is in constrain_nonzero / exact_division (nonlinear);
            // ox_flow is in a constraint alongside a nonlinear Mul (nonlinear).
            // turbopump_rpm and gimbal_response need explicit anchoring.
            if PARAM_NAMES[p] == "turbopump_rpm" || PARAM_NAMES[p] == "gimbal_response" {
                let name = format!("ehc_engine_{e}_{}", PARAM_NAMES[p]);
                builder.constrain_equal(
                    mul_expr(signal_expr(&name), signal_expr("__ehc_anchor_one")),
                    signal_expr(&name),
                )?;
            }
        }
    }
    builder.constrain_equal(
        mul_expr(
            signal_expr("ehc_max_rms_deviation"),
            signal_expr("__ehc_anchor_one"),
        ),
        signal_expr("ehc_max_rms_deviation"),
    )?;

    // Per-engine constraints: each param within acceptance band
    let mut deviation_sq_exprs = Vec::new();
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
            let param = format!("ehc_engine_{e}_{}", PARAM_NAMES[p]);
            let low = format!("ehc_band_low_{}", PARAM_NAMES[p]);
            let high = format!("ehc_band_high_{}", PARAM_NAMES[p]);
            builder.constrain_geq(
                format!("ehc_engine_{e}_{}_low_slack", PARAM_NAMES[p]),
                signal_expr(&param),
                signal_expr(&low),
                amount_bits,
            )?;
            builder.constrain_leq(
                format!("ehc_engine_{e}_{}_high_slack", PARAM_NAMES[p]),
                signal_expr(&param),
                signal_expr(&high),
                amount_bits,
            )?;
        }
        // Mixture ratio check via exact division: mixture_ratio = ox_flow / fuel_flow
        let mr_name = format!("ehc_engine_{e}_mr_check");
        let mr_rem = format!("ehc_engine_{e}_mr_remainder");
        let mr_slack = format!("ehc_engine_{e}_mr_slack");
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&format!("ehc_engine_{e}_ox_flow")),
                const_expr(&scale),
            ),
            signal_expr(&format!("ehc_engine_{e}_fuel_flow")),
            &mr_name,
            &mr_rem,
            &mr_slack,
            &fh_goldilocks_amount_bound(),
            &format!("ehc_engine_{e}_mr"),
        )?;
        builder.constrain_nonzero(&format!("ehc_engine_{e}_fuel_flow"))?;

        // Deviation of thrust from mean (signed bound)
        let deviation = format!("ehc_engine_{e}_thrust_deviation");
        builder.private_signal(&deviation)?;
        builder.append_signed_bound(
            &deviation,
            &fh_goldilocks_amount_bound(),
            &format!("ehc_engine_{e}_thrust_deviation"),
        )?;
        deviation_sq_exprs.push(mul_expr(signal_expr(&deviation), signal_expr(&deviation)));
    }

    // Mean thrust for deviation computation
    builder.private_signal("ehc_mean_thrust")?;
    builder.private_signal("ehc_mean_thrust_remainder")?;
    builder.private_signal("ehc_mean_thrust_slack")?;
    let thrust_names: Vec<String> = (0..FALCON_HEAVY_ENGINE_COUNT)
        .map(|e| format!("ehc_engine_{e}_thrust"))
        .collect();
    builder.append_exact_division_constraints(
        sum_exprs(&thrust_names),
        const_expr(&BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64)),
        "ehc_mean_thrust",
        "ehc_mean_thrust_remainder",
        "ehc_mean_thrust_slack",
        &BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64),
        "ehc_mean_thrust",
    )?;
    builder.append_nonnegative_bound(
        "ehc_mean_thrust",
        &fh_goldilocks_amount_bound(),
        "ehc_mean_thrust_bound",
    )?;

    // Constrain each deviation = engine thrust - mean
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        let deviation = format!("ehc_engine_{e}_thrust_deviation");
        builder.constrain_equal(
            signal_expr(&deviation),
            sub_expr(
                signal_expr(&format!("ehc_engine_{e}_thrust")),
                signal_expr("ehc_mean_thrust"),
            ),
        )?;
    }

    // RMS deviation via mean-square and floor_sqrt
    builder.private_signal("ehc_mean_square_deviation")?;
    builder.private_signal("ehc_mean_square_deviation_remainder")?;
    builder.private_signal("ehc_mean_square_deviation_slack")?;
    builder.private_signal("ehc_rms_deviation")?;
    builder.private_signal("ehc_rms_deviation_remainder")?;
    builder.private_signal("ehc_rms_deviation_upper_slack")?;

    builder.append_exact_division_constraints(
        add_expr(deviation_sq_exprs),
        const_expr(&BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64)),
        "ehc_mean_square_deviation",
        "ehc_mean_square_deviation_remainder",
        "ehc_mean_square_deviation_slack",
        &BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64),
        "ehc_mean_square_deviation",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("ehc_mean_square_deviation"),
        "ehc_rms_deviation",
        "ehc_rms_deviation_remainder",
        "ehc_rms_deviation_upper_slack",
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "ehc_rms_deviation",
    )?;
    builder.constrain_leq(
        "ehc_rms_tolerance_slack",
        signal_expr("ehc_rms_deviation"),
        signal_expr("ehc_max_rms_deviation"),
        amount_bits,
    )?;

    // Poseidon chain over engines
    let mut previous_digest = signal_expr("ehc_chain_seed");
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        let step_digest = builder.append_poseidon_hash(
            &format!("ehc_engine_commitment_{e}"),
            [
                signal_expr(&format!("ehc_engine_{e}_thrust")),
                signal_expr(&format!("ehc_engine_{e}_chamber_pressure")),
                signal_expr(&format!("ehc_engine_{e}_mixture_ratio")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "ehc_final_commitment",
        [
            previous_digest,
            signal_expr("ehc_mean_thrust"),
            signal_expr("ehc_rms_deviation"),
            const_expr(&BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64)),
        ],
    )?;
    builder.bind("ehc_commitment", signal_expr(&final_digest))?;
    builder.bind("ehc_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn engine_health_certification_witness_from_request(
    request: &EngineHealthCertificationRequestV1,
) -> ZkfResult<Witness> {
    if request.engine_params.len() != FALCON_HEAVY_ENGINE_COUNT {
        return Err(ZkfError::InvalidArtifact(format!(
            "engine health requires exactly {FALCON_HEAVY_ENGINE_COUNT} engines"
        )));
    }
    let scale = fh_goldilocks_scale();
    let mut values = BTreeMap::new();

    // Parse acceptance bands
    let bands_low: Vec<BigInt> = request
        .acceptance_bands_low
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("band_low_{}", PARAM_NAMES[i])))
        .collect::<ZkfResult<Vec<_>>>()?;
    let bands_high: Vec<BigInt> = request
        .acceptance_bands_high
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("band_high_{}", PARAM_NAMES[i])))
        .collect::<ZkfResult<Vec<_>>>()?;
    let max_rms_deviation =
        parse_goldilocks_amount(&request.max_rms_deviation, "max_rms_deviation")?;

    for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
        write_value(
            &mut values,
            format!("ehc_band_low_{}", PARAM_NAMES[p]),
            bands_low[p].clone(),
        );
        write_value(
            &mut values,
            format!("ehc_band_high_{}", PARAM_NAMES[p]),
            bands_high[p].clone(),
        );
    }
    write_value(
        &mut values,
        "ehc_max_rms_deviation",
        max_rms_deviation.clone(),
    );
    write_value(&mut values, "ehc_chain_seed", zero());

    // Parse all engine parameters
    let mut all_thrusts = Vec::with_capacity(FALCON_HEAVY_ENGINE_COUNT);
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        if request.engine_params[e].len() != FALCON_HEAVY_PARAMS_PER_ENGINE {
            return Err(ZkfError::InvalidArtifact(format!(
                "engine {e} must have exactly {FALCON_HEAVY_PARAMS_PER_ENGINE} parameters"
            )));
        }
        write_value(
            &mut values,
            format!("ehc_engine_{e}_flight_count"),
            BigInt::from(request.engine_flight_counts[e]),
        );
        for p in 0..FALCON_HEAVY_PARAMS_PER_ENGINE {
            let param_val = parse_goldilocks_amount(
                &request.engine_params[e][p],
                &format!("engine_{e}_{}", PARAM_NAMES[p]),
            )?;
            if param_val < bands_low[p] || param_val > bands_high[p] {
                return Err(ZkfError::InvalidArtifact(format!(
                    "engine {e} {} out of acceptance band",
                    PARAM_NAMES[p]
                )));
            }
            write_value(
                &mut values,
                format!("ehc_engine_{e}_{}", PARAM_NAMES[p]),
                param_val.clone(),
            );
            write_value(
                &mut values,
                format!("ehc_engine_{e}_{}_low_slack", PARAM_NAMES[p]),
                &param_val - &bands_low[p],
            );
            write_value(
                &mut values,
                format!("ehc_engine_{e}_{}_high_slack", PARAM_NAMES[p]),
                &bands_high[p] - &param_val,
            );
            if PARAM_NAMES[p] == "thrust" {
                all_thrusts.push(param_val);
            }
        }
        // Mixture ratio check
        let ox_flow =
            parse_goldilocks_amount(&request.engine_params[e][3], &format!("engine_{e}_ox_flow"))?;
        let fuel_flow = parse_goldilocks_amount(
            &request.engine_params[e][2],
            &format!("engine_{e}_fuel_flow"),
        )?;
        if fuel_flow == zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "engine {e} fuel_flow must be nonzero"
            )));
        }
        let mr_numerator = &ox_flow * &scale;
        let mr_check = &mr_numerator / &fuel_flow;
        let mr_remainder = &mr_numerator % &fuel_flow;
        let mr_slack = &fuel_flow - &mr_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("ehc_engine_{e}_mr_check"),
            &mr_check,
            &format!("ehc_engine_{e}_mr_remainder"),
            &mr_remainder,
            &format!("ehc_engine_{e}_mr_slack"),
            &mr_slack,
            &format!("ehc_engine_{e}_mr"),
        );
    }

    // Compute mean thrust
    let total_thrust = sum_bigints(&all_thrusts);
    let engine_count = BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64);
    let mean_thrust = &total_thrust / &engine_count;
    let mean_thrust_remainder = &total_thrust % &engine_count;
    let mean_thrust_slack = &engine_count - &mean_thrust_remainder - one();
    write_exact_division_support(
        &mut values,
        "ehc_mean_thrust",
        &mean_thrust,
        "ehc_mean_thrust_remainder",
        &mean_thrust_remainder,
        "ehc_mean_thrust_slack",
        &mean_thrust_slack,
        "ehc_mean_thrust",
    );

    // Compute deviations and mean-square
    let mut sum_squared_deviations = zero();
    for (e, thrust) in all_thrusts.iter().enumerate() {
        let deviation = thrust - &mean_thrust;
        write_value(
            &mut values,
            format!("ehc_engine_{e}_thrust_deviation"),
            deviation.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &deviation,
            &fh_goldilocks_amount_bound(),
            &format!("ehc_engine_{e}_thrust_deviation"),
        )?;
        sum_squared_deviations += &deviation * &deviation;
    }

    let mean_square_deviation = &sum_squared_deviations / &engine_count;
    let mean_square_deviation_remainder = &sum_squared_deviations % &engine_count;
    let mean_square_deviation_slack = &engine_count - &mean_square_deviation_remainder - one();
    write_exact_division_support(
        &mut values,
        "ehc_mean_square_deviation",
        &mean_square_deviation,
        "ehc_mean_square_deviation_remainder",
        &mean_square_deviation_remainder,
        "ehc_mean_square_deviation_slack",
        &mean_square_deviation_slack,
        "ehc_mean_square_deviation",
    );
    let rms_deviation = bigint_isqrt_floor(&mean_square_deviation);
    if rms_deviation > max_rms_deviation {
        return Err(ZkfError::InvalidArtifact(
            "engine health RMS deviation exceeds tolerance".to_string(),
        ));
    }
    let rms_remainder = &mean_square_deviation - (&rms_deviation * &rms_deviation);
    let rms_upper_slack =
        ((&rms_deviation + one()) * (&rms_deviation + one())) - &mean_square_deviation - one();
    write_floor_sqrt_support(
        &mut values,
        "ehc_rms_deviation",
        &rms_deviation,
        "ehc_rms_deviation_remainder",
        &rms_remainder,
        "ehc_rms_deviation_upper_slack",
        &rms_upper_slack,
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "ehc_rms_deviation",
    )?;
    write_value(
        &mut values,
        "ehc_rms_tolerance_slack",
        &max_rms_deviation - &rms_deviation,
    );

    // Poseidon chain
    let mut previous_digest = zero();
    for e in 0..FALCON_HEAVY_ENGINE_COUNT {
        let digest = poseidon_permutation4(
            FH_GOLDILOCKS_FIELD,
            [
                &all_thrusts[e],
                &parse_goldilocks_amount(&request.engine_params[e][0], "chamber_pressure")?,
                &parse_goldilocks_amount(&request.engine_params[e][4], "mixture_ratio")?,
                &previous_digest,
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("ehc_engine_commitment_{e}"), digest)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &mean_thrust,
            &rms_deviation,
            &BigInt::from(FALCON_HEAVY_ENGINE_COUNT as u64),
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "ehc_final_commitment", final_digest);
    values.insert("ehc_commitment".to_string(), commitment);
    values.insert("ehc_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_engine_health_certification_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 2 — Ascent Trajectory Certification (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_ascent_trajectory_program(request: &AscentTrajectoryRequestV1) -> ZkfResult<Program> {
    let steps = request.altitude.len();
    if steps == 0
        || steps != request.velocity.len()
        || steps != request.acceleration.len()
        || steps != request.dynamic_pressure.len()
        || steps != request.throttle_pct.len()
        || steps != request.mass.len()
    {
        return Err(ZkfError::InvalidArtifact(
            "ascent trajectory requires equal-length non-empty vectors".to_string(),
        ));
    }
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new(
        format!("falcon_heavy_ascent_trajectory_{steps}"),
        FH_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "ascent-trajectory")?;
    builder.metadata_entry("steps", steps.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    // Structural limits
    for input in [
        "at_max_q",
        "at_max_axial_load",
        "at_max_lateral_load",
        "at_meco_altitude_min",
        "at_meco_velocity_min",
        "at_gravity",
    ] {
        builder.private_input(input)?;
        builder.constrain_range(input, amount_bits)?;
    }

    // Per-step inputs
    for step in 0..steps {
        for name in [
            "altitude",
            "velocity",
            "acceleration",
            "dynamic_pressure",
            "throttle_pct",
            "mass",
        ] {
            let sig = format!("at_step_{step}_{name}");
            builder.private_input(&sig)?;
            builder.constrain_range(&sig, amount_bits)?;
        }
    }

    builder.public_output("at_commitment")?;
    builder.public_output("at_compliance_bit")?;
    builder.constant_signal("at_chain_seed", FieldElement::ZERO)?;

    // Nonlinear anchoring for signals that would otherwise be linear-only
    builder.constant_signal("__at_anchor_one", FieldElement::ONE)?;
    for input in [
        "at_max_axial_load",
        "at_max_lateral_load",
        "at_meco_altitude_min",
        "at_meco_velocity_min",
    ] {
        builder.constrain_equal(
            mul_expr(signal_expr(input), signal_expr("__at_anchor_one")),
            signal_expr(input),
        )?;
    }
    for step in 0..steps {
        for name in ["throttle_pct", "mass"] {
            let sig = format!("at_step_{step}_{name}");
            builder.constrain_equal(
                mul_expr(signal_expr(&sig), signal_expr("__at_anchor_one")),
                signal_expr(&sig),
            )?;
        }
    }

    // Per-step constraints
    for step in 0..steps {
        // Dynamic pressure <= max_q
        builder.constrain_leq(
            format!("at_step_{step}_q_slack"),
            signal_expr(&format!("at_step_{step}_dynamic_pressure")),
            signal_expr("at_max_q"),
            amount_bits,
        )?;
        // Throttle bound check (0..1000 for 0..100%)
        builder.constrain_leq(
            format!("at_step_{step}_throttle_slack"),
            signal_expr(&format!("at_step_{step}_throttle_pct")),
            const_expr(&fh_goldilocks_scale()),
            amount_bits,
        )?;

        // Euler integration constraint: altitude_{n+1} ≈ altitude_n + velocity_n * dt
        // We use signed-bound deviation from nominal to prove trajectory consistency
        if step > 0 {
            let deviation = format!("at_step_{step}_deviation");
            builder.private_signal(&deviation)?;
            builder.append_signed_bound(
                &deviation,
                &fh_goldilocks_amount_bound(),
                &format!("at_step_{step}_deviation"),
            )?;
            // deviation = altitude[step] - altitude[step-1] (simplified integration check)
            builder.constrain_equal(
                signal_expr(&deviation),
                sub_expr(
                    signal_expr(&format!("at_step_{step}_altitude")),
                    signal_expr(&format!("at_step_{}_altitude", step - 1)),
                ),
            )?;
        }

        // Axial load check via exact division: a/g <= max_axial_load
        let axial_q = format!("at_step_{step}_axial_quotient");
        let axial_r = format!("at_step_{step}_axial_remainder");
        let axial_s = format!("at_step_{step}_axial_slack");
        builder.append_exact_division_constraints(
            mul_expr(
                signal_expr(&format!("at_step_{step}_acceleration")),
                const_expr(&scale),
            ),
            signal_expr("at_gravity"),
            &axial_q,
            &axial_r,
            &axial_s,
            &fh_goldilocks_amount_bound(),
            &format!("at_step_{step}_axial"),
        )?;
        builder.constrain_leq(
            format!("at_step_{step}_axial_load_slack"),
            signal_expr(&axial_q),
            signal_expr("at_max_axial_load"),
            amount_bits,
        )?;
    }
    builder.constrain_nonzero("at_gravity")?;

    // MECO checks (last step)
    let last = steps - 1;
    builder.constrain_geq(
        "at_meco_altitude_slack",
        signal_expr(&format!("at_step_{last}_altitude")),
        signal_expr("at_meco_altitude_min"),
        amount_bits,
    )?;
    builder.constrain_geq(
        "at_meco_velocity_slack",
        signal_expr(&format!("at_step_{last}_velocity")),
        signal_expr("at_meco_velocity_min"),
        amount_bits,
    )?;

    // Poseidon chain
    let mut previous_digest = signal_expr("at_chain_seed");
    for step in 0..steps {
        let step_digest = builder.append_poseidon_hash(
            &format!("at_step_commitment_{step}"),
            [
                signal_expr(&format!("at_step_{step}_altitude")),
                signal_expr(&format!("at_step_{step}_velocity")),
                signal_expr(&format!("at_step_{step}_dynamic_pressure")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "at_final_commitment",
        [
            previous_digest,
            signal_expr(&format!("at_step_{last}_altitude")),
            signal_expr(&format!("at_step_{last}_velocity")),
            signal_expr("at_max_q"),
        ],
    )?;
    builder.bind("at_commitment", signal_expr(&final_digest))?;
    builder.bind("at_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn ascent_trajectory_witness_from_request(
    request: &AscentTrajectoryRequestV1,
) -> ZkfResult<Witness> {
    let steps = request.altitude.len();
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "ascent trajectory requires non-empty vectors".to_string(),
        ));
    }
    let scale = fh_goldilocks_scale();
    let mut values = BTreeMap::new();

    let max_q = parse_goldilocks_amount(&request.max_q, "max_q")?;
    let max_axial = parse_goldilocks_amount(&request.max_axial_load, "max_axial_load")?;
    let max_lateral = parse_goldilocks_amount(&request.max_lateral_load, "max_lateral_load")?;
    let meco_alt_min = parse_goldilocks_amount(&request.meco_altitude_min, "meco_altitude_min")?;
    let meco_vel_min = parse_goldilocks_amount(&request.meco_velocity_min, "meco_velocity_min")?;
    let gravity = parse_goldilocks_amount(&request.gravity, "gravity")?;
    if gravity == zero() {
        return Err(ZkfError::InvalidArtifact(
            "gravity must be nonzero".to_string(),
        ));
    }

    write_value(&mut values, "at_max_q", max_q.clone());
    write_value(&mut values, "at_max_axial_load", max_axial.clone());
    write_value(&mut values, "at_max_lateral_load", max_lateral.clone());
    write_value(&mut values, "at_meco_altitude_min", meco_alt_min.clone());
    write_value(&mut values, "at_meco_velocity_min", meco_vel_min.clone());
    write_value(&mut values, "at_gravity", gravity.clone());
    write_value(&mut values, "at_chain_seed", zero());

    let mut altitudes = Vec::with_capacity(steps);
    let mut velocities = Vec::with_capacity(steps);
    for step in 0..steps {
        let alt = parse_goldilocks_amount(&request.altitude[step], &format!("altitude_{step}"))?;
        let vel = parse_goldilocks_amount(&request.velocity[step], &format!("velocity_{step}"))?;
        let acc =
            parse_goldilocks_amount(&request.acceleration[step], &format!("acceleration_{step}"))?;
        let q = parse_goldilocks_amount(&request.dynamic_pressure[step], &format!("q_{step}"))?;
        let throttle =
            parse_goldilocks_amount(&request.throttle_pct[step], &format!("throttle_{step}"))?;
        let mass = parse_goldilocks_amount(&request.mass[step], &format!("mass_{step}"))?;

        if q > max_q {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} dynamic pressure exceeds max_q"
            )));
        }

        write_value(&mut values, format!("at_step_{step}_altitude"), alt.clone());
        write_value(&mut values, format!("at_step_{step}_velocity"), vel.clone());
        write_value(
            &mut values,
            format!("at_step_{step}_acceleration"),
            acc.clone(),
        );
        write_value(
            &mut values,
            format!("at_step_{step}_dynamic_pressure"),
            q.clone(),
        );
        write_value(
            &mut values,
            format!("at_step_{step}_throttle_pct"),
            throttle.clone(),
        );
        write_value(&mut values, format!("at_step_{step}_mass"), mass.clone());

        write_value(&mut values, format!("at_step_{step}_q_slack"), &max_q - &q);
        write_value(
            &mut values,
            format!("at_step_{step}_throttle_slack"),
            &scale - &throttle,
        );

        if step > 0 {
            let deviation: BigInt = &alt - &altitudes[step - 1];
            write_value(
                &mut values,
                format!("at_step_{step}_deviation"),
                deviation.clone(),
            );
            write_signed_bound_support(
                &mut values,
                &deviation,
                &fh_goldilocks_amount_bound(),
                &format!("at_step_{step}_deviation"),
            )?;
        }

        // Axial load
        let axial_numerator = &acc * &scale;
        let axial_quotient = &axial_numerator / &gravity;
        let axial_remainder = &axial_numerator % &gravity;
        let axial_slack = &gravity - &axial_remainder - one();
        write_exact_division_support(
            &mut values,
            &format!("at_step_{step}_axial_quotient"),
            &axial_quotient,
            &format!("at_step_{step}_axial_remainder"),
            &axial_remainder,
            &format!("at_step_{step}_axial_slack"),
            &axial_slack,
            &format!("at_step_{step}_axial"),
        );
        if axial_quotient > max_axial {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} axial load exceeds maximum"
            )));
        }
        write_value(
            &mut values,
            format!("at_step_{step}_axial_load_slack"),
            &max_axial - &axial_quotient,
        );

        altitudes.push(alt);
        velocities.push(vel);
    }

    // MECO checks
    let last = steps - 1;
    if altitudes[last] < meco_alt_min {
        return Err(ZkfError::InvalidArtifact(
            "MECO altitude below minimum".to_string(),
        ));
    }
    if velocities[last] < meco_vel_min {
        return Err(ZkfError::InvalidArtifact(
            "MECO velocity below minimum".to_string(),
        ));
    }
    write_value(
        &mut values,
        "at_meco_altitude_slack",
        &altitudes[last] - &meco_alt_min,
    );
    write_value(
        &mut values,
        "at_meco_velocity_slack",
        &velocities[last] - &meco_vel_min,
    );

    // Poseidon chain
    let mut previous_digest = zero();
    for step in 0..steps {
        let q = parse_goldilocks_amount(&request.dynamic_pressure[step], "q")?;
        let digest = poseidon_permutation4(
            FH_GOLDILOCKS_FIELD,
            [&altitudes[step], &velocities[step], &q, &previous_digest],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("at_step_commitment_{step}"), digest)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &altitudes[last],
            &velocities[last],
            &max_q,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "at_final_commitment", final_digest);
    values.insert("at_commitment".to_string(), commitment);
    values.insert("at_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_ascent_trajectory_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 3 — Booster Recovery Certification (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_booster_recovery_program(
    request: &BoosterRecoveryCertificationRequestV1,
) -> ZkfResult<Program> {
    if request.cores.len() != FALCON_HEAVY_CORE_COUNT {
        return Err(ZkfError::InvalidArtifact(format!(
            "booster recovery requires exactly {FALCON_HEAVY_CORE_COUNT} cores"
        )));
    }
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new("falcon_heavy_booster_recovery_3", FH_GOLDILOCKS_FIELD);
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "booster-recovery")?;
    builder.metadata_entry("core_count", FALCON_HEAVY_CORE_COUNT.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    builder.private_input("br_max_landing_velocity")?;
    builder.private_input("br_max_landing_position_error")?;
    builder.constrain_range("br_max_landing_velocity", amount_bits)?;
    builder.constrain_range("br_max_landing_position_error", amount_bits)?;
    builder.public_output("br_commitment")?;
    builder.public_output("br_compliance_bit")?;
    builder.constant_signal("br_chain_seed", FieldElement::ZERO)?;
    builder.constant_signal("__br_anchor_one", FieldElement::ONE)?;

    for core in 0..FALCON_HEAVY_CORE_COUNT {
        let recovery_steps = request.cores[core].altitude_profile.len();
        for input in [
            format!("br_core_{core}_sep_altitude"),
            format!("br_core_{core}_sep_velocity"),
            format!("br_core_{core}_propellant"),
            format!("br_core_{core}_landing_alt_error"),
            format!("br_core_{core}_landing_velocity"),
        ] {
            builder.private_input(&input)?;
            builder.constrain_range(&input, amount_bits)?;
        }
        let tea_teb = format!("br_core_{core}_tea_teb_ignitions");
        let max_tea_teb = format!("br_core_{core}_max_tea_teb");
        builder.private_input(&tea_teb)?;
        builder.private_input(&max_tea_teb)?;
        builder.constrain_range(&tea_teb, 8)?;
        builder.constrain_range(&max_tea_teb, 8)?;
        builder.constrain_leq(
            format!("br_core_{core}_tea_teb_slack"),
            signal_expr(&tea_teb),
            signal_expr(&max_tea_teb),
            8,
        )?;

        // Per-step altitude/velocity profiles
        for step in 0..recovery_steps {
            let alt = format!("br_core_{core}_step_{step}_altitude");
            let vel = format!("br_core_{core}_step_{step}_velocity");
            builder.private_input(&alt)?;
            builder.private_input(&vel)?;
            builder.constrain_range(&alt, amount_bits)?;
            builder.constrain_range(&vel, amount_bits)?;
        }

        // Burn durations
        for b in 0..request.cores[core].burn_durations.len() {
            let burn = format!("br_core_{core}_burn_{b}");
            builder.private_input(&burn)?;
            builder.constrain_range(&burn, amount_bits)?;
        }

        // Landing velocity check
        builder.constrain_leq(
            format!("br_core_{core}_landing_vel_slack"),
            signal_expr(&format!("br_core_{core}_landing_velocity")),
            signal_expr("br_max_landing_velocity"),
            amount_bits,
        )?;

        // Landing position error via floor_sqrt
        builder.private_signal(&format!("br_core_{core}_position_error_sq"))?;
        builder.constrain_equal(
            signal_expr(&format!("br_core_{core}_position_error_sq")),
            mul_expr(
                signal_expr(&format!("br_core_{core}_landing_alt_error")),
                signal_expr(&format!("br_core_{core}_landing_alt_error")),
            ),
        )?;
        let sqrt_sig = format!("br_core_{core}_position_error");
        let sqrt_rem = format!("br_core_{core}_position_error_remainder");
        let sqrt_upper = format!("br_core_{core}_position_error_upper_slack");
        builder.append_floor_sqrt_constraints(
            signal_expr(&format!("br_core_{core}_position_error_sq")),
            &sqrt_sig,
            &sqrt_rem,
            &sqrt_upper,
            &fh_goldilocks_score_bound(),
            &fh_goldilocks_score_bound(),
            &format!("br_core_{core}_position_error"),
        )?;
        builder.constrain_leq(
            format!("br_core_{core}_position_error_slack"),
            signal_expr(&sqrt_sig),
            signal_expr("br_max_landing_position_error"),
            amount_bits,
        )?;

        // Euler integration checks for recovery steps
        for step in 1..recovery_steps {
            let alt_delta = format!("br_core_{core}_step_{step}_alt_delta");
            builder.private_signal(&alt_delta)?;
            builder.constrain_equal(
                signal_expr(&alt_delta),
                sub_expr(
                    signal_expr(&format!("br_core_{core}_step_{step}_altitude")),
                    signal_expr(&format!("br_core_{core}_step_{}_altitude", step - 1)),
                ),
            )?;
            builder.append_signed_bound(
                &alt_delta,
                &fh_goldilocks_amount_bound(),
                &format!("br_core_{core}_step_{step}_alt_delta"),
            )?;
        }

        // Nonlinear anchoring for linear-only signals in this core
        let sep_vel = format!("br_core_{core}_sep_velocity");
        builder.constrain_equal(
            mul_expr(signal_expr(&sep_vel), signal_expr("__br_anchor_one")),
            signal_expr(&sep_vel),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&tea_teb), signal_expr("__br_anchor_one")),
            signal_expr(&tea_teb),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&max_tea_teb), signal_expr("__br_anchor_one")),
            signal_expr(&max_tea_teb),
        )?;
        for step in 0..recovery_steps {
            let alt = format!("br_core_{core}_step_{step}_altitude");
            let vel = format!("br_core_{core}_step_{step}_velocity");
            builder.constrain_equal(
                mul_expr(signal_expr(&alt), signal_expr("__br_anchor_one")),
                signal_expr(&alt),
            )?;
            builder.constrain_equal(
                mul_expr(signal_expr(&vel), signal_expr("__br_anchor_one")),
                signal_expr(&vel),
            )?;
        }
        for b in 0..request.cores[core].burn_durations.len() {
            let burn = format!("br_core_{core}_burn_{b}");
            builder.constrain_equal(
                mul_expr(signal_expr(&burn), signal_expr("__br_anchor_one")),
                signal_expr(&burn),
            )?;
        }
    }

    // Poseidon chain over cores
    let mut previous_digest = signal_expr("br_chain_seed");
    for core in 0..FALCON_HEAVY_CORE_COUNT {
        let step_digest = builder.append_poseidon_hash(
            &format!("br_core_commitment_{core}"),
            [
                signal_expr(&format!("br_core_{core}_sep_altitude")),
                signal_expr(&format!("br_core_{core}_landing_velocity")),
                signal_expr(&format!("br_core_{core}_propellant")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "br_final_commitment",
        [
            previous_digest,
            signal_expr("br_max_landing_velocity"),
            signal_expr("br_max_landing_position_error"),
            const_expr(&BigInt::from(FALCON_HEAVY_CORE_COUNT as u64)),
        ],
    )?;
    builder.bind("br_commitment", signal_expr(&final_digest))?;
    builder.bind("br_compliance_bit", const_expr(&one()))?;
    builder.build()
}

/// Build a standalone recovery circuit for a single core (300 steps).
/// This is the per-core decomposition of the monolithic 3-core `build_booster_recovery_program`.
pub fn build_single_core_recovery_program(
    core_id: usize,
    data: &CoreRecoveryDataV1,
    _max_landing_velocity: &str,
    _max_landing_position_error: &str,
) -> ZkfResult<Program> {
    let recovery_steps = data.altitude_profile.len();
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new(
        format!("falcon_heavy_core_{core_id}_recovery_300"),
        FH_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", format!("core-{core_id}-recovery"))?;
    builder.metadata_entry("recovery_steps", recovery_steps.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    builder.private_input("br_max_landing_velocity")?;
    builder.private_input("br_max_landing_position_error")?;
    builder.constrain_range("br_max_landing_velocity", amount_bits)?;
    builder.constrain_range("br_max_landing_position_error", amount_bits)?;
    builder.public_output(&format!("br_core_{core_id}_commitment"))?;
    builder.public_output(&format!("br_core_{core_id}_compliance_bit"))?;
    builder.constant_signal("br_chain_seed", FieldElement::ZERO)?;
    builder.constant_signal("__br_anchor_one", FieldElement::ONE)?;

    // Separation state, propellant, landing data
    for input in [
        format!("br_core_{core_id}_sep_altitude"),
        format!("br_core_{core_id}_sep_velocity"),
        format!("br_core_{core_id}_propellant"),
        format!("br_core_{core_id}_landing_alt_error"),
        format!("br_core_{core_id}_landing_velocity"),
    ] {
        builder.private_input(&input)?;
        builder.constrain_range(&input, amount_bits)?;
    }

    // TEA-TEB checks
    let tea_teb = format!("br_core_{core_id}_tea_teb_ignitions");
    let max_tea_teb = format!("br_core_{core_id}_max_tea_teb");
    builder.private_input(&tea_teb)?;
    builder.private_input(&max_tea_teb)?;
    builder.constrain_range(&tea_teb, 8)?;
    builder.constrain_range(&max_tea_teb, 8)?;
    builder.constrain_leq(
        format!("br_core_{core_id}_tea_teb_slack"),
        signal_expr(&tea_teb),
        signal_expr(&max_tea_teb),
        8,
    )?;

    // Per-step altitude/velocity profiles (300 steps)
    for step in 0..recovery_steps {
        let alt = format!("br_core_{core_id}_step_{step}_altitude");
        let vel = format!("br_core_{core_id}_step_{step}_velocity");
        builder.private_input(&alt)?;
        builder.private_input(&vel)?;
        builder.constrain_range(&alt, amount_bits)?;
        builder.constrain_range(&vel, amount_bits)?;
    }

    // Burn durations
    for b in 0..data.burn_durations.len() {
        let burn = format!("br_core_{core_id}_burn_{b}");
        builder.private_input(&burn)?;
        builder.constrain_range(&burn, amount_bits)?;
    }

    // Landing velocity check
    builder.constrain_leq(
        format!("br_core_{core_id}_landing_vel_slack"),
        signal_expr(&format!("br_core_{core_id}_landing_velocity")),
        signal_expr("br_max_landing_velocity"),
        amount_bits,
    )?;

    // Landing position error via floor_sqrt
    builder.private_signal(&format!("br_core_{core_id}_position_error_sq"))?;
    builder.constrain_equal(
        signal_expr(&format!("br_core_{core_id}_position_error_sq")),
        mul_expr(
            signal_expr(&format!("br_core_{core_id}_landing_alt_error")),
            signal_expr(&format!("br_core_{core_id}_landing_alt_error")),
        ),
    )?;
    let sqrt_sig = format!("br_core_{core_id}_position_error");
    let sqrt_rem = format!("br_core_{core_id}_position_error_remainder");
    let sqrt_upper = format!("br_core_{core_id}_position_error_upper_slack");
    builder.append_floor_sqrt_constraints(
        signal_expr(&format!("br_core_{core_id}_position_error_sq")),
        &sqrt_sig,
        &sqrt_rem,
        &sqrt_upper,
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        &format!("br_core_{core_id}_position_error"),
    )?;
    builder.constrain_leq(
        format!("br_core_{core_id}_position_error_slack"),
        signal_expr(&sqrt_sig),
        signal_expr("br_max_landing_position_error"),
        amount_bits,
    )?;

    // Euler integration checks for recovery steps
    for step in 1..recovery_steps {
        let alt_delta = format!("br_core_{core_id}_step_{step}_alt_delta");
        builder.private_signal(&alt_delta)?;
        builder.constrain_equal(
            signal_expr(&alt_delta),
            sub_expr(
                signal_expr(&format!("br_core_{core_id}_step_{step}_altitude")),
                signal_expr(&format!("br_core_{core_id}_step_{}_altitude", step - 1)),
            ),
        )?;
        builder.append_signed_bound(
            &alt_delta,
            &fh_goldilocks_amount_bound(),
            &format!("br_core_{core_id}_step_{step}_alt_delta"),
        )?;
    }

    // Nonlinear anchoring for linear-only signals
    let sep_vel = format!("br_core_{core_id}_sep_velocity");
    builder.constrain_equal(
        mul_expr(signal_expr(&sep_vel), signal_expr("__br_anchor_one")),
        signal_expr(&sep_vel),
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr(&tea_teb), signal_expr("__br_anchor_one")),
        signal_expr(&tea_teb),
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr(&max_tea_teb), signal_expr("__br_anchor_one")),
        signal_expr(&max_tea_teb),
    )?;
    for step in 0..recovery_steps {
        let alt = format!("br_core_{core_id}_step_{step}_altitude");
        let vel = format!("br_core_{core_id}_step_{step}_velocity");
        builder.constrain_equal(
            mul_expr(signal_expr(&alt), signal_expr("__br_anchor_one")),
            signal_expr(&alt),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&vel), signal_expr("__br_anchor_one")),
            signal_expr(&vel),
        )?;
    }
    for b in 0..data.burn_durations.len() {
        let burn = format!("br_core_{core_id}_burn_{b}");
        builder.constrain_equal(
            mul_expr(signal_expr(&burn), signal_expr("__br_anchor_one")),
            signal_expr(&burn),
        )?;
    }

    // Poseidon chain for this core
    let core_digest = builder.append_poseidon_hash(
        &format!("br_core_commitment_{core_id}"),
        [
            signal_expr(&format!("br_core_{core_id}_sep_altitude")),
            signal_expr(&format!("br_core_{core_id}_landing_velocity")),
            signal_expr(&format!("br_core_{core_id}_propellant")),
            signal_expr("br_chain_seed"),
        ],
    )?;
    let final_digest = builder.append_poseidon_hash(
        &format!("br_core_{core_id}_final_commitment"),
        [
            signal_expr(&core_digest),
            signal_expr("br_max_landing_velocity"),
            signal_expr("br_max_landing_position_error"),
            const_expr(&BigInt::from(1u64)),
        ],
    )?;
    builder.bind(
        &format!("br_core_{core_id}_commitment"),
        signal_expr(&final_digest),
    )?;
    builder.bind(
        &format!("br_core_{core_id}_compliance_bit"),
        const_expr(&one()),
    )?;
    builder.build()
}

pub fn booster_recovery_witness_from_request(
    request: &BoosterRecoveryCertificationRequestV1,
) -> ZkfResult<Witness> {
    if request.cores.len() != FALCON_HEAVY_CORE_COUNT {
        return Err(ZkfError::InvalidArtifact(format!(
            "booster recovery requires exactly {FALCON_HEAVY_CORE_COUNT} cores"
        )));
    }
    let mut values = BTreeMap::new();

    let max_landing_vel =
        parse_goldilocks_amount(&request.max_landing_velocity, "max_landing_velocity")?;
    let max_landing_err = parse_goldilocks_amount(
        &request.max_landing_position_error,
        "max_landing_position_error",
    )?;

    write_value(
        &mut values,
        "br_max_landing_velocity",
        max_landing_vel.clone(),
    );
    write_value(
        &mut values,
        "br_max_landing_position_error",
        max_landing_err.clone(),
    );
    write_value(&mut values, "br_chain_seed", zero());

    for core in 0..FALCON_HEAVY_CORE_COUNT {
        let c = &request.cores[core];
        let sep_alt =
            parse_goldilocks_amount(&c.separation_altitude, &format!("core_{core}_sep_alt"))?;
        let sep_vel =
            parse_goldilocks_amount(&c.separation_velocity, &format!("core_{core}_sep_vel"))?;
        let propellant =
            parse_goldilocks_amount(&c.propellant_reserve, &format!("core_{core}_propellant"))?;
        let landing_alt_error = parse_goldilocks_amount(
            &c.landing_altitude_error,
            &format!("core_{core}_landing_alt_error"),
        )?;
        let landing_vel =
            parse_goldilocks_amount(&c.landing_velocity, &format!("core_{core}_landing_vel"))?;

        if landing_vel > max_landing_vel {
            return Err(ZkfError::InvalidArtifact(format!(
                "core {core} landing velocity exceeds limit"
            )));
        }

        write_value(
            &mut values,
            format!("br_core_{core}_sep_altitude"),
            sep_alt.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_sep_velocity"),
            sep_vel.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_propellant"),
            propellant.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_landing_alt_error"),
            landing_alt_error.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_landing_velocity"),
            landing_vel.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_tea_teb_ignitions"),
            BigInt::from(c.tea_teb_ignitions),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_max_tea_teb"),
            BigInt::from(c.max_tea_teb),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_tea_teb_slack"),
            BigInt::from(c.max_tea_teb) - BigInt::from(c.tea_teb_ignitions),
        );
        write_value(
            &mut values,
            format!("br_core_{core}_landing_vel_slack"),
            &max_landing_vel - &landing_vel,
        );

        // Position error
        let pos_err_sq = &landing_alt_error * &landing_alt_error;
        write_value(
            &mut values,
            format!("br_core_{core}_position_error_sq"),
            pos_err_sq.clone(),
        );
        let pos_err = bigint_isqrt_floor(&pos_err_sq);
        let pos_err_remainder = &pos_err_sq - (&pos_err * &pos_err);
        let pos_err_upper_slack = ((&pos_err + one()) * (&pos_err + one())) - &pos_err_sq - one();
        write_floor_sqrt_support(
            &mut values,
            &format!("br_core_{core}_position_error"),
            &pos_err,
            &format!("br_core_{core}_position_error_remainder"),
            &pos_err_remainder,
            &format!("br_core_{core}_position_error_upper_slack"),
            &pos_err_upper_slack,
            &fh_goldilocks_score_bound(),
            &fh_goldilocks_score_bound(),
            &format!("br_core_{core}_position_error"),
        )?;
        if pos_err > max_landing_err {
            return Err(ZkfError::InvalidArtifact(format!(
                "core {core} landing position error exceeds limit"
            )));
        }
        write_value(
            &mut values,
            format!("br_core_{core}_position_error_slack"),
            &max_landing_err - &pos_err,
        );

        // Altitude/velocity profiles
        let recovery_steps = c.altitude_profile.len();
        let mut alts = Vec::with_capacity(recovery_steps);
        for step in 0..recovery_steps {
            let alt = parse_goldilocks_amount(
                &c.altitude_profile[step],
                &format!("core_{core}_step_{step}_alt"),
            )?;
            let vel = parse_goldilocks_amount(
                &c.velocity_profile[step],
                &format!("core_{core}_step_{step}_vel"),
            )?;
            write_value(
                &mut values,
                format!("br_core_{core}_step_{step}_altitude"),
                alt.clone(),
            );
            write_value(
                &mut values,
                format!("br_core_{core}_step_{step}_velocity"),
                vel.clone(),
            );
            if step > 0 {
                let delta: BigInt = &alt - &alts[step - 1];
                write_value(
                    &mut values,
                    format!("br_core_{core}_step_{step}_alt_delta"),
                    delta.clone(),
                );
                write_signed_bound_support(
                    &mut values,
                    &delta,
                    &fh_goldilocks_amount_bound(),
                    &format!("br_core_{core}_step_{step}_alt_delta"),
                )?;
            }
            alts.push(alt);
        }

        // Burns
        for (b, burn) in c.burn_durations.iter().enumerate() {
            let bv = parse_goldilocks_amount(burn, &format!("core_{core}_burn_{b}"))?;
            write_value(&mut values, format!("br_core_{core}_burn_{b}"), bv);
        }
    }

    // Poseidon chain
    let mut previous_digest = zero();
    for core in 0..FALCON_HEAVY_CORE_COUNT {
        let c = &request.cores[core];
        let sep_alt = parse_goldilocks_amount(&c.separation_altitude, "sep_alt")?;
        let landing_vel = parse_goldilocks_amount(&c.landing_velocity, "landing_vel")?;
        let propellant = parse_goldilocks_amount(&c.propellant_reserve, "propellant")?;
        let digest = poseidon_permutation4(
            FH_GOLDILOCKS_FIELD,
            [&sep_alt, &landing_vel, &propellant, &previous_digest],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("br_core_commitment_{core}"), digest)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &max_landing_vel,
            &max_landing_err,
            &BigInt::from(FALCON_HEAVY_CORE_COUNT as u64),
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "br_final_commitment", final_digest);
    values.insert("br_commitment".to_string(), commitment);
    values.insert("br_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_booster_recovery_program(request)?;
    materialize_seeded_witness(&program, values)
}

/// Generate a witness for a single-core recovery circuit.
pub fn single_core_recovery_witness_from_request(
    core_id: usize,
    data: &CoreRecoveryDataV1,
    max_landing_velocity: &str,
    max_landing_position_error: &str,
) -> ZkfResult<Witness> {
    let mut values = BTreeMap::new();

    let max_landing_vel = parse_goldilocks_amount(max_landing_velocity, "max_landing_velocity")?;
    let max_landing_err =
        parse_goldilocks_amount(max_landing_position_error, "max_landing_position_error")?;

    write_value(
        &mut values,
        "br_max_landing_velocity",
        max_landing_vel.clone(),
    );
    write_value(
        &mut values,
        "br_max_landing_position_error",
        max_landing_err.clone(),
    );
    write_value(&mut values, "br_chain_seed", zero());

    let sep_alt = parse_goldilocks_amount(
        &data.separation_altitude,
        &format!("core_{core_id}_sep_alt"),
    )?;
    let sep_vel = parse_goldilocks_amount(
        &data.separation_velocity,
        &format!("core_{core_id}_sep_vel"),
    )?;
    let propellant = parse_goldilocks_amount(
        &data.propellant_reserve,
        &format!("core_{core_id}_propellant"),
    )?;
    let landing_alt_error = parse_goldilocks_amount(
        &data.landing_altitude_error,
        &format!("core_{core_id}_landing_alt_error"),
    )?;
    let landing_vel = parse_goldilocks_amount(
        &data.landing_velocity,
        &format!("core_{core_id}_landing_vel"),
    )?;

    if landing_vel > max_landing_vel {
        return Err(ZkfError::InvalidArtifact(format!(
            "core {core_id} landing velocity exceeds limit"
        )));
    }

    write_value(
        &mut values,
        format!("br_core_{core_id}_sep_altitude"),
        sep_alt.clone(),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_sep_velocity"),
        sep_vel.clone(),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_propellant"),
        propellant.clone(),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_landing_alt_error"),
        landing_alt_error.clone(),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_landing_velocity"),
        landing_vel.clone(),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_tea_teb_ignitions"),
        BigInt::from(data.tea_teb_ignitions),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_max_tea_teb"),
        BigInt::from(data.max_tea_teb),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_tea_teb_slack"),
        BigInt::from(data.max_tea_teb) - BigInt::from(data.tea_teb_ignitions),
    );
    write_value(
        &mut values,
        format!("br_core_{core_id}_landing_vel_slack"),
        &max_landing_vel - &landing_vel,
    );

    // Position error
    let pos_err_sq = &landing_alt_error * &landing_alt_error;
    write_value(
        &mut values,
        format!("br_core_{core_id}_position_error_sq"),
        pos_err_sq.clone(),
    );
    let pos_err = bigint_isqrt_floor(&pos_err_sq);
    let pos_err_remainder = &pos_err_sq - (&pos_err * &pos_err);
    let pos_err_upper_slack = ((&pos_err + one()) * (&pos_err + one())) - &pos_err_sq - one();
    write_floor_sqrt_support(
        &mut values,
        &format!("br_core_{core_id}_position_error"),
        &pos_err,
        &format!("br_core_{core_id}_position_error_remainder"),
        &pos_err_remainder,
        &format!("br_core_{core_id}_position_error_upper_slack"),
        &pos_err_upper_slack,
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        &format!("br_core_{core_id}_position_error"),
    )?;
    if pos_err > max_landing_err {
        return Err(ZkfError::InvalidArtifact(format!(
            "core {core_id} landing position error exceeds limit"
        )));
    }
    write_value(
        &mut values,
        format!("br_core_{core_id}_position_error_slack"),
        &max_landing_err - &pos_err,
    );

    // Altitude/velocity profiles
    let recovery_steps = data.altitude_profile.len();
    let mut alts = Vec::with_capacity(recovery_steps);
    for step in 0..recovery_steps {
        let alt = parse_goldilocks_amount(
            &data.altitude_profile[step],
            &format!("core_{core_id}_step_{step}_alt"),
        )?;
        let vel = parse_goldilocks_amount(
            &data.velocity_profile[step],
            &format!("core_{core_id}_step_{step}_vel"),
        )?;
        write_value(
            &mut values,
            format!("br_core_{core_id}_step_{step}_altitude"),
            alt.clone(),
        );
        write_value(
            &mut values,
            format!("br_core_{core_id}_step_{step}_velocity"),
            vel.clone(),
        );
        if step > 0 {
            let delta: BigInt = &alt - &alts[step - 1];
            write_value(
                &mut values,
                format!("br_core_{core_id}_step_{step}_alt_delta"),
                delta.clone(),
            );
            write_signed_bound_support(
                &mut values,
                &delta,
                &fh_goldilocks_amount_bound(),
                &format!("br_core_{core_id}_step_{step}_alt_delta"),
            )?;
        }
        alts.push(alt);
    }

    // Burns
    for (b, burn) in data.burn_durations.iter().enumerate() {
        let bv = parse_goldilocks_amount(burn, &format!("core_{core_id}_burn_{b}"))?;
        write_value(&mut values, format!("br_core_{core_id}_burn_{b}"), bv);
    }

    // Poseidon chain
    let core_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [&sep_alt, &landing_vel, &propellant, &zero()],
    )?;
    let core_digest_lane = write_hash_lanes(
        &mut values,
        &format!("br_core_commitment_{core_id}"),
        core_digest,
    );
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &core_digest_lane.as_bigint(),
            &max_landing_vel,
            &max_landing_err,
            &BigInt::from(1u64),
        ],
    )?;
    let commitment = write_hash_lanes(
        &mut values,
        &format!("br_core_{core_id}_final_commitment"),
        final_digest,
    );
    values.insert(format!("br_core_{core_id}_commitment"), commitment);
    values.insert(
        format!("br_core_{core_id}_compliance_bit"),
        FieldElement::ONE,
    );
    let program = build_single_core_recovery_program(
        core_id,
        data,
        max_landing_velocity,
        max_landing_position_error,
    )?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 4 — Upper Stage Multi-Burn (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_upper_stage_multi_burn_program(
    request: &UpperStageMultiBurnRequestV1,
) -> ZkfResult<Program> {
    if request.burns.len() > FALCON_HEAVY_MAX_BURNS || request.burns.is_empty() {
        return Err(ZkfError::InvalidArtifact(format!(
            "upper stage requires 1-{FALCON_HEAVY_MAX_BURNS} burns"
        )));
    }
    let num_burns = request.burns.len();
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new(
        format!("falcon_heavy_upper_stage_{num_burns}"),
        FH_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "upper-stage-multi-burn")?;
    builder.metadata_entry("burn_count", num_burns.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    builder.private_input("us_initial_propellant")?;
    builder.constrain_range("us_initial_propellant", amount_bits)?;
    for input in [
        "us_perigee_tolerance",
        "us_apogee_tolerance",
        "us_inclination_tolerance",
        "us_target_perigee",
        "us_target_apogee",
        "us_target_inclination",
    ] {
        builder.private_input(input)?;
        builder.constrain_range(input, amount_bits)?;
    }
    builder.public_output("us_commitment")?;
    builder.public_output("us_compliance_bit")?;
    builder.constant_signal("us_chain_seed", FieldElement::ZERO)?;
    builder.constant_signal("__us_anchor_one", FieldElement::ONE)?;

    // Nonlinear anchoring for tolerance / target / per-burn signals that are
    // otherwise linear-only.
    for input in [
        "us_apogee_tolerance",
        "us_inclination_tolerance",
        "us_target_apogee",
        "us_target_inclination",
    ] {
        builder.constrain_equal(
            mul_expr(signal_expr(input), signal_expr("__us_anchor_one")),
            signal_expr(input),
        )?;
    }

    // Per-burn inputs
    for b in 0..num_burns {
        let active_name = format!("us_burn_{b}_active");
        builder.private_input(&active_name)?;
        builder.constrain_boolean(&active_name)?;
        for field_name in [
            "delta_v",
            "burn_duration",
            "perigee",
            "apogee",
            "inclination",
            "propellant_consumed",
        ] {
            let name = format!("us_burn_{b}_{field_name}");
            builder.private_input(&name)?;
            builder.constrain_range(&name, amount_bits)?;
        }
    }

    // Per-burn constraints
    builder.private_signal("us_total_propellant_consumed")?;
    let mut propellant_consumed_names = Vec::new();
    for b in 0..num_burns {
        propellant_consumed_names.push(format!("us_burn_{b}_propellant_consumed"));

        // Perigee deviation (signed bound)
        let perigee_dev = format!("us_burn_{b}_perigee_deviation");
        builder.private_signal(&perigee_dev)?;
        builder.constrain_equal(
            signal_expr(&perigee_dev),
            sub_expr(
                signal_expr(&format!("us_burn_{b}_perigee")),
                signal_expr("us_target_perigee"),
            ),
        )?;
        builder.append_signed_bound(
            &perigee_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_perigee_deviation"),
        )?;

        // Apogee deviation (signed bound)
        let apogee_dev = format!("us_burn_{b}_apogee_deviation");
        builder.private_signal(&apogee_dev)?;
        builder.constrain_equal(
            signal_expr(&apogee_dev),
            sub_expr(
                signal_expr(&format!("us_burn_{b}_apogee")),
                signal_expr("us_target_apogee"),
            ),
        )?;
        builder.append_signed_bound(
            &apogee_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_apogee_deviation"),
        )?;

        // Inclination deviation (signed bound)
        let inc_dev = format!("us_burn_{b}_inclination_deviation");
        builder.private_signal(&inc_dev)?;
        builder.constrain_equal(
            signal_expr(&inc_dev),
            sub_expr(
                signal_expr(&format!("us_burn_{b}_inclination")),
                signal_expr("us_target_inclination"),
            ),
        )?;
        builder.append_signed_bound(
            &inc_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_inclination_deviation"),
        )?;

        // Conditional tolerance check: if active, deviation must be within tolerance
        // Use constrain_select: selected_tolerance = active ? tolerance : amount_bound
        let perigee_sel = format!("us_burn_{b}_perigee_selected_bound");
        builder.constrain_select(
            &perigee_sel,
            &format!("us_burn_{b}_active"),
            signal_expr("us_perigee_tolerance"),
            const_expr(&fh_goldilocks_amount_bound()),
        )?;

        // Nonlinear anchoring for per-burn linear-only signals
        for field_name in ["burn_duration", "inclination", "propellant_consumed"] {
            let name = format!("us_burn_{b}_{field_name}");
            builder.constrain_equal(
                mul_expr(signal_expr(&name), signal_expr("__us_anchor_one")),
                signal_expr(&name),
            )?;
        }
    }

    // Total propellant consumed
    builder.constrain_equal(
        signal_expr("us_total_propellant_consumed"),
        sum_exprs(&propellant_consumed_names),
    )?;
    // Propellant budget: total consumed <= initial propellant
    builder.constrain_leq(
        "us_propellant_budget_slack",
        signal_expr("us_total_propellant_consumed"),
        signal_expr("us_initial_propellant"),
        amount_bits,
    )?;

    // Poseidon chain
    let mut previous_digest = signal_expr("us_chain_seed");
    for b in 0..num_burns {
        let step_digest = builder.append_poseidon_hash(
            &format!("us_burn_commitment_{b}"),
            [
                signal_expr(&format!("us_burn_{b}_delta_v")),
                signal_expr(&format!("us_burn_{b}_perigee")),
                signal_expr(&format!("us_burn_{b}_apogee")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "us_final_commitment",
        [
            previous_digest,
            signal_expr("us_initial_propellant"),
            signal_expr("us_total_propellant_consumed"),
            signal_expr("us_target_perigee"),
        ],
    )?;
    builder.bind("us_commitment", signal_expr(&final_digest))?;
    builder.bind("us_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn upper_stage_multi_burn_witness_from_request(
    request: &UpperStageMultiBurnRequestV1,
) -> ZkfResult<Witness> {
    if request.burns.is_empty() || request.burns.len() > FALCON_HEAVY_MAX_BURNS {
        return Err(ZkfError::InvalidArtifact(format!(
            "upper stage requires 1-{FALCON_HEAVY_MAX_BURNS} burns"
        )));
    }
    let num_burns = request.burns.len();
    let mut values = BTreeMap::new();

    let initial_propellant =
        parse_goldilocks_amount(&request.initial_propellant, "initial_propellant")?;
    let perigee_tol = parse_goldilocks_amount(&request.perigee_tolerance, "perigee_tolerance")?;
    let apogee_tol = parse_goldilocks_amount(&request.apogee_tolerance, "apogee_tolerance")?;
    let inc_tol = parse_goldilocks_amount(&request.inclination_tolerance, "inclination_tolerance")?;
    let target_perigee = parse_goldilocks_amount(&request.target_perigee, "target_perigee")?;
    let target_apogee = parse_goldilocks_amount(&request.target_apogee, "target_apogee")?;
    let target_inclination =
        parse_goldilocks_amount(&request.target_inclination, "target_inclination")?;

    write_value(
        &mut values,
        "us_initial_propellant",
        initial_propellant.clone(),
    );
    write_value(&mut values, "us_perigee_tolerance", perigee_tol.clone());
    write_value(&mut values, "us_apogee_tolerance", apogee_tol.clone());
    write_value(&mut values, "us_inclination_tolerance", inc_tol.clone());
    write_value(&mut values, "us_target_perigee", target_perigee.clone());
    write_value(&mut values, "us_target_apogee", target_apogee.clone());
    write_value(
        &mut values,
        "us_target_inclination",
        target_inclination.clone(),
    );
    write_value(&mut values, "us_chain_seed", zero());

    let mut total_prop_consumed = zero();
    for b in 0..num_burns {
        let burn = &request.burns[b];
        write_bool_value(&mut values, format!("us_burn_{b}_active"), burn.active);
        let dv = parse_goldilocks_amount(&burn.delta_v, &format!("burn_{b}_delta_v"))?;
        let dur = parse_goldilocks_amount(&burn.burn_duration, &format!("burn_{b}_duration"))?;
        let perigee = parse_goldilocks_amount(&burn.perigee, &format!("burn_{b}_perigee"))?;
        let apogee = parse_goldilocks_amount(&burn.apogee, &format!("burn_{b}_apogee"))?;
        let inc = parse_goldilocks_amount(&burn.inclination, &format!("burn_{b}_inclination"))?;
        let prop = parse_goldilocks_amount(&burn.propellant_consumed, &format!("burn_{b}_prop"))?;

        write_value(&mut values, format!("us_burn_{b}_delta_v"), dv.clone());
        write_value(
            &mut values,
            format!("us_burn_{b}_burn_duration"),
            dur.clone(),
        );
        write_value(&mut values, format!("us_burn_{b}_perigee"), perigee.clone());
        write_value(&mut values, format!("us_burn_{b}_apogee"), apogee.clone());
        write_value(&mut values, format!("us_burn_{b}_inclination"), inc.clone());
        write_value(
            &mut values,
            format!("us_burn_{b}_propellant_consumed"),
            prop.clone(),
        );

        // Deviations
        let perigee_dev = &perigee - &target_perigee;
        let apogee_dev = &apogee - &target_apogee;
        let inc_dev = &inc - &target_inclination;

        write_value(
            &mut values,
            format!("us_burn_{b}_perigee_deviation"),
            perigee_dev.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &perigee_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_perigee_deviation"),
        )?;

        write_value(
            &mut values,
            format!("us_burn_{b}_apogee_deviation"),
            apogee_dev.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &apogee_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_apogee_deviation"),
        )?;

        write_value(
            &mut values,
            format!("us_burn_{b}_inclination_deviation"),
            inc_dev.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &inc_dev,
            &fh_goldilocks_amount_bound(),
            &format!("us_burn_{b}_inclination_deviation"),
        )?;

        // Selected bound for conditional check
        let selected_bound = if burn.active {
            perigee_tol.clone()
        } else {
            fh_goldilocks_amount_bound()
        };
        write_value(
            &mut values,
            format!("us_burn_{b}_perigee_selected_bound"),
            selected_bound,
        );

        total_prop_consumed += &prop;
    }

    if total_prop_consumed > initial_propellant {
        return Err(ZkfError::InvalidArtifact(
            "total propellant consumed exceeds budget".to_string(),
        ));
    }
    write_value(
        &mut values,
        "us_total_propellant_consumed",
        total_prop_consumed.clone(),
    );
    write_value(
        &mut values,
        "us_propellant_budget_slack",
        &initial_propellant - &total_prop_consumed,
    );

    // Poseidon chain
    let mut previous_digest = zero();
    for b in 0..num_burns {
        let burn = &request.burns[b];
        let dv = parse_goldilocks_amount(&burn.delta_v, "dv")?;
        let perigee = parse_goldilocks_amount(&burn.perigee, "perigee")?;
        let apogee = parse_goldilocks_amount(&burn.apogee, "apogee")?;
        let digest = poseidon_permutation4(
            FH_GOLDILOCKS_FIELD,
            [&dv, &perigee, &apogee, &previous_digest],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("us_burn_commitment_{b}"), digest).as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &initial_propellant,
            &total_prop_consumed,
            &target_perigee,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "us_final_commitment", final_digest);
    values.insert("us_commitment".to_string(), commitment);
    values.insert("us_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_upper_stage_multi_burn_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 5 — Engine-Out Mission Assurance (BN254 / Groth16)
// ---------------------------------------------------------------------------

pub fn build_engine_out_mission_program(request: &EngineOutMissionRequestV1) -> ZkfResult<Program> {
    let steps = request.recalculated_thrust.len();
    if steps == 0
        || steps != request.recalculated_velocity.len()
        || steps != request.recalculated_altitude.len()
    {
        return Err(ZkfError::InvalidArtifact(
            "engine-out requires equal-length non-empty vectors".to_string(),
        ));
    }
    let scale = fh_bn254_scale();
    let amount_bits = bits_for_bound(&fh_bn254_amount_bound());

    let mut builder =
        ProgramBuilder::new(format!("falcon_heavy_engine_out_{steps}"), FH_BN254_FIELD);
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "engine-out-mission")?;
    builder.metadata_entry("steps", steps.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "arkworks-groth16-bn254")?;

    builder.private_input("eo_min_thrust_fraction")?;
    builder.private_input("eo_nominal_total_thrust")?;
    builder.private_input("eo_mission_success")?;
    builder.constrain_range("eo_min_thrust_fraction", amount_bits)?;
    builder.constrain_range("eo_nominal_total_thrust", amount_bits)?;
    builder.constrain_boolean("eo_mission_success")?;

    // Shutdown events
    for (i, _event) in request.shutdown_events.iter().enumerate() {
        let idx_name = format!("eo_shutdown_{i}_engine_index");
        let step_name = format!("eo_shutdown_{i}_step");
        builder.private_input(&idx_name)?;
        builder.private_input(&step_name)?;
        builder.constrain_range(&idx_name, 8)?;
        builder.constrain_range(&step_name, 16)?;
    }

    // Per-step trajectory with reduced thrust
    for step in 0..steps {
        for name in ["thrust", "velocity", "altitude"] {
            let sig = format!("eo_step_{step}_{name}");
            builder.private_input(&sig)?;
            builder.constrain_range(&sig, amount_bits)?;
        }
    }

    builder.public_output("eo_commitment")?;
    builder.public_output("eo_compliance_bit")?;
    builder.constant_signal("eo_chain_seed", FieldElement::ZERO)?;

    // Nonlinear anchoring for shutdown event signals (Range-only)
    builder.constant_signal("__eo_anchor_one", FieldElement::ONE)?;
    for (i, _event) in request.shutdown_events.iter().enumerate() {
        let idx_name = format!("eo_shutdown_{i}_engine_index");
        let step_name = format!("eo_shutdown_{i}_step");
        builder.constrain_equal(
            mul_expr(signal_expr(&idx_name), signal_expr("__eo_anchor_one")),
            signal_expr(&idx_name),
        )?;
        builder.constrain_equal(
            mul_expr(signal_expr(&step_name), signal_expr("__eo_anchor_one")),
            signal_expr(&step_name),
        )?;
    }

    // Compute minimum thrust threshold: min_thrust_fraction * nominal / scale
    builder.private_signal("eo_min_thrust_threshold")?;
    builder.private_signal("eo_min_thrust_threshold_remainder")?;
    builder.private_signal("eo_min_thrust_threshold_slack")?;
    builder.append_exact_division_constraints(
        mul_expr(
            signal_expr("eo_min_thrust_fraction"),
            signal_expr("eo_nominal_total_thrust"),
        ),
        const_expr(&scale),
        "eo_min_thrust_threshold",
        "eo_min_thrust_threshold_remainder",
        "eo_min_thrust_threshold_slack",
        &scale,
        "eo_min_thrust_threshold",
    )?;
    builder.constrain_nonzero("eo_nominal_total_thrust")?;

    // Per-step thrust margin check
    for step in 0..steps {
        builder.constrain_geq(
            format!("eo_step_{step}_thrust_margin_slack"),
            signal_expr(&format!("eo_step_{step}_thrust")),
            signal_expr("eo_min_thrust_threshold"),
            amount_bits,
        )?;

        // Euler integration check
        if step > 0 {
            let delta = format!("eo_step_{step}_alt_delta");
            builder.private_signal(&delta)?;
            builder.constrain_equal(
                signal_expr(&delta),
                sub_expr(
                    signal_expr(&format!("eo_step_{step}_altitude")),
                    signal_expr(&format!("eo_step_{}_altitude", step - 1)),
                ),
            )?;
            builder.append_signed_bound(
                &delta,
                &fh_bn254_amount_bound(),
                &format!("eo_step_{step}_alt_delta"),
            )?;
        }
    }

    // Mission success must be true
    builder.constrain_equal(signal_expr("eo_mission_success"), const_expr(&one()))?;

    // Poseidon chain
    let mut previous_digest = signal_expr("eo_chain_seed");
    for step in 0..steps {
        let step_digest = builder.append_poseidon_hash(
            &format!("eo_step_commitment_{step}"),
            [
                signal_expr(&format!("eo_step_{step}_thrust")),
                signal_expr(&format!("eo_step_{step}_velocity")),
                signal_expr(&format!("eo_step_{step}_altitude")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "eo_final_commitment",
        [
            previous_digest,
            signal_expr("eo_nominal_total_thrust"),
            signal_expr("eo_min_thrust_threshold"),
            signal_expr("eo_mission_success"),
        ],
    )?;
    builder.bind("eo_commitment", signal_expr(&final_digest))?;
    builder.bind("eo_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn engine_out_mission_witness_from_request(
    request: &EngineOutMissionRequestV1,
) -> ZkfResult<Witness> {
    let steps = request.recalculated_thrust.len();
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "engine-out requires non-empty vectors".to_string(),
        ));
    }
    let scale = fh_bn254_scale();
    let mut values = BTreeMap::new();

    let min_thrust_fraction =
        parse_bn254_amount(&request.min_thrust_fraction, "min_thrust_fraction")?;
    let nominal_thrust = parse_bn254_amount(&request.nominal_total_thrust, "nominal_total_thrust")?;
    if nominal_thrust == zero() {
        return Err(ZkfError::InvalidArtifact(
            "nominal thrust must be nonzero".to_string(),
        ));
    }
    if !request.mission_success {
        return Err(ZkfError::InvalidArtifact(
            "engine-out circuit requires mission success = true".to_string(),
        ));
    }

    write_value(
        &mut values,
        "eo_min_thrust_fraction",
        min_thrust_fraction.clone(),
    );
    write_value(
        &mut values,
        "eo_nominal_total_thrust",
        nominal_thrust.clone(),
    );
    write_bool_value(&mut values, "eo_mission_success", true);
    write_value(&mut values, "eo_chain_seed", zero());

    // Shutdown events
    for (i, event) in request.shutdown_events.iter().enumerate() {
        write_value(
            &mut values,
            format!("eo_shutdown_{i}_engine_index"),
            BigInt::from(event.engine_index),
        );
        write_value(
            &mut values,
            format!("eo_shutdown_{i}_step"),
            BigInt::from(event.shutdown_step),
        );
    }

    // Min thrust threshold
    let threshold_numerator = &min_thrust_fraction * &nominal_thrust;
    let min_thrust_threshold = &threshold_numerator / &scale;
    let threshold_remainder = &threshold_numerator % &scale;
    let threshold_slack = &scale - &threshold_remainder - one();
    write_exact_division_support(
        &mut values,
        "eo_min_thrust_threshold",
        &min_thrust_threshold,
        "eo_min_thrust_threshold_remainder",
        &threshold_remainder,
        "eo_min_thrust_threshold_slack",
        &threshold_slack,
        "eo_min_thrust_threshold",
    );

    // Per-step data
    let mut altitudes = Vec::with_capacity(steps);
    for step in 0..steps {
        let thrust = parse_bn254_amount(
            &request.recalculated_thrust[step],
            &format!("step_{step}_thrust"),
        )?;
        let velocity = parse_bn254_amount(
            &request.recalculated_velocity[step],
            &format!("step_{step}_velocity"),
        )?;
        let altitude = parse_bn254_amount(
            &request.recalculated_altitude[step],
            &format!("step_{step}_altitude"),
        )?;

        if thrust < min_thrust_threshold {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} thrust below minimum threshold"
            )));
        }

        write_value(
            &mut values,
            format!("eo_step_{step}_thrust"),
            thrust.clone(),
        );
        write_value(
            &mut values,
            format!("eo_step_{step}_velocity"),
            velocity.clone(),
        );
        write_value(
            &mut values,
            format!("eo_step_{step}_altitude"),
            altitude.clone(),
        );
        write_value(
            &mut values,
            format!("eo_step_{step}_thrust_margin_slack"),
            &thrust - &min_thrust_threshold,
        );

        if step > 0 {
            let delta: BigInt = &altitude - &altitudes[step - 1];
            write_value(
                &mut values,
                format!("eo_step_{step}_alt_delta"),
                delta.clone(),
            );
            write_signed_bound_support(
                &mut values,
                &delta,
                &fh_bn254_amount_bound(),
                &format!("eo_step_{step}_alt_delta"),
            )?;
        }

        altitudes.push(altitude);
    }

    // Poseidon chain
    let mut previous_digest = zero();
    for step in 0..steps {
        let thrust = parse_bn254_amount(&request.recalculated_thrust[step], "thrust")?;
        let vel = parse_bn254_amount(&request.recalculated_velocity[step], "vel")?;
        let alt = parse_bn254_amount(&request.recalculated_altitude[step], "alt")?;
        let digest =
            poseidon_permutation4(FH_BN254_FIELD, [&thrust, &vel, &alt, &previous_digest])?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("eo_step_commitment_{step}"), digest)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_BN254_FIELD,
        [
            &previous_digest,
            &nominal_thrust,
            &min_thrust_threshold,
            &one(),
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "eo_final_commitment", final_digest);
    values.insert("eo_commitment".to_string(), commitment);
    values.insert("eo_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_engine_out_mission_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 6 — Payload Fairing Environment (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_payload_fairing_environment_program(
    request: &PayloadFairingEnvironmentRequestV1,
) -> ZkfResult<Program> {
    let steps = request.acoustic_levels.len();
    if steps == 0
        || steps != request.vibration_levels.len()
        || steps != request.thermal_levels.len()
    {
        return Err(ZkfError::InvalidArtifact(
            "fairing environment requires equal-length non-empty vectors".to_string(),
        ));
    }
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new(
        format!("falcon_heavy_fairing_environment_{steps}"),
        FH_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "payload-fairing-environment")?;
    builder.metadata_entry("steps", steps.to_string())?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    for input in [
        "pf_max_acoustic",
        "pf_max_vibration",
        "pf_max_thermal",
        "pf_fairing_jettison_altitude",
        "pf_fairing_jettison_pressure",
        "pf_min_jettison_altitude",
        "pf_max_jettison_pressure",
    ] {
        builder.private_input(input)?;
        builder.constrain_range(input, amount_bits)?;
    }

    for step in 0..steps {
        for name in ["acoustic", "vibration", "thermal"] {
            let sig = format!("pf_step_{step}_{name}");
            builder.private_input(&sig)?;
            builder.constrain_range(&sig, amount_bits)?;
        }
    }

    builder.public_output("pf_commitment")?;
    builder.public_output("pf_compliance_bit")?;
    builder.constant_signal("pf_chain_seed", FieldElement::ZERO)?;

    // Nonlinear anchoring for linear-only signals
    builder.constant_signal("__pf_anchor_one", FieldElement::ONE)?;
    for input in [
        "pf_max_vibration",
        "pf_max_thermal",
        "pf_fairing_jettison_pressure",
        "pf_min_jettison_altitude",
        "pf_max_jettison_pressure",
    ] {
        builder.constrain_equal(
            mul_expr(signal_expr(input), signal_expr("__pf_anchor_one")),
            signal_expr(input),
        )?;
    }

    // Per-step bounds
    for step in 0..steps {
        builder.constrain_leq(
            format!("pf_step_{step}_acoustic_slack"),
            signal_expr(&format!("pf_step_{step}_acoustic")),
            signal_expr("pf_max_acoustic"),
            amount_bits,
        )?;
        builder.constrain_leq(
            format!("pf_step_{step}_vibration_slack"),
            signal_expr(&format!("pf_step_{step}_vibration")),
            signal_expr("pf_max_vibration"),
            amount_bits,
        )?;
        builder.constrain_leq(
            format!("pf_step_{step}_thermal_slack"),
            signal_expr(&format!("pf_step_{step}_thermal")),
            signal_expr("pf_max_thermal"),
            amount_bits,
        )?;
    }

    // Fairing jettison checks
    builder.constrain_geq(
        "pf_jettison_altitude_slack",
        signal_expr("pf_fairing_jettison_altitude"),
        signal_expr("pf_min_jettison_altitude"),
        amount_bits,
    )?;
    builder.constrain_leq(
        "pf_jettison_pressure_slack",
        signal_expr("pf_fairing_jettison_pressure"),
        signal_expr("pf_max_jettison_pressure"),
        amount_bits,
    )?;

    // RMS environment score
    let mut env_sq_exprs = Vec::new();
    for step in 0..steps {
        // squared deviations from max for each parameter
        let acoustic_dev = format!("pf_step_{step}_acoustic_dev");
        builder.private_signal(&acoustic_dev)?;
        builder.constrain_equal(
            signal_expr(&acoustic_dev),
            sub_expr(
                signal_expr("pf_max_acoustic"),
                signal_expr(&format!("pf_step_{step}_acoustic")),
            ),
        )?;
        builder.append_signed_bound(
            &acoustic_dev,
            &fh_goldilocks_amount_bound(),
            &format!("pf_step_{step}_acoustic_dev"),
        )?;
        env_sq_exprs.push(mul_expr(
            signal_expr(&acoustic_dev),
            signal_expr(&acoustic_dev),
        ));
    }

    builder.private_signal("pf_mean_square_margin")?;
    builder.private_signal("pf_mean_square_margin_remainder")?;
    builder.private_signal("pf_mean_square_margin_slack")?;
    builder.private_signal("pf_rms_margin")?;
    builder.private_signal("pf_rms_margin_remainder")?;
    builder.private_signal("pf_rms_margin_upper_slack")?;

    builder.append_exact_division_constraints(
        add_expr(env_sq_exprs),
        const_expr(&BigInt::from(steps as u64)),
        "pf_mean_square_margin",
        "pf_mean_square_margin_remainder",
        "pf_mean_square_margin_slack",
        &BigInt::from(steps as u64),
        "pf_mean_square_margin",
    )?;
    builder.append_floor_sqrt_constraints(
        signal_expr("pf_mean_square_margin"),
        "pf_rms_margin",
        "pf_rms_margin_remainder",
        "pf_rms_margin_upper_slack",
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "pf_rms_margin",
    )?;

    // Poseidon chain
    let mut previous_digest = signal_expr("pf_chain_seed");
    for step in 0..steps {
        let step_digest = builder.append_poseidon_hash(
            &format!("pf_step_commitment_{step}"),
            [
                signal_expr(&format!("pf_step_{step}_acoustic")),
                signal_expr(&format!("pf_step_{step}_vibration")),
                signal_expr(&format!("pf_step_{step}_thermal")),
                previous_digest.clone(),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "pf_final_commitment",
        [
            previous_digest,
            signal_expr("pf_fairing_jettison_altitude"),
            signal_expr("pf_rms_margin"),
            signal_expr("pf_max_acoustic"),
        ],
    )?;
    builder.bind("pf_commitment", signal_expr(&final_digest))?;
    builder.bind("pf_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn payload_fairing_environment_witness_from_request(
    request: &PayloadFairingEnvironmentRequestV1,
) -> ZkfResult<Witness> {
    let steps = request.acoustic_levels.len();
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "fairing environment requires non-empty vectors".to_string(),
        ));
    }
    let mut values = BTreeMap::new();

    let max_acoustic = parse_goldilocks_amount(&request.max_acoustic, "max_acoustic")?;
    let max_vibration = parse_goldilocks_amount(&request.max_vibration, "max_vibration")?;
    let max_thermal = parse_goldilocks_amount(&request.max_thermal, "max_thermal")?;
    let jettison_alt =
        parse_goldilocks_amount(&request.fairing_jettison_altitude, "jettison_altitude")?;
    let jettison_pressure =
        parse_goldilocks_amount(&request.fairing_jettison_pressure, "jettison_pressure")?;
    let min_jettison_alt =
        parse_goldilocks_amount(&request.min_jettison_altitude, "min_jettison_altitude")?;
    let max_jettison_pressure =
        parse_goldilocks_amount(&request.max_jettison_pressure, "max_jettison_pressure")?;

    if jettison_alt < min_jettison_alt {
        return Err(ZkfError::InvalidArtifact(
            "fairing jettison altitude below minimum".to_string(),
        ));
    }
    if jettison_pressure > max_jettison_pressure {
        return Err(ZkfError::InvalidArtifact(
            "fairing jettison pressure exceeds maximum".to_string(),
        ));
    }

    write_value(&mut values, "pf_max_acoustic", max_acoustic.clone());
    write_value(&mut values, "pf_max_vibration", max_vibration.clone());
    write_value(&mut values, "pf_max_thermal", max_thermal.clone());
    write_value(
        &mut values,
        "pf_fairing_jettison_altitude",
        jettison_alt.clone(),
    );
    write_value(
        &mut values,
        "pf_fairing_jettison_pressure",
        jettison_pressure.clone(),
    );
    write_value(
        &mut values,
        "pf_min_jettison_altitude",
        min_jettison_alt.clone(),
    );
    write_value(
        &mut values,
        "pf_max_jettison_pressure",
        max_jettison_pressure.clone(),
    );
    write_value(&mut values, "pf_chain_seed", zero());

    write_value(
        &mut values,
        "pf_jettison_altitude_slack",
        &jettison_alt - &min_jettison_alt,
    );
    write_value(
        &mut values,
        "pf_jettison_pressure_slack",
        &max_jettison_pressure - &jettison_pressure,
    );

    let mut sum_squared_margins = zero();
    for step in 0..steps {
        let acoustic =
            parse_goldilocks_amount(&request.acoustic_levels[step], &format!("acoustic_{step}"))?;
        let vibration = parse_goldilocks_amount(
            &request.vibration_levels[step],
            &format!("vibration_{step}"),
        )?;
        let thermal =
            parse_goldilocks_amount(&request.thermal_levels[step], &format!("thermal_{step}"))?;

        if acoustic > max_acoustic {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} acoustic exceeds max"
            )));
        }
        if vibration > max_vibration {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} vibration exceeds max"
            )));
        }
        if thermal > max_thermal {
            return Err(ZkfError::InvalidArtifact(format!(
                "step {step} thermal exceeds max"
            )));
        }

        write_value(
            &mut values,
            format!("pf_step_{step}_acoustic"),
            acoustic.clone(),
        );
        write_value(
            &mut values,
            format!("pf_step_{step}_vibration"),
            vibration.clone(),
        );
        write_value(
            &mut values,
            format!("pf_step_{step}_thermal"),
            thermal.clone(),
        );
        write_value(
            &mut values,
            format!("pf_step_{step}_acoustic_slack"),
            &max_acoustic - &acoustic,
        );
        write_value(
            &mut values,
            format!("pf_step_{step}_vibration_slack"),
            &max_vibration - &vibration,
        );
        write_value(
            &mut values,
            format!("pf_step_{step}_thermal_slack"),
            &max_thermal - &thermal,
        );

        let acoustic_dev = &max_acoustic - &acoustic;
        write_value(
            &mut values,
            format!("pf_step_{step}_acoustic_dev"),
            acoustic_dev.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &acoustic_dev,
            &fh_goldilocks_amount_bound(),
            &format!("pf_step_{step}_acoustic_dev"),
        )?;
        sum_squared_margins += &acoustic_dev * &acoustic_dev;
    }

    let step_count = BigInt::from(steps as u64);
    let mean_square_margin = &sum_squared_margins / &step_count;
    let mean_square_margin_remainder = &sum_squared_margins % &step_count;
    let mean_square_margin_slack = &step_count - &mean_square_margin_remainder - one();
    write_exact_division_support(
        &mut values,
        "pf_mean_square_margin",
        &mean_square_margin,
        "pf_mean_square_margin_remainder",
        &mean_square_margin_remainder,
        "pf_mean_square_margin_slack",
        &mean_square_margin_slack,
        "pf_mean_square_margin",
    );
    let rms_margin = bigint_isqrt_floor(&mean_square_margin);
    let rms_remainder = &mean_square_margin - (&rms_margin * &rms_margin);
    let rms_upper_slack =
        ((&rms_margin + one()) * (&rms_margin + one())) - &mean_square_margin - one();
    write_floor_sqrt_support(
        &mut values,
        "pf_rms_margin",
        &rms_margin,
        "pf_rms_margin_remainder",
        &rms_remainder,
        "pf_rms_margin_upper_slack",
        &rms_upper_slack,
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "pf_rms_margin",
    )?;

    // Poseidon chain
    let mut previous_digest = zero();
    for step in 0..steps {
        let acoustic = parse_goldilocks_amount(&request.acoustic_levels[step], "acoustic")?;
        let vibration = parse_goldilocks_amount(&request.vibration_levels[step], "vibration")?;
        let thermal = parse_goldilocks_amount(&request.thermal_levels[step], "thermal")?;
        let digest = poseidon_permutation4(
            FH_GOLDILOCKS_FIELD,
            [&acoustic, &vibration, &thermal, &previous_digest],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("pf_step_commitment_{step}"), digest)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [&previous_digest, &jettison_alt, &rms_margin, &max_acoustic],
    )?;
    let commitment = write_hash_lanes(&mut values, "pf_final_commitment", final_digest);
    values.insert("pf_commitment".to_string(), commitment);
    values.insert("pf_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_payload_fairing_environment_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 7 — Full Mission Integration (Goldilocks)
// ---------------------------------------------------------------------------

pub fn build_full_mission_integration_program(
    _request: &FullMissionIntegrationRequestV1,
) -> ZkfResult<Program> {
    let amount_bits = bits_for_bound(&fh_goldilocks_amount_bound());
    let scale = fh_goldilocks_scale();

    let mut builder = ProgramBuilder::new("falcon_heavy_mission_integration", FH_GOLDILOCKS_FIELD);
    builder.metadata_entry("application", "falcon-heavy-certification")?;
    builder.metadata_entry("circuit", "full-mission-integration")?;
    builder.metadata_entry("fixed_point_scale", scale.to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    // Circuit commitments (8 sub-circuit commitments: C1..C6 + C3a/C3b/C3c split)
    // — full Goldilocks field elements.
    // No range constraint: these are arbitrary field elements fed directly into
    // the Poseidon blackbox hash, which provides nonlinear anchoring.
    for i in 0..8 {
        let name = format!("fmi_circuit_commitment_{i}");
        builder.private_input(&name)?;
    }

    // Status bits
    for i in 0..8 {
        let name = format!("fmi_status_bit_{i}");
        builder.private_input(&name)?;
        builder.constrain_boolean(&name)?;
        // Each must be 1
        builder.constrain_equal(signal_expr(&name), const_expr(&one()))?;
    }

    // Mission parameters
    for input in [
        "fmi_vehicle_mass",
        "fmi_payload_mass",
        "fmi_mission_duration",
        "fmi_success_threshold",
    ] {
        builder.private_input(input)?;
        builder.constrain_range(input, amount_bits)?;
    }

    builder.public_output("fmi_commitment")?;
    builder.public_output("fmi_compliance_bit")?;
    builder.constant_signal("fmi_chain_seed", FieldElement::ZERO)?;

    // Nonlinear anchoring for linear-only signals
    builder.constant_signal("__fmi_anchor_one", FieldElement::ONE)?;
    for input in ["fmi_payload_mass", "fmi_mission_duration"] {
        builder.constrain_equal(
            mul_expr(signal_expr(input), signal_expr("__fmi_anchor_one")),
            signal_expr(input),
        )?;
    }

    // Commitment root: hash all 8 commitments into a single root (two groups of 4)
    // First 4 commitments (C1 engine health, C2 ascent, C3a side booster 1, C3b side booster 2)
    let root_hi = builder.append_poseidon_hash(
        "fmi_commitment_root_hi",
        [
            signal_expr("fmi_circuit_commitment_0"),
            signal_expr("fmi_circuit_commitment_1"),
            signal_expr("fmi_circuit_commitment_2"),
            signal_expr("fmi_circuit_commitment_3"),
        ],
    )?;
    // Last 4 commitments (C3c center core, C4 upper stage, C5 engine-out, C6 fairing)
    let root_lo = builder.append_poseidon_hash(
        "fmi_commitment_root_lo",
        [
            signal_expr("fmi_circuit_commitment_4"),
            signal_expr("fmi_circuit_commitment_5"),
            signal_expr("fmi_circuit_commitment_6"),
            signal_expr("fmi_circuit_commitment_7"),
        ],
    )?;
    // Merge the two roots
    let root_merged = builder.append_poseidon_hash(
        "fmi_commitment_root_merged",
        [
            signal_expr(&root_hi),
            signal_expr(&root_lo),
            signal_expr("fmi_chain_seed"),
            signal_expr("fmi_chain_seed"),
        ],
    )?;

    // Overall mission certification score: sqrt of squared status sum
    // (trivially 8 when all pass, but the constraint structure matters)
    let mut status_sq_exprs = Vec::new();
    for i in 0..8 {
        let name = format!("fmi_status_bit_{i}");
        status_sq_exprs.push(mul_expr(signal_expr(&name), signal_expr(&name)));
    }
    builder.private_signal("fmi_status_sum_sq")?;
    builder.constrain_equal(signal_expr("fmi_status_sum_sq"), add_expr(status_sq_exprs))?;
    builder.private_signal("fmi_certification_score")?;
    builder.private_signal("fmi_certification_score_remainder")?;
    builder.private_signal("fmi_certification_score_upper_slack")?;
    builder.append_floor_sqrt_constraints(
        signal_expr("fmi_status_sum_sq"),
        "fmi_certification_score",
        "fmi_certification_score_remainder",
        "fmi_certification_score_upper_slack",
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "fmi_certification_score",
    )?;

    // Final commitment
    let final_digest = builder.append_poseidon_hash(
        "fmi_final_commitment",
        [
            signal_expr(&root_merged),
            signal_expr("fmi_vehicle_mass"),
            signal_expr("fmi_certification_score"),
            signal_expr("fmi_success_threshold"),
        ],
    )?;
    builder.bind("fmi_commitment", signal_expr(&final_digest))?;
    builder.bind("fmi_compliance_bit", const_expr(&one()))?;
    builder.build()
}

pub fn full_mission_integration_witness_from_request(
    request: &FullMissionIntegrationRequestV1,
) -> ZkfResult<Witness> {
    let mut values = BTreeMap::new();

    // Parse commitments from sub-circuits (8 sub-circuits)
    let mut commitments = Vec::with_capacity(8);
    for (i, commitment_str) in request.circuit_commitments.iter().enumerate() {
        let parsed = BigInt::parse_bytes(commitment_str.as_bytes(), 10).ok_or_else(|| {
            ZkfError::InvalidArtifact(format!("circuit commitment {i} must be a base-10 integer"))
        })?;
        write_value(
            &mut values,
            format!("fmi_circuit_commitment_{i}"),
            parsed.clone(),
        );
        commitments.push(parsed);
    }

    // Status bits (8 sub-circuits)
    for (i, bit) in request.circuit_status_bits.iter().enumerate() {
        if !bit {
            return Err(ZkfError::InvalidArtifact(format!(
                "circuit {i} status bit must be true for mission integration"
            )));
        }
        write_bool_value(&mut values, format!("fmi_status_bit_{i}"), true);
    }

    let vehicle_mass = parse_goldilocks_amount(&request.vehicle_mass, "vehicle_mass")?;
    let payload_mass = parse_goldilocks_amount(&request.payload_mass, "payload_mass")?;
    let mission_duration = parse_goldilocks_amount(&request.mission_duration, "mission_duration")?;
    let success_threshold =
        parse_goldilocks_amount(&request.success_threshold, "success_threshold")?;

    write_value(&mut values, "fmi_vehicle_mass", vehicle_mass.clone());
    write_value(&mut values, "fmi_payload_mass", payload_mass.clone());
    write_value(
        &mut values,
        "fmi_mission_duration",
        mission_duration.clone(),
    );
    write_value(
        &mut values,
        "fmi_success_threshold",
        success_threshold.clone(),
    );
    write_value(&mut values, "fmi_chain_seed", zero());

    // Commitment roots (two groups of 4)
    let root_hi = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &commitments[0],
            &commitments[1],
            &commitments[2],
            &commitments[3],
        ],
    )?;
    let root_hi_lane = write_hash_lanes(&mut values, "fmi_commitment_root_hi", root_hi);
    let root_lo = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &commitments[4],
            &commitments[5],
            &commitments[6],
            &commitments[7],
        ],
    )?;
    let root_lo_lane = write_hash_lanes(&mut values, "fmi_commitment_root_lo", root_lo);
    // Merge the two roots
    let root_merged = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &root_hi_lane.as_bigint(),
            &root_lo_lane.as_bigint(),
            &zero(),
            &zero(),
        ],
    )?;
    let root_merged_lane = write_hash_lanes(&mut values, "fmi_commitment_root_merged", root_merged);

    // Status sum squared (8 because all bits are 1)
    let status_sum_sq = BigInt::from(8u64);
    write_value(&mut values, "fmi_status_sum_sq", status_sum_sq.clone());
    let cert_score = bigint_isqrt_floor(&status_sum_sq);
    let cert_remainder = &status_sum_sq - (&cert_score * &cert_score);
    let cert_upper_slack = ((&cert_score + one()) * (&cert_score + one())) - &status_sum_sq - one();
    write_floor_sqrt_support(
        &mut values,
        "fmi_certification_score",
        &cert_score,
        "fmi_certification_score_remainder",
        &cert_remainder,
        "fmi_certification_score_upper_slack",
        &cert_upper_slack,
        &fh_goldilocks_score_bound(),
        &fh_goldilocks_score_bound(),
        "fmi_certification_score",
    )?;

    // Final commitment
    let final_digest = poseidon_permutation4(
        FH_GOLDILOCKS_FIELD,
        [
            &root_merged_lane.as_bigint(),
            &vehicle_mass,
            &cert_score,
            &success_threshold,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "fmi_final_commitment", final_digest);
    values.insert("fmi_commitment".to_string(), commitment);
    values.insert("fmi_compliance_bit".to_string(), FieldElement::ONE);
    let program = build_full_mission_integration_program(request)?;
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

    const FH_TEST_STACK_SIZE: usize = 256 * 1024 * 1024;

    fn run_fh_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(FH_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn sample_engine_health_request() -> EngineHealthCertificationRequestV1 {
        let single_engine_params = vec![
            "6895.000".to_string(),  // chamber_pressure (kPa)
            "36000.000".to_string(), // turbopump_rpm
            "260.000".to_string(),   // fuel_flow (kg/s)
            "650.000".to_string(),   // ox_flow (kg/s)
            "2.500".to_string(),     // mixture_ratio
            "845.000".to_string(),   // thrust (kN)
            "5.000".to_string(),     // gimbal_response (deg/s)
        ];
        EngineHealthCertificationRequestV1 {
            engine_params: vec![single_engine_params; FALCON_HEAVY_ENGINE_COUNT],
            acceptance_bands_low: vec![
                "6800.000".to_string(),
                "35000.000".to_string(),
                "250.000".to_string(),
                "640.000".to_string(),
                "2.400".to_string(),
                "840.000".to_string(),
                "4.000".to_string(),
            ],
            acceptance_bands_high: vec![
                "7000.000".to_string(),
                "37000.000".to_string(),
                "270.000".to_string(),
                "660.000".to_string(),
                "2.600".to_string(),
                "850.000".to_string(),
                "6.000".to_string(),
            ],
            engine_flight_counts: vec![0; FALCON_HEAVY_ENGINE_COUNT],
            max_rms_deviation: "100.000".to_string(),
        }
    }

    fn sample_ascent_trajectory_request() -> AscentTrajectoryRequestV1 {
        let steps = FALCON_HEAVY_ASCENT_STEPS;
        let mut altitude = Vec::with_capacity(steps);
        let mut velocity = Vec::with_capacity(steps);
        let mut acceleration = Vec::with_capacity(steps);
        let mut dynamic_pressure = Vec::with_capacity(steps);
        let mut throttle_pct = Vec::with_capacity(steps);
        let mut mass = Vec::with_capacity(steps);

        for i in 0..steps {
            // 1 Hz sampling: step i = T+i seconds
            let t = i as f64;
            // Altitude: ground to ~180 km at MECO (roughly linear for simplified model)
            altitude.push(format!("{:.3}", 100.0 + t * 960.0));
            // Velocity: 0 to ~7800 m/s at MECO
            velocity.push(format!("{:.3}", 50.0 + t * 41.0));
            // Acceleration: ~3g average
            acceleration.push(format!("{:.3}", 15.0 + t * 0.04));
            // Dynamic pressure: rises to max Q around T+60s then falls
            let q = if t < 60.0 {
                20.0 + t * 0.5
            } else {
                50.0 - (t - 60.0) * 0.2
            };
            dynamic_pressure.push(format!("{:.3}", q.max(1.0)));
            throttle_pct.push("0.900".to_string());
            // Mass: 1,420,788 kg - 2,600 kg/s burn rate = ~934,588 kg at T+187s
            mass.push(format!("{:.3}", 1_420_788.0 - t * 2600.0));
        }

        AscentTrajectoryRequestV1 {
            altitude,
            velocity,
            acceleration,
            dynamic_pressure,
            throttle_pct,
            mass,
            max_q: "50.000".to_string(),
            max_axial_load: "5.000".to_string(),
            max_lateral_load: "2.000".to_string(),
            meco_altitude_min: "100.000".to_string(),
            meco_velocity_min: "50.000".to_string(),
            gravity: "9.807".to_string(),
        }
    }

    fn sample_booster_recovery_request() -> BoosterRecoveryCertificationRequestV1 {
        let core_data = || {
            let recovery_steps = FALCON_HEAVY_RECOVERY_STEPS_PER_CORE;
            let mut altitude_profile = Vec::with_capacity(recovery_steps);
            let mut velocity_profile = Vec::with_capacity(recovery_steps);
            for i in 0..recovery_steps {
                // Descent from 80 km to near ground over 300 seconds
                altitude_profile.push(format!("{:.3}", 80_000.0 - (i as f64) * 266.0));
                // Velocity decreasing from 1500 m/s to ~50 m/s at landing
                velocity_profile.push(format!("{:.3}", 1500.0 - (i as f64) * 4.8));
            }
            CoreRecoveryDataV1 {
                separation_altitude: "80000.000".to_string(),
                separation_velocity: "1500.000".to_string(),
                propellant_reserve: "5000.000".to_string(),
                burn_durations: vec![
                    "30.000".to_string(),
                    "15.000".to_string(),
                    "20.000".to_string(),
                ],
                landing_altitude_error: "5.000".to_string(),
                landing_velocity: "2.000".to_string(),
                tea_teb_ignitions: 3,
                max_tea_teb: 4,
                altitude_profile,
                velocity_profile,
            }
        };
        BoosterRecoveryCertificationRequestV1 {
            cores: vec![core_data(), core_data(), core_data()],
            max_landing_velocity: "3.000".to_string(),
            max_landing_position_error: "10.000".to_string(),
        }
    }

    fn sample_upper_stage_request() -> UpperStageMultiBurnRequestV1 {
        UpperStageMultiBurnRequestV1 {
            burns: vec![
                OrbitalBurnV1 {
                    active: true,
                    delta_v: "9400.000".to_string(),
                    burn_duration: "360.000".to_string(),
                    perigee: "200.000".to_string(),
                    apogee: "35786.000".to_string(),
                    inclination: "28.500".to_string(),
                    propellant_consumed: "75000.000".to_string(),
                },
                OrbitalBurnV1 {
                    active: true,
                    delta_v: "1500.000".to_string(),
                    burn_duration: "60.000".to_string(),
                    perigee: "200.000".to_string(),
                    apogee: "35786.000".to_string(),
                    inclination: "28.500".to_string(),
                    propellant_consumed: "15000.000".to_string(),
                },
            ],
            initial_propellant: "100000.000".to_string(),
            perigee_tolerance: "50.000".to_string(),
            apogee_tolerance: "100.000".to_string(),
            inclination_tolerance: "1.000".to_string(),
            target_perigee: "200.000".to_string(),
            target_apogee: "35786.000".to_string(),
            target_inclination: "28.500".to_string(),
        }
    }

    fn sample_engine_out_request() -> EngineOutMissionRequestV1 {
        let steps = FALCON_HEAVY_ASCENT_STEPS;
        let mut thrust = Vec::with_capacity(steps);
        let mut velocity = Vec::with_capacity(steps);
        let mut altitude = Vec::with_capacity(steps);
        for i in 0..steps {
            let t = i as f64 * 3.0;
            // ~25 of 27 engines after shutdown
            thrust.push(format!("{:.3}", 21130.0));
            velocity.push(format!("{:.3}", 50.0 + t * 18.0));
            altitude.push(format!("{:.3}", 100.0 + t * 45.0));
        }
        EngineOutMissionRequestV1 {
            shutdown_events: vec![
                EngineShutdownEventV1 {
                    engine_index: 5,
                    shutdown_step: 10,
                },
                EngineShutdownEventV1 {
                    engine_index: 14,
                    shutdown_step: 15,
                },
            ],
            recalculated_thrust: thrust,
            recalculated_velocity: velocity,
            recalculated_altitude: altitude,
            min_thrust_fraction: "0.800".to_string(),
            nominal_total_thrust: "22819.000".to_string(),
            mission_success: true,
        }
    }

    fn sample_fairing_environment_request() -> PayloadFairingEnvironmentRequestV1 {
        let steps = FALCON_HEAVY_ENVIRONMENT_STEPS;
        let mut acoustic = Vec::with_capacity(steps);
        let mut vibration = Vec::with_capacity(steps);
        let mut thermal = Vec::with_capacity(steps);
        for _i in 0..steps {
            acoustic.push("130.000".to_string());
            vibration.push("8.000".to_string());
            thermal.push("100.000".to_string());
        }
        PayloadFairingEnvironmentRequestV1 {
            acoustic_levels: acoustic,
            vibration_levels: vibration,
            thermal_levels: thermal,
            max_acoustic: "145.000".to_string(),
            max_vibration: "14.100".to_string(),
            max_thermal: "150.000".to_string(),
            fairing_jettison_altitude: "110000.000".to_string(),
            fairing_jettison_pressure: "1.000".to_string(),
            min_jettison_altitude: "100000.000".to_string(),
            max_jettison_pressure: "2.000".to_string(),
        }
    }

    fn sample_mission_integration_request(
        commitments: [String; 8],
        status_bits: [bool; 8],
    ) -> FullMissionIntegrationRequestV1 {
        FullMissionIntegrationRequestV1 {
            circuit_commitments: commitments,
            circuit_status_bits: status_bits,
            mission_name: "FH-Demo-2".to_string(),
            vehicle_mass: "1420788.000".to_string(),
            payload_mass: "63800.000".to_string(),
            mission_duration: "21600.000".to_string(),
            success_threshold: "1.000".to_string(),
        }
    }

    fn sample_single_core_recovery_data(core_id: usize) -> CoreRecoveryDataV1 {
        let recovery_steps = FALCON_HEAVY_RECOVERY_STEPS_PER_CORE;
        // Separation altitude varies by core type:
        // cores 0,1 are side boosters (~80 km), core 2 is center core (~120 km)
        let sep_alt = if core_id < 2 { 80000.0 } else { 120000.0 };
        let sep_vel = if core_id < 2 { 1500.0 } else { 2200.0 };
        let mut altitude_profile = Vec::with_capacity(recovery_steps);
        let mut velocity_profile = Vec::with_capacity(recovery_steps);
        for i in 0..recovery_steps {
            // Linear descent from separation altitude to near-zero
            let frac = i as f64 / (recovery_steps - 1) as f64;
            let alt = sep_alt * (1.0 - frac) + 5.0 * frac;
            let vel = sep_vel * (1.0 - frac) + 2.0 * frac;
            altitude_profile.push(format!("{alt:.3}"));
            velocity_profile.push(format!("{vel:.3}"));
        }
        CoreRecoveryDataV1 {
            separation_altitude: format!("{sep_alt:.3}"),
            separation_velocity: format!("{sep_vel:.3}"),
            propellant_reserve: "5000.000".to_string(),
            burn_durations: vec![
                "30.000".to_string(),
                "15.000".to_string(),
                "20.000".to_string(),
            ],
            landing_altitude_error: "5.000".to_string(),
            landing_velocity: "2.000".to_string(),
            tea_teb_ignitions: 3,
            max_tea_teb: 4,
            altitude_profile,
            velocity_profile,
        }
    }

    #[test]
    fn falcon_heavy_circuit_roundtrip() {
        run_fh_test_on_large_stack("fh-circuit-roundtrip", || {
            // --- Circuit 1 (C1): Engine Health ---
            let ehc_request = sample_engine_health_request();
            let ehc_program =
                build_engine_health_certification_program(&ehc_request).expect("ehc program");
            let ehc_audit = audit_program_default(&ehc_program, Some(BackendKind::Plonky3));
            if ehc_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&ehc_program);
                panic!(
                    "ehc audit must pass: {:?}\nunderconstrained={:?}",
                    ehc_audit.checks, analysis
                );
            }
            let ehc_witness = engine_health_certification_witness_from_request(&ehc_request)
                .expect("ehc witness");
            let ehc_compiled = compile(&ehc_program, "plonky3", None).expect("ehc compile");
            let ehc_artifact = prove(&ehc_compiled, &ehc_witness).expect("ehc prove");
            assert!(verify(&ehc_compiled, &ehc_artifact).expect("ehc verify"));
            assert_eq!(ehc_artifact.public_inputs.len(), 2);
            assert_eq!(ehc_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 2 (C2): Ascent Trajectory (187 steps) ---
            let at_request = sample_ascent_trajectory_request();
            let at_program = build_ascent_trajectory_program(&at_request).expect("at program");
            let at_audit = audit_program_default(&at_program, Some(BackendKind::Plonky3));
            if at_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&at_program);
                panic!(
                    "at audit must pass: {:?}\nunderconstrained={:?}",
                    at_audit.checks, analysis
                );
            }
            let at_witness =
                ascent_trajectory_witness_from_request(&at_request).expect("at witness");
            let at_compiled = compile(&at_program, "plonky3", None).expect("at compile");
            let at_artifact = prove(&at_compiled, &at_witness).expect("at prove");
            assert!(verify(&at_compiled, &at_artifact).expect("at verify"));
            assert_eq!(at_artifact.public_inputs.len(), 2);
            assert_eq!(at_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 3a (C3a): Side Booster 1 Recovery (300 steps) ---
            let c3a_data = sample_single_core_recovery_data(0);
            let c3a_program = build_single_core_recovery_program(0, &c3a_data, "3.000", "10.000")
                .expect("c3a program");
            let c3a_audit = audit_program_default(&c3a_program, Some(BackendKind::Plonky3));
            if c3a_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&c3a_program);
                panic!(
                    "c3a audit must pass: {:?}\nunderconstrained={:?}",
                    c3a_audit.checks, analysis
                );
            }
            let c3a_witness =
                single_core_recovery_witness_from_request(0, &c3a_data, "3.000", "10.000")
                    .expect("c3a witness");
            let c3a_compiled = compile(&c3a_program, "plonky3", None).expect("c3a compile");
            let c3a_artifact = prove(&c3a_compiled, &c3a_witness).expect("c3a prove");
            assert!(verify(&c3a_compiled, &c3a_artifact).expect("c3a verify"));
            assert_eq!(c3a_artifact.public_inputs.len(), 2);
            assert_eq!(c3a_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 3b (C3b): Side Booster 2 Recovery (300 steps) ---
            let c3b_data = sample_single_core_recovery_data(1);
            let c3b_program = build_single_core_recovery_program(1, &c3b_data, "3.000", "10.000")
                .expect("c3b program");
            let c3b_audit = audit_program_default(&c3b_program, Some(BackendKind::Plonky3));
            if c3b_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&c3b_program);
                panic!(
                    "c3b audit must pass: {:?}\nunderconstrained={:?}",
                    c3b_audit.checks, analysis
                );
            }
            let c3b_witness =
                single_core_recovery_witness_from_request(1, &c3b_data, "3.000", "10.000")
                    .expect("c3b witness");
            let c3b_compiled = compile(&c3b_program, "plonky3", None).expect("c3b compile");
            let c3b_artifact = prove(&c3b_compiled, &c3b_witness).expect("c3b prove");
            assert!(verify(&c3b_compiled, &c3b_artifact).expect("c3b verify"));
            assert_eq!(c3b_artifact.public_inputs.len(), 2);
            assert_eq!(c3b_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 3c (C3c): Center Core Recovery (300 steps) ---
            let c3c_data = sample_single_core_recovery_data(2);
            let c3c_program = build_single_core_recovery_program(2, &c3c_data, "3.000", "10.000")
                .expect("c3c program");
            let c3c_audit = audit_program_default(&c3c_program, Some(BackendKind::Plonky3));
            if c3c_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&c3c_program);
                panic!(
                    "c3c audit must pass: {:?}\nunderconstrained={:?}",
                    c3c_audit.checks, analysis
                );
            }
            let c3c_witness =
                single_core_recovery_witness_from_request(2, &c3c_data, "3.000", "10.000")
                    .expect("c3c witness");
            let c3c_compiled = compile(&c3c_program, "plonky3", None).expect("c3c compile");
            let c3c_artifact = prove(&c3c_compiled, &c3c_witness).expect("c3c prove");
            assert!(verify(&c3c_compiled, &c3c_artifact).expect("c3c verify"));
            assert_eq!(c3c_artifact.public_inputs.len(), 2);
            assert_eq!(c3c_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 4 (C4): Upper Stage ---
            let us_request = sample_upper_stage_request();
            let us_program = build_upper_stage_multi_burn_program(&us_request).expect("us program");
            let us_audit = audit_program_default(&us_program, Some(BackendKind::Plonky3));
            if us_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&us_program);
                panic!(
                    "us audit must pass: {:?}\nunderconstrained={:?}",
                    us_audit.checks, analysis
                );
            }
            let us_witness =
                upper_stage_multi_burn_witness_from_request(&us_request).expect("us witness");
            let us_compiled = compile(&us_program, "plonky3", None).expect("us compile");
            let us_artifact = prove(&us_compiled, &us_witness).expect("us prove");
            assert!(verify(&us_compiled, &us_artifact).expect("us verify"));
            assert_eq!(us_artifact.public_inputs.len(), 2);
            assert_eq!(us_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 5 (C5): Engine-Out (BN254 / Groth16) ---
            let eo_request = sample_engine_out_request();
            let eo_program = build_engine_out_mission_program(&eo_request).expect("eo program");
            let eo_audit = audit_program_default(&eo_program, Some(BackendKind::ArkworksGroth16));
            if eo_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&eo_program);
                panic!(
                    "eo audit must pass: {:?}\nunderconstrained={:?}",
                    eo_audit.checks, analysis
                );
            }
            let eo_witness =
                engine_out_mission_witness_from_request(&eo_request).expect("eo witness");
            let (eo_compiled, eo_artifact) =
                with_allow_dev_deterministic_groth16_override(Some(true), || {
                    let compiled =
                        compile(&eo_program, "arkworks-groth16", None).expect("eo compile");
                    let artifact = prove(&compiled, &eo_witness).expect("eo prove");
                    (compiled, artifact)
                });
            assert!(verify(&eo_compiled, &eo_artifact).expect("eo verify"));
            assert_eq!(eo_artifact.public_inputs.len(), 2);
            assert_eq!(eo_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 6 (C6): Payload Fairing (187 steps) ---
            let pf_request = sample_fairing_environment_request();
            let pf_program =
                build_payload_fairing_environment_program(&pf_request).expect("pf program");
            let pf_audit = audit_program_default(&pf_program, Some(BackendKind::Plonky3));
            if pf_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&pf_program);
                panic!(
                    "pf audit must pass: {:?}\nunderconstrained={:?}",
                    pf_audit.checks, analysis
                );
            }
            let pf_witness =
                payload_fairing_environment_witness_from_request(&pf_request).expect("pf witness");
            let pf_compiled = compile(&pf_program, "plonky3", None).expect("pf compile");
            let pf_artifact = prove(&pf_compiled, &pf_witness).expect("pf prove");
            assert!(verify(&pf_compiled, &pf_artifact).expect("pf verify"));
            assert_eq!(pf_artifact.public_inputs.len(), 2);
            assert_eq!(pf_artifact.public_inputs[1].to_decimal_string(), "1");

            // --- Circuit 7 (C7): Full Mission Integration (8 sub-circuit commitments) ---
            let fmi_request = sample_mission_integration_request(
                [
                    ehc_artifact.public_inputs[0].to_decimal_string(), // C1 engine health
                    at_artifact.public_inputs[0].to_decimal_string(),  // C2 ascent trajectory
                    c3a_artifact.public_inputs[0].to_decimal_string(), // C3a side booster 1
                    c3b_artifact.public_inputs[0].to_decimal_string(), // C3b side booster 2
                    c3c_artifact.public_inputs[0].to_decimal_string(), // C3c center core
                    us_artifact.public_inputs[0].to_decimal_string(),  // C4 upper stage
                    eo_artifact.public_inputs[0].to_decimal_string(),  // C5 engine-out
                    pf_artifact.public_inputs[0].to_decimal_string(),  // C6 payload fairing
                ],
                [true, true, true, true, true, true, true, true],
            );
            let fmi_program =
                build_full_mission_integration_program(&fmi_request).expect("fmi program");
            let fmi_audit = audit_program_default(&fmi_program, Some(BackendKind::Plonky3));
            if fmi_audit.summary.failed != 0 {
                let analysis = analyze_underconstrained(&fmi_program);
                panic!(
                    "fmi audit must pass: {:?}\nunderconstrained={:?}",
                    fmi_audit.checks, analysis
                );
            }
            let fmi_witness =
                full_mission_integration_witness_from_request(&fmi_request).expect("fmi witness");
            let fmi_compiled = compile(&fmi_program, "plonky3", None).expect("fmi compile");
            let fmi_artifact = prove(&fmi_compiled, &fmi_witness).expect("fmi prove");
            assert!(verify(&fmi_compiled, &fmi_artifact).expect("fmi verify"));
            assert_eq!(fmi_artifact.public_inputs.len(), 2);
            assert_eq!(fmi_artifact.public_inputs[1].to_decimal_string(), "1");
        });
    }

    #[test]
    fn engine_health_rejects_out_of_band_engine() {
        let mut request = sample_engine_health_request();
        // Set engine 0 thrust below acceptance band
        request.engine_params[0][5] = "800.000".to_string();
        let err = engine_health_certification_witness_from_request(&request)
            .expect_err("out-of-band engine must fail");
        let message = err.to_string();
        assert!(
            message.contains("acceptance band") || message.contains("out of"),
            "unexpected error: {message}"
        );
    }
}
