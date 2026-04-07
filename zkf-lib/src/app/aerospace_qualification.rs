#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Aerospace Qualification, Digital Thread, and Flight-Readiness Exchange
//!
//! Six zero-knowledge circuits proving aerospace supply-chain qualification
//! evidence without revealing proprietary data:
//!
//! 1. Component Thermal Qualification (Goldilocks/Plonky3, post-quantum)
//! 2. Vibration/Shock Qualification (Goldilocks/Plonky3)
//! 3. Lot Genealogy & Chain of Custody (BN254/Groth16, EVM-verifiable)
//! 4. Firmware Provenance (BN254/Groth16)
//! 5. Test Campaign Compliance (Goldilocks/Plonky3)
//! 6. Flight-Readiness Assembly (Goldilocks/Plonky3, integration circuit)

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
use zkf_core::{
    Expr, FieldElement, FieldId, Program, Witness, WitnessInputs, ZkfError, ZkfResult,
    generate_witness,
};

use super::builder::ProgramBuilder;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const AEROSPACE_QUALIFICATION_GOLDILOCKS_SCALE_DECIMALS: u32 = 3;
pub const AEROSPACE_QUALIFICATION_BN254_SCALE_DECIMALS: u32 = 18;
pub const AEROSPACE_QUALIFICATION_MAX_READINGS: usize = 256;
pub const AEROSPACE_QUALIFICATION_MAX_TESTS: usize = 64;
pub const AEROSPACE_QUALIFICATION_MAX_COMPONENTS: usize = 32;
pub const AEROSPACE_QUALIFICATION_MAX_HANDLERS: usize = 16;
pub const AEROSPACE_QUALIFICATION_SPECTRAL_BANDS: usize = 8;

const AQ_GOLDILOCKS_FIELD: FieldId = FieldId::Goldilocks;
const AQ_BN254_FIELD: FieldId = FieldId::Bn254;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentThermalQualificationRequestV1 {
    pub component_id: String,
    pub lot_id: String,
    pub temperature_readings: Vec<String>,
    pub duration_measurements: Vec<String>,
    pub cycle_count: u64,
    pub min_required_cycles: u64,
    pub temperature_upper_limit: String,
    pub temperature_lower_floor: String,
    pub required_duration: String,
    pub margin_threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VibrationShockQualificationRequestV1 {
    pub component_id: String,
    pub acceleration_readings: Vec<String>,
    pub spectral_density_readings: Vec<String>,
    pub spectral_density_limits: Vec<String>,
    pub shock_pulse_durations: Vec<String>,
    pub min_shock_duration: String,
    pub peak_g_limit: String,
    pub calibration_hash: String,
    pub approved_calibration_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LotGenealogyRequestV1 {
    pub source_lot_id: String,
    pub material_batch_certificate_hashes: Vec<String>,
    pub transformation_record_hashes: Vec<String>,
    pub inspection_stamp_hashes: Vec<String>,
    pub handler_signature_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirmwareProvenanceRequestV1 {
    pub firmware_binary_hash: String,
    pub approved_firmware_hash: String,
    pub build_toolchain_hash: String,
    pub approved_toolchain_hashes: Vec<String>,
    pub signing_key_fingerprint: String,
    pub approved_signing_keys: Vec<String>,
    pub version_major: u64,
    pub version_minor: u64,
    pub version_patch: u64,
    pub minimum_version_major: u64,
    pub minimum_version_minor: u64,
    pub minimum_version_patch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestCampaignComplianceRequestV1 {
    pub campaign_id: String,
    pub test_results: Vec<String>,
    pub test_thresholds: Vec<String>,
    pub operator_certification_hashes: Vec<String>,
    pub min_test_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlightReadinessAssemblyRequestV1 {
    pub mission_id: String,
    pub component_qualification_commitments: Vec<String>,
    pub approval_signature_hashes: Vec<String>,
    pub revocation_flags: Vec<bool>,
    pub required_approval_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AerospaceQualificationRunManifestV1 {
    pub run_id: String,
    pub thermal_qualification: ComponentThermalQualificationRequestV1,
    pub vibration_shock: VibrationShockQualificationRequestV1,
    pub lot_genealogy: LotGenealogyRequestV1,
    pub firmware_provenance: FirmwareProvenanceRequestV1,
    pub test_campaign: TestCampaignComplianceRequestV1,
    pub flight_readiness: FlightReadinessAssemblyRequestV1,
}

// ---------------------------------------------------------------------------
// Helpers (self-contained, mirrors SED pattern)
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

fn aq_goldilocks_scale() -> BigInt {
    fixed_scale(AEROSPACE_QUALIFICATION_GOLDILOCKS_SCALE_DECIMALS)
}

fn aq_goldilocks_amount_bound() -> BigInt {
    BigInt::from(1_000_000_000u64)
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
}

fn decimal_scaled(value: &str, decimals: u32) -> BigInt {
    fn digits_to_bigint(digits: &str) -> BigInt {
        digits
            .bytes()
            .filter(|digit| digit.is_ascii_digit())
            .fold(BigInt::from(0u8), |acc, digit| {
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
    if fraction_digits.len() > decimals as usize {
        fraction_digits.truncate(decimals as usize);
    }
    while fraction_digits.len() < decimals as usize {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * fixed_scale(decimals) + fraction_value;
    if negative { -scaled } else { scaled }
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

fn nonnegative_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_slack")
}

fn nonnegative_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_anchor")
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
    let parsed = decimal_scaled(value, AEROSPACE_QUALIFICATION_GOLDILOCKS_SCALE_DECIMALS);
    ensure_nonnegative_le(label, &parsed, &aq_goldilocks_amount_bound())?;
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

fn sum_exprs(names: &[String]) -> Expr {
    add_expr(names.iter().map(|name| signal_expr(name)).collect())
}

fn materialize_seeded_witness(program: &Program, values: WitnessInputs) -> ZkfResult<Witness> {
    generate_witness(program, &values)
}

// ---------------------------------------------------------------------------
// Circuit 1: Component Thermal Qualification (Goldilocks / Plonky3)
// ---------------------------------------------------------------------------

pub fn build_component_thermal_qualification_program(
    request: &ComponentThermalQualificationRequestV1,
) -> ZkfResult<Program> {
    validate_equal_lengths(
        "component thermal qualification",
        &[
            request.temperature_readings.len(),
            request.duration_measurements.len(),
        ],
    )?;
    let readings = request.temperature_readings.len();
    let amount_bits = bits_for_bound(&aq_goldilocks_amount_bound());
    let cycle_bits = 32u32;

    let mut builder = ProgramBuilder::new(
        format!("aerospace_qualification_thermal_{readings}"),
        AQ_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "component-thermal-qualification")?;
    builder.metadata_entry("readings", readings.to_string())?;
    builder.metadata_entry("fixed_point_scale", aq_goldilocks_scale().to_str_radix(10))?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut temp_names = Vec::with_capacity(readings);
    let mut dur_names = Vec::with_capacity(readings);
    for i in 0..readings {
        let temp = format!("ctq_temp_{i}");
        let dur = format!("ctq_dur_{i}");
        builder.private_input(&temp)?;
        builder.private_input(&dur)?;
        builder.constrain_range(&temp, amount_bits)?;
        builder.constrain_range(&dur, amount_bits)?;
        temp_names.push(temp);
        dur_names.push(dur);
    }

    builder.private_input("ctq_cycle_count")?;
    builder.private_input("ctq_min_required_cycles")?;
    builder.private_input("ctq_upper_limit")?;
    builder.private_input("ctq_lower_floor")?;
    builder.private_input("ctq_required_duration")?;
    builder.private_input("ctq_margin_threshold")?;
    builder.private_input("ctq_component_id")?;
    builder.private_input("ctq_lot_id")?;
    builder.constrain_range("ctq_cycle_count", cycle_bits)?;
    builder.constrain_range("ctq_min_required_cycles", cycle_bits)?;
    builder.constrain_range("ctq_upper_limit", amount_bits)?;
    builder.constrain_range("ctq_lower_floor", amount_bits)?;
    builder.constrain_range("ctq_required_duration", amount_bits)?;
    builder.constrain_range("ctq_margin_threshold", amount_bits)?;

    builder.public_output("ctq_qualification_commitment")?;
    builder.public_output("ctq_thermal_pass")?;
    builder.public_output("ctq_margin_adequate")?;
    builder.constant_signal("ctq_chain_seed", FieldElement::ZERO)?;

    // Max temperature via iterative pairwise max
    if readings == 1 {
        builder.private_signal("ctq_max_temp")?;
        builder.constrain_equal(signal_expr("ctq_max_temp"), signal_expr(&temp_names[0]))?;
        builder.append_nonnegative_bound(
            "ctq_max_temp",
            &aq_goldilocks_amount_bound(),
            "ctq_max_temp_bound",
        )?;
    } else {
        let mut prev = temp_names[0].clone();
        for i in 1..readings {
            let target = if i == readings - 1 {
                "ctq_max_temp".to_string()
            } else {
                format!("ctq_max_temp_partial_{i}")
            };
            append_pairwise_max_signal(
                &mut builder,
                &target,
                &prev,
                &temp_names[i],
                &aq_goldilocks_amount_bound(),
                &format!("ctq_max_temp_{i}"),
            )?;
            prev = target;
        }
    }

    // Max temp must be below upper limit
    builder.constrain_leq(
        "ctq_max_temp_below_limit_slack",
        signal_expr("ctq_max_temp"),
        signal_expr("ctq_upper_limit"),
        amount_bits,
    )?;

    // Each temp must be above lower floor
    for i in 0..readings {
        builder.constrain_geq(
            format!("ctq_temp_above_floor_slack_{i}"),
            signal_expr(&temp_names[i]),
            signal_expr("ctq_lower_floor"),
            amount_bits,
        )?;
    }

    // Each duration must meet required duration
    for i in 0..readings {
        builder.constrain_geq(
            format!("ctq_dur_meets_req_slack_{i}"),
            signal_expr(&dur_names[i]),
            signal_expr("ctq_required_duration"),
            amount_bits,
        )?;
    }

    // Cycle count >= min required
    builder.constrain_geq(
        "ctq_cycle_count_slack",
        signal_expr("ctq_cycle_count"),
        signal_expr("ctq_min_required_cycles"),
        cycle_bits,
    )?;

    // Margin computation: margin = (upper_limit - max_temp)
    // Margin adequate if margin >= margin_threshold
    builder.private_signal("ctq_margin")?;
    builder.constrain_equal(
        signal_expr("ctq_margin"),
        sub_expr(signal_expr("ctq_upper_limit"), signal_expr("ctq_max_temp")),
    )?;
    builder.append_nonnegative_bound(
        "ctq_margin",
        &aq_goldilocks_amount_bound(),
        "ctq_margin_bound",
    )?;
    builder.constrain_geq(
        "ctq_margin_adequate_slack",
        signal_expr("ctq_margin"),
        signal_expr("ctq_margin_threshold"),
        amount_bits,
    )?;

    // Poseidon commitment chain across readings
    let mut previous_digest = signal_expr("ctq_chain_seed");
    for i in 0..readings {
        let step_digest = builder.append_poseidon_hash(
            &format!("ctq_reading_commitment_{i}"),
            [
                signal_expr(&temp_names[i]),
                signal_expr(&dur_names[i]),
                previous_digest.clone(),
                signal_expr("ctq_component_id"),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    // Anchor linearly-used signals through Poseidon
    let anchor_digest = builder.append_poseidon_hash(
        "ctq_anchor_hash",
        [
            previous_digest,
            signal_expr("ctq_min_required_cycles"),
            signal_expr("ctq_required_duration"),
            signal_expr("ctq_lot_id"),
        ],
    )?;
    // Anchor remaining linear-only signals: upper_limit, lower_floor, margin_threshold
    let limits_anchor = builder.append_poseidon_hash(
        "ctq_limits_anchor",
        [
            signal_expr(&anchor_digest),
            signal_expr("ctq_upper_limit"),
            signal_expr("ctq_lower_floor"),
            signal_expr("ctq_margin_threshold"),
        ],
    )?;
    let final_digest = builder.append_poseidon_hash(
        "ctq_final_commitment",
        [
            signal_expr(&limits_anchor),
            signal_expr("ctq_cycle_count"),
            signal_expr("ctq_margin"),
            signal_expr("ctq_component_id"),
        ],
    )?;
    builder.bind("ctq_qualification_commitment", signal_expr(&final_digest))?;
    builder.bind("ctq_thermal_pass", const_expr(&one()))?;
    builder.bind("ctq_margin_adequate", const_expr(&one()))?;
    builder.build()
}

pub fn component_thermal_qualification_witness_from_request(
    request: &ComponentThermalQualificationRequestV1,
) -> ZkfResult<Witness> {
    validate_equal_lengths(
        "component thermal qualification",
        &[
            request.temperature_readings.len(),
            request.duration_measurements.len(),
        ],
    )?;
    let readings = request.temperature_readings.len();
    let mut values = BTreeMap::new();

    let temps: Vec<BigInt> = request
        .temperature_readings
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("temperature reading {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let durs: Vec<BigInt> = request
        .duration_measurements
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("duration measurement {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let cycle_count = BigInt::from(request.cycle_count);
    let min_required_cycles = BigInt::from(request.min_required_cycles);
    let upper_limit = parse_goldilocks_amount(&request.temperature_upper_limit, "upper limit")?;
    let lower_floor = parse_goldilocks_amount(&request.temperature_lower_floor, "lower floor")?;
    let required_duration =
        parse_goldilocks_amount(&request.required_duration, "required duration")?;
    let margin_threshold = parse_goldilocks_amount(&request.margin_threshold, "margin threshold")?;
    let component_id = parse_nonnegative_integer(&request.component_id, "component id")?;
    let lot_id = parse_nonnegative_integer(&request.lot_id, "lot id")?;

    for (i, v) in temps.iter().enumerate() {
        write_value(&mut values, format!("ctq_temp_{i}"), v.clone());
    }
    for (i, v) in durs.iter().enumerate() {
        write_value(&mut values, format!("ctq_dur_{i}"), v.clone());
    }
    write_value(&mut values, "ctq_cycle_count", cycle_count.clone());
    write_value(
        &mut values,
        "ctq_min_required_cycles",
        min_required_cycles.clone(),
    );
    write_value(&mut values, "ctq_upper_limit", upper_limit.clone());
    write_value(&mut values, "ctq_lower_floor", lower_floor.clone());
    write_value(
        &mut values,
        "ctq_required_duration",
        required_duration.clone(),
    );
    write_value(
        &mut values,
        "ctq_margin_threshold",
        margin_threshold.clone(),
    );
    write_value(&mut values, "ctq_component_id", component_id.clone());
    write_value(&mut values, "ctq_lot_id", lot_id.clone());
    write_value(&mut values, "ctq_chain_seed", zero());

    // Compute max temperature
    let mut max_temp = temps[0].clone();
    if readings == 1 {
        write_value(&mut values, "ctq_max_temp", max_temp.clone());
    } else {
        let mut prev_max = temps[0].clone();
        for i in 1..readings {
            let current_max = if prev_max >= temps[i] {
                prev_max.clone()
            } else {
                temps[i].clone()
            };
            let target = if i == readings - 1 {
                "ctq_max_temp".to_string()
            } else {
                format!("ctq_max_temp_partial_{i}")
            };
            // Write comparator support
            let geq = prev_max >= temps[i];
            write_bool_value(&mut values, format!("ctq_max_temp_{i}_geq_bit"), geq);
            let offset = positive_comparison_offset(&aq_goldilocks_amount_bound());
            let slack = comparator_slack(&prev_max, &temps[i], &offset);
            write_nonnegative_bound_support(
                &mut values,
                format!("ctq_max_temp_{i}_geq_slack"),
                &slack,
                &(&offset - one()),
                &format!("ctq_max_temp_{i}_comparator_slack"),
            )?;
            write_value(&mut values, &target, current_max.clone());
            prev_max = current_max;
        }
        max_temp = prev_max;
    }

    // Verify constraints hold
    if max_temp > upper_limit {
        return Err(ZkfError::InvalidArtifact(
            "max temperature exceeds upper limit".to_string(),
        ));
    }
    write_value(
        &mut values,
        "ctq_max_temp_below_limit_slack",
        &upper_limit - &max_temp,
    );

    for (i, temp) in temps.iter().enumerate() {
        if *temp < lower_floor {
            return Err(ZkfError::InvalidArtifact(format!(
                "temperature reading {i} below lower floor"
            )));
        }
        write_value(
            &mut values,
            format!("ctq_temp_above_floor_slack_{i}"),
            temp - &lower_floor,
        );
    }

    for (i, dur) in durs.iter().enumerate() {
        if *dur < required_duration {
            return Err(ZkfError::InvalidArtifact(format!(
                "duration measurement {i} below required duration"
            )));
        }
        write_value(
            &mut values,
            format!("ctq_dur_meets_req_slack_{i}"),
            dur - &required_duration,
        );
    }

    if cycle_count < min_required_cycles {
        return Err(ZkfError::InvalidArtifact(
            "cycle count below minimum required".to_string(),
        ));
    }
    write_value(
        &mut values,
        "ctq_cycle_count_slack",
        &cycle_count - &min_required_cycles,
    );

    let margin = &upper_limit - &max_temp;
    write_value(&mut values, "ctq_margin", margin.clone());

    if margin < margin_threshold {
        return Err(ZkfError::InvalidArtifact(
            "thermal margin below threshold".to_string(),
        ));
    }
    write_value(
        &mut values,
        "ctq_margin_adequate_slack",
        &margin - &margin_threshold,
    );

    // Poseidon commitment chain
    let mut previous_digest = zero();
    for i in 0..readings {
        let digest = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [&temps[i], &durs[i], &previous_digest, &component_id],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("ctq_reading_commitment_{i}"), digest)
                .as_bigint();
    }
    let anchor_digest = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &min_required_cycles,
            &required_duration,
            &lot_id,
        ],
    )?;
    let anchor_val = write_hash_lanes(&mut values, "ctq_anchor_hash", anchor_digest).as_bigint();
    // Anchor remaining linear-only signals: upper_limit, lower_floor, margin_threshold
    let limits_anchor_digest = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [&anchor_val, &upper_limit, &lower_floor, &margin_threshold],
    )?;
    let limits_anchor_val =
        write_hash_lanes(&mut values, "ctq_limits_anchor", limits_anchor_digest).as_bigint();
    let final_digest = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [&limits_anchor_val, &cycle_count, &margin, &component_id],
    )?;
    let commitment = write_hash_lanes(&mut values, "ctq_final_commitment", final_digest);
    values.insert("ctq_qualification_commitment".to_string(), commitment);
    values.insert("ctq_thermal_pass".to_string(), FieldElement::ONE);
    values.insert("ctq_margin_adequate".to_string(), FieldElement::ONE);

    let program = build_component_thermal_qualification_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 2: Vibration/Shock Qualification (Goldilocks / Plonky3)
// ---------------------------------------------------------------------------

pub fn build_vibration_shock_qualification_program(
    request: &VibrationShockQualificationRequestV1,
) -> ZkfResult<Program> {
    let accel_count = request.acceleration_readings.len();
    let spectral_count = request.spectral_density_readings.len();
    let shock_count = request.shock_pulse_durations.len();
    if accel_count == 0 || spectral_count == 0 || shock_count == 0 {
        return Err(ZkfError::InvalidArtifact(
            "vibration qualification requires at least one reading in each category".to_string(),
        ));
    }
    validate_equal_lengths(
        "vibration spectral bands",
        &[spectral_count, request.spectral_density_limits.len()],
    )?;
    let amount_bits = bits_for_bound(&aq_goldilocks_amount_bound());

    let mut builder = ProgramBuilder::new(
        format!("aerospace_qualification_vibration_{accel_count}_{spectral_count}_{shock_count}"),
        AQ_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "vibration-shock-qualification")?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut accel_names = Vec::with_capacity(accel_count);
    for i in 0..accel_count {
        let name = format!("vsq_accel_{i}");
        builder.private_input(&name)?;
        builder.constrain_range(&name, amount_bits)?;
        accel_names.push(name);
    }

    let mut spectral_names = Vec::with_capacity(spectral_count);
    let mut spectral_limit_names = Vec::with_capacity(spectral_count);
    for i in 0..spectral_count {
        let name = format!("vsq_spectral_{i}");
        let limit_name = format!("vsq_spectral_limit_{i}");
        builder.private_input(&name)?;
        builder.private_input(&limit_name)?;
        builder.constrain_range(&name, amount_bits)?;
        builder.constrain_range(&limit_name, amount_bits)?;
        spectral_names.push(name);
        spectral_limit_names.push(limit_name);
    }

    let mut shock_dur_names = Vec::with_capacity(shock_count);
    for i in 0..shock_count {
        let name = format!("vsq_shock_dur_{i}");
        builder.private_input(&name)?;
        builder.constrain_range(&name, amount_bits)?;
        shock_dur_names.push(name);
    }

    builder.private_input("vsq_min_shock_duration")?;
    builder.private_input("vsq_peak_g_limit")?;
    builder.private_input("vsq_calibration_hash")?;
    builder.private_input("vsq_approved_calibration_hash")?;
    builder.constrain_range("vsq_min_shock_duration", amount_bits)?;
    builder.constrain_range("vsq_peak_g_limit", amount_bits)?;

    builder.public_output("vsq_vibration_commitment")?;
    builder.public_output("vsq_vibration_pass")?;
    builder.public_output("vsq_spectral_compliance")?;
    builder.constant_signal("vsq_chain_seed", FieldElement::ZERO)?;

    // Peak g-force via iterative pairwise max
    if accel_count == 1 {
        builder.private_signal("vsq_peak_g")?;
        builder.constrain_equal(signal_expr("vsq_peak_g"), signal_expr(&accel_names[0]))?;
        builder.append_nonnegative_bound(
            "vsq_peak_g",
            &aq_goldilocks_amount_bound(),
            "vsq_peak_g_bound",
        )?;
    } else {
        let mut prev = accel_names[0].clone();
        for i in 1..accel_count {
            let target = if i == accel_count - 1 {
                "vsq_peak_g".to_string()
            } else {
                format!("vsq_peak_g_partial_{i}")
            };
            append_pairwise_max_signal(
                &mut builder,
                &target,
                &prev,
                &accel_names[i],
                &aq_goldilocks_amount_bound(),
                &format!("vsq_peak_g_{i}"),
            )?;
            prev = target;
        }
    }

    // Peak g <= limit
    builder.constrain_leq(
        "vsq_peak_g_slack",
        signal_expr("vsq_peak_g"),
        signal_expr("vsq_peak_g_limit"),
        amount_bits,
    )?;

    // Each spectral density <= its limit
    for i in 0..spectral_count {
        builder.constrain_leq(
            format!("vsq_spectral_slack_{i}"),
            signal_expr(&spectral_names[i]),
            signal_expr(&spectral_limit_names[i]),
            amount_bits,
        )?;
    }

    // Each shock duration >= min
    for i in 0..shock_count {
        builder.constrain_geq(
            format!("vsq_shock_dur_slack_{i}"),
            signal_expr(&shock_dur_names[i]),
            signal_expr("vsq_min_shock_duration"),
            amount_bits,
        )?;
    }

    // Calibration hash match
    builder.constrain_equal(
        signal_expr("vsq_calibration_hash"),
        signal_expr("vsq_approved_calibration_hash"),
    )?;

    // Boolean AND chain for spectral compliance
    if spectral_count == 1 {
        builder.private_signal("vsq_spectral_all_pass")?;
        builder.constrain_boolean("vsq_spectral_all_pass")?;
        builder.bind("vsq_spectral_all_pass", const_expr(&one()))?;
    } else {
        for i in 0..spectral_count {
            let bit = format!("vsq_spectral_pass_bit_{i}");
            builder.private_signal(&bit)?;
            builder.constrain_boolean(&bit)?;
            builder.bind(&bit, const_expr(&one()))?;
        }
        let mut prev = "vsq_spectral_pass_bit_0".to_string();
        for i in 1..spectral_count {
            let target = if i == spectral_count - 1 {
                "vsq_spectral_all_pass".to_string()
            } else {
                format!("vsq_spectral_and_{i}")
            };
            append_boolean_and(
                &mut builder,
                &target,
                &prev,
                &format!("vsq_spectral_pass_bit_{i}"),
            )?;
            prev = target;
        }
    }

    // Poseidon commitment chain
    let mut previous_digest = signal_expr("vsq_chain_seed");
    for i in 0..accel_count {
        let step_digest = builder.append_poseidon_hash(
            &format!("vsq_accel_commitment_{i}"),
            [
                signal_expr(&accel_names[i]),
                previous_digest.clone(),
                signal_expr("vsq_calibration_hash"),
                signal_expr("vsq_peak_g_limit"),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    // Anchor spectral limit signals (linear-only via constrain_leq) through Poseidon
    for i in 0..spectral_count {
        let spectral_anchor = builder.append_poseidon_hash(
            &format!("vsq_spectral_anchor_{i}"),
            [
                previous_digest.clone(),
                signal_expr(&spectral_limit_names[i]),
                signal_expr(&spectral_names[i]),
                signal_expr("vsq_min_shock_duration"),
            ],
        )?;
        previous_digest = signal_expr(&spectral_anchor);
    }
    // Anchor shock duration signals (linear-only via constrain_geq) through Poseidon
    for i in 0..shock_count {
        let shock_anchor = builder.append_poseidon_hash(
            &format!("vsq_shock_anchor_{i}"),
            [
                previous_digest.clone(),
                signal_expr(&shock_dur_names[i]),
                signal_expr("vsq_min_shock_duration"),
                signal_expr("vsq_calibration_hash"),
            ],
        )?;
        previous_digest = signal_expr(&shock_anchor);
    }
    let final_digest = builder.append_poseidon_hash(
        "vsq_final_commitment",
        [
            previous_digest,
            signal_expr("vsq_peak_g"),
            signal_expr("vsq_approved_calibration_hash"),
            signal_expr("vsq_min_shock_duration"),
        ],
    )?;
    builder.bind("vsq_vibration_commitment", signal_expr(&final_digest))?;
    builder.bind("vsq_vibration_pass", const_expr(&one()))?;
    builder.bind(
        "vsq_spectral_compliance",
        signal_expr("vsq_spectral_all_pass"),
    )?;
    builder.build()
}

pub fn vibration_shock_qualification_witness_from_request(
    request: &VibrationShockQualificationRequestV1,
) -> ZkfResult<Witness> {
    let accel_count = request.acceleration_readings.len();
    let spectral_count = request.spectral_density_readings.len();
    let _shock_count = request.shock_pulse_durations.len();
    validate_equal_lengths(
        "vibration spectral bands",
        &[spectral_count, request.spectral_density_limits.len()],
    )?;
    let mut values = BTreeMap::new();

    let accels: Vec<BigInt> = request
        .acceleration_readings
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("acceleration {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let spectrals: Vec<BigInt> = request
        .spectral_density_readings
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("spectral {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let spectral_limits: Vec<BigInt> = request
        .spectral_density_limits
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("spectral limit {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let shock_durs: Vec<BigInt> = request
        .shock_pulse_durations
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("shock duration {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let min_shock_dur = parse_goldilocks_amount(&request.min_shock_duration, "min shock duration")?;
    let peak_g_limit = parse_goldilocks_amount(&request.peak_g_limit, "peak g limit")?;
    let calibration_hash =
        parse_nonnegative_integer(&request.calibration_hash, "calibration hash")?;
    let approved_cal_hash = parse_nonnegative_integer(
        &request.approved_calibration_hash,
        "approved calibration hash",
    )?;

    for (i, v) in accels.iter().enumerate() {
        write_value(&mut values, format!("vsq_accel_{i}"), v.clone());
    }
    for (i, v) in spectrals.iter().enumerate() {
        write_value(&mut values, format!("vsq_spectral_{i}"), v.clone());
    }
    for (i, v) in spectral_limits.iter().enumerate() {
        write_value(&mut values, format!("vsq_spectral_limit_{i}"), v.clone());
    }
    for (i, v) in shock_durs.iter().enumerate() {
        write_value(&mut values, format!("vsq_shock_dur_{i}"), v.clone());
    }
    write_value(&mut values, "vsq_min_shock_duration", min_shock_dur.clone());
    write_value(&mut values, "vsq_peak_g_limit", peak_g_limit.clone());
    write_value(
        &mut values,
        "vsq_calibration_hash",
        calibration_hash.clone(),
    );
    write_value(
        &mut values,
        "vsq_approved_calibration_hash",
        approved_cal_hash.clone(),
    );
    write_value(&mut values, "vsq_chain_seed", zero());

    if calibration_hash != approved_cal_hash {
        return Err(ZkfError::InvalidArtifact(
            "calibration hash does not match approved hash".to_string(),
        ));
    }

    // Peak g-force
    let mut peak_g = accels[0].clone();
    if accel_count == 1 {
        write_value(&mut values, "vsq_peak_g", peak_g.clone());
    } else {
        let mut prev_max = accels[0].clone();
        for i in 1..accel_count {
            let current_max = std::cmp::max(prev_max.clone(), accels[i].clone());
            let target = if i == accel_count - 1 {
                "vsq_peak_g".to_string()
            } else {
                format!("vsq_peak_g_partial_{i}")
            };
            let geq = prev_max >= accels[i];
            write_bool_value(&mut values, format!("vsq_peak_g_{i}_geq_bit"), geq);
            let offset = positive_comparison_offset(&aq_goldilocks_amount_bound());
            let slack = comparator_slack(&prev_max, &accels[i], &offset);
            write_nonnegative_bound_support(
                &mut values,
                format!("vsq_peak_g_{i}_geq_slack"),
                &slack,
                &(&offset - one()),
                &format!("vsq_peak_g_{i}_comparator_slack"),
            )?;
            write_value(&mut values, &target, current_max.clone());
            prev_max = current_max;
        }
        peak_g = prev_max;
    }

    if peak_g > peak_g_limit {
        return Err(ZkfError::InvalidArtifact(
            "peak g-force exceeds limit".to_string(),
        ));
    }
    write_value(&mut values, "vsq_peak_g_slack", &peak_g_limit - &peak_g);

    for (i, (spectral, limit)) in spectrals.iter().zip(spectral_limits.iter()).enumerate() {
        if spectral > limit {
            return Err(ZkfError::InvalidArtifact(format!(
                "spectral density {i} exceeds limit"
            )));
        }
        write_value(
            &mut values,
            format!("vsq_spectral_slack_{i}"),
            limit - spectral,
        );
    }

    for (i, dur) in shock_durs.iter().enumerate() {
        if *dur < min_shock_dur {
            return Err(ZkfError::InvalidArtifact(format!(
                "shock pulse duration {i} below minimum"
            )));
        }
        write_value(
            &mut values,
            format!("vsq_shock_dur_slack_{i}"),
            dur - &min_shock_dur,
        );
    }

    // Spectral compliance bits
    if spectral_count == 1 {
        write_bool_value(&mut values, "vsq_spectral_all_pass", true);
    } else {
        for i in 0..spectral_count {
            write_bool_value(&mut values, format!("vsq_spectral_pass_bit_{i}"), true);
        }
        let prev_and = true;
        for i in 1..spectral_count {
            let target = if i == spectral_count - 1 {
                "vsq_spectral_all_pass".to_string()
            } else {
                format!("vsq_spectral_and_{i}")
            };
            write_bool_value(&mut values, &target, prev_and && true);
        }
    }

    // Poseidon commitment chain
    let mut previous_digest = zero();
    for i in 0..accel_count {
        let digest = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [
                &accels[i],
                &previous_digest,
                &calibration_hash,
                &peak_g_limit,
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("vsq_accel_commitment_{i}"), digest).as_bigint();
    }
    // Anchor spectral limit signals through Poseidon (matches circuit builder)
    for i in 0..spectral_count {
        let anchor_digest = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [
                &previous_digest,
                &spectral_limits[i],
                &spectrals[i],
                &min_shock_dur,
            ],
        )?;
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("vsq_spectral_anchor_{i}"),
            anchor_digest,
        )
        .as_bigint();
    }
    // Anchor shock duration signals through Poseidon (matches circuit builder)
    for i in 0..shock_durs.len() {
        let shock_anchor = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [
                &previous_digest,
                &shock_durs[i],
                &min_shock_dur,
                &calibration_hash,
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("vsq_shock_anchor_{i}"), shock_anchor)
                .as_bigint();
    }
    let final_digest = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &peak_g,
            &approved_cal_hash,
            &min_shock_dur,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "vsq_final_commitment", final_digest);
    values.insert("vsq_vibration_commitment".to_string(), commitment);
    values.insert("vsq_vibration_pass".to_string(), FieldElement::ONE);
    values.insert(
        "vsq_spectral_compliance".to_string(),
        values
            .get("vsq_spectral_all_pass")
            .cloned()
            .unwrap_or(FieldElement::ONE),
    );

    let program = build_vibration_shock_qualification_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 3: Lot Genealogy & Chain of Custody (BN254 / Groth16)
// ---------------------------------------------------------------------------

pub fn build_lot_genealogy_program(request: &LotGenealogyRequestV1) -> ZkfResult<Program> {
    let chain_len = request.handler_signature_hashes.len();
    if chain_len == 0 {
        return Err(ZkfError::InvalidArtifact(
            "lot genealogy requires at least one handler".to_string(),
        ));
    }
    validate_equal_lengths(
        "lot genealogy",
        &[
            request.material_batch_certificate_hashes.len(),
            request.transformation_record_hashes.len(),
            request.inspection_stamp_hashes.len(),
            chain_len,
        ],
    )?;

    let mut builder = ProgramBuilder::new(
        format!("aerospace_qualification_lot_genealogy_{chain_len}"),
        AQ_BN254_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "lot-genealogy")?;
    builder.metadata_entry("chain_length", chain_len.to_string())?;
    builder.metadata_entry("backend_expectation", "arkworks-groth16")?;

    builder.private_input("lg_source_lot_id")?;

    let mut batch_names = Vec::with_capacity(chain_len);
    let mut transform_names = Vec::with_capacity(chain_len);
    let mut inspection_names = Vec::with_capacity(chain_len);
    let mut handler_names = Vec::with_capacity(chain_len);
    for i in 0..chain_len {
        let batch = format!("lg_batch_cert_{i}");
        let transform = format!("lg_transform_{i}");
        let inspection = format!("lg_inspection_{i}");
        let handler = format!("lg_handler_{i}");
        builder.private_input(&batch)?;
        builder.private_input(&transform)?;
        builder.private_input(&inspection)?;
        builder.private_input(&handler)?;
        builder.constrain_nonzero(&handler)?;
        batch_names.push(batch);
        transform_names.push(transform);
        inspection_names.push(inspection);
        handler_names.push(handler);
    }

    builder.public_output("lg_lineage_commitment")?;
    builder.public_output("lg_lineage_intact")?;
    builder.public_output("lg_handler_count")?;

    // Poseidon hash chain from source lot through each link
    let mut previous_digest = signal_expr("lg_source_lot_id");
    for i in 0..chain_len {
        let step_digest = builder.append_poseidon_hash(
            &format!("lg_chain_{i}"),
            [
                previous_digest.clone(),
                signal_expr(&batch_names[i]),
                signal_expr(&transform_names[i]),
                signal_expr(&inspection_names[i]),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }

    builder.bind("lg_lineage_commitment", previous_digest)?;
    builder.bind("lg_lineage_intact", const_expr(&one()))?;
    builder.bind(
        "lg_handler_count",
        const_expr(&BigInt::from(chain_len as u64)),
    )?;
    builder.build()
}

pub fn lot_genealogy_witness_from_request(request: &LotGenealogyRequestV1) -> ZkfResult<Witness> {
    let chain_len = request.handler_signature_hashes.len();
    validate_equal_lengths(
        "lot genealogy",
        &[
            request.material_batch_certificate_hashes.len(),
            request.transformation_record_hashes.len(),
            request.inspection_stamp_hashes.len(),
            chain_len,
        ],
    )?;
    let mut values = BTreeMap::new();

    let source_lot_id = parse_nonnegative_integer(&request.source_lot_id, "source lot id")?;
    write_value(&mut values, "lg_source_lot_id", source_lot_id.clone());

    let mut batch_vals = Vec::with_capacity(chain_len);
    let mut transform_vals = Vec::with_capacity(chain_len);
    let mut inspection_vals = Vec::with_capacity(chain_len);
    let mut handler_vals = Vec::with_capacity(chain_len);
    for i in 0..chain_len {
        let b = parse_nonnegative_integer(
            &request.material_batch_certificate_hashes[i],
            &format!("batch cert {i}"),
        )?;
        let t = parse_nonnegative_integer(
            &request.transformation_record_hashes[i],
            &format!("transform {i}"),
        )?;
        let insp = parse_nonnegative_integer(
            &request.inspection_stamp_hashes[i],
            &format!("inspection {i}"),
        )?;
        let h = parse_nonnegative_integer(
            &request.handler_signature_hashes[i],
            &format!("handler {i}"),
        )?;
        if h == zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "handler signature hash {i} must be nonzero"
            )));
        }
        write_value(&mut values, format!("lg_batch_cert_{i}"), b.clone());
        write_value(&mut values, format!("lg_transform_{i}"), t.clone());
        write_value(&mut values, format!("lg_inspection_{i}"), insp.clone());
        write_value(&mut values, format!("lg_handler_{i}"), h.clone());
        batch_vals.push(b);
        transform_vals.push(t);
        inspection_vals.push(insp);
        handler_vals.push(h);
    }

    // Poseidon hash chain
    let mut previous_digest = source_lot_id;
    for i in 0..chain_len {
        let digest = poseidon_permutation4(
            AQ_BN254_FIELD,
            [
                &previous_digest,
                &batch_vals[i],
                &transform_vals[i],
                &inspection_vals[i],
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("lg_chain_{i}"), digest).as_bigint();
    }

    values.insert(
        "lg_lineage_commitment".to_string(),
        field_ref(&previous_digest),
    );
    values.insert("lg_lineage_intact".to_string(), FieldElement::ONE);
    values.insert(
        "lg_handler_count".to_string(),
        field(BigInt::from(chain_len as u64)),
    );

    let program = build_lot_genealogy_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 4: Firmware Provenance (BN254 / Groth16)
// ---------------------------------------------------------------------------

pub fn build_firmware_provenance_program(
    _request: &FirmwareProvenanceRequestV1,
) -> ZkfResult<Program> {
    let version_bits = 32u32;

    let mut builder = ProgramBuilder::new(
        "aerospace_qualification_firmware_provenance".to_string(),
        AQ_BN254_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "firmware-provenance")?;
    builder.metadata_entry("backend_expectation", "arkworks-groth16")?;

    builder.private_input("fp_firmware_hash")?;
    builder.private_input("fp_approved_hash")?;
    builder.private_input("fp_toolchain_hash")?;
    builder.private_input("fp_signing_key")?;
    builder.private_input("fp_version_encoded")?;
    builder.private_input("fp_min_version_encoded")?;
    builder.constrain_range("fp_version_encoded", version_bits)?;
    builder.constrain_range("fp_min_version_encoded", version_bits)?;

    builder.public_output("fp_provenance_commitment")?;
    builder.public_output("fp_approved_release")?;
    builder.public_output("fp_hash_matches")?;

    // Firmware hash must equal approved hash
    builder.constrain_equal(
        signal_expr("fp_firmware_hash"),
        signal_expr("fp_approved_hash"),
    )?;

    // Version must be >= minimum
    builder.constrain_geq(
        "fp_version_slack",
        signal_expr("fp_version_encoded"),
        signal_expr("fp_min_version_encoded"),
        version_bits,
    )?;

    // Poseidon commitment over all inputs
    let commitment_digest = builder.append_poseidon_hash(
        "fp_commitment_hash",
        [
            signal_expr("fp_firmware_hash"),
            signal_expr("fp_toolchain_hash"),
            signal_expr("fp_signing_key"),
            signal_expr("fp_version_encoded"),
        ],
    )?;
    // Anchor linear-only signals: fp_approved_hash, fp_min_version_encoded
    let anchor_digest = builder.append_poseidon_hash(
        "fp_anchor_hash",
        [
            signal_expr(&commitment_digest),
            signal_expr("fp_approved_hash"),
            signal_expr("fp_min_version_encoded"),
            signal_expr("fp_firmware_hash"),
        ],
    )?;

    builder.bind("fp_provenance_commitment", signal_expr(&anchor_digest))?;
    builder.bind("fp_approved_release", const_expr(&one()))?;
    builder.bind("fp_hash_matches", const_expr(&one()))?;
    builder.build()
}

pub fn firmware_provenance_witness_from_request(
    request: &FirmwareProvenanceRequestV1,
) -> ZkfResult<Witness> {
    let mut values = BTreeMap::new();

    let firmware_hash = parse_nonnegative_integer(&request.firmware_binary_hash, "firmware hash")?;
    let approved_hash =
        parse_nonnegative_integer(&request.approved_firmware_hash, "approved firmware hash")?;
    let toolchain_hash =
        parse_nonnegative_integer(&request.build_toolchain_hash, "toolchain hash")?;
    let signing_key = parse_nonnegative_integer(&request.signing_key_fingerprint, "signing key")?;

    if firmware_hash != approved_hash {
        return Err(ZkfError::InvalidArtifact(
            "firmware binary hash does not match approved hash".to_string(),
        ));
    }

    let version_encoded = BigInt::from(request.version_major) * BigInt::from(1_000_000u64)
        + BigInt::from(request.version_minor) * BigInt::from(1_000u64)
        + BigInt::from(request.version_patch);
    let min_version_encoded = BigInt::from(request.minimum_version_major)
        * BigInt::from(1_000_000u64)
        + BigInt::from(request.minimum_version_minor) * BigInt::from(1_000u64)
        + BigInt::from(request.minimum_version_patch);

    if version_encoded < min_version_encoded {
        return Err(ZkfError::InvalidArtifact(
            "firmware version below minimum required version".to_string(),
        ));
    }

    write_value(&mut values, "fp_firmware_hash", firmware_hash.clone());
    write_value(&mut values, "fp_approved_hash", approved_hash.clone());
    write_value(&mut values, "fp_toolchain_hash", toolchain_hash.clone());
    write_value(&mut values, "fp_signing_key", signing_key.clone());
    write_value(&mut values, "fp_version_encoded", version_encoded.clone());
    write_value(
        &mut values,
        "fp_min_version_encoded",
        min_version_encoded.clone(),
    );
    write_value(
        &mut values,
        "fp_version_slack",
        &version_encoded - &min_version_encoded,
    );

    let commitment_digest = poseidon_permutation4(
        AQ_BN254_FIELD,
        [
            &firmware_hash,
            &toolchain_hash,
            &signing_key,
            &version_encoded,
        ],
    )?;
    let commitment_val =
        write_hash_lanes(&mut values, "fp_commitment_hash", commitment_digest).as_bigint();
    // Anchor linear-only signals: fp_approved_hash, fp_min_version_encoded
    let anchor_digest = poseidon_permutation4(
        AQ_BN254_FIELD,
        [
            &commitment_val,
            &approved_hash,
            &min_version_encoded,
            &firmware_hash,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "fp_anchor_hash", anchor_digest);

    values.insert("fp_provenance_commitment".to_string(), commitment);
    values.insert("fp_approved_release".to_string(), FieldElement::ONE);
    values.insert("fp_hash_matches".to_string(), FieldElement::ONE);

    let program = build_firmware_provenance_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 5: Test Campaign Compliance (Goldilocks / Plonky3)
// ---------------------------------------------------------------------------

pub fn build_test_campaign_compliance_program(
    request: &TestCampaignComplianceRequestV1,
) -> ZkfResult<Program> {
    validate_equal_lengths(
        "test campaign",
        &[request.test_results.len(), request.test_thresholds.len()],
    )?;
    let test_count = request.test_results.len();
    let operator_count = request.operator_certification_hashes.len();
    if test_count == 0 || operator_count == 0 {
        return Err(ZkfError::InvalidArtifact(
            "test campaign requires at least one test and one operator".to_string(),
        ));
    }
    let amount_bits = bits_for_bound(&aq_goldilocks_amount_bound());
    let count_bits = 32u32;

    let mut builder = ProgramBuilder::new(
        format!("aerospace_qualification_test_campaign_{test_count}"),
        AQ_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "test-campaign-compliance")?;
    builder.metadata_entry("test_count", test_count.to_string())?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    let mut result_names = Vec::with_capacity(test_count);
    let mut threshold_names = Vec::with_capacity(test_count);
    for i in 0..test_count {
        let result = format!("tcc_result_{i}");
        let threshold = format!("tcc_threshold_{i}");
        builder.private_input(&result)?;
        builder.private_input(&threshold)?;
        builder.constrain_range(&result, amount_bits)?;
        builder.constrain_range(&threshold, amount_bits)?;
        result_names.push(result);
        threshold_names.push(threshold);
    }

    let mut operator_names = Vec::with_capacity(operator_count);
    for i in 0..operator_count {
        let name = format!("tcc_operator_cert_{i}");
        builder.private_input(&name)?;
        builder.constrain_nonzero(&name)?;
        operator_names.push(name);
    }

    builder.private_input("tcc_actual_test_count")?;
    builder.private_input("tcc_min_test_count")?;
    builder.constrain_range("tcc_actual_test_count", count_bits)?;
    builder.constrain_range("tcc_min_test_count", count_bits)?;

    builder.public_output("tcc_campaign_commitment")?;
    builder.public_output("tcc_all_tests_passed")?;
    builder.public_output("tcc_total_margin")?;
    builder.constant_signal("tcc_chain_seed", FieldElement::ZERO)?;

    // Each result <= its threshold
    let mut margin_names = Vec::with_capacity(test_count);
    for i in 0..test_count {
        builder.constrain_leq(
            format!("tcc_result_slack_{i}"),
            signal_expr(&result_names[i]),
            signal_expr(&threshold_names[i]),
            amount_bits,
        )?;
        let margin = format!("tcc_margin_{i}");
        builder.private_signal(&margin)?;
        builder.constrain_equal(
            signal_expr(&margin),
            sub_expr(
                signal_expr(&threshold_names[i]),
                signal_expr(&result_names[i]),
            ),
        )?;
        builder.append_nonnegative_bound(
            &margin,
            &aq_goldilocks_amount_bound(),
            &format!("tcc_margin_{i}_bound"),
        )?;
        margin_names.push(margin);
    }

    // Min test count met
    builder.constrain_geq(
        "tcc_test_count_slack",
        signal_expr("tcc_actual_test_count"),
        signal_expr("tcc_min_test_count"),
        count_bits,
    )?;

    // Total margin = sum of individual margins
    builder.private_signal("tcc_total_margin_signal")?;
    builder.constrain_equal(
        signal_expr("tcc_total_margin_signal"),
        sum_exprs(&margin_names),
    )?;

    // Poseidon commitment chain
    let mut previous_digest = signal_expr("tcc_chain_seed");
    for i in 0..test_count {
        let step_digest = builder.append_poseidon_hash(
            &format!("tcc_test_commitment_{i}"),
            [
                signal_expr(&result_names[i]),
                signal_expr(&threshold_names[i]),
                previous_digest.clone(),
                signal_expr(&margin_names[i]),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    let final_digest = builder.append_poseidon_hash(
        "tcc_final_commitment",
        [
            previous_digest,
            signal_expr("tcc_actual_test_count"),
            signal_expr("tcc_total_margin_signal"),
            signal_expr("tcc_min_test_count"),
        ],
    )?;
    builder.bind("tcc_campaign_commitment", signal_expr(&final_digest))?;
    builder.bind("tcc_all_tests_passed", const_expr(&one()))?;
    builder.bind("tcc_total_margin", signal_expr("tcc_total_margin_signal"))?;
    builder.build()
}

pub fn test_campaign_compliance_witness_from_request(
    request: &TestCampaignComplianceRequestV1,
) -> ZkfResult<Witness> {
    validate_equal_lengths(
        "test campaign",
        &[request.test_results.len(), request.test_thresholds.len()],
    )?;
    let test_count = request.test_results.len();
    let _operator_count = request.operator_certification_hashes.len();
    let mut values = BTreeMap::new();

    let results: Vec<BigInt> = request
        .test_results
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("test result {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let thresholds: Vec<BigInt> = request
        .test_thresholds
        .iter()
        .enumerate()
        .map(|(i, v)| parse_goldilocks_amount(v, &format!("test threshold {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;
    let operators: Vec<BigInt> = request
        .operator_certification_hashes
        .iter()
        .enumerate()
        .map(|(i, v)| parse_nonnegative_integer(v, &format!("operator cert {i}")))
        .collect::<ZkfResult<Vec<_>>>()?;

    for op in &operators {
        if *op == zero() {
            return Err(ZkfError::InvalidArtifact(
                "operator certification hash must be nonzero".to_string(),
            ));
        }
    }

    let actual_test_count = BigInt::from(test_count as u64);
    let min_test_count = BigInt::from(request.min_test_count);

    if actual_test_count < min_test_count {
        return Err(ZkfError::InvalidArtifact(
            "test count below minimum required".to_string(),
        ));
    }

    for (i, v) in results.iter().enumerate() {
        write_value(&mut values, format!("tcc_result_{i}"), v.clone());
    }
    for (i, v) in thresholds.iter().enumerate() {
        write_value(&mut values, format!("tcc_threshold_{i}"), v.clone());
    }
    for (i, v) in operators.iter().enumerate() {
        write_value(&mut values, format!("tcc_operator_cert_{i}"), v.clone());
    }
    write_value(
        &mut values,
        "tcc_actual_test_count",
        actual_test_count.clone(),
    );
    write_value(&mut values, "tcc_min_test_count", min_test_count.clone());
    write_value(
        &mut values,
        "tcc_test_count_slack",
        &actual_test_count - &min_test_count,
    );
    write_value(&mut values, "tcc_chain_seed", zero());

    let mut total_margin = zero();
    for i in 0..test_count {
        if results[i] > thresholds[i] {
            return Err(ZkfError::InvalidArtifact(format!(
                "test result {i} exceeds threshold"
            )));
        }
        let margin = &thresholds[i] - &results[i];
        write_value(&mut values, format!("tcc_margin_{i}"), margin.clone());
        write_value(&mut values, format!("tcc_result_slack_{i}"), margin.clone());
        total_margin += &margin;
    }
    write_value(&mut values, "tcc_total_margin_signal", total_margin.clone());

    // Poseidon commitment chain
    let mut previous_digest = zero();
    for i in 0..test_count {
        let margin = &thresholds[i] - &results[i];
        let digest = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [&results[i], &thresholds[i], &previous_digest, &margin],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("tcc_test_commitment_{i}"), digest).as_bigint();
    }
    let final_digest = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &BigInt::from(test_count as u64),
            &total_margin,
            &min_test_count,
        ],
    )?;
    let commitment = write_hash_lanes(&mut values, "tcc_final_commitment", final_digest);
    values.insert("tcc_campaign_commitment".to_string(), commitment);
    values.insert("tcc_all_tests_passed".to_string(), FieldElement::ONE);
    values.insert("tcc_total_margin".to_string(), field(total_margin));

    let program = build_test_campaign_compliance_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Circuit 6: Flight-Readiness Assembly (Goldilocks / Plonky3) — Integration
// ---------------------------------------------------------------------------

pub fn build_flight_readiness_assembly_program(
    request: &FlightReadinessAssemblyRequestV1,
) -> ZkfResult<Program> {
    let component_count = request.component_qualification_commitments.len();
    let approval_count = request.approval_signature_hashes.len();
    validate_equal_lengths(
        "flight readiness",
        &[component_count, request.revocation_flags.len()],
    )?;
    if component_count == 0 || approval_count == 0 {
        return Err(ZkfError::InvalidArtifact(
            "flight readiness requires at least one component and one approval".to_string(),
        ));
    }
    let count_bits = 32u32;

    let mut builder = ProgramBuilder::new(
        format!("aerospace_qualification_flight_readiness_{component_count}_{approval_count}"),
        AQ_GOLDILOCKS_FIELD,
    );
    builder.metadata_entry("application", "aerospace-qualification")?;
    builder.metadata_entry("circuit", "flight-readiness-assembly")?;
    builder.metadata_entry("component_count", component_count.to_string())?;
    builder.metadata_entry("approval_count", approval_count.to_string())?;
    builder.metadata_entry("backend_expectation", "plonky3-goldilocks")?;

    builder.private_input("fra_mission_id")?;

    let mut commitment_names = Vec::with_capacity(component_count);
    let mut revocation_names = Vec::with_capacity(component_count);
    for i in 0..component_count {
        let commitment = format!("fra_component_commitment_{i}");
        let revocation = format!("fra_revocation_flag_{i}");
        builder.private_input(&commitment)?;
        builder.private_input(&revocation)?;
        builder.constrain_boolean(&revocation)?;
        // Revocation flag must be 0 (not revoked)
        builder.constrain_equal(signal_expr(&revocation), const_expr(&zero()))?;
        commitment_names.push(commitment);
        revocation_names.push(revocation);
    }

    let mut approval_names = Vec::with_capacity(approval_count);
    for i in 0..approval_count {
        let name = format!("fra_approval_sig_{i}");
        builder.private_input(&name)?;
        builder.constrain_nonzero(&name)?;
        approval_names.push(name);
    }

    builder.private_input("fra_actual_approval_count")?;
    builder.private_input("fra_required_approval_count")?;
    builder.constrain_range("fra_actual_approval_count", count_bits)?;
    builder.constrain_range("fra_required_approval_count", count_bits)?;

    builder.public_output("fra_readiness_commitment")?;
    builder.public_output("fra_flight_ready")?;
    builder.public_output("fra_component_count_out")?;
    builder.public_output("fra_approval_count_out")?;

    // Approval count >= required
    builder.constrain_geq(
        "fra_approval_count_slack",
        signal_expr("fra_actual_approval_count"),
        signal_expr("fra_required_approval_count"),
        count_bits,
    )?;

    // Poseidon chain across all component commitments
    let mut previous_digest = signal_expr("fra_mission_id");
    for i in 0..component_count {
        let step_digest = builder.append_poseidon_hash(
            &format!("fra_chain_{i}"),
            [
                previous_digest.clone(),
                signal_expr(&commitment_names[i]),
                signal_expr(&revocation_names[i]),
                signal_expr("fra_actual_approval_count"),
            ],
        )?;
        previous_digest = signal_expr(&step_digest);
    }
    // Anchor fra_required_approval_count (linear-only via constrain_geq) through Poseidon
    let fra_final_digest = builder.append_poseidon_hash(
        "fra_final_commitment",
        [
            previous_digest,
            signal_expr("fra_required_approval_count"),
            signal_expr("fra_actual_approval_count"),
            signal_expr("fra_mission_id"),
        ],
    )?;

    builder.bind("fra_readiness_commitment", signal_expr(&fra_final_digest))?;
    builder.bind("fra_flight_ready", const_expr(&one()))?;
    builder.bind(
        "fra_component_count_out",
        const_expr(&BigInt::from(component_count as u64)),
    )?;
    builder.bind(
        "fra_approval_count_out",
        const_expr(&BigInt::from(approval_count as u64)),
    )?;
    builder.build()
}

pub fn flight_readiness_assembly_witness_from_request(
    request: &FlightReadinessAssemblyRequestV1,
) -> ZkfResult<Witness> {
    let component_count = request.component_qualification_commitments.len();
    let approval_count = request.approval_signature_hashes.len();
    validate_equal_lengths(
        "flight readiness",
        &[component_count, request.revocation_flags.len()],
    )?;
    let mut values = BTreeMap::new();

    let mission_id = parse_nonnegative_integer(&request.mission_id, "mission id")?;
    write_value(&mut values, "fra_mission_id", mission_id.clone());

    let mut commitment_vals = Vec::with_capacity(component_count);
    for i in 0..component_count {
        let c = parse_nonnegative_integer(
            &request.component_qualification_commitments[i],
            &format!("component commitment {i}"),
        )?;
        write_value(
            &mut values,
            format!("fra_component_commitment_{i}"),
            c.clone(),
        );
        commitment_vals.push(c);

        if request.revocation_flags[i] {
            return Err(ZkfError::InvalidArtifact(format!(
                "component {i} is revoked — flight readiness cannot be established"
            )));
        }
        write_bool_value(&mut values, format!("fra_revocation_flag_{i}"), false);
    }

    let mut approval_vals = Vec::with_capacity(approval_count);
    for i in 0..approval_count {
        let a = parse_nonnegative_integer(
            &request.approval_signature_hashes[i],
            &format!("approval signature {i}"),
        )?;
        if a == zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "approval signature hash {i} must be nonzero"
            )));
        }
        write_value(&mut values, format!("fra_approval_sig_{i}"), a.clone());
        approval_vals.push(a);
    }

    let actual_approval_count = BigInt::from(approval_count as u64);
    let required_approval_count = BigInt::from(request.required_approval_count);
    if actual_approval_count < required_approval_count {
        return Err(ZkfError::InvalidArtifact(
            "insufficient approvals for flight readiness".to_string(),
        ));
    }
    write_value(
        &mut values,
        "fra_actual_approval_count",
        actual_approval_count.clone(),
    );
    write_value(
        &mut values,
        "fra_required_approval_count",
        required_approval_count.clone(),
    );
    write_value(
        &mut values,
        "fra_approval_count_slack",
        &actual_approval_count - &required_approval_count,
    );

    // Poseidon chain across all component commitments
    let mut previous_digest = mission_id.clone();
    for i in 0..component_count {
        let revocation_val = zero();
        let digest = poseidon_permutation4(
            AQ_GOLDILOCKS_FIELD,
            [
                &previous_digest,
                &commitment_vals[i],
                &revocation_val,
                &actual_approval_count,
            ],
        )?;
        previous_digest =
            write_hash_lanes(&mut values, &format!("fra_chain_{i}"), digest).as_bigint();
    }
    // Anchor fra_required_approval_count through Poseidon (matches circuit builder)
    let fra_final = poseidon_permutation4(
        AQ_GOLDILOCKS_FIELD,
        [
            &previous_digest,
            &required_approval_count,
            &actual_approval_count,
            &mission_id,
        ],
    )?;
    let fra_commitment = write_hash_lanes(&mut values, "fra_final_commitment", fra_final);

    values.insert("fra_readiness_commitment".to_string(), fra_commitment);
    values.insert("fra_flight_ready".to_string(), FieldElement::ONE);
    values.insert(
        "fra_component_count_out".to_string(),
        field(BigInt::from(component_count as u64)),
    );
    values.insert(
        "fra_approval_count_out".to_string(),
        field(BigInt::from(approval_count as u64)),
    );

    let program = build_flight_readiness_assembly_program(request)?;
    materialize_seeded_witness(&program, values)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_thermal_request() -> ComponentThermalQualificationRequestV1 {
        ComponentThermalQualificationRequestV1 {
            component_id: "1001".to_string(),
            lot_id: "5001".to_string(),
            temperature_readings: vec!["85.0".to_string(), "90.0".to_string(), "88.0".to_string()],
            duration_measurements: vec![
                "3600.0".to_string(),
                "3600.0".to_string(),
                "3600.0".to_string(),
            ],
            cycle_count: 100,
            min_required_cycles: 50,
            temperature_upper_limit: "125.0".to_string(),
            temperature_lower_floor: "20.0".to_string(),
            required_duration: "1800.0".to_string(),
            margin_threshold: "10.0".to_string(),
        }
    }

    fn sample_vibration_request() -> VibrationShockQualificationRequestV1 {
        VibrationShockQualificationRequestV1 {
            component_id: "1001".to_string(),
            acceleration_readings: vec!["8.0".to_string(), "12.0".to_string(), "10.0".to_string()],
            spectral_density_readings: vec!["50.0".to_string(), "60.0".to_string()],
            spectral_density_limits: vec!["100.0".to_string(), "100.0".to_string()],
            shock_pulse_durations: vec!["5.0".to_string(), "6.0".to_string()],
            min_shock_duration: "3.0".to_string(),
            peak_g_limit: "20.0".to_string(),
            calibration_hash: "999".to_string(),
            approved_calibration_hash: "999".to_string(),
        }
    }

    fn sample_lot_genealogy_request() -> LotGenealogyRequestV1 {
        LotGenealogyRequestV1 {
            source_lot_id: "7001".to_string(),
            material_batch_certificate_hashes: vec!["100".to_string(), "200".to_string()],
            transformation_record_hashes: vec!["300".to_string(), "400".to_string()],
            inspection_stamp_hashes: vec!["500".to_string(), "600".to_string()],
            handler_signature_hashes: vec!["700".to_string(), "800".to_string()],
        }
    }

    fn sample_firmware_provenance_request() -> FirmwareProvenanceRequestV1 {
        FirmwareProvenanceRequestV1 {
            firmware_binary_hash: "123456789".to_string(),
            approved_firmware_hash: "123456789".to_string(),
            build_toolchain_hash: "987654321".to_string(),
            approved_toolchain_hashes: vec!["987654321".to_string()],
            signing_key_fingerprint: "555555".to_string(),
            approved_signing_keys: vec!["555555".to_string()],
            version_major: 2,
            version_minor: 1,
            version_patch: 0,
            minimum_version_major: 1,
            minimum_version_minor: 0,
            minimum_version_patch: 0,
        }
    }

    fn sample_test_campaign_request() -> TestCampaignComplianceRequestV1 {
        TestCampaignComplianceRequestV1 {
            campaign_id: "TC-2026-001".to_string(),
            test_results: vec!["75.0".to_string(), "80.0".to_string(), "70.0".to_string()],
            test_thresholds: vec![
                "100.0".to_string(),
                "100.0".to_string(),
                "100.0".to_string(),
            ],
            operator_certification_hashes: vec!["1111".to_string(), "2222".to_string()],
            min_test_count: 2,
        }
    }

    fn sample_flight_readiness_request() -> FlightReadinessAssemblyRequestV1 {
        FlightReadinessAssemblyRequestV1 {
            mission_id: "20260001".to_string(),
            component_qualification_commitments: vec![
                "111".to_string(),
                "222".to_string(),
                "333".to_string(),
            ],
            approval_signature_hashes: vec!["444".to_string(), "555".to_string()],
            revocation_flags: vec![false, false, false],
            required_approval_count: 2,
        }
    }

    #[test]
    fn thermal_qualification_roundtrip() {
        let request = sample_thermal_request();
        let witness = component_thermal_qualification_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("ctq_qualification_commitment"));
    }

    #[test]
    fn vibration_shock_roundtrip() {
        let request = sample_vibration_request();
        let witness = vibration_shock_qualification_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("vsq_vibration_commitment"));
    }

    #[test]
    fn lot_genealogy_roundtrip() {
        let request = sample_lot_genealogy_request();
        let witness = lot_genealogy_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("lg_lineage_commitment"));
    }

    #[test]
    fn firmware_provenance_roundtrip() {
        let request = sample_firmware_provenance_request();
        let witness = firmware_provenance_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("fp_provenance_commitment"));
    }

    #[test]
    fn test_campaign_roundtrip() {
        let request = sample_test_campaign_request();
        let witness = test_campaign_compliance_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("tcc_campaign_commitment"));
    }

    #[test]
    fn flight_readiness_roundtrip() {
        let request = sample_flight_readiness_request();
        let witness = flight_readiness_assembly_witness_from_request(&request).unwrap();
        assert!(witness.values.contains_key("fra_readiness_commitment"));
    }

    #[test]
    fn thermal_rejects_over_limit() {
        let mut request = sample_thermal_request();
        request.temperature_readings = vec!["130.0".to_string()]; // above 125 limit
        request.duration_measurements = vec!["3600.0".to_string()];
        let result = component_thermal_qualification_witness_from_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn firmware_rejects_hash_mismatch() {
        let mut request = sample_firmware_provenance_request();
        request.approved_firmware_hash = "999999999".to_string();
        let result = firmware_provenance_witness_from_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn flight_readiness_rejects_revoked() {
        let mut request = sample_flight_readiness_request();
        request.revocation_flags = vec![false, true, false]; // component 1 revoked
        let result = flight_readiness_assembly_witness_from_request(&request);
        assert!(result.is_err());
    }
}
