#![cfg_attr(not(test), allow(dead_code))]

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
#[cfg(test)]
use zkf_core::check_constraints;
use zkf_core::{
    Expr, FieldElement, FieldId, Program, Witness, WitnessInputs, ZkfError, ZkfResult,
    generate_witness,
};

use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

pub const PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS: usize = 8;
pub const PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS: usize = 3;
pub const PRIVATE_TURBINE_BLADE_DEFAULT_STEPS: usize = 500;
pub const PRIVATE_TURBINE_BLADE_PUBLIC_OUTPUTS: usize = 5;
pub const PRIVATE_TURBINE_BLADE_PRIVATE_INPUTS: usize = (PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS
    * 8)
    + 21
    + (PRIVATE_TURBINE_BLADE_DEFAULT_STEPS * 5)
    + 8;

const TURBINE_FIELD: FieldId = FieldId::Bn254;
const CONTROL_SECTION_SOURCE_STATIONS: [usize; PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS] = [0, 3, 7];
const COMMITMENT_DOMAIN_DAMAGE: i64 = 11;
const COMMITMENT_DOMAIN_CRACK: i64 = 22;
const COMMITMENT_DOMAIN_REMAINING_LIFE: i64 = 33;
const COMMITMENT_DOMAIN_MARGIN: i64 = 44;
const INPUT_MAX: u64 = 1_000_000;
const STRESS_MAX: u64 = 10_000_000_000;
const DAMAGE_MAX: u64 = 50_000_000_000;
const MARGIN_OFFSET: u64 = 100_000_000;
const SHIFTED_MARGIN_MAX: u64 = 200_000_000_000;
const MODEL_MAX_RPM: u64 = 10;
const MODEL_MAX_GAS_TEMP: u64 = 200;
const MODEL_MAX_SURFACE_TEMP: u64 = 180;
const MODEL_MAX_LOAD_FACTOR: u64 = 10;
const MODEL_MAX_METAL_TEMP: u64 = 600;
const MODEL_MAX_STRESS: u64 = 100_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeGeometryStationV1 {
    pub radius: u64,
    pub chord: u64,
    pub max_thickness: u64,
    pub camber: u64,
    pub twist_deg: u64,
    pub wall_thickness: u64,
    pub coating_thickness: u64,
    pub tbc_effectiveness: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeMaterialPropertiesV1 {
    pub youngs_modulus: u64,
    pub poissons_ratio: u64,
    pub thermal_expansion_coeff: u64,
    pub density: u64,
    pub creep_coeffs: [u64; 3],
    pub fatigue_coeffs: [u64; 3],
    pub fracture_toughness_proxy: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeMissionStepV1 {
    pub rotational_speed: u64,
    pub gas_temperature: u64,
    pub blade_surface_temperature: u64,
    pub centrifugal_load_factor: u64,
    pub pressure_load_factor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeThresholdsV1 {
    pub allowable_stress: [u64; PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS],
    pub allowable_temperature: [u64; PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS],
    pub damage_limit: u64,
    pub crack_limit: u64,
    pub reserve_margin_min: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeCommitmentBlindersV1 {
    pub damage_commitment: [u64; 2],
    pub crack_commitment: [u64; 2],
    pub remaining_life_commitment: [u64; 2],
    pub min_margin_commitment: [u64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurbineBladeLifeRequestV1 {
    pub geometry_stations: Vec<TurbineBladeGeometryStationV1>,
    pub material: TurbineBladeMaterialPropertiesV1,
    pub initial_crack_length: u64,
    pub mission_profile: Vec<TurbineBladeMissionStepV1>,
    pub thresholds: TurbineBladeThresholdsV1,
    pub commitment_blinders: TurbineBladeCommitmentBlindersV1,
}

fn zero() -> BigInt {
    BigInt::from(0u8)
}

fn one() -> BigInt {
    BigInt::from(1u8)
}

fn field(value: impl Into<BigInt>) -> FieldElement {
    FieldElement::from_bigint(value.into())
}

fn field_ref(value: &BigInt) -> FieldElement {
    FieldElement::from_bigint(value.clone())
}

fn const_expr(value: impl Into<BigInt>) -> Expr {
    Expr::Const(field(value))
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

fn bits_for_bound(bound: u64) -> u32 {
    let bigint = BigInt::from(bound);
    bigint.to_str_radix(2).len() as u32
}

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: impl Into<BigInt>,
) {
    values.insert(name.into(), field(value));
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

fn positive_comparison_offset(bound: u64) -> BigInt {
    BigInt::from(bound) + one()
}

fn comparator_slack(lhs: &BigInt, rhs: &BigInt, offset: &BigInt) -> BigInt {
    if lhs >= rhs {
        lhs - rhs
    } else {
        lhs - rhs + offset
    }
}

fn write_nonnegative_support(
    values: &mut BTreeMap<String, FieldElement>,
    signal_name: impl Into<String>,
    value: &BigInt,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let bound_bigint = BigInt::from(bound);
    if value < &zero() || value > &bound_bigint {
        return Err(ZkfError::InvalidArtifact(format!(
            "{prefix} expected a nonnegative value <= {bound}, got {}",
            value.to_str_radix(10),
        )));
    }
    values.insert(signal_name.into(), field_ref(value));
    values.insert(
        format!("{prefix}_comparator_slack_nonnegative_bound_slack"),
        field_ref(&(bound_bigint.clone() - value)),
    );
    values.insert(
        format!("{prefix}_comparator_slack_nonnegative_bound_anchor"),
        field_ref(&((bound_bigint - value) * (BigInt::from(bound) - value))),
    );
    Ok(())
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_poseidon_state_0"),
        format!("{prefix}_poseidon_state_1"),
        format!("{prefix}_poseidon_state_2"),
        format!("{prefix}_poseidon_state_3"),
    ]
}

fn poseidon_permutation4(inputs: [&BigInt; 4]) -> ZkfResult<[FieldElement; 4]> {
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    let lanes = poseidon2_permutation_native(
        &inputs.into_iter().cloned().collect::<Vec<_>>(),
        &params,
        TURBINE_FIELD,
    )
    .map_err(ZkfError::Backend)?;
    if lanes.len() != 4 {
        return Err(ZkfError::Backend(format!(
            "poseidon permutation returned {} lanes instead of 4",
            lanes.len()
        )));
    }
    Ok([
        field_ref(&lanes[0]),
        field_ref(&lanes[1]),
        field_ref(&lanes[2]),
        field_ref(&lanes[3]),
    ])
}

fn write_hash_lanes(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    lanes: [FieldElement; 4],
) -> BigInt {
    let names = hash_state_names(prefix);
    for (name, lane) in names.iter().zip(lanes) {
        values.insert(name.clone(), lane);
    }
    values
        .get(&names[0])
        .cloned()
        .unwrap_or(FieldElement::ZERO)
        .as_bigint()
}

fn station_field_name(field: &str, station: usize) -> String {
    format!("tb_geometry_{field}_{station}")
}

fn material_field_name(field: &str) -> String {
    format!("tb_material_{field}")
}

fn material_coeff_name(kind: &str, index: usize) -> String {
    format!("tb_material_{kind}_{index}")
}

fn threshold_field_name(field: &str, index: usize) -> String {
    format!("tb_threshold_{field}_{index}")
}

fn mission_field_name(field: &str, step: usize) -> String {
    format!("tb_mission_{field}_{step}")
}

fn commitment_blinder_field_name(commitment: &str, lane: usize) -> String {
    format!("tb_commitment_{commitment}_blinder_{lane}")
}

fn step_section_prefix(step: usize, section: usize) -> String {
    format!("tb_step_{step}_section_{section}")
}

fn append_private_input_anchor_chain(
    builder: &mut ProgramBuilder,
    inputs: &[String],
    prefix: &str,
) -> ZkfResult<String> {
    let mut previous = const_expr(0);
    let mut final_digest = String::new();
    for (index, chunk) in inputs.chunks(3).enumerate() {
        let digest = builder.append_poseidon_hash(
            &format!("{prefix}_{index}"),
            [
                previous.clone(),
                signal_expr(&chunk[0]),
                chunk
                    .get(1)
                    .map(|name| signal_expr(name))
                    .unwrap_or_else(|| const_expr(0)),
                chunk
                    .get(2)
                    .map(|name| signal_expr(name))
                    .unwrap_or_else(|| const_expr(0)),
            ],
        )?;
        previous = signal_expr(&digest);
        final_digest = digest;
    }
    Ok(final_digest)
}

fn write_private_input_anchor_chain(
    values: &mut BTreeMap<String, FieldElement>,
    input_names: &[String],
    prefix: &str,
) -> ZkfResult<BigInt> {
    let mut previous = zero();
    for (index, chunk) in input_names.chunks(3).enumerate() {
        let lane_1 = values
            .get(&chunk[0])
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let lane_2 = chunk
            .get(1)
            .and_then(|name| values.get(name))
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let lane_3 = chunk
            .get(2)
            .and_then(|name| values.get(name))
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let digest = poseidon_permutation4([&previous, &lane_1, &lane_2, &lane_3])?;
        previous = write_hash_lanes(values, &format!("{prefix}_{index}"), digest);
    }
    Ok(previous)
}

fn section_copy_field_pairs() -> [(&'static str, &'static str); 8] {
    [
        ("radius", "radius"),
        ("chord", "chord"),
        ("thickness", "max_thickness"),
        ("camber", "camber"),
        ("twist", "twist_deg"),
        ("wall", "wall_thickness"),
        ("coating", "coating_thickness"),
        ("tbc", "tbc_effectiveness"),
    ]
}

fn section_signal_name(section: usize, field: &str) -> String {
    format!("tb_section_{section}_{field}")
}

fn collect_section_anchor_signals() -> Vec<String> {
    let mut signals = Vec::new();
    for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        for (field, _) in section_copy_field_pairs() {
            signals.push(section_signal_name(section, field));
        }
    }
    signals
}

fn collect_barrier_shape_signals() -> Vec<String> {
    (0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS)
        .map(|section| format!("tb_section_{section}_barrier_shape"))
        .collect()
}

fn collect_thermal_gap_signals(steps: usize) -> Vec<String> {
    let mut signals = Vec::new();
    for step in 0..steps {
        for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
            signals.push(format!(
                "{}_thermal_gap",
                step_section_prefix(step, section)
            ));
        }
    }
    signals
}

fn write_section_copy_signals(
    values: &mut BTreeMap<String, FieldElement>,
    request: &TurbineBladeLifeRequestV1,
) {
    for (section, station_index) in CONTROL_SECTION_SOURCE_STATIONS.iter().enumerate() {
        let station = &request.geometry_stations[*station_index];
        for (field, source) in section_copy_field_pairs() {
            let value = match source {
                "radius" => station.radius,
                "chord" => station.chord,
                "max_thickness" => station.max_thickness,
                "camber" => station.camber,
                "twist_deg" => station.twist_deg,
                "wall_thickness" => station.wall_thickness,
                "coating_thickness" => station.coating_thickness,
                "tbc_effectiveness" => station.tbc_effectiveness,
                _ => unreachable!("section copy field mapping is static"),
            };
            write_value(values, section_signal_name(section, field), value);
        }
    }
}

fn write_section_barrier_shapes(
    values: &mut BTreeMap<String, FieldElement>,
    request: &TurbineBladeLifeRequestV1,
) {
    for (section, station_index) in CONTROL_SECTION_SOURCE_STATIONS.iter().enumerate() {
        let station = &request.geometry_stations[*station_index];
        let barrier_shape = station.coating_thickness
            + station.tbc_effectiveness
            + station.twist_deg
            + station.camber
            + 1;
        write_value(
            values,
            format!("tb_section_{section}_barrier_shape"),
            barrier_shape,
        );
    }
}

fn append_geq_comparator_bit(
    builder: &mut ProgramBuilder,
    lhs: Expr,
    rhs: Expr,
    bit_signal: &str,
    slack_signal: &str,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let offset = positive_comparison_offset(bound);
    builder.private_signal(bit_signal)?;
    builder.constrain_boolean(bit_signal)?;
    builder.private_signal(slack_signal)?;
    builder.constrain_equal(
        add_expr(vec![lhs, const_expr(offset.clone())]),
        add_expr(vec![
            rhs,
            signal_expr(slack_signal),
            mul_expr(signal_expr(bit_signal), const_expr(offset)),
        ]),
    )?;
    builder.constrain_range(slack_signal, bits_for_bound(bound))?;
    builder.private_signal(&format!(
        "{prefix}_comparator_slack_nonnegative_bound_slack"
    ))?;
    builder.private_signal(&format!(
        "{prefix}_comparator_slack_nonnegative_bound_anchor"
    ))?;
    builder.constrain_equal(
        signal_expr(&format!(
            "{prefix}_comparator_slack_nonnegative_bound_anchor"
        )),
        mul_expr(
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
        ),
    )?;
    builder.constrain_equal(
        add_expr(vec![
            signal_expr(slack_signal),
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
        ]),
        const_expr(BigInt::from(bound)),
    )?;
    builder.constrain_range(
        &format!("{prefix}_comparator_slack_nonnegative_bound_slack"),
        bits_for_bound(bound),
    )?;
    Ok(())
}

fn append_pairwise_max_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: u64,
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
        bound,
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.constrain_select(
        target,
        &bit_signal,
        signal_expr(left_signal),
        signal_expr(right_signal),
    )?;
    builder.constrain_range(target, bits_for_bound(bound))?;
    Ok(())
}

fn append_pairwise_min_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: u64,
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
        bound,
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.constrain_select(
        target,
        &bit_signal,
        signal_expr(right_signal),
        signal_expr(left_signal),
    )?;
    builder.constrain_range(target, bits_for_bound(bound))?;
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
    builder.bind(target, mul_expr(signal_expr(left), signal_expr(right)))?;
    Ok(())
}

fn validate_request(request: &TurbineBladeLifeRequestV1, steps: usize) -> ZkfResult<()> {
    if request.geometry_stations.len() != PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS {
        return Err(ZkfError::InvalidArtifact(format!(
            "turbine blade geometry requires exactly {} stations",
            PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS
        )));
    }
    if request.mission_profile.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "mission profile requires exactly {steps} time steps",
        )));
    }
    if request.thresholds.damage_limit > DAMAGE_MAX || request.thresholds.crack_limit > DAMAGE_MAX {
        return Err(ZkfError::InvalidArtifact(
            "damage_limit and crack_limit must stay within the demo model bounds".to_string(),
        ));
    }
    if request.thresholds.reserve_margin_min > MARGIN_OFFSET {
        return Err(ZkfError::InvalidArtifact(format!(
            "reserve_margin_min must be <= {MARGIN_OFFSET}"
        )));
    }
    for (index, station) in request.geometry_stations.iter().enumerate() {
        for (label, value) in [
            ("radius", station.radius),
            ("chord", station.chord),
            ("max_thickness", station.max_thickness),
            ("camber", station.camber),
            ("twist_deg", station.twist_deg),
            ("wall_thickness", station.wall_thickness),
            ("coating_thickness", station.coating_thickness),
            ("tbc_effectiveness", station.tbc_effectiveness),
        ] {
            if value > INPUT_MAX {
                return Err(ZkfError::InvalidArtifact(format!(
                    "geometry station {index} field {label} exceeded {INPUT_MAX}"
                )));
            }
        }
    }
    for (label, value) in [
        ("youngs_modulus", request.material.youngs_modulus),
        ("poissons_ratio", request.material.poissons_ratio),
        (
            "thermal_expansion_coeff",
            request.material.thermal_expansion_coeff,
        ),
        ("density", request.material.density),
        (
            "fracture_toughness_proxy",
            request.material.fracture_toughness_proxy,
        ),
        ("initial_crack_length", request.initial_crack_length),
    ] {
        if value > INPUT_MAX {
            return Err(ZkfError::InvalidArtifact(format!(
                "{label} exceeded {INPUT_MAX}"
            )));
        }
    }
    for (label, blinders) in [
        (
            "damage_commitment",
            request.commitment_blinders.damage_commitment,
        ),
        (
            "crack_commitment",
            request.commitment_blinders.crack_commitment,
        ),
        (
            "remaining_life_commitment",
            request.commitment_blinders.remaining_life_commitment,
        ),
        (
            "min_margin_commitment",
            request.commitment_blinders.min_margin_commitment,
        ),
    ] {
        for (lane, blinder) in blinders.into_iter().enumerate() {
            if blinder > DAMAGE_MAX {
                return Err(ZkfError::InvalidArtifact(format!(
                    "{label} blinder lane {lane} exceeded {DAMAGE_MAX}"
                )));
            }
        }
    }
    for (index, coeff) in request.material.creep_coeffs.iter().enumerate() {
        if *coeff > INPUT_MAX {
            return Err(ZkfError::InvalidArtifact(format!(
                "creep coefficient {index} exceeded {INPUT_MAX}"
            )));
        }
    }
    for (index, coeff) in request.material.fatigue_coeffs.iter().enumerate() {
        if *coeff > INPUT_MAX {
            return Err(ZkfError::InvalidArtifact(format!(
                "fatigue coefficient {index} exceeded {INPUT_MAX}"
            )));
        }
    }
    for (index, step) in request.mission_profile.iter().enumerate() {
        if step.rotational_speed > MODEL_MAX_RPM
            || step.gas_temperature > MODEL_MAX_GAS_TEMP
            || step.blade_surface_temperature > MODEL_MAX_SURFACE_TEMP
            || step.centrifugal_load_factor > MODEL_MAX_LOAD_FACTOR
            || step.pressure_load_factor > MODEL_MAX_LOAD_FACTOR
        {
            return Err(ZkfError::InvalidArtifact(format!(
                "mission step {index} exceeded the modeled input bounds"
            )));
        }
        if step.gas_temperature < step.blade_surface_temperature {
            return Err(ZkfError::InvalidArtifact(format!(
                "mission step {index} has gas_temperature < blade_surface_temperature"
            )));
        }
    }
    Ok(())
}

fn request_to_inputs(request: &TurbineBladeLifeRequestV1) -> WitnessInputs {
    let mut values = BTreeMap::new();
    for (station_index, station) in request.geometry_stations.iter().enumerate() {
        write_value(
            &mut values,
            station_field_name("radius", station_index),
            station.radius,
        );
        write_value(
            &mut values,
            station_field_name("chord", station_index),
            station.chord,
        );
        write_value(
            &mut values,
            station_field_name("thickness", station_index),
            station.max_thickness,
        );
        write_value(
            &mut values,
            station_field_name("camber", station_index),
            station.camber,
        );
        write_value(
            &mut values,
            station_field_name("twist", station_index),
            station.twist_deg,
        );
        write_value(
            &mut values,
            station_field_name("wall", station_index),
            station.wall_thickness,
        );
        write_value(
            &mut values,
            station_field_name("coating", station_index),
            station.coating_thickness,
        );
        write_value(
            &mut values,
            station_field_name("tbc", station_index),
            station.tbc_effectiveness,
        );
    }
    write_value(
        &mut values,
        material_field_name("youngs_modulus"),
        request.material.youngs_modulus,
    );
    write_value(
        &mut values,
        material_field_name("poissons_ratio"),
        request.material.poissons_ratio,
    );
    write_value(
        &mut values,
        material_field_name("thermal_expansion_coeff"),
        request.material.thermal_expansion_coeff,
    );
    write_value(
        &mut values,
        material_field_name("density"),
        request.material.density,
    );
    write_value(
        &mut values,
        material_field_name("fracture_toughness_proxy"),
        request.material.fracture_toughness_proxy,
    );
    for (index, coeff) in request.material.creep_coeffs.iter().enumerate() {
        write_value(&mut values, material_coeff_name("creep", index), *coeff);
    }
    for (index, coeff) in request.material.fatigue_coeffs.iter().enumerate() {
        write_value(&mut values, material_coeff_name("fatigue", index), *coeff);
    }
    write_value(
        &mut values,
        material_field_name("initial_crack_length"),
        request.initial_crack_length,
    );
    for (index, threshold) in request.thresholds.allowable_stress.iter().enumerate() {
        write_value(
            &mut values,
            threshold_field_name("allowable_stress", index),
            *threshold,
        );
    }
    for (index, threshold) in request.thresholds.allowable_temperature.iter().enumerate() {
        write_value(
            &mut values,
            threshold_field_name("allowable_temperature", index),
            *threshold,
        );
    }
    write_value(
        &mut values,
        material_field_name("damage_limit"),
        request.thresholds.damage_limit,
    );
    write_value(
        &mut values,
        material_field_name("crack_limit"),
        request.thresholds.crack_limit,
    );
    write_value(
        &mut values,
        material_field_name("reserve_margin_min"),
        request.thresholds.reserve_margin_min,
    );
    for (commitment, blinders) in [
        ("damage", request.commitment_blinders.damage_commitment),
        ("crack", request.commitment_blinders.crack_commitment),
        (
            "remaining_life",
            request.commitment_blinders.remaining_life_commitment,
        ),
        (
            "min_margin",
            request.commitment_blinders.min_margin_commitment,
        ),
    ] {
        for (lane, blinder) in blinders.into_iter().enumerate() {
            write_value(
                &mut values,
                commitment_blinder_field_name(commitment, lane),
                blinder,
            );
        }
    }
    for (step_index, step) in request.mission_profile.iter().enumerate() {
        write_value(
            &mut values,
            mission_field_name("rpm", step_index),
            step.rotational_speed,
        );
        write_value(
            &mut values,
            mission_field_name("gas_temp", step_index),
            step.gas_temperature,
        );
        write_value(
            &mut values,
            mission_field_name("surface_temp", step_index),
            step.blade_surface_temperature,
        );
        write_value(
            &mut values,
            mission_field_name("centrifugal_factor", step_index),
            step.centrifugal_load_factor,
        );
        write_value(
            &mut values,
            mission_field_name("pressure_factor", step_index),
            step.pressure_load_factor,
        );
    }
    values
}

fn collect_expected_inputs(steps: usize) -> Vec<String> {
    let mut inputs = Vec::new();
    for station in 0..PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS {
        for field in [
            "radius",
            "chord",
            "thickness",
            "camber",
            "twist",
            "wall",
            "coating",
            "tbc",
        ] {
            inputs.push(station_field_name(field, station));
        }
    }
    for field in [
        "youngs_modulus",
        "poissons_ratio",
        "thermal_expansion_coeff",
        "density",
        "fracture_toughness_proxy",
    ] {
        inputs.push(material_field_name(field));
    }
    for index in 0..3 {
        inputs.push(material_coeff_name("creep", index));
    }
    for index in 0..3 {
        inputs.push(material_coeff_name("fatigue", index));
    }
    inputs.push(material_field_name("initial_crack_length"));
    for index in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        inputs.push(threshold_field_name("allowable_stress", index));
    }
    for index in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        inputs.push(threshold_field_name("allowable_temperature", index));
    }
    inputs.push(material_field_name("damage_limit"));
    inputs.push(material_field_name("crack_limit"));
    inputs.push(material_field_name("reserve_margin_min"));
    for commitment in ["damage", "crack", "remaining_life", "min_margin"] {
        for lane in 0..2 {
            inputs.push(commitment_blinder_field_name(commitment, lane));
        }
    }
    for step in 0..steps {
        for field in [
            "rpm",
            "gas_temp",
            "surface_temp",
            "centrifugal_factor",
            "pressure_factor",
        ] {
            inputs.push(mission_field_name(field, step));
        }
    }
    inputs
}

pub fn build_private_turbine_blade_life_program() -> ZkfResult<Program> {
    build_private_turbine_blade_life_program_with_steps(PRIVATE_TURBINE_BLADE_DEFAULT_STEPS)
}

pub fn build_private_turbine_blade_life_program_with_steps(steps: usize) -> ZkfResult<Program> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private turbine blade life showcase requires at least one step".to_string(),
        ));
    }

    let input_bits = bits_for_bound(INPUT_MAX);
    let stress_bits = bits_for_bound(STRESS_MAX);
    let damage_bits = bits_for_bound(DAMAGE_MAX);
    let shifted_margin_bits = bits_for_bound(SHIFTED_MARGIN_MAX);

    let mut builder = ProgramBuilder::new(
        format!("private_turbine_blade_life_showcase_{steps}"),
        TURBINE_FIELD,
    );
    builder.metadata_entry("application", "private-turbine-blade-life-showcase")?;
    builder.metadata_entry("mission_steps", steps.to_string())?;
    builder.metadata_entry(
        "geometry_stations",
        PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS.to_string(),
    )?;
    builder.metadata_entry(
        "control_sections",
        PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS.to_string(),
    )?;
    builder.metadata_entry(
        "model_boundary",
        "normalized integer surrogate over section-stack blade geometry",
    )?;
    builder.metadata_entry("primary_backend_expectation", "strict-runtime-selected")?;
    builder.metadata_entry("compatibility_backend", "arkworks-groth16")?;
    builder.metadata_entry("nova_ivc_in", "safe_to_deploy")?;
    builder.metadata_entry("nova_ivc_out", "safe_to_deploy")?;

    for station in 0..PRIVATE_TURBINE_BLADE_GEOMETRY_STATIONS {
        for field in [
            "radius",
            "chord",
            "thickness",
            "camber",
            "twist",
            "wall",
            "coating",
            "tbc",
        ] {
            let name = station_field_name(field, station);
            builder.private_input(&name)?;
            builder.constrain_range(&name, input_bits)?;
        }
    }
    for field in [
        "youngs_modulus",
        "poissons_ratio",
        "thermal_expansion_coeff",
        "density",
        "fracture_toughness_proxy",
        "initial_crack_length",
        "damage_limit",
        "crack_limit",
        "reserve_margin_min",
    ] {
        let name = material_field_name(field);
        builder.private_input(&name)?;
        builder.constrain_range(&name, damage_bits)?;
    }
    for index in 0..3 {
        let name = material_coeff_name("creep", index);
        builder.private_input(&name)?;
        builder.constrain_range(&name, input_bits)?;
    }
    for index in 0..3 {
        let name = material_coeff_name("fatigue", index);
        builder.private_input(&name)?;
        builder.constrain_range(&name, input_bits)?;
    }
    for index in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        let stress = threshold_field_name("allowable_stress", index);
        builder.private_input(&stress)?;
        builder.constrain_range(&stress, stress_bits)?;
        let temp = threshold_field_name("allowable_temperature", index);
        builder.private_input(&temp)?;
        builder.constrain_range(&temp, input_bits)?;
    }
    for commitment in ["damage", "crack", "remaining_life", "min_margin"] {
        for lane in 0..2 {
            let name = commitment_blinder_field_name(commitment, lane);
            builder.private_input(&name)?;
            builder.constrain_range(&name, damage_bits)?;
        }
    }
    for step in 0..steps {
        let rpm = mission_field_name("rpm", step);
        let gas = mission_field_name("gas_temp", step);
        let surface = mission_field_name("surface_temp", step);
        let cent = mission_field_name("centrifugal_factor", step);
        let press = mission_field_name("pressure_factor", step);
        for (name, bits) in [
            (rpm.as_str(), input_bits),
            (gas.as_str(), input_bits),
            (surface.as_str(), input_bits),
            (cent.as_str(), input_bits),
            (press.as_str(), input_bits),
        ] {
            builder.private_input(name)?;
            builder.constrain_range(name, bits)?;
        }
        builder.constrain_leq(
            format!("tb_step_{step}_rpm_model_limit"),
            signal_expr(&rpm),
            const_expr(MODEL_MAX_RPM),
            input_bits,
        )?;
        builder.constrain_leq(
            format!("tb_step_{step}_gas_model_limit"),
            signal_expr(&gas),
            const_expr(MODEL_MAX_GAS_TEMP),
            input_bits,
        )?;
        builder.constrain_leq(
            format!("tb_step_{step}_surface_model_limit"),
            signal_expr(&surface),
            const_expr(MODEL_MAX_SURFACE_TEMP),
            input_bits,
        )?;
        builder.constrain_leq(
            format!("tb_step_{step}_cent_model_limit"),
            signal_expr(&cent),
            const_expr(MODEL_MAX_LOAD_FACTOR),
            input_bits,
        )?;
        builder.constrain_leq(
            format!("tb_step_{step}_press_model_limit"),
            signal_expr(&press),
            const_expr(MODEL_MAX_LOAD_FACTOR),
            input_bits,
        )?;
        builder.constrain_geq(
            format!("tb_step_{step}_gas_surface_gap_check"),
            signal_expr(&gas),
            signal_expr(&surface),
            input_bits,
        )?;
    }
    let raw_input_names = collect_expected_inputs(steps);
    let input_anchor_root =
        append_private_input_anchor_chain(&mut builder, &raw_input_names, "tb_input_anchor")?;

    for output in [
        "damage_commitment",
        "crack_commitment",
        "remaining_life_commitment",
        "min_margin_commitment",
        "safe_to_deploy",
    ] {
        builder.public_output(output)?;
    }
    builder.constrain_boolean("safe_to_deploy")?;

    for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        let station = CONTROL_SECTION_SOURCE_STATIONS[section];
        for (target_suffix, input_field) in [
            ("radius", "radius"),
            ("chord", "chord"),
            ("thickness", "thickness"),
            ("camber", "camber"),
            ("twist", "twist"),
            ("wall", "wall"),
            ("coating", "coating"),
            ("tbc", "tbc"),
        ] {
            let target = section_signal_name(section, target_suffix);
            builder.private_signal(&target)?;
            builder.bind(
                &target,
                signal_expr(&station_field_name(input_field, station)),
            )?;
            builder.constrain_range(&target, input_bits)?;
        }
        let geometry_shape = format!("tb_section_{section}_geometry_shape");
        let barrier_shape = format!("tb_section_{section}_barrier_shape");
        builder.private_signal(&geometry_shape)?;
        builder.bind(
            &geometry_shape,
            add_expr(vec![
                mul_expr(
                    signal_expr(&format!("tb_section_{section}_chord")),
                    signal_expr(&format!("tb_section_{section}_thickness")),
                ),
                signal_expr(&format!("tb_section_{section}_wall")),
                signal_expr(&format!("tb_section_{section}_camber")),
                const_expr(1),
            ]),
        )?;
        builder.constrain_range(&geometry_shape, stress_bits)?;
        builder.private_signal(&barrier_shape)?;
        builder.bind(
            &barrier_shape,
            add_expr(vec![
                signal_expr(&format!("tb_section_{section}_coating")),
                signal_expr(&format!("tb_section_{section}_tbc")),
                signal_expr(&format!("tb_section_{section}_twist")),
                signal_expr(&format!("tb_section_{section}_camber")),
                const_expr(1),
            ]),
        )?;
        builder.constrain_range(&barrier_shape, input_bits)?;
    }
    let section_anchor_names = collect_section_anchor_signals();
    let section_anchor_root = append_private_input_anchor_chain(
        &mut builder,
        &section_anchor_names,
        "tb_section_anchor",
    )?;
    let barrier_shape_names = collect_barrier_shape_signals();
    let _barrier_shape_anchor_root = append_private_input_anchor_chain(
        &mut builder,
        &barrier_shape_names,
        "tb_barrier_shape_anchor",
    )?;

    let mut previous_damage = Vec::new();
    let mut previous_crack = Vec::new();
    for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
        let damage = format!("tb_section_{section}_damage_0");
        let crack = format!("tb_section_{section}_crack_0");
        builder.private_signal(&damage)?;
        builder.bind(&damage, const_expr(0))?;
        builder.constrain_range(&damage, damage_bits)?;
        builder.private_signal(&crack)?;
        builder.bind(
            &crack,
            signal_expr(&material_field_name("initial_crack_length")),
        )?;
        builder.constrain_range(&crack, damage_bits)?;
        previous_damage.push(damage);
        previous_crack.push(crack);
    }

    let policy_hash_0 = builder.append_poseidon_hash(
        "tb_policy_anchor_0",
        [
            signal_expr(&material_field_name("initial_crack_length")),
            signal_expr(&material_field_name("damage_limit")),
            signal_expr(&material_field_name("crack_limit")),
            signal_expr(&material_field_name("reserve_margin_min")),
        ],
    )?;
    let policy_hash_1 = builder.append_poseidon_hash(
        "tb_policy_anchor_1",
        [
            signal_expr(&policy_hash_0),
            signal_expr(&material_field_name("fracture_toughness_proxy")),
            signal_expr(&threshold_field_name("allowable_stress", 0)),
            signal_expr(&threshold_field_name("allowable_temperature", 0)),
        ],
    )?;
    let policy_hash_2 = builder.append_poseidon_hash(
        "tb_policy_anchor_2",
        [
            signal_expr(&policy_hash_1),
            signal_expr(&threshold_field_name("allowable_stress", 1)),
            signal_expr(&threshold_field_name("allowable_stress", 2)),
            signal_expr(&threshold_field_name("allowable_temperature", 1)),
        ],
    )?;
    let policy_hash_3 = builder.append_poseidon_hash(
        "tb_policy_anchor_3",
        [
            signal_expr(&input_anchor_root),
            signal_expr(&policy_hash_2),
            signal_expr(&section_anchor_root),
            const_expr(0),
        ],
    )?;
    let _policy_hash_4 = builder.append_poseidon_hash(
        "tb_policy_anchor_4",
        [
            signal_expr(&policy_hash_3),
            const_expr(0),
            const_expr(0),
            const_expr(0),
        ],
    )?;

    let mut running_min_margin_shifted = String::new();
    let mut thermal_gap_names = Vec::new();

    for step in 0..steps {
        let mut section_margin_names = Vec::new();
        let rpm = mission_field_name("rpm", step);
        let gas = mission_field_name("gas_temp", step);
        let surface = mission_field_name("surface_temp", step);
        let cent = mission_field_name("centrifugal_factor", step);
        let press = mission_field_name("pressure_factor", step);

        for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
            let prefix = step_section_prefix(step, section);
            let thermal_gap = format!("{prefix}_thermal_gap");
            thermal_gap_names.push(thermal_gap.clone());
            builder.private_signal(&thermal_gap)?;
            builder.bind(
                &thermal_gap,
                sub_expr(signal_expr(&gas), signal_expr(&surface)),
            )?;
            builder.constrain_range(&thermal_gap, input_bits)?;

            let metal_temp = format!("{prefix}_metal_temp");
            builder.private_signal(&metal_temp)?;
            builder.bind(
                &metal_temp,
                add_expr(vec![
                    signal_expr(&surface),
                    signal_expr(&thermal_gap),
                    signal_expr(&format!("tb_section_{section}_barrier_shape")),
                ]),
            )?;
            builder.constrain_range(&metal_temp, input_bits)?;
            builder.constrain_leq(
                format!("{prefix}_metal_temp_model_limit"),
                signal_expr(&metal_temp),
                const_expr(MODEL_MAX_METAL_TEMP),
                input_bits,
            )?;

            let thermal_strain = format!("{prefix}_thermal_strain");
            builder.private_signal(&thermal_strain)?;
            builder.bind(
                &thermal_strain,
                mul_expr(
                    signal_expr(&material_field_name("thermal_expansion_coeff")),
                    add_expr(vec![
                        signal_expr(&metal_temp),
                        signal_expr(&format!("tb_section_{section}_radius")),
                    ]),
                ),
            )?;
            builder.constrain_range(&thermal_strain, stress_bits)?;

            let rpm_sq = format!("{prefix}_rpm_sq");
            builder.private_signal(&rpm_sq)?;
            builder.bind(&rpm_sq, mul_expr(signal_expr(&rpm), signal_expr(&rpm)))?;
            builder.constrain_range(&rpm_sq, stress_bits)?;

            let sigma_cf = format!("{prefix}_sigma_cf");
            builder.private_signal(&sigma_cf)?;
            builder.bind(
                &sigma_cf,
                mul_expr(
                    mul_expr(
                        mul_expr(
                            signal_expr(&material_field_name("density")),
                            signal_expr(&format!("tb_section_{section}_radius")),
                        ),
                        signal_expr(&rpm_sq),
                    ),
                    signal_expr(&cent),
                ),
            )?;
            builder.constrain_range(&sigma_cf, stress_bits)?;

            let sigma_pr = format!("{prefix}_sigma_pr");
            builder.private_signal(&sigma_pr)?;
            builder.bind(
                &sigma_pr,
                mul_expr(
                    mul_expr(signal_expr(&press), signal_expr(&gas)),
                    add_expr(vec![
                        signal_expr(&format!("tb_section_{section}_geometry_shape")),
                        signal_expr(&material_field_name("poissons_ratio")),
                        const_expr(1),
                    ]),
                ),
            )?;
            builder.constrain_range(&sigma_pr, stress_bits)?;

            let sigma_th = format!("{prefix}_sigma_th");
            builder.private_signal(&sigma_th)?;
            builder.bind(
                &sigma_th,
                mul_expr(
                    signal_expr(&material_field_name("youngs_modulus")),
                    signal_expr(&thermal_strain),
                ),
            )?;
            builder.constrain_range(&sigma_th, stress_bits)?;

            let sigma_eq = format!("{prefix}_sigma_eq");
            builder.private_signal(&sigma_eq)?;
            builder.bind(
                &sigma_eq,
                add_expr(vec![
                    signal_expr(&sigma_cf),
                    signal_expr(&sigma_pr),
                    signal_expr(&sigma_th),
                ]),
            )?;
            builder.constrain_range(&sigma_eq, stress_bits)?;
            builder.constrain_leq(
                format!("{prefix}_sigma_eq_model_limit"),
                signal_expr(&sigma_eq),
                const_expr(MODEL_MAX_STRESS),
                stress_bits,
            )?;

            let fatigue_inc = format!("{prefix}_fatigue_inc");
            builder.private_signal(&fatigue_inc)?;
            builder.bind(
                &fatigue_inc,
                add_expr(vec![
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 0)),
                        signal_expr(&sigma_eq),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 1)),
                        signal_expr(&metal_temp),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 2)),
                        signal_expr(&press),
                    ),
                ]),
            )?;
            builder.constrain_range(&fatigue_inc, damage_bits)?;

            let creep_inc = format!("{prefix}_creep_inc");
            builder.private_signal(&creep_inc)?;
            builder.bind(
                &creep_inc,
                add_expr(vec![
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 0)),
                        signal_expr(&metal_temp),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 1)),
                        signal_expr(&sigma_eq),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 2)),
                        signal_expr(&cent),
                    ),
                ]),
            )?;
            builder.constrain_range(&creep_inc, damage_bits)?;

            let damage_next = format!("tb_section_{section}_damage_{}", step + 1);
            builder.private_signal(&damage_next)?;
            builder.bind(
                &damage_next,
                add_expr(vec![
                    signal_expr(&previous_damage[section]),
                    signal_expr(&fatigue_inc),
                    signal_expr(&creep_inc),
                ]),
            )?;
            builder.constrain_range(&damage_next, damage_bits)?;

            let crack_inc = format!("{prefix}_crack_inc");
            builder.private_signal(&crack_inc)?;
            builder.bind(
                &crack_inc,
                add_expr(vec![
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 0)),
                        add_expr(vec![
                            signal_expr(&sigma_eq),
                            signal_expr(&material_field_name("fracture_toughness_proxy")),
                        ]),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 1)),
                        signal_expr(&surface),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("fatigue", 2)),
                        add_expr(vec![
                            signal_expr(&material_field_name("initial_crack_length")),
                            signal_expr(&format!("tb_section_{section}_radius")),
                        ]),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 0)),
                        signal_expr(&press),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 1)),
                        signal_expr(&gas),
                    ),
                    mul_expr(
                        signal_expr(&material_coeff_name("creep", 2)),
                        signal_expr(&cent),
                    ),
                ]),
            )?;
            builder.constrain_range(&crack_inc, damage_bits)?;

            let crack_next = format!("tb_section_{section}_crack_{}", step + 1);
            builder.private_signal(&crack_next)?;
            builder.bind(
                &crack_next,
                add_expr(vec![
                    signal_expr(&previous_crack[section]),
                    signal_expr(&crack_inc),
                ]),
            )?;
            builder.constrain_range(&crack_next, damage_bits)?;

            let stress_margin_shifted = format!("{prefix}_stress_margin_shifted");
            builder.private_signal(&stress_margin_shifted)?;
            builder.bind(
                &stress_margin_shifted,
                add_expr(vec![
                    const_expr(MARGIN_OFFSET),
                    signal_expr(&threshold_field_name("allowable_stress", section)),
                    sub_expr(const_expr(0), signal_expr(&sigma_eq)),
                ]),
            )?;
            builder.constrain_range(&stress_margin_shifted, shifted_margin_bits)?;

            let temp_margin_shifted = format!("{prefix}_temp_margin_shifted");
            builder.private_signal(&temp_margin_shifted)?;
            builder.bind(
                &temp_margin_shifted,
                add_expr(vec![
                    const_expr(MARGIN_OFFSET),
                    signal_expr(&threshold_field_name("allowable_temperature", section)),
                    sub_expr(const_expr(0), signal_expr(&metal_temp)),
                ]),
            )?;
            builder.constrain_range(&temp_margin_shifted, shifted_margin_bits)?;

            let damage_margin_shifted = format!("{prefix}_damage_margin_shifted");
            builder.private_signal(&damage_margin_shifted)?;
            builder.bind(
                &damage_margin_shifted,
                add_expr(vec![
                    const_expr(MARGIN_OFFSET),
                    signal_expr(&material_field_name("damage_limit")),
                    sub_expr(const_expr(0), signal_expr(&damage_next)),
                ]),
            )?;
            builder.constrain_range(&damage_margin_shifted, shifted_margin_bits)?;

            let crack_margin_shifted = format!("{prefix}_crack_margin_shifted");
            builder.private_signal(&crack_margin_shifted)?;
            builder.bind(
                &crack_margin_shifted,
                add_expr(vec![
                    const_expr(MARGIN_OFFSET),
                    signal_expr(&material_field_name("crack_limit")),
                    sub_expr(const_expr(0), signal_expr(&crack_next)),
                ]),
            )?;
            builder.constrain_range(&crack_margin_shifted, shifted_margin_bits)?;

            let pair_min_0 = format!("{prefix}_margin_pair_min_0");
            append_pairwise_min_signal(
                &mut builder,
                &pair_min_0,
                &stress_margin_shifted,
                &temp_margin_shifted,
                SHIFTED_MARGIN_MAX,
                &format!("{prefix}_margin_pair_0"),
            )?;
            let pair_min_1 = format!("{prefix}_margin_pair_min_1");
            append_pairwise_min_signal(
                &mut builder,
                &pair_min_1,
                &damage_margin_shifted,
                &crack_margin_shifted,
                SHIFTED_MARGIN_MAX,
                &format!("{prefix}_margin_pair_1"),
            )?;
            let section_margin_shifted = format!("{prefix}_margin_shifted");
            append_pairwise_min_signal(
                &mut builder,
                &section_margin_shifted,
                &pair_min_0,
                &pair_min_1,
                SHIFTED_MARGIN_MAX,
                &format!("{prefix}_margin_pair_2"),
            )?;
            section_margin_names.push(section_margin_shifted);
            previous_damage[section] = damage_next;
            previous_crack[section] = crack_next;
        }

        let step_margin_shifted_a = format!("tb_step_{step}_margin_shifted_a");
        append_pairwise_min_signal(
            &mut builder,
            &step_margin_shifted_a,
            &section_margin_names[0],
            &section_margin_names[1],
            SHIFTED_MARGIN_MAX,
            &format!("tb_step_{step}_margin_reduce_0"),
        )?;
        let step_margin_shifted = format!("tb_step_{step}_margin_shifted");
        append_pairwise_min_signal(
            &mut builder,
            &step_margin_shifted,
            &step_margin_shifted_a,
            &section_margin_names[2],
            SHIFTED_MARGIN_MAX,
            &format!("tb_step_{step}_margin_reduce_1"),
        )?;

        if step == 0 {
            running_min_margin_shifted = step_margin_shifted;
        } else {
            let next_running = if step == steps - 1 {
                "tb_final_min_margin_shifted".to_string()
            } else {
                format!("tb_running_min_margin_shifted_{step}")
            };
            append_pairwise_min_signal(
                &mut builder,
                &next_running,
                &running_min_margin_shifted,
                &step_margin_shifted,
                SHIFTED_MARGIN_MAX,
                &format!("tb_running_margin_reduce_{step}"),
            )?;
            running_min_margin_shifted = next_running;
        }
    }
    let _thermal_gap_anchor_root = append_private_input_anchor_chain(
        &mut builder,
        &thermal_gap_names,
        "tb_thermal_gap_anchor",
    )?;

    if steps == 1 {
        builder.private_signal("tb_final_min_margin_shifted")?;
        builder.bind(
            "tb_final_min_margin_shifted",
            signal_expr(&running_min_margin_shifted),
        )?;
        builder.constrain_range("tb_final_min_margin_shifted", shifted_margin_bits)?;
    }

    let final_damage_a = "tb_final_damage_a".to_string();
    append_pairwise_max_signal(
        &mut builder,
        &final_damage_a,
        &previous_damage[0],
        &previous_damage[1],
        DAMAGE_MAX,
        "tb_final_damage_reduce_0",
    )?;
    builder.private_signal("tb_final_damage")?;
    append_pairwise_max_signal(
        &mut builder,
        "tb_final_damage",
        &final_damage_a,
        &previous_damage[2],
        DAMAGE_MAX,
        "tb_final_damage_reduce_1",
    )?;

    let final_crack_a = "tb_final_crack_a".to_string();
    append_pairwise_max_signal(
        &mut builder,
        &final_crack_a,
        &previous_crack[0],
        &previous_crack[1],
        DAMAGE_MAX,
        "tb_final_crack_reduce_0",
    )?;
    builder.private_signal("tb_final_crack")?;
    append_pairwise_max_signal(
        &mut builder,
        "tb_final_crack",
        &final_crack_a,
        &previous_crack[2],
        DAMAGE_MAX,
        "tb_final_crack_reduce_1",
    )?;

    builder.private_signal("tb_final_damage_margin_shifted")?;
    builder.bind(
        "tb_final_damage_margin_shifted",
        add_expr(vec![
            const_expr(MARGIN_OFFSET),
            signal_expr(&material_field_name("damage_limit")),
            sub_expr(const_expr(0), signal_expr("tb_final_damage")),
        ]),
    )?;
    builder.constrain_range("tb_final_damage_margin_shifted", shifted_margin_bits)?;
    builder.private_signal("tb_final_crack_margin_shifted")?;
    builder.bind(
        "tb_final_crack_margin_shifted",
        add_expr(vec![
            const_expr(MARGIN_OFFSET),
            signal_expr(&material_field_name("crack_limit")),
            sub_expr(const_expr(0), signal_expr("tb_final_crack")),
        ]),
    )?;
    builder.constrain_range("tb_final_crack_margin_shifted", shifted_margin_bits)?;
    append_pairwise_min_signal(
        &mut builder,
        "tb_final_remaining_life_shifted",
        "tb_final_damage_margin_shifted",
        "tb_final_crack_margin_shifted",
        SHIFTED_MARGIN_MAX,
        "tb_final_remaining_life_reduce",
    )?;

    builder.private_signal("tb_final_remaining_life")?;
    builder.bind(
        "tb_final_remaining_life",
        sub_expr(
            signal_expr("tb_final_remaining_life_shifted"),
            const_expr(MARGIN_OFFSET),
        ),
    )?;
    builder.private_signal("tb_final_min_margin")?;
    builder.bind(
        "tb_final_min_margin",
        sub_expr(
            signal_expr("tb_final_min_margin_shifted"),
            const_expr(MARGIN_OFFSET),
        ),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&material_field_name("damage_limit")),
        signal_expr("tb_final_damage"),
        "tb_final_damage_ok",
        "tb_final_damage_ok_slack",
        DAMAGE_MAX,
        "tb_final_damage_ok",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&material_field_name("crack_limit")),
        signal_expr("tb_final_crack"),
        "tb_final_crack_ok",
        "tb_final_crack_ok_slack",
        DAMAGE_MAX,
        "tb_final_crack_ok",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("tb_final_min_margin_shifted"),
        add_expr(vec![
            const_expr(MARGIN_OFFSET),
            signal_expr(&material_field_name("reserve_margin_min")),
        ]),
        "tb_final_margin_ok",
        "tb_final_margin_ok_slack",
        SHIFTED_MARGIN_MAX,
        "tb_final_margin_ok",
    )?;
    append_boolean_and(
        &mut builder,
        "tb_safe_partial",
        "tb_final_damage_ok",
        "tb_final_crack_ok",
    )?;
    builder.bind(
        "safe_to_deploy",
        mul_expr(
            signal_expr("tb_safe_partial"),
            signal_expr("tb_final_margin_ok"),
        ),
    )?;

    let damage_commit = builder.append_poseidon_hash(
        "tb_damage_commitment_hash",
        [
            signal_expr("tb_final_damage"),
            signal_expr(&commitment_blinder_field_name("damage", 0)),
            signal_expr(&commitment_blinder_field_name("damage", 1)),
            const_expr(COMMITMENT_DOMAIN_DAMAGE),
        ],
    )?;
    builder.bind("damage_commitment", signal_expr(&damage_commit))?;
    let crack_commit = builder.append_poseidon_hash(
        "tb_crack_commitment_hash",
        [
            signal_expr("tb_final_crack"),
            signal_expr(&commitment_blinder_field_name("crack", 0)),
            signal_expr(&commitment_blinder_field_name("crack", 1)),
            const_expr(COMMITMENT_DOMAIN_CRACK),
        ],
    )?;
    builder.bind("crack_commitment", signal_expr(&crack_commit))?;
    let remaining_commit = builder.append_poseidon_hash(
        "tb_remaining_life_commitment_hash",
        [
            signal_expr("tb_final_remaining_life"),
            signal_expr(&commitment_blinder_field_name("remaining_life", 0)),
            signal_expr(&commitment_blinder_field_name("remaining_life", 1)),
            const_expr(COMMITMENT_DOMAIN_REMAINING_LIFE),
        ],
    )?;
    builder.bind("remaining_life_commitment", signal_expr(&remaining_commit))?;
    let margin_commit = builder.append_poseidon_hash(
        "tb_margin_commitment_hash",
        [
            signal_expr("tb_final_min_margin"),
            signal_expr(&commitment_blinder_field_name("min_margin", 0)),
            signal_expr(&commitment_blinder_field_name("min_margin", 1)),
            const_expr(COMMITMENT_DOMAIN_MARGIN),
        ],
    )?;
    builder.bind("min_margin_commitment", signal_expr(&margin_commit))?;

    builder.build()
}

fn sample_geometry() -> Vec<TurbineBladeGeometryStationV1> {
    vec![
        TurbineBladeGeometryStationV1 {
            radius: 48,
            chord: 18,
            max_thickness: 6,
            camber: 3,
            twist_deg: 2,
            wall_thickness: 5,
            coating_thickness: 3,
            tbc_effectiveness: 8,
        },
        TurbineBladeGeometryStationV1 {
            radius: 49,
            chord: 18,
            max_thickness: 6,
            camber: 3,
            twist_deg: 2,
            wall_thickness: 5,
            coating_thickness: 3,
            tbc_effectiveness: 8,
        },
        TurbineBladeGeometryStationV1 {
            radius: 50,
            chord: 17,
            max_thickness: 6,
            camber: 3,
            twist_deg: 2,
            wall_thickness: 5,
            coating_thickness: 3,
            tbc_effectiveness: 8,
        },
        TurbineBladeGeometryStationV1 {
            radius: 51,
            chord: 16,
            max_thickness: 5,
            camber: 2,
            twist_deg: 2,
            wall_thickness: 4,
            coating_thickness: 3,
            tbc_effectiveness: 9,
        },
        TurbineBladeGeometryStationV1 {
            radius: 52,
            chord: 15,
            max_thickness: 5,
            camber: 2,
            twist_deg: 2,
            wall_thickness: 4,
            coating_thickness: 3,
            tbc_effectiveness: 9,
        },
        TurbineBladeGeometryStationV1 {
            radius: 53,
            chord: 15,
            max_thickness: 5,
            camber: 2,
            twist_deg: 3,
            wall_thickness: 4,
            coating_thickness: 2,
            tbc_effectiveness: 9,
        },
        TurbineBladeGeometryStationV1 {
            radius: 54,
            chord: 14,
            max_thickness: 4,
            camber: 2,
            twist_deg: 3,
            wall_thickness: 4,
            coating_thickness: 2,
            tbc_effectiveness: 9,
        },
        TurbineBladeGeometryStationV1 {
            radius: 55,
            chord: 13,
            max_thickness: 4,
            camber: 2,
            twist_deg: 4,
            wall_thickness: 3,
            coating_thickness: 2,
            tbc_effectiveness: 9,
        },
    ]
}

pub fn private_turbine_blade_life_sample_request_with_steps(
    steps: usize,
) -> TurbineBladeLifeRequestV1 {
    let mut mission_profile = Vec::with_capacity(steps);
    for step in 0..steps {
        mission_profile.push(TurbineBladeMissionStepV1 {
            rotational_speed: 4 + (step % 3) as u64,
            gas_temperature: 55 + (step % 5) as u64,
            blade_surface_temperature: 42 + (step % 4) as u64,
            centrifugal_load_factor: 2 + (step % 2) as u64,
            pressure_load_factor: 3 + (step % 2) as u64,
        });
    }
    TurbineBladeLifeRequestV1 {
        geometry_stations: sample_geometry(),
        material: TurbineBladeMaterialPropertiesV1 {
            youngs_modulus: 3,
            poissons_ratio: 1,
            thermal_expansion_coeff: 1,
            density: 2,
            creep_coeffs: [1, 1, 1],
            fatigue_coeffs: [1, 1, 1],
            fracture_toughness_proxy: 5,
        },
        initial_crack_length: 4,
        mission_profile,
        thresholds: TurbineBladeThresholdsV1 {
            allowable_stress: [120_000, 120_000, 120_000],
            allowable_temperature: [120, 120, 120],
            damage_limit: 80_000_000,
            crack_limit: 80_000_000,
            reserve_margin_min: 10,
        },
        commitment_blinders: TurbineBladeCommitmentBlindersV1 {
            damage_commitment: [101, 202],
            crack_commitment: [303, 404],
            remaining_life_commitment: [505, 606],
            min_margin_commitment: [707, 808],
        },
    }
}

pub fn private_turbine_blade_life_sample_request() -> TurbineBladeLifeRequestV1 {
    private_turbine_blade_life_sample_request_with_steps(PRIVATE_TURBINE_BLADE_DEFAULT_STEPS)
}

pub fn private_turbine_blade_life_violation_request_with_steps(
    steps: usize,
) -> TurbineBladeLifeRequestV1 {
    let mut request = private_turbine_blade_life_sample_request_with_steps(steps);
    request.thresholds.damage_limit = 5_000_000;
    request.thresholds.crack_limit = 5_000_000;
    request.thresholds.allowable_stress = [50_000, 50_000, 50_000];
    request.thresholds.reserve_margin_min = 30_000;
    request
}

pub fn private_turbine_blade_life_sample_inputs_with_steps(steps: usize) -> WitnessInputs {
    request_to_inputs(&private_turbine_blade_life_sample_request_with_steps(steps))
}

pub fn private_turbine_blade_life_sample_inputs() -> WitnessInputs {
    private_turbine_blade_life_sample_inputs_with_steps(PRIVATE_TURBINE_BLADE_DEFAULT_STEPS)
}

pub fn private_turbine_blade_life_violation_inputs_with_steps(steps: usize) -> WitnessInputs {
    request_to_inputs(&private_turbine_blade_life_violation_request_with_steps(
        steps,
    ))
}

fn materialize_seeded_witness(program: &Program, values: WitnessInputs) -> ZkfResult<Witness> {
    generate_witness(program, &values)
}

pub fn private_turbine_blade_life_witness_from_request_with_steps(
    request: &TurbineBladeLifeRequestV1,
    steps: usize,
) -> ZkfResult<Witness> {
    validate_request(request, steps)?;
    let mut values = request_to_inputs(request);
    let raw_input_names = collect_expected_inputs(steps);
    let input_anchor_root =
        write_private_input_anchor_chain(&mut values, &raw_input_names, "tb_input_anchor")?;
    write_section_copy_signals(&mut values, request);
    write_section_barrier_shapes(&mut values, request);
    let section_anchor_names = collect_section_anchor_signals();
    let section_anchor_root =
        write_private_input_anchor_chain(&mut values, &section_anchor_names, "tb_section_anchor")?;
    let barrier_shape_names = collect_barrier_shape_signals();
    let _barrier_shape_anchor_root = write_private_input_anchor_chain(
        &mut values,
        &barrier_shape_names,
        "tb_barrier_shape_anchor",
    )?;

    let damage_limit = BigInt::from(request.thresholds.damage_limit);
    let crack_limit = BigInt::from(request.thresholds.crack_limit);
    let reserve_margin = BigInt::from(request.thresholds.reserve_margin_min);
    let fracture = BigInt::from(request.material.fracture_toughness_proxy);
    let initial_crack = BigInt::from(request.initial_crack_length);
    let density = BigInt::from(request.material.density);
    let youngs = BigInt::from(request.material.youngs_modulus);
    let poisson = BigInt::from(request.material.poissons_ratio);
    let alpha = BigInt::from(request.material.thermal_expansion_coeff);
    let fatigue_coeffs = request.material.fatigue_coeffs.map(BigInt::from);
    let creep_coeffs = request.material.creep_coeffs.map(BigInt::from);

    let station_data = CONTROL_SECTION_SOURCE_STATIONS
        .iter()
        .map(|station| &request.geometry_stations[*station])
        .collect::<Vec<_>>();

    let mut previous_damage = [zero(), zero(), zero()];
    let mut previous_crack = [
        initial_crack.clone(),
        initial_crack.clone(),
        initial_crack.clone(),
    ];
    let mut running_min_margin_shifted = BigInt::from(SHIFTED_MARGIN_MAX);

    let policy_hash_0 =
        poseidon_permutation4([&initial_crack, &damage_limit, &crack_limit, &reserve_margin])?;
    let policy_hash_0_value = write_hash_lanes(&mut values, "tb_policy_anchor_0", policy_hash_0);
    let allow_stress_root = BigInt::from(request.thresholds.allowable_stress[0]);
    let allow_temp_root = BigInt::from(request.thresholds.allowable_temperature[0]);
    let policy_hash_1 = poseidon_permutation4([
        &policy_hash_0_value,
        &fracture,
        &allow_stress_root,
        &allow_temp_root,
    ])?;
    let policy_hash_1_value = write_hash_lanes(&mut values, "tb_policy_anchor_1", policy_hash_1);
    let policy_hash_2 = poseidon_permutation4([
        &policy_hash_1_value,
        &BigInt::from(request.thresholds.allowable_stress[1]),
        &BigInt::from(request.thresholds.allowable_stress[2]),
        &BigInt::from(request.thresholds.allowable_temperature[1]),
    ])?;
    let policy_hash_2_value = write_hash_lanes(&mut values, "tb_policy_anchor_2", policy_hash_2);
    let policy_hash_3 = poseidon_permutation4([
        &input_anchor_root,
        &policy_hash_2_value,
        &section_anchor_root,
        &zero(),
    ])?;
    let policy_hash_3_value = write_hash_lanes(&mut values, "tb_policy_anchor_3", policy_hash_3);
    let policy_hash_4 = poseidon_permutation4([&policy_hash_3_value, &zero(), &zero(), &zero()])?;
    write_hash_lanes(&mut values, "tb_policy_anchor_4", policy_hash_4);

    for step in 0..steps {
        let mission = &request.mission_profile[step];
        let rpm = BigInt::from(mission.rotational_speed);
        let gas = BigInt::from(mission.gas_temperature);
        let surface = BigInt::from(mission.blade_surface_temperature);
        let cent = BigInt::from(mission.centrifugal_load_factor);
        let press = BigInt::from(mission.pressure_load_factor);
        let mut section_margins = Vec::new();

        for section in 0..PRIVATE_TURBINE_BLADE_CONTROL_SECTIONS {
            let prefix = step_section_prefix(step, section);
            let station = station_data[section];
            let radius = BigInt::from(station.radius);
            let chord = BigInt::from(station.chord);
            let thickness = BigInt::from(station.max_thickness);
            let camber = BigInt::from(station.camber);
            let twist = BigInt::from(station.twist_deg);
            let wall = BigInt::from(station.wall_thickness);
            let coating = BigInt::from(station.coating_thickness);
            let tbc = BigInt::from(station.tbc_effectiveness);

            let thermal_gap = &gas - &surface;
            let barrier_shape = &coating + &tbc + &twist + &camber + BigInt::from(1u8);
            let metal_temp = &surface + &thermal_gap + &barrier_shape;
            let thermal_input = &metal_temp + &radius;
            let thermal_strain = &alpha * &thermal_input;
            let rpm_sq = &rpm * &rpm;
            let chord_thickness = &chord * &thickness;
            let geometry_shape = &chord_thickness + &wall + &camber + BigInt::from(1u8);
            let sigma_cf_core = &density * &radius;
            let sigma_cf_spin = &sigma_cf_core * &rpm_sq;
            let sigma_cf = &sigma_cf_spin * &cent;
            let pressure_shape = &geometry_shape + &poisson + BigInt::from(1u8);
            let sigma_pr_core = &press * &gas;
            let sigma_pr = &sigma_pr_core * &pressure_shape;
            let sigma_th = &youngs * &thermal_strain;
            let sigma_eq = &sigma_cf + &sigma_pr + &sigma_th;
            let fatigue_stress = &fatigue_coeffs[0] * &sigma_eq;
            let fatigue_temp = &fatigue_coeffs[1] * &metal_temp;
            let fatigue_load = &fatigue_coeffs[2] * &press;
            let fatigue_inc = &fatigue_stress + &fatigue_temp + &fatigue_load;
            let creep_temp = &creep_coeffs[0] * &metal_temp;
            let creep_stress = &creep_coeffs[1] * &sigma_eq;
            let creep_load = &creep_coeffs[2] * &cent;
            let creep_inc = &creep_temp + &creep_stress + &creep_load;
            let damage_core = &previous_damage[section] + &fatigue_inc;
            let damage_next = &damage_core + &creep_inc;
            let crack_drive = &sigma_eq + &fracture;
            let crack_fatigue = &fatigue_coeffs[0] * &crack_drive;
            let crack_surface = &fatigue_coeffs[1] * &surface;
            let crack_geometry = &fatigue_coeffs[2] * (&initial_crack + &radius);
            let crack_press = &creep_coeffs[0] * &press;
            let crack_gas = &creep_coeffs[1] * &gas;
            let crack_cent = &creep_coeffs[2] * &cent;
            let crack_partial = &crack_fatigue + &crack_surface + &crack_geometry;
            let crack_support = &crack_press + &crack_gas + &crack_cent;
            let crack_inc = &crack_partial + &crack_support;
            let crack_next = &previous_crack[section] + &crack_inc;

            let stress_margin_shifted = BigInt::from(MARGIN_OFFSET)
                + BigInt::from(request.thresholds.allowable_stress[section])
                - &sigma_eq;
            let temp_margin_shifted = BigInt::from(MARGIN_OFFSET)
                + BigInt::from(request.thresholds.allowable_temperature[section])
                - &metal_temp;
            let damage_margin_shifted = BigInt::from(MARGIN_OFFSET) + &damage_limit - &damage_next;
            let crack_margin_shifted = BigInt::from(MARGIN_OFFSET) + &crack_limit - &crack_next;

            for (name, value, bound) in [
                (
                    format!("{prefix}_thermal_gap"),
                    thermal_gap.clone(),
                    INPUT_MAX,
                ),
                (
                    format!("{prefix}_metal_temp"),
                    metal_temp.clone(),
                    MODEL_MAX_METAL_TEMP,
                ),
                (
                    format!("{prefix}_thermal_strain"),
                    thermal_strain.clone(),
                    STRESS_MAX,
                ),
                (format!("{prefix}_rpm_sq"), rpm_sq.clone(), STRESS_MAX),
                (format!("{prefix}_sigma_cf"), sigma_cf.clone(), STRESS_MAX),
                (format!("{prefix}_sigma_pr"), sigma_pr.clone(), STRESS_MAX),
                (format!("{prefix}_sigma_th"), sigma_th.clone(), STRESS_MAX),
                (
                    format!("{prefix}_sigma_eq"),
                    sigma_eq.clone(),
                    MODEL_MAX_STRESS,
                ),
                (
                    format!("{prefix}_fatigue_inc"),
                    fatigue_inc.clone(),
                    DAMAGE_MAX,
                ),
                (format!("{prefix}_creep_inc"), creep_inc.clone(), DAMAGE_MAX),
                (
                    format!("tb_section_{section}_damage_{}", step + 1),
                    damage_next.clone(),
                    DAMAGE_MAX,
                ),
                (format!("{prefix}_crack_inc"), crack_inc.clone(), DAMAGE_MAX),
                (
                    format!("tb_section_{section}_crack_{}", step + 1),
                    crack_next.clone(),
                    DAMAGE_MAX,
                ),
                (
                    format!("{prefix}_stress_margin_shifted"),
                    stress_margin_shifted.clone(),
                    SHIFTED_MARGIN_MAX,
                ),
                (
                    format!("{prefix}_temp_margin_shifted"),
                    temp_margin_shifted.clone(),
                    SHIFTED_MARGIN_MAX,
                ),
                (
                    format!("{prefix}_damage_margin_shifted"),
                    damage_margin_shifted.clone(),
                    SHIFTED_MARGIN_MAX,
                ),
                (
                    format!("{prefix}_crack_margin_shifted"),
                    crack_margin_shifted.clone(),
                    SHIFTED_MARGIN_MAX,
                ),
            ] {
                if value < zero() || value > BigInt::from(bound) {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "{name} left the modeled bounds at step {step}, section {section}"
                    )));
                }
                write_value(&mut values, name, value);
            }

            let pair_min_0_prefix = format!("{prefix}_margin_pair_0");
            let pair_min_0 = if stress_margin_shifted <= temp_margin_shifted {
                stress_margin_shifted.clone()
            } else {
                temp_margin_shifted.clone()
            };
            write_bool_value(
                &mut values,
                format!("{pair_min_0_prefix}_geq_bit"),
                stress_margin_shifted >= temp_margin_shifted,
            );
            let pair_min_0_slack = comparator_slack(
                &stress_margin_shifted,
                &temp_margin_shifted,
                &positive_comparison_offset(SHIFTED_MARGIN_MAX),
            );
            write_nonnegative_support(
                &mut values,
                format!("{pair_min_0_prefix}_geq_slack"),
                &pair_min_0_slack,
                SHIFTED_MARGIN_MAX,
                &pair_min_0_prefix,
            )?;

            let pair_min_1_prefix = format!("{prefix}_margin_pair_1");
            let pair_min_1 = if damage_margin_shifted <= crack_margin_shifted {
                damage_margin_shifted.clone()
            } else {
                crack_margin_shifted.clone()
            };
            write_bool_value(
                &mut values,
                format!("{pair_min_1_prefix}_geq_bit"),
                damage_margin_shifted >= crack_margin_shifted,
            );
            let pair_min_1_slack = comparator_slack(
                &damage_margin_shifted,
                &crack_margin_shifted,
                &positive_comparison_offset(SHIFTED_MARGIN_MAX),
            );
            write_nonnegative_support(
                &mut values,
                format!("{pair_min_1_prefix}_geq_slack"),
                &pair_min_1_slack,
                SHIFTED_MARGIN_MAX,
                &pair_min_1_prefix,
            )?;

            let pair_min_2_prefix = format!("{prefix}_margin_pair_2");
            let section_margin = if pair_min_0 <= pair_min_1 {
                pair_min_0.clone()
            } else {
                pair_min_1.clone()
            };
            write_bool_value(
                &mut values,
                format!("{pair_min_2_prefix}_geq_bit"),
                pair_min_0 >= pair_min_1,
            );
            let pair_min_2_slack = comparator_slack(
                &pair_min_0,
                &pair_min_1,
                &positive_comparison_offset(SHIFTED_MARGIN_MAX),
            );
            write_nonnegative_support(
                &mut values,
                format!("{pair_min_2_prefix}_geq_slack"),
                &pair_min_2_slack,
                SHIFTED_MARGIN_MAX,
                &pair_min_2_prefix,
            )?;
            section_margins.push(section_margin);

            previous_damage[section] = damage_next;
            previous_crack[section] = crack_next;
        }

        let reduce_0_prefix = format!("tb_step_{step}_margin_reduce_0");
        let step_margin_a = if section_margins[0] <= section_margins[1] {
            section_margins[0].clone()
        } else {
            section_margins[1].clone()
        };
        write_bool_value(
            &mut values,
            format!("{reduce_0_prefix}_geq_bit"),
            section_margins[0] >= section_margins[1],
        );
        let step_margin_a_slack = comparator_slack(
            &section_margins[0],
            &section_margins[1],
            &positive_comparison_offset(SHIFTED_MARGIN_MAX),
        );
        write_nonnegative_support(
            &mut values,
            format!("{reduce_0_prefix}_geq_slack"),
            &step_margin_a_slack,
            SHIFTED_MARGIN_MAX,
            &reduce_0_prefix,
        )?;

        let reduce_1_prefix = format!("tb_step_{step}_margin_reduce_1");
        let step_margin = if step_margin_a <= section_margins[2] {
            step_margin_a.clone()
        } else {
            section_margins[2].clone()
        };
        write_bool_value(
            &mut values,
            format!("{reduce_1_prefix}_geq_bit"),
            step_margin_a >= section_margins[2],
        );
        let step_margin_slack = comparator_slack(
            &step_margin_a,
            &section_margins[2],
            &positive_comparison_offset(SHIFTED_MARGIN_MAX),
        );
        write_nonnegative_support(
            &mut values,
            format!("{reduce_1_prefix}_geq_slack"),
            &step_margin_slack,
            SHIFTED_MARGIN_MAX,
            &reduce_1_prefix,
        )?;

        if step == 0 {
            running_min_margin_shifted = step_margin;
        } else {
            let running_prefix = format!("tb_running_margin_reduce_{step}");
            write_bool_value(
                &mut values,
                format!("{running_prefix}_geq_bit"),
                running_min_margin_shifted >= step_margin,
            );
            let running_slack = comparator_slack(
                &running_min_margin_shifted,
                &step_margin,
                &positive_comparison_offset(SHIFTED_MARGIN_MAX),
            );
            write_nonnegative_support(
                &mut values,
                format!("{running_prefix}_geq_slack"),
                &running_slack,
                SHIFTED_MARGIN_MAX,
                &running_prefix,
            )?;
            running_min_margin_shifted = if running_min_margin_shifted <= step_margin {
                running_min_margin_shifted
            } else {
                step_margin
            };
        }
    }
    let thermal_gap_names = collect_thermal_gap_signals(steps);
    let _thermal_gap_anchor_root =
        write_private_input_anchor_chain(&mut values, &thermal_gap_names, "tb_thermal_gap_anchor")?;

    write_value(
        &mut values,
        "tb_final_min_margin_shifted",
        running_min_margin_shifted.clone(),
    );

    let final_damage_a_prefix = "tb_final_damage_reduce_0";
    let final_damage_a = if previous_damage[0] >= previous_damage[1] {
        previous_damage[0].clone()
    } else {
        previous_damage[1].clone()
    };
    write_bool_value(
        &mut values,
        format!("{final_damage_a_prefix}_geq_bit"),
        previous_damage[0] >= previous_damage[1],
    );
    let final_damage_a_slack = comparator_slack(
        &previous_damage[0],
        &previous_damage[1],
        &positive_comparison_offset(DAMAGE_MAX),
    );
    write_nonnegative_support(
        &mut values,
        format!("{final_damage_a_prefix}_geq_slack"),
        &final_damage_a_slack,
        DAMAGE_MAX,
        final_damage_a_prefix,
    )?;
    let final_damage_prefix = "tb_final_damage_reduce_1";
    let final_damage = if final_damage_a >= previous_damage[2] {
        final_damage_a.clone()
    } else {
        previous_damage[2].clone()
    };
    write_bool_value(
        &mut values,
        format!("{final_damage_prefix}_geq_bit"),
        final_damage_a >= previous_damage[2],
    );
    let final_damage_slack = comparator_slack(
        &final_damage_a,
        &previous_damage[2],
        &positive_comparison_offset(DAMAGE_MAX),
    );
    write_nonnegative_support(
        &mut values,
        format!("{final_damage_prefix}_geq_slack"),
        &final_damage_slack,
        DAMAGE_MAX,
        final_damage_prefix,
    )?;

    let final_crack_a_prefix = "tb_final_crack_reduce_0";
    let final_crack_a = if previous_crack[0] >= previous_crack[1] {
        previous_crack[0].clone()
    } else {
        previous_crack[1].clone()
    };
    write_bool_value(
        &mut values,
        format!("{final_crack_a_prefix}_geq_bit"),
        previous_crack[0] >= previous_crack[1],
    );
    let final_crack_a_slack = comparator_slack(
        &previous_crack[0],
        &previous_crack[1],
        &positive_comparison_offset(DAMAGE_MAX),
    );
    write_nonnegative_support(
        &mut values,
        format!("{final_crack_a_prefix}_geq_slack"),
        &final_crack_a_slack,
        DAMAGE_MAX,
        final_crack_a_prefix,
    )?;
    let final_crack_prefix = "tb_final_crack_reduce_1";
    let final_crack = if final_crack_a >= previous_crack[2] {
        final_crack_a.clone()
    } else {
        previous_crack[2].clone()
    };
    write_bool_value(
        &mut values,
        format!("{final_crack_prefix}_geq_bit"),
        final_crack_a >= previous_crack[2],
    );
    let final_crack_slack = comparator_slack(
        &final_crack_a,
        &previous_crack[2],
        &positive_comparison_offset(DAMAGE_MAX),
    );
    write_nonnegative_support(
        &mut values,
        format!("{final_crack_prefix}_geq_slack"),
        &final_crack_slack,
        DAMAGE_MAX,
        final_crack_prefix,
    )?;
    write_value(&mut values, "tb_final_damage", final_damage.clone());
    write_value(&mut values, "tb_final_crack", final_crack.clone());

    let final_damage_margin_shifted = BigInt::from(MARGIN_OFFSET) + &damage_limit - &final_damage;
    let final_crack_margin_shifted = BigInt::from(MARGIN_OFFSET) + &crack_limit - &final_crack;
    write_value(
        &mut values,
        "tb_final_damage_margin_shifted",
        final_damage_margin_shifted.clone(),
    );
    write_value(
        &mut values,
        "tb_final_crack_margin_shifted",
        final_crack_margin_shifted.clone(),
    );
    let remaining_reduce_prefix = "tb_final_remaining_life_reduce";
    let remaining_life_shifted = if final_damage_margin_shifted <= final_crack_margin_shifted {
        final_damage_margin_shifted.clone()
    } else {
        final_crack_margin_shifted.clone()
    };
    write_bool_value(
        &mut values,
        format!("{remaining_reduce_prefix}_geq_bit"),
        final_damage_margin_shifted >= final_crack_margin_shifted,
    );
    let remaining_slack = comparator_slack(
        &final_damage_margin_shifted,
        &final_crack_margin_shifted,
        &positive_comparison_offset(SHIFTED_MARGIN_MAX),
    );
    write_nonnegative_support(
        &mut values,
        format!("{remaining_reduce_prefix}_geq_slack"),
        &remaining_slack,
        SHIFTED_MARGIN_MAX,
        remaining_reduce_prefix,
    )?;
    write_value(
        &mut values,
        "tb_final_remaining_life_shifted",
        remaining_life_shifted.clone(),
    );
    write_value(
        &mut values,
        "tb_final_remaining_life",
        remaining_life_shifted.clone() - BigInt::from(MARGIN_OFFSET),
    );
    write_value(
        &mut values,
        "tb_final_min_margin",
        running_min_margin_shifted.clone() - BigInt::from(MARGIN_OFFSET),
    );

    for (prefix, lhs, rhs, bound) in [
        (
            "tb_final_damage_ok",
            damage_limit.clone(),
            final_damage.clone(),
            DAMAGE_MAX,
        ),
        (
            "tb_final_crack_ok",
            crack_limit.clone(),
            final_crack.clone(),
            DAMAGE_MAX,
        ),
        (
            "tb_final_margin_ok",
            running_min_margin_shifted.clone(),
            BigInt::from(MARGIN_OFFSET) + reserve_margin.clone(),
            SHIFTED_MARGIN_MAX,
        ),
    ] {
        write_bool_value(&mut values, prefix, lhs >= rhs);
        let slack = comparator_slack(&lhs, &rhs, &positive_comparison_offset(bound));
        write_nonnegative_support(
            &mut values,
            format!("{prefix}_slack"),
            &slack,
            bound,
            prefix,
        )?;
    }
    let safe_partial = damage_limit >= final_damage && crack_limit >= final_crack;
    write_bool_value(&mut values, "tb_safe_partial", safe_partial);
    let safe = safe_partial
        && running_min_margin_shifted >= (BigInt::from(MARGIN_OFFSET) + reserve_margin);
    write_bool_value(&mut values, "safe_to_deploy", safe);

    let damage_commit = poseidon_permutation4([
        &final_damage,
        &BigInt::from(request.commitment_blinders.damage_commitment[0]),
        &BigInt::from(request.commitment_blinders.damage_commitment[1]),
        &BigInt::from(COMMITMENT_DOMAIN_DAMAGE),
    ])?;
    let damage_commitment =
        write_hash_lanes(&mut values, "tb_damage_commitment_hash", damage_commit);
    write_value(&mut values, "damage_commitment", damage_commitment);

    let crack_commit = poseidon_permutation4([
        &final_crack,
        &BigInt::from(request.commitment_blinders.crack_commitment[0]),
        &BigInt::from(request.commitment_blinders.crack_commitment[1]),
        &BigInt::from(COMMITMENT_DOMAIN_CRACK),
    ])?;
    let crack_commitment = write_hash_lanes(&mut values, "tb_crack_commitment_hash", crack_commit);
    write_value(&mut values, "crack_commitment", crack_commitment);

    let remaining_life_actual = remaining_life_shifted.clone() - BigInt::from(MARGIN_OFFSET);
    let remaining_commit = poseidon_permutation4([
        &remaining_life_actual,
        &BigInt::from(request.commitment_blinders.remaining_life_commitment[0]),
        &BigInt::from(request.commitment_blinders.remaining_life_commitment[1]),
        &BigInt::from(COMMITMENT_DOMAIN_REMAINING_LIFE),
    ])?;
    let remaining_commitment = write_hash_lanes(
        &mut values,
        "tb_remaining_life_commitment_hash",
        remaining_commit,
    );
    write_value(
        &mut values,
        "remaining_life_commitment",
        remaining_commitment,
    );

    let min_margin_actual = running_min_margin_shifted.clone() - BigInt::from(MARGIN_OFFSET);
    let margin_commit = poseidon_permutation4([
        &min_margin_actual,
        &BigInt::from(request.commitment_blinders.min_margin_commitment[0]),
        &BigInt::from(request.commitment_blinders.min_margin_commitment[1]),
        &BigInt::from(COMMITMENT_DOMAIN_MARGIN),
    ])?;
    let min_margin_commitment =
        write_hash_lanes(&mut values, "tb_margin_commitment_hash", margin_commit);
    write_value(&mut values, "min_margin_commitment", min_margin_commitment);

    let program = build_private_turbine_blade_life_program_with_steps(steps)?;
    materialize_seeded_witness(&program, values)
}

pub fn private_turbine_blade_life_witness_from_request(
    request: &TurbineBladeLifeRequestV1,
) -> ZkfResult<Witness> {
    private_turbine_blade_life_witness_from_request_with_steps(
        request,
        PRIVATE_TURBINE_BLADE_DEFAULT_STEPS,
    )
}

pub fn private_turbine_blade_life_showcase() -> ZkfResult<TemplateProgram> {
    private_turbine_blade_life_showcase_with_steps(PRIVATE_TURBINE_BLADE_DEFAULT_STEPS)
}

pub fn private_turbine_blade_life_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    Ok(TemplateProgram {
        program: build_private_turbine_blade_life_program_with_steps(steps)?,
        expected_inputs: collect_expected_inputs(steps),
        public_outputs: vec![
            "damage_commitment".to_string(),
            "crack_commitment".to_string(),
            "remaining_life_commitment".to_string(),
            "min_margin_commitment".to_string(),
            "safe_to_deploy".to_string(),
        ],
        sample_inputs: private_turbine_blade_life_sample_inputs_with_steps(steps),
        violation_inputs: private_turbine_blade_life_violation_inputs_with_steps(steps),
        description: "Prove a private 500-step turbine blade life and safety analysis over a reduced thermal-mechanical surrogate while exposing only committed final state and a public deployment decision.",
    })
}

#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
mod export {
    use super::*;
    use crate::app::api::{EmbeddedProof, capability_matrix, compile, prove, verify};
    use crate::app::audit::audit_program_with_live_capabilities;
    use crate::app::evidence::{
        collect_formal_evidence_for_generated_app, effective_gpu_attribution_summary,
        ensure_dir_exists, ensure_file_exists, ensure_foundry_layout, foundry_project_dir,
        generated_app_closure_bundle_summary, json_pretty, read_json, read_text,
        run_foundry_report, write_json, write_text,
    };
    use crate::app::verifier::export_groth16_solidity_verifier;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
    use zkf_backends::metal_runtime::metal_runtime_report;
    use zkf_backends::{
        BackendSelection, backend_surface_status, prepare_witness_for_proving,
        requested_groth16_setup_blob_path, with_allow_dev_deterministic_groth16_override,
        with_proof_seed_override, with_setup_seed_override,
    };
    use zkf_core::ccs::CcsProgram;
    use zkf_core::{
        BackendKind, CompiledProgram, Program, ProofArtifact, Witness, WitnessInputs,
        check_constraints, optimize_program,
    };
    use zkf_runtime::{
        BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
        RuntimeExecutor, SwarmConfig,
    };

    const APP_ID: &str = "private_turbine_blade_life_showcase";
    const SETUP_SEED: [u8; 32] = [0x54; 32];
    const PROOF_SEED: [u8; 32] = [0x39; 32];
    const DISTRIBUTED_SHARD_COUNT: usize = 5;
    const HEARTBEAT_INTERVAL_SECS: u64 = 5;

    #[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateTurbineBladeExportProfile {
        Flagship,
        Smoke,
    }

    impl PrivateTurbineBladeExportProfile {
        pub fn parse(value: &str) -> ZkfResult<Self> {
            match value {
                "flagship" => Ok(Self::Flagship),
                "smoke" => Ok(Self::Smoke),
                other => Err(ZkfError::Backend(format!(
                    "unsupported ZKF_PRIVATE_TURBINE_BLADE_PROFILE value {other:?} (expected `flagship` or `smoke`)"
                ))),
            }
        }

        pub fn as_str(self) -> &'static str {
            match self {
                Self::Flagship => "flagship",
                Self::Smoke => "smoke",
            }
        }

        pub fn bundle_contract(self) -> &'static str {
            match self {
                Self::Flagship => "private-turbine-blade-flagship-v1",
                Self::Smoke => "private-turbine-blade-smoke-v1",
            }
        }

        pub fn is_flagship(self) -> bool {
            matches!(self, Self::Flagship)
        }
    }

    #[derive(Debug, Clone)]
    pub struct PrivateTurbineBladeExportConfig {
        pub out_dir: PathBuf,
        pub steps: usize,
        pub profile: PrivateTurbineBladeExportProfile,
        pub primary_backend: BackendSelection,
        pub full_audit_requested: bool,
        pub optional_cloudfs_requested: bool,
        pub distributed_plan_requested: bool,
    }

    #[derive(Debug, Serialize)]
    struct ProgramStats {
        signals: usize,
        constraints: usize,
        public_outputs: usize,
        blackbox_constraints: usize,
    }

    #[derive(Debug, Clone, Serialize)]
    struct ExportTimings {
        template_build_ms: f64,
        witness_ms: f64,
        optimize_ms: f64,
        primary_compile_ms: Option<f64>,
        primary_prepare_witness_ms: Option<f64>,
        primary_prove_ms: Option<f64>,
        primary_verify_ms: Option<f64>,
        compat_prove_ms: f64,
        compat_verify_ms: f64,
    }

    #[derive(Debug, Serialize)]
    struct ExportProgress {
        application: &'static str,
        export_profile: &'static str,
        bundle_contract: &'static str,
        steps: usize,
        primary_backend: String,
        stage: String,
        status: String,
        elapsed_ms: f64,
        error: Option<String>,
    }

    struct BundleInputs {
        config: PrivateTurbineBladeExportConfig,
        original_program: Program,
        optimized_program: Program,
        optimizer_report: zkf_core::OptimizeReport,
        witness_public_outputs: BTreeMap<String, String>,
        primary_execution: Option<BackendProofExecutionResult>,
        primary_direct_proof: Option<EmbeddedProof>,
        compat_proof: crate::app::api::EmbeddedProof,
        manual_witness: Witness,
        telemetry_before: BTreeSet<String>,
        telemetry_after: BTreeSet<String>,
        trusted_setup_requested: bool,
        trusted_setup_used: bool,
        setup_provenance: String,
        timings: ExportTimings,
    }

    fn stats(program: &Program) -> ProgramStats {
        ProgramStats {
            signals: program.signals.len(),
            constraints: program.constraints.len(),
            public_outputs: program
                .signals
                .iter()
                .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
                .count(),
            blackbox_constraints: program
                .constraints
                .iter()
                .filter(|constraint| matches!(constraint, zkf_core::Constraint::BlackBox { .. }))
                .count(),
        }
    }

    fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
    where
        T: Send + 'static,
        F: FnOnce() -> ZkfResult<T> + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(512 * 1024 * 1024)
            .spawn(f)
            .map_err(|error| ZkfError::Backend(format!("spawn {name} worker: {error}")))?;
        handle.join().map_err(|panic| {
            if let Some(message) = panic.downcast_ref::<&str>() {
                ZkfError::Backend(format!("{name} worker panicked: {message}"))
            } else if let Some(message) = panic.downcast_ref::<String>() {
                ZkfError::Backend(format!("{name} worker panicked: {message}"))
            } else {
                ZkfError::Backend(format!("{name} worker panicked"))
            }
        })?
    }

    fn progress_path(out_dir: &Path) -> PathBuf {
        out_dir.join("private_turbine_blade.progress.json")
    }

    fn write_progress(
        out_dir: &Path,
        profile: PrivateTurbineBladeExportProfile,
        steps: usize,
        primary_backend: &str,
        stage: &str,
        status: &str,
        elapsed_ms: f64,
        error: Option<String>,
    ) -> ZkfResult<()> {
        write_json(
            &progress_path(out_dir),
            &ExportProgress {
                application: APP_ID,
                export_profile: profile.as_str(),
                bundle_contract: profile.bundle_contract(),
                steps,
                primary_backend: primary_backend.to_string(),
                stage: stage.to_string(),
                status: status.to_string(),
                elapsed_ms,
                error,
            },
        )
    }

    fn maybe_write_progress(
        out_dir: &Path,
        profile: PrivateTurbineBladeExportProfile,
        steps: usize,
        primary_backend: &str,
        stage: &str,
        status: &str,
        elapsed_ms: f64,
        error: Option<String>,
    ) {
        if let Err(write_error) = write_progress(
            out_dir,
            profile,
            steps,
            primary_backend,
            stage,
            status,
            elapsed_ms,
            error,
        ) {
            eprintln!(
                "private_turbine_blade_life_showcase: warning: failed to write progress for {stage}: {write_error}"
            );
        }
    }

    fn run_with_stage_heartbeat<T, F>(
        config: &PrivateTurbineBladeExportConfig,
        stage: &str,
        f: F,
    ) -> ZkfResult<T>
    where
        F: FnOnce() -> ZkfResult<T>,
    {
        let stage_label = stage.to_string();
        let start = Instant::now();
        let out_dir = config.out_dir.clone();
        let profile = config.profile;
        let steps = config.steps;
        let primary_backend = config.primary_backend.requested_name.clone();
        maybe_write_progress(
            &out_dir,
            profile,
            steps,
            &primary_backend,
            &stage_label,
            "running",
            0.0,
            None,
        );
        let result = std::thread::scope(|scope| {
            let (tx, rx) = mpsc::channel::<()>();
            let heartbeat_stage = stage_label.clone();
            let heartbeat_out_dir = out_dir.clone();
            let heartbeat_backend = primary_backend.clone();
            scope.spawn(move || loop {
                match rx.recv_timeout(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
                        eprintln!(
                            "private_turbine_blade_life_showcase: heartbeat: {heartbeat_stage} running ({:.2}s)",
                            elapsed_ms / 1_000.0
                        );
                        maybe_write_progress(
                            &heartbeat_out_dir,
                            profile,
                            steps,
                            &heartbeat_backend,
                            &heartbeat_stage,
                            "running",
                            elapsed_ms,
                            None,
                        );
                    }
                }
            });

            let result = f();
            let _ = tx.send(());
            result
        });
        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
        match &result {
            Ok(_) => {
                eprintln!(
                    "private_turbine_blade_life_showcase: checkpoint: {stage_label} complete in {:.2}s",
                    elapsed_ms / 1_000.0
                );
                maybe_write_progress(
                    &out_dir,
                    profile,
                    steps,
                    &primary_backend,
                    &stage_label,
                    "completed",
                    elapsed_ms,
                    None,
                );
            }
            Err(error) => {
                eprintln!(
                    "private_turbine_blade_life_showcase: checkpoint: {stage_label} failed in {:.2}s: {error}",
                    elapsed_ms / 1_000.0
                );
                maybe_write_progress(
                    &out_dir,
                    profile,
                    steps,
                    &primary_backend,
                    &stage_label,
                    "failed",
                    elapsed_ms,
                    Some(error.to_string()),
                );
            }
        }
        result
    }

    fn public_outputs(program: &Program, witness: &Witness) -> BTreeMap<String, String> {
        program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .filter_map(|signal| {
                witness
                    .values
                    .get(&signal.name)
                    .map(|value| (signal.name.clone(), value.to_decimal_string()))
            })
            .collect()
    }

    fn telemetry_snapshot() -> BTreeSet<String> {
        let mut snapshot = BTreeSet::new();
        let dir = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            .join(".zkf/telemetry");
        if let Ok(read_dir) = fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                snapshot.insert(entry.path().display().to_string());
            }
        }
        snapshot
    }

    fn new_telemetry_paths(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
        after.difference(before).cloned().collect()
    }

    fn ccs_summary(compiled: &CompiledProgram) -> ZkfResult<Value> {
        let ccs = CcsProgram::try_from_program(&compiled.program)?;
        Ok(json!({
            "program_name": ccs.name,
            "field": ccs.field.as_str(),
            "num_constraints": ccs.num_constraints,
            "num_variables": ccs.num_variables,
            "num_public": ccs.num_public,
            "num_matrices": ccs.num_matrices(),
            "num_terms": ccs.num_terms(),
            "degree": ccs.degree(),
            "matrix_nnz": ccs.matrices.iter().enumerate().map(|(index, matrix)| {
                json!({
                    "index": index,
                    "rows": matrix.rows,
                    "cols": matrix.cols,
                    "nnz": matrix.nnz(),
                })
            }).collect::<Vec<_>>(),
            "compiled_metadata": compiled.metadata,
        }))
    }

    fn with_showcase_groth16_mode<T, F: FnOnce() -> ZkfResult<T>>(
        trusted_setup_used: bool,
        f: F,
    ) -> ZkfResult<T> {
        if trusted_setup_used {
            f()
        } else {
            with_allow_dev_deterministic_groth16_override(Some(true), f)
        }
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn backend_surface_json(kind: BackendKind) -> Value {
        let surface = backend_surface_status(kind);
        json!({
            "backend": kind.as_str(),
            "implementation_type": format!("{:?}", surface.implementation_type),
            "compiled_in": surface.compiled_in,
            "compat_available": surface.compat_available,
        })
    }

    fn filtered_capability_entries() -> Value {
        let matrix = capability_matrix();
        let value = serde_json::to_value(matrix).unwrap_or_else(|_| json!({}));
        let Some(backends) = value.get("backends").and_then(Value::as_array) else {
            return json!([]);
        };
        json!(
            backends
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.get("backend").and_then(Value::as_str),
                        Some("hypernova") | Some("arkworks-groth16")
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        )
    }

    fn shard_plan(steps: usize, enabled: bool) -> Value {
        if !enabled {
            return json!({
                "enabled": false,
                "mode": "single-node",
                "note": "distributed proving plan not requested; exporter ran a single-node proof",
                "planned_shards": [],
            });
        }

        let shard_count = usize::min(DISTRIBUTED_SHARD_COUNT, steps.max(1));
        let shard_width = steps.div_ceil(shard_count);
        let master_seed =
            Sha256::digest(b"private_turbine_blade_life_showcase_distributed_plan_v1");
        let mut shards = Vec::new();
        let mut aggregate = Sha256::new();
        for shard_index in 0..shard_count {
            let start = shard_index * shard_width;
            let end = usize::min(start + shard_width, steps);
            if start >= end {
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(master_seed);
            hasher.update((shard_index as u64).to_le_bytes());
            hasher.update((start as u64).to_le_bytes());
            hasher.update((end as u64).to_le_bytes());
            let digest = hasher.finalize();
            aggregate.update(digest);
            let digest_hex = hex_string(&digest);
            shards.push(json!({
                "shard_index": shard_index,
                "step_start": start,
                "step_end_exclusive": end,
                "worker_id": format!("turbine-worker-{}", &digest_hex[..12]),
                "assignment_digest": digest_hex,
                "execution_status": "planned-only",
            }));
        }
        json!({
            "enabled": true,
            "mode": "planned-only",
            "note": "deterministic shard planning is emitted, but the exporter currently executes the proof on a single node",
            "shard_seed_digest": hex_string(&master_seed),
            "aggregation_digest": hex_string(&aggregate.finalize()),
            "planned_shards": shards,
        })
    }

    fn stage_summary(
        report: &zkf_runtime::GraphExecutionReport,
        artifact_metadata: &BTreeMap<String, String>,
    ) -> Value {
        let gpu_attribution = effective_gpu_attribution_summary(
            report.gpu_nodes,
            report.gpu_stage_busy_ratio(),
            artifact_metadata,
        );
        json!({
            "total_wall_time_ms": report.total_wall_time.as_secs_f64() * 1_000.0,
            "peak_memory_bytes": report.peak_memory_bytes,
            "gpu_nodes": report.gpu_nodes,
            "cpu_nodes": report.cpu_nodes,
            "delegated_nodes": report.delegated_nodes,
            "fallback_nodes": report.fallback_nodes,
            "gpu_busy_ratio": report.gpu_stage_busy_ratio(),
            "effective_gpu_attribution": gpu_attribution,
            "stage_breakdown": report.stage_breakdown(),
            "watchdog_alerts": report.watchdog_alerts,
        })
    }

    fn report_markdown(
        profile: PrivateTurbineBladeExportProfile,
        primary_backend_name: &str,
        steps: usize,
        original_program: &Program,
        optimized_program: &Program,
        primary_lane: &Value,
        primary_runtime_breakdown: Option<&Value>,
        witness_public_outputs: &BTreeMap<String, String>,
        formal_evidence: &Value,
        audit_summary: &Value,
        generated_closure: &Value,
        telemetry_paths: &[String],
        distributed_report: &Value,
        foundry: &Value,
    ) -> String {
        let telemetry_lines = if telemetry_paths.is_empty() {
            "- No new telemetry file paths were detected during export.\n".to_string()
        } else {
            telemetry_paths
                .iter()
                .map(|path| format!("- `{path}`\n"))
                .collect::<String>()
        };
        let formal_status = formal_evidence
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let formal_sentence = if formal_status == "included" {
            "The bundle includes formal logs and an exercised-surface extract under `formal/`."
        } else {
            "The bundle records the attempted formal runs under `formal/` and preserves any failure state explicitly."
        };
        let primary_lane_status = primary_lane
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let primary_execution_path = primary_lane
            .get("execution_path")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let primary_lane_sentence = match primary_lane_status {
            "completed" => match primary_runtime_breakdown {
                Some(stage_breakdown) => format!(
                    "The primary {} lane completed successfully via `{}` and reverified. Runtime stage breakdown:\n\n`{}`",
                    primary_backend_name,
                    primary_execution_path,
                    json_pretty(stage_breakdown),
                ),
                None => format!(
                    "The primary {} lane completed successfully via `{}` and reverified. This bundle used the compiled proof/export path rather than the runtime scheduler path.",
                    primary_backend_name, primary_execution_path,
                ),
            },
            "omitted_in_smoke" => format!(
                "The smoke profile intentionally omitted the strict {} primary lane and validated only the compatibility proof/export surface.",
                primary_backend_name
            ),
            other => format!(
                "The primary {} lane ended with status `{}`.",
                primary_backend_name, other
            ),
        };

        format!(
            r#"# ZirOS Private Turbine Blade Life Showcase

## Profile

- `export_profile`: `{export_profile}`
- `bundle_contract`: `{bundle_contract}`

## What Was Built

This bundle exports a private turbine blade thermal-mechanical life analysis over exactly {steps} deterministic mission steps. The proofed application takes private blade geometry, material coefficients, defect state, mission telemetry, manufacturer thresholds, reserve margin policy, and commitment blinders. It exposes only four Poseidon commitments plus the public `safe_to_deploy` decision.

{primary_lane_sentence}

The compatibility lane always emits the Arkworks Groth16 verifier and Foundry project. Foundry validation status:

`{foundry}`

## ProgramBuilder Breakdown

The circuit is built entirely with `ProgramBuilder`, not framework internals. The builder phases are:

1. input loading and range binding
2. control-section reduction from 8 geometry stations to root/mid/tip sections
3. thermal recurrence and thermal strain synthesis
4. centrifugal, pressure, and thermal stress composition
5. bounded fatigue and creep increment updates
6. monotone crack-growth updates
7. running minimum safety margin logic
8. final threshold decision logic
9. blinded Poseidon commitments for final damage, crack, remaining life, and minimum margin

The source program has `{original_constraints}` constraints before optimization and `{optimized_constraints}` after optimization.

## Runtime And Telemetry

Primary public outputs were:

`{witness_public_outputs:?}`

The bundle-local distributed proving record was:

`{distributed_report}`

The exporter also captured these new telemetry paths:

{telemetry_lines}

## Formal Evidence

{formal_sentence}

Formal evidence summary:

`{formal_evidence}`

Generated closure summary:

`{generated_closure}`

Structured audit summary:

`{audit_summary}`
"#,
            export_profile = profile.as_str(),
            bundle_contract = profile.bundle_contract(),
            steps = steps,
            primary_lane_sentence = primary_lane_sentence,
            foundry = json_pretty(foundry),
            original_constraints = original_program.constraints.len(),
            optimized_constraints = optimized_program.constraints.len(),
            witness_public_outputs = witness_public_outputs,
            distributed_report = json_pretty(distributed_report),
            telemetry_lines = telemetry_lines,
            formal_sentence = formal_sentence,
            formal_evidence = json_pretty(formal_evidence),
            generated_closure = json_pretty(generated_closure),
            audit_summary = json_pretty(audit_summary),
        )
    }

    fn optional_primary_lane_surface(
        profile: PrivateTurbineBladeExportProfile,
        primary_backend_name: &str,
        primary_compiled: Option<&CompiledProgram>,
        primary_verify_ms: Option<f64>,
        primary_execution_path: Option<&str>,
    ) -> Value {
        match primary_compiled {
            Some(compiled) => json!({
                "status": "completed",
                "backend": primary_backend_name,
                "compiled_backend": compiled.backend.as_str(),
                "execution_path": primary_execution_path,
                "verified": true,
                "verify_ms": primary_verify_ms,
            }),
            None => json!({
                "status": if profile.is_flagship() { "missing" } else { "omitted_in_smoke" },
                "backend": primary_backend_name,
                "compiled_backend": Value::Null,
                "execution_path": Value::Null,
                "verified": Value::Null,
                "verify_ms": Value::Null,
            }),
        }
    }

    fn export_bundle(inputs: BundleInputs) -> ZkfResult<PathBuf> {
        let bundle_start = Instant::now();
        let BundleInputs {
            config,
            original_program,
            optimized_program,
            optimizer_report,
            witness_public_outputs,
            primary_execution,
            primary_direct_proof,
            compat_proof,
            manual_witness,
            telemetry_before,
            telemetry_after,
            trusted_setup_requested,
            trusted_setup_used,
            setup_provenance,
            timings,
        } = inputs;
        let primary_compiled = primary_execution
            .as_ref()
            .map(|execution| &execution.compiled)
            .or_else(|| primary_direct_proof.as_ref().map(|proof| &proof.compiled));
        let primary_artifact = primary_execution
            .as_ref()
            .map(|execution| &execution.artifact)
            .or_else(|| primary_direct_proof.as_ref().map(|proof| &proof.artifact));
        let primary_execution_path = match (primary_execution.as_ref(), primary_artifact) {
            (Some(_), Some(_)) => Some("strict-runtime"),
            (None, Some(_)) => Some("direct-compiled"),
            _ => None,
        };
        let primary_runtime_breakdown = primary_execution
            .as_ref()
            .map(|execution| json!(execution.result.report.stage_breakdown()));

        let compiled_dir = config.out_dir.join("compiled");
        let proofs_dir = config.out_dir.join("proofs");
        let verification_dir = config.out_dir.join("verification");
        let telemetry_bundle_dir = config.out_dir.join("telemetry");
        let audit_dir = config.out_dir.join("audit");
        fs::create_dir_all(&compiled_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", compiled_dir.display())))?;
        fs::create_dir_all(&proofs_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", proofs_dir.display())))?;
        fs::create_dir_all(&verification_dir).map_err(|error| {
            ZkfError::Io(format!("create {}: {error}", verification_dir.display()))
        })?;
        fs::create_dir_all(&telemetry_bundle_dir).map_err(|error| {
            ZkfError::Io(format!(
                "create {}: {error}",
                telemetry_bundle_dir.display()
            ))
        })?;

        let verifier_source = export_groth16_solidity_verifier(
            &compat_proof.artifact,
            Some("PrivateTurbineBladeVerifier"),
        )?;
        let calldata = proof_to_calldata_json(
            &compat_proof.artifact.proof,
            &compat_proof.artifact.public_inputs,
        )
        .map_err(ZkfError::Backend)?;
        let foundry_test = generate_foundry_test_from_artifact(
            &compat_proof.artifact.proof,
            &compat_proof.artifact.public_inputs,
            "../src/PrivateTurbineBladeVerifier.sol",
            "PrivateTurbineBladeVerifier",
        )
        .map_err(ZkfError::Backend)?;
        let project_dir = foundry_project_dir(&config.out_dir);
        ensure_foundry_layout(&project_dir)?;

        let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
        let distributed_report = shard_plan(config.steps, config.distributed_plan_requested);
        let primary_gpu_attribution = match (primary_execution.as_ref(), primary_artifact) {
            (Some(execution), Some(artifact)) => effective_gpu_attribution_summary(
                execution.result.report.gpu_nodes,
                execution.result.report.gpu_stage_busy_ratio(),
                &artifact.metadata,
            ),
            (None, Some(artifact)) => effective_gpu_attribution_summary(0, 0.0, &artifact.metadata),
            _ => json!({"status": "omitted_in_smoke"}),
        };
        let compat_gpu_attribution =
            effective_gpu_attribution_summary(0, 0.0, &compat_proof.artifact.metadata);

        let program_original_path =
            compiled_dir.join("private_turbine_blade.program.original.json");
        let program_optimized_path =
            compiled_dir.join("private_turbine_blade.program.optimized.json");
        let primary_compiled_path =
            compiled_dir.join("private_turbine_blade.primary.compiled.json");
        let compat_compiled_path = compiled_dir.join("private_turbine_blade.compat.compiled.json");
        let primary_proof_path = proofs_dir.join("private_turbine_blade.primary.proof.json");
        let compat_proof_path = proofs_dir.join("private_turbine_blade.compat.proof.json");
        let verifier_path = config
            .out_dir
            .join("foundry/src/PrivateTurbineBladeVerifier.sol");
        let foundry_test_path = config
            .out_dir
            .join("foundry/test/PrivateTurbineBladeVerifier.t.sol");
        let foundry_report_path = config.out_dir.join("foundry_report.txt");
        let progress_report_path = progress_path(&config.out_dir);
        let calldata_path = verification_dir.join("private_turbine_blade.calldata.json");
        let public_inputs_path = config.out_dir.join("public_inputs.json");
        let witness_summary_path = config.out_dir.join("witness_summary.json");
        let run_report_path = config.out_dir.join("private_turbine_blade.run_report.json");
        let translation_report_path = config
            .out_dir
            .join("private_turbine_blade.translation_report.json");
        let telemetry_report_path =
            telemetry_bundle_dir.join("private_turbine_blade.telemetry_report.json");
        let verification_report_path =
            verification_dir.join("private_turbine_blade.verification_report.json");
        let smoke_validation_path =
            verification_dir.join("private_turbine_blade.smoke_validation.json");
        let summary_path = config.out_dir.join("private_turbine_blade.summary.json");
        let audit_path = config.out_dir.join("private_turbine_blade.audit.json");
        let evidence_manifest_path = config
            .out_dir
            .join("private_turbine_blade.evidence_manifest.json");
        let matrix_path = config
            .out_dir
            .join("private_turbine_blade.matrix_summary.json");
        let report_path = config.out_dir.join("private_turbine_blade.report.md");
        let swarm_assignments_path = config.out_dir.join("swarm_assignments.json");
        let aggregation_report_path = config.out_dir.join("aggregation_report.json");

        write_text(&verifier_path, &verifier_source)?;
        write_text(&foundry_test_path, &foundry_test.source)?;
        let foundry_status = run_foundry_report(&project_dir, &foundry_report_path)?;

        let full_audit_enabled = config.full_audit_requested;
        let structural_summary = json!({
            "original": {
                "program_digest": original_program.digest_hex(),
                "program_stats": stats(&original_program),
            },
            "optimized": {
                "program_digest": optimized_program.digest_hex(),
                "program_stats": stats(&optimized_program),
                "optimizer_report": optimizer_report,
            },
            "primary_compiled": match primary_compiled {
                Some(compiled) => json!({
                    "status": "included",
                    "program_digest": compiled.program_digest,
                    "program_stats": stats(&compiled.program),
                    "backend": compiled.backend.as_str(),
                }),
                None => json!({
                    "status": "omitted_in_smoke",
                    "backend": config.primary_backend.requested_name,
                }),
            },
            "compat_compiled": {
                "status": "included",
                "program_digest": compat_proof.compiled.program_digest,
                "program_stats": stats(&compat_proof.compiled.program),
                "backend": compat_proof.compiled.backend.as_str(),
            },
        });

        let (full_source_audit, full_primary_audit, full_compat_audit) = if full_audit_enabled {
            fs::create_dir_all(&audit_dir).map_err(|error| {
                ZkfError::Io(format!("create {}: {error}", audit_dir.display()))
            })?;
            let source_audit_path = audit_dir.join("private_turbine_blade.source_audit.json");
            let compat_audit_path =
                audit_dir.join("private_turbine_blade.compat_compiled_audit.json");
            let source_audit = audit_program_with_live_capabilities(
                &original_program,
                Some(config.primary_backend.backend),
            );
            let compat_audit = audit_program_with_live_capabilities(
                &compat_proof.compiled.program,
                Some(BackendKind::ArkworksGroth16),
            );
            write_json(&source_audit_path, &source_audit)?;
            write_json(&compat_audit_path, &compat_audit)?;
            let primary_json = match primary_compiled {
                Some(compiled) => {
                    let primary_audit_path =
                        audit_dir.join("private_turbine_blade.primary_compiled_audit.json");
                    let primary_audit = audit_program_with_live_capabilities(
                        &compiled.program,
                        Some(config.primary_backend.backend),
                    );
                    write_json(&primary_audit_path, &primary_audit)?;
                    json!({
                        "status": "included",
                        "reason": "requested via config.full_audit_requested",
                        "path": "audit/private_turbine_blade.primary_compiled_audit.json",
                        "summary": primary_audit.summary,
                    })
                }
                None => json!({
                    "status": "omitted_in_smoke",
                    "reason": "smoke profile does not emit a primary compiled artifact",
                    "path": Value::Null,
                }),
            };
            (
                json!({
                    "status": "included",
                    "reason": "requested via config.full_audit_requested",
                    "path": "audit/private_turbine_blade.source_audit.json",
                    "summary": source_audit.summary,
                }),
                primary_json,
                json!({
                    "status": "included",
                    "reason": "requested via config.full_audit_requested",
                    "path": "audit/private_turbine_blade.compat_compiled_audit.json",
                    "summary": compat_audit.summary,
                }),
            )
        } else {
            (
                json!({
                    "status": "omitted-by-default",
                    "reason": "enable full_audit_requested to include the heavyweight source audit",
                    "path": Value::Null,
                }),
                json!({
                    "status": if config.profile.is_flagship() { "omitted-by-default" } else { "omitted_in_smoke" },
                    "reason": if config.profile.is_flagship() {
                        "enable full_audit_requested to include the heavyweight primary compiled audit"
                    } else {
                        "smoke profile does not emit a primary compiled artifact"
                    },
                    "path": Value::Null,
                }),
                json!({
                    "status": "omitted-by-default",
                    "reason": "enable full_audit_requested to include the heavyweight compatibility compiled audit",
                    "path": Value::Null,
                }),
            )
        };

        let audit_summary = json!({
            "mode": "two-tier-showcase-audit-v2",
            "structural_summary": structural_summary,
            "full_source_audit": full_source_audit,
            "full_primary_compiled_audit": full_primary_audit,
            "full_compat_compiled_audit": full_compat_audit,
        });

        let witness_summary = json!({
            "schema": "private-turbine-blade-witness-summary-v2",
            "mission_steps": config.steps,
            "public_outputs": witness_public_outputs,
            "manual_witness_signal_count": manual_witness.values.len(),
            "public_signal_count": PRIVATE_TURBINE_BLADE_PUBLIC_OUTPUTS,
            "private_input_count": collect_expected_inputs(config.steps).len(),
            "sensitivity_boundary": "private geometry, material, thresholds, mission profile, and blinders are not emitted into the bundle",
        });

        let primary_lane = optional_primary_lane_surface(
            config.profile,
            &config.primary_backend.requested_name,
            primary_compiled,
            timings.primary_verify_ms,
            primary_execution_path,
        );
        let compatibility_lane = json!({
            "status": "completed",
            "backend": compat_proof.compiled.backend.as_str(),
            "verified": true,
            "verify_ms": timings.compat_verify_ms,
        });

        let verification_report = json!({
            "schema": "private-turbine-blade-verification-report-v2",
            "export_profile": config.profile.as_str(),
            "bundle_contract": config.profile.bundle_contract(),
            "primary_lane": primary_lane,
            "compatibility_lane": compatibility_lane,
            "smoke_validation_path": if config.profile.is_flagship() {
                Value::Null
            } else {
                Value::String("verification/private_turbine_blade.smoke_validation.json".to_string())
            },
        });

        let smoke_validation = (!config.profile.is_flagship()).then(|| {
            json!({
                "schema": "private-turbine-blade-smoke-validation-v1",
                "export_profile": config.profile.as_str(),
                "bundle_contract": config.profile.bundle_contract(),
                "primary_lane": {
                    "status": "omitted_in_smoke",
                    "reason": "smoke profile validates the compatibility proof/export surface only",
                },
                "compatibility_lane": {
                    "status": "completed",
                    "verified": true,
                },
                "foundry": foundry_status,
            })
        });

        let translation_report = json!({
            "schema": "private-turbine-blade-translation-report-v2",
            "export_profile": config.profile.as_str(),
            "bundle_contract": config.profile.bundle_contract(),
            "primary_lane": {
                "status": primary_lane["status"],
                "backend": config.primary_backend.requested_name,
                "compiled_backend": primary_compiled
                    .map(|compiled| Value::String(compiled.backend.as_str().to_string()))
                    .unwrap_or(Value::Null),
                "execution_path": primary_execution_path
                    .map(|path| Value::String(path.to_string()))
                    .unwrap_or(Value::Null),
                "route": if config.profile.is_flagship() { Value::String("auto".to_string()) } else { Value::Null },
                "trust_lane": if config.profile.is_flagship() { Value::String("StrictCryptographic".to_string()) } else { Value::Null },
                "execution_mode": if config.profile.is_flagship() { Value::String("Deterministic".to_string()) } else { Value::Null },
            },
            "compatibility_lane": {
                "status": "completed",
                "backend": "arkworks-groth16",
                "program_digest": compat_proof.compiled.program_digest,
                "solidity_export": "supported",
                "foundry_export": "supported",
            },
            "distributed_proving": distributed_report,
        });

        let telemetry_report = json!({
            "schema": "private-turbine-blade-telemetry-report-v2",
            "export_profile": config.profile.as_str(),
            "metal_runtime": metal_runtime_report(),
            "primary_runtime": primary_execution
                .as_ref()
                .map(|execution| stage_summary(&execution.result.report, &execution.artifact.metadata))
                .unwrap_or(Value::Null),
            "primary_control_plane": primary_execution
                .as_ref()
                .map(|execution| serde_json::to_value(&execution.result.control_plane).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
            "primary_security": primary_execution
                .as_ref()
                .map(|execution| serde_json::to_value(&execution.result.security).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
            "primary_model_integrity": primary_execution
                .as_ref()
                .map(|execution| serde_json::to_value(&execution.result.model_integrity).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
            "primary_swarm": primary_execution
                .as_ref()
                .map(|execution| serde_json::to_value(&execution.result.swarm).unwrap_or(Value::Null))
                .unwrap_or(Value::Null),
            "primary_gpu_attribution": primary_gpu_attribution,
            "compatibility_gpu_attribution": compat_gpu_attribution,
            "backend_surface_status": [
                backend_surface_json(config.primary_backend.backend),
                backend_surface_json(BackendKind::ArkworksGroth16),
            ],
            "capability_entries": filtered_capability_entries(),
            "telemetry_paths": telemetry_paths,
        });

        let (_, formal_evidence) =
            collect_formal_evidence_for_generated_app(&config.out_dir, APP_ID)?;
        let generated_closure = generated_app_closure_bundle_summary(APP_ID)?;

        let run_report = json!({
            "schema": "private-turbine-blade-run-report-v2",
            "export_profile": config.profile.as_str(),
            "bundle_contract": config.profile.bundle_contract(),
            "steps": config.steps,
            "setup_seed_hex": hex_string(&SETUP_SEED),
            "proof_seed_hex": hex_string(&PROOF_SEED),
            "swarm_enabled": SwarmConfig::is_enabled(),
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
            "compat_setup_provenance": setup_provenance,
            "primary_backend": config.primary_backend.requested_name,
            "primary_execution_path": primary_execution_path,
            "compat_backend": "arkworks-groth16",
            "primary_proof_size_bytes": primary_artifact.map(|artifact| artifact.proof.len()),
            "compat_proof_size_bytes": compat_proof.artifact.proof.len(),
            "primary_vk_size_bytes": primary_artifact.map(|artifact| artifact.verification_key.len()),
            "compat_vk_size_bytes": compat_proof.artifact.verification_key.len(),
            "timings_ms": {
                "template_build": timings.template_build_ms,
                "witness_generation": timings.witness_ms,
                "program_optimization": timings.optimize_ms,
                "primary_compile": timings.primary_compile_ms,
                "primary_prepare_witness": timings.primary_prepare_witness_ms,
                "primary_prove": timings.primary_prove_ms,
                "primary_verify": timings.primary_verify_ms,
                "compatibility_prove": timings.compat_prove_ms,
                "compatibility_verify": timings.compat_verify_ms,
                "bundle_finalize": bundle_start.elapsed().as_secs_f64() * 1_000.0,
            },
        });

        let summary = json!({
            "schema": "private-turbine-blade-summary-v2",
            "application": APP_ID,
            "export_profile": config.profile.as_str(),
            "bundle_contract": config.profile.bundle_contract(),
            "steps": config.steps,
            "primary_backend": config.primary_backend.requested_name,
            "compat_backend": "arkworks-groth16",
            "public_outputs": witness_public_outputs,
            "primary_lane": primary_lane,
            "compatibility_lane": compatibility_lane,
            "foundry": foundry_status,
            "formal": formal_evidence,
            "audit": audit_summary,
            "closure": generated_closure,
            "telemetry": {
                "primary_gpu_attribution": primary_execution
                    .as_ref()
                    .map(|execution| effective_gpu_attribution_summary(
                        execution.result.report.gpu_nodes,
                        execution.result.report.gpu_stage_busy_ratio(),
                        &execution.artifact.metadata,
                    ))
                    .or_else(|| primary_artifact.map(|artifact| effective_gpu_attribution_summary(0, 0.0, &artifact.metadata)))
                    .unwrap_or_else(|| json!({"status": "omitted_in_smoke"})),
                "compatibility_gpu_attribution": compat_gpu_attribution,
                "telemetry_paths": telemetry_paths,
            },
        });

        let mut compiled_artifacts = vec![
            "compiled/private_turbine_blade.program.original.json".to_string(),
            "compiled/private_turbine_blade.program.optimized.json".to_string(),
            "compiled/private_turbine_blade.compat.compiled.json".to_string(),
        ];
        let mut proof_artifacts =
            vec!["proofs/private_turbine_blade.compat.proof.json".to_string()];
        if config.profile.is_flagship() {
            compiled_artifacts
                .push("compiled/private_turbine_blade.primary.compiled.json".to_string());
            proof_artifacts.push("proofs/private_turbine_blade.primary.proof.json".to_string());
        }
        let mut verification_artifacts = vec![
            "verification/private_turbine_blade.verification_report.json".to_string(),
            "verification/private_turbine_blade.calldata.json".to_string(),
        ];
        if !config.profile.is_flagship() {
            verification_artifacts
                .push("verification/private_turbine_blade.smoke_validation.json".to_string());
        }

        let evidence_manifest = json!({
            "bundle_evidence_version": "private-turbine-blade-evidence-v2",
            "application": APP_ID,
            "export_profile": config.profile.as_str(),
            "bundle_contract": config.profile.bundle_contract(),
            "artifacts": {
                "compiled": compiled_artifacts,
                "proofs": proof_artifacts,
                "verification": verification_artifacts,
                "reports": [
                    "private_turbine_blade.progress.json",
                    "private_turbine_blade.summary.json",
                    "private_turbine_blade.run_report.json",
                    "private_turbine_blade.translation_report.json",
                    "telemetry/private_turbine_blade.telemetry_report.json",
                    "private_turbine_blade.audit.json",
                    "private_turbine_blade.report.md",
                    "foundry_report.txt",
                ],
                "formal": formal_evidence.get("files").cloned().unwrap_or(json!({})),
                "foundry": [
                    "foundry/src/PrivateTurbineBladeVerifier.sol",
                    "foundry/test/PrivateTurbineBladeVerifier.t.sol",
                    "foundry_report.txt",
                ],
            },
            "formal_evidence": formal_evidence,
            "generated_closure": generated_closure,
            "audit_coverage": audit_summary,
            "gpu_attribution": {
                "primary": summary["telemetry"]["primary_gpu_attribution"],
                "compatibility": compat_gpu_attribution,
            },
            "trusted_setup": {
                "requested": trusted_setup_requested,
                "used": trusted_setup_used,
                "provenance": setup_provenance,
            },
            "primary_lane": primary_lane,
            "compatibility_lane": compatibility_lane,
            "foundry": foundry_status,
        });

        write_json(&program_original_path, &original_program)?;
        write_json(&program_optimized_path, &optimized_program)?;
        if let (Some(compiled), Some(artifact)) = (primary_compiled, primary_artifact) {
            write_json(&primary_compiled_path, compiled)?;
            write_json(&primary_proof_path, artifact)?;
        }
        write_json(&compat_compiled_path, &compat_proof.compiled)?;
        write_json(&compat_proof_path, &compat_proof.artifact)?;
        write_json(&calldata_path, &calldata)?;
        let public_inputs_value = primary_artifact
            .map(|artifact| artifact.public_inputs.clone())
            .unwrap_or_else(|| compat_proof.artifact.public_inputs.clone());
        write_json(&public_inputs_path, &public_inputs_value)?;
        write_json(&witness_summary_path, &witness_summary)?;
        write_json(&run_report_path, &run_report)?;
        write_json(&translation_report_path, &translation_report)?;
        write_json(&telemetry_report_path, &telemetry_report)?;
        write_json(&verification_report_path, &verification_report)?;
        if let Some(smoke_validation) = smoke_validation.as_ref() {
            write_json(&smoke_validation_path, smoke_validation)?;
        }
        write_json(&summary_path, &summary)?;
        write_json(&audit_path, &audit_summary)?;
        write_json(
            &matrix_path,
            &json!({
                "primary": match primary_compiled {
                    Some(compiled) => ccs_summary(compiled)?,
                    None => Value::Null,
                },
                "compatibility": ccs_summary(&compat_proof.compiled)?,
            }),
        )?;
        write_json(&swarm_assignments_path, &distributed_report)?;
        write_json(
            &aggregation_report_path,
            &json!({
                "schema": "private-turbine-blade-aggregation-report-v2",
                "distributed_proving": distributed_report,
                "execution_status": if config.distributed_plan_requested { "planned-only" } else { "disabled" },
                "note": "aggregation correctness is represented as a deterministic shard manifest in this exporter; end-to-end distributed execution is not yet integrated here",
            }),
        )?;
        write_json(&evidence_manifest_path, &evidence_manifest)?;
        write_text(
            &report_path,
            &report_markdown(
                config.profile,
                &config.primary_backend.requested_name,
                config.steps,
                &original_program,
                &optimized_program,
                &primary_lane,
                primary_runtime_breakdown.as_ref(),
                &witness_public_outputs,
                &summary["formal"],
                &audit_summary,
                &summary["closure"],
                &telemetry_paths,
                &translation_report["distributed_proving"],
                &foundry_status,
            ),
        )?;

        ensure_file_exists(&program_original_path)?;
        ensure_file_exists(&program_optimized_path)?;
        if config.profile.is_flagship() {
            ensure_file_exists(&primary_compiled_path)?;
            ensure_file_exists(&primary_proof_path)?;
        }
        ensure_file_exists(&compat_compiled_path)?;
        ensure_file_exists(&compat_proof_path)?;
        ensure_file_exists(&verifier_path)?;
        ensure_file_exists(&foundry_test_path)?;
        ensure_file_exists(&foundry_report_path)?;
        ensure_file_exists(&progress_report_path)?;
        ensure_file_exists(&calldata_path)?;
        ensure_file_exists(&public_inputs_path)?;
        ensure_file_exists(&witness_summary_path)?;
        ensure_file_exists(&run_report_path)?;
        ensure_file_exists(&translation_report_path)?;
        ensure_file_exists(&telemetry_report_path)?;
        ensure_file_exists(&verification_report_path)?;
        if !config.profile.is_flagship() {
            ensure_file_exists(&smoke_validation_path)?;
        }
        ensure_file_exists(&summary_path)?;
        ensure_file_exists(&audit_path)?;
        ensure_file_exists(&matrix_path)?;
        ensure_file_exists(&swarm_assignments_path)?;
        ensure_file_exists(&aggregation_report_path)?;
        ensure_file_exists(&evidence_manifest_path)?;
        ensure_file_exists(&report_path)?;
        ensure_dir_exists(&project_dir)?;
        ensure_file_exists(&config.out_dir.join("formal/STATUS.md"))?;
        ensure_file_exists(&config.out_dir.join("formal/exercised_surfaces.json"))?;

        let _: Value = read_json(&summary_path)?;
        let _: Value = read_json(&audit_path)?;
        let _: Value = read_json(&evidence_manifest_path)?;
        let _: Value = read_json(&verification_report_path)?;
        let _: Value = read_json(&public_inputs_path)?;
        if !config.profile.is_flagship() {
            let _: Value = read_json(&smoke_validation_path)?;
        }

        let compat_compiled: CompiledProgram = read_json(&compat_compiled_path)?;
        let compat_artifact: ProofArtifact = read_json(&compat_proof_path)?;
        if !verify(&compat_compiled, &compat_artifact)? {
            return Err(ZkfError::Backend(
                "exported compatibility proof failed reverification".to_string(),
            ));
        }
        if config.profile.is_flagship() {
            let primary_compiled: CompiledProgram = read_json(&primary_compiled_path)?;
            let primary_artifact: ProofArtifact = read_json(&primary_proof_path)?;
            if !verify(&primary_compiled, &primary_artifact)? {
                return Err(ZkfError::Backend(
                    "exported primary proof failed reverification".to_string(),
                ));
            }
        }
        let foundry_report_text = read_text(&foundry_report_path)?;
        if foundry_report_text.trim().is_empty() {
            return Err(ZkfError::InvalidArtifact(format!(
                "{} is empty",
                foundry_report_path.display()
            )));
        }

        if config.optional_cloudfs_requested {
            let mut artifacts = vec![
                ("compiled".to_string(), compat_compiled_path.clone()),
                ("proofs".to_string(), compat_proof_path.clone()),
                ("reports".to_string(), summary_path.clone()),
                ("reports".to_string(), evidence_manifest_path.clone()),
                ("reports".to_string(), report_path.clone()),
            ];
            if config.profile.is_flagship() {
                artifacts.push(("compiled".to_string(), primary_compiled_path.clone()));
                artifacts.push(("proofs".to_string(), primary_proof_path.clone()));
            }
            let _ = crate::app::evidence::persist_artifacts_to_cloudfs(APP_ID, &artifacts)?;
        }

        Ok(report_path)
    }

    fn run_private_turbine_blade_export_inner(
        config: PrivateTurbineBladeExportConfig,
    ) -> ZkfResult<PathBuf> {
        fs::create_dir_all(&config.out_dir).map_err(|error| {
            ZkfError::Io(format!("create {}: {error}", config.out_dir.display()))
        })?;
        if config.steps == 0 {
            return Err(ZkfError::Backend(
                "private turbine blade export requires at least one step".to_string(),
            ));
        }
        maybe_write_progress(
            &config.out_dir,
            config.profile,
            config.steps,
            &config.primary_backend.requested_name,
            "initializing",
            "running",
            0.0,
            None,
        );

        eprintln!(
            "private_turbine_blade_life_showcase: building template ({})",
            config.profile.as_str()
        );
        let template_start = Instant::now();
        let template = private_turbine_blade_life_showcase_with_steps(config.steps)?;
        let template_build_ms = template_start.elapsed().as_secs_f64() * 1_000.0;
        let request = private_turbine_blade_life_sample_request_with_steps(config.steps);
        let original_program = template.program.clone();
        let valid_inputs: WitnessInputs = template.sample_inputs.clone();

        eprintln!("private_turbine_blade_life_showcase: building witness summary");
        let witness_start = Instant::now();
        let manual_witness =
            private_turbine_blade_life_witness_from_request_with_steps(&request, config.steps)?;
        check_constraints(&original_program, &manual_witness)?;
        let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;
        let witness_public_outputs = public_outputs(&original_program, &manual_witness);

        eprintln!("private_turbine_blade_life_showcase: optimizing program");
        let optimize_start = Instant::now();
        let (optimized_program, optimizer_report) = optimize_program(&original_program);
        let optimize_ms = optimize_start.elapsed().as_secs_f64() * 1_000.0;

        let trusted_setup_requested =
            requested_groth16_setup_blob_path(&optimized_program).is_some();
        let trusted_setup_used = trusted_setup_requested;
        let setup_provenance = if trusted_setup_used {
            "trusted-imported".to_string()
        } else {
            "deterministic-dev".to_string()
        };

        let telemetry_before = telemetry_snapshot();
        let (
            primary_execution,
            primary_direct_proof,
            primary_compile_ms,
            primary_prepare_witness_ms,
            primary_prove_ms,
            primary_verify_ms,
        ) = if config.profile.is_flagship() {
            let primary_program = match config.primary_backend.backend {
                BackendKind::ArkworksGroth16 => optimized_program.clone(),
                _ => original_program.clone(),
            };
            eprintln!(
                "private_turbine_blade_life_showcase: compiling primary {} artifact",
                config.primary_backend.requested_name
            );
            let primary_compile_start = Instant::now();
            let primary_compiled = run_with_stage_heartbeat(&config, "primary-compile", || {
                match config.primary_backend.backend {
                    BackendKind::ArkworksGroth16 => {
                        with_showcase_groth16_mode(trusted_setup_used, || {
                            compile(
                                &primary_program,
                                &config.primary_backend.requested_name,
                                Some(SETUP_SEED),
                            )
                        })
                    }
                    _ => with_setup_seed_override(Some(SETUP_SEED), || {
                        compile(
                            &primary_program,
                            &config.primary_backend.requested_name,
                            Some(SETUP_SEED),
                        )
                    }),
                }
            })?;
            let primary_compile_ms = primary_compile_start.elapsed().as_secs_f64() * 1_000.0;

            eprintln!(
                "private_turbine_blade_life_showcase: preparing primary {} witness",
                config.primary_backend.requested_name
            );
            let primary_prepare_start = Instant::now();
            let primary_witness =
                run_with_stage_heartbeat(&config, "primary-witness-prepare", || {
                    let prepared = prepare_witness_for_proving(&primary_compiled, &manual_witness)?;
                    check_constraints(&primary_compiled.program, &prepared)?;
                    Ok(prepared)
                })?;
            let primary_prepare_witness_ms =
                primary_prepare_start.elapsed().as_secs_f64() * 1_000.0;

            let (primary_execution, primary_direct_proof, primary_prove_ms) =
                match config.primary_backend.backend {
                    BackendKind::ArkworksGroth16 => {
                        eprintln!(
                            "private_turbine_blade_life_showcase: running primary {} direct prove",
                            config.primary_backend.requested_name
                        );
                        let prove_start = Instant::now();
                        let compiled_for_prove = primary_compiled.clone();
                        let witness_for_prove = manual_witness.clone();
                        let artifact = run_with_stage_heartbeat(&config, "primary-prove", || {
                            with_showcase_groth16_mode(trusted_setup_used, || {
                                with_proof_seed_override(Some(PROOF_SEED), || {
                                    prove(&compiled_for_prove, &witness_for_prove)
                                })
                            })
                        })?;
                        let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
                        (
                            None,
                            Some(EmbeddedProof {
                                compiled: primary_compiled.clone(),
                                artifact,
                            }),
                            Some(prove_ms),
                        )
                    }
                    _ => {
                        eprintln!(
                            "private_turbine_blade_life_showcase: running primary {} runtime prove",
                            config.primary_backend.requested_name
                        );
                        let prove_inputs = valid_inputs.clone();
                        let prove_program = primary_compiled.program.clone();
                        let prove_compiled = primary_compiled.clone();
                        let prove_witness = primary_witness.clone();
                        let runtime_start = Instant::now();
                        let execution =
                            run_with_stage_heartbeat(&config, "primary-runtime-prove", || {
                                let prove = || {
                                    RuntimeExecutor::run_backend_prove_job_with_objective(
                                        config.primary_backend.backend,
                                        config.primary_backend.route,
                                        Arc::new(prove_program),
                                        Some(Arc::new(prove_inputs)),
                                        Some(Arc::new(prove_witness)),
                                        Some(Arc::new(prove_compiled)),
                                        OptimizationObjective::FastestProve,
                                        RequiredTrustLane::StrictCryptographic,
                                        ExecutionMode::Deterministic,
                                    )
                                    .map_err(|error| ZkfError::Backend(error.to_string()))
                                };
                                with_setup_seed_override(Some(SETUP_SEED), || {
                                    with_proof_seed_override(Some(PROOF_SEED), prove)
                                })
                            })?;
                        let runtime_ms = runtime_start.elapsed().as_secs_f64() * 1_000.0;
                        (Some(execution), None, Some(runtime_ms))
                    }
                };
            maybe_write_progress(
                &config.out_dir,
                config.profile,
                config.steps,
                &config.primary_backend.requested_name,
                "primary-verify",
                "running",
                0.0,
                None,
            );
            let verify_start = Instant::now();
            let primary_proof = primary_execution
                .as_ref()
                .map(|execution| (&execution.compiled, &execution.artifact))
                .or_else(|| {
                    primary_direct_proof
                        .as_ref()
                        .map(|proof| (&proof.compiled, &proof.artifact))
                })
                .ok_or_else(|| {
                    ZkfError::Backend(
                        "primary flagship proof missing after proof generation".to_string(),
                    )
                })?;
            if !verify(primary_proof.0, primary_proof.1)? {
                return Err(ZkfError::Backend(format!(
                    "primary {} verification returned false",
                    config.primary_backend.requested_name
                )));
            }
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
            maybe_write_progress(
                &config.out_dir,
                config.profile,
                config.steps,
                &config.primary_backend.requested_name,
                "primary-verify",
                "completed",
                verify_ms,
                None,
            );
            (
                primary_execution,
                primary_direct_proof,
                Some(primary_compile_ms),
                Some(primary_prepare_witness_ms),
                primary_prove_ms,
                Some(verify_ms),
            )
        } else {
            (None, None, None, None, None, None)
        };

        eprintln!(
            "private_turbine_blade_life_showcase: running compatibility groth16 export prove"
        );
        let (compat_proof, compat_prove_ms) = if config.profile.is_flagship()
            && config.primary_backend.backend == BackendKind::ArkworksGroth16
        {
            let proof = primary_direct_proof.as_ref().ok_or_else(|| {
                ZkfError::Backend(
                    "primary arkworks-groth16 proof missing while deriving compatibility export"
                        .to_string(),
                )
            })?;
            (
                EmbeddedProof {
                    compiled: proof.compiled.clone(),
                    artifact: proof.artifact.clone(),
                },
                0.0,
            )
        } else {
            let compat_start = Instant::now();
            let compat_witness = manual_witness.clone();
            let compat = run_with_stage_heartbeat(&config, "compatibility-export-prove", || {
                with_showcase_groth16_mode(trusted_setup_used, || {
                    let compiled =
                        compile(&optimized_program, "arkworks-groth16", Some(SETUP_SEED))?;
                    let artifact = with_proof_seed_override(Some(PROOF_SEED), || {
                        prove(&compiled, &compat_witness)
                    })?;
                    Ok(EmbeddedProof { compiled, artifact })
                })
            })?;
            (compat, compat_start.elapsed().as_secs_f64() * 1_000.0)
        };
        maybe_write_progress(
            &config.out_dir,
            config.profile,
            config.steps,
            &config.primary_backend.requested_name,
            "compatibility-verify",
            "running",
            0.0,
            None,
        );
        let compat_verify_start = Instant::now();
        if !verify(&compat_proof.compiled, &compat_proof.artifact)? {
            return Err(ZkfError::Backend(
                "compatibility groth16 verification returned false".to_string(),
            ));
        }
        let compat_verify_ms = compat_verify_start.elapsed().as_secs_f64() * 1_000.0;
        maybe_write_progress(
            &config.out_dir,
            config.profile,
            config.steps,
            &config.primary_backend.requested_name,
            "compatibility-verify",
            "completed",
            compat_verify_ms,
            None,
        );
        let telemetry_after = telemetry_snapshot();

        eprintln!("private_turbine_blade_life_showcase: exporting bundle");
        let finalize_config = config.clone();
        let report_path =
            run_with_stage_heartbeat(&finalize_config, "bundle-finalize", move || {
                export_bundle(BundleInputs {
                    config,
                    original_program,
                    optimized_program,
                    optimizer_report,
                    witness_public_outputs,
                    primary_execution,
                    primary_direct_proof,
                    compat_proof,
                    manual_witness,
                    telemetry_before,
                    telemetry_after,
                    trusted_setup_requested,
                    trusted_setup_used,
                    setup_provenance,
                    timings: ExportTimings {
                        template_build_ms,
                        witness_ms,
                        optimize_ms,
                        primary_compile_ms,
                        primary_prepare_witness_ms,
                        primary_prove_ms,
                        primary_verify_ms,
                        compat_prove_ms,
                        compat_verify_ms,
                    },
                })
            })?;
        maybe_write_progress(
            &finalize_config.out_dir,
            finalize_config.profile,
            finalize_config.steps,
            &finalize_config.primary_backend.requested_name,
            "completed",
            "completed",
            0.0,
            None,
        );
        Ok(report_path)
    }

    pub fn run_private_turbine_blade_export(
        config: PrivateTurbineBladeExportConfig,
    ) -> ZkfResult<PathBuf> {
        run_with_large_stack_result("private-turbine-blade-export-run", move || {
            run_private_turbine_blade_export_inner(config)
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn unique_temp_dir(label: &str) -> PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            std::env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()))
        }

        #[test]
        #[ignore = "expensive export smoke with foundry and formal runners"]
        fn private_turbine_blade_export_smoke() {
            let out_dir = unique_temp_dir("private-turbine-blade-export-smoke");
            let report_path = run_private_turbine_blade_export(PrivateTurbineBladeExportConfig {
                out_dir: out_dir.clone(),
                steps: 2,
                profile: PrivateTurbineBladeExportProfile::Smoke,
                primary_backend: BackendSelection::native(BackendKind::HyperNova),
                full_audit_requested: false,
                optional_cloudfs_requested: false,
                distributed_plan_requested: false,
            })
            .expect("smoke export");
            assert_eq!(
                report_path,
                out_dir.join("private_turbine_blade.report.md"),
                "export should return the report path"
            );
            ensure_file_exists(&report_path).expect("report");
            let summary: Value =
                read_json(&out_dir.join("private_turbine_blade.summary.json")).expect("summary");
            assert_eq!(summary["export_profile"], "smoke");
            assert_eq!(summary["primary_lane"]["status"], "omitted_in_smoke");
            let evidence: Value =
                read_json(&out_dir.join("private_turbine_blade.evidence_manifest.json"))
                    .expect("evidence manifest");
            assert_eq!(
                evidence["bundle_contract"],
                "private-turbine-blade-smoke-v1"
            );
            let smoke_validation: Value = read_json(
                &out_dir.join("verification/private_turbine_blade.smoke_validation.json"),
            )
            .expect("smoke validation");
            assert_eq!(smoke_validation["compatibility_lane"]["verified"], true);
            let compat_compiled: CompiledProgram =
                read_json(&out_dir.join("compiled/private_turbine_blade.compat.compiled.json"))
                    .expect("compat compiled");
            let compat_artifact: ProofArtifact =
                read_json(&out_dir.join("proofs/private_turbine_blade.compat.proof.json"))
                    .expect("compat proof");
            assert!(verify(&compat_compiled, &compat_artifact).expect("compat verify"));
            let foundry_report =
                fs::read_to_string(out_dir.join("foundry_report.txt")).expect("foundry report");
            assert!(
                !foundry_report.trim().is_empty(),
                "foundry report should not be empty"
            );
            let _ = fs::remove_dir_all(&out_dir);
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
pub use export::{
    PrivateTurbineBladeExportConfig, PrivateTurbineBladeExportProfile,
    run_private_turbine_blade_export,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_safe_witness_satisfies_program() {
        let steps = 6;
        let program = build_private_turbine_blade_life_program_with_steps(steps).expect("program");
        let witness = private_turbine_blade_life_witness_from_request_with_steps(
            &private_turbine_blade_life_sample_request_with_steps(steps),
            steps,
        )
        .expect("witness");
        check_constraints(&program, &witness).expect("constraints");
        assert_eq!(
            witness
                .values
                .get("safe_to_deploy")
                .expect("safe bit")
                .to_decimal_string(),
            "1"
        );
    }

    #[test]
    fn small_violation_witness_still_proves_false() {
        let steps = 6;
        let program = build_private_turbine_blade_life_program_with_steps(steps).expect("program");
        let witness = private_turbine_blade_life_witness_from_request_with_steps(
            &private_turbine_blade_life_violation_request_with_steps(steps),
            steps,
        )
        .expect("witness");
        check_constraints(&program, &witness).expect("constraints");
        assert_eq!(
            witness
                .values
                .get("safe_to_deploy")
                .expect("safe bit")
                .to_decimal_string(),
            "0"
        );
    }
}
