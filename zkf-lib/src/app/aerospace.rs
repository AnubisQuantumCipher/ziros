#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use zkf_core::{Expr, FieldElement, FieldId, Program, WitnessInputs, ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::science::{
    bits_for_bound, decimal_scaled, field, science_scale, science_scale_string, signal_expr,
};
use super::templates::TemplateProgram;

pub const AEROSPACE_TRANSLATIONAL_AXES: usize = 3;
pub const AEROSPACE_ROTATIONAL_AXES: usize = 3;
pub const STARSHIP_DEFAULT_GNC_STEPS: usize = 6;
pub const STARSHIP_DEFAULT_MONTE_CARLO_SAMPLES: usize = 8;
pub const STARSHIP_MONTE_CARLO_PRODUCTION_TARGET_SAMPLES: usize = 10_000;
pub const STARSHIP_TEAM_SUBGRAPH_COUNT: usize = 5;

const GNC_6DOF_CORE_DESCRIPTION: &str = "Attested fixed-step 6-DOF GNC core surface with trajectory commitment, engine-out readiness, bounded replan latency, and surrogate residual lookup binding.";
const TOWER_CATCH_DESCRIPTION: &str = "Tower-catch landing interface certificate with catch-box geometry, arm-clearance floor, and fail-closed closing-speed bounds.";
const BARGE_TERMINAL_DESCRIPTION: &str = "Barge propulsive terminal-profile certificate with deck-motion bounds, lateral clearance, and fail-closed terminal-velocity checks.";
const PLANETARY_PAD_DESCRIPTION: &str = "Planetary pad landing-interface certificate with pad-radius, slope, dust-clearance, and fail-closed terminal-profile bounds.";
const GUST_BATCH_DESCRIPTION: &str = "Monte-Carlo gust robustness batch reducer that proves zero admitted failures for the attested uncertainty batch and bounded replan latency.";
const STARSHIP_DESCRIPTION: &str = "Private Starship-class flip-and-catch certification surface with committed team subgraphs, imported-CRS-only production posture, TCP-counted distributed proving, landing-profile selection, and one-shot Monte-Carlo robustness outputs.";

const TEAM_KIND_ORDER: [TeamSubgraphKindV1; STARSHIP_TEAM_SUBGRAPH_COUNT] = [
    TeamSubgraphKindV1::Propulsion,
    TeamSubgraphKindV1::Aero,
    TeamSubgraphKindV1::Structures,
    TeamSubgraphKindV1::Gnc,
    TeamSubgraphKindV1::LandingInterface,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LandingInterfaceProfileV1 {
    TowerCatch,
    BargePropulsive,
    PlanetaryPad,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TeamSubgraphKindV1 {
    Propulsion,
    Aero,
    Structures,
    Gnc,
    LandingInterface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RigidBodyStateV1 {
    pub position: [String; AEROSPACE_TRANSLATIONAL_AXES],
    pub velocity: [String; AEROSPACE_TRANSLATIONAL_AXES],
    pub attitude: [String; AEROSPACE_ROTATIONAL_AXES],
    pub angular_rate: [String; AEROSPACE_ROTATIONAL_AXES],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VehicleEnvelopeV1 {
    pub wet_mass: String,
    pub dry_mass: String,
    pub propellant_at_flip: String,
    pub max_dynamic_pressure: String,
    pub max_bending_moment: String,
    pub max_thermal_load: String,
    pub fuel_budget: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TowerCatchGeometryV1 {
    pub catch_box_half_width: String,
    pub catch_box_half_height: String,
    pub arm_clearance_floor: String,
    pub closing_speed_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BargeTerminalProfileV1 {
    pub deck_heave_limit: String,
    pub deck_velocity_limit: String,
    pub lateral_clearance_floor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanetaryTerminalProfileV1 {
    pub pad_radius: String,
    pub slope_limit: String,
    pub dust_clearance_floor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonteCarloBatchConfigV1 {
    pub admitted_samples: usize,
    pub gust_bound: String,
    pub mass_property_variation_percent: String,
    pub sensor_noise_bound: String,
    pub engine_out_included: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeamSubgraphDescriptorV1 {
    pub kind: TeamSubgraphKindV1,
    pub interface_commitment: [String; 4],
    pub residual_bound: String,
    pub surrogate_regime_code: u64,
    pub surrogate_certificate_limit: String,
    pub locality_hint: String,
    pub reputation_floor: String,
    pub quorum_weight: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportedCrsManifestRefV1 {
    pub imported_mpc: bool,
    pub ceremony_commitment: [String; 4],
    pub program_binding_commitment: [String; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationInvariantSetV1 {
    pub terminal_velocity_limit: String,
    pub terminal_attitude_limit: String,
    pub terminal_position_limit: String,
    pub max_replan_latency_ms: String,
    pub minimum_collision_clearance: String,
    pub minimum_abort_margin: String,
    pub human_rating_loc_denominator: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificationObservedMetricsV1 {
    pub terminal_velocity_error: String,
    pub terminal_attitude_error: String,
    pub terminal_position_error: String,
    pub fuel_used: String,
    pub max_dynamic_pressure: String,
    pub max_bending_moment: String,
    pub max_thermal_load: String,
    pub min_collision_clearance: String,
    pub abort_reserve_margin: String,
    pub replan_latency_ms: String,
    pub monte_carlo_failure_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistributedProofConfigV1 {
    pub cluster_nodes: usize,
    pub tcp_transport_enforced: bool,
    pub rdma_requested: bool,
    pub peer_reputation_floor: String,
    pub deterministic_partition_manifest_commitment: [String; 4],
    pub scheduler_commitment: [String; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurrogateBandRowV1 {
    pub regime_code: u64,
    pub residual_bound: String,
    pub certificate_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateStarshipFlipCatchRequestV1 {
    pub landing_profile: LandingInterfaceProfileV1,
    pub initial_state: RigidBodyStateV1,
    pub terminal_state: RigidBodyStateV1,
    pub vehicle: VehicleEnvelopeV1,
    pub tower: Option<TowerCatchGeometryV1>,
    pub barge: Option<BargeTerminalProfileV1>,
    pub planetary: Option<PlanetaryTerminalProfileV1>,
    pub monte_carlo: MonteCarloBatchConfigV1,
    pub distributed_proving: DistributedProofConfigV1,
    pub team_subgraphs: Vec<TeamSubgraphDescriptorV1>,
    pub imported_crs: ImportedCrsManifestRefV1,
    pub invariants: CertificationInvariantSetV1,
    pub observed: CertificationObservedMetricsV1,
    pub single_engine_out_abort_ready: bool,
    pub sensor_denial_fallback_ready: bool,
}

fn bool_field(value: bool) -> FieldElement {
    if value {
        FieldElement::ONE
    } else {
        FieldElement::ZERO
    }
}

fn code_field(code: u64) -> FieldElement {
    FieldElement::from_u64(code)
}

fn landing_profile_code(profile: LandingInterfaceProfileV1) -> u64 {
    match profile {
        LandingInterfaceProfileV1::TowerCatch => 1,
        LandingInterfaceProfileV1::BargePropulsive => 2,
        LandingInterfaceProfileV1::PlanetaryPad => 3,
    }
}

fn profile_flags(profile: LandingInterfaceProfileV1) -> [bool; 3] {
    match profile {
        LandingInterfaceProfileV1::TowerCatch => [true, false, false],
        LandingInterfaceProfileV1::BargePropulsive => [false, true, false],
        LandingInterfaceProfileV1::PlanetaryPad => [false, false, true],
    }
}

fn team_kind_slug(kind: TeamSubgraphKindV1) -> &'static str {
    match kind {
        TeamSubgraphKindV1::Propulsion => "propulsion",
        TeamSubgraphKindV1::Aero => "aero",
        TeamSubgraphKindV1::Structures => "structures",
        TeamSubgraphKindV1::Gnc => "gnc",
        TeamSubgraphKindV1::LandingInterface => "landing_interface",
    }
}

fn find_team_descriptor<'a>(
    descriptors: &'a [TeamSubgraphDescriptorV1],
    kind: TeamSubgraphKindV1,
) -> ZkfResult<&'a TeamSubgraphDescriptorV1> {
    descriptors
        .iter()
        .find(|descriptor| descriptor.kind == kind)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "private-starship request is missing required team subgraph '{:?}'",
                kind
            ))
        })
}

fn ordered_team_descriptors(
    descriptors: &[TeamSubgraphDescriptorV1],
) -> ZkfResult<Vec<&TeamSubgraphDescriptorV1>> {
    if descriptors.len() != STARSHIP_TEAM_SUBGRAPH_COUNT {
        return Err(ZkfError::InvalidArtifact(format!(
            "private-starship request requires exactly {STARSHIP_TEAM_SUBGRAPH_COUNT} team subgraphs, got {}",
            descriptors.len()
        )));
    }
    let mut ordered = Vec::with_capacity(STARSHIP_TEAM_SUBGRAPH_COUNT);
    for kind in TEAM_KIND_ORDER {
        ordered.push(find_team_descriptor(descriptors, kind)?);
    }
    Ok(ordered)
}

fn insert_decimal(inputs: &mut WitnessInputs, name: impl Into<String>, value: &str) {
    inputs.insert(name.into(), field(decimal_scaled(value)));
}

fn insert_bool(inputs: &mut WitnessInputs, name: impl Into<String>, value: bool) {
    inputs.insert(name.into(), bool_field(value));
}

fn insert_u64(inputs: &mut WitnessInputs, name: impl Into<String>, value: u64) {
    inputs.insert(name.into(), code_field(value));
}

fn insert_string_array(inputs: &mut WitnessInputs, prefix: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        insert_decimal(inputs, format!("{prefix}_{index}"), value);
    }
}

fn insert_commitment(inputs: &mut WitnessInputs, prefix: &str, words: &[String; 4]) {
    for (index, word) in words.iter().enumerate() {
        insert_decimal(inputs, format!("{prefix}_{index}"), word);
    }
}

fn insert_state(inputs: &mut WitnessInputs, prefix: &str, state: &RigidBodyStateV1) {
    insert_string_array(inputs, &format!("{prefix}_position"), &state.position);
    insert_string_array(inputs, &format!("{prefix}_velocity"), &state.velocity);
    insert_string_array(inputs, &format!("{prefix}_attitude"), &state.attitude);
    insert_string_array(
        inputs,
        &format!("{prefix}_angular_rate"),
        &state.angular_rate,
    );
}

fn commitment_fold_expr(inputs: &[Expr]) -> ZkfResult<Expr> {
    if inputs.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "commitment fold requires at least one input".to_string(),
        ));
    }

    let one = Expr::Const(FieldElement::ONE);
    let mut acc = Expr::Add(vec![inputs[0].clone(), one.clone()]);
    for (index, input) in inputs.iter().enumerate().skip(1) {
        let offset = Expr::Const(FieldElement::from_u64((index as u64) + 1));
        acc = Expr::Add(vec![
            Expr::Mul(
                Box::new(Expr::Add(vec![acc, offset.clone()])),
                Box::new(Expr::Add(vec![input.clone(), one.clone()])),
            ),
            offset,
        ]);
    }
    Ok(acc)
}

fn bind_commitment_fold(
    builder: &mut ProgramBuilder,
    target: &str,
    inputs: &[Expr],
    label: &str,
) -> ZkfResult<()> {
    builder.bind_labeled(
        target,
        commitment_fold_expr(inputs)?,
        Some(label.to_string()),
    )?;
    Ok(())
}

fn sample_state(base: i64) -> RigidBodyStateV1 {
    let s = |offset: i64| (base + offset).to_string();
    RigidBodyStateV1 {
        position: [s(1), s(2), s(3)],
        velocity: [s(4), s(5), s(6)],
        attitude: [s(7), s(8), s(9)],
        angular_rate: [s(10), s(11), s(12)],
    }
}

fn sample_surrogate_rows() -> Vec<SurrogateBandRowV1> {
    vec![
        SurrogateBandRowV1 {
            regime_code: 0,
            residual_bound: "0.01".to_string(),
            certificate_limit: "0.05".to_string(),
        },
        SurrogateBandRowV1 {
            regime_code: 1,
            residual_bound: "0.02".to_string(),
            certificate_limit: "0.08".to_string(),
        },
        SurrogateBandRowV1 {
            regime_code: 2,
            residual_bound: "0.03".to_string(),
            certificate_limit: "0.10".to_string(),
        },
        SurrogateBandRowV1 {
            regime_code: 3,
            residual_bound: "0.04".to_string(),
            certificate_limit: "0.12".to_string(),
        },
        SurrogateBandRowV1 {
            regime_code: 4,
            residual_bound: "0.05".to_string(),
            certificate_limit: "0.15".to_string(),
        },
    ]
}

pub fn add_surrogate_band_lookup(
    builder: &mut ProgramBuilder,
    table_name: &str,
    rows: &[SurrogateBandRowV1],
) -> ZkfResult<()> {
    let values = rows
        .iter()
        .map(|row| {
            vec![
                code_field(row.regime_code),
                field(decimal_scaled(&row.residual_bound)),
                field(decimal_scaled(&row.certificate_limit)),
            ]
        })
        .collect::<Vec<_>>();
    builder.add_lookup_table(table_name, 3, values)?;
    Ok(())
}

pub fn constrain_surrogate_band_lookup(
    builder: &mut ProgramBuilder,
    table_name: &str,
    regime_signal: &str,
    residual_signal: &str,
    limit_signal: &str,
    label: Option<&str>,
) -> ZkfResult<()> {
    builder.constrain_lookup_labeled(
        &[
            signal_expr(regime_signal),
            signal_expr(residual_signal),
            signal_expr(limit_signal),
        ],
        table_name.to_string(),
        label.map(str::to_string),
    )?;
    Ok(())
}

fn declare_state(builder: &mut ProgramBuilder, prefix: &str) -> ZkfResult<Vec<String>> {
    let mut names = Vec::new();
    for group in ["position", "velocity", "attitude", "angular_rate"] {
        let len = if matches!(group, "attitude" | "angular_rate") {
            AEROSPACE_ROTATIONAL_AXES
        } else {
            AEROSPACE_TRANSLATIONAL_AXES
        };
        names.extend(builder.private_input_array(format!("{prefix}_{group}"), len)?);
    }
    Ok(names)
}

fn build_gnc_6dof_core_program_internal(steps: usize) -> ZkfResult<Program> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "gnc-6dof-core requires at least one step".to_string(),
        ));
    }

    let mut builder =
        ProgramBuilder::new(format!("gnc_6dof_core_{steps}_steps_v1"), FieldId::Bn254);
    builder.metadata_entry("application", "gnc-6dof-core")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;
    builder.metadata_entry("distributed_transport", "tcp-counted;rdma-follow-on")?;
    builder.metadata_entry(
        "backend_pattern",
        "monte-carlo=plonky3;folding=nova-hypernova;wrap=groth16",
    )?;
    builder.metadata_entry("neural_engine_role", "advisory-only")?;
    builder.metadata_entry("attested_fixed_steps", &steps.to_string())?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;

    let state_inputs = declare_state(&mut builder, "initial_state")?;
    let final_state_inputs = declare_state(&mut builder, "terminal_state")?;
    let step_margins = builder.private_input_array("step_margin", steps)?;
    builder.private_input("fuel_used")?;
    builder.private_input("fuel_budget")?;
    builder.private_input("max_dynamic_pressure_observed")?;
    builder.private_input("max_dynamic_pressure_limit")?;
    builder.private_input("replan_latency_ms")?;
    builder.private_input("max_replan_latency_ms")?;
    builder.private_input("engine_out_abort_ready")?;
    builder.private_input("sensor_denial_ready")?;
    builder.private_input("surrogate_regime_code")?;
    builder.private_input("surrogate_residual_bound")?;
    builder.private_input("surrogate_certificate_limit")?;
    builder.public_output("state_commitment")?;
    builder.public_output("fuel_margin")?;
    builder.public_output("dynamic_pressure_margin")?;
    builder.public_output("latency_margin")?;
    builder.public_output("core_safety_satisfied")?;

    let range_bits = bits_for_bound(&(science_scale() * 10_000u32));
    builder.constrain_boolean("engine_out_abort_ready")?;
    builder.constrain_boolean("sensor_denial_ready")?;
    builder.constrain_equal(
        signal_expr("engine_out_abort_ready"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("sensor_denial_ready"),
        Expr::Const(FieldElement::ONE),
    )?;
    for name in [
        "fuel_used",
        "fuel_budget",
        "max_dynamic_pressure_observed",
        "max_dynamic_pressure_limit",
        "replan_latency_ms",
        "max_replan_latency_ms",
        "surrogate_regime_code",
        "surrogate_residual_bound",
        "surrogate_certificate_limit",
    ] {
        builder.constrain_range(name, range_bits)?;
    }
    for name in &step_margins {
        builder.constrain_range(name, range_bits)?;
    }
    builder.constrain_leq(
        "fuel_margin",
        signal_expr("fuel_used"),
        signal_expr("fuel_budget"),
        range_bits,
    )?;
    builder.constrain_leq(
        "dynamic_pressure_margin",
        signal_expr("max_dynamic_pressure_observed"),
        signal_expr("max_dynamic_pressure_limit"),
        range_bits,
    )?;
    builder.constrain_leq(
        "latency_margin",
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
        range_bits,
    )?;
    builder.constrain_equal(
        signal_expr("core_safety_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;

    add_surrogate_band_lookup(
        &mut builder,
        "gnc_surrogate_bands",
        &sample_surrogate_rows(),
    )?;
    constrain_surrogate_band_lookup(
        &mut builder,
        "gnc_surrogate_bands",
        "surrogate_regime_code",
        "surrogate_residual_bound",
        "surrogate_certificate_limit",
        Some("gnc_surrogate_band"),
    )?;

    let mut commitment_inputs = state_inputs
        .iter()
        .chain(final_state_inputs.iter())
        .chain(step_margins.iter())
        .map(|name| signal_expr(name))
        .collect::<Vec<_>>();
    commitment_inputs.extend([
        signal_expr("fuel_used"),
        signal_expr("fuel_budget"),
        signal_expr("max_dynamic_pressure_observed"),
        signal_expr("max_dynamic_pressure_limit"),
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
        signal_expr("surrogate_regime_code"),
        signal_expr("surrogate_residual_bound"),
        signal_expr("surrogate_certificate_limit"),
    ]);
    bind_commitment_fold(
        &mut builder,
        "state_commitment",
        &commitment_inputs,
        "state_commitment_fold",
    )?;

    builder.build()
}

fn default_gnc_6dof_core_sample_inputs(steps: usize) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    insert_state(&mut inputs, "initial_state", &sample_state(10));
    insert_state(&mut inputs, "terminal_state", &sample_state(30));
    for index in 0..steps {
        insert_decimal(&mut inputs, format!("step_margin_{index}"), "5");
    }
    insert_decimal(&mut inputs, "fuel_used", "800");
    insert_decimal(&mut inputs, "fuel_budget", "900");
    insert_decimal(&mut inputs, "max_dynamic_pressure_observed", "200");
    insert_decimal(&mut inputs, "max_dynamic_pressure_limit", "250");
    insert_decimal(&mut inputs, "replan_latency_ms", "200");
    insert_decimal(&mut inputs, "max_replan_latency_ms", "500");
    insert_bool(&mut inputs, "engine_out_abort_ready", true);
    insert_bool(&mut inputs, "sensor_denial_ready", true);
    insert_u64(&mut inputs, "surrogate_regime_code", 1);
    insert_decimal(&mut inputs, "surrogate_residual_bound", "0.02");
    insert_decimal(&mut inputs, "surrogate_certificate_limit", "0.08");
    inputs
}

pub fn build_gnc_6dof_core_program_with_steps(steps: usize) -> ZkfResult<Program> {
    build_gnc_6dof_core_program_internal(steps)
}

pub fn gnc_6dof_core_showcase() -> ZkfResult<TemplateProgram> {
    gnc_6dof_core_showcase_with_steps(STARSHIP_DEFAULT_GNC_STEPS)
}

pub fn gnc_6dof_core_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    let sample_inputs = default_gnc_6dof_core_sample_inputs(steps);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(
        "replan_latency_ms".to_string(),
        field(decimal_scaled("750")),
    );
    Ok(TemplateProgram {
        program: build_gnc_6dof_core_program_internal(steps)?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "state_commitment".to_string(),
            "fuel_margin".to_string(),
            "dynamic_pressure_margin".to_string(),
            "latency_margin".to_string(),
            "core_safety_satisfied".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: GNC_6DOF_CORE_DESCRIPTION,
    })
}

fn build_tower_catch_geometry_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("tower_catch_geometry_v1", FieldId::Bn254);
    builder.metadata_entry("application", "tower-catch-geometry")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry("landing_interface", "tower-catch")?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;

    builder.private_input("lateral_offset")?;
    builder.private_input("vertical_offset")?;
    builder.private_input("arm_clearance")?;
    builder.private_input("closing_speed")?;
    builder.private_input("half_width_limit")?;
    builder.private_input("half_height_limit")?;
    builder.private_input("arm_clearance_floor")?;
    builder.private_input("closing_speed_limit")?;
    builder.public_output("geometry_commitment")?;
    builder.public_output("clearance_margin")?;
    builder.public_output("closing_speed_margin")?;
    builder.public_output("geometry_satisfied")?;

    let bits = bits_for_bound(&(science_scale() * 1000u32));
    for name in [
        "lateral_offset",
        "vertical_offset",
        "arm_clearance",
        "closing_speed",
        "half_width_limit",
        "half_height_limit",
        "arm_clearance_floor",
        "closing_speed_limit",
    ] {
        builder.constrain_range(name, bits)?;
    }
    builder.constrain_leq(
        "lateral_margin",
        signal_expr("lateral_offset"),
        signal_expr("half_width_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "vertical_margin",
        signal_expr("vertical_offset"),
        signal_expr("half_height_limit"),
        bits,
    )?;
    builder.constrain_geq(
        "clearance_margin",
        signal_expr("arm_clearance"),
        signal_expr("arm_clearance_floor"),
        bits,
    )?;
    builder.constrain_leq(
        "closing_speed_margin",
        signal_expr("closing_speed"),
        signal_expr("closing_speed_limit"),
        bits,
    )?;
    builder.constrain_equal(
        signal_expr("geometry_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;
    bind_commitment_fold(
        &mut builder,
        "geometry_commitment",
        &[
            signal_expr("lateral_offset"),
            signal_expr("vertical_offset"),
            signal_expr("arm_clearance"),
            signal_expr("closing_speed"),
            signal_expr("half_width_limit"),
            signal_expr("half_height_limit"),
        ],
        "tower_geometry_commitment_fold",
    )?;
    builder.build()
}

pub fn tower_catch_geometry_showcase() -> ZkfResult<TemplateProgram> {
    let sample_inputs = WitnessInputs::from([
        ("lateral_offset".to_string(), field(decimal_scaled("0.5"))),
        ("vertical_offset".to_string(), field(decimal_scaled("0.25"))),
        ("arm_clearance".to_string(), field(decimal_scaled("4"))),
        ("closing_speed".to_string(), field(decimal_scaled("0.6"))),
        ("half_width_limit".to_string(), field(decimal_scaled("2"))),
        ("half_height_limit".to_string(), field(decimal_scaled("1"))),
        (
            "arm_clearance_floor".to_string(),
            field(decimal_scaled("3")),
        ),
        (
            "closing_speed_limit".to_string(),
            field(decimal_scaled("1")),
        ),
    ]);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert("arm_clearance".to_string(), field(decimal_scaled("2")));
    Ok(TemplateProgram {
        program: build_tower_catch_geometry_program()?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "geometry_commitment".to_string(),
            "clearance_margin".to_string(),
            "closing_speed_margin".to_string(),
            "geometry_satisfied".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: TOWER_CATCH_DESCRIPTION,
    })
}

fn build_barge_terminal_profile_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("barge_terminal_profile_v1", FieldId::Bn254);
    builder.metadata_entry("application", "barge-terminal-profile")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry("landing_interface", "barge-propulsive")?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;

    builder.private_input("deck_heave")?;
    builder.private_input("deck_velocity")?;
    builder.private_input("terminal_velocity")?;
    builder.private_input("lateral_clearance")?;
    builder.private_input("deck_heave_limit")?;
    builder.private_input("deck_velocity_limit")?;
    builder.private_input("terminal_velocity_limit")?;
    builder.private_input("lateral_clearance_floor")?;
    builder.public_output("profile_commitment")?;
    builder.public_output("heave_margin")?;
    builder.public_output("velocity_margin")?;
    builder.public_output("clearance_margin")?;
    builder.public_output("profile_satisfied")?;

    let bits = bits_for_bound(&(science_scale() * 1000u32));
    for name in [
        "deck_heave",
        "deck_velocity",
        "terminal_velocity",
        "lateral_clearance",
        "deck_heave_limit",
        "deck_velocity_limit",
        "terminal_velocity_limit",
        "lateral_clearance_floor",
    ] {
        builder.constrain_range(name, bits)?;
    }
    builder.constrain_leq(
        "heave_margin",
        signal_expr("deck_heave"),
        signal_expr("deck_heave_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "deck_velocity_margin",
        signal_expr("deck_velocity"),
        signal_expr("deck_velocity_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "velocity_margin",
        signal_expr("terminal_velocity"),
        signal_expr("terminal_velocity_limit"),
        bits,
    )?;
    builder.constrain_geq(
        "clearance_margin",
        signal_expr("lateral_clearance"),
        signal_expr("lateral_clearance_floor"),
        bits,
    )?;
    builder.constrain_equal(
        signal_expr("profile_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;
    bind_commitment_fold(
        &mut builder,
        "profile_commitment",
        &[
            signal_expr("deck_heave"),
            signal_expr("deck_velocity"),
            signal_expr("terminal_velocity"),
            signal_expr("lateral_clearance"),
        ],
        "barge_profile_commitment_fold",
    )?;
    builder.build()
}

pub fn barge_terminal_profile_showcase() -> ZkfResult<TemplateProgram> {
    let sample_inputs = WitnessInputs::from([
        ("deck_heave".to_string(), field(decimal_scaled("0.8"))),
        ("deck_velocity".to_string(), field(decimal_scaled("0.7"))),
        (
            "terminal_velocity".to_string(),
            field(decimal_scaled("0.9")),
        ),
        ("lateral_clearance".to_string(), field(decimal_scaled("5"))),
        ("deck_heave_limit".to_string(), field(decimal_scaled("1"))),
        (
            "deck_velocity_limit".to_string(),
            field(decimal_scaled("1")),
        ),
        (
            "terminal_velocity_limit".to_string(),
            field(decimal_scaled("1")),
        ),
        (
            "lateral_clearance_floor".to_string(),
            field(decimal_scaled("4")),
        ),
    ]);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(
        "terminal_velocity".to_string(),
        field(decimal_scaled("1.4")),
    );
    Ok(TemplateProgram {
        program: build_barge_terminal_profile_program()?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "profile_commitment".to_string(),
            "heave_margin".to_string(),
            "velocity_margin".to_string(),
            "clearance_margin".to_string(),
            "profile_satisfied".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: BARGE_TERMINAL_DESCRIPTION,
    })
}

fn build_planetary_terminal_profile_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("planetary_terminal_profile_v1", FieldId::Bn254);
    builder.metadata_entry("application", "planetary-terminal-profile")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry("landing_interface", "planetary-pad")?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;

    builder.private_input("pad_radius_error")?;
    builder.private_input("terminal_velocity")?;
    builder.private_input("slope")?;
    builder.private_input("dust_clearance")?;
    builder.private_input("pad_radius_limit")?;
    builder.private_input("terminal_velocity_limit")?;
    builder.private_input("slope_limit")?;
    builder.private_input("dust_clearance_floor")?;
    builder.public_output("profile_commitment")?;
    builder.public_output("radius_margin")?;
    builder.public_output("velocity_margin")?;
    builder.public_output("slope_margin")?;
    builder.public_output("dust_margin")?;
    builder.public_output("profile_satisfied")?;

    let bits = bits_for_bound(&(science_scale() * 1000u32));
    for name in [
        "pad_radius_error",
        "terminal_velocity",
        "slope",
        "dust_clearance",
        "pad_radius_limit",
        "terminal_velocity_limit",
        "slope_limit",
        "dust_clearance_floor",
    ] {
        builder.constrain_range(name, bits)?;
    }
    builder.constrain_leq(
        "radius_margin",
        signal_expr("pad_radius_error"),
        signal_expr("pad_radius_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "velocity_margin",
        signal_expr("terminal_velocity"),
        signal_expr("terminal_velocity_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "slope_margin",
        signal_expr("slope"),
        signal_expr("slope_limit"),
        bits,
    )?;
    builder.constrain_geq(
        "dust_margin",
        signal_expr("dust_clearance"),
        signal_expr("dust_clearance_floor"),
        bits,
    )?;
    builder.constrain_equal(
        signal_expr("profile_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;
    bind_commitment_fold(
        &mut builder,
        "profile_commitment",
        &[
            signal_expr("pad_radius_error"),
            signal_expr("terminal_velocity"),
            signal_expr("slope"),
            signal_expr("dust_clearance"),
        ],
        "planetary_profile_commitment_fold",
    )?;
    builder.build()
}

pub fn planetary_terminal_profile_showcase() -> ZkfResult<TemplateProgram> {
    let sample_inputs = WitnessInputs::from([
        ("pad_radius_error".to_string(), field(decimal_scaled("0.8"))),
        (
            "terminal_velocity".to_string(),
            field(decimal_scaled("0.7")),
        ),
        ("slope".to_string(), field(decimal_scaled("2"))),
        ("dust_clearance".to_string(), field(decimal_scaled("6"))),
        ("pad_radius_limit".to_string(), field(decimal_scaled("2"))),
        (
            "terminal_velocity_limit".to_string(),
            field(decimal_scaled("1")),
        ),
        ("slope_limit".to_string(), field(decimal_scaled("5"))),
        (
            "dust_clearance_floor".to_string(),
            field(decimal_scaled("4")),
        ),
    ]);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert("slope".to_string(), field(decimal_scaled("7")));
    Ok(TemplateProgram {
        program: build_planetary_terminal_profile_program()?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "profile_commitment".to_string(),
            "radius_margin".to_string(),
            "velocity_margin".to_string(),
            "slope_margin".to_string(),
            "dust_margin".to_string(),
            "profile_satisfied".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: PLANETARY_PAD_DESCRIPTION,
    })
}

fn build_gust_robustness_batch_program_internal(samples: usize) -> ZkfResult<Program> {
    if samples == 0 {
        return Err(ZkfError::InvalidArtifact(
            "gust-robustness-batch requires at least one sample".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("gust_robustness_batch_{samples}_samples_v1"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "gust-robustness-batch")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry(
        "production_monte_carlo_target",
        &STARSHIP_MONTE_CARLO_PRODUCTION_TARGET_SAMPLES.to_string(),
    )?;
    builder.metadata_entry("backend_pattern", "batch=plonky3;final-wrap=groth16")?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;

    let gusts = builder.private_input_array("gust_sample", samples)?;
    builder.private_input("gust_bound")?;
    builder.private_input("admitted_failures")?;
    builder.private_input("replan_latency_ms")?;
    builder.private_input("max_replan_latency_ms")?;
    builder.private_input("engine_out_included")?;
    builder.public_output("batch_commitment")?;
    builder.public_output("batch_satisfied")?;
    builder.public_output("latency_margin")?;

    let bits = bits_for_bound(&(science_scale() * 100_000u32));
    builder.constrain_boolean("engine_out_included")?;
    builder.constrain_equal(
        signal_expr("engine_out_included"),
        Expr::Const(FieldElement::ONE),
    )?;
    for name in [
        "gust_bound",
        "admitted_failures",
        "replan_latency_ms",
        "max_replan_latency_ms",
    ] {
        builder.constrain_range(name, bits)?;
    }
    for gust in &gusts {
        builder.constrain_range(gust, bits)?;
        builder.constrain_leq(
            format!("{gust}_margin"),
            signal_expr(gust),
            signal_expr("gust_bound"),
            bits,
        )?;
    }
    builder.constrain_equal(
        signal_expr("admitted_failures"),
        Expr::Const(FieldElement::ZERO),
    )?;
    builder.constrain_leq(
        "latency_margin",
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
        bits,
    )?;
    builder.constrain_equal(
        signal_expr("batch_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;

    let mut commitment_inputs = gusts
        .iter()
        .map(|name| signal_expr(name))
        .collect::<Vec<_>>();
    commitment_inputs.extend([
        signal_expr("gust_bound"),
        signal_expr("admitted_failures"),
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
    ]);
    bind_commitment_fold(
        &mut builder,
        "batch_commitment",
        &commitment_inputs,
        "gust_batch_commitment_fold",
    )?;
    builder.build()
}

pub fn build_gust_robustness_batch_program_with_samples(samples: usize) -> ZkfResult<Program> {
    build_gust_robustness_batch_program_internal(samples)
}

pub fn gust_robustness_batch_showcase() -> ZkfResult<TemplateProgram> {
    gust_robustness_batch_showcase_with_samples(STARSHIP_DEFAULT_MONTE_CARLO_SAMPLES)
}

pub fn gust_robustness_batch_showcase_with_samples(samples: usize) -> ZkfResult<TemplateProgram> {
    let mut sample_inputs = WitnessInputs::new();
    for index in 0..samples {
        insert_decimal(&mut sample_inputs, format!("gust_sample_{index}"), "12");
    }
    insert_decimal(&mut sample_inputs, "gust_bound", "50");
    insert_decimal(&mut sample_inputs, "admitted_failures", "0");
    insert_decimal(&mut sample_inputs, "replan_latency_ms", "250");
    insert_decimal(&mut sample_inputs, "max_replan_latency_ms", "500");
    insert_bool(&mut sample_inputs, "engine_out_included", true);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert("admitted_failures".to_string(), field(decimal_scaled("1")));
    Ok(TemplateProgram {
        program: build_gust_robustness_batch_program_internal(samples)?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "batch_commitment".to_string(),
            "batch_satisfied".to_string(),
            "latency_margin".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: GUST_BATCH_DESCRIPTION,
    })
}

fn selected_profile_geometry(
    request: &PrivateStarshipFlipCatchRequestV1,
) -> ZkfResult<(String, String, String)> {
    match request.landing_profile {
        LandingInterfaceProfileV1::TowerCatch => {
            let tower = request.tower.as_ref().ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "tower-catch profile requires `tower` geometry".to_string(),
                )
            })?;
            Ok((
                tower.arm_clearance_floor.clone(),
                tower.closing_speed_limit.clone(),
                request.invariants.terminal_position_limit.clone(),
            ))
        }
        LandingInterfaceProfileV1::BargePropulsive => {
            let barge = request.barge.as_ref().ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "barge-propulsive profile requires `barge` geometry".to_string(),
                )
            })?;
            Ok((
                barge.lateral_clearance_floor.clone(),
                barge.deck_velocity_limit.clone(),
                request.invariants.terminal_position_limit.clone(),
            ))
        }
        LandingInterfaceProfileV1::PlanetaryPad => {
            let planetary = request.planetary.as_ref().ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "planetary-pad profile requires `planetary` geometry".to_string(),
                )
            })?;
            Ok((
                planetary.dust_clearance_floor.clone(),
                planetary.slope_limit.clone(),
                request.invariants.terminal_position_limit.clone(),
            ))
        }
    }
}

pub fn private_starship_flip_catch_inputs_from_request(
    request: &PrivateStarshipFlipCatchRequestV1,
    steps: usize,
    samples: usize,
) -> ZkfResult<WitnessInputs> {
    if request.monte_carlo.admitted_samples != samples {
        return Err(ZkfError::InvalidArtifact(format!(
            "request admitted_samples={} must match template samples={samples}",
            request.monte_carlo.admitted_samples
        )));
    }
    if request.distributed_proving.cluster_nodes == 0 {
        return Err(ZkfError::InvalidArtifact(
            "distributed proving requires cluster_nodes > 0".to_string(),
        ));
    }
    let ordered_descriptors = ordered_team_descriptors(&request.team_subgraphs)?;
    let flags = profile_flags(request.landing_profile);
    let (selected_clearance_floor, selected_motion_limit, selected_position_limit) =
        selected_profile_geometry(request)?;

    let mut inputs = WitnessInputs::new();
    insert_state(&mut inputs, "initial_state", &request.initial_state);
    insert_state(&mut inputs, "terminal_state", &request.terminal_state);
    for index in 0..steps {
        insert_decimal(&mut inputs, format!("step_margin_{index}"), "4");
    }
    for index in 0..samples {
        insert_decimal(&mut inputs, format!("batch_sample_{index}"), "1");
    }

    for (index, enabled) in flags.iter().enumerate() {
        insert_bool(&mut inputs, format!("landing_profile_{index}"), *enabled);
    }
    insert_u64(
        &mut inputs,
        "landing_profile_code",
        landing_profile_code(request.landing_profile),
    );
    insert_decimal(
        &mut inputs,
        "terminal_velocity_error",
        &request.observed.terminal_velocity_error,
    );
    insert_decimal(
        &mut inputs,
        "terminal_attitude_error",
        &request.observed.terminal_attitude_error,
    );
    insert_decimal(
        &mut inputs,
        "terminal_position_error",
        &request.observed.terminal_position_error,
    );
    insert_decimal(&mut inputs, "fuel_used", &request.observed.fuel_used);
    insert_decimal(&mut inputs, "fuel_budget", &request.vehicle.fuel_budget);
    insert_decimal(
        &mut inputs,
        "max_dynamic_pressure_observed",
        &request.observed.max_dynamic_pressure,
    );
    insert_decimal(
        &mut inputs,
        "max_dynamic_pressure_limit",
        &request.vehicle.max_dynamic_pressure,
    );
    insert_decimal(
        &mut inputs,
        "max_bending_moment_observed",
        &request.observed.max_bending_moment,
    );
    insert_decimal(
        &mut inputs,
        "max_bending_moment_limit",
        &request.vehicle.max_bending_moment,
    );
    insert_decimal(
        &mut inputs,
        "max_thermal_load_observed",
        &request.observed.max_thermal_load,
    );
    insert_decimal(
        &mut inputs,
        "max_thermal_load_limit",
        &request.vehicle.max_thermal_load,
    );
    insert_decimal(
        &mut inputs,
        "terminal_velocity_limit",
        &request.invariants.terminal_velocity_limit,
    );
    insert_decimal(
        &mut inputs,
        "terminal_attitude_limit",
        &request.invariants.terminal_attitude_limit,
    );
    insert_decimal(
        &mut inputs,
        "terminal_position_limit",
        &request.invariants.terminal_position_limit,
    );
    insert_decimal(
        &mut inputs,
        "selected_clearance_floor",
        &selected_clearance_floor,
    );
    insert_decimal(&mut inputs, "selected_motion_limit", &selected_motion_limit);
    insert_decimal(
        &mut inputs,
        "selected_position_limit",
        &selected_position_limit,
    );
    insert_decimal(
        &mut inputs,
        "min_collision_clearance",
        &request.observed.min_collision_clearance,
    );
    insert_decimal(
        &mut inputs,
        "minimum_collision_clearance",
        &request.invariants.minimum_collision_clearance,
    );
    insert_decimal(
        &mut inputs,
        "abort_reserve_margin",
        &request.observed.abort_reserve_margin,
    );
    insert_decimal(
        &mut inputs,
        "minimum_abort_margin",
        &request.invariants.minimum_abort_margin,
    );
    insert_decimal(
        &mut inputs,
        "replan_latency_ms",
        &request.observed.replan_latency_ms,
    );
    insert_decimal(
        &mut inputs,
        "max_replan_latency_ms",
        &request.invariants.max_replan_latency_ms,
    );
    insert_decimal(&mut inputs, "gust_bound", &request.monte_carlo.gust_bound);
    insert_decimal(
        &mut inputs,
        "mass_property_variation_percent",
        &request.monte_carlo.mass_property_variation_percent,
    );
    insert_decimal(
        &mut inputs,
        "sensor_noise_bound",
        &request.monte_carlo.sensor_noise_bound,
    );
    insert_decimal(
        &mut inputs,
        "monte_carlo_failure_count",
        &request.observed.monte_carlo_failure_count.to_string(),
    );
    insert_bool(
        &mut inputs,
        "monte_carlo_engine_out_included",
        request.monte_carlo.engine_out_included,
    );
    insert_bool(
        &mut inputs,
        "single_engine_out_abort_ready",
        request.single_engine_out_abort_ready,
    );
    insert_bool(
        &mut inputs,
        "sensor_denial_fallback_ready",
        request.sensor_denial_fallback_ready,
    );
    insert_bool(
        &mut inputs,
        "imported_crs_only_flag",
        request.imported_crs.imported_mpc,
    );
    insert_bool(
        &mut inputs,
        "tcp_transport_enforced",
        request.distributed_proving.tcp_transport_enforced,
    );
    insert_bool(
        &mut inputs,
        "rdma_requested",
        request.distributed_proving.rdma_requested,
    );
    insert_decimal(
        &mut inputs,
        "peer_reputation_floor",
        &request.distributed_proving.peer_reputation_floor,
    );
    insert_decimal(
        &mut inputs,
        "cluster_nodes",
        &request.distributed_proving.cluster_nodes.to_string(),
    );
    insert_commitment(
        &mut inputs,
        "partition_manifest_commitment",
        &request
            .distributed_proving
            .deterministic_partition_manifest_commitment,
    );
    insert_commitment(
        &mut inputs,
        "scheduler_commitment",
        &request.distributed_proving.scheduler_commitment,
    );
    insert_commitment(
        &mut inputs,
        "imported_crs_ceremony_commitment",
        &request.imported_crs.ceremony_commitment,
    );
    insert_commitment(
        &mut inputs,
        "imported_crs_program_binding_commitment",
        &request.imported_crs.program_binding_commitment,
    );

    for descriptor in ordered_descriptors {
        let prefix = format!("team_{}", team_kind_slug(descriptor.kind));
        insert_commitment(
            &mut inputs,
            &format!("{prefix}_commitment"),
            &descriptor.interface_commitment,
        );
        insert_decimal(
            &mut inputs,
            format!("{prefix}_residual_bound"),
            &descriptor.residual_bound,
        );
        insert_u64(
            &mut inputs,
            format!("{prefix}_surrogate_regime_code"),
            descriptor.surrogate_regime_code,
        );
        insert_decimal(
            &mut inputs,
            format!("{prefix}_surrogate_certificate_limit"),
            &descriptor.surrogate_certificate_limit,
        );
        insert_decimal(
            &mut inputs,
            format!("{prefix}_reputation_floor"),
            &descriptor.reputation_floor,
        );
        insert_decimal(
            &mut inputs,
            format!("{prefix}_quorum_weight"),
            &descriptor.quorum_weight,
        );
    }

    Ok(inputs)
}

fn build_private_starship_flip_catch_program_internal(
    profile: LandingInterfaceProfileV1,
    steps: usize,
    samples: usize,
) -> ZkfResult<Program> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private-starship-flip-catch requires at least one step".to_string(),
        ));
    }
    if samples == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private-starship-flip-catch requires at least one Monte-Carlo sample".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!(
            "private_starship_flip_catch_{}_{}_steps_{}_samples_v1",
            landing_profile_code(profile),
            steps,
            samples
        ),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "private-starship-flip-catch")?;
    builder.metadata_entry("domain", "aerospace")?;
    builder.metadata_entry(
        "landing_profile_default",
        &landing_profile_code(profile).to_string(),
    )?;
    builder.metadata_entry("production_trusted_setup", "imported-crs-only")?;
    builder.metadata_entry("neural_engine_role", "advisory-only")?;
    builder.metadata_entry(
        "distributed_transport",
        "tcp-counted;rdma-follow-on-unshipped",
    )?;
    builder.metadata_entry("distributed_cluster_target", "128")?;
    builder.metadata_entry(
        "backend_pattern",
        "batch=plonky3;long-horizon=nova-hypernova;final-wrap=groth16",
    )?;
    builder.metadata_entry(
        "scope_boundary",
        "committed reduced-order certification surface with surrogate/error bounds; no raw CFD, FEM, or flight software source is exposed",
    )?;
    builder.metadata_entry("attested_fixed_steps", &steps.to_string())?;
    builder.metadata_entry("attested_batch_samples", &samples.to_string())?;
    builder.metadata_entry(
        "production_batch_target",
        &STARSHIP_MONTE_CARLO_PRODUCTION_TARGET_SAMPLES.to_string(),
    )?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;

    let initial_state_inputs = declare_state(&mut builder, "initial_state")?;
    let terminal_state_inputs = declare_state(&mut builder, "terminal_state")?;
    let step_margins = builder.private_input_array("step_margin", steps)?;
    let batch_samples = builder.private_input_array("batch_sample", samples)?;
    let landing_selectors = builder.private_input_array("landing_profile", 3)?;
    builder.private_input("landing_profile_code")?;
    for name in [
        "terminal_velocity_error",
        "terminal_attitude_error",
        "terminal_position_error",
        "fuel_used",
        "fuel_budget",
        "max_dynamic_pressure_observed",
        "max_dynamic_pressure_limit",
        "max_bending_moment_observed",
        "max_bending_moment_limit",
        "max_thermal_load_observed",
        "max_thermal_load_limit",
        "terminal_velocity_limit",
        "terminal_attitude_limit",
        "terminal_position_limit",
        "selected_clearance_floor",
        "selected_motion_limit",
        "selected_position_limit",
        "min_collision_clearance",
        "minimum_collision_clearance",
        "abort_reserve_margin",
        "minimum_abort_margin",
        "replan_latency_ms",
        "max_replan_latency_ms",
        "gust_bound",
        "mass_property_variation_percent",
        "sensor_noise_bound",
        "monte_carlo_failure_count",
        "peer_reputation_floor",
        "cluster_nodes",
    ] {
        builder.private_input(name)?;
    }
    for name in [
        "single_engine_out_abort_ready",
        "sensor_denial_fallback_ready",
        "monte_carlo_engine_out_included",
        "imported_crs_only_flag",
        "tcp_transport_enforced",
        "rdma_requested",
    ] {
        builder.private_input(name)?;
    }
    let partition_commitment = builder.private_input_array("partition_manifest_commitment", 4)?;
    let scheduler_commitment = builder.private_input_array("scheduler_commitment", 4)?;
    let crs_ceremony_commitment =
        builder.private_input_array("imported_crs_ceremony_commitment", 4)?;
    let crs_program_binding_commitment =
        builder.private_input_array("imported_crs_program_binding_commitment", 4)?;
    let mut team_commitments = Vec::new();
    let mut team_scalar_inputs = Vec::new();
    for kind in TEAM_KIND_ORDER {
        let slug = team_kind_slug(kind);
        team_commitments.extend(builder.private_input_array(format!("team_{slug}_commitment"), 4)?);
        for suffix in [
            "residual_bound",
            "surrogate_regime_code",
            "surrogate_certificate_limit",
            "reputation_floor",
            "quorum_weight",
        ] {
            let name = format!("team_{slug}_{suffix}");
            builder.private_input(&name)?;
            team_scalar_inputs.push(name);
        }
    }

    for name in [
        "trajectory_commitment",
        "subgraph_commitment",
        "batch_commitment",
        "fuel_margin",
        "velocity_margin",
        "attitude_margin",
        "position_margin",
        "dynamic_pressure_margin",
        "bending_margin",
        "thermal_margin",
        "collision_margin",
        "abort_margin",
        "latency_margin",
        "landing_profile_public_code",
        "safety_satisfied",
    ] {
        builder.public_output(name)?;
    }

    let bits = bits_for_bound(&(science_scale() * 1_000_000u32));
    builder.constrain_exactly_one(&landing_selectors)?;
    builder.constrain_mux_from_one_hot(
        "landing_profile_public_code",
        &landing_selectors,
        &[
            Expr::Const(code_field(1)),
            Expr::Const(code_field(2)),
            Expr::Const(code_field(3)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("landing_profile_public_code"),
        signal_expr("landing_profile_code"),
    )?;

    for name in [
        "single_engine_out_abort_ready",
        "sensor_denial_fallback_ready",
        "monte_carlo_engine_out_included",
        "imported_crs_only_flag",
        "tcp_transport_enforced",
        "rdma_requested",
    ] {
        builder.constrain_boolean(name)?;
    }
    builder.constrain_equal(
        signal_expr("single_engine_out_abort_ready"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("sensor_denial_fallback_ready"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("monte_carlo_engine_out_included"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("imported_crs_only_flag"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("tcp_transport_enforced"),
        Expr::Const(FieldElement::ONE),
    )?;
    builder.constrain_equal(
        signal_expr("rdma_requested"),
        Expr::Const(FieldElement::ZERO),
    )?;

    for name in [
        "landing_profile_code",
        "terminal_velocity_error",
        "terminal_attitude_error",
        "terminal_position_error",
        "fuel_used",
        "fuel_budget",
        "max_dynamic_pressure_observed",
        "max_dynamic_pressure_limit",
        "max_bending_moment_observed",
        "max_bending_moment_limit",
        "max_thermal_load_observed",
        "max_thermal_load_limit",
        "terminal_velocity_limit",
        "terminal_attitude_limit",
        "terminal_position_limit",
        "selected_clearance_floor",
        "selected_motion_limit",
        "selected_position_limit",
        "min_collision_clearance",
        "minimum_collision_clearance",
        "abort_reserve_margin",
        "minimum_abort_margin",
        "replan_latency_ms",
        "max_replan_latency_ms",
        "gust_bound",
        "mass_property_variation_percent",
        "sensor_noise_bound",
        "monte_carlo_failure_count",
        "peer_reputation_floor",
        "cluster_nodes",
    ] {
        builder.constrain_range(name, bits)?;
    }
    for name in step_margins
        .iter()
        .chain(batch_samples.iter())
        .chain(partition_commitment.iter())
        .chain(scheduler_commitment.iter())
        .chain(crs_ceremony_commitment.iter())
        .chain(crs_program_binding_commitment.iter())
        .chain(team_commitments.iter())
        .chain(team_scalar_inputs.iter())
    {
        builder.constrain_range(name, bits)?;
    }

    builder.constrain_leq(
        "fuel_margin",
        signal_expr("fuel_used"),
        signal_expr("fuel_budget"),
        bits,
    )?;
    builder.constrain_leq(
        "velocity_margin",
        signal_expr("terminal_velocity_error"),
        signal_expr("terminal_velocity_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "attitude_margin",
        signal_expr("terminal_attitude_error"),
        signal_expr("terminal_attitude_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "position_margin",
        signal_expr("terminal_position_error"),
        signal_expr("selected_position_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "dynamic_pressure_margin",
        signal_expr("max_dynamic_pressure_observed"),
        signal_expr("max_dynamic_pressure_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "bending_margin",
        signal_expr("max_bending_moment_observed"),
        signal_expr("max_bending_moment_limit"),
        bits,
    )?;
    builder.constrain_leq(
        "thermal_margin",
        signal_expr("max_thermal_load_observed"),
        signal_expr("max_thermal_load_limit"),
        bits,
    )?;
    builder.constrain_geq(
        "collision_margin",
        signal_expr("min_collision_clearance"),
        signal_expr("selected_clearance_floor"),
        bits,
    )?;
    builder.constrain_geq(
        "abort_margin",
        signal_expr("abort_reserve_margin"),
        signal_expr("minimum_abort_margin"),
        bits,
    )?;
    builder.constrain_leq(
        "latency_margin",
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
        bits,
    )?;
    builder.constrain_equal(
        signal_expr("monte_carlo_failure_count"),
        Expr::Const(FieldElement::ZERO),
    )?;
    builder.constrain_equal(
        signal_expr("safety_satisfied"),
        Expr::Const(FieldElement::ONE),
    )?;

    add_surrogate_band_lookup(
        &mut builder,
        "starship_surrogate_bands",
        &sample_surrogate_rows(),
    )?;
    for kind in TEAM_KIND_ORDER {
        let slug = team_kind_slug(kind);
        constrain_surrogate_band_lookup(
            &mut builder,
            "starship_surrogate_bands",
            &format!("team_{slug}_surrogate_regime_code"),
            &format!("team_{slug}_residual_bound"),
            &format!("team_{slug}_surrogate_certificate_limit"),
            Some(&format!("team_{slug}_surrogate_lookup")),
        )?;
    }

    let mut trajectory_inputs = initial_state_inputs
        .iter()
        .chain(terminal_state_inputs.iter())
        .chain(step_margins.iter())
        .map(|name| signal_expr(name))
        .collect::<Vec<_>>();
    trajectory_inputs.extend([
        signal_expr("landing_profile_0"),
        signal_expr("landing_profile_1"),
        signal_expr("landing_profile_2"),
        signal_expr("landing_profile_public_code"),
        signal_expr("terminal_velocity_error"),
        signal_expr("terminal_velocity_limit"),
        signal_expr("terminal_attitude_error"),
        signal_expr("terminal_attitude_limit"),
        signal_expr("terminal_position_error"),
        signal_expr("terminal_position_limit"),
        signal_expr("selected_motion_limit"),
        signal_expr("selected_position_limit"),
        signal_expr("fuel_used"),
        signal_expr("fuel_budget"),
        signal_expr("max_dynamic_pressure_limit"),
        signal_expr("max_bending_moment_limit"),
        signal_expr("max_thermal_load_limit"),
        signal_expr("min_collision_clearance"),
        signal_expr("minimum_collision_clearance"),
        signal_expr("abort_reserve_margin"),
        signal_expr("minimum_abort_margin"),
    ]);
    bind_commitment_fold(
        &mut builder,
        "trajectory_commitment",
        &trajectory_inputs,
        "trajectory_commitment_fold",
    )?;

    let mut subgraph_inputs = team_commitments
        .iter()
        .map(|name| signal_expr(name))
        .collect::<Vec<_>>();
    subgraph_inputs.extend(
        team_scalar_inputs
            .iter()
            .chain(partition_commitment.iter())
            .chain(scheduler_commitment.iter())
            .chain(crs_ceremony_commitment.iter())
            .chain(crs_program_binding_commitment.iter())
            .map(|name| signal_expr(name)),
    );
    bind_commitment_fold(
        &mut builder,
        "subgraph_commitment",
        &subgraph_inputs,
        "subgraph_commitment_fold",
    )?;

    let mut batch_inputs = batch_samples
        .iter()
        .map(|name| signal_expr(name))
        .collect::<Vec<_>>();
    batch_inputs.extend([
        signal_expr("gust_bound"),
        signal_expr("mass_property_variation_percent"),
        signal_expr("sensor_noise_bound"),
        signal_expr("monte_carlo_failure_count"),
        signal_expr("replan_latency_ms"),
        signal_expr("max_replan_latency_ms"),
        signal_expr("peer_reputation_floor"),
        signal_expr("cluster_nodes"),
    ]);
    bind_commitment_fold(
        &mut builder,
        "batch_commitment",
        &batch_inputs,
        "batch_commitment_fold",
    )?;

    builder.build()
}

pub fn build_private_starship_flip_catch_program_with_profile(
    profile: LandingInterfaceProfileV1,
    steps: usize,
    samples: usize,
) -> ZkfResult<Program> {
    build_private_starship_flip_catch_program_internal(profile, steps, samples)
}

pub fn private_starship_flip_catch_sample_request(
    profile: LandingInterfaceProfileV1,
    samples: usize,
) -> PrivateStarshipFlipCatchRequestV1 {
    let team_subgraphs = TEAM_KIND_ORDER
        .iter()
        .enumerate()
        .map(|(index, kind)| TeamSubgraphDescriptorV1 {
            kind: *kind,
            interface_commitment: [
                (10 + index as i64).to_string(),
                (20 + index as i64).to_string(),
                (30 + index as i64).to_string(),
                (40 + index as i64).to_string(),
            ],
            residual_bound: format!("0.0{}", index + 1),
            surrogate_regime_code: index as u64,
            surrogate_certificate_limit: sample_surrogate_rows()[index].certificate_limit.clone(),
            locality_hint: format!("rack-{}", index + 1),
            reputation_floor: "0.9".to_string(),
            quorum_weight: "1".to_string(),
        })
        .collect();

    PrivateStarshipFlipCatchRequestV1 {
        landing_profile: profile,
        initial_state: sample_state(100),
        terminal_state: sample_state(150),
        vehicle: VehicleEnvelopeV1 {
            wet_mass: "1200".to_string(),
            dry_mass: "200".to_string(),
            propellant_at_flip: "950".to_string(),
            max_dynamic_pressure: "250".to_string(),
            max_bending_moment: "300".to_string(),
            max_thermal_load: "180".to_string(),
            fuel_budget: "900".to_string(),
        },
        tower: Some(TowerCatchGeometryV1 {
            catch_box_half_width: "2".to_string(),
            catch_box_half_height: "1".to_string(),
            arm_clearance_floor: "3".to_string(),
            closing_speed_limit: "1".to_string(),
        }),
        barge: Some(BargeTerminalProfileV1 {
            deck_heave_limit: "1".to_string(),
            deck_velocity_limit: "1".to_string(),
            lateral_clearance_floor: "4".to_string(),
        }),
        planetary: Some(PlanetaryTerminalProfileV1 {
            pad_radius: "2".to_string(),
            slope_limit: "5".to_string(),
            dust_clearance_floor: "4".to_string(),
        }),
        monte_carlo: MonteCarloBatchConfigV1 {
            admitted_samples: samples,
            gust_bound: "50".to_string(),
            mass_property_variation_percent: "5".to_string(),
            sensor_noise_bound: "2".to_string(),
            engine_out_included: true,
        },
        distributed_proving: DistributedProofConfigV1 {
            cluster_nodes: 128,
            tcp_transport_enforced: true,
            rdma_requested: false,
            peer_reputation_floor: "0.9".to_string(),
            deterministic_partition_manifest_commitment: [
                "51".to_string(),
                "52".to_string(),
                "53".to_string(),
                "54".to_string(),
            ],
            scheduler_commitment: [
                "61".to_string(),
                "62".to_string(),
                "63".to_string(),
                "64".to_string(),
            ],
        },
        team_subgraphs,
        imported_crs: ImportedCrsManifestRefV1 {
            imported_mpc: true,
            ceremony_commitment: [
                "71".to_string(),
                "72".to_string(),
                "73".to_string(),
                "74".to_string(),
            ],
            program_binding_commitment: [
                "81".to_string(),
                "82".to_string(),
                "83".to_string(),
                "84".to_string(),
            ],
        },
        invariants: CertificationInvariantSetV1 {
            terminal_velocity_limit: "1".to_string(),
            terminal_attitude_limit: "0.5".to_string(),
            terminal_position_limit: "2".to_string(),
            max_replan_latency_ms: "500".to_string(),
            minimum_collision_clearance: "3".to_string(),
            minimum_abort_margin: "5".to_string(),
            human_rating_loc_denominator: 270,
        },
        observed: CertificationObservedMetricsV1 {
            terminal_velocity_error: "0.8".to_string(),
            terminal_attitude_error: "0.4".to_string(),
            terminal_position_error: "1.5".to_string(),
            fuel_used: "850".to_string(),
            max_dynamic_pressure: "200".to_string(),
            max_bending_moment: "250".to_string(),
            max_thermal_load: "140".to_string(),
            min_collision_clearance: "6".to_string(),
            abort_reserve_margin: "8".to_string(),
            replan_latency_ms: "320".to_string(),
            monte_carlo_failure_count: 0,
        },
        single_engine_out_abort_ready: true,
        sensor_denial_fallback_ready: true,
    }
}

pub fn private_starship_flip_catch_showcase() -> ZkfResult<TemplateProgram> {
    private_starship_flip_catch_showcase_with_profile(
        LandingInterfaceProfileV1::TowerCatch,
        STARSHIP_DEFAULT_GNC_STEPS,
        STARSHIP_DEFAULT_MONTE_CARLO_SAMPLES,
    )
}

pub fn private_starship_flip_catch_showcase_with_profile(
    profile: LandingInterfaceProfileV1,
    steps: usize,
    samples: usize,
) -> ZkfResult<TemplateProgram> {
    let request = private_starship_flip_catch_sample_request(profile, samples);
    let sample_inputs = private_starship_flip_catch_inputs_from_request(&request, steps, samples)?;
    let mut violation_request = request.clone();
    violation_request.imported_crs.imported_mpc = false;
    let violation_inputs =
        private_starship_flip_catch_inputs_from_request(&violation_request, steps, samples)?;
    Ok(TemplateProgram {
        program: build_private_starship_flip_catch_program_internal(profile, steps, samples)?,
        expected_inputs: sample_inputs.keys().cloned().collect(),
        public_outputs: vec![
            "trajectory_commitment".to_string(),
            "subgraph_commitment".to_string(),
            "batch_commitment".to_string(),
            "fuel_margin".to_string(),
            "velocity_margin".to_string(),
            "attitude_margin".to_string(),
            "position_margin".to_string(),
            "dynamic_pressure_margin".to_string(),
            "bending_margin".to_string(),
            "thermal_margin".to_string(),
            "collision_margin".to_string(),
            "abort_margin".to_string(),
            "latency_margin".to_string(),
            "landing_profile_public_code".to_string(),
            "safety_satisfied".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: STARSHIP_DESCRIPTION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starship_request_inputs_fail_closed_on_missing_team_subgraph() {
        let mut request =
            private_starship_flip_catch_sample_request(LandingInterfaceProfileV1::TowerCatch, 4);
        request.team_subgraphs.pop();
        let err = private_starship_flip_catch_inputs_from_request(&request, 2, 4)
            .expect_err("missing team should fail");
        assert!(err.to_string().contains("requires exactly"));
    }

    #[test]
    fn starship_request_inputs_encode_profile_and_transport_flags() {
        let request = private_starship_flip_catch_sample_request(
            LandingInterfaceProfileV1::BargePropulsive,
            4,
        );
        let inputs =
            private_starship_flip_catch_inputs_from_request(&request, 2, 4).expect("inputs");
        assert_eq!(inputs.get("landing_profile_code"), Some(&code_field(2)));
        assert_eq!(
            inputs.get("tcp_transport_enforced"),
            Some(&FieldElement::ONE)
        );
        assert_eq!(inputs.get("rdma_requested"), Some(&FieldElement::ZERO));
    }
}
