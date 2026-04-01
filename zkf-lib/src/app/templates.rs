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

use std::collections::BTreeMap;

use zkf_core::{
    BlackBoxOp, Expr, FieldElement, FieldId, Program, WitnessInputs, ZkfError, ZkfResult,
};

pub use super::aerospace::{
    AEROSPACE_ROTATIONAL_AXES, AEROSPACE_TRANSLATIONAL_AXES, BargeTerminalProfileV1,
    CertificationInvariantSetV1, CertificationObservedMetricsV1, DistributedProofConfigV1,
    ImportedCrsManifestRefV1, LandingInterfaceProfileV1, MonteCarloBatchConfigV1,
    PlanetaryTerminalProfileV1, PrivateStarshipFlipCatchRequestV1, RigidBodyStateV1,
    STARSHIP_DEFAULT_GNC_STEPS, STARSHIP_DEFAULT_MONTE_CARLO_SAMPLES,
    STARSHIP_MONTE_CARLO_PRODUCTION_TARGET_SAMPLES, STARSHIP_TEAM_SUBGRAPH_COUNT,
    SurrogateBandRowV1, TeamSubgraphDescriptorV1, TeamSubgraphKindV1, TowerCatchGeometryV1,
    VehicleEnvelopeV1, add_surrogate_band_lookup, barge_terminal_profile_showcase,
    build_gnc_6dof_core_program_with_steps, build_gust_robustness_batch_program_with_samples,
    build_private_starship_flip_catch_program_with_profile, constrain_surrogate_band_lookup,
    gnc_6dof_core_showcase, gnc_6dof_core_showcase_with_steps, gust_robustness_batch_showcase,
    gust_robustness_batch_showcase_with_samples, planetary_terminal_profile_showcase,
    private_starship_flip_catch_inputs_from_request, private_starship_flip_catch_sample_request,
    private_starship_flip_catch_showcase, private_starship_flip_catch_showcase_with_profile,
    tower_catch_geometry_showcase,
};
use super::builder::ProgramBuilder;
pub use super::combustion::{
    COMBUSTION_DEFAULT_SAMPLES, COMBUSTION_PUBLIC_OUTPUTS, CombustionInstabilityRequestV1,
    build_combustion_instability_program_with_samples, combustion_instability_inputs_from_request,
    combustion_instability_rayleigh_showcase,
    combustion_instability_rayleigh_showcase_with_samples,
};
pub use super::descent::{
    PRIVATE_POWERED_DESCENT_DEFAULT_STEPS, PRIVATE_POWERED_DESCENT_DIMENSIONS,
    PRIVATE_POWERED_DESCENT_PRIVATE_INPUTS, PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS,
    PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS, PrivatePoweredDescentPrivateInputsV1,
    PrivatePoweredDescentPublicInputsV1, PrivatePoweredDescentRequestV1,
    build_private_powered_descent_program, private_powered_descent_sample_inputs,
    private_powered_descent_showcase, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness, private_powered_descent_witness_with_steps,
};
use super::inputs::bytes_to_field_elements;
pub use super::multi_satellite::{
    PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT, PRIVATE_MULTI_SATELLITE_BASE_PUBLIC_OUTPUTS,
    PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT, PRIVATE_MULTI_SATELLITE_BASE_STEPS,
    PRIVATE_MULTI_SATELLITE_DIMENSIONS, PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE,
    PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS, PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT,
    PRIVATE_MULTI_SATELLITE_STRESS_PUBLIC_OUTPUTS, PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT,
    PRIVATE_MULTI_SATELLITE_STRESS_STEPS, PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS, PairCheck,
    PrivateMultiSatelliteScenario, PrivateMultiSatelliteScenarioSpec,
    private_multi_satellite_conjunction_sample_inputs,
    private_multi_satellite_conjunction_showcase_base32,
    private_multi_satellite_conjunction_showcase_for_scenario,
    private_multi_satellite_conjunction_showcase_stress64,
    private_multi_satellite_conjunction_witness, private_multi_satellite_pair_schedule,
    private_multi_satellite_scenario_spec,
};
pub use super::navier_stokes::{
    NAVIER_STOKES_DEFAULT_CELLS, NAVIER_STOKES_PUBLIC_OUTPUTS, NavierStokesCellStateV1,
    NavierStokesInterfaceCertificateV1, NavierStokesStructuredStepRequestV1,
    build_navier_stokes_structured_step_program, navier_stokes_structured_step_inputs_from_request,
    navier_stokes_structured_step_showcase, navier_stokes_structured_step_showcase_with_cells,
};
pub use super::orbital::{
    PRIVATE_NBODY_BODY_COUNT, PRIVATE_NBODY_DEFAULT_STEPS, PRIVATE_NBODY_DIMENSIONS,
    PRIVATE_NBODY_PRIVATE_INPUTS, PRIVATE_NBODY_PUBLIC_OUTPUTS,
    private_nbody_orbital_sample_inputs, private_nbody_orbital_showcase,
    private_nbody_orbital_showcase_with_steps, private_nbody_orbital_witness,
    private_nbody_orbital_witness_with_steps,
};
use super::private_identity as private_identity_app;
pub use super::real_gas::{
    REAL_GAS_COMPONENTS, REAL_GAS_PUBLIC_OUTPUTS, RealGasModelFamilyV1, RealGasStateRequestV1,
    build_real_gas_state_program, real_gas_state_inputs_from_request, real_gas_state_showcase,
    real_gas_state_showcase_for_model,
};
pub use super::reentry::{
    PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS, PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS,
    PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS, PrivateReentryThermalRequestV1,
    REENTRY_ASSURANCE_ML_DSA_CONTEXT, ReentryAbortCorridorBandRowV1, ReentryAbortThresholdsV1,
    ReentryAssuranceReceiptV1, ReentryAssuranceReceiptV2, ReentryAtmosphereBandRowV1,
    ReentryAuthorizedSignerV1, ReentryMissionPackV1, ReentryMissionPackV2, ReentryPrivateInputsV1,
    ReentryPrivateInputsV2, ReentryPrivateModelCommitmentsV1, ReentryPublicEnvelopeV1,
    ReentryPublicInputsV1, ReentrySignerManifestV1, ReentrySineBandRowV1,
    SignedReentryMissionPackV1, build_private_reentry_thermal_program,
    build_reentry_assurance_receipt_v2, materialize_private_reentry_request_v1_from_v2,
    private_reentry_thermal_sample_inputs, private_reentry_thermal_sample_request_with_steps,
    private_reentry_thermal_showcase, private_reentry_thermal_showcase_with_steps,
    private_reentry_thermal_witness, private_reentry_thermal_witness_with_steps,
    reentry_mission_pack_v2_digest, reentry_mission_pack_v2_sample_with_steps,
    reentry_signer_manifest_digest, validate_signed_reentry_mission_pack,
};
pub use super::satellite::{
    PRIVATE_SATELLITE_DEFAULT_STEPS, PRIVATE_SATELLITE_DIMENSIONS,
    PRIVATE_SATELLITE_PRIVATE_INPUTS, PRIVATE_SATELLITE_PUBLIC_INPUTS,
    PRIVATE_SATELLITE_PUBLIC_OUTPUTS, PRIVATE_SATELLITE_SPACECRAFT_COUNT,
    private_satellite_conjunction_sample_inputs, private_satellite_conjunction_showcase,
    private_satellite_conjunction_witness,
};
pub use super::thermochemical::{
    THERMOCHEMICAL_ELEMENTS, THERMOCHEMICAL_PUBLIC_OUTPUTS, THERMOCHEMICAL_SPECIES,
    ThermochemicalEquilibriumRequestV1, build_thermochemical_equilibrium_program,
    thermochemical_equilibrium_inputs_from_request, thermochemical_equilibrium_showcase,
};

#[derive(Debug, Clone)]
pub struct TemplateProgram {
    pub program: Program,
    pub expected_inputs: Vec<String>,
    pub public_outputs: Vec<String>,
    pub sample_inputs: WitnessInputs,
    pub violation_inputs: WitnessInputs,
    pub description: &'static str,
}

fn poseidon_round(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: &[Expr],
) -> ZkfResult<String> {
    let output_names = [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ];
    for output in &output_names {
        builder.private_signal(output)?;
    }
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    builder.constrain_blackbox(
        BlackBoxOp::Poseidon,
        inputs,
        &[
            output_names[0].as_str(),
            output_names[1].as_str(),
            output_names[2].as_str(),
            output_names[3].as_str(),
        ],
        &params,
    )?;
    Ok(output_names[0].clone())
}

pub fn poseidon_commitment() -> ZkfResult<TemplateProgram> {
    let mut builder = ProgramBuilder::new("poseidon_commitment", FieldId::Bn254);
    builder.private_input("secret")?;
    builder.private_input("blinding")?;
    builder.constrain_range("secret", 32)?;
    builder.constant_signal("__poseidon_zero_0", FieldElement::ZERO)?;
    builder.constant_signal("__poseidon_zero_1", FieldElement::ZERO)?;
    builder.public_output("commitment")?;

    let commitment_state = poseidon_round(
        &mut builder,
        "__poseidon_commitment",
        &[
            Expr::signal("secret"),
            Expr::signal("blinding"),
            Expr::signal("__poseidon_zero_0"),
            Expr::signal("__poseidon_zero_1"),
        ],
    )?;
    builder.constrain_equal(Expr::signal("commitment"), Expr::signal(commitment_state))?;

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs: vec!["secret".to_string(), "blinding".to_string()],
        public_outputs: vec!["commitment".to_string()],
        sample_inputs: WitnessInputs::from([
            ("secret".to_string(), FieldElement::from_i64(7)),
            ("blinding".to_string(), FieldElement::from_i64(11)),
        ]),
        violation_inputs: WitnessInputs::from([
            ("secret".to_string(), FieldElement::from_u64(1u64 << 40)),
            ("blinding".to_string(), FieldElement::from_i64(11)),
        ]),
        description: "Compute a BN254 Poseidon commitment from secret and blinding inputs.",
    })
}

pub fn merkle_membership() -> ZkfResult<TemplateProgram> {
    merkle_membership_with_depth(2)
}

pub fn merkle_membership_with_depth(depth: usize) -> ZkfResult<TemplateProgram> {
    let mut builder =
        ProgramBuilder::new(format!("merkle_membership_depth_{depth}"), FieldId::Bn254);
    builder.private_input("leaf")?;
    builder.public_output("root")?;
    builder.constant_signal("__merkle_zero_left", FieldElement::ZERO)?;
    builder.constant_signal("__merkle_zero_right", FieldElement::ZERO)?;

    let mut sample_inputs = WitnessInputs::from([("leaf".to_string(), FieldElement::from_i64(5))]);
    let mut current = Expr::signal("leaf");
    for level in 0..depth {
        let sibling = format!("sibling_{level}");
        let direction = format!("direction_{level}");
        let left = format!("left_{level}");
        let right = format!("right_{level}");
        builder.private_input(&sibling)?;
        builder.private_input(&direction)?;
        builder.private_signal(&left)?;
        builder.private_signal(&right)?;
        builder.constrain_boolean(&direction)?;
        builder.constrain_equal(
            Expr::signal(&left),
            Expr::Add(vec![
                current.clone(),
                Expr::Mul(
                    Box::new(Expr::signal(&direction)),
                    Box::new(Expr::Sub(
                        Box::new(Expr::signal(&sibling)),
                        Box::new(current.clone()),
                    )),
                ),
            ]),
        )?;
        builder.constrain_equal(
            Expr::signal(&right),
            Expr::Add(vec![
                Expr::signal(&sibling),
                Expr::Mul(
                    Box::new(Expr::signal(&direction)),
                    Box::new(Expr::Sub(
                        Box::new(current.clone()),
                        Box::new(Expr::signal(&sibling)),
                    )),
                ),
            ]),
        )?;
        current = Expr::signal(poseidon_round(
            &mut builder,
            &format!("__merkle_round_{level}"),
            &[
                Expr::signal(&left),
                Expr::signal(&right),
                Expr::signal("__merkle_zero_left"),
                Expr::signal("__merkle_zero_right"),
            ],
        )?);

        sample_inputs.insert(sibling.clone(), FieldElement::from_i64((level + 2) as i64));
        sample_inputs.insert(
            direction.clone(),
            FieldElement::from_i64((level % 2) as i64),
        );
    }
    builder.constrain_equal(Expr::signal("root"), current)?;

    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert("direction_0".to_string(), FieldElement::from_i64(2));

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs: std::iter::once("leaf".to_string())
            .chain(
                (0..depth)
                    .flat_map(|level| [format!("sibling_{level}"), format!("direction_{level}")]),
            )
            .collect(),
        public_outputs: vec!["root".to_string()],
        sample_inputs,
        violation_inputs,
        description: "Compute a Poseidon-based binary Merkle root from a private leaf and authentication path.",
    })
}

pub fn range_proof() -> ZkfResult<TemplateProgram> {
    range_proof_with_bits(32)
}

pub fn range_proof_with_bits(bits: u32) -> ZkfResult<TemplateProgram> {
    let mut builder = ProgramBuilder::new(format!("range_proof_{bits}_bits"), FieldId::Goldilocks);
    builder.private_input("value")?;
    builder.private_input("blinding")?;
    builder.public_output("commitment")?;
    builder.constrain_range("value", bits)?;
    let commitment_expr = Expr::Mul(
        Box::new(Expr::signal("value")),
        Box::new(Expr::Add(vec![
            Expr::signal("value"),
            Expr::signal("blinding"),
            Expr::Const(FieldElement::ONE),
        ])),
    );
    builder.add_assignment("commitment", commitment_expr.clone())?;
    builder.constrain_equal(Expr::signal("commitment"), commitment_expr)?;

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs: vec!["value".to_string(), "blinding".to_string()],
        public_outputs: vec!["commitment".to_string()],
        sample_inputs: WitnessInputs::from([
            ("value".to_string(), FieldElement::from_i64(1337)),
            ("blinding".to_string(), FieldElement::from_i64(21)),
        ]),
        violation_inputs: WitnessInputs::from([
            (
                "value".to_string(),
                FieldElement::from_u64((1u64 << bits.min(63)) + 1),
            ),
            ("blinding".to_string(), FieldElement::from_i64(21)),
        ]),
        description: "Prove that a private value fits within the configured bit range and anchor it with a blinded multiplication gate on the transparent Goldilocks/Plonky3 starter path.",
    })
}

pub fn private_vote_commitment_three_candidate() -> ZkfResult<TemplateProgram> {
    let mut builder =
        ProgramBuilder::new("private_vote_commitment_three_candidate", FieldId::Bn254);
    builder.metadata_entry("election_id", "20260324")?;
    builder.metadata_entry("candidate_domain", "1,2,3")?;
    builder.metadata_entry(
        "commitment_scheme",
        "poseidon(candidate,blinding,election_id,domain)",
    )?;

    builder.private_input("candidate")?;
    builder.private_input("blinding")?;
    builder.public_output("vote_commitment")?;

    builder.constant_signal("__vote_candidate_one", FieldElement::ONE)?;
    builder.constant_signal("__vote_candidate_two", FieldElement::from_i64(2))?;
    builder.constant_signal("__vote_candidate_three", FieldElement::from_i64(3))?;
    builder.constant_signal("__vote_election_id", FieldElement::from_u64(20260324))?;
    builder.constant_signal("__vote_domain_sep", FieldElement::from_u64(7_771))?;

    builder.constrain_range("candidate", 2)?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::Sub(
                Box::new(Expr::signal("candidate")),
                Box::new(Expr::signal("__vote_candidate_one")),
            )),
            Box::new(Expr::Mul(
                Box::new(Expr::Sub(
                    Box::new(Expr::signal("candidate")),
                    Box::new(Expr::signal("__vote_candidate_two")),
                )),
                Box::new(Expr::Sub(
                    Box::new(Expr::signal("candidate")),
                    Box::new(Expr::signal("__vote_candidate_three")),
                )),
            )),
        ),
        Expr::Const(FieldElement::ZERO),
    )?;
    let commitment_state = poseidon_round(
        &mut builder,
        "__vote_commitment",
        &[
            Expr::signal("candidate"),
            Expr::signal("blinding"),
            Expr::signal("__vote_election_id"),
            Expr::signal("__vote_domain_sep"),
        ],
    )?;
    builder.constrain_equal(
        Expr::signal("vote_commitment"),
        Expr::signal(commitment_state),
    )?;

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs: vec!["candidate".to_string(), "blinding".to_string()],
        public_outputs: vec!["vote_commitment".to_string()],
        sample_inputs: WitnessInputs::from([
            ("candidate".to_string(), FieldElement::from_i64(2)),
            ("blinding".to_string(), FieldElement::from_u64(424_242)),
        ]),
        violation_inputs: WitnessInputs::from([
            ("candidate".to_string(), FieldElement::from_i64(4)),
            ("blinding".to_string(), FieldElement::from_u64(424_242)),
        ]),
        description: "Commit to a private vote for candidate 1, 2, or 3 and prove membership in the allowed candidate set without revealing the chosen candidate.",
    })
}

pub fn sha256_preimage() -> ZkfResult<TemplateProgram> {
    sha256_preimage_with_len(4)
}

pub fn sha256_preimage_with_len(byte_len: usize) -> ZkfResult<TemplateProgram> {
    let mut builder = ProgramBuilder::new(
        format!("sha256_preimage_{byte_len}_bytes"),
        FieldId::Goldilocks,
    );

    let input_names = (0..byte_len)
        .map(|index| format!("byte_{index}"))
        .collect::<Vec<_>>();
    for input in &input_names {
        builder.private_input(input)?;
        builder.constrain_range(input, 8)?;
    }

    let digest_names = (0..32)
        .map(|index| format!("digest_{index}"))
        .collect::<Vec<_>>();
    for digest in &digest_names {
        builder.public_output(digest)?;
    }

    let blackbox_inputs = input_names.iter().map(Expr::signal).collect::<Vec<_>>();
    let digest_refs = digest_names.iter().map(String::as_str).collect::<Vec<_>>();
    builder.constrain_blackbox(
        BlackBoxOp::Sha256,
        &blackbox_inputs,
        &digest_refs,
        &BTreeMap::new(),
    )?;

    let sample_bytes = b"ziros app demo!!";
    let mut sample_inputs = WitnessInputs::new();
    for (index, element) in
        bytes_to_field_elements(&sample_bytes[..byte_len.min(sample_bytes.len())])
            .into_iter()
            .enumerate()
    {
        sample_inputs.insert(format!("byte_{index}"), element);
    }
    for index in sample_inputs.len()..byte_len {
        sample_inputs.insert(format!("byte_{index}"), FieldElement::ZERO);
    }

    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert("byte_0".to_string(), FieldElement::from_i64(300));

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs: input_names,
        public_outputs: digest_names,
        sample_inputs,
        violation_inputs,
        description: "Compute a SHA-256 digest from private byte inputs and expose the digest publicly.",
    })
}

pub fn private_identity_kyc() -> ZkfResult<TemplateProgram> {
    private_identity_app::private_identity_kyc()
}

pub fn gnc_6dof_core_template() -> ZkfResult<TemplateProgram> {
    gnc_6dof_core_showcase()
}

pub fn gnc_6dof_core_template_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    gnc_6dof_core_showcase_with_steps(steps)
}

pub fn tower_catch_geometry_template() -> ZkfResult<TemplateProgram> {
    tower_catch_geometry_showcase()
}

pub fn barge_terminal_profile_template() -> ZkfResult<TemplateProgram> {
    barge_terminal_profile_showcase()
}

pub fn planetary_terminal_profile_template() -> ZkfResult<TemplateProgram> {
    planetary_terminal_profile_showcase()
}

pub fn gust_robustness_batch_template() -> ZkfResult<TemplateProgram> {
    gust_robustness_batch_showcase()
}

pub fn gust_robustness_batch_template_with_samples(samples: usize) -> ZkfResult<TemplateProgram> {
    gust_robustness_batch_showcase_with_samples(samples)
}

pub fn private_starship_flip_catch_template() -> ZkfResult<TemplateProgram> {
    private_starship_flip_catch_showcase()
}

pub fn private_starship_flip_catch_template_with_profile(
    profile: LandingInterfaceProfileV1,
    steps: usize,
    samples: usize,
) -> ZkfResult<TemplateProgram> {
    private_starship_flip_catch_showcase_with_profile(profile, steps, samples)
}

pub fn private_powered_descent_showcase_template() -> ZkfResult<TemplateProgram> {
    private_powered_descent_showcase()
}

pub fn private_powered_descent_showcase_template_with_steps(
    steps: usize,
) -> ZkfResult<TemplateProgram> {
    private_powered_descent_showcase_with_steps(steps)
}

pub fn private_powered_descent_showcase_sample_inputs() -> WitnessInputs {
    private_powered_descent_sample_inputs()
}

pub fn private_powered_descent_showcase_witness(
    inputs: &WitnessInputs,
) -> Result<zkf_core::Witness, ZkfError> {
    private_powered_descent_witness(inputs)
}

pub fn private_powered_descent_showcase_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> Result<zkf_core::Witness, ZkfError> {
    private_powered_descent_witness_with_steps(inputs, steps)
}

pub fn private_satellite_conjunction_showcase_template() -> ZkfResult<TemplateProgram> {
    private_satellite_conjunction_showcase()
}

pub fn private_satellite_conjunction_showcase_sample_inputs() -> WitnessInputs {
    private_satellite_conjunction_sample_inputs()
}

pub fn private_satellite_conjunction_showcase_witness(
    inputs: &WitnessInputs,
) -> Result<zkf_core::Witness, ZkfError> {
    private_satellite_conjunction_witness(inputs)
}

pub fn private_multi_satellite_conjunction_showcase_base32_template() -> ZkfResult<TemplateProgram>
{
    private_multi_satellite_conjunction_showcase_base32()
}

pub fn private_multi_satellite_conjunction_showcase_stress64_template() -> ZkfResult<TemplateProgram>
{
    private_multi_satellite_conjunction_showcase_stress64()
}

pub fn private_multi_satellite_conjunction_showcase_sample_inputs(
    scenario: PrivateMultiSatelliteScenario,
) -> WitnessInputs {
    private_multi_satellite_conjunction_sample_inputs(scenario)
}

pub fn private_multi_satellite_conjunction_showcase_witness(
    inputs: &WitnessInputs,
    scenario: PrivateMultiSatelliteScenario,
) -> Result<zkf_core::Witness, ZkfError> {
    private_multi_satellite_conjunction_witness(inputs, scenario)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::api::{compile_and_prove_default, verify};

    fn assert_template_roundtrip(name: &str, template: TemplateProgram) {
        let handle = std::thread::Builder::new()
            .name(format!("template-{name}"))
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let embedded =
                    zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                        compile_and_prove_default(
                            &template.program,
                            &template.sample_inputs,
                            None,
                            None,
                        )
                    })
                    .expect("template compile/prove");
                assert!(verify(&embedded.compiled, &embedded.artifact).expect("verify"));
            })
            .expect("spawn template test thread");
        handle.join().expect("template roundtrip should succeed");
    }

    #[test]
    fn poseidon_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "poseidon",
            poseidon_commitment().expect("poseidon template"),
        );
    }

    #[test]
    fn merkle_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "merkle",
            merkle_membership_with_depth(1).expect("merkle template"),
        );
    }

    #[test]
    fn range_template_compiles_proves_and_verifies() {
        assert_template_roundtrip("range", range_proof().expect("range template"));
    }

    #[test]
    fn private_vote_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "private-vote",
            private_vote_commitment_three_candidate().expect("private vote template"),
        );
    }

    #[test]
    fn sha256_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "sha256",
            sha256_preimage_with_len(2).expect("sha256 template"),
        );
    }

    #[test]
    fn private_identity_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "private-identity",
            private_identity_kyc().expect("private identity template"),
        );
    }

    #[test]
    fn thermochemical_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "thermochemical",
            thermochemical_equilibrium_showcase().expect("thermochemical template"),
        );
    }

    #[test]
    fn aerospace_gnc_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "gnc-6dof-core",
            gnc_6dof_core_showcase_with_steps(2).expect("gnc template"),
        );
    }

    #[test]
    fn aerospace_flagship_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "private-starship-flip-catch",
            private_starship_flip_catch_showcase_with_profile(
                LandingInterfaceProfileV1::TowerCatch,
                2,
                4,
            )
            .expect("starship template"),
        );
    }

    #[test]
    fn real_gas_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "real-gas",
            real_gas_state_showcase().expect("real gas template"),
        );
    }

    #[test]
    fn navier_stokes_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "navier-stokes",
            navier_stokes_structured_step_showcase().expect("navier-stokes template"),
        );
    }

    #[test]
    fn combustion_template_compiles_proves_and_verifies() {
        assert_template_roundtrip(
            "combustion",
            combustion_instability_rayleigh_showcase().expect("combustion template"),
        );
    }
}
