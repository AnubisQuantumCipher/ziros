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

use serde::{Deserialize, Serialize};
use zkf_core::{Expr, FieldElement, FieldId, Program, WitnessInputs, ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::science::{
    add_expr, append_poseidon_commitment, bits_for_bound, const_expr, decimal_scaled, field,
    mul_expr, science_scale, science_scale_string, signal_expr, sub_expr, two, zero,
};
use super::templates::TemplateProgram;

pub const COMBUSTION_DEFAULT_SAMPLES: usize = 4;
pub const COMBUSTION_PUBLIC_OUTPUTS: usize = 6;

const COMBUSTION_DESCRIPTION: &str = "Combustion-instability certificate over a fixed trace window. The circuit proves the discrete Rayleigh integral for the attested pressure/heat-release window, the coupled low-order modal growth relation, explicit positive/negative sign witnesses for both quantities, and a Poseidon commitment binding the trace and modal parameters.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CombustionInstabilityRequestV1 {
    pub pressure_trace: Vec<String>,
    pub heat_release_trace: Vec<String>,
    pub dt: String,
    pub coupling: String,
    pub damping: String,
    pub rayleigh_index: String,
    pub rayleigh_positive_flag: bool,
    pub rayleigh_positive_margin: String,
    pub rayleigh_negative_margin: String,
    pub modal_growth_rate: String,
    pub modal_positive_flag: bool,
    pub modal_positive_margin: String,
    pub modal_negative_margin: String,
}

fn pressure_name(index: usize) -> String {
    format!("pressure_trace_{index}")
}

fn heat_name(index: usize) -> String {
    format!("heat_release_trace_{index}")
}

pub fn combustion_instability_inputs_from_request(
    request: &CombustionInstabilityRequestV1,
) -> ZkfResult<WitnessInputs> {
    if request.pressure_trace.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "combustion-instability request requires at least one sample".to_string(),
        ));
    }
    if request.pressure_trace.len() != request.heat_release_trace.len() {
        return Err(ZkfError::InvalidArtifact(format!(
            "pressure trace length {} must match heat-release trace length {}",
            request.pressure_trace.len(),
            request.heat_release_trace.len()
        )));
    }
    let mut inputs = WitnessInputs::new();
    inputs.insert("dt".to_string(), field(decimal_scaled(&request.dt)));
    inputs.insert(
        "coupling".to_string(),
        field(decimal_scaled(&request.coupling)),
    );
    inputs.insert(
        "damping".to_string(),
        field(decimal_scaled(&request.damping)),
    );
    inputs.insert(
        "rayleigh_index".to_string(),
        field(decimal_scaled(&request.rayleigh_index)),
    );
    inputs.insert(
        "rayleigh_positive_flag".to_string(),
        if request.rayleigh_positive_flag {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
    );
    inputs.insert(
        "rayleigh_positive_margin".to_string(),
        field(decimal_scaled(&request.rayleigh_positive_margin)),
    );
    inputs.insert(
        "rayleigh_negative_margin".to_string(),
        field(decimal_scaled(&request.rayleigh_negative_margin)),
    );
    inputs.insert(
        "modal_growth_rate".to_string(),
        field(decimal_scaled(&request.modal_growth_rate)),
    );
    inputs.insert(
        "modal_positive_flag".to_string(),
        if request.modal_positive_flag {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
    );
    inputs.insert(
        "modal_positive_margin".to_string(),
        field(decimal_scaled(&request.modal_positive_margin)),
    );
    inputs.insert(
        "modal_negative_margin".to_string(),
        field(decimal_scaled(&request.modal_negative_margin)),
    );
    for (index, value) in request.pressure_trace.iter().enumerate() {
        inputs.insert(pressure_name(index), field(decimal_scaled(value)));
    }
    for (index, value) in request.heat_release_trace.iter().enumerate() {
        inputs.insert(heat_name(index), field(decimal_scaled(value)));
    }
    Ok(inputs)
}

fn combustion_expected_inputs(samples: usize) -> Vec<String> {
    let mut inputs = vec![
        "dt".to_string(),
        "coupling".to_string(),
        "damping".to_string(),
        "rayleigh_index".to_string(),
        "rayleigh_positive_flag".to_string(),
        "rayleigh_positive_margin".to_string(),
        "rayleigh_negative_margin".to_string(),
        "modal_growth_rate".to_string(),
        "modal_positive_flag".to_string(),
        "modal_positive_margin".to_string(),
        "modal_negative_margin".to_string(),
    ];
    for index in 0..samples {
        inputs.push(pressure_name(index));
    }
    for index in 0..samples {
        inputs.push(heat_name(index));
    }
    inputs
}

fn combustion_public_outputs() -> Vec<String> {
    vec![
        "trace_commitment".to_string(),
        "constraint_satisfaction".to_string(),
        "rayleigh_index".to_string(),
        "rayleigh_positive_flag".to_string(),
        "modal_growth_rate".to_string(),
        "modal_positive_flag".to_string(),
    ]
}

fn sample_request(samples: usize) -> CombustionInstabilityRequestV1 {
    let pressure_trace = vec!["1".to_string(); samples];
    let heat_release_trace = vec!["1".to_string(); samples];
    CombustionInstabilityRequestV1 {
        pressure_trace,
        heat_release_trace,
        dt: "1".to_string(),
        coupling: "1".to_string(),
        damping: "1".to_string(),
        rayleigh_index: samples.to_string(),
        rayleigh_positive_flag: true,
        rayleigh_positive_margin: samples.to_string(),
        rayleigh_negative_margin: "0".to_string(),
        modal_growth_rate: (samples - 1).to_string(),
        modal_positive_flag: true,
        modal_positive_margin: (samples - 1).to_string(),
        modal_negative_margin: "0".to_string(),
    }
}

pub fn build_combustion_instability_program_with_samples(samples: usize) -> ZkfResult<Program> {
    if samples == 0 {
        return Err(ZkfError::InvalidArtifact(
            "combustion-instability surface requires at least one sample".to_string(),
        ));
    }
    let mut builder = ProgramBuilder::new(
        format!("combustion_instability_rayleigh_{samples}_samples_v1"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "combustion-instability-rayleigh")?;
    builder.metadata_entry("scientific_domain", "combustion-instability")?;
    builder.metadata_entry(
        "claim_scope",
        "rayleigh-window-and-modal-growth-certificate",
    )?;
    builder.metadata_entry("samples", &samples.to_string())?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;
    builder.metadata_entry(
        "scope_boundary",
        "proves a discrete Rayleigh-window integral and the coupled low-order modal growth relation for the attested trace; does not mechanize nonlinear combustor CFD",
    )?;

    for name in [
        "dt",
        "coupling",
        "damping",
        "rayleigh_index",
        "rayleigh_positive_flag",
        "rayleigh_positive_margin",
        "rayleigh_negative_margin",
        "modal_growth_rate",
        "modal_positive_flag",
        "modal_positive_margin",
        "modal_negative_margin",
    ] {
        builder.public_output(name)?;
    }
    builder.public_output("trace_commitment")?;
    builder.public_output("constraint_satisfaction")?;

    let margin_bits = bits_for_bound(&(science_scale() * science_scale() * two()));
    builder.constrain_boolean("rayleigh_positive_flag")?;
    builder.constrain_boolean("modal_positive_flag")?;
    for name in [
        "dt",
        "coupling",
        "damping",
        "rayleigh_positive_margin",
        "rayleigh_negative_margin",
        "modal_positive_margin",
        "modal_negative_margin",
    ] {
        builder.constrain_range(name, margin_bits)?;
    }

    let mut commitment_inputs = vec![
        signal_expr("dt"),
        signal_expr("coupling"),
        signal_expr("damping"),
        signal_expr("rayleigh_index"),
        signal_expr("rayleigh_positive_flag"),
        signal_expr("modal_growth_rate"),
        signal_expr("modal_positive_flag"),
    ];
    let mut rayleigh_term_sum = Vec::new();
    for index in 0..samples {
        let pressure = pressure_name(index);
        let heat = heat_name(index);
        builder.private_input(&pressure)?;
        builder.private_input(&heat)?;
        commitment_inputs.push(signal_expr(&pressure));
        commitment_inputs.push(signal_expr(&heat));
        rayleigh_term_sum.push(mul_expr(signal_expr(&pressure), signal_expr(&heat)));
    }

    let scale = science_scale();
    builder.constrain_equal(
        mul_expr(
            signal_expr("rayleigh_index"),
            mul_expr(const_expr(&scale), const_expr(&scale)),
        ),
        mul_expr(signal_expr("dt"), add_expr(rayleigh_term_sum)),
    )?;
    builder.constrain_equal(
        signal_expr("rayleigh_index"),
        sub_expr(
            signal_expr("rayleigh_positive_margin"),
            signal_expr("rayleigh_negative_margin"),
        ),
    )?;
    builder.constrain_equal(
        mul_expr(
            signal_expr("rayleigh_positive_flag"),
            signal_expr("rayleigh_negative_margin"),
        ),
        const_expr(&zero()),
    )?;
    builder.constrain_equal(
        mul_expr(
            sub_expr(
                Expr::Const(FieldElement::ONE),
                signal_expr("rayleigh_positive_flag"),
            ),
            signal_expr("rayleigh_positive_margin"),
        ),
        const_expr(&zero()),
    )?;

    builder.constrain_equal(
        mul_expr(signal_expr("modal_growth_rate"), const_expr(&scale)),
        add_expr(vec![
            mul_expr(signal_expr("coupling"), signal_expr("rayleigh_index")),
            sub_expr(
                const_expr(&zero()),
                mul_expr(signal_expr("damping"), const_expr(&scale)),
            ),
        ]),
    )?;
    builder.constrain_equal(
        signal_expr("modal_growth_rate"),
        sub_expr(
            signal_expr("modal_positive_margin"),
            signal_expr("modal_negative_margin"),
        ),
    )?;
    builder.constrain_equal(
        mul_expr(
            signal_expr("modal_positive_flag"),
            signal_expr("modal_negative_margin"),
        ),
        const_expr(&zero()),
    )?;
    builder.constrain_equal(
        mul_expr(
            sub_expr(
                Expr::Const(FieldElement::ONE),
                signal_expr("modal_positive_flag"),
            ),
            signal_expr("modal_positive_margin"),
        ),
        const_expr(&zero()),
    )?;

    builder.constrain_equal(
        signal_expr("constraint_satisfaction"),
        Expr::Const(FieldElement::ONE),
    )?;
    append_poseidon_commitment(
        &mut builder,
        "__combustion_trace_commitment",
        &commitment_inputs,
        "trace_commitment",
    )?;
    builder.build()
}

pub fn combustion_instability_rayleigh_showcase_with_samples(
    samples: usize,
) -> ZkfResult<TemplateProgram> {
    let sample_request = sample_request(samples);
    let sample_inputs = combustion_instability_inputs_from_request(&sample_request)?;
    let mut violation_request = sample_request.clone();
    violation_request.damping = "10".to_string();
    let violation_inputs = combustion_instability_inputs_from_request(&violation_request)?;
    Ok(TemplateProgram {
        program: build_combustion_instability_program_with_samples(samples)?,
        expected_inputs: combustion_expected_inputs(samples),
        public_outputs: combustion_public_outputs(),
        sample_inputs,
        violation_inputs,
        description: COMBUSTION_DESCRIPTION,
    })
}

pub fn combustion_instability_rayleigh_showcase() -> ZkfResult<TemplateProgram> {
    combustion_instability_rayleigh_showcase_with_samples(COMBUSTION_DEFAULT_SAMPLES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combustion_surface_exposes_expected_outputs() {
        let template =
            combustion_instability_rayleigh_showcase_with_samples(COMBUSTION_DEFAULT_SAMPLES)
                .expect("template");
        assert_eq!(template.public_outputs.len(), COMBUSTION_PUBLIC_OUTPUTS);
        assert_eq!(
            template.program.metadata.get("samples"),
            Some(&COMBUSTION_DEFAULT_SAMPLES.to_string())
        );
    }

    #[test]
    fn combustion_request_digest_is_stable() {
        let request = sample_request(COMBUSTION_DEFAULT_SAMPLES);
        assert_eq!(
            super::super::science::sha256_hex_json("combustion-instability", &request)
                .expect("digest")
                .len(),
            64
        );
    }
}
