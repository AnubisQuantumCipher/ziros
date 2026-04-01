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
use zkf_core::{Expr, FieldId, Program, WitnessInputs, ZkfResult};

use super::builder::ProgramBuilder;
use super::science::{
    add_expr, append_poseidon_commitment, bits_for_bound, const_expr, decimal_scaled, field,
    mul_expr, science_scale, science_scale_string, signal_expr, sub_expr, two, zero,
};
use super::templates::TemplateProgram;

pub const THERMOCHEMICAL_SPECIES: usize = 3;
pub const THERMOCHEMICAL_ELEMENTS: usize = 2;
pub const THERMOCHEMICAL_PUBLIC_OUTPUTS: usize = 5;

const THERMOCHEMICAL_DESCRIPTION: &str = "Gas-phase thermochemical-equilibrium certificate over a fixed 3-species/2-element surface. The circuit proves element balance, nonnegative species amounts, KKT-style complementarity on the supplied chemical-potential witness, and a Poseidon commitment binding the attested thermodynamic state, species set, and coefficient table.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThermochemicalEquilibriumRequestV1 {
    pub temperature: String,
    pub pressure: String,
    pub element_totals: [String; THERMOCHEMICAL_ELEMENTS],
    pub species_amounts: [String; THERMOCHEMICAL_SPECIES],
    pub chemical_potentials: [String; THERMOCHEMICAL_SPECIES],
    pub element_multipliers: [String; THERMOCHEMICAL_ELEMENTS],
    pub stoichiometry: [[String; THERMOCHEMICAL_ELEMENTS]; THERMOCHEMICAL_SPECIES],
}

fn amount_name(species: usize) -> String {
    format!("species_amount_{species}")
}

fn potential_name(species: usize) -> String {
    format!("chemical_potential_{species}")
}

fn multiplier_name(element: usize) -> String {
    format!("element_multiplier_{element}")
}

fn total_name(element: usize) -> String {
    format!("element_total_{element}")
}

fn stoich_name(species: usize, element: usize) -> String {
    format!("stoich_{species}_{element}")
}

fn stationarity_name(species: usize) -> String {
    format!("stationarity_residual_{species}")
}

fn balance_name(element: usize) -> String {
    format!("element_balance_residual_{element}")
}

fn stoich_bigint(value: &str) -> BigInt {
    BigInt::parse_bytes(value.as_bytes(), 10).unwrap_or_else(|| {
        panic!("thermochemical stoichiometric coefficients must be base-10 integers, got '{value}'")
    })
}

pub fn thermochemical_equilibrium_inputs_from_request(
    request: &ThermochemicalEquilibriumRequestV1,
) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    inputs.insert(
        "temperature".to_string(),
        field(decimal_scaled(&request.temperature)),
    );
    inputs.insert(
        "pressure".to_string(),
        field(decimal_scaled(&request.pressure)),
    );
    for element in 0..THERMOCHEMICAL_ELEMENTS {
        inputs.insert(
            total_name(element),
            field(decimal_scaled(&request.element_totals[element])),
        );
        inputs.insert(
            multiplier_name(element),
            field(decimal_scaled(&request.element_multipliers[element])),
        );
    }
    for species in 0..THERMOCHEMICAL_SPECIES {
        inputs.insert(
            amount_name(species),
            field(decimal_scaled(&request.species_amounts[species])),
        );
        inputs.insert(
            potential_name(species),
            field(decimal_scaled(&request.chemical_potentials[species])),
        );
        for element in 0..THERMOCHEMICAL_ELEMENTS {
            inputs.insert(
                stoich_name(species, element),
                field(stoich_bigint(&request.stoichiometry[species][element])),
            );
        }
    }
    inputs
}

fn thermochemical_expected_inputs() -> Vec<String> {
    let mut inputs = vec!["temperature".to_string(), "pressure".to_string()];
    for element in 0..THERMOCHEMICAL_ELEMENTS {
        inputs.push(total_name(element));
    }
    for species in 0..THERMOCHEMICAL_SPECIES {
        inputs.push(amount_name(species));
    }
    for species in 0..THERMOCHEMICAL_SPECIES {
        inputs.push(potential_name(species));
    }
    for element in 0..THERMOCHEMICAL_ELEMENTS {
        inputs.push(multiplier_name(element));
    }
    for species in 0..THERMOCHEMICAL_SPECIES {
        for element in 0..THERMOCHEMICAL_ELEMENTS {
            inputs.push(stoich_name(species, element));
        }
    }
    inputs
}

fn thermochemical_public_outputs() -> Vec<String> {
    vec![
        "equilibrium_commitment".to_string(),
        "constraint_satisfaction".to_string(),
        "total_moles".to_string(),
        "stationarity_norm".to_string(),
        "balance_norm".to_string(),
    ]
}

pub fn build_thermochemical_equilibrium_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("thermochemical_equilibrium_v1", FieldId::Bn254);
    builder.metadata_entry("application", "thermochemical-equilibrium")?;
    builder.metadata_entry("scientific_domain", "thermochemical-equilibrium")?;
    builder.metadata_entry("claim_scope", "gas-phase-tp-discrete-kkt-certificate")?;
    builder.metadata_entry("model_family", "gibbs-kkt-gas-phase")?;
    builder.metadata_entry("species_count", &THERMOCHEMICAL_SPECIES.to_string())?;
    builder.metadata_entry("element_count", &THERMOCHEMICAL_ELEMENTS.to_string())?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;
    builder.metadata_entry(
        "scope_boundary",
        "proves discrete element balance and KKT-style complementarity for the attested witness; does not claim continuous thermodynamic completeness",
    )?;

    builder.private_input("temperature")?;
    builder.private_input("pressure")?;
    for element in 0..THERMOCHEMICAL_ELEMENTS {
        builder.private_input(&total_name(element))?;
        builder.private_input(&multiplier_name(element))?;
    }
    let nonnegative_bits = bits_for_bound(&(science_scale() * science_scale() * two()));
    for species in 0..THERMOCHEMICAL_SPECIES {
        let amount = amount_name(species);
        builder.private_input(&amount)?;
        builder.private_input(&potential_name(species))?;
        builder.constrain_range(&amount, nonnegative_bits)?;
        for element in 0..THERMOCHEMICAL_ELEMENTS {
            builder.private_input(&stoich_name(species, element))?;
        }
    }

    for output in thermochemical_public_outputs() {
        builder.public_output(&output)?;
    }

    let mut commitment_inputs = vec![signal_expr("temperature"), signal_expr("pressure")];
    let mut total_moles_terms = Vec::new();
    let mut stationarity_norm_terms = Vec::new();
    let mut balance_norm_terms = Vec::new();

    for species in 0..THERMOCHEMICAL_SPECIES {
        let amount = amount_name(species);
        let potential = potential_name(species);
        total_moles_terms.push(signal_expr(&amount));
        commitment_inputs.push(signal_expr(&amount));
        commitment_inputs.push(signal_expr(&potential));

        let mut stationarity_terms = vec![signal_expr(&potential)];
        for element in 0..THERMOCHEMICAL_ELEMENTS {
            let multiplier = multiplier_name(element);
            let stoich = stoich_name(species, element);
            commitment_inputs.push(signal_expr(&stoich));
            stationarity_terms.push(sub_expr(
                const_expr(&zero()),
                mul_expr(signal_expr(&multiplier), signal_expr(&stoich)),
            ));
        }

        let stationarity = stationarity_name(species);
        builder.private_signal(&stationarity)?;
        builder.add_assignment(&stationarity, add_expr(stationarity_terms.clone()))?;
        builder.constrain_range(&stationarity, nonnegative_bits)?;
        builder.constrain_equal(
            mul_expr(signal_expr(&amount), signal_expr(&stationarity)),
            const_expr(&zero()),
        )?;
        stationarity_norm_terms.push(mul_expr(
            signal_expr(&stationarity),
            signal_expr(&stationarity),
        ));
    }

    for element in 0..THERMOCHEMICAL_ELEMENTS {
        let mut balance_terms = vec![sub_expr(
            const_expr(&zero()),
            signal_expr(&total_name(element)),
        )];
        commitment_inputs.push(signal_expr(&total_name(element)));
        commitment_inputs.push(signal_expr(&multiplier_name(element)));
        for species in 0..THERMOCHEMICAL_SPECIES {
            balance_terms.push(mul_expr(
                signal_expr(&amount_name(species)),
                signal_expr(&stoich_name(species, element)),
            ));
        }
        let balance = balance_name(element);
        builder.private_signal(&balance)?;
        builder.add_assignment(&balance, add_expr(balance_terms))?;
        builder.constrain_equal(signal_expr(&balance), const_expr(&zero()))?;
        balance_norm_terms.push(mul_expr(signal_expr(&balance), signal_expr(&balance)));
    }

    builder.add_assignment("total_moles", add_expr(total_moles_terms))?;
    builder.add_assignment("stationarity_norm", add_expr(stationarity_norm_terms))?;
    builder.add_assignment("balance_norm", add_expr(balance_norm_terms))?;
    builder.constrain_equal(
        signal_expr("constraint_satisfaction"),
        Expr::Const(zkf_core::FieldElement::ONE),
    )?;
    append_poseidon_commitment(
        &mut builder,
        "__thermochemical_commitment",
        &commitment_inputs,
        "equilibrium_commitment",
    )?;
    builder.build()
}

pub fn thermochemical_equilibrium_showcase() -> ZkfResult<TemplateProgram> {
    let sample_request = ThermochemicalEquilibriumRequestV1 {
        temperature: "3500".to_string(),
        pressure: "101325".to_string(),
        element_totals: ["4".to_string(), "3".to_string()],
        species_amounts: ["1".to_string(), "1".to_string(), "1".to_string()],
        chemical_potentials: ["4".to_string(), "6".to_string(), "7".to_string()],
        element_multipliers: ["2".to_string(), "3".to_string()],
        stoichiometry: [
            ["2".to_string(), "0".to_string()],
            ["0".to_string(), "2".to_string()],
            ["2".to_string(), "1".to_string()],
        ],
    };
    let sample_inputs = thermochemical_equilibrium_inputs_from_request(&sample_request);
    let mut violation_request = sample_request.clone();
    violation_request.element_totals[1] = "4".to_string();
    let violation_inputs = thermochemical_equilibrium_inputs_from_request(&violation_request);

    Ok(TemplateProgram {
        program: build_thermochemical_equilibrium_program()?,
        expected_inputs: thermochemical_expected_inputs(),
        public_outputs: thermochemical_public_outputs(),
        sample_inputs,
        violation_inputs,
        description: THERMOCHEMICAL_DESCRIPTION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thermochemical_showcase_surface_is_stable() {
        let template = thermochemical_equilibrium_showcase().expect("template");
        assert_eq!(
            template.expected_inputs.len(),
            2 + THERMOCHEMICAL_ELEMENTS * 2
                + THERMOCHEMICAL_SPECIES * 2
                + THERMOCHEMICAL_SPECIES * THERMOCHEMICAL_ELEMENTS
        );
        assert_eq!(template.public_outputs.len(), THERMOCHEMICAL_PUBLIC_OUTPUTS);
        assert_eq!(
            template.program.metadata.get("normalization_scale"),
            Some(&science_scale_string())
        );
    }

    #[test]
    fn thermochemical_request_roundtrip_binds_commitment() {
        let request = ThermochemicalEquilibriumRequestV1 {
            temperature: "3500".to_string(),
            pressure: "101325".to_string(),
            element_totals: ["4".to_string(), "3".to_string()],
            species_amounts: ["1".to_string(), "1".to_string(), "1".to_string()],
            chemical_potentials: ["4".to_string(), "6".to_string(), "7".to_string()],
            element_multipliers: ["2".to_string(), "3".to_string()],
            stoichiometry: [
                ["2".to_string(), "0".to_string()],
                ["0".to_string(), "2".to_string()],
                ["2".to_string(), "1".to_string()],
            ],
        };
        let inputs = thermochemical_equilibrium_inputs_from_request(&request);
        let commitment = super::super::science::poseidon_chain_commitment(
            &inputs.values().cloned().collect::<Vec<_>>(),
        )
        .expect("commitment");
        assert_ne!(commitment, zkf_core::FieldElement::ZERO);
        assert!(
            super::super::science::sha256_hex_json("thermochemical", &request)
                .expect("digest")
                .len()
                == 64
        );
    }
}
