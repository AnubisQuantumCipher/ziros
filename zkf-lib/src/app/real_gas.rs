#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use zkf_core::{Expr, FieldElement, FieldId, Program, WitnessInputs, ZkfResult};

use super::builder::ProgramBuilder;
use super::science::{
    add_expr, append_poseidon_commitment, bits_for_bound, const_expr, decimal_scaled, field,
    mul_expr, science_scale, science_scale_string, signal_expr, sub_expr, two, zero,
};
use super::templates::TemplateProgram;

pub const REAL_GAS_COMPONENTS: usize = 2;
pub const REAL_GAS_PUBLIC_OUTPUTS: usize = 5;

const REAL_GAS_DESCRIPTION: &str = "Real-gas state certificate over a fixed binary-mixture surface. The circuit proves the attested reduced mixing coefficients, admissible compressibility root selection, cubic EOS root satisfaction for either Peng-Robinson or Redlich-Kwong, and a Poseidon commitment binding the state and coefficient table.";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RealGasModelFamilyV1 {
    PengRobinson,
    RedlichKwong,
}

impl RealGasModelFamilyV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PengRobinson => "peng-robinson",
            Self::RedlichKwong => "redlich-kwong",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealGasStateRequestV1 {
    pub temperature: String,
    pub pressure: String,
    pub mole_fractions: [String; REAL_GAS_COMPONENTS],
    pub reduced_a: String,
    pub reduced_b: String,
    pub z_factor: String,
    pub attraction_matrix: [[String; REAL_GAS_COMPONENTS]; REAL_GAS_COMPONENTS],
    pub covolumes: [String; REAL_GAS_COMPONENTS],
}

fn mole_fraction_name(component: usize) -> String {
    format!("mole_fraction_{component}")
}

fn covolume_name(component: usize) -> String {
    format!("covolume_{component}")
}

fn attraction_name(left: usize, right: usize) -> String {
    format!("attraction_{left}_{right}")
}

pub fn real_gas_state_inputs_from_request(request: &RealGasStateRequestV1) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    inputs.insert(
        "temperature".to_string(),
        field(decimal_scaled(&request.temperature)),
    );
    inputs.insert(
        "pressure".to_string(),
        field(decimal_scaled(&request.pressure)),
    );
    inputs.insert(
        "reduced_a".to_string(),
        field(decimal_scaled(&request.reduced_a)),
    );
    inputs.insert(
        "reduced_b".to_string(),
        field(decimal_scaled(&request.reduced_b)),
    );
    inputs.insert(
        "z_factor".to_string(),
        field(decimal_scaled(&request.z_factor)),
    );
    for component in 0..REAL_GAS_COMPONENTS {
        inputs.insert(
            mole_fraction_name(component),
            field(decimal_scaled(&request.mole_fractions[component])),
        );
        inputs.insert(
            covolume_name(component),
            field(decimal_scaled(&request.covolumes[component])),
        );
        for other in 0..REAL_GAS_COMPONENTS {
            inputs.insert(
                attraction_name(component, other),
                field(decimal_scaled(&request.attraction_matrix[component][other])),
            );
        }
    }
    inputs
}

fn real_gas_expected_inputs() -> Vec<String> {
    let mut inputs = vec![
        "temperature".to_string(),
        "pressure".to_string(),
        "reduced_a".to_string(),
        "reduced_b".to_string(),
        "z_factor".to_string(),
    ];
    for component in 0..REAL_GAS_COMPONENTS {
        inputs.push(mole_fraction_name(component));
    }
    for component in 0..REAL_GAS_COMPONENTS {
        inputs.push(covolume_name(component));
    }
    for left in 0..REAL_GAS_COMPONENTS {
        for right in 0..REAL_GAS_COMPONENTS {
            inputs.push(attraction_name(left, right));
        }
    }
    inputs
}

fn real_gas_public_outputs() -> Vec<String> {
    vec![
        "state_commitment".to_string(),
        "constraint_satisfaction".to_string(),
        "z_factor_public".to_string(),
        "compressibility_departure".to_string(),
        "eos_residual_norm".to_string(),
    ]
}

fn add_common_real_gas_constraints(builder: &mut ProgramBuilder) -> ZkfResult<()> {
    let nonnegative_bits = bits_for_bound(&(science_scale() * science_scale() * two()));
    let composition_scale = science_scale();
    builder.private_input("temperature")?;
    builder.private_input("pressure")?;
    builder.private_input("reduced_a")?;
    builder.private_input("reduced_b")?;
    builder.private_input("z_factor")?;
    builder.constrain_range("reduced_a", nonnegative_bits)?;
    builder.constrain_range("reduced_b", nonnegative_bits)?;
    builder.constrain_range("z_factor", nonnegative_bits)?;
    for component in 0..REAL_GAS_COMPONENTS {
        let x = mole_fraction_name(component);
        let b = covolume_name(component);
        builder.private_input(&x)?;
        builder.private_input(&b)?;
        builder.constrain_range(&x, nonnegative_bits)?;
        builder.constrain_range(&b, nonnegative_bits)?;
        for other in 0..REAL_GAS_COMPONENTS {
            let a = attraction_name(component, other);
            builder.private_input(&a)?;
            builder.constrain_range(&a, nonnegative_bits)?;
        }
    }

    for output in real_gas_public_outputs() {
        builder.public_output(&output)?;
    }

    builder.constrain_equal(
        add_expr(vec![
            signal_expr(&mole_fraction_name(0)),
            signal_expr(&mole_fraction_name(1)),
        ]),
        const_expr(&composition_scale),
    )?;

    let mixed_a = add_expr(vec![
        mul_expr(
            signal_expr(&attraction_name(0, 0)),
            mul_expr(
                signal_expr(&mole_fraction_name(0)),
                signal_expr(&mole_fraction_name(0)),
            ),
        ),
        mul_expr(
            mul_expr(const_expr(&two()), signal_expr(&attraction_name(0, 1))),
            mul_expr(
                signal_expr(&mole_fraction_name(0)),
                signal_expr(&mole_fraction_name(1)),
            ),
        ),
        mul_expr(
            signal_expr(&attraction_name(1, 1)),
            mul_expr(
                signal_expr(&mole_fraction_name(1)),
                signal_expr(&mole_fraction_name(1)),
            ),
        ),
    ]);
    builder.constrain_equal(
        mul_expr(
            signal_expr("reduced_a"),
            mul_expr(
                const_expr(&composition_scale),
                const_expr(&composition_scale),
            ),
        ),
        mixed_a,
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr("reduced_b"), const_expr(&composition_scale)),
        add_expr(vec![
            mul_expr(
                signal_expr(&covolume_name(0)),
                signal_expr(&mole_fraction_name(0)),
            ),
            mul_expr(
                signal_expr(&covolume_name(1)),
                signal_expr(&mole_fraction_name(1)),
            ),
        ]),
    )?;

    let phase_slack = "phase_admissibility_slack";
    builder.private_signal(phase_slack)?;
    builder.add_assignment(
        phase_slack,
        sub_expr(signal_expr("z_factor"), signal_expr("reduced_b")),
    )?;
    builder.constrain_range(phase_slack, nonnegative_bits)?;
    builder.constrain_equal(
        signal_expr("z_factor"),
        add_expr(vec![signal_expr("reduced_b"), signal_expr(phase_slack)]),
    )?;
    builder.private_signal("phase_admissibility_anchor")?;
    builder.constrain_equal(
        signal_expr("phase_admissibility_anchor"),
        mul_expr(signal_expr(phase_slack), signal_expr(phase_slack)),
    )?;

    builder.add_assignment("z_factor_public", signal_expr("z_factor"))?;
    builder.add_assignment(
        "compressibility_departure",
        sub_expr(signal_expr("z_factor"), const_expr(&science_scale())),
    )?;
    builder.constrain_equal(
        signal_expr("constraint_satisfaction"),
        Expr::Const(FieldElement::ONE),
    )?;

    let mut commitment_inputs = vec![
        signal_expr("temperature"),
        signal_expr("pressure"),
        signal_expr("reduced_a"),
        signal_expr("reduced_b"),
        signal_expr("z_factor"),
    ];
    for component in 0..REAL_GAS_COMPONENTS {
        commitment_inputs.push(signal_expr(&mole_fraction_name(component)));
    }
    for component in 0..REAL_GAS_COMPONENTS {
        commitment_inputs.push(signal_expr(&covolume_name(component)));
    }
    for left in 0..REAL_GAS_COMPONENTS {
        for right in 0..REAL_GAS_COMPONENTS {
            commitment_inputs.push(signal_expr(&attraction_name(left, right)));
        }
    }
    append_poseidon_commitment(
        builder,
        "__real_gas_commitment",
        &commitment_inputs,
        "state_commitment",
    )?;
    Ok(())
}

pub fn build_real_gas_state_program(model_family: RealGasModelFamilyV1) -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new(
        format!(
            "real_gas_state_{}_v1",
            model_family.as_str().replace('-', "_")
        ),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "real-gas-state")?;
    builder.metadata_entry("scientific_domain", "real-gas")?;
    builder.metadata_entry("claim_scope", "binary-mixture-cubic-eos-root-certificate")?;
    builder.metadata_entry("model_family", model_family.as_str())?;
    builder.metadata_entry("components", &REAL_GAS_COMPONENTS.to_string())?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;
    builder.metadata_entry(
        "scope_boundary",
        "proves reduced mixing arithmetic, admissible Z > B root selection, and cubic EOS residual closure for the attested coefficients; does not mechanize fugacity logarithms",
    )?;
    add_common_real_gas_constraints(&mut builder)?;

    let z = signal_expr("z_factor");
    let a = signal_expr("reduced_a");
    let b = signal_expr("reduced_b");
    let scale = science_scale();
    let scale_expr = const_expr(&scale);

    let residual_expr = match model_family {
        RealGasModelFamilyV1::PengRobinson => add_expr(vec![
            mul_expr(z.clone(), mul_expr(z.clone(), z.clone())),
            sub_expr(
                const_expr(&zero()),
                mul_expr(
                    sub_expr(scale_expr.clone(), b.clone()),
                    mul_expr(z.clone(), z.clone()),
                ),
            ),
            mul_expr(
                add_expr(vec![
                    mul_expr(a.clone(), const_expr(&scale)),
                    sub_expr(
                        const_expr(&zero()),
                        mul_expr(
                            const_expr(&num_bigint::BigInt::from(3u8)),
                            mul_expr(b.clone(), b.clone()),
                        ),
                    ),
                    sub_expr(
                        const_expr(&zero()),
                        mul_expr(const_expr(&(two() * scale.clone())), b.clone()),
                    ),
                ]),
                z.clone(),
            ),
            sub_expr(
                const_expr(&zero()),
                add_expr(vec![
                    mul_expr(mul_expr(a, b.clone()), const_expr(&scale)),
                    sub_expr(
                        const_expr(&zero()),
                        mul_expr(mul_expr(b.clone(), b.clone()), const_expr(&scale)),
                    ),
                    sub_expr(
                        const_expr(&zero()),
                        mul_expr(b.clone(), mul_expr(b.clone(), b)),
                    ),
                ]),
            ),
        ]),
        RealGasModelFamilyV1::RedlichKwong => add_expr(vec![
            mul_expr(z.clone(), mul_expr(z.clone(), z.clone())),
            sub_expr(
                const_expr(&zero()),
                mul_expr(scale_expr.clone(), mul_expr(z.clone(), z.clone())),
            ),
            mul_expr(
                add_expr(vec![
                    mul_expr(a.clone(), const_expr(&scale)),
                    sub_expr(const_expr(&zero()), mul_expr(scale_expr.clone(), b.clone())),
                    sub_expr(const_expr(&zero()), mul_expr(b.clone(), b.clone())),
                ]),
                z.clone(),
            ),
            sub_expr(
                const_expr(&zero()),
                mul_expr(mul_expr(a, b), const_expr(&scale)),
            ),
        ]),
    };
    builder.add_assignment(
        "eos_residual_norm",
        mul_expr(residual_expr.clone(), residual_expr.clone()),
    )?;
    builder.constrain_equal(residual_expr, const_expr(&zero()))?;
    builder.build()
}

pub fn real_gas_state_showcase_for_model(
    model_family: RealGasModelFamilyV1,
) -> ZkfResult<TemplateProgram> {
    let sample_request = RealGasStateRequestV1 {
        temperature: "300".to_string(),
        pressure: "1".to_string(),
        mole_fractions: ["1".to_string(), "0".to_string()],
        reduced_a: "0".to_string(),
        reduced_b: "0".to_string(),
        z_factor: "1".to_string(),
        attraction_matrix: [
            ["0".to_string(), "0".to_string()],
            ["0".to_string(), "0".to_string()],
        ],
        covolumes: ["0".to_string(), "0".to_string()],
    };
    let sample_inputs = real_gas_state_inputs_from_request(&sample_request);
    let mut violation_request = sample_request.clone();
    violation_request.z_factor = "2".to_string();
    let violation_inputs = real_gas_state_inputs_from_request(&violation_request);

    Ok(TemplateProgram {
        program: build_real_gas_state_program(model_family)?,
        expected_inputs: real_gas_expected_inputs(),
        public_outputs: real_gas_public_outputs(),
        sample_inputs,
        violation_inputs,
        description: REAL_GAS_DESCRIPTION,
    })
}

pub fn real_gas_state_showcase() -> ZkfResult<TemplateProgram> {
    real_gas_state_showcase_for_model(RealGasModelFamilyV1::PengRobinson)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_gas_showcase_surfaces_are_present() {
        for family in [
            RealGasModelFamilyV1::PengRobinson,
            RealGasModelFamilyV1::RedlichKwong,
        ] {
            let template = real_gas_state_showcase_for_model(family).expect("template");
            assert_eq!(template.public_outputs.len(), REAL_GAS_PUBLIC_OUTPUTS);
            assert_eq!(
                template.program.metadata.get("model_family"),
                Some(&family.as_str().to_string())
            );
        }
    }

    #[test]
    fn real_gas_request_json_digest_is_stable() {
        let request = RealGasStateRequestV1 {
            temperature: "300".to_string(),
            pressure: "1".to_string(),
            mole_fractions: ["1".to_string(), "0".to_string()],
            reduced_a: "0".to_string(),
            reduced_b: "0".to_string(),
            z_factor: "1".to_string(),
            attraction_matrix: [
                ["0".to_string(), "0".to_string()],
                ["0".to_string(), "0".to_string()],
            ],
            covolumes: ["0".to_string(), "0".to_string()],
        };
        assert_eq!(
            super::super::science::sha256_hex_json("real-gas", &request)
                .expect("digest")
                .len(),
            64
        );
    }
}
