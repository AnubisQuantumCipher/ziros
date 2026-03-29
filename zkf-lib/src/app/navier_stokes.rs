#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use zkf_core::{Expr, FieldElement, FieldId, Program, WitnessInputs, ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::science::{
    add_expr, append_poseidon_commitment, bits_for_bound, const_expr, decimal_scaled, field,
    mul_expr, science_scale, science_scale_string, signal_expr, sub_expr, two, zero,
};
use super::templates::TemplateProgram;

pub const NAVIER_STOKES_DEFAULT_CELLS: usize = 3;
pub const NAVIER_STOKES_PUBLIC_OUTPUTS: usize = 5;

const NAVIER_STOKES_DESCRIPTION: &str = "Structured-grid 1D finite-volume Navier-Stokes step certificate. The circuit proves the supplied primitive-state helpers, Rusanov convective fluxes, central viscous fluxes, CFL guard, explicit next-state update, and a Poseidon commitment binding the step trace and boundary conditions.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavierStokesCellStateV1 {
    pub density: String,
    pub momentum: String,
    pub energy: String,
    pub velocity: String,
    pub kinetic_energy_density: String,
    pub pressure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavierStokesInterfaceCertificateV1 {
    pub signal_speed: String,
    pub convective_flux_mass: String,
    pub convective_flux_momentum: String,
    pub convective_flux_energy: String,
    pub viscous_flux_momentum: String,
    pub viscous_flux_energy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavierStokesStructuredStepRequestV1 {
    pub dt: String,
    pub dx: String,
    pub gamma: String,
    pub viscosity: String,
    pub cfl_limit: String,
    pub left_boundary: NavierStokesCellStateV1,
    pub right_boundary: NavierStokesCellStateV1,
    pub current_cells: Vec<NavierStokesCellStateV1>,
    pub next_cells: Vec<NavierStokesCellStateV1>,
    pub interfaces: Vec<NavierStokesInterfaceCertificateV1>,
}

fn density_name(prefix: &str) -> String {
    format!("{prefix}_density")
}

fn momentum_name(prefix: &str) -> String {
    format!("{prefix}_momentum")
}

fn energy_name(prefix: &str) -> String {
    format!("{prefix}_energy")
}

fn velocity_name(prefix: &str) -> String {
    format!("{prefix}_velocity")
}

fn kinetic_name(prefix: &str) -> String {
    format!("{prefix}_kinetic")
}

fn pressure_name(prefix: &str) -> String {
    format!("{prefix}_pressure")
}

fn iface_name(index: usize, field: &str) -> String {
    format!("iface_{index}_{field}")
}

fn current_prefix(cell: usize) -> String {
    format!("cell_{cell}_current")
}

fn next_prefix(cell: usize) -> String {
    format!("cell_{cell}_next")
}

fn populate_state_inputs(
    inputs: &mut WitnessInputs,
    prefix: &str,
    state: &NavierStokesCellStateV1,
) {
    inputs.insert(density_name(prefix), field(decimal_scaled(&state.density)));
    inputs.insert(
        momentum_name(prefix),
        field(decimal_scaled(&state.momentum)),
    );
    inputs.insert(energy_name(prefix), field(decimal_scaled(&state.energy)));
    inputs.insert(
        velocity_name(prefix),
        field(decimal_scaled(&state.velocity)),
    );
    inputs.insert(
        kinetic_name(prefix),
        field(decimal_scaled(&state.kinetic_energy_density)),
    );
    inputs.insert(
        pressure_name(prefix),
        field(decimal_scaled(&state.pressure)),
    );
}

fn declare_state_inputs(
    builder: &mut ProgramBuilder,
    prefix: &str,
    nonnegative_bits: u32,
) -> ZkfResult<()> {
    let density = density_name(prefix);
    let energy = energy_name(prefix);
    let velocity = velocity_name(prefix);
    let momentum = momentum_name(prefix);
    let kinetic = kinetic_name(prefix);
    let pressure = pressure_name(prefix);
    builder.private_input(&density)?;
    builder.private_input(&momentum)?;
    builder.private_input(&energy)?;
    builder.private_input(&velocity)?;
    builder.private_input(&kinetic)?;
    builder.private_input(&pressure)?;
    builder.constrain_range(&density, nonnegative_bits)?;
    builder.constrain_range(&energy, nonnegative_bits)?;
    builder.constrain_range(&kinetic, nonnegative_bits)?;
    builder.constrain_range(&pressure, nonnegative_bits)?;
    Ok(())
}

fn constrain_state_closure(
    builder: &mut ProgramBuilder,
    prefix: &str,
    gamma_name: &str,
) -> ZkfResult<()> {
    let scale = science_scale();
    builder.constrain_equal(
        mul_expr(
            signal_expr(&density_name(prefix)),
            signal_expr(&velocity_name(prefix)),
        ),
        signal_expr(&momentum_name(prefix)),
    )?;
    builder.constrain_equal(
        mul_expr(
            mul_expr(const_expr(&two()), signal_expr(&density_name(prefix))),
            signal_expr(&kinetic_name(prefix)),
        ),
        mul_expr(
            signal_expr(&momentum_name(prefix)),
            signal_expr(&momentum_name(prefix)),
        ),
    )?;
    builder.constrain_equal(
        mul_expr(signal_expr(&pressure_name(prefix)), const_expr(&scale)),
        mul_expr(
            sub_expr(signal_expr(gamma_name), const_expr(&scale)),
            sub_expr(
                signal_expr(&energy_name(prefix)),
                signal_expr(&kinetic_name(prefix)),
            ),
        ),
    )?;
    Ok(())
}

pub fn navier_stokes_structured_step_inputs_from_request(
    request: &NavierStokesStructuredStepRequestV1,
) -> ZkfResult<WitnessInputs> {
    let cells = request.current_cells.len();
    if cells == 0 {
        return Err(ZkfError::InvalidArtifact(
            "navier-stokes request requires at least one cell".to_string(),
        ));
    }
    if request.next_cells.len() != cells {
        return Err(ZkfError::InvalidArtifact(format!(
            "next_cells length {} must match current_cells length {cells}",
            request.next_cells.len()
        )));
    }
    if request.interfaces.len() != cells + 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "interfaces length {} must equal current_cells length + 1 ({})",
            request.interfaces.len(),
            cells + 1
        )));
    }

    let mut inputs = WitnessInputs::new();
    inputs.insert("dt".to_string(), field(decimal_scaled(&request.dt)));
    inputs.insert("dx".to_string(), field(decimal_scaled(&request.dx)));
    inputs.insert("gamma".to_string(), field(decimal_scaled(&request.gamma)));
    inputs.insert(
        "viscosity".to_string(),
        field(decimal_scaled(&request.viscosity)),
    );
    inputs.insert(
        "cfl_limit".to_string(),
        field(decimal_scaled(&request.cfl_limit)),
    );

    populate_state_inputs(&mut inputs, "left_boundary", &request.left_boundary);
    populate_state_inputs(&mut inputs, "right_boundary", &request.right_boundary);
    for (cell, state) in request.current_cells.iter().enumerate() {
        populate_state_inputs(&mut inputs, &current_prefix(cell), state);
    }
    for (cell, state) in request.next_cells.iter().enumerate() {
        populate_state_inputs(&mut inputs, &next_prefix(cell), state);
    }
    for (index, interface) in request.interfaces.iter().enumerate() {
        inputs.insert(
            iface_name(index, "signal_speed"),
            field(decimal_scaled(&interface.signal_speed)),
        );
        inputs.insert(
            iface_name(index, "convective_flux_mass"),
            field(decimal_scaled(&interface.convective_flux_mass)),
        );
        inputs.insert(
            iface_name(index, "convective_flux_momentum"),
            field(decimal_scaled(&interface.convective_flux_momentum)),
        );
        inputs.insert(
            iface_name(index, "convective_flux_energy"),
            field(decimal_scaled(&interface.convective_flux_energy)),
        );
        inputs.insert(
            iface_name(index, "viscous_flux_momentum"),
            field(decimal_scaled(&interface.viscous_flux_momentum)),
        );
        inputs.insert(
            iface_name(index, "viscous_flux_energy"),
            field(decimal_scaled(&interface.viscous_flux_energy)),
        );
    }
    Ok(inputs)
}

fn navier_expected_inputs(cells: usize) -> Vec<String> {
    let mut inputs = vec![
        "dt".to_string(),
        "dx".to_string(),
        "gamma".to_string(),
        "viscosity".to_string(),
        "cfl_limit".to_string(),
    ];
    for prefix in ["left_boundary", "right_boundary"] {
        inputs.push(density_name(prefix));
        inputs.push(momentum_name(prefix));
        inputs.push(energy_name(prefix));
        inputs.push(velocity_name(prefix));
        inputs.push(kinetic_name(prefix));
        inputs.push(pressure_name(prefix));
    }
    for cell in 0..cells {
        let prefix = current_prefix(cell);
        inputs.push(density_name(&prefix));
        inputs.push(momentum_name(&prefix));
        inputs.push(energy_name(&prefix));
        inputs.push(velocity_name(&prefix));
        inputs.push(kinetic_name(&prefix));
        inputs.push(pressure_name(&prefix));
    }
    for cell in 0..cells {
        let prefix = next_prefix(cell);
        inputs.push(density_name(&prefix));
        inputs.push(momentum_name(&prefix));
        inputs.push(energy_name(&prefix));
        inputs.push(velocity_name(&prefix));
        inputs.push(kinetic_name(&prefix));
        inputs.push(pressure_name(&prefix));
    }
    for iface in 0..=cells {
        for field in [
            "signal_speed",
            "convective_flux_mass",
            "convective_flux_momentum",
            "convective_flux_energy",
            "viscous_flux_momentum",
            "viscous_flux_energy",
        ] {
            inputs.push(iface_name(iface, field));
        }
    }
    inputs
}

fn navier_public_outputs() -> Vec<String> {
    vec![
        "step_commitment".to_string(),
        "constraint_satisfaction".to_string(),
        "mass_drift".to_string(),
        "momentum_drift".to_string(),
        "energy_drift".to_string(),
    ]
}

fn sample_uniform_state() -> NavierStokesCellStateV1 {
    NavierStokesCellStateV1 {
        density: "1".to_string(),
        momentum: "0".to_string(),
        energy: "2.5".to_string(),
        velocity: "0".to_string(),
        kinetic_energy_density: "0".to_string(),
        pressure: "1".to_string(),
    }
}

fn sample_uniform_interface() -> NavierStokesInterfaceCertificateV1 {
    NavierStokesInterfaceCertificateV1 {
        signal_speed: "1".to_string(),
        convective_flux_mass: "0".to_string(),
        convective_flux_momentum: "1".to_string(),
        convective_flux_energy: "0".to_string(),
        viscous_flux_momentum: "0".to_string(),
        viscous_flux_energy: "0".to_string(),
    }
}

fn sample_request(cells: usize) -> NavierStokesStructuredStepRequestV1 {
    NavierStokesStructuredStepRequestV1 {
        dt: "0.1".to_string(),
        dx: "1".to_string(),
        gamma: "1.4".to_string(),
        viscosity: "0.1".to_string(),
        cfl_limit: "0.5".to_string(),
        left_boundary: sample_uniform_state(),
        right_boundary: sample_uniform_state(),
        current_cells: vec![sample_uniform_state(); cells],
        next_cells: vec![sample_uniform_state(); cells],
        interfaces: vec![sample_uniform_interface(); cells + 1],
    }
}

pub fn build_navier_stokes_structured_step_program(cells: usize) -> ZkfResult<Program> {
    if cells == 0 {
        return Err(ZkfError::InvalidArtifact(
            "navier-stokes structured step requires at least one cell".to_string(),
        ));
    }
    let mut builder = ProgramBuilder::new(
        format!("navier_stokes_structured_step_{cells}_cells_v1"),
        FieldId::Bn254,
    );
    builder.metadata_entry("application", "navier-stokes-structured")?;
    builder.metadata_entry("scientific_domain", "navier-stokes")?;
    builder.metadata_entry(
        "claim_scope",
        "structured-grid-finite-volume-step-certificate",
    )?;
    builder.metadata_entry("discretization", "1d-rusanov-plus-central-viscous")?;
    builder.metadata_entry("cell_count", &cells.to_string())?;
    builder.metadata_entry("normalization_scale", &science_scale_string())?;
    builder.metadata_entry(
        "scope_boundary",
        "proves one discrete structured finite-volume update for the attested state and flux witnesses; does not claim PDE existence, turbulence closure, or unstructured support",
    )?;

    builder.private_input("dt")?;
    builder.private_input("dx")?;
    builder.private_input("gamma")?;
    builder.private_input("viscosity")?;
    builder.private_input("cfl_limit")?;

    let nonnegative_bits = bits_for_bound(&(science_scale() * science_scale() * two()));
    builder.constrain_range("dt", nonnegative_bits)?;
    builder.constrain_range("dx", nonnegative_bits)?;
    builder.constrain_range("gamma", nonnegative_bits)?;
    builder.constrain_range("viscosity", nonnegative_bits)?;
    builder.constrain_range("cfl_limit", nonnegative_bits)?;

    declare_state_inputs(&mut builder, "left_boundary", nonnegative_bits)?;
    declare_state_inputs(&mut builder, "right_boundary", nonnegative_bits)?;
    constrain_state_closure(&mut builder, "left_boundary", "gamma")?;
    constrain_state_closure(&mut builder, "right_boundary", "gamma")?;

    for cell in 0..cells {
        let current = current_prefix(cell);
        let next = next_prefix(cell);
        declare_state_inputs(&mut builder, &current, nonnegative_bits)?;
        declare_state_inputs(&mut builder, &next, nonnegative_bits)?;
        constrain_state_closure(&mut builder, &current, "gamma")?;
        constrain_state_closure(&mut builder, &next, "gamma")?;
    }

    for output in navier_public_outputs() {
        builder.public_output(&output)?;
    }
    builder.constrain_equal(
        signal_expr("constraint_satisfaction"),
        Expr::Const(FieldElement::ONE),
    )?;

    let scale = science_scale();
    let two_scale = two() * scale.clone();
    let mut commitment_inputs = vec![
        signal_expr("dt"),
        signal_expr("dx"),
        signal_expr("gamma"),
        signal_expr("viscosity"),
        signal_expr("cfl_limit"),
    ];
    for prefix in ["left_boundary", "right_boundary"] {
        commitment_inputs.push(signal_expr(&density_name(prefix)));
        commitment_inputs.push(signal_expr(&momentum_name(prefix)));
        commitment_inputs.push(signal_expr(&energy_name(prefix)));
        commitment_inputs.push(signal_expr(&velocity_name(prefix)));
        commitment_inputs.push(signal_expr(&kinetic_name(prefix)));
        commitment_inputs.push(signal_expr(&pressure_name(prefix)));
    }

    for iface in 0..=cells {
        for field in [
            "signal_speed",
            "convective_flux_mass",
            "convective_flux_momentum",
            "convective_flux_energy",
            "viscous_flux_momentum",
            "viscous_flux_energy",
        ] {
            let name = iface_name(iface, field);
            builder.private_input(&name)?;
            if field == "signal_speed" {
                builder.constrain_range(&name, nonnegative_bits)?;
            }
            commitment_inputs.push(signal_expr(&name));
        }

        let left_prefix = if iface == 0 {
            "left_boundary".to_string()
        } else {
            current_prefix(iface - 1)
        };
        let right_prefix = if iface == cells {
            "right_boundary".to_string()
        } else {
            current_prefix(iface)
        };
        let speed = signal_expr(&iface_name(iface, "signal_speed"));
        let conv_mass = signal_expr(&iface_name(iface, "convective_flux_mass"));
        let conv_momentum = signal_expr(&iface_name(iface, "convective_flux_momentum"));
        let conv_energy = signal_expr(&iface_name(iface, "convective_flux_energy"));
        let visc_momentum = signal_expr(&iface_name(iface, "viscous_flux_momentum"));
        builder.constrain_equal(
            mul_expr(const_expr(&two_scale), conv_mass),
            add_expr(vec![
                mul_expr(
                    const_expr(&scale),
                    add_expr(vec![
                        signal_expr(&momentum_name(&left_prefix)),
                        signal_expr(&momentum_name(&right_prefix)),
                    ]),
                ),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        speed.clone(),
                        sub_expr(
                            signal_expr(&density_name(&right_prefix)),
                            signal_expr(&density_name(&left_prefix)),
                        ),
                    ),
                ),
            ]),
        )?;

        builder.constrain_equal(
            mul_expr(const_expr(&two_scale), conv_momentum),
            add_expr(vec![
                mul_expr(
                    signal_expr(&momentum_name(&left_prefix)),
                    signal_expr(&velocity_name(&left_prefix)),
                ),
                mul_expr(
                    signal_expr(&momentum_name(&right_prefix)),
                    signal_expr(&velocity_name(&right_prefix)),
                ),
                mul_expr(
                    const_expr(&scale),
                    add_expr(vec![
                        signal_expr(&pressure_name(&left_prefix)),
                        signal_expr(&pressure_name(&right_prefix)),
                    ]),
                ),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        speed.clone(),
                        sub_expr(
                            signal_expr(&momentum_name(&right_prefix)),
                            signal_expr(&momentum_name(&left_prefix)),
                        ),
                    ),
                ),
            ]),
        )?;

        builder.constrain_equal(
            mul_expr(const_expr(&two_scale), conv_energy),
            add_expr(vec![
                mul_expr(
                    signal_expr(&velocity_name(&left_prefix)),
                    add_expr(vec![
                        signal_expr(&energy_name(&left_prefix)),
                        signal_expr(&pressure_name(&left_prefix)),
                    ]),
                ),
                mul_expr(
                    signal_expr(&velocity_name(&right_prefix)),
                    add_expr(vec![
                        signal_expr(&energy_name(&right_prefix)),
                        signal_expr(&pressure_name(&right_prefix)),
                    ]),
                ),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        speed.clone(),
                        sub_expr(
                            signal_expr(&energy_name(&right_prefix)),
                            signal_expr(&energy_name(&left_prefix)),
                        ),
                    ),
                ),
            ]),
        )?;

        builder.constrain_equal(
            mul_expr(visc_momentum.clone(), signal_expr("dx")),
            mul_expr(
                signal_expr("viscosity"),
                sub_expr(
                    signal_expr(&velocity_name(&right_prefix)),
                    signal_expr(&velocity_name(&left_prefix)),
                ),
            ),
        )?;
        builder.constrain_equal(
            mul_expr(
                mul_expr(
                    const_expr(&two_scale),
                    signal_expr(&iface_name(iface, "viscous_flux_energy")),
                ),
                signal_expr("dx"),
            ),
            mul_expr(
                signal_expr("viscosity"),
                mul_expr(
                    sub_expr(
                        signal_expr(&velocity_name(&right_prefix)),
                        signal_expr(&velocity_name(&left_prefix)),
                    ),
                    add_expr(vec![
                        signal_expr(&velocity_name(&left_prefix)),
                        signal_expr(&velocity_name(&right_prefix)),
                    ]),
                ),
            ),
        )?;

        builder.constrain_leq(
            &iface_name(iface, "cfl_slack"),
            mul_expr(signal_expr("dt"), speed),
            mul_expr(signal_expr("cfl_limit"), signal_expr("dx")),
            bits_for_bound(&(science_scale() * science_scale() * science_scale())),
        )?;
    }

    let mut mass_drift_terms = Vec::new();
    let mut momentum_drift_terms = Vec::new();
    let mut energy_drift_terms = Vec::new();
    for cell in 0..cells {
        let current = current_prefix(cell);
        let next = next_prefix(cell);
        commitment_inputs.push(signal_expr(&density_name(&current)));
        commitment_inputs.push(signal_expr(&momentum_name(&current)));
        commitment_inputs.push(signal_expr(&energy_name(&current)));
        commitment_inputs.push(signal_expr(&velocity_name(&current)));
        commitment_inputs.push(signal_expr(&kinetic_name(&current)));
        commitment_inputs.push(signal_expr(&pressure_name(&current)));
        commitment_inputs.push(signal_expr(&density_name(&next)));
        commitment_inputs.push(signal_expr(&momentum_name(&next)));
        commitment_inputs.push(signal_expr(&energy_name(&next)));
        commitment_inputs.push(signal_expr(&velocity_name(&next)));
        commitment_inputs.push(signal_expr(&kinetic_name(&next)));
        commitment_inputs.push(signal_expr(&pressure_name(&next)));

        builder.constrain_equal(
            mul_expr(signal_expr("dx"), signal_expr(&density_name(&next))),
            add_expr(vec![
                mul_expr(signal_expr("dx"), signal_expr(&density_name(&current))),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        signal_expr("dt"),
                        sub_expr(
                            signal_expr(&iface_name(cell + 1, "convective_flux_mass")),
                            signal_expr(&iface_name(cell, "convective_flux_mass")),
                        ),
                    ),
                ),
            ]),
        )?;

        builder.constrain_equal(
            mul_expr(signal_expr("dx"), signal_expr(&momentum_name(&next))),
            add_expr(vec![
                mul_expr(signal_expr("dx"), signal_expr(&momentum_name(&current))),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        signal_expr("dt"),
                        sub_expr(
                            signal_expr(&iface_name(cell + 1, "convective_flux_momentum")),
                            signal_expr(&iface_name(cell, "convective_flux_momentum")),
                        ),
                    ),
                ),
                mul_expr(
                    signal_expr("dt"),
                    sub_expr(
                        signal_expr(&iface_name(cell + 1, "viscous_flux_momentum")),
                        signal_expr(&iface_name(cell, "viscous_flux_momentum")),
                    ),
                ),
            ]),
        )?;

        builder.constrain_equal(
            mul_expr(signal_expr("dx"), signal_expr(&energy_name(&next))),
            add_expr(vec![
                mul_expr(signal_expr("dx"), signal_expr(&energy_name(&current))),
                sub_expr(
                    const_expr(&zero()),
                    mul_expr(
                        signal_expr("dt"),
                        sub_expr(
                            signal_expr(&iface_name(cell + 1, "convective_flux_energy")),
                            signal_expr(&iface_name(cell, "convective_flux_energy")),
                        ),
                    ),
                ),
                mul_expr(
                    signal_expr("dt"),
                    sub_expr(
                        signal_expr(&iface_name(cell + 1, "viscous_flux_energy")),
                        signal_expr(&iface_name(cell, "viscous_flux_energy")),
                    ),
                ),
            ]),
        )?;

        mass_drift_terms.push(sub_expr(
            signal_expr(&density_name(&next)),
            signal_expr(&density_name(&current)),
        ));
        momentum_drift_terms.push(sub_expr(
            signal_expr(&momentum_name(&next)),
            signal_expr(&momentum_name(&current)),
        ));
        energy_drift_terms.push(sub_expr(
            signal_expr(&energy_name(&next)),
            signal_expr(&energy_name(&current)),
        ));
    }

    builder.add_assignment("mass_drift", add_expr(mass_drift_terms))?;
    builder.add_assignment("momentum_drift", add_expr(momentum_drift_terms))?;
    builder.add_assignment("energy_drift", add_expr(energy_drift_terms))?;
    append_poseidon_commitment(
        &mut builder,
        "__navier_stokes_step_commitment",
        &commitment_inputs,
        "step_commitment",
    )?;
    builder.build()
}

pub fn navier_stokes_structured_step_showcase_with_cells(
    cells: usize,
) -> ZkfResult<TemplateProgram> {
    let sample_request = sample_request(cells);
    let sample_inputs = navier_stokes_structured_step_inputs_from_request(&sample_request)?;
    let mut violation_request = sample_request.clone();
    violation_request.next_cells[1.min(cells - 1)].density = "2".to_string();
    let violation_inputs = navier_stokes_structured_step_inputs_from_request(&violation_request)?;
    Ok(TemplateProgram {
        program: build_navier_stokes_structured_step_program(cells)?,
        expected_inputs: navier_expected_inputs(cells),
        public_outputs: navier_public_outputs(),
        sample_inputs,
        violation_inputs,
        description: NAVIER_STOKES_DESCRIPTION,
    })
}

pub fn navier_stokes_structured_step_showcase() -> ZkfResult<TemplateProgram> {
    navier_stokes_structured_step_showcase_with_cells(NAVIER_STOKES_DEFAULT_CELLS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navier_surface_metadata_matches_cell_count() {
        let cells = 3;
        let template = navier_stokes_structured_step_showcase_with_cells(cells).expect("template");
        assert_eq!(
            template.program.metadata.get("cell_count"),
            Some(&cells.to_string())
        );
        assert_eq!(template.public_outputs.len(), NAVIER_STOKES_PUBLIC_OUTPUTS);
        assert_eq!(
            template.program.metadata.get("normalization_scale"),
            Some(&science_scale_string())
        );
    }

    #[test]
    fn navier_request_digest_is_stable() {
        let request = sample_request(3);
        assert_eq!(
            super::super::science::sha256_hex_json("navier-stokes", &request)
                .expect("digest")
                .len(),
            64
        );
    }
}
