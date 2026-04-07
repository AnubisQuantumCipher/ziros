#![allow(dead_code)]

/// Shipped proof-core summary of the Groth16 debug-gate and matrix-surface
/// behavior that the Verus boundary proof binds.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16SynthesisModeModel {
    Setup,
    Prove { construct_matrices: bool },
}

#[cfg_attr(hax, hax_lib::include)]
pub fn should_debug_check_constraint_system_mode_model(
    debug_build: bool,
    construct_matrices: bool,
    env_forced: bool,
    num_constraints: usize,
) -> bool {
    debug_build && construct_matrices && (env_forced || num_constraints <= 50_000)
}

#[cfg_attr(hax, hax_lib::include)]
pub fn matrix_free_satisfaction_check_rejected(mode: Groth16SynthesisModeModel) -> bool {
    match mode {
        Groth16SynthesisModeModel::Setup => true,
        Groth16SynthesisModeModel::Prove { construct_matrices } => !construct_matrices,
    }
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixTermModel {
    pub variable: usize,
    pub coeff_bytes: Vec<u8>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRowModel {
    pub a: Vec<MatrixTermModel>,
    pub b: Vec<MatrixTermModel>,
    pub c: Vec<MatrixTermModel>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintMatricesModel {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub rows: Vec<MatrixRowModel>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16OutlinedLcModel {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub expanded_rows: Vec<MatrixRowModel>,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn materialized_matrices(model: &Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows.clone(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn streaming_matrices(model: &Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows.clone(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn draining_matrices(model: &Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows.clone(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn groth16_matrix_surfaces_equivalent(model: &Groth16OutlinedLcModel) -> bool {
    let materialized = materialized_matrices(model);
    let streaming = streaming_matrices(model);
    let draining = draining_matrices(model);
    materialized == streaming && materialized == draining && streaming == draining
}

#[cfg(test)]
mod tests {
    use super::{
        Groth16OutlinedLcModel, Groth16SynthesisModeModel, MatrixRowModel, MatrixTermModel,
        groth16_matrix_surfaces_equivalent, matrix_free_satisfaction_check_rejected,
        should_debug_check_constraint_system_mode_model,
    };

    #[test]
    fn debug_gate_depends_on_matrix_construction() {
        assert!(!should_debug_check_constraint_system_mode_model(
            true, false, true, 1_000
        ));
        assert!(should_debug_check_constraint_system_mode_model(
            true, true, true, 1_000
        ));
    }

    #[test]
    fn matrix_free_modes_fail_closed() {
        assert!(matrix_free_satisfaction_check_rejected(
            Groth16SynthesisModeModel::Setup
        ));
        assert!(matrix_free_satisfaction_check_rejected(
            Groth16SynthesisModeModel::Prove {
                construct_matrices: false
            }
        ));
        assert!(!matrix_free_satisfaction_check_rejected(
            Groth16SynthesisModeModel::Prove {
                construct_matrices: true
            }
        ));
    }

    #[test]
    fn matrix_surface_equivalence_is_exact_for_shared_rows() {
        let row = MatrixRowModel {
            a: vec![MatrixTermModel {
                variable: 0,
                coeff_bytes: vec![1],
            }],
            b: vec![MatrixTermModel {
                variable: 1,
                coeff_bytes: vec![2],
            }],
            c: vec![MatrixTermModel {
                variable: 2,
                coeff_bytes: vec![3],
            }],
        };
        let model = Groth16OutlinedLcModel {
            num_instance_variables: 2,
            num_witness_variables: 2,
            expanded_rows: vec![row],
        };
        assert!(groth16_matrix_surfaces_equivalent(&model));
    }
}
