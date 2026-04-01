#![allow(dead_code)]

use crate::arkworks::should_debug_check_constraint_system_mode;
use crate::audited_backend::build_audited_compiled_program;
use crate::blackbox_gadgets::lookup_lowering::{self, LookupLoweringShape};
use crate::wrapping::halo2_ipa_accumulator::{Halo2IpaBindingModel, halo2_ipa_binding_accepts};
use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystem, ConstraintSystemRef, LinearCombination, OptimizationGoal,
    SynthesisError, SynthesisMode, Variable, satisfaction_check_error_for_mode,
};
use zkf_core::ir::LookupTable;
use zkf_core::{BackendKind, FieldElement, FieldId, Program};

fn lookup_table_fixture() -> LookupTable {
    LookupTable {
        name: "table".to_string(),
        columns: vec!["selector".to_string(), "mapped".to_string()],
        values: vec![
            vec![FieldElement::from_i64(0), FieldElement::from_i64(5)],
            vec![FieldElement::from_i64(1), FieldElement::from_i64(9)],
        ],
    }
}

fn digest_mismatch_programs() -> (Program, Program) {
    (
        Program {
            name: "kani-backend-source".to_string(),
            field: FieldId::Bn254,
            ..Program::default()
        },
        Program {
            name: "kani-backend-compiled".to_string(),
            field: FieldId::Bn254,
            ..Program::default()
        },
    )
}

fn groth16_matrix_equivalence_fixture(mode: SynthesisMode) -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Weight);
    cs.set_mode(mode);

    let public = cs
        .new_input_variable(|| Ok(Fr::from(1u64)))
        .expect("fixture public input should allocate");
    let witness = cs
        .new_witness_variable(|| Ok(Fr::from(2u64)))
        .expect("fixture witness should allocate");
    let doubled = cs
        .new_witness_variable(|| Ok(Fr::from(2u64)))
        .expect("fixture doubled witness should allocate");

    let outlined_sum = cs
        .new_lc(LinearCombination::from(public) + witness)
        .expect("fixture symbolic lc 1 should allocate");
    cs.enforce_constraint(
        LinearCombination::from(outlined_sum),
        LinearCombination::from(Variable::One),
        LinearCombination::from(outlined_sum),
    )
    .expect("fixture constraint 1 should allocate");

    let matching_outlined_sum = cs
        .new_lc(LinearCombination::from(public) + doubled)
        .expect("fixture symbolic lc 2 should allocate");
    cs.enforce_constraint(
        LinearCombination::from(outlined_sum),
        LinearCombination::from(Variable::One),
        LinearCombination::from(matching_outlined_sum),
    )
    .expect("fixture constraint 2 should allocate");

    cs.enforce_constraint(
        LinearCombination::from(matching_outlined_sum),
        LinearCombination::from(Variable::One),
        LinearCombination::from(matching_outlined_sum),
    )
    .expect("fixture constraint 3 should allocate");

    cs.finalize();
    cs
}

fn collect_constraint_matrices_from_draining_rows(
    cs: &ConstraintSystemRef<Fr>,
) -> ConstraintMatrices<Fr> {
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();

    cs.for_each_expanded_row_draining::<(), _>(|_, a_row, b_row, c_row| {
        a.push(a_row.to_vec());
        b.push(b_row.to_vec());
        c.push(c_row.to_vec());
        Ok(())
    })
    .expect("draining-row expansion should succeed")
    .expect("draining-row expansion should stay enabled");

    ConstraintMatrices {
        num_instance_variables: cs.num_instance_variables(),
        num_witness_variables: cs.num_witness_variables(),
        num_constraints: cs.num_constraints(),
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        c_num_non_zero: c.iter().map(Vec::len).sum(),
        a,
        b,
        c,
    }
}

fn assert_groth16_matrix_paths_match(mode: SynthesisMode) {
    let cs = groth16_matrix_equivalence_fixture(mode);
    let materialized = cs
        .to_matrices()
        .expect("materialized matrices should be available");
    let streaming = cs
        .to_matrices_streaming()
        .expect("streaming matrices should be available");
    let draining = collect_constraint_matrices_from_draining_rows(&cs);

    assert_eq!(materialized, streaming);
    assert_eq!(materialized, draining);
    assert_eq!(streaming, draining);
}

#[kani::proof]
fn lookup_lowering_shape_matches_small_fixture() {
    let table = lookup_table_fixture();
    let shape = lookup_lowering::summarize_lookup_lowering_shape(1, 1, &table)
        .expect("lookup lowering summary should succeed");
    assert_eq!(
        shape,
        LookupLoweringShape {
            selector_count: 2,
            boolean_constraint_count: 2,
            equality_constraint_count: 3,
            output_binding_count: 1,
        }
    );
}

#[kani::proof]
fn audited_compiled_program_retains_original_on_digest_mismatch() {
    let (original, compiled_program) = digest_mismatch_programs();
    let compiled =
        build_audited_compiled_program(BackendKind::ArkworksGroth16, &original, compiled_program)
            .expect("audit-safe digest mismatch fixture should compile");
    assert!(compiled.original_program.is_some());
}

#[kani::proof]
fn cached_shape_debug_gate_stays_off_without_matrices() {
    let debug_build: bool = kani::any();
    let env_forced: bool = kani::any();
    let num_constraints: usize = kani::any();

    assert!(!should_debug_check_constraint_system_mode(
        debug_build,
        false,
        env_forced,
        num_constraints,
    ));
}

#[kani::proof]
fn matrix_free_satisfaction_check_is_rejected() {
    assert!(matches!(
        satisfaction_check_error_for_mode(SynthesisMode::Prove {
            construct_matrices: false,
        }),
        Some(SynthesisError::AssignmentMissing)
    ));
    assert!(matches!(
        satisfaction_check_error_for_mode(SynthesisMode::Setup),
        Some(SynthesisError::AssignmentMissing)
    ));
    assert!(matches!(
        satisfaction_check_error_for_mode(SynthesisMode::Prove {
            construct_matrices: true,
        }),
        None
    ));
}

#[kani::proof]
#[kani::unwind(16)]
fn groth16_materialized_matrices_match_streaming_rows_in_setup_mode() {
    assert_groth16_matrix_paths_match(SynthesisMode::Setup);
}

#[kani::proof]
#[kani::unwind(16)]
fn groth16_materialized_matrices_match_streaming_rows_in_prove_mode() {
    assert_groth16_matrix_paths_match(SynthesisMode::Prove {
        construct_matrices: true,
    });
}

#[kani::proof]
fn halo2_ipa_binding_accepts_complete_small_batches() {
    let proof_count: u8 = kani::any();
    kani::assume(proof_count > 0);
    kani::assume(proof_count <= 4);

    let model = Halo2IpaBindingModel {
        proof_count: usize::from(proof_count),
        proof_hash_count: usize::from(proof_count),
        bound_g_point_count: usize::from(proof_count),
        malformed_g_point_count: 0,
    };

    assert!(halo2_ipa_binding_accepts(model));
}

#[kani::proof]
fn halo2_ipa_binding_rejects_missing_hashes_points_or_malformed_entries() {
    let proof_count: u8 = kani::any();
    kani::assume(proof_count <= 4);

    let missing_hashes: bool = kani::any();
    let missing_points: bool = kani::any();
    let malformed_points: bool = kani::any();
    kani::assume(proof_count == 0 || missing_hashes || missing_points || malformed_points);

    let proof_hash_count = if proof_count == 0 {
        0
    } else if missing_hashes {
        usize::from(proof_count.saturating_sub(1))
    } else {
        usize::from(proof_count)
    };
    let bound_g_point_count = if proof_count == 0 {
        0
    } else if missing_points {
        usize::from(proof_count.saturating_sub(1))
    } else {
        usize::from(proof_count)
    };
    let malformed_g_point_count = usize::from(malformed_points);

    let model = Halo2IpaBindingModel {
        proof_count: usize::from(proof_count),
        proof_hash_count,
        bound_g_point_count,
        malformed_g_point_count,
    };

    assert!(!halo2_ipa_binding_accepts(model));
}
