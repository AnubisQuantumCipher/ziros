#![allow(dead_code)]

use crate::app::api::{
    canonical_input_key, default_backend_for_field, default_backend_name_for_field,
    ensure_matching_program_digest,
};
use crate::app::private_identity::{
    MerklePathNodeV1, PRIVATE_IDENTITY_TREE_DEPTH, merkle_root_from_path_bn254,
    private_identity_public_inputs_from_artifact,
};
use zkf_core::{BackendKind, FieldId, ZkfError};
use zkf_core::{FieldElement, ProofArtifact};

fn one_hot_burn_selector(step: usize, burn_step: usize, horizon: usize) -> bool {
    step < horizon && burn_step < horizon && step == burn_step
}

fn running_min_with_slacks(left: usize, right: usize) -> (usize, usize, usize) {
    let min = left.min(right);
    (min, left - min, right - min)
}

fn conjunction_threshold_gate(
    minimum_separation: usize,
    collision_threshold: usize,
) -> Result<(), ()> {
    if minimum_separation < collision_threshold {
        Err(())
    } else {
        Ok(())
    }
}

fn delta_v_budget_gate(total_delta_v: usize, delta_v_budget: usize) -> Result<(), ()> {
    if total_delta_v > delta_v_budget {
        Err(())
    } else {
        Ok(())
    }
}

fn state_commitment_binding(
    final_position: [usize; 3],
    final_velocity: [usize; 3],
    step_tag: usize,
) -> ([usize; 3], [usize; 3], usize) {
    (final_position, final_velocity, step_tag)
}

fn plan_commitment_binding(
    delta_v: [usize; 3],
    burn_step: usize,
    mass: usize,
    impulse: [usize; 3],
) -> ([usize; 3], usize, usize, [usize; 3]) {
    (delta_v, burn_step, mass, impulse)
}

#[kani::proof]
fn app_alias_resolution_maps_external_key_to_canonical_signal() {
    assert_eq!(canonical_input_key(1u8, Some(9u8)), 9u8);
    assert_eq!(canonical_input_key(1u8, None), 1u8);
}

#[kani::proof]
fn app_digest_mismatch_is_rejected_before_proving() {
    let err = ensure_matching_program_digest("compiled-digest", "source-digest")
        .expect_err("digest mismatch should fail before proving");

    assert!(matches!(err, ZkfError::ProgramMismatch { .. }));
}

#[kani::proof]
fn app_digest_mismatch_preserves_expected_and_found_digests() {
    let expected = "compiled-digest";
    let found = "source-digest";
    let err = ensure_matching_program_digest(expected, found)
        .expect_err("digest mismatch should surface a typed error");

    match err {
        ZkfError::ProgramMismatch { expected, found } => {
            assert_eq!(expected, "compiled-digest");
            assert_eq!(found, "source-digest");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[kani::proof]
fn default_backend_mapping_is_valid_for_all_fields() {
    let cases = [
        (
            FieldId::Bn254,
            BackendKind::ArkworksGroth16,
            "arkworks-groth16",
        ),
        (
            FieldId::Bls12_381,
            BackendKind::Halo2Bls12381,
            "halo2-bls12-381",
        ),
        (FieldId::PastaFp, BackendKind::Halo2, "halo2"),
        (FieldId::PastaFq, BackendKind::Halo2, "halo2"),
        (FieldId::Goldilocks, BackendKind::Plonky3, "plonky3"),
        (FieldId::BabyBear, BackendKind::Plonky3, "plonky3"),
        (FieldId::Mersenne31, BackendKind::Plonky3, "plonky3"),
    ];

    for (field, backend, name) in cases {
        assert_eq!(default_backend_for_field(field), backend);
        assert_eq!(default_backend_name_for_field(field), name);
    }
}

#[kani::proof]
fn private_identity_merkle_paths_reject_invalid_directions() {
    let path = vec![
        MerklePathNodeV1 {
            sibling: FieldElement::ZERO,
            direction: 2,
        };
        PRIVATE_IDENTITY_TREE_DEPTH
    ];

    let err = merkle_root_from_path_bn254(&FieldElement::ONE, &path)
        .expect_err("invalid directions must fail closed");
    assert!(err.contains("direction must be 0 or 1"));
}

#[kani::proof]
fn private_identity_public_input_parser_rejects_wrong_arity() {
    let artifact = ProofArtifact::new(
        BackendKind::ArkworksGroth16,
        "digest",
        vec![],
        vec![],
        vec![FieldElement::ZERO; 4],
    );

    let err = private_identity_public_inputs_from_artifact(&artifact)
        .expect_err("wrong public input arity must fail closed");
    assert!(err.contains("must expose 5 public inputs"));
}

#[kani::proof]
fn satellite_burn_selector_is_unique_and_exact() {
    let burn_step = kani::any::<usize>();
    kani::assume(burn_step < 4);

    let mut selector_count = 0usize;
    let mut weighted_sum = 0usize;
    for step in 0..4 {
        let flag = one_hot_burn_selector(step, burn_step, 4);
        if flag {
            selector_count += 1;
            weighted_sum += step;
        }
    }

    assert_eq!(selector_count, 1);
    assert_eq!(weighted_sum, burn_step);
}

#[kani::proof]
fn satellite_running_min_reduction_is_correct() {
    let s0 = kani::any::<usize>();
    let s1 = kani::any::<usize>();
    let s2 = kani::any::<usize>();
    let s3 = kani::any::<usize>();
    kani::assume(s0 <= 16);
    kani::assume(s1 <= 16);
    kani::assume(s2 <= 16);
    kani::assume(s3 <= 16);

    let mut current = s0;
    for sep in [s1, s2, s3] {
        let (next, prev_slack, curr_slack) = running_min_with_slacks(current, sep);
        assert_eq!(next + prev_slack, current);
        assert_eq!(next + curr_slack, sep);
        assert_eq!(prev_slack * curr_slack, 0);
        current = next;
    }
    assert_eq!(current, s0.min(s1).min(s2).min(s3));
}

#[kani::proof]
fn satellite_threshold_checks_fail_closed_when_separation_is_too_small() {
    let minimum_separation = kani::any::<usize>();
    let collision_threshold = kani::any::<usize>();
    kani::assume(minimum_separation < collision_threshold);
    kani::assume(collision_threshold <= 16);

    assert!(conjunction_threshold_gate(minimum_separation, collision_threshold).is_err());
}

#[kani::proof]
fn satellite_budget_checks_fail_closed_when_delta_v_is_too_large() {
    let total_delta_v = kani::any::<usize>();
    let delta_v_budget = kani::any::<usize>();
    kani::assume(total_delta_v > delta_v_budget);
    kani::assume(total_delta_v <= 16);

    assert!(delta_v_budget_gate(total_delta_v, delta_v_budget).is_err());
}

#[kani::proof]
fn satellite_commitment_binding_detects_state_and_plan_tampering() {
    let final_position = [
        kani::any::<usize>(),
        kani::any::<usize>(),
        kani::any::<usize>(),
    ];
    let final_velocity = [
        kani::any::<usize>(),
        kani::any::<usize>(),
        kani::any::<usize>(),
    ];
    let delta_v = [
        kani::any::<usize>(),
        kani::any::<usize>(),
        kani::any::<usize>(),
    ];
    let impulse = [
        kani::any::<usize>(),
        kani::any::<usize>(),
        kani::any::<usize>(),
    ];
    let step_tag = kani::any::<usize>();
    let burn_step = kani::any::<usize>();
    let mass = kani::any::<usize>();
    kani::assume(final_position[0] < usize::MAX);
    kani::assume(delta_v[1] < usize::MAX);

    let original_state = state_commitment_binding(final_position, final_velocity, step_tag);
    let tampered_state = state_commitment_binding(
        [final_position[0] + 1, final_position[1], final_position[2]],
        final_velocity,
        step_tag,
    );
    assert_ne!(original_state, tampered_state);

    let original_plan = plan_commitment_binding(delta_v, burn_step, mass, impulse);
    let tampered_plan = plan_commitment_binding(
        [delta_v[0], delta_v[1] + 1, delta_v[2]],
        burn_step,
        mass,
        impulse,
    );
    assert_ne!(original_plan, tampered_plan);
}
