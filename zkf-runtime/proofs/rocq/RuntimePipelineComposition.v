Require Import Bool.

Require Import KernelCompat.
Require Import KernelGenerated.
Require Import KernelSemantics.
Require Import PipelineComposition.
From ZkfCoreExtraction Require Import Zkf_core_Proof_transform_spec.
From ZkfRuntimeExtraction Require Import Zkf_runtime_Proof_runtime_spec.

Definition proof_runtime_field_of_core_field (field : t_FieldId) : t_ProofRuntimeFieldId :=
  match field with
  | FieldId_Bn254 => ProofRuntimeFieldId_Bn254
  | FieldId_Bls12_381_ => ProofRuntimeFieldId_Bls12_381_
  | FieldId_PastaFp => ProofRuntimeFieldId_PastaFp
  | FieldId_PastaFq => ProofRuntimeFieldId_PastaFq
  | FieldId_Goldilocks => ProofRuntimeFieldId_Goldilocks
  | FieldId_BabyBear => ProofRuntimeFieldId_BabyBear
  | FieldId_Mersenne31 => ProofRuntimeFieldId_Mersenne31
  end.

Theorem runtime_default_backend_candidates_are_nonempty_ok :
  forall field,
    runtime_default_backend_candidates_are_nonempty field = true.
Proof.
  intros field.
  destruct field;
    reflexivity.
Qed.

Theorem cli_runtime_path_composition_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    runtime_default_backend_candidates_are_nonempty
      (proof_runtime_field_of_core_field (SpecTransformProgram_f_field program)) = true /\
    ProgramHolds
      (transform_program_to_kernel
        (optimize_ir_program_output (normalize_program_output program)))
      witness.
Proof.
  intros program witness Hcheck.
  split.
  - destruct program as [field signals constraints assignments hints].
    simpl.
    apply runtime_default_backend_candidates_are_nonempty_ok.
  - eapply cli_runtime_pipeline_to_kernel_sound_ok.
    exact Hcheck.
Qed.

Theorem hybrid_verify_decision_is_logical_and_ok :
  forall primary_ok companion_ok,
    hybrid_verify_decision_spec primary_ok companion_ok =
      andb primary_ok companion_ok.
Proof.
  intros primary_ok companion_ok.
  reflexivity.
Qed.

Theorem digest_matches_recorded_hash_spec_rejects_missing_or_explicit_mismatch_ok :
  forall recorded expected,
    (recorded = Option_None \/
      exists value,
        recorded = Option_Some value /\ runtime_digest_bytes_match value expected = false) ->
    digest_matches_recorded_hash_spec recorded expected = false.
Proof.
  intros recorded expected [Hnone | [value [Hsome Hneq]]].
  - subst recorded.
    reflexivity.
  - subst recorded.
    simpl.
    rewrite Hneq.
    reflexivity.
Qed.

Theorem hardware_probes_clean_spec_rejects_unhealthy_or_mismatched_ok :
  forall summary,
    (f_ok summary = false \/
      f_mismatch_free summary = false) ->
    hardware_probes_clean_spec summary = false.
Proof.
  intros [ok mismatch_free] [Hok | Hmismatch];
    simpl in *.
  - rewrite Hok.
    reflexivity.
  - destruct ok;
      simpl;
      rewrite Hmismatch;
      reflexivity.
Qed.

Theorem hybrid_primary_leg_byte_components_match_spec_rejects_component_divergence_ok :
  forall artifact_proof artifact_vk primary_proof primary_vk,
    (runtime_digest_bytes_match artifact_proof primary_proof = false \/
      runtime_digest_bytes_match artifact_vk primary_vk = false) ->
    hybrid_primary_leg_byte_components_match_spec
      artifact_proof artifact_vk primary_proof primary_vk = false.
Proof.
  intros artifact_proof artifact_vk primary_proof primary_vk [Hproof | Hvk].
  - unfold hybrid_primary_leg_byte_components_match_spec.
    change
      (andb
        (runtime_digest_bytes_match artifact_proof primary_proof)
        (runtime_digest_bytes_match artifact_vk primary_vk) = false).
    replace (runtime_digest_bytes_match artifact_proof primary_proof) with false by
      (symmetry; exact Hproof).
    reflexivity.
  - unfold hybrid_primary_leg_byte_components_match_spec.
    change
      (andb
        (runtime_digest_bytes_match artifact_proof primary_proof)
        (runtime_digest_bytes_match artifact_vk primary_vk) = false).
    replace (runtime_digest_bytes_match artifact_vk primary_vk) with false by
      (symmetry; exact Hvk).
    destruct (runtime_digest_bytes_match artifact_proof primary_proof);
      reflexivity.
Qed.

Theorem replay_manifest_identity_is_deterministic_spec_ok :
  forall manifest,
    replay_manifest_identity_is_deterministic_spec manifest = true.
Proof.
  intros manifest.
  reflexivity.
Qed.
