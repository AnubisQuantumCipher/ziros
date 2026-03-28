Require Import Bool.
Require Import NArith.

Require Import KernelCompat.
Require Import KernelGenerated.
Require Import KernelSemantics.
Require Import PipelineComposition.
From ZkfCoreExtraction Require Import Zkf_core_Proof_transform_spec.
From ZkfLibExtraction Require Import Zkf_lib_Proof_embedded_app_spec.

Definition proof_embedded_field_of_core_field (field : t_FieldId) : t_ProofEmbeddedFieldId :=
  match field with
  | FieldId_Bn254 => ProofEmbeddedFieldId_Bn254
  | FieldId_Bls12_381_ => ProofEmbeddedFieldId_Bls12_381_
  | FieldId_PastaFp => ProofEmbeddedFieldId_PastaFp
  | FieldId_PastaFq => ProofEmbeddedFieldId_PastaFq
  | FieldId_Goldilocks => ProofEmbeddedFieldId_Goldilocks
  | FieldId_BabyBear => ProofEmbeddedFieldId_BabyBear
  | FieldId_Mersenne31 => ProofEmbeddedFieldId_Mersenne31
  end.

Theorem canonical_input_key_string_resolves_alias_ok :
  forall requested alias_target,
    canonical_input_key_string requested alias_target =
      match alias_target with
      | Option_Some target => target
      | Option_None => requested
      end.
Proof.
  intros requested alias_target.
  destruct alias_target; reflexivity.
Qed.

Theorem program_digest_guard_accepts_only_matching_digests_ok :
  forall expected found,
    program_digest_guard_accepts expected found = true ->
    expected = found.
Proof.
  intros expected found Hmatch.
  apply String.eqb_eq.
  exact Hmatch.
Qed.

Theorem program_digest_guard_rejects_mismatch_ok :
  forall expected found,
    expected <> found ->
    program_digest_guard_accepts expected found = false.
Proof.
  intros expected found Hmismatch.
  destruct (program_digest_guard_accepts expected found) eqn:Hguard.
  - exfalso.
    apply Hmismatch.
    eapply program_digest_guard_accepts_only_matching_digests_ok.
    exact Hguard.
  - reflexivity.
Qed.

Theorem program_mismatch_fields_preserve_expected_and_found_ok :
  forall expected found,
    ProgramMismatchFields_f_expected (program_mismatch_fields expected found) = expected /\
    ProgramMismatchFields_f_found (program_mismatch_fields expected found) = found.
Proof.
  intros expected found.
  split; reflexivity.
Qed.

Theorem default_backend_for_proof_field_spec_total_ok :
  forall field,
    default_backend_for_proof_field_spec field =
      match field with
      | ProofEmbeddedFieldId_Bn254 => ProofEmbeddedBackendKind_ArkworksGroth16
      | ProofEmbeddedFieldId_Bls12_381_ => ProofEmbeddedBackendKind_Halo2Bls12381
      | ProofEmbeddedFieldId_PastaFp
      | ProofEmbeddedFieldId_PastaFq => ProofEmbeddedBackendKind_Halo2
      | ProofEmbeddedFieldId_Goldilocks
      | ProofEmbeddedFieldId_BabyBear
      | ProofEmbeddedFieldId_Mersenne31 => ProofEmbeddedBackendKind_Plonky3
      end.
Proof.
  intros field.
  destruct field; reflexivity.
Qed.

Theorem digest_bytes_match_accepts_only_equal_bytes_ok :
  forall expected found,
    digest_bytes_match expected found = true ->
    expected = found.
Proof.
  intros expected.
  induction expected as [|expected_head expected_tail IH];
    intros found Hmatch;
    destruct found as [|found_head found_tail];
    simpl in Hmatch.
  - reflexivity.
  - discriminate Hmatch.
  - discriminate Hmatch.
  - apply andb_true_iff in Hmatch as [Hhead Htail].
    apply N.eqb_eq in Hhead.
    destruct expected_head as [expected_head_raw].
    destruct found_head as [found_head_raw].
    destruct expected_head_raw as [expected_head_bits].
    destruct found_head_raw as [found_head_bits].
    simpl in Hhead.
    subst found_head_bits.
    specialize (IH found_tail Htail).
    subst found_tail.
    reflexivity.
Qed.

Theorem private_identity_merkle_direction_binary_guard_ok :
  forall direction,
    private_identity_merkle_direction_is_binary direction =
      orb
        (N.eqb (U8_f_v (u8_0 direction)) 0%N)
        (N.eqb (U8_f_v (u8_0 direction)) 1%N).
Proof.
  intros direction.
  reflexivity.
Qed.

Theorem private_identity_public_input_arity_guard_ok :
  forall len,
    private_identity_public_input_arity_is_expected len =
      f_eq len (private_identity_expected_public_input_arity tt).
Proof.
  intros len.
  reflexivity.
Qed.

Theorem embedded_default_path_composition_ok :
  forall program witness requested alias_target expected found,
    transform_check_program program witness = Result_Ok tt ->
    canonical_input_key_string requested alias_target =
      match alias_target with
      | Option_Some target => target
      | Option_None => requested
      end /\
    (digest_bytes_match expected found = true -> expected = found) /\
    default_backend_for_proof_field_spec
      (proof_embedded_field_of_core_field (SpecTransformProgram_f_field program)) =
      match proof_embedded_field_of_core_field (SpecTransformProgram_f_field program) with
      | ProofEmbeddedFieldId_Bn254 => ProofEmbeddedBackendKind_ArkworksGroth16
      | ProofEmbeddedFieldId_Bls12_381_ => ProofEmbeddedBackendKind_Halo2Bls12381
      | ProofEmbeddedFieldId_PastaFp
      | ProofEmbeddedFieldId_PastaFq => ProofEmbeddedBackendKind_Halo2
      | ProofEmbeddedFieldId_Goldilocks
      | ProofEmbeddedFieldId_BabyBear
      | ProofEmbeddedFieldId_Mersenne31 => ProofEmbeddedBackendKind_Plonky3
      end /\
    ProgramHolds
      (transform_program_to_kernel
        (optimize_zir_program_output (normalize_program_output program)))
      witness.
Proof.
  intros program witness requested alias_target expected found Hcheck.
  split.
  - apply canonical_input_key_string_resolves_alias_ok.
  - split.
    + apply digest_bytes_match_accepts_only_equal_bytes_ok.
    + split.
      * destruct program as [field signals constraints assignments hints].
        simpl.
        apply default_backend_for_proof_field_spec_total_ok.
      * eapply embedded_default_pipeline_to_kernel_sound_ok.
        exact Hcheck.
Qed.
