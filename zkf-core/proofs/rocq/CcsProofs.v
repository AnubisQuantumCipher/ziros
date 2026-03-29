Require Import List.
Require Import NArith.
Import List.ListNotations.

Require Import KernelCompat.
Require Import CcsSemantics.
From ZkfCoreExtraction Require Import Zkf_core_Proof_ccs_spec.

Lemma encode_constraint_runtime_success_supported :
  forall builder constraint constraint_index next_builder,
    encode_constraint_runtime builder constraint constraint_index =
      (next_builder, Result_Ok tt) ->
    ConstraintSupported constraint.
Proof.
  intros builder constraint constraint_index next_builder Hencode.
  destruct constraint.
  - exact I.
  - exact I.
  - exact I.
  - cbn in Hencode.
    discriminate Hencode.
  - destruct (SpecCcsConstraint_BlackBox_f_kind s) eqn:Hkind.
    + unfold ConstraintSupported.
      rewrite Hkind.
      exact I.
    + cbn in Hencode.
      rewrite Hkind in Hencode.
      discriminate Hencode.
Qed.

Theorem synthesize_constraints_from_success_supported :
  forall builder constraints constraint_index synthesized_builder,
    synthesize_constraints_from builder constraints constraint_index =
      Result_Ok synthesized_builder ->
    Forall ConstraintSupported constraints.
Proof.
  intros builder constraints constraint_index synthesized_builder Hsynthesize.
  revert builder constraint_index synthesized_builder Hsynthesize.
  induction constraints as [|constraint remaining_constraints IH];
    intros initial_builder constraint_index synthesized_builder Hsynthesize.
  - cbn in Hsynthesize.
    constructor.
  - cbn in Hsynthesize.
    destruct (encode_constraint_runtime initial_builder constraint constraint_index)
      as [next_builder encode_result] eqn:Hencode;
      destruct encode_result as [()|encode_error];
      try discriminate.
    constructor.
    + eapply encode_constraint_runtime_success_supported.
      exact Hencode.
    + eapply IH.
      exact Hsynthesize.
Qed.

Theorem synthesize_ccs_program_fail_closed_ok :
  forall program ccs_program,
    synthesize_ccs_program program = Result_Ok ccs_program ->
    ProgramSupported program.
Proof.
  intros program ccs_program Hsynthesize.
  unfold synthesize_ccs_program in Hsynthesize.
  destruct
    (synthesize_constraints_from
      (builder_new program)
      (SpecCcsConstraintProgram_f_constraints program)
      0%N) as [builder|error] eqn:Hconstraints.
  - cbn in Hsynthesize.
    inversion Hsynthesize; subst.
    exact
      (synthesize_constraints_from_success_supported
        (builder_new program)
        (SpecCcsConstraintProgram_f_constraints program)
        0%N
        builder
        Hconstraints).
  - cbn in Hsynthesize.
    rewrite Hconstraints in Hsynthesize.
    discriminate Hsynthesize.
Qed.

Lemma builder_finish_canonical_shape_ok :
  forall builder field,
    CanonicalCcsShape (builder_finish builder field).
Proof.
  intros builder field.
  unfold CanonicalCcsShape, canonical_multisets, MatrixDimensionsMatchProgram.
  simpl.
  split.
  - reflexivity.
  - split.
    + constructor.
      * split; reflexivity.
      * constructor.
        -- split; reflexivity.
        -- constructor.
           ++ split; reflexivity.
           ++ constructor.
    + reflexivity.
Qed.

Theorem synthesize_ccs_program_supported_shape_ok :
  forall program ccs_program,
    synthesize_ccs_program program = Result_Ok ccs_program ->
    CanonicalCcsShape ccs_program.
Proof.
  intros program ccs_program Hsynthesize.
  unfold synthesize_ccs_program in Hsynthesize.
  destruct
    (synthesize_constraints_from
      (builder_new program)
      (SpecCcsConstraintProgram_f_constraints program)
      0%N) as [builder|error] eqn:Hconstraints.
  - cbn in Hsynthesize.
    rewrite Hconstraints in Hsynthesize.
    inversion Hsynthesize; subst.
    eapply builder_finish_canonical_shape_ok.
  - cbn in Hsynthesize.
    rewrite Hconstraints in Hsynthesize.
    discriminate Hsynthesize.
Qed.

Theorem synthesize_ccs_program_supported_conversion_ok :
  forall program ccs_program,
    synthesize_ccs_program program = Result_Ok ccs_program ->
    ProgramSupported program /\ CanonicalCcsShape ccs_program.
Proof.
  intros program ccs_program Hsynthesize.
  split.
  - eapply synthesize_ccs_program_fail_closed_ok.
    exact Hsynthesize.
  - eapply synthesize_ccs_program_supported_shape_ok.
    exact Hsynthesize.
Qed.
