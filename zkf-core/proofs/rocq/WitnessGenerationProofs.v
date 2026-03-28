Require Import KernelCompat.
Require Import KernelGenerated.
Require Import WitnessGenerationSemantics.
From ZkfCoreExtraction Require Import Zkf_core_Proof_witness_generation_spec.

Lemma validate_generated_witness_sound_ok :
  forall program witness validated_witness,
    validate_generated_witness program witness = Result_Ok validated_witness ->
    validated_witness = witness /\
    GeneratedWitnessAccepted program witness.
Proof.
  intros program witness validated_witness Hvalidate.
  unfold validate_generated_witness in Hvalidate.
  destruct (check_program (f_kernel_program program) witness) eqn:Hcheck;
    try discriminate.
  destruct u.
  simpl in Hvalidate.
  inversion Hvalidate; subst.
  split.
  - reflexivity.
  - exact Hcheck.
Qed.

Theorem generate_non_blackbox_witness_sound_ok :
  forall program inputs witness,
    generate_non_blackbox_witness program inputs = Result_Ok witness ->
    GeneratedWitnessAccepted program witness.
Proof.
  intros program inputs witness Hgenerate.
  unfold generate_non_blackbox_witness in Hgenerate.
  destruct (generate_non_blackbox_witness_unchecked program inputs) eqn:Hunchecked;
    try discriminate.
  destruct (validate_generated_witness_sound_ok program s witness Hgenerate)
    as [Hwitness Haccepted].
  subst.
  exact Haccepted.
Qed.
