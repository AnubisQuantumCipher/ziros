Require Import BackendCompat.
Require Import BlackboxHashSemantics.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_hash_spec.

Theorem poseidon_bn254_width4_lowering_sound_ok :
  forall semantics,
    critical_hash_lowering_semantics
      SpecCriticalHashBlackBoxOp_Poseidon
      SpecCriticalHashFieldId_Bn254
      usize_4
      usize_4 = Option_Some semantics ->
    PoseidonBn254Width4LoweringSemantics semantics.
Proof.
  intros semantics Hsemantics.
  unfold critical_hash_lowering_semantics in Hsemantics.
  cbn in Hsemantics.
  inversion Hsemantics; subst.
  repeat split; reflexivity.
Qed.

Theorem poseidon_bn254_width4_aux_witness_sound_ok :
  forall semantics,
    critical_hash_lowering_semantics
      SpecCriticalHashBlackBoxOp_Poseidon
      SpecCriticalHashFieldId_Bn254
      usize_4
      usize_4 = Option_Some semantics ->
    f_aux_witness_mode semantics = CriticalHashAuxWitnessMode_ConstraintSolverDerived.
Proof.
  intros semantics Hsemantics.
  eapply poseidon_bn254_width4_lowering_sound_ok in Hsemantics.
  destruct Hsemantics as [_ [_ [_ Haux]]].
  exact Haux.
Qed.

Theorem sha256_bytes_to_digest_lowering_sound_ok :
  forall field inputs_len semantics,
    critical_hash_lowering_semantics
      SpecCriticalHashBlackBoxOp_Sha256
      field
      inputs_len
      usize_32 = Option_Some semantics ->
    Sha256BytesToDigestLoweringSemantics inputs_len semantics.
Proof.
  intros field inputs_len semantics Hsemantics.
  unfold critical_hash_lowering_semantics in Hsemantics.
  destruct (critical_hash_proof_surface
    SpecCriticalHashBlackBoxOp_Sha256
    field
    inputs_len
    usize_32) eqn:Hsurface;
    try discriminate.
  unfold critical_hash_proof_surface in Hsurface.
  cbn in Hsurface.
  inversion Hsurface; subst.
  cbn in Hsemantics.
  inversion Hsemantics; subst.
  repeat split; reflexivity.
Qed.

Theorem sha256_bytes_to_digest_aux_witness_sound_ok :
  forall field inputs_len semantics,
    critical_hash_lowering_semantics
      SpecCriticalHashBlackBoxOp_Sha256
      field
      inputs_len
      usize_32 = Option_Some semantics ->
    f_aux_witness_mode semantics = CriticalHashAuxWitnessMode_ConstraintSolverDerived.
Proof.
  intros field inputs_len semantics Hsemantics.
  eapply sha256_bytes_to_digest_lowering_sound_ok in Hsemantics.
  destruct Hsemantics as [_ [_ [_ Haux]]].
  exact Haux.
Qed.
