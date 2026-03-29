Require Import NoirRecheckSemantics.

Theorem noir_acir_recheck_wrapper_sound_ok :
  forall boundary,
    noir_acir_recheck_wrapper_surface boundary =
      SpecNoirRecheckStatus_Accepted ->
    NoirRecheckWrapperSound boundary.
Proof.
  intros [translated_constraints_valid acvm_witness_present] Hsurface.
  cbn in Hsurface.
  destruct translated_constraints_valid, acvm_witness_present; try discriminate;
    split; reflexivity.
Qed.
