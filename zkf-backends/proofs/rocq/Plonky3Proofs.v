Require Import BackendCompat.
Require Import Plonky3Semantics.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_plonky3_surface.

Theorem plonky3_lower_program_sound_ok :
  forall program lowered,
    lower_program program = Result_Ok lowered ->
    LoweredProgramAccepted program lowered.
Proof.
  intros program lowered Hlowered.
  exact Hlowered.
Qed.

Theorem plonky3_public_inputs_preserved_ok :
  forall program lowered,
    public_input_positions_preserved program lowered = Result_Ok true ->
    PublicInputsPreserved program lowered.
Proof.
  intros program lowered Hpreserved.
  exact Hpreserved.
Qed.

Theorem plonky3_lowering_witness_preservation_ok :
  forall lowered witness field row,
    build_trace_row lowered witness field = Result_Ok row ->
    LoweredProgramWellFormed lowered /\ TraceRowAccepted lowered witness field row.
Proof.
  intros lowered witness field row Hrow.
  unfold TraceRowAccepted.
  split.
  - unfold LoweredProgramWellFormed.
    unfold build_trace_row in Hrow.
    destruct (validate_lowered_program lowered) eqn:Hvalidate;
      try discriminate.
    destruct u.
    reflexivity.
  - exact Hrow.
Qed.
