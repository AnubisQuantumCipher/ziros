Require Import BackendCompat.
Require Import LookupLoweringSemantics.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_lookup_lowering_spec.

Theorem lookup_lowering_witness_preservation_ok :
  forall input_count output_count table_rows table_columns surface,
    supported_lookup_lowering_surface
      input_count
      output_count
      table_rows
      table_columns = Option_Some surface ->
    LookupLoweringWitnessPreservation
      input_count
      output_count
      table_rows
      table_columns
      surface.
Proof.
  intros input_count output_count table_rows table_columns surface Hsurface.
  unfold supported_lookup_lowering_surface in Hsurface.
  destruct
    (lookup_lowering_surface_supported input_count table_rows table_columns) eqn:Hsupported;
    try discriminate.
  inversion Hsurface; subst.
  unfold LookupLoweringWitnessPreservation.
  repeat split; reflexivity.
Qed.
