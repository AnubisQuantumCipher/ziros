Require Import Bool.

Inductive t_SpecNoirRecheckStatus :=
| SpecNoirRecheckStatus_Accepted
| SpecNoirRecheckStatus_Rejected.

Record t_SpecNoirRecheckBoundary := {
  f_translated_constraints_valid : bool;
  f_acvm_witness_present : bool;
}.

Definition noir_acir_recheck_wrapper_surface
  (boundary : t_SpecNoirRecheckBoundary) : t_SpecNoirRecheckStatus :=
  if andb boundary.(f_translated_constraints_valid) boundary.(f_acvm_witness_present)
  then SpecNoirRecheckStatus_Accepted
  else SpecNoirRecheckStatus_Rejected.

Definition NoirRecheckWrapperSound
  (boundary : t_SpecNoirRecheckBoundary) : Prop :=
  boundary.(f_translated_constraints_valid) = true /\
  boundary.(f_acvm_witness_present) = true.
