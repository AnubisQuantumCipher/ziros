From Coq Require Import List String.
Import ListNotations.
Open Scope string_scope.

Inductive source_constraint :=
| SourceEqual : string -> string -> source_constraint
| SourceRange : string -> nat -> source_constraint
| SourceBoolean : string -> source_constraint.

Inductive zir_constraint :=
| ZirEqual : string -> string -> zir_constraint
| ZirRange : string -> nat -> zir_constraint
| ZirBoolean : string -> zir_constraint.

Definition lower_constraint (constraint : source_constraint) : zir_constraint :=
  match constraint with
  | SourceEqual lhs rhs => ZirEqual lhs rhs
  | SourceRange signal bits => ZirRange signal bits
  | SourceBoolean signal => ZirBoolean signal
  end.

Theorem zir_source_to_zir_preserves_equality_shape :
  forall lhs rhs,
    lower_constraint (SourceEqual lhs rhs) = ZirEqual lhs rhs.
Proof.
  reflexivity.
Qed.

Theorem zir_source_to_zir_preserves_range_shape :
  forall signal bits,
    lower_constraint (SourceRange signal bits) = ZirRange signal bits.
Proof.
  reflexivity.
Qed.

Theorem zir_source_to_zir_preserves_boolean_shape :
  forall signal,
    lower_constraint (SourceBoolean signal) = ZirBoolean signal.
Proof.
  reflexivity.
Qed.
