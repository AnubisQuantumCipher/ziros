From Coq Require Import Bool String.
Open Scope string_scope.

Inductive visibility :=
| Public
| Private.

Record symbol := {
  visibility_of : visibility;
  assigned : bool
}.

Definition can_expose (s : symbol) : bool :=
  match visibility_of s with
  | Public => true
  | Private => assigned s
  end.

Theorem private_unassigned_input_cannot_be_exposed :
  forall s,
    visibility_of s = Private ->
    assigned s = false ->
    can_expose s = false.
Proof.
  intros s Hvisibility Hassigned.
  unfold can_expose.
  rewrite Hvisibility.
  exact Hassigned.
Qed.

Theorem public_symbol_can_be_exposed :
  forall s,
    visibility_of s = Public ->
    can_expose s = true.
Proof.
  intros s Hvisibility.
  unfold can_expose.
  rewrite Hvisibility.
  reflexivity.
Qed.
