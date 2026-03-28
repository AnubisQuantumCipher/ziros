From Stdlib Require Import ZArith Lia.

Open Scope Z_scope.

Theorem normalization_add_zero : forall x : Z, 0 + x = x.
Proof.
  intros x.
  lia.
Qed.
