From Stdlib Require Import ZArith Lia.

Open Scope Z_scope.

Definition is_boolean (x : Z) : Prop := x = 0 \/ x = 1.

Definition fits_bits (bits x : Z) : Prop := 0 <= x < 2 ^ bits.

Lemma boolean_fits_one_bit : forall x, is_boolean x -> fits_bits 1 x.
Proof.
  intros x Hbool.
  unfold is_boolean in Hbool.
  unfold fits_bits.
  destruct Hbool as [-> | ->];
    split; simpl; lia.
Qed.

Lemma fits_bits_monotone :
  forall x small large,
    0 <= small <= large ->
    fits_bits small x ->
    fits_bits large x.
Proof.
  intros x small large Hbounds [Hx_nonneg Hx_lt].
  unfold fits_bits.
  split.
  - exact Hx_nonneg.
  - apply Z.lt_le_trans with (m := 2 ^ small).
    + exact Hx_lt.
    + apply Z.pow_le_mono_r; lia.
Qed.
