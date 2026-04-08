From Stdlib Require Import ZArith Lia.
Open Scope Z_scope.

Definition deductible_adjusted (covered deductible : Z) : Z :=
  Z.max 0 (covered - deductible).

Definition capped_payout (covered deductible cap : Z) : Z :=
  Z.min (deductible_adjusted covered deductible) cap.

Theorem deductible_adjusted_nonnegative :
  forall covered deductible,
    0 <= deductible_adjusted covered deductible.
Proof.
  intros covered deductible.
  unfold deductible_adjusted.
  apply Z.le_max_l.
Qed.

Theorem capped_payout_below_cap :
  forall covered deductible cap,
    capped_payout covered deductible cap <= cap.
Proof.
  intros covered deductible cap.
  unfold capped_payout.
  apply Z.le_min_r.
Qed.

Theorem zero_deductible_preserves_min_cap :
  forall covered cap,
    0 <= covered ->
    capped_payout covered 0 cap = Z.min covered cap.
Proof.
  intros covered cap Hcovered.
  unfold capped_payout, deductible_adjusted.
  rewrite Z.sub_0_r.
  rewrite Z.max_r by lia.
  reflexivity.
Qed.
