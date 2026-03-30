(** Sovereign Economic Defense — Mechanized Proofs

    These three theorems replace the Kani bounded model checks with
    universal proofs over all inputs, eliminating the
    [kani-bounded-model-check-soundness] trusted assumption.

    Theorem IDs:
      - sed.common.exact_division_remainder_bounded
      - sed.common.floor_sqrt_satisfies_relation
      - sed.recirculation.recirculation_rate_bounded
*)

From Stdlib Require Import ZArith Lia.

Open Scope Z_scope.

(* ======================================================================== *)
(*  sed.common.exact_division_remainder_bounded                             *)
(* ======================================================================== *)

(**
    The exact division decomposition in ZirOS constrains:
      numerator = denominator * quotient + remainder
      slack     = denominator - remainder - 1
      0 <= remainder    (range-checked)
      0 <= slack        (range-checked)

    We prove that these constraints imply 0 <= remainder < denominator.
*)

Theorem exact_division_remainder_bounded :
  forall numerator denominator quotient remainder slack : Z,
    denominator > 0 ->
    numerator = denominator * quotient + remainder ->
    slack = denominator - remainder - 1 ->
    0 <= remainder ->
    0 <= slack ->
    0 <= remainder < denominator.
Proof.
  intros numerator denominator quotient remainder slack
    Hden_pos Hdiv Hslack Hrem_nonneg Hslack_nonneg.
  split.
  - exact Hrem_nonneg.
  - (* From slack = denominator - remainder - 1 and slack >= 0,
       we get denominator - remainder - 1 >= 0,
       hence remainder <= denominator - 1,
       hence remainder < denominator. *)
    lia.
Qed.

(**
    Corollary: the quotient produced by Euclidean division is the
    unique integer satisfying the decomposition with bounded remainder.
*)

Corollary exact_division_quotient_unique :
  forall numerator denominator q1 r1 q2 r2 : Z,
    denominator > 0 ->
    numerator = denominator * q1 + r1 ->
    numerator = denominator * q2 + r2 ->
    0 <= r1 < denominator ->
    0 <= r2 < denominator ->
    q1 = q2 /\ r1 = r2.
Proof.
  intros numerator denominator q1 r1 q2 r2
    Hden Hdiv1 Hdiv2 [Hr1_lo Hr1_hi] [Hr2_lo Hr2_hi].
  assert (denominator * q1 + r1 = denominator * q2 + r2) as Heq by lia.
  assert (denominator * (q1 - q2) = r2 - r1) as Hdiff by lia.
  assert (-denominator < r2 - r1 < denominator) as Hrange by lia.
  assert (q1 - q2 = 0) as Hq_eq.
  { destruct (Z.eq_dec (q1 - q2) 0) as [Hzero | Hnonzero].
    - exact Hzero.
    - (* |denominator * (q1 - q2)| >= denominator, but |r2 - r1| < denominator *)
      exfalso.
      assert (Z.abs (q1 - q2) >= 1) by lia.
      assert (Z.abs (denominator * (q1 - q2)) >= denominator).
      { rewrite Z.abs_mul. nia. }
      lia.
  }
  split; lia.
Qed.

(* ======================================================================== *)
(*  sed.common.floor_sqrt_satisfies_relation                                *)
(* ======================================================================== *)

(**
    The floor square root decomposition in ZirOS constrains:
      value               = sqrt^2 + remainder
      value + upper_slack + 1 = (sqrt + 1)^2
      0 <= remainder      (range-checked)
      0 <= upper_slack    (range-checked)
      0 <= sqrt           (range-checked via nonnegative bound)

    We prove that these constraints imply sqrt = floor(sqrt(value)),
    i.e., sqrt^2 <= value < (sqrt + 1)^2.
*)

Theorem floor_sqrt_satisfies_relation :
  forall value sqrt remainder upper_slack : Z,
    value >= 0 ->
    sqrt >= 0 ->
    remainder >= 0 ->
    upper_slack >= 0 ->
    value = sqrt * sqrt + remainder ->
    value + upper_slack + 1 = (sqrt + 1) * (sqrt + 1) ->
    sqrt * sqrt <= value < (sqrt + 1) * (sqrt + 1).
Proof.
  intros value sqrt remainder upper_slack
    Hval_nonneg Hsqrt_nonneg Hrem_nonneg Hus_nonneg Hdecomp Hupper.
  split.
  - (* sqrt^2 <= value follows from value = sqrt^2 + remainder
       with remainder >= 0. *)
    lia.
  - (* value < (sqrt+1)^2 follows from
       value + upper_slack + 1 = (sqrt+1)^2 with upper_slack >= 0,
       hence (sqrt+1)^2 = value + upper_slack + 1 >= value + 1 > value. *)
    lia.
Qed.

(**
    Corollary: the remainder is bounded by 2*sqrt.
    This follows from (sqrt+1)^2 - sqrt^2 = 2*sqrt + 1,
    so remainder = value - sqrt^2 < (sqrt+1)^2 - sqrt^2 = 2*sqrt + 1.
*)

Corollary floor_sqrt_remainder_bounded :
  forall value sqrt remainder upper_slack : Z,
    value >= 0 ->
    sqrt >= 0 ->
    remainder >= 0 ->
    upper_slack >= 0 ->
    value = sqrt * sqrt + remainder ->
    value + upper_slack + 1 = (sqrt + 1) * (sqrt + 1) ->
    0 <= remainder <= 2 * sqrt.
Proof.
  intros value sqrt remainder upper_slack
    Hval Hsqrt Hrem Hus Hdecomp Hupper.
  split.
  - lia.
  - (* remainder = value - sqrt^2
       upper_slack = (sqrt+1)^2 - value - 1 = 2*sqrt + 1 - 1 - remainder
                   = 2*sqrt - remainder
       Since upper_slack >= 0, remainder <= 2*sqrt. *)
    nia.
Qed.

(* ======================================================================== *)
(*  sed.recirculation.recirculation_rate_bounded                            *)
(* ======================================================================== *)

(**
    The recirculation rate is computed as:
      rate = (internal * scale) / total
    where total = internal + external.

    We prove that rate <= scale when internal >= 0 and external >= 0
    and total > 0. This means the recirculation rate cannot exceed 100%.
*)

Theorem recirculation_rate_bounded :
  forall internal external scale : Z,
    internal >= 0 ->
    external >= 0 ->
    scale > 0 ->
    internal + external > 0 ->
    (internal * scale) / (internal + external) <= scale.
Proof.
  intros internal external scale
    Hint_nonneg Hext_nonneg Hscale_pos Htotal_pos.
  (* Since internal <= internal + external (because external >= 0),
     and scale > 0, we have:
       internal * scale <= (internal + external) * scale
     Dividing both sides by (internal + external) > 0:
       (internal * scale) / (internal + external) <= scale *)
  apply Z.div_le_upper_bound; nia.
Qed.

(**
    Corollary: rate is also nonnegative.
*)

Corollary recirculation_rate_nonneg :
  forall internal external scale : Z,
    internal >= 0 ->
    external >= 0 ->
    scale > 0 ->
    internal + external > 0 ->
    0 <= (internal * scale) / (internal + external).
Proof.
  intros internal external scale
    Hint Hext Hscale Htotal.
  apply Z.div_pos; nia.
Qed.

(**
    Full bound: 0 <= rate <= scale.
*)

Corollary recirculation_rate_in_range :
  forall internal external scale : Z,
    internal >= 0 ->
    external >= 0 ->
    scale > 0 ->
    internal + external > 0 ->
    0 <= (internal * scale) / (internal + external) <= scale.
Proof.
  intros internal external scale Hint Hext Hscale Htotal.
  split.
  - exact (recirculation_rate_nonneg internal external scale Hint Hext Hscale Htotal).
  - exact (recirculation_rate_bounded internal external scale Hint Hext Hscale Htotal).
Qed.
