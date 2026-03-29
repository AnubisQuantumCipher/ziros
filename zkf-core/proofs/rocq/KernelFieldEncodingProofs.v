From Stdlib Require Import ZArith Lia.
From Core Require Import Core.

Require Import KernelCompat.
Require Import KernelGenerated.

Lemma spec_field_modulus_positive :
  forall field,
    0 < spec_field_modulus field.
Proof.
  intros field.
  destruct field;
    cbv [spec_field_modulus]; lia.
Qed.

Lemma spec_field_modulus_gt_one :
  forall field,
    1 < spec_field_modulus field.
Proof.
  intros field.
  destruct field;
    cbv [spec_field_modulus]; lia.
Qed.

Lemma spec_field_modulus_fits_32_bytes :
  forall field,
    spec_field_modulus field < 256 ^ 32.
Proof.
  intros field.
  destruct field;
    apply Z.ltb_lt;
    vm_compute;
    reflexivity.
Qed.

Lemma spec_normalize_z_bounds :
  forall value modulus,
    0 < modulus ->
    0 <= spec_normalize_z value modulus < modulus.
Proof.
  intros value modulus Hmodulus.
  unfold spec_normalize_z.
  apply Z.mod_pos_bound.
  exact Hmodulus.
Qed.

Lemma spec_normalize_z_small :
  forall value modulus,
    0 <= value < modulus ->
    spec_normalize_z value modulus = value.
Proof.
  intros value modulus [Hlower Hupper].
  unfold spec_normalize_z.
  replace (value mod modulus) with value.
  2:{
    symmetry.
    apply Z.mod_small.
    lia.
  }
  replace (value + modulus) with (value + 1 * modulus) by lia.
  rewrite Z.mod_add by lia.
  rewrite Z.mod_small by lia.
  reflexivity.
Qed.

Lemma spec_normalize_z_idempotent :
  forall value modulus,
    0 < modulus ->
    spec_normalize_z (spec_normalize_z value modulus) modulus =
      spec_normalize_z value modulus.
Proof.
  intros value modulus Hmodulus.
  pose proof (spec_normalize_z_bounds value modulus Hmodulus) as Hbounds.
  unfold spec_normalize_z at 1.
  destruct Hbounds as [Hlower Hupper].
  rewrite Z.add_mod_idemp_l by lia.
  replace (spec_normalize_z value modulus + modulus) with
    (spec_normalize_z value modulus + 1 * modulus) by lia.
  rewrite Z.mod_add by lia.
  apply Z.mod_small.
  lia.
Qed.

Lemma spec_u8_of_z_roundtrip_ok :
  forall value,
    Z.of_N (U8_f_v (u8_0 (spec_u8_of_z value))) = value mod 256.
Proof.
  intros value.
  unfold spec_u8_of_z.
  simpl.
  rewrite Z2N.id.
  - reflexivity.
  - apply Z.mod_pos_bound.
    lia.
Qed.

Lemma spec_z_to_bytes_le_roundtrip_weight_ok :
  forall count value weight,
    0 <= value < 256 ^ Z.of_nat count ->
    spec_bytes_to_z_le (spec_z_to_bytes_le count value) weight =
      value * weight.
Proof.
  induction count as [|count IH]; intros value weight Hbounds.
  - simpl.
    assert (value = 0) by lia.
    subst value.
    ring.
  - simpl.
    unfold spec_u8_of_z.
    simpl.
    rewrite Z2N.id.
    2:{
      apply Z.mod_pos_bound.
      lia.
    }
    assert (Hdiv_bounds : 0 <= value / 256 < 256 ^ Z.of_nat count).
    {
      destruct Hbounds as [Hlower Hupper].
      split.
      - apply Z.div_pos; lia.
      - apply (Z.div_lt_upper_bound value 256 (256 ^ Z.of_nat count)); try lia.
        replace (256 * (256 ^ Z.of_nat count)) with
          (256 ^ Z.of_nat (S count)).
        + exact Hupper.
        + replace (Z.of_nat (S count)) with (Z.succ (Z.of_nat count)) by lia.
          rewrite Z.pow_succ_r by lia.
          ring.
    }
    rewrite (IH (value / 256) (weight * 256) Hdiv_bounds).
    replace (value * weight) with
      ((256 * (value / 256) + value mod 256) * weight).
    2:{
      rewrite <- (Z_div_mod_eq_full value 256).
      ring.
    }
    ring.
Qed.

Theorem spec_z_to_bytes_le_roundtrip_32_ok :
  forall value,
    0 <= value < 256 ^ 32 ->
    spec_bytes_to_z_le (spec_z_to_bytes_le 32 value) 1 = value.
Proof.
  intros value Hbounds.
  pose proof (spec_z_to_bytes_le_roundtrip_weight_ok 32 value 1 Hbounds) as Hroundtrip.
  rewrite Z.mul_1_r in Hroundtrip.
  exact Hroundtrip.
Qed.

Lemma spec_bytes_to_array32_slice_ok :
  forall bytes,
    Slice_f_v (Array_f_v (spec_bytes_to_array32 bytes)) = bytes.
Proof.
  intros bytes.
  reflexivity.
Qed.

Theorem spec_field_value_of_z_roundtrip_ok :
  forall value,
    0 <= value < 256 ^ 32 ->
    spec_field_value_to_z (spec_field_value_of_z value) = value.
Proof.
  intros value Hbounds.
  unfold spec_field_value_to_z, spec_field_value_of_z.
  replace (value <? 0) with false by (symmetry; apply Z.ltb_ge; lia).
  cbn [SpecFieldValue_f_negative SpecFieldValue_f_bytes spec_bytes_to_array32].
  change (spec_bytes_to_z_le (spec_z_to_bytes_le 32 value) 1 = value).
  apply spec_z_to_bytes_le_roundtrip_32_ok.
  exact Hbounds.
Qed.

Lemma spec_field_value_of_z_fixed_ok :
  forall value,
    0 <= value < 256 ^ 32 ->
    spec_field_value_of_z (spec_field_value_to_z (spec_field_value_of_z value)) =
      spec_field_value_of_z value.
Proof.
  intros value Hbounds.
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounds.
  reflexivity.
Qed.

Lemma spec_normalize_z_fits_32_bytes :
  forall value modulus,
    0 < modulus ->
    modulus < 256 ^ 32 ->
    0 <= spec_normalize_z value modulus < 256 ^ 32.
Proof.
  intros value modulus Hmodulus Hbound.
  pose proof (spec_normalize_z_bounds value modulus Hmodulus) as [Hlower Hupper].
  split.
  - exact Hlower.
  - lia.
Qed.

Lemma normalize_output_canonical_ok :
  forall value field,
    normalize (normalize value field) field = normalize value field.
Proof.
  intros value field.
  unfold normalize.
  set (modulus := spec_field_modulus field).
  set (bounded := spec_normalize_z (spec_field_value_to_z value) modulus).
  assert (Hbounded_modulus : 0 <= bounded < modulus).
  {
    subst bounded modulus.
    apply spec_normalize_z_bounds.
    apply spec_field_modulus_positive.
  }
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  apply f_equal.
  apply spec_normalize_z_small.
  exact Hbounded_modulus.
Qed.

Lemma add_output_canonical_ok :
  forall lhs rhs field,
    normalize (Add_f_add lhs rhs field) field = Add_f_add lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold Add_f_add, normalize.
  set (modulus := spec_field_modulus field).
  set (bounded :=
    spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus +
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).
  assert (Hbounded_modulus : 0 <= bounded < modulus).
  {
    subst bounded modulus.
    apply spec_normalize_z_bounds.
    apply spec_field_modulus_positive.
  }
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  apply f_equal.
  apply spec_normalize_z_small.
  exact Hbounded_modulus.
Qed.

Lemma sub_output_canonical_ok :
  forall lhs rhs field,
    normalize (Sub_f_sub lhs rhs field) field = Sub_f_sub lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold Sub_f_sub, normalize.
  set (modulus := spec_field_modulus field).
  set (bounded :=
    spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus -
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).
  assert (Hbounded_modulus : 0 <= bounded < modulus).
  {
    subst bounded modulus.
    apply spec_normalize_z_bounds.
    apply spec_field_modulus_positive.
  }
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  apply f_equal.
  apply spec_normalize_z_small.
  exact Hbounded_modulus.
Qed.

Lemma mul_output_canonical_ok :
  forall lhs rhs field,
    normalize (Mul_f_mul lhs rhs field) field = Mul_f_mul lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold Mul_f_mul, normalize.
  set (modulus := spec_field_modulus field).
  set (bounded :=
    spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus *
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).
  assert (Hbounded_modulus : 0 <= bounded < modulus).
  {
    subst bounded modulus.
    apply spec_normalize_z_bounds.
    apply spec_field_modulus_positive.
  }
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  apply f_equal.
  apply spec_normalize_z_small.
  exact Hbounded_modulus.
Qed.

Lemma div_output_canonical_ok :
  forall lhs rhs field value,
    Div_f_div lhs rhs field = Option_Some value ->
    normalize value field = value.
Proof.
  intros lhs rhs field value Hdiv.
  unfold Div_f_div in Hdiv.
  set (modulus := spec_field_modulus field) in *.
  set (lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus) in *.
  set (rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus) in *.
  destruct (spec_mod_inverse rhs_value modulus) as [inverse|] eqn:Hinverse;
    try discriminate.
  inversion Hdiv; subst value.
  unfold normalize.
  set (bounded := spec_normalize_z (lhs_value * inverse) modulus).
  assert (Hbounded_modulus : 0 <= bounded < modulus).
  {
    subst bounded modulus.
    apply spec_normalize_z_bounds.
    apply spec_field_modulus_positive.
  }
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  apply f_equal.
  apply spec_normalize_z_small.
  exact Hbounded_modulus.
Qed.

Lemma normalize_runtime_semantics_ok :
  forall value field,
    spec_field_value_to_z (normalize value field) =
      spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field).
Proof.
  intros value field.
  unfold normalize.
  set (modulus := spec_field_modulus field).
  set (bounded := spec_normalize_z (spec_field_value_to_z value) modulus).
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  reflexivity.
Qed.

Lemma add_runtime_semantics_ok :
  forall lhs rhs field,
    spec_field_value_to_z (Add_f_add lhs rhs field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) +
         spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
        (spec_field_modulus field).
Proof.
  intros lhs rhs field.
  unfold Add_f_add.
  set (modulus := spec_field_modulus field).
  set (lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus).
  set (rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus).
  set (bounded := spec_normalize_z (lhs_value + rhs_value) modulus).
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  reflexivity.
Qed.

Lemma sub_runtime_semantics_ok :
  forall lhs rhs field,
    spec_field_value_to_z (Sub_f_sub lhs rhs field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) -
         spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
        (spec_field_modulus field).
Proof.
  intros lhs rhs field.
  unfold Sub_f_sub.
  set (modulus := spec_field_modulus field).
  set (lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus).
  set (rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus).
  set (bounded := spec_normalize_z (lhs_value - rhs_value) modulus).
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  reflexivity.
Qed.

Lemma mul_runtime_semantics_ok :
  forall lhs rhs field,
    spec_field_value_to_z (Mul_f_mul lhs rhs field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) *
         spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
        (spec_field_modulus field).
Proof.
  intros lhs rhs field.
  unfold Mul_f_mul.
  set (modulus := spec_field_modulus field).
  set (lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus).
  set (rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus).
  set (bounded := spec_normalize_z (lhs_value * rhs_value) modulus).
  assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
  {
    eapply spec_normalize_z_fits_32_bytes.
    - subst modulus.
      apply spec_field_modulus_positive.
    - subst modulus.
      apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
  reflexivity.
Qed.

Lemma div_runtime_semantics_ok :
  forall lhs rhs field value,
    Div_f_div lhs rhs field = Option_Some value ->
    exists inverse,
      spec_mod_inverse
        (spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
        (spec_field_modulus field) = Some inverse /\
      spec_field_value_to_z value =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) * inverse)
          (spec_field_modulus field).
Proof.
  intros lhs rhs field value Hdiv.
  unfold Div_f_div in Hdiv.
  set (modulus := spec_field_modulus field) in *.
  set (lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus) in *.
  set (rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus) in *.
  destruct (spec_mod_inverse rhs_value modulus) as [inverse|] eqn:Hinverse;
    try discriminate.
  inversion Hdiv; subst value.
  exists inverse.
  split.
  - reflexivity.
  - set (bounded := spec_normalize_z (lhs_value * inverse) modulus).
    assert (Hbounded_bytes : 0 <= bounded < 256 ^ 32).
    {
      eapply spec_normalize_z_fits_32_bytes.
      - subst modulus.
        apply spec_field_modulus_positive.
      - subst modulus.
        apply spec_field_modulus_fits_32_bytes.
    }
    rewrite spec_field_value_of_z_roundtrip_ok by exact Hbounded_bytes.
    reflexivity.
Qed.

Definition small_direct_field (field : t_FieldId) : Prop :=
  field = FieldId_Goldilocks \/
  field = FieldId_BabyBear \/
  field = FieldId_Mersenne31.

Theorem small_field_runtime_semantics_ok :
  forall field,
    small_direct_field field ->
    (forall value,
      spec_field_value_to_z (normalize value field) =
        spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field)) /\
    (forall lhs rhs,
      spec_field_value_to_z (Add_f_add lhs rhs field) =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) +
           spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
          (spec_field_modulus field)) /\
    (forall lhs rhs,
      spec_field_value_to_z (Sub_f_sub lhs rhs field) =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) -
           spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
          (spec_field_modulus field)) /\
    (forall lhs rhs,
      spec_field_value_to_z (Mul_f_mul lhs rhs field) =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) *
           spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
          (spec_field_modulus field)) /\
    (forall lhs rhs value,
      Div_f_div lhs rhs field = Option_Some value ->
      exists inverse,
        spec_mod_inverse
          (spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
          (spec_field_modulus field) = Some inverse /\
        spec_field_value_to_z value =
          spec_normalize_z
            (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) * inverse)
            (spec_field_modulus field)).
Proof.
  intros field _.
  repeat split; intros.
  - apply normalize_runtime_semantics_ok.
  - apply add_runtime_semantics_ok.
  - apply sub_runtime_semantics_ok.
  - apply mul_runtime_semantics_ok.
  - eapply div_runtime_semantics_ok; eauto.
Qed.
