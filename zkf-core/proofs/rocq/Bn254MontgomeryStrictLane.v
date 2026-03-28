From Stdlib Require Import Lia List NArith ZArith.
Import List.ListNotations.

Require Import FieldGenerationProvenance.
Require Import KernelCompat.
Require Import KernelFieldEncodingProofs.
Require Import KernelGenerated.

Definition bn254_field : t_FieldId := FieldId_Bn254.
Definition bn254_modulus_z : Z := spec_field_modulus bn254_field.
Definition bn254_word_modulus : Z := 2 ^ 64.
Definition bn254_modulus_limb0 : Z := 4891460686036598785.
Definition bn254_modulus_limb1 : Z := 2896914383306846353.
Definition bn254_modulus_limb2 : Z := 13281191951274694749.
Definition bn254_modulus_limb3 : Z := 3486998266802970665.
Definition bn254_reduction_constant : Z := 14042775128853446655.

Definition bn254_final_conditional_subtract (candidate : Z) : Z :=
  if Z.geb candidate bn254_modulus_z then
    candidate - bn254_modulus_z
  else
    candidate.

Theorem bn254_modulus_from_limbs_ok :
  bn254_modulus_z =
    bn254_modulus_limb0 +
    bn254_modulus_limb1 * bn254_word_modulus +
    bn254_modulus_limb2 * (bn254_word_modulus ^ 2) +
    bn254_modulus_limb3 * (bn254_word_modulus ^ 3).
Proof.
  vm_compute.
  reflexivity.
Qed.

Theorem bn254_reduction_constant_correct :
  ((bn254_modulus_limb0 * bn254_reduction_constant) + 1) mod bn254_word_modulus = 0.
Proof.
  vm_compute.
  reflexivity.
Qed.

Theorem bn254_final_conditional_subtract_ok :
  forall candidate,
    0 <= candidate < 2 * bn254_modulus_z ->
    0 <= bn254_final_conditional_subtract candidate < bn254_modulus_z /\
    bn254_final_conditional_subtract candidate =
      spec_normalize_z candidate bn254_modulus_z.
Proof.
  intros candidate [Hlower Hupper].
  assert (Hmodulus_pos : 0 < bn254_modulus_z).
  {
    unfold bn254_modulus_z, bn254_field.
    apply spec_field_modulus_positive.
  }
  assert (Hmodulus_nonzero : bn254_modulus_z <> 0) by lia.
  unfold bn254_final_conditional_subtract.
  destruct (candidate >=? bn254_modulus_z) eqn:Hgeb.
  - apply Z.geb_le in Hgeb.
    split.
    + split.
      * apply Z.le_0_sub.
        exact Hgeb.
      * lia.
    + unfold spec_normalize_z.
      assert (Hreduced_bounds :
        0 <= candidate - bn254_modulus_z < bn254_modulus_z) by lia.
      assert (Hmod : candidate mod bn254_modulus_z = candidate - bn254_modulus_z).
      {
        symmetry.
        apply Z.mod_unique_pos with (q := 1).
        - exact Hreduced_bounds.
        - lia.
      }
      rewrite Hmod.
      replace (candidate - bn254_modulus_z + bn254_modulus_z) with candidate by lia.
      symmetry.
      exact Hmod.
  - assert (Hlt : candidate < bn254_modulus_z).
    {
      destruct (Z_lt_ge_dec candidate bn254_modulus_z) as [Hlt | Hge].
      - exact Hlt.
      - assert (Htrue : (candidate >=? bn254_modulus_z)%Z = true).
        {
          apply Z.geb_le.
          lia.
        }
        rewrite Htrue in Hgeb.
        discriminate.
    }
    split.
    + split; lia.
    + unfold spec_normalize_z.
      assert (Hmod : candidate mod bn254_modulus_z = candidate).
      {
        apply Z.mod_small.
        split; [exact Hlower | exact Hlt].
      }
      rewrite Hmod.
      apply Z.mod_unique_pos with (q := 1).
      * split; [exact Hlower | exact Hlt].
      * lia.
Qed.

Theorem bn254_strict_lane_dispatch_slot_unique :
  forall field,
    large_prime_runtime_dispatch_index field = Some 0%N ->
    field = Bn254.
Proof.
  intros field Hdispatch.
  destruct field; simpl in Hdispatch; try discriminate; reflexivity.
Qed.

Theorem bn254_strict_lane_excludes_uncertified_impl_ok :
  In Bn254 large_prime_runtime_manifest /\
  ~ In OtherLargePrimeField large_prime_runtime_manifest /\
  (forall field,
    In field large_prime_runtime_manifest ->
    large_prime_runtime_dispatch_index field = Some 0%N ->
    field = Bn254).
Proof.
  repeat split.
  - simpl.
    auto.
  - simpl.
    intros Hcontra.
    repeat destruct Hcontra as [Hcontra | Hcontra].
    all: inversion Hcontra.
  - intros field _ Hdispatch.
    eapply bn254_strict_lane_dispatch_slot_unique.
    exact Hdispatch.
Qed.

Theorem bn254_strict_lane_normalize_runtime_semantics_ok :
  forall value,
    spec_field_value_to_z (normalize value bn254_field) =
      spec_normalize_z (spec_field_value_to_z value) bn254_modulus_z.
Proof.
  intros value.
  unfold bn254_modulus_z, bn254_field.
  apply normalize_runtime_semantics_ok.
Qed.

Theorem bn254_strict_lane_mul_output_canonical_ok :
  forall lhs rhs,
    normalize (Mul_f_mul lhs rhs bn254_field) bn254_field =
      Mul_f_mul lhs rhs bn254_field.
Proof.
  intros lhs rhs.
  unfold bn254_field.
  apply mul_output_canonical_ok.
Qed.

Theorem bn254_strict_lane_mul_runtime_semantics_ok :
  forall lhs rhs,
    spec_field_value_to_z (Mul_f_mul lhs rhs bn254_field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) bn254_modulus_z *
         spec_normalize_z (spec_field_value_to_z rhs) bn254_modulus_z)
        bn254_modulus_z.
Proof.
  intros lhs rhs.
  unfold bn254_modulus_z, bn254_field.
  apply mul_runtime_semantics_ok.
Qed.

Theorem bn254_strict_lane_div_output_canonical_ok :
  forall lhs rhs value,
    Div_f_div lhs rhs bn254_field = Option_Some value ->
    normalize value bn254_field = value.
Proof.
  intros lhs rhs value Hdiv.
  unfold bn254_field.
  eapply div_output_canonical_ok.
  exact Hdiv.
Qed.

Theorem bn254_strict_lane_div_runtime_semantics_ok :
  forall lhs rhs value,
    Div_f_div lhs rhs bn254_field = Option_Some value ->
    exists inverse,
      spec_mod_inverse
        (spec_normalize_z (spec_field_value_to_z rhs) bn254_modulus_z)
        bn254_modulus_z = Some inverse /\
      spec_field_value_to_z value =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) bn254_modulus_z * inverse)
          bn254_modulus_z.
Proof.
  intros lhs rhs value Hdiv.
  unfold bn254_modulus_z, bn254_field.
  eapply div_runtime_semantics_ok.
  exact Hdiv.
Qed.

Theorem bn254_strict_lane_bug_class_closed_ok :
  bn254_modulus_z =
    bn254_modulus_limb0 +
    bn254_modulus_limb1 * bn254_word_modulus +
    bn254_modulus_limb2 * (bn254_word_modulus ^ 2) +
    bn254_modulus_limb3 * (bn254_word_modulus ^ 3) /\
  ((bn254_modulus_limb0 * bn254_reduction_constant) + 1) mod bn254_word_modulus = 0 /\
  (forall candidate,
    0 <= candidate < 2 * bn254_modulus_z ->
    0 <= bn254_final_conditional_subtract candidate < bn254_modulus_z /\
    bn254_final_conditional_subtract candidate =
      spec_normalize_z candidate bn254_modulus_z) /\
  In Bn254 large_prime_runtime_manifest /\
  ~ In OtherLargePrimeField large_prime_runtime_manifest /\
  (forall field,
    In field large_prime_runtime_manifest ->
    large_prime_runtime_dispatch_index field = Some 0%N ->
    field = Bn254) /\
  (forall lhs rhs,
    normalize (Mul_f_mul lhs rhs bn254_field) bn254_field =
      Mul_f_mul lhs rhs bn254_field) /\
  (forall lhs rhs,
    spec_field_value_to_z (Mul_f_mul lhs rhs bn254_field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) bn254_modulus_z *
         spec_normalize_z (spec_field_value_to_z rhs) bn254_modulus_z)
        bn254_modulus_z) /\
  (forall lhs rhs value,
    Div_f_div lhs rhs bn254_field = Option_Some value ->
    normalize value bn254_field = value) /\
  (forall lhs rhs value,
    Div_f_div lhs rhs bn254_field = Option_Some value ->
    exists inverse,
      spec_mod_inverse
        (spec_normalize_z (spec_field_value_to_z rhs) bn254_modulus_z)
        bn254_modulus_z = Some inverse /\
      spec_field_value_to_z value =
        spec_normalize_z
          (spec_normalize_z (spec_field_value_to_z lhs) bn254_modulus_z * inverse)
          bn254_modulus_z).
Proof.
  split.
  - apply bn254_modulus_from_limbs_ok.
  - split.
    + apply bn254_reduction_constant_correct.
    + split.
      * apply bn254_final_conditional_subtract_ok.
      * split.
        { exact (proj1 bn254_strict_lane_excludes_uncertified_impl_ok). }
        split.
        { exact (proj1 (proj2 bn254_strict_lane_excludes_uncertified_impl_ok)). }
        split.
        { exact (proj2 (proj2 bn254_strict_lane_excludes_uncertified_impl_ok)). }
        split.
        { apply bn254_strict_lane_mul_output_canonical_ok. }
        split.
        { apply bn254_strict_lane_mul_runtime_semantics_ok. }
        split.
        { apply bn254_strict_lane_div_output_canonical_ok. }
        { apply bn254_strict_lane_div_runtime_semantics_ok. }
Qed.
