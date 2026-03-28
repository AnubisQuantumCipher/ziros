From Stdlib Require Import ZArith Lia.
Require Import List.
Require Import Permutation.
Import List.ListNotations.

Require Import KernelCompat.
Require Import KernelGenerated.
Require Import KernelFieldEncodingProofs.
Require Import KernelSemantics.
Require Import KernelProofs.
Require Import TransformSemantics.
From ZkfCoreExtraction Require Import Zkf_core_Proof_transform_spec.

Lemma spec_normalize_z_zero :
  forall modulus,
    0 < modulus ->
    spec_normalize_z 0 modulus = 0.
Proof.
  intros modulus Hmodulus.
  unfold spec_normalize_z.
  rewrite Z.mod_0_l by lia.
  rewrite Z.add_0_l.
  rewrite Z.mod_same by lia.
  reflexivity.
Qed.

Lemma spec_normalize_z_one :
  forall modulus,
    1 < modulus ->
    spec_normalize_z 1 modulus = 1.
Proof.
  intros modulus Hmodulus.
  apply spec_normalize_z_small.
  lia.
Qed.

Lemma normalize_spec_value_zero_raw_ok :
  forall value field,
    spec_value_is_zero_raw value = true ->
    normalize_spec_value value field = zero_spec_value tt.
Proof.
  intros value field Hzero.
  unfold spec_value_is_zero_raw in Hzero.
  apply Z.eqb_eq in Hzero.
  unfold normalize_spec_value, zero_spec_value, normalize, zero.
  simpl.
  rewrite Hzero.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma normalize_spec_value_one_raw_ok :
  forall value field,
    spec_value_is_one_raw value = true ->
    normalize_spec_value value field = spec_field_value_of_z 1.
Proof.
  intros value field Hone.
  unfold spec_value_is_one_raw in Hone.
  apply Z.eqb_eq in Hone.
  unfold normalize_spec_value, normalize.
  simpl.
  rewrite Hone.
  rewrite spec_normalize_z_one by apply spec_field_modulus_gt_one.
  reflexivity.
Qed.

Lemma add_spec_values_zero_l_ok :
  forall value field,
    add_spec_values (zero_spec_value tt) value field = normalize_spec_value value field.
Proof.
  intros value field.
  unfold add_spec_values, zero_spec_value, normalize_spec_value, Add_f_add, zero, normalize.
  simpl.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  rewrite Z.add_0_l.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma add_spec_values_zero_r_ok :
  forall value field,
    add_spec_values value (zero_spec_value tt) field = normalize_spec_value value field.
Proof.
  intros value field.
  unfold add_spec_values, zero_spec_value, normalize_spec_value, Add_f_add, zero, normalize.
  simpl.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  rewrite Z.add_0_r.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma sub_spec_values_zero_r_ok :
  forall value field,
    sub_spec_values value (zero_spec_value tt) field = normalize_spec_value value field.
Proof.
  intros value field.
  unfold sub_spec_values, zero_spec_value, normalize_spec_value, Sub_f_sub, zero, normalize.
  simpl.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  rewrite Z.sub_0_r.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_zero_l_ok :
  forall value field,
    mul_spec_values (zero_spec_value tt) value field = zero_spec_value tt.
Proof.
  intros value field.
  unfold mul_spec_values, zero_spec_value, Mul_f_mul, zero.
  simpl.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  rewrite Z.mul_0_l.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_zero_r_ok :
  forall value field,
    mul_spec_values value (zero_spec_value tt) field = zero_spec_value tt.
Proof.
  intros value field.
  unfold mul_spec_values, zero_spec_value, Mul_f_mul, zero.
  simpl.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  rewrite Z.mul_0_r.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_one_l_ok :
  forall value field,
    mul_spec_values (spec_field_value_of_z 1) value field = normalize_spec_value value field.
Proof.
  intros value field.
  unfold mul_spec_values, normalize_spec_value, Mul_f_mul, normalize.
  simpl.
  rewrite spec_normalize_z_one by apply spec_field_modulus_gt_one.
  rewrite Z.mul_1_l.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_one_r_ok :
  forall value field,
    mul_spec_values value (spec_field_value_of_z 1) field = normalize_spec_value value field.
Proof.
  intros value field.
  unfold mul_spec_values, normalize_spec_value, Mul_f_mul, normalize.
  simpl.
  rewrite spec_normalize_z_one by apply spec_field_modulus_gt_one.
  rewrite Z.mul_1_r.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma zero_spec_value_normalized_ok :
  forall field,
    normalize (zero_spec_value tt) field = zero_spec_value tt.
Proof.
  intros field.
  unfold zero_spec_value, spec_field_value_zero, normalize.
  rewrite spec_field_value_of_z_roundtrip_ok by lia.
  rewrite spec_normalize_z_zero by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma transform_signal_value_eq_kernel_signal_value_ok :
  forall witness signal_index field,
    transform_signal_value witness signal_index field =
      kernel_signal_value witness signal_index field.
Proof.
  intros witness signal_index field.
  unfold transform_signal_value, kernel_signal_value, normalize_spec_value.
  reflexivity.
Qed.

Lemma transform_expr_add_some_acc_ok :
  forall values acc field,
    (let fix to_kernel_values
      (values : list t_SpecTransformExpr)
      (acc_opt : t_Option t_SpecKernelExpr)
      : t_SpecKernelExpr :=
      match values with
      | [] =>
        match acc_opt with
        | Option_Some acc_expr =>
          acc_expr
        | Option_None =>
          SpecKernelExpr_Const (zero_spec_value tt)
        end
      | value :: remaining_values =>
        let next_acc :=
          match acc_opt with
          | Option_Some acc_expr =>
            SpecKernelExpr_Add acc_expr (transform_expr_to_kernel value field)
          | Option_None =>
            transform_expr_to_kernel value field
          end in
        to_kernel_values remaining_values (Option_Some next_acc)
      end in
    to_kernel_values values (Option_Some acc)) =
      to_kernel_expr_from_list values acc field.
Proof.
  induction values as [|value remaining_values IH];
    intros acc field; simpl.
  - reflexivity.
  - rewrite IH.
    reflexivity.
Qed.

Lemma transform_expr_add_to_kernel_ok :
  forall values field,
    transform_expr_to_kernel (SpecTransformExpr_Add values) field =
      to_kernel_expr_list values field.
Proof.
  intros values field.
  destruct values as [|first remaining_values]; simpl.
  - reflexivity.
  - apply transform_expr_add_some_acc_ok.
Qed.

Lemma transform_eval_exprs_list_local_ok :
  forall values witness field acc,
    (let fix eval_values
      (values : list t_SpecTransformExpr)
      (acc : t_SpecFieldValue)
      : t_Result t_SpecFieldValue t_SpecKernelCheckError :=
      match values with
      | [] =>
          Result_Ok acc
      | value :: remaining_values =>
          match transform_eval_expr value witness field with
          | Result_Ok evaluated =>
              eval_values remaining_values (add_spec_values acc evaluated field)
          | Result_Err error =>
              Result_Err error
          end
      end in
    eval_values values acc) =
      transform_eval_exprs_list values witness field acc.
Proof.
  intros values witness field.
  induction values as [|value remaining_values IH];
    intros acc; simpl.
  - reflexivity.
  - destruct (transform_eval_expr value witness field) eqn:Heval.
    + exact (IH (add_spec_values acc s field)).
    + reflexivity.
Qed.

Lemma transform_eval_expr_add_as_list :
  forall values witness field,
    transform_eval_expr (SpecTransformExpr_Add values) witness field =
      transform_eval_exprs_list values witness field (zero_spec_value tt).
Proof.
  intros values witness field.
  apply transform_eval_exprs_list_local_ok.
Qed.

Lemma transform_expr_holds_acc_irrelevant :
  forall witness field acc_from acc_to expr value,
    TransformExprHolds witness field acc_from expr value ->
    TransformExprHolds witness field acc_to expr value.
Proof.
  intros witness field acc_from acc_to expr value Hholds.
  induction Hholds.
  - constructor.
  - econstructor.
    exact H.
  - econstructor.
    exact H.
  - eapply TransformExprHolds_Sub.
    + exact IHHholds1.
    + exact IHHholds2.
  - eapply TransformExprHolds_Mul.
    + exact IHHholds1.
    + exact IHHholds2.
  - eapply TransformExprHolds_Div.
    + exact IHHholds1.
    + exact IHHholds2.
    + assumption.
Qed.

Lemma transform_eval_expr_sound_ok :
  forall expr witness field value,
    transform_eval_expr expr witness field = Result_Ok value ->
    TransformExprHolds witness field (zero_spec_value tt) expr value.
Proof.
  refine (
    fix expr_sound (expr : t_SpecTransformExpr)
      : forall witness field value,
          transform_eval_expr expr witness field = Result_Ok value ->
          TransformExprHolds witness field (zero_spec_value tt) expr value := _).
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    intros witness field value Heval.
  - simpl in Heval.
    inversion Heval; subst.
    constructor.
  - simpl in Heval.
    econstructor.
    exact Heval.
  - rewrite transform_eval_expr_add_as_list in Heval.
    econstructor.
    assert (
      forall list_values acc result,
        transform_eval_exprs_list list_values witness field acc = Result_Ok result ->
        TransformExprListHolds witness field acc list_values result
    ) as Hlist_sound.
    {
      intro list_values.
      induction list_values as [|value_expr remaining_values IH];
        intros acc result Heval_list; simpl in Heval_list.
      - inversion Heval_list; subst.
        constructor.
      - destruct (transform_eval_expr value_expr witness field) eqn:Hvalue;
          try discriminate.
        eapply TransformExprListHolds_cons.
        + eapply transform_expr_holds_acc_irrelevant with (acc_from := zero_spec_value tt).
          eapply expr_sound.
          exact Hvalue.
        + eapply IH.
          exact Heval_list.
    }
    eapply Hlist_sound.
    exact Heval.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    inversion Heval; subst.
    eapply TransformExprHolds_Sub.
    + eapply expr_sound.
      exact Hlhs.
    + eapply expr_sound.
      exact Hrhs.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    inversion Heval; subst.
    eapply TransformExprHolds_Mul.
    + eapply expr_sound.
      exact Hlhs.
    + eapply expr_sound.
      exact Hrhs.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    destruct (div_spec_values s s0 field) eqn:Hdiv; try discriminate.
    inversion Heval; subst.
    eapply TransformExprHolds_Div.
    + eapply expr_sound.
      exact Hlhs.
    + eapply expr_sound.
      exact Hrhs.
    + exact Hdiv.
Qed.

Lemma transform_eval_exprs_list_sound_ok :
  forall values witness field acc value,
    transform_eval_exprs_list values witness field acc = Result_Ok value ->
    TransformExprListHolds witness field acc values value.
Proof.
  induction values as [|value_expr remaining_values IH];
    intros witness field acc value Heval; simpl in Heval.
  - inversion Heval; subst.
    constructor.
  - destruct (transform_eval_expr value_expr witness field) eqn:Hvalue;
      try discriminate.
    eapply TransformExprListHolds_cons.
    + eapply transform_expr_holds_acc_irrelevant with (acc_from := zero_spec_value tt).
      eapply transform_eval_expr_sound_ok.
      exact Hvalue.
    + eapply IH.
      exact Heval.
Qed.

Lemma transform_signal_value_normalized_ok :
  forall witness signal_index field value,
    transform_signal_value witness signal_index field = Result_Ok value ->
    normalize value field = value.
Proof.
  intros witness signal_index field value Hvalue.
  unfold transform_signal_value in Hvalue.
  remember (impl__get (f_deref (f_values witness)) signal_index) as slot eqn:Hlookup.
  destruct slot as [|maybe_value]; simpl in Hvalue.
  1:{
    discriminate.
  }
  destruct maybe_value as [|raw_value].
  1:{
    simpl in Hvalue.
    discriminate.
  }
  simpl in Hvalue.
  inversion Hvalue; subst; clear Hvalue.
  unfold normalize_spec_value.
  apply normalize_output_canonical_ok.
Qed.

Lemma transform_expr_normalized_pair :
  (forall witness field acc expr value,
      TransformExprHolds witness field acc expr value ->
      normalize value field = value)
  /\
  (forall witness field acc values value,
      TransformExprListHolds witness field acc values value ->
      normalize acc field = acc ->
      normalize value field = value).
Proof.
  assert (
    forall witness field acc,
      (forall values value,
          TransformExprListHolds witness field acc values value ->
          normalize acc field = acc ->
          normalize value field = value)
      /\
      (forall expr value,
          TransformExprHolds witness field acc expr value ->
          normalize value field = value)
  ) as Hnormalized.
  {
    intros witness field acc.
    eapply (TransformExprHolds_mutind witness field
      (fun acc values value _ =>
         normalize acc field = acc ->
         normalize value field = value)
      (fun acc expr value _ =>
         normalize value field = value)).
    - intros current_acc Hacc.
      exact Hacc.
    - intros current_acc expr remaining_exprs expr_value final_value
        _ _ _ IHremaining Hacc.
      eapply IHremaining.
      rewrite add_output_canonical_ok.
      reflexivity.
    - intros current_acc const_expr.
      apply normalize_output_canonical_ok.
    - intros current_acc signal_expr value Hsignal.
      eapply transform_signal_value_normalized_ok.
      exact Hsignal.
    - intros current_acc values value _ IHvalues.
      eapply IHvalues.
      apply zero_spec_value_normalized_ok.
    - intros current_acc lhs rhs lhs_value rhs_value _ _ _ _.
      apply sub_output_canonical_ok.
    - intros current_acc lhs rhs lhs_value rhs_value _ _ _ _.
      apply mul_output_canonical_ok.
    - intros current_acc lhs rhs lhs_value rhs_value value _ _ _ _ Hdiv.
      eapply div_output_canonical_ok.
      exact Hdiv.
  }
  split.
  - intros witness field acc expr value Hholds.
    pose proof (Hnormalized witness field acc) as [_ Hexpr_normalized].
    eapply Hexpr_normalized.
    exact Hholds.
  - intros witness field acc values value Hholds Hacc.
    pose proof (Hnormalized witness field acc) as [Hlist_normalized _].
    eapply Hlist_normalized.
    + exact Hholds.
    + exact Hacc.
Qed.

Lemma transform_eval_expr_normalized_ok :
  forall expr witness field value,
    transform_eval_expr expr witness field = Result_Ok value ->
    normalize value field = value.
Proof.
  intros expr witness field value Heval.
  pose proof transform_expr_normalized_pair as [Hexpr_normalized _].
  eapply Hexpr_normalized.
  eapply transform_eval_expr_sound_ok.
  exact Heval.
Qed.

Lemma transform_eval_exprs_list_normalized_ok :
  forall values witness field acc value,
    normalize acc field = acc ->
    transform_eval_exprs_list values witness field acc = Result_Ok value ->
    normalize value field = value.
Proof.
  intros values witness field acc value Hacc Heval.
  pose proof transform_expr_normalized_pair as [_ Hlist_normalized].
  eapply Hlist_normalized.
  - eapply transform_eval_exprs_list_sound_ok.
    exact Heval.
  - exact Hacc.
Qed.

Lemma transform_eval_expr_to_kernel_ok :
  forall expr witness field value,
    transform_eval_expr expr witness field = Result_Ok value ->
    eval_expr (transform_expr_to_kernel expr field) witness field = Result_Ok value.
Proof.
  refine (
    fix expr_to_kernel (expr : t_SpecTransformExpr)
      : forall witness field value,
          transform_eval_expr expr witness field = Result_Ok value ->
          eval_expr (transform_expr_to_kernel expr field) witness field = Result_Ok value := _).
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    intros witness field value Heval.
  - simpl in Heval.
    exact Heval.
  - simpl in Heval.
    rewrite transform_signal_value_eq_kernel_signal_value_ok in Heval.
    exact Heval.
  - rewrite transform_eval_expr_add_as_list in Heval.
    rewrite transform_expr_add_to_kernel_ok.
    destruct values as [|first remaining_values].
    + simpl in Heval.
      simpl.
      rewrite zero_spec_value_normalized_ok.
      exact Heval.
    + assert (
        forall values acc_expr acc_value result,
          eval_expr acc_expr witness field = Result_Ok acc_value ->
          transform_eval_exprs_list values witness field acc_value = Result_Ok result ->
          eval_expr (to_kernel_expr_from_list values acc_expr field) witness field = Result_Ok result
      ) as Hlist.
      {
        induction values as [|value_expr remaining IH];
          intros acc_expr acc_value result Hacc Heval_list; simpl in Heval_list.
        - inversion Heval_list; subst.
          exact Hacc.
        - destruct (transform_eval_expr value_expr witness field) eqn:Hvalue;
            try discriminate.
          simpl.
          eapply IH.
          + simpl.
            rewrite Hacc.
            rewrite (expr_to_kernel value_expr witness field s Hvalue).
            reflexivity.
          + exact Heval_list.
      }
      simpl in Heval.
      destruct (transform_eval_expr first witness field) eqn:Hfirst; try discriminate.
      rewrite add_spec_values_zero_l_ok in Heval.
      unfold normalize_spec_value in Heval.
      rewrite (transform_eval_expr_normalized_ok first witness field s Hfirst) in Heval.
      simpl.
      eapply Hlist.
      * eapply expr_to_kernel.
        exact Hfirst.
      * exact Heval.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    simpl.
    rewrite (expr_to_kernel lhs witness field s Hlhs).
    rewrite (expr_to_kernel rhs witness field s0 Hrhs).
    exact Heval.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    simpl.
    rewrite (expr_to_kernel lhs witness field s Hlhs).
    rewrite (expr_to_kernel rhs witness field s0 Hrhs).
    exact Heval.
  - simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs; try discriminate.
    destruct (div_spec_values s s0 field) eqn:Hdiv; try discriminate.
    unfold div_spec_values in Hdiv.
    simpl.
    rewrite (expr_to_kernel lhs witness field s Hlhs).
    rewrite (expr_to_kernel rhs witness field s0 Hrhs).
    rewrite Hdiv.
    exact Heval.
Qed.

Lemma transform_eval_expr_complete_pair :
  (forall witness field acc expr value,
      TransformExprHolds witness field acc expr value ->
      transform_eval_expr expr witness field = Result_Ok value)
  /\
  (forall witness field acc values value,
      TransformExprListHolds witness field acc values value ->
      transform_eval_exprs_list values witness field acc = Result_Ok value).
Proof.
  assert (
    forall witness field acc,
      (forall values value,
          TransformExprListHolds witness field acc values value ->
          transform_eval_exprs_list values witness field acc = Result_Ok value)
      /\
      (forall expr value,
          TransformExprHolds witness field acc expr value ->
          transform_eval_expr expr witness field = Result_Ok value)
  ) as Hcomplete.
  {
    intros witness field acc.
    eapply (TransformExprHolds_mutind witness field
      (fun acc values value _ =>
         transform_eval_exprs_list values witness field acc = Result_Ok value)
      (fun acc expr value _ =>
         transform_eval_expr expr witness field = Result_Ok value)).
    - intros current_acc.
      reflexivity.
    - intros current_acc expr remaining_exprs expr_value final_value _ Hexpr _ IHremaining.
      simpl.
      rewrite Hexpr.
      exact IHremaining.
    - intros current_acc const_expr.
      reflexivity.
    - intros current_acc signal_expr value Hsignal.
      exact Hsignal.
    - intros current_acc values value _ IHvalues.
      rewrite transform_eval_expr_add_as_list.
      exact IHvalues.
    - intros current_acc lhs rhs lhs_value rhs_value _ Hlhs _ Hrhs.
      simpl.
      rewrite Hlhs.
      rewrite Hrhs.
      reflexivity.
    - intros current_acc lhs rhs lhs_value rhs_value _ Hlhs _ Hrhs.
      simpl.
      rewrite Hlhs.
      rewrite Hrhs.
      reflexivity.
    - intros current_acc lhs rhs lhs_value rhs_value value _ Hlhs _ Hrhs Hdiv.
      simpl.
      rewrite Hlhs.
      rewrite Hrhs.
      rewrite Hdiv.
      reflexivity.
  }
  split.
  - intros witness field acc expr value Hholds.
    pose proof (Hcomplete witness field acc) as [_ Hexpr_complete].
    eapply Hexpr_complete.
    exact Hholds.
  - intros witness field acc values value Hholds.
    pose proof (Hcomplete witness field acc) as [Hlist_complete _].
    eapply Hlist_complete.
    exact Hholds.
Qed.

Lemma transform_eval_expr_complete_ok :
  forall witness field acc expr value,
    TransformExprHolds witness field acc expr value ->
    transform_eval_expr expr witness field = Result_Ok value.
Proof.
  intros witness field acc expr value Hholds.
  exact (proj1 transform_eval_expr_complete_pair witness field acc expr value Hholds).
Qed.

Lemma transform_eval_exprs_list_complete_ok :
  forall witness field acc values value,
    TransformExprListHolds witness field acc values value ->
    transform_eval_exprs_list values witness field acc = Result_Ok value.
Proof.
  intros witness field acc values value Hholds.
  exact (proj2 transform_eval_expr_complete_pair witness field acc values value Hholds).
Qed.

Lemma transform_eval_exprs_list_app_ok :
  forall prefix suffix witness field acc mid value,
    transform_eval_exprs_list prefix witness field acc = Result_Ok mid ->
    transform_eval_exprs_list suffix witness field mid = Result_Ok value ->
    transform_eval_exprs_list (prefix ++ suffix) witness field acc = Result_Ok value.
Proof.
  induction prefix as [|expr remaining_prefix IH];
    intros suffix witness field acc mid value Hprefix Hsuffix; simpl in Hprefix.
  - inversion Hprefix; subst.
    exact Hsuffix.
  - destruct (transform_eval_expr expr witness field) eqn:Hexpr; try discriminate.
    simpl.
    rewrite Hexpr.
    eapply IH.
    + exact Hprefix.
    + exact Hsuffix.
Qed.

Lemma transform_eval_exprs_list_app_inv_ok :
  forall prefix suffix witness field acc value,
    transform_eval_exprs_list (prefix ++ suffix) witness field acc = Result_Ok value ->
    exists mid,
      transform_eval_exprs_list prefix witness field acc = Result_Ok mid /\
      transform_eval_exprs_list suffix witness field mid = Result_Ok value.
Proof.
  induction prefix as [|expr remaining_prefix IH];
    intros suffix witness field acc value Heval.
  - simpl in Heval.
    exists acc.
    split.
    + reflexivity.
    + exact Heval.
  - simpl in Heval.
    destruct (transform_eval_expr expr witness field) eqn:Hexpr; try discriminate.
    destruct (IH suffix witness field (add_spec_values acc s field) value Heval)
      as [mid [Hprefix Hsuffix]].
    exists mid.
    split.
    + simpl.
      rewrite Hexpr.
      exact Hprefix.
    + exact Hsuffix.
Qed.

Lemma result_ok_injective :
  forall {value error} (lhs rhs : value),
    @Result_Ok value error lhs = Result_Ok rhs ->
    lhs = rhs.
Proof.
  intros value error lhs rhs Hresult.
  inversion Hresult.
  reflexivity.
Qed.

Lemma normalize_non_zero_values_from_list_prefix_ok :
  forall values report prefix final_report final_values,
    normalize_non_zero_values_from_list values report prefix = (final_report, final_values) ->
    exists suffix,
      final_values = prefix ++ suffix.
Proof.
  induction values as [|value remaining_values IH];
    intros report prefix final_report final_values Hnormalize; simpl in Hnormalize.
  - inversion Hnormalize; subst.
    exists [].
    rewrite app_nil_r.
    reflexivity.
  - destruct (normalize_transform_expr value report) as [report' normalized] eqn:Hvalue.
    destruct normalized as [const_expr | signal_expr | add_values | lhs rhs | lhs rhs | lhs rhs];
      simpl in Hnormalize.
    + destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value const_expr)) eqn:Hzero.
      * eapply IH in Hnormalize.
        exact Hnormalize.
      * eapply IH in Hnormalize.
        destruct Hnormalize as [suffix Hsuffix].
        exists (SpecTransformExpr_Const const_expr :: suffix).
        unfold impl_1__push in Hsuffix.
        rewrite <- app_assoc in Hsuffix.
        exact Hsuffix.
    + eapply IH in Hnormalize.
      destruct Hnormalize as [suffix Hsuffix].
      exists (SpecTransformExpr_Signal signal_expr :: suffix).
      unfold impl_1__push in Hsuffix.
      rewrite <- app_assoc in Hsuffix.
      exact Hsuffix.
    + eapply IH in Hnormalize.
      destruct Hnormalize as [suffix Hsuffix].
      exists (SpecTransformExpr_Add add_values :: suffix).
      unfold impl_1__push in Hsuffix.
      rewrite <- app_assoc in Hsuffix.
      exact Hsuffix.
    + eapply IH in Hnormalize.
      destruct Hnormalize as [suffix Hsuffix].
      exists (SpecTransformExpr_Sub lhs rhs :: suffix).
      unfold impl_1__push in Hsuffix.
      rewrite <- app_assoc in Hsuffix.
      exact Hsuffix.
    + eapply IH in Hnormalize.
      destruct Hnormalize as [suffix Hsuffix].
      exists (SpecTransformExpr_Mul lhs rhs :: suffix).
      unfold impl_1__push in Hsuffix.
      rewrite <- app_assoc in Hsuffix.
      exact Hsuffix.
    + eapply IH in Hnormalize.
      destruct Hnormalize as [suffix Hsuffix].
      exists (SpecTransformExpr_Div lhs rhs :: suffix).
      unfold impl_1__push in Hsuffix.
      rewrite <- app_assoc in Hsuffix.
      exact Hsuffix.
Qed.


Lemma transform_expr_to_kernel_sound_ok :
  forall witness field acc expr value,
    TransformExprHolds witness field acc expr value ->
    ExprEval witness field (transform_expr_to_kernel expr field) value.
Proof.
  intros witness field acc expr value Hholds.
  eapply eval_expr_sound_relative_ok.
  eapply transform_eval_expr_to_kernel_ok.
  eapply transform_eval_expr_complete_ok.
  exact Hholds.
Qed.

Lemma transform_check_constraint_sound_ok :
  forall constraint constraint_index program witness,
    transform_check_constraint constraint constraint_index program witness = Result_Ok tt ->
    TransformConstraintHolds program witness constraint.
Proof.
  intros constraint constraint_index program witness Hcheck.
  destruct constraint as [equal_constraint | boolean_constraint | range_constraint];
    simpl in Hcheck.
  - destruct (transform_eval_expr
      (SpecTransformConstraint_Equal_f_lhs equal_constraint)
      witness
      (SpecTransformProgram_f_field program)) eqn:Hlhs; try discriminate.
    destruct (transform_eval_expr
      (SpecTransformConstraint_Equal_f_rhs equal_constraint)
      witness
      (SpecTransformProgram_f_field program)) eqn:Hrhs; try discriminate.
    destruct (spec_values_equal s s0 (SpecTransformProgram_f_field program)) eqn:Heq;
      try discriminate.
    econstructor.
    + eapply transform_eval_expr_sound_ok.
      exact Hlhs.
    + eapply transform_eval_expr_sound_ok.
      exact Hrhs.
    + exact Heq.
  - destruct (transform_signal_value
      witness
      (SpecTransformConstraint_Boolean_f_signal_index boolean_constraint)
      (SpecTransformProgram_f_field program)) eqn:Hvalue; try discriminate.
    destruct (spec_value_is_boolean s (SpecTransformProgram_f_field program)) eqn:Hbool;
      try discriminate.
    econstructor.
    + exact Hvalue.
    + exact Hbool.
  - destruct (transform_signal_value
      witness
      (SpecTransformConstraint_Range_f_signal_index range_constraint)
      (SpecTransformProgram_f_field program)) eqn:Hvalue; try discriminate.
    destruct (spec_value_fits_bits
      s
      (SpecTransformConstraint_Range_f_bits range_constraint)
      (SpecTransformProgram_f_field program)) eqn:Hbits; try discriminate.
    econstructor.
    + exact Hvalue.
    + exact Hbits.
Qed.

Lemma transform_check_constraint_complete_ok :
  forall program witness constraint constraint_index,
    TransformConstraintHolds program witness constraint ->
    transform_check_constraint constraint constraint_index program witness = Result_Ok tt.
Proof.
  intros program witness constraint constraint_index Hholds.
  destruct Hholds; simpl.
  - rewrite (transform_eval_expr_complete_ok
      witness
      (SpecTransformProgram_f_field program)
      (zero_spec_value tt)
      (SpecTransformConstraint_Equal_f_lhs equal_constraint)
      lhs_value); try assumption.
    rewrite (transform_eval_expr_complete_ok
      witness
      (SpecTransformProgram_f_field program)
      (zero_spec_value tt)
      (SpecTransformConstraint_Equal_f_rhs equal_constraint)
      rhs_value); try assumption.
    rewrite H1.
    reflexivity.
  - rewrite H.
    rewrite H0.
    reflexivity.
  - rewrite H.
    rewrite H0.
    reflexivity.
Qed.

Lemma transform_check_constraints_from_list_sound_ok :
  forall constraints constraint_index program witness,
    transform_check_constraints_from_list constraints constraint_index program witness = Result_Ok tt ->
    Forall (TransformConstraintHolds program witness) constraints.
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros constraint_index program witness Hcheck; simpl in Hcheck.
  - constructor.
  - destruct (transform_check_constraint constraint constraint_index program witness)
      as [u | error] eqn:Hconstraint; try discriminate.
    destruct u.
    constructor.
    + eapply transform_check_constraint_sound_ok.
      exact Hconstraint.
    + eapply IH.
      exact Hcheck.
Qed.

Lemma transform_check_constraints_from_list_complete_ok :
  forall constraints constraint_index program witness,
    Forall (TransformConstraintHolds program witness) constraints ->
    transform_check_constraints_from_list constraints constraint_index program witness = Result_Ok tt.
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros constraint_index program witness Hholds; inversion Hholds; subst; simpl.
  - reflexivity.
  - rewrite (transform_check_constraint_complete_ok
      program
      witness
      constraint
      constraint_index H1).
    eapply IH.
    exact H2.
Qed.

Theorem transform_check_program_sound_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    TransformProgramHolds program witness.
Proof.
  intros program witness Hcheck.
  unfold TransformProgramHolds.
  unfold transform_check_program in Hcheck.
  eapply transform_check_constraints_from_list_sound_ok.
  exact Hcheck.
Qed.

Lemma transform_check_program_complete_ok :
  forall program witness,
    TransformProgramHolds program witness ->
    transform_check_program program witness = Result_Ok tt.
Proof.
  intros program witness Hholds.
  unfold TransformProgramHolds in Hholds.
  unfold transform_check_program.
  eapply transform_check_constraints_from_list_complete_ok.
  exact Hholds.
Qed.

Definition transform_constraint_to_kernel_at
  (constraint : t_SpecTransformConstraint)
  (constraint_index : t_usize)
  (field : t_FieldId) : t_SpecKernelConstraint :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    SpecKernelConstraint_Equal
      {| SpecKernelConstraint_Equal_f_index := constraint_index;
         SpecKernelConstraint_Equal_f_lhs :=
           transform_expr_to_kernel
             (SpecTransformConstraint_Equal_f_lhs equal_constraint)
             field;
         SpecKernelConstraint_Equal_f_rhs :=
           transform_expr_to_kernel
             (SpecTransformConstraint_Equal_f_rhs equal_constraint)
             field |}
  | SpecTransformConstraint_Boolean boolean_constraint =>
    SpecKernelConstraint_Boolean
      {| SpecKernelConstraint_Boolean_f_index := constraint_index;
         SpecKernelConstraint_Boolean_f_signal :=
           SpecTransformConstraint_Boolean_f_signal_index boolean_constraint |}
  | SpecTransformConstraint_Range range_constraint =>
    SpecKernelConstraint_Range
      {| SpecKernelConstraint_Range_f_index := constraint_index;
         SpecKernelConstraint_Range_f_signal :=
           SpecTransformConstraint_Range_f_signal_index range_constraint;
         SpecKernelConstraint_Range_f_bits :=
           SpecTransformConstraint_Range_f_bits range_constraint |}
  end.

Lemma transform_constraint_to_kernel_sound_ok :
  forall program witness constraint constraint_index,
    TransformConstraintHolds program witness constraint ->
    ConstraintHolds
      (transform_program_to_kernel program)
      witness
      (transform_constraint_to_kernel_at
        constraint
        constraint_index
        (SpecTransformProgram_f_field program)).
Proof.
  intros program witness constraint constraint_index Hholds.
  destruct Hholds; simpl.
  - econstructor.
    + eapply transform_expr_to_kernel_sound_ok.
      exact H.
    + eapply transform_expr_to_kernel_sound_ok.
      exact H0.
    + exact H1.
  - econstructor.
    + rewrite transform_signal_value_eq_kernel_signal_value_ok in H.
      exact H.
    + exact H0.
  - econstructor.
    + rewrite transform_signal_value_eq_kernel_signal_value_ok in H.
      exact H.
    + exact H0.
Qed.

Lemma transform_constraints_to_kernel_from_list_sound_ok :
  forall constraints constraint_index kernel_constraints program witness,
    Forall (TransformConstraintHolds program witness) constraints ->
    Forall (ConstraintHolds (transform_program_to_kernel program) witness) kernel_constraints ->
    Forall
      (ConstraintHolds (transform_program_to_kernel program) witness)
      (transform_constraints_to_kernel_from_list
        constraints
        constraint_index
        kernel_constraints
        (SpecTransformProgram_f_field program)).
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros constraint_index kernel_constraints program witness Hholds Hkernel; simpl.
  - exact Hkernel.
  - inversion Hholds; subst.
    eapply IH.
    + exact H2.
    + unfold impl_1__push.
      apply Forall_app.
      split.
      * exact Hkernel.
      * constructor.
        -- eapply transform_constraint_to_kernel_sound_ok.
           exact H1.
        -- constructor.
Qed.

Lemma transform_program_holds_to_kernel_sound_ok :
  forall program witness,
    TransformProgramHolds program witness ->
    ProgramHolds (transform_program_to_kernel program) witness.
Proof.
  intros program witness Hholds.
  unfold TransformProgramHolds in Hholds.
  unfold ProgramHolds.
  unfold transform_program_to_kernel.
  simpl.
  eapply transform_constraints_to_kernel_from_list_sound_ok.
  - exact Hholds.
  - constructor.
Qed.

Theorem transform_program_to_kernel_sound_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    ProgramHolds (transform_program_to_kernel program) witness.
Proof.
  intros program witness Hcheck.
  eapply transform_program_holds_to_kernel_sound_ok.
  eapply transform_check_program_sound_ok.
  exact Hcheck.
Qed.

Lemma transform_expr_is_const_zero_eval_ok :
  forall expr witness field value,
    transform_expr_is_const_zero expr = true ->
    transform_eval_expr expr witness field = Result_Ok value ->
    value = zero_spec_value tt.
Proof.
  intros expr witness field value Hzero Heval.
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    simpl in Hzero; try discriminate.
  simpl in Heval.
  inversion Heval; subst.
  rewrite normalize_spec_value_zero_raw_ok by exact Hzero.
  reflexivity.
Qed.

Lemma transform_expr_is_const_one_eval_ok :
  forall expr witness field value,
    transform_expr_is_const_one expr = true ->
    transform_eval_expr expr witness field = Result_Ok value ->
    value = spec_field_value_of_z 1.
Proof.
  intros expr witness field value Hone Heval.
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    simpl in Hone; try discriminate.
  simpl in Heval.
  inversion Heval; subst.
  rewrite normalize_spec_value_one_raw_ok by exact Hone.
  reflexivity.
Qed.

Lemma div_spec_values_zero_l_ok :
  forall rhs field value,
    div_spec_values (zero_spec_value tt) rhs field = Option_Some value ->
    value = zero_spec_value tt.
Proof.
  intros rhs field value Hdiv.
  unfold div_spec_values, zero_spec_value, Div_f_div, zero in Hdiv.
  simpl in Hdiv.
  rewrite spec_normalize_z_zero in Hdiv by apply spec_field_modulus_positive.
  destruct (spec_mod_inverse
    (spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
    (spec_field_modulus field)) as [inverse|] eqn:Hinverse; try discriminate.
  inversion Hdiv; subst.
  unfold zero_spec_value, zero, spec_field_value_zero.
  f_equal.
  replace (spec_normalize_z 0 (spec_field_modulus field) * inverse) with 0 by
    (rewrite spec_normalize_z_zero by apply spec_field_modulus_positive; lia).
  apply spec_normalize_z_zero.
  apply spec_field_modulus_positive.
Qed.

Lemma spec_mod_inverse_one_ok :
  forall modulus,
    1 < modulus ->
    spec_mod_inverse 1 modulus = Some 1.
Proof.
  intros modulus Hmodulus.
  unfold spec_mod_inverse.
  remember (Z.ggcd 1 modulus) as ggcd eqn:Hggcd.
  destruct ggcd as [g [coefficient other]].
  assert (Hg : g = 1).
  {
    assert (Hfst : g = fst (Z.ggcd 1 modulus)).
    {
      rewrite <- Hggcd.
      reflexivity.
    }
    rewrite Z.ggcd_gcd in Hfst.
    rewrite Z.gcd_1_l in Hfst.
    exact Hfst.
  }
  pose proof (Z.ggcd_correct_divisors 1 modulus) as Hdivisors.
  rewrite <- Hggcd in Hdivisors.
  simpl in Hdivisors.
  destruct Hdivisors as [Hcoefficient _].
  rewrite Hg in Hcoefficient.
  ring_simplify in Hcoefficient.
  assert (Hcoefficient_one : coefficient = 1).
  {
    lia.
  }
  rewrite Hg.
  rewrite Hcoefficient_one.
  rewrite Z.eqb_refl.
  rewrite spec_normalize_z_one by exact Hmodulus.
  reflexivity.
Qed.

Lemma div_spec_values_one_r_ok :
  forall lhs field value,
    div_spec_values lhs (spec_field_value_of_z 1) field = Option_Some value ->
    value = normalize_spec_value lhs field.
Proof.
  intros lhs field value Hdiv.
  unfold div_spec_values, normalize_spec_value, Div_f_div, normalize in Hdiv.
  simpl in Hdiv.
  rewrite spec_normalize_z_one in Hdiv by apply spec_field_modulus_gt_one.
  rewrite spec_mod_inverse_one_ok in Hdiv by apply spec_field_modulus_gt_one.
  inversion Hdiv; subst.
  rewrite Z.mul_1_r.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma normalize_transform_expr_preserves_eval_ok :
  forall expr report report' normalized witness field value,
    normalize_transform_expr expr report = (report', normalized) ->
    transform_eval_expr expr witness field = Result_Ok value ->
    transform_eval_expr normalized witness field = Result_Ok value.
Proof.
  refine (
    fix normalize_expr_preserve
      (expr : t_SpecTransformExpr)
      : forall report report' normalized witness field value,
          normalize_transform_expr expr report = (report', normalized) ->
          transform_eval_expr expr witness field = Result_Ok value ->
          transform_eval_expr normalized witness field = Result_Ok value := _).
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    intros report report' normalized witness field value Hnormalize Heval.
  - simpl in Hnormalize.
    inversion Hnormalize; subst.
    exact Heval.
  - simpl in Hnormalize.
    inversion Hnormalize; subst.
    exact Heval.
  - simpl in Hnormalize.
    rewrite transform_eval_expr_add_as_list in Heval.
    change
      (match normalize_non_zero_values_from_list values report (impl__new tt) with
       | (report0, LIST_NIL) =>
           (normalization_report_inc_constant report0, zero_spec_expr tt)
       | (report0, [single]) =>
           (report0, single)
       | (report0, (single :: _ :: _) as non_zero) =>
           (if all_const_exprs_list non_zero
            then normalization_report_inc_constant report0
            else report0, SpecTransformExpr_Add non_zero)
       end = (report', normalized)) in Hnormalize.
    assert (
      forall values report prefix report' final_values acc mid final_value,
        normalize_non_zero_values_from_list values report prefix = (report', final_values) ->
        normalize acc field = acc ->
        transform_eval_exprs_list prefix witness field acc = Result_Ok mid ->
        transform_eval_exprs_list values witness field mid = Result_Ok final_value ->
        transform_eval_exprs_list final_values witness field acc = Result_Ok final_value
    ) as Hvalues_preserve.
    {
      intros list_values.
      induction list_values as [|value_expr remaining_values IH];
        intros report0 prefix report1 final_values acc mid final_value
          Hvalues Hacc Hprefix Heval_values;
        simpl in Hvalues.
      - inversion Hvalues; subst.
        simpl in Heval_values.
        inversion Heval_values; subst.
        exact Hprefix.
      - destruct (normalize_transform_expr value_expr report0)
          as [report2 normalized_value] eqn:Hvalue_normalized.
        destruct normalized_value as [const_expr | signal_expr | add_values | lhs rhs | lhs rhs | lhs rhs];
          simpl in Hvalues.
        + destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value const_expr))
            eqn:Hzero.
          * simpl in Heval_values.
            destruct (transform_eval_expr value_expr witness field)
              eqn:Hvalue_eval; try discriminate.
            pose proof (normalize_expr_preserve
              value_expr
              report0
              report2
              (SpecTransformExpr_Const const_expr)
              witness
              field
              s
              Hvalue_normalized
              Hvalue_eval) as Hnormalized_eval.
            simpl in Hnormalized_eval.
            rewrite normalize_spec_value_zero_raw_ok in Hnormalized_eval by exact Hzero.
            inversion Hnormalized_eval; subst; clear Hnormalized_eval.
            rewrite add_spec_values_zero_r_ok in Heval_values.
            pose proof (transform_eval_exprs_list_normalized_ok
              prefix witness field acc mid Hacc Hprefix) as Hmid.
            unfold normalize_spec_value in Heval_values.
            rewrite Hmid in Heval_values.
            eapply IH.
            -- exact Hvalues.
            -- exact Hacc.
            -- exact Hprefix.
            -- exact Heval_values.
          * simpl in Heval_values.
            destruct (transform_eval_expr value_expr witness field)
              eqn:Hvalue_eval; try discriminate.
            pose proof (normalize_expr_preserve
              value_expr
              report0
              report2
              (SpecTransformExpr_Const const_expr)
              witness
              field
              s
              Hvalue_normalized
              Hvalue_eval) as Hnormalized_eval.
            inversion Hnormalized_eval; subst s; clear Hnormalized_eval.
            eapply IH.
            -- exact Hvalues.
            -- exact Hacc.
            -- unfold impl_1__push.
               eapply transform_eval_exprs_list_app_ok.
               ++ exact Hprefix.
               ++ simpl.
                  reflexivity.
            -- exact Heval_values.
        + simpl in Heval_values.
          destruct (transform_eval_expr value_expr witness field)
            eqn:Hvalue_eval; try discriminate.
          pose proof (normalize_expr_preserve
            value_expr
            report0
            report2
            (SpecTransformExpr_Signal signal_expr)
            witness
            field
            s
            Hvalue_normalized
            Hvalue_eval) as Hnormalized_eval.
          eapply IH.
          * exact Hvalues.
          * exact Hacc.
          * unfold impl_1__push.
            eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- cbn [transform_eval_exprs_list].
               rewrite Hnormalized_eval.
               reflexivity.
          * exact Heval_values.
        + simpl in Heval_values.
          destruct (transform_eval_expr value_expr witness field)
            eqn:Hvalue_eval; try discriminate.
          pose proof (normalize_expr_preserve
            value_expr
            report0
            report2
            (SpecTransformExpr_Add add_values)
            witness
            field
            s
            Hvalue_normalized
            Hvalue_eval) as Hnormalized_eval.
          eapply IH.
          * exact Hvalues.
          * exact Hacc.
          * unfold impl_1__push.
            eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- cbn [transform_eval_exprs_list].
               rewrite Hnormalized_eval.
               reflexivity.
          * exact Heval_values.
        + simpl in Heval_values.
          destruct (transform_eval_expr value_expr witness field)
            eqn:Hvalue_eval; try discriminate.
          pose proof (normalize_expr_preserve
            value_expr
            report0
            report2
            (SpecTransformExpr_Sub lhs rhs)
            witness
            field
            s
            Hvalue_normalized
            Hvalue_eval) as Hnormalized_eval.
          eapply IH.
          * exact Hvalues.
          * exact Hacc.
          * unfold impl_1__push.
            eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- cbn [transform_eval_exprs_list].
               rewrite Hnormalized_eval.
               reflexivity.
          * exact Heval_values.
        + simpl in Heval_values.
          destruct (transform_eval_expr value_expr witness field)
            eqn:Hvalue_eval; try discriminate.
          pose proof (normalize_expr_preserve
            value_expr
            report0
            report2
            (SpecTransformExpr_Mul lhs rhs)
            witness
            field
            s
            Hvalue_normalized
            Hvalue_eval) as Hnormalized_eval.
          eapply IH.
          * exact Hvalues.
          * exact Hacc.
          * unfold impl_1__push.
            eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- cbn [transform_eval_exprs_list].
               rewrite Hnormalized_eval.
               reflexivity.
          * exact Heval_values.
        + simpl in Heval_values.
          destruct (transform_eval_expr value_expr witness field)
            eqn:Hvalue_eval; try discriminate.
          pose proof (normalize_expr_preserve
            value_expr
            report0
            report2
            (SpecTransformExpr_Div lhs rhs)
            witness
            field
            s
            Hvalue_normalized
            Hvalue_eval) as Hnormalized_eval.
          eapply IH.
          * exact Hvalues.
          * exact Hacc.
          * unfold impl_1__push.
            eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- cbn [transform_eval_exprs_list].
               rewrite Hnormalized_eval.
               reflexivity.
          * exact Heval_values.
    }
    remember (normalize_non_zero_values_from_list values report (impl__new tt))
      as normalized_values eqn:Hvalues.
    destruct normalized_values as [report1 non_zero].
    destruct non_zero as [|single remaining_values].
    + symmetry in Hnormalize.
      injection Hnormalize as Hreport Hnormalized.
      subst report' normalized.
      pose proof (Hvalues_preserve
        values
        report
        (impl__new tt)
        report1
        []
        (zero_spec_value tt)
        (zero_spec_value tt)
        value
        (eq_sym Hvalues)
        (zero_spec_value_normalized_ok field)
        eq_refl
        Heval) as Hempty.
      simpl in Hempty.
      simpl.
      rewrite zero_spec_value_normalized_ok.
      exact Hempty.
    + destruct remaining_values as [|second remaining_values].
      * symmetry in Hnormalize.
        injection Hnormalize as Hreport Hnormalized.
        subst report' normalized.
        pose proof (Hvalues_preserve
          values
          report
          (impl__new tt)
          report1
          [single]
          (zero_spec_value tt)
          (zero_spec_value tt)
          value
          (eq_sym Hvalues)
          (zero_spec_value_normalized_ok field)
          eq_refl
          Heval) as Hsingle_list.
        simpl in Hsingle_list.
        destruct (transform_eval_expr single witness field) eqn:Hsingle_eval;
          try discriminate.
        rewrite add_spec_values_zero_l_ok in Hsingle_list.
        unfold normalize_spec_value in Hsingle_list.
        rewrite (transform_eval_expr_normalized_ok
          single witness field s Hsingle_eval) in Hsingle_list.
        exact Hsingle_list.
      * symmetry in Hnormalize.
        injection Hnormalize as Hreport Hnormalized.
        subst report' normalized.
        rewrite transform_eval_expr_add_as_list.
        eapply Hvalues_preserve.
        -- exact (eq_sym Hvalues).
        -- apply zero_spec_value_normalized_ok.
        -- reflexivity.
        -- exact Heval.
  - simpl in Hnormalize.
    destruct (normalize_transform_expr lhs report)
      as [report1 normalized_lhs] eqn:Hlhs_normalized.
    destruct (normalize_transform_expr rhs report1)
      as [report2 normalized_rhs] eqn:Hrhs_normalized.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct (transform_expr_is_const_zero normalized_rhs) eqn:Hzero_rhs.
    + inversion Hnormalize; subst; clear Hnormalize.
      pose proof (normalize_expr_preserve
        rhs report1 report2 normalized_rhs witness field s0 Hrhs_normalized Hrhs_eval)
        as Hrhs_preserved.
      pose proof (transform_expr_is_const_zero_eval_ok
        normalized_rhs witness field s0 Hzero_rhs Hrhs_preserved) as Hrhs_zero.
      rewrite Hrhs_zero in Heval.
      rewrite sub_spec_values_zero_r_ok in Heval.
      unfold normalize_spec_value in Heval.
      rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
      apply result_ok_injective in Heval.
      subst value.
      eapply normalize_expr_preserve.
      * exact Hlhs_normalized.
      * exact Hlhs_eval.
    + inversion Hnormalize; subst; clear Hnormalize.
      pose proof (normalize_expr_preserve
        lhs _ _ _ witness field s Hlhs_normalized Hlhs_eval) as Hlhs_preserved.
      pose proof (normalize_expr_preserve
        rhs _ _ _ witness field s0 Hrhs_normalized Hrhs_eval) as Hrhs_preserved.
      simpl.
      rewrite Hlhs_preserved.
      rewrite Hrhs_preserved.
      exact Heval.
  - simpl in Hnormalize.
    destruct (normalize_transform_expr lhs report)
      as [report1 normalized_lhs] eqn:Hlhs_normalized.
    destruct (normalize_transform_expr rhs report1)
      as [report2 normalized_rhs] eqn:Hrhs_normalized.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct (transform_expr_is_const_one normalized_lhs) eqn:Hone_lhs.
    + inversion Hnormalize; subst; clear Hnormalize.
      pose proof (normalize_expr_preserve
        lhs report report1 normalized_lhs witness field s Hlhs_normalized Hlhs_eval)
        as Hlhs_preserved.
      pose proof (transform_expr_is_const_one_eval_ok
        normalized_lhs witness field s Hone_lhs Hlhs_preserved) as Hlhs_one.
      rewrite Hlhs_one in Heval.
      rewrite mul_spec_values_one_l_ok in Heval.
      unfold normalize_spec_value in Heval.
      rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
      apply result_ok_injective in Heval.
      subst value.
      eapply normalize_expr_preserve.
      * exact Hrhs_normalized.
      * exact Hrhs_eval.
    + destruct (transform_expr_is_const_one normalized_rhs) eqn:Hone_rhs.
      * inversion Hnormalize; subst; clear Hnormalize.
        pose proof (normalize_expr_preserve
          rhs report1 report2 normalized_rhs witness field s0 Hrhs_normalized Hrhs_eval)
          as Hrhs_preserved.
        pose proof (transform_expr_is_const_one_eval_ok
          normalized_rhs witness field s0 Hone_rhs Hrhs_preserved) as Hrhs_one.
        rewrite Hrhs_one in Heval.
        rewrite mul_spec_values_one_r_ok in Heval.
        unfold normalize_spec_value in Heval.
        rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
        apply result_ok_injective in Heval.
        subst value.
        eapply normalize_expr_preserve.
        -- exact Hlhs_normalized.
        -- exact Hlhs_eval.
      * destruct (transform_expr_is_const_zero normalized_lhs) eqn:Hzero_lhs.
        -- inversion Hnormalize; subst; clear Hnormalize.
           pose proof (normalize_expr_preserve
             lhs report report1 normalized_lhs witness field s Hlhs_normalized Hlhs_eval)
             as Hlhs_preserved.
           pose proof (transform_expr_is_const_zero_eval_ok
             normalized_lhs witness field s Hzero_lhs Hlhs_preserved) as Hlhs_zero.
           rewrite Hlhs_zero in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (transform_expr_is_const_zero normalized_rhs) eqn:Hzero_rhs.
           ++ inversion Hnormalize; subst; clear Hnormalize.
              pose proof (normalize_expr_preserve
                rhs report1 report2 normalized_rhs witness field s0 Hrhs_normalized Hrhs_eval)
                as Hrhs_preserved.
              pose proof (transform_expr_is_const_zero_eval_ok
                normalized_rhs witness field s0 Hzero_rhs Hrhs_preserved) as Hrhs_zero.
              rewrite Hrhs_zero in Heval.
              rewrite mul_spec_values_zero_r_ok in Heval.
              simpl.
              rewrite zero_spec_value_normalized_ok.
              exact Heval.
           ++ inversion Hnormalize; subst; clear Hnormalize.
              pose proof (normalize_expr_preserve
                lhs _ _ _ witness field s Hlhs_normalized Hlhs_eval) as Hlhs_preserved.
              pose proof (normalize_expr_preserve
                rhs _ _ _ witness field s0 Hrhs_normalized Hrhs_eval) as Hrhs_preserved.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
  - simpl in Hnormalize.
    destruct (normalize_transform_expr lhs report)
      as [report1 normalized_lhs] eqn:Hlhs_normalized.
    destruct (normalize_transform_expr rhs report1)
      as [report2 normalized_rhs] eqn:Hrhs_normalized.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct (transform_expr_is_const_one normalized_rhs) eqn:Hone_rhs.
    + inversion Hnormalize; subst; clear Hnormalize.
      pose proof (normalize_expr_preserve
        rhs report1 report2 normalized_rhs witness field s0 Hrhs_normalized Hrhs_eval)
        as Hrhs_preserved.
      pose proof (transform_expr_is_const_one_eval_ok
        normalized_rhs witness field s0 Hone_rhs Hrhs_preserved) as Hrhs_one.
      rewrite Hrhs_one in Heval.
      destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
      apply div_spec_values_one_r_ok in Hdiv.
      rewrite Hdiv in Heval.
      unfold normalize_spec_value in Heval.
      rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
      apply result_ok_injective in Heval.
      subst value.
      eapply normalize_expr_preserve.
      * exact Hlhs_normalized.
      * exact Hlhs_eval.
    + destruct (transform_expr_is_const_zero normalized_lhs) eqn:Hzero_lhs.
      * inversion Hnormalize; subst; clear Hnormalize.
        pose proof (normalize_expr_preserve
          lhs report report1 normalized_lhs witness field s Hlhs_normalized Hlhs_eval)
          as Hlhs_preserved.
        pose proof (transform_expr_is_const_zero_eval_ok
          normalized_lhs witness field s Hzero_lhs Hlhs_preserved) as Hlhs_zero.
        rewrite Hlhs_zero in Heval.
        destruct (div_spec_values (zero_spec_value tt) s0 field) eqn:Hdiv; try discriminate.
        apply div_spec_values_zero_l_ok in Hdiv.
        rewrite Hdiv in Heval.
        simpl.
        rewrite zero_spec_value_normalized_ok.
        exact Heval.
      * inversion Hnormalize; subst; clear Hnormalize.
        pose proof (normalize_expr_preserve
          lhs _ _ _ witness field s Hlhs_normalized Hlhs_eval) as Hlhs_preserved.
        pose proof (normalize_expr_preserve
          rhs _ _ _ witness field s0 Hrhs_normalized Hrhs_eval) as Hrhs_preserved.
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
Qed.

Lemma normalize_transform_constraint_preserves_holds_ok :
  forall constraint report report' normalized_constraint program witness,
    normalize_transform_constraint constraint report = (report', normalized_constraint) ->
    TransformConstraintHolds program witness constraint ->
    TransformConstraintHolds program witness normalized_constraint.
Proof.
  intros constraint report report' normalized_constraint program witness Hnormalize Hholds.
  destruct constraint as [equal_constraint | boolean_constraint | range_constraint];
    simpl in Hnormalize.
  - destruct (normalize_transform_expr
      (SpecTransformConstraint_Equal_f_lhs equal_constraint) report)
      as [report1 lhs] eqn:Hlhs_normalized.
    destruct (normalize_transform_expr
      (SpecTransformConstraint_Equal_f_rhs equal_constraint) report1)
      as [report2 rhs] eqn:Hrhs_normalized.
    inversion Hnormalize; subst; clear Hnormalize.
    inversion Hholds as
      [equal_constraint0 lhs_value rhs_value Hlhs_hold Hrhs_hold Hequal
      | | ]; subst.
    econstructor.
    + eapply transform_eval_expr_sound_ok.
      eapply normalize_transform_expr_preserves_eval_ok.
      * exact Hlhs_normalized.
      * eapply transform_eval_expr_complete_ok.
        exact Hlhs_hold.
    + eapply transform_eval_expr_sound_ok.
      eapply normalize_transform_expr_preserves_eval_ok.
      * exact Hrhs_normalized.
      * eapply transform_eval_expr_complete_ok.
        exact Hrhs_hold.
    + exact Hequal.
  - inversion Hnormalize; subst.
    exact Hholds.
  - inversion Hnormalize; subst.
    exact Hholds.
Qed.

Lemma normalize_constraints_from_list_preserves_holds_ok :
  forall constraints report normalized_constraints report' final_constraints program witness,
    normalize_constraints_from_list constraints report normalized_constraints =
      (report', final_constraints) ->
    Forall (TransformConstraintHolds program witness) normalized_constraints ->
    Forall (TransformConstraintHolds program witness) constraints ->
    Forall (TransformConstraintHolds program witness) final_constraints.
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros report normalized_constraints report' final_constraints program witness
      Hnormalize Hnormalized Hholds;
    simpl in Hnormalize.
  - inversion Hnormalize; subst.
    exact Hnormalized.
  - inversion Hholds; subst.
    destruct (normalize_transform_constraint constraint report)
      as [report1 normalized_constraint] eqn:Hconstraint_normalized.
    eapply IH.
    + exact Hnormalize.
    + unfold impl_1__push.
      apply Forall_app.
      split.
      * exact Hnormalized.
      * constructor.
        -- eapply normalize_transform_constraint_preserves_holds_ok.
           ++ exact Hconstraint_normalized.
           ++ exact H1.
        -- constructor.
    + exact H2.
Qed.

Lemma insert_constraint_sorted_from_list_preserves_holds_ok :
  forall constraint sorted inserted result program witness,
    TransformConstraintHolds program witness constraint ->
    Forall (TransformConstraintHolds program witness) result ->
    Forall (TransformConstraintHolds program witness) sorted ->
    Forall
      (TransformConstraintHolds program witness)
      (insert_constraint_sorted_from_list constraint sorted inserted result).
Proof.
  induction sorted as [|item remaining_sorted IH];
    intros inserted result program witness Hconstraint Hresult Hsorted;
    simpl.
  - destruct inserted.
    + exact Hresult.
    + unfold impl_1__push.
      apply Forall_app.
      split.
      * exact Hresult.
      * constructor.
        -- exact Hconstraint.
        -- constructor.
  - inversion Hsorted; subst.
    destruct (andb (negb inserted) (constraint_order_lt constraint item)) eqn:Hinsert.
    + eapply IH.
      * exact Hconstraint.
      * repeat unfold impl_1__push.
        apply Forall_app.
        split.
        -- apply Forall_app.
           split.
           ++ exact Hresult.
           ++ constructor.
              ** exact Hconstraint.
              ** constructor.
        -- constructor.
           ++ exact H1.
           ++ constructor.
      * exact H2.
    + eapply IH.
      * exact Hconstraint.
      * unfold impl_1__push.
        apply Forall_app.
        split.
        -- exact Hresult.
        -- constructor.
           ++ exact H1.
           ++ constructor.
      * exact H2.
Qed.

Lemma sort_constraints_by_key_list_preserves_holds_ok :
  forall constraints program witness,
    Forall (TransformConstraintHolds program witness) constraints ->
    Forall
      (TransformConstraintHolds program witness)
      (sort_constraints_by_key_list constraints).
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros program witness Hholds; simpl.
  - constructor.
  - inversion Hholds; subst.
    eapply insert_constraint_sorted_from_list_preserves_holds_ok.
    + exact H1.
    + constructor.
    + eapply IH.
      exact H2.
Qed.

Lemma transform_constraint_holds_field_irrelevant_ok :
  forall program_from program_to witness constraint,
    SpecTransformProgram_f_field program_from =
      SpecTransformProgram_f_field program_to ->
    TransformConstraintHolds program_from witness constraint ->
    TransformConstraintHolds program_to witness constraint.
Proof.
  intros program_from program_to witness constraint Hfield Hholds.
  destruct Hholds.
  - econstructor.
    + rewrite <- Hfield.
      exact H.
    + rewrite <- Hfield.
      exact H0.
    + rewrite <- Hfield.
      exact H1.
  - econstructor.
    + rewrite <- Hfield.
      exact H.
    + rewrite <- Hfield.
      exact H0.
  - econstructor.
    + rewrite <- Hfield.
      exact H.
    + rewrite <- Hfield.
      exact H0.
Qed.

Lemma forall_transform_constraint_holds_field_irrelevant_ok :
  forall constraints program_from program_to witness,
    SpecTransformProgram_f_field program_from =
      SpecTransformProgram_f_field program_to ->
    Forall (TransformConstraintHolds program_from witness) constraints ->
    Forall (TransformConstraintHolds program_to witness) constraints.
Proof.
  intros constraints program_from program_to witness Hfield Hholds.
  induction Hholds.
  - constructor.
  - constructor.
    + eapply transform_constraint_holds_field_irrelevant_ok.
      * exact Hfield.
      * exact H.
    + exact IHHholds.
Qed.

Theorem normalize_supported_program_preserves_checks_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    transform_check_program (normalize_program_output program) witness = Result_Ok tt.
Proof.
  intros program witness Hcheck.
  apply transform_check_program_complete_ok.
  unfold normalize_program_output, normalize_supported_program.
  simpl.
  remember
    (normalize_constraints_from_list
      (SpecTransformProgram_f_constraints program)
      empty_normalization_report
      (impl__new tt)) as normalized eqn:Hnormalized_constraints.
  destruct normalized as [report1 normalized_constraints].
  remember (referenced_signal_indices program (Build_t_Slice _ normalized_constraints))
    as referenced.
  remember
    (filter_live_signals_for_normalization_from_list
      (SpecTransformProgram_f_signals program)
      referenced
      report1
      (impl__new tt)) as filtered eqn:Hfiltered.
  destruct filtered as [report2 live_signals].
  eapply forall_transform_constraint_holds_field_irrelevant_ok
    with (program_from := program).
  - simpl.
    reflexivity.
  - eapply sort_constraints_by_key_list_preserves_holds_ok.
    eapply normalize_constraints_from_list_preserves_holds_ok.
    + exact (eq_sym Hnormalized_constraints).
    + constructor.
    + eapply transform_check_program_sound_ok.
      exact Hcheck.
Qed.

Lemma spec_normalize_z_eq_mod :
  forall value modulus,
    0 < modulus ->
    spec_normalize_z value modulus = value mod modulus.
Proof.
  intros value modulus Hmodulus.
  unfold spec_normalize_z.
  replace (value mod modulus + modulus) with
    (value mod modulus + 1 * modulus) by lia.
  rewrite Z.mod_add by lia.
  apply Z.mod_small.
  apply Z.mod_pos_bound.
  exact Hmodulus.
Qed.

Lemma normalize_spec_value_to_z_ok :
  forall value field,
    spec_field_value_to_z (normalize_spec_value value field) =
      spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field).
Proof.
  intros value field.
  unfold normalize_spec_value, normalize.
  rewrite spec_field_value_of_z_roundtrip_ok.
  - reflexivity.
  - eapply spec_normalize_z_fits_32_bytes.
    + apply spec_field_modulus_positive.
    + apply spec_field_modulus_fits_32_bytes.
Qed.

Lemma add_spec_values_to_z_ok :
  forall lhs rhs field,
    spec_field_value_to_z (add_spec_values lhs rhs field) =
      spec_normalize_z
        (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field) +
         spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field))
        (spec_field_modulus field).
Proof.
  intros lhs rhs field.
  unfold add_spec_values, Add_f_add.
  rewrite spec_field_value_of_z_roundtrip_ok.
  - reflexivity.
  - eapply spec_normalize_z_fits_32_bytes.
    + apply spec_field_modulus_positive.
    + apply spec_field_modulus_fits_32_bytes.
Qed.

Lemma add_spec_values_normalize_l_ok :
  forall lhs rhs field,
    add_spec_values (normalize_spec_value lhs field) rhs field =
      add_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold add_spec_values, Add_f_add.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma add_spec_values_normalize_r_ok :
  forall lhs rhs field,
    add_spec_values lhs (normalize_spec_value rhs field) field =
      add_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold add_spec_values, Add_f_add.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma normalize_spec_value_idempotent_ok :
  forall value field,
    normalize_spec_value (normalize_spec_value value field) field =
      normalize_spec_value value field.
Proof.
  intros value field.
  unfold normalize_spec_value, normalize.
  rewrite spec_field_value_of_z_roundtrip_ok.
  2:{
    eapply spec_normalize_z_fits_32_bytes.
    - apply spec_field_modulus_positive.
    - apply spec_field_modulus_fits_32_bytes.
  }
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma sub_spec_values_normalize_l_ok :
  forall lhs rhs field,
    sub_spec_values (normalize_spec_value lhs field) rhs field =
      sub_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold sub_spec_values, Sub_f_sub.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma sub_spec_values_normalize_r_ok :
  forall lhs rhs field,
    sub_spec_values lhs (normalize_spec_value rhs field) field =
      sub_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold sub_spec_values, Sub_f_sub.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_normalize_l_ok :
  forall lhs rhs field,
    mul_spec_values (normalize_spec_value lhs field) rhs field =
      mul_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold mul_spec_values, Mul_f_mul.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma mul_spec_values_normalize_r_ok :
  forall lhs rhs field,
    mul_spec_values lhs (normalize_spec_value rhs field) field =
      mul_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold mul_spec_values, Mul_f_mul.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma div_spec_values_normalize_l_ok :
  forall lhs rhs field,
    div_spec_values (normalize_spec_value lhs field) rhs field =
      div_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold div_spec_values, Div_f_div.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma div_spec_values_normalize_r_ok :
  forall lhs rhs field,
    div_spec_values lhs (normalize_spec_value rhs field) field =
      div_spec_values lhs rhs field.
Proof.
  intros lhs rhs field.
  unfold div_spec_values, Div_f_div.
  rewrite normalize_spec_value_to_z_ok.
  rewrite spec_normalize_z_idempotent by apply spec_field_modulus_positive.
  reflexivity.
Qed.

Lemma add_spec_values_comm_ok :
  forall lhs rhs field,
    add_spec_values lhs rhs field = add_spec_values rhs lhs field.
Proof.
  intros lhs rhs field.
  unfold add_spec_values, Add_f_add.
  repeat rewrite spec_normalize_z_eq_mod by apply spec_field_modulus_positive.
  f_equal.
  rewrite Z.add_comm.
  reflexivity.
Qed.

Lemma add_spec_values_assoc_ok :
  forall lhs mid rhs field,
    add_spec_values (add_spec_values lhs mid field) rhs field =
      add_spec_values lhs (add_spec_values mid rhs field) field.
Proof.
  intros lhs mid rhs field.
  pose proof (spec_field_modulus_positive field) as Hmodulus.
  assert (Hmodulus_nonzero : spec_field_modulus field <> 0) by lia.
  change
    (Add_f_add (add_spec_values lhs mid field) rhs field =
     Add_f_add lhs (add_spec_values mid rhs field) field).
  unfold Add_f_add.
  rewrite add_spec_values_to_z_ok.
  rewrite add_spec_values_to_z_ok.
  repeat rewrite spec_normalize_z_eq_mod by exact Hmodulus.
  f_equal.
  repeat rewrite Z.mod_mod by exact Hmodulus_nonzero.
  rewrite <- (Z.add_mod
    ((spec_field_value_to_z lhs) mod spec_field_modulus field +
     (spec_field_value_to_z mid) mod spec_field_modulus field)
    (spec_field_value_to_z rhs)
    (spec_field_modulus field)
    Hmodulus_nonzero).
  replace
    (((spec_field_value_to_z lhs) mod spec_field_modulus field +
      ((spec_field_value_to_z mid) mod spec_field_modulus field +
       (spec_field_value_to_z rhs) mod spec_field_modulus field) mod
        spec_field_modulus field) mod spec_field_modulus field)
    with
      (((spec_field_value_to_z lhs) mod spec_field_modulus field +
        (((spec_field_value_to_z mid) mod spec_field_modulus field +
          (spec_field_value_to_z rhs) mod spec_field_modulus field) mod
           spec_field_modulus field) mod spec_field_modulus field) mod
       spec_field_modulus field)
    by (rewrite Z.mod_mod by exact Hmodulus_nonzero; reflexivity).
  rewrite <- (Z.add_mod
    (spec_field_value_to_z lhs)
    (((spec_field_value_to_z mid) mod spec_field_modulus field +
      (spec_field_value_to_z rhs) mod spec_field_modulus field) mod
       spec_field_modulus field)
    (spec_field_modulus field)
    Hmodulus_nonzero).
  rewrite <- (Z.add_mod
    (spec_field_value_to_z mid)
    (spec_field_value_to_z rhs)
    (spec_field_modulus field)
    Hmodulus_nonzero).
  replace
    ((spec_field_value_to_z lhs) mod spec_field_modulus field +
     (spec_field_value_to_z mid) mod spec_field_modulus field +
     spec_field_value_to_z rhs)
    with
      ((spec_field_value_to_z lhs) mod spec_field_modulus field +
       ((spec_field_value_to_z mid) mod spec_field_modulus field +
        spec_field_value_to_z rhs))
    by lia.
  rewrite <- Z.add_mod_idemp_r by exact Hmodulus_nonzero.
  rewrite Z.add_mod_idemp_l by exact Hmodulus_nonzero.
  rewrite Z.add_mod_idemp_l by exact Hmodulus_nonzero.
  reflexivity.
Qed.

Lemma transform_eval_exprs_list_shift_ok :
  forall values witness field base acc value,
    normalize acc field = acc ->
    transform_eval_exprs_list values witness field base = Result_Ok value ->
    transform_eval_exprs_list values witness field (add_spec_values acc base field) =
      Result_Ok (add_spec_values acc value field).
Proof.
  induction values as [|expr remaining_values IH];
    intros witness field base acc value Hacc Heval;
    simpl in Heval.
  - inversion Heval; subst.
    reflexivity.
  - destruct (transform_eval_expr expr witness field) eqn:Hexpr; try discriminate.
    simpl.
    rewrite Hexpr.
    replace
      (add_spec_values (add_spec_values acc base field) s field)
      with
      (add_spec_values acc (add_spec_values base s field) field)
      by (symmetry; apply add_spec_values_assoc_ok).
    eapply IH.
    + exact Hacc.
    + exact Heval.
Qed.

Lemma transform_eval_exprs_list_move_acc_to_end_ok :
  forall values witness field acc const_value final_value,
    normalize acc field = acc ->
    transform_eval_exprs_list values witness field (add_spec_values acc const_value field) =
      Result_Ok final_value ->
    transform_eval_exprs_list
      (values ++
        [SpecTransformExpr_Const
          {| SpecTransformExpr_Const_f_value := const_value;
             SpecTransformExpr_Const_f_sort_key := (0 : t_usize) |}])
      witness
      field
      acc = Result_Ok final_value.
Proof.
  induction values as [|expr remaining_values IH];
    intros witness field acc const_value final_value Hacc Heval.
  - simpl in Heval.
    inversion Heval; subst.
    simpl.
    rewrite add_spec_values_normalize_r_ok.
    reflexivity.
  - simpl in Heval.
    destruct (transform_eval_expr expr witness field) eqn:Hexpr; try discriminate.
    simpl.
    rewrite Hexpr.
    replace
      (add_spec_values (add_spec_values acc const_value field) s field)
      with
      (add_spec_values (add_spec_values acc s field) const_value field)
      in Heval.
    2:{
      transitivity (add_spec_values acc (add_spec_values s const_value field) field).
      - exact (add_spec_values_assoc_ok acc s const_value field).
      - rewrite (add_spec_values_comm_ok s const_value field).
        symmetry.
        exact (add_spec_values_assoc_ok acc const_value s field).
    }
    eapply IH.
    + apply add_output_canonical_ok.
    + exact Heval.
Qed.

Lemma append_transform_exprs_list_app_eq :
  forall target values,
    append_transform_exprs_list target values = target ++ values.
Proof.
  intros target values.
  induction values as [|value remaining_values IH] in target |- *; simpl.
  - rewrite app_nil_r.
    reflexivity.
  - rewrite IH.
    unfold impl_1__push.
    rewrite <- app_assoc.
    reflexivity.
Qed.

Lemma fold_terms_matches_fold_add_terms_from_list_ok :
  forall values field folded_nodes const_acc saw_const terms,
    (fix fold_terms
      (values : t_LIST t_SpecTransformExpr)
      (folded_nodes : t_usize)
      (const_acc : t_SpecFieldValue)
      (saw_const : bool)
      (terms : t_Vec ((t_SpecTransformExpr)) ((t_Global))) {struct values}
      : t_usize * (t_SpecFieldValue * bool * t_Vec ((t_SpecTransformExpr)) ((t_Global))) :=
      match values with
      | [] =>
        (folded_nodes, (const_acc, saw_const, terms))
      | value :: remaining_values =>
        let '(folded_nodes0, folded) :=
          fold_transform_expr value field folded_nodes in
        let '(folded_nodes1, const_acc0, saw_const0, terms0) :=
          match folded with
          | SpecTransformExpr_Const const_expr =>
            ( f_add folded_nodes0 (1 : t_usize),
              add_spec_values const_acc (SpecTransformExpr_Const_f_value const_expr) field,
              true,
              terms)
          | SpecTransformExpr_Add nested =>
            ( f_add folded_nodes0 (1 : t_usize),
              const_acc,
              saw_const,
              append_transform_exprs_list terms nested)
          | _ =>
            (folded_nodes0, const_acc, saw_const, impl_1__push terms folded)
          end in
        fold_terms remaining_values folded_nodes1 const_acc0 saw_const0 terms0
      end)
      values
      folded_nodes
      const_acc
      saw_const
      terms =
    fold_add_terms_from_list values field folded_nodes const_acc saw_const terms.
Proof.
  induction values as [|value remaining_values IH];
    intros field folded_nodes const_acc saw_const terms;
    simpl.
  - reflexivity.
  - destruct (fold_transform_expr value field folded_nodes)
      as [folded_nodes_step folded_value] eqn:Hfolded_step.
    destruct folded_value as
      [const_folded | signal_folded | add_folded | sub_lhs sub_rhs
      | mul_lhs mul_rhs | div_lhs div_rhs];
      simpl;
      apply IH.
Qed.

Lemma fold_add_terms_from_list_true_stays_true_ok :
  forall values field folded_nodes const_acc terms
         folded_nodes' final_const final_saw_const final_terms,
    fold_add_terms_from_list values field folded_nodes const_acc true terms =
      (folded_nodes', (final_const, final_saw_const, final_terms)) ->
    final_saw_const = true.
Proof.
  induction values as [|value remaining_values IH];
    intros field folded_nodes const_acc terms
      folded_nodes' final_const final_saw_const final_terms Hfold;
    simpl in Hfold.
  - inversion Hfold; subst.
    reflexivity.
  - destruct (fold_transform_expr value field folded_nodes)
      as [folded_nodes_step folded_value] eqn:Hvalue_folded.
    destruct folded_value as
      [const_folded | signal_folded | add_folded | sub_lhs sub_rhs
      | mul_lhs mul_rhs | div_lhs div_rhs];
      simpl in Hfold;
      eapply IH;
      exact Hfold.
Qed.

Lemma fold_add_terms_from_list_no_const_preserves_acc_ok :
  forall values field folded_nodes const_acc terms
         folded_nodes' final_const final_terms,
    fold_add_terms_from_list values field folded_nodes const_acc false terms =
      (folded_nodes', (final_const, false, final_terms)) ->
    final_const = const_acc.
Proof.
  induction values as [|value remaining_values IH];
    intros field folded_nodes const_acc terms
      folded_nodes' final_const final_terms Hfold;
    simpl in Hfold.
  - inversion Hfold; subst.
    reflexivity.
  - destruct (fold_transform_expr value field folded_nodes)
      as [folded_nodes_step folded_value] eqn:Hvalue_folded.
    destruct folded_value as
      [const_folded | signal_folded | add_folded | sub_lhs sub_rhs
      | mul_lhs mul_rhs | div_lhs div_rhs];
      simpl in Hfold.
    + pose proof (fold_add_terms_from_list_true_stays_true_ok
        remaining_values
        field
        (f_add folded_nodes_step (1 : t_usize))
        (add_spec_values const_acc (SpecTransformExpr_Const_f_value const_folded) field)
        terms
        folded_nodes'
        final_const
        false
        final_terms
        Hfold) as Hsaw_const.
      discriminate.
    + eapply IH.
      exact Hfold.
    + eapply IH.
      exact Hfold.
    + eapply IH.
      exact Hfold.
    + eapply IH.
      exact Hfold.
    + eapply IH.
      exact Hfold.
Qed.

Lemma fold_transform_expr_add_from_list_ok :
  forall values field folded_nodes,
    fold_transform_expr (SpecTransformExpr_Add values) field folded_nodes =
      let '(folded_nodes1, (const_acc, saw_const, terms)) :=
        fold_add_terms_from_list
          values
          field
          folded_nodes
          (zero_spec_value tt)
          false
          (impl__new tt) in
      let terms :=
        if andb saw_const (negb (spec_value_is_zero_raw const_acc)) then
          impl_1__push terms (make_const_expr const_acc (0 : t_usize))
        else
          terms in
      match terms with
      | [] =>
        (folded_nodes1, zero_spec_expr tt)
      | [single] =>
        (folded_nodes1, single)
      | _ =>
        (folded_nodes1, SpecTransformExpr_Add terms)
      end.
Proof.
  intros values field folded_nodes.
  unfold fold_transform_expr at 1.
  fold fold_transform_expr.
  rewrite fold_terms_matches_fold_add_terms_from_list_ok.
  reflexivity.
Qed.

Local Ltac pose_fold_expr_preserve_from_eq pf Hname witness value Hfolded Heval :=
  lazymatch type of Hfolded with
  | fold_transform_expr ?expr ?field ?folded_nodes_in = (?folded_nodes_out, ?folded_expr) =>
      pose proof (pf
        expr field folded_nodes_in folded_nodes_out folded_expr
        witness value Hfolded Heval) as Hname
  end.

Local Ltac change_mul_goal_from_fold_eq :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr _ _ _ = (_, ?folded_lhs),
      Hrhs_folded : fold_transform_expr _ _ _ = (_, ?folded_rhs)
      |- transform_eval_expr _ ?w ?f = Result_Ok ?v ] =>
      change (transform_eval_expr (SpecTransformExpr_Mul folded_lhs folded_rhs) w f = Result_Ok v)
  end.

Local Ltac change_div_goal_from_fold_eq :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, ?folded_rhs)
      |- transform_eval_expr _ ?w ?f = Result_Ok ?v ] =>
      change (transform_eval_expr (SpecTransformExpr_Div folded_lhs folded_rhs) w f = Result_Ok v)
  end.

Local Ltac solve_mul_nonconst_pair fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, ?folded_rhs),
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ |- _ ] =>
      simpl in Hfold;
      injection Hfold as Hfold_nodes Hfold_expr;
      subst;
      clear Hfold;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      change_mul_goal_from_fold_eq;
      simpl;
      rewrite Hlhs_preserved;
      rewrite Hrhs_preserved;
      exact Heval
  end.

Local Ltac solve_mul_lhs_const_generic_rhs fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, SpecTransformExpr_Const ?lhs_const),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, ?folded_rhs),
      Hzero_lhs : spec_value_is_zero_raw _ = false,
      Hone_lhs : spec_value_is_one_raw _ = false,
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ |- _ ] =>
      rewrite Hzero_lhs in Hfold;
      rewrite Hone_lhs in Hfold;
      simpl in Hfold;
      inversion Hfold; subst;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      apply result_ok_injective in Hlhs_preserved;
      change_mul_goal_from_fold_eq;
      simpl;
      rewrite Hrhs_preserved;
      rewrite Hlhs_preserved;
      exact Heval
  end.

Local Ltac solve_mul_rhs_const_generic_lhs fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, SpecTransformExpr_Const ?rhs_const),
      Hzero_rhs : spec_value_is_zero_raw _ = false,
      Hone_rhs : spec_value_is_one_raw _ = false,
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ |- _ ] =>
      rewrite Hzero_rhs in Hfold;
      rewrite Hone_rhs in Hfold;
      simpl in Hfold;
      inversion Hfold; subst;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      apply result_ok_injective in Hrhs_preserved;
      change_mul_goal_from_fold_eq;
      simpl;
      rewrite Hlhs_preserved;
      rewrite Hrhs_preserved;
      exact Heval
  end.

Local Ltac solve_div_nonconst_pair fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, ?folded_rhs),
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _ = (?folded_nodes_out, ?folded_out),
      Heval : _ |- _ ] =>
      simpl in Hfold;
      inversion Hfold;
      subst folded_nodes_out folded_out;
      clear Hfold;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      change_div_goal_from_fold_eq;
      simpl;
      rewrite Hlhs_preserved;
      rewrite Hrhs_preserved;
      exact Heval
  end.

Local Ltac solve_div_lhs_const_generic_rhs fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, SpecTransformExpr_Const ?lhs_const),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, ?folded_rhs),
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ |- _ ] =>
      simpl in Hfold;
      inversion Hfold; subst;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      apply result_ok_injective in Hlhs_preserved;
      change_div_goal_from_fold_eq;
      simpl;
      rewrite Hrhs_preserved;
      rewrite Hlhs_preserved;
      exact Heval
  end.

Local Ltac solve_div_rhs_const_generic_lhs fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, SpecTransformExpr_Const ?rhs_const),
      Hone_rhs : spec_value_is_one_raw (SpecTransformExpr_Const_f_value ?rhs_const) = false,
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ |- _ ] =>
      rewrite Hone_rhs in Hfold;
      simpl in Hfold;
      inversion Hfold; subst;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hlhs_preserved, Hrhs_preserved;
      apply result_ok_injective in Hrhs_preserved;
      change_div_goal_from_fold_eq;
      simpl;
      rewrite Hlhs_preserved;
      rewrite Hrhs_preserved;
      exact Heval
  end.

Local Ltac solve_div_rhs_const_one fold_expr_preserve :=
  lazymatch goal with
  | [ Hlhs_folded : fold_transform_expr ?lhs ?field ?folded_nodes = (?folded_nodes1, ?folded_lhs),
      Hrhs_folded : fold_transform_expr ?rhs ?field ?folded_nodes1 = (?folded_nodes2, SpecTransformExpr_Const ?rhs_const),
      Hone_rhs : spec_value_is_one_raw (SpecTransformExpr_Const_f_value ?rhs_const) = true,
      Hlhs_eval : transform_eval_expr ?lhs ?w ?field = Result_Ok ?s,
      Hrhs_eval : transform_eval_expr ?rhs ?w ?field = Result_Ok ?s0,
      Hfold : _,
      Heval : _ = Result_Ok ?value |- _ ] =>
      let Hrhs_preserved := fresh "Hrhs_preserved" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved w s0 Hrhs_folded Hrhs_eval;
      simpl in Hrhs_preserved;
      rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs;
      apply result_ok_injective in Hrhs_preserved;
      rewrite <- Hrhs_preserved in Heval;
      destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate;
      apply div_spec_values_one_r_ok in Hdiv;
      rewrite Hdiv in Heval;
      unfold normalize_spec_value in Heval;
      rewrite (transform_eval_expr_normalized_ok lhs w field s Hlhs_eval) in Heval;
      apply result_ok_injective in Heval;
      subst value;
      let Hlhs_preserved := fresh "Hlhs_preserved" in
      let Hfold_expr := fresh "Hfold_expr" in
      pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved w s Hlhs_folded Hlhs_eval;
      injection Hfold as _ Hfold_expr;
      first [ rewrite Hfold_expr | rewrite <- Hfold_expr ];
      exact Hlhs_preserved
  end.

Lemma fold_transform_expr_preserves_eval_ok :
  forall expr field folded_nodes folded_nodes' folded witness value,
    fold_transform_expr expr field folded_nodes = (folded_nodes', folded) ->
    transform_eval_expr expr witness field = Result_Ok value ->
    transform_eval_expr folded witness field = Result_Ok value.
Proof.
  refine (
    fix fold_expr_preserve
      (expr : t_SpecTransformExpr)
      : forall field folded_nodes folded_nodes' folded witness value,
          fold_transform_expr expr field folded_nodes = (folded_nodes', folded) ->
          transform_eval_expr expr witness field = Result_Ok value ->
          transform_eval_expr folded witness field = Result_Ok value := _).
  destruct expr as [const_expr | signal_expr | values | lhs rhs | lhs rhs | lhs rhs];
    intros field folded_nodes folded_nodes' folded witness value Hfold Heval.
  - simpl in Hfold.
    inversion Hfold; subst.
    exact Heval.
  - simpl in Hfold.
    inversion Hfold; subst.
    exact Heval.
  - simpl in Hfold.
    rewrite transform_eval_expr_add_as_list in Heval.
    remember
      (fold_add_terms_from_list values field folded_nodes (zero_spec_value tt) false (impl__new tt))
      as folded_values eqn:Hvalues.
    destruct folded_values as [folded_nodes1 [[const_value saw_const] terms]].
    assert (
      forall list_values folded_nodes_current const_acc saw_const_current prefix_terms
             folded_nodes_final final_const final_saw_const final_terms
             prefix_value final_value,
        fold_add_terms_from_list
          list_values
          field
          folded_nodes_current
          const_acc
          saw_const_current
          prefix_terms =
          (folded_nodes_final, (final_const, final_saw_const, final_terms)) ->
        normalize const_acc field = const_acc ->
        transform_eval_exprs_list
          prefix_terms
          witness
          field
          (add_spec_values (zero_spec_value tt) const_acc field) =
          Result_Ok prefix_value ->
        transform_eval_exprs_list list_values witness field prefix_value =
          Result_Ok final_value ->
        transform_eval_exprs_list
          final_terms
          witness
          field
          (add_spec_values (zero_spec_value tt) final_const field) =
          Result_Ok final_value
    ) as Hvalues_preserve.
    {
      induction list_values as [|value_expr remaining_values IH];
        intros folded_nodes_current const_acc saw_const_current prefix_terms
          folded_nodes_final final_const final_saw_const final_terms
          prefix_value final_value Hfold_values Hconst_acc Hprefix Heval_values;
        simpl in Hfold_values.
      - inversion Hfold_values; subst.
        simpl in Heval_values.
        inversion Heval_values; subst.
        exact Hprefix.
      - destruct (fold_transform_expr value_expr field folded_nodes_current)
          as [folded_nodes_step folded_value] eqn:Hvalue_folded.
        simpl in Heval_values.
        destruct (transform_eval_expr value_expr witness field) eqn:Hvalue_eval;
          try discriminate.
        destruct folded_value as
          [const_folded | signal_folded | add_folded | sub_lhs sub_rhs
          | mul_lhs mul_rhs | div_lhs div_rhs];
          simpl in Hfold_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Const const_folded)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          simpl in Hfolded_eval.
          assert (
            Hconst_eval :
              normalize_spec_value
                (SpecTransformExpr_Const_f_value const_folded)
                field = s
          ).
          {
            inversion Hfolded_eval.
            reflexivity.
          }
          assert (Hs_canonical : normalize s field = s).
          {
            rewrite <- Hconst_eval.
            apply normalize_output_canonical_ok.
          }
          pose proof (transform_eval_exprs_list_shift_ok
            prefix_terms
            witness
            field
            (add_spec_values (zero_spec_value tt) const_acc field)
            s
            prefix_value
            Hs_canonical
            Hprefix) as Hprefix_shifted.
          replace
            (add_spec_values s prefix_value field)
            with
            (add_spec_values prefix_value s field)
            in Hprefix_shifted
            by apply add_spec_values_comm_ok.
          replace
            (add_spec_values s
              (add_spec_values (zero_spec_value tt) const_acc field)
              field)
            with
              (add_spec_values
                (zero_spec_value tt)
                (add_spec_values
                  const_acc
                  (SpecTransformExpr_Const_f_value const_folded)
                  field)
                field)
            in Hprefix_shifted.
          2:{
            repeat rewrite add_spec_values_zero_l_ok.
            unfold normalize_spec_value.
            rewrite Hconst_acc.
            rewrite (add_spec_values_comm_ok s const_acc field).
            rewrite <- Hconst_eval.
            rewrite add_spec_values_normalize_r_ok.
            rewrite add_output_canonical_ok.
            reflexivity.
          }
          eapply IH.
          * exact Hfold_values.
          * apply add_output_canonical_ok.
          * exact Hprefix_shifted.
          * exact Heval_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Signal signal_folded)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          simpl in Hfolded_eval.
          eapply IH.
          * exact Hfold_values.
          * exact Hconst_acc.
          * eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- simpl.
               rewrite Hfolded_eval.
               reflexivity.
          * exact Heval_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Add add_folded)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          rewrite transform_eval_expr_add_as_list in Hfolded_eval.
          pose proof (transform_eval_exprs_list_normalized_ok
            prefix_terms
            witness
            field
            (add_spec_values (zero_spec_value tt) const_acc field)
            prefix_value
            (add_output_canonical_ok (zero_spec_value tt) const_acc field)
            Hprefix) as Hprefix_value.
          pose proof (transform_eval_exprs_list_shift_ok
            add_folded
            witness
            field
            (zero_spec_value tt)
            prefix_value
            s
            Hprefix_value
            Hfolded_eval) as Hadd_shifted.
          rewrite add_spec_values_zero_r_ok in Hadd_shifted by exact Hprefix_value.
          unfold normalize_spec_value in Hadd_shifted.
          rewrite Hprefix_value in Hadd_shifted.
          pose proof (transform_eval_exprs_list_app_ok
            prefix_terms
            add_folded
            witness
            field
            (add_spec_values (zero_spec_value tt) const_acc field)
            prefix_value
            (add_spec_values prefix_value s field)
            Hprefix
            Hadd_shifted) as Happ_eval.
          rewrite <- append_transform_exprs_list_app_eq in Happ_eval.
          eapply IH.
          * exact Hfold_values.
          * exact Hconst_acc.
          * exact Happ_eval.
          * exact Heval_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Sub sub_lhs sub_rhs)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          simpl in Hfolded_eval.
          eapply IH.
          * exact Hfold_values.
          * exact Hconst_acc.
          * eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- simpl.
               rewrite Hfolded_eval.
               reflexivity.
          * exact Heval_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Mul mul_lhs mul_rhs)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          simpl in Hfolded_eval.
          eapply IH.
          * exact Hfold_values.
          * exact Hconst_acc.
          * eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- simpl.
               rewrite Hfolded_eval.
               reflexivity.
          * exact Heval_values.
        + pose proof (fold_expr_preserve
            value_expr
            field
            folded_nodes_current
            folded_nodes_step
            (SpecTransformExpr_Div div_lhs div_rhs)
            witness
            s
            Hvalue_folded
            Hvalue_eval) as Hfolded_eval.
          simpl in Hfolded_eval.
          eapply IH.
          * exact Hfold_values.
          * exact Hconst_acc.
          * eapply transform_eval_exprs_list_app_ok.
            -- exact Hprefix.
            -- simpl.
               rewrite Hfolded_eval.
               reflexivity.
          * exact Heval_values.
	    }
	    assert (
	      Hempty_prefix :
	        transform_eval_exprs_list
	          (impl__new tt)
	          witness
	          field
	          (add_spec_values (zero_spec_value tt) (zero_spec_value tt) field) =
	        Result_Ok (zero_spec_value tt)
	    ).
	    {
	      simpl.
	      rewrite add_spec_values_zero_l_ok.
	      rewrite zero_spec_value_normalized_ok.
	      reflexivity.
	    }
	    pose proof (Hvalues_preserve
	      values
	      folded_nodes
      (zero_spec_value tt)
      false
      (impl__new tt)
      folded_nodes1
      const_value
      saw_const
      terms
      (zero_spec_value tt)
	      value
	      (eq_sym Hvalues)
	      (zero_spec_value_normalized_ok field)
	      Hempty_prefix
	      Heval) as Hterms_value.
    destruct (spec_value_is_zero_raw const_value) eqn:Hzero_const.
    + rewrite add_spec_values_zero_l_ok in Hterms_value.
	      rewrite normalize_spec_value_zero_raw_ok in Hterms_value by exact Hzero_const.
		      destruct terms as [|single remaining_terms].
		      * rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
		        rewrite <- Hvalues in Hfold.
		        rewrite Hzero_const in Hfold.
		        destruct saw_const; simpl in Hfold;
		          inversion Hfold; subst;
		          simpl in Hterms_value;
		          inversion Hterms_value; subst;
		          simpl;
		          f_equal;
		          apply normalize_spec_value_zero_raw_ok;
		          unfold spec_value_is_zero_raw, zero_spec_value, spec_field_value_zero;
		          simpl;
		          reflexivity.
	      * destruct remaining_terms as [|second remaining_terms].
		        -- rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
		           rewrite <- Hvalues in Hfold.
		           rewrite Hzero_const in Hfold.
		           destruct saw_const; simpl in Hfold;
		             inversion Hfold; subst;
		             simpl in Hterms_value;
		             destruct (transform_eval_expr folded witness field) eqn:Hsingle_eval;
		               try discriminate;
		             rewrite add_spec_values_zero_l_ok in Hterms_value;
		             unfold normalize_spec_value in Hterms_value;
		             rewrite (transform_eval_expr_normalized_ok
		               folded
		               witness
		               field
		               s
		               Hsingle_eval) in Hterms_value;
		             exact Hterms_value.
		        -- rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
		           rewrite <- Hvalues in Hfold.
		           rewrite Hzero_const in Hfold.
		           destruct saw_const; simpl in Hfold;
		             inversion Hfold; subst;
		             rewrite transform_eval_expr_add_as_list;
		             exact Hterms_value.
    + pose proof (transform_eval_exprs_list_move_acc_to_end_ok
        terms
        witness
        field
        (zero_spec_value tt)
        const_value
        value
        (zero_spec_value_normalized_ok field)
        Hterms_value) as Hmaterialized.
      assert (Hsaw_const_true : saw_const = true).
      {
        destruct saw_const eqn:Hsaw_const.
        - reflexivity.
        - pose proof (fold_add_terms_from_list_no_const_preserves_acc_ok
            values
            field
            folded_nodes
            (zero_spec_value tt)
            (impl__new tt)
            folded_nodes1
            const_value
            terms
            (eq_sym Hvalues)) as Hconst_zero.
          rewrite Hconst_zero in Hzero_const.
          unfold spec_value_is_zero_raw, zero_spec_value, spec_field_value_zero in Hzero_const.
          simpl in Hzero_const.
          discriminate.
      }
      subst saw_const.
      destruct terms as [|single remaining_terms].
      * rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
        rewrite <- Hvalues in Hfold.
        rewrite Hzero_const in Hfold.
        simpl in Hfold.
        inversion Hfold; subst.
        simpl.
        apply result_ok_injective in Hmaterialized.
        rewrite add_spec_values_zero_l_ok in Hmaterialized.
        rewrite normalize_spec_value_idempotent_ok in Hmaterialized.
        subst value.
        reflexivity.
      * destruct remaining_terms as [|second remaining_terms].
        -- rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
           rewrite <- Hvalues in Hfold.
           rewrite Hzero_const in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           rewrite transform_eval_expr_add_as_list.
           exact Hmaterialized.
        -- rewrite fold_terms_matches_fold_add_terms_from_list_ok in Hfold.
           rewrite <- Hvalues in Hfold.
           rewrite Hzero_const in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           rewrite transform_eval_expr_add_as_list.
           exact Hmaterialized.
  - simpl in Hfold.
    destruct (fold_transform_expr lhs field folded_nodes)
      as [folded_nodes1 folded_lhs] eqn:Hlhs_folded.
    destruct (fold_transform_expr rhs field folded_nodes1)
      as [folded_nodes2 folded_rhs] eqn:Hrhs_folded.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct folded_rhs as
      [rhs_const | rhs_signal | rhs_add | rhs_lhs rhs_rhs
      | rhs_lhs rhs_rhs | rhs_lhs rhs_rhs].
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * inversion Hfold; subst.
        simpl in Heval.
        inversion Heval; subst.
        pose proof (fold_expr_preserve
          lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
          witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
        pose proof (fold_expr_preserve
          rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
          witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        apply result_ok_injective in Hrhs_preserved.
        simpl.
        rewrite <- sub_spec_values_normalize_l_ok.
        rewrite <- sub_spec_values_normalize_r_ok.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        rewrite sub_output_canonical_ok.
        reflexivity.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite sub_spec_values_zero_r_ok in Heval.
           apply result_ok_injective in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           subst value.
           eapply fold_expr_preserve; [exact Hlhs_folded | exact Hlhs_eval].
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           simpl.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Signal lhs_signal)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes' (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite sub_spec_values_zero_r_ok in Heval.
           apply result_ok_injective in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           subst value.
           eapply fold_expr_preserve; [exact Hlhs_folded | exact Hlhs_eval].
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           simpl.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Add lhs_add)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes' (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite sub_spec_values_zero_r_ok in Heval.
           apply result_ok_injective in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           subst value.
           eapply fold_expr_preserve; [exact Hlhs_folded | exact Hlhs_eval].
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           simpl.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes' (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite sub_spec_values_zero_r_ok in Heval.
           apply result_ok_injective in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           subst value.
           eapply fold_expr_preserve; [exact Hlhs_folded | exact Hlhs_eval].
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           simpl.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes' (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite sub_spec_values_zero_r_ok in Heval.
           apply result_ok_injective in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           subst value.
           eapply fold_expr_preserve; [exact Hlhs_folded | exact Hlhs_eval].
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           simpl.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Div lhs_lhs lhs_rhs)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes' (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst; simpl.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
  - simpl in Hfold.
    destruct (fold_transform_expr lhs field folded_nodes)
      as [folded_nodes1 folded_lhs] eqn:Hlhs_folded.
    destruct (fold_transform_expr rhs field folded_nodes1)
      as [folded_nodes2 folded_rhs] eqn:Hrhs_folded.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct folded_rhs as
      [rhs_const | rhs_signal | rhs_add | rhs_lhs rhs_rhs
      | rhs_lhs rhs_rhs | rhs_lhs rhs_rhs].
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      * inversion Hfold; subst.
        simpl in Heval.
        inversion Heval; subst.
        pose proof (fold_expr_preserve
          lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
          witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
        pose proof (fold_expr_preserve
          rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
          witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        apply result_ok_injective in Hrhs_preserved.
        simpl.
        rewrite <- mul_spec_values_normalize_l_ok.
        rewrite <- mul_spec_values_normalize_r_ok.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        rewrite mul_output_canonical_ok.
        reflexivity.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite mul_spec_values_zero_r_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose proof (fold_expr_preserve
                rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
                witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
              simpl in Hrhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
              apply result_ok_injective in Hrhs_preserved.
              rewrite <- Hrhs_preserved in Heval.
              rewrite mul_spec_values_one_r_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hlhs_folded.
              ** exact Hlhs_eval.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hrhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite mul_spec_values_zero_r_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose proof (fold_expr_preserve
                rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
                witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
              simpl in Hrhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
              apply result_ok_injective in Hrhs_preserved.
              rewrite <- Hrhs_preserved in Heval.
              rewrite mul_spec_values_one_r_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hlhs_folded.
              ** exact Hlhs_eval.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hrhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite mul_spec_values_zero_r_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose proof (fold_expr_preserve
                rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
                witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
              simpl in Hrhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
              apply result_ok_injective in Hrhs_preserved.
              rewrite <- Hrhs_preserved in Heval.
              rewrite mul_spec_values_one_r_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hlhs_folded.
              ** exact Hlhs_eval.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hrhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite mul_spec_values_zero_r_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose proof (fold_expr_preserve
                rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
                witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
              simpl in Hrhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
              apply result_ok_injective in Hrhs_preserved.
              rewrite <- Hrhs_preserved in Heval.
              rewrite mul_spec_values_one_r_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hlhs_folded.
              ** exact Hlhs_eval.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hrhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hzero_rhs.
        -- simpl in Hfold.
           rewrite Hzero_rhs in Hfold.
           simpl in Hfold.
           inversion Hfold; subst.
           pose proof (fold_expr_preserve
             rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
             witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hrhs_preserved by exact Hzero_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           rewrite mul_spec_values_zero_r_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose proof (fold_expr_preserve
                rhs field folded_nodes1 folded_nodes2 (SpecTransformExpr_Const rhs_const)
                witness s0 Hrhs_folded Hrhs_eval) as Hrhs_preserved.
              simpl in Hrhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
              apply result_ok_injective in Hrhs_preserved.
              rewrite <- Hrhs_preserved in Heval.
              rewrite mul_spec_values_one_r_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hlhs_folded.
              ** exact Hlhs_eval.
           ++ simpl in Hfold.
              rewrite Hzero_rhs in Hfold.
              rewrite Hone_rhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hrhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hlhs_preserved.
              rewrite Hrhs_preserved.
              exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hzero_lhs.
        -- inversion Hfold; subst.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           simpl in Hlhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hlhs_preserved by exact Hzero_lhs.
           apply result_ok_injective in Hlhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hone_lhs.
           ++ inversion Hfold; subst.
              pose proof (fold_expr_preserve
                lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
                witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
              simpl in Hlhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hlhs_preserved by exact Hone_lhs.
              apply result_ok_injective in Hlhs_preserved.
              rewrite <- Hlhs_preserved in Heval.
              rewrite mul_spec_values_one_l_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hrhs_folded.
              ** exact Hrhs_eval.
           ++ simpl in Hfold.
              try rewrite Hzero_lhs in Hfold.
              try rewrite Hone_lhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hlhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hrhs_preserved.
              rewrite Hlhs_preserved.
              exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Signal lhs_signal)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Add lhs_add)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Div lhs_lhs lhs_rhs)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hzero_lhs.
        -- inversion Hfold; subst.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           simpl in Hlhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hlhs_preserved by exact Hzero_lhs.
           apply result_ok_injective in Hlhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hone_lhs.
           ++ inversion Hfold; subst.
              pose proof (fold_expr_preserve
                lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
                witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
              simpl in Hlhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hlhs_preserved by exact Hone_lhs.
              apply result_ok_injective in Hlhs_preserved.
              rewrite <- Hlhs_preserved in Heval.
              rewrite mul_spec_values_one_l_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hrhs_folded.
              ** exact Hrhs_eval.
           ++ simpl in Hfold.
              try rewrite Hzero_lhs in Hfold.
              try rewrite Hone_lhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hlhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hrhs_preserved.
              rewrite Hlhs_preserved.
              exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Signal lhs_signal)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Add lhs_add)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Div lhs_lhs lhs_rhs)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hzero_lhs.
        -- inversion Hfold; subst.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           simpl in Hlhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hlhs_preserved by exact Hzero_lhs.
           apply result_ok_injective in Hlhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hone_lhs.
           ++ inversion Hfold; subst.
              pose proof (fold_expr_preserve
                lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
                witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
              simpl in Hlhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hlhs_preserved by exact Hone_lhs.
              apply result_ok_injective in Hlhs_preserved.
              rewrite <- Hlhs_preserved in Heval.
              rewrite mul_spec_values_one_l_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hrhs_folded.
              ** exact Hrhs_eval.
           ++ simpl in Hfold.
              try rewrite Hzero_lhs in Hfold.
              try rewrite Hone_lhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hlhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hrhs_preserved.
              rewrite Hlhs_preserved.
              exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Signal lhs_signal)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Add lhs_add)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Div lhs_lhs lhs_rhs)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hzero_lhs.
        -- inversion Hfold; subst.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           simpl in Hlhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hlhs_preserved by exact Hzero_lhs.
           apply result_ok_injective in Hlhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hone_lhs.
           ++ inversion Hfold; subst.
              pose proof (fold_expr_preserve
                lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
                witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
              simpl in Hlhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hlhs_preserved by exact Hone_lhs.
              apply result_ok_injective in Hlhs_preserved.
              rewrite <- Hlhs_preserved in Heval.
              rewrite mul_spec_values_one_l_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hrhs_folded.
              ** exact Hrhs_eval.
           ++ simpl in Hfold.
              try rewrite Hzero_lhs in Hfold.
              try rewrite Hone_lhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hlhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hrhs_preserved.
              rewrite Hlhs_preserved.
              exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Signal lhs_signal)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Add lhs_add)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Div lhs_lhs lhs_rhs)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs
        | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs].
      simpl in Hfold.
      * destruct (spec_value_is_zero_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hzero_lhs.
        -- inversion Hfold; subst.
           pose proof (fold_expr_preserve
             lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
             witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
           simpl in Hlhs_preserved.
           rewrite normalize_spec_value_zero_raw_ok in Hlhs_preserved by exact Hzero_lhs.
           apply result_ok_injective in Hlhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite mul_spec_values_zero_l_ok in Heval.
           simpl in Heval |- *.
           rewrite zero_spec_value_normalized_ok.
           exact Heval.
        -- destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value lhs_const)) eqn:Hone_lhs.
           ++ inversion Hfold; subst.
              pose proof (fold_expr_preserve
                lhs field folded_nodes folded_nodes1 (SpecTransformExpr_Const lhs_const)
                witness s Hlhs_folded Hlhs_eval) as Hlhs_preserved.
              simpl in Hlhs_preserved.
              rewrite normalize_spec_value_one_raw_ok in Hlhs_preserved by exact Hone_lhs.
              apply result_ok_injective in Hlhs_preserved.
              rewrite <- Hlhs_preserved in Heval.
              rewrite mul_spec_values_one_l_ok in Heval.
              unfold normalize_spec_value in Heval.
              rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval) in Heval.
              apply result_ok_injective in Heval.
              subst value.
              eapply fold_expr_preserve.
              ** exact Hrhs_folded.
              ** exact Hrhs_eval.
           ++ simpl in Hfold.
              try rewrite Hzero_lhs in Hfold.
              try rewrite Hone_lhs in Hfold.
              simpl in Hfold.
              inversion Hfold; subst.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
              pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
              simpl in Hlhs_preserved, Hrhs_preserved.
              apply result_ok_injective in Hlhs_preserved.
              change_mul_goal_from_fold_eq.
              simpl.
              rewrite Hrhs_preserved.
              rewrite Hlhs_preserved.
              exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Signal lhs_signal)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Add lhs_add)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Sub lhs_lhs lhs_rhs)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Mul lhs_lhs lhs_rhs)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Mul
              (SpecTransformExpr_Div lhs_lhs lhs_rhs)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hlhs_preserved.
        rewrite Hrhs_preserved.
        exact Heval.
  - simpl in Hfold.
    destruct (fold_transform_expr lhs field folded_nodes)
      as [folded_nodes1 folded_lhs] eqn:Hlhs_folded.
    destruct (fold_transform_expr rhs field folded_nodes1)
      as [folded_nodes2 folded_rhs] eqn:Hrhs_folded.
    simpl in Heval.
    destruct (transform_eval_expr lhs witness field) eqn:Hlhs_eval; try discriminate.
    destruct (transform_eval_expr rhs witness field) eqn:Hrhs_eval; try discriminate.
    destruct folded_rhs as
      [rhs_const | rhs_signal | rhs_add | rhs_lhs rhs_rhs | rhs_lhs rhs_rhs | rhs_lhs rhs_rhs];
      simpl in Hfold.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * destruct (div_spec_values
          (SpecTransformExpr_Const_f_value lhs_const)
          (SpecTransformExpr_Const_f_value rhs_const)
          field) as [div_value|] eqn:Hdiv_folded.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hlhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           simpl.
           rewrite <- div_spec_values_normalize_l_ok.
           rewrite <- div_spec_values_normalize_r_ok.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           unfold normalize_spec_value.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval).
           rewrite (transform_eval_expr_normalized_ok rhs witness field s0 Hrhs_eval).
           exact Heval.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hlhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hlhs_preserved in Heval.
           rewrite div_spec_values_normalize_l_ok in Heval.
           rewrite <- Hrhs_preserved in Heval.
           rewrite div_spec_values_normalize_r_ok in Heval.
           rewrite Hdiv_folded in Heval.
           inversion Heval; subst.
           simpl.
           unfold normalize_spec_value.
           rewrite (div_output_canonical_ok
             (SpecTransformExpr_Const_f_value lhs_const)
             (SpecTransformExpr_Const_f_value rhs_const)
             field
             value
             Hdiv_folded).
           reflexivity.
      * destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
           apply div_spec_values_one_r_ok in Hdiv.
           rewrite Hdiv in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           apply result_ok_injective in Heval.
           subst value.
           eapply fold_expr_preserve.
           ++ exact Hlhs_folded.
           ++ exact Hlhs_eval.
        -- simpl in Hfold.
           inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           change_div_goal_from_fold_eq.
           simpl.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
           apply div_spec_values_one_r_ok in Hdiv.
           rewrite Hdiv in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           apply result_ok_injective in Heval.
           subst value.
           eapply fold_expr_preserve.
           ++ exact Hlhs_folded.
           ++ exact Hlhs_eval.
        -- simpl in Hfold.
           inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           change_div_goal_from_fold_eq.
           simpl.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
           apply div_spec_values_one_r_ok in Hdiv.
           rewrite Hdiv in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           apply result_ok_injective in Heval.
           subst value.
           eapply fold_expr_preserve.
           ++ exact Hlhs_folded.
           ++ exact Hlhs_eval.
        -- simpl in Hfold.
           inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           change_div_goal_from_fold_eq.
           simpl.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
           apply div_spec_values_one_r_ok in Hdiv.
           rewrite Hdiv in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           apply result_ok_injective in Heval.
           subst value.
           eapply fold_expr_preserve.
           ++ exact Hlhs_folded.
           ++ exact Hlhs_eval.
        -- simpl in Hfold.
           inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           change_div_goal_from_fold_eq.
           simpl.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
      * destruct (spec_value_is_one_raw (SpecTransformExpr_Const_f_value rhs_const)) eqn:Hone_rhs.
        -- inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hrhs_preserved.
           rewrite normalize_spec_value_one_raw_ok in Hrhs_preserved by exact Hone_rhs.
           apply result_ok_injective in Hrhs_preserved.
           rewrite <- Hrhs_preserved in Heval.
           destruct (div_spec_values s (spec_field_value_of_z 1) field) eqn:Hdiv; try discriminate.
           apply div_spec_values_one_r_ok in Hdiv.
           rewrite Hdiv in Heval.
           unfold normalize_spec_value in Heval.
           rewrite (transform_eval_expr_normalized_ok lhs witness field s Hlhs_eval) in Heval.
           apply result_ok_injective in Heval.
           subst value.
           eapply fold_expr_preserve.
           ++ exact Hlhs_folded.
           ++ exact Hlhs_eval.
        -- simpl in Hfold.
           inversion Hfold; subst.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
           pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
           simpl in Hlhs_preserved, Hrhs_preserved.
           apply result_ok_injective in Hrhs_preserved.
           change_div_goal_from_fold_eq.
           simpl.
           rewrite Hlhs_preserved.
           rewrite Hrhs_preserved.
           exact Heval.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Div
              (SpecTransformExpr_Const lhs_const)
              (SpecTransformExpr_Signal rhs_signal))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hrhs_preserved.
        rewrite Hlhs_preserved.
        exact Heval.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Div
              (SpecTransformExpr_Const lhs_const)
              (SpecTransformExpr_Add rhs_add))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hrhs_preserved.
        rewrite Hlhs_preserved.
        exact Heval.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Div
              (SpecTransformExpr_Const lhs_const)
              (SpecTransformExpr_Sub rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hrhs_preserved.
        rewrite Hlhs_preserved.
        exact Heval.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Div
              (SpecTransformExpr_Const lhs_const)
              (SpecTransformExpr_Mul rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hrhs_preserved.
        rewrite Hlhs_preserved.
        exact Heval.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
    + destruct folded_lhs as
        [lhs_const | lhs_signal | lhs_add | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs | lhs_lhs lhs_rhs];
        simpl in Hfold.
      * simpl in Hfold.
        inversion Hfold; subst.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hlhs_preserved witness s Hlhs_folded Hlhs_eval.
        pose_fold_expr_preserve_from_eq fold_expr_preserve Hrhs_preserved witness s0 Hrhs_folded Hrhs_eval.
        simpl in Hlhs_preserved, Hrhs_preserved.
        apply result_ok_injective in Hlhs_preserved.
        change (
          transform_eval_expr
            (SpecTransformExpr_Div
              (SpecTransformExpr_Const lhs_const)
              (SpecTransformExpr_Div rhs_lhs rhs_rhs))
            witness
            field = Result_Ok value).
        simpl.
        rewrite Hrhs_preserved.
        rewrite Hlhs_preserved.
        exact Heval.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
      * solve_div_nonconst_pair fold_expr_preserve.
Qed.

Lemma fold_transform_constraint_preserves_holds_ok :
  forall constraint field folded_nodes folded_nodes' folded_constraint program witness,
    field = SpecTransformProgram_f_field program ->
    fold_transform_constraint constraint field folded_nodes =
      (folded_nodes', folded_constraint) ->
    TransformConstraintHolds program witness constraint ->
    TransformConstraintHolds program witness folded_constraint.
Proof.
  intros constraint field folded_nodes folded_nodes' folded_constraint program witness
    Hfield Hfold Hholds.
  subst field.
  destruct constraint as [equal_constraint | boolean_constraint | range_constraint];
    simpl in Hfold.
  - destruct (fold_transform_expr
      (SpecTransformConstraint_Equal_f_lhs equal_constraint)
      (SpecTransformProgram_f_field program)
      folded_nodes) as [folded_nodes1 lhs] eqn:Hlhs_folded.
    destruct (fold_transform_expr
      (SpecTransformConstraint_Equal_f_rhs equal_constraint)
      (SpecTransformProgram_f_field program)
      folded_nodes1) as [folded_nodes2 rhs] eqn:Hrhs_folded.
    inversion Hfold; subst; clear Hfold.
    inversion Hholds as
      [equal_constraint0 lhs_value rhs_value Hlhs_hold Hrhs_hold Hequal
      | | ]; subst.
    econstructor.
    + eapply transform_eval_expr_sound_ok.
      simpl.
      eapply fold_transform_expr_preserves_eval_ok.
      * exact Hlhs_folded.
      * eapply transform_eval_expr_complete_ok.
        exact Hlhs_hold.
    + eapply transform_eval_expr_sound_ok.
      simpl.
      eapply fold_transform_expr_preserves_eval_ok.
      * exact Hrhs_folded.
      * eapply transform_eval_expr_complete_ok.
        exact Hrhs_hold.
    + exact Hequal.
  - inversion Hfold; subst.
    exact Hholds.
  - inversion Hfold; subst.
    exact Hholds.
Qed.

Lemma fold_constraints_for_ir_from_preserves_holds_ok :
  forall constraints field report folded_constraints report' final_constraints program witness,
    field = SpecTransformProgram_f_field program ->
    fold_constraints_for_ir_from constraints field report folded_constraints =
      (report', final_constraints) ->
    Forall (TransformConstraintHolds program witness) folded_constraints ->
    Forall (TransformConstraintHolds program witness) (Slice_f_v constraints) ->
    Forall (TransformConstraintHolds program witness) final_constraints.
Proof.
  intros constraints field report folded_constraints report' final_constraints program witness
    Hfield Hfold Hfolded Hholds.
  unfold fold_constraints_for_ir_from in Hfold.
  revert report folded_constraints report' final_constraints Hfold Hfolded Hholds.
  induction (Slice_f_v constraints) as [|constraint remaining_constraints IH];
    intros report folded_constraints report' final_constraints Hfold Hfolded Hholds;
    simpl in Hfold.
  - inversion Hfold; subst.
    exact Hfolded.
  - inversion Hholds; subst.
    destruct (fold_transform_constraint
      constraint
      (SpecTransformProgram_f_field program)
      (f_folded_expr_nodes report))
      as [folded_nodes1 folded_constraint] eqn:Hconstraint_folded.
    destruct (constraint_is_tautology folded_constraint) eqn:Htautology.
    + eapply IH.
      * exact Hfold.
      * exact Hfolded.
      * exact H2.
    + eapply IH.
      * exact Hfold.
      * unfold impl_1__push.
        apply Forall_app.
        split.
        -- exact Hfolded.
        -- constructor.
           ++ eapply fold_transform_constraint_preserves_holds_ok.
              ** reflexivity.
              ** exact Hconstraint_folded.
              ** exact H1.
           ++ constructor.
      * exact H2.
Qed.

Lemma fold_constraints_for_zir_from_preserves_holds_ok :
  forall constraints field report folded_constraints report' final_constraints program witness,
    field = SpecTransformProgram_f_field program ->
    fold_constraints_for_zir_from constraints field report folded_constraints =
      (report', final_constraints) ->
    Forall (TransformConstraintHolds program witness) folded_constraints ->
    Forall (TransformConstraintHolds program witness) (Slice_f_v constraints) ->
    Forall (TransformConstraintHolds program witness) final_constraints.
Proof.
  intros constraints field report folded_constraints report' final_constraints program witness
    Hfield Hfold Hfolded Hholds.
  unfold fold_constraints_for_zir_from in Hfold.
  revert report folded_constraints report' final_constraints Hfold Hfolded Hholds.
  induction (Slice_f_v constraints) as [|constraint remaining_constraints IH];
    intros report folded_constraints report' final_constraints Hfold Hfolded Hholds;
    simpl in Hfold.
  - inversion Hfold; subst.
    exact Hfolded.
  - inversion Hholds; subst.
    destruct (fold_transform_constraint
      constraint
      (SpecTransformProgram_f_field program)
      (f_folded_expr_nodes report))
      as [folded_nodes1 folded_constraint] eqn:Hconstraint_folded.
    destruct (constraint_is_tautology folded_constraint) eqn:Htautology.
    + eapply IH.
      * exact Hfold.
      * exact Hfolded.
      * exact H2.
    + eapply IH.
      * exact Hfold.
      * unfold impl_1__push.
        apply Forall_app.
        split.
        -- exact Hfolded.
        -- constructor.
           ++ eapply fold_transform_constraint_preserves_holds_ok.
              ** reflexivity.
              ** exact Hconstraint_folded.
              ** exact H1.
           ++ constructor.
      * exact H2.
Qed.

Lemma dedup_constraints_ir_preserves_holds_ok :
  forall constraints report report' final_constraints program witness,
    dedup_constraints_ir constraints report = (report', final_constraints) ->
    Forall (TransformConstraintHolds program witness) (Slice_f_v constraints) ->
    Forall (TransformConstraintHolds program witness) final_constraints.
Proof.
  intros constraints report report' final_constraints program witness Hdedup Hholds.
  unfold dedup_constraints_ir in Hdedup.
  revert report report' final_constraints Hdedup Hholds.
  induction (Slice_f_v constraints) as [|constraint remaining_constraints IH];
    intros report report' final_constraints Hdedup Hholds;
    simpl in Hdedup.
  - inversion Hdedup; subst.
    constructor.
  - inversion Hholds; subst.
    destruct (dedup_constraints_ir_list remaining_constraints report)
      as [report1 deduped_constraints] eqn:Hremaining_dedup.
    destruct (contains_equivalent_ir_constraint_list deduped_constraints constraint)
      eqn:Hcontains.
    + eapply IH.
      * inversion Hdedup; subst.
        exact Hremaining_dedup.
      * exact H2.
    + inversion Hdedup; subst.
      eapply insert_constraint_sorted_from_list_preserves_holds_ok.
      * exact H1.
      * constructor.
      * eapply IH.
        -- exact Hremaining_dedup.
        -- exact H2.
Qed.

Lemma dedup_constraints_zir_preserves_holds_ok :
  forall constraints report report' final_constraints program witness,
    dedup_constraints_zir constraints report = (report', final_constraints) ->
    Forall (TransformConstraintHolds program witness) (Slice_f_v constraints) ->
    Forall (TransformConstraintHolds program witness) final_constraints.
Proof.
  intros constraints report report' final_constraints program witness Hdedup Hholds.
  unfold dedup_constraints_zir in Hdedup.
  revert report report' final_constraints Hdedup Hholds.
  induction (Slice_f_v constraints) as [|constraint remaining_constraints IH];
    intros report report' final_constraints Hdedup Hholds;
    simpl in Hdedup.
  - inversion Hdedup; subst.
    constructor.
  - inversion Hholds; subst.
    destruct (dedup_constraints_zir_list remaining_constraints report)
      as [report1 deduped_constraints] eqn:Hremaining_dedup.
    destruct (contains_exact_constraint_list deduped_constraints constraint)
      eqn:Hcontains.
    + eapply IH.
      * inversion Hdedup; subst.
        exact Hremaining_dedup.
      * exact H2.
    + inversion Hdedup; subst.
      eapply insert_constraint_sorted_from_list_preserves_holds_ok.
      * exact H1.
      * constructor.
      * eapply IH.
        -- exact Hremaining_dedup.
        -- exact H2.
Qed.

Theorem optimize_supported_ir_program_preserves_checks_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    transform_check_program (optimize_ir_program_output program) witness = Result_Ok tt.
Proof.
  intros program witness Hcheck.
  apply transform_check_program_complete_ok.
  unfold optimize_ir_program_output, optimize_supported_ir_program.
  simpl.
  remember
    (fold_constraints_for_ir_from
      (SpecTransformProgram_f_constraints program)
      (SpecTransformProgram_f_field program)
      empty_optimize_report
      (impl__new tt)) as folded eqn:Hfolded_constraints.
  destruct folded as [report1 folded_constraints].
  remember
    (dedup_constraints_ir (Build_t_Slice _ folded_constraints) report1)
      as deduped eqn:Hdedup_constraints.
  destruct deduped as [report2 deduped_constraints].
  remember
    (filter_live_signals program (Build_t_Slice _ deduped_constraints) report2)
      as filtered eqn:Hfiltered.
  destruct filtered as [report3 live_signals].
  eapply forall_transform_constraint_holds_field_irrelevant_ok
    with (program_from := program).
  - unfold fold_constraints_for_ir_from in Hfolded_constraints.
    unfold dedup_constraints_ir in Hdedup_constraints.
    simpl in Hfolded_constraints, Hdedup_constraints.
    rewrite <- Hfolded_constraints.
    rewrite <- Hdedup_constraints.
    rewrite <- Hfiltered.
    simpl.
    reflexivity.
  - pose proof Hfolded_constraints as Hfolded_constraints_wrapper.
    pose proof Hdedup_constraints as Hdedup_constraints_wrapper.
    unfold fold_constraints_for_ir_from in Hfolded_constraints.
    unfold dedup_constraints_ir in Hdedup_constraints.
    simpl in Hfolded_constraints, Hdedup_constraints.
    rewrite <- Hfolded_constraints.
    rewrite <- Hdedup_constraints.
    rewrite <- Hfiltered.
    cbn [SpecOptimizeResult_f_program SpecTransformProgram_f_constraints].
    eapply dedup_constraints_ir_preserves_holds_ok.
    + exact (eq_sym Hdedup_constraints_wrapper).
    + eapply fold_constraints_for_ir_from_preserves_holds_ok.
      * reflexivity.
      * exact (eq_sym Hfolded_constraints_wrapper).
      * constructor.
      * eapply transform_check_program_sound_ok.
        exact Hcheck.
Qed.

Theorem optimize_supported_zir_program_preserves_checks_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    transform_check_program (optimize_zir_program_output program) witness = Result_Ok tt.
Proof.
  intros program witness Hcheck.
  apply transform_check_program_complete_ok.
  unfold optimize_zir_program_output, optimize_supported_zir_program.
  simpl.
  remember
    (fold_constraints_for_zir_from
      (SpecTransformProgram_f_constraints program)
      (SpecTransformProgram_f_field program)
      empty_optimize_report
      (impl__new tt)) as folded eqn:Hfolded_constraints.
  destruct folded as [report1 folded_constraints].
  remember
    (dedup_constraints_zir (Build_t_Slice _ folded_constraints) report1)
      as deduped eqn:Hdedup_constraints.
  destruct deduped as [report2 deduped_constraints].
  remember
    (filter_live_signals program (Build_t_Slice _ deduped_constraints) report2)
      as filtered eqn:Hfiltered.
  destruct filtered as [report3 live_signals].
  eapply forall_transform_constraint_holds_field_irrelevant_ok
    with (program_from := program).
  - unfold fold_constraints_for_zir_from in Hfolded_constraints.
    unfold dedup_constraints_zir in Hdedup_constraints.
    simpl in Hfolded_constraints, Hdedup_constraints.
    rewrite <- Hfolded_constraints.
    rewrite <- Hdedup_constraints.
    rewrite <- Hfiltered.
    simpl.
    reflexivity.
  - pose proof Hfolded_constraints as Hfolded_constraints_wrapper.
    pose proof Hdedup_constraints as Hdedup_constraints_wrapper.
    unfold fold_constraints_for_zir_from in Hfolded_constraints.
    unfold dedup_constraints_zir in Hdedup_constraints.
    simpl in Hfolded_constraints, Hdedup_constraints.
    rewrite <- Hfolded_constraints.
    rewrite <- Hdedup_constraints.
    rewrite <- Hfiltered.
    cbn [SpecOptimizeResult_f_program SpecTransformProgram_f_constraints].
    eapply dedup_constraints_zir_preserves_holds_ok.
    + exact (eq_sym Hdedup_constraints_wrapper).
    + eapply fold_constraints_for_zir_from_preserves_holds_ok.
      * reflexivity.
      * exact (eq_sym Hfolded_constraints_wrapper).
      * constructor.
      * eapply transform_check_program_sound_ok.
        exact Hcheck.
Qed.
