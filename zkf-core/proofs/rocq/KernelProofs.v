From Coq Require Import Bool List NArith.
Import List.ListNotations.

Require Import KernelCompat.
Require Import KernelGenerated.
Require Import KernelSemantics.

Lemma eval_expr_const_normalizes
  (value : t_SpecFieldValue)
  (witness : t_SpecKernelWitness)
  (field : t_FieldId) :
  eval_expr (SpecKernelExpr_Const value) witness field =
    Result_Ok (normalize value field).
Proof.
  reflexivity.
Qed.

Lemma eval_expr_signal_delegates
  (signal_index : t_usize)
  (witness : t_SpecKernelWitness)
  (field : t_FieldId) :
  eval_expr (SpecKernelExpr_Signal signal_index) witness field =
    kernel_signal_value witness signal_index field.
Proof.
  reflexivity.
Qed.

Theorem eval_expr_sound_relative_ok :
  forall expr witness field value,
    eval_expr expr witness field = Result_Ok value ->
    ExprEval witness field expr value.
Proof.
  induction expr; intros witness field value Heval; simpl in Heval.
  - inversion Heval; subst.
    constructor.
  - econstructor.
    exact Heval.
  - destruct (eval_expr expr1 witness field) eqn:Hlhs; try discriminate.
    destruct (eval_expr expr2 witness field) eqn:Hrhs; try discriminate.
    inversion Heval; subst.
    eapply ExprEval_Add.
    + eapply IHexpr1; exact Hlhs.
    + eapply IHexpr2; exact Hrhs.
  - destruct (eval_expr expr1 witness field) eqn:Hlhs; try discriminate.
    destruct (eval_expr expr2 witness field) eqn:Hrhs; try discriminate.
    inversion Heval; subst.
    eapply ExprEval_Sub.
    + eapply IHexpr1; exact Hlhs.
    + eapply IHexpr2; exact Hrhs.
  - destruct (eval_expr expr1 witness field) eqn:Hlhs; try discriminate.
    destruct (eval_expr expr2 witness field) eqn:Hrhs; try discriminate.
    inversion Heval; subst.
    eapply ExprEval_Mul.
    + eapply IHexpr1; exact Hlhs.
    + eapply IHexpr2; exact Hrhs.
  - destruct (eval_expr expr1 witness field) eqn:Hlhs; try discriminate.
    destruct (eval_expr expr2 witness field) eqn:Hrhs; try discriminate.
    destruct (Div_f_div s s0 field) eqn:Hdiv; try discriminate.
    inversion Heval; subst.
    eapply ExprEval_Div.
    + eapply IHexpr1; exact Hlhs.
    + eapply IHexpr2; exact Hrhs.
    + exact Hdiv.
Qed.

Lemma collect_evaluated_inputs_from_list_sound_ok_with_acc :
  forall inputs witness field acc result,
    collect_evaluated_inputs_from_list inputs witness field acc = Result_Ok result ->
    exists values,
      result = acc ++ values /\
      InputsEval witness field inputs values.
Proof.
  induction inputs as [|input remaining_inputs IH];
    intros witness field acc result Hcollect; simpl in Hcollect.
  - inversion Hcollect; subst.
    exists [].
    split.
    + rewrite app_nil_r.
      reflexivity.
    + constructor.
  - destruct (eval_expr input witness field) eqn:Heval; try discriminate.
    specialize (IH witness field (impl_1__push acc s) result Hcollect)
      as [remaining_values [Hresult Hinputs]].
    exists (s :: remaining_values).
    split.
    + rewrite Hresult.
      unfold impl_1__push.
      rewrite <- app_assoc.
      simpl.
      reflexivity.
    + constructor.
      * eapply eval_expr_sound_relative_ok; exact Heval.
      * exact Hinputs.
Qed.

Theorem collect_evaluated_inputs_sound_ok :
  forall inputs witness field values,
    collect_evaluated_inputs_from_list inputs witness field (impl__new tt) = Result_Ok values ->
    InputsEval witness field inputs values.
Proof.
  intros inputs witness field values Hcollect.
  pose proof
    (collect_evaluated_inputs_from_list_sound_ok_with_acc
      inputs
      witness
      field
      (impl__new tt)
      values
      Hcollect)
    as [evaluated_values [Hvalues Hinputs]].
  unfold impl__new in Hvalues.
  simpl in Hvalues.
  subst.
  exact Hinputs.
Qed.

Lemma render_lookup_outputs_from_list_sound_ok_with_acc :
  forall signal_indices current_column lookup_table witness field acc result,
    render_lookup_outputs_from_list
      signal_indices
      current_column
      lookup_table
      witness
      field
      acc = Result_Ok result ->
    exists values,
      result = acc ++ values /\
      RenderedLookupOutputs
        witness
        field
        lookup_table
        current_column
        signal_indices
        values.
Proof.
  induction signal_indices as [|signal_index remaining_indices IH];
    intros current_column lookup_table witness field acc result Hrender;
    simpl in Hrender.
  - inversion Hrender; subst.
    exists [].
    split.
    + rewrite app_nil_r.
      reflexivity.
    + constructor.
  - destruct (f_lt current_column (f_column_count lookup_table)) eqn:Hlt.
    + destruct (kernel_signal_value witness signal_index field) eqn:Hsignal;
        try discriminate.
      specialize
        (IH
          (f_add current_column (n_to_usize 1%N))
          lookup_table
          witness
          field
          (impl_1__push acc s)
          result
          Hrender)
        as [remaining_values [Hresult Houtputs]].
      exists (s :: remaining_values).
      split.
      * rewrite Hresult.
        unfold impl_1__push.
        rewrite <- app_assoc.
        simpl.
        reflexivity.
      * eapply RenderedLookupOutputs_take.
        -- exact Hlt.
        -- exact Hsignal.
        -- exact Houtputs.
    + specialize
        (IH
          (f_add current_column (n_to_usize 1%N))
          lookup_table
          witness
          field
          acc
          result
          Hrender)
        as [remaining_values [Hresult Houtputs]].
      exists remaining_values.
      split.
      * exact Hresult.
      * eapply RenderedLookupOutputs_skip.
        -- exact Hlt.
        -- exact Houtputs.
Qed.

Theorem render_lookup_outputs_sound_ok :
  forall signal_indices current_column lookup_table witness field values,
    render_lookup_outputs_from_list
      signal_indices
      current_column
      lookup_table
      witness
      field
      (impl__new tt) = Result_Ok values ->
    RenderedLookupOutputs
      witness
      field
      lookup_table
      current_column
      signal_indices
      values.
Proof.
  intros signal_indices current_column lookup_table witness field values Hrender.
  pose proof
    (render_lookup_outputs_from_list_sound_ok_with_acc
      signal_indices
      current_column
      lookup_table
      witness
      field
      (impl__new tt)
      values
      Hrender)
    as [rendered_values [Hvalues Houtputs]].
  unfold impl__new in Hvalues.
  simpl in Hvalues.
  subst.
  exact Houtputs.
Qed.

Theorem lookup_has_matching_row_sound_true :
  forall rows evaluated_inputs expected_outputs input_len field,
    lookup_has_matching_row_from_list rows evaluated_inputs expected_outputs input_len field = true ->
    LookupRowsSatisfy rows field evaluated_inputs expected_outputs input_len.
Proof.
  induction rows as [|row remaining_rows IH];
    intros evaluated_inputs expected_outputs input_len field Hlookup;
    simpl in Hlookup.
  - discriminate.
  - apply orb_true_iff in Hlookup.
    destruct Hlookup as [Hhead | Htail].
    + exists row.
      split.
      * left.
        reflexivity.
      * unfold LookupRowMatches.
        destruct (row_matches_inputs_from_list row evaluated_inputs field) eqn:Hinputs;
          simpl in Hhead.
        -- split.
           ++ reflexivity.
           ++ destruct expected_outputs.
              ** exact I.
              ** exact Hhead.
        -- discriminate.
    + destruct (IH evaluated_inputs expected_outputs input_len field Htail)
        as [matched_row [Hin Hmatches]].
      exists matched_row.
      split.
      * right.
        exact Hin.
      * exact Hmatches.
Qed.

Theorem check_constraints_from_list_sound_relative_ok :
  forall constraints program witness,
    check_constraints_from_list constraints program witness = Result_Ok tt ->
    Forall (ConstraintHolds program witness) constraints.
Proof.
  induction constraints as [|constraint remaining_constraints IH];
    intros program witness Hcheck; simpl in Hcheck.
  - constructor.
  - destruct constraint as
      [equal_constraint | boolean_constraint | range_constraint | lookup_constraint];
      simpl in Hcheck.
    + destruct (eval_expr
        (SpecKernelConstraint_Equal_f_lhs equal_constraint)
        witness
        (SpecKernelProgram_f_field program)) eqn:Hlhs; try discriminate.
      destruct (eval_expr
        (SpecKernelConstraint_Equal_f_rhs equal_constraint)
        witness
        (SpecKernelProgram_f_field program)) eqn:Hrhs; try discriminate.
      destruct (PartialEq_f_eq s s0 (SpecKernelProgram_f_field program)) eqn:Heq;
        try discriminate.
      constructor.
      * eapply ConstraintHolds_Equal.
        -- eapply eval_expr_sound_relative_ok; exact Hlhs.
        -- eapply eval_expr_sound_relative_ok; exact Hrhs.
        -- exact Heq.
      * eapply IH.
        exact Hcheck.
    + destruct (kernel_signal_value
        witness
        (SpecKernelConstraint_Boolean_f_signal boolean_constraint)
        (SpecKernelProgram_f_field program)) eqn:Hvalue; try discriminate.
      destruct (is_boolean s (SpecKernelProgram_f_field program)) eqn:Hbool; try discriminate.
      constructor.
      * eapply ConstraintHolds_Boolean.
        -- exact Hvalue.
        -- exact Hbool.
      * eapply IH.
        exact Hcheck.
    + destruct (kernel_signal_value
        witness
        (SpecKernelConstraint_Range_f_signal range_constraint)
        (SpecKernelProgram_f_field program)) eqn:Hvalue; try discriminate.
      destruct (fits_bits
        s
        (SpecKernelConstraint_Range_f_bits range_constraint)
        (SpecKernelProgram_f_field program)) eqn:Hrange; try discriminate.
      constructor.
      * eapply ConstraintHolds_Range.
        -- exact Hvalue.
        -- exact Hrange.
      * eapply IH.
        exact Hcheck.
    + destruct (impl__get
        (f_deref (f_lookup_tables program))
        (SpecKernelConstraint_Lookup_f_table_index lookup_constraint)) eqn:Htable;
        try discriminate.
      destruct (f_gt
        (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
        (f_column_count s)) eqn:Harity.
      * destruct (collect_evaluated_inputs_from_list
          (SpecKernelConstraint_Lookup_f_inputs lookup_constraint)
          witness
          (SpecKernelProgram_f_field program)
          (impl__new tt)) as [evaluated_inputs | input_error] eqn:Hinputs;
          try discriminate.
        destruct (SpecKernelConstraint_Lookup_f_outputs lookup_constraint)
          eqn:Hlookup_outputs in Hcheck;
          simpl in Hcheck.
        -- discriminate.
        -- rename t into output_signal_indices.
           destruct (render_lookup_outputs_from_list
            output_signal_indices
            (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
            s
            witness
            (SpecKernelProgram_f_field program)
            (impl__new tt)) as [expected_output_values | output_error] eqn:Houtputs;
            discriminate.
      * destruct (collect_evaluated_inputs_from_list
          (SpecKernelConstraint_Lookup_f_inputs lookup_constraint)
          witness
          (SpecKernelProgram_f_field program)
          (impl__new tt)) as [evaluated_inputs | input_error] eqn:Hinputs;
          try discriminate.
        destruct (SpecKernelConstraint_Lookup_f_outputs lookup_constraint)
          eqn:Hlookup_outputs in Hcheck;
          simpl in Hcheck.
        -- destruct (lookup_has_matching_row_from_list
            (f_rows s)
            evaluated_inputs
            Option_None
            (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
            (SpecKernelProgram_f_field program)) eqn:Hmatch; try discriminate.
           constructor.
           ++ eapply ConstraintHolds_Lookup with
                (lookup_table := s)
                (evaluated_inputs := evaluated_inputs)
                (expected_outputs := Option_None).
              ** exact Htable.
              ** exact Harity.
              ** eapply collect_evaluated_inputs_sound_ok.
                 exact Hinputs.
              ** rewrite Hlookup_outputs.
                 apply LookupExpectedOutputs_none.
              ** eapply lookup_has_matching_row_sound_true.
                 exact Hmatch.
           ++ eapply IH.
              exact Hcheck.
        -- rename t into output_signal_indices.
           destruct (render_lookup_outputs_from_list
            output_signal_indices
            (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
            s
            witness
            (SpecKernelProgram_f_field program)
            (impl__new tt)) as [expected_output_values | output_error] eqn:Houtputs;
            try discriminate.
           destruct (lookup_has_matching_row_from_list
            (f_rows s)
            evaluated_inputs
            (Option_Some expected_output_values)
            (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
            (SpecKernelProgram_f_field program)) eqn:Hmatch; try discriminate.
           constructor.
           ++ eapply ConstraintHolds_Lookup with
                (lookup_table := s)
                (evaluated_inputs := evaluated_inputs)
                (expected_outputs := Option_Some expected_output_values).
              ** exact Htable.
              ** exact Harity.
              ** eapply collect_evaluated_inputs_sound_ok.
                 exact Hinputs.
              ** rewrite Hlookup_outputs.
                 apply LookupExpectedOutputs_some.
                 eapply render_lookup_outputs_sound_ok.
                 exact Houtputs.
              ** eapply lookup_has_matching_row_sound_true.
                 exact Hmatch.
           ++ eapply IH.
              exact Hcheck.
Qed.

Theorem check_constraints_from_sound_relative_ok :
  forall constraints program witness,
    check_constraints_from constraints program witness = Result_Ok tt ->
    Forall (ConstraintHolds program witness) (Slice_f_v constraints).
Proof.
  intros constraints program witness Hcheck.
  unfold check_constraints_from in Hcheck.
  eapply check_constraints_from_list_sound_relative_ok.
  exact Hcheck.
Qed.

Theorem check_program_sound_relative_ok :
  forall program witness,
    check_program program witness = Result_Ok tt ->
    ProgramHolds program witness.
Proof.
  intros program witness Hcheck.
  unfold ProgramHolds.
  unfold check_program in Hcheck.
  unfold check_constraints_from in Hcheck.
  simpl in Hcheck.
  eapply check_constraints_from_list_sound_relative_ok.
  exact Hcheck.
Qed.
