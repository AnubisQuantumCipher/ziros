Require Import List NArith.
Import List.ListNotations.

Require Import KernelCompat.
Require Import KernelGenerated.

Inductive ExprEval
  (witness : t_SpecKernelWitness)
  (field : t_FieldId) :
  t_SpecKernelExpr -> t_SpecFieldValue -> Prop :=
| ExprEval_Const value :
    ExprEval witness field
      (SpecKernelExpr_Const value)
      (normalize value field)
| ExprEval_Signal signal_index value :
    kernel_signal_value witness signal_index field = Result_Ok value ->
    ExprEval witness field
      (SpecKernelExpr_Signal signal_index)
      value
| ExprEval_Add lhs rhs lhs_value rhs_value :
    ExprEval witness field lhs lhs_value ->
    ExprEval witness field rhs rhs_value ->
    ExprEval witness field
      (SpecKernelExpr_Add lhs rhs)
      (Add_f_add lhs_value rhs_value field)
| ExprEval_Sub lhs rhs lhs_value rhs_value :
    ExprEval witness field lhs lhs_value ->
    ExprEval witness field rhs rhs_value ->
    ExprEval witness field
      (SpecKernelExpr_Sub lhs rhs)
      (Sub_f_sub lhs_value rhs_value field)
| ExprEval_Mul lhs rhs lhs_value rhs_value :
    ExprEval witness field lhs lhs_value ->
    ExprEval witness field rhs rhs_value ->
    ExprEval witness field
      (SpecKernelExpr_Mul lhs rhs)
      (Mul_f_mul lhs_value rhs_value field)
| ExprEval_Div lhs rhs lhs_value rhs_value value :
    ExprEval witness field lhs lhs_value ->
    ExprEval witness field rhs rhs_value ->
    Div_f_div lhs_value rhs_value field = Option_Some value ->
    ExprEval witness field
      (SpecKernelExpr_Div lhs rhs)
      value.

Inductive InputsEval
  (witness : t_SpecKernelWitness)
  (field : t_FieldId) :
  t_Vec t_SpecKernelExpr t_Global ->
  t_Vec t_SpecFieldValue t_Global -> Prop :=
| InputsEval_nil :
    InputsEval witness field [] []
| InputsEval_cons expr remaining_exprs value remaining_values :
    ExprEval witness field expr value ->
    InputsEval witness field remaining_exprs remaining_values ->
    InputsEval witness field
      (expr :: remaining_exprs)
      (value :: remaining_values).

Inductive RenderedLookupOutputs
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (lookup_table : t_SpecKernelLookupTable) :
  t_usize ->
  t_Vec t_usize t_Global ->
  t_Vec t_SpecFieldValue t_Global -> Prop :=
| RenderedLookupOutputs_nil current_column :
    RenderedLookupOutputs witness field lookup_table current_column [] []
| RenderedLookupOutputs_take current_column signal_index remaining_indices value remaining_values :
    f_lt current_column (f_column_count lookup_table) = true ->
    kernel_signal_value witness signal_index field = Result_Ok value ->
    RenderedLookupOutputs
      witness
      field
      lookup_table
      (f_add current_column (n_to_usize 1%N))
      remaining_indices
      remaining_values ->
    RenderedLookupOutputs
      witness
      field
      lookup_table
      current_column
      (signal_index :: remaining_indices)
      (value :: remaining_values)
| RenderedLookupOutputs_skip current_column signal_index remaining_indices remaining_values :
    f_lt current_column (f_column_count lookup_table) = false ->
    RenderedLookupOutputs
      witness
      field
      lookup_table
      (f_add current_column (n_to_usize 1%N))
      remaining_indices
      remaining_values ->
    RenderedLookupOutputs
      witness
      field
      lookup_table
      current_column
      (signal_index :: remaining_indices)
      remaining_values.

Definition LookupRowMatches
  (field : t_FieldId)
  (row : t_Vec t_SpecFieldValue t_Global)
  (inputs : t_Vec t_SpecFieldValue t_Global)
  (expected_outputs : t_Option (t_Vec t_SpecFieldValue t_Global))
  (input_len : t_usize) : Prop :=
  row_matches_inputs_from_list row inputs field = true /\
  match expected_outputs with
  | Option_Some outputs =>
      row_matches_outputs_from_list
        (skip_row_prefix_list row input_len)
        outputs
        field = true
  | Option_None =>
      True
  end.

Definition LookupRowsSatisfy
  (rows : t_Vec (t_Vec t_SpecFieldValue t_Global) t_Global)
  (field : t_FieldId)
  (inputs : t_Vec t_SpecFieldValue t_Global)
  (expected_outputs : t_Option (t_Vec t_SpecFieldValue t_Global))
  (input_len : t_usize) : Prop :=
  exists row,
    In row rows /\
    LookupRowMatches field row inputs expected_outputs input_len.

Inductive LookupExpectedOutputs
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (lookup_table : t_SpecKernelLookupTable)
  (input_len : t_usize) :
  t_Option (t_Vec t_usize t_Global) ->
  t_Option (t_Vec t_SpecFieldValue t_Global) -> Prop :=
| LookupExpectedOutputs_none :
    LookupExpectedOutputs
      witness
      field
      lookup_table
      input_len
      Option_None
      Option_None
| LookupExpectedOutputs_some signal_indices values :
    RenderedLookupOutputs witness field lookup_table input_len signal_indices values ->
    LookupExpectedOutputs
      witness
      field
      lookup_table
      input_len
      (Option_Some signal_indices)
      (Option_Some values).

Inductive ConstraintHolds
  (program : t_SpecKernelProgram)
  (witness : t_SpecKernelWitness) :
  t_SpecKernelConstraint -> Prop :=
| ConstraintHolds_Equal equal_constraint lhs_value rhs_value :
    ExprEval
      witness
      (SpecKernelProgram_f_field program)
      (SpecKernelConstraint_Equal_f_lhs equal_constraint)
      lhs_value ->
    ExprEval
      witness
      (SpecKernelProgram_f_field program)
      (SpecKernelConstraint_Equal_f_rhs equal_constraint)
      rhs_value ->
    PartialEq_f_eq lhs_value rhs_value (SpecKernelProgram_f_field program) = true ->
    ConstraintHolds
      program
      witness
      (SpecKernelConstraint_Equal equal_constraint)
| ConstraintHolds_Boolean boolean_constraint value :
    kernel_signal_value
      witness
      (SpecKernelConstraint_Boolean_f_signal boolean_constraint)
      (SpecKernelProgram_f_field program) = Result_Ok value ->
    is_boolean value (SpecKernelProgram_f_field program) = true ->
    ConstraintHolds
      program
      witness
      (SpecKernelConstraint_Boolean boolean_constraint)
| ConstraintHolds_Range range_constraint value :
    kernel_signal_value
      witness
      (SpecKernelConstraint_Range_f_signal range_constraint)
      (SpecKernelProgram_f_field program) = Result_Ok value ->
    fits_bits
      value
      (SpecKernelConstraint_Range_f_bits range_constraint)
      (SpecKernelProgram_f_field program) = true ->
    ConstraintHolds
      program
      witness
      (SpecKernelConstraint_Range range_constraint)
| ConstraintHolds_Lookup lookup_constraint lookup_table evaluated_inputs expected_outputs :
    impl__get
      (f_deref (f_lookup_tables program))
      (SpecKernelConstraint_Lookup_f_table_index lookup_constraint) =
      Option_Some lookup_table ->
    f_gt
      (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
      (f_column_count lookup_table) = false ->
    InputsEval
      witness
      (SpecKernelProgram_f_field program)
      (SpecKernelConstraint_Lookup_f_inputs lookup_constraint)
      evaluated_inputs ->
    LookupExpectedOutputs
      witness
      (SpecKernelProgram_f_field program)
      lookup_table
      (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint))
      (SpecKernelConstraint_Lookup_f_outputs lookup_constraint)
      expected_outputs ->
    LookupRowsSatisfy
      (f_rows lookup_table)
      (SpecKernelProgram_f_field program)
      evaluated_inputs
      expected_outputs
      (impl_1__len (SpecKernelConstraint_Lookup_f_inputs lookup_constraint)) ->
    ConstraintHolds
      program
      witness
      (SpecKernelConstraint_Lookup lookup_constraint).

Definition ProgramHolds
  (program : t_SpecKernelProgram)
  (witness : t_SpecKernelWitness) : Prop :=
  Forall (ConstraintHolds program witness) (SpecKernelProgram_f_constraints program).
