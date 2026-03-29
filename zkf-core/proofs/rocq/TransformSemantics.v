Require Import List NArith.
Import List.ListNotations.

Require Import KernelCompat.
Require Import KernelGenerated.

Inductive TransformExprListHolds
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (acc : t_SpecFieldValue) :
  t_Vec t_SpecTransformExpr t_Global ->
  t_SpecFieldValue -> Prop :=
| TransformExprListHolds_nil :
    TransformExprListHolds witness field acc [] acc
| TransformExprListHolds_cons expr remaining_exprs expr_value final_value :
    TransformExprHolds witness field acc expr expr_value ->
    TransformExprListHolds
      witness
      field
      (add_spec_values acc expr_value field)
      remaining_exprs
      final_value ->
    TransformExprListHolds
      witness
      field
      acc
      (expr :: remaining_exprs)
      final_value
with TransformExprHolds
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (acc : t_SpecFieldValue) :
  t_SpecTransformExpr ->
  t_SpecFieldValue -> Prop :=
| TransformExprHolds_Const const_expr :
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Const const_expr)
      (normalize_spec_value (SpecTransformExpr_Const_f_value const_expr) field)
| TransformExprHolds_Signal signal_expr value :
    transform_signal_value
      witness
      (SpecTransformExpr_Signal_f_signal_index signal_expr)
      field = Result_Ok value ->
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Signal signal_expr)
      value
| TransformExprHolds_Add values value :
    TransformExprListHolds
      witness
      field
      (zero_spec_value tt)
      values
      value ->
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Add values)
      value
| TransformExprHolds_Sub lhs rhs lhs_value rhs_value :
    TransformExprHolds witness field acc lhs lhs_value ->
    TransformExprHolds witness field acc rhs rhs_value ->
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Sub lhs rhs)
      (sub_spec_values lhs_value rhs_value field)
| TransformExprHolds_Mul lhs rhs lhs_value rhs_value :
    TransformExprHolds witness field acc lhs lhs_value ->
    TransformExprHolds witness field acc rhs rhs_value ->
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Mul lhs rhs)
      (mul_spec_values lhs_value rhs_value field)
| TransformExprHolds_Div lhs rhs lhs_value rhs_value value :
    TransformExprHolds witness field acc lhs lhs_value ->
    TransformExprHolds witness field acc rhs rhs_value ->
    div_spec_values lhs_value rhs_value field = Option_Some value ->
    TransformExprHolds
      witness
      field
      acc
      (SpecTransformExpr_Div lhs rhs)
      value.

Scheme TransformExprListHolds_ind'
  := Induction for TransformExprListHolds Sort Prop
with TransformExprHolds_ind'
  := Induction for TransformExprHolds Sort Prop.

Combined Scheme TransformExprHolds_mutind
  from TransformExprListHolds_ind', TransformExprHolds_ind'.

Inductive TransformConstraintHolds
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness) :
  t_SpecTransformConstraint -> Prop :=
| TransformConstraintHolds_Equal equal_constraint lhs_value rhs_value :
    TransformExprHolds
      witness
      (SpecTransformProgram_f_field program)
      (zero_spec_value tt)
      (SpecTransformConstraint_Equal_f_lhs equal_constraint)
      lhs_value ->
    TransformExprHolds
      witness
      (SpecTransformProgram_f_field program)
      (zero_spec_value tt)
      (SpecTransformConstraint_Equal_f_rhs equal_constraint)
      rhs_value ->
    spec_values_equal lhs_value rhs_value (SpecTransformProgram_f_field program) = true ->
    TransformConstraintHolds
      program
      witness
      (SpecTransformConstraint_Equal equal_constraint)
| TransformConstraintHolds_Boolean boolean_constraint value :
    transform_signal_value
      witness
      (SpecTransformConstraint_Boolean_f_signal_index boolean_constraint)
      (SpecTransformProgram_f_field program) = Result_Ok value ->
    spec_value_is_boolean value (SpecTransformProgram_f_field program) = true ->
    TransformConstraintHolds
      program
      witness
      (SpecTransformConstraint_Boolean boolean_constraint)
| TransformConstraintHolds_Range range_constraint value :
    transform_signal_value
      witness
      (SpecTransformConstraint_Range_f_signal_index range_constraint)
      (SpecTransformProgram_f_field program) = Result_Ok value ->
    spec_value_fits_bits
      value
      (SpecTransformConstraint_Range_f_bits range_constraint)
      (SpecTransformProgram_f_field program) = true ->
    TransformConstraintHolds
      program
      witness
      (SpecTransformConstraint_Range range_constraint).

Definition TransformProgramHolds
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness) : Prop :=
  Forall (TransformConstraintHolds program witness) (SpecTransformProgram_f_constraints program).

Fixpoint transform_signal_sort_key_from_list
  (signals : list t_SpecTransformSignal)
  (signal_index : t_usize) : t_usize :=
  match signals with
  | [] =>
      signal_index
  | signal :: remaining_signals =>
      if f_eq (SpecTransformSignal_f_signal_index signal) signal_index then
        SpecTransformSignal_f_sort_key signal
      else
        transform_signal_sort_key_from_list remaining_signals signal_index
  end.

Definition transform_signal_sort_key
  (signals : t_Vec t_SpecTransformSignal t_Global)
  (signal_index : t_usize) : t_usize :=
  transform_signal_sort_key_from_list signals signal_index.

Fixpoint canonicalize_transform_expr
  (expr : t_SpecTransformExpr) : t_SpecTransformExpr :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
      SpecTransformExpr_Const const_expr
  | SpecTransformExpr_Signal signal_expr =>
      SpecTransformExpr_Signal
        {| SpecTransformExpr_Signal_f_signal_index :=
             SpecTransformExpr_Signal_f_sort_key signal_expr;
           SpecTransformExpr_Signal_f_sort_key :=
             SpecTransformExpr_Signal_f_sort_key signal_expr |}
  | SpecTransformExpr_Add values =>
      SpecTransformExpr_Add (map canonicalize_transform_expr values)
  | SpecTransformExpr_Sub lhs rhs =>
      SpecTransformExpr_Sub
        (canonicalize_transform_expr lhs)
        (canonicalize_transform_expr rhs)
  | SpecTransformExpr_Mul lhs rhs =>
      SpecTransformExpr_Mul
        (canonicalize_transform_expr lhs)
        (canonicalize_transform_expr rhs)
  | SpecTransformExpr_Div lhs rhs =>
      SpecTransformExpr_Div
        (canonicalize_transform_expr lhs)
        (canonicalize_transform_expr rhs)
  end.

Definition canonicalize_transform_constraint
  (signals : t_Vec t_SpecTransformSignal t_Global)
  (constraint : t_SpecTransformConstraint) : t_SpecTransformConstraint :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
      SpecTransformConstraint_Equal
        {| SpecTransformConstraint_Equal_f_lhs :=
             canonicalize_transform_expr
               (SpecTransformConstraint_Equal_f_lhs equal_constraint);
           SpecTransformConstraint_Equal_f_rhs :=
             canonicalize_transform_expr
               (SpecTransformConstraint_Equal_f_rhs equal_constraint);
           SpecTransformConstraint_Equal_f_label_key :=
             SpecTransformConstraint_Equal_f_label_key equal_constraint |}
  | SpecTransformConstraint_Boolean boolean_constraint =>
      SpecTransformConstraint_Boolean
        {| SpecTransformConstraint_Boolean_f_signal_index :=
             transform_signal_sort_key
               signals
               (SpecTransformConstraint_Boolean_f_signal_index boolean_constraint);
           SpecTransformConstraint_Boolean_f_label_key :=
             SpecTransformConstraint_Boolean_f_label_key boolean_constraint |}
  | SpecTransformConstraint_Range range_constraint =>
      SpecTransformConstraint_Range
        {| SpecTransformConstraint_Range_f_signal_index :=
             transform_signal_sort_key
               signals
               (SpecTransformConstraint_Range_f_signal_index range_constraint);
           SpecTransformConstraint_Range_f_bits :=
             SpecTransformConstraint_Range_f_bits range_constraint;
           SpecTransformConstraint_Range_f_label_key :=
             SpecTransformConstraint_Range_f_label_key range_constraint |}
  end.

Definition canonicalize_transform_signal
  (signal : t_SpecTransformSignal) : t_SpecTransformSignal :=
  {| SpecTransformSignal_f_signal_index := SpecTransformSignal_f_sort_key signal;
     SpecTransformSignal_f_sort_key := SpecTransformSignal_f_sort_key signal;
     SpecTransformSignal_f_visibility := SpecTransformSignal_f_visibility signal;
     SpecTransformSignal_f_constant_value := SpecTransformSignal_f_constant_value signal;
     SpecTransformSignal_f_required := SpecTransformSignal_f_required signal |}.

Definition canonicalize_transform_assignment
  (signals : t_Vec t_SpecTransformSignal t_Global)
  (assignment : t_SpecTransformAssignment) : t_SpecTransformAssignment :=
  {| SpecTransformAssignment_f_target_signal_index :=
       transform_signal_sort_key
         signals
         (SpecTransformAssignment_f_target_signal_index assignment);
     SpecTransformAssignment_f_expr :=
       canonicalize_transform_expr (SpecTransformAssignment_f_expr assignment) |}.

Definition canonicalize_transform_hint
  (signals : t_Vec t_SpecTransformSignal t_Global)
  (hint : t_SpecTransformHint) : t_SpecTransformHint :=
  {| SpecTransformHint_f_target_signal_index :=
       transform_signal_sort_key
         signals
         (SpecTransformHint_f_target_signal_index hint);
     SpecTransformHint_f_source_signal_index :=
       transform_signal_sort_key
         signals
         (SpecTransformHint_f_source_signal_index hint) |}.

Definition canonicalize_transform_program
  (program : t_SpecTransformProgram) : t_SpecTransformProgram :=
  let signals :=
    map canonicalize_transform_signal (SpecTransformProgram_f_signals program) in
  let constraints :=
    map
      (canonicalize_transform_constraint (SpecTransformProgram_f_signals program))
      (SpecTransformProgram_f_constraints program) in
  {| SpecTransformProgram_f_field := SpecTransformProgram_f_field program;
     SpecTransformProgram_f_signals :=
       sort_signals_by_key (Build_t_Slice _ signals);
     SpecTransformProgram_f_constraints :=
       sort_constraints_by_key (Build_t_Slice _ constraints);
     SpecTransformProgram_f_assignments :=
       map
         (canonicalize_transform_assignment (SpecTransformProgram_f_signals program))
         (SpecTransformProgram_f_assignments program);
     SpecTransformProgram_f_hints :=
       map
         (canonicalize_transform_hint (SpecTransformProgram_f_signals program))
         (SpecTransformProgram_f_hints program) |}.

Definition TransformProgramsReorderReindexEquivalent
  (lhs rhs : t_SpecTransformProgram) : Prop :=
  canonicalize_transform_program lhs = canonicalize_transform_program rhs.
