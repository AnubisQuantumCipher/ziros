(* BEGIN TRANSFORM PRE-RECORD RUNTIME *)

Fixpoint insert_signal_sorted_from_list
  (signal : t_SpecTransformSignal)
  (sorted : list t_SpecTransformSignal)
  (inserted : bool)
  (result : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  match sorted with
  | [] =>
    if inserted then
      result
    else
      impl_1__push result signal
  | item :: remaining =>
    let '(result, inserted) :=
      if andb (negb inserted) (f_lt (SpecTransformSignal_f_sort_key signal) (SpecTransformSignal_f_sort_key item)) then
        (impl_1__push result signal, true)
      else
        (result, inserted) in
    let result := impl_1__push result item in
    insert_signal_sorted_from_list signal remaining inserted result
  end.

Definition insert_signal_sorted_from
  (signal : t_SpecTransformSignal)
  (sorted : t_Slice t_SpecTransformSignal)
  (inserted : bool)
  (result : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  insert_signal_sorted_from_list signal (Slice_f_v sorted) inserted result.

Fixpoint contains_signal_index_list
  (signals : list t_usize)
  (signal_index : t_usize) : bool :=
  match signals with
  | [] =>
    false
  | current_signal_index :: remaining_signals =>
    if f_eq current_signal_index signal_index then
      true
    else
      contains_signal_index_list remaining_signals signal_index
  end.

Definition contains_signal_index
  (signals : t_Slice t_usize)
  (signal_index : t_usize) : bool :=
  contains_signal_index_list (Slice_f_v signals) signal_index.

Fixpoint collect_signal_indices_from_signals_list
  (signals : list t_SpecTransformSignal)
  (kept_signal_indices : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match signals with
  | [] =>
    kept_signal_indices
  | signal :: remaining_signals =>
    collect_signal_indices_from_signals_list
      remaining_signals
      (impl_1__push kept_signal_indices (SpecTransformSignal_f_signal_index signal))
  end.

Definition collect_signal_indices_from_signals
  (signals : t_Slice t_SpecTransformSignal)
  (kept_signal_indices : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  collect_signal_indices_from_signals_list (Slice_f_v signals) kept_signal_indices.

(* END TRANSFORM PRE-RECORD RUNTIME *)

(* BEGIN TRANSFORM EXECUTABLE RUNTIME *)

Definition empty_normalization_report : t_SpecNormalizationReport :=
  {| SpecNormalizationReport_f_algebraic_rewrites := (0 : t_u32);
     SpecNormalizationReport_f_constant_folds := (0 : t_u32);
     SpecNormalizationReport_f_dead_signals_removed := (0 : t_u32) |}.

Definition empty_optimize_report : t_SpecOptimizeReport :=
  {| SpecOptimizeReport_f_folded_expr_nodes := (0 : t_usize);
     SpecOptimizeReport_f_deduplicated_constraints := (0 : t_usize);
     SpecOptimizeReport_f_removed_tautology_constraints := (0 : t_usize);
     SpecOptimizeReport_f_removed_private_signals := (0 : t_usize) |}.

Definition u32_add (lhs rhs : t_u32) : t_u32 :=
  Add_f_add (t_Add := _ : t_Add t_u32 t_u32) lhs rhs.

Definition u32_eq (lhs rhs : t_u32) : bool :=
  PartialEq_f_eq (t_PartialEq := _ : t_PartialEq t_u32 t_u32) lhs rhs.

Definition u32_lt (lhs rhs : t_u32) : bool :=
  PartialOrd_f_lt (t_PartialOrd := _ : t_PartialOrd t_u32 t_u32) lhs rhs.

Definition spec_field_value_eq_raw
  (lhs rhs : t_SpecFieldValue) : bool :=
  Z.eqb (spec_field_value_to_z lhs) (spec_field_value_to_z rhs).

Definition normalization_report_inc_algebraic
  (report : t_SpecNormalizationReport) : t_SpecNormalizationReport :=
  {| SpecNormalizationReport_f_algebraic_rewrites :=
       u32_add (SpecNormalizationReport_f_algebraic_rewrites report) (1 : t_u32);
     SpecNormalizationReport_f_constant_folds :=
       SpecNormalizationReport_f_constant_folds report;
     SpecNormalizationReport_f_dead_signals_removed :=
       SpecNormalizationReport_f_dead_signals_removed report |}.

Definition normalization_report_inc_constant
  (report : t_SpecNormalizationReport) : t_SpecNormalizationReport :=
  {| SpecNormalizationReport_f_algebraic_rewrites :=
       SpecNormalizationReport_f_algebraic_rewrites report;
     SpecNormalizationReport_f_constant_folds :=
       u32_add (SpecNormalizationReport_f_constant_folds report) (1 : t_u32);
     SpecNormalizationReport_f_dead_signals_removed :=
       SpecNormalizationReport_f_dead_signals_removed report |}.

Definition normalization_report_inc_dead
  (report : t_SpecNormalizationReport) : t_SpecNormalizationReport :=
  {| SpecNormalizationReport_f_algebraic_rewrites :=
       SpecNormalizationReport_f_algebraic_rewrites report;
     SpecNormalizationReport_f_constant_folds :=
       SpecNormalizationReport_f_constant_folds report;
     SpecNormalizationReport_f_dead_signals_removed :=
       u32_add (SpecNormalizationReport_f_dead_signals_removed report) (1 : t_u32) |}.

Definition optimize_report_inc_folded
  (report : t_SpecOptimizeReport) : t_SpecOptimizeReport :=
  {| SpecOptimizeReport_f_folded_expr_nodes :=
       f_add (SpecOptimizeReport_f_folded_expr_nodes report) (1 : t_usize);
     SpecOptimizeReport_f_deduplicated_constraints :=
       SpecOptimizeReport_f_deduplicated_constraints report;
     SpecOptimizeReport_f_removed_tautology_constraints :=
       SpecOptimizeReport_f_removed_tautology_constraints report;
     SpecOptimizeReport_f_removed_private_signals :=
       SpecOptimizeReport_f_removed_private_signals report |}.

Definition optimize_report_inc_dedup
  (report : t_SpecOptimizeReport) : t_SpecOptimizeReport :=
  {| SpecOptimizeReport_f_folded_expr_nodes :=
       SpecOptimizeReport_f_folded_expr_nodes report;
     SpecOptimizeReport_f_deduplicated_constraints :=
       f_add (SpecOptimizeReport_f_deduplicated_constraints report) (1 : t_usize);
     SpecOptimizeReport_f_removed_tautology_constraints :=
       SpecOptimizeReport_f_removed_tautology_constraints report;
     SpecOptimizeReport_f_removed_private_signals :=
       SpecOptimizeReport_f_removed_private_signals report |}.

Definition optimize_report_inc_tautology
  (report : t_SpecOptimizeReport) : t_SpecOptimizeReport :=
  {| SpecOptimizeReport_f_folded_expr_nodes :=
       SpecOptimizeReport_f_folded_expr_nodes report;
     SpecOptimizeReport_f_deduplicated_constraints :=
       SpecOptimizeReport_f_deduplicated_constraints report;
     SpecOptimizeReport_f_removed_tautology_constraints :=
       f_add (SpecOptimizeReport_f_removed_tautology_constraints report) (1 : t_usize);
     SpecOptimizeReport_f_removed_private_signals :=
       SpecOptimizeReport_f_removed_private_signals report |}.

Definition optimize_report_inc_removed_private
  (report : t_SpecOptimizeReport) : t_SpecOptimizeReport :=
  {| SpecOptimizeReport_f_folded_expr_nodes :=
       SpecOptimizeReport_f_folded_expr_nodes report;
     SpecOptimizeReport_f_deduplicated_constraints :=
       SpecOptimizeReport_f_deduplicated_constraints report;
     SpecOptimizeReport_f_removed_tautology_constraints :=
       SpecOptimizeReport_f_removed_tautology_constraints report;
     SpecOptimizeReport_f_removed_private_signals :=
       f_add (SpecOptimizeReport_f_removed_private_signals report) (1 : t_usize) |}.

Definition make_const_expr
  (value : t_SpecFieldValue)
  (sort_key : t_usize) : t_SpecTransformExpr :=
  SpecTransformExpr_Const
    {| SpecTransformExpr_Const_f_value := value;
       SpecTransformExpr_Const_f_sort_key := sort_key |}.

Definition zero_spec_expr '(_ : unit) : t_SpecTransformExpr :=
  make_const_expr (zero_spec_value tt) (0 : t_usize).

Definition transform_expr_is_const_zero
  (expr : t_SpecTransformExpr) : bool :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
    spec_value_is_zero_raw (SpecTransformExpr_Const_f_value const_expr)
  | _ =>
    false
  end.

Definition transform_expr_is_const_one
  (expr : t_SpecTransformExpr) : bool :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
    spec_value_is_one_raw (SpecTransformExpr_Const_f_value const_expr)
  | _ =>
    false
  end.

Definition expr_order_rank (expr : t_SpecTransformExpr) : t_usize :=
  match expr with
  | SpecTransformExpr_Add _ =>
    (0 : t_usize)
  | SpecTransformExpr_Const _ =>
    (1 : t_usize)
  | SpecTransformExpr_Div _ _ =>
    (2 : t_usize)
  | SpecTransformExpr_Mul _ _ =>
    (3 : t_usize)
  | SpecTransformExpr_Signal _ =>
    (4 : t_usize)
  | SpecTransformExpr_Sub _ _ =>
    (5 : t_usize)
  end.

Definition expr_sort_key (expr : t_SpecTransformExpr) : t_usize :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
    SpecTransformExpr_Const_f_sort_key const_expr
  | SpecTransformExpr_Signal signal_expr =>
    SpecTransformExpr_Signal_f_sort_key signal_expr
  | _ =>
    (0 : t_usize)
  end.

Definition expr_order_lt (lhs : t_SpecTransformExpr) (rhs : t_SpecTransformExpr) : bool :=
  let lhs_rank := expr_order_rank lhs in
  let rhs_rank := expr_order_rank rhs in
  if negb (f_eq lhs_rank rhs_rank) then
    f_lt lhs_rank rhs_rank
  else
    f_lt (expr_sort_key lhs) (expr_sort_key rhs).

Definition constraint_order_variant
  (constraint : t_SpecTransformConstraint) : t_usize :=
  match constraint with
  | SpecTransformConstraint_Equal _ =>
    (0 : t_usize)
  | SpecTransformConstraint_Boolean _ =>
    (1 : t_usize)
  | SpecTransformConstraint_Range _ =>
    (2 : t_usize)
  end.

Definition constraint_order_lt
  (lhs : t_SpecTransformConstraint)
  (rhs : t_SpecTransformConstraint) : bool :=
  let lhs_variant := constraint_order_variant lhs in
  let rhs_variant := constraint_order_variant rhs in
  if negb (f_eq lhs_variant rhs_variant) then
    f_lt lhs_variant rhs_variant
  else
    match lhs, rhs with
    | SpecTransformConstraint_Equal lhs_equal, SpecTransformConstraint_Equal rhs_equal =>
      let lhs_expr := SpecTransformConstraint_Equal_f_lhs lhs_equal in
      let lhs_rhs := SpecTransformConstraint_Equal_f_rhs lhs_equal in
      let lhs_label := SpecTransformConstraint_Equal_f_label_key lhs_equal in
      let rhs_expr := SpecTransformConstraint_Equal_f_lhs rhs_equal in
      let rhs_rhs := SpecTransformConstraint_Equal_f_rhs rhs_equal in
      let rhs_label := SpecTransformConstraint_Equal_f_label_key rhs_equal in
      if expr_order_lt lhs_expr rhs_expr then
        true
      else if expr_order_lt rhs_expr lhs_expr then
        false
      else if expr_order_lt lhs_rhs rhs_rhs then
        true
      else if expr_order_lt rhs_rhs lhs_rhs then
        false
      else
        f_lt lhs_label rhs_label
    | SpecTransformConstraint_Boolean lhs_boolean, SpecTransformConstraint_Boolean rhs_boolean =>
      let lhs_signal := SpecTransformConstraint_Boolean_f_signal_index lhs_boolean in
      let lhs_label := SpecTransformConstraint_Boolean_f_label_key lhs_boolean in
      let rhs_signal := SpecTransformConstraint_Boolean_f_signal_index rhs_boolean in
      let rhs_label := SpecTransformConstraint_Boolean_f_label_key rhs_boolean in
      if negb (f_eq lhs_signal rhs_signal) then
        f_lt lhs_signal rhs_signal
      else
        f_lt lhs_label rhs_label
    | SpecTransformConstraint_Range lhs_range, SpecTransformConstraint_Range rhs_range =>
      let lhs_signal := SpecTransformConstraint_Range_f_signal_index lhs_range in
      let lhs_bits := SpecTransformConstraint_Range_f_bits lhs_range in
      let lhs_label := SpecTransformConstraint_Range_f_label_key lhs_range in
      let rhs_signal := SpecTransformConstraint_Range_f_signal_index rhs_range in
      let rhs_bits := SpecTransformConstraint_Range_f_bits rhs_range in
      let rhs_label := SpecTransformConstraint_Range_f_label_key rhs_range in
      if negb (f_eq lhs_signal rhs_signal) then
        f_lt lhs_signal rhs_signal
      else if negb (u32_eq lhs_bits rhs_bits) then
        u32_lt lhs_bits rhs_bits
      else
        f_lt lhs_label rhs_label
    | _, _ =>
      false
    end.

Definition insert_signal_sorted
  (signal : t_SpecTransformSignal)
  (sorted : t_Slice t_SpecTransformSignal)
  : t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  insert_signal_sorted_from_list signal (Slice_f_v sorted) false (impl__new tt).

Definition push_unique_signal
  (signals : t_Vec ((t_usize)) ((t_Global)))
  (signal_index : t_usize) : t_Vec ((t_usize)) ((t_Global)) :=
  if contains_signal_index_list signals signal_index then
    signals
  else
    impl_1__push signals signal_index.

Fixpoint sort_signals_by_key_list
  (signals : list t_SpecTransformSignal)
  : t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  match signals with
  | [] =>
    impl__new tt
  | signal :: remaining_signals =>
    let sorted := sort_signals_by_key_list remaining_signals in
    insert_signal_sorted_from_list signal sorted false (impl__new tt)
  end.

Definition sort_signals_by_key
  (signals : t_Slice t_SpecTransformSignal)
  : t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  sort_signals_by_key_list (Slice_f_v signals).

Fixpoint insert_constraint_sorted_from_list
  (constraint : t_SpecTransformConstraint)
  (sorted : list t_SpecTransformConstraint)
  (inserted : bool)
  (result : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match sorted with
  | [] =>
    if inserted then
      result
    else
      impl_1__push result constraint
  | item :: remaining =>
    let '(result, inserted) :=
      if andb (negb inserted) (constraint_order_lt constraint item) then
        (impl_1__push result constraint, true)
      else
        (result, inserted) in
    let result := impl_1__push result item in
    insert_constraint_sorted_from_list constraint remaining inserted result
  end.

Definition insert_constraint_sorted
  (constraint : t_SpecTransformConstraint)
  (sorted : t_Slice t_SpecTransformConstraint)
  : t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  insert_constraint_sorted_from_list constraint (Slice_f_v sorted) false (impl__new tt).

Fixpoint sort_constraints_by_key_list
  (constraints : list t_SpecTransformConstraint)
  : t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    impl__new tt
  | constraint :: remaining_constraints =>
    let sorted := sort_constraints_by_key_list remaining_constraints in
    insert_constraint_sorted_from_list constraint sorted false (impl__new tt)
  end.

Definition sort_constraints_by_key
  (constraints : t_Slice t_SpecTransformConstraint)
  : t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  sort_constraints_by_key_list (Slice_f_v constraints).

Fixpoint collect_hint_signal_indices_from_list
  (hints : list t_SpecTransformHint)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match hints with
  | [] =>
    referenced
  | hint :: remaining_hints =>
    let referenced := push_unique_signal referenced (SpecTransformHint_f_target_signal_index hint) in
    let referenced := push_unique_signal referenced (SpecTransformHint_f_source_signal_index hint) in
    collect_hint_signal_indices_from_list remaining_hints referenced
  end.

Definition collect_hint_signal_indices_from
  (hints : t_Slice t_SpecTransformHint)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  collect_hint_signal_indices_from_list (Slice_f_v hints) referenced.

Fixpoint collect_expr_signals
  (expr : t_SpecTransformExpr)
  (signals : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match expr with
  | SpecTransformExpr_Const _ =>
    signals
  | SpecTransformExpr_Signal signal_expr =>
    push_unique_signal signals (SpecTransformExpr_Signal_f_signal_index signal_expr)
  | SpecTransformExpr_Add values =>
    let fix collect_values
      (values : list t_SpecTransformExpr)
      (signals : t_Vec ((t_usize)) ((t_Global)))
      : t_Vec ((t_usize)) ((t_Global)) :=
      match values with
      | [] =>
        signals
      | value :: remaining_values =>
        let signals := collect_expr_signals value signals in
        collect_values remaining_values signals
      end in
    collect_values values signals
  | SpecTransformExpr_Sub lhs rhs =>
    let signals := collect_expr_signals lhs signals in
    collect_expr_signals rhs signals
  | SpecTransformExpr_Mul lhs rhs =>
    let signals := collect_expr_signals lhs signals in
    collect_expr_signals rhs signals
  | SpecTransformExpr_Div lhs rhs =>
    let signals := collect_expr_signals lhs signals in
    collect_expr_signals rhs signals
  end.

Fixpoint collect_expr_signal_values_list
  (values : list t_SpecTransformExpr)
  (signals : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match values with
  | [] =>
    signals
  | value :: remaining_values =>
    let signals := collect_expr_signals value signals in
    collect_expr_signal_values_list remaining_values signals
  end.

Definition collect_expr_signal_values
  (values : t_Slice t_SpecTransformExpr)
  (signals : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  collect_expr_signal_values_list (Slice_f_v values) signals.

Definition collect_constraint_signals
  (constraint : t_SpecTransformConstraint)
  (signals : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    let signals := collect_expr_signals (SpecTransformConstraint_Equal_f_lhs equal_constraint) signals in
    collect_expr_signals (SpecTransformConstraint_Equal_f_rhs equal_constraint) signals
  | SpecTransformConstraint_Boolean boolean_constraint =>
    push_unique_signal signals (SpecTransformConstraint_Boolean_f_signal_index boolean_constraint)
  | SpecTransformConstraint_Range range_constraint =>
    push_unique_signal signals (SpecTransformConstraint_Range_f_signal_index range_constraint)
  end.

Fixpoint collect_constraint_signal_indices_from_list
  (constraints : list t_SpecTransformConstraint)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match constraints with
  | [] =>
    referenced
  | constraint :: remaining_constraints =>
    let referenced := collect_constraint_signals constraint referenced in
    collect_constraint_signal_indices_from_list remaining_constraints referenced
  end.

Definition collect_constraint_signal_indices_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  collect_constraint_signal_indices_from_list (Slice_f_v constraints) referenced.

Fixpoint collect_assignment_signal_indices_from_list
  (assignments : list t_SpecTransformAssignment)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  match assignments with
  | [] =>
    referenced
  | assignment :: remaining_assignments =>
    let referenced := push_unique_signal referenced (SpecTransformAssignment_f_target_signal_index assignment) in
    let referenced := collect_expr_signals (SpecTransformAssignment_f_expr assignment) referenced in
    collect_assignment_signal_indices_from_list remaining_assignments referenced
  end.

Definition collect_assignment_signal_indices_from
  (assignments : t_Slice t_SpecTransformAssignment)
  (referenced : t_Vec ((t_usize)) ((t_Global)))
  : t_Vec ((t_usize)) ((t_Global)) :=
  collect_assignment_signal_indices_from_list (Slice_f_v assignments) referenced.

Definition referenced_signal_indices
  (program : t_SpecTransformProgram)
  (constraints : t_Slice t_SpecTransformConstraint)
  : t_Vec ((t_usize)) ((t_Global)) :=
  let referenced := collect_constraint_signal_indices_from constraints (impl__new tt) in
  let referenced := collect_assignment_signal_indices_from (Build_t_Slice _ (SpecTransformProgram_f_assignments program)) referenced in
  collect_hint_signal_indices_from (Build_t_Slice _ (SpecTransformProgram_f_hints program)) referenced.

Fixpoint all_const_exprs_list
  (values : list t_SpecTransformExpr) : bool :=
  match values with
  | [] =>
    true
  | value :: remaining_values =>
    match value with
    | SpecTransformExpr_Const _ =>
      all_const_exprs_list remaining_values
    | _ =>
      false
    end
  end.

Definition all_const_exprs
  (values : t_Slice t_SpecTransformExpr) : bool :=
  all_const_exprs_list (Slice_f_v values).

Fixpoint append_transform_exprs_list
  (target : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  (values : list t_SpecTransformExpr)
  : t_Vec ((t_SpecTransformExpr)) ((t_Global)) :=
  match values with
  | [] =>
    target
  | value :: remaining_values =>
    append_transform_exprs_list (impl_1__push target value) remaining_values
  end.

Definition append_transform_exprs
  (target : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  (values : t_Slice t_SpecTransformExpr)
  : t_Vec ((t_SpecTransformExpr)) ((t_Global)) :=
  append_transform_exprs_list target (Slice_f_v values).

Fixpoint normalize_transform_expr
  (expr : t_SpecTransformExpr)
  (report : t_SpecNormalizationReport)
  : t_SpecNormalizationReport * t_SpecTransformExpr :=
  match expr with
  | SpecTransformExpr_Const _ =>
    (report, expr)
  | SpecTransformExpr_Signal _ =>
    (report, expr)
  | SpecTransformExpr_Add values =>
    let fix normalize_values
      (values : list t_SpecTransformExpr)
      (report : t_SpecNormalizationReport)
      (non_zero : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
      : t_SpecNormalizationReport * t_Vec ((t_SpecTransformExpr)) ((t_Global)) :=
      match values with
      | [] =>
        (report, non_zero)
      | value :: remaining_values =>
        let '(report, normalized) := normalize_transform_expr value report in
        let '(report, non_zero) :=
          match normalized with
          | SpecTransformExpr_Const const_expr =>
            if spec_value_is_zero_raw (SpecTransformExpr_Const_f_value const_expr) then
              (normalization_report_inc_algebraic report, non_zero)
            else
              (report, impl_1__push non_zero normalized)
          | _ =>
            (report, impl_1__push non_zero normalized)
          end in
        normalize_values remaining_values report non_zero
      end in
    let '(report, non_zero) := normalize_values values report (impl__new tt) in
    match non_zero with
    | [] =>
      (normalization_report_inc_constant report, zero_spec_expr tt)
    | single :: [] =>
      (report, single)
    | _ =>
      let report :=
        if all_const_exprs_list non_zero then
          normalization_report_inc_constant report
        else
          report in
      (report, SpecTransformExpr_Add non_zero)
    end
  | SpecTransformExpr_Mul lhs rhs =>
    let '(report, lhs) := normalize_transform_expr lhs report in
    let '(report, rhs) := normalize_transform_expr rhs report in
    if transform_expr_is_const_one lhs then
      (normalization_report_inc_algebraic report, rhs)
    else if transform_expr_is_const_one rhs then
      (normalization_report_inc_algebraic report, lhs)
    else if transform_expr_is_const_zero lhs then
      (normalization_report_inc_algebraic report, zero_spec_expr tt)
    else if transform_expr_is_const_zero rhs then
      (normalization_report_inc_algebraic report, zero_spec_expr tt)
    else
      (report, SpecTransformExpr_Mul lhs rhs)
  | SpecTransformExpr_Sub lhs rhs =>
    let '(report, lhs) := normalize_transform_expr lhs report in
    let '(report, rhs) := normalize_transform_expr rhs report in
    if transform_expr_is_const_zero rhs then
      (normalization_report_inc_algebraic report, lhs)
    else
      (report, SpecTransformExpr_Sub lhs rhs)
  | SpecTransformExpr_Div lhs rhs =>
    let '(report, lhs) := normalize_transform_expr lhs report in
    let '(report, rhs) := normalize_transform_expr rhs report in
    if transform_expr_is_const_one rhs then
      (normalization_report_inc_algebraic report, lhs)
    else if transform_expr_is_const_zero lhs then
      (normalization_report_inc_algebraic report, zero_spec_expr tt)
    else
      (report, SpecTransformExpr_Div lhs rhs)
  end.

Fixpoint normalize_non_zero_values_from_list
  (values : list t_SpecTransformExpr)
  (report : t_SpecNormalizationReport)
  (non_zero : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformExpr)) ((t_Global)) :=
  match values with
  | [] =>
    (report, non_zero)
  | value :: remaining_values =>
    let '(report, normalized) := normalize_transform_expr value report in
    let '(report, non_zero) :=
      match normalized with
      | SpecTransformExpr_Const const_expr =>
        if spec_value_is_zero_raw (SpecTransformExpr_Const_f_value const_expr) then
          (normalization_report_inc_algebraic report, non_zero)
        else
          (report, impl_1__push non_zero normalized)
      | _ =>
        (report, impl_1__push non_zero normalized)
      end in
    normalize_non_zero_values_from_list remaining_values report non_zero
  end.

Definition normalize_non_zero_values_from
  (values : t_Slice t_SpecTransformExpr)
  (report : t_SpecNormalizationReport)
  (non_zero : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformExpr)) ((t_Global)) :=
  normalize_non_zero_values_from_list (Slice_f_v values) report non_zero.

Definition normalize_transform_constraint
  (constraint : t_SpecTransformConstraint)
  (report : t_SpecNormalizationReport)
  : t_SpecNormalizationReport * t_SpecTransformConstraint :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    let '(report, lhs) := normalize_transform_expr (SpecTransformConstraint_Equal_f_lhs equal_constraint) report in
    let '(report, rhs) := normalize_transform_expr (SpecTransformConstraint_Equal_f_rhs equal_constraint) report in
    (report,
      SpecTransformConstraint_Equal
        {| SpecTransformConstraint_Equal_f_lhs := lhs;
           SpecTransformConstraint_Equal_f_rhs := rhs;
           SpecTransformConstraint_Equal_f_label_key :=
             SpecTransformConstraint_Equal_f_label_key equal_constraint |})
  | _ =>
    (report, constraint)
  end.

Definition normalize_expr_output
  (expr : t_SpecTransformExpr) : t_SpecTransformExpr :=
  snd (normalize_transform_expr expr empty_normalization_report).

Definition normalize_constraint_output
  (constraint : t_SpecTransformConstraint) : t_SpecTransformConstraint :=
  snd (normalize_transform_constraint constraint empty_normalization_report).

Fixpoint normalize_constraints_from_list
  (constraints : list t_SpecTransformConstraint)
  (report : t_SpecNormalizationReport)
  (normalized_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    (report, normalized_constraints)
  | constraint :: remaining_constraints =>
    let '(report, normalized_constraint) := normalize_transform_constraint constraint report in
    normalize_constraints_from_list
      remaining_constraints
      report
      (impl_1__push normalized_constraints normalized_constraint)
  end.

Definition normalize_constraints_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (report : t_SpecNormalizationReport)
  (normalized_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  normalize_constraints_from_list (Slice_f_v constraints) report normalized_constraints.

Fixpoint filter_live_signals_for_normalization_from_list
  (signals : list t_SpecTransformSignal)
  (referenced : list t_usize)
  (report : t_SpecNormalizationReport)
  (live_signals : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  match signals with
  | [] =>
    (report, live_signals)
  | signal :: remaining_signals =>
    let keep :=
      orb
        (orb
          (match SpecTransformSignal_f_visibility signal with
           | SpecTransformVisibility_Public => true
           | _ => false
           end)
          (match SpecTransformSignal_f_visibility signal with
           | SpecTransformVisibility_Constant => true
           | _ => false
           end))
        (contains_signal_index_list referenced (SpecTransformSignal_f_signal_index signal)) in
    let '(report, live_signals) :=
      if keep then
        (report, impl_1__push live_signals signal)
      else
        (normalization_report_inc_dead report, live_signals) in
    filter_live_signals_for_normalization_from_list
      remaining_signals referenced report live_signals
  end.

Definition filter_live_signals_for_normalization_from
  (signals : t_Slice t_SpecTransformSignal)
  (referenced : t_Slice t_usize)
  (report : t_SpecNormalizationReport)
  (live_signals : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_SpecNormalizationReport * t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  filter_live_signals_for_normalization_from_list
    (Slice_f_v signals)
    (Slice_f_v referenced)
    report
    live_signals.

Definition normalize_supported_program
  (program : t_SpecTransformProgram) : t_SpecNormalizationResult :=
  let report := empty_normalization_report in
  let '(report, constraints) :=
    normalize_constraints_from_list
      (SpecTransformProgram_f_constraints program)
      report
      (impl__new tt) in
  let referenced := referenced_signal_indices program (Build_t_Slice _ constraints) in
  let '(report, live_signals) :=
    filter_live_signals_for_normalization_from_list
      (SpecTransformProgram_f_signals program)
      referenced
      report
      (impl__new tt) in
  {| SpecNormalizationResult_f_program :=
       {| SpecTransformProgram_f_field := SpecTransformProgram_f_field program;
          SpecTransformProgram_f_signals := sort_signals_by_key_list live_signals;
          SpecTransformProgram_f_constraints := sort_constraints_by_key_list constraints;
          SpecTransformProgram_f_assignments := SpecTransformProgram_f_assignments program;
          SpecTransformProgram_f_hints := SpecTransformProgram_f_hints program |};
     SpecNormalizationResult_f_report := report |}.

Definition normalize_program_output
  (program : t_SpecTransformProgram) : t_SpecTransformProgram :=
  SpecNormalizationResult_f_program (normalize_supported_program program).

Fixpoint transform_expr_eq
  (lhs : t_SpecTransformExpr)
  (rhs : t_SpecTransformExpr) : bool :=
  match lhs, rhs with
  | SpecTransformExpr_Const lhs_const, SpecTransformExpr_Const rhs_const =>
    andb
      (f_eq (SpecTransformExpr_Const_f_sort_key lhs_const) (SpecTransformExpr_Const_f_sort_key rhs_const))
      (spec_field_value_eq_raw
        (SpecTransformExpr_Const_f_value lhs_const)
        (SpecTransformExpr_Const_f_value rhs_const))
  | SpecTransformExpr_Signal lhs_signal, SpecTransformExpr_Signal rhs_signal =>
    andb
      (f_eq (SpecTransformExpr_Signal_f_signal_index lhs_signal) (SpecTransformExpr_Signal_f_signal_index rhs_signal))
      (f_eq (SpecTransformExpr_Signal_f_sort_key lhs_signal) (SpecTransformExpr_Signal_f_sort_key rhs_signal))
  | SpecTransformExpr_Add lhs_values, SpecTransformExpr_Add rhs_values =>
    let fix eq_values
      (lhs_values rhs_values : list t_SpecTransformExpr) : bool :=
      match lhs_values, rhs_values with
      | [], [] =>
        true
      | lhs_value :: lhs_remaining, rhs_value :: rhs_remaining =>
        andb (transform_expr_eq lhs_value rhs_value)
          (eq_values lhs_remaining rhs_remaining)
      | _, _ =>
        false
      end in
    eq_values lhs_values rhs_values
  | SpecTransformExpr_Sub lhs_lhs lhs_rhs, SpecTransformExpr_Sub rhs_lhs rhs_rhs =>
    andb (transform_expr_eq lhs_lhs rhs_lhs) (transform_expr_eq lhs_rhs rhs_rhs)
  | SpecTransformExpr_Mul lhs_lhs lhs_rhs, SpecTransformExpr_Mul rhs_lhs rhs_rhs =>
    andb (transform_expr_eq lhs_lhs rhs_lhs) (transform_expr_eq lhs_rhs rhs_rhs)
  | SpecTransformExpr_Div lhs_lhs lhs_rhs, SpecTransformExpr_Div rhs_lhs rhs_rhs =>
    andb (transform_expr_eq lhs_lhs rhs_lhs) (transform_expr_eq lhs_rhs rhs_rhs)
  | _, _ =>
    false
  end.

Fixpoint transform_expr_list_eq_list
  (lhs : list t_SpecTransformExpr)
  (rhs : list t_SpecTransformExpr) : bool :=
  match lhs, rhs with
  | [], [] =>
    true
  | lhs_value :: lhs_remaining, rhs_value :: rhs_remaining =>
    andb (transform_expr_eq lhs_value rhs_value)
      (transform_expr_list_eq_list lhs_remaining rhs_remaining)
  | _, _ =>
    false
  end.

Definition transform_expr_list_eq
  (lhs : t_Slice t_SpecTransformExpr)
  (rhs : t_Slice t_SpecTransformExpr) : bool :=
  transform_expr_list_eq_list (Slice_f_v lhs) (Slice_f_v rhs).

Definition constraint_is_tautology
  (constraint : t_SpecTransformConstraint) : bool :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    transform_expr_eq
      (SpecTransformConstraint_Equal_f_lhs equal_constraint)
      (SpecTransformConstraint_Equal_f_rhs equal_constraint)
  | _ =>
    false
  end.

Definition transform_constraint_eq
  (lhs : t_SpecTransformConstraint)
  (rhs : t_SpecTransformConstraint) : bool :=
  match lhs, rhs with
  | SpecTransformConstraint_Equal lhs_equal, SpecTransformConstraint_Equal rhs_equal =>
    andb
      (andb
        (transform_expr_eq (SpecTransformConstraint_Equal_f_lhs lhs_equal) (SpecTransformConstraint_Equal_f_lhs rhs_equal))
        (transform_expr_eq (SpecTransformConstraint_Equal_f_rhs lhs_equal) (SpecTransformConstraint_Equal_f_rhs rhs_equal)))
      (f_eq
        (SpecTransformConstraint_Equal_f_label_key lhs_equal)
        (SpecTransformConstraint_Equal_f_label_key rhs_equal))
  | SpecTransformConstraint_Boolean lhs_boolean, SpecTransformConstraint_Boolean rhs_boolean =>
    andb
      (f_eq
        (SpecTransformConstraint_Boolean_f_signal_index lhs_boolean)
        (SpecTransformConstraint_Boolean_f_signal_index rhs_boolean))
      (f_eq
        (SpecTransformConstraint_Boolean_f_label_key lhs_boolean)
        (SpecTransformConstraint_Boolean_f_label_key rhs_boolean))
  | SpecTransformConstraint_Range lhs_range, SpecTransformConstraint_Range rhs_range =>
    andb
      (andb
        (f_eq
          (SpecTransformConstraint_Range_f_signal_index lhs_range)
          (SpecTransformConstraint_Range_f_signal_index rhs_range))
        (u32_eq
          (SpecTransformConstraint_Range_f_bits lhs_range)
          (SpecTransformConstraint_Range_f_bits rhs_range)))
      (f_eq
        (SpecTransformConstraint_Range_f_label_key lhs_range)
        (SpecTransformConstraint_Range_f_label_key rhs_range))
  | _, _ =>
    false
  end.

Definition constraint_equals_ignoring_label
  (lhs : t_SpecTransformConstraint)
  (rhs : t_SpecTransformConstraint) : bool :=
  match lhs, rhs with
  | SpecTransformConstraint_Equal lhs_equal, SpecTransformConstraint_Equal rhs_equal =>
    andb
      (transform_expr_eq (SpecTransformConstraint_Equal_f_lhs lhs_equal) (SpecTransformConstraint_Equal_f_lhs rhs_equal))
      (transform_expr_eq (SpecTransformConstraint_Equal_f_rhs lhs_equal) (SpecTransformConstraint_Equal_f_rhs rhs_equal))
  | SpecTransformConstraint_Boolean lhs_boolean, SpecTransformConstraint_Boolean rhs_boolean =>
    f_eq
      (SpecTransformConstraint_Boolean_f_signal_index lhs_boolean)
      (SpecTransformConstraint_Boolean_f_signal_index rhs_boolean)
  | SpecTransformConstraint_Range lhs_range, SpecTransformConstraint_Range rhs_range =>
    andb
      (f_eq
        (SpecTransformConstraint_Range_f_signal_index lhs_range)
        (SpecTransformConstraint_Range_f_signal_index rhs_range))
      (u32_eq
        (SpecTransformConstraint_Range_f_bits lhs_range)
        (SpecTransformConstraint_Range_f_bits rhs_range))
  | _, _ =>
    false
  end.

Fixpoint contains_equivalent_ir_constraint_list
  (constraints : list t_SpecTransformConstraint)
  (target : t_SpecTransformConstraint) : bool :=
  match constraints with
  | [] =>
    false
  | current :: remaining =>
    orb
      (constraint_equals_ignoring_label current target)
      (contains_equivalent_ir_constraint_list remaining target)
  end.

Definition contains_equivalent_ir_constraint
  (constraints : t_Slice t_SpecTransformConstraint)
  (target : t_SpecTransformConstraint) : bool :=
  contains_equivalent_ir_constraint_list (Slice_f_v constraints) target.

Fixpoint contains_exact_constraint_list
  (constraints : list t_SpecTransformConstraint)
  (target : t_SpecTransformConstraint) : bool :=
  match constraints with
  | [] =>
    false
  | current :: remaining =>
    orb
      (transform_constraint_eq current target)
      (contains_exact_constraint_list remaining target)
  end.

Definition contains_exact_constraint
  (constraints : t_Slice t_SpecTransformConstraint)
  (target : t_SpecTransformConstraint) : bool :=
  contains_exact_constraint_list (Slice_f_v constraints) target.

Fixpoint fold_transform_expr
  (expr : t_SpecTransformExpr)
  (field : t_FieldId)
  (folded_nodes : t_usize)
  : t_usize * t_SpecTransformExpr :=
  match expr with
  | SpecTransformExpr_Const _ =>
    (folded_nodes, expr)
  | SpecTransformExpr_Signal _ =>
    (folded_nodes, expr)
  | SpecTransformExpr_Add values =>
    let fix fold_terms
      (values : list t_SpecTransformExpr)
      (folded_nodes : t_usize)
      (const_acc : t_SpecFieldValue)
      (saw_const : bool)
      (terms : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
      : t_usize * (t_SpecFieldValue * bool * t_Vec ((t_SpecTransformExpr)) ((t_Global))) :=
      match values with
      | [] =>
        (folded_nodes, (const_acc, saw_const, terms))
      | value :: remaining_values =>
        let '(folded_nodes, folded) := fold_transform_expr value field folded_nodes in
        let '(folded_nodes, const_acc, saw_const, terms) :=
          match folded with
          | SpecTransformExpr_Const const_expr =>
            ( f_add folded_nodes (1 : t_usize),
              add_spec_values const_acc (SpecTransformExpr_Const_f_value const_expr) field,
              true,
              terms)
          | SpecTransformExpr_Add nested =>
            ( f_add folded_nodes (1 : t_usize),
              const_acc,
              saw_const,
              append_transform_exprs_list terms nested)
          | _ =>
            (folded_nodes, const_acc, saw_const, impl_1__push terms folded)
          end in
        fold_terms remaining_values folded_nodes const_acc saw_const terms
      end in
    let '(folded_nodes, folded_state) :=
      fold_terms values folded_nodes (zero_spec_value tt) false (impl__new tt) in
    let '(const_acc, saw_const, terms) := folded_state in
    let terms :=
      if andb saw_const (negb (spec_value_is_zero_raw const_acc)) then
        impl_1__push terms (make_const_expr const_acc (0 : t_usize))
      else
        terms in
    match terms with
    | [] =>
      (folded_nodes, zero_spec_expr tt)
    | single :: [] =>
      (folded_nodes, single)
    | _ =>
      (folded_nodes, SpecTransformExpr_Add terms)
    end
  | SpecTransformExpr_Sub lhs rhs =>
    let '(folded_nodes, lhs) := fold_transform_expr lhs field folded_nodes in
    let '(folded_nodes, rhs) := fold_transform_expr rhs field folded_nodes in
    match lhs, rhs with
    | SpecTransformExpr_Const lhs_const, SpecTransformExpr_Const rhs_const =>
      ( f_add folded_nodes (1 : t_usize),
        make_const_expr
          (sub_spec_values
            (SpecTransformExpr_Const_f_value lhs_const)
            (SpecTransformExpr_Const_f_value rhs_const)
            field)
          (0 : t_usize))
    | _, _ =>
      if transform_expr_is_const_zero rhs then
        (f_add folded_nodes (1 : t_usize), lhs)
      else
        (folded_nodes, SpecTransformExpr_Sub lhs rhs)
    end
  | SpecTransformExpr_Mul lhs rhs =>
    let '(folded_nodes, lhs) := fold_transform_expr lhs field folded_nodes in
    let '(folded_nodes, rhs) := fold_transform_expr rhs field folded_nodes in
    match lhs, rhs with
    | SpecTransformExpr_Const lhs_const, SpecTransformExpr_Const rhs_const =>
      ( f_add folded_nodes (1 : t_usize),
        make_const_expr
          (mul_spec_values
            (SpecTransformExpr_Const_f_value lhs_const)
            (SpecTransformExpr_Const_f_value rhs_const)
            field)
          (0 : t_usize))
    | _, _ =>
      if transform_expr_is_const_zero lhs then
        (f_add folded_nodes (1 : t_usize), zero_spec_expr tt)
      else if transform_expr_is_const_zero rhs then
        (f_add folded_nodes (1 : t_usize), zero_spec_expr tt)
      else if transform_expr_is_const_one lhs then
        (f_add folded_nodes (1 : t_usize), rhs)
      else if transform_expr_is_const_one rhs then
        (f_add folded_nodes (1 : t_usize), lhs)
      else
        (folded_nodes, SpecTransformExpr_Mul lhs rhs)
    end
  | SpecTransformExpr_Div lhs rhs =>
    let '(folded_nodes, lhs) := fold_transform_expr lhs field folded_nodes in
    let '(folded_nodes, rhs) := fold_transform_expr rhs field folded_nodes in
    match lhs, rhs with
    | SpecTransformExpr_Const lhs_const, SpecTransformExpr_Const rhs_const =>
      match div_spec_values
        (SpecTransformExpr_Const_f_value lhs_const)
        (SpecTransformExpr_Const_f_value rhs_const)
        field with
      | Option_Some value =>
        (f_add folded_nodes (1 : t_usize), make_const_expr value (0 : t_usize))
      | Option_None =>
        (folded_nodes, SpecTransformExpr_Div lhs rhs)
      end
    | _, _ =>
      if transform_expr_is_const_one rhs then
        (f_add folded_nodes (1 : t_usize), lhs)
      else
        (folded_nodes, SpecTransformExpr_Div lhs rhs)
    end
  end.

Fixpoint fold_add_terms_from_list
  (values : list t_SpecTransformExpr)
  (field : t_FieldId)
  (folded_nodes : t_usize)
  (const_acc : t_SpecFieldValue)
  (saw_const : bool)
  (terms : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  : t_usize * (t_SpecFieldValue * bool * t_Vec ((t_SpecTransformExpr)) ((t_Global))) :=
  match values with
  | [] =>
    (folded_nodes, (const_acc, saw_const, terms))
  | value :: remaining_values =>
    let '(folded_nodes, folded) := fold_transform_expr value field folded_nodes in
    let '(folded_nodes, const_acc, saw_const, terms) :=
      match folded with
      | SpecTransformExpr_Const const_expr =>
        ( f_add folded_nodes (1 : t_usize),
          add_spec_values const_acc (SpecTransformExpr_Const_f_value const_expr) field,
          true,
          terms)
      | SpecTransformExpr_Add nested =>
        ( f_add folded_nodes (1 : t_usize),
          const_acc,
          saw_const,
          append_transform_exprs_list terms nested)
      | _ =>
        (folded_nodes, const_acc, saw_const, impl_1__push terms folded)
      end in
    fold_add_terms_from_list remaining_values field folded_nodes const_acc saw_const terms
  end.

Definition fold_add_terms_from
  (values : t_Slice t_SpecTransformExpr)
  (field : t_FieldId)
  (folded_nodes : t_usize)
  (const_acc : t_SpecFieldValue)
  (saw_const : bool)
  (terms : t_Vec ((t_SpecTransformExpr)) ((t_Global)))
  : t_usize * (t_SpecFieldValue * bool * t_Vec ((t_SpecTransformExpr)) ((t_Global))) :=
  fold_add_terms_from_list (Slice_f_v values) field folded_nodes const_acc saw_const terms.

Definition fold_transform_constraint
  (constraint : t_SpecTransformConstraint)
  (field : t_FieldId)
  (folded_nodes : t_usize)
  : t_usize * t_SpecTransformConstraint :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    let '(folded_nodes, lhs) :=
      fold_transform_expr (SpecTransformConstraint_Equal_f_lhs equal_constraint) field folded_nodes in
    let '(folded_nodes, rhs) :=
      fold_transform_expr (SpecTransformConstraint_Equal_f_rhs equal_constraint) field folded_nodes in
    ( folded_nodes,
      SpecTransformConstraint_Equal
        {| SpecTransformConstraint_Equal_f_lhs := lhs;
           SpecTransformConstraint_Equal_f_rhs := rhs;
           SpecTransformConstraint_Equal_f_label_key :=
             SpecTransformConstraint_Equal_f_label_key equal_constraint |})
  | _ =>
    (folded_nodes, constraint)
  end.

Definition fold_expr_output
  (expr : t_SpecTransformExpr)
  (field : t_FieldId) : t_SpecTransformExpr :=
  snd (fold_transform_expr expr field (0 : t_usize)).

Definition fold_constraint_output
  (constraint : t_SpecTransformConstraint)
  (field : t_FieldId) : t_SpecTransformConstraint :=
  snd (fold_transform_constraint constraint field (0 : t_usize)).

Fixpoint fold_constraints_for_ir_from_list
  (constraints : list t_SpecTransformConstraint)
  (field : t_FieldId)
  (report : t_SpecOptimizeReport)
  (folded_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    (report, folded_constraints)
  | constraint :: remaining_constraints =>
    let '(folded_nodes, folded_constraint) :=
      fold_transform_constraint constraint field (SpecOptimizeReport_f_folded_expr_nodes report) in
    let report :=
      {| SpecOptimizeReport_f_folded_expr_nodes := folded_nodes;
         SpecOptimizeReport_f_deduplicated_constraints := SpecOptimizeReport_f_deduplicated_constraints report;
         SpecOptimizeReport_f_removed_tautology_constraints := SpecOptimizeReport_f_removed_tautology_constraints report;
         SpecOptimizeReport_f_removed_private_signals := SpecOptimizeReport_f_removed_private_signals report |} in
    let '(report, folded_constraints) :=
      if constraint_is_tautology folded_constraint then
        (optimize_report_inc_tautology report, folded_constraints)
      else
        (report, impl_1__push folded_constraints folded_constraint) in
    fold_constraints_for_ir_from_list remaining_constraints field report folded_constraints
  end.

Definition fold_constraints_for_ir_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (field : t_FieldId)
  (report : t_SpecOptimizeReport)
  (folded_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  fold_constraints_for_ir_from_list (Slice_f_v constraints) field report folded_constraints.

Fixpoint fold_constraints_for_zir_from_list
  (constraints : list t_SpecTransformConstraint)
  (field : t_FieldId)
  (report : t_SpecOptimizeReport)
  (folded_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    (report, folded_constraints)
  | constraint :: remaining_constraints =>
    let '(folded_nodes, folded_constraint) :=
      fold_transform_constraint constraint field (SpecOptimizeReport_f_folded_expr_nodes report) in
    let report :=
      {| SpecOptimizeReport_f_folded_expr_nodes := folded_nodes;
         SpecOptimizeReport_f_deduplicated_constraints := SpecOptimizeReport_f_deduplicated_constraints report;
         SpecOptimizeReport_f_removed_tautology_constraints := SpecOptimizeReport_f_removed_tautology_constraints report;
         SpecOptimizeReport_f_removed_private_signals := SpecOptimizeReport_f_removed_private_signals report |} in
    let '(report, folded_constraints) :=
      if constraint_is_tautology folded_constraint then
        (optimize_report_inc_tautology report, folded_constraints)
      else
        (report, impl_1__push folded_constraints folded_constraint) in
    fold_constraints_for_zir_from_list remaining_constraints field report folded_constraints
  end.

Definition fold_constraints_for_zir_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (field : t_FieldId)
  (report : t_SpecOptimizeReport)
  (folded_constraints : t_Vec ((t_SpecTransformConstraint)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  fold_constraints_for_zir_from_list (Slice_f_v constraints) field report folded_constraints.

Fixpoint dedup_constraints_ir_list
  (constraints : list t_SpecTransformConstraint)
  (report : t_SpecOptimizeReport)
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    (report, impl__new tt)
  | constraint :: remaining_constraints =>
    let '(report, deduped) := dedup_constraints_ir_list remaining_constraints report in
    if contains_equivalent_ir_constraint_list deduped constraint then
      (optimize_report_inc_dedup report, deduped)
    else
      (report, insert_constraint_sorted_from_list constraint deduped false (impl__new tt))
  end.

Definition dedup_constraints_ir
  (constraints : t_Slice t_SpecTransformConstraint)
  (report : t_SpecOptimizeReport)
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  dedup_constraints_ir_list (Slice_f_v constraints) report.

Fixpoint dedup_constraints_zir_list
  (constraints : list t_SpecTransformConstraint)
  (report : t_SpecOptimizeReport)
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    (report, impl__new tt)
  | constraint :: remaining_constraints =>
    let '(report, deduped) := dedup_constraints_zir_list remaining_constraints report in
    if contains_exact_constraint_list deduped constraint then
      (optimize_report_inc_dedup report, deduped)
    else
      (report, insert_constraint_sorted_from_list constraint deduped false (impl__new tt))
  end.

Definition dedup_constraints_zir
  (constraints : t_Slice t_SpecTransformConstraint)
  (report : t_SpecOptimizeReport)
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformConstraint)) ((t_Global)) :=
  dedup_constraints_zir_list (Slice_f_v constraints) report.

Fixpoint filter_live_signals__filter_live_signals_from_list
  (signals : list t_SpecTransformSignal)
  (referenced : list t_usize)
  (report : t_SpecOptimizeReport)
  (kept_signals : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  match signals with
  | [] =>
    (report, kept_signals)
  | signal :: remaining_signals =>
    let keep :=
      orb
        (negb
          (match SpecTransformSignal_f_visibility signal with
           | SpecTransformVisibility_Private => true
           | _ => false
           end))
        (contains_signal_index_list referenced (SpecTransformSignal_f_signal_index signal)) in
    let '(report, kept_signals) :=
      if keep then
        (report, impl_1__push kept_signals signal)
      else
        (optimize_report_inc_removed_private report, kept_signals) in
    filter_live_signals__filter_live_signals_from_list
      remaining_signals referenced report kept_signals
  end.

Definition filter_live_signals__filter_live_signals_from
  (signals : t_Slice t_SpecTransformSignal)
  (referenced : t_Slice t_usize)
  (report : t_SpecOptimizeReport)
  (kept_signals : t_Vec ((t_SpecTransformSignal)) ((t_Global)))
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  filter_live_signals__filter_live_signals_from_list
    (Slice_f_v signals)
    (Slice_f_v referenced)
    report
    kept_signals.

Definition filter_live_signals
  (program : t_SpecTransformProgram)
  (constraints : t_Slice t_SpecTransformConstraint)
  (report : t_SpecOptimizeReport)
  : t_SpecOptimizeReport * t_Vec ((t_SpecTransformSignal)) ((t_Global)) :=
  let referenced := referenced_signal_indices program constraints in
  filter_live_signals__filter_live_signals_from_list
    (SpecTransformProgram_f_signals program)
    referenced
    report
    (impl__new tt).

Fixpoint filter_assignments_by_signal_indices_from_list
  (assignments : list t_SpecTransformAssignment)
  (kept_signal_indices : list t_usize)
  (filtered_assignments : t_Vec ((t_SpecTransformAssignment)) ((t_Global)))
  : t_Vec ((t_SpecTransformAssignment)) ((t_Global)) :=
  match assignments with
  | [] =>
    filtered_assignments
  | assignment :: remaining_assignments =>
    let filtered_assignments :=
      if contains_signal_index_list kept_signal_indices (SpecTransformAssignment_f_target_signal_index assignment) then
        impl_1__push filtered_assignments assignment
      else
        filtered_assignments in
    filter_assignments_by_signal_indices_from_list
      remaining_assignments kept_signal_indices filtered_assignments
  end.

Definition filter_assignments_by_signal_indices_from
  (assignments : t_Slice t_SpecTransformAssignment)
  (kept_signal_indices : t_Slice t_usize)
  (filtered_assignments : t_Vec ((t_SpecTransformAssignment)) ((t_Global)))
  : t_Vec ((t_SpecTransformAssignment)) ((t_Global)) :=
  filter_assignments_by_signal_indices_from_list
    (Slice_f_v assignments)
    (Slice_f_v kept_signal_indices)
    filtered_assignments.

Fixpoint filter_hints_by_signal_indices_from_list
  (hints : list t_SpecTransformHint)
  (kept_signal_indices : list t_usize)
  (filtered_hints : t_Vec ((t_SpecTransformHint)) ((t_Global)))
  : t_Vec ((t_SpecTransformHint)) ((t_Global)) :=
  match hints with
  | [] =>
    filtered_hints
  | hint :: remaining_hints =>
    let filtered_hints :=
      if contains_signal_index_list kept_signal_indices (SpecTransformHint_f_target_signal_index hint) then
        impl_1__push filtered_hints hint
      else
        filtered_hints in
    filter_hints_by_signal_indices_from_list
      remaining_hints kept_signal_indices filtered_hints
  end.

Definition filter_hints_by_signal_indices_from
  (hints : t_Slice t_SpecTransformHint)
  (kept_signal_indices : t_Slice t_usize)
  (filtered_hints : t_Vec ((t_SpecTransformHint)) ((t_Global)))
  : t_Vec ((t_SpecTransformHint)) ((t_Global)) :=
  filter_hints_by_signal_indices_from_list
    (Slice_f_v hints)
    (Slice_f_v kept_signal_indices)
    filtered_hints.

Definition optimize_supported_ir_program
  (program : t_SpecTransformProgram) : t_SpecOptimizeResult :=
  let report := empty_optimize_report in
  let '(report, folded_constraints) :=
    fold_constraints_for_ir_from_list
      (SpecTransformProgram_f_constraints program)
      (SpecTransformProgram_f_field program)
      report
      (impl__new tt) in
  let '(report, constraints) := dedup_constraints_ir_list folded_constraints report in
  let '(report, signals) :=
    filter_live_signals program (Build_t_Slice _ constraints) report in
  let kept_signal_indices := collect_signal_indices_from_signals_list signals (impl__new tt) in
  let assignments :=
    filter_assignments_by_signal_indices_from_list
      (SpecTransformProgram_f_assignments program)
      kept_signal_indices
      (impl__new tt) in
  let hints :=
    filter_hints_by_signal_indices_from_list
      (SpecTransformProgram_f_hints program)
      kept_signal_indices
      (impl__new tt) in
  {| SpecOptimizeResult_f_program :=
       {| SpecTransformProgram_f_field := SpecTransformProgram_f_field program;
          SpecTransformProgram_f_signals := signals;
          SpecTransformProgram_f_constraints := constraints;
          SpecTransformProgram_f_assignments := assignments;
          SpecTransformProgram_f_hints := hints |};
     SpecOptimizeResult_f_report := report |}.

Definition optimize_ir_program_output
  (program : t_SpecTransformProgram) : t_SpecTransformProgram :=
  SpecOptimizeResult_f_program (optimize_supported_ir_program program).

Definition optimize_supported_zir_program
  (program : t_SpecTransformProgram) : t_SpecOptimizeResult :=
  let report := empty_optimize_report in
  let '(report, folded_constraints) :=
    fold_constraints_for_zir_from_list
      (SpecTransformProgram_f_constraints program)
      (SpecTransformProgram_f_field program)
      report
      (impl__new tt) in
  let '(report, constraints) := dedup_constraints_zir_list folded_constraints report in
  let '(report, signals) :=
    filter_live_signals program (Build_t_Slice _ constraints) report in
  {| SpecOptimizeResult_f_program :=
       {| SpecTransformProgram_f_field := SpecTransformProgram_f_field program;
          SpecTransformProgram_f_signals := signals;
          SpecTransformProgram_f_constraints := constraints;
          SpecTransformProgram_f_assignments := SpecTransformProgram_f_assignments program;
          SpecTransformProgram_f_hints := SpecTransformProgram_f_hints program |};
     SpecOptimizeResult_f_report := report |}.

Definition optimize_zir_program_output
  (program : t_SpecTransformProgram) : t_SpecTransformProgram :=
  SpecOptimizeResult_f_program (optimize_supported_zir_program program).

Fixpoint transform_eval_expr
  (expr : t_SpecTransformExpr)
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
    Result_Ok (normalize_spec_value (SpecTransformExpr_Const_f_value const_expr) field)
  | SpecTransformExpr_Signal signal_expr =>
    transform_signal_value witness (SpecTransformExpr_Signal_f_signal_index signal_expr) field
  | SpecTransformExpr_Add values =>
    let fix eval_values
      (values : list t_SpecTransformExpr)
      (acc : t_SpecFieldValue)
      : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :=
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
    eval_values values (zero_spec_value tt)
  | SpecTransformExpr_Sub lhs rhs =>
    match transform_eval_expr lhs witness field with
    | Result_Ok lhs_value =>
      match transform_eval_expr rhs witness field with
      | Result_Ok rhs_value =>
        Result_Ok (sub_spec_values lhs_value rhs_value field)
      | Result_Err error =>
        Result_Err error
      end
    | Result_Err error =>
      Result_Err error
    end
  | SpecTransformExpr_Mul lhs rhs =>
    match transform_eval_expr lhs witness field with
    | Result_Ok lhs_value =>
      match transform_eval_expr rhs witness field with
      | Result_Ok rhs_value =>
        Result_Ok (mul_spec_values lhs_value rhs_value field)
      | Result_Err error =>
        Result_Err error
      end
    | Result_Err error =>
      Result_Err error
    end
  | SpecTransformExpr_Div lhs rhs =>
    match transform_eval_expr lhs witness field with
    | Result_Ok lhs_value =>
      match transform_eval_expr rhs witness field with
      | Result_Ok rhs_value =>
        match div_spec_values lhs_value rhs_value field with
        | Option_Some value =>
          Result_Ok value
        | Option_None =>
          Result_Err SpecKernelCheckError_DivisionByZero
        end
      | Result_Err error =>
        Result_Err error
      end
    | Result_Err error =>
      Result_Err error
    end
  end.

Fixpoint transform_eval_exprs_list
  (values : list t_SpecTransformExpr)
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (acc : t_SpecFieldValue)
  : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :=
  match values with
  | [] =>
    Result_Ok acc
  | value :: remaining_values =>
    match transform_eval_expr value witness field with
    | Result_Ok evaluated =>
      transform_eval_exprs_list
        remaining_values witness field (add_spec_values acc evaluated field)
    | Result_Err error =>
      Result_Err error
    end
  end.

Definition transform_eval_exprs
  (values : t_Slice t_SpecTransformExpr)
  (witness : t_SpecKernelWitness)
  (field : t_FieldId)
  (acc : t_SpecFieldValue)
  : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :=
  transform_eval_exprs_list (Slice_f_v values) witness field acc.

Definition transform_check_constraint
  (constraint : t_SpecTransformConstraint)
  (constraint_index : t_usize)
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness)
  : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
  match constraint with
  | SpecTransformConstraint_Equal equal_constraint =>
    match transform_eval_expr (SpecTransformConstraint_Equal_f_lhs equal_constraint) witness (SpecTransformProgram_f_field program) with
    | Result_Ok lhs_value =>
      match transform_eval_expr (SpecTransformConstraint_Equal_f_rhs equal_constraint) witness (SpecTransformProgram_f_field program) with
      | Result_Ok rhs_value =>
        if spec_values_equal lhs_value rhs_value (SpecTransformProgram_f_field program) then
          Result_Ok tt
        else
          Result_Err
            (SpecKernelCheckError_EqualViolation
              {| SpecKernelCheckError_EqualViolation_f_constraint_index := constraint_index;
                 SpecKernelCheckError_EqualViolation_f_lhs := lhs_value;
                 SpecKernelCheckError_EqualViolation_f_rhs := rhs_value |})
      | Result_Err error =>
        Result_Err error
      end
    | Result_Err error =>
      Result_Err error
    end
  | SpecTransformConstraint_Boolean boolean_constraint =>
    let signal_index := SpecTransformConstraint_Boolean_f_signal_index boolean_constraint in
    match transform_signal_value witness signal_index (SpecTransformProgram_f_field program) with
    | Result_Ok value =>
      if spec_value_is_boolean value (SpecTransformProgram_f_field program) then
        Result_Ok tt
      else
        Result_Err
          (SpecKernelCheckError_BooleanViolation
            {| SpecKernelCheckError_BooleanViolation_f_constraint_index := constraint_index;
               SpecKernelCheckError_BooleanViolation_f_signal_index := signal_index;
               SpecKernelCheckError_BooleanViolation_f_value := value |})
    | Result_Err error =>
      Result_Err error
    end
  | SpecTransformConstraint_Range range_constraint =>
    let signal_index := SpecTransformConstraint_Range_f_signal_index range_constraint in
    let bits := SpecTransformConstraint_Range_f_bits range_constraint in
    match transform_signal_value witness signal_index (SpecTransformProgram_f_field program) with
    | Result_Ok value =>
      if spec_value_fits_bits value bits (SpecTransformProgram_f_field program) then
        Result_Ok tt
      else
        Result_Err
          (SpecKernelCheckError_RangeViolation
            {| SpecKernelCheckError_RangeViolation_f_constraint_index := constraint_index;
               SpecKernelCheckError_RangeViolation_f_signal_index := signal_index;
               SpecKernelCheckError_RangeViolation_f_bits := bits;
               SpecKernelCheckError_RangeViolation_f_value := value |})
    | Result_Err error =>
      Result_Err error
    end
  end.

Fixpoint transform_check_constraints_from_list
  (constraints : list t_SpecTransformConstraint)
  (constraint_index : t_usize)
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness)
  : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
  match constraints with
  | [] =>
    Result_Ok tt
  | constraint :: remaining_constraints =>
    match transform_check_constraint constraint constraint_index program witness with
    | Result_Ok tt =>
      transform_check_constraints_from_list
        remaining_constraints
        (f_add constraint_index (1 : t_usize))
        program
        witness
    | Result_Err error =>
      Result_Err error
    end
  end.

Definition transform_check_constraints_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (constraint_index : t_usize)
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness)
  : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
  transform_check_constraints_from_list (Slice_f_v constraints) constraint_index program witness.

Definition transform_check_program
  (program : t_SpecTransformProgram)
  (witness : t_SpecKernelWitness)
  : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
  transform_check_constraints_from_list
    (SpecTransformProgram_f_constraints program)
    (0 : t_usize)
    program
    witness.

Fixpoint transform_expr_to_kernel
  (expr : t_SpecTransformExpr)
  (field : t_FieldId) : t_SpecKernelExpr :=
  match expr with
  | SpecTransformExpr_Const const_expr =>
    SpecKernelExpr_Const (SpecTransformExpr_Const_f_value const_expr)
  | SpecTransformExpr_Signal signal_expr =>
    SpecKernelExpr_Signal (SpecTransformExpr_Signal_f_signal_index signal_expr)
  | SpecTransformExpr_Add values =>
    let fix to_kernel_values
      (values : list t_SpecTransformExpr)
      (acc : t_Option ((t_SpecKernelExpr)))
      : t_SpecKernelExpr :=
      match values with
      | [] =>
        match acc with
        | Option_Some acc =>
          acc
        | Option_None =>
          SpecKernelExpr_Const (zero_spec_value tt)
        end
      | value :: remaining_values =>
        let next_acc :=
          match acc with
          | Option_Some acc =>
            SpecKernelExpr_Add acc (transform_expr_to_kernel value field)
          | Option_None =>
            transform_expr_to_kernel value field
          end in
        to_kernel_values remaining_values (Option_Some next_acc)
      end in
    to_kernel_values values Option_None
  | SpecTransformExpr_Sub lhs rhs =>
    SpecKernelExpr_Sub (transform_expr_to_kernel lhs field) (transform_expr_to_kernel rhs field)
  | SpecTransformExpr_Mul lhs rhs =>
    SpecKernelExpr_Mul (transform_expr_to_kernel lhs field) (transform_expr_to_kernel rhs field)
  | SpecTransformExpr_Div lhs rhs =>
    SpecKernelExpr_Div (transform_expr_to_kernel lhs field) (transform_expr_to_kernel rhs field)
  end.

Fixpoint to_kernel_expr_from_list
  (values : list t_SpecTransformExpr)
  (acc : t_SpecKernelExpr)
  (field : t_FieldId) : t_SpecKernelExpr :=
  match values with
  | [] =>
    acc
  | value :: remaining_values =>
    to_kernel_expr_from_list
      remaining_values
      (SpecKernelExpr_Add acc (transform_expr_to_kernel value field))
      field
  end.

Definition to_kernel_expr_list
  (values : list t_SpecTransformExpr)
  (field : t_FieldId) : t_SpecKernelExpr :=
  match values with
  | [] =>
    SpecKernelExpr_Const (zero_spec_value tt)
  | first :: rest =>
    to_kernel_expr_from_list rest (transform_expr_to_kernel first field) field
  end.

Definition to_kernel_expr_from
  (values : t_Slice t_SpecTransformExpr)
  (acc : t_SpecKernelExpr)
  (field : t_FieldId) : t_SpecKernelExpr :=
  to_kernel_expr_from_list (Slice_f_v values) acc field.

Definition to_kernel_expr
  (values : t_Slice t_SpecTransformExpr)
  (field : t_FieldId) : t_SpecKernelExpr :=
  to_kernel_expr_list (Slice_f_v values) field.

Fixpoint transform_constraints_to_kernel_from_list
  (constraints : list t_SpecTransformConstraint)
  (index : t_usize)
  (kernel_constraints : t_Vec ((t_SpecKernelConstraint)) ((t_Global)))
  (field : t_FieldId)
  : t_Vec ((t_SpecKernelConstraint)) ((t_Global)) :=
  match constraints with
  | [] =>
    kernel_constraints
  | constraint :: remaining_constraints =>
    let kernel_constraints :=
      impl_1__push kernel_constraints
        (match constraint with
         | SpecTransformConstraint_Equal equal_constraint =>
           SpecKernelConstraint_Equal
             {| SpecKernelConstraint_Equal_f_index := index;
                SpecKernelConstraint_Equal_f_lhs :=
                  transform_expr_to_kernel (SpecTransformConstraint_Equal_f_lhs equal_constraint) field;
                SpecKernelConstraint_Equal_f_rhs :=
                  transform_expr_to_kernel (SpecTransformConstraint_Equal_f_rhs equal_constraint) field |}
         | SpecTransformConstraint_Boolean boolean_constraint =>
           SpecKernelConstraint_Boolean
             {| SpecKernelConstraint_Boolean_f_index := index;
                SpecKernelConstraint_Boolean_f_signal :=
                  SpecTransformConstraint_Boolean_f_signal_index boolean_constraint |}
         | SpecTransformConstraint_Range range_constraint =>
           SpecKernelConstraint_Range
             {| SpecKernelConstraint_Range_f_index := index;
                SpecKernelConstraint_Range_f_signal :=
                  SpecTransformConstraint_Range_f_signal_index range_constraint;
                SpecKernelConstraint_Range_f_bits :=
                  SpecTransformConstraint_Range_f_bits range_constraint |}
         end) in
    transform_constraints_to_kernel_from_list
      remaining_constraints
      (f_add index (1 : t_usize))
      kernel_constraints
      field
  end.

Definition transform_constraints_to_kernel_from
  (constraints : t_Slice t_SpecTransformConstraint)
  (index : t_usize)
  (kernel_constraints : t_Vec ((t_SpecKernelConstraint)) ((t_Global)))
  (field : t_FieldId)
  : t_Vec ((t_SpecKernelConstraint)) ((t_Global)) :=
  transform_constraints_to_kernel_from_list
    (Slice_f_v constraints)
    index
    kernel_constraints
    field.

Definition transform_program_to_kernel
  (program : t_SpecTransformProgram) : t_SpecKernelProgram :=
  {| SpecKernelProgram_f_field := SpecTransformProgram_f_field program;
     SpecKernelProgram_f_constraints :=
       transform_constraints_to_kernel_from_list
         (SpecTransformProgram_f_constraints program)
         (0 : t_usize)
         (impl__new tt)
         (SpecTransformProgram_f_field program);
     SpecKernelProgram_f_lookup_tables := impl__new tt |}.

(* END TRANSFORM EXECUTABLE RUNTIME *)
