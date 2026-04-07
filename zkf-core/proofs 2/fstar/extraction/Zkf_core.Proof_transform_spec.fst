module Zkf_core.Proof_transform_spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Zkf_core.Proof_kernel_spec in
  ()

type t_SpecTransformVisibility =
  | SpecTransformVisibility_Public : t_SpecTransformVisibility
  | SpecTransformVisibility_Constant : t_SpecTransformVisibility
  | SpecTransformVisibility_Private : t_SpecTransformVisibility

type t_SpecTransformSignal = {
  f_signal_index:usize;
  f_sort_key:usize;
  f_visibility:t_SpecTransformVisibility;
  f_constant_value:Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue;
  f_required:bool
}

type t_SpecTransformHint = {
  f_target_signal_index:usize;
  f_source_signal_index:usize
}

type t_SpecNormalizationReport = {
  f_algebraic_rewrites:u32;
  f_constant_folds:u32;
  f_dead_signals_removed:u32
}

type t_SpecOptimizeReport = {
  f_folded_expr_nodes:usize;
  f_deduplicated_constraints:usize;
  f_removed_tautology_constraints:usize;
  f_removed_private_signals:usize
}

let zero_spec_value (_: Prims.unit) : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.spec_field_value_zero ()

let normalize_spec_value
      (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.Spec_field_ops.normalize value field

let add_spec_values
      (lhs rhs: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.Spec_field_ops.add lhs rhs field

let sub_spec_values
      (lhs rhs: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.Spec_field_ops.sub lhs rhs field

let mul_spec_values
      (lhs rhs: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.Spec_field_ops.mul lhs rhs field

let div_spec_values
      (lhs rhs: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.Spec_field_ops.div lhs rhs field

let spec_values_equal
      (lhs rhs: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool = Zkf_core.Proof_kernel_spec.Spec_field_ops.eq lhs rhs field

let spec_value_is_boolean
      (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool = Zkf_core.Proof_kernel_spec.Spec_field_ops.is_boolean value field

let spec_value_fits_bits
      (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (bits: u32)
      (field: Zkf_core.Field.t_FieldId)
    : bool = Zkf_core.Proof_kernel_spec.Spec_field_ops.fits_bits value bits field

let spec_value_is_zero_raw (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue) : bool =
  Zkf_core.Proof_kernel_spec.spec_field_value_is_zero_raw value

let spec_value_is_one_raw (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue) : bool =
  Zkf_core.Proof_kernel_spec.spec_field_value_is_one_raw value

let sort_signals_by_key (signals: t_Slice t_SpecTransformSignal)
    : Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
  let sorted:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec #t_SpecTransformSignal signals
  in
  let sorted:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (Alloc.Slice.impl__sort_by #t_SpecTransformSignal
          #(t_SpecTransformSignal -> t_SpecTransformSignal -> Core_models.Cmp.t_Ordering)
          (Alloc.Vec.impl_1__as_slice sorted <: t_Slice t_SpecTransformSignal)
          (fun lhs rhs ->
              let lhs:t_SpecTransformSignal = lhs in
              let rhs:t_SpecTransformSignal = rhs in
              Core_models.Cmp.f_cmp #usize
                #FStar.Tactics.Typeclasses.solve
                lhs.f_sort_key
                rhs.f_sort_key
              <:
              Core_models.Cmp.t_Ordering)
        <:
        t_Slice t_SpecTransformSignal)
  in
  sorted

let signal_index_is_marked (signal_marks: t_Slice u8) (signal_index: usize) : bool =
  (Core_models.Option.impl__unwrap_or #u8
      (Core_models.Option.impl_2__copied #u8
          (Core_models.Slice.impl__get #u8 #usize signal_marks signal_index
            <:
            Core_models.Option.t_Option u8)
        <:
        Core_models.Option.t_Option u8)
      (mk_u8 0)
    <:
    u8) <>.
  mk_u8 0

let mark_signal_index (signal_marks: t_Slice u8) (signal_index: usize) : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    if signal_index <. (Core_models.Slice.impl__len #u8 signal_marks <: usize)
    then
      let signal_marks:t_Slice u8 =
        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize signal_marks
          signal_index
          (mk_u8 1)
      in
      signal_marks
    else signal_marks
  in
  signal_marks

let collect_hint_signal_marks (hints: t_Slice t_SpecTransformHint) (signal_marks: t_Slice u8)
    : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
            t_SpecTransformHint)
          #FStar.Tactics.Typeclasses.solve
          hints
        <:
        Core_models.Slice.Iter.t_Iter t_SpecTransformHint)
      signal_marks
      (fun signal_marks hint ->
          let signal_marks:t_Slice u8 = signal_marks in
          let hint:t_SpecTransformHint = hint in
          let signal_marks:t_Slice u8 = mark_signal_index signal_marks hint.f_target_signal_index in
          let signal_marks:t_Slice u8 = mark_signal_index signal_marks hint.f_source_signal_index in
          signal_marks)
  in
  signal_marks

let collect_signal_marks_from_signals (signals: t_Slice t_SpecTransformSignal) (signal_count: usize)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let kept_signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #u8 (mk_u8 0) signal_count
  in
  let kept_signal_marks:Prims.unit =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
            t_SpecTransformSignal)
          #FStar.Tactics.Typeclasses.solve
          signals
        <:
        Core_models.Slice.Iter.t_Iter t_SpecTransformSignal)
      kept_signal_marks
      (fun kept_signal_marks signal ->
          let kept_signal_marks:Prims.unit = kept_signal_marks in
          let signal:t_SpecTransformSignal = signal in
          Alloc.Slice.impl__to_vec (mark_signal_index (Alloc.Vec.impl_1__as_slice kept_signal_marks
                  <:
                  t_Slice u8)
                signal.f_signal_index
              <:
              t_Slice u8)
          <:
          Prims.unit)
  in
  kept_signal_marks

let transform_signal_value
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
      (signal_index: usize)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__get #(Core_models.Option.t_Option
        Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      #usize
      (Alloc.Vec.impl_1__as_slice witness.Zkf_core.Proof_kernel_spec.f_values
        <:
        t_Slice (Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue))
      signal_index
    <:
    Core_models.Option.t_Option
    (Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
  with
  | Core_models.Option.Option_Some (Core_models.Option.Option_Some value) ->
    Core_models.Result.Result_Ok (normalize_spec_value value field)
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
  | _ ->
    Core_models.Result.Result_Err
    (Zkf_core.Proof_kernel_spec.SpecKernelCheckError_MissingSignal
      ({ Zkf_core.Proof_kernel_spec.f_signal_index = signal_index })
      <:
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError

type t_SpecTransformExpr =
  | SpecTransformExpr_Const {
    f_value:Zkf_core.Proof_kernel_spec.t_SpecFieldValue;
    f_sort_key:usize
  }: t_SpecTransformExpr
  | SpecTransformExpr_Signal {
    f_signal_index:usize;
    f_sort_key:usize
  }: t_SpecTransformExpr
  | SpecTransformExpr_Add : Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global
    -> t_SpecTransformExpr
  | SpecTransformExpr_Sub : t_SpecTransformExpr -> t_SpecTransformExpr -> t_SpecTransformExpr
  | SpecTransformExpr_Mul : t_SpecTransformExpr -> t_SpecTransformExpr -> t_SpecTransformExpr
  | SpecTransformExpr_Div : t_SpecTransformExpr -> t_SpecTransformExpr -> t_SpecTransformExpr

let rec insert_signal_sorted_from
      (signal: t_SpecTransformSignal)
      (sorted: t_Slice t_SpecTransformSignal)
      (inserted: bool)
      (result: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformSignal sorted
    <:
    Core_models.Option.t_Option (t_SpecTransformSignal & t_Slice t_SpecTransformSignal)
  with
  | Core_models.Option.Option_Some (item, remaining) ->
    let (result: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global), (inserted: bool) =
      if ~.inserted && signal.f_sort_key <. item.f_sort_key
      then
        let result:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformSignal
            #Alloc.Alloc.t_Global
            result
            (Core_models.Clone.f_clone #t_SpecTransformSignal
                #FStar.Tactics.Typeclasses.solve
                signal
              <:
              t_SpecTransformSignal)
        in
        result, true <: (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & bool)
      else result, inserted <: (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & bool)
    in
    let result:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
      Alloc.Vec.impl_1__push #t_SpecTransformSignal
        #Alloc.Alloc.t_Global
        result
        (Core_models.Clone.f_clone #t_SpecTransformSignal #FStar.Tactics.Typeclasses.solve item
          <:
          t_SpecTransformSignal)
    in
    insert_signal_sorted_from signal remaining inserted result
  | Core_models.Option.Option_None  ->
    let result:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
      if ~.inserted
      then
        let result:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformSignal #Alloc.Alloc.t_Global result signal
        in
        result
      else result
    in
    result

let rec filter_live_signals_for_normalization_from
      (signals: t_Slice t_SpecTransformSignal)
      (referenced_marks: t_Slice u8)
      (report: t_SpecNormalizationReport)
      (live_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
    : (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
  let
  ((live_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global),
    (report: t_SpecNormalizationReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformSignal signals
      <:
      Core_models.Option.t_Option (t_SpecTransformSignal & t_Slice t_SpecTransformSignal)
    with
    | Core_models.Option.Option_Some (signal, remaining_signals) ->
      let keep:bool =
        (match signal.f_visibility <: t_SpecTransformVisibility with
          | SpecTransformVisibility_Public  -> true
          | _ -> false) ||
        (match signal.f_visibility <: t_SpecTransformVisibility with
          | SpecTransformVisibility_Constant  -> true
          | _ -> false) ||
        signal_index_is_marked referenced_marks signal.f_signal_index
      in
      let
      (live_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global),
      (report: t_SpecNormalizationReport) =
        if keep
        then
          let live_signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_SpecTransformSignal
              #Alloc.Alloc.t_Global
              live_signals
              (Core_models.Clone.f_clone #t_SpecTransformSignal
                  #FStar.Tactics.Typeclasses.solve
                  signal
                <:
                t_SpecTransformSignal)
          in
          live_signals, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport)
        else
          let report:t_SpecNormalizationReport =
            { report with f_dead_signals_removed = report.f_dead_signals_removed +! mk_u32 1 }
            <:
            t_SpecNormalizationReport
          in
          live_signals, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport)
      in
      let
      (tmp0: t_SpecNormalizationReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
        filter_live_signals_for_normalization_from remaining_signals
          referenced_marks
          report
          live_signals
      in
      let report:t_SpecNormalizationReport = tmp0 in
      (live_signals, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport)),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (live_signals, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport)),
      live_signals
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)

let rec filter_live_signals__filter_live_signals_from
      (signals: t_Slice t_SpecTransformSignal)
      (referenced_marks: t_Slice u8)
      (report: t_SpecOptimizeReport)
      (kept_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
  let
  ((kept_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global),
    (report: t_SpecOptimizeReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformSignal signals
      <:
      Core_models.Option.t_Option (t_SpecTransformSignal & t_Slice t_SpecTransformSignal)
    with
    | Core_models.Option.Option_Some (signal, remaining_signals) ->
      let keep:bool =
        ~.(match signal.f_visibility <: t_SpecTransformVisibility with
          | SpecTransformVisibility_Private  -> true
          | _ -> false) ||
        signal_index_is_marked referenced_marks signal.f_signal_index
      in
      let
      (kept_signals: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global),
      (report: t_SpecOptimizeReport) =
        if keep
        then
          let kept_signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_SpecTransformSignal
              #Alloc.Alloc.t_Global
              kept_signals
              (Core_models.Clone.f_clone #t_SpecTransformSignal
                  #FStar.Tactics.Typeclasses.solve
                  signal
                <:
                t_SpecTransformSignal)
          in
          kept_signals, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport)
        else
          let report:t_SpecOptimizeReport =
            {
              report with
              f_removed_private_signals = report.f_removed_private_signals +! mk_usize 1
            }
            <:
            t_SpecOptimizeReport
          in
          kept_signals, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport)
      in
      let
      (tmp0: t_SpecOptimizeReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
        filter_live_signals__filter_live_signals_from remaining_signals
          referenced_marks
          report
          kept_signals
      in
      let report:t_SpecOptimizeReport = tmp0 in
      (kept_signals, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (kept_signals, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      kept_signals
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)

let rec filter_hints_by_signal_indices_from
      (hints: t_Slice t_SpecTransformHint)
      (kept_signal_marks: t_Slice u8)
      (filtered_hints: Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformHint hints
    <:
    Core_models.Option.t_Option (t_SpecTransformHint & t_Slice t_SpecTransformHint)
  with
  | Core_models.Option.Option_Some (hint, remaining_hints) ->
    let filtered_hints:Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global =
      if signal_index_is_marked kept_signal_marks hint.f_target_signal_index
      then
        let filtered_hints:Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformHint
            #Alloc.Alloc.t_Global
            filtered_hints
            (Core_models.Clone.f_clone #t_SpecTransformHint #FStar.Tactics.Typeclasses.solve hint
              <:
              t_SpecTransformHint)
        in
        filtered_hints
      else filtered_hints
    in
    filter_hints_by_signal_indices_from remaining_hints kept_signal_marks filtered_hints
  | Core_models.Option.Option_None  -> filtered_hints

type t_SpecTransformConstraint =
  | SpecTransformConstraint_Equal {
    f_lhs:t_SpecTransformExpr;
    f_rhs:t_SpecTransformExpr;
    f_label_key:usize
  }: t_SpecTransformConstraint
  | SpecTransformConstraint_Boolean {
    f_signal_index:usize;
    f_signal_sort_key:usize;
    f_label_key:usize
  }: t_SpecTransformConstraint
  | SpecTransformConstraint_Range {
    f_signal_index:usize;
    f_signal_sort_key:usize;
    f_bits:u32;
    f_label_key:usize
  }: t_SpecTransformConstraint

type t_SpecTransformAssignment = {
  f_target_signal_index:usize;
  f_expr:t_SpecTransformExpr
}

type t_SpecTransformProgram = {
  f_field:Zkf_core.Field.t_FieldId;
  f_signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global;
  f_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global;
  f_assignments:Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global;
  f_hints:Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global
}

type t_SpecNormalizationResult = {
  f_program:t_SpecTransformProgram;
  f_report:t_SpecNormalizationReport
}

type t_SpecOptimizeResult = {
  f_program:t_SpecTransformProgram;
  f_report:t_SpecOptimizeReport
}

let zero_spec_expr (_: Prims.unit) : t_SpecTransformExpr =
  SpecTransformExpr_Const ({ f_value = zero_spec_value (); f_sort_key = mk_usize 0 })
  <:
  t_SpecTransformExpr

let expr_order_rank (expr: t_SpecTransformExpr) : usize =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Add _ -> mk_usize 0
  | SpecTransformExpr_Const {  } -> mk_usize 1
  | SpecTransformExpr_Div _ _ -> mk_usize 2
  | SpecTransformExpr_Mul _ _ -> mk_usize 3
  | SpecTransformExpr_Signal {  } -> mk_usize 4
  | SpecTransformExpr_Sub _ _ -> mk_usize 5

let expr_sort_key (expr: t_SpecTransformExpr) : usize =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Const { f_sort_key = sort_key }
  | SpecTransformExpr_Signal { f_sort_key = sort_key } -> sort_key
  | _ -> mk_usize 0

let expr_order_lt (lhs rhs: t_SpecTransformExpr) : bool =
  let lhs_rank:usize = expr_order_rank lhs in
  let rhs_rank:usize = expr_order_rank rhs in
  if lhs_rank <>. rhs_rank
  then lhs_rank <. rhs_rank
  else (expr_sort_key lhs <: usize) <. (expr_sort_key rhs <: usize)

let expr_order_cmp (lhs rhs: t_SpecTransformExpr) : Core_models.Cmp.t_Ordering =
  let lhs_rank:usize = expr_order_rank lhs in
  let rhs_rank:usize = expr_order_rank rhs in
  Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
    (Core_models.Cmp.f_cmp #usize #FStar.Tactics.Typeclasses.solve lhs_rank rhs_rank
      <:
      Core_models.Cmp.t_Ordering)
    (fun temp_0_ ->
        let _:Prims.unit = temp_0_ in
        Core_models.Cmp.f_cmp #usize
          #FStar.Tactics.Typeclasses.solve
          (expr_sort_key lhs <: usize)
          (expr_sort_key rhs <: usize)
        <:
        Core_models.Cmp.t_Ordering)

let constraint_order_variant (constraint: t_SpecTransformConstraint) : usize =
  match constraint <: t_SpecTransformConstraint with
  | SpecTransformConstraint_Equal {  } -> mk_usize 0
  | SpecTransformConstraint_Boolean {  } -> mk_usize 1
  | SpecTransformConstraint_Range {  } -> mk_usize 2

let constraint_order_lt (lhs rhs: t_SpecTransformConstraint) : bool =
  let lhs_variant:usize = constraint_order_variant lhs in
  let rhs_variant:usize = constraint_order_variant rhs in
  if lhs_variant <>. rhs_variant
  then lhs_variant <. rhs_variant
  else
    match lhs, rhs <: (t_SpecTransformConstraint & t_SpecTransformConstraint) with
    | SpecTransformConstraint_Equal { f_lhs = lhs_expr ; f_rhs = lhs_rhs ; f_label_key = lhs_label },
    SpecTransformConstraint_Equal { f_lhs = rhs_expr ; f_rhs = rhs_rhs ; f_label_key = rhs_label } ->
      if expr_order_lt lhs_expr rhs_expr
      then true
      else
        if expr_order_lt rhs_expr lhs_expr
        then false
        else
          if expr_order_lt lhs_rhs rhs_rhs
          then true
          else if expr_order_lt rhs_rhs lhs_rhs then false else lhs_label <. rhs_label
    | SpecTransformConstraint_Boolean
      { f_signal_sort_key = lhs_signal_sort_key ;
        f_signal_index = lhs_signal_index ;
        f_label_key = lhs_label },
    SpecTransformConstraint_Boolean
      { f_signal_sort_key = rhs_signal_sort_key ;
        f_signal_index = rhs_signal_index ;
        f_label_key = rhs_label } ->
      if lhs_signal_sort_key <>. rhs_signal_sort_key
      then lhs_signal_sort_key <. rhs_signal_sort_key
      else
        if lhs_signal_index <>. rhs_signal_index
        then lhs_signal_index <. rhs_signal_index
        else lhs_label <. rhs_label
    | SpecTransformConstraint_Range
      { f_signal_sort_key = lhs_signal_sort_key ;
        f_signal_index = lhs_signal_index ;
        f_bits = lhs_bits ;
        f_label_key = lhs_label },
    SpecTransformConstraint_Range
      { f_signal_sort_key = rhs_signal_sort_key ;
        f_signal_index = rhs_signal_index ;
        f_bits = rhs_bits ;
        f_label_key = rhs_label } ->
      if lhs_signal_sort_key <>. rhs_signal_sort_key
      then lhs_signal_sort_key <. rhs_signal_sort_key
      else
        if lhs_signal_index <>. rhs_signal_index
        then lhs_signal_index <. rhs_signal_index
        else if lhs_bits <>. rhs_bits then lhs_bits <. rhs_bits else lhs_label <. rhs_label
    | _ -> false

let constraint_order_cmp (lhs rhs: t_SpecTransformConstraint) : Core_models.Cmp.t_Ordering =
  let lhs_variant:usize = constraint_order_variant lhs in
  let rhs_variant:usize = constraint_order_variant rhs in
  Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
    (Core_models.Cmp.f_cmp #usize #FStar.Tactics.Typeclasses.solve lhs_variant rhs_variant
      <:
      Core_models.Cmp.t_Ordering)
    (fun temp_0_ ->
        let _:Prims.unit = temp_0_ in
        match lhs, rhs <: (t_SpecTransformConstraint & t_SpecTransformConstraint) with
        | SpecTransformConstraint_Equal
          { f_lhs = lhs_expr ; f_rhs = lhs_rhs ; f_label_key = lhs_label },
        SpecTransformConstraint_Equal
          { f_lhs = rhs_expr ; f_rhs = rhs_rhs ; f_label_key = rhs_label } ->
          Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
            (Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
                (expr_order_cmp lhs_expr rhs_expr <: Core_models.Cmp.t_Ordering)
                (fun temp_0_ ->
                    let _:Prims.unit = temp_0_ in
                    expr_order_cmp lhs_rhs rhs_rhs <: Core_models.Cmp.t_Ordering)
              <:
              Core_models.Cmp.t_Ordering)
            (fun temp_0_ ->
                let _:Prims.unit = temp_0_ in
                Core_models.Cmp.f_cmp #usize #FStar.Tactics.Typeclasses.solve lhs_label rhs_label
                <:
                Core_models.Cmp.t_Ordering)
          <:
          Core_models.Cmp.t_Ordering
        | SpecTransformConstraint_Boolean
          { f_signal_sort_key = lhs_signal_sort_key ;
            f_signal_index = lhs_signal_index ;
            f_label_key = lhs_label },
        SpecTransformConstraint_Boolean
          { f_signal_sort_key = rhs_signal_sort_key ;
            f_signal_index = rhs_signal_index ;
            f_label_key = rhs_label } ->
          Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
            (Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
                (Core_models.Cmp.f_cmp #usize
                    #FStar.Tactics.Typeclasses.solve
                    lhs_signal_sort_key
                    rhs_signal_sort_key
                  <:
                  Core_models.Cmp.t_Ordering)
                (fun temp_0_ ->
                    let _:Prims.unit = temp_0_ in
                    Core_models.Cmp.f_cmp #usize
                      #FStar.Tactics.Typeclasses.solve
                      lhs_signal_index
                      rhs_signal_index
                    <:
                    Core_models.Cmp.t_Ordering)
              <:
              Core_models.Cmp.t_Ordering)
            (fun temp_0_ ->
                let _:Prims.unit = temp_0_ in
                Core_models.Cmp.f_cmp #usize #FStar.Tactics.Typeclasses.solve lhs_label rhs_label
                <:
                Core_models.Cmp.t_Ordering)
          <:
          Core_models.Cmp.t_Ordering
        | SpecTransformConstraint_Range
          { f_signal_sort_key = lhs_signal_sort_key ;
            f_signal_index = lhs_signal_index ;
            f_bits = lhs_bits ;
            f_label_key = lhs_label },
        SpecTransformConstraint_Range
          { f_signal_sort_key = rhs_signal_sort_key ;
            f_signal_index = rhs_signal_index ;
            f_bits = rhs_bits ;
            f_label_key = rhs_label } ->
          Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
            (Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
                (Core_models.Cmp.impl__then_with #(Prims.unit -> Core_models.Cmp.t_Ordering)
                    (Core_models.Cmp.f_cmp #usize
                        #FStar.Tactics.Typeclasses.solve
                        lhs_signal_sort_key
                        rhs_signal_sort_key
                      <:
                      Core_models.Cmp.t_Ordering)
                    (fun temp_0_ ->
                        let _:Prims.unit = temp_0_ in
                        Core_models.Cmp.f_cmp #usize
                          #FStar.Tactics.Typeclasses.solve
                          lhs_signal_index
                          rhs_signal_index
                        <:
                        Core_models.Cmp.t_Ordering)
                  <:
                  Core_models.Cmp.t_Ordering)
                (fun temp_0_ ->
                    let _:Prims.unit = temp_0_ in
                    Core_models.Cmp.f_cmp #u32 #FStar.Tactics.Typeclasses.solve lhs_bits rhs_bits
                    <:
                    Core_models.Cmp.t_Ordering)
              <:
              Core_models.Cmp.t_Ordering)
            (fun temp_0_ ->
                let _:Prims.unit = temp_0_ in
                Core_models.Cmp.f_cmp #usize #FStar.Tactics.Typeclasses.solve lhs_label rhs_label
                <:
                Core_models.Cmp.t_Ordering)
          <:
          Core_models.Cmp.t_Ordering
        | _ -> Core_models.Cmp.Ordering_Equal <: Core_models.Cmp.t_Ordering)

let insert_signal_sorted (signal: t_SpecTransformSignal) (sorted: t_Slice t_SpecTransformSignal)
    : Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global =
  insert_signal_sorted_from signal
    sorted
    false
    (Alloc.Vec.impl__with_capacity #t_SpecTransformSignal
        ((Core_models.Slice.impl__len #t_SpecTransformSignal sorted <: usize) +! mk_usize 1 <: usize
        )
      <:
      Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)

let sort_constraints_by_key (constraints: t_Slice t_SpecTransformConstraint)
    : Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
  let sorted:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec #t_SpecTransformConstraint constraints
  in
  let sorted:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (Alloc.Slice.impl__sort_by #t_SpecTransformConstraint
          #(t_SpecTransformConstraint -> t_SpecTransformConstraint -> Core_models.Cmp.t_Ordering)
          (Alloc.Vec.impl_1__as_slice sorted <: t_Slice t_SpecTransformConstraint)
          constraint_order_cmp
        <:
        t_Slice t_SpecTransformConstraint)
  in
  sorted

let rec insert_constraint_sorted_from
      (constraint: t_SpecTransformConstraint)
      (sorted: t_Slice t_SpecTransformConstraint)
      (inserted: bool)
      (result: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformConstraint sorted
    <:
    Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
  with
  | Core_models.Option.Option_Some (item, remaining) ->
    let (result: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global), (inserted: bool) =
      if ~.inserted && constraint_order_lt constraint item
      then
        let result:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformConstraint
            #Alloc.Alloc.t_Global
            result
            (Core_models.Clone.f_clone #t_SpecTransformConstraint
                #FStar.Tactics.Typeclasses.solve
                constraint
              <:
              t_SpecTransformConstraint)
        in
        result, true <: (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & bool)
      else
        result, inserted <: (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & bool)
    in
    let result:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
      Alloc.Vec.impl_1__push #t_SpecTransformConstraint
        #Alloc.Alloc.t_Global
        result
        (Core_models.Clone.f_clone #t_SpecTransformConstraint #FStar.Tactics.Typeclasses.solve item
          <:
          t_SpecTransformConstraint)
    in
    insert_constraint_sorted_from constraint remaining inserted result
  | Core_models.Option.Option_None  ->
    let result:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
      if ~.inserted
      then
        let result:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformConstraint #Alloc.Alloc.t_Global result constraint
        in
        result
      else result
    in
    result

let collect_assignment_signal_marks
      (assignments: t_Slice t_SpecTransformAssignment)
      (signal_marks: t_Slice u8)
    : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
            t_SpecTransformAssignment)
          #FStar.Tactics.Typeclasses.solve
          assignments
        <:
        Core_models.Slice.Iter.t_Iter t_SpecTransformAssignment)
      signal_marks
      (fun signal_marks assignment ->
          let signal_marks:t_Slice u8 = signal_marks in
          let assignment:t_SpecTransformAssignment = assignment in
          let signal_marks:t_Slice u8 =
            mark_signal_index signal_marks assignment.f_target_signal_index
          in
          let signal_marks:t_Slice u8 = collect_expr_signals assignment.f_expr signal_marks in
          signal_marks)
  in
  signal_marks

let collect_constraint_signals (constraint: t_SpecTransformConstraint) (signal_marks: t_Slice u8)
    : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    match constraint <: t_SpecTransformConstraint with
    | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs } ->
      let signal_marks:t_Slice u8 = collect_expr_signals lhs signal_marks in
      let signal_marks:t_Slice u8 = collect_expr_signals rhs signal_marks in
      signal_marks
    | SpecTransformConstraint_Boolean { f_signal_index = signal_index }
    | SpecTransformConstraint_Range { f_signal_index = signal_index } ->
      let signal_marks:t_Slice u8 = mark_signal_index signal_marks signal_index in
      signal_marks
  in
  signal_marks

let rec all_const_exprs (values: t_Slice t_SpecTransformExpr) : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformExpr values
    <:
    Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
  with
  | Core_models.Option.Option_Some (value, remaining_values) ->
    (match value <: t_SpecTransformExpr with
      | SpecTransformExpr_Const {  } -> true
      | _ -> false) &&
    all_const_exprs remaining_values
  | Core_models.Option.Option_None  -> true

let rec append_transform_exprs
      (target: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
      (values: t_Slice t_SpecTransformExpr)
    : Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
  let target:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformExpr values
      <:
      Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
    with
    | Core_models.Option.Option_Some (value, remaining_values) ->
      let target:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
        Alloc.Vec.impl_1__push #t_SpecTransformExpr
          #Alloc.Alloc.t_Global
          target
          (Core_models.Clone.f_clone #t_SpecTransformExpr #FStar.Tactics.Typeclasses.solve value
            <:
            t_SpecTransformExpr)
      in
      let target:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
        append_transform_exprs target remaining_values
      in
      target
    | _ -> target
  in
  target

let constraint_is_tautology (constraint: t_SpecTransformConstraint) : bool =
  match constraint <: t_SpecTransformConstraint with
  | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs } -> transform_expr_eq lhs rhs
  | _ -> false

let transform_constraint_eq (lhs rhs: t_SpecTransformConstraint) : bool =
  match lhs, rhs <: (t_SpecTransformConstraint & t_SpecTransformConstraint) with
  | SpecTransformConstraint_Equal
    { f_lhs = lhs_expr ; f_rhs = lhs_rhs ; f_label_key = lhs_label_key },
  SpecTransformConstraint_Equal { f_lhs = rhs_expr ; f_rhs = rhs_rhs ; f_label_key = rhs_label_key } ->
    transform_expr_eq lhs_expr rhs_expr && transform_expr_eq lhs_rhs rhs_rhs &&
    lhs_label_key =. rhs_label_key
  | SpecTransformConstraint_Boolean
    { f_signal_index = lhs_signal ;
      f_signal_sort_key = lhs_signal_sort_key ;
      f_label_key = lhs_label_key },
  SpecTransformConstraint_Boolean
    { f_signal_index = rhs_signal ;
      f_signal_sort_key = rhs_signal_sort_key ;
      f_label_key = rhs_label_key } ->
    lhs_signal =. rhs_signal && lhs_signal_sort_key =. rhs_signal_sort_key &&
    lhs_label_key =. rhs_label_key
  | SpecTransformConstraint_Range
    { f_signal_index = lhs_signal ;
      f_signal_sort_key = lhs_signal_sort_key ;
      f_bits = lhs_bits ;
      f_label_key = lhs_label_key },
  SpecTransformConstraint_Range
    { f_signal_index = rhs_signal ;
      f_signal_sort_key = rhs_signal_sort_key ;
      f_bits = rhs_bits ;
      f_label_key = rhs_label_key } ->
    lhs_signal =. rhs_signal && lhs_signal_sort_key =. rhs_signal_sort_key && lhs_bits =. rhs_bits &&
    lhs_label_key =. rhs_label_key
  | _ -> false

let constraint_equals_ignoring_label (lhs rhs: t_SpecTransformConstraint) : bool =
  match lhs, rhs <: (t_SpecTransformConstraint & t_SpecTransformConstraint) with
  | SpecTransformConstraint_Equal { f_lhs = lhs_expr ; f_rhs = lhs_rhs },
  SpecTransformConstraint_Equal { f_lhs = rhs_expr ; f_rhs = rhs_rhs } ->
    transform_expr_eq lhs_expr rhs_expr && transform_expr_eq lhs_rhs rhs_rhs
  | SpecTransformConstraint_Boolean { f_signal_index = lhs_signal },
  SpecTransformConstraint_Boolean { f_signal_index = rhs_signal } ->
    lhs_signal =. rhs_signal
  | SpecTransformConstraint_Range { f_signal_index = lhs_signal ; f_bits = lhs_bits },
  SpecTransformConstraint_Range { f_signal_index = rhs_signal ; f_bits = rhs_bits } ->
    lhs_signal =. rhs_signal && lhs_bits =. rhs_bits
  | _ -> false

let rec filter_assignments_by_signal_indices_from
      (assignments: t_Slice t_SpecTransformAssignment)
      (kept_signal_marks: t_Slice u8)
      (filtered_assignments: Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformAssignment assignments
    <:
    Core_models.Option.t_Option (t_SpecTransformAssignment & t_Slice t_SpecTransformAssignment)
  with
  | Core_models.Option.Option_Some (assignment, remaining_assignments) ->
    let filtered_assignments:Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global =
      if signal_index_is_marked kept_signal_marks assignment.f_target_signal_index
      then
        let filtered_assignments:Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformAssignment
            #Alloc.Alloc.t_Global
            filtered_assignments
            (Core_models.Clone.f_clone #t_SpecTransformAssignment
                #FStar.Tactics.Typeclasses.solve
                assignment
              <:
              t_SpecTransformAssignment)
        in
        filtered_assignments
      else filtered_assignments
    in
    filter_assignments_by_signal_indices_from remaining_assignments
      kept_signal_marks
      filtered_assignments
  | Core_models.Option.Option_None  -> filtered_assignments

let transform_check_constraint
      (constraint: t_SpecTransformConstraint)
      (constraint_index: usize)
      (program: t_SpecTransformProgram)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
    : Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  match constraint <: t_SpecTransformConstraint with
  | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs } ->
    (match
        transform_eval_expr lhs witness program.f_field
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            transform_eval_expr rhs witness program.f_field
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            if spec_values_equal lhs_value rhs_value program.f_field
            then
              Core_models.Result.Result_Ok (() <: Prims.unit)
              <:
              Core_models.Result.t_Result Prims.unit
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
            else
              Core_models.Result.Result_Err
              (Zkf_core.Proof_kernel_spec.SpecKernelCheckError_EqualViolation
                ({
                    Zkf_core.Proof_kernel_spec.f_constraint_index = constraint_index;
                    Zkf_core.Proof_kernel_spec.f_lhs = lhs_value;
                    Zkf_core.Proof_kernel_spec.f_rhs = rhs_value
                  })
                <:
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
              <:
              Core_models.Result.t_Result Prims.unit
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
        )
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | SpecTransformConstraint_Boolean { f_signal_index = signal_index } ->
    (match
        transform_signal_value witness signal_index program.f_field
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok value ->
        if spec_value_is_boolean value program.f_field
        then
          Core_models.Result.Result_Ok (() <: Prims.unit)
          <:
          Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
        else
          Core_models.Result.Result_Err
          (Zkf_core.Proof_kernel_spec.SpecKernelCheckError_BooleanViolation
            ({
                Zkf_core.Proof_kernel_spec.f_constraint_index = constraint_index;
                Zkf_core.Proof_kernel_spec.f_signal_index = signal_index;
                Zkf_core.Proof_kernel_spec.f_value = value
              })
            <:
            Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
          <:
          Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | SpecTransformConstraint_Range { f_signal_index = signal_index ; f_bits = bits } ->
    match
      transform_signal_value witness signal_index program.f_field
      <:
      Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
        Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
    with
    | Core_models.Result.Result_Ok value ->
      if spec_value_fits_bits value bits program.f_field
      then
        Core_models.Result.Result_Ok (() <: Prims.unit)
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      else
        Core_models.Result.Result_Err
        (Zkf_core.Proof_kernel_spec.SpecKernelCheckError_RangeViolation
          ({
              Zkf_core.Proof_kernel_spec.f_constraint_index = constraint_index;
              Zkf_core.Proof_kernel_spec.f_signal_index = signal_index;
              Zkf_core.Proof_kernel_spec.f_bits = bits;
              Zkf_core.Proof_kernel_spec.f_value = value
            })
          <:
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
    | Core_models.Result.Result_Err error ->
      Core_models.Result.Result_Err error
      <:
      Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError

let transform_program_to_kernel (program: t_SpecTransformProgram)
    : Zkf_core.Proof_kernel_spec.t_SpecKernelProgram =
  let constraints:Alloc.Vec.t_Vec Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
    Alloc.Alloc.t_Global =
    transform_constraints_to_kernel_from (Alloc.Vec.impl_1__as_slice program.f_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      (mk_usize 0)
      (Alloc.Vec.impl__new #Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint ()
        <:
        Alloc.Vec.t_Vec Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint Alloc.Alloc.t_Global)
      program.f_field
  in
  {
    Zkf_core.Proof_kernel_spec.f_field = program.f_field;
    Zkf_core.Proof_kernel_spec.f_constraints = constraints;
    Zkf_core.Proof_kernel_spec.f_lookup_tables
    =
    Alloc.Vec.impl__new #Zkf_core.Proof_kernel_spec.t_SpecKernelLookupTable ()
  }
  <:
  Zkf_core.Proof_kernel_spec.t_SpecKernelProgram

let insert_constraint_sorted
      (constraint: t_SpecTransformConstraint)
      (sorted: t_Slice t_SpecTransformConstraint)
    : Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
  insert_constraint_sorted_from constraint
    sorted
    false
    (Alloc.Vec.impl__with_capacity #t_SpecTransformConstraint
        ((Core_models.Slice.impl__len #t_SpecTransformConstraint sorted <: usize) +! mk_usize 1
          <:
          usize)
      <:
      Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let collect_constraint_signal_marks
      (constraints: t_Slice t_SpecTransformConstraint)
      (signal_marks: t_Slice u8)
    : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
            t_SpecTransformConstraint)
          #FStar.Tactics.Typeclasses.solve
          constraints
        <:
        Core_models.Slice.Iter.t_Iter t_SpecTransformConstraint)
      signal_marks
      (fun signal_marks constraint ->
          let signal_marks:t_Slice u8 = signal_marks in
          let constraint:t_SpecTransformConstraint = constraint in
          collect_constraint_signals constraint signal_marks <: t_Slice u8)
  in
  signal_marks

let referenced_signal_marks
      (program: t_SpecTransformProgram)
      (constraints: t_Slice t_SpecTransformConstraint)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #u8
      (mk_u8 0)
      (Alloc.Vec.impl_1__len #t_SpecTransformSignal #Alloc.Alloc.t_Global program.f_signals <: usize
      )
  in
  let signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (collect_constraint_signal_marks constraints
          (Alloc.Vec.impl_1__as_slice signal_marks <: t_Slice u8)
        <:
        t_Slice u8)
  in
  let signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (collect_assignment_signal_marks (Alloc.Vec.impl_1__as_slice program
                .f_assignments
            <:
            t_Slice t_SpecTransformAssignment)
          (Alloc.Vec.impl_1__as_slice signal_marks <: t_Slice u8)
        <:
        t_Slice u8)
  in
  let signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (collect_hint_signal_marks (Alloc.Vec.impl_1__as_slice program.f_hints
            <:
            t_Slice t_SpecTransformHint)
          (Alloc.Vec.impl_1__as_slice signal_marks <: t_Slice u8)
        <:
        t_Slice u8)
  in
  signal_marks

let filter_live_signals
      (program: t_SpecTransformProgram)
      (constraints: t_Slice t_SpecTransformConstraint)
      (report: t_SpecOptimizeReport)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
  let referenced_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    referenced_signal_marks program constraints
  in
  let
  (tmp0: t_SpecOptimizeReport), (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    filter_live_signals__filter_live_signals_from (Alloc.Vec.impl_1__as_slice program.f_signals
        <:
        t_Slice t_SpecTransformSignal)
      (Alloc.Vec.impl_1__as_slice referenced_marks <: t_Slice u8)
      report
      (Alloc.Vec.impl__new #t_SpecTransformSignal ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let hax_temp_output:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global = out in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)

let normalize_transform_constraint
      (constraint: t_SpecTransformConstraint)
      (report: t_SpecNormalizationReport)
    : (t_SpecNormalizationReport & t_SpecTransformConstraint) =
  let (report: t_SpecNormalizationReport), (hax_temp_output: t_SpecTransformConstraint) =
    match constraint <: t_SpecTransformConstraint with
    | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs ; f_label_key = label_key } ->
      let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
        normalize_transform_expr lhs report
      in
      let report:t_SpecNormalizationReport = tmp0 in
      let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
        normalize_transform_expr rhs report
      in
      let report:t_SpecNormalizationReport = tmp0 in
      report,
      (SpecTransformConstraint_Equal ({ f_lhs = out; f_rhs = out; f_label_key = label_key })
        <:
        t_SpecTransformConstraint)
      <:
      (t_SpecNormalizationReport & t_SpecTransformConstraint)
    | _ ->
      report,
      Core_models.Clone.f_clone #t_SpecTransformConstraint
        #FStar.Tactics.Typeclasses.solve
        constraint
      <:
      (t_SpecNormalizationReport & t_SpecTransformConstraint)
  in
  report, hax_temp_output <: (t_SpecNormalizationReport & t_SpecTransformConstraint)

let normalize_expr_output (expr: t_SpecTransformExpr) : t_SpecTransformExpr =
  let report:t_SpecNormalizationReport =
    Core_models.Default.f_default #t_SpecNormalizationReport #FStar.Tactics.Typeclasses.solve ()
  in
  let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
    normalize_transform_expr expr report
  in
  let report:t_SpecNormalizationReport = tmp0 in
  out

let fold_transform_constraint
      (constraint: t_SpecTransformConstraint)
      (field: Zkf_core.Field.t_FieldId)
      (folded_nodes: usize)
    : (usize & t_SpecTransformConstraint) =
  let (folded_nodes: usize), (hax_temp_output: t_SpecTransformConstraint) =
    match constraint <: t_SpecTransformConstraint with
    | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs ; f_label_key = label_key } ->
      let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr lhs field folded_nodes in
      let folded_nodes:usize = tmp0 in
      let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr rhs field folded_nodes in
      let folded_nodes:usize = tmp0 in
      folded_nodes,
      (SpecTransformConstraint_Equal ({ f_lhs = out; f_rhs = out; f_label_key = label_key })
        <:
        t_SpecTransformConstraint)
      <:
      (usize & t_SpecTransformConstraint)
    | _ ->
      folded_nodes,
      Core_models.Clone.f_clone #t_SpecTransformConstraint
        #FStar.Tactics.Typeclasses.solve
        constraint
      <:
      (usize & t_SpecTransformConstraint)
  in
  folded_nodes, hax_temp_output <: (usize & t_SpecTransformConstraint)

let fold_expr_output (expr: t_SpecTransformExpr) (field: Zkf_core.Field.t_FieldId)
    : t_SpecTransformExpr =
  let folded_nodes:usize = mk_usize 0 in
  let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr expr field folded_nodes in
  let folded_nodes:usize = tmp0 in
  out

let rec contains_equivalent_ir_constraint
      (constraints: t_Slice t_SpecTransformConstraint)
      (target: t_SpecTransformConstraint)
    : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
    <:
    Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
  with
  | Core_models.Option.Option_Some (current, remaining) ->
    constraint_equals_ignoring_label current target ||
    contains_equivalent_ir_constraint remaining target
  | Core_models.Option.Option_None  -> false

let rec contains_exact_constraint
      (constraints: t_Slice t_SpecTransformConstraint)
      (target: t_SpecTransformConstraint)
    : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
    <:
    Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
  with
  | Core_models.Option.Option_Some (current, remaining) ->
    transform_constraint_eq current target || contains_exact_constraint remaining target
  | Core_models.Option.Option_None  -> false

let rec transform_check_constraints_from
      (constraints: t_Slice t_SpecTransformConstraint)
      (constraint_index: usize)
      (program: t_SpecTransformProgram)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
    : Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
    <:
    Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
  with
  | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
    (match
        transform_check_constraint constraint constraint_index program witness
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok () ->
        transform_check_constraints_from remaining_constraints
          (constraint_index +! mk_usize 1 <: usize)
          program
          witness
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | Core_models.Option.Option_None  ->
    Core_models.Result.Result_Ok (() <: Prims.unit)
    <:
    Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError

let normalize_constraint_output (constraint: t_SpecTransformConstraint) : t_SpecTransformConstraint =
  let report:t_SpecNormalizationReport =
    Core_models.Default.f_default #t_SpecNormalizationReport #FStar.Tactics.Typeclasses.solve ()
  in
  let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformConstraint) =
    normalize_transform_constraint constraint report
  in
  let report:t_SpecNormalizationReport = tmp0 in
  out

let fold_constraint_output (constraint: t_SpecTransformConstraint) (field: Zkf_core.Field.t_FieldId)
    : t_SpecTransformConstraint =
  let folded_nodes:usize = mk_usize 0 in
  let (tmp0: usize), (out: t_SpecTransformConstraint) =
    fold_transform_constraint constraint field folded_nodes
  in
  let folded_nodes:usize = tmp0 in
  out

let transform_check_program
      (program: t_SpecTransformProgram)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
    : Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  transform_check_constraints_from (Alloc.Vec.impl_1__as_slice program.f_constraints
      <:
      t_Slice t_SpecTransformConstraint)
    (mk_usize 0)
    program
    witness

let rec normalize_constraints_from
      (constraints: t_Slice t_SpecTransformConstraint)
      (report: t_SpecNormalizationReport)
      (normalized_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    : (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
  let
  ((normalized_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
    (report: t_SpecNormalizationReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
      <:
      Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
    with
    | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
      let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformConstraint) =
        normalize_transform_constraint constraint report
      in
      let report:t_SpecNormalizationReport = tmp0 in
      let normalized_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
        Alloc.Vec.impl_1__push #t_SpecTransformConstraint
          #Alloc.Alloc.t_Global
          normalized_constraints
          out
      in
      let
      (tmp0: t_SpecNormalizationReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
        normalize_constraints_from remaining_constraints report normalized_constraints
      in
      let report:t_SpecNormalizationReport = tmp0 in
      (normalized_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecNormalizationReport)
      ),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (normalized_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecNormalizationReport)
      ),
      normalized_constraints
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let rec dedup_constraints_ir
      (constraints: t_Slice t_SpecTransformConstraint)
      (report: t_SpecOptimizeReport)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
  let
  (report: t_SpecOptimizeReport),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
      <:
      Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
    with
    | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
      let
      (tmp0: t_SpecOptimizeReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
        dedup_constraints_ir remaining_constraints report
      in
      let report:t_SpecOptimizeReport = tmp0 in
      let deduped:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
      let
      (deduped: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
      (report: t_SpecOptimizeReport) =
        if
          contains_equivalent_ir_constraint (Alloc.Vec.impl_1__as_slice deduped
              <:
              t_Slice t_SpecTransformConstraint)
            constraint
        then
          let report:t_SpecOptimizeReport =
            {
              report with
              f_deduplicated_constraints = report.f_deduplicated_constraints +! mk_usize 1
            }
            <:
            t_SpecOptimizeReport
          in
          deduped, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
        else
          let deduped:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
            insert_constraint_sorted (Core_models.Clone.f_clone #t_SpecTransformConstraint
                  #FStar.Tactics.Typeclasses.solve
                  constraint
                <:
                t_SpecTransformConstraint)
              (Alloc.Vec.impl_1__as_slice deduped <: t_Slice t_SpecTransformConstraint)
          in
          deduped, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
      in
      report, deduped
      <:
      (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      report, Alloc.Vec.impl__new #t_SpecTransformConstraint ()
      <:
      (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let rec dedup_constraints_zir
      (constraints: t_Slice t_SpecTransformConstraint)
      (report: t_SpecOptimizeReport)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
  let
  (report: t_SpecOptimizeReport),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
      <:
      Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
    with
    | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
      let
      (tmp0: t_SpecOptimizeReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
        dedup_constraints_zir remaining_constraints report
      in
      let report:t_SpecOptimizeReport = tmp0 in
      let deduped:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
      let
      (deduped: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
      (report: t_SpecOptimizeReport) =
        if
          contains_exact_constraint (Alloc.Vec.impl_1__as_slice deduped
              <:
              t_Slice t_SpecTransformConstraint)
            constraint
        then
          let report:t_SpecOptimizeReport =
            {
              report with
              f_deduplicated_constraints = report.f_deduplicated_constraints +! mk_usize 1
            }
            <:
            t_SpecOptimizeReport
          in
          deduped, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
        else
          let deduped:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
            insert_constraint_sorted (Core_models.Clone.f_clone #t_SpecTransformConstraint
                  #FStar.Tactics.Typeclasses.solve
                  constraint
                <:
                t_SpecTransformConstraint)
              (Alloc.Vec.impl_1__as_slice deduped <: t_Slice t_SpecTransformConstraint)
          in
          deduped, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
      in
      report, deduped
      <:
      (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      report, Alloc.Vec.impl__new #t_SpecTransformConstraint ()
      <:
      (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let rec fold_constraints_for_ir_from
      (constraints: t_Slice t_SpecTransformConstraint)
      (field: Zkf_core.Field.t_FieldId)
      (report: t_SpecOptimizeReport)
      (folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
  let
  ((folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
    (report: t_SpecOptimizeReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
      <:
      Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
    with
    | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
      let (tmp0: usize), (out: t_SpecTransformConstraint) =
        fold_transform_constraint constraint field report.f_folded_expr_nodes
      in
      let report:t_SpecOptimizeReport =
        { report with f_folded_expr_nodes = tmp0 } <: t_SpecOptimizeReport
      in
      let folded:t_SpecTransformConstraint = out in
      let
      (folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
      (report: t_SpecOptimizeReport) =
        if constraint_is_tautology folded
        then
          let report:t_SpecOptimizeReport =
            {
              report with
              f_removed_tautology_constraints = report.f_removed_tautology_constraints +! mk_usize 1
            }
            <:
            t_SpecOptimizeReport
          in
          folded_constraints, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
        else
          let folded_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_SpecTransformConstraint
              #Alloc.Alloc.t_Global
              folded_constraints
              folded
          in
          folded_constraints, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
      in
      let
      (tmp0: t_SpecOptimizeReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
        fold_constraints_for_ir_from remaining_constraints field report folded_constraints
      in
      let report:t_SpecOptimizeReport = tmp0 in
      (folded_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (folded_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      folded_constraints
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let rec fold_constraints_for_zir_from
      (constraints: t_Slice t_SpecTransformConstraint)
      (field: Zkf_core.Field.t_FieldId)
      (report: t_SpecOptimizeReport)
      (folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    : (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
  let
  ((folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
    (report: t_SpecOptimizeReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
      <:
      Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
    with
    | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
      let (tmp0: usize), (out: t_SpecTransformConstraint) =
        fold_transform_constraint constraint field report.f_folded_expr_nodes
      in
      let report:t_SpecOptimizeReport =
        { report with f_folded_expr_nodes = tmp0 } <: t_SpecOptimizeReport
      in
      let folded:t_SpecTransformConstraint = out in
      let
      (folded_constraints: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global),
      (report: t_SpecOptimizeReport) =
        if constraint_is_tautology folded
        then
          let report:t_SpecOptimizeReport =
            {
              report with
              f_removed_tautology_constraints = report.f_removed_tautology_constraints +! mk_usize 1
            }
            <:
            t_SpecOptimizeReport
          in
          folded_constraints, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
        else
          let folded_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_SpecTransformConstraint
              #Alloc.Alloc.t_Global
              folded_constraints
              folded
          in
          folded_constraints, report
          <:
          (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)
      in
      let
      (tmp0: t_SpecOptimizeReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
        fold_constraints_for_zir_from remaining_constraints field report folded_constraints
      in
      let report:t_SpecOptimizeReport = tmp0 in
      (folded_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (folded_constraints, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport)),
      folded_constraints
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global & t_SpecOptimizeReport) &
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecOptimizeReport & Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)

let normalize_supported_program (program: t_SpecTransformProgram) : t_SpecNormalizationResult =
  let report:t_SpecNormalizationReport =
    Core_models.Default.f_default #t_SpecNormalizationReport #FStar.Tactics.Typeclasses.solve ()
  in
  let
  (tmp0: t_SpecNormalizationReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    normalize_constraints_from (Alloc.Vec.impl_1__as_slice program.f_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      report
      (Alloc.Vec.impl__with_capacity #t_SpecTransformConstraint
          (Alloc.Vec.impl_1__len #t_SpecTransformConstraint
              #Alloc.Alloc.t_Global
              program.f_constraints
            <:
            usize)
        <:
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  let report:t_SpecNormalizationReport = tmp0 in
  let constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
  let referenced_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    referenced_signal_marks program
      (Alloc.Vec.impl_1__as_slice constraints <: t_Slice t_SpecTransformConstraint)
  in
  let
  (tmp0: t_SpecNormalizationReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    filter_live_signals_for_normalization_from (Alloc.Vec.impl_1__as_slice program.f_signals
        <:
        t_Slice t_SpecTransformSignal)
      (Alloc.Vec.impl_1__as_slice referenced_marks <: t_Slice u8)
      report
      (Alloc.Vec.impl__new #t_SpecTransformSignal ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global)
  in
  let report:t_SpecNormalizationReport = tmp0 in
  let live_signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global = out in
  {
    f_program
    =
    {
      f_field = program.f_field;
      f_signals
      =
      sort_signals_by_key (Alloc.Vec.impl_1__as_slice live_signals <: t_Slice t_SpecTransformSignal);
      f_constraints
      =
      sort_constraints_by_key (Alloc.Vec.impl_1__as_slice constraints
          <:
          t_Slice t_SpecTransformConstraint);
      f_assignments
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        program.f_assignments;
      f_hints
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        program.f_hints
    }
    <:
    t_SpecTransformProgram;
    f_report = report
  }
  <:
  t_SpecNormalizationResult

let normalize_program_output (program: t_SpecTransformProgram) : t_SpecTransformProgram =
  (normalize_supported_program program).f_program

let optimize_supported_ir_program (program: t_SpecTransformProgram) : t_SpecOptimizeResult =
  let report:t_SpecOptimizeReport =
    Core_models.Default.f_default #t_SpecOptimizeReport #FStar.Tactics.Typeclasses.solve ()
  in
  let
  (tmp0: t_SpecOptimizeReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    fold_constraints_for_ir_from (Alloc.Vec.impl_1__as_slice program.f_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      program.f_field
      report
      (Alloc.Vec.impl__new #t_SpecTransformConstraint ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let folded_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
  let
  (tmp0: t_SpecOptimizeReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    dedup_constraints_ir (Alloc.Vec.impl_1__as_slice folded_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      report
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
  let
  (tmp0: t_SpecOptimizeReport), (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    filter_live_signals program
      (Alloc.Vec.impl_1__as_slice constraints <: t_Slice t_SpecTransformConstraint)
      report
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global = out in
  let kept_signal_marks:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    collect_signal_marks_from_signals (Alloc.Vec.impl_1__as_slice signals
        <:
        t_Slice t_SpecTransformSignal)
      (Alloc.Vec.impl_1__len #t_SpecTransformSignal #Alloc.Alloc.t_Global program.f_signals <: usize
      )
  in
  let assignments:Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global =
    filter_assignments_by_signal_indices_from (Alloc.Vec.impl_1__as_slice program.f_assignments
        <:
        t_Slice t_SpecTransformAssignment)
      (Alloc.Vec.impl_1__as_slice kept_signal_marks <: t_Slice u8)
      (Alloc.Vec.impl__new #t_SpecTransformAssignment ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global)
  in
  let hints:Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global =
    filter_hints_by_signal_indices_from (Alloc.Vec.impl_1__as_slice program.f_hints
        <:
        t_Slice t_SpecTransformHint)
      (Alloc.Vec.impl_1__as_slice kept_signal_marks <: t_Slice u8)
      (Alloc.Vec.impl__new #t_SpecTransformHint ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global)
  in
  {
    f_program
    =
    {
      f_field = program.f_field;
      f_signals = signals;
      f_constraints = constraints;
      f_assignments = assignments;
      f_hints = hints
    }
    <:
    t_SpecTransformProgram;
    f_report = report
  }
  <:
  t_SpecOptimizeResult

let optimize_ir_program_output (program: t_SpecTransformProgram) : t_SpecTransformProgram =
  (optimize_supported_ir_program program).f_program

let optimize_supported_zir_program (program: t_SpecTransformProgram) : t_SpecOptimizeResult =
  let report:t_SpecOptimizeReport =
    Core_models.Default.f_default #t_SpecOptimizeReport #FStar.Tactics.Typeclasses.solve ()
  in
  let
  (tmp0: t_SpecOptimizeReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    fold_constraints_for_zir_from (Alloc.Vec.impl_1__as_slice program.f_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      program.f_field
      report
      (Alloc.Vec.impl__new #t_SpecTransformConstraint ()
        <:
        Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global)
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let folded_constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
  let
  (tmp0: t_SpecOptimizeReport),
  (out: Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global) =
    dedup_constraints_zir (Alloc.Vec.impl_1__as_slice folded_constraints
        <:
        t_Slice t_SpecTransformConstraint)
      report
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let constraints:Alloc.Vec.t_Vec t_SpecTransformConstraint Alloc.Alloc.t_Global = out in
  let
  (tmp0: t_SpecOptimizeReport), (out: Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global) =
    filter_live_signals program
      (Alloc.Vec.impl_1__as_slice constraints <: t_Slice t_SpecTransformConstraint)
      report
  in
  let report:t_SpecOptimizeReport = tmp0 in
  let signals:Alloc.Vec.t_Vec t_SpecTransformSignal Alloc.Alloc.t_Global = out in
  {
    f_program
    =
    {
      f_field = program.f_field;
      f_signals = signals;
      f_constraints = constraints;
      f_assignments
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SpecTransformAssignment Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        program.f_assignments;
      f_hints
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SpecTransformHint Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        program.f_hints
    }
    <:
    t_SpecTransformProgram;
    f_report = report
  }
  <:
  t_SpecOptimizeResult

let optimize_zir_program_output (program: t_SpecTransformProgram) : t_SpecTransformProgram =
  (optimize_supported_zir_program program).f_program

let rec collect_expr_signals (expr: t_SpecTransformExpr) (signal_marks: t_Slice u8) : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    match expr <: t_SpecTransformExpr with
    | SpecTransformExpr_Const {  } -> signal_marks
    | SpecTransformExpr_Signal { f_signal_index = signal_index } ->
      mark_signal_index signal_marks signal_index
    | SpecTransformExpr_Add values ->
      collect_expr_signal_slice (Alloc.Vec.impl_1__as_slice values <: t_Slice t_SpecTransformExpr)
        signal_marks
    | SpecTransformExpr_Sub lhs rhs
    | SpecTransformExpr_Mul lhs rhs
    | SpecTransformExpr_Div lhs rhs ->
      let signal_marks:t_Slice u8 = collect_expr_signals lhs signal_marks in
      let signal_marks:t_Slice u8 = collect_expr_signals rhs signal_marks in
      signal_marks
  in
  signal_marks

and collect_expr_signal_slice (values: t_Slice t_SpecTransformExpr) (signal_marks: t_Slice u8)
    : t_Slice u8 =
  let signal_marks:t_Slice u8 =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformExpr values
      <:
      Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
    with
    | Core_models.Option.Option_Some (value, remaining) ->
      let signal_marks:t_Slice u8 = collect_expr_signals value signal_marks in
      let signal_marks:t_Slice u8 = collect_expr_signal_slice remaining signal_marks in
      signal_marks
    | _ -> signal_marks
  in
  signal_marks

let rec normalize_transform_expr (expr: t_SpecTransformExpr) (report: t_SpecNormalizationReport)
    : (t_SpecNormalizationReport & t_SpecTransformExpr) =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Const {  }
  | SpecTransformExpr_Signal {  } ->
    report, Core_models.Clone.f_clone #t_SpecTransformExpr #FStar.Tactics.Typeclasses.solve expr
    <:
    (t_SpecNormalizationReport & t_SpecTransformExpr)
  | SpecTransformExpr_Add values ->
    let
    (tmp0: t_SpecNormalizationReport),
    (out: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) =
      normalize_non_zero_values_from (Alloc.Vec.impl_1__as_slice values
          <:
          t_Slice t_SpecTransformExpr)
        report
        (Alloc.Vec.impl__new #t_SpecTransformExpr ()
          <:
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let non_zero:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global = out in
    (match Alloc.Vec.impl_1__len #t_SpecTransformExpr #Alloc.Alloc.t_Global non_zero <: usize with
      | Rust_primitives.Integers.MkInt 0 ->
        let report:t_SpecNormalizationReport =
          { report with f_constant_folds = report.f_constant_folds +! mk_u32 1 }
          <:
          t_SpecNormalizationReport
        in
        report, zero_spec_expr () <: (t_SpecNormalizationReport & t_SpecTransformExpr)
      | Rust_primitives.Integers.MkInt 1 ->
        let
        (tmp0: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global), (out: t_SpecTransformExpr)
        =
          Alloc.Vec.impl_1__remove #t_SpecTransformExpr #Alloc.Alloc.t_Global non_zero (mk_usize 0)
        in
        let non_zero:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global = tmp0 in
        report, out <: (t_SpecNormalizationReport & t_SpecTransformExpr)
      | _ ->
        let report:t_SpecNormalizationReport =
          if all_const_exprs (Alloc.Vec.impl_1__as_slice non_zero <: t_Slice t_SpecTransformExpr)
          then
            let report:t_SpecNormalizationReport =
              { report with f_constant_folds = report.f_constant_folds +! mk_u32 1 }
              <:
              t_SpecNormalizationReport
            in
            report
          else report
        in
        report, (SpecTransformExpr_Add non_zero <: t_SpecTransformExpr)
        <:
        (t_SpecNormalizationReport & t_SpecTransformExpr))
  | SpecTransformExpr_Mul lhs rhs ->
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr lhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr rhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    if
      match
        (match lhs <: t_SpecTransformExpr with
          | SpecTransformExpr_Const { f_value = value } ->
            (match spec_value_is_one_raw value <: bool with
              | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
          | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
        <:
        Core_models.Option.t_Option bool
      with
      | Core_models.Option.Option_Some x -> x
      | Core_models.Option.Option_None  -> false
    then
      let report:t_SpecNormalizationReport =
        { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
        <:
        t_SpecNormalizationReport
      in
      report, rhs <: (t_SpecNormalizationReport & t_SpecTransformExpr)
    else
      if
        match
          (match rhs <: t_SpecTransformExpr with
            | SpecTransformExpr_Const { f_value = value } ->
              (match spec_value_is_one_raw value <: bool with
                | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
            | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
          <:
          Core_models.Option.t_Option bool
        with
        | Core_models.Option.Option_Some x -> x
        | Core_models.Option.Option_None  -> false
      then
        let report:t_SpecNormalizationReport =
          { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
          <:
          t_SpecNormalizationReport
        in
        report, lhs <: (t_SpecNormalizationReport & t_SpecTransformExpr)
      else
        if
          match
            (match lhs <: t_SpecTransformExpr with
              | SpecTransformExpr_Const { f_value = value } ->
                (match spec_value_is_zero_raw value <: bool with
                  | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                  | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
            <:
            Core_models.Option.t_Option bool
          with
          | Core_models.Option.Option_Some x -> x
          | Core_models.Option.Option_None  -> false
        then
          let report:t_SpecNormalizationReport =
            { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
            <:
            t_SpecNormalizationReport
          in
          report, zero_spec_expr () <: (t_SpecNormalizationReport & t_SpecTransformExpr)
        else
          if
            match
              (match rhs <: t_SpecTransformExpr with
                | SpecTransformExpr_Const { f_value = value } ->
                  (match spec_value_is_zero_raw value <: bool with
                    | true ->
                      Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                    | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
                | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
              <:
              Core_models.Option.t_Option bool
            with
            | Core_models.Option.Option_Some x -> x
            | Core_models.Option.Option_None  -> false
          then
            let report:t_SpecNormalizationReport =
              { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
              <:
              t_SpecNormalizationReport
            in
            report, zero_spec_expr () <: (t_SpecNormalizationReport & t_SpecTransformExpr)
          else
            report, (SpecTransformExpr_Mul lhs rhs <: t_SpecTransformExpr)
            <:
            (t_SpecNormalizationReport & t_SpecTransformExpr)
  | SpecTransformExpr_Sub lhs rhs ->
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr lhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr rhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    if
      match
        (match rhs <: t_SpecTransformExpr with
          | SpecTransformExpr_Const { f_value = value } ->
            (match spec_value_is_zero_raw value <: bool with
              | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
          | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
        <:
        Core_models.Option.t_Option bool
      with
      | Core_models.Option.Option_Some x -> x
      | Core_models.Option.Option_None  -> false
    then
      let report:t_SpecNormalizationReport =
        { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
        <:
        t_SpecNormalizationReport
      in
      report, lhs <: (t_SpecNormalizationReport & t_SpecTransformExpr)
    else
      report, (SpecTransformExpr_Sub lhs rhs <: t_SpecTransformExpr)
      <:
      (t_SpecNormalizationReport & t_SpecTransformExpr)
  | SpecTransformExpr_Div lhs rhs ->
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr lhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
      normalize_transform_expr rhs report
    in
    let report:t_SpecNormalizationReport = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    if
      match
        (match rhs <: t_SpecTransformExpr with
          | SpecTransformExpr_Const { f_value = value } ->
            (match spec_value_is_one_raw value <: bool with
              | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
          | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
        <:
        Core_models.Option.t_Option bool
      with
      | Core_models.Option.Option_Some x -> x
      | Core_models.Option.Option_None  -> false
    then
      let report:t_SpecNormalizationReport =
        { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
        <:
        t_SpecNormalizationReport
      in
      report, lhs <: (t_SpecNormalizationReport & t_SpecTransformExpr)
    else
      report, (SpecTransformExpr_Div lhs rhs <: t_SpecTransformExpr)
      <:
      (t_SpecNormalizationReport & t_SpecTransformExpr)

and normalize_non_zero_values_from
      (values: t_Slice t_SpecTransformExpr)
      (report: t_SpecNormalizationReport)
      (non_zero: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
    : (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) =
  let
  ((non_zero: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global),
    (report: t_SpecNormalizationReport)),
  (hax_temp_output: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformExpr values
      <:
      Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
    with
    | Core_models.Option.Option_Some (value, remaining_values) ->
      let (tmp0: t_SpecNormalizationReport), (out: t_SpecTransformExpr) =
        normalize_transform_expr value report
      in
      let report:t_SpecNormalizationReport = tmp0 in
      let normalized:t_SpecTransformExpr = out in
      let (report: t_SpecNormalizationReport), (hoist38: Core_models.Option.t_Option Prims.unit) =
        match normalized <: t_SpecTransformExpr with
        | SpecTransformExpr_Const { f_value = value } ->
          (match spec_value_is_zero_raw value <: bool with
            | true ->
              let report:t_SpecNormalizationReport =
                { report with f_algebraic_rewrites = report.f_algebraic_rewrites +! mk_u32 1 }
                <:
                t_SpecNormalizationReport
              in
              report, (Core_models.Option.Option_Some () <: Core_models.Option.t_Option Prims.unit)
              <:
              (t_SpecNormalizationReport & Core_models.Option.t_Option Prims.unit)
            | _ ->
              report, (Core_models.Option.Option_None <: Core_models.Option.t_Option Prims.unit)
              <:
              (t_SpecNormalizationReport & Core_models.Option.t_Option Prims.unit))
        | _ ->
          report, (Core_models.Option.Option_None <: Core_models.Option.t_Option Prims.unit)
          <:
          (t_SpecNormalizationReport & Core_models.Option.t_Option Prims.unit)
      in
      let non_zero:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
        match hoist38 <: Core_models.Option.t_Option Prims.unit with
        | Core_models.Option.Option_Some x -> non_zero
        | Core_models.Option.Option_None  ->
          Alloc.Vec.impl_1__push #t_SpecTransformExpr #Alloc.Alloc.t_Global non_zero normalized
      in
      let
      (tmp0: t_SpecNormalizationReport),
      (out: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) =
        normalize_non_zero_values_from remaining_values report non_zero
      in
      let report:t_SpecNormalizationReport = tmp0 in
      (non_zero, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global & t_SpecNormalizationReport)),
      out
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
    | Core_models.Option.Option_None  ->
      (non_zero, report
        <:
        (Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global & t_SpecNormalizationReport)),
      non_zero
      <:
      ((Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global & t_SpecNormalizationReport) &
        Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
  in
  report, hax_temp_output
  <:
  (t_SpecNormalizationReport & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)

let rec fold_transform_expr
      (expr: t_SpecTransformExpr)
      (field: Zkf_core.Field.t_FieldId)
      (folded_nodes: usize)
    : (usize & t_SpecTransformExpr) =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Const {  }
  | SpecTransformExpr_Signal {  } ->
    folded_nodes,
    Core_models.Clone.f_clone #t_SpecTransformExpr #FStar.Tactics.Typeclasses.solve expr
    <:
    (usize & t_SpecTransformExpr)
  | SpecTransformExpr_Add values ->
    let
    (tmp0: usize),
    (out:
      (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
        Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)) =
      fold_add_terms_from (Alloc.Vec.impl_1__as_slice values <: t_Slice t_SpecTransformExpr)
        field
        folded_nodes
        (zero_spec_value () <: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
        false
        (Alloc.Vec.impl__new #t_SpecTransformExpr ()
          <:
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
    in
    let folded_nodes:usize = tmp0 in
    let
    (const_acc: Zkf_core.Proof_kernel_spec.t_SpecFieldValue),
    (saw_const: bool),
    (terms: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) =
      out
    in
    let terms:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
      if saw_const && ~.(spec_value_is_zero_raw const_acc <: bool)
      then
        let terms:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecTransformExpr
            #Alloc.Alloc.t_Global
            terms
            (SpecTransformExpr_Const ({ f_value = const_acc; f_sort_key = mk_usize 0 })
              <:
              t_SpecTransformExpr)
        in
        terms
      else terms
    in
    (match Alloc.Vec.impl_1__len #t_SpecTransformExpr #Alloc.Alloc.t_Global terms <: usize with
      | Rust_primitives.Integers.MkInt 0 ->
        folded_nodes, zero_spec_expr () <: (usize & t_SpecTransformExpr)
      | Rust_primitives.Integers.MkInt 1 ->
        let
        (tmp0: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global), (out: t_SpecTransformExpr)
        =
          Alloc.Vec.impl_1__remove #t_SpecTransformExpr #Alloc.Alloc.t_Global terms (mk_usize 0)
        in
        let terms:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global = tmp0 in
        folded_nodes, out <: (usize & t_SpecTransformExpr)
      | _ ->
        folded_nodes, (SpecTransformExpr_Add terms <: t_SpecTransformExpr)
        <:
        (usize & t_SpecTransformExpr))
  | SpecTransformExpr_Sub lhs rhs ->
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr lhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr rhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    (match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
      | SpecTransformExpr_Const { f_value = lhs_value },
      SpecTransformExpr_Const { f_value = rhs_value } ->
        let folded_nodes:usize = folded_nodes +! mk_usize 1 in
        folded_nodes,
        (SpecTransformExpr_Const
          ({ f_value = sub_spec_values lhs_value rhs_value field; f_sort_key = mk_usize 0 })
          <:
          t_SpecTransformExpr)
        <:
        (usize & t_SpecTransformExpr)
      | _ ->
        if
          match
            (match rhs <: t_SpecTransformExpr with
              | SpecTransformExpr_Const { f_value = value } ->
                (match spec_value_is_zero_raw value <: bool with
                  | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                  | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
            <:
            Core_models.Option.t_Option bool
          with
          | Core_models.Option.Option_Some x -> x
          | Core_models.Option.Option_None  -> false
        then
          let folded_nodes:usize = folded_nodes +! mk_usize 1 in
          folded_nodes, lhs <: (usize & t_SpecTransformExpr)
        else
          folded_nodes, (SpecTransformExpr_Sub lhs rhs <: t_SpecTransformExpr)
          <:
          (usize & t_SpecTransformExpr))
  | SpecTransformExpr_Mul lhs rhs ->
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr lhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr rhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    (match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
      | SpecTransformExpr_Const { f_value = lhs_value },
      SpecTransformExpr_Const { f_value = rhs_value } ->
        let folded_nodes:usize = folded_nodes +! mk_usize 1 in
        folded_nodes,
        (SpecTransformExpr_Const
          ({ f_value = mul_spec_values lhs_value rhs_value field; f_sort_key = mk_usize 0 })
          <:
          t_SpecTransformExpr)
        <:
        (usize & t_SpecTransformExpr)
      | _ ->
        let (folded_nodes: usize), (hoist56: Core_models.Option.t_Option t_SpecTransformExpr) =
          match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
          | SpecTransformExpr_Const { f_value = value }, _ ->
            (match spec_value_is_zero_raw value <: bool with
              | true ->
                let folded_nodes:usize = folded_nodes +! mk_usize 1 in
                folded_nodes,
                (Core_models.Option.Option_Some (zero_spec_expr ())
                  <:
                  Core_models.Option.t_Option t_SpecTransformExpr)
                <:
                (usize & Core_models.Option.t_Option t_SpecTransformExpr)
              | _ ->
                folded_nodes,
                (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr)
                <:
                (usize & Core_models.Option.t_Option t_SpecTransformExpr))
          | _ ->
            folded_nodes,
            (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr)
            <:
            (usize & Core_models.Option.t_Option t_SpecTransformExpr)
        in
        match hoist56 <: Core_models.Option.t_Option t_SpecTransformExpr with
        | Core_models.Option.Option_Some x -> folded_nodes, x <: (usize & t_SpecTransformExpr)
        | Core_models.Option.Option_None  ->
          let (folded_nodes: usize), (hoist54: Core_models.Option.t_Option t_SpecTransformExpr) =
            match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
            | _, SpecTransformExpr_Const { f_value = value } ->
              (match spec_value_is_zero_raw value <: bool with
                | true ->
                  let folded_nodes:usize = folded_nodes +! mk_usize 1 in
                  folded_nodes,
                  (Core_models.Option.Option_Some (zero_spec_expr ())
                    <:
                    Core_models.Option.t_Option t_SpecTransformExpr)
                  <:
                  (usize & Core_models.Option.t_Option t_SpecTransformExpr)
                | _ ->
                  folded_nodes,
                  (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr
                  )
                  <:
                  (usize & Core_models.Option.t_Option t_SpecTransformExpr))
            | _ ->
              folded_nodes,
              (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr)
              <:
              (usize & Core_models.Option.t_Option t_SpecTransformExpr)
          in
          match hoist54 <: Core_models.Option.t_Option t_SpecTransformExpr with
          | Core_models.Option.Option_Some x -> folded_nodes, x <: (usize & t_SpecTransformExpr)
          | Core_models.Option.Option_None  ->
            let (folded_nodes: usize), (hoist52: Core_models.Option.t_Option t_SpecTransformExpr) =
              match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
              | SpecTransformExpr_Const { f_value = value }, _ ->
                (match spec_value_is_one_raw value <: bool with
                  | true ->
                    let folded_nodes:usize = folded_nodes +! mk_usize 1 in
                    folded_nodes,
                    (Core_models.Option.Option_Some rhs
                      <:
                      Core_models.Option.t_Option t_SpecTransformExpr)
                    <:
                    (usize & Core_models.Option.t_Option t_SpecTransformExpr)
                  | _ ->
                    folded_nodes,
                    (Core_models.Option.Option_None
                      <:
                      Core_models.Option.t_Option t_SpecTransformExpr)
                    <:
                    (usize & Core_models.Option.t_Option t_SpecTransformExpr))
              | _ ->
                folded_nodes,
                (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr)
                <:
                (usize & Core_models.Option.t_Option t_SpecTransformExpr)
            in
            match hoist52 <: Core_models.Option.t_Option t_SpecTransformExpr with
            | Core_models.Option.Option_Some x -> folded_nodes, x <: (usize & t_SpecTransformExpr)
            | Core_models.Option.Option_None  ->
              let (folded_nodes: usize), (hoist50: Core_models.Option.t_Option t_SpecTransformExpr)
              =
                match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
                | _, SpecTransformExpr_Const { f_value = value } ->
                  (match spec_value_is_one_raw value <: bool with
                    | true ->
                      let folded_nodes:usize = folded_nodes +! mk_usize 1 in
                      folded_nodes,
                      (Core_models.Option.Option_Some lhs
                        <:
                        Core_models.Option.t_Option t_SpecTransformExpr)
                      <:
                      (usize & Core_models.Option.t_Option t_SpecTransformExpr)
                    | _ ->
                      folded_nodes,
                      (Core_models.Option.Option_None
                        <:
                        Core_models.Option.t_Option t_SpecTransformExpr)
                      <:
                      (usize & Core_models.Option.t_Option t_SpecTransformExpr))
                | _ ->
                  folded_nodes,
                  (Core_models.Option.Option_None <: Core_models.Option.t_Option t_SpecTransformExpr
                  )
                  <:
                  (usize & Core_models.Option.t_Option t_SpecTransformExpr)
              in
              match hoist50 <: Core_models.Option.t_Option t_SpecTransformExpr with
              | Core_models.Option.Option_Some x -> folded_nodes, x <: (usize & t_SpecTransformExpr)
              | Core_models.Option.Option_None  ->
                folded_nodes, (SpecTransformExpr_Mul lhs rhs <: t_SpecTransformExpr)
                <:
                (usize & t_SpecTransformExpr))
  | SpecTransformExpr_Div lhs rhs ->
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr lhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let lhs:t_SpecTransformExpr = out in
    let (tmp0: usize), (out: t_SpecTransformExpr) = fold_transform_expr rhs field folded_nodes in
    let folded_nodes:usize = tmp0 in
    let rhs:t_SpecTransformExpr = out in
    match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
    | SpecTransformExpr_Const { f_value = lhs_value },
    SpecTransformExpr_Const { f_value = rhs_value } ->
      (match
          div_spec_values lhs_value rhs_value field
          <:
          Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue
        with
        | Core_models.Option.Option_Some value ->
          let folded_nodes:usize = folded_nodes +! mk_usize 1 in
          folded_nodes,
          (SpecTransformExpr_Const ({ f_value = value; f_sort_key = mk_usize 0 })
            <:
            t_SpecTransformExpr)
          <:
          (usize & t_SpecTransformExpr)
        | _ ->
          folded_nodes, (SpecTransformExpr_Div lhs rhs <: t_SpecTransformExpr)
          <:
          (usize & t_SpecTransformExpr))
    | _ ->
      if
        match
          (match rhs <: t_SpecTransformExpr with
            | SpecTransformExpr_Const { f_value = value } ->
              (match spec_value_is_one_raw value <: bool with
                | true -> Core_models.Option.Option_Some true <: Core_models.Option.t_Option bool
                | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
            | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
          <:
          Core_models.Option.t_Option bool
        with
        | Core_models.Option.Option_Some x -> x
        | Core_models.Option.Option_None  -> false
      then
        let folded_nodes:usize = folded_nodes +! mk_usize 1 in
        folded_nodes, lhs <: (usize & t_SpecTransformExpr)
      else
        folded_nodes, (SpecTransformExpr_Div lhs rhs <: t_SpecTransformExpr)
        <:
        (usize & t_SpecTransformExpr)

and fold_add_terms_from
      (values: t_Slice t_SpecTransformExpr)
      (field: Zkf_core.Field.t_FieldId)
      (folded_nodes: usize)
      (const_acc: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (saw_const: bool)
      (terms: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
    : (usize &
      (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
        Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)) =
  let
  ((folded_nodes: usize), (terms: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)),
  (hax_temp_output:
    (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
      Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)) =
    match
      Core_models.Slice.impl__split_first #t_SpecTransformExpr values
      <:
      Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
    with
    | Core_models.Option.Option_Some (value, remaining_values) ->
      let (tmp0: usize), (out: t_SpecTransformExpr) =
        fold_transform_expr value field folded_nodes
      in
      let folded_nodes:usize = tmp0 in
      let folded:t_SpecTransformExpr = out in
      let
      ((folded_nodes: usize), (terms: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)),
      ((const_acc: Zkf_core.Proof_kernel_spec.t_SpecFieldValue),
        (saw_const: bool),
        (terms: Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)) =
        match folded <: t_SpecTransformExpr with
        | SpecTransformExpr_Const { f_value = value } ->
          let folded_nodes:usize = folded_nodes +! mk_usize 1 in
          (folded_nodes, terms <: (usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
          ),
          (add_spec_values const_acc value field, true, terms
            <:
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
          <:
          ((usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) &
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
        | SpecTransformExpr_Add nested ->
          let folded_nodes:usize = folded_nodes +! mk_usize 1 in
          let terms:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
            append_transform_exprs terms
              (Alloc.Vec.impl_1__as_slice nested <: t_Slice t_SpecTransformExpr)
          in
          (folded_nodes, terms <: (usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
          ),
          (const_acc, saw_const, terms
            <:
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
          <:
          ((usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) &
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
        | other ->
          let terms:Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_SpecTransformExpr #Alloc.Alloc.t_Global terms other
          in
          (folded_nodes, terms <: (usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)
          ),
          (const_acc, saw_const, terms
            <:
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
          <:
          ((usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) &
            (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
              Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
      in
      let
      (tmp0: usize),
      (out:
        (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)) =
        fold_add_terms_from remaining_values field folded_nodes const_acc saw_const terms
      in
      let folded_nodes:usize = tmp0 in
      (folded_nodes, terms <: (usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)),
      out
      <:
      ((usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) &
        (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
    | Core_models.Option.Option_None  ->
      (folded_nodes, terms <: (usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global)),
      (const_acc, saw_const, terms
        <:
        (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
      <:
      ((usize & Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global) &
        (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
          Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))
  in
  folded_nodes, hax_temp_output
  <:
  (usize &
    (Zkf_core.Proof_kernel_spec.t_SpecFieldValue & bool &
      Alloc.Vec.t_Vec t_SpecTransformExpr Alloc.Alloc.t_Global))

let rec transform_expr_list_eq (lhs rhs: t_Slice t_SpecTransformExpr) : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformExpr lhs,
    Core_models.Slice.impl__split_first #t_SpecTransformExpr rhs
    <:
    (Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr) &
      Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr))
  with
  | Core_models.Option.Option_Some (lhs_value, lhs_remaining),
  Core_models.Option.Option_Some (rhs_value, rhs_remaining) ->
    transform_expr_eq lhs_value rhs_value && transform_expr_list_eq lhs_remaining rhs_remaining
  | Core_models.Option.Option_None , Core_models.Option.Option_None  -> true
  | _ -> false

and transform_expr_eq (lhs rhs: t_SpecTransformExpr) : bool =
  match lhs, rhs <: (t_SpecTransformExpr & t_SpecTransformExpr) with
  | SpecTransformExpr_Const { f_value = lhs_value ; f_sort_key = lhs_sort_key },
  SpecTransformExpr_Const { f_value = rhs_value ; f_sort_key = rhs_sort_key } ->
    lhs_sort_key =. rhs_sort_key && lhs_value =. rhs_value
  | SpecTransformExpr_Signal { f_signal_index = lhs_signal_index ; f_sort_key = lhs_sort_key },
  SpecTransformExpr_Signal { f_signal_index = rhs_signal_index ; f_sort_key = rhs_sort_key } ->
    lhs_signal_index =. rhs_signal_index && lhs_sort_key =. rhs_sort_key
  | SpecTransformExpr_Add lhs_values, SpecTransformExpr_Add rhs_values ->
    transform_expr_list_eq (Alloc.Vec.impl_1__as_slice lhs_values <: t_Slice t_SpecTransformExpr)
      (Alloc.Vec.impl_1__as_slice rhs_values <: t_Slice t_SpecTransformExpr)
  | SpecTransformExpr_Sub lhs_lhs lhs_rhs, SpecTransformExpr_Sub rhs_lhs rhs_rhs
  | SpecTransformExpr_Mul lhs_lhs lhs_rhs, SpecTransformExpr_Mul rhs_lhs rhs_rhs
  | SpecTransformExpr_Div lhs_lhs lhs_rhs, SpecTransformExpr_Div rhs_lhs rhs_rhs ->
    transform_expr_eq lhs_lhs rhs_lhs && transform_expr_eq lhs_rhs rhs_rhs
  | _ -> false

let rec transform_eval_exprs
      (values: t_Slice t_SpecTransformExpr)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
      (acc: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformExpr values
    <:
    Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
  with
  | Core_models.Option.Option_Some (value, remaining_values) ->
    (match
        transform_eval_expr value witness field
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok evaluated ->
        transform_eval_exprs remaining_values
          witness
          field
          (add_spec_values acc evaluated field <: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | Core_models.Option.Option_None  ->
    Core_models.Result.Result_Ok acc
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError

and transform_eval_expr
      (expr: t_SpecTransformExpr)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Const { f_value = value } ->
    Core_models.Result.Result_Ok (normalize_spec_value value field)
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
      Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
  | SpecTransformExpr_Signal { f_signal_index = signal_index } ->
    transform_signal_value witness signal_index field
  | SpecTransformExpr_Add values ->
    transform_eval_exprs (Alloc.Vec.impl_1__as_slice values <: t_Slice t_SpecTransformExpr)
      witness
      field
      (zero_spec_value () <: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
  | SpecTransformExpr_Sub lhs rhs ->
    (match
        transform_eval_expr lhs witness field
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            transform_eval_expr rhs witness field
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            Core_models.Result.Result_Ok (sub_spec_values lhs_value rhs_value field)
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | SpecTransformExpr_Mul lhs rhs ->
    (match
        transform_eval_expr lhs witness field
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            transform_eval_expr rhs witness field
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            Core_models.Result.Result_Ok (mul_spec_values lhs_value rhs_value field)
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
              Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
          Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
  | SpecTransformExpr_Div lhs rhs ->
    match
      transform_eval_expr lhs witness field
      <:
      Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
        Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
    with
    | Core_models.Result.Result_Ok lhs_value ->
      (match
          transform_eval_expr rhs witness field
          <:
          Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
            Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
        with
        | Core_models.Result.Result_Ok rhs_value ->
          (match
              div_spec_values lhs_value rhs_value field
              <:
              Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue
            with
            | Core_models.Option.Option_Some value ->
              Core_models.Result.Result_Ok value
              <:
              Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
            | Core_models.Option.Option_None  ->
              Core_models.Result.Result_Err
              (Zkf_core.Proof_kernel_spec.SpecKernelCheckError_DivisionByZero
                <:
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
              <:
              Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
                Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
        | Core_models.Result.Result_Err error ->
          Core_models.Result.Result_Err error
          <:
          Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
            Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError)
    | Core_models.Result.Result_Err error ->
      Core_models.Result.Result_Err error
      <:
      Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecFieldValue
        Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError

let rec transform_expr_to_kernel (expr: t_SpecTransformExpr) (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecKernelExpr =
  match expr <: t_SpecTransformExpr with
  | SpecTransformExpr_Const { f_value = value } ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Const
    (Core_models.Clone.f_clone #Zkf_core.Proof_kernel_spec.t_SpecFieldValue
        #FStar.Tactics.Typeclasses.solve
        value)
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
  | SpecTransformExpr_Signal { f_signal_index = signal_index } ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Signal signal_index
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
  | SpecTransformExpr_Add values ->
    to_kernel_expr (Alloc.Vec.impl_1__as_slice values <: t_Slice t_SpecTransformExpr) field
  | SpecTransformExpr_Sub lhs rhs ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Sub (transform_expr_to_kernel lhs field)
      (transform_expr_to_kernel rhs field)
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
  | SpecTransformExpr_Mul lhs rhs ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Mul (transform_expr_to_kernel lhs field)
      (transform_expr_to_kernel rhs field)
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
  | SpecTransformExpr_Div lhs rhs ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Div (transform_expr_to_kernel lhs field)
      (transform_expr_to_kernel rhs field)
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr

and to_kernel_expr_from
      (values: t_Slice t_SpecTransformExpr)
      (acc: Zkf_core.Proof_kernel_spec.t_SpecKernelExpr)
      (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecKernelExpr =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformExpr values
    <:
    Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
  with
  | Core_models.Option.Option_Some (value, remaining_values) ->
    to_kernel_expr_from remaining_values
      (Zkf_core.Proof_kernel_spec.SpecKernelExpr_Add acc
          (transform_expr_to_kernel value field <: Zkf_core.Proof_kernel_spec.t_SpecKernelExpr)
        <:
        Zkf_core.Proof_kernel_spec.t_SpecKernelExpr)
      field
  | Core_models.Option.Option_None  -> acc

and to_kernel_expr (values: t_Slice t_SpecTransformExpr) (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecKernelExpr =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformExpr values
    <:
    Core_models.Option.t_Option (t_SpecTransformExpr & t_Slice t_SpecTransformExpr)
  with
  | Core_models.Option.Option_Some (first, rest) ->
    to_kernel_expr_from rest
      (transform_expr_to_kernel first field <: Zkf_core.Proof_kernel_spec.t_SpecKernelExpr)
      field
  | Core_models.Option.Option_None  ->
    Zkf_core.Proof_kernel_spec.SpecKernelExpr_Const (zero_spec_value ())
    <:
    Zkf_core.Proof_kernel_spec.t_SpecKernelExpr

let rec transform_constraints_to_kernel_from
      (constraints: t_Slice t_SpecTransformConstraint)
      (index: usize)
      (kernel_constraints:
          Alloc.Vec.t_Vec Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint Alloc.Alloc.t_Global)
      (field: Zkf_core.Field.t_FieldId)
    : Alloc.Vec.t_Vec Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint Alloc.Alloc.t_Global =
  match
    Core_models.Slice.impl__split_first #t_SpecTransformConstraint constraints
    <:
    Core_models.Option.t_Option (t_SpecTransformConstraint & t_Slice t_SpecTransformConstraint)
  with
  | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
    let kernel_constraints:Alloc.Vec.t_Vec Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
      Alloc.Alloc.t_Global =
      Alloc.Vec.impl_1__push #Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
        #Alloc.Alloc.t_Global
        kernel_constraints
        (match constraint <: t_SpecTransformConstraint with
          | SpecTransformConstraint_Equal { f_lhs = lhs ; f_rhs = rhs } ->
            Zkf_core.Proof_kernel_spec.SpecKernelConstraint_Equal
            ({
                Zkf_core.Proof_kernel_spec.f_index = index;
                Zkf_core.Proof_kernel_spec.f_lhs
                =
                transform_expr_to_kernel lhs field <: Zkf_core.Proof_kernel_spec.t_SpecKernelExpr;
                Zkf_core.Proof_kernel_spec.f_rhs
                =
                transform_expr_to_kernel rhs field <: Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
              })
            <:
            Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
          | SpecTransformConstraint_Boolean { f_signal_index = signal_index } ->
            Zkf_core.Proof_kernel_spec.SpecKernelConstraint_Boolean
            ({
                Zkf_core.Proof_kernel_spec.f_index = index;
                Zkf_core.Proof_kernel_spec.f_signal = signal_index
              })
            <:
            Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
          | SpecTransformConstraint_Range { f_signal_index = signal_index ; f_bits = bits } ->
            Zkf_core.Proof_kernel_spec.SpecKernelConstraint_Range
            ({
                Zkf_core.Proof_kernel_spec.f_index = index;
                Zkf_core.Proof_kernel_spec.f_signal = signal_index;
                Zkf_core.Proof_kernel_spec.f_bits = bits
              })
            <:
            Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint)
    in
    transform_constraints_to_kernel_from remaining_constraints
      (index +! mk_usize 1 <: usize)
      kernel_constraints
      field
  | Core_models.Option.Option_None  -> kernel_constraints
