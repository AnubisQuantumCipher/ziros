module Zkf_core.Proof_kernel_spec.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Num_bigint.Bigint in
  let open Num_traits.Identities in
  let open Zkf_core.Proof_kernel_spec in
  ()

type t_SpecFieldValue = {
  f_bytes:t_Array u8 (mk_usize 32);
  f_len:u8;
  f_negative:bool
}

let spec_field_value_raw_bigint (value: t_SpecFieldValue) : Num_bigint.Bigint.t_BigInt =
  Zkf_core.Proof_kernel_spec.impl_SpecFieldValue__as_bigint value

let spec_field_value_from_bigint_with_field
      (value: Num_bigint.Bigint.t_BigInt)
      (field: Zkf_core.Field.t_FieldId)
    : t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.impl_SpecFieldValue__from_runtime (Zkf_core.Field.impl_FieldElement__from_bigint_with_field
        value
        field
      <:
      Zkf_core.Field.t_FieldElement)

let spec_field_value_zero (_: Prims.unit) : t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.impl_SpecFieldValue__from_runtime (Zkf_core.Field.impl_FieldElement__from_i64
        (mk_i64 0)
      <:
      Zkf_core.Field.t_FieldElement)

let spec_field_value_is_zero_raw (value: t_SpecFieldValue) : bool =
  Num_traits.Identities.f_is_zero #Num_bigint.Bigint.t_BigInt
    #FStar.Tactics.Typeclasses.solve
    (spec_field_value_raw_bigint value <: Num_bigint.Bigint.t_BigInt)

let spec_field_value_is_one_raw (value: t_SpecFieldValue) : bool =
  Num_traits.Identities.f_is_one #Num_bigint.Bigint.t_BigInt
    #FStar.Tactics.Typeclasses.solve
    (spec_field_value_raw_bigint value <: Num_bigint.Bigint.t_BigInt)

let spec_normalize_mod_bigint (value modulus: Num_bigint.Bigint.t_BigInt)
    : Num_bigint.Bigint.t_BigInt = Zkf_core.Field.normalize_mod value modulus

let spec_mod_inverse_bigint (value modulus: Num_bigint.Bigint.t_BigInt)
    : Core_models.Option.t_Option Num_bigint.Bigint.t_BigInt =
  Zkf_core.Field.mod_inverse_bigint value modulus

type t_SpecKernelLookupTable = {
  f_column_count:usize;
  f_rows:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global
}

type t_SpecKernelWitness = {
  f_values:Alloc.Vec.t_Vec (Core_models.Option.t_Option t_SpecFieldValue) Alloc.Alloc.t_Global
}

type t_SpecLookupFailureKind =
  | SpecLookupFailureKind_InputArityMismatch {
    f_provided:usize;
    f_available:usize
  }: t_SpecLookupFailureKind
  | SpecLookupFailureKind_NoMatchingRow : t_SpecLookupFailureKind

type t_SpecKernelCheckError =
  | SpecKernelCheckError_MissingSignal { f_signal_index:usize }: t_SpecKernelCheckError
  | SpecKernelCheckError_DivisionByZero : t_SpecKernelCheckError
  | SpecKernelCheckError_UnknownLookupTable { f_table_index:usize }: t_SpecKernelCheckError
  | SpecKernelCheckError_EqualViolation {
    f_constraint_index:usize;
    f_lhs:t_SpecFieldValue;
    f_rhs:t_SpecFieldValue
  }: t_SpecKernelCheckError
  | SpecKernelCheckError_BooleanViolation {
    f_constraint_index:usize;
    f_signal_index:usize;
    f_value:t_SpecFieldValue
  }: t_SpecKernelCheckError
  | SpecKernelCheckError_RangeViolation {
    f_constraint_index:usize;
    f_signal_index:usize;
    f_bits:u32;
    f_value:t_SpecFieldValue
  }: t_SpecKernelCheckError
  | SpecKernelCheckError_LookupViolation {
    f_constraint_index:usize;
    f_table_index:usize;
    f_inputs:Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global;
    f_outputs:Core_models.Option.t_Option (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global);
    f_kind:t_SpecLookupFailureKind
  }: t_SpecKernelCheckError

assume
val zero': Prims.unit -> t_SpecFieldValue

unfold
let zero = zero'

assume
val normalize': value: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId -> t_SpecFieldValue

unfold
let normalize = normalize'

let kernel_signal_value
      (witness: t_SpecKernelWitness)
      (signal_index: usize)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__get #(Core_models.Option.t_Option t_SpecFieldValue)
      #usize
      (Alloc.Vec.impl_1__as_slice witness.f_values
        <:
        t_Slice (Core_models.Option.t_Option t_SpecFieldValue))
      signal_index
    <:
    Core_models.Option.t_Option (Core_models.Option.t_Option t_SpecFieldValue)
  with
  | Core_models.Option.Option_Some (Core_models.Option.Option_Some value) ->
    Core_models.Result.Result_Ok (normalize value field)
    <:
    Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
  | _ ->
    Core_models.Result.Result_Err
    (SpecKernelCheckError_MissingSignal ({ f_signal_index = signal_index })
      <:
      t_SpecKernelCheckError)
    <:
    Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError

assume
val add': lhs: t_SpecFieldValue -> rhs: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId
  -> t_SpecFieldValue

unfold
let add = add'

assume
val sub': lhs: t_SpecFieldValue -> rhs: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId
  -> t_SpecFieldValue

unfold
let sub = sub'

assume
val mul': lhs: t_SpecFieldValue -> rhs: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId
  -> t_SpecFieldValue

unfold
let mul = mul'

assume
val div': lhs: t_SpecFieldValue -> rhs: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId
  -> Core_models.Option.t_Option t_SpecFieldValue

unfold
let div = div'

assume
val eq': lhs: t_SpecFieldValue -> rhs: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId -> bool

unfold
let eq = eq'

assume
val is_boolean': value: t_SpecFieldValue -> field: Zkf_core.Field.t_FieldId -> bool

unfold
let is_boolean = is_boolean'

assume
val fits_bits': value: t_SpecFieldValue -> bits: u32 -> field: Zkf_core.Field.t_FieldId -> bool

unfold
let fits_bits = fits_bits'

type t_SpecKernelExpr =
  | SpecKernelExpr_Const : t_SpecFieldValue -> t_SpecKernelExpr
  | SpecKernelExpr_Signal : usize -> t_SpecKernelExpr
  | SpecKernelExpr_Add : t_SpecKernelExpr -> t_SpecKernelExpr -> t_SpecKernelExpr
  | SpecKernelExpr_Sub : t_SpecKernelExpr -> t_SpecKernelExpr -> t_SpecKernelExpr
  | SpecKernelExpr_Mul : t_SpecKernelExpr -> t_SpecKernelExpr -> t_SpecKernelExpr
  | SpecKernelExpr_Div : t_SpecKernelExpr -> t_SpecKernelExpr -> t_SpecKernelExpr

let rec render_lookup_outputs_from
      (signal_indices: t_Slice usize)
      (current_column: usize)
      (lookup_table: t_SpecKernelLookupTable)
      (witness: t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
      (acc: Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__split_first #usize signal_indices
    <:
    Core_models.Option.t_Option (usize & t_Slice usize)
  with
  | Core_models.Option.Option_Some (signal_index, remaining_signal_indices) ->
    if current_column <. lookup_table.f_column_count
    then
      match
        kernel_signal_value witness signal_index field
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok value ->
        let acc:Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecFieldValue #Alloc.Alloc.t_Global acc value
        in
        render_lookup_outputs_from remaining_signal_indices
          (current_column +! mk_usize 1 <: usize)
          lookup_table
          witness
          field
          acc
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
          t_SpecKernelCheckError
    else
      render_lookup_outputs_from remaining_signal_indices
        (current_column +! mk_usize 1 <: usize)
        lookup_table
        witness
        field
        acc
  | Core_models.Option.Option_None  ->
    Core_models.Result.Result_Ok acc
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError

let rec row_matches_inputs_from
      (row evaluated_inputs: t_Slice t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecFieldValue evaluated_inputs
    <:
    Core_models.Option.t_Option (t_SpecFieldValue & t_Slice t_SpecFieldValue)
  with
  | Core_models.Option.Option_Some (input_value, remaining_inputs) ->
    let (row_value: t_SpecFieldValue), (remaining_row: t_Slice t_SpecFieldValue) =
      match
        Core_models.Slice.impl__split_first #t_SpecFieldValue row
        <:
        Core_models.Option.t_Option (t_SpecFieldValue & t_Slice t_SpecFieldValue)
      with
      | Core_models.Option.Option_Some (value, remaining_row) ->
        Core_models.Clone.f_clone #t_SpecFieldValue #FStar.Tactics.Typeclasses.solve value,
        remaining_row
        <:
        (t_SpecFieldValue & t_Slice t_SpecFieldValue)
      | Core_models.Option.Option_None  ->
        zero (), row <: (t_SpecFieldValue & t_Slice t_SpecFieldValue)
    in
    eq row_value input_value field && row_matches_inputs_from remaining_row remaining_inputs field
  | Core_models.Option.Option_None  -> true

let rec skip_row_prefix (row: t_Slice t_SpecFieldValue) (remaining_to_skip: usize)
    : t_Slice t_SpecFieldValue =
  if remaining_to_skip =. mk_usize 0
  then row
  else
    match
      Core_models.Slice.impl__split_first #t_SpecFieldValue row
      <:
      Core_models.Option.t_Option (t_SpecFieldValue & t_Slice t_SpecFieldValue)
    with
    | Core_models.Option.Option_Some (e_value, remaining_row) ->
      skip_row_prefix remaining_row (remaining_to_skip -! mk_usize 1 <: usize)
    | Core_models.Option.Option_None  -> row

let rec row_matches_outputs_from
      (row expected_outputs: t_Slice t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool =
  match
    Core_models.Slice.impl__split_first #t_SpecFieldValue expected_outputs
    <:
    Core_models.Option.t_Option (t_SpecFieldValue & t_Slice t_SpecFieldValue)
  with
  | Core_models.Option.Option_Some (output_value, remaining_outputs) ->
    let (row_value: t_SpecFieldValue), (remaining_row: t_Slice t_SpecFieldValue) =
      match
        Core_models.Slice.impl__split_first #t_SpecFieldValue row
        <:
        Core_models.Option.t_Option (t_SpecFieldValue & t_Slice t_SpecFieldValue)
      with
      | Core_models.Option.Option_Some (value, remaining_row) ->
        Core_models.Clone.f_clone #t_SpecFieldValue #FStar.Tactics.Typeclasses.solve value,
        remaining_row
        <:
        (t_SpecFieldValue & t_Slice t_SpecFieldValue)
      | Core_models.Option.Option_None  ->
        zero (), row <: (t_SpecFieldValue & t_Slice t_SpecFieldValue)
    in
    eq row_value output_value field &&
    row_matches_outputs_from remaining_row remaining_outputs field
  | Core_models.Option.Option_None  -> true

type t_SpecKernelConstraint =
  | SpecKernelConstraint_Equal {
    f_index:usize;
    f_lhs:t_SpecKernelExpr;
    f_rhs:t_SpecKernelExpr
  }: t_SpecKernelConstraint
  | SpecKernelConstraint_Boolean {
    f_index:usize;
    f_signal:usize
  }: t_SpecKernelConstraint
  | SpecKernelConstraint_Range {
    f_index:usize;
    f_signal:usize;
    f_bits:u32
  }: t_SpecKernelConstraint
  | SpecKernelConstraint_Lookup {
    f_index:usize;
    f_inputs:Alloc.Vec.t_Vec t_SpecKernelExpr Alloc.Alloc.t_Global;
    f_table_index:usize;
    f_outputs:Core_models.Option.t_Option (Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global)
  }: t_SpecKernelConstraint

type t_SpecKernelProgram = {
  f_field:Zkf_core.Field.t_FieldId;
  f_constraints:Alloc.Vec.t_Vec t_SpecKernelConstraint Alloc.Alloc.t_Global;
  f_lookup_tables:Alloc.Vec.t_Vec t_SpecKernelLookupTable Alloc.Alloc.t_Global
}

let render_lookup_outputs
      (signal_indices: t_Slice usize)
      (input_len: usize)
      (lookup_table: t_SpecKernelLookupTable)
      (witness: t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError =
  render_lookup_outputs_from signal_indices
    input_len
    lookup_table
    witness
    field
    (Alloc.Vec.impl__new #t_SpecFieldValue ()
      <:
      Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)

let row_matches_inputs
      (row evaluated_inputs: t_Slice t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool = row_matches_inputs_from row evaluated_inputs field

let row_matches_outputs
      (row: t_Slice t_SpecFieldValue)
      (input_len: usize)
      (expected_outputs: t_Slice t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : bool =
  row_matches_outputs_from (skip_row_prefix row input_len <: t_Slice t_SpecFieldValue)
    expected_outputs
    field

let rec lookup_has_matching_row_from
      (rows: t_Slice (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global))
      (evaluated_inputs: t_Slice t_SpecFieldValue)
      (expected_outputs:
          Core_models.Option.t_Option (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global))
      (input_len: usize)
      (field: Zkf_core.Field.t_FieldId)
    : bool =
  match
    Core_models.Slice.impl__split_first #(Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      rows
    <:
    Core_models.Option.t_Option
    (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global &
      t_Slice (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global))
  with
  | Core_models.Option.Option_Some (row, remaining_rows) ->
    let row_matches:bool =
      if
        row_matches_inputs (Alloc.Vec.impl_1__as_slice row <: t_Slice t_SpecFieldValue)
          evaluated_inputs
          field
      then
        match
          expected_outputs
          <:
          Core_models.Option.t_Option (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
        with
        | Core_models.Option.Option_Some outputs ->
          row_matches_outputs (Alloc.Vec.impl_1__as_slice row <: t_Slice t_SpecFieldValue)
            input_len
            (Alloc.Vec.impl_1__as_slice outputs <: t_Slice t_SpecFieldValue)
            field
        | Core_models.Option.Option_None  -> true
      else false
    in
    row_matches ||
    lookup_has_matching_row_from remaining_rows evaluated_inputs expected_outputs input_len field
  | Core_models.Option.Option_None  -> false

let rec eval_expr
      (expr: t_SpecKernelExpr)
      (witness: t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError =
  match expr <: t_SpecKernelExpr with
  | SpecKernelExpr_Const value ->
    Core_models.Result.Result_Ok (normalize value field)
    <:
    Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
  | SpecKernelExpr_Signal signal_index -> kernel_signal_value witness signal_index field
  | SpecKernelExpr_Add lhs rhs ->
    (match
        eval_expr lhs witness field
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            eval_expr rhs witness field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            Core_models.Result.Result_Ok (add lhs_value rhs_value field)
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
  | SpecKernelExpr_Sub lhs rhs ->
    (match
        eval_expr lhs witness field
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            eval_expr rhs witness field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            Core_models.Result.Result_Ok (sub lhs_value rhs_value field)
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
  | SpecKernelExpr_Mul lhs rhs ->
    (match
        eval_expr lhs witness field
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok lhs_value ->
        (match
            eval_expr rhs witness field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok rhs_value ->
            Core_models.Result.Result_Ok (mul lhs_value rhs_value field)
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
  | SpecKernelExpr_Div lhs rhs ->
    match
      eval_expr lhs witness field
      <:
      Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
    with
    | Core_models.Result.Result_Ok lhs_value ->
      (match
          eval_expr rhs witness field
          <:
          Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
        with
        | Core_models.Result.Result_Ok rhs_value ->
          (match div lhs_value rhs_value field <: Core_models.Option.t_Option t_SpecFieldValue with
            | Core_models.Option.Option_Some value ->
              Core_models.Result.Result_Ok value
              <:
              Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
            | Core_models.Option.Option_None  ->
              Core_models.Result.Result_Err
              (SpecKernelCheckError_DivisionByZero <: t_SpecKernelCheckError)
              <:
              Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
        | Core_models.Result.Result_Err error ->
          Core_models.Result.Result_Err error
          <:
          Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError)
    | Core_models.Result.Result_Err error ->
      Core_models.Result.Result_Err error
      <:
      Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError

let rec collect_evaluated_inputs_from
      (inputs: t_Slice t_SpecKernelExpr)
      (witness: t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
      (acc: Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__split_first #t_SpecKernelExpr inputs
    <:
    Core_models.Option.t_Option (t_SpecKernelExpr & t_Slice t_SpecKernelExpr)
  with
  | Core_models.Option.Option_Some (input, remaining_inputs) ->
    (match
        eval_expr input witness field
        <:
        Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
      with
      | Core_models.Result.Result_Ok value ->
        let acc:Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #t_SpecFieldValue #Alloc.Alloc.t_Global acc value
        in
        collect_evaluated_inputs_from remaining_inputs witness field acc
      | Core_models.Result.Result_Err error ->
        Core_models.Result.Result_Err error
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
          t_SpecKernelCheckError)
  | Core_models.Option.Option_None  ->
    Core_models.Result.Result_Ok acc
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError

let collect_evaluated_inputs
      (inputs: t_Slice t_SpecKernelExpr)
      (witness: t_SpecKernelWitness)
      (field: Zkf_core.Field.t_FieldId)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
      t_SpecKernelCheckError =
  collect_evaluated_inputs_from inputs
    witness
    field
    (Alloc.Vec.impl__new #t_SpecFieldValue ()
      <:
      Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)

let rec check_constraints_from
      (constraints: t_Slice t_SpecKernelConstraint)
      (program: t_SpecKernelProgram)
      (witness: t_SpecKernelWitness)
    : Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError =
  match
    Core_models.Slice.impl__split_first #t_SpecKernelConstraint constraints
    <:
    Core_models.Option.t_Option (t_SpecKernelConstraint & t_Slice t_SpecKernelConstraint)
  with
  | Core_models.Option.Option_Some (constraint, remaining_constraints) ->
    (match constraint <: t_SpecKernelConstraint with
      | SpecKernelConstraint_Equal { f_index = index ; f_lhs = lhs ; f_rhs = rhs } ->
        (match
            eval_expr lhs witness program.f_field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok lhs_value ->
            (match
                eval_expr rhs witness program.f_field
                <:
                Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
              with
              | Core_models.Result.Result_Ok rhs_value ->
                if eq lhs_value rhs_value program.f_field
                then check_constraints_from remaining_constraints program witness
                else
                  Core_models.Result.Result_Err
                  (SpecKernelCheckError_EqualViolation
                    ({ f_constraint_index = index; f_lhs = lhs_value; f_rhs = rhs_value })
                    <:
                    t_SpecKernelCheckError)
                  <:
                  Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
              | Core_models.Result.Result_Err error ->
                Core_models.Result.Result_Err error
                <:
                Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
      | SpecKernelConstraint_Boolean { f_index = index ; f_signal = signal } ->
        (match
            kernel_signal_value witness signal program.f_field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok value ->
            if is_boolean value program.f_field
            then check_constraints_from remaining_constraints program witness
            else
              Core_models.Result.Result_Err
              (SpecKernelCheckError_BooleanViolation
                ({ f_constraint_index = index; f_signal_index = signal; f_value = value })
                <:
                t_SpecKernelCheckError)
              <:
              Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
      | SpecKernelConstraint_Range { f_index = index ; f_signal = signal ; f_bits = bits } ->
        (match
            kernel_signal_value witness signal program.f_field
            <:
            Core_models.Result.t_Result t_SpecFieldValue t_SpecKernelCheckError
          with
          | Core_models.Result.Result_Ok value ->
            if fits_bits value bits program.f_field
            then check_constraints_from remaining_constraints program witness
            else
              Core_models.Result.Result_Err
              (SpecKernelCheckError_RangeViolation
                ({
                    f_constraint_index = index;
                    f_signal_index = signal;
                    f_bits = bits;
                    f_value = value
                  })
                <:
                t_SpecKernelCheckError)
              <:
              Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
          | Core_models.Result.Result_Err error ->
            Core_models.Result.Result_Err error
            <:
            Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
      | SpecKernelConstraint_Lookup
        { f_index = index ; f_inputs = inputs ; f_table_index = table_index ; f_outputs = outputs } ->
        match
          Core_models.Slice.impl__get #t_SpecKernelLookupTable
            #usize
            (Alloc.Vec.impl_1__as_slice program.f_lookup_tables <: t_Slice t_SpecKernelLookupTable)
            table_index
          <:
          Core_models.Option.t_Option t_SpecKernelLookupTable
        with
        | Core_models.Option.Option_Some lookup_table ->
          if
            (Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs <: usize) >.
            lookup_table.f_column_count
          then
            match
              collect_evaluated_inputs (Alloc.Vec.impl_1__as_slice inputs
                  <:
                  t_Slice t_SpecKernelExpr)
                witness
                program.f_field
              <:
              Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                t_SpecKernelCheckError
            with
            | Core_models.Result.Result_Ok rendered_inputs ->
              (match
                  outputs
                  <:
                  Core_models.Option.t_Option (Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global)
                with
                | Core_models.Option.Option_Some signal_indices ->
                  (match
                      render_lookup_outputs (Alloc.Vec.impl_1__as_slice signal_indices
                          <:
                          t_Slice usize)
                        (Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs
                          <:
                          usize)
                        lookup_table
                        witness
                        program.f_field
                      <:
                      Core_models.Result.t_Result
                        (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                        t_SpecKernelCheckError
                    with
                    | Core_models.Result.Result_Ok values ->
                      Core_models.Result.Result_Err
                      (SpecKernelCheckError_LookupViolation
                        ({
                            f_constraint_index = index;
                            f_table_index = table_index;
                            f_inputs = rendered_inputs;
                            f_outputs
                            =
                            Core_models.Option.Option_Some values
                            <:
                            Core_models.Option.t_Option
                            (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global);
                            f_kind
                            =
                            SpecLookupFailureKind_InputArityMismatch
                            ({
                                f_provided
                                =
                                Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs;
                                f_available = lookup_table.f_column_count
                              })
                            <:
                            t_SpecLookupFailureKind
                          })
                        <:
                        t_SpecKernelCheckError)
                      <:
                      Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
                    | Core_models.Result.Result_Err error ->
                      Core_models.Result.Result_Err error
                      <:
                      Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
                | Core_models.Option.Option_None  ->
                  Core_models.Result.Result_Err
                  (SpecKernelCheckError_LookupViolation
                    ({
                        f_constraint_index = index;
                        f_table_index = table_index;
                        f_inputs = rendered_inputs;
                        f_outputs
                        =
                        Core_models.Option.Option_None
                        <:
                        Core_models.Option.t_Option
                        (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global);
                        f_kind
                        =
                        SpecLookupFailureKind_InputArityMismatch
                        ({
                            f_provided
                            =
                            Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs;
                            f_available = lookup_table.f_column_count
                          })
                        <:
                        t_SpecLookupFailureKind
                      })
                    <:
                    t_SpecKernelCheckError)
                  <:
                  Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
            | Core_models.Result.Result_Err error ->
              Core_models.Result.Result_Err error
              <:
              Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
          else
            (match
                collect_evaluated_inputs (Alloc.Vec.impl_1__as_slice inputs
                    <:
                    t_Slice t_SpecKernelExpr)
                  witness
                  program.f_field
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                  t_SpecKernelCheckError
              with
              | Core_models.Result.Result_Ok evaluated_inputs ->
                (match
                    outputs
                    <:
                    Core_models.Option.t_Option (Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global)
                  with
                  | Core_models.Option.Option_Some signal_indices ->
                    (match
                        render_lookup_outputs (Alloc.Vec.impl_1__as_slice signal_indices
                            <:
                            t_Slice usize)
                          (Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs
                            <:
                            usize)
                          lookup_table
                          witness
                          program.f_field
                        <:
                        Core_models.Result.t_Result
                          (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                          t_SpecKernelCheckError
                      with
                      | Core_models.Result.Result_Ok values ->
                        let expected_outputs:Core_models.Option.t_Option
                        (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global) =
                          Core_models.Option.Option_Some values
                          <:
                          Core_models.Option.t_Option
                          (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                        in
                        if
                          lookup_has_matching_row_from (Alloc.Vec.impl_1__as_slice lookup_table
                                  .f_rows
                              <:
                              t_Slice (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global))
                            (Alloc.Vec.impl_1__as_slice evaluated_inputs <: t_Slice t_SpecFieldValue
                            )
                            expected_outputs
                            (Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs
                              <:
                              usize)
                            program.f_field
                        then check_constraints_from remaining_constraints program witness
                        else
                          Core_models.Result.Result_Err
                          (SpecKernelCheckError_LookupViolation
                            ({
                                f_constraint_index = index;
                                f_table_index = table_index;
                                f_inputs = evaluated_inputs;
                                f_outputs = expected_outputs;
                                f_kind
                                =
                                SpecLookupFailureKind_NoMatchingRow <: t_SpecLookupFailureKind
                              })
                            <:
                            t_SpecKernelCheckError)
                          <:
                          Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError
                      | Core_models.Result.Result_Err error ->
                        Core_models.Result.Result_Err error
                        <:
                        Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
                  | Core_models.Option.Option_None  ->
                    let expected_outputs:Core_models.Option.t_Option
                    (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global) =
                      Core_models.Option.Option_None
                      <:
                      Core_models.Option.t_Option
                      (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global)
                    in
                    if
                      lookup_has_matching_row_from (Alloc.Vec.impl_1__as_slice lookup_table.f_rows
                          <:
                          t_Slice (Alloc.Vec.t_Vec t_SpecFieldValue Alloc.Alloc.t_Global))
                        (Alloc.Vec.impl_1__as_slice evaluated_inputs <: t_Slice t_SpecFieldValue)
                        expected_outputs
                        (Alloc.Vec.impl_1__len #t_SpecKernelExpr #Alloc.Alloc.t_Global inputs
                          <:
                          usize)
                        program.f_field
                    then check_constraints_from remaining_constraints program witness
                    else
                      Core_models.Result.Result_Err
                      (SpecKernelCheckError_LookupViolation
                        ({
                            f_constraint_index = index;
                            f_table_index = table_index;
                            f_inputs = evaluated_inputs;
                            f_outputs = expected_outputs;
                            f_kind = SpecLookupFailureKind_NoMatchingRow <: t_SpecLookupFailureKind
                          })
                        <:
                        t_SpecKernelCheckError)
                      <:
                      Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
              | Core_models.Result.Result_Err error ->
                Core_models.Result.Result_Err error
                <:
                Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
        | Core_models.Option.Option_None  ->
          Core_models.Result.Result_Err
          (SpecKernelCheckError_UnknownLookupTable ({ f_table_index = table_index })
            <:
            t_SpecKernelCheckError)
          <:
          Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError)
  | Core_models.Option.Option_None  ->
    Core_models.Result.Result_Ok (() <: Prims.unit)
    <:
    Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError

let check_program (program: t_SpecKernelProgram) (witness: t_SpecKernelWitness)
    : Core_models.Result.t_Result Prims.unit t_SpecKernelCheckError =
  check_constraints_from (Alloc.Vec.impl_1__as_slice program.f_constraints
      <:
      t_Slice t_SpecKernelConstraint)
    program
    witness
