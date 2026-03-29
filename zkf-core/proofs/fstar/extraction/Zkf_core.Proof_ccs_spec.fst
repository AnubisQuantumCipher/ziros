module Zkf_core.Proof_ccs_spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Num_bigint.Bigint in
  let open Num_bigint.Bigint.Addition in
  let open Num_bigint.Bigint.Shift in
  let open Num_traits.Identities in
  ()

type t_SpecCcsVisibility =
  | SpecCcsVisibility_Public : t_SpecCcsVisibility
  | SpecCcsVisibility_NonPublic : t_SpecCcsVisibility

type t_SpecCcsSignal = { f_visibility:t_SpecCcsVisibility }

type t_SpecCcsBlackBoxKind =
  | SpecCcsBlackBoxKind_RecursiveAggregationMarker : t_SpecCcsBlackBoxKind
  | SpecCcsBlackBoxKind_Other : t_SpecCcsBlackBoxKind

type t_SpecCcsMatrixEntry = {
  f_row:usize;
  f_col:usize;
  f_value:Zkf_core.Proof_kernel_spec.t_SpecFieldValue
}

type t_SpecCcsMatrix = {
  f_rows:usize;
  f_cols:usize;
  f_entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global
}

type t_SpecCcsMultiset = {
  f_matrix_indices:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global;
  f_coefficient:Zkf_core.Proof_kernel_spec.t_SpecFieldValue
}

type t_SpecCcsProgram = {
  f_field:Zkf_core.Field.t_FieldId;
  f_num_constraints:usize;
  f_num_variables:usize;
  f_num_public:usize;
  f_matrices:Alloc.Vec.t_Vec t_SpecCcsMatrix Alloc.Alloc.t_Global;
  f_multisets:Alloc.Vec.t_Vec t_SpecCcsMultiset Alloc.Alloc.t_Global
}

type t_SpecCcsSynthesisErrorKind =
  | SpecCcsSynthesisErrorKind_InvalidSignalIndex : t_SpecCcsSynthesisErrorKind
  | SpecCcsSynthesisErrorKind_LookupRequiresLowering : t_SpecCcsSynthesisErrorKind
  | SpecCcsSynthesisErrorKind_BlackBoxRequiresLowering : t_SpecCcsSynthesisErrorKind

type t_SpecCcsSynthesisError = {
  f_constraint_index:usize;
  f_kind:t_SpecCcsSynthesisErrorKind
}

let spec_value_to_bigint
      (value: Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      (field: Zkf_core.Field.t_FieldId)
    : Num_bigint.Bigint.t_BigInt =
  Zkf_core.Field.normalize (Zkf_core.Field.impl_FieldElement__as_bigint (Zkf_core.Proof_kernel_spec.impl_SpecFieldValue__to_runtime
            value
          <:
          Zkf_core.Field.t_FieldElement)
      <:
      Num_bigint.Bigint.t_BigInt)
    field

let bigint_to_spec_value (value: Num_bigint.Bigint.t_BigInt) (field: Zkf_core.Field.t_FieldId)
    : Zkf_core.Proof_kernel_spec.t_SpecFieldValue =
  Zkf_core.Proof_kernel_spec.impl_SpecFieldValue__from_runtime (Zkf_core.Field.impl_FieldElement__from_bigint_with_field
        value
        field
      <:
      Zkf_core.Field.t_FieldElement)

type t_SpecCcsBuilder = {
  f_field:Zkf_core.Field.t_FieldId;
  f_signal_columns:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global;
  f_next_col:usize;
  f_num_public:usize;
  f_row:usize;
  f_a_entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global;
  f_b_entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global;
  f_c_entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global
}

let builder_finish (builder: t_SpecCcsBuilder) (field: Zkf_core.Field.t_FieldId) : t_SpecCcsProgram =
  let num_constraints:usize = builder.f_row in
  let rows:usize = num_constraints in
  let cols:usize = builder.f_next_col in
  {
    f_field = field;
    f_num_constraints = num_constraints;
    f_num_variables = cols;
    f_num_public = builder.f_num_public;
    f_matrices
    =
    Alloc.Slice.impl__into_vec #t_SpecCcsMatrix
      #Alloc.Alloc.t_Global
      ((let list =
            [
              { f_rows = rows; f_cols = cols; f_entries = builder.f_a_entries } <: t_SpecCcsMatrix;
              { f_rows = rows; f_cols = cols; f_entries = builder.f_b_entries } <: t_SpecCcsMatrix;
              { f_rows = rows; f_cols = cols; f_entries = builder.f_c_entries } <: t_SpecCcsMatrix
            ]
          in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
          Rust_primitives.Hax.array_of_list 3 list)
        <:
        t_Slice t_SpecCcsMatrix);
    f_multisets
    =
    Alloc.Slice.impl__into_vec #t_SpecCcsMultiset
      #Alloc.Alloc.t_Global
      ((let list =
            [
              {
                f_matrix_indices
                =
                Alloc.Slice.impl__into_vec #usize
                  #Alloc.Alloc.t_Global
                  ((let list = [mk_usize 0; mk_usize 1] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    <:
                    t_Slice usize);
                f_coefficient
                =
                bigint_to_spec_value (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt
                      #FStar.Tactics.Typeclasses.solve
                      ()
                    <:
                    Num_bigint.Bigint.t_BigInt)
                  field
              }
              <:
              t_SpecCcsMultiset;
              {
                f_matrix_indices
                =
                Alloc.Slice.impl__into_vec #usize
                  #Alloc.Alloc.t_Global
                  ((let list = [mk_usize 2] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                    <:
                    t_Slice usize);
                f_coefficient
                =
                bigint_to_spec_value (Core_models.Ops.Arith.f_neg #Num_bigint.Bigint.t_BigInt
                      #FStar.Tactics.Typeclasses.solve
                      (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt
                          #FStar.Tactics.Typeclasses.solve
                          ()
                        <:
                        Num_bigint.Bigint.t_BigInt)
                    <:
                    Num_bigint.Bigint.t_BigInt)
                  field
              }
              <:
              t_SpecCcsMultiset
            ]
          in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
          Rust_primitives.Hax.array_of_list 2 list)
        <:
        t_Slice t_SpecCcsMultiset)
  }
  <:
  t_SpecCcsProgram

let builder_allocate_aux (builder: t_SpecCcsBuilder) : (t_SpecCcsBuilder & usize) =
  let col:usize = builder.f_next_col in
  let builder:t_SpecCcsBuilder =
    { builder with f_next_col = builder.f_next_col +! mk_usize 1 } <: t_SpecCcsBuilder
  in
  let hax_temp_output:usize = col in
  builder, hax_temp_output <: (t_SpecCcsBuilder & usize)

let lc_add_term
      (target:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
      (col: usize)
      (coeff: Num_bigint.Bigint.t_BigInt)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  if
    Num_traits.Identities.f_is_zero #Num_bigint.Bigint.t_BigInt
      #FStar.Tactics.Typeclasses.solve
      coeff
  then target
  else
    let
    (tmp0:
      Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global),
    (out: Core_models.Option.t_Option Num_bigint.Bigint.t_BigInt) =
      Alloc.Collections.Btree.Map.impl_20__remove #usize
        #Num_bigint.Bigint.t_BigInt
        #Alloc.Alloc.t_Global
        #usize
        target
        col
    in
    let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
      Num_bigint.Bigint.t_BigInt
      Alloc.Alloc.t_Global =
      tmp0
    in
    let updated:Num_bigint.Bigint.t_BigInt =
      Core_models.Option.impl__unwrap_or #Num_bigint.Bigint.t_BigInt
        (Core_models.Option.impl__map #Num_bigint.Bigint.t_BigInt
            #Num_bigint.Bigint.t_BigInt
            #(Num_bigint.Bigint.t_BigInt -> Num_bigint.Bigint.t_BigInt)
            out
            (fun existing ->
                let existing:Num_bigint.Bigint.t_BigInt = existing in
                Core_models.Ops.Arith.f_add #Num_bigint.Bigint.t_BigInt
                  #Num_bigint.Bigint.t_BigInt
                  #FStar.Tactics.Typeclasses.solve
                  existing
                  (Core_models.Clone.f_clone #Num_bigint.Bigint.t_BigInt
                      #FStar.Tactics.Typeclasses.solve
                      coeff
                    <:
                    Num_bigint.Bigint.t_BigInt)
                <:
                Num_bigint.Bigint.t_BigInt)
          <:
          Core_models.Option.t_Option Num_bigint.Bigint.t_BigInt)
        coeff
    in
    if
      ~.(Num_traits.Identities.f_is_zero #Num_bigint.Bigint.t_BigInt
          #FStar.Tactics.Typeclasses.solve
          updated
        <:
        bool)
    then
      let
      (tmp0:
        Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global
      ),
      (out: Core_models.Option.t_Option Num_bigint.Bigint.t_BigInt) =
        Alloc.Collections.Btree.Map.impl_20__insert #usize
          #Num_bigint.Bigint.t_BigInt
          #Alloc.Alloc.t_Global
          target
          col
          updated
      in
      let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
        Num_bigint.Bigint.t_BigInt
        Alloc.Alloc.t_Global =
        tmp0
      in
      let _:Core_models.Option.t_Option Num_bigint.Bigint.t_BigInt = out in
      target
    else target

let lc_const (value: Num_bigint.Bigint.t_BigInt)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
  in
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    lc_add_term expr (mk_usize 0) value
  in
  expr

let lc_var (col: usize)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
  in
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    lc_add_term expr
      col
      (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt #FStar.Tactics.Typeclasses.solve ()
        <:
        Num_bigint.Bigint.t_BigInt)
  in
  expr

let builder_signal_lc (builder: t_SpecCcsBuilder) (signal_index constraint_index: usize)
    : Core_models.Result.t_Result
      (Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
      t_SpecCcsSynthesisError =
  match
    Core_models.Option.impl_2__copied #usize
      (Core_models.Slice.impl__get #usize
          #usize
          (Alloc.Vec.impl_1__as_slice builder.f_signal_columns <: t_Slice usize)
          signal_index
        <:
        Core_models.Option.t_Option usize)
    <:
    Core_models.Option.t_Option usize
  with
  | Core_models.Option.Option_Some col ->
    Core_models.Result.Result_Ok (lc_var col)
    <:
    Core_models.Result.t_Result
      (Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
      t_SpecCcsSynthesisError
  | _ ->
    Core_models.Result.Result_Err
    ({
        f_constraint_index = constraint_index;
        f_kind = SpecCcsSynthesisErrorKind_InvalidSignalIndex <: t_SpecCcsSynthesisErrorKind
      }
      <:
      t_SpecCcsSynthesisError)
    <:
    Core_models.Result.t_Result
      (Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
      t_SpecCcsSynthesisError

let lc_one (_: Prims.unit)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  lc_const (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt
        #FStar.Tactics.Typeclasses.solve
        ()
      <:
      Num_bigint.Bigint.t_BigInt)

let lc_one_minus_var (col: usize)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    lc_one ()
  in
  let expr:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    lc_add_term expr
      col
      (Core_models.Ops.Arith.f_neg #Num_bigint.Bigint.t_BigInt
          #FStar.Tactics.Typeclasses.solve
          (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt
              #FStar.Tactics.Typeclasses.solve
              ()
            <:
            Num_bigint.Bigint.t_BigInt)
        <:
        Num_bigint.Bigint.t_BigInt)
  in
  expr

let lc_add_assign
      (target other:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Collections.Btree.Map.t_BTreeMap
              usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          other
        <:
        Alloc.Collections.Btree.Map.t_Iter usize Num_bigint.Bigint.t_BigInt)
      target
      (fun target temp_1_ ->
          let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global =
            target
          in
          let (col: usize), (coeff: Num_bigint.Bigint.t_BigInt) = temp_1_ in
          lc_add_term target
            col
            (Core_models.Clone.f_clone #Num_bigint.Bigint.t_BigInt
                #FStar.Tactics.Typeclasses.solve
                coeff
              <:
              Num_bigint.Bigint.t_BigInt)
          <:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
  in
  target

let lc_sub_assign
      (target other:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
    : Alloc.Collections.Btree.Map.t_BTreeMap usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global =
  let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
    Num_bigint.Bigint.t_BigInt
    Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Collections.Btree.Map.t_BTreeMap
              usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          other
        <:
        Alloc.Collections.Btree.Map.t_Iter usize Num_bigint.Bigint.t_BigInt)
      target
      (fun target temp_1_ ->
          let target:Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global =
            target
          in
          let (col: usize), (coeff: Num_bigint.Bigint.t_BigInt) = temp_1_ in
          lc_add_term target
            col
            (Core_models.Ops.Arith.f_neg #Num_bigint.Bigint.t_BigInt
                #FStar.Tactics.Typeclasses.solve
                (Core_models.Clone.f_clone #Num_bigint.Bigint.t_BigInt
                    #FStar.Tactics.Typeclasses.solve
                    coeff
                  <:
                  Num_bigint.Bigint.t_BigInt)
              <:
              Num_bigint.Bigint.t_BigInt)
          <:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
  in
  target

let push_lc_entries
      (field: Zkf_core.Field.t_FieldId)
      (entries: Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global)
      (row: usize)
      (lc:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global =
  let entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Collections.Btree.Map.t_BTreeMap
              usize Num_bigint.Bigint.t_BigInt Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          lc
        <:
        Alloc.Collections.Btree.Map.t_Iter usize Num_bigint.Bigint.t_BigInt)
      entries
      (fun entries temp_1_ ->
          let entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global = entries in
          let (col: usize), (coeff: Num_bigint.Bigint.t_BigInt) = temp_1_ in
          let normalized:Num_bigint.Bigint.t_BigInt =
            Zkf_core.Field.normalize_mod (Core_models.Clone.f_clone #Num_bigint.Bigint.t_BigInt
                  #FStar.Tactics.Typeclasses.solve
                  coeff
                <:
                Num_bigint.Bigint.t_BigInt)
              (Zkf_core.Field.impl_FieldId__modulus field <: Num_bigint.Bigint.t_BigInt)
          in
          if
            ~.(Num_traits.Identities.f_is_zero #Num_bigint.Bigint.t_BigInt
                #FStar.Tactics.Typeclasses.solve
                normalized
              <:
              bool)
          then
            let entries:Alloc.Vec.t_Vec t_SpecCcsMatrixEntry Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #t_SpecCcsMatrixEntry
                #Alloc.Alloc.t_Global
                entries
                ({
                    f_row = row;
                    f_col = col;
                    f_value
                    =
                    bigint_to_spec_value normalized field
                    <:
                    Zkf_core.Proof_kernel_spec.t_SpecFieldValue
                  }
                  <:
                  t_SpecCcsMatrixEntry)
            in
            entries
          else entries)
  in
  entries

let builder_add_row
      (builder: t_SpecCcsBuilder)
      (a b c:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global)
    : t_SpecCcsBuilder =
  let row:usize = builder.f_row in
  let builder:t_SpecCcsBuilder =
    { builder with f_a_entries = push_lc_entries builder.f_field builder.f_a_entries row a }
    <:
    t_SpecCcsBuilder
  in
  let builder:t_SpecCcsBuilder =
    { builder with f_b_entries = push_lc_entries builder.f_field builder.f_b_entries row b }
    <:
    t_SpecCcsBuilder
  in
  let builder:t_SpecCcsBuilder =
    { builder with f_c_entries = push_lc_entries builder.f_field builder.f_c_entries row c }
    <:
    t_SpecCcsBuilder
  in
  let builder:t_SpecCcsBuilder =
    { builder with f_row = builder.f_row +! mk_usize 1 } <: t_SpecCcsBuilder
  in
  builder

type t_SpecCcsExpr =
  | SpecCcsExpr_Const : Zkf_core.Proof_kernel_spec.t_SpecFieldValue -> t_SpecCcsExpr
  | SpecCcsExpr_Signal : usize -> t_SpecCcsExpr
  | SpecCcsExpr_Add : Alloc.Vec.t_Vec t_SpecCcsExpr Alloc.Alloc.t_Global -> t_SpecCcsExpr
  | SpecCcsExpr_Sub : t_SpecCcsExpr -> t_SpecCcsExpr -> t_SpecCcsExpr
  | SpecCcsExpr_Mul : t_SpecCcsExpr -> t_SpecCcsExpr -> t_SpecCcsExpr
  | SpecCcsExpr_Div : t_SpecCcsExpr -> t_SpecCcsExpr -> t_SpecCcsExpr

type t_SpecCcsConstraint =
  | SpecCcsConstraint_Equal {
    f_lhs:t_SpecCcsExpr;
    f_rhs:t_SpecCcsExpr
  }: t_SpecCcsConstraint
  | SpecCcsConstraint_Boolean { f_signal_index:usize }: t_SpecCcsConstraint
  | SpecCcsConstraint_Range {
    f_signal_index:usize;
    f_bits:u32
  }: t_SpecCcsConstraint
  | SpecCcsConstraint_Lookup : t_SpecCcsConstraint
  | SpecCcsConstraint_BlackBox { f_kind:t_SpecCcsBlackBoxKind }: t_SpecCcsConstraint

type t_SpecCcsConstraintProgram = {
  f_field:Zkf_core.Field.t_FieldId;
  f_signals:Alloc.Vec.t_Vec t_SpecCcsSignal Alloc.Alloc.t_Global;
  f_constraints:Alloc.Vec.t_Vec t_SpecCcsConstraint Alloc.Alloc.t_Global
}

let builder_new (program: t_SpecCcsConstraintProgram) : t_SpecCcsBuilder =
  let signal_columns:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #usize
      (mk_usize 0)
      (Alloc.Vec.impl_1__len #t_SpecCcsSignal #Alloc.Alloc.t_Global program.f_signals <: usize)
  in
  let next_col:usize = mk_usize 1 in
  let num_public:usize = mk_usize 0 in
  let
  (next_col: usize),
  (num_public: usize),
  (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_enumerated_slice (Alloc.Vec.impl_1__as_slice program.f_signals
        <:
        t_Slice t_SpecCcsSignal)
      (fun temp_0_ temp_1_ ->
          let
          (next_col: usize),
          (num_public: usize),
          (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          true)
      (next_col, num_public, signal_columns
        <:
        (usize & usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global))
      (fun temp_0_ temp_1_ ->
          let
          (next_col: usize),
          (num_public: usize),
          (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
            temp_0_
          in
          let (signal_index: usize), (signal: t_SpecCcsSignal) = temp_1_ in
          if signal.f_visibility =. (SpecCcsVisibility_Public <: t_SpecCcsVisibility) <: bool
          then
            let signal_columns:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global =
              Alloc.Slice.impl__to_vec (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (
                      Alloc.Vec.impl_1__as_slice signal_columns <: t_Slice usize)
                    signal_index
                    next_col
                  <:
                  t_Slice usize)
            in
            let next_col:usize = next_col +! mk_usize 1 in
            let num_public:usize = num_public +! mk_usize 1 in
            next_col, num_public, signal_columns
            <:
            (usize & usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global)
          else
            next_col, num_public, signal_columns
            <:
            (usize & usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global))
  in
  let (next_col: usize), (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_enumerated_slice (Alloc.Vec.impl_1__as_slice program.f_signals
        <:
        t_Slice t_SpecCcsSignal)
      (fun temp_0_ temp_1_ ->
          let (next_col: usize), (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          true)
      (next_col, signal_columns <: (usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global))
      (fun temp_0_ temp_1_ ->
          let (next_col: usize), (signal_columns: Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global) =
            temp_0_
          in
          let (signal_index: usize), (signal: t_SpecCcsSignal) = temp_1_ in
          if signal.f_visibility <>. (SpecCcsVisibility_Public <: t_SpecCcsVisibility) <: bool
          then
            let signal_columns:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global =
              Alloc.Slice.impl__to_vec (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (
                      Alloc.Vec.impl_1__as_slice signal_columns <: t_Slice usize)
                    signal_index
                    next_col
                  <:
                  t_Slice usize)
            in
            let next_col:usize = next_col +! mk_usize 1 in
            next_col, signal_columns <: (usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global)
          else next_col, signal_columns <: (usize & Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global))
  in
  {
    f_field = program.f_field;
    f_signal_columns = signal_columns;
    f_next_col = next_col;
    f_num_public = num_public;
    f_row = mk_usize 0;
    f_a_entries = Alloc.Vec.impl__new #t_SpecCcsMatrixEntry ();
    f_b_entries = Alloc.Vec.impl__new #t_SpecCcsMatrixEntry ();
    f_c_entries = Alloc.Vec.impl__new #t_SpecCcsMatrixEntry ()
  }
  <:
  t_SpecCcsBuilder

let rec builder_expr_to_lc (builder: t_SpecCcsBuilder) (expr: t_SpecCcsExpr) (constraint_index: usize)
    : (t_SpecCcsBuilder &
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
  match expr <: t_SpecCcsExpr with
  | SpecCcsExpr_Const value ->
    builder,
    (Core_models.Result.Result_Ok
      (lc_const (spec_value_to_bigint value builder.f_field <: Num_bigint.Bigint.t_BigInt))
      <:
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
    <:
    (t_SpecCcsBuilder &
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
  | SpecCcsExpr_Signal signal_index ->
    builder, builder_signal_lc builder signal_index constraint_index
    <:
    (t_SpecCcsBuilder &
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
  | SpecCcsExpr_Add terms ->
    let acc:Alloc.Collections.Btree.Map.t_BTreeMap usize
      Num_bigint.Bigint.t_BigInt
      Alloc.Alloc.t_Global =
      Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
    in
    (match
        Rust_primitives.Hax.Folds.fold_return (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                  t_SpecCcsExpr Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              terms
            <:
            Core_models.Slice.Iter.t_Iter t_SpecCcsExpr)
          (acc, builder
            <:
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global &
              t_SpecCcsBuilder))
          (fun temp_0_ term ->
              let
              (acc:
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global),
              (builder: t_SpecCcsBuilder) =
                temp_0_
              in
              let term:t_SpecCcsExpr = term in
              let
              (tmp0: t_SpecCcsBuilder),
              (out:
                Core_models.Result.t_Result
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
                builder_expr_to_lc builder term constraint_index
              in
              let builder:t_SpecCcsBuilder = tmp0 in
              match
                out
                <:
                Core_models.Result.t_Result
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
              with
              | Core_models.Result.Result_Ok hoist2 ->
                Core_models.Ops.Control_flow.ControlFlow_Continue
                (lc_add_assign acc hoist2, builder
                  <:
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global &
                    t_SpecCcsBuilder))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (t_SpecCcsBuilder &
                        Core_models.Result.t_Result
                          (Alloc.Collections.Btree.Map.t_BTreeMap usize
                              Num_bigint.Bigint.t_BigInt
                              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
                      (Prims.unit &
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global &
                          t_SpecCcsBuilder)))
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global &
                    t_SpecCcsBuilder)
              | Core_models.Result.Result_Err err ->
                Core_models.Ops.Control_flow.ControlFlow_Break
                (Core_models.Ops.Control_flow.ControlFlow_Break
                  (builder,
                    (Core_models.Result.Result_Err err
                      <:
                      Core_models.Result.t_Result
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
                    <:
                    (t_SpecCcsBuilder &
                      Core_models.Result.t_Result
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
                  <:
                  Core_models.Ops.Control_flow.t_ControlFlow
                    (t_SpecCcsBuilder &
                      Core_models.Result.t_Result
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
                    (Prims.unit &
                      (Alloc.Collections.Btree.Map.t_BTreeMap usize
                          Num_bigint.Bigint.t_BigInt
                          Alloc.Alloc.t_Global &
                        t_SpecCcsBuilder)))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (t_SpecCcsBuilder &
                        Core_models.Result.t_Result
                          (Alloc.Collections.Btree.Map.t_BTreeMap usize
                              Num_bigint.Bigint.t_BigInt
                              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
                      (Prims.unit &
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global &
                          t_SpecCcsBuilder)))
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global &
                    t_SpecCcsBuilder))
        <:
        Core_models.Ops.Control_flow.t_ControlFlow
          (t_SpecCcsBuilder &
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global &
            t_SpecCcsBuilder)
      with
      | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core_models.Ops.Control_flow.ControlFlow_Continue (acc, builder) ->
        builder,
        (Core_models.Result.Result_Ok acc
          <:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder &
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
  | SpecCcsExpr_Sub lhs rhs ->
    let
    (tmp0: t_SpecCcsBuilder),
    (out:
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
      builder_expr_to_lc builder lhs constraint_index
    in
    let builder:t_SpecCcsBuilder = tmp0 in
    (match
        out
        <:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
      with
      | Core_models.Result.Result_Ok acc ->
        let
        (tmp0: t_SpecCcsBuilder),
        (out:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
          builder_expr_to_lc builder rhs constraint_index
        in
        let builder:t_SpecCcsBuilder = tmp0 in
        (match
            out
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
          with
          | Core_models.Result.Result_Ok hoist6 ->
            let acc:Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global =
              lc_sub_assign acc hoist6
            in
            builder,
            (Core_models.Result.Result_Ok acc
              <:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder &
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
          | Core_models.Result.Result_Err err ->
            builder,
            (Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder &
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
      | Core_models.Result.Result_Err err ->
        builder,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder &
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
  | SpecCcsExpr_Mul lhs rhs ->
    let
    (tmp0: t_SpecCcsBuilder),
    (out:
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
      builder_expr_to_lc builder lhs constraint_index
    in
    let builder:t_SpecCcsBuilder = tmp0 in
    (match
        out
        <:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
      with
      | Core_models.Result.Result_Ok lhs_lc ->
        let
        (tmp0: t_SpecCcsBuilder),
        (out:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
          builder_expr_to_lc builder rhs constraint_index
        in
        let builder:t_SpecCcsBuilder = tmp0 in
        (match
            out
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
          with
          | Core_models.Result.Result_Ok rhs_lc ->
            let (tmp0: t_SpecCcsBuilder), (out: usize) = builder_allocate_aux builder in
            let builder:t_SpecCcsBuilder = tmp0 in
            let aux_col:usize = out in
            let builder:t_SpecCcsBuilder =
              builder_add_row builder
                lhs_lc
                rhs_lc
                (lc_var aux_col
                  <:
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global)
            in
            builder,
            (Core_models.Result.Result_Ok (lc_var aux_col)
              <:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder &
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
          | Core_models.Result.Result_Err err ->
            builder,
            (Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder &
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
      | Core_models.Result.Result_Err err ->
        builder,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder &
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
  | SpecCcsExpr_Div lhs rhs ->
    let
    (tmp0: t_SpecCcsBuilder),
    (out:
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
      builder_expr_to_lc builder lhs constraint_index
    in
    let builder:t_SpecCcsBuilder = tmp0 in
    match
      out
      <:
      Core_models.Result.t_Result
        (Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
    with
    | Core_models.Result.Result_Ok numerator ->
      let
      (tmp0: t_SpecCcsBuilder),
      (out:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
        builder_expr_to_lc builder rhs constraint_index
      in
      let builder:t_SpecCcsBuilder = tmp0 in
      (match
          out
          <:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
        with
        | Core_models.Result.Result_Ok denominator ->
          let (tmp0: t_SpecCcsBuilder), (out: usize) = builder_allocate_aux builder in
          let builder:t_SpecCcsBuilder = tmp0 in
          let quotient_col:usize = out in
          let (tmp0: t_SpecCcsBuilder), (out: usize) = builder_allocate_aux builder in
          let builder:t_SpecCcsBuilder = tmp0 in
          let inverse_col:usize = out in
          let builder:t_SpecCcsBuilder =
            builder_add_row builder
              (Core_models.Clone.f_clone #(Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  denominator
                <:
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global)
              (lc_var inverse_col
                <:
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global)
              (lc_one ()
                <:
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global)
          in
          let builder:t_SpecCcsBuilder =
            builder_add_row builder
              (lc_var quotient_col
                <:
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global)
              denominator
              numerator
          in
          builder,
          (Core_models.Result.Result_Ok (lc_var quotient_col)
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
          <:
          (t_SpecCcsBuilder &
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
        | Core_models.Result.Result_Err err ->
          builder,
          (Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
          <:
          (t_SpecCcsBuilder &
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError))
    | Core_models.Result.Result_Err err ->
      builder,
      (Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)
      <:
      (t_SpecCcsBuilder &
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError)

let encode_constraint_runtime
      (builder: t_SpecCcsBuilder)
      (constraint: t_SpecCcsConstraint)
      (constraint_index: usize)
    : (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError) =
  match constraint <: t_SpecCcsConstraint with
  | SpecCcsConstraint_Equal { f_lhs = lhs ; f_rhs = rhs } ->
    (match lhs <: t_SpecCcsExpr with
      | SpecCcsExpr_Mul left right ->
        let
        (tmp0: t_SpecCcsBuilder),
        (out:
          Core_models.Result.t_Result
            (Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
          builder_expr_to_lc builder left constraint_index
        in
        let builder:t_SpecCcsBuilder = tmp0 in
        (match
            out
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
          with
          | Core_models.Result.Result_Ok a ->
            let
            (tmp0: t_SpecCcsBuilder),
            (out:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
              builder_expr_to_lc builder right constraint_index
            in
            let builder:t_SpecCcsBuilder = tmp0 in
            (match
                out
                <:
                Core_models.Result.t_Result
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
              with
              | Core_models.Result.Result_Ok b ->
                let
                (tmp0: t_SpecCcsBuilder),
                (out:
                  Core_models.Result.t_Result
                    (Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
                  builder_expr_to_lc builder rhs constraint_index
                in
                let builder:t_SpecCcsBuilder = tmp0 in
                (match
                    out
                    <:
                    Core_models.Result.t_Result
                      (Alloc.Collections.Btree.Map.t_BTreeMap usize
                          Num_bigint.Bigint.t_BigInt
                          Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
                  with
                  | Core_models.Result.Result_Ok c ->
                    let builder:t_SpecCcsBuilder = builder_add_row builder a b c in
                    builder,
                    (Core_models.Result.Result_Ok (() <: Prims.unit)
                      <:
                      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                    <:
                    (t_SpecCcsBuilder &
                      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                  | Core_models.Result.Result_Err err ->
                    builder,
                    (Core_models.Result.Result_Err err
                      <:
                      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                    <:
                    (t_SpecCcsBuilder &
                      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
              | Core_models.Result.Result_Err err ->
                builder,
                (Core_models.Result.Result_Err err
                  <:
                  Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                <:
                (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
          | Core_models.Result.Result_Err err ->
            builder,
            (Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
      | _ ->
        match rhs <: t_SpecCcsExpr with
        | SpecCcsExpr_Mul left right ->
          let
          (tmp0: t_SpecCcsBuilder),
          (out:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
            builder_expr_to_lc builder left constraint_index
          in
          let builder:t_SpecCcsBuilder = tmp0 in
          (match
              out
              <:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
            with
            | Core_models.Result.Result_Ok a ->
              let
              (tmp0: t_SpecCcsBuilder),
              (out:
                Core_models.Result.t_Result
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
                builder_expr_to_lc builder right constraint_index
              in
              let builder:t_SpecCcsBuilder = tmp0 in
              (match
                  out
                  <:
                  Core_models.Result.t_Result
                    (Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
                with
                | Core_models.Result.Result_Ok b ->
                  let
                  (tmp0: t_SpecCcsBuilder),
                  (out:
                    Core_models.Result.t_Result
                      (Alloc.Collections.Btree.Map.t_BTreeMap usize
                          Num_bigint.Bigint.t_BigInt
                          Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
                    builder_expr_to_lc builder lhs constraint_index
                  in
                  let builder:t_SpecCcsBuilder = tmp0 in
                  (match
                      out
                      <:
                      Core_models.Result.t_Result
                        (Alloc.Collections.Btree.Map.t_BTreeMap usize
                            Num_bigint.Bigint.t_BigInt
                            Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
                    with
                    | Core_models.Result.Result_Ok c ->
                      let builder:t_SpecCcsBuilder = builder_add_row builder a b c in
                      builder,
                      (Core_models.Result.Result_Ok (() <: Prims.unit)
                        <:
                        Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                      <:
                      (t_SpecCcsBuilder &
                        Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                    | Core_models.Result.Result_Err err ->
                      builder,
                      (Core_models.Result.Result_Err err
                        <:
                        Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                      <:
                      (t_SpecCcsBuilder &
                        Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
                | Core_models.Result.Result_Err err ->
                  builder,
                  (Core_models.Result.Result_Err err
                    <:
                    Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                  <:
                  (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError
                  ))
            | Core_models.Result.Result_Err err ->
              builder,
              (Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
              <:
              (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
        | _ ->
          let
          (tmp0: t_SpecCcsBuilder),
          (out:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
            builder_expr_to_lc builder lhs constraint_index
          in
          let builder:t_SpecCcsBuilder = tmp0 in
          match
            out
            <:
            Core_models.Result.t_Result
              (Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
          with
          | Core_models.Result.Result_Ok lhs_lc ->
            let
            (tmp0: t_SpecCcsBuilder),
            (out:
              Core_models.Result.t_Result
                (Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) t_SpecCcsSynthesisError) =
              builder_expr_to_lc builder rhs constraint_index
            in
            let builder:t_SpecCcsBuilder = tmp0 in
            (match
                out
                <:
                Core_models.Result.t_Result
                  (Alloc.Collections.Btree.Map.t_BTreeMap usize
                      Num_bigint.Bigint.t_BigInt
                      Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
              with
              | Core_models.Result.Result_Ok rhs_lc ->
                let diff:Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global =
                  lhs_lc
                in
                let diff:Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global =
                  lc_sub_assign diff rhs_lc
                in
                let builder:t_SpecCcsBuilder =
                  builder_add_row builder
                    diff
                    (lc_one ()
                      <:
                      Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global)
                    (Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
                      <:
                      Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global)
                in
                builder,
                (Core_models.Result.Result_Ok (() <: Prims.unit)
                  <:
                  Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                <:
                (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
              | Core_models.Result.Result_Err err ->
                builder,
                (Core_models.Result.Result_Err err
                  <:
                  Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
                <:
                (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
          | Core_models.Result.Result_Err err ->
            builder,
            (Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
  | SpecCcsConstraint_Boolean { f_signal_index = signal_index } ->
    (match
        builder_signal_lc builder signal_index constraint_index
        <:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
      with
      | Core_models.Result.Result_Ok value ->
        (match
            Core_models.Option.impl__ok_or #usize
              #t_SpecCcsSynthesisError
              (Core_models.Option.impl_2__copied #usize
                  (Core_models.Slice.impl__get #usize
                      #usize
                      (Alloc.Vec.impl_1__as_slice builder.f_signal_columns <: t_Slice usize)
                      signal_index
                    <:
                    Core_models.Option.t_Option usize)
                <:
                Core_models.Option.t_Option usize)
              ({
                  f_constraint_index = constraint_index;
                  f_kind
                  =
                  SpecCcsSynthesisErrorKind_InvalidSignalIndex <: t_SpecCcsSynthesisErrorKind
                }
                <:
                t_SpecCcsSynthesisError)
            <:
            Core_models.Result.t_Result usize t_SpecCcsSynthesisError
          with
          | Core_models.Result.Result_Ok col ->
            let builder:t_SpecCcsBuilder =
              builder_add_row builder
                value
                (lc_one_minus_var col
                  <:
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global)
                (Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
                  <:
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global)
            in
            builder,
            (Core_models.Result.Result_Ok (() <: Prims.unit)
              <:
              Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
          | Core_models.Result.Result_Err err ->
            builder,
            (Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
            <:
            (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
      | Core_models.Result.Result_Err err ->
        builder,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
  | SpecCcsConstraint_Range { f_signal_index = signal_index ; f_bits = bits } ->
    (match
        builder_signal_lc builder signal_index constraint_index
        <:
        Core_models.Result.t_Result
          (Alloc.Collections.Btree.Map.t_BTreeMap usize
              Num_bigint.Bigint.t_BigInt
              Alloc.Alloc.t_Global) t_SpecCcsSynthesisError
      with
      | Core_models.Result.Result_Ok signal_value ->
        let recomposed:Alloc.Collections.Btree.Map.t_BTreeMap usize
          Num_bigint.Bigint.t_BigInt
          Alloc.Alloc.t_Global =
          Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
        in
        let
        (builder: t_SpecCcsBuilder),
        (recomposed:
          Alloc.Collections.Btree.Map.t_BTreeMap usize
            Num_bigint.Bigint.t_BigInt
            Alloc.Alloc.t_Global) =
          Rust_primitives.Hax.Folds.fold_range (mk_u32 0)
            bits
            (fun temp_0_ temp_1_ ->
                let
                (builder: t_SpecCcsBuilder),
                (recomposed:
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) =
                  temp_0_
                in
                let _:u32 = temp_1_ in
                true)
            (builder, recomposed
              <:
              (t_SpecCcsBuilder &
                Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global))
            (fun temp_0_ bit ->
                let
                (builder: t_SpecCcsBuilder),
                (recomposed:
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global) =
                  temp_0_
                in
                let bit:u32 = bit in
                let (tmp0: t_SpecCcsBuilder), (out: usize) = builder_allocate_aux builder in
                let builder:t_SpecCcsBuilder = tmp0 in
                let bit_col:usize = out in
                let builder:t_SpecCcsBuilder =
                  builder_add_row builder
                    (lc_var bit_col
                      <:
                      Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global)
                    (lc_one_minus_var bit_col
                      <:
                      Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global)
                    (Alloc.Collections.Btree.Map.impl_18__new #usize #Num_bigint.Bigint.t_BigInt ()
                      <:
                      Alloc.Collections.Btree.Map.t_BTreeMap usize
                        Num_bigint.Bigint.t_BigInt
                        Alloc.Alloc.t_Global)
                in
                let recomposed:Alloc.Collections.Btree.Map.t_BTreeMap usize
                  Num_bigint.Bigint.t_BigInt
                  Alloc.Alloc.t_Global =
                  lc_add_term recomposed
                    bit_col
                    (Core_models.Ops.Bit.f_shl #Num_bigint.Bigint.t_BigInt
                        #usize
                        #FStar.Tactics.Typeclasses.solve
                        (Num_traits.Identities.f_one #Num_bigint.Bigint.t_BigInt
                            #FStar.Tactics.Typeclasses.solve
                            ()
                          <:
                          Num_bigint.Bigint.t_BigInt)
                        (Core_models.Result.impl__unwrap_or #usize
                            #Core_models.Num.Error.t_TryFromIntError
                            (Core_models.Convert.f_try_from #usize
                                #u32
                                #FStar.Tactics.Typeclasses.solve
                                bit
                              <:
                              Core_models.Result.t_Result usize
                                Core_models.Num.Error.t_TryFromIntError)
                            (mk_usize 0)
                          <:
                          usize)
                      <:
                      Num_bigint.Bigint.t_BigInt)
                in
                builder, recomposed
                <:
                (t_SpecCcsBuilder &
                  Alloc.Collections.Btree.Map.t_BTreeMap usize
                    Num_bigint.Bigint.t_BigInt
                    Alloc.Alloc.t_Global))
        in
        let builder:t_SpecCcsBuilder =
          builder_add_row builder
            signal_value
            (lc_one ()
              <:
              Alloc.Collections.Btree.Map.t_BTreeMap usize
                Num_bigint.Bigint.t_BigInt
                Alloc.Alloc.t_Global)
            recomposed
        in
        builder,
        (Core_models.Result.Result_Ok (() <: Prims.unit)
          <:
          Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
      | Core_models.Result.Result_Err err ->
        builder,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
        <:
        (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError))
  | SpecCcsConstraint_Lookup  ->
    builder,
    (Core_models.Result.Result_Err
      ({
          f_constraint_index = constraint_index;
          f_kind = SpecCcsSynthesisErrorKind_LookupRequiresLowering <: t_SpecCcsSynthesisErrorKind
        }
        <:
        t_SpecCcsSynthesisError)
      <:
      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
    <:
    (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
  | SpecCcsConstraint_BlackBox { f_kind = SpecCcsBlackBoxKind_RecursiveAggregationMarker  } ->
    builder,
    (Core_models.Result.Result_Ok (() <: Prims.unit)
      <:
      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
    <:
    (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
  | SpecCcsConstraint_BlackBox {  } ->
    builder,
    (Core_models.Result.Result_Err
      ({
          f_constraint_index = constraint_index;
          f_kind = SpecCcsSynthesisErrorKind_BlackBoxRequiresLowering <: t_SpecCcsSynthesisErrorKind
        }
        <:
        t_SpecCcsSynthesisError)
      <:
      Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)
    <:
    (t_SpecCcsBuilder & Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError)

let synthesize_constraints_from
      (builder: t_SpecCcsBuilder)
      (constraints: t_Slice t_SpecCcsConstraint)
      (constraint_index: usize)
    : Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError =
  match
    Rust_primitives.Hax.Folds.fold_enumerated_slice_return constraints
      (fun builder temp_1_ ->
          let builder:t_SpecCcsBuilder = builder in
          let _:usize = temp_1_ in
          true)
      builder
      (fun builder temp_1_ ->
          let builder:t_SpecCcsBuilder = builder in
          let (offset: usize), (constraint: t_SpecCcsConstraint) = temp_1_ in
          let current_index:usize =
            Core_models.Num.impl_usize__saturating_add constraint_index offset
          in
          let
          (tmp0: t_SpecCcsBuilder),
          (out: Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError) =
            encode_constraint_runtime builder constraint current_index
          in
          let builder:t_SpecCcsBuilder = tmp0 in
          match out <: Core_models.Result.t_Result Prims.unit t_SpecCcsSynthesisError with
          | Core_models.Result.Result_Ok _ ->
            Core_models.Ops.Control_flow.ControlFlow_Continue builder
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError)
                  (Prims.unit & t_SpecCcsBuilder)) t_SpecCcsBuilder
          | Core_models.Result.Result_Err err ->
            Core_models.Ops.Control_flow.ControlFlow_Break
            (Core_models.Ops.Control_flow.ControlFlow_Break
              (Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError)
              <:
              Core_models.Ops.Control_flow.t_ControlFlow
                (Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError)
                (Prims.unit & t_SpecCcsBuilder))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError)
                  (Prims.unit & t_SpecCcsBuilder)) t_SpecCcsBuilder)
    <:
    Core_models.Ops.Control_flow.t_ControlFlow
      (Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError) t_SpecCcsBuilder
  with
  | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
  | Core_models.Ops.Control_flow.ControlFlow_Continue builder ->
    Core_models.Result.Result_Ok builder
    <:
    Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError

let synthesize_ccs_program (program: t_SpecCcsConstraintProgram)
    : Core_models.Result.t_Result t_SpecCcsProgram t_SpecCcsSynthesisError =
  let builder:t_SpecCcsBuilder = builder_new program in
  match
    synthesize_constraints_from builder
      (Alloc.Vec.impl_1__as_slice program.f_constraints <: t_Slice t_SpecCcsConstraint)
      (mk_usize 0)
    <:
    Core_models.Result.t_Result t_SpecCcsBuilder t_SpecCcsSynthesisError
  with
  | Core_models.Result.Result_Ok builder ->
    Core_models.Result.Result_Ok (builder_finish builder program.f_field)
    <:
    Core_models.Result.t_Result t_SpecCcsProgram t_SpecCcsSynthesisError
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err error
    <:
    Core_models.Result.t_Result t_SpecCcsProgram t_SpecCcsSynthesisError
