module ConstantTimeProofs

#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"

open Zkf_core.Proof_constant_time_spec

let rec eval_expr_constant_time_trace_shape_only
  (expr:t_CtExpr)
  (witness:t_CtWitnessMask)
  (field:t_CtFieldMarker)
  : Lemma (ensures eval_expr_constant_time_trace expr witness field == structural_trace expr)
  =
  match expr with
  | CtExpr_Const ->
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)
  | CtExpr_Signal ->
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)
  | CtExpr_Add lhs rhs ->
    eval_expr_constant_time_trace_shape_only lhs witness field;
    eval_expr_constant_time_trace_shape_only rhs witness field;
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)
  | CtExpr_Sub lhs rhs ->
    eval_expr_constant_time_trace_shape_only lhs witness field;
    eval_expr_constant_time_trace_shape_only rhs witness field;
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)
  | CtExpr_Mul lhs rhs ->
    eval_expr_constant_time_trace_shape_only lhs witness field;
    eval_expr_constant_time_trace_shape_only rhs witness field;
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)
  | CtExpr_Div lhs rhs ->
    eval_expr_constant_time_trace_shape_only lhs witness field;
    eval_expr_constant_time_trace_shape_only rhs witness field;
    assert_norm (eval_expr_constant_time_trace expr witness field == structural_trace expr)

let eval_expr_constant_time_secret_independence
  (expr:t_CtExpr)
  (witness_a:t_CtWitnessMask)
  (witness_b:t_CtWitnessMask)
  (field_a:t_CtFieldMarker)
  (field_b:t_CtFieldMarker)
  : Lemma
      (ensures
        eval_expr_constant_time_trace expr witness_a field_a ==
        eval_expr_constant_time_trace expr witness_b field_b)
  =
  eval_expr_constant_time_trace_shape_only expr witness_a field_a;
  eval_expr_constant_time_trace_shape_only expr witness_b field_b;
  assert (
    eval_expr_constant_time_trace expr witness_a field_a == structural_trace expr
  );
  assert (
    eval_expr_constant_time_trace expr witness_b field_b == structural_trace expr
  )

let rec eval_expr_constant_time_reference_result_equivalence
  (expr:t_CtExpr)
  (witness:t_CtWitnessMask)
  (field:t_CtFieldMarker)
  : Lemma
      (ensures
        eval_expr_constant_time_result expr witness field ==
        eval_expr_reference_result expr witness field)
  =
  match expr with
  | CtExpr_Const ->
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
  | CtExpr_Signal ->
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
  | CtExpr_Add lhs rhs ->
    eval_expr_constant_time_reference_result_equivalence lhs witness field;
    eval_expr_constant_time_reference_result_equivalence rhs witness field;
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
  | CtExpr_Sub lhs rhs ->
    eval_expr_constant_time_reference_result_equivalence lhs witness field;
    eval_expr_constant_time_reference_result_equivalence rhs witness field;
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
  | CtExpr_Mul lhs rhs ->
    eval_expr_constant_time_reference_result_equivalence lhs witness field;
    eval_expr_constant_time_reference_result_equivalence rhs witness field;
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
  | CtExpr_Div lhs rhs ->
    eval_expr_constant_time_reference_result_equivalence lhs witness field;
    eval_expr_constant_time_reference_result_equivalence rhs witness field;
    assert_norm (
      eval_expr_constant_time_result expr witness field ==
      eval_expr_reference_result expr witness field
    )
