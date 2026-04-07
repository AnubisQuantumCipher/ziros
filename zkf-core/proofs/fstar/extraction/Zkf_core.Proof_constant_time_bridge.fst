module Zkf_core.Proof_constant_time_bridge

open Prims

type t_CtWitnessMask =
  | CtWitnessMask : t_CtWitnessMask

type t_CtFieldMarker =
  | CtFieldMarker_Primary : t_CtFieldMarker
  | CtFieldMarker_Secondary : t_CtFieldMarker

type t_CtExpr =
  | CtExpr_Const : t_CtExpr
  | CtExpr_Signal : t_CtExpr
  | CtExpr_Add : t_CtExpr -> t_CtExpr -> t_CtExpr
  | CtExpr_Sub : t_CtExpr -> t_CtExpr -> t_CtExpr
  | CtExpr_Mul : t_CtExpr -> t_CtExpr -> t_CtExpr
  | CtExpr_Div : t_CtExpr -> t_CtExpr -> t_CtExpr

type t_CtTrace =
  | CtTrace_Const : t_CtTrace
  | CtTrace_Signal : t_CtTrace
  | CtTrace_Add : t_CtTrace -> t_CtTrace -> t_CtTrace
  | CtTrace_Sub : t_CtTrace -> t_CtTrace -> t_CtTrace
  | CtTrace_Mul : t_CtTrace -> t_CtTrace -> t_CtTrace
  | CtTrace_Div : t_CtTrace -> t_CtTrace -> t_CtTrace

type t_CtEvalResult =
  | CtEvalResult_Const : t_CtEvalResult
  | CtEvalResult_Signal : t_CtEvalResult
  | CtEvalResult_Add : t_CtEvalResult -> t_CtEvalResult -> t_CtEvalResult
  | CtEvalResult_Sub : t_CtEvalResult -> t_CtEvalResult -> t_CtEvalResult
  | CtEvalResult_Mul : t_CtEvalResult -> t_CtEvalResult -> t_CtEvalResult
  | CtEvalResult_Div : t_CtEvalResult -> t_CtEvalResult -> t_CtEvalResult

let rec structural_trace (expr: t_CtExpr) : t_CtTrace =
  match expr <: t_CtExpr with
  | CtExpr_Const  -> CtTrace_Const <: t_CtTrace
  | CtExpr_Signal  -> CtTrace_Signal <: t_CtTrace
  | CtExpr_Add lhs rhs -> CtTrace_Add (structural_trace lhs) (structural_trace rhs) <: t_CtTrace
  | CtExpr_Sub lhs rhs -> CtTrace_Sub (structural_trace lhs) (structural_trace rhs) <: t_CtTrace
  | CtExpr_Mul lhs rhs -> CtTrace_Mul (structural_trace lhs) (structural_trace rhs) <: t_CtTrace
  | CtExpr_Div lhs rhs -> CtTrace_Div (structural_trace lhs) (structural_trace rhs) <: t_CtTrace

let rec eval_expr_reference_result
      (expr: t_CtExpr)
      (e_witness: t_CtWitnessMask)
      (e_field: t_CtFieldMarker)
    : t_CtEvalResult =
  match expr <: t_CtExpr with
  | CtExpr_Const  -> CtEvalResult_Const <: t_CtEvalResult
  | CtExpr_Signal  -> CtEvalResult_Signal <: t_CtEvalResult
  | CtExpr_Add lhs rhs ->
    CtEvalResult_Add (eval_expr_reference_result lhs e_witness e_field)
      (eval_expr_reference_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Sub lhs rhs ->
    CtEvalResult_Sub (eval_expr_reference_result lhs e_witness e_field)
      (eval_expr_reference_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Mul lhs rhs ->
    CtEvalResult_Mul (eval_expr_reference_result lhs e_witness e_field)
      (eval_expr_reference_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Div lhs rhs ->
    CtEvalResult_Div (eval_expr_reference_result lhs e_witness e_field)
      (eval_expr_reference_result rhs e_witness e_field)
      <: t_CtEvalResult

let rec eval_expr_constant_time_trace
      (expr: t_CtExpr)
      (e_witness: t_CtWitnessMask)
      (e_field: t_CtFieldMarker)
    : t_CtTrace =
  match expr <: t_CtExpr with
  | CtExpr_Const  -> CtTrace_Const <: t_CtTrace
  | CtExpr_Signal  -> CtTrace_Signal <: t_CtTrace
  | CtExpr_Add lhs rhs ->
    CtTrace_Add (eval_expr_constant_time_trace lhs e_witness e_field)
      (eval_expr_constant_time_trace rhs e_witness e_field)
      <: t_CtTrace
  | CtExpr_Sub lhs rhs ->
    CtTrace_Sub (eval_expr_constant_time_trace lhs e_witness e_field)
      (eval_expr_constant_time_trace rhs e_witness e_field)
      <: t_CtTrace
  | CtExpr_Mul lhs rhs ->
    CtTrace_Mul (eval_expr_constant_time_trace lhs e_witness e_field)
      (eval_expr_constant_time_trace rhs e_witness e_field)
      <: t_CtTrace
  | CtExpr_Div lhs rhs ->
    CtTrace_Div (eval_expr_constant_time_trace lhs e_witness e_field)
      (eval_expr_constant_time_trace rhs e_witness e_field)
      <: t_CtTrace

let rec eval_expr_constant_time_result
      (expr: t_CtExpr)
      (e_witness: t_CtWitnessMask)
      (e_field: t_CtFieldMarker)
    : t_CtEvalResult =
  match expr <: t_CtExpr with
  | CtExpr_Const  -> CtEvalResult_Const <: t_CtEvalResult
  | CtExpr_Signal  -> CtEvalResult_Signal <: t_CtEvalResult
  | CtExpr_Add lhs rhs ->
    CtEvalResult_Add (eval_expr_constant_time_result lhs e_witness e_field)
      (eval_expr_constant_time_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Sub lhs rhs ->
    CtEvalResult_Sub (eval_expr_constant_time_result lhs e_witness e_field)
      (eval_expr_constant_time_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Mul lhs rhs ->
    CtEvalResult_Mul (eval_expr_constant_time_result lhs e_witness e_field)
      (eval_expr_constant_time_result rhs e_witness e_field)
      <: t_CtEvalResult
  | CtExpr_Div lhs rhs ->
    CtEvalResult_Div (eval_expr_constant_time_result lhs e_witness e_field)
      (eval_expr_constant_time_result rhs e_witness e_field)
      <: t_CtEvalResult
