From Coq Require Import ZArith.
Require Import List.
Import List.ListNotations.
Open Scope Z_scope.

From Core Require Export Core.
From Core Require Import ControlFlow.

Inductive globality :=
| t_Global.

Definition t_Vec (t : Type) (_ : globality) : Type := list t.

Inductive t_Result (t : Type) (e : Type) : Type :=
| Result_Ok : t -> t_Result t e
| Result_Err : e -> t_Result t e.
Arguments Result_Ok {_} {_}.
Arguments Result_Err {_} {_}.

Definition usize_to_nat (value : t_usize) : nat :=
  N.to_nat (U64_f_v (usize_0 value)).

Definition usize_to_n (value : t_usize) : N :=
  U64_f_v (usize_0 value).

Definition n_to_usize (value : N) : t_usize :=
  Build_t_usize (Build_t_U64 value).

Axiom dropped_body : forall {a}, a.

Definition usize_eqb (lhs rhs : t_usize) : bool :=
  N.eqb (usize_to_n lhs) (usize_to_n rhs).

Definition usize_compare (lhs rhs : t_usize) : t_Ordering :=
  if N.ltb (usize_to_n lhs) (usize_to_n rhs) then Ordering_Less
  else if N.eqb (usize_to_n lhs) (usize_to_n rhs) then Ordering_Equal
  else Ordering_Greater.

Definition index_list_at_usize {a} (values : list a) (index : t_usize) : a :=
  match nth_error values (usize_to_nat index) with
  | Some value => value
  | None => dropped_body
  end.

Class t_SameAdd (a : Type) := {
  same_add : a -> a -> a;
}.

Class t_SameSub (a : Type) := {
  same_sub : a -> a -> a;
}.

Class t_SameMul (a : Type) := {
  same_mul : a -> a -> a;
}.

Class t_SameRem (a : Type) := {
  same_rem : a -> a -> a;
}.

Class t_SameBitAnd (a : Type) := {
  same_bitand : a -> a -> a;
}.

Class t_ShrOut64 (rhs : Type) := {
  same_shr_u64 : t_u64 -> rhs -> t_u64;
}.

#[global] Instance t_SameAdd_u64 : t_SameAdd t_u64 :=
  { same_add := fun lhs rhs => Build_t_u64 (Add_f_add (u64_0 lhs) (u64_0 rhs)) }.
#[global] Instance t_SameAdd_u32 : t_SameAdd t_u32 :=
  { same_add := fun lhs rhs => Build_t_u32 (Add_f_add (u32_0 lhs) (u32_0 rhs)) }.
#[global] Instance t_SameAdd_usize : t_SameAdd t_usize :=
  { same_add := fun lhs rhs => Build_t_usize (Add_f_add (usize_0 lhs) (usize_0 rhs)) }.

#[global] Instance t_SameSub_u64 : t_SameSub t_u64 :=
  { same_sub := fun lhs rhs => Build_t_u64 (Sub_f_sub (u64_0 lhs) (u64_0 rhs)) }.
#[global] Instance t_SameSub_u32 : t_SameSub t_u32 :=
  { same_sub := fun lhs rhs => Build_t_u32 (Sub_f_sub (u32_0 lhs) (u32_0 rhs)) }.
#[global] Instance t_SameSub_usize : t_SameSub t_usize :=
  { same_sub := fun lhs rhs => Build_t_usize (Sub_f_sub (usize_0 lhs) (usize_0 rhs)) }.

#[global] Instance t_SameMul_u64 : t_SameMul t_u64 :=
  { same_mul := fun lhs rhs => Build_t_u64 (Mul_f_mul (u64_0 lhs) (u64_0 rhs)) }.
#[global] Instance t_SameMul_u32 : t_SameMul t_u32 :=
  { same_mul := fun lhs rhs => Build_t_u32 (Mul_f_mul (u32_0 lhs) (u32_0 rhs)) }.
#[global] Instance t_SameMul_usize : t_SameMul t_usize :=
  { same_mul := fun lhs rhs => Build_t_usize (Mul_f_mul (usize_0 lhs) (usize_0 rhs)) }.

#[global] Instance t_SameRem_u64 : t_SameRem t_u64 :=
  { same_rem := fun lhs rhs => Build_t_u64 (Rem_f_rem (u64_0 lhs) (u64_0 rhs)) }.
#[global] Instance t_SameRem_u32 : t_SameRem t_u32 :=
  { same_rem := fun lhs rhs => Build_t_u32 (Rem_f_rem (u32_0 lhs) (u32_0 rhs)) }.
#[global] Instance t_SameRem_usize : t_SameRem t_usize :=
  { same_rem := fun lhs rhs => Build_t_usize (Rem_f_rem (usize_0 lhs) (usize_0 rhs)) }.

#[global] Instance t_SameBitAnd_u64 : t_SameBitAnd t_u64 :=
  { same_bitand := fun lhs rhs => Build_t_u64 (BitAnd_f_bitand (u64_0 lhs) (u64_0 rhs)) }.

#[global] Instance t_ShrOut64_u32 : t_ShrOut64 t_u32 :=
  { same_shr_u64 := fun lhs rhs => Build_t_u64 (Shr_f_shr (u64_0 lhs) (u32_0 rhs)) }.

#[global] Instance t_PartialEq_string : t_PartialEq t_String t_String :=
  {
    PartialEq_f_eq := String.eqb;
    PartialEq_f_ne := fun lhs rhs => negb (String.eqb lhs rhs);
  }.

#[global] Instance t_PartialEq_usize : t_PartialEq t_usize t_usize :=
  {
    PartialEq_f_eq := usize_eqb;
    PartialEq_f_ne := fun lhs rhs => negb (usize_eqb lhs rhs);
  }.

#[global] Instance t_PartialOrd_usize : t_PartialOrd t_usize t_usize :=
  {
    PartialOrd_f_partial_cmp := fun lhs rhs => Option_Some (usize_compare lhs rhs);
    PartialOrd_f_lt := fun lhs rhs => N.ltb (usize_to_n lhs) (usize_to_n rhs);
    PartialOrd_f_le := fun lhs rhs => N.leb (usize_to_n lhs) (usize_to_n rhs);
    PartialOrd_f_gt := fun lhs rhs => N.ltb (usize_to_n rhs) (usize_to_n lhs);
    PartialOrd_f_ge := fun lhs rhs => N.leb (usize_to_n rhs) (usize_to_n lhs);
  }.

#[global] Instance t_Index_list_usize {a} : t_Index (list a) t_usize :=
  {
    Index_f_Output := a;
    Index_f_index := fun self index => index_list_at_usize self index;
  }.

#[global] Instance t_Index_slice_usize {a} : t_Index (t_Slice a) t_usize :=
  {
    Index_f_Output := a;
    Index_f_index := fun self index => index_list_at_usize (Slice_f_v self) index;
  }.

Definition f_add {a} `{t_SameAdd a} (lhs : a) (rhs : a) : a := same_add lhs rhs.
Definition f_sub {a} `{t_SameSub a} (lhs : a) (rhs : a) : a := same_sub lhs rhs.
Definition f_mul {a} `{t_SameMul a} (lhs : a) (rhs : a) : a := same_mul lhs rhs.
Definition f_rem {a} `{t_SameRem a} (lhs : a) (rhs : a) : a := same_rem lhs rhs.
Definition f_bitand {a} `{t_SameBitAnd a} (lhs : a) (rhs : a) : a := same_bitand lhs rhs.
Definition f_shr {rhs} `{t_ShrOut64 rhs} (lhs : t_u64) (rhs_value : rhs) : t_u64 :=
  same_shr_u64 lhs rhs_value.

Notation f_eq := PartialEq_f_eq.
Notation f_ne := PartialEq_f_ne.
Notation f_lt := PartialOrd_f_lt.
Notation f_le := PartialOrd_f_le.
Notation f_ge := PartialOrd_f_ge.
Notation f_gt := PartialOrd_f_gt.

Definition f_index {a} (values : t_Slice a) (index : t_usize) : a :=
  index_list_at_usize (Slice_f_v values) index.

Definition f_not (value : bool) : bool := negb value.

Definition f_branch {a e} (value : t_Result a e) : t_ControlFlow a e :=
  match value with
  | Result_Ok inner => ControlFlow_Continue inner
  | Result_Err residual => ControlFlow_Break residual
  end.

Definition f_from_residual {a e} (residual : e) : t_Result a e :=
  Result_Err residual.

Definition impl_u64__MAX : t_u64 := (18446744073709551615 : t_u64).
Definition impl_u32__MAX : t_u32 := (4294967295 : t_u32).
Definition impl_usize__MAX : t_usize := (18446744073709551615 : t_usize).

Definition impl__new {a} (_ : unit) : t_Vec a t_Global := [].

Definition impl_1__len {a} (values : list a) : t_usize :=
  Z.of_nat (List.length values).

Definition impl__len {a} (values : t_Slice a) : t_usize :=
  Z.of_nat (List.length (Slice_f_v values)).

Definition impl__get {a} (values : t_Slice a) (index : t_usize) : t_Option a :=
  match nth_error (Slice_f_v values) (usize_to_nat index) with
  | Some value => Option_Some value
  | None => Option_None
  end.

Definition impl_1__is_empty {a} (values : list a) : bool :=
  match values with
  | [] => true
  | _ => false
  end.

Definition impl__is_empty {a} (values : t_Slice a) : bool :=
  impl_1__is_empty (Slice_f_v values).

Definition impl__split_first {a} (values : t_Slice a) : t_Option (a * t_Slice a) :=
  match Slice_f_v values with
  | [] => Option_None
  | value :: remaining_values => Option_Some (value, Build_t_Slice _ remaining_values)
  end.

Definition impl__iter {a} (values : t_Slice a) : list a :=
  Slice_f_v values.

Definition impl_2__cloned {a} (value : t_Option a) : t_Option a := value.

Definition impl_2__copied {a} (value : t_Option a) : t_Option a := value.

Definition impl__is_some {a} (value : t_Option a) : bool :=
  match value with
  | Option_Some _ => true
  | Option_None => false
  end.

Definition impl__is_none {a} (value : t_Option a) : bool :=
  negb (impl__is_some value).

Definition impl__unwrap_or_else {a} (value : t_Option a) (fallback : unit -> a) : a :=
  match value with
  | Option_Some inner => inner
  | Option_None => fallback tt
  end.

Definition impl__unwrap_or {a} (value : t_Option a) (fallback : a) : a :=
  match value with
  | Option_Some inner => inner
  | Option_None => fallback
  end.

Definition impl__map {a b} (value : t_Option a) (f : a -> b) : t_Option b :=
  match value with
  | Option_Some inner => Option_Some (f inner)
  | Option_None => Option_None
  end.

Definition impl__ok_or {a e} (value : t_Option a) (error : e) : t_Result a e :=
  match value with
  | Option_Some inner => Result_Ok inner
  | Option_None => Result_Err error
  end.

Definition impl__ok_or_else {a e} (value : t_Option a) (error : unit -> e) : t_Result a e :=
  match value with
  | Option_Some inner => Result_Ok inner
  | Option_None => Result_Err (error tt)
  end.

Definition f_deref {a} (value : a) : a := value.

Definition f_clone {a} (value : a) : a := value.

Definition impl_1__push {a} (values : list a) (value : a) : t_Vec a t_Global :=
  values ++ [value].

Definition impl_1__as_slice {a} (values : list a) : t_Slice a :=
  Build_t_Slice _ values.

Definition f_into_iter {a} (values : list a) : list a := values.

Definition f_fold {a acc} (values : list a) (init : acc) (f : acc -> a -> acc) : acc :=
  List.fold_left f values init.

Definition unsize {a} (values : list a) : t_Slice a :=
  Build_t_Slice _ values.

Definition impl__to_vec {a} (values : t_Slice a) : t_Vec a t_Global :=
  Slice_f_v values.


Definition impl__into_vec {a} (values : t_Slice a) : t_Vec a t_Global :=
  Slice_f_v values.

Definition from_elem {a} (value : a) (len : t_usize) : list a :=
  List.repeat value (usize_to_nat len).

Definition impl_usize__saturating_add (lhs : t_usize) (rhs : t_usize) : t_usize :=
  f_add lhs rhs.

Fixpoint update_at_nat {a} (values : list a) (index : nat) (value : a) : list a :=
  match values, index with
  | [], _ => []
  | _ :: remaining_values, O => value :: remaining_values
  | current_value :: remaining_values, S remaining_index =>
      current_value :: update_at_nat remaining_values remaining_index value
  end.

Definition update_at_usize {a} (values : t_Slice a) (index : t_usize) (value : a) : t_Slice a :=
  Build_t_Slice _ (update_at_nat (Slice_f_v values) (usize_to_nat index) value).

Definition n_to_u32 (value : N) : t_u32 :=
  Build_t_u32 (Build_t_U32 value).

Definition u32_to_n (value : t_u32) : N :=
  U32_f_v (u32_0 value).

Definition build_enumerated {a} (values : list a) : list (t_usize * a) :=
  List.combine
    (List.map (fun index => n_to_usize (N.of_nat index)) (List.seq 0 (List.length values)))
    values.

Definition fold_enumerated_slice {a acc}
  (values : t_Slice a)
  (_ : acc -> unit -> bool)
  (init : acc)
  (f : acc -> (t_usize * a) -> acc) : acc :=
  List.fold_left f (build_enumerated (Slice_f_v values)) init.

Definition build_u32_range (lower upper : t_u32) : list t_u32 :=
  List.map
    (fun index => n_to_u32 (N.of_nat index))
    (List.seq
      (N.to_nat (u32_to_n lower))
      (N.to_nat (u32_to_n upper - u32_to_n lower))).

Definition fold_range {acc}
  (lower : t_u32)
  (upper : t_u32)
  (_ : acc -> t_u32 -> bool)
  (init : acc)
  (f : acc -> t_u32 -> acc) : acc :=
  List.fold_left f (build_u32_range lower upper) init.
