From Coq Require Import ZArith.
Require Import List.
Import List.ListNotations.
Open Scope Z_scope.

From Core Require Export Core.

Notation f_index := Index_f_index.

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

Definition f_add (lhs : t_usize) (rhs : t_usize) : t_usize :=
  n_to_usize (N.add (usize_to_n lhs) (usize_to_n rhs)).

Definition f_sub (lhs : t_usize) (rhs : t_usize) : t_usize :=
  n_to_usize (N.sub (usize_to_n lhs) (usize_to_n rhs)).

Definition f_eq (lhs : t_usize) (rhs : t_usize) : bool :=
  N.eqb (usize_to_n lhs) (usize_to_n rhs).

Definition f_lt (lhs : t_usize) (rhs : t_usize) : bool :=
  N.ltb (usize_to_n lhs) (usize_to_n rhs).

Definition f_ge (lhs : t_usize) (rhs : t_usize) : bool :=
  N.leb (usize_to_n rhs) (usize_to_n lhs).

Definition f_gt (lhs : t_usize) (rhs : t_usize) : bool :=
  N.ltb (usize_to_n rhs) (usize_to_n lhs).

Definition f_not (value : bool) : bool := negb value.

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

Definition impl__split_first {a} (values : t_Slice a) : t_Option (a * t_Slice a) :=
  match Slice_f_v values with
  | [] => Option_None
  | value :: remaining_values => Option_Some (value, Build_t_Slice _ remaining_values)
  end.

Definition impl_2__cloned {a} (value : t_Option a) : t_Option a := value.

Definition impl_2__copied {a} (value : t_Option a) : t_Option a := value.

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

Definition f_deref {a} (value : a) : a := value.

Definition f_clone {a} (value : a) : a := value.

Definition impl_1__push {a} (values : list a) (value : a) : t_Vec a t_Global :=
  values ++ [value].

Definition impl_1__as_slice {a} (values : list a) : t_Slice a :=
  Build_t_Slice _ values.

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

Axiom dropped_body : forall {a}, a.
