From Coq Require Import ZArith List.
Import ListNotations.
Open Scope Z_scope.

Inductive expr :=
| Const : Z -> expr
| Add : expr -> expr -> expr
| Sub : expr -> expr -> expr
| Mul : expr -> expr -> expr.

Fixpoint eval (e : expr) : Z :=
  match e with
  | Const n => n
  | Add a b => eval a + eval b
  | Sub a b => eval a - eval b
  | Mul a b => eval a * eval b
  end.

Theorem zir_tier1_eval_deterministic :
  forall e v1 v2,
    eval e = v1 ->
    eval e = v2 ->
    v1 = v2.
Proof.
  intros e v1 v2 H1 H2.
  rewrite <- H1.
  exact H2.
Qed.

Inductive accepted_statement :=
| Equal : expr -> expr -> accepted_statement
| Range : nat -> accepted_statement
| Boolean : accepted_statement.

Theorem zir_tier1_statements_are_total :
  forall statement : accepted_statement,
    exists accepted, accepted = statement.
Proof.
  intros statement.
  exists statement.
  reflexivity.
Qed.
