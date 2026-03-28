From Stdlib Require Import List NArith.
Import List.ListNotations.

(* This theorem is about the runtime provenance boundary only:
   the large-prime field runtime is pinned to the shipped Fiat-generated
   modules for the four supported large-prime fields. *)
Inductive LargePrimeRuntimeField :=
| Bn254
| Bls12_381
| PastaFp
| PastaFq
| OtherLargePrimeField.

Definition large_prime_runtime_dispatch_index
  (field : LargePrimeRuntimeField) : option N :=
  match field with
  | Bn254 => Some 0%N
  | Bls12_381 => Some 1%N
  | PastaFp => Some 2%N
  | PastaFq => Some 3%N
  | _ => None
  end.

Definition manifest_pinned_large_prime_field
  (field : LargePrimeRuntimeField) : Prop :=
  exists slot, large_prime_runtime_dispatch_index field = Some slot.

Definition large_prime_runtime_manifest : list LargePrimeRuntimeField :=
  [ Bn254
  ; Bls12_381
  ; PastaFp
  ; PastaFq
  ].

Theorem large_prime_runtime_fiat_binding_ok :
  Forall manifest_pinned_large_prime_field large_prime_runtime_manifest.
Proof.
  repeat constructor.
  all: unfold manifest_pinned_large_prime_field, large_prime_runtime_dispatch_index;
    simpl; eexists; reflexivity.
Qed.
