From Stdlib Require Import List Strings.String.
Import List.ListNotations.

(* This shell model only tracks the kernel view that the public adapter
   exposes. It does not claim anything about external translator semantics. *)
Record WitnessAdapterSurface : Type := {
  witness_adapter_kernel_program : list string;
  witness_adapter_kernel_witness : list (option string);
  witness_adapter_signal_names : list string;
  witness_adapter_constraint_labels : list (option string);
  witness_adapter_table_names : list string;
}.

Definition witness_adapter_shell_copy
  (surface : WitnessAdapterSurface) : WitnessAdapterSurface :=
  surface.

Definition WitnessKernelAdapterPreserved
  (before after : WitnessAdapterSurface) : Prop :=
  witness_adapter_kernel_program before = witness_adapter_kernel_program after /\
  witness_adapter_kernel_witness before = witness_adapter_kernel_witness after /\
  witness_adapter_signal_names before = witness_adapter_signal_names after /\
  witness_adapter_constraint_labels before = witness_adapter_constraint_labels after /\
  witness_adapter_table_names before = witness_adapter_table_names after.
