module Zkf_core.Proof_witness_adapter_spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_SpecWitnessAdapterSurface = {
  f_kernel_program:Zkf_core.Proof_kernel_spec.t_SpecKernelProgram;
  f_kernel_witness:Zkf_core.Proof_kernel_spec.t_SpecKernelWitness;
  f_signal_names:Alloc.Vec.t_Vec Alloc.String.t_String Alloc.Alloc.t_Global;
  f_constraint_labels:Alloc.Vec.t_Vec (Core_models.Option.t_Option Alloc.String.t_String)
    Alloc.Alloc.t_Global;
  f_table_names:Alloc.Vec.t_Vec Alloc.String.t_String Alloc.Alloc.t_Global
}

let supported_shell_surface
      (kernel_program: Zkf_core.Proof_kernel_spec.t_SpecKernelProgram)
      (kernel_witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
      (signal_names: Alloc.Vec.t_Vec Alloc.String.t_String Alloc.Alloc.t_Global)
      (constraint_labels:
          Alloc.Vec.t_Vec (Core_models.Option.t_Option Alloc.String.t_String) Alloc.Alloc.t_Global)
      (table_names: Alloc.Vec.t_Vec Alloc.String.t_String Alloc.Alloc.t_Global)
    : t_SpecWitnessAdapterSurface =
  {
    f_kernel_program = kernel_program;
    f_kernel_witness = kernel_witness;
    f_signal_names = signal_names;
    f_constraint_labels = constraint_labels;
    f_table_names = table_names
  }
  <:
  t_SpecWitnessAdapterSurface

let shell_surface_is_structural_copy (surface: t_SpecWitnessAdapterSurface) : bool =
  (Alloc.Vec.impl_1__len #Alloc.String.t_String #Alloc.Alloc.t_Global surface.f_signal_names
    <:
    usize) =.
  (Alloc.Vec.impl_1__len #(Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue)
      #Alloc.Alloc.t_Global
      surface.f_kernel_witness.Zkf_core.Proof_kernel_spec.f_values
    <:
    usize) &&
  (Alloc.Vec.impl_1__len #(Core_models.Option.t_Option Alloc.String.t_String)
      #Alloc.Alloc.t_Global
      surface.f_constraint_labels
    <:
    usize) =.
  (Alloc.Vec.impl_1__len #Zkf_core.Proof_kernel_spec.t_SpecKernelConstraint
      #Alloc.Alloc.t_Global
      surface.f_kernel_program.Zkf_core.Proof_kernel_spec.f_constraints
    <:
    usize) &&
  (Alloc.Vec.impl_1__len #Alloc.String.t_String #Alloc.Alloc.t_Global surface.f_table_names <: usize
  ) =.
  (Alloc.Vec.impl_1__len #Zkf_core.Proof_kernel_spec.t_SpecKernelLookupTable
      #Alloc.Alloc.t_Global
      surface.f_kernel_program.Zkf_core.Proof_kernel_spec.f_lookup_tables
    <:
    usize)
