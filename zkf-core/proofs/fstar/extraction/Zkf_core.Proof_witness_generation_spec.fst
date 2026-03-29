module Zkf_core.Proof_witness_generation_spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_SpecWitnessSignal = {
  f_constant_value:Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue;
  f_required:bool
}

type t_SpecWitnessAssignment = {
  f_target_signal_index:usize;
  f_expr:Zkf_core.Proof_kernel_spec.t_SpecKernelExpr
}

type t_SpecWitnessHint = {
  f_target_signal_index:usize;
  f_source_signal_index:usize
}

type t_SpecWitnessGenerationProgram = {
  f_kernel_program:Zkf_core.Proof_kernel_spec.t_SpecKernelProgram;
  f_signals:Alloc.Vec.t_Vec t_SpecWitnessSignal Alloc.Alloc.t_Global;
  f_assignments:Alloc.Vec.t_Vec t_SpecWitnessAssignment Alloc.Alloc.t_Global;
  f_hints:Alloc.Vec.t_Vec t_SpecWitnessHint Alloc.Alloc.t_Global
}

type t_SpecWitnessGenerationError =
  | SpecWitnessGenerationError_MissingRequiredSignal { f_signal_index:usize }: t_SpecWitnessGenerationError
  | SpecWitnessGenerationError_UnsupportedWitnessSolve {
    f_unresolved_signal_indices:Alloc.Vec.t_Vec usize Alloc.Alloc.t_Global
  }: t_SpecWitnessGenerationError
  | SpecWitnessGenerationError_KernelCheck : Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
    -> t_SpecWitnessGenerationError
  | SpecWitnessGenerationError_AmbiguousLookup {
    f_constraint_index:usize;
    f_table_index:usize
  }: t_SpecWitnessGenerationError

let generate_non_blackbox_witness_unchecked
      (program: t_SpecWitnessGenerationProgram)
      (inputs: t_Slice (Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue))
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError = generate_non_blackbox_witness_unchecked_runtime program inputs

let validate_generated_witness
      (program: t_SpecWitnessGenerationProgram)
      (witness: Zkf_core.Proof_kernel_spec.t_SpecKernelWitness)
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError =
  match
    Zkf_core.Proof_kernel_spec.check_program program.f_kernel_program witness
    <:
    Core_models.Result.t_Result Prims.unit Zkf_core.Proof_kernel_spec.t_SpecKernelCheckError
  with
  | Core_models.Result.Result_Ok () ->
    Core_models.Result.Result_Ok witness
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err
    (SpecWitnessGenerationError_KernelCheck error <: t_SpecWitnessGenerationError)
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError

let generate_non_blackbox_witness
      (program: t_SpecWitnessGenerationProgram)
      (inputs: t_Slice (Core_models.Option.t_Option Zkf_core.Proof_kernel_spec.t_SpecFieldValue))
    : Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError =
  match
    generate_non_blackbox_witness_unchecked program inputs
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError
  with
  | Core_models.Result.Result_Ok witness -> validate_generated_witness program witness
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err error
    <:
    Core_models.Result.t_Result Zkf_core.Proof_kernel_spec.t_SpecKernelWitness
      t_SpecWitnessGenerationError
