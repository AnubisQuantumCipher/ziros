Require Import KernelCompat.
Require Import KernelGenerated.
From ZkfCoreExtraction Require Import Zkf_core_Proof_witness_generation_spec.

Notation "'t_SpecWitnessSignal'" := (SpecWitnessSignal_record).
Notation "'t_SpecWitnessGenerationProgram'" := (SpecWitnessGenerationProgram_record).
Notation "'f_kernel_program'" := (SpecWitnessGenerationProgram_f_kernel_program).
Notation "'f_signals'" := (SpecWitnessGenerationProgram_f_signals).

Definition GeneratedWitnessAccepted
  (program : t_SpecWitnessGenerationProgram)
  (witness : t_SpecKernelWitness) : Prop :=
  check_program (f_kernel_program program) witness = Result_Ok tt.
