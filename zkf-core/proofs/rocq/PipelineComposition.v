Require Import KernelCompat.
Require Import KernelGenerated.
Require Import KernelFieldEncodingProofs.
Require Import KernelSemantics.
Require Import KernelProofs.
Require Import TransformSemantics.
Require Import TransformProofs.
From ZkfCoreExtraction Require Import Zkf_core_Proof_transform_spec.

Theorem cli_runtime_pipeline_to_kernel_sound_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    ProgramHolds
      (transform_program_to_kernel
        (optimize_ir_program_output (normalize_program_output program)))
      witness.
Proof.
  intros program witness Hcheck.
  eapply transform_program_to_kernel_sound_ok.
  eapply optimize_supported_ir_program_preserves_checks_ok.
  eapply normalize_supported_program_preserves_checks_ok.
  exact Hcheck.
Qed.

Theorem embedded_default_pipeline_to_kernel_sound_ok :
  forall program witness,
    transform_check_program program witness = Result_Ok tt ->
    ProgramHolds
      (transform_program_to_kernel
        (optimize_zir_program_output (normalize_program_output program)))
      witness.
Proof.
  intros program witness Hcheck.
  eapply transform_program_to_kernel_sound_ok.
  eapply optimize_supported_zir_program_preserves_checks_ok.
  eapply normalize_supported_program_preserves_checks_ok.
  exact Hcheck.
Qed.
