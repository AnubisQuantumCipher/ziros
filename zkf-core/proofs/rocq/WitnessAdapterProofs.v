Require Import WitnessAdapterSemantics.

Theorem witness_kernel_adapter_preservation_ok :
  forall surface,
    WitnessKernelAdapterPreserved surface (witness_adapter_shell_copy surface).
Proof.
  intros surface.
  unfold witness_adapter_shell_copy, WitnessKernelAdapterPreserved.
  repeat split; reflexivity.
Qed.
