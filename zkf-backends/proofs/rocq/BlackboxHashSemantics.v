From Coq Require Import NArith.
Require Import BackendCompat.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_hash_spec.

Definition usize_4 : t_usize := n_to_usize 4%N.
Definition usize_32 : t_usize := n_to_usize 32%N.

Definition PoseidonBn254Width4LoweringSemantics (semantics : t_CriticalHashLoweringSemantics) : Prop :=
  f_supported_op semantics = SupportedCriticalHashOp_PoseidonBn254Width4 /\
  f_supported_inputs_len semantics = usize_4 /\
  f_supported_outputs_len semantics = usize_4 /\
  f_aux_witness_mode semantics = CriticalHashAuxWitnessMode_ConstraintSolverDerived.

Definition PoseidonPastaFqWidth4LoweringSemantics (semantics : t_CriticalHashLoweringSemantics) : Prop :=
  f_supported_op semantics = SupportedCriticalHashOp_PoseidonPastaFqWidth4 /\
  f_supported_inputs_len semantics = usize_4 /\
  f_supported_outputs_len semantics = usize_4 /\
  f_aux_witness_mode semantics = CriticalHashAuxWitnessMode_ConstraintSolverDerived.

Definition Sha256BytesToDigestLoweringSemantics
  (inputs_len : t_usize)
  (semantics : t_CriticalHashLoweringSemantics)
  : Prop :=
  f_supported_op semantics = SupportedCriticalHashOp_Sha256BytesToDigest /\
  f_supported_inputs_len semantics = inputs_len /\
  f_supported_outputs_len semantics = usize_32 /\
  f_aux_witness_mode semantics = CriticalHashAuxWitnessMode_ConstraintSolverDerived.
