From Coq Require Import NArith.
Require Import BackendCompat.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_ecdsa_spec.

Definition usize_1 : t_usize := n_to_usize 1%N.
Definition usize_160 : t_usize := n_to_usize 160%N.

Definition EcdsaRuntimeRelationSemantics
  (relation : t_CriticalEcdsaRuntimeRelation)
  : Prop :=
  f_valid_signature_forces_one relation = true /\
  f_invalid_signature_forces_zero relation = true /\
  f_malformed_abi_fails_closed relation = true /\
  f_low_s_is_required relation = true.

Definition EcdsaSecp256k1ByteAbiSemantics
  (semantics : t_CriticalEcdsaByteAbiSemantics)
  : Prop :=
  f_supported_curve semantics = SupportedCriticalEcdsaCurve_Secp256k1 /\
  f_supported_field semantics = SpecCriticalEcdsaFieldId_Bn254 /\
  f_supported_inputs_len semantics = usize_160 /\
  f_supported_outputs_len semantics = usize_1 /\
  f_result_is_boolean semantics = true /\
  f_aux_witness_mode semantics = CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness /\
  EcdsaRuntimeRelationSemantics (f_runtime_relation semantics).

Definition EcdsaSecp256r1ByteAbiSemantics
  (semantics : t_CriticalEcdsaByteAbiSemantics)
  : Prop :=
  f_supported_curve semantics = SupportedCriticalEcdsaCurve_Secp256r1 /\
  f_supported_field semantics = SpecCriticalEcdsaFieldId_Bn254 /\
  f_supported_inputs_len semantics = usize_160 /\
  f_supported_outputs_len semantics = usize_1 /\
  f_result_is_boolean semantics = true /\
  f_aux_witness_mode semantics = CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness /\
  EcdsaRuntimeRelationSemantics (f_runtime_relation semantics).
