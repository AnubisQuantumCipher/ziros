Require Import BackendCompat.
Require Import BlackboxEcdsaSemantics.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_ecdsa_spec.

Theorem ecdsa_secp256k1_byte_abi_lowering_sound_ok :
  forall semantics,
    critical_ecdsa_byte_abi_semantics
      SpecCriticalEcdsaOp_Secp256k1
      SpecCriticalEcdsaFieldId_Bn254
      usize_160
      usize_1 = Option_Some semantics ->
    EcdsaSecp256k1ByteAbiSemantics semantics.
Proof.
  intros semantics Hsemantics.
  unfold critical_ecdsa_byte_abi_semantics in Hsemantics.
  cbn in Hsemantics.
  inversion Hsemantics; subst.
  repeat split; reflexivity.
Qed.

Theorem ecdsa_secp256k1_byte_abi_aux_witness_sound_ok :
  forall semantics,
    critical_ecdsa_byte_abi_semantics
      SpecCriticalEcdsaOp_Secp256k1
      SpecCriticalEcdsaFieldId_Bn254
      usize_160
      usize_1 = Option_Some semantics ->
    f_aux_witness_mode semantics = CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness.
Proof.
  intros semantics Hsemantics.
  eapply ecdsa_secp256k1_byte_abi_lowering_sound_ok in Hsemantics.
  destruct Hsemantics as [_ [_ [_ [_ [_ [Haux _]]]]]].
  exact Haux.
Qed.

Theorem ecdsa_secp256r1_byte_abi_lowering_sound_ok :
  forall semantics,
    critical_ecdsa_byte_abi_semantics
      SpecCriticalEcdsaOp_Secp256r1
      SpecCriticalEcdsaFieldId_Bn254
      usize_160
      usize_1 = Option_Some semantics ->
    EcdsaSecp256r1ByteAbiSemantics semantics.
Proof.
  intros semantics Hsemantics.
  unfold critical_ecdsa_byte_abi_semantics in Hsemantics.
  cbn in Hsemantics.
  inversion Hsemantics; subst.
  repeat split; reflexivity.
Qed.

Theorem ecdsa_secp256r1_byte_abi_aux_witness_sound_ok :
  forall semantics,
    critical_ecdsa_byte_abi_semantics
      SpecCriticalEcdsaOp_Secp256r1
      SpecCriticalEcdsaFieldId_Bn254
      usize_160
      usize_1 = Option_Some semantics ->
    f_aux_witness_mode semantics = CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness.
Proof.
  intros semantics Hsemantics.
  eapply ecdsa_secp256r1_byte_abi_lowering_sound_ok in Hsemantics.
  destruct Hsemantics as [_ [_ [_ [_ [_ [Haux _]]]]]].
  exact Haux.
Qed.
