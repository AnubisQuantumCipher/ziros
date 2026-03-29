Require Import BackendCompat.
Require Import BackendCompat.
Require Import BlackboxHashSemantics.
Require Import BlackboxHashProofs.
Require Import BlackboxEcdsaSemantics.
Require Import BlackboxEcdsaProofs.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_hash_spec.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_blackbox_ecdsa_spec.

Theorem blackbox_runtime_checks_critical_surface_ok :
  (forall semantics,
      critical_hash_lowering_semantics
        SpecCriticalHashBlackBoxOp_Poseidon
        SpecCriticalHashFieldId_Bn254
        usize_4
        usize_4 = Option_Some semantics ->
      PoseidonBn254Width4LoweringSemantics semantics) /\
  (forall semantics,
      critical_hash_lowering_semantics
        SpecCriticalHashBlackBoxOp_Poseidon
        SpecCriticalHashFieldId_Bn254
        usize_4
        usize_4 = Option_Some semantics ->
      CriticalHashLoweringSemantics_f_aux_witness_mode semantics =
        CriticalHashAuxWitnessMode_ConstraintSolverDerived) /\
  (forall field inputs_len semantics,
      critical_hash_lowering_semantics
        SpecCriticalHashBlackBoxOp_Sha256
        field
        inputs_len
        usize_32 = Option_Some semantics ->
      Sha256BytesToDigestLoweringSemantics inputs_len semantics) /\
  (forall field inputs_len semantics,
      critical_hash_lowering_semantics
        SpecCriticalHashBlackBoxOp_Sha256
        field
        inputs_len
        usize_32 = Option_Some semantics ->
      CriticalHashLoweringSemantics_f_aux_witness_mode semantics =
        CriticalHashAuxWitnessMode_ConstraintSolverDerived) /\
  (forall semantics,
      critical_ecdsa_byte_abi_semantics
        SpecCriticalEcdsaOp_Secp256k1
        SpecCriticalEcdsaFieldId_Bn254
        usize_160
        usize_1 = Option_Some semantics ->
      EcdsaSecp256k1ByteAbiSemantics semantics) /\
  (forall semantics,
      critical_ecdsa_byte_abi_semantics
        SpecCriticalEcdsaOp_Secp256k1
        SpecCriticalEcdsaFieldId_Bn254
        usize_160
        usize_1 = Option_Some semantics ->
      CriticalEcdsaByteAbiSemantics_f_aux_witness_mode semantics =
        CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness) /\
  (forall semantics,
      critical_ecdsa_byte_abi_semantics
        SpecCriticalEcdsaOp_Secp256r1
        SpecCriticalEcdsaFieldId_Bn254
        usize_160
        usize_1 = Option_Some semantics ->
      EcdsaSecp256r1ByteAbiSemantics semantics) /\
  (forall semantics,
      critical_ecdsa_byte_abi_semantics
        SpecCriticalEcdsaOp_Secp256r1
        SpecCriticalEcdsaFieldId_Bn254
        usize_160
        usize_1 = Option_Some semantics ->
      CriticalEcdsaByteAbiSemantics_f_aux_witness_mode semantics =
        CriticalEcdsaAuxWitnessMode_ArithmeticAuxWitness).
Proof.
  split.
  - intros semantics H.
    eapply poseidon_bn254_width4_lowering_sound_ok; eauto.
  - split.
    + intros semantics H.
      eapply poseidon_bn254_width4_aux_witness_sound_ok; eauto.
    + split.
      * intros field inputs_len semantics H.
        eapply sha256_bytes_to_digest_lowering_sound_ok; eauto.
      * split.
        -- intros field inputs_len semantics H.
           eapply sha256_bytes_to_digest_aux_witness_sound_ok; eauto.
        -- split.
           ++ intros semantics H.
              eapply ecdsa_secp256k1_byte_abi_lowering_sound_ok; eauto.
           ++ split.
              ** intros semantics H.
                 eapply ecdsa_secp256k1_byte_abi_aux_witness_sound_ok; eauto.
              ** split.
                 --- intros semantics H.
                     eapply ecdsa_secp256r1_byte_abi_lowering_sound_ok; eauto.
                 --- intros semantics H.
                     eapply ecdsa_secp256r1_byte_abi_aux_witness_sound_ok; eauto.
Qed.
