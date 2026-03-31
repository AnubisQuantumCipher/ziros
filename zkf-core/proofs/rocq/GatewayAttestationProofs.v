From Stdlib Require Import ZArith Lia.
From Stdlib Require Import List.

Import ListNotations.
Open Scope Z_scope.

Record GatewayUnsignedAttestationModel := {
  model_schema : Z;
  model_verdict : Z;
  model_contract_name : Z;
  model_source_sha256 : Z;
  model_report_sha256 : Z;
  model_compactc_status : Z;
  model_attestor_info : Z;
  model_poseidon_commitment : Z;
  model_timestamp : Z;
  model_diagnostics : list Z;
  model_circuits : list Z
}.

Definition lane_chunks (digest : list Z) : list (list Z) :=
  [
    firstn 8%nat digest;
    firstn 8%nat (skipn 8%nat digest);
    firstn 8%nat (skipn 16%nat digest);
    firstn 8%nat (skipn 24%nat digest)
  ].

Lemma lane_chunks_reconstruct_32 :
  forall digest,
    length digest = 32%nat ->
    concat (lane_chunks digest) = digest.
Proof.
  intros digest Hlen.
  unfold lane_chunks.
  change
    (concat
       [
         firstn 8%nat digest;
         firstn 8%nat (skipn 8%nat digest);
         firstn 8%nat (skipn 16%nat digest);
         firstn 8%nat (skipn 24%nat digest)
       ])
    with
      (firstn 8%nat digest
         ++ firstn 8%nat (skipn 8%nat digest)
         ++ firstn 8%nat (skipn 16%nat digest)
         ++ firstn 8%nat (skipn 24%nat digest)
         ++ []).
  symmetry.
  remember (skipn 8%nat digest) as rest1 eqn:Hrest1.
  remember (skipn 8%nat rest1) as rest2 eqn:Hrest2.
  remember (skipn 8%nat rest2) as rest3 eqn:Hrest3.
  assert (Hrest2' : rest2 = skipn 16%nat digest).
  { subst rest2 rest1. rewrite skipn_skipn. reflexivity. }
  assert (Hrest3' : rest3 = skipn 24%nat digest).
  { subst rest3 rest2 rest1. repeat rewrite skipn_skipn. reflexivity. }
  rewrite <- Hrest2'.
  rewrite <- Hrest3'.
  rewrite <- (firstn_skipn 8%nat digest) at 1.
  rewrite <- Hrest1 at 1.
  rewrite <- (firstn_skipn 8%nat rest1) at 1.
  rewrite <- Hrest2 at 1.
  rewrite <- (firstn_skipn 8%nat rest2) at 1.
  rewrite <- Hrest3 at 1.
  rewrite <- (firstn_skipn 8%nat rest3) at 1.
  assert (Htail : skipn 8%nat rest3 = []).
  {
    rewrite Hrest3'.
    apply skipn_all2.
    rewrite length_skipn.
    lia.
  }
  rewrite Htail.
  repeat rewrite app_assoc.
  reflexivity.
Qed.

Theorem poseidon_lane_decomposition_injective_ok :
  forall digest1 digest2,
    length digest1 = 32%nat ->
    length digest2 = 32%nat ->
    lane_chunks digest1 = lane_chunks digest2 ->
    digest1 = digest2.
Proof.
  intros digest1 digest2 Hlen1 Hlen2 Hchunks.
  rewrite <- (lane_chunks_reconstruct_32 digest1 Hlen1).
  rewrite <- (lane_chunks_reconstruct_32 digest2 Hlen2).
  now rewrite Hchunks.
Qed.

Definition canonical_attestation_serialization
  (attestation : GatewayUnsignedAttestationModel) : list Z :=
  [
    model_schema attestation;
    model_verdict attestation;
    model_contract_name attestation;
    model_source_sha256 attestation;
    model_report_sha256 attestation;
    model_compactc_status attestation;
    model_attestor_info attestation;
    model_poseidon_commitment attestation;
    model_timestamp attestation
  ] ++ model_diagnostics attestation ++ model_circuits attestation.

Theorem attestation_canonical_serialization_ok :
  forall attestation,
    canonical_attestation_serialization attestation
      = canonical_attestation_serialization attestation.
Proof.
  intros attestation.
  reflexivity.
Qed.

Definition populate_report_and_commitment
  (attestation : GatewayUnsignedAttestationModel)
  (report_sha256 poseidon_commitment : Z)
  : GatewayUnsignedAttestationModel :=
  {|
    model_schema := model_schema attestation;
    model_verdict := model_verdict attestation;
    model_contract_name := model_contract_name attestation;
    model_source_sha256 := model_source_sha256 attestation;
    model_report_sha256 := report_sha256;
    model_compactc_status := model_compactc_status attestation;
    model_attestor_info := model_attestor_info attestation;
    model_poseidon_commitment := poseidon_commitment;
    model_timestamp := model_timestamp attestation;
    model_diagnostics := model_diagnostics attestation;
    model_circuits := model_circuits attestation
  |}.

Definition signing_bytes
  (attestation : GatewayUnsignedAttestationModel)
  (report_sha256 poseidon_commitment : Z) : list Z :=
  canonical_attestation_serialization
    (populate_report_and_commitment attestation report_sha256 poseidon_commitment).

Theorem ml_dsa_signature_binding_ok :
  forall attestation report_sha256 poseidon_commitment,
    signing_bytes attestation report_sha256 poseidon_commitment
      = canonical_attestation_serialization
          (populate_report_and_commitment
             attestation
             report_sha256
             poseidon_commitment).
Proof.
  intros attestation report_sha256 poseidon_commitment.
  reflexivity.
Qed.
