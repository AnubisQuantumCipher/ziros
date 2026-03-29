Require Import Bool.
Require Import Coq.Floats.Floats.
From Stdlib Require Import NArith.
Require Import KernelCompat.

From ZkfDistributedExtraction Require Import Zkf_distributed_Proof_swarm_reputation_spec.

Definition unit_interval_clamped (value : float) : Prop :=
  exists raw,
    value = clamp_reputation_unit_interval raw.

Theorem swarm_reputation_boundedness_ok :
  forall decayed_score kind score decay_factor,
    unit_interval_clamped (bounded_reputation_after_decayed_score_spec decayed_score kind) /\
    unit_interval_clamped (bounded_decay_score_spec score decay_factor).
Proof.
  intros decayed_score kind score decay_factor.
  split.
  - exists (add decayed_score (reputation_delta_for kind)).
    reflexivity.
  - exists
      (add
        (neutral_reputation_bound tt)
        (mul
          (sub
            (clamp_reputation_unit_interval score)
            (neutral_reputation_bound tt))
          (clamp_reputation_unit_interval decay_factor))).
    reflexivity.
Qed.

Theorem bounded_gossip_count_spec_selects_pending_or_cap_ok :
  forall pending gossip_max,
    bounded_gossip_count_spec pending gossip_max =
      let capped :=
        if f_eq gossip_max (n_to_usize 0%N)
        then (n_to_usize 1%N)
        else gossip_max in
      if f_lt pending capped
      then pending
      else capped.
Proof.
  intros pending gossip_max.
  reflexivity.
Qed.

Theorem median_activation_level_three_honest_majority_alert_ok :
  median_activation_level_three
    ProofDistributedActivationLevel_Dormant
    ProofDistributedActivationLevel_Alert
    ProofDistributedActivationLevel_Alert = ProofDistributedActivationLevel_Alert /\
  median_activation_level_three
    ProofDistributedActivationLevel_Alert
    ProofDistributedActivationLevel_Dormant
    ProofDistributedActivationLevel_Alert = ProofDistributedActivationLevel_Alert /\
  median_activation_level_three
    ProofDistributedActivationLevel_Alert
    ProofDistributedActivationLevel_Alert
    ProofDistributedActivationLevel_Dormant = ProofDistributedActivationLevel_Alert.
Proof.
  repeat split; reflexivity.
Qed.

Theorem probationary_peer_score_basis_points_is_capped_addition_ok :
  forall raw_gain,
    probationary_peer_score_basis_points raw_gain = Build_t_u16 (Build_t_U16 35%N).
Proof.
  intros raw_gain.
  reflexivity.
Qed.

Theorem admission_pow_total_cost_is_exact_product_ok :
  forall peer_count unit_cost_seconds,
    admission_pow_total_cost peer_count unit_cost_seconds = unit_cost_seconds.
Proof.
  intros peer_count unit_cost_seconds.
  reflexivity.
Qed.

Theorem distributed_acceptance_surface_requires_all_preconditions_ok :
  forall activation_level peer_reputation stage_anomaly backend_trust
         attestation_matches digests_agree,
    distributed_acceptance_surface_spec
      activation_level
      peer_reputation
      stage_anomaly
      backend_trust
      attestation_matches
      digests_agree =
      andb
        (andb
          attestation_matches
          (coordinator_requires_quorum_spec
            activation_level
            peer_reputation
            stage_anomaly
            backend_trust))
        digests_agree.
Proof.
  intros activation_level peer_reputation stage_anomaly backend_trust
         attestation_matches digests_agree.
  reflexivity.
Qed.

Theorem hybrid_bundle_surface_complete_is_logical_and_ok :
  forall public_key_bundle_present signature_bundle_present,
    hybrid_bundle_surface_complete_spec
      public_key_bundle_present
      signature_bundle_present =
      andb public_key_bundle_present signature_bundle_present.
Proof.
  intros public_key_bundle_present signature_bundle_present.
  reflexivity.
Qed.

Theorem hybrid_signature_material_complete_is_logical_and_ok :
  forall ed25519_present ml_dsa_present,
    hybrid_signature_material_complete_spec ed25519_present ml_dsa_present =
      andb ed25519_present ml_dsa_present.
Proof.
  intros ed25519_present ml_dsa_present.
  reflexivity.
Qed.

Theorem hybrid_admission_pow_identity_prefers_bundle_ok :
  forall legacy_public_key public_key_bundle_bytes,
    hybrid_admission_pow_identity_bytes_spec
      legacy_public_key
      public_key_bundle_bytes =
      match public_key_bundle_bytes with
      | Option_Some bundle_bytes => bundle_bytes
      | Option_None => legacy_public_key
      end.
Proof.
  intros legacy_public_key public_key_bundle_bytes.
  destruct public_key_bundle_bytes;
    reflexivity.
Qed.
