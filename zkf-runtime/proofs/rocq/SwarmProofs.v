Require Import KernelCompat.
From Stdlib Require Import NArith.
From ZkfRuntimeExtraction Require Import Zkf_runtime_Proof_swarm_spec.

Lemma u8_list_eq_refl :
  forall bytes,
    u8_list_eq bytes bytes = true.
Proof.
  induction bytes as [| byte bytes IHbytes].
  - reflexivity.
  - simpl.
    rewrite N.eqb_refl.
    exact IHbytes.
Qed.

Lemma artifact_bytes_eq_refl :
  forall artifact,
    artifact_bytes_eq artifact artifact = true.
Proof.
  intros [slice].
  destruct slice as [bytes].
  simpl.
  apply u8_list_eq_refl.
Qed.

Theorem swarm_non_interference_ok :
  forall enabled artifact reject artifact_out,
    controller_artifact_path enabled artifact reject = Result_Ok artifact_out ->
    artifact_out = artifact.
Proof.
  intros enabled artifact reject artifact_out Hpath.
  destruct enabled;
    destruct reject;
    simpl in Hpath;
    inversion Hpath;
    reflexivity.
Qed.

Theorem disabled_surface_state_is_dormant_ok :
  f_activation_level (disabled_surface_state_spec tt) = ProofSwarmActivationLevel_Dormant /\
  f_verdict_activation_level (disabled_surface_state_spec tt) = ProofSwarmActivationLevel_Dormant /\
  f_consensus_confirmed (disabled_surface_state_spec tt) = false /\
  f_telemetry_present (disabled_surface_state_spec tt) = false.
Proof.
  repeat split; reflexivity.
Qed.

Theorem controller_artifact_path_matches_pure_helper_ok :
  forall enabled artifact reject,
    controller_artifact_path_matches_pure_helper enabled artifact reject = true.
Proof.
  intros enabled artifact reject.
  destruct enabled;
    destruct reject;
    simpl;
    try reflexivity;
    apply artifact_bytes_eq_refl.
Qed.

Theorem controller_artifact_path_success_preserves_bytes_ok :
  forall enabled artifact,
    successful_artifact_path_preserves_bytes enabled artifact = true.
Proof.
  intros enabled artifact.
  destruct enabled;
    simpl;
    apply artifact_bytes_eq_refl.
Qed.

Theorem swarm_encrypted_gossip_non_interference_ok :
  forall artifact,
    encrypted_gossip_surface_preserves_artifact_bytes artifact =
      artifact_bytes_eq (encrypted_gossip_artifact_projection artifact) artifact.
Proof.
  intros artifact.
  reflexivity.
Qed.

Theorem swarm_encrypted_gossip_fail_closed_ok :
  forall negotiated plaintext_present encrypted_payload_present,
    encrypted_gossip_fail_closed_spec
      negotiated
      plaintext_present
      encrypted_payload_present =
      if negotiated
      then negb plaintext_present
      else andb (negb plaintext_present) (negb encrypted_payload_present).
Proof.
  intros negotiated plaintext_present encrypted_payload_present.
  destruct negotiated;
  destruct plaintext_present;
    destruct encrypted_payload_present;
    reflexivity.
Qed.

Theorem controller_artifact_mutation_surface_absent_ok :
  controller_artifact_mutation_surface_count tt =
    f_threat_digest_count (disabled_surface_state_spec tt).
Proof.
  reflexivity.
Qed.

Theorem cooldown_tick_non_deescalating_ok :
  forall level,
    cooldown_tick_is_non_deescalating level = true.
Proof.
  intros level.
  destruct level;
    reflexivity.
Qed.

Theorem cooldown_tick_drops_at_most_one_level_ok :
  forall level,
    cooldown_tick_drops_at_most_one_level level = true.
Proof.
  intros level.
  destruct level;
    reflexivity.
Qed.
