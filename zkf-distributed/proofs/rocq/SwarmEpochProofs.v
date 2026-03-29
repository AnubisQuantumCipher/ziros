Require Import KernelCompat.
From Stdlib Require Import NArith Lia.
From ZkfDistributedExtraction Require Import Zkf_distributed_Proof_swarm_reputation_spec.

Lemma u8_eq_refl :
  forall byte,
    u8_eq byte byte = true.
Proof.
  intros [inner].
  unfold u8_eq.
  cbn.
  unfold haxint_cmp.
  destruct (U8_f_v inner) eqn:Hinner.
  - reflexivity.
  - simpl.
    destruct (positive_cmp p p) eqn:Hcmp; try reflexivity.
    + pose proof (positive_cmp_is_spec p p) as Hspec.
      rewrite Hcmp in Hspec.
      simpl in Hspec.
      rewrite Pos.compare_refl in Hspec.
      discriminate.
    + pose proof (positive_cmp_is_spec p p) as Hspec.
      rewrite Hcmp in Hspec.
      simpl in Hspec.
      rewrite Pos.compare_refl in Hspec.
      discriminate.
Qed.

Lemma array2_eq_refl :
  forall bytes,
    array2_eq bytes bytes = true.
Proof.
  intros [left right].
  unfold array2_eq.
  simpl.
  rewrite u8_eq_refl.
  rewrite u8_eq_refl.
  reflexivity.
Qed.

Theorem distributed_encrypted_gossip_fail_closed_ok :
  forall negotiated plaintext_present encrypted_payload_present,
    encrypted_gossip_negotiation_fail_closed_spec
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

Theorem swarm_memory_append_only_prefix_preserved_ok :
  forall prefix suffix,
    chain_prefix4 (append_only_memory_chain_after_append prefix suffix) = prefix.
Proof.
  intros prefix suffix.
  destruct prefix as [p0 p1 p2 p3].
  destruct suffix as [s0 s1 s2 s3].
  reflexivity.
Qed.

Theorem snapshot_chain_head_roundtrip_matches_array_equality_ok :
  forall exported_head imported_head,
    snapshot_chain_head_roundtrip_spec exported_head imported_head =
      array4_eq exported_head imported_head.
Proof.
  intros exported_head imported_head.
  reflexivity.
Qed.

Theorem intelligence_root_canonical_pair_converges_ok :
  forall first second,
    intelligence_root_convergence_under_canonical_ordering_spec first second =
      array2_eq
        (canonical_intelligence_leaf_pair first second)
        (canonical_intelligence_leaf_pair second first).
Proof.
  intros first second.
  reflexivity.
Qed.

Theorem intelligence_root_canonical_ordering_spec_ok :
  forall first second,
    intelligence_root_convergence_under_canonical_ordering_spec first second =
      array2_eq
        (canonical_intelligence_leaf_pair first second)
        (canonical_intelligence_leaf_pair second first).
Proof.
  intros first second.
  reflexivity.
Qed.

Theorem snapshot_authenticated_roundtrip_helper_surface_ok :
  (forall prefix suffix,
      chain_prefix4 (append_only_memory_chain_after_append prefix suffix) = prefix) /\
  (forall exported_head imported_head,
      snapshot_chain_head_roundtrip_spec exported_head imported_head =
        array4_eq exported_head imported_head).
Proof.
  split.
  - exact swarm_memory_append_only_prefix_preserved_ok.
  - exact snapshot_chain_head_roundtrip_matches_array_equality_ok.
Qed.
