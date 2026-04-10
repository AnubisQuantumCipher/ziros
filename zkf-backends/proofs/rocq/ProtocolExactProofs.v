Require Import BackendCompat.
Require Import ProtocolExactSemantics.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_fri_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_groth16_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_hypernova_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_nova_exact_spec.

Theorem groth16_exact_completeness_reduction_ok :
  forall model,
    groth16ImportedCrsValidityHypothesis model ->
    groth16ExactCompletenessHypothesis model ->
    Groth16VerifierGuard model ->
    groth16_exact_completeness_reduction model = true.
Proof.
  intros model Hcrs Hhyp Hguard.
  unfold groth16ImportedCrsValidityHypothesis in Hcrs.
  unfold groth16ExactCompletenessHypothesis in Hhyp.
  unfold Groth16VerifierGuard in Hguard.
  unfold groth16_exact_completeness_reduction.
  rewrite Hcrs.
  rewrite Hguard.
  simpl.
  exact (Hhyp Hguard).
Qed.

Theorem groth16_exact_knowledge_soundness_reduction_ok :
  forall model,
    groth16ImportedCrsValidityHypothesis model ->
    groth16KnowledgeOfExponentHypothesis model ->
    Groth16ExactSurfaceModel_f_verifier_accepts model = true ->
    groth16_exact_knowledge_soundness_reduction model = true.
Proof.
  intros model Hcrs Hhyp Haccepted.
  unfold groth16ImportedCrsValidityHypothesis in Hcrs.
  unfold groth16KnowledgeOfExponentHypothesis in Hhyp.
  unfold groth16_exact_knowledge_soundness_reduction.
  rewrite Hcrs.
  rewrite Haccepted.
  simpl.
  exact (Hhyp Haccepted).
Qed.

Theorem groth16_exact_zero_knowledge_reduction_ok :
  forall model,
    groth16ImportedCrsValidityHypothesis model ->
    groth16ExactZeroKnowledgeHypothesis model ->
    groth16_exact_zero_knowledge_reduction model = true.
Proof.
  intros model Hcrs Hhyp.
  unfold groth16ImportedCrsValidityHypothesis in Hcrs.
  unfold groth16ExactZeroKnowledgeHypothesis in Hhyp.
  unfold groth16_exact_zero_knowledge_reduction.
  rewrite Hcrs.
  simpl.
  exact Hhyp.
Qed.

Theorem fri_exact_completeness_reduction_ok :
  forall model,
    friExactCompletenessHypothesis model ->
    FriExactVerifierGuard model ->
    fri_exact_completeness_reduction model = true.
Proof.
  intros model Hhyp Hguard.
  unfold friExactCompletenessHypothesis in Hhyp.
  unfold FriExactVerifierGuard in Hguard.
  unfold fri_exact_completeness_reduction.
  rewrite Hguard.
  simpl.
  exact (Hhyp Hguard).
Qed.

Theorem fri_exact_proximity_soundness_reduction_ok :
  forall model,
    friReedSolomonProximitySoundnessHypothesis model ->
    FriExactSurfaceModel_f_verifier_accepts model = true ->
    fri_exact_proximity_soundness_reduction model = true.
Proof.
  intros model Hhyp Haccepted.
  unfold friReedSolomonProximitySoundnessHypothesis in Hhyp.
  unfold fri_exact_proximity_soundness_reduction.
  rewrite Haccepted.
  simpl.
  exact (Hhyp Haccepted).
Qed.

Theorem nova_exact_completeness_reduction_ok :
  forall model,
    novaExactCompletenessHypothesis model ->
    completeClassicNovaIvcMetadata model ->
    NovaExactVerifierGuard model ->
    nova_exact_completeness_reduction model = true.
Proof.
  intros model Hhyp Hmetadata Hguard.
  unfold novaExactCompletenessHypothesis in Hhyp.
  unfold completeClassicNovaIvcMetadata in Hmetadata.
  unfold NovaExactVerifierGuard in Hguard.
  unfold nova_exact_completeness_reduction.
  rewrite Hmetadata.
  rewrite Hguard.
  simpl.
  exact (Hhyp Hmetadata Hguard).
Qed.

Theorem nova_exact_folding_soundness_reduction_ok :
  forall model,
    novaExactFoldingSoundnessHypothesis model ->
    NovaExactSurfaceModel_f_verifier_accepts model = true ->
    nova_exact_folding_soundness_reduction model = true.
Proof.
  intros model Hhyp Haccepted.
  unfold novaExactFoldingSoundnessHypothesis in Hhyp.
  unfold nova_exact_folding_soundness_reduction.
  rewrite Haccepted.
  simpl.
  exact (Hhyp Haccepted).
Qed.

Theorem hypernova_exact_completeness_reduction_ok :
  forall model,
    hypernovaExactCompletenessHypothesis model ->
    HyperNovaExactVerifierGuard model ->
    hypernova_exact_completeness_reduction model = true.
Proof.
  intros model Hhyp Hguard.
  unfold hypernovaExactCompletenessHypothesis in Hhyp.
  unfold HyperNovaExactVerifierGuard in Hguard.
  unfold hypernova_exact_completeness_reduction.
  rewrite Hguard.
  simpl.
  exact (Hhyp Hguard).
Qed.

Theorem hypernova_exact_folding_soundness_reduction_ok :
  forall model,
    hypernovaExactFoldingSoundnessHypothesis model ->
    HyperNovaExactSurfaceModel_f_verifier_accepts model = true ->
    hypernova_exact_folding_soundness_reduction model = true.
Proof.
  intros model Hhyp Haccepted.
  unfold hypernovaExactFoldingSoundnessHypothesis in Hhyp.
  unfold hypernova_exact_folding_soundness_reduction.
  rewrite Haccepted.
  simpl.
  exact (Hhyp Haccepted).
Qed.
