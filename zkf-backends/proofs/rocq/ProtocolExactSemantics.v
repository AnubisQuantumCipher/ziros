Require Import BackendCompat.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_fri_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_groth16_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_hypernova_exact_spec.
From ZkfBackendsExtraction Require Import Zkf_protocol_exact_hax_Proof_nova_exact_spec.

Definition Groth16VerifierGuard (model : t_Groth16ExactSurfaceModel) : Prop :=
  groth16_verifier_guard model = true.

Definition groth16ImportedCrsValidityHypothesis (model : t_Groth16ExactSurfaceModel) : Prop :=
  Groth16ExactSurfaceModel_f_imported_crs_valid model = true.

Definition groth16ExactCompletenessHypothesis (model : t_Groth16ExactSurfaceModel) : Prop :=
  Groth16VerifierGuard model ->
  Groth16ExactSurfaceModel_f_verifier_accepts model = true.

Definition groth16KnowledgeOfExponentHypothesis (model : t_Groth16ExactSurfaceModel) : Prop :=
  Groth16ExactSurfaceModel_f_verifier_accepts model = true ->
  Groth16ExactSurfaceModel_f_public_input_arity_matches model = true.

Definition groth16ExactZeroKnowledgeHypothesis (model : t_Groth16ExactSurfaceModel) : Prop :=
  Groth16ExactSurfaceModel_f_simulator_view_matches model = true.

Definition FriExactVerifierGuard (model : t_FriExactSurfaceModel) : Prop :=
  fri_exact_verifier_guard model = true.

Definition friExactCompletenessHypothesis (model : t_FriExactSurfaceModel) : Prop :=
  FriExactVerifierGuard model -> FriExactSurfaceModel_f_verifier_accepts model = true.

Definition friReedSolomonProximitySoundnessHypothesis (model : t_FriExactSurfaceModel) : Prop :=
  FriExactSurfaceModel_f_verifier_accepts model = true ->
  FriExactSurfaceModel_f_merkle_queries_match model = true.

Definition completeClassicNovaIvcMetadata (model : t_NovaExactSurfaceModel) : Prop :=
  complete_classic_nova_ivc_metadata model = true.

Definition NovaExactVerifierGuard (model : t_NovaExactSurfaceModel) : Prop :=
  nova_exact_verifier_guard model = true.

Definition novaExactCompletenessHypothesis (model : t_NovaExactSurfaceModel) : Prop :=
  completeClassicNovaIvcMetadata model ->
  NovaExactVerifierGuard model ->
  NovaExactSurfaceModel_f_verifier_accepts model = true.

Definition novaExactFoldingSoundnessHypothesis (model : t_NovaExactSurfaceModel) : Prop :=
  NovaExactSurfaceModel_f_verifier_accepts model = true ->
  NovaExactSurfaceModel_f_fold_profile_matches model = true.

Definition HyperNovaExactVerifierGuard (model : t_HyperNovaExactSurfaceModel) : Prop :=
  hypernova_exact_verifier_guard model = true.

Definition hypernovaExactCompletenessHypothesis
  (model : t_HyperNovaExactSurfaceModel)
  : Prop :=
  HyperNovaExactVerifierGuard model ->
  HyperNovaExactSurfaceModel_f_verifier_accepts model = true.

Definition hypernovaExactFoldingSoundnessHypothesis
  (model : t_HyperNovaExactSurfaceModel)
  : Prop :=
  HyperNovaExactSurfaceModel_f_verifier_accepts model = true ->
  HyperNovaExactSurfaceModel_f_fold_profile_matches model = true.
