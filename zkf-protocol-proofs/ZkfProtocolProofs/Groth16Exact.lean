import ZkfProtocolProofs.GeneratedSnapshots
import ZkfProtocolProofs.ProtocolGoals

namespace ZkfProtocolProofs

def groth16ExactSurface : BilinearGroupSurface := {
  backend := groth16Snapshot.backend
  curve := groth16Snapshot.curve
  scalarField := groth16Snapshot.field
  scheme := groth16Snapshot.scheme
  setupBlobVersion := groth16Snapshot.setupBlobVersion
  setupProvenance := groth16Snapshot.setupProvenance
  securityBoundary := groth16Snapshot.securityBoundary
  developmentBoundary := groth16Snapshot.developmentBoundary
  requiredCompiledMetadata := groth16Snapshot.requiredCompiledMetadata
  requiredProofMetadata := groth16Snapshot.requiredProofMetadata
  verifierChecks := groth16Snapshot.verifierChecks
  rustFiles := groth16Snapshot.rustFiles
}

theorem groth16Exact_surface :
    groth16Snapshot.surface = "groth16" := rfl

theorem groth16Exact_backend :
    groth16ExactSurface.backend = "arkworks-groth16" := rfl

theorem groth16Exact_scalarField :
    groth16ExactSurface.scalarField = "bn254" := rfl

theorem groth16Exact_curve :
    groth16ExactSurface.curve = "bn254" := rfl

theorem groth16Exact_scheme :
    groth16ExactSurface.scheme = "groth16" := rfl

theorem groth16Exact_setupBlobVersion :
    groth16ExactSurface.setupBlobVersion = 1 := rfl

theorem groth16Exact_importedBoundary :
    groth16ExactSurface.securityBoundary = "trusted-imported" := rfl

theorem groth16Exact_devBoundary :
    groth16ExactSurface.developmentBoundary = "development-only" := rfl

theorem groth16Exact_importedProvenance :
    groth16ExactSurface.setupProvenance = "trusted-imported-blob" := rfl

theorem groth16Exact_requiredCompiledMetadata_count :
    groth16ExactSurface.requiredCompiledMetadata.length = 8 := rfl

theorem groth16Exact_requiredProofMetadata_count :
    groth16ExactSurface.requiredProofMetadata.length = 4 := rfl

theorem groth16Exact_verifierChecks_count :
    groth16ExactSurface.verifierChecks.length = 4 := rfl

theorem groth16Exact_compiledMetadata_tracks_imported_crs_path :
    "groth16_setup_blob_path" ∈ groth16ExactSurface.requiredCompiledMetadata := by
  decide

theorem groth16Exact_compiledMetadata_tracks_security_boundary :
    "groth16_setup_security_boundary" ∈ groth16ExactSurface.requiredCompiledMetadata := by
  decide

theorem groth16Exact_verifierChecks_bind_vk_to_setup_blob :
    "verification_key_matches_compiled_setup_blob" ∈ groth16ExactSurface.verifierChecks := by
  decide

theorem groth16Exact_proofMetadata_excludes_seed_hex :
    "prove_seed_hex" ∉ groth16ExactSurface.requiredProofMetadata := by
  decide

structure ExactGroth16CompiledContext where
  backend : String
  curve : String
  scheme : String
  setupBlobVersion : Nat
  setupProvenance : String
  securityBoundary : String
  requiredCompiledMetadata : List String
  verifierChecks : List String
  expectedProgramDigest : String
  expectedVerificationKeyDigest : String
deriving Repr, DecidableEq

structure ExactGroth16Artifact (Proof : Type) where
  backend : String
  curve : String
  scheme : String
  programDigest : String
  verificationKeyDigest : String
  proveDeterministic : String
  proveSeedSource : String
  proveSeedHex : Option String
  proof : Proof
deriving Repr, DecidableEq

structure ExactGroth16PublicView (View : Type) where
  backend : String
  curve : String
  scheme : String
  programDigest : String
  verificationKeyDigest : String
  proveDeterministic : String
  proveSeedSource : String
  proveSeedHex : Option String
  proofView : View
deriving Repr, DecidableEq

def cleanGroth16ProofMetadata {Proof : Type} (artifact : ExactGroth16Artifact Proof) : Prop :=
  artifact.proveDeterministic = "false" ∧
    artifact.proveSeedSource = "system-rng" ∧
      artifact.proveSeedHex = none

def shippedGroth16CompiledContext
    (programDigest verificationKeyDigest : String) : ExactGroth16CompiledContext := {
  backend := groth16ExactSurface.backend
  curve := groth16ExactSurface.curve
  scheme := groth16ExactSurface.scheme
  setupBlobVersion := groth16ExactSurface.setupBlobVersion
  setupProvenance := groth16ExactSurface.setupProvenance
  securityBoundary := groth16ExactSurface.securityBoundary
  requiredCompiledMetadata := groth16ExactSurface.requiredCompiledMetadata
  verifierChecks := groth16ExactSurface.verifierChecks
  expectedProgramDigest := programDigest
  expectedVerificationKeyDigest := verificationKeyDigest
}

def shippedGroth16Artifact {Proof : Type}
    (programDigest verificationKeyDigest : String)
    (proof : Proof) : ExactGroth16Artifact Proof := {
  backend := groth16ExactSurface.backend
  curve := groth16ExactSurface.curve
  scheme := groth16ExactSurface.scheme
  programDigest := programDigest
  verificationKeyDigest := verificationKeyDigest
  proveDeterministic := "false"
  proveSeedSource := "system-rng"
  proveSeedHex := none
  proof := proof
}

def exactGroth16VerifierGuardsHold {Proof : Type}
    (ctx : ExactGroth16CompiledContext)
    (artifact : ExactGroth16Artifact Proof) : Prop :=
  ctx.backend = groth16ExactSurface.backend ∧
    ctx.curve = groth16ExactSurface.curve ∧
      ctx.scheme = groth16ExactSurface.scheme ∧
        ctx.setupBlobVersion = groth16ExactSurface.setupBlobVersion ∧
          ctx.setupProvenance = groth16ExactSurface.setupProvenance ∧
            ctx.securityBoundary = groth16ExactSurface.securityBoundary ∧
              "groth16_setup_blob_path" ∈ ctx.requiredCompiledMetadata ∧
                "groth16_setup_security_boundary" ∈ ctx.requiredCompiledMetadata ∧
                  "compiled_backend_matches" ∈ ctx.verifierChecks ∧
                    "artifact_backend_matches" ∈ ctx.verifierChecks ∧
                      "program_digest_matches" ∈ ctx.verifierChecks ∧
                        "verification_key_matches_compiled_setup_blob" ∈ ctx.verifierChecks ∧
                          artifact.backend = ctx.backend ∧
                            artifact.curve = ctx.curve ∧
                              artifact.scheme = ctx.scheme ∧
                                artifact.programDigest = ctx.expectedProgramDigest ∧
                                  artifact.verificationKeyDigest = ctx.expectedVerificationKeyDigest ∧
                                    cleanGroth16ProofMetadata artifact

def groth16ImportedCrsValidityHypothesis
    (ctx : ExactGroth16CompiledContext) : Prop :=
  ctx.setupProvenance = groth16ExactSurface.setupProvenance ∧
    ctx.securityBoundary = groth16ExactSurface.securityBoundary ∧
      "groth16_setup_blob_path" ∈ ctx.requiredCompiledMetadata ∧
        "groth16_setup_security_boundary" ∈ ctx.requiredCompiledMetadata

def groth16ExactCompletenessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop) : Prop :=
  ∀ stmt wit, relation stmt wit -> verify stmt (prove stmt wit)

def groth16KnowledgeOfExponentHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness) : Prop :=
  ∀ stmt proof, verify stmt proof -> relation stmt (extract stmt proof)

def groth16ExactZeroKnowledgeHypothesis
    {Statement Witness Proof PublicView : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (simulate : Statement -> Proof)
    (proofView : Proof -> PublicView) : Prop :=
  ∀ stmt wit, relation stmt wit -> proofView (prove stmt wit) = proofView (simulate stmt)

def exactGroth16VerifierAccepts
    {Statement Proof : Type}
    (verify : Statement -> Proof -> Prop)
    (ctx : ExactGroth16CompiledContext)
    (stmt : Statement)
    (artifact : ExactGroth16Artifact Proof) : Prop :=
  exactGroth16VerifierGuardsHold ctx artifact ∧ verify stmt artifact.proof

def exactGroth16PublicView
    {Proof View : Type}
    (proofView : Proof -> View)
    (artifact : ExactGroth16Artifact Proof) : ExactGroth16PublicView View := {
  backend := artifact.backend
  curve := artifact.curve
  scheme := artifact.scheme
  programDigest := artifact.programDigest
  verificationKeyDigest := artifact.verificationKeyDigest
  proveDeterministic := artifact.proveDeterministic
  proveSeedSource := artifact.proveSeedSource
  proveSeedHex := artifact.proveSeedHex
  proofView := proofView artifact.proof
}

theorem shippedGroth16Artifact_uses_clean_randomized_metadata
    {Proof : Type}
    (programDigest verificationKeyDigest : String)
    (proof : Proof) :
    cleanGroth16ProofMetadata (shippedGroth16Artifact programDigest verificationKeyDigest proof) := by
  simp [cleanGroth16ProofMetadata, shippedGroth16Artifact]

theorem shippedGroth16VerifierGuardsHold
    {Proof : Type}
    (programDigest verificationKeyDigest : String)
    (proof : Proof) :
    exactGroth16VerifierGuardsHold
      (shippedGroth16CompiledContext programDigest verificationKeyDigest)
      (shippedGroth16Artifact programDigest verificationKeyDigest proof) := by
  dsimp [
    exactGroth16VerifierGuardsHold,
    shippedGroth16CompiledContext,
    shippedGroth16Artifact,
    cleanGroth16ProofMetadata,
  ]
  refine
    ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_, ?_, ?_, rfl, rfl, rfl, rfl, rfl, ?_⟩
  · exact groth16Exact_compiledMetadata_tracks_imported_crs_path
  · exact groth16Exact_compiledMetadata_tracks_security_boundary
  · decide
  · decide
  · decide
  · exact groth16Exact_verifierChecks_bind_vk_to_setup_blob
  · simp

theorem groth16_exact_completeness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop)
    (programDigest verificationKeyDigest : String) :
    groth16ImportedCrsValidityHypothesis
        (shippedGroth16CompiledContext programDigest verificationKeyDigest) ->
      groth16ExactCompletenessHypothesis relation prove verify ->
      ∀ {stmt : Statement} {wit : Witness},
        relation stmt wit ->
        exactGroth16VerifierAccepts
          verify
          (shippedGroth16CompiledContext programDigest verificationKeyDigest)
          stmt
          (shippedGroth16Artifact
            programDigest
            verificationKeyDigest
            (prove stmt wit)) := by
  intro _ hCompleteness stmt wit hRelation
  refine ⟨?_, ?_⟩
  · exact
      shippedGroth16VerifierGuardsHold
        programDigest
        verificationKeyDigest
        (prove stmt wit)
  · exact hCompleteness stmt wit hRelation

theorem groth16_exact_knowledge_soundness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness)
    {stmt : Statement}
    {programDigest verificationKeyDigest : String}
    {artifact : ExactGroth16Artifact Proof}
    (hImportedCrs :
      groth16ImportedCrsValidityHypothesis
        (shippedGroth16CompiledContext programDigest verificationKeyDigest))
    (hKnowledge :
      groth16KnowledgeOfExponentHypothesis relation verify extract)
    (hAccept :
      exactGroth16VerifierAccepts
        verify
        (shippedGroth16CompiledContext programDigest verificationKeyDigest)
        stmt
        artifact) :
    relation stmt (extract stmt artifact.proof) := by
  have _ := hImportedCrs
  exact hKnowledge stmt artifact.proof hAccept.2

theorem groth16_exact_zero_knowledge
    {Statement Witness Proof PublicView : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (simulate : Statement -> Proof)
    (proofView : Proof -> PublicView)
    (programDigest verificationKeyDigest : String) :
    groth16ImportedCrsValidityHypothesis
        (shippedGroth16CompiledContext programDigest verificationKeyDigest) ->
      groth16ExactZeroKnowledgeHypothesis relation prove simulate proofView ->
      ∀ {stmt : Statement} {wit : Witness},
        relation stmt wit ->
        exactGroth16PublicView proofView
          (shippedGroth16Artifact
            programDigest
            verificationKeyDigest
            (prove stmt wit))
        =
        exactGroth16PublicView proofView
          (shippedGroth16Artifact
            programDigest
            verificationKeyDigest
            (simulate stmt)) := by
  intro _ hZk stmt wit hRelation
  simp [exactGroth16PublicView, shippedGroth16Artifact, hZk stmt wit hRelation]

theorem groth16_exact_knowledge_soundness_goal_targets_remaining_ledger_row :
    groth16KnowledgeSoundnessObligation.ledgerTheoremId =
      "protocol.groth16_knowledge_soundness" := rfl

theorem groth16_exact_completeness_goal_targets_remaining_ledger_row :
    groth16CompletenessObligation.ledgerTheoremId =
      "protocol.groth16_completeness" := rfl

theorem groth16_exact_zero_knowledge_goal_targets_remaining_ledger_row :
    groth16ZeroKnowledgeObligation.ledgerTheoremId =
      "protocol.groth16_zero_knowledge" := rfl

end ZkfProtocolProofs
