import ZkfProtocolProofs.GeneratedSnapshots
import ZkfProtocolProofs.ProtocolGoals

namespace ZkfProtocolProofs

def friExactTranscriptSurface : FriTranscriptSurface := {
  backend := friSnapshot.backend
  scheme := friSnapshot.scheme
  pcs := friSnapshot.pcs
  plonky3Version := friSnapshot.plonky3Version
  seedDerivation := friSnapshot.seedDerivation
  wrapperSurface := friSnapshot.wrapperSurface
  wrapperStatuses := friSnapshot.wrapperStatuses
  wrapperStrategies := friSnapshot.wrapperStrategies
  wrapperSemantics := friSnapshot.wrapperSemantics
  sourceVerificationSemantics := friSnapshot.sourceVerificationSemantics
  requiredProofMetadata := friSnapshot.requiredProofMetadata
  rustFiles := friSnapshot.rustFiles
}

def friExactReedSolomonSurface : ReedSolomonDomainSurface := {
  backend := friSnapshot.backend
  pcs := friSnapshot.pcs
  wrapperSurface := friSnapshot.wrapperSurface
  transcriptSeed := friSnapshot.seedDerivation
  wrapperStrategies := friSnapshot.wrapperStrategies
  wrapperStatuses := friSnapshot.wrapperStatuses
  rustFiles := friSnapshot.rustFiles
}

theorem friExact_surface :
    friSnapshot.surface = "fri" := rfl

theorem friExact_backend :
    friExactTranscriptSurface.backend = "plonky3" := rfl

theorem friExact_scheme :
    friExactTranscriptSurface.scheme = "stark" := rfl

theorem friExact_pcs :
    friExactTranscriptSurface.pcs = "fri" := rfl

theorem friExact_versionPinned :
    friExactTranscriptSurface.plonky3Version = "0.4.2" := rfl

theorem friExact_seedDerivation :
    friExactTranscriptSurface.seedDerivation = "program-digest" := rfl

theorem friExact_wrapperSurface :
    friExactTranscriptSurface.wrapperSurface = "stark-to-groth16" := rfl

theorem friExact_wrapperStatuses_count :
    friExactTranscriptSurface.wrapperStatuses.length = 2 := rfl

theorem friExact_wrapperStrategies_count :
    friExactTranscriptSurface.wrapperStrategies.length = 2 := rfl

theorem friExact_wrapperSemantics_count :
    friExactTranscriptSurface.wrapperSemantics.length = 2 := rfl

theorem friExact_requiredProofMetadata_count :
    friExactTranscriptSurface.requiredProofMetadata.length = 4 := rfl

theorem friExact_requiredProofMetadata_tracks_field :
    "field" ∈ friExactTranscriptSurface.requiredProofMetadata := by
  decide

theorem friExact_requiredProofMetadata_tracks_scheme :
    "scheme" ∈ friExactTranscriptSurface.requiredProofMetadata := by
  decide

theorem friExact_requiredProofMetadata_tracks_pcs :
    "pcs" ∈ friExactTranscriptSurface.requiredProofMetadata := by
  decide

theorem friExact_requiredProofMetadata_tracks_seed :
    "seed" ∈ friExactTranscriptSurface.requiredProofMetadata := by
  decide

theorem friExact_supports_direct_strict_wrap :
    "direct-fri-v2" ∈ friExactTranscriptSurface.wrapperStrategies := by
  decide

theorem friExact_supports_compressed_wrap_surface :
    "nova-compressed-v3" ∈ friExactTranscriptSurface.wrapperStrategies := by
  decide

theorem friExact_wrapper_replays_circuit_surface :
    "circuit-replayed" ∈ friExactTranscriptSurface.sourceVerificationSemantics := by
  decide

theorem friExact_wrapper_tracks_nova_compressed_attestation :
    "nova-compressed-attestation-binding" ∈ friExactTranscriptSurface.wrapperSemantics := by
  decide

theorem friExact_wrapper_tracks_fri_verifier_circuit :
    "fri-verifier-circuit" ∈ friExactTranscriptSurface.wrapperSemantics := by
  decide

theorem friExact_sourceVerification_tracks_host_compressed_check :
    "host-compressed-check" ∈ friExactTranscriptSurface.sourceVerificationSemantics := by
  decide

theorem friExact_reed_solomon_surface_uses_same_wrapper :
    friExactReedSolomonSurface.wrapperSurface =
      friExactTranscriptSurface.wrapperSurface := rfl

structure ExactFriCompiledContext where
  backend : String
  scheme : String
  pcs : String
  plonky3Version : String
  seedDerivation : String
  wrapperSurface : String
  wrapperStrategies : List String
  wrapperSemantics : List String
  sourceVerificationSemantics : List String
  requiredProofMetadata : List String
  expectedField : String
  expectedProgramDigest : String
  expectedVerificationKeyDigest : String
  expectedSeed : String
deriving Repr, DecidableEq

structure ExactFriArtifact (Proof : Type) where
  backend : String
  field : String
  scheme : String
  pcs : String
  programDigest : String
  verificationKeyDigest : String
  seed : String
  proof : Proof
deriving Repr, DecidableEq

def shippedFriSeed (programDigest : String) : String :=
  "plonky3-seed:" ++ programDigest

def shippedFriCompiledContext
    (field programDigest verificationKeyDigest : String) : ExactFriCompiledContext := {
  backend := friExactTranscriptSurface.backend
  scheme := friExactTranscriptSurface.scheme
  pcs := friExactTranscriptSurface.pcs
  plonky3Version := friExactTranscriptSurface.plonky3Version
  seedDerivation := friExactTranscriptSurface.seedDerivation
  wrapperSurface := friExactTranscriptSurface.wrapperSurface
  wrapperStrategies := friExactTranscriptSurface.wrapperStrategies
  wrapperSemantics := friExactTranscriptSurface.wrapperSemantics
  sourceVerificationSemantics := friExactTranscriptSurface.sourceVerificationSemantics
  requiredProofMetadata := friExactTranscriptSurface.requiredProofMetadata
  expectedField := field
  expectedProgramDigest := programDigest
  expectedVerificationKeyDigest := verificationKeyDigest
  expectedSeed := shippedFriSeed programDigest
}

def shippedFriArtifact {Proof : Type}
    (field programDigest verificationKeyDigest : String)
    (proof : Proof) : ExactFriArtifact Proof := {
  backend := friExactTranscriptSurface.backend
  field := field
  scheme := friExactTranscriptSurface.scheme
  pcs := friExactTranscriptSurface.pcs
  programDigest := programDigest
  verificationKeyDigest := verificationKeyDigest
  seed := shippedFriSeed programDigest
  proof := proof
}

def exactFriVerifierGuardsHold {Proof : Type}
    (ctx : ExactFriCompiledContext)
    (artifact : ExactFriArtifact Proof) : Prop :=
  ctx.backend = friExactTranscriptSurface.backend ∧
    ctx.scheme = friExactTranscriptSurface.scheme ∧
      ctx.pcs = friExactTranscriptSurface.pcs ∧
        ctx.plonky3Version = friExactTranscriptSurface.plonky3Version ∧
          ctx.seedDerivation = friExactTranscriptSurface.seedDerivation ∧
            ctx.wrapperSurface = friExactTranscriptSurface.wrapperSurface ∧
              "field" ∈ ctx.requiredProofMetadata ∧
                "scheme" ∈ ctx.requiredProofMetadata ∧
                  "pcs" ∈ ctx.requiredProofMetadata ∧
                    "seed" ∈ ctx.requiredProofMetadata ∧
                      "direct-fri-v2" ∈ ctx.wrapperStrategies ∧
                        "nova-compressed-v3" ∈ ctx.wrapperStrategies ∧
                          "fri-verifier-circuit" ∈ ctx.wrapperSemantics ∧
                            "nova-compressed-attestation-binding" ∈ ctx.wrapperSemantics ∧
                              "circuit-replayed" ∈ ctx.sourceVerificationSemantics ∧
                                "host-compressed-check" ∈ ctx.sourceVerificationSemantics ∧
                                  artifact.backend = ctx.backend ∧
                                    artifact.field = ctx.expectedField ∧
                                      artifact.scheme = ctx.scheme ∧
                                        artifact.pcs = ctx.pcs ∧
                                          artifact.programDigest = ctx.expectedProgramDigest ∧
                                            artifact.verificationKeyDigest =
                                              ctx.expectedVerificationKeyDigest ∧
                                              artifact.seed = ctx.expectedSeed

def friExactCompletenessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop) : Prop :=
  ∀ stmt wit, relation stmt wit -> verify stmt (prove stmt wit)

def friReedSolomonProximitySoundnessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness) : Prop :=
  ∀ stmt proof, verify stmt proof -> relation stmt (extract stmt proof)

def exactFriVerifierAccepts
    {Statement Proof : Type}
    (verify : Statement -> Proof -> Prop)
    (ctx : ExactFriCompiledContext)
    (stmt : Statement)
    (artifact : ExactFriArtifact Proof) : Prop :=
  exactFriVerifierGuardsHold ctx artifact ∧ verify stmt artifact.proof

theorem shippedFriVerifierGuardsHold
    {Proof : Type}
    (field programDigest verificationKeyDigest : String)
    (proof : Proof) :
    exactFriVerifierGuardsHold
      (shippedFriCompiledContext field programDigest verificationKeyDigest)
      (shippedFriArtifact field programDigest verificationKeyDigest proof) := by
  simp [
    exactFriVerifierGuardsHold,
    shippedFriCompiledContext,
    shippedFriArtifact,
    shippedFriSeed,
    friExact_requiredProofMetadata_tracks_field,
    friExact_requiredProofMetadata_tracks_scheme,
    friExact_requiredProofMetadata_tracks_pcs,
    friExact_requiredProofMetadata_tracks_seed,
    friExact_supports_direct_strict_wrap,
    friExact_supports_compressed_wrap_surface,
    friExact_wrapper_tracks_fri_verifier_circuit,
    friExact_wrapper_tracks_nova_compressed_attestation,
    friExact_wrapper_replays_circuit_surface,
    friExact_sourceVerification_tracks_host_compressed_check,
  ]

theorem fri_exact_completeness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop)
    (field programDigest verificationKeyDigest : String) :
    friExactCompletenessHypothesis relation prove verify ->
      ∀ {stmt : Statement} {wit : Witness},
        relation stmt wit ->
        exactFriVerifierAccepts
          verify
          (shippedFriCompiledContext field programDigest verificationKeyDigest)
          stmt
          (shippedFriArtifact
            field
            programDigest
            verificationKeyDigest
            (prove stmt wit)) := by
  intro hCompleteness stmt wit hRelation
  refine ⟨?_, ?_⟩
  · exact
      shippedFriVerifierGuardsHold
        field
        programDigest
        verificationKeyDigest
        (prove stmt wit)
  · exact hCompleteness stmt wit hRelation

theorem fri_exact_proximity_soundness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness)
    {stmt : Statement}
    {field programDigest verificationKeyDigest : String}
    {artifact : ExactFriArtifact Proof}
    (hProximity :
      friReedSolomonProximitySoundnessHypothesis relation verify extract)
    (hAccept :
      exactFriVerifierAccepts
        verify
        (shippedFriCompiledContext field programDigest verificationKeyDigest)
        stmt
        artifact) :
    relation stmt (extract stmt artifact.proof) := by
  exact hProximity stmt artifact.proof hAccept.2

theorem fri_exact_proximity_soundness_goal_targets_remaining_ledger_row :
    friProximitySoundnessObligation.ledgerTheoremId =
      "protocol.fri_proximity_soundness" := rfl

theorem fri_exact_completeness_goal_targets_remaining_ledger_row :
    friCompletenessObligation.ledgerTheoremId =
      "protocol.fri_completeness" := rfl

end ZkfProtocolProofs
