import ZkfProtocolProofs.GeneratedSnapshots
import ZkfProtocolProofs.ProtocolGoals

namespace ZkfProtocolProofs

def hyperNovaExactSurface : HyperNovaCcsSurface := {
  backend := novaSnapshot.backend
  profile := "hypernova"
  compileScheme := novaSnapshot.compileScheme
  nativeMode := novaSnapshot.nativeMode
  primaryCurve := novaSnapshot.primaryCurve
  secondaryCurve := novaSnapshot.secondaryCurve
  curveCycle := novaSnapshot.curveCycle
  stepArity := novaSnapshot.stepArity
  requiredCompiledMetadata := novaSnapshot.requiredCompiledMetadata
  requiredSingleStepProofMetadata := novaSnapshot.requiredSingleStepProofMetadata
  rustFiles := novaSnapshot.rustFiles
}

theorem hypernovaExact_profilePresent :
    "hypernova" ∈ novaSnapshot.profiles := by
  decide

theorem hypernovaExact_compileScheme :
    hyperNovaExactSurface.compileScheme = "nova-ivc" := rfl

theorem hypernovaExact_nativeMode :
    hyperNovaExactSurface.nativeMode = "recursive-snark-v2" := rfl

theorem hypernovaExact_curvePairMatchesNovaBoundary :
    (hyperNovaExactSurface.primaryCurve, hyperNovaExactSurface.secondaryCurve) =
      ("pallas", "vesta") := rfl

theorem hypernovaExact_curveCycle :
    hyperNovaExactSurface.curveCycle = "pallas-vesta" := rfl

theorem hypernovaExact_stepArity :
    hyperNovaExactSurface.stepArity = 1 := rfl

theorem hypernovaExact_not_in_compressedFoldSurface :
    "hypernova" ∉ novaSnapshot.compressedFoldSupportedProfiles := by
  decide

theorem hypernovaExact_requiredCompiledMetadata_tracks_profile :
    "nova_profile" ∈ hyperNovaExactSurface.requiredCompiledMetadata := by
  decide

theorem hypernovaExact_requiredCompiledMetadata_tracks_scheme :
    "scheme" ∈ hyperNovaExactSurface.requiredCompiledMetadata := by
  decide

theorem hypernovaExact_requiredSingleStepProofMetadata_tracks_steps :
    "nova_steps" ∈ hyperNovaExactSurface.requiredSingleStepProofMetadata := by
  decide

structure ExactHyperNovaCompiledContext where
  backend : String
  profile : String
  compileScheme : String
  scheme : String
  nativeMode : String
  primaryCurve : String
  secondaryCurve : String
  curveCycle : String
  stepArity : Nat
  requiredCompiledMetadata : List String
  requiredSingleStepProofMetadata : List String
  expectedProgramDigest : String
  expectedVerificationKeyDigest : String
deriving Repr, DecidableEq

structure ExactHyperNovaArtifact (Proof : Type) where
  backend : String
  profile : String
  nativeMode : String
  curveCycle : String
  programDigest : String
  verificationKeyDigest : String
  steps : String
  proof : Proof
deriving Repr, DecidableEq

def shippedHyperNovaCompiledContext
    (programDigest verificationKeyDigest : String) : ExactHyperNovaCompiledContext := {
  backend := hyperNovaExactSurface.backend
  profile := hyperNovaExactSurface.profile
  compileScheme := hyperNovaExactSurface.compileScheme
  scheme := "hypernova-ccs-ivc"
  nativeMode := hyperNovaExactSurface.nativeMode
  primaryCurve := hyperNovaExactSurface.primaryCurve
  secondaryCurve := hyperNovaExactSurface.secondaryCurve
  curveCycle := hyperNovaExactSurface.curveCycle
  stepArity := hyperNovaExactSurface.stepArity
  requiredCompiledMetadata := hyperNovaExactSurface.requiredCompiledMetadata
  requiredSingleStepProofMetadata := hyperNovaExactSurface.requiredSingleStepProofMetadata
  expectedProgramDigest := programDigest
  expectedVerificationKeyDigest := verificationKeyDigest
}

def shippedHyperNovaArtifact {Proof : Type}
    (programDigest verificationKeyDigest steps : String)
    (proof : Proof) : ExactHyperNovaArtifact Proof := {
  backend := hyperNovaExactSurface.backend
  profile := hyperNovaExactSurface.profile
  nativeMode := hyperNovaExactSurface.nativeMode
  curveCycle := hyperNovaExactSurface.curveCycle
  programDigest := programDigest
  verificationKeyDigest := verificationKeyDigest
  steps := steps
  proof := proof
}

def exactHyperNovaVerifierGuardsHold {Proof : Type}
    (ctx : ExactHyperNovaCompiledContext)
    (artifact : ExactHyperNovaArtifact Proof) : Prop :=
  ctx.backend = hyperNovaExactSurface.backend ∧
    ctx.profile = hyperNovaExactSurface.profile ∧
      ctx.compileScheme = hyperNovaExactSurface.compileScheme ∧
        ctx.scheme = "hypernova-ccs-ivc" ∧
          ctx.nativeMode = hyperNovaExactSurface.nativeMode ∧
            ctx.primaryCurve = hyperNovaExactSurface.primaryCurve ∧
              ctx.secondaryCurve = hyperNovaExactSurface.secondaryCurve ∧
                ctx.curveCycle = hyperNovaExactSurface.curveCycle ∧
                  ctx.stepArity = hyperNovaExactSurface.stepArity ∧
                    "nova_profile" ∈ ctx.requiredCompiledMetadata ∧
                      "scheme" ∈ ctx.requiredCompiledMetadata ∧
                        "nova_steps" ∈ ctx.requiredSingleStepProofMetadata ∧
                          artifact.backend = ctx.backend ∧
                            artifact.profile = ctx.profile ∧
                              artifact.nativeMode = ctx.nativeMode ∧
                                artifact.curveCycle = ctx.curveCycle ∧
                                  artifact.programDigest = ctx.expectedProgramDigest ∧
                                    artifact.verificationKeyDigest =
                                      ctx.expectedVerificationKeyDigest

def hypernovaExactCompletenessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop) : Prop :=
  ∀ stmt wit, relation stmt wit -> verify stmt (prove stmt wit)

def hypernovaExactFoldingSoundnessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness) : Prop :=
  ∀ stmt proof, verify stmt proof -> relation stmt (extract stmt proof)

def exactHyperNovaVerifierAccepts
    {Statement Proof : Type}
    (verify : Statement -> Proof -> Prop)
    (ctx : ExactHyperNovaCompiledContext)
    (stmt : Statement)
    (artifact : ExactHyperNovaArtifact Proof) : Prop :=
  exactHyperNovaVerifierGuardsHold ctx artifact ∧ verify stmt artifact.proof

theorem shippedHyperNovaVerifierGuardsHold
    {Proof : Type}
    (programDigest verificationKeyDigest steps : String)
    (proof : Proof) :
    exactHyperNovaVerifierGuardsHold
      (shippedHyperNovaCompiledContext programDigest verificationKeyDigest)
      (shippedHyperNovaArtifact programDigest verificationKeyDigest steps proof) := by
  dsimp [
    exactHyperNovaVerifierGuardsHold,
    shippedHyperNovaCompiledContext,
    shippedHyperNovaArtifact,
  ]
  refine
    ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, rfl, rfl, rfl, rfl,
      rfl, rfl⟩
  · exact hypernovaExact_requiredCompiledMetadata_tracks_profile
  · exact hypernovaExact_requiredCompiledMetadata_tracks_scheme
  · exact hypernovaExact_requiredSingleStepProofMetadata_tracks_steps

theorem hypernova_exact_completeness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop)
    (programDigest verificationKeyDigest steps : String) :
    hypernovaExactCompletenessHypothesis relation prove verify ->
      ∀ {stmt : Statement} {wit : Witness},
        relation stmt wit ->
        exactHyperNovaVerifierAccepts
          verify
          (shippedHyperNovaCompiledContext programDigest verificationKeyDigest)
          stmt
          (shippedHyperNovaArtifact
            programDigest
            verificationKeyDigest
            steps
            (prove stmt wit)) := by
  intro hCompleteness stmt wit hRelation
  refine ⟨?_, ?_⟩
  · exact
      shippedHyperNovaVerifierGuardsHold
        programDigest
        verificationKeyDigest
        steps
        (prove stmt wit)
  · exact hCompleteness stmt wit hRelation

theorem hypernova_exact_folding_sound
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness)
    {stmt : Statement}
    {programDigest verificationKeyDigest : String}
    {artifact : ExactHyperNovaArtifact Proof}
    (hFolding :
      hypernovaExactFoldingSoundnessHypothesis relation verify extract)
    (hAccept :
      exactHyperNovaVerifierAccepts
        verify
        (shippedHyperNovaCompiledContext programDigest verificationKeyDigest)
        stmt
        artifact) :
    relation stmt (extract stmt artifact.proof) := by
  exact hFolding stmt artifact.proof hAccept.2

theorem hypernova_exact_folding_sound_goal_targets_remaining_ledger_row :
    hypernovaFoldingSoundnessObligation.ledgerTheoremId =
      "protocol.hypernova_folding_soundness" := rfl

theorem hypernova_exact_completeness_goal_targets_remaining_ledger_row :
    hypernovaCompletenessObligation.ledgerTheoremId =
      "protocol.hypernova_completeness" := rfl

end ZkfProtocolProofs
