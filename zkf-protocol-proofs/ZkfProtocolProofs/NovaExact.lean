import ZkfProtocolProofs.GeneratedSnapshots
import ZkfProtocolProofs.ProtocolGoals

namespace ZkfProtocolProofs

def classicNovaExactSurface : RelaxedR1CSSurface := {
  backend := novaSnapshot.backend
  profile := "classic"
  compileScheme := novaSnapshot.compileScheme
  foldScheme := novaSnapshot.foldScheme
  nativeMode := novaSnapshot.nativeMode
  primaryCurve := novaSnapshot.primaryCurve
  secondaryCurve := novaSnapshot.secondaryCurve
  curveCycle := novaSnapshot.curveCycle
  stepArity := novaSnapshot.stepArity
  requiredCompiledMetadata := novaSnapshot.requiredCompiledMetadata
  requiredSingleStepProofMetadata := novaSnapshot.requiredSingleStepProofMetadata
  requiredFoldProofMetadata := novaSnapshot.requiredFoldProofMetadata
  rustFiles := novaSnapshot.rustFiles
}

theorem novaExact_surface :
    novaSnapshot.surface = "nova-hypernova" := rfl

theorem novaExact_backend :
    classicNovaExactSurface.backend = "nova-native" := rfl

theorem novaExact_classicProfilePresent :
    "classic" ∈ novaSnapshot.profiles := by decide

theorem novaExact_compileScheme :
    classicNovaExactSurface.compileScheme = "nova-ivc" := rfl

theorem novaExact_foldScheme :
    classicNovaExactSurface.foldScheme = "nova-ivc-fold" := rfl

theorem novaExact_nativeMode :
    classicNovaExactSurface.nativeMode = "recursive-snark-v2" := rfl

theorem novaExact_primaryCurve :
    classicNovaExactSurface.primaryCurve = "pallas" := rfl

theorem novaExact_secondaryCurve :
    classicNovaExactSurface.secondaryCurve = "vesta" := rfl

theorem novaExact_curveCycle :
    classicNovaExactSurface.curveCycle = "pallas-vesta" := rfl

theorem novaExact_stepArity :
    classicNovaExactSurface.stepArity = 1 := rfl

theorem novaExact_compiledMetadata_count :
    classicNovaExactSurface.requiredCompiledMetadata.length = 6 := rfl

theorem novaExact_singleStepProofMetadata_count :
    classicNovaExactSurface.requiredSingleStepProofMetadata.length = 4 := rfl

theorem novaExact_foldProofMetadata_count :
    classicNovaExactSurface.requiredFoldProofMetadata.length = 9 := rfl

theorem novaExact_compressedFoldSupportsClassic :
    "classic" ∈ novaSnapshot.compressedFoldSupportedProfiles := by
  decide

theorem novaExact_requiredCompiledMetadata_tracks_profile :
    "nova_profile" ∈ classicNovaExactSurface.requiredCompiledMetadata := by
  decide

theorem novaExact_requiredCompiledMetadata_tracks_scheme :
    "scheme" ∈ classicNovaExactSurface.requiredCompiledMetadata := by
  decide

theorem novaExact_requiredSingleStepProofMetadata_tracks_steps :
    "nova_steps" ∈ classicNovaExactSurface.requiredSingleStepProofMetadata := by
  decide

theorem novaExact_requiredFoldProofMetadata_tracks_compression :
    "nova_compressed" ∈ classicNovaExactSurface.requiredFoldProofMetadata := by
  decide

theorem novaExact_requiredFoldProofMetadata_tracks_initial_state :
    "nova_ivc_initial_state" ∈ classicNovaExactSurface.requiredFoldProofMetadata := by
  decide

theorem novaExact_requiredFoldProofMetadata_tracks_final_state :
    "nova_ivc_final_state" ∈ classicNovaExactSurface.requiredFoldProofMetadata := by
  decide

structure ExactNovaCompiledContext where
  backend : String
  profile : String
  compileScheme : String
  foldScheme : String
  nativeMode : String
  primaryCurve : String
  secondaryCurve : String
  curveCycle : String
  stepArity : Nat
  requiredCompiledMetadata : List String
  requiredSingleStepProofMetadata : List String
  requiredFoldProofMetadata : List String
  expectedProgramDigest : String
  expectedVerificationKeyDigest : String
deriving Repr, DecidableEq

structure ExactNovaArtifact (Proof : Type) where
  backend : String
  profile : String
  nativeMode : String
  curveCycle : String
  programDigest : String
  verificationKeyDigest : String
  steps : String
  compressed : Option String
  ivcIn : Option String
  ivcOut : Option String
  ivcInitialState : Option String
  ivcFinalState : Option String
  proof : Proof
deriving Repr, DecidableEq

def completeClassicNovaIvcMetadata {Proof : Type} (artifact : ExactNovaArtifact Proof) : Prop :=
  artifact.ivcIn.isSome = artifact.ivcOut.isSome ∧
    artifact.ivcIn.isSome = artifact.ivcInitialState.isSome ∧
      artifact.ivcIn.isSome = artifact.ivcFinalState.isSome

def shippedNovaCompiledContext
    (programDigest verificationKeyDigest : String) : ExactNovaCompiledContext := {
  backend := classicNovaExactSurface.backend
  profile := classicNovaExactSurface.profile
  compileScheme := classicNovaExactSurface.compileScheme
  foldScheme := classicNovaExactSurface.foldScheme
  nativeMode := classicNovaExactSurface.nativeMode
  primaryCurve := classicNovaExactSurface.primaryCurve
  secondaryCurve := classicNovaExactSurface.secondaryCurve
  curveCycle := classicNovaExactSurface.curveCycle
  stepArity := classicNovaExactSurface.stepArity
  requiredCompiledMetadata := classicNovaExactSurface.requiredCompiledMetadata
  requiredSingleStepProofMetadata := classicNovaExactSurface.requiredSingleStepProofMetadata
  requiredFoldProofMetadata := classicNovaExactSurface.requiredFoldProofMetadata
  expectedProgramDigest := programDigest
  expectedVerificationKeyDigest := verificationKeyDigest
}

def shippedNovaArtifact {Proof : Type}
    (programDigest verificationKeyDigest steps : String)
    (compressed : Option String)
    (ivcIn ivcOut ivcInitialState ivcFinalState : Option String)
    (proof : Proof) : ExactNovaArtifact Proof := {
  backend := classicNovaExactSurface.backend
  profile := classicNovaExactSurface.profile
  nativeMode := classicNovaExactSurface.nativeMode
  curveCycle := classicNovaExactSurface.curveCycle
  programDigest := programDigest
  verificationKeyDigest := verificationKeyDigest
  steps := steps
  compressed := compressed
  ivcIn := ivcIn
  ivcOut := ivcOut
  ivcInitialState := ivcInitialState
  ivcFinalState := ivcFinalState
  proof := proof
}

def exactNovaVerifierGuardsHold {Proof : Type}
    (ctx : ExactNovaCompiledContext)
    (artifact : ExactNovaArtifact Proof) : Prop :=
  ctx.backend = classicNovaExactSurface.backend ∧
    ctx.profile = classicNovaExactSurface.profile ∧
      ctx.compileScheme = classicNovaExactSurface.compileScheme ∧
        ctx.foldScheme = classicNovaExactSurface.foldScheme ∧
          ctx.nativeMode = classicNovaExactSurface.nativeMode ∧
            ctx.primaryCurve = classicNovaExactSurface.primaryCurve ∧
              ctx.secondaryCurve = classicNovaExactSurface.secondaryCurve ∧
                ctx.curveCycle = classicNovaExactSurface.curveCycle ∧
                  ctx.stepArity = classicNovaExactSurface.stepArity ∧
                    "nova_profile" ∈ ctx.requiredCompiledMetadata ∧
                      "scheme" ∈ ctx.requiredCompiledMetadata ∧
                        "nova_steps" ∈ ctx.requiredSingleStepProofMetadata ∧
                          "nova_compressed" ∈ ctx.requiredFoldProofMetadata ∧
                            "nova_ivc_initial_state" ∈ ctx.requiredFoldProofMetadata ∧
                              "nova_ivc_final_state" ∈ ctx.requiredFoldProofMetadata ∧
                                artifact.backend = ctx.backend ∧
                                  artifact.profile = ctx.profile ∧
                                    artifact.nativeMode = ctx.nativeMode ∧
                                      artifact.curveCycle = ctx.curveCycle ∧
                                        artifact.programDigest = ctx.expectedProgramDigest ∧
                                          artifact.verificationKeyDigest =
                                            ctx.expectedVerificationKeyDigest ∧
                                            completeClassicNovaIvcMetadata artifact

def novaExactCompletenessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop) : Prop :=
  ∀ stmt wit, relation stmt wit -> verify stmt (prove stmt wit)

def novaExactFoldingSoundnessHypothesis
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness) : Prop :=
  ∀ stmt proof, verify stmt proof -> relation stmt (extract stmt proof)

def exactNovaVerifierAccepts
    {Statement Proof : Type}
    (verify : Statement -> Proof -> Prop)
    (ctx : ExactNovaCompiledContext)
    (stmt : Statement)
    (artifact : ExactNovaArtifact Proof) : Prop :=
  exactNovaVerifierGuardsHold ctx artifact ∧ verify stmt artifact.proof

theorem shippedNovaVerifierGuardsHold
    {Proof : Type}
    (programDigest verificationKeyDigest steps : String)
    (compressed : Option String)
    (ivcIn ivcOut ivcInitialState ivcFinalState : Option String)
    (proof : Proof)
    (hMetadata :
      completeClassicNovaIvcMetadata
        (shippedNovaArtifact
          programDigest
          verificationKeyDigest
          steps
          compressed
          ivcIn
          ivcOut
          ivcInitialState
          ivcFinalState
          proof)) :
    exactNovaVerifierGuardsHold
      (shippedNovaCompiledContext programDigest verificationKeyDigest)
      (shippedNovaArtifact
        programDigest
        verificationKeyDigest
        steps
        compressed
        ivcIn
        ivcOut
        ivcInitialState
        ivcFinalState
        proof) := by
  dsimp [
    exactNovaVerifierGuardsHold,
    shippedNovaCompiledContext,
    shippedNovaArtifact,
  ]
  refine
    ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_, ?_, ?_, rfl, rfl, rfl,
      rfl, rfl, rfl, hMetadata⟩
  · exact novaExact_requiredCompiledMetadata_tracks_profile
  · exact novaExact_requiredCompiledMetadata_tracks_scheme
  · exact novaExact_requiredSingleStepProofMetadata_tracks_steps
  · exact novaExact_requiredFoldProofMetadata_tracks_compression
  · exact novaExact_requiredFoldProofMetadata_tracks_initial_state
  · exact novaExact_requiredFoldProofMetadata_tracks_final_state

theorem nova_exact_completeness
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (prove : Statement -> Witness -> Proof)
    (verify : Statement -> Proof -> Prop)
    {programDigest verificationKeyDigest steps : String}
    {compressed : Option String}
    {ivcIn ivcOut ivcInitialState ivcFinalState : Option String}
    :
    novaExactCompletenessHypothesis relation prove verify ->
      ∀ {stmt : Statement} {wit : Witness},
        completeClassicNovaIvcMetadata
          (shippedNovaArtifact
            programDigest
            verificationKeyDigest
            steps
            compressed
            ivcIn
            ivcOut
            ivcInitialState
            ivcFinalState
            (prove stmt wit)) ->
        relation stmt wit ->
        exactNovaVerifierAccepts
          verify
          (shippedNovaCompiledContext programDigest verificationKeyDigest)
          stmt
          (shippedNovaArtifact
            programDigest
            verificationKeyDigest
            steps
            compressed
            ivcIn
            ivcOut
            ivcInitialState
            ivcFinalState
            (prove stmt wit)) := by
  intro hCompleteness stmt wit hMetadata hRelation
  refine ⟨?_, ?_⟩
  · exact
      shippedNovaVerifierGuardsHold
        programDigest
        verificationKeyDigest
        steps
        compressed
        ivcIn
        ivcOut
        ivcInitialState
        ivcFinalState
        (prove stmt wit)
        hMetadata
  · exact hCompleteness stmt wit hRelation

theorem nova_exact_folding_sound
    {Statement Witness Proof : Type}
    (relation : Statement -> Witness -> Prop)
    (verify : Statement -> Proof -> Prop)
    (extract : Statement -> Proof -> Witness)
    {stmt : Statement}
    {programDigest verificationKeyDigest : String}
    {artifact : ExactNovaArtifact Proof}
    (hFolding :
      novaExactFoldingSoundnessHypothesis relation verify extract)
    (hAccept :
      exactNovaVerifierAccepts
        verify
        (shippedNovaCompiledContext programDigest verificationKeyDigest)
        stmt
        artifact) :
    relation stmt (extract stmt artifact.proof) := by
  exact hFolding stmt artifact.proof hAccept.2

theorem nova_exact_folding_sound_goal_targets_remaining_ledger_row :
    novaFoldingSoundnessObligation.ledgerTheoremId =
      "protocol.nova_folding_soundness" := rfl

theorem nova_exact_completeness_goal_targets_remaining_ledger_row :
    novaCompletenessObligation.ledgerTheoremId =
      "protocol.nova_completeness" := rfl

end ZkfProtocolProofs
