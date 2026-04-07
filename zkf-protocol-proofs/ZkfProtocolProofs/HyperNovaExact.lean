namespace ZkfProtocolProofs

structure HyperNovaExactSurface where
  ccsMetadataComplete : Prop
  verifierGuardsMatch : Prop
  foldProfileMatches : Prop
  verifierAccepted : Prop

def HyperNovaExactVerifierGuard (surface : HyperNovaExactSurface) : Prop :=
  surface.ccsMetadataComplete ∧ surface.verifierGuardsMatch ∧ surface.foldProfileMatches

def hypernovaExactCompletenessHypothesis (surface : HyperNovaExactSurface) : Prop :=
  HyperNovaExactVerifierGuard surface → surface.verifierAccepted

def hypernovaExactFoldingSoundnessHypothesis (surface : HyperNovaExactSurface) : Prop :=
  surface.verifierAccepted → surface.foldProfileMatches

theorem hypernova_exact_completeness (surface : HyperNovaExactSurface) :
    hypernovaExactCompletenessHypothesis surface →
      HyperNovaExactVerifierGuard surface →
        surface.verifierAccepted := by
  intro hHyp hGuard
  exact hHyp hGuard

theorem hypernova_exact_folding_sound (surface : HyperNovaExactSurface) :
    hypernovaExactFoldingSoundnessHypothesis surface →
      surface.verifierAccepted →
        surface.foldProfileMatches := by
  intro hHyp hAccepted
  exact hHyp hAccepted

end ZkfProtocolProofs
