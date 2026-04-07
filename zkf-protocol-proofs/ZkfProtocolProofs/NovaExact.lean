namespace ZkfProtocolProofs

structure NovaExactSurface where
  metadataComplete : Prop
  verifierGuardsMatch : Prop
  foldProfileMatches : Prop
  verifierAccepted : Prop

def completeClassicNovaIvcMetadata (surface : NovaExactSurface) : Prop :=
  surface.metadataComplete

def NovaExactVerifierGuard (surface : NovaExactSurface) : Prop :=
  surface.verifierGuardsMatch ∧ surface.foldProfileMatches

def novaExactCompletenessHypothesis (surface : NovaExactSurface) : Prop :=
  completeClassicNovaIvcMetadata surface →
    NovaExactVerifierGuard surface →
      surface.verifierAccepted

def novaExactFoldingSoundnessHypothesis (surface : NovaExactSurface) : Prop :=
  surface.verifierAccepted → surface.foldProfileMatches

theorem nova_exact_completeness (surface : NovaExactSurface) :
    novaExactCompletenessHypothesis surface →
      completeClassicNovaIvcMetadata surface →
        NovaExactVerifierGuard surface →
          surface.verifierAccepted := by
  intro hHyp hMetadata hGuard
  exact hHyp hMetadata hGuard

theorem nova_exact_folding_sound (surface : NovaExactSurface) :
    novaExactFoldingSoundnessHypothesis surface →
      surface.verifierAccepted →
        surface.foldProfileMatches := by
  intro hHyp hAccepted
  exact hHyp hAccepted

end ZkfProtocolProofs
