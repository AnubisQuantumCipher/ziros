namespace ZkfProtocolProofs

structure FriExactSurface where
  transcriptMatches : Prop
  seedReplayMatches : Prop
  merkleQueriesMatch : Prop
  verifierAccepted : Prop

def FriExactVerifierGuard (surface : FriExactSurface) : Prop :=
  surface.transcriptMatches ∧ surface.seedReplayMatches ∧ surface.merkleQueriesMatch

def friExactCompletenessHypothesis (surface : FriExactSurface) : Prop :=
  FriExactVerifierGuard surface → surface.verifierAccepted

def friReedSolomonProximitySoundnessHypothesis (surface : FriExactSurface) : Prop :=
  surface.verifierAccepted → surface.merkleQueriesMatch

theorem fri_exact_completeness (surface : FriExactSurface) :
    friExactCompletenessHypothesis surface →
      FriExactVerifierGuard surface →
        surface.verifierAccepted := by
  intro hExact hGuard
  exact hExact hGuard

theorem fri_exact_proximity_soundness (surface : FriExactSurface) :
    friReedSolomonProximitySoundnessHypothesis surface →
      surface.verifierAccepted →
        surface.merkleQueriesMatch := by
  intro hHyp hAccepted
  exact hHyp hAccepted

end ZkfProtocolProofs
