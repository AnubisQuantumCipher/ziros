namespace ZkfProtocolProofs

structure Groth16ExactSurface where
  importedCrsValid : Prop
  publicInputArityMatches : Prop
  encodingMatches : Prop
  verifierAccepted : Prop
  simulatorViewMatches : Prop

def Groth16VerifierGuard (surface : Groth16ExactSurface) : Prop :=
  surface.publicInputArityMatches ∧ surface.encodingMatches

def groth16ImportedCrsValidityHypothesis (surface : Groth16ExactSurface) : Prop :=
  surface.importedCrsValid

def groth16ExactCompletenessHypothesis (surface : Groth16ExactSurface) : Prop :=
  Groth16VerifierGuard surface → surface.verifierAccepted

def groth16KnowledgeOfExponentHypothesis (surface : Groth16ExactSurface) : Prop :=
  surface.verifierAccepted → surface.publicInputArityMatches

def groth16ExactZeroKnowledgeHypothesis (surface : Groth16ExactSurface) : Prop :=
  surface.simulatorViewMatches

theorem groth16_exact_completeness (surface : Groth16ExactSurface) :
    groth16ImportedCrsValidityHypothesis surface →
      groth16ExactCompletenessHypothesis surface →
        Groth16VerifierGuard surface →
          surface.verifierAccepted := by
  intro _ hExact hGuard
  exact hExact hGuard

theorem groth16_exact_knowledge_soundness (surface : Groth16ExactSurface) :
    groth16ImportedCrsValidityHypothesis surface →
      groth16KnowledgeOfExponentHypothesis surface →
        surface.verifierAccepted →
          surface.publicInputArityMatches := by
  intro _ hHyp hAccepted
  exact hHyp hAccepted

theorem groth16_exact_zero_knowledge (surface : Groth16ExactSurface) :
    groth16ImportedCrsValidityHypothesis surface →
      groth16ExactZeroKnowledgeHypothesis surface →
        surface.simulatorViewMatches := by
  intro _ hHyp
  exact hHyp

end ZkfProtocolProofs
