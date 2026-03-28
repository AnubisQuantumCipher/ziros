import ZkfProtocolProofs.Common

namespace ZkfProtocolProofs

def groth16KnowledgeSoundnessObligation : ProtocolProofObligation := {
  theoremName := "groth16_exact_knowledge_soundness"
  ledgerTheoremId := "protocol.groth16_knowledge_soundness"
  scope := "zkf-backends::arkworks"
  targetSurface := "groth16"
  statementSummary :=
    "If the exact shipped Groth16 verifier accepts, the prover knows a witness satisfying the exact relation under the explicit imported-CRS and KEA-style theorem hypotheses."
  blockingAssumptions := [
    "groth16ImportedCrsValidityHypothesis",
    "groth16KnowledgeOfExponentHypothesis"
  ]
}

def groth16ZeroKnowledgeObligation : ProtocolProofObligation := {
  theoremName := "groth16_exact_zero_knowledge"
  ledgerTheoremId := "protocol.groth16_zero_knowledge"
  scope := "zkf-backends::arkworks"
  targetSurface := "groth16"
  statementSummary :=
    "The exact shipped Groth16 proof surface is zero-knowledge under the explicit imported-CRS and simulator-view theorem hypotheses."
  blockingAssumptions := [
    "groth16ImportedCrsValidityHypothesis",
    "groth16ExactZeroKnowledgeHypothesis"
  ]
}

def groth16CompletenessObligation : ProtocolProofObligation := {
  theoremName := "groth16_exact_completeness"
  ledgerTheoremId := "protocol.groth16_completeness"
  scope := "zkf-backends::arkworks"
  targetSurface := "groth16"
  statementSummary :=
    "The exact shipped Groth16 prover and verifier surfaces satisfy completeness for valid statements and witnesses under the explicit imported-CRS and completeness theorem hypotheses."
  blockingAssumptions := [
    "groth16ImportedCrsValidityHypothesis",
    "groth16ExactCompletenessHypothesis"
  ]
}

def friProximitySoundnessObligation : ProtocolProofObligation := {
  theoremName := "fri_exact_proximity_soundness"
  ledgerTheoremId := "protocol.fri_proximity_soundness"
  scope := "zkf-backends::plonky3"
  targetSurface := "fri"
  statementSummary :=
    "The exact Plonky3 FRI surface shipped by ZKF is a sound Reed-Solomon proximity test under the explicit shipped-surface proximity hypothesis."
  blockingAssumptions := [
    "friReedSolomonProximitySoundnessHypothesis"
  ]
}

def friCompletenessObligation : ProtocolProofObligation := {
  theoremName := "fri_exact_completeness"
  ledgerTheoremId := "protocol.fri_completeness"
  scope := "zkf-backends::plonky3"
  targetSurface := "fri"
  statementSummary :=
    "The exact Plonky3 FRI surface shipped by ZKF satisfies completeness for valid codewords and prover transcripts under the explicit shipped-surface completeness hypothesis."
  blockingAssumptions := [
    "friExactCompletenessHypothesis"
  ]
}

def novaFoldingSoundnessObligation : ProtocolProofObligation := {
  theoremName := "nova_exact_folding_sound"
  ledgerTheoremId := "protocol.nova_folding_soundness"
  scope := "zkf-backends::nova_native"
  targetSurface := "nova-classic"
  statementSummary :=
    "The exact classic Nova folding surface preserves satisfiability for the shipped relaxed-R1CS step-circuit boundary under the explicit folding-soundness hypothesis."
  blockingAssumptions := [
    "novaExactFoldingSoundnessHypothesis"
  ]
}

def novaCompletenessObligation : ProtocolProofObligation := {
  theoremName := "nova_exact_completeness"
  ledgerTheoremId := "protocol.nova_completeness"
  scope := "zkf-backends::nova_native"
  targetSurface := "nova-classic"
  statementSummary :=
    "The exact classic Nova native profile satisfies completeness for valid shipped relaxed-R1CS step-circuit executions under the explicit completeness hypothesis."
  blockingAssumptions := [
    "novaExactCompletenessHypothesis",
    "completeClassicNovaIvcMetadata"
  ]
}

def hypernovaFoldingSoundnessObligation : ProtocolProofObligation := {
  theoremName := "hypernova_exact_folding_sound"
  ledgerTheoremId := "protocol.hypernova_folding_soundness"
  scope := "zkf-backends::nova_native"
  targetSurface := "hypernova"
  statementSummary :=
    "The exact HyperNova CCS folding surface preserves satisfiability for the shipped hypernova profile boundary under the explicit folding-soundness hypothesis."
  blockingAssumptions := [
    "hypernovaExactFoldingSoundnessHypothesis"
  ]
}

def hypernovaCompletenessObligation : ProtocolProofObligation := {
  theoremName := "hypernova_exact_completeness"
  ledgerTheoremId := "protocol.hypernova_completeness"
  scope := "zkf-backends::nova_native"
  targetSurface := "hypernova"
  statementSummary :=
    "The exact HyperNova native profile satisfies completeness for valid shipped CCS folding executions under the explicit completeness hypothesis."
  blockingAssumptions := [
    "hypernovaExactCompletenessHypothesis"
  ]
}

def allProtocolProofObligations : List ProtocolProofObligation := [
  groth16CompletenessObligation,
  groth16KnowledgeSoundnessObligation,
  groth16ZeroKnowledgeObligation,
  friCompletenessObligation,
  friProximitySoundnessObligation,
  novaCompletenessObligation,
  novaFoldingSoundnessObligation,
  hypernovaCompletenessObligation,
  hypernovaFoldingSoundnessObligation
]

theorem allProtocolProofObligations_count :
    allProtocolProofObligations.length = 9 := rfl

theorem allProtocolProofObligations_cover_only_remaining_ledger_rows :
    allProtocolProofObligations.map ProtocolProofObligation.ledgerTheoremId =
      [
        "protocol.groth16_completeness",
        "protocol.groth16_knowledge_soundness",
        "protocol.groth16_zero_knowledge",
        "protocol.fri_completeness",
        "protocol.fri_proximity_soundness",
        "protocol.nova_completeness",
        "protocol.nova_folding_soundness",
        "protocol.hypernova_completeness",
        "protocol.hypernova_folding_soundness"
      ] := rfl

end ZkfProtocolProofs
