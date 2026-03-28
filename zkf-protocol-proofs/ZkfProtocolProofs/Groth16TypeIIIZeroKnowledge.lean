import ZkfProtocolProofs.Groth16TypeIII

namespace ZkfProtocolProofs

/--
Minimal ZKF-owned Lean 4.28 wrapper for the Groth16 Type III zero-knowledge transfer boundary.

The cryptographic simulation argument for the underlying Groth16 proof system is modeled here as
an abstract public-view equality over a prover and simulator. This keeps the exact-surface theorem
focused on the shipped ZKF artifact boundary while preserving the imported Type III structure.
-/
structure Groth16TypeIIIZeroKnowledgeModel extends Groth16TypeIIIModel where
  PublicView : Type
  simulate : Statement -> Proof
  proofView : Proof -> PublicView
  publicView_simulation :
    ∀ {stmt : Statement} {wit : Witness},
      relation stmt wit ->
        proofView (prove stmt wit) = proofView (simulate stmt)

def Groth16TypeIIIZeroKnowledgeModel.zeroKnowledge
    (model : Groth16TypeIIIZeroKnowledgeModel) : Prop :=
  ∀ stmt wit,
    model.relation stmt wit ->
      model.proofView (model.prove stmt wit) = model.proofView (model.simulate stmt)

theorem Groth16TypeIIIZeroKnowledgeModel.zeroKnowledge_ok
    (model : Groth16TypeIIIZeroKnowledgeModel) :
    model.zeroKnowledge := by
  intro stmt wit hRelation
  exact model.publicView_simulation hRelation

end ZkfProtocolProofs
