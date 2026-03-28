namespace ZkfProtocolProofs

/--
Minimal ZKF-owned Lean 4.28 port of the reusable Groth16 Type III soundness boundary.

This file intentionally keeps only the abstract interface that the exact-surface transfer
theorems need in this workspace. Provenance for the soundness boundary lives under the pinned
vendor snapshot at `vendor/formal-snarks-project/` (commit
`dcfc78d456882087d4e592e090e8d6d6df83e560`), specifically the Type III Groth16 definitions and
soundness development under `FormalSnarksProject/SNARKs/Groth16TypeIII/`.
-/
structure Groth16TypeIIIModel where
  Statement : Type
  Witness : Type
  Proof : Type
  relation : Statement -> Witness -> Prop
  prove : Statement -> Witness -> Proof
  verify : Statement -> Proof -> Prop
  extract : Statement -> Proof -> Witness
  complete :
    ∀ {stmt : Statement} {wit : Witness},
      relation stmt wit -> verify stmt (prove stmt wit)
  sound :
    ∀ {stmt : Statement} {proof : Proof},
      verify stmt proof -> relation stmt (extract stmt proof)

def Groth16TypeIIIModel.completeness (model : Groth16TypeIIIModel) : Prop :=
  ∀ stmt wit, model.relation stmt wit -> model.verify stmt (model.prove stmt wit)

theorem Groth16TypeIIIModel.completeness_ok
    (model : Groth16TypeIIIModel) :
    model.completeness := by
  intro stmt wit hRelation
  exact model.complete hRelation

def Groth16TypeIIIModel.knowledgeSoundness (model : Groth16TypeIIIModel) : Prop :=
  ∀ stmt proof, model.verify stmt proof -> model.relation stmt (model.extract stmt proof)

theorem Groth16TypeIIIModel.knowledgeSoundness_ok
    (model : Groth16TypeIIIModel) :
    model.knowledgeSoundness := by
  intro stmt proof hVerify
  exact model.sound hVerify

end ZkfProtocolProofs
