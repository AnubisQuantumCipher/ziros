namespace ZkfProtocolProofs

/--
Minimal ZKF-owned Lean 4.28 model for transporting classic Nova folding soundness onto the exact
native profile surface shipped by ZKF.
-/
structure NovaFoldingModel where
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

def NovaFoldingModel.completeness (model : NovaFoldingModel) : Prop :=
  ∀ stmt wit, model.relation stmt wit -> model.verify stmt (model.prove stmt wit)

theorem NovaFoldingModel.completeness_ok
    (model : NovaFoldingModel) :
    model.completeness := by
  intro stmt wit hRelation
  exact model.complete hRelation

def NovaFoldingModel.foldingSoundness (model : NovaFoldingModel) : Prop :=
  ∀ stmt proof, model.verify stmt proof -> model.relation stmt (model.extract stmt proof)

theorem NovaFoldingModel.foldingSoundness_ok
    (model : NovaFoldingModel) :
    model.foldingSoundness := by
  intro stmt proof hVerify
  exact model.sound hVerify

end ZkfProtocolProofs
