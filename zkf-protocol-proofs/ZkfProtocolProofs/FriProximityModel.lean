namespace ZkfProtocolProofs

/--
Minimal ZKF-owned Lean 4.28 model for transporting FRI proximity soundness onto the shipped
Plonky3 exact surface.

The reusable FRI/oracle-reduction background is pinned under `vendor/arklib/` for provenance, but
the final closure theorem in this workspace only depends on the abstract soundness boundary below.
-/
structure FriProximityModel where
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

def FriProximityModel.completeness (model : FriProximityModel) : Prop :=
  ∀ stmt wit, model.relation stmt wit -> model.verify stmt (model.prove stmt wit)

theorem FriProximityModel.completeness_ok
    (model : FriProximityModel) :
    model.completeness := by
  intro stmt wit hRelation
  exact model.complete hRelation

def FriProximityModel.proximitySoundness (model : FriProximityModel) : Prop :=
  ∀ stmt proof, model.verify stmt proof -> model.relation stmt (model.extract stmt proof)

theorem FriProximityModel.proximitySoundness_ok
    (model : FriProximityModel) :
    model.proximitySoundness := by
  intro stmt proof hVerify
  exact model.sound hVerify

end ZkfProtocolProofs
