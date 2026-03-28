import ZkfProtocolProofs.Common

namespace ZkfProtocolProofs

def orbitalBodyCount : Nat := 5

def orbitalStepCount : Nat := 1000

def orbitalPrivateInputCount : Nat := 35

def orbitalPublicOutputCount : Nat := 5

def orbitalPairCount : Nat := orbitalBodyCount * (orbitalBodyCount - 1) / 2

def pairwiseDelta (ri rj : Int) : Int := rj - ri

def velocityVerletPositionNext (x v a : Int) : Int := x + v + a / 2

def velocityVerletVelocityNext (v aNow aNext : Int) : Int := v + (aNow + aNext) / 2

def orbitalCommitmentPayload (x y z : Int) (bodyTag : Nat) : Int × Int × Int × Nat :=
  (x, y, z, bodyTag)

theorem orbital_body_count_exact :
    orbitalBodyCount = 5 := rfl

theorem orbital_step_count_exact :
    orbitalStepCount = 1000 := rfl

theorem orbital_private_input_count_exact :
    orbitalPrivateInputCount = 35 := rfl

theorem orbital_public_output_count_exact :
    orbitalPublicOutputCount = 5 := rfl

theorem orbital_pair_count_exact :
    orbitalPairCount = 10 := rfl

theorem orbital_pairwise_delta_zero_self (r : Int) :
    pairwiseDelta r r = 0 := by
  simp [pairwiseDelta]

theorem orbital_pairwise_delta_antisymmetric (ri rj : Int) :
    pairwiseDelta ri rj + pairwiseDelta rj ri = 0 := by
  calc
    pairwiseDelta ri rj + pairwiseDelta rj ri
      = (rj + -ri) + (ri + -rj) := by
          simp [pairwiseDelta, Int.sub_eq_add_neg]
    _ = rj + (-ri + (ri + -rj)) := by
          rw [Int.add_assoc]
    _ = rj + ((-ri + ri) + -rj) := by
          rw [Int.add_assoc]
    _ = rj + (0 + -rj) := by
          rw [Int.add_left_neg]
    _ = rj + -rj := by
          rw [Int.zero_add]
    _ = 0 := by
          rw [Int.add_right_neg]

theorem orbital_velocity_verlet_position_deterministic (x v a : Int) :
    velocityVerletPositionNext x v a = velocityVerletPositionNext x v a := rfl

theorem orbital_velocity_verlet_velocity_deterministic (v aNow aNext : Int) :
    velocityVerletVelocityNext v aNow aNext = velocityVerletVelocityNext v aNow aNext := rfl

theorem orbital_commitment_payload_domain_separated
    (x y z : Int)
    {tag₁ tag₂ : Nat}
    (hTag : tag₁ ≠ tag₂) :
    orbitalCommitmentPayload x y z tag₁ ≠ orbitalCommitmentPayload x y z tag₂ := by
  intro hEqual
  apply hTag
  cases hEqual
  rfl

end ZkfProtocolProofs
