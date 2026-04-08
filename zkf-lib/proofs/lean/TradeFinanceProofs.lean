def deductibleAdjusted (covered deductible : Nat) : Nat :=
  covered - deductible

def cappedPayout (covered deductible cap : Nat) : Nat :=
  Nat.min (deductibleAdjusted covered deductible) cap

theorem cappedPayoutLeCap (covered deductible cap : Nat) :
    cappedPayout covered deductible cap <= cap := by
  unfold cappedPayout
  exact Nat.min_le_right _ _

theorem deductibleAdjustedLeCovered (covered deductible : Nat) :
    deductibleAdjusted covered deductible <= covered := by
  unfold deductibleAdjusted
  exact Nat.sub_le _ _
