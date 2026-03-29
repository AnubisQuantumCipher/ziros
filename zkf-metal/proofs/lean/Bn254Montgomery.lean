import Init

namespace ZkfMetalProofs

def bn254WordModulus : Nat := 2 ^ 64

theorem bn254_word_modulus_pos : 0 < bn254WordModulus := by
  native_decide

abbrev U64 := Fin bn254WordModulus

def u64OfNat (value : Nat) : U64 :=
  ⟨value % bn254WordModulus, Nat.mod_lt _ bn254_word_modulus_pos⟩

def bn254ModulusLimb0 : Nat := 0x43e1f593f0000001
def bn254ModulusLimb1 : Nat := 0x2833e84879b97091
def bn254ModulusLimb2 : Nat := 0xb85045b68181585d
def bn254ModulusLimb3 : Nat := 0x30644e72e131a029

def bn254OneMontLimb0 : Nat := 0xac96341c4ffffffb
def bn254OneMontLimb1 : Nat := 0x36fc76959f60cd29
def bn254OneMontLimb2 : Nat := 0x666ea36f7879462e
def bn254OneMontLimb3 : Nat := 0x0e0a77c19a07df2f

def bn254R2Limb0 : Nat := 0x1bb8e645ae216da7
def bn254R2Limb1 : Nat := 0x53fe3ab1e35c59e3
def bn254R2Limb2 : Nat := 0x8c49833d53bb8085
def bn254R2Limb3 : Nat := 0x0216d0b17f4e44a5

def bn254Inv : Nat := 0xc2e1f593efffffff

def bn254RInvLimb0 : Nat := 0xdc5ba0056db1194e
def bn254RInvLimb1 : Nat := 0x090ef5a9e111ec87
def bn254RInvLimb2 : Nat := 0xc8260de4aeb85d5d
def bn254RInvLimb3 : Nat := 0x15ebf95182c5551c

def bn254Modulus : Nat :=
  bn254ModulusLimb0
    + bn254WordModulus
        * (bn254ModulusLimb1
            + bn254WordModulus
                * (bn254ModulusLimb2 + bn254WordModulus * bn254ModulusLimb3))

def bn254OneMont : Nat :=
  bn254OneMontLimb0
    + bn254WordModulus
        * (bn254OneMontLimb1
            + bn254WordModulus
                * (bn254OneMontLimb2 + bn254WordModulus * bn254OneMontLimb3))

def bn254R2 : Nat :=
  bn254R2Limb0
    + bn254WordModulus
        * (bn254R2Limb1
            + bn254WordModulus
                * (bn254R2Limb2 + bn254WordModulus * bn254R2Limb3))

def bn254RInv : Nat :=
  bn254RInvLimb0
    + bn254WordModulus
        * (bn254RInvLimb1
            + bn254WordModulus
                * (bn254RInvLimb2 + bn254WordModulus * bn254RInvLimb3))

def bn254R : Nat := bn254WordModulus ^ 4

def Bn254Canonical (value : Nat) : Prop := value < bn254Modulus

def bn254Normalize (value : Nat) : Nat := value % bn254Modulus

def bn254NormalizeWord (value : Nat) : Nat := value % bn254WordModulus

def bn254FinalConditionalSubtract (candidate : Nat) : Nat :=
  if bn254Modulus ≤ candidate then
    candidate - bn254Modulus
  else
    candidate

def bn254MontgomeryReduceSpec (value : Nat) : Nat :=
  bn254Normalize (value * bn254RInv)

def bn254MontgomeryMulSpecNat (lhs rhs : Nat) : Nat :=
  bn254MontgomeryReduceSpec (lhs * rhs)

def bn254MontAdd (lhs rhs : Nat) : Nat :=
  bn254Normalize (lhs + rhs)

def bn254MontSub (lhs rhs : Nat) : Nat :=
  bn254Normalize (lhs + bn254Modulus - rhs)

def bn254MontMul (lhs rhs : Nat) : Nat :=
  bn254MontgomeryMulSpecNat lhs rhs

structure Fin4Limbs where
  limb0 : U64
  limb1 : U64
  limb2 : U64
  limb3 : U64
  deriving DecidableEq, Repr

structure Fin5Limbs where
  limb0 : U64
  limb1 : U64
  limb2 : U64
  limb3 : U64
  limb4 : U64
  deriving DecidableEq, Repr

@[simp] def Fin4Limbs.value (x : Fin4Limbs) : Nat :=
  x.limb0.val
    + bn254WordModulus
        * (x.limb1.val + bn254WordModulus * (x.limb2.val + bn254WordModulus * x.limb3.val))

@[simp] def Fin5Limbs.value (x : Fin5Limbs) : Nat :=
  x.limb0.val
    + bn254WordModulus
        * (x.limb1.val
            + bn254WordModulus
                * (x.limb2.val
                    + bn254WordModulus * (x.limb3.val + bn254WordModulus * x.limb4.val)))

@[simp] def fin4OfNat (value : Nat) : Fin4Limbs :=
  {
    limb0 := u64OfNat value
    limb1 := u64OfNat (value / bn254WordModulus)
    limb2 := u64OfNat (value / (bn254WordModulus ^ 2))
    limb3 := u64OfNat (value / (bn254WordModulus ^ 3))
  }

@[simp] def fin5OfNat (value : Nat) : Fin5Limbs :=
  {
    limb0 := u64OfNat value
    limb1 := u64OfNat (value / bn254WordModulus)
    limb2 := u64OfNat (value / (bn254WordModulus ^ 2))
    limb3 := u64OfNat (value / (bn254WordModulus ^ 3))
    limb4 := u64OfNat (value / (bn254WordModulus ^ 4))
  }

def natToFin4Canonical (value : Nat) : Fin4Limbs :=
  fin4OfNat (bn254Normalize value)

def bn254ModulusFin4 : Fin4Limbs :=
  {
    limb0 := u64OfNat bn254ModulusLimb0
    limb1 := u64OfNat bn254ModulusLimb1
    limb2 := u64OfNat bn254ModulusLimb2
    limb3 := u64OfNat bn254ModulusLimb3
  }

def bn254OneMontFin4 : Fin4Limbs :=
  {
    limb0 := u64OfNat bn254OneMontLimb0
    limb1 := u64OfNat bn254OneMontLimb1
    limb2 := u64OfNat bn254OneMontLimb2
    limb3 := u64OfNat bn254OneMontLimb3
  }

def bn254R2Fin4 : Fin4Limbs :=
  {
    limb0 := u64OfNat bn254R2Limb0
    limb1 := u64OfNat bn254R2Limb1
    limb2 := u64OfNat bn254R2Limb2
    limb3 := u64OfNat bn254R2Limb3
  }

def bn254MontgomeryMulSpec (lhs rhs : Fin4Limbs) : Fin4Limbs :=
  fin4OfNat (bn254MontgomeryMulSpecNat lhs.value rhs.value)

def bn254FrToMont (value : Fin4Limbs) : Fin4Limbs :=
  fin4OfNat (bn254MontMul value.value bn254R2)

def frMul64 (lhs rhs : U64) : U64 × U64 :=
  let product := lhs.val * rhs.val
  (u64OfNat (product / bn254WordModulus), u64OfNat product)

def frAdc (lhs rhs carry : U64) : U64 × U64 :=
  let total := lhs.val + rhs.val + carry.val
  (u64OfNat total, u64OfNat (total / bn254WordModulus))

def frSbb (lhs rhs borrow : U64) : U64 × U64 :=
  let rhsTotal := rhs.val + borrow.val
  if _h : rhsTotal ≤ lhs.val then
    (u64OfNat (lhs.val - rhsTotal), u64OfNat 0)
  else
    (u64OfNat (bn254WordModulus + lhs.val - rhsTotal), u64OfNat 1)

def frMac (lhs rhs acc carry : U64) : U64 × U64 :=
  let total := lhs.val * rhs.val + acc.val + carry.val
  (u64OfNat total, u64OfNat (total / bn254WordModulus))

def bn254WordAt (index value : Nat) : Nat :=
  (value / (bn254WordModulus ^ index)) % bn254WordModulus

def bn254CiosRoundM (acc lhs rhsWord : Nat) : Nat :=
  bn254NormalizeWord ((acc + lhs * rhsWord) * bn254Inv)

def bn254CiosRoundNext (acc lhs rhsWord : Nat) : Nat :=
  let m := bn254CiosRoundM acc lhs rhsWord
  (acc + lhs * rhsWord + m * bn254Modulus) / bn254WordModulus

def bn254CiosRound (acc : Fin5Limbs) (lhs : Fin4Limbs) (rhsWord : U64) : Fin5Limbs :=
  fin5OfNat (bn254CiosRoundNext acc.value lhs.value rhsWord.val)

def bn254CiosMulStage0M (lhs rhs : Nat) : Nat :=
  bn254CiosRoundM 0 lhs (bn254WordAt 0 rhs)

def bn254CiosMulStage0 (lhs rhs : Nat) : Nat :=
  bn254CiosRoundNext 0 lhs (bn254WordAt 0 rhs)

def bn254CiosMulStage1M (lhs rhs : Nat) : Nat :=
  bn254CiosRoundM (bn254CiosMulStage0 lhs rhs) lhs (bn254WordAt 1 rhs)

def bn254CiosMulStage1 (lhs rhs : Nat) : Nat :=
  bn254CiosRoundNext (bn254CiosMulStage0 lhs rhs) lhs (bn254WordAt 1 rhs)

def bn254CiosMulStage2M (lhs rhs : Nat) : Nat :=
  bn254CiosRoundM (bn254CiosMulStage1 lhs rhs) lhs (bn254WordAt 2 rhs)

def bn254CiosMulStage2 (lhs rhs : Nat) : Nat :=
  bn254CiosRoundNext (bn254CiosMulStage1 lhs rhs) lhs (bn254WordAt 2 rhs)

def bn254CiosMulStage3M (lhs rhs : Nat) : Nat :=
  bn254CiosRoundM (bn254CiosMulStage2 lhs rhs) lhs (bn254WordAt 3 rhs)

def bn254CiosMulStage3 (lhs rhs : Nat) : Nat :=
  bn254CiosRoundNext (bn254CiosMulStage2 lhs rhs) lhs (bn254WordAt 3 rhs)

def bn254CiosMulRawNat (lhs rhs : Nat) : Nat :=
  bn254CiosMulStage3 lhs rhs

def bn254CiosQuotientNat (lhs rhs : Nat) : Nat :=
  bn254CiosMulStage0M lhs rhs
    + bn254WordModulus
        * (bn254CiosMulStage1M lhs rhs
            + bn254WordModulus
                * (bn254CiosMulStage2M lhs rhs
                    + bn254WordModulus * bn254CiosMulStage3M lhs rhs))

theorem bn254_modulus_from_limbs_ok :
    bn254Modulus =
      bn254ModulusLimb0
        + bn254WordModulus
            * (bn254ModulusLimb1
                + bn254WordModulus
                    * (bn254ModulusLimb2 + bn254WordModulus * bn254ModulusLimb3)) := by
  rfl

theorem bn254_modulus_pos : 0 < bn254Modulus := by
  native_decide

theorem bn254_modulus_lt_r : bn254Modulus < bn254R := by
  native_decide

theorem bn254_reduction_constant_correct :
    ((bn254ModulusLimb0 * bn254Inv) + 1) % bn254WordModulus = 0 := by
  native_decide

theorem bn254_rinv_is_inverse_of_r :
    bn254Normalize (bn254R * bn254RInv) = 1 := by
  native_decide

theorem bn254_r2_matches_r_squared :
    bn254R2 = bn254Normalize (bn254R * bn254R) := by
  native_decide

theorem bn254_one_mont_canonical : Bn254Canonical bn254OneMont := by
  unfold Bn254Canonical
  native_decide

theorem bn254_r2_canonical : Bn254Canonical bn254R2 := by
  unfold Bn254Canonical
  native_decide

theorem bn254_normalize_canonical (value : Nat) :
    Bn254Canonical (bn254Normalize value) := by
  unfold Bn254Canonical bn254Normalize
  exact Nat.mod_lt _ bn254_modulus_pos

theorem bn254_final_conditional_subtract_sound {candidate : Nat}
    (h : candidate < 2 * bn254Modulus) :
    bn254FinalConditionalSubtract candidate = bn254Normalize candidate := by
  unfold bn254FinalConditionalSubtract bn254Normalize
  by_cases hge : bn254Modulus ≤ candidate
  · have hsub : candidate - bn254Modulus < bn254Modulus := by
      omega
    rw [if_pos hge, Nat.mod_eq_sub_mod hge, Nat.mod_eq_of_lt hsub]
  · have hlt : candidate < bn254Modulus := by
      omega
    rw [if_neg hge, Nat.mod_eq_of_lt hlt]

theorem bn254_final_conditional_subtract_canonical {candidate : Nat}
    (h : candidate < 2 * bn254Modulus) :
    Bn254Canonical (bn254FinalConditionalSubtract candidate) := by
  rw [bn254_final_conditional_subtract_sound h]
  exact bn254_normalize_canonical candidate

theorem bn254_normalize_add_multiple_modulus (value k : Nat) :
    bn254Normalize (value + k * bn254Modulus) = bn254Normalize value := by
  simp [bn254Normalize, Nat.add_mod]

theorem bn254_normalize_mul_normalize_left (lhs rhs : Nat) :
    bn254Normalize (bn254Normalize lhs * rhs) = bn254Normalize (lhs * rhs) := by
  simp [bn254Normalize, Nat.mul_mod]

theorem bn254_normalize_mul_normalize_right (lhs rhs : Nat) :
    bn254Normalize (lhs * bn254Normalize rhs) = bn254Normalize (lhs * rhs) := by
  simp [bn254Normalize, Nat.mul_mod]

theorem bn254_mont_add_sound (lhs rhs : Nat) :
    bn254MontAdd lhs rhs = bn254Normalize (lhs + rhs) := by
  rfl

theorem bn254_mont_sub_sound (lhs rhs : Nat) :
    bn254MontSub lhs rhs = bn254Normalize (lhs + bn254Modulus - rhs) := by
  rfl

theorem bn254_mont_mul_sound (lhs rhs : Nat) :
    bn254MontMul lhs rhs = bn254MontgomeryReduceSpec (lhs * rhs) := by
  rfl

theorem bn254_mont_add_canonical (lhs rhs : Nat) :
    Bn254Canonical (bn254MontAdd lhs rhs) := by
  exact bn254_normalize_canonical (lhs + rhs)

theorem bn254_mont_sub_canonical (lhs rhs : Nat) :
    Bn254Canonical (bn254MontSub lhs rhs) := by
  exact bn254_normalize_canonical (lhs + bn254Modulus - rhs)

theorem bn254_mont_mul_canonical (lhs rhs : Nat) :
    Bn254Canonical (bn254MontMul lhs rhs) := by
  unfold bn254MontMul bn254MontgomeryMulSpecNat bn254MontgomeryReduceSpec
  exact bn254_normalize_canonical (lhs * rhs * bn254RInv)

theorem bn254_mont_add_matches_single_subtract {lhs rhs : Nat}
    (hlhs : Bn254Canonical lhs) (hrhs : Bn254Canonical rhs) :
    bn254MontAdd lhs rhs = bn254FinalConditionalSubtract (lhs + rhs) := by
  unfold bn254MontAdd
  symm
  have hsum : lhs + rhs < 2 * bn254Modulus := by
    unfold Bn254Canonical at hlhs hrhs
    omega
  exact bn254_final_conditional_subtract_sound hsum

theorem fr_mul64_correct (lhs rhs : U64) :
    let result := frMul64 lhs rhs
    result.2.val + bn254WordModulus * result.1.val = lhs.val * rhs.val := by
  unfold frMul64
  have hhi : lhs.val * rhs.val / bn254WordModulus < bn254WordModulus := by
    have hlhs : lhs.val < bn254WordModulus := lhs.isLt
    have hrhs : rhs.val < bn254WordModulus := rhs.isLt
    have hprod :
        lhs.val * rhs.val < bn254WordModulus * bn254WordModulus := by
      exact Nat.lt_of_le_of_lt
        (Nat.mul_le_mul_right _ (Nat.le_of_lt hlhs))
        (Nat.mul_lt_mul_of_pos_left hrhs bn254_word_modulus_pos)
    exact Nat.div_lt_of_lt_mul hprod
  simp [u64OfNat, Nat.mod_add_div, Nat.mod_eq_of_lt hhi]

theorem fr_adc_correct (lhs rhs carry : U64) :
    let result := frAdc lhs rhs carry
    result.1.val + bn254WordModulus * result.2.val = lhs.val + rhs.val + carry.val := by
  unfold frAdc
  have hthree : 3 ≤ bn254WordModulus := by
    native_decide
  have hsum : lhs.val + rhs.val + carry.val < 3 * bn254WordModulus := by
    have hlhs : lhs.val < bn254WordModulus := lhs.isLt
    have hrhs : rhs.val < bn254WordModulus := rhs.isLt
    have hcarry : carry.val < bn254WordModulus := carry.isLt
    omega
  have hhi : (lhs.val + rhs.val + carry.val) / bn254WordModulus < bn254WordModulus := by
    have hlt3 : (lhs.val + rhs.val + carry.val) / bn254WordModulus < 3 := by
      exact Nat.div_lt_of_lt_mul <| by simpa [Nat.mul_comm] using hsum
    exact Nat.lt_of_lt_of_le hlt3 hthree
  simp [u64OfNat, Nat.mod_add_div, Nat.mod_eq_of_lt hhi]

theorem fr_sbb_correct (lhs rhs borrow : U64)
    (hborrow : borrow.val ≤ 1) :
    let result := frSbb lhs rhs borrow
    result.1.val = lhs.val + bn254WordModulus * result.2.val - (rhs.val + borrow.val) := by
  unfold frSbb
  by_cases h : rhs.val + borrow.val ≤ lhs.val
  · have hlt : lhs.val - (rhs.val + borrow.val) < bn254WordModulus := by
      have hlhs : lhs.val < bn254WordModulus := lhs.isLt
      omega
    simp [h, u64OfNat, Nat.mod_eq_of_lt hlt]
  · have hlt :
        bn254WordModulus + lhs.val - (rhs.val + borrow.val) < bn254WordModulus := by
      have hlhs : lhs.val < bn254WordModulus := lhs.isLt
      have hrhs : rhs.val < bn254WordModulus := rhs.isLt
      omega
    have hone : 1 % bn254WordModulus = 1 := by
      exact Nat.mod_eq_of_lt (by native_decide)
    simp [h, u64OfNat, Nat.mod_eq_of_lt hlt, hone]
    omega

theorem fr_mac_correct (lhs rhs acc carry : U64) :
    let result := frMac lhs rhs acc carry
    result.1.val + bn254WordModulus * result.2.val
      = lhs.val * rhs.val + acc.val + carry.val := by
  unfold frMac
  have hsum :
      lhs.val * rhs.val + acc.val + carry.val
        < bn254WordModulus * bn254WordModulus := by
    have hlhs : lhs.val < bn254WordModulus := lhs.isLt
    have hrhs : rhs.val < bn254WordModulus := rhs.isLt
    have hacc : acc.val < bn254WordModulus := acc.isLt
    have hcarry : carry.val < bn254WordModulus := carry.isLt
    have hprod :
        lhs.val * rhs.val
          ≤ (bn254WordModulus - 1) * (bn254WordModulus - 1) := by
      apply Nat.mul_le_mul
      · exact Nat.le_pred_of_lt hlhs
      · exact Nat.le_pred_of_lt hrhs
    have hconst :
        (bn254WordModulus - 1) * (bn254WordModulus - 1)
          + (bn254WordModulus - 1) + (bn254WordModulus - 1)
        < bn254WordModulus * bn254WordModulus := by
      native_decide
    omega
  have hhi :
      (lhs.val * rhs.val + acc.val + carry.val) / bn254WordModulus
        < bn254WordModulus := by
    exact Nat.div_lt_of_lt_mul hsum
  simp [u64OfNat, Nat.mod_add_div, Nat.mod_eq_of_lt hhi]

def bn254ToMontNat (value : Nat) : Nat :=
  bn254MontMul value bn254R2

theorem fr_to_mont_correct (value : Fin4Limbs) :
    bn254FrToMont value = bn254MontgomeryMulSpec value bn254R2Fin4 := by
  unfold bn254FrToMont bn254MontgomeryMulSpec bn254MontMul bn254MontgomeryMulSpecNat
  rw [show bn254R2Fin4.value = bn254R2 by rfl]

end ZkfMetalProofs
