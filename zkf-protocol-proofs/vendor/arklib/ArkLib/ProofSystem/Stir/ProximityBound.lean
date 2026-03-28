/-
Copyright (c) 2025 ArkLib Contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Mirco Richter, Poulami Das (Least Authority)
-/

import Mathlib.Data.Finset.Basic
import Mathlib.Data.Real.Basic
import Mathlib.Data.Real.Sqrt

open NNReal

namespace STIR

/-- Proximity bound function (`B⋆` in STIR, Section 4.1), which is just a square root.
`B⋆(x) = √x`, where `x` is a code rate.
-/
noncomputable def Bstar (x : ℝ≥0) : ℝ≥0 := x.sqrt

/-- Proximity error function (STIR, Section 4.1). `err⋆(d, ρ, δ, m)` is defined as follows:
- UDR bound: If `δ ∈ (0, (1 - ρ) / 2]` then: `err⋆(d, ρ, δ, m) = ((m - 1) * d) / (ρ * |𝔽|)`
- LDR bound: If `δ ∈ ((1 - ρ) / 2, 1 - √ρ)` then
  `err⋆(d, ρ, δ, m) = ((m - 1) * d^2) / (|𝔽| * (2 * min{1 - √ρ - δ, √ρ / 20})^7)`
-/
noncomputable def proximityError (F : Type*) [Fintype F]
  (d : ℕ) (ρ : ℝ≥0) (δ : ℝ≥0) (m : ℕ) : ℝ≥0 :=
  if δ ≤ (1 - ρ) / 2 then
    ((m - 1) * d) / (ρ * (Fintype.card F))
  else if δ < 1 - ρ.sqrt then
    let min_val := min (1 - (ρ.sqrt) - δ) ((ρ.sqrt) / 20)
    ((m - 1) * d^2) / ((Fintype.card F) * (2 * min_val)^7)
  else -- When δ ≥ 1 - √ρ, the function is undefined per spec, return 0 to avoid division by zero
    0

end STIR
