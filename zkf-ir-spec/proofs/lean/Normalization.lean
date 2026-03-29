theorem normalization_mul_one (x : Int) : 1 * x = x := by
  simp

theorem normalization_sub_zero (x : Int) : x - 0 = x := by
  simp

inductive SupportedExpr where
  | const : Int → SupportedExpr
  | signal : Nat → SupportedExpr
  | add : List SupportedExpr → SupportedExpr
  | mul : SupportedExpr → SupportedExpr → SupportedExpr
  | sub : SupportedExpr → SupportedExpr → SupportedExpr
deriving Repr

def normalizeSupportedExpr : SupportedExpr → SupportedExpr
  | .const value => .const value
  | .signal signalKey => .signal signalKey
  | .add terms =>
      let normalizedTerms := (terms.map normalizeSupportedExpr).filter fun term =>
        match term with
        | .const 0 => false
        | _ => true
      match normalizedTerms with
      | [] => .const 0
      | [term] => term
      | remaining => .add remaining
  | .mul lhs rhs =>
      let lhsNorm := normalizeSupportedExpr lhs
      let rhsNorm := normalizeSupportedExpr rhs
      match lhsNorm, rhsNorm with
      | .const 1, rhsValue => rhsValue
      | lhsValue, .const 1 => lhsValue
      | .const 0, _ => .const 0
      | _, .const 0 => .const 0
      | lhsValue, rhsValue => .mul lhsValue rhsValue
  | .sub lhs rhs =>
      let lhsNorm := normalizeSupportedExpr lhs
      let rhsNorm := normalizeSupportedExpr rhs
      match rhsNorm with
      | .const 0 => lhsNorm
      | rhsValue => .sub lhsNorm rhsValue

def supportedExprDigest : SupportedExpr → Nat
  | .const value => value.natAbs + 1
  | .signal signalKey => signalKey + 17
  | .add terms =>
      29 + (terms.foldl (fun acc term => acc + supportedExprDigest term) 0)
  | .mul lhs rhs =>
      31 + supportedExprDigest lhs + supportedExprDigest rhs
  | .sub lhs rhs =>
      37 + supportedExprDigest lhs + supportedExprDigest rhs

structure SupportedSignalSurface where
  sortKey : Nat
  retained : Bool
deriving Repr

inductive SupportedConstraintSurface where
  | equal : SupportedExpr → SupportedExpr → Nat → SupportedConstraintSurface
  | boolean : Nat → Nat → SupportedConstraintSurface
  | range : Nat → Nat → Nat → SupportedConstraintSurface
deriving Repr

def supportedConstraintKey : SupportedConstraintSurface → Nat
  | .equal lhs rhs labelKey =>
      101
        + supportedExprDigest (normalizeSupportedExpr lhs)
        + supportedExprDigest (normalizeSupportedExpr rhs)
        + labelKey
  | .boolean signalKey labelKey => 103 + signalKey + labelKey
  | .range signalKey bits labelKey => 107 + signalKey + bits + labelKey

def retainedSignalKeys : List SupportedSignalSurface → List Nat
  | [] => []
  | signal :: rest =>
      if signal.retained then
        signal.sortKey :: retainedSignalKeys rest
      else
        retainedSignalKeys rest

def normalizedConstraintKeys (constraints : List SupportedConstraintSurface) : List Nat :=
  constraints.map supportedConstraintKey

structure SupportedProgram where
  signalKeys : List Nat
  constraintKeys : List Nat
  assignmentDigest : Nat
  hintDigest : Nat
deriving Repr

structure SupportedProgramSurface where
  signals : List SupportedSignalSurface
  constraints : List SupportedConstraintSurface
  assignmentDigest : Nat
  hintDigest : Nat
deriving Repr

def extractSupportedProgram (surface : SupportedProgramSurface) : SupportedProgram :=
  { signalKeys := retainedSignalKeys surface.signals
    constraintKeys := normalizedConstraintKeys surface.constraints
    assignmentDigest := surface.assignmentDigest
    hintDigest := surface.hintDigest }

def insertNat (value : Nat) : List Nat → List Nat
  | [] => [value]
  | head :: tail =>
      if value ≤ head then
        value :: head :: tail
      else
        head :: insertNat value tail

def sortNatList : List Nat → List Nat
  | [] => []
  | head :: tail => insertNat head (sortNatList tail)

def SortedNat : List Nat → Prop
  | [] => True
  | [_] => True
  | head :: next :: tail => head ≤ next ∧ SortedNat (next :: tail)

theorem insertNat_preserves_sorted :
    ∀ value xs, SortedNat xs → SortedNat (insertNat value xs)
  | value, [], _ => by
      simp [insertNat, SortedNat]
  | value, [head], _ => by
      by_cases h : value ≤ head
      · simp [insertNat, SortedNat, h]
      · have hHead : head ≤ value := Nat.le_of_lt (Nat.lt_of_not_ge h)
        simp [insertNat, SortedNat, h, hHead]
  | value, head :: next :: tail, hSorted => by
      rcases hSorted with ⟨hHeadNext, hTail⟩
      by_cases hValueHead : value ≤ head
      · simp [insertNat, SortedNat, hValueHead, hHeadNext, hTail]
      · by_cases hValueNext : value ≤ next
        · have hHeadValue : head ≤ value := Nat.le_of_lt (Nat.lt_of_not_ge hValueHead)
          simp [insertNat, SortedNat, hValueHead, hValueNext, hTail, hHeadValue]
        · have hInsertedTail :
              SortedNat (insertNat value (next :: tail)) :=
            insertNat_preserves_sorted value (next :: tail) hTail
          simpa [insertNat, SortedNat, hValueHead, hValueNext, hHeadNext] using
            And.intro hHeadNext hInsertedTail

theorem sortNatList_sorted : ∀ xs, SortedNat (sortNatList xs)
  | [] => by
      simp [sortNatList, SortedNat]
  | head :: tail => by
      exact insertNat_preserves_sorted head (sortNatList tail) (sortNatList_sorted tail)

theorem sortNatList_eq_of_sorted : ∀ xs, SortedNat xs → sortNatList xs = xs
  | [], _ => by
      simp [sortNatList]
  | [head], _ => by
      simp [sortNatList, insertNat]
  | head :: next :: tail, hSorted => by
      rcases hSorted with ⟨hHeadNext, hTail⟩
      calc
        sortNatList (head :: next :: tail)
          = insertNat head (sortNatList (next :: tail)) := rfl
        _ = insertNat head (next :: tail) := by
              rw [sortNatList_eq_of_sorted (next :: tail) hTail]
        _ = head :: next :: tail := by
              simp [insertNat, hHeadNext]

theorem sortNatList_idempotent (xs : List Nat) :
    sortNatList (sortNatList xs) = sortNatList xs :=
  sortNatList_eq_of_sorted (sortNatList xs) (sortNatList_sorted xs)

def normalizeSupportedProgram (program : SupportedProgram) : SupportedProgram :=
  { signalKeys := sortNatList program.signalKeys
    constraintKeys := sortNatList program.constraintKeys
    assignmentDigest := program.assignmentDigest
    hintDigest := program.hintDigest }

def canonicalDigest (program : SupportedProgram) : List Nat :=
  [program.signalKeys.length]
    ++ program.signalKeys
    ++ [program.constraintKeys.length]
    ++ program.constraintKeys
    ++ [program.assignmentDigest, program.hintDigest]

def supportedSurfaceOrderingEquivalent
    (lhs rhs : SupportedProgramSurface) : Prop :=
  sortNatList (retainedSignalKeys lhs.signals) = sortNatList (retainedSignalKeys rhs.signals) ∧
    sortNatList (normalizedConstraintKeys lhs.constraints) =
      sortNatList (normalizedConstraintKeys rhs.constraints) ∧
    lhs.assignmentDigest = rhs.assignmentDigest ∧
    lhs.hintDigest = rhs.hintDigest

theorem normalization_supported_program_idempotent
    (surface : SupportedProgramSurface) :
    normalizeSupportedProgram
        (normalizeSupportedProgram (extractSupportedProgram surface)) =
      normalizeSupportedProgram (extractSupportedProgram surface) := by
  cases surface
  simp [extractSupportedProgram, normalizeSupportedProgram, sortNatList_idempotent]

theorem normalization_supported_program_digest_stable
    {lhs rhs : SupportedProgramSurface}
    (hEq : supportedSurfaceOrderingEquivalent lhs rhs) :
    canonicalDigest (normalizeSupportedProgram (extractSupportedProgram lhs)) =
      canonicalDigest (normalizeSupportedProgram (extractSupportedProgram rhs)) := by
  rcases hEq with ⟨hSignals, hConstraints, hAssignments, hHints⟩
  cases lhs
  cases rhs
  simp [extractSupportedProgram, normalizeSupportedProgram, canonicalDigest, hSignals,
    hConstraints]
  exact And.intro hAssignments hHints
