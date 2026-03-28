namespace ZkfProtocolProofs

def canonicalThreatPair (first second : Nat) : Nat × Nat :=
  (Nat.min first second, Nat.max first second)

theorem intelligence_root_convergence (first second : Nat) :
    canonicalThreatPair first second = canonicalThreatPair second first := by
  simp [canonicalThreatPair, Nat.min_comm, Nat.max_comm]

def appendOnlyMemory (baseSnapshot extensionSnapshot : List Nat) : List Nat :=
  baseSnapshot ++ extensionSnapshot

theorem memory_append_only_convergence (baseSnapshot extensionSnapshot : List Nat) :
    (appendOnlyMemory baseSnapshot extensionSnapshot).take baseSnapshot.length = baseSnapshot := by
  simp [appendOnlyMemory]

end ZkfProtocolProofs
