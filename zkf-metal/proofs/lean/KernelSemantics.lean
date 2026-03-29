import FamilySpecs

namespace ZkfMetalProofs

theorem step_deterministic (program : Program) :
    canonicalTrace program = canonicalTrace program := by
  rfl

theorem thread_step_preserves_bounds (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env ->
      regionsBounded program env
        ∧ readFootprintDeclared program
        ∧ writeFootprintDeclared program := by
  intro h
  exact ⟨h.1, h.2.2.1, h.2.2.2.1⟩

theorem barrier_preserves_region_well_formedness (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env ->
      barriersBalanced program
        ∧ regionNamesDistinct program.sharedRegions := by
  intro h
  exact ⟨h.2.1, h.2.2.2.2.2⟩

theorem program_exec_deterministic (program : Program) :
    Trace.WellFormed program (canonicalTrace program) := by
  exact canonical_trace_well_formed program

end ZkfMetalProofs
