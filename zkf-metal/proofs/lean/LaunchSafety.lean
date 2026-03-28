import KernelSemantics

namespace ZkfMetalProofs

def LaunchContractSound (program : Program) (env : SymbolEnv) : Prop :=
  structuralMemorySound program env
    ∧ regionsBounded program env
    ∧ writeRegionsDistinct program
    ∧ barriersBalanced program

theorem dispatch_valid_implies_no_oob_reads (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env -> regionsBounded program env := by
  intro h
  exact (thread_step_preserves_bounds program env h).1

theorem dispatch_valid_implies_no_oob_writes (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env ->
      regionsBounded program env
        ∧ writeFootprintDeclared program := by
  intro h
  exact ⟨(thread_step_preserves_bounds program env h).1, (thread_step_preserves_bounds program env h).2.2⟩

theorem dispatch_valid_implies_non_overlapping_writes (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env ->
      writeRegionsDistinct program
        ∧ regionNamesDistinct program.sharedRegions := by
  intro h
  exact ⟨h.2.2.2.2.1, h.2.2.2.2.2⟩

theorem dispatch_valid_implies_barrier_scope_sound (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env -> barriersBalanced program := by
  intro h
  exact (barrier_preserves_region_well_formedness program env h).1

theorem gpu_launch_contract_sound (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env -> LaunchContractSound program env := by
  intro h
  exact ⟨
    h,
    dispatch_valid_implies_no_oob_reads program env h,
    (dispatch_valid_implies_non_overlapping_writes program env h).1,
    dispatch_valid_implies_barrier_scope_sound program env h
  ⟩

end ZkfMetalProofs
