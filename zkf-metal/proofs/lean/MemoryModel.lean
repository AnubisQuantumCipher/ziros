import TraceModel

namespace ZkfMetalProofs

def RegionSlice.startValue (env : SymbolEnv) (region : RegionSlice) : Nat :=
  evalNumeric env region.start

def RegionSlice.lenValue (env : SymbolEnv) (region : RegionSlice) : Nat :=
  evalNumeric env region.len

def RegionSlice.boundValue (env : SymbolEnv) (region : RegionSlice) : Nat :=
  evalNumeric env region.bound

def RegionSlice.WellBounded (env : SymbolEnv) (region : RegionSlice) : Prop :=
  region.elementBytes > 0
    ∧ region.lenValue env > 0
    ∧ region.startValue env + region.lenValue env <= region.boundValue env

def RegionSlice.Aligned (env : SymbolEnv) (region : RegionSlice) : Prop :=
  region.elementBytes > 0
    ∧ region.startValue env % region.elementBytes = 0
    ∧ region.boundValue env % region.elementBytes = 0

def Program.allRegions (program : Program) : List RegionSlice :=
  program.readRegions ++ program.writeRegions ++ program.sharedRegions

def regionsBounded (program : Program) (env : SymbolEnv) : Prop :=
  ∀ region ∈ program.allRegions, region.WellBounded env

def barriersBalanced (program : Program) : Prop :=
  ∀ barrier ∈ program.barriers, barrier.afterStep < program.stepCount

def readFootprintDeclared (program : Program) : Prop :=
  ∀ step ∈ program.steps, ∀ regionName ∈ step.reads, program.HasRegionNamed regionName

def writeFootprintDeclared (program : Program) : Prop :=
  ∀ step ∈ program.steps, ∀ regionName ∈ step.writes, program.HasRegionNamed regionName

def regionNamesDistinct (regions : List RegionSlice) : Prop :=
  regions.Pairwise (fun lhs rhs => lhs.name ≠ rhs.name)

def writeRegionsDistinct (program : Program) : Prop :=
  regionNamesDistinct program.writeRegions

def alignedRegions (program : Program) (env : SymbolEnv) : Prop :=
  ∀ region ∈ program.allRegions, region.Aligned env

def initializedReadsDeclared (program : Program) : Prop :=
  readFootprintDeclared program

def outputWritebackRegionsDeclared (program : Program) : Prop :=
  ∀ region ∈ program.writeRegions, region.kind = MemoryRegionKind.globalOutput

def structuralMemorySound (program : Program) (env : SymbolEnv) : Prop :=
  regionsBounded program env
    ∧ barriersBalanced program
    ∧ readFootprintDeclared program
    ∧ writeFootprintDeclared program
    ∧ writeRegionsDistinct program
    ∧ regionNamesDistinct program.sharedRegions

def BufferLayoutSound (program : Program) (env : SymbolEnv) : Prop :=
  structuralMemorySound program env
    ∧ alignedRegions program env
    ∧ initializedReadsDeclared program
    ∧ outputWritebackRegionsDeclared program

theorem gpu_buffer_layout_sound (program : Program) (env : SymbolEnv) :
    structuralMemorySound program env ->
      alignedRegions program env ->
      outputWritebackRegionsDeclared program ->
      BufferLayoutSound program env := by
  intro hstruct halign hwriteback
  exact ⟨hstruct, halign, hstruct.2.2.1, hwriteback⟩

end ZkfMetalProofs
