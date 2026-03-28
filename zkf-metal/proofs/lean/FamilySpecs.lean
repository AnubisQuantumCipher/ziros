import MemoryModel

namespace ZkfMetalProofs

structure KernelSpec where
  programId : String
  family : KernelFamily
  kernel : String
  variant : String
  field : Option FieldFamily
  curve : Option CurveFamily
  route : Option MsmRoute
  requiredOperators : List TransitionOperator
  requiredReads : List String
  requiredWrites : List String
  requiresBarrier : Bool
  certifiedClaim : Bool
  deriving Repr

@[simp] def ProgramDeclaresRegions (program : Program) (regionNames : List String) : Prop :=
  ∀ regionName ∈ regionNames, program.HasRegionNamed regionName

def ProgramRefinesKernelSpec (program : Program) (spec : KernelSpec) : Prop :=
  program.programId = spec.programId
    ∧ program.family = spec.family
    ∧ program.kernel = spec.kernel
    ∧ program.variant = spec.variant
    ∧ program.field = spec.field
    ∧ program.curve = spec.curve
    ∧ program.route = spec.route
    ∧ program.steps.map KernelStep.operator = spec.requiredOperators
    ∧ program.readRegions.map RegionSlice.name = spec.requiredReads
    ∧ program.writeRegions.map RegionSlice.name = spec.requiredWrites
    ∧ program.certifiedClaim = spec.certifiedClaim

@[simp] def ProgramStepOperators (program : Program) : List TransitionOperator :=
  program.steps.map KernelStep.operator

@[simp] def ProgramReadRegionNames (program : Program) : List String :=
  program.readRegions.map RegionSlice.name

@[simp] def ProgramWriteRegionNames (program : Program) : List String :=
  program.writeRegions.map RegionSlice.name

@[simp] def ProgramSharedRegionNames (program : Program) : List String :=
  program.sharedRegions.map RegionSlice.name

@[simp] def ProgramReadElementBytes (program : Program) : List Nat :=
  program.readRegions.map RegionSlice.elementBytes

@[simp] def ProgramWriteElementBytes (program : Program) : List Nat :=
  program.writeRegions.map RegionSlice.elementBytes

@[simp] def ProgramSharedElementBytes (program : Program) : List Nat :=
  program.sharedRegions.map RegionSlice.elementBytes

@[simp] def ProgramBarrierScopes (program : Program) : List String :=
  program.barriers.map BarrierPoint.scope

@[simp] def ProgramBarrierAfterSteps (program : Program) : List Nat :=
  program.barriers.map BarrierPoint.afterStep

@[simp] def ProgramBindingKinds (program : Program) : List String :=
  program.lowering.stepBindings.map LoweringBinding.bindingKind

@[simp] def ProgramBindingEntrypoints (program : Program) : List String :=
  program.lowering.stepBindings.map LoweringBinding.entrypoint

@[simp] def ProgramBindingLibraries (program : Program) : List String :=
  program.lowering.stepBindings.map LoweringBinding.library

@[simp] def ProgramBindingSourcePaths (program : Program) : List String :=
  program.lowering.stepBindings.map LoweringBinding.sourcePath

@[simp] def ProgramUsesLaneIndex (program : Program) : Bool :=
  program.indexMap.laneIndex.isSome

@[simp] def ProgramUsesBatchIndex (program : Program) : Bool :=
  program.indexMap.batchIndex.isSome

end ZkfMetalProofs
