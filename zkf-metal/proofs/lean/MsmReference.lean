import FamilySpecs

namespace ZkfMetalProofs

def msmSpec
    (programId kernel variant : String)
    (curve : CurveFamily)
    (route : MsmRoute)
    (operator : TransitionOperator)
    (reads writes : List String) : KernelSpec :=
  {
    programId := programId
    family := KernelFamily.msm
    kernel := kernel
    variant := variant
    field := none
    curve := some curve
    route := some route
    requiredOperators := [operator]
    requiredReads := reads
    requiredWrites := writes
    requiresBarrier := false
    certifiedClaim := true
  }

def bn254ClassicAssignSpec : KernelSpec :=
  msmSpec "msm_bn254_classic_assign" "msm_bucket_assign" "classic_assign"
    CurveFamily.bn254 MsmRoute.classic TransitionOperator.msmBucketAssign
    ["scalars"] ["bucket_map"]

def bn254ClassicAccumulateSpec : KernelSpec :=
  msmSpec "msm_bn254_classic_accumulate" "msm_bucket_acc" "classic_accumulate"
    CurveFamily.bn254 MsmRoute.classic TransitionOperator.msmBucketAccumulate
    ["scalars", "bases_x", "bases_y", "bucket_map"] ["buckets"]

def bn254ClassicReduceSpec : KernelSpec :=
  msmSpec "msm_bn254_classic_reduce" "msm_bucket_reduce" "classic_reduce"
    CurveFamily.bn254 MsmRoute.classic TransitionOperator.msmBucketReduce
    ["buckets"] ["window_results"]

def bn254ClassicCombineSpec : KernelSpec :=
  msmSpec "msm_bn254_classic_combine" "msm_window_combine" "classic_combine"
    CurveFamily.bn254 MsmRoute.classic TransitionOperator.msmWindowCombine
    ["window_results"] ["final_result"]

def pallasClassicAssignSpec : KernelSpec :=
  msmSpec "msm_pallas_classic_assign" "msm_bucket_assign" "classic_assign"
    CurveFamily.pallas MsmRoute.classic TransitionOperator.msmBucketAssign
    ["scalars"] ["bucket_map"]

def pallasClassicAccumulateSpec : KernelSpec :=
  msmSpec "msm_pallas_classic_accumulate" "msm_bucket_acc" "classic_accumulate"
    CurveFamily.pallas MsmRoute.classic TransitionOperator.msmBucketAccumulate
    ["scalars", "bases_x", "bases_y", "bucket_map"] ["buckets"]

def pallasNafAccumulateSpec : KernelSpec :=
  msmSpec "msm_pallas_naf_accumulate" "msm_bucket_acc_naf" "naf_accumulate"
    CurveFamily.pallas MsmRoute.naf TransitionOperator.msmBucketAccumulate
    ["bases_x", "bases_y", "bucket_map"] ["buckets"]

def vestaClassicAssignSpec : KernelSpec :=
  msmSpec "msm_vesta_classic_assign" "msm_bucket_assign" "classic_assign"
    CurveFamily.vesta MsmRoute.classic TransitionOperator.msmBucketAssign
    ["scalars"] ["bucket_map"]

def vestaClassicAccumulateSpec : KernelSpec :=
  msmSpec "msm_vesta_classic_accumulate" "msm_bucket_acc" "classic_accumulate"
    CurveFamily.vesta MsmRoute.classic TransitionOperator.msmBucketAccumulate
    ["scalars", "bases_x", "bases_y", "bucket_map"] ["buckets"]

def vestaNafAccumulateSpec : KernelSpec :=
  msmSpec "msm_vesta_naf_accumulate" "msm_bucket_acc_naf" "naf_accumulate"
    CurveFamily.vesta MsmRoute.naf TransitionOperator.msmBucketAccumulate
    ["bases_x", "bases_y", "bucket_map"] ["buckets"]

inductive MsmExecutionStage where
  | assign
  | accumulate
  | reduce
  | combine
  deriving Repr

inductive MsmDigitSemantics where
  | classic
  | naf
  deriving Repr

structure MsmPippengerSemantics where
  programId : String
  kernel : String
  variant : String
  curve : CurveFamily
  route : MsmRoute
  executionStage : MsmExecutionStage
  digitSemantics : MsmDigitSemantics
  scalarLimbs : Nat
  baseLimbs : Nat
  bucketLimbCount : Nat
  phaseOperators : List TransitionOperator
  readRegions : List String
  writeRegions : List String
  readElementBytes : List Nat
  writeElementBytes : List Nat
  sourcePaths : List String
  entrypoint : String
  bindingKinds : List String
  bindingLibrary : String
  bindingSourcePath : String
  reflectionPolicy : String
  workgroupPolicy : String
  usesBatchIndex : Bool
  usesLaneIndex : Bool
  deriving Repr

@[simp] def MsmAcceptedLaunchSurface (program : Program) (env : SymbolEnv) : Prop :=
  program.EnvWellFormed env ∧ evalBoolean env program.indexMap.guard

def ProgramImplementsMsmPippengerSemantics
    (program : Program) (sem : MsmPippengerSemantics) : Prop :=
  program.programId = sem.programId
    ∧ program.kernel = sem.kernel
    ∧ program.variant = sem.variant
    ∧ program.family = KernelFamily.msm
    ∧ program.curve = some sem.curve
    ∧ program.route = some sem.route
    ∧ sem.scalarLimbs = 4
    ∧ sem.baseLimbs = 4
    ∧ sem.bucketLimbCount = 12
    ∧ ProgramStepOperators program = sem.phaseOperators
    ∧ ProgramReadRegionNames program = sem.readRegions
    ∧ ProgramWriteRegionNames program = sem.writeRegions
    ∧ ProgramSharedRegionNames program = []
    ∧ ProgramReadElementBytes program = sem.readElementBytes
    ∧ ProgramWriteElementBytes program = sem.writeElementBytes
    ∧ ProgramBarrierScopes program = []
    ∧ ProgramBarrierAfterSteps program = []
    ∧ ProgramUsesBatchIndex program = sem.usesBatchIndex
    ∧ ProgramUsesLaneIndex program = sem.usesLaneIndex
    ∧ ProgramBindingKinds program = sem.bindingKinds
    ∧ ProgramBindingEntrypoints program = List.replicate sem.bindingKinds.length sem.entrypoint
    ∧ ProgramBindingLibraries program = List.replicate sem.bindingKinds.length sem.bindingLibrary
    ∧ ProgramBindingSourcePaths program
        = List.replicate sem.bindingKinds.length sem.bindingSourcePath
    ∧ program.lowering.entrypoints = [sem.entrypoint]
    ∧ program.lowering.sourcePaths = sem.sourcePaths
    ∧ program.lowering.reflectionPolicy = sem.reflectionPolicy
    ∧ program.lowering.workgroupPolicy = sem.workgroupPolicy
    ∧ program.HasCertifiedClaim

def Bn254ClassicChainSurface
    (assign accumulate reduce combine : Program) : Prop :=
  assign.curve = some CurveFamily.bn254
    ∧ accumulate.curve = some CurveFamily.bn254
    ∧ reduce.curve = some CurveFamily.bn254
    ∧ combine.curve = some CurveFamily.bn254
    ∧ assign.route = some MsmRoute.classic
    ∧ accumulate.route = some MsmRoute.classic
    ∧ reduce.route = some MsmRoute.classic
    ∧ combine.route = some MsmRoute.classic
    ∧ ProgramStepOperators assign = [TransitionOperator.msmBucketAssign]
    ∧ ProgramStepOperators accumulate = [TransitionOperator.msmBucketAccumulate]
    ∧ ProgramStepOperators reduce = [TransitionOperator.msmBucketReduce]
    ∧ ProgramStepOperators combine = [TransitionOperator.msmWindowCombine]
    ∧ ProgramWriteRegionNames assign = ["bucket_map"]
    ∧ ProgramWriteRegionNames accumulate = ["buckets"]
    ∧ ProgramWriteRegionNames reduce = ["window_results"]
    ∧ ProgramWriteRegionNames combine = ["final_result"]
    ∧ assign.lowering.reflectionPolicy = accumulate.lowering.reflectionPolicy
    ∧ accumulate.lowering.reflectionPolicy = reduce.lowering.reflectionPolicy
    ∧ reduce.lowering.reflectionPolicy = combine.lowering.reflectionPolicy
    ∧ assign.lowering.workgroupPolicy = accumulate.lowering.workgroupPolicy
    ∧ accumulate.lowering.workgroupPolicy = reduce.lowering.workgroupPolicy
    ∧ reduce.lowering.workgroupPolicy = combine.lowering.workgroupPolicy

def CurveClassicOrNafSurface
    (assign classicAccumulate nafAccumulate : Program)
    (curve : CurveFamily)
    (bindingLibrary : String) : Prop :=
  assign.curve = some curve
    ∧ classicAccumulate.curve = some curve
    ∧ nafAccumulate.curve = some curve
    ∧ assign.route = some MsmRoute.classic
    ∧ classicAccumulate.route = some MsmRoute.classic
    ∧ nafAccumulate.route = some MsmRoute.naf
    ∧ ProgramStepOperators assign = [TransitionOperator.msmBucketAssign]
    ∧ ProgramStepOperators classicAccumulate = [TransitionOperator.msmBucketAccumulate]
    ∧ ProgramStepOperators nafAccumulate = [TransitionOperator.msmBucketAccumulate]
    ∧ ProgramWriteRegionNames assign = ["bucket_map"]
    ∧ ProgramWriteRegionNames classicAccumulate = ["buckets"]
    ∧ ProgramWriteRegionNames nafAccumulate = ["buckets"]
    ∧ ProgramBindingLibraries assign = [bindingLibrary]
    ∧ ProgramBindingLibraries classicAccumulate = [bindingLibrary]
    ∧ ProgramBindingLibraries nafAccumulate = [bindingLibrary]
    ∧ assign.lowering.reflectionPolicy = classicAccumulate.lowering.reflectionPolicy
    ∧ classicAccumulate.lowering.reflectionPolicy = nafAccumulate.lowering.reflectionPolicy
    ∧ assign.lowering.workgroupPolicy = classicAccumulate.lowering.workgroupPolicy
    ∧ classicAccumulate.lowering.workgroupPolicy = nafAccumulate.lowering.workgroupPolicy

def msmSemantics
    (programId kernel variant entrypoint bindingKind bindingLibrary bindingSourcePath : String)
    (curve : CurveFamily)
    (route : MsmRoute)
    (executionStage : MsmExecutionStage)
    (digitSemantics : MsmDigitSemantics)
    (readRegions writeRegions : List String)
    (readElementBytes writeElementBytes : List Nat)
    (sourcePaths : List String) : MsmPippengerSemantics :=
  {
    programId := programId
    kernel := kernel
    variant := variant
    curve := curve
    route := route
    executionStage := executionStage
    digitSemantics := digitSemantics
    scalarLimbs := 4
    baseLimbs := 4
    bucketLimbCount := 12
    phaseOperators :=
      match executionStage with
      | MsmExecutionStage.assign => [TransitionOperator.msmBucketAssign]
      | MsmExecutionStage.accumulate => [TransitionOperator.msmBucketAccumulate]
      | MsmExecutionStage.reduce => [TransitionOperator.msmBucketReduce]
      | MsmExecutionStage.combine => [TransitionOperator.msmWindowCombine]
    readRegions := readRegions
    writeRegions := writeRegions
    readElementBytes := readElementBytes
    writeElementBytes := writeElementBytes
    sourcePaths := sourcePaths
    entrypoint := entrypoint
    bindingKinds := [bindingKind]
    bindingLibrary := bindingLibrary
    bindingSourcePath := bindingSourcePath
    reflectionPolicy := "SPIR-V reflection entrypoints must match the shipped MSM bucket and reduction kernels"
    workgroupPolicy := "certified BN254 route is classic-only; Pallas and Vesta may use classic and NAF entrypoints"
    usesBatchIndex := true
    usesLaneIndex := false
  }

def bn254SourcePaths : List String :=
  ["zkf-metal/src/shaders/msm_bn254.metal", "zkf-metal/src/msm/mod.rs",
    "zkf-metal/src/msm/pippenger.rs", "zkf-metal/src/shaders/msm_sort.metal",
    "zkf-metal/src/shaders/msm_reduce.metal"]

def bn254ReduceSourcePaths : List String :=
  ["zkf-metal/src/shaders/msm_reduce.metal", "zkf-metal/src/msm/mod.rs",
    "zkf-metal/src/msm/pippenger.rs", "zkf-metal/src/shaders/msm_sort.metal",
    "zkf-metal/src/shaders/msm_reduce.metal"]

def pallasSourcePaths : List String :=
  ["zkf-metal/src/shaders/msm_pallas.metal", "zkf-metal/src/msm/mod.rs",
    "zkf-metal/src/msm/pallas_pippenger.rs"]

def vestaSourcePaths : List String :=
  ["zkf-metal/src/shaders/msm_vesta.metal", "zkf-metal/src/msm/mod.rs",
    "zkf-metal/src/msm/vesta_pippenger.rs"]

def bn254ClassicAssignSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_bn254_classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "bn254_msm_library"
    "zkf-metal/src/shaders/msm_bn254.metal"
    CurveFamily.bn254
    MsmRoute.classic
    MsmExecutionStage.assign
    MsmDigitSemantics.classic
    ["scalars"]
    ["bucket_map"]
    [8]
    [4]
    bn254SourcePaths

def bn254ClassicAccumulateSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_bn254_classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "bn254_msm_library"
    "zkf-metal/src/shaders/msm_bn254.metal"
    CurveFamily.bn254
    MsmRoute.classic
    MsmExecutionStage.accumulate
    MsmDigitSemantics.classic
    ["scalars", "bases_x", "bases_y", "bucket_map"]
    ["buckets"]
    [8, 8, 8, 4]
    [8]
    bn254SourcePaths

def bn254ClassicReduceSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_bn254_classic_reduce"
    "msm_bucket_reduce"
    "classic_reduce"
    "msm_bucket_reduce"
    "classic_reduce"
    "bn254_msm_library"
    "zkf-metal/src/shaders/msm_reduce.metal"
    CurveFamily.bn254
    MsmRoute.classic
    MsmExecutionStage.reduce
    MsmDigitSemantics.classic
    ["buckets"]
    ["window_results"]
    [8]
    [8]
    bn254ReduceSourcePaths

def bn254ClassicCombineSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_bn254_classic_combine"
    "msm_window_combine"
    "classic_combine"
    "msm_window_combine"
    "classic_combine"
    "bn254_msm_library"
    "zkf-metal/src/shaders/msm_reduce.metal"
    CurveFamily.bn254
    MsmRoute.classic
    MsmExecutionStage.combine
    MsmDigitSemantics.classic
    ["window_results"]
    ["final_result"]
    [8]
    [8]
    bn254ReduceSourcePaths

def pallasClassicAssignSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_pallas_classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "pallas_msm_library"
    "zkf-metal/src/shaders/msm_pallas.metal"
    CurveFamily.pallas
    MsmRoute.classic
    MsmExecutionStage.assign
    MsmDigitSemantics.classic
    ["scalars"]
    ["bucket_map"]
    [8]
    [4]
    pallasSourcePaths

def pallasClassicAccumulateSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_pallas_classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "pallas_msm_library"
    "zkf-metal/src/shaders/msm_pallas.metal"
    CurveFamily.pallas
    MsmRoute.classic
    MsmExecutionStage.accumulate
    MsmDigitSemantics.classic
    ["scalars", "bases_x", "bases_y", "bucket_map"]
    ["buckets"]
    [8, 8, 8, 4]
    [8]
    pallasSourcePaths

def pallasNafAccumulateSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_pallas_naf_accumulate"
    "msm_bucket_acc_naf"
    "naf_accumulate"
    "msm_bucket_acc_naf"
    "naf_accumulate"
    "pallas_msm_library"
    "zkf-metal/src/shaders/msm_pallas.metal"
    CurveFamily.pallas
    MsmRoute.naf
    MsmExecutionStage.accumulate
    MsmDigitSemantics.naf
    ["bases_x", "bases_y", "bucket_map"]
    ["buckets"]
    [8, 8, 4]
    [8]
    pallasSourcePaths

def vestaClassicAssignSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_vesta_classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "msm_bucket_assign"
    "classic_assign"
    "vesta_msm_library"
    "zkf-metal/src/shaders/msm_vesta.metal"
    CurveFamily.vesta
    MsmRoute.classic
    MsmExecutionStage.assign
    MsmDigitSemantics.classic
    ["scalars"]
    ["bucket_map"]
    [8]
    [4]
    vestaSourcePaths

def vestaClassicAccumulateSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_vesta_classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "msm_bucket_acc"
    "classic_accumulate"
    "vesta_msm_library"
    "zkf-metal/src/shaders/msm_vesta.metal"
    CurveFamily.vesta
    MsmRoute.classic
    MsmExecutionStage.accumulate
    MsmDigitSemantics.classic
    ["scalars", "bases_x", "bases_y", "bucket_map"]
    ["buckets"]
    [8, 8, 8, 4]
    [8]
    vestaSourcePaths

def vestaNafAccumulateSemantics : MsmPippengerSemantics :=
  msmSemantics
    "msm_vesta_naf_accumulate"
    "msm_bucket_acc_naf"
    "naf_accumulate"
    "msm_bucket_acc_naf"
    "naf_accumulate"
    "vesta_msm_library"
    "zkf-metal/src/shaders/msm_vesta.metal"
    CurveFamily.vesta
    MsmRoute.naf
    MsmExecutionStage.accumulate
    MsmDigitSemantics.naf
    ["bases_x", "bases_y", "bucket_map"]
    ["buckets"]
    [8, 8, 4]
    [8]
    vestaSourcePaths

end ZkfMetalProofs
