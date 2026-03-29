import FamilySpecs

namespace ZkfMetalProofs

def nttButterflySpec
    (programId kernel variant : String)
    (field : FieldFamily)
    (_batched : Bool) : KernelSpec :=
  {
    programId := programId
    family := KernelFamily.ntt
    kernel := kernel
    variant := variant
    field := some field
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.nttButterflyStage,
      TransitionOperator.layoutWriteback
    ]
    requiredReads := ["values", "twiddles"]
    requiredWrites := ["values"]
    requiresBarrier := true
    certifiedClaim := true
  }

def nttSmallSpec (programId kernel variant : String) (field : FieldFamily) : KernelSpec :=
  {
    programId := programId
    family := KernelFamily.ntt
    kernel := kernel
    variant := variant
    field := some field
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.nttSmallTransform,
      TransitionOperator.layoutWriteback
    ]
    requiredReads := ["values", "twiddles"]
    requiredWrites := ["values"]
    requiresBarrier := false
    certifiedClaim := true
  }

def nttHybridSpec (programId kernel variant : String) (field : FieldFamily) : KernelSpec :=
  {
    programId := programId
    family := KernelFamily.ntt
    kernel := kernel
    variant := variant
    field := some field
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.nttHybridStage,
      TransitionOperator.layoutWriteback
    ]
    requiredReads := ["values", "twiddles"]
    requiredWrites := ["values"]
    requiresBarrier := false
    certifiedClaim := true
  }

def goldilocksButterflySpec : KernelSpec :=
  nttButterflySpec "ntt_butterfly_goldilocks" "ntt_butterfly_goldilocks" "goldilocks_single"
    FieldFamily.goldilocks false

def goldilocksBatchSpec : KernelSpec :=
  nttButterflySpec
    "ntt_butterfly_goldilocks_batch"
    "ntt_butterfly_goldilocks_batch"
    "goldilocks_batch"
    FieldFamily.goldilocks true

def goldilocksSmallSpec : KernelSpec :=
  nttSmallSpec "ntt_small_goldilocks" "ntt_small_goldilocks" "goldilocks_small"
    FieldFamily.goldilocks

def goldilocksHybridSpec : KernelSpec :=
  nttHybridSpec "ntt_hybrid_goldilocks" "ntt_hybrid_goldilocks" "goldilocks_hybrid"
    FieldFamily.goldilocks

def babybearButterflySpec : KernelSpec :=
  nttButterflySpec "ntt_butterfly_babybear" "ntt_butterfly_babybear" "babybear_single"
    FieldFamily.babyBear false

def babybearBatchSpec : KernelSpec :=
  nttButterflySpec
    "ntt_butterfly_babybear_batch"
    "ntt_butterfly_babybear_batch"
    "babybear_batch"
    FieldFamily.babyBear true

def bn254ButterflySpec : KernelSpec :=
  nttButterflySpec "ntt_butterfly_bn254" "ntt_butterfly_bn254" "bn254_single"
    FieldFamily.bn254Scalar false

def bn254SmallSpec : KernelSpec :=
  nttSmallSpec "ntt_small_bn254" "ntt_small_bn254" "bn254_small"
    FieldFamily.bn254Scalar

def bn254HybridSpec : KernelSpec :=
  nttHybridSpec "ntt_hybrid_bn254" "ntt_hybrid_bn254" "bn254_hybrid"
    FieldFamily.bn254Scalar

inductive NttExecutionModel where
  | butterfly
  | small
  | hybrid
  deriving Repr

inductive NttTwiddleLayout where
  | stageMajor
  | batchedStageMajor
  | montgomeryStageMajor
  deriving Repr

structure NttTransformSemantics where
  programId : String
  kernel : String
  variant : String
  field : FieldFamily
  executionModel : NttExecutionModel
  twiddleLayout : NttTwiddleLayout
  radix : Nat
  stageSpan : Nat
  phaseOperators : List TransitionOperator
  sourcePaths : List String
  entrypoint : String
  bindingKinds : List String
  bindingLibrary : String
  bindingSourcePath : String
  reflectionPolicy : String
  workgroupPolicy : String
  elementBytes : Nat
  requiresHostBarrier : Bool
  usesBatchIndex : Bool
  montgomeryPath : Bool
  deriving Repr

@[simp] def NttAcceptedLaunchSurface (program : Program) (env : SymbolEnv) : Prop :=
  program.EnvWellFormed env ∧ evalBoolean env program.indexMap.guard

def ProgramImplementsNttTransformSemantics
    (program : Program) (sem : NttTransformSemantics) : Prop :=
  program.programId = sem.programId
    ∧ program.kernel = sem.kernel
    ∧ program.variant = sem.variant
    ∧ program.family = KernelFamily.ntt
    ∧ program.field = some sem.field
    ∧ sem.radix = 2
    ∧ sem.stageSpan = 2
    ∧ ProgramStepOperators program = sem.phaseOperators
    ∧ ProgramReadRegionNames program = ["values", "twiddles"]
    ∧ ProgramWriteRegionNames program = ["values"]
    ∧ ProgramSharedRegionNames program = []
    ∧ ProgramReadElementBytes program = [sem.elementBytes, sem.elementBytes]
    ∧ ProgramWriteElementBytes program = [sem.elementBytes]
    ∧ ProgramBarrierScopes program
        = (match sem.requiresHostBarrier with
          | true => ["buffers"]
          | false => [])
    ∧ ProgramBarrierAfterSteps program
        = (match sem.requiresHostBarrier with
          | true => [0]
          | false => [])
    ∧ ProgramUsesLaneIndex program = false
    ∧ ProgramUsesBatchIndex program = sem.usesBatchIndex
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

def NttLargeScheduleSurface (single batched : Program) (field : FieldFamily) (elementBytes : Nat) :
    Prop :=
  single.family = KernelFamily.ntt
    ∧ batched.family = KernelFamily.ntt
    ∧ single.field = some field
    ∧ batched.field = some field
    ∧ ProgramStepOperators single
        = [TransitionOperator.nttButterflyStage, TransitionOperator.layoutWriteback]
    ∧ ProgramStepOperators batched = ProgramStepOperators single
    ∧ ProgramReadRegionNames single = ["values", "twiddles"]
    ∧ ProgramReadRegionNames batched = ["values", "twiddles"]
    ∧ ProgramWriteRegionNames single = ["values"]
    ∧ ProgramWriteRegionNames batched = ["values"]
    ∧ ProgramReadElementBytes single = [elementBytes, elementBytes]
    ∧ ProgramReadElementBytes batched = [elementBytes, elementBytes]
    ∧ ProgramWriteElementBytes single = [elementBytes]
    ∧ ProgramWriteElementBytes batched = [elementBytes]
    ∧ ProgramBarrierScopes single = ["buffers"]
    ∧ ProgramBarrierScopes batched = ["buffers"]
    ∧ ProgramBarrierAfterSteps single = [0]
    ∧ ProgramBarrierAfterSteps batched = [0]
    ∧ ProgramUsesBatchIndex single = false
    ∧ ProgramUsesBatchIndex batched = true
    ∧ single.lowering.reflectionPolicy = batched.lowering.reflectionPolicy
    ∧ single.lowering.workgroupPolicy = batched.lowering.workgroupPolicy

def NttStagedTransformSurface
    (butterfly small hybrid : Program)
    (field : FieldFamily)
    (elementBytes : Nat)
    (montgomeryPath : Bool) : Prop :=
  butterfly.family = KernelFamily.ntt
    ∧ small.family = KernelFamily.ntt
    ∧ hybrid.family = KernelFamily.ntt
    ∧ butterfly.field = some field
    ∧ small.field = some field
    ∧ hybrid.field = some field
    ∧ ProgramStepOperators butterfly
        = [TransitionOperator.nttButterflyStage, TransitionOperator.layoutWriteback]
    ∧ ProgramStepOperators small
        = [TransitionOperator.nttSmallTransform, TransitionOperator.layoutWriteback]
    ∧ ProgramStepOperators hybrid
        = [TransitionOperator.nttHybridStage, TransitionOperator.layoutWriteback]
    ∧ ProgramReadRegionNames butterfly = ["values", "twiddles"]
    ∧ ProgramReadRegionNames small = ["values", "twiddles"]
    ∧ ProgramReadRegionNames hybrid = ["values", "twiddles"]
    ∧ ProgramWriteRegionNames butterfly = ["values"]
    ∧ ProgramWriteRegionNames small = ["values"]
    ∧ ProgramWriteRegionNames hybrid = ["values"]
    ∧ ProgramReadElementBytes butterfly = [elementBytes, elementBytes]
    ∧ ProgramReadElementBytes small = [elementBytes, elementBytes]
    ∧ ProgramReadElementBytes hybrid = [elementBytes, elementBytes]
    ∧ ProgramWriteElementBytes butterfly = [elementBytes]
    ∧ ProgramWriteElementBytes small = [elementBytes]
    ∧ ProgramWriteElementBytes hybrid = [elementBytes]
    ∧ ProgramBarrierScopes butterfly = ["buffers"]
    ∧ ProgramBarrierAfterSteps butterfly = [0]
    ∧ ProgramBarrierScopes small = []
    ∧ ProgramBarrierAfterSteps small = []
    ∧ ProgramBarrierScopes hybrid = []
    ∧ ProgramBarrierAfterSteps hybrid = []
    ∧ ProgramUsesBatchIndex butterfly = false
    ∧ ProgramUsesBatchIndex small = false
    ∧ ProgramUsesBatchIndex hybrid = false
    ∧ butterfly.lowering.reflectionPolicy = small.lowering.reflectionPolicy
    ∧ butterfly.lowering.workgroupPolicy = small.lowering.workgroupPolicy
    ∧ small.lowering.reflectionPolicy = hybrid.lowering.reflectionPolicy
    ∧ small.lowering.workgroupPolicy = hybrid.lowering.workgroupPolicy
    ∧ (montgomeryPath = true ↔ field = FieldFamily.bn254Scalar)

def nttTransformSemantics
    (programId kernel variant entrypoint bindingKind : String)
    (field : FieldFamily)
    (executionModel : NttExecutionModel)
    (twiddleLayout : NttTwiddleLayout)
    (sourcePaths : List String)
    (bindingLibrary bindingSourcePath : String)
    (elementBytes : Nat)
    (requiresHostBarrier usesBatchIndex montgomeryPath : Bool) : NttTransformSemantics :=
  {
    programId := programId
    kernel := kernel
    variant := variant
    field := field
    executionModel := executionModel
    twiddleLayout := twiddleLayout
    radix := 2
    stageSpan := 2
    phaseOperators :=
      match executionModel with
      | NttExecutionModel.butterfly =>
          [TransitionOperator.nttButterflyStage, TransitionOperator.layoutWriteback]
      | NttExecutionModel.small =>
          [TransitionOperator.nttSmallTransform, TransitionOperator.layoutWriteback]
      | NttExecutionModel.hybrid =>
          [TransitionOperator.nttHybridStage, TransitionOperator.layoutWriteback]
    sourcePaths := sourcePaths
    entrypoint := entrypoint
    bindingKinds := [bindingKind, bindingKind]
    bindingLibrary := bindingLibrary
    bindingSourcePath := bindingSourcePath
    reflectionPolicy :=
      "SPIR-V reflection entrypoints must match the shipped single, batch, small, and hybrid NTT entrypoints"
    workgroupPolicy := "one thread per butterfly with host-enforced buffer barriers between stages"
    elementBytes := elementBytes
    requiresHostBarrier := requiresHostBarrier
    usesBatchIndex := usesBatchIndex
    montgomeryPath := montgomeryPath
  }

def goldilocksButterflyTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_butterfly_goldilocks"
    "ntt_butterfly_goldilocks"
    "goldilocks_single"
    "ntt_butterfly_goldilocks"
    "goldilocks_single"
    FieldFamily.goldilocks
    NttExecutionModel.butterfly
    NttTwiddleLayout.stageMajor
    ["zkf-metal/src/shaders/ntt_radix2.metal", "zkf-metal/src/ntt/p3_adapter.rs",
      "zkf-metal/src/ntt/radix2.rs", "zkf-metal/src/ntt/bn254.rs"]
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2.metal"
    8
    true
    false
    false

def goldilocksBatchTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_butterfly_goldilocks_batch"
    "ntt_butterfly_goldilocks_batch"
    "goldilocks_batch"
    "ntt_butterfly_goldilocks_batch"
    "goldilocks_batch"
    FieldFamily.goldilocks
    NttExecutionModel.butterfly
    NttTwiddleLayout.batchedStageMajor
    ["zkf-metal/src/shaders/ntt_radix2_batch.metal", "zkf-metal/src/ntt/p3_adapter.rs",
      "zkf-metal/src/ntt/radix2.rs", "zkf-metal/src/ntt/bn254.rs"]
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2_batch.metal"
    8
    true
    true
    false

def goldilocksSmallTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_small_goldilocks"
    "ntt_small_goldilocks"
    "goldilocks_small"
    "ntt_small_goldilocks"
    "goldilocks_small"
    FieldFamily.goldilocks
    NttExecutionModel.small
    NttTwiddleLayout.stageMajor
    goldilocksButterflyTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2.metal"
    8
    false
    false
    false

def goldilocksHybridTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_hybrid_goldilocks"
    "ntt_hybrid_goldilocks"
    "goldilocks_hybrid"
    "ntt_hybrid_goldilocks"
    "goldilocks_hybrid"
    FieldFamily.goldilocks
    NttExecutionModel.hybrid
    NttTwiddleLayout.stageMajor
    goldilocksButterflyTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2.metal"
    8
    false
    false
    false

def babybearButterflyTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_butterfly_babybear"
    "ntt_butterfly_babybear"
    "babybear_single"
    "ntt_butterfly_babybear"
    "babybear_single"
    FieldFamily.babyBear
    NttExecutionModel.butterfly
    NttTwiddleLayout.stageMajor
    goldilocksButterflyTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2.metal"
    4
    true
    false
    false

def babybearBatchTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_butterfly_babybear_batch"
    "ntt_butterfly_babybear_batch"
    "babybear_batch"
    "ntt_butterfly_babybear_batch"
    "babybear_batch"
    FieldFamily.babyBear
    NttExecutionModel.butterfly
    NttTwiddleLayout.batchedStageMajor
    goldilocksBatchTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_radix2_batch.metal"
    4
    true
    true
    false

def bn254ButterflyTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_butterfly_bn254"
    "ntt_butterfly_bn254"
    "bn254_single"
    "ntt_butterfly_bn254"
    "bn254_single"
    FieldFamily.bn254Scalar
    NttExecutionModel.butterfly
    NttTwiddleLayout.montgomeryStageMajor
    ["zkf-metal/src/shaders/field_bn254_fr.metal", "zkf-metal/src/shaders/ntt_bn254.metal",
      "zkf-metal/src/ntt/p3_adapter.rs", "zkf-metal/src/ntt/radix2.rs",
      "zkf-metal/src/ntt/bn254.rs"]
    "main_library"
    "zkf-metal/src/shaders/ntt_bn254.metal"
    8
    true
    false
    true

def bn254SmallTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_small_bn254"
    "ntt_small_bn254"
    "bn254_small"
    "ntt_small_bn254"
    "bn254_small"
    FieldFamily.bn254Scalar
    NttExecutionModel.small
    NttTwiddleLayout.montgomeryStageMajor
    bn254ButterflyTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_bn254.metal"
    8
    false
    false
    true

def bn254HybridTransformSemantics : NttTransformSemantics :=
  nttTransformSemantics
    "ntt_hybrid_bn254"
    "ntt_hybrid_bn254"
    "bn254_hybrid"
    "ntt_hybrid_bn254"
    "bn254_hybrid"
    FieldFamily.bn254Scalar
    NttExecutionModel.hybrid
    NttTwiddleLayout.montgomeryStageMajor
    bn254ButterflyTransformSemantics.sourcePaths
    "main_library"
    "zkf-metal/src/shaders/ntt_bn254.metal"
    8
    false
    false
    true

end ZkfMetalProofs
