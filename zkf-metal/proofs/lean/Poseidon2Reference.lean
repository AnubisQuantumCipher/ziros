import FamilySpecs

namespace ZkfMetalProofs

def poseidon2Spec (programId kernel variant : String) (field : FieldFamily) (requiresBarrier : Bool) :
    KernelSpec :=
  {
    programId := programId
    family := KernelFamily.poseidon2
    kernel := kernel
    variant := variant
    field := some field
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.poseidon2ExternalRound,
      TransitionOperator.poseidon2MatrixLayer,
      TransitionOperator.poseidon2SBox,
      TransitionOperator.poseidon2InternalRound
    ]
    requiredReads := ["state", "round_constants", "matrix_diag"]
    requiredWrites := ["state"]
    requiresBarrier := requiresBarrier
    certifiedClaim := true
  }

def goldilocksScalarSpec : KernelSpec :=
  poseidon2Spec "poseidon2_goldilocks" "poseidon2_goldilocks" "goldilocks_scalar"
    FieldFamily.goldilocks false

def goldilocksSimdSpec : KernelSpec :=
  poseidon2Spec "poseidon2_goldilocks_simd" "poseidon2_goldilocks_simd" "goldilocks_simd"
    FieldFamily.goldilocks true

def babybearScalarSpec : KernelSpec :=
  poseidon2Spec "poseidon2_babybear" "poseidon2_babybear" "babybear_scalar"
    FieldFamily.babyBear false

def babybearSimdSpec : KernelSpec :=
  poseidon2Spec "poseidon2_babybear_simd" "poseidon2_babybear_simd" "babybear_simd"
    FieldFamily.babyBear true

inductive Poseidon2ExecutionModel where
  | scalar
  | simd
  deriving Repr

structure Poseidon2PermutationSemantics where
  programId : String
  kernel : String
  variant : String
  field : FieldFamily
  executionModel : Poseidon2ExecutionModel
  stateWidth : Nat
  sboxDegree : Nat
  externalChunkWidth : Nat
  internalDiagWidth : Nat
  phaseOperators : List TransitionOperator
  sourcePaths : List String
  entrypoint : String
  bindingKinds : List String
  reflectionPolicy : String
  workgroupPolicy : String
  elementBytes : Nat
  deriving Repr

@[simp] def Poseidon2AcceptedLaunchSurface (program : Program) (env : SymbolEnv) : Prop :=
  program.EnvWellFormed env ∧ evalBoolean env program.indexMap.guard

def ProgramImplementsPoseidon2PermutationSemantics
    (program : Program) (sem : Poseidon2PermutationSemantics) : Prop :=
  program.programId = sem.programId
    ∧ program.kernel = sem.kernel
    ∧ program.variant = sem.variant
    ∧ program.family = KernelFamily.poseidon2
    ∧ program.field = some sem.field
    ∧ sem.stateWidth = 16
    ∧ sem.sboxDegree = 7
    ∧ sem.externalChunkWidth = 4
    ∧ sem.internalDiagWidth = 16
    ∧ ProgramStepOperators program = sem.phaseOperators
    ∧ ProgramReadRegionNames program = ["state", "round_constants", "matrix_diag"]
    ∧ ProgramWriteRegionNames program = ["state"]
    ∧ ProgramReadElementBytes program = [sem.elementBytes, sem.elementBytes, sem.elementBytes]
    ∧ ProgramWriteElementBytes program = [sem.elementBytes]
    ∧ ProgramSharedRegionNames program
        = (match sem.executionModel with
          | Poseidon2ExecutionModel.scalar => []
          | Poseidon2ExecutionModel.simd => ["lane_scratch"])
    ∧ ProgramSharedElementBytes program
        = (match sem.executionModel with
          | Poseidon2ExecutionModel.scalar => []
          | Poseidon2ExecutionModel.simd => [sem.elementBytes])
    ∧ ProgramBarrierScopes program
        = (match sem.executionModel with
          | Poseidon2ExecutionModel.scalar => []
          | Poseidon2ExecutionModel.simd => ["threadgroup"])
    ∧ ProgramBarrierAfterSteps program
        = (match sem.executionModel with
          | Poseidon2ExecutionModel.scalar => []
          | Poseidon2ExecutionModel.simd => [1])
    ∧ ProgramUsesLaneIndex program
        = (match sem.executionModel with
          | Poseidon2ExecutionModel.scalar => false
          | Poseidon2ExecutionModel.simd => true)
    ∧ ProgramBindingKinds program = sem.bindingKinds
    ∧ ProgramBindingEntrypoints program = List.replicate sem.bindingKinds.length sem.entrypoint
    ∧ program.lowering.entrypoints = [sem.entrypoint]
    ∧ program.lowering.sourcePaths = sem.sourcePaths
    ∧ program.lowering.reflectionPolicy = sem.reflectionPolicy
    ∧ program.lowering.workgroupPolicy = sem.workgroupPolicy
    ∧ program.HasCertifiedClaim

def Poseidon2EquivalentScalarSimdSurface (scalar simd : Program) : Prop :=
  ProgramStepOperators scalar = ProgramStepOperators simd
    ∧ ProgramReadRegionNames scalar = ProgramReadRegionNames simd
    ∧ ProgramWriteRegionNames scalar = ProgramWriteRegionNames simd
    ∧ ProgramReadElementBytes scalar = ProgramReadElementBytes simd
    ∧ ProgramWriteElementBytes scalar = ProgramWriteElementBytes simd
    ∧ scalar.lowering.sourcePaths = simd.lowering.sourcePaths
    ∧ scalar.lowering.reflectionPolicy = simd.lowering.reflectionPolicy
    ∧ scalar.lowering.workgroupPolicy = simd.lowering.workgroupPolicy

def goldilocksScalarPermutationSemantics : Poseidon2PermutationSemantics :=
  {
    programId := "poseidon2_goldilocks"
    kernel := "poseidon2_goldilocks"
    variant := "goldilocks_scalar"
    field := FieldFamily.goldilocks
    executionModel := Poseidon2ExecutionModel.scalar
    stateWidth := 16
    sboxDegree := 7
    externalChunkWidth := 4
    internalDiagWidth := 16
    phaseOperators := [
      TransitionOperator.poseidon2ExternalRound,
      TransitionOperator.poseidon2MatrixLayer,
      TransitionOperator.poseidon2SBox,
      TransitionOperator.poseidon2InternalRound
    ]
    sourcePaths := ["zkf-metal/src/shaders/poseidon2.metal", "zkf-metal/src/poseidon2/mod.rs"]
    entrypoint := "poseidon2_goldilocks"
    bindingKinds := ["scalar", "scalar", "scalar", "scalar"]
    reflectionPolicy := "SPIR-V reflection entrypoints must match the scalar or SIMD Poseidon2 kernel exactly"
    workgroupPolicy := "scalar path uses one thread per permutation; SIMD path uses 16 threads per permutation"
    elementBytes := 8
  }

def goldilocksSimdPermutationSemantics : Poseidon2PermutationSemantics :=
  {
    programId := "poseidon2_goldilocks_simd"
    kernel := "poseidon2_goldilocks_simd"
    variant := "goldilocks_simd"
    field := FieldFamily.goldilocks
    executionModel := Poseidon2ExecutionModel.simd
    stateWidth := 16
    sboxDegree := 7
    externalChunkWidth := 4
    internalDiagWidth := 16
    phaseOperators := goldilocksScalarPermutationSemantics.phaseOperators
    sourcePaths := goldilocksScalarPermutationSemantics.sourcePaths
    entrypoint := "poseidon2_goldilocks_simd"
    bindingKinds := ["simd", "simd", "simd", "simd"]
    reflectionPolicy := goldilocksScalarPermutationSemantics.reflectionPolicy
    workgroupPolicy := goldilocksScalarPermutationSemantics.workgroupPolicy
    elementBytes := 8
  }

def babybearScalarPermutationSemantics : Poseidon2PermutationSemantics :=
  {
    programId := "poseidon2_babybear"
    kernel := "poseidon2_babybear"
    variant := "babybear_scalar"
    field := FieldFamily.babyBear
    executionModel := Poseidon2ExecutionModel.scalar
    stateWidth := 16
    sboxDegree := 7
    externalChunkWidth := 4
    internalDiagWidth := 16
    phaseOperators := goldilocksScalarPermutationSemantics.phaseOperators
    sourcePaths := goldilocksScalarPermutationSemantics.sourcePaths
    entrypoint := "poseidon2_babybear"
    bindingKinds := ["scalar", "scalar", "scalar", "scalar"]
    reflectionPolicy := goldilocksScalarPermutationSemantics.reflectionPolicy
    workgroupPolicy := goldilocksScalarPermutationSemantics.workgroupPolicy
    elementBytes := 4
  }

def babybearSimdPermutationSemantics : Poseidon2PermutationSemantics :=
  {
    programId := "poseidon2_babybear_simd"
    kernel := "poseidon2_babybear_simd"
    variant := "babybear_simd"
    field := FieldFamily.babyBear
    executionModel := Poseidon2ExecutionModel.simd
    stateWidth := 16
    sboxDegree := 7
    externalChunkWidth := 4
    internalDiagWidth := 16
    phaseOperators := goldilocksScalarPermutationSemantics.phaseOperators
    sourcePaths := goldilocksScalarPermutationSemantics.sourcePaths
    entrypoint := "poseidon2_babybear_simd"
    bindingKinds := ["simd", "simd", "simd", "simd"]
    reflectionPolicy := goldilocksScalarPermutationSemantics.reflectionPolicy
    workgroupPolicy := goldilocksScalarPermutationSemantics.workgroupPolicy
    elementBytes := 4
  }

end ZkfMetalProofs
