import FamilySpecs

namespace ZkfMetalProofs

def sha256Spec : KernelSpec :=
  {
    programId := "batch_sha256"
    family := KernelFamily.hash
    kernel := "batch_sha256"
    variant := "sha256_batch"
    field := some FieldFamily.bytes
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.sha256MessageSchedule,
      TransitionOperator.sha256CompressionRound,
      TransitionOperator.layoutWriteback
    ]
    requiredReads := ["inputs"]
    requiredWrites := ["digests"]
    requiresBarrier := false
    certifiedClaim := true
  }

def keccakSpec : KernelSpec :=
  {
    programId := "batch_keccak256"
    family := KernelFamily.hash
    kernel := "batch_keccak256"
    variant := "keccak256_batch"
    field := some FieldFamily.bytes
    curve := none
    route := none
    requiredOperators := [
      TransitionOperator.keccakTheta,
      TransitionOperator.keccakRhoPi,
      TransitionOperator.keccakChiIota,
      TransitionOperator.layoutWriteback
    ]
    requiredReads := ["inputs"]
    requiredWrites := ["digests"]
    requiresBarrier := false
    certifiedClaim := true
  }

inductive HashReferenceModel where
  | sha256MerkleDamgard
  | keccak256Sponge
  deriving Repr

structure HashDigestSemantics where
  programId : String
  kernel : String
  variant : String
  field : FieldFamily
  referenceModel : HashReferenceModel
  blockBytes : Nat
  scheduleWords : Nat
  roundCount : Nat
  digestBytes : Nat
  phaseOperators : List TransitionOperator
  sourcePaths : List String
  entrypoint : String
  bindingKinds : List String
  reflectionPolicy : String
  workgroupPolicy : String
  deriving Repr

@[simp] def sha256PaddedBytes (inputLen : Nat) : Nat :=
  ((inputLen + 9 + 63) / 64) * 64

@[simp] def sha256BlockCount (inputLen : Nat) : Nat :=
  sha256PaddedBytes inputLen / 64

@[simp] def keccakRateBytes : Nat := 136

@[simp] def keccakCapacityBytes : Nat := 64

@[simp] def HashAcceptedLaunchSurface (program : Program) (env : SymbolEnv) : Prop :=
  program.EnvWellFormed env ∧ evalBoolean env program.indexMap.guard

def ProgramImplementsHashDigestSemantics (program : Program) (sem : HashDigestSemantics) : Prop :=
  program.programId = sem.programId
    ∧ program.kernel = sem.kernel
    ∧ program.variant = sem.variant
    ∧ program.family = KernelFamily.hash
    ∧ program.field = some sem.field
    ∧ sem.digestBytes = 32
    ∧ ProgramStepOperators program = sem.phaseOperators
    ∧ ProgramReadRegionNames program = ["inputs"]
    ∧ ProgramWriteRegionNames program = ["digests"]
    ∧ ProgramSharedRegionNames program = []
    ∧ ProgramReadElementBytes program = [1]
    ∧ ProgramWriteElementBytes program = [1]
    ∧ ProgramBarrierScopes program = []
    ∧ ProgramBindingKinds program = sem.bindingKinds
    ∧ ProgramBindingEntrypoints program = List.replicate sem.bindingKinds.length sem.entrypoint
    ∧ program.lowering.entrypoints = [sem.entrypoint]
    ∧ program.lowering.sourcePaths = sem.sourcePaths
    ∧ program.lowering.reflectionPolicy = sem.reflectionPolicy
    ∧ program.lowering.workgroupPolicy = sem.workgroupPolicy
    ∧ program.HasCertifiedClaim

def sha256ExactDigestSemantics : HashDigestSemantics :=
  {
    programId := "batch_sha256"
    kernel := "batch_sha256"
    variant := "sha256_batch"
    field := FieldFamily.bytes
    referenceModel := HashReferenceModel.sha256MerkleDamgard
    blockBytes := 64
    scheduleWords := 64
    roundCount := 64
    digestBytes := 32
    phaseOperators := [
      TransitionOperator.sha256MessageSchedule,
      TransitionOperator.sha256CompressionRound,
      TransitionOperator.layoutWriteback
    ]
    sourcePaths := ["zkf-metal/src/shaders/sha256.metal", "zkf-metal/src/hash/mod.rs"]
    entrypoint := "batch_sha256"
    bindingKinds := ["sha256_batch", "sha256_batch", "sha256_batch"]
    reflectionPolicy := "SPIR-V reflection entrypoints must exactly match the shipped Metal hash entrypoint"
    workgroupPolicy := "one thread per message; host threads-per-group capped at 256"
  }

def keccakExactDigestSemantics : HashDigestSemantics :=
  {
    programId := "batch_keccak256"
    kernel := "batch_keccak256"
    variant := "keccak256_batch"
    field := FieldFamily.bytes
    referenceModel := HashReferenceModel.keccak256Sponge
    blockBytes := keccakRateBytes
    scheduleWords := 25
    roundCount := 24
    digestBytes := 32
    phaseOperators := [
      TransitionOperator.keccakTheta,
      TransitionOperator.keccakRhoPi,
      TransitionOperator.keccakChiIota,
      TransitionOperator.layoutWriteback
    ]
    sourcePaths := ["zkf-metal/src/shaders/keccak256.metal", "zkf-metal/src/hash/mod.rs"]
    entrypoint := "batch_keccak256"
    bindingKinds := ["keccak256_batch", "keccak256_batch", "keccak256_batch", "keccak256_batch"]
    reflectionPolicy := "SPIR-V reflection entrypoints must exactly match the shipped Metal hash entrypoint"
    workgroupPolicy := "one thread per message; host threads-per-group capped at 256"
  }

end ZkfMetalProofs
