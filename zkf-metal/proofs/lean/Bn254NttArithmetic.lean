import Bn254Montgomery
import NttReference

namespace ZkfMetalProofs

def bn254LimbsPerElement : Nat := 4
def bn254LimbBytes : Nat := 8

def bn254ButterflyHalfN (stage : Nat) : Nat := 2 ^ stage

def bn254ButterflyGroupSize (stage : Nat) : Nat :=
  bn254ButterflyHalfN stage * 2

def bn254ButterflyGroup (stage tid : Nat) : Nat :=
  tid / bn254ButterflyHalfN stage

def bn254ButterflyPos (stage tid : Nat) : Nat :=
  tid % bn254ButterflyHalfN stage

def bn254ButterflyIdx0 (stage tid : Nat) : Nat :=
  bn254ButterflyGroup stage tid * bn254ButterflyGroupSize stage + bn254ButterflyPos stage tid

def bn254ButterflyIdx1 (stage tid : Nat) : Nat :=
  bn254ButterflyIdx0 stage tid + bn254ButterflyHalfN stage

def bn254ButterflyTwiddleIndex (stage tid : Nat) : Nat :=
  bn254ButterflyHalfN stage + bn254ButterflyPos stage tid

def Bn254ButterflyBranchActive (stage n tid : Nat) : Prop :=
  bn254ButterflyHalfN stage > 0 ∧ bn254ButterflyIdx1 stage tid < n

def bn254ButterflyOut0 (lhs rhs twiddle : Nat) : Nat :=
  bn254MontAdd lhs (bn254MontMul twiddle rhs)

def bn254ButterflyOut1 (lhs rhs twiddle : Nat) : Nat :=
  bn254MontSub lhs (bn254MontMul twiddle rhs)

def ProgramImplementsBn254ButterflyArithmetic (program : Program) : Prop :=
  program.programId = "ntt_butterfly_bn254"
    ∧ program.kernel = "ntt_butterfly_bn254"
    ∧ program.variant = "bn254_single"
    ∧ program.family = KernelFamily.ntt
    ∧ program.field = some FieldFamily.bn254Scalar
    ∧ ProgramStepOperators program
        = [TransitionOperator.nttButterflyStage, TransitionOperator.layoutWriteback]
    ∧ ProgramReadRegionNames program = ["values", "twiddles"]
    ∧ ProgramWriteRegionNames program = ["values"]
    ∧ ProgramReadElementBytes program = [bn254LimbBytes, bn254LimbBytes]
    ∧ ProgramWriteElementBytes program = [bn254LimbBytes]
    ∧ ProgramBarrierScopes program = ["buffers"]
    ∧ ProgramBarrierAfterSteps program = [0]
    ∧ ProgramBindingKinds program = ["bn254_single", "bn254_single"]
    ∧ ProgramBindingEntrypoints program = ["ntt_butterfly_bn254", "ntt_butterfly_bn254"]
    ∧ ProgramBindingSourcePaths program
        = ["zkf-metal/src/shaders/ntt_bn254.metal", "zkf-metal/src/shaders/ntt_bn254.metal"]
    ∧ program.lowering.entrypoints = ["ntt_butterfly_bn254"]
    ∧ program.lowering.sourcePaths
        = [ "zkf-metal/src/shaders/field_bn254_fr.metal"
          , "zkf-metal/src/shaders/ntt_bn254.metal"
          , "zkf-metal/src/ntt/p3_adapter.rs"
          , "zkf-metal/src/ntt/radix2.rs"
          , "zkf-metal/src/ntt/bn254.rs"
          ]
    ∧ program.lowering.reflectionPolicy
        = "SPIR-V reflection entrypoints must match the shipped single, batch, small, and hybrid NTT entrypoints"
    ∧ program.lowering.workgroupPolicy
        = "one thread per butterfly with host-enforced buffer barriers between stages"
    ∧ program.HasCertifiedClaim

theorem bn254_butterfly_twiddle_index_matches_shader (stage tid : Nat) :
    bn254ButterflyTwiddleIndex stage tid =
      bn254ButterflyHalfN stage + bn254ButterflyPos stage tid := by
  rfl

theorem bn254_butterfly_out0_canonical (lhs rhs twiddle : Nat) :
    Bn254Canonical (bn254ButterflyOut0 lhs rhs twiddle) := by
  unfold bn254ButterflyOut0
  exact bn254_mont_add_canonical lhs (bn254MontMul twiddle rhs)

theorem bn254_butterfly_out1_canonical (lhs rhs twiddle : Nat) :
    Bn254Canonical (bn254ButterflyOut1 lhs rhs twiddle) := by
  unfold bn254ButterflyOut1
  exact bn254_mont_sub_canonical lhs (bn254MontMul twiddle rhs)

theorem bn254ButterflyArithmeticSurfaceSound :
    ProgramImplementsBn254ButterflyArithmetic ntt_butterfly_bn254
      ∧
    (∀ stage n tid lhs rhs twiddle,
      Bn254ButterflyBranchActive stage n tid ->
      Bn254Canonical lhs ->
      Bn254Canonical rhs ->
      Bn254Canonical twiddle ->
      Bn254Canonical (bn254MontMul twiddle rhs)
        ∧ Bn254Canonical (bn254ButterflyOut0 lhs rhs twiddle)
        ∧ Bn254Canonical (bn254ButterflyOut1 lhs rhs twiddle)
        ∧ bn254ButterflyOut0 lhs rhs twiddle
            = bn254Normalize (lhs + bn254MontMul twiddle rhs)
        ∧ bn254ButterflyOut1 lhs rhs twiddle
            = bn254Normalize (lhs + bn254Modulus - bn254MontMul twiddle rhs)
        ∧ bn254ButterflyTwiddleIndex stage tid
            = bn254ButterflyHalfN stage + bn254ButterflyPos stage tid) := by
  refine ⟨?_, ?_⟩
  · simp [ProgramImplementsBn254ButterflyArithmetic, bn254LimbBytes, ntt_butterfly_bn254]
  · intro stage n tid lhs rhs twiddle _active _hlhs _hrhs _htwiddle
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
    · exact bn254_mont_mul_canonical twiddle rhs
    · exact bn254_butterfly_out0_canonical lhs rhs twiddle
    · exact bn254_butterfly_out1_canonical lhs rhs twiddle
    · simp [bn254ButterflyOut0, bn254_mont_add_sound]
    · simp [bn254ButterflyOut1, bn254_mont_sub_sound]
    · rfl

end ZkfMetalProofs
