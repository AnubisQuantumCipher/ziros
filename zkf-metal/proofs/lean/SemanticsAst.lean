import Init
import Generated.GpuPrograms

namespace ZkfMetalProofs

abbrev Program := GeneratedProgram
abbrev SymbolEnv := String → Nat

@[simp] def Program.stepCount (program : Program) : Nat :=
  program.steps.length

@[simp] def Program.barrierCount (program : Program) : Nat :=
  program.barriers.length

@[simp] def Program.entrypointCount (program : Program) : Nat :=
  program.lowering.entrypoints.length

def evalNumeric (env : SymbolEnv) : NumericExpr → Nat
  | .natConst value => value
  | .symbol name => env name
  | .add lhs rhs => evalNumeric env lhs + evalNumeric env rhs
  | .sub lhs rhs => evalNumeric env lhs - evalNumeric env rhs
  | .mul lhs rhs => evalNumeric env lhs * evalNumeric env rhs
  | .divCeil lhs rhs =>
      let denom := evalNumeric env rhs
      if _h : denom = 0 then
        0
      else
        Nat.div (evalNumeric env lhs + (denom - 1)) denom
  | .modNat lhs rhs =>
      let denom := evalNumeric env rhs
      if _h : denom = 0 then
        0
      else
        Nat.mod (evalNumeric env lhs) denom

def IsPowerOfTwo (value : Nat) : Prop :=
  ∃ exponent : Nat, value = 2 ^ exponent

def evalBoolean (env : SymbolEnv) : BooleanExpr → Prop
  | .truth => True
  | .eqExpr lhs rhs => evalNumeric env lhs = evalNumeric env rhs
  | .geExpr lhs rhs => evalNumeric env lhs >= evalNumeric env rhs
  | .leExpr lhs rhs => evalNumeric env lhs <= evalNumeric env rhs
  | .isPowerOfTwo value => IsPowerOfTwo (evalNumeric env value)
  | .isMultipleOf value divisor =>
      divisor = 0 ∨ evalNumeric env value % divisor = 0
  | .allOf clauses => ∀ clause ∈ clauses, evalBoolean env clause

def SymbolDomain.Holds (env : SymbolEnv) (domain : SymbolDomain) : Prop :=
  domain.minValue <= env domain.name
    ∧ (match domain.maxValue with
      | some maxValue => env domain.name <= maxValue
      | none => True)
    ∧ (domain.nonZero = false ∨ env domain.name > 0)
    ∧ (domain.powerOfTwo = false ∨ IsPowerOfTwo (env domain.name))
    ∧ (match domain.multipleOf with
      | some factor => factor = 0 ∨ env domain.name % factor = 0
      | none => True)

def Program.EnvWellFormed (program : Program) (env : SymbolEnv) : Prop :=
  ∀ domain ∈ program.symbols, domain.Holds env

@[simp] def Program.regionNames (program : Program) : List String :=
  (program.readRegions.map RegionSlice.name)
    ++ (program.writeRegions.map RegionSlice.name)
    ++ (program.sharedRegions.map RegionSlice.name)

@[simp] def Program.HasRegionNamed (program : Program) (name : String) : Prop :=
  name ∈ program.regionNames

@[simp] def Program.HasLoweringCertificate (program : Program) : Prop :=
  program.lowering.entrypoints ≠ []
    ∧ program.lowering.stepBindings.length = program.stepCount
    ∧ program.lowering.sourcePaths ≠ []

@[simp] def Program.HasExecutableSurface (program : Program) : Prop :=
  program.stepCount > 0 ∧ program.HasLoweringCertificate

@[simp] def Program.HasCertifiedClaim (program : Program) : Prop :=
  program.certifiedClaim = true ∧ program.HasExecutableSurface

end ZkfMetalProofs
