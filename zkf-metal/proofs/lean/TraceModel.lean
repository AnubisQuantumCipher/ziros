import SemanticsAst

namespace ZkfMetalProofs

inductive TraceEvent where
  | step (programId : String) (stepName : String)
  | barrier (programId : String) (scope : String)
  deriving Repr, DecidableEq, Inhabited

structure Trace where
  events : List TraceEvent
  deriving Repr, DecidableEq, Inhabited

def barrierEventsAfter (program : Program) (index : Nat) : List TraceEvent :=
  program.barriers.foldr
    (fun barrier acc =>
      if barrier.afterStep = index then
        TraceEvent.barrier program.programId barrier.scope :: acc
      else
        acc)
    []

def canonicalEventsForSteps (program : Program) : Nat → List KernelStep → List TraceEvent
  | _, [] => []
  | index, step :: remaining =>
      TraceEvent.step program.programId step.name
        :: barrierEventsAfter program index
        ++ canonicalEventsForSteps program (index + 1) remaining

def canonicalTrace (program : Program) : Trace :=
  { events := canonicalEventsForSteps program 0 program.steps }

def Trace.WellFormed (program : Program) (trace : Trace) : Prop :=
  trace.events = (canonicalTrace program).events

theorem canonical_trace_well_formed (program : Program) :
    Trace.WellFormed program (canonicalTrace program) := by
  rfl

end ZkfMetalProofs
