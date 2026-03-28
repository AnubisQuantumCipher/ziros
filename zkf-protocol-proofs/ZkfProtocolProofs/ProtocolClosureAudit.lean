import Lean

namespace ZkfProtocolProofs
namespace ProtocolClosureAudit

open Lean
open Lean Elab Command

structure AuditState where
  visited : NameSet := {}
  deps : NameSet := {}

abbrev AuditM := ReaderT Environment <| StateM AuditState

mutual

private partial def collectExprDeps (e : Expr) : AuditM Unit := do
  for declName in e.getUsedConstants do
    collectConstDeps declName

private partial def collectConstDeps (declName : Name) : AuditM Unit := do
  let state ← get
  unless state.visited.contains declName do
    modify fun state => {
      state with
        visited := state.visited.insert declName
        deps := state.deps.insert declName
    }
    let env ← read
    match env.find? declName with
    | none => pure ()
    | some constInfo =>
        collectExprDeps constInfo.type
        if let some value := constInfo.value? (allowOpaque := true) then
          collectExprDeps value
        match constInfo with
        | .inductInfo info =>
            for ctorName in info.ctors do
              collectConstDeps ctorName
        | _ => pure ()

end

def dependencyClosure (env : Environment) (declName : Name) : NameSet :=
  let (_, state) := ((collectConstDeps declName).run env).run {}
  state.deps

def blockedAbstractDependencies : List Name := [
  `ZkfProtocolProofs.Groth16TypeIIIModel,
  `ZkfProtocolProofs.Groth16TypeIIIModel.relation,
  `ZkfProtocolProofs.Groth16TypeIIIModel.verify,
  `ZkfProtocolProofs.Groth16TypeIIIModel.extract,
  `ZkfProtocolProofs.Groth16TypeIIIModel.sound,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel.relation,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel.prove,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel.simulate,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel.proofView,
  `ZkfProtocolProofs.Groth16TypeIIIZeroKnowledgeModel.publicView_simulation,
  `ZkfProtocolProofs.FriProximityModel,
  `ZkfProtocolProofs.FriProximityModel.relation,
  `ZkfProtocolProofs.FriProximityModel.verify,
  `ZkfProtocolProofs.FriProximityModel.extract,
  `ZkfProtocolProofs.FriProximityModel.sound,
  `ZkfProtocolProofs.NovaFoldingModel,
  `ZkfProtocolProofs.NovaFoldingModel.relation,
  `ZkfProtocolProofs.NovaFoldingModel.verify,
  `ZkfProtocolProofs.NovaFoldingModel.extract,
  `ZkfProtocolProofs.NovaFoldingModel.sound,
  `ZkfProtocolProofs.HyperNovaCcsModel,
  `ZkfProtocolProofs.HyperNovaCcsModel.relation,
  `ZkfProtocolProofs.HyperNovaCcsModel.verify,
  `ZkfProtocolProofs.HyperNovaCcsModel.extract,
  `ZkfProtocolProofs.HyperNovaCcsModel.sound
]

private def formatNames (names : List Name) : String :=
  String.intercalate ", " <| names.map toString

private def auditClosureTheorem (declName : Name) (requiredDecls : List Name) :
    CommandElabM Unit := do
  let env ← getEnv
  let some constInfo := env.find? declName
    | throwError "protocol closure audit could not find declaration `{declName}`"
  if !(match constInfo with
      | .thmInfo _ => true
      | _ => false) then
    throwError "protocol closure audit expected `{declName}` to be a theorem"

  let deps := dependencyClosure env declName
  let blockedHits :=
    blockedAbstractDependencies.filter deps.contains
  unless blockedHits.isEmpty do
    throwError
      m!"protocol closure theorem `{declName}` depends on blocked abstract protocol constants: {formatNames blockedHits}"

  let missingRequired :=
    requiredDecls.filter fun requiredDecl => !deps.contains requiredDecl
  unless missingRequired.isEmpty do
    throwError
      m!"protocol closure theorem `{declName}` is missing required concrete shipped-surface dependencies: {formatNames missingRequired}"

  logInfo m!"protocol closure theorem shape ok: {declName}"

syntax (name := protocolClosureAuditCmd)
  "#protocol_closure_audit " ident (" requires " "[" ident,* "]")? : command

elab_rules : command
  | `(#protocol_closure_audit $decl:ident requires [$requiredDecls:ident,*]) => do
      auditClosureTheorem decl.getId (requiredDecls.getElems.toList.map TSyntax.getId)
  | `(#protocol_closure_audit $decl:ident) => do
      auditClosureTheorem decl.getId []

end ProtocolClosureAudit
end ZkfProtocolProofs
