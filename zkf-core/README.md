# zkf-core

`zkf-core` defines ZirOS’s canonical circuit representation, field types,
witness generation, audit logic, and proof artifact data structures. Most of
the workspace depends on this crate for the core objects that describe,
evaluate, and validate proof programs.

## Public API Surface

- Library crate: `zkf_core`
- Key exports: `Program`, `Expr`, `Constraint`, `Signal`, `FieldElement`,
  `FieldId`, `Witness`, `WitnessInputs`, `CompiledProgram`, `ProofArtifact`
- Core services: witness generation, constraint checking, audits, diagnostics
