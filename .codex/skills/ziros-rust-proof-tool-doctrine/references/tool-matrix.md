# ZirOS Rust Verification Tool Matrix

Use this matrix after reading the permanent doctrine.

| Tool | Method | Best Fit | Unsafe / Layout Coverage | ZirOS Status | Can Count? | Typical Evidence | Main Red Flag |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RefinedRust | Foundational Rust verification with generated Rocq/Radium proofs | Small unsafe capsules, FFI boundaries, pointer-heavy helpers, layout-sensitive memory logic | Strongest fit of this set for unsafe and layout-sensitive Rust, but only when the surface is narrow enough | Core development lane; admitted counted lane for eligible surfaces | Yes, but only after `cargo refinedrust` and `dune build` both pass on an admitted surface | `formal/refinedrust/<surface>/`, `STATUS.md`, generated output, passing Rocq build | Trying to prove a large mixed-feature module instead of extracting a capsule |
| Verus | SMT-backed deductive verification for executable Rust with specs and proofs | Safe proof-core logic, arithmetic, state machines, fail-closed policy rules, shell contracts | Not the first choice when raw memory and aliasing are the hard part | Default counted theorem lane for safe Rust proof cores | Yes | crate-local proof file, runner command, theorem id, honest notes | Using it where the real risk is hidden unsafe or layout reasoning outside the proof boundary |
| Kani | Bounded model checking / counterexample search | Bug-finding, panic or overflow search, concrete failing executions, narrow regressions | Useful for bounded exploration around unsafe code, but not a foundational proof lane | Support lane only | No | harness path, bounds, command output, bounded-scope note | Treating a bounded harness as an unbounded theorem |
| Thrust | Safe-Rust refinement checking with CHC solving | Cheap screening of safe proof-core modules, invariant discovery, regression triage | Safe-Rust-focused; not the right lane for unsafe memory capsules | Non-counted support lane | No | target name, solver args, trusted-function inventory, machine-readable JSON | Using it to replace counted Verus or Rocq rows |
| Flux | Refinement-type-oriented Rust verification | Comparison point for refinement-type ergonomics on safe Rust | Comparison only in current ZirOS doctrine | Reference-only | No | comparison memo with version and exercised subset | Treating ergonomic comparison as an admitted proof lane |
| Creusot | Deductive verification for Rust via Why3 | Comparison point for contract and proof workflow tradeoffs | Comparison only in current ZirOS doctrine | Reference-only | No | comparison memo with version and exercised subset | Promoting a one-off experiment into truth surfaces |
| Prusti | Contract-style Rust verification with Viper backend | Comparison point for contract-heavy safe Rust verification | Comparison only in current ZirOS doctrine | Reference-only | No | comparison memo with version and exercised subset | Assuming "verified by Prusti" means admitted ZirOS assurance |

## Derived Rules

- If the surface is unsafe or layout-sensitive, start by asking where the
  RefinedRust capsule should begin and end.
- If the surface is already pure and safe, ask whether the theorem belongs in
  Verus.
- If the main need is quick confidence rather than a counted theorem, add Kani
  or Thrust as support instead of stretching the primary proof lane.
- If someone proposes Flux, Creusot, or Prusti, answer the comparison question
  honestly and stop there unless the repo doctrine changes.
