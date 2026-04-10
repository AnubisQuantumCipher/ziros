# ZirOS Rust Verification Decision Tree And Evidence Rules

## Decision Tree

1. Is the claim about protocol cryptography rather than a Rust implementation
   boundary?
   - Yes: route out of this doctrine.
   - No: continue.

2. Is the target unsafe, FFI-facing, raw-pointer-heavy, aliasing-sensitive, or
   layout-sensitive?
   - Yes:
     - primary lane: RefinedRust
     - optional secondary lane: Verus if a pure model or shell contract exists
     - optional support: Kani for bounded regressions
   - No: continue.

3. Is the target safe proof-core logic, arithmetic, deterministic scheduling
   logic, or a pure state-machine boundary?
   - Yes:
     - primary lane: Verus
     - optional support: Thrust or Kani
   - No: continue.

4. Is the user mainly asking for cheap safe-Rust screening or invariant
   discovery?
   - Yes: Thrust
   - No: continue.

5. Is the user mainly asking for bounded bug-finding or counterexamples?
   - Yes: Kani
   - No: continue.

6. Is the request really about Flux, Creusot, or Prusti?
   - Yes: comparison only

## Evidence Checklists

### RefinedRust

- boundary cut into a small capsule
- admitted surface under `formal/refinedrust/<surface>/`
- generated translation from `cargo refinedrust`
- passing `dune build`
- `STATUS.md` naming scope, exclusions, theorem ids, and logs
- no hidden unsupported-feature dependency inside the claim

### Verus

- theorem file in the shipped proof surface
- reproducible runner command
- exact theorem name
- explicit preconditions
- explicit boundary statement for what remains outside the theorem

### Kani

- harness name and path
- bounds or nondeterministic domain restrictions
- command line used
- pass or fail output captured
- explicit statement that evidence is bounded and non-counted

### Thrust

- target name
- solver configuration
- trusted-function inventory
- machine-readable output JSON
- explicit statement that evidence is non-counted

### Flux / Creusot / Prusti

- comparison memo only
- upstream version or commit
- exercised subset
- exact conclusion
- explicit statement that no truth-surface claim changed

## Red Flags

- unsafe code with no identified RefinedRust capsule
- large feature-rich module offered as a RefinedRust target
- Kani or Thrust presented as ledger-counted evidence
- Flux, Creusot, or Prusti presented as admitted ZirOS lanes
- missing `dune build` after RefinedRust translation
- undocumented trusted functions or solver assumptions
- protocol-soundness claims being mixed into implementation-lane reporting
