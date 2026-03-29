# ZKF Patch Metadata

- Upstream crate: `ark-relations`
- Upstream version family: `0.5.x`
- Patch role: local R1CS relation compatibility for ZKF backends
- Risk class: proving-system critical

## Local ZKF delta notes

- `ConstraintSystem::which_is_unsatisfied()` now returns `AssignmentMissing` when
  called in `SynthesisMode::Prove { construct_matrices: false }`.
- Rationale: ZKF's cached Groth16 prove-shape path intentionally disables matrix
  construction during proving; satisfaction checks in that mode must fail closed
  instead of indexing empty constraint-vector storage and panicking.

Keep this vendor fork in sync with upstream on a quarterly cadence and after any Arkworks security release.
