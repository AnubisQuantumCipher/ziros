# Collatz STARK Wrap Status

## Verified Against Current Repo

The report at `/Users/sicarii/Desktop/ZKF_Collatz_STARK_Wrap_Report.md` was partially accurate and partially stale against the current tree.

- Accurate:
  - the Nova-compressed V3 wrapper path exists
  - the failure was in the final Groth16 outer-prove boundary
  - the failure was tied to the vendored `ark-relations` layer
- Inaccurate or too imprecise:
  - the current reproducible failure was not an empty assignment vector in the Groth16 prover core
  - the actual panic occurred earlier, during a debug satisfaction check on a matrix-free proving constraint system

## Actual Root Cause

The failing path was:

1. `wrap_nova_compressed_v3(...)`
2. `create_local_groth16_proof_with_cached_shape(...)`
3. `create_local_groth16_proof_with_shape(...)`
4. debug-only `cs.is_satisfied()` call
5. `ark-relations` `ConstraintSystem::which_is_unsatisfied()`

When cached prove-shapes are present, Groth16 proving intentionally uses:

- `SynthesisMode::Prove { construct_matrices: false }`

That mode keeps assignments, but it does not populate `a_constraints`, `b_constraints`, or `c_constraints`.

The vendored `ark-relations` implementation of `which_is_unsatisfied()` still indexed those vectors by `num_constraints`, which caused:

- `index out of bounds: the len is 0 but the index is 0`

So the failure was real, but it was a matrix-free satisfaction-check bug, not a Groth16 assignment-materialization bug.

## Delivered Fix

Two changes were applied:

1. `vendor/ark-relations-patched/src/r1cs/constraint_system.rs`
   - `which_is_unsatisfied()` now returns `AssignmentMissing` when matrices were intentionally not constructed.
2. `zkf-backends/src/arkworks.rs`
   - the debug Groth16 satisfaction check now only runs when the constraint system actually constructed matrices.

## Regression Coverage

Added in `zkf-backends/src/wrapping/nova_verifier_circuit.rs`:

- `groth16_outer_prove_and_verify_succeeds_for_accumulator_binding`

This regression performs:

1. Groth16 setup on `NovaVerifierCircuit::sizing_instance(...)`
2. Groth16 prove on `NovaVerifierCircuit::new(...)`
3. Groth16 verify against `public_inputs_for_compressed_proof(...)`

This closes the exact outer-prove boundary that the report identified.

## Bounded Verification Coverage

This fix is now recorded as:

- `wrapping.groth16_cached_shape_matrix_free_fail_closed`

Evidence is split across:

1. `zkf-backends/src/verification_kani.rs`
   - `cached_shape_debug_gate_stays_off_without_matrices`
   - `matrix_free_satisfaction_check_is_rejected`
2. `zkf-backends/src/wrapping/nova_verifier_circuit.rs`
   - `groth16_outer_prove_and_verify_succeeds_for_accumulator_binding`

The Kani claim is intentionally bounded to the fail-closed debug/satisfaction boundary for cached-shape Groth16 proving. It does not restate Groth16 cryptographic soundness.

## Remaining Gap

The repo still does not contain a committed end-to-end Collatz artifact fixture reproducing the exact report inputs and timings. The mathematical and wrapper boundary is now covered, but the specific Collatz report remains an external run report rather than a checked-in fixture-driven integration case.
