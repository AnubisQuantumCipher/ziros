# Light Test Developer Experience Report

## 1. What the Application Does

The Private Satellite Fuel Budget Compliance Verifier proves that a satellite's remaining fuel after a 4-step maneuver sequence stays above a required safety reserve threshold — without revealing any of the private fuel data. It generates a real Plonky3 STARK proof and verifies it, exercises private inputs, arithmetic constraints, multi-step state updates, a safety compliance condition, and artifact generation.

## 2. Whether ZirOS Handled It Cleanly

**Mostly yes, with one significant friction point.**

The core proof pipeline worked exactly as documented:
- Circuit construction via ZIR types → IR-v2 lowering was correct
- Witness generation from private inputs resolved all signals automatically
- Constraint checking caught non-compliant inputs with clear error messages
- Plonky3 compile → prove → verify completed in 22ms total
- Proof size was 3,054 bytes
- Verification returned `true` for valid inputs

The ZirOS framework correctly:
- Inferred intermediate signal values from witness assignments
- Enforced range constraints (16-bit) to prove non-negativity
- Rejected non-compliant inputs with a clear range violation error on the safety slack signal
- Generated a real, verifiable proof artifact

## 3. Whether ProgramBuilder Was Enough

**ProgramBuilder was not usable due to a platform-level linking issue.**

`ProgramBuilder` lives in `zkf-lib`, which unconditionally depends on `zkf-backends` with `features = ["full"]`, which pulls in `bn254_blackbox_solver` → `wasmer`. On this Linux environment, wasmer fails to link with `undefined symbol: __rust_probestack`. This affects ALL binaries (examples and tests) that depend on `zkf-lib`.

As a workaround, the circuit was constructed using raw `zkf_core::zir` types and lowered via `program_zir_to_v2()`. The `zkf-backends` crate was used with `default-features = false` to avoid wasmer, and the Plonky3 backend (which doesn't need wasmer) worked fine.

**If ProgramBuilder had been usable**, the circuit construction would have been significantly more ergonomic — particularly:
- `builder.bind()` combines assignment + constraint in one call
- `builder.constrain_geq()` creates slack variables automatically
- `builder.constrain_range()` handles nonlinear anchoring automatically
- No need to manually construct `zir::Signal`, `zir::Constraint`, and `zir::WitnessAssignment` structs

The raw ZIR approach required ~80 more lines of boilerplate and explicit nonlinear anchoring (`signal * __anchor_one == signal`) that ProgramBuilder handles internally.

## 4. What Friction Appeared

1. **Wasmer linker failure** (`__rust_probestack` undefined): This was the primary blocker. It prevented using `zkf-lib` as an example binary. The workaround (standalone crate with `zkf-backends` default-features=false) was effective but required understanding the dependency tree.

2. **Nonlinear anchoring requirement**: The fail-closed audit system correctly flagged signals that lacked nonlinear constraints. This is a security feature, but when constructing circuits manually (without ProgramBuilder), it requires explicit knowledge that every private signal must participate in at least one multiplication. The error messages were clear and suggested fixes.

3. **ZIR signal deduplication**: When constructing signals manually, adding `compliance_status` both as a `public_output()` and later with `SignalType::Bool` caused duplication. Required manual dedup.

## 5. What Had to Be Improved

No changes were made to the ZirOS framework itself. The app was built entirely using existing APIs:

- `zkf_core::zir` types for circuit construction
- `zkf_core::program_zir_to_v2()` for lowering
- `zkf_core::generate_witness()` for witness generation
- `zkf_core::check_constraints()` for validation
- `zkf_backends::backend_for(BackendKind::Plonky3)` for compile/prove/verify

The only adaptation was architectural: using `zkf-core` + `zkf-backends` (no full features) instead of `zkf-lib` to avoid the wasmer linking issue.

## 6. Whether Proof Generation and Verification Felt Stable

**Yes, completely stable.**

- Proof generation succeeded on the first try after constraints were satisfied
- Verification returned `true` deterministically
- The non-compliant scenario was correctly rejected at the witness/constraint level before even reaching proof generation
- Plonky3 backend required no configuration, no ceremony, no seed — just `backend.compile()`, `backend.prove()`, `backend.verify()`
- Timing was consistent: ~17ms prove, ~5ms verify
- The proof artifact serialized cleanly to JSON

## 7. Whether This Lightweight Test Gives Confidence for Larger Apps

**Yes, with caveats.**

**Confidence gained:**
- The core proof pipeline (circuit → witness → prove → verify) is solid
- The constraint system correctly enforces arithmetic and range properties
- The audit system (nonlinear anchoring) catches real security issues
- The Plonky3 backend works out of the box for transparent proofs
- Error messages are clear and actionable
- The framework handles multi-step stateful computations cleanly

**Caveats:**
- The wasmer linking issue on Linux is a real blocker for using `ProgramBuilder` in standalone binaries. This would need to be fixed for production use (either make wasmer optional, or fix the probestack issue).
- Without ProgramBuilder, circuit construction is verbose. The framework's value proposition depends on having access to the high-level builder API.
- Only Plonky3 was tested. Groth16 (which produces much smaller proofs and supports Solidity verifiers) was not testable due to the same linking issue.

**Overall assessment:** ZirOS is a capable proof framework with a well-designed layered architecture. The core primitives are correct, the audit system is valuable, and the proof backends work. The main gap is the platform-level linking issue that blocks the high-level API on this environment.
