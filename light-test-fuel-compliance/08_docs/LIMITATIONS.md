# Limitations

## Circuit Limitations

- **Fixed step count**: The circuit is hardcoded for exactly 4 maneuver steps. A production version would parameterize this.
- **16-bit range**: Fuel values are constrained to 0–65535. Real missions would need larger ranges.
- **Simple commitment**: Uses `value * (value + reserve + 1)` instead of a cryptographic hash like Poseidon. This is sufficient for binding but not hiding against brute-force if the value space is small. A production system should use Poseidon commitments on BN254.
- **No timestamp or mission ID**: The proof doesn't bind to a specific mission context.

## Platform Limitations

- **Wasmer linker issue**: On this Linux environment, the `wasmer` dependency (pulled by `bn254_blackbox_solver`) causes `__rust_probestack` undefined symbol errors when linking binaries that depend on `zkf-lib` with full features. This forced the app to use `zkf-core` + `zkf-backends` directly (without the `full` feature) rather than the higher-level `ProgramBuilder` API from `zkf-lib`.
- **No ProgramBuilder**: Due to the above, the circuit was constructed using raw ZIR types instead of the ergonomic `ProgramBuilder`. This required manual nonlinear anchoring that ProgramBuilder handles automatically.

## Backend Limitations

- **Plonky3 only**: Tested with Plonky3/Goldilocks. Groth16 (BN254) would produce smaller proofs (~128 bytes vs ~3KB) but requires the dev-deterministic setup override which is in `zkf-backends` full feature.
- **No Solidity export**: Plonky3 proofs cannot be exported as Solidity verifiers (only Groth16 supports this).

## Security Notes

- This is a development/test application, not production-grade
- The transparent setup (Plonky3) means no trusted ceremony is needed
- The commitment scheme binds but does not provide hiding in the cryptographic sense against offline search
