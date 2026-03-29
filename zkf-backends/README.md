# zkf-backends

`zkf-backends` owns backend-specific compile, prove, and verify implementations
for the proof systems exposed by ZirOS. This crate turns canonical IR into
backend artifacts, prover executions, verifier checks, and wrapper/export
lanes.

## Public API Surface

- Library crate: `zkf_backends`
- Main backend ids: `arkworks-groth16`, `plonky3`, `halo2`,
  `halo2-bls12-381`, `nova`, `hypernova`, `midnight-compact`
- Key abstractions: backend selection, capability matrix, compile/prove/verify
  implementations, wrapping helpers
- Binary target: `zkf-recursive-groth16-worker`
