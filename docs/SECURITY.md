# ZirOS Security Model

## Threat Model

### ZirOS Protects Against

- Underconstrained circuits that leave private values linearly free.
- Invalid witness values reaching the prover unchecked.
- Tampered proof artifacts failing verification.
- Backend/field mismatches that would silently degrade soundness.
- Unattested or drifted Metal dispatch on the verified GPU lane.
- Operational ambiguity about whether a proving lane is transparent, trusted
  setup, recursive, external, or compatibility-only.

### ZirOS Does Not Protect Against

- Bugs in the trusted computing base below the proof surface:
  Rust, theorem provers, Apple’s Metal compiler/runtime/driver, or hardware.
- Incorrect claims made by external frontends before import.
- Side-channel leakage on an untrusted prover host.
- Production misuse of a development-only trusted setup.
- External proof-server failures or compromise in delegated lanes.

## Trusted Computing Base

The practical TCB for this checkout includes:

- Rust and the Cargo toolchain
- Lean, Rocq/Coq, Verus, Kani, and their proof libraries
- Apple’s Metal compiler/runtime/driver plus Apple GPU hardware on the Metal lane
- Upstream backend libraries that are not fully mechanized in the local ledger

## Fail-Closed Design

ZirOS tries to reject unsafe states earlier than typical proof tooling:

- audit fails before compile,
- witness checks fail before prove,
- verification does not accept witness data,
- verified Metal dispatch rejects drift instead of silently falling back.

## Trusted Setup Honesty

- `plonky3` and `halo2` (IPA/Pasta) are the transparent first-proof lanes.
- `arkworks-groth16` and `halo2-bls12-381` require trusted setup.
- `ZKF_ALLOW_DEV_DETERMINISTIC_GROTH16=1` is development-only. It exists so
  local testing can exercise Groth16 flows without a ceremony artifact. It is
  not a production trust story and must not be described as one.

## Swarm And Neural Engine Boundaries

- Swarm may change scheduling, retries, peer selection, or rejection posture.
  It must not change proof semantics.
- Neural Engine models may influence routing and scheduling. They do not define
  proof validity.

## Source Of Truth

When prose and generated evidence disagree, trust the live truth surfaces:

- `zkf-ir-spec/verification-ledger.json`
- `.zkf-completion-status.json`
- `docs/CANONICAL_TRUTH.md`
- `support-matrix.json`
