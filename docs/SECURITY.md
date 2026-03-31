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

## Reentry Mission-Ops Boundary

- The reentry mission-ops flagship targets `NASA Class D ground-support
  mission-ops assurance`.
- Any mission that wants to use ZirOS outputs inside a `Class C` or higher
  decision chain must perform an independent assessment outside ZirOS.
- The mission-ops ingestion layer pins normalized exports, schema names,
  frames, time systems, unit conventions, and derived-package digests. It does
  not claim to replace GMAT, SPICE, Dymos/OpenMDAO, Trick, cFS, or F Prime.
- The accepted reentry release path is gated by deterministic oracle parity on
  exported public metrics before verify/report/export are accepted.
- Bundle, annex, dashboard, and downstream handoff artifacts carry a
  machine-visible artifact class and public-export eligibility boundary so the
  release-safe export can fail closed on private or non-exportable surfaces.
- The shared mission-ops/aerospace-kit layer now centralizes that artifact
  class matrix, export filtering, export scrubbing, boundary rendering, and
  deterministic-oracle release gating under `zkf-lib/src/app/mission_ops.rs`.
- Dashboard, annex, and downstream handoff artifacts are governed operational
  evidence. They are not new proof-bearing claims beyond the accepted reentry
  theorem lane.
- The staged public `AnubisQuantumCipher/ziros` mirror is open core only in its
  first cut. Private or BSL-only crates stay outside that mirror until they can
  be published honestly under the correct boundary and license posture.

## Source Of Truth

When prose and generated evidence disagree, trust the live truth surfaces:

- `zkf-ir-spec/verification-ledger.json`
- `.zkf-completion-status.json`
- `docs/CANONICAL_TRUTH.md`
- `support-matrix.json`

<!-- BEGIN GENERATED VERIFICATION STATUS -->
This block is generated from `zkf-ir-spec/verification-ledger.json`.

- Total ledger entries: 165.
- Machine-checked rows: 165 total (165 `mechanized_local`, 0 `mechanized_generated`).
- Remaining bounded/external/pending rows: 0 `bounded_checked`, 0 `assumed_external`, 0 `pending`.
- Assurance classes: 137 `mechanized_implementation_claim`, 0 `bounded_check`, 3 `attestation_backed_lane`, 16 `model_only_claim`, 9 `hypothesis_carried_theorem`.
- Whole-runtime target inventory: 89 files / 1788 functions, with 89 files / 1788 functions at a completion state.
- Swarm proof-boundary closure: `true` (`zkf-runtime-swarm-path` = 13/13 files complete, `zkf-distributed-swarm-path` = 37/37 files complete).
- Rows with non-empty `trusted_assumptions`: 0.
- All protocol rows are `mechanized_local`.
<!-- END GENERATED VERIFICATION STATUS -->
