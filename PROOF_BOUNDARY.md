# ZKF Proof Boundary

This document is the literal freeze record for the proving-core boundary and the
swarm defense envelope.

## Freeze Record

- Phase C freeze completed for the current workspace state.
- Freeze baseline commit: `787ca08fe84e54e7639838e41c4f30b37bbee233`
- Authoritative proof-claim source: `zkf-ir-spec/verification-ledger.json`
- Core-path pending claims remaining: `0`
- Swarm-path pending claims remaining: `0`

<!-- BEGIN GENERATED VERIFICATION STATUS -->
This block is generated from `zkf-ir-spec/verification-ledger.json`.

- Total ledger entries: 168.
- Machine-checked rows: 168 total (168 `mechanized_local`, 0 `mechanized_generated`).
- Remaining bounded/external/pending rows: 0 `bounded_checked`, 0 `assumed_external`, 0 `pending`.
- Assurance classes: 140 `mechanized_implementation_claim`, 0 `bounded_check`, 3 `attestation_backed_lane`, 16 `model_only_claim`, 9 `hypothesis_carried_theorem`.
- Whole-runtime target inventory: 89 files / 1788 functions, with 89 files / 1788 functions at a completion state.
- Swarm proof-boundary closure: `true` (`zkf-runtime-swarm-path` = 13/13 files complete, `zkf-distributed-swarm-path` = 37/37 files complete).
- Release-grade ready: `true`.
- Release-grade blockers: none.
<!-- END GENERATED VERIFICATION STATUS -->

When prose and the ledger disagree, the ledger wins.

## Verified GPU Lane

The shipped verified GPU lane is now claimed as a split surface:

- structural family-model rows for the shipped hash, Poseidon2, NTT, and MSM inventories, bindings, layouts, and attested source sets
- mechanized launch, layout, provenance, and fail-closed runtime boundaries
- one counted arithmetic subtranche: `gpu.ntt_bn254_butterfly_arithmetic_sound` for the admitted `ntt_butterfly_bn254` kernel, assuming the pinned Apple Metal compiler, driver/runtime, and GPU hardware execute the attested metallib and pipeline state correctly

That claim is intentionally narrower than "zero-trust Metal." The verified lane is a pinned subset:

- BN254 classic MSM
- Goldilocks and BN254 NTT
- Goldilocks Poseidon batch
- SHA-256 batch

GPU-capable stages outside that subset must route to CPU or an explicit non-verified GPU lane. Verified mode must fail closed on unavailable devices, runtime compilation, reflection drift, pipeline-descriptor drift, entrypoint drift, or metallib digest drift.

## Freeze Protocol

The freeze protocol for this workspace is:

1. Run `./scripts/run_rocq_proofs.sh`.
2. Run `python3 ./scripts/proof_audit.py`.
3. Require `jq '[.entries[] | select(.status=="pending")] | length' zkf-ir-spec/verification-ledger.json`
   to return `0`.

The current workspace is only considered frozen if all three gates pass together.

## Reentry Mission-Ops Product Boundary

The theorem-first reentry flagship now ships a governed mission-ops wrapper
layer around the accepted proof lane. That wrapper adds:

- normalized-export source-model manifests for upstream tools such as GMAT,
  SPICE, OpenMDAO/Dymos, and Trick-style environments
- derived-model packages with approved operating domains and residual/error
  metadata
- scenario-library qualification and assurance trace matrices
- deterministic oracle parity artifacts (`oracle_summary.json` and
  `oracle_comparison.json`) that must match the theorem-lane public metrics
  before verify/report/export are accepted
- machine-visible artifact classification across the bundle, annex, dashboard,
  and downstream handoff surfaces (`proof_bearing`,
  `governed_upstream_evidence`, `operational_annex`,
  `downstream_integration_artifact`, `human_readable_report_only`)
- annex publication, Open MCT dashboard bundles, and downstream cFS / F Prime
  handoff manifests

This is product and evidence plumbing around the accepted reentry theorem lane.
It is not a new counted proof claim and it does not widen the mechanized
surface beyond the theorem rows already recorded in
`zkf-ir-spec/verification-ledger.json`.

The explicit process target for that product surface is `NASA Class D
ground-support mission-ops assurance`. Any mission that wants to place ZirOS
outputs into a `Class C` or higher decision chain must perform an independent
program assessment outside ZirOS.

The reusable mission-ops/aerospace-kit layer now lives in
`zkf-lib/src/app/mission_ops.rs`. It standardizes the artifact-class matrix,
public/private export filtering hooks, public-export scrubbing hooks, shared
boundary rendering, and deterministic-oracle release-gate helper used by the
reentry flagship. This remains product plumbing around the accepted theorem
lane, not a new counted proof row.

The staged public-safe `AnubisQuantumCipher/ziros` mirror is also part of this
tranche, but only as an open-core packaging surface. It does not widen the
proof claim. It exists to publish the theorem-first reentry/aerospace slice
without dragging BSL/private crates or non-open-core runtime lanes into the
first public cut.

## Sealed Core

The mathematically sealed core includes:

- field arithmetic semantics tracked in Rocq and Fiat-Crypto evidence, with the strict BN254 Montgomery lane closed by a dedicated Rocq theorem bundle
- constraint checking and supported witness-generation semantics
- supported IR and ZIR preservation claims
- backend lowering and wrapper claims already promoted in the ledger

The swarm layer is not part of that arithmetic kernel. It is closed separately as
its own mechanized runtime/distributed proof boundary, tracked by
`zkf-runtime-swarm-path` and `zkf-distributed-swarm-path`.

## Swarm Boundary

The swarm defense layer may affect:

- scheduling and device placement
- redundant execution and quorum verification
- peer reputation, quarantine, and admission control
- operational rejection posture under active threat
- sentinel-owned timing probes and cache-flush measurements used only for anomaly detection

The swarm defense layer must never affect:

- witness generation semantics
- constraint checking semantics
- successful proof bytes for the same mathematical run
- verification truth

Sentinel jitter and cache-flush detection are therefore constrained to
Sentinel-owned probe buffers and runtime traces. They must not read, mutate, or
derive decisions from witness bytes or successful proof bytes directly.

The defining non-interference rule is recorded in the ledger as `swarm.non_interference`.

## Closed BlackBox Runtime Gap

The former pending witness/runtime BlackBox gap is now tracked as
`witness.blackbox_runtime_checks = mechanized_local`.

Its evidence is:

- `zkf-backends/proofs/rocq/BlackboxRuntimeProofs.v`

That promoted local proof surface covers:

- `lower_blackbox_program -> enrich_witness_for_proving -> check_constraints`
- SHA-256 bytes-to-digest
- Poseidon BN254 width-4
- ECDSA secp256k1
- ECDSA secp256r1
- malformed ABI rejection
- boolean-result forcing
- low-S enforcement on the extracted ECDSA proof surface
- incorrect witness fail-closed behavior

The randomized backend regressions in `zkf-backends/tests/verification_prop.rs`
remain as backstops over the shipped Rust path, but they are no longer the
primary promoted claim for this surface.

## Trusted Computing Base

The remaining trusted boundary is unchanged:

- the Rust compiler and generated machine code
- Rocq, Kani, and other proof/checking tools
- the operating system and host hardware
- imported Groth16 CRS material for any security-covered Groth16 proving lane; deterministic Groth16 setup is development-only and outside the strict cryptographic boundary
- for the verified Metal lane specifically: the pinned Apple Metal compiler, driver/runtime, and GPU hardware executing the attested metallib and pipeline state correctly
