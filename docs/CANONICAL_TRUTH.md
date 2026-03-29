# Canonical Truth Sources

This repository contains a mix of live operational docs, generated machine-readable metadata, and
historical design/assessment documents. When these disagree, use the sources below in priority
order.

## Live Product Truth

1. `zkf capabilities --json`
   This is the canonical public source for backend readiness, supported fields, operator actions,
   and explicit compatibility aliases on the current binary and host.
2. `zkf audit --backend ... --json`
   This is the canonical per-program compatibility and constraint-truth surface.
3. Package/runtime/proof metadata
   Trust semantics must come from emitted metadata keys such as `trust_model`,
   `algebraic_binding`, `in_circuit_verification`, `proof_semantics`, and
   `aggregation_semantics`.
4. [`support-matrix.json`](../support-matrix.json)
   Machine-readable repo truth for backends, frontends, gadgets, and roadmap completion.

## Program Family Truth

- `zir-v1` is the canonical lossless interchange family.
- `ir-v2` is the lowered backend-consumption dialect.
- `zkf import --ir-family auto` preserves `zir-v1` whenever the frontend exposes semantics that
  lowered `ir-v2` cannot represent exactly.
- When a caller forces `ir-v2`, lowering must be explicit and any adapted semantics must be
  surfaced through lowering metadata rather than silently flattened.

## Trust Model Truth

- Attestation or metadata-only surfaces must never be presented as recursive SNARKs or
  algebraically binding recursion.
- The deprecated `RecursiveAggregator` alias is attestation-only.
- `Halo2IpaAccumulator` is the current cryptographic/algebraic-binding aggregation surface.
- `CryptographicGroth16Aggregator` is implemented but fail-closed and remains roadmap-only until
  the in-circuit BN254 final exponentiation and Frobenius constraints are complete, soundness
  validated, and the truth surfaces are updated again.
- Public/release-safe flows are strict cryptographic unless the caller explicitly opts into an
  attestation trust lane.

Additional trust semantics guidance lives in
`WRAPPING_SECURITY.md`.

## Scientific Certificate Truth

- Scientific app templates in `zkf-lib` are discrete certificate lanes only.
- `thermochemical-equilibrium` proves gas-phase `T,P` balance/KKT closure for the attested witness
  surface; it does not prove unrestricted equilibrium theory.
- `real-gas-state` proves the shipped cubic EOS residual and admissible root checks for attested
  reduced coefficients; it does not mechanize fugacity logarithms or REFPROP.
- `navier-stokes-structured` proves the shipped structured finite-volume step relation for the
  attested state and flux witnesses; it does not prove global existence/smoothness or turbulence
  closure.
- `combustion-instability-rayleigh` proves the discrete Rayleigh-window integral and coupled
  low-order modal growth relation for the attested trace; it does not prove nonlinear combustor CFD.

## Neural Engine Model Truth

- Repo-local fixture models are deterministic smoke-floor artifacts only.
- Operator-trained production models come from local telemetry and retraining.
- If only fixture bundles are installed, do not describe the model state as production-fresh.
- Neural Engine lanes are advisory for optimization and risk scoring only.
- Deterministic policy is the enforcement boundary for runtime security actions.
- Installed production models in `~/.zkf/models/` are expected to be pinned by bundle manifest and
  hash, or they must be treated as development-only.
- Proof validity, proof arithmetic, and verifier behavior remain independent of all model output.

Operational guidance lives in
`NEURAL_ENGINE_OPERATIONS.md`
and `DEPLOYMENT.md`.

## Historical Documents

Files such as `WHITEPAPER.md`, `ZKF_FINAL_REPORT.md`, and other narrative assessments are useful
context, but they are not authoritative for live readiness, trust semantics, or current gap
status. Treat them as snapshots unless they explicitly defer to the live truth sources above.
