# Changelog

## 2026-04-08 — Private source release tranche

- Added a release-facing documentation index under `docs/releases/` together with a private source release note and a 5,000-word operator experience report.
- Added the Hermes operator blueprint, constitution, bootstrap prompt, and machine-readable operator contract so the agent layer is now documented as a first-class ZirOS operating surface.
- Added the `private_trade_finance_settlement` subsystem to `zkf-lib`, including core decision, settlement binding, disclosure projection, duplicate-registry handoff, exporter, showcase example, and TDD coverage.
- Hardened the trade-finance export surface so renamed business-facing fields now map to dedicated in-circuit commitment surfaces instead of legacy semantic aliases.
- Added trade-finance packaging, Midnight validation, and formal-surface runner scripts for subsystem materialization and proof-side checks.
- Refreshed generated forensics and release staging artifacts to capture the new subsystem and operator-facing release posture.
- Added release-hygiene ignores for local `.hermes/` planning material and `zkf-protocol-proofs/.lake/` build outputs so future commits stay closer to source and evidence rather than host-local scratch state.

## v0.1.0

- Repositioned the repository as ZirOS: a zero-knowledge operating system for
  agent-operated, fail-closed proving workflows.
- Added first-class `zirapp.json` loading to the shared CLI program loader so
  `zkf-cli compile --spec <zirapp.json>` and other program-consuming commands
  no longer require a Rust escape hatch.
- Tightened default backend selection so omitted backend choice now lands on the
  transparent Plonky3 path only for supported transparent fields.
- Improved nonlinear-anchoring audit messages with plain-English remediation
  guidance and dedicated documentation.
- Updated `zkf-cli app init` to scaffold compliant and violation inputs,
  explicit backend selection, and fail-closed smoke tests.
- Standardized the root build/install surface around `zkf-build.sh`,
  `install.sh`, `BUILD.md`, and a release-focused `Makefile`.
- Added root release process documentation in `RELEASE_CHECKLIST.md`.
- Normalized the workspace release metadata to `v0.1.0`.
- Enabled release-profile stripping and LTO to reduce shipped binary size.
- Carried forward the live proving lanes exposed by the current checkout:
  `plonky3`, `halo2`, `halo2-bls12-381`, `arkworks-groth16`, `nova`,
  `hypernova`, and `midnight-compact`.
- Preserved the live frontend surface exposed by the current checkout:
  Noir, Circom, Cairo, Compact, Halo2-Rust, Plonky3-AIR, and zkVM.
- Preserved Apple Silicon acceleration surfaces, including the Metal-backed
  proving path and prewarmed pipeline inventory already present in the tree.
