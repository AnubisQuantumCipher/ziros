# Changelog

## v0.7.4

- Added the `private_claims_truth_and_settlement_subsystem` flagship lane as a
  production-style property and casualty claims adjudication, settlement, and
  selective-disclosure subsystem with strict HyperNova-backed packaging and
  operator evidence bundles.
- Closed the flagship claims release path with packaged subsystem completeness,
  Midnight contract validation outputs, claim decision artifacts, and a
  flagship report that truthfully states the proof boundary, attestation chain,
  and host hardware participation.
- Extended the HyperNova/Nova truth surface to cover the Pasta field path used
  by the claims subsystem and corrected the public capability and support-matrix
  surfaces to match the live proof lane.
- Raised the runtime proof-encode buffer budget so flagship HyperNova runs no
  longer fail when large proof artifacts are emitted through the execution
  adapter.
- Preserved the existing task-scoped claims flagship release artifacts while
  folding their deliverables into the repo-wide `v0.7.4` semver cut.

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
