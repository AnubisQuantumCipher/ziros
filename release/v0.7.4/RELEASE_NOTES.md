# ZirOS v0.7.4

`v0.7.4` is a repo-wide release cut that folds the flagship
`private_claims_truth_and_settlement_subsystem` into the main ZirOS release
line while updating the public installer surfaces to resolve against this
repository's GitHub releases.

## Included in this release

- Flagship `private_claims_truth_and_settlement_subsystem` artifacts for
  property and casualty claims truth, selective-disclosure settlement, and
  Midnight-facing settlement validation.
- Strict HyperNova/Pasta proof-lane closure for the flagship claims subsystem,
  with truthful telemetry and subsystem completeness evidence.
- Runtime and backend fixes required to support the claims flagship lane,
  including corrected HyperNova/Nova field truth surfaces and larger proof
  encode buffers for large flagship artifacts.
- Updated support, product, provenance, and operator readiness truth surfaces
  for `v0.7.4`.
- Repo-native npm installer defaults and installer manifest URLs that target the
  `AnubisQuantumCipher/ziros` release line.

## Attached assets

- `ziros-darwin-arm64-v0.7.4.tar.gz`
- `installer-manifest.json`
- `ziros-agent-0.7.4.tgz`
- `private_claims_truth_and_settlement_showcase_flagship_20260408.tar.gz`
- `private_claims_truth_and_settlement_subsystem_flagship_20260408.tar.gz`
- `sha256.txt`

## Honesty boundary

- The flagship claims subsystem is validated on the current host with
  `backend_selected = hypernova`.
- The recorded host telemetry for the flagship claims run is CPU-only on this
  machine; the release does not claim Metal or GPU execution where telemetry did
  not prove it.
- Midnight-facing validation in this release is compile/prepare-grade evidence,
  not a claim of live deploy on-chain finality.
- The task-scoped claims release
  `private-claims-truth-flagship-20260408` remains published separately and is
  preserved as its own artifact tranche.
