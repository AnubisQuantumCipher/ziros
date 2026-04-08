# Private Claims Truth And Settlement Subsystem Flagship

This is a task-scoped ZirOS release for the `private_claims_truth_and_settlement_subsystem` flagship bundle. It is not a full workspace semver cutover; the repository remains source-visible and its broader version/changelog surfaces were already out of sync before this tranche.

## Included

- Strict flagship showcase bundle with `profile=flagship`, `lane_classification=primary-strict`, `primary_backend=hypernova`, and `effective_core_backend=hypernova`.
- Packaged subsystem bundle with passing completeness verification.
- Midnight package validation covering 6 contracts and 10 prepared call flows.
- Claims-specific HyperNova/PastaFq support closure and runtime proof-encode sizing fixes required to make the flagship lane execute honestly.

## Verified Outputs

- Showcase summary: `dist/showcases/private_claims_truth_and_settlement/private_claims_truth.summary.json`
- Telemetry: `dist/showcases/private_claims_truth_and_settlement/telemetry/private_claims_truth.telemetry_report.json`
- Midnight validation: `dist/showcases/private_claims_truth_and_settlement/midnight_validation/summary.json`
- Subsystem manifest: `dist/subsystems/private_claims_truth_and_settlement/02_manifest/subsystem_manifest.json`
- Completeness report: `dist/subsystems/private_claims_truth_and_settlement/17_report/verify-completeness.json`

## Runtime Truth

- Backend selected: `hypernova`
- Metal available: `false`
- Actual GPU stage coverage: `0`
- Actual CPU stage coverage: `4`
- Actual fallback count: `0`

## Midnight Validation Truth

- Network: `preprod`
- Contract count: `6`
- Call count: `10`
- Gateway `/ready` endpoint: reachable but auth-gated (`401`)
- Validation used local compile/deploy-prepare/call-prepare outputs and recorded auth-gated admission responses as evidence instead of treating them as package failures.

## Assets

- `private_claims_truth_and_settlement_showcase_flagship_20260408.tar.gz`
- `private_claims_truth_and_settlement_subsystem_flagship_20260408.tar.gz`
- `sha256.txt`

## Honesty Boundary

- This release proves the flagship claims subsystem bundle and its emitted evidence artifacts from the current checkout.
- It does not claim that the entire ZirOS workspace has completed the repository-wide `RELEASE_CHECKLIST.md` gates for a new semver-wide release.
