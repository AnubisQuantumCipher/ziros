# Reentry Schema Freeze

This document is the explicit schema-freeze gate for the theorem-first reentry
mission-assurance tranche.

The following serialized contracts are frozen at their current version and JSON
shape:

- `ReentryMissionPackV2`
- `SignedReentryMissionPackV1`
- `ReentrySignerManifestV1`
- `ReentryAssuranceReceiptV2`
- `SourceModelManifestV1`
- `DerivedModelPackageV1`
- `ScenarioLibraryManifestV1`
- `AssuranceTraceMatrixV1`

## Freeze Rules

For these schemas, the following are release-blocking changes unless they land
with an intentional version bump and synchronized bundle, CLI, dashboard,
handoff, and documentation updates:

- adding, removing, renaming, or retyping a field
- changing whether a field is omitted or always emitted
- changing the meaning of a field without changing its version
- silently widening the accepted JSON input shape

## Enforcement

The freeze is enforced in three places:

1. `serde(deny_unknown_fields)` on the frozen schema structs and their bounded
   nested rows, so unexpected drift is rejected at deserialize time.
2. Exact JSON-shape regression tests in:
   - `zkf-lib/src/app/reentry.rs`
   - `zkf-lib/src/app/reentry_ops.rs`
3. Versioned release docs and bundle/export logic that must continue to name the
   same schema versions explicitly.

## Boundary

This freeze does not widen the mathematical claim. It stabilizes the product
contract around the current accepted proof lane:

- `Plonky3`
- transparent proof semantics
- fixed-policy CPU-first theorem lane
- theorem-first reduced-order RK4 reentry certificate
- NASA Class D ground-support mission-ops assurance boundary

Any future schema evolution must be treated as a versioned public-interface
change, not as ordinary refactoring.
