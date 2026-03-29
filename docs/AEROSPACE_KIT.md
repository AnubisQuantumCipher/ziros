# ZirOS Aerospace Kit

The current theorem-first reentry flagship is now the reference contract for
the reusable aerospace kit inside ZirOS.

## Scope

This kit is not a new proof claim. It is the shared mission-ops plumbing that
lets multiple aerospace apps reuse the same honest product boundaries without
reopening reentry design decisions every time.

The shared reusable layer lives in:

- `zkf-lib/src/app/mission_ops.rs`

The frozen reentry-specific schemas remain in:

- `zkf-lib/src/app/reentry.rs`
- `zkf-lib/src/app/reentry_ops.rs`

## Shared Kit Surface

The shared mission-ops layer now provides:

- machine-visible artifact classification descriptors
- an explicit mission-ops boundary contract payload
- public/private export filtering hooks
- public-export text scrubbing hooks
- deterministic oracle mismatch release gating helpers
- shared boundary-statement rendering helpers for reports and release surfaces

The artifact classes are fixed as:

- `proof_bearing`
- `governed_upstream_evidence`
- `operational_annex`
- `downstream_integration_artifact`
- `human_readable_report_only`

## Reentry As The Reference App

Reentry remains the proving reference app for this kit.

That means the following rules are already exercised there:

- frozen versioned schemas
- deterministic oracle parity as a release blocker
- public/private export split
- governed provenance manifests
- boundary contract consistency
- annex versus proof-bearing separation

## Boundary

The shared aerospace kit does not widen the current product claim.

The explicit product boundary remains:

- ground-side mission assurance
- NASA Class D ground-support mission-ops assurance
- normalized-export-based ingestion
- no native replacement claim for GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime

Any mission that wants to place ZirOS outputs into a NASA Class C or higher
decision chain must perform an independent assessment outside ZirOS.

## Next App Families

The next aerospace apps are defined at the contract level now, but not
implemented in this tranche:

- orbital / n-body mission certificate
- conjunction-risk / multi-satellite assurance
- powered-descent / descent-corridor assurance

They should reuse the shared mission-ops layer instead of cloning reentry logic
again.
