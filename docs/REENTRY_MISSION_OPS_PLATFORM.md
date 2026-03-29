# ZirOS Reentry Mission-Ops Platform

This document describes the production target for the theorem-first reentry
surface in the current ZirOS tree.

## Classification Boundary

The reentry mission-assurance surface is targeted at:

- `NASA Class D ground-support mission-ops assurance`

This is an honest boundary, not a marketing downgrade. The current product is a
ground-side proof-bearing assurance layer that validates bounded reduced-order
reentry statements, provenance, scenario qualification, and operator evidence.
It is not onboard flight software and it is not a certification-equivalent
replacement for a NASA program's broader assurance process.

Any mission that wants to place ZirOS outputs in a `Class C` or higher
decision chain must perform an independent program assessment outside ZirOS.
That assessment is expected to determine the required process, independence,
inspection, test, and artifact burden for the actual mission context.

## Schema Freeze Gate

Before more CLI, bundle, dashboard, handoff, or release logic is added, the
reentry tranche treats its live serialized contracts as frozen. The freeze
record is tracked in:

- `docs/REENTRY_SCHEMA_FREEZE.md`

Any change to the frozen reentry proof-bearing or governed mission-ops schemas
must land as an intentional versioned interface change, not as incidental field
drift during product work.

## Shared Aerospace Kit

The reentry flagship is now the reference contract for the shared aerospace kit
inside `zkf-lib`.

The generic reusable mission-ops layer lives in:

- `zkf-lib/src/app/mission_ops.rs`

That layer now owns the shared artifact classification contract, public/private
export filtering hooks, public-export scrub hooks, deterministic oracle release
gate helper, and shared boundary-statement rendering used by the reentry
product surfaces.

The reentry-specific schemas remain frozen and continue to live in the reentry
modules. The shared kit is underneath the frozen contract, not a replacement
for it.

## Operator Flow

The mission-ops workflow is:

1. Ingest normalized upstream engineering exports into pinned source manifests.
2. Derive a proof-safe reduced-order model package and mission pack.
3. Qualify the derived package against a scenario library and generate the
   assurance trace matrix.
4. Sign the mission pack with the pinned signer authority.
5. Prove, verify, report, and export the theorem-first bundle.
6. Publish annex-only operational evidence and downstream handoff bundles.

The primary commands are:

```bash
zkf app reentry-assurance ingest-gmat --input normalized_gmat.json --out gmat_manifest.json
zkf app reentry-assurance ingest-spice --input normalized_spice.json --out spice_manifest.json
zkf app reentry-assurance derive-model --request derive_request.json --out derived/
zkf app reentry-assurance qualify-model --package derived/derived_model_package.json --scenario-library scenario_library.json --out qualified/
zkf app reentry-assurance sign-pack --pack derived/mission_pack_v2.json --source-model-manifest gmat_manifest.json --source-model-manifest spice_manifest.json --derived-model-package derived/derived_model_package.json --scenario-library-manifest scenario_library.json --assurance-trace-matrix qualified/assurance_trace_matrix.json --signer-key signer_keys.json --signer-id flight-authority --not-before-unix-epoch-seconds 0 --not-after-unix-epoch-seconds 4000000000 --out signed_pack.json
zkf app reentry-assurance prove --signed-pack signed_pack.json --signer-manifest signer_manifest.json --source-model-manifest gmat_manifest.json --source-model-manifest spice_manifest.json --derived-model-package derived/derived_model_package.json --scenario-library-manifest scenario_library.json --assurance-trace-matrix qualified/assurance_trace_matrix.json --out bundle/
zkf app reentry-assurance verify --bundle bundle/
zkf app reentry-assurance report --bundle bundle/
zkf app reentry-assurance export-bundle --bundle bundle/ --out public_bundle/
zkf app reentry-assurance publish-annex --bundle bundle/ --out annex/ --metal-doctor metal_doctor.json --runtime-policy runtime_policy.json --telemetry telemetry.json --security security.json
zkf app reentry-assurance build-dashboard --bundle bundle/ --annex annex/ --out dashboard/
zkf app reentry-assurance handoff-cfs --bundle bundle/ --out handoff_cfs/
zkf app reentry-assurance handoff-fprime --bundle bundle/ --out handoff_fprime/
```

## Artifact Classification

Every exported reentry mission-ops artifact now carries a machine-visible
classification in the bundle/evidence/annex/handoff metadata:

- `proof_bearing`
- `governed_upstream_evidence`
- `operational_annex`
- `downstream_integration_artifact`
- `human_readable_report_only`

Each descriptor also records:

- `trust_lane`
- `classification_boundary`
- `contains_private_data`
- `public_export_allowed`

The public export path is not allowed to infer this structure from prose. It
filters exportable artifacts from the machine-visible descriptors and rewrites
the exported manifest/report surfaces to match the actual public-safe file set.

## Deterministic Oracle Gate

The accepted theorem lane is release-blocked by a deterministic pure-Rust oracle
lane over the same accepted RK4 profile and the same fixed-point surface.

Every production bundle now includes:

- `oracle_summary.json`
- `oracle_comparison.json`

The proof/report/export surface is only accepted when the theorem lane and the
deterministic oracle agree on the public metrics required by the release gate:

- peak dynamic pressure
- peak heating rate
- compliance bit
- horizon steps

The current policy is exact equality for those exported public metrics. Any
mismatch blocks `verify`, `report`, `export-bundle`, and release publication.

## Upstream Tool Boundary

The ingestion commands are intentionally strict about scope and follow the
shared `normalized-export-based ingestion` contract:

- They ingest **normalized exports** from tools such as GMAT, SPICE, Dymos,
  Trick/JEOD, or Basilisk.
- They pin source files, schema names, coordinate frame, time system, and unit
  conventions.
- They do **not** claim that ZirOS natively replaces those tools.

The proof lane continues to certify the reduced-order bounded statement. The
upstream tools remain the source of engineering truth used to calibrate the
reduced-order package.

## Bundle Boundary

The correctness-bearing bundle is the proof/report/evidence path rooted at:

- `receipt.json`
- `proof.json`
- `compiled.json`
- `summary.json`
- `evidence_manifest.json`
- `formal/`

Annex-only operational evidence is published separately:

- Metal Doctor
- runtime policy
- telemetry
- security supervision
- downstream mission-ops/dashboard/handoff artifacts

These annex artifacts are useful for mission operations and deployment
readiness, but they are not theorem-bearing.

When those governed mission-ops artifacts are staged under the proof bundle,
`zkf app reentry-assurance export-bundle` carries them into the public-safe
export alongside the proof/report/formal subtree. The export still omits the
private signed mission pack and any witness material by default.

## Public Export Hygiene

The release-safe export is treated as a product boundary, not a convenience
copy. In addition to filtering non-exportable artifacts by descriptor, the
public export path rewrites exported manifest and report surfaces so they only
describe the public-safe artifact set, and it scrubs machine-specific path/user
leakage from text artifacts under the exported tree.
