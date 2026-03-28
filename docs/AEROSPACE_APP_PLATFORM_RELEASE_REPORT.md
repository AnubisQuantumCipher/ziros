# Aerospace App Platform Release Report

## Scope

This release adds a permanent aerospace app-building surface to ZirOS through the
existing `zkf-lib` and `ziros app init` interfaces. It does not introduce a
parallel aerospace DSL. It extends the maintained app/template/builder/scaffold
surface so aerospace certification apps can be created repeatedly from the same
public contract.

## Included Changes

- Added `zkf-lib/src/app/aerospace.rs` as the reusable aerospace app kit.
- Added typed request/config surfaces for the flagship
  `private-starship-flip-catch` app.
- Added reusable builder helpers for indexed signals, one-hot selectors, mux
  lowering, and nonlinear commitment binding.
- Registered first-class aerospace templates:
  - `gnc-6dof-core`
  - `tower-catch-geometry`
  - `barge-terminal-profile`
  - `planetary-terminal-profile`
  - `gust-robustness-batch`
  - `private-starship-flip-catch`
- Extended `ziros app init` to scaffold aerospace apps with:
  - `scripts/benchmark.sh`
  - `scripts/generate_report.sh`
  - `scripts/export_public_bundle.sh`
  - `artifacts/benchmarks/`
  - `artifacts/reports/`
  - `artifacts/public/`
- Updated developer-facing docs and support metadata for the new aerospace lane.

## Production Posture Encoded By This Release

- `AppSpecV1` remains the stable declarative app contract.
- `ProgramBuilder` remains the imperative escape hatch.
- Final regulator-facing wrap posture is documented as imported CRS only.
- Neural Engine is documented as advisory only.
- TCP is documented as the counted distributed transport baseline.
- RDMA remains follow-on and is not claimed as shipped proof-bearing surface.

## What This Release Does Not Claim

- It does not claim that the broader ZirOS runtime/distributed/formal proof
  boundary has been newly closed for all aerospace workload semantics.
- It does not claim that RDMA transport is implemented and proven.
- It does not claim that the runtime proof ledger or verification ledger now
  covers the full Starship certification narrative.
- It does not publish an artifact-only proof bundle. This is a source-visible
  branch release of the app-platform tranche.

## Validation Run

The following checks were executed successfully during this release pass:

```bash
CARGO_TARGET_DIR=/tmp/zkf-codex-target cargo check -p zkf-lib -p zkf-cli
CARGO_TARGET_DIR=/tmp/zkf-codex-target cargo test -p zkf-lib builder_ -- --nocapture
CARGO_TARGET_DIR=/tmp/zkf-codex-target cargo test -p zkf-lib starship_request_inputs -- --nocapture
CARGO_TARGET_DIR=/tmp/zkf-codex-target cargo test -p zkf-lib aerospace_ -- --nocapture
CARGO_TARGET_DIR=/tmp/zkf-codex-target cargo test -p zkf-cli aerospace_app_init_generates_scripts_and_public_bundle_dirs -- --nocapture
```

## Environment Notes

- `rustfmt` could not be executed on this host because the installed `rustfmt`
  binary is missing `librustc_driver` at runtime.
- The repository worktree contained unrelated user changes outside this tranche.
  This release intentionally stages and publishes only the aerospace app-platform
  files listed in this report.

## Release Intent

This release is a maintained platform tranche, not a one-off demo. The flagship
Starship template is shipped as the first app on the permanent aerospace rail,
with reusable helpers and scaffold support intended for future aerospace
applications built through the same surfaces.
