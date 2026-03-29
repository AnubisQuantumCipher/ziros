# zkf-lib

`zkf-lib` is the primary embedded application surface for ZirOS. Applications
that want to compile, prove, verify, scaffold app specs, and export verifiers
in-process should start here instead of shelling out to the CLI.

## Public API Surface

- Library crate: `zkf_lib`
- Primary entrypoints: `compile`, `prove`, `verify`, `check`,
  `compile_and_prove`, `compile_and_prove_with_progress_backend`
- Authoring surfaces: `ProgramBuilder`, `AppSpecV1`, `build_app_spec`,
  `instantiate_template`, `template_registry`
