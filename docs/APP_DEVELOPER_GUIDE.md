# ZirOS App Developer Guide

## Goal

Phase V1 makes `zkf-lib` the single source of truth for standalone application developers.

Use it for:

- declarative `AppSpecV1` / `zirapp.json` authoring
- explicit circuit construction with `ProgramBuilder`
- starter templates via `zkf_lib::templates`
- deterministic witness input encoding via `zkf_lib::inputs`
- app-facing audit wrappers
- programmatic verifier export

Use `ziros app init` when you want a working external Rust app scaffolded against
the current checkout. `zkf app init` remains the compatibility alias.

## Start Here

For a first app:

1. scaffold with `ziros app init`
2. edit `zirapp.json`
3. run `cargo run`
4. run `cargo test`

Read these alongside the scaffold:

- [`TUTORIAL.md`](/Users/sicarii/Projects/ZK DEV/docs/TUTORIAL.md)
- [`APPSPEC_REFERENCE.md`](/Users/sicarii/Projects/ZK DEV/docs/APPSPEC_REFERENCE.md)
- [`NONLINEAR_ANCHORING.md`](/Users/sicarii/Projects/ZK DEV/docs/NONLINEAR_ANCHORING.md)

## Scaffold a Standalone App

```bash
ziros app init my-zk-app --template poseidon-commitment
ziros app init my-zk-app --template poseidon-commitment --style tui
ziros app gallery
cd my-zk-app
cargo run
cargo test
```

Generated files:

- `Cargo.toml`: standalone package plus its own `[workspace]`
- `zirapp.json`: canonical declarative app spec
- `src/spec.rs`: generic runtime loader for `zirapp.json`
- `src/main.rs`: compile/prove/verify in-process
- `inputs.compliant.json`: valid starter inputs
- `inputs.violation.json`: intentionally bad inputs that should fail closed
- `tests/smoke.rs`: end-to-end prove/verify smoke
- `README.md`: local instructions

Available templates:

- `poseidon-commitment`
- `merkle-membership`
- `private-identity`
- `private-vote`
- `range-proof`
- `sha256-preimage`
- `private-powered-descent`
- `private-satellite-conjunction`
- `private-multi-satellite-base32`
- `private-multi-satellite-stress64`
- `private-nbody-orbital`

Available styles:

- `minimal`: plain-text proving flow
- `colored`: default polished proving flow with `zkf-ui`
- `tui`: dashboard scaffold with `zkf-tui`

Use [`APP_DEVELOPER_TUI_GUIDE.md`](/Users/sicarii/Projects/ZK DEV/docs/APP_DEVELOPER_TUI_GUIDE.md)
when you want a dashboard-style application or want to adapt the AegisVault example pattern.

List templates with:

```bash
ziros app templates
ziros app templates --json
ziros app init my-zk-app --template merkle-membership --template-arg depth=4
```

The direct `zirapp.json` route remains available when you want the manual/operator
path, but the scaffold above is the default new-developer workflow.

## Build a Program Explicitly

`ProgramBuilder` builds on `zir-v1` internally and lowers to `ir-v2` on `build()`. The v1 surface
is intentionally explicit: use `zkf_core::Expr` values directly, declare signals yourself, and add
constraints deliberately. This is the escape hatch, not the required starting point.

```rust
use zkf_lib::{Expr, FieldElement, FieldId, ProgramBuilder};

pub fn program() -> zkf_lib::Program {
    let mut builder = ProgramBuilder::new("age_check", FieldId::Bn254);
    builder.private_input("age").expect("age");
    builder.public_output("is_valid").expect("is_valid");
    builder.constant_signal("one", FieldElement::ONE).expect("one");
    builder.constrain_range("age", 8).expect("range");
    builder
        .constrain_equal(Expr::signal("is_valid"), Expr::signal("one"))
        .expect("valid flag");
    builder.build().expect("build")
}
```

Available builder methods:

- signal declaration: `private_input`, `public_input`, `public_output`, `private_signal`, `constant_signal`
- witness/alias support: `add_assignment`, `bind`, `add_hint`, `input_alias`
- constraints: `constrain_equal`, `constrain_boolean`, `constrain_range`, `constrain_leq`, `constrain_geq`, `constrain_nonzero`, `constrain_select`
- parity surfaces: `add_lookup_table`, `constrain_lookup`, `define_custom_gate`, `constrain_custom_gate`, `define_memory_region`, `constrain_memory_read`, `constrain_memory_write`, `constrain_copy`, `constrain_permutation`, `constrain_blackbox`
- extension hooks: `register_gadget`, `with_registry`, `emit_gadget`

The builder restores input aliases into `WitnessPlan.input_aliases` after lowering, so external app
input names can stay stable even when internal signal names change.

## Use Safe Templates

Starter templates return a `TemplateProgram` with:

- `program`
- `expected_inputs`
- `public_outputs`
- `sample_inputs`
- `description`

Example:

```rust
let template = zkf_lib::templates::poseidon_commitment().expect("template");
let embedded = zkf_lib::compile_and_prove_default(
    &template.program,
    &template.sample_inputs,
    None,
    None,
)
.expect("prove");
assert!(zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"));
```

V1 templates ship only production-safe starter surfaces. They do not enable permissive toy-circuit
shortcuts or weaken the hardened underconstraint/signature audit boundary.

## Encode Inputs Deterministically

`zkf_lib::inputs` contains small, explicit helpers for app-side encoding:

- `bytes_to_field_elements`
- `string_to_field_elements`
- `u64s_to_field_elements`
- `bools_to_field_elements`
- `merkle_path_witness_inputs`

These helpers are intentionally narrow. V1 does not include arbitrary nested JSON auto-mapping.

## Run Audits from the App Surface

When you already have an `ir-v2::Program`, use the app-facing wrappers:

```rust
let report = zkf_lib::audit_program_default(&program, None);
let live_report = zkf_lib::audit_program_with_live_capabilities(&program, None);
```

These wrappers bridge back to the audit surface internally so app code does not need to work with
`zir-v1` directly.

## Export a Verifier

Programmatic verifier export is available through `zkf-lib` for proof artifacts:

```rust
let solidity = zkf_lib::export_groth16_solidity_verifier(&artifact, Some("MyVerifier"))
    .expect("solidity verifier");
```

V1 default:

- Groth16 Solidity export is the primary app-facing path

V1 non-goals:

- SP1 Solidity export from the shared library surface
- automatic verifier selection for unsupported backend/language pairs

For unsupported combinations, use the generic `export_verifier(...)` helper and handle the returned
error explicitly.

## Phase Boundaries

V1 includes:

- standalone scaffolds wired by local path dependencies
- explicit builder APIs over existing signal/expression concepts
- safe starter templates
- deterministic input helpers
- app-facing audit wrappers
- library-side verifier export helpers

Deferred beyond V1:

- `zkf app check`
- published/git dependency scaffold modes
- string DSL parsing
- hidden witness inference
- expanded example-app catalog
- SP1 shared-library verifier export
