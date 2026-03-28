# ZirOS AppSpecV1 Reference

`AppSpecV1` is the declarative schema behind `zirapp.json`. Use it when you want
the default standalone-app path:

1. scaffold with `ziros app init`,
2. edit `zirapp.json`,
3. run `cargo run` / `cargo test`.

Use `ProgramBuilder` instead when you need imperative Rust authoring, dynamic
program construction, or library-driven reuse that is awkward to express in
JSON.

## Top-Level Fields

An `AppSpecV1` document contains:

- `program`: required; `{ "name": "...", "field": "bn254" }`
- `signals`: required in practice; signal declarations with `name`,
  `visibility`, and optional `constant`
- `ops`: ordered `BuilderOpV1` entries that build witness assignments and
  constraints
- `lookup_tables`: optional lookup-table declarations
- `memory_regions`: optional advanced memory-region declarations
- `custom_gates`: optional advanced custom-gate declarations
- `metadata`: optional string-to-string metadata copied into the lowered program
- `sample_inputs`: optional known-good witness inputs
- `violation_inputs`: optional intentionally bad witness inputs that should fail
  closed
- `expected_inputs`: optional ordered input names for app surfaces
- `public_outputs`: optional ordered public output names for app surfaces
- `description`: optional human-readable summary
- `template_id` / `template_args`: optional template provenance when the spec
  came from `ziros app init`

## Signals

Each signal entry is:

```json
{ "name": "value", "visibility": "private" }
```

Visibility values:

- `private`: hidden witness value
- `public`: public input/output lane
- `constant`: fixed field element; requires `constant`

Constant example:

```json
{ "name": "one", "visibility": "constant", "constant": "1" }
```

## Expression Encoding

`Expr` values use tagged JSON:

```json
{ "op": "signal", "args": "value" }
{ "op": "const", "args": "1" }
{ "op": "add", "args": [
  { "op": "signal", "args": "a" },
  { "op": "signal", "args": "b" }
] }
{ "op": "sub", "args": [
  { "op": "signal", "args": "lhs" },
  { "op": "signal", "args": "rhs" }
] }
{ "op": "mul", "args": [
  { "op": "signal", "args": "x" },
  { "op": "signal", "args": "x" }
] }
{ "op": "div", "args": [
  { "op": "signal", "args": "numerator" },
  { "op": "signal", "args": "denominator" }
] }
```

## `BuilderOpV1` Kinds

Every `ops` entry must include `kind`.

Core authoring kinds:

- `assign`: derive a witness value
- `hint`: copy or resolve a witness value from another source
- `equal`: enforce equality between two expressions
- `boolean`: enforce `x ∈ {0,1}`
- `range`: enforce `0 <= x < 2^bits`
- `lookup`: constrain inputs against a named lookup table
- `black_box`: invoke built-in gadgets such as Poseidon, SHA-256, or Keccak

Convenience/helper kinds:

- `leq` / `geq`: ordered-comparison helpers with an explicit slack signal
- `nonzero`: require a signal to be nonzero
- `select`: conditional selection helper
- `copy` / `permutation`: wiring helpers
- `gadget`: registry-driven gadget emission

Advanced kinds:

- `custom_gate`: invoke a named custom gate
- `memory_read` / `memory_write`: memory-region constraints

Example range + equality spec:

```json
{
  "program": { "name": "range_demo", "field": "bn254" },
  "signals": [
    { "name": "value", "visibility": "private" },
    { "name": "is_valid", "visibility": "public" }
  ],
  "ops": [
    { "kind": "range", "signal": "value", "bits": 16, "label": "value_range" },
    {
      "kind": "equal",
      "lhs": { "op": "signal", "args": "is_valid" },
      "rhs": { "op": "const", "args": "1" },
      "label": "valid_flag"
    }
  ],
  "sample_inputs": { "value": "42" },
  "violation_inputs": { "value": "70000" },
  "public_outputs": ["is_valid"],
  "description": "16-bit range proof"
}
```

## Sample And Violation Inputs

- `sample_inputs` should be your known-good example for `cargo run`
- `violation_inputs` should be your fail-closed regression case for `cargo test`

The scaffolded app README and smoke test assume both are present when the
template can provide them.

## When To Switch To `ProgramBuilder`

Stay with `zirapp.json` when:

- the circuit is declarative and stable
- you want a portable scaffold file
- you want non-Rust tooling or agents to edit the spec directly

Switch to `ProgramBuilder` when:

- you need loops, branching, or host-language abstraction during construction
- the program shape depends on runtime configuration
- you want a Rust API instead of a JSON contract

## Related Docs

- [`APP_DEVELOPER_GUIDE.md`](/Users/sicarii/Projects/ZK DEV/docs/APP_DEVELOPER_GUIDE.md)
- [`TUTORIAL.md`](/Users/sicarii/Projects/ZK DEV/docs/TUTORIAL.md)
- [`NONLINEAR_ANCHORING.md`](/Users/sicarii/Projects/ZK DEV/docs/NONLINEAR_ANCHORING.md)
