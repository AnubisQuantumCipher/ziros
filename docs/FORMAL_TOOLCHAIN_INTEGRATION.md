# RefinedRust And Thrust Integration

This checkout admits RefinedRust and Thrust as additional formal-tool lanes
without changing the current verification-ledger counts.

## Counting Policy

- RefinedRust is a candidate counted lane. A RefinedRust row may become
  `mechanized_local` only after `cargo refinedrust` generates the Rocq/Radium
  translation and `dune build` checks the generated and stable proof files.
- Thrust is a non-counted support lane in this checkout. It may be used for
  automated safe-Rust refinement checks, invariant discovery, and regression
  screening, but it does not increase `mechanized_total`.
- A generated proof artifact, solver success, or checked-in pin file alone does
  not widen any theorem claim in `zkf-ir-spec/verification-ledger.json`.

## Tool Pins

- RefinedRust: `formal/tools/refinedrust-pin.json`
- Thrust: `formal/tools/thrust-pin.json`

The pins record upstream commit IDs, expected checker/solver assumptions, and
the local counting policy.

## Evidence Layout

RefinedRust counted evidence belongs under:

```text
formal/refinedrust/<surface>/
```

Thrust support evidence belongs under:

```text
formal/tool-evidence/thrust/
```

Fresh runner output is written under `target-local/formal/` so proof runs do not
silently mutate checked-in truth surfaces.

## Operator Commands

```bash
scripts/run_refinedrust_proofs.sh [--strict] [surface...]
scripts/run_thrust_checks.sh [--strict] [target...]
```

Strict mode fails closed on missing tools, missing surfaces, failed proof builds,
or failed solver checks. Non-strict mode emits machine-readable skipped evidence
when the optional toolchain is unavailable.

## Initial Target Policy

Use RefinedRust first on small unsafe or FFI capsules, especially runtime buffer
views, keystore/randomness boundaries, and host-side Metal launch wrappers. Use
Thrust first on safe proof-core modules where automation can cheaply catch
state-machine and arithmetic regressions.

Protocol rows for Groth16, FRI, Nova, and HyperNova remain separate proof
obligations. RefinedRust and Thrust can strengthen the implementation boundary,
but they do not prove cryptographic protocol soundness by themselves.
