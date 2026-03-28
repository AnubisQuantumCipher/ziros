# Contributing

ZirOS is maintained under a truth-first policy: documentation, capability
surfaces, and release claims must stay behind the code, never ahead of it.

## Build

```bash
./zkf-build.sh
./zkf-build.sh --release
```

## Required Checks

Run these before opening a change:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
./scripts/run_builtin_example_audits.sh
./scripts/run_conformance_suite.sh
```

## Audit Requirements

- Treat audit failures as release blockers.
- Do not weaken nonlinear-anchoring checks, witness validation, or fail-closed
  runtime behavior to make a change land.
- Keep truth surfaces aligned with the live sources:
  `zkf-ir-spec/verification-ledger.json`, `.zkf-completion-status.json`,
  `docs/CANONICAL_TRUTH.md`, and `support-matrix.json`.

## Coding Standards

- Match existing crate patterns before adding new abstractions.
- Prefer deterministic, machine-checkable behavior over convenience heuristics.
- Keep strict cryptographic lanes explicit; do not silently downgrade them.
- Add or update tests when behavior changes.
- Do not commit local artifacts, setup blobs, logs, temporary bundles, or
  generated files unless the repository intentionally tracks them.
