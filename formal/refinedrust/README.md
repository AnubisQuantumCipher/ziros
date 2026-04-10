# RefinedRust Evidence Surfaces

RefinedRust is the preferred counted lane for high-assurance Rust memory and
unsafe-boundary verification. A surface is counted in
`zkf-ir-spec/verification-ledger.json` only after:

1. `cargo refinedrust` generates the Rocq/Radium translation for the target.
2. `dune build` checks the generated and stable proof files.
3. The surface `STATUS.md` names the shipped Rust boundary, exclusions, trusted
   assumptions, and checked log path.

Expected per-surface layout:

```text
formal/refinedrust/<surface>/
  STATUS.md
  pin.json
  target_path
  dune_path
  generated/
  proofs/
  interface.rrlib
```

`target_path` and `dune_path` are plain text paths relative to the repository
root. When absent, the runner uses the surface directory for both commands.
