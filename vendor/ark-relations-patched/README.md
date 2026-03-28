# ark-relations-patched

Patched local vendor of `ark-relations` used by ZKF.

## Upstream Base

- Crate: `ark-relations`
- Upstream line: `0.5.x`
- Local patch source of truth: this directory plus the workspace `[patch.crates-io]` entry in the repo root `Cargo.toml`

## Why This Exists

ZKF vendors this crate because the proving stack depends on local behavior in the R1CS relation layer that is not consumed from crates.io directly. The patch is intentionally explicit because cargo security tooling cannot infer the diff semantics of an unpublished local fork.

## Local Diff Summary

- Carries ZKF-specific R1CS relation behavior required by the backend stack.
- Must remain compatible with the workspace Arkworks dependency set pinned in the root manifest.
- Any semantic change here must be reviewed as proving-system-critical.

## Sync Procedure

1. Compare this directory against the current upstream `ark-relations` release line.
2. Re-apply only the minimal ZKF-required changes.
3. Re-run `cargo build --workspace` and the Arkworks/backend test surfaces.
4. Update this file with the new upstream base and diff summary.

## Review Cadence

- Review upstream releases at least quarterly.
- Review immediately when Arkworks publishes a security advisory or a bug fix in the relation layer.
