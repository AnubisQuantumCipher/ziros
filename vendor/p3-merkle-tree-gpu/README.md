# p3-merkle-tree-gpu

Patched local vendor of `p3-merkle-tree` used by ZKF.

## Upstream Base

- Crate family: `p3-merkle-tree`
- Upstream line: `0.4.2`
- Local patch source of truth: this directory plus the root workspace dependency override

## Why This Exists

ZKF needs a local fork because the Plonky3 stack is pinned to exact `0.4.2` semantics and the Merkle tree path includes GPU-aware behavior that is not provided by the upstream crates.io release.

## Local Diff Summary

- Preserves exact Plonky3 `0.4.2` compatibility expected by the wrapping path.
- Carries ZKF GPU-aware Merkle tree behavior used by the Metal execution path.
- Must not drift independently from the rest of the pinned Plonky3 dependency set.

## Sync Procedure

1. Diff this directory against upstream `p3-merkle-tree = 0.4.2`.
2. Re-apply the GPU-specific changes only.
3. Re-run Plonky3, wrapping, and Metal-related tests.
4. Update this file when the upstream base or local diff changes.

## Review Cadence

- Review upstream Plonky3 changes quarterly.
- Re-review immediately if the wrapper path or Merkle commitments change.
