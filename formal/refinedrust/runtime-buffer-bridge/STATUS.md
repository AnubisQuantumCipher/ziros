# Runtime Buffer Bridge RefinedRust Surface

## Scope

This surface verifies the feature-gated RefinedRust translation of
`zkf-runtime::buffer_bridge_core::resident_bytes_after_add` and the shipped
`BufferBridgeCore` call sites that delegate resident-byte increment arithmetic
through that helper under `kani-minimal`.

The counted theorem is narrow: resident-byte addition returns the exact
mathematical sum when the sum is in `usize`. Eviction subtraction, filesystem
spill behavior, GPU residency, slot-map allocation, and full typed-view
semantics remain covered by their existing Verus/Kani/proptest rows rather than
this RefinedRust row.

## Commands

```bash
scripts/run_refinedrust_proofs.sh --strict runtime-buffer-bridge
```

The surface runner executes:

```bash
cargo refinedrust -- -p zkf-runtime --lib --no-default-features --features kani-minimal,refinedrust
dune build
```

The generated Rocq/Radium output and build log are intentionally regenerated
under ignored local artifact roots:

- `target/verify/zkf_runtime/`
- `target-local/formal/refinedrust/refinedrust.log`
- `target-local/formal/refinedrust/refinedrust-evidence.json`

## Trusted Boundary

- RefinedRust upstream implementation pinned by `formal/tools/refinedrust-pin.json`
- Rocq kernel and imported Radium/Iris/RefinedRust libraries
- Rust compiler semantics accepted by RefinedRust for this surface
- The explicit `usize` no-overflow precondition in the RefinedRust spec
