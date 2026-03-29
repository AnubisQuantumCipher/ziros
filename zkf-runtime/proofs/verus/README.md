# Runtime Verus Proof Surface

This workspace mechanizes the pure `BufferBridgeCore` proof model rather than
the full runtime crate. The target claims are the three Phase 2 buffer
invariants promoted from bounded Kani evidence:

- `runtime.buffer_read_write_bounded`
- `runtime.buffer_residency_transition_bounded`
- `runtime.buffer_alias_separation_bounded`

The proof file models slot occupancy, resident-byte accounting, unique slot
identity, and fail-closed access after eviction or free. Concrete typed-view
roundtrip behavior remains covered by the existing Kani harnesses in
`zkf-runtime/src/verification_kani.rs`; the Verus lane strengthens the global
buffer invariant story by proving the model-level layout, separation, and
transition properties for all states.
