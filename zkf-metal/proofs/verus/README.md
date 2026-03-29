# Metal GPU Verus Proof Surface

This directory holds the host-boundary proof model for the checked GPU launch
contracts exported by `zkf-metal/src/launch_contracts.rs`.

The current Verus lane proves the pure model properties that are honest to
claim today:

- non-empty typed regions on accepted launches
- non-zero dispatch geometry on accepted launches
- certified BN254 routing excludes hybrid, tensor, and full-GPU routes

These proofs are intentionally scoped to the host boundary. They do not yet
prove the full kernel mathematics for hash, Poseidon2, NTT, or MSM.
