# Supply-Chain Boundary

This store is the `cargo vet` root for ZKF.

The first audited boundary for the Apple-Silicon hybrid defense tranche is:

- `libcrux-ml-dsa`
- `ed25519-dalek`
- `sha2`

These crates back the hybrid swarm identity, transcript digest, replay-manifest, and proof-bundle surfaces. They must remain audited in `supply-chain/audits.toml`.

Update workflow:

1. Run `cargo vet check --store-path supply-chain --manifest-path Cargo.toml`.
2. If the boundary changes, add an explicit audit entry before merging.
3. Do not broaden vendoring beyond the trust boundary without a separate review.
