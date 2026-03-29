# zkf-frontends

`zkf-frontends` imports external proof DSLs and artifact formats into the
canonical ZirOS IR. It is the bridge from Noir, Circom, Cairo, Compact,
Halo2-export, Plonky3-AIR, and zkVM descriptors into `zkf-core::Program`.

## Public API Surface

- Library crate: `zkf_frontends`
- Main traits and types: frontend registry, import helpers, frontend probes,
  frontend import/export options
- Supported frontend families: Noir, Circom, Cairo, Compact, Halo2-Rust,
  Plonky3-AIR, zkVM
