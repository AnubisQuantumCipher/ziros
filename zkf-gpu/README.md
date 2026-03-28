# zkf-gpu

`zkf-gpu` defines stable GPU abstraction interfaces used across acceleration
lanes. In the current workspace the production proving path is the Metal
implementation, and this crate provides the broader abstraction layer around it.

## Public API Surface

- Library crate: `zkf_gpu`
- Scope: accelerator interfaces and GPU-facing abstraction types
