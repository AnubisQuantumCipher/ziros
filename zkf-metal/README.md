# zkf-metal

`zkf-metal` is the Apple Silicon GPU execution crate for ZirOS. It owns the
Metal-backed kernels, attestation data, runtime bindings, and strict host
boundary checks used by the verified GPU lane.

## Public API Surface

- Library crate: `zkf_metal`
- Scope: Metal device context, MSM/NTT/hash dispatch, attested GPU execution
