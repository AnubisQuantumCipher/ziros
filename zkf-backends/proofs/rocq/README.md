# zkf-backends Rocq Workspace

This directory is the Rocq-facing proof workspace for backend-local proof kernels in
`zkf-backends`.

The initial backend proof surface is intentionally narrow:

- crate: `zkf-backends`
- extraction filter: `-**`
- included Rust entrypoints: `zkf_backends::proof_plonky3_spec::*` plus future
  backend proof kernels annotated with `hax_lib::include`
- backend name in hax: `coq`
- checked-in sync target: `zkf-backends/proofs/rocq/extraction/`
- pinned opam switch: `hax-5.1.1`
- pinned OCaml version: `5.1.1`

The backend extraction path is kept separate from `zkf-core` so backend-local proof
obligations can evolve without widening the core proof kernel.

Current completion boundary:

- backend proof-kernel extraction wiring exists locally
- the shipped Plonky3 backend now delegates through `proof_plonky3_spec.rs`
- the Plonky3/blackbox backend proof files are green on the checked-in extraction lane
- the protocol exact reduction lane uses the dedicated `zkf-protocol-exact-hax`
  crate and `HAX_PROTOCOL_PIN.toml` to extract the shipped
  `proof_*_exact_spec.rs` modules into this workspace
- `scripts/run_protocol_exact_rocq_proofs.sh` regenerates the protocol exact
  extraction files and checks `ProtocolExactProofs.v`
