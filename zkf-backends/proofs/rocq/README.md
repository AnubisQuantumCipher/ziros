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
- no backend theorem is promoted in the ledger from this workspace until the extracted
  files and hand-written proofs are actually green
