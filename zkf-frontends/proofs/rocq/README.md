# zkf-frontends Rocq Workspace

This directory is the Rocq-facing proof workspace for the Noir import/recheck
boundary in `zkf-frontends`.

The surface for this tranche is intentionally narrow:

- crate: `zkf-frontends`
- extraction filter: `-**`
- included Rust entrypoint: `zkf_frontends::proof_noir_recheck_spec::*`
- backend name in hax: `coq`
- checked-in sync target: `zkf-frontends/proofs/rocq/extraction/`
- pinned opam switch: `hax-5.1.1`
- pinned OCaml version: `5.1.1`

The theorem boundary is limited to `validate_translated_constraints_against_acvm_witness`
as a shell-contract wrapper:

- it models the local acceptance/rejection boundary of the wrapper
- it does not claim ACVM semantics
- it does not claim Noir translator semantics

Pinned hax source:

- repo: `https://github.com/cryspen/hax`
- rev: `1f0259212fa994fb351853026397042c497d07b9`

Local commands:

- `./scripts/run_hax_frontend_rocq_extract.sh`

Current completion boundary:

- no frontend theorem is promoted in the ledger from this workspace until the
  extracted files and hand-written proofs are actually green
