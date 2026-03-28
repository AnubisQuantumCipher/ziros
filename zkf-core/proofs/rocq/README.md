# zkf-core Rocq Workspace

This directory is the Rocq-facing proof workspace for the `zkf-core` proof kernel.

The extracted target for this tranche is intentionally narrow and annotation-driven:

- crate: `zkf-core`
- extraction filter: `-**`
- included Rust entrypoints: `zkf_core::proof_kernel_spec::*`, `zkf_core::proof_witness_generation_spec::*`, and `zkf_core::proof_ccs_spec::*` items annotated with `hax_lib::include`
- backend name in hax: `coq`
- checked-in sync target: `zkf-core/proofs/rocq/extraction/`
- pinned opam switch: `hax-5.1.1`
- pinned OCaml version: `5.1.1`

The hax frontend still names the Rocq backend `coq`, so the local runner uses that backend name and then mirrors the generated files into the `rocq/` workspace path used by the ZKF ledger.

`scripts/run_hax_rocq_extract.sh` also repairs and normalizes the generated Rocq so this workspace compiles reproducibly:

- `Zkf_core_Proof_kernel_spec_Bundle.v` imports `Zkf_core_Field`
- `Zkf_core_Proof_kernel_spec.v` imports `Zkf_core_Proof_kernel_spec_Bundle`
- `Zkf_core_Proof_kernel_spec_Spec_field_ops.v` imports `Zkf_core_Proof_kernel_spec_Bundle`
- `Zkf_core_Proof_witness_generation_spec.v` imports `Zkf_core_Proof_kernel_spec` and `KernelCompat`
- `Zkf_core_Proof_ccs_spec.v` is normalized into a Rocq-compilable pure CCS builder/runtime surface
- the generated kernel bundle is rewritten into structurally recursive list helpers that Rocq accepts
- the generated witness file is normalized so slice-of-option types and opaque runtime hooks parse under Rocq 9.1
- the generated CCS file is normalized so the extracted builder/runtime path for fail-closed synthesis compiles under Rocq 9.1

`scripts/run_rocq_proofs.sh` compiles those generated modules in dependency order before checking `KernelGenerated.v`, `KernelSemantics.v`, `KernelProofs.v`, `WitnessGenerationSemantics.v`, `WitnessGenerationProofs.v`, `CcsSemantics.v`, and `CcsProofs.v`.

Pinned hax source:

- repo: `https://github.com/cryspen/hax`
- rev: `1f0259212fa994fb351853026397042c497d07b9`

Local commands:

- `./scripts/bootstrap_hax_toolchain.sh`
- `./scripts/run_hax_rocq_extract.sh`
- `./scripts/run_rocq_proofs.sh`

Current completion boundary:

- local hax bootstrap and extraction are in scope here
- `./scripts/run_hax_rocq_extract.sh` and `./scripts/run_rocq_proofs.sh` are both green locally
- `KernelSemantics.v` and `KernelProofs.v` mechanize relative soundness for `eval_expr`, lookup helpers, `check_constraints_from`, and `check_program` over the extracted datatypes, and the generated workspace now concretizes the extracted field operators to canonical modular arithmetic so these kernel theorems are axiom-free at the semantic-model layer
- the shipped BN254, BLS12-381 scalar, PastaFp, and PastaFq runtime now comes from checked-in Fiat-Crypto generated modules under `zkf-core/src/fiat_generated/`, with `zkf-core/fiat-crypto-manifest.json` and `scripts/regenerate_fiat_fields.sh --check` acting as the runtime freshness boundary
- `WitnessGenerationSemantics.v` and `WitnessGenerationProofs.v` prove the extraction-safe non-blackbox witness-generation subset returns witnesses accepted by the extracted proof kernel, now including assignments and hints in the shipped pure-core runtime
- `CcsSemantics.v` and `CcsProofs.v` prove the extracted pure CCS conversion path is fail-closed on unsupported lookup/non-lowered-blackbox constraints and preserves the canonical three-matrix CCS/R1CS shape for successful conversions
- the public `generate_witness` entrypoint now routes pure-core-supported programs through the extracted proof-facing generator; blackbox handling, ACVM presolve, backend-specific presolvers, and other external-solver-dependent runtime paths remain outside the mechanized subset
