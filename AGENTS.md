# AGENTS.md — ZKF (Zero-Knowledge Framework)

## Project overview
Treat the current checkout as the source of truth. Historical planning prose in old status docs is not authoritative when it conflicts with the code, the generated support matrix, or the verification ledger.

Current live truth sources, in order:
- `zkf-ir-spec/verification-ledger.json`
- `.zkf-completion-status.json`
- `docs/CANONICAL_TRUTH.md`
- `support-matrix.json`
- `forensics/`

Do not revive the historical "10 gaps" list as if it were current. Several formerly listed items are already implemented in this tree, including Python `abi3-py38`, GPU SHA/Keccak, Nova compression hooks, HyperNova end-to-end tests, API queue/auth/rate-limit/CORS/health/status, LSP hover/definition/diagnostics, and Neural Engine / CoreML control-plane wiring.

## Build & test commands
- Build: `cargo build --workspace`
- Build release: `cargo build --workspace --release`
- Test all: `cargo test --workspace --lib --no-fail-fast`
- Test one crate: `cargo test -p <crate-name> --lib`
- Lint: `cargo clippy --workspace -- -D warnings`
- Format check: `cargo fmt --all -- --check`

## Working agreements
- Run `/Users/sicarii/.jacobian/bin/codex-memory resume --cwd /Users/sicarii/Desktop/ZirOS` before substantial work so the ZirOS context pack and global memory spine are current.
- Run `cargo build --workspace` after modifications. Never leave the build broken.
- Run `cargo test -p <crate>` on every crate you change before considering work done.
- Write real implementations. Do not land placeholders, TODO deliverables, or documentation that advertises capabilities the checkout does not have.
- Read existing code before writing new code. Match established patterns and naming.
- Never delete or weaken passing tests to make changes land.
- Update `.zkf-completion-status.json`, generated proof-boundary summaries, and forensic reports when status-bearing claims change.
- After substantial work, run `/Users/sicarii/.jacobian/bin/codex-memory handoff --cwd /Users/sicarii/Desktop/ZirOS --summary "..." --next-step "..."` so `.ops/context/` and the global memory store stay synchronized.

## Architecture
- **zkf-core/src/ir.rs**: IR v2 — `Expr`, `Signal`, `Constraint`, `Program`
- **zkf-core/src/witness.rs**: witness generation, `check_constraints`, `eval_expr`
- **zkf-core/src/field.rs**: `FieldElement`, 7 finite fields
- **zkf-backends/src/lib.rs**: `BackendEngine` trait (`compile` / `prove` / `verify`)
- **zkf-backends/src/blackbox_gadgets/mod.rs**: `lower_blackbox_program()`, `enrich_witness_for_proving()`
- **zkf-backends/src/arkworks.rs**: Groth16 reference backend
- **zkf-backends/src/plonky3.rs**: STARK backend with Metal GPU stages
- **zkf-backends/src/wrapping/stark_to_groth16.rs**: STARK-to-Groth16 wrapper lane
- **zkf-metal/src/**: Metal device, NTT/MSM/hash kernels, runtime bindings
- **zkf-runtime/src/lib.rs**: UMPG runtime, trust lanes, scheduler, telemetry
- **zkf-api/src/**: Axum API, auth, job queue, rate limiting
- **zkf-lsp/src/**: IR/LSP diagnostics, hover, goto-definition
- **zkf-python/src/lib.rs**: PyO3 bindings for compile/prove/verify/import/inspect

## Soundness invariants — never break these
- `lower_blackbox_program()` must run before circuit synthesis in every backend prove path.
- `enrich_witness_for_proving()` must run before `check_constraints()` in every prove path.
- `original_program` must be retained in `CompiledProgram` when BlackBox constraints are lowered.
- `check_constraints()` must pass before any proof is generated.
- Verification must only use `proof + verification key + public inputs`. Never use witness data at verify time.
- Strict cryptographic lanes must fail closed. They must not silently downgrade into compatibility aliases, attestation-only paths, metadata-only markers, or model-advisory routes.

## Assurance vocabulary
Use these buckets precisely in docs, status JSON, and user-facing capability surfaces:
- `mechanized`: machine-checked theorem over the shipped proof surface
- `bounded`: regression/property/model-check evidence over a bounded corpus, not an unbounded theorem
- `model-only`: theorem about a model/boundary summary, not direct end-to-end implementation correctness
- `hypothesis-carried`: theorem that still depends on explicit cryptographic or upstream hypotheses
- `compatibility alias`: explicit compatibility route such as `sp1-compat`; never present as a native strict lane
- `metadata-only`: marker/binding surface with no in-circuit recursive verifier semantics
- `explicit_tcb_adapter`: operational/runtime boundary that is intentionally tracked as trusted infrastructure rather than as mechanized proof logic

## First-tranche priorities
- Truth first: keep docs, status JSON, support matrix, and forensic reports synchronized with the checkout and ledger.
- Strict honesty: label compatibility aliases, metadata-only recursion markers, model-backed control-plane outputs, and delegated/external lanes explicitly.
- Strict crypto lane: reject unsupported strict requests instead of silently downgrading them.
- Assurance closure: reduce first-party unclassified surfaces by promoting them either to mechanized/shell-contract proof coverage or to explicit TCB boundaries with precise notes.
- Evidence over aspiration: do not add speculative roadmap prose as if it were shipped capability.

## Key technical constraints
- Plonky3 is pinned to `=0.4.2`; do not change it casually.
- `RecursiveAggregationMarker` is metadata-only, not an in-circuit recursive verifier.
- BN254 is the default field; Poseidon2, Pedersen, and Schnorr remain BN254-only operations.
- Metal GPU functionality must stay behind macOS gating and the existing feature flags.
- Neural Engine functionality stays behind `#[cfg(feature = "neural-engine")]` and remains advisory for scheduling/recommendation, not proof validity.
