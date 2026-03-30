# ZirOS

> ## The Zero-Knowledge Operating System
>
> A source-backed proving workspace for authoring, importing, auditing, compiling, scheduling, accelerating, verifying, exporting, and formally accounting for zero-knowledge computation.
>
> ZirOS is the system layer that sits between application intent and raw proving machinery. You describe a statement. ZirOS owns the rest of the path: canonical IR, fail-closed audits, witness generation, backend routing, CPU/GPU scheduling, attested Metal execution, proof verification, verifier/export surfaces, runtime telemetry, and evidence-carrying artifacts.
>
> This checkout is the public ZirOS workspace and proof surface shipped in this repository. The constitution and supporting docs also describe broader ZirOS infrastructure and release posture; this README is intentionally stricter than that broader story. It only claims what can be grounded in the current tree, its live truth surfaces, and its checked-in public adjuncts.

## Live Checkout Facts

| Fact | Current checkout value |
| --- | --- |
| Workspace crates | 30 |
| First-party Rust source lines | 288,785 `.rs` lines outside `vendor/` |
| Proving backends in `support-matrix.json` | 9 total: 5 `ready`, 1 `limited`, 3 `broken` |
| Frontend families in `support-matrix.json` | 7 total: 6 `ready`, 1 `limited` |
| Gadget families in `support-matrix.json` | 11 total: 8 `ready`, 3 `limited` |
| Canonical finite fields in `zkf-core` | 7: `bn254`, `bls12-381`, `pasta-fp`, `pasta-fq`, `goldilocks`, `babybear`, `mersenne31` |
| Metal shader sources | 18 `.metal` files with 50 kernel entrypoints |
| Verified Metal manifests | 9 checked-in manifest files under `zkf-metal/proofs/manifests` |
| Verification ledger | 168 total rows (160 `mechanized_local` + 8 `proposed` SED entries), 0 pending |
| Runtime proof coverage | 89 files and 1,788 functions marked complete |

## Table Of Contents

- What ZirOS Is
- System Architecture
- Full Technology Stack
- Proving And Execution Surfaces
- Core ZirOS Subsystems
- Verified Boundary And Trust Model
- Scientific, Engineering, And Mission Applications
- Operator Entry Paths
- Performance, Hardware, And Storage
- Quick Start
- Documentation And Truth Surfaces
- Workspace And Technology Catalog
- Standalone Subsystems
- Distributed Proving And Cluster Scaling
- Midnight Network Integration
- License

## What ZirOS Is

ZirOS is not just a proof library and it is not just a backend wrapper. It is a workspace that treats zero-knowledge proving as an end-to-end systems problem:

- Authoring and import: `zirapp.json`, `ProgramBuilder`, Rust macros, and foreign-circuit importers.
- Truth and audit: canonical IR, field typing, nonlinear anchoring, constraint checking, and live capability surfaces.
- Execution: backend selection, UMPG graph planning, hybrid CPU/GPU scheduling, trust-lane propagation, and telemetry.
- Acceleration: Apple Silicon Metal kernels, ARM crypto paths, and GPU abstraction layers.
- Interfaces: CLI, API, Python, C FFI, LSP, UI/TUI, registry, and plugin SDK.
- Evidence: verification ledger, proof-boundary metadata, formal proof surfaces, verifier/export helpers, and public proof tools.

That is why the repository is broad. The same checkout contains:

- formal IR and live truth surfaces in `zkf-ir-spec`
- proving primitives in `zkf-core`, `zkf-gadgets`, and `zkf-backends`
- runtime and hardware layers in `zkf-runtime`, `zkf-metal`, `zkf-gpu`, and `zkf-crypto-accel`
- distributed and defensive layers in `zkf-distributed`
- operator surfaces in `zkf-cli`, `zkf-api`, `zkf-python`, `zkf-ffi`, `zkf-lsp`, `zkf-ui`, and `zkf-tui`
- application and showcase layers in `zkf-lib`, `zkCarbon`, `zk_rollup`, `private_budget_approval`, and `uccr-showcase`

The result is a workspace that can speak to cryptographers, systems engineers, compiler/tooling authors, and scientific users without pretending they all need the same interface.

## System Architecture

```mermaid
flowchart LR
    A["Authoring Surfaces<br/>AppSpecV1 • ProgramBuilder • zkf-dsl • Noir • Circom • Cairo • Compact • Halo2 export • Plonky3 AIR • zkVM descriptors"]
    B["Canonical Core<br/>zkf-core • zkf-ir-spec<br/>IR • fields • witness generation • audits • proof artifacts"]
    C["Backend Layer<br/>zkf-backends • zkf-backends-pro<br/>compile • prove • verify • wrapping • capability routing"]
    D["Runtime Layer<br/>zkf-runtime<br/>UMPG DAG • trust lanes • telemetry • planning"]
    E["Execution Placements<br/>CPU • CpuCrypto • CpuSme • GPU • Either"]
    F["Acceleration Layer<br/>zkf-metal • zkf-gpu • zkf-crypto-accel<br/>Metal kernels • attestation • GPU abstractions"]
    G["Artifacts And Evidence<br/>proofs • verifiers • calldata • bundles • reports • archive metadata"]
    H["Operator Surfaces<br/>zkf-cli • zkf-api • zkf-python • zkf-ffi • zkf-lsp • zkf-ui • zkf-tui"]
    I["Truth Surfaces<br/>verification-ledger.json • .zkf-completion-status.json • support-matrix.json • docs/CANONICAL_TRUTH.md"]

    A --> B --> C --> D
    D --> E
    E --> F
    D --> G
    F --> G
    B --> H
    C --> H
    D --> H
    B --> I
    C --> I
    D --> I
```

| Layer | Primary surfaces | Responsibility |
| --- | --- | --- |
| Authoring | `zkf-lib`, `zkf-dsl`, `zkf-frontends`, `zkf-frontend-sdk` | Build or import proof programs from native specs and foreign circuit formats |
| Canonical core | `zkf-core`, `zkf-ir-spec` | Define IR, fields, witnesses, artifacts, audits, versioning, and verification-ledger truth |
| Proof systems | `zkf-backends`, `zkf-backends-pro` | Compile/prove/verify across backend families and expose wrapping/export helpers |
| Runtime | `zkf-runtime` | Model proving as a graph, plan execution, propagate trust, and attribute acceleration |
| Hardware lane | `zkf-metal`, `zkf-gpu`, `zkf-crypto-accel` | Provide Apple Silicon execution, host-boundary checks, and accelerator abstractions |
| Distributed and defensive | `zkf-distributed` | Coordinate multi-node proving and swarm-style control surfaces |
| Operator surfaces | `zkf-cli`, `zkf-api`, `zkf-python`, `zkf-ffi`, `zkf-lsp`, `zkf-ui`, `zkf-tui` | Expose proving, verification, debugging, service, and editor-facing workflows |
| Verification and public proof tools | `zkf-verify`, `zkf-metal-public-cli`, `zkf-metal-public-proof-lib` | Narrow verifier-side and public Metal artifact surfaces |
| Examples and conformance | `zkf-examples`, `zkf-conformance`, `zkf-integration-tests` | Provide sample programs, compatibility corpus, and end-to-end regression coverage |

## Full Technology Stack

| Technology family | What is present in this checkout | Primary surfaces |
| --- | --- | --- |
| Circuit authoring | `AppSpecV1`, `BuilderOpV1`, `ProgramBuilder`, Rust DSL macros, template registry | `zkf-lib`, `zkf-dsl` |
| Frontend import | Noir ACIR, Circom R1CS/descriptor, Cairo Sierra/ZIR, Compact ZKIR/source, Halo2 export, Plonky3 AIR export, zkVM descriptors | `zkf-frontends`, `zkf-frontend-sdk` |
| Proof systems | Arkworks Groth16, Halo2 IPA, Halo2 KZG, Plonky3 STARK, Nova, HyperNova, delegated SP1/RISC Zero compatibility, Midnight external/delegated lane, wrapper helpers | `zkf-backends`, `zkf-backends-pro` |
| Curves and fields | BN254, BLS12-381, Pasta Fp/Fq, Goldilocks, BabyBear, Mersenne31 | `zkf-core`, `zkf-gadgets`, `support-matrix.json` |
| Gadgets and circuits | Poseidon, SHA-256, BLAKE3, Merkle, range, comparison, ECDSA, Schnorr, KZG, PLONK gate, boolean logic | `zkf-gadgets` |
| Runtime and scheduling | UMPG graph execution, trust lanes, unified buffer pool, runtime planning, telemetry, package workflows, runtime verification | `zkf-runtime`, `zkf-cli` |
| Hardware acceleration | Apple Silicon, Metal, unified memory, CPU crypto extensions, CPU SME lane, GPU abstraction layer | `zkf-metal`, `zkf-gpu`, `zkf-crypto-accel` |
| Formal methods | Lean 4, Rocq, F*, Verus, Kani, verification ledger, proof-boundary metadata, checked manifests | `zkf-metal/proofs`, `zkf-core/proofs`, `zkf-backends/proofs`, `zkf-ir-spec` |
| Interface stack | Clap CLI, Axum/Tower HTTP service, PyO3/maturin Python package, C FFI/cbindgen, LSP server, Ratatui/Crossterm terminal UI | `zkf-cli`, `zkf-api`, `zkf-python`, `zkf-ffi`, `zkf-lsp`, `zkf-ui`, `zkf-tui` |
| Defensive and distributed systems | Multi-node coordination, swarm identity/reputation/rule lifecycle, supply-chain audit store, benchmark harnesses | `zkf-distributed`, `supply-chain`, `benchmarks` |
| Public proof and showcase surfaces | verifier-only binary, public Metal proof helpers, carbon and rollup apps, standalone builder-spec app, Midnight showcase | `zkf-verify`, `zkf-metal-public-cli`, `tools/zkf-metal-public-proof`, `zkCarbon`, `zk_rollup`, `private_budget_approval`, `uccr-showcase` |

## Proving And Execution Surfaces

### Status Vocabulary

| Term | Meaning in this repo |
| --- | --- |
| `ready` | Shipped and available on the current host according to the live support matrix |
| `limited` | Shipped, but explicitly caveated or restricted |
| `broken` | Checked in, but unconfigured, unavailable, or not compiled into the current host surface |
| `native` | First-party proof implementation in this workspace |
| `delegated` | Compatibility lane that routes through another backend or external validation surface |

### Backends

| Backend | Status | Mode | Fields | Assurance lane | Proof semantics | Current host GPU coverage | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `plonky3` | `ready` | `native` | `goldilocks`, `babybear`, `mersenne31` | `native-cryptographic-proof` | `proof-enforced-lowered-ir` | `2/2 GPU stages active on current host` | Transparent STARK path with native GPU hash/NTT coverage |
| `halo2` | `ready` | `native` | `pasta-fp` | `native-cryptographic-proof` | `proof-enforced-basic-ir` | `1/2 GPU stages active on current host` | Native Halo2 IPA lane |
| `halo2-bls12-381` | `ready` | `native` | `bls12-381` | `native-cryptographic-proof` | `proof-enforced-basic-ir` | `0/2 GPU stages active on current host` | Native Halo2 KZG lane |
| `arkworks-groth16` | `limited` | `native` | `bn254` | `native-cryptographic-proof` | `proof-enforced-basic-ir` | `3/3 GPU stages active on current host` | Support matrix marks it non-production until upstream production disclaimer is resolved |
| `nova` | `ready` | `native` | `bn254` | `native-cryptographic-proof` | `proof-enforced-basic-ir-recursive-shell` | `0/1 GPU stages active on current host` | Native recursive shell |
| `hypernova` | `ready` | `native` | `bn254` | `native-cryptographic-proof` | `proof-enforced-basic-ir-recursive-shell` | `0/1 GPU stages active on current host` | Native multifolding shell |
| `sp1` | `broken` | `delegated` | `goldilocks`, `babybear`, `mersenne31` | `attestation-backed-host-validated-lane` | `attestation-over-host-validation` | `0/0 GPU stages active on current host` | Delegated compatibility lane to `plonky3`; native backend not compiled into this host surface |
| `risc-zero` | `broken` | `delegated` | `goldilocks`, `babybear`, `mersenne31` | `attestation-backed-host-validated-lane` | `attestation-over-host-validation` | `0/0 GPU stages active on current host` | Delegated compatibility lane to `plonky3`; native backend not compiled into this host surface |
| `midnight-compact` | `broken` | `native` | `pasta-fp`, `pasta-fq` | `delegated-or-external-lane` | `external-or-delegated` | `0/0 GPU stages active on current host` | Requires external proof-server configuration or explicit compatibility delegation |

Wrapping and export surfaces: `zkf-backends-pro` carries advanced backend extensions beside the core backend crate, including strict wrapping helpers and specialized integration lanes. In this checkout those are backend extensions, not separate backend rows in `support-matrix.json`.

### Frontends

| Frontend | Status | Input forms | Notes |
| --- | --- | --- | --- |
| `noir` | `ready` | `noir-artifact-json`, `acir-program-json` | Imports ACIR plus native BlackBox metadata and Brillig hint surfaces |
| `circom` | `ready` | `circom-r1cs-json`, `zkf-program-json`, `frontend-descriptor-json` | Supports snarkjs-style import and descriptor-driven witness execution |
| `cairo` | `limited` | `sierra-json`, `cairo-descriptor-json`, `zkf-program-json`, `zkf-zir-program-json` | Supports a shipped Sierra subset; unsupported libfuncs fail closed |
| `compact` | `ready` | `compact-zkir-json`, `compact-descriptor-json`, `zkf-program-json`, `compact-source` | Midnight Compact import path with sidecar discovery |
| `halo2-rust` | `ready` | `zkf-halo2-export-json`, `zkf-halo2-export-descriptor-json` | Direct Halo2 export import |
| `plonky3-air` | `ready` | `zkf-plonky3-air-export-json`, `zkf-plonky3-air-export-descriptor-json` | Direct Plonky3 AIR export import |
| `zkvm` | `ready` | `zkvm-descriptor-json`, `zkf-program-json` | Descriptor-driven external zkVM import and execution hooks |

### Gadgets

| Gadget | Status | Supported fields | Audit status | Notes |
| --- | --- | --- | --- | --- |
| `blake3` | `ready` | `bn254`, `bls12-381`, `pasta-fp`, `pasta-fq`, `goldilocks` | `unaudited` | Hash gadget surface |
| `boolean` | `ready` | all 7 canonical fields | `informally-reviewed` | Boolean constraint helpers |
| `comparison` | `ready` | all 7 canonical fields | `unaudited` | Ordering/comparison helpers |
| `ecdsa` | `limited` | `bn254` | `informally-reviewed` | `secp256k1` and `secp256r1` verification surface |
| `kzg` | `limited` | `bn254`, `bls12-381` | `unaudited` | Pairing-check/KZG surface |
| `merkle` | `ready` | `bn254`, `bls12-381`, `pasta-fp`, `goldilocks`, `babybear`, `mersenne31` | `informally-reviewed` | Merkle inclusion helpers |
| `plonk_gate` | `ready` | all 7 canonical fields | `unaudited` | Generic PLONK gate metadata |
| `poseidon` | `ready` | `bn254`, `bls12-381`, `pasta-fp`, `goldilocks`, `babybear`, `mersenne31` | `informally-reviewed` | Algebraic hash surface |
| `range` | `ready` | all 7 canonical fields | `informally-reviewed` | Range decomposition helpers |
| `schnorr` | `limited` | `bn254` | `unaudited` | Schnorr verification surface |
| `sha256` | `ready` | `bn254`, `bls12-381`, `pasta-fp`, `goldilocks`, `babybear`, `mersenne31` | `informally-reviewed` | SHA-256 gadget surface |

## Core ZirOS Subsystems

### Canonical Core And Proof Systems

| Surface | Purpose |
| --- | --- |
| `zkf-ir-spec` | Holds IR versioning, verification ledger, and proof-boundary support metadata; it is the place that determines what the repo is allowed to claim |
| `zkf-core` | Defines `Program`, `Expr`, `Constraint`, `Signal`, `FieldElement`, witness generation, audits, diagnostics, and proof artifact data structures |
| `zkf-gadgets` | Provides the builtin gadget registry and specification metadata |
| `zkf-frontends` | Imports foreign proof DSLs and artifacts into canonical ZirOS IR |
| `zkf-backends` | Owns backend-specific compile/prove/verify implementations and wrapper/export lanes |
| `zkf-backends-pro` | Packages advanced backend extensions and specialized integration lanes beside the core backend surface |

### Runtime, Hardware, And Distributed Layers

| Surface | Purpose |
| --- | --- |
| `zkf-runtime` | Implements UMPG planning/execution, trust-lane routing, telemetry-backed scheduling, runtime policy, and unified memory management |
| `zkf-metal` | Owns Apple Silicon GPU execution, Metal kernels, attestation data, runtime bindings, and launch contracts |
| `zkf-gpu` | Defines the stable GPU abstraction interfaces used across accelerator lanes |
| `zkf-crypto-accel` | Exposes ARM CPU crypto extensions and Apple Silicon acceleration helpers |
| `zkf-distributed` | Handles multi-node coordination, worker logic, and cluster-aware proving |

### Operator, Extension, And Public Proof Surfaces

| Surface | Purpose |
| --- | --- |
| `zkf-lib` | Embeddable SDK for compile/prove/verify flows, app specs, templates, evidence, and verifier export |
| `zkf-cli` | Operator-facing CLI for proving, importing, auditing, runtime planning, cluster/swarm control, packaging, registry flows, deployment, and diagnostics |
| `zkf-api` | Axum/Tower HTTP proving-as-a-service server with auth, queueing, rate limiting, and health/capabilities endpoints |
| `zkf-python` | Python bindings for compile/prove/verify and helper flows |
| `zkf-ffi` | C-compatible FFI bridge for native embedding |
| `zkf-lsp` | LSP diagnostics, hover, goto-definition, and IR analysis |
| `zkf-ui` | Reusable terminal-rendering helpers for proof flows |
| `zkf-tui` | Standalone TUI shell and widgets built on top of UI helpers |
| `zkf-registry` | Gadget publication, listing, manifests, and dependency resolution |
| `zkf-dsl` | Rust macro surface for embedded circuit authoring |
| `zkf-frontend-sdk` | SDK for extension authors who want to add new frontend plugins |
| `zkf-verify` | Verifier-side library and standalone binary for proof inspection and checking |
| `zkf-metal-public-cli` | Narrow public CLI for Metal proof artifact handling |
| `zkf-metal-public-proof-lib` | Public proof verification helpers for the Metal artifact release lane |
| `zkf-examples` | Canonical sample programs and fixtures used across the workspace |
| `zkf-conformance` | Backend compatibility corpus and conformance checks |
| `zkf-integration-tests` | End-to-end regression coverage for cross-crate behavior |

## Verified Boundary And Trust Model

### Live Truth Surfaces

| Source | Role |
| --- | --- |
| `zkf-ir-spec/verification-ledger.json` | Authoritative proof-claim inventory |
| `.zkf-completion-status.json` | Current completion, assurance-class counts, runtime proof coverage, and checked build/test status |
| `docs/CANONICAL_TRUTH.md` | Explains how to interpret support, trust, and program-family truth |
| `support-matrix.json` | Machine-readable backend/frontend/gadget readiness on the current tree |

### Ledger And Assurance Counts

| Metric | Value |
| --- | --- |
| Total verification-ledger rows | 143 |
| `mechanized_local` rows | 143 |
| `mechanized_generated` rows | 0 |
| `bounded_checked` rows | 0 |
| `assumed_external` rows | 0 |
| Pending rows | 0 |
| `mechanized_implementation_claim` | 115 |
| `attestation_backed_lane` | 3 |
| `model_only_claim` | 16 |
| `hypothesis_carried_theorem` | 9 |
| Runtime/distributed proof coverage | 89 files, 1,788 functions complete |

### Trust Vocabulary

| Term | Meaning here |
| --- | --- |
| `mechanized` | Machine-checked theorem over a shipped implementation or tracked proof boundary |
| `attestation-backed` | Host-validated lane, not an in-circuit cryptographic proof |
| `model-only` | Theorem about a model or boundary summary, not direct end-to-end implementation correctness |
| `hypothesis-carried` | Mechanized theorem that still depends on explicit upstream or cryptographic hypotheses |
| `Cryptographic` | Runtime trust model for in-circuit proof-enforced outputs |
| `Attestation` | Runtime trust model for host-validated outputs |
| `MetadataOnly` | Runtime trust model for non-cryptographic metadata markers |
| `StrictCryptographic` | Required runtime lane when only cryptographic proofs are acceptable |
| `AllowAttestation` | Required runtime lane when host-validated attestations may be admitted |
| `AllowMetadataOnly` | Required runtime lane when metadata-only markers may be admitted |

`zkf-runtime/src/trust.rs` makes the weakening rule explicit: if any dependency has a weaker trust model, the node inherits the weakest.

### The Verified Metal Lane

| Source-backed fact | Current checkout value |
| --- | --- |
| Metal shader source files | 18 |
| Kernel entrypoints found in shipped `.metal` files | 50 |
| Generated GPU program definitions | 60 |
| Checked attestation manifests | 9 |
| Lean files under `zkf-metal/proofs/lean` | 18 |
| Verus files under `zkf-metal/proofs/verus` | 5 |
| Static entrypoint whitelist | `expected_arguments()` in `zkf-metal/src/verified_artifacts.rs` |
| Attestation chain | metallib digest, reflection digest, pipeline-descriptor digest, toolchain identity |

The Metal proof surface is deliberately split:

- `zkf-metal/proofs/lean` proves kernel-family refinement, launch safety, memory-model, and codegen truth for the admitted proof surface.
- `zkf-metal/proofs/verus` proves host-boundary launch-contract properties that are honest to claim today.
- `docs/VERIFIED_METAL_BOUNDARY.md` is the public description of that lane.

The Verus README for the Metal host boundary is explicit about scope: the current Verus lane proves non-empty typed regions, non-zero dispatch geometry, and certified BN254 route exclusions. It does not claim to prove full kernel mathematics for hash, Poseidon2, NTT, or MSM on its own.

## Scientific, Engineering, And Mission Applications

ZirOS is not confined to toy circuits. The `zkf-lib` application surface and adjacent crates expose mission, scientific, privacy, and compliance programs that treat zero-knowledge proving as a certificate layer over structured computation.

| Surface | Primary module or crate | What it certifies |
| --- | --- | --- |
| Private N-body orbital dynamics | `zkf-lib::orbital` | Structured orbital trace commitments and replayable orbital witness/program bundles |
| Satellite conjunction | `zkf-lib::satellite` | Private conjunction and maneuver-plan safety certificates |
| Multi-satellite screening | `zkf-lib::multi_satellite` | Pairwise constellation screening and mission-safety commitments |
| Powered descent | `zkf-lib::descent` | Structured descent-program constraints and witness-safe mission traces |
| Thermochemical equilibrium | `zkf-lib::thermochemical` | Gas-phase equilibrium certificate lanes with attested request/inputs surfaces |
| Real-gas state | `zkf-lib::real_gas` | Cubic equation-of-state certificate lanes over attested reduced coefficients |
| Navier-Stokes structured step | `zkf-lib::navier_stokes` | Structured finite-volume step certificates rather than unrestricted CFD claims |
| Combustion instability / Rayleigh | `zkf-lib::combustion` | Rayleigh-window and coupled low-order modal growth certificates |
| Private identity | `zkf-lib::private_identity` and `credential` CLI flows | Credential issuance, Merkle-path proofs, and privacy-preserving verification reports |
| Finance and voting examples | `financial_loan_qualification.rs`, `private_voting_commitment_pipeline.rs`, `private_identity_service_tier.rs` | Example private-policy, threshold, commitment, and eligibility flows |
| Builder-only app spec example | `private_budget_approval/` | Standalone `AppSpecV1` / `ProgramBuilder` application with prove/verify/export coverage |
| Carbon compliance showcase | `zkCarbon/` | Verifiable carbon-emission reduction proof flow |
| Rollup application experiments | `zk_rollup/` | Rollup-oriented application logic on top of ZirOS primitives |
| Midnight showcase | `uccr-showcase/` | Privacy-preserving compliance showcase for finance, medicine, and engineering on Midnight Network |

Several of these surfaces also emit evidence-oriented bundles through `zkf-lib::evidence`, including generated closure summaries, formal-evidence collection hooks, and verifier/export helpers.

## Operator Entry Paths

### For Cryptographers

- Start with `support-matrix.json`, `zkf-ir-spec/verification-ledger.json`, `.zkf-completion-status.json`, and [`docs/CANONICAL_TRUTH.md`](docs/CANONICAL_TRUTH.md).
- Read `zkf-backends`, `zkf-backends-pro`, and `zkf-verify` for backend and verifier surfaces.
- Read [`docs/VERIFIED_METAL_BOUNDARY.md`](docs/VERIFIED_METAL_BOUNDARY.md) and `zkf-metal/proofs/*` for the GPU lane.

### For Engineers And Programmers

- Start with `zkf-lib`, `ProgramBuilder`, `AppSpecV1`, and `zkf-cli`.
- Use `zkf-api`, `zkf-python`, or `zkf-ffi` if you need embedding instead of shell workflows.
- Use `zkf-examples`, `zkf-conformance`, and `zkf-integration-tests` to see complete end-to-end flows.

### For Scientists, Physicists, Chemists, And Mathematicians

- Start with the `zkf-lib::orbital`, `satellite`, `multi_satellite`, `descent`, `thermochemical`, `real_gas`, `navier_stokes`, and `combustion` modules.
- Treat these as certificate lanes over shipped discrete models, not as claims about unrestricted theory.
- The canonical truth file is explicit about those scope boundaries and is part of the public story.

### For App And Platform Builders

- Start with `zkf-dsl`, `zkf-frontend-sdk`, `zkf-registry`, `zkf-lsp`, `zkf-ui`, and `zkf-tui`.
- Use `zkf-cli app ...`, `package ...`, `runtime ...`, and `registry ...` to scaffold, package, and inspect flows.
- Use `zkf-metal-public-cli` and `zkf-metal-public-proof-lib` when you need a narrower public proof surface than the full workspace.

## Performance, Hardware, And Storage

### Apple Silicon And Execution Planning

| Runtime fact | Current checkout evidence |
| --- | --- |
| Hardware profiles | `M1`, `M2`, `M3`, `M4`, `A17Pro`, `A18`, `A18Pro`, `VisionPro`, `CpuOnly` in `zkf-runtime/src/trust.rs` |
| Device placements | `Cpu`, `Gpu`, `CpuCrypto`, `CpuSme`, `Either` in `zkf-runtime/src/graph.rs` |
| GPU-capable stage keys | `ntt`, `lde`, `msm`, `poseidon-batch`, `sha256-batch`, `merkle-layer`, `fri-fold`, `fri-query-open` |
| Unified memory classes | `HotResident`, `EphemeralScratch`, `Spillable` in `zkf-runtime/src/memory.rs` |
| Neural Engine role | advisory control plane only; proof validity does not depend on model output |

### Neural Engine Control Plane

The repo ships a Neural Engine control-plane story through runtime and documentation surfaces:

- retraining and telemetry commands in `zkf-cli`
- model-operations docs in [`docs/NEURAL_ENGINE_OPERATIONS.md`](docs/NEURAL_ENGINE_OPERATIONS.md)
- explicit canonical-truth language that model output is advisory, not proof-validity truth

### Post-Quantum Cryptographic Surfaces

ZirOS ships NIST-standardized post-quantum cryptography across the proving, identity, and communication layers.

| Surface | Algorithm | Standard | Security Level | Status |
| --- | --- | --- | --- | --- |
| STARK proofs (Plonky3) | FRI + hash-based Merkle commitment | Information-theoretic | Post-quantum (no elliptic curves) | `ready` |
| Swarm peer identity | ML-DSA-87 (hybrid with Ed25519) | NIST FIPS 204 | Level 5 (AES-256 equivalent) | `ready` |
| Credential issuance | ML-DSA-87 signature bundles | NIST FIPS 204 | Level 5 | `ready` |
| Proof-origin attestation | ML-DSA-87 on proof artifacts | NIST FIPS 204 | Level 5 | `ready` |
| Epoch key exchange | ML-KEM-1024 (hybrid with X25519) | NIST FIPS 203 | Level 5 | `ready` |
| Gossip encryption | ChaCha20-Poly1305 (256-bit symmetric) | — | Post-quantum (symmetric) | `ready` |
| Key derivation | HKDF-SHA384 | CNSA 2.0 compliant | Post-quantum | `ready` |
| Credential KDF | Argon2id + SHA-256 | — | Post-quantum (symmetric) | `ready` |

CNSA 2.0 alignment: ML-DSA-87 for digital signatures, ML-KEM-1024 for key establishment, SHA-384 for key derivation, and ChaCha20-Poly1305 (AES-256 equivalent) for authenticated encryption. The Plonky3 STARK backend provides post-quantum proofs without trusted setup; Groth16, Halo2, and Nova backends remain classical (elliptic-curve-based) and are explicitly labeled as such.

The hybrid identity scheme (`HybridEd25519MlDsa87`) requires both Ed25519 and ML-DSA-87 signatures to verify. If either algorithm is broken, the other provides continued security. The hybrid key exchange combines X25519 and ML-KEM-1024 shared secrets through HKDF-SHA384; compromising one algorithm does not compromise the derived key.

Implementation surface: `libcrux-ml-dsa` v0.0.8 for ML-DSA-87, `libcrux-ml-kem` v0.0.8 for ML-KEM-1024, `chacha20poly1305` for AEAD, `hkdf` with SHA-384 for key derivation. Private keys are stored in iCloud Keychain on macOS (Secure Enclave protected, synced with Advanced Data Protection) or in file-based storage with restricted permissions on other platforms.

Post-quantum backend classification:

| Backend | Post-Quantum | Basis |
| --- | --- | --- |
| `plonky3` | Yes | FRI polynomial commitment is hash-based; no number-theoretic assumptions |
| `arkworks-groth16` | No | BN254 elliptic curve pairings; vulnerable to Shor's algorithm |
| `halo2` | No | Pasta curve IPA; vulnerable to Shor's algorithm |
| `halo2-bls12-381` | No | BLS12-381 KZG; vulnerable to Shor's algorithm |
| `nova` / `hypernova` | No | Pallas/Vesta curves; vulnerable to Shor's algorithm |
| STARK-to-SNARK wrapping | Outer: No | Inner STARK is post-quantum; outer Groth16 wrapper is classical |

For end-to-end post-quantum proof generation, use `--backend plonky3` without wrapping.

### iCloud-Native Storage Architecture

ZirOS implements iCloud Drive as the persistent storage layer and iCloud Keychain as the key management layer. The local SSD operates as a transparent cache. Artifacts are written directly to iCloud on creation; macOS handles upload, sync, cross-device availability, and automatic local eviction under storage pressure.

Persistent state directory: `~/Library/Mobile Documents/com~apple~CloudDocs/ZirOS/`

| Directory | Contents | Access pattern |
| --- | --- | --- |
| `proofs/{app}/{timestamp}/` | Proof artifacts organized by application and proving timestamp | Write on prove, read on verify/inspect |
| `traces/{app}/{timestamp}/` | UMPG execution telemetry, GPU attribution, security verdicts | Write on prove |
| `verifiers/{app}/{timestamp}/` | Solidity verification contracts | Write on export |
| `reports/{app}/{timestamp}/` | Mission assurance and proving reports | Write on export |
| `audits/{app}/{timestamp}/` | Circuit security audit results | Write on audit |
| `telemetry/` | Neural Engine training records | Write per job, read on retrain |
| `swarm/` | Threat patterns, detection rules, reputation logs, entrypoint observations, attestation chains | Read/write per job |

Key management: persistent private keys (Ed25519, ML-DSA-87, proving keys, credential keys) are stored in iCloud Keychain with `kSecAttrSynchronizable = true` and Secure Enclave protection on each device. Keys sync across Apple devices signed into the same Apple ID with Advanced Data Protection enabled. Ephemeral keys (X25519, ML-KEM-1024 epoch keys) remain in-process memory only and are never persisted.

Witness handling: witnesses contain every private input to a circuit in plaintext. They are generated in the local cache (`~/.zkf/cache/`), used for proving, and deleted immediately after proof verification. Witnesses are never written to iCloud. This is the enforcement mechanism that preserves the zero-knowledge property on the storage layer.

Local cache: `~/.zkf/cache/` holds ephemeral computation artifacts (witnesses during proving, build intermediates, active proving keys pulled from iCloud for a session). The cache is expendable; its contents can be rebuilt from iCloud or regenerated from source.

Device-adaptive profiles:

| Profile | SSD capacity | Warning threshold | Critical threshold | Monitor interval |
| --- | --- | --- | --- | --- |
| Constrained | up to 300 GB | 30 GB | 15 GB | 30 minutes |
| Standard | 301 to 600 GB | 50 GB | 25 GB | 1 hour |
| Comfortable | 601 GB to 1.2 TB | 100 GB | 50 GB | 1 hour |
| Generous | above 1.2 TB | 200 GB | 100 GB | daily |

Cross-device operation: install ZirOS on any Mac, sign in with the same Apple ID, and all keys, proofs, telemetry, models, and swarm state are immediately available. No manual file transfer, no USB drives, no configuration beyond `ziros doctor`.

Storage and key commands:

```bash
ziros storage status --json    # iCloud sync state, local cache usage, key inventory
ziros storage evict            # Release locally cached iCloud files to free SSD space
ziros storage warm             # Pre-fetch frequently used files into local cache
ziros storage install          # Install the hourly macOS launchd cache-management agent
ziros keys list --json         # Enumerate all keys across Keychain and file backends
ziros keys audit --json        # Report key age, rotation status, sync health, permissions
ziros keys rotate <id>         # Generate new key material and retire the previous key
```

On non-macOS platforms, the iCloud layer falls back to local file storage at `~/.zkf/` with the same directory structure and access patterns.

### Checked Build And Test Truth

`.zkf-completion-status.json` records the current checked build/test posture for this tree:

- build truth dated March 25, 2026 includes `cargo build --workspace`
- test truth dated March 25, 2026 includes `cargo test -p zkf-lib --lib`, `cargo test -p zkf-core --lib`, `cargo test -p zkf-backends --lib`, and selected `zkf-integration-tests` showcase flows

## Quick Start

### Prebuilt Binary (any Mac, recommended)

```bash
curl -fsSL https://github.com/AnubisQuantumCipher/ziros/releases/download/v0.3.0/zkf-aarch64-apple-darwin.tar.gz | tar xz
sudo mv zkf-aarch64-apple-darwin /usr/local/bin/zkf
zkf doctor --json
zkf storage install
```

### Source Build

```bash
git clone https://github.com/AnubisQuantumCipher/ziros.git
cd ziros
./install.sh
export PATH="$HOME/.local/bin:$PATH"
ziros doctor
ziros capabilities
```

`install.sh` builds `zkf-cli`, installs it to `~/.local/bin`, and also writes a `ziros` wrapper alongside it.

### Inspect What The Current Binary Claims

```bash
ziros capabilities
ziros support-matrix
ziros frontends --json
ziros doctor --json
ziros metal-doctor --json
```

### Scaffold, Audit, Compile, Prove, Verify

```bash
ziros app templates
ziros audit --program docs/examples/fixtures/epa/zirapp.json --backend arkworks-groth16 --json
ziros compile --spec docs/examples/fixtures/epa/zirapp.json --backend arkworks-groth16 --out /tmp/epa.compiled.json --allow-dev-deterministic-groth16
ziros prove --program docs/examples/fixtures/epa/zirapp.json --inputs docs/examples/fixtures/epa/inputs.compliant.json --backend arkworks-groth16 --out /tmp/epa.proof.json --allow-dev-deterministic-groth16
ziros verify --program docs/examples/fixtures/epa/zirapp.json --artifact /tmp/epa.proof.json --backend arkworks-groth16 --allow-dev-deterministic-groth16
```

### Service And Verifier Surfaces

```bash
cargo run -p zkf-api
ziros deploy --artifact /tmp/epa.proof.json --backend arkworks-groth16 --out /tmp/EpaVerifier.sol
cargo run -p zkf-verify -- --help
```

## Documentation And Truth Surfaces

| Document | Role |
| --- | --- |
| [`CONSTITUTION.md`](CONSTITUTION.md) | Binding philosophy and claim discipline |
| [`PROOF_BOUNDARY.md`](PROOF_BOUNDARY.md) | Proof-boundary baseline |
| [`docs/CANONICAL_TRUTH.md`](docs/CANONICAL_TRUTH.md) | How to interpret truth, trust lanes, and live support |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Higher-level system architecture |
| [`docs/BACKENDS.md`](docs/BACKENDS.md) | Backend comparison and operator guidance |
| [`docs/NONLINEAR_ANCHORING.md`](docs/NONLINEAR_ANCHORING.md) | Fail-closed audit model |
| [`docs/VERIFIED_METAL_BOUNDARY.md`](docs/VERIFIED_METAL_BOUNDARY.md) | Public description of the attested Metal proof lane |
| [`docs/WRAPPING_SECURITY.md`](docs/WRAPPING_SECURITY.md) | Wrapping trust model and security posture |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Security model and TCB discussion |
| [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) | End-to-end starter flow |
| [`docs/APP_DEVELOPER_GUIDE.md`](docs/APP_DEVELOPER_GUIDE.md) | App-builder guidance |
| [`docs/CLI.md`](docs/CLI.md) and [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) | CLI surfaces and command reference |
| [`docs/NEURAL_ENGINE_OPERATIONS.md`](docs/NEURAL_ENGINE_OPERATIONS.md) | Model/telemetry/control-plane operations |

## Workspace And Technology Catalog

### Workspace Crates

| Package | Path | Purpose |
| --- | --- | --- |
| `zkf-api` | `zkf-api/` | Proving-as-a-service HTTP API with auth, queueing, metering, deploy, benchmark, and health/capabilities routes |
| `zkf-backends` | `zkf-backends/` | Native compile/prove/verify implementations and backend capability routing |
| `zkf-backends-pro` | `zkf-backends-pro/` | Advanced backend extensions, wrapping helpers, and specialized integration lanes |
| `zkf-cli` | `zkf-cli/` | Operator CLI for proving, importing, auditing, runtime, packaging, registry, swarm, and diagnostics |
| `zkf-conformance` | `zkf-conformance/` | Backend compatibility corpus behind `ziros conformance` |
| `zkf-core` | `zkf-core/` | Canonical IR, fields, witness generation, audits, and proof artifact structures |
| `zkf-crypto-accel` | `zkf-crypto-accel/` | ARM CPU crypto-extension and Apple Silicon acceleration helpers |
| `zkf-distributed` | `zkf-distributed/` | Multi-node proving coordination and cluster worker logic |
| `zkf-dsl` | `zkf-dsl/` | Rust macro surface for embedded circuit authoring |
| `zkf-examples` | `zkf-examples/` | Canonical sample programs and reusable fixtures |
| `zkf-ffi` | `zkf-ffi/` | C-compatible native embedding bridge |
| `zkf-frontend-sdk` | `zkf-frontend-sdk/` | SDK for writing additional frontend plugins |
| `zkf-frontends` | `zkf-frontends/` | Importers from Noir, Circom, Cairo, Compact, Halo2 export, Plonky3 AIR, and zkVM descriptors |
| `zkf-gadgets` | `zkf-gadgets/` | Builtin gadget registry and metadata catalog |
| `zkf-gpu` | `zkf-gpu/` | Stable GPU abstraction interfaces |
| `zkf-integration-tests` | `zkf-integration-tests/` | End-to-end cross-crate regression coverage |
| `zkf-ir-spec` | `zkf-ir-spec/` | Formal IR specification and verification-ledger support surfaces |
| `zkf-lib` | `zkf-lib/` | Embeddable SDK for compile/prove/verify, templates, evidence, and export |
| `zkf-lsp` | `zkf-lsp/` | Language Server Protocol support for ZirOS IR |
| `zkf-metal` | `zkf-metal/` | Apple Silicon Metal execution crate with attestation and launch contracts |
| `zkf-metal-public-cli` | `zkf-metal-public-cli/` | Narrow public CLI for Metal proof artifact handling |
| `zkf-metal-public-proof-lib` | `tools/zkf-metal-public-proof/lib/` | Public proof verification helpers for the Metal artifact release lane |
| `zkf-python` | `zkf-python/` | Python bindings for ZirOS |
| `zkf-registry` | `zkf-registry/` | Gadget publication, manifests, listing, and dependency resolution |
| `zkf-runtime` | `zkf-runtime/` | UMPG planning/execution, trust lanes, telemetry, and runtime policy |
| `zkf-tui` | `zkf-tui/` | Standalone TUI shell and widgets for proof-driven apps |
| `zkf-ui` | `zkf-ui/` | Reusable terminal presentation helpers |
| `zkf-verify` | `zkf-verify/` | Verifier-side library and standalone verification binary |
| `zk_carbon` | `zkCarbon/` | Carbon-emission reduction proof showcase crate |
| `zk_rollup` | `zk_rollup/` | Rollup-oriented proving experiments built on ZirOS primitives |

### Notable First-Party Adjuncts

| Surface | Path | Role |
| --- | --- | --- |
| Builder-only app-spec app | `private_budget_approval/` | Standalone `AppSpecV1` / builder-only proof app with prove/verify/export coverage |
| Midnight compliance showcase | `uccr-showcase/` | TypeScript/Midnight Network showcase for finance, clinical, and engineering compliance proofs |
| Benchmark harness | `benchmarks/` | Competition manifest and runners for `snarkjs`, `gnark`, `Noir/Nargo`, `SP1`, `RISC Zero`, and external `Plonky3` across three scenarios |
| Supply-chain boundary | `supply-chain/` | `cargo vet` trust store for audited cryptographic dependencies |
| Public Metal proof toolchain | `tools/zkf-metal-public-proof/` | Narrow public proof-program/script surfaces around the Metal artifact lane |


## Standalone Subsystems

ZirOS produces standalone subsystems — complete applications that run independently without the ZirOS source code. Each subsystem ships with `install.sh` that downloads the 26 MB `zkf` binary, giving it the full ZirOS proving engine: all 9 backends, all 7 frontends, all 11 gadgets, Metal GPU, iCloud storage, swarm defense, Neural Engine, credential system, and distributed proving.

**Any Mac with Apple Silicon can run any subsystem. No Rust toolchain needed. No compilation. Just `./install.sh`.**

### Deployed Subsystems

| Subsystem | What It Proves | Repo |
|-----------|---------------|------|
| **Sovereign Economic Defense** | Cooperative treasury, land trust, predatory lending, portfolio, 96-step sovereignty | [ziros-sovereign-economic-defense](https://github.com/AnubisQuantumCipher/ziros-sovereign-economic-defense) |
| **Falcon Heavy Flight Certification** | 27 engines, 187-step ascent, 3x300-step recovery, orbital, engine-out, fairing | [ziros-falcon-heavy-flight-certification](https://github.com/AnubisQuantumCipher/ziros-falcon-heavy-flight-certification) |
| **Reentry Thermal Envelope** | RLV reentry mission assurance | [ziros-reentry-thermal-envelope-flagship](https://github.com/AnubisQuantumCipher/ziros-reentry-thermal-envelope-flagship) |
| **RPOD Verifier** | Powered descent + docking corridor | [rpod-verifier](https://github.com/AnubisQuantumCipher/rpod-verifier) |
| **Mixture Lock** | Propellant formulation O/F bounds | [mixture-lock](https://github.com/AnubisQuantumCipher/mixture-lock) |
| **Conjunction Proof** | Satellite conjunction risk | [conjunction-proof](https://github.com/AnubisQuantumCipher/conjunction-proof) |
| **Burn Budget** | Multi-phase fuel budget | [burn-budget](https://github.com/AnubisQuantumCipher/burn-budget) |
| **Metal Provers** | 51 Lean 4 GPU kernel theorems | [metal-provers](https://github.com/AnubisQuantumCipher/metal-provers) |
| **Bubble Proof** | Sonoluminescence simulation | [bubble-proof](https://github.com/AnubisQuantumCipher/bubble-proof) |
| **Aerospace Qualification Exchange** | Component thermal, vibration/shock, firmware provenance, lot genealogy, test campaign, flight readiness | [ziros-aerospace-qualification](https://github.com/AnubisQuantumCipher/ziros-aerospace-qualification) |
| **EDL Monte Carlo Mission-Risk Exchange** | 500-step trajectory, 48K constraints, Monte Carlo risk, Midnight selective disclosure | [ziros-midnight-edl-monte-carlo-exchange](https://github.com/AnubisQuantumCipher/ziros-midnight-edl-monte-carlo-exchange) |

---

## Distributed Proving And Cluster Scaling

Every subsystem scales by stacking Macs. The `zkf` binary includes a full distributed proving cluster:

```bash
# Start nodes
zkf cluster start        # on each Mac
zkf cluster status --json # see peers
zkf cluster benchmark    # test throughput
```

Nodes discover each other over TCP. The coordinator distributes proving jobs across workers. Swarm defense monitors every node — compromised nodes are quarantined without affecting proof correctness.

---

## Midnight Network Integration

ZirOS has a fully operational [Midnight Network](https://midnight.network/) frontend for privacy-preserving on-chain deployment:

```bash
zkf import --frontend compact --in contract.zkir --out program.json
zkf prove --program program.json --inputs inputs.json --out proof.json
```

Compact ZKIR v2.0 import, BLS12-381 field, Halo2-KZG backend, selective disclosure via `disclose()`. The Sovereign Economic Defense subsystem ships 5 Compact contracts with regulatory compliance policies.

---
## License

See `LICENSE-BSL` and the crate metadata for the current repository licensing posture.
