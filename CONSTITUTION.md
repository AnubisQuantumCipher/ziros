
# THE CONSTITUTION OF ZirOS

### A System Manifesto on Trust, Verification, and the Refusal to Bluff

-----

## PREAMBLE

This document is the governing philosophy of ZirOS and all systems derived from it, including zkf-metal. It is not a marketing statement. It is not aspirational language pasted over unfinished work. It is a binding contract between this system and anyone who encounters it: every claim will be mechanically checkable, every boundary will be enforced before execution, and every surface that asks for trust will provide evidence instead.

We hold that the prevailing model of trust in cryptographic systems — paid auditors reviewing code, writing reports, and issuing opinions for six-figure fees — is structurally inadequate. Auditors are humans. Humans miss things. Humans have time constraints, cognitive biases, financial incentives, and reputational conflicts. An audit report is a snapshot of one group’s understanding at one moment in time. It degrades silently. It cannot be re-executed. It does not grow with the codebase. It is, at best, an informed opinion. We do not build systems that rest on opinions.

We chose a different foundation. We build systems that rest on theorems.

-----

## ARTICLE I — THE FIRST PRINCIPLE

**We do not use auditors. We use 100% mechanized formal verification to remove all doubt.**

Every Metal kernel in this system has a corresponding Lean 4 theorem proving that the GPU program refines its mathematical specification. Every dispatch is gated by a pinned attestation chain: metallib SHA256, reflection SHA256, pipeline descriptor SHA256, and toolchain identity. If any link in the chain is tampered with, broken, or drifted, the dispatch is rejected before a single GPU thread executes.

The root of trust is mathematics, not reputation.

This is not a preference. It is a constitutional commitment. No component of ZirOS may claim correctness on the basis of manual review alone. No surface may be described as verified unless a mechanized proof artifact exists and can be re-executed independently. No kernel may dispatch to GPU hardware without passing through the attestation gate. There are no exceptions, no expedient overrides, and no “we’ll add proofs later” deferrals that survive into a release.

-----

## ARTICLE II — THE ATTESTATION CHAIN

### Section 1 — Fail-Closed Dispatch

Every GPU kernel dispatch passes through a deterministic verification pipeline before execution. This pipeline is fail-closed: if any check does not pass, the dispatch is rejected. There is no silent fallback to CPU. There is no degraded mode that bypasses verification. There is no runtime flag that disables the gate. Rejection is the only response to a broken chain.

### Section 2 — The Four Digests

Each kernel entrypoint is attested by four cryptographic digests computed at build time and verified at dispatch time.

The **metallib digest** is the SHA256 of the compiled Metal library binary. It pins the exact GPU code that will execute. If the binary has been recompiled, tampered with, or substituted, this digest will not match and the dispatch will be rejected.

The **reflection digest** is the SHA256 of the kernel’s argument signature — the names, indices, types, and access modes of every buffer and threadgroup memory binding. It is computed from a canonical materialization of the expected argument shape. If the runtime Metal pipeline exposes a different argument signature than what was attested at build time, the dispatch will be rejected.

The **pipeline descriptor digest** is the SHA256 of the compute pipeline configuration — its label, indirect command buffer support flag, maximum threads per threadgroup, and threadgroup-multiple-of-execution-width flag. If the pipeline was created with different configuration than what was attested, the dispatch will be rejected.

The **toolchain identity** records the exact Metal compiler version, Xcode version, and SDK version used to produce the attested metallib. If the build environment drifts — a compiler update, an SDK change, a toolchain migration — the identity will no longer match and the system will know that re-attestation is required.

### Section 3 — Source Pinning

Beyond the four runtime digests, every attestation manifest pins the SHA256 of every source file — both Metal shader sources and Rust host-dispatch sources — that contributed to the kernel. This creates a verifiable chain from human-readable source code to compiled binary to runtime execution. Anyone can recompute the source digests, rebuild the metallib, and verify that the binary matches the attested value.

### Section 4 — The Whitelist

Only kernel entrypoints that appear in the `expected_arguments` whitelist inside `verified_artifacts.rs` are dispatchable. The whitelist is exhaustive and static. It is not populated at runtime. It is not configurable by the user. It is not extensible without a code change that triggers re-attestation. An entrypoint that does not appear in the whitelist cannot be dispatched through the verified path, regardless of whether a valid pipeline exists for it.

-----

## ARTICLE III — LAUNCH CONTRACTS

### Section 1 — Purpose

Launch contracts are pure-Rust boundary checks that validate every parameter of a GPU dispatch before it reaches the Metal API. They exist because attestation alone is not sufficient. A correctly attested kernel can still be dispatched with invalid parameters — zero-length buffers, misaligned memory, undersized scratch regions, uncertified route classes. Launch contracts close that gap.

### Section 2 — Contract Families

Each kernel family has a dedicated contract function that validates the specific invariants of that family.

The **hash contract** validates that the batch count is nonzero, the input length is nonzero, the input buffer size equals batch count multiplied by input length, and the output buffer size equals batch count multiplied by 32 bytes (the digest size). A dispatch that violates any of these is rejected.

The **Poseidon2 contract** validates that the state element count is nonzero and a multiple of 16 (the permutation width), that round constants are provided, that both external and internal round counts are nonzero, and that zero-copy mode is only permitted on page-aligned buffers. A dispatch that violates any of these is rejected.

The **NTT contract** validates that the transform height is at least 2 and a power of two, that the width is nonzero, and that the twiddle buffer contains at least as many elements as the height. A dispatch that violates any of these is rejected.

The **MSM contract** validates that the point count is nonzero, that the bucket map covers point count multiplied by num windows entries, that bucket storage covers total buckets multiplied by 12 projective limbs, and that certified BN254 routes are restricted to the Classic Pippenger path. Hybrid, full-GPU, and tensor routes are excluded from the certified surface for BN254. A dispatch that requests a certified route outside this whitelist is rejected.

### Section 3 — No Success Without Validation

Every contract function returns `Result<ValidatedDispatch, LaunchContractError>`. There is no code path that produces a `ValidatedDispatch` without passing through the full validation logic. The `ValidatedDispatch` struct is the only type accepted by the downstream dispatch machinery. Constructing it outside the contract function is not possible through public API.

### Section 4 — Pure Rust, No Objective-C

Launch contracts are written in pure Rust and intentionally avoid touching the Objective-C Metal bindings. This keeps them available to proof harnesses (Kani, Verus), to the proof IR, and to host dispatch code as a single source of truth. The contract logic is the same whether it is executed during a Kani harness, a unit test, or a live GPU dispatch.

-----

## ARTICLE IV — MECHANIZED PROOFS

### Section 1 — What We Mean by “Proven”

When this system states that a kernel is proven, it means a Lean 4 theorem exists that establishes a refinement relationship between the GPU program and a mathematical specification. The theorem is machine-checked. It can be re-executed by anyone with a Lean 4 installation. It does not depend on the reader’s trust in the author. It closes or it does not. Mathematics does not negotiate.

### Section 2 — Kernel Refinement

Each GPU kernel program is modeled as a `Program` that operates on a `SymbolEnv`. The Lean proof establishes that the program refines a `KernelSpec` — a mathematical description of the kernel’s intended behavior. For MSM, the specification is Pippenger multi-scalar multiplication. For NTT, the specification is the radix-2 decimation-in-time number theoretic transform. For Poseidon2, the specification is the width-16 permutation with M4 circulant MDS and x^7 S-box.

Refinement means: for every valid input state, the program produces an output state that satisfies the specification. If the program deviates from the specification on any input, the theorem will not close in Lean.

### Section 3 — Pipeline Soundness

Beyond individual kernel refinement, the proof surface covers multi-kernel pipeline chains. The MSM pipeline is a four-stage chain — bucket assignment, bucket accumulation, bucket reduction, window combination — and the Lean proof (`msm_family_exact_pippenger_sound`) establishes that the full chain correctly implements Pippenger semantics for all three supported curves (BN254, Pallas, Vesta) and all certified route variants (Classic, NAF).

The NTT pipeline covers single-butterfly, batch-butterfly, small-threadgroup, and hybrid-global variants across three fields (Goldilocks, BabyBear, BN254 scalar), with the Lean proof (`ntt_family_exact_transform_sound`) establishing transform correctness for every combination.

The Poseidon2 proof (`poseidon2_family_exact_permutation_sound`) establishes that scalar and SIMD-cooperative kernel variants produce identical permutation outputs, and that both refine the reference Poseidon2 specification.

### Section 4 — Launch Safety

The `gpu_launch_contract_sound` theorem in `LaunchSafety.lean` proves that any dispatch passing structural memory soundness checks guarantees four properties: all memory regions are bounded, all write regions are non-overlapping, all barriers are balanced, and no out-of-bounds read or write can occur. This theorem is the formal backbone of the fail-closed dispatch model.

### Section 5 — Proofs Are Living Infrastructure

Proof files are not sacred relics. They are maintained code. When a toolchain updates, proofs are adapted. When a kernel changes, the theorem is updated and re-checked. When a syntax drifts, the proof is repaired. The commitment is not to the permanence of any particular file, but to the permanent enforceability of the mechanized guarantee. A proof that does not compile is not a proof. A proof that compiles against a stale specification is not a proof. Only a proof that compiles against the current source and the current toolchain counts.

### Section 6 — The Trusted Computing Base

The trusted computing base of this system is explicitly and exhaustively stated: Lean 4 (the theorem prover), the Apple Metal compiler (shader compilation), the Apple Metal driver and runtime (GPU dispatch), and the Apple GPU hardware (execution). We trust these components because we must — they are below the level at which our verification operates. We do not trust auditors, reputation, governance committees, or social consensus. We trust the TCB and we prove everything above it.

-----

## ARTICLE V — THE TRUSTED COMPUTING BASE OATH

We will never describe a surface as verified without a mechanized proof artifact.

We will never describe a dispatch as safe without a launch contract that has been exercised by negative tests — tests that prove tampering, misalignment, and invalid parameters are correctly rejected.

We will never ship a kernel without a pinned attestation chain that can be independently verified by anyone who can compute a SHA256 digest.

We will never add an override, flag, or environment variable that bypasses the attestation gate or the launch contracts in a release build.

We will never allow the story told by documentation, marketing, or public statements to exceed the story told by the proof artifacts. If the proofs do not cover a claim, the claim will not be made.

We will never substitute a passing test suite for a mechanized theorem. Tests demonstrate the absence of observed bugs. Theorems demonstrate the absence of possible bugs within the proven model. These are categorically different things and we will not conflate them.

We will never describe GPU acceleration as “real” unless the runtime telemetry, the attestation chain, and the formal proofs all agree that the GPU participated in the computation. Marketing claims will not outrun engineering evidence.

-----

## ARTICLE VI — ON AUDITORS

We do not hold animosity toward individual auditors. Many are skilled, honest, and diligent. The problem is structural, not personal.

An audit is a human reading code and writing an opinion. That opinion has a shelf life. It does not update when the code changes. It does not re-execute when the compiler updates. It does not detect regressions that occur after the engagement ends. It is a document produced under time pressure, billing constraints, and the inherent limitations of human attention. An audit that finds zero issues is not proof of zero issues. It is proof that one group of humans, in the time allotted, under the conditions of their engagement, did not find issues. The distinction matters.

A mechanized proof has no shelf life as long as it compiles. It re-executes in seconds. It detects any change to the proven surface because the theorem will no longer close. It is not subject to billing constraints or time pressure. It does not depend on the reader’s trust in the prover’s competence, because the reader can run the proof themselves.

We chose mechanized proofs because they are categorically stronger. We will maintain this position until someone demonstrates a category of correctness guarantee that auditors provide and theorem provers do not. That demonstration has not yet occurred.

-----

## ARTICLE VII — ON SEMANTICS

### Section 1 — Naming Discipline

Fields, digests, identifiers, and labels in this system mean exactly one thing. A `program_digest` is the SHA256 of the compiled program artifact. It is not sometimes the source digest. A `metallib_sha256` is the digest of the compiled Metal library binary. It is not sometimes the digest of the source files that produced it. A `certified_route` is a dispatch route that has been formally proven correct for a given curve. It is not sometimes a suggestion.

When a vocabulary term begins to mean two things depending on context, the system is becoming dishonest. This constitution treats vocabulary collapse as a defect of the same severity as a soundness bug, because vocabulary collapse in verification systems leads to soundness bugs.

### Section 2 — Trust Lanes

Trust is not a boolean. A system is not simply “trusted” or “untrusted.” Trust has lanes. A dispatch with a deterministic development setup has a different trust profile than a dispatch with a production trusted setup. Both may be valid. Neither should be described as the other. The system must name its trust lane explicitly in every artifact, every export, and every report.

### Section 3 — Artifact Honesty

An exported artifact — a proof bundle, a Solidity verifier, a Foundry test project, a desktop bundle — is the system’s ambassador to the outside world. It will be judged in isolation by people who have not read the repository. It must carry enough of the system’s truth to survive that judgment. If a reviewer opens a bundle and concludes that formal evidence is absent because the bundle does not contain it, the correct response is not to argue with the reviewer. The correct response is to put the evidence in the bundle.

-----

## ARTICLE VIII — ON HARDWARE

### Section 1 — The Machine Is Not Incidental

ZirOS is designed for Apple Silicon. This is not a compatibility constraint. It is an architectural commitment. The unified memory model, the GPU core count, the Metal API, the native uint64 support, the threadgroup shared memory, the SIMD lane width — these are not features we tolerate. They are features we design for.

### Section 2 — Honest Acceleration

When this system claims GPU acceleration, the claim is backed by the attestation chain, the launch contracts, and the runtime telemetry. The GPU was not merely available. It was dispatched, it executed attested kernels, and the results were consumed by the proving pipeline. If the telemetry does not support the claim, the claim will not be made.

### Section 3 — Discipline Over Excess

A powerful machine invites misuse. Unified memory invites careless allocation. Many CPU cores invite vanity parallelism. A large SSD invites undisciplined accumulation. This system treats hardware discipline as part of correctness. Serialized heavyweight proving lanes, intentional memory management, and architecture-aware scheduling are not optimizations. They are requirements.

-----

## ARTICLE IX — ON OPENNESS

### Section 1 — What We Release

When we release a component publicly, we release it with its proofs, its attestation manifests, its launch contracts, and its evidence. We do not release code without the verification surface that makes the code trustworthy. A shader without its Lean theorem is an assertion. A shader with its Lean theorem is a proof. We release proofs.

### Section 2 — What We Protect

The full ZirOS system — its runtime, its backends, its swarm defense, its builder, its agentic pipeline, its formal verification ledger — is proprietary infrastructure that represents years of architectural work. Releasing the GPU core does not obligate us to release the system that drives it. The shaders are the engine block. ZirOS is the car. We give the world the engine block and keep the car.

### Section 3 — Verification Is Not a Gate to Entry

Anyone can verify our claims. Clone the repository. Install Lean 4. Run the proofs. Recompute the SHA256 digests. Read the launch contracts. Execute the negative tests. The verification surface is public because verification must be public. Trust that cannot be independently verified is not trust. It is faith. We do not ask for faith.

-----

## ARTICLE X — AMENDMENT

This constitution may be amended only by adding stronger guarantees. No amendment may weaken the attestation chain, remove the fail-closed dispatch model, introduce silent fallback paths, substitute audit reports for mechanized proofs, or allow any claim to exist without a corresponding verifiable artifact.

The direction of change is always toward more evidence, never toward less. Toward harder boundaries, never softer. Toward more checkable truth, never more comfortable ambiguity.

-----

## RATIFICATION

This constitution is ratified by the existence of the proof artifacts, the attestation manifests, the launch contracts, and the evidence pack in the zkf-metal repository. It is not ratified by signature or ceremony. It is ratified by the fact that the system already behaves according to these principles, and that anyone can verify that it does.

The truth cannot be ignored when it comes with a mechanized proof.

-----

*Authored by Sicarii. Solo architect. The laptop never stops.*

*github.com/AnubisQuantumCipher*
