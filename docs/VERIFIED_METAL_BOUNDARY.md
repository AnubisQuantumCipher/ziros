# Verified Metal Boundary

This document is the authoritative current technical companion to [`CONSTITUTION.md`](../CONSTITUTION.md). [`CONSTITUTION.md`](../CONSTITUTION.md) states ZirOS philosophy in maximal language; this file records the narrower, source-backed claim surface defended by the current checkout, the current proof inventory, the current runtime enforcement code, and the live command output gathered in this session on March 26, 2026. When prose diverges from source, the authoritative order is [`zkf-ir-spec/verification-ledger.json`](../zkf-ir-spec/verification-ledger.json), [`.zkf-completion-status.json`](../.zkf-completion-status.json), [`docs/CANONICAL_TRUTH.md`](CANONICAL_TRUTH.md), [`docs/SECURITY.md`](SECURITY.md), then the cited proof and runtime source files.

## Live Inventory

- March 26, 2026 live counts from [`.zkf-completion-status.json`](../.zkf-completion-status.json) and [`zkf-ir-spec/verification-ledger.json`](../zkf-ir-spec/verification-ledger.json): 143 total entries, 143 `mechanized_local`, 0 `mechanized_generated`, 0 `bounded_checked`, 0 `assumed_external`, 0 `pending`.
- Assurance classes on March 26, 2026: 115 `mechanized_implementation_claim`, 3 `attestation_backed_lane`, 16 `model_only_claim`, 9 `hypothesis_carried_theorem`.
- The GPU rows cited below are all present in the live ledger and all currently carry `status=mechanized_local`.

## What Is Mechanized Today

| Ledger row | Checker / assurance | Evidence surface | Current defended claim |
| --- | --- | --- | --- |
| `gpu.ntt_differential_bounded` | Lean / `model_only_claim` | [`zkf-metal/proofs/lean/Ntt.lean`](../zkf-metal/proofs/lean/Ntt.lean) | The shipped Goldilocks, BabyBear, and BN254 NTT program inventory stays synchronized with the mechanized staged radix-2 boundary model: program ids, operators, layouts, bindings, source paths, and reflection/workgroup policies. |
| `gpu.ntt_bn254_butterfly_arithmetic_sound` | Lean / `mechanized_implementation_claim` | [`zkf-metal/proofs/lean/Ntt.lean`](../zkf-metal/proofs/lean/Ntt.lean) | The admitted `ntt_butterfly_bn254` kernel computes the mechanized BN254 Montgomery-domain butterfly branch `a + w*b` / `a - w*b` over canonical values using the pinned helper-plus-entrypoint source set. |
| `gpu.msm_differential_bounded` | Lean / `model_only_claim` | [`zkf-metal/proofs/lean/Msm.lean`](../zkf-metal/proofs/lean/Msm.lean) | The shipped MSM program inventory stays synchronized with the mechanized bucket-chain boundary model: program ids, operators, routes, layouts, source paths, and reflection/workgroup policies. |
| `gpu.poseidon2_differential_bounded` | Lean / `model_only_claim` | [`zkf-metal/proofs/lean/Poseidon2.lean`](../zkf-metal/proofs/lean/Poseidon2.lean) | The shipped Poseidon2 scalar/SIMD program inventory stays synchronized with the mechanized family boundary model: operators, layouts, source paths, and reflection/workgroup policies. |
| `gpu.hash_differential_bounded` | Lean / `model_only_claim` | [`zkf-metal/proofs/lean/Hash.lean`](../zkf-metal/proofs/lean/Hash.lean) | The shipped SHA-256 and Keccak-256 batch-hash program inventory stays synchronized with the mechanized family boundary model: operators, layouts, source paths, and reflection/workgroup policies. |
| `gpu.launch_contract_sound` | Lean / `mechanized_implementation_claim` | [`zkf-metal/proofs/lean/LaunchSafety.lean`](../zkf-metal/proofs/lean/LaunchSafety.lean) | Admitted verified-lane dispatches have bounded regions, non-overlapping writes, and balanced barriers. |
| `gpu.buffer_layout_sound` | Lean / `mechanized_implementation_claim` | [`zkf-metal/proofs/lean/MemoryModel.lean`](../zkf-metal/proofs/lean/MemoryModel.lean) | Verified GPU buffer layouts, alias separation, initialized-read footprints, and writeback regions are structurally sound. |
| `gpu.dispatch_schedule_sound` | Lean / `mechanized_implementation_claim` | [`zkf-metal/proofs/lean/CodegenSoundness.lean`](../zkf-metal/proofs/lean/CodegenSoundness.lean) | The verified Metal schedule uses only the exported lowering bindings, step ordering, and barrier placements that refine the mechanized family semantics. |
| `gpu.shader_bundle_provenance` | Lean / `attestation_backed_lane` | [`zkf-metal/proofs/lean/CodegenSoundness.lean`](../zkf-metal/proofs/lean/CodegenSoundness.lean) | The checked manifest binds shipped entrypoints to source digests, metallib digests, reflection digests, pipeline-descriptor digests, and pinned toolchain identity. |
| `gpu.runtime_fail_closed` | Verus / `attestation_backed_lane` | [`zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs`](../zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs) | Verified GPU mode rejects unavailable devices, runtime compilation, attestation drift, and unsupported dispatches instead of silently falling back. |
| `gpu.cpu_gpu_partition_equivalence` | Verus / `mechanized_implementation_claim` | [`zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs`](../zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs) | The verified CPU/GPU placement partition preserves prover truth across the composed execution plan. |

The rows above split into four claim lanes:

- Structural family-model rows: `gpu.hash_differential_bounded`, `gpu.poseidon2_differential_bounded`, `gpu.ntt_differential_bounded`, `gpu.msm_differential_bounded`
- Arithmetic-mechanized subtranches: `gpu.ntt_bn254_butterfly_arithmetic_sound`
- Launch, layout, and schedule boundary rows: `gpu.launch_contract_sound`, `gpu.buffer_layout_sound`, `gpu.dispatch_schedule_sound`
- Provenance and fail-closed runtime rows: `gpu.shader_bundle_provenance`, `gpu.runtime_fail_closed`, `gpu.cpu_gpu_partition_equivalence`

Proof and code surfaces behind these rows:

- Lean family and boundary proofs: [`zkf-metal/proofs/lean/Ntt.lean`](../zkf-metal/proofs/lean/Ntt.lean), [`zkf-metal/proofs/lean/Msm.lean`](../zkf-metal/proofs/lean/Msm.lean), [`zkf-metal/proofs/lean/Poseidon2.lean`](../zkf-metal/proofs/lean/Poseidon2.lean), [`zkf-metal/proofs/lean/Hash.lean`](../zkf-metal/proofs/lean/Hash.lean), [`zkf-metal/proofs/lean/LaunchSafety.lean`](../zkf-metal/proofs/lean/LaunchSafety.lean), [`zkf-metal/proofs/lean/MemoryModel.lean`](../zkf-metal/proofs/lean/MemoryModel.lean), and [`zkf-metal/proofs/lean/CodegenSoundness.lean`](../zkf-metal/proofs/lean/CodegenSoundness.lean).
- Generated GPU inventory carried into Lean: [`zkf-metal/proofs/lean/Generated/GpuPrograms.lean`](../zkf-metal/proofs/lean/Generated/GpuPrograms.lean).
- Verus runtime proofs: [`zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs`](../zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs).
- Rust attestation and runtime enforcement: [`zkf-metal/src/verified_artifacts.rs`](../zkf-metal/src/verified_artifacts.rs), [`zkf-metal/src/launch_contracts.rs`](../zkf-metal/src/launch_contracts.rs), [`zkf-metal/src/device.rs`](../zkf-metal/src/device.rs), [`zkf-metal/src/proof_ir.rs`](../zkf-metal/src/proof_ir.rs), [`zkf-runtime/src/metal_dispatch_macos.rs`](../zkf-runtime/src/metal_dispatch_macos.rs), [`zkf-runtime/src/scheduler.rs`](../zkf-runtime/src/scheduler.rs), and [`zkf-runtime/src/metal_driver.rs`](../zkf-runtime/src/metal_driver.rs).

## Verified Runtime Lane Is Narrower Than The Full GPU Surface

- The generated Lean inventory in [`zkf-metal/proofs/lean/Generated/GpuPrograms.lean`](../zkf-metal/proofs/lean/Generated/GpuPrograms.lean) covers a broader mechanized GPU family surface than the strict runtime verified lane. The generated `allPrograms` list includes:
  - hash: `batch_sha256`, `batch_keccak256`
  - MSM families: BN254 classic assign/accumulate/reduce/combine plus Pallas/Vesta classic and NAF accumulation surfaces
  - NTT families: Goldilocks, BabyBear, and BN254 variants
  - Poseidon2 families: Goldilocks and BabyBear scalar/SIMD variants
- The strict runtime verified lane is narrower. The current pinned runtime subset, as supported by the live source and by [`docs/SECURITY.md`](SECURITY.md), is:
  - BN254 classic MSM
  - BN254 NTT
  - Goldilocks NTT
  - Goldilocks Poseidon batch
  - SHA-256 batch
- Runtime verified mode is `GpuVerificationMode::VerifiedPinned` in [`zkf-runtime/src/metal_driver.rs`](../zkf-runtime/src/metal_driver.rs). In this mode:
  - [`zkf-runtime/src/metal_dispatch_macos.rs`](../zkf-runtime/src/metal_dispatch_macos.rs) rejects nodes outside the pinned verified GPU subset.
  - [`zkf-runtime/src/scheduler.rs`](../zkf-runtime/src/scheduler.rs) refuses silent fallback when verified mode is fail-closed.
  - [`zkf-metal/src/device.rs`](../zkf-metal/src/device.rs) rejects runtime compilation, toolchain drift, metallib drift, reflection drift, and pipeline-descriptor drift before dispatch.
- Broader Metal accelerators exist outside that strict subset. The live runtime reports active accelerators for `constraint_eval`, `field_ops`, `fri`, `hash`, `msm`, `ntt`, `poly_ops`, and `poseidon2`, but this document does not treat all of those as part of the current strict verified GPU lane.

## Attestation Chain

- [`zkf-metal/src/verified_artifacts.rs`](../zkf-metal/src/verified_artifacts.rs) defines `ExpectedKernelAttestation` with four pinned runtime artifacts:
  - `metallib_sha256`
  - `reflection_sha256`
  - `pipeline_descriptor_sha256`
  - `toolchain`
- The same file defines `ToolchainIdentity` and `current_toolchain_identity()`, which bind the shipped lane to the injected Metal compiler version, Xcode version, and SDK version.
- `expected_metallib_sha256()` pins the compiled library digests for the shipped Metal libraries. `expected_arguments()` defines the static argument whitelist used to derive expected reflection digests.
- Reflection digests are computed from canonical expected arguments in [`zkf-metal/src/verified_artifacts.rs`](../zkf-metal/src/verified_artifacts.rs), then compared against runtime reflection in [`zkf-metal/src/device.rs`](../zkf-metal/src/device.rs).
- Pipeline-descriptor digests are computed and rechecked the same way, again through [`zkf-metal/src/verified_artifacts.rs`](../zkf-metal/src/verified_artifacts.rs) and [`zkf-metal/src/device.rs`](../zkf-metal/src/device.rs).
- Source pinning and lowering provenance are carried through [`zkf-metal/src/proof_ir.rs`](../zkf-metal/src/proof_ir.rs) into [`zkf-metal/proofs/lean/Generated/GpuPrograms.lean`](../zkf-metal/proofs/lean/Generated/GpuPrograms.lean), where each generated program records source digests, source paths, toolchain identity, entrypoint attestations, reflection policy, workgroup policy, and step bindings.
- The whitelist is static. If an entrypoint is not represented by `expected_arguments()` and the generated program inventory, it is not admitted to the verified path.

## Launch Contracts And Negative Evidence

- The host-side launch contracts live in [`zkf-metal/src/launch_contracts.rs`](../zkf-metal/src/launch_contracts.rs). They are pure Rust, emit `Result<ValidatedDispatch, LaunchContractError>`, and keep the verified launch boundary available to proofs, Kani harnesses, and runtime code as a shared source of truth.
- Contract families currently implemented there:
  - Hash: nonzero batch count and input length, exact input byte length, exact digest output length.
  - Poseidon2: nonzero state size, state width multiple of 16, nonzero round constants, nonzero external/internal round counts, zero-copy only when page-aligned.
  - NTT: transform height at least 2, transform height power-of-two, width nonzero, twiddle buffer covers height.
  - MSM: nonzero points, sufficient bucket map coverage, sufficient bucket storage, sufficient window/final buffers, and certified BN254 route restricted to Classic only.
- Unit tests in [`zkf-metal/src/launch_contracts.rs`](../zkf-metal/src/launch_contracts.rs) exercise explicit rejection cases for:
  - short hash output buffers
  - mis-sized Poseidon2 state
  - short NTT twiddle buffers
  - certified BN254 hybrid-route misuse
- Kani proofs in [`zkf-metal/src/verification_kani.rs`](../zkf-metal/src/verification_kani.rs) cover additional negative evidence:
  - zero input length
  - short digest output
  - misaligned Poseidon2 state width
  - bad zero-copy request
  - non-power-of-two NTT height
  - short twiddle regions
  - short MSM bucket map
  - invalid NAF bucket shape
  - non-Classic certified BN254 routes
- Runtime strict-fallback behavior is exercised separately in [`zkf-runtime/src/lib.rs`](../zkf-runtime/src/lib.rs) and enforced in [`zkf-runtime/src/scheduler.rs`](../zkf-runtime/src/scheduler.rs) and [`zkf-runtime/src/metal_dispatch_macos.rs`](../zkf-runtime/src/metal_dispatch_macos.rs): proof-critical verified GPU fallback is rejected instead of silently continuing on CPU.

## Current Machine State (March 25, 2026)

Live, reproducible facts from this session:

- `target-local/release/zkf-cli metal-doctor --json` reported:
  - `runtime.metal_compiled=true`
  - `runtime.metal_available=true`
  - `runtime.metal_device="Apple M4 Max"`
  - `runtime.metallib_mode="aot"`
  - `certified_hardware_profile="apple-silicon-m4-max-48gb"`
  - `strict_bn254_ready=true`
  - `strict_bn254_auto_route=true`
  - `strict_gpu_stage_coverage.coverage_ratio=1.0`
  - `production_ready=false`
  - `production_failures=["strict certification report missing at /var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/zkf-stark-to-groth16/certification/strict-m4-max.json"]`
- The same `metal-doctor` run reported active accelerator registration for `constraint_eval`, `field_ops`, `fri`, `hash`, `msm`, `ntt`, `poly_ops`, and `poseidon2`. This is accelerator availability information, not a blanket verified-lane claim.
- `target-local/release/zkf-cli telemetry stats --json` reported:
  - `schema="zkf-telemetry-corpus-v1"`
  - `directory="/Users/sicarii/.zkf/telemetry"`
  - `record_count=1439`
  - `corpus_hash="a83ce2bb061dfaafbadd05bd7768164869bdda1fb1ee8469200501cbe1e19832"`
- `target-local/release/zkf-cli metal-doctor --strict --json` failed in this session because the strict certification report file was missing. This document therefore does not claim current strict production certification on this machine.
- `python3 scripts/proof_audit.py --release-grade` still did not complete successfully in this session, but the current stop is no longer the Montgomery tranche. The new BN254 strict-lane Rocq theorem and `scripts/run_montgomery_assurance.sh` regression backstops both passed; the remaining audit failure is an unrelated F* / hax extraction issue in `zkf-core/src/proof_transform_spec.rs`.
- A lightweight benchmark run in this session, `target-local/release/zkf-cli benchmark --out /tmp/zkf-bench.json --backends plonky3 --iterations 1 --skip-large`, produced backend-level `metal_stage_breakdown` metadata for Goldilocks and BabyBear Plonky3 cases. The same report still recorded `runtime_execution_regime="cpu-only"` and `runtime_gpu_stage_busy_ratio=0.0`, so this document treats that benchmark as capability/coverage evidence only.

## Non-Claims

- This document does not claim that every `.metal` shader file in [`zkf-metal/src/shaders`](../zkf-metal/src/shaders) is mechanized today.
- This document does not claim that every mechanized GPU family surface is admitted to the current strict runtime whitelist.
- This document does not claim that current strict production certification is present on this machine. As of March 25, 2026 the live strict gate fails because the certification report file is missing.
- This document does not claim heat, temperature, or thermal-throttling measurements from the current local telemetry corpus.
- This document does not present benchmark metadata busy ratios or stage-breakdown fields as proof of realized runtime GPU participation when the same run reports `cpu-only` execution realization.
- This document does not cite a passing `scripts/proof_audit.py --release-grade` rerun from this session.
