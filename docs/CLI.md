# ZirOS CLI Reference

`ziros` is the preferred public command name. The legacy `zkf` command remains
supported for compatibility, and internal crate/package names stay `zkf-*` for now.

## Global Flags

| Flag | Description |
|------|-------------|
| `--allow-compat` | Allow explicit compatibility backend aliases such as `sp1-compat` and `risc-zero-compat` |

---

## Core Commands

### `zkf app init`

Scaffold a standalone Rust application that embeds `zkf-lib` directly.

```bash
ziros app init my-zk-app --template range-proof
ziros app init my-zk-app --template poseidon-commitment
ziros app init my-zk-app --template poseidon-commitment --style tui
ziros app init my-zk-app --template thermochemical-equilibrium
ziros app init my-zk-app --template real-gas-state --template-arg model=redlich-kwong
```

The scaffold creates its own `[workspace]`, points `zkf-lib` back at the local ZirOS checkout with
a path dependency, writes `zirapp.json`, `src/spec.rs`, `src/main.rs`, `inputs.compliant.json`,
`inputs.violation.json`, `tests/smoke.rs`, and a local `README.md`, then leaves you with a normal
external Cargo app.

| Flag | Description |
|------|-------------|
| `<name>` | Output app directory / package name |
| `--template` | Starter template from the shared registry (`zkf app templates`) |
| `--template-arg key=value` | Pass template parameters such as `depth=4` or `bits=16` |
| `--style` | Scaffold style: `minimal`, `colored` (default), or `tui` |
| `--out` | Override the scaffold output directory |

Use this path for new standalone apps. The lower-level `emit-example`, `compile`, `prove`, and raw
IR JSON commands remain available for operator workflows, imports, inspection, and debugging.

The primary authoring surface is `zirapp.json`; `ProgramBuilder` remains available inside the local
app dependency graph when the declarative spec is not enough.
For the declarative schema itself, read
`APPSPEC_REFERENCE.md`.
The scientific templates are discrete certificate lanes. They prove the attested discretized model
and witness satisfy the shipped equations and residual checks; they do not claim continuous-theory
closure such as the Clay Navier-Stokes result.

### `zkf app gallery`

Show the available scaffold styles as styled terminal cards.

```bash
ziros app gallery
```

The gallery lists exactly three styles:

- `minimal`: plain text for CI, scripts, and quiet shells
- `colored`: default proof banner, audit, credential, and progress output
- `tui`: full-screen dashboard scaffolds backed by `zkf-tui`

### `zkf app templates`

List the declarative scaffold templates from the shared registry.

```bash
ziros app templates
ziros app templates --json
```

### `zkf app reentry-assurance`

Operate the theorem-first reentry mission-assurance and mission-ops surface.
The production target is an explicit `NASA Class D ground-support mission-ops`
boundary, not onboard flight software and not a Class C+ certification claim.
The mission-ops ingestion layer is `normalized-export-based ingestion`, and this
surface does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD,
Basilisk, cFS, or F Prime.
For the full workflow and artifact boundary, read
[`REENTRY_MISSION_OPS_PLATFORM.md`](REENTRY_MISSION_OPS_PLATFORM.md).
For the shared reusable layer and the staged public mirror posture, read
[`AEROSPACE_KIT.md`](AEROSPACE_KIT.md) and
[`PUBLIC_MONOREPO_MIRROR.md`](PUBLIC_MONOREPO_MIRROR.md).

### `zkf capabilities`

List live backend capabilities and readiness for the current binary and host.
The JSON output is the canonical public truth source consumed by `doctor`,
the assistant bundle, and the system dashboard.

```bash
zkf capabilities
```

### `zkf frontends`

List supported frontends with their capabilities.

```bash
zkf frontends
zkf frontends --json
```

### `zkf doctor`

Run diagnostics: check backend availability, native dependencies, feature flags.

```bash
zkf doctor
zkf doctor --json
```

### `zkf metal-doctor`

Check Metal GPU availability and shader compilation on Apple Silicon.
Use `--strict` on the certified production host to fail closed if the Metal
runtime is not healthy enough for strict cryptographic BN254 wrapping.
On the certified `AppleSiliconM4Max48GB` lane, the strict JSON report exposes:
`production_ready`, `certified_hardware_profile`, `strict_bn254_ready`,
`strict_bn254_auto_route`, `strict_gpu_stage_coverage`,
`strict_certification_present`, `strict_certification_match`,
`strict_certified_at_unix_ms`, `strict_certification_report`, and
`strict_gpu_busy_ratio_peak`.

```bash
zkf metal-doctor
zkf metal-doctor --json
zkf metal-doctor --strict --json
```

### `zkf audit`

Generate a machine-verifiable audit report for a program. When `--backend` is provided,
the command uses the live backend capability/readiness model and reports implementation type,
production readiness, exact blocked reasons, operator actions, and explicit compat aliases.

```bash
zkf audit --program ir/program.json
zkf audit --program ir/program.json --backend sp1
zkf audit --program ir/program.json --backend sp1 --json
```

### `zkf conformance`

Run the backend conformance suite and optionally export standalone release artifacts.

```bash
zkf conformance --backend arkworks-groth16
zkf conformance --backend arkworks-groth16 --json
zkf conformance --backend arkworks-groth16 \
  --export-json target/conformance/arkworks-groth16.json \
  --export-cbor target/conformance/arkworks-groth16.cbor
```

### `zkf emit-example`

Write a sample multiply circuit (IR JSON) to a file. This is the low-level/manual path; new
application work should start with `zkf app init`.

```bash
zkf emit-example --out examples/multiply.json
```

---

## Import & Inspect

### `zkf import`

Import an external ZK artifact into a ZKF program family. Use `--ir-family auto` to keep
lossless `zir-v1` when the frontend exposes semantics that lowered `ir-v2` cannot preserve.

```bash
zkf import --frontend noir --in ./target/acir.json --out ir/program.json
zkf import --frontend halo2-export --in ./halo2_schema.json --out zir/program.json --ir-family auto
zkf import --frontend circom --in ./circuit.r1cs.json --out ir/program.json --field bn254
zkf import --frontend cairo --in ./program.sierra.json --out ir/program.json
zkf import --frontend compact --in ./descriptor.json --out ir/program.json
zkf import --frontend halo2-export --in ./halo2_schema.json --out ir/program.json
zkf import --frontend plonky3-air-export --in ./air_schema.json --out ir/program.json
zkf import --frontend zkvm --in ./guest.elf --out ir/program.json
```

| Flag | Description |
|------|-------------|
| `--frontend` | Frontend to use (default: `noir`) |
| `--in` | Input file path |
| `--out` | Output IR JSON path |
| `--name` | Override circuit name |
| `--field` | Override target field (e.g., `bn254`, `pasta-fp`, `goldilocks`) |
| `--ir-family` | Output family: `auto`, `zir-v1`, or `ir-v2` (default: `auto`) |
| `--allow-unsupported-version` | Skip version checks on frontend artifacts |
| `--package-out` | Also create a package manifest at this path |
| `--json` | Output results as JSON |

### `zkf import-acir`

Direct ACIR import (shorthand for `--frontend noir`).

```bash
zkf import-acir --in ./acir.json --out ir/program.json
zkf import-acir --in ./acir.json --out zir/program.json --ir-family zir-v1
```

### `zkf inspect`

Inspect an external artifact without importing.

```bash
zkf inspect --frontend noir --in ./target/acir.json
zkf inspect --frontend circom --in ./circuit.r1cs.json --json
```

---

## Witness & Optimization

### `zkf witness`

Generate a witness from a program and inputs.

```bash
zkf witness --program ir/program.json --inputs inputs.json --out witness.json
```

### `zkf optimize`

Run the IR optimizer: constant folding, tautology removal, deduplication, dead signal elimination.

```bash
zkf optimize --program ir/program.json --out ir/optimized.json
zkf optimize --program ir/program.json --out ir/optimized.json --json
```

### `zkf debug`

Run witness debugger with constraint-level traces.

```bash
zkf debug --program ir/program.json --inputs inputs.json --out debug_report.json
zkf debug --program ir/program.json --inputs inputs.json --out debug_report.json --continue-on-failure
zkf debug --program ir/program.json --inputs inputs.json --out debug_report.json --solver acvm
```

---

## Compile, Prove, Verify

### `zkf compile`

Compile an IR program for a specific backend.

```bash
zkf compile --program ir/program.json --backend arkworks-groth16 \
  --groth16-setup-blob trusted-setup.bin --out compiled.json
zkf compile --program ir/program.json --backend halo2 --out compiled.json
zkf compile --program ir/program.json --backend plonky3 --out compiled.json
zkf compile --program ir/program.json --backend nova --out compiled.json --seed 42
```

| Backend | Field | Description |
|---------|-------|-------------|
| `arkworks-groth16` | BN254 | Groth16 with imported trusted setup on the security-covered path; deterministic setup is dev/test-only via `--allow-dev-deterministic-groth16` |
| `halo2` | Pasta Fp | Halo2 with IPA, transparent setup |
| `halo2-bls12-381` | BLS12-381 | Halo2 with BLS12-381 curve |
| `plonky3` | Goldilocks/BabyBear/Mersenne31 | STARK+FRI |
| `nova` | BN254 (Pallas/Vesta) | Nova IVC |
| `hypernova` / `hyper-nova` | BN254 | HyperNova CCS multifolding |
| `sp1` | - | Native SP1 zkVM backend name |
| `sp1-compat` | - | Explicit SP1 compatibility/delegated backend alias (requires `--allow-compat`) |
| `risc-zero` | - | Native RISC Zero zkVM backend name |
| `risc-zero-compat` | - | Explicit RISC Zero compatibility/delegated backend alias (requires `--allow-compat`) |
| `midnight-compact` (`midnight`, `compact` accepted) | Pasta Fp | Midnight Compact |

### `zkf prove`

Generate a witness and prove in one step.

```bash
zkf prove --program ir/program.json --inputs inputs.json --backend arkworks-groth16 --out proof.json
zkf prove --program ir/program.json --inputs inputs.json --out proof.json \
  --compiled-out compiled.json --solver acvm --seed 42
zkf prove --program ir/program.json --inputs inputs.json --backend auto \
  --objective smallest-proof --out proof.json
zkf prove --program ir/program.json --inputs inputs.json \
  --backend arkworks-groth16 --distributed --out proof.json
```

| Flag | Description |
|------|-------------|
| `--program` | IR program JSON |
| `--inputs` | Witness inputs JSON |
| `--backend` | Backend (`auto` or omitted means model-first recommendation, then heuristic fallback) |
| `--objective` | Auto-selection target (`fastest-prove`, `smallest-proof`, `no-trusted-setup`); default `fastest-prove` |
| `--mode` | Proving mode (`default`, `metal-first`); on the certified M4 Max host, `metal-first` auto-routes BN254 to strict `arkworks-groth16` |
| `--export` | Export format (`solidity`) |
| `--out` | Output proof artifact path |
| `--compiled-out` | Also save compiled program |
| `--solver` | Witness solver (`default`, `acvm`) |
| `--seed` | Deterministic seed for setup |

Primary proof commands now route backend proving through UMPG. For backend proof jobs,
the runtime executes the delegated proving lane
`WitnessSolve -> TranscriptUpdate -> BackendProve -> ProofEncode`
under the scheduler and trace system.

Native backend names fail closed when the native path is not production-ready on the current
binary or host. Use `--allow-compat` only with explicit aliases such as `sp1-compat` and
`risc-zero-compat`; native names are never silently reinterpreted as compat.

When `--distributed` is enabled, the coordinator partitions the UMPG graph, transfers boundary
buffers to workers over TCP, and retries failed remote partitions locally without changing proof
semantics. Experimental RDMA stays fail-closed and is not used for production jobs.

### `zkf verify`

Verify a proof artifact.

```bash
zkf verify --program ir/program.json --artifact proof.json --backend arkworks-groth16
```

---

## Proof Wrapping

### `zkf wrap`

Wrap a STARK proof into a Groth16 proof (STARK-to-SNARK).

```bash
zkf wrap --proof plonky3_proof.json --compiled plonky3_compiled.json --out wrapped_groth16.json
```

Strict production wrapping on the certified M4 Max host emits `wrapped-v2`
artifacts only. Top-level proof metadata and `zkf runtime trace --proof ... --json`
surface finalized GPU-stage fields including:
`qap_witness_map_engine`, `qap_witness_map_reason`,
`qap_witness_map_parallelism`, `groth16_msm_engine`,
`groth16_msm_reason`, `groth16_msm_parallelism`,
`gpu_stage_coverage`, `gpu_stage_busy_ratio`,
`metal_dispatch_circuit_open`, and `metal_dispatch_last_failure`.
When fixture or production Neural Engine models are installed, wrap also emits the runtime-native
model catalog, advisory duration estimate, conservative duration bound when available,
execution-regime/ETA-semantics labels, anomaly metadata, runtime security verdict,
security signals/actions, and model-integrity metadata; without models it stays on the
heuristic control plane plus deterministic security supervision.

### `zkf runtime plan` / `zkf runtime execute`

Plan and execute UMPG graphs directly. For the supported wrapper surface,
UMPG now executes the native wrapper graph
`WitnessSolve -> TranscriptUpdate -> VerifierEmbed -> OuterProve -> ProofEncode`
under the scheduler. Public wrapper execution traces should keep
`delegated_nodes=0`.

```bash
zkf runtime plan --proof proof-plonky3.json --compiled compiled-plonky3.json --trust allow-attestation --output /tmp/zkf-wrapper.plan.json
zkf runtime execute --plan /tmp/zkf-wrapper.plan.json --out /tmp/zkf-wrapper.groth16.json --trace /tmp/zkf-wrapper.trace.json
```

### `zkf runtime certify`

Certify the strict M4 Max production lane and emit a typed certification report.

```bash
zkf runtime certify --mode gate --proof stark-proof.json --compiled stark-compiled.json
zkf runtime certify --mode soak --proof stark-proof.json --compiled stark-compiled.json --parallel-jobs auto
```

### `zkf runtime policy`

Evaluate the runtime-native Neural Engine control plane. The command reports the chosen
dispatch plan, backend ranking, advisory duration estimate, conservative duration bound when
available, execution regime, ETA semantics, anomaly baseline, security posture, and discovered
model catalog. It uses the same runtime module that prove/fold/wrap consume. When `--backends` is
omitted, the command now derives a field-aware multi-backend candidate set that matches runtime
auto-selection instead of collapsing to a Groth16-only default. Model scores stay advisory: hard
field/program compatibility, host readiness, and `no-trusted-setup` guards are enforced after
scoring, and filtered candidates are surfaced in the emitted notes. On CPU-only or no-Metal
fallback paths, ETA is explicitly labeled `non-sla-fallback` and must not be treated as a WCET
or countdown guarantee. The Neural Engine security detector is advisory only; deterministic policy
is the enforcement boundary.

```bash
python3 -m pip install -r scripts/neural_engine_requirements.txt
python3 scripts/build_fixture_neural_models.py
python3 scripts/build_fixture_neural_models.py --check
python3 scripts/install_fixture_neural_models.py --dest target/coreml
zkf runtime policy --objective smallest-proof --trace /tmp/zkf-wrapper.trace.json --json
zkf prove --program program.json --inputs inputs.json --backend auto --objective no-trusted-setup --out proof.json
zkf fold --manifest package.json --inputs inputs.json --steps 8 --objective fastest-prove --json
```

Production/operator model training uses the same lane names but a larger telemetry corpus:

```bash
python3 scripts/build_control_plane_corpus.py --out ~/.zkf/models/control_plane_corpus.jsonl
python3 scripts/train_scheduler_model.py --out ~/.zkf/models/scheduler_v1.mlpackage
python3 scripts/train_backend_recommender.py --out ~/.zkf/models/backend_recommender_v1.mlpackage
python3 scripts/train_duration_estimator.py --out ~/.zkf/models/duration_estimator_v1.mlpackage
python3 scripts/train_anomaly_detector.py --out ~/.zkf/models/anomaly_detector_v1.mlpackage
python3 scripts/train_security_detector.py --out ~/.zkf/models/security_detector_v1.mlpackage
zkf runtime policy --trace /tmp/zkf-wrapper.trace.json --json
```

Model discovery order:

1. `ZKF_*_MODEL`
2. `~/.zkf/models/*.mlpackage`
3. `target/coreml/*.mlpackage`

The repo-tracked fixture bundles are deterministic smoke artifacts under
`zkf-runtime/tests/fixtures/neural_engine/models/`; operator-trained models in `~/.zkf/models/`
override them through the same discovery contract. Auto-discovered models from `~/.zkf/models/`
and `target/coreml/` must carry a sidecar with the expected schema, input shape, output name, and
a passing `quality_gate`. Explicit `ZKF_*_MODEL` paths may omit the sidecar for local development,
but a present sidecar marked failed is still rejected.

See docs/NEURAL_ENGINE_OPERATIONS.md
for training, validation, and rollback.

The soak report is the source of truth for strict readiness. `zkf metal-doctor --strict --json`
is only `production_ready=true` when the runtime is healthy and the current binary has a matching
successful installed soak report.

---

## Folding (IVC)

### `zkf fold`

Run Nova/HyperNova IVC folding over multiple steps. Folding executes through UMPG so fold jobs
emit the same runtime/scheduler telemetry model as prove and wrap jobs.

```bash
zkf fold --manifest package.json --inputs step_inputs.json --steps 10
zkf fold --manifest package.json --inputs step_inputs.json --steps 5 --backend hypernova --json
zkf fold --manifest package.json --inputs step_inputs.json --steps 8 --objective smallest-proof --json
```

| Flag | Description |
|------|-------------|
| `--manifest` | Package manifest path |
| `--inputs` | Step inputs JSON |
| `--steps` | Number of IVC steps |
| `--backend` | Folding backend (`auto`, `nova`, `hypernova` or `hyper-nova`); `auto` or omitted means model-first recommendation, then heuristic fallback |
| `--objective` | Auto-selection target (`fastest-prove`, `smallest-proof`, `no-trusted-setup`); default `fastest-prove` |
| `--step-mode` | Step mode (`chain`, `reuse`) |
| `--solver` | Witness solver |
| `--seed` | Deterministic seed |
| `--json` | JSON output |

---

## Benchmarking

### `zkf benchmark`

Run benchmarks across backends with configurable parameters.

```bash
zkf benchmark --out results.json
zkf benchmark --out results.json --backends arkworks-groth16,halo2,plonky3 --iterations 5
zkf benchmark --out results.json --markdown-out results.md --parallel --skip-large
```

| Flag | Description |
|------|-------------|
| `--out` | Output results JSON |
| `--markdown-out` | Also write a Markdown table |
| `--mode` | Benchmark mode |
| `--backends` | Comma-separated backend list |
| `--iterations` | Repetitions per benchmark |
| `--skip-large` | Skip large circuits |
| `--continue-on-error` | Don't abort on failures |
| `--parallel` | Run backends in parallel |

---

## Gas Estimation & Deployment

### `zkf estimate-gas`

Estimate on-chain verification gas cost.

```bash
zkf estimate-gas --backend arkworks-groth16
zkf estimate-gas --backend arkworks-groth16 --artifact proof.json --json
zkf estimate-gas --backend arkworks-groth16 --artifact proof.json --evm-target optimism-arbitrum-l2
```

Supported `--evm-target` values are `ethereum` (default), `optimism-arbitrum-l2`, and
`generic-evm`.

### `zkf deploy`

Generate a Solidity verifier contract from a proof artifact.

```bash
zkf deploy --artifact proof.json --backend arkworks-groth16 --out Verifier.sol
zkf deploy --artifact proof.json --backend arkworks-groth16 --out Verifier.sol --contract-name MyVerifier
zkf deploy --artifact proof.json --backend arkworks-groth16 \
  --out Verifier.sol --evm-target generic-evm --json
```

`zkf deploy --json` includes `evm_target`, and when artifact metadata exposes
`algebraic_binding=false`, it also emits an explicit trust-boundary note instead of silently
implying a fully algebraically bound in-circuit accumulator check.

---

## Proof Exploration

### `zkf explore`

Inspect proof internals: size, public inputs, VK hash.

```bash
zkf explore --proof proof.json --backend arkworks-groth16
zkf explore --proof proof.json --backend arkworks-groth16 --json
```

For wrapped or aggregated artifacts, `zkf explore` also surfaces trust-boundary metadata such as
`trust_model`, `proof_semantics`, `aggregation_semantics`, `algebraic_binding`, and any exported
`trust_boundary_note`.

---

## Test Vectors

### `zkf test-vectors`

Run test vectors across backends.

```bash
zkf test-vectors --program ir/program.json --vectors test_vectors.json
zkf test-vectors --program ir/program.json --vectors test_vectors.json --backends arkworks-groth16,halo2 --json
```

---

## Package Commands

Package commands manage the full lifecycle of a ZK circuit package.

### `zkf package verify`

Verify package manifest integrity (file digests, schema version).

```bash
zkf package verify --manifest package.json
```

### `zkf package migrate`

Migrate manifest between schema versions.

```bash
zkf package migrate --manifest package.json --from 1 --to 2
```

### `zkf package compile`

Compile the package's program for a backend.

```bash
zkf package compile --manifest package.json --backend arkworks-groth16
```

### `zkf package prove`

Prove a single run from the package.

```bash
zkf package prove --manifest package.json --backend arkworks-groth16 --run-id main
zkf package prove --manifest package.json --backend auto --objective smallest-proof --run-id main
```

### `zkf package prove-all`

Prove one package across all production-ready real backends for the current binary and host. Backends that are compiled in but not ready are reported as skipped with exact readiness reasons. Pass `--mode metal-first` only when you want the single certified Metal lane instead of the default cross-backend behavior.

```bash
zkf package prove-all --manifest package.json --backends arkworks-groth16,halo2,plonky3 --parallel --jobs 4
```

The default `prove-all` path is the canonical one-circuit/all-real-backends workflow. It selects
all production-ready non-delegated backends for the current binary and host, then reports blocked
or skipped native backends with exact machine-readable reasons and operator-facing remediation.

### `zkf package verify-proof`

Verify a proof stored in the package.

```bash
zkf package verify-proof --manifest package.json --backend arkworks-groth16 --run-id main
zkf package verify-proof --manifest package.json --backend arkworks-groth16 --solidity-verifier Verifier.sol
```

### `zkf package aggregate`

Emit a metadata-binding aggregate artifact across multiple backend proofs. This is the
canonical package-level aggregate surface. With `--crypto`, ZKF may also materialize a
backend-specific cryptographic aggregate artifact when that backend exposes one. Today the live
cryptographic path is Halo2 IPA accumulation; Groth16 universal recursive aggregation remains
fail-closed roadmap work. The package aggregate report itself is not proof compression.

```bash
zkf package aggregate --manifest package.json --backends arkworks-groth16,plonky3 --crypto
zkf package verify-aggregate --manifest package.json --run-id main
```

### `zkf package compose`

Compose proofs across backends with proof-enforced digest/VK/public-input linkage plus
host-validated `recursive_aggregation_marker` semantics. This is not the same thing as
cryptographic recursive verification of each carried proof.

```bash
zkf package compose --manifest package.json --backend nova
zkf package verify-compose --manifest package.json --backend nova
```

---

## Registry Commands

### `zkf registry list`

List available gadgets in the local registry.

```bash
zkf registry list
zkf registry list --json
```

The list surface merges local manifests with the remote registry index cache when configured.

### `zkf registry add`

Install a gadget from the registry.

```bash
zkf registry add poseidon2
```

If the gadget is not already present locally, ZKF fetches the remote manifest and content, validates
the content digest, and then installs it into the local registry cache.

### `zkf registry publish`

Publish a gadget to the local registry.

```bash
zkf registry publish --manifest gadget.json --content gadget_content.json
```

---

## Common Workflows

### Import → Compile → Prove → Verify → Deploy

```bash
# 1. Import from Noir
zkf import --frontend noir --in ./target/acir.json --out ir/program.json

# 2. Compile for the target backend
zkf compile --program ir/program.json --backend arkworks-groth16 \
  --groth16-setup-blob trusted-setup.bin --out compiled.json

# 3. Prove with Groth16
zkf prove --program ir/program.json --inputs inputs.json \
  --backend arkworks-groth16 --groth16-setup-blob trusted-setup.bin \
  --out proof.json

# 4. Verify
zkf verify --program ir/program.json --artifact proof.json \
  --backend arkworks-groth16

# 5. Export the verifier
zkf deploy --artifact proof.json --backend arkworks-groth16 \
  --out Verifier.sol --evm-target ethereum
```

### Package Workflow

```bash
# 1. Import with package output
zkf import --frontend noir --in ./target/acir.json \
  --out ir/program.json --package-out package.json

# 2. Verify manifest
zkf package verify --manifest package.json

# 3. Compile + prove + verify
zkf package compile --manifest package.json --backend arkworks-groth16
zkf package prove --manifest package.json --backend arkworks-groth16
zkf package verify-proof --manifest package.json --backend arkworks-groth16

# 4. Deploy Solidity verifier
zkf deploy --artifact proof.json --backend arkworks-groth16 --out Verifier.sol
```

### Multi-Backend Benchmarking

```bash
zkf benchmark --out bench.json --markdown-out bench.md \
  --backends arkworks-groth16,halo2,plonky3 \
  --iterations 10 --parallel
```

### Competition Gate

```bash
make competition-bootstrap
make competition-report
make competition-gate
```

The competition gate runs the repo-owned mixed corpus from `benchmarks/manifest.json`,
bootstraps or validates competitor toolchains from `benchmarks/toolchain-lock.json`, and writes:
- `target/competition/toolchain_manifest.json`
- `target/competition/competitive_harness.json`
- `target/competition/competition_gate.json`

The repo-owned corpus currently includes vendored Circom/snarkjs, Noir/Nargo, gnark,
official RISC Zero, and an external Plonky3 lane under `benchmarks/workspaces/`.
The official SP1 lane uses the same scenario contract and now declares Docker as an explicit
toolchain prerequisite in the bootstrap lock, so missing Docker reports as a prerequisite failure
instead of a false backend-negative result. On Apple Silicon, the SP1 lane forces Docker to
`linux/amd64` so the current stable `sp1-gnark` image can run through emulation.
On macOS, the SP1 Groth16 lane also fails early if Docker exposes less than 32GB of memory,
which keeps low-memory Colima or Docker Desktop setups from surfacing as opaque prover failures;
for Colima, restart with `colima stop && colima start --cpu 8 --memory 32 --disk 80`.
On macOS, the lane also redirects SP1 temp files into a home-directory temp root before invoking
the upstream gnark Docker wrapper, which avoids Colima turning unshared `/var/folders/...` file
binds into directories inside the container.

`make competition-report` always emits the artifacts even when the gate fails. `make competition-gate`
fails closed when required toolchains, scenarios, or verification evidence are missing.

### Workspace Validation

```bash
make validation-report
```

This writes `target/validation/workspace_validation.json` after running the whole-workspace
production validation matrix. Release finalization fails closed unless this report exists and
records `passed=true`. The matrix also runs the native Nova recursion hardening integration test,
and on macOS it additionally runs Metal SHA-256/Keccak GPU-vs-CPU checks plus the `zkf-python`
build/import smoke so PyO3 linker regressions are release-blocking.

### IVC Folding

```bash
# Run 10-step Nova IVC folding
zkf fold --manifest package.json --inputs steps.json --steps 10 --backend nova

# Verify folded proof
zkf package verify-proof --manifest package.json --backend nova
```

Native Nova IVC folding requires the program or package metadata to declare
`nova_ivc_in` and `nova_ivc_out`, which identify the step-state input signal and
the next-state output signal. Package folding chains `nova_ivc_out` from one step
into `nova_ivc_in` for the next step before invoking the native fold path.

`chain-public-outputs` is different: it copies public outputs back into the next
step by public-signal position. It does not infer semantic state handoff. Use
`nova_ivc_in` / `nova_ivc_out` when the next step's state input should come from
one specific prior-step output.

---

## Feature Flags

| Feature | Description |
|---------|-------------|
| `native-nova` | Enable Nova/HyperNova backends |
| `all-native-backends` | Enable the optional native zkVM bundle (`native-sp1` and `native-risc-zero`) |
| `native-sp1` | Enable the native SP1 zkVM backend |
| `native-risc-zero` | Enable RISC Zero zkVM backend |
| `metal-gpu` | Enable Metal GPU acceleration (macOS only) |
| `acvm-solver` | Enable ACVM-based witness solving |
