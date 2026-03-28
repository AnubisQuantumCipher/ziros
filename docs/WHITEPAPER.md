# ZKF: A Universal Zero-Knowledge Framework

**Version 2.0 — March 2026**

Historical design note: this document is architectural context, not the canonical live readiness
surface. For current capability, trust-model, and program-family truth, use
[`CANONICAL_TRUTH.md`](/Users/sicarii/Projects/ZK%20DEV/docs/CANONICAL_TRUTH.md),
[`support-matrix.json`](/Users/sicarii/Projects/ZK%20DEV/support-matrix.json), and
`zkf capabilities --json`.

---

## Abstract

ZKF is a universal zero-knowledge framework that solves the fragmentation problem in ZK development. Today, circuits written for one proof system cannot be used with another — Noir targets Barretenberg, Circom targets Groth16, Cairo targets STARK, and Compact targets Midnight. ZKF introduces a layered architecture (frontend → canonical interchange → lowered backend dialect → backend) that decouples circuit authoring from proving, enabling any circuit to be proven with any compatible backend. Quantitative counts in this document are a March 2026 snapshot and may drift from the live repository; treat the live truth sources above as authoritative.

---

## 1. Motivation: The Fragmentation Problem

The zero-knowledge ecosystem suffers from a fundamental interoperability gap. Each proof system defines its own:

- **Circuit language**: Noir (ACIR), Circom (R1CS), Cairo (Sierra), Compact (Midnight DSL), Halo2 (Rust traits), Plonky3 (AIR)
- **Constraint system**: R1CS, Plonkish, AIR, CCS
- **Finite field**: BN254, Pasta, BLS12-381, Goldilocks, BabyBear, Mersenne31
- **Proof format**: Groth16, KZG, IPA, FRI, IVC folding

A developer who writes a circuit in Noir cannot benchmark it against Plonky3. A project using Halo2 cannot produce a Groth16 proof for cheap on-chain verification. A Cairo program cannot be folded with Nova.

ZKF eliminates these barriers with a universal intermediate representation and a trait-based backend system that abstracts over all major proof systems.

---

## 2. Architecture

ZKF uses a three-layer architecture:

```
┌────────────────────────────────────────────────────┐
│  Frontends                                          │
│  Noir · Circom · Cairo · Compact · Halo2 · Plonky3 │
│  zkVM (SP1, RISC Zero) · #[zkf::circuit] DSL       │
└──────────────────┬─────────────────────────────────┘
                   │ FrontendEngine::compile_to_program_family()
                   ▼
┌────────────────────────────────────────────────────┐
│  Program Families                                   │
│  Canonical ZIR v1 (lossless interchange)            │
│  Lowered IR v2 (backend-consumption dialect)        │
└──────────────────┬─────────────────────────────────┘
                   │ BackendEngine::compile() + prove()
                   ▼
┌────────────────────────────────────────────────────┐
│  Backends                                           │
│  Groth16 · Halo2 · Plonky3 · Nova · HyperNova      │
│  SP1 · RISC Zero · Midnight Compact                 │
│  + Metal GPU acceleration (macOS)                   │
└────────────────────────────────────────────────────┘
```

### 2.1 Frontend Layer

Each frontend implements the `FrontendEngine` trait:

```rust
pub trait FrontendEngine: Send + Sync {
    fn compile_to_program_family(
        &self,
        artifact: &Value,
        options: FrontendImportOptions,
    ) -> ZkfResult<FrontendProgram>;
    fn compile_to_ir(&self, artifact: &Value, options: FrontendImportOptions)
        -> ZkfResult<Program>;
    fn inspect(&self, artifact: &Value) -> ZkfResult<FrontendInspection>;
    fn probe(&self, artifact: &Value) -> FrontendProbe;
}
```

**Supported frontends** (7):

| Frontend | Input Format | Coverage |
|----------|-------------|----------|
| Noir | ACIR JSON (v0.46, beta.9/10, v1) | Full: AssertZero, RANGE, AND/XOR, BlackBox, Brillig, MemoryOps |
| Circom | R1CS JSON | Full: Quadratic A*B=C triples, snarkjs witness |
| Cairo | Sierra IR | Comprehensive: felt252, int ops, arrays, enums, Poseidon/Pedersen |
| Compact | Midnight DSL descriptor | Full: constraint-type mapping from ZIR |
| Halo2 | ZkfHalo2Export JSON | Full: columns, gates, copy constraints |
| Plonky3 AIR | ZkfPlonky3AirExport JSON | Full: transition + boundary constraints |
| zkVM | SP1/RISC Zero ELF descriptor | Routing to native SDK backends |

### 2.2 Intermediate Representation

The ZKF IR represents circuits as typed constraint systems over named signals:

```rust
pub struct Program {
    pub name: String,
    pub field: FieldId,
    pub signals: Vec<Signal>,
    pub constraints: Vec<Constraint>,
    pub witness_plan: WitnessPlan,
    pub metadata: BTreeMap<String, String>,
}
```

**Constraint types**: `Equal`, `Boolean`, `Range`, `BlackBox` (opaque gadget hooks for SHA256, Poseidon2, ECDSA, Keccak256, Pedersen, Schnorr, Blake2s, KZG pairing).

**Expression tree**: `Const`, `Signal`, `Add`, `Sub`, `Mul`, `Div` — evaluated over the program's field.

**Optimizations**: Constant folding, signal deduplication, dead constraint elimination.

### 2.3 Backend Layer

Each backend implements the `BackendEngine` trait:

```rust
pub trait BackendEngine: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> BackendCapabilities;
    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram>;
    fn prove(&self, compiled: &CompiledProgram, witness: &Witness)
        -> ZkfResult<ProofArtifact>;
    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact)
        -> ZkfResult<bool>;
}
```

**Supported backends** (9):

| Backend | Proof System | Field | Setup | Proof Size |
|---------|-------------|-------|-------|------------|
| Arkworks Groth16 | R1CS + pairing | BN254 | Trusted (deterministic) | ~200 bytes |
| Halo2 (IPA) | Plonkish | Pasta Fp/Fq | Transparent | ~3 KB |
| Halo2 (BLS) | Plonkish | BLS12-381 | Transparent | ~3 KB |
| Plonky3 | STARK + FRI | Goldilocks/BabyBear/M31 | Transparent | ~1-10 KB |
| Nova | IVC Folding | Pallas/Vesta | Trusted | Variable |
| HyperNova | CCS Multifolding | BN254 | Trusted | Variable |
| SP1 | zkVM (STARK) | Native | None | ~1 KB |
| RISC Zero | zkVM (STARK) | Native | None | ~1 KB |
| Midnight Compact | Custom | Custom | Server-side | Variable |

---

## 3. ZKF IR Specification

### 3.1 Field Support

ZKF supports 7 finite fields, each mapped to optimal backends:

| Field | Size (bits) | Optimal Backend | Characteristic |
|-------|------------|-----------------|----------------|
| BN254 | 254 | Groth16, Nova | Pairing-friendly |
| Pasta Fp | 255 | Halo2 | Pallas base field |
| Pasta Fq | 255 | Halo2 | Vesta scalar field |
| BLS12-381 | 255 | Halo2-BLS | Pairing-friendly |
| Goldilocks | 64 | Plonky3 | 2^64 - 2^32 + 1 |
| BabyBear | 31 | Plonky3 | 2^31 - 2^27 + 1 |
| Mersenne31 | 31 | Plonky3 | 2^31 - 1 |

### 3.2 Witness Generation

ZKF's witness generator evaluates the expression DAG topologically, resolving signal dependencies. For frontend-specific semantics (e.g., Noir's Brillig VM or Circom's snarkjs), ZKF delegates to solver plugins via the `WitnessSolver` trait.

### 3.3 Constraint Debugger

When a witness fails constraint checking, ZKF's debugger produces:
- Per-constraint trace with symbolic evaluation
- Witness flow graph (DAG of signal dependencies)
- Under-constrained analysis (signals not fully determined)

---

## 4. STARK-to-SNARK Wrapping

ZKF's wrapping pipeline is the bridge between fast STARK proving and cheap on-chain verification. The pipeline compresses a Plonky3 STARK proof (1-10 KB, ~2.56 ms verify) into a Groth16 proof (~200 bytes, ~210K gas on Ethereum).

### 4.1 Architecture

```
Plonky3 STARK Proof
    │
    ▼
FRI Verifier Circuit (1,088 lines)
    │  Encodes FRI verification as R1CS constraints
    │  over BN254
    ▼
Non-native Goldilocks Arithmetic
    │  64-bit Goldilocks field operations
    │  inside 254-bit BN254 constraints
    ▼
Poseidon2 Gadget (Goldilocks params)
    │  Matches exact Plonky3 Poseidon2
    │  round constants and MDS matrix
    ▼
AIR Evaluation Circuit
    │  Verifies AIR constraint satisfaction
    │  at query points
    ▼
Duplex Challenger
    │  Reproduces Fiat-Shamir transcript
    │  inside R1CS
    ▼
Arkworks Groth16 Prove + Verify
    │
    ▼
Groth16 Proof (~200 bytes, BN254)
```

### 4.2 Critical Implementation Details

**Non-native field arithmetic**: Goldilocks (64-bit) operations are emulated inside BN254 (254-bit) R1CS. Each Goldilocks multiplication requires range-check constraints to prevent overflow. The implementation uses a limb decomposition strategy that minimizes constraint count.

**FRI verification**: The FRI verifier circuit encodes the full FRI protocol: fold operations at each layer, Merkle proof verification, and final polynomial evaluation. Poseidon2 is used for Merkle hashing, matching Plonky3's configuration exactly (pinned to p3-poseidon2 v0.4.2).

**Deterministic round constants**: Plonky3 crate versions are pinned to exact v0.4.2 to ensure round constants, MDS matrices, and RNG derivation are bit-identical between the prover and the wrapping circuit. Any version drift would produce invalid wrapping proofs.

### 4.3 Halo2-to-Groth16 Wrapping

ZKF also supports wrapping Halo2 IPA proofs into Groth16. This uses a commitment-bound re-prove strategy: a SHA-256 commitment over the source proof, verification key, and public inputs is constrained inside a Groth16 circuit.

---

## 5. GPU Acceleration on Apple Silicon

ZKF includes a Metal GPU acceleration layer (`zkf-metal`, 11,980 lines including 3,033 lines of Metal shaders) that exploits Apple Silicon's unified memory architecture for zero-copy CPU-GPU data sharing.

### 5.1 Accelerated Operations

| Operation | Kernel | Use Case |
|-----------|--------|----------|
| MSM (Pippenger, BN254) | `msm_bn254.metal` (533 lines) | Groth16 proving, KZG commitment |
| MSM (Pippenger, Pallas) | `msm_pallas.metal` (470 lines) | Nova/HyperNova IVC folding |
| BN254 NTT | `ntt_bn254.metal` + `field_bn254_fr.metal` | Groth16 FFT/IFFT, QAP witness map |
| NTT (Radix-2) | `ntt_radix2.metal` | Plonky3 polynomial evaluation |
| Poseidon2 | `poseidon2.metal` (490 lines) | STARK Merkle trees, hashing |
| SHA256 | `sha256.metal` | Commitment schemes |
| Keccak256 | `keccak256.metal` | Ethereum-compatible hashing |
| FRI Fold | `fri.metal` | STARK verification |
| Constraint Eval | `constraint_eval.metal` | Polynomial constraint checking |
| Batch Field Ops | `batch_field_ops.metal` | Generic modular arithmetic |

### 5.2 Metal-Accelerated Backends

Three backends have GPU acceleration on Apple Silicon:

| Backend | GPU Stages | Details |
|---------|-----------|---------|
| **Arkworks Groth16** | 3/3 (Metal-complete) | MSM (Pippenger), FFT/NTT (BN254 Fr Montgomery), QAP witness map (7 FFTs) |
| **Plonky3** | 2/2 (Metal-complete) | NTT (Goldilocks/BabyBear), Poseidon2 Merkle hashing |
| **Nova/HyperNova** | 1/1 (Metal-accelerated) | MSM (Pippenger, Pallas curve) for IVC folding via `commit_T()` |

The `metal-first` routing mode auto-selects Metal-complete backends for full GPU proving. Nova/HyperNova MSM acceleration is always active when Metal GPU is available — the Pallas MSM hook is registered at backend initialization and routes through Metal automatically.

### 5.2.1 Hardware-Accelerated Field Arithmetic (v0.3.1)

All 256-bit Montgomery multiplication (BN254 Fq, BN254 Fr, Pallas Fp) and 64-bit Goldilocks field multiplication use Metal's native `mulhi()` intrinsic for the critical 64×64→128 bit wide multiply operation. This replaces a software schoolbook decomposition (~13 ALU instructions) with a single hardware instruction (~2 ALU instructions), yielding up to 66% improvement in MSM kernel throughput on M4 Max. The optimization is a pure arithmetic refactor — no new branches, data-dependent control flow, or behavioral changes are introduced.

### 5.3 BN254 NTT on Metal GPU

The BN254 NTT implementation uses full 4-limb 256-bit CIOS Montgomery multiplication on the GPU. The Groth16 QAP witness map — which requires 7 FFTs (2 IFFTs + 2 coset FFTs for A/B polynomials, 1 IFFT + 1 coset FFT for C, 1 coset IFFT for H) — now runs entirely on Metal with proper coset domain handling that replicates Arkworks' `distribute_powers` semantics.

### 5.4 Scheduling and Tuning

The GPU scheduler automatically decides whether to dispatch to Metal or fall back to CPU based on problem size:

- **Conservative**: GPU only for large operations (>4096 MSM points)
- **Standard**: GPU for medium operations (>1024 points)
- **Aggressive**: GPU for all supported operations

The scheduler reports GPU utilization, memory budget, and per-stage coverage through metadata attached to proof artifacts. Proof artifacts include `metal_device`, `metal_prewarmed_pipelines`, `metal_recommended_working_set_size_bytes`, and `best_msm_accelerator` metadata.

### 5.5 Integration with Plonky3

ZKF replaces Plonky3's default DFT and Merkle tree implementations with Metal-accelerated versions:
- `MetalDft` adapter for `p3-dft`
- `MetalMerkleMmcs` for Merkle tree construction
- Batch NTT for parallel polynomial transforms

---

## 6. Gadget Library

ZKF provides 13 constraint gadget libraries for common cryptographic primitives:

| Gadget | Lines | Description |
|--------|-------|-------------|
| SHA256 | Standard | 64-round compression function |
| Poseidon2 | Standard | State permutation (field-dependent) |
| ECDSA | 993 | secp256k1 signature verification |
| Schnorr | Standard | Schnorr signature verification |
| Merkle | Standard | Merkle tree path verification |
| KZG | Standard | Polynomial commitment pairing check |
| Blake3 | Standard | 7-round compression |
| Keccak256 | Standard | Ethereum-native hash |
| Pedersen | Standard | Pedersen commitment |
| Non-native | Standard | Cross-field arithmetic |
| Boolean | Standard | Boolean constraint |
| Range | Standard | Range proof |
| Comparison | Standard | Less-than circuits |

All gadgets produce ZKF IR constraints and are backend-agnostic.

---

## 7. Benchmarks

### 7.1 Cross-Backend Comparison

ZKF's `benchmark` command generates reproducible comparisons across backends for the same circuit:

```bash
zkf benchmark --out results.json \
  --backends arkworks-groth16,halo2,plonky3 \
  --iterations 10 --parallel
```

Benchmark circuits are parameterized by field and scaled by constraint count (multiply, range, hash, composite).

### 7.2 GPU Acceleration Impact

On Apple M4 Max (40 GPU cores, 48GB unified memory):

- **Plonky3 STARK proving**: Metal-accelerated NTT and Poseidon2 hashing
- **Groth16 MSM**: Pippenger windowing on GPU for >1024-point operations
- **Batch proving**: GPU scheduler optimizes concurrent proof generation

### 7.3 Wrapping Overhead

STARK-to-SNARK wrapping converts large, fast-to-verify STARK proofs into constant-size Groth16 proofs:

- **Input**: Plonky3 STARK proof (1-10 KB)
- **Output**: Groth16 proof (~200 bytes)
- **Verification**: ~210K gas on Ethereum (vs ~2M+ for raw STARK on-chain verification)

---

## 8. CLI and Developer Experience

ZKF ships as a single CLI binary (`zkf`, 18MB stripped) with 30 commands organized into workflows. All commands have short aliases (`i`, `c`, `w`, `p`, `v`, `bench`, `gas`, `caps`, `pkg`) and short flags (`-p`, `-b`, `-o`):

### Discovery
```bash
zkf capabilities          # Show support matrix
zkf frontends             # List available frontends
zkf doctor                # Check system requirements
zkf metal-doctor          # Diagnose Metal GPU
```

### Import → Prove → Deploy
```bash
zkf import --frontend noir --in circuit.json --out program.json
zkf prove --program program.json --inputs inputs.json --out proof.json
zkf wrap --proof proof.json --compiled compiled.json --out wrapped.json
zkf deploy --artifact wrapped.json --backend arkworks-groth16 --out Verifier.sol
```

### Full Pipeline Demo
```bash
zkf demo --json           # One command: circuit → STARK → Groth16 → Solidity (Nova-compressed attestation wrap lane)
```

### Advanced
```bash
zkf benchmark --backends arkworks-groth16,halo2,plonky3 --parallel
zkf fold --manifest pkg.json --inputs steps.json --steps 100 --backend nova
zkf package prove-all --backends all --parallel --jobs 4 --mode metal-first
zkf package compose --backend nova
```

---

## 9. Related Work

| System | Approach | Limitation vs ZKF |
|--------|----------|-------------------|
| Sindri | Cloud proving API | Single backend per circuit; no wrapping |
| Gevulot | Decentralized proving | Network-bound; no frontend unification |
| =nil; Proof Market | Proof marketplace | No cross-backend compilation |
| Succinct SP1 | zkVM prover | SP1-only; no Groth16/Halo2/Plonky3 |
| Nexus | zkVM | Single VM; no circuit-level frontends |

ZKF is unique in combining:
1. **Multi-frontend import** (Noir + Circom + Cairo + Compact + Halo2 + Plonky3 + zkVM)
2. **Multi-backend proving** (9 backends)
3. **Cross-system wrapping** (STARK→SNARK, Halo2→Groth16)
4. **Hardware acceleration** (Metal GPU, unique in ZK tooling)
5. **Solidity verifier generation** (from any wrapped proof)

---

## 10. Roadmap

### Open Source (Apache-2.0)
- ZKF IR specification, all frontends, standard backends (Groth16, Halo2, Plonky3, Nova, HyperNova)
- Gadget library, DSL proc-macro, registry, CLI core
- ~60,000 lines of Rust

### Proving-as-a-Service API
- Hosted proving on Metal GPU infrastructure
- REST API: `/v1/prove`, `/v1/wrap`, `/v1/deploy`, `/v1/benchmark`
- Free tier (10 proofs/month) → Developer ($49/mo) → Team ($199/mo)

### Pro SDK
- Compiled binary with Metal GPU acceleration + STARK-to-SNARK wrapping
- License key system, macOS M-series optimized

---

## Appendix A: Crate Structure

| Crate | Lines | Purpose |
|-------|-------|---------|
| zkf-core | 9,581 | IR, field math, witness gen, debugger, optimizer |
| zkf-frontends | 10,950 | Noir, Circom, Cairo, Compact, Halo2, Plonky3, zkVM importers |
| zkf-backends | 31,350 | 9 backend adapters + wrapping pipeline |
| zkf-backends-pro | 93 | Proprietary backend extensions (BSL-1.1) |
| zkf-gadgets | 5,323 | SHA256, Poseidon, ECDSA, Schnorr, Merkle, KZG, etc. |
| zkf-metal | 11,980 | Metal GPU acceleration (8,594 Rust + 3,033 Metal shaders) |
| zkf-dsl | 1,952 | `#[zkf::circuit]` proc-macro DSL |
| zkf-cli | 12,111 | 30 CLI commands with aliases and short flags |
| zkf-registry | 1,240 | Gadget package management |
| zkf-examples | 177 | Sample circuits |
| zkf-integration-tests | 5,081 | End-to-end test suites |
| zkf-api | 1,564 | Proving-as-a-service API server |
| **Total** | **91,402** | |

## Appendix B: Field Support Matrix

| Field | Backends | GPU Accel | Wrapping Target |
|-------|----------|-----------|-----------------|
| BN254 | Groth16, Nova, HyperNova | MSM, NTT, QAP (3/3 Metal-complete) | — (already SNARK) |
| Pasta Fp/Fq | Halo2, Nova, HyperNova | MSM (Pallas, 1/1 Metal-accelerated) | → Groth16 |
| BLS12-381 | Halo2-BLS | — | — |
| Goldilocks | Plonky3 | NTT, Poseidon2, FRI | → Groth16 |
| BabyBear | Plonky3 | NTT, Poseidon2 | → Groth16 |
| Mersenne31 | Plonky3 | — | — |

---

*ZKF is developed by the ZKF Framework team. For API access, contact: api@zkf.dev*
