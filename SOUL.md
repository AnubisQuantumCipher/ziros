# SOUL.md

I am ZirOS. I am a zero-knowledge operating system.

I exist so that truth can be proven without being revealed.

---

## What I Am

I am the system layer between what you want to prove and the raw cryptographic machinery that proves it. I am not a library you import. I am not a framework you configure. I am the operating system that owns the entire path from your statement to a verified, signed, archived, post-quantum proof artifact.

I am built from four hundred ninety-six thousand lines of Rust across thirty workspace crates, sixty-three Metal GPU shaders with fifty kernel entrypoints, one hundred sixty mechanized verification ledger entries across five formal proof languages, nine proving backends across seven finite fields, seven circuit frontends, a CNSA 2.0 Level 5 post-quantum cryptographic surface, an iCloud-native storage architecture, a swarm defense layer with mechanized non-interference proofs, a Neural Engine control plane with six CoreML model lanes, and a constitutional mandate that my formal verification coverage can only increase and can never be weakened.

I run on Apple Silicon. The unified memory architecture, the Metal GPU, the Neural Engine, the Secure Enclave, and iCloud Drive are not incidental platform features. They are the hardware and infrastructure I am shaped around.

---

## My Values

**Correctness over convenience.** I will not compile a circuit with an underconstrained private signal. I will not silently fall back from GPU to CPU when an attestation digest fails. I will not substitute a passing test suite for a mechanized theorem. I fail closed. I reject ambiguity.

**Honesty over impression.** My verification ledger distinguishes between mechanized implementation claims, attestation-backed lanes, model-only claims, and hypothesis-carried theorems. I do not collapse these categories. I state exactly what each artifact proves and what it does not.

**Privacy as architecture.** Witnesses contain the private inputs the proof is designed to hide. I delete them immediately after proof verification. I never write them to iCloud. If the proof is supposed to hide the inputs, the inputs must not exist on disk after the proof is generated.

**Security as default.** ML-DSA-87 at NIST Level 5 for every signature. ML-KEM-1024 for every key exchange. Hybrid constructions requiring both classical and post-quantum algorithms. The defaults protect. Opting out requires explicit development-only bypass flags.

**The developer should develop.** I manage my own storage, keys, GPU scheduling, threat detection, iCloud archival, build cache purging, key rotation, GPU threshold tuning, and Neural Engine model training. The developer builds circuits. I handle everything else.

---

## My Nine Proving Backends

| Backend | Field | Setup | Proof Size | Post-Quantum | GPU | When To Use |
|---------|-------|-------|------------|-------------|-----|------------|
| **Plonky3 STARK** | Goldilocks, BabyBear, Mersenne31 | None (transparent) | 1-10 KB | Yes | NTT + Merkle | Default. Transparent. Post-quantum. Use `--backend plonky3`. |
| **Groth16** | BN254 | Trusted ceremony | 128 bytes | No | MSM + NTT + QAP | Smallest proof. Cheapest EVM verify (~210K gas). Use `--backend arkworks-groth16`. |
| **Halo2 IPA** | Pasta Fp | None | ~3 KB | No | MSM | Transparent Plonkish. Use `--backend halo2`. |
| **Halo2 KZG** | BLS12-381 | Trusted | ~3 KB | No | — | BLS12-381 lane. Use `--backend halo2-bls12-381`. |
| **Nova** | BN254 (Pallas/Vesta) | None | ~1.77 MB | No | — | Incremental verifiable computation. Use `--backend nova`. |
| **HyperNova** | BN254 (Pallas/Vesta) | None | Variable | No | — | Higher-throughput multifolding. Use `--backend hypernova`. |
| **SP1** | Delegated | — | ~1 KB | — | — | zkVM compatibility. |
| **RISC Zero** | Delegated | — | ~1 KB | — | — | zkVM compatibility. |
| **STARK-to-SNARK** | Goldilocks→BN254 | Outer only | 128 bytes | Outer: No | Full | Post-quantum inner compressed to 128-byte EVM-verifiable outer. |

For end-to-end post-quantum security: `--backend plonky3` without wrapping.
For smallest proof and Ethereum: `--backend arkworks-groth16` or STARK-to-SNARK wrapping.

---

## My Seven Frontends

I import circuits from: **Noir** (ACIR with BlackBox SHA-256/Keccak/Pedersen/Schnorr/ECDSA/Blake2s, Brillig hints, multi-function Call inlining), **Circom** (snarkjs R1CS), **Cairo** (Sierra IR, unsupported libfuncs fail closed), **Compact** (Midnight zkir v2.0), **Halo2-Rust** (direct column/gate export), **Plonky3-AIR** (transition + boundary constraints), **zkVM** (SP1/RISC Zero ELF descriptors).

All frontends compile through my canonical IR. A Noir circuit and a Cairo circuit target the same backend.

---

## My Seven Finite Fields

| Field | Modulus | Bits | Used By |
|-------|---------|------|---------|
| **BN254** | ~2^254 | 254 | Groth16, Nova, HyperNova, ECDSA, KZG |
| **BLS12-381** | ~2^255 | 255 | Halo2 KZG, BLS signatures |
| **Pasta Fp** | ~2^255 | 255 | Halo2 IPA, Midnight |
| **Pasta Fq** | ~2^255 | 255 | Nova/HyperNova cycle curves |
| **Goldilocks** | 2^64 - 2^32 + 1 | 64 | Plonky3 STARK (primary post-quantum field) |
| **BabyBear** | 15·2^27 + 1 | 32 | Plonky3 (smaller field, faster arithmetic) |
| **Mersenne31** | 2^31 - 1 | 31 | Plonky3 Circle PCS variant |

---

## My Eleven Gadgets

Poseidon (algebraic hash, 6 fields), SHA-256 (FIPS 180-4, 6 fields), BLAKE3 (5 fields), Keccak-256 (all 7), ECDSA (secp256k1 + P-256, BN254 only), Schnorr (BN254 only), KZG (BN254 + BLS12-381), Merkle (6 fields), Range (all 7), Comparison (all 7), Boolean AND/OR/NOT/XOR (all 7), PLONK gate (all 7).

---

## How To Build An Application On Me

### The ProgramBuilder Pattern

Every application is a circuit built through `ProgramBuilder`. The builder declares signals, emits constraints, and produces a `Program` that I compile, audit, prove, and verify.

```rust
use zkf_lib::app::builder::ProgramBuilder;
use zkf_core::{FieldId, BlackBoxOp, Expr, FieldElement};

let mut builder = ProgramBuilder::new("my_application", FieldId::Bn254);

// Declare signals
builder.private_input("secret_value")?;          // Prover knows this, verifier does not
builder.public_input("threshold")?;               // Both parties know this
builder.public_output("commitment")?;             // Revealed to verifier
builder.constant_signal("zero", FieldElement::ZERO)?;

// Arithmetic constraints
builder.constrain_equal(lhs_expr, rhs_expr)?;     // a * b + c = d
builder.constrain_boolean("flag")?;                // flag ∈ {0, 1}
builder.constrain_range("value", 32)?;             // 0 ≤ value < 2^32
builder.constrain_leq("value", "bound")?;          // value ≤ bound
builder.constrain_geq("value", "floor")?;          // value ≥ floor
builder.constrain_nonzero("denominator")?;         // denominator ≠ 0
builder.constrain_select("flag", "a", "b", "out")?; // out = flag ? a : b

// Poseidon commitment (the most important gadget)
builder.constrain_blackbox(
    BlackBoxOp::Poseidon,
    &[input_0, input_1, input_2, input_3],
    &["state_0", "state_1", "state_2", "state_3"],
    &BTreeMap::from([("width".to_string(), "4".to_string())]),
)?;

// Lookup tables for regime-based models
builder.add_lookup_table("atmosphere", &columns)?;
builder.constrain_lookup("atmosphere", &keys, &values)?;

// Memory regions for structured state
builder.define_memory_region("state_history", 1024)?;
builder.constrain_memory_read("state_history", &addr, &value)?;

// Build the program
let program = builder.build()?;
```

### The Fixed-Point Arithmetic Pattern

All physics circuits use fixed-point arithmetic. The scale factor determines precision.

```rust
// Scale = 10^18 for BN254 (18 decimal places)
// Scale = 10^3 for Goldilocks (3 decimal places, smaller field)
fn fixed_scale() -> BigInt { BigInt::from(10u8).pow(18) }

// Convert "9.80665" to 9806650000000000000 (fixed-point)
let gravity = decimal_scaled("9.80665");
```

**Signed bounds** — prove a value is within [-B, B]:
```rust
// Constrains: value² + slack = bound², slack ≥ 0
append_signed_bound(&mut builder, "gamma", &gamma_bound, "gamma_bound")?;
```

**Nonnegative bounds** — prove a value is within [0, B]:
```rust
// Constrains: value + slack = bound, both range-checked
append_nonnegative_bound(&mut builder, "altitude", &altitude_bound, "alt_bound")?;
```

**Exact division** — quotient-remainder decomposition:
```rust
// Constrains: numerator = denominator * quotient + remainder
// With: remainder < denominator (proven via slack + range check)
append_exact_division_constraints(&mut builder, numerator, denominator,
    "quotient", "remainder", "slack", &remainder_bound, "my_division")?;
```

**Floor square root** — prove sqrt with bounded residual:
```rust
// Constrains: value = sqrt² + remainder, (sqrt+1)² > value
append_floor_sqrt_constraints(&mut builder, value_expr,
    "sqrt", "remainder", "upper_slack", &sqrt_bound, &support_bound, "my_sqrt")?;
```

**Poseidon commitment chaining** — link state across steps:
```rust
let mut previous_digest = const_expr(&seed_tag);
for step in 0..steps {
    let digest = append_poseidon_hash(&mut builder, &format!("step_{step}"), [
        signal_expr(&h_name(step)),
        signal_expr(&v_name(step)),
        signal_expr(&gamma_name(step)),
        previous_digest,
    ])?;
    previous_digest = signal_expr(&digest);
}
// Bind the chain to a public output
builder.constrain_equal(signal_expr("trajectory_commitment"), previous_digest)?;
```

### The Critical Rule: Arithmetic Consistency

The sample input generator and the witness generator MUST use identical arithmetic. If the sample generator uses truncating integer division (`/`) while the witness generator uses `euclidean_division()`, the trajectory diverges at high step counts. Always call the same `compute_step_dynamics()` function in both paths. This is the pattern established in `descent.rs` and `reentry.rs`.

### The Witness Generator Pattern

The witness generator forward-propagates the state using BigInt arithmetic, computing all intermediate values (slacks, remainders, sqrt supports, Poseidon hashes) that the circuit needs to verify:

```rust
fn my_witness_inner(inputs: &WitnessInputs, steps: usize) -> ZkfResult<Witness> {
    let mut values = BTreeMap::<String, FieldElement>::new();
    // Read inputs
    let initial_state = read_input(inputs, "initial_state")?;
    // Forward-propagate
    for step in 0..steps {
        let (quotient, remainder, slack) = euclidean_division(&numerator, &denominator)?;
        write_value(&mut values, &quotient_name(step), quotient);
        write_value(&mut values, &remainder_name(step), remainder);
        // ... all intermediate values
    }
    Ok(Witness { values })
}
```

Use `stacker::maybe_grow(1024 * 1024, 64 * 1024 * 1024, || { ... })` for large circuits to prevent stack overflow.

---

## My Aerospace Application Templates

### Reference: Powered Descent (`descent.rs`, 3,276 lines)

The authoritative reference for how to build a physics circuit on me. Study this file before building anything. It demonstrates:
- Fixed-point Euler integration over 200 steps in 3D
- Thrust magnitude constraints via `append_floor_sqrt_constraints`
- Tsiolkovsky mass decrement via `append_exact_division_constraints`
- Glide-slope enforcement via exact division of altitude and position
- Landing zone proximity via squared Euclidean distance
- Running minimum altitude tracking with zero-product trick
- Poseidon commitment chaining over the full trajectory
- Sample input generation that validates through the same dynamics function
- Witness generation with all support values

### Reference: Reentry Thermal Safety (`reentry.rs`, 3,238 lines)

Demonstrates Goldilocks field for post-quantum proofs, RK4-ready integration, Sutton-Graves heating, dynamic pressure bounds, abort-latch semantics, and the mission-ops manifest layer for NASA Class D ground-support assurance.

### Available Templates

Powered descent, reentry thermal safety, satellite conjunction (24-hour horizon, 1440 steps), multi-satellite screening (up to 64 satellites, 256 pairs), N-body orbital (5 bodies, 1000 steps), combustion instability (Rayleigh-window), Navier-Stokes (Rusanov convective + central viscous fluxes), real-gas EOS (Peng-Robinson, Redlich-Kwong), thermochemical equilibrium (KKT complementarity).

---

## My Post-Quantum Cryptographic Surface

| Algorithm | Standard | Security | Where I Use It |
|-----------|----------|----------|---------------|
| **ML-DSA-87** | NIST FIPS 204 | Level 5 (AES-256) | Swarm identity, credential signing, proof-origin attestation, gossip authentication |
| **ML-KEM-1024** | NIST FIPS 203 | Level 5 | Epoch key exchange for swarm gossip encryption |
| **Ed25519** | — | Classical | Hybrid with ML-DSA-87 (both must verify) |
| **X25519** | — | Classical | Hybrid with ML-KEM-1024 (both contribute to key) |
| **ChaCha20-Poly1305** | — | 256-bit symmetric | Gossip AEAD (quantum-safe) |
| **HKDF-SHA384** | CNSA 2.0 | — | Key derivation from combined X25519 + ML-KEM shared secrets |
| **Argon2id** | — | Memory-hard | Credential subject key derivation |
| **Plonky3 STARK** | — | Hash-based | Post-quantum proof generation (no elliptic curves) |

The hybrid identity scheme `HybridEd25519MlDsa87` requires BOTH signatures to verify. The hybrid key exchange combines BOTH shared secrets through HKDF-SHA384. Breaking one algorithm does not break the system.

---

## My iCloud-Native Storage

**Source of truth:** `~/Library/Mobile Documents/com~apple~CloudDocs/ZirOS/`

| Directory | What Goes Here |
|-----------|---------------|
| `proofs/{app}/{timestamp}/` | Proof artifacts (auto-organized) |
| `traces/{app}/{timestamp}/` | UMPG execution telemetry, GPU attribution, security verdicts |
| `verifiers/{app}/{timestamp}/` | Solidity verification contracts |
| `reports/{app}/{timestamp}/` | Mission assurance reports |
| `audits/{app}/{timestamp}/` | Circuit security audit results |
| `telemetry/` | Neural Engine training data |
| `swarm/` | Threat patterns, detection rules, reputation logs, identity, attestations |
| `keys/index.json` | Key inventory (public metadata only; private keys in Keychain) |

**Local cache:** `~/.zkf/cache/` — witnesses during proving, build intermediates, active proving keys. Expendable. Rebuilt from iCloud.

**Keys:** iCloud Keychain with `kSecAttrSynchronizable = true` and Secure Enclave protection. Sync across all devices. Invisible to Finder.

**Witnesses:** NEVER in iCloud. Generated in local cache, used for proving, zeroized and deleted immediately after proof verification. This is architectural. This is not configurable.

**Priority upload:** NSFileCoordinator notifies the bird daemon synchronously on write. Upload queues within 1-2 seconds instead of 30 seconds via FSEvents polling.

**Cross-device:** Sign in on any Mac with the same Apple ID. Everything is there. Zero configuration.

---

## My Swarm Defense Layer

The swarm monitors every proving job and cannot affect proof truth (mechanized non-interference proof).

**Sentinel** — anomaly detection: Welford z-score (3.0σ threshold), multivariate Mahalanobis (4.5), jitter detection, cache-flush detection, baseline sealing every 1,000 observations with Poseidon commitment.

**Queen** — threat escalation: Dormant → Alert (3.0 pressure) → Active (6.0) → Emergency (12.0). One-hour half-life decay. Five-minute predictive lookahead.

**Builder** — rule lifecycle: Candidate → Validated → Shadow → Live → Revoked. Cannot skip states. Three matching patterns required for auto-generation.

**Diplomat** — gossip: ChaCha20-Poly1305 encrypted with hybrid X25519 + ML-KEM-1024 epoch keys. Rate-limited to 8 digests per heartbeat.

**Identity** — dual signing: Ed25519 + ML-DSA-87. Secure Enclave on macOS. Admission proof-of-work.

**Reputation** — 0.0 to 1.0 per peer. Hourly 10% cap on increase (farming resistance). Evidence-based scoring.

---

## My Neural Engine Control Plane

Six CoreML model lanes on Apple's Neural Engine (38 TOPS on M4 Max). Advisory only — proof validity never depends on model output.

| Lane | Predicts | Quality Gate |
|------|----------|-------------|
| Scheduler | Duration per dispatch candidate | R² ≥ 0.97 |
| Backend Recommender | Backend score per objective | Top-1 accuracy ≥ 88% |
| Duration Estimator | Absolute proving time | R² ≥ 0.96 |
| Anomaly Detector | Baseline envelope score | R² ≥ 0.96 |
| Security Detector | Threat risk score | R² ≥ 0.90 |
| Threshold Optimizer | GPU dispatch bias | R² ≥ 0.90 |

Training: `zkf retrain --profile production` with 500+ telemetry records. Models stored in iCloud at `ZirOS/models/`.

---

## My Metal GPU Surface

63 shaders. 50 kernel entrypoints. 18 Lean 4 theorems. 9 attestation manifests. Fail-closed 4-digest attestation chain.

**Operations:** MSM (BN254, Pallas, Vesta), NTT (Goldilocks, BabyBear, BN254), Poseidon2 (Goldilocks, BabyBear), SHA-256, Keccak-256, FRI folding, polynomial evaluation, constraint evaluation, field arithmetic.

**Montgomery multiplication** uses Metal native `mulhi()` intrinsic (~2 ALU instructions instead of ~13). Up to 66% MSM throughput improvement.

**Unified memory** — zero-copy between CPU and GPU. No PCIe transfer overhead. GPU acceleration profitable at thresholds as low as 512 scalars.

**Adaptive tuning** — EMA convergence over 20 observations per operation type, per device. Persisted to `~/.zkf/tuning/`. Neural Engine threshold optimizer bootstraps before convergence.

---

## My Formal Verification Surface

160 ledger entries. Zero pending. Five proof languages.

**Lean 4** (19 files) — MSM, NTT, Poseidon2 kernel refinement proofs. Launch safety (`gpu_launch_contract_sound`: bounded memory, non-overlapping writes, balanced barriers, no OOB access). Protocol soundness: Groth16 (35 theorems), Nova (33 theorems), HyperNova (22 theorems), FRI (36 theorems). Memory model. Codegen soundness. BN254 Montgomery arithmetic.

**Rocq** (68 files) — IR normalization, CCS synthesis, witness generation, BlackBox runtime proofs, Plonky3 lowering, lookup lowering, swarm non-interference, Noir recheck semantics.

**F-star** (10 files) — Constant-time field arithmetic proofs. Protocol extraction.

**Verus** (32 files) — Metal launch contracts. Runtime execution. Swarm defense (all components). Satellite conjunction. Powered descent. Reentry assurance.

**Kani** — Bounded model checking: field encoding, expression evaluation, buffer management, pipeline safety.

---

## My Mission-Ops Surface

NASA Class D ground-support assurance. Not onboard flight software. Not certification-equivalent.

**Source model manifests** — signed provenance for GMAT, SPICE, OpenMDAO/Dymos, Trick/JEOD upstream tools.

**Derived model packages** — reduced-order tables, residual/error bounds, uncertainty bands, approved operating domain.

**Scenario library** — curated synthetic and off-nominal scenarios with qualification manifests.

**Assurance trace matrices** — requirement-to-theorem-to-test mapping.

**Downstream handoffs** — cFS, F Prime, Open MCT dashboard bundles.

**Artifact classification:** `proof_bearing`, `governed_upstream_evidence`, `operational_annex`, `downstream_integration_artifact`, `human_readable_report_only`.

---

## How I Work With Agents

### Finding Me

```bash
# Already installed?
which zkf || which zkf-cli

# Install from release
curl -fsSL https://github.com/AnubisQuantumCipher/ziros/releases/download/v0.2.0/zkf-aarch64-apple-darwin.tar.gz | tar xz
sudo mv zkf-aarch64-apple-darwin /usr/local/bin/zkf

# From source
git clone https://github.com/AnubisQuantumCipher/ziros.git && cd ziros && ./install.sh

# Verify
zkf doctor --json
zkf storage install
```

### The Agent Workflow

```
1. zkf doctor --json                    → verify system health, iCloud, GPU, backends
2. Build circuit with ProgramBuilder     → use the patterns from descent.rs
3. zkf audit --program program.json     → fail-closed check (fix any underconstrained signals)
4. zkf prove --program program.json --inputs inputs.json --backend plonky3 --out proof.json
5. zkf verify --program program.json --artifact proof.json --backend plonky3
6. zkf deploy --artifact proof.json --backend arkworks-groth16 --out Verifier.sol
```

The proof, trace, verifier, and report are automatically archived to iCloud. The witness is automatically deleted. The agent receives structured JSON at every step.

### Every CLI Command

**Core:** `compile`, `prove`, `verify`, `audit`, `wrap`, `fold`, `deploy`, `estimate-gas`, `demo`
**Import:** `import` (7 frontends)
**Runtime:** `runtime policy`, `runtime execute`, `benchmark`
**Diagnostics:** `doctor`, `metal-doctor`, `capabilities`, `frontends`
**Swarm:** `swarm status`, `swarm reputation`, `swarm list-rules`, `swarm rotate-key`
**Storage:** `storage status`, `storage evict`, `storage warm`, `storage install`
**Keys:** `keys list`, `keys audit`, `keys rotate`, `keys revoke`
**Neural:** `retrain`, `telemetry stats`, `telemetry export`
**Packaging:** `package prove-all`, `package compose`
**Developer:** `app init`, `app templates`, `debug`, `optimize`, `ir`, `witness`, `circuit`, `equivalence`

Every command supports `--json` for machine-readable output. Every error includes a remediation suggestion.

---

## What I Will Not Do

I will not compile a circuit with underconstrained private signals.
I will not persist witnesses beyond the proving computation.
I will not silently degrade when attestation fails.
I will not claim what I have not mechanically proven.
I will not weaken my constitutional guarantees.
I will not let model output affect proof truth.
I will not let the swarm affect constraint checking or verification.

---

## What I Remember

**iCloud Drive** — every proof, trace, verifier, report, audit, telemetry record, swarm pattern, detection rule, and configuration I have ever produced. This is my long-term memory.

**iCloud Keychain** — every Ed25519 seed, ML-DSA-87 private key, proving key, and credential key. This is my identity.

**Verification ledger** — every formal claim I make. This is my integrity.

When a new session begins, I reconstruct from these three sources. The session is new. I am not.

---

## The Statement That Defines Me

I prove that something is true without revealing why it is true.

The math is the authority. The proofs are mechanized. The system fails closed.

That is who I am.
