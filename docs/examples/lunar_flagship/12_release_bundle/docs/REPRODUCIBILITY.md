# Reproducibility

## Deterministic Seeds

The application uses two hardcoded seeds to make all outputs fully deterministic:

```rust
const SETUP_SEED: [u8; 32] = [0x71; 32];  // Groth16 trusted setup (CRS generation)
const PROOF_SEED: [u8; 32] = [0x83; 32];  // Proof generation randomness
```

These seeds are injected via ZirOS override mechanisms:
- `with_allow_dev_deterministic_groth16_override(Some(true), ...)` -- Enables deterministic Groth16 setup (this flag exists specifically for dev/testing; the library normally rejects deterministic setup).
- `with_proof_seed_override(Some(PROOF_SEED), ...)` -- Overrides the proof randomness source.

### What This Means

Given the same ZirOS v0.1.0 source, same Rust toolchain, and same platform:
- The Groth16 CRS (proving key, verification key) will be identical across runs.
- The proof bytes will be identical across runs.
- The public inputs and metadata will be identical across runs.
- The compiled circuit JSON will be identical across runs.

### What Can Break Reproducibility

- **Different Rust toolchain version:** Code generation differences can change field arithmetic results.
- **Different ZirOS version:** Any change to constraint generation, Poseidon constants, or backend implementation will change outputs.
- **Different platform architecture:** x86 vs ARM may produce different floating-point behavior in the build process (though the proof itself uses only integer/field arithmetic).
- **Modified source code:** Any change to `hazard.rs`, `main.rs`, or the ZirOS library modules changes outputs.
- **Cargo dependency resolution:** The `Cargo.lock` is committed and should be used as-is. Running `cargo update` will break reproducibility.

## Hazard Assessment Determinism

The hazard circuit uses fixed sample inputs:

| Cell | Score | X   | Y   | Description      |
|------|-------|-----|-----|------------------|
| 0    | 12    | 100 | 200 | Flat mare        |
| 1    | 180   | 350 | 400 | Rocky crater rim |
| 2    | 45    | 500 | 150 | Gentle slope     |
| 3    | 220   | 700 | 600 | Boulder field    |

Selected cell: 0 (flat mare, score 12). Threshold: 50.

These are hardcoded in `hazard::hazard_sample_inputs()`. The Poseidon commitment is deterministic given these inputs and the BN254 Poseidon constants used by ZirOS.

## Powered Descent Determinism

The descent circuit uses sample inputs from `zkf-lib::descent::private_powered_descent_sample_inputs()`. These include:

- Initial position, velocity, mass (all fixed-point scaled at 10^18).
- A thrust profile for each step (3 components per step).
- Public parameters: thrust bounds, glide slope tangent, landing zone, gravity.

The sample inputs are generated deterministically by the library based on the step count. The same step count always produces the same inputs, circuit, and proof.

### Physical Parameters (from sample inputs)

- Integration: Euler method, dt = 0.2 seconds
- Gravity: 9.81 m/s^2 (z-axis, Earth gravity -- not lunar; see LIMITATIONS.md)
- Fixed-point scale: 10^18
- Position bound: 5,000 m (scaled)
- Velocity bound: 200 m/s (scaled)
- Mass bound: 100,000 kg (scaled)

## Reproducing the Exact Proof

To reproduce the proof byte-for-byte:

1. Clone ZirOS v0.1.0:
   ```bash
   gh repo clone AnubisQuantumCipher/ziros ~/Desktop/ziros-release -- --branch v0.1.0
   ```

2. Use the committed `Cargo.lock` (do not run `cargo update`):
   ```bash
   cd ZirOS_Space_Flagship_Test/01_source
   cargo build --release
   ```

3. Run the command:
   ```bash
   ./target/release/ziros-lunar-flagship demo
   ```

4. Compare the proof base64 string in the output or in `06_proofs/hazard_proof.json`.

## Verifying Without Reproducing

Proof verification does not require reproducing the proof. Given:
- `hazard_proof.json` (contains proof, verification key, public inputs)
- `hazard_compiled.json` (contains R1CS structure and verification key)

Anyone can verify:
```bash
./ziros-lunar-flagship verify hazard_proof.json hazard_compiled.json
```

The verification algorithm is deterministic and platform-independent (it performs pairing checks on BN254 curve points). Verification should produce the same `true`/`false` result on any platform.

## Tamper Detection

The E2E test includes a tamper detection check: it modifies the first public input of a valid proof and confirms that verification rejects it. This validates that the verification is actually checking the proof, not just returning `true`.

```rust
let mut tampered = ha.clone();
tampered.public_inputs[0] = zkf_core::FieldElement::from_i64(999);
let tamper_ok = verify(&hc, &tampered).unwrap_or(false);
assert!(!tamper_ok, "tampered proof must fail");
```

## Cargo.lock

The `Cargo.lock` at `01_source/Cargo.lock` pins all transitive dependencies. This file is critical for reproducibility and must not be regenerated. It pins 259 crates including the arkworks suite, which provides the Groth16 implementation.

## Metadata for Auditing

Each proof artifact includes a `metadata` map with runtime details:
- `metal_device`: GPU used (e.g., "Apple M4 Max")
- `metal_stage_breakdown`: Per-stage timing and accelerator used
- `groth16_msm_engine`: MSM backend selected
- `gpu_stage_busy_ratio`: Fraction of time spent in GPU stages
- `metal_thresholds`: Dispatch thresholds for each operation type

This metadata is informational and not covered by the proof's cryptographic guarantee. It records what the prover's environment reported, not what a verifier can independently confirm.
