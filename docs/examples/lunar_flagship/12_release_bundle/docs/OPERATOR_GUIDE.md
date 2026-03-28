# Operator Guide

## Overview

This guide describes how a mission operator would use the system to generate and verify proofs for a lunar landing scenario. The system has two modes: a fast demo for pipeline validation, and a full mission run for production-scale proof generation.

**Important:** This is a demonstration system. The terrain data is synthetic, the physics uses simplified Euler integration with Earth gravity, and the trusted setup uses deterministic dev seeds. See LIMITATIONS.md for a full accounting.

## Prerequisites

- macOS with Apple Silicon (M-series) for Metal GPU acceleration, or any platform with Rust toolchain
- ZirOS v0.1.0 source at `~/Desktop/ziros-release`
- Rust 2024 edition toolchain
- Approximately 5 GB free RAM for the 200-step descent proof
- 512 MB stack space is allocated automatically by the application

### First-Time Setup

```bash
./04_scripts/setup.sh
```

This checks that Rust is installed and ZirOS v0.1.0 is present at the expected path.

### Building

```bash
./04_scripts/build.sh
```

Produces the release binary at `01_source/target/release/ziros-lunar-flagship`. Build takes 2-5 minutes depending on hardware (full release optimization).

## Mission Workflow

### Step 1: Validate the Pipeline (Demo Mode)

Before committing to a full mission run, validate that the pipeline works:

```bash
./04_scripts/run.sh
```

Expected output:
- Phase 1 (Hazard Assessment): ~40 signals, ~32 constraints, proof generated and verified.
- Phase 2 (1-step Descent): Small circuit, proof generated and verified.
- Total time: approximately 7-10 seconds.

If this fails, do not proceed to full mission. Common failure modes:
- Missing ZirOS source: Check `~/Desktop/ziros-release` exists with `zkf-lib`, `zkf-backends`, `zkf-core`.
- Build errors: Run `./04_scripts/build.sh` again with a clean build (`cargo clean --manifest-path 01_source/Cargo.toml`).

### Step 2: Run Full Mission

```bash
./04_scripts/prove.sh
```

This runs the `full-mission` command which:

1. Generates and proves the hazard assessment circuit (~32 constraints). Takes a few seconds.
2. Generates and proves the 200-step powered descent circuit (~23,000 constraints). Takes 30-60+ minutes.
3. Writes proof artifacts to `06_proofs/`.
4. Exports Solidity verifier contracts to `07_verifiers/`.
5. Writes mission metadata to `05_artifacts/`.

**Resource expectations for the 200-step descent:**
- CPU: 100% utilization on one core for the duration of proving.
- RAM: ~4.8 GB peak.
- Time: 60+ minutes is typical. Do not kill the process; it is working.
- Disk: Proof artifacts are small (128-byte proofs, larger compiled circuit JSONs in the MB range).

### Step 3: Verify Proofs

After the mission completes, verify the proofs independently:

```bash
./04_scripts/verify.sh
```

This runs:
```bash
ziros-lunar-flagship verify 06_proofs/hazard_proof.json 06_proofs/hazard_compiled.json
ziros-lunar-flagship verify 06_proofs/descent_proof.json 06_proofs/descent_compiled.json
```

Verification takes 1-3 ms per proof. Output should show `VERIFIED: true` for both.

The proof files are portable. Anyone with the binary can verify them without access to the private inputs.

### Step 4: Export On-Chain Verifiers (Optional)

```bash
./04_scripts/export.sh
```

Produces for each circuit:
- A Solidity verifier contract (`HazardAssessmentVerifier.sol`, `PoweredDescentVerifier.sol`)
- Calldata JSON for submitting the proof on-chain
- A Foundry test contract with positive and tamper-detection tests

Output directory: `07_verifiers/hazard/` and `07_verifiers/descent/`.

## Operating the End-to-End Test

The E2E test validates the full pipeline including tamper detection:

```bash
./04_scripts/e2e.sh
```

Six stages:
1. Prove hazard assessment
2. Prove 50-step descent (faster than 200)
3. Verify hazard proof from saved files
4. Tamper detection: flip a public input and confirm verification rejects
5. Export Solidity verifiers
6. Validate exported artifacts contain expected contract code

All six must pass. Results logged to `09_test_results/e2e_log.txt`.

## Operating the Benchmark Suite

```bash
./04_scripts/benchmark.sh
```

Runs hazard assessment and descent at 1, 50, and 200 steps. Reports timing breakdown per phase (circuit build, witness generation, Groth16 compile, constraint check, proving, verification). Results written to `08_benchmarks/benchmark_results.md`.

## Interpreting Proof Artifacts

### Proof JSON Structure

Each proof artifact (`*_proof.json`) contains:
- `backend`: Always `"arkworks-groth16"`
- `proof`: Base64-encoded 128-byte Groth16 proof
- `verification_key`: Base64-encoded verification key
- `public_inputs`: Array of field element strings (decimal)
- `metadata`: Detailed runtime metadata including Metal GPU status

### Hazard Proof Public Inputs

The hazard proof exposes 6 public values:
1. `hazard_threshold` (e.g., `"50"`)
2. `grid_commitment` (Poseidon hash, large field element)
3. `selected_landing_x` (e.g., `"100"`)
4. `selected_landing_y` (e.g., `"200"`)
5. `selected_score` (e.g., `"12"`)
6. `hazard_safe` (always `"1"` for valid proofs)

A verifier sees these values and knows: the prover had a grid whose Poseidon commitment matches, the selected cell scored 12 which is below threshold 50, and landing coordinates are (100, 200). The actual grid contents remain private.

### Descent Proof Public Inputs

The descent proof exposes 13 public values:
- The 8 public parameters (thrust bounds, glide slope, landing zone, gravity)
- The 5 public outputs (trajectory commitment, landing position commitment, constraint satisfaction, final mass, minimum altitude)

### Compiled Circuit JSON

The compiled circuit files (`*_compiled.json`) are large (several MB for descent). They contain the R1CS representation and verification key. Both the proof and compiled circuit are needed for verification.

## Troubleshooting

**Proof takes longer than expected:** The 200-step descent is compute-intensive. 60+ minutes is normal. Monitor with `top` or `Activity Monitor` -- you should see near-100% CPU on one core and ~4.8 GB resident memory.

**Out of memory:** The application allocates 512 MB stack per thread. If your system has less than 8 GB total RAM, the 200-step descent may fail. Use a smaller step count via `e2e` mode (50 steps).

**Verification fails:** If verification fails on a proof you just generated, this indicates a bug. File an issue. If verification fails on a proof from a different build, the compiled circuit and proof may be from incompatible builds.

**Stack overflow:** If you see a stack overflow, the 512 MB thread stack was insufficient. This should not happen at 200 steps but could occur if the code is modified for significantly larger circuits.

## Configuration Files

`03_configs/demo.json`:
```json
{
  "name": "demo",
  "hazard_cells": 4,
  "descent_steps": 1,
  "description": "Quick pipeline validation",
  "expected_time": "< 10 seconds"
}
```

`03_configs/full_mission.json`:
```json
{
  "name": "full_mission",
  "hazard_cells": 4,
  "descent_steps": 200,
  "descent_dt_seconds": 0.2,
  "descent_window_seconds": 40,
  "expected_time": "30-45 minutes"
}
```

These files are documentation only. The step count and parameters are compiled into the binary via the ZirOS library calls. Changing these JSON files does not change the binary's behavior.
