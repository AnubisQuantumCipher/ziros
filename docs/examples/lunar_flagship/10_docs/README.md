# ZirOS Lunar Landing Hazard Avoidance and Powered Descent Verification System

## What This Is

A zero-knowledge proof application that demonstrates two flight-safety verification circuits built on ZirOS v0.1.0. It generates Groth16 proofs on BN254 that attest to:

1. A terrain hazard assessment selected a safe landing cell from a private grid.
2. A powered descent trajectory satisfies physical and safety constraints over an Euler-integrated burn window.

Neither circuit operates on real sensor data. This is a demonstration of the ZirOS proof pipeline applied to a space-domain problem, not a flight-qualified system.

## What It Proves

### Proof 1: Terrain Hazard Assessment

**Circuit origin:** Built from scratch using `ProgramBuilder` in `01_source/src/hazard.rs`.

Given a private 4-cell terrain hazard grid (each cell has a score, x, y), the proof attests that:

- Exactly one cell was selected (one-hot encoding, boolean flags, weighted-sum constraint).
- The selected cell's hazard score is below a public threshold (score + non-negative gap = threshold).
- The entire grid is committed via a chained 4-round Poseidon permutation, binding the proof to the specific grid data.
- The selected landing coordinates and score are correctly extracted via MUX constraints.

**Public inputs:** `hazard_threshold`
**Public outputs:** `grid_commitment`, `selected_landing_x`, `selected_landing_y`, `selected_score`, `hazard_safe`

**Scale:** ~40 signals, ~32 constraints.

### Proof 2: Powered Descent Verification

**Circuit origin:** Existing `zkf-lib::descent` module (`private_powered_descent_showcase_with_steps`).

Given private initial state (position, velocity, mass) and a private thrust profile, the proof attests that over `N` integration steps (each 0.2 seconds):

- Euler integration of position and velocity is correct at every step.
- Thrust magnitude at each step is within `[thrust_min, thrust_max]` bounds.
- Glide slope constraint is satisfied at every step (altitude vs. radial distance).
- The vehicle remains within the landing zone radius.
- Mass decrements correctly based on thrust and specific impulse.
- Altitude remains non-negative throughout.
- The full trajectory and final landing position are committed via Poseidon.
- A fail-closed `constraint_satisfaction` flag is constrained to 1 (invalid trajectories fail during witness generation, not at proof time).

**Public inputs:** `thrust_min`, `thrust_max`, `glide_slope_tangent`, `max_landing_velocity`, `landing_zone_radius`, `landing_zone_center_x`, `landing_zone_center_y`, `g_z`
**Public outputs:** `trajectory_commitment`, `landing_position_commitment`, `constraint_satisfaction`, `final_mass`, `min_altitude`

**Scale at 200 steps:** ~12,150 signals, ~23,000 constraints.

## How to Build

Prerequisites:
- Rust toolchain (2024 edition)
- ZirOS v0.1.0 cloned to `~/Desktop/ziros-release`

```bash
# Check prerequisites
./04_scripts/setup.sh

# Build release binary
./04_scripts/build.sh
```

The binary is produced at `01_source/target/release/ziros-lunar-flagship`.

## How to Run

### Demo (fast validation, ~7-10 seconds)

```bash
./01_source/target/release/ziros-lunar-flagship demo
# or
./04_scripts/run.sh
```

Runs the hazard assessment circuit plus a 1-step descent circuit. Validates the full pipeline (build, compile, witness, prove, verify) without the heavy compute.

### Full Mission (200-step descent, 30-60+ minutes)

```bash
./01_source/target/release/ziros-lunar-flagship full-mission
# or
./04_scripts/prove.sh
```

Runs both circuits at full scale. The 200-step descent generates ~23,000 constraints and takes 60+ minutes at 100% CPU utilization with ~4.8 GB RAM. Writes proofs to `06_proofs/`, Solidity verifiers to `07_verifiers/`, and metadata to `05_artifacts/`.

### End-to-End Test (~1 minute, 50-step descent)

```bash
./01_source/target/release/ziros-lunar-flagship e2e
# or
./04_scripts/e2e.sh
```

Six-stage test: prove hazard, prove 50-step descent, verify from files, tamper detection, Solidity export, artifact validation.

### Benchmark (multi-scale)

```bash
./01_source/target/release/ziros-lunar-flagship benchmark
# or
./04_scripts/benchmark.sh
```

Runs hazard + descent at 1, 50, and 200 steps. Writes results to `08_benchmarks/`.

### Standalone Verification

```bash
./01_source/target/release/ziros-lunar-flagship verify 06_proofs/hazard_proof.json 06_proofs/hazard_compiled.json
```

### Solidity Export

```bash
./01_source/target/release/ziros-lunar-flagship export 06_proofs/hazard_proof.json 07_verifiers/hazard HazardAssessmentVerifier
```

Produces a `.sol` verifier contract, `calldata.json`, and a Foundry test file.

## Directory Layout

```
ZirOS_Space_Flagship_Test/
  01_source/          Rust source code and Cargo project
  02_app/             App-level README
  03_configs/         demo.json, full_mission.json
  04_scripts/         Shell scripts for build/run/verify/export/benchmark/e2e
  05_artifacts/       Mission metadata (written by full-mission)
  06_proofs/          Compiled circuits and proof artifacts (JSON)
  07_verifiers/       Exported Solidity verifier contracts
  08_benchmarks/      Benchmark results
  09_test_results/    E2E test logs
  10_docs/            This documentation
  11_report/          (Reserved for mission reports)
  12_release_bundle/  (Reserved for release packaging)
```

## Backend and Proof Size

- Backend: Arkworks Groth16 on BN254
- Proof size: 128 bytes constant (base64-encoded in JSON artifacts)
- Verification: ~1-3 ms regardless of circuit size
- Trusted setup: Deterministic dev seeds (not suitable for production; see TRUST_BOUNDARIES.md)

## ZirOS Version

Built against ZirOS v0.1.0: https://github.com/AnubisQuantumCipher/ziros/releases/tag/v0.1.0

The application depends on three ZirOS crates via local path:
- `zkf-core` (types, field elements, constraint checking)
- `zkf-backends` (Groth16 proving, witness preparation, Solidity export)
- `zkf-lib` (ProgramBuilder, descent module, Poseidon permutation)
