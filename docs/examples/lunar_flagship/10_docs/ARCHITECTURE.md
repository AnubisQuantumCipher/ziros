# Architecture

## System Overview

The application composes two independent zero-knowledge proof circuits into a mission pipeline. Each circuit is compiled, witnessed, proved, and verified separately. There is no recursive composition or proof aggregation between them -- they are two standalone Groth16 proofs that happen to run in sequence.

```
                    +---------------------+
                    |   Mission Runner    |
                    |   (main.rs)         |
                    +-----+--------+------+
                          |        |
              +-----------+        +------------+
              |                                 |
   +----------v-----------+       +-------------v-----------+
   | Hazard Assessment    |       | Powered Descent         |
   | (hazard.rs)          |       | (zkf-lib::descent)      |
   | ProgramBuilder       |       | ProgramBuilder          |
   +----------+-----------+       +-------------+-----------+
              |                                 |
              v                                 v
   +-----------------------------------------------------+
   |              ZirOS Proof Pipeline                    |
   |  compile() -> prepare_witness() -> check() ->       |
   |  prove() -> verify()                                |
   |  Backend: arkworks-groth16 (BN254)                  |
   +-----------------------------------------------------+
```

## Circuit 1: Terrain Hazard Assessment

### Signal Hierarchy

**Private inputs (13 signals):**
- `cell_0_score`, `cell_0_x`, `cell_0_y` (cell 0 terrain data)
- `cell_1_score`, `cell_1_x`, `cell_1_y` (cell 1)
- `cell_2_score`, `cell_2_x`, `cell_2_y` (cell 2)
- `cell_3_score`, `cell_3_x`, `cell_3_y` (cell 3)
- `selected_index` (which cell was chosen)

**Public input (1 signal):**
- `hazard_threshold` (maximum acceptable hazard score)

**Public outputs (5 signals):**
- `grid_commitment` (Poseidon hash of entire grid)
- `selected_landing_x`, `selected_landing_y` (extracted coordinates)
- `selected_score` (extracted score of chosen cell)
- `hazard_safe` (constrained to 1)

**Internal private signals (~21 signals):**
- `select_flag_0` through `select_flag_3` (one-hot selection encoding)
- `threshold_gap` (non-negative slack for threshold check)
- `__poseidon_r{1..4}_{0..3}` (16 Poseidon intermediate state lanes)

### Constraint Structure (~32 constraints)

1. **Range checks** (9 constraints): Each cell score is 8-bit, coordinates are 16-bit, threshold is 8-bit, selected_index is 2-bit.

2. **One-hot encoding** (6 constraints):
   - Each `select_flag_i` is boolean: `flag * (flag - 1) = 0`
   - Sum of flags equals 1: `flag_0 + flag_1 + flag_2 + flag_3 = 1`
   - Weighted sum equals index: `0*flag_0 + 1*flag_1 + 2*flag_2 + 3*flag_3 = selected_index`

3. **MUX extraction** (3 constraints):
   - `selected_score = sum(flag_i * cell_i_score)`
   - `selected_landing_x = sum(flag_i * cell_i_x)`
   - `selected_landing_y = sum(flag_i * cell_i_y)`

4. **Threshold check** (2 constraints):
   - `hazard_threshold = selected_score + threshold_gap`
   - `threshold_gap` range-checked to 8 bits (ensures non-negative)

5. **Poseidon commitment** (4 BlackBox constraints):
   - Round 1: `poseidon(cell_0_score, cell_0_x, cell_0_y, cell_1_score)`
   - Round 2: `poseidon(r1_0, cell_1_x, cell_1_y, cell_2_score)`
   - Round 3: `poseidon(r2_0, cell_2_x, cell_2_y, cell_3_score)`
   - Round 4: `poseidon(r3_0, cell_3_x, cell_3_y, selected_index)`
   - `grid_commitment = r4_0`

6. **Safety flag** (2 constraints):
   - `hazard_safe` is boolean
   - `hazard_safe = 1`

### ProgramBuilder Usage

The hazard circuit is built entirely from `ProgramBuilder` calls in `hazard.rs`:

```rust
let mut b = ProgramBuilder::new("lunar_hazard_assessment", FieldId::Bn254);
b.private_input("cell_0_score")?;
b.public_input("hazard_threshold")?;
b.public_output("grid_commitment")?;
b.private_signal("select_flag_0")?;
b.constrain_boolean("select_flag_0")?;
b.constrain_equal_labeled(lhs, rhs, Some("label".into()))?;
b.constrain_range("cell_0_score", 8)?;
b.constrain_blackbox(BlackBoxOp::Poseidon, &inputs, &outputs, &params)?;
```

Key `ProgramBuilder` methods used:
- `private_input()` / `public_input()` / `public_output()` -- declare signal roles
- `private_signal()` -- internal computation signals
- `constrain_boolean()` -- `x * (x - 1) = 0`
- `constrain_equal()` / `constrain_equal_labeled()` -- equality constraints
- `constrain_range()` -- bit-decomposition range check
- `constrain_blackbox()` -- Poseidon permutation via host-validated BlackBox
- `metadata_entry()` -- attach metadata to the program
- `build()` -- finalize into a `Program`

Witness generation is manual: `hazard_witness()` computes all intermediate values (flags, Poseidon rounds, gap) and returns a `Witness` with all signal values populated.

## Circuit 2: Powered Descent Verification

### Signal Hierarchy (at 200 steps)

**Public inputs (8 signals):**
- `thrust_min`, `thrust_max` (thrust magnitude bounds, fixed-point scaled)
- `glide_slope_tangent` (cone constraint parameter)
- `max_landing_velocity` (terminal velocity limit)
- `landing_zone_radius`, `landing_zone_center_x`, `landing_zone_center_y`
- `g_z` (gravitational acceleration, z-axis)

**Private inputs (~608 signals):**
- `wet_mass` (initial mass at ignition)
- `specific_impulse` (engine efficiency)
- `initial_position_{x,y,z}`, `initial_velocity_{x,y,z}` (6 state values)
- `thrust_{step}_{x,y,z}` for each step (200 * 3 = 600 thrust components)

**Public outputs (5 signals):**
- `trajectory_commitment` (Poseidon commitment to full trajectory)
- `landing_position_commitment` (Poseidon commitment to final position)
- `constraint_satisfaction` (fail-closed flag, constrained to 1)
- `final_mass` (remaining propellant mass)
- `min_altitude` (minimum altitude seen during descent)

**Internal signals (~11,500+):**
Per-step intermediates for Euler integration, range checks, thrust magnitude computation (square, sqrt, slack), engine acceleration with division remainders and slacks, velocity and position deltas, mass decrement, glide slope computation (radial distance squared, altitude squared, cone squared, division slack), Poseidon hash state lanes, and bound-checking support signals.

### Constraint Structure (at 200 steps, ~23,000 constraints)

Per integration step, the circuit enforces:

1. **Thrust bounds:** `thrust_min^2 <= |T|^2 <= thrust_max^2` via squared magnitudes and non-negative slack signals.
2. **Euler integration:** `v_{n+1} = v_n + (T/m - g) * dt`, `x_{n+1} = x_n + v_n * dt`. Each axis. Fixed-point arithmetic with explicit division remainder and slack constraints.
3. **Mass decrement:** `m_{n+1} = m_n - |T| * dt / I_sp` with remainder/slack.
4. **Glide slope:** `altitude^2 * glide_slope_tangent^2 >= radial_distance^2` at each step.
5. **Landing zone:** Final position within radius of center.
6. **Non-negative altitude:** `z >= 0` at every step.
7. **Poseidon commitment:** Chained Poseidon hashing of trajectory state at each step.

The constraint count scales linearly with step count: roughly `115 * steps + base_overhead`.

### Fixed-Point Arithmetic

All physical quantities use 10^18 fixed-point scaling within BN254 field elements. Division is constrained via: `quotient * divisor + remainder = dividend` with `0 <= remainder < divisor` enforced by range checks and slack signals. This is how the circuit avoids floating-point while maintaining sufficient precision for trajectory integration.

## Proof Pipeline

Both circuits follow the same pipeline:

```
Program ----compile()----> CompiledProgram
                               |
Witness --prepare_witness()--->|
                               |
          check_constraints()  |  (R1CS satisfaction check)
                               |
             prove() ----------+----> ProofArtifact
                                          |
             verify() <-------------------+
```

### Key Pipeline Functions

- `compile(program, "arkworks-groth16", Some(seed))` -- Generates proving/verification keys via Groth16 setup. Uses deterministic seed for reproducibility.
- `prepare_witness_for_proving(compiled, witness)` -- Enriches witness with auxiliary values needed by the backend.
- `check_constraints(program, witness)` -- Verifies R1CS constraint satisfaction before proving.
- `prove(compiled, prepared_witness)` -- Generates Groth16 proof.
- `verify(compiled, artifact)` -- Verifies Groth16 proof against verification key and public inputs.

### Deterministic Overrides

The application uses two deterministic overrides for reproducibility:

```rust
const SETUP_SEED: [u8; 32] = [0x71; 32];  // Groth16 setup randomness
const PROOF_SEED: [u8; 32] = [0x83; 32];  // Proof generation randomness
```

These are wrapped via:
- `with_allow_dev_deterministic_groth16_override(Some(true), || { ... })`
- `with_proof_seed_override(Some(PROOF_SEED), || { ... })`

This makes proofs fully reproducible but is NOT suitable for production use (see TRUST_BOUNDARIES.md).

### Stack Management

The 200-step descent circuit generates a deeply nested expression tree. The application spawns dedicated threads with 512 MB stack:

```rust
const STACK_SIZE: usize = 512 * 1024 * 1024;
std::thread::Builder::new().stack_size(STACK_SIZE).spawn(f)
```

The descent module itself also uses `stacker::maybe_grow()` internally.

## Solidity Export

Both proofs can be exported to on-chain verifiers:

- `export_groth16_solidity_verifier()` -- Generates a Solidity contract with embedded verification key and a `verifyProof()` function.
- `proof_to_calldata_json()` -- Serializes proof + public inputs as JSON for contract calls.
- `generate_foundry_test_from_artifact()` -- Generates a Foundry test contract with a positive test and a tamper-detection test.

Output per circuit:
- `{ContractName}.sol` -- Verifier contract
- `calldata.json` -- Proof calldata
- `{ContractName}.t.sol` -- Foundry test

## Metal GPU Acceleration

ZirOS instruments Metal GPU acceleration for MSM (multi-scalar multiplication), NTT, and other operations. The proof metadata reports:

- `metal_available: true`
- `metal_device: Apple M4 Max`
- `metal_thresholds: msm=512, ntt=512, poseidon2=256, field_ops=2048, merkle=512`
- `groth16_msm_engine: metal-bn254-msm`

The metadata threshold for MSM dispatch is 512 in the actual Metal configuration (the "16,384" figure referenced in configs is the original MSM threshold; the aggressive profile lowers it to 512). Whether Metal actually accelerated the Groth16 proving versus running equivalent operations on CPU is reported in the proof metadata but cannot be independently confirmed from timing alone.

## Dependencies

The application depends on three ZirOS crates:

| Crate | Role |
|-------|------|
| `zkf-core` | Field elements, `Program`, `Witness`, `CompiledProgram`, `ProofArtifact`, constraint checking, `Expr` AST |
| `zkf-backends` | Groth16 proving/verification, witness preparation, Solidity export, Foundry test generation, deterministic overrides |
| `zkf-lib` | `ProgramBuilder`, descent module, Poseidon permutation helper, template programs |

Plus `serde_json` for serialization.
