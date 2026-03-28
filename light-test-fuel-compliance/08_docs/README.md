# Private Satellite Fuel Budget Compliance Verifier

A lightweight end-to-end ZirOS application that proves a satellite's remaining fuel stays above a required safety reserve after a sequence of maneuvers — without revealing any private fuel data.

## What It Does

- Accepts private inputs: starting fuel, 4 burn amounts, safety reserve threshold
- Computes remaining fuel at each step (privately)
- Proves the final remaining fuel >= safety reserve
- Outputs only a public commitment to starting fuel and a boolean compliance status
- Generates a real cryptographic proof using Plonky3 (Goldilocks field, transparent setup)
- Verifies the proof

## Quick Start

```bash
# Build
cd 02_app && cargo build

# Run (build + prove + verify)
cargo run

# Or use the end-to-end script
cd 03_scripts && ./e2e.sh
```

## Architecture

```
Private Inputs          Circuit                    Public Outputs
─────────────          ───────                    ──────────────
starting_fuel    ──┐
burn_step_0      ──┤   fuel_after_step_0          fuel_commitment
burn_step_1      ──┤   fuel_after_step_1            (nonlinear binding)
burn_step_2      ──┤   fuel_after_step_2
burn_step_3      ──┤   fuel_after_step_3          compliance_status
safety_reserve   ──┘   safety_slack                 (boolean: 1)
```

## Proof Backend

- **Field**: Goldilocks (64-bit prime field)
- **Backend**: Plonky3 (STARK with FRI)
- **Setup**: Transparent (no trusted ceremony)
- **Proof size**: ~3KB
- **Prove time**: ~17ms
- **Verify time**: ~5ms

## Sample Scenario

**Compliant** (proof succeeds):
- Starting fuel: 10,000 units
- Burns: 1,500 + 2,000 + 1,000 + 500 = 5,000
- Remaining: 5,000 (above reserve of 3,000)

**Non-compliant** (correctly rejected):
- Starting fuel: 10,000 units
- Burns: 3,000 + 3,000 + 2,500 + 1,000 = 9,500
- Remaining: 500 (below reserve of 3,000)
