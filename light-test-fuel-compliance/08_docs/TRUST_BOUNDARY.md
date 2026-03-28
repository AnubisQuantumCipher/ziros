# Trust Boundary

## What Is Private (Never Revealed)

- `starting_fuel` — the satellite's initial fuel amount
- `burn_step_0` through `burn_step_3` — fuel consumed in each maneuver
- `safety_reserve` — the minimum required fuel reserve
- `fuel_after_step_0` through `fuel_after_step_3` — intermediate fuel levels
- `safety_slack` — the difference between final fuel and reserve

These values exist only in the prover's witness. They are never included in the proof artifact. A verifier cannot recover them.

## What Is Public (Revealed in Proof)

- `fuel_commitment` — a nonlinear commitment: `starting_fuel * (starting_fuel + safety_reserve + 1)`. This binds the prover to specific starting_fuel and safety_reserve values without revealing them individually.
- `compliance_status` — always 1 (the existence of a valid proof IS the compliance assertion; if the inputs don't satisfy constraints, no proof can be generated)

## What the Verifier Learns

1. The prover knows fuel amounts that satisfy all constraints
2. No individual fuel value at any step goes negative (16-bit range checks)
3. The final remaining fuel is at least as large as the safety reserve
4. The commitment value ties the proof to specific (hidden) starting conditions

## What the Verifier Does NOT Learn

1. The actual starting fuel amount
2. The actual burn amounts at each step
3. The actual safety reserve threshold
4. The actual remaining fuel at any step
5. How close to the reserve threshold the fuel actually is
