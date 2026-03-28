# Trust Boundaries

## What the Proofs Actually Guarantee

### Hazard Assessment Proof

A valid hazard assessment proof guarantees to the verifier:

1. The prover possessed a 4-cell terrain grid whose Poseidon commitment equals the public `grid_commitment`.
2. Exactly one cell was selected from that grid via one-hot encoding.
3. The selected cell's hazard score is at most `hazard_threshold`.
4. The reported `selected_landing_x`, `selected_landing_y`, and `selected_score` correspond to the selected cell.
5. All cell scores are in [0, 255], all coordinates are in [0, 65535].

A valid proof does NOT guarantee:
- That the terrain data corresponds to any real terrain.
- That the selected cell is globally optimal (only that it is below threshold).
- That the 4-cell grid covers the actual landing area.
- That the Poseidon commitment was computed over genuine sensor data.

### Powered Descent Proof

A valid descent proof guarantees to the verifier:

1. There exists a thrust profile and initial state such that:
   - Euler integration over the specified steps produces a valid trajectory.
   - Thrust magnitude is within `[thrust_min, thrust_max]` at every step.
   - Glide slope constraint is satisfied at every step.
   - Altitude is non-negative at every step.
   - Mass decrements correctly.
   - The final position is within the landing zone.
2. The trajectory's Poseidon commitment equals the public `trajectory_commitment`.
3. The landing position's Poseidon commitment equals `landing_position_commitment`.
4. `constraint_satisfaction` is 1 (fail-closed: invalid trajectories fail at witness generation).
5. `final_mass` and `min_altitude` are the actual values from the trajectory.

A valid proof does NOT guarantee:
- That the trajectory was actually flown.
- That the physical model is accurate (it uses simplified Euler integration).
- That the initial conditions correspond to a real vehicle state.
- That thrust_min/thrust_max correspond to real engine limits.

## What Is Private vs. Public

### Hazard Assessment

| Data | Visibility | Rationale |
|------|-----------|-----------|
| Cell scores, coordinates | Private | Terrain intelligence may be sensitive |
| Selected cell index | Private | Part of decision-making process |
| One-hot flags | Private | Internal encoding |
| Poseidon intermediates | Private | Internal computation |
| Threshold gap | Private | Reveals how much margin exists |
| Hazard threshold | Public | Verifier needs to know the safety standard |
| Grid commitment | Public | Binding proof to specific terrain data |
| Selected coordinates/score | Public | Verifier sees the landing site choice |
| Safety flag | Public | Attestation of safety |

### Powered Descent

| Data | Visibility | Rationale |
|------|-----------|-----------|
| Initial position, velocity | Private | Vehicle state is operationally sensitive |
| Thrust profile (per-step) | Private | Propulsion capability is sensitive |
| Wet mass, specific impulse | Private | Vehicle performance parameters |
| All integration intermediates | Private | Internal computation |
| Thrust bounds | Public | Safety envelope must be auditable |
| Glide slope tangent | Public | Safety constraint must be auditable |
| Landing zone parameters | Public | Landing target must be verifiable |
| Gravity | Public | Physical parameter must be agreed upon |
| Trajectory commitment | Public | Binding proof to specific trajectory |
| Landing position commitment | Public | Binding proof to final position |
| Constraint satisfaction | Public | Attestation of constraint satisfaction |
| Final mass | Public | Verifier sees remaining propellant |
| Minimum altitude | Public | Verifier sees worst-case terrain clearance |

## Threat Model

### Prover (Mission Operator)

The prover is trusted to:
- Generate honest witness data (the proof system cannot verify that inputs correspond to reality).
- Use appropriate physical parameters (the circuit enforces internal consistency, not external accuracy).

The prover is NOT trusted to:
- Produce a proof for a trajectory that violates the circuit's constraints. Groth16 soundness prevents this (under the trusted setup assumption).
- Forge a grid commitment that doesn't match the actual grid data. Poseidon collision resistance prevents this.
- Claim a selected cell with a score above threshold. The circuit's range-checked gap constraint prevents this.

### Verifier (Auditor)

The verifier can:
- Confirm proof validity in ~1-3 ms without any private data.
- Confirm the public inputs match expectations (correct threshold, correct landing zone, etc.).
- Confirm the grid/trajectory commitments bind the proof to specific data.
- Run on-chain verification via the exported Solidity contract.

The verifier cannot:
- Determine whether the private inputs correspond to real-world data.
- Determine the actual terrain scores or trajectory details beyond what is public.
- Distinguish a proof generated from synthetic data versus real sensor data.

### Assumptions

The security of this system depends on:

1. **Groth16 soundness:** No polynomial-time adversary can produce a valid proof for a false statement. This relies on the Knowledge of Exponent assumption on BN254.

2. **BN254 security:** The BN254 curve provides approximately 100-110 bits of security against known attacks. This is considered adequate for most applications but is below the 128-bit target of newer curves (BLS12-381, BN254 with larger parameters).

3. **Poseidon collision resistance:** The grid and trajectory commitments rely on Poseidon's collision resistance over BN254. The specific Poseidon parameters are provided by ZirOS's `poseidon_permutation4_bn254` implementation.

4. **Trusted setup (CRS):** Groth16 requires a Common Reference String generated by a trusted party. If the CRS toxic waste is known, proofs can be forged.

## Groth16 Trusted Setup -- The Critical Caveat

**This application uses deterministic dev seeds for the trusted setup.** The setup seed is `[0x71; 32]` (all bytes 0x71). This means:

- The "toxic waste" (the secret randomness used to generate the CRS) is trivially known to anyone who reads the source code.
- Any party with this knowledge can forge proofs for arbitrary false statements.
- **These proofs provide ZERO cryptographic security against a motivated adversary.**

This is acceptable for:
- Demonstration and testing
- Pipeline validation
- Performance benchmarking
- Development

This is NOT acceptable for:
- Production deployment
- Any scenario where proof soundness matters
- On-chain verification with real economic stakes
- Regulatory or safety-critical attestation

### What Production Would Require

For production use, the trusted setup must be replaced with either:

1. **Multi-party computation (MPC) ceremony:** Multiple independent parties contribute randomness. The CRS is secure as long as at least one participant is honest and destroys their contribution. This is the standard approach (used by Zcash, Tornado Cash, etc.).

2. **Universal/transparent setup:** Move to a proof system that does not require a trusted setup (e.g., PLONK with KZG from a universal ceremony, or STARKs/FRI-based systems). ZirOS supports Plonky3 which provides this, but at different performance/proof-size tradeoffs.

## BlackBox Semantics

The Poseidon hash operations use ZirOS's `BlackBoxOp::Poseidon` mechanism. The proof metadata reports `blackbox_semantics: "host-validated-blackbox"`. This means:

- The Poseidon permutation is computed by the host (prover) and the result is constrained via BlackBox constraints in the R1CS.
- The verifier trusts that the BlackBox constraint encoding correctly captures the Poseidon permutation.
- This is standard practice for hash functions in R1CS-based systems (native Poseidon constraints would be equivalent but the implementation path differs).

## Side-Channel Considerations

This demonstration application does not implement side-channel protections:
- The prover leaks timing information proportional to the step count (though not to the private input values, since the circuit structure is fixed).
- No constant-time witness generation is attempted.
- Private input values exist in plaintext memory during witness generation and proving.

For production use, the prover environment should be hardened:
- Prove in an isolated environment (TEE, air-gapped machine).
- Clear memory after proving.
- Do not expose timing information to adversaries.

## On-Chain Verification Trust

The exported Solidity verifiers embed the verification key from the deterministic setup. If deployed on-chain:
- Any valid proof against that verification key will pass. This works correctly.
- But since the setup is deterministic, anyone can forge a valid proof. The on-chain verifier cannot distinguish real from forged proofs.
- The Foundry test suite includes a tamper detection test that confirms modified public inputs are rejected. This validates the verifier contract logic but does not address the trusted setup issue.

## Summary of Trust Hierarchy

```
Most trusted (verifier can confirm):
  - Proof passes pairing check
  - Public inputs match expectations
  - Constraint satisfaction flag is 1
  - Commitments bind to specific private data

Conditionally trusted (depends on setup):
  - No false proof exists (requires honest CRS)
  - Poseidon commitments are collision-resistant

Not verified by the proof:
  - Private inputs correspond to reality
  - Physical model is accurate
  - Terrain data is real
  - Trajectory was actually executed
```
