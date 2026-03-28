# Limitations

This document catalogs the known limitations of the ZirOS Lunar Landing Hazard Avoidance and Powered Descent Verification System. These are not bugs -- they are scope boundaries, simplifications, and constraints inherent in a demonstration application.

## Physics Model Limitations

### Earth Gravity, Not Lunar

The descent circuit uses `g_z = 9.81 m/s^2` -- Earth surface gravity. Lunar surface gravity is approximately 1.625 m/s^2. The sample inputs were designed for a Falcon-9-scale Earth landing demonstration, not an actual lunar lander. Changing the gravity value would require different sample inputs (thrust profile, initial conditions) to produce a valid trajectory.

### Euler Integration Only

The trajectory integration uses first-order Euler: `v_{n+1} = v_n + a * dt`, `x_{n+1} = x_n + v_n * dt`. This is the simplest possible integrator and introduces integration error that grows with step count and time step size.

A production system would use at minimum RK4 (Runge-Kutta 4th order), or better, a symplectic integrator that preserves energy over long integration windows. Euler integration can produce trajectories that violate conservation of energy for sufficiently large dt or step counts.

The time step is fixed at dt = 0.2 seconds. This is not configurable at runtime; it is baked into the circuit and witness generation.

### No Attitude Dynamics

The circuit treats the vehicle as a point mass with a 3-axis thrust vector. There is no:
- Rotational dynamics (attitude, angular velocity, moments of inertia)
- Thrust vectoring constraints (gimbal limits)
- Aerodynamic forces (drag, lift)
- Reaction control system modeling
- Attitude-dependent thrust direction constraints

The thrust vector at each step is unconstrained in direction; only its magnitude is bounded.

### No J2 Perturbation

The gravity model is constant and unidirectional (z-axis only). There is no:
- Gravitational field variation with altitude
- J2 oblateness perturbation
- Third-body gravitational effects
- Gravity gradient or tidal forces

### No Atmosphere

There is no atmospheric model. No drag, no wind, no density variation. This is less of a limitation for a lunar scenario (no atmosphere) but means the system cannot be directly applied to Earth landing scenarios without modification.

### Fixed Step Count

The descent circuit is compiled with a fixed step count. The circuit structure changes for different step counts (different constraint count, different signal count). You cannot run a 200-step circuit with 100 steps of data or vice versa. The step count must be chosen at build time.

### Fixed-Point Arithmetic Precision

All physical quantities are represented as fixed-point integers with 10^18 scaling. This provides approximately 18 decimal digits of precision, which is sufficient for trajectory integration but:
- Division produces truncation errors (quotient * divisor + remainder = dividend, remainder is discarded in the next step).
- Accumulated truncation over 200 steps can drift from the true floating-point trajectory.
- The circuit does not prove that the fixed-point trajectory approximates the continuous-time trajectory to any particular accuracy.

## Terrain Model Limitations

### Synthetic Data Only

The hazard grid contains 4 hardcoded cells with arbitrary scores and coordinates:
- Cell 0: score=12, (100, 200) -- "flat mare"
- Cell 1: score=180, (350, 400) -- "crater rim"
- Cell 2: score=45, (500, 150) -- "gentle slope"
- Cell 3: score=220, (700, 600) -- "boulder field"

These are not derived from any real terrain data, DEM (digital elevation model), or sensor measurements.

### 4-Cell Grid Is Trivially Small

A real hazard avoidance system processes thousands to millions of terrain cells from LIDAR, camera, or radar data. The 4-cell grid demonstrates the proof structure but does not represent a realistic resolution.

### No Terrain Sensing Model

There is no model of:
- Sensor noise or uncertainty
- Terrain slope computation from elevation data
- Boulder detection from point cloud data
- Shadow/illumination effects
- Sensor field of view or coverage

### Score Semantics Are Opaque

The hazard "score" is an 8-bit integer with no defined relationship to physical terrain properties. In a real system, the score would be computed from measurable quantities (slope angle, roughness, boulder density) via a defined algorithm. Here it is just a number.

### No Global Optimality Guarantee

The circuit proves that the selected cell's score is below threshold. It does NOT prove that the selected cell has the lowest score. A prover could select any cell below threshold, even if a better option exists.

## Proof System Limitations

### Deterministic Trusted Setup (Not Production-Safe)

As detailed in TRUST_BOUNDARIES.md, the Groth16 CRS uses deterministic dev seeds. The "toxic waste" is public knowledge. Proofs can be trivially forged. This is the single most critical limitation for any use beyond demonstration.

### No Proof Composition

The hazard assessment and powered descent proofs are independent. There is no recursive proof that ties them together. A verifier must check both proofs separately and trust that they refer to the same mission scenario. The proofs share no commitments or cross-references.

A production system might:
- Use a recursive SNARK to compose both proofs into one.
- Share a commitment between circuits (e.g., the landing coordinates from hazard assessment bound to the landing zone in descent).
- Use proof aggregation to batch multiple mission verifications.

None of this is implemented.

### Groth16 Circuit-Specific Setup

Groth16 requires a new trusted setup for every circuit. If you change the step count, hazard cell count, or any constraint, you need a new CRS. This makes Groth16 inflexible for circuits that change between missions.

### BN254 Security Level

BN254 provides approximately 100-110 bits of security. While adequate for most current applications, it is below the 128-bit target recommended by NIST and targeted by newer curves (BLS12-381). The proof system's security is bounded by the weakest link: the curve security or the setup integrity.

### Proof Size Is Constant But Small

The 128-byte Groth16 proof is extremely compact, which is a strength. However, it contains no information about what was proved -- interpretation requires the verification key and knowledge of the circuit structure.

## Performance Limitations

### 200-Step Descent Is Compute-Intensive

The 200-step descent proof takes 60+ minutes of 100% CPU at ~4.8 GB RAM. This is a genuine workload:
- Circuit build (ProgramBuilder expression tree construction): significant time for deep expression nesting.
- Groth16 setup (CRS generation for ~23,000 constraints): O(n log n) operations.
- Proving (MSM, NTT, witness map): the dominant cost.

This timing makes real-time proving infeasible. A landing decision cannot wait 60 minutes.

### Metal GPU Acceleration Ambiguity

The proof metadata reports Metal GPU acceleration via `metal-bn254-msm` with an aggressive threshold profile (MSM threshold = 512). The metadata reports Metal dispatch for `groth16_prove_core`, `msm_window`, and `witness_map` stages. However:
- Whether the GPU actually provided speedup over CPU is not independently measurable from timing data alone.
- The `gpu_stage_busy_ratio` of 0.250 suggests GPU was engaged for 25% of proving time, but this is self-reported metadata, not an external measurement.
- The MSM threshold of 512 means even the small hazard circuit (~32 constraints) could trigger GPU dispatch, but the overhead may negate any benefit at that scale.

### 512 MB Stack Requirement

The application spawns threads with 512 MB stack. The deeply nested `Expr` tree for the 200-step descent circuit causes deep recursion during construction and evaluation. This is a consequence of the tree-based expression representation, not an inherent limitation of the circuit.

### No Parallel Proving

The two proofs are generated sequentially. They could in principle be generated in parallel on separate cores, but the current implementation does not do this.

## Solidity Export Limitations

### Not Tested On-Chain

The exported Solidity verifiers have not been deployed to any EVM chain (mainnet, testnet, or local). The Foundry test generation is structural but has not been executed against a Foundry environment.

### Gas Cost Unknown

The on-chain verification gas cost has not been measured. Groth16 verification on BN254 typically costs ~200,000-300,000 gas on Ethereum due to precompiled curve operations (ecAdd, ecMul, ecPairing), but actual cost depends on the number of public inputs.

### No EIP-4337 or Account Abstraction Integration

The verifier contracts are standalone. There is no integration with smart contract wallets, account abstraction, or any on-chain governance mechanism.

## Operational Limitations

### No Real-Time Capability

The proving time (minutes to hours) makes this unsuitable for real-time landing decisions. A real system would need:
- Hardware-accelerated proving (FPGA/ASIC)
- A much smaller circuit (fewer steps, simpler constraints)
- Or a different proof system optimized for speed (e.g., folding schemes)

### No Incremental Proving

The entire trajectory must be known before proving begins. There is no streaming or incremental proof generation as new trajectory data arrives.

### No Fault Tolerance

If proving fails (crash, timeout, OOM), the entire process must restart from scratch. There is no checkpointing or resumption.

### Single Configuration

The step count, cell count, time step, and all physical parameters are compile-time constants. A real system would need runtime configuration for different mission profiles.

## Summary

This application demonstrates that:
1. ProgramBuilder can construct non-trivial application-domain circuits.
2. ZirOS can prove circuits at the ~23,000 constraint scale.
3. Groth16 proofs verify in milliseconds regardless of circuit size.
4. The full pipeline (build, compile, prove, verify, export) works end-to-end.

It does NOT demonstrate:
1. Real-world applicability to lunar landing.
2. Production-grade trusted setup.
3. Real-time proof generation.
4. Integration with actual sensors or flight systems.
5. Formal verification of the circuit's physical correctness.
