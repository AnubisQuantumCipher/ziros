# Benchmark Results

Built from ZirOS v0.1.0 (GitHub release)
Backend: arkworks-groth16 (BN254)
Platform: macOS Apple Silicon (M4 Max)

## Hazard Assessment Circuit

| Metric | Value |
|--------|-------|
| Signals | 40 |
| Constraints | 32 |
| Circuit build | <1 ms |
| Witness gen | 65 ms |
| Groth16 compile | 665 ms |
| Proving | 1,472 ms |
| Verification | 16 ms |
| **Total** | **2,262 ms** |
| Proof size | 128 bytes |

## Powered Descent Circuit

| Steps | Signals | Constraints | Compile (ms) | Prove (ms) | Verify (ms) | Total (ms) |
|-------|---------|-------------|-------------|------------|-------------|------------|
| 1 | 215 | 273 | 1,371 | 3,165 | 16 | 4,711 |
| 200 | 22,901 | 30,720 | 7,571,931 | 1,038,204 | 17 | 8,644,159 |

## Scaling Analysis

- 1 step → 200 steps: constraints scale 112x (273 → 30,720)
- Compile time scales ~5,500x (superlinear — dominated by QAP evaluation and MSM for setup)
- Prove time scales ~328x (superlinear — MSM over 30K elements)
- Verify time is CONSTANT at 16-17 ms (Groth16 pairing check)
- Proof size is CONSTANT at 128 bytes

## Metal GPU Dispatch

- MSM threshold: 16,384 elements
- 1-step circuit (273 constraints): **CPU-only** (below threshold)
- 200-step circuit (30,720 constraints): **Threshold crossed** (30,720 > 16,384)
- Self-reported gpu_stage_busy_ratio: 0.250 (from proof metadata)
- Honest note: Whether Metal actually dispatched for the MSM kernel vs. the self-reported metadata is not independently verified

## Key Observations

1. Groth16 trusted setup (compile) is 87% of total time at 200 steps
2. In production, the setup is done ONCE per circuit configuration — subsequent proofs only pay the 17-minute prove cost
3. Verification is instant (17 ms) regardless of circuit size — this is Groth16's key advantage
4. 462 MB compiled program (proving + verification keys) — the verification key alone is much smaller
5. Peak memory: ~4.8 GB for 200-step descent
