# ZirOS Lunar Flagship — Quick Start

Built from ZirOS v0.1.0 (https://github.com/AnubisQuantumCipher/ziros/releases/tag/v0.1.0)

## Binary
```
01_source/target/release/ziros-lunar-flagship
```

## Commands
```bash
ziros-lunar-flagship demo          # Quick validation (~10s)
ziros-lunar-flagship full-mission  # 200-step descent + hazard (~30-45min)
ziros-lunar-flagship e2e           # End-to-end test with tamper detection
ziros-lunar-flagship benchmark     # Multi-scale timing
ziros-lunar-flagship verify <proof.json> <compiled.json>
ziros-lunar-flagship export <proof.json> <out_dir> [ContractName]
```

## What it proves
1. **Hazard Assessment**: From a private 4-cell terrain grid, the safest landing cell was selected and is below the hazard threshold. Grid committed via Poseidon.
2. **Powered Descent**: The descent trajectory satisfies thrust bounds, glide slope, landing zone, velocity limits, and mass budget over the full integration window.
