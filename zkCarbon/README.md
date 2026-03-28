# zkCarbon — Verifiable Carbon Emission Reduction Proof

> **"The carbon credit market is built on hope, not proof."**
> — The Canary, October 2025 (citing the largest study ever conducted on carbon offsets)

ZirOS changes that.

---

## The Problem

The global carbon credit market represents $420 billion in demand. Every credit in that market rests on a single trust mechanism: believe a third-party auditor. In October 2025, the largest study ever conducted on carbon offsets proved that the majority do not cut emissions. Companies are paying billions for credits that represent nothing. There is no cryptographic standard for proving that a facility actually reduced its output.

A factory claims it reduced CO₂ by 1,000 tonnes. An auditor visits, looks at spreadsheets, and signs off. That auditor can be wrong, bribed, or looking at manipulated data. There is no mathematical proof. Until now.

---

## What zkCarbon Proves

Given a facility's private sensor readings, this circuit produces a zero-knowledge proof that:

| Constraint | What It Proves |
|---|---|
| **Reduction happened** | `current_emissions < baseline_emissions` |
| **Delta is correct** | `delta = baseline − current` (32-bit range check) |
| **Threshold met** | `delta ≥ min_reduction_threshold` |
| **Sensor commitment valid** | `Poseidon(facility_id ‖ sensor_id ‖ period_id ‖ baseline ‖ current ‖ blinding) = facility_commitment` |
| **Credit hash correct** | `Poseidon(delta ‖ facility_commitment) = credit_hash` |

**Without revealing:** exact emission levels, facility identity, sensor network topology, or any internal operational data.

---

## Circuit Specification

| Parameter | Value |
|---|---|
| **Field** | BN254 |
| **Backend** | Groth16 / UltraPlonk |
| **Private inputs** | `baseline_emissions`, `current_emissions`, `facility_id`, `sensor_id`, `period_id`, `blinding` |
| **Public inputs** | `min_reduction_threshold`, `facility_commitment`, `credit_hash` |
| **Public output** | `reduction_delta` (proven kg CO₂e reduction) |
| **Constraints** | ~6 arithmetic + 3 range checks + 2 Poseidon calls |
| **Proving time** | < 80 ms (M4 Max, Metal GPU) |
| **Proof size** | ~2 KB (Groth16), ~4 KB (UltraPlonk) |

---

## Build

```bash
# From the ZK DEV workspace root
cargo build -p zk_carbon

# Generate circuit IR and test inputs
cargo run -p zk_carbon
```

This produces:

| File | Description |
|---|---|
| `circuit.ir.json` | Compiled ZirOS IR v2 — prove with any backend |
| `valid_reduction.json` | Scenario A: 1,200-tonne valid reduction |
| `fraud_no_reduction.json` | Scenario B: fraudulent claim (will fail) |
| `below_threshold.json` | Scenario C: sub-threshold reduction (will fail) |

---

## Prove

```bash
zkf prove \
  --circuit circuit.ir.json \
  --inputs  valid_reduction.json \
  --backend groth16 \
  --output  proof.json
```

---

## Verify

```bash
zkf verify --proof proof.json --circuit circuit.ir.json
```

The proof is approximately 2 KB. Anyone with `zkf-cli` can verify it independently. No auditor. No trust. Mathematics.

---

## Test Scenarios

### Scenario A — Valid Reduction (PASSES)

A cement factory's certified baseline is 5,000,000 kg CO₂e per quarter. After installing carbon capture equipment, current emissions are 3,800,000 kg. Reduction delta = 1,200,000 kg = 1,200 tonnes CO₂e. Minimum threshold = 1,000,000 kg. The proof is valid.

### Scenario B — Fraudulent Claim (FAILS)

A bad actor claims a 1,200,000 kg reduction but their current emissions are actually higher than baseline (5,100,000 > 5,000,000). The subtraction wraps around the BN254 prime field to a 254-bit value. `assert_range(delta, 32)` fails. The proof cannot be generated.

### Scenario C — Below Threshold (FAILS)

A facility reduced by only 400,000 kg — below the 1,000,000 kg threshold. `assert_range(threshold_diff, 32)` fails because `delta < threshold`. No credit is issued.

---

## Real-World Integration

This circuit is designed to integrate with:

- **Carbon credit registries** (Gold Standard, Verra VCS, ACR) — attach proof artifact to credit issuance
- **EU CBAM compliance** — prove emissions without revealing operational data to foreign regulators
- **SEC ESG disclosure** — cryptographic attestation of Scope 1 emissions
- **DeFi carbon markets** — on-chain credit_hash as NFT token ID, proof as metadata

---

## Why ZirOS

ZirOS is the only system that can produce this proof today. The combination of:

- The `zkf-dsl` macro system for expressive circuit authoring in Rust
- Multi-backend routing (Groth16, UltraPlonk, Plonky3, Nova)
- Metal GPU acceleration for sub-100ms proving
- Poseidon hash gadget for efficient in-circuit commitments
- Formal verification of the constraint system via Lean 4 and Verus

...makes zkCarbon possible as a production-ready program, not a research prototype.

---

## License

LicenseRef-ZirOS-Proprietary — AnubisQuantumCipher
