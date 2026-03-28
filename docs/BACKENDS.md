# Backend Guide

Use the live backend ids. Friendly names are for humans; ids are for commands.

## Decision Tree

```text
Need no trusted setup?
  Yes -> use plonky3 or halo2
  No  -> continue

Need direct EVM verifier export and small proofs?
  Yes -> use arkworks-groth16
  No  -> continue

Need recursive folding / IVC?
  Yes -> use nova or hypernova
  No  -> continue

Need Compact proof-server integration?
  Yes -> use midnight-compact
```

## Comparison

| Backend ID | Setup | Verification Profile | Proof Profile | Best For |
| --- | --- | --- | --- | --- |
| `plonky3` | Transparent | Local verifier, optional wrapper for EVM | Largest proofs, Metal-friendly proving | First proofs, transparent onboarding, STARK workflows |
| `halo2` | Transparent | Local verifier | Medium proofs | Transparent Plonkish circuits on Pasta Fp |
| `halo2-bls12-381` | Trusted setup | Local verifier | Medium proofs | BLS12-381 KZG workflows |
| `arkworks-groth16` | Trusted setup | Fastest on-chain verification | Smallest proofs | Solidity export, minimal calldata, BN254 |
| `nova` | Recursive shell | Recursive verification/folding workflow | Folded artifact flow | Incremental proving |
| `hypernova` | Recursive shell | Recursive multifolding workflow | Folded artifact flow | Higher-throughput folding |
| `midnight-compact` | External / delegated | Proof-server dependent | External lane | Compact integration when the external server is configured |

## Recommendations

- Start with `plonky3` when you want a transparent backend and a working proof
  quickly.
- Use `halo2` when your circuit naturally lives on Pasta Fp and you want a
  transparent Plonkish lane.
- Use `arkworks-groth16` when deployment to Ethereum matters more than setup
  ceremony friction.
- Use `nova` or `hypernova` when the application is inherently incremental.
- Treat `midnight-compact` as a specialized external lane, not as the default.
