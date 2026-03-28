# Mission Artifacts

## From E2E Test (1-step descent)
- hazard_proof.json + hazard_compiled.json in 06_proofs/
- descent_proof.json + descent_compiled.json in 06_proofs/
- Verified, tamper-tested, Solidity-exported

## From Full Mission (200-step descent)
- Running at time of assembly — 200-step Groth16 proof (~23,000 constraints)
- Expected to complete and write mission_metadata.json here
- This is genuine heavy compute: 60+ minutes at 100% CPU, 4.8GB RAM
- When complete, will also populate 07_verifiers/ with 200-step contracts

## Backend
- arkworks-groth16 (BN254)
- Deterministic setup seed: [0x71; 32]
- Deterministic proof seed: [0x83; 32]
