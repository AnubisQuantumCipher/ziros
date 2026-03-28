# ZirOS Lunar Flagship Bundle

This directory is the imported evidence bundle from the desktop
`ZirOS_Space_Flagship_Test` run. It is preserved in-repo so a developer or
reviewer can inspect the exact source, proof artifacts, verifier exports,
benchmark output, operator docs, and release packaging that came out of the
flagship space-domain test.

## What Is Included

- `01_source/`
  Rust source for the flagship app without local build output.
- `02_app/`
  Quick-start description of the application surface.
- `03_configs/`
  Demo and full-mission input configs.
- `04_scripts/`
  Build, run, prove, verify, export, benchmark, and end-to-end helper scripts.
- `05_artifacts/`
  Mission metadata and notes produced by the run.
- `06_proofs/`
  Hazard and powered-descent compiled artifacts plus proof JSONs.
- `07_verifiers/`
  Solidity verifier contracts, Foundry tests, and calldata for both circuits.
- `08_benchmarks/`
  Benchmark output captured from the bundle.
- `09_test_results/`
  End-to-end test log.
- `10_docs/`
  Architecture, reproducibility, trust-boundary, limitation, and operator docs.
- `11_report/`
  The full developer-experience report for the flagship exercise.
- `12_release_bundle/`
  The packaged release-oriented copy of the same flagship app surface.

## Important Packaging Note

`06_proofs/descent_compiled.json` is large and is tracked with Git LFS. That is
intentional: the goal is to keep the full compiled powered-descent artifact in
the repo instead of replacing it with a summary.

## Recommended Reading Order

1. `10_docs/README.md`
2. `11_report/SPACE_FLAGSHIP_DEVELOPER_EXPERIENCE_REPORT.md`
3. `10_docs/TRUST_BOUNDARIES.md`
4. `10_docs/REPRODUCIBILITY.md`
5. `06_proofs/` and `07_verifiers/`
