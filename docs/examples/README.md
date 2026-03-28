# Examples

This directory collects shipped example fixtures and evidence bundles that are
worth keeping in the repository.

## Included

- `fixtures/epa/`
  Small app-spec fixture used by the getting-started and audit docs.
- `lunar_flagship/`
  Full Lunar Flagship evidence bundle imported from the desktop test run. This
  includes source, configs, scripts, mission metadata, Groth16 proofs, exported
  Solidity verifiers, benchmark results, test logs, operator docs, and the
  developer-experience report.

## Notes

- The Lunar Flagship descent compiled artifact is large and is tracked through
  Git LFS so the full proof surface can stay in the repo without breaking
  GitHub object limits.
- Generated scratch files and local-only build output do not belong here.
