# Protocol Proof Vendor Sources

This directory pins external proof inputs used by the ZKF protocol-proof closure work.

- `formal-snarks-project/` is a local vendored snapshot of Bolton Bailey's Lean proof code used as the Groth16 knowledge-soundness starting point.
- `arklib/`, `VCVio/`, `CompPoly/`, `ExtTreeMapLemmas/`, `doc-gen4/`, and `checkdecls/` are local vendored snapshots for the FRI/oracle-reduction dependency chain.
- `sources.json` is the repo-level provenance manifest for reusable repositories and paper baselines that define the Phase D closure program.
- Vendoring these sources does not close any protocol-security row by itself. It only removes the dependency on CI-time fetching and makes the proof workspace capable of offline dependency resolution once the local Lake files are wired to the vendored paths.

Nothing in this directory widens the proof boundary by itself. The authoritative truth source remains `zkf-ir-spec/verification-ledger.json`.
