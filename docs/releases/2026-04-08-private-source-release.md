# ZirOS Private Source Release — 2026-04-08

Status: private source release
Repository visibility: private
Intended publication lane: private GitHub source release with attached release notes and source provenance

## Executive Summary

This release captures a substantial expansion of ZirOS as an operator-grade zero-knowledge operating system rather than a narrow proving library. The release adds a new Hermes operator doc stack, a new private trade-finance settlement subsystem in `zkf-lib`, new packaging and validation scripts for Midnight-oriented subsystem export, lightweight formal proof surfaces for trade-finance invariants, refreshed generated forensics, and evidence/export plumbing required to package the new subsystem as a release-style artifact bundle.

The dominant architectural theme of this release is alignment between operator intent, machine-readable evidence, and release-facing artifacts. Several additions are specifically aimed at reducing the gap between what the system says it proves and what the checked-in source and emitted bundles can actually justify. That includes a stronger Hermes operator constitution, explicit bootstrap and contract documents for the agent layer, and a dedicated trade-finance subsystem that now carries its own program surfaces, exporter, proofs, scripts, and validation path.

This is a private source release, not a public-source relicensing event. It preserves the private posture stated in the repository README while packaging the current working system into a cleaner release-ready source snapshot.

## Release Highlights

### 1. Hermes operator documentation became a first-class repo surface

New operator materials in this release include:

- `HERMES.md`
- `docs/agent/HERMES_BOOTSTRAP_PROMPT.md`
- `docs/agent/HERMES_CONSTITUTION.md`
- `docs/agent/HERMES_OPERATOR_BLUEPRINT.md`
- `docs/agent/HERMES_OPERATOR_CONTRACT.json`

Together these files establish a clearer operating contract for Hermes on ZirOS:

- local-first execution on the trusted host
- proof-first and command-first workflow discipline
- explicit trust-lane honesty
- stronger separation between native, strict, delegated, compatibility, and advisory lanes
- publication boundaries that distinguish private source, public artifacts, and mechanized evidence

This matters because ZirOS now spans more than one interaction model. The agent is no longer just a convenience wrapper around the repository; it is documented as a resident operator surface with defined responsibilities, escalation boundaries, and truth sources.

### 2. New private trade-finance settlement subsystem

This release adds a new subsystem family under `zkf-lib`:

- `zkf-lib/src/app/private_trade_finance_settlement.rs`
- `zkf-lib/src/app/private_trade_finance_settlement_export.rs`
- `zkf-lib/examples/private_trade_finance_settlement_showcase.rs`
- `zkf-lib/tests/private_trade_finance_tdd.rs`

The subsystem is designed as a private trade-finance / receivables-style proving and export surface with multiple linked modules:

- core decision proof
- settlement binding proof
- selective disclosure projection
- duplicate-registry handoff

It also adds a first-class export surface that emits a release-style artifact set:

- compiled programs
- proof artifacts
- verification reports
- audit reports
- public input/output bundles
- witness summary
- telemetry report
- translation report
- run report
- evidence summary
- deterministic manifest
- closure artifact manifest
- operator notes
- deployment notes
- subsystem prebundle metadata
- long-form engineering report

The subsystem is operator-serious rather than demo-serious. It is structured so that a local operator can produce source-backed artifacts, validate a Midnight package, scaffold a finished subsystem bundle, and preserve an honest record of what is cryptographically proven versus what is merely exported, delegated, or operationally assumed.

### 3. Dedicated in-circuit commitment hardening for trade-finance outputs

During the release prep, the subsystem’s artifact vocabulary was upgraded from naming-only hardening to actual in-circuit semantic hardening.

Two exported fields that had previously been artifact-layer aliases now have dedicated in-circuit commitment surfaces:

- `fee_amount_commitment`
- `maturity_schedule_commitment`

The current semantics are:

- `fee_amount_commitment` is a dedicated commitment to the computed fee-like scalar already present in the subsystem
- `maturity_schedule_commitment` is a dedicated commitment to the subsystem’s current temporal-window tuple, rather than a reused settlement-instruction commitment

Important honesty note: ZirOS still does not model an explicit invoice due-date / tenor / amortization schedule in this subsystem. As a result, the maturity schedule commitment is now a real dedicated in-circuit surface, but it remains a truthful commitment to currently modeled temporal fields rather than a full receivables schedule model. The release preserves that distinction explicitly.

### 4. New subsystem packaging and validation scripts

The following scripts were added for repeatable export and validation:

- `scripts/materialize_private_trade_finance_settlement_subsystem.sh`
- `scripts/validate_private_trade_finance_midnight_contracts.sh`
- `scripts/run_lean_trade_finance_proofs.sh`
- `scripts/run_rocq_trade_finance_proofs.sh`
- `scripts/run_verus_trade_finance_proofs.sh`

These scripts move the subsystem closer to a complete operator workflow:

- export a finished showcase bundle
- validate generated Midnight contracts and prepared calls
- scaffold the 20-slot subsystem structure
- copy reports, proofs, manifests, and disclosure policy material into the subsystem shell
- run completeness checks and public bundling
- exercise supporting formal surfaces when the required tools are available

This is exactly the kind of procedural surface ZirOS needs if it is going to behave like an operating system for proof-driven applications rather than a loose collection of crates.

### 5. Lightweight formal surfaces for trade-finance invariants

The release adds three proof-side files:

- `zkf-lib/proofs/lean/TradeFinanceProofs.lean`
- `zkf-lib/proofs/rocq/TradeFinanceProofs.v`
- `zkf-lib/proofs/verus/trade_finance_verus.rs`

These do not yet constitute end-to-end formalization of the entire subsystem. Instead, they focus on tightly scoped arithmetic and capped-payout invariants. That is still valuable. It establishes a pattern for theorem-bearing subsystem support without falsely claiming complete formal closure where none exists.

### 6. Generated forensics and release staging artifacts

The release refreshes and extends generated source-backed metadata under `forensics/generated/`, including:

- `forensics/generated/app_closure/private_trade_finance_settlement_showcase.json`
- updated implementation closure summary data

It also carries forward staged release material for the claims subsystem under:

- `release/private-claims-truth-flagship-20260408/`

That folder contains staged tarballs, checksums, and release notes. In other words, the repository is not only adding new source surfaces; it is also accumulating operator-facing release practice in checked-in form.

## Verification Performed For This Release

The following verification work was run directly on the local workspace during release preparation for the trade-finance subsystem work that is central to this drop:

- targeted TDD checks for new dedicated fee/maturity commitment surfaces
- `cargo test -p zkf-lib trade_finance --lib`
- `cargo test -p zkf-lib trade_finance_decision_core_fixture_builds_and_witnesses --test private_trade_finance_tdd`
- `cargo run --release -p zkf-lib --example private_trade_finance_settlement_showcase -- /tmp/private_trade_finance_flagship_semantics`
- `bash scripts/validate_private_trade_finance_midnight_contracts.sh /tmp/private_trade_finance_flagship_semantics preprod`

Observed outcome:

- targeted tests passed
- broader trade-finance library tests passed
- showcase regeneration succeeded
- Midnight contract validation succeeded

Formatting note:

- `cargo fmt --all` is not reliable on this host because it can be captured by a broken parent workspace outside the ZirOS root
- touched ZirOS files were formatted with direct `rustfmt` instead

## Source Scope Included In This Release

This release is source-heavy. The intended scope includes:

- modified tracked files already in the ZirOS workspace
- newly added operator docs
- new trade-finance subsystem source, exporter, example, tests, proofs, and scripts
- generated forensics needed to describe the current subsystem closure state
- staged release materials already assembled in the tree

The release is intentionally broader than a small feature patch. It packages a working tranche of operator docs, subsystem source, proof surfaces, and generated evidence together.

## Known Boundaries And Release Caveats

### Private repo, not public-source conversion

The repository remains private. Nothing in this release changes the licensing posture described in `README.md`.

### Some generated artifacts remain host-shaped

The current release staging area includes artifacts and reports with local path details. Because this is a private source release, that is not a blocker to publication into the private repository, but it remains a hygiene concern for any future public artifact lane.

### Trade-finance naming drift is reduced, not eliminated everywhere

The trade-finance subsystem has been significantly hardened, especially at the artifact and export level. Some deeper internal naming still carries historical claims-oriented ancestry. This release improves semantics materially, but it is not the final naming cleanup pass.

### Maturity semantics are honest but not yet full receivables-tenor semantics

The newly dedicated maturity commitment is real, but the subsystem still lacks a fully modeled due-date / tenor / amortization schedule input surface. The release therefore preserves the honest claim: the system proves a dedicated temporal commitment, not a complete receivables schedule model.

### Midnight remains lane-specific

Midnight contract packaging and validation are real surfaces in this release, but they remain distinct from strict-native proof claims. The release does not flatten delegated-or-external lanes into native strict language.

## Recommended Reader Paths

If you are approaching this release as an operator or reviewer, start in this order:

1. `README.md`
2. `HERMES.md`
3. `docs/agent/README.md`
4. `docs/agent/HERMES_CONSTITUTION.md`
5. `docs/CANONICAL_TRUTH.md`
6. `docs/releases/2026-04-08-operator-experience-report.md`
7. `zkf-lib/src/app/private_trade_finance_settlement.rs`
8. `zkf-lib/src/app/private_trade_finance_settlement_export.rs`
9. `scripts/materialize_private_trade_finance_settlement_subsystem.sh`
10. `scripts/validate_private_trade_finance_midnight_contracts.sh`

That sequence moves from posture and trust boundaries into concrete subsystem mechanics.

## Why This Release Matters

The importance of this release is not any single subsystem file. The importance is that ZirOS looks more like a coherent operator system after this cut than it did before it.

The repo now contains:

- a more explicit operator constitution
- a stronger local-first Hermes operating contract
- a new proof/export subsystem with its own validation and release surfaces
- a better example of how renamed business vocabulary should be carried into actual in-circuit semantics
- a clearer record of where the system is still honest about gaps

That is exactly the right direction for ZirOS. An operating system for zero-knowledge computation should not merely grow more files. It should grow more exactness. This release moves the project in that direction.
