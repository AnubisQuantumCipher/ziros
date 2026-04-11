# ZirOS Capability Truth Audit and Midnight Trade-Finance Contract Blueprint

Generated: `2026-04-11T19:15:57.899008Z`

This report is source-first and truth-surface-first. It implements the requested audit of what the current checkout can actually do across formal verification, ZIR/ZKF language surfaces, and Midnight contract support, then narrows the opportunity to the best repo-aligned market: private trade-finance receivables settlement.

## PHASE 1 — Formal Verification Truth
### Files Examined
- `AGENTS.md`
- `docs/CANONICAL_TRUTH.md`
- `docs/FORMAL_TOOLCHAIN_INTEGRATION.md`
- `docs/SECURITY.md`
- `.zkf-completion-status.json`
- `zkf-ir-spec/verification-ledger.json`
- `zkf-ir-spec/src/verification.rs`
- `formal/refinedrust/README.md`
- `formal/refinedrust/runtime-buffer-bridge/STATUS.md`
- `scripts/run_refinedrust_proofs.sh`
- `scripts/run_thrust_checks.sh`
### Findings
- The live truth surfaces report `193` verification rows with `189` `mechanized_local` rows and `4` `mechanized_generated` rows; release-grade readiness is `True`.
- Counted checker mix is `verus=96`, `rocq=76`, `lean=13`, `fstar=2`, `refined_rust=1`, and `generated_proof=4`.
- The Rust doctrine is strict: `RefinedRust` and `Verus` are counted lanes, `Kani` and `Thrust` are support-only, and `Flux`, `Creusot`, and `Prusti` are comparison-only.
- The currently admitted counted RefinedRust surface is only `runtime-buffer-bridge`; this checkout does not admit broad RefinedRust coverage claims outside that capsule.
- Runtime proof-boundary closure is complete at `89` files / `1788` functions.
### Gaps and Concerns
- The protocol rows are machine-checked but still intentionally classed as `trusted_protocol_tcb`, so the checkout does not claim end-to-end elimination of cryptographic assumptions.
- The mechanized-generated trade-finance rows are generated artifact/certificate surfaces and must not be confused with standalone hand-written theorem files.
### Verdict
The checkout is genuinely proof-heavy and release-grade on its own truth surfaces, but its assurance story is honest only when counted lanes, support lanes, model-only rows, and trusted protocol boundaries remain clearly separated.

## PHASE 2 — ZIR / ZirFlow / Program Family Truth
### Files Examined
- `docs/ZIR_LANGUAGE.md`
- `docs/ZIRFLOW.md`
- `docs/CLI.md`
- `zkf-cli/src/cmd/lang.rs`
- `zkf-lang/src/lib.rs`
- `zkf-frontends/src/lib.rs`
- `zkf-frontends/src/cairo.rs`
### Findings
- Zir is a native source DSL over shipped program families, not a claim that arbitrary general-purpose software is automatically formally verified.
- Tier 1 is the bounded total circuit subset; Tier 2 preserves advanced ZIR constructs and fails closed when forced through unsupported `ir-v2` or backend paths.
- The canonical family split is `zir-v1` for lossless interchange and `ir-v2` for lowered backend consumption.
- Live frontend support in the current binary covers `noir, circom, cairo, compact, halo2-rust, plonky3-air, zkvm`.
- ZirFlow is already a bounded workflow surface with explicit approval for mutating steps such as package, prove, and verify.
### Gaps and Concerns
- Tier 2 recursive aggregation markers remain metadata-only and must not be marketed as in-circuit recursive verification.
- Some frontend families, especially Cairo and Compact, retain fail-closed subset boundaries rather than universal source-language coverage.
### Verdict
The native language stack is strong for bounded proof programming and lossless interchange, but it is intentionally not a claim of universal, automatic verification for arbitrary programs.

## PHASE 3 — Live Binary + Midnight Capability Truth
### Files Examined
- `support-matrix.json`
- `zkf-cli/src/cmd/capabilities.rs`
- `zkf-cli/src/cmd/midnight.rs`
- `zkf-cli/src/cmd/midnight/templates.rs`
- `zkf-cli/src/tests/midnight_platform.rs`
- `zkf-cli/src/tests/compact_integration.rs`
- `.ops/bitrove-first-dollar/README.md`
- `dist/showcases/private_trade_finance_settlement/midnight_validation/summary.json`
### Findings
- Live backend support in the current binary covers `plonky3, halo2, halo2-bls12381, arkworks-groth16, sp1, risc-zero, nova, hyper-nova, midnight-compact`.
- The current binary reports `6` shipped Midnight templates, including `supply-chain-provenance`, but the strongest contract/product fit in this checkout is the trade-finance settlement package already emitted under `dist/showcases/private_trade_finance_settlement`.
- On this host, Midnight doctor reports `passed=7`, `warned=2`, `failed=0`, and `not_checkable=4`.
- The proof server is healthy on `http://127.0.0.1:6300` and the gateway is reachable but Access-protected.
- The current host blocker is preview RPC reachability, not proof-server absence.
### Gaps and Concerns
- The support matrix labels `midnight-compact` as delegated-or-external; it must not be described as a native strict cryptographic proof lane.
- Wallet session and spendable tDUST remain not checkable from a bare CLI process on this host.
### Verdict
The local Midnight developer platform is real and already useful, but the honest contract remains: proof-server and gateway surfaces are shipped, while live submission readiness remains environment-dependent and fail-closed.

## PHASE 4 — Web Market Verdict
### Files Examined
- `research_trade_finance_competitor_gap_landscape.txt`
- `https://www.federalreserve.gov/econres/notes/feds-notes/tokenized-assets-on-public-blockchains-how-transparent-is-the-blockchain-20240403.html`
- `https://institutions.ethereum.org/privacy`
- `https://www.adb.org/sites/default/files/publication/906596/adb-brief-256-2023-trade-finance-gaps-growth-jobs-survey.pdf`
- `https://iccwbo.org/news-publications/news/new-icc-case-studies-provide-guidance-for-trade-digitalisation/`
- `https://www.sba.gov/funding-programs/loans/export-loans/export-working-capital-program`
### Findings
- Federal Reserve guidance confirms that public-chain transparency is a poor default for sensitive financial workflows.
- Ethereum institutional privacy guidance confirms that institutions want selective disclosure and confidentiality for counterparties, data, and business logic.
- ADB quantifies trade finance as a multi-trillion-dollar unmet financing problem and explicitly links digitalization progress to standards and document-law gaps.
- ICC case studies and DSI guidance confirm that trade digitalization is a multi-document interoperability problem, not just a smart-contract coding problem.
- The repo-local competitor landscape already points to the same gap: privacy-native, selective-disclosure, workflow-centric trade finance.
### Gaps and Concerns
- The web evidence supports the market thesis, but American market sizing is stronger on need/problem structure than on a single canonical U.S.-only trade-finance number.
- This opportunity should be framed as a U.S.-relevant enterprise financing and export-working-capital problem, not as a consumer-market app.
### Verdict
The best billion-scale problem to target with this checkout is private trade-finance receivables settlement: it matches the repo’s strongest shipped proof/application lane and maps cleanly to the documented market need for confidentiality, interoperability, document coordination, and selective disclosure.

## PHASE 5 — Contract Blueprint
### Files Examined
- `dist/showcases/private_trade_finance_settlement/private_trade_finance_settlement.summary.json`
- `dist/showcases/private_trade_finance_settlement/private_trade_finance_settlement.run_report.json`
- `dist/showcases/private_trade_finance_settlement/private_trade_finance_settlement.evidence_summary.json`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/package_manifest.json`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/flow_manifest.json`
- `zkf-lib/examples/private_trade_finance_settlement_showcase.rs`
- `zkf-lib/src/app/private_trade_finance_settlement.rs`
- `zkf-lib/src/app/private_trade_finance_settlement_export.rs`
- `scripts/validate_private_trade_finance_midnight_contracts.sh`
- `scripts/materialize_private_trade_finance_settlement_subsystem.sh`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/financing_request_registration.compact`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/settlement_authorization.compact`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/dispute_hold.compact`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/disclosure_access.compact`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/repayment_completion.compact`
- `dist/showcases/private_trade_finance_settlement/midnight_package/trade-finance-settlement/contracts/compact/supplier_receipt_confirmation.compact`
### Findings
- The shipped trade-finance Midnight package is already decomposed into six Compact contracts and ten flow calls; the honest first implementation is to preserve that split.
- The primary strict off-chain proof lane is `hypernova`, with effective backend `hypernova` and lane classification `primary-strict`.
- The contract family cleanly separates registration, settlement authorization, dispute hold, disclosure access, repayment completion, and supplier receipt confirmation.
- All on-chain fields are commitments, role codes, or Boolean flags; raw commercial data stays off chain.
- The generated validation lane already covers compile, deploy-prepare, call-prepare, and gateway admission reporting.
- Per-contract deploy-prepare assets are preserved under `deploy_prepare_assets` instead of collapsing to the final loop iteration.
- Per-call call-prepare assets are preserved under `call_prepare_assets` instead of collapsing to the final loop iteration.
- `financing_request_registration` exposes `invoice_packet_commitment, eligibility_commitment, action_class_code, registered`.
- `settlement_authorization` exposes `maturity_schedule_commitment, approved_advance_commitment, reserve_amount_commitment, settlement_finality_flag`.
- `dispute_hold` exposes `dispute_hold_commitment, hold_active`.
- `disclosure_access` exposes `disclosure_role_code, disclosure_view_commitment, disclosure_authorization_commitment`.
- `repayment_completion` exposes `repayment_completion_commitment, released`.
- `supplier_receipt_confirmation` exposes `maturity_schedule_commitment, supplier_receipt_confirmation_confirmed`.
### Gaps and Concerns
- The current Compact contracts are commitment-and-state publication surfaces; they do not by themselves replace the off-chain proof system or prove native recursive verification on Midnight.
- Live deployment still depends on environment readiness: RPC, wallet session, and DUST availability remain operational prerequisites.
### Verdict
The correct first Midnight contract implementation is not a fresh monolithic design. It is the six-contract trade-finance settlement family already emitted in `dist/`, with HyperNova remaining the primary strict proof lane and Midnight Compact remaining the commitment, admission, and selective-disclosure publication layer.

## Final Assessment
- The formal-verification stack is far more capable than a typical ZK repo, but only when its honesty rules are preserved.
- The ZIR/ZirFlow stack is mature enough to describe and package bounded proof programs without pretending to verify arbitrary software.
- The Midnight surface is already concrete enough to ship contract families and validation artifacts.
- The strongest repo-aligned business opportunity is private receivables settlement with selective disclosure, not a generic smart-contract platform pitch.
