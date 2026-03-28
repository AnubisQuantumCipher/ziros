# ZirOS App Developer TUI Guide

## Goal

Use this guide when you want a standalone ZirOS app to feel like an application, not just a proof
runner. The TUI lane keeps the same proving and verification guarantees as `zkf-lib`; it only
changes presentation and interaction.

## Choose the Right Style

- Choose `colored` when you want a normal CLI entrypoint with a polished proof banner, audit
  surface, proof summary, and live progress reporting.
- Choose `tui` when you want a full-screen terminal application with panels, selection state,
  prove actions, and proof/result modals.

Start from the gallery or scaffold directly:

```bash
zkf app gallery
zkf app init my-zk-app --template poseidon-commitment --style tui
```

## How Progress Feeds the UI

`zkf-lib` now exposes `ProofEvent` plus `compile_and_prove_with_progress(...)`.

The event order is fixed:

1. compile
2. witness generation
3. witness preparation / constraint check
4. prove

`zkf-tui` consumes those events to drive:

- the proof gauge
- the proof activity animation
- the live progress modal

This is presentation only. The same proving path still routes through the existing audited
compile/prove surface and keeps the soundness choke points intact.

## Dashboard Model

The current `zkf-tui` dashboard surface is intentionally small:

- `VaultEntry`: row-level data for the left table
- `DashboardState`: selected row, health score, proof progress state, audit lines, modal state
- `ZkDashboard`: draw + keyboard handling
- `spawn_local_proof_job(...)`: background worker for the local proof demo path

The default layout is:

- left: vault table
- center: credential detail panel
- right: health gauge, proof gauge, audit panel
- lower strip: status panel plus proof activity animation
- modal: credential detail or proof/result surface

## Adapting the Scaffold

The scaffolded `src/dashboard.rs` is the integration layer. Customize there first.

Safe customization points:

- replace the sample `VaultEntry` rows with your app data
- rewrite the center panel labels for your credential type
- change the status and audit lines to match your domain
- replace the prove trigger wiring with your own program/template inputs

Do not move proof soundness responsibilities into the TUI layer. Keep these in the proving path:

- program construction in `zkf-lib`
- compile/prove/verify through `zkf-lib`
- audit surfaces through `zkf-lib`
- witness correctness and backend preparation through the existing backend pipeline

## AegisVault Reference

The reference dashboard lives at:

`cargo run -p zkf-tui --example aegisvault`

The shipped reference proof path uses the deterministic Groth16 development override so it can
prove locally without imported CRS material. Treat that as a demo convenience only; production app
flows should compile against trusted setup blobs instead.

Use it as the visual baseline for:

- table/detail/gauge layout
- proof progress behavior
- modal-driven proof results
- command bar phrasing

## Validation

Phase 5 validation uses two paths:

- automated viewport validation via `cargo test -p zkf-tui --lib`
- terminal profile reporting via `cargo run -p zkf-tui --example aegisvault_validation`

The validation profile matrix currently covers:

- `iTerm2`
- `Terminal.app`
- `VS Code Terminal`
- `Windows Terminal`
- compact resize smoke profiles for narrow layouts

The detailed checklist and commands live in
[`AEGISVAULT_TERMINAL_VALIDATION.md`](/Users/sicarii/Projects/ZK DEV/docs/AEGISVAULT_TERMINAL_VALIDATION.md).
