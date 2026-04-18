# ZirOS Operator Core

This document is the shared operator core for Codex and Hermes when they operate on ZirOS.

It does not replace machine-readable truth. It normalizes how the operator runtimes should behave around the repo, the command surface, and the proof boundary.

## Authority Split

Use this split exactly:

- machine-readable repo truth owns formal and capability claims
- `AGENTS.md` owns repo mutation discipline, build and test obligations, and proof-tool doctrine
- `HERMES_CONSTITUTION.md` owns operator posture and non-negotiable behavioral law
- this file owns the merged operator model

If sources conflict:

1. live commands and emitted artifacts win
2. machine-readable repo truth wins next
3. `AGENTS.md` wins for repo mutation and verification discipline
4. `HERMES_CONSTITUTION.md` wins for operator posture
5. local `~/.hermes/**` state loses to all repo-tracked sources

## Truth Order

When ZirOS is in scope, trust sources in this order:

1. live commands and emitted artifacts
2. `zkf-ir-spec/verification-ledger.json`
3. `.zkf-completion-status.json`
4. `docs/CANONICAL_TRUTH.md`
5. `support-matrix.json`
6. `forensics/`
7. `AGENTS.md`
8. `docs/agent/HERMES_CONSTITUTION.md`
9. this file
10. narrative docs only when they do not conflict with the above

## Lanes

Use these lane meanings consistently:

| Lane | Meaning | Counted as release-grade formal evidence? |
| --- | --- | --- |
| `strict-proof` | mechanized or admitted proof surface work | yes, but only through the verification ledger and related truth surfaces |
| `operator-managed` | build, test, inspect, package, deploy, report, and local automation work | no |
| `support-evidence` | bounded or solver-backed support checks | no |
| `external-delegated` | remote or third-party systems outside ZirOS-owned proof truth | no |

Hermes runtime state, cron, non-GUI official-web fetch, browser automation,
session memory, and local overlays are always `operator-managed`.

## Repo-Managed Hermes Pack

The canonical Hermes pack for ZirOS lives in the repo:

- `setup/hermes/manifest.json`
- `setup/hermes/config/ziros-overlay.yaml`
- `setup/hermes/policy/ziros-guardrails.json`
- `setup/hermes/prompts/ziros-bootstrap.md`

Canonical docs and skills in the repo are copied into `~/.hermes` by the managed install and sync surfaces. The repo copy is authoritative. The home-directory copy is only the installed runtime view.

## Non-Canonical Local State

The following are local continuity state, not canonical ZirOS truth:

- `~/.hermes/config.yaml`
- `~/.hermes/SOUL.md`
- `~/.hermes/memories/`
- `~/.hermes/sessions/`
- `~/.hermes/plans/`
- `~/.hermes/cron/`
- `~/.hermes/skills/`
- `~/.hermes/ziros-pack/`
- `~/.hermes/ziros-pack.lock.json`

They may help the operator work. They must never be used as the sole source for formal, cryptographic, or release-grade claims about ZirOS.

## Command Routing

Use this routing order:

1. structured `ziros` or `zkf` command
2. `zkf-command-surface` or `zkf-agent` typed API
3. MCP tool over the same typed surfaces
4. raw shell only when no structured surface exists

When a structured surface exists, do not replace it with ad hoc shell behavior.
For official docs and release hosts, prefer `ziros agent --json web fetch`
before any GUI browser path when a deterministic fetch is sufficient.
For genuinely interactive pages, use `ziros agent browser open` and
`ziros agent browser eval` rather than ad hoc `open` or raw AppleScript.

## Hard Gates

The operator must fail closed when any of the following is true:

- a strict lane request would silently downgrade
- a remote bridge wants to mutate without a real local acceptance boundary
- secrets, approvals, or wallet material are missing
- on-chain claims lack live confirmation
- trust-lane provenance is ambiguous
- repo-managed Hermes pack drift is detected in rigorous mode
- tracked repo changes are left without required postflight verification

## Postflight Rules

After tracked repo mutations:

- run `cargo build --workspace`
- run tests for every changed crate
- rerun truth-surface or proof-boundary generators when status-bearing files change
- do not claim completion while those obligations are still outstanding

## Publication Defaults

Default posture:

- local only
- source private
- proof first
- trust-lane honest

Do not push source or repo state by default just because a remote exists.

## Hermes Rigorous Profile

The rigorous Hermes profile for ZirOS means:

- repo-managed pack installed and in sync
- hard gates enforced
- structured command first
- remote bridge read-only by default for mutation
- local handoff preserved for real writes
- truth and proof claims sourced from repo-tracked artifacts, not local memory
