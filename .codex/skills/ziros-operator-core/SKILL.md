---
name: ziros-operator-core
description: Load the shared ZirOS operator core, preserve the authority split between repo truth, AGENTS discipline, and Hermes posture, and keep local Hermes state classified as non-canonical overlay state.
---

# ZirOS Operator Core

Use this skill whenever Hermes or another operator runtime is working on ZirOS.

## Rules

- Read `docs/agent/OPERATOR_CORE.md` before treating local memory or prompts as truth.
- Use live commands and machine-readable repo truth ahead of local `~/.hermes/**` state.
- Treat `~/.hermes/**` as operator continuity state, never as canonical proof or release truth.
- Preserve the lane split: `strict-proof`, `operator-managed`, `support-evidence`, `external-delegated`.
- Preserve the repo authority split:
  - machine truth for claims
  - `AGENTS.md` for repo mutation and verification discipline
  - `HERMES_CONSTITUTION.md` for operator law

## First commands

- `ziros agent hermes doctor --json`
- `~/.ziros/bin/ziros-managed.bin gateway status --json`
- `~/.ziros/bin/ziros-managed.bin capabilities --json`
