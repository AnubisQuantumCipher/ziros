---
name: ziros-worktree-discipline
description: Enforce Codex-grade repo mutation discipline for Hermes and other operator runtimes on ZirOS worktrees.
---

# ZirOS Worktree Discipline

- Do not mutate unrelated dirty files.
- Prefer managed worktrees or tightly scoped edits.
- Never use destructive git operations unless explicitly requested.
- After tracked-file changes, run required crate tests and `cargo build --workspace`.
- Do not claim completion while postflight checks are missing.
