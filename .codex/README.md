# ZirOS Codex Workflow

This repo keeps a shared Codex workflow at the repo root because the wallet spans SwiftUI, Rust, and the JS helper.

Use these scripts as the project-local Codex actions:

- `./.codex/setup.sh`
- `./.codex/actions/build-mac-debug.sh`
- `./.codex/actions/open-xcode-project.sh`
- `./.codex/actions/run-mac-visual-audit.sh`
- `./.codex/actions/build-helper.sh`
- `./.codex/actions/build-workspace.sh`

Recommended worktree lanes for Mac wallet closure:

1. lock screen + unlock transition
2. overview + DUST hero
3. messages + crypto badge
4. transact + approval sheet
5. screenshot QA + regression

Local skill:

- `./.codex/skills/ziros-wallet-mac-finish`

That skill carries the wallet-specific build commands, visual targets, and acceptance checks for the Mac app.
