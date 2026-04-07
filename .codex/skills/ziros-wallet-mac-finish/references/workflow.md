# ZirOS Wallet Mac Workflow

## Build order

1. `./.codex/setup.sh`
2. `./.codex/actions/build-workspace.sh`
3. `./.codex/actions/build-helper.sh` when helper-facing UI/reporting changes are involved
4. `./.codex/actions/build-mac-debug.sh`

## Visual audit launcher

The wallet coordinator has a built-in visual-audit mode.

Use:

```bash
AUDIT_STATE=locked AUDIT_SECTION=overview ./.codex/actions/run-mac-visual-audit.sh
AUDIT_STATE=unlocked AUDIT_SECTION=overview ./.codex/actions/run-mac-visual-audit.sh
AUDIT_STATE=unlocked AUDIT_SECTION=messages ./.codex/actions/run-mac-visual-audit.sh
AUDIT_STATE=unlocked AUDIT_SECTION=dust ./.codex/actions/run-mac-visual-audit.sh
AUDIT_STATE=unlocked AUDIT_SECTION=transact AUDIT_TRANSACT_MODE=send ./.codex/actions/run-mac-visual-audit.sh
AUDIT_STATE=unlocked AUDIT_SECTION=transact AUDIT_TRANSACT_MODE=send AUDIT_APPROVAL=transaction ./.codex/actions/run-mac-visual-audit.sh
```

## Guardrails

- Do not redesign Rust/FFI/helper policy in a Mac polish task.
- Keep proof-server route visibility intact.
- Keep DUST and privacy as hero surfaces.
- Prefer Mac-specific layout branches over regressions to iPhone fit.
