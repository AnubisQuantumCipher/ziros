# ZirOS Agent Closure Spec

Generated: `2026-04-07T05:33:10.164268Z`

This document enumerates what is already closed by source and what remains to reach the full ZirOS Agent blueprint end-state without changing the architectural direction.

## Closed Now
- In-tree workspace integration is complete.
- `zkf-command-surface` is the command-native substrate.
- `zkf-agent` owns planner, executor, daemon, Brain, trust gate, and MCP.
- `zkf wallet ...` and the missing Midnight contract/status surfaces are CLI-addressable.
- The host is now available as both SwiftPM shell and Xcode app target, with a launchd wrapper for local daemon supervision.

## Remaining Depth Work

## Immediate Next Implementation Tranche
- Expand the executor into more of the existing ZirOS runtime and release surfaces as new subsystem families are added.
- Keep reducing the need for keyword fallback by passing explicit intent from more callers.
- Add deeper end-to-end tests for daemon restarts, checkpoint rollback, and host-driven approval resumes.

## Current Quantitative Snapshot
- Action inventory: `19` actions.
- Workflow families: `12`.
- Brain tables: `18`.
- Agent top-level commands: `18`.

## Non-Goals For This Tranche
- Replacing the daemon with XPC.
- Rewriting the host into a direct engine UI.
- Adding cloud sync to ZirOS Brain.
