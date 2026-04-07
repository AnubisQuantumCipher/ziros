# ZirOS Agent Memory And Learning

The ZirOS agent is designed to remember local operational history and become
more effective over time without hiding how that happens.

## Where Memory Lives

The Brain is an encrypted local SQLite database:

```text
~/.ziros/agent/brain.sqlite3
```

The key is managed through ZirOS key-management layers, not by a plaintext
password file in the repo.

## What The Agent Persists

The current Brain surfaces in `zkf-agent` persist:

- sessions
- goals
- workgraphs and nodes
- receipts
- artifacts
- procedures
- incidents
- approval requests
- approval tokens
- submission grants
- deployments
- environment snapshots
- worktrees
- checkpoints
- provider routes
- project registry entries

## How This Improves Capability

The agent does not claim open-ended autonomous self-rewriting. It improves by
carrying forward useful local state:

- successful workflows become reusable procedures
- failures become incidents with exact blocked surfaces and repair hints
- project roots stay registered locally
- provider routing decisions persist across sessions
- worktrees and checkpoints make long-running work resumable
- receipts, artifacts, and deployment records let the agent explain prior work

This is why the agent can get more capable the longer it runs on the same host:
it accumulates local operator memory, not because it invents new hidden system
capabilities.

## Commands To Inspect Memory

Sessions:

```bash
ziros agent memory sessions --limit 20
```

Receipts:

```bash
ziros agent memory receipts --session-id <session-id>
```

Artifacts and deployments:

```bash
ziros agent memory artifacts --session-id <session-id>
ziros agent memory deployments --session-id <session-id>
```

Environment snapshots:

```bash
ziros agent memory environments
```

Procedures and incidents:

```bash
ziros agent memory procedures
ziros agent memory incidents
```

Approvals and lineage:

```bash
ziros agent approvals list
```

## Commands To Inspect Continuity

Worktrees:

```bash
ziros agent worktree list
```

Checkpoints:

```bash
ziros agent checkpoint list --session-id <session-id>
```

Provider routes:

```bash
ziros agent provider status
ziros agent provider test
```

## What It Does Not Mean

- The Brain is not cloud-synced memory.
- The Brain is not a hidden remote SaaS service.
- The Brain does not bypass approval gates.
- The Brain does not turn advisory model output into trust truth.
