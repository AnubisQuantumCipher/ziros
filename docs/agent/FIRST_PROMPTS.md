# ZirOS Agent First Prompts

These prompts are designed to exercise the real agent/operator surface, not a
separate chat-only workflow.

## Repo Analysis

Goal:

```text
Inspect this ZirOS checkout, summarize the current operator state, and tell me what you can do next.
```

Run:

```bash
ziros agent --json run \
  --events-jsonl /tmp/ziros-agent.events.jsonl \
  --goal "Inspect this ZirOS checkout, summarize the current operator state, and tell me what you can do next."
```

Expected outputs:

- one session
- receipts
- trust-gate report
- provider route

Inspect after:

```bash
ziros agent status --limit 5
ziros agent memory sessions --limit 5
```

## Subsystem Creation

Goal:

```text
Create a new subsystem named mission-policy-ledger with a Midnight-first contract surface and a public evidence bundle.
```

Run:

```bash
ziros agent --json run \
  --goal "Create a new subsystem named mission-policy-ledger with a Midnight-first contract surface and a public evidence bundle."
```

Approvals:

- none for scaffold and local proof work
- possible later approval for live publish edges

Inspect after:

```bash
ziros agent memory artifacts
ziros agent memory procedures
```

## Custom Circuit Extension

Goal:

```text
Add a new circuit module to the current subsystem for selective disclosure over a committed Merkle-backed membership proof, then validate and re-prove it.
```

Run:

```bash
ziros agent --json run \
  --goal "Add a new circuit module to the current subsystem for selective disclosure over a committed Merkle-backed membership proof, then validate and re-prove it."
```

Inspect after:

```bash
ziros agent memory artifacts
ziros agent memory incidents
```

## Midnight-First Contract Work

Goal:

```text
Scaffold a private-voting subsystem, prove it, and prepare the Midnight deployment artifacts.
```

Run:

```bash
ziros agent --json run \
  --goal "Scaffold a private-voting subsystem, prove it, and prepare the Midnight deployment artifacts."
```

Approvals:

- none for prepare-only work
- approval required for live submit if the flow reaches deployment

Inspect after:

```bash
ziros agent memory deployments
ziros midnight status --json
```

## EVM Secondary-Lane Export

Goal:

```text
Export the current subsystem proof as an EVM verifier bundle, initialize a Foundry project, and run the local Anvil test flow.
```

Run:

```bash
ziros agent --json run \
  --goal "Export the current subsystem proof as an EVM verifier bundle, initialize a Foundry project, and run the local Anvil test flow."
```

Inspect after:

```bash
ziros agent memory artifacts
ziros evm diagnose --json
```

## Resume A Blocked Session

If the agent paused on approval or a restart:

```bash
ziros agent status --limit 10
ziros agent resume --session-id <session-id>
```

Then inspect:

```bash
ziros agent logs --session-id <session-id>
ziros agent approvals list --session-id <session-id>
```
