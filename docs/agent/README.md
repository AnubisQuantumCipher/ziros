# ZirOS Agent Setup

This is the canonical setup path for the ZirOS autonomous operator on Apple
Silicon.

ZirOS is not a chat shell glued onto random tools. The real product surface is:

- `ziros` for operator commands
- `ziros-agentd` as the single local execution authority
- the encrypted local Brain for persistent memory
- `ZirOSAgentHost` as an optional thin macOS shell over the daemon

Start here if you want the agent to:

- remember sessions, procedures, incidents, artifacts, and deployments
- improve continuity across runs by reusing local state
- route work through Apple-Silicon-native proof and model surfaces
- operate Midnight-first and EVM-second from one prompt with sparse approvals

## Start Here

1. [Quickstart](QUICKSTART.md)
2. [Apple Silicon Setup](SETUP_APPLE_SILICON.md)
3. [Memory And Learning](MEMORY_AND_LEARNING.md)
4. [First Prompts](FIRST_PROMPTS.md)
5. [Midnight Operations](MIDNIGHT_OPERATIONS.md)
6. [EVM Operations](EVM_OPERATIONS.md)
7. [Troubleshooting](TROUBLESHOOTING.md)
8. [Reference](REFERENCE.md)

## Canonical Bootstrap

The one supported bootstrap entrypoint is:

```bash
bash setup/agent/bootstrap.sh
```

The script builds and installs the public-facing command aliases expected by
this guide:

- `~/.local/bin/ziros`
- `~/.local/bin/zkf`
- `~/.local/bin/ziros-agentd`

The current release artifact built by Cargo is `zkf-cli`. This guide
standardizes on the installed `ziros` command, while keeping `zkf` as a
compatibility alias.

## State And Control Plane

The most important local paths are:

- agent socket: `~/.zkf/cache/agent/ziros-agentd.sock`
- encrypted Brain: `~/.zkf/cache/agent/brain.sqlite3`
- local env example: `examples/agent/ziros-agent.env.example`
- bootstrap: `setup/agent/bootstrap.sh`
- optional host shell: `ZirOSAgentHost/README.md`

## Product Posture

- Midnight is the primary smart-contract lane.
- EVM is the secondary verifier/export/deploy/test lane.
- Metal proof execution is authoritative for acceleration.
- Core ML and the Neural Engine are advisory control-plane inputs only.
- Memory is local, encrypted, and inspectable through `ziros agent memory ...`.
