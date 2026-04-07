# ZirOS Apple Silicon Setup

This guide explains the runtime stack that the ZirOS agent actually uses on
Apple Silicon.

## Runtime Roles

| Layer | What it does | What it does not do | How to inspect |
| --- | --- | --- | --- |
| Metal proof lane | Accelerates proving stages such as NTT, MSM, hashing, and related runtime work on Apple Silicon GPUs | It is not LLM inference and it is not advisory-only | `ziros metal-doctor --json --strict` |
| MLX local model lane | Preferred local assistant-model routing for planning, summarization, and operator help on Apple Silicon | It does not decide proof validity or bypass policy | `ziros agent --json provider status` and `ziros agent --json provider test` |
| Core ML / Neural Engine lane | Advisory control-plane models for scheduling, anomaly scoring, and related runtime policy hints | It does not prove anything and it must not be treated as a trust boundary | `docs/NEURAL_ENGINE_OPERATIONS.md` |
| Encrypted Brain | Stores the agent's persistent local memory | It is not cloud memory and it is not a hidden remote service | `ziros agent memory ...` |
| Keychain / Secure Enclave | Protects local secrets and agent Brain encryption keys through ZirOS key-management layers | It does not replace explicit approvals or receipts | `ziros doctor --json` |

## Required Tools

| Tool | Why ZirOS needs it |
| --- | --- |
| `cargo` and `rustc` | Build the CLI and daemon |
| `git` | Worktree-per-run isolation and repo operations |
| `xcrun` | Apple toolchain presence check |

## Midnight-First Tools

These are required if you want the Midnight lane enabled:

| Tool | Why it matters |
| --- | --- |
| `node` | Midnight package and project tooling |
| `npm` | Pinned Midnight dependency install lane |
| `compactc` | Compact contract compilation |
| `compact` | Compact manager tooling |

Headless wallet diagnostics for release-grade operator work can also use:

- `MIDNIGHT_WALLET_SEED`
- `MIDNIGHT_WALLET_MNEMONIC`

Those are optional for basic setup, but required for honest live-submit checks.

## EVM Secondary-Lane Tools

These are required if you want the EVM compatibility lane enabled:

| Tool | Why it matters |
| --- | --- |
| `forge` | Foundry build and test surface |
| `anvil` | Canonical local EVM node |
| `cast` | Canonical call/send interaction surface |

## Local-First Model Routing

The agent currently uses:

- in-process planner: `embedded-zkf-planner`
- local assistant preference order:
  - `mlx-local`
  - `openai-compatible-local`
  - `ollama-local`
- remote optional assistant:
  - `openai-api`

The repo discovers those endpoints through these env vars:

- `ZIROS_AGENT_MLX_BASE_URL`
- `MLX_SERVER_URL`
- `ZIROS_AGENT_MODEL_BASE_URL`
- `OPENAI_BASE_URL`
- `OLLAMA_HOST`
- `OPENAI_API_KEY`
- `ZIROS_AGENT_OPENAI_MODEL`
- `OPENAI_MODEL`
- `ZIROS_AGENT_OPENAI_BASE_URL`
- `OPENAI_API_BASE`
- `OPENAI_PROJECT`
- `OPENAI_ORG_ID`

If you want ZirOS to talk to OpenAI directly without a local gateway, set
`OPENAI_API_KEY` and optionally `ZIROS_AGENT_OPENAI_MODEL`.

The guide-standard env file is:

```text
examples/agent/ziros-agent.env.example
```

## Canonical Checks

Base runtime:

```bash
ziros doctor --json
ziros metal-doctor --json --strict
ziros agent --json doctor
ziros agent --json provider status
ziros agent --json provider test
```

Midnight:

```bash
ziros midnight status --json
ziros midnight doctor --json --strict --network preprod
```

EVM:

```bash
ziros evm diagnose --json
```

## State Paths

| Path | Meaning |
| --- | --- |
| `~/.local/bin/ziros` | Public-facing CLI alias installed by the bootstrap |
| `~/.local/bin/zkf` | Legacy compatibility alias |
| `~/.local/bin/ziros-agentd` | Installed daemon binary |
| `~/.zkf/cache/agent/ziros-agentd.sock` | Local daemon socket |
| `~/.zkf/cache/agent/brain.sqlite3` | Encrypted local Brain |
| `~/.zkf/models/` | Operator-installed Core ML model bundles |

## Honest Limits

- Core ML and the Neural Engine are advisory only.
- Proof validity does not depend on any model output.
- Midnight local operator readiness and Midnight live-submit readiness are not
  the same thing. Always inspect `ready_for_live_submit`.
- EVM remains the secondary lane in `0.6.0`.
