# ZirOS Agent Setup Reference

This is the short reference for the setup-relevant surfaces only.

## Canonical Commands

| Surface | Commands |
| --- | --- |
| Base health | `ziros doctor`, `ziros metal-doctor` |
| Agent | `ziros agent doctor`, `status`, `plan`, `run`, `resume`, `logs` |
| Agent memory | `ziros agent memory sessions`, `receipts`, `artifacts`, `deployments`, `environments`, `procedures`, `incidents` |
| Agent approvals | `ziros agent approvals list`, `approve`, `reject` |
| Agent continuity | `ziros agent worktree list`, `create`, `cleanup`; `ziros agent checkpoint list`, `create`, `rollback` |
| Agent provider | `ziros agent provider status`, `route`, `test` |
| MCP | `ziros agent mcp serve` |
| Midnight | `ziros midnight status`, `doctor`, `resolve`, `contract ...` |
| EVM | `ziros evm verifier export`, `estimate-gas`, `foundry init`, `deploy`, `call`, `test`, `diagnose` |

## State Paths

| Path | Meaning |
| --- | --- |
| `~/.local/bin/ziros` | public-facing CLI alias |
| `~/.local/bin/zkf` | legacy compatibility alias |
| `~/.local/bin/ziros-agentd` | daemon binary |
| `~/.zkf/cache/agent/ziros-agentd.sock` | agent socket |
| `~/.zkf/cache/agent/brain.sqlite3` | encrypted Brain |
| `~/.zkf/state/ziros-first-run-v1` | first-run banner marker |
| `~/.zkf/models/` | operator-installed Core ML bundles |

## Env Vars

| Variable | Purpose |
| --- | --- |
| `ZIROS_AGENT_MLX_BASE_URL` | preferred MLX-local assistant endpoint |
| `MLX_SERVER_URL` | alternate MLX endpoint name |
| `ZIROS_AGENT_MODEL_BASE_URL` | local OpenAI-compatible assistant endpoint |
| `OPENAI_BASE_URL` | alternate local OpenAI-compatible endpoint name |
| `OLLAMA_HOST` | Ollama local endpoint |
| `OPENAI_API_KEY` | direct official OpenAI API access for the agent |
| `ZIROS_AGENT_OPENAI_MODEL` | preferred model name for the official OpenAI route |
| `OPENAI_MODEL` | alternate official OpenAI model name |
| `ZIROS_AGENT_OPENAI_BASE_URL` | override base URL for the official OpenAI route |
| `OPENAI_API_BASE` | alternate base URL override for the official OpenAI route |
| `OPENAI_PROJECT` | optional OpenAI project header for direct API calls |
| `OPENAI_ORG_ID` | optional OpenAI organization header for direct API calls |
| `MIDNIGHT_WALLET_SEED` | headless Midnight wallet diagnostics |
| `MIDNIGHT_WALLET_MNEMONIC` | headless Midnight wallet diagnostics |

## Primary Truth Files

| File | Role |
| --- | --- |
| `docs/CANONICAL_TRUTH.md` | trust and readiness interpretation |
| `release/product-release.json` | product release state |
| `release/midnight_operator_readiness.json` | Midnight readiness |
| `release/evm_operator_readiness.json` | EVM readiness |
| `support-matrix.json` | backend/frontend/gadget truth |
| `.zkf-completion-status.json` | theorem/build/test closure truth |
| `release/agent_setup_contract.json` | machine-readable setup contract for this guide |

## Agent JSON Flag Placement

`agent` owns its JSON and JSONL flags. Use:

```bash
ziros agent --json doctor
ziros agent --json provider status
ziros agent --json run --goal "Inspect this checkout"
```
