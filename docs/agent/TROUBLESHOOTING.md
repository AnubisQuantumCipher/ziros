# ZirOS Agent Troubleshooting

## Daemon And Socket

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| `ziros agent ...` cannot connect | `ls ~/.zkf/cache/agent/ziros-agentd.sock` | socket exists | start `ziros-agentd` |
| Host opens but shows nothing | `ziros agent status --limit 10` | JSON or human session list | start daemon first, then reopen `ZirOSAgentHost` |
| Session vanished after restart | `ziros agent memory sessions --limit 20` | prior sessions still listed | inspect the Brain at `~/.zkf/cache/agent/brain.sqlite3` and restart the daemon |

## Provider Routing

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| No local model route detected | `ziros agent --json provider status` | `mlx-local`, local OpenAI-compatible, or Ollama route appears when configured | set `ZIROS_AGENT_MLX_BASE_URL`, `ZIROS_AGENT_MODEL_BASE_URL`, or `OLLAMA_HOST` |
| Provider detected but unhealthy | `ziros agent --json provider test` | route probe returns `ready=true` | fix the local endpoint and retry |
| Agent only uses planner | `ziros agent --json provider status` | `embedded-zkf-planner` plus optional assistant routes | add one local assistant endpoint to the env file and re-source it |

## Apple Silicon And Metal

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| Metal unavailable | `ziros metal-doctor --json --strict` | healthy Metal report | confirm Apple Silicon host and Xcode toolchain availability |
| You expected Neural Engine to prove | `ziros metal-doctor --json` | proof lane is Metal, not ANE | read `docs/NEURAL_ENGINE_OPERATIONS.md`; ANE is advisory only |

## Midnight

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| Proof server not ready | `ziros midnight doctor --json --network preprod` | proof-server check passes | start `ziros midnight proof-server serve --engine umpg` |
| Gateway not ready | `ziros midnight doctor --json --network preprod` | gateway check passes | start `ziros midnight gateway serve --port 6311` |
| Wallet not checkable | `ziros midnight doctor --json --strict --network preprod` | wallet check no longer reports `not_checkable_from_cli` | set `MIDNIGHT_WALLET_SEED` or `MIDNIGHT_WALLET_MNEMONIC`, or use the browser-assisted path |
| tDUST not ready | `ziros midnight status --json` | `ready_for_live_submit=true` only when wallet and tDUST are honestly ready | fund the wallet and re-run doctor/status |

## EVM

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| Foundry missing | `ziros evm diagnose --json` | Foundry tool checks pass | install or expose `forge`, `anvil`, and `cast` in `PATH` |
| Local deploy fails | `ziros evm test --project /path/to/project --json` | tests pass against the local harness | start `anvil`, then retry deploy/call |

## Memory And Learning

| Symptom | Check | Expected signal | Fix |
| --- | --- | --- | --- |
| Agent "forgot" prior work | `ziros agent memory sessions --limit 20` | old sessions still exist | verify you are on the same host/user and using the same Brain path |
| Procedures never appear | `ziros agent memory procedures` | successful reusable procedures show up over time | complete a full successful run; only successful flows promote to procedures |
| Incidents never appear | `ziros agent memory incidents` | failed runs are listed | inspect the latest receipts and rerun the failed goal |
