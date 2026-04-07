# ZirOS Midnight Operations

Midnight is the primary contract lane for the ZirOS agent.

## What "Ready" Means

Use the machine-readable readiness surfaces, not guesswork:

```bash
ziros midnight status --json
ziros midnight doctor --json --strict --network preprod
```

Important distinction:

- `ready_for_local_operator=true` means local compile/prove/prepare work is
  ready
- `ready_for_live_submit=true` means wallet, gateway, and tDUST conditions are
  also ready for honest live submission

## Local Operator Workflow

Scaffold a project:

```bash
ziros midnight init --name my-dapp --template token-transfer
```

Compile:

```bash
ziros midnight contract compile \
  --source /absolute/path/to/contract.compact \
  --out /tmp/my-contract.zkir.json \
  --json
```

Prepare deploy:

```bash
ziros midnight contract deploy-prepare \
  --source /absolute/path/to/contract.compact \
  --out /tmp/deploy.json \
  --project /absolute/path/to/my-dapp \
  --json
```

Prepare call:

```bash
ziros midnight contract call-prepare \
  --source /absolute/path/to/contract.compact \
  --call castVote \
  --inputs /absolute/path/to/inputs.json \
  --out /tmp/call.json \
  --project /absolute/path/to/my-dapp \
  --json
```

Validate contract-scoped readiness:

```bash
ziros midnight contract test --project /absolute/path/to/my-dapp --json
ziros midnight contract diagnose --project /absolute/path/to/my-dapp --json
```

## Live Submit Workflow

Only do this when the readiness report says live submit is actually ready.

Deploy:

```bash
ziros midnight contract deploy --project /absolute/path/to/my-dapp --json
```

Call:

```bash
ziros midnight contract call --project /absolute/path/to/my-dapp --json
```

Explorer verification:

```bash
ziros midnight contract verify-explorer --project /absolute/path/to/my-dapp --json
```

## Agent-Driven Midnight Prompt

```bash
ziros agent --json run \
  --goal "Create a subsystem for private voting, prove it, and prepare the Midnight deployment and call artifacts."
```

If the run blocks on approval:

```bash
ziros agent approvals list
ziros agent approve --pending-id <pending-id> --primary-prompt "Approve Midnight submission"
```

## Failure Classification

Treat these categories differently:

- product/toolchain readiness: compile, proof server, package pin, local gateway
- operator readiness: wallet session and tDUST
- external network issues: RPC, indexer, explorer, remote gateway edge cases

The canonical place to inspect those distinctions is the JSON report from:

```bash
ziros midnight doctor --json --strict --network preprod
```
