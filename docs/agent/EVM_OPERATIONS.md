# ZirOS EVM Operations

EVM is the secondary contract lane in `0.6.0`.

Use it for verifier export, Foundry/Anvil local testing, gas estimation, and
supported deploy/call workflows. Do not treat it as semantic parity with the
Midnight contract universe.

## Readiness

```bash
ziros evm diagnose --json
```

The supported target profiles are:

- `ethereum`
- `optimism-arbitrum-l2`
- `generic-evm`

## Verifier Export

```bash
ziros evm verifier export \
  --artifact /absolute/path/to/proof.json \
  --backend arkworks-groth16 \
  --out /tmp/Verifier.sol \
  --evm-target ethereum \
  --json
```

Compatibility aliases still exist:

- `zkf deploy` maps to the verifier export lane
- `zkf estimate-gas` maps to the EVM gas-estimate lane

## Foundry Bundle

```bash
ziros evm foundry init \
  --solidity /tmp/Verifier.sol \
  --out /tmp/verifier-foundry \
  --contract-name Verifier \
  --json
```

## Local Anvil Flow

Deploy:

```bash
ziros evm deploy \
  --project /tmp/verifier-foundry \
  --contract Verifier \
  --rpc-url http://127.0.0.1:8545 \
  --json
```

Call:

```bash
ziros evm call \
  --rpc-url http://127.0.0.1:8545 \
  --to 0xYourContractAddress \
  --signature "verify(bytes,bytes)" \
  --arg 0xproof \
  --arg 0xpublicInputs \
  --json
```

Test:

```bash
ziros evm test --project /tmp/verifier-foundry --json
```

Estimate gas:

```bash
ziros evm estimate-gas \
  --backend arkworks-groth16 \
  --artifact /absolute/path/to/proof.json \
  --evm-target ethereum \
  --json
```

## Agent-Driven EVM Prompt

```bash
ziros agent --json run \
  --goal "Export the current subsystem proof as an EVM verifier bundle, initialize a Foundry project, deploy it to Anvil, and run the verification test flow."
```

## Honest Limits

- EVM is a supported secondary lane, not the primary contract universe.
- Unsupported proof/backend combinations must fail explicitly.
- The agent should prefer Midnight unless the prompt clearly asks for verifier
  export or EVM deployment/test work.
