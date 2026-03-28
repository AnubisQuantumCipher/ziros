# CLI Reference

This file documents the source-checkout binary surface. Requested headings like
“swarm rules” and “runtime policy” map to the real commands exposed by
`./target-local/release/zkf-cli`. For installed usage, prefer `ziros`; `zkf`
remains the compatibility alias.

## Core Proof Flow

- `emit-example`: emit a starter IR program.
  Example: `zkf-cli emit-example --field goldilocks --out /tmp/example.json`
- `compile`: compile a program or app spec.
  Example: `zkf-cli compile --spec ./zirapp.json --backend plonky3 --out /tmp/compiled.json`
- `prove`: compile, solve, and prove in one step.
  Example: `zkf-cli prove --program ./zirapp.json --inputs ./inputs.compliant.json --out /tmp/proof.json`
- `verify`: verify a proof artifact.
  Example: `zkf-cli verify --program ./zirapp.json --artifact /tmp/proof.json --backend plonky3`
- `audit`: run the fail-closed audit.
  Example: `zkf-cli audit --program ./zirapp.json --backend plonky3 --json`
- `debug`: dump diagnostics and first-failure witness information.
  Example: `zkf-cli debug --program ./zirapp.json --inputs ./inputs.compliant.json --out /tmp/debug.json`
- `optimize`: normalize and reduce a program.
  Example: `zkf-cli optimize --program ./program.json --out /tmp/optimized.json`

## Deployment And Composition

- `deploy`: export a Solidity verifier.
  Example: `zkf-cli deploy --artifact /tmp/proof.json --backend arkworks-groth16 --out /tmp/Verifier.sol`
- `estimate-gas`: estimate verifier gas.
  Example: `zkf-cli estimate-gas --backend arkworks-groth16 --artifact /tmp/proof.json --json`
- `wrap`: wrap a Plonky3 proof into Groth16.
  Example: `zkf-cli wrap --proof /tmp/stark-proof.json --compiled /tmp/stark-compiled.json --out /tmp/wrapped.json`
- `fold`: run Nova/HyperNova step folding.
  Example: `zkf-cli fold --manifest ./manifest.json --inputs ./inputs.json --backend nova --steps 4 --json`
- `equivalence`: compare outputs across backends.
  Example: `zkf-cli equivalence --program ./program.json --inputs ./inputs.json --backends arkworks-groth16,halo2,plonky3 --json`
- `conformance`: run the backend conformance suite.
  Example: `zkf-cli conformance --backend plonky3 --json`

## Inspection And Benchmarking

- `benchmark`: run multi-backend benchmarks.
  Example: `zkf-cli benchmark --backends arkworks-groth16,halo2,plonky3 --out /tmp/bench.json`
- `explore`: inspect proof internals.
  Example: `zkf-cli explore --proof /tmp/proof.json --backend plonky3 --json`
- `inspect`: inspect a frontend artifact without importing it.
  Example: `zkf-cli inspect --frontend noir --in ./target/circuit.json --json`
- `circuit show`: show IR structure and witness flow.
  Example: `zkf-cli circuit show --program ./program.json`

## Health And Capability Discovery

- `doctor`: run the system health check.
  Example: `zkf-cli doctor --json`
- `metal-doctor`: run Metal diagnostics.
  Example: `zkf-cli metal-doctor --json`
- `capabilities`: list backend capabilities.
  Example: `zkf-cli capabilities`
- `frontends`: list frontend capabilities.
  Example: `zkf-cli frontends --json`

## Swarm

Requested heading “swarm rules” maps to `swarm list-rules`.

- `swarm status`: local swarm state.
  Example: `zkf-cli swarm status --json`
- `swarm reputation`: peer reputation table.
  Example: `zkf-cli swarm reputation --all --json`
- `swarm reputation-log`: reputation evidence log.
  Example: `zkf-cli swarm reputation-log --all --json`
- `swarm list-rules`: list persisted rules.
  Example: `zkf-cli swarm list-rules --json`

## Cluster And Telemetry

- `cluster status`: show discovered peers and health.
  Example: `zkf-cli cluster status`
- `telemetry stats`: summarize the telemetry corpus.
  Example: `zkf-cli telemetry stats --json`
- `telemetry export`: export anonymized telemetry.
  Example: `zkf-cli telemetry export --input ./telemetry --out /tmp/telemetry-export.json`

## Runtime

- `runtime plan`: build a UMPG plan.
  Example: `zkf-cli runtime plan --help`
- `runtime policy`: evaluate ANE/Core ML routing policy.
  Example: `zkf-cli runtime policy --field goldilocks --backends plonky3 --constraints 50000 --json`

## Credentials

- `credential issue`: issue a private-identity credential.
  Example: `zkf-cli credential issue --help`
- `credential prove`: prove policy compliance for a credential.
  Example: `zkf-cli credential prove --help`
- `credential verify`: verify a credential proof bundle.
  Example: `zkf-cli credential verify --help`

## Apps, Registry, And Demo

- `retrain`: retrain the Neural Engine model bundle.
  Example: `zkf-cli retrain --profile production --json`
- `registry list`: list published gadgets.
  Example: `zkf-cli registry list --json`
- `app init`: scaffold a standalone app.
  Example: `zkf-cli app init --template range-proof --name quickstart --out /tmp/quickstart`
- `app gallery`: show scaffold styles.
  Example: `zkf-cli app gallery`
- `app templates`: list built-in templates.
  Example: `zkf-cli app templates`
- `demo`: run the end-to-end demo pipeline. The shipped demo uses the
  `nova-compressed-v3` attestation wrapper lane so the STARK→Groth16→Solidity
  flow completes quickly on a fresh machine; use `wrap` without `--compress`
  when you need the stricter direct FRI wrapper on a certified host.
  Example: `zkf-cli demo --out /tmp/demo --json`
