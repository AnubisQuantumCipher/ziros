# Getting Started: EPA Water Discharge Compliance Verifier

This tutorial walks through a complete ZirOS application using the EPA water
discharge example. It uses `zirapp.json` as the authoring surface and finishes
with compile, prove, verify, and Solidity export.

## 1. Start From The Fixture

The repo ships the example spec and inputs here:

- [`docs/examples/fixtures/epa/zirapp.json`](/Users/sicarii/Projects/ZK DEV/docs/examples/fixtures/epa/zirapp.json)
- [`docs/examples/fixtures/epa/inputs.compliant.json`](/Users/sicarii/Projects/ZK DEV/docs/examples/fixtures/epa/inputs.compliant.json)
- [`docs/examples/fixtures/epa/inputs.violation.json`](/Users/sicarii/Projects/ZK DEV/docs/examples/fixtures/epa/inputs.violation.json)

The statement is:

- pH is within range,
- lead is below the threshold,
- mercury is below the threshold,
- dissolved oxygen is above the threshold,
- temperature is below the threshold,
- the raw readings stay private,
- a public commitment binds the private data.

## 2. Understand The Signals

The app spec declares:

- private inputs such as `ph_x10`, `lead_ppb`, and `temperature_c`,
- intermediate private signals such as `__lead_gap` and `__temp_gap`,
- one public output: `commitment`.

The range checks are encoded through `ops`, and the commitment path uses staged
Poseidon permutations so the final commitment anchors the entire private state.

## 3. Audit The Spec

```bash
./target-local/release/zkf-cli audit \
  --program docs/examples/fixtures/epa/zirapp.json \
  --backend arkworks-groth16 \
  --json
```

This is the first command an agent should run. If the circuit is underanchored
or structurally unsafe, ZirOS stops here.

## 4. Compile The App Spec Directly

`compile --spec` is the high-level path for `zirapp.json`.

```bash
./target-local/release/zkf-cli compile \
  --spec docs/examples/fixtures/epa/zirapp.json \
  --backend arkworks-groth16 \
  --out /tmp/epa-compiled.json \
  --allow-dev-deterministic-groth16
```

Production note: replace `--allow-dev-deterministic-groth16` with an imported
trusted setup blob for a real Groth16 trust lane. This tutorial keeps the local
path runnable.

## 5. Prove The Compliant Case

```bash
./target-local/release/zkf-cli prove \
  --program docs/examples/fixtures/epa/zirapp.json \
  --inputs docs/examples/fixtures/epa/inputs.compliant.json \
  --backend arkworks-groth16 \
  --out /tmp/epa-proof.json \
  --allow-dev-deterministic-groth16
```

## 6. Verify

```bash
./target-local/release/zkf-cli verify \
  --program docs/examples/fixtures/epa/zirapp.json \
  --artifact /tmp/epa-proof.json \
  --backend arkworks-groth16 \
  --allow-dev-deterministic-groth16
```

## 7. Confirm The Violation Fails

```bash
./target-local/release/zkf-cli prove \
  --program docs/examples/fixtures/epa/zirapp.json \
  --inputs docs/examples/fixtures/epa/inputs.violation.json \
  --backend arkworks-groth16 \
  --out /tmp/epa-proof-bad.json \
  --allow-dev-deterministic-groth16
```

This command should fail closed because the violation input exceeds the allowed
lead threshold.

## 8. Deploy The Solidity Verifier

```bash
./target-local/release/zkf-cli deploy \
  --artifact /tmp/epa-proof.json \
  --backend arkworks-groth16 \
  --out /tmp/EpaComplianceVerifier.sol
```

Estimate the verification gas:

```bash
./target-local/release/zkf-cli estimate-gas \
  --backend arkworks-groth16 \
  --artifact /tmp/epa-proof.json \
  --json
```

## Common Mistakes

### Missing Nonlinear Anchoring

If you remove the Poseidon commitment chain and keep only subtraction/range
logic, ZirOS will reject the circuit as linearly underdetermined.

### Assuming Range Checks Alone Are Enough

They are useful, but they are not the whole story. Read
[`docs/NONLINEAR_ANCHORING.md`](docs/NONLINEAR_ANCHORING.md).

### Expecting Transparent Setup On A Groth16 Deploy Path

The transparent default is Plonky3 for first proofs. This EPA tutorial uses
Groth16 because the goal is Solidity deployment.
