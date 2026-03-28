# ZirOS Tutorial

`ziros` is the preferred installed command name in this guide. `zkf` remains
the compatibility alias. Use `./target-local/release/zkf-cli` only when you
explicitly want the source-checkout binary.

## Your First ZK App in 5 Minutes

### 1. Scaffold a standalone app

```bash
ziros app init my-zk-app --template poseidon-commitment
cd my-zk-app
```

This is the primary application-developer path in v1. The scaffold gives you a local Cargo
workspace wired to the current ZirOS checkout, plus a declarative `zirapp.json`,
`inputs.compliant.json`, `inputs.violation.json`, and a smoke test.

### 2. Run the generated app

```bash
cargo run
cargo test
```

The generated binary compiles, proves, and verifies in-process through `zkf-lib`. No shelling out
to `zkf-cli`, no temp JSON handoff files, and no separate runtime install are required for shipped
apps.

### 3. Customize the app in `zirapp.json`

The default scaffold path is declarative. Edit `zirapp.json`, then rerun the generated app:

```json
{
  "program": { "name": "custom_range_app", "field": "bn254" },
  "signals": [
    { "name": "value", "visibility": "private" },
    { "name": "is_valid", "visibility": "public" }
  ],
  "ops": [
    { "kind": "range", "signal": "value", "bits": 32, "label": "value_range" },
    {
      "kind": "equal",
      "lhs": { "op": "signal", "args": "is_valid" },
      "rhs": { "op": "const", "args": "1" },
      "label": "valid_flag"
    }
  ]
}
```

### 4. Use `ProgramBuilder` when you need the escape hatch

When the declarative surface is not enough, switch to explicit Rust authoring:

```rust
use zkf_lib::{Expr, FieldElement, FieldId, ProgramBuilder};

pub fn program() -> zkf_lib::Program {
    let mut builder = ProgramBuilder::new("custom_range_app", FieldId::Bn254);
    builder.private_input("value").expect("value");
    builder.public_output("is_valid").expect("is_valid");
    builder
        .constant_signal("one", FieldElement::ONE)
        .expect("one");
    builder.constrain_range("value", 32).expect("range");
    builder
        .constrain_equal(Expr::signal("is_valid"), Expr::signal("one"))
        .expect("valid flag");
    builder.build().expect("build")
}
```

For the full app-developer surface, including input helpers, audit wrappers, and verifier export,
see:

- [`docs/APP_DEVELOPER_GUIDE.md`](/Users/sicarii/Projects/ZK DEV/docs/APP_DEVELOPER_GUIDE.md)
- [`docs/APPSPEC_REFERENCE.md`](/Users/sicarii/Projects/ZK DEV/docs/APPSPEC_REFERENCE.md)
- [`docs/NONLINEAR_ANCHORING.md`](/Users/sicarii/Projects/ZK DEV/docs/NONLINEAR_ANCHORING.md)

---

## Raw IR JSON Flow

You can still author or inspect raw IR JSON directly when you need the
lower-level/manual path.

### 1. Generate a sample circuit

```bash
zkf emit-example --out multiply.json
```

This creates a simple multiplication circuit: given private inputs `x` and `y`, prove that `out = x * y` without revealing `x` or `y`.

### 2. Create witness inputs

```bash
cat > inputs.json << 'EOF'
{
  "x": "3",
  "y": "7"
}
EOF
```

### 3. Compile, prove, verify, and deploy

```bash
# Compile for Groth16
zkf compile --program multiply.json --backend arkworks-groth16 --out compiled.json

# Prove with Groth16
zkf prove --program multiply.json --inputs inputs.json \
  --backend arkworks-groth16 --out proof.json

# Verify the proof
zkf verify --program multiply.json --artifact proof.json \
  --backend arkworks-groth16

# Export an Ethereum verifier
zkf deploy --artifact proof.json --backend arkworks-groth16 \
  --out Verifier.sol --evm-target ethereum
```

The verifier sees only that `out = 21` — never the individual factors.

On the certified Apple Silicon host, `--mode metal-first` can route BN254 proving and wrapping
through the strict Metal lane. Outside that lane, Metal remains an optimization, not a correctness
requirement. If you pass `--distributed`, the coordinator partitions the proving graph and retries
failed remote partitions locally so proof results stay identical to single-node execution.

---

## Importing from Noir

### 1. Compile your Noir program

```bash
# In your Noir project directory
nargo compile
```

This produces an ACIR artifact (typically at `target/your_circuit.json`).

### 2. Import into ZKF

```bash
zkf import --frontend noir --in ./target/your_circuit.json \
  --out ir/program.json --name my_circuit --ir-family auto
```

### 3. Inspect the import

```bash
zkf inspect --frontend noir --in ./target/your_circuit.json
```

### 4. Prove with any backend

```bash
# Groth16 (BN254)
zkf prove --program ir/program.json --inputs inputs.json \
  --backend arkworks-groth16 --out proof_groth16.json

# Halo2 (Pasta, transparent setup)
zkf prove --program ir/program.json --inputs inputs.json \
  --backend halo2 --out proof_halo2.json

# Plonky3 (Goldilocks STARK)
zkf prove --program ir/program.json --inputs inputs.json \
  --backend plonky3 --out proof_plonky3.json
```

---

## Importing from Circom

```bash
# Export R1CS from circom
circom circuit.circom --r1cs --json

# Import into ZKF
zkf import --frontend circom --in ./circuit.r1cs.json \
  --out ir/program.json --field bn254 --ir-family auto
```

---

## Importing from Cairo

```bash
# Compile Sierra from Cairo
scarb build

# Import into ZKF
zkf import --frontend cairo --in ./target/dev/program.sierra.json \
  --out ir/program.json --ir-family auto
```

---

## Cross-Backend Proving

ZKF's canonical program-family flow means you can import once, keep `zir-v1` when needed, and
still prove the lowered program with different backends:

```bash
# Import once
zkf import --frontend noir --in ./acir.json --out ir/program.json --ir-family auto

# Optimize
zkf optimize --program ir/program.json --out ir/optimized.json

# Prove with multiple backends
zkf prove --program ir/optimized.json --inputs inputs.json \
  --backend arkworks-groth16 --out proofs/groth16.json

zkf prove --program ir/optimized.json --inputs inputs.json \
  --backend halo2 --out proofs/halo2.json

zkf prove --program ir/optimized.json --inputs inputs.json \
  --backend plonky3 --out proofs/plonky3.json

# Or use the package workflow for automated multi-backend proving
zkf package prove-all --manifest package.json \
  --backends arkworks-groth16,halo2,plonky3 --parallel
```

---

## Writing Circuits with the DSL

The shipped `zkf-dsl` proc macro compiles Rust functions directly into canonical `zir-v1`.
Backends consume the lowered `ir-v2` form after explicit lowering.

### Basic circuit

```rust
use zkf_dsl::prelude::*;

#[zkf::circuit(field = "bn254")]
fn multiply(
    x: Private<Field>,
    y: Private<Field>,
) -> Public<Field> {
    x * y
}
```

### Range proof

```rust
#[zkf::circuit(field = "bn254")]
fn range_proof(
    value: Private<Field>,
    bits: Public<Field>,
) -> Public<bool> {
    assert_range(value, 32);
    true
}
```

### Using builtins

```rust
#[zkf::circuit(field = "bn254")]
fn verify_membership(
    leaf: Private<Field>,
    path: Private<[Field; 20]>,
    root: Public<Field>,
) -> Public<bool> {
    // Hash the leaf
    let hash = poseidon_hash(leaf);

    // Verify Merkle path
    merkle_verify(hash, path, root);

    true
}
```

### Loops and conditionals

```rust
#[zkf::circuit(field = "bn254")]
fn fibonacci(n: Public<Field>) -> Public<Field> {
    let mut a: Field = 0;
    let mut b: Field = 1;

    for _i in 0..10 {
        let tmp = a + b;
        a = b;
        b = tmp;
    }

    b
}
```

### Available builtins

| Category | Functions |
|----------|-----------|
| Assertions | `assert_range`, `assert_bool`, `assert_eq`, `assert_ne`, `assert_lt` |
| Hashes | `poseidon_hash`, `sha256_hash`, `keccak256_hash`, `blake2s_hash`, `blake3_hash`, `pedersen_hash` |
| Signatures | `ecdsa_verify`, `schnorr_verify` |
| Merkle | `merkle_verify`, `merkle_root` |
| Field ops | `field_inverse`, `field_sqrt`, `field_pow` |
| Non-native | `nonnative_mul`, `nonnative_add` |
| Curves | `secp256k1_mul`, `kzg_verify` |
| Comparison | `comparison_lt`, `comparison_gt` |

---

## Writing Gadgets

Gadgets are reusable constraint patterns published through the registry.

### 1. Create a gadget manifest

```json
{
  "name": "my_hash_gadget",
  "version": "1.0.0",
  "description": "Custom hash function gadget",
  "field": "bn254",
  "inputs": ["preimage"],
  "outputs": ["digest"],
  "constraint_count": 256
}
```

### 2. Publish locally

```bash
zkf registry publish --manifest gadget.json --content gadget_constraints.json
```

### 3. Use in other circuits

```bash
zkf registry add my_hash_gadget
```

---

## GPU Acceleration on Apple Silicon

### 1. Check GPU availability

```bash
zkf metal-doctor
```

### 2. Prove with Metal GPU

```bash
# Build with Metal support
cargo build --release --features metal-gpu

# Prove — Metal auto-selects when beneficial
zkf prove --program ir/program.json --inputs inputs.json \
  --backend arkworks-groth16 --out proof.json --mode metal-first
```

Metal accelerates:
- **MSM** (multi-scalar multiplication) — the bottleneck in Groth16 proving
- **NTT** (number-theoretic transform) — polynomial evaluation

The scheduler automatically routes to GPU vs CPU based on problem size.

---

## Deploying a Solidity Verifier

### 1. Generate the proof

```bash
zkf prove --program ir/program.json --inputs inputs.json \
  --backend arkworks-groth16 --out proof.json
```

### 2. Generate the Solidity contract

```bash
zkf deploy --artifact proof.json --backend arkworks-groth16 \
  --out Verifier.sol --contract-name MyVerifier
```

### 3. Estimate gas

```bash
zkf estimate-gas --backend arkworks-groth16 --artifact proof.json
```

### 4. Deploy

Deploy `Verifier.sol` using your preferred toolchain (Foundry, Hardhat, etc.). The contract exposes a `verify(uint256[] calldata input, Proof calldata proof)` function.

---

## Proof Wrapping (STARK to Groth16)

Convert a STARK proof (large, fast) into a Groth16 proof (small, on-chain verifiable):

```bash
# 1. Prove with Plonky3 (STARK)
zkf prove --program ir/program.json --inputs inputs.json \
  --backend plonky3 --out stark_proof.json --compiled-out stark_compiled.json

# 2. Wrap into Groth16
zkf wrap --proof stark_proof.json --compiled stark_compiled.json \
  --out wrapped_groth16.json

# 3. Verify the wrapped proof
zkf verify --program ir/program.json --artifact wrapped_groth16.json \
  --backend arkworks-groth16
```

---

## IVC Folding with Nova

Incrementally verifiable computation — prove a computation over many steps with constant-size proofs:

```bash
# Prepare step inputs (one per step)
cat > steps.json << 'EOF'
{
  "steps": [
    { "x": "1", "y": "1" },
    { "x": "1", "y": "2" },
    { "x": "2", "y": "3" },
    { "x": "3", "y": "5" },
    { "x": "5", "y": "8" }
  ]
}
EOF

# Run 5-step IVC folding
zkf fold --manifest package.json --inputs steps.json \
  --steps 5 --backend nova
```

---

## Debugging Failing Proofs

### 1. Run the debugger

```bash
zkf debug --program ir/program.json --inputs inputs.json \
  --out debug_report.json --continue-on-failure
```

The debugger reports:
- Which constraints fail and why
- Signal values at each step
- Flow DAG showing dependency chains

### 2. Check constraint satisfaction

```bash
# Generate witness first
zkf witness --program ir/program.json --inputs inputs.json --out witness.json

# Then check which constraints pass/fail in the debug output
```

### 3. Optimize and re-prove

```bash
# Optimize to remove redundant constraints
zkf optimize --program ir/program.json --out ir/optimized.json

# Re-prove with the optimized program
zkf prove --program ir/optimized.json --inputs inputs.json \
  --backend arkworks-groth16 --out proof.json
```
