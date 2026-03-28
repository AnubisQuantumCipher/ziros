# Private Budget Approval

This is a standalone ZirOS builder-spec app under `/Users/sicarii/Projects/ZK DEV/private_budget_approval`.

The app keeps these witness values private:

- `balance_cents`
- `purchase_cents`
- `fee_cents`

It reveals these public outputs in this exact order:

- `approved`
- `total_cents`
- `balance_commitment`

Semantics:

- `total_cents = purchase_cents + fee_cents`
- `approved = 1` iff `balance_cents >= total_cents`
- `approved = 0` iff `balance_cents < total_cents`
- `approved` is constrained boolean
- `balance_commitment` is a deterministic Poseidon commitment of `balance_cents`

Important builder-surface note:

The shipped BN254 Poseidon app surface in this checkout supports the normal `4 -> 4` permutation lane. This app keeps the implementation builder-only and defines:

- `balance_commitment = Poseidon([balance_cents, 0, 0, 0])[0]`

That stays entirely on the exposed app spec / ProgramBuilder surface and avoids framework changes.

## Files

- [`zirapp.json`](/Users/sicarii/Projects/ZK DEV/private_budget_approval/zirapp.json): canonical `AppSpecV1`
- [`src/spec.rs`](/Users/sicarii/Projects/ZK DEV/private_budget_approval/src/spec.rs): generic app-spec loader
- [`src/main.rs`](/Users/sicarii/Projects/ZK DEV/private_budget_approval/src/main.rs): demo / prove / verify / export entrypoint
- [`tests/smoke.rs`](/Users/sicarii/Projects/ZK DEV/private_budget_approval/tests/smoke.rs): prove/verify/export coverage

## Input Format

Use decimal strings in JSON because the normal embedded loader deserializes field elements directly:

```json
{
  "balance_cents": "10000",
  "purchase_cents": "7500",
  "fee_cents": "200"
}
```

## Commands

Demo flow:

```bash
cargo run --manifest-path '/Users/sicarii/Projects/ZK DEV/private_budget_approval/Cargo.toml'
```

Generate proof artifacts:

```bash
cargo run --manifest-path '/Users/sicarii/Projects/ZK DEV/private_budget_approval/Cargo.toml' -- \
  prove '/Users/sicarii/Projects/ZK DEV/private_budget_approval/inputs.example.json' \
  '/tmp/private-budget-proof'
```

Verify saved artifacts:

```bash
cargo run --manifest-path '/Users/sicarii/Projects/ZK DEV/private_budget_approval/Cargo.toml' -- \
  verify '/tmp/private-budget-proof/compiled.json' '/tmp/private-budget-proof/proof.json'
```

Export Solidity verifier, calldata, and Foundry assets:

```bash
cargo run --manifest-path '/Users/sicarii/Projects/ZK DEV/private_budget_approval/Cargo.toml' -- \
  export '/tmp/private-budget-proof/proof.json' '/tmp/private-budget-export'
```

## Tests

Run the app tests with:

```bash
cargo test --manifest-path '/Users/sicarii/Projects/ZK DEV/private_budget_approval/Cargo.toml'
```
