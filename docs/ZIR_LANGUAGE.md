# Zir Language

Zir is the native ZirOS source language for proof programs. It is a DSL over the shipped ZIR v1 and IR v2 program families, not a claim that arbitrary general-purpose programs are automatically formally verified.

## Tiers

Tier 1 is the total circuit subset:

- bounded source programs
- explicit public/private signals
- arithmetic expressions
- `range`, `boolean`, `nonzero`, `leq`, `geq`, and equality constraints
- explicit `expose`
- no recursion, host effects, unbounded loops, or unknown calls

Tier 2 is the explicit advanced ZIR subset:

- lookup tables
- blackbox constraints
- memory regions
- custom gates
- copy and permutation constraints
- metadata-only recursive aggregation markers remain metadata-only

Tier 2 constructs preserve ZIR v1 semantics and fail closed when a caller forces an unsupported IR v2 or backend path.

## CLI

```bash
ziros lang check program.zir --json
ziros lang inspect program.zir --json
ziros lang lower program.zir --to zir-v1 --out build/program.zir.json --json
ziros lang lower program.zir --to ir-v2 --out build/program.ir.json --json
ziros lang package program.zir --out build/package --to zir-v1 --json
ziros lang obligations program.zir --json
ziros lang fmt program.zir --check
ziros lang lsp serve
```

Packages include source provenance, source digest, check report, proof obligations, and the lowered program artifact.

## Example

```zir
circuit private_trade_finance_settlement(field: bn254, tier: 1) {
  private invoice_amount: u64<32>;
  private settlement_amount: u64<32>;
  private fee_amount: u64<16>;
  public net_amount: field;

  net_amount = settlement_amount - fee_amount;
  constrain settlement_amount == invoice_amount;
  constrain leq(fee_amount, settlement_amount, 32);
  expose net_amount;
}
```

The shipped example lives at `zkf-examples/zir/private_trade_finance_settlement.zir`.
