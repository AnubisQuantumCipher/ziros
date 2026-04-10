# ZirFlow

ZirFlow is the bounded workflow surface for native Zir programs. It produces deterministic proof plans for agent-operated CLI runs.

```zirflow
workflow trade_finance_settlement {
  source "./private_trade_finance_settlement.zir" as settlement;
  check settlement tier tier1;
  lower settlement to zir-v1 out "./build/private_trade_finance_settlement.zir.json";
  package settlement out "./build/private_trade_finance_settlement.package";
  prove settlement backend "nova" inputs "./private_trade_finance_settlement.inputs.valid.json" out "./build/private_trade_finance_settlement.proof.json";
  verify settlement backend "nova" artifact "./build/private_trade_finance_settlement.proof.json";
}
```

Commands:

```bash
ziros lang flow check workflow.zirflow --json
ziros lang flow plan workflow.zirflow --out plan.json --json
ziros lang flow run workflow.zirflow --approve --json
```

`flow run` requires `--approve` for write, package, prove, or verify steps. ZirFlow has no arbitrary shell execution; all source, output, proof, and artifact paths are visible in the plan.

`allow_dev_deterministic_groth16` is an explicit development-only workflow flag for local Groth16 smoke tests without an external setup blob; the shipped example uses the native `nova` backend so the strict backend-readiness audit can pass.
