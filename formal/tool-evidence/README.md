# Formal Tool Evidence

This directory records optional, non-counted formal-tool evidence that supports
the release-grade ledger without inflating it.

`thrust/` is intentionally outside the counted theorem ledger in this checkout.
Thrust runs may catch safe-Rust functional regressions and infer useful
invariants, but they do not become `mechanized_local` rows unless the audit
policy is changed explicitly.
