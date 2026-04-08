#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
proof_file="$repo_root/zkf-lib/proofs/rocq/TradeFinanceProofs.v"

if command -v coqc >/dev/null 2>&1; then
  coqc "$proof_file"
else
  echo "coqc unavailable; running structural Rocq surface check only"
  rg -n "Theorem|Qed\\." "$proof_file" >/dev/null
fi
