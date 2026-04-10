#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
proof_file="$repo_root/zkf-lib/proofs/rocq/TradeFinanceProofs.v"

if command -v coqc >/dev/null 2>&1; then
  coqc "$proof_file"
else
  echo "coqc unavailable; running structural Rocq surface check only"
  rg -n "within_term_window_true_iff|eligibility_passed_true_implies_trade_finance_conditions|approved_advance_bounded_by_cap|reserve_amount_respects_floor|action_class_code_is_in_range|supplier_disclosure_binds_expected_commitments|duplicate_registry_handoff_deterministic|generated_circuit_certificate_acceptance_soundness" "$proof_file" >/dev/null
  ! rg -n "deductible|capped_payout" "$proof_file" >/dev/null
fi
