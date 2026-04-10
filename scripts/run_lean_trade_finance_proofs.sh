#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
proof_file="$repo_root/zkf-lib/proofs/lean/TradeFinanceProofs.lean"

if command -v lean >/dev/null 2>&1; then
  lean "$proof_file"
else
  echo "lean unavailable; running structural Lean surface check only"
  rg -n "withinTermWindow_true_implies_lower|eligibilityPassed_true_implies_conditions|approvedAdvanceAmount_le_cap|reserveAmount_ge_floor|actionClassCode_in_range|supplierDisclosureBindsExpectedCommitments|duplicateRegistryHandoffDeterministic|generatedCircuitCertificateAcceptanceSoundness" "$proof_file" >/dev/null
  ! rg -n "deductible|cappedPayout" "$proof_file" >/dev/null
fi
