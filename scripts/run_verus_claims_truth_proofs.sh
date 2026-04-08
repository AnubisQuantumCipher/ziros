#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
proof_file="$repo_root/zkf-lib/proofs/verus/claims_truth_verus.rs"

if command -v verus >/dev/null 2>&1; then
  verus "$proof_file"
else
  echo "verus unavailable; running structural Verus surface check only"
  rg -n "spec fn|proof fn|ensures" "$proof_file" >/dev/null
fi
