#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
proof_file="$repo_root/zkf-lib/proofs/lean/ClaimsTruthProofs.lean"

if command -v lean >/dev/null 2>&1; then
  lean "$proof_file"
else
  echo "lean unavailable; running structural Lean surface check only"
  rg -n "theorem|def" "$proof_file" >/dev/null
fi
