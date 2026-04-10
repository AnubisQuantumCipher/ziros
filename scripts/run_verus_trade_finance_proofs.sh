#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
exec "$repo_root/scripts/run_verus_workspace.sh" \
  trade-finance \
  zkf-lib/proofs/verus/trade_finance_verus.rs \
  "$@"
