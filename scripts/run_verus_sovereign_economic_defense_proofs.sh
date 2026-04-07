#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
exec "$repo_root/scripts/run_verus_workspace.sh" \
  sovereign-economic-defense \
  zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs \
  "$@"
