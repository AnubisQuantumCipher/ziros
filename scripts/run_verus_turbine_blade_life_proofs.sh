#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
if [[ ! -x "$repo_root/.zkf-tools/verus/install/verus" ]] && ! command -v verus >/dev/null 2>&1; then
  echo "[verus:turbine-blade-life] unavailable: Verus toolchain is not installed on this host" >&2
  exit 1
fi
exec "$repo_root/scripts/run_verus_workspace.sh" \
  turbine-blade-life \
  zkf-lib/proofs/verus/turbine_blade_life_verus.rs \
  "$@"
