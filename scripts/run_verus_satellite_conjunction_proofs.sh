#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

env_file="$alias_root/.zkf-tools/verus/verus.env"
proof_file="$alias_root/zkf-runtime/proofs/verus/satellite_conjunction_verus.rs"

log() {
  printf '[verus-satellite] %s\n' "$*" >&2
}

if [[ ! -x "$alias_root/.zkf-tools/verus/bin/verus" ]]; then
  "$alias_root/scripts/bootstrap_verus_toolchain.sh" >/dev/null
fi

if [[ ! -f "$env_file" ]]; then
  echo "missing Verus environment file at $env_file" >&2
  exit 1
fi

if [[ ! -f "$proof_file" ]]; then
  echo "missing Verus proof file at $proof_file" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$env_file"

log "Verifying satellite conjunction surface invariants"
verus "$proof_file" --crate-type lib
