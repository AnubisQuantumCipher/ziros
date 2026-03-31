#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <label> <proof-file>" >&2
  exit 2
fi

label="$1"
proof_path="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

log() {
  printf '[verus:%s] %s\n' "$label" "$*" >&2
}

proof_file="$alias_root/$proof_path"
if [[ ! -f "$proof_file" ]]; then
  echo "missing Verus proof file at $proof_file" >&2
  exit 1
fi

env_file="$alias_root/.zkf-tools/verus/verus.env"
if [[ -f "$env_file" ]]; then
  # shellcheck disable=SC1090
  source "$env_file"
fi

verus_bin=""
if [[ -n "${VERUS_HOME:-}" && -x "${VERUS_HOME}/verus" ]]; then
  verus_bin="${VERUS_HOME}/verus"
elif [[ -x "$alias_root/.zkf-tools/verus/install/verus" ]]; then
  verus_bin="$alias_root/.zkf-tools/verus/install/verus"
elif command -v verus >/dev/null 2>&1; then
  verus_bin="$(command -v verus)"
else
  echo "missing Verus binary; expected .zkf-tools/verus/install/verus or \`verus\` on PATH" >&2
  exit 1
fi

log "Verifying $proof_path"
"$verus_bin" "$proof_file" --crate-type lib
