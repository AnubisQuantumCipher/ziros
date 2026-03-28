#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <label> <proof-file-relative-to-repo-root>" >&2
  exit 1
fi

label="$1"
proof_file_rel="$2"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

env_file="$alias_root/.zkf-tools/verus/verus.env"
proof_file="$alias_root/$proof_file_rel"

log() {
  printf '[verus-%s] %s\n' "$label" "$*" >&2
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

log "Verifying $proof_file_rel"
verus "$proof_file" --crate-type lib
