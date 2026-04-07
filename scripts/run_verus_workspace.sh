#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <label> <proof-file> [verus-args...]" >&2
  exit 1
fi

label="$1"
proof_file="$2"
shift 2

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

env_file="$alias_root/.zkf-tools/verus/verus.env"
if [[ ! -x "$alias_root/.zkf-tools/verus/install/verus" ]]; then
  "$alias_root/scripts/bootstrap_verus_toolchain.sh" >/dev/null
fi

if [[ ! -f "$env_file" ]]; then
  echo "missing Verus environment file at $env_file" >&2
  exit 1
fi

if [[ "$proof_file" = /* ]]; then
  proof_path="$proof_file"
else
  proof_path="$alias_root/$proof_file"
fi

if [[ ! -f "$proof_path" ]]; then
  echo "missing Verus proof file at $proof_path" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$env_file"

printf '[verus:%s] %s\n' "$label" "$proof_path" >&2
verus "$proof_path" --crate-type lib "$@"
