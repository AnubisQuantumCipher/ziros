#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
alias_root="${TMPDIR:-/tmp}/zkf-zk-dev"
ln -sfn "$repo_root" "$alias_root"

tool_bin="$alias_root/.zkf-tools/fstar/bin"
workspace_dir="$alias_root/zkf-core/proofs/fstar"

if [ ! -x "$tool_bin/fstar.exe" ] || [ ! -x "$tool_bin/z3-4.8.5" ] || [ ! -x "$tool_bin/z3-4.13.3" ]; then
  "$alias_root/scripts/bootstrap_fstar_toolchain.sh" >/dev/null
fi

export PATH="$tool_bin:$PATH"
export ZKF_FSTAR_REPO_ROOT="$alias_root"

"$alias_root/scripts/run_hax_core_fstar_extract.sh"

(
  cd "$workspace_dir"
  make clean
  OTHERFLAGS="--lax" make
  make clean
  make
)
