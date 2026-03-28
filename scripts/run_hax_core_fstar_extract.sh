#!/usr/bin/env bash
set -euo pipefail

repo_root="${ZKF_FSTAR_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)}"
exec "$repo_root/scripts/run_hax_crate_fstar_extract.sh" \
  "$repo_root/zkf-core/proofs/fstar/HAX_PIN.toml"
