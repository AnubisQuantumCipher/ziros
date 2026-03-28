#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$repo_root/scripts/run_hax_crate_rocq_extract.sh" \
  "$repo_root/zkf-lib/proofs/rocq/HAX_PIN.toml"
