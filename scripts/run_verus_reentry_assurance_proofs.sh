#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
exec "$repo_root/scripts/run_verus_workspace.sh" \
  reentry-assurance \
  zkf-runtime/proofs/verus/reentry_assurance_verus.rs \
  "$@"
