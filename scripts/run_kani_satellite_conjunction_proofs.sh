#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
cd "$repo_root"

export ZKF_KANI_MODE="satellite"
bash ./scripts/run_kani_suite.sh
