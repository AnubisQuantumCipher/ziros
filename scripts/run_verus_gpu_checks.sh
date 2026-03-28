#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
env_file="$repo_root/.zkf-tools/verus/verus.env"
proof_root="$repo_root/zkf-metal/proofs/verus"

if [[ ! -f "$env_file" ]]; then
  "$repo_root/scripts/bootstrap_verus_toolchain.sh" >/dev/null
fi

# shellcheck disable=SC1090
source "$env_file"

cd "$proof_root"
"$ZKF_VERUS_BIN" --crate-type=lib LaunchContracts.rs
"$ZKF_VERUS_BIN" --crate-type=lib HashLaunch.rs
"$ZKF_VERUS_BIN" --crate-type=lib Poseidon2Launch.rs
"$ZKF_VERUS_BIN" --crate-type=lib NttLaunch.rs
"$ZKF_VERUS_BIN" --crate-type=lib MsmLaunch.rs
