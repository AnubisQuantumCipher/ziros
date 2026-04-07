#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h:h}

mkdir -p "${HOME}/.zkf/cache/agent" "${HOME}/Library/Logs/ZirOSAgent"
export CARGO_TARGET_DIR="${repo_root}/target-public"
cd "${repo_root}"

exec cargo run -p zkf-agent --bin ziros-agentd
