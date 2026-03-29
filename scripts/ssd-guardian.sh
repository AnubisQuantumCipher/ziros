#!/usr/bin/env bash
set -euo pipefail

CLI="${ZKF_CLI_PATH:-${HOME}/.local/bin/zkf-cli}"

if [[ ! -x "${CLI}" ]]; then
  echo "missing zkf-cli binary: ${CLI}" >&2
  exit 1
fi

"${CLI}" storage evict
