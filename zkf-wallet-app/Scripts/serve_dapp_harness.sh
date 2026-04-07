#!/bin/sh
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/../Testing/DAppHarness" && pwd)"
PORT="${PORT:-8787}"

cd "${HARNESS_ROOT}"
python3 -m http.server "${PORT}"
