#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$ROOT_DIR/scripts/build_npm_agent_package.py"
python3 "$ROOT_DIR/scripts/generate_npm_installer_manifest.py" "$@"

cd "$ROOT_DIR/packaging/npm/agent"
npm publish --access public --provenance
