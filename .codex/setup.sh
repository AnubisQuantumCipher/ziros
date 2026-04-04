#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v cargo >/dev/null
command -v npm >/dev/null
command -v xcodegen >/dev/null
command -v xcodebuild >/dev/null

test -f "${REPO_ROOT}/AGENTS.md"
test -f "${REPO_ROOT}/zkf-wallet-app/project.yml"
test -f "${REPO_ROOT}/zkf-wallet-app/ZirOSWallet.xcodeproj/project.pbxproj"
test -f "${REPO_ROOT}/zkf-wallet-app/Scripts/build_wallet_beta.sh"
test -f "${REPO_ROOT}/zkf-wallet-app/Scripts/serve_dapp_harness.sh"

echo "Codex wallet environment ready."
