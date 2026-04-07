#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="${REPO_ROOT}/zkf-wallet-app"
APP_PROCESS_PATH="${HOME}/Library/Developer/Xcode/ZirOSWalletmacOS/Debug/ZirOSWallet.app/Contents/MacOS/ZirOSWallet"

pkill -f "${APP_PROCESS_PATH}" >/dev/null 2>&1 || true

xcodegen generate --spec "${APP_ROOT}/project.yml"
xcodebuild \
  -project "${APP_ROOT}/ZirOSWallet.xcodeproj" \
  -scheme ZirOSWallet \
  -configuration Debug \
  build
