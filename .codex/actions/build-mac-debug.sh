#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="${REPO_ROOT}/zkf-wallet-app"

xcodegen generate --spec "${APP_ROOT}/project.yml"
xcodebuild \
  -project "${APP_ROOT}/ZirOSWallet.xcodeproj" \
  -scheme ZirOSWallet \
  -configuration Debug \
  build
