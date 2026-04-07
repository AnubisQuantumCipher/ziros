#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
open "${REPO_ROOT}/zkf-wallet-app/ZirOSWallet.xcodeproj"
