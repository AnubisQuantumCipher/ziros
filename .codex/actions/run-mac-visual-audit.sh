#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ROOT="${REPO_ROOT}/zkf-wallet-app"
DERIVED_DATA="${APP_ROOT}/build-codex-visual-audit"

AUDIT_STATE="${AUDIT_STATE:-unlocked}"
AUDIT_SECTION="${AUDIT_SECTION:-overview}"
AUDIT_TRANSACT_MODE="${AUDIT_TRANSACT_MODE:-send}"
AUDIT_APPROVAL="${AUDIT_APPROVAL:-}"

xcodegen generate --spec "${APP_ROOT}/project.yml"
xcodebuild \
  -project "${APP_ROOT}/ZirOSWallet.xcodeproj" \
  -scheme ZirOSWallet \
  -configuration Debug \
  -derivedDataPath "${DERIVED_DATA}" \
  build

DERIVED_APP_BINARY="${DERIVED_DATA}/Build/Products/Debug/ZirOSWallet.app/Contents/MacOS/ZirOSWallet"
SYMROOT_APP_BINARY="${HOME}/Library/Developer/Xcode/ZirOSWalletmacOS/Debug/ZirOSWallet.app/Contents/MacOS/ZirOSWallet"

APP_BINARY="${DERIVED_APP_BINARY}"
if [[ ! -x "${APP_BINARY}" && -x "${SYMROOT_APP_BINARY}" ]]; then
  APP_BINARY="${SYMROOT_APP_BINARY}"
fi

if [[ ! -x "${APP_BINARY}" ]]; then
  echo "Unable to find built ZirOSWallet binary." >&2
  echo "Checked: ${DERIVED_APP_BINARY}" >&2
  echo "Checked: ${SYMROOT_APP_BINARY}" >&2
  exit 1
fi

LOG_PATH="/tmp/ziros-wallet-visual-audit.log"
: > "${LOG_PATH}"

ARGS=(
  "-wallet-visual-audit"
  "-wallet-audit-state" "${AUDIT_STATE}"
  "-wallet-audit-section" "${AUDIT_SECTION}"
  "-wallet-audit-transact-mode" "${AUDIT_TRANSACT_MODE}"
)

if [[ -n "${AUDIT_APPROVAL}" ]]; then
  ARGS+=("-wallet-audit-approval" "${AUDIT_APPROVAL}")
fi

"${APP_BINARY}" "${ARGS[@]}" >"${LOG_PATH}" 2>&1 &
echo "Launched visual audit app with args: ${ARGS[*]}"
