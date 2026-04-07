#!/bin/sh
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${APP_ROOT}/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
SCHEME="ZirOSWallet"
PROJECT_PATH="${APP_ROOT}/ZirOSWallet.xcodeproj"

case "${CONFIGURATION}" in
  Debug) DERIVED_DATA_DEFAULT="${APP_ROOT}/build" ;;
  *) DERIVED_DATA_DEFAULT="${APP_ROOT}/build-release" ;;
esac

DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${DERIVED_DATA_DEFAULT}}"
CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED:-NO}"
LAUNCH_SMOKE_TEST="${LAUNCH_SMOKE_TEST:-0}"

if [ "${CLEAN:-0}" = "1" ]; then
  rm -rf "${DERIVED_DATA_PATH}"
fi

cd "${REPO_ROOT}"
xcodegen generate --spec "${APP_ROOT}/project.yml"

xcodebuild \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -configuration "${CONFIGURATION}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED}" \
  build

APP_PATH="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/ZirOSWallet.app"
BUNDLED_NODE="${APP_PATH}/Contents/Resources/WalletHelper/NodeRuntime/bin/node"

if [ ! -x "${BUNDLED_NODE}" ]; then
  echo "Missing bundled Node runtime at ${BUNDLED_NODE}" >&2
  exit 1
fi

"${BUNDLED_NODE}" -v >/dev/null
otool -L "${APP_PATH}/Contents/MacOS/ZirOSWallet" | grep -q 'libzkf_ffi' && {
  echo "Unexpected dynamic libzkf_ffi dependency in app binary." >&2
  exit 1
}

if [ "${LAUNCH_SMOKE_TEST}" = "1" ]; then
  LOG_PATH="${DERIVED_DATA_PATH}/zirOSWallet-launch.log"
  rm -f "${LOG_PATH}"
  "${APP_PATH}/Contents/MacOS/ZirOSWallet" >"${LOG_PATH}" 2>&1 &
  APP_PID=$!
  sleep 5
  if ! ps -p "${APP_PID}" >/dev/null 2>&1; then
    echo "Launch smoke test failed; app exited early." >&2
    sed -n '1,120p' "${LOG_PATH}" >&2
    exit 1
  fi
  kill "${APP_PID}" >/dev/null 2>&1 || true
  wait "${APP_PID}" >/dev/null 2>&1 || true
fi

echo "Built app: ${APP_PATH}"
