#!/bin/sh
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${APP_ROOT}/artifacts/${CONFIGURATION}}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${APP_ROOT}/build-release}"

if [ "${CONFIGURATION}" = "Debug" ]; then
  DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${APP_ROOT}/build}"
fi

APP_PATH="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/ZirOSWallet.app"
VERSION="${VERSION:-0.1.0-beta}"
ZIP_PATH="${ARTIFACT_ROOT}/ZirOSWallet-${VERSION}-arm64.zip"
DMG_PATH="${ARTIFACT_ROOT}/ZirOSWallet-${VERSION}-arm64.dmg"

mkdir -p "${ARTIFACT_ROOT}"

if [ ! -d "${APP_PATH}" ]; then
  echo "Expected app bundle at ${APP_PATH}" >&2
  exit 1
fi

TMP_ROOT="${ARTIFACT_ROOT}/staging"
rm -rf "${TMP_ROOT}"
mkdir -p "${TMP_ROOT}"
cp -R "${APP_PATH}" "${TMP_ROOT}/ZirOSWallet.app"

(
  cd "${TMP_ROOT}"
  ditto -c -k --keepParent "ZirOSWallet.app" "${ZIP_PATH}"
)

if [ "${CREATE_DMG:-0}" = "1" ]; then
  rm -f "${DMG_PATH}"
  hdiutil create \
    -volname "ZirOS Wallet" \
    -srcfolder "${TMP_ROOT}/ZirOSWallet.app" \
    -ov \
    -format UDZO \
    "${DMG_PATH}"
  echo "Created DMG: ${DMG_PATH}"
fi

echo "Created ZIP: ${ZIP_PATH}"
