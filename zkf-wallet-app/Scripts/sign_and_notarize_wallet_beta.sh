#!/bin/sh
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${APP_ROOT}/build-release}"
APP_PATH="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/ZirOSWallet.app"
EXTENSION_PATH="${APP_PATH}/Contents/PlugIns/ZirOSWalletExtension.appex"
APP_ENTITLEMENTS="${APP_ROOT}/Sources/App/ZirOSWallet.entitlements"
EXTENSION_ENTITLEMENTS="${APP_ROOT}/Sources/Extension/ZirOSWalletExtension.entitlements"
IDENTITY="${DEVELOPER_ID_APPLICATION:?Set DEVELOPER_ID_APPLICATION to your Developer ID Application identity.}"
APPLE_ID="${APPLE_ID:?Set APPLE_ID for notarization.}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:?Set APPLE_TEAM_ID for notarization.}"
APPLE_APP_PASSWORD="${APPLE_APP_PASSWORD:?Set APPLE_APP_PASSWORD for notarization.}"
VERSION="${VERSION:-0.1.0-beta}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${APP_ROOT}/artifacts/${CONFIGURATION}}"
ZIP_PATH="${ARTIFACT_ROOT}/ZirOSWallet-${VERSION}-arm64-signed.zip"

if [ ! -d "${APP_PATH}" ]; then
  echo "Expected release app bundle at ${APP_PATH}" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_ROOT}"

sign_nested_code() {
  find "${APP_PATH}/Contents/Resources/WalletHelper/NodeRuntime" \
    \( -path "*/bin/*" -o -name "*.dylib" -o -name "*.so" \) \
    -type f \
    -print0 | while IFS= read -r -d '' executable; do
      codesign --force --sign "${IDENTITY}" --timestamp --options runtime "${executable}"
    done
}

sign_nested_code

codesign \
  --force \
  --sign "${IDENTITY}" \
  --timestamp \
  --options runtime \
  --entitlements "${EXTENSION_ENTITLEMENTS}" \
  "${EXTENSION_PATH}"

codesign \
  --force \
  --sign "${IDENTITY}" \
  --timestamp \
  --options runtime \
  --entitlements "${APP_ENTITLEMENTS}" \
  "${APP_PATH}"

codesign --verify --deep --strict --verbose=2 "${APP_PATH}"

ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"

xcrun notarytool submit \
  "${ZIP_PATH}" \
  --apple-id "${APPLE_ID}" \
  --team-id "${APPLE_TEAM_ID}" \
  --password "${APPLE_APP_PASSWORD}" \
  --wait

xcrun stapler staple "${APP_PATH}"

echo "Signed and notarized app: ${APP_PATH}"
echo "Signed artifact: ${ZIP_PATH}"
