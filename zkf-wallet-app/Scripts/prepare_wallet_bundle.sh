#!/bin/sh
set -euo pipefail

export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"

REPO_ROOT="$(cd "${SRCROOT}/.." && pwd)"
HELPER_ROOT="${REPO_ROOT}/zkf-wallet-helper"
MAILBOX_ROOT="${REPO_ROOT}/zkf-wallet-mailbox"
export MACOSX_DEPLOYMENT_TARGET="15.0"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
is_debug_build=0
if [ "${CONFIGURATION:-Debug}" = "Debug" ]; then
  is_debug_build=1
fi
NODE_VERSION="22.22.2"
NODE_DIST="node-v${NODE_VERSION}-darwin-arm64"
NODE_ARCHIVE="${NODE_DIST}.tar.gz"
NODE_BASE_URL="https://nodejs.org/dist/v${NODE_VERSION}"
CACHE_ROOT="${REPO_ROOT}/.cache/wallet-runtime"
NODE_CACHE_DIR="${CACHE_ROOT}/${NODE_DIST}"
NODE_ARCHIVE_PATH="${CACHE_ROOT}/${NODE_ARCHIVE}"
NODE_SHASUMS_PATH="${CACHE_ROOT}/SHASUMS256-v${NODE_VERSION}.txt"

if ! command -v cargo >/dev/null 2>&1; then
  echo "prepare_wallet_bundle.sh: cargo not found. Expected at ~/.cargo/bin/cargo or in PATH." >&2
  exit 127
fi

platform_name="${PLATFORM_NAME:-macosx}"
include_node_runtime=0
build_mode=""
if [ "${CONFIGURATION:-Debug}" = "Release" ]; then
  build_mode="--release"
fi
profile_dir="debug"
if [ -n "${build_mode}" ]; then
  profile_dir="release"
fi

path_is_newer_than() {
  candidate="$1"
  marker="$2"
  if [ -d "${candidate}" ]; then
    if find "${candidate}" -type f -newer "${marker}" -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
    return 1
  fi
  if [ -e "${candidate}" ] && [ "${candidate}" -nt "${marker}" ]; then
    return 0
  fi
  return 1
}

needs_rebuild() {
  marker="$1"
  shift
  if [ ! -e "${marker}" ]; then
    return 0
  fi
  for candidate in "$@"; do
    if path_is_newer_than "${candidate}" "${marker}"; then
      return 0
    fi
  done
  return 1
}

ensure_rust_target() {
  rust_target="$1"
  if ! rustup target list --installed | grep -qx "${rust_target}"; then
    rustup target add "${rust_target}"
  fi
}

clear_stale_ios_product() {
  if [ -z "${TARGET_BUILD_DIR:-}" ] || [ -z "${FULL_PRODUCT_NAME:-}" ]; then
    return 0
  fi
  stale_product="${TARGET_BUILD_DIR}/${FULL_PRODUCT_NAME}"
  if [ -e "${stale_product}" ]; then
    chmod -R u+w "${stale_product}" 2>/dev/null || true
    xattr -cr "${stale_product}" 2>/dev/null || true
  fi
}

case "${platform_name}" in
  macosx)
    include_node_runtime=1
    if ! command -v npm >/dev/null 2>&1; then
      echo "prepare_wallet_bundle.sh: npm not found. Expected at /opt/homebrew/bin/npm, /usr/local/bin/npm, or in PATH." >&2
      exit 127
    fi
    RUST_MARKER="${REPO_ROOT}/target-public/${profile_dir}/libzkf_ffi.a"
    HELPER_MARKER="${HELPER_ROOT}/dist/src/main.js"
    MAILBOX_MARKER="${MAILBOX_ROOT}/contracts/compiled/ziros_wallet_mailbox/contract/index.js"
    if [ "${is_debug_build}" = "1" ]; then
      [ -f "${RUST_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${RUST_MARKER}. Build zkf-ffi in the terminal before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${HELPER_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${HELPER_MARKER}. Run 'npm --prefix \"${HELPER_ROOT}\" run build' before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${MAILBOX_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${MAILBOX_MARKER}. Run 'npm --prefix \"${MAILBOX_ROOT}\" run compile-contracts' before launching Xcode Debug." >&2
        exit 1
      }
      exit 0
    fi
    if needs_rebuild "${RUST_MARKER}" \
      "${REPO_ROOT}/Cargo.lock" \
      "${REPO_ROOT}/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/Cargo.toml" \
      "${REPO_ROOT}/zkf-wallet/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/src" \
      "${REPO_ROOT}/zkf-wallet/src"; then
      cargo build -p zkf-ffi ${build_mode} --manifest-path "${REPO_ROOT}/Cargo.toml" --target-dir "${REPO_ROOT}/target-public"
    fi
    if needs_rebuild "${HELPER_MARKER}" \
      "${HELPER_ROOT}/package.json" \
      "${HELPER_ROOT}/tsconfig.json" \
      "${HELPER_ROOT}/src" \
      "${HELPER_ROOT}/test"; then
      npm --prefix "${HELPER_ROOT}" run build
    fi
    if needs_rebuild "${MAILBOX_MARKER}" \
      "${MAILBOX_ROOT}/package.json" \
      "${MAILBOX_ROOT}/tsconfig.json" \
      "${MAILBOX_ROOT}/contracts/compact" \
      "${MAILBOX_ROOT}/scripts/compile-contracts.sh"; then
      npm --prefix "${MAILBOX_ROOT}" run compile-contracts
    fi
    ;;
  iphonesimulator)
    RUST_MARKER="${REPO_ROOT}/target-ios-sim/aarch64-apple-ios-sim/${profile_dir}/libzkf_ffi.a"
    HELPER_MARKER="${HELPER_ROOT}/dist/src/main.js"
    WEBKIT_MARKER="${HELPER_ROOT}/dist/src/main_webkit.js"
    MAILBOX_MARKER="${MAILBOX_ROOT}/contracts/compiled/ziros_wallet_mailbox/contract/index.js"
    if [ "${is_debug_build}" = "1" ]; then
      [ -f "${RUST_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${RUST_MARKER}. Build zkf-ffi for aarch64-apple-ios-sim in the terminal before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${HELPER_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${HELPER_MARKER}. Run 'npm --prefix \"${HELPER_ROOT}\" run build' before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${WEBKIT_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${WEBKIT_MARKER}. Run 'npm --prefix \"${HELPER_ROOT}\" run build' before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${MAILBOX_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${MAILBOX_MARKER}. Run 'npm --prefix \"${MAILBOX_ROOT}\" run compile-contracts' before launching Xcode Debug." >&2
        exit 1
      }
    fi
    ensure_rust_target "aarch64-apple-ios-sim"
    clear_stale_ios_product
    if needs_rebuild "${RUST_MARKER}" \
      "${REPO_ROOT}/Cargo.lock" \
      "${REPO_ROOT}/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/Cargo.toml" \
      "${REPO_ROOT}/zkf-wallet/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/src" \
      "${REPO_ROOT}/zkf-wallet/src"; then
      cargo build -p zkf-ffi ${build_mode} --manifest-path "${REPO_ROOT}/Cargo.toml" --target aarch64-apple-ios-sim --target-dir "${REPO_ROOT}/target-ios-sim"
    fi
    if [ "${is_debug_build}" != "1" ]; then
      if ! command -v npm >/dev/null 2>&1; then
        echo "prepare_wallet_bundle.sh: npm not found. Expected at /opt/homebrew/bin/npm, /usr/local/bin/npm, or in PATH." >&2
        exit 127
      fi
      if needs_rebuild "${HELPER_MARKER}" \
        "${HELPER_ROOT}/package.json" \
        "${HELPER_ROOT}/tsconfig.json" \
        "${HELPER_ROOT}/src" \
        "${HELPER_ROOT}/test"; then
        npm --prefix "${HELPER_ROOT}" run build
      fi
      if needs_rebuild "${MAILBOX_MARKER}" \
        "${MAILBOX_ROOT}/package.json" \
        "${MAILBOX_ROOT}/tsconfig.json" \
        "${MAILBOX_ROOT}/contracts/compact" \
        "${MAILBOX_ROOT}/scripts/compile-contracts.sh"; then
        npm --prefix "${MAILBOX_ROOT}" run compile-contracts
      fi
    fi
    ;;
  iphoneos)
    RUST_MARKER="${REPO_ROOT}/target-ios-device/aarch64-apple-ios/${profile_dir}/libzkf_ffi.a"
    HELPER_MARKER="${HELPER_ROOT}/dist/src/main.js"
    WEBKIT_MARKER="${HELPER_ROOT}/dist/src/main_webkit.js"
    MAILBOX_MARKER="${MAILBOX_ROOT}/contracts/compiled/ziros_wallet_mailbox/contract/index.js"
    if [ "${is_debug_build}" = "1" ]; then
      [ -f "${RUST_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${RUST_MARKER}. Build zkf-ffi for aarch64-apple-ios in the terminal before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${HELPER_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${HELPER_MARKER}. Run 'npm --prefix \"${HELPER_ROOT}\" run build' before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${WEBKIT_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${WEBKIT_MARKER}. Run 'npm --prefix \"${HELPER_ROOT}\" run build' before launching Xcode Debug." >&2
        exit 1
      }
      [ -f "${MAILBOX_MARKER}" ] || {
        echo "prepare_wallet_bundle.sh: missing ${MAILBOX_MARKER}. Run 'npm --prefix \"${MAILBOX_ROOT}\" run compile-contracts' before launching Xcode Debug." >&2
        exit 1
      }
    fi
    ensure_rust_target "aarch64-apple-ios"
    clear_stale_ios_product
    if needs_rebuild "${RUST_MARKER}" \
      "${REPO_ROOT}/Cargo.lock" \
      "${REPO_ROOT}/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/Cargo.toml" \
      "${REPO_ROOT}/zkf-wallet/Cargo.toml" \
      "${REPO_ROOT}/zkf-ffi/src" \
      "${REPO_ROOT}/zkf-wallet/src"; then
      cargo build -p zkf-ffi ${build_mode} --manifest-path "${REPO_ROOT}/Cargo.toml" --target aarch64-apple-ios --target-dir "${REPO_ROOT}/target-ios-device"
    fi
    if [ "${is_debug_build}" != "1" ]; then
      if ! command -v npm >/dev/null 2>&1; then
        echo "prepare_wallet_bundle.sh: npm not found. Expected at /opt/homebrew/bin/npm, /usr/local/bin/npm, or in PATH." >&2
        exit 127
      fi
      if needs_rebuild "${HELPER_MARKER}" \
        "${HELPER_ROOT}/package.json" \
        "${HELPER_ROOT}/tsconfig.json" \
        "${HELPER_ROOT}/src" \
        "${HELPER_ROOT}/test"; then
        npm --prefix "${HELPER_ROOT}" run build
      fi
      if needs_rebuild "${MAILBOX_MARKER}" \
        "${MAILBOX_ROOT}/package.json" \
        "${MAILBOX_ROOT}/tsconfig.json" \
        "${MAILBOX_ROOT}/contracts/compact" \
        "${MAILBOX_ROOT}/scripts/compile-contracts.sh"; then
        npm --prefix "${MAILBOX_ROOT}" run compile-contracts
      fi
    fi
    ;;
  *)
    echo "prepare_wallet_bundle.sh: unsupported platform '${platform_name}'." >&2
    exit 1
    ;;
esac

mkdir -p "${CACHE_ROOT}"

download_node_runtime() {
  tmp_archive="${NODE_ARCHIVE_PATH}.tmp"
  tmp_shasums="${NODE_SHASUMS_PATH}.tmp"
  curl -fsSL "${NODE_BASE_URL}/${NODE_ARCHIVE}" -o "${tmp_archive}"
  curl -fsSL "${NODE_BASE_URL}/SHASUMS256.txt" -o "${tmp_shasums}"
  expected_sum="$(awk -v archive="${NODE_ARCHIVE}" '$2 == archive { print $1 }' "${tmp_shasums}")"
  actual_sum="$(shasum -a 256 "${tmp_archive}" | awk '{ print $1 }')"
  if [ -z "${expected_sum}" ] || [ "${expected_sum}" != "${actual_sum}" ]; then
    echo "Downloaded Node runtime failed SHA-256 verification." >&2
    rm -f "${tmp_archive}" "${tmp_shasums}"
    exit 1
  fi
  mv "${tmp_archive}" "${NODE_ARCHIVE_PATH}"
  mv "${tmp_shasums}" "${NODE_SHASUMS_PATH}"
}

extract_node_runtime() {
  tmp_extract="${CACHE_ROOT}/${NODE_DIST}.extract"
  rm -rf "${tmp_extract}" "${NODE_CACHE_DIR}"
  mkdir -p "${tmp_extract}"
  tar -xzf "${NODE_ARCHIVE_PATH}" -C "${tmp_extract}"
  mv "${tmp_extract}/${NODE_DIST}" "${NODE_CACHE_DIR}"
  rm -rf "${tmp_extract}"
}

if [ ! -f "${NODE_ARCHIVE_PATH}" ] || [ ! -f "${NODE_SHASUMS_PATH}" ]; then
  if [ "${include_node_runtime}" = "1" ]; then
    download_node_runtime
  fi
fi

if [ "${include_node_runtime}" = "1" ] && [ ! -x "${NODE_CACHE_DIR}/bin/node" ]; then
  extract_node_runtime
fi

DESTINATION="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/WalletHelper"
rm -rf "${DESTINATION}"
mkdir -p "${DESTINATION}"
cp -R "${HELPER_ROOT}/dist" "${DESTINATION}/dist"
if [ "${include_node_runtime}" = "1" ]; then
  cp -R "${NODE_CACHE_DIR}" "${DESTINATION}/NodeRuntime"
fi
mkdir -p "${DESTINATION}/Mailbox/contracts/compiled" "${DESTINATION}/Mailbox/deployment"
cp -R "${MAILBOX_ROOT}/contracts/compiled/ziros_wallet_mailbox" "${DESTINATION}/Mailbox/contracts/compiled/ziros_wallet_mailbox"
cp "${MAILBOX_ROOT}/deployment/mailbox.deployment.template.json" "${DESTINATION}/Mailbox/deployment/mailbox.deployment.template.json"
if [ -f "${MAILBOX_ROOT}/deployment/mailbox.deployment.json" ]; then
  cp "${MAILBOX_ROOT}/deployment/mailbox.deployment.json" "${DESTINATION}/Mailbox/deployment/mailbox.deployment.json"
fi

if [ "${include_node_runtime}" = "1" ]; then
  BUNDLED_RUNTIME_ROOT="${DESTINATION}/NodeRuntime"
  BUNDLED_NODE="${BUNDLED_RUNTIME_ROOT}/bin/node"
  if ! "${BUNDLED_NODE}" -v >/dev/null 2>&1; then
    echo "Bundled Node runtime failed smoke check." >&2
    exit 1
  fi

  if [ "${CONFIGURATION:-Debug}" = "Release" ] && [ ! -x "${BUNDLED_NODE}" ]; then
    echo "Release build requires bundled official Node runtime." >&2
    exit 1
  fi

  if command -v codesign >/dev/null 2>&1; then
    find "${BUNDLED_RUNTIME_ROOT}" \
      \( -path "*/bin/node" -o -name "*.dylib" -o -name "*.so" \) \
      -type f \
      -print0 | while IFS= read -r -d '' executable; do
        chmod +x "${executable}" 2>/dev/null || true
        codesign --force --sign - --timestamp=none "${executable}" >/dev/null
      done
  fi
else
  rm -rf "${DESTINATION}/NodeRuntime"
fi
