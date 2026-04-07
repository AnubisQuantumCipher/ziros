#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
pin_file="$repo_root/zkf-runtime/proofs/verus/VERUS_PIN.toml"
tool_root="$repo_root/.zkf-tools/verus"
install_root="$tool_root/install"

log() {
  printf '[bootstrap-verus] %s\n' "$*" >&2
}

if [[ ! -f "$pin_file" ]]; then
  log "missing Verus pin file at $pin_file"
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    url_key="download_url_macos_arm64"
    ;;
  Darwin-x86_64)
    url_key="download_url_macos_x86_64"
    ;;
  Linux-x86_64)
    url_key="download_url_linux_x86_64"
    ;;
  *)
    log "unsupported host platform $(uname -s)-$(uname -m)"
    exit 1
    ;;
esac

download_url="$(awk -F'"' -v key="$url_key" '$1 ~ key { print $2 }' "$pin_file")"
if [[ -z "$download_url" ]]; then
  log "failed to resolve $url_key from $pin_file"
  exit 1
fi

mkdir -p "$tool_root"
rm -rf "$install_root"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/zkf-verus.XXXXXX")"
archive_path="$tmpdir/verus.zip"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

log "downloading pinned Verus toolchain"
curl -L "$download_url" -o "$archive_path"

log "extracting Verus toolchain"
unzip -q "$archive_path" -d "$tmpdir"

extracted_root="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d -name 'verus-*' | head -n 1)"
if [[ -z "$extracted_root" ]]; then
  log "download did not contain a verus-* directory"
  exit 1
fi

mv "$extracted_root" "$install_root"

cat >"$tool_root/verus.env" <<EOF
export VERUS_HOME="$install_root"
export VERUS_Z3_PATH="$install_root/z3"
export PATH="$install_root:\$PATH"
EOF

log "installed Verus at $install_root"
