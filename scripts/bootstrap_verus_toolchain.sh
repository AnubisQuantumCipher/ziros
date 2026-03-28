#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/zkf-runtime/proofs/verus/VERUS_PIN.toml"
tools_root="$repo_root/.zkf-tools/verus"
release_root="$tools_root/release"
bin_root="$tools_root/bin"
env_file="$tools_root/verus.env"

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

detect_platform_key() {
  local system
  local machine
  system="$(uname -s)"
  machine="$(uname -m)"
  case "${system}:${machine}" in
    Darwin:arm64|Darwin:aarch64)
      printf '%s\n' "macos_arm64"
      ;;
    Darwin:x86_64)
      printf '%s\n' "macos_x86_64"
      ;;
    Linux:x86_64)
      printf '%s\n' "linux_x86_64"
      ;;
    *)
      return 1
      ;;
  esac
}

require_binary() {
  local binary="$1"
  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "required binary '$binary' was not found in PATH" >&2
    exit 1
  fi
}

require_binary curl
require_binary unzip

version="$(pin_value version)"
release_tag="$(pin_value release_tag)"
platform_key="${ZKF_VERUS_PLATFORM_OVERRIDE:-}"
platform_key="${platform_key//-/_}"

if [[ -z "$platform_key" ]]; then
  if ! platform_key="$(detect_platform_key)"; then
    echo "unsupported Verus host platform: $(uname -s) $(uname -m)" >&2
    echo "supported platforms: Apple Silicon macOS, Intel macOS, x86_64 Linux" >&2
    exit 1
  fi
fi

asset="$(pin_value "asset_${platform_key}")"
download_url="$(pin_value "download_url_${platform_key}")"

if [[ -z "$asset" || -z "$download_url" ]]; then
  asset="$(pin_value asset)"
  download_url="$(pin_value download_url)"
fi

if [[ -z "$asset" || -z "$download_url" || -z "$version" || -z "$release_tag" ]]; then
  echo "failed to read pinned Verus settings from $pin_file" >&2
  exit 1
fi

archive_path="$release_root/$asset"
install_dir="$release_root/${version}-${platform_key}"

mkdir -p "$release_root" "$bin_root"

if [[ ! -f "$archive_path" ]]; then
  curl -L --fail "$download_url" -o "$archive_path"
fi

if [[ ! -d "$install_dir" ]]; then
  tmp_dir="$(mktemp -d "$release_root/.extract.XXXXXX")"
  trap 'rm -rf "$tmp_dir"' EXIT
  unzip -q "$archive_path" -d "$tmp_dir"
  extracted_root="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$extracted_root" ]]; then
    echo "failed to extract Verus release from $archive_path" >&2
    exit 1
  fi
  mv "$extracted_root" "$install_dir"
fi

if command -v xattr >/dev/null 2>&1; then
  xattr -dr com.apple.quarantine "$install_dir" >/dev/null 2>&1 || true
fi

verus_bin="$(find "$install_dir" -type f -name verus | head -n 1)"
cargo_verus_bin="$(find "$install_dir" -type f -name cargo-verus | head -n 1)"
if [[ -z "$verus_bin" || -z "$cargo_verus_bin" ]]; then
  echo "failed to locate Verus binaries under $install_dir" >&2
  exit 1
fi

tool_bin_dir="$(dirname "$verus_bin")"
verus_probe_output=""

if [[ "${ZKF_VERUS_SKIP_PROBE:-0}" != "1" ]]; then
  verus_probe_output="$("$verus_bin" 2>&1 >/dev/null || true)"
fi

if [[ "$verus_probe_output" == *"rustup not found"* ]]; then
  echo "Verus requires rustup, but rustup is not installed. Install rustup and rerun." >&2
  exit 1
fi

required_toolchain="$(printf '%s\n' "$verus_probe_output" | sed -nE 's/.*required rust toolchain ([^[:space:]]+) not found.*/\1/p' | head -n 1)"
if [[ -n "$required_toolchain" ]]; then
  require_binary rustup
  rustup install "$required_toolchain"
fi

ln -sf "$verus_bin" "$bin_root/verus"
ln -sf "$cargo_verus_bin" "$bin_root/cargo-verus"

mkdir -p "$(dirname "$env_file")"
cat >"$env_file" <<EOF
#!/usr/bin/env bash
export ZKF_VERUS_HOME="$install_dir"
export ZKF_VERUS_BIN="$verus_bin"
export ZKF_CARGO_VERUS_BIN="$cargo_verus_bin"
export PATH="$bin_root:$tool_bin_dir:\$PATH"
EOF
chmod +x "$env_file"

echo "$bin_root"
