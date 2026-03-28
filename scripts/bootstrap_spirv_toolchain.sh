#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/zkf-metal/proofs/spirv/SPIRV_PIN.toml"
tools_root="$repo_root/.zkf-tools/spirv"
src_root="$tools_root/src"
build_root="$tools_root/build"
bin_root="$tools_root/bin"
env_file="$tools_root/spirv.env"

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

require_binary() {
  local binary="$1"
  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "required binary '$binary' was not found in PATH" >&2
    exit 1
  fi
}

checkout_repo() {
  local name="$1"
  local repo="$2"
  local rev="$3"
  local dir="$src_root/$name"

  if [[ ! -d "$dir/.git" ]]; then
    git clone --recursive "$repo" "$dir"
  fi

  git -C "$dir" fetch --tags --force origin
  git -C "$dir" checkout --force "$rev"
  git -C "$dir" submodule update --init --recursive
}

checkout_repo_at_dir() {
  local dir="$1"
  local repo="$2"
  local rev="$3"

  if [[ ! -d "$dir/.git" ]]; then
    mkdir -p "$(dirname "$dir")"
    git clone "$repo" "$dir"
  fi

  git -C "$dir" fetch --tags --force origin
  git -C "$dir" checkout --force "$rev"
}

require_binary git
require_binary cmake
require_binary ninja

llvm_config_hint="$(pin_value llvm_config_hint)"
if [[ -n "$llvm_config_hint" && -x "$llvm_config_hint" ]]; then
  llvm_config="$llvm_config_hint"
elif command -v llvm-config >/dev/null 2>&1; then
  llvm_config="$(command -v llvm-config)"
else
  echo "llvm-config is required to build the pinned SPIR-V translator toolchain" >&2
  exit 1
fi

spirv_cross_repo="$(pin_value spirv_cross_repo)"
spirv_cross_rev="$(pin_value spirv_cross_rev)"
spirv_tools_repo="$(pin_value spirv_tools_repo)"
spirv_tools_rev="$(pin_value spirv_tools_rev)"
spirv_translator_repo="$(pin_value spirv_llvm_translator_repo)"
spirv_translator_rev="$(pin_value spirv_llvm_translator_rev)"

mkdir -p "$src_root" "$build_root" "$bin_root"

checkout_repo SPIRV-Cross "$spirv_cross_repo" "$spirv_cross_rev"
checkout_repo SPIRV-Tools "$spirv_tools_repo" "$spirv_tools_rev"
checkout_repo SPIRV-LLVM-Translator "$spirv_translator_repo" "$spirv_translator_rev"

spirv_tools_headers_rev="$(python3 - <<'PY'
from pathlib import Path
import re
deps = Path(".zkf-tools/spirv/src/SPIRV-Tools/DEPS").read_text()
match = re.search(r"'spirv_headers_revision': '([^']+)'", deps)
if not match:
    raise SystemExit("failed to locate spirv_headers_revision in SPIRV-Tools/DEPS")
print(match.group(1))
PY
)"
translator_headers_rev="$(cat "$src_root/SPIRV-LLVM-Translator/spirv-headers-tag.conf")"

checkout_repo_at_dir \
  "$src_root/SPIRV-Tools/external/spirv-headers" \
  "https://github.com/KhronosGroup/SPIRV-Headers.git" \
  "$spirv_tools_headers_rev"
checkout_repo_at_dir \
  "$src_root/SPIRV-Headers-translator" \
  "https://github.com/KhronosGroup/SPIRV-Headers.git" \
  "$translator_headers_rev"

cmake -S "$src_root/SPIRV-Cross" \
  -B "$build_root/SPIRV-Cross" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DSPIRV_CROSS_SHARED=OFF \
  -DSPIRV_CROSS_CLI=ON
cmake --build "$build_root/SPIRV-Cross" --target spirv-cross

cmake -S "$src_root/SPIRV-Tools" \
  -B "$build_root/SPIRV-Tools" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DSPIRV_SKIP_TESTS=ON \
  -DSPIRV_WERROR=OFF
cmake --build "$build_root/SPIRV-Tools" --target spirv-val spirv-as

cmake -S "$src_root/SPIRV-LLVM-Translator" \
  -B "$build_root/SPIRV-LLVM-Translator" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$("$llvm_config" --cmakedir)" \
  -DLLVM_EXTERNAL_SPIRV_HEADERS_SOURCE_DIR="$src_root/SPIRV-Headers-translator" \
  -DBUILD_SHARED_LIBS=OFF
cmake --build "$build_root/SPIRV-LLVM-Translator" --target llvm-spirv

spirv_cross_bin="$(find "$build_root/SPIRV-Cross" -type f -name spirv-cross | head -n 1)"
spirv_val_bin="$(find "$build_root/SPIRV-Tools" -type f -name spirv-val | head -n 1)"
spirv_as_bin="$(find "$build_root/SPIRV-Tools" -type f -name spirv-as | head -n 1)"
llvm_spirv_bin="$(find "$build_root/SPIRV-LLVM-Translator" -type f -name llvm-spirv | head -n 1)"

if [[ -z "$spirv_cross_bin" || -z "$spirv_val_bin" || -z "$spirv_as_bin" || -z "$llvm_spirv_bin" ]]; then
  echo "failed to locate one or more SPIR-V binaries after build" >&2
  exit 1
fi

ln -sf "$spirv_cross_bin" "$bin_root/spirv-cross"
ln -sf "$spirv_val_bin" "$bin_root/spirv-val"
ln -sf "$spirv_as_bin" "$bin_root/spirv-as"
ln -sf "$llvm_spirv_bin" "$bin_root/llvm-spirv"

llvm_bin_dir="$(dirname "$llvm_config")"

cat >"$env_file" <<EOF
#!/usr/bin/env bash
export ZKF_SPIRV_TOOLS_ROOT="$tools_root"
export ZKF_SPIRV_LLVM_CONFIG="$llvm_config"
export PATH="$bin_root:$llvm_bin_dir:\$PATH"
EOF
chmod +x "$env_file"

echo "$bin_root"
