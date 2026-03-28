#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target-public-artifact-build}"
OUT_DIR="${PUBLIC_ARTIFACT_BIN_OUT_DIR:-$TARGET_DIR/public}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
TRIM_PATHS_MODE="${PUBLIC_ARTIFACT_TRIM_PATHS:-all}"
HOST_TARGET="$(rustc -vV | awk '/host:/ { print $2 }')"
RUSTC_HASH="$(rustc +nightly -vV | awk '/commit-hash:/ { print $2 }')"
REGISTRY_SRC_DIR="$(find "$CARGO_HOME_DIR/registry/src" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1 || true)"
GIT_CHECKOUT_DIR="$CARGO_HOME_DIR/git/checkouts"
BINUTILS_PREFIX="${PUBLIC_ARTIFACT_BINUTILS_PREFIX:-/opt/homebrew/opt/binutils/bin}"

VERIFY_TARGETS=(
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
)

if ! cargo +nightly -V >/dev/null 2>&1; then
  echo "[public-build] nightly Cargo is required for trim-paths and location-detail sanitization" >&2
  exit 1
fi

if [[ "$HOST_TARGET" != "aarch64-apple-darwin" ]]; then
  echo "[public-build] public zkf-metal runtime builds are only supported from Apple Silicon hosts; found $HOST_TARGET" >&2
  exit 1
fi

resolve_tool() {
  local name="$1"
  local prefixed_path="$2"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  if [[ -x "$prefixed_path" ]]; then
    printf '%s\n' "$prefixed_path"
    return 0
  fi
  return 1
}

resolve_zig_bin() {
  if [[ -n "${PUBLIC_ARTIFACT_ZIG_BIN:-}" && -x "${PUBLIC_ARTIFACT_ZIG_BIN:-}" ]]; then
    printf '%s\n' "${PUBLIC_ARTIFACT_ZIG_BIN}"
    return 0
  fi
  if command -v zig >/dev/null 2>&1; then
    command -v zig
    return 0
  fi
  local pip_zig="$HOME/.local/lib/python3.10/site-packages/ziglang/zig"
  if [[ -x "$pip_zig" ]]; then
    printf '%s\n' "$pip_zig"
    return 0
  fi
  return 1
}

GNU_STRIP_BIN="$(resolve_tool gstrip "$BINUTILS_PREFIX/gstrip" || true)"
GNU_NM_BIN="$(resolve_tool gnm "$BINUTILS_PREFIX/gnm" || true)"
GNU_READELF_BIN="$(resolve_tool greadelf "$BINUTILS_PREFIX/greadelf" || true)"
GNU_OBJDUMP_BIN="$(resolve_tool gobjdump "$BINUTILS_PREFIX/gobjdump" || true)"
ZIG_BIN="$(resolve_zig_bin || true)"

if [[ -z "$GNU_STRIP_BIN" && -z "$ZIG_BIN" ]]; then
  echo "[public-build] need gstrip or zig to strip ELF verifier binaries" >&2
  exit 1
fi

if [[ -z "$GNU_NM_BIN" || -z "$GNU_READELF_BIN" || -z "$GNU_OBJDUMP_BIN" ]]; then
  echo "[public-build] GNU binutils are required to inspect Linux verifier binaries" >&2
  exit 1
fi

mkdir -p "$OUT_DIR/bin" "$OUT_DIR/linkers"

export ZKF_PUBLIC_ARTIFACT_BUILD=1
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_PROFILE_RELEASE_TRIM_PATHS="$TRIM_PATHS_MODE"
export CARGO_PROFILE_RELEASE_DEBUG=0

echo "[public-build] target dir: $TARGET_DIR"
echo "[public-build] output dir: $OUT_DIR"

target_link_arg() {
  local target="$1"
  case "$target" in
    *apple-darwin)
      printf '%s\n' "-Clink-arg=-Wl,-dead_strip"
      ;;
    *unknown-linux-gnu)
      printf '%s\n' "-Clink-arg=-Wl,--gc-sections"
      ;;
    *)
      return 0
      ;;
  esac
}

encoded_rustflags_for_target() {
  local target="$1"
  local flags=(
    "--remap-path-prefix=$ROOT=workspace"
    "--remap-path-prefix=$RUSTUP_HOME_DIR=rustup"
    "-Zlocation-detail=none"
    "-Zremap-path-scope=all"
    "-Cdebuginfo=0"
    "-Cstrip=symbols"
    "-Cpanic=abort"
  )

  if [[ -n "$REGISTRY_SRC_DIR" ]]; then
    flags+=("--remap-path-prefix=$REGISTRY_SRC_DIR=registry")
  fi
  if [[ -d "$GIT_CHECKOUT_DIR" ]]; then
    flags+=("--remap-path-prefix=$GIT_CHECKOUT_DIR=gitdeps")
  fi
  if [[ -n "$RUSTC_HASH" ]]; then
    flags+=("--remap-path-prefix=/rustc/$RUSTC_HASH=rustc-src")
  fi

  local link_arg=""
  link_arg="$(target_link_arg "$target" || true)"
  if [[ -n "$link_arg" ]]; then
    flags+=("$link_arg")
  fi

  local encoded=""
  encoded="$(printf '%s\x1f' "${flags[@]}")"
  encoded="${encoded%$'\x1f'}"
  printf '%s\n' "$encoded"
}

linker_env_var_for_target() {
  local target="$1"
  local normalized=""
  normalized="$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')"
  printf 'CARGO_TARGET_%s_LINKER\n' "$normalized"
}

cc_env_var_for_target() {
  local target="$1"
  local normalized=""
  normalized="$(printf '%s' "$target" | tr '[:upper:]-' '[:lower:]_')"
  printf 'CC_%s\n' "$normalized"
}

cxx_env_var_for_target() {
  local target="$1"
  local normalized=""
  normalized="$(printf '%s' "$target" | tr '[:upper:]-' '[:lower:]_')"
  printf 'CXX_%s\n' "$normalized"
}

zig_target_for_rust_target() {
  local target="$1"
  case "$target" in
    x86_64-unknown-linux-gnu)
      printf '%s\n' "x86_64-linux-gnu"
      ;;
    aarch64-unknown-linux-gnu)
      printf '%s\n' "aarch64-linux-gnu"
      ;;
    *)
      echo "[public-build] unsupported Zig-linked target: $target" >&2
      exit 1
      ;;
  esac
}

ensure_zig_linker_wrapper() {
  local target="$1"
  if [[ -z "$ZIG_BIN" ]]; then
    echo "[public-build] zig is required to cross-link $target" >&2
    exit 1
  fi

  local zig_target=""
  zig_target="$(zig_target_for_rust_target "$target")"
  local wrapper="$OUT_DIR/linkers/${target}-zig-cc"
  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail

filtered=()
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --target=*)
      shift
      ;;
    --target)
      shift 2
      ;;
    *)
      filtered+=("\$1")
      shift
      ;;
  esac
done

exec "$ZIG_BIN" cc -target $zig_target "\${filtered[@]}"
EOF
  chmod +x "$wrapper"
  printf '%s\n' "$wrapper"
}

run_release_build() {
  local target="$1"
  shift

  export CARGO_ENCODED_RUSTFLAGS
  CARGO_ENCODED_RUSTFLAGS="$(encoded_rustflags_for_target "$target")"

  local linker_env_var=""
  local cc_env_var=""
  local cxx_env_var=""
  local linker_wrapper=""
  if [[ "$target" == *unknown-linux-gnu ]]; then
    linker_env_var="$(linker_env_var_for_target "$target")"
    cc_env_var="$(cc_env_var_for_target "$target")"
    cxx_env_var="$(cxx_env_var_for_target "$target")"
    linker_wrapper="$(ensure_zig_linker_wrapper "$target")"
    export "$linker_env_var=$linker_wrapper"
    export "$cc_env_var=$linker_wrapper"
    export "$cxx_env_var=$linker_wrapper"
  fi

  cargo +nightly -Z trim-paths build --release --target "$target" "$@"

  if [[ -n "$linker_env_var" ]]; then
    unset "$linker_env_var"
    unset "$cc_env_var"
    unset "$cxx_env_var"
  fi
}

strip_binary() {
  local path="$1"
  local description=""
  description="$(file -b "$path" 2>/dev/null || true)"

  if [[ "$description" == *"ELF"* ]]; then
    if [[ -n "$GNU_STRIP_BIN" ]]; then
      "$GNU_STRIP_BIN" --strip-all "$path"
      return
    fi
    local stripped="$path.stripped"
    "$ZIG_BIN" objcopy --strip-all "$path" "$stripped"
    mv "$stripped" "$path"
    return
  fi

  if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip --strip-all "$path"
    return
  fi
  strip -S -x "$path"
}

scan_binary_output() {
  local artifact_path="$1"
  local tool_name="$2"
  local pattern="$3"
  local label="$4"
  shift 4

  local raw_output=""
  local filtered_output=""
  raw_output="$(mktemp)"
  filtered_output="$(mktemp)"

  if ! "$@" >"$raw_output" 2>/dev/null; then
    rm -f "$raw_output" "$filtered_output"
    return 0
  fi

  grep -vF "$artifact_path" "$raw_output" >"$filtered_output" || true

  if grep -Eq "$pattern" "$filtered_output"; then
    echo "[public-build] $label detected in $artifact_path via $tool_name" >&2
    grep -En "$pattern" "$filtered_output" | head -50 >&2 || true
    rm -f "$raw_output" "$filtered_output"
    exit 1
  fi

  rm -f "$raw_output" "$filtered_output"
}

check_binary() {
  local path="$1"
  local description=""
  local absolute_path_pattern='(/Users/|/home/|/private/var/|Projects/ZK DEV)'
  local private_symbol_pattern='(#include <metal_stdlib>|using namespace metal;|Batch SHA-256 hashing on Metal GPU|[A-Za-z0-9_./-]+\.metal($|[:[:space:]"'"'"')])|[A-Za-z0-9_./-]+\.lean($|[:[:space:]"'"'"')])|ZirOS|zkf_cli|zkf_runtime|zkf_runtime::|zkf-cli|proof_ir\.rs|verified_artifacts\.rs|workspace/|vendor/|zkf-metal-public-cli/src/main\.rs|zkf-lib/src/|zkf-core/src/|zkf-backends/src/)'

  description="$(file -b "$path" 2>/dev/null || true)"
  scan_binary_output "$path" "strings" "$absolute_path_pattern" "absolute path leak" strings -a "$path"
  scan_binary_output "$path" "strings" "$private_symbol_pattern" "source or internal-symbol leak" strings -a "$path"

  if [[ "$description" == *"ELF"* ]]; then
    scan_binary_output "$path" "gnm" "$absolute_path_pattern" "absolute path leak" "$GNU_NM_BIN" -a "$path"
    scan_binary_output "$path" "gnm" "$private_symbol_pattern" "source or internal-symbol leak" "$GNU_NM_BIN" -a "$path"
    scan_binary_output "$path" "greadelf" "$absolute_path_pattern" "absolute path leak" "$GNU_READELF_BIN" -Wa "$path"
    scan_binary_output "$path" "greadelf" "$private_symbol_pattern" "source or internal-symbol leak" "$GNU_READELF_BIN" -Wa "$path"
    scan_binary_output "$path" "gobjdump" "$absolute_path_pattern" "absolute path leak" "$GNU_OBJDUMP_BIN" -x "$path"
    scan_binary_output "$path" "gobjdump" "$private_symbol_pattern" "source or internal-symbol leak" "$GNU_OBJDUMP_BIN" -x "$path"
    return
  fi

  scan_binary_output "$path" "nm" "$absolute_path_pattern" "absolute path leak" nm -a "$path"
  scan_binary_output "$path" "nm" "$private_symbol_pattern" "source or internal-symbol leak" nm -a "$path"
  scan_binary_output "$path" "otool" "$absolute_path_pattern" "absolute path leak" otool -l "$path"
  scan_binary_output "$path" "otool" "$private_symbol_pattern" "source or internal-symbol leak" otool -l "$path"
  scan_binary_output "$path" "objdump" "$absolute_path_pattern" "absolute path leak" objdump --macho --section-headers "$path"
  scan_binary_output "$path" "objdump" "$private_symbol_pattern" "source or internal-symbol leak" objdump --macho --section-headers "$path"
}

copy_publish_binary() {
  local source_path="$1"
  local published_path="$2"
  mkdir -p "$(dirname "$published_path")"
  cp "$source_path" "$published_path"
  strip_binary "$published_path"
  check_binary "$published_path"
}

build_target_binary_path() {
  local target="$1"
  local binary="$2"
  printf '%s/%s/release/%s\n' "$TARGET_DIR" "$target" "$binary"
}

publish_host_runtime_and_verifier() {
  run_release_build "$HOST_TARGET" -p zkf-metal-public-cli -p zkf-verify

  local host_runtime_source=""
  local host_verify_source=""
  host_runtime_source="$(build_target_binary_path "$HOST_TARGET" "zkf-metal")"
  host_verify_source="$(build_target_binary_path "$HOST_TARGET" "zkf-verify")"

  copy_publish_binary "$host_runtime_source" "$OUT_DIR/bin/$HOST_TARGET/zkf-metal"
  copy_publish_binary "$host_verify_source" "$OUT_DIR/bin/$HOST_TARGET/zkf-verify"
  cp "$OUT_DIR/bin/$HOST_TARGET/zkf-metal" "$OUT_DIR/bin/zkf-metal"
  cp "$OUT_DIR/bin/$HOST_TARGET/zkf-verify" "$OUT_DIR/bin/zkf-verify"
}

publish_cross_verifiers() {
  local target=""
  for target in "${VERIFY_TARGETS[@]}"; do
    if [[ "$target" == "$HOST_TARGET" ]]; then
      continue
    fi
    run_release_build "$target" -p zkf-verify
    copy_publish_binary \
      "$(build_target_binary_path "$target" "zkf-verify")" \
      "$OUT_DIR/bin/$target/zkf-verify"
  done
}

publish_host_runtime_and_verifier
publish_cross_verifiers

cat >"$OUT_DIR/build-summary.txt" <<EOF
target_dir=$TARGET_DIR
host_target=$HOST_TARGET
zkf_metal_binary=$OUT_DIR/bin/zkf-metal
zkf_verify_binary=$OUT_DIR/bin/zkf-verify
zkf_metal_binary_aarch64_apple_darwin=$OUT_DIR/bin/aarch64-apple-darwin/zkf-metal
zkf_verify_binary_aarch64_apple_darwin=$OUT_DIR/bin/aarch64-apple-darwin/zkf-verify
zkf_verify_binary_x86_64_apple_darwin=$OUT_DIR/bin/x86_64-apple-darwin/zkf-verify
zkf_verify_binary_x86_64_unknown_linux_gnu=$OUT_DIR/bin/x86_64-unknown-linux-gnu/zkf-verify
zkf_verify_binary_aarch64_unknown_linux_gnu=$OUT_DIR/bin/aarch64-unknown-linux-gnu/zkf-verify
public_artifact_build=1
EOF

echo "[public-build] built:"
echo "  $OUT_DIR/bin/$HOST_TARGET/zkf-metal"
echo "  $OUT_DIR/bin/$HOST_TARGET/zkf-verify"
echo "  $OUT_DIR/bin/x86_64-apple-darwin/zkf-verify"
echo "  $OUT_DIR/bin/x86_64-unknown-linux-gnu/zkf-verify"
echo "  $OUT_DIR/bin/aarch64-unknown-linux-gnu/zkf-verify"
