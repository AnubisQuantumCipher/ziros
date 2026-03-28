#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${ZIROS_BIN_DIR:-$HOME/.local/bin}"

ensure_rust() {
    if command -v cargo >/dev/null 2>&1 && command -v rustup >/dev/null 2>&1; then
        return
    fi

    echo "Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
}

ensure_xcode_clt() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        return
    fi
    if xcode-select -p >/dev/null 2>&1; then
        return
    fi

    echo "Xcode Command Line Tools are required on macOS."
    xcode-select --install || true
    echo "Install the Command Line Tools, then rerun ./install.sh."
    exit 1
}

install_binary() {
    mkdir -p "$BIN_DIR"
    cp "$ROOT_DIR/target-local/release/zkf-cli" "$BIN_DIR/zkf-cli"
    cat > "$BIN_DIR/ziros" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/zkf-cli" "$@"
EOF
    chmod +x "$BIN_DIR/zkf-cli" "$BIN_DIR/ziros"
}

ensure_rust
ensure_xcode_clt

echo "Building ZirOS..."
"$ROOT_DIR/zkf-build.sh" --release -p zkf-cli

install_binary

mkdir -p "$HOME/.zkf/storage" "$HOME/.zkf/logs"
if [[ "$(uname -s)" == "Darwin" ]]; then
    "$BIN_DIR/zkf-cli" storage install 2>/dev/null || true
fi

echo "Running doctor..."
"$BIN_DIR/zkf-cli" doctor
"$BIN_DIR/zkf-cli" storage status

cat <<EOF

Installed:
  $BIN_DIR/zkf-cli
  $BIN_DIR/ziros

Quick start:
  export PATH="$BIN_DIR:\$PATH"
  zkf-cli app init --template range-proof --name quickstart --out /tmp/quickstart
  cargo test --manifest-path /tmp/quickstart/Cargo.toml --quiet
  cargo run --manifest-path /tmp/quickstart/Cargo.toml --quiet
EOF
