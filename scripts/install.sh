#!/bin/bash
# ZirOS Installer (formerly ZKF)
# Usage: curl -sSf https://zkf.dev/install.sh | sh

set -euo pipefail

VERSION="${ZKF_VERSION:-latest}"
INSTALL_DIR="${ZKF_INSTALL_DIR:-$HOME/.zkf/bin}"
BASE_URL="${ZKF_RELEASE_BASE_URL:-https://releases.zkf.dev}"

write_wrapper() {
    local path="$1"
    local target_name="$2"
    cat > "$path" <<EOF
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
exec -a "$(basename "$path")" "\$SCRIPT_DIR/$target_name" "\$@"
EOF
    chmod +x "$path"
}

echo "ZirOS Installer (formerly ZKF)"
echo "=============================="
echo ""

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64)
                TARGET="aarch64-apple-darwin"
                echo "Detected: macOS Apple Silicon (M-series)"
                echo "Metal GPU acceleration: enabled"
                ;;
            x86_64)
                TARGET="x86_64-apple-darwin"
                echo "Detected: macOS Intel"
                echo "Metal GPU acceleration: not available (requires Apple Silicon)"
                ;;
            *)
                echo "Error: unsupported architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            x86_64)
                TARGET="x86_64-unknown-linux-gnu"
                echo "Detected: Linux x86_64"
                echo "Metal GPU acceleration: not available (macOS only)"
                ;;
            aarch64)
                TARGET="aarch64-unknown-linux-gnu"
                echo "Detected: Linux ARM64"
                ;;
            *)
                echo "Error: unsupported architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Error: unsupported OS: $OS"
        exit 1
        ;;
esac

echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download binary
DOWNLOAD_URL="${BASE_URL}/${VERSION}/zkf-${TARGET}"
echo "Downloading zkf from $DOWNLOAD_URL..."

if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$DOWNLOAD_URL" -o "$INSTALL_DIR/zkf-cli"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/zkf-cli"
else
    echo "Error: curl or wget required"
    exit 1
fi

chmod +x "$INSTALL_DIR/zkf-cli"
write_wrapper "$INSTALL_DIR/ziros" "zkf-cli"
write_wrapper "$INSTALL_DIR/zkf" "zkf-cli"

# Verify installation
"$INSTALL_DIR/zkf-cli" --version 2>/dev/null || true

echo ""
echo "ZirOS installed to: $INSTALL_DIR/zkf-cli"
echo "ZirOS alias installed to: $INSTALL_DIR/ziros"
echo "Legacy zkf alias installed to: $INSTALL_DIR/zkf"
echo ""

# Add to PATH if needed
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    SHELL_NAME="$(basename "$SHELL")"
    case "$SHELL_NAME" in
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        *)
            RC_FILE=""
            ;;
    esac

    if [ -n "$RC_FILE" ]; then
        echo "Add to your PATH by running:"
        echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> $RC_FILE"
        echo "  source $RC_FILE"
    else
        echo "Add $INSTALL_DIR to your PATH"
    fi
fi

echo ""
echo "Quick start:"
echo "  ziros demo --json            # Preferred command name"
echo "  zkf-cli doctor               # Installed binary name"
echo "  ziros capabilities           # Show supported backends"
echo "  ziros doctor                 # Check system requirements"
echo "  zkf ...                      # Legacy alias still works"
echo ""
echo "Documentation: https://zkf.dev/docs"
echo "API access: https://zkf.dev/api"
