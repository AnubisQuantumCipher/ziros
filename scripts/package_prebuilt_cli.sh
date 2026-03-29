#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${ZKF_PREBUILT_OUTPUT_DIR:-$ROOT_DIR/target-local/prebuilt}"
VERSION="${ZKF_PREBUILT_VERSION:-latest}"
BINARY_PATH="${ZKF_PREBUILT_BINARY:-$ROOT_DIR/target-local/release/zkf-cli}"
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage: scripts/package_prebuilt_cli.sh [options]

Package the current release zkf-cli binary into the layout consumed by
scripts/install.sh and releases.zkf.dev.

Options:
  --version VALUE       Output version directory (default: latest)
  --output-dir PATH     Root output directory (default: target-local/prebuilt)
  --binary PATH         Existing release binary to package
  --skip-build          Reuse the existing binary without rebuilding
  --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    "$ROOT_DIR/zkf-build.sh" --release -p zkf-cli
fi

if [[ ! -x "$BINARY_PATH" ]]; then
    echo "missing release binary: $BINARY_PATH" >&2
    exit 1
fi

HOST_TRIPLE="$(rustc -vV | awk '/^host: / { print $2 }')"
if [[ -z "$HOST_TRIPLE" ]]; then
    echo "failed to determine host target triple" >&2
    exit 1
fi

DEST_DIR="$OUTPUT_ROOT/$VERSION"
RAW_BINARY_NAME="zkf-$HOST_TRIPLE"
RAW_BINARY_PATH="$DEST_DIR/$RAW_BINARY_NAME"
ARCHIVE_PATH="$DEST_DIR/$RAW_BINARY_NAME.tar.gz"
MANIFEST_PATH="$DEST_DIR/manifest.json"
CHECKSUM_PATH="$DEST_DIR/SHA256SUMS"

mkdir -p "$DEST_DIR"
cp "$BINARY_PATH" "$RAW_BINARY_PATH"
chmod +x "$RAW_BINARY_PATH"

STAGING_DIR="$(mktemp -d "$DEST_DIR/.package.XXXXXX")"
cleanup() {
    rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

mkdir -p "$STAGING_DIR/bin"
cp "$BINARY_PATH" "$STAGING_DIR/bin/zkf-cli"
chmod +x "$STAGING_DIR/bin/zkf-cli"
cat > "$STAGING_DIR/bin/ziros" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/zkf-cli" "$@"
EOF
cat > "$STAGING_DIR/bin/zkf" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/zkf-cli" "$@"
EOF
chmod +x "$STAGING_DIR/bin/ziros" "$STAGING_DIR/bin/zkf"

tar -C "$STAGING_DIR" -czf "$ARCHIVE_PATH" .

RAW_SHA="$(shasum -a 256 "$RAW_BINARY_PATH" | awk '{print $1}')"
ARCHIVE_SHA="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
RAW_SIZE="$(stat -f '%z' "$RAW_BINARY_PATH")"
ARCHIVE_SIZE="$(stat -f '%z' "$ARCHIVE_PATH")"
GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
    GIT_DIRTY=true
else
    GIT_DIRTY=false
fi
BUILT_AT_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

cat > "$CHECKSUM_PATH" <<EOF
$RAW_SHA  $RAW_BINARY_NAME
$ARCHIVE_SHA  ${RAW_BINARY_NAME}.tar.gz
EOF

cat > "$MANIFEST_PATH" <<EOF
{
  "schema": "ziros-prebuilt-cli-v1",
  "version": "$VERSION",
  "target": "$HOST_TRIPLE",
  "built_at_utc": "$BUILT_AT_UTC",
  "git_commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "binary_name": "$RAW_BINARY_NAME",
  "binary_path": "$RAW_BINARY_PATH",
  "binary_sha256": "$RAW_SHA",
  "binary_size_bytes": $RAW_SIZE,
  "archive_path": "$ARCHIVE_PATH",
  "archive_sha256": "$ARCHIVE_SHA",
  "archive_size_bytes": $ARCHIVE_SIZE
}
EOF

echo "packaged prebuilt binary:"
echo "  raw:      $RAW_BINARY_PATH"
echo "  archive:  $ARCHIVE_PATH"
echo "  checksums:$CHECKSUM_PATH"
echo "  manifest: $MANIFEST_PATH"
