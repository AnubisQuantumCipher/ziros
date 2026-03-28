#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: cutover_zkf_metal_public_repo.sh --artifact-dir PATH [options]

Rename the current public source-visible repo to the preview line, archive it,
create a fresh public zkf-metal repo, and publish an artifact-only tree into it.

Options:
  --artifact-dir PATH    Generated public artifact repo tree to publish.
  --owner NAME           GitHub owner. Default: AnubisQuantumCipher
  --public-repo NAME     Fresh artifact-only repo name. Default: zkf-metal
  --preview-repo NAME    Archived preview repo name. Default: zkf-metal-preview
  --branch NAME          Branch to publish. Default: main
  --verify-bin PATH      Optional local zkf-verify binary to run before publish.
  --skip-cutover         Skip rename/archive/create and only publish.
  -h, --help             Show this help text.
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_SCRIPT="$ROOT/scripts/publish_zkf_metal_public_artifact_repo.sh"

ARTIFACT_DIR=""
OWNER="AnubisQuantumCipher"
PUBLIC_REPO="zkf-metal"
PREVIEW_REPO="zkf-metal-preview"
BRANCH="main"
VERIFY_BIN=""
SKIP_CUTOVER=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact-dir)
            ARTIFACT_DIR="${2:-}"
            shift 2
            ;;
        --owner)
            OWNER="${2:-}"
            shift 2
            ;;
        --public-repo)
            PUBLIC_REPO="${2:-}"
            shift 2
            ;;
        --preview-repo)
            PREVIEW_REPO="${2:-}"
            shift 2
            ;;
        --branch)
            BRANCH="${2:-}"
            shift 2
            ;;
        --verify-bin)
            VERIFY_BIN="${2:-}"
            shift 2
            ;;
        --skip-cutover)
            SKIP_CUTOVER=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$ARTIFACT_DIR" ]]; then
    echo "--artifact-dir is required" >&2
    usage >&2
    exit 1
fi

for required in gh bash; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "Missing required command: $required" >&2
        exit 1
    fi
done

if [[ ! -x "$PUBLISH_SCRIPT" ]]; then
    echo "Publish script is missing or not executable: $PUBLISH_SCRIPT" >&2
    exit 1
fi

gh auth status -h github.com >/dev/null

PUBLIC_SLUG="$OWNER/$PUBLIC_REPO"
PREVIEW_SLUG="$OWNER/$PREVIEW_REPO"

if [[ "$SKIP_CUTOVER" -ne 1 ]]; then
    public_exists=0
    preview_exists=0
    if gh repo view "$PUBLIC_SLUG" >/dev/null 2>&1; then
        public_exists=1
    fi
    if gh repo view "$PREVIEW_SLUG" >/dev/null 2>&1; then
        preview_exists=1
    fi

    if [[ "$public_exists" -eq 1 && "$preview_exists" -eq 1 ]]; then
        echo "Both $PUBLIC_SLUG and $PREVIEW_SLUG already exist; refusing ambiguous cutover." >&2
        exit 1
    fi

    if [[ "$public_exists" -eq 1 ]]; then
        gh api -X PATCH "repos/$PUBLIC_SLUG" \
            -f name="$PREVIEW_REPO" \
            -f description="Archived preview period for the source-visible zkf-metal releases"
        gh api -X PATCH "repos/$PREVIEW_SLUG" -F archived=true
    elif [[ "$preview_exists" -eq 1 ]]; then
        gh api -X PATCH "repos/$PREVIEW_SLUG" -F archived=true >/dev/null
    fi

    if ! gh repo view "$PUBLIC_SLUG" >/dev/null 2>&1; then
        gh repo create "$PUBLIC_SLUG" --public \
            --description "Artifact-only public verification release for zkf-metal"
    fi
fi

publish_args=(
    --artifact-dir "$ARTIFACT_DIR"
    --repo "$PUBLIC_SLUG"
    --branch "$BRANCH"
    --visibility public
)
if [[ -n "$VERIFY_BIN" ]]; then
    publish_args+=(--verify-bin "$VERIFY_BIN")
fi

"$PUBLISH_SCRIPT" "${publish_args[@]}"

echo "Cutover complete:"
echo "  preview: https://github.com/$PREVIEW_SLUG"
echo "  public:  https://github.com/$PUBLIC_SLUG"
