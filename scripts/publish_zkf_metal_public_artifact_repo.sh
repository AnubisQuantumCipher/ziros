#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: publish_zkf_metal_public_artifact_repo.sh --artifact-dir PATH [options]

Publish a generated zkf-metal public artifact tree to GitHub without exposing the
private source repository history.

Options:
  --artifact-dir PATH   Generated public artifact repo tree to publish.
  --repo OWNER/NAME     GitHub repo slug. Default: AnubisQuantumCipher/zkf-metal
  --branch NAME         Git branch to publish. Default: main
  --visibility VALUE    public or private. Default: public
  --verify-bin PATH     Optional local zkf-verify binary to run before publish.
  --skip-create         Fail instead of creating the GitHub repo when missing.
  -h, --help            Show this help text.
EOF
}

ARTIFACT_DIR=""
REPO_SLUG="AnubisQuantumCipher/zkf-metal"
BRANCH="main"
VISIBILITY="public"
VERIFY_BIN=""
SKIP_CREATE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact-dir)
            ARTIFACT_DIR="${2:-}"
            shift 2
            ;;
        --repo)
            REPO_SLUG="${2:-}"
            shift 2
            ;;
        --branch)
            BRANCH="${2:-}"
            shift 2
            ;;
        --visibility)
            VISIBILITY="${2:-}"
            shift 2
            ;;
        --verify-bin)
            VERIFY_BIN="${2:-}"
            shift 2
            ;;
        --skip-create)
            SKIP_CREATE=1
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

case "$VISIBILITY" in
    public|private)
        ;;
    *)
        echo "--visibility must be public or private" >&2
        exit 1
        ;;
esac

for required in git gh rsync; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "Missing required command: $required" >&2
        exit 1
    fi
done

if [[ ! -d "$ARTIFACT_DIR" ]]; then
    echo "Artifact directory does not exist: $ARTIFACT_DIR" >&2
    exit 1
fi

if [[ ! -f "$ARTIFACT_DIR/README.md" ]]; then
    echo "Artifact directory is missing README.md: $ARTIFACT_DIR" >&2
    exit 1
fi

if [[ ! -f "$ARTIFACT_DIR/checksums/sha256.txt" ]]; then
    echo "Artifact directory is missing checksums/sha256.txt: $ARTIFACT_DIR" >&2
    exit 1
fi

if [[ -n "$VERIFY_BIN" ]]; then
    if [[ ! -x "$VERIFY_BIN" ]]; then
        echo "Verifier binary is not executable: $VERIFY_BIN" >&2
        exit 1
    fi
    "$VERIFY_BIN" verify-all --repo "$ARTIFACT_DIR"
fi

gh auth status -h github.com >/dev/null

if ! gh repo view "$REPO_SLUG" >/dev/null 2>&1; then
    if [[ "$SKIP_CREATE" -eq 1 ]]; then
        echo "GitHub repo does not exist and --skip-create was set: $REPO_SLUG" >&2
        exit 1
    fi
    gh repo create "$REPO_SLUG" "--$VISIBILITY" --description "Artifact-only public verification release for zkf-metal"
fi

TEMP_REPO="$(mktemp -d)"
cleanup() {
    rm -rf "$TEMP_REPO"
}
trap cleanup EXIT

rsync -a --delete "$ARTIFACT_DIR"/ "$TEMP_REPO"/

pushd "$TEMP_REPO" >/dev/null
git init --initial-branch "$BRANCH" >/dev/null

AUTHOR_NAME="$(git config --global user.name || true)"
AUTHOR_EMAIL="$(git config --global user.email || true)"

if [[ -z "$AUTHOR_NAME" ]]; then
    AUTHOR_NAME="zkf-metal release bot"
fi
if [[ -z "$AUTHOR_EMAIL" ]]; then
    AUTHOR_EMAIL="release-bot@local"
fi

git add -A
git -c user.name="$AUTHOR_NAME" -c user.email="$AUTHOR_EMAIL" commit -m "Publish zkf-metal artifact release" >/dev/null
git remote add origin "https://github.com/$REPO_SLUG.git"
git push --force --set-upstream origin "$BRANCH" >/dev/null
popd >/dev/null

echo "Published https://github.com/$REPO_SLUG on branch $BRANCH"
