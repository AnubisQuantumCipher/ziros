#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${ROOT_DIR}/target-local/release/zkf-cli"
if [[ ! -x "${BIN}" && -x "${ROOT_DIR}/target/release/zkf-cli" ]]; then
    BIN="${ROOT_DIR}/target/release/zkf-cli"
fi
ANE_MODEL="${ROOT_DIR}/target/coreml/zkf-runtime-policy.mlpackage"
PROOF="${ROOT_DIR}/tmp/does-not-exist"
COMPILED="${ROOT_DIR}/tmp/does-not-exist"
OUT_DIR=""

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
info() { echo -e "  ${CYAN}→${NC} $1"; }

usage() {
    cat <<'EOF'
Usage:
  ./setup-metal.sh [--proof <stark-proof.json>] [--compiled <stark-compiled.json>] [--out-dir <dir>] [--bin <zkf-cli>]

Provision the certified Apple Silicon Metal production lane:
  1. Validate platform and toolchain
  2. Build warning-free release zkf-cli with --features metal-gpu
  3. Generate the Core ML / Neural Engine control-plane policy model
  4. Run metal-doctor --json preflight
  5. Prepare the strict direct-wrap cache
  6. Run scripts/production_gate.sh
  7. Run scripts/production_soak.sh
  8. Verify metal-doctor --strict --json after certification

If --proof/--compiled are omitted, the script falls back to:
  /tmp/zkf-demo-full/stark-proof.json
  /tmp/zkf-demo-full/stark-compiled.json
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proof)
            PROOF="$2"
            shift 2
            ;;
        --compiled)
            COMPILED="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --bin)
            BIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ "${PROOF}" == "${ROOT_DIR}/tmp/does-not-exist" ]]; then
    PROOF="/tmp/zkf-demo-full/stark-proof.json"
fi
if [[ "${COMPILED}" == "${ROOT_DIR}/tmp/does-not-exist" ]]; then
    COMPILED="/tmp/zkf-demo-full/stark-compiled.json"
fi
if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zkf-setup-metal.XXXXXX")"
else
    mkdir -p "${OUT_DIR}"
fi

echo -e "${BOLD}ZKF Metal Production Setup${NC}"
echo ""

echo -e "${BOLD}1. Platform${NC}"
if [[ "$(uname)" != "Darwin" ]]; then
    fail "Not macOS"
    exit 1
fi
CHIP="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")"
ok "macOS detected: ${CHIP}"
if ! sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
    fail "Not Apple Silicon"
    exit 1
fi
ok "Apple Silicon confirmed"

echo ""
echo -e "${BOLD}2. Toolchain${NC}"
command -v cargo >/dev/null 2>&1 || { fail "cargo not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { fail "jq not found"; exit 1; }
ok "$(rustc --version 2>/dev/null)"

echo ""
echo -e "${BOLD}3. Release Build${NC}"
info "Building zkf-cli --release --features metal-gpu"
cargo build -p zkf-cli --release --features metal-gpu
if cargo build -p zkf-cli --release --features metal-gpu 2>&1 | rg -q '^warning:'; then
    fail "release build emitted warnings"
    exit 1
fi
ok "Release Metal build is warning-free"

echo ""
echo -e "${BOLD}4. ANE Policy Model${NC}"
mkdir -p "$(dirname "${ANE_MODEL}")"
if [[ -x "${ROOT_DIR}/.venv-coreml/bin/python" ]]; then
    COREML_PYTHON="${ROOT_DIR}/.venv-coreml/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    COREML_PYTHON="$(command -v python3)"
else
    fail "python3 is required to generate the Core ML policy model"
    exit 1
fi
info "Generating Core ML policy model at ${ANE_MODEL}"
"${COREML_PYTHON}" "${ROOT_DIR}/scripts/generate_ane_policy_model.py" --out "${ANE_MODEL}" >/dev/null
ok "Core ML / Neural Engine policy model generated"

info "Refreshing assistant knowledge bundle in ~/Library/Application Support/ZFK/assistant"
"${COREML_PYTHON}" "${ROOT_DIR}/scripts/build_zfk_assistant_bundle.py" >/dev/null
ok "Assistant knowledge bundle refreshed"

echo ""
echo -e "${BOLD}5. Doctor Preflight${NC}"
"${BIN}" metal-doctor --json | tee "${OUT_DIR}/metal-doctor.json" >/dev/null
ok "metal-doctor preflight captured"

echo ""
echo -e "${BOLD}6. Storage Guardian Gate${NC}"
STORAGE_JSON="$("${BIN}" storage doctor --json)"
echo "${STORAGE_JSON}" | tee "${OUT_DIR}/storage-doctor.json" >/dev/null
HEALTH="$(echo "${STORAGE_JSON}" | jq -r '.health_status')"
FREE_GB="$(echo "${STORAGE_JSON}" | jq -r '.available_gb')"
if [[ "${HEALTH}" == "critical" ]]; then
    fail "storage doctor reported critical SSD health"
    exit 1
fi
if awk "BEGIN { exit !(${FREE_GB} < 50) }"; then
    warn "free space below 50 GB; running storage sweep"
    "${BIN}" storage sweep
else
    ok "storage doctor passed (${FREE_GB} GB free)"
fi

if [[ ! -f "${PROOF}" || ! -f "${COMPILED}" ]]; then
    fail "strict provisioning inputs are required; missing proof=${PROOF} or compiled=${COMPILED}"
    exit 1
fi

echo ""
echo -e "${BOLD}7. Strict Cache Prepare${NC}"
"${BIN}" runtime prepare \
    --proof "${PROOF}" \
    --compiled "${COMPILED}" \
    --output "${OUT_DIR}/strict-prepare.json"
ok "Strict direct-wrap cache prepared"

echo ""
echo -e "${BOLD}8. Certified Production Gate${NC}"
"${ROOT_DIR}/scripts/production_gate.sh" \
    --proof "${PROOF}" \
    --compiled "${COMPILED}" \
    --out-dir "${OUT_DIR}/production-gate" \
    --bin "${BIN}"
ok "Certified production gate passed"

echo ""
echo -e "${BOLD}9. Certified Production Soak${NC}"
"${ROOT_DIR}/scripts/production_soak.sh" \
    --proof "${PROOF}" \
    --compiled "${COMPILED}" \
    --out-dir "${OUT_DIR}/production-soak" \
    --json-out "${OUT_DIR}/production-soak/strict-certification.json" \
    --bin "${BIN}"
ok "Certified production soak passed"

echo ""
echo -e "${BOLD}10. Strict Doctor Gate${NC}"
"${BIN}" metal-doctor --strict --json | tee "${OUT_DIR}/metal-doctor-strict.json" >/dev/null
ok "metal-doctor strict gate passed"

echo ""
echo -e "${BOLD}Summary${NC}"
echo "  Device: ${CHIP}"
echo "  Binary: ${BIN}"
echo "  Inputs: ${PROOF} / ${COMPILED}"
echo "  Output: ${OUT_DIR}"
echo "  Dashboard: python3 ${ROOT_DIR}/scripts/system_dashboard_agent.py start --port 8777 --dir /tmp/zkf-production-soak-current --auto-refresh-bundle"
ok "Certified Metal production lane is provisioned."
