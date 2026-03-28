#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

shard="${1:-}"

run_shard() {
    ./zkf-build.sh test "$@" --no-fail-fast
}

case "$shard" in
    foundations)
        run_shard \
            -p zkf-core \
            -p zkf-crypto-accel \
            -p zkf-gadgets \
            -p zkf-dsl \
            -p zkf-registry \
            -p zkf-ir-spec \
            -p zkf-conformance \
            -p zkf-verify \
            -p zkf-frontend-sdk \
            -p zkf-metal-public-proof-lib \
            -p zk_rollup \
            --all-targets
        ;;
    runtime)
        run_shard \
            -p zkf-frontends \
            -p zkf-runtime \
            -p zkf-metal \
            -p zkf-distributed \
            -p zkf-gpu \
            -p zkf-backends-pro \
            --all-targets
        ;;
    apps)
        run_shard \
            -p zkf-lib \
            -p zkf-api \
            -p zkf-python \
            -p zkf-lsp \
            -p zkf-ui \
            -p zkf-tui \
            -p zkf-ffi \
            -p zkf-examples \
            -p zkf-metal-public-cli \
            --all-targets
        ;;
    backends_core)
        run_shard -p zkf-backends --lib
        for test_name in \
            arkworks_roundtrip \
            blackbox_soundness \
            blackbox_support \
            halo2_roundtrip \
            plonky3_roundtrip \
            verification_prop \
            verifier_integrity
        do
            run_shard -p zkf-backends --test "$test_name"
        done
        ;;
    backends_recursive)
        for test_name in \
            compat_backends_roundtrip \
            midnight_native_runtime \
            midnight_readiness \
            native_zkvm_roundtrip \
            nova_native_roundtrip \
            recursive_aggregation_soundness \
            recursive_integration_hardening
        do
            run_shard -p zkf-backends --test "$test_name"
        done
        ;;
    cli)
        run_shard -p zkf-cli --all-targets
        ;;
    integration)
        run_shard -p zkf-integration-tests --all-targets
        ;;
    *)
        echo "usage: $0 {foundations|runtime|apps|backends_core|backends_recursive|cli|integration}" >&2
        exit 64
        ;;
esac
