# Deployment

This document is the consolidated deployment guide for ZKF operators.

## Scope

This guide covers:

- Supported host assumptions
- Local build and bring-up
- Neural Engine fixture and operator-model installation
- Validation and smoke commands
- Release artifact finalization and rollback

For the wrapping trust model, see
[WRAPPING_SECURITY.md](/Users/sicarii/Projects/ZK DEV/docs/WRAPPING_SECURITY.md).

## Supported Hosts

Primary release lane:

- Apple Silicon M4 Max, 48 GB unified memory
- macOS host with Metal available
- Rust toolchain, Python 3, and the CLI/tooling described below installed

Other hosts can still run ZKF, but:

- strict cryptographic wrapper certification is host-profile specific
- Metal acceleration is macOS-only
- Neural Engine control-plane acceleration is feature-gated and Apple-only

## Required Tooling

Core commands expected on a release host:

- `cargo`
- `rustc`
- `python3`
- `xcrun`
- `nargo`
- `snarkjs`
- `scarb`

Recommended quick health check:

```bash
cargo build --workspace
target/release/zkf-cli metal-doctor --json
```

Strict production readiness check:

```bash
target/release/zkf-cli metal-doctor --strict --json
```

## Build And Install

Build debug and release artifacts from the repo root:

```bash
cargo build --workspace
cargo build --workspace --release
```

Neural Engine fixture model install:

```bash
python3 -m pip install -r scripts/neural_engine_requirements.txt
python3 scripts/build_fixture_neural_models.py --check
python3 scripts/install_fixture_neural_models.py --dest target/coreml
```

Optional operator model install into the user model directory:

```bash
python3 scripts/install_fixture_neural_models.py --dest ~/.zkf/models
```

Model discovery precedence:

1. `ZKF_*_MODEL`
2. `~/.zkf/models/`
3. `target/coreml/`

Repo-local fixture models are deterministic smoke-floor artifacts. Production-tuned models should
be trained from larger telemetry corpora and installed into `~/.zkf/models/` or pinned through
`ZKF_*_MODEL`. Installed production bundles in `~/.zkf/models/` are expected to carry a pinned
manifest and hash-verified sidecars; set `ZKF_ALLOW_UNPINNED_MODELS=1` only for explicit
development bypasses.

Preferred production model refresh:

```bash
python3 scripts/build_control_plane_corpus.py \
  --profile production \
  --out ~/.zkf/models/control_plane_corpus.jsonl \
  --summary-out ~/.zkf/models/control_plane_corpus.summary.json
python3 scripts/train_control_plane_models.py \
  --profile production \
  --model-dir ~/.zkf/models \
  --corpus-out ~/.zkf/models/control_plane_corpus.jsonl \
  --summary-out ~/.zkf/models/control_plane_corpus.summary.json \
  --manifest-out ~/.zkf/models/control_plane_models_manifest.json
```

## Standard Bring-Up

Run the baseline checks in this order:

```bash
cargo build --workspace
cargo build --workspace --release
cargo clippy --workspace -- -D warnings
python3 scripts/check_rustfmt_workspace.py --check
```

Install fixture models and inspect the runtime policy surface:

```bash
python3 scripts/build_fixture_neural_models.py --check
python3 scripts/install_fixture_neural_models.py --dest target/coreml
target/release/zkf-cli runtime policy --objective fastest-prove --json
```

If `neural-engine` is enabled, runtime policy, prove, and fold will consume the same objective-aware
control plane used in production.

## Validation Gates

Whole-workspace release validation:

```bash
python3 scripts/validate_workspace.py
```

Expected success conditions:

- `target/validation/workspace_validation.json` exists
- `summary.passed=true`
- `summary.commands_ok=11`

If the validator fails or stalls, inspect:

- `target/validation/logs/*.stderr.log`
- `target/validation/logs/*.stdout.log`

Do not cut a release bundle until the validator is freshly green.

Post-soak release validation report:

```bash
python3 scripts/run_post_soak_release_checks.py \
  --source-binary /tmp/zkf-certified-release-binary/zkf-cli \
  --out /Users/sicarii/Projects/ZK\ DEV/target/validation/post_soak_release_checks.certified.json \
  --workspace-validation-report /Users/sicarii/Projects/ZK\ DEV/target/validation/workspace_validation.certified.json
```

Run this against the certified binary copy produced by the soak, not the mutable
`target/release/zkf-cli` workspace build. If you intentionally want to validate a different
binary, pass explicit paths and treat that as a separate certification path.

The checker now fails fast if another process already owns the same `--out` path. Concurrent
post-soak validators must use distinct report paths instead of sharing a single output file.

Expected success conditions:

- `target/validation/post_soak_release_checks.certified.json` exists
- `summary.passed=true`
- `strict-metal-doctor`, wrapper smoke, native SP1/RISC Zero matrices, the full feature-enabled
  `zkf-cli` suite, and the workspace validator all completed successfully

If the post-soak checker fails or stalls, inspect:

- `target/validation/post_soak_release_checks.certified.logs/*.stderr.log`
- `target/validation/post_soak_release_checks.certified.logs/*.stdout.log`

## Targeted Runtime Smoke

Native wrapper smoke on the certified host:

```bash
cargo test -p zkf-cli --bin zkf-cli --features metal-gpu,neural-engine cmd::runtime::tests::runtime_execute_native_wrapper_plan_end_to_end -- --ignored --exact --nocapture
```

Treat this as passed only if the wrapper lane completes end to end without a strict Metal health
guard forcing a `cpu-only` fallback.

Additional targeted Neural Engine checks:

```bash
cargo test -p zkf-runtime --lib
cargo test -p zkf-cli --bin zkf-cli
target/release/zkf-cli runtime policy --objective smallest-proof --json
```

## Certification And Release Bundle

The release finalizer uses the existing full bundle flow:

```bash
python3 scripts/finalize_no_dashboard_release.py \
  --bundle-dir /Users/sicarii/Desktop/ZKF-Release-v1.0.0-2026-03-17-NoEmbeddedDashboard \
  --source-binary /tmp/zkf-certified-release-binary/zkf-cli \
  --desktop-binary /Users/sicarii/Desktop/ZKF-Release-v1.0.0-2026-03-17-NoEmbeddedDashboard/bin/zkf-cli \
  --gate-report /tmp/zkf-production-gate-current-binary/strict-certification.json \
  --soak-report /tmp/zkf-production-soak-current-binary/strict-certification.json \
  --soak-progress /tmp/zkf-production-soak-current-binary/soak-progress.json \
  --installed-report /var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/zkf-stark-to-groth16/certification/strict-m4-max.json \
  --workspace-validation-report /Users/sicarii/Projects/ZK\ DEV/target/validation/workspace_validation.certified.json \
  --post-soak-checks-report /Users/sicarii/Projects/ZK\ DEV/target/validation/post_soak_release_checks.certified.json
```

Preflight expectations before running the finalizer:

- the certified soak binary exists at `/tmp/zkf-certified-release-binary/zkf-cli`
- the Desktop bundle binary exists and hash-matches the certified soak binary
- gate report exists
- soak report exists and records a final passing soak for the current binary
- installed strict certification report exists and matches the current binary
- workspace validation report is freshly green
- post-soak checks report is freshly green

If any of those inputs are missing or stale, stop and refresh the missing certification step before
attempting finalization.

## Versioning And Tagging

Release steps after the gates are green:

```bash
cargo build --workspace
cargo build --workspace --release
git tag -a v1.0.0 -m "ZKF v1.0.0"
```

Tagging is local-only in the current release workflow unless an operator intentionally pushes it.

## Rollback

Fast rollback options:

- remove or rename `~/.zkf/models/*.mlpackage`
- remove repo-local installs under `target/coreml/`
- unset any `ZKF_*_MODEL` environment variables
- run without the `neural-engine` feature
- fall back to the last known good release bundle and matching certification artifacts

Rollback does not require changing proof formats. The control plane will fall back to deterministic
heuristics when models are unavailable or rejected.
