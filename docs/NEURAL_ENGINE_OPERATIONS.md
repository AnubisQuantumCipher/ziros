# Neural Engine Operations

This is the authoritative operator runbook for the ZKF Neural Engine control plane.

## Scope

- Control-plane only. Core ML / ANE never executes proof arithmetic.
- Runtime lanes (6 total):
  - dispatch-plan scheduler
  - backend recommender
  - duration estimator
  - anomaly detector
  - security detector
  - threshold optimizer (GPU-vs-CPU crossover prediction)
- Runtime failure policy is split by responsibility:
  - optimization lanes fail open to the existing heuristic path
  - security detector may be missing and the deterministic supervisor still enforces policy
  - model-integrity failures quarantine the affected model and fall back to heuristics
  - proof generation and verification semantics stay unchanged
- Enforcement boundary:
  - Neural Engine lanes are advisory only
  - deterministic security policy is authoritative
  - do not describe the system as impenetrable, unhackable, or AI-secured
- Hard backend validity checks stay outside model scoring:
  - field/program incompatible backends are removed before final selection
  - host-unready backends are removed when compatible ready alternatives exist
  - `no-trusted-setup` removes trusted-setup backends when transparent alternatives exist

## Model Classes

- Fixture models:
  - committed deterministic smoke/reproducibility artifacts
  - live under `zkf-runtime/tests/fixtures/neural_engine/models/`
  - shipped with sidecars and `zkf-runtime/tests/fixtures/neural_engine/fixture_manifest.json`
  - built from a deterministic forty-eight-record fixture matrix that covers multiple backends,
    multiple dispatch candidates, and degraded anomaly cases across prove/fold/wrap jobs
- Production models:
  - operator-generated from larger telemetry corpora
  - installed into `~/.zkf/models/` or pointed to with explicit env vars
  - override fixture installs through the same discovery precedence

## Model Discovery

For each lane the runtime resolves models in this order:

1. Explicit environment variable
2. `~/.zkf/models/<lane>.mlpackage`
3. `target/coreml/<lane>.mlpackage`

Environment variables:

- `ZKF_SCHEDULER_MODEL`
- `ZKF_BACKEND_RECOMMENDER_MODEL`
- `ZKF_DURATION_ESTIMATOR_MODEL`
- `ZKF_ANOMALY_DETECTOR_MODEL`
- `ZKF_SECURITY_DETECTOR_MODEL`
- `ZKF_THRESHOLD_OPTIMIZER_MODEL`

Compatibility env var:

- `ZKF_ANE_POLICY_MODEL`
  - Scheduler-only legacy alias

Expected package names (v2 preferred, v1 accepted):

- `scheduler_v2.mlpackage` / `scheduler_v1.mlpackage`
- `backend_recommender_v2.mlpackage` / `backend_recommender_v1.mlpackage`
- `duration_estimator_v2.mlpackage` / `duration_estimator_v1.mlpackage`
- `anomaly_detector_v2.mlpackage` / `anomaly_detector_v1.mlpackage`
- `security_detector_v2.mlpackage` / `security_detector_v1.mlpackage`
- `threshold_optimizer_v1.mlpackage`

Each exported model should have a sibling sidecar at `<model>.json` with schema fingerprint, input
shape, output name, lane semantics, metrics, and a `quality_gate`.

Auto-discovered models from `~/.zkf/models/` and `target/coreml/` are accepted only when the
sidecar schema matches and the `quality_gate.passed` flag is true. Installed production models in
`~/.zkf/models/` now also require a pinned bundle manifest with package-tree and sidecar hashes
unless `ZKF_ALLOW_UNPINNED_MODELS=1` is explicitly set for development. Explicit `ZKF_*_MODEL`
paths may omit the sidecar for local development, but a present sidecar marked failed is still
rejected.

Quarantine lifecycle:

- quarantined model markers live under `~/.zkf/security/quarantine/`
- high-risk runtime incidents live under `~/.zkf/security/events/`
- a quarantined model remains blocked until the bundle is replaced or the operator explicitly
  removes the quarantine marker after inspection

The fixture manifest records:

- lane
- version
- schema fingerprint
- input shape
- corpus hash
- lane semantics
- trainer/tool versions
- exported metrics
- quality gate thresholds and measurements

## Fixture Models

Install the pinned Python dependencies first:

```bash
python3 -m pip install -r scripts/neural_engine_requirements.txt
```

Rebuild all committed fixture models plus sidecars and manifest:

```bash
python3 scripts/build_fixture_neural_models.py
```

Verify the committed fixture models are still deterministic:

```bash
python3 scripts/build_fixture_neural_models.py --check
```

Install the committed fixture models into repo-local discovery:

```bash
python3 scripts/install_fixture_neural_models.py --dest target/coreml
```

Install the same fixture models into the user model directory:

```bash
python3 scripts/install_fixture_neural_models.py --dest ~/.zkf/models
```

## Training

Build a normalized corpus:

```bash
python3 scripts/build_control_plane_corpus.py --out ~/.zkf/models/control_plane_corpus.jsonl
```

For a production-ready corpus, require broad live coverage instead of the deterministic fixture floor:

```bash
python3 scripts/build_control_plane_corpus.py \
  --profile production \
  --out ~/.zkf/models/control_plane_corpus.jsonl \
  --summary-out ~/.zkf/models/control_plane_corpus.summary.json
```

The production profile currently fails closed unless the corpus contains at least:

- 500 total records
- 350 live records
- 100 distinct scenarios
- coverage for `prove`, `fold`, and `wrap`
- coverage for `fastest-prove`, `smallest-proof`, and `no-trusted-setup`
- at least 6 backends across at least 3 fields
- both nominal and degraded hardware states
- no more than 25% fixture-derived rows

Train the six model lanes:

```bash
python3 scripts/train_scheduler_model.py --out ~/.zkf/models/scheduler_v1.mlpackage
python3 scripts/train_backend_recommender.py --out ~/.zkf/models/backend_recommender_v1.mlpackage
python3 scripts/train_duration_estimator.py --out ~/.zkf/models/duration_estimator_v1.mlpackage
python3 scripts/train_anomaly_detector.py --out ~/.zkf/models/anomaly_detector_v1.mlpackage
python3 scripts/train_security_detector.py --out ~/.zkf/models/security_detector_v1.mlpackage
python3 scripts/train_threshold_optimizer.py --out ~/.zkf/models/threshold_optimizer_v1.mlpackage
```

Preferred production path (Python scripts):

```bash
python3 scripts/train_control_plane_models.py \
  --profile production \
  --model-dir ~/.zkf/models \
  --corpus-out ~/.zkf/models/control_plane_corpus.jsonl \
  --summary-out ~/.zkf/models/control_plane_corpus.summary.json \
  --manifest-out ~/.zkf/models/control_plane_models_manifest.json
```

Preferred production path (CLI):

```bash
zkf retrain --profile production
```

The `zkf retrain` command wraps `train_control_plane_models.py` (5 core lanes including security)
and `train_threshold_optimizer.py` (6th lane). Use `--skip-threshold-optimizer` to skip the 6th
lane.
Use `--json` for machine-readable output.

This writes the normalized corpus, validates coverage, retrains all six lanes, and emits
`~/.zkf/models/control_plane_models_manifest.json` with per-lane hashes, quality gates, and the
validated corpus summary.

Legacy compatibility:

```bash
python3 scripts/generate_ane_policy_model.py --out ~/.zkf/models/scheduler_v1.mlpackage
```

Production operators should treat the repo fixture models as a smoke floor only. For release or
host tuning, rebuild from fresh telemetry and install the resulting five `.mlpackage` bundles into
`~/.zkf/models/` or set `ZKF_*_MODEL` explicitly. Do not call the Neural Engine lane
production-ready while the installed models are still only fixture-trained.

`zkf runtime policy` now uses the same field-aware default backend candidate set as runtime
prove/fold auto-selection. If a model-ranked backend is filtered out by a hard constraint, the
decision records that override in `backend_recommendation.notes` and the top-level report notes.

## Feature Vector Versions

The control-plane feature vector has two versions:

- **v1** (47 elements): Circuit profile, BlackBox ratios, stage ratios, hardware state,
  job/objective/dispatch/backend one-hot encodings. No platform awareness.
- **v2** (57 elements): v1 plus 10 platform-specific features: chip generation score, GPU cores
  normalized, ANE TOPS normalized, battery present, on external power, low power mode, and form
  factor one-hot (desktop, laptop, mobile, headset).

The `predict_numeric` function dispatches to v1 or v2 builder based on the model sidecar's
`input_shape` field. v1 models (47 features) work with v2 code; v2 models (57 features) are
rejected when the sidecar declares 57 inputs but the code only knows 47.

The threshold optimizer lane uses a separate 12-element feature vector with platform and workload
features only (no circuit-specific or one-hot encoding features).

## Telemetry and Retraining

Telemetry records (schema `zkf-telemetry-v4`) include:

- Full `PlatformCapability` snapshot
- Watchdog alerts emitted during the proving job
- Adaptive tuning status (learned thresholds, observation counts)
- Control-plane execution summary
- Security verdict + model-integrity summary
- Telemetry sequence id and replay-guard material
- Feature vector version

Inspect corpus state:

```bash
zkf telemetry stats
zkf telemetry stats --json
```

Export anonymized telemetry for cross-device aggregation:

```bash
zkf telemetry export
zkf telemetry export --out /path/to/output.jsonl
```

The export strips model identifiers, machine names, chip names, and timestamps. No secrets
(witnesses, proofs, program content) are included.

## Model Freshness

On model discovery, the control plane compares each model's sidecar `corpus_hash` against the
current telemetry corpus hash. When the corpus has changed since the model was trained, a
`freshness_notice` is emitted suggesting `zkf retrain`. This appears in logs and in the model
catalog metadata.

## Adaptive Tuning Integration

The 6th model lane (threshold optimizer) works alongside the EMA-based adaptive threshold learning
system. See [ADAPTIVE_TUNING.md](ADAPTIVE_TUNING.md) for details on convergence, runtime bias,
persistence, and the `ZKF_STATIC_THRESHOLDS=1` override.

## Validation

Validate the native runtime path with committed fixture models:

```bash
python3 scripts/build_fixture_neural_models.py --check
python3 scripts/install_fixture_neural_models.py --dest target/coreml
cargo run -p zkf-cli --features metal-gpu,neural-engine -- runtime policy --objective smallest-proof --trace /tmp/zkf-wrapper.trace.json --json
```

Inspect the runtime decision surface:

```bash
cargo run -p zkf-cli --features metal-gpu,neural-engine -- runtime policy --trace /tmp/zkf-wrapper.trace.json --json
```

Prove with backend auto-selection:

```bash
cargo run -p zkf-cli --features metal-gpu,neural-engine -- prove --program program.json --inputs inputs.json --backend auto --objective no-trusted-setup --out proof.json
```

Fold with backend auto-selection:

```bash
cargo run -p zkf-cli --features metal-gpu,neural-engine -- fold --manifest package.json --inputs inputs.json --steps 8 --objective fastest-prove --json
```

Recommended validation sweep after model refresh:

```bash
cargo test -p zkf-runtime --lib
cargo test -p zkf-cli --bin zkf-cli
cargo build --workspace
cargo build --workspace --release
cargo clippy --workspace -- -D warnings
python3 scripts/check_rustfmt_workspace.py --check
cargo test --workspace --all-targets
python3 scripts/validate_workspace.py
```

## Runtime Outputs

The runtime and proof metadata now record:

- requested optimization objective
- chosen dispatch plan
- candidate rankings
- backend recommendation
- predicted duration
- anomaly baseline and observed anomaly verdict
- model catalog metadata
- realized GPU-capable stage set

Telemetry is written per job to `~/.zkf/telemetry/*.json`.

## Rollback

Fast rollback options:

1. Remove or rename the model packages in `~/.zkf/models/`
2. Unset the model env vars
3. Run without `neural-engine`

The runtime will fall back to the heuristic scheduler/backend path automatically.

## Release Checklist

Before calling the Neural Engine lane release-ready:

1. Rebuild fixture models with `python3 scripts/build_fixture_neural_models.py`.
2. Verify determinism with `python3 scripts/build_fixture_neural_models.py --check`.
3. Install fixture models into `target/coreml` and run the macOS native-loading tests.
4. Confirm the fixture manifest and sidecars still match the committed hashes/schema.
5. Run the full validation sweep above.

## Historical Reports

`docs/ZKF_NEURAL_ENGINE_REPORT.md` is historical analysis. This runbook, the CLI docs, and the README are the operational source of truth.
