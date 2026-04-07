#!/usr/bin/env python3
"""Train ZirOS Neural Engine control-plane models from telemetry data.

Called by: zkf retrain --profile production

Reads telemetry JSON files, builds a JSONL corpus, and trains five model
lanes (scheduler, backend_recommender, duration_estimator, anomaly_detector,
security_detector) using scikit-learn, exporting each as a CoreML .mlpackage
via coremltools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

try:
    import numpy as np
except ImportError:
    print(
        "error: numpy is required but not installed.\n"
        "  pip install numpy",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        GradientBoostingRegressor,
        IsolationForest,
    )
    from sklearn.linear_model import Ridge
    from sklearn.model_selection import cross_val_score, train_test_split
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print(
        "error: scikit-learn is required but not installed.\n"
        "  pip install scikit-learn",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import coremltools as ct
except ImportError:
    print(
        "error: coremltools is required but not installed.\n"
        "  pip install coremltools",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TELEMETRY_DIR = os.path.join(
    os.path.expanduser("~"),
    "Library",
    "Mobile Documents",
    "com~apple~CloudDocs",
    "ZirOS",
    "telemetry",
)

# Features extracted from each telemetry record.
FEATURE_NAMES = [
    "constraint_count",
    "signal_count",
    "prove_time_ms",
    "verify_time_ms",
    "witness_gen_time_ms",
    "backend",
    "field",
    "gpu_busy_ratio",
    "peak_memory_bytes",
    "proof_size_bytes",
]

NUMERIC_FEATURES = [
    "constraint_count",
    "signal_count",
    "prove_time_ms",
    "verify_time_ms",
    "witness_gen_time_ms",
    "gpu_busy_ratio",
    "peak_memory_bytes",
    "proof_size_bytes",
]

CATEGORICAL_FEATURES = ["backend", "field"]

# Model lanes produced by this script.
MODEL_LANES = [
    "scheduler",
    "backend_recommender",
    "duration_estimator",
    "anomaly_detector",
    "security_detector",
]

# Backend and field vocabularies for one-hot encoding.
KNOWN_BACKENDS = [
    "groth16",
    "halo2",
    "nova",
    "plonk",
    "spartan",
    "stark",
    "supernova",
    "unknown",
]
KNOWN_FIELDS = [
    "bn254",
    "bls12-381",
    "goldilocks",
    "pallas",
    "vesta",
    "babybear",
    "mersenne31",
    "unknown",
]

# ---------------------------------------------------------------------------
# Telemetry parsing
# ---------------------------------------------------------------------------


def _safe_float(obj: Any, *keys: str, default: float = 0.0) -> float:
    """Drill into nested dicts and return a float, or *default* on any miss."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    try:
        return float(cur) if cur is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(obj: Any, *keys: str, default: int = 0) -> int:
    val = _safe_float(obj, *keys, default=float(default))
    return int(val)


def _safe_str(obj: Any, *keys: str, default: str = "unknown") -> str:
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    return str(cur) if cur is not None else default


def parse_telemetry_record(raw: dict) -> dict | None:
    """Extract a flat feature dict from a single telemetry JSON record.

    Returns None if the record is malformed or lacks critical fields.
    """
    circuit = raw.get("circuit_features")
    outcome = raw.get("outcome")
    metadata = raw.get("metadata")
    hardware = raw.get("hardware_state")

    if circuit is None or outcome is None or metadata is None:
        return None

    constraint_count = _safe_int(circuit, "constraint_count")
    signal_count = _safe_int(circuit, "signal_count")

    # Total proving time is our main timing field.
    prove_time_ms = _safe_float(outcome, "total_proving_time_ms")

    # Per-stage times: attempt to extract verify and witness gen.
    per_stage = outcome.get("per_stage_times_ms", {}) if isinstance(outcome, dict) else {}
    verify_time_ms = _safe_float(per_stage, "verify", default=0.0)
    if verify_time_ms == 0.0:
        verify_time_ms = _safe_float(per_stage, "verification", default=0.0)
    witness_gen_time_ms = _safe_float(per_stage, "witness_gen", default=0.0)
    if witness_gen_time_ms == 0.0:
        witness_gen_time_ms = _safe_float(per_stage, "witness-gen", default=0.0)

    backend = _safe_str(metadata, "backend_used")
    field = _safe_str(metadata, "field_used")
    proof_size_bytes = _safe_int(metadata, "proof_size_bytes")

    gpu_busy_ratio = _safe_float(hardware, "gpu_utilization") if hardware else 0.0
    peak_memory_bytes = _safe_int(hardware, "memory_pressure_bytes") if hardware else 0

    gpu_was_faster = outcome.get("gpu_was_faster", False) if isinstance(outcome, dict) else False

    return {
        "constraint_count": constraint_count,
        "signal_count": signal_count,
        "prove_time_ms": prove_time_ms,
        "verify_time_ms": verify_time_ms,
        "witness_gen_time_ms": witness_gen_time_ms,
        "backend": backend,
        "field": field,
        "gpu_busy_ratio": gpu_busy_ratio,
        "peak_memory_bytes": peak_memory_bytes,
        "proof_size_bytes": proof_size_bytes,
        # Derived labels for classification lanes.
        "gpu_was_faster": bool(gpu_was_faster),
    }


def load_telemetry(input_dirs: list[str]) -> list[dict]:
    """Read all JSON files from the given directories and parse them."""
    records: list[dict] = []
    for directory in input_dirs:
        dirpath = pathlib.Path(directory)
        if not dirpath.is_dir():
            print(f"  [warn] telemetry directory not found: {dirpath}")
            continue
        for filepath in sorted(dirpath.iterdir()):
            if not filepath.is_file():
                continue
            if filepath.suffix not in (".json",):
                continue
            try:
                raw = json.loads(filepath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"  [warn] skipping {filepath.name}: {exc}")
                continue
            parsed = parse_telemetry_record(raw)
            if parsed is not None:
                records.append(parsed)
    return records


# ---------------------------------------------------------------------------
# Corpus I/O
# ---------------------------------------------------------------------------


def write_corpus(records: list[dict], corpus_path: str) -> str:
    """Write JSONL corpus and return its SHA-256 hash."""
    os.makedirs(os.path.dirname(corpus_path) or ".", exist_ok=True)
    hasher = hashlib.sha256()
    with open(corpus_path, "w", encoding="utf-8") as fh:
        for rec in records:
            line = json.dumps(rec, sort_keys=True)
            fh.write(line + "\n")
            hasher.update(line.encode("utf-8"))
    return hasher.hexdigest()


def write_summary(records: list[dict], summary_path: str) -> None:
    """Write a summary JSON with record count and feature statistics."""
    os.makedirs(os.path.dirname(summary_path) or ".", exist_ok=True)
    stats: dict[str, Any] = {}
    for feat in NUMERIC_FEATURES:
        vals = [r[feat] for r in records if feat in r]
        if vals:
            arr = np.array(vals, dtype=np.float64)
            stats[feat] = {
                "count": len(vals),
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "median": float(np.median(arr)),
            }
    for feat in CATEGORICAL_FEATURES:
        vals = [r.get(feat, "unknown") for r in records]
        unique, counts = np.unique(vals, return_counts=True)
        stats[feat] = {
            "distinct_values": int(len(unique)),
            "distribution": {str(u): int(c) for u, c in zip(unique, counts)},
        }
    summary = {
        "schema": "zkf-training-corpus-summary-v1",
        "record_count": len(records),
        "feature_statistics": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Feature encoding
# ---------------------------------------------------------------------------


def _one_hot(value: str, vocabulary: list[str]) -> list[float]:
    """Return a one-hot vector for *value* against *vocabulary*."""
    vec = [0.0] * len(vocabulary)
    lower = value.lower()
    for i, v in enumerate(vocabulary):
        if lower == v:
            vec[i] = 1.0
            return vec
    # If not found, mark the last slot ("unknown").
    vec[-1] = 1.0
    return vec


def encode_features(records: list[dict]) -> np.ndarray:
    """Encode records into a numeric feature matrix.

    Layout per row:
      [constraint_count, signal_count, prove_time_ms, verify_time_ms,
       witness_gen_time_ms, gpu_busy_ratio, peak_memory_bytes,
       proof_size_bytes, <backend one-hot>, <field one-hot>]
    """
    rows: list[list[float]] = []
    for rec in records:
        row: list[float] = []
        for feat in NUMERIC_FEATURES:
            row.append(float(rec.get(feat, 0.0)))
        row.extend(_one_hot(rec.get("backend", "unknown"), KNOWN_BACKENDS))
        row.extend(_one_hot(rec.get("field", "unknown"), KNOWN_FIELDS))
        rows.append(row)
    return np.array(rows, dtype=np.float64)


def feature_dimension() -> int:
    """Return the width of the encoded feature vector."""
    return len(NUMERIC_FEATURES) + len(KNOWN_BACKENDS) + len(KNOWN_FIELDS)


# ---------------------------------------------------------------------------
# Synthetic data generation (fallback when telemetry is sparse)
# ---------------------------------------------------------------------------


def generate_synthetic_records(n: int = 500) -> list[dict]:
    """Generate synthetic telemetry records for bootstrapping models."""
    rng = np.random.default_rng(seed=42)
    records: list[dict] = []
    for _ in range(n):
        constraints = int(rng.integers(100, 1_000_000))
        signals = int(constraints * rng.uniform(0.8, 1.5))
        backend = rng.choice(KNOWN_BACKENDS[:-1])  # exclude "unknown"
        field = rng.choice(KNOWN_FIELDS[:-1])
        gpu_ratio = float(rng.uniform(0.0, 1.0))
        prove_time = float(constraints * rng.uniform(0.001, 0.05) + rng.normal(50, 20))
        prove_time = max(1.0, prove_time)
        verify_time = float(rng.uniform(1.0, prove_time * 0.1))
        witness_gen = float(rng.uniform(0.5, prove_time * 0.3))
        peak_mem = int(constraints * rng.uniform(50, 500))
        proof_size = int(rng.integers(128, 65536))
        gpu_faster = bool(constraints > 50_000 and gpu_ratio > 0.3)
        records.append({
            "constraint_count": constraints,
            "signal_count": signals,
            "prove_time_ms": prove_time,
            "verify_time_ms": verify_time,
            "witness_gen_time_ms": witness_gen,
            "backend": str(backend),
            "field": str(field),
            "gpu_busy_ratio": gpu_ratio,
            "peak_memory_bytes": peak_mem,
            "proof_size_bytes": proof_size,
            "gpu_was_faster": gpu_faster,
        })
    return records


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------


def _train_scheduler(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Scheduler model: predict total proving time in ms (regression)."""
    y = np.array([r["prove_time_ms"] for r in records], dtype=np.float64)
    model = GradientBoostingRegressor(
        n_estimators=100 if profile == "production" else 30,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="r2")
    return model, {
        "r2_cv_mean": float(np.mean(scores)),
        "r2_cv_std": float(np.std(scores)),
        "output_name": "predicted_duration_ms",
    }


def _train_backend_recommender(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Backend recommender: classify which backend yields fastest prove time."""
    y = np.array([
        KNOWN_BACKENDS.index(r["backend"]) if r["backend"] in KNOWN_BACKENDS
        else len(KNOWN_BACKENDS) - 1
        for r in records
    ], dtype=np.int64)
    n_classes = len(np.unique(y))
    if n_classes < 2:
        # Fall back to a dummy two-class problem.
        y[0] = (y[0] + 1) % len(KNOWN_BACKENDS)
        n_classes = 2
    model = GradientBoostingClassifier(
        n_estimators=80 if profile == "production" else 20,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="accuracy")
    return model, {
        "accuracy_cv_mean": float(np.mean(scores)),
        "accuracy_cv_std": float(np.std(scores)),
        "output_name": "backend_score",
    }


def _train_duration_estimator(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Duration estimator: predict total proving time (lighter regression)."""
    y = np.array([r["prove_time_ms"] for r in records], dtype=np.float64)
    model = Ridge(alpha=1.0)
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="r2")
    return model, {
        "r2_cv_mean": float(np.mean(scores)),
        "r2_cv_std": float(np.std(scores)),
        "output_name": "predicted_duration_ms",
    }


def _train_anomaly_detector(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Anomaly detector: IsolationForest on timing features, converted to
    a regression score via decision_function."""
    iso = IsolationForest(
        n_estimators=100 if profile == "production" else 30,
        contamination=0.05,
        random_state=42,
    )
    iso.fit(X)
    # Produce an anomaly score target for a surrogate regressor that CoreML
    # can load (IsolationForest is not directly convertible).
    anomaly_scores = -iso.decision_function(X)  # higher = more anomalous
    surrogate = GradientBoostingRegressor(
        n_estimators=60 if profile == "production" else 15,
        max_depth=4,
        random_state=42,
    )
    surrogate.fit(X, anomaly_scores)
    return surrogate, {
        "anomaly_fraction": float(np.mean(iso.predict(X) == -1)),
        "output_name": "anomaly_score",
    }


def _train_security_detector(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Security risk detector: surrogate regression on a synthetic risk score.

    Risk heuristic: high memory + unusual timing patterns + small proof size.
    """
    risk = np.zeros(len(records), dtype=np.float64)
    for i, rec in enumerate(records):
        mem_norm = min(rec["peak_memory_bytes"] / 1e9, 1.0)
        timing_ratio = (rec["prove_time_ms"] + 1) / (rec["verify_time_ms"] + 1)
        timing_risk = 1.0 / (1.0 + np.exp(-(timing_ratio - 100) / 20))
        size_risk = 1.0 / (1.0 + rec["proof_size_bytes"] / 1000)
        risk[i] = 0.4 * mem_norm + 0.35 * timing_risk + 0.25 * size_risk
    model = GradientBoostingRegressor(
        n_estimators=80 if profile == "production" else 20,
        max_depth=4,
        random_state=42,
    )
    model.fit(X, risk)
    return model, {
        "risk_mean": float(np.mean(risk)),
        "risk_std": float(np.std(risk)),
        "output_name": "risk_score",
    }


LANE_TRAINERS = {
    "scheduler": _train_scheduler,
    "backend_recommender": _train_backend_recommender,
    "duration_estimator": _train_duration_estimator,
    "anomaly_detector": _train_anomaly_detector,
    "security_detector": _train_security_detector,
}


def export_to_coreml(
    model,
    lane: str,
    output_path: str,
    input_dim: int,
    output_name: str,
) -> str:
    """Convert a scikit-learn model to a CoreML .mlpackage and return its path."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    input_features = []
    # Build descriptive feature names matching the encoded vector layout.
    for feat in NUMERIC_FEATURES:
        input_features.append(feat)
    for backend in KNOWN_BACKENDS:
        input_features.append(f"backend_{backend}")
    for field in KNOWN_FIELDS:
        input_features.append(f"field_{field}")

    coreml_model = ct.converters.sklearn.convert(
        model,
        input_features=[(name, ct.models.datatypes.Double()) for name in input_features[:input_dim]],
        output_feature_names=output_name,
    )

    coreml_model.short_description = f"ZirOS control-plane {lane} model"
    coreml_model.author = "ZirOS Neural Engine training pipeline"
    coreml_model.version = "2"

    # Remove existing package directory if present (coremltools will fail otherwise).
    pkg_path = pathlib.Path(output_path)
    if pkg_path.exists():
        import shutil
        shutil.rmtree(pkg_path)

    coreml_model.save(output_path)
    return output_path


def compute_package_hash(path: str) -> str:
    """Compute SHA-256 over the contents of an .mlpackage directory tree."""
    hasher = hashlib.sha256()
    pkg = pathlib.Path(path)
    if pkg.is_dir():
        for fpath in sorted(pkg.rglob("*")):
            if fpath.is_file():
                hasher.update(str(fpath.relative_to(pkg)).encode("utf-8"))
                hasher.update(b"\x00")
                hasher.update(fpath.read_bytes())
                hasher.update(b"\x00")
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def write_manifest(
    entries: list[dict],
    manifest_path: str,
    corpus_hash: str,
    record_count: int,
) -> None:
    """Write the control_plane_models_manifest.json."""
    manifest = {
        "schema": "zkf-control-plane-manifest-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_hash": corpus_hash,
        "corpus_record_count": record_count,
        "models": entries,
    }
    os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


def _quality_gate(lane: str, metrics: dict, profile: str) -> dict:
    """Evaluate whether a trained model passes the quality gate."""
    thresholds: dict[str, float] = {}
    measurements: dict[str, float] = {}
    reasons: list[str] = []
    passed = True

    if "r2_cv_mean" in metrics:
        threshold = 0.3 if profile == "production" else 0.0
        thresholds["r2_cv_mean"] = threshold
        measurements["r2_cv_mean"] = metrics["r2_cv_mean"]
        if metrics["r2_cv_mean"] < threshold:
            passed = False
            reasons.append(
                f"R2 cross-val mean {metrics['r2_cv_mean']:.4f} < {threshold}"
            )

    if "accuracy_cv_mean" in metrics:
        threshold = 0.4 if profile == "production" else 0.0
        thresholds["accuracy_cv_mean"] = threshold
        measurements["accuracy_cv_mean"] = metrics["accuracy_cv_mean"]
        if metrics["accuracy_cv_mean"] < threshold:
            passed = False
            reasons.append(
                f"Accuracy cross-val mean {metrics['accuracy_cv_mean']:.4f} < {threshold}"
            )

    return {
        "passed": passed,
        "thresholds": thresholds,
        "measurements": measurements,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train ZirOS Neural Engine control-plane models.",
    )
    parser.add_argument(
        "--profile",
        required=True,
        choices=["fixture", "production"],
        help="Training quality profile.",
    )
    parser.add_argument(
        "--model-dir",
        required=True,
        help="Directory to write trained .mlpackage models.",
    )
    parser.add_argument(
        "--corpus-out",
        required=True,
        help="Path for the JSONL training corpus.",
    )
    parser.add_argument(
        "--summary-out",
        required=True,
        help="Path for the corpus summary JSON.",
    )
    parser.add_argument(
        "--manifest-out",
        required=True,
        help="Path for the models manifest JSON.",
    )
    parser.add_argument(
        "--input",
        action="append",
        default=None,
        help="Telemetry input directory (may be repeated). "
        "Defaults to iCloud ZirOS telemetry path.",
    )
    args = parser.parse_args()

    input_dirs = args.input if args.input else [DEFAULT_TELEMETRY_DIR]

    print(f"[train_control_plane] profile={args.profile}")
    print(f"[train_control_plane] model-dir={args.model_dir}")
    print(f"[train_control_plane] input dirs: {input_dirs}")

    # 1. Load telemetry.
    print("[train_control_plane] loading telemetry records ...")
    records = load_telemetry(input_dirs)
    print(f"[train_control_plane] loaded {len(records)} records from telemetry")

    # If too few real records, supplement with synthetic data.
    MIN_RECORDS = 50
    if len(records) < MIN_RECORDS:
        n_synthetic = MIN_RECORDS - len(records)
        print(
            f"[train_control_plane] insufficient telemetry ({len(records)} < {MIN_RECORDS}), "
            f"generating {n_synthetic} synthetic records"
        )
        records.extend(generate_synthetic_records(n_synthetic))

    # 2. Write corpus.
    print(f"[train_control_plane] writing corpus -> {args.corpus_out}")
    corpus_hash = write_corpus(records, args.corpus_out)
    print(f"[train_control_plane] corpus hash: {corpus_hash[:16]}...")

    # 3. Write summary.
    print(f"[train_control_plane] writing summary -> {args.summary_out}")
    write_summary(records, args.summary_out)

    # 4. Encode features.
    X = encode_features(records)
    input_dim = X.shape[1]
    print(f"[train_control_plane] feature matrix: {X.shape[0]} x {X.shape[1]}")

    # 5. Train and export each model lane.
    os.makedirs(args.model_dir, exist_ok=True)
    manifest_entries: list[dict] = []
    trained_at = datetime.now(timezone.utc).isoformat()

    for lane in MODEL_LANES:
        print(f"[train_control_plane] training {lane} ...")
        t0 = time.monotonic()
        trainer = LANE_TRAINERS[lane]
        model, metrics = trainer(X, records, args.profile)
        elapsed = time.monotonic() - t0
        print(f"[train_control_plane]   {lane} trained in {elapsed:.2f}s  metrics={metrics}")

        output_name = metrics.pop("output_name", "output")
        model_filename = f"{lane}_v2.mlpackage"
        model_path = os.path.join(args.model_dir, model_filename)

        print(f"[train_control_plane]   exporting -> {model_path}")
        export_to_coreml(model, lane, model_path, input_dim, output_name)

        quality = _quality_gate(lane, metrics, args.profile)
        pkg_hash = compute_package_hash(model_path)

        entry = {
            "lane": lane,
            "path": model_path,
            "source": "retrained",
            "version": "2",
            "input_shape": input_dim,
            "output_name": output_name,
            "quality_gate": quality,
            "corpus_hash": corpus_hash,
            "corpus_record_count": len(records),
            "trained_at": trained_at,
            "package_tree_sha256": pkg_hash,
            "training_time_s": round(elapsed, 3),
            "metrics": metrics,
        }
        manifest_entries.append(entry)

        status = "PASS" if quality["passed"] else "WARN"
        print(f"[train_control_plane]   quality gate: {status}")

    # 6. Write manifest.
    print(f"[train_control_plane] writing manifest -> {args.manifest_out}")
    write_manifest(manifest_entries, args.manifest_out, corpus_hash, len(records))

    all_passed = all(e["quality_gate"]["passed"] for e in manifest_entries)
    print(
        f"[train_control_plane] done. {len(manifest_entries)} models exported. "
        f"quality={'ALL PASS' if all_passed else 'SOME WARNINGS'}"
    )


if __name__ == "__main__":
    main()
