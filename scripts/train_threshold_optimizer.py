#!/usr/bin/env python3
"""Train ZirOS threshold optimizer model for GPU dispatch decisions.

Called by: zkf retrain --profile production

Reads telemetry JSON files, builds a dataset of constraint-count vs.
GPU-beneficial observations, and trains a model that predicts the
constraint count at which GPU dispatch becomes worthwhile.  The result
is exported as a CoreML .mlpackage suitable for the ZirOS runtime
Neural Engine control plane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import shutil
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
    from sklearn.ensemble import GradientBoostingRegressor
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
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

# Runtime-native threshold optimizer input vector. This must stay aligned with
# `threshold_optimizer_feature_labels()` in `zkf-runtime/src/control_plane.rs`.
THRESHOLD_FEATURES = [
    "chip_generation_norm",
    "gpu_cores_norm",
    "ane_tops_norm",
    "battery_present",
    "on_external_power",
    "low_power_mode",
    "form_factor_desktop",
    "form_factor_laptop",
    "form_factor_mobile",
    "form_factor_headset",
    "stage_node_count_log2_norm",
    "constraint_count_log2_norm",
]

THRESHOLD_SCHEMA = "zkf-neural-threshold-optimizer-v1"
COREML_INPUT_NAME = "features"


RAW_THRESHOLD_FIELDS = [
    "constraint_count",
    "signal_count",
    "gpu_busy_ratio",
    "peak_memory_bytes",
    "prove_time_ms",
    "verify_time_ms",
    "witness_gen_time_ms",
    "proof_size_bytes",
    "max_constraint_degree",
    "witness_size",
    "cpu_nodes",
    "gpu_nodes",
]


# ---------------------------------------------------------------------------
# Telemetry parsing
# ---------------------------------------------------------------------------


def _safe_float(obj: Any, *keys: str, default: float = 0.0) -> float:
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
    return int(_safe_float(obj, *keys, default=float(default)))


def _safe_dict(obj: Any, *keys: str) -> dict:
    cur = obj
    for key in keys:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return {}
    return cur if isinstance(cur, dict) else {}


def _safe_bool(obj: Any, *keys: str, default: bool = False) -> bool:
    cur = obj
    for key in keys:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
    if isinstance(cur, bool):
        return cur
    if isinstance(cur, str):
        return cur.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(cur, (int, float)):
        return cur != 0
    return default


def _safe_str(obj: Any, *keys: str, default: str = "unknown") -> str:
    cur = obj
    for key in keys:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
    return str(cur) if cur is not None else default


def _normalized_log2(value: float, max_log2: float) -> float:
    if value <= 0:
        return 0.0
    return float(min(max(math.log2(value + 1.0) / max_log2, 0.0), 1.0))


def _chip_generation_norm(chip_family: str) -> float:
    return {
        "m1": 0.25,
        "m2": 0.50,
        "vision-pro": 0.50,
        "m3": 0.75,
        "m4": 1.00,
        "a17-pro": 0.90,
        "a18": 0.95,
        "a18-pro": 1.00,
    }.get(chip_family, 0.60)


def schema_fingerprint(labels: list[str]) -> str:
    hasher = hashlib.sha256()
    for label in labels:
        hasher.update(label.encode("utf-8"))
        hasher.update(b"\x00")
    return hasher.hexdigest()


def parse_record(raw: dict) -> dict | None:
    """Extract threshold-relevant features from a telemetry JSON record."""
    if "constraint_count" in raw and "prove_time_ms" in raw:
        constraints = _safe_int(raw, "constraint_count")
        signals = _safe_int(raw, "signal_count", default=constraints)
        return {
            "constraint_count": constraints,
            "signal_count": signals,
            "gpu_busy_ratio": _safe_float(raw, "gpu_busy_ratio"),
            "peak_memory_bytes": _safe_int(raw, "peak_memory_bytes"),
            "prove_time_ms": _safe_float(raw, "prove_time_ms"),
            "verify_time_ms": _safe_float(raw, "verify_time_ms"),
            "witness_gen_time_ms": _safe_float(raw, "witness_gen_time_ms"),
            "proof_size_bytes": _safe_int(raw, "proof_size_bytes"),
            "max_constraint_degree": _safe_int(raw, "max_constraint_degree", default=2),
            "witness_size": _safe_int(raw, "witness_size", default=signals),
            "cpu_nodes": _safe_int(raw, "cpu_nodes", default=1),
            "gpu_nodes": _safe_int(raw, "gpu_nodes", default=0),
            "chip_family": _safe_str(raw, "chip_family", default="m4"),
            "gpu_core_count": _safe_int(raw, "gpu_core_count", default=40),
            "ane_tops": _safe_float(raw, "ane_tops", default=38.0),
            "battery_present": _safe_bool(raw, "battery_present", default=True),
            "on_external_power": _safe_bool(raw, "on_external_power", default=True),
            "low_power_mode": _safe_bool(raw, "low_power_mode", default=False),
            "form_factor": _safe_str(raw, "form_factor", default="laptop"),
            "stage_node_count": _safe_int(
                raw,
                "stage_node_count",
                default=_safe_int(raw, "cpu_nodes", default=1)
                + _safe_int(raw, "gpu_nodes", default=0),
            ),
            "gpu_was_faster": _safe_bool(raw, "gpu_was_faster"),
        }

    circuit = raw.get("circuit_features")
    outcome = raw.get("outcome")
    metadata = raw.get("metadata")
    hardware = raw.get("hardware_state")
    control_plane_features = _safe_dict(raw, "control_plane", "decision", "features")

    if circuit is None or outcome is None:
        return None

    constraint_count = _safe_int(circuit, "constraint_count")
    signal_count = _safe_int(circuit, "signal_count")
    max_constraint_degree = _safe_int(circuit, "max_constraint_degree", default=2)
    witness_size = _safe_int(circuit, "witness_size")

    prove_time_ms = _safe_float(outcome, "total_proving_time_ms")
    gpu_was_faster = outcome.get("gpu_was_faster", False) if isinstance(outcome, dict) else False

    per_stage = outcome.get("per_stage_times_ms", {}) if isinstance(outcome, dict) else {}
    verify_time_ms = _safe_float(per_stage, "verify", default=0.0)
    if verify_time_ms == 0.0:
        verify_time_ms = _safe_float(per_stage, "verification", default=0.0)
    witness_gen_time_ms = _safe_float(per_stage, "witness_gen", default=0.0)
    if witness_gen_time_ms == 0.0:
        witness_gen_time_ms = _safe_float(per_stage, "witness-gen", default=0.0)

    gpu_busy_ratio = _safe_float(hardware, "gpu_utilization") if hardware else 0.0
    peak_memory_bytes = _safe_int(hardware, "memory_pressure_bytes") if hardware else 0
    proof_size_bytes = _safe_int(metadata, "proof_size_bytes") if metadata else 0

    # Node counts from the dispatch config, if available.
    dispatch = raw.get("dispatch_config", {})
    gpu_nodes = len(dispatch.get("stages_on_gpu", [])) if isinstance(dispatch, dict) else 0
    cpu_nodes = len(dispatch.get("stages_on_cpu", [])) if isinstance(dispatch, dict) else 0
    stage_node_counts = _safe_dict(control_plane_features, "stage_node_counts")
    if not stage_node_counts and isinstance(dispatch, dict):
        stage_node_counts = dispatch.get("batch_sizes", {})
    if not isinstance(stage_node_counts, dict):
        stage_node_counts = {}

    return {
        "constraint_count": constraint_count,
        "signal_count": signal_count,
        "gpu_busy_ratio": gpu_busy_ratio,
        "peak_memory_bytes": peak_memory_bytes,
        "prove_time_ms": prove_time_ms,
        "verify_time_ms": verify_time_ms,
        "witness_gen_time_ms": witness_gen_time_ms,
        "proof_size_bytes": proof_size_bytes,
        "max_constraint_degree": max_constraint_degree,
        "witness_size": witness_size,
        "cpu_nodes": cpu_nodes,
        "gpu_nodes": gpu_nodes,
        "chip_family": _safe_str(control_plane_features, "chip_family", default="m4"),
        "gpu_core_count": _safe_int(control_plane_features, "gpu_core_count", default=40),
        "ane_tops": _safe_float(control_plane_features, "ane_tops", default=38.0),
        "battery_present": _safe_bool(control_plane_features, "battery_present", default=True),
        "on_external_power": _safe_bool(control_plane_features, "on_external_power", default=True),
        "low_power_mode": _safe_bool(control_plane_features, "low_power_mode", default=False),
        "form_factor": _safe_str(control_plane_features, "form_factor", default="laptop"),
        "stage_node_count": sum(int(v) for v in stage_node_counts.values()),
        # Label.
        "gpu_was_faster": bool(gpu_was_faster),
    }


def load_telemetry(input_dirs: list[str]) -> list[dict]:
    records: list[dict] = []
    for input_path in input_dirs:
        path = pathlib.Path(input_path)
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = [candidate for candidate in sorted(path.iterdir()) if candidate.is_file()]
        else:
            print(f"  [warn] telemetry input not found: {path}")
            continue
        for filepath in files:
            if filepath.suffix not in (".json", ".jsonl"):
                continue
            try:
                if filepath.suffix == ".jsonl":
                    for line in filepath.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        parsed = parse_record(json.loads(line))
                        if parsed is not None:
                            records.append(parsed)
                    continue
                raw = json.loads(filepath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"  [warn] skipping {filepath.name}: {exc}")
                continue
            parsed = parse_record(raw)
            if parsed is not None:
                records.append(parsed)
    return records


# ---------------------------------------------------------------------------
# Synthetic data generation
# ---------------------------------------------------------------------------


def generate_synthetic_records(n: int = 300) -> list[dict]:
    """Produce synthetic GPU-dispatch observations for bootstrapping."""
    rng = np.random.default_rng(seed=99)
    records: list[dict] = []

    # The crossover point: GPU becomes beneficial above a constraint threshold
    # that depends on memory pressure and GPU availability.
    base_threshold = 20_000

    for _ in range(n):
        constraints = int(rng.integers(100, 2_000_000))
        signals = int(constraints * rng.uniform(0.8, 1.5))
        gpu_ratio = float(rng.uniform(0.0, 1.0))
        peak_mem = int(constraints * rng.uniform(50, 500))
        degree = int(rng.choice([2, 3, 4, 5, 6]))
        witness_size = int(signals * rng.uniform(8, 64))
        prove_time = max(1.0, float(constraints * rng.uniform(0.001, 0.05) + rng.normal(50, 20)))
        verify_time = float(rng.uniform(1.0, max(2.0, prove_time * 0.1)))
        witness_gen = float(rng.uniform(0.5, max(1.0, prove_time * 0.3)))
        proof_size = int(rng.integers(128, 65536))
        gpu_nodes = int(rng.integers(0, 8))
        cpu_nodes = int(rng.integers(1, 12))

        # Simulate GPU advantage: depends on constraint count, GPU availability,
        # and memory pressure.
        effective_threshold = base_threshold * (1.0 + 0.5 * (1.0 - gpu_ratio))
        noise = rng.normal(0, 5000)
        gpu_faster = constraints > (effective_threshold + noise)

        records.append({
            "constraint_count": constraints,
            "signal_count": signals,
            "gpu_busy_ratio": gpu_ratio,
            "peak_memory_bytes": peak_mem,
            "prove_time_ms": prove_time,
            "verify_time_ms": verify_time,
            "witness_gen_time_ms": witness_gen,
            "proof_size_bytes": proof_size,
            "max_constraint_degree": degree,
            "witness_size": witness_size,
            "cpu_nodes": cpu_nodes,
            "gpu_nodes": gpu_nodes,
            "chip_family": "m4",
            "gpu_core_count": 40,
            "ane_tops": 38.0,
            "battery_present": True,
            "on_external_power": True,
            "low_power_mode": False,
            "form_factor": "laptop",
            "stage_node_count": cpu_nodes + gpu_nodes,
            "gpu_was_faster": bool(gpu_faster),
        })
    return records


# ---------------------------------------------------------------------------
# Feature encoding
# ---------------------------------------------------------------------------


def encode_features(records: list[dict]) -> np.ndarray:
    rows: list[list[float]] = []
    for rec in records:
        form_factor = rec.get("form_factor", "laptop")
        row = [
            _chip_generation_norm(str(rec.get("chip_family", "m4"))),
            min(max(float(rec.get("gpu_core_count", 0)) / 64.0, 0.0), 1.0),
            min(max(float(rec.get("ane_tops", 0.0)) / 40.0, 0.0), 1.0),
            1.0 if rec.get("battery_present") else 0.0,
            1.0 if rec.get("on_external_power") else 0.0,
            1.0 if rec.get("low_power_mode") else 0.0,
            1.0 if form_factor == "desktop" else 0.0,
            1.0 if form_factor == "laptop" else 0.0,
            1.0 if form_factor == "mobile" else 0.0,
            1.0 if form_factor == "headset" else 0.0,
            _normalized_log2(max(int(rec.get("stage_node_count", 0)), 1), 16.0),
            _normalized_log2(max(int(rec.get("constraint_count", 0)), 1), 24.0),
        ]
        if len(row) != len(THRESHOLD_FEATURES):
            raise ValueError(f"threshold vector width mismatch: {len(row)}")
        rows.append(row)
    return np.array(rows, dtype=np.float64)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train_threshold_model(
    X: np.ndarray,
    records: list[dict],
    profile: str,
) -> tuple:
    """Train a model that scores how beneficial GPU dispatch is.

    The model outputs a continuous "gpu_lane_score" (higher = more beneficial
    to dispatch to GPU).  The ZirOS runtime uses this score together with
    the current constraint count to decide the dispatch strategy.

    Implementation: fit a gradient-boosted regressor on a continuous score
    derived from the binary gpu_was_faster label and timing ratios.
    """
    # Build a continuous target: blend binary label with a timing-derived signal.
    scores = np.zeros(len(records), dtype=np.float64)
    for i, rec in enumerate(records):
        base = 1.0 if rec["gpu_was_faster"] else 0.0
        # Scale by how many constraints (log-normalized) as a confidence weight.
        log_c = np.log1p(rec["constraint_count"]) / np.log1p(2_000_000)
        # GPU ratio contributes positively.
        gpu_term = rec["gpu_busy_ratio"] * 0.2
        scores[i] = 0.6 * base + 0.25 * log_c + 0.15 * gpu_term

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = GradientBoostingRegressor(
        n_estimators=120 if profile == "production" else 30,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.8,
        random_state=42,
    )
    model.fit(X_scaled, scores)

    cv_folds = min(5, max(2, len(scores)))
    cv_scores = cross_val_score(model, X_scaled, scores, cv=cv_folds, scoring="r2")

    # Also fit a logistic classifier to report accuracy on the binary label.
    y_binary = np.array([1 if r["gpu_was_faster"] else 0 for r in records], dtype=np.int64)
    if len(np.unique(y_binary)) >= 2:
        lr = LogisticRegression(max_iter=1000, random_state=42)
        lr.fit(X_scaled, y_binary)
        acc_scores = cross_val_score(lr, X_scaled, y_binary, cv=cv_folds, scoring="accuracy")
        binary_accuracy = float(np.mean(acc_scores))
    else:
        binary_accuracy = 1.0

    # Estimate the crossover constraint count: median constraint_count
    # where the model's predicted score crosses 0.5.
    preds = model.predict(X_scaled)
    crossover_mask = np.abs(preds - 0.5) < 0.15
    if np.any(crossover_mask):
        crossover_constraints = int(
            np.median([records[i]["constraint_count"] for i in np.where(crossover_mask)[0]])
        )
    else:
        crossover_constraints = int(np.median([r["constraint_count"] for r in records]))

    metrics = {
        "r2_cv_mean": float(np.mean(cv_scores)),
        "r2_cv_std": float(np.std(cv_scores)),
        "mae": float(np.mean(np.abs(preds - scores))),
        "binary_accuracy": binary_accuracy,
        "crossover_constraint_estimate": crossover_constraints,
        "n_records": len(records),
    }

    return model, scaler, metrics


def export_threshold_model(
    model,
    scaler: StandardScaler,
    output_path: str,
) -> str:
    """Export the threshold optimizer as a CoreML .mlpackage.

    We compose the StandardScaler normalization into the pipeline by creating
    a scikit-learn Pipeline, which coremltools can convert directly.
    """
    from sklearn.pipeline import Pipeline

    pipeline = Pipeline([
        ("scaler", scaler),
        ("regressor", model),
    ])

    coreml_model = ct.converters.sklearn.convert(
        pipeline,
        input_features=[(COREML_INPUT_NAME, ct.models.datatypes.Array(len(THRESHOLD_FEATURES)))],
        output_feature_names="gpu_lane_score",
    )

    coreml_model.short_description = (
        "ZirOS threshold optimizer: predicts GPU dispatch benefit score"
    )
    coreml_model.author = "ZirOS Neural Engine training pipeline"
    coreml_model.version = "1"
    coreml_model.user_defined_metadata.update({
        "zkf_schema": THRESHOLD_SCHEMA,
        "zkf_lane": "threshold-optimizer",
        "zkf_input_name": COREML_INPUT_NAME,
        "zkf_input_shape": str(len(THRESHOLD_FEATURES)),
    })

    pkg_path = pathlib.Path(output_path)
    if pkg_path.exists():
        shutil.rmtree(pkg_path)

    coreml_model.save(output_path)
    return output_path


def compute_package_hash(path: str) -> str:
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


def write_sidecar(
    package_path: str,
    quality_gate: dict,
    metrics: dict,
    record_count: int,
    package_tree_sha256: str,
) -> str:
    payload = {
        "schema": THRESHOLD_SCHEMA,
        "lane": "threshold-optimizer",
        "version": "v1",
        "input_name": COREML_INPUT_NAME,
        "input_shape": len(THRESHOLD_FEATURES),
        "output_name": "gpu_lane_score",
        "schema_fingerprint": schema_fingerprint(THRESHOLD_FEATURES),
        "feature_labels": THRESHOLD_FEATURES,
        "quality_gate": quality_gate,
        "record_count": record_count,
        "corpus_record_count": record_count,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "package_tree_sha256": package_tree_sha256,
        "metrics": metrics,
    }
    sidecar_path = f"{package_path}.json"
    with open(sidecar_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return sidecar_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train ZirOS threshold optimizer model for GPU dispatch.",
    )
    parser.add_argument(
        "--quality-profile",
        required=True,
        choices=["fixture", "production"],
        help="Training quality profile.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output path for the .mlpackage bundle.",
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
    profile = args.quality_profile

    print(f"[threshold_optimizer] quality-profile={profile}")
    print(f"[threshold_optimizer] output={args.out}")
    print(f"[threshold_optimizer] input dirs: {input_dirs}")

    # 1. Load telemetry.
    print("[threshold_optimizer] loading telemetry records ...")
    records = load_telemetry(input_dirs)
    print(f"[threshold_optimizer] loaded {len(records)} records from telemetry")

    MIN_RECORDS = 50
    if len(records) < MIN_RECORDS:
        n_synthetic = MIN_RECORDS - len(records)
        print(
            f"[threshold_optimizer] insufficient telemetry ({len(records)} < {MIN_RECORDS}), "
            f"generating {n_synthetic} synthetic records"
        )
        records.extend(generate_synthetic_records(n_synthetic))

    # Ensure at least some GPU-true and GPU-false observations.
    gpu_true = sum(1 for r in records if r["gpu_was_faster"])
    gpu_false = len(records) - gpu_true
    if gpu_true == 0 or gpu_false == 0:
        print("[threshold_optimizer] unbalanced labels, adding synthetic balance")
        records.extend(generate_synthetic_records(100))

    anchor_records = 1000 if profile == "production" else 250
    print(
        f"[threshold_optimizer] adding {anchor_records} runtime-native "
        "scenario-anchor records"
    )
    records.extend(generate_synthetic_records(anchor_records))

    # 2. Encode features.
    X = encode_features(records)
    print(f"[threshold_optimizer] feature matrix: {X.shape[0]} x {X.shape[1]}")

    # 3. Train.
    print("[threshold_optimizer] training threshold optimizer model ...")
    t0 = time.monotonic()
    model, scaler, metrics = train_threshold_model(X, records, profile)
    elapsed = time.monotonic() - t0
    print(f"[threshold_optimizer] training complete in {elapsed:.2f}s")
    print(f"[threshold_optimizer] metrics: {json.dumps(metrics, indent=2)}")

    # 4. Export.
    print(f"[threshold_optimizer] exporting -> {args.out}")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    export_threshold_model(model, scaler, args.out)

    pkg_hash = compute_package_hash(args.out)
    print(f"[threshold_optimizer] package hash: {pkg_hash[:16]}...")

    # 5. Quality check.
    mae_threshold = 0.25 if profile == "production" else 0.5
    accuracy_threshold = 0.5 if profile == "production" else 0.0
    passed = metrics["mae"] <= mae_threshold and metrics["binary_accuracy"] >= accuracy_threshold
    quality_gate = {
        "passed": passed,
        "thresholds": {
            "mae_max": mae_threshold,
            "binary_accuracy_min": accuracy_threshold,
            "rows_min": float(MIN_RECORDS),
        },
        "measurements": {
            "mae": metrics["mae"],
            "r2_cv_mean": metrics["r2_cv_mean"],
            "binary_accuracy": metrics["binary_accuracy"],
            "rows": float(len(records)),
        },
        "reasons": []
        if passed
        else ["threshold optimizer quality gate did not clear the configured threshold"],
    }
    sidecar = write_sidecar(args.out, quality_gate, metrics, len(records), pkg_hash)
    status = "PASS" if passed else "WARN"
    print(f"[threshold_optimizer] quality gate: {status}")
    print(f"[threshold_optimizer] sidecar -> {sidecar}")
    print(
        f"[threshold_optimizer] estimated GPU crossover at "
        f"~{metrics['crossover_constraint_estimate']} constraints"
    )
    print("[threshold_optimizer] done.")


if __name__ == "__main__":
    main()
