#!/usr/bin/env python3
"""Train the adaptive threshold optimizer lane and export Core ML."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error

from zkf_control_plane_common import (
    DEFAULT_MODEL_DIR,
    DEFAULT_TELEMETRY_DIR,
    THRESHOLD_OPTIMIZER_FEATURE_LABELS,
    THRESHOLD_SCHEMA_V1,
    build_quality_gate,
    build_threshold_optimizer_feature_vector,
    corpus_hash,
    convert_sklearn_regressor,
    load_telemetry_records,
    safe_r2,
    scenario_id,
    write_sidecar,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[], help="Telemetry file, glob, or directory")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "threshold_optimizer_v1.mlpackage",
    )
    parser.add_argument(
        "--quality-profile",
        choices=["fixture", "production"],
        default="fixture",
        help="Quality-gate profile to embed in the model sidecar",
    )
    return parser.parse_args()


def quality_thresholds(profile: str) -> dict[str, float]:
    if profile == "production":
        return {
            "rows_min": 200.0,
            "scenario_count_min": 30.0,
            "mae_max": 0.25,
            "r2_min": 0.70,
        }
    return {
        "rows_min": 12.0,
        "scenario_count_min": 4.0,
        "mae_max": 0.08,
        "r2_min": 0.90,
    }


def telemetry_dir_stats(directory: Path) -> dict[str, str | int]:
    import hashlib

    entries = [path for path in directory.iterdir() if path.is_file()]
    entries.sort(key=lambda path: path.name)
    digest = hashlib.sha256()
    for path in entries:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return {
        "record_count": len(entries),
        "corpus_hash": digest.hexdigest(),
    }


def main() -> int:
    args = parse_args()
    records = load_telemetry_records(args.input)
    digest = corpus_hash(args.input)
    telemetry_stats = telemetry_dir_stats(DEFAULT_TELEMETRY_DIR)

    rows = []
    scenario_ids = set()
    for record in records:
        stage_counts = record.get("control_plane", {}).get("decision", {}).get("features", {}).get("stage_node_counts", {})
        if not isinstance(stage_counts, dict) or not stage_counts:
            continue
        scenario_ids.add(scenario_id(record))
        rows.append(
            (
                build_threshold_optimizer_feature_vector(record),
                1.0 if record.get("outcome", {}).get("gpu_was_faster") else 0.0,
            )
        )

    if len(rows) < 12:
        raise SystemExit("threshold optimizer needs at least 12 telemetry rows")

    x = np.asarray([features for features, _ in rows], dtype=np.float32)
    y = np.asarray([label for _, label in rows], dtype=np.float32)
    model = GradientBoostingRegressor(random_state=42, n_estimators=160, max_depth=3)
    model.fit(x, y)
    predictions = model.predict(x)
    metrics = {
        "rows": int(len(rows)),
        "scenario_count": int(len(scenario_ids)),
        "mae": float(mean_absolute_error(y, predictions)),
        "r2": safe_r2(y, predictions),
    }
    quality_gate = build_quality_gate(quality_thresholds(args.quality_profile), metrics)
    convert_sklearn_regressor(
        model,
        "gpu_lane_score",
        args.out,
        feature_count=len(THRESHOLD_OPTIMIZER_FEATURE_LABELS),
    )
    extra_metadata = {
        "lane_semantics": "stage crossover score for adaptive GPU-versus-CPU threshold selection",
        "telemetry_corpus_hash": telemetry_stats["corpus_hash"],
        "telemetry_record_count": telemetry_stats["record_count"],
        "telemetry_source": str(DEFAULT_TELEMETRY_DIR),
    }
    if args.quality_profile != "fixture":
        extra_metadata["quality_profile"] = args.quality_profile
        extra_metadata["record_count"] = int(len(rows))
        extra_metadata["trained_at"] = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    write_sidecar(
        args.out,
        "threshold-optimizer",
        metrics,
        "gpu_lane_score",
        corpus_digest=digest,
        trainer_script=Path(__file__).name,
        quality_gate=quality_gate,
        extra_metadata=extra_metadata,
        feature_labels=list(THRESHOLD_OPTIMIZER_FEATURE_LABELS),
        schema=THRESHOLD_SCHEMA_V1,
        version="v1",
    )
    print(
        f"threshold-optimizer rows={metrics['rows']} mae={metrics['mae']:.3f} r2={metrics['r2']:.4f}"
    )
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
