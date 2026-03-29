#!/usr/bin/env python3
"""Train the anomaly detector residual model and export Core ML."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error

from zkf_control_plane_common import (
    DEFAULT_MODEL_DIR,
    build_quality_gate,
    build_feature_vector,
    control_plane_feature_labels,
    control_plane_schema_name,
    chosen_backend,
    chosen_candidate,
    corpus_hash,
    convert_sklearn_regressor,
    decision_objective,
    deployed_anomaly_budget,
    load_telemetry_records,
    record_role,
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
        default=DEFAULT_MODEL_DIR / "anomaly_detector_v1.mlpackage",
    )
    parser.add_argument(
        "--quality-profile",
        choices=["fixture", "production"],
        default="fixture",
        help="Quality-gate profile to embed in the model sidecar",
    )
    parser.add_argument(
        "--feature-schema",
        choices=["v1", "v2", "v3"],
        default="v3",
        help="Control-plane feature schema to train against",
    )
    return parser.parse_args()


def quality_thresholds(profile: str) -> dict[str, float]:
    if profile == "production":
        return {
            "rows_min": 300.0,
            "scenario_count_min": 40.0,
            "mae_max": 0.2,
            "r2_min": 0.85,
        }
    return {
        "rows_min": 12.0,
        "scenario_count_min": 4.0,
        "mae_max": 0.08,
        "r2_min": 0.96,
    }


def main() -> int:
    args = parse_args()
    feature_labels = control_plane_feature_labels(args.feature_schema)
    records = load_telemetry_records(args.input)
    digest = corpus_hash(args.input)
    included_roles = {"realized", "anomaly-nominal", "anomaly-degraded"}
    rows = []
    scenario_ids = set()
    for record in records:
        if record_role(record) not in included_roles:
            continue
        label = deployed_anomaly_budget(record)
        scenario_ids.add(scenario_id(record))
        for objective in [decision_objective(record)]:
            rows.append(
                (
                    build_feature_vector(
                        record,
                        candidate=chosen_candidate(record),
                        backend=chosen_backend(record),
                        objective=objective,
                        feature_schema=args.feature_schema,
                    ),
                    label,
                )
            )
    if len(rows) < 12:
        raise SystemExit("anomaly detector needs at least 12 deployed-envelope rows")

    x = np.asarray([features for features, _ in rows], dtype=np.float32)
    y = np.asarray([label for _, label in rows], dtype=np.float32)
    model = RandomForestRegressor(random_state=42, n_estimators=320, n_jobs=-1)
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
        "anomaly_score",
        args.out,
        feature_count=len(feature_labels),
    )
    extra_metadata = {
        "lane_semantics": "deployed anomaly envelope factor capped to the runtime 1.0x-4.0x range",
    }
    if args.quality_profile != "fixture":
        extra_metadata["quality_profile"] = args.quality_profile
        extra_metadata["record_count"] = int(len(rows))
        extra_metadata["trained_at"] = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    write_sidecar(
        args.out,
        "anomaly",
        metrics,
        "anomaly_score",
        corpus_digest=digest,
        trainer_script=Path(__file__).name,
        quality_gate=quality_gate,
        extra_metadata=extra_metadata,
        feature_labels=feature_labels,
        schema=control_plane_schema_name(args.feature_schema),
        version=args.feature_schema,
    )
    print(f"anomaly rows={metrics['rows']} mae={metrics['mae']:.3f} r2={metrics['r2']:.4f}")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
