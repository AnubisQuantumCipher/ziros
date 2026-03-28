#!/usr/bin/env python3
"""Train the backend recommendation cost model and export Core ML."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error

from zkf_control_plane_common import (
    DEFAULT_MODEL_DIR,
    OBJECTIVES,
    build_quality_gate,
    build_feature_vector,
    control_plane_feature_labels,
    control_plane_schema_name,
    chosen_backend,
    corpus_hash,
    convert_sklearn_regressor,
    duration_ms,
    load_telemetry_records,
    proof_size_bytes,
    record_role,
    safe_r2,
    scenario_id,
    transparent_backend,
    write_sidecar,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[], help="Telemetry file, glob, or directory")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "backend_recommender_v1.mlpackage",
    )
    parser.add_argument(
        "--quality-profile",
        choices=["fixture", "production"],
        default="fixture",
        help="Quality-gate profile to embed in the model sidecar",
    )
    parser.add_argument(
        "--feature-schema",
        choices=["v1", "v2"],
        default="v1",
        help="Control-plane feature schema to train against",
    )
    return parser.parse_args()


def quality_thresholds(profile: str) -> dict[str, float]:
    if profile == "production":
        return {
            "rows_min": 180.0,
            "group_count_min": 30.0,
            "mae_max": 0.8,
            "r2_min": 0.70,
            "top1_accuracy_min": 0.65,
            "mean_reciprocal_rank_min": 0.78,
        }
    return {
        "rows_min": 18.0,
        "group_count_min": 6.0,
        "mae_max": 0.35,
        "r2_min": 0.95,
        "top1_accuracy_min": 0.88,
        "mean_reciprocal_rank_min": 0.94,
    }


def objective_score(record: dict, objective: str) -> float:
    backend = chosen_backend(record)
    if objective == "fastest-prove":
        return duration_ms(record)
    if objective == "smallest-proof":
        return float(max(1, proof_size_bytes(record)))
    return duration_ms(record) * (1.0 if transparent_backend(backend) else 6.0)


def main() -> int:
    args = parse_args()
    feature_labels = control_plane_feature_labels(args.feature_schema)
    records = load_telemetry_records(args.input)
    digest = corpus_hash(args.input)
    included_roles = {"realized", "backend-option"}
    grouped_records: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        backend = chosen_backend(record)
        if not backend or duration_ms(record) <= 0.0:
            continue
        if record_role(record) not in included_roles:
            continue
        grouped_records[scenario_id(record)].append(record)

    rows = []
    row_metadata: list[tuple[str, str, str]] = []
    for group_id, group in grouped_records.items():
        backends = {chosen_backend(record) for record in group}
        if len(backends) < 2:
            continue
        for objective in OBJECTIVES:
            raw_scores = [objective_score(record, objective) for record in group]
            best = min(raw_scores)
            normalizer = max(best, 1.0)
            for record, raw_score in zip(group, raw_scores):
                backend = chosen_backend(record)
                rows.append(
                    (
                        build_feature_vector(
                            record,
                            candidate=None,
                            backend=backend,
                            objective=objective,
                            feature_schema=args.feature_schema,
                        ),
                        raw_score / normalizer,
                    )
                )
                row_metadata.append((group_id, objective, backend))
    if len(rows) < 18:
        raise SystemExit("backend recommender needs at least 18 grouped objective rows")

    x = np.asarray([features for features, _ in rows], dtype=np.float32)
    y = np.asarray([label for _, label in rows], dtype=np.float32)
    model = GradientBoostingRegressor(random_state=42, n_estimators=220, max_depth=3)
    model.fit(x, y)
    predictions = model.predict(x)

    grouped_predictions: dict[tuple[str, str], list[tuple[str, float, float]]] = defaultdict(list)
    for (group_id, objective, backend), (_, actual), predicted in zip(
        row_metadata, rows, predictions
    ):
        grouped_predictions[(group_id, objective)].append((backend, float(actual), float(predicted)))

    top1_hits = 0
    reciprocal_ranks = []
    for candidates in grouped_predictions.values():
        best_actual = min(actual for _, actual, _ in candidates)
        best_backends = {
            backend
            for backend, actual, _ in candidates
            if abs(actual - best_actual) <= 1e-9
        }
        predicted_ranking = sorted(candidates, key=lambda item: item[2])
        if predicted_ranking[0][0] in best_backends:
            top1_hits += 1
        for rank, (backend, _, _) in enumerate(predicted_ranking, start=1):
            if backend in best_backends:
                reciprocal_ranks.append(1.0 / rank)
                break

    metrics = {
        "rows": int(len(rows)),
        "group_count": int(len(grouped_predictions)),
        "mae": float(mean_absolute_error(y, predictions)),
        "r2": safe_r2(y, predictions),
        "top1_accuracy": float(top1_hits / max(1, len(grouped_predictions))),
        "mean_reciprocal_rank": float(sum(reciprocal_ranks) / max(1, len(reciprocal_ranks))),
    }
    quality_gate = build_quality_gate(quality_thresholds(args.quality_profile), metrics)
    convert_sklearn_regressor(
        model,
        "backend_score",
        args.out,
        feature_count=len(feature_labels),
    )
    extra_metadata = {
        "lane_semantics": "grouped backend ranking smoke floor across optimization objectives",
    }
    if args.quality_profile != "fixture":
        extra_metadata["quality_profile"] = args.quality_profile
        extra_metadata["record_count"] = int(len(rows))
        extra_metadata["trained_at"] = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    write_sidecar(
        args.out,
        "backend",
        metrics,
        "backend_score",
        corpus_digest=digest,
        trainer_script=Path(__file__).name,
        quality_gate=quality_gate,
        extra_metadata=extra_metadata,
        feature_labels=feature_labels,
        schema=control_plane_schema_name(args.feature_schema),
        version=args.feature_schema,
    )
    print(f"backend rows={metrics['rows']} mae={metrics['mae']:.3f} r2={metrics['r2']:.4f}")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
