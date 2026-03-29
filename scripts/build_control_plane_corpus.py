#!/usr/bin/env python3
"""Normalize ~/.zkf/telemetry and explicit inputs into a JSONL corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from zkf_control_plane_common import (
    DEFAULT_MODEL_DIR,
    build_feature_vector,
    chosen_backend,
    chosen_candidate,
    control_plane_feature_labels,
    control_plane_schema_name,
    duration_ms,
    field_used,
    load_telemetry_records,
    proof_size_bytes,
    schema_fingerprint,
    summarize_corpus,
    validate_corpus_summary,
)

PRODUCTION_REQUIRED_JOB_KINDS = ["prove", "fold", "wrap"]
PRODUCTION_REQUIRED_OBJECTIVES = ["fastest-prove", "smallest-proof", "no-trusted-setup"]
PRODUCTION_REQUIRED_FIELDS = ["bn254", "goldilocks", "pasta-fp"]
PRODUCTION_REQUIREMENTS = {
    "min_records": 500,
    "min_live_records": 350,
    "min_scenarios": 100,
    "min_backends": 6,
    "min_fields": 3,
    "required_job_kinds": PRODUCTION_REQUIRED_JOB_KINDS,
    "required_objectives": PRODUCTION_REQUIRED_OBJECTIVES,
    "required_fields": PRODUCTION_REQUIRED_FIELDS,
    "require_nominal": True,
    "require_degraded": True,
    "max_fixture_share": 0.25,
    "max_duplicate_sequence_ids": 0,
    "max_duplicate_replay_guards": 0,
    "max_integrity_mismatch_records": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[], help="Telemetry file, glob, or directory")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "control_plane_corpus.jsonl",
        help="Normalized JSONL output path",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        help="Optional machine-readable corpus summary report",
    )
    parser.add_argument(
        "--profile",
        choices=["custom", "production"],
        default="custom",
        help="Apply a named corpus validation profile",
    )
    parser.add_argument("--min-records", type=int)
    parser.add_argument("--min-live-records", type=int)
    parser.add_argument("--min-scenarios", type=int)
    parser.add_argument("--min-backends", type=int)
    parser.add_argument("--min-fields", type=int)
    parser.add_argument("--require-job-kind", action="append", default=[])
    parser.add_argument("--require-objective", action="append", default=[])
    parser.add_argument("--require-backend", action="append", default=[])
    parser.add_argument("--require-field", action="append", default=[])
    parser.add_argument("--require-nominal", action="store_true")
    parser.add_argument("--require-degraded", action="store_true")
    parser.add_argument("--max-fixture-share", type=float)
    parser.add_argument(
        "--feature-schema",
        choices=["v1", "v2", "v3"],
        default="v3",
        help="Feature schema to materialize in the normalized corpus",
    )
    return parser.parse_args()


def build_rows(records: list[dict], *, feature_schema: str) -> list[dict]:
    feature_labels = control_plane_feature_labels(feature_schema)
    rows = []
    for record in records:
        rows.append(
            {
                "schema": control_plane_schema_name(feature_schema),
                "source_path": record.get("_source_path"),
                "job_kind": record.get("metadata", {}).get("job_kind", "prove"),
                "backend": chosen_backend(record),
                "field": field_used(record),
                "dispatch_candidate": chosen_candidate(record),
                "proof_size_bytes": proof_size_bytes(record),
                "total_proving_time_ms": duration_ms(record),
                "feature_labels": feature_labels,
                "feature_vector": build_feature_vector(
                    record,
                    candidate=chosen_candidate(record),
                    backend=chosen_backend(record),
                    feature_schema=feature_schema,
                ),
                "schema_fingerprint": schema_fingerprint(feature_labels),
                "record": record,
            }
        )
    return rows


def validation_config(args: argparse.Namespace) -> dict:
    config = {
        "min_records": 0,
        "min_live_records": 0,
        "min_scenarios": 0,
        "min_backends": 0,
        "min_fields": 0,
        "required_job_kinds": [],
        "required_objectives": [],
        "required_backends": [],
        "required_fields": [],
        "require_nominal": False,
        "require_degraded": False,
        "max_fixture_share": None,
    }
    if args.profile == "production":
        config.update(PRODUCTION_REQUIREMENTS)
    if args.min_records is not None:
        config["min_records"] = args.min_records
    if args.min_live_records is not None:
        config["min_live_records"] = args.min_live_records
    if args.min_scenarios is not None:
        config["min_scenarios"] = args.min_scenarios
    if args.min_backends is not None:
        config["min_backends"] = args.min_backends
    if args.min_fields is not None:
        config["min_fields"] = args.min_fields
    if args.require_job_kind:
        config["required_job_kinds"] = args.require_job_kind
    if args.require_objective:
        config["required_objectives"] = args.require_objective
    if args.require_backend:
        config["required_backends"] = args.require_backend
    if args.require_field:
        config["required_fields"] = args.require_field
    if args.require_nominal:
        config["require_nominal"] = True
    if args.require_degraded:
        config["require_degraded"] = True
    if args.max_fixture_share is not None:
        config["max_fixture_share"] = args.max_fixture_share
    return config


def write_corpus(
    *,
    records: list[dict],
    out_path: Path,
    summary_out: Path | None,
    profile: str,
    validation: dict,
    feature_schema: str = "v3",
) -> tuple[int, dict]:
    rows = build_rows(records, feature_schema=feature_schema)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")
    summary = summarize_corpus(records)
    reasons = validate_corpus_summary(summary, **validation)
    summary["profile"] = profile
    summary["feature_schema"] = feature_schema
    summary["schema_fingerprint"] = schema_fingerprint(control_plane_feature_labels(feature_schema))
    summary["output_path"] = str(out_path)
    summary["validation"] = {
        "passed": not reasons,
        "requirements": validation,
        "reasons": reasons,
    }
    if summary_out is not None:
        summary_out.parent.mkdir(parents=True, exist_ok=True)
        summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(rows), summary


def main() -> int:
    args = parse_args()
    records = load_telemetry_records(args.input)
    validation = validation_config(args)
    summary_out = args.summary_out
    if summary_out is None:
        summary_out = args.out.with_suffix(".summary.json")
    rows, summary = write_corpus(
        records=records,
        out_path=args.out,
        summary_out=summary_out,
        profile=args.profile,
        validation=validation,
        feature_schema=args.feature_schema,
    )
    if not summary["validation"]["passed"]:
        raise SystemExit(
            "control-plane corpus does not satisfy the requested coverage profile:\n- "
            + "\n- ".join(summary["validation"]["reasons"])
        )
    print(f"wrote {rows} rows -> {args.out}")
    print(f"wrote summary -> {summary_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
