#!/usr/bin/env python3
"""Export telemetry records with host-identifying fields removed."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from zkf_control_plane_common import DEFAULT_MODEL_DIR, load_telemetry_records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", default=[], help="Telemetry file, glob, or directory")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_MODEL_DIR / "telemetry_anonymized.jsonl",
        help="Destination JSONL file",
    )
    return parser.parse_args()


def anonymize_record(record: dict) -> dict:
    payload = copy.deepcopy(record)
    payload.pop("_source_path", None)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    platform = payload.get("platform_capability")
    if isinstance(platform, dict):
        identity = platform.get("identity")
        if isinstance(identity, dict):
            identity.pop("model_identifier", None)
            identity.pop("machine_name", None)
            identity.pop("raw_chip_name", None)
    return payload


def main() -> int:
    args = parse_args()
    records = [anonymize_record(record) for record in load_telemetry_records(args.input)]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")
    print(f"wrote {len(records)} anonymized telemetry records -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
