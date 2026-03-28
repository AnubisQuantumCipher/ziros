#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"missing required bundle file: {path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a powered descent public bundle and optionally require release-safe status."
    )
    parser.add_argument("--bundle", required=True, help="bundle directory")
    parser.add_argument(
        "--require-release-safe",
        action="store_true",
        help="fail unless the bundle is explicitly labeled release-safe",
    )
    args = parser.parse_args()

    bundle_dir = Path(args.bundle).resolve()
    summary = read_json(bundle_dir / "private_powered_descent.summary.json")
    evidence = read_json(bundle_dir / "private_powered_descent.evidence_manifest.json")

    bundle_mode = summary.get("bundle_mode")
    release_safety = summary.get("release_safety")
    if bundle_mode != "public":
        raise SystemExit(f"expected bundle_mode=public, got {bundle_mode!r}")
    if release_safety not in {"demo-only", "release-safe"}:
        raise SystemExit(f"unexpected release_safety label: {release_safety!r}")
    if evidence.get("bundle_mode") != bundle_mode:
        raise SystemExit("summary/evidence bundle_mode mismatch")
    if evidence.get("release_safety") != release_safety:
        raise SystemExit("summary/evidence release_safety mismatch")

    if args.require_release_safe and release_safety != "release-safe":
        raise SystemExit(
            "refusing to publish a proof-bearing powered descent bundle labeled demo-only"
        )

    private_artifacts = [
        "private_powered_descent.original.program.json",
        "private_powered_descent.optimized.program.json",
        "private_powered_descent.compiled.json",
        "private_powered_descent.request.json",
        "private_powered_descent.inputs.json",
        "private_powered_descent.witness.base.json",
        "private_powered_descent.witness.prepared.json",
        "private_powered_descent.matrix_ccs_summary.json",
    ]
    for artifact in private_artifacts:
        path = bundle_dir / artifact
        if path.exists():
            raise SystemExit(f"public bundle leaked private artifact: {artifact}")

    print(
        json.dumps(
            {
                "bundle": str(bundle_dir),
                "bundle_mode": bundle_mode,
                "release_safety": release_safety,
                "status": "ok",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
