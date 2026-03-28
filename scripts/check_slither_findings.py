#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_ASSEMBLY_DESCRIPTIONS = (
    re.compile(r"^Pairing\.addition\(Pairing\.G1Point,Pairing\.G1Point\)"),
    re.compile(r"^Pairing\.scalarMul\(Pairing\.G1Point,uint256\)"),
    re.compile(r"^Pairing\.pairing\(Pairing\.G1Point\[\],Pairing\.G2Point\[\]\)"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail on unexpected Slither findings.")
    parser.add_argument("--report", required=True, help="path to slither JSON report")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        help="detector check name to allow",
    )
    args = parser.parse_args()

    report = json.loads(Path(args.report).read_text())
    detectors = report.get("results", {}).get("detectors", [])
    allow = set(args.allow)
    unexpected = []
    for detector in detectors:
        check = detector.get("check")
        description = detector.get("description", "")
        if check == "assembly" and any(
            pattern.search(description) for pattern in EXPECTED_ASSEMBLY_DESCRIPTIONS
        ):
            continue
        if check not in allow:
            unexpected.append(
                {
                    "check": check,
                    "impact": detector.get("impact"),
                    "confidence": detector.get("confidence"),
                    "description": description,
                }
            )
    if unexpected:
        print(json.dumps({"unexpected_findings": unexpected}, indent=2))
        return 1
    print(
        json.dumps(
            {"status": "ok", "findings": len(detectors), "allowed": sorted(allow)},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
