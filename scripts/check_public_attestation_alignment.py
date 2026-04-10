#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PUBLIC_ROOT = Path("/Users/sicarii/Projects/ziros-attestation")
DEFAULT_EXPORT_PATH = Path("/tmp/ziros-public-attestation-export-bundle/public_attestation_export.json")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, default=DEFAULT_PUBLIC_ROOT)
    parser.add_argument("--private-export", type=Path, default=DEFAULT_EXPORT_PATH)
    args = parser.parse_args()

    public_root = args.public_root.resolve()
    export_doc = load_json(args.private_export.resolve())
    latest = load_json(public_root / "attestation" / "latest.json")
    manifest = load_json(public_root / "publication" / "manifest.json")
    midnight_readiness = load_json(public_root / "midnight" / "readiness.json")
    evm_readiness = load_json(public_root / "evm" / "readiness.json")

    issues: list[str] = []

    if export_doc.get("working_tree_dirty"):
        issues.append("private export is dirty; public attestation refresh is blocked")

    expected_release_tag = export_doc["release_tag"]
    public_release_tag = manifest.get("release_tag")
    if public_release_tag != expected_release_tag:
        issues.append(
            f"release tag mismatch: private export expects {expected_release_tag!r}, public repo publishes {public_release_tag!r}"
        )

    headline_counts = export_doc["headline_counts"]
    expected_counts = {
        "implementation_bound_rows": headline_counts["mechanized_implementation_claim"],
        "hypothesis_carried_rows": headline_counts["hypothesis_carried_theorem"],
        "trusted_protocol_tcb_rows": headline_counts.get("trusted_protocol_tcb", 0),
        "mechanized_local_rows": headline_counts["total_entries"],
        "pending_rows": headline_counts["pending"],
    }
    actual_counts = latest.get("headline_counts", {})
    for key, expected_value in expected_counts.items():
        actual_value = actual_counts.get(key)
        if actual_value != expected_value:
            issues.append(
                f"headline count mismatch for {key}: private export expects {expected_value!r}, public repo publishes {actual_value!r}"
            )

    readiness = export_doc.get("operator_readiness_summary")
    if readiness:
        expected_midnight = readiness.get("midnight", {})
        if midnight_readiness.get("status") != expected_midnight.get("status"):
            issues.append(
                f"midnight readiness status mismatch: private export expects {expected_midnight.get('status')!r}, public repo publishes {midnight_readiness.get('status')!r}"
            )
        if midnight_readiness.get("ready_for_local_operator") != expected_midnight.get(
            "ready_for_local_operator"
        ):
            issues.append(
                "midnight ready_for_local_operator mismatch between private export and public repo"
            )
        if midnight_readiness.get("ready_for_live_submit") != expected_midnight.get(
            "ready_for_live_submit"
        ):
            issues.append(
                "midnight ready_for_live_submit mismatch between private export and public repo"
            )

        expected_evm = readiness.get("evm", {})
        if evm_readiness.get("status") != expected_evm.get("status"):
            issues.append(
                f"evm readiness status mismatch: private export expects {expected_evm.get('status')!r}, public repo publishes {evm_readiness.get('status')!r}"
            )

    if issues:
        for issue in issues:
            print(issue)
        return 1

    print("public attestation repo is aligned with the private export")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
