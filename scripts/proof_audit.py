#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
STATUS_PATH = ROOT / ".zkf-completion-status.json"
RELEASE_STATUS_PATH = ROOT / "release" / "theorem_coverage_status.json"
PROTOCOL_RUNNER_PATH = ROOT / "scripts" / "run_protocol_lean_proofs.sh"
PRODUCT_RELEASE_PATH = ROOT / "release" / "product-release.json"
PRIVATE_SOURCE_CENSUS_PATH = ROOT / "release" / "private_source_census.json"

STATUS_ORDER = [
    "mechanized_local",
    "mechanized_generated",
    "hypothesis_stated",
    "bounded_checked",
    "assumed_external",
    "pending",
]
ALLOWED_RELEASE_GRADE_HYPOTHESIS_PREFIXES = ("protocol.",)
ASSURANCE_CLASS_ORDER = [
    "mechanized_implementation_claim",
    "bounded_check",
    "attestation_backed_lane",
    "model_only_claim",
    "trusted_protocol_tcb",
    "hypothesis_carried_theorem",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    require(path.exists(), f"missing required artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def count_entries(entries: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    status_counts = {key: 0 for key in STATUS_ORDER}
    assurance_counts = {key: 0 for key in ASSURANCE_CLASS_ORDER}
    for entry in entries:
        status_counts[entry["status"]] = status_counts.get(entry["status"], 0) + 1
        assurance = entry.get("assurance_class", "mechanized_implementation_claim")
        assurance_counts[assurance] = assurance_counts.get(assurance, 0) + 1
    return status_counts, assurance_counts


def compare_status_payload(payload: dict, status_counts: dict[str, int], assurance_counts: dict[str, int]) -> None:
    require(
        payload.get("counts") == status_counts,
        f"status counts out of sync in {payload.get('generated_from', 'status payload')}",
    )
    require(
        payload.get("assurance_class_counts") == assurance_counts,
        "assurance class counts out of sync",
    )


def audit_release_grade(entries: list[dict], status_counts: dict[str, int], assurance_counts: dict[str, int]) -> None:
    require(status_counts.get("pending", 0) == 0, "pending verification rows remain")
    require(status_counts.get("hypothesis_stated", 0) == 0, "hypothesis_stated rows remain")
    require(status_counts.get("bounded_checked", 0) == 0, "bounded_checked rows remain")
    non_protocol_assumed_external = [
        entry["theorem_id"]
        for entry in entries
        if entry["status"] == "assumed_external"
        and not entry["theorem_id"].startswith("protocol.")
    ]
    require(
        not non_protocol_assumed_external,
        f"non-protocol assumed_external rows remain: {non_protocol_assumed_external}",
    )
    require(
        assurance_counts.get("attestation_backed_lane", 0) == 0,
        "attestation_backed_lane rows remain",
    )
    require(
        assurance_counts.get("hypothesis_carried_theorem", 0) == 0,
        "hypothesis_carried_theorem rows remain",
    )
    require(PROTOCOL_RUNNER_PATH.exists(), f"missing protocol Lean runner: {PROTOCOL_RUNNER_PATH}")
    require(PRODUCT_RELEASE_PATH.exists(), f"missing product release artifact: {PRODUCT_RELEASE_PATH}")
    require(
        PRIVATE_SOURCE_CENSUS_PATH.exists(),
        f"missing private source census artifact: {PRIVATE_SOURCE_CENSUS_PATH}",
    )
    unexpected_trust_rows = []
    for entry in entries:
        if entry["theorem_id"].startswith("protocol."):
            require(entry["evidence_path"], f"protocol row {entry['theorem_id']} is missing evidence_path")
            require(
                (ROOT / entry["evidence_path"]).exists(),
                f"protocol evidence path missing for {entry['theorem_id']}: {entry['evidence_path']}",
            )
            require(
                entry.get("assurance_class") == "trusted_protocol_tcb",
                f"protocol row {entry['theorem_id']} must be explicit trusted_protocol_tcb",
            )
        if entry.get("trusted_assumptions") and not entry["theorem_id"].startswith(
            ALLOWED_RELEASE_GRADE_HYPOTHESIS_PREFIXES
        ):
            unexpected_trust_rows.append(entry["theorem_id"])
    require(
        not unexpected_trust_rows,
        f"unexpected trusted-assumption rows remain: {unexpected_trust_rows}",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit ledger/status proof-boundary artifacts.")
    parser.add_argument(
        "--release-grade",
        action="store_true",
        help="enforce release-grade proof-boundary expectations",
    )
    args = parser.parse_args()

    ledger = load_json(LEDGER_PATH)
    status = load_json(STATUS_PATH)
    release_status = load_json(RELEASE_STATUS_PATH)
    entries = ledger["entries"]

    status_counts, assurance_counts = count_entries(entries)
    compare_status_payload(status, status_counts, assurance_counts)
    compare_status_payload(release_status, status_counts, assurance_counts)

    require(
        status.get("total_entries") == len(entries),
        ".zkf-completion-status.json total_entries is out of sync",
    )
    require(
        release_status.get("total_entries") == len(entries),
        "release/theorem_coverage_status.json total_entries is out of sync",
    )

    if args.release_grade:
        audit_release_grade(entries, status_counts, assurance_counts)

    print(
        json.dumps(
            {
                "ok": True,
                "total_entries": len(entries),
                "counts": status_counts,
                "assurance_class_counts": assurance_counts,
                "release_grade_checked": args.release_grade,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
