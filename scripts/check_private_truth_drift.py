#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import generate_private_release_truth as truth


BEGIN = "<!-- BEGIN GENERATED PRIVATE SUMMARY -->"
END = "<!-- END GENERATED PRIVATE SUMMARY -->"


def extract_block(path: Path, begin: str, end: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(begin) + len(begin)
    finish = text.index(end)
    return text[start:finish].strip()


def compare_payload_subset(actual: dict, expected: dict, prefix: str, issues: list[str]) -> None:
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict):
                issues.append(f"{prefix}{key} should be an object")
                continue
            compare_payload_subset(actual_value, expected_value, f"{prefix}{key}.", issues)
            continue
        if actual_value != expected_value:
            issues.append(
                f"{prefix}{key} drifted: expected {expected_value!r}, found {actual_value!r}"
            )


def strip_generated_at(value):
    if isinstance(value, dict):
        return {
            key: strip_generated_at(inner)
            for key, inner in value.items()
            if key != "generated_at"
        }
    if isinstance(value, list):
        return [strip_generated_at(item) for item in value]
    return value


def source_commit_is_acceptable(recorded: str) -> bool:
    if not recorded:
        return False
    head = truth.git_head_commit()
    if recorded == head:
        return True
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", recorded, head],
        cwd=truth.ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def main() -> int:
    version = truth.workspace_version()
    metadata = truth.cargo_metadata()
    workspace_members = sorted({package["name"] for package in metadata["packages"]})
    tracked = truth.tracked_files()
    rust_lines = truth.tracked_rs_lines()
    support = truth.load_json(truth.SUPPORT_MATRIX)
    completion = truth.load_json(truth.COMPLETION)
    ledger_doc = truth.load_json(truth.LEDGER)
    ledger_entries = ledger_doc["entries"]
    product_release = truth.load_json(truth.RELEASE_DIR / "product-release.json")
    private_census = truth.load_json(truth.RELEASE_DIR / "private_source_census.json")
    public_export = truth.load_json(truth.PROVENANCE_DIR / "public_attestation_export.json")
    midnight_taxonomy = truth.load_json(truth.RELEASE_DIR / "midnight_universal_contract_taxonomy.json")
    evm_taxonomy = truth.load_json(truth.RELEASE_DIR / "evm_secondary_contract_taxonomy.json")
    primitive_set = truth.load_json(truth.RELEASE_DIR / "guaranteed_circuit_primitive_set.json")
    midnight_readiness = truth.load_json(truth.RELEASE_DIR / "midnight_operator_readiness.json")
    evm_readiness = truth.load_json(truth.RELEASE_DIR / "evm_operator_readiness.json")
    alignment_report = truth.load_json(truth.RELEASE_DIR / "vision_alignment_report.json")

    issues: list[str] = []

    expected_summary = truth.build_readme_summary(
        len(workspace_members),
        rust_lines,
        support,
        ledger_entries,
        completion,
        midnight_readiness,
        evm_readiness,
    )
    current_summary = extract_block(truth.README, BEGIN, END)
    if current_summary != expected_summary:
        issues.append("README generated summary block is stale")

    if support.get("generated_for") != version:
        issues.append(
            f"support-matrix.json generated_for drifted: expected {version!r}, found {support.get('generated_for')!r}"
        )

    expected_product_subset = {
        "version": version,
        "release_tag": f"v{version}",
        "working_tree_dirty": truth.git_dirty(),
        "workspace_members": {
            "count": len(workspace_members),
            "names": workspace_members,
        },
        "verification_summary": {
            "total_entries": len(ledger_entries),
            "status_counts": completion["counts"],
            "assurance_class_counts": completion["assurance_class_counts"],
        },
    }
    compare_payload_subset(product_release, expected_product_subset, "release/product-release.json:", issues)
    if not source_commit_is_acceptable(product_release.get("source_commit", "")):
        issues.append(
            "release/product-release.json:source_commit is not HEAD and not an ancestor of HEAD"
        )

    expected_census_subset = {
        "tracked_file_count": len(tracked),
        "counts_by_extension": truth.count_by_extension(tracked),
        "counts_by_family": truth.count_by_family(tracked),
        "workspace_member_count": len(workspace_members),
        "tracked_rust_lines": rust_lines,
        "zero_unclassified_assertion": True,
    }
    compare_payload_subset(
        private_census,
        expected_census_subset,
        "release/private_source_census.json:",
        issues,
    )

    expected_export_subset = {
        "version": version,
        "release_tag": f"v{version}",
        "working_tree_dirty": truth.git_dirty(),
        "headline_counts": {
            "total_entries": len(ledger_entries),
            "mechanized_total": completion["mechanized_total"],
            "hypothesis_stated": completion["counts"]["hypothesis_stated"],
            "mechanized_implementation_claim": completion["assurance_class_counts"][
                "mechanized_implementation_claim"
            ],
            "hypothesis_carried_theorem": completion["assurance_class_counts"][
                "hypothesis_carried_theorem"
            ],
            "pending": completion["counts"]["pending"],
        },
        "support_matrix_summary": {
            "generated_for": support["generated_for"],
            "backend_count": len(support["backends"]),
            "frontend_count": len(support["frontends"]),
            "gadget_count": len(support["gadgets"]),
        },
    }
    compare_payload_subset(
        public_export,
        expected_export_subset,
        "release/provenance/public_attestation_export.json:",
        issues,
    )
    if not source_commit_is_acceptable(public_export.get("source_commit", "")):
        issues.append(
            "release/provenance/public_attestation_export.json:source_commit is not HEAD and not an ancestor of HEAD"
        )

    expected_midnight_taxonomy = truth.midnight_contract_taxonomy(version)
    expected_midnight_taxonomy.pop("generated_at", None)
    compare_payload_subset(
        midnight_taxonomy,
        expected_midnight_taxonomy,
        "release/midnight_universal_contract_taxonomy.json:",
        issues,
    )
    expected_evm_taxonomy = truth.evm_secondary_contract_taxonomy(version)
    expected_evm_taxonomy.pop("generated_at", None)
    compare_payload_subset(
        evm_taxonomy,
        expected_evm_taxonomy,
        "release/evm_secondary_contract_taxonomy.json:",
        issues,
    )
    expected_primitive_set = truth.guaranteed_circuit_primitive_set(version)
    expected_primitive_set.pop("generated_at", None)
    compare_payload_subset(
        primitive_set,
        expected_primitive_set,
        "release/guaranteed_circuit_primitive_set.json:",
        issues,
    )
    expected_midnight_readiness = strip_generated_at(
        truth.midnight_operator_readiness(version, support)
    )
    compare_payload_subset(
        strip_generated_at(midnight_readiness),
        expected_midnight_readiness,
        "release/midnight_operator_readiness.json:",
        issues,
    )
    expected_evm_readiness = strip_generated_at(truth.evm_operator_readiness(version))
    compare_payload_subset(
        strip_generated_at(evm_readiness),
        expected_evm_readiness,
        "release/evm_operator_readiness.json:",
        issues,
    )
    expected_alignment = strip_generated_at(
        truth.vision_alignment_report(
            version, completion, support, expected_midnight_readiness
        )
    )
    compare_payload_subset(
        strip_generated_at(alignment_report),
        expected_alignment,
        "release/vision_alignment_report.json:",
        issues,
    )

    if issues:
        for issue in issues:
            print(issue)
        return 1

    print("private truth surfaces are in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
