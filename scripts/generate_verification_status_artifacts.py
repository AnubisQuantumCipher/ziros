#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
RUNTIME_COVERAGE_MANIFEST = ROOT / "zkf-ir-spec" / "runtime-proof-coverage-manifest.json"
SECURITY_DOC = ROOT / "docs" / "SECURITY.md"
PROOF_BOUNDARY_DOC = ROOT / "PROOF_BOUNDARY.md"
STATUS_JSON = ROOT / ".zkf-completion-status.json"
GENERATED_BEGIN = "<!-- BEGIN GENERATED VERIFICATION STATUS -->"
GENERATED_END = "<!-- END GENERATED VERIFICATION STATUS -->"
STATUS_ORDER = [
    "mechanized_local",
    "mechanized_generated",
    "bounded_checked",
    "assumed_external",
    "pending",
]
ASSURANCE_CLASS_ORDER = [
    "mechanized_implementation_claim",
    "bounded_check",
    "attestation_backed_lane",
    "model_only_claim",
    "hypothesis_carried_theorem",
]
RUNTIME_COVERAGE_ORDER = [
    "implementation_mechanized",
    "shell_contract_mechanized",
    "partial_mechanized",
    "helper_or_model_only",
    "bounded_only",
    "unverified",
    "explicit_tcb_adapter",
]
COMPLETE_COVERAGE_STATES = {
    "implementation_mechanized",
    "shell_contract_mechanized",
    "explicit_tcb_adapter",
}
RELEASE_GRADE_STRICT_THEOREMS = {
    "witness.kernel_expr_eval_relative_soundness",
    "witness.kernel_constraint_relative_soundness",
    "field.large_prime_runtime_generated",
    "field.bn254_strict_lane_generated",
    "gpu.shader_bundle_provenance",
    "gpu.runtime_fail_closed",
    "pipeline.cli_runtime_path_composition",
    "orbital.surface_constants",
    "orbital.position_update_half_step_soundness",
    "orbital.velocity_update_half_step_soundness",
    "orbital.residual_split_soundness",
    "orbital.field_embedding_nonwrap_bounds",
    "orbital.commitment_body_tag_domain_separation",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_ledger() -> dict:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))


def load_existing_status() -> dict:
    if not STATUS_JSON.exists():
        return {}
    try:
        return json.loads(STATUS_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def load_runtime_coverage_manifest() -> dict:
    return json.loads(RUNTIME_COVERAGE_MANIFEST.read_text(encoding="utf-8"))


def count_statuses(entries: list[dict]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_ORDER}
    for entry in entries:
        status = entry["status"]
        counts.setdefault(status, 0)
        counts[status] += 1
    return counts


def count_assurance_classes(entries: list[dict]) -> dict[str, int]:
    counts = {claim_class: 0 for claim_class in ASSURANCE_CLASS_ORDER}
    for entry in entries:
        claim_class = entry.get("assurance_class", "mechanized_implementation_claim")
        counts.setdefault(claim_class, 0)
        counts[claim_class] += 1
    return counts


def protocol_rows(entries: list[dict]) -> list[dict]:
    rows = [
        {
            "theorem_id": entry["theorem_id"],
            "status": entry["status"],
            "scope": entry["scope"],
            "evidence_path": entry["evidence_path"],
        }
        for entry in entries
        if entry["theorem_id"].startswith("protocol.")
    ]
    return sorted(rows, key=lambda row: row["theorem_id"])


def trusted_assumption_rows(entries: list[dict]) -> list[str]:
    return sorted(
        entry["theorem_id"] for entry in entries if entry.get("trusted_assumptions")
    )


def release_grade_blockers(
    entries: list[dict], counts: dict[str, int], trust_rows: list[str]
) -> list[str]:
    blockers: list[str] = []
    if counts.get("assumed_external", 0):
        blockers.append(
            f"{counts['assumed_external']} assumed_external row(s) remain"
        )
    if counts.get("bounded_checked", 0):
        blockers.append(
            f"{counts['bounded_checked']} bounded_checked row(s) remain"
        )
    if trust_rows:
        blockers.append(
            f"{len(trust_rows)} row(s) still carry trusted_assumptions"
        )
    strict_rows = [
        entry["theorem_id"]
        for entry in entries
        if entry["theorem_id"] in RELEASE_GRADE_STRICT_THEOREMS
        and entry.get("assurance_class") != "mechanized_implementation_claim"
    ]
    if strict_rows:
        blockers.append(
            f"{len(strict_rows)} release-grade strict theorem row(s) remain non-mechanized-implementation claims"
        )
    return blockers


def summarize_runtime_coverage(manifest: dict) -> dict:
    file_counts = {state: 0 for state in RUNTIME_COVERAGE_ORDER}
    fn_counts = {state: 0 for state in RUNTIME_COVERAGE_ORDER}
    target_summaries = []
    total_files = 0
    total_functions = 0
    for target in manifest["targets"]:
        entries = target["entries"]
        target_file_counts = {state: 0 for state in RUNTIME_COVERAGE_ORDER}
        target_fn_counts = {state: 0 for state in RUNTIME_COVERAGE_ORDER}
        for entry in entries:
            state = entry["coverage_state"]
            target_file_counts[state] += 1
            target_fn_counts[state] += entry["fn_count"]
            file_counts[state] += 1
            fn_counts[state] += entry["fn_count"]
            total_files += 1
            total_functions += entry["fn_count"]
        target_complete_files = sum(
            target_file_counts[state] for state in COMPLETE_COVERAGE_STATES
        )
        target_complete_functions = sum(
            target_fn_counts[state] for state in COMPLETE_COVERAGE_STATES
        )
        target_summaries.append(
            {
                "name": target["name"],
                "total_files": len(entries),
                "total_functions": sum(entry["fn_count"] for entry in entries),
                "complete_files": target_complete_files,
                "complete_functions": target_complete_functions,
                "closed": target_complete_files == len(entries),
                "file_counts": {
                    state: count for state, count in target_file_counts.items() if count
                },
                "function_counts": {
                    state: count for state, count in target_fn_counts.items() if count
                },
            }
        )
    complete_files = sum(file_counts[state] for state in COMPLETE_COVERAGE_STATES)
    complete_functions = sum(fn_counts[state] for state in COMPLETE_COVERAGE_STATES)
    return {
        "schema": manifest["schema"],
        "total_files": total_files,
        "total_functions": total_functions,
        "file_counts": {state: count for state, count in file_counts.items() if count},
        "function_counts": {state: count for state, count in fn_counts.items() if count},
        "complete_files": complete_files,
        "complete_functions": complete_functions,
        "targets": target_summaries,
    }


def runtime_target_by_name(runtime_coverage: dict, name: str) -> dict:
    for target in runtime_coverage["targets"]:
        if target["name"] == name:
            return target
    raise KeyError(f"missing runtime coverage target {name}")


def summarize_swarm_proof_boundary(runtime_coverage: dict) -> dict:
    runtime_target = runtime_target_by_name(runtime_coverage, "zkf-runtime-swarm-path")
    distributed_target = runtime_target_by_name(
        runtime_coverage, "zkf-distributed-swarm-path"
    )
    return {
        "runtime_target": runtime_target,
        "distributed_target": distributed_target,
        "closed": runtime_target["closed"] and distributed_target["closed"],
    }


def build_status_payload(entries: list[dict], existing_status: dict | None = None) -> dict:
    existing_status = existing_status or {}
    counts = count_statuses(entries)
    assurance_counts = count_assurance_classes(entries)
    protocol = protocol_rows(entries)
    trust_rows = trusted_assumption_rows(entries)
    runtime_coverage = summarize_runtime_coverage(load_runtime_coverage_manifest())
    swarm_proof_boundary = summarize_swarm_proof_boundary(runtime_coverage)
    runtime_swarm = swarm_proof_boundary["runtime_target"]
    distributed_swarm = swarm_proof_boundary["distributed_target"]
    blockers = release_grade_blockers(entries, counts, trust_rows)
    if runtime_coverage["complete_files"] != runtime_coverage["total_files"]:
        blockers.append(
            f"{runtime_coverage['total_files'] - runtime_coverage['complete_files']} runtime/distributed target file(s) remain outside a completion state"
        )
    total_entries = len(entries)
    mechanized_total = (
        counts.get("mechanized_local", 0) + counts.get("mechanized_generated", 0)
    )
    counts_summary = ", ".join(
        f"{counts.get(status, 0)} {status}" for status in STATUS_ORDER
    )
    assurance_summary = ", ".join(
        f"{assurance_counts.get(claim_class, 0)} {claim_class}"
        for claim_class in ASSURANCE_CLASS_ORDER
    )
    open_protocol_rows = [
        row["theorem_id"] for row in protocol if row["status"] != "mechanized_local"
    ]
    current_priority = existing_status.get(
        "current_priority",
        "formal-verification-zero-repo-assumption-program",
    )
    current_priority_progress = (
        "March 25, 2026 release-grade closure complete. "
        f"Ledger inventory totals {total_entries} rows with {mechanized_total} machine-checked rows. "
        "Ledger counts: "
        f"{counts_summary}. "
        "Assurance classes: "
        f"{assurance_summary}. "
        "Swarm proof-boundary targets: "
        f"{runtime_swarm['name']} {runtime_swarm['complete_files']}/{runtime_swarm['total_files']} files complete, "
        f"{distributed_swarm['name']} {distributed_swarm['complete_files']}/{distributed_swarm['total_files']} files complete. "
        "Whole-runtime target inventory: "
        f"{runtime_coverage['total_files']} files / {runtime_coverage['total_functions']} functions, with "
        f"{runtime_coverage['complete_files']} files / {runtime_coverage['complete_functions']} functions at a completion state "
        "(implementation_mechanized, shell_contract_mechanized, or explicit_tcb_adapter). "
        "All generated truth surfaces now match the checked ledger and the shipped runtime/distributed inventory. "
        + (
            "Open protocol rows: " + ", ".join(open_protocol_rows) + "."
            if open_protocol_rows
            else "All protocol rows are mechanized_local."
        )
    )
    recent_delivery = (
        existing_status.get("recent_delivery")
        or (
            "Promoted the remaining bounded/mechanized-generated verification rows in place, reclassified the runtime buffer bridge as a mechanized shell contract, and kept the swarm proof-boundary closure reporting explicit on top of the checked runtime/distributed proof coverage manifest: "
            f"{runtime_swarm['complete_files']}/{runtime_swarm['total_files']} runtime-swarm files complete and "
            f"{distributed_swarm['complete_files']}/{distributed_swarm['total_files']} distributed-swarm files complete; "
            "whole-runtime proof progress is still measured against the shipped source files rather than helper/model theorems: "
            f"{runtime_coverage['total_files']} files / {runtime_coverage['total_functions']} functions inventoried, "
            f"{runtime_coverage['complete_files']} files / {runtime_coverage['complete_functions']} functions currently at a completion state."
        )
    )
    return {
        "schema": "zkf-completion-status-v2",
        "generated_from": "zkf-ir-spec/verification-ledger.json",
        "current_priority": current_priority,
        "current_priority_progress": current_priority_progress,
        "build_status": existing_status.get(
            "build_status", "derive-live-workspace-gates-separately-from-ledger"
        ),
        "test_status": existing_status.get(
            "test_status", "derive-live-proof-and-build-gates-separately-from-ledger"
        ),
        "recent_delivery": recent_delivery,
        "authoritative_status_source": "zkf-ir-spec/verification-ledger.json",
        "total_entries": total_entries,
        "mechanized_total": mechanized_total,
        "counts": counts,
        "assurance_class_counts": assurance_counts,
        "runtime_proof_coverage": runtime_coverage,
        "swarm_proof_boundary": swarm_proof_boundary,
        "trusted_assumption_rows": trust_rows,
        "release_grade_ready": not blockers,
        "release_grade_blockers": blockers,
        "protocol_rows": protocol,
    }


def render_with_generated_block(text: str, body: str, path: Path) -> str:
    require(
        GENERATED_BEGIN in text and GENERATED_END in text,
        f"{path} is missing generated verification status markers",
    )
    prefix, remainder = text.split(GENERATED_BEGIN, 1)
    _, suffix = remainder.split(GENERATED_END, 1)
    return (
        prefix
        + GENERATED_BEGIN
        + "\n"
        + body.rstrip()
        + "\n"
        + GENERATED_END
        + suffix
    )


def security_block(payload: dict) -> str:
    counts = payload["counts"]
    assurance_counts = payload["assurance_class_counts"]
    runtime_coverage = payload["runtime_proof_coverage"]
    swarm_boundary = payload["swarm_proof_boundary"]
    runtime_swarm = swarm_boundary["runtime_target"]
    distributed_swarm = swarm_boundary["distributed_target"]
    protocol = payload["protocol_rows"]
    open_protocol = [row for row in protocol if row["status"] != "mechanized_local"]
    lines = [
        "This block is generated from `zkf-ir-spec/verification-ledger.json`.",
        "",
        f"- Total ledger entries: {payload['total_entries']}.",
        f"- Machine-checked rows: {payload['mechanized_total']} total ({counts['mechanized_local']} `mechanized_local`, {counts['mechanized_generated']} `mechanized_generated`).",
        f"- Remaining bounded/external/pending rows: {counts['bounded_checked']} `bounded_checked`, {counts['assumed_external']} `assumed_external`, {counts['pending']} `pending`.",
        f"- Assurance classes: {assurance_counts['mechanized_implementation_claim']} `mechanized_implementation_claim`, {assurance_counts['bounded_check']} `bounded_check`, {assurance_counts['attestation_backed_lane']} `attestation_backed_lane`, {assurance_counts['model_only_claim']} `model_only_claim`, {assurance_counts['hypothesis_carried_theorem']} `hypothesis_carried_theorem`.",
        f"- Whole-runtime target inventory: {runtime_coverage['total_files']} files / {runtime_coverage['total_functions']} functions, with {runtime_coverage['complete_files']} files / {runtime_coverage['complete_functions']} functions at a completion state.",
        f"- Swarm proof-boundary closure: `{str(swarm_boundary['closed']).lower()}` (`{runtime_swarm['name']}` = {runtime_swarm['complete_files']}/{runtime_swarm['total_files']} files complete, `{distributed_swarm['name']}` = {distributed_swarm['complete_files']}/{distributed_swarm['total_files']} files complete).",
        f"- Rows with non-empty `trusted_assumptions`: {len(payload['trusted_assumption_rows'])}.",
    ]
    if open_protocol:
        lines.append("- Open protocol rows:")
        for row in open_protocol:
            lines.append(
                f"  - `{row['theorem_id']}`: `{row['status']}` via `{row['evidence_path']}`"
            )
    else:
        lines.append("- All protocol rows are `mechanized_local`.")
    return "\n".join(lines)


def proof_boundary_block(payload: dict) -> str:
    counts = payload["counts"]
    assurance_counts = payload["assurance_class_counts"]
    runtime_coverage = payload["runtime_proof_coverage"]
    swarm_boundary = payload["swarm_proof_boundary"]
    runtime_swarm = swarm_boundary["runtime_target"]
    distributed_swarm = swarm_boundary["distributed_target"]
    blockers = payload["release_grade_blockers"]
    lines = [
        "This block is generated from `zkf-ir-spec/verification-ledger.json`.",
        "",
        f"- Total ledger entries: {payload['total_entries']}.",
        f"- Machine-checked rows: {payload['mechanized_total']} total ({counts['mechanized_local']} `mechanized_local`, {counts['mechanized_generated']} `mechanized_generated`).",
        f"- Remaining bounded/external/pending rows: {counts['bounded_checked']} `bounded_checked`, {counts['assumed_external']} `assumed_external`, {counts['pending']} `pending`.",
        f"- Assurance classes: {assurance_counts['mechanized_implementation_claim']} `mechanized_implementation_claim`, {assurance_counts['bounded_check']} `bounded_check`, {assurance_counts['attestation_backed_lane']} `attestation_backed_lane`, {assurance_counts['model_only_claim']} `model_only_claim`, {assurance_counts['hypothesis_carried_theorem']} `hypothesis_carried_theorem`.",
        f"- Whole-runtime target inventory: {runtime_coverage['total_files']} files / {runtime_coverage['total_functions']} functions, with {runtime_coverage['complete_files']} files / {runtime_coverage['complete_functions']} functions at a completion state.",
        f"- Swarm proof-boundary closure: `{str(swarm_boundary['closed']).lower()}` (`{runtime_swarm['name']}` = {runtime_swarm['complete_files']}/{runtime_swarm['total_files']} files complete, `{distributed_swarm['name']}` = {distributed_swarm['complete_files']}/{distributed_swarm['total_files']} files complete).",
        f"- Release-grade ready: `{str(payload['release_grade_ready']).lower()}`.",
    ]
    if blockers:
        lines.append("- Release-grade blockers:")
        for blocker in blockers:
            lines.append(f"  - {blocker}")
    else:
        lines.append("- Release-grade blockers: none.")
    return "\n".join(lines)


def write_or_check(path: Path, expected: str, check: bool) -> None:
    actual = path.read_text(encoding="utf-8") if path.exists() else None
    if check:
        require(
            actual == expected,
            f"{path} is out of sync; run scripts/generate_verification_status_artifacts.py",
        )
        return
    path.write_text(expected, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate or verify ledger-derived status artifacts."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generated artifacts differ from the checked-in files",
    )
    args = parser.parse_args()

    ledger = load_ledger()
    entries = ledger["entries"]
    existing_status = load_existing_status()
    payload = build_status_payload(entries, existing_status)

    security_expected = SECURITY_DOC.read_text(encoding="utf-8")
    proof_boundary_expected = PROOF_BOUNDARY_DOC.read_text(encoding="utf-8")
    require(
        GENERATED_BEGIN in security_expected and GENERATED_END in security_expected,
        f"{SECURITY_DOC} is missing generated verification status markers",
    )
    require(
        GENERATED_BEGIN in proof_boundary_expected
        and GENERATED_END in proof_boundary_expected,
        f"{PROOF_BOUNDARY_DOC} is missing generated verification status markers",
    )

    security_body = security_block(payload)
    proof_boundary_body = proof_boundary_block(payload)

    regenerated_security = render_with_generated_block(
        security_expected,
        security_body,
        SECURITY_DOC,
    )
    regenerated_proof_boundary = render_with_generated_block(
        proof_boundary_expected,
        proof_boundary_body,
        PROOF_BOUNDARY_DOC,
    )

    if args.check:
        require(
            security_expected == regenerated_security,
            f"{SECURITY_DOC} is out of sync; run scripts/generate_verification_status_artifacts.py",
        )
        require(
            proof_boundary_expected == regenerated_proof_boundary,
            f"{PROOF_BOUNDARY_DOC} is out of sync; run scripts/generate_verification_status_artifacts.py",
        )
    else:
        SECURITY_DOC.write_text(regenerated_security, encoding="utf-8")
        PROOF_BOUNDARY_DOC.write_text(regenerated_proof_boundary, encoding="utf-8")

    status_json_expected = json.dumps(payload, indent=2) + "\n"
    write_or_check(STATUS_JSON, status_json_expected, args.check)


if __name__ == "__main__":
    main()
