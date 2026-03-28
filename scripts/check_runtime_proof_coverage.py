#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
MANIFEST_PATH = ROOT / "zkf-ir-spec" / "runtime-proof-coverage-manifest.json"
FUNCTION_PATTERN = re.compile(
    r"^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
VALID_COVERAGE_STATES = {
    "implementation_mechanized",
    "shell_contract_mechanized",
    "partial_mechanized",
    "helper_or_model_only",
    "bounded_only",
    "unverified",
    "explicit_tcb_adapter",
}
COMPLETE_COVERAGE_STATES = {
    "implementation_mechanized",
    "shell_contract_mechanized",
    "explicit_tcb_adapter",
}
HELPER_SCOPE_PREFIXES = (
    "zkf-runtime::proof_",
    "zkf-distributed::proof_",
    "zkf-core::proof_",
    "zkf-lib::proof_",
)
HELPER_SCOPE_EXACT = {
    "zkf-runtime::buffer_bridge_core",
}
TARGET_LEDGER_PREFIXES = ("runtime.", "swarm.", "distributed.", "hybrid.")
TARGET_LEDGER_EXACT = {"pipeline.cli_runtime_path_composition"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def relative_file_function_count(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if FUNCTION_PATTERN.match(line))

def path_matches_includes(relative: str, include_paths: list[str] | None) -> bool:
    if not include_paths:
        return True
    for include in include_paths:
        normalized = include.rstrip("/")
        if include.endswith("/"):
            if relative == normalized or relative.startswith(f"{normalized}/"):
                return True
        elif relative == include:
            return True
    return False


def target_ledger_entry(entry: dict) -> bool:
    theorem_id = entry["theorem_id"]
    return theorem_id.startswith(TARGET_LEDGER_PREFIXES) or theorem_id in TARGET_LEDGER_EXACT


def helper_or_model_row(entry: dict) -> bool:
    scope = entry["scope"]
    assurance_class = entry.get("assurance_class")
    return (
        assurance_class == "model_only_claim"
        or scope.startswith(HELPER_SCOPE_PREFIXES)
        or scope in HELPER_SCOPE_EXACT
    )


def implementation_like_row(entry: dict) -> bool:
    return (
        entry["status"] in {"mechanized_local", "mechanized_generated"}
        and not helper_or_model_row(entry)
        and entry.get("assurance_class") != "bounded_check"
    )


def collect_actual_target_files(target: dict) -> dict[str, int]:
    root = ROOT / target["root"]
    exclude_files = set(target.get("exclude_files", []))
    include_paths = target.get("include_paths")
    actual: dict[str, int] = {}
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        if path.name in exclude_files or relative in exclude_files:
            continue
        if not path_matches_includes(relative, include_paths):
            continue
        fn_count = relative_file_function_count(path)
        if fn_count:
            actual[relative] = fn_count
    return actual


def summarize_entries(entries: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    file_counts: dict[str, int] = defaultdict(int)
    fn_counts: dict[str, int] = defaultdict(int)
    for entry in entries:
        state = entry["coverage_state"]
        file_counts[state] += 1
        fn_counts[state] += entry["fn_count"]
    return dict(file_counts), dict(fn_counts)


def audit_manifest(target: dict, ledger_entries: dict[str, dict]) -> tuple[dict[str, int], dict[str, int]]:
    target_name = target["name"]
    manifest_entries = target["entries"]
    manifest_files = {entry["path"]: entry for entry in manifest_entries}
    actual_files = collect_actual_target_files(target)

    missing_files = sorted(set(actual_files) - set(manifest_files))
    extra_files = sorted(set(manifest_files) - set(actual_files))
    require(not missing_files, f"{target_name}: manifest missing target files: {', '.join(missing_files)}")
    require(not extra_files, f"{target_name}: manifest lists non-target files: {', '.join(extra_files)}")

    for path, entry in manifest_files.items():
        state = entry["coverage_state"]
        require(
            state in VALID_COVERAGE_STATES,
            f"{target_name}:{path} has invalid coverage_state={state}",
        )
        require(
            actual_files[path] == entry["fn_count"],
            f"{target_name}:{path} recorded fn_count={entry['fn_count']} but actual count is {actual_files[path]}",
        )
        evidence_rows = entry.get("evidence_rows", [])
        for theorem_id in evidence_rows:
            require(
                theorem_id in ledger_entries,
                f"{target_name}:{path} references unknown theorem_id {theorem_id}",
            )

        if state == "implementation_mechanized":
            require(evidence_rows, f"{target_name}:{path} must cite implementation theorems")
            if not all(implementation_like_row(ledger_entries[theorem_id]) for theorem_id in evidence_rows):
                raise SystemExit(
                    f"{target_name}:{path} is marked implementation_mechanized but cites helper/model/bounded evidence"
                )
        elif state == "shell_contract_mechanized":
            require(evidence_rows, f"{target_name}:{path} must cite shell-contract theorems")
            if not all(implementation_like_row(ledger_entries[theorem_id]) for theorem_id in evidence_rows):
                raise SystemExit(
                    f"{target_name}:{path} is marked shell_contract_mechanized but cites helper/model/bounded evidence"
                )
        elif state == "partial_mechanized":
            require(evidence_rows, f"{target_name}:{path} must cite at least one theorem row")
            if not any(implementation_like_row(ledger_entries[theorem_id]) for theorem_id in evidence_rows):
                raise SystemExit(
                    f"{target_name}:{path} is marked partial_mechanized but cites no implementation-level evidence"
                )
        elif state == "helper_or_model_only":
            require(evidence_rows, f"{target_name}:{path} must cite helper/model evidence")
            if not all(helper_or_model_row(ledger_entries[theorem_id]) for theorem_id in evidence_rows):
                raise SystemExit(
                    f"{target_name}:{path} is marked helper_or_model_only but cites non-helper evidence"
                )
        elif state == "bounded_only":
            require(evidence_rows, f"{target_name}:{path} must cite bounded evidence")
            if not all(ledger_entries[theorem_id]["status"] == "bounded_checked" for theorem_id in evidence_rows):
                raise SystemExit(
                    f"{target_name}:{path} is marked bounded_only but cites non-bounded evidence"
                )
        elif state == "unverified":
            require(
                not evidence_rows,
                f"{target_name}:{path} is marked unverified but still cites theorem rows",
            )
        elif state == "explicit_tcb_adapter":
            require(
                entry.get("notes"),
                f"{target_name}:{path} is an explicit_tcb_adapter and must explain its trust boundary",
            )

    return summarize_entries(manifest_entries)


def audit_complete_requirement(targets: list[dict], ledger_entries: dict[str, dict]) -> None:
    incomplete_paths: list[str] = []
    relevant_theorem_ids: set[str] = set()
    for target in targets:
        for entry in target["entries"]:
            if entry["coverage_state"] not in COMPLETE_COVERAGE_STATES:
                incomplete_paths.append(f"{target['name']}:{entry['path']}")
            relevant_theorem_ids.update(entry.get("evidence_rows", []))

    blocking_rows = []
    for theorem_id in sorted(relevant_theorem_ids):
        entry = ledger_entries[theorem_id]
        if entry["status"] == "bounded_checked" or helper_or_model_row(entry):
            blocking_rows.append(theorem_id)

    failures: list[str] = []
    if incomplete_paths:
        failures.append(
            f"{len(incomplete_paths)} file(s) are not at a completion state: "
            + ", ".join(incomplete_paths[:16])
            + (" ..." if len(incomplete_paths) > 16 else "")
        )
    if blocking_rows:
        failures.append(
            f"{len(blocking_rows)} runtime/distributed ledger row(s) remain helper/model/bounded: "
            + ", ".join(sorted(blocking_rows))
        )
    if failures:
        raise SystemExit("runtime proof coverage is not complete: " + "; ".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the full-runtime proof coverage manifest against the current repo."
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail unless every target file is implementation/shell-contract mechanized or an explicit TCB adapter",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="limit validation to one or more named manifest targets",
    )
    args = parser.parse_args()

    ledger = load_json(LEDGER_PATH)
    manifest = load_json(MANIFEST_PATH)
    require(
        manifest.get("schema") == "zkf-runtime-proof-coverage-v1",
        f"{MANIFEST_PATH} must use schema zkf-runtime-proof-coverage-v1",
    )

    ledger_entries = {entry["theorem_id"]: entry for entry in ledger["entries"]}
    target_summaries = []
    total_files = 0
    total_functions = 0
    targets = manifest["targets"]
    if args.target:
        requested = set(args.target)
        targets = [target for target in manifest["targets"] if target["name"] in requested]
        found = {target["name"] for target in targets}
        missing = sorted(requested - found)
        require(not missing, f"unknown manifest target(s): {', '.join(missing)}")

    for target in targets:
        file_counts, fn_counts = audit_manifest(target, ledger_entries)
        total_files += sum(file_counts.values())
        total_functions += sum(fn_counts.values())
        target_summaries.append((target["name"], file_counts, fn_counts))

    if args.require_complete:
        audit_complete_requirement(targets, ledger_entries)

    print(
        f"runtime proof coverage manifest OK: {total_files} files / {total_functions} functions"
    )
    for target_name, file_counts, fn_counts in target_summaries:
        ordered_states = [
            state
            for state in (
                "implementation_mechanized",
                "shell_contract_mechanized",
                "partial_mechanized",
                "helper_or_model_only",
                "bounded_only",
                "unverified",
                "explicit_tcb_adapter",
            )
            if file_counts.get(state, 0)
        ]
        summary = ", ".join(
            f"{state}={file_counts[state]} files/{fn_counts.get(state, 0)} fns"
            for state in ordered_states
        )
        print(f"  {target_name}: {summary}")


if __name__ == "__main__":
    main()
