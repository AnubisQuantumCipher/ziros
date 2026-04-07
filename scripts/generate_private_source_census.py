#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "zkf-ir-spec" / "runtime-proof-coverage-manifest.json"
OUT_PATH = ROOT / "release" / "private_source_census.json"


def canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def repo_relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_runtime_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def runtime_coverage_lookup() -> dict[str, str]:
    manifest = load_runtime_manifest()
    lookup: dict[str, str] = {}
    for target in manifest["targets"]:
        root = target["root"].rstrip("/")
        for entry in target["entries"]:
            lookup[f"{root}/{entry['path']}"] = entry["coverage_state"]
    return lookup


def git_ls_files() -> list[str]:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        text=False,
    )
    return [item.decode("utf-8") for item in output.split(b"\x00") if item]


def coverage_state_for(path: str, runtime_lookup: dict[str, str]) -> str:
    runtime_state = runtime_lookup.get(path)
    if runtime_state == "explicit_tcb_adapter":
        return "explicit_tcb"
    if runtime_state in {"implementation_mechanized", "shell_contract_mechanized"}:
        return "mechanized"
    if runtime_state in {"partial_mechanized", "helper_or_model_only", "bounded_only"}:
        return "bounded"
    if path.startswith("vendor/") or path.startswith("release/private_bundle/"):
        return "excluded_from_release"
    if "/proofs/" in path or path.endswith((".lean", ".v", ".fst", ".fsti")):
        return "mechanized"
    if path.endswith("_spec.rs") or "/proof_" in path:
        return "mechanized"
    return "bounded"


def trust_band_for(path: str) -> str:
    if path.startswith("release/") or path.startswith(".github/"):
        return "publication_critical"
    if path in {
        ".zkf-completion-status.json",
        "PROOF_BOUNDARY.md",
        "README.md",
        "support-matrix.json",
    } or path.startswith("docs/") or path.startswith("scripts/"):
        return "release_critical"
    if (
        path.startswith("tests/")
        or "/tests/" in path
        or path.startswith("zkf-examples/")
        or "/examples/" in path
    ):
        return "noncritical_support"
    return "sealed_core"


def included_in_release(path: str, coverage_state: str) -> bool:
    if coverage_state == "excluded_from_release":
        return False
    if path.startswith("vendor/") or path.startswith("release/private_bundle/"):
        return False
    return True


def build_entries() -> list[dict]:
    runtime_lookup = runtime_coverage_lookup()
    entries: list[dict] = []
    for rel in git_ls_files():
        digest = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        coverage_state = coverage_state_for(rel, runtime_lookup)
        entries.append(
            {
                "path": rel,
                "sha256": digest,
                "trust_band": trust_band_for(rel),
                "coverage_state": coverage_state,
                "included_in_release": included_in_release(rel, coverage_state),
            }
        )
    return entries


def main() -> None:
    entries = build_entries()
    trust_band_counts: dict[str, int] = {}
    coverage_state_counts: dict[str, int] = {}
    by_band_and_coverage: dict[str, dict[str, int]] = {}
    for entry in entries:
        trust_band_counts[entry["trust_band"]] = trust_band_counts.get(entry["trust_band"], 0) + 1
        coverage_state_counts[entry["coverage_state"]] = (
            coverage_state_counts.get(entry["coverage_state"], 0) + 1
        )
        bucket = by_band_and_coverage.setdefault(entry["trust_band"], {})
        bucket[entry["coverage_state"]] = bucket.get(entry["coverage_state"], 0) + 1

    payload_core = {
        "schema": "ziros-private-source-census-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            text=True,
        ).strip(),
        "working_tree_dirty": bool(
            subprocess.check_output(
                ["git", "-C", str(ROOT), "status", "--short"],
                text=True,
            ).strip()
        ),
        "total_tracked_files": len(entries),
        "zero_unclassified_files": all(
            entry["trust_band"] and entry["coverage_state"] for entry in entries
        ),
        "trust_band_counts": trust_band_counts,
        "coverage_state_counts": coverage_state_counts,
        "by_trust_band_and_coverage": by_band_and_coverage,
        "release_included_counts": {
            "included": sum(1 for entry in entries if entry["included_in_release"]),
            "excluded": sum(1 for entry in entries if not entry["included_in_release"]),
        },
        "entries": entries,
    }
    payload_core["source_census_root"] = canonical_sha256(entries)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload_core, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
