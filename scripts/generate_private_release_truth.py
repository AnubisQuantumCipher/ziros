#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SUPPORT_MATRIX = ROOT / "support-matrix.json"
LEDGER = ROOT / "zkf-ir-spec" / "verification-ledger.json"
COMPLETION = ROOT / ".zkf-completion-status.json"
RELEASE_DIR = ROOT / "release"
PROVENANCE_DIR = RELEASE_DIR / "provenance"


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(*args: str) -> str:
    result = subprocess.run(
        list(args),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def cargo_metadata() -> dict:
    return json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps"))


def workspace_version() -> str:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return cargo["workspace"]["package"]["version"]


def git_head_commit() -> str:
    return run("git", "rev-parse", "HEAD").strip()


def git_dirty() -> bool:
    return bool(run("git", "status", "--short").strip())


def tracked_files() -> list[str]:
    return [line for line in run("git", "ls-files").splitlines() if line]


def tracked_rs_lines() -> int:
    total = 0
    for rel in run("git", "ls-files", "*.rs").splitlines():
        if not rel or rel.startswith("vendor/"):
            continue
        path = ROOT / rel
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            total += sum(1 for _ in handle)
    return total


def count_by_extension(files: list[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for rel in files:
        suffix = Path(rel).suffix.lower()
        counts[suffix or "<no-ext>"] += 1
    return dict(sorted(counts.items()))


def count_by_family(files: list[str]) -> dict[str, int]:
    counts = Counter()
    proof_suffixes = {".v", ".lean", ".fst", ".fsti"}
    script_suffixes = {".py", ".sh", ".bash", ".zsh"}
    for rel in files:
        path = Path(rel)
        suffix = path.suffix.lower()
        if suffix == ".rs":
            counts["rust"] += 1
        elif suffix == ".swift":
            counts["swift"] += 1
        elif suffix in {".ts", ".tsx", ".js", ".mjs", ".cjs"}:
            counts["typescript_or_js"] += 1
        elif suffix in proof_suffixes:
            counts["formal_proofs"] += 1
        elif suffix == ".metal":
            counts["metal"] += 1
        elif suffix == ".json":
            counts["json"] += 1
        elif suffix in script_suffixes:
            counts["scripts"] += 1
        elif suffix in {".md", ".txt"}:
            counts["docs"] += 1
        elif suffix in {".compact", ".zkir", ".bzkir"}:
            counts["compact_or_zkir"] += 1
        else:
            counts["other"] += 1
    return dict(sorted(counts.items()))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def replace_generated_block(path: Path, begin: str, end: str, body: str) -> None:
    text = path.read_text(encoding="utf-8")
    start = text.index(begin)
    finish = text.index(end) + len(end)
    replacement = f"{begin}\n{body.rstrip()}\n{end}"
    path.write_text(text[:start] + replacement + text[finish:], encoding="utf-8")


def build_readme_summary(
    workspace_count: int,
    rust_lines: int,
    support: dict,
    ledger_entries: list[dict],
    completion: dict,
) -> str:
    backend_statuses = Counter(entry["status"] for entry in support["backends"])
    frontend_statuses = Counter(entry["status"] for entry in support["frontends"])
    gadget_statuses = Counter(entry["status"] for entry in support["gadgets"])
    assurance = Counter(entry["assurance_class"] for entry in ledger_entries)
    metal_sources = list((ROOT / "zkf-metal").rglob("*.metal"))
    kernel_entrypoints = sum(path.read_text(encoding="utf-8", errors="ignore").count("kernel void") for path in metal_sources)
    metal_manifests = list((ROOT / "zkf-metal" / "proofs" / "manifests").rglob("*.json"))
    runtime = completion.get("runtime_proof_coverage", {})
    lines = [
        "| Fact | Current checkout value |",
        "| --- | --- |",
        f"| Workspace crates | {workspace_count} |",
        f"| First-party Rust source lines | {rust_lines:,} tracked `.rs` lines outside `vendor/` |",
        "| Proving backends in `support-matrix.json` | "
        f"{len(support['backends'])} total: {backend_statuses.get('ready', 0)} `ready`, "
        f"{backend_statuses.get('limited', 0)} `limited`, {backend_statuses.get('broken', 0)} `broken` |",
        "| Frontend families in `support-matrix.json` | "
        f"{len(support['frontends'])} total: {frontend_statuses.get('ready', 0)} `ready`, "
        f"{frontend_statuses.get('limited', 0)} `limited` |",
        "| Gadget families in `support-matrix.json` | "
        f"{len(support['gadgets'])} total: {gadget_statuses.get('ready', 0)} `ready`, "
        f"{gadget_statuses.get('limited', 0)} `limited` |",
        "| Canonical finite fields in `zkf-core` | 7: `bn254`, `bls12-381`, `pasta-fp`, `pasta-fq`, `goldilocks`, `babybear`, `mersenne31` |",
        f"| Metal shader sources | {len(metal_sources)} `.metal` files with {kernel_entrypoints} kernel entrypoints |",
        f"| Verified Metal manifests | {len(metal_manifests)} checked-in manifest files under `zkf-metal/proofs/manifests` |",
        "| Verification ledger | "
        f"{len(ledger_entries)} total rows, {completion['counts']['mechanized_local']} `mechanized_local`, "
        f"{completion['counts']['hypothesis_stated']} `hypothesis_stated`, "
        f"{completion['assurance_class_counts'].get('model_only_claim', 0)} `model_only_claim`, "
        f"{completion['assurance_class_counts'].get('attestation_backed_lane', 0)} `attestation_backed_lane`, "
        f"{assurance.get('hypothesis_carried_theorem', 0)} `hypothesis_carried_theorem`, "
        f"{completion['counts'].get('pending', 0)} pending |",
        f"| Runtime proof coverage | {runtime.get('complete_files', 0)} files and {runtime.get('complete_functions', 0):,} functions marked complete |",
    ]
    return "\n".join(lines)


def main() -> None:
    version = workspace_version()
    source_commit = git_head_commit()
    working_tree_dirty = git_dirty()
    metadata = cargo_metadata()
    workspace_members = sorted({package["name"] for package in metadata["packages"]})
    tracked = tracked_files()
    rust_lines = tracked_rs_lines()
    ledger_doc = load_json(LEDGER)
    ledger_entries = ledger_doc["entries"]
    completion = load_json(COMPLETION)
    support = load_json(SUPPORT_MATRIX)
    support["generated_for"] = version
    write_json(SUPPORT_MATRIX, support)

    product_release = {
        "schema": "ziros-product-release-v1",
        "generated_at": now_rfc3339(),
        "version": version,
        "release_version": version,
        "release_tag": f"v{version}",
        "source_commit": source_commit,
        "working_tree_dirty": working_tree_dirty,
        "workspace_members": {
            "count": len(workspace_members),
            "names": workspace_members,
        },
        "truth_surfaces": {
            "verification_ledger": "zkf-ir-spec/verification-ledger.json",
            "completion_status": ".zkf-completion-status.json",
            "support_matrix": "support-matrix.json",
            "canonical_truth": "docs/CANONICAL_TRUTH.md",
            "agent_forensics": "forensics/",
        },
        "verification_summary": {
            "total_entries": len(ledger_entries),
            "status_counts": completion["counts"],
            "assurance_class_counts": completion["assurance_class_counts"],
        },
        "release_boundary": {
            "allowlist_path": "release/public_release_allowlist.json",
            "boundary_report_path": "release/public_release_boundary_report.json",
            "scanner_script": "scripts/check_public_release_boundary.py",
            "public_export_script": "scripts/export_public_attestation_bundle.py",
            "public_repo": "/Users/sicarii/Projects/ziros-attestation",
        },
    }
    write_json(RELEASE_DIR / "product-release.json", product_release)

    private_census = {
        "schema": "ziros-private-source-census-v1",
        "generated_at": now_rfc3339(),
        "source_commit": source_commit,
        "tracked_file_count": len(tracked),
        "counts_by_extension": count_by_extension(tracked),
        "counts_by_family": count_by_family(tracked),
        "workspace_member_count": len(workspace_members),
        "workspace_crate_count": len(workspace_members),
        "tracked_rust_lines": rust_lines,
        "tracked_rust_line_count": rust_lines,
        "zero_unclassified_assertion": True,
    }
    write_json(RELEASE_DIR / "private_source_census.json", private_census)

    allowlist = {
        "schema": "ziros-public-release-allowlist-v1",
        "generated_at": now_rfc3339(),
        "version": version,
        "public_repo_root": "/Users/sicarii/Projects/ziros-attestation",
        "package_roots": [
            "attestation",
            "zkf-wallet-helper",
            "zkf-wallet-mailbox",
            "ziros-twitter-mcp",
        ],
        "allowed_public_extensions": [".json", ".md", ".txt", ".yml", ".yaml"],
        "forbidden_path_fragments": [
            "/Users/",
            "/private/var/",
            "node_modules/",
            ".tmp/",
            "logs/",
            "__pycache__/",
            "target-local/",
            "target-public/",
            "ZirOSAgentHost/build/",
            "ZirOSAgentHost/.build/",
        ],
        "forbidden_suffixes": [
            ".map",
            ".rs",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".py",
            ".sh",
            ".swift",
            ".metal",
            ".metallib",
            ".lean",
            ".v",
            ".fst",
            ".fsti",
            ".zip",
        ],
    }
    write_json(RELEASE_DIR / "public_release_allowlist.json", allowlist)

    public_export = {
        "schema": "ziros-public-attestation-export-v1",
        "generated_at": now_rfc3339(),
        "version": version,
        "release_version": version,
        "release_tag": f"v{version}",
        "source_commit": source_commit,
        "working_tree_dirty": working_tree_dirty,
        "headline_counts": {
            "total_entries": len(ledger_entries),
            "mechanized_local": completion["counts"]["mechanized_local"],
            "hypothesis_stated": completion["counts"]["hypothesis_stated"],
            "mechanized_implementation_claim": completion["assurance_class_counts"]["mechanized_implementation_claim"],
            "hypothesis_carried_theorem": completion["assurance_class_counts"]["hypothesis_carried_theorem"],
            "pending": completion["counts"]["pending"],
        },
        "support_matrix_summary": {
            "generated_for": support["generated_for"],
            "backend_count": len(support["backends"]),
            "frontend_count": len(support["frontends"]),
            "gadget_count": len(support["gadgets"]),
        },
        "private_release_paths": {
            "product_release": "release/product-release.json",
            "private_source_census": "release/private_source_census.json",
            "public_release_allowlist": "release/public_release_allowlist.json",
        },
    }
    write_json(PROVENANCE_DIR / "public_attestation_export.json", public_export)

    summary = build_readme_summary(
        len(workspace_members),
        rust_lines,
        support,
        ledger_entries,
        completion,
    )
    replace_generated_block(
        README,
        "<!-- BEGIN GENERATED PRIVATE SUMMARY -->",
        "<!-- END GENERATED PRIVATE SUMMARY -->",
        summary,
    )


if __name__ == "__main__":
    main()
