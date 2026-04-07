#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = ROOT / "release"
PROVENANCE_DIR = RELEASE_DIR / "provenance"
DEFAULT_OUT = Path("/tmp/ziros-public-attestation-export-bundle")


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


def git_dirty() -> bool:
    return bool(run("git", "status", "--short").strip())


def git_head_commit() -> str:
    return run("git", "rev-parse", "HEAD").strip()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--write-tracked-export", action="store_true")
    args = parser.parse_args()

    if git_dirty() and not args.allow_dirty:
        print("refusing to export a public attestation bundle from a dirty source tree")
        return 1

    product_release = load_json(RELEASE_DIR / "product-release.json")
    allowlist = load_json(RELEASE_DIR / "public_release_allowlist.json")
    census = load_json(RELEASE_DIR / "private_source_census.json")
    completion = load_json(ROOT / ".zkf-completion-status.json")
    support = load_json(ROOT / "support-matrix.json")
    export_doc = {
        "schema": "ziros-public-attestation-export-bundle-v1",
        "generated_at": now_rfc3339(),
        "source_commit": git_head_commit(),
        "working_tree_dirty": git_dirty(),
        "version": product_release["version"],
        "release_tag": product_release["release_tag"],
        "headline_counts": {
            "total_entries": completion["total_entries"],
            "mechanized_total": completion["mechanized_total"],
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
        "private_release_inputs": {
            "product_release": product_release,
            "private_source_census": census,
            "public_release_allowlist": allowlist,
        },
    }

    out_root = args.out.resolve()
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    write_json(out_root / "public_attestation_export.json", export_doc)
    if args.write_tracked_export:
        write_json(PROVENANCE_DIR / "public_attestation_export.json", export_doc)
    print(out_root.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
