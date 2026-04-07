#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / ".zkf-completion-status.json"
SUPPORT_MATRIX_PATH = ROOT / "support-matrix.json"
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
OUT_PATH = ROOT / "release" / "product-release.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.4.2")
    parser.add_argument("--release-tag", default="v0.4.2")
    parser.add_argument(
        "--binary",
        default=str(ROOT / "target-public" / "release" / "zkf-cli"),
        help="path to the release zkf binary",
    )
    parser.add_argument(
        "--target-triple",
        default="aarch64-apple-darwin",
    )
    args = parser.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        raise SystemExit(f"missing release binary: {binary_path}")

    status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    support_matrix_digest = sha256_file(SUPPORT_MATRIX_PATH)
    ledger_digest = sha256_file(LEDGER_PATH)

    payload = {
        "schema": "ziros-product-release-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": args.version,
        "release_tag": args.release_tag,
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
        "binary_target": args.target_triple,
        "binary": {
            "path": repo_relative(binary_path),
            "sha256": sha256_file(binary_path),
        },
        "source_truth_surfaces": [
            "zkf-ir-spec/verification-ledger.json",
            ".zkf-completion-status.json",
            "support-matrix.json",
            "release/product-release.json",
            "release/private_source_census.json",
        ],
        "headline_counts": {
            "implementation_bound_rows": status["assurance_class_counts"][
                "mechanized_implementation_claim"
            ],
            "hypothesis_carried_rows": status["assurance_class_counts"][
                "hypothesis_carried_theorem"
            ],
            "mechanized_local_rows": status["counts"]["mechanized_local"],
            "pending_rows": status["counts"]["pending"],
        },
        "digests": {
            "verification_ledger_sha256": ledger_digest,
            "support_matrix_sha256": support_matrix_digest,
        },
        "proof_runners": [
            "scripts/run_rocq_proofs.sh",
            "scripts/run_protocol_lean_proofs.sh",
            "scripts/run_verus_workspace.sh",
        ],
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def repo_relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


if __name__ == "__main__":
    main()
