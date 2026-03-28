#!/usr/bin/env python3
"""Run rustfmt against the local workspace without walking up to a parent Cargo.toml."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "Cargo.toml"
DEFAULT_BATCH_SIZE = 64
RUSTFMT_TARGET_KINDS = {
    "lib",
    "bin",
    "example",
    "test",
    "bench",
    "proc-macro",
    "custom-build",
}


def cargo_metadata() -> dict:
    proc = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(MANIFEST),
            "--format-version",
            "1",
            "--no-deps",
        ],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cargo metadata failed")
    return json.loads(proc.stdout)


def workspace_target_roots(payload: dict) -> dict[str, list[Path]]:
    workspace_ids = set(payload.get("workspace_members") or [])
    grouped: dict[str, set[Path]] = defaultdict(set)
    for package in payload.get("packages") or []:
        if package.get("id") not in workspace_ids:
            continue
        edition = str(package.get("edition") or "2021")
        for target in package.get("targets") or []:
            kinds = set(target.get("kind") or [])
            if not kinds.intersection(RUSTFMT_TARGET_KINDS):
                continue
            src_path = target.get("src_path")
            if src_path:
                grouped[edition].add(Path(src_path))
    return {
        edition: sorted(paths)
        for edition, paths in grouped.items()
    }


def batched(items: list[Path], batch_size: int) -> list[list[Path]]:
    return [items[i : i + batch_size] for i in range(0, len(items), batch_size)]


def run_rustfmt(*, check_only: bool, batch_size: int) -> int:
    payload = cargo_metadata()
    grouped = workspace_target_roots(payload)
    rustfmt = os.environ.get("RUSTFMT", "rustfmt")
    overall_rc = 0

    for edition, files in sorted(grouped.items()):
        for batch in batched(files, batch_size):
            cmd = [rustfmt, f"--edition={edition}"]
            if check_only:
                cmd.append("--check")
            cmd.extend(str(path) for path in batch)
            proc = subprocess.run(
                cmd,
                cwd=str(ROOT),
                text=True,
                capture_output=True,
                check=False,
            )
            if proc.stdout:
                sys.stdout.write(proc.stdout)
            if proc.stderr:
                sys.stderr.write(proc.stderr)
            if proc.returncode != 0:
                overall_rc = proc.returncode

    return overall_rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Run rustfmt in check mode (default).")
    mode.add_argument("--write", action="store_true", help="Format files in place.")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Maximum number of crate roots to pass to each rustfmt invocation.",
    )
    args = parser.parse_args()
    check_only = not args.write
    return run_rustfmt(check_only=check_only, batch_size=max(1, args.batch_size))


if __name__ == "__main__":
    raise SystemExit(main())
