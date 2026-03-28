#!/usr/bin/env python3
"""Run vendored Noir/Nargo competition scenarios with Barretenberg proof generation."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = Path(__file__).resolve().parent


def run(cmd: list[str], *, cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def scenario_dir(name: str) -> Path:
    path = WORKSPACE / name
    if not path.exists():
        raise SystemExit(f"unknown nargo scenario: {name}")
    return path


def prove(name: str) -> None:
    path = scenario_dir(name)
    bb_dir = path / "target" / "bb"
    if bb_dir.exists():
        shutil.rmtree(bb_dir)
    run(["nargo", "compile"], cwd=path)
    run(["nargo", "execute", "witness"], cwd=path)
    package = name
    run(
        [
            "bb",
            "prove",
            "-b",
            str(path / "target" / f"{package}.json"),
            "-w",
            str(path / "target" / "witness.gz"),
            "-o",
            str(bb_dir),
            "--output_format",
            "json",
            "--write_vk",
            "--verify",
        ],
        cwd=path,
    )


def verify(name: str) -> None:
    path = scenario_dir(name)
    bb_dir = path / "target" / "bb"
    run(
        [
            "bb",
            "verify",
            "-k",
            str(bb_dir / "vk.json"),
            "-p",
            str(bb_dir / "proof.json"),
            "-i",
            str(bb_dir / "public_inputs.json"),
        ],
        cwd=path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--mode", choices=["prove", "verify"], required=True)
    args = parser.parse_args()

    if args.mode == "prove":
        prove(args.scenario)
    else:
        verify(args.scenario)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
