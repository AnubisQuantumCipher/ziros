#!/usr/bin/env python3
"""Run vendored Circom/snarkjs competition scenarios."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parent


def run(cmd: list[str], *, cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def scenario_dir(name: str) -> Path:
    path = WORKSPACE / name
    if not path.exists():
        raise SystemExit(f"unknown snarkjs scenario: {name}")
    return path


def prove(name: str) -> None:
    path = scenario_dir(name)
    build_dir = path / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    run(
        [
            "circom2",
            str(path / "circuit.circom"),
            "--r1cs",
            "--wasm",
            "--sym",
            "-o",
            str(build_dir),
        ],
        cwd=path,
    )
    run(["snarkjs", "powersoftau", "new", "bn128", "8", str(build_dir / "pot.ptau")], cwd=path)
    run(
        [
            "snarkjs",
            "powersoftau",
            "prepare",
            "phase2",
            str(build_dir / "pot.ptau"),
            str(build_dir / "pot_final.ptau"),
        ],
        cwd=path,
    )
    run(
        [
            "snarkjs",
            "groth16",
            "setup",
            str(build_dir / "circuit.r1cs"),
            str(build_dir / "pot_final.ptau"),
            str(build_dir / "circuit_0000.zkey"),
        ],
        cwd=path,
    )
    run(
        [
            "snarkjs",
            "zkey",
            "export",
            "verificationkey",
            str(build_dir / "circuit_0000.zkey"),
            str(build_dir / "verification_key.json"),
        ],
        cwd=path,
    )
    run(
        [
            "snarkjs",
            "groth16",
            "fullprove",
            str(path / "input.json"),
            str(build_dir / "circuit_js" / "circuit.wasm"),
            str(build_dir / "circuit_0000.zkey"),
            str(build_dir / "proof.json"),
            str(build_dir / "public.json"),
        ],
        cwd=path,
    )


def verify(name: str) -> None:
    path = scenario_dir(name)
    build_dir = path / "build"
    run(
        [
            "snarkjs",
            "groth16",
            "verify",
            str(build_dir / "verification_key.json"),
            str(build_dir / "public.json"),
            str(build_dir / "proof.json"),
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
