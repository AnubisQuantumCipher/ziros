#!/usr/bin/env python3

from __future__ import annotations

import filecmp
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_DIR = ROOT / "zkf-metal" / "proofs" / "manifests"
LEAN_GENERATED = ROOT / "zkf-metal" / "proofs" / "lean" / "Generated" / "GpuPrograms.lean"
FAMILIES = (
    "hash",
    "poseidon2",
    "ntt",
    "msm",
    "field_ops",
    "poly",
    "fri",
    "constraint_eval",
    "msm_aux",
)


def require(path: Path, label: str) -> None:
    if not path.exists():
        raise SystemExit(f"missing {label}: {path}")


def main() -> int:
    require(ROOT / "Cargo.toml", "workspace manifest")
    with tempfile.TemporaryDirectory(prefix="zkf-gpu-proof-manifest-") as tmp:
        tmp_root = Path(tmp)
        tmp_manifests = tmp_root / "manifests"
        tmp_lean = tmp_root / "lean"
        env = dict(**os.environ)
        env.setdefault("CARGO_TARGET_DIR", str(ROOT / "target-verification-export"))
        subprocess.run(
            [
                "cargo",
                "run",
                "-p",
                "zkf-metal",
                "--example",
                "export_gpu_proof_artifacts",
                "--",
                "--out-dir",
                str(tmp_manifests),
                "--lean-dir",
                str(tmp_lean),
            ],
            cwd=ROOT,
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
        )

        require(MANIFEST_DIR, "checked-in GPU manifest directory")
        require(LEAN_GENERATED, "checked-in generated Lean export")

        for family in FAMILIES:
            expected = MANIFEST_DIR / f"{family}.json"
            actual = tmp_manifests / f"{family}.json"
            require(expected, f"checked-in {family} manifest")
            require(actual, f"generated {family} manifest")
            if not filecmp.cmp(expected, actual, shallow=False):
                raise SystemExit(
                    f"GPU proof manifest drift detected for {family}; rerun "
                    "cargo run -p zkf-metal --example export_gpu_proof_artifacts"
                )

        generated_lean = tmp_lean / "Generated" / "GpuPrograms.lean"
        require(generated_lean, "generated Lean constants")
        if not filecmp.cmp(LEAN_GENERATED, generated_lean, shallow=False):
            raise SystemExit(
                "generated Lean GPU proof constants drift detected; rerun "
                "cargo run -p zkf-metal --example export_gpu_proof_artifacts"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
