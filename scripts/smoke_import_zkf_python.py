#!/usr/bin/env python3
"""Import the built zkf Python extension from a Cargo target directory."""

from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
import sysconfig
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def candidate_library_paths(target_dir: Path) -> list[Path]:
    names = ["libzkf.dylib", "libzkf.so", "zkf.dll", "zkf.pyd"]
    return [target_dir / name for name in names]


def candidate_target_dirs(target_dir: Path) -> list[Path]:
    candidates = [target_dir]
    fallback = ROOT / "target-local" / "debug"
    if fallback != target_dir:
        candidates.append(fallback)
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target" / "debug")
    args = parser.parse_args()

    target_dir = args.target_dir.expanduser().resolve()
    library = next(
        (
            path
            for directory in candidate_target_dirs(target_dir)
            for path in candidate_library_paths(directory)
            if path.exists()
        ),
        None,
    )
    if library is None:
        searched = ", ".join(str(path) for path in candidate_target_dirs(target_dir))
        raise SystemExit(f"zkf extension library not found under any of: {searched}")

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    with tempfile.TemporaryDirectory(prefix="zkf-python-smoke-") as tempdir:
        tempdir_path = Path(tempdir)
        importable_path = tempdir_path / f"zkf{ext_suffix}"
        shutil.copy2(library, importable_path)
        sys.path.insert(0, str(tempdir_path))
        try:
            zkf = importlib.import_module("zkf")
            capability_matrix = json.loads(zkf.capability_matrix())
            program_json = json.dumps(
                {
                    "name": "python_smoke",
                    "field": "bn254",
                    "signals": [
                        {"name": "x", "visibility": "private"},
                        {"name": "y", "visibility": "private"},
                        {"name": "sum", "visibility": "public"},
                    ],
                    "constraints": [
                        {
                            "kind": "equal",
                            "lhs": {"op": "signal", "args": "sum"},
                            "rhs": {
                                "op": "add",
                                "args": [
                                    {"op": "signal", "args": "x"},
                                    {"op": "signal", "args": "y"},
                                ],
                            },
                        }
                    ],
                    "witness_plan": {"assignments": [], "hints": []},
                }
            )
            inspection = json.loads(zkf.inspect(program_json))
            payload = {
                "module": "zkf",
                "library": str(importable_path),
                "version": zkf.version(),
                "ir_version": zkf.ir_version(),
                "backend_count": len(capability_matrix),
                "has_import_circuit": hasattr(zkf, "import_circuit"),
                "has_inspect": hasattr(zkf, "inspect"),
                "inspection_constraints": inspection["program"]["constraints"],
                "inspection_preferred_backend": inspection["preferred_backend"],
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        finally:
            sys.path.pop(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
