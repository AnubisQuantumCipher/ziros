#!/usr/bin/env python3
"""Install the checked-in Neural Engine fixture models into a runtime discovery root."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "zkf-runtime" / "tests" / "fixtures" / "neural_engine"
MODELS_DIR = FIXTURE_ROOT / "models"
MANIFEST_PATH = FIXTURE_ROOT / "fixture_manifest.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dest",
        required=True,
        help="Installation root such as target/coreml or ~/.zkf/models",
    )
    return parser.parse_args()


def resolve_dest(raw: str) -> Path:
    expanded = Path(raw).expanduser()
    if expanded.is_absolute():
        return expanded
    return ROOT / expanded


def main() -> int:
    if not MODELS_DIR.is_dir():
        raise SystemExit(
            f"missing committed fixture models in {MODELS_DIR}; run "
            "`python3 scripts/build_fixture_neural_models.py` first"
        )
    dest_root = resolve_dest(parse_args().dest)
    dest_root.mkdir(parents=True, exist_ok=True)

    for package in sorted(MODELS_DIR.glob("*.mlpackage")):
        dest_package = dest_root / package.name
        if dest_package.exists():
            shutil.rmtree(dest_package)
        shutil.copytree(package, dest_package)

        source_sidecar = Path(f"{package}.json")
        if source_sidecar.exists():
            shutil.copy2(source_sidecar, Path(f"{dest_package}.json"))

    if MANIFEST_PATH.exists():
        shutil.copy2(MANIFEST_PATH, dest_root / MANIFEST_PATH.name)
    print(dest_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
