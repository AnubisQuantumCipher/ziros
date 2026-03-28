#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest_path="$repo_root/Cargo.toml"

python3 - "$manifest_path" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

manifest = Path(sys.argv[1]).resolve()
repo_root = manifest.parent

metadata = subprocess.check_output(
    [
        "cargo",
        "metadata",
        "--manifest-path",
        str(manifest),
        "--format-version",
        "1",
        "--no-deps",
    ],
    text=True,
)

packages = json.loads(metadata)["packages"]
seen = set()

for package in packages:
    package_manifest = Path(package["manifest_path"]).resolve()
    if package_manifest in seen:
        continue
    if repo_root not in package_manifest.parents:
        continue
    seen.add(package_manifest)
    print(f"rustfmt check: {package_manifest}")
    subprocess.check_call(
        [
            "cargo",
            "fmt",
            "--manifest-path",
            str(package_manifest),
            "--",
            "--check",
        ]
    )
PY
