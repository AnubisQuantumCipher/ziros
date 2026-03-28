#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def generated_manifests() -> dict[str, dict]:
    with tempfile.TemporaryDirectory(prefix="zkf-gpu-bundle-attestation-") as tmp:
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

        out = {}
        for family in FAMILIES:
            manifest_path = tmp_manifests / f"{family}.json"
            require(manifest_path.exists(), f"missing generated manifest {manifest_path}")
            out[family] = json.loads(manifest_path.read_text(encoding="utf-8"))
        return out


def verify_lowering(program: dict) -> None:
    lowering = program["lowering"]
    toolchain = lowering.get("toolchain")
    require(isinstance(toolchain, dict), f"{program['program_id']} missing lowering.toolchain")
    for field in ("metal_compiler_version", "xcode_version", "sdk_version"):
        value = toolchain.get(field, "")
        require(
            isinstance(value, str) and value.strip(),
            f"{program['program_id']} missing pinned toolchain field `{field}`",
        )

    entrypoints = lowering.get("entrypoints", [])
    attestations = lowering.get("entrypoint_attestations", [])
    require(
        isinstance(entrypoints, list) and entrypoints,
        f"{program['program_id']} missing lowering.entrypoints",
    )
    require(
        isinstance(attestations, list) and attestations,
        f"{program['program_id']} missing lowering.entrypoint_attestations",
    )
    require(
        len(attestations) == len(entrypoints),
        f"{program['program_id']} attestation count does not match entrypoint count",
    )

    bound_pairs = {
        (binding["library"], binding["entrypoint"])
        for binding in lowering.get("step_bindings", [])
    }
    attested_pairs = set()
    for attestation in attestations:
        library_id = attestation.get("library_id")
        entrypoint = attestation.get("entrypoint")
        require(
            isinstance(library_id, str) and library_id,
            f"{program['program_id']} attestation missing library_id",
        )
        require(
            isinstance(entrypoint, str) and entrypoint,
            f"{program['program_id']} attestation missing entrypoint",
        )
        pair = (library_id, entrypoint)
        require(
            pair in bound_pairs,
            f"{program['program_id']} attests unbound kernel {library_id}:{entrypoint}",
        )
        require(
            pair not in attested_pairs,
            f"{program['program_id']} duplicates attestation for {library_id}:{entrypoint}",
        )
        attested_pairs.add(pair)

        for field in (
            "metallib_sha256",
            "reflection_sha256",
            "pipeline_descriptor_sha256",
        ):
            value = attestation.get(field, "")
            require(
                isinstance(value, str) and HEX_64.fullmatch(value),
                f"{program['program_id']} has invalid {field} for {library_id}:{entrypoint}",
            )

        arguments = attestation.get("arguments", [])
        require(
            isinstance(arguments, list) and arguments,
            f"{program['program_id']} attestation missing argument list for {library_id}:{entrypoint}",
        )
        for argument in arguments:
            require(
                argument.get("kind") in {"buffer", "threadgroup_memory"},
                f"{program['program_id']} has unknown argument kind in {library_id}:{entrypoint}",
            )
            require(
                argument.get("access") in {"read_only", "read_write", "write_only"},
                f"{program['program_id']} has unknown argument access in {library_id}:{entrypoint}",
            )


def main() -> int:
    manifests = generated_manifests()
    for family, manifest in manifests.items():
        require(
            manifest.get("schema") == "zkf-metal-gpu-proof-manifest-v3",
            f"{family} manifest schema drifted",
        )
        for program in manifest.get("programs", []):
            verify_lowering(program)
    return 0


if __name__ == "__main__":
    sys.exit(main())
