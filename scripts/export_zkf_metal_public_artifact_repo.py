#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
BINUTILS_PREFIX = Path(
    os.environ.get("PUBLIC_ARTIFACT_BINUTILS_PREFIX", "/opt/homebrew/opt/binutils/bin")
)
PIP_ZIG_BIN = Path.home() / ".local" / "lib" / "python3.10" / "site-packages" / "ziglang" / "zig"
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
STATEMENT_SCHEMA = "zkf-metal-public-statement-bundle-v1"
PROOF_MANIFEST_SCHEMA = "zkf-metal-public-proof-manifest-v1"
ATTESTATION_MANIFEST_SCHEMA = "zkf-metal-public-attestation-manifest-v1"
BUNDLE_EVIDENCE_SCHEMA = "zkf-metal-public-bundle-evidence-v1"
PROOF_PLAN_SCHEMA = "zkf-metal-public-proof-plan-v1"
PUBLIC_INPUT_SCHEMA = "zkf-metal-public-proof-inputs-v2"
PROOF_SYSTEM = "zkf-groth16"
PUBLIC_GROTH16_PROOF_SCHEMA = "zkf-metal-public-groth16-proof-v1"
PUBLIC_REFLECTION_DIGEST_SCHEME_V1 = "public-v1-no-arg-names"
PUBLIC_ORBITAL_CLOSURE_SCHEMA = "zkf-metal-public-orbital-proof-surface-v1"
DEFAULT_OUT_DIR = ROOT / "target" / "zkf-metal-public-repo"
DEFAULT_VERIFICATION_REPORT = ROOT / "evidence" / "zkf-metal-verification-report.md"
CHECKSUM_PATH = "checksums/sha256.txt"
PROOF_GENERATOR_MANIFEST = (
    ROOT / "tools" / "zkf-metal-public-proof" / "script" / "Cargo.toml"
)
PRIVATE_VALIDATION_SCRIPTS = (
    ROOT / "scripts" / "verify_gpu_proof_manifest.py",
    ROOT / "scripts" / "verify_gpu_bundle_attestation.py",
)
PUBLIC_VERIFIER_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)
LIBRARY_OUTPUTS = {
    "main_library": "main.metallib",
    "hash_library": "hash.metallib",
    "bn254_msm_library": "msm.metallib",
    "msm_library": "msm.metallib",
    "pallas_msm_library": "msm_pallas.metallib",
    "vesta_msm_library": "msm_vesta.metallib",
}
FORBIDDEN_TERMS = (
    str(ROOT),
    "ZirOS",
    "zkf-cli/src/",
    "zkf-metal/src/",
    "zkf_cli",
    "zkf-cli",
    "zkf_runtime",
    "zkf-runtime",
    "zkf_runtime::",
    "zkf_metal::",
    "proof_ir.rs",
    "verified_artifacts.rs",
    "LaunchSafety.lean",
    "proofs/lean/",
)
ABSOLUTE_PATH_RE = re.compile(r"(/Users/[^\s\"']+|/home/[^\s\"']+|/private/var/[^\s\"']+)")
SOURCE_FILENAME_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:rs|metal|lean)\b")
ASCII_RUN_RE = re.compile(rb"[ -~]{4,}")
INSTALLED_DIR_FRAGMENT_RE = re.compile(r"\s*\|\s*InstalledDir:\s*[^|]+")
PRIVATE_BINARY_SOURCE_RE = re.compile(
    r"(workspace/|vendor/|zkf-metal-public-cli/src/main\.rs|zkf-lib/src/|zkf-core/src/|zkf-backends/src/|proof_ir\.rs|verified_artifacts\.rs|[A-Za-z0-9_./-]+\.metal(?=$|[:\s\"')])|[A-Za-z0-9_./-]+\.lean(?=$|[:\s\"')]))"
)
ORBITAL_PUBLIC_SOURCE_RELATIVE_PATHS = {
    "evidence/orbital/private_nbody_orbital_showcase.rs",
    "evidence/orbital/orbital_dynamics_verus.rs",
}
ALLOWLISTED_SOURCE_FILENAME_TEXT_PATHS = {
    "evidence/generator-summary.json",
    "evidence/orbital/private_nbody_orbital_showcase_closure.json",
}


def resolve_tool(name: str, prefixed_path: Path | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if prefixed_path is not None and prefixed_path.is_file():
        return str(prefixed_path)
    return None


def resolve_zig_bin() -> str | None:
    if os.environ.get("PUBLIC_ARTIFACT_ZIG_BIN"):
        candidate = Path(os.environ["PUBLIC_ARTIFACT_ZIG_BIN"]).expanduser()
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("zig")
    if found:
        return found
    if PIP_ZIG_BIN.is_file():
        return str(PIP_ZIG_BIN)
    return None


GNU_STRIP_BIN = resolve_tool("gstrip", BINUTILS_PREFIX / "gstrip")
GNU_NM_BIN = resolve_tool("gnm", BINUTILS_PREFIX / "gnm")
GNU_READELF_BIN = resolve_tool("greadelf", BINUTILS_PREFIX / "greadelf")
GNU_OBJDUMP_BIN = resolve_tool("gobjdump", BINUTILS_PREFIX / "gobjdump")
ZIG_BIN = resolve_zig_bin()

THEOREM_CATALOG = {
    "gpu.hash_differential_bounded": {
        "title": "Hash Family Boundary Model",
        "summary": "The shipped SHA-256 and Keccak-256 Metal batch programs stay synchronized with the mechanized hash-family boundary inventory exported by the release.",
        "formal_claim": "For the attested hash-family entrypoints published in this release, the exported program inventory, source-path set, reflection policy, and layout boundary remain synchronized with the mechanized hash-family model.",
    },
    "gpu.poseidon2_differential_bounded": {
        "title": "Poseidon2 Family Boundary Model",
        "summary": "The shipped width-16 Goldilocks and BabyBear scalar and SIMD Poseidon2 programs stay synchronized with the mechanized boundary inventory exported by the release.",
        "formal_claim": "For the attested Poseidon2 entrypoints published in this release, the exported program inventory, source-path set, reflection policy, and layout boundary remain synchronized with the mechanized Poseidon2 family model.",
    },
    "gpu.ntt_differential_bounded": {
        "title": "NTT Family Boundary Model",
        "summary": "The shipped Goldilocks, BabyBear, and BN254 Metal NTT programs stay synchronized with the mechanized staged-boundary inventory exported by the release.",
        "formal_claim": "For the attested NTT entrypoints published in this release, the exported program inventory, source-path set, reflection policy, workgroup policy, and staged binding surface remain synchronized with the mechanized NTT family model.",
    },
    "gpu.ntt_bn254_butterfly_arithmetic_sound": {
        "title": "BN254 NTT Butterfly Arithmetic",
        "summary": "The shipped `ntt_butterfly_bn254` entrypoint is tied to a dedicated mechanized Montgomery-domain butterfly theorem over the attested helper-plus-entrypoint source set.",
        "formal_claim": "For the attested `ntt_butterfly_bn254` program published in this release, the active butterfly branch computes `a + w*b` and `a - w*b` over canonical BN254 Montgomery-domain values using the pinned helper shader, twiddle lookup, and final-subtraction boundary modeled by the mechanized theorem.",
    },
    "gpu.msm_differential_bounded": {
        "title": "MSM Family Boundary Model",
        "summary": "The shipped BN254 classic MSM chain and the shipped Pallas and Vesta classic or NAF programs stay synchronized with the mechanized boundary inventory exported by the release.",
        "formal_claim": "For the attested MSM entrypoints published in this release, the exported program inventory, route tags, source-path set, reflection policy, and staged binding surface remain synchronized with the mechanized MSM family model.",
    },
    "gpu.launch_contract_sound": {
        "title": "Launch Safety",
        "summary": "Dispatches admitted by the verified host boundary satisfy bounded-region, non-overlap, and barrier-balance constraints before a GPU thread executes.",
        "formal_claim": "Any dispatch admitted by the verified launch-contract boundary has structurally bounded memory regions, balanced barriers, and no admitted out-of-bounds or overlapping-write configuration within the mechanized model.",
    },
    "gpu.buffer_layout_sound": {
        "title": "Memory Model Soundness",
        "summary": "Verified GPU buffer layouts, alias separation, initialized-read footprints, and writeback regions are structurally sound for the shipped lane.",
        "formal_claim": "The verified GPU memory-layout model enforces the attested read and write regions, alias-separation rules, and initialized-read constraints for the shipped kernel surface.",
    },
    "gpu.dispatch_schedule_sound": {
        "title": "Dispatch Schedule Soundness",
        "summary": "The verified Metal schedule uses only the exported lowering bindings, step ordering, and barrier placements that refine the mechanized family semantics.",
        "formal_claim": "The shipped Metal lowering and dispatch schedule preserve the mechanized program step ordering, barrier placement, and kernel-entrypoint binding required by the verified GPU lane.",
    },
    "gpu.shader_bundle_provenance": {
        "title": "Shader Bundle Provenance",
        "summary": "The checked artifact surface binds shipped entrypoints to metallib digests, reflection digests, pipeline-descriptor digests, and the pinned toolchain identity.",
        "formal_claim": "Each published entrypoint is bound to the attested compiled metallib, reflection digest, pipeline-descriptor digest, and pinned Metal toolchain identity required by the verified release lane.",
    },
    "gpu.runtime_fail_closed": {
        "title": "Runtime Fail-Closed Enforcement",
        "summary": "The verified GPU lane rejects unavailable devices, unsupported stages, and artifact drift instead of silently substituting an unverified path.",
        "formal_claim": "The verified runtime lane rejects unavailable GPUs, unsupported verified-lane stages, runtime-compiled libraries, and artifact-attestation drift instead of silently bypassing the verified GPU boundary.",
    },
    "gpu.cpu_gpu_partition_equivalence": {
        "title": "CPU/GPU Partition Equivalence",
        "summary": "The verified runtime placement partition preserves prover truth across the composed CPU and GPU execution plan.",
        "formal_claim": "The verified runtime placement partition composes the mechanized GPU subset with the verified CPU lane without changing the accepted statement.",
    },
    "public.build_integrity_commitment": {
        "title": "Build Integrity Commitment",
        "summary": "The public release binds the hidden committed source set and pinned Metal toolchain identity to the published metallib digest set without disclosing reconstructible source artifacts.",
        "formal_claim": "The public build-integrity proof binds the private committed source tree and the pinned Metal toolchain identity to the exact published metallib digest set for this release.",
    },
    "field.large_prime_runtime_generated": {
        "title": "Large-Prime Runtime Field Provenance",
        "summary": "The admitted large-prime runtime field lane is pinned to the shipped generated modules for the supported large-prime fields.",
        "formal_claim": "The admitted large-prime runtime lane dispatches only through the shipped generated large-prime modules for the supported release fields.",
    },
    "field.bn254_strict_lane_generated": {
        "title": "BN254 Strict-Lane Montgomery Closure",
        "summary": "The admitted BN254 strict lane proves its Montgomery reduction constant, final subtraction, canonical multiply/divide normalization, and generated-only exclusion boundary.",
        "formal_claim": "The admitted BN254 strict lane closes the Montgomery bug class for the shipped generated BN254 field path by proving the checked reduction constant, the final conditional subtraction boundary, canonical multiply/divide normalization, and exclusion of uncertified alternate BN254 Montgomery implementations from the verified release lane.",
    },
    "field.small_field_runtime_semantics": {
        "title": "Small-Field Runtime Semantics",
        "summary": "The shipped small-field runtime encodings refine the mechanized runtime semantics used by the public GPU lane.",
        "formal_claim": "The shipped small-field runtime encodings satisfy the mechanized runtime semantics for the small-field surfaces admitted by the public release lane.",
    },
    "pipeline.cli_runtime_path_composition": {
        "title": "CLI Runtime Path Composition",
        "summary": "The shipped CLI/runtime composition preserves the verified execution path into the certified Metal lane without bypassing the host boundary.",
        "formal_claim": "The shipped CLI/runtime composition preserves the verified host and runtime path into the certified Metal execution lane without bypassing the admitted validation and attestation boundary.",
    },
    "orbital.surface_constants": {
        "title": "Orbital Surface Constants",
        "summary": "The public orbital showcase fixes the body count, step count, private input count, public output count, and fixed-point kernel constants used by the admitted proof surface.",
        "formal_claim": "The public orbital fixed-point showcase is bound to the exact body count, step count, fixed-point scale, gravity constant, and commitment output count published in this repository.",
    },
    "orbital.position_update_half_step_soundness": {
        "title": "Orbital Position Half-Step Soundness",
        "summary": "The public orbital proof surface reconstructs the exact fixed-point position half-step update from the rounded witness lane and bounded residual.",
        "formal_claim": "For the admitted orbital fixed-point position update, the rounded half-step witness and bounded residual reconstruct the exact discrete position-update relation published by this release.",
    },
    "orbital.velocity_update_half_step_soundness": {
        "title": "Orbital Velocity Half-Step Soundness",
        "summary": "The public orbital proof surface reconstructs the exact fixed-point velocity half-step update from the rounded witness lane and bounded residual.",
        "formal_claim": "For the admitted orbital fixed-point velocity update, the rounded half-step witness and bounded residual reconstruct the exact discrete velocity-update relation published by this release.",
    },
    "orbital.residual_split_soundness": {
        "title": "Orbital Residual Split Soundness",
        "summary": "The public orbital proof surface binds signed residuals to the positive/negative split carried by the fixed-point witness model.",
        "formal_claim": "The public orbital residual witness split reconstructs the signed residual exactly and preserves the non-negativity and exclusivity conditions of the admitted fixed-point residual model.",
    },
    "orbital.field_embedding_nonwrap_bounds": {
        "title": "Orbital Field-Embedding Non-Wrap Bounds",
        "summary": "The public orbital fixed-point bounds fit inside the admitted BN254 non-wrap domain used by the showcase constraint surface.",
        "formal_claim": "The published orbital fixed-point bounds stay strictly inside the admitted BN254 non-wrap domain required by the showcase field embedding and residual surface.",
    },
    "orbital.commitment_body_tag_domain_separation": {
        "title": "Orbital Commitment Domain Separation",
        "summary": "The public orbital commitment body tags are disjoint across the five-body showcase surface.",
        "formal_claim": "The published orbital commitment body tags are distinct and stay within the admitted five-body showcase surface, preserving the domain separation used by the public commitment payload model.",
    },
}
TRUSTED_COMPUTING_BASE_NOTE = (
    "Trusted computing base: Lean 4, Verus, the pinned Apple Metal compiler and SDK, the Apple Metal driver/runtime, Apple GPU hardware, and the public BN254 Groth16 verifier used for the packaged proof bundles."
)
BUNDLE_DEFINITIONS = (
    {
        "bundle_id": "kernel-families",
        "theorem_ids": [
            "gpu.hash_differential_bounded",
            "gpu.poseidon2_differential_bounded",
            "gpu.ntt_differential_bounded",
            "gpu.msm_differential_bounded",
        ],
        "summary": "Mechanized structural family-boundary theorem statements for the shipped Metal hash, Poseidon2, NTT, and MSM surfaces.",
        "formal_statement": "The shipped Metal kernel-family inventories, binding surfaces, and attested source sets stay synchronized with the mechanized family boundary models published in this repository.",
        "scope": "matching_theorems",
    },
    {
        "bundle_id": "launch-safety",
        "theorem_ids": ["gpu.launch_contract_sound"],
        "summary": "Mechanized host-boundary launch-safety statement for the verified Metal dispatch lane.",
        "formal_statement": "Verified dispatches admitted by the public lane satisfy the mechanized launch-safety boundary before any GPU execution begins.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "memory-model",
        "theorem_ids": ["gpu.buffer_layout_sound"],
        "summary": "Mechanized host-boundary memory-model statement for the verified Metal dispatch lane.",
        "formal_statement": "The published GPU buffer layouts, alias-separation rules, and writeback regions satisfy the mechanized memory-model boundary for the shipped lane.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "schedule-and-provenance",
        "theorem_ids": ["gpu.dispatch_schedule_sound", "gpu.shader_bundle_provenance"],
        "summary": "Mechanized schedule and attestation-provenance statements for the shipped Metal dispatch lane.",
        "formal_statement": "The published dispatch schedule and the published attestation chain bind the shipped entrypoints, compiled metallibs, reflection surface, and pipeline descriptors to the verified release lane.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "runtime-safety",
        "theorem_ids": ["gpu.runtime_fail_closed", "gpu.cpu_gpu_partition_equivalence"],
        "summary": "Mechanized runtime fail-closed and CPU/GPU partition statements for the verified Metal execution lane.",
        "formal_statement": "The verified runtime lane rejects unsupported GPU execution and preserves prover truth across the composed CPU and GPU execution plan.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "build-integrity",
        "theorem_ids": ["public.build_integrity_commitment"],
        "summary": "Public build-integrity statement binding the private committed source tree to the published metallib digest set.",
        "formal_statement": "The published build-integrity proof binds the hidden committed source tree and the pinned Metal toolchain identity to the exact published metallib digest set for this release.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "field-arithmetic",
        "theorem_ids": [
            "field.large_prime_runtime_generated",
            "field.small_field_runtime_semantics",
        ],
        "summary": "Mechanized field-lane provenance and runtime-semantics statements for the public Metal proving surface.",
        "formal_statement": "The admitted large-prime and small-field runtime lanes used by the public Metal release bind to the mechanized field surfaces published in this repository.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "montgomery-bn254",
        "theorem_ids": ["field.bn254_strict_lane_generated"],
        "summary": "Mechanized BN254 strict-lane Montgomery theorem bundle for the public field path.",
        "formal_statement": "The admitted BN254 strict field lane proves its reduction constant, final subtraction boundary, canonical multiply/divide normalization, and generated-only exclusion surface for the verified public release path.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "cli-runtime-composition",
        "theorem_ids": ["pipeline.cli_runtime_path_composition"],
        "summary": "Mechanized CLI/runtime composition statement for the public Metal proving lane.",
        "formal_statement": "The shipped CLI/runtime composition preserves the verified path into the public Metal proving lane without bypassing the admitted host and runtime boundary.",
        "scope": "all_programs",
    },
    {
        "bundle_id": "orbital-fixed-point",
        "theorem_ids": [
            "orbital.surface_constants",
            "orbital.position_update_half_step_soundness",
            "orbital.velocity_update_half_step_soundness",
            "orbital.residual_split_soundness",
            "orbital.field_embedding_nonwrap_bounds",
            "orbital.commitment_body_tag_domain_separation",
        ],
        "summary": "Mechanized fixed-point orbital theorem statements for the public five-body showcase and its BN254 embedding boundary.",
        "formal_statement": "The published orbital showcase is bound to the exact five-body fixed-point model, bounded residual relations, and BN254 non-wrap embedding surface described by this release.",
        "scope": "all_programs",
    },
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def ensure_hex_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError(f"{label} must be a lowercase SHA-256 hex digest")


def run_checked(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def parse_key_path_pairs(values: list[str], *, label: str) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for raw in values:
        key, sep, value = raw.partition("=")
        if not sep:
            raise RuntimeError(f"{label} entries must use KEY=PATH syntax: {raw}")
        key = key.strip()
        if not key:
            raise RuntimeError(f"{label} entries must include a non-empty key: {raw}")
        path = Path(value).expanduser().resolve()
        if key in parsed:
            raise RuntimeError(f"duplicate {label} entry for `{key}`")
        parsed[key] = path
    return parsed


def current_host_target() -> str:
    machine = os.uname().machine
    system = os.uname().sysname
    if system == "Darwin" and machine == "arm64":
        return "aarch64-apple-darwin"
    if system == "Darwin" and machine == "x86_64":
        return "x86_64-apple-darwin"
    if system == "Linux" and machine == "x86_64":
        return "x86_64-unknown-linux-gnu"
    if system == "Linux" and machine in {"arm64", "aarch64"}:
        return "aarch64-unknown-linux-gnu"
    raise RuntimeError(f"unsupported host target: {system} {machine}")


def normalize_library_key(raw: str) -> str:
    if raw in LIBRARY_OUTPUTS:
        return raw
    for library_id, public_name in LIBRARY_OUTPUTS.items():
        if raw == public_name:
            return library_id
    raise RuntimeError(f"unknown metallib key `{raw}`; expected one of {sorted(LIBRARY_OUTPUTS)}")


def normalize_private_manifest_family_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    for program in manifest.get("programs", []):
        lowering = program.get("lowering") or {}
        if "toolchain" in lowering:
            lowering["toolchain"] = sanitize_toolchain_identity(lowering["toolchain"])
        for attestation in lowering.get("entrypoint_attestations", []):
            library_id = attestation.get("library_id")
            if library_id == "msm_library":
                attestation["library_id"] = "bn254_msm_library"
    return manifest


def sanitize_toolchain_identity(toolchain: dict[str, str]) -> dict[str, str]:
    metal_compiler_version = INSTALLED_DIR_FRAGMENT_RE.sub(
        "",
        toolchain["metal_compiler_version"],
    ).strip()
    metal_compiler_version = re.sub(r"\s+\|\s+", " | ", metal_compiler_version)
    sanitized = {
        "metal_compiler_version": metal_compiler_version,
        "xcode_version": toolchain["xcode_version"].strip(),
        "sdk_version": toolchain["sdk_version"].strip(),
    }
    hits = leak_hits_for_text(json.dumps(sanitized, sort_keys=True))
    if hits:
        raise RuntimeError(
            "sanitized toolchain identity still leaks private material: "
            + ", ".join(sorted(set(hits)))
        )
    return sanitized


def export_private_manifests() -> dict[str, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="zkf-metal-public-export-") as tempdir:
        temp_root = Path(tempdir)
        manifests_dir = temp_root / "manifests"
        lean_dir = temp_root / "lean"
        env = dict(os.environ)
        env.setdefault("CARGO_TARGET_DIR", str(ROOT / "target-verification-export"))
        run_checked(
            [
                "cargo",
                "run",
                "-p",
                "zkf-metal",
                "--example",
                "export_gpu_proof_artifacts",
                "--",
                "--out-dir",
                str(manifests_dir),
                "--lean-dir",
                str(lean_dir),
            ],
            cwd=ROOT,
            env=env,
        )
        manifests: dict[str, dict[str, Any]] = {}
        for family in FAMILIES:
            path = manifests_dir / f"{family}.json"
            manifests[family] = normalize_private_manifest_family_manifest(
                json.loads(path.read_text(encoding="utf-8"))
            )
        return manifests


def run_private_validation() -> list[dict[str, str]]:
    reports: list[dict[str, str]] = []
    for script in PRIVATE_VALIDATION_SCRIPTS:
        result = run_checked([sys.executable, str(script)], cwd=ROOT)
        reports.append(
            {
                "script": str(script.relative_to(ROOT)),
                "status": "passed",
                "stdout_sha256": sha256_bytes(result.stdout.encode("utf-8")),
                "stderr_sha256": sha256_bytes(result.stderr.encode("utf-8")),
            }
        )
    return reports


def toolchain_identity_digest(toolchain: dict[str, str]) -> str:
    payload = (
        f"metal_compiler_version={toolchain['metal_compiler_version']}\n"
        f"xcode_version={toolchain['xcode_version']}\n"
        f"sdk_version={toolchain['sdk_version']}\n"
    )
    return sha256_bytes(payload.encode("utf-8"))


def private_source_commitment_root(private_manifests: dict[str, dict[str, Any]]) -> str:
    leaves: list[bytes] = []
    seen: set[tuple[str, str]] = set()
    for manifest in private_manifests.values():
        for program in manifest.get("programs", []):
            source_map = ((program.get("lowering") or {}).get("source_sha256") or {})
            for path, digest in source_map.items():
                normalized_path = normalize_private_source_path(path)
                pair = (normalized_path, digest)
                if pair not in seen:
                    seen.add(pair)
                    leaves.append(
                        hashlib.sha256(
                            f"{normalized_path}\0{digest}".encode("utf-8")
                        ).digest()
                    )
    if not leaves:
        raise RuntimeError("private source commitment root requires at least one source leaf")
    return merkle_root_hex(leaves)


def normalize_private_source_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if normalized.startswith("/"):
        raise RuntimeError(f"private source path must be relative, got: {path}")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", ".", ".."} or normalized.startswith("../") or "/../" in normalized:
        raise RuntimeError(f"private source path escapes repository root: {path}")
    return normalized


def merkle_root_hex(leaves: list[bytes]) -> str:
    level = sorted(set(leaves))
    if not level:
        raise RuntimeError("merkle root requires at least one leaf")
    while len(level) > 1:
        next_level: list[bytes] = []
        index = 0
        while index < len(level):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
            index += 2
        level = next_level
    return level[0].hex()


def run_gpu_proof_closure_audit(*, skip_runners: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="zkf-metal-gpu-proof-closure-") as tempdir:
        out_path = Path(tempdir) / "gpu-proof-closure.json"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "check_gpu_proof_closure.py"),
            "--out",
            str(out_path),
        ]
        if skip_runners:
            command.append("--skip-proof-runners")
        run_checked(command, cwd=ROOT)
        return json.loads(out_path.read_text(encoding="utf-8"))


def run_supporting_proof_closure_audit(*, skip_runners: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="zkf-metal-supporting-proof-closure-") as tempdir:
        out_path = Path(tempdir) / "supporting-proof-closure.json"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "check_supporting_proof_closure.py"),
            "--out",
            str(out_path),
        ]
        if skip_runners:
            command.append("--skip-proof-runners")
        run_checked(command, cwd=ROOT)
        return json.loads(out_path.read_text(encoding="utf-8"))


def write_hash_field(hasher: hashlib._hashlib.HASH, key: str, value: str) -> None:
    hasher.update(key.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(value.encode("utf-8"))
    hasher.update(b"\xff")


def write_sorted_string_list(
    hasher: hashlib._hashlib.HASH, key: str, values: list[str]
) -> None:
    sorted_values = sorted(set(values))
    write_hash_field(hasher, f"{key}_len", str(len(sorted_values)))
    for value in sorted_values:
        write_hash_field(hasher, key, value)


def bundle_evidence_digest(evidence: dict[str, Any]) -> str:
    hasher = hashlib.sha256()
    write_hash_field(hasher, "schema", BUNDLE_EVIDENCE_SCHEMA)
    kind = evidence["kind"]
    write_hash_field(hasher, "kind", kind)
    write_hash_field(hasher, "bundle_id", evidence["bundle_id"])
    if kind == "theorem_closure":
        write_hash_field(
            hasher,
            "toolchain_identity_digest",
            evidence["toolchain_identity_digest"],
        )
        write_sorted_string_list(hasher, "theorem_id", list(evidence["theorem_ids"]))
        records = list(evidence["theorem_records"])
        records.sort(
            key=lambda item: (
                item["theorem_id"],
                item["checker"],
                item["decl_name"],
            )
        )
        write_hash_field(hasher, "record_len", str(len(records)))
        for record in records:
            write_hash_field(hasher, "record_theorem_id", record["theorem_id"])
            write_hash_field(hasher, "record_checker", record["checker"])
            write_hash_field(hasher, "record_decl_name", record["decl_name"])
            write_hash_field(hasher, "record_module_name", record["module_name"])
            write_hash_field(
                hasher,
                "record_proof_artifact_kind",
                record["proof_artifact_kind"],
            )
            write_hash_field(
                hasher,
                "record_proof_artifact_digest",
                record["proof_artifact_digest"],
            )
            write_hash_field(
                hasher,
                "record_allowed_axioms_only",
                "true" if record["allowed_axioms_only"] else "false",
            )
            write_sorted_string_list(hasher, "record_axiom", list(record["axioms"]))
        return hasher.hexdigest()

    write_sorted_string_list(hasher, "theorem_id", list(evidence["theorem_ids"]))
    write_hash_field(
        hasher,
        "private_source_commitment_root",
        evidence["private_source_commitment_root"],
    )
    write_hash_field(
        hasher,
        "toolchain_identity_digest",
        evidence["toolchain_identity_digest"],
    )
    write_sorted_string_list(hasher, "metallib_digest", list(evidence["metallib_digests"]))
    return hasher.hexdigest()


def collect_program_records(private_manifests: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for manifest in private_manifests.values():
        for program in manifest.get("programs", []):
            lowering = program["lowering"]
            artifacts = []
            for attestation in lowering["entrypoint_attestations"]:
                library_id = normalize_library_key(attestation["library_id"])
                artifacts.append(
                    {
                        "kernel_program_label": program["program_id"],
                        "entrypoint_label": attestation["entrypoint"],
                        "library_id": library_id,
                        "metallib_public_name": LIBRARY_OUTPUTS[library_id],
                        "metallib_digest": attestation["metallib_sha256"],
                        "reflection_digest": attestation["public_reflection_sha256"],
                        "pipeline_descriptor_digest": attestation["pipeline_descriptor_sha256"],
                    }
                )
            records.append(
                {
                    "theorem_id": program["theorem_id"],
                    "program_id": program["program_id"],
                    "artifacts": artifacts,
                    "toolchain": sanitize_toolchain_identity(lowering["toolchain"]),
                }
            )
    return records


def selected_records(bundle: dict[str, Any], program_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if bundle["scope"] == "matching_theorems":
        selected = [
            record
            for record in program_records
            if record["theorem_id"] in bundle["theorem_ids"]
        ]
    else:
        selected = list(program_records)
    if not selected:
        raise RuntimeError(f"bundle {bundle['bundle_id']} selected no program records")
    return selected


def theorem_program_mappings(
    bundle: dict[str, Any], selected: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in selected:
        grouped.setdefault(record["theorem_id"], []).append(record)

    mappings: list[dict[str, Any]] = []
    for theorem_id in bundle["theorem_ids"]:
        theorem_records = grouped.get(theorem_id, [])
        if theorem_records:
            mapping_kind = (
                "compositional_family_surface"
                if theorem_id in {
                    "gpu.hash_differential_bounded",
                    "gpu.poseidon2_differential_bounded",
                    "gpu.ntt_differential_bounded",
                    "gpu.msm_differential_bounded",
                }
                else "direct_program_surface"
            )
            records = theorem_records
        else:
            mapping_kind = "bundle_wide_release_surface"
            records = selected

        program_ids = sorted({record["program_id"] for record in records})
        entrypoints = sorted(
            {
                artifact["entrypoint_label"]
                for record in records
                for artifact in record["artifacts"]
            }
        )
        metallibs = sorted(
            {
                f"binary/{artifact['metallib_public_name']}"
                for record in records
                for artifact in record["artifacts"]
            }
        )
        mapping: dict[str, Any] = {
            "theorem_id": theorem_id,
            "mapping_kind": mapping_kind,
            "program_ids": program_ids,
            "entrypoints": entrypoints,
            "metallib_paths": metallibs,
        }
        if theorem_id == "gpu.ntt_differential_bounded":
            mapping["derived_from_programs"] = program_ids
            mapping["note"] = (
                "The NTT family row is a structural theorem over the attested staged butterfly, "
                "batch, small, and hybrid kernels listed here; arithmetic-only claims are tracked "
                "separately by narrower theorem rows."
            )
        elif theorem_id == "gpu.msm_differential_bounded":
            mapping["derived_from_programs"] = program_ids
            mapping["note"] = (
                "The MSM family theorem covers the attested BN254 classic four-stage chain and "
                "the attested Pallas/Vesta classic and NAF admitted surfaces listed here."
            )
        mappings.append(mapping)
    return mappings


def build_bundle_statement(
    bundle: dict[str, Any],
    selected: list[dict[str, Any]],
    *,
    private_source_root: str,
    bundle_evidence_digest_value: str,
) -> dict[str, Any]:
    program_labels = sorted({record["program_id"] for record in selected})
    metallib_digests = sorted(
        {
            artifact["metallib_digest"]
            for record in selected
            for artifact in record["artifacts"]
        }
    )
    reflection_digests = sorted(
        {
            artifact["reflection_digest"]
            for record in selected
            for artifact in record["artifacts"]
        }
    )
    pipeline_digests = sorted(
        {
            artifact["pipeline_descriptor_digest"]
            for record in selected
            for artifact in record["artifacts"]
        }
    )
    toolchains = {
        (
            record["toolchain"]["metal_compiler_version"],
            record["toolchain"]["xcode_version"],
            record["toolchain"]["sdk_version"],
        )
        for record in selected
    }
    if len(toolchains) != 1:
        raise RuntimeError(
            f"bundle {bundle['bundle_id']} spans multiple toolchain identities; public release requires one pinned identity"
        )
    toolchain = selected[0]["toolchain"]
    theorem_mappings = theorem_program_mappings(bundle, selected)
    return {
        "schema": STATEMENT_SCHEMA,
        "bundle_id": bundle["bundle_id"],
        "proof_system": PROOF_SYSTEM,
        "theorem_ids": bundle["theorem_ids"],
        "summary": bundle["summary"],
        "formal_statement": bundle["formal_statement"],
        "trusted_computing_base_note": TRUSTED_COMPUTING_BASE_NOTE,
        "theorems": [
            {
                "theorem_id": theorem_id,
                **THEOREM_CATALOG[theorem_id],
                "trusted_computing_base_note": TRUSTED_COMPUTING_BASE_NOTE,
            }
            for theorem_id in bundle["theorem_ids"]
        ],
        "theorem_program_mappings": theorem_mappings,
        "artifact_bindings": {
            "program_labels": program_labels,
            "metallib_digests": metallib_digests,
            "reflection_digests": reflection_digests,
            "reflection_digest_scheme": PUBLIC_REFLECTION_DIGEST_SCHEME_V1,
            "pipeline_descriptor_digests": pipeline_digests,
            "toolchain_identity_digest": toolchain_identity_digest(toolchain),
            "private_source_commitment_root": private_source_root,
            "bundle_evidence_digest": bundle_evidence_digest_value,
        },
    }


def bundle_artifacts(selected: list[dict[str, Any]]) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for record in selected:
        for artifact in record["artifacts"]:
            key = (
                artifact["kernel_program_label"],
                artifact["entrypoint_label"],
                artifact["metallib_public_name"],
                artifact["reflection_digest"],
                artifact["pipeline_descriptor_digest"],
            )
            if key in seen:
                continue
            seen.add(key)
            artifacts.append(
                {
                    "kernel_program_label": artifact["kernel_program_label"],
                    "entrypoint_label": artifact["entrypoint_label"],
                    "library_id": artifact["library_id"],
                    "metallib_path": f"binary/{artifact['metallib_public_name']}",
                    "metallib_digest": artifact["metallib_digest"],
                    "reflection_digest": artifact["reflection_digest"],
                    "pipeline_descriptor_digest": artifact["pipeline_descriptor_digest"],
                }
            )
    artifacts.sort(key=lambda item: (item["kernel_program_label"], item["entrypoint_label"]))
    return artifacts


def build_bundle_evidence(
    bundle: dict[str, Any],
    selected: list[dict[str, Any]],
    *,
    theorem_records_by_id: dict[str, dict[str, Any]],
    private_source_root: str,
) -> dict[str, Any]:
    if bundle["bundle_id"] == "build-integrity":
        artifacts = bundle_artifacts(selected)
        return {
            "schema": BUNDLE_EVIDENCE_SCHEMA,
            "kind": "build_integrity",
            "bundle_id": bundle["bundle_id"],
            "theorem_ids": bundle["theorem_ids"],
            "private_source_commitment_root": private_source_root,
            "toolchain_identity_digest": toolchain_identity_digest(selected[0]["toolchain"]),
            "metallib_digests": sorted(
                {artifact["metallib_digest"] for artifact in artifacts}
            ),
        }

    missing = [
        theorem_id
        for theorem_id in bundle["theorem_ids"]
        if theorem_id not in theorem_records_by_id
    ]
    if missing:
        raise RuntimeError(
            f"proof closure report is missing theorem records for bundle {bundle['bundle_id']}: {', '.join(missing)}"
        )
    return {
        "schema": BUNDLE_EVIDENCE_SCHEMA,
        "kind": "theorem_closure",
        "bundle_id": bundle["bundle_id"],
        "theorem_ids": bundle["theorem_ids"],
        "toolchain_identity_digest": toolchain_identity_digest(selected[0]["toolchain"]),
        "theorem_records": [
            theorem_records_by_id[theorem_id] for theorem_id in bundle["theorem_ids"]
        ],
    }


def build_attestation_manifest(
    bundle: dict[str, Any],
    selected: list[dict[str, Any]],
    statement_digest: str,
    bundle_evidence_digest_value: str,
    *,
    private_source_root: str,
) -> dict[str, Any]:
    toolchain = selected[0]["toolchain"]
    artifacts = bundle_artifacts(selected)
    return {
        "schema": ATTESTATION_MANIFEST_SCHEMA,
        "bundle_id": bundle["bundle_id"],
        "proof_system": PROOF_SYSTEM,
        "public_input_schema": PUBLIC_INPUT_SCHEMA,
        "theorem_ids": bundle["theorem_ids"],
        "statement_bundle_path": f"proofs/statements/{bundle['bundle_id']}.json",
        "statement_bundle_digest": statement_digest,
        "bundle_evidence_path": f"proofs/evidence/{bundle['bundle_id']}.json",
        "bundle_evidence_digest": bundle_evidence_digest_value,
        "private_source_commitment_root": private_source_root,
        "toolchain_identity": toolchain,
        "toolchain_identity_digest": toolchain_identity_digest(toolchain),
        "metallib_digest_set_root": metallib_digest_set_root(artifacts),
        "reflection_digest_scheme": PUBLIC_REFLECTION_DIGEST_SCHEME_V1,
        "theorem_program_mappings": theorem_program_mappings(bundle, selected),
        "artifacts": artifacts,
    }


def build_bundle_manifest(
    bundle: dict[str, Any],
    proof_digest: str,
    verification_key_digest: str,
    attestation_manifest_digest: str,
    *,
    bundle_evidence_digest_value: str,
) -> dict[str, Any]:
    return {
        "schema": PROOF_MANIFEST_SCHEMA,
        "bundle_id": bundle["bundle_id"],
        "proof_system": PROOF_SYSTEM,
        "public_input_schema": PUBLIC_INPUT_SCHEMA,
        "reflection_digest_scheme": PUBLIC_REFLECTION_DIGEST_SCHEME_V1,
        "theorem_ids": bundle["theorem_ids"],
        "attestation_manifest_path": f"proofs/attestations/{bundle['bundle_id']}.json",
        "attestation_manifest_digest": attestation_manifest_digest,
        "bundle_evidence_path": f"proofs/evidence/{bundle['bundle_id']}.json",
        "bundle_evidence_digest": bundle_evidence_digest_value,
        "proof_bundle_path": f"proofs/zkproofs/{bundle['bundle_id']}.bin",
        "proof_bundle_digest": proof_digest,
        "verification_key_path": f"proofs/verification_keys/{bundle['bundle_id']}.bin",
        "verification_key_digest": verification_key_digest,
    }


def metallib_digest_set_root(artifacts: list[dict[str, str]]) -> str:
    digests = sorted({artifact["metallib_digest"] for artifact in artifacts})
    return sha256_bytes("\n".join(digests).encode("utf-8"))


def discover_metallibs(
    expected_by_library: dict[str, str], *, excluded_roots: list[Path] | None = None
) -> dict[str, Path]:
    found: dict[str, Path] = {}
    needed_by_digest = {digest: library_id for library_id, digest in expected_by_library.items()}
    search_roots = [ROOT / "target", ROOT / "target-local", *sorted(ROOT.glob("target-*"))]
    excluded = [path.resolve() for path in (excluded_roots or [])]
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for candidate in search_root.rglob("*.metallib"):
            candidate = candidate.resolve()
            if any(candidate.is_relative_to(prefix) for prefix in excluded):
                continue
            digest = sha256_file(candidate)
            library_id = needed_by_digest.get(digest)
            if library_id and library_id not in found:
                found[library_id] = candidate
    return found


def copy_file(source: Path, dest: Path) -> None:
    if not source.is_file():
        raise RuntimeError(f"required file is missing: {source}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)


def sanitize_orbital_showcase_source(text: str) -> str:
    sanitized = text.replace(
        "Desktop/ZirOS_Private_NBody_5Body_1000Step",
        "Desktop/zkf-metal-private-nbody-5body-1000step",
    )
    sanitized = sanitized.replace("ZirOS", "zkf-metal")
    return sanitized


def copy_orbital_public_source(out_dir: Path) -> dict[str, str]:
    orbital_dir = out_dir / "evidence" / "orbital"
    orbital_dir.mkdir(parents=True, exist_ok=True)

    showcase_source = (
        ROOT / "zkf-lib" / "examples" / "private_nbody_orbital_showcase.rs"
    )
    showcase_dest = orbital_dir / "private_nbody_orbital_showcase.rs"
    write_text(
        showcase_dest,
        sanitize_orbital_showcase_source(showcase_source.read_text(encoding="utf-8")),
    )

    verus_source = ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs"
    verus_dest = orbital_dir / "orbital_dynamics_verus.rs"
    write_text(verus_dest, verus_source.read_text(encoding="utf-8"))

    return {
        "evidence/orbital/private_nbody_orbital_showcase.rs": sha256_file(showcase_dest),
        "evidence/orbital/orbital_dynamics_verus.rs": sha256_file(verus_dest),
    }


def write_orbital_public_closure(
    out_dir: Path,
    *,
    source_digests: dict[str, str],
    theorem_bundle_ids: list[str],
) -> str:
    closure = {
        "schema": PUBLIC_ORBITAL_CLOSURE_SCHEMA,
        "app_id": "private_nbody_orbital_showcase",
        "summary": (
            "Public proof surface for the five-body, 1000-step orbital showcase. "
            "This is the only intentional source carve-out in the public zkf-metal release."
        ),
        "fixed_surface": {
            "body_count": 5,
            "integration_steps": 1000,
            "private_inputs": 35,
            "public_outputs": 5,
            "fixed_point_scale": "10^18",
            "gravity_scaled": "66743000",
        },
        "public_source_files": [
            {"path": path, "sha256": digest}
            for path, digest in sorted(source_digests.items())
        ],
        "mechanized_theorem_ids": [
            "orbital.surface_constants",
            "orbital.position_update_half_step_soundness",
            "orbital.velocity_update_half_step_soundness",
            "orbital.residual_split_soundness",
            "orbital.field_embedding_nonwrap_bounds",
            "orbital.commitment_body_tag_domain_separation",
        ],
        "proof_bundle_dependencies": theorem_bundle_ids,
        "field_embedding_boundary_note": (
            "The public orbital proof surface is a fixed-point and BN254 non-wrap embedding "
            "surface. It proves the admitted discrete model, bounded residual relations, and "
            "commitment domain separation published by this release."
        ),
        "trusted_computing_base_note": TRUSTED_COMPUTING_BASE_NOTE,
    }
    path = out_dir / "evidence" / "orbital" / "private_nbody_orbital_showcase_closure.json"
    write_json(path, closure)
    return path.relative_to(out_dir).as_posix()


def strip_binary_in_place(path: Path) -> None:
    llvm_strip = shutil.which("llvm-strip")
    if llvm_strip:
        subprocess.run([llvm_strip, "--strip-all", str(path)], check=True, capture_output=True)
        return

    file_proc = subprocess.run(
        ["file", "-b", str(path)],
        text=True,
        capture_output=True,
        check=True,
    )
    description = file_proc.stdout.strip()
    strip_tool = shutil.which("strip")
    if "Mach-O" in description:
        if not strip_tool:
            raise RuntimeError(f"no strip tool available for Mach-O binary {path}")
        subprocess.run([strip_tool, "-S", "-x", str(path)], check=True, capture_output=True)
        return
    if "ELF" in description:
        if GNU_STRIP_BIN:
            subprocess.run(
                [GNU_STRIP_BIN, "--strip-unneeded", str(path)],
                check=True,
                capture_output=True,
            )
            return
        if ZIG_BIN:
            stripped_path = path.with_suffix(path.suffix + ".stripped")
            subprocess.run(
                [ZIG_BIN, "objcopy", "--strip-all", str(path), str(stripped_path)],
                check=True,
                capture_output=True,
            )
            stripped_path.replace(path)
            return
        if strip_tool:
            subprocess.run(
                [strip_tool, "--strip-unneeded", str(path)],
                check=True,
                capture_output=True,
            )
            return
        raise RuntimeError(f"no strip tool available for ELF binary {path}")
    raise RuntimeError(f"unsupported binary format for strip: {path} ({description})")


def printable_strings(path: Path) -> list[str]:
    return [match.group().decode("ascii", "ignore") for match in ASCII_RUN_RE.finditer(path.read_bytes())]


def leak_hits_for_text(text: str, *, allow_source_filenames: bool = False) -> list[str]:
    hits: list[str] = []
    for term in FORBIDDEN_TERMS:
        if term in text:
            hits.append(f"forbidden term `{term}`")
    if ABSOLUTE_PATH_RE.search(text):
        hits.append("absolute path")
    if not allow_source_filenames and SOURCE_FILENAME_RE.search(text):
        hits.append("source filename")
    return hits


def file_description(path: Path) -> str:
    return subprocess.run(
        ["file", "-b", str(path)],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def inspection_output(command: list[str], *, scrub: str | None = None) -> str:
    try:
        output = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        if scrub:
            output = output.replace(scrub, "<artifact-binary>")
        return output
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def binary_inspection_blobs(path: Path) -> list[str]:
    blobs = ["\n".join(printable_strings(path))]
    description = file_description(path)
    if "Mach-O" in description:
        blobs.append(inspection_output(["nm", "-a", str(path)], scrub=str(path)))
        blobs.append(inspection_output(["otool", "-l", str(path)], scrub=str(path)))
        blobs.append(
            inspection_output(
                ["objdump", "--macho", "--section-headers", str(path)],
                scrub=str(path),
            )
        )
    elif "ELF" in description:
        nm_tool = GNU_NM_BIN or shutil.which("nm")
        readelf_tool = GNU_READELF_BIN or shutil.which("readelf")
        objdump_tool = GNU_OBJDUMP_BIN or shutil.which("objdump")
        if nm_tool:
            blobs.append(inspection_output([nm_tool, "-a", str(path)], scrub=str(path)))
        if readelf_tool:
            blobs.append(
                inspection_output([readelf_tool, "-Wa", str(path)], scrub=str(path))
            )
        if objdump_tool:
            blobs.append(inspection_output([objdump_tool, "-x", str(path)], scrub=str(path)))
    return [blob for blob in blobs if blob]


def binary_leak_hits_for_blob(blob: str) -> list[str]:
    hits: list[str] = []
    for term in FORBIDDEN_TERMS:
        if term in blob:
            hits.append(f"forbidden term `{term}`")
    if ABSOLUTE_PATH_RE.search(blob):
        hits.append("absolute path")
    if PRIVATE_BINARY_SOURCE_RE.search(blob):
        hits.append("private source marker")
    return hits


def enforce_allowlist(out_dir: Path) -> None:
    allowed_prefixes = (
        "README.md",
        "CONSTITUTION.md",
        "LICENSE.md",
        "install.sh",
        "checksums/sha256.txt",
        "proofs/statements/",
        "proofs/evidence/",
        "proofs/attestations/",
        "proofs/zkproofs/",
        "proofs/verification_keys/",
        "proofs/manifests/",
        "binary/",
        "bin/",
        "evidence/",
    )
    for path in sorted(out_dir.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(out_dir).as_posix()
        if not any(
            relative == prefix.rstrip("/") or relative.startswith(prefix)
            for prefix in allowed_prefixes
        ):
            raise RuntimeError(f"non-allowlisted public artifact emitted: {relative}")


def run_leak_gate(out_dir: Path) -> None:
    findings: list[str] = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(out_dir).as_posix()
        if path.suffix in {".md", ".json", ".txt", ".sh"}:
            hits = leak_hits_for_text(
                path.read_text(encoding="utf-8"),
                allow_source_filenames=relative in ALLOWLISTED_SOURCE_FILENAME_TEXT_PATHS,
            )
        elif relative in ORBITAL_PUBLIC_SOURCE_RELATIVE_PATHS:
            text = path.read_text(encoding="utf-8")
            hits = []
            if ABSOLUTE_PATH_RE.search(text):
                hits.append("absolute path")
            for term in ("ZirOS", "Jacobi", str(ROOT)):
                if term in text:
                    hits.append(f"forbidden term `{term}`")
        else:
            hits = []
            for blob in binary_inspection_blobs(path):
                for hit in binary_leak_hits_for_blob(blob):
                    excerpt = next(
                        (
                            line.strip()
                            for line in blob.splitlines()
                            if line.strip()
                            and hit.removeprefix("forbidden term `").removesuffix("`")
                            in line
                        ),
                        blob[:160].replace("\n", " "),
                    )
                    hits.append(f"{hit}: {excerpt}")
                    if len(hits) >= 4:
                        break
                if len(hits) >= 4:
                    break
        if hits:
            findings.append(f"{relative}: {', '.join(hits)}")
    if findings:
        raise RuntimeError("public leak gate failed:\n" + "\n".join(findings))


def build_checksums(out_dir: Path) -> list[tuple[str, str]]:
    checksums: list[tuple[str, str]] = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(out_dir).as_posix()
        if relative == CHECKSUM_PATH:
            continue
        checksums.append((sha256_file(path), relative))
    return checksums


def write_checksums(out_dir: Path) -> None:
    checksum_path = out_dir / "checksums" / "sha256.txt"
    entries = build_checksums(out_dir)
    write_text(checksum_path, "".join(f"{digest}  {relative}\n" for digest, relative in entries))


def render_readme(*, owner: str, repo: str, ref: str) -> str:
    base_url = f"https://github.com/{owner}/{repo}"
    raw_repo_note = f"`~/.zkf-metal/share/repository`"
    return textwrap.dedent(
        f"""\
        # zkf-metal

        The entire ZK ecosystem tells developers: "open source your code so we can check it." That request contradicts the foundational premise of zero-knowledge proofs. The whole point of ZK is to prove a statement is true WITHOUT revealing the witness. Your source code is the witness. The correctness of that code is the statement. If your own system cannot prove its own correctness without showing the code, then what exactly is the system for?

        `zkf-metal` proves it differently. You publish:

        - The THEOREM STATEMENTS (what is proven - not how)
        - ZK PROOFS that those theorems are mechanically verified by Lean 4
        - VERIFICATION KEYS so anyone on earth can check the proofs
        - PINNED DIGESTS (public commitments to the compiled binaries)
        - The COMPILED METALLIB (the binary, not the source)

        You do NOT publish:

        - Metal shader source code
        - general Rust implementation source (except the intentional orbital evidence carve-out)
        - Lean proof files (the proof construction)
        - Lean environment definitions (which encode the program logic)
        - Any file from which source code could be reconstructed

        The community gets something stronger than general implementation source. They get mathematical proof that the certified release surface is correct, together with the compiled binaries and the exact digests they can verify.

        This repository is a proof-first verification release. It is installable from GitHub, but it is not a general source release.

        ## Current Public Surface Today

        The public release surface today is:

        - compiled Metallib artifacts and the host/runtime binaries required to verify them
        - theorem statements, proof bundles, verification keys, attestation manifests, and evidence summaries
        - pinned digest commitments for the shipped binaries and proof artifacts
        - one intentional source carve-out under `evidence/orbital/` containing the five-body orbital showcase Rust file and its public Verus proof surface

        Everything else remains private.

        ## Contents

        - `proofs/statements/`: public theorem statements and trusted-computing-base notes
        - `proofs/evidence/`: redacted bundle evidence summaries for theorem closure and build-integrity commitments
        - `proofs/attestations/`: attestation manifests that the public proof inputs commit to
        - `proofs/zkproofs/`: public BN254 Groth16 proof bundles
        - `proofs/verification_keys/`: verification keys for the published BN254 Groth16 proofs
        - `proofs/manifests/`: final public manifests binding theorem bundles, evidence, proofs, and metallib digests
        - `binary/`: published Metallib artifacts
        - `bin/`: public runtime and verifier binaries
        - `evidence/`: release evidence, risk-boundary notes, validation summaries, and the intentional orbital source carve-out

        ## Download

        Clone or download this repository from [{base_url}]({base_url}) to inspect the public artifacts directly. The repository tree is sufficient for offline verification with `zkf-verify`.

        ## Install

        ```bash
        curl -fsSL https://raw.githubusercontent.com/{owner}/{repo}/{ref}/install.sh | sh
        ```

        The installer downloads the artifact repository into {raw_repo_note}, installs the verifier into `~/.zkf-metal/bin/zkf-verify`, and installs `~/.zkf-metal/bin/zkf-metal` on Apple Silicon hosts.

        ## Verify

        ```bash
        ~/.zkf-metal/bin/zkf-verify verify-all --repo ~/.zkf-metal/share/repository
        ```

        This checks release checksums, theorem bundles, bundle-evidence summaries, attestation manifests, metallib digests, and the packaged BN254 Groth16 proof and verification-key pairs.

        ## Uninstall

        ```bash
        rm -rf ~/.zkf-metal/bin ~/.zkf-metal/share
        ```

        ## Trust Boundary

        Public verification here is stronger than source inspection, but it is not magic. The trusted computing base is explicit: Lean 4, Verus, the pinned Apple Metal toolchain, the Apple Metal driver/runtime, Apple GPU hardware, and the public BN254 Groth16 verifier used for the packaged proof bundles. The live release caveats, the field-lane boundary, and the orbital fixed-point/field-embedding boundary are documented in `evidence/public-risk-boundary.md`.

        ## Public Verification Ceremony

        Start with `evidence/verification-ceremony.md`. It contains the launch challenge, the artifact identifiers for this release, and the exact public verification steps expected for `v1.0.0`.
        """
    )


def render_constitution() -> str:
    return textwrap.dedent(
        f"""\
        # THE CONSTITUTION OF zkf-metal

        ## Preamble

        This repository is a public verification release. It is not a promise to disclose source. It is a promise to disclose theorem statements, proofs, verification keys, pinned binary commitments, and enough evidence for any third party to check the published claims without trusting an auditor.

        ## Article I - First Principle

        `zkf-metal` does not ask for trust in reputations, audit brands, or claims that cannot be re-executed. Public claims must be backed by checkable artifacts. If a claim is not bound to a published theorem statement, a published proof bundle, a published verification key, and a published binary commitment, it does not belong in this repository.

        ## Article II - Artifact Honesty

        This repository publishes what is proven, not how the proof construction was authored. The public surface is theorem statements, proof bundles, verification keys, pinned digests, compiled metallibs, and supporting evidence. The repository does not publish Metal shader source, general Rust implementation source, Lean proof construction files, Lean environment definitions, or any reconstructible source residue beyond the single intentional orbital showcase carve-out documented under `evidence/orbital/`.

        ## Article III - Attestation Chain

        Every published kernel family is bound to the compiled metallib digest set, the reflection digests, the pipeline-descriptor digests, the pinned Metal toolchain identity, and the redacted mechanized closure evidence that the public proof bundles commit to. Digest drift is a release failure, not a warning.

        ## Article IV - Mechanized Claims

        When `zkf-metal` states that a surface is proven, it means the public theorem statement is paired with a machine-checkable proof artifact, a verification key, and a redacted closure summary that can be exercised independently. Proofs are not narratives. They either verify or they do not.

        ## Article V - Release Boundary

        The implementation repository remains private. This public repository exists to publish the proof-and-artifact boundary: statements, proofs, keys, compiled binaries, evidence, and the single intentional orbital showcase carve-out. Verification is public. Reconstruction of the hidden implementation is not.

        ## Article VI - Amendment

        This constitution may only be amended by adding stronger release evidence, stronger proof bindings, or stricter leak-prevention guarantees. No amendment may weaken the attestation chain, the proof requirement, or the source-protection boundary of this repository.
        """
    )


def render_license() -> str:
    return textwrap.dedent(
        """\
        # zkf-metal Public Verification License

        Copyright (c) Sicarii. All rights reserved.

        Permission is granted to download, store, execute, benchmark, and verify the public artifacts contained in this repository, and to redistribute exact unmodified copies of this repository with this notice intact.

        No permission is granted to:

        - reverse engineer or reconstruct unpublished source from the public artifacts
        - create derivative works from unpublished implementation logic
        - remove attribution or legal notices
        - represent modified artifacts as an official `zkf-metal` verification release

        This repository is provided solely for artifact verification and authorized execution of the published binaries. No patent, trademark, source-code, or trade-secret license is granted except as strictly necessary to verify the published artifact set under this license.

        THE ARTIFACTS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
        """
    )


def render_install_script(*, owner: str, repo: str, ref: str) -> str:
    return textwrap.dedent(
        f"""\
        #!/bin/sh
        set -eu

        OWNER="${{ZKF_METAL_GITHUB_OWNER:-{owner}}}"
        REPO="${{ZKF_METAL_GITHUB_REPO:-{repo}}}"
        REF="${{ZKF_METAL_REF:-{ref}}}"
        BASE_URL="${{ZKF_METAL_BASE_URL:-https://raw.githubusercontent.com/${{OWNER}}/${{REPO}}/${{REF}}}}"
        INSTALL_ROOT="${{ZKF_METAL_INSTALL_ROOT:-$HOME/.zkf-metal}}"
        BIN_DIR="$INSTALL_ROOT/bin"
        REPO_DIR="$INSTALL_ROOT/share/repository"
        CHECKSUM_FILE="$REPO_DIR/checksums/sha256.txt"

        download() {{
          url="$1"
          dest="$2"
          mkdir -p "$(dirname "$dest")"
          if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$url" -o "$dest"
          elif command -v wget >/dev/null 2>&1; then
            wget -q "$url" -O "$dest"
          else
            echo "error: curl or wget is required" >&2
            exit 1
          fi
        }}

        file_sha256() {{
          path="$1"
          if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$path" | awk '{{print $1}}'
          elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 "$path" | awk '{{print $1}}'
          else
            echo "error: sha256sum or shasum is required" >&2
            exit 1
          fi
        }}

        detect_target() {{
          os="$(uname -s)"
          arch="$(uname -m)"
          case "$os:$arch" in
            Darwin:arm64) echo "aarch64-apple-darwin" ;;
            Darwin:x86_64) echo "x86_64-apple-darwin" ;;
            Linux:x86_64) echo "x86_64-unknown-linux-gnu" ;;
            Linux:aarch64) echo "aarch64-unknown-linux-gnu" ;;
            Linux:arm64) echo "aarch64-unknown-linux-gnu" ;;
            *) echo "unsupported:$os:$arch" ;;
          esac
        }}

        TARGET="$(detect_target)"
        if [ "${{TARGET#unsupported:}}" != "$TARGET" ]; then
          echo "error: unsupported platform $TARGET" >&2
          exit 1
        fi

        rm -rf "$REPO_DIR"
        mkdir -p "$BIN_DIR" "$REPO_DIR"

        download "$BASE_URL/checksums/sha256.txt" "$CHECKSUM_FILE"

        while IFS= read -r line; do
          [ -n "$line" ] || continue
          digest="$(printf '%s' "$line" | awk '{{print $1}}')"
          relative="$(printf '%s' "$line" | awk '{{print $2}}')"
          dest="$REPO_DIR/$relative"
          download "$BASE_URL/$relative" "$dest"
          actual="$(file_sha256 "$dest")"
          if [ "$actual" != "$digest" ]; then
            echo "error: checksum mismatch for $relative" >&2
            exit 1
          fi
        done < "$CHECKSUM_FILE"

        cp "$REPO_DIR/bin/$TARGET/zkf-verify" "$BIN_DIR/zkf-verify"
        chmod +x "$BIN_DIR/zkf-verify"

        if [ "$TARGET" = "aarch64-apple-darwin" ] && [ -f "$REPO_DIR/bin/aarch64-apple-darwin/zkf-metal" ]; then
          cp "$REPO_DIR/bin/aarch64-apple-darwin/zkf-metal" "$BIN_DIR/zkf-metal"
          chmod +x "$BIN_DIR/zkf-metal"
        fi

        "$BIN_DIR/zkf-verify" verify-all --repo "$REPO_DIR"

        echo
        echo "zkf-metal installed under $INSTALL_ROOT"
        echo "Verifier: $BIN_DIR/zkf-verify"
        if [ -f "$BIN_DIR/zkf-metal" ]; then
          echo "Runtime:  $BIN_DIR/zkf-metal"
        fi
        echo
        echo "Add to PATH if needed:"
        echo "  export PATH=\\"$BIN_DIR:\\$PATH\\""
        """
    )


def ensure_required_mappings(
    provided: dict[str, Path], *, expected_keys: set[str], label: str
) -> None:
    missing = sorted(expected_keys - set(provided))
    if missing:
        raise RuntimeError(f"missing {label} entries for: {', '.join(missing)}")


def ensure_matching_bundle_inputs(
    proof_bundles: dict[str, Path], verification_keys: dict[str, Path]
) -> None:
    proof_ids = set(proof_bundles)
    verification_key_ids = set(verification_keys)
    if proof_ids == verification_key_ids:
        return
    missing_proofs = sorted(verification_key_ids - proof_ids)
    missing_verification_keys = sorted(proof_ids - verification_key_ids)
    details: list[str] = []
    if missing_proofs:
        details.append(
            "proof bundles missing for: " + ", ".join(missing_proofs)
        )
    if missing_verification_keys:
        details.append(
            "verification keys missing for: " + ", ".join(missing_verification_keys)
        )
    raise RuntimeError(
        "public proof bundle overrides must be supplied as complete proof/vkey pairs; "
        + "; ".join(details)
    )


def build_proof_generation_plan(
    requests: list[dict[str, Any]], *, proof_mode: str
) -> dict[str, Any]:
    return {
        "schema": PROOF_PLAN_SCHEMA,
        "proof_mode": proof_mode,
        "requests": requests,
    }


def generate_public_proof_bundles(
    requests: list[dict[str, Any]], *, out_dir: Path, proof_mode: str
) -> tuple[dict[str, Path], dict[str, Path]]:
    if not requests:
        return {}, {}

    temp_root = Path(tempfile.mkdtemp(prefix="zkf-metal-public-proof-plan-"))
    plan_path = temp_root / "proof-plan.json"
    generated_root = temp_root / "generated"
    write_json(plan_path, build_proof_generation_plan(requests, proof_mode=proof_mode))

    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(ROOT / "target-public-proof"))

    try:
        run_checked(
            [
                "cargo",
                "run",
                "--release",
                "--manifest-path",
                str(PROOF_GENERATOR_MANIFEST),
                "--",
                "--plan",
                str(plan_path),
                "--out-dir",
                str(generated_root),
                "--proof-mode",
                proof_mode,
            ],
            cwd=ROOT,
            env=env,
        )

        proof_paths: dict[str, Path] = {}
        verification_key_paths: dict[str, Path] = {}
        for request in requests:
            bundle_id = request["bundle_id"]
            proof_source = generated_root / "zkproofs" / f"{bundle_id}.bin"
            verification_key_source = (
                generated_root / "verification_keys" / f"{bundle_id}.bin"
            )
            proof_destination = out_dir / "proofs" / "zkproofs" / f"{bundle_id}.bin"
            verification_key_destination = (
                out_dir / "proofs" / "verification_keys" / f"{bundle_id}.bin"
            )
            copy_file(proof_source, proof_destination)
            copy_file(verification_key_source, verification_key_destination)
            proof_paths[bundle_id] = proof_destination
            verification_key_paths[bundle_id] = verification_key_destination
        shutil.rmtree(temp_root)
        return proof_paths, verification_key_paths
    except subprocess.CalledProcessError as err:
        raise RuntimeError(
            "\n".join(
                [
                    "public proof bundle generation failed",
                    f"plan_path: {plan_path}",
                    f"generated_root: {generated_root}",
                    f"exit_code: {err.returncode}",
                    f"stdout:\n{err.stdout.strip() or '<empty>'}",
                    f"stderr:\n{err.stderr.strip() or '<empty>'}",
                ]
            )
        ) from err


def copy_optional_report(
    source: Path | None, *, out_dir: Path, stem: str
) -> str | None:
    if source is None:
        return None
    source = source.expanduser().resolve()
    suffix = source.suffix.lower()
    if suffix not in {".md", ".json", ".txt"}:
        suffix = ".txt"
    destination = out_dir / "evidence" / f"{stem}{suffix}"
    copy_file(source, destination)
    return destination.relative_to(out_dir).as_posix()


def write_report_with_default(
    *,
    out_dir: Path,
    stem: str,
    provided_source: Path | None,
    default_content: str,
) -> str:
    if provided_source is not None:
        copied = copy_optional_report(provided_source, out_dir=out_dir, stem=stem)
        if copied is not None:
            return copied
    destination = out_dir / "evidence" / f"{stem}.md"
    write_text(destination, default_content)
    return destination.relative_to(out_dir).as_posix()


def render_groth16_setup(proof_mode: str) -> str:
    return textwrap.dedent(
        f"""\
        # Groth16 Setup

        This release uses the native BN254 Groth16 `{proof_mode}` proving lane over the verified Metal host boundary.

        The Groth16 setup, verification keys, and verifier implementation are part of the trusted computing base for this release. Public users should verify:

        - the packaged verification keys match the published checksum manifest
        - `zkf-verify verify-all` accepts the proof bundles against those keys
        - the release tag and evidence pack state the same proof mode and schema versions
        - the packaged proving-lane metadata reports Metal-backed MSM and QAP witness-map execution with no CPU fallback

        This release does not claim to remove the trusted setup or upstream Groth16 security assumptions. Users must treat setup generation, toxic-waste handling, and the Groth16 knowledge-soundness assumptions as explicit external trust assumptions.
        """
    )


def render_no_source_support_policy() -> str:
    return textwrap.dedent(
        """\
        # No-Source Support Policy

        This repository is artifact-first. Public support therefore operates at the artifact boundary, except for the intentional orbital showcase carve-out under `evidence/orbital/`.

        Supported public debugging inputs:

        - `zkf-verify verify-all --repo <path>` output
        - release checksum mismatches
        - theorem or manifest bundle identifiers
        - `zkf-metal metal-doctor --json` output
        - host model, macOS version, Xcode/Metal toolchain facts, and reproduction steps

        Unsupported public debugging requests:

        - requests for unpublished Rust, Metal, or Lean source
        - requests for unpublished internal environment definitions
        - requests that require reconstructing hidden source structure from shipped artifacts

        Public users can verify, benchmark, and report drift. They cannot inspect unpublished implementation internals through this repository.
        """
    )


def render_binary_transparency() -> str:
    return textwrap.dedent(
        """\
        # Binary Transparency

        The published checksums, theorem statements, attestation manifests, and public proof bundles bind this release to exact metallib and binary digests.

        What this release proves:

        - the public manifests, proof bundles, verification keys, and shipped digests are internally consistent
        - the build-integrity proof input binds the hidden private source commitment root, the pinned toolchain identity, and the published metallib digest set

        What this release does not yet prove:

        - a publicly reproducible rebuild from hidden source
        - immunity against a compromised private build host before artifact publication
        - removal of all sanitized Rust sysroot and third-party dependency filename markers from shipped binaries under current Rust tooling

        The binary-transparency boundary is therefore honest but incomplete: digest integrity is public; private build-host integrity remains outside the current proof boundary. The public leak gate rejects private/workspace source residue, internal crate names, codenames, and absolute paths. Sanitized sysroot or third-party dependency path markers may still appear because current Rust tooling preserves them even after path trimming; these do not disclose unpublished `zkf-metal` source.
        """
    )


def render_verification_ceremony(
    *,
    owner: str,
    repo: str,
    ref: str,
    proof_mode: str,
) -> str:
    return textwrap.dedent(
        f"""\
        # Public Verification Ceremony

        Release: `v1.0.0`
        Repository: `https://github.com/{owner}/{repo}`
        Ref: `{ref}`
        Proof system: `BN254 Groth16`
        Proof mode: `{proof_mode}`

        Challenge:

        > Here are the theorem statements, the proofs, the verification keys, and the compiled binaries. We claim these binaries implement correct, formally verified GPU kernels for zero-knowledge proving. We claim this without revealing a single line of source code. Verify it yourself or tell us why you can't.

        Public verification steps:

        1. Install the repository and binaries with `install.sh`, or clone the repository directly.
        2. Run `zkf-verify verify-all --repo ~/.zkf-metal/share/repository`.
        3. Confirm the checksum manifest, theorem bundles, attestation manifests, metallib digests, proof bundles, and verification keys all verify.
        4. Confirm the packaged proving-lane metadata reports Metal-backed MSM and QAP witness-map execution with no CPU fallback.
        5. On Apple Silicon, run `zkf-metal metal-doctor --json`.
        6. On Apple Silicon, run the published sample prove/verify flow from `evidence/sample-prove-run.md`.

        Expected public outcome:

        - every manifest bundle verifies
        - every published checksum matches
        - the verifier exits successfully without source access
        """
    )


def sample_program_payload() -> dict[str, Any]:
    return {
        "name": "zkf_metal_public_sample_sum",
        "field": "bn254",
        "signals": [
            {"name": "left", "visibility": "private"},
            {"name": "right", "visibility": "private"},
            {"name": "sum", "visibility": "public"},
        ],
        "constraints": [
            {
                "kind": "equal",
                "lhs": {"op": "signal", "args": "sum"},
                "rhs": {
                    "op": "add",
                    "args": [
                        {"op": "signal", "args": "left"},
                        {"op": "signal", "args": "right"},
                    ],
                },
            }
        ],
        "witness_plan": {
            "assignments": [
                {
                    "target": "sum",
                    "expr": {
                        "op": "add",
                        "args": [
                            {"op": "signal", "args": "left"},
                            {"op": "signal", "args": "right"},
                        ],
                    },
                }
            ]
        },
    }


def sample_inputs_payload() -> dict[str, str]:
    return {"left": "7", "right": "11"}


def render_sample_prove_run() -> str:
    return textwrap.dedent(
        """\
        # Sample Prove Run

        Apple Silicon hosts can exercise the public runtime with the bundled sample program and inputs:

        ```bash
        ~/.zkf-metal/bin/zkf-metal prove \
          --backend plonky3 \
          --program ~/.zkf-metal/share/repository/evidence/sample-program.ir.json \
          --inputs ~/.zkf-metal/share/repository/evidence/sample-inputs.json \
          --compiled-out /tmp/zkf-metal-sample.compiled.json \
          --proof-out /tmp/zkf-metal-sample.proof.json
        ```

        Then verify the produced proof:

        ```bash
        ~/.zkf-metal/bin/zkf-metal verify \
          --compiled /tmp/zkf-metal-sample.compiled.json \
          --proof /tmp/zkf-metal-sample.proof.json
        ```

        Expected outcome:

        - the prove command emits a JSON summary with the selected backend and program digest
        - the verify command emits `\"verified\": true`
        - on Apple Silicon with the attested Metal lane available, `metal-doctor --json` should be green before running the sample
        """
    )


def render_public_risk_boundary(
    *,
    proof_mode: str,
    groth16_setup_report_path: str,
    support_policy_path: str,
    binary_transparency_path: str,
) -> str:
    return textwrap.dedent(
        f"""\
        # zkf-metal Public Risk Boundary

        This repository is a proof-and-artifact release. It narrows trust, but it does not remove every trust assumption. The remaining risk boundary is explicit.

        ## Groth16 Setup

        The published public proof bundles use the native BN254 Groth16 `{proof_mode}` proving lane. The release-specific setup note is bundled at `{groth16_setup_report_path}`.

        Trusted-setup risk is not erased by publishing proofs and verification keys. Users still need to understand how the setup was performed, who controlled or destroyed toxic waste, and how the published verifier keys correspond to the accepted setup transcript.

        ## No-Source Debugging

        A dedicated no-source support policy is bundled at `{support_policy_path}`.

        In this repository, a public user can independently check whether a proof verifies, whether a metallib digest matches the published commitment, and whether the attestation chain is internally consistent. A public user cannot inspect unpublished implementation logic to diagnose logic bugs directly.

        ## Binary Transparency

        A binary-transparency note is bundled at `{binary_transparency_path}`.

        The current build-integrity lane is a commitment lane: it binds the hidden committed source set, the pinned toolchain identity, and the published metallib digest set inside the public proof inputs. It does not yet prove a fully reproducible public rebuild from source, and it does not eliminate the risk of a compromised private build environment. Current Rust tooling may also preserve sanitized sysroot or third-party dependency filename markers in binaries even when private source paths are removed.
        """
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the artifact-only public zkf-metal repository tree."
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--github-owner", default="AnubisQuantumCipher", help="public GitHub owner"
    )
    parser.add_argument("--github-repo", default="zkf-metal", help="public GitHub repo name")
    parser.add_argument("--git-ref", default="main", help="public Git ref for install URLs")
    parser.add_argument("--zkf-metal-binary", type=Path, required=True)
    parser.add_argument(
        "--zkf-verify-binary",
        action="append",
        default=[],
        help="repeat TARGET=PATH for public verifier binaries",
    )
    parser.add_argument(
        "--proof-bundle",
        action="append",
        default=[],
        help="repeat BUNDLE_ID=PATH for pre-generated public Groth16 proof bundles",
    )
    parser.add_argument(
        "--verification-key",
        action="append",
        default=[],
        help="repeat BUNDLE_ID=PATH for pre-generated public Groth16 verification keys",
    )
    parser.add_argument(
        "--metallib",
        action="append",
        default=[],
        help="repeat LIBRARY_ID=PATH or PUBLIC_FILENAME=PATH for published metallibs",
    )
    parser.add_argument(
        "--verification-report",
        type=Path,
        default=DEFAULT_VERIFICATION_REPORT if DEFAULT_VERIFICATION_REPORT.exists() else None,
    )
    parser.add_argument(
        "--proof-mode",
        choices=("groth16",),
        default="groth16",
        help="Groth16 proof mode for generated public proof bundles",
    )
    parser.add_argument(
        "--skip-gpu-proof-closure-runners",
        action="store_true",
        help="skip rerunning Lean and Verus GPU proof runners before exporting the public closure report",
    )
    parser.add_argument(
        "--skip-supporting-proof-closure-runners",
        action="store_true",
        help="skip rerunning Rocq and orbital Verus proof runners before exporting the supporting public closure report",
    )
    parser.add_argument(
        "--groth16-setup-report",
        type=Path,
        help="optional release-specific Groth16 setup documentation copied into evidence/",
    )
    parser.add_argument(
        "--support-policy-report",
        type=Path,
        help="optional no-source support-policy documentation copied into evidence/",
    )
    parser.add_argument(
        "--binary-transparency-report",
        type=Path,
        help="optional binary-transparency documentation copied into evidence/",
    )
    parser.add_argument(
        "--evidence-file",
        action="append",
        default=[],
        help="repeat NAME=PATH for extra evidence files copied under evidence/",
    )
    parser.add_argument(
        "--skip-private-validation",
        action="store_true",
        help="skip the existing private GPU manifest and bundle-attestation validation scripts",
    )
    args = parser.parse_args()

    out_dir = args.out_dir.expanduser().resolve()
    zkf_metal_binary = args.zkf_metal_binary.expanduser().resolve()
    verifier_binaries = parse_key_path_pairs(args.zkf_verify_binary, label="--zkf-verify-binary")
    proof_bundles = parse_key_path_pairs(args.proof_bundle, label="--proof-bundle")
    verification_keys = parse_key_path_pairs(args.verification_key, label="--verification-key")
    ensure_matching_bundle_inputs(proof_bundles, verification_keys)
    metallib_inputs = {
        normalize_library_key(key): value
        for key, value in parse_key_path_pairs(args.metallib, label="--metallib").items()
    }
    evidence_inputs = parse_key_path_pairs(args.evidence_file, label="--evidence-file")

    host_target = current_host_target()
    ensure_required_mappings(
        verifier_binaries, expected_keys=set(PUBLIC_VERIFIER_TARGETS), label="verifier binary"
    )
    bundle_ids = {bundle["bundle_id"] for bundle in BUNDLE_DEFINITIONS}

    private_validation = []
    if not args.skip_private_validation:
        private_validation = run_private_validation()

    private_manifests = export_private_manifests()
    program_records = collect_program_records(private_manifests)
    private_source_root = private_source_commitment_root(private_manifests)
    gpu_proof_closure = run_gpu_proof_closure_audit(
        skip_runners=args.skip_gpu_proof_closure_runners
    )
    supporting_proof_closure = run_supporting_proof_closure_audit(
        skip_runners=args.skip_supporting_proof_closure_runners
    )
    theorem_records_by_id = {
        theorem["theorem_id"]: theorem
        for report in (gpu_proof_closure, supporting_proof_closure)
        for theorem in report["theorems"]
    }
    expected_metallibs = {
        library_id: next(
            artifact["metallib_digest"]
            for record in program_records
            for artifact in record["artifacts"]
            if artifact["metallib_public_name"] == public_name
        )
        for library_id, public_name in LIBRARY_OUTPUTS.items()
        if library_id != "msm_library"
    }

    discovered = discover_metallibs(
        {
            library_id: digest
            for library_id, digest in expected_metallibs.items()
            if library_id not in metallib_inputs
        },
        excluded_roots=[out_dir],
    )
    metallib_inputs = {**discovered, **metallib_inputs}
    ensure_required_mappings(
        metallib_inputs,
        expected_keys={library for library in expected_metallibs},
        label="metallib",
    )
    for library_id, digest in expected_metallibs.items():
        actual = sha256_file(metallib_inputs[library_id])
        if actual != digest:
            raise RuntimeError(
                f"metallib digest mismatch for {library_id}: expected {digest}, got {actual}"
            )

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_text(
        out_dir / "README.md",
        render_readme(
            owner=args.github_owner,
            repo=args.github_repo,
            ref=args.git_ref,
        ),
    )
    write_text(out_dir / "CONSTITUTION.md", render_constitution())
    write_text(out_dir / "LICENSE.md", render_license())
    write_text(
        out_dir / "install.sh",
        render_install_script(owner=args.github_owner, repo=args.github_repo, ref=args.git_ref),
    )
    os.chmod(out_dir / "install.sh", 0o755)

    for library_id, public_name in sorted(
        ((library_id, LIBRARY_OUTPUTS[library_id]) for library_id in expected_metallibs),
        key=lambda item: item[1],
    ):
        copy_file(metallib_inputs[library_id], out_dir / "binary" / public_name)

    copy_file(zkf_metal_binary, out_dir / "bin" / "aarch64-apple-darwin" / "zkf-metal")
    strip_binary_in_place(out_dir / "bin" / "aarch64-apple-darwin" / "zkf-metal")
    for target, source in verifier_binaries.items():
        destination = out_dir / "bin" / target / "zkf-verify"
        copy_file(source, destination)
        strip_binary_in_place(destination)

    copied_groth16_setup_path = write_report_with_default(
        out_dir=out_dir,
        stem="groth16-setup",
        provided_source=args.groth16_setup_report,
        default_content=render_groth16_setup(args.proof_mode),
    )
    copied_support_policy_path = write_report_with_default(
        out_dir=out_dir,
        stem="no-source-support-policy",
        provided_source=args.support_policy_report,
        default_content=render_no_source_support_policy(),
    )
    copied_binary_transparency_path = write_report_with_default(
        out_dir=out_dir,
        stem="binary-transparency",
        provided_source=args.binary_transparency_report,
        default_content=render_binary_transparency(),
    )
    write_text(
        out_dir / "evidence" / "verification-ceremony.md",
        render_verification_ceremony(
            owner=args.github_owner,
            repo=args.github_repo,
            ref=args.git_ref,
            proof_mode=args.proof_mode,
        ),
    )
    write_json(out_dir / "evidence" / "sample-program.ir.json", sample_program_payload())
    write_json(out_dir / "evidence" / "sample-inputs.json", sample_inputs_payload())
    write_text(out_dir / "evidence" / "sample-prove-run.md", render_sample_prove_run())
    write_text(
        out_dir / "evidence" / "public-risk-boundary.md",
        render_public_risk_boundary(
            proof_mode=args.proof_mode,
            groth16_setup_report_path=copied_groth16_setup_path,
            support_policy_path=copied_support_policy_path,
            binary_transparency_path=copied_binary_transparency_path,
        ),
    )
    orbital_source_digests = copy_orbital_public_source(out_dir)
    orbital_closure_path = write_orbital_public_closure(
        out_dir,
        source_digests=orbital_source_digests,
        theorem_bundle_ids=["orbital-fixed-point", "field-arithmetic", "montgomery-bn254"],
    )

    statement_digests: dict[str, str] = {}
    attestation_digests: dict[str, str] = {}
    bundle_evidence_digests: dict[str, str] = {}
    pending_requests: list[dict[str, Any]] = []
    for bundle in BUNDLE_DEFINITIONS:
        selected = selected_records(bundle, program_records)
        evidence = build_bundle_evidence(
            bundle,
            selected,
            theorem_records_by_id=theorem_records_by_id,
            private_source_root=private_source_root,
        )
        evidence_digest = bundle_evidence_digest(evidence)
        evidence_path = out_dir / "proofs" / "evidence" / f"{bundle['bundle_id']}.json"
        write_json(evidence_path, evidence)

        statement = build_bundle_statement(
            bundle,
            selected,
            private_source_root=private_source_root,
            bundle_evidence_digest_value=evidence_digest,
        )
        statement_path = out_dir / "proofs" / "statements" / f"{bundle['bundle_id']}.json"
        write_json(statement_path, statement)
        statement_digest = sha256_file(statement_path)
        attestation_manifest = build_attestation_manifest(
            bundle,
            selected,
            statement_digest,
            evidence_digest,
            private_source_root=private_source_root,
        )
        attestation_manifest_path = (
            out_dir / "proofs" / "attestations" / f"{bundle['bundle_id']}.json"
        )
        write_json(attestation_manifest_path, attestation_manifest)
        attestation_digest = sha256_file(attestation_manifest_path)

        statement_digests[bundle["bundle_id"]] = statement_digest
        attestation_digests[bundle["bundle_id"]] = attestation_digest
        bundle_evidence_digests[bundle["bundle_id"]] = evidence_digest
        if bundle["bundle_id"] not in proof_bundles:
            pending_requests.append(
                {
                    "bundle_id": bundle["bundle_id"],
                    "theorem_ids": bundle["theorem_ids"],
                    "statement_bundle_digest": statement_digest,
                    "private_source_commitment_root": private_source_root,
                    "metallib_digest_set_root": attestation_manifest[
                        "metallib_digest_set_root"
                    ],
                    "attestation_manifest_digest": attestation_digest,
                    "toolchain_identity_digest": attestation_manifest[
                        "toolchain_identity_digest"
                    ],
                    "bundle_evidence": evidence,
                }
            )

    generated_proof_bundles, generated_verification_keys = generate_public_proof_bundles(
        pending_requests,
        out_dir=out_dir,
        proof_mode=args.proof_mode,
    )

    for bundle in BUNDLE_DEFINITIONS:
        bundle_id = bundle["bundle_id"]
        proof_destination = out_dir / "proofs" / "zkproofs" / f"{bundle_id}.bin"
        verification_key_destination = (
            out_dir / "proofs" / "verification_keys" / f"{bundle_id}.bin"
        )
        if bundle_id in proof_bundles:
            copy_file(proof_bundles[bundle_id], proof_destination)
            copy_file(verification_keys[bundle_id], verification_key_destination)

        manifest = build_bundle_manifest(
            bundle,
            sha256_file(proof_destination),
            sha256_file(verification_key_destination),
            attestation_digests[bundle_id],
            bundle_evidence_digest_value=bundle_evidence_digests[bundle_id],
        )
        manifest_path = out_dir / "proofs" / "manifests" / f"{bundle['bundle_id']}.json"
        write_json(manifest_path, manifest)

    evidence_summary = {
        "schema": "zkf-metal-public-generator-summary-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "private_source_commitment_root": private_source_root,
        "private_validation": private_validation,
        "gpu_proof_closure": {
            "schema": gpu_proof_closure["schema"],
            "theorem_ids": [
                theorem["theorem_id"] for theorem in gpu_proof_closure["theorems"]
            ],
            "checker_counts": {
                "lean": sum(
                    1
                    for theorem in gpu_proof_closure["theorems"]
                    if theorem["checker"] == "lean"
                ),
                "verus": sum(
                    1
                    for theorem in gpu_proof_closure["theorems"]
                    if theorem["checker"] == "verus"
                ),
            },
        },
        "supporting_proof_closure": {
            "schema": supporting_proof_closure["schema"],
            "theorem_ids": [
                theorem["theorem_id"] for theorem in supporting_proof_closure["theorems"]
            ],
            "checker_counts": {
                "rocq": sum(
                    1
                    for theorem in supporting_proof_closure["theorems"]
                    if theorem["checker"] == "rocq"
                ),
                "verus": sum(
                    1
                    for theorem in supporting_proof_closure["theorems"]
                    if theorem["checker"] == "verus"
                ),
            },
        },
        "bundles": sorted(bundle_ids),
        "generated_proof_bundles": sorted(request["bundle_id"] for request in pending_requests),
        "public_groth16_proof_bundle_schema": PUBLIC_GROTH16_PROOF_SCHEMA,
        "proof_mode": args.proof_mode,
        "metallibs": {
            LIBRARY_OUTPUTS[library_id]: sha256_file(out_dir / "binary" / LIBRARY_OUTPUTS[library_id])
            for library_id in expected_metallibs
        },
        "verifier_targets": sorted(verifier_binaries),
        "risk_boundary": {
            "groth16_setup_report_path": copied_groth16_setup_path,
            "support_policy_path": copied_support_policy_path,
            "binary_transparency_path": copied_binary_transparency_path,
            "risk_boundary_path": "evidence/public-risk-boundary.md",
        },
        "orbital_public_surface": {
            "closure_path": orbital_closure_path,
            "source_files": sorted(orbital_source_digests),
        },
        "verification_ceremony_path": "evidence/verification-ceremony.md",
    }
    write_json(out_dir / "evidence" / "generator-summary.json", evidence_summary)

    if args.verification_report is not None:
        copy_file(args.verification_report.expanduser().resolve(), out_dir / "evidence" / "verification-report.md")
    for name, source in evidence_inputs.items():
        copy_file(source, out_dir / "evidence" / name)

    enforce_allowlist(out_dir)
    run_leak_gate(out_dir)
    write_checksums(out_dir)

    verifier_path = out_dir / "bin" / host_target / "zkf-verify"
    if verifier_path.exists():
        run_checked(
            [str(verifier_path), "verify-all", "--repo", str(out_dir), "--json"],
            cwd=ROOT,
        )
    else:
        raise RuntimeError(f"host verifier binary is missing for verification gate: {host_target}")

    print(out_dir)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as err:
        raise SystemExit(f"error: {err}")
