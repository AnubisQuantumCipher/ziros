#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from lean_toolchain import LEAN_TOOLCHAIN, lean_cmd_prefix


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
GPU_PROOF_ROOT = ROOT / "zkf-metal" / "proofs" / "lean"
RUNTIME_SCHEDULER_PROOF = (
    ROOT / "zkf-runtime" / "proofs" / "verus" / "runtime_execution_scheduler_verus.rs"
)
APPROVED_AXIOMS = {"Classical.choice", "Quot.sound", "propext"}
SCHEMA = "zkf-metal-gpu-proof-closure-v1"

THEOREM_GATES = {
    "gpu.hash_differential_bounded": {
        "checker": "lean",
        "module": "Hash",
        "decl": "hash_family_exact_digest_sound",
        "artifact_path": GPU_PROOF_ROOT / "Hash.olean",
    },
    "gpu.poseidon2_differential_bounded": {
        "checker": "lean",
        "module": "Poseidon2",
        "decl": "poseidon2_family_exact_permutation_sound",
        "artifact_path": GPU_PROOF_ROOT / "Poseidon2.olean",
    },
    "gpu.ntt_differential_bounded": {
        "checker": "lean",
        "module": "Ntt",
        "decl": "ntt_family_exact_transform_sound",
        "artifact_path": GPU_PROOF_ROOT / "Ntt.olean",
    },
    "gpu.ntt_bn254_butterfly_arithmetic_sound": {
        "checker": "lean",
        "module": "Ntt",
        "decl": "gpu_bn254_ntt_butterfly_arithmetic_sound",
        "artifact_path": GPU_PROOF_ROOT / "Ntt.olean",
    },
    "gpu.msm_differential_bounded": {
        "checker": "lean",
        "module": "Msm",
        "decl": "msm_family_exact_pippenger_sound",
        "artifact_path": GPU_PROOF_ROOT / "Msm.olean",
    },
    "gpu.launch_contract_sound": {
        "checker": "lean",
        "module": "LaunchSafety",
        "decl": "gpu_launch_contract_sound",
        "artifact_path": GPU_PROOF_ROOT / "LaunchSafety.olean",
    },
    "gpu.buffer_layout_sound": {
        "checker": "lean",
        "module": "MemoryModel",
        "decl": "gpu_buffer_layout_sound",
        "artifact_path": GPU_PROOF_ROOT / "MemoryModel.olean",
    },
    "gpu.dispatch_schedule_sound": {
        "checker": "lean",
        "module": "CodegenSoundness",
        "decl": "gpu_dispatch_schedule_sound",
        "artifact_path": GPU_PROOF_ROOT / "CodegenSoundness.olean",
    },
    "gpu.shader_bundle_provenance": {
        "checker": "lean",
        "module": "CodegenSoundness",
        "decl": "gpu_shader_bundle_provenance",
        "artifact_path": GPU_PROOF_ROOT / "CodegenSoundness.olean",
    },
    "gpu.runtime_fail_closed": {
        "checker": "verus",
        "module": "runtime_execution_scheduler_verus",
        "decl": "gpu_runtime_fail_closed",
        "artifact_path": RUNTIME_SCHEDULER_PROOF,
    },
    "gpu.cpu_gpu_partition_equivalence": {
        "checker": "verus",
        "module": "runtime_execution_scheduler_verus",
        "decl": "gpu_cpu_gpu_partition_equivalence",
        "artifact_path": RUNTIME_SCHEDULER_PROOF,
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_checked(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"command failed ({' '.join(command)}):\n{result.stdout}",
    )
    return result.stdout


def ensure_private_gpu_proofs_current(*, skip_runners: bool) -> None:
    if skip_runners:
        return
    run_checked(["bash", str(ROOT / "scripts" / "run_lean_proofs.sh")], cwd=ROOT)
    run_checked(
        ["bash", str(ROOT / "scripts" / "run_verus_runtime_execution_proofs.sh")],
        cwd=ROOT,
    )


def ledger_entries_by_id() -> dict[str, dict[str, object]]:
    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    entries = {
        entry["theorem_id"]: entry
        for entry in ledger["entries"]
        if entry["theorem_id"] in THEOREM_GATES
    }
    require(
        set(entries) == set(THEOREM_GATES),
        "GPU closure audit could not find all tracked GPU theorem ledger entries",
    )
    for theorem_id, gate in THEOREM_GATES.items():
        entry = entries[theorem_id]
        require(
            entry["status"] == "mechanized_local",
            f"{theorem_id} is not mechanized_local in the verification ledger",
        )
        require(
            entry["checker"] == gate["checker"],
            f"{theorem_id} checker drifted from expected {gate['checker']}",
        )
        require(
            entry.get("trusted_assumptions") == [],
            f"{theorem_id} still carries trusted assumptions in the verification ledger",
        )
    return entries


def audit_lean_axioms() -> dict[str, list[str]]:
    lean_modules = sorted(
        {
            gate["module"]
            for gate in THEOREM_GATES.values()
            if gate["checker"] == "lean"
        }
    )
    lean_decls = [
        gate["decl"]
        for gate in THEOREM_GATES.values()
        if gate["checker"] == "lean"
    ]
    env = dict(os.environ)
    existing_lean_path = env.get("LEAN_PATH")
    env["LEAN_PATH"] = (
        f"{GPU_PROOF_ROOT}{os.pathsep}{existing_lean_path}"
        if existing_lean_path
        else str(GPU_PROOF_ROOT)
    )

    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".lean",
        prefix="GpuProofClosureAudit.",
        dir=ROOT,
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_path = Path(temp_file.name)
        for module in lean_modules:
            temp_file.write(f"import {module}\n")
        temp_file.write("\n")
        for decl in lean_decls:
            temp_file.write(f"#print axioms ZkfMetalProofs.{decl}\n")

    try:
        output = run_checked([*lean_cmd_prefix(), temp_path.name], cwd=ROOT, env=env)
    finally:
        temp_path.unlink(missing_ok=True)

    audited: dict[str, list[str]] = {}
    for decl in lean_decls:
        full_name = f"ZkfMetalProofs.{decl}"
        pattern = re.compile(
            rf"'{re.escape(full_name)}' "
            rf"(does not depend on any axioms|depends on axioms: (?P<axioms>[^\n]+))"
        )
        match = pattern.search(output)
        require(match is not None, f"Lean axiom audit did not report `{full_name}`")
        axioms_str = match.group("axioms")
        if axioms_str is None:
            audited[decl] = []
            continue
        axioms = sorted(
            {
                axiom.strip().strip("[]")
                for axiom in axioms_str.split(",")
                if axiom.strip().strip("[]")
            }
        )
        require("Lean.sorryAx" not in axioms, f"{full_name} still depends on Lean.sorryAx")
        disallowed = [axiom for axiom in axioms if axiom not in APPROVED_AXIOMS]
        require(
            not disallowed,
            f"{full_name} depends on disallowed axioms: {', '.join(disallowed)}",
        )
        audited[decl] = axioms
    return audited


def theorem_source_contains_decl(path: Path, checker: str, decl_name: str) -> bool:
    text = path.read_text(encoding="utf-8")
    marker = f"theorem {decl_name}" if checker == "lean" else f"pub proof fn {decl_name}"
    return marker in text


def build_report(*, skip_runners: bool) -> dict[str, object]:
    ensure_private_gpu_proofs_current(skip_runners=skip_runners)
    entries = ledger_entries_by_id()
    lean_axioms = audit_lean_axioms()

    theorem_records: list[dict[str, object]] = []
    for theorem_id, gate in THEOREM_GATES.items():
        entry = entries[theorem_id]
        artifact_path = Path(gate["artifact_path"])
        require(
            artifact_path.is_file(),
            f"missing proof artifact for {theorem_id}: {artifact_path}",
        )
        source_path = ROOT / str(entry["evidence_path"])
        require(
            source_path.is_file(),
            f"missing proof source for {theorem_id}: {source_path}",
        )
        require(
            theorem_source_contains_decl(source_path, gate["checker"], gate["decl"]),
            f"{theorem_id} is tracked as mechanized but {source_path} lacks `{gate['decl']}`",
        )
        axioms = lean_axioms.get(gate["decl"], []) if gate["checker"] == "lean" else []
        theorem_records.append(
            {
                "theorem_id": theorem_id,
                "title": entry["title"],
                "checker": gate["checker"],
                "decl_name": gate["decl"],
                "module_name": gate["module"],
                "proof_artifact_kind": "olean" if gate["checker"] == "lean" else "verus_source",
                "proof_artifact_digest": sha256_file(artifact_path),
                "allowed_axioms_only": True,
                "axioms": axioms,
            }
        )

    theorem_records.sort(key=lambda item: str(item["theorem_id"]))
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "lean_toolchain": LEAN_TOOLCHAIN,
        "theorems": theorem_records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit the mechanized GPU proof surface and emit a redacted closure report."
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--skip-proof-runners",
        action="store_true",
        help="skip rerunning Lean and Verus proof runners before the audit",
    )
    args = parser.parse_args()

    report = build_report(skip_runners=args.skip_proof_runners)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
