#!/usr/bin/env python3
"""Run the production workspace validation matrix and emit a machine-readable report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "target" / "validation" / "workspace_validation.json"
SCHEMA = "zkf-workspace-validation-v1"
LOG_DIRNAME = "logs"
DEFAULT_REQUIRED_MEMBERS = [
    "zkf-api",
    "zkf-backends-pro",
    "zkf-conformance",
    "zkf-ffi",
    "zkf-gpu",
    "zkf-lib",
    "zkf-lsp",
    "zkf-python",
]
WORKSPACE_TEST_SKIP_FILTERS = [
    "gpu_benchmark_scaling",
    "gpu_dispatch_verification",
    "proving_produces_valid_proofs_at_all_sizes",
    "cross_backend_proof_sizes",
    "groth16_scaling_with_gpu_dispatch",
    "batch_workload_scaling",
    "plonky3_proof_size_scaling",
    "halo2_proof_scaling",
    "backend_head_to_head_defi",
    "groth16_constant_proof_size",
]


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def run_command(
    *,
    label: str,
    cmd: list[str],
    logs_dir: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    stdout_path = logs_dir / f"{label}.stdout.log"
    stderr_path = logs_dir / f"{label}.stderr.log"
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    stdout_path.write_text(proc.stdout)
    stderr_path.write_text(proc.stderr)
    return {
        "label": label,
        "command": cmd,
        "returncode": proc.returncode,
        "elapsed_ms": round(elapsed_ms, 3),
        "ok": proc.returncode == 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_preview": proc.stdout.strip()[:4000] or None,
        "stderr_preview": proc.stderr.strip()[:4000] or None,
    }


def is_macos_host() -> bool:
    return sys.platform == "darwin"


def validation_commands() -> list[dict[str, Any]]:
    workspace_test_cmd = ["cargo", "test", "--workspace", "--lib", "--bins", "--tests", "--"]
    for name in WORKSPACE_TEST_SKIP_FILTERS:
        workspace_test_cmd.extend(["--skip", name])
    commands = [
        {
            "label": "cargo-check-workspace",
            "cmd": ["cargo", "check", "--workspace", "--all-targets"],
        },
        {
            "label": "cargo-clippy-workspace",
            "cmd": ["cargo", "clippy", "--workspace", "--", "-D", "warnings"],
        },
        {
            "label": "rustfmt-workspace-check",
            "cmd": ["python3", "scripts/check_rustfmt_workspace.py", "--check"],
        },
        {
            "label": "cargo-test-workspace",
            "cmd": workspace_test_cmd,
        },
        {
            "label": "python-release-tools",
            "cmd": ["python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"],
        },
        {
            "label": "cargo-test-zkf-backends-recursive-hardening",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-backends",
                "--features",
                "native-nova",
                "--test",
                "recursive_integration_hardening",
            ],
        },
    ]
    if is_macos_host():
        python_build_env = os.environ.copy()
        python_build_env.setdefault("PYO3_PYTHON", "python3")
        commands.extend(
            [
                {
                    "label": "cargo-test-zkf-metal-sha256",
                    "cmd": ["cargo", "test", "-p", "zkf-metal", "batch_sha256_matches_cpu"],
                },
                {
                    "label": "cargo-test-zkf-metal-keccak256",
                    "cmd": ["cargo", "test", "-p", "zkf-metal", "batch_keccak256_matches_cpu"],
                },
                {
                    "label": "cargo-test-zkf-integration-benchmarks-compile",
                    "cmd": [
                        "cargo",
                        "test",
                        "-p",
                        "zkf-integration-tests",
                        "--test",
                        "metal_gpu_benchmark",
                        "--test",
                        "production_benchmark",
                        "--no-run",
                    ],
                },
                {
                    "label": "cargo-build-zkf-python",
                    "cmd": ["cargo", "build", "-p", "zkf-python"],
                    "env": python_build_env,
                },
                {
                    "label": "python-import-zkf",
                    "cmd": ["python3", "scripts/smoke_import_zkf_python.py", "--target-dir", "target/debug"],
                },
            ]
        )
    return commands


def cargo_metadata_workspace_members() -> list[str]:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cargo metadata failed")
    payload = json.loads(proc.stdout)
    packages = payload.get("packages") or []
    workspace_ids = set(payload.get("workspace_members") or [])
    members = []
    for package in packages:
        if isinstance(package, dict) and package.get("id") in workspace_ids and package.get("name"):
            members.append(str(package["name"]))
    return sorted(set(members))


def validate_required_members(workspace_members: list[str], required_members: list[str]) -> dict[str, Any]:
    missing = [member for member in required_members if member not in workspace_members]
    return {
        "required_members": required_members,
        "present_members": [member for member in required_members if member in workspace_members],
        "missing_members": missing,
        "ok": not missing,
    }


def build_report(*, out_path: Path, required_members: list[str]) -> dict[str, Any]:
    logs_dir = out_path.parent / LOG_DIRNAME
    logs_dir.mkdir(parents=True, exist_ok=True)

    workspace_members = cargo_metadata_workspace_members()
    member_validation = validate_required_members(workspace_members, required_members)

    commands = validation_commands()

    results = [
        run_command(
            label=entry["label"],
            cmd=entry["cmd"],
            logs_dir=logs_dir,
            env=entry.get("env"),
        )
        for entry in commands
    ]
    blocking_reasons = []
    if not member_validation["ok"]:
        blocking_reasons.append("required-workspace-members-missing")
    blocking_reasons.extend(result["label"] for result in results if not result["ok"])

    passed = member_validation["ok"] and all(result["ok"] for result in results)
    next_actions = []
    if not member_validation["ok"]:
        next_actions.append(
            "restore the required production workspace members before finalizing a release"
        )
    for result in results:
        if not result["ok"]:
            next_actions.append(
                f"fix {result['label']} and inspect {result['stderr_path']} for the exact failure"
            )

    report = {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "root": str(ROOT),
        "workspace_members": workspace_members,
        "workspace_member_validation": member_validation,
        "commands": results,
        "summary": {
            "passed": passed,
            "command_count": len(results),
            "commands_ok": sum(1 for result in results if result["ok"]),
            "blocking_reasons": blocking_reasons,
        },
        "next_actions": next_actions,
    }
    write_json(out_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    report = build_report(
        out_path=args.out.expanduser().resolve(),
        required_members=DEFAULT_REQUIRED_MEMBERS,
    )
    print(
        json.dumps(
            {
                "workspace_validation": str(args.out.expanduser().resolve()),
                "schema": SCHEMA,
                "passed": report["summary"]["passed"],
            },
            indent=2,
        )
    )
    return 0 if report["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
